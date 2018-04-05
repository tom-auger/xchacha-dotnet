namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    public class XChaChaBufferedStream : XChaChaStreamBase
    {
        private const int BlockLength = 128 * 1024;
        private const int EncryptedBlockLength = BlockLength + crypto_secretstream_xchacha20poly1305_ABYTES;
        

        private int plaintextBufferPosition;
        private byte[] plaintextBuffer = new byte[BlockLength];
        private byte[] ciphertextBuffer = new byte[EncryptedBlockLength];

        public XChaChaBufferedStream(Stream stream, ReadOnlySpan<byte> key, EncryptionMode encryptionMode)
            : base(stream, key, encryptionMode)
        {
        }

        public override bool CanRead =>
            this.encryptionMode == EncryptionMode.Decrypt &&
            !this.isClosed &&
            this.stream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite =>
            this.encryptionMode == EncryptionMode.Encrypt &&
            !isClosed &&
            this.stream.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
            if (this.encryptionMode == EncryptionMode.Encrypt)
                this.EncryptPlainTextBuffer(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        }

        public void FlushFinal()
        {
            if (this.encryptionMode == EncryptionMode.Encrypt)
                this.EncryptPlainTextBuffer(crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!this.CanRead) throw new NotSupportedException();

            var totalBytesOutput = 0;
            while (count > 0)
            {
                // If there's any data left in the plaintextBuffer then output this first
                if (this.plaintextBufferPosition > 0)
                {
                    var numBytesLeftInPlaintextBuffer =
                        this.plaintextBuffer.Length - this.plaintextBufferPosition;

                    var numberOfBufferedBytesToOutput = Math.Min(numBytesLeftInPlaintextBuffer, count);

                    Array.Copy(this.plaintextBuffer, this.plaintextBufferPosition, buffer, offset, numberOfBufferedBytesToOutput);

                    this.plaintextBufferPosition += numberOfBufferedBytesToOutput;
                    offset += numberOfBufferedBytesToOutput;
                    count -= numberOfBufferedBytesToOutput;
                    totalBytesOutput += numberOfBufferedBytesToOutput;

                    if (this.plaintextBufferPosition == this.plaintextBuffer.Length)
                        this.plaintextBufferPosition = 0;

                    continue;
                }

                // Read the next block from the stream
                var bytesRead = this.stream.Read(this.ciphertextBuffer);

                // Stop if we've already reached the end of the stream
                if (bytesRead == 0) break;

                // Decrypt the next block
                var decryptResult = crypto_secretstream_xchacha20poly1305_pull(
                    this.state,
                    ref MemoryMarshal.GetReference(this.plaintextBuffer.AsSpan()),
                    out var decryptedBlockLongLength,
                    out var tag,
                    in MemoryMarshal.GetReference(this.ciphertextBuffer.AsReadOnlySpan()),
                    (UInt64)bytesRead,
                    IntPtr.Zero,
                    0);

                // Throw an error if the decrypt failed
                if (decryptResult != 0) throw new CryptographicException("block is invalid or corrupt");

                // Remember the tag in case we want to verify it later
                this.tagOfLastDecryptedBlock = tag;

                // Output the plaintext
                var decryptedBlockLength = (int)decryptedBlockLongLength;
                var numberOfBytesToOutput = Math.Min(count, decryptedBlockLength);
                Array.Copy(this.plaintextBuffer, 0, buffer, offset, numberOfBytesToOutput);

                this.plaintextBufferPosition =
                    numberOfBytesToOutput < decryptedBlockLength
                    ? numberOfBytesToOutput
                    : 0;

                offset += numberOfBytesToOutput;
                count -= numberOfBytesToOutput;
                totalBytesOutput += numberOfBytesToOutput;
            }

            return totalBytesOutput;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!this.CanWrite) throw new NotSupportedException();

            if (!this.headerWritten)
            {
                this.EncryptHeader();
            }

            while (count > 0)
            {
                // Consume what's in the plaintextBbuffer first before processing new data
                var remainingPlaintextBufferCapacity = this.plaintextBuffer.Length - this.plaintextBufferPosition;
                var plaintextBufferIsFull = remainingPlaintextBufferCapacity == 0;
                var plaintextBufferIsEmpty = remainingPlaintextBufferCapacity == BlockLength;

                if (plaintextBufferIsFull)
                {
                    // Buffer is full, so process it first
                    this.EncryptPlainTextBuffer(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
                }
                else if (plaintextBufferIsEmpty)
                {
                    // Buffer is empty, so process as much as possible and store the remainder in the buffer
                    if (count > BlockLength)
                    {
                        // There is more than one block left to go so process it immediately and circumvent the buffer
                        var block = buffer.AsReadOnlySpan().Slice(offset, BlockLength);
                        this.EncryptBlock(block, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
                        count -= BlockLength;
                        offset += BlockLength;
                    }
                    else
                    {
                        // Store what's left in the buffer
                        Array.Copy(buffer, offset, this.plaintextBuffer, 0, count);
                        this.plaintextBufferPosition += count;
                        count = 0;
                        offset += count;
                    }
                }
                else
                {
                    // Attempt to fill the buffer first before processing
                    var bytesToRead = Math.Min(count, remainingPlaintextBufferCapacity);
                    Array.Copy(buffer, this.plaintextBuffer, bytesToRead);
                    this.plaintextBufferPosition += bytesToRead;
                    count -= bytesToRead;
                    offset += bytesToRead;
                }
            }
        }

        public override void Close()
        {
            if (!isClosed)
            {
                this.EncryptPlainTextBuffer(crypto_secretstream_xchacha20poly1305_TAG_FINAL);
                base.Close();
                Marshal.FreeHGlobal(this.state);
                isClosed = true;
            }
        }

        private void EncryptHeader()
        {
            this.stream.Write(this.headerBuffer);
            this.headerWritten = true;
        }

        private void EncryptPlainTextBuffer(byte tag)
        {
            if (!this.headerWritten)
            {
                this.EncryptHeader();
            }
            else
            {
                if (this.plaintextBufferPosition != 0)
                {
                    var block = this.plaintextBuffer
                        .AsReadOnlySpan()
                        .Slice(0, this.plaintextBufferPosition);

                    this.EncryptBlock(block, tag);
                }
            }
        }

        private void EncryptBlock(ReadOnlySpan<byte> block, byte tag)
        {
            var encryptionResult = crypto_secretstream_xchacha20poly1305_push(
                    this.state,
                    ref MemoryMarshal.GetReference(this.ciphertextBuffer.AsSpan()),
                    out var cipherTextLength,
                    in MemoryMarshal.GetReference(block),
                    (ulong)block.Length,
                    IntPtr.Zero,
                    0,
                    tag);

            if (encryptionResult != 0) throw new CryptographicException("encryption of block failed");

            this.stream.Write(this.ciphertextBuffer, 0, (int)cipherTextLength);
            this.plaintextBufferPosition = 0;
        }

        public bool VerifyEndOfCipherStream()
           => this.tagOfLastDecryptedBlock == crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    }
}