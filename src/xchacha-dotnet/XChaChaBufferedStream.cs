namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    public class XChaChaBufferedStream : XChaChaStreamBase
    {
        private const int PlaintextBufferLength = 128 * 1024;
        private const int CiphertextBufferLength =
            PlaintextBufferLength + crypto_secretstream_xchacha20poly1305_ABYTES;

        private int plaintextBufferPosition;
        private byte[] plaintextBuffer = new byte[PlaintextBufferLength];
        private byte[] ciphertextBuffer = new byte[CiphertextBufferLength];

        public XChaChaBufferedStream(Stream stream, ReadOnlySpan<byte> key, EncryptionMode encryptionMode)
            : base(stream, key, encryptionMode)
        {
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
                        PlaintextBufferLength - this.plaintextBufferPosition;

                    var numberOfBufferedBytesToOutput = Math.Min(numBytesLeftInPlaintextBuffer, count);

                    Array.Copy(this.plaintextBuffer, this.plaintextBufferPosition, buffer, offset, numberOfBufferedBytesToOutput);

                    this.plaintextBufferPosition += numberOfBufferedBytesToOutput;
                    offset += numberOfBufferedBytesToOutput;
                    count -= numberOfBufferedBytesToOutput;
                    totalBytesOutput += numberOfBufferedBytesToOutput;

                    if (this.plaintextBufferPosition == PlaintextBufferLength)
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

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!this.CanWrite) throw new NotSupportedException();

            if (!this.headerWritten)
            {
                this.WriteHeader();
            }

            while (count > 0)
            {
                // Consume what's in the plaintextBbuffer first before processing new data
                var remainingPlaintextBufferCapacity = PlaintextBufferLength - this.plaintextBufferPosition;
                var plaintextBufferIsFull = remainingPlaintextBufferCapacity == 0;
                var plaintextBufferIsEmpty = remainingPlaintextBufferCapacity == PlaintextBufferLength;

                if (plaintextBufferIsFull)
                {
                    // Buffer is full, so process it first
                    this.EncryptPlainTextBuffer(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
                }
                else if (plaintextBufferIsEmpty)
                {
                    // Buffer is empty, so process as much as possible and store the remainder in the buffer
                    if (count > PlaintextBufferLength)
                    {
                        // There is more than one block left to go so process it immediately and circumvent the buffer
                        var block = buffer.AsReadOnlySpan().Slice(offset, PlaintextBufferLength);
                        this.EncryptBlock(block, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
                        count -= PlaintextBufferLength;
                        offset += PlaintextBufferLength;
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

        private void WriteHeader()
        {
            this.stream.Write(this.headerBuffer);
            this.headerWritten = true;
        }

        private void EncryptPlainTextBuffer(byte tag)
        {
            if (!this.headerWritten)
            {
                this.WriteHeader();
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
    }
}