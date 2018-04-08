namespace XChaChaDotNet
{
    using System;
    using System.Buffers;
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
        private byte[] plaintextBuffer = ArrayPool<byte>.Shared.Rent(PlaintextBufferLength);
        private byte[] ciphertextBuffer = ArrayPool<byte>.Shared.Rent(CiphertextBufferLength);

        public XChaChaBufferedStream(Stream stream, XChaChaKey key, EncryptionMode encryptionMode)
            : base(stream, key, encryptionMode)
        {
        }

        public override int Read(Span<byte> destination)
        {
            if (!this.CanRead) throw new NotSupportedException();

            var totalBytesOutput = 0;
            while (destination.Length > 0)
            {
                // If there's any data left in the plaintextBuffer then output this first
                if (this.plaintextBufferPosition > 0)
                {
                    var numBytesLeftInPlaintextBuffer =
                        PlaintextBufferLength - this.plaintextBufferPosition;

                    var numberOfBufferedBytesToOutput = Math.Min(numBytesLeftInPlaintextBuffer, destination.Length);

                    this.plaintextBuffer
                        .AsReadOnlySpan()
                        .Slice(this.plaintextBufferPosition, numberOfBufferedBytesToOutput)
                        .CopyTo(destination);

                    this.plaintextBufferPosition += numberOfBufferedBytesToOutput;
                    destination = destination.Slice(numberOfBufferedBytesToOutput);
                    totalBytesOutput += numberOfBufferedBytesToOutput;

                    if (this.plaintextBufferPosition == PlaintextBufferLength)
                        this.plaintextBufferPosition = 0;

                    continue;
                }

                // Read the next block from the stream
                var bytesRead = this.stream.Read(this.ciphertextBuffer, 0, CiphertextBufferLength);

                // Stop if we've already reached the end of the stream
                if (bytesRead == 0) break;

                // Decrypt the next block
                var decryptResult = crypto_secretstream_xchacha20poly1305_pull(
                    this.state.Handle,
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
                var numberOfBytesToOutput = Math.Min(destination.Length, decryptedBlockLength);

                this.plaintextBuffer
                    .AsReadOnlySpan()
                    .Slice(0, numberOfBytesToOutput)
                    .CopyTo(destination);

                this.plaintextBufferPosition =
                    numberOfBytesToOutput < decryptedBlockLength
                    ? numberOfBytesToOutput
                    : 0;

                destination = destination.Slice(numberOfBytesToOutput);
                totalBytesOutput += numberOfBytesToOutput;
            }

            return totalBytesOutput;
        }

        public override void Write(ReadOnlySpan<byte> source)
        {
            if (!this.CanWrite) throw new NotSupportedException();

            if (!this.headerWritten)
            {
                this.WriteHeader();
            }

            while (source.Length > 0)
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
                    if (source.Length > PlaintextBufferLength)
                    {
                        // There is more than one block left to go so process it immediately and circumvent the buffer
                        var block = source.Slice(0, PlaintextBufferLength);
                        this.EncryptBlock(block, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

                        source = source.Slice(PlaintextBufferLength);
                    }
                    else
                    {
                        // Store what's left in the buffer
                        source.CopyTo(this.plaintextBuffer);
                        this.plaintextBufferPosition += source.Length;
                        source = ReadOnlySpan<byte>.Empty;
                    }
                }
                else
                {
                    // Attempt to fill the buffer first before processing
                    var bytesToStore = Math.Min(source.Length, remainingPlaintextBufferCapacity);
                    source.Slice(0, bytesToStore).CopyTo(this.plaintextBuffer);

                    this.plaintextBufferPosition += bytesToStore;
                    source = source.Slice(bytesToStore);
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
                this.state.Dispose();
                ArrayPool<byte>.Shared.Return(this.plaintextBuffer);
                ArrayPool<byte>.Shared.Return(this.ciphertextBuffer);
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
                    this.state.Handle,
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