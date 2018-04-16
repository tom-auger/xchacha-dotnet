namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    public class XChaChaBufferedStream : XChaChaStreamBase
    {
        // Default plaintext buffer length 128KB
        private const int DefaultPlaintextBufferLength = 128 * 1024;

        private int plaintextBufferPosition;
        private readonly RentedArray plaintextBuffer;
        private readonly RentedArray ciphertextBuffer;

        public XChaChaBufferedStream(
            Stream stream,
            XChaChaKey key,
            EncryptionMode encryptionMode,
            bool leaveOpen = false)
            : base(stream, key, encryptionMode, leaveOpen)
        {
            this.plaintextBuffer = new RentedArray(DefaultPlaintextBufferLength);
            this.ciphertextBuffer = new RentedArray(CalculateCiphertextLength(DefaultPlaintextBufferLength));
        }

        public XChaChaBufferedStream(
            Stream stream,
            XChaChaKey key,
            EncryptionMode encryptionMode,
            int bufferLength,
            bool leaveOpen = false)
            : base(stream, key, encryptionMode, leaveOpen)
        {
            this.plaintextBuffer = new RentedArray(bufferLength);
            this.ciphertextBuffer = new RentedArray(CalculateCiphertextLength(bufferLength));
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
                        this.plaintextBuffer.Length - this.plaintextBufferPosition;

                    var numberOfBufferedBytesToOutput = Math.Min(numBytesLeftInPlaintextBuffer, destination.Length);

                    this.plaintextBuffer
                        .AsReadOnlySpan(this.plaintextBufferPosition, numberOfBufferedBytesToOutput)
                        .CopyTo(destination);

                    this.plaintextBufferPosition += numberOfBufferedBytesToOutput;
                    destination = destination.Slice(numberOfBufferedBytesToOutput);
                    totalBytesOutput += numberOfBufferedBytesToOutput;

                    if (this.plaintextBufferPosition == this.plaintextBuffer.Length)
                        this.plaintextBufferPosition = 0;

                    continue;
                }

                // Read the next block from the stream
                var bytesRead = this.stream.Read(this.ciphertextBuffer.AsSpan());

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
                    ref MemoryMarshal.GetReference(ReadOnlySpan<byte>.Empty),
                    0);

                // Throw an error if the decrypt failed
                if (decryptResult != 0) throw new CryptographicException("block is invalid or corrupt");

                // Remember the tag in case we want to verify it later
                this.tagOfLastDecryptedBlock = tag;

                // Output the plaintext
                var decryptedBlockLength = (int)decryptedBlockLongLength;
                var numberOfBytesToOutput = Math.Min(destination.Length, decryptedBlockLength);

                this.plaintextBuffer
                    .AsReadOnlySpan(0, numberOfBytesToOutput)
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
                var remainingPlaintextBufferCapacity = this.plaintextBuffer.Length - this.plaintextBufferPosition;
                var plaintextBufferIsFull = remainingPlaintextBufferCapacity == 0;
                var plaintextBufferIsEmpty = remainingPlaintextBufferCapacity == this.plaintextBuffer.Length;

                if (plaintextBufferIsFull)
                {
                    // Buffer is full, so process it first
                    this.EncryptPlainTextBuffer(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
                }
                else if (plaintextBufferIsEmpty)
                {
                    // Buffer is empty, so process as much as possible and store the remainder in the buffer
                    if (source.Length > this.plaintextBuffer.Length)
                    {
                        // There is more than one block left to go so process it immediately and circumvent the buffer
                        var block = source.Slice(0, this.plaintextBuffer.Length);
                        this.EncryptBlock(block, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

                        source = source.Slice(this.plaintextBuffer.Length);
                    }
                    else
                    {
                        // Store what's left in the buffer
                        source.CopyTo(this.plaintextBuffer.AsSpan());
                        this.plaintextBufferPosition += source.Length;
                        source = ReadOnlySpan<byte>.Empty;
                    }
                }
                else
                {
                    // Attempt to fill the buffer first before processing
                    var bytesToStore = Math.Min(source.Length, remainingPlaintextBufferCapacity);
                    source.Slice(0, bytesToStore).CopyTo(this.plaintextBuffer.AsSpan());

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
                        .AsReadOnlySpan(0, this.plaintextBufferPosition);

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
                    ref MemoryMarshal.GetReference(ReadOnlySpan<byte>.Empty),
                    0,
                    tag);

            if (encryptionResult != 0) throw new CryptographicException("encryption of block failed");

            this.stream.Write(this.ciphertextBuffer.AsReadOnlySpan(0, (int)cipherTextLength));
            this.plaintextBufferPosition = 0;
        }

        #region IDisposable
        protected override void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                try
                {
                    if (disposing && this.stream != null)
                    {
                        if (this.encryptionMode == EncryptionMode.Encrypt)
                            this.EncryptPlainTextBuffer(crypto_secretstream_xchacha20poly1305_TAG_FINAL);
                    }
                }
                finally
                {
                    try
                    {
                        if (disposing)
                        {
                            this.plaintextBuffer?.Dispose();
                            this.ciphertextBuffer?.Dispose();
                        }
                    }
                    finally
                    {
                        base.Dispose(disposing);
                    }
                }
            }
        }
        #endregion
    }
}