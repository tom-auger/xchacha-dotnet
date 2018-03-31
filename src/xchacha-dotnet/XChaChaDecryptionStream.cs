namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    public class XChaChaDecryptionStream : Stream
    {
        private const int BlockLength = 128 * 1024;
        private const int EncryptedBlockLength = BlockLength + crypto_secretstream_xchacha20poly1305_ABYTES;

        private readonly Stream stream;
        private readonly IntPtr state;

        private bool isClosed;
        private byte[] inBuffer = new byte[EncryptedBlockLength];
        private int outBufferPosition;
        private byte[] outBuffer = new byte[BlockLength];
        private byte tagOfLastProcessedBlock;

        public XChaChaDecryptionStream(Stream stream, ReadOnlySpan<byte> key)
        {
            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));

            if (key.Length != crypto_secretstream_xchacha20poly1305_KEYBYTES)
                throw new ArgumentException("key has invalid length", nameof(key));

            this.state =
                Marshal.AllocHGlobal(Marshal.SizeOf<crypto_secretstream_xchacha20poly1305_state>());

            // The length of the header is smaller than EncryptedBlockLength so it will fit
            var bytesRead = this.stream.Read(this.inBuffer, 0, crypto_secretstream_xchacha20poly1305_HEADERBYTES);
            if (bytesRead != crypto_secretstream_xchacha20poly1305_HEADERBYTES)
                throw new CryptographicException("invalid or corrupt header");

            var initResult = crypto_secretstream_xchacha20poly1305_init_pull(this.state, this.inBuffer, key.ToArray());

            if (initResult != 0)
                throw new CryptographicException("crypto stream initialization failed");
        }

        public override bool CanRead => !this.isClosed && this.stream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
            return;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!this.stream.CanRead) throw new NotSupportedException();

            var totalBytesOutput = 0;
            while (count > 0)
            {
                // If there's any data left in the outBuffer then output this first
                if (this.outBufferPosition > 0)
                {
                    var numberOfBytesLeftInOutBuffer =
                        this.outBuffer.Length - this.outBufferPosition;

                    var numberOfBufferedBytesToOutput = Math.Min(numberOfBytesLeftInOutBuffer, count);

                    Array.Copy(this.outBuffer, this.outBufferPosition, buffer, offset, numberOfBufferedBytesToOutput);

                    this.outBufferPosition += numberOfBufferedBytesToOutput;
                    offset += numberOfBufferedBytesToOutput;
                    count -= numberOfBufferedBytesToOutput;
                    totalBytesOutput += numberOfBufferedBytesToOutput;

                    if (this.outBufferPosition == this.outBuffer.Length)
                        this.outBufferPosition = 0;

                    continue;
                }

                // Read the next block from the stream
                var bytesRead = this.stream.Read(this.inBuffer);

                // Stop if we've already reached the end of the stream
                if (bytesRead == 0) break;

                // Decrypt the next block
                var decryptResult = crypto_secretstream_xchacha20poly1305_pull(
                    this.state,
                    ref MemoryMarshal.GetReference(this.outBuffer.AsSpan()),
                    out var decryptedBlockLongLength,
                    out var tag,
                    in MemoryMarshal.GetReference(this.inBuffer.AsReadOnlySpan()),
                    (UInt64)bytesRead,
                    IntPtr.Zero,
                    0);

                // Throw an error if the decrypt failed
                if (decryptResult != 0) throw new CryptographicException("block is invalid or corrupt");

                // Remember the tag in case we want to verify it later
                this.tagOfLastProcessedBlock = tag;

                // Output the plaintext
                var decryptedBlockLength = (int)decryptedBlockLongLength;
                var numberOfBytesToOutput = Math.Min(count, decryptedBlockLength);
                Array.Copy(this.outBuffer, 0, buffer, offset, numberOfBytesToOutput);

                this.outBufferPosition =
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

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException("decryption stream is read only");

        public override void Close()
        {
            if (!isClosed)
            {
                base.Close();
                Marshal.FreeHGlobal(this.state);
                isClosed = true;
            }
        }

        public bool VerifyEndOfCipherStream()
            => this.tagOfLastProcessedBlock == crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    }
}