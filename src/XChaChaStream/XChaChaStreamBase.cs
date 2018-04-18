namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    /// <summary>
    /// Base class for XChaCha stream implementations.
    /// </summary>
    public abstract class XChaChaStreamBase : Stream
    {
        private protected readonly EncryptionMode encryptionMode;
        private protected readonly XChaChaStreamState state;
        private readonly bool leaveOpen;
        private protected readonly Stream stream;
        private protected readonly byte[] headerBuffer =
            new byte[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

        private protected bool headerWritten;
        private protected byte tagOfLastDecryptedBlock;
        private protected bool disposed;

        private protected XChaChaStreamBase(Stream stream, XChaChaKey key, EncryptionMode encryptionMode, bool leaveOpen)
        {
            Sodium.Initialize();

            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
            if (key == null) throw new ArgumentNullException(nameof(key));

            this.encryptionMode = encryptionMode;
            this.leaveOpen = leaveOpen;
            this.state = new XChaChaStreamState();

            int initResult;
            if (encryptionMode == EncryptionMode.Encrypt)
            {
                initResult = crypto_secretstream_xchacha20poly1305_init_push(
                    this.state.Handle,
                    this.headerBuffer,
                    key.Handle);
            }
            else
            {
                var bytesRead = this.stream.Read(this.headerBuffer);
                if (bytesRead != this.headerBuffer.Length)
                    throw new CryptographicException("invalid or corrupt header");

                initResult = crypto_secretstream_xchacha20poly1305_init_pull(
                    this.state.Handle,
                    this.headerBuffer,
                    key.Handle);
            }

            if (initResult != 0)
                throw new CryptographicException("crypto stream initialization failed");
        }

        /// <summary>
        /// Whether reading is supported.
        /// </summary>
        public override bool CanRead =>
            this.encryptionMode == EncryptionMode.Decrypt &&
            this.stream != null &&
            this.stream.CanRead;

        /// <summary>
        /// Whether writing is supported.
        /// </summary>
        public override bool CanWrite =>
            this.encryptionMode == EncryptionMode.Encrypt &&
            this.stream != null &&
            this.stream.CanWrite;

        /// <summary>
        /// Whether seeking is supported. This is always false.
        /// </summary>
        public override bool CanSeek => false;

        /// <summary>
        /// This property is not supported and throws a <see cref="NotSupportedException" />.
        /// </summary>
        /// <returns></returns>
        public override long Length => throw new NotSupportedException();

        /// <summary>
        /// This property is not supported and will throw a <see cref="NotSupportedException" />.
        /// </summary>
        /// <returns></returns>
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        /// <summary>
        /// Decrypts the inner stream and populates <paramref name="buffer"/> with at most 
        /// <paramref name="count" /> bytes of the resulting plaintext, starting from <paramref name="offset"/>.
        /// </summary>
        /// <param name="buffer">The buffer where plaintext will be output to.</param>
        /// <param name="offset">The offset within the buffer to begin writing the plaintext.</param>
        /// <param name="count">The maximum number of bytes to output.</param>
        /// <returns>The number of bytes written to <paramref name="buffer" />.</returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            this.ValidateParameters(buffer, offset, count);
            var destination = buffer.AsSpan().Slice(offset, count);
            return this.Read(destination);
        }

        /// <summary>
        /// Encrypts the <paramref name="buffer"/> and writes the resulting ciphertext to the inner stream.
        /// </summary>
        /// <param name="buffer">The plaintext to encrypt.</param>
        /// <param name="offset">The offset within the buffer to begin using.</param>
        /// <param name="count">The number of bytes to read from the offset.</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            this.ValidateParameters(buffer, offset, count);
            var source = buffer.AsSpan(offset, count);
            this.Write(source);
        }

        /// <summary>
        /// This method is not supported and will throw a <see cref="NotSupportedException" />.
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="origin"></param>
        /// <returns></returns>
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        /// <summary>
        /// This method is not supported and will throw a <see cref="NotSupportedException" />.
        /// </summary>
        /// <param name="value"></param>
        public override void SetLength(long value) => throw new NotSupportedException();

        /// <summary>
        /// When the encryption mode is Decrypt, verifies that the last block decrypted was appended with a final tag.
        /// Use this to confirm that the end of the ciphertext has been reached.
        /// </summary>
        /// <returns>Whether the last decrypted block was appended with a final tag.</returns>
        public bool VerifyEndOfMessage() => 
            this.tagOfLastDecryptedBlock == crypto_secretstream_xchacha20poly1305_TAG_FINAL;

        private protected static int CalculateCiphertextLength(int plaintextLength)
        {
            return plaintextLength + crypto_secretstream_xchacha20poly1305_ABYTES;
        }

        private protected void ValidateParameters(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset));

            if (count < 0)
                throw new ArgumentOutOfRangeException(nameof(count));

            if (buffer.Length - offset < count)
                throw new ArgumentException($"{nameof(buffer)} length, {nameof(offset)}, and {nameof(count)} are inconsistent");
        }

        #region IDisposable
        /// <summary>
        /// Disposes of all resources.
        /// </summary>
        /// <param name="disposing">True if called from <see cref="Dispose"/>.</param>
        protected override void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                try
                {
                    if (disposing)
                    {
                        this.state?.Dispose();

                        if (!this.leaveOpen)
                            this.stream?.Dispose();
                    }
                }
                finally
                {
                    base.Dispose(disposing);
                    this.disposed = true;
                }
            }
        }
        #endregion
    }
}