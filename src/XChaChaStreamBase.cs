namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    public abstract class XChaChaStreamBase : Stream
    {
        private protected readonly EncryptionMode encryptionMode;
        private protected readonly SecretStreamState state;
        private readonly bool leaveOpen;
        private protected readonly Stream stream;
        private protected readonly byte[] headerBuffer =
            new byte[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

        private protected bool headerWritten;
        private protected byte tagOfLastDecryptedBlock;


        protected XChaChaStreamBase(Stream stream, XChaChaKey key, EncryptionMode encryptionMode, bool leaveOpen)
        {
            Sodium.Initialize();

            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
            if (key == null) throw new ArgumentNullException(nameof(key));

            this.encryptionMode = encryptionMode;
            this.leaveOpen = leaveOpen;
            this.state = new SecretStreamState();

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

        public override bool CanRead =>
            this.encryptionMode == EncryptionMode.Decrypt &&
            this.stream != null &&
            this.stream.CanRead;

        public override bool CanWrite =>
            this.encryptionMode == EncryptionMode.Encrypt &&
            this.stream != null &&
            this.stream.CanWrite;

        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            this.ValidateParameters(buffer, offset, count);
            var destination = buffer.AsSpan().Slice(offset, count);
            return this.Read(destination);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.ValidateParameters(buffer, offset, count);
            var source = buffer.AsReadOnlySpan().Slice(offset, count);
            this.Write(source);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public bool VerifyEndOfCipherStream()
            => this.tagOfLastDecryptedBlock == crypto_secretstream_xchacha20poly1305_TAG_FINAL;

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
        protected override void Dispose(bool disposing)
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
            }
        }
        #endregion
    }
}