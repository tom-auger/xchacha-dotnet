namespace XChaChaDotNet
{
    using System.Runtime.InteropServices;
    using System.IO;
    using System.Security.Cryptography;
    using System;
    using static SodiumInterop;

    public class XChaChaStream : Stream
    {
        private readonly Stream stream;
        private readonly EncryptionMode encryptionMode;
        private readonly IntPtr state;

        private bool isClosed;
        private byte tagOfLastDecryptedBlock;

        private bool headerWritten;
        private byte[] headerBuffer = new byte[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

        public XChaChaStream(Stream stream, ReadOnlySpan<byte> key, EncryptionMode encryptionMode)
        {
            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
            this.encryptionMode = encryptionMode;

            if (key.Length != crypto_secretstream_xchacha20poly1305_KEYBYTES)
                throw new ArgumentException("key has invalid length", nameof(key));

            this.state = Marshal.AllocHGlobal(Marshal.SizeOf<crypto_secretstream_xchacha20poly1305_state>());

            int initResult;
            if (encryptionMode == EncryptionMode.Encrypt)
            {
                initResult = crypto_secretstream_xchacha20poly1305_init_push(this.state, this.headerBuffer, key.ToArray());
            }
            else
            {
                var bytesRead = this.stream.Read(this.headerBuffer);
                if (bytesRead != this.headerBuffer.Length)
                    throw new CryptographicException("invalid or corrupt header");

                initResult = crypto_secretstream_xchacha20poly1305_init_pull(this.state, this.headerBuffer, key.ToArray());
            }

            if (initResult != 0)
                throw new CryptographicException("crypto stream initialization failed");
        }

        public override bool CanRead =>
            this.encryptionMode == EncryptionMode.Decrypt &&
            !this.isClosed &&
            this.stream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite =>
            this.encryptionMode == EncryptionMode.Encrypt &&
            !this.isClosed &&
            this.stream.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
            if (this.encryptionMode == EncryptionMode.Encrypt && !this.headerWritten)
            {
                this.WriteHeader();
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!this.CanRead) throw new NotSupportedException();

            var inputSize = count + crypto_secretstream_xchacha20poly1305_ABYTES;
            Span<byte> inBuffer = new byte[inputSize];

            var bytesRead = this.stream.Read(inBuffer);

            var decryptResult = crypto_secretstream_xchacha20poly1305_pull(
                   this.state,
                   ref MemoryMarshal.GetReference(buffer.AsSpan()),
                   out var decryptedBlockLongLength,
                   out var tag,
                   in MemoryMarshal.GetReference(inBuffer),
                   (UInt64)bytesRead,
                   IntPtr.Zero,
                   0);

            if (decryptResult != 0) throw new CryptographicException("block is invalid or corrupt");
            this.tagOfLastDecryptedBlock = tag;

            return (int)decryptedBlockLongLength;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.EncryptBlock(buffer, offset, count, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        }

        public void WriteFinal(byte[] buffer, int offset, int count)
        {
            this.EncryptBlock(buffer, offset, count, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        }

        private void EncryptBlock(byte[] buffer, int offset, int count, byte tag)
        {
            if (!this.CanWrite) throw new NotSupportedException();

            if (!this.headerWritten)
            {
                this.WriteHeader();
            }

            if (count > 0)
            {
                var outputSize = count + crypto_secretstream_xchacha20poly1305_ABYTES;
                Span<byte> outBuffer = new byte[outputSize];

                var encryptionResult = crypto_secretstream_xchacha20poly1305_push(
                       this.state,
                       ref MemoryMarshal.GetReference(outBuffer),
                       out var _,
                       in MemoryMarshal.GetReference(buffer.AsReadOnlySpan()),
                       (ulong)count,
                       IntPtr.Zero,
                       0,
                       tag);

                if (encryptionResult != 0) throw new CryptographicException("encryption of block failed");

                this.stream.Write(outBuffer);
            }
        }

        private void WriteHeader()
        {
            this.stream.Write(this.headerBuffer);
            this.headerWritten = true;
        }

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
          => this.tagOfLastDecryptedBlock == crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    }
}