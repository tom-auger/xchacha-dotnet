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
        private readonly EncryptionMode mode;
        private readonly IntPtr state;

        private bool isClosed;

        public XChaChaStream(Stream stream, ReadOnlySpan<byte> key, EncryptionMode mode)
        {
            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
            this.mode = mode;

            if (key.Length != crypto_secretstream_xchacha20poly1305_KEYBYTES)
                throw new ArgumentException("key has invalid length", nameof(key));

            this.state = Marshal.AllocHGlobal(Marshal.SizeOf<crypto_secretstream_xchacha20poly1305_state>());
            var headerBuffer = new byte[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
            var initResult =
                mode == EncryptionMode.Encrypt
                ? crypto_secretstream_xchacha20poly1305_init_push(this.state, headerBuffer, key.ToArray())
                : crypto_secretstream_xchacha20poly1305_init_pull(this.state, headerBuffer, key.ToArray());

            if (initResult != 0)
                throw new CryptographicException("crypto stream initialization failed");
        }

        public override bool CanRead => this.mode == EncryptionMode.Decrypt && this.stream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => this.mode == EncryptionMode.Encrypt && this.stream.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
            throw new System.NotImplementedException();
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
                   out var _,
                   in MemoryMarshal.GetReference(inBuffer),
                   (UInt64)bytesRead,
                   IntPtr.Zero,
                   0);

            if (decryptResult != 0) throw new CryptographicException("block is invalid or corrupt");

            return (int)decryptedBlockLongLength;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.InternalWrite(buffer, offset, count, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        }

        public void WriteFinal(byte[] buffer, int offset, int count)
        {
            this.InternalWrite(buffer, offset, count, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        }

        private void InternalWrite(byte[] buffer, int offset, int count, byte tag)
        {
            if (!this.CanWrite) throw new NotSupportedException();
            
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

        public override void Close()
        {
            if (!isClosed)
            {
                base.Close();
                Marshal.FreeHGlobal(this.state);
                isClosed = true;
            }
        }
    }
}