namespace XChaChaDotNet
{
    using System.Runtime.InteropServices;
    using System.IO;
    using System.Security.Cryptography;
    using System;
    using static SodiumInterop;

    public class XChaChaStream : XChaChaStreamBase
    {
        public XChaChaStream(Stream stream, ReadOnlySpan<byte> key, EncryptionMode encryptionMode)
            : base(stream, key, encryptionMode)
        {
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
    }
}