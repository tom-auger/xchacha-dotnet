namespace XChaChaDotNet
{
    using System;
    using System.Buffers;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    public class XChaChaStream : XChaChaStreamBase
    {
        public XChaChaStream(Stream stream, ReadOnlySpan<byte> key, EncryptionMode encryptionMode)
            : base(stream, key, encryptionMode)
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var inputSize = count + crypto_secretstream_xchacha20poly1305_ABYTES;
            var ciphertextBuffer = ArrayPool<byte>.Shared.Rent(inputSize);

            try
            {
                if (!this.CanRead) throw new NotSupportedException();

                var bytesRead = this.stream.Read(ciphertextBuffer, 0, inputSize);
                var decryptResult = crypto_secretstream_xchacha20poly1305_pull(
                       this.state,
                       ref MemoryMarshal.GetReference(buffer.AsSpan()),
                       out var decryptedBlockLongLength,
                       out var tag,
                       in MemoryMarshal.GetReference(ciphertextBuffer.AsReadOnlySpan()),
                       (UInt64)bytesRead,
                       IntPtr.Zero,
                       0);

                if (decryptResult != 0) throw new CryptographicException("block is invalid or corrupt");
                this.tagOfLastDecryptedBlock = tag;

                return (int)decryptedBlockLongLength;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(ciphertextBuffer);
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.EncryptBlock(buffer, offset, count, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        }

        public void WriteFinal(byte[] buffer, int offset, int count)
        {
            this.EncryptBlock(buffer, offset, count, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        }

        public void WriteFinal(ReadOnlySpan<byte> buffer)
        {
            var plaintextBuffer = ArrayPool<byte>.Shared.Rent(buffer.Length);
            try
            {
                buffer.CopyTo(plaintextBuffer);
                this.WriteFinal(plaintextBuffer, 0, buffer.Length);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(plaintextBuffer);
            }
        }

        public override void Flush()
        {
            if (this.encryptionMode == EncryptionMode.Encrypt && !this.headerWritten)
            {
                this.WriteHeader();
            }
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
                var ciphertextBuffer = ArrayPool<byte>.Shared.Rent(outputSize);

                try
                {
                    var encryptionResult = crypto_secretstream_xchacha20poly1305_push(
                           this.state,
                           ref MemoryMarshal.GetReference(ciphertextBuffer.AsSpan()),
                           out var ciphertextLength,
                           in MemoryMarshal.GetReference(buffer.AsReadOnlySpan()),
                           (ulong)count,
                           IntPtr.Zero,
                           0,
                           tag);

                    if (encryptionResult != 0) throw new CryptographicException("encryption of block failed");

                    this.stream.Write(ciphertextBuffer, 0, (int)ciphertextLength);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(ciphertextBuffer);
                }
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