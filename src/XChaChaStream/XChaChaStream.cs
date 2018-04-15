namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    public class XChaChaStream : XChaChaStreamBase
    {
        public XChaChaStream(Stream stream, XChaChaKey key, EncryptionMode encryptionMode, bool leaveOpen = false)
            : base(stream, key, encryptionMode, leaveOpen)
        {
        }

        public override int Read(Span<byte> destination)
        {
            var inputSize = CalculateCiphertextLength(destination.Length);
            using (var ciphertextBuffer = new RentedArray(inputSize))
            {
                if (!this.CanRead) throw new NotSupportedException();

                var bytesRead = this.stream.Read(ciphertextBuffer.AsSpan());
                var decryptResult = crypto_secretstream_xchacha20poly1305_pull(
                       this.state.Handle,
                       ref MemoryMarshal.GetReference(destination),
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
        }

        public override void Write(ReadOnlySpan<byte> source)
        {
            this.EncryptBlock(source, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        }

        public void WriteFinal(byte[] buffer, int offset, int count)
        {
            this.ValidateParameters(buffer, offset, count);
            var source = buffer.AsSpan(offset, count);
            this.WriteFinal(source);
        }

        public void WriteFinal(ReadOnlySpan<byte> source)
        {
            this.EncryptBlock(source, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        }

        public override void Flush()
        {
            if (this.encryptionMode == EncryptionMode.Encrypt && !this.headerWritten)
            {
                this.WriteHeader();
            }
        }

        private void EncryptBlock(ReadOnlySpan<byte> source, byte tag)
        {
            if (!this.CanWrite) throw new NotSupportedException();

            if (!this.headerWritten)
            {
                this.WriteHeader();
            }

            var count = source.Length;
            if (count > 0)
            {
                var outputSize = CalculateCiphertextLength(count);
                using (var ciphertextBuffer = new RentedArray(outputSize))
                {
                    var encryptionResult = crypto_secretstream_xchacha20poly1305_push(
                           this.state.Handle,
                           ref MemoryMarshal.GetReference(ciphertextBuffer.AsSpan()),
                           out var ciphertextLength,
                           in MemoryMarshal.GetReference(source),
                           (ulong)count,
                           IntPtr.Zero,
                           0,
                           tag);

                    if (encryptionResult != 0) throw new CryptographicException("encryption of block failed");

                    this.stream.Write(ciphertextBuffer.AsReadOnlySpan(0, (int)ciphertextLength));
                }
            }
        }

        private void WriteHeader()
        {
            this.stream.Write(this.headerBuffer);
            this.headerWritten = true;
        }
    }
}