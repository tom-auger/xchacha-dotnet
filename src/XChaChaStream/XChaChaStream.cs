namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    /// <summary>
    /// Represents an XChaCha stream cipher.
    /// </summary>
    public class XChaChaStream : XChaChaStreamBase
    {
        /// <summary>
        /// Creates a new instance.
        /// </summary>
        /// <param name="stream">When encrypting, the stream to write the ciphertext to. When decrypting, the stream to read the ciphertext from.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="encryptionMode">Whether the stream will be used for encryption or decryption.</param>
        /// <param name="leaveOpen">Whether to leave the <paramref name="stream"/> open.</param>
        public XChaChaStream(Stream stream, XChaChaKey key, EncryptionMode encryptionMode, bool leaveOpen = false)
            : base(stream, key, encryptionMode, leaveOpen)
        {
        }

        /// <summary>
        /// Decrypts the inner stream and populates <paramref name="destination"/> with the resulting plaintext.
        /// </summary>
        /// <param name="destination">The buffer where the plaintext will be output to.</param>
        /// <param name="additionalData">Additional data to use when verify the authentication tag.</param>
        /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
        public int Read(Span<byte> destination, ReadOnlySpan<byte> additionalData)
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
                       ref MemoryMarshal.GetReference(additionalData),
                       (UInt64)additionalData.Length);

                if (decryptResult != 0) throw new CryptographicException("block is invalid or corrupt");
                this.tagOfLastDecryptedBlock = tag;

                return (int)decryptedBlockLongLength;
            }
        }
        
        /// <summary>
        /// Decrypts the inner stream and populates <paramref name="destination"/> with the resulting plaintext.
        /// </summary>
        /// <param name="destination">The buffer where the plaintext will be output to.</param>
        /// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
        public override int Read(Span<byte> destination)
        {
            return this.Read(destination, ReadOnlySpan<byte>.Empty);
        }

        /// <summary>
        /// Encrypts the <paramref name="source"/> and writes the resulting ciphertext to the inner stream,
        /// with the expectation that more data will be written. If no subsequent data will be written, use 
        /// <see cref="WriteFinal(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
        /// </summary>
        /// <param name="source">The plaintext to encrypt.</param>
        /// <param name="additionalData">Additional data to use when computing the authentication tag.</param>
        public void Write(ReadOnlySpan<byte> source, ReadOnlySpan<byte> additionalData)
        {
            this.EncryptBlock(source, additionalData, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

        }

        /// <summary>
        /// Encrypts the <paramref name="source"/> and writes the resulting ciphertext to the inner stream,
        /// with the expectation that more data will be written. If no subsequent data will be written, use 
        /// <see cref="WriteFinal(ReadOnlySpan{byte})"/>.
        /// </summary>
        /// <param name="source">The plaintext to encrypt.</param>
        public override void Write(ReadOnlySpan<byte> source)
        {
            this.Write(source, ReadOnlySpan<byte>.Empty);
        }

        /// <summary>
        /// Encrypts the <paramref name="buffer"/> and writes the resulting ciphertext to the inner stream,
        /// appending a final tag to the end of the block.
        /// Only call this if no more data will be written, otherwise use 
        /// <see cref="XChaChaStreamBase.Write(byte[], int, int)"/>.
        /// </summary>
        /// <param name="buffer">The plaintext to encrypt.</param>
        /// <param name="offset">The offset within the buffer to begin using.</param>
        /// <param name="count">The number of bytes to read from the offset.</param>
        public void WriteFinal(byte[] buffer, int offset, int count)
        {
            this.ValidateParameters(buffer, offset, count);
            var source = buffer.AsSpan(offset, count);
            this.WriteFinal(source);
        }

        /// <summary>
        /// Encrypts the <paramref name="source"/> and writes the resulting ciphertext to the inner stream,
        /// appending a final tag to the end of the block.
        /// Only call this if no more data will be written, otherwise use <see cref="Write(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
        /// </summary>
        /// <param name="source">The plaintext to encrypt.</param>
        /// <param name="additionalData">Additional data to use when computing the authentication tag.</param>
        public void WriteFinal(ReadOnlySpan<byte> source, ReadOnlySpan<byte> additionalData)
        {
            this.EncryptBlock(source, additionalData, crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        }

        /// <summary>
        /// Encrypts the <paramref name="source"/> and writes the resulting ciphertext to the inner stream,
        /// appending a final tag to the end of the block.
        /// Only call this if no more data will be written, otherwise use <see cref="Write(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>.
        /// </summary>
        /// <param name="source">The plaintext to encrypt.</param>
        public void WriteFinal(ReadOnlySpan<byte> source)
        {
            this.WriteFinal(source, ReadOnlySpan<byte>.Empty);
        }

        /// <summary>
        /// When the encryption mode is Encrypt, writes any data remaining in the internal buffer to the stream.
        /// </summary>
        public override void Flush()
        {
            if (this.encryptionMode == EncryptionMode.Encrypt && !this.headerWritten)
            {
                this.WriteHeader();
            }
        }

        private void EncryptBlock(ReadOnlySpan<byte> source, ReadOnlySpan<byte> additionalData, byte tag)
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
                           ref MemoryMarshal.GetReference(additionalData),
                           (UInt64)additionalData.Length,
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