namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    /// <summary>
    /// Represents an XChaCha AEAD cipher based on the IETF specification of ChaCha20Poly1305 but with a 192 bit nonce.
    /// </summary>
    public class XChaChaAeadCipher : XChaChaSecretKeyCipher, IXChaChaAeadCipher
    {
        /// <summary>
        /// Encrypts the <paramref name="message"/> and writes computed ciphertext to <paramref name="ciphertext"/>.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="ciphertext">The buffer in which to write the ciphertext.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        /// <param name="additionalData">The associated data to use for computing the authentication tag.</param>
        public void Encrypt(
            ReadOnlySpan<byte> message,
            Span<byte> ciphertext,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData)
        {
            InternalEncrypt(message, ciphertext, key, nonce, additionalData);
        }

        /// <summary>
        /// Encrypts the <paramref name="message"/> and returns the computed ciphertext.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        /// <param name="additionalData">The associated data to use for computing the authentication tag.</param>
        /// <returns>The computed ciphertext.</returns>
        public byte[] Encrypt(
            ReadOnlySpan<byte> message,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData)
        {
            ValidateMaxMessageLength(message);
            var ciphertext = new byte[GetCipherTextLength(message.Length)];
            this.Encrypt(message, ciphertext, key, nonce, additionalData);
            return ciphertext;
        }

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <param name="additionalData">The associated data to use for computing the authentication tag.</param>
        public void Decrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData)
        {
            this.InternalDecrypt(ciphertext, message, key, nonce, additionalData);
        }

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// returns the decrypted message.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <param name="additionalData">The associated data to use for computing the authentication tag.</param>
        /// <returns>The decrypted message.</returns>
        public byte[] Decrypt(
            ReadOnlySpan<byte> ciphertext,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData)
        {
            var messageLength = GetPlaintextLength(ciphertext.Length);
            var message = new byte[messageLength];
            this.Decrypt(ciphertext, message, key, nonce, additionalData);
            return message;
        }

        /// <summary>
        /// Tries to decrypt the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <param name="additionalData">The associated data to use for computing the authentication tag.</param>
        /// <returns>Whether the decryption succeeded.</returns>
        public bool TryDecrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData)
        {
            try
            {
                this.InternalDecrypt(ciphertext, message, key, nonce, additionalData);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Calculates the size of the ciphertext for a given plaintext length.
        /// </summary>
        /// <param name="plaintextLength">The length of the plaintext.</param>
        /// <returns>The length of the ciphertext.</returns>
        public override int GetCipherTextLength(int plaintextLength) =>
            plaintextLength + crypto_aead_xchacha20poly1305_ietf_ABYTES;

        /// <summary>
        /// Calculates the size of the plaintext for a given ciphertext length.
        /// </summary>
        /// <param name="ciphertextLength">The length of the ciphertext.</param>
        /// <returns>The length of the plaintext.</returns>
        public override int GetPlaintextLength(int ciphertextLength) =>
            Math.Max(0, ciphertextLength - crypto_aead_xchacha20poly1305_ietf_ABYTES);

        private protected override int GetMaximumMessageSize() =>
            int.MaxValue - crypto_aead_xchacha20poly1305_ietf_ABYTES;

        private protected override void InternalEncrypt(
            ReadOnlySpan<byte> message,
            Span<byte> ciphertext,
            XChaChaKey key,
            XChaChaNonce nonce)
        {
            this.InternalEncrypt(message, ciphertext, key, nonce, ReadOnlySpan<byte>.Empty);
        }

        private protected override void InternalDecrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            XChaChaKey key,
            XChaChaNonce nonce)
        {
            this.InternalDecrypt(ciphertext, message, key, nonce, ReadOnlySpan<byte>.Empty);
        }

        private void InternalEncrypt(
            ReadOnlySpan<byte> message,
            Span<byte> ciphertext,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData)
        {
            ValidateEncryptParameters(message, ciphertext, nonce);
            // nsec is always null for the XChaCha AEAD construction, here we pass IntPtr.Zero.
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ref MemoryMarshal.GetReference(ciphertext),
                out var ciphertextLongLength,
                in MemoryMarshal.GetReference(message),
                (UInt64)message.Length,
                in MemoryMarshal.GetReference(additionalData),
                (UInt64)additionalData.Length,
                IntPtr.Zero,
                in nonce.Handle,
                key.Handle);
        }

        private void InternalDecrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData)
        {
            ValidateDecryptParameters(ciphertext, message, nonce);
            // nsec is always null for the XChaCha AEAD construction, here we pass IntPtr.Zero.
            var result = crypto_aead_xchacha20poly1305_ietf_decrypt(
                ref MemoryMarshal.GetReference(message),
                out var messageLength,
                IntPtr.Zero,
                in MemoryMarshal.GetReference(ciphertext),
                (UInt64)ciphertext.Length,
                in MemoryMarshal.GetReference(additionalData),
                (UInt64)additionalData.Length,
                in nonce.Handle,
                key.Handle);

            if (result != 0) throw new CryptographicException("decryption failed");
        }
    }
}