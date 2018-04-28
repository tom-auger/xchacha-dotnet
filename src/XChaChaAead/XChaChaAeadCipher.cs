namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    /// <summary>
    /// Represents an XChaCha AEAD cipher based on the IETF specification of ChaCha20Poly1305, but with a 192 bit nonce.
    /// </summary>
    public class XChaChaAeadCipher : IXChaChaAeadCipher
    {
        /// <summary>
        /// Encrypts the <paramref name="message"/> and writes computed ciphertext to <paramref name="ciphertext"/>.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="ciphertext">The buffer in which to write the ciphertext.</param>
        /// <param name="associatedData">The associated data to use for computing the authentication tag.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        public void Encrypt(
            ReadOnlySpan<byte> message,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> associatedData,
            XChaChaKey key,
            XChaChaNonce nonce)
        {
            ValidateEncryptParameters(message, ciphertext, nonce);
            // nsec is always null for the XChaCha AEAD construction, here we pass IntPtr.Zero.
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ref MemoryMarshal.GetReference(ciphertext),
                out var ciphertextLongLength,
                in MemoryMarshal.GetReference(message),
                (UInt64)message.Length,
                in MemoryMarshal.GetReference(associatedData),
                (UInt64)associatedData.Length,
                IntPtr.Zero,
                in nonce.Handle,
                key.Handle);
        }

        /// <summary>
        /// Encrypts the <paramref name="message"/> and writes computed ciphertext to <paramref name="ciphertext"/>.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="ciphertext">The buffer in which to write the ciphertext.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        public void Encrypt(ReadOnlySpan<byte> message, Span<byte> ciphertext, XChaChaKey key, XChaChaNonce nonce)
        {
            this.Encrypt(message, ciphertext, ReadOnlySpan<byte>.Empty, key, nonce);
        }

        /// <summary>
        /// Encrypts the <paramref name="message"/> and returns the computed ciphertext.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="associatedData">The associated data to use for computing the authentication tag.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        /// <returns>The computed ciphertext.</returns>
        public Span<byte> Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> associatedData, XChaChaKey key, XChaChaNonce nonce)
        {
            var cipherTextLength = GetCipherTextLength(message.Length);
            var cipherText = new byte[cipherTextLength];
            this.Encrypt(message, cipherText, associatedData, key, nonce);
            return cipherText;
        }

        /// <summary>
        /// Encrypts the <paramref name="message"/> and returns the computed ciphertext.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        /// <returns>The computed ciphertext.</returns>
        public Span<byte> Encrypt(ReadOnlySpan<byte> message, XChaChaKey key, XChaChaNonce nonce)
        {
            return this.Encrypt(message, ReadOnlySpan<byte>.Empty, key, nonce);
        }

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="associatedData">The associated data to use for computing the authentication tag.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        public void Decrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            ReadOnlySpan<byte> associatedData,
            XChaChaKey key,
            XChaChaNonce nonce)
        {
            ValidateDecryptParameters(ciphertext, message, nonce);
            var success = InternalDecrypt(ciphertext, message, associatedData, key, nonce);
            if (!success) throw new CryptographicException("decryption failed");
        }

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        public void Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> message, XChaChaKey key, XChaChaNonce nonce)
        {
            this.Decrypt(ciphertext, message, ReadOnlySpan<byte>.Empty, key, nonce);
        }

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// returns the decrypted message.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="associatedData">The associated data to use for computing the authentication tag.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <returns>The decrypted message.</returns>
        public Span<byte> Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, XChaChaKey key, XChaChaNonce nonce)
        {
            var messageLength = GetPlaintextLength(ciphertext.Length);
            var message = new byte[messageLength];
            this.Decrypt(ciphertext, message, associatedData, key, nonce);
            return message;
        }

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// returns the decrypted message.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <returns>The decrypted message.</returns>
        public Span<byte> Decrypt(ReadOnlySpan<byte> ciphertext, XChaChaKey key, XChaChaNonce nonce)
        {
            return this.Decrypt(ciphertext, ReadOnlySpan<byte>.Empty, key, nonce);
        }

        /// <summary>
        /// Tries to decrypt the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="associatedData">The associated data to use for computing the authentication tag.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <returns>Whether the decryption succeeded.</returns>
        public bool TryDecrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            ReadOnlySpan<byte> associatedData,
            XChaChaKey key,
            XChaChaNonce nonce)
        {
            try
            {
                return InternalDecrypt(ciphertext, message, associatedData, key, nonce);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Tries to decrypt the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <returns>Whether the decryption succeeded.</returns>
        public bool TryDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> message, XChaChaKey key, XChaChaNonce nonce)
        {
            return this.TryDecrypt(ciphertext, message, ReadOnlySpan<byte>.Empty, key, nonce);
        }

        /// <summary>
        /// Calculates the size of the ciphertext for a given plaintext length.
        /// </summary>
        /// <param name="plaintextLength">The length of the plaintext.</param>
        /// <returns>The length of the ciphertext.</returns>
        public static int GetCipherTextLength(int plaintextLength) =>
            plaintextLength + crypto_aead_xchacha20poly1305_ietf_ABYTES;

        /// <summary>
        /// Calculates the size of the plaintext for a given ciphertext length.
        /// </summary>
        /// <param name="ciphertextLength">The length of the ciphertext.</param>
        /// <returns>The length of the plaintext.</returns>
        public static int GetPlaintextLength(int ciphertextLength) =>
            Math.Max(0, ciphertextLength - crypto_aead_xchacha20poly1305_ietf_ABYTES);

        private static bool InternalDecrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            ReadOnlySpan<byte> associatedData,
            XChaChaKey key,
            XChaChaNonce nonce)
        {
            // nsec is always null for the XChaCha AEAD construction, here we pass IntPtr.Zero.
            var result = crypto_aead_xchacha20poly1305_ietf_decrypt(
                ref MemoryMarshal.GetReference(message),
                out var messageLength,
                IntPtr.Zero,
                in MemoryMarshal.GetReference(ciphertext),
                (UInt64)ciphertext.Length,
                in MemoryMarshal.GetReference(associatedData),
                (UInt64)associatedData.Length,
                in nonce.Handle,
                key.Handle);

            return result == 0;
        }

        private static void ValidateEncryptParameters(ReadOnlySpan<byte> message, Span<byte> ciphertext, XChaChaNonce nonce)
        {
            if (ciphertext.Length < GetCipherTextLength(message.Length))
                throw new ArgumentException($"{nameof(ciphertext)} buffer is not large enough");

            ValidateNonce(nonce);
        }

        private static void ValidateDecryptParameters(ReadOnlySpan<byte> ciphertext, Span<byte> message, XChaChaNonce nonce)
        {
            if (message.Length < GetPlaintextLength(ciphertext.Length))
                throw new ArgumentException($"{nameof(message)} buffer is not large enough");

            ValidateNonce(nonce);
        }

        private static void ValidateNonce(XChaChaNonce nonce)
        {
            if (nonce.IsEmpty)
                throw new ArgumentException($"{nameof(nonce)} is empty");
        }
    }
}