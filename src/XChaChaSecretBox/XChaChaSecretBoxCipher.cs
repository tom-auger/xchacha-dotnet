﻿namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    /// <summary>
    /// Represents the xchacha_secret_box construction. This is based on the NaCl crypto_secretbox_xsalsa20poly1305 
    /// construction but uses xchacha rather than xsalsa.
    /// </summary>
    public class XChaChaSecretBoxCipher : IXChaChaSecretBoxCipher
    {
        /// <summary>
        /// Encrypts the <paramref name="message"/> and writes computed ciphertext to <paramref name="ciphertext"/>.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="ciphertext">The buffer in which to write the ciphertext.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        public void Encrypt(ReadOnlySpan<byte> message, Span<byte> ciphertext, XChaChaKey key, XChaChaNonce nonce)
        {
            ValidateEncryptParameters(message, ciphertext, nonce);
            crypto_secretbox_xchacha20poly1305_easy(
                ref MemoryMarshal.GetReference(ciphertext),
                in MemoryMarshal.GetReference(message),
                (UInt64)message.Length,
                in nonce.Handle,
                key.Handle);
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
            var cipherTextLength = GetCipherTextLength(message.Length);
            var cipherText = new byte[cipherTextLength];
            this.Encrypt(message, cipherText, key, nonce);
            return cipherText;
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
            ValidateDecryptParameters(ciphertext, message, nonce);
            var success = this.InternalDecrypt(ciphertext, message, key, nonce);
            if (!success) throw new CryptographicException("decryption failed");
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
            var messageLength = GetPlaintextLength(ciphertext.Length);
            var message = new byte[messageLength];
            this.Decrypt(ciphertext, message, key, nonce);
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
        /// <returns>Whether the decryption succeeded.</returns>
        public bool TryDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> message, XChaChaKey key, XChaChaNonce nonce)
        {
            try
            {
                return this.InternalDecrypt(ciphertext, message, key, nonce);
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
        public static int GetCipherTextLength(int plaintextLength) =>
            plaintextLength + crypto_secretbox_xchacha20poly1305_MACBYTES;

        /// <summary>
        /// Calculates the size of the plaintext for a given ciphertext length.
        /// </summary>
        /// <param name="ciphertextLength">The length of the ciphertext.</param>
        /// <returns>The length of the plaintext.</returns>
        public static int GetPlaintextLength(int ciphertextLength) =>
            Math.Max(0, ciphertextLength - crypto_secretbox_xchacha20poly1305_MACBYTES);

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

        private bool InternalDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> message, XChaChaKey key, XChaChaNonce nonce)
        {
            var returnCode = crypto_secretbox_xchacha20poly1305_open_easy(
                ref MemoryMarshal.GetReference(message),
                in MemoryMarshal.GetReference(ciphertext),
                (UInt64)ciphertext.Length,
                in nonce.Handle,
                key.Handle);

            return returnCode == 0;
        }
    }
}