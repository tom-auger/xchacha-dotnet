namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    /// <summary>
    /// Represents an XChaCha secret box. Recommended for encrypting a single message
    /// with a key and nonce to keep it confidential.
    /// </summary>
    public class XChaChaSecretBox
    {
        private readonly XChaChaKey key;

        /// <summary>
        /// Creates an instance using the specified key.
        /// </summary>
        /// <param name="key">The key to use for encryption/decryption.</param>
        public XChaChaSecretBox(XChaChaKey key)
        {
            this.key = key;
        }

        /// <summary>
        /// Encrypts a <paramref name="message"/> and writes the output to <paramref name="ciphertext"/>.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="ciphertext">The buffer in which to write the ciphertext.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        public void Encrypt(ReadOnlySpan<byte> message, Span<byte> ciphertext, XChaChaNonce nonce)
        {
            ValidateEncryptParameters(message, ciphertext, nonce);

            crypto_secretbox_xchacha20poly1305_easy(
                ref MemoryMarshal.GetReference(ciphertext),
                in MemoryMarshal.GetReference(message),
                (UInt64)message.Length,
                in nonce.Handle,
                this.key.Handle);
        }

        /// <summary>
        /// Decrypts a <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <returns>Whether the decryption succeeded.</returns>
        public bool Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> message, XChaChaNonce nonce)
        {
            ValidateDecryptParameters(ciphertext, message, nonce);

            var returnCode =
                crypto_secretbox_xchacha20poly1305_open_easy(
                    ref MemoryMarshal.GetReference(message),
                    in MemoryMarshal.GetReference(ciphertext),
                    (UInt64)ciphertext.Length,
                    in nonce.Handle,
                    this.key.Handle);

            return returnCode == 0;
        }

        /// <summary>
        /// Calculates the size of the ciphertext for a given plaintext length.
        /// </summary>
        /// <param name="plaintextLength">The length of the plaintext.</param>
        /// <returns>The length of the ciphertext.</returns>
        public static int GetCipherTextLength(int plaintextLength) =>
            plaintextLength + crypto_secretbox_xchacha20poly1305_MACBYTES;

        private static int GetPlaintextLength(int ciphertextLength) =>
            ciphertextLength - crypto_secretbox_xchacha20poly1305_MACBYTES;

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