namespace XChaChaDotNet
{
    using System;

    /// <summary>
    /// Represents an XChaCha cipher that uses a single secret key to encrypt and decrypt a message.
    /// </summary>
    public abstract class XChaChaSecretKeyCipher : IXChaChaSecretKeyCipher
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
            this.InternalEncrypt(message, ciphertext, key, nonce);
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
            this.ValidateMaxMessageLength(message);
            var cipherText = new byte[GetCipherTextLength(message.Length)];
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
            this.InternalDecrypt(ciphertext, message, key, nonce);
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
                this.InternalDecrypt(ciphertext, message, key, nonce);
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
        public abstract int GetCipherTextLength(int plaintextLength);

        /// <summary>
        /// Calculates the size of the plaintext for a given ciphertext length.
        /// </summary>
        /// <param name="ciphertextLength">The length of the ciphertext.</param>
        /// <returns>The length of the plaintext.</returns>
        public abstract int GetPlaintextLength(int ciphertextLength);

        private protected abstract int GetMaximumMessageSize();

        private protected abstract void InternalEncrypt(
            ReadOnlySpan<byte> message,
            Span<byte> ciphertext,
            XChaChaKey key,
            XChaChaNonce nonce);

        private protected abstract void InternalDecrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            XChaChaKey key,
            XChaChaNonce nonce);

        private protected void ValidateEncryptParameters(ReadOnlySpan<byte> message, Span<byte> ciphertext, XChaChaNonce nonce)
        {
            ValidateMaxMessageLength(message);
            ValidateCiphertextLength(message, ciphertext);
            ValidateNonce(nonce);
        }

        private protected void ValidateDecryptParameters(ReadOnlySpan<byte> ciphertext, Span<byte> message, XChaChaNonce nonce)
        {
            ValidateMessageLength(ciphertext, message);
            ValidateNonce(nonce);
        }

        private void ValidateCiphertextLength(ReadOnlySpan<byte> message, Span<byte> ciphertext)
        {
            if (ciphertext.Length < GetCipherTextLength(message.Length))
                throw new ArgumentException($"{nameof(ciphertext)} buffer is not large enough");
        }

        private protected void ValidateMaxMessageLength(ReadOnlySpan<byte> message)
        {
            if (message.Length > GetMaximumMessageSize())
                throw new ArgumentException($"{nameof(message)} is too long");
        }

        private static void ValidateNonce(XChaChaNonce nonce)
        {
            if (nonce.IsEmpty)
                throw new ArgumentException($"{nameof(nonce)} is empty");
        }

        private void ValidateMessageLength(ReadOnlySpan<byte> ciphertext, Span<byte> message)
        {
            if (message.Length < GetPlaintextLength(ciphertext.Length))
                throw new ArgumentException($"{nameof(message)} buffer is not large enough");
        }
    }
}