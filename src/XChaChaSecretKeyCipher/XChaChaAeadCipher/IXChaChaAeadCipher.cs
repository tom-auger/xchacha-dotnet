namespace XChaChaDotNet
{
    using System;

    /// <summary>
    /// Represents an XChaCha AEAD cipher based on the IETF specification of ChaCha20Poly1305 but with a 192 bit nonce.
    /// </summary>
    public interface IXChaChaAeadCipher : IXChaChaSecretKeyCipher
    {
        /// <summary>
        /// Encrypts the <paramref name="message"/> and writes computed ciphertext to <paramref name="ciphertext"/>.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="ciphertext">The buffer in which to write the ciphertext.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        /// <param name="additionalData">The associated data to use for computing the authentication tag.</param>
        void Encrypt(
            ReadOnlySpan<byte> message,
            Span<byte> ciphertext,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData);

        /// <summary>
        /// Encrypts the <paramref name="message"/> and returns the computed ciphertext.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        /// <param name="additionalData">The associated data to use for computing the authentication tag.</param>
        /// <returns>The computed ciphertext.</returns>
        byte[] Encrypt(ReadOnlySpan<byte> message, XChaChaKey key, XChaChaNonce nonce, ReadOnlySpan<byte> additionalData);

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <param name="additionalData">The associated data to use for computing the authentication tag.</param>
        void Decrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData);

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// returns the decrypted message.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <param name="additionalData">The associated data to use for computing the authentication tag.</param>
        /// <returns>The decrypted message.</returns>
        byte[] Decrypt(ReadOnlySpan<byte> ciphertext, XChaChaKey key, XChaChaNonce nonce, ReadOnlySpan<byte> additionalData);

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
        bool TryDecrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            XChaChaKey key,
            XChaChaNonce nonce,
            ReadOnlySpan<byte> additionalData);
    }
}