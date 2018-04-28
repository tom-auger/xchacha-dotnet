namespace XChaChaDotNet
{
    using System;

    /// <summary>
    /// Represents an XChaCha AEAD cipher.
    /// </summary>
    public interface IXChaChaAeadCipher
    {
        /// <summary>
        /// Encrypts the <paramref name="message"/> and writes computed ciphertext to <paramref name="ciphertext"/>.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="ciphertext">The buffer in which to write the ciphertext.</param>
        /// <param name="associatedData">The associated data to use for computing the authentication tag.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        void Encrypt(
            ReadOnlySpan<byte> message,
            Span<byte> ciphertext,
            ReadOnlySpan<byte> associatedData,
            XChaChaKey key,
            XChaChaNonce nonce);

        /// <summary>
        /// Encrypts the <paramref name="message"/> and writes computed ciphertext to <paramref name="ciphertext"/>.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="ciphertext">The buffer in which to write the ciphertext.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        void Encrypt(ReadOnlySpan<byte> message, Span<byte> ciphertext, XChaChaKey key, XChaChaNonce nonce);

        /// <summary>
        /// Encrypts the <paramref name="message"/> and returns the computed ciphertext.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="associatedData">The associated data to use for computing the authentication tag.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        /// <returns>The computed ciphertext.</returns>
        Span<byte> Encrypt(ReadOnlySpan<byte> message, ReadOnlySpan<byte> associatedData, XChaChaKey key, XChaChaNonce nonce);

        /// <summary>
        /// Encrypts the <paramref name="message"/> and returns the computed ciphertext.
        /// </summary>
        /// <param name="message">The message to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when encrypting the <paramref name="message"/>.</param>
        /// <returns>The computed ciphertext.</returns>
        Span<byte> Encrypt(ReadOnlySpan<byte> message, XChaChaKey key, XChaChaNonce nonce);

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="associatedData">The associated data to use for computing the authentication tag.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        void Decrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            ReadOnlySpan<byte> associatedData,
            XChaChaKey key,
            XChaChaNonce nonce);

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        void Decrypt(ReadOnlySpan<byte> ciphertext, Span<byte> message, XChaChaKey key, XChaChaNonce nonce);

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// returns the decrypted message.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="associatedData">The associated data to use for computing the authentication tag.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <returns>The decrypted message.</returns>
        Span<byte> Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, XChaChaKey key, XChaChaNonce nonce);

        /// <summary>
        /// Decrypts the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// returns the decrypted message.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <returns>The decrypted message.</returns>
        Span<byte> Decrypt(ReadOnlySpan<byte> ciphertext, XChaChaKey key, XChaChaNonce nonce);

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
        bool TryDecrypt(
            ReadOnlySpan<byte> ciphertext,
            Span<byte> message,
            ReadOnlySpan<byte> associatedData,
            XChaChaKey key,
            XChaChaNonce nonce);

        /// <summary>
        /// Tries to decrypt the <paramref name="ciphertext"/>, verifies the authenticaion tag, and if successful,
        /// writes the output to <paramref name="message"/>.
        /// </summary>
        /// <param name="ciphertext">The ciphertext to decrypt.</param>
        /// <param name="message">The buffer in which to write the decrypted message.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="nonce">The nonce to use when decrypting the <paramref name="ciphertext"/>.</param>
        /// <returns>Whether the decryption succeeded.</returns>
        bool TryDecrypt(ReadOnlySpan<byte> ciphertext, Span<byte> message, XChaChaKey key, XChaChaNonce nonce);
    }
}