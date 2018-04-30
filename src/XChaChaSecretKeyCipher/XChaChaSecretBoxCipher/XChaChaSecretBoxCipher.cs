namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    /// <summary>
    /// Represents the xchacha_secret_box construction. This is based on the NaCl crypto_secretbox_xsalsa20poly1305 
    /// construction but uses xchacha rather than xsalsa.
    /// </summary>
    public class XChaChaSecretBoxCipher : XChaChaSecretKeyCipher, IXChaChaSecretBoxCipher
    {
        /// <summary>
        /// Calculates the size of the ciphertext for a given plaintext length.
        /// </summary>
        /// <param name="plaintextLength">The length of the plaintext.</param>
        /// <returns>The length of the ciphertext.</returns>
        public override int GetCipherTextLength(int plaintextLength) =>
            plaintextLength + crypto_secretbox_xchacha20poly1305_MACBYTES;

        /// <summary>
        /// Calculates the size of the plaintext for a given ciphertext length.
        /// </summary>
        /// <param name="ciphertextLength">The length of the ciphertext.</param>
        /// <returns>The length of the plaintext.</returns>
        public override int GetPlaintextLength(int ciphertextLength) =>
            Math.Max(0, ciphertextLength - crypto_secretbox_xchacha20poly1305_MACBYTES);

        private protected override int GetMaximumMessageSize() => 
            int.MaxValue - crypto_secretbox_xchacha20poly1305_MACBYTES;

        private protected override void InternalEncrypt(
            ReadOnlySpan<byte> message,
            Span<byte> ciphertext,
            XChaChaKey key,
            XChaChaNonce nonce)
        {
            ValidateEncryptParameters(message, ciphertext, nonce);
            crypto_secretbox_xchacha20poly1305_easy(
                ref MemoryMarshal.GetReference(ciphertext),
                in MemoryMarshal.GetReference(message),
                (UInt64)message.Length,
                in nonce.Handle,
                key.Handle);
        }

        private protected override void InternalDecrypt(
            ReadOnlySpan<byte> ciphertext, 
            Span<byte> message,
            XChaChaKey key,
            XChaChaNonce nonce)
        {
            ValidateDecryptParameters(ciphertext, message, nonce);
            var returnCode = crypto_secretbox_xchacha20poly1305_open_easy(
                ref MemoryMarshal.GetReference(message),
                in MemoryMarshal.GetReference(ciphertext),
                (UInt64)ciphertext.Length,
                in nonce.Handle,
                key.Handle);

            if (returnCode != 0) throw new CryptographicException("decryption failed");
        }
    }
}