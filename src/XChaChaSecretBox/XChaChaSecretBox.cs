namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    public class XChaChaSecretBox
    {
        private readonly XChaChaKey key;

        public XChaChaSecretBox(XChaChaKey key)
        {
            this.key = key;
        }

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