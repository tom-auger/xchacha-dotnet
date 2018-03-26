namespace XChaChaDotNet
{
    using System;

    public static class XChaChaKeyGenerator
    {
        public static ReadOnlySpan<byte> GenerateKey() 
        {
            var keyBytes = new byte[SodiumInterop.crypto_secretstream_xchacha20poly1305_KEYBYTES];
            SodiumInterop.crypto_secretstream_xchacha20poly1305_keygen(keyBytes);
            return keyBytes.AsReadOnlySpan();
        }
    }
}