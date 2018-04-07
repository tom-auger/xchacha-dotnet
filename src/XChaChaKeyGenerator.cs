namespace XChaChaDotNet
{
    using System;
    using static SodiumInterop;

    public static class XChaChaKeyGenerator
    {
        public static ReadOnlySpan<byte> GenerateKey() 
        {
            var keyBytes = new byte[crypto_secretstream_xchacha20poly1305_KEYBYTES];
            crypto_secretstream_xchacha20poly1305_keygen(keyBytes);
            return keyBytes.AsReadOnlySpan();
        }
    }
}