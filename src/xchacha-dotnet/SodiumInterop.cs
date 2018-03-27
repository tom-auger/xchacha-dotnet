namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;

    internal class SodiumInterop
    {
        private const string LibraryName = "libsodium";

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_init();

        #region XChaCha20Poly1305SecretStream

        public const int crypto_secretstream_xchacha20poly1305_KEYBYTES = 32;
        public const int crypto_secretstream_xchacha20poly1305_HEADERBYTES = 24;
        public const int crypto_secretstream_xchacha20poly1305_ABYTES = 17;
        
        // Final tags
        public const byte crypto_secretstream_xchacha20poly1305_TAG_MESSAGE = 0x00;      
        public const byte crypto_secretstream_xchacha20poly1305_TAG_PUSH = 0x01;
        public const byte crypto_secretstream_xchacha20poly1305_TAG_REKEY = 0x02;
        public const byte crypto_secretstream_xchacha20poly1305_TAG_FINAL = 
            crypto_secretstream_xchacha20poly1305_TAG_PUSH | crypto_secretstream_xchacha20poly1305_TAG_REKEY;

        // Key generation
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void crypto_secretstream_xchacha20poly1305_keygen(byte[] k);

        // Encryption
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_secretstream_xchacha20poly1305_init_push(
            IntPtr state,
            byte[] header,
            byte[] k);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_secretstream_xchacha20poly1305_push(
            IntPtr state,
            ref byte c,
            out UInt64 clen_p,
            in byte m,
            UInt64 mlen,
            IntPtr ad,
            UInt64 adlen,
            byte tag);

         // Decryption
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_secretstream_xchacha20poly1305_init_pull(
            IntPtr state,
            byte[] header,
            byte[] key);

        // State
        public struct crypto_secretstream_xchacha20poly1305_state
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] k;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public byte[] nonce;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public byte[] _pad;
        }

        #endregion
    }
}
