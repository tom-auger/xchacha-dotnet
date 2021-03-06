﻿namespace XChaChaDotNet
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
        public static extern void crypto_secretstream_xchacha20poly1305_keygen(ref byte k);

        // Encryption
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_secretstream_xchacha20poly1305_init_push(
            GuardedMemoryHandle state,
            byte[] header,
            GuardedMemoryHandle k);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_secretstream_xchacha20poly1305_push(
            GuardedMemoryHandle state,
            ref byte c,
            out UInt64 clen_p,
            in byte m,
            UInt64 mlen,
            ref byte ad,
            UInt64 adlen,
            byte tag);

        // Decryption
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_secretstream_xchacha20poly1305_init_pull(
            GuardedMemoryHandle state,
            byte[] header,
            GuardedMemoryHandle k);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_secretstream_xchacha20poly1305_pull(
            GuardedMemoryHandle state,
            ref byte m,
            out UInt64 mlen_p,
            out byte tag_p,
            in byte c,
            UInt64 clen,
            ref byte ad,
            UInt64 adlen);

        // State
        public struct crypto_secretstream_xchacha20poly1305_state
        {
            // Disable compilier warning: Field is not assigned to and will always have its default value 'null'
#pragma warning disable 0649

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] k;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public byte[] nonce;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public byte[] _pad;

#pragma warning restore 0649
        }
        #endregion

        #region XChaCha20Poly1305SecretBox
        public const int crypto_secretbox_xchacha20poly1305_KEYBYTES = 32;
        public const int crypto_secretbox_xchacha20poly1305_NONCEBYTES = 24;
        public const int crypto_secretbox_xchacha20poly1305_MACBYTES = 16;

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_secretbox_xchacha20poly1305_easy(
            ref byte c,
            in byte m,
            UInt64 mlen,
            in byte n,
            GuardedMemoryHandle k);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_secretbox_xchacha20poly1305_open_easy(
            ref byte m,
            in byte c,
            UInt64 clen,
            in byte n,
            GuardedMemoryHandle k);
        #endregion

        #region XChaCha20Poly1305Aead
        public const int crypto_aead_xchacha20poly1305_ietf_KEYBYTES = 32;
        // The XChaCha AEAD construction doesn't require a secret nonce, hence
        // has length 0.
        public const int crypto_aead_xchacha20poly1305_ietf_NSECBYTES = 0;
        public const int crypto_aead_xchacha20poly1305_ietf_NPUBBYTES = 24;
        public const int crypto_aead_xchacha20poly1305_ietf_ABYTES = 16;
        
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_xchacha20poly1305_ietf_encrypt(
            ref byte c,
            out UInt64 clen_p,
            in byte m,
            UInt64 mlen,
            in byte ad,
            UInt64 adlen,
            IntPtr nsec,
            in byte npub,
            GuardedMemoryHandle k);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int crypto_aead_xchacha20poly1305_ietf_decrypt(
            ref byte m,
            out UInt64 mlen_p,
            IntPtr nsec,
            in byte c,
            UInt64 clen,
            in byte ad,
            UInt64 adlen,
            in byte npub,
            GuardedMemoryHandle k);
        #endregion

        #region GuardedMemory
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern GuardedMemoryHandle sodium_malloc(UIntPtr size);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int sodium_mprotect_readonly(GuardedMemoryHandle ptr);

        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void sodium_free(IntPtr ptr);
        #endregion

        #region RandomBytes
        [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void randombytes_buf(
            ref byte buf,
            UIntPtr size);
        #endregion
    }
}
