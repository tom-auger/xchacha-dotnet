namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using static SodiumInterop;

    public abstract class XChaChaStreamBase : Stream
    {
        protected readonly EncryptionMode encryptionMode;
        protected readonly IntPtr state;
        protected readonly Stream stream;
        protected byte[] headerBuffer = new byte[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
        
        protected XChaChaStreamBase(Stream stream, ReadOnlySpan<byte> key, EncryptionMode encryptionMode)
        {
            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
            this.encryptionMode = encryptionMode;

            if (key.Length != crypto_secretstream_xchacha20poly1305_KEYBYTES)
                throw new ArgumentException("key has invalid length", nameof(key));

            this.state = Marshal.AllocHGlobal(Marshal.SizeOf<crypto_secretstream_xchacha20poly1305_state>());

            int initResult;
            if (encryptionMode == EncryptionMode.Encrypt)
            {
                initResult = crypto_secretstream_xchacha20poly1305_init_push(this.state, this.headerBuffer, key.ToArray());
            }
            else
            {
                var bytesRead = this.stream.Read(this.headerBuffer);
                if (bytesRead != this.headerBuffer.Length)
                    throw new CryptographicException("invalid or corrupt header");

                initResult = crypto_secretstream_xchacha20poly1305_init_pull(this.state, this.headerBuffer, key.ToArray());
            }

            if (initResult != 0)
                throw new CryptographicException("crypto stream initialization failed");
        }

    }
}