namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    public sealed class XChaChaKey : IDisposable
    {
        private readonly GuardedMemoryHandle handle;

        private bool disposed = false;

        public XChaChaKey(ReadOnlySpan<byte> key)
        {
            if (key.Length != crypto_secretstream_xchacha20poly1305_KEYBYTES)
                throw new ArgumentException("key has invalid length", nameof(key));

            GuardedMemoryHandle.Alloc(crypto_secretstream_xchacha20poly1305_KEYBYTES, out this.handle);
            this.handle.Write(key);
            this.handle.MakeReadOnly();
        }

        private XChaChaKey(GuardedMemoryHandle handle)
        {
            this.handle = handle;
        }

        public static XChaChaKey Generate()
        {
            GuardedMemoryHandle handle;
            GuardedMemoryHandle.Alloc(crypto_secretstream_xchacha20poly1305_KEYBYTES, out handle);
            var keySpan = handle.DangerousGetSpan();
            crypto_secretstream_xchacha20poly1305_keygen(ref MemoryMarshal.GetReference(keySpan));

            return new XChaChaKey(handle);
        }

        internal GuardedMemoryHandle Handle => this.handle;

        #region IDisposable
        void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    this.handle.Dispose();
                }

                disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}