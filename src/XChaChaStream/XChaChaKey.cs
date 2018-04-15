namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    public sealed class XChaChaKey : IDisposable
    {
        private readonly GuardedMemoryHandle handle;
        
        private bool disposed;

        public XChaChaKey(ReadOnlySpan<byte> key)
        {
            Sodium.Initialize();

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
            Sodium.Initialize();
            GuardedMemoryHandle.Alloc(crypto_secretstream_xchacha20poly1305_KEYBYTES, out var handle);
            var keySpan = handle.DangerousGetSpan();
            crypto_secretstream_xchacha20poly1305_keygen(ref MemoryMarshal.GetReference(keySpan));
            handle.MakeReadOnly();

            return new XChaChaKey(handle);
        }

        internal GuardedMemoryHandle Handle => this.handle;

        #region IDisposable
        private void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    this.handle?.Dispose();
                }

                this.disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}