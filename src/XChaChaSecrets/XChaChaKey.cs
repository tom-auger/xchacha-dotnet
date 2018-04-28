namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    /// <summary>
    /// Represents an encryption key to be used with the XChaCha cipher.
    /// </summary>
    public sealed class XChaChaKey : IDisposable
    {
        // All the XChaCha constructions in this library use a 32 byte key.
        private const int KeyLengthBytes = 32;
        private readonly GuardedMemoryHandle handle;
        
        private bool disposed;

        /// <summary>
        /// Create a new instance from an existing key.
        /// </summary>
        /// <param name="key">The key.</param>
        public XChaChaKey(ReadOnlySpan<byte> key)
        {
            Sodium.Initialize();

            if (key.Length != KeyLengthBytes)
                throw new ArgumentException("key has invalid length", nameof(key));

            GuardedMemoryHandle.Alloc(KeyLengthBytes, out this.handle);
            this.handle.Write(key);
            this.handle.MakeReadOnly();
        }

        private XChaChaKey(GuardedMemoryHandle handle)
        {
            this.handle = handle;
        }

        /// <summary>
        /// Creates a new randomly generated key.
        /// </summary>
        /// <returns>A new randomly generated key.</returns>
        public static XChaChaKey Generate()
        {
            Sodium.Initialize();
            GuardedMemoryHandle.Alloc(KeyLengthBytes, out var handle);
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

        /// <summary>
        /// Disposes the key, immediately removing it from memory.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}