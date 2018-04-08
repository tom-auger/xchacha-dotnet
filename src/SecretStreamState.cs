namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    internal class SecretStreamState : IDisposable
    {
        private static readonly int Length = Marshal.SizeOf<crypto_secretstream_xchacha20poly1305_state>();

        private bool disposed = false;
        private GuardedMemoryHandle handle;

        internal SecretStreamState()
        {
            GuardedMemoryHandle.Alloc(Length, out this.handle);
        }

        public GuardedMemoryHandle Handle => this.handle;

        #region IDisposable
        protected virtual void Dispose(bool disposing)
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