namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    internal sealed class XChaChaStreamState : IDisposable
    {
        private static readonly int Length = Marshal.SizeOf<crypto_secretstream_xchacha20poly1305_state>();

        private readonly GuardedMemoryHandle handle;

        internal XChaChaStreamState()
        {
            GuardedMemoryHandle.Alloc(Length, out this.handle);
        }

        public GuardedMemoryHandle Handle => this.handle;

        #region IDisposable
        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.handle?.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}