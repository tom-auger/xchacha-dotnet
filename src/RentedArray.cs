namespace XChaChaDotNet
{
    using System.Buffers;
    using System;

    internal class RentedArray : IDisposable
    {
        private readonly byte[] rentedArray;
        private readonly int length;

        private bool disposed = false;

        public RentedArray(int length)
        {
            this.length = length;
            this.rentedArray = ArrayPool<byte>.Shared.Rent(length);
        }

        public Span<byte> AsSpan() => this.rentedArray.AsSpan(0, this.length);
        public Span<byte> AsSpan(int offset, int length) => this.rentedArray.AsSpan(offset, length);
        public ReadOnlySpan<byte> AsReadOnlySpan() => this.rentedArray.AsSpan(0, this.length);
        public ReadOnlySpan<byte> AsReadOnlySpan(int offset, int length) => this.rentedArray.AsSpan(offset, length);

        #region IDisposable
        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    ArrayPool<byte>.Shared.Return(this.rentedArray, clearArray: true);
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