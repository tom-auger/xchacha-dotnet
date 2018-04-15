namespace XChaChaDotNet
{
    using System.Buffers;
    using System;

    internal class RentedArray : IDisposable
    {
        private readonly byte[] rentedArray;

        private bool disposed;

        public RentedArray(int length)
        {
            this.Length = length;
            this.rentedArray = ArrayPool<byte>.Shared.Rent(length);
        }

        public int Length { get; }

        public Span<byte> AsSpan() => this.rentedArray.AsSpan(0, this.Length);
        public Span<byte> AsSpan(int offset, int length) => this.rentedArray.AsSpan(offset, length);
        public ReadOnlySpan<byte> AsReadOnlySpan() => this.rentedArray.AsSpan(0, this.Length);
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