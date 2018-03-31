namespace XChaChaDotNet.Benchmarks
{
    using System;
    using System.IO;

    public class DevNullStream : Stream
    {
        private int length;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => length;

        public override long Position { get => 0; set => throw new NotImplementedException(); }

        public override void Flush()
        {
            return;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            return;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.length += count;
            return;
        }
    }
}