namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    public class XChaChaEncryptionStream : Stream
    {
        private const int BlockLength = 128 * 1024;
        private const int EncryptedBlockLength = BlockLength + crypto_secretstream_xchacha20poly1305_ABYTES;

        private readonly Stream stream;
        private readonly IntPtr state;

        private bool headerWritten;
        private int inBufferBlockPosition;
        private byte[] inBuffer = new byte[BlockLength];
        private int outBufferBlockLength;
        private byte[] outBuffer = new byte[EncryptedBlockLength];

        private bool isClosed;

        public XChaChaEncryptionStream(Stream stream, ReadOnlySpan<byte> key)
        {
            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));

            if (key.Length != crypto_secretstream_xchacha20poly1305_KEYBYTES)
                throw new ArgumentException("key has invalid length", nameof(key));

            this.state =
                Marshal.AllocHGlobal(Marshal.SizeOf<crypto_secretstream_xchacha20poly1305_state>());

            // The length of the header is smaller than EncryptedBlockLength so it will fit
            var initResult = crypto_secretstream_xchacha20poly1305_init_push(this.state, this.outBuffer, key.ToArray());
            this.outBufferBlockLength = crypto_secretstream_xchacha20poly1305_HEADERBYTES;

            if (initResult != 0)
                throw new Exception("crypto stream initialization failed");
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => !isClosed && this.stream.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new InvalidOperationException("encryption stream is write only");

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!this.CanWrite) throw new NotSupportedException();

            if (this.headerWritten)
            {
                // Process the last block in the buffer
                this.ProcessInBuffer(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
            }

            // Consume the new data
            // Initially just do this badly and copy every block into the buffer
            // later on look ahead and only copy when necessary
            while (count > 0)
            {
                // Read the next block into the buffer
                var remainingInBlockCapacity = BlockLength - this.inBufferBlockPosition;
                if (remainingInBlockCapacity == 0)
                {
                    this.ProcessInBuffer(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
                }
                else
                {
                    var blockLength = Math.Min(count, remainingInBlockCapacity);
                    Array.Copy(buffer, this.inBuffer, blockLength);
                    this.inBufferBlockPosition += blockLength;
                    count -= blockLength;
                    offset += blockLength;
                }
            }
        }

        public override void Close()
        {
            if (!isClosed)
            {
                this.ProcessInBuffer(crypto_secretstream_xchacha20poly1305_TAG_FINAL);
                base.Close();
                isClosed = true;
            }
        }

        private void ProcessInBuffer(byte tag)
        {
            if (this.inBufferBlockPosition != 0)
            {
                var block = this.inBuffer.AsReadOnlySpan();

                crypto_secretstream_xchacha20poly1305_push(
                        this.state,
                        ref MemoryMarshal.GetReference(this.outBuffer.AsSpan()),
                        out var clen,
                        in MemoryMarshal.GetReference(block),
                        (ulong)this.inBufferBlockPosition,
                        IntPtr.Zero,
                        0,
                        tag);

                this.outBufferBlockLength = (int)clen;
                this.stream.Write(this.outBuffer, 0, this.outBufferBlockLength);
                this.inBufferBlockPosition = 0;
            }
        }
    }
}