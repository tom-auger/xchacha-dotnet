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

        private bool isClosed;
        private bool headerWritten;
        private int inBufferPosition;
        private byte[] inBuffer = new byte[BlockLength];
        private byte[] outBuffer = new byte[EncryptedBlockLength];

        public XChaChaEncryptionStream(Stream stream, ReadOnlySpan<byte> key)
        {
            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));

            if (key.Length != crypto_secretstream_xchacha20poly1305_KEYBYTES)
                throw new ArgumentException("key has invalid length", nameof(key));

            this.state =
                Marshal.AllocHGlobal(Marshal.SizeOf<crypto_secretstream_xchacha20poly1305_state>());

            // The length of the header is smaller than EncryptedBlockLength so it will fit
            var initResult = crypto_secretstream_xchacha20poly1305_init_push(this.state, this.outBuffer, key.ToArray());

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
            this.ProcessInBuffer(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
        }

        public void FlushFinal()
        {
            this.ProcessInBuffer(crypto_secretstream_xchacha20poly1305_TAG_FINAL);
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new InvalidOperationException("encryption stream is write only");

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (!this.CanWrite) throw new NotSupportedException();

            if (!this.headerWritten)
            {
                this.ProcessHeader();
            }

            while (count > 0)
            {
                // Consume what's in the buffer first before processing new data
                var remainingInBufferCapacity = BlockLength - this.inBufferPosition;
                var inBufferIsFull = remainingInBufferCapacity == 0;
                var inBufferIsEmpty = remainingInBufferCapacity == BlockLength;

                if (inBufferIsFull)
                {
                    // Buffer is full, so process it first
                    this.ProcessInBuffer(crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
                }
                else if (inBufferIsEmpty)
                {
                    // Buffer is empty, so process as much as possible and store the remainder in the buffer
                    if (count > BlockLength)
                    {
                        // There is more than one block left to go so process it immediately and circumvent the buffer
                        var block = buffer.AsReadOnlySpan().Slice(offset, BlockLength);
                        this.ProcessBlock(block, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);
                        count -= BlockLength;
                        offset += BlockLength;
                    }
                    else
                    {
                        // Store what's left in the buffer
                        Array.Copy(buffer, this.inBuffer, count);
                        this.inBufferPosition += count;
                        count = 0;
                        offset += count;
                    }
                }
                else
                {
                    // Attempt to fill the buffer first before processing
                    var bytesToRead = Math.Min(count, remainingInBufferCapacity);
                    Array.Copy(buffer, this.inBuffer, bytesToRead);
                    this.inBufferPosition += bytesToRead;
                    count -= bytesToRead;
                    offset += bytesToRead;
                }
            }
        }

        public override void Close()
        {
            if (!isClosed)
            {
                this.ProcessInBuffer(crypto_secretstream_xchacha20poly1305_TAG_FINAL);
                base.Close();
                Marshal.FreeHGlobal(this.state);
                isClosed = true;
            }
        }

        private void ProcessHeader()
        {
            this.stream.Write(this.outBuffer, 0, crypto_secretstream_xchacha20poly1305_HEADERBYTES);
            this.headerWritten = true;
        }

        private void ProcessInBuffer(byte tag)
        {
            if (!this.headerWritten)
            {
                this.ProcessHeader();
            }
            else
            {
                if (this.inBufferPosition != 0)
                {
                    var block = this.inBuffer
                        .AsReadOnlySpan()
                        .Slice(0, this.inBufferPosition);

                    this.ProcessBlock(block, tag);
                }
            }
        }

        private void ProcessBlock(ReadOnlySpan<byte> block, byte tag)
        {
            crypto_secretstream_xchacha20poly1305_push(
                    this.state,
                    ref MemoryMarshal.GetReference(this.outBuffer.AsSpan()),
                    out var cipherTextLength,
                    in MemoryMarshal.GetReference(block),
                    (ulong)block.Length,
                    IntPtr.Zero,
                    0,
                    tag);

            this.stream.Write(this.outBuffer, 0, (int)cipherTextLength);
            this.inBufferPosition = 0;
        }
    }
}