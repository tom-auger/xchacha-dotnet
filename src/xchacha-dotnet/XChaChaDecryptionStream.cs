namespace XChaChaDotNet
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    public class XChaChaDecryptionStream : Stream
    {
        private const int BlockLength = 128 * 1024;
        private const int EncryptedBlockLength = BlockLength + crypto_secretstream_xchacha20poly1305_ABYTES;

        private readonly Stream stream;
        private IntPtr state;

        private bool isClosed;
        private int inBufferPosition;
        private byte[] inBuffer = new byte[EncryptedBlockLength];
        private int outBufferPosition;
        private byte[] outBuffer = new byte[BlockLength];

        public XChaChaDecryptionStream(Stream stream, ReadOnlySpan<byte> key)
        {
            this.stream = stream ?? throw new ArgumentNullException(nameof(stream));

            if (key.Length != crypto_secretstream_xchacha20poly1305_KEYBYTES)
                throw new ArgumentException("key has invalid length", nameof(key));

            this.state =
                Marshal.AllocHGlobal(Marshal.SizeOf<crypto_secretstream_xchacha20poly1305_state>());

            // The length of the header is smaller than EncryptedBlockLength so it will fit
            var bytesRead = this.stream.Read(this.inBuffer, 0, crypto_secretstream_xchacha20poly1305_HEADERBYTES);
            if (bytesRead != crypto_secretstream_xchacha20poly1305_HEADERBYTES)
                throw new Exception("invalid or corrupt header");

            var initResult = crypto_secretstream_xchacha20poly1305_init_push(this.state, this.inBuffer, key.ToArray());

            if (initResult != 0)
                throw new Exception("crypto stream initialization failed");
        }

        public override bool CanRead => !this.isClosed && this.stream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
            return;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (!this.stream.CanRead) throw new NotSupportedException();

            var totalBytesRead = 0;
            
            
            while (count > 0)
            {
                var bytesRead = this.stream.Read(this.inBuffer);

                // Stop if we've reached the end of the stream
                if (bytesRead == 0) break;

                // Decrypt the next block
                var decryptResult = crypto_secretstream_xchacha20poly1305_pull(
                    this.state,
                    ref MemoryMarshal.GetReference(this.outBuffer.AsReadOnlySpan()),
                    out var messageLength,
                    out var tag,
                    in MemoryMarshal.GetReference(this.inBuffer.AsReadOnlySpan()),
                    (UInt64)bytesRead,
                    IntPtr.Zero,
                    0);

                if (decryptResult != 0) throw new Exception("block is invalid or corrupt");
                
                Array.Copy(this.outBuffer, 0, buffer, offset, bytesRead);

                offset += bytesRead;
                count -= bytesRead;
            }

            return totalBytesRead;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException("decryption stream is read only");

        public override void Close()
        {
            if (!isClosed)
            {
                base.Close();
                Marshal.FreeHGlobal(this.state);
                isClosed = true;
            }
        }
    }
}