namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    /// <summary>
    /// Represents a nonce for use with XChaCha ciphers.
    /// </summary>
    public readonly struct XChaChaNonce
    {
        // All the XChaCha constructions in this library use a 24 byte nonce.
        private const int NonceLengthBytes = 24;
        private readonly byte[] bytes;

        /// <summary>
        /// Creates an instance from an existing nonce.
        /// </summary>
        /// <param name="nonceBytes">The raw nonce bytes.</param>
        public XChaChaNonce(ReadOnlySpan<byte> nonceBytes)
        {
            if (nonceBytes.Length != NonceLengthBytes)
                throw new ArgumentException($"{nameof(nonceBytes)} has incorrect length");

            this.bytes = nonceBytes.ToArray();
        }

        /// <summary>
        /// Returns a ReadOnlySpan to the raw nonce bytes.
        /// </summary>
        public ReadOnlySpan<byte> ReadOnlySpan => this.bytes;

        /// <summary>
        /// Returns the raw nonce bytes.
        /// </summary>
        public byte[] ToArray() => this.bytes;

        internal ref byte Handle => ref MemoryMarshal.GetReference((ReadOnlySpan<byte>)this.bytes);

        internal bool IsEmpty => this.bytes == default(byte[]);

        /// <summary>
        /// Create a new randomly generated nonce.
        /// </summary>
        public static XChaChaNonce Generate()
        {
            Sodium.Initialize();

            Span<byte> nonceBytes = new byte[NonceLengthBytes];
            randombytes_buf(
                ref MemoryMarshal.GetReference(nonceBytes),
                (UIntPtr)NonceLengthBytes);

            return new XChaChaNonce(nonceBytes);
        }
    }
}