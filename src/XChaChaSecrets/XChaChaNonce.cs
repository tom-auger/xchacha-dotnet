namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    /// <summary>
    /// Represents a nonce for use with XChaCha ciphers.
    /// </summary>
    public readonly ref struct XChaChaNonce
    {
        // All the XChaCha constructions in this library use a 24 byte nonce.
        private const int NonceLengthBytes = 24;
        private readonly ReadOnlySpan<byte> bytes;

        /// <summary>
        /// Creates an instance from an existing nonce.
        /// </summary>
        /// <param name="nonceBytes">The raw nonce bytes.</param>
        public XChaChaNonce(ReadOnlySpan<byte> nonceBytes)
        {
            if (nonceBytes.Length != NonceLengthBytes)
                throw new ArgumentException($"{nameof(nonceBytes)} has incorrect length");

            this.bytes = nonceBytes;
        }

        /// <summary>
        /// Returns the raw nonce bytes.
        /// </summary>
        public ReadOnlySpan<byte> ReadOnlySpan => this.bytes;

        internal ref byte Handle => ref MemoryMarshal.GetReference(this.bytes);

        internal bool IsEmpty => this.bytes == ReadOnlySpan<byte>.Empty;

        /// <summary>
        /// Creates an instance with a new randomly generated nonce.
        /// </summary>
        /// <returns>An instance with a new randomly generated nonce.</returns>
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