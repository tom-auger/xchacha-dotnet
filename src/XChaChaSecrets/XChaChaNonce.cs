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
        private readonly ReadOnlySpan<byte> bytes;

        /// <summary>
        /// Creates an instance from an existing nonce.
        /// </summary>
        /// <param name="nonceBytes">The raw nonce bytes.</param>
        public XChaChaNonce(ReadOnlySpan<byte> nonceBytes)
        {
            if (nonceBytes.Length != crypto_secretbox_xchacha20poly1305_NONCEBYTES)
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

            Span<byte> nonceBytes = new byte[crypto_secretbox_xchacha20poly1305_NONCEBYTES];
            randombytes_buf(
                ref MemoryMarshal.GetReference(nonceBytes),
                (UIntPtr)crypto_secretbox_xchacha20poly1305_NONCEBYTES);

            return new XChaChaNonce(nonceBytes);
        }
    }
}