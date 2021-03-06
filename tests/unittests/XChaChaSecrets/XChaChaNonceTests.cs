namespace XChaChaDotNet.UnitTests
{
    using System;
    using Xunit;
    using static TestConstants;

    public class XChaChaNonceTests
    {
        [Fact]
        public void Test_GenerateNonce_GeneratesNonceOfTheCorrectLength()
        {
            var nonce = XChaChaNonce.Generate();
            Assert.Equal(NonceLength, nonce.ReadOnlySpan.Length);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(55)]
        public void Test_InitializeNonce_LengthIncorrect_ThrowsArgumentException(int length)
        {
            var nonceBytes = RandomBytesGenerator.NextBytes(length);

            Action action = () => new XChaChaNonce(nonceBytes);

            var exception = Assert.Throws<ArgumentException>(action);
            Assert.Equal("nonceBytes has incorrect length", exception.Message);
        }

        [Fact]
        public void Test_InitializeNonce_ExistingNonce_InitializesSuccessfully()
        {
            var nonceBytes = RandomBytesGenerator.NextBytes(NonceLength);
            var nonce = new XChaChaNonce(nonceBytes);

            Assert.Equal(nonce.ToArray(), nonceBytes);
        }
    }
}