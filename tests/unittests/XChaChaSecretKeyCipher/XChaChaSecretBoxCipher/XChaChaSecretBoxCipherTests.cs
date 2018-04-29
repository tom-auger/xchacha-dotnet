namespace XChaChaDotNet
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using XChaChaDotNet.UnitTests;
    using Xunit;

    public class XChaChaSecretBoxCipherTests
    {
        [Theory]
        [InlineData(4, 0)]
        [InlineData(15, 0)]
        [InlineData(17, 1)]
        [InlineData(1024, 1008)]
        public void Test_GetPlaintextLength_ReturnsCorrectLength(int ciphertextLength, int expectedPlaintextLength)
        {
            var secretBoxCipher = new XChaChaSecretBoxCipher();
            var plaintextLength = secretBoxCipher.GetPlaintextLength(ciphertextLength);
            Assert.Equal(expectedPlaintextLength, plaintextLength);
        }
    }
}