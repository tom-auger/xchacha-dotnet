namespace XChaChaDotNet.UnitTests
{
    using System;
    using Xunit;

    public class XChaChaKeyGeneratorTests
    {
        [Fact]
        public void Test_GenerateKey_IsNotEmpty()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            Assert.False(key.IsEmpty);
        }

        [Fact]
        public void Test_KeyLengthIs32()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            Assert.Equal(32, key.Length);
        }
    }
}