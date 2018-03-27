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
    }
}