namespace XChaChaDotNet.UnitTests
{
    using System;
    using Xunit;

    public class XChaChaKeyTests
    {
        [Fact]
        public void Test_Initialize_InvalidKeyLength_ThrowsArgumentException()
        {
            var key = new byte[4];
            Action action = () => new XChaChaKey(key);
            var exception = Assert.Throws<ArgumentException>(action);
            Assert.Equal("key has invalid length\r\nParameter name: key", exception.Message);
        }
    }
}