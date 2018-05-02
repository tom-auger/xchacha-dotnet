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

        [Fact]
        public void Test_GenerateKey_GeneratesKeyOfCorrectLength()
        {
            using (var key = XChaChaKey.Generate())
            {
                var keyBytes = key.ToArray();
                Assert.Equal(XChaChaConstants.KeyLength, keyBytes.Length);
            }
        }

        [Fact]
        public void Test_ToArray_ReturnsKey()
        {
            var keyBytes = XChaChaConstants.Key;
            using (var key = new XChaChaKey(keyBytes))
            {
                var result = key.ToArray();
                Assert.Equal(keyBytes, result);
            }
        }
    }
}