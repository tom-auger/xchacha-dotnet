namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.IO;
    using System.Text;
    using Xunit;

    public class XChaChaEncryptionStreamTests
    {
        [Fact]
        public void Test_Encrypt_DoesNotFail()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            var outputStream = new MemoryStream();

            using(var cStream = new XChaChaEncryptionStream(outputStream, key))
            {
                var plainText = Encoding.UTF8.GetBytes("banana");
                cStream.Write(plainText, 0, plainText.Length);
            }
            
            var cipherText = outputStream.ToArray();
            
            Assert.NotEmpty(cipherText);
        }
    }
}