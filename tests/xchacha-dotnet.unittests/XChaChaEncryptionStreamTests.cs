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
            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var cipherStream = new XChaChaEncryptionStream(outputStream, key))
                {
                    var plainText = Encoding.UTF8.GetBytes("banana");
                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                var cipherText = outputStream.ToArray();

                Assert.NotEmpty(cipherText);
            }
        }

        [Fact]
        public void Test_Encrypt_DoesNotFail_WithLargeData()
        {
            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var cipherStream = new XChaChaEncryptionStream(outputStream, key))
                {
                    var plainText = new byte[1024 * 1024];
                    Array.Fill(plainText, (byte)0x7);

                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                var cipherText = outputStream.ToArray();

                Assert.NotEmpty(cipherText);
            }
        }
    }
}