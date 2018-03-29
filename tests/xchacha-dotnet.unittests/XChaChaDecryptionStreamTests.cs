namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.IO;
    using System.Text;
    using Xunit;

    public class XChaChaDecryptionStreamTests
    {
        [Fact]
        public void Test_Decrypt_DecryptsSmallBlock()
        {
            using (var cipherTextStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                var plainText = Encoding.UTF8.GetBytes("banana");

                using (var cipherStream = new XChaChaEncryptionStream(cipherTextStream, key))
                {
                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                cipherTextStream.Position = 0;
                
                using (var decryptionStream = new XChaChaDecryptionStream(cipherTextStream, key))
                {
                    var decryptedPlainText = new byte[plainText.Length];
                    var numberOfBytesRead = decryptionStream.Read(decryptedPlainText, 0, decryptedPlainText.Length);

                    Assert.Equal(plainText, decryptedPlainText);
                }
            }
        }
    }
}