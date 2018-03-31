namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.IO;
    using System.Text;
    using Xunit;

    public class XChaChaEncryptionStreamTests
    {
        private const int HeaderLength = 24;
        private const int ABytes = 17;

        [Fact]
        public void Test_Encrypt_ProducesCorrectOutputLength()
        {
            var plainText = Encoding.UTF8.GetBytes("banana");
            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var cipherStream = new XChaChaEncryptionStream(outputStream, key))
                {
                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                var cipherText = outputStream.ToArray();

                // The encryption stream encrypts in 128KB blocks
                const int numberOfBlocks = 1;
                var expectedCipherTextLength = plainText.Length + HeaderLength + (ABytes * numberOfBlocks);
                Assert.Equal(expectedCipherTextLength, cipherText.Length);
            }
        }

        [Fact]
        public void Test_Encrypt_WithLargeData_ProducesCorrectOutputLength()
        {
            var plainText = new byte[1024 * 1024];
            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var cipherStream = new XChaChaEncryptionStream(outputStream, key))
                {
                    Array.Fill(plainText, (byte)0x7);

                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                var cipherText = outputStream.ToArray();

                // The encryption stream encrypts in 128KB blocks
                var numberOfBlocks = 1024 / 128;
                var expectedCipherTextLength = plainText.Length + HeaderLength + (ABytes * numberOfBlocks);
                Assert.Equal(expectedCipherTextLength, cipherText.Length);
            }
        }

        [Fact]
        public void Test_Encrypt_OutputsHeader()
        {
            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var cipherStream = new XChaChaEncryptionStream(outputStream, key))
                {
                    var plainText = Array.Empty<byte>();

                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                var cipherText = outputStream.ToArray();

                Assert.Equal(HeaderLength, cipherText.Length);
            }
        }

        [Fact]
        public void Test_Flush_FlushesHeader()
        {
            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var cipherStream = new XChaChaEncryptionStream(outputStream, key))
                {
                    var plainText = Array.Empty<byte>();

                    cipherStream.Write(plainText, 0, plainText.Length);
                    cipherStream.Flush();

                    var cipherText = outputStream.ToArray();
                    Assert.Equal(HeaderLength, cipherText.Length);
                }
            }
        }
    }
}