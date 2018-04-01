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
            var plainText = RandomBytesGenerator.NextBytes(1024 * 1024);

            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var cipherStream = new XChaChaEncryptionStream(outputStream, key))
                {
                    cipherStream.Write(plainText);
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

        [Fact]
        public void Test_Encrypt_WriteDifferentAmountsToStream()
        {
            var plainText1 = RandomBytesGenerator.NextBytes(157 * 1024);
            var plainText2 = RandomBytesGenerator.NextBytes(314 * 1024);
            var plaintext3 = RandomBytesGenerator.NextBytes(273 * 1024);

            var totalPlainTextLength = plainText1.Length + plainText2.Length + plaintext3.Length;
            // The encryption stream encrypts in 128KB blocks
            const int numberOfBlocks = 6;
            var expectedOutputLength = HeaderLength + totalPlainTextLength + (numberOfBlocks * ABytes);

            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var cipherStream = new XChaChaEncryptionStream(outputStream, key))
                {
                    cipherStream.Write(plainText1);
                    cipherStream.Write(plainText2);
                    cipherStream.Write(plaintext3);
                }

                var cipherText = outputStream.ToArray();

                Assert.Equal(expectedOutputLength, cipherText.Length);
            }
        }
    }
}