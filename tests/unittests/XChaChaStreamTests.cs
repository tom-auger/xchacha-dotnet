namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Xunit;

    public class XChaChaStreamTests
    {
        private const int HeaderLength = 24;
        private const int ABytes = 17;

        #region Encryption

        [Fact]
        public void Test_Encrypt_ProducesCorrectOutputLength()
        {
            var plainText = Encoding.UTF8.GetBytes("banana");
            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.WriteFinal(plainText);
                }

                var cipherText = outputStream.ToArray();

                var expectedCipherTextLength = HeaderLength + plainText.Length + ABytes;
                Assert.Equal(expectedCipherTextLength, cipherText.Length);
            }
        }

        [Fact]
        public void Test_Encrypt_OutputsHeader()
        {
            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    var plainText = Array.Empty<byte>();
                    encryptionStream.WriteFinal(plainText);
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
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    var plainText = Array.Empty<byte>();

                    encryptionStream.WriteFinal(plainText);
                    encryptionStream.Flush();

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
            const int numberOfWrites = 3;
            var expectedOutputLength = HeaderLength + totalPlainTextLength + (numberOfWrites * ABytes);

            using (var outputStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(plainText1);
                    encryptionStream.Write(plainText2);
                    encryptionStream.WriteFinal(plaintext3);
                }

                var cipherText = outputStream.ToArray();

                Assert.Equal(expectedOutputLength, cipherText.Length);
            }
        }

        #endregion

        #region Decryption

        [Fact]
        public void Test_Decrypt_DecryptsBlock()
        {
            using (var cipherTextStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                var plainText = Encoding.UTF8.GetBytes("banana");

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.WriteFinal(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText.Length];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plainText.Length, numberOfBytesOutput);
                    Assert.Equal(plainText, decryptedPlainText);
                }
            }
        }

        [Fact]
        public void Test_Decrypt_VerifyEndOfStream_FalseWhenPartiallyDecrypted()
        {
            using (var cipherTextStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                var plainText1 = RandomBytesGenerator.NextBytes(1024);
                var plainText2 = RandomBytesGenerator.NextBytes(1024);

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(plainText1);
                    encryptionStream.WriteFinal(plainText2);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText1.Length];

                    decryptionStream.Read(decryptedPlainText);
                    Assert.False(decryptionStream.VerifyEndOfCipherStream());
                }
            }
        }

        [Fact]
        public void Test_Decrypt_VerifyEndOfStream_TrueWhenFullyDecrypted()
        {
            using (var cipherTextStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                var plainText = RandomBytesGenerator.NextBytes(1024 * 1024);

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.WriteFinal(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText.Length];

                    decryptionStream.Read(decryptedPlainText);
                    Assert.True(decryptionStream.VerifyEndOfCipherStream());
                }
            }
        }

        [Fact]
        public void Test_Decrypt_OverReadDecryptionStream_OutputsCorrectNumberOfBytes()
        {
            using (var cipherTextStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                var plainText = Encoding.UTF8.GetBytes("banana");

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.WriteFinal(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText.Length * 2];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plainText.Length, numberOfBytesOutput);
                    Assert.Equal(plainText, decryptedPlainText.Take(plainText.Length));
                }
            }
        }

        #endregion
    }
}