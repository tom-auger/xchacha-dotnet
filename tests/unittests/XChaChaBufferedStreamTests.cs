namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using Xunit;

    public class XChaChaBufferedStreamTests
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
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(plainText);
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
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(plainText);
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
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    var plainText = Array.Empty<byte>();

                    encryptionStream.Write(plainText);
                }

                var cipherText = outputStream.ToArray();

                Assert.Equal(HeaderLength, cipherText.Length);
            }
        }

        [Fact]
        public void Test_Flush_FlushesHeader()
        {
            using (var outputStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt))
            {
                var plainText = Array.Empty<byte>();

                encryptionStream.Write(plainText);
                encryptionStream.Flush();

                var cipherText = outputStream.ToArray();
                Assert.Equal(HeaderLength, cipherText.Length);
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
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(plainText1);
                    encryptionStream.Write(plainText2);
                    encryptionStream.Write(plaintext3);
                }

                var cipherText = outputStream.ToArray();

                Assert.Equal(expectedOutputLength, cipherText.Length);
            }
        }

        #endregion

        #region Decryption

        [Fact]
        public void Test_Decrypt_DecryptsSmallBlock()
        {
            using (var cipherTextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plainText = Encoding.UTF8.GetBytes("banana");

                using (var encryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Decrypt))
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
            using (var key = XChaChaKey.Generate())
            {
                var plainText = RandomBytesGenerator.NextBytes(1024 * 1024);

                using (var encryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText.Length];

                    decryptionStream.Read(decryptedPlainText, 0, decryptedPlainText.Length / 2);
                    Assert.False(decryptionStream.VerifyEndOfCipherStream());
                }
            }
        }

        [Fact]
        public void Test_Decrypt_VerifyEndOfStream_TrueWhenFullyDecrypted()
        {
            using (var cipherTextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plainText = RandomBytesGenerator.NextBytes(1024 * 1024);

                using (var encryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Decrypt))
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
            using (var key = XChaChaKey.Generate())
            {
                var plainText = Encoding.UTF8.GetBytes("banana");

                using (var encryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText.Length * 2];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plainText.Length, numberOfBytesOutput);
                    Assert.Equal(plainText, decryptedPlainText.Take(plainText.Length));
                }
            }
        }

        [Fact]
        public void Test_Decrypt_DecryptsLargeBlock()
        {
            using (var cipherTextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plainText = RandomBytesGenerator.NextBytes(1024 * 1024);

                using (var encryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText.Length];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plainText.Length, numberOfBytesOutput);
                    Assert.Equal(plainText.ToArray(), decryptedPlainText);
                }
            }
        }

        #endregion
    }
}