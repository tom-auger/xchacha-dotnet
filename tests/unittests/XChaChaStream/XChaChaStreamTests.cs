namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using Xunit;
    using static TestConstants;

    public class XChaChaStreamTests
    {
        #region Encryption
        [Fact]
        public void Test_Encrypt_ProducesCorrectOutputLength()
        {
            var plainText = TestConstants.MessageBytes;
            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.WriteFinal(plainText);
                }

                var cipherText = outputStream.ToArray();

                var expectedCipherTextLength = StreamHeaderLength + plainText.Length + StreamABytes;
                Assert.Equal(expectedCipherTextLength, cipherText.Length);
            }
        }

        [Fact]
        public void Test_Encrypt_OutputsHeader()
        {
            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    var plainText = Array.Empty<byte>();
                    encryptionStream.WriteFinal(plainText);
                }

                var cipherText = outputStream.ToArray();

                Assert.Equal(StreamHeaderLength, cipherText.Length);
            }
        }

        [Fact]
        public void Test_Flush_FlushesHeader()
        {
            using (var outputStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
            {
                var plainText = Array.Empty<byte>();

                encryptionStream.WriteFinal(plainText);
                encryptionStream.Flush();

                var cipherText = outputStream.ToArray();
                Assert.Equal(StreamHeaderLength, cipherText.Length);
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
            var expectedOutputLength = StreamHeaderLength + totalPlainTextLength + (numberOfWrites * StreamABytes);

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
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

        [Fact]
        public void Test_Encrypt_WithAdditionalData()
        {
            var plainText = TestConstants.MessageBytes;
            var additionalData = Encoding.UTF8.GetBytes("apple");

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.WriteFinal(plainText, additionalData);
                }

                var cipherText = outputStream.ToArray();

                var expectedCipherTextLength = StreamHeaderLength + plainText.Length + StreamABytes;
                Assert.Equal(expectedCipherTextLength, cipherText.Length);
            }
        }

        [Fact]
        public void Test_Encrypt_WriteDifferentAmountsToStream_WithAdditionalData()
        {
            var plainText1 = RandomBytesGenerator.NextBytes(157 * 1024);
            var additionalData1 = RandomBytesGenerator.NextBytes(512);
            var plainText2 = RandomBytesGenerator.NextBytes(314 * 1024);
            var additionalData2 = RandomBytesGenerator.NextBytes(512);
            var plaintext3 = RandomBytesGenerator.NextBytes(273 * 1024);
            var additionalData3 = RandomBytesGenerator.NextBytes(512);

            var totalPlainTextLength = plainText1.Length + plainText2.Length + plaintext3.Length;
            const int numberOfWrites = 3;
            var expectedOutputLength = StreamHeaderLength + totalPlainTextLength + (numberOfWrites * StreamABytes);

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(plainText1, additionalData1);
                    encryptionStream.Write(plainText2, additionalData2);
                    encryptionStream.WriteFinal(plaintext3, additionalData3);
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
            using (var key = XChaChaKey.Generate())
            {
                var plainText = TestConstants.MessageBytes;

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
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
        public void Test_Decrypt_DecryptsBlock_WithAdditionalData()
        {
            using (var cipherTextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plainText = TestConstants.MessageBytes;
                var additionalData = Encoding.UTF8.GetBytes("apple");

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.WriteFinal(plainText, additionalData);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText.Length];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText, additionalData);

                    Assert.Equal(plainText.Length, numberOfBytesOutput);
                    Assert.Equal(plainText, decryptedPlainText);
                }
            }
        }


        [Fact]
        public void Test_Decrypt_WithInvalidAdditionalData_Fails()
        {
            using (var cipherTextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plainText = TestConstants.MessageBytes;
                var additionalData = Encoding.UTF8.GetBytes("apple");

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.WriteFinal(plainText, additionalData);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText.Length];
                    var invalidAdditionalData = Encoding.UTF8.GetBytes("pear");

                    Action action = () => decryptionStream.Read(decryptedPlainText, invalidAdditionalData);
                    var exception = Assert.Throws<CryptographicException>(action);

                    Assert.Equal("block is invalid or corrupt", exception.Message);
                    Assert.True(decryptedPlainText.All((b) => b == 0));
                }
            }
        }

        [Fact]
        public void Test_Decrypt_VerifyEndOfMessage_FalseWhenPartiallyDecrypted()
        {
            using (var cipherTextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plainText1 = RandomBytesGenerator.NextBytes(1024);
                var plainText2 = RandomBytesGenerator.NextBytes(1024);

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plainText1);
                    encryptionStream.WriteFinal(plainText2);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText1.Length];

                    decryptionStream.Read(decryptedPlainText);
                    Assert.False(decryptionStream.VerifyEndOfMessage());
                }
            }
        }

        [Fact]
        public void Test_Decrypt_VerifyEndOfMessage_TrueWhenFullyDecrypted()
        {
            using (var cipherTextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plainText = RandomBytesGenerator.NextBytes(1024 * 1024);

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.WriteFinal(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plainText.Length];

                    decryptionStream.Read(decryptedPlainText);
                    Assert.True(decryptionStream.VerifyEndOfMessage());
                }
            }
        }

        [Fact]
        public void Test_Decrypt_OverReadDecryptionStream_OutputsCorrectNumberOfBytes()
        {
            using (var cipherTextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plainText = TestConstants.MessageBytes;

                using (var encryptionStream = new XChaChaStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
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