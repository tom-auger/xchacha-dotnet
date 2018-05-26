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
            var plaintext = TestConstants.MessageBytes;
            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.WriteFinal(plaintext);
                }

                var ciphertext = outputStream.ToArray();

                var expectedCipherTextLength = StreamHeaderLength + plaintext.Length + StreamABytes;
                Assert.Equal(expectedCipherTextLength, ciphertext.Length);
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
                    var plaintext = Array.Empty<byte>();
                    encryptionStream.WriteFinal(plaintext);
                }

                var ciphertext = outputStream.ToArray();

                Assert.Equal(StreamHeaderLength, ciphertext.Length);
            }
        }

        [Fact]
        public void Test_Flush_FlushesHeader()
        {
            using (var outputStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
            {
                var plaintext = Array.Empty<byte>();

                encryptionStream.WriteFinal(plaintext);
                encryptionStream.Flush();

                var ciphertext = outputStream.ToArray();
                Assert.Equal(StreamHeaderLength, ciphertext.Length);
            }
        }

        [Fact]
        public void Test_Encrypt_WriteDifferentAmountsToStream()
        {
            var plaintext1 = RandomBytesGenerator.NextBytes(157 * 1024);
            var plaintext2 = RandomBytesGenerator.NextBytes(314 * 1024);
            var plaintext3 = RandomBytesGenerator.NextBytes(273 * 1024);

            var totalPlainTextLength = plaintext1.Length + plaintext2.Length + plaintext3.Length;
            const int numberOfWrites = 3;
            var expectedOutputLength = StreamHeaderLength + totalPlainTextLength + (numberOfWrites * StreamABytes);

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(plaintext1);
                    encryptionStream.Write(plaintext2);
                    encryptionStream.WriteFinal(plaintext3);
                }

                var ciphertext = outputStream.ToArray();

                Assert.Equal(expectedOutputLength, ciphertext.Length);
            }
        }

        [Fact]
        public void Test_Encrypt_WithAdditionalData()
        {
            var plaintext = TestConstants.MessageBytes;
            var additionalData = Encoding.UTF8.GetBytes("apple");

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.WriteFinal(plaintext, additionalData);
                }

                var ciphertext = outputStream.ToArray();

                var expectedCipherTextLength = StreamHeaderLength + plaintext.Length + StreamABytes;
                Assert.Equal(expectedCipherTextLength, ciphertext.Length);
            }
        }

        [Fact]
        public void Test_Encrypt_WriteDifferentAmountsToStream_WithAdditionalData()
        {
            var plaintext1 = RandomBytesGenerator.NextBytes(157 * 1024);
            var additionalData1 = RandomBytesGenerator.NextBytes(512);
            var plaintext2 = RandomBytesGenerator.NextBytes(314 * 1024);
            var additionalData2 = RandomBytesGenerator.NextBytes(512);
            var plaintext3 = RandomBytesGenerator.NextBytes(273 * 1024);
            var additionalData3 = RandomBytesGenerator.NextBytes(512);

            var totalPlainTextLength = plaintext1.Length + plaintext2.Length + plaintext3.Length;
            const int numberOfWrites = 3;
            var expectedOutputLength = StreamHeaderLength + totalPlainTextLength + (numberOfWrites * StreamABytes);

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(plaintext1, additionalData1);
                    encryptionStream.Write(plaintext2, additionalData2);
                    encryptionStream.WriteFinal(plaintext3, additionalData3);
                }

                var ciphertext = outputStream.ToArray();

                Assert.Equal(expectedOutputLength, ciphertext.Length);
            }
        }
        #endregion

        #region Decryption
        [Fact]
        public void Test_Decrypt_DecryptsBlock()
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext = TestConstants.MessageBytes;

                using (var encryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.WriteFinal(plaintext);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plaintext.Length];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plaintext.Length, numberOfBytesOutput);
                    Assert.Equal(plaintext, decryptedPlainText);
                }
            }
        }

        [Fact]
        public void Test_Decrypt_DecryptsBlock_WithAdditionalData()
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext = TestConstants.MessageBytes;
                var additionalData = Encoding.UTF8.GetBytes("apple");

                using (var encryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.WriteFinal(plaintext, additionalData);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plaintext.Length];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText, additionalData);

                    Assert.Equal(plaintext.Length, numberOfBytesOutput);
                    Assert.Equal(plaintext, decryptedPlainText);
                }
            }
        }


        [Fact]
        public void Test_Decrypt_WithInvalidAdditionalData_Fails()
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext = TestConstants.MessageBytes;
                var additionalData = Encoding.UTF8.GetBytes("apple");

                using (var encryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.WriteFinal(plaintext, additionalData);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plaintext.Length];
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
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext1 = RandomBytesGenerator.NextBytes(1024);
                var plaintext2 = RandomBytesGenerator.NextBytes(1024);

                using (var encryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plaintext1);
                    encryptionStream.WriteFinal(plaintext2);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plaintext1.Length];

                    decryptionStream.Read(decryptedPlainText);
                    Assert.False(decryptionStream.VerifyEndOfMessage());
                }
            }
        }

        [Fact]
        public void Test_Decrypt_VerifyEndOfMessage_TrueWhenFullyDecrypted()
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext = RandomBytesGenerator.NextBytes(1024 * 1024);

                using (var encryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.WriteFinal(plaintext);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plaintext.Length];

                    decryptionStream.Read(decryptedPlainText);
                    Assert.True(decryptionStream.VerifyEndOfMessage());
                }
            }
        }

        [Fact]
        public void Test_Decrypt_OverReadDecryptionStream_OutputsCorrectNumberOfBytes()
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext = TestConstants.MessageBytes;

                using (var encryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.WriteFinal(plaintext);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plaintext.Length * 2];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plaintext.Length, numberOfBytesOutput);
                    Assert.Equal(plaintext, decryptedPlainText.Take(plaintext.Length));
                }
            }
        }
        #endregion
    }
}