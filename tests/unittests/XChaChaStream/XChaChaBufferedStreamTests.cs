namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using Xunit;
    using static TestConstants;

    public class XChaChaBufferedStreamTests
    {
        public static readonly TheoryData<int> TestBufferLengths = new TheoryData<int>
        {
            128 * 1024,
            192 * 1024,
            256 * 1024
        };

        #region Encryption
        [Fact]
        public void Test_Encrypt_ProducesCorrectOutputLength()
        {
            var plainText = TestConstants.MessageBytes;
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
                var expectedCipherTextLength = plainText.Length + StreamHeaderLength + (StreamABytes * numberOfBlocks);
                Assert.Equal(expectedCipherTextLength, cipherText.Length);
            }
        }

        [Theory]
        [MemberData(nameof(TestBufferLengths))]
        public void Test_Encrypt_WithLargeData_ProducesCorrectOutputLength(int bufferLength)
        {
            var plainText = RandomBytesGenerator.NextBytes(1024 * 1024);

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt, bufferLength))
                {
                    encryptionStream.Write(plainText);
                }

                var cipherText = outputStream.ToArray();

                var numberOfBlocks = Math.Ceiling((decimal)plainText.Length / bufferLength);
                var expectedCipherTextLength = plainText.Length + StreamHeaderLength + (StreamABytes * numberOfBlocks);
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

                Assert.Equal(StreamHeaderLength, cipherText.Length);
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
                Assert.Equal(StreamHeaderLength, cipherText.Length);
            }
        }

        [Theory]
        [MemberData(nameof(TestBufferLengths))]
        public void Test_Encrypt_WriteDifferentAmountsToStream(int bufferLength)
        {
            var plainText1 = RandomBytesGenerator.NextBytes(157 * 1024);
            var plainText2 = RandomBytesGenerator.NextBytes(314 * 1024);
            var plaintext3 = RandomBytesGenerator.NextBytes(273 * 1024);

            var totalPlainTextLength = plainText1.Length + plainText2.Length + plaintext3.Length;
            var numberOfBlocks = Math.Ceiling((decimal)totalPlainTextLength / bufferLength);
            var expectedOutputLength = StreamHeaderLength + totalPlainTextLength + (numberOfBlocks * StreamABytes);

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt, bufferLength))
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
                var plainText = TestConstants.MessageBytes;

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
        public void Test_Decrypt_VerifyEndOfMessage_FalseWhenPartiallyDecrypted()
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

                using (var encryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Decrypt))
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

        [Theory]
        [MemberData(nameof(TestBufferLengths))]
        public void Test_Decrypt_DecryptsLargeBlock(int bufferLength)
        {
            using (var cipherTextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plainText = RandomBytesGenerator.NextBytes(1024 * 1024);

                using (var encryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Encrypt, bufferLength, leaveOpen: true))
                {
                    encryptionStream.Write(plainText);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(cipherTextStream, key, EncryptionMode.Decrypt, bufferLength))
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