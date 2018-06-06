namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Compression;
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
            var plaintext = TestConstants.MessageBytes;
            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt))
                {
                    encryptionStream.Write(plaintext);
                }

                var ciphertext = outputStream.ToArray();

                // The encryption stream encrypts in 128KB blocks
                const int numberOfBlocks = 1;
                var expectedCipherTextLength = plaintext.Length + StreamHeaderLength + (StreamABytes * numberOfBlocks);
                Assert.Equal(expectedCipherTextLength, ciphertext.Length);
            }
        }

        [Theory]
        [MemberData(nameof(TestBufferLengths))]
        public void Test_Encrypt_WithLargeData_ProducesCorrectOutputLength(int bufferLength)
        {
            var plaintext = RandomBytesGenerator.NextBytes(1024 * 1024);

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt, bufferLength))
                {
                    encryptionStream.Write(plaintext);
                }

                var ciphertext = outputStream.ToArray();

                var numberOfBlocks = Math.Ceiling((decimal)plaintext.Length / bufferLength);
                var expectedCipherTextLength = plaintext.Length + StreamHeaderLength + (StreamABytes * numberOfBlocks);
                Assert.Equal(expectedCipherTextLength, ciphertext.Length);
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
                    var plaintext = Array.Empty<byte>();

                    encryptionStream.Write(plaintext);
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
            using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt))
            {
                var plaintext = Array.Empty<byte>();

                encryptionStream.Write(plaintext);
                encryptionStream.Flush();

                var ciphertext = outputStream.ToArray();
                Assert.Equal(StreamHeaderLength, ciphertext.Length);
            }
        }

        [Theory]
        [MemberData(nameof(TestBufferLengths))]
        public void Test_Encrypt_WriteDifferentAmountsToStream(int bufferLength)
        {
            var plaintext1 = RandomBytesGenerator.NextBytes(157 * 1024);
            var plaintext2 = RandomBytesGenerator.NextBytes(314 * 1024);
            var plaintext3 = RandomBytesGenerator.NextBytes(273 * 1024);

            var totalPlainTextLength = plaintext1.Length + plaintext2.Length + plaintext3.Length;
            var numberOfBlocks = Math.Ceiling((decimal)totalPlainTextLength / bufferLength);
            var expectedOutputLength = StreamHeaderLength + totalPlainTextLength + (numberOfBlocks * StreamABytes);

            using (var outputStream = new MemoryStream())
            {
                using (var key = XChaChaKey.Generate())
                using (var encryptionStream = new XChaChaBufferedStream(outputStream, key, EncryptionMode.Encrypt, bufferLength))
                {
                    encryptionStream.Write(plaintext1);
                    encryptionStream.Write(plaintext2);
                    encryptionStream.Write(plaintext3);
                }

                var ciphertext = outputStream.ToArray();

                Assert.Equal(expectedOutputLength, ciphertext.Length);
            }
        }
        #endregion

        #region Decryption
        [Fact]
        public void Test_Decrypt_DecryptsSmallBlock()
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext = TestConstants.MessageBytes;

                using (var encryptionStream =
                    new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plaintext);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plaintext.Length];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plaintext.Length, numberOfBytesOutput);
                    Assert.Equal(plaintext, decryptedPlainText);
                }
            }
        }

        [Fact]
        public void Test_Decrypt_MultipleSmallBlocks()
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext1 = RandomBytesGenerator.NextBytes(17);
                var plaintext2 = RandomBytesGenerator.NextBytes(23);

                using (var encryptionStream =
                    new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plaintext1);
                    encryptionStream.Write(plaintext2);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var plaintextLength = plaintext1.Length + plaintext2.Length;
                    var decryptedPlainText = new byte[plaintextLength];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plaintextLength, numberOfBytesOutput);
                    Assert.Equal(plaintext1.Concat(plaintext2), decryptedPlainText);
                }
            }
        }

        [Fact]
        public void Test_Decrypt_VerifyEndOfMessage_FalseWhenPartiallyDecrypted()
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext = RandomBytesGenerator.NextBytes(1024 * 1024);

                using (var encryptionStream =
                    new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plaintext);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plaintext.Length];

                    decryptionStream.Read(decryptedPlainText, 0, decryptedPlainText.Length / 2);
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

                using (var encryptionStream =
                    new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plaintext);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Decrypt))
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

                using (var encryptionStream =
                    new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    encryptionStream.Write(plaintext);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    var decryptedPlainText = new byte[plaintext.Length * 2];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plaintext.Length, numberOfBytesOutput);
                    Assert.Equal(plaintext, decryptedPlainText.Take(plaintext.Length));
                }
            }
        }

        [Theory]
        [MemberData(nameof(TestBufferLengths))]
        public void Test_Decrypt_DecryptsLargeBlock(int bufferLength)
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext = RandomBytesGenerator.NextBytes(1024 * 1024);

                using (var encryptionStream =
                    new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Encrypt, bufferLength, leaveOpen: true))
                {
                    encryptionStream.Write(plaintext);
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream =
                    new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Decrypt, bufferLength))
                {
                    var decryptedPlainText = new byte[plaintext.Length];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText);

                    Assert.Equal(plaintext.Length, numberOfBytesOutput);
                    Assert.Equal(plaintext.ToArray(), decryptedPlainText);
                }
            }
        }

        [Fact]
        public void Test_Decrypt_UsingCompressionStream_DecryptsSmallBlock()
        {
            using (var ciphertextStream = new MemoryStream())
            using (var key = XChaChaKey.Generate())
            {
                var plaintext = TestConstants.MessageBytes;

                using (var encryptionStream =
                    new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Encrypt, leaveOpen: true))
                {
                    using (var compressionStream = new BrotliStream(encryptionStream, CompressionMode.Compress))
                    {
                        compressionStream.Write(plaintext);
                    }
                }

                ciphertextStream.Position = 0;

                using (var decryptionStream = new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Decrypt))
                {
                    using (var decompressionStream = new BrotliStream(decryptionStream, CompressionMode.Decompress))
                    {
                        var decryptedPlainText = new byte[plaintext.Length];
                        var numberOfBytesOutput = decompressionStream.Read(decryptedPlainText);

                        Assert.Equal(plaintext.Length, numberOfBytesOutput);
                        Assert.Equal(plaintext, decryptedPlainText);
                    }
                }
            }
        }
        #endregion
    }
}