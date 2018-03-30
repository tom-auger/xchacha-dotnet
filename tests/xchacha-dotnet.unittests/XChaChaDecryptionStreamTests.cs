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
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText, 0, decryptedPlainText.Length);

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
                var plainText = new byte[1024 * 1024];
                Array.Fill(plainText, (byte)0x7);

                using (var cipherStream = new XChaChaEncryptionStream(cipherTextStream, key))
                {
                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaDecryptionStream(cipherTextStream, key))
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
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                var plainText = new byte[1024 * 1024];
                Array.Fill(plainText, (byte)0x7);

                using (var cipherStream = new XChaChaEncryptionStream(cipherTextStream, key))
                {
                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaDecryptionStream(cipherTextStream, key))
                {
                    var decryptedPlainText = new byte[plainText.Length];

                    decryptionStream.Read(decryptedPlainText, 0, decryptedPlainText.Length);
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

                using (var cipherStream = new XChaChaEncryptionStream(cipherTextStream, key))
                {
                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaDecryptionStream(cipherTextStream, key))
                {
                    var decryptedPlainText = new byte[plainText.Length];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText, 0, decryptedPlainText.Length * 2);

                    Assert.Equal(plainText.Length, numberOfBytesOutput);
                    Assert.Equal(plainText, decryptedPlainText);
                }
            }
        }

        [Fact]
        public void Test_Decrypt_DecryptsLargeData()
        {
            using (var cipherTextStream = new MemoryStream())
            {
                var key = XChaChaKeyGenerator.GenerateKey();
                var plainText = new byte[1024 * 1024];
                Array.Fill(plainText, (byte)0x7);

                using (var cipherStream = new XChaChaEncryptionStream(cipherTextStream, key))
                {
                    cipherStream.Write(plainText, 0, plainText.Length);
                }

                cipherTextStream.Position = 0;

                using (var decryptionStream = new XChaChaDecryptionStream(cipherTextStream, key))
                {
                    var decryptedPlainText = new byte[plainText.Length];
                    var numberOfBytesOutput = decryptionStream.Read(decryptedPlainText, 0, decryptedPlainText.Length);

                    Assert.Equal(plainText.Length, numberOfBytesOutput);
                    Assert.Equal(plainText, decryptedPlainText);
                }
            }
        }
    }
}