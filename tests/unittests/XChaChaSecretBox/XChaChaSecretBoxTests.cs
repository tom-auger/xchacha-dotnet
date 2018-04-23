namespace XChaChaDotNet
{
    using System;
    using System.Linq;
    using XChaChaDotNet.UnitTests;
    using Xunit;

    public class XChaChaSecretBoxTests
    {
        #region Encryption
        [Fact]
        public void Test_Encrypt_ProducesNonZeroOutput()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);
                var nonce = XChaChaNonce.Generate();

                var message = RandomBytesGenerator.NextBytes(1024 * 1024);
                var cipherText = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                secretBox.Encrypt(message, cipherText, nonce);

                Assert.False(cipherText.All(b => b == 0));
            }
        }

        [Fact]
        public void Test_Encrypt_NonceEmpty_ThrowsArgumentException()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);

                var message = Array.Empty<byte>();
                var cipherText = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        secretBox.Encrypt(message, cipherText, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("nonce is empty", exception.Message);
            }
        }

        [Fact]
        public void Test_Encrypt_CiphertextBufferTooSmall_ThrowsArgumentException()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);

                var message = Array.Empty<byte>();
                var cipherText = Array.Empty<byte>();

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        secretBox.Encrypt(message, cipherText, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("ciphertext buffer is not large enough", exception.Message);
            }
        }
        #endregion

        #region Decryption
        [Fact]
        public void Test_Decrypt_CanDecryptCiphertext()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var cipherText = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                secretBox.Encrypt(message, cipherText, nonce);

                var decryptedMessage = new byte[messageLength];
                var result = secretBox.Decrypt(cipherText, decryptedMessage, nonce);
                Assert.True(result);
                Assert.Equal(message.ToArray(), decryptedMessage);
            }
        }

        [Fact]
        public void Test_Decrypt_NonceEmpty_ThrowsArgumentException()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);

                var message = Array.Empty<byte>();
                var cipherText = Array.Empty<byte>();

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        secretBox.Decrypt(cipherText, message, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("nonce is empty", exception.Message);
            }
        }

        [Fact]
        public void Test_Decrypt_MessageBufferTooSmall_ThrowsArgumentException()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);

                var message = Array.Empty<byte>();
                var cipherText = new byte[XChaChaSecretBox.GetCipherTextLength(1)];

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        secretBox.Decrypt(cipherText, message, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("message buffer is not large enough", exception.Message);
            }
        }

        [Fact]
        public void Test_Decryption_InPlace_DecryptsCiphertext()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var cipherText = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                secretBox.Encrypt(message, cipherText, nonce);

                var result = secretBox.Decrypt(cipherText, cipherText, nonce);
                Assert.True(result);
                Assert.Equal(message.ToArray(), cipherText.Take(messageLength));
            }
        }

        [Theory]
        [InlineData(4, 0)]
        [InlineData(15, 0)]
        [InlineData(17, 1)]
        [InlineData(1024, 1008)]
        public void Test_GetPlaintextLength_ReturnsCorrectLength(int ciphertextLength, int expectedPlaintextLength)
        {
            var plaintextLength = XChaChaSecretBox.GetPlaintextLength(ciphertextLength);
            Assert.Equal(expectedPlaintextLength, plaintextLength);
        }
        #endregion
    }
}