namespace XChaChaDotNet
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
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
                var ciphertext = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                secretBox.Encrypt(message, ciphertext, nonce);

                Assert.False(ciphertext.All(b => b == 0));
            }
        }

        [Fact]
        public void Test_Encrypt_NonceEmpty_ThrowsArgumentException()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);

                var message = Array.Empty<byte>();
                var ciphertext = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        secretBox.Encrypt(message, ciphertext, nonce);
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
                var ciphertext = Array.Empty<byte>();

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        secretBox.Encrypt(message, ciphertext, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("ciphertext buffer is not large enough", exception.Message);
            }
        }

        [Fact]
        public void Test_Encrypt_ReturnsCiphertext()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);
                var nonce = XChaChaNonce.Generate();

                var message = RandomBytesGenerator.NextBytes(1024 * 1024);
                var ciphertext = secretBox.Encrypt(message, nonce);

                Assert.False(ciphertext.ToArray().All(b => b == 0));
            }
        }
        #endregion

        #region Decryption
        [Fact]
        public void Test_TryDecrypt_CanDecryptCiphertext()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                secretBox.Encrypt(message, ciphertext, nonce);

                var decryptedMessage = new byte[messageLength];
                var result = secretBox.TryDecrypt(ciphertext, decryptedMessage, nonce);
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
                var ciphertext = Array.Empty<byte>();

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        secretBox.Decrypt(ciphertext, message, nonce);
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
                var ciphertext = new byte[XChaChaSecretBox.GetCipherTextLength(1)];

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        secretBox.Decrypt(ciphertext, message, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("message buffer is not large enough", exception.Message);
            }
        }

        [Fact]
        public void Test_TryDecrypt_InPlace_DecryptsCiphertext()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                secretBox.Encrypt(message, ciphertext, nonce);

                var result = secretBox.TryDecrypt(ciphertext, ciphertext, nonce);
                Assert.True(result);
                Assert.Equal(message.ToArray(), ciphertext.Take(messageLength));
            }
        }

        [Fact]
        public void Test_Decrypt_Fails_ThrowsCryptographicException()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                secretBox.Encrypt(message, ciphertext, nonce);

                Action action = () =>
                    {
                        var wrongNonce = XChaChaNonce.Generate();
                        secretBox.Decrypt(ciphertext, ciphertext, wrongNonce);
                    };
                var exception = Assert.Throws<CryptographicException>(action);
                Assert.Equal("decryption failed", exception.Message);
            }
        }

        [Fact]
        public void Test_TryDecrypt_Fails_ReturnsFalse()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = new byte[XChaChaSecretBox.GetCipherTextLength(message.Length)];

                secretBox.Encrypt(message, ciphertext, nonce);

                var wrongNonce = XChaChaNonce.Generate();
                var result = secretBox.TryDecrypt(ciphertext, ciphertext, wrongNonce);
                Assert.False(result);
            }
        }

        [Fact]
        public void Test_Decrypt_ReturnsMessage()
        {
            using (var key = XChaChaKey.Generate())
            {
                var secretBox = new XChaChaSecretBox(key);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = secretBox.Encrypt(message, nonce);

                var result = secretBox.Decrypt(ciphertext, nonce);
                Assert.Equal(message.ToArray(), result.ToArray());
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