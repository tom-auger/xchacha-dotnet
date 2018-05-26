namespace XChaChaDotNet
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using XChaChaDotNet.UnitTests;
    using Xunit;

    public class XChaChaSecretKeyCipherTests
    {
        public static readonly TheoryData<Type> CipherTypes = new TheoryData<Type>
        {
            typeof(XChaChaSecretBoxCipher),
            typeof(XChaChaAeadCipher)
        };

        #region Encryption
        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Encrypt_ProducesNonZeroOutput(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();

                var message = TestConstants.MessageBytes;
                var ciphertext = new byte[cipher.GetCipherTextLength(message.Length)];

                cipher.Encrypt(message, ciphertext, key, nonce);

                Assert.False(ciphertext.All(b => b == 0));
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Encrypt_NonceEmpty_ThrowsArgumentException(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var message = TestConstants.MessageBytes;
                var nonce = new XChaChaNonce();
                Action action = () =>
                    {
                        cipher.Encrypt(message, key, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("nonce is empty", exception.Message);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Encrypt_CiphertextBufferTooSmall_ThrowsArgumentException(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var message = TestConstants.MessageBytes;
                var ciphertext = Array.Empty<byte>();
                var nonce = XChaChaNonce.Generate();
                Action action = () =>
                    {
                        cipher.Encrypt(message, ciphertext, key, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("ciphertext buffer is not large enough", exception.Message);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Encrypt_ReturnsNonZeroCiphertext(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();

                var message = TestConstants.MessageBytes;
                var ciphertext = cipher.Encrypt(message, key, nonce);

                Assert.False(ciphertext.All(b => b == 0));
            }
        }
        #endregion

        #region Decryption
        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Decrypt_CanDecryptCiphertext(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();
                var message = TestConstants.MessageBytes;

                var ciphertext = cipher.Encrypt(message, key, nonce);
                var result = cipher.Decrypt(ciphertext, key, nonce);

                Assert.Equal(message, result);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Decrypt_WrongNonce_ThrowsException(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();
                var message = TestConstants.MessageBytes;

                var ciphertext = cipher.Encrypt(message, key, nonce);
                Action action = () =>
                {
                    var wrongNonce = XChaChaNonce.Generate();
                    var result = cipher.Decrypt(ciphertext, key, wrongNonce);
                };

                var exception = Assert.Throws<CryptographicException>(action);
                Assert.Equal("decryption failed", exception.Message);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Decrypt_WrongKey_ThrowsException(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = new XChaChaNonce(TestConstants.Nonce);
                var message = TestConstants.MessageBytes;

                var ciphertext = cipher.Encrypt(message, key, nonce);
                using (var wrongKey = XChaChaKey.Generate())
                {
                    Action action = () =>
                    {
                        var result = cipher.Decrypt(ciphertext, wrongKey, nonce);
                    };

                    var exception = Assert.Throws<CryptographicException>(action);
                    Assert.Equal("decryption failed", exception.Message);
                }
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_TryDecrypt_CanDecryptCiphertext(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = new byte[cipher.GetCipherTextLength(message.Length)];

                cipher.Encrypt(message, ciphertext, key, nonce);

                var decryptedMessage = new byte[messageLength];
                var result = cipher.TryDecrypt(ciphertext, decryptedMessage, key, nonce);
                Assert.True(result);
                Assert.Equal(message, decryptedMessage);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Decrypt_NonceEmpty_ThrowsArgumentException(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = new XChaChaNonce();
                var message = Array.Empty<byte>();
                var ciphertext = Array.Empty<byte>();

                Action action = () =>
                    {
                        cipher.Decrypt(ciphertext, message, key, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("nonce is empty", exception.Message);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Decrypt_MessageBufferTooSmall_ThrowsArgumentException(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var message = Array.Empty<byte>();
                var ciphertext = new byte[cipher.GetCipherTextLength(1)];
                var nonce = XChaChaNonce.Generate();

                Action action = () =>
                    {
                        cipher.Decrypt(ciphertext, message, key, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("message buffer is not large enough", exception.Message);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_TryDecrypt_InPlace_DecryptsCiphertext(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = new byte[cipher.GetCipherTextLength(message.Length)];

                cipher.Encrypt(message, ciphertext, key, nonce);

                var result = cipher.TryDecrypt(ciphertext, ciphertext, key, nonce);
                Assert.True(result);
                Assert.Equal(message, ciphertext.Take(messageLength));
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Decrypt_Fails_ThrowsCryptographicException(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = new byte[cipher.GetCipherTextLength(message.Length)];

                cipher.Encrypt(message, ciphertext, key, nonce);

                Action action = () =>
                    {
                        var wrongNonce = XChaChaNonce.Generate();
                        cipher.Decrypt(ciphertext, ciphertext, key, wrongNonce);
                    };
                var exception = Assert.Throws<CryptographicException>(action);
                Assert.Equal("decryption failed", exception.Message);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_TryDecrypt_Fails_ReturnsFalse(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = new byte[cipher.GetCipherTextLength(message.Length)];

                cipher.Encrypt(message, ciphertext, key, nonce);

                var wrongNonce = XChaChaNonce.Generate();
                var result = cipher.TryDecrypt(ciphertext, ciphertext, key, wrongNonce);
                Assert.False(result);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Decrypt_ReturnsMessage(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = cipher.Encrypt(message, key, nonce);

                var result = cipher.Decrypt(ciphertext, key, nonce);
                Assert.Equal(message, result);
            }
        }
        #endregion

        #region Validation
        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_EncryptWithReturn_MaxMessageLengthExceeded_ThrowsException(Type cipherType)
        {
            unsafe
            {
                using (var key = XChaChaKey.Generate())
                {
                    var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                    Action action = () =>
                    {
                        var message = new ReadOnlySpan<byte>(IntPtr.Zero.ToPointer(), int.MaxValue);
                        var nonce = XChaChaNonce.Generate();
                        cipher.Encrypt(message, key, nonce);
                    };

                    var exception = Assert.Throws<ArgumentException>(action);
                    Assert.Equal("message is too long", exception.Message);
                }
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Encrypt_MaxMessageLengthExceeded_ThrowsException(Type cipherType)
        {
            unsafe
            {
                using (var key = XChaChaKey.Generate())
                {
                    var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                    Action action = () =>
                    {
                        var message = new ReadOnlySpan<byte>(IntPtr.Zero.ToPointer(), int.MaxValue);
                        var ciphertext = new Span<byte>(IntPtr.Zero.ToPointer(), int.MaxValue);
                        var nonce = XChaChaNonce.Generate();
                        cipher.Encrypt(message, ciphertext, key, nonce);
                    };

                    var exception = Assert.Throws<ArgumentException>(action);
                    Assert.Equal("message is too long", exception.Message);
                }
            }
        }
        #endregion
    }
}