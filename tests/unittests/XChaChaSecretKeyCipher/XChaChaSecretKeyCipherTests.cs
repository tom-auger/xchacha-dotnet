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

                var message = RandomBytesGenerator.NextBytes(1024 * 1024);
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
                var message = Array.Empty<byte>();
                var ciphertext = new byte[cipher.GetCipherTextLength(message.Length)];

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        cipher.Encrypt(message, ciphertext, key, nonce);
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
                var message = Array.Empty<byte>();
                var ciphertext = Array.Empty<byte>();

                Action action = () =>
                    {
                        XChaChaNonce nonce;
                        cipher.Encrypt(message, ciphertext, key, nonce);
                    };

                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("ciphertext buffer is not large enough", exception.Message);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Encrypt_ReturnsCiphertext(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var nonce = XChaChaNonce.Generate();

                var message = RandomBytesGenerator.NextBytes(1024 * 1024);
                var ciphertext = cipher.Encrypt(message, key, nonce);

                Assert.False(ciphertext.ToArray().All(b => b == 0));
            }
        }
        #endregion

        #region Decryption
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
                Assert.Equal(message.ToArray(), decryptedMessage);
            }
        }

        [Theory]
        [MemberData(nameof(CipherTypes))]
        public void Test_Decrypt_NonceEmpty_ThrowsArgumentException(Type cipherType)
        {
            using (var key = XChaChaKey.Generate())
            {
                var cipher = (XChaChaSecretKeyCipher)Activator.CreateInstance(cipherType);
                var message = Array.Empty<byte>();
                var ciphertext = Array.Empty<byte>();

                Action action = () =>
                    {
                        XChaChaNonce nonce;
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

                Action action = () =>
                    {
                        XChaChaNonce nonce;
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
                Assert.Equal(message.ToArray(), ciphertext.Take(messageLength));
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
                Assert.Equal(message.ToArray(), result.ToArray());
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
                        var cipherText = new Span<byte>(IntPtr.Zero.ToPointer(), int.MaxValue);
                        var nonce = XChaChaNonce.Generate();
                        cipher.Encrypt(message, cipherText, key, nonce);
                    };

                    var exception = Assert.Throws<ArgumentException>(action);
                    Assert.Equal("message is too long", exception.Message);
                }
            }
        }
        #endregion
    }
}