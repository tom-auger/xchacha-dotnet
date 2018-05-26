namespace XChaChaDotNet
{
    using System;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using XChaChaDotNet.UnitTests;
    using Xunit;

    public class XChaChaAeadCipherTests
    {
        #region Encryption
        [Fact]
        public void Test_Encrypt_WithAdditionalData_ProducesNonZeroOutput()
        {
            using (var key = XChaChaKey.Generate())
            {
                var aeadCipher = new XChaChaAeadCipher();
                var nonce = XChaChaNonce.Generate();
                var additionalData = Encoding.UTF8.GetBytes(DateTime.Now.ToString());

                var message = RandomBytesGenerator.NextBytes(1024 * 1024);
                var ciphertext = new byte[aeadCipher.GetCipherTextLength(message.Length)];

                aeadCipher.Encrypt(message, ciphertext, key, nonce, additionalData);

                Assert.False(ciphertext.All(b => b == 0));
            }
        }

        [Fact]
        public void Test_Encrypt_WithAdditionalData_ReturnsNonZeroOutput()
        {
            using (var key = XChaChaKey.Generate())
            {
                var aeadCipher = new XChaChaAeadCipher();
                var nonce = XChaChaNonce.Generate();
                var additionalData = Encoding.UTF8.GetBytes(DateTime.Now.ToString());

                var message = RandomBytesGenerator.NextBytes(1024 * 1024);
                var ciphertext = aeadCipher.Encrypt(message, key, nonce, additionalData);

                Assert.False(ciphertext.All(b => b == 0));
            }
        }
        #endregion

        #region Decryption
        [Fact]
        public void Test_Decrypt_WithAdditionalData_Success()
        {
            using (var key = XChaChaKey.Generate())
            {
                var aeadCipher = new XChaChaAeadCipher();
                var nonce = XChaChaNonce.Generate();
                var additionalData = Encoding.UTF8.GetBytes(DateTime.Now.ToString());

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = aeadCipher.Encrypt(message, key, nonce, additionalData);

                var result = aeadCipher.Decrypt(ciphertext, key, nonce, additionalData);
                Assert.Equal(message, result);
            }
        }

        [Fact]
        public void Test_Decrypt_WithInvalidAdditionalData_Fails()
        {
            using (var key = XChaChaKey.Generate())
            {
                var aeadCipher = new XChaChaAeadCipher();
                var nonce = XChaChaNonce.Generate().ToArray();
                var additionalData = Encoding.UTF8.GetBytes(DateTime.Now.ToString());

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = aeadCipher.Encrypt(message, key, new XChaChaNonce(nonce), additionalData);

                var invalidAdditionalData = Encoding.UTF8.GetBytes("banana");
                Action action = () => { aeadCipher.Decrypt(ciphertext, key, new XChaChaNonce(nonce), invalidAdditionalData); };
                var exception = Assert.Throws<CryptographicException>(action);

                Assert.Equal("decryption failed", exception.Message);
            }
        }
        #endregion

        #region Validation
        [Theory]
        [InlineData(4, 0)]
        [InlineData(15, 0)]
        [InlineData(17, 1)]
        [InlineData(1024, 1008)]
        public void Test_GetPlaintextLength_ReturnsCorrectLength(int ciphertextLength, int expectedPlaintextLength)
        {
            var aeadCipher = new XChaChaAeadCipher();
            var plaintextLength = aeadCipher.GetPlaintextLength(ciphertextLength);
            Assert.Equal(expectedPlaintextLength, plaintextLength);
        }

        [Fact]
        public void Test_EncryptWithReturn_MaxMessageLengthExceeded_ThrowsException()
        {
            unsafe
            {
                using (var key = XChaChaKey.Generate())
                {
                    var aeadCipher = new XChaChaAeadCipher();
                    Action action = () =>
                    {
                        var message = new ReadOnlySpan<byte>(IntPtr.Zero.ToPointer(), int.MaxValue);
                        var additionalData = Encoding.UTF8.GetBytes(DateTime.Now.ToString());
                        var nonce = XChaChaNonce.Generate();
                        aeadCipher.Encrypt(message, key, nonce, additionalData);
                    };

                    var exception = Assert.Throws<ArgumentException>(action);
                    Assert.Equal("message is too long", exception.Message);
                }
            }
        }

        [Fact]
        public void Test_Encrypt_MaxMessageLengthExceeded_ThrowsException()
        {
            unsafe
            {
                using (var key = XChaChaKey.Generate())
                {
                    var aeadCipher = new XChaChaAeadCipher();
                    Action action = () =>
                    {
                        var message = new ReadOnlySpan<byte>(IntPtr.Zero.ToPointer(), int.MaxValue);
                        var ciphertext = new Span<byte>(IntPtr.Zero.ToPointer(), int.MaxValue);
                        var additionalData = Encoding.UTF8.GetBytes(DateTime.Now.ToString());
                        var nonce = XChaChaNonce.Generate();
                        aeadCipher.Encrypt(message, ciphertext, key, nonce, additionalData);
                    };

                    var exception = Assert.Throws<ArgumentException>(action);
                    Assert.Equal("message is too long", exception.Message);
                }
            }
        }
        #endregion
    }
}