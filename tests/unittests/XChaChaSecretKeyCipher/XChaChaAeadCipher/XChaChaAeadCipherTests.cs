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
        public void Test_Encrypt_WithAssociatedData_ProducesNonZeroOutput()
        {
           using (var key = XChaChaKey.Generate())
            {
                var aeadCipher = new XChaChaAeadCipher();
                var nonce = XChaChaNonce.Generate();
                var associatedData = Encoding.UTF8.GetBytes(DateTime.Now.ToString());

                var message = RandomBytesGenerator.NextBytes(1024 * 1024);
                var ciphertext = new byte[aeadCipher.GetCipherTextLength(message.Length)];

                aeadCipher.Encrypt(message, ciphertext, key, nonce, associatedData);

                Assert.False(ciphertext.All(b => b == 0));
            }
        }
        #endregion

        #region Decryption
        [Fact]
        public void Test_Decrypt_WithAssociatedData()
        {
            using (var key = XChaChaKey.Generate())
            {
                var aeadCipher = new XChaChaAeadCipher();
                var nonce = XChaChaNonce.Generate();
                var associatedData = Encoding.UTF8.GetBytes(DateTime.Now.ToString());

                const int messageLength = 1024 * 1024;
                var message = RandomBytesGenerator.NextBytes(messageLength);
                var ciphertext = aeadCipher.Encrypt(message, key, nonce, associatedData);

                var result = aeadCipher.Decrypt(ciphertext, key, nonce, associatedData);
                Assert.Equal(message.ToArray(), result.ToArray());
            }
        }
        #endregion

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
    }
}