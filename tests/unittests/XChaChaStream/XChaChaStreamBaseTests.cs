namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using Xunit;

    public class XChaChaStreamBaseTests
    {
        [Fact]
        public void Test_Write_NullBuffer_ExceptionThrown()
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Write(null, 0, 1);
                Assert.Throws<ArgumentNullException>(action);
            }
        }

        [Fact]
        public void Test_Write_OffsetNegative_ExceptionThrown()
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Write(Array.Empty<byte>(), -1, 1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Fact]
        public void Test_Write_CountNegative_ExceptionThrown()
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Write(Array.Empty<byte>(), 0, -1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Fact]
        public void Test_Write_ParametersInconsistent_ExceptionThrown()
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Write(Array.Empty<byte>(), 3, 1);
                Assert.Throws<ArgumentException>(action);
            }
        }

        [Fact]
        public void Test_Read_NullBuffer_ExceptionThrown()
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Read(null, 0, 1);
                Assert.Throws<ArgumentNullException>(action);
            }
        }

        [Fact]
        public void Test_Read_OffsetNegative_ExceptionThrown()
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Read(Array.Empty<byte>(), -1, 1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Fact]
        public void Test_Read_CountNegative_ExceptionThrown()
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Read(Array.Empty<byte>(), 0, -1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Fact]
        public void Test_Read_ParametersInconsistent_ExceptionThrown()
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Read(Array.Empty<byte>(), 3, 1);
                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("buffer length, offset, and count are inconsistent", exception.Message);
            }
        }

        [Theory]
        [InlineData(EncryptionMode.Encrypt)]
        [InlineData(EncryptionMode.Decrypt)]
        public void Test_Initialize_KeyNull_ThrowsNullArgumentException(EncryptionMode mode)
        {
            Action action = () => new XChaChaBufferedStream(Stream.Null, null, mode);
            Assert.Throws<ArgumentNullException>(action);
        }

        [Fact]
        public void Test_Initialize_Decrypt_WrongHeaderLength_ThrowsCryptographicException()
        {
            var invalidHeader = new byte[3];
            using (var key = XChaChaKey.Generate())
            using (var ciphertextStream = new MemoryStream(invalidHeader))
            {
                Action action = () => new XChaChaBufferedStream(ciphertextStream, key, EncryptionMode.Decrypt);
                var exception = Assert.Throws<CryptographicException>(action);
                Assert.Equal("invalid or corrupt header", exception.Message);
            }
        }
    }
}