namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.IO;
    using Xunit;

    public class XChaChaStreamBaseTests
    {
        [Fact]
        public void Test_Write_NullBuffer_ExceptionThrown()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Write(null, 0, 1);
                Assert.Throws<ArgumentNullException>(action);
            }
        }

        [Fact]
        public void Test_Write_OffsetNegative_ExceptionThrown()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Write(Array.Empty<byte>(), -1, 1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Fact]
        public void Test_Write_CountNegative_ExceptionThrown()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Write(Array.Empty<byte>(), 0, -1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Fact]
        public void Test_Write_ParametersInconsistent_ExceptionThrown()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Write(Array.Empty<byte>(), 3, 1);
                Assert.Throws<ArgumentException>(action);
            }
        }

        [Fact]
        public void Test_Read_NullBuffer_ExceptionThrown()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Read(null, 0, 1);
                Assert.Throws<ArgumentNullException>(action);
            }
        }

        [Fact]
        public void Test_Read_OffsetNegative_ExceptionThrown()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Read(Array.Empty<byte>(), -1, 1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Fact]
        public void Test_Read_CountNegative_ExceptionThrown()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Read(Array.Empty<byte>(), 0, -1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Fact]
        public void Test_Read_ParametersInconsistent_ExceptionThrown()
        {
            var key = XChaChaKeyGenerator.GenerateKey();
            using (var xchachaStream = new XChaChaBufferedStream(Stream.Null, key, EncryptionMode.Encrypt))
            {
                Action action = () => xchachaStream.Read(Array.Empty<byte>(), 3, 1);
                Assert.Throws<ArgumentException>(action);
            }
        }
    }
}