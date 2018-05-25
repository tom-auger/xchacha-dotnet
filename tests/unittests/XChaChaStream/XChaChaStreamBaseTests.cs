namespace XChaChaDotNet.UnitTests
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using Xunit;
    using static TestConstants;

    public class XChaChaStreamBaseTests
    {
        public static readonly TheoryData<Type> StreamTypes = new TheoryData<Type>
        {
            typeof(XChaChaStream),
            typeof(XChaChaBufferedStream)
        };

        public static readonly TheoryData<Type, EncryptionMode> StreamsAndEncryptionModes = new TheoryData<Type, EncryptionMode>
        {
            { typeof(XChaChaStream), EncryptionMode.Encrypt },
            { typeof(XChaChaStream), EncryptionMode.Decrypt },
            { typeof(XChaChaBufferedStream), EncryptionMode.Encrypt },
            { typeof(XChaChaBufferedStream), EncryptionMode.Decrypt }
        };

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_Write_NullBuffer_ExceptionThrown(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, Stream.Null, key, EncryptionMode.Encrypt, false))
            {
                Action action = () => xchachaStream.Write(null, 0, 1);
                Assert.Throws<ArgumentNullException>(action);
            }
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_Write_OffsetNegative_ExceptionThrown(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, Stream.Null, key, EncryptionMode.Encrypt, false))
            {
                Action action = () => xchachaStream.Write(Array.Empty<byte>(), -1, 1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_Write_CountNegative_ExceptionThrown(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, Stream.Null, key, EncryptionMode.Encrypt, false))
            {
                Action action = () => xchachaStream.Write(Array.Empty<byte>(), 0, -1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_Write_ParametersInconsistent_ExceptionThrown(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, Stream.Null, key, EncryptionMode.Encrypt, false))
            {
                Action action = () => xchachaStream.Write(Array.Empty<byte>(), 3, 1);
                Assert.Throws<ArgumentException>(action);
            }
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_Read_NullBuffer_ExceptionThrown(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, Stream.Null, key, EncryptionMode.Encrypt, false))
            {
                Action action = () => xchachaStream.Read(null, 0, 1);
                Assert.Throws<ArgumentNullException>(action);
            }
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_Read_OffsetNegative_ExceptionThrown(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, Stream.Null, key, EncryptionMode.Encrypt, false))
            {
                Action action = () => xchachaStream.Read(Array.Empty<byte>(), -1, 1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_Read_CountNegative_ExceptionThrown(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, Stream.Null, key, EncryptionMode.Encrypt, false))
            {
                Action action = () => xchachaStream.Read(Array.Empty<byte>(), 0, -1);
                Assert.Throws<ArgumentOutOfRangeException>(action);
            }
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_Read_ParametersInconsistent_ExceptionThrown(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, Stream.Null, key, EncryptionMode.Encrypt, false))
            {
                Action action = () => xchachaStream.Read(Array.Empty<byte>(), 3, 1);
                var exception = Assert.Throws<ArgumentException>(action);
                Assert.Equal("buffer length, offset, and count are inconsistent", exception.Message);
            }
        }

        [Theory]
        [MemberData(nameof(StreamsAndEncryptionModes))]
        public void Test_Initialize_KeyNull_ThrowsNullArgumentException(Type streamType, EncryptionMode mode)
        {
            Action action = () => Activator.CreateInstance(streamType, Stream.Null, null, mode, false);
            var exception = Assert.ThrowsAny<Exception>(action);
            // The action throws a System.Reflection.TargetInvocationException. The inner exception contains
            // the actual exception thrown in the class constructor
            Assert.IsType<ArgumentNullException>(exception.InnerException);
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_Initialize_Decrypt_WrongHeaderLength_ThrowsCryptographicException(Type streamType)
        {
            var invalidHeader = new byte[3];
            using (var key = XChaChaKey.Generate())
            using (var ciphertextStream = new MemoryStream(invalidHeader))
            {
                Action action = () => Activator.CreateInstance(streamType, ciphertextStream, key, EncryptionMode.Decrypt, false);
                var exception = Assert.ThrowsAny<Exception>(action);
                // The action throws a System.Reflection.TargetInvocationException. The inner exception contains
                // the actual exception thrown in the class constructor
                var innerException = exception.InnerException;
                Assert.IsType<CryptographicException>(innerException);
                Assert.Equal("invalid or corrupt header", innerException.Message);
            }
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_CanRead_Encrypt_False(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, Stream.Null, key, EncryptionMode.Encrypt, false))
            {
                Assert.False(xchachaStream.CanRead);
            }
        }

        [Theory]
        [MemberData(nameof(StreamTypes))]
        public void Test_CanWrite_Decrypt_False(Type streamType)
        {
            using (var key = XChaChaKey.Generate())
            using (var plaintextStream = new MemoryStream(new byte[StreamHeaderLength]))
            using (var xchachaStream =
                (XChaChaStreamBase)Activator.CreateInstance(streamType, plaintextStream, key, EncryptionMode.Decrypt, false))
            {
                Assert.False(xchachaStream.CanWrite);
            }
        }
    }
}