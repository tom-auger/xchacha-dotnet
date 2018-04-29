namespace XChaChaDotNet
{
    using System;

    /// <summary>
    /// Represents the xchacha_secret_box construction. This is based on the NaCl crypto_secretbox_xsalsa20poly1305,
    /// but uses xchacha rather than xsalsa.
    /// </summary>
    public interface IXChaChaSecretBoxCipher : IXChaChaSecretKeyCipher
    {
    }
}