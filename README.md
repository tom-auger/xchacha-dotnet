# XChaCha-DotNet

A .NET wrapper for the XChaCha constructions and APIs provided by [libsodium](https://libsodium.org/) crypto library.

The API supports the new `Span<T>` and `ReadOnlySpan<T>` types. 

Currently only supports .NET Core 2.1. 

# Algorithms and APIs

XChaCha-DotNet contains the following ciphers:

| Class | Algorithm | Description |
--------|-----------| ----------- |
| [XChaChaAeadCipher](https://github.com/tom-auger/xchacha-dotnet/wiki/XChaChaAeadCipher) | XChaCha20-Poly1305 IETF AEAD | XChaCha AEAD cipher with 192-bit nonce and 192-bit key. Poly-1305 used to compute the authentication tag. Supports Additional Authenticated Data. Can safely encrypt messages up to 2^64 bytes. |
| [XChaChaStream](https://github.com/tom-auger/xchacha-dotnet/wiki/XChaChaStream) | XChaCha20-Poly1305 | XChaCha20 stream cipher using Poly-1305 to compute the authentication tags. Automatically generates and rotates nonces. Supports using Additional Authenticated Data. Can safely encrypt messages up to any practical limit.
| [XChaChaBufferedStream](https://github.com/tom-auger/xchacha-dotnet/wiki/XChaChaBufferedStream) | XChaCha20-Poly1305 | XChaCha20 stream cipher using Poly-1305 to compute the authentication tags. Automatically generates and rotates nonces and buffers the input stream to encrypt data in fixed sized blocks. Can safely encrypt messages up to any practical limit. |
| [XChaChaSecretBoxCipher](https://github.com/tom-auger/xchacha-dotnet/wiki/XChaChaSecretBoxCipher) | XChaCha20-Poly1305 | An implementation of the `secret_box` API in the [NaCl](https://nacl.cr.yp.to/secretbox.html) crypto library using XChaCha20 for the cipher and Poly-1305 to compute the authentication tag. |

# Installation

Install from [nuget](https://www.nuget.org/packages/xchacha-dotnet/):

Using the dotnet CLI:

```powershell
dotnet add package xchacha-dotnet
```

Using the package manager:

```powershell
Install-Package xchacha-dotnet
```

# Quick Example

Example encryption/decryption using the [XChaChaAeadCipher](https://github.com/tom-auger/xchacha-dotnet/wiki/XChaChaAeadCipher):

#### Encryption
```csharp
using (var key = XChaChaKey.Generate())
{
    var aeadCipher = new XChaChaAeadCipher();
    var nonce = XChaChaNonce.Generate();
    var message = Encoding.UTF8.GetBytes("Test Message");
    var ciphertext = aeadCipher.Encrypt(message, key, nonce);
}
```

#### Decryption
```csharp
var keyBytes = Convert.FromBase64String("XPRT6QuYZDdytKM55WW+gnZklhaJBcDnOWi1kEI2we4=");
var nonceBytes = Convert.FromBase64String("2eQuiE8Fy70rwlCAi5T2oVEj5MrwxJaT");
var ciphertext = Convert.FromBase64String("w2jUPkWL0PfvnNFM7xq4o9gcVKrMTkd6SsYhLQ==");
using (var key = new XChaChaKey(keyBytes))
{
    var aeadCipher = new XChaChaAeadCipher();
    var nonce = new XChaChaNonce(nonceBytes);
    var message = aeadCipher.Decrypt(ciphertext, key, nonce);
}
```

# Contributing

Please raise issues to report bugs or request new features. Pull requests welcome.