using System.Security.Cryptography;
using Xunit;

namespace Cryptography.GM.Test.SM4;

public class Sm4Reference
{
    [Fact]
    public void Sm4Vector1()
    {
        var key = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
        var expected = new byte[] { 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46 };
        using var sm4 = System.Security.Cryptography.SM4.Create();
        sm4.Key = key;
        sm4.Mode = CipherMode.ECB;
        sm4.Padding = PaddingMode.None;

        using var enc = sm4.CreateEncryptor();
        using var dec = sm4.CreateDecryptor();

        var cipherText = enc.TransformFinalBlock(key, 0, key.Length);
        Assert.Equal(expected, cipherText);

        var plaintext = dec.TransformFinalBlock(cipherText, 0, cipherText.Length);
        Assert.Equal(key, plaintext);
    }
}
