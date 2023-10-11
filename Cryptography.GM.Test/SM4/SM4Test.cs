using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Xunit;

namespace Cryptography.GM.Test.SM4;

public class SM4Test
{
    [Theory]
    [MemberData(nameof(GenerateTest))]
    public void TestRoundTrip(CipherMode mode, PaddingMode padding, byte[] a)
    {
        using var sm4e = System.Security.Cryptography.SM4.Create();
        sm4e.Mode = mode;
        sm4e.Padding = padding;
        sm4e.GenerateKey();
        sm4e.GenerateIV();

        var a2 = new byte[a.Length + 2];
        Array.Copy(a, 0, a2, 1, a.Length);

        using var enc = sm4e.CreateEncryptor();
        var cipherText = enc.TransformFinalBlock(a2, 1, a.Length);
        Array.Resize(ref cipherText, cipherText.Length + 2);
        Array.Copy(cipherText, 0, cipherText, 1, cipherText.Length - 2);

        using var dec = sm4e.CreateDecryptor();
        var buf = dec.TransformFinalBlock(cipherText, 1, cipherText.Length - 2);
        Assert.Equal(a, buf);

        using var sm4d = System.Security.Cryptography.SM4.Create();
        sm4d.Mode = mode;
        sm4d.Padding = padding;
        sm4d.Key = sm4e.Key;
        sm4d.IV = sm4e.IV;
        using var dec2 = sm4d.CreateDecryptor();
        buf = dec2.TransformFinalBlock(cipherText, 1, cipherText.Length - 2);
        Assert.Equal(a, buf);
    }

    [ExcludeFromCodeCoverage]
    public static IEnumerable<object?[]> GenerateTest()
    {
        var rng = new Random();
        foreach (var mode in new[] { CipherMode.ECB, CipherMode.CBC }) {
            foreach (var padding in new[] { PaddingMode.ISO10126, PaddingMode.PKCS7, PaddingMode.ANSIX923, PaddingMode.Zeros, PaddingMode.None }) {
                var len = rng.Next() & 0xFFF;
                if (padding is PaddingMode.None or PaddingMode.Zeros)
                    len &= 0xF0;

                var a = new byte[len];
                rng.NextBytes(a);
                yield return new object[] { mode, padding, a };
            }
        }
    }
}
