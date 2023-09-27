using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Cryptography;
using Cryptography.GM.Primitives;
using Xunit;

namespace Cryptography.GM.Test.CryptoPrimitives;

public class CbcTransformTest
{
    [Theory]
    [MemberData(nameof(GenerateRandomTest), 3)]
    public void TestCbc(byte[] k, byte[] iv, byte[] d)
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        var reference = TransformData(aes.CreateEncryptor(k, iv), d);

        var ecb = Aes.Create();
        ecb.Padding = PaddingMode.None;
        ecb.Mode = CipherMode.ECB;
        var encChain = new PaddingTransform(new CbcTransform(ecb.CreateEncryptor(k, iv), iv, false), PaddingMode.PKCS7, false);
        var actual = TransformData(encChain, d);

        Assert.Equal(reference, actual);

        var decChain = new PaddingTransform(new CbcTransform(ecb.CreateDecryptor(k, iv), iv, true), PaddingMode.PKCS7, true);
        var decrypted = TransformData(decChain, actual);
        Assert.Equal(d, decrypted);
    }

    private byte[] TransformData(ICryptoTransform xfrm, byte[] d)
    {
        using var buf = new MemoryStream();
        using (var cryptStream = new CryptoStream(buf, xfrm, CryptoStreamMode.Write)) {
            cryptStream.Write(d, 0, d.Length);
        }

        return buf.ToArray();
    }

    [ExcludeFromCodeCoverage]
    public static IEnumerable<object?[]> GenerateRandomTest(int n)
    {
        var rng = new Random();
        while (n-- > 0) {
            var key = new byte[16];
            var iv = new byte[16];
            var data = new byte[rng.Next() & 0xFFFF];
            rng.NextBytes(key);
            rng.NextBytes(iv);
            rng.NextBytes(data);
            yield return new object[] { key, iv, data };
        }
    }
}
