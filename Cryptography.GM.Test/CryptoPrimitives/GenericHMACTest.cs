using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Cryptography.GM.Primitives;
using Xunit;
// ReSharper disable InconsistentNaming

namespace Cryptography.GM.Test.CryptoPrimitives;

public class GenericHMACTest
{
    [Theory]
    [MemberData(nameof(GenerateRandomTest), 3)]
    public void TestHMAC(byte[] k, byte[] d)
    {
        Assert.Equal(new HMACMD5(k).ComputeHash(d), new GenericHMAC<MD5>(MD5.Create(), 64, k).ComputeHash(d));
        Assert.Equal(new HMACSHA1(k).ComputeHash(d), new GenericHMAC<SHA1>(SHA1.Create(), 64, k).ComputeHash(d));
        Assert.Equal(new HMACSHA256(k).ComputeHash(d), new GenericHMAC<SHA256>(SHA256.Create(), 64, k).ComputeHash(d));
        Assert.Equal(new HMACSHA512(k).ComputeHash(d), new GenericHMAC<SHA512>(SHA512.Create(), 128, k).ComputeHash(d));
    }

    [ExcludeFromCodeCoverage]
    public static IEnumerable<object?[]> GenerateRandomTest(int n)
    {
        var rng = new Random();
        while (n-- > 0) {
            var hmacKey = new byte[1 + (rng.Next() & 0xFF)];
            var data = new byte[rng.Next() & 0xFFF];
            rng.NextBytes(hmacKey);
            rng.NextBytes(data);
            yield return new object[] { hmacKey, data };
        }
    }
}
