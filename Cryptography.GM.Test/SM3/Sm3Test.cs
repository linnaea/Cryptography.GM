using System;
using Xunit;

namespace Cryptography.GM.Test.SM3;

public class Sm3Test
{
    [Fact]
    public void TestBitHash()
    {
        var r = new byte[3];
        new Random().NextBytes(r);
        using var sm3 = System.Security.Cryptography.SM3.Create();
        var reference = sm3.ComputeHash(r);

        sm3.HashCoreBits(r, 9);
        r[0] = r[1];
        r[0] <<= 1;
        sm3.HashCoreBits(r, 7);
        r[0] = r[2];
        sm3.HashCoreBits(r, 3);
        r[0] <<= 3;
        sm3.HashCoreBits(r, 5);
        sm3.TransformFinalBlock(EmptyArray<byte>.Instance, 0, 0);
        Assert.Equal(reference, sm3.Hash);
    }
}
