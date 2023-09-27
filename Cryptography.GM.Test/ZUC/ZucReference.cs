using System;
using System.Linq;
using Xunit;

#pragma warning disable CS0618
namespace Cryptography.GM.Test.ZUC;

public class ZucReference
{
    [Theory]
    [InlineData(
        new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        0x27BEDE74u, 0x018082DAu
    )]
    [InlineData(
        new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
        0x0657CFA0u, 0x7096398Bu
    )]
    [InlineData(
        new byte[] { 0x3D, 0x4C, 0x4B, 0xE9, 0x6A, 0x82, 0xFD, 0xAE, 0xB5, 0x8F, 0x64, 0x1D, 0xB1, 0x7B, 0x45, 0x5B },
        new byte[] { 0x84, 0x31, 0x9A, 0xA8, 0xDE, 0x69, 0x15, 0xCA, 0x1F, 0x6B, 0xDA, 0x6B, 0xFB, 0xD8, 0xC7, 0x66 },
        0x14F1C272u, 0x3279C419u
    )]
    public void Zuc15Vector(byte[] sk, byte[] iv, uint z1, uint z2) => Zuc15TestVector2(sk, iv, z1, z2);

    private static ZucKeyStreamGenerator Zuc15TestVector2(byte[] sk, byte[] iv, uint z1, uint z2)
    {
        var cipher = new ZucKeyStreamGenerator(sk, iv);

        Assert.Equal(z1, cipher.NextKey());
        Assert.Equal(z2, cipher.NextKey());
        return cipher;
    }

    [Theory]
    [InlineData(
        new byte[] {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        new byte[] {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        },
        new[] {
            0x58d03ad6u, 0x2e032ce2u, 0xdafc683au, 0x39bdcb03u, 0x52a2bc67u, 0xf1b7de74u, 0x163ce3a1u,
            0x01ef5558u, 0x9639d75bu, 0x95fa681bu, 0x7f090df7u, 0x56391cccu, 0x903b7612u, 0x744d544cu,
            0x17bc3fadu, 0x8b163b08u, 0x21787c0bu, 0x97775bb8u, 0x4943c6bbu, 0xe8ad8afdu
        })]
    [InlineData(
        new byte[] {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        },
        new byte[] {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        },
        new[] {
            0x3356cbaeu, 0xd1a1c18bu, 0x6baa4ffeu, 0x343f777cu, 0x9e15128fu, 0x251ab65bu, 0x949f7b26u,
            0xef7157f2u, 0x96dd2fa9u, 0xdf95e3eeu, 0x7a5be02eu, 0xc32ba585u, 0x505af316u, 0xc2f9ded2u,
            0x7cdbd935u, 0xe441ce11u, 0x15fd0a80u, 0xbb7aef67u, 0x68989416u, 0xb8fac8c2u
        })]
    public void Zuc256EVector(byte[] sk, byte[] iv, uint[] seq)
    {
        var cipher = new ZucKeyStreamGenerator(sk, iv, ZucVersion.Zuc256E);
        Assert.Equal(seq, cipher.EnumerateKeys().Take(seq.Length));
    }

    [Fact]
    public void Zuc15Vector4()
    {
        var cipher = Zuc15TestVector2(
            new byte[] { 0x4D, 0x32, 0x0B, 0xFA, 0xD4, 0xC2, 0x85, 0xBF, 0xD6, 0xB8, 0xBD, 0x00, 0xF3, 0x9D, 0x8B, 0x41 },
            new byte[] { 0x52, 0x95, 0x9D, 0xAB, 0xA0, 0xBF, 0x17, 0x6E, 0xCE, 0x2D, 0xC3, 0x15, 0x04, 0x9E, 0xB5, 0x74 },
            0xED4400E7u, 0x0633E5C5u);

        for (var i = 2; i < 1999; i++) cipher.NextKey();
        Assert.Equal(0x7A574CDBu, cipher.NextKey());
    }

    [Theory]
    [InlineData(
        new byte[] { 123, 149, 193, 87, 42, 150, 117, 4, 209, 101, 85, 57, 46, 117, 49, 243 },
        new byte[] { 92, 80, 241, 10, 0, 217, 47, 224, 48, 203, 0, 45, 204, 0, 0, 17 },
        new byte[] { 92, 182, 241, 10, 0, 217, 47, 224, 48, 203, 0, 45, 204, 0, 0, 17 },
        new[] {
            0xf09cc17du, 0x41f12d3fu, 0x453ac0c3u, 0xcadcef9fu, 0xf98fb964u, 0xca6e576eu, 0xb48b813u, 0x6c43da22u
        })]
    [InlineData(
        new byte[] { 87, 4, 95, 13, 161, 32, 199, 61, 20, 147, 56, 84, 126, 205, 165, 148 },
        new byte[] { 166, 166, 112, 38, 192, 214, 34, 211, 170, 25, 18, 71, 4, 135, 68, 5 },
        new byte[] { 116, 166, 112, 38, 192, 214, 34, 211, 170, 25, 18, 71, 4, 135, 68, 5 },
        new[] {
            0xbfe800d5u, 0x0360a22bu, 0x6c4554c8u, 0x67f00672u, 0x2ce94f3fu, 0xf94d12bau, 0x11c382b3u, 0xcbaf4b31u
        })]
    public void Zuc14WeakKeyIvCollision(byte[] sk, byte[] iv1, byte[] iv2, uint[] keystream)
    {
        var cipher1 = new ZucKeyStreamGenerator(sk, iv1, ZucVersion.Zuc14);
        var cipher2 = new ZucKeyStreamGenerator(sk, iv2, ZucVersion.Zuc14);
        foreach (var tv in keystream) {
            Assert.Equal(tv, cipher1.NextKey());
            Assert.Equal(tv, cipher2.NextKey());
        }

        for (int i = 0; i < 5000; i++)
            Assert.Equal(cipher2.NextKey(), cipher1.NextKey());
    }

    [Theory]
    [InlineData(ZucVersion.Zuc15)]
    [InlineData(ZucVersion.Zuc256E)]
    [InlineData(ZucVersion.Zuc256M32)]
    [InlineData(ZucVersion.Zuc256M64)]
    [InlineData(ZucVersion.Zuc256M128)]
    public void CrossLoadStateThrows(ZucVersion v)
    {
        var st14 = new ZucKeyStreamGenerator(new byte[32], new byte[23], ZucVersion.Zuc14);
        var sttest = new ZucKeyStreamGenerator(new byte[32], new byte[23], v);
        Assert.Throws<InvalidOperationException>(() => sttest.LoadState(st14.DumpState()));
        Assert.Throws<InvalidOperationException>(() => st14.LoadState(sttest.DumpState()));
    }

    [Fact]
    public void BadVersionThrows()
    {
        var st = new ZucKeyStreamGenerator(new byte[32], new byte[23], ZucVersion.Zuc14).DumpState();
        for (var i = 0; i < st.Length; i++) st[i] = 0;
        Assert.Throws<InvalidOperationException>(() => new ZucKeyStreamGenerator(st));
        Assert.Throws<ArgumentException>(() => new ZucKeyStreamGenerator(new byte[32], new byte[23], 0));
    }

    [Fact]
    public void BadInitializationThrows()
    {
        var badIv = new byte[25];
        var badState = new uint[10];
        for (var i = 0; i < badIv.Length; i++) badIv[i] = 0x80;
        badState[0] = (uint)ZucVersion.Zuc15;
        Assert.Throws<ArgumentException>(() => new ZucKeyStreamGenerator(new byte[32], badIv, ZucVersion.Zuc256E));
        Assert.Throws<InvalidOperationException>(() => new ZucKeyStreamGenerator(badState));
        Assert.Throws<IndexOutOfRangeException>(() => new ZucKeyStreamGenerator(Array.Empty<byte>(), Array.Empty<byte>()));
    }
}
