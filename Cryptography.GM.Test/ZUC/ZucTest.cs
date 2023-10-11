using System;
using Xunit;
#pragma warning disable CS0618 // Type or member is obsolete

namespace Cryptography.GM.Test.ZUC;

public class ZucTest
{
    [Theory]
    [InlineData(ZucVersion.Zuc15)]
    [InlineData(ZucVersion.Zuc256E)]
    [InlineData(ZucVersion.Zuc256M32)]
    [InlineData(ZucVersion.Zuc256M64)]
    [InlineData(ZucVersion.Zuc256M128)]
    public void CrossLoadStateThrows(ZucVersion v)
    {
        using var st14 = new ZucKeyStreamGenerator(new byte[32], new byte[23], ZucVersion.Zuc14);
        using var stTest = new ZucKeyStreamGenerator(new byte[32], new byte[23], v);
        Assert.Throws<InvalidOperationException>(() => stTest.LoadState(st14.DumpState()));
        Assert.Throws<InvalidOperationException>(() => st14.LoadState(stTest.DumpState()));
        Assert.Throws<NotSupportedException>(() => stTest.Reset());
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
        Assert.Throws<IndexOutOfRangeException>(() => new ZucKeyStreamGenerator(EmptyArray<byte>.Instance, EmptyArray<byte>.Instance));
    }
}
