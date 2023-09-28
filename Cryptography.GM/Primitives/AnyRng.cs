using System;
using System.Numerics;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

public abstract class AnyRng : IDisposable
{
    public abstract void NextBytes(byte[] buf);

    public BigInteger NextBigInt(BigInteger minInclusive, BigInteger maxExclusive)
    {
        var range = maxExclusive - minInclusive;
        var rb = range.ToByteArray();
        BigInteger r;
        byte lastMask = 0;
        while ((lastMask & rb.Back()) != rb.Back()) {
            lastMask <<= 1;
            lastMask |= 1;
        }

        do {
            NextBytes(rb);
            rb.Back() &= lastMask;
            r = new BigInteger(rb);
        } while (r >= range);

        return minInclusive + r;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    ~AnyRng() => Dispose(false);
    protected virtual void Dispose(bool disposing)
    { }

    public static implicit operator AnyRng(RandomNumberGenerator rng) => new CryptoRngWrapper(rng);
    public static implicit operator AnyRng(BlockDeriveBytes drbg) => new BlockDrbgWrapper(drbg);
    public static implicit operator AnyRng(DeriveBytes drbg)
        => drbg is BlockDeriveBytes b ? new BlockDrbgWrapper(b) : new DrbgWrapper(drbg);
}

internal sealed class CryptoRngWrapper : AnyRng
{
    private readonly RandomNumberGenerator _rng;
    public CryptoRngWrapper(RandomNumberGenerator rng) => _rng = rng;
    public override void NextBytes(byte[] buf) => _rng.GetBytes(buf);
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if(disposing) _rng.Dispose();
    }
}

internal sealed class BlockDrbgWrapper : AnyRng
{
    private readonly BlockDeriveBytes _rng;
    public BlockDrbgWrapper(BlockDeriveBytes rng) => _rng = rng;
    public override void NextBytes(byte[] buf) => _rng.GetBytes(buf);
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if(disposing) _rng.Dispose();
    }
}

internal sealed class DrbgWrapper : AnyRng
{
    private readonly DeriveBytes _rng;
    public DrbgWrapper(DeriveBytes rng) => _rng = rng;
    public override void NextBytes(byte[] buf) => Array.Copy(_rng.GetBytes(buf.Length), buf, buf.Length);
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if(disposing) _rng.Dispose();
    }
}
