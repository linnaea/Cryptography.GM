using Cryptography.GM;

namespace System.Security.Cryptography;

public sealed class Zuc256Mac64 : Zuc256Mac<ulong>
{
    public Zuc256Mac64(byte[] rgbKey) : base(ZucVersion.Zuc256M64)
    {
        HashSizeValue = 64;
        Key = rgbKey;
    }

    protected override ulong Xor(ulong l, ulong r, bool skip) => l ^ (skip ? 0 : r); // lowers to conditional mov

    protected override (ulong hi, ulong lo) ShiftInWord((ulong hi, ulong lo) l)
    {
        var k0 = NextU32Key();
        var k1 = NextU32Key();
        return (l.lo, (ulong)k0 << 32 | k1);
    }

    protected override ulong WordAtBit((ulong hi, ulong lo) v, int n) =>
        n switch {
            0 => v.hi,
            64 => v.lo,
            > 0 and < 64 => v.lo >> (64 - n) | v.hi << n,
            _ => throw new InvalidOperationException(),
        };

    protected override int ToBigEndian(ulong l, Span<byte> r)
    {
        if (r.Length < 8)
            throw new InvalidOperationException();

        BitOps.WriteU64Be(r, l);
        return 8;
    }
}
