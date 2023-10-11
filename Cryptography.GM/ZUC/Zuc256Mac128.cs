using Cryptography.GM;

namespace System.Security.Cryptography;

public sealed class Zuc256Mac128 : Zuc256Mac<Bits128>
{
    public Zuc256Mac128(byte[] rgbKey) : base(ZucVersion.Zuc256M128)
    {
        HashSizeValue = 128;
        Key = rgbKey;
    }

    protected override Bits128 Xor(Bits128 l, Bits128 r, bool skip) => l ^ ((Bits128)(skip ? 0 : -1) & r);

    protected override Bits128 WordAtBit((Bits128 hi, Bits128 lo) v, int n) =>
        n switch {
            0 => v.hi,
            128 => v.lo,
            > 0 and < 128 => v.lo >> (128 - n) | v.hi << n,
            _ => throw new InvalidOperationException(),
        };

    protected override (Bits128 hi, Bits128 lo) ShiftInWord((Bits128 hi, Bits128 lo) l)
    {
        var k0 = NextU32Key();
        var k1 = NextU32Key();
        var k2 = NextU32Key();
        var k3 = NextU32Key();
        return (l.lo, new Bits128(k0, k1, k2, k3));
    }

    protected override int ToBigEndian(Bits128 l, Span<byte> r)
    {
        if (r.Length < 16)
            throw new InvalidOperationException();

        var (hi, lo) = l;
        BitOps.WriteU64Be(r, hi);
        BitOps.WriteU64Be(r.Slice(8), lo);
        return 16;
    }
}
