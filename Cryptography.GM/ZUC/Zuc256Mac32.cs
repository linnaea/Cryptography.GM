using Cryptography.GM;

namespace System.Security.Cryptography;

public sealed class Zuc256Mac32 : Zuc256Mac<uint>
{
    public Zuc256Mac32(byte[] rgbKey) : base(ZucVersion.Zuc256M32)
    {
        HashSizeValue = 32;
        Key = rgbKey;
    }

    protected override (uint hi, uint lo) ShiftInWord((uint hi, uint lo) l) => (NextU32Key(), l.hi);
    protected override uint Xor(uint l, uint r, bool skip) => l ^ (skip ? 0 : r); // lowers to conditional mov

    protected override uint WordAtBit((uint hi, uint lo) v, int n) => // this pattern lowers to a single right shift
        n switch {
            0 => v.lo,
            32 => v.hi,
            > 0 and < 32 => (uint)((v.hi | (ulong)v.lo << 32) >> (32 - n)),
            _ => throw new InvalidOperationException(),
        };

    protected override int ToBigEndian(uint l, Span<byte> r)
    {
        if (r.Length < 4)
            throw new InvalidOperationException();

        BitOps.WriteU32Be(r, l);
        return 4;
    }
}
