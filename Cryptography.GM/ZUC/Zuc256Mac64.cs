using Cryptography.GM;

namespace System.Security.Cryptography
{
    public sealed class Zuc256Mac64 : Zuc256Mac<ulong>
    {
        public Zuc256Mac64(byte[] rgbKey) : base(ZucVersion.Zuc256M64)
        {
            Key = rgbKey;
        }

        public override int HashSize => 64;
        protected override ulong WordAtBit((ulong hi, ulong lo) v, int n) => (ulong) (MakePair(v) >> (64 - n));
        protected override (ulong hi, ulong lo) ShiftInU32((ulong hi, ulong lo) l, uint r) => ToPair((MakePair(l) << 32) | r);
        protected override ulong Xor(ulong l, ulong r) => l ^ r;
        protected override ulong Mask(ulong l, int mask) => l & (ulong) mask;
        protected override byte[] ToBigEndian(ulong l)
        {
            var r = new byte[8];
            for (var i = 0; i < 8; i++) {
                r[i] = (byte) (l >> (56 - i * 8));
            }

            return r;
        }

        private static (ulong, ulong) ToPair(Bits128 v) => v;
        private static Bits128 MakePair((ulong hi, ulong lo) v) => v;
    }
}