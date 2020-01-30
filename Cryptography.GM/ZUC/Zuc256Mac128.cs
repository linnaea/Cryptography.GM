using Cryptography.GM;

namespace System.Security.Cryptography
{
    public sealed class Zuc256Mac128 : Zuc256Mac<Bits128>
    {
        public Zuc256Mac128(byte[] rgbKey) : base(ZucVersion.Zuc256M128)
        {
            Key = rgbKey;
        }

        public override int HashSize => 128;
        protected override Bits128 WordAtBit((Bits128 hi, Bits128 lo) v, int n) => (Bits128) (FromPair(v) >> (128 - n));
        protected override (Bits128 hi, Bits128 lo) ShiftInU32((Bits128 hi, Bits128 lo) l, uint r) => ToPair((FromPair(l) << 32) | r);
        protected override Bits128 Xor(Bits128 l, Bits128 r) => l ^ r;
        protected override Bits128 Mask(Bits128 l, int mask) => l & (Bits128)mask;
        protected override byte[] ToBigEndian(Bits128 l)
        {
            var r = new byte[16];
            for (var i = 0; i < 16; i++) {
                r[i] = (byte) (l >> (120 - i * 8));
            }

            return r;
        }

        private static (Bits128, Bits128) ToPair(Bits256 v) => v;
        private static Bits256 FromPair((Bits128 hi, Bits128 lo) v) => v;
    }
}