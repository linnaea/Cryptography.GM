using Cryptography.GM;

namespace System.Security.Cryptography
{
    public sealed class Zuc256Mac32 : Zuc256Mac<uint>
    {
        public Zuc256Mac32(byte[] rgbKey) : base(ZucVersion.Zuc256M32)
        {
            Key = rgbKey;
        }

        public override int HashSize => 32;
        protected override uint WordAtBit((uint hi, uint lo) v, int n) => (uint) (MakePair(v) >> (32 - n));
        protected override (uint hi, uint lo) ShiftInU32((uint hi, uint lo) l, uint r) => (l.lo, r);
        protected override uint Xor(uint l, uint r) => l ^ r;
        protected override uint Mask(uint l, int mask) => l & (uint) mask;
        protected override byte[] ToBigEndian(uint l)
        {
            var r = new byte[4];
            for (var i = 0; i < 4; i++) {
                r[i] = (byte) (l >> (24 - i * 8));
            }

            return r;
        }

        private static ulong MakePair((uint hi, uint lo) v) => (ulong)v.hi << 32 | v.lo;
    }
}