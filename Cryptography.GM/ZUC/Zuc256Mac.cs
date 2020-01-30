using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM
{
    public abstract class Zuc256Mac<T> : KeyedHashAlgorithm where T : struct
    {
        private readonly ZucVersion _version;
        private readonly byte[] _sk = new byte[32];
        private readonly byte[] _iv = new byte[23];
        private ZucKeyStreamGenerator _cipher;

        private T _a;
        private (T hi, T lo) _w;
        private ushort _p;

        public override byte[] Key {
            get {
                var r = new byte[55];
                Array.Copy(_sk, 0, r, 0, 32);
                Array.Copy(_iv, 0, r, 32, 23);
                return r;
            }
            set {
                if (value.Length != 55) throw new ArgumentException();
                Array.Copy(value, 0, _sk, 0, 32);
                Array.Copy(value, 32, _iv, 0, 23);
                Initialize();
            }
        }

        protected abstract T WordAtBit((T hi, T lo) v, int n);
        protected abstract (T hi, T lo) ShiftInU32((T hi, T lo) v, uint r);
        protected abstract T Xor(T l, T r);
        protected abstract T Mask(T l, int mask);
        protected abstract byte[] ToBigEndian(T l);

        protected Zuc256Mac(ZucVersion version)
        {
            _version = version;
            _cipher = null!;
        }

        private T NextWord()
        {
            while (_p >= HashSize) {
                _w = ShiftInU32(_w, _cipher.NextKey());
                _p -= 32;
            }

            var w = WordAtBit(_w, _p);
            _p += 1;
            return w;
        }

        public void HashBits(ReadOnlySpan<byte> buf, int nBits)
        {
            var bPos = 0;
            while (bPos < nBits) {
                var b = bPos % 8;
                var bit = buf[bPos / 8] & (1 << (7 - b));
                bit <<= b + 24;
                var k = Mask(NextWord(), bit >> 31);
                _a = Xor(_a, k);
                bPos += 1;
            }
        }

        public T FinalizeHash()
        {
            var r = Xor(_a, NextWord());
            _p--;
            return r;
        }

        public byte[] FinalizeHashBytes()
        {
            var a = FinalizeHash();
            return ToBigEndian(a);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            while (cbSize > 0) {
                var loopBytes = Math.Min(cbSize, int.MaxValue / 8);
                HashBits(new ReadOnlySpan<byte>(array).Slice(ibStart), loopBytes * 8);
                cbSize -= loopBytes;
                ibStart += loopBytes;
            }
        }

        protected override byte[] HashFinal() => FinalizeHashBytes();

        public override void Initialize()
        {
            _cipher = new ZucKeyStreamGenerator(_sk, _iv, _version);
            _p = (ushort) (HashSize * 2);
            _a = NextWord();
            _p += (ushort) HashSize;
            _p--;
        }
    }
}
