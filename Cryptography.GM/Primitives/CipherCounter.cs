using System.Buffers;

namespace System.Security.Cryptography.Primitives
{
    public class CtrTransform : XorStreamCipherTransform<CipherCounterRng>
    {
        public CtrTransform(ICryptoTransform ecbNoPad, byte[] iv) : base(new CipherCounterRng(ecbNoPad, iv))
        { }
    }

    public class CipherCounterRng : BlockDeriveBytes
    {
        private readonly ICryptoTransform _ecbNoPad;
        private readonly byte[] _iv;
        private readonly byte[] _ctr;

        public CipherCounterRng(ICryptoTransform ecbNoPad, byte[] iv)
        {
            if(iv.Length != ecbNoPad.InputBlockSize)
                throw new CryptographicException("IV length mismatch");

            _ecbNoPad = ecbNoPad;
            _ctr = new byte[ecbNoPad.InputBlockSize];
            Array.Copy(iv, _ctr, ecbNoPad.InputBlockSize);
            _iv = (byte[]) _ctr.Clone();
        }

        public override int BlockSize => _ecbNoPad.OutputBlockSize;
        public override void NextBlock(Span<byte> buf)
        {
            var bounce = ArrayPool<byte>.Shared.Rent(_ecbNoPad.OutputBlockSize);
            _ecbNoPad.TransformBlock(_ctr, 0, _ctr.Length, bounce, 0);
            byte acc = 1;
            for (var i = _ctr.Length - 1; i >= 0; i--) {
                var sum = _ctr[i] + acc;
                _ctr[i] = (byte)sum;
                acc = (byte) ((sum >> 8) & 1);
            }

            bounce.AsSpan(0, _ecbNoPad.OutputBlockSize).CopyTo(buf);
            ArrayPool<byte>.Shared.Return(bounce);
        }

        public override void Reset()
        {
            base.Reset();
            Array.Copy(_iv, 0, _ctr, 0, _iv.Length);
        }

        protected override void Dispose(bool disposing)
        {
            Array.Clear(_iv, 0, _iv.Length);
            Array.Clear(_ctr, 0, _ctr.Length);
            if (disposing) {
                _ecbNoPad.Dispose();
            }
        }
    }
}