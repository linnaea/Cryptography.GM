using System.Buffers;

namespace System.Security.Cryptography.Primitives
{
    public abstract class BlockDeriveBytes : DeriveBytes
    {
        private byte[] _remaining = Array.Empty<byte>();

        public abstract int BlockSize { get; }
        public abstract void NextBlock(Span<byte> buf);

        public void GetBytes(byte[] buf)
        {
            var cb = buf.Length;
            if (cb < _remaining.Length) {
                Array.Copy(_remaining, 0, buf, 0, cb);
                Array.Copy(_remaining, cb, _remaining, 0, _remaining.Length - cb);
                Array.Resize(ref _remaining, _remaining.Length - cb);
                return;
            }

            Array.Copy(_remaining, buf, _remaining.Length);
            var offset = _remaining.Length;
            _remaining = Array.Empty<byte>();

            while (offset < cb) {
                var toCopy = Math.Min(cb - offset, BlockSize);
                if (toCopy == BlockSize) {
                    NextBlock(buf.AsSpan(offset));
                } else {
                    var bounce = ArrayPool<byte>.Shared.Rent(BlockSize);
                    _remaining = new byte[BlockSize - toCopy];
                    NextBlock(bounce.AsSpan(0, BlockSize));
                    Array.Copy(bounce, 0, buf, offset, toCopy);
                    Array.Copy(bounce, toCopy, _remaining, 0, _remaining.Length);
                    ArrayPool<byte>.Shared.Return(bounce);
                }
                offset += toCopy;
            }
        }

        public override byte[] GetBytes(int cb)
        {
            var ret = new byte[cb];
            GetBytes(ret);
            return ret;
        }

        public override void Reset()
        {
            _remaining = Array.Empty<byte>();
        }
    }
}
