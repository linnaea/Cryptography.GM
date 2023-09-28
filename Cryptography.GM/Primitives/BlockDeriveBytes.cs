using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

public abstract class BlockDeriveBytes : DeriveBytes
{
    private byte[] _buf = EmptyArray<byte>.Instance;
    private int _bufPos;

    public abstract int BlockSize { get; }
    public abstract void NextBlock(Span<byte> buf);

    public void GetBytes(Span<byte> buf)
    {
        if (_buf.Length == 0)
            _buf = new byte[_bufPos = BlockSize];

        while (!buf.IsEmpty) {
            var cb = buf.Length;
            if (cb + _bufPos <= _buf.Length) {
                _buf.AsSpan(_bufPos, cb).CopyTo(buf);
                _bufPos += cb;
                return;
            }

            _buf.AsSpan(_bufPos).CopyTo(buf);
            buf = buf.Slice(_buf.Length - _bufPos);

            while (buf.Length >= BlockSize) {
                NextBlock(buf.Slice(0, BlockSize));
                buf = buf.Slice(BlockSize);
            }

            NextBlock(_buf);
            _bufPos = 0;
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
        _bufPos = _buf.Length;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Array.Clear(_buf, 0, _buf.Length);
        _buf = null!;
    }
}
