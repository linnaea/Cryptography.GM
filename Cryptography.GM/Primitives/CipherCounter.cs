using System;
using System.Buffers;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

public sealed class CtrTransform : XorStreamCipherTransform<CipherCounterRng>
{
    public CtrTransform(ICryptoTransform ecbNoPad, byte[] iv) : base(new CipherCounterRng(ecbNoPad, iv))
    { }
}

public sealed class CipherCounterRng : BlockDeriveBytes
{
    private readonly ICryptoTransform _ecbNoPad;
    // ReSharper disable MemberInitializerValueIgnored
    private readonly byte[] _iv = EmptyArray<byte>.Instance;
    private readonly byte[] _ctr = EmptyArray<byte>.Instance;
    // ReSharper restore MemberInitializerValueIgnored

    public CipherCounterRng(ICryptoTransform ecbNoPad, byte[] iv)
    {
        if (iv.Length != ecbNoPad.InputBlockSize)
            throw new CryptographicException("IV length mismatch");

        _ecbNoPad = ecbNoPad;
        _ctr = (byte[])iv.Clone();
        _iv = (byte[])iv.Clone();
    }

    public override int BlockSize => _ecbNoPad.OutputBlockSize;

    public override void NextBlock(Span<byte> buf)
    {
        var bounce = ArrayPool<byte>.Shared.Rent(_ecbNoPad.OutputBlockSize);
        _ecbNoPad.TransformBlock(_ctr, 0, _ctr.Length, bounce, 0);
        for (var i = _ctr.Length - 1; i >= 0; i--)
            if (++_ctr[i] != 0)
                break;

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
        base.Dispose(disposing);
        Array.Clear(_iv, 0, _iv.Length);
        Array.Clear(_ctr, 0, _ctr.Length);
        if (disposing) _ecbNoPad.Dispose();
    }
}
