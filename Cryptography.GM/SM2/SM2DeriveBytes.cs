using Cryptography.GM.Primitives;
// ReSharper disable InconsistentNaming

namespace System.Security.Cryptography;

public sealed class SM2DeriveBytes : BlockDeriveBytes
{
    private readonly bool _disposeHash;
    private readonly HashAlgorithm _hasher;
    private readonly byte[] _key;

    public SM2DeriveBytes(ReadOnlySpan<byte> key, HashAlgorithm? hash = null, bool disposeHash = false)
    {
        _key = new byte[key.Length + 4];
        _disposeHash = disposeHash || hash == null;
        _hasher = hash ?? SM3.Create();
        key.CopyTo(_key);
    }

    public override void NextBlock(Span<byte> buf)
    {
        for (var i = 1; i <= 4; i++)
            if (++_key[_key.Length - i] != 0)
                break;

        _hasher.ComputeHash(_key).CopyTo(buf);
    }

    public override int BlockSize => _hasher.HashSize / 8;

    public override void Reset()
    {
        base.Reset();
        Array.Clear(_key, _key.Length - 4, 4);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Array.Clear(_key, 0, _key.Length);
        if (disposing && _disposeHash)
            _hasher.Dispose();
    }
}
