using Cryptography.GM.Primitives;
using static Cryptography.GM.BitOps;
// ReSharper disable InconsistentNaming

namespace System.Security.Cryptography;

public class SM2DeriveBytes : BlockDeriveBytes
{
    private readonly HashAlgorithm _hasher;
    private readonly byte[] _key;
    private uint _counter;

    public SM2DeriveBytes(ReadOnlySpan<byte> key, HashAlgorithm? hash = null)
    {
        _key = new byte[key.Length + 4];
        _hasher = hash ?? new SM3();
        key.CopyTo(_key);
    }

    public override void NextBlock(Span<byte> buf)
    {
        WriteU32Be(_key.AsSpan(_key.Length - 4), ++_counter);
        _hasher.ComputeHash(_key).CopyTo(buf);
    }

    public override int BlockSize => _hasher.HashSize / 8;

    public override void Reset()
    {
        base.Reset();
        _counter = 0;
    }

    protected override void Dispose(bool disposing)
    {
        Array.Clear(_key, 0, _key.Length);
        if (disposing) _hasher.Dispose();
    }
}
