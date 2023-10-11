using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

// ReSharper disable once InconsistentNaming
public class GenericHMAC<T> : HMAC where T : HashAlgorithm
{
    private readonly int _blockBytes;
    private readonly byte[] _rgbInner;
    private readonly byte[] _rgbOuter;
    private bool _hashing;

    protected readonly T Hasher;

    public GenericHMAC(T hasher, int blockBytes, byte[] rgbKey)
    {
        HashSizeValue = hasher.HashSize;
        Hasher = hasher;
        _blockBytes = blockBytes;
        _rgbInner = new byte[blockBytes];
        _rgbOuter = new byte[blockBytes + (HashSizeValue + 7) / 8];
        Key = rgbKey;
    }

    public sealed override byte[] Key {
        get => (byte[])KeyValue.Clone();
        set {
            if (_hashing)
                throw new InvalidOperationException("Cannot change key while hashing");

            if (value.Length > _blockBytes) {
                KeyValue = Hasher.ComputeHash(value);
            } else {
                KeyValue = (byte[])value.Clone();
            }

            for (var i = 0; i < _blockBytes; i++) {
                _rgbInner[i] = 0x36;
                _rgbOuter[i] = 0x5C;
            }

            for (var i = 0; i < KeyValue.Length; i++) {
                _rgbInner[i] ^= KeyValue[i];
                _rgbOuter[i] ^= KeyValue[i];
            }
        }
    }

    public sealed override void Initialize()
    {
        _hashing = false;
    }

    protected virtual void AddHashData(byte[] rgb, int ib, int cb) => Hasher.TransformBlock(rgb, ib, cb, null, 0);

    protected virtual int FinalizeInnerHash(Span<byte> hashValueBuf)
    {
        Hasher.TransformFinalBlock(EmptyArray<byte>.Instance, 0, 0);
        var hash = Hasher.Hash!;
        if (hash.Length != hashValueBuf.Length)
            throw new InvalidOperationException();

        hash.CopyTo(hashValueBuf);
        return hash.Length;
    }

    private void EnsureStarted()
    {
        if (_hashing) return;
        Hasher.Initialize();
        AddHashData(_rgbInner, 0, _blockBytes);
        _hashing = true;
    }

    protected sealed override void HashCore(byte[] rgb, int ib, int cb)
    {
        EnsureStarted();
        AddHashData(rgb, ib, cb);
    }

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
    protected sealed override bool TryHashFinal(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = FinalizeHash(destination);
        return true;
    }
#endif

    // ReSharper disable once UnusedMethodReturnValue.Local
    private int FinalizeHash(Span<byte> destination)
    {
        EnsureStarted();
        FinalizeInnerHash(_rgbOuter.AsSpan(_blockBytes));
        Hasher.Initialize();
        AddHashData(_rgbOuter, 0, _rgbOuter.Length);
        _hashing = false;
        return FinalizeInnerHash(destination);
    }

    protected sealed override byte[] HashFinal()
    {
        var r = new byte[_rgbOuter.Length - _blockBytes];
        FinalizeHash(r);
        return r;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Array.Clear(_rgbInner, 0, _rgbInner.Length);
        Array.Clear(_rgbOuter, 0, _rgbOuter.Length);
        if (disposing) Hasher.Dispose();
    }
}
