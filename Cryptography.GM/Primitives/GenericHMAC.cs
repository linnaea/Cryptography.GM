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
    private byte[] _keyValue = Array.Empty<byte>();
    private bool _hashing;

    protected readonly T Hasher;

    public sealed override int HashSize => Hasher.HashSize;

    public GenericHMAC(T hasher, int blockBytes, byte[] rgbKey)
    {
        Hasher = hasher;
        _blockBytes = blockBytes;
        _rgbInner = new byte[blockBytes];
        _rgbOuter = new byte[blockBytes];
        Key = rgbKey;
    }

    public sealed override byte[] Key {
        get => (byte[])_keyValue.Clone();
        set {
            if (_hashing) {
                throw new InvalidOperationException("Cannot change key during hash operation");
            }

            if (value.Length > _blockBytes) {
                _keyValue = Hasher.ComputeHash(value);
            } else {
                _keyValue = (byte[])value.Clone();
            }

            for (var i = 0; i < _blockBytes; i++) {
                _rgbInner[i] = 0x36;
                _rgbOuter[i] = 0x5C;
            }

            for (var i = 0; i < _keyValue.Length; i++) {
                _rgbInner[i] ^= _keyValue[i];
                _rgbOuter[i] ^= _keyValue[i];
            }
        }
    }

    public sealed override void Initialize()
    {
        _hashing = false;
    }

    protected virtual void AddHashData(byte[] rgb, int ib, int cb) => Hasher.TransformBlock(rgb, ib, cb, null, 0);

    protected virtual byte[] FinalizeInnerHash()
    {
        Hasher.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        return Hasher.Hash;
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

    protected sealed override byte[] HashFinal()
    {
        EnsureStarted();
        var hashInner = FinalizeInnerHash();
        Hasher.Initialize();
        AddHashData(_rgbOuter, 0, _blockBytes);
        AddHashData(hashInner, 0, hashInner.Length);
        _hashing = false;
        return FinalizeInnerHash();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) Hasher.Dispose();
        base.Dispose(disposing);
    }
}
