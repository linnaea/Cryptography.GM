using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM;

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
    protected abstract (T hi, T lo) ShiftInWord((T hi, T lo) v);
    protected abstract T Xor(T l, T r, bool skip);
    protected abstract int ToBigEndian(T l, Span<byte> buf);

    protected Zuc256Mac(ZucVersion version)
    {
        _version = version;
        _cipher = null!;
    }

    protected uint NextU32Key() => _cipher.NextKey();

    private T NextWord()
    {
        while (_p > HashSize) {
            _w = ShiftInWord(_w);
            _p -= (ushort)HashSize;
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
            _a = Xor(_a, NextWord(), bit == 0);
            bPos += 1;
        }
    }

    public T FinalizeHash()
    {
        var r = Xor(_a, NextWord(), false);
        _p--;
        return r;
    }

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
    protected override bool TryHashFinal(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = FinalizeHash(destination);
        return true;
    }
#endif

    private int FinalizeHash(Span<byte> destination) => ToBigEndian(FinalizeHash(), destination);

    protected override byte[] HashFinal()
    {
        var r = new byte[(HashSize + 7) / 8];
        FinalizeHash(r);
        return r;
    }

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
    protected override void HashCore(ReadOnlySpan<byte> source)
#else
    private void HashCore(ReadOnlySpan<byte> source)
#endif
    {
        while (!source.IsEmpty) {
            var loopBytes = Math.Min(source.Length, int.MaxValue / 8);
            HashBits(source, loopBytes * 8);
            source = source.Slice(loopBytes);
        }
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize) => HashCore(array.AsSpan(ibStart, cbSize));

    public override void Initialize()
    {
        _cipher?.Dispose();
        _cipher = new ZucKeyStreamGenerator(_sk, _iv, _version);
        _p = (ushort)(HashSize * 2);
        _a = NextWord();
        _p += (ushort)HashSize;
        _p--;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Array.Clear(_sk, 0, _sk.Length);
        Array.Clear(_iv, 0, _iv.Length);
        _w = default;
        _p = 0;
        _a = default;
        if (disposing) _cipher.Dispose();
    }
}
