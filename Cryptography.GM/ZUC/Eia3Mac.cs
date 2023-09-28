using System.Runtime.InteropServices;
using Cryptography.GM;

namespace System.Security.Cryptography;

public sealed class Eia3Mac : KeyedHashAlgorithm
{
    private readonly ZucVersion _version;
    private readonly byte[] _sk = new byte[16];
    private readonly byte[] _iv = new byte[16];
    private ZucKeyStreamGenerator _cipher;
    private ulong _w;
    private byte _p = 64;
    private uint _a;

    public override byte[] Key {
        get {
            var r = new byte[32];
            Array.Copy(_sk, 0, r, 0, 16);
            Array.Copy(_iv, 0, r, 16, 16);
            return r;
        }
        set {
            if (value.Length != 32) throw new ArgumentException();
            Array.Copy(value, 0, _sk, 0, 16);
            Array.Copy(value, 16, _iv, 0, 16);
            Initialize();
        }
    }

    public Eia3Mac(byte[] rgbKey, ZucVersion version = ZucVersion.Zuc15)
    {
        HashSizeValue = 32;
        _version = version;
        _cipher = null!;
        Key = rgbKey;
    }

    private uint NextWord()
    {
        if (_p >= 32) {
            _w <<= 32;
            _w |= _cipher.NextKey();
            _p -= 32;
        }

        var w = (uint)(_w >> (32 - _p));
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
            var k = NextWord() & (uint)(bit >> 31);
            _a ^= k;
            bPos += 1;
        }
    }

    public uint FinalizeHash()
    {
        _a ^= NextWord();

        _p += 30;
        _p /= 32;
        _p += 1;
        _p *= 32;
        var r = _a ^ NextWord();

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

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
    protected override bool TryHashFinal(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = FinalizeHash(destination);
        return true;
    }
#endif

    private int FinalizeHash(Span<byte> destination)
    {
        if (destination.Length < 4)
            throw new InvalidOperationException();

        BitOps.WriteU32Be(destination, FinalizeHash());
        return 4;
    }

    protected override byte[] HashFinal()
    {
        var h = new byte[4];
        FinalizeHash(h);
        return h;
    }

    public override void Initialize()
    {
        _cipher?.Dispose();
        _cipher = new ZucKeyStreamGenerator(_sk, _iv, _version);
        _p = 64;
        _a = 0;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Array.Clear(_sk, 0, _sk.Length);
        Array.Clear(_iv, 0, _iv.Length);
        _w = 0;
        _p = 0;
        _a = 0;
        if (disposing) _cipher.Dispose();
    }
}
