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

    public override int HashSize => 32;

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

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        while (cbSize > 0) {
            var loopBytes = Math.Min(cbSize, int.MaxValue / 8);
            HashBits(new ReadOnlySpan<byte>(array).Slice(ibStart), loopBytes * 8);
            cbSize -= loopBytes;
            ibStart += loopBytes;
        }
    }

    protected override byte[] HashFinal()
    {
        var a = FinalizeHash();
        var h = new byte[4];
        for (var i = 0; i < 4; i++) {
            h[i] = (byte)(a >> (24 - i * 8));
        }

        return h;
    }

    public override void Initialize()
    {
        _cipher = new ZucKeyStreamGenerator(_sk, _iv, _version);
        _p = 64;
        _a = 0;
    }
}
