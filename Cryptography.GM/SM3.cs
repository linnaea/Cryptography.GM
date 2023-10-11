using System.Diagnostics.CodeAnalysis;
using Cryptography.GM.Primitives;
using Cryptography.GM;
using static Cryptography.GM.BitOps;
// ReSharper disable InconsistentNaming

namespace System.Security.Cryptography;

public sealed class SM3 : HashAlgorithm
{
    public const ushort BlockSize = 512;

    private readonly byte[] _msgBuf = new byte[BlockSize / 8];
    private ushort _msgBufCount;

    private Bits256 _state;
    private ulong _blockCount;

    public new static SM3 Create() => new();
    public SM3()
    {
        HashSizeValue = 256;
        Initialize();
    }

    private static uint P0(uint v) => v ^ RotL32(v, 9) ^ RotL32(v, 17);
    private static uint P1(uint v) => v ^ RotL32(v, 15) ^ RotL32(v, 23);
    private static uint T(int j) => j < 16 ? 0x79cc4519u : 0x7a879d8au;
    private static uint FF(int j, uint x, uint y, uint z) => j < 16 ? x ^ y ^ z : (x & y) | (x & z) | (y & z);
    private static uint GG(int j, uint x, uint y, uint z) => j < 16 ? x ^ y ^ z : (x & y) | (~x & z);

    private void CompressOneBlock(ReadOnlySpan<byte> block)
    {
        _blockCount += 1;
        Span<uint> w = stackalloc uint[68];
        for (var i = 0; i < 16; i++) {
            w[i] = ReadU32Be(block.Slice(i * 4, 4));
        }

        for (var j = 16; j < 68; j++) {
            w[j] = P1(w[j - 16] ^ w[j - 9] ^ RotL32(w[j - 3], 15)) ^ RotL32(w[j - 13], 7) ^ w[j - 6];
        }

        Span<uint> wp = stackalloc uint[64];
        for (var j = 0; j < 64; j++) {
            wp[j] = w[j] ^ w[j + 4];
        }

        var (a, b, c, d, e, f, g, h) = _state;
        for (var j = 0; j < 64; j++) {
            var ss1 = RotL32(RotL32(a, 12) + e + RotL32(T(j), (byte)(j % 32)), 7);
            var ss2 = ss1 ^ RotL32(a, 12);
            var tt1 = FF(j, a, b, c) + d + ss2 + wp[j];
            var tt2 = GG(j, e, f, g) + h + ss1 + w[j];
            d = c;
            c = RotL32(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = RotL32(f, 19);
            f = e;
            e = P0(tt2);
        }

        _state = new Bits256(a, b, c, d, e, f, g, h) ^ _state;
    }

    private ReadOnlySpan<byte> CopyToBuffer(ReadOnlySpan<byte> buf, ref ulong nBits)
    {
        var toCopy = (ushort)Math.Min((ushort)(BlockSize - _msgBufCount), nBits);
        var r = BitCopy(buf, _msgBuf, _msgBufCount, toCopy);
        _msgBufCount += toCopy;
        nBits -= toCopy;
        return r;
    }

    public void HashCoreBits(ReadOnlySpan<byte> buf, ulong nBits)
    {
        while (nBits > 0) {
            if (_msgBufCount == 0 && nBits >= BlockSize) {
                CompressOneBlock(buf.Slice(0, _msgBuf.Length));
                buf = buf.Slice(_msgBuf.Length);
                nBits -= BlockSize;
            } else {
                buf = CopyToBuffer(buf, ref nBits);
                if (_msgBufCount != BlockSize) continue;
                CompressOneBlock(_msgBuf);
                _msgBufCount = 0;
            }
        }
    }

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
    protected override void HashCore(ReadOnlySpan<byte> buf)
#else
    private void HashCore(ReadOnlySpan<byte> buf)
#endif
        => HashCoreBits(buf, (uint)buf.Length * 8);

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
    protected override bool TryHashFinal(Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = FinalizeHash(destination);
        return true;
    }
#endif

    public int FinalizeHash(Span<byte> destination)
    {
        if (destination.Length < 32)
            throw new InvalidOperationException();

        var messageBits = _blockCount * BlockSize + _msgBufCount;
        HashCoreBits(new byte[] { 0x80 }, 8 - (messageBits & 7));
        byte[] finalBlock;
        uint finalBlockOffset;
        if (_msgBufCount > BlockSize - 64) {
            finalBlock = new byte[BlockSize / 8 + 8];
            finalBlockOffset = _msgBufCount - (BlockSize - 64u);
        } else {
            finalBlock = new byte[BlockSize / 8];
            finalBlockOffset = _msgBufCount;
        }

        WriteU64Be(finalBlock.AsSpan(finalBlock.Length - 8), messageBits);
        HashCoreBits(finalBlock.SliceBits(finalBlockOffset), (uint)finalBlock.Length * 8 - finalBlockOffset);

        var (ul0, ul1, ul2, ul3) = _state;
        WriteU64Be(destination.Slice(0, 8), ul0);
        WriteU64Be(destination.Slice(8, 8), ul1);
        WriteU64Be(destination.Slice(16, 8), ul2);
        WriteU64Be(destination.Slice(24, 8), ul3);
        return 32;
    }

    protected override byte[] HashFinal()
    {
        var r = new byte[32];
        FinalizeHash(r);
        return r;
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
        => HashCore(array.AsSpan(ibStart, cbSize));

    public override void Initialize()
    {
        _state = new Bits256(0x7380166fu, 0x4914b2b9u, 0x172442d7u, 0xda8a0600u, 0xa96f30bcu, 0x163138aau, 0xe38dee4du, 0xb0fb0e4e);
        _blockCount = 0;
        _msgBufCount = 0;
    }
}

[SuppressMessage("ReSharper", "IdentifierTypo")]
public sealed class HMACSM3 : GenericHMAC<SM3>
{
    public HMACSM3(byte[] rgbKey) : base(SM3.Create(), SM3.BlockSize / 8, rgbKey)
    { }

    protected override int FinalizeInnerHash(Span<byte> hashValueBuf)
        => Hasher.FinalizeHash(hashValueBuf);

    protected override void AddHashData(byte[] rgb, int ib, int cb)
        => Hasher.HashCoreBits(rgb.AsSpan(ib, cb), (uint)cb * 8);
}
