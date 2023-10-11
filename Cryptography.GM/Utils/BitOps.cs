using System;
using System.Numerics;
using Cryptography.GM.ECMath;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM;

internal static class BitOps
{
    public static uint RotL32(uint a, byte b) => (a << b) | (a >> (32 - b));
    public static uint MakeU32(byte hh, byte hl, byte lh, byte ll) => (uint)(hh << 24 | hl << 16 | lh << 8 | ll);
    public static uint ReadU32Be(ReadOnlySpan<byte> b) => MakeU32(b[0], b[1], b[2], b[3]);
    public static ulong ReadU64Be(ReadOnlySpan<byte> b) => (ulong)MakeU32(b[0], b[1], b[2], b[3]) << 32 | MakeU32(b[4], b[5], b[6], b[7]);

    public static void WriteU16Be(Span<byte> b, ushort n)
    {
        b[0] = (byte)(n >> 8);
        b[1] = (byte)n;
    }

    public static void WriteU32Be(Span<byte> b, uint n)
    {
        b[0] = (byte)(n >> 24);
        b[1] = (byte)(n >> 16);
        b[2] = (byte)(n >> 8);
        b[3] = (byte)n;
    }

    public static void WriteU64Be(Span<byte> b, ulong n)
    {
        b[0] = (byte)(n >> 56);
        b[1] = (byte)(n >> 48);
        b[2] = (byte)(n >> 40);
        b[3] = (byte)(n >> 32);
        b[4] = (byte)(n >> 24);
        b[5] = (byte)(n >> 16);
        b[6] = (byte)(n >> 8);
        b[7] = (byte)n;
    }

    public static ref T Back<T>(this T[] v, int n = 0) => ref v[v.Length - 1 - n];

    public static void FillBytesUBe(this BigInteger x, Span<byte> target, int xBytes = -1)
    {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
        xBytes = xBytes < 0 ? x.GetByteCount(true) : xBytes;
        var p = target.Length - xBytes;
        target.Slice(0, p).Clear();
        if (!x.TryWriteBytes(target.Slice(p), out var lenReal, true, true))
            throw new Exception();
        if (lenReal != xBytes)
            throw new Exception();
#else
        x.ToByteArrayUBe(target.Length).CopyTo(target);
#endif
    }

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
    public static byte[] ToByteArrayUBe(this BigInteger x) => x.ToByteArray(true, true);
#else
    public static byte[] ToByteArrayUBe(this BigInteger x, int len = -1)
    {
        if (x.Sign < 0) throw new OverflowException();
        var xb = x.ToByteArray();
        if (len >= 0) {
            for (var i = len; i < xb.Length; i++) {
                if (xb[i] != 0) throw new OverflowException();
            }

            Array.Resize(ref xb, len);
        } else if (xb.Back() == 0) {
            Array.Resize(ref xb, xb.Length - 1);
        }

        Array.Reverse(xb);
        return xb;
    }
#endif

    public static BigInteger AsBigUIntBe(this byte[] x)
    {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
        return new BigInteger(x, true, true);
#else
        var b = x;
        if ((x[0] & 0x80) != 0) {
            b = new byte[x.Length + 1];
            x.CopyTo(b, 1);
        }

        Array.Reverse(b);
        var r = new BigInteger(b);
        return r;
#endif
    }

    public static BigInteger AsBigUIntBe(this ReadOnlySpan<byte> x)
    {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
        return new BigInteger(x, true, true);
#else
        var b = new byte[x.Length + 1];
        x.CopyTo(b.AsSpan(1));
        Array.Reverse(b);
        var r = new BigInteger(b);
        return r;
#endif
    }

    public static BigInteger InvMod(this BigInteger v, BigInteger n)
    {
        var t = BigInteger.Zero;
        var nextT = BigInteger.One;
        var r = n;
        var nextR = v;

        while (!nextR.IsZero) {
            var q = r / nextR;
            (t, nextT) = (nextT, t - q * nextT);
            (r, nextR) = (nextR, r - q * nextR);
        }

        if (!r.IsOne)
            throw new ArithmeticException();

        if (t < 0)
            t += n;

        return t;
    }

#if !NET5_0_OR_GREATER
    public static uint GetBitLength(this BigInteger v)
    {
#if NETSTANDARD2_1_OR_GREATER
        var bits = v.GetByteCount();
        var b = bits < 72 ? stackalloc byte[bits] : new byte[bits];
        v.TryWriteBytes(b, out bits);
        bits *= 8;
#else
        var b = v.ToByteArray();
        var bits = b.Length * 8;
#endif
        while (b[bits / 8 - 1] == 0)
            bits -= 8;

        var nz = b[bits / 8 - 1];
        byte mask = 0xFF;
        while ((nz & mask) == nz) {
            mask >>= 1;
            bits -= 1;
        }

        return (uint)bits + 1;
    }
#endif

    public static bool SequenceEquals(this ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
            return false;

        var error = 0;
        for (var i = 0; i < a.Length; i++)
            error |= a[i] ^ b[i];

        return error == 0;
    }

    public static ReadOnlySpan<byte> SliceBits(this byte[] src, uint srcBitOffset)
        => SliceBits(src.AsSpan(), srcBitOffset);

    public static ReadOnlySpan<byte> SliceBits(ReadOnlySpan<byte> src, uint srcBitOffset)
    {
        src = src.Slice((int)(srcBitOffset / 8));
        srcBitOffset %= 8;
        if (srcBitOffset == 0) {
            return src;
        }

        var realign = src.ToArray();
        var b1 = (byte)(8 - srcBitOffset);
        var b2 = (byte)srcBitOffset;
        for (var i = 0; i < realign.Length; i++) {
            realign[i] <<= b2;
            if (i + 1 != src.Length) {
                realign[i] |= (byte)(src[i + 1] >> b1);
            }
        }

        return realign;
    }

    public static ReadOnlySpan<byte> BitCopy(ReadOnlySpan<byte> src, Span<byte> dst, uint dstBitOffset, uint bitLength)
    {
        if (bitLength == 0)
            return src;

        dst = dst.Slice((int)(dstBitOffset / 8));
        var dstUnaligned = (byte)(dstBitOffset % 8);

        if (dstUnaligned != 0) {
            var toCopy = Math.Min(8u - dstUnaligned, bitLength);
            dst[0] |= (byte)(src[0] >> dstUnaligned);
            dstUnaligned += (byte)toCopy;
            if (dstUnaligned == 8) {
                dst = dst.Slice(1);
            } else {
                return EmptyArray<byte>.Instance;
            }

            bitLength -= toCopy;
            src = SliceBits(src, toCopy);
        }

        var remainingBytes = (int)((bitLength + 7) / 8);
        src.Slice(0, remainingBytes).CopyTo(dst.Slice(0, remainingBytes));
        return SliceBits(src, bitLength);
    }

    public static int SerializedLength(this EcPointFormat pointFormat, int elementLength)
        => 1 + elementLength * (pointFormat == EcPointFormat.Compressed ? 1 : 2);
}
