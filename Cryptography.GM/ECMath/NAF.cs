using System.Numerics;
// ReSharper disable InconsistentNaming
// ReSharper disable once CheckNamespace

namespace Cryptography.GM.ECMath;

internal static class NAF
{
    public static int ToNAFBytes(this BigInteger x, ref byte[]? naf)
    {
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
        var len = x.GetByteCount(true);
#else
        var len = x.ToByteArray().Length;
#endif

        len = len * 4 + 1;
        naf ??= new byte[len];
        if (naf.Length < len)
            naf = new byte[len];

        var i = 0;
        while (!x.IsZero) {
            var k = 0;
            if (!x.IsEven) {
                k = (int)(2 - x % 4);
            }

            var nibble = (byte)(k & 0xF);
            nibble <<= (i & 1) << 2;
            if((i & 1) == 0)
                naf[i / 2] = nibble;
            else
                naf[i / 2] |= nibble;
            x = (x - k) / 2;
            i++;
        }

        return (i + 1) / 2;
    }

    public static sbyte H(this byte b) => (sbyte)((sbyte)b >> 4);
    public static sbyte L(this byte b) => (sbyte)((sbyte)(b << 4) >> 4);
    public static sbyte NafValue(this byte v) => (sbyte)(v.H() * 2 + v.L());
}
