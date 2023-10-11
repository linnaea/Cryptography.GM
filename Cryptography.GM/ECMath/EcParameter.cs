using System;
using System.Numerics;
using Cryptography.GM.Primitives;
// ReSharper disable once RedundantUsingDirective
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.ECMath;

public interface IEcParameter
{
    EcPoint G { get; }
    BigInteger N { get; }
    BigInteger H { get; }
    ushort BitLength { get; }
    IEcCurve Curve { get; }
#if NETSTANDARD || NETCOREAPP || NET47_OR_GREATER
    ECCurve ToEcCurve();
#endif
}

public interface IEcCurve
{
    BigInteger A { get; }
    BigInteger B { get; }
    ushort BitLength { get; }
    BigInteger SolveY(BigInteger x, bool lsbSet);
    JacobianEcPoint Multiply(BigInteger k, JacobianEcPoint p, AnyRng rng);
    JacobianEcPoint MultiplyAndAdd(BigInteger k, JacobianEcPoint p, BigInteger m, JacobianEcPoint s, AnyRng rng);
    EcPoint ToAffine(JacobianEcPoint jp);
    bool ValidatePoint(EcPoint p);
}

public struct EcKeyPair
{
    public EcPoint Q { get; init; }
    public BigInteger D { get; init; }
    public IEcParameter? Param { get; init; }

#if NETSTANDARD || NETCOREAPP || NET47_OR_GREATER
    public static implicit operator ECParameters(EcKeyPair p) =>
        new() {
            Curve = p.Param?.ToEcCurve() ?? new ECCurve { CurveType = ECCurve.ECCurveType.Implicit },
            D = p.D.ToByteArrayUBe(),
            Q = p.Q
        };

    public static explicit operator EcKeyPair(ECParameters p) =>
        new() {
            Param = ParameterFromEcCurve(p.Curve),
            D = p.D?.AsBigUIntBe() ?? BigInteger.Zero,
            Q = p.Q
        };

    public static IEcParameter ParameterFromEcCurve(ECCurve curve)
    {
        switch (curve.CurveType) {
        case ECCurve.ECCurveType.Implicit:
            return null!;
        case ECCurve.ECCurveType.PrimeShortWeierstrass:
            curve.Validate();
            return new ShortWeierstrassFpParameter(
                new ShortWeierstrassFpCurve(
                    curve.Prime?.AsBigUIntBe() ?? throw new InvalidCastException(),
                    curve.A?.AsBigUIntBe() ?? throw new InvalidCastException(),
                    curve.B?.AsBigUIntBe() ?? throw new InvalidCastException()),
                curve.G, curve.Order?.AsBigUIntBe() ?? throw new InvalidCastException());
        case ECCurve.ECCurveType.Characteristic2:
        case ECCurve.ECCurveType.Named:
        case ECCurve.ECCurveType.PrimeMontgomery:
        case ECCurve.ECCurveType.PrimeTwistedEdwards:
        default:
            throw new NotSupportedException();
        }
    }
#endif
}

public enum EcPointFormat
{
    Mixed,
    Compressed,
    Uncompressed
}

public readonly struct EcPoint : IEquatable<EcPoint>
{
    public static readonly EcPoint Infinity = default;

#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
    private readonly int _xb;
    private readonly int _yb;
#else
    private readonly byte[] _xb;
    private readonly byte[] _yb;
#endif

    public BigInteger X { get; }
    public BigInteger Y { get; }

    public bool Inf => _xb == default || _yb == default;

    public EcPoint(BigInteger x, BigInteger y)
    {
        X = x;
        Y = y;
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
        _xb = X.GetByteCount(true);
        _yb = Y.GetByteCount(true);
#else
        _xb = X.ToByteArrayUBe();
        _yb = Y.ToByteArrayUBe();
#endif
    }

    public void WriteBytes(Span<byte> buf, EcPointFormat format = EcPointFormat.Mixed)
    {
        if (Inf) throw new InvalidOperationException();

        if (format == EcPointFormat.Compressed) {
            buf[0] = Y.IsEven ? (byte)2 : (byte)3;
            CopyBytesToEnd(X, _xb, buf.Slice(1));
        } else if((buf.Length & 1) != 1) {
            throw new ArgumentException();
        } else {
            var elementLength = buf.Length / 2;
            buf[0] = format == EcPointFormat.Uncompressed ? (byte)4 : Y.IsEven ? (byte)6 : (byte)7;
            CopyBytesToEnd(X, _xb, buf.Slice(1, elementLength));
            CopyBytesToEnd(Y, _yb, buf.Slice(1 + elementLength));
        }
    }

    public void FillBytesX(Span<byte> buf) => CopyBytesToEnd(X, _xb, buf);
    public void FillBytesY(Span<byte> buf) => CopyBytesToEnd(Y, _yb, buf);
#if NETSTANDARD2_1_OR_GREATER || NETCOREAPP
    private static void CopyBytesToEnd(BigInteger n, int byteLength, Span<byte> tgt)
        => n.FillBytesUBe(tgt, byteLength);
#else
    // ReSharper disable once UnusedParameter.Local
    private static void CopyBytesToEnd(BigInteger n, byte[] src, Span<byte> tgt)
    {
        var p = tgt.Length - src.Length;
        tgt.Slice(0, p).Clear();
        src.CopyTo(tgt.Slice(p));
    }
#endif

    public byte[] ToBytes(int bitLength, EcPointFormat format = EcPointFormat.Mixed)
    {
        var r = new byte[format.SerializedLength((bitLength + 7) / 8)];
        WriteBytes(r, format);
        return r;
    }

#if NETSTANDARD || NETCOREAPP || NET47_OR_GREATER
    public static implicit operator EcPoint(ECPoint p)
    {
        if (p.X == null || p.Y == null)
            return Infinity;

        return new EcPoint(p.X.AsBigUIntBe(), p.Y.AsBigUIntBe());
    }

    public static implicit operator ECPoint(EcPoint p)
    {
        if (p.Inf)
            return new ECPoint { X = null, Y = null };

        return new ECPoint {
            X = p.X.ToByteArrayUBe(),
            Y = p.Y.ToByteArrayUBe()
        };
    }
#endif

    public bool Equals(EcPoint other)
    {
        if (Inf && other.Inf)
            return true;

        if (Inf || other.Inf)
            return false;

        return X.Equals(other.X) && Y.Equals(other.Y);
    }

    public static bool operator ==(EcPoint l, EcPoint r) => l.Equals(r);
    public static bool operator !=(EcPoint l, EcPoint r) => !(l == r);
    public override bool Equals(object? obj) => obj is EcPoint other && Equals(other);
    public override int GetHashCode() => Inf ? 0 : (X.GetHashCode() * 397) ^ Y.GetHashCode();
    public override string ToString() => Inf ? "EcPoint(O)" : $"EcPoint(X={X:X}, Y={Y:X})";
}
