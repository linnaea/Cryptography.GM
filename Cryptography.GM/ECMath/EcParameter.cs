using System;
using System.Numerics;
using System.Security.Cryptography;
using Cryptography.GM.Primitives;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.ECMath;

public interface IEcParameter
{
    EcPoint G { get; }
    BigInteger N { get; }
    BigInteger H { get; }
    ushort BitLength { get; }
    IEcCurve Curve { get; }
    ECCurve ToEcCurve();
}

public interface IEcCurve
{
    BigInteger A { get; }
    BigInteger B { get; }
    ushort BitLength { get; }
    BigInteger SolveY(BigInteger x, bool lsbSet, AnyRng rng);
    JacobianEcPoint Multiply(BigInteger k, JacobianEcPoint p, AnyRng rng);
    JacobianEcPoint MultiplyAndAdd(BigInteger k, JacobianEcPoint p, BigInteger m, JacobianEcPoint s, AnyRng rng);
    EcPoint ToAffine(JacobianEcPoint jp);
    bool ValidatePoint(EcPoint p);
}

public struct EcKeyPair
{
    public EcPoint Q { get; set; }
    public BigInteger D { get; set; }
    public IEcParameter Param { get; set; }

    public static implicit operator ECParameters(EcKeyPair p) =>
        new() {
            Curve = p.Param.ToEcCurve(),
            D = p.D.ToByteArrayUBe(),
            Q = p.Q
        };
}

public enum EcPointFormat
{
    Mixed,
    Compressed,
    Uncompressed
}

public struct EcPoint
{
    public static readonly EcPoint Infinity = default;

    private readonly bool _notInf;

    public BigInteger X { get; }
    public BigInteger Y { get; }

    public bool Inf => !_notInf;

    public EcPoint(BigInteger x, BigInteger y)
    {
        X = x;
        Y = y;
        _notInf = true;
    }

    public byte[] ToBytes(AsymmetricAlgorithm a, EcPointFormat format = EcPointFormat.Mixed)
        => ToBytes(format, (a.KeySize + 7) / 8);

    public byte[] ToBytes(EcPointFormat format = EcPointFormat.Mixed, int l = -1)
    {
        if (Inf) throw new InvalidOperationException();
        var xb = X.ToByteArrayUBe(l);
        if (format == EcPointFormat.Compressed) {
            var r = new byte[xb.Length + 1];
            xb.CopyTo(r, 1);
            r[0] = Y.IsEven ? (byte)2 : (byte)3;
            return r;
        } else {
            var yb = Y.ToByteArrayUBe(l);
            if (l == -1) {
                return ToBytes(format, Math.Max(xb.Length, yb.Length));
            }

            var r = new byte[l * 2 + 1];
            r[0] = format == EcPointFormat.Uncompressed ? (byte)4 : Y.IsEven ? (byte)6 : (byte)7;
            xb.CopyTo(r, 1);
            yb.CopyTo(r, l + 1);
            return r;
        }
    }

    public static implicit operator EcPoint(ECPoint p)
    {
        if (p.X == null || p.Y == null)
            return Infinity;

        return new EcPoint(p.X.AsBigUIntBe(), p.Y.AsBigUIntBe());
    }

    public static implicit operator ECPoint(EcPoint p)
    {
        if (p.Inf) {
            return new ECPoint { X = null, Y = null };
        }

        return new ECPoint {
            X = p.X.ToByteArrayUBe(),
            Y = p.Y.ToByteArrayUBe()
        };
    }

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
    public override string ToString() => Inf ? "EcPoint{O}" : $"EcPoint{{X={X:X}, Y={Y:X}}}";
}
