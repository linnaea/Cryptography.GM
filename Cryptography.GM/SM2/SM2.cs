using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Numerics;
using Cryptography.GM;
using Cryptography.GM.ECMath;
using Cryptography.GM.Primitives;

namespace System.Security.Cryptography;

// ReSharper disable once InconsistentNaming
public sealed class SM2 : AsymmetricAlgorithm
{
    private readonly AnyRng _rng;
    private readonly HashAlgorithm _hash;
    private readonly bool _disposeRng;
    private readonly bool _disposeHash;
    private int _pubKeyBytes;
    private int _keyBytes;
    private IEcParameter _param;
    private BigInteger _pkBound;
    private BigInteger _privateKey;
    private EcPoint _pubKey;
    private byte[] _ident;
    private byte[]? _z;

    public new static SM2 Create() => new();
    public static SM2 Create(AnyRng rng, bool disposeRng = false) => new(rng: rng, disposeRng: disposeRng);
    public SM2(IEcParameter? param = null, HashAlgorithm? hash = null, AnyRng? rng = null, bool disposeRng = false, bool disposeHash = false)
    {
        _disposeRng = disposeRng || rng == null;
        _disposeHash = disposeHash || hash == null;
        rng ??= RandomNumberGenerator.Create();
        hash ??= SM3.Create();

        if (!hash.CanReuseTransform || !hash.CanTransformMultipleBlocks || hash.InputBlockSize != 1)
            throw new ArgumentException(nameof(hash));

        _rng = rng;
        _hash = hash;
        _ident = EmptyArray<byte>.Instance;
        _param = null!;
        ChangeParameter(param ?? StandardParam);
    }

    [AllowNull]
    public byte[] Ident {
        get => (byte[])_ident.Clone();
        set {
            value ??= EmptyArray<byte>.Instance;
            _ident = value.Length > ushort.MaxValue / 8
                         ? throw new CryptographicException()
                         : (byte[])value.Clone();
            _z = null;
        }
    }

    public bool HasPublicKey => !_pubKey.Inf;
    public bool HasPrivateKey => !_privateKey.IsZero;

#region GM/T 0003.1-2012 Generals
    public EcKeyPair GenerateKeyPair()
    {
        var pk = _rng.NextBigInt(_pkBound, _param.N - _pkBound);
        ImportPrivateKey(pk);
        return ExportKey();
    }

    public void ImportPrivateKey(BigInteger d)
    {
        if (d.Sign <= 0 || d >= _param.N - 1)
            throw new CryptographicException();

        _privateKey = d;
        _pubKey = _param.Curve.ToAffine(_param.Curve.Multiply(d, _param.G, _rng));
        _z = null;
    }

    public void ImportPublicKey(EcPoint jp)
    {
        if (!_param.Curve.ValidatePoint(jp))
            throw new CryptographicException();

        if (_pubKey != jp)
            _privateKey = 0;

        _pubKey = jp;
        _z = null;
    }

    public void ImportKey(EcKeyPair kp)
    {
        if (kp.Param != null) {
            ChangeParameter(kp.Param);
        }

        if (!kp.D.IsZero) {
            ImportPrivateKey(kp.D);
            return;
        }

        if (!kp.Q.Inf) {
            ImportPublicKey(kp.Q);
            return;
        }

        throw new InvalidOperationException();
    }

    public EcKeyPair ExportKey() =>
        new() {
            D = _privateKey,
            Q = _pubKey,
            Param = _param
        };

    private void ChangeParameter(IEcParameter param)
    {
        _z = null;
        _param = param;
        _pubKey = default;
        _privateKey = default;
        _pkBound = BigInteger.Pow(2, (int)param.N.GetBitLength() * 11 / 16);
        KeySizeValue = param.BitLength;
        _keyBytes = (param.BitLength + 7) / 8;
        _pubKeyBytes = (param.Curve.BitLength + 7) / 8;
        LegalKeySizesValue = new[] {
            new KeySizes(KeySize, KeySize, 0)
        };
    }

    public (EcPoint Point, int Bytes) PointFromBytes(ReadOnlySpan<byte> p)
    {
        var dataLen = _pubKeyBytes + 1;
        if (p.Length < dataLen) throw new InvalidDataException("Too short");

        var x = p.Slice(1, _pubKeyBytes).AsBigUIntBe();
        switch (p[0]) {
        case 2:
        case 3:
            try {
                return (new EcPoint(x, _param.Curve.SolveY(x, p[0] == 3)), dataLen);
            }
            catch (ArithmeticException e) {
                throw new InvalidDataException("Not a valid point", e);
            }
        case 4:
        case 6:
        case 7: {
            dataLen += _pubKeyBytes;
            if (p.Length < dataLen) throw new InvalidDataException("Too short");

            var y = p.Slice(1 + _pubKeyBytes, _pubKeyBytes).AsBigUIntBe();
            var point = new EcPoint(x, y);

            if (p[0] != 4) {
                try {
                    if (y != _param.Curve.SolveY(x, p[0] == 7))
                        throw new InvalidDataException("Not a valid point");
                }
                catch (ArithmeticException e) {
                    throw new InvalidDataException("Not a valid point", e);
                }
            } else {
                if (!_param.Curve.ValidatePoint(point))
                    throw new InvalidDataException("Not a valid point on curve");
            }

            return (point, dataLen);
        }
        default:
            throw new InvalidDataException("Invalid format");
        }
    }

    internal static byte[] ZValue(IEcParameter param, HashAlgorithm hash, ReadOnlySpan<byte> identity, EcPoint pubKey)
    {
        if (pubKey.Inf)
            throw new InvalidOperationException();

        if (identity.Length > ushort.MaxValue / 8)
            throw new CryptographicException();

        var pkBytes = (param.Curve.BitLength + 7) / 8;

        var z = ArrayPool<byte>.Shared.Rent(Math.Max(2 + identity.Length, pkBytes));
        BitOps.WriteU16Be(z, (ushort)(identity.Length * 8));
        identity.CopyTo(z.AsSpan(2));

        var pkBuffer = z.AsSpan(0, pkBytes);
        hash.TransformBlock(z, 0, identity.Length + 2, null, 0);
        param.Curve.A.FillBytesUBe(pkBuffer); hash.TransformBlock(z, 0, pkBytes, null, 0);
        param.Curve.B.FillBytesUBe(pkBuffer); hash.TransformBlock(z, 0, pkBytes, null, 0);
        param.G.FillBytesX(pkBuffer); hash.TransformBlock(z, 0, pkBytes, null, 0);
        param.G.FillBytesY(pkBuffer); hash.TransformBlock(z, 0, pkBytes, null, 0);
        pubKey.FillBytesX(pkBuffer); hash.TransformBlock(z, 0, pkBytes, null, 0);
        pubKey.FillBytesY(pkBuffer); hash.TransformFinalBlock(z, 0, pkBytes);
        var zHash = hash.Hash!;
        hash.Initialize();

        ArrayPool<byte>.Shared.Return(z);
        return zHash;
    }
#endregion

#region GM/T 0003.2-2012 Digital Signature
    public (BigInteger r, BigInteger s) SignHash(BigInteger e)
    {
        if (!HasPrivateKey) throw new InvalidOperationException();

        BigInteger r, s;

        do {
            var k = _rng.NextBigInt(_pkBound, _param.N - _pkBound);
            var xy1 = _param.Curve.Multiply(k, _param.G, _rng);
            r = (e + _param.Curve.ToAffine(xy1).X) % _param.N;
            s = (1 + _privateKey).InvMod(_param.N) * (k - r * _privateKey);
            s -= (s / _param.N - (s.Sign < 0 ? 1 : 0)) * _param.N;
        } while (s.IsZero);

        return (r, s);
    }

    public bool VerifyHash(BigInteger r, BigInteger s, BigInteger e)
    {
        if (!HasPublicKey) throw new InvalidOperationException();
        if (r.IsZero || s.IsZero) return false;
        if (r >= _param.N || s >= _param.N) return false;

        var t = (r + s) % _param.N;
        if (t.IsZero) return false;

        var xy1 = _param.Curve.MultiplyAndAdd(s, _param.G, t, _pubKey, _rng);
        return (e + _param.Curve.ToAffine(xy1).X) % _param.N == r;
    }

    public byte[] SignData(ReadOnlySpan<byte> message)
    {
        _z ??= ZValue(_param, _hash, _ident, _pubKey);
        var hashBytes = _z.Length;
        var m = ArrayPool<byte>.Shared.Rent(hashBytes + message.Length);
        _z.CopyTo(m, 0);
        message.CopyTo(m.AsSpan(hashBytes));
        var h = _hash.ComputeHash(m, 0, hashBytes + message.Length).AsBigUIntBe();
        var (r, s) = SignHash(h);
        ArrayPool<byte>.Shared.Return(m);

        var buf = new byte[_keyBytes * 2];
        r.FillBytesUBe(buf.AsSpan(0, _keyBytes));
        s.FillBytesUBe(buf.AsSpan(_keyBytes));
        return buf;
    }

    public bool VerifyData(ReadOnlySpan<byte> sig, ReadOnlySpan<byte> message)
    {
        if (sig.Length != _keyBytes * 2) return false;
        var r = sig.Slice(0, _keyBytes).AsBigUIntBe();
        var s = sig.Slice(_keyBytes, _keyBytes).AsBigUIntBe();
        _z ??= ZValue(_param, _hash, _ident, _pubKey);
        var hashBytes = _z.Length;

        var m = ArrayPool<byte>.Shared.Rent(hashBytes + message.Length);
        _z.CopyTo(m, 0);
        message.CopyTo(m.AsSpan(hashBytes));
        var h = _hash.ComputeHash(m, 0, hashBytes + message.Length).AsBigUIntBe();
        ArrayPool<byte>.Shared.Return(m);

        return VerifyHash(r, s, h);
    }
#endregion

#region GM/T 0003.3-2012 Key Exchange
    public SM2KeyExchange ContinueKeyExchange(BigInteger eKey, bool responder)
    {
        if (!HasPrivateKey) throw new InvalidOperationException();

        _z ??= ZValue(_param, _hash, _ident, _pubKey);
        return new SM2KeyExchange(_rng, _hash, _z, _privateKey, responder, new EcKeyPair {
            D = eKey, Param = _param,
            Q = _param.Curve.ToAffine(_param.Curve.Multiply(eKey, _param.G, _rng))
        });
    }

    public SM2KeyExchange StartKeyExchange(bool responder)
        => ContinueKeyExchange(_rng.NextBigInt(_pkBound, _param.N - _pkBound), responder);
#endregion

#region GM/T 0003.4-2012 Encryption
    private XorStreamCipherTransform<SM2DeriveBytes> CreateCipher(EcPoint xy)
    {
        Span<byte> key = stackalloc byte[_pubKeyBytes * 2];
        xy.FillBytesX(key.Slice(0, _pubKeyBytes));
        xy.FillBytesY(key.Slice(_pubKeyBytes));
        var kdf = new SM2DeriveBytes(key, _hash);
        var cipher = new XorStreamCipherTransform<SM2DeriveBytes>(kdf);

        return cipher;
    }

    private byte[] ComputeC3Sig(EcPoint xy, ReadOnlySpan<byte> message)
    {
        var c3Data = ArrayPool<byte>.Shared.Rent(Math.Max(_pubKeyBytes, message.Length));
        xy.FillBytesX(c3Data.AsSpan(0, _pubKeyBytes)); _hash.TransformBlock(c3Data, 0, _pubKeyBytes, null, 0);
        message.CopyTo(c3Data); _hash.TransformBlock(c3Data, 0, message.Length, null, 0);
        xy.FillBytesY(c3Data.AsSpan(0, _pubKeyBytes)); _hash.TransformFinalBlock(c3Data, 0, _pubKeyBytes);
        Array.Clear(c3Data, 0, message.Length);
        ArrayPool<byte>.Shared.Return(c3Data);

        var c3 = _hash.Hash!;
        _hash.Initialize();
        return c3;
    }

    public (EcPoint c1MsgKey, byte[] c3Sig, byte[] c2Cipher) EncryptMessage(ReadOnlySpan<byte> message)
    {
        if (!HasPublicKey) throw new InvalidOperationException();
        if (_param.Curve.Multiply(_param.H, _pubKey, _rng).Inf) throw new CryptographicException();

        var k = _rng.NextBigInt(_pkBound, _param.N - _pkBound);
        var c1 = _param.Curve.ToAffine(_param.Curve.Multiply(k, _param.G, _rng));
        var xy = _param.Curve.ToAffine(_param.Curve.Multiply(k, _pubKey, _rng));

        using var cipher = CreateCipher(xy);
        var c2 = new byte[message.Length];
        cipher.TransformBits(message, c2, c2.Length * 8);

        return (c1, ComputeC3Sig(xy, message), c2);
    }

    public byte[] DecryptMessage(EcPoint c1MsgKey, ReadOnlySpan<byte> c3Sig, ReadOnlySpan<byte> c2Cipher)
    {
        if (!HasPrivateKey) throw new InvalidOperationException();
        if (!_param.Curve.ValidatePoint(c1MsgKey)) throw new CryptographicException();
        if (_param.Curve.Multiply(_param.H, c1MsgKey, _rng).Inf) throw new CryptographicException();

        var xy = _param.Curve.ToAffine(_param.Curve.Multiply(_privateKey, c1MsgKey, _rng));

        using var cipher = CreateCipher(xy);
        var message = new byte[c2Cipher.Length];
        cipher.TransformBits(c2Cipher, message, c2Cipher.Length * 8);

        if (!c3Sig.SequenceEquals(ComputeC3Sig(xy, message))) throw new CryptographicException();

        return message;
    }

    public byte[] EncryptData(ReadOnlySpan<byte> data, EcPointFormat pointFormat = EcPointFormat.Mixed)
    {
        var (c1MsgKey, c3Sig, c2Cipher) = EncryptMessage(data);
        var c1Bytes = pointFormat.SerializedLength(_pubKeyBytes);
        Array.Resize(ref c2Cipher, c2Cipher.Length + c3Sig.Length + c1Bytes);
        Array.Copy(c2Cipher, 0, c2Cipher, c3Sig.Length + c1Bytes, data.Length);
        c1MsgKey.WriteBytes(c2Cipher.AsSpan(0, c1Bytes), pointFormat);
        Array.Copy(c3Sig, 0, c2Cipher, c1Bytes, c3Sig.Length);
        return c2Cipher;
    }

    public byte[] DecryptData(ReadOnlySpan<byte> data)
    {
        var (c1MsgKey, c1Length) = PointFromBytes(data);
        data = data.Slice(c1Length);

        var c3Sig = data.Slice(0, (_hash.HashSize + 7) / 8);
        var c2Cipher = data.Slice(c3Sig.Length);

        return DecryptMessage(c1MsgKey, c3Sig, c2Cipher);
    }
#endregion

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _privateKey = default;
        if (_disposeRng && disposing) _rng.Dispose();
        if (_disposeHash && disposing) _hash.Dispose();
    }

#if NETFRAMEWORK && !NET46_OR_GREATER
    [ExcludeFromCodeCoverage] public override string SignatureAlgorithm => throw new NotImplementedException();
    [ExcludeFromCodeCoverage] public override string KeyExchangeAlgorithm => throw new NotImplementedException();
    [ExcludeFromCodeCoverage] public override void FromXmlString(string xmlString) => throw new NotImplementedException();
    [ExcludeFromCodeCoverage] public override string ToXmlString(bool includePrivateParameters) => throw new NotImplementedException();
#endif

    [SuppressMessage("ReSharper", "StringLiteralTypo"), SuppressMessage("ReSharper", "InconsistentNaming")]
    public static readonly ShortWeierstrassFpParameter StandardParam = new(
        new ShortWeierstrassFpCurve(
            BigInteger.Parse("0FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
                             NumberStyles.HexNumber),
            BigInteger.Parse("0FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
                             NumberStyles.HexNumber),
            BigInteger.Parse("028E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
                             NumberStyles.HexNumber)
        ),
        new EcPoint(
            BigInteger.Parse("032C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                             NumberStyles.HexNumber),
            BigInteger.Parse("0BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
                             NumberStyles.HexNumber)
        ),
        BigInteger.Parse("0FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
                         NumberStyles.HexNumber)
    );
}
