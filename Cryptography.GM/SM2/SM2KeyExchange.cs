using System.Numerics;
using Cryptography.GM.ECMath;
using Cryptography.GM.Primitives;

namespace System.Security.Cryptography;

// ReSharper disable once InconsistentNaming
public sealed class SM2KeyExchange : IDisposable
{
    private readonly AnyRng _rng;
    private readonly HashAlgorithm _hash;
    private readonly bool _responder;
    private readonly BigInteger _privateKey;
    private readonly EcKeyPair _ephemeralKey;
    private readonly byte[] _zValue;

    public EcPoint R => _ephemeralKey.Q;
    public BigInteger EphemeralKey => _ephemeralKey.D;

    internal SM2KeyExchange(AnyRng rng, HashAlgorithm hash, byte[] zValue, BigInteger privateKey, bool responder,
                            EcKeyPair ephemeralKey)
    {
        _rng = rng;
        _ephemeralKey = ephemeralKey;
        _hash = hash;
        _privateKey = privateKey;
        _zValue = zValue;
        _responder = responder;
    }

    public (SM2DeriveBytes? Key, byte[] Verifier, byte[] PeerVerifier) DeriveKey(
        EcPoint peerPubKey, EcPoint peerR, ReadOnlySpan<byte> peerIdent)
    {
        if (!_ephemeralKey.Param.Curve.ValidatePoint(peerPubKey))
            throw new CryptographicException();

        if (!_ephemeralKey.Param.Curve.ValidatePoint(peerR))
            throw new CryptographicException();

        var pkBytes = (_ephemeralKey.Param.Curve.BitLength + 7) / 8;

        var zPeer = SM2.ZValue(_ephemeralKey.Param, _hash, peerIdent, peerPubKey);
        var w = _ephemeralKey.Param.BitLength;
        w = (ushort)((w >> 1) + (w & 1) - 1);
        var w2 = (BigInteger)1 << w;
        var x2 = w2 + (_ephemeralKey.Q.X & (w2 - 1));
        var t = (_privateKey + x2 * _ephemeralKey.D) % _ephemeralKey.Param.N;
        var x1 = w2 + (peerR.X & (w2 - 1));

        var vi = _ephemeralKey.Param.Curve.MultiplyAndAdd(1, peerPubKey, x1, peerR, _rng);
        var v = _ephemeralKey.Param.Curve.ToAffine(_ephemeralKey.Param.Curve.Multiply(_ephemeralKey.Param.H * t, vi, _rng));
        if (v.Inf)
            return (null, null!, null!);

        var za = _responder ? zPeer : _zValue;
        var zb = _responder ? _zValue : zPeer;
        var zl = za.Length + zb.Length;
        var key = new byte[pkBytes * 2 + zl];
        var xv = key.AsSpan(0, pkBytes);
        var yv = key.AsSpan(pkBytes, pkBytes);
        v.FillBytesX(xv);
        v.FillBytesY(yv);
        za.CopyTo(key, pkBytes * 2);
        zb.CopyTo(key, pkBytes * 2 + za.Length);

        var kdf = new SM2DeriveBytes(key, _hash);
        var ra = _responder ? peerR : _ephemeralKey.Q;
        var rb = _responder ? _ephemeralKey.Q : peerR;

        _hash.TransformBlock(key, 0, pkBytes, null, 0);
        _hash.TransformBlock(za, 0, za.Length, null, 0);
        _hash.TransformBlock(zb, 0, zb.Length, null, 0);
        ra.FillBytesX(xv); _hash.TransformBlock(key, 0, pkBytes, null, 0);
        ra.FillBytesY(xv); _hash.TransformBlock(key, 0, pkBytes, null, 0);
        rb.FillBytesX(xv); _hash.TransformBlock(key, 0, pkBytes, null, 0);
        rb.FillBytesY(xv); _hash.TransformFinalBlock(key, 0, pkBytes);
        var si = _hash.Hash;

        key[pkBytes - 1] = 2;
        _hash.Initialize();
        _hash.TransformBlock(key, pkBytes - 1, pkBytes + 1, null, 0);
        _hash.TransformFinalBlock(si, 0, si.Length);
        var sb = _hash.Hash;

        key[pkBytes - 1] = 3;
        _hash.Initialize();
        _hash.TransformBlock(key, pkBytes - 1, pkBytes + 1, null, 0);
        _hash.TransformFinalBlock(si, 0, si.Length);
        var sa = _hash.Hash;

        _hash.Initialize();
        return (kdf, _responder ? sb : sa, _responder ? sa : sb);
    }

    public void Dispose()
    {
        ClearMaterial();
        GC.SuppressFinalize(this);
    }

    ~SM2KeyExchange() => ClearMaterial();
    private void ClearMaterial() => Array.Clear(_zValue, 0, _zValue.Length);
}
