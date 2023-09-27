using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

public class XorStreamCipherTransform<TRng> : ICryptoTransform where TRng : DeriveBytes
{
    protected readonly TRng Rng;
    private byte[] _w = Array.Empty<byte>();
    private int _iPos;
    private sbyte _bPos;

    public XorStreamCipherTransform(TRng rng)
    {
        Rng = rng;
    }

    private byte NextByte()
    {
        if (_w == null)
            throw new InvalidOperationException();

        Span<byte> next = stackalloc byte[Rng is BlockDeriveBytes bdb ? bdb.BlockSize : 64];
        while (_iPos >= _w.Length - 2) {
            if (Rng is BlockDeriveBytes bdb1) {
                bdb1.NextBlock(next);
            } else {
                Rng.GetBytes(next.Length).CopyTo(next);
            }

            var newBuf = new byte[_w.Length - _iPos + next.Length];
            Array.Copy(_w, _iPos, newBuf, 0, _w.Length - _iPos);
            next.CopyTo(newBuf.AsSpan(_w.Length - _iPos));
            _iPos = 0;
            _w = newBuf;
        }

        if (_bPos == 0) {
            return _w[_iPos++];
        }

        var r = _w[_iPos];
        r <<= _bPos;
        r |= (byte)(_w[++_iPos] >> (8 - _bPos));
        return r;
    }

    public void TransformBits(ReadOnlySpan<byte> input, Span<byte> output, int nBits)
    {
        int outputOffset = 0, inputOffset = 0;

        while (nBits >= 8) {
            output[outputOffset] = (byte)(input[inputOffset] ^ NextByte());
            outputOffset += 1;
            inputOffset += 1;
            nBits -= 8;
        }

        if (nBits <= 0) return;

        var mask = (byte)(0xFF00 >> nBits);
        mask &= NextByte();
        output[outputOffset] = (byte)(input[inputOffset] ^ mask);
        _bPos -= (sbyte)(8 - nBits);

        if (_bPos >= 0) return;
        _bPos += 8;
        _iPos -= 1;
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        var r = inputCount;
        while (inputCount > 0) {
            var loopBytes = Math.Min(inputCount, int.MaxValue / 8);
            TransformBits(new ReadOnlySpan<byte>(inputBuffer).Slice(inputOffset),
                          new Span<byte>(outputBuffer).Slice(outputOffset),
                          loopBytes * 8);

            inputCount -= loopBytes;
            outputOffset += loopBytes;
            inputOffset += loopBytes;
        }

        return r;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        var buf = new byte[inputCount];
        TransformBlock(inputBuffer, inputOffset, inputCount, buf, 0);
        if (CanReuseTransform) {
            ResetRng();
            _w = Array.Empty<byte>();
            _iPos = _bPos = 0;
        } else {
            _w = null!;
        }

        return buf;
    }

    protected virtual void ResetRng() => Rng.Reset();

    public virtual bool CanReuseTransform => true;
    public bool CanTransformMultipleBlocks => true;
    public int InputBlockSize => 1;
    public int OutputBlockSize => 1;

    public void Dispose()
    {
        _w = null!;
        Rng.Dispose();
    }
}
