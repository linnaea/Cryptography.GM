using System;
using System.Buffers;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

public sealed class CbcTransform : ICryptoTransform
{
    private readonly ICryptoTransform _ecbNoPad;
    private readonly bool _decrypt;
    // ReSharper disable MemberInitializerValueIgnored
    private readonly byte[] _iv = EmptyArray<byte>.Instance;
    private readonly byte[] _lastCipherBlock = EmptyArray<byte>.Instance;
    // ReSharper restore MemberInitializerValueIgnored

    public CbcTransform(ICryptoTransform ecbNoPad, byte[] iv, bool decrypt)
    {
        _ecbNoPad = ecbNoPad;
        _decrypt = decrypt;

        if (_ecbNoPad.InputBlockSize != _ecbNoPad.OutputBlockSize)
            throw new CryptographicException();

        if (iv.Length != BlockSize)
            throw new CryptographicException("IV length mismatch");

        _iv = (byte[])iv.Clone();
        _lastCipherBlock = (byte[])iv.Clone();
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (inputCount % BlockSize != 0)
            throw new ArgumentOutOfRangeException(nameof(inputCount));

        var blocks = inputCount / BlockSize;
        while (blocks > 0) {
            TransformOneBlock(inputBuffer, inputOffset, outputBuffer, outputOffset, false);
            blocks -= 1;
            inputOffset += BlockSize;
            outputOffset += BlockSize;
        }

        return inputCount;
    }

    private void TransformOneBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset, bool isFinalBlock)
    {
        var imm = ArrayPool<byte>.Shared.Rent(BlockSize);
        Array.Copy(inputBuffer, inputOffset, imm, 0, BlockSize);
        if (!_decrypt)
            for (var i = 0; i < BlockSize; i++)
                imm[i] ^= _lastCipherBlock[i];

        if (isFinalBlock) {
            var lastBlock = _ecbNoPad.TransformFinalBlock(imm, 0, BlockSize);
            Array.Copy(lastBlock, 0, outputBuffer, outputOffset, BlockSize);
        } else {
            _ecbNoPad.TransformBlock(imm, 0, BlockSize, outputBuffer, outputOffset);
        }

        if (_decrypt) {
            for (var i = 0; i < BlockSize; i++)
                outputBuffer[outputOffset + i] ^= _lastCipherBlock[i];

            Array.Copy(imm, 0, _lastCipherBlock, 0, BlockSize);
        } else {
            Array.Copy(outputBuffer, outputOffset, _lastCipherBlock, 0, BlockSize);
        }

        ArrayPool<byte>.Shared.Return(imm);
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        var blocks = inputCount / BlockSize;
        var output = new byte[blocks * BlockSize];
        if (blocks > 1)
            TransformBlock(inputBuffer, inputOffset, inputCount - BlockSize, output, 0);

        if (blocks >= 1) {
            TransformOneBlock(inputBuffer, inputOffset + inputCount - BlockSize, output, output.Length - BlockSize, true);
        } else {
            output = _ecbNoPad.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }

        Array.Copy(_iv, _lastCipherBlock, BlockSize);
        return output;
    }

    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => _ecbNoPad.CanReuseTransform;
    public int InputBlockSize => BlockSize;
    public int OutputBlockSize => BlockSize;
    private int BlockSize => _ecbNoPad.InputBlockSize;

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    ~CbcTransform() => Dispose(false);
    private void Dispose(bool disposing)
    {
        Array.Clear(_iv, 0, _iv.Length);
        Array.Clear(_lastCipherBlock, 0, _lastCipherBlock.Length);
        if (disposing) _ecbNoPad.Dispose();
    }
}
