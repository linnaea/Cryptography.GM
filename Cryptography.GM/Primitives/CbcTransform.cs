using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

public sealed class CbcTransform : ICryptoTransform
{
    private readonly ICryptoTransform _ecbNoPad;
    private readonly bool _decrypt;
    private readonly byte[] _iv;
    private readonly byte[] _lastCipherBlock;

    public CbcTransform(ICryptoTransform ecbNoPad, byte[] iv, bool decrypt)
    {
        _ecbNoPad = ecbNoPad;
        _decrypt = decrypt;
        _lastCipherBlock = new byte[InputBlockSize];

        if (InputBlockSize != OutputBlockSize)
            throw new CryptographicException();

        if (iv.Length != InputBlockSize)
            throw new CryptographicException("IV length mismatch");

        Array.Copy(iv, _lastCipherBlock, InputBlockSize);
        _iv = (byte[])_lastCipherBlock.Clone();
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (inputCount % InputBlockSize != 0)
            throw new ArgumentOutOfRangeException(nameof(inputCount));

        var blocks = inputCount / InputBlockSize;
        while (blocks > 0) {
            TransformOneBlock(inputBuffer, inputOffset, outputBuffer, outputOffset, false);
            blocks -= 1;
            inputOffset += InputBlockSize;
            outputOffset += OutputBlockSize;
        }

        return inputCount;
    }

    private void TransformOneBlock(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset,
                                   bool signalFinalBlock)
    {
        var imm = new byte[InputBlockSize];
        Array.Copy(inputBuffer, inputOffset, imm, 0, InputBlockSize);
        if (!_decrypt) {
            for (var i = 0; i < InputBlockSize; i++) {
                imm[i] ^= _lastCipherBlock[i];
            }
        }

        if (signalFinalBlock) {
            var lastBlock = _ecbNoPad.TransformFinalBlock(imm, 0, InputBlockSize);
            Array.Copy(lastBlock, 0, outputBuffer, outputOffset, InputBlockSize);
        } else {
            _ecbNoPad.TransformBlock(imm, 0, InputBlockSize, outputBuffer, outputOffset);
        }

        if (_decrypt) {
            for (var i = 0; i < InputBlockSize; i++) {
                outputBuffer[outputOffset + i] ^= _lastCipherBlock[i];
            }

            Array.Copy(imm, 0, _lastCipherBlock, 0, InputBlockSize);
        } else {
            Array.Copy(outputBuffer, outputOffset, _lastCipherBlock, 0, InputBlockSize);
        }
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        var blocks = inputCount / InputBlockSize;
        var output = new byte[blocks * OutputBlockSize];
        if (blocks > 1) {
            TransformBlock(inputBuffer, inputOffset, inputCount - InputBlockSize, output, 0);
        }

        if (blocks >= 1) {
            TransformOneBlock(inputBuffer, inputOffset + inputCount - InputBlockSize, output, output.Length - InputBlockSize, true);
        } else {
            output = _ecbNoPad.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }

        Array.Copy(_iv, _lastCipherBlock, InputBlockSize);
        return output;
    }

    public bool CanTransformMultipleBlocks => true;
    public bool CanReuseTransform => _ecbNoPad.CanReuseTransform;
    public int InputBlockSize => _ecbNoPad.InputBlockSize;
    public int OutputBlockSize => _ecbNoPad.OutputBlockSize;
    public void Dispose() => _ecbNoPad.Dispose();
}
