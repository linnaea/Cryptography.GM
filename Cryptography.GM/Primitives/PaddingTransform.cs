using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

public sealed class PaddingTransform : ICryptoTransform
{
    private readonly byte[] _lastBlock;
    private readonly ICryptoTransform _blkCipher;
    private readonly PaddingMode _mode;
    private readonly bool _decrypt;
    private bool _hasWithheldBlock;

    public PaddingTransform(ICryptoTransform blkCipher, PaddingMode mode, bool decrypt)
    {
        _mode = mode;
        _blkCipher = blkCipher;
        _decrypt = decrypt;
        if (mode != PaddingMode.ISO10126 && mode != PaddingMode.ANSIX923 && mode != PaddingMode.PKCS7)
            throw new NotSupportedException();

        if (blkCipher.InputBlockSize is > byte.MaxValue or < 2 || blkCipher.OutputBlockSize is > byte.MaxValue or < 2)
            throw new CryptographicException("Padding can only be used with block ciphers with block size of [2,255]");

        _lastBlock = new byte[decrypt ? InputBlockSize : OutputBlockSize];
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        var nXfrm = _blkCipher.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        if (!_decrypt || nXfrm < OutputBlockSize) return nXfrm;

        if (_hasWithheldBlock) {
            Span<byte> lastBlock = stackalloc byte[OutputBlockSize];
            outputBuffer.AsSpan(outputOffset + nXfrm - OutputBlockSize, OutputBlockSize).CopyTo(lastBlock);
            Array.Copy(outputBuffer, outputOffset, outputBuffer, outputOffset + OutputBlockSize, nXfrm - OutputBlockSize);
            Array.Copy(_lastBlock, 0, outputBuffer, outputOffset, OutputBlockSize);
            lastBlock.CopyTo(_lastBlock);
        } else {
            Array.Copy(outputBuffer, outputOffset + nXfrm - OutputBlockSize, _lastBlock, 0, OutputBlockSize);
            _hasWithheldBlock = true;
            nXfrm -= OutputBlockSize;
        }

        return nXfrm;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        if (_decrypt) {
            var data = _blkCipher.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
            if (_hasWithheldBlock) {
                Array.Resize(ref data, data.Length + OutputBlockSize);
                Array.Copy(data, 0, data, OutputBlockSize, data.Length - OutputBlockSize);
                Array.Copy(_lastBlock, 0, data, 0, OutputBlockSize);
            }

            if (data.Length < 1)
                throw new CryptographicException("Invalid padding");

            var paddingLength = data.Back();
            var paddingValue = _mode == PaddingMode.ANSIX923 ? 0 : paddingLength;
            var paddingError = 0;
            if (_mode != PaddingMode.ISO10126) {
                for (var i = OutputBlockSize; i >= 1; i--) {
                    // if i > paddingLength ignore;
                    // if paddingLength != data[data.Length - i] error;
                    var posMask = ~(paddingLength - i) >> 31;
                    paddingError |= (paddingValue ^ data[data.Length - i]) & posMask;
                }
            }

            if (paddingError != 0 || paddingLength == 0 || paddingLength > OutputBlockSize)
                throw new CryptographicException("Invalid padding");

            Array.Resize(ref data, data.Length - paddingLength);
            return data;
        } else {
            var paddingLength = InputBlockSize - inputCount % InputBlockSize;
            var paddingValue = _mode switch {
                PaddingMode.ANSIX923 => 0,
                PaddingMode.ISO10126 => GetHashCode() & 0xFF ^ paddingLength,
                PaddingMode.PKCS7 => paddingLength,
                _ => throw new Exception()
            };
            var cipherBlock = new byte[inputCount + paddingLength];
            Array.Copy(inputBuffer, inputOffset, cipherBlock, 0, inputCount);
            for (var i = InputBlockSize; i >= 1; i--) {
                var posMask = ~(paddingLength - i) >> 31;
                cipherBlock[cipherBlock.Length - i] &= (byte)~posMask;
                cipherBlock[cipherBlock.Length - i] |= (byte)(paddingValue & posMask);
            }

            if (cipherBlock.Length <= InputBlockSize || CanTransformMultipleBlocks) {
                return _blkCipher.TransformFinalBlock(cipherBlock, 0, cipherBlock.Length);
            }

            var remainingBlocks = cipherBlock.Length / InputBlockSize;
            var returnData = new byte[(remainingBlocks - 1) * OutputBlockSize];
            for (var i = 0; i < remainingBlocks - 1; i++) {
                _blkCipher.TransformBlock(cipherBlock, i * InputBlockSize, InputBlockSize, returnData, i * OutputBlockSize);
            }

            var lastBlock = _blkCipher.TransformFinalBlock(cipherBlock, cipherBlock.Length - InputBlockSize, InputBlockSize);
            Array.Resize(ref returnData, returnData.Length + lastBlock.Length);
            Array.Copy(lastBlock, 0, returnData, OutputBlockSize, lastBlock.Length);
            return returnData;
        }
    }

    public bool CanReuseTransform => _blkCipher.CanReuseTransform;
    public bool CanTransformMultipleBlocks => _blkCipher.CanTransformMultipleBlocks;
    public int InputBlockSize => _blkCipher.InputBlockSize;
    public int OutputBlockSize => _blkCipher.OutputBlockSize;

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    ~PaddingTransform() => Dispose(false);
    private void Dispose(bool disposing)
    {
        Array.Clear(_lastBlock, 0, _lastBlock.Length);
        if (disposing) _blkCipher.Dispose();
    }
}
