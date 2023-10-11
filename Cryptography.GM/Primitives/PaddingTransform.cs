using System;
using System.Buffers;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

public sealed class PaddingTransform : ICryptoTransform
{
    private readonly byte[] _lastBlock = EmptyArray<byte>.Instance;
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

        if (decrypt)
            _lastBlock = new byte[OutputBlockSize];
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (!_decrypt) return _blkCipher.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        if (inputCount == 0) return 0;
        if (inputCount < InputBlockSize) throw new ArgumentException();

        var nXfrm = 0;
        if (_hasWithheldBlock) {
            nXfrm = OutputBlockSize;
            Array.Copy(_lastBlock, 0, outputBuffer, outputOffset, OutputBlockSize);
            if (inputCount > InputBlockSize)
                nXfrm += _blkCipher.TransformBlock(inputBuffer, inputOffset, inputCount - InputBlockSize, outputBuffer, outputOffset + OutputBlockSize);
        } else {
            if (inputCount > InputBlockSize)
                nXfrm += _blkCipher.TransformBlock(inputBuffer, inputOffset, inputCount - InputBlockSize, outputBuffer, outputOffset);
        }

        var lastBlockSize = _blkCipher.TransformBlock(inputBuffer, inputOffset + inputCount - InputBlockSize, InputBlockSize, _lastBlock, 0);
        if (lastBlockSize == 0) {
            if (nXfrm == 0) {
                if (_hasWithheldBlock)
                    throw new CryptographicException();
                return 0;
            }

            nXfrm -= OutputBlockSize;
            Array.Copy(outputBuffer, outputOffset + nXfrm - OutputBlockSize, _lastBlock, 0, OutputBlockSize);
            _hasWithheldBlock = true;
            return nXfrm;
        }

        if (lastBlockSize != OutputBlockSize)
            throw new CryptographicException();

        _hasWithheldBlock = true;
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
                for (var i = OutputBlockSize; i >= 2; i--) {
                    // if (i > paddingLength) continue;
                    // if (paddingValue != data[data.Length - i]) error;
                    var posMask = ~(paddingLength - i) >> 31;
                    paddingError |= (paddingValue ^ data[data.Length - i]) & posMask;
                }
            }

            if (paddingError != 0 || paddingLength == 0 || paddingLength > OutputBlockSize)
                throw new CryptographicException("Invalid padding");

            Array.Resize(ref data, data.Length - paddingLength);
            _hasWithheldBlock = false;
            return data;
        } else {
            var paddingLength = InputBlockSize - inputCount % InputBlockSize;
            var paddingValue = _mode switch {
                PaddingMode.ANSIX923 => 0,
                PaddingMode.ISO10126 => GetHashCode() & 0xFF ^ paddingLength,
                PaddingMode.PKCS7 => paddingLength,
                _ => throw new Exception()
            };

            var paddedLength = inputCount + paddingLength;
            var cipherBlock = ArrayPool<byte>.Shared.Rent(paddedLength);
            Array.Copy(inputBuffer, inputOffset, cipherBlock, 0, inputCount);

            for (var i = InputBlockSize; i >= 2; i--) {
                // if (i > paddingLength) continue;
                // data[data.Length - i] = paddingValue;
                var posMask = ~(paddingLength - i) >> 31;
                cipherBlock[paddedLength - i] &= (byte)~posMask;
                cipherBlock[paddedLength - i] |= (byte)(paddingValue & posMask);
            }

            cipherBlock[paddedLength - 1] = (byte)paddingLength;
            byte[] returnData;
            if (paddedLength == InputBlockSize || CanTransformMultipleBlocks) {
                returnData = _blkCipher.TransformFinalBlock(cipherBlock, 0, paddedLength);
            } else {
                var remainingBlocks = paddedLength / InputBlockSize;
                returnData = new byte[remainingBlocks * OutputBlockSize];
                remainingBlocks -= 1;

                for (var i = 0; i < remainingBlocks; i++)
                    _blkCipher.TransformBlock(cipherBlock, i * InputBlockSize, InputBlockSize,
                                              returnData, i * OutputBlockSize);

                var lastBlock = _blkCipher.TransformFinalBlock(cipherBlock, paddedLength - InputBlockSize, InputBlockSize);
                Array.Resize(ref returnData, remainingBlocks * OutputBlockSize + lastBlock.Length);
                Array.Copy(lastBlock, 0,
                           returnData, remainingBlocks * OutputBlockSize,
                           lastBlock.Length);
            }

            Array.Clear(cipherBlock, 0, paddedLength);
            ArrayPool<byte>.Shared.Return(cipherBlock);
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
