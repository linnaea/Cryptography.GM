using System;
using System.Security.Cryptography;

// ReSharper disable once CheckNamespace
namespace Cryptography.GM.Primitives;

public abstract class EcbTransform : ICryptoTransform
{
    public bool CanReuseTransform => true;
    public bool CanTransformMultipleBlocks => true;
    public abstract int InputBlockSize { get; }
    public abstract int OutputBlockSize { get; }
    protected abstract void TransformOneBlock(ReadOnlySpan<byte> input, Span<byte> output);

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (inputCount % InputBlockSize != 0)
            throw new ArgumentOutOfRangeException(nameof(inputCount));

        var blocks = inputCount / InputBlockSize;
        while (blocks > 0) {
            TransformOneBlock(inputBuffer.AsSpan(inputOffset, InputBlockSize),
                              outputBuffer.AsSpan(outputOffset, OutputBlockSize));
            blocks -= 1;
            inputOffset += InputBlockSize;
            outputOffset += OutputBlockSize;
        }

        return inputCount / InputBlockSize * OutputBlockSize;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        var blocks = inputCount / InputBlockSize;
        var output = new byte[blocks * OutputBlockSize];
        TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
        return output;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    ~EcbTransform() => Dispose(false);
    protected virtual void Dispose(bool disposing)
    { }
}
