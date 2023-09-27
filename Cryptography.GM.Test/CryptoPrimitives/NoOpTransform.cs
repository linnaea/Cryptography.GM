using System;
using System.Linq;
using System.Security.Cryptography;
using Cryptography.GM.Primitives;
using Xunit;

namespace Cryptography.GM.Test.CryptoPrimitives;

public class NoOpTransform : EcbTransform
{
    public NoOpTransform(int blockSize)
    {
        InputBlockSize = OutputBlockSize = blockSize;
    }

    public override int InputBlockSize { get; }
    public override int OutputBlockSize { get; }

    protected override void TransformOneBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        input.CopyTo(output);
    }
}

public class NoOpSingleBlockTransform : ICryptoTransform
{
    public NoOpSingleBlockTransform(int blockSize = 16)
    {
        InputBlockSize = OutputBlockSize = blockSize;
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (inputCount != InputBlockSize && inputCount != 0)
            throw new InvalidOperationException();

        Array.Copy(inputBuffer, inputOffset, outputBuffer, outputOffset, inputCount);
        return inputCount;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        var o = new byte[inputCount];
        TransformBlock(inputBuffer, inputOffset, inputCount, o, 0);
        return o;
    }

    public bool CanReuseTransform => true;
    public bool CanTransformMultipleBlocks => false;
    public int InputBlockSize { get; }
    public int OutputBlockSize { get; }

    void IDisposable.Dispose()
    { }

    [Fact]
    public void MultipleBlocksThrows()
    {
        Assert.Equal(0, TransformBlock(Array.Empty<byte>(), 0, 0, Array.Empty<byte>(), 0));
        var b = new byte[2 * InputBlockSize];
        new Random().NextBytes(b);
        Assert.Equal(InputBlockSize, TransformBlock(b, 0, InputBlockSize, b, InputBlockSize));
        Assert.Equal(b.Take(InputBlockSize), b.Skip(InputBlockSize));
        Assert.Throws<InvalidOperationException>(() => TransformFinalBlock(b, 0, b.Length));
    }
}
