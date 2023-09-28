using Cryptography.GM.Primitives;
using Xunit;

namespace Cryptography.GM.Test.CryptoPrimitives;

public class ZerosPaddingTest
{
    [Theory]
    [InlineData(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }, 16, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0 })]
    [InlineData(new byte[] { 2, 2, 3, 4, 5, 6, 7, 8 }, 8, new byte[] { 2, 2, 3, 4, 5, 6, 7, 8 })]
    [InlineData(new byte[] { 3, 2, 3, 4, 5, 6, 7 }, 8, new byte[] { 3, 2, 3, 4, 5, 6, 7, 0 })]
    public void ZeroPaddingVector(byte[] input, int blockSize, byte[] reference)
    {
        using var blkCipher = new NoOpSingleBlockTransform(blockSize);
        using var enc = new ZerosPaddingTransform(blkCipher, false);
        Assert.Equal(blockSize, enc.InputBlockSize);
        Assert.Equal(blockSize, enc.OutputBlockSize);
        Assert.True(enc.CanReuseTransform);
        Assert.False(enc.CanTransformMultipleBlocks);

        var padded = enc.TransformFinalBlock(input, 0, input.Length);
        Assert.Equal(reference, padded);
    }
}
