using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Cryptography.GM.Primitives;
using Xunit;

namespace Cryptography.GM.Test.CryptoPrimitives;

public class Pkcs7PaddingReference
{
    [Theory]
    [InlineData(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }, 16, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 6, 6, 6, 6, 6, 6 })]
    [InlineData(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 }, 8, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 6, 6, 6, 6, 6, 6 })]
    [InlineData(new byte[] { 2, 2, 3, 4, 5, 6, 7, 8 }, 8, new byte[] { 2, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8 })]
    [InlineData(new byte[] { 3, 2, 3, 4, 5, 6, 7 }, 8, new byte[] { 3, 2, 3, 4, 5, 6, 7, 1 })]
    public void Pkcs7PaddingVector(byte[] input, int blockSize, byte[] reference)
    {
        var blkCipher = new NoOpSingleBlockTransform(blockSize);
        var enc = new PaddingTransform(blkCipher, PaddingMode.PKCS7, false);
        var dec = new PaddingTransform(blkCipher, PaddingMode.PKCS7, true);
        var padded = enc.TransformFinalBlock(input, 0, input.Length);
        Assert.Equal(reference.AsEnumerable(), padded);

        using (var unPadded = new MemoryStream()) {
            using (var cryptoStream = new CryptoStream(unPadded, dec, CryptoStreamMode.Write)) {
                for (var i = 0; i < padded.Length; i += blockSize) {
                    cryptoStream.Write(padded, i, blockSize);
                }
            }

            Assert.Equal(input.AsEnumerable(), unPadded.ToArray());
        }

        Assert.True(enc.CanReuseTransform);
        Assert.False(enc.CanTransformMultipleBlocks);
    }

    [Theory]
    [InlineData(new byte[] { }, 8)]
    [InlineData(new byte[] { 1, 2, 3, 4, 5, 6, 7, 9 }, 8)]
    [InlineData(new byte[] { 2, 2, 3, 4, 5, 6, 7, 0 }, 8)]
    [InlineData(new byte[] { 3, 2, 3, 4, 5, 6, 7, 8 }, 8)]
    [InlineData(new byte[] { 4, 2, 3, 4, 5, 6, 7, 7 }, 8)]
    public void InvalidPaddingThrows(byte[] error, int blockSize)
    {
        var blkCipher = new NoOpTransform(blockSize);
        var dec = new PaddingTransform(blkCipher, PaddingMode.PKCS7, true);
        Assert.True(dec.CanReuseTransform);
        Assert.True(dec.CanTransformMultipleBlocks);
        Assert.Throws<CryptographicException>(() => dec.TransformFinalBlock(error, 0, error.Length));
    }

    [Fact]
    public void LargeBlockThrows()
    {
        Assert.Throws<CryptographicException>(() => new PaddingTransform(new NoOpTransform(256), PaddingMode.PKCS7, false));
    }
}
