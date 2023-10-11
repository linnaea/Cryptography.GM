using System;
using System.IO;
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
        using var blkCipher = new NoOpSingleBlockTransform(blockSize);
        using var enc = new PaddingTransform(blkCipher, PaddingMode.PKCS7, false);
        using var dec = new PaddingTransform(blkCipher, PaddingMode.PKCS7, true);
        var x2 = new byte[input.Length + 2];
        Array.Copy(input, 0, x2, 1, input.Length);
        var padded = enc.TransformFinalBlock(x2, 1, input.Length);
        Assert.Equal(reference, padded);

        using (var unPadded = new MemoryStream()) {
            using (var cryptoStream = new CryptoStream(unPadded, dec, CryptoStreamMode.Write)) {
                for (var i = 0; i < padded.Length; i += blockSize) {
                    cryptoStream.Write(padded, i, blockSize);
                }
            }

            Assert.Equal(input, unPadded.ToArray());
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
        using var blkCipher = new NoOpTransform(blockSize);
        using var dec = new PaddingTransform(blkCipher, PaddingMode.PKCS7, true);
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
