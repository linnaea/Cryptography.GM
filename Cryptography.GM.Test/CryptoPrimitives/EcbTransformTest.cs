using System;
using Xunit;

namespace Cryptography.GM.Test.CryptoPrimitives;

public class EcbTransformTest
{
    [Fact]
    public void IncompleteBlockThrows()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new NoOpTransform(16).TransformFinalBlock(new byte[1], 0, 1));
    }
}
