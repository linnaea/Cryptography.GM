// ReSharper disable InconsistentNaming

using Cryptography.GM.Primitives;
using Cryptography.GM;

namespace System.Security.Cryptography;

public sealed class SM4 : SymmetricAlgorithm
{
    public SM4()
    {
        LegalKeySizesValue = new[] { new KeySizes(128, 128, 0) };
        LegalBlockSizesValue = new[] { new KeySizes(128, 128, 0) };
        KeySizeValue = BlockSizeValue = 128;
    }

    private ICryptoTransform CreateXfrm(byte[] rgbKey, byte[]? rgbIV, bool decrypt)
    {
        ICryptoTransform xfrm = new SM4Transform(rgbKey, decrypt);
        switch (Mode) {
        case CipherMode.ECB:
            break;
        case CipherMode.CBC:
            if (rgbIV == null)
                throw new ArgumentNullException(nameof(rgbIV));
            xfrm = new CbcTransform(xfrm, rgbIV, decrypt);
            break;
        default:
            throw new NotSupportedException("Only CBC/ECB is supported");
        }

        switch (PaddingValue) {
        case PaddingMode.None:
            break;
        case PaddingMode.PKCS7:
        case PaddingMode.ISO10126:
        case PaddingMode.ANSIX923:
            xfrm = new PaddingTransform(xfrm, PaddingValue, decrypt);
            break;
        case PaddingMode.Zeros:
            xfrm = new ZerosPaddingTransform(xfrm, decrypt);
            break;
        default:
            throw new NotSupportedException("Only PKCS#7 padding is supported");
        }

        return xfrm;
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
        => CreateXfrm(rgbKey, rgbIV, true);

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
        => CreateXfrm(rgbKey, rgbIV, false);

    public override void GenerateIV()
    {
        var iv = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(iv);
        IVValue = iv;
    }

    public override void GenerateKey()
    {
        var k = new byte[16];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(k);
        KeyValue = k;
    }
}
