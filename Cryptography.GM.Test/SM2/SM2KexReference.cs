using System;
using System.Globalization;
using System.Numerics;
using System.Text;
using Xunit;
// ReSharper disable InconsistentNaming

namespace Cryptography.GM.Test.SM2;

public class SM2KexReference
{
    [Fact]
    public void KexVector()
    {
        var da = BigInteger.Parse("081EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029",
                                  NumberStyles.HexNumber);
        var db = BigInteger.Parse("0785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5",
                                  NumberStyles.HexNumber);
        var ra = (BigInteger.Parse("0D4DE15474DB74D06491C440D305E012400990F3E390C7E87153C12DB2EA60BB3",
                                   NumberStyles.HexNumber) - 1).ToByteArray();
        var rb = (BigInteger.Parse("07E07124814B309489125EAED101113164EBF0F3458C5BD88335C1F9D596243D6",
                                   NumberStyles.HexNumber) - 1).ToByteArray();
        var id = Encoding.ASCII.GetBytes("1234567812345678");
        var sa = new byte[] {
            0x18, 0xC7, 0x89, 0x4B, 0x38, 0x16, 0xDF, 0x16, 0xCF, 0x07, 0xB0, 0x5C, 0x5E, 0xC0, 0xBE, 0xF5,
            0xD6, 0x55, 0xD5, 0x8F, 0x77, 0x9C, 0xC1, 0xB4, 0x00, 0xA4, 0xF3, 0x88, 0x46, 0x44, 0xDB, 0x88
        };
        var sb = new byte[] {
            0xD3, 0xA0, 0xFE, 0x15, 0xDE, 0xE1, 0x85, 0xCE, 0xAE, 0x90, 0x7A, 0x6B, 0x59, 0x5C, 0xC3, 0x2A,
            0x26, 0x6E, 0xD7, 0xB3, 0x36, 0x7E, 0x99, 0x83, 0xA8, 0x96, 0xDC, 0x32, 0xFA, 0x20, 0xF8, 0xEB
        };
        var k = new byte[] {
            0x6C, 0x89, 0x34, 0x73, 0x54, 0xDE, 0x24, 0x84, 0xC6, 0x0B, 0x4A, 0xB1, 0xFD, 0xE4, 0xC6, 0xE5
        };

        Array.Resize(ref ra, ra.Length + 13);
        Array.Resize(ref rb, rb.Length + 13);
        var rngA = new FixedBytesGenerator(ra);
        var rngB = new FixedBytesGenerator(rb);
        var a = System.Security.Cryptography.SM2.Create(rngA);
        var b = System.Security.Cryptography.SM2.Create(rngB);
        a.ImportPrivateKey(da);
        b.ImportPrivateKey(db);
        a.Ident = id;
        b.Ident = id;

        rngA.Reset();
        rngB.Reset();
        var keA = a.StartKeyExchange(false);
        var keB = b.StartKeyExchange(true);

        var (kdfA, s1a, s2a) = keA.DeriveKey(b.ExportKey().Q, keB.R, id);
        var (kdfB, s1b, s2b) = keB.DeriveKey(a.ExportKey().Q, keA.R, id);

        Assert.NotNull(kdfA);
        Assert.NotNull(kdfB);
        Assert.Equal(sa, s1a);
        Assert.Equal(sa, s2b);
        Assert.Equal(sb, s1b);
        Assert.Equal(sb, s2a);

        Assert.Equal(k, kdfA.GetBytes(k.Length));
        Assert.Equal(k, kdfB.GetBytes(k.Length));
        Assert.Equal(kdfA.GetBytes(32), kdfB.GetBytes(32));
    }
}
