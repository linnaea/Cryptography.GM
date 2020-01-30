using System;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography.Primitives;
using System.Text;
using Xunit;

namespace Cryptography.GM.Test.SM2
{
    public class FixedBytesGenerator : BlockDeriveBytes
    {
        private readonly byte[] _d;
        public FixedBytesGenerator(byte[] d) => _d = d;
        public override int BlockSize => _d.Length;
        public override void NextBlock(Span<byte> buf) => _d.CopyTo(buf);
    }
    
    // ReSharper disable once InconsistentNaming
    public class SM2SignatureReference
    {
        [Fact]
        public void SignatureVector()
        {
            var k = (BigInteger.Parse("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21",
                                      NumberStyles.HexNumber) - 1).ToByteArray();
            var d = BigInteger.Parse("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
                                     NumberStyles.HexNumber);
            var q = new byte[] {
                0x03,
                0x09,0xF9,0xDF,0x31,0x1E,0x54,0x21,0xA1,0x50,0xDD,0x7D,0x16,0x1E,0x4B,0xC5,0xC6,
                0x72,0x17,0x9F,0xAD,0x18,0x33,0xFC,0x07,0x6B,0xB0,0x8F,0xF3,0x56,0xF3,0x50,0x20
            };

            var id = Encoding.ASCII.GetBytes("1234567812345678");
            var message = Encoding.ASCII.GetBytes("message digest");
            var rs = new byte[] {
                0xF5, 0xA0, 0x3B, 0x06, 0x48, 0xD2, 0xC4, 0x63, 0x0E, 0xEA, 0xC5, 0x13, 0xE1, 0xBB, 0x81, 0xA1,
                0x59, 0x44, 0xDA, 0x38, 0x27, 0xD5, 0xB7, 0x41, 0x43, 0xAC, 0x7E, 0xAC, 0xEE, 0xE7, 0x20, 0xB3,
                0xB1, 0xB6, 0xAA, 0x29, 0xDF, 0x21, 0x2F, 0xD8, 0x76, 0x31, 0x82, 0xBC, 0x0D, 0x42, 0x1C, 0xA1,
                0xBB, 0x90, 0x38, 0xFD, 0x1F, 0x7F, 0x42, 0xD4, 0x84, 0x0B, 0x69, 0xC4, 0x85, 0xBB, 0xC1, 0xAA
            };
            
            Array.Resize(ref k, k.Length + 13);
            var rng = new FixedBytesGenerator(k);
            var sm2 = System.Security.Cryptography.SM2.Create(rng);
            sm2.Ident = id;
            sm2.ImportPrivateKey(d);
            Assert.Equal(q, sm2.ExportKey().Q.ToBytes(sm2));

            sm2.ImportPublicKey(sm2.PointFromBytes(q).Point);
            Assert.Equal(d, sm2.ExportKey().D);

            rng.Reset();
            var sig = sm2.SignData(message);
            Assert.Equal(rs, sig);
            
            Assert.True(sm2.VerifyData(sig, message));
            var touch = new Random().Next(sig.Length);
            sig[touch] ^= 1;
            Assert.False(sm2.VerifyData(sig, message));
        }
    }
}
