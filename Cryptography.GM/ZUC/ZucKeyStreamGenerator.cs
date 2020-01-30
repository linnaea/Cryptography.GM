using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Primitives;
using static Cryptography.GM.BitOps;
#pragma warning disable 618

// ReSharper disable RedundantExplicitArraySize
// ReSharper disable once CheckNamespace
namespace Cryptography.GM
{
    public enum ZucVersion : byte
    {
        [Obsolete("Known IV collision")]
        Zuc14 = 14,
        Zuc15 = 15,
        Zuc256E = 128,
        Zuc256M32 = 129,
        Zuc256M64 = 130,
        Zuc256M128 = 131
    }

    public sealed class ZucKeyStreamGenerator : BlockDeriveBytes
    {
        private static readonly IReadOnlyList<byte> S0 = new byte[256] {
                   /*  x0    x1    x2    x3    x4    x5    x6    x7    x8    x9    xA    xB    xC    xD    xE    xF */
            /* 0x */ 0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB,
            /* 1x */ 0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53, 0x03, 0x90,
            /* 2x */ 0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B, 0x29, 0x6E, 0xAC,
            /* 3x */ 0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39, 0x63, 0x20, 0xD4, 0x38,
            /* 4x */ 0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB, 0x14, 0x21, 0x06, 0x55, 0x9B,
            /* 5x */ 0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82, 0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C,
            /* 6x */ 0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C, 0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD,
            /* 7x */ 0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A, 0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8,
            /* 8x */ 0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13, 0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56,
            /* 9x */ 0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE,
            /* Ax */ 0xBC, 0x26, 0x95, 0x88, 0x8A, 0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D,
            /* Bx */ 0xD0, 0xDC, 0x11, 0x66, 0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23,
            /* Cx */ 0x0E, 0x86, 0xAB, 0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1,
            /* Dx */ 0xF6, 0xFA, 0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F,
            /* Ex */ 0x8E, 0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65,
            /* Fx */ 0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34, 0x60
        };

        private static readonly IReadOnlyList<byte> S1 = new byte[256] {
                   /*  x0    x1    x2    x3    x4    x5    x6    x7    x8    x9    xA    xB    xC    xD    xE    xF */
            /* 0x */ 0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77,
            /* 1x */ 0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42,
            /* 2x */ 0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1,
            /* 3x */ 0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48,
            /* 4x */ 0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87,
            /* 5x */ 0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB,
            /* 6x */ 0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09,
            /* 7x */ 0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9,
            /* 8x */ 0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9,
            /* 9x */ 0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89,
            /* Ax */ 0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4,
            /* Bx */ 0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE,
            /* Cx */ 0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21,
            /* Dx */ 0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34,
            /* Ex */ 0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28,
            /* Fx */ 0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2
        };

        private static readonly IReadOnlyList<ushort> EKd = new ushort[16] {
            0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
            0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
        };

        private static readonly IReadOnlyList<byte> EKd256E = new byte[16] {
            0b0100010, 0b0101111, 0b0100100, 0b0101010, 0b1101101, 0b1000000, 0b1000000, 0b1000000,
            0b1000000, 0b1000000, 0b1000000, 0b1000000, 0b1000000, 0b1010010, 0b0010000, 0b0110000
        };

        private static readonly IReadOnlyList<byte> EKd256M32 = new byte[16] {
            0b0100010, 0b0101111, 0b0100101, 0b0101010, 0b1101101, 0b1000000, 0b1000000, 0b1000000,
            0b1000000, 0b1000000, 0b1000000, 0b1000000, 0b1000000, 0b1010010, 0b0010000, 0b0110000
        };

        private static readonly IReadOnlyList<byte> EKd256M64 = new byte[16] {
            0b0100011, 0b0101111, 0b0100100, 0b0101010, 0b1101101, 0b1000000, 0b1000000, 0b1000000,
            0b1000000, 0b1000000, 0b1000000, 0b1000000, 0b1000000, 0b1010010, 0b0010000, 0b0110000
        };

        private static readonly IReadOnlyList<byte> EKd256M128 = new byte[16] {
            0b0100011, 0b0101111, 0b0100101, 0b0101010, 0b1101101, 0b1000000, 0b1000000, 0b1000000,
            0b1000000, 0b1000000, 0b1000000, 0b1000000, 0b1000000, 0b1010010, 0b0010000, 0b0110000
        };

        public ZucVersion Version { get; }

        private readonly uint[] _lfsr = new uint[16];
        private uint _fr1;
        private uint _fr2;

        private static uint AddM(uint a, uint b)
        {
            uint c = a + b;
            return (c & 0x7fffffff) + (c >> 31);
        }

        private static uint RotL31(uint a, byte b) => ((a << b) | (a >> (31 - b))) & 0x7FFFFFFF;

        private static uint L1(uint a) => a ^ RotL32(a, 2) ^ RotL32(a, 10) ^ RotL32(a, 18) ^ RotL32(a, 24);

        private static uint L2(uint a) => a ^ RotL32(a, 8) ^ RotL32(a, 14) ^ RotL32(a, 22) ^ RotL32(a, 30);

        private static uint MakeU31(byte hh, byte hl, byte lh, byte ll) => (uint) (hh << 23 | hl << 16 | lh << 8 | ll);

        private static uint MakeU31(byte h, ushort m, byte l) => (uint) (h << 23 | m << 8 | l);

        private static uint S(uint v) => MakeU32(S0[(byte) (v >> 24)], S1[(byte) (v >> 16)], S0[(byte) (v >> 8)], S1[(byte) v]);

        private void Lfsr(uint u)
        {
            uint f = _lfsr[0];
            f = AddM(f, RotL31(_lfsr[0], 8));
            f = AddM(f, RotL31(_lfsr[4], 20));
            f = AddM(f, RotL31(_lfsr[10], 21));
            f = AddM(f, RotL31(_lfsr[13], 17));
            f = AddM(f, RotL31(_lfsr[15], 15));
            for (var i = 0; i < 15; i++) {
                _lfsr[i] = _lfsr[i + 1];
            }

            _lfsr[15] = Version switch {
                ZucVersion.Zuc14 => f ^ u,
                _ => AddM(f, u)
            };

            if (_lfsr[15] == 0) {
                _lfsr[15] = 0x7fffffff;
            }
        }

        private (uint, uint, uint, uint) Brx()
            => (
                   (_lfsr[15] & 0x7FFF8000u) << 1 | _lfsr[14] & 0xFFFF,
                   (_lfsr[11] & 0xFFFFu) << 16 | _lfsr[9] >> 15,
                   (_lfsr[7] & 0xFFFFu) << 16 | _lfsr[5] >> 15,
                   (_lfsr[2] & 0xFFFFu) << 16 | _lfsr[0] >> 15
               );

        private uint F(uint brx0, uint brx1, uint brx2)
        {
            var w = (_fr1 ^ brx0) + _fr2;
            var w1 = _fr1 + brx1;
            var w2 = _fr2 ^ brx2;
            _fr1 = S(L1((w1 << 16) | (w2 >> 16)));
            _fr2 = S(L2((w2 << 16) | (w1 >> 16)));
            return w;
        }

        public ZucKeyStreamGenerator(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> iv, ZucVersion version = ZucVersion.Zuc15)
        {
            Version = version;

            switch (version) {
            case ZucVersion.Zuc14:
            case ZucVersion.Zuc15:
                for (var i = 0; i < 16; i++) {
                    _lfsr[i] = MakeU31(sk[i], EKd[i], iv[i]);
                }

                break;
            case ZucVersion.Zuc256E:
            case ZucVersion.Zuc256M32:
            case ZucVersion.Zuc256M64:
            case ZucVersion.Zuc256M128:
                if (iv.Length >= 25) {
                    for (var i = 17; i < 25; i++) {
                        if((iv[i] & 0xc0) != 0) {
                            throw new ArgumentException(nameof(iv));
                        }
                    }
                } else {
                    var xiv = new byte[25];
                    iv.CopyTo(xiv);
                    xiv[17] = (byte) (iv[17] >> 2);
                    xiv[18] = (byte) (((iv[17] & 0x3) << 4) | (iv[18] >> 4));
                    xiv[19] = (byte) (((iv[18] & 0xf) << 2) | (iv[19] >> 6));
                    xiv[20] = (byte) (iv[19] & 0x3f);
                    xiv[21] = (byte) (iv[20] >> 2);
                    xiv[22] = (byte) (((iv[20] & 0x3) << 4) | (iv[21] >> 4));
                    xiv[23] = (byte) (((iv[21] & 0xf) << 2) | (iv[22] >> 6));
                    xiv[24] = (byte) (iv[22] & 0x3f);
                    iv = xiv;
                }
                var ekd = version switch {
                    ZucVersion.Zuc256E => EKd256E,
                    ZucVersion.Zuc256M32 => EKd256M32,
                    ZucVersion.Zuc256M64 => EKd256M64,
                    ZucVersion.Zuc256M128 => EKd256M128,
                    _ => throw new Exception()
                };
                for (var i = 0; i < 5; i++) {
                    _lfsr[i] = MakeU31(sk[i], ekd[i], sk[i + 21], sk[i + 16]);
                }

                _lfsr[5] = MakeU31(iv[0], (byte) (ekd[5] | iv[17]), sk[5], sk[26]);
                _lfsr[6] = MakeU31(iv[1], (byte) (ekd[6] | iv[18]), sk[6], sk[27]);
                _lfsr[7] = MakeU31(iv[10], (byte) (ekd[7] | iv[19]), sk[7], iv[2]);
                _lfsr[8] = MakeU31(sk[8], (byte) (ekd[8] | iv[20]), iv[3], iv[11]);
                _lfsr[9] = MakeU31(sk[9], (byte) (ekd[9] | iv[21]), iv[12], iv[4]);
                _lfsr[10] = MakeU31(sk[5], (byte) (ekd[10] | iv[22]), sk[10], sk[28]);
                _lfsr[11] = MakeU31(sk[11], (byte) (ekd[11] | iv[23]), iv[6], iv[13]);
                _lfsr[12] = MakeU31(sk[12], (byte) (ekd[12] | iv[24]), iv[7], iv[14]);
                _lfsr[13] = MakeU31(sk[13], ekd[13], iv[15], iv[8]);
                _lfsr[14] = MakeU31(sk[14], (byte) (ekd[14] | (sk[31] >> 4)), iv[16], iv[9]);
                _lfsr[15] = MakeU31(sk[15], (byte) (ekd[15] | (sk[31] & 0xf)), sk[30], sk[29]);
                break;
            default:
                throw new ArgumentException(nameof(version));
            }

            for (int i = 0; i < 32; i++) {
                var (brx0, brx1, brx2, brx3) = Brx();
                var w = F(brx0, brx1, brx2) ^ Version switch {
                    ZucVersion.Zuc14 => brx3,
                    _ => 0
                };
                Lfsr(w >> 1);
            }

            NextKey();
        }

        public ZucKeyStreamGenerator(uint[] state)
        {
            Version = (ZucVersion) state[0];
            if (!Enum.IsDefined(typeof(ZucVersion), Version)) {
                throw new InvalidOperationException();
            }

            LoadState(state);
        }

        public uint NextKey()
        {
            var (brx0, brx1, brx2, brx3) = Brx();
            var k = F(brx0, brx1, brx2) ^ brx3;
            Lfsr(0);
            return k;
        }

        [SuppressMessage("ReSharper", "IteratorNeverReturns")]
        public IEnumerable<uint> EnumerateKeys()
        {
            while (true)
                yield return NextKey();
        }

        public uint[] DumpState()
        {
            var r = new uint[_lfsr.Length + 3];
            r[0] = (uint)Version;
            r[1] = _fr1;
            r[2] = _fr2;
            Array.Copy(_lfsr, 0, r, 3, _lfsr.Length);
            return r;
        }

        public void LoadState(uint[] state)
        {
            if(state.Length != _lfsr.Length + 3) throw new InvalidOperationException();
            if(state[0] != (uint)Version) throw new InvalidOperationException();
            _fr1 = state[1];
            _fr2 = state[2];
            Array.Copy(state, 3, _lfsr, 0, _lfsr.Length);
        }

        public override int BlockSize => 4;
        public override void NextBlock(Span<byte> buf) => WriteU32Be(buf, NextKey());
        public override void Reset() => throw new NotSupportedException();
    }
}
