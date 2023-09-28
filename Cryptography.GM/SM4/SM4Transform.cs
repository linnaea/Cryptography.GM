using System;
using Cryptography.GM.Primitives;
using static Cryptography.GM.BitOps;
// ReSharper disable RedundantExplicitArraySize
// ReSharper disable once CheckNamespace
// ReSharper disable once InconsistentNaming

namespace Cryptography.GM;

public sealed class SM4Transform : EcbTransform
{
    private static readonly byte[] S = {
        /*         x0    x1    x2    x3    x4    x5    x6    x7    x8    x9    xA    xB    xC    xD    xE    xF */
        /* 0x */ 0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        /* 1x */ 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        /* 2x */ 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        /* 3x */ 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        /* 4x */ 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        /* 5x */ 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        /* 6x */ 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        /* 7x */ 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        /* 8x */ 0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        /* 9x */ 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        /* Ax */ 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        /* Bx */ 0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        /* Cx */ 0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        /* Dx */ 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        /* Ex */ 0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        /* Fx */ 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
    };

    private static readonly uint[] Fk = {
        0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
    };

    private readonly uint[] _rk = new uint[32];

    public override int InputBlockSize => 16;
    public override int OutputBlockSize => 16;

    public SM4Transform(ReadOnlySpan<byte> key, bool decrypt)
    {
        Span<uint> k = stackalloc uint[4] {
            ReadU32Be(key.Slice(0, 4)) ^ Fk[0],
            ReadU32Be(key.Slice(4, 4)) ^ Fk[1],
            ReadU32Be(key.Slice(8, 4)) ^ Fk[2],
            ReadU32Be(key.Slice(12, 4)) ^ Fk[3]
        };
        for (var i = 0; i < 32; i++) {
            var ck = MakeU32((byte)(28 * i), (byte)(28 * i + 7), (byte)(28 * i + 14), (byte)(28 * i + 21));
            var k4 = k[0] ^ Lp(Tao(k[1] ^ k[2] ^ k[3] ^ ck));
            _rk[decrypt ? 31 - i : i] = k4;
            for (var j = 0; j < 3; j++) {
                k[j] = k[j + 1];
            }

            k[3] = k4;
        }
    }

    private static uint L(uint b) => b ^ RotL32(b, 2) ^ RotL32(b, 10) ^ RotL32(b, 18) ^ RotL32(b, 24);
    private static uint Lp(uint b) => b ^ RotL32(b, 13) ^ RotL32(b, 23);
    private static uint Tao(uint v) => MakeU32(S[(byte)(v >> 24)], S[(byte)(v >> 16)], S[(byte)(v >> 8)], S[(byte)v]);

    protected override void TransformOneBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<uint> x = stackalloc uint[4] {
            ReadU32Be(input.Slice(0, 4)),
            ReadU32Be(input.Slice(4, 4)),
            ReadU32Be(input.Slice(8, 4)),
            ReadU32Be(input.Slice(12, 4))
        };

        foreach (var rk in _rk) {
            var x4 = x[0] ^ L(Tao(x[1] ^ x[2] ^ x[3] ^ rk));
            for (var j = 0; j < 3; j++) {
                x[j] = x[j + 1];
            }

            x[3] = x4;
        }

        WriteU32Be(output.Slice(0, 4), x[3]);
        WriteU32Be(output.Slice(4, 4), x[2]);
        WriteU32Be(output.Slice(8, 4), x[1]);
        WriteU32Be(output.Slice(12, 4), x[0]);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Array.Clear(_rk, 0, _rk.Length);
    }
}
