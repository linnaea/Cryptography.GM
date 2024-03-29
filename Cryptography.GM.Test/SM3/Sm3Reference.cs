// ReSharper disable once RedundantUsingDirective
using System;
using System.Security.Cryptography;
using Xunit;

namespace Cryptography.GM.Test.SM3;

public class Sm3Reference
{
    [Theory]
    [InlineData(new byte[] {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
    }, new byte[] {
        0x61, 0x62, 0x63
    })]
    [InlineData(new byte[] {
        0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
        0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32
    }, new byte[] {
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64
    })]
    [InlineData(new byte[] {
        0xF4, 0xA3, 0x84, 0x89, 0xE3, 0x2B, 0x45, 0xB6, 0xF8, 0x76, 0xE3, 0xAC, 0x21, 0x68, 0xCA, 0x39,
        0x23, 0x62, 0xDC, 0x8F, 0x23, 0x45, 0x9C, 0x1D, 0x11, 0x46, 0xFC, 0x3D, 0xBF, 0xB7, 0xBC, 0x9A
    }, new byte[] {
        0x00, 0x90, 0x41, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33, 0x40, 0x59, 0x41, 0x48, 0x4F, 0x4F,
        0x2E, 0x43, 0x4F, 0x4D, 0x78, 0x79, 0x68, 0xB4, 0xFA, 0x32, 0xC3, 0xFD, 0x24, 0x17, 0x84, 0x2E,
        0x73, 0xBB, 0xFE, 0xFF, 0x2F, 0x3C, 0x84, 0x8B, 0x68, 0x31, 0xD7, 0xE0, 0xEC, 0x65, 0x22, 0x8B,
        0x39, 0x37, 0xE4, 0x98, 0x63, 0xE4, 0xC6, 0xD3, 0xB2, 0x3B, 0x0C, 0x84, 0x9C, 0xF8, 0x42, 0x41,

        0x48, 0x4B, 0xFE, 0x48, 0xF6, 0x1D, 0x59, 0xA5, 0xB1, 0x6B, 0xA0, 0x6E, 0x6E, 0x12, 0xD1, 0xDA,
        0x27, 0xC5, 0x24, 0x9A, 0x42, 0x1D, 0xEB, 0xD6, 0x1B, 0x62, 0xEA, 0xB6, 0x74, 0x64, 0x34, 0xEB,
        0xC3, 0xCC, 0x31, 0x5E, 0x32, 0x22, 0x0B, 0x3B, 0xAD, 0xD5, 0x0B, 0xDC, 0x4C, 0x4E, 0x6C, 0x14,
        0x7F, 0xED, 0xD4, 0x3D, 0x06, 0x80, 0x51, 0x2B, 0xCB, 0xB4, 0x2C, 0x07, 0xD4, 0x73, 0x49, 0xD2,

        0x15, 0x3B, 0x70, 0xC4, 0xE5, 0xD7, 0xFD, 0xFC, 0xBF, 0xA3, 0x6E, 0xA1, 0xA8, 0x58, 0x41, 0xB9,
        0xE4, 0x6E, 0x09, 0xA2, 0x0A, 0xE4, 0xC7, 0x79, 0x8A, 0xA0, 0xF1, 0x19, 0x47, 0x1B, 0xEE, 0x11,
        0x82, 0x5B, 0xE4, 0x62, 0x02, 0xBB, 0x79, 0xE2, 0xA5, 0x84, 0x44, 0x95, 0xE9, 0x7C, 0x04, 0xFF,
        0x4D, 0xF2, 0x54, 0x8A, 0x7C, 0x02, 0x40, 0xF8, 0x8F, 0x1C, 0xD4, 0xE1, 0x63, 0x52, 0xA7, 0x3C,

        0x17, 0xB7, 0xF1, 0x6F, 0x07, 0x35, 0x3E, 0x53, 0xA1, 0x76, 0xD6, 0x84, 0xA9, 0xFE, 0x0C, 0x6B,
        0xB7, 0x98, 0xE8, 0x57
    })]
    [InlineData(new byte[] {
        0x75, 0xab, 0x06, 0x0d, 0xb0, 0x1a, 0x2a, 0xa7, 0x45, 0x33, 0xdf, 0x25, 0x3d, 0xda, 0x15, 0x8e,
        0xc7, 0x0b, 0xd4, 0xc9, 0x0e, 0x50, 0xc9, 0xd6, 0xba, 0x5d, 0x63, 0xf3, 0x70, 0x3e, 0x59, 0xb7
    }, new byte[] {
        0xf7, 0x43, 0x90, 0xeb, 0xda, 0x4f, 0x7d, 0xc7, 0x15, 0x5f, 0x92, 0xb5, 0xf7, 0x71, 0xb9, 0x4a,
        0x69, 0xf8, 0x82, 0x7c, 0xdf, 0x11, 0x1a, 0x19, 0xcf, 0xc9, 0x40, 0x4c, 0xcd, 0xab, 0x9d, 0xf6,
        0xd6, 0x5d, 0xc9, 0xfd, 0xfb, 0x22, 0x70, 0x37, 0x99, 0xd5, 0xa6, 0x38, 0x1d, 0xfa, 0x16, 0xc2,
        0x6b, 0x83, 0x32, 0x52, 0x29, 0xad, 0xb9, 0x0d, 0x32, 0x4a, 0xbd, 0x14
    })]
    [InlineData(new byte[] {
        0x26, 0x35, 0x2A, 0xF8, 0x2E, 0xC1, 0x9F, 0x20, 0x7B, 0xBC, 0x6F, 0x94, 0x74, 0xE1, 0x1E, 0x90,
        0xCE, 0x0F, 0x7D, 0xDA, 0xCE, 0x03, 0xB2, 0x7F, 0x80, 0x18, 0x17, 0xE8, 0x97, 0xA8, 0x1F, 0xD5
    }, new byte[] {
        0x00, 0x90, 0x41, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33, 0x40, 0x59, 0x41, 0x48, 0x4F, 0x4F,
        0x2E, 0x43, 0x4F, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE7, 0x8B, 0xCD, 0x09, 0x74, 0x6C, 0x20, 0x23, 0x78, 0xA7,

        0xE7, 0x2B, 0x12, 0xBC, 0xE0, 0x02, 0x66, 0xB9, 0x62, 0x7E, 0xCB, 0x0B, 0x5A, 0x25, 0x36, 0x7A,
        0xD1, 0xAD, 0x4C, 0xC6, 0x24, 0x2B, 0x00, 0xCD, 0xB9, 0xCA, 0x7F, 0x1E, 0x6B, 0x04, 0x41, 0xF6,
        0x58, 0x34, 0x3F, 0x4B, 0x10, 0x29, 0x7C, 0x0E, 0xF9, 0xB6, 0x49, 0x10, 0x82, 0x40, 0x0A, 0x62,
        0xE7, 0xA7, 0x48, 0x57, 0x35, 0xFA, 0xDD, 0x01, 0x3D, 0xE7, 0x4D, 0xA6, 0x59, 0x51, 0xC4, 0xD7,

        0x6D, 0xC8, 0x92, 0x20, 0xD5, 0xF7, 0x77, 0x7A, 0x61, 0x1B, 0x1C, 0x38, 0xBA, 0xE2, 0x60, 0xB1,
        0x75, 0x95, 0x1D, 0xC8, 0x06, 0x0C, 0x2B, 0x3E, 0x01, 0x65, 0x96, 0x16, 0x45, 0x28, 0x1A, 0x86,
        0x26, 0x60, 0x7B, 0x91, 0x7F, 0x65, 0x7D, 0x7E, 0x93, 0x82, 0xF1, 0xEA, 0x5C, 0xD9, 0x31, 0xF4,
        0x0F, 0x66, 0x27, 0xF3, 0x57, 0x54, 0x26, 0x53, 0xB2, 0x01, 0x68, 0x65, 0x22, 0x13, 0x0D, 0x59,

        0x0F, 0xB8, 0xDE, 0x63, 0x5D, 0x8F, 0xCA, 0x71, 0x5C, 0xC6, 0xBF, 0x3D, 0x05, 0xBE, 0xF3, 0xF7,
        0x5D, 0xA5, 0xD5, 0x43, 0x45, 0x44, 0x48, 0x16, 0x66, 0x12
    })]
    public void Sm3Vector(byte[] hash, byte[] data)
    {
        using var hasher = System.Security.Cryptography.SM3.Create();
        var rng = new Random();
        var offset = 0;
        while (offset < data.Length) {
            var len = rng.Next(1, data.Length - offset);
            hasher.TransformBlock(data, offset, len, null, 0);
            offset += len;
        }

        hasher.TransformFinalBlock(EmptyArray<byte>.Instance, 0, 0);
        Assert.Equal(hash, hasher.Hash);
    }

    [Theory]
    [InlineData(new byte[] {
        0x27, 0x3a, 0x1e, 0xc9, 0x39, 0xd3, 0x4e, 0xe8, 0xf9, 0xca, 0xc5, 0x91, 0x7b, 0xd7, 0x97, 0x93,
        0xd3, 0x3f, 0x21, 0x94, 0x1a, 0xeb, 0x3b, 0xcd, 0x72, 0xdf, 0x6a, 0x87, 0xe0, 0x2a, 0x14, 0xc4
    }, new byte[] {
        0x75, 0xab, 0x06, 0x0d, 0xb0, 0x1a, 0x2a, 0xa7, 0x45, 0x33, 0xdf, 0x25, 0x3d, 0xda, 0x15, 0x8e,
        0xc7, 0x0b, 0xd4, 0xc9, 0x0e, 0x50, 0xc9, 0xd6, 0xba, 0x5d, 0x63, 0xf3, 0x70, 0x3e, 0x59, 0xb7
    }, new byte[] {
        0xf7, 0x43, 0x90, 0xeb, 0xda, 0x4f, 0x7d, 0xc7, 0x15, 0x5f, 0x92, 0xb5, 0xf7, 0x71, 0xb9, 0x4a,
        0x69, 0xf8, 0x82, 0x7c, 0xdf, 0x11, 0x1a, 0x19, 0xcf, 0xc9, 0x40, 0x4c, 0xcd, 0xab, 0x9d, 0xf6,
        0xd6, 0x5d, 0xc9, 0xfd, 0xfb, 0x22, 0x70, 0x37, 0x99, 0xd5, 0xa6, 0x38, 0x1d, 0xfa, 0x16, 0xc2,
        0x6b, 0x83, 0x32, 0x52, 0x29, 0xad, 0xb9, 0x0d, 0x32, 0x4a, 0xbd, 0x14
    })]
    [InlineData(new byte[] {
        0xbd, 0x11, 0xc0, 0xa0, 0xf7, 0x8f, 0x53, 0x96, 0x62, 0xb1, 0xcc, 0x43, 0x2b, 0xfd, 0x6a, 0x91,
        0x63, 0x75, 0xfd, 0x7c, 0x04, 0x1c, 0x33, 0x81, 0x70, 0x13, 0x16, 0x00, 0xe5, 0xce, 0x55, 0x61
    }, new byte[] {
        0x75, 0xab, 0x06, 0x0d, 0xb0, 0x1a, 0x2a, 0xa7, 0x45, 0x33, 0xdf, 0x25, 0x3d, 0xda, 0x15, 0x8e,
        0xc7, 0x0b, 0xd4, 0xc9, 0x0e, 0x50, 0xc9, 0xd6, 0xba, 0x5d, 0x63, 0xf3, 0x70, 0x3e, 0x59, 0xb7,
        0x75, 0xab, 0x06, 0x0d, 0xb0, 0x1a, 0x2a, 0xa7, 0x45, 0x33, 0xdf, 0x25, 0x3d, 0xda, 0x15, 0x8e,
        0xc7, 0x0b, 0xd4, 0xc9, 0x0e, 0x50, 0xc9, 0xd6, 0xba, 0x5d, 0x63, 0xf3, 0x70, 0x3e, 0x59, 0xb7
    }, new byte[] {
        0xf7, 0x43, 0x90, 0xeb, 0xda, 0x4f, 0x7d, 0xc7, 0x15, 0x5f, 0x92, 0xb5, 0xf7, 0x71, 0xb9, 0x4a,
        0x69, 0xf8, 0x82, 0x7c, 0xdf, 0x11, 0x1a, 0x19, 0xcf, 0xc9, 0x40, 0x4c, 0xcd, 0xab, 0x9d, 0xf6,
        0xd6, 0x5d, 0xc9, 0xfd, 0xfb, 0x22, 0x70, 0x37, 0x99, 0xd5, 0xa6, 0x38, 0x1d, 0xfa, 0x16, 0xc2,
        0x6b, 0x83, 0x32, 0x52, 0x29, 0xad, 0xb9, 0x0d, 0x32, 0x4a, 0xbd, 0x14
    })]
    [InlineData(new byte[] {
        0x24, 0x8d, 0x49, 0xb8, 0x04, 0xd5, 0x84, 0xf2, 0x22, 0x4f, 0xf6, 0xf7, 0xe7, 0x6d, 0x9d, 0xe7,
        0x7b, 0x78, 0x5a, 0x70, 0x9b, 0xbb, 0x08, 0xda, 0x58, 0x1c, 0x1e, 0xa0, 0xbd, 0x57, 0xd0, 0xe9
    }, new byte[] {
        0x75, 0xab, 0x06, 0x0d, 0xb0, 0x1a, 0x2a, 0xa7, 0x45, 0x33, 0xdf, 0x25, 0x3d, 0xda, 0x15, 0x8e,
        0xc7, 0x0b, 0xd4, 0xc9, 0x0e, 0x50, 0xc9, 0xd6, 0xba, 0x5d, 0x63, 0xf3, 0x70, 0x3e, 0x59, 0xb7,
        0x9c, 0xfa, 0x00, 0x0f, 0x17, 0x06, 0xb5, 0x3f, 0xf7, 0xca, 0x2c, 0xa5, 0x38, 0x46, 0x75, 0x38,
        0x7c, 0xaa, 0x1b, 0x4e, 0x0b, 0x5f, 0x17, 0x31, 0x5c, 0x7e, 0x74, 0x8c, 0xdd, 0xdb, 0x28, 0xb8,
        0x9b, 0xfb, 0x9b, 0x43, 0x98, 0x7d, 0x47, 0x99, 0xb2, 0x69, 0xf4, 0xd7, 0x80, 0x74, 0xd6, 0x39,
        0x2b, 0xfc, 0x5d, 0x18, 0x29, 0x0a, 0xeb, 0x37, 0x46, 0xcc, 0x2b, 0xb8, 0x5c, 0xb9, 0xba, 0x18
    }, new byte[] {
        0xf7, 0x43, 0x90, 0xeb, 0xda, 0x4f, 0x7d, 0xc7, 0x15, 0x5f, 0x92, 0xb5, 0xf7, 0x71, 0xb9, 0x4a,
        0x69, 0xf8, 0x82, 0x7c, 0xdf, 0x11, 0x1a, 0x19, 0xcf, 0xc9, 0x40, 0x4c, 0xcd, 0xab, 0x9d, 0xf6,
        0xd6, 0x5d, 0xc9, 0xfd, 0xfb, 0x22, 0x70, 0x37, 0x99, 0xd5, 0xa6, 0x38, 0x1d, 0xfa, 0x16, 0xc2,
        0x6b, 0x83, 0x32, 0x52, 0x29, 0xad, 0xb9, 0x0d, 0x32, 0x4a, 0xbd, 0x14
    })]
    public void HmacSm3Vector(byte[] hash, byte[] hmacKey, byte[] data)
    {
        using var hasher = new HMACSM3(hmacKey);
        Assert.Equal(hash, hasher.ComputeHash(data));
    }
}
