// ReSharper disable once CheckNamespace
namespace Cryptography.GM;

public struct Bits128
{
    private ulong _lo;
    private ulong _hi;

    public void Deconstruct(out ulong hi, out ulong lo)
    {
        hi = _hi;
        lo = _lo;
    }

    public void Deconstruct(out uint hh, out uint hl, out uint lh, out uint ll)
    {
        hh = (uint)(_hi >> 32);
        hl = (uint)_hi;
        lh = (uint)(_lo >> 32);
        ll = (uint)_lo;
    }

    public Bits128(uint hh, uint hl, uint lh, uint ll)
    {
        _lo = (ulong)lh << 32 | ll;
        _hi = (ulong)hh << 32 | hl;
    }

    public static explicit operator Bits128(int v) => new() {
        _lo = (ulong)v,
        _hi = (ulong)(v >> 31)
    };

    public static Bits128 operator >> (Bits128 l, int r)
    {
        r %= 128;
        if (r >= 64) {
            return new Bits128 {
                _lo = l._hi >> (r - 64)
            };
        }

        if (r > 0) {
            var hi = l._hi;
            l._hi >>= r;
            l._lo >>= r;
            l._lo |= hi << (64 - r);
        }

        return l;
    }

    public static Bits128 operator <<(Bits128 l, int r)
    {
        r %= 128;
        if (r >= 64) {
            return new Bits128 {
                _hi = l._lo << (r - 64)
            };
        }

        if (r > 0) {
            var lo = l._lo;
            l._hi <<= r;
            l._lo <<= r;
            l._hi |= lo >> (64 - r);
        }

        return l;
    }

    public static Bits128 operator ^(Bits128 l, Bits128 r) => new() {
        _lo = l._lo ^ r._lo,
        _hi = l._hi ^ r._hi
    };

    public static Bits128 operator &(Bits128 l, Bits128 r) => new() {
        _lo = l._lo & r._lo,
        _hi = l._hi & r._hi
    };

    public static Bits128 operator |(Bits128 l, Bits128 r) => new() {
        _lo = l._lo | r._lo,
        _hi = l._hi | r._hi
    };

    public override string ToString() => $"{_hi:x16}{_lo:x16}";
}

internal struct Bits256
{
    private Bits128 _lo;
    private Bits128 _hi;

    public void Deconstruct(out ulong hh, out ulong hl, out ulong lh, out ulong ll)
    {
        (hh, hl) = _hi;
        (lh, ll) = _lo;
    }

    public void Deconstruct(out uint hhh, out uint hhl, out uint hlh, out uint hll,
                            out uint lhh, out uint lhl, out uint llh, out uint lll)
    {
        (hhh, hhl, hlh, hll) = _hi;
        (lhh, lhl, llh, lll) = _lo;
    }

    public Bits256(uint hhh, uint hhl, uint hlh, uint hll, uint lhh, uint lhl, uint llh, uint lll)
    {
        _hi = new Bits128(hhh, hhl, hlh, hll);
        _lo = new Bits128(lhh, lhl, llh, lll);
    }

    public static Bits256 operator ^(Bits256 l, Bits256 r) => new() {
        _lo = l._lo ^ r._lo,
        _hi = l._hi ^ r._hi
    };

    public override string ToString() => $"{_hi}{_lo}";
}
