using Cryptography.GM;
using Cryptography.GM.Primitives;

namespace System.Security.Cryptography;

public sealed class Eea3Transform : XorStreamCipherTransform<ZucKeyStreamGenerator>
{
    private readonly uint[]? _initState;

    public Eea3Transform(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> iv, bool reuseTransform = false,
                         ZucVersion version = ZucVersion.Zuc15)
        : base(new ZucKeyStreamGenerator(sk, iv, version))
    {
        if (reuseTransform)
            _initState = Rng.DumpState();
    }

    protected override void ResetRng()
    {
        if (_initState == null)
            throw new InvalidOperationException();

        Rng.LoadState(_initState);
    }

    public override bool CanReuseTransform => _initState != null;
}
