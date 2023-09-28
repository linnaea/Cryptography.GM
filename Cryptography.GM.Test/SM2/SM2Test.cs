using System;
using System.Security.Cryptography;
using Cryptography.GM.ECMath;
using Xunit;

namespace Cryptography.GM.Test.SM2;

public class SM2Test
{
    [Fact]
    public void FxKeyRoundTripTest()
    {
        using var sm2Export = System.Security.Cryptography.SM2.Create();
        var kp = sm2Export.GenerateKeyPair();
        using var sm2Import = System.Security.Cryptography.SM2.Create();
        Assert.Throws<InvalidOperationException>(() => sm2Import.ImportKey(default));
#if NETSTANDARD || NETCOREAPP || NET47_OR_GREATER
        sm2Import.ImportKey((EcKeyPair)(ECParameters)kp);
#else
        sm2Import.ImportKey(kp);
#endif
        Assert.Equal(sm2Import.ExportKey().D, kp.D);
        var buf = new byte[128];
        new Random().NextBytes(buf);
        var enc = sm2Export.EncryptData(buf);
        var dec = sm2Import.DecryptData(enc);
        Assert.Equal(buf, dec);
    }

    [Fact]
    public void KexRequiresKeyPair()
    {
        using var sm2 = System.Security.Cryptography.SM2.Create();
        Assert.Throws<InvalidOperationException>(() => sm2.StartKeyExchange(true));
        Assert.Throws<InvalidOperationException>(() => sm2.StartKeyExchange(false));
        var pubKey = sm2.GenerateKeyPair() with { D = default };
        using var sm2PubOnly = System.Security.Cryptography.SM2.Create();
        sm2PubOnly.ImportKey(pubKey);
        Assert.Throws<InvalidOperationException>(() => sm2PubOnly.StartKeyExchange(true));
        Assert.Throws<InvalidOperationException>(() => sm2PubOnly.StartKeyExchange(false));
    }

    [Fact]
    public void SigningRequiresKey()
    {
        var data = new byte[16];
        new Random().NextBytes(data);

        using var sm2 = System.Security.Cryptography.SM2.Create();
        var pubKey = sm2.GenerateKeyPair() with { D = default };
        var sig = sm2.SignData(data);

        using var sm2PubOnly = System.Security.Cryptography.SM2.Create();
        Assert.Throws<InvalidOperationException>(() => sm2PubOnly.VerifyData(sig, data));
        sm2PubOnly.ImportKey(pubKey);
        Assert.Throws<InvalidOperationException>(() => sm2PubOnly.SignData(data));
        Assert.True(sm2PubOnly.VerifyData(sig, data));
    }

    [Fact]
    public void EncDecRequiresKey()
    {
        var data = new byte[16];
        new Random().NextBytes(data);

        using var sm2 = System.Security.Cryptography.SM2.Create();
        var pubKey = sm2.GenerateKeyPair() with { D = default };

        using var sm2PubOnly = System.Security.Cryptography.SM2.Create();
        Assert.Throws<InvalidOperationException>(() => sm2PubOnly.EncryptData(data));
        sm2PubOnly.ImportKey(pubKey);
        var enc = sm2PubOnly.EncryptData(data);

        Assert.Throws<InvalidOperationException>(() => sm2PubOnly.DecryptData(enc));
        var dec = sm2.DecryptData(enc);
        Assert.Equal(data, dec);
    }
}
