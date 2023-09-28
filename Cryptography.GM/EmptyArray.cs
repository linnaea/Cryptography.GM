using System.Runtime.CompilerServices;
[assembly:InternalsVisibleTo("Cryptography.GM.Test")]

// ReSharper disable CheckNamespace
internal static class EmptyArray<T>
{
#if NETSTANDARD || NETCOREAPP || NET46_OR_GREATER
    public static readonly T[] Instance = System.Array.Empty<T>();
#else
    public static readonly T[] Instance = new T[0];
#endif
}

#if !(NETSTANDARD2_1_OR_GREATER || NETCOREAPP3_0_OR_GREATER)
namespace System.Diagnostics.CodeAnalysis
{
    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Parameter | AttributeTargets.Property)]
    internal sealed class AllowNullAttribute : Attribute
    {
    }
}
#endif

#if !NET5_0_OR_GREATER
namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit
    { }
}
#endif
