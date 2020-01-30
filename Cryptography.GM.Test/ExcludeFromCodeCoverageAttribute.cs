// ReSharper disable CheckNamespace
#if NETCOREAPP1_1
namespace System.Diagnostics.CodeAnalysis
{
    [AttributeUsage(
        AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Constructor |
        AttributeTargets.Event | AttributeTargets.Method | AttributeTargets.Property |
        AttributeTargets.Struct, Inherited = false)]
    internal sealed class ExcludeFromCodeCoverageAttribute : Attribute
    { }
}
#endif
