// ReSharper disable CheckNamespace
internal class EmptyArray<T>
{
#if NETSTANDARD
    public static readonly T[] Instance = System.Array.Empty<T>();
#else
    public static readonly T[] Instance = new T[0];
#endif
}
