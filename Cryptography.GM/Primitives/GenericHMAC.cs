using System.Linq;
using System.Reflection;
// ReSharper disable InconsistentNaming

namespace System.Security.Cryptography.Primitives
{
    public class GenericHMAC<T> : KeyedHashAlgorithm where T: HashAlgorithm
    {
        private readonly MethodInfo _hashCore;
        private readonly MethodInfo _hashFinal;
        private readonly int _blockBytes;
        private readonly byte[] _rgbInner;
        private readonly byte[] _rgbOuter;
        private byte[] _keyValue = Array.Empty<byte>();
        private bool _hashing;

        protected readonly T Hash;

        public sealed override int HashSize => Hash.HashSize;

        public GenericHMAC(T hash, int blockBytes, byte[] rgbKey)
        {
            Hash = hash;
            _blockBytes = blockBytes;
            _rgbInner = new byte[blockBytes];
            _rgbOuter = new byte[blockBytes];
            Key = rgbKey;

            var typeMethods = Hash.GetType().GetRuntimeMethods()
                                   .Where(v => !v.IsPrivate && !v.IsPublic && v.IsVirtual && !v.IsStatic).ToArray();
            _hashCore = typeMethods.Single(v => v.Name == nameof(HashCore) && v.GetParameters().Length == 3);
            _hashFinal = typeMethods.Single(v => v.Name == nameof(HashFinal) && v.GetParameters().Length == 0);
        }

        public sealed override byte[] Key {
            get => (byte[]) _keyValue.Clone();
            set {
                if (_hashing) {
                    throw new InvalidOperationException("Cannot change key during hash operation");
                }

                if (value.Length > _blockBytes) {
                    _keyValue = Hash.ComputeHash(value);
                } else {
                    _keyValue = (byte[]) value.Clone();
                }

                for (var i = 0; i < _blockBytes; i++) {
                    _rgbInner[i] = 0x36;
                    _rgbOuter[i] = 0x5C;
                }

                for (var i = 0; i < _keyValue.Length; i++) {
                    _rgbInner[i] ^= _keyValue[i];
                    _rgbOuter[i] ^= _keyValue[i];
                }
            }
        }

        public sealed override void Initialize()
        {
            Hash.Initialize();
            _hashing = false;
        }

        protected virtual void AddHashData(byte[] rgb, int ib, int cb) => _hashCore.Invoke(Hash, new object[] {rgb, ib, cb});
        protected virtual byte[] FinalizeInnerHash() => (byte[]) _hashFinal.Invoke(Hash, Array.Empty<object>());
        
        private void EnsureStarted()
        {
            if (_hashing) return;
            AddHashData(_rgbInner, 0, _blockBytes);
            _hashing = true;
        }

        protected sealed override void HashCore(byte[] rgb, int ib, int cb)
        {
            EnsureStarted();
            AddHashData(rgb, ib, cb);
        }

        protected sealed override byte[] HashFinal()
        {
            EnsureStarted();
            var hashInner = FinalizeInnerHash();
            Hash.Initialize();
            AddHashData(_rgbOuter, 0, _blockBytes);
            AddHashData(hashInner, 0, hashInner.Length);
            _hashing = false;
            return FinalizeInnerHash();
        }

        protected override void Dispose(bool disposing)
        {
            if(disposing) Hash.Dispose();
            base.Dispose(disposing);
        }
    }
}