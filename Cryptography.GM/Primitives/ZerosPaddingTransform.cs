namespace System.Security.Cryptography.Primitives
{
    public sealed class ZerosPaddingTransform : ICryptoTransform
    {
        private readonly ICryptoTransform _blkCipher;
        private readonly bool _decrypt;

        public ZerosPaddingTransform(ICryptoTransform blkCipher, bool decrypt)
        {
            _blkCipher = blkCipher;
            _decrypt = decrypt;
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            => _blkCipher.TransformBlock(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (!_decrypt && inputCount % InputBlockSize != 0) {
                var paddingNeeded = InputBlockSize - inputCount % InputBlockSize;
                var padded = new byte[inputCount + paddingNeeded];
                Array.Copy(inputBuffer, inputOffset, padded, 0, inputCount);
                inputBuffer = padded;
                inputOffset = 0;
                inputCount += paddingNeeded;
            }

            return _blkCipher.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
        }

        public bool CanReuseTransform => _blkCipher.CanReuseTransform;
        public bool CanTransformMultipleBlocks => _blkCipher.CanTransformMultipleBlocks;
        public int InputBlockSize => _blkCipher.InputBlockSize;
        public int OutputBlockSize => _blkCipher.OutputBlockSize;
        public void Dispose() => _blkCipher.Dispose();
    }
}