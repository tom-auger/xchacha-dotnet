namespace XChaChaDotNet
{
    using System;
    using System.Runtime.InteropServices;
    using static SodiumInterop;

    internal sealed class GuardedMemoryHandle : SafeHandle
    {
        private int length;

        private GuardedMemoryHandle()
            : base(invalidHandleValue: IntPtr.Zero, ownsHandle: true)
        {
        }

        public override bool IsInvalid => handle == IntPtr.Zero;

        public static void Alloc(int length, out GuardedMemoryHandle handle)
        {
            handle = sodium_malloc((UIntPtr)length);
            handle.length = length;
            GC.AddMemoryPressure((length + 16 + 0x3FFF) & ~0xFFF);
        }

        public void Write(ReadOnlySpan<byte> source)
        {
            var addedRef = false;
            try
            {
                DangerousAddRef(ref addedRef);
                source.CopyTo(DangerousGetSpan());
            }
            finally
            {
                if (addedRef)
                {
                    DangerousRelease();
                }
            }
        }

        public void MakeReadOnly()
        {
            sodium_mprotect_readonly(this);
        }

        protected override bool ReleaseHandle()
        {
            sodium_free(handle);
            GC.RemoveMemoryPressure((length + 16 + 0x3FFF) & ~0xFFF);
            return true;
        }

        public unsafe Span<byte> DangerousGetSpan()
        {
            return new Span<byte>(handle.ToPointer(), length);
        }
    }
}