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
            
            // GC.AddMemoryPressure informs the runtime of a large allocation of unmanaged memory that should be 
            // taken into account when scheduling garbage collection.
            // 16 = length of the canary
            // 0x3FFF = 4 * dwPageSize (on Windows x64 dwPageSize is 0xFFF = 4096 bytes). 
            // Sodium rounds (length + dwPageSize) down to the nearest dwPageSize, and then adds 3 * dwPageSize extra. 
            // Thus (length + 16 + 0x3FFF) is initial amount to allocate and & ~(0xFFF) rounds down to the nearest dwPageSize
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