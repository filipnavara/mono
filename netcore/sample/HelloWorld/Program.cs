using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace HelloWorld
{
    class Program
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        public static unsafe void ComputeHash32(ref byte data)
        {
            for (int i=0; i<1; i++)
                data = ref Unsafe.Add(ref data, 1);
            // or:
            // data = ref Unsafe.AddByteOffset(ref data, (IntPtr)1);
        }

        static void Main(string[] args)
        {
            byte[] a = new byte[100];
            ComputeHash32(ref a[0]);
        }
    }
}
