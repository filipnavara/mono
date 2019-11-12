using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using System;

namespace BenchmarkApp
{
    class Program
    {
        static void Main(string[] args) => BenchmarkRunner.Run<Perf_Array>();
    }

    [InProcess]
    public class Perf_Array
    {
        [Benchmark]
        public Array ArrayCreate1D() => Array.CreateInstance(typeof(int), 4096 * 4096);

        [Benchmark]
        public Array ArrayCreate2D() => Array.CreateInstance(typeof(int), 4096, 4096);
    }
}
