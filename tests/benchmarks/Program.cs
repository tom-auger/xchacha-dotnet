namespace XChaChaDotNet.Benchmarks
{
    using BenchmarkDotNet.Running;
    using System;

    public class Program
    {
        static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<EncryptionStreamTest>();
        }
    }
}
