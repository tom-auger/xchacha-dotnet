﻿namespace XChaChaDotNet.Benchmarks
{
    using BenchmarkDotNet.Running;
    using System;

    public class Program
    {
        static void Main(string[] args)
        {
            var switcher = new BenchmarkSwitcher(
                new[] 
                {
                    typeof(EncryptionStreamTest),
                    typeof(DecryptionStreamTest)
                });

            switcher.Run(args);
        }
    }
}
