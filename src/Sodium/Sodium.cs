namespace XChaChaDotNet
{
    using System;
    using System.Security.Cryptography;
    using static SodiumInterop;

    internal static class Sodium
    {
        [ThreadStatic]
        private static bool initialized;
        private static object lockObject = new object();

        public static void Initialize()
        {
            if (!initialized)
            {
                lock (lockObject)
                {
                    if (!initialized)
                    {
                        // sodium_init returns 0 on success, -1 on failure and 1 if it's already been initialized
                        if (sodium_init() < 0)
                        {
                            throw new CryptographicException("sodium initialization failed");
                        }

                        initialized = true;
                    }
                }
            }
        }
    }
}