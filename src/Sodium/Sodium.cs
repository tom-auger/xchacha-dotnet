namespace XChaChaDotNet
{
    using System.Security.Cryptography;
    using static SodiumInterop;

    internal static class Sodium
    {
        private static bool initialized;

        public static void Initialize()
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