namespace xchacha_dotnet
{    
    public static class Sodium
    {
        // sodium_init returns 0 on success, -1 on failure and 1 if it's already been initialized
        public static bool InitializedSuccessfully = 
            SodiumInterop.sodium_init() >= 0;
    }
}