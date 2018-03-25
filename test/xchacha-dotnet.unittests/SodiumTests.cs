using System;
using Xunit;

namespace xchacha_dotnet.unittests
{
    public class SodiumTests
    {
        [Fact]
        public void Test_SodiumInitialiszedSuccessfully()
        {
            Assert.True(Sodium.InitializedSuccessfully);
        }
    }
}
