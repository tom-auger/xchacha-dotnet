namespace XChaChaDotNet.UnitTests
{
    using System;
    using Xunit;

    public class SodiumTests
    {
        [Fact]
        public void Test_SodiumInitializedSuccessfully()
        {
            Assert.True(Sodium.InitializedSuccessfully);
        }
    }
}
