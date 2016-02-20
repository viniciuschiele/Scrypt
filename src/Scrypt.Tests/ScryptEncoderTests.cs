using Scrypt;
using Xunit;

namespace Scrypt.Tests
{
    public class ScryptEncoderTests
    {
        [Fact]
        public void TestEncode()
        {
            var encoder = new ScryptEncoder();
            var hashedPassword = encoder.Encode("MyPassword");
            Assert.True(encoder.Compare("MyPassword", hashedPassword));
            Assert.False(encoder.Compare("WrongPassword", hashedPassword));
        }
    }
}