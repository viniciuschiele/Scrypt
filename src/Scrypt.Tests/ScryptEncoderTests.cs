using Scrypt;
using System;
using Xunit;

namespace Scrypt.Tests
{
    public class ScryptEncoderTests
    {
        [Fact]
        public void TestEncode()
        {
            int iterationCount = 2;

            for (int i = 0; i < 15; i++)
            {
                var encoder = new ScryptEncoder(iterationCount, 8, 1);
                var hashedPassword = encoder.Encode("MyPassword");
                Assert.True(encoder.Compare("MyPassword", hashedPassword));

                iterationCount *= 2;
            }
        }

        [Fact]
        public void TestCompare()
        {
            var encoder = new ScryptEncoder();
            var hashedPassword = encoder.Encode("MyPassword");
            Assert.True(encoder.Compare("MyPassword", hashedPassword));
            Assert.False(encoder.Compare("WrongPassword", hashedPassword));
        }

        [Fact]
        public void TestIsValid()
        {
            var encoder = new ScryptEncoder();
            Assert.False(encoder.IsValid("$e1$adasdasd$asdasdsd"));
            Assert.True(encoder.IsValid(encoder.Encode("MyPassword")));
        }

        [Fact]
        public void TestIterationCountNonPowerOfTwo()
        {
            var encoder = new ScryptEncoder(1000, 8, 1);
            Assert.Throws<ArgumentException>(() => encoder.Encode("MyPassword"));
        }

        [Fact]
        public void TestBackwardCompatibility()
        {
            var encoder = new ScryptEncoder();

            var hashedPassword = "$s0$40000801$eM1F+ITBb6SVFQ5QxD2jWXY8s4RGsIU+Yh4JosOewoY=$1h22/MY2cpm9Vz7//NRiXwCjffVXQWOKJ7n27vNVfP4=";
            Assert.True(encoder.Compare("MyPassword", hashedPassword));

            hashedPassword = "$s1$40000801$5ScyYcGbFmSF5P+A64cThg+c6rFtsfyxDHkWWCt97xI=$U+7EMhBXHjNHudmn/sgvX4VZ6ddoSKLkL0nDOSKYLaQ=";
            Assert.True(encoder.Compare("MyPassword", hashedPassword));
        }
    }
}