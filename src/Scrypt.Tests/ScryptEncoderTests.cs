using System;
using System.Text;
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

        [Theory]
        [InlineData("$s0$40000801$eM1F+ITBb6SVFQ5QxD2jWXY8s4RGsIU+Yh4JosOewoY=$1h22/MY2cpm9Vz7//NRiXwCjffVXQWOKJ7n27vNVfP4=")]
        [InlineData("$s1$40000801$5ScyYcGbFmSF5P+A64cThg+c6rFtsfyxDHkWWCt97xI=$U+7EMhBXHjNHudmn/sgvX4VZ6ddoSKLkL0nDOSKYLaQ=")]
        [InlineData("$s2$16384$8$1$pKHZk7yiyj5l4UaW1lMDBkj6Q0+Fw/Nyqx9r+sgM9PE=$JuhWa5STBbHuPbOJjcxSV8WDxSH5hQsPlW9nTNce/sc=")]
        public void TestVersionsForBackwardCompatibility(string hashedPassword)
        {
            var encoder = new ScryptEncoder();
            Assert.True(encoder.Compare("MyPassword", hashedPassword));
        }

        [Theory]
        [InlineData("", "", 16, 1, 1, 64, "77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97 f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42 fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17 e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06")]
        [InlineData("password", "NaCl", 1024, 8, 16, 64, "fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe 7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62 2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40")]
        [InlineData("pleaseletmein", "SodiumChloride", 16384, 8, 1, 64, "70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2 d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9 e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87")]
        [InlineData("pleaseletmein", "SodiumChloride", 1048576, 8, 1, 64, "21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81 ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47 8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3 37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4")]
        public void TestVectorsForCryptoScrypt(string password, string salt, int N, int r, int p, int dklen, string expected)
        {
            // These test vectors are taken from RFC 7914: https://datatracker.ietf.org/doc/html/rfc7914#section-12

            var P = Encoding.UTF8.GetBytes(password);
            var S = Encoding.UTF8.GetBytes(salt);

            var actualBytes = ScryptEncoder.CryptoScrypt(P, S, N, r, p, dklen);
            var actualString = BitConverter.ToString(actualBytes).Replace("-", " ");

            Assert.Equal(expected, actualString, ignoreCase: true);
        }
    }
}