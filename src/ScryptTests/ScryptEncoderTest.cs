using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Scrypt;

namespace ScryptTests
{
    [TestClass]
    public class ScryptEncoderTest
    {
        [TestMethod]
        public void TestEncode()
        {
            var encoder = new ScryptEncoder();
            var hashedPassword = encoder.Encode("MyPassword");
            Assert.IsTrue(encoder.Compare("MyPassword", hashedPassword));
            Assert.IsFalse(encoder.Compare("WrongPassword", hashedPassword));
        }
    }
}