/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2020, 2022  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System.IO;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using updater.data;
using updater.utility;

namespace updater_test.utility
{
    /// <summary>
    /// Contains tests for the Checksum class.
    /// </summary>
    [TestClass]
    public class Checksum_Tests
    {
        /// <summary>
        /// Tests whether Checksum.areEqual() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_areEqual_positive()
        {
            var cases = new Dictionary<string, string>(3)
            {
                { "a61f9380255bb154f001cc15f27374ea30de1013", "a61f9380255bb154f001cc15f27374ea30de1013" },
                { "a61f 9380 255b b154 f001 cc15 f273 74ea 30de 1013", "a61f9380255bb154f001cc15f27374ea30de1013" },
                {
                    "6274E8CB 0358EF3E 3906A910 36BC8413 8A8FDE60 6A6E926B 9A580C79 F9CFC489",
                    "6274e8cb0358ef3e3906a91036bc84138a8fde606a6e926b9a580c79f9cfc489"
                }
            };

            foreach (var item in cases)
            {
                Assert.IsTrue(Checksum.areEqual(item.Key, item.Value));
            }
        }


        /// <summary>
        /// Tests whether Checksum.areEqual() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_areEqual_negative()
        {
            Assert.IsFalse(Checksum.areEqual(null, null));
            Assert.IsFalse(Checksum.areEqual("", ""));
            Assert.IsFalse(Checksum.areEqual("    ", "    "));

            Assert.IsFalse(Checksum.areEqual(null, "a61f9380255bb154f001cc15f27374ea30de1013"));
            Assert.IsFalse(Checksum.areEqual("a61f9380255bb154f001cc15f27374ea30de1013", null));

            Assert.IsFalse(Checksum.areEqual("a61f9380255bb154f001cc15f27374ea30de1013", 
                "6274e8cb0358ef3e3906a91036bc84138a8fde606a6e926b9a580c79f9cfc489"));
        }


        /// <summary>
        /// Tests whether Checksum.calculate() can calculate checksums.
        /// </summary>
        [TestMethod]
        public void Test_calculate_size_zero()
        {
            var cases = new Dictionary<HashAlgorithm, string>(5)
            {
                { HashAlgorithm.Unknown, null },
                { HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
                { HashAlgorithm.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                { HashAlgorithm.SHA384, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" },
                {
                    HashAlgorithm.SHA512,
                    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                }
            };

            // Create temporary file of zero bytes size.
            string fileName = Path.GetTempFileName();
            try
            {
                foreach (var item in cases)
                {
                    Assert.AreEqual<string>(item.Value, Checksum.calculate(fileName, item.Key));
                }
            }
            finally
            {
                // Always clean up.
                File.Delete(fileName);
            }
        }


        /// <summary>
        /// Tests whether Checksum.calculate() can calculate checksums.
        /// </summary>
        [TestMethod]
        public void Test_calculate_with_content()
        {
            var cases = new Dictionary<HashAlgorithm, string>(5)
            {
                { HashAlgorithm.Unknown, null },
                { HashAlgorithm.SHA1, "8843d7f92416211de9ebb963ff4ce28125932878" },
                { HashAlgorithm.SHA256, "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2" },
                { HashAlgorithm.SHA384, "3c9c30d9f665e74d515c842960d4a451c83a0125fd3de7392d7b37231af10c72ea58aedfcdf89a5765bf902af93ecf06" },
                {
                    HashAlgorithm.SHA512,
                    "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425"
                }
            };

            // Create temporary file of zero bytes size.
            string fileName = Path.GetTempFileName();
            byte[] data = new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }; // "foobar"
            File.WriteAllBytes(fileName, data);
            try
            {
                foreach (var item in cases)
                {
                    Assert.AreEqual<string>(item.Value, Checksum.calculate(fileName, item.Key));
                }
            }
            finally
            {
                // Always clean up.
                File.Delete(fileName);
            }
        }


        /// <summary>
        /// Tests whether Checksum.hashToString() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_hashToString()
        {
            Assert.AreEqual<string>("deadbeef", Checksum.hashToString(
                new byte[] { 0xde, 0xad, 0xbe, 0xef }));
            Assert.AreEqual<string>("a61f9380255bb154f001cc15f27374ea30de1013", Checksum.hashToString(
                new byte[] { 0xa6, 0x1f, 0x93, 0x80, 0x25, 0x5b, 0xb1, 0x54, 0xf0, 0x01, 0xcc, 0x15, 0xf2, 0x73, 0x74, 0xea, 0x30, 0xde, 0x10, 0x13 }));
        }


        /// <summary>
        /// Tests whether Checksum.hashToString() can handle null and empty parameters.
        /// </summary>
        [TestMethod]
        public void Test_hashToString_NullEmpty()
        {
            Assert.IsNull(Checksum.hashToString(null));
            Assert.IsNull(Checksum.hashToString(new byte[] { }));
        }


        /// <summary>
        /// Tests whether Checksum.normalise() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_normalise()
        {
            var cases = new Dictionary<string, string>(4)
            {
                { "a61f9380255bb154f001cc15f27374ea30de1013", "a61f9380255bb154f001cc15f27374ea30de1013" },
                { "a61f 9380 255b b154 f001 cc15 f273 74ea 30de 1013", "a61f9380255bb154f001cc15f27374ea30de1013" },
                {
                    "6274E8CB 0358EF3E 3906A910 36BC8413 8A8FDE60 6A6E926B 9A580C79 F9CFC489",
                    "6274e8cb0358ef3e3906a91036bc84138a8fde606a6e926b9a580c79f9cfc489"
                },
                { "   a61f   ghijklmnopqrstuvwxyz \t \\ / ", "a61f" }
            };

            foreach (var item in cases)
            {
                Assert.AreEqual<string>(item.Value, Checksum.normalise(item.Key));
            }
        }
    } // class
} // namespace
