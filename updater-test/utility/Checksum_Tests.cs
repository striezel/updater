/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
    /// Zusammenfassungsbeschreibung für Checksum_Tests
    /// </summary>
    [TestClass]
    public class Checksum_Tests
    {
        /// <summary>
        /// tests whether Checksum.areEqual() works as expected
        /// </summary>
        [TestMethod]
        public void Test_areEqual_positive()
        {
            Dictionary<string, string> cases = new Dictionary<string, string>();
            cases.Add("a61f9380255bb154f001cc15f27374ea30de1013", "a61f9380255bb154f001cc15f27374ea30de1013");
            cases.Add("a61f 9380 255b b154 f001 cc15 f273 74ea 30de 1013", "a61f9380255bb154f001cc15f27374ea30de1013");
            cases.Add("6274E8CB 0358EF3E 3906A910 36BC8413 8A8FDE60 6A6E926B 9A580C79 F9CFC489",
                "6274e8cb0358ef3e3906a91036bc84138a8fde606a6e926b9a580c79f9cfc489");

            foreach (var item in cases)
            {
                Assert.IsTrue(Checksum.areEqual(item.Key, item.Value));
            }
        }


        /// <summary>
        /// tests whether Checksum.areEqual() works as expected
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
        /// tests whether Checksum.calculate() can calculate checksums
        /// </summary>
        [TestMethod]
        public void Test_calculate()
        {
            Dictionary<HashAlgorithm, string> cases = new Dictionary<HashAlgorithm, string>();
            cases.Add(HashAlgorithm.Unknown, null);
            cases.Add(HashAlgorithm.SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
            cases.Add(HashAlgorithm.SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            cases.Add(HashAlgorithm.SHA384, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
            cases.Add(HashAlgorithm.SHA512,
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

            //create temporary file of zero bytes size
            string fileName = Path.GetTempFileName();
            try
            {
                foreach (var item in cases)
                {
                    Assert.AreEqual<string>(item.Value, Checksum.calculate(fileName, item.Key));
                } //foreach                
            } //try-fin
            finally
            {
                //Always clean up.
                File.Delete(fileName);
            }
        }


        /// <summary>
        /// tests whether Checksum.hashToString() works as expected
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
        /// tests whether Checksum.hashToString() can handle null and empty parameters
        /// </summary>
        [TestMethod]
        public void Test_hashToString_NullEmpty()
        {
            Assert.IsNull(Checksum.hashToString(null));
            Assert.IsNull(Checksum.hashToString(new byte[] { }));
        }


        /// <summary>
        /// tests whether Checksum.normalise() works as expected
        /// </summary>
        [TestMethod]
        public void Test_normalise()
        {
            Dictionary<string, string> cases = new Dictionary<string, string>();
            cases.Add("a61f9380255bb154f001cc15f27374ea30de1013", "a61f9380255bb154f001cc15f27374ea30de1013");
            cases.Add("a61f 9380 255b b154 f001 cc15 f273 74ea 30de 1013", "a61f9380255bb154f001cc15f27374ea30de1013");
            cases.Add("6274E8CB 0358EF3E 3906A910 36BC8413 8A8FDE60 6A6E926B 9A580C79 F9CFC489",
                "6274e8cb0358ef3e3906a91036bc84138a8fde606a6e926b9a580c79f9cfc489");
            cases.Add("   a61f   ghijklmnopqrstuvwxyz \t \\ / ", "a61f");

            foreach (var item in cases)
            {
                Assert.AreEqual<string>(item.Value, Checksum.normalise(item.Key));
            }
        }
    } //class
} //namespace
