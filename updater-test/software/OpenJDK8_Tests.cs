/*
    This file is part of the updater command line interface.
    Copyright (C) 2021  Dirk Stolle

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


using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text.RegularExpressions;
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// Contains tests for OpenJDK8 class.
    /// </summary>
    [TestClass]
    public class OpenJDK8_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new OpenJDK8(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var jdk = new OpenJDK8(false);
            Assert.IsTrue(jdk.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new OpenJDK8(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new OpenJDK8(false));
        }


        /// <summary>
        /// Checks whether the regular expression for the software name matches known names.
        /// </summary>
        [TestMethod]
        public void Test_regexMatches()
        {
            var info = new OpenJDK8(false).knownInfo();
            Assert.IsNotNull(info, "knownInfo() returned null!");

            var re64 = new Regex(info.match64Bit, RegexOptions.IgnoreCase);
            // Match old AdoptOpenJDK product names.
            Assert.IsTrue(re64.IsMatch("AdoptOpenJDK JDK with Hotspot 8u282-b08 (x64)"), "English product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("AdoptOpenJDK JDK avec Hotspot 8u282-b08 (x64)"), "French product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("AdoptOpenJDK JDK mit Hotspot 8u282-b08 (x64)"), "German product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("AdoptOpenJDK JDK con Hotspot 8u282-b08 (x64)"), "Spanish product name (64-bit) does not match!");
            // Match new Eclipse Temurin product names.
            Assert.IsTrue(re64.IsMatch("Eclipse Temurin JDK with Hotspot 8u302-b08 (x64)"), "English product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("Eclipse Temurin JDK avec Hotspot 8u302-b08 (x64)"), "French product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("Eclipse Temurin JDK mit Hotspot 8u302-b08 (x64)"), "German product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("Eclipse Temurin JDK con Hotspot 8u302-b08 (x64)"), "Spanish product name (64-bit) does not match!");

            var re32 = new Regex(info.match32Bit, RegexOptions.IgnoreCase);
            // Match old AdoptOpenJDK product names.
            Assert.IsTrue(re32.IsMatch("AdoptOpenJDK JDK with Hotspot 8u292-b10 (x86)"), "English product name (32-bit) does not match!");
            Assert.IsTrue(re32.IsMatch("AdoptOpenJDK JDK avec Hotspot 8u292-b10 (x86)"), "French product name (32-bit) does not match!");
            Assert.IsTrue(re32.IsMatch("AdoptOpenJDK JDK mit Hotspot 8u292-b10 (x86)"), "German product name (32-bit) does not match!");
            Assert.IsTrue(re32.IsMatch("AdoptOpenJDK JDK con Hotspot 8u292-b10 (x86)"), "Spanish product name (32-bit) does not match!");
            // Match new Eclipse Temurin product names.
            Assert.IsTrue(re32.IsMatch("Eclipse Temurin JDK with Hotspot 8u302-b08 (x86)"), "English product name (32-bit) does not match!");
            Assert.IsTrue(re32.IsMatch("Eclipse Temurin JDK avec Hotspot 8u302-b08 (x86)"), "French product name (32-bit) does not match!");
            Assert.IsTrue(re32.IsMatch("Eclipse Temurin JDK mit Hotspot 8u302-b08 (x86)"), "German product name (32-bit) does not match!");
            Assert.IsTrue(re32.IsMatch("Eclipse Temurin JDK con Hotspot 8u302-b08 (x86)"), "Spanish product name (32-bit) does not match!");
        }
    } // class
} // namespace
