/*
    This file is part of the updater command line interface.
    Copyright (C) 2025  Dirk Stolle

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
    /// Contains tests for OpenJRE25 class.
    /// </summary>
    [TestClass]
    public class OpenJRE25_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new OpenJRE25(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var jre = new OpenJRE25(false);
            Assert.IsTrue(jre.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new OpenJRE25(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new OpenJRE25(false));
        }


        /// <summary>
        /// Checks whether the regular expression for the software name matches known names.
        /// </summary>
        [TestMethod]
        public void Test_regexMatches()
        {
            var info = new OpenJRE25(false).knownInfo();
            Assert.IsNotNull(info, "knownInfo() returned null!");
            var re64 = new Regex(info.match64Bit, RegexOptions.IgnoreCase);
            Assert.IsTrue(re64.IsMatch("Eclipse Temurin JRE with Hotspot 25+36 (x64)"), "English product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("Eclipse Temurin JRE avec Hotspot 25+36 (x64)"), "French product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("Eclipse Temurin JRE mit Hotspot 25+36 (x64)"), "German product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("Eclipse Temurin JRE con Hotspot 25+36 (x64)"), "Spanish product name (64-bit) does not match!");
        }
    } // class
} // namespace
