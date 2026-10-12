/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2026  Dirk Stolle

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
    /// Contains unit tests for the LibreOfficeHelpPackGerman class.
    /// </summary>
    [TestClass]
    public class LibreOfficeHelpPackGerman_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new LibreOfficeHelpPackGerman(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var libO = new LibreOfficeHelpPackGerman(false);
            Assert.IsTrue(libO.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new LibreOfficeHelpPackGerman(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new LibreOfficeHelpPackGerman(false));
        }


        /// <summary>
        /// Checks whether the regular expression for the software name matches known names.
        /// </summary>
        [TestMethod]
        public void Test_regexMatches()
        {
            var info = new LibreOfficeHelpPackGerman(false).knownInfo();
            Assert.IsNotNull(info, "knownInfo() returned null!");

            var re64 = new Regex(info.match64Bit, RegexOptions.IgnoreCase);
            var re32 = new Regex(info.match32Bit, RegexOptions.IgnoreCase);
            // Match old product name with parenthesis and without semicolon.
            Assert.IsTrue(re64.IsMatch("LibreOffice 26.2 Help Pack (German)"), "Old product name (64-bit) does not match!");
            Assert.IsTrue(re32.IsMatch("LibreOffice 26.2 Help Pack (German)"), "Old product name (32-bit) does not match!");
            // Match new product name with semicolon.
            Assert.IsTrue(re64.IsMatch("LibreOffice 26.8 Help Pack: German"), "New product name (64-bit) does not match!");
            Assert.IsTrue(re32.IsMatch("LibreOffice 26.8 Help Pack: German"), "New product name (32-bit) does not match!");
        }
    } // class
} // namespace
