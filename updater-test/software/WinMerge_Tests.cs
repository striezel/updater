/*
    This file is part of the updater command line interface.
    Copyright (C) 2024, 2025  Dirk Stolle

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
    /// Contains tests for the WinMerge class.
    /// </summary>
    [TestClass]
    public class WinMerge_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new WinMerge(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var w = new WinMerge(false);
            Assert.IsTrue(w.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new WinMerge(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new WinMerge(false));
        }


        /// <summary>
        /// Checks whether the regular expression for the software name matches known names.
        /// </summary>
        [TestMethod]
        public void Test_regexMatches()
        {
            var info = new WinMerge(false).knownInfo();
            Assert.IsNotNull(info, "knownInfo() returned null!");

            var re64 = new Regex(info.match64Bit, RegexOptions.IgnoreCase);
            // Match old WinMerge product names including version number.
            Assert.IsTrue(re64.IsMatch("WinMerge 2.16.48.0 x64"), "Old product name (64-bit) does not match!");
            Assert.IsTrue(re64.IsMatch("WinMerge 2.16.48.2 x64"), "Old product name (64-bit) does not match!");
            // Match new WinMerge product name without version number (since version 2.16.50.0).
            Assert.IsTrue(re64.IsMatch("WinMerge x64"), "New product name (64-bit) does not match!");

            var re32 = new Regex(info.match32Bit, RegexOptions.IgnoreCase);
            // Match old WinMerge product names including version number.
            Assert.IsTrue(re32.IsMatch("WinMerge 2.16.48.2"), "Old product name (32-bit) does not match!");
            // Product name pattern for 32-bit version has not changed.
            Assert.IsTrue(re32.IsMatch("WinMerge 2.16.50.0"), "'New' product name (32-bit) does not match!");
        }
    } // class
} // namespace
