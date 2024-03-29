﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2022  Dirk Stolle

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
    /// Contains tests for Mumble class.
    /// </summary>
    [TestClass]
    public class Mumble_Tests : BasicSoftwareTests
    {

        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new Mumble(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var m = new Mumble(false);
            Assert.IsTrue(m.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new Mumble(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new Mumble(false));
        }


        /// <summary>
        /// Checks whether the regular expression for the software name matches known names.
        /// </summary>
        [TestMethod]
        public void Test_regexMatches()
        {
            var info = new Mumble(false).knownInfo();
            Assert.IsNotNull(info, "knownInfo() returned null!");

            var re64 = new Regex(info.match64Bit, RegexOptions.IgnoreCase);
            // Match old pre-1.4.0 product names.
            Assert.IsTrue(re64.IsMatch("Mumble 1.3.4"));
            Assert.IsTrue(re64.IsMatch("Mumble 1.3.3"));
            Assert.IsTrue(re64.IsMatch("Mumble 1.3.2"));
            Assert.IsTrue(re64.IsMatch("Mumble 1.3.1"));
            Assert.IsTrue(re64.IsMatch("Mumble 1.3.0"));
            // Match new post-1.4.0 name.
            Assert.IsTrue(re64.IsMatch("Mumble (client)"));

            var re32 = new Regex(info.match32Bit, RegexOptions.IgnoreCase);
            // Match old pre-1.4.0 product names.
            Assert.IsTrue(re32.IsMatch("Mumble 1.3.4"));
            Assert.IsTrue(re32.IsMatch("Mumble 1.3.3"));
            Assert.IsTrue(re32.IsMatch("Mumble 1.3.2"));
            Assert.IsTrue(re32.IsMatch("Mumble 1.3.1"));
            Assert.IsTrue(re32.IsMatch("Mumble 1.3.0"));
            Assert.IsTrue(re32.IsMatch("Mumble 1.2.16"));
            Assert.IsTrue(re32.IsMatch("Mumble 1.1.8"));
            // Match new post-1.4.0 name.
            Assert.IsTrue(re32.IsMatch("Mumble (client)"));
        }
    } // class
} // namespace
