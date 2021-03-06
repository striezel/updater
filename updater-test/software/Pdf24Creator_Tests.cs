﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2020  Dirk Stolle

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
using updater.software;
using updater.versions;

namespace updater_test.software
{
    /// <summary>
    /// Contains tests for the Pdf24Creator class.
    /// </summary>
    [TestClass]
    public class Pdf24Creator_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new Pdf24Creator(false, false, false, false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var p24c = new Pdf24Creator(false, false, false, false);
            Assert.IsTrue(p24c.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new Pdf24Creator(false, false, false, false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            var sw = new Pdf24Creator(false, false, false, false);
            Assert.IsNotNull(sw);
            var info = sw.info();
            var newerInfo = sw.searchForNewer();
            Assert.IsNotNull(newerInfo, "searchForNewer() returned null!");
            var known = new Triple(info.newestVersion);
            var newest = new Triple(newerInfo.newestVersion);
            if (known < newest)
            {
                Assert.Inconclusive(
                    "Known newest version of " + info.Name + " is " + info.newestVersion
                    + ", but the current newest version is " + newerInfo.newestVersion + "!");
            }
        }

    } // class
} // namespace
