/*
    This file is part of the updater command line interface.
    Copyright (C) 2021, 2023  Dirk Stolle

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
    /// Contains tests for Transmission class.
    /// </summary>
    [TestClass]
    public class Transmission_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new Transmission(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var tm = new Transmission(false);
            Assert.IsTrue(tm.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new Transmission(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new Transmission(false));
        }


        /// <summary>
        /// Checks whether the regular expression for Transmission matches a
        /// typical version of Transmission.
        /// </summary>
        [TestMethod]
        public void Test_matchTest()
        {
            var tm = new Transmission(false);
            var info = tm.info();

            var re = new Regex(info.match64Bit);
            // match old style with one separator, v3.00 and earlier
            Assert.IsTrue(re.IsMatch("Transmission 3.00 (bb6b5a062e) (x64)"));
            // match new style with two separators, v4.0.0+
            Assert.IsTrue(re.IsMatch("Transmission 4.0.0 (280ace12f8) (x64)"));
            re = new Regex(info.match32Bit);
            // match old style with one separator, v3.00 and earlier
            Assert.IsTrue(re.IsMatch("Transmission 3.00 (bb6b5a062e)"));
            // match new style with two separators, v4.0.0+
            Assert.IsTrue(re.IsMatch("Transmission 4.0.0 (280ace12f8)"));
        }
    }
}
