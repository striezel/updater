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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using updater.data;
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// Contains tests for the SeaMonkey class.
    /// </summary>
    [TestClass]
    public class SeaMonkey_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks return value of the validLanguageCodes() method.
        /// </summary>
        [TestMethod]
        public void Test_validLanguageCodes()
        {
            var list = SeaMonkey.validLanguageCodes();
            Assert.IsNotNull(list);

            int items = 0;
            foreach (var item in list)
            {
                Assert.IsFalse(string.IsNullOrWhiteSpace(item));
                ++items;
            }
            Assert.IsGreaterThan(15, items);
        }


        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new SeaMonkey("de", false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var sm = new SeaMonkey("de", false);
            Assert.IsTrue(sm.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new SeaMonkey("de", false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new SeaMonkey("de", false));
        }


        /// <summary>
        /// Checks whether the needsUpdate() method works as expected.
        /// </summary>
        [TestMethod]
        public void Test_needsUpdate()
        {
            string[] versions = ["1.0.1", "2.5", "2.9", "2.40"];

            var sm = new SeaMonkey("de", false);
            var dect = new DetectedSoftware();
            foreach (var item in versions)
            {
                dect.displayVersion = item;
                Assert.IsTrue(sm.needsUpdate(dect));
            }
        }
    } // class
} // namespace
