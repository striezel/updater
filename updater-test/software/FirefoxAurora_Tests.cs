/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
    /// Contains tests for the FirefoxAurora class.
    /// </summary>
    [TestClass]
    public class FirefoxAurora_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks return value of the validLanguageCodes() method.
        /// </summary>
        [TestMethod]
        public void Test_validLanguageCodes()
        {
            var list = FirefoxAurora.validLanguageCodes();
            Assert.IsNotNull(list);

            int items = 0;
            foreach (var item in list)
            {
                Assert.IsFalse(string.IsNullOrWhiteSpace(item));
                ++items;
            }
            Assert.IsTrue(items > 50);
        }


        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new FirefoxAurora("de", false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var fx = new FirefoxAurora("de", false);
            Assert.IsTrue(fx.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether the regular expressions match both old and newer
        /// naming conventions of the software.
        /// </summary>
        [TestMethod]
        public void Test_matchTest()
        {
            var fx = new FirefoxAurora("de", false);
            var info = fx.info();

            Regex re = new Regex(info.match64Bit);
            // older naming convention
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition 53.0a2 (x64 de)"));
            // newer naming convention
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition 59.0 (x64 de)"));
            re = new Regex(info.match32Bit);
            // older naming convention
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition 53.0a2 (x86 de)"));
            // newer naming convention
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition 59.0 (x86 de)"));
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new FirefoxAurora("de", false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new FirefoxAurora("de", false));
        }
        
    } // class
} // namespace
