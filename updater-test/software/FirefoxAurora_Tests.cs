/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2025  Dirk Stolle

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
using updater.versions;

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
            Assert.IsGreaterThan(50, items);
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

            var re = new Regex(info.match64Bit);
            // older naming convention
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition 53.0a2 (x64 de)"));
            // newer naming convention
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition 59.0 (x64 de)"));
            // next newer naming convention without version number
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition (x64 de)"));
            re = new Regex(info.match32Bit);
            // older naming convention
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition 53.0a2 (x86 de)"));
            // newer naming convention
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition 59.0 (x86 de)"));
            // next newer naming convention without version number
            Assert.IsTrue(re.IsMatch("Firefox Developer Edition (x86 de)"));
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
            var fx = new FirefoxAurora("de", false);
            Assert.IsNotNull(fx);
            if (!fx.implementsSearchForNewer())
            {
                Assert.Inconclusive("The check for up to date information was not performed, "
                    + "because this class indicates that it does not implement the searchForNewer() method.");
            }
            var info = fx.info();
            var newerInfo = fx.searchForNewer();
            Assert.IsNotNull(newerInfo, "searchForNewer() returned null!");
            int comp = string.Compare(info.newestVersion, newerInfo.newestVersion);
            var older = new QuartetAurora(info.newestVersion);
            var newer = new QuartetAurora(newerInfo.newestVersion);
            if (comp < 0 || older < newer)
            {
                Assert.Inconclusive(
                    "Known newest version of " + info.Name + " is " + info.newestVersion
                    + ", but the current newest version is " + newerInfo.newestVersion + "!");
            }
        }
    } // class
} // namespace
