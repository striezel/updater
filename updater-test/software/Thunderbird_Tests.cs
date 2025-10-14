/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2021, 2022, 2025  Dirk Stolle

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
    /// Contains tests for the Thunderbird class.
    /// </summary>
    [TestClass]
    public class Thunderbird_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks return value of the validLanguageCodes() method.
        /// </summary>
        [TestMethod]
        public void Test_validLanguageCodes()
        {
            var list = Thunderbird.validLanguageCodes();
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
            var languages = Thunderbird.validLanguageCodes();
            foreach (var languageCode in languages)
            {
                _info(new Thunderbird(languageCode, false));
            }
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var tb = new Thunderbird("de", false);
            Assert.IsTrue(tb.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new Thunderbird("de", false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new Thunderbird("de", false));
        }


        /// <summary>
        /// Checks whether the regular expression for Thunderbird matches a
        /// typical version of Thunderbird.
        /// </summary>
        [TestMethod]
        public void Test_matchTest()
        {
            var tb = new Thunderbird("de", false);
            var info = tb.info();

            var re = new Regex(info.match64Bit);
            // match old style, including version number
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 45.7.0 (x64 de)"));
            // match old style, including version number, major and minor version only
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 45.7 (x64 de)"));
            // match new style, without version number
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird (x64 de)"));
            // match new ESR style (no version number)
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird ESR (x64 de)"));
            re = new Regex(info.match32Bit);
            // match old style, including version number
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 45.7.0 (x86 de)"));
            // match old style, including version number, major and minor version only
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 45.7 (x86 de)"));
            // match new style, without version number
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird (x86 de)"));
            // match new ESR style (no version number)
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird ESR (x86 de)"));
        }


        /// <summary>
        /// Checks whether the regular expression for Thunderbird also matches
        /// versions where the minor version has more than one digit.
        /// </summary>
        [TestMethod]
        public void Test_matchTest_twoDigitMinorVersion()
        {
            var fx = new Thunderbird("de", false);
            var info = fx.info();

            var re = new Regex(info.match64Bit);
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 78.13.0 (x64 de)"));
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 78.13 (x64 de)"));
            re = new Regex(info.match32Bit);
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 78.13.0 (x86 de)"));
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 78.13 (x86 de)"));
        }
    } // class
} // namespace
