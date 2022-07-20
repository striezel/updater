/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2021, 2022  Dirk Stolle

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
    /// Contains tests for the Thunderbird78 class.
    /// </summary>
    [TestClass]
    public class Thunderbird78_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks return value of the validLanguageCodes() method.
        /// </summary>
        [TestMethod]
        public void Test_validLanguageCodes()
        {
            var list = Thunderbird78.validLanguageCodes();
            Assert.IsNotNull(list);

            int items = 0;
            foreach (var item in list)
            {
                Assert.IsFalse(string.IsNullOrWhiteSpace(item));
                ++items;
            }
            Assert.IsTrue(items == 2);
        }


        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            var languages = Thunderbird78.validLanguageCodes();
            foreach (var languageCode in languages)
            {
                _info(new Thunderbird78(languageCode, false));
            }
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var tb = new Thunderbird78("fa", false);
            Assert.IsTrue(tb.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether the regular expression for Thunderbird matches a
        /// typical version of Thunderbird.
        /// </summary>
        [TestMethod]
        public void Test_matchTest_fa()
        {
            var tb = new Thunderbird78("fa", false);
            var info = tb.info();

            var re = new Regex(info.match64Bit);
            // match old style, including version number
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 45.7.0 (x64 fa)"));
            re = new Regex(info.match32Bit);
            // match old style, including version number
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 45.7.0 (x86 fa)"));
        }


        /// <summary>
        /// Checks whether the regular expression for Thunderbird matches a
        /// typical version of Thunderbird.
        /// </summary>
        [TestMethod]
        public void Test_matchTest_si()
        {
            var tb = new Thunderbird78("si", false);
            var info = tb.info();

            var re = new Regex(info.match64Bit);
            // match old style, including version number
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 45.7.0 (x64 si)"));
            re = new Regex(info.match32Bit);
            // match old style, including version number
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 45.7.0 (x86 si)"));
        }


        /// <summary>
        /// Checks whether the regular expression for Thunderbird also matches
        /// versions where the minor version has more than one digit.
        /// </summary>
        [TestMethod]
        public void Test_matchTest_twoDigitMinorVersion()
        {
            var tb = new Thunderbird78("fa", false);
            var info = tb.info();

            var re = new Regex(info.match64Bit);
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 78.13.0 (x64 fa)"));
            re = new Regex(info.match32Bit);
            Assert.IsTrue(re.IsMatch("Mozilla Thunderbird 78.13.0 (x86 fa)"));
        }
    } // class
} // namespace
