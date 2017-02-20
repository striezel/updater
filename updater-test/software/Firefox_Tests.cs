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
using System.Text.RegularExpressions;
using updater_cli.software;

namespace updater_test.software
{
    [TestClass]
    public class Firefox_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// checks return value of the validLanguageCodes() method
        /// </summary>
        [TestMethod]
        public void Test_validLanguageCodes()
        {
            var list = Firefox.validLanguageCodes();
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
        /// checks whether info() returns some meaningful data
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new Firefox("de"));
        }


        /// <summary>
        /// checks whether the class implements the searchForNewer() method
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var fx = new Firefox("de");
            Assert.IsTrue(fx.implementsSearchForNewer());
        }


        [TestMethod]
        public void Test_matchTest()
        {
            var fx = new Firefox("de");
            var info = fx.info();

            //versions with three number
            Regex re = new Regex(info.match64Bit);
            Assert.IsTrue(re.IsMatch("Mozilla Firefox 51.0.1 (x64 de)"));
            re = new Regex(info.match32Bit);
            Assert.IsTrue(re.IsMatch("Mozilla Firefox 51.0.1 (x86 de)"));
            //versions with two numbers
            re = new Regex(info.match64Bit);
            Assert.IsTrue(re.IsMatch("Mozilla Firefox 50.0 (x64 de)"));
            re = new Regex(info.match32Bit);
            Assert.IsTrue(re.IsMatch("Mozilla Firefox 50.0 (x86 de)"));
        }


        /// <summary>
        /// checks whether searchForNewer() returns something
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new Firefox("de"));
        }


        /// <summary>
        /// checks whether the class info is up to date
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new Firefox("de"));
        }
    } //class
} //namespace
