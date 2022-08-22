/*
    This file is part of the updater command line interface.
    Copyright (C) 2021  Dirk Stolle

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
    /// Contains tests for the TreeSizeFree class.
    /// </summary>
    [TestClass]
    public class TreeSizeFree_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new TreeSizeFree(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var treeSize = new TreeSizeFree(false);
            Assert.IsTrue(treeSize.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new TreeSizeFree(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new TreeSizeFree(false));
        }

        /// <summary>
        /// Checks whether the regular expression for TreeSize Free matches a
        /// typical 64 bit version of it.
        /// </summary>
        [TestMethod]
        public void Test_matchTest_64bit()
        {
            var tsf = new TreeSizeFree(false);
            var info = tsf.info();

            var re = new Regex(info.match64Bit);
            // match old style, without bits
            Assert.IsTrue(re.IsMatch("TreeSize Free V4.5"));
            Assert.IsTrue(re.IsMatch("TreeSize Free V4.5.3"));
            // match new style, with bits
            Assert.IsTrue(re.IsMatch("TreeSize Free V4.6 (64 bit)"));
            Assert.IsTrue(re.IsMatch("TreeSize Free V4.6.2 (64 bit)"));
            // match new style, with bits after failed update
            Assert.IsTrue(re.IsMatch("TreeSize Free V4.6 (64 bit) (64 Bit)"));
            Assert.IsTrue(re.IsMatch("TreeSize Free V4.6.2 (64 bit) (64 Bit)"));
        }

        /// <summary>
        /// Checks whether the regular expression for TreeSize Free matches a
        /// typical 32 bit version of it.
        /// </summary>
        [TestMethod]
        public void Test_matchTest_32bit()
        {
            var tsf = new TreeSizeFree(false);
            var info = tsf.info();

            var re = new Regex(info.match32Bit);
            // match old style, without bits
            Assert.IsTrue(re.IsMatch("TreeSize Free V4.5"));
            Assert.IsTrue(re.IsMatch("TreeSize Free V4.5.3"));
        }
    }
}
