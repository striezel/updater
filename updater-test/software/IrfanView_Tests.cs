/*
    This file is part of the updater command line interface.
    Copyright (C) 2022  Dirk Stolle

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
    /// Contains tests for the IrfanView class.
    /// </summary>
    [TestClass]
    public class IrfanView_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
           _info(new IrfanView(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var iv = new IrfanView(false);
            Assert.IsTrue(iv.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new IrfanView(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new IrfanView(false));
        }


        /// <summary>
        /// Checks whether the regular expression for IrfanView matches a
        /// typical version of IrfanView.
        /// </summary>
        [TestMethod]
        public void Test_matchTest()
        {
            var iv = new IrfanView(false);
            var info = iv.info();

            var re = new Regex(info.match64Bit);
            // match old style
            Assert.IsTrue(re.IsMatch("IrfanView 64 (remove only)"));
            // match new style
            Assert.IsTrue(re.IsMatch("IrfanView 4.60 (64-bit)"));
            re = new Regex(info.match32Bit);
            // match old style
            Assert.IsTrue(re.IsMatch("IrfanView (remove only)"));
            // match new style, without version number
            Assert.IsTrue(re.IsMatch("IrfanView 4.60 (32-bit)"));
        }
    } // class
} // namespace
