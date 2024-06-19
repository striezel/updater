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
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// Contains tests for the NotepadPlusPlus class.
    /// </summary>
    [TestClass]
    public class NotepadPlusPlus_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new NotepadPlusPlus(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var npp = new NotepadPlusPlus(false);
            Assert.IsTrue(npp.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new NotepadPlusPlus(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new NotepadPlusPlus(false));
        }


        /// <summary>
        /// Checks whether the regular expression for 32-bit variant detects old
        /// and new variants.
        /// </summary>
        [TestMethod]
        public void Test_match32Bit()
        {
            var npp = new NotepadPlusPlus(false);
            var regex = new Regex(npp.knownInfo().match32Bit);
            // new variant (after introduction of 64-bit variant)
            Assert.IsTrue(regex.IsMatch("Notepad++ (32-bit x86)"));
            // old variant (before introduction of 64-bit variant)
            Assert.IsTrue(regex.IsMatch("Notepad++"), "The regular expression does not detect the old variant of 32-bit Notepad++.");
        }
    } // class
} // namespace