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
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// Contains tests for LibreOffice class.
    /// </summary>
    [TestClass]
    public class LibreOffice_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new LibreOffice(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var libO = new LibreOffice(false);
            Assert.IsTrue(libO.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new LibreOffice(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new LibreOffice(false));
        }


        /// <summary>
        /// Checks whether InstallInfoLibO is derived from InstallInfoMsi.
        /// (This is required for MSI handling in the Update class.)
        /// </summary>
        [TestMethod]
        public void Test_isInstallInfoMsi()
        {
            var libO = new LibreOffice(false);
            updater.data.InstallInfo inst = libO.knownInfo().install32Bit;
            Assert.IsTrue(inst is updater.data.InstallInfoLibO);
            Assert.IsTrue(inst is updater.data.InstallInfoMsi, "InstallInfoLibO is not derived from InstallInfoMsi!");
        }
    } // class
} // namespace
