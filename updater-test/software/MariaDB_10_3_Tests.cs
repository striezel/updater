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
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// Contains tests for MariaDB_10_3.
    /// </summary>
    [TestClass]
    public class MariaDB_10_3_Tests: BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            var sw = new MariaDB_10_3(false);
            Assert.IsNotNull(sw);
            var info = sw.info();
            Assert.IsNotNull(info);
            // name must be set
            Assert.IsFalse(string.IsNullOrWhiteSpace(info.Name));
            // 64 bit installation information instance should be present
            Assert.IsTrue(info.install64Bit != null);
            // regex should be present
            Assert.IsTrue(!string.IsNullOrWhiteSpace(info.match64Bit));
            // 64 bit information should match
            Assert.AreEqual<bool>(info.install64Bit != null, !string.IsNullOrWhiteSpace(info.match64Bit));
            // checksums should always be present, or at least a signature for verification
            Assert.IsTrue(info.install64Bit.hasChecksum() || info.install64Bit.hasVerifiableSignature());
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var mdb = new MariaDB_10_3(false);
            Assert.IsTrue(mdb.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new MariaDB_10_3(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new MariaDB_10_3(false));
        }
    }
}
