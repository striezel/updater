/*
    This file is part of the updater command line interface.
    Copyright (C) 2024  Dirk Stolle

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
using System.Collections.Generic;
using updater.data;
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// Contains tests for classes derived from MariaDB_Base.
    /// </summary>
    [TestClass]
    public class MariaDB_Base_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether MariaDB 10.3 release still uses the old certificate data.
        /// </summary>
        [TestMethod]
        public void Test_certificate_10_3()
        {
            var mdb_10_3 = new MariaDB_10_3(false);
            var signature = mdb_10_3.knownInfo().install64Bit.signature;
            Assert.IsTrue(signature.ContainsData());
            Assert.IsTrue(signature.publisher.Contains("MariaDB Corporation Ab"));
            Assert.IsTrue(signature.publisher.Contains("Espoo"));
            Assert.IsTrue(signature.HasExpired());
        }


        /// <summary>
        /// Checks whether MariaDB 10.4 release still uses the old certificate data.
        /// </summary>
        [TestMethod]
        public void Test_certificate_10_4()
        {
            var mdb_10_4 = new MariaDB_10_4(false);
            var signature = mdb_10_4.knownInfo().install64Bit.signature;
            Assert.IsTrue(signature.ContainsData());
            Assert.IsTrue(signature.publisher.Contains("MariaDB USA, Inc."));
            Assert.IsTrue(signature.publisher.Contains("Redwood City"));
            Assert.IsFalse(signature.HasExpired()); // Note: Change to IsTrue() after 2026-03-21.
        }


        /// <summary>
        /// Checks whether MariaDB 10.5 and newer releases use the current certificate data.
        /// </summary>
        [TestMethod]
        public void Test_certificates_newer()
        {
            var signatures = new List<Signature>
            {
                new MariaDB_10_5(false).knownInfo().install64Bit.signature,
                new MariaDB_10_6(false).knownInfo().install64Bit.signature,
                new MariaDB_10_11(false).knownInfo().install64Bit.signature,
                new MariaDB_11_4(false).knownInfo().install64Bit.signature
            };

            foreach (var signature in signatures)
            {
                Assert.IsTrue(signature.ContainsData());
                Assert.IsTrue(signature.publisher.Contains("MariaDB USA, Inc."));
                Assert.IsTrue(signature.publisher.Contains("Redwood City"));
                Assert.IsTrue(signature.expiresAt > new System.DateTime(2024, 2, 1, 0, 0, 0, System.DateTimeKind.Utc));
            }
        }


        /// <summary>
        /// Checks whether end of support dates are in the same order as releases.
        /// </summary>
        [TestMethod]
        public void Test_EndOfLife()
        {
            var mdb_10_3 = new MariaDB_10_3(false);
            var mdb_10_4 = new MariaDB_10_4(false);
            var mdb_10_5 = new MariaDB_10_5(false);
            var mdb_10_6 = new MariaDB_10_6(false);
            var mdb_10_11 = new MariaDB_10_11(false);
            var mdb_11_4 = new MariaDB_11_4(false);

            Assert.IsTrue(mdb_10_3.EndOfLife() < mdb_10_4.EndOfLife());
            Assert.IsTrue(mdb_10_4.EndOfLife() < mdb_10_5.EndOfLife());
            Assert.IsTrue(mdb_10_5.EndOfLife() < mdb_10_6.EndOfLife());
            Assert.IsTrue(mdb_10_6.EndOfLife() < mdb_10_11.EndOfLife());
            Assert.IsTrue(mdb_10_11.EndOfLife() < mdb_11_4.EndOfLife());
        }
    }
}
