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
using System;
using updater.cli;
using updater.operations;

namespace updater_test.algorithm
{
    /// <summary>
    /// unit tests for operations.SoftwareStatus class
    /// </summary>
    [TestClass]
    public class SoftwareStatus_Tests
    {
        /// <summary>
        /// Checks whether operations.SoftwareStatus.query() returns something.
        /// </summary>
        [TestMethod]
        public void Test_query()
        {
            var opts = new Options()
            {
                excluded = null,
                autoGetNewer = false
            };
            var q = SoftwareStatus.query(opts);
            Assert.IsNotNull(q);
            Assert.IsGreaterThanOrEqualTo(0, q.Count);

            foreach (var item in q)
            {
                Assert.IsNotNull(item.detected);
                Assert.IsNotNull(item.software);
                Assert.IsNotNull(item.needsUpdate);
            }
        }


        /// <summary>
        /// Checks whether operations.SoftwareStatus.toConsoleOutput() works.
        /// </summary>
        [TestMethod]
        public void Test_toConsoleOutput()
        {
            var opts = new Options()
            {
                excluded = null,
                autoGetNewer = false
            };
            var q = SoftwareStatus.query(opts);
            Assert.IsNotEmpty(q);

            string data = SoftwareStatus.toConsoleOutput(q);
            Assert.IsNotNull(data);
            Assert.IsGreaterThan(5, data.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries).Length);
        }


        /// <summary>
        /// Checks whether operations.SoftwareStatus.toConsoleOutput() can handle
        /// null and empty input.
        /// </summary>
        [TestMethod]
        public void Test_toConsoleOutput_NullEmpty()
        {
            // null
            Assert.IsNull(SoftwareStatus.toConsoleOutput(null));
            // empty
            var data = SoftwareStatus.toConsoleOutput([]);
            Assert.IsNotNull(data);
            Assert.AreEqual<int>(1, data.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries).Length);
        }

    } // class
} // namespace
