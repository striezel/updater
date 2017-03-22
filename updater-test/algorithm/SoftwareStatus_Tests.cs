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

using System;
using updater_cli.operations;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace updater_test.algorithm
{
    /// <summary>
    /// unit tests for algorithm.SoftwareStatus class
    /// </summary>
    [TestClass]
    public class SoftwareStatus_Tests
    {
        /// <summary>
        /// checks whether algorithm.SoftwareStatus.query() returns something
        /// </summary>
        [TestMethod]
        public void Test_query()
        {
            var q = SoftwareStatus.query(false, false, null);
            Assert.IsNotNull(q);
            Assert.IsTrue(q.Count >= 0);

            foreach (var item in q)
            {
                Assert.IsNotNull(item.detected);
                Assert.IsNotNull(item.software);
                Assert.IsNotNull(item.needsUpdate);
            }
        }


        /// <summary>
        /// checks whether algorithm.SoftwareStatus.toConsoleOutput() works
        /// </summary>
        [TestMethod]
        public void Test_toConsoleOutput()
        {
            var q = SoftwareStatus.query(false, false, null);
            Assert.IsTrue(q.Count > 0);

            string data = SoftwareStatus.toConsoleOutput(q);
            Assert.IsNotNull(data);
            Assert.IsTrue(data.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries).Length > 5);
        }


        /// <summary>
        /// checks whether algorithm.SoftwareStatus.toConsoleOutput() can handle
        /// null and empty input
        /// </summary>
        [TestMethod]
        public void Test_toConsoleOutput_NullEmpty()
        {
            //null
            Assert.IsNull(SoftwareStatus.toConsoleOutput(null));
            //empty
            var data = SoftwareStatus.toConsoleOutput(new List<updater_cli.data.QueryEntry>());
            Assert.IsNotNull(data);
            Assert.AreEqual<int>(1, data.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries).Length);
        }


    } //class
} //namespace
