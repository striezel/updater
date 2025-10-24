/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2024, 2025  Dirk Stolle

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
using updater.cli;
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// unit tests for software.All class
    /// </summary>
    [TestClass]
    public class All_Tests
    {
        /// <summary>
        /// Checks whether All.get() returns some usable data.
        /// </summary>
        [TestMethod]
        public void Test_get()
        {
            var opts = new Options
            {
                autoGetNewer = false,
                excluded = []
            };
            var result = All.get(opts);
            Assert.IsNotNull(result);
            Assert.IsNotEmpty(result);
            for (int i = 0; i < result.Count; i++)
            {
                Assert.IsNotNull(result[i]);
            }
        }


        /// <summary>
        /// Checks whether All.get() can handle null and empty exclusion lists.
        /// </summary>
        [TestMethod]
        public void Test_get_NullEmpty()
        {
            var opts = new Options
            {
                autoGetNewer = false,
                excluded = null
            };
            var result = All.get(opts);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Count > 0);

            opts.autoGetNewer = false;
            opts.excluded = [];
            var result2 = All.get(opts);
            Assert.IsNotNull(result2);
            Assert.IsTrue(result2.Count > 0);

            // count should be equal
            Assert.AreEqual<int>(result.Count, result2.Count);
        }


        /// <summary>
        /// Checks whether All.get() respects the exclusion list.
        /// </summary>
        [TestMethod]
        public void Test_get_WithExclusionList()
        {
            var opts = new Options
            {
                autoGetNewer = false,
                excluded = null
            };

            var result = All.get(opts);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Count > 0);


            var excluded = new List<string>()
            {
                new CCleaner(false).id()[0],
                new CDBurnerXP(false).id()[0],
                new Pidgin(false).id()[0]
            };
            opts.excluded = excluded;

            var result2 = All.get(opts);
            Assert.IsNotNull(result2);
            Assert.IsTrue(result2.Count > 0);

            // count should not be equal
            Assert.AreNotEqual<int>(result.Count, result2.Count);
            Assert.AreEqual<int>(result.Count - excluded.Count, result2.Count);
        }


        /// <summary>
        /// Checks that each software has at least one unique id.
        /// </summary>
        [TestMethod]
        public void Test_get_UniqueIds()
        {
            var opts = new Options
            {
                autoGetNewer = false,
                excluded = null
            };
            var result = All.get(opts);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Count > 0);

            HashSet<string> uniqueIds = new(result.Count);
            foreach (var software in result)
            {
                var ids = software.id();
                Assert.IsNotNull(ids);
                Assert.AreNotEqual(0, ids.Length);
                bool added = false;
                foreach (var id in ids)
                {
                    added |= uniqueIds.Add(id);
                }
                Assert.IsTrue(added, "The software " + software.info().Name + " has no unique id.");
            }
        }
    } // class
} // namespace
