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

using updater_cli.software;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace updater_test.software
{
    /// <summary>
    /// unit tests for software.All class
    /// </summary>
    [TestClass]
    public class All_Tests
    {
        /// <summary>
        /// checks whether All.get() returns some usable data
        /// </summary>
        [TestMethod]
        public void Test_get()
        {
            var result = All.get(false, true);
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Count > 0);
            for (int i = 0; i < result.Count; i++)
            {
                Assert.IsNotNull(result[i]);
            } //for
        }
    } //class
} //namespace
