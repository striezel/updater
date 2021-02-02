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
using updater.data;
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// CMake class with custom version number
    /// </summary>
    class CmTest : CMake
    {
        public CmTest(bool autoNewer, string version)
            : base(autoNewer)
        {
            mVersion = version;
        }

        private readonly string mVersion;

        public override AvailableSoftware knownInfo()
        {
            // inject different version number for tests
            var baseValue = base.knownInfo();
            baseValue.newestVersion = mVersion;
            return baseValue;
        }
    } // class


    /// <summary>
    /// Contains tests for the CMake class.
    /// </summary>
    [TestClass]
    public class CMake_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new CMake(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var cm = new CMake(false);
            Assert.IsTrue(cm.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new CMake(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new CMake(false));
        }


        /// <summary>
        /// Checks whether the needsUpdate() method works as expected.
        /// </summary>
        [TestMethod]
        public void Test_needsUpdate()
        {
            string[] versions = { "1.0.1", "2.5.1", "2.8.9", "2.40.3", "3.2.1", "3.4.1", "3.19.3", "3.19.11" };

            var dect = new DetectedSoftware();

            for (int i = 0; i < versions.Length; i++)
            {
                for (int j = 0; j < versions.Length; j++)
                {
                    dect.displayVersion = versions[i];
                    var cm = new CmTest(false, versions[j]);
   
                    Assert.AreEqual<bool>(i < j, cm.needsUpdate(dect));
                }
            }
        }
    } // class
} // namespace