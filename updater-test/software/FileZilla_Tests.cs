/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2022  Dirk Stolle

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
using updater.data;
using updater.software;

namespace updater_test.software
{
    /// <summary>
    /// FileZilla class with custom version number
    /// </summary>
    class FzTest : FileZilla
    {
        public FzTest(bool autoNewer, string version)
            : base(autoNewer)
        {
            mVersion = version;
        }

        private readonly string mVersion;

        public override AvailableSoftware knownInfo()
        {
            // Use information of base class, ...
            var baseValue = base.knownInfo();
            // ... but inject different version number for tests.
            baseValue.newestVersion = mVersion;
            return baseValue;
        }
    } // class


    /// <summary>
    /// Contains tests for FileZilla class.
    /// </summary>
    [TestClass]
    public class FileZilla_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new FileZilla(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var fz = new FileZilla(false);
            Assert.IsTrue(fz.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new FileZilla(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new FileZilla(false));
        }


        /// <summary>
        /// Checks whether the regular expressions match usual software name / description.
        /// </summary>
        [TestMethod]
        public void Test_name_matches()
        {
            var fz = new FileZilla(false);

            var regEx32 = new Regex(fz.info().match32Bit, RegexOptions.IgnoreCase);
            var regEx64 = new Regex(fz.info().match64Bit, RegexOptions.IgnoreCase);

            // Test long name of earlier versions.
            Assert.IsTrue(regEx32.IsMatch("FileZilla Client 3.25.1"));
            Assert.IsTrue(regEx64.IsMatch("FileZilla Client 3.25.1"));
            // Test shortened name of version 3.60.0.
            Assert.IsTrue(regEx32.IsMatch("FileZilla 3.60.0"));
            Assert.IsTrue(regEx64.IsMatch("FileZilla 3.60.0"));
        }


        /// <summary>
        /// Checks whether the needsUpdate() method works as expected.
        /// </summary>
        [TestMethod]
        public void Test_needsUpdate()
        {
            var fz = new FileZilla(false);
            var det = new DetectedSoftware()
            {
                displayVersion = fz.knownInfo().newestVersion
            };
            // equal numbers does not need update
            Assert.IsFalse(fz.needsUpdate(det));

            // some older version numbers in ascending order
            string[] older = [ "3.0.0", "3.0.1", "3.0.2", "3.0.2.1",
                "3.2.8", "3.2.8.1", "3.3.0", "3.3.0.1", "3.3.1", "3.3.2",
                "3.3.2.1", "3.3.3",
                "3.9.0", "3.9.0.1", "3.9.0.2", "3.9.0.3", "3.9.0.4", "3.9.0.5", "3.9.0.6",
                "3.10.0", "3.10.0.1", "3.10.0.2", "3.10.1", "3.10.2", "3.10.3",
                "3.11.0", "3.11.0.1", "3.11.0.2", "3.12.0", "3.12.0.1", "3.12.0.2",
                "3.13.0" ];
            // older versions should always need update
            foreach (string version in older)
            {
                det.displayVersion = version;
                Assert.IsTrue(fz.needsUpdate(det));
            }

            // Only need update, if detected version is older than known version.
            for (int i = 0; i < older.Length; i++)
            {
                for (int j = 0; j < older.Length; j++)
                {
                    det.displayVersion = older[i];
                    fz = new FzTest(false, older[j]);
                    Assert.AreEqual<bool>(i < j, fz.needsUpdate(det),
                        "Failed check for i=" + i.ToString() + " and j=" + j.ToString() + "!"
                        + " v[i]=" + older[i] + ", v[j]=" + older[j] + ".");
                }
            }
        }
    } // class
} // namespace
