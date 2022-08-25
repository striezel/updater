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
using updater.data;
using updater.software;
using updater.versions;

namespace updater_test.software
{
    /// <summary>
    /// HeidiSQL class with custom version number
    /// </summary>
    class HeidiVersionTest : HeidiSQL
    {
        public HeidiVersionTest(bool autoNewer, string version)
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
    /// Contains tests for the HeidiSQL class.
    /// </summary>
    [TestClass]
    public class HeidiSQL_Tests : BasicSoftwareTests
    {
        /// <summary>
        /// Checks whether info() returns some meaningful data.
        /// </summary>
        [TestMethod]
        public void Test_info()
        {
            _info(new HeidiSQL(false));
        }


        /// <summary>
        /// Checks whether the class implements the searchForNewer() method.
        /// </summary>
        [TestMethod]
        public void Test_implementsSearchForNewer()
        {
            var heidi = new HeidiSQL(false);
            Assert.IsTrue(heidi.implementsSearchForNewer());
        }


        /// <summary>
        /// Checks whether searchForNewer() returns something.
        /// </summary>
        [TestMethod]
        public void Test_searchForNewer()
        {
            _searchForNewer(new HeidiSQL(false));
        }


        /// <summary>
        /// Checks whether the class info is up to date.
        /// </summary>
        [TestMethod]
        public void Test_upToDate_info()
        {
            _upToDate_info(new HeidiSQL(false));
        }


        /// <summary>
        /// Checks whether the needsUpdate() method works as expected.
        /// </summary>
        [TestMethod]
        public void Test_needsUpdate_same_version()
        {
            var heidi = new HeidiSQL(false);
            var det = new DetectedSoftware()
            {
                displayVersion = heidi.knownInfo().newestVersion
            };
            // equal numbers does not need update
            Assert.IsFalse(heidi.needsUpdate(det));
        }


        /// <summary>
        /// Checks whether the needsUpdate() method works as expected.
        /// </summary>
        [TestMethod]
        public void Test_needsUpdate_same_major_and_minor()
        {
            var heidi = new HeidiSQL(false);
            var quartet = new Quartet(heidi.knownInfo().newestVersion)
            {
                patch = 0,
                build = 0
            };
            var det = new DetectedSoftware()
            {
                displayVersion = quartet.full()
            };
            // equal numbers does not need update
            Assert.IsFalse(heidi.needsUpdate(det));
            // still needs no update
            det.displayVersion = quartet.major.ToString() + "." + quartet.minor.ToString();
            Assert.IsFalse(heidi.needsUpdate(det));
        }


        /// <summary>
        /// Checks whether the needsUpdate() method works as expected.
        /// </summary>
        [TestMethod]
        public void Test_needsUpdate_when_older()
        {
            var heidi = new HeidiVersionTest(false, "12.1.0.6537");
            var det = new DetectedSoftware()
            {
                displayVersion = heidi.knownInfo().newestVersion
            };

            // older versions should always need update
            string[] older = { "8.3.0.1234", "9.1", "10.2", "11.3" };
            foreach (string version in older)
            {
                det.displayVersion = version;
                Assert.IsTrue(heidi.needsUpdate(det));
            }
            // Still holds for shorter version number.
            heidi = new HeidiVersionTest(false, "12.1");
            foreach (string version in older)
            {
                det.displayVersion = version;
                Assert.IsTrue(heidi.needsUpdate(det));
            }
        }


        /// <summary>
        /// Checks whether the needsUpdate() method works as expected.
        /// </summary>
        [TestMethod]
        public void Test_needsUpdate_same_point_release()
        {
            var heidi = new HeidiVersionTest(false, "12.1.0.6537");
            var det = new DetectedSoftware()
            {
                displayVersion = heidi.knownInfo().newestVersion
            };

            // Versions from same point release should never need update.
            string[] same_point_release = { "12.1", "12.1.0", "12.1.0.0", "12.1.0.1234", "12.1.0.9999" };
            foreach (string version in same_point_release)
            {
                det.displayVersion = version;
                Assert.IsFalse(heidi.needsUpdate(det));
            }
            // Still holds for shorter version number.
            heidi = new HeidiVersionTest(false, "12.1");
            foreach (string version in same_point_release)
            {
                det.displayVersion = version;
                Assert.IsFalse(heidi.needsUpdate(det));
            }
        }


        /// <summary>
        /// Checks whether the needsUpdate() method works as expected.
        /// </summary>
        [TestMethod]
        public void Test_needsUpdate_newer_point_release()
        {
            var heidi = new HeidiVersionTest(false, "12.1.0.6537");
            var det = new DetectedSoftware()
            {
                displayVersion = heidi.knownInfo().newestVersion
            };

            // Versions from a newer point release should never need update.
            string[] same_point_release = { "12.2", "12.2.0", "12.2.0.0", "12.2.0.1234", "12.2.0.9999" };
            foreach (string version in same_point_release)
            {
                det.displayVersion = version;
                Assert.IsFalse(heidi.needsUpdate(det));
            }
            // Still holds for shorter version number.
            heidi = new HeidiVersionTest(false, "12.1");
            foreach (string version in same_point_release)
            {
                det.displayVersion = version;
                Assert.IsFalse(heidi.needsUpdate(det));
            }
        }


        /// <summary>
        /// Checks whether the needsUpdate() method works as expected.
        /// </summary>
        [TestMethod]
        public void Test_needsUpdate_newer_major_release()
        {
            var heidi = new HeidiVersionTest(false, "12.1.0.6537");
            var det = new DetectedSoftware()
            {
                displayVersion = heidi.knownInfo().newestVersion
            };

            // Versions from a newer point release should never need update.
            string[] same_point_release = { "13.0", "13.0.0", "13.0.0.0", "13.0.0.1234", "13.0.0.9999" };
            foreach (string version in same_point_release)
            {
                det.displayVersion = version;
                Assert.IsFalse(heidi.needsUpdate(det));
            }
            // Still holds for shorter version number.
            heidi = new HeidiVersionTest(false, "12.1");
            foreach (string version in same_point_release)
            {
                det.displayVersion = version;
                Assert.IsFalse(heidi.needsUpdate(det));
            }
        }
    } // class
} // namespace
