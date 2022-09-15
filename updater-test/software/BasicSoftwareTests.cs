/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2021  Dirk Stolle

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
using updater.versions;

namespace updater_test.software
{
    /// <summary>
    /// Provides methods to implement some test for classes derived from ISoftware.
    /// </summary>
    public class BasicSoftwareTests
    {
        protected static void _info(ISoftware sw)
        {
            Assert.IsNotNull(sw);
            var info = sw.info();
            Assert.IsNotNull(info);
            // name must be set
            Assert.IsFalse(string.IsNullOrWhiteSpace(info.Name));
            // at least one installation information instance should be present
            Assert.IsTrue((info.install32Bit != null) || (info.install64Bit != null));
            // at least one regex should be present
            Assert.IsTrue(!string.IsNullOrWhiteSpace(info.match32Bit) || !string.IsNullOrWhiteSpace(info.match64Bit));
            // 32 bit information should match
            Assert.AreEqual<bool>(info.install32Bit != null, !string.IsNullOrWhiteSpace(info.match32Bit));
            // 64 bit information should match
            Assert.AreEqual<bool>(info.install64Bit != null, !string.IsNullOrWhiteSpace(info.match64Bit));
            // checksums should always be present, or at least a signature for verification
            if (null != info.install32Bit)
                Assert.IsTrue(info.install32Bit.hasChecksum() || info.install32Bit.hasVerifiableSignature());
            if (null != info.install64Bit)
                Assert.IsTrue(info.install64Bit.hasChecksum() || info.install64Bit.hasVerifiableSignature());
            // check whether signature data has expired
            // Expiration is not an error though, because some people publish signed binaries that expire the day after the release.
            if (null != info.install32Bit && info.install32Bit.signature.containsData() && info.install32Bit.signature.hasExpired())
            {
                Assert.Inconclusive("Signature data of 32 bit installer is past its expiration date!");
            }
            if (null != info.install64Bit && info.install64Bit.signature.containsData() && info.install64Bit.signature.hasExpired())
            {
                Assert.Inconclusive("Signature data of 64 bit installer is past its expiration date!");
            }
        }


        protected static void _searchForNewer(ISoftware sw)
        {
            Assert.IsNotNull(sw);
            if (!sw.implementsSearchForNewer())
                Assert.Inconclusive("The result of searchForNewer() was not tested, "
                    + "because this class indicates that it does not implement that method.");
            var newerInfo = sw.searchForNewer();
            Assert.IsNotNull(newerInfo);
        }


        public static void _upToDate_info(ISoftware sw)
        {
            Assert.IsNotNull(sw);
            if (!sw.implementsSearchForNewer())
                Assert.Inconclusive("The check for up to date information was not performed, "
                    + "because this class indicates that it does not implement the searchForNewer() method.");
            var info = sw.info();
            var newerInfo = sw.searchForNewer();
            Assert.IsNotNull(newerInfo, "searchForNewer() returned null!");
            int comp = string.Compare(info.newestVersion, newerInfo.newestVersion);
            var older = new Quartet(info.newestVersion);
            var newer = new Quartet(newerInfo.newestVersion);
            if (comp < 0 || older < newer)
            {
                Assert.Inconclusive(
                    "Known newest version of " + info.Name + " is " + info.newestVersion
                    + ", but the current newest version is " + newerInfo.newestVersion + "!");
            }
        }
    } // class
} // namespace
