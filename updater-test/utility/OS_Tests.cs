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

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using updater.utility;

namespace updater_test.utility
{
    /// <summary>
    /// Contains unit tests for updater.utility.OS class.
    /// </summary>
    [TestClass]
    public class OS_Tests
    {
        private static OperatingSystem win2000()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(5, 0));
        }

        private static OperatingSystem winXP()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(5, 1));
        }

        private static OperatingSystem winXP64()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(5, 2));
        }

        private static OperatingSystem winVista()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(6, 0));
        }

        private static OperatingSystem win7()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(6, 1));
        }

        private static OperatingSystem win8()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(6, 2));
        }

        private static OperatingSystem win8_1()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(6, 3));
        }

        private static OperatingSystem win10()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(10, 0));
        }


        /// <summary>
        /// Checks whether isWinXPOrNewer() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_isWinXPOrNewer()
        {
            Assert.IsFalse(OS.isWinXPOrNewer(win2000()));
            Assert.IsTrue(OS.isWinXPOrNewer(winXP()));
            Assert.IsTrue(OS.isWinXPOrNewer(winXP64()));
            Assert.IsTrue(OS.isWinXPOrNewer(winVista()));
            Assert.IsTrue(OS.isWinXPOrNewer(win7()));
            Assert.IsTrue(OS.isWinXPOrNewer(win8()));
            Assert.IsTrue(OS.isWinXPOrNewer(win8_1()));
            Assert.IsTrue(OS.isWinXPOrNewer(win10()));
        }


        /// <summary>
        /// Checks whether isWinVistaOrNewer() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_isWinVistaOrNewer()
        {
            Assert.IsFalse(OS.isWinVistaOrNewer(win2000()));
            Assert.IsFalse(OS.isWinVistaOrNewer(winXP()));
            Assert.IsFalse(OS.isWinVistaOrNewer(winXP64()));
            Assert.IsTrue(OS.isWinVistaOrNewer(winVista()));
            Assert.IsTrue(OS.isWinVistaOrNewer(win7()));
            Assert.IsTrue(OS.isWinVistaOrNewer(win8()));
            Assert.IsTrue(OS.isWinVistaOrNewer(win8_1()));
            Assert.IsTrue(OS.isWinVistaOrNewer(win10()));
        }


        /// <summary>
        /// Checks whether isWin7OrNewer() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_isWin7OrNewer()
        {
            Assert.IsFalse(OS.isWin7OrNewer(win2000()));
            Assert.IsFalse(OS.isWin7OrNewer(winXP()));
            Assert.IsFalse(OS.isWin7OrNewer(winXP64()));
            Assert.IsFalse(OS.isWin7OrNewer(winVista()));
            Assert.IsTrue(OS.isWin7OrNewer(win7()));
            Assert.IsTrue(OS.isWin7OrNewer(win8()));
            Assert.IsTrue(OS.isWin7OrNewer(win8_1()));
            Assert.IsTrue(OS.isWin7OrNewer(win10()));
        }


        /// <summary>
        /// Checks whether isWin10OrNewer() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_isWin10OrNewer()
        {
            Assert.IsFalse(OS.isWin10OrNewer(win2000()));
            Assert.IsFalse(OS.isWin10OrNewer(winXP()));
            Assert.IsFalse(OS.isWin10OrNewer(winXP64()));
            Assert.IsFalse(OS.isWin10OrNewer(winVista()));
            Assert.IsFalse(OS.isWin10OrNewer(win7()));
            Assert.IsFalse(OS.isWin10OrNewer(win8()));
            Assert.IsFalse(OS.isWin10OrNewer(win8_1()));
            Assert.IsTrue(OS.isWin10OrNewer(win10()));
        }
    } // class
} // namespace
