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
using System;
using updater.utility;

namespace updater_test.utility
{
    /// <summary>
    /// Contains unit tests for updater.utility.OS class.
    /// </summary>
    [TestClass]
    public class OS_Tests
    {
        private static OperatingSystem Win2000()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(5, 0));
        }

        private static OperatingSystem WinXP()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(5, 1));
        }

        private static OperatingSystem WinXP64()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(5, 2));
        }

        private static OperatingSystem WinVista()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(6, 0));
        }

        private static OperatingSystem Win7()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(6, 1));
        }

        private static OperatingSystem Win8()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(6, 2));
        }

        private static OperatingSystem Win8_1()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(6, 3));
        }

        private static OperatingSystem Win10()
        {
            return new OperatingSystem(PlatformID.Win32NT, new Version(10, 0));
        }


        /// <summary>
        /// Checks whether isWinXPOrNewer() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_isWinXPOrNewer()
        {
            Assert.IsFalse(OS.isWinXPOrNewer(Win2000()));
            Assert.IsTrue(OS.isWinXPOrNewer(WinXP()));
            Assert.IsTrue(OS.isWinXPOrNewer(WinXP64()));
            Assert.IsTrue(OS.isWinXPOrNewer(WinVista()));
            Assert.IsTrue(OS.isWinXPOrNewer(Win7()));
            Assert.IsTrue(OS.isWinXPOrNewer(Win8()));
            Assert.IsTrue(OS.isWinXPOrNewer(Win8_1()));
            Assert.IsTrue(OS.isWinXPOrNewer(Win10()));
        }


        /// <summary>
        /// Checks whether isWinVistaOrNewer() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_isWinVistaOrNewer()
        {
            Assert.IsFalse(OS.isWinVistaOrNewer(Win2000()));
            Assert.IsFalse(OS.isWinVistaOrNewer(WinXP()));
            Assert.IsFalse(OS.isWinVistaOrNewer(WinXP64()));
            Assert.IsTrue(OS.isWinVistaOrNewer(WinVista()));
            Assert.IsTrue(OS.isWinVistaOrNewer(Win7()));
            Assert.IsTrue(OS.isWinVistaOrNewer(Win8()));
            Assert.IsTrue(OS.isWinVistaOrNewer(Win8_1()));
            Assert.IsTrue(OS.isWinVistaOrNewer(Win10()));
        }


        /// <summary>
        /// Checks whether isWin7OrNewer() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_isWin7OrNewer()
        {
            Assert.IsFalse(OS.isWin7OrNewer(Win2000()));
            Assert.IsFalse(OS.isWin7OrNewer(WinXP()));
            Assert.IsFalse(OS.isWin7OrNewer(WinXP64()));
            Assert.IsFalse(OS.isWin7OrNewer(WinVista()));
            Assert.IsTrue(OS.isWin7OrNewer(Win7()));
            Assert.IsTrue(OS.isWin7OrNewer(Win8()));
            Assert.IsTrue(OS.isWin7OrNewer(Win8_1()));
            Assert.IsTrue(OS.isWin7OrNewer(Win10()));
        }


        /// <summary>
        /// Checks whether isWin10OrNewer() works as expected.
        /// </summary>
        [TestMethod]
        public void Test_isWin10OrNewer()
        {
            Assert.IsFalse(OS.isWin10OrNewer(Win2000()));
            Assert.IsFalse(OS.isWin10OrNewer(WinXP()));
            Assert.IsFalse(OS.isWin10OrNewer(WinXP64()));
            Assert.IsFalse(OS.isWin10OrNewer(WinVista()));
            Assert.IsFalse(OS.isWin10OrNewer(Win7()));
            Assert.IsFalse(OS.isWin10OrNewer(Win8()));
            Assert.IsFalse(OS.isWin10OrNewer(Win8_1()));
            Assert.IsTrue(OS.isWin10OrNewer(Win10()));
        }
    } // class
} // namespace
