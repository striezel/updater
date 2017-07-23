using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using updater.utility;

namespace updater_test.utility
{
    /// <summary>
    /// contains unit tests for updater.utility.OS class
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
        }


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
        }


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
        }
    } //class
} //namespace
