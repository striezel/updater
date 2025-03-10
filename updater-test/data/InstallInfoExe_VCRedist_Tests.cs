/*
    This file is part of the updater command line interface.
    Copyright (C) 2025  Dirk Stolle

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
using updater.data;

namespace updater_test.data
{
    /// <summary>
    /// Contains tests for the InstallInfoExe_VCRedist class.
    /// </summary>
    [TestClass]
    public class InstallInfoExe_VCRedist_Tests
    {
        [TestMethod]
        public void CreateInstallProcess()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var ii = new InstallInfoExe_VCRedist("https://example.org/foo/bar.exe", HashAlgorithm.Unknown, null, sig, "/S /FOO");
            const string file_name = "C:\\foo\\bar.exe";
            var proc = ii.createInstallProccess(file_name, new DetectedSoftware());

            Assert.IsNotNull(proc);
            Assert.AreEqual(file_name, proc.StartInfo.FileName);
            Assert.AreEqual("/S /FOO", proc.StartInfo.Arguments);
        }


        [TestMethod]
        public void CreateInstallProcess_null()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var info = new InstallInfoExe_VCRedist("https://example.org/foo/bar.exe", HashAlgorithm.Unknown, null, sig, "/S /FOO");

            var proc = info.createInstallProccess(null, new DetectedSoftware());
            Assert.IsNull(proc);

            proc = info.createInstallProccess("", new DetectedSoftware());
            Assert.IsNull(proc);

            proc = info.createInstallProccess("     ", new DetectedSoftware());
            Assert.IsNull(proc);
        }

        [TestMethod]
        public void ExitCodeIsSuccessButRequiresReboot()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var info = new InstallInfoExe_VCRedist("https://example.org/foo/bar.exe", HashAlgorithm.Unknown, null, sig, "/S /FOO");

            Assert.IsFalse(info.ExitCodeIsSuccessButRequiresReboot(0));
            Assert.IsFalse(info.ExitCodeIsSuccessButRequiresReboot(1));
            Assert.IsFalse(info.ExitCodeIsSuccessButRequiresReboot(2));

            Assert.IsTrue(info.ExitCodeIsSuccessButRequiresReboot(InstallInfoMsi.successRebootRequired));
        }
    } // class
} // namespace
