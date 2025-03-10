/*
    This file is part of the updater command line interface.
    Copyright (C) 2023, 2025  Dirk Stolle

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
    /// Contains tests for the InstallInfoPidgin class.
    /// </summary>
    [TestClass]
    public class InstallInfoPidgin_Tests
    {
        [TestMethod]
        public void createInstallProcess()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var info = new InstallInfoPidgin("https://example.org/foo/bar.exe", HashAlgorithm.Unknown, null, sig, "/DS=1 /SMS=1 /S");
            const string file_name = "C:\\foo\\bar.exe";
            var proc = info.createInstallProccess(file_name, new DetectedSoftware());

            Assert.IsNotNull(proc);
            Assert.AreEqual(file_name, proc.StartInfo.FileName);
            Assert.AreEqual("/DS=1 /SMS=1 /S", proc.StartInfo.Arguments);
        }

        [TestMethod]
        public void createInstallProcess_with_installation_directory()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var info = new InstallInfoPidgin("https://example.org/foo/bar.exe", HashAlgorithm.Unknown, null, sig, "/DS=1 /SMS=1 /S");
            const string file_name = "C:\\foo\\bar.exe";
            var detected = new DetectedSoftware("Foo", "1.0.0", "C:\\Program Files\\foo\\");
            var proc = info.createInstallProccess(file_name, detected);

            Assert.IsNotNull(proc);
            Assert.AreEqual(file_name, proc.StartInfo.FileName);
            Assert.AreEqual("/DS=1 /SMS=1 /S /D C:\\Program Files\\foo", proc.StartInfo.Arguments);
        }

        [TestMethod]
        public void createInstallProcess_null()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var info = new InstallInfoPidgin("https://example.org/foo/bar.exe", HashAlgorithm.Unknown, null, sig, "/S");

            var proc = info.createInstallProccess(null, new DetectedSoftware());
            Assert.IsNull(proc);

            proc = info.createInstallProccess("", new DetectedSoftware());
            Assert.IsNull(proc);

            proc = info.createInstallProccess("       ", new DetectedSoftware());
            Assert.IsNull(proc);
        }

        [TestMethod]
        public void ExitCodeIsSuccessButRequiresReboot()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var info = new InstallInfoPidgin("https://example.org/foo/bar.exe", HashAlgorithm.Unknown, null, sig, "/S /FOO");

            Assert.IsFalse(info.ExitCodeIsSuccessButRequiresReboot(0));
            Assert.IsFalse(info.ExitCodeIsSuccessButRequiresReboot(1));
            Assert.IsFalse(info.ExitCodeIsSuccessButRequiresReboot(2));

            Assert.IsFalse(info.ExitCodeIsSuccessButRequiresReboot(InstallInfoMsi.successRebootRequired));
        }
    } // class
} // namespace