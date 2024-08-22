/*
    This file is part of the updater command line interface.
    Copyright (C) 2023  Dirk Stolle

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
    /// Contains tests for the InstallInfoMsiPatch class.
    /// </summary>
    [TestClass]
    public class InstallInfoMsiPatch_Tests
    {
        [TestMethod]
        public void createInstallProcess()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var info = new InstallInfoMsiPatch("https://example.org/foo/bar.msp", HashAlgorithm.Unknown, null, sig, "/qn /norestart");
            const string file_name = "C:\\foo\\bar.msp";
            var proc = info.createInstallProccess(file_name, new DetectedSoftware());

            Assert.IsNotNull(proc);
            Assert.AreEqual("msiexec.exe", proc.StartInfo.FileName);
            Assert.AreEqual("/p \"" + file_name + "\" /qn /norestart", proc.StartInfo.Arguments);
        }

        [TestMethod]
        public void createInstallProcess_null()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var info = new InstallInfoMsiPatch("https://example.org/foo/bar.msp", HashAlgorithm.Unknown, null, sig, "/qn /norestart");

            var proc = info.createInstallProccess(null, new DetectedSoftware());
            Assert.IsNull(proc);

            proc = info.createInstallProccess("", new DetectedSoftware());
            Assert.IsNull(proc);

            proc = info.createInstallProccess("       ", new DetectedSoftware());
            Assert.IsNull(proc);
        }

        [TestMethod]
        public void DerivedFromMsi()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var info = new InstallInfoMsiPatch("https://example.org/foo/bar.msp", HashAlgorithm.Unknown, null, sig, "/qn /norestart");
#pragma warning disable IDE0150
            Assert.IsTrue(info is InstallInfoMsi);
#pragma warning restore IDE0150
        }
    } // class
} // namespace