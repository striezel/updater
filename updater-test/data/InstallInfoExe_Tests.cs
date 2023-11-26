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
using updater.data;
using System;

namespace updater_test.data
{
    /// <summary>
    /// Contains tests for the InstallInfoExe class.
    /// </summary>
    [TestClass]
    public class InstallInfoExe_Tests
    {
        [TestMethod]
        public void createInstallProcess()
        {
            var sig = new Signature("CN=foo, OU=bar", DateTime.Now.AddDays(3.0));
            var ii = new InstallInfoExe("https://example.org/foo/bar.exe", HashAlgorithm.Unknown, null, sig, "/S /FOO");
            const string file_name = "C:\\foo\\bar.exe";
            var proc = ii.createInstallProccess(file_name, new DetectedSoftware());

            Assert.IsNotNull(proc);
            Assert.AreEqual(file_name, proc.StartInfo.FileName);
            Assert.AreEqual("/S /FOO", proc.StartInfo.Arguments);
        }
    } // class
} // namespace