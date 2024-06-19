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
using System.IO;
using System.Net.Http;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using updater.utility;

namespace updater_test.utility
{
    /// <summary>
    /// Contains tests for the PortableExecutable utility class.
    /// </summary>
    [TestClass]
    public class PortableExecutable_Tests
    {
        /// <summary>
        /// Checks whether PortableExecutable.determineFormat() can properly detect
        /// the format of a 32-bit portable executable.
        /// </summary>
        [TestMethod]
        public void Test_determineFormat_executable32()
        {
            // Download https://the.earth.li/~sgtatham/putty/0.77/w32/putty.exe, that is a known 32-bit file.
            string local_path = Path.Combine(Path.GetTempPath(), "known-32bit-exe.bak");
            using (var client = new HttpClient())
            {
                using (var stream = client.GetStreamAsync("https://the.earth.li/~sgtatham/putty/0.77/w32/putty.exe"))
                {
                    using (var file_stream = new FileStream(local_path, FileMode.OpenOrCreate))
                    {
                        stream.Result.CopyTo(file_stream);
                    }
                }
            }

            // Downloaded .exe should always be 32-bit.
            var format = PortableExecutable.determineFormat(local_path);
            File.Delete(local_path);
            Assert.AreEqual(PEFormat.PE32, format);
        }


        /// <summary>
        /// Checks whether PortableExecutable.determineFormat() can properly detect
        /// the format of a 64-bit portable executable.
        /// </summary>
        [TestMethod]
        public void Test_determineFormat_executable64()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                Assert.Inconclusive("Probably there will not be an 64-bit executables on a 32-bit operating system,"
                    + " so we cannot test a 64-bit executable.");
                return;
            }

            // explorer.exe should be 64-bit on a 64-bit OS.
            var format = PortableExecutable.determineFormat("C:\\Windows\\explorer.exe");
            Assert.AreEqual(PEFormat.PE64, format);
        }


        /// <summary>
        /// checks whether PortableExecutable.determineFormat() can handle null,
        /// empty and whitespace values gracefully
        /// </summary>
        [TestMethod]
        public void Test_determineFormat_NullEmptyWhitespace()
        {
            // null
            var format = PortableExecutable.determineFormat(null);
            Assert.AreNotEqual(PEFormat.PE32, format);
            Assert.AreNotEqual(PEFormat.PE64, format);
            // empty
            format = PortableExecutable.determineFormat("");
            Assert.AreNotEqual(PEFormat.PE32, format);
            Assert.AreNotEqual(PEFormat.PE64, format);
            // whitespace
            format = PortableExecutable.determineFormat("   \t   \r\n  \r  \n   \v  ");
            Assert.AreNotEqual(PEFormat.PE32, format);
            Assert.AreNotEqual(PEFormat.PE64, format);
        }
    } // class
} // namespace
