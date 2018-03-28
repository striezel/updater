/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
using updater.data;

namespace updater_test
{
    /// <summary>
    /// class that provides some common functionality for test cases
    /// </summary>
    internal class BasicTest
    {
        /// <summary>
        /// Gets a temporary file name (does NOT create the file).
        /// </summary>
        /// <returns>Returns file name, if successful.
        /// Returns null, if an error occurred.</returns>
        internal static string getTempFileName()
        {
            try
            {
                string result = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
                return result;
            }
            catch (Exception)
            {
                return null;
            }
        }


        /// <summary>
        /// Gets an instance if AvailableSoftware filled with example data.
        /// </summary>
        /// <returns>Returns a filled instance of AvailableSoftware class.</returns>
        internal static AvailableSoftware getAcme()
        {
            return new AvailableSoftware("ACME", "1.2.3", "ACME 32", "ACME 64",
                new InstallInfoExe("https://www.example.com/dl/file.ext", HashAlgorithm.SHA1,
                "7772433567cb18608519f649f981e38a0be12c26", null, "/S"),
                new InstallInfoExe("https://www.example.com/dl/file64.ext", HashAlgorithm.SHA1,
                "08519f649f981e38a0be12c267772433567cb186", null, "/S"));
        }

    } // class
} // namespace
