﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2022  Dirk Stolle

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

using System.Diagnostics;

namespace updater.data
{
    /// <summary>
    /// Like InstallInfoMsi, but it installs patches (*.msp) instead of full packages (*.msi).
    /// </summary>
    public class InstallInfoMsiPatch : InstallInfoMsi
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        public InstallInfoMsiPatch()
            : base()
        {
            // Base class constructor does initialization.
        }


        /// <summary>
        /// Constructor with initial value parameters.
        /// </summary>
        /// <param name="_downloadUrl">URL where the installer can be downloaded</param>
        /// <param name="_algo">hash algorithm that was used to create or verify the checksum</param>
        /// <param name="_check">checksum for the installer - hexadecimal representation</param>
        /// <param name="_sig">common name of publisher and expiration date, if file is signed</param>
        /// <param name="_silent">switches for silent installation</param>
        public InstallInfoMsiPatch(string _downloadUrl, HashAlgorithm _algo, string _check, Signature _sig, string _silent)
            : base(_downloadUrl, _algo, _check, _sig, _silent)
        {
            // Base class constructor does initialization.
        }


        /// <summary>
        /// Creates a process instance that can be used to perform the update.
        /// </summary>
        /// <param name="downloadedFile">path to the downloaded installer file</param>
        /// <param name="detected">info about detected software</param>
        /// <returns>Returns a process instance ready to start, if successful.
        /// Returns null, if an error occurred.</returns>
        public override Process createInstallProccess(string downloadedFile, DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(downloadedFile))
                return null;

            var proc = new Process();
            proc.StartInfo.FileName = "msiexec.exe";
            proc.StartInfo.Arguments = "/p \"" + downloadedFile + "\" " + silentSwitches;
            return proc;
        }
    } // class
} // namespace
