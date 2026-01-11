/*
    This file is part of the updater command line interface.
    Copyright (C) 2024, 2025, 2026  Dirk Stolle

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
using System.Collections.Generic;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Doxygen.
    /// </summary>
    public class Doxygen : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Doxygen class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Doxygen).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Doxygen(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            InstallInfo info = new InstallInfoExe(
                "https://www.doxygen.nl/files/doxygen-1.16.1-setup.exe",
                HashAlgorithm.SHA256,
                "acb198f5db33b295d2d4cf8a2e06503637bc7d241d2f0ed7f5e493eeece0da58",
                Signature.None,
                "/VERYSILENT /NORESTART"
                );

            return new AvailableSoftware("Doxygen",
                "1.16.1",
                "^doxygen [0-9]+\\.[0-9]+\\.[0-9]+$",
                "^doxygen [0-9]+\\.[0-9]+\\.[0-9]+$",
                info,
                info);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["doxygen"];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }

        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Doxygen...");
            string html;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://www.doxygen.nl/download.html");
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Doxygen version: " + ex.Message);
                return null;
            }

            // Checksum and version are contained in a HTML line like
            // "<tr><td class="right">doxygen-1.11.0-setup.exe</td><td class="left"><code>b4761a654ce4ed46cc46bfb46f3f8c53812bdc84067ef3367b4089963718698a</code></td></tr>"
            var regEx = new Regex("doxygen\\-([0-9]+\\.[0-9]+\\.[0-9]+)\\-setup\\.exe</td><td class=\"left\"><code>([0-9a-f]{64})</code>");
            Match match = regEx.Match(html);
            if (!match.Success)
                return null;
            var info = knownInfo();
            info.install32Bit.checksum = match.Groups[2].Value;
            info.install64Bit.checksum = match.Groups[2].Value;
            var version = match.Groups[1].Value;
            info.install32Bit.downloadUrl = info.install32Bit.downloadUrl.Replace(info.newestVersion, version);
            info.install64Bit.downloadUrl = info.install64Bit.downloadUrl.Replace(info.newestVersion, version);
            info.newestVersion = version;

            return info;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return
            [
                "doxygen",
                "doxyindexer",
                "doxysearch.cgi",
                "doxywizard"
            ];
        }
    }
}
