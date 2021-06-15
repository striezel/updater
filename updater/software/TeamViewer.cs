/*
    This file is part of the updater command line interface.
    Copyright (C) 2021  Dirk Stolle

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
using updater.utility;

namespace updater.software
{
    /// <summary>
    /// Handles updates for TeamViewer Desktop.
    /// </summary>
    public class TeamViewer : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for TeamViewer class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(TeamViewer).FullName);


        /// <summary>
        /// publisher name for signed installers
        /// </summary>
        private const string publisherX509 = "CN=TeamViewer Germany GmbH, O=TeamViewer Germany GmbH, L=Göppingen, S=Baden-Württemberg, C=DE";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2022, 1, 26, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public TeamViewer(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("TeamViewer",
                "15.18.5",
                "^TeamViewer$",
                "^TeamViewer$",
                new InstallInfoExe(
                    "https://download.teamviewer.com/download/TeamViewer_Setup.exe",
                    HashAlgorithm.Unknown,
                    null,
                    signature,
                    "/S /norestart"),
                new InstallInfoExe(
                    "https://download.teamviewer.com/download/TeamViewer_Setup_x64.exe",
                    HashAlgorithm.Unknown,
                    null,
                    signature,
                    "/S /norestart")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "teamviewer" };
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of TeamViewer...");
            string html;
            using (var client = new TimelyWebClient())
            {
                try
                {
                    html = client.DownloadString("https://www.teamviewer.com/en/download/windows/");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Git for Windows: " + ex.Message);
                    return null;
                }
            }

            // HTML text will contain version in a paragraph like "<p>Current version: 15.18.5</p>".
            Regex reVersion = new Regex("<p>Current version: ([0-9]+\\.[0-9]+\\.[0-9])</p>");
            var matchVersion = reVersion.Match(html);
            if (!matchVersion.Success)
                return null;
            string currentVersion = matchVersion.Groups[1].Value;

            // The TeamViewer website does not provide any checksums, so we can just use the signatures.

            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = currentVersion;
            return newInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(4)
            {
                "TeamViewer",
                "TeamViewer_Desktop",
                "tv_w32",
                "tv_x64"
            };
        }
    }
}
