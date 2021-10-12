﻿/*
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
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of the TeamSpeak client.
    /// </summary>
    public class TeamSpeakClient : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for NodeJS class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(TeamSpeakClient).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public TeamSpeakClient(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher name for signed installers
        /// </summary>
        private const string publisherX509 = "CN=TeamSpeak Systems GmbH, O=TeamSpeak Systems GmbH, L=Krün, S=Bayern, C=DE";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2023, 9, 8, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "3.5.6";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware(
                "TeamSpeak Client",
                version,
                "^TeamSpeak 3 Client$",
                "^TeamSpeak 3 Client$",
                new InstallInfoExe(
                    "https://files.teamspeak-services.com/releases/client/" + version + "/TeamSpeak3-Client-win32-" + version + ".exe",
                    HashAlgorithm.SHA256,
                    "c1387e7dd8be6ddeb23d235fad04f207b5c81b0a71e9e5acba1c6ce856414142",
                    signature,
                    "/S"),
                new InstallInfoExe(
                    "https://files.teamspeak-services.com/releases/client/" + version + "/TeamSpeak3-Client-win64-" + version + ".exe",
                    HashAlgorithm.SHA256,
                    "86381879a3e7dc7a2e90e4da1cccfbd2e5359b7ce6dd8bc11196d18dfc9e2abc",
                    signature,
                    "/S")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "teamspeak-client", "teamspeak" };
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
            logger.Info("Searching for newer version of TeamSpeak Client...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                // Looks like we have to add a user agent to get a valid response.
                // Without user agent the server returns "403 Forbidden".
                client.Headers.Add("User-Agent", "curl/7.77.0");
                try
                {
                    htmlCode = client.DownloadString("https://teamspeak.com/en/downloads/");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of TeamSpeak Client: " + ex.Message);
                    return null;
                }
                client.Dispose();
            }

            Regex reExe = new Regex("https://files\\.teamspeak\\-services\\.com/releases/client/[0-9]+\\.[0-9]+\\.[0-9]+/TeamSpeak3-Client-win32-([0-9]+\\.[0-9]+\\.[0-9]+).exe");
            Match match = reExe.Match(htmlCode);
            if (!match.Success)
            {
                return null;
            }
            string newVersion = match.Groups[1].Value;

            var info = knownInfo();
            info.install32Bit.downloadUrl = info.install32Bit.downloadUrl.Replace(info.newestVersion, newVersion);
            info.install64Bit.downloadUrl = info.install64Bit.downloadUrl.Replace(info.newestVersion, newVersion);
            info.newestVersion = newVersion;

            int idx32 = htmlCode.IndexOf("Client 32-bit");
            int idx64 = htmlCode.IndexOf("Client 64-bit");
            // Both must exist and 32 bit occurs before 64 bit client.
            if (idx32 == -1 || idx64 == -1 || idx32 > idx64)
            {
                return null;
            }

            Regex reHash = new Regex("SHA256\\: ([0-9a-f]{64})");
            match = reHash.Match(htmlCode.Substring(idx32));
            if (!match.Success)
                return null;
            info.install32Bit.checksum = match.Groups[1].Value;
            match = reHash.Match(htmlCode.Substring(idx64));
            if (!match.Success)
                return null;
            info.install64Bit.checksum = match.Groups[1].Value;

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
            return new List<string>(2)
            {
                "ts3client_win64",
                "ts3client_win32"
            };
        }
    } // class
} // namespace