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
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Node.js.
    /// </summary>
    public class NodeJS: NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for NodeJS class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(NodeJS).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public NodeJS(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=OpenJS Foundation, O=OpenJS Foundation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2023, 12, 18, 12, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "16.13.2";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware(
                "Node.js",
                version,
                "^Node\\.js$",
                "^Node\\.js$",
                new InstallInfoMsi(
                    "https://nodejs.org/download/release/v" + version + "/node-v" + version + "-x86.msi",
                    HashAlgorithm.SHA256,
                    "a220a4b55ec0a6b9aa7b5651cded20a167a75f8a51aa908ff15dd25890f19e00",
                    signature,
                    "/qn /norestart"),
                new InstallInfoMsi(
                    "https://nodejs.org/download/release/v" + version + "/node-v" + version + "-x64.msi",
                    HashAlgorithm.SHA256,
                    "1690d6c4947e9b998b183b8eca3056729763e63d2306bc38fc1170b4f0de0689",
                    signature,
                    "/qn /norestart")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "nodejs", "node", "node.js", "node-js" };
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
            logger.Info("Searching for newer version of Node.js...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://nodejs.org/en/download/");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Node.js: " + ex.Message);
                    return null;
                }
                client.Dispose();
            }

            Regex reMsi = new Regex("https://nodejs\\.org/dist/v([0-9]+\\.[0-9]+\\.[0-9]+)/node\\-v([0-9]+\\.[0-9]+\\.[0-9]+)\\-x64\\.msi");
            Match matchMsi = reMsi.Match(htmlCode);
            if (!matchMsi.Success)
                return null;
            if (matchMsi.Groups[1].Value != matchMsi.Groups[2].Value)
            {
                logger.Error("Detected Node.js versions do not match: " + matchMsi.Groups[1].Value + " != " + matchMsi.Groups[2].Value + "!");
                return null;
            }
            string newVersion = matchMsi.Groups[1].Value;

            // Now get SHA-256 checksum file from server.
            // URL is something like https://nodejs.org/download/release/v14.16.0/SHASUMS256.txt.
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://nodejs.org/download/release/v" + newVersion + "/SHASUMS256.txt");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while retrieving checksums for newer version of Node.js: " + ex.Message);
                    return null;
                }
                client.Dispose();
            }

            // Line looks like "61d549ed39fc264df9978f824042f3f4cac90a866e933c5088384d5dedf283fe  node-v14.16.0-x86.msi".
            string escapedVersion = Regex.Escape(newVersion);
            Regex reChecksum32 = new Regex("[0-9a-f]{64}  node\\-v" + escapedVersion + "\\-x86\\.msi");
            Match match32 = reChecksum32.Match(htmlCode);
            if (!match32.Success)
                return null;
            // Line looks like "d9243c9d02f5e4801b8b3ab848f45ce0da2882b5fff448191548ca49af434066  node-v14.16.0-x64.msi".
            Regex reChecksum64 = new Regex("[0-9a-f]{64}  node\\-v" + escapedVersion + "\\-x64\\.msi");
            Match match64 = reChecksum64.Match(htmlCode);
            if (!match64.Success)
                return null;

            // construct new version information
            var newInfo = knownInfo();
            // ... but use known information, if versions match.
            if (newInfo.newestVersion == newVersion)
                return newInfo;
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = match32.Value.Substring(0, 64);
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = match64.Value.Substring(0, 64);
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
            return new List<string>(1)
            {
                "node"
            };
        }
    } // class
} // namespace
