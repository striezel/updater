/*
    This file is part of the updater command line interface.
    Copyright (C) 2021, 2022, 2023, 2024, 2025, 2026  Dirk Stolle

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
    /// Handles updates of Node.js.
    /// </summary>
    public class NodeJS : NoPreUpdateProcessSoftware
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
        private static readonly DateTime certificateExpiration = new(2026, 10, 29, 21, 24, 44, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("Node.js does not provide 32-bit binaries from version 24.0.0 onwards.");
                logger.Warn("Please consider switching to an 64-bit operating system to get newer Node.js updates.");
                return Last32BitBuild();
            }

            const string version = "26.13.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            var installer = new InstallInfoMsi(
                "https://nodejs.org/download/release/v" + version + "/node-v" + version + "-x64.msi",
                HashAlgorithm.SHA256,
                "0e5ee99c7cbf922887f04af268e3665990748945336a44956f47cc0df695b6df",
                signature,
                "/qn /norestart");
            return new AvailableSoftware(
                "Node.js",
                version,
                "^Node\\.js$",
                "^Node\\.js$",
                installer, // cross-grade 32-bit installations to 64-bit
                installer);
        }


        /// <summary>
        /// Gets the information about the latest Node.js version that still has 32-bit builds.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public static AvailableSoftware Last32BitBuild()
        {
            const string version = "22.23.4";
            var signature = new Signature(
                "CN=OpenJS Foundation, O=OpenJS Foundation, L=San Francisco, S=California, C=US",
                new(2026, 5, 15, 22, 41, 19, DateTimeKind.Utc));
            return new AvailableSoftware(
                "Node.js",
                version,
                "^Node\\.js$",
                "^Node\\.js$",
                new InstallInfoMsi(
                    "https://nodejs.org/download/release/v" + version + "/node-v" + version + "-x86.msi",
                    HashAlgorithm.SHA256,
                    "c2a76d76eda52b7930b51fd490264c2fe34a094c04ae721bb71893f3fd6cd1d0",
                    signature,
                    "/qn /norestart"),
                new InstallInfoMsi(
                    "https://nodejs.org/download/release/v" + version + "/node-v" + version + "-x64.msi",
                    HashAlgorithm.SHA256,
                    "ca9303d3a12e8bec6de829fcb7812fc776930e0ce5c030328a24984ef928427e",
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
            return ["nodejs", "node", "node.js", "node-js"];
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
            logger.Info("Searching for newer version of Node.js...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                // Note: Change this URL as soon as the next version enters LTS state.
                var task = client.GetStringAsync("https://nodejs.org/dist/latest-v26.x/");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Node.js: " + ex.Message);
                return null;
            }

            var reMsi = new Regex("node\\-v([0-9]+\\.[0-9]+\\.[0-9]+)\\-x64\\.msi");
            Match matchMsi = reMsi.Match(htmlCode);
            if (!matchMsi.Success)
                return null;
            string newVersion = matchMsi.Groups[1].Value;

            // Now get SHA-256 checksum file from server.
            // URL is something like https://nodejs.org/download/release/v14.16.0/SHASUMS256.txt.
            try
            {
                var task = client.GetStringAsync("https://nodejs.org/download/release/v" + newVersion + "/SHASUMS256.txt");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while retrieving checksums for newer version of Node.js: " + ex.Message);
                return null;
            }

            string escapedVersion = Regex.Escape(newVersion);
            // Line looks like "d9243c9d02f5e4801b8b3ab848f45ce0da2882b5fff448191548ca49af434066  node-v14.16.0-x64.msi".
            var reChecksum64 = new Regex("[0-9a-f]{64}  node\\-v" + escapedVersion + "\\-x64\\.msi");
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
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = match64.Value[..64];
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
            return ["node"];
        }
    } // class
} // namespace
