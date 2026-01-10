/*
    This file is part of the updater command line interface.
    Copyright (C) 2026  Dirk Stolle

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
    /// Handles updates for KeePassXC.
    /// </summary>
    public class KeePassXC : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for KeePassXC class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(KeePassXC).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public KeePassXC(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=\"DroidMonkey Apps, LLC\", O=\"DroidMonkey Apps, LLC\", S=Virginia, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 2, 22, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("KeePassXC",
                "2.7.11",
                null,
                "^KeePassXC$",
                // There is no 32-bit installer.
                null,
                new InstallInfoMsi(
                    "https://github.com/keepassxreboot/keepassxc/releases/download/2.7.11/KeePassXC-2.7.11-Win64.msi",
                    HashAlgorithm.SHA256,
                    "74abea9e12282cc2b0feb51ebc6db65299eb4ef0086e89cfad8dcaafc94a6f67",
                    signature,
                    "/qn /norestart"));
        }


        /// <summary>
        /// Gets the list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["keepassxc"];
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
            logger.Info("Searching for newer version of KeePassXC...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://keepassxc.org/download/#windows");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of KeePassXC: " + ex.Message);
                return null;
            }

            var regExp = new Regex("/KeePassXC-([0-9]+\\.[0-9]+\\.[0-9]+)-Win64.msi");
            Match match = regExp.Match(htmlCode);
            if (!match.Success)
                return null;
            string version = match.Groups[1].Value;
            try
            {
                var task = client.GetStringAsync("https://github.com/keepassxreboot/keepassxc/releases/download/" + version + "/KeePassXC-" + version + "-Win64.msi.DIGEST");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of KeePassXC: " + ex.Message);
                return null;
            }
            // extract hash
            var hash = new Regex("[0-9a-fA-F]{64}  KeePassXC-" + Regex.Escape(version) + "-Win64.msi");
            Match matchHash = hash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash = matchHash.Value[..64];
            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = version;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, version);
            newInfo.install64Bit.checksum = newHash;
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
            return [];
        }

    } // class
} // namespace
