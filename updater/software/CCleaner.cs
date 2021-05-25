/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
    /// CCleaner (free version)
    /// </summary>
    public class CCleaner : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for CCleaner class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(CCleaner).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public CCleaner(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher name for signed executables
        /// </summary>
        private const string publisherX509 = "CN=Piriform Software Ltd, OU=RE 901, O=Piriform Software Ltd, L=London, C=GB";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2022, 10, 18, 12, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            var installer = new InstallInfoExe(
                "https://download.ccleaner.com/ccsetup580.exe",
                HashAlgorithm.SHA256,
                "aeb20eec5600175f4f8cc1f5d38dbd98c54f1664cb44e8f18a579fe1f59c1d45",
                signature,
                "/S");
            return new AvailableSoftware("CCleaner",
                "5.80",
                "^CCleaner+$",
                "^CCleaner+$",
                // CCleaner uses the same installer for 32 and 64 bit.
                installer,
                installer
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "ccleaner" };
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
            logger.Debug("Searching for newer version of CCleaner...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("http://www.ccleaner.com/ccleaner/download/standard");
                }
                catch (Exception ex)
                {
                    logger.Error("Exception occurred while checking for newer version of CCleaner: " + ex.Message);
                    return null;
                }
                client.Dispose();
            }

            // extract download URL
            Regex reg = new Regex("http(s)?://download\\.ccleaner\\.com/ccsetup[0-9]+\\.exe");
            Match match = reg.Match(htmlCode);
            if (!match.Success)
                return null;
            // switch to HTTPS, if URL is HTTP only
            string newUrl = match.Value.Replace("http://", "https://");
            // extract version
            reg = new Regex("[0-9]+");
            match = reg.Match(newUrl);
            if (!match.Success)
                return null;
            string newVersion = match.Value;
            // new version should be at least three digits long
            if (newVersion.Length < 3)
                return null;
            newVersion = newVersion.Substring(0, newVersion.Length - 2) + "." + newVersion.Substring(newVersion.Length - 2);
            if (newVersion == knownInfo().newestVersion)
                return knownInfo();

            // No checksums are provided, but binary is signed.

            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = newVersion;
            // 32 bit
            newInfo.install32Bit.downloadUrl = newUrl;
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            // 64 bit - same installer
            newInfo.install64Bit.downloadUrl = newUrl;
            newInfo.install64Bit.checksum = null;
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
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
            return new List<string>();
        }
    } // class
} // namespace
