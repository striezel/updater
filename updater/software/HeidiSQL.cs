/*
    This file is part of the updater command line interface.
    Copyright (C) 2022, 2023  Dirk Stolle

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
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Handles updates of HeidiSQL.
    /// </summary>
    public class HeidiSQL : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for HeidiSQL class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(HeidiSQL).FullName);


        /// <summary>
        /// publisher name for signed executables of LibreOffice
        /// </summary>
        private const string publisherX509 = "CN=Ansgar Becker, O=Ansgar Becker, S=Nordrhein-Westfalen, C=DE";


        /// <summary>
        /// expiration date of the certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2025, 4, 9, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public HeidiSQL(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var installer = new InstallInfoExe(
                    "https://www.heidisql.com/installers/HeidiSQL_12.4.0.6659_Setup.exe",
                    HashAlgorithm.SHA1,
                    "40cebf3e01dff591e4fdc425d0453488d92e5b49",
                    new Signature(publisherX509, certificateExpiration),
                    "/VERYSILENT /NORESTART");
            return new AvailableSoftware("HeidiSQL",
                "12.4.0.6659",
                "^HeidiSQL [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                "^HeidiSQL [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                // 32 bit installer
                installer,
                // 64 bit installer
                installer
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "heidisql", "heidi-sql" };
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
            logger.Info("Searching for newer version of HeidiSQL...");
            var client = HttpClientProvider.Provide();
            string htmlCode;
            try
            {
                var task = client.GetStringAsync("https://www.heidisql.com/download.php");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Error("Exception occurred while checking for newer version of HeidiSQL: " + ex.Message);
                return null;
            }

            // Checksum file is something like <a href="/installers/HeidiSQL_12.1.0.6537_Setup.sha1.txt"> in HTML.
            var reVersion = new Regex("/installers/HeidiSQL_([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)_Setup.sha1.txt\"");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string newVersion = matchVersion.Groups[1].Value;
            try
            {
                var task = client.GetStringAsync("https://www.heidisql.com/installers/HeidiSQL_" + newVersion + "_Setup.sha1.txt");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Error("Exception occurred while checking for newer version of HeidiSQL: " + ex.Message);
                return null;
            }
            var reHash = new Regex("[0-9a-f]{40}");
            Match matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string hash = matchHash.Value;

            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = hash;
            newInfo.install32Bit.algorithm = HashAlgorithm.SHA1;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = hash;
            newInfo.install64Bit.algorithm = HashAlgorithm.SHA1;
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
                "heidisql"
            };
        }


        /// <summary>
        /// Checks whether the detected software is older than the newest known software.
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            // HeidiSQL version information from registry only contains the
            // major and minor version number, e. g. 12.1 instead of the full
            // version number 12.1.0.6537. Therefore, comparision should only
            // consider the first two numbers for updates.
            var verDetected = new Quartet(detected.displayVersion)
            {
                patch = 0,
                build = 0
            };
            var verNewest = new Quartet(info().newestVersion)
            {
                patch = 0,
                build = 0
            };
            return verDetected < verNewest;
        }
    }
}
