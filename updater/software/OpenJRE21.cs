/*
    This file is part of the updater command line interface.
    Copyright (C) 2023, 2024  Dirk Stolle

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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net.Http;
using updater.data;
using updater.software.openjdk_api;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Eclipse Temurin JRE 21 with Hotspot JVM.
    /// </summary>
    public class OpenJRE21 : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for OpenJRE21 class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(OpenJRE21).FullName);


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=\"Eclipse.org Foundation, Inc.\", O=\"Eclipse.org Foundation, Inc.\", L=Ottawa, S=Ontario, C=CA";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2025, 7, 21, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public OpenJRE21(bool autoGetNewer)
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
            const string version = "21.0.5.11";
            return new AvailableSoftware("Eclipse Temurin JRE 21 with Hotspot",
                version,
                null, // no 32-bit installer
                "^Eclipse Temurin JRE [a-z]+ Hotspot 21\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?\\+[0-9]+(\\.[0-9]+)? \\(x64\\)$",
                null, // no 32-bit installer
                new InstallInfoMsiNoLocation(
                    "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5%2B11/OpenJDK21U-jre_x64_windows_hotspot_21.0.5_11.msi",
                    HashAlgorithm.SHA256,
                    "baa356843cbe2cbc8e49bad1cfef27eaaf5e59748a1627be40492804753c706a",
                    signature,
                    "INSTALLLEVEL=3 /qn /norestart")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["openjdk-21-jre", "openjre-21", "openjdk-jre", "openjre", "jre"];
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
            logger.Info("Searching for newer version of Eclipse Temurin 21 JRE...");
            string json;
            using (var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(25) })
            {
                try
                {
                    var task = client.GetStringAsync("https://api.adoptium.net/v3/assets/feature_releases/21/ga?heap_size=normal&image_type=jre&jvm_impl=hotspot&os=windows&page=0&page_size=1&project=jdk&sort_method=DEFAULT&sort_order=DESC&vendor=eclipse");
                    task.Wait();
                    json = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Eclipse Temurin 21 JRE: " + ex.Message);
                    return null;
                }
            }


            var releases = JsonConvert.DeserializeObject<IList<Release>>(json);
            if (releases == null)
            {
                logger.Error("Error: Could not deserialize AdoptOpenJDK API response!");
                return null;
            }
            if (releases.Count == 0)
            {
                logger.Error("Error: AdoptOpenJDK API returned empty response!");
                return null;
            }

            var release = releases[0];
            if (release.version_data == null
                || release.version_data.major == VersionData.MissingBuildNumber
                || release.version_data.minor == VersionData.MissingBuildNumber
                || release.version_data.security == VersionData.MissingBuildNumber
                || release.version_data.build == VersionData.MissingBuildNumber)
            {
                logger.Error("Error: AdoptOpenJDK API response does not contain complete version data!");
                return null;
            }

            // Construct new information.
            var newInfo = knownInfo();
            newInfo.newestVersion = release.version_data.major.ToString() + "."
                + release.version_data.minor.ToString() + "."
                + release.version_data.security.ToString() + "."
                + release.version_data.build.ToString();
            bool hasBuild64 = false;

            foreach (Binary bin in release.binaries)
            {
                if (string.IsNullOrEmpty(bin.architecture) || null == bin.installer
                    || string.IsNullOrEmpty(bin.installer.link) || string.IsNullOrEmpty(bin.installer.checksum))
                {
                    logger.Error("Error: AdoptOpenJDK API response contains incomplete data!");
                    return null;
                }
                if (bin.architecture == "x64")
                {
                    newInfo.install64Bit.checksum = bin.installer.checksum;
                    newInfo.install64Bit.downloadUrl = bin.installer.link;
                    hasBuild64 = true;
                    break;
                }
            }

            // Do we have all the data we need?
            if (!hasBuild64)
            {
                logger.Error("The 64-bit build information of Eclipse Temurin JRE was not found!");
                return null;
            }
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
            return new List<string>(3)
            {
                "jaotc",
                "java",
                "javaw"
            };
        }
    } // class
} // namespace
