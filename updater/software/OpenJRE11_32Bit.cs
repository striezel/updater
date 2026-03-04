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
using System.Net.Http;
using System.Text.Json;
using updater.data;
using updater.software.openjdk_api;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Eclipse Temurin (formerly AdoptOpenJDK) JRE 11 with
    /// Hotspot JVM, but only for the 32 bit variant.
    /// </summary>
    public class OpenJRE11_32Bit : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for OpenJRE11_32Bit class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(OpenJRE11_32Bit).FullName);


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=\"Eclipse.org Foundation, Inc.\", O=\"Eclipse.org Foundation, Inc.\", L=Ottawa, S=Ontario, C=CA";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2026, 7, 16, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public OpenJRE11_32Bit(bool autoGetNewer)
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
            const string version = "11.0.29.7";
            return new AvailableSoftware("Eclipse Temurin JRE 11 with Hotspot",
                version,
                "^(Eclipse Temurin|AdoptOpenJDK) JRE [a-z]+ Hotspot 11\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?\\+[0-9]+(\\.[0-9]+)? \\(x86\\)$",
                null, // 64 bit variant is handled in another class
                new InstallInfoMsiNoLocation(
                    "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.29%2B7/OpenJDK11U-jre_x86-32_windows_hotspot_11.0.29_7.msi",
                    HashAlgorithm.SHA256,
                    "dec292e1d6e90944d0c4592e3df26d19072025ed34657d67d3456281f7f3026a",
                    signature,
                    "INSTALLLEVEL=3 /qn /norestart"),
                null);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["openjdk-11-jre-32bit", "openjdk-11-jre", "openjre-11", "openjdk-jre", "openjre", "jre"];
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
            logger.Info("Searching for newer version of Eclipse Temurin 11 JRE (32 bit) ...");
            logger.Warn("The 32 bit variant of Eclipse Temurin 1 JRE does not get regular updates anymore."
                + " Consider switching to the 64 bit variant instead.");
            string json;
            using (var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(25) })
            {
                try
                {
                    var task = client.GetStringAsync("https://api.adoptopenjdk.net/v3/assets/feature_releases/11/ga?heap_size=normal&image_type=jre&jvm_impl=hotspot&os=windows&page=0&page_size=1&project=jdk&sort_method=DEFAULT&sort_order=DESC&vendor=adoptopenjdk&architecture=x86");
                    task.Wait();
                    json = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Eclipse Temurin 11 JRE (32 bit): " + ex.Message);
                    return null;
                }
            }


            var releases = JsonSerializer.Deserialize<IList<Release>>(json);
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
            if (release.VersionData == null
                || release.VersionData.Major == VersionData.MissingBuildNumber
                || release.VersionData.Minor == VersionData.MissingBuildNumber
                || release.VersionData.Security == VersionData.MissingBuildNumber
                || release.VersionData.Build == VersionData.MissingBuildNumber)
            {
                logger.Error("Error: AdoptOpenJDK API response does not contain complete version data!");
                return null;
            }

            // Construct new information.
            var newInfo = knownInfo();
            newInfo.newestVersion = release.VersionData.Major.ToString() + "."
                + release.VersionData.Minor.ToString() + "."
                + release.VersionData.Security.ToString() + "."
                + release.VersionData.Build.ToString();
            bool hasBuild32 = false;

            foreach (Binary bin in release.Binaries)
            {
                if (string.IsNullOrEmpty(bin.Architecture) || null == bin.Installer
                    || string.IsNullOrEmpty(bin.Installer.Link) || string.IsNullOrEmpty(bin.Installer.Checksum))
                {
                    logger.Error("Error: AdoptOpenJDK API response contains incomplete data!");
                    return null;
                }
                if (bin.Architecture == "x32")
                {
                    newInfo.install32Bit.checksum = bin.Installer.Checksum;
                    newInfo.install32Bit.downloadUrl = bin.Installer.Link;
                    hasBuild32 = true;
                }
            }

            // Do we have all the data we need?
            if (!hasBuild32)
            {
                logger.Error("The 32-bit build information of Eclipse Temurin JRE was not found!");
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
            return
            [
                "jaotc",
                "java",
                "javaw"
            ];
        }
    } // class
} // namespace
