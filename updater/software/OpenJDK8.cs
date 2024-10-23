/*
    This file is part of the updater command line interface.
    Copyright (C) 2021, 2022, 2023, 2024  Dirk Stolle

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
    /// Handles updates of Eclipse Temurin (formerly AdoptOpenJDK) JDK 8 with Hotspot JVM.
    /// </summary>
    public class OpenJDK8 : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for OpenJDK8 class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(OpenJDK8).FullName);


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
        public OpenJDK8(bool autoGetNewer)
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
            const string version = "8.0.432.6";
            return new AvailableSoftware("Eclipse Temurin JDK 8 with Hotspot",
                version,
                "^(Eclipse Temurin JDK [a-z]+ Hotspot 8u[0-9]+\\-b[0-9]+ \\(x86\\)|AdoptOpenJDK JDK [a-z]+ Hotspot 8u[0-9]+\\-b[0-9]+ \\(x86\\))$",
                "^(Eclipse Temurin JDK [a-z]+ Hotspot 8u[0-9]+\\-b[0-9]+ \\(x64\\)|AdoptOpenJDK JDK [a-z]+ Hotspot 8u[0-9]+\\-b[0-9]+ \\(x64\\))$",
                new InstallInfoMsiNoLocation(
                    "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u432-b06/OpenJDK8U-jdk_x86-32_windows_hotspot_8u432b06.msi",
                    HashAlgorithm.SHA256,
                    "83efc58a52a3ada3fd22993e96a8fbf4b91c5cd39d34ffa88dacee27e11f6b3e",
                    signature,
                    "INSTALLLEVEL=3 /qn /norestart"),
                new InstallInfoMsiNoLocation(
                    "https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u432-b06/OpenJDK8U-jdk_x64_windows_hotspot_8u432b06.msi",
                    HashAlgorithm.SHA256,
                    "c9280205858928756374d930d4b539c59b1cb470425d2cf300b943c56efe4d86",
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
            return new string[] { "openjdk-8-jdk", "openjdk-8", "openjdk-jdk", "openjdk", "jdk" };
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
            logger.Info("Searching for newer version of Eclipse Temurin 8 JDK...");
            // Just getting the latest release does not work here, because that may also be a release candidate, and we do not want that.
            string json;
            using (var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(25) })
            {
                try
                {
                    var task = client.GetStringAsync("https://api.adoptopenjdk.net/v3/assets/feature_releases/8/ga?heap_size=normal&image_type=jdk&jvm_impl=hotspot&os=windows&page=0&page_size=5&project=jdk&sort_method=DEFAULT&sort_order=DESC&vendor=adoptopenjdk");
                    task.Wait();
                    json = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Eclipse Temurin 8 JDK: " + ex.Message);
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

            // Construct new information.
            var newInfo = knownInfo();
            bool hasBuild32 = false;
            bool hasBuild64 = false;
            // The logic here is a bit complicated, because Eclipse Adoptium (formerly AdoptOpenJDK)
            // may release versions like jdk8u302-b08.1 on top of the proper jdk8u302-b08 to include
            // fixes, but the fix may not be available for all architectures. So it is possible that
            // x86 and x64 may need to be downloaded from different tags.
            foreach (var release in releases)
            {
                if (release.version_data == null
                    || release.version_data.major == VersionData.MissingBuildNumber
                    || release.version_data.minor == VersionData.MissingBuildNumber
                    || release.version_data.security == VersionData.MissingBuildNumber
                    || release.version_data.build == VersionData.MissingBuildNumber)
                {
                    logger.Error("Error: AdoptOpenJDK API response does not contain complete version data!");
                    continue;
                }
                newInfo.newestVersion = release.version_data.major.ToString() + "."
                    + release.version_data.minor.ToString() + "."
                    + release.version_data.security.ToString() + "."
                    + release.version_data.build.ToString();

                foreach (Binary bin in release.binaries)
                {
                    if (string.IsNullOrEmpty(bin.architecture) || null == bin.installer
                        || string.IsNullOrEmpty(bin.installer.link) || string.IsNullOrEmpty(bin.installer.checksum))
                    {
                        logger.Error("Error: AdoptOpenJDK API response contains incomplete data!");
                        continue;
                    }
                    if (bin.architecture == "x64")
                    {
                        if (!hasBuild64)
                        {
                            newInfo.install64Bit.checksum = bin.installer.checksum;
                            newInfo.install64Bit.downloadUrl = bin.installer.link;
                            hasBuild64 = true;
                        }
                    }
                    else if (bin.architecture == "x32")
                    {
                        if (!hasBuild32)
                        {
                            newInfo.install32Bit.checksum = bin.installer.checksum;
                            newInfo.install32Bit.downloadUrl = bin.installer.link;
                            hasBuild32 = true;
                        }
                    }

                    if (hasBuild32 && hasBuild64)
                        return newInfo;
                }
            }

            // Do we have all the data we need?
            if (!hasBuild32 || !hasBuild64)
            {
                logger.Error("Either 32-bit build or 64-bit build information of Eclipse Temurin 8 JDK was not found!");
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
            return new List<string>(5)
            {
                "java",
                "javac",
                "javadoc",
                "javap",
                "javaw"
            };
        }
    } // class
} // namespace
