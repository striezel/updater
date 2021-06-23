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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using updater.data;
using updater.software.openjdk_api;
using updater.utility;

namespace updater.software
{
    /// <summary>
    /// Handles updates of AdoptOpenJDK JDK 11 with Hotspot JVM.
    /// </summary>
    public class OpenJDK11 : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for OpenJDK11 class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(OpenJDK11).FullName);


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=London Jamocha Community CIC, O=London Jamocha Community CIC, L=Camberley, C=GB";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2021, 10, 13, 12, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public OpenJDK11(bool autoGetNewer)
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
            return new AvailableSoftware("AdoptOpenJDK JDK 11 with Hotspot",
                "11.0.11.9",
                "^AdoptOpenJDK JDK [a-z]+ Hotspot 11\\.[0-9]+\\.[0-9]+\\+[0-9]+(\\.[0-9]+)? \\(x86\\)$",
                "^AdoptOpenJDK JDK [a-z]+ Hotspot 11\\.[0-9]+\\.[0-9]+\\+[0-9]+(\\.[0-9]+)? \\(x64\\)$",
                new InstallInfoMsiNoLocation(
                    "https://github.com/AdoptOpenJDK/openjdk11-binaries/releases/download/jdk-11.0.11%2B9/OpenJDK11U-jdk_x86-32_windows_hotspot_11.0.11_9.msi",
                    HashAlgorithm.SHA256,
                    "205eb727fb10eed1894666340c50b4d98b035fe40b6a4f0075cc9340f36bb190",
                    signature,
                    "INSTALLLEVEL=3 /qn /norestart"),
                new InstallInfoMsiNoLocation(
                    "https://github.com/AdoptOpenJDK/openjdk11-binaries/releases/download/jdk-11.0.11%2B9/OpenJDK11U-jdk_x64_windows_hotspot_11.0.11_9.msi",
                    HashAlgorithm.SHA256,
                    "de7de70fbd9f3ff49ce34db87c5f331a5c0b72e54c16e9e6d9ba3007d23b361e",
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
            return new string[] { "openjdk-11-jdk", "openjdk-11", "openjdk-jdk", "openjdk", "jdk" };
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
            logger.Info("Searching for newer version of AdoptOpenJDK 11 JDK...");
            // Just getting the latest release does not work here, because that may also be a release candidate, and we do not want that.
            string json;
            using (var client = new TimelyWebClient())
            {
                try
                {
                    json = client.DownloadString("https://api.adoptopenjdk.net/v3/assets/feature_releases/11/ga?heap_size=normal&image_type=jdk&jvm_impl=hotspot&os=windows&page=0&page_size=1&project=jdk&sort_method=DEFAULT&sort_order=DESC&vendor=adoptopenjdk");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of AdoptOpenJDK 11 JDK: " + ex.Message);
                    return null;
                }
            }


            var releases = JsonConvert.DeserializeObject<IList<Release>>(json);
            if (releases == null)
            {
                logger.Error("Error: Could not deserialize OpenJDK API response!");
                return null;
            }
            if (releases.Count == 0)
            {
                logger.Error("Error: OpenJDK API returned empty response!");
                return null;
            }

            var release = releases[0];
            if (release.version_data == null
                || release.version_data.major == VersionData.MissingBuildNumber
                || release.version_data.minor == VersionData.MissingBuildNumber
                || release.version_data.security == VersionData.MissingBuildNumber
                || release.version_data.build == VersionData.MissingBuildNumber)
            {
                logger.Error("Error: OpenJDK API response does not contain complete version data!");
                return null;
            }

            // Construct new information.
            var newInfo = knownInfo();
            newInfo.newestVersion = release.version_data.major.ToString() + "."
                + release.version_data.minor.ToString() + "."
                + release.version_data.security.ToString() + "."
                + release.version_data.build.ToString();
            bool hasBuild32 = false;
            bool hasBuild64 = false;

            foreach (Binary bin in release.binaries)
            {
                if (string.IsNullOrEmpty(bin.architecture) || null == bin.installer
                    || string.IsNullOrEmpty(bin.installer.link) || string.IsNullOrEmpty(bin.installer.checksum))
                {
                    logger.Error("Error: OpenJDK API response contains incomplete data!");
                    return null;
                }
                if (bin.architecture == "x64")
                {
                    newInfo.install64Bit.checksum = bin.installer.checksum;
                    newInfo.install64Bit.downloadUrl = bin.installer.link;
                    hasBuild64 = true;
                }
                else if (bin.architecture == "x32")
                {
                    newInfo.install32Bit.checksum = bin.installer.checksum;
                    newInfo.install32Bit.downloadUrl = bin.installer.link;
                    hasBuild32 = true;
                }
                else
                {
                    logger.Error("Error: unknown architecture '" + bin.architecture + "' in OpenJDK API response!");
                    return null;
                }
            }

            // Do we have all the data we need?
            if (!hasBuild32 || !hasBuild64)
            {
                logger.Error("Either 32 bit build or 64 bit build information of OpenJDK was not found!");
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
