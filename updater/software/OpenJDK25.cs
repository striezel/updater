/*
    This file is part of the updater command line interface.
    Copyright (C) 2025, 2026  Dirk Stolle

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
using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using updater.data;
using updater.software.openjdk_api;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Eclipse Temurin JDK 25 with Hotspot JVM.
    /// </summary>
    public class OpenJDK25 : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for OpenJDK25 class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(OpenJDK25).FullName);


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
        public OpenJDK25(bool autoGetNewer)
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
            return new AvailableSoftware("Eclipse Temurin JDK 25 with Hotspot",
                "25.0.2.10",
                null, // no 32-bit installer
                "^Eclipse Temurin JDK [a-z]+ Hotspot 25(\\.[0-9]+\\.[0-9]+)?\\+[0-9]+ \\(x64\\)$",
                null, // no 32-bit installer
                new InstallInfoMsiNoLocation(
                    "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.2%2B10/OpenJDK25U-jdk_x64_windows_hotspot_25.0.2_10.msi",
                    HashAlgorithm.SHA256,
                    "c433b59ab42630634657ae273940183c2f95a115dd5bf6846a70dcd0a42b9c0d",
                    signature,
                    "ALLUSERS=1 INSTALLLEVEL=3 /qn /norestart")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["openjdk-25-jdk", "openjdk-25", "openjdk-jdk", "openjdk", "jdk"];
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
            logger.Info("Searching for newer version of Eclipse Temurin 25 JDK...");
            // Just getting the latest release does not work here, because that may also be a release candidate, and we do not want that.
            string json;
            using (var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(25) })
            {
                try
                {
                    var task = client.GetStringAsync("https://api.adoptium.net/v3/assets/feature_releases/25/ga?heap_size=normal&image_type=jdk&jvm_impl=hotspot&os=windows&page=0&page_size=1&project=jdk&sort_method=DEFAULT&sort_order=DESC&vendor=eclipse");
                    task.Wait();
                    json = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Eclipse Temurin 25 JDK: " + ex.Message);
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
            bool hasBuild64 = false;

            foreach (Binary bin in release.Binaries)
            {
                if (string.IsNullOrEmpty(bin.Architecture) || null == bin.Installer
                    || string.IsNullOrEmpty(bin.Installer.Link) || string.IsNullOrEmpty(bin.Installer.Checksum))
                {
                    logger.Error("Error: AdoptOpenJDK API response contains incomplete data!");
                    return null;
                }
                if (bin.Architecture == "x64")
                {
                    newInfo.install64Bit.checksum = bin.Installer.Checksum;
                    newInfo.install64Bit.downloadUrl = bin.Installer.Link;
                    hasBuild64 = true;
                    break;
                }
            }

            // Do we have all the data we need?
            if (!hasBuild64)
            {
                logger.Error("The 64-bit build information of Eclipse Temurin JDK was not found!");
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
                "java",
                "javac",
                "javadoc",
                "javap",
                "javaw"
            ];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            // Due to a limitation of the MSI format, an update where the first
            // three version numbers match cannot be performed. Instead it
            // installs a new software. That means that an update from e.g.
            // version 25.0.0.36 to 25.0.0.37 is not possible and will add a
            // new installation. But that is not what we want, so we have to
            // uninstall the old version first.
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            // Uninstall the old version first. See needsPreUpdateProcess() for
            // an explanation of why this is required.
            if (string.IsNullOrWhiteSpace(detected.uninstallString))
            {
                logger.Error("There is not enough information to uninstall the old Eclipse Temurin JDK 25 version.");
                return null;
            }

            var re = new Regex("\\{[0-9A-F]{8}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{12}\\}", RegexOptions.IgnoreCase);
            Match m = re.Match(detected.uninstallString);
            if (!m.Success)
            {
                logger.Error("Could not extract GUID of old Eclipse Temurin JDK 25 version for pre-update process.");
                return null;
            }
            var proc = new Process();
            proc.StartInfo.FileName = "msiexec.exe";
            proc.StartInfo.Arguments = "/X" + m.Value + " /qn /norestart";
            return new List<Process>(1) { proc };
        }
    } // class
} // namespace
