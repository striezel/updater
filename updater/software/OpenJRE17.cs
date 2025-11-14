/*
    This file is part of the updater command line interface.
    Copyright (C) 2022, 2023, 2024, 2025  Dirk Stolle

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
    /// Handles updates of Eclipse Temurin JRE 17 with Hotspot JVM.
    /// </summary>
    public class OpenJRE17 : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for OpenJRE17 class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(OpenJRE17).FullName);


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
        public OpenJRE17(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("Eclipse Temurin JRE 17 does not provide 32-bit binaries from version 17.0.17+10 onwards."
                    + "Please consider switching to an 64-bit operating system to get newer updates.");
                return Last32BitBuild();
            }
            var signature = new Signature(publisherX509, certificateExpiration);
            var install64Bit = new InstallInfoMsiNoLocation(
                "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.17%2B10/OpenJDK17U-jre_x64_windows_hotspot_17.0.17_10.msi",
                HashAlgorithm.SHA256,
                "23eea3080b9545915b5af64807fd310ee7227688a179b33859530912cca4c1e6",
                signature,
                "INSTALLLEVEL=3 /qn /norestart");
            return new AvailableSoftware("Eclipse Temurin JRE 17 with Hotspot",
                "17.0.17.10",
                "^Eclipse Temurin JRE [a-z]+ Hotspot 17\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?\\+[0-9]+(\\.[0-9]+)? \\(x86\\)$",
                "^Eclipse Temurin JRE [a-z]+ Hotspot 17\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?\\+[0-9]+(\\.[0-9]+)? \\(x64\\)$",
                // Use 64-bit installer on 32-bit installations for cross-grading.
                install64Bit,
                // 64-bit installation
                install64Bit
                );
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public static AvailableSoftware Last32BitBuild()
        {
            const string publisherX509_32 = "CN=\"Eclipse.org Foundation, Inc.\", O=\"Eclipse.org Foundation, Inc.\", L=Ottawa, S=Ontario, C=CA";
            DateTime certificateExpiration_32 = new(2025, 7, 21, 23, 59, 59, DateTimeKind.Utc);
            var signature = new Signature(publisherX509_32, certificateExpiration_32);
            const string version = "17.0.16.8";
            return new AvailableSoftware("Eclipse Temurin JRE 17 with Hotspot",
                version,
                "^Eclipse Temurin JRE [a-z]+ Hotspot 17\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?\\+[0-9]+(\\.[0-9]+)? \\(x86\\)$",
                "^Eclipse Temurin JRE [a-z]+ Hotspot 17\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?\\+[0-9]+(\\.[0-9]+)? \\(x64\\)$",
                new InstallInfoMsiNoLocation(
                    "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.16%2B8/OpenJDK17U-jre_x86-32_windows_hotspot_17.0.16_8.msi",
                    HashAlgorithm.SHA256,
                    "47ac8df108d911103a053880a401fc18302b4b9a098814436716deba86cdfb76",
                    signature,
                    "INSTALLLEVEL=3 /qn /norestart"),
                new InstallInfoMsiNoLocation(
                    "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.16%2B8/OpenJDK17U-jre_x64_windows_hotspot_17.0.16_8.msi",
                    HashAlgorithm.SHA256,
                    "9937d754d7157dcdb7ec70a83a5e6238ce093c71316435b4dd07ae38880980d2",
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
            return ["openjdk-17-jre", "openjre-17", "openjdk-jre", "openjre", "jre"];
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
            logger.Info("Searching for newer version of Eclipse Temurin 17 JRE...");
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("Eclipse Temurin JRE 17 does not provide 32-bit binaries from version 17.0.17+10 onwards."
                    + "Please consider switching to an 64-bit operating system to get newer updates.");
                return Last32BitBuild();
            }
            string json;
            using (var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(25) })
            {
                try
                {
                    var task = client.GetStringAsync("https://api.adoptopenjdk.net/v3/assets/feature_releases/17/ga?heap_size=normal&image_type=jre&jvm_impl=hotspot&os=windows&page=0&page_size=1&project=jdk&sort_method=DEFAULT&sort_order=DESC&vendor=adoptopenjdk");
                    task.Wait();
                    json = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Eclipse Temurin 17 JRE: " + ex.Message);
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
                }
                else if (bin.Architecture == "x32")
                {
                    newInfo.install32Bit.checksum = bin.Installer.Checksum;
                    newInfo.install32Bit.downloadUrl = bin.Installer.Link;
                    hasBuild32 = true;
                }
            }

            // Do we have all the data we need?
            if (!hasBuild64)
            {
                logger.Error("The 64-bit build information of Eclipse Temurin JRE was not found!");
                return null;
            }
            if (!hasBuild32)
            {
                // Use information of 64 bit version to perform cross-grade.
                newInfo.install32Bit = newInfo.install64Bit;
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
            // If it's a 32-bit installation, we need to uninstall it to perform
            // a cross-grade to the 64-bit version.
            return detected.appType == ApplicationType.Bit32;
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
            // Only 32-bit installations need a pre-update process.
            if (detected.appType != ApplicationType.Bit32)
            {
                return null;
            }

            if (string.IsNullOrWhiteSpace(detected.uninstallString))
            {
                logger.Error("There is not enough information to uninstall the old 32-bit Eclipse Temurin JRE 17 version.");
                return null;
            }

            var re = new Regex("\\{[0-9A-F]{8}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{12}\\}", RegexOptions.IgnoreCase);
            Match m = re.Match(detected.uninstallString);
            if (!m.Success)
            {
                logger.Error("Could not extract GUID of old Eclipse Temurin JRE 17 version for pre-update process.");
                return null;
            }
            var proc = new Process();
            proc.StartInfo.FileName = "msiexec.exe";
            proc.StartInfo.Arguments = "/X" + m.Value + " /qn /norestart";
            return [proc];
        }
    } // class
} // namespace
