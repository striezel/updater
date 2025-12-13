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
using System.IO;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Handles updates of HeidiSQL.
    /// </summary>
    public class HeidiSQL : AbstractSoftware
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
        private static readonly DateTime certificateExpiration = new(2028, 3, 16, 23, 59, 59, DateTimeKind.Utc);


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
            // Existing 32-bit installations on 64-bit operating systems will
            // effectively get "cross-graded" to 64-bit installations. So check
            // that we are on an 64-bit OS before doing that.
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("HeidiSQL does not provide 32-bit binaries from version 12.12.0.7122 onwards.");
                logger.Warn("Please consider switching to an 64-bit operating system to get newer HeidiSQL updates.");
                return Last32BitVersion();
            }
            var installer = new InstallInfoExe(
                    "https://www.heidisql.com/downloads/installers/HeidiSQL_12.14.0.7165_Setup.exe",
                    HashAlgorithm.SHA1,
                    "fbb31096c4e0a562cec3710827ed940f150345dd",
                    new Signature(publisherX509, certificateExpiration),
                    "/VERYSILENT /NORESTART");
            return new AvailableSoftware("HeidiSQL",
                "12.14.0.7165",
                "^HeidiSQL [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                "^HeidiSQL [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                // use 64-bit installer, too, to update 32-bit installations to 64-bit
                installer,
                // 64-bit installer
                installer
                );
        }

        /// <summary>
        /// Gets the information about the latest HeidiSQL version that still
        /// has 32-bit builds.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public static AvailableSoftware Last32BitVersion()
        {
            var installer = new InstallInfoExe(
                    "https://www.heidisql.com/installers/HeidiSQL_12.11.0.7065_Setup.exe",
                    HashAlgorithm.SHA1,
                    "5a3eba649eb654970574bdf91455b0cf2da9182f",
                    new Signature("CN=Ansgar Becker, O=Ansgar Becker, S=Nordrhein-Westfalen, C=DE",
                                  new(2028, 3, 16, 23, 59, 59, DateTimeKind.Utc)),
                    "/VERYSILENT /NORESTART");
            return new AvailableSoftware("HeidiSQL",
                "12.11.0.7065",
                "^HeidiSQL [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                "^HeidiSQL [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                // 32-bit installer
                installer,
                // 64-bit installer
                installer
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["heidisql", "heidi-sql"];
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
            logger.Info("Searching for newer version of HeidiSQL...");
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("HeidiSQL does not provide 32-bit binaries from version 12.12.0.7122 onwards.");
                logger.Warn("Please consider switching to an 64-bit operating system to get newer HeidiSQL updates.");
                return Last32BitVersion();
            }
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

            // Installer file was something like <a href="/downloads/installers/HeidiSQL_12.1.0.6537_Setup.exe"> in HTML.
            // Now it's a link to the release like <a href="https://github.com/HeidiSQL/HeidiSQL/releases/tag/v12.13.0.7147">.
            var reVersion = new Regex("HeidiSQL/releases/tag/v([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\">");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string newVersion = matchVersion.Groups[1].Value;
            var currentInfo = knownInfo();
            var currentQuartet = new Quartet(currentInfo.newestVersion);
            var newQuartet = new Quartet(newVersion);
            if (newQuartet < currentQuartet || currentQuartet.Equals(newQuartet))
            {
                // Known information is equal or newer, no need to get more new stuff.
                return currentInfo;
            }
            try
            {
                var task = client.GetStringAsync("https://www.heidisql.com/downloads/installers/HeidiSQL_" + newVersion + "_Setup.exe.sha1.txt");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception)
            {
                // Getting into this exception block usually means that the file was not found (HTTP 404).
                // Sometimes the ".exe" part is included in the URL and sometimes not, so try this one, too.
                try
                {
                    var task2 = client.GetStringAsync("https://www.heidisql.com/downloads/installers/HeidiSQL_" + newVersion + "_Setup.sha1.txt");
                    task2.Wait();
                    htmlCode = task2.Result;
                }
                catch (Exception ex)
                {
                    logger.Error("Exception occurred while checking for newer version of HeidiSQL: " + ex.Message);
                    return null;
                }
            }
            var reHash = new Regex("[0-9a-f]{40}");
            Match matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string hash = matchHash.Value;

            // construct new version information
            // replace version number - both as newest version and in URL for download
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            currentInfo.install32Bit.checksum = hash;
            currentInfo.install32Bit.algorithm = HashAlgorithm.SHA1;
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            currentInfo.install64Bit.checksum = hash;
            currentInfo.install64Bit.algorithm = HashAlgorithm.SHA1;
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return ["heidisql"];
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
            return detected.appType == ApplicationType.Bit32;
        }


        /// <summary>
        /// Returns a list of processes that must be run before the update.
        /// This can be an empty list.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (detected.appType != ApplicationType.Bit32)
            {
                return null;
            }

            // Prepare clean uninstall of 32-bit version before updating to 64-bit version.
            string uninstallerPath = null;
            if (!string.IsNullOrWhiteSpace(detected.uninstallString))
            {
                uninstallerPath = detected.uninstallString;
                // Remove enclosing quotes, if any.
                if (uninstallerPath.StartsWith('\"') && uninstallerPath.EndsWith('\"'))
                {
                    uninstallerPath = uninstallerPath[1..^1];
                }
            }
            if (string.IsNullOrWhiteSpace(uninstallerPath) && !string.IsNullOrWhiteSpace(detected.installPath))
            {
                uninstallerPath = detected.installPath;
                // Remove enclosing quotes, if any.
                if (uninstallerPath.StartsWith('\"') && uninstallerPath.EndsWith('\"'))
                {
                    uninstallerPath = uninstallerPath[1..^1];
                    uninstallerPath = Path.Combine(uninstallerPath, "unins000.exe");
                }
            }

            var proc = new Process();
            proc.StartInfo.FileName = uninstallerPath;
            proc.StartInfo.Arguments = "/VERYSILENT /NORESTART";
            return
            [
                proc
            ];
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
            // major and minor version number, e.g. 12.1 instead of the full
            // version number 12.1.0.6537. Therefore, comparison should only
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
