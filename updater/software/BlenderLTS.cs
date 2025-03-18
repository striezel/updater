/*
    This file is part of the updater command line interface.
    Copyright (C) 2024, 2025  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Blender LTS version (currently 4.2.x, but that may
    /// change when a newer LTS branch is released in the future).
    /// </summary>
    public class BlenderLTS : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for BlenderLTS class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(BlenderLTS).FullName);


        /// <summary>
        /// publisher name for signed installers of Blender LTS
        /// </summary>
        private const string publisherX509 = "CN=Blender Foundation, O=Blender Foundation, L=Amsterdam, S=Noord-Holland, C=NL";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2025, 3, 20, 6, 0, 5, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public BlenderLTS(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Blender LTS",
                "4.2.8",
                null,
                "^blender$",
                null,
                new InstallInfoMsi(
                    // Use mirror URL, because the "original" URL of the Blender
                    // website will redirect to a mirror site, and this redirect
                    // is not machine-friendly, i.e. uses JavaScript etc., so a
                    // mirror is the safe choice here.
                    // "https://ftp.nluug.nl/pub/graphics/blender/release/Blender4.2/blender-4.2.8-windows-x64.msi",
                    "https://ftp.halifax.rwth-aachen.de/blender/release/Blender4.2/blender-4.2.8-windows-x64.msi",
                    HashAlgorithm.SHA256,
                    "eac24e174d5d81d91393cbad68dbc017412f3f184238f4fd404c4c9b50bdfafe",
                    new Signature(publisherX509, certificateExpiration),
                    "/qn /norestart ALLUSERS=1")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["blender", "blender-lts"];
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
            logger.Info("Searching for newer version of Blender...");
            var client = HttpClientProvider.Provide();
            string currentVersion;
            try
            {
                var task = client.GetStringAsync("https://www.blender.org/download/lts/4-2/");
                task.Wait();
                var html = task.Result;
                // Installer will be something like "https://www.blender.org/download/release/Blender4.2/blender-4.2.7-windows-x64.msi".
                var reVersion = new Regex("blender\\-([0-9]+\\.[0-9]+\\.[0-9]+)\\-windows\\-x64\\.msi");
                Match matchVersion = reVersion.Match(html);
                if (!matchVersion.Success)
                    return null;
                currentVersion = matchVersion.Groups[1].Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Blender: " + ex.Message);
                return null;
            }

            // Download checksum file, e.g. "https://download.blender.org/release/Blender4.2/blender-4.2.7.sha256".
            string checksum;
            try
            {
                var task = client.GetStringAsync("https://download.blender.org/release/Blender4.2/blender-" + currentVersion + ".sha256");
                task.Wait();
                var html = task.Result;

                var reCheckSum = new Regex("[0-9a-f]{64}  blender\\-" + Regex.Escape(currentVersion) + "\\-windows\\-x64\\.msi$", RegexOptions.Multiline);
                var match = reCheckSum.Match(html);
                if (!match.Success)
                    return null;
                checksum = match.Value[..64];
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Blender: " + ex.Message);
                return null;
            }

            // construct new information
            var newInfo = knownInfo();
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = currentVersion;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, currentVersion);
            newInfo.install64Bit.checksum = checksum;
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
            return ["blender"];
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
            if (!string.IsNullOrWhiteSpace(detected.uninstallString))
            {
                var re = new Regex("\\{[0-9A-F]{8}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{12}\\}", RegexOptions.IgnoreCase);
                Match m = re.Match(detected.uninstallString);
                if (!m.Success)
                {
                    logger.Error("Could not extract GUID of old Blender version for pre-update process.");
                    return null;
                }
                var proc = new Process();
                proc.StartInfo.FileName = "msiexec.exe";
                proc.StartInfo.Arguments = "/X" + m.Value + " /qn /norestart";
                return new List<Process>(1) { proc };
            }

            logger.Error("There is not enough information to uninstall the old Blender version.");
            return null;
        }
    } // class
} // namespace
