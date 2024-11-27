/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of PuTTY.
    /// </summary>
    public class Putty : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Putty class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Putty).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Putty(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher name on signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Simon Tatham, O=Simon Tatham, S=Cambridgeshire, C=GB";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 9, 27, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("PuTTY",
                "0.82",
                "^PuTTY release [0-9]\\.[0-9]+$",
                "^PuTTY release [0-9]\\.[0-9]+ \\(64\\-bit\\)$",
                // 32-bit installer
                new InstallInfoMsi(
                    "https://the.earth.li/~sgtatham/putty/0.82/w32/putty-0.82-installer.msi",
                    HashAlgorithm.SHA512,
                    "0b7a84f08957d2a3e9f2d9486bc8de0df83eaafda825dfd7d5352e5f5ef39afaae25fc1347a19277a5b822f25ac6a314d9fc6a253131543edba43a794463cbb6",
                    signature,
                    "/qn /norestart"),
                // 64-bit installer
                new InstallInfoMsi(
                    "https://the.earth.li/~sgtatham/putty/0.82/w64/putty-64bit-0.82-installer.msi",
                    HashAlgorithm.SHA512,
                    "3a69468a992f9f42ff7258afecfe042bbd0226909fd3965f208eb0738c40bfd96a9befd5792a8201719c71e2a5262d654afebb81d7c2eda42b00233094890391",
                    signature,
                    "/qn /norestart")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["putty"];
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
            logger.Info("Searching for newer version of PuTTY...");
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            string newLocation;
            try
            {
                var task = httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, "https://the.earth.li/~sgtatham/putty/latest/"));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                newLocation = response.Headers.Location?.ToString();
                response = null;
                task = null;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer PuTTY version: " + ex.Message);
                return null;
            }

            var reVersion = new Regex("/[0-9]+\\.[0-9]+/");
            Match matchVersion = reVersion.Match(newLocation);
            if (!matchVersion.Success)
                return null;
            string newVersion = matchVersion.Value.Replace("/", "");

            // Checksums are in a file like https://the.earth.li/~sgtatham/putty/0.68/sha512sums
            string sha512sums = null;
            using (var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(25) })
            {
                try
                {
                    var task = client.GetStringAsync("https://the.earth.li/~sgtatham/putty/" + newVersion + "/sha512sums");
                    task.Wait();
                    sha512sums = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of PuTTY: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            var reHash32 = new Regex("[0-9a-f]{128}  w32/putty\\-" + Regex.Escape(newVersion) + "\\-installer\\.msi");
            Match matchHash32 = reHash32.Match(sha512sums);
            if (!matchHash32.Success)
                return null;
            string hash32 = matchHash32.Value[..128];

            var reHash64 = new Regex("[0-9a-f]{128}  w64/putty\\-64bit\\-" + Regex.Escape(newVersion) + "\\-installer\\.msi");
            Match matchHash64 = reHash64.Match(sha512sums);
            if (!matchHash64.Success)
                return null;
            string hash64 = matchHash64.Value[..128];

            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = hash32;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = hash64;
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
            return ["putty"];
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
            return !string.IsNullOrWhiteSpace(detected.displayVersion);
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
            // We also cannot create a process, if the version is unknown.
            if (string.IsNullOrWhiteSpace(detected.displayVersion))
                return null;

            // If the version is older than 0.68, that uses an *.exe installer.
            // Versions from 0.68 onwards use MSI installers.
            bool oldExeInstaller = string.Compare(detected.displayVersion, "0.68") < 0;
            // Install path is required when uninstalling old *.exe installed
            // versions of PuTTY.
            if (oldExeInstaller && string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            // Uninstall string containing GUID is required when uninstalling
            // MSI installers.
            if (!oldExeInstaller && string.IsNullOrWhiteSpace(detected.uninstallString))
                return null;

            var processes = new List<Process>();
            // Uninstallation process for versions before 0.68 (*.exe installers):
            if (oldExeInstaller)
            {
                // First process:
                // Delete putty.exe to disable prompt that deletes settings (we want to keep them).
                var proc = new Process();
                proc.StartInfo.FileName = "cmd.exe";
                proc.StartInfo.Arguments = "/C del \""
                    + System.IO.Path.Combine(detected.installPath, "putty.exe") + "\"";
                processes.Add(proc);
                // second process: uninstall old PuTTY
                proc = new Process();
                proc.StartInfo.FileName = System.IO.Path.Combine(detected.installPath, "unins000.exe");
                proc.StartInfo.Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART";
                processes.Add(proc);
            }
            // Uninstallation process for MSI packages (0.68 and later):
            else
            {
                var re = new Regex("\\{[0-9A-F]{8}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{4}\\-[0-9A-F]{12}\\}", RegexOptions.IgnoreCase);
                Match m = re.Match(detected.uninstallString);
                if (!m.Success)
                {
                    logger.Error("Could not extract GUID of old PuTTY version for pre-update process.");
                    return null;
                }
                var proc = new Process();
                proc.StartInfo.FileName = "msiexec.exe";
                proc.StartInfo.Arguments = "/X" + m.Value + " /qn /norestart";
                processes.Add(proc);
            }
            return processes;
        }


        /// <summary>
        /// whether the detected software is older than the newest known software
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            // Simple version string comparison.
            return string.Compare(detected.displayVersion, info().newestVersion, true) < 0;
        }
    } // class
} // namespace
