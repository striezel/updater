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

using updater.data;
using System;
using System.Net;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using updater.utility;
using System.Net.Http;

namespace updater.software
{
    /// <summary>
    /// Handles updates of the Notepad++ text editor.
    /// </summary>
    public class NotepadPlusPlus : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for NotepadPlusPlus class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(NotepadPlusPlus).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public NotepadPlusPlus(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher name for signed binaries
        /// </summary>
        private const string publisherX509 = "CN=\"Notepad++\", O=\"Notepad++\", L=Saint Cloud, S=Ile-de-France, C=FR";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2025, 5, 14, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            // Both version and tag are usually the same, except for major releases like 8.0.
            const string version = "8.6.5";
            const string tag = "8.6.5";
            return new AvailableSoftware("Notepad++",
                version,
                "^Notepad\\+\\+ \\(32\\-bit x86\\)$|^Notepad\\+\\+$",
                "^Notepad\\+\\+ \\(64\\-bit x64\\)$",
                new InstallInfoExe(
                    "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v" + tag + "/npp." + version + ".Installer.exe",
                    HashAlgorithm.SHA256,
                    "5180a17f24df75ccc000cdc2904b14c865ccfd7521909bf06cc75189a65c3e2f",
                    signature,
                    "/S"),
                new InstallInfoExe(
                    "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v" + tag + "/npp." + version + ".Installer.x64.exe",
                    HashAlgorithm.SHA256,
                    "eedf45e0803ce36c4b745e54fc7a7136d9b364c2a795e646548a4350cf88a366",
                    signature,
                    "/S")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "notepad++" };
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
            logger.Info("Searching for newer version of Notepad++...");
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            string currentVersion;
            try
            {
                var task = httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Head, "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest"));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                task = null;
                // Location header will point to something like "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v7.9.1".
                var reVersion = new Regex("v[0-9]+(\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?)?$");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                currentVersion = matchVersion.Value.Remove(0, 1);
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Notepad++: " + ex.Message);
                return null;
            }

            string versionNumber = currentVersion.Contains('.') ? currentVersion : currentVersion + ".0";

            // download checksum file, e.g. "http://download.notepad-plus-plus.org/repository/7.x/7.7/npp.7.7.checksums.sha256"
            //                           or for GitHub releases: "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.9.1/npp.7.9.1.checksums.sha256"
            string htmlCode = null;
            using (var client = new TimelyWebClient())
            {
                try
                {
                    // Use GitHub releases for download of checksum file,
                    // because GitHub has a valid TLS certificate for HTTPS
                    // while the domain download.notepad-plus-plus.org does
                    // not and can only be accessed via HTTP.
                    // But we want HTTPS / TLS for the checksum download.
                    htmlCode = client.DownloadString("https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v" + currentVersion + "/npp." + versionNumber + ".checksums.sha256");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Notepad++: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // find SHA256 hash for 32 bit installer
            var reHash = new Regex("[a-f0-9]{64}  npp.+Installer\\.exe");
            Match matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash32Bit = matchHash.Value[..64];
            // find SHA256 hash for 64 bit installer
            reHash = new Regex("[a-f0-9]{64}  npp.+Installer\\.x64\\.exe");
            matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash64Bit = matchHash.Value[..64];
            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = versionNumber;
            // e. g. https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.9.1/npp.7.9.1.Installer.exe
            newInfo.install32Bit.downloadUrl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v" + currentVersion + "/npp." + versionNumber + ".Installer.exe";
            newInfo.install32Bit.checksum = newHash32Bit;
            // e. g. https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.9.1/npp.7.9.1.Installer.x64.exe
            newInfo.install64Bit.downloadUrl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v" + versionNumber + "/npp." + versionNumber + ".Installer.x64.exe";
            newInfo.install64Bit.checksum = newHash64Bit;
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
                "notepad++"
            };
        }

    } // class
} // namespace
