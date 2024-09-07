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
using System.Text.RegularExpressions;
using updater.data;
using updater.software.gitlab_api;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Handles updates of LibreWolf, a Firefox fork.
    /// </summary>
    public class LibreWolf : Improved64BitDetectionSoftware
    {
        /// <summary>
        /// NLog.Logger for LibreWolf class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(LibreWolf).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public LibreWolf(bool autoGetNewer)
            : base(autoGetNewer, "librewolf.exe")
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("LibreWolf",
                "130.0-2",
                "^LibreWolf$",
                "^LibreWolf$",
                new InstallInfoExe(
                    "https://gitlab.com/api/v4/projects/44042130/packages/generic/librewolf/130.0-2/librewolf-130.0-2-windows-i686-setup.exe",
                    HashAlgorithm.SHA256,
                    "f4e8001547bb240307e4ad9c9b1860b96afa3dbe1fe2db5d05ed89e770b14bfb",
                    Signature.None,
                    "/S"),
                new InstallInfoExe(
                    "https://gitlab.com/api/v4/projects/44042130/packages/generic/librewolf/130.0-2/librewolf-130.0-2-windows-x86_64-setup.exe",
                    HashAlgorithm.SHA256,
                    "64db1671c8a60144f67dfb7c48fd1b77f831dd7f77eed79a8d3440697badb563",
                    Signature.None,
                    "/S")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "librewolf" };
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
        /// Tries to find the newest version number of LibreWolf.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        private static ShrinkingDashedQuartet determineNewestRelease()
        {
            string url = "https://gitlab.com/api/v4/projects/44042130/releases/";
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                var response = task.Result;
                var releases = JsonConvert.DeserializeObject<IList<Release>>(response);
                if (releases != null && releases.Count > 0)
                {
                    return new ShrinkingDashedQuartet(releases[0].name);
                }

                return new ShrinkingDashedQuartet();
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer LibreWolf version: " + ex.Message);
                return new ShrinkingDashedQuartet();
            }
        }

        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searcing for newer version of LibreWolf...");
            var newerVersion = determineNewestRelease();
            var known = knownInfo();
            var knownVersion = new ShrinkingDashedQuartet(known.newestVersion);
            if (knownVersion > newerVersion)
                return known;

            // Checksums are available under an URL like https://gitlab.com/api/v4/projects/44042130/packages/generic/librewolf/119.0-7/sha256sums.txt.
            var client = HttpClientProvider.Provide();
            string full_version = newerVersion.full();
            string response;
            try
            {
                var task = client.GetStringAsync("https://gitlab.com/api/v4/projects/44042130/packages/generic/librewolf/" + full_version + "/sha256sums.txt");
                task.Wait();
                response = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer LibreWolf version: " + ex.Message);
                return null;
            }

            // Find checksums.
            // The 32-bit installer checksum is listed in a line like
            // "068650cc45da848ac31500e0525063de00068f5a09bebc59d1f36d34e5a8851a  librewolf-119.0-6-windows-i686-setup.exe".
            var regEx = new Regex("[0-9a-f]{64}  librewolf\\-" + Regex.Escape(full_version) + "\\-windows\\-i686\\-setup.exe");
            Match match = regEx.Match(response);
            if (!match.Success)
                return null;
            known.install32Bit.checksum = match.Value[..64];
            known.install32Bit.downloadUrl = known.install32Bit.downloadUrl.Replace(known.newestVersion, full_version);

            // The 64-bit installer checksum is listed in a line like
            // "b9a241ead1c8ce53785087081a2b2b69af0222515cb99fb3a38b6cefd9fff812  librewolf-119.0-6-windows-x86_64-setup.exe"
            regEx = new Regex("[0-9a-f]{64}  librewolf\\-" + Regex.Escape(full_version) + "\\-windows\\-x86_64\\-setup.exe");
            match = regEx.Match(response);
            if (!match.Success)
                return null;
            known.install64Bit.checksum = match.Value[..64];
            known.install64Bit.downloadUrl = known.install64Bit.downloadUrl.Replace(known.newestVersion, full_version);

            known.newestVersion = full_version;
            return known;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
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
            // Simple version string comparison may not be enough, so use the
            // parsed version numbers instead.
            var verDetected = new ShrinkingDashedQuartet(detected.displayVersion);
            var verNewest = new ShrinkingDashedQuartet(info().newestVersion);
            return verDetected < verNewest;
        }
    }
}
