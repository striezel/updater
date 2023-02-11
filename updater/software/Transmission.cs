/*
    This file is part of the updater command line interface.
    Copyright (C) 2021, 2023  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Transmission, a BitTorrent client.
    /// </summary>
    public class Transmission : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Transmission class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Transmission).FullName);


        /// <summary>
        /// publisher name for signed installers
        /// </summary>
        private const string publisherX509 = "CN=SignPath Foundation, OU=sig.fo/Transmission, O=SignPath Foundation, L=Lewes, S=Delaware, C=US";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private readonly DateTime certificateExpiration = new(2023, 5, 13, 18, 16, 53, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public Transmission(bool autoGetNewer)
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
            return new AvailableSoftware("Transmission",
                "3.00",
                "^Transmission [0-9]+\\.[0-9]+ \\([0-9a-f]+\\) \\(x86\\)$",
                "^Transmission [0-9]+\\.[0-9]+ \\([0-9a-f]+\\) \\(x64\\)$",
                new InstallInfoMsi(
                    "https://github.com/transmission/transmission/releases/download/3.00/transmission-3.00-x86.msi",
                    HashAlgorithm.SHA256,
                    "eeab85327fa8a1299bb133d5f60f6674ca9e76522297202bbe39aae92dad4f32",
                    signature,
                    "/qn /norestart"),
                new InstallInfoMsi(
                    "https://github.com/transmission/transmission/releases/download/3.00/transmission-3.00-x64.msi",
                    HashAlgorithm.SHA256,
                    "c34828a6d2c50c7c590d05ca50249b511d46e9a2a7223323fb3d1421e3f6b9d1",
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
            return new string[] { "transmission", "transmission-qt" };
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
            logger.Info("Searching for newer version of Transmission...");
            string html;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://transmissionbt.com/download");
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Transmission: " + ex.Message);
                return null;
            }

            // Download page should contain embedded JSON with version, something
            // like '"softwareVersion": ["3.00"]' or similar.
            var reVersion = new Regex("\"softwareVersion\":\\s*\\[\"([0-9]+\\.[0-9]+\\.[0-9]+)\"\\]");
            var matchVersion = reVersion.Match(html);
            if (!matchVersion.Success)
                return null;
            string currentVersion = matchVersion.Groups[1].Value;

            // find SHA256 hash for 32 bit installer
            // Hash is something like 
            // 'Transmission-3.00-x86.msi: <a href="https://www.virustotal.com/en/file/eeab85327fa8a1299bb133d5f60f6674ca9e76522297202bbe39aae92dad4f32/analysis">eeab85327fa8a1299bb133d5f60f6674ca9e76522297202bbe39aae92dad4f32</a>'
            string escapedVersion = Regex.Escape(currentVersion);
            var reHash = new Regex("[Tt]ransmission\\-" + escapedVersion + "\\-x86\\.msi</th>\\s+<td class=\"card\\-text font\\-monospace\">\\s?<a\\s+href=\"https://www\\.virustotal\\.com/en/file/([a-f0-9]{64})/analysis\">");
            Match matchHash = reHash.Match(html);
            if (!matchHash.Success)
                return null;
            string newHash32Bit = matchHash.Groups[1].Value;
            // find SHA256 hash for 64 bit installer
            // Hash is something like 
            // 'Transmission-3.00-x64.msi: <a href="https://www.virustotal.com/en/file/c34828a6d2c50c7c590d05ca50249b511d46e9a2a7223323fb3d1421e3f6b9d1/analysis">c34828a6d2c50c7c590d05ca50249b511d46e9a2a7223323fb3d1421e3f6b9d1</a>'
            reHash = new Regex("[Tt]ransmission\\-" + escapedVersion + "\\-x64\\.msi</th>\\s+<td class=\"card\\-text font\\-monospace\">\\s?<a\\s+href=\"https://www\\.virustotal\\.com/en/file/([a-f0-9]{64})/analysis\">");
            matchHash = reHash.Match(html);
            if (!matchHash.Success)
                return null;
            string newHash64Bit = matchHash.Groups[1].Value;
            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = currentVersion;
            // e. g. https://github.com/transmission/transmission/releases/download/3.00/transmission-3.00-x86.msi
            newInfo.install32Bit.downloadUrl = "https://github.com/transmission/transmission/releases/download/" + currentVersion + "/transmission-" + currentVersion + "-x86.msi";
            newInfo.install32Bit.checksum = newHash32Bit;
            // e. g. https://github.com/transmission/transmission/releases/download/3.00/transmission-3.00-x64.msi
            newInfo.install64Bit.downloadUrl = "https://github.com/transmission/transmission/releases/download/" + currentVersion + "/transmission-" + currentVersion + "-x64.msi";
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
                "transmission-qt"
            };
        }
    } // class
} // namespace
