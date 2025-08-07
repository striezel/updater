﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
    /// Manages updates for Opera browser.
    /// </summary>
    public class Opera : Improved64BitDetectionSoftware
    {
        /// <summary>
        /// NLog.Logger for Opera class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Opera).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Opera(bool autoGetNewer)
            : base(autoGetNewer, "opera.exe")
        { }


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Opera Norway AS, O=Opera Norway AS, L=Oslo, S=Oslo, C=NO, SERIALNUMBER=916 368 127, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=NO";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2026, 5, 29, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string silentOptions = "/silent /norestart /launchopera 0 /setdefaultbrowser 0 /enable-stats 0 /enable-installer-stats 0 /pintotaskbar 0 /pin-additional-shortcuts 0 /allusers";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Opera",
                "120.0.5543.161",
                "^Opera Stable [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                "^Opera Stable [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                new InstallInfoExe(
                    "https://get.geo.opera.com/pub/opera/desktop/120.0.5543.161/win/Opera_120.0.5543.161_Setup.exe",
                    HashAlgorithm.SHA256,
                    "22c18bfb13ae9cbf6ad912163096ff393ade56199adb8805de132052fcd07ae4",
                    signature,
                    silentOptions),
                new InstallInfoExe(
                    "https://get.geo.opera.com/pub/opera/desktop/120.0.5543.161/win/Opera_120.0.5543.161_Setup_x64.exe",
                    HashAlgorithm.SHA256,
                    "f342148612b3292e461508b30291d0efcd051d37dca1780ef22f696203eac870",
                    signature,
                    silentOptions)
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["opera"];
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
            logger.Info("Searching for newer version of Opera...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://get.geo.opera.com/pub/opera/desktop/");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Opera: " + ex.Message);
                return null;
            }

            // Search for all known versions.
            var reVersion = new Regex("\"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/\"");
            var matches = reVersion.Matches(htmlCode);
            if (matches.Count == 0)
                return null;
            // Add found versions to a list ...
            var versions = new List<versions.Quartet>();
            foreach (Match match in matches)
            {
                if (!match.Success)
                    return null;
                string version = match.Value[1..].Replace("/\"", "");
                versions.Add(new versions.Quartet(version));
            }
            // ... and sort them from earliest to latest.
            versions.Sort();

            // Now find the latest version that already has a win/ directory
            // containing a checksum file for the 64-bit build.
            string newVersion = null;
            for (int i = versions.Count - 1; i >= 0; i--)
            {
                bool exists;
                try
                {
                    var fullVersion = versions[i].full();
                    var task = client.GetStringAsync("https://get.geo.opera.com/pub/opera/desktop/" + fullVersion + "/win/Opera_" + fullVersion + "_Setup_x64.exe.sha256sum");
                    task.Wait();
                    htmlCode = task.Result;
                    exists = true;
                }
                catch (Exception)
                {
                    // Not found.
                    exists = false;
                }
                if (exists)
                {
                    newVersion = versions[i].full();
                    break;
                } // if
            } // for

            if (null == newVersion)
                return null;

            var newInfo = knownInfo();
            if (newVersion == newInfo.newestVersion)
                return newInfo;

            // Look into "https://get.geo.opera.com/pub/opera/desktop/<version>/win/Opera_<version>_Setup_x64.exe.sha256sum"
            // to get the checksum for 64-bit installer.
            try
            {
                var task = client.GetStringAsync("https://get.geo.opera.com/pub/opera/desktop/" + newVersion + "/win/Opera_" + newVersion + "_Setup_x64.exe.sha256sum");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while finding checksums for newer version of Opera: " + ex.Message);
                return null;
            }

            // checksum for 64-bit installer
            var reg = new Regex("[0-9a-f]{64}");
            Match m = reg.Match(htmlCode);
            if (!m.Success)
                return null;
            string checksum64 = m.Value;

            // Look into "https://get.geo.opera.com/pub/opera/desktop/<version>/win/Opera_<version>_Setup.exe.sha256sum"
            // to get the checksum for 32-bit installer.
            try
            {
                var task = client.GetStringAsync("https://get.geo.opera.com/pub/opera/desktop/" + newVersion + "/win/Opera_" + newVersion + "_Setup.exe.sha256sum");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while finding checksums for newer version of Opera: " + ex.Message);
                return null;
            }

            // checksum for 32-bit installer
            m = reg.Match(htmlCode);
            if (!m.Success)
                return null;
            string checksum32 = m.Value;

            // Construct new version information based on old information.
            // Replace version number - both as newest version and in URL for download.
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = checksum32;
            newInfo.install32Bit.algorithm = HashAlgorithm.SHA256;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = checksum64;
            newInfo.install64Bit.algorithm = HashAlgorithm.SHA256;
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
            return [];
        }
    } // class
} // namespace
