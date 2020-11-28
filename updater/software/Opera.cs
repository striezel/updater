/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020  Dirk Stolle

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
using updater.data;
using System.Net;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Opera browser.
    /// </summary>
    public class Opera : NoPreUpdateProcessSoftware
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
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string silentOptions = "/silent /norestart /launchopera 0 /setdefaultbrowser 0 /enable-stats 0 /enable-installer-stats 0 /pintotaskbar 0 /pin-additional-shortcuts 0 /allusers";
            return new AvailableSoftware("Opera",
                "71.0.3770.198",
                "^Opera Stable [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                "^Opera Stable [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$",
                new InstallInfoExe(
                    "https://get.geo.opera.com/pub/opera/desktop/71.0.3770.198/win/Opera_71.0.3770.198_Setup.exe",
                    HashAlgorithm.SHA256,
                    "8201129f56d23074a14ecd470432ae1f1233f33c8a999a1e9a43197c52059adf",
                    null,
                    silentOptions),
                new InstallInfoExe(
                    "https://get.geo.opera.com/pub/opera/desktop/71.0.3770.198/win/Opera_71.0.3770.198_Setup_x64.exe",
                    HashAlgorithm.SHA256,
                    "7b56d84cf8226bb5833811eb5f3a446272f4568849308fe76ca08b1b003b7d3d",
                    null,
                    silentOptions)
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "opera" };
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
            logger.Debug("Searching for newer version of Opera...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://get.geo.opera.com/pub/opera/desktop/");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Opera: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // Search for all known versions.
            Regex reVersion = new Regex("\"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/\"");
            var matches = reVersion.Matches(htmlCode);
            if (matches.Count == 0)
                return null;
            // Add found versions to a list ...
            List<versions.Quartet> versions = new List<versions.Quartet>();
            foreach (Match match in matches)
            {
                if (!match.Success)
                    return null;
                string version = match.Value.Substring(1).Replace("/\"", "");
                versions.Add(new versions.Quartet(version));
            }
            // ... and sort them from earliest to latest.
            versions.Sort();

            // Now find the latest version that already has a win/ directory.
            string newVersion = null;
            for (int i = versions.Count - 1; i >= 0; i--)
            {
                bool exists = false;
                using (var client = new WebClient())
                {
                    try
                    {
                        htmlCode = client.DownloadString("https://get.geo.opera.com/ftp/pub/opera/desktop/" + versions[i].full() + "/win/");
                        exists = true;
                    }
                    catch (Exception)
                    {
                        // Not found.
                        exists = false;
                    }
                    client.Dispose();
                } // using
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

            // Look into "https://get.geo.opera.com/ftp/pub/opera/desktop/<version>/win/Opera_<version>_Setup_x64.exe.sha256sum"
            // to get the checksum for 64 bit installer.
            htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://get.geo.opera.com/ftp/pub/opera/desktop/" + newVersion + "/win/Opera_" + newVersion + "_Setup_x64.exe.sha256sum");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while finding checksums for newer version of Opera: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // checksum for 64 bit installer
            Regex reg = new Regex("[0-9a-f]{64}");
            Match m = reg.Match(htmlCode);
            if (!m.Success)
                return null;
            string checksum64 = m.Value;

            // Look into "https://get.geo.opera.com/ftp/pub/opera/desktop/<version>/win/Opera_<version>_Setup.exe.sha256sum"
            // to get the checksum for 32 bit installer.
            htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://get.geo.opera.com/ftp/pub/opera/desktop/" + newVersion + "/win/Opera_" + newVersion + "_Setup.exe.sha256sum");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while finding checksums for newer version of Opera: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // checksum for 32 bit installer
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
            return new List<string>();
        }
    } // class
} // namespace
