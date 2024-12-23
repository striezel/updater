/*
    This file is part of the updater command line interface.
    Copyright (C) 2024  Dirk Stolle

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
    /// Handles updates of Stellarium.
    /// </summary>
    public class Stellarium : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Stellarium class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Stellarium).FullName);


        /// <summary>
        /// publisher name for signed executables
        /// </summary>
        private const string publisherX509 = "CN=SignPath Foundation, O=SignPath Foundation, L=Lewes, S=Delaware, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2026, 2, 9, 10, 48, 49, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public Stellarium(bool autoGetNewer)
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
            return new AvailableSoftware("Stellarium",
                "24.4",
                "^Stellarium [0-9]+\\.[0-9]+$",
                "^Stellarium [0-9]+\\.[0-9]+$",
                new InstallInfoExe(
                    "https://github.com/Stellarium/stellarium/releases/download/v24.4/stellarium-24.4-qt5-win32.exe",
                    HashAlgorithm.SHA256,
                    "71b620f40b330af0444791181684942df7b8bd51c73b72a32b3e2c3d0109a127",
                    signature,
                    "/VERYSILENT /ALLUSERS /NORESTART"),
                new InstallInfoExe(
                    "https://github.com/Stellarium/stellarium/releases/download/v24.4/stellarium-24.4-qt6-win64.exe",
                    HashAlgorithm.SHA256,
                    "c52a7a2da4e0639457d1c4a2010d4bdbf47594710fac179fdfa69718d83bc36b",
                    signature,
                    "/VERYSILENT /ALLUSERS /NORESTART"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["stellarium"];
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
            logger.Info("Searching for newer version of Stellarium...");

            string html;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://github.com/Stellarium/stellarium/releases");
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Stellarium: " + ex.Message);
                return null;
            }

            // HTML text will contain links to releases like "https://github.com/Stellarium/stellarium/releases/tag/v24.3".
            var reVersion = new Regex("stellarium/releases/tag/v([0-9]+\\.[0-9])\"");
            var matchesVersion = reVersion.Matches(html);
            if (matchesVersion.Count == 0)
                return null;
            string version = matchesVersion[0].Groups[1].Value;

            // Checksum will be in a HTML table after the name of the executable, e. g. "stellarium-24.3-qt6-win64.exe".
            int exe_pos = html.IndexOf("stellarium-" + version + "-qt6-win64.exe");
            if (exe_pos == -1)
                return null;

            var reChecksum = new Regex("[0-9a-f]{64}");
            var matchChecksum = reChecksum.Match(html, exe_pos);
            if (!matchChecksum.Success)
                return null;
            string newHash64Bit = matchChecksum.Value;

            // Checksum will be in a HTML table after the name of the executable, e. g. "stellarium-24.3-qt5-win32.exe".
            exe_pos = html.IndexOf("stellarium-" + version + "-qt5-win32.exe");
            if (exe_pos == -1)
                return null;
            matchChecksum = reChecksum.Match(html, exe_pos);
            if (!matchChecksum.Success)
                return null;
            string newHash32Bit = matchChecksum.Value;

            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = version;
            // Construct download URL for 64-bit build of Stellarium,
            // e.g. https://github.com/Stellarium/stellarium/releases/download/v24.3/stellarium-24.3-qt6-win64.exe
            newInfo.install64Bit.downloadUrl = "https://github.com/Stellarium/stellarium/releases/download/v" + version + "/stellarium-" + version + "-qt6-win64.exe";
            newInfo.install64Bit.checksum = newHash64Bit;
            // Construct download URL for 32-bit build of Stellarium,
            // e.g. https://github.com/Stellarium/stellarium/releases/download/v24.3/stellarium-24.3-qt5-win32.exe
            newInfo.install32Bit.downloadUrl = "https://github.com/Stellarium/stellarium/releases/download/v" + version + "/stellarium-" + version + "-qt5-win32.exe";
            newInfo.install32Bit.checksum = newHash32Bit;
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
            return ["stellarium"];
        }
    }
}
