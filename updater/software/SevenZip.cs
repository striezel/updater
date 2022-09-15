/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2021, 2022  Dirk Stolle

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
    /// 7-Zip update management class
    /// </summary>
    public class SevenZip : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for SevenZip class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(SevenZip).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public SevenZip(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("7-Zip",
                "22.01",
                "^7\\-Zip [0-9]+\\.[0-9]{2}$",
                "^7\\-Zip [0-9]+\\.[0-9]{2} \\(x64\\)$",
                new InstallInfoExe(
                    "https://www.7-zip.org/a/7z2201.exe",
                    HashAlgorithm.SHA256,
                    "8c8fbcf80f0484b48a07bd20e512b103969992dbf81b6588832b08205e3a1b43",
                    Signature.None,
                    "/S"),
                new InstallInfoExe(
                    "https://www.7-zip.org/a/7z2201-x64.exe",
                    HashAlgorithm.SHA256,
                    "b055fee85472921575071464a97a79540e489c1c3a14b9bdfbdbab60e17f36e4",
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
            return new string[] { "7zip", "7-zip", "sevenzip" };
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
            logger.Info("Searching for newer version of 7-Zip...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://www.7-zip.org/");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of 7-Zip: " + ex.Message);
                return null;
            }

            var reVersion = new Regex("<A href=\"a/7z[0-9]{4}.exe\">Download</A>", RegexOptions.IgnoreCase);
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;

            string version = matchVersion.Value.Replace("<A href=\"a/7z", "")
                .Replace(".exe\">Download</A>", "").Trim();
            version = version.Substring(0, 2) + "." + version.Substring(2, 2);

            // construct new information
            var newInfo = knownInfo();
            if (newInfo.newestVersion == version)
            {
                // No need to change things here, it is still the same version.
                return newInfo;
            }
            newInfo.newestVersion = version;
            string newVersionWithoutDot = version.Replace(".", "");
            // 32 bit
            newInfo.install32Bit.downloadUrl = "https://www.7-zip.org/a/7z" + newVersionWithoutDot + ".exe";
            // The official 7-zip.org site does not provide any checksums,
            // so we have to do without.
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install32Bit.checksum = null;
            // 64 bit
            newInfo.install64Bit.downloadUrl = "https://www.7-zip.org/a/7z" + newVersionWithoutDot + "-x64.exe";
            // The official 7-zip.org site does not provide any checksums,
            // so we have to do without.
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install64Bit.checksum = null;
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
