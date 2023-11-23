/*
    This file is part of the updater command line interface.
    Copyright (C) 2023  Dirk Stolle

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
    /// Handles updates of HexChat.
    /// </summary>
    public class HexChat : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for HexChat class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(HexChat).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public HexChat(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("HexChat",
                "2.16.1",
                "^HexChat$",
                "^HexChat$",
                new InstallInfoExe(
                    "https://dl.hexchat.net/hexchat/HexChat%202.16.1%20x86.exe",
                    HashAlgorithm.SHA256,
                    "ab6db5c0cdd0a1ddd80dd7124430a6b56d75905859e4bab68c973837171c6161",
                    Signature.None,
                    "/VERYSILENT /NORESTART"),
                new InstallInfoExe(
                    "https://dl.hexchat.net/hexchat/HexChat%202.16.1%20x64.exe",
                    HashAlgorithm.SHA256,
                    "4b47930951ebc46e9cb8e8201856b8bddcd7499f5510fe1059f67d65cc80bf07",
                    Signature.None,
                    "/VERYSILENT /NORESTART")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "hexchat" };
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
            logger.Info("Searching for newer version of HexChat...");
            // Just getting the latest release does not work here, because that may also be a release candidate, and we do not want that.
            string html;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://hexchat.github.io/downloads.html");
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of HexChat: " + ex.Message);
                return null;
            }

            // HTML text will contain hashes like "4b47930951ebc46e9cb8e8201856b8bddcd7499f5510fe1059f67d65cc80bf07  HexChat 2.16.1 x64.exe".
            var reVersion = new Regex("([0-9a-f]{64})  HexChat ([0-9]+\\.[0-9]+\\.[0-9]+) x64\\.exe");
            var matchVersion = reVersion.Match(html);
            if (!matchVersion.Success)
                return null;
            string hash_64_bit = matchVersion.Groups[1].Value;
            string current_version = matchVersion.Groups[2].Value;

            reVersion = new Regex("([0-9a-f]{64})  HexChat ([0-9]+\\.[0-9]+\\.[0-9]+) x86\\.exe");
            matchVersion = reVersion.Match(html);
            if (!matchVersion.Success)
                return null;
            string hash_32_bit = matchVersion.Groups[1].Value;

            var new_info = knownInfo();
            string old_version = new_info.newestVersion;

            new_info.newestVersion = current_version;
            new_info.install32Bit.checksum = hash_32_bit;
            new_info.install32Bit.downloadUrl = new_info.install32Bit.downloadUrl.Replace(old_version, current_version);
            new_info.install64Bit.checksum = hash_64_bit;
            new_info.install64Bit.downloadUrl = new_info.install64Bit.downloadUrl.Replace(old_version, current_version);

            return new_info;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(2)
            {
                "hexchat", // HexChat itself
                "thememan" // theme manager
            };
        }
    } // class
} // namespace
