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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of ShareX.
    /// </summary>
    public class ShareX : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for ShareX class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(ShareX).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public ShareX(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var installer = new InstallInfoExe(
                "https://github.com/ShareX/ShareX/releases/download/v18.0.1/ShareX-18.0.1-setup.exe",
                HashAlgorithm.SHA256,
                "9344D713095CCFF0829B6E2C83E75C3DB0279EDA0780EADFA287B510521A12B5",
                Signature.None,
                "/SP- /VERYSILENT /NORESTART /UPDATE /NORUN");
            return new AvailableSoftware("ShareX",
                "18.0.1",
                "^ShareX$",
                "^ShareX$",
                installer,
                installer);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["sharex"];
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
            logger.Info("Searching for newer version of ShareX...");
            string html;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://github.com/ShareX/ShareX/releases/latest");
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of ShareX: " + ex.Message);
                return null;
            }

            // HTML text will contain links to releases like "https://github.com/ShareX/ShareX/releases/download/v16.1.0/ShareX-16.1.0-setup.exe".
            var reVersion = new Regex("ShareX/releases/tag/v([0-9]+\\.[0-9]+\\.[0-9]+)\"");
            var matchVersion = reVersion.Match(html);
            if (!matchVersion.Success)
                return null;
            string newVersion = matchVersion.Groups[1].Value;

            /* Checksum is in HTML part that looks like
             * <td>ShareX-16.1.0-setup.exe</td>
             * <td><code>8F082B1939AF2894FEA681E6E807E577D15EA546FC0231F84720AC62867CA7F4</code></td>
             */
            int idx = html.IndexOf("ShareX-" + newVersion + "-setup.exe");
            if (idx < 0)
            {
                return null;
            }
            string escapedVersion = Regex.Escape(newVersion);
            Regex reHash = new("<td>ShareX\\-" + escapedVersion + "\\-setup\\.exe</td>\r?\n<td><code>([a-fA-F0-9]{64})</code></td>");
            Match matchHash = reHash.Match(html);
            if (!matchHash.Success)
            {
                return null;
            }
            string newHash = matchHash.Groups[1].Value;
            // construct new information
            var newInfo = knownInfo();

            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(newInfo.newestVersion, newVersion);
            newInfo.install64Bit.checksum = newHash;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(newInfo.newestVersion, newVersion);
            newInfo.install32Bit.checksum = newHash;
            newInfo.newestVersion = newVersion;
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
            return ["ShareX"];
        }
    } // class
} // namespace
