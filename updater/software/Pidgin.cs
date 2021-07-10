/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
using System.Net;
using System.Text.RegularExpressions;
using updater.data;
using updater.utility;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Pidgin instant messaging client.
    /// </summary>
    public class Pidgin : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Pidgin class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Pidgin).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Pidgin(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Gary Kramlich, O=Gary Kramlich, STREET=2653 N 54TH ST, L=MILWAUKEE, S=Wisconsin, PostalCode=53210, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 3, 21, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "2.14.6";
            return new AvailableSoftware("Pidgin",
                version,
                "^Pidgin$",
                null,
                // Pidgin only has an installer for 32 bit.
                new InstallInfoPidgin(
                    "https://netcologne.dl.sourceforge.net/project/pidgin/Pidgin/" + version + "/pidgin-" + version + "-offline.exe",
                    HashAlgorithm.SHA256,
                    "d031f64236c1de4e9d91bc51cdc604e8ca29953f453898ef047f2e785390d426",
                    new Signature(publisherX509, certificateExpiration),
                    "/DS=1 /SMS=1 /S"),
                null
                );
        }


        /// <summary>
        /// Gets a collection of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "pidgin" };
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
            logger.Info("Searching for newer version of Pidgin...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://pidgin.im/install/");
                }
                catch (Exception ex)
                {
                    logger.Error("Exception occurred while checking for newer version of Pidgin: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            Regex reVersion = new Regex("href=\"https://sourceforge\\.net/projects/pidgin/files/Pidgin/([0-9]+\\.[0-9]+\\.[0-9]+)/pidgin\\-([0-9]+\\.[0-9]+\\.[0-9]+)\\.exe\"");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string v1 = matchVersion.Groups[1].Value;
            string v2 = matchVersion.Groups[2].Value;
            if (v1 != v2)
            {
                logger.Error("Error: There are two different version numbers in Pidgin's download URL!");
                return null;
            }
            string version = v1;

            // construct new information
            var newInfo = knownInfo();
            string oldVersion = newInfo.newestVersion;
            // If newest version is the same as the old version, then keep the known information.
            // That way the known checksum will be preserved.
            if (version == oldVersion)
                return newInfo;
            newInfo.newestVersion = version;
            // Try to get checksum.
            htmlCode = null;
            using (var client = new TimelyWebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://netcologne.dl.sourceforge.net/project/pidgin/Pidgin/" + version + "/pidgin-" + version + "-offline.exe.sha256sum");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while retrieving checksum for newer version of Pidgin: " + ex.Message);
                }
                client.Dispose();
            } // using
            string checksum32 = null;
            if (htmlCode != null)
            {
                var hashRegEx = new Regex("[0-9a-f]{64} [ \\*]pidgin-" + Regex.Escape(version) + "-offline.exe");
                var match = hashRegEx.Match(htmlCode);
                if (match.Success)
                {
                    checksum32 = match.Value.Substring(0, 64);
                }
            }
            // 32 bit
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, version);
            if (checksum32 != null)
            {
                newInfo.install32Bit.checksum = checksum32;
                newInfo.install32Bit.algorithm = HashAlgorithm.SHA256;
            }
            else
            {
                // No checksum, only signature.
                newInfo.install32Bit.checksum = null;
                newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
                newInfo.install32Bit.signature = Signature.NeverExpires(publisherX509);
            }
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
            return new List<string>(1) { "pidgin" };
        }

    } // class
} // namespace
