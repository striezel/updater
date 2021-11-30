/*
    This file is part of the updater command line interface.
    Copyright (C) 2021  Dirk Stolle

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

namespace updater.software
{
    /// <summary>
    /// Handles updates of TreeSize Free.
    /// </summary>
    public class TreeSizeFree : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for TreeSizeFree class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(TreeSizeFree).FullName);


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=JAM Software GmbH, O=JAM Software GmbH, STREET=Am Wissenschaftspark 26, L=Trier, S=Rheinland-Pfalz, C=DE, OID.1.3.6.1.4.1.311.60.2.1.1=Wittlich, OID.1.3.6.1.4.1.311.60.2.1.2=Rheinland-Pfalz, OID.1.3.6.1.4.1.311.60.2.1.3=DE, SERIALNUMBER=HRB 4920, OID.2.5.4.15=Private Organization";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2022, 1, 29, 16, 49, 49, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public TreeSizeFree(bool autoGetNewer)
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
            var info = new InstallInfoExe(
                "https://downloads.jam-software.de/treesize_free/TreeSizeFreeSetup.exe",
                HashAlgorithm.SHA256,
                "4de19445df877ef4df981fbead9440cf4a8832a284ea0e753ff1e7dd41dc10fa",
                signature,
                "/VERYSILENT /NORESTART");
            return new AvailableSoftware("TreeSize Free",
                "4.5.3",
                "^TreeSize Free V[0-9]+\\.[0-9]+(\\.[0-9]+)?$",
                "^TreeSize Free V[0-9]+\\.[0-9]+(\\.[0-9]+)?$",
                info,
                info);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "treesizefree", "treesize" };
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
            logger.Info("Searching for newer version of TreeSize Free...");
            // Just getting the latest release does not work here, because that may also be a release candidate, and we do not want that.
            string html;
            using (var client = new WebClient())
            {
                try
                {
                    html = client.DownloadString("https://customers.jam-software.de/downloadTrial.php?language=DE&article_no=80");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of TreeSize Free: " + ex.Message);
                    return null;
                }
            }

            // HTML text will contain something like "<b>TreeSize Free V4.42</b>".
            Regex reVersion = new Regex("<b>TreeSize Free V([0-9]+\\.[0-9]+)</b>");
            var matchVersion = reVersion.Match(html);
            if (!matchVersion.Success)
                return null;
            string currentVersion = matchVersion.Groups[1].Value;
            // The version number on the website is a bit weird, because a version "4.42" actually means
            // version "4.4.2", so we have to split the second part manually here.
            int dotIndex = currentVersion.IndexOf('.');
            if (dotIndex >= 0)
            {
                string partTwo = currentVersion.Substring(dotIndex + 1);
                if (partTwo.Length == 2)
                {
                    currentVersion = currentVersion.Substring(0, dotIndex) + '.' + partTwo[0] + '.' + partTwo[1];
                }
            }

            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = currentVersion;
            // There are no official checksums, so we have to use the certificate instead.
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install32Bit.signature = Signature.NeverExpires(publisherX509);
            newInfo.install64Bit.checksum = null;
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install64Bit.signature = Signature.NeverExpires(publisherX509);
            // The download URL stays the same, it just points to the newest version.
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
                "TreeSizeFree"
            };
        }
    } // class
} // namespace
