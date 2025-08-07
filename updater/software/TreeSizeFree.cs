﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2021, 2022, 2023, 2024  Dirk Stolle

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
using System.Diagnostics;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of TreeSize Free.
    /// </summary>
    public class TreeSizeFree : AbstractSoftware
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
        private static readonly DateTime certificateExpiration = new(2026, 7, 31, 14, 42, 20, DateTimeKind.Utc);


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
                "c685e16e86183d11c30407ee688dc5a6081e3ea1958d3b9b509bc36e3edbce07",
                signature,
                "/VERYSILENT /NORESTART");
            return new AvailableSoftware("TreeSize Free",
                "4.7.3",
                "^TreeSize Free V[0-9]+\\.[0-9]+(\\.[0-9]+)?$",
                "^TreeSize Free V[0-9]+\\.[0-9]+(\\.[0-9]+)?( \\(64 bit\\)( \\(64 Bit\\))?)?$",
                info,
                info);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["treesizefree", "treesize"];
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
            logger.Info("Searching for newer version of TreeSize Free...");
            // Just getting the latest release does not work here, because that may also be a release candidate, and we do not want that.
            string html;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://www.jam-software.de/treesize_free/changes.shtml");
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of TreeSize Free: " + ex.Message);
                return null;
            }

            // HTML text will contain something like "<h3 class="collapsed-item__ttl">Version 4.7.3</h3>".
            var reVersion = new Regex(">[Vv]ersion ([0-9]+\\.[0-9]+\\.[0-9]+)</h3>");
            var matchVersion = reVersion.Match(html);
            if (!matchVersion.Success)
                return null;
            string currentVersion = matchVersion.Groups[1].Value;

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
            return ["TreeSizeFree"];
        }

        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.displayVersion))
            {
                throw new ArgumentNullException("detected.displayVersion",
                    "detected.displayVersion of current TreeSize Free version "
                    + "is not set! Pre-update process cannot be determined.");
            }
            // Versions before 4.6.0 need to be uninstalled before installation
            // of new version.
            var v4_6_0 = new versions.Triple("4.6.0");
            var prev = new versions.Triple(detected.displayVersion);
            return prev < v4_6_0;
        }


        /// <summary>
        /// Returns a list of processes that must be run before the update.
        /// This can be an empty list.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            // Versions before 4.6.0 need to be uninstalled before installation
            // of new version.
            var v4_6_0 = new versions.Triple("4.6.0");
            var prev = new versions.Triple(detected.displayVersion);
            if (!(prev < v4_6_0))
                return null;

            var proc = new Process();
            proc.StartInfo.FileName = System.IO.Path.Combine(detected.installPath, "unins000.exe");
            proc.StartInfo.Arguments = "/VERYSILENT /NORESTART";
            return new List<Process>(1) { proc };
        }
    } // class
} // namespace
