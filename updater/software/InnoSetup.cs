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
using System.Diagnostics;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles update of Inno Setup (Unicode version).
    /// </summary>
    public class InnoSetup : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for InnoSetup class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(InnoSetup).FullName);


        /// <summary>
        /// publisher name for signed installers of Inno Setup
        /// </summary>
        private const string publisherX509 = "CN=Pyrsys B.V., O=Pyrsys B.V., S=Noord-Holland, C=NL";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2028, 3, 9, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public InnoSetup(bool autoGetNewer)
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
                "https://files.innosetup.nl/innosetup-6.5.2.exe",
                HashAlgorithm.SHA256,
                "8582879760b6e0e42e00f2e28ce904afac0d739941a130d3da3573c3cbf2d75b",
                new Signature(publisherX509, certificateExpiration),
                "/ALLUSERS /VERYSILENT /NORESTART");
            return new AvailableSoftware("Inno Setup",
                "6.5.2",
                "^Inno Setup Version [0-9]+\\.[0-9]+\\.[0-9]+$",
                "^Inno Setup Version [0-9]+\\.[0-9]+\\.[0-9]+$",
                installer,
                installer);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["inno-setup", "innosetup"];
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
            logger.Info("Searching for newer version of Inno Setup...");
            var client = HttpClientProvider.Provide();
            string response;
            try
            {
                var task = client.GetStringAsync("https://jrsoftware.org/isdl.php");
                task.Wait();
                response = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Inno Setup version: " + ex.Message);
                return null;
            }

            var regEx = new Regex("innosetup\\-([0-9]+\\.[0-9]+\\.[0-9]+)\\.exe");
            var match = regEx.Match(response);
            if (!match.Success)
                return null;
            string version = match.Groups[1].Value;
            string major_version = version.Split('.')[0];
            // Checksum is available in a file like https://files.jrsoftware.org/is/6/innosetup-6.4.3.exe.issig.
            try
            {
                var task = client.GetStringAsync("https://files.jrsoftware.org/is/" + major_version + "/innosetup-" + version + ".exe.issig");
                task.Wait();
                response = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Inno Setup version: " + ex.Message);
                return null;
            }
            // Line with hash looks like "file-hash f3c42116542c4cc57263c5ba6c4feabfc49fe771f2f98a79d2f7628b8762723b".
            regEx = new Regex("file\\-hash ([0-9a-f]{64})");
            match = regEx.Match(response);
            if (!match.Success)
                return null;
            var checksum = match.Groups[1].Value;

            var info = knownInfo();
            info.install32Bit.checksum = checksum;
            info.install32Bit.downloadUrl = info.install32Bit.downloadUrl.Replace(info.newestVersion, version);
            info.install64Bit.checksum = checksum;
            info.install64Bit.downloadUrl = info.install64Bit.downloadUrl.Replace(info.newestVersion, version);
            info.newestVersion = version;
            return info;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return
            [
                "Compil32",
                "ISCC",
                "islzma32",
                "islzma64"
            ];
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
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
            {
                logger.Error("There is not enough information to uninstall the old Inno Setup version.");
                return null;
            }

            // Remove enclosing quotes, if any.
            if (detected.installPath.StartsWith('\"') && detected.installPath.EndsWith('\"'))
            {
                detected.installPath = detected.installPath[1..^1];
            }
            var proc = new Process();
            proc.StartInfo.FileName = System.IO.Path.Combine(detected.installPath, "unins000.exe");
            proc.StartInfo.Arguments = "/VERYSILENT /NORESTART";
            return new List<Process>(1) { proc };
        }
    }
}
