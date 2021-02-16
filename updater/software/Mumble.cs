/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021  Dirk Stolle

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
    /// Handles updates of Mumble.
    /// </summary>
    public class Mumble : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Mumble class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Mumble).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Mumble(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher name for signed binaries
        /// </summary>
        private const string publisherX509 = "E=contact@davidebeatrici.dev, CN=\"Open Source Developer, Davide Beatrici\", O=Open Source Developer, S=Lombardia, C=IT";


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Mumble",
                "1.3.4",
                "^Mumble [0-9]\\.[0-9]+\\.[0-9]+$",
                "^Mumble [0-9]\\.[0-9]+\\.[0-9]+$",
                new InstallInfoMsi(
                    "https://github.com/mumble-voip/mumble/releases/download/1.3.4/mumble-1.3.4.msi",
                    HashAlgorithm.SHA256,
                    "eb2f452dccaa60f64409356815f7ee834aa07823f92410eefe3a2628cf90d52e",
                    publisherX509,
                    "/qn /norestart"),
                // 64 bit MSI installer started with 1.3.0.
                new InstallInfoMsi(
                    "https://github.com/mumble-voip/mumble/releases/download/1.3.4/mumble-1.3.4.winx64.msi",
                    HashAlgorithm.SHA256,
                    "14e58074269ae32d1678738fb66fc9551c2aac2e789439157081886860802e02",
                    publisherX509,
                    "/qn /norestart")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "mumble" };
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
            logger.Debug("Searching for newer version of Mumble...");
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://github.com/mumble-voip/mumble/releases/latest");
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            string currentVersion;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("tag/[0-9]+\\.[0-9]+\\.[0-9]+$");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                currentVersion = matchVersion.Value.Substring(4);
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Mumble version: " + ex.Message);
                return null;
            }
            // Use known info, if version has not changed.
            if (currentVersion == knownInfo().newestVersion)
                return knownInfo();

            /* New URL is something like 
               https://github.com/mumble-voip/mumble/releases/download/1.2.19/mumble-1.2.19.msi
               and signature file is something like
               https://github.com/mumble-voip/mumble/releases/download/1.2.19/mumble-1.2.19.msi.sig
               However, the updater cannot check signatures yet.
            */
            
            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = currentVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, currentVersion);
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, currentVersion);
            // no checksums are provided, only signature files
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install64Bit.checksum = null;
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
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
            // Technically, mumble.exe is a blocker, but the installer just closes it,
            // if it is running.
            return new List<string>();
        }


        /// <summary>
        /// Determines whether the detected software is older than the newest known software.
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            versions.Triple verDetected = new versions.Triple(detected.displayVersion);
            versions.Triple verNewest = new versions.Triple(info().newestVersion);
            return verNewest.CompareTo(verDetected) > 0;
        }
    } // class
} // namespace
