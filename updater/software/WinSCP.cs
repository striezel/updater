/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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

using updater.data;
using System;
using System.Net;
using System.Text.RegularExpressions;
using System.Collections.Generic;

namespace updater.software
{
    /// <summary>
    /// Handles updates for WinSCP.
    /// </summary>
    public class WinSCP : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for WinSCP class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(WinSCP).FullName);

        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Martin Prikryl, O=Martin Prikryl, L=Prague, C=CZ, SERIALNUMBER=87331519, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=CZ";
        
        /// <summary>
        /// expiration date of certificate in signature of binary installer
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2023, 2, 17, 12, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public WinSCP(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("WinSCP",
                "5.21.0",
                "^WinSCP [1-9]+\\.[0-9]+(\\.[0-9]+)?$", null,
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/winscp/WinSCP/5.21/WinSCP-5.21-Setup.exe",
                    HashAlgorithm.SHA256,
                    "ba6ab981065411f88573ba9b129b9e13fd8b8b3e4104973059630c665c4d2d5e",
                    new Signature(publisherX509, certificateExpiration),
                    "/VERYSILENT /NORESTART"),
                // There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "winscp" };
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
            logger.Info("Searching for newer version of WinSCP...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://winscp.net/eng/download.php");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of WinSCP: " + ex.Message);
                    return null;
                }
                client.Dispose();
            }

            Regex reExe = new Regex("WinSCP\\-[1-9]+\\.[0-9]+(\\.[0-9]+)?\\-Setup\\.exe");
            Match matchExe = reExe.Match(htmlCode);
            if (!matchExe.Success)
                return null;
            // extract new version number
            string newVersion = matchExe.Value.Replace("WinSCP-", "").Replace("-Setup.exe", "");
            versions.Triple newTriple = new versions.Triple(newVersion);
            versions.Triple oldTriple = new versions.Triple(knownInfo().newestVersion);
            if (newTriple < oldTriple)
                return null;
            // version number should match usual scheme, e.g. 5.x.y, where x and y are digits
            Regex version = new Regex("^[1-9]+\\.[0-9]+(\\.[0-9]+)?$");
            if (!version.IsMatch(newVersion))
                return null;

            // Readme (e.g. https://winscp.net/download/WinSCP-5.9.5-ReadMe.txt) contains hash.
            htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://winscp.net/download/WinSCP-" + newVersion + "-ReadMe.txt");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of WinSCP: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // extract hash - .exe occurs first, so first hash is the one we want
            Regex hash = new Regex("SHA\\-256\\: [0-9a-f]{64}");
            Match matchHash = hash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash = matchHash.Value.Replace("SHA-256: ", "").Trim();

            // The "file" https://winscp.net/download/WinSCP-5.9.5-Setup.exe or
            // similar is just a HTML page that starts the download of the real
            // file after a few seconds, so we have to parse the direct link of
            // the download and use that.
            htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://winscp.net/download/WinSCP-" + newVersion + "-Setup.exe");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of WinSCP: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // URL for direct download is something like
            // https://winscp.net/download/files/201704212143f42467fc64e4c84259bce4a07a98edbd/WinSCP-5.9.5-Setup.exe,
            // where the middle part (date plus random MD5 hash?) varies.
            Regex downloadUrl = new Regex(Regex.Escape("https://winscp.net/download/files/")
                + "[0-9]{12}[0-9a-f]{32}" + "/WinSCP\\-" + Regex.Escape(newVersion)
                + "\\-Setup\\.exe");
            Match matchUrl = downloadUrl.Match(htmlCode);
            if (!matchUrl.Success)
                return null;

            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = matchUrl.Value;
            newInfo.install32Bit.checksum = newHash;
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
                "WinSCP"
            };
        }

    } // class
} // namespace
