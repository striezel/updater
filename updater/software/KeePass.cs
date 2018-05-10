﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
    public class KeePass : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for KeePass class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(KeePass).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public KeePass(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private string publisherX509 = "E=cert@dominik-reichl.de, CN=\"Open Source Developer, Dominik Reichl\", L=Metzingen, O=Open Source Developer, C=DE";


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("KeePass",
                "2.39",
                "^KeePass Password Safe [2-9]\\.[0-9]{2}$", null,
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/keepass/KeePass%202.x/2.39/KeePass-2.39-Setup.exe",
                    HashAlgorithm.SHA256,
                    "B61DB932 44B95946 33D2E685 4497C580 76F93A26 A0C8CBEB 4D65F16D ED74C578",
                    publisherX509,
                    "/VERYSILENT"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// Gets the list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "keepass" };
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
            logger.Debug("Searching for newer version of KeePass...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("http://keepass.info/integrity.html");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of KeePass: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            Regex reExe = new Regex(">KeePass\\-[2-9]\\.[0-9]{2}\\-Setup\\.exe<");
            Match matchExe = reExe.Match(htmlCode);
            if (!matchExe.Success)
                return null;
            // MSI follows after .exe
            Regex reMsi = new Regex(">KeePass\\-[2-9]\\.[0-9]{2}\\.msi<");
            Match matchMsi = reMsi.Match(htmlCode, matchExe.Index + 1);
            if (!matchMsi.Success)
                return null;
            // extract new version number
            string newVersion = matchExe.Value.Replace(">KeePass-", "").Replace("-Setup.exe<", "");
            if (string.Compare(newVersion, knownInfo().newestVersion) < 0)
                return null;
            // Version number should match usual scheme, e.g. 2.xx, where xx are two digits.
            Regex version = new Regex("^[2-9]\\.[0-9]{2}$");
            if (!version.IsMatch(newVersion))
                return null;

            // extract hash
            Regex hash = new Regex("([0-9A-F]{8} ){7}[0-9A-F]{8}");
            Match matchHash = hash.Match(htmlCode, matchExe.Index + 1);
            if (!matchHash.Success)
                return null;
            if (matchHash.Index > matchMsi.Index)
                return null;
            string newHash = matchHash.Value.Trim();
            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = newHash;
            return newInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }

    } // class
} // namespace
