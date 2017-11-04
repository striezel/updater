/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public KeePass(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private string publisherX509 = "E=cert@dominik-reichl.de, CN=\"Open Source Developer, Dominik Reichl\", O=Open Source Developer, C=DE";


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("KeePass",
                "2.37",
                "^KeePass Password Safe [2-9]\\.[0-9]{2}$", null,
                new InstallInfoExe(
                    "https://kent.dl.sourceforge.net/project/keepass/KeePass%202.x/2.37/KeePass-2.37-Setup.exe",
                    HashAlgorithm.SHA256,
                    "3EB75F0D 94270469 3110859E 97B66B8E 5245398D DE7E2CCD 82AB0ABC C5D73B36",
                    publisherX509,
                    "/VERYSILENT",
                    "C:\\Program Files\\KeePass Password Safe 2",
                    "C:\\Program Files (x86)\\KeePass Password Safe 2"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "keepass" };
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
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
            } //using

            Regex reExe = new Regex("&lt;KeePass\\-[2-9]\\.[0-9]{2}\\-Setup\\.exe&gt;");
            Match matchExe = reExe.Match(htmlCode);
            if (!matchExe.Success)
                return null;
            //MSI follows after .exe
            Regex reMsi = new Regex("&lt;KeePass\\-[2-9]\\.[0-9]{2}\\.msi&gt;");
            Match matchMsi = reMsi.Match(htmlCode, matchExe.Index + 1);
            if (!matchMsi.Success)
                return null;
            //extract new version number
            string newVersion = matchExe.Value.Replace("&lt;KeePass-", "").Replace("-Setup.exe&gt;", "");
            if (string.Compare(newVersion, knownInfo().newestVersion) < 0)
                return null;
            //version number should match usual scheme, e.g. 2.xx, where xx are two digits
            Regex version = new Regex("^[2-9]\\.[0-9]{2}$");
            if (!version.IsMatch(newVersion))
                return null;

            //extract hash
            Regex hash = new Regex("SHA256       \\: [0-9A-F ]+");
            Match matchHash = hash.Match(htmlCode, matchExe.Index + 1);
            if (!matchHash.Success)
                return null;
            if (matchHash.Index > matchMsi.Index)
                return null;
            //find second part of hash
            Regex hash2 = new Regex("[0-9A-F ]+");
            Match matchHash2 = hash2.Match(htmlCode, matchHash.Index + matchHash.Length);
            if (!matchHash2.Success)
                return null;
            if (matchHash2.Index > matchMsi.Index)
                return null;
            string newHash = matchHash.Value.Replace("SHA256       : ", "").Trim()
                + " " + matchHash2.Value.Trim();
            //construct new version information
            var newInfo = knownInfo();
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = newHash;
            return newInfo;
        }


        /// <summary>
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }

    } //class
} //namespace
