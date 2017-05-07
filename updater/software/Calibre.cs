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

using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    public class Calibre : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Calibre class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Calibre).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Calibre(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Calibre", 
                "2.84.0",
                "^calibre$",
                "^calibre 64 bit$",
                new InstallInfoMsi(
                    "https://download.calibre-ebook.com/2.84.0/calibre-2.84.0.msi",
                    HashAlgorithm.SHA256,
                    "9712fe39ec2dafb3954352a5b5810402c2955cec943d752223016005a63f20d7",
                    "/qn /norestart",
                    "C:\\Program Files\\Calibre2",
                    "C:\\Program Files (x86)\\Calibre2"),
                new InstallInfoMsi(
                    "https://download.calibre-ebook.com/2.84.0/calibre-64bit-2.84.0.msi",
                    HashAlgorithm.SHA256,
                    "d0b5af644bee98529d66f81ba21134e48583dfcd7cb37bc1aa38521295058203",
                    "/qn /norestart",
                    null,
                    "C:\\Program Files\\Calibre2")
                    );
        }


        /// <summary>
        /// list iof IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "calibre" };
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
            logger.Debug("Searching for newer version of Calibre...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://calibre-ebook.com/download_windows64");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Calibre: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            //get new version from alternative MSI path on GitHub
            Regex reMsi = new Regex("https://github.com/kovidgoyal/calibre/releases/download/v[0-9]+\\.[0-9]+\\.[0-9]+/calibre\\-64bit\\-[0-9]+\\.[0-9]+\\.[0-9]+\\.msi");
            Match matchMsi = reMsi.Match(htmlCode);
            if (!matchMsi.Success)
                return null;
            string newVersion = matchMsi.Value.Replace("https://github.com/kovidgoyal/calibre/releases/download/v", "");
            int idx = newVersion.IndexOf('/');
            if (idx < 0)
                return null;
            newVersion = newVersion.Remove(idx);

            //get SHA-256 sums from FossHub (official site provides no hashes)
            htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://www.fosshub.com/Calibre.html");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Calibre: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            //checksum for Windows 64bit installer
            idx = htmlCode.IndexOf("Windows 64bit installer");
            if (idx < 0)
                return null;
            Regex exprSha256 = new Regex("SHA256: [0-9a-f]{64}");
            Match match = exprSha256.Match(htmlCode, idx);
            if (!match.Success)
                return null;
            string checksum64 = match.Value.Substring(match.Value.Length - 64, 64);

            //checksum for Windows 32bit installer
            idx = htmlCode.IndexOf("Windows installer");
            if (idx < 0)
                return null;
            match = exprSha256.Match(htmlCode, idx);
            if (!match.Success)
                return null;
            string checksum32 = match.Value.Substring(match.Value.Length - 64, 64);

            //construct new version information
            var newInfo = knownInfo();
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            //no checksums are provided on the official site, but binaries are signed
            newInfo.install32Bit.checksum = checksum32;
            newInfo.install32Bit.algorithm = HashAlgorithm.SHA256;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            //no checksums are provided on the official site, but binaries are signed
            newInfo.install64Bit.checksum = checksum64;
            newInfo.install64Bit.algorithm = HashAlgorithm.SHA256;
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
