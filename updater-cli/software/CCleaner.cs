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
using System.Net;
using System.Text.RegularExpressions;
using updater_cli.data;

namespace updater_cli.software
{
    public class CCleaner : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for CCleaner class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(CCleaner).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public CCleaner(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("CCleaner", "5.28",
                "^CCleaner+$",
                "^CCleaner+$",
                //CCleaner uses the same installer for 32 and 64 bit.
                new InstallInfoExe(
                    "https://download.piriform.com/ccsetup528.exe",
                    HashAlgorithm.SHA256,
                    "c0095229fe2e0c9bde8ef960b6fed40a71f5f2d9cc17d4c53ee9ca30c5b032a9",
                    "/S",
                    "C:\\Program Files\\CCleaner",
                    "C:\\Program Files (x86)\\CCleaner"),
                new InstallInfoExe(
                    "https://download.piriform.com/ccsetup528.exe",
                    HashAlgorithm.SHA256,
                    "c0095229fe2e0c9bde8ef960b6fed40a71f5f2d9cc17d4c53ee9ca30c5b032a9",
                    "/S",
                    null,
                    "C:\\Program Files\\CCleaner")
                );
        }


        /// <summary>
        /// list iof IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "ccleaner" };
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
            logger.Debug("Searching for newer version of CCleaner...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://www.piriform.com/ccleaner/download/standard");
                }
                catch (Exception ex)
                {
                    logger.Error("Exception occurred while checking for newer version of CCleaner: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            //extract download URL
            Regex reg = new Regex("http(s)?://download\\.piriform\\.com/ccsetup[0-9]+\\.exe");
            Match match = reg.Match(htmlCode);
            if (!match.Success)
                return null;
            string newUrl = match.Value.Replace("http://", "https://");
            //extract version
            reg = new Regex("[0-9]+");
            match = reg.Match(newUrl);
            if (!match.Success)
                return null;
            string newVersion = match.Value;
            newVersion = newVersion.Substring(0, newVersion.Length - 2) + "." + newVersion.Substring(newVersion.Length - 2);
            if (newVersion == knownInfo().newestVersion)
                return knownInfo();

            //No checksums are provided.

            //construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = newVersion;
            //32 bit
            newInfo.install32Bit.downloadUrl = newUrl;
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            // 64 bit - same installer
            newInfo.install64Bit.downloadUrl = newUrl;
            newInfo.install64Bit.checksum = null;
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
            return newInfo;
        }
    } //class
} //namespace
