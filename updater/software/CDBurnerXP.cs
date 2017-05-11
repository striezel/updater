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
    public class CDBurnerXP : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for CDBurnerXP class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(CDBurnerXP).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public CDBurnerXP(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("CDBurnerXP",
                "4.5.7.6623",
                "^CDBurnerXP$",
                "^CDBurnerXP \\(64 Bit\\)$",
                new InstallInfoMsi(
                    "https://download.cdburnerxp.se/msi/cdbxp_setup_4.5.7.6623.msi",
                    HashAlgorithm.SHA256,
                    "e4f35b5948b92a02b4f0e00426536dc65e3c28b200f2a9c8f3e19b01bff502f3",
                    "/qn /norestart",
                    "C:\\Program Files\\CDBurnerXP",
                    "C:\\Program Files (x86)\\CDBurnerXP"),
                new InstallInfoMsi(
                    "https://download.cdburnerxp.se/msi/cdbxp_setup_x64_4.5.7.6623.msi",
                    HashAlgorithm.SHA256,
                    "b73e4fc3843aba9f9a1d8ecf01e52307b856e088fb4f6a5c74e52d0f9db25508",
                    "/qn /norestart",
                    null,
                    "C:\\Program Files\\CDBurnerXP")
                    );
        }


        /// <summary>
        /// list iof IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "cdburnerxp" };
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
            logger.Debug("Searching for newer version of CDBurnerXP...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://cdburnerxp.se/download");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of CDBurnerXP: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reMsi = new Regex("cdbxp_setup_[1-9]\\.[0-9]\\.[0-9]\\.[0-9]{4}\\.msi");
            Match matchMsi = reMsi.Match(htmlCode);
            if (!matchMsi.Success)
                return null;
            string newVersion = matchMsi.Value.Replace("cdbxp_setup_", "").Replace(".msi", "");
            
            //construct new version information
            var newInfo = knownInfo();
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            //no checksums are provided on the official site, but binaries are signed
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            //no checksums are provided on the official site, but binaries are signed
            newInfo.install64Bit.checksum = null;
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
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
