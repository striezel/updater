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
    public class Audacity : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Audacity class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Audacity).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Audacity(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Audacity", "2.1.3",
                "^Audacity [0-9]+\\.[0-9]+\\.[0-9]+$",
                null,
                //Audacity only has an installer for 32 bit.
                new InstallInfoExe(
                    "https://www.fosshub.com/Audacity.html/audacity-win-2.1.3.exe",
                    HashAlgorithm.SHA256,
                    "12d83cb444734e3aaba8114115a83f7ceaa314d14641cde65b4f35f9847c5e1f",
                    "/VERYSILENT /NORESTART",
                    "C:\\Program Files\\Audacity",
                    "C:\\Program Files (x86)\\Audacity"),
                null
                );
        }


        /// <summary>
        /// list iof IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "audacity" };
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
            logger.Debug("Searching for newer version of Audacity...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://www.fosshub.com/Audacity.html");
                }
                catch (Exception ex)
                {
                    logger.Error("Exception occurred while checking for newer version of Audacity: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            const string winInstaller = "Windows Installer";
            int idx = htmlCode.IndexOf(winInstaller);
            if (idx < 0)
                return null;
            htmlCode = htmlCode.Remove(0, idx);

            Regex reVersion = new Regex("version: [0-9]+\\.[0-9]+\\.[0-9]+");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string version = matchVersion.Value.Replace("version: ", "");

            //SHA-256 checksum

            Regex reChecksum = new Regex("SHA256: [0-9a-f]{64}");
            Match m = reChecksum.Match(htmlCode);
            if (!m.Success)
                return null;
            string checksum = m.Value.Replace("SHA256: ", "");

            //construct new information
            var newInfo = knownInfo();
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = version;
            //32 bit
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, version);
            newInfo.install32Bit.checksum = checksum;
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
