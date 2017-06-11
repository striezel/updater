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
    public class FileZilla : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FileZilla class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FileZilla).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FileZilla(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            //Note: This only works on Windows 7 or newer.
            // The last version for Windows Vista is 3.25.1.
            // The last version that still supports Windows XP is 3.8.0
            return new AvailableSoftware("FileZilla FTP Client",
                "3.26.1",
                "^FileZilla Client [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                "^FileZilla Client [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/filezilla/FileZilla_Client/3.26.1/FileZilla_3.26.1_win32-setup.exe",
                    HashAlgorithm.SHA512,
                    "e1e33fe05c8b4c0993380347bc2d385bde6324c94546d2b98ec20f617a559d0998cec427c152f16a63f4b1ff26ff6759da5374caab7ed5b6bad77031a2540f21",
                    "/S",
                    "C:\\Program Files\\FileZilla FTP Client",
                    "C:\\Program Files (x86)\\FileZilla FTP Client"),
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/filezilla/FileZilla_Client/3.26.1/FileZilla_3.26.1_win64-setup.exe",
                    HashAlgorithm.SHA512,
                    "68f8de89322046436dc0a73aacea7064b576082be0671e1d3111663ece9d184f6db436ed60a9b6ca71799b100aec7a95a7095f00571802b7d1b1d069ab868ee4",
                    "/S",
                    null,
                    "C:\\Program Files\\FileZilla FTP Client")
                );
        }


        /// <summary>
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "filezilla" };
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
            logger.Debug("Searching for newer version of FileZilla FTP Client...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://filezilla-project.org/download.php?show_all=1");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of FileZilla: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //find version number
            Regex reVersion = new Regex("FileZilla_[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?_win64\\-setup\\.exe");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string version = matchVersion.Value.Replace("FileZilla_", "").Replace("_win64-setup.exe", "");
            if (version == knownInfo().newestVersion)
                return knownInfo();

            //find hashes
            int idx64 = htmlCode.IndexOf("FileZilla_" + version + "_win64-setup.exe");
            if (idx64 < 0)
                return null;
            int idx32 = htmlCode.IndexOf("FileZilla_" + version + "_win32-setup.exe");
            if (idx32 < 0)
                return null;

            string checksum64 = null;
            string checksum32 = null;
            Regex reSha512 = new Regex("[0-9a-f]{128}");
            if (idx64< idx32)
            {
                //64 bit first
                Match sha512 = reSha512.Match(htmlCode, idx64 + 1, idx32 - idx64);
                if (!sha512.Success)
                    return null;
                checksum64 = sha512.Value;
                //32 bit next
                sha512 = reSha512.Match(htmlCode, idx32);
                if (!sha512.Success)
                    return null;
                checksum32 = sha512.Value;
            } //if 64 bit build is before 32 bit build
            else
            {
                //32 bit build before 64 bit build
                Match sha512 = reSha512.Match(htmlCode, idx32 + 1, idx64 - idx32);
                if (!sha512.Success)
                    return null;
                checksum32 = sha512.Value;
                //64 bit next
                sha512 = reSha512.Match(htmlCode, idx64);
                if (!sha512.Success)
                    return null;
                checksum64 = sha512.Value;
            } //else
            
            //construct new information
            var newInfo = knownInfo();
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = version;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, version);
            newInfo.install32Bit.checksum = checksum32;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, version);
            newInfo.install64Bit.checksum = checksum64;
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


        /// <summary>
        /// whether the detected software is older than the newest known software
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            versions.Quartet verDetected = new versions.Quartet(detected.displayVersion);
            versions.Quartet verNewest = new versions.Quartet(info().newestVersion);
            return (verNewest.CompareTo(verDetected) > 0);
        }


        /// <summary>
        /// checks whether the software is in the list of detected software
        /// </summary>
        /// <param name="detected">list of detected software on the system</param>
        /// <param name="autoGetNew">whether to automatically get new software information</param>
        /// <param name="result">query result where software will be added, if it is in the detection list</param>
        public override void detectionQuery(List<DetectedSoftware> detected, bool autoGetNew, List<QueryEntry> result)
        {
            //32 bit systems use normal detection.
            if (!Environment.Is64BitOperatingSystem)
            {
                base.detectionQuery(detected, autoGetNew, result);
                return;
            }
            //64 bit systems might need adjustments.
            var resBase = new List<QueryEntry>();
            base.detectionQuery(detected, autoGetNew, resBase);
            foreach (var item in resBase)
            {
                if (string.IsNullOrWhiteSpace(item.detected.installPath))
                    continue;
                //See if we need to adjust the type for the 64 bit variant.
                string exePath = System.IO.Path.Combine(item.detected.installPath, "filezilla.exe");
                utility.PEFormat format = utility.PortableExecutable.determineFormat(exePath);
                if ((format == utility.PEFormat.PE64) && (item.type != ApplicationType.Bit64))
                {
                    item.type = ApplicationType.Bit64;
                    item.detected.appType = ApplicationType.Bit64;
                }
            } //foreach
            result.AddRange(resBase);
        }

    } //class
} //namespace
