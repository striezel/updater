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
using updater_cli.data;

namespace updater_cli.software
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
            return new AvailableSoftware("FileZilla FTP Client", "3.25.1",
                "^FileZilla Client [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                "^FileZilla Client [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/filezilla/FileZilla_Client/3.25.1/FileZilla_3.25.1_win32-setup.exe",
                    HashAlgorithm.SHA512,
                    "c87ad1c6379374efdb11c4176dfc9237164ce4218d8add3fb65dd9f459ab695405580e357806d2f7cb0140589dcb2599106ad52c615af3501d1702fd51c41895",
                    "/S",
                    "C:\\Program Files\\FileZilla FTP Client",
                    "C:\\Program Files (x86)\\FileZilla FTP Client"),
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/filezilla/FileZilla_Client/3.25.1/FileZilla_3.25.1_win64-setup.exe",
                    HashAlgorithm.SHA512,
                    "929e8c6a12dc1fc3e77eb17efe5cd860e5a263b97facd1fd2d9a427277d515dad7dd14516341d600b271b1013cc1d966ad36560edd619a401571caacce94e1b1",
                    "/S",
                    null,
                    "C:\\Program Files\\FileZilla FTP Client")
                );
        }


        /// <summary>
        /// list iof IDs to identify the software
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
