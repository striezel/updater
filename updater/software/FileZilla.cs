/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023  Dirk Stolle

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
    /// FileZilla FTP Client
    /// </summary>
    public class FileZilla : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FileZilla class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FileZilla).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FileZilla(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Tim Kosse, O=Tim Kosse, S=Nordrhein-Westfalen, C=DE";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2025, 2, 17, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            // Note: This only works on Windows 7 or newer.
            // The last version for Windows Vista is 3.25.1.
            // The last version that still supports Windows XP is 3.8.0
            if (utility.OS.isWin7OrNewer())
            {
                var signature = new Signature(publisherX509, certificateExpiration);
                return new AvailableSoftware("FileZilla FTP Client",
                    "3.66.1",
                    "^FileZilla (Client )?[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                    "^FileZilla (Client )?[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                    new InstallInfoExe(
                        "https://download.filezilla-project.org/client/FileZilla_3.66.1_win32-setup.exe",
                        HashAlgorithm.SHA512,
                        "d43061de825b248487b0b82f4d57b1bb3b9546e065bcdebcdc6b5de070dbc60291584f15534c03754d6551140987ae26155f0b0bd4537c20c11922b9d04230b1",
                        signature,
                        "/S"),
                    new InstallInfoExe(
                        "https://download.filezilla-project.org/client/FileZilla_3.66.1_win64-setup.exe",
                        HashAlgorithm.SHA512,
                        "36c1a15f525800a2b0c03325802b603088d0cd6c137408ed584b8091caaced41b140d16e2de92d0b0782c363ca487379ffa44b80c20e2a947cdf8f5f2c5981f3",
                        signature,
                        "/S")
                    );
            }
            // Windows Vista
            if (utility.OS.isWinVistaOrNewer())
                return LatestSupportedVersionWinVista();
            // WinXP or older, but we do not care about older stuff. If you are
            // still using Windows 2000 or Windows 98 as productive system, you
            // have screwed up somewhere along the way.
            return LatestSupportedVersionWinXP();
        }


        /// <summary>
        /// Gets the information about the latest supported software version in WinXP.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        private static AvailableSoftware LatestSupportedVersionWinVista()
        {
            // The last version for Windows Vista is 3.25.1.
            // Additionally, Windows Vista is not officially supported by Microsoft anymore.
            logger.Warn("Windows Vista cannot use newer FileZilla versions than 3.25.1. Please consider updating your operating system!");
            return new AvailableSoftware("FileZilla FTP Client",
                "3.25.1",
                "^FileZilla Client [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                "^FileZilla Client [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/filezilla/FileZilla_Client/3.25.1/FileZilla_3.25.1_win32-setup.exe",
                    HashAlgorithm.SHA512,
                    "c87ad1c6379374efdb11c4176dfc9237164ce4218d8add3fb65dd9f459ab695405580e357806d2f7cb0140589dcb2599106ad52c615af3501d1702fd51c41895",
                    Signature.None,
                    "/S"),
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/filezilla/FileZilla_Client/3.25.1/FileZilla_3.25.1_win64-setup.exe",
                    HashAlgorithm.SHA512,
                    "929e8c6a12dc1fc3e77eb17efe5cd860e5a263b97facd1fd2d9a427277d515dad7dd14516341d600b271b1013cc1d966ad36560edd619a401571caacce94e1b1",
                    Signature.None,
                    "/S")
                );
        }


        /// <summary>
        /// Gets the information about the latest supported software version in WinXP.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        private static AvailableSoftware LatestSupportedVersionWinXP()
        {
            // The last version that still supports Windows XP is 3.8.0.
            // Additionally, WinXP is not officially supported by Microsoft anymore.
            logger.Warn("Windows XP cannot use newer FileZilla versions than 3.8.0. Please consider updating your operating system!");
            return new AvailableSoftware("FileZilla FTP Client",
                "3.8.0",
                "^FileZilla Client [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                "^FileZilla Client [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?$",
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/filezilla/FileZilla_Client/3.8.0/FileZilla_3.8.0_win32-setup.exe",
                    HashAlgorithm.SHA512,
                    "48089aad2da20b49b2d6ad1baf450a14cd20ed2b65b681c469b2b9c943f20970d48cf73008e4ff427ed9743af0c257cfca1b6bdeecdd2153b6531c1449ab8353",
                    Signature.None,
                    "/S"),
                // There was no 64 bit version as of version 3.8.0.
                null
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "filezilla" };
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
            logger.Info("Searching for newer version of FileZilla FTP Client...");
            if (utility.OS.isWin7OrNewer())
            {
                string htmlCode = null;
                using (var client = new WebClient())
                {
                    // Looks like we have to add a user agent to get a valid response.
                    // Without user agent the server returns "403 Forbidden".
                    client.Headers.Add("User-Agent", "curl/7.86.0");
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
                } // using

                // find version number
                var reVersion = new Regex("FileZilla_[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?_win64\\-setup\\.exe");
                Match matchVersion = reVersion.Match(htmlCode);
                if (!matchVersion.Success)
                    return null;
                string version = matchVersion.Value.Replace("FileZilla_", "").Replace("_win64-setup.exe", "");
                /* if (version == knownInfo().newestVersion)
                    return knownInfo(); */

                // find hashes
                int idx64 = htmlCode.IndexOf("FileZilla_" + version + "_win64-setup.exe");
                if (idx64 < 0)
                    return null;
                int idx32 = htmlCode.IndexOf("FileZilla_" + version + "_win32-setup.exe");
                if (idx32 < 0)
                    return null;

                string checksum64;
                string checksum32;
                var reSha512 = new Regex("[0-9a-f]{128}");
                if (idx64 < idx32)
                {
                    // 64 bit first
                    Match sha512 = reSha512.Match(htmlCode, idx64 + 1, idx32 - idx64);
                    if (!sha512.Success)
                        return null;
                    checksum64 = sha512.Value;
                    // 32 bit next
                    sha512 = reSha512.Match(htmlCode, idx32);
                    if (!sha512.Success)
                        return null;
                    checksum32 = sha512.Value;
                } // if 64 bit build is before 32 bit build
                else
                {
                    // 32 bit build before 64 bit build
                    Match sha512 = reSha512.Match(htmlCode, idx32 + 1, idx64 - idx32);
                    if (!sha512.Success)
                        return null;
                    checksum32 = sha512.Value;
                    // 64 bit next
                    sha512 = reSha512.Match(htmlCode, idx64);
                    if (!sha512.Success)
                        return null;
                    checksum64 = sha512.Value;
                } // else

                // find download URL
                // URL is something like "https://dl4.cdn.filezilla-project.org/client/FileZilla_3.50.0_win64-setup.exe?h=wJDamKbB9lkk6abFtg1Lig&x=1600204244"
                // for the 64 bit binary. Similar pattern is applied for 32 bit binary.
                var reDownload64 = new Regex("href=\"(https://dl[0-9]+\\.cdn\\.filezilla\\-project\\.org/client/FileZilla_[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?_win64\\-setup\\.exe\\?h=[A-Za-z0-9_\\-]+&x=[0-9]+)\"");
                Match dl64 = reDownload64.Match(htmlCode);
                if (!dl64.Success)
                    return null;
                var reDownload32 = new Regex("href=\"(https://dl[0-9]+\\.cdn\\.filezilla\\-project\\.org/client/FileZilla_[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?_win32\\-setup\\.exe\\?h=[A-Za-z0-9_\\-]+&x=[0-9]+)\"");
                Match dl32 = reDownload32.Match(htmlCode);
                if (!dl32.Success)
                    return null;

                // construct new information
                var newInfo = knownInfo();
                newInfo.newestVersion = version;
                newInfo.install32Bit.downloadUrl = dl32.Groups[1].Value;
                newInfo.install32Bit.checksum = checksum32;
                newInfo.install64Bit.downloadUrl = dl64.Groups[1].Value;
                newInfo.install64Bit.checksum = checksum64;
                return newInfo;
            }
            // Windows Vista
            if (utility.OS.isWinVistaOrNewer())
            {
                return LatestSupportedVersionWinVista();
            }
            // WinXP or older - you should really get an OS update.
            return LatestSupportedVersionWinXP();
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
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
            var verDetected = new versions.Quartet(detected.displayVersion);
            var verNewest = new versions.Quartet(info().newestVersion);
            return verNewest.CompareTo(verDetected) > 0;
        }


        /// <summary>
        /// Checks whether the software is in the list of detected software.
        /// </summary>
        /// <param name="detected">list of detected software on the system</param>
        /// <param name="autoGetNew">whether to automatically get new software information</param>
        /// <param name="result">query result where software will be added, if it is in the detection list</param>
        public override void detectionQuery(List<DetectedSoftware> detected, bool autoGetNew, List<QueryEntry> result)
        {
            // 32 bit systems use normal detection.
            if (!Environment.Is64BitOperatingSystem)
            {
                base.detectionQuery(detected, autoGetNew, result);
                return;
            }
            // 64 bit systems might need adjustments.
            var resBase = new List<QueryEntry>();
            base.detectionQuery(detected, autoGetNew, resBase);
            foreach (var item in resBase)
            {
                if (string.IsNullOrWhiteSpace(item.detected.installPath))
                    continue;
                // See if we need to adjust the type for the 64 bit variant.
                string exePath = System.IO.Path.Combine(item.detected.installPath, "filezilla.exe");
                utility.PEFormat format = utility.PortableExecutable.determineFormat(exePath);
                if ((format == utility.PEFormat.PE64) && (item.type != ApplicationType.Bit64))
                {
                    item.type = ApplicationType.Bit64;
                    item.detected.appType = ApplicationType.Bit64;
                }
            } // foreach
            result.AddRange(resBase);
        }

    } // class
} // namespace
