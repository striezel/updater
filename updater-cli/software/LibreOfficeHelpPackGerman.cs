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
    public class LibreOfficeHelpPackGerman : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for LibreOfficeHelpPackGerman class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(LibreOfficeHelpPackGerman).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public LibreOfficeHelpPackGerman(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("LibreOffice Help Pack German", "5.3.1.2",
                "^LibreOffice [0-9]\\.[0-9] Help Pack \\(German\\)$",
                "^LibreOffice [0-9]\\.[0-9] Help Pack \\(German\\)$",
                new InstallInfoLibO(
                    "https://download.documentfoundation.org/libreoffice/stable/5.3.1/win/x86/LibreOffice_5.3.1_Win_x86_helppack_de.msi",
                    HashAlgorithm.SHA256,
                    "401bd5d0e84f37fc0713c5e2f6f33424421c7b6ccc8b101c0cdb053447e684b2",
                    "/qn /norestart",
                    "C:\\Program Files\\LibreOffice 5",
                    "C:\\Program Files (x86)\\LibreOffice 5"),
                new InstallInfoLibO(
                    "https://download.documentfoundation.org/libreoffice/stable/5.3.1/win/x86_64/LibreOffice_5.3.1_Win_x64_helppack_de.msi",
                    HashAlgorithm.SHA256,
                    "4035bb3036177e89d02591e8cae209277cb2ec520a52ae2f2f5455b908e00a49",
                    "/qn /norestart",
                    null,
                    "C:\\Program Files\\LibreOffice 5")
                    );
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
            logger.Debug("Searching for newer version of LibreOffice Help Pack (German)...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://download.documentfoundation.org/libreoffice/stable/?C=N;O=D");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of LibreOffice Help Pack: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            // Link is something like <a href="5.3.0/">5.3.0/</a>, no fourth digit.
            Regex reVersion = new Regex("<a href=\"[0-9]\\.[0-9]\\.[0-9]/\">[0-9]\\.[0-9]\\.[0-9]/</a>");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string newVersion = matchVersion.Value.Replace("<a href=\"", "");
            int idx = newVersion.IndexOf('/');
            if (idx < 0)
                return null;
            newVersion = newVersion.Substring(0, idx);

            // Hash info is in files like
            // https://download.documentfoundation.org/libreoffice/stable/5.3.0/win/x86/LibreOffice_5.3.0_Win_x86_helppack_de.msi.sha256
            // https://download.documentfoundation.org/libreoffice/stable/5.3.0/win/x86_64/LibreOffice_5.3.0_Win_x64_helppack_de.msi.sha256
            htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://download.documentfoundation.org/libreoffice/stable/"
                        + newVersion + "/win/x86/LibreOffice_" + newVersion + "_Win_x86_helppack_de.msi.sha256");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of LibreOffice Help Pack: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reHash32 = new Regex("[0-9a-f]{64}  LibreOffice_" + Regex.Escape(newVersion) + "_Win_x86_helppack_de\\.msi");
            Match matchHash32 = reHash32.Match(htmlCode);
            if (!matchHash32.Success)
                return null;
            string hash32 = matchHash32.Value.Substring(0, 64);

            htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://download.documentfoundation.org/libreoffice/stable/"
                        + newVersion + "/win/x86_64/LibreOffice_" + newVersion + "_Win_x64_helppack_de.msi.sha256");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of LibreOffice Help Pack: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            Regex reHash64 = new Regex("[0-9a-f]{64}  LibreOffice_" + Regex.Escape(newVersion) + "_Win_x64_helppack_de\\.msi");
            Match matchHash64 = reHash64.Match(htmlCode);
            if (!matchHash64.Success)
                return null;
            string hash64 = matchHash64.Value.Substring(0, 64);

            //construct new version information
            var newInfo = knownInfo();
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = "http://download.documentfoundation.org/libreoffice/stable/"
                + newVersion + "/win/x86/LibreOffice_" + newVersion + "_Win_x86_helppack_de.msi";
            newInfo.install32Bit.checksum = hash32;
            newInfo.install64Bit.downloadUrl = "http://download.documentfoundation.org/libreoffice/stable/"
                + newVersion + "/win/x86_64/LibreOffice_" + newVersion + "_Win_x64_helppack_de.msi";
            newInfo.install64Bit.checksum = hash64;
            return newInfo;
        }

    } //class
} //namespace
