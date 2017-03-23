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
    public class Pdf24Creator : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Pdf24Creator class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Pdf24Creator).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        /// <param name="autoUpdate">whether automatic updates of PDF24 shall be enabled</param>
        /// <param name="desktopIcons">whether desktop icons shall be created on update</param>
        /// <param name="faxPrinter">whether the fax printer shall be enabled</param>
        public Pdf24Creator(bool autoGetNewer, bool autoUpdate, bool desktopIcons, bool faxPrinter)
            : base(autoGetNewer)
        {
            mAutoUpdate = autoUpdate;
            mDesktopIcons = desktopIcons;
            mFaxPrinter = faxPrinter;
        }


        /// <summary>
        /// gets options for update
        /// </summary>
        private string getOptions()
        {
            string options = "AUTOUPDATE=";
            if (mAutoUpdate)
                options += "Yes";
            else
                options += "No";
            options += " DESKTOPICONS=";
            if (mDesktopIcons)
                options += "Yes";
            else
                options += "No";
            options += " FAXPRINTER=";
            if (mFaxPrinter)
                options += "Yes";
            else
                options += "No";
            return options;
        }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {

            return new AvailableSoftware("PDF24 Creator", "8.1.0",
                "^PDF24 Creator$",
                null, //no 64 bit version
                new InstallInfoMsi(
                    "https://en.pdf24.org/products/pdf-creator/download/pdf24-creator-8.1.0.msi",
                    HashAlgorithm.SHA512,
                    "77faa847d8f54e0e63a9e86a6c9c83c9357998f7f11b043584eb077a5829c0cffa66910898af652d6f58da54e5be7dab4149d47f90e0a697f480d7b8d09e1e7e",
                    getOptions() + " /qn /norestart",
                    "C:\\Program Files\\PDF24",
                    "C:\\Program Files (x86)\\PDF24"),
                //There is no 64 bit installer.
                null);
        }


        /// <summary>
        /// list iof IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "pdf24-creator" };
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return false;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Debug("Searching for newer version of PDF24 Creator...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://en.pdf24.org/pdf-creator-download.html");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of PDF24 Creator: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using

            //version number occurs three times on the site (private exe, business exe, msi)
            Regex reVersion = new Regex("[1-9]+\\.[0-9]+\\.[0-9]+");
            Match versionMatch = reVersion.Match(htmlCode);
            if (!versionMatch.Success)
                return null;
            Match match2 = reVersion.Match(htmlCode, versionMatch.Index + 4);
            if (!match2.Success || match2.Value != versionMatch.Value)
                return null;
            match2 = reVersion.Match(htmlCode, match2.Index + 4);
            if (!match2.Success || match2.Value != versionMatch.Value)
                return null;
            string newVersion = versionMatch.Value;
            
            //construct new version information
            var newInfo = knownInfo();
            //replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            //no checksums are provided on the official site, but binaries are signed
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
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
            versions.Triple verDetected = new versions.Triple(detected.displayVersion);
            versions.Triple verNewest = new versions.Triple(info().newestVersion);
            return (verNewest.CompareTo(verDetected) > 0);
        }


        /// <summary>
        /// sets whether automatic updates are enabled
        /// </summary>
        /// <param name="enabled">true if automatic updates shall be enabled</param>
        public void enableAutoUpdate(bool enabled)
        {
            mAutoUpdate = enabled;
        }


        /// <summary>
        /// determines whether to create desktop icons
        /// </summary>
        /// <param name="create">true to create icons, false if not</param>
        public void createDesktopIcons(bool create)
        {
            mDesktopIcons = create;
        }


        /// <summary>
        /// determines whether the fax printer will be enabled
        /// </summary>
        /// <param name="enabled">true to enable fax printer, false to disable fax printer</param>
        public void enableFaxPrinter(bool enabled)
        {
            mFaxPrinter = enabled;
        }

        /// <summary>
        /// whether automatic updates are enabled
        /// </summary>
        private bool mAutoUpdate;


        /// <summary>
        /// whether desktop icons are created
        /// </summary>
        private bool mDesktopIcons;


        /// <summary>
        /// whether the fax printer is enabled
        /// </summary>
        private bool mFaxPrinter;
    } //class
} //namespace
