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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates for PDF24 Creator.
    /// </summary>
    public class Pdf24Creator : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Pdf24Creator class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Pdf24Creator).FullName);

        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Geek Software GmbH, O=Geek Software GmbH, S=Berlin, C=DE, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=DE, SERIALNUMBER=HRB 100865";

        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2026, 9, 24, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
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
        /// Gets options for update.
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
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);

            return new AvailableSoftware("PDF24 Creator",
                "11.14.0",
                "^PDF24 Creator$",
                "^PDF24 Creator$", // 64 bit version uses same pattern as 32 bit.
                new InstallInfoMsi(
                "https://download.pdf24.org/pdf24-creator-11.14.0-x86.msi",
                HashAlgorithm.SHA256,
                "D5E4EB14A60F81C5F32810AD52DCABFC7198F096BD381F10C83D253DA660EECE",
                signature, getOptions() + " /qn /norestart"),
                new InstallInfoMsi(
                "https://download.pdf24.org/pdf24-creator-11.14.0-x64.msi",
                HashAlgorithm.SHA256,
                "2F795A89069EE7AF70021A0AA164ADB32EB34C86C1EB03973646A641FCE461DD",
                signature, getOptions() + " /qn /norestart")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "pdf24-creator" };
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
            logger.Info("Searching for newer version of PDF24 Creator...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://creator.pdf24.org/listVersions.php");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of PDF24 Creator: " + ex.Message);
                return null;
            }

            // version number occurs several times on the site (exe, msi, and for 64 and 32 bit)
            var reVersion = new Regex("pdf24\\-creator\\-([0-9]+\\.[0-9]+\\.[0-9]+)\\-x64.msi");
            Match versionMatch = reVersion.Match(htmlCode);
            if (!versionMatch.Success)
                return null;
            string newVersion = versionMatch.Groups[1].Value;
            var regExHash = new Regex("[A-Z0-9]{64}", RegexOptions.IgnoreCase);
            var match = regExHash.Match(htmlCode, versionMatch.Index + versionMatch.Length);
            if (!match.Success)
                return null;
            string checksum = match.Value;

            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = checksum;
            newInfo.install64Bit.algorithm = HashAlgorithm.SHA256;

            int idx = htmlCode.IndexOf("pdf24-creator-" + newVersion + "-x86.msi");
            if (idx == -1)
                return null;
            match = regExHash.Match(htmlCode, idx);
            if (!match.Success)
                return null;

            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install32Bit.checksum = match.Value;
            newInfo.install32Bit.algorithm = HashAlgorithm.SHA256;

            return newInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(0);
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
            var verDetected = new versions.Triple(detected.displayVersion);
            var verNewest = new versions.Triple(info().newestVersion);
            return verNewest.CompareTo(verDetected) > 0;
        }


        /// <summary>
        /// Sets whether automatic updates are enabled.
        /// </summary>
        /// <param name="enabled">true if automatic updates shall be enabled</param>
        public void enableAutoUpdate(bool enabled)
        {
            mAutoUpdate = enabled;
        }


        /// <summary>
        /// Determines whether to create desktop icons.
        /// </summary>
        /// <param name="create">true to create icons, false if not</param>
        public void createDesktopIcons(bool create)
        {
            mDesktopIcons = create;
        }


        /// <summary>
        /// Determines whether the fax printer will be enabled.
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
    } // class
} // namespace
