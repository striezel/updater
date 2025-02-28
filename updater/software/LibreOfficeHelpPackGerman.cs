/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
    /// Handles update for the German version of the LibreOffice offline help.
    /// </summary>
    public class LibreOfficeHelpPackGerman : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for LibreOfficeHelpPackGerman class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(LibreOfficeHelpPackGerman).FullName);


        /// <summary>
        /// publisher name for signed executables of LibreOffice
        /// </summary>
        private const string publisherX509 = "E=info@documentfoundation.org, CN=The Document Foundation, O=The Document Foundation, OU=LibreOffice Build Team, L=Berlin, S=Berlin, C=DE";


        /// <summary>
        /// expiration date of the certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2026, 9, 13, 12, 18, 28, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public LibreOfficeHelpPackGerman(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("LibreOffice Help Pack German",
                "25.2.1.2",
                "^LibreOffice [0-9]+\\.[0-9]+ Help Pack \\(German\\)$",
                "^LibreOffice [0-9]+\\.[0-9]+ Help Pack \\(German\\)$",
                new InstallInfoLibO(
                    "https://download.documentfoundation.org/libreoffice/stable/25.2.1/win/x86/LibreOffice_25.2.1_Win_x86_helppack_de.msi",
                    HashAlgorithm.SHA256,
                    "6ea6d864494f98c980584bf76ae5946206e79104e2111ab6dd59c8e8fd073a08",
                    signature,
                    "/qn /norestart"),
                new InstallInfoLibO(
                    "https://download.documentfoundation.org/libreoffice/stable/25.2.1/win/x86_64/LibreOffice_25.2.1_Win_x86-64_helppack_de.msi",
                    HashAlgorithm.SHA256,
                    "0ed40fc875e639ece89b7b031be7b5339247f495cd7a6cdcb9a2a448bb1a0fcd",
                    signature,
                    "/qn /norestart")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["libreoffice-help-de"];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of LibreOffice Help Pack (German)...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://download.documentfoundation.org/libreoffice/stable/?C=N;O=D");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of LibreOffice Help Pack: " + ex.Message);
                return null;
            }

            // Link is something like <a href="5.3.0/">5.3.0/</a>, no fourth digit.
            var reVersion = new Regex("<a href=\"[0-9]+\\.[0-9]+\\.[0-9]+/\">[0-9]+\\.[0-9]+\\.[0-9]+/</a>");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string newVersion = matchVersion.Value.Replace("<a href=\"", "");
            int idx = newVersion.IndexOf('/');
            if (idx < 0)
                return null;
            newVersion = newVersion[..idx];

            // Hash info is in files like
            // https://download.documentfoundation.org/libreoffice/stable/7.5.0/win/x86/LibreOffice_7.5.0_Win_x86_helppack_de.msi.sha256
            // https://download.documentfoundation.org/libreoffice/stable/7.5.0/win/x86_64/LibreOffice_7.5.0_Win_x86-64_helppack_de.msi.sha256

            try
            {
                var task = client.GetStringAsync("https://download.documentfoundation.org/libreoffice/stable/"
                    + newVersion + "/win/x86/LibreOffice_" + newVersion + "_Win_x86_helppack_de.msi.sha256");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of LibreOffice Help Pack: " + ex.Message);
                return null;
            }

            var reHash32 = new Regex("[0-9a-f]{64}  LibreOffice_" + Regex.Escape(newVersion) + "_Win_x86_helppack_de\\.msi");
            Match matchHash32 = reHash32.Match(htmlCode);
            if (!matchHash32.Success)
                return null;
            string hash32 = matchHash32.Value[..64];

            try
            {
                var task = client.GetStringAsync("https://download.documentfoundation.org/libreoffice/stable/"
                    + newVersion + "/win/x86_64/LibreOffice_" + newVersion + "_Win_x86-64_helppack_de.msi.sha256");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of LibreOffice Help Pack: " + ex.Message);
                return null;
            }

            var reHash64 = new Regex("[0-9a-f]{64}  LibreOffice_" + Regex.Escape(newVersion) + "_Win_x86\\-64_helppack_de\\.msi");
            Match matchHash64 = reHash64.Match(htmlCode);
            if (!matchHash64.Success)
                return null;
            string hash64 = matchHash64.Value[..64];

            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = "https://download.documentfoundation.org/libreoffice/stable/"
                + newVersion + "/win/x86/LibreOffice_" + newVersion + "_Win_x86_helppack_de.msi";
            newInfo.install32Bit.checksum = hash32;
            newInfo.install64Bit.downloadUrl = "https://download.documentfoundation.org/libreoffice/stable/"
                + newVersion + "/win/x86_64/LibreOffice_" + newVersion + "_Win_x86-64_helppack_de.msi";
            newInfo.install64Bit.checksum = hash64;
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
            return [];
        }

    } // class
} // namespace
