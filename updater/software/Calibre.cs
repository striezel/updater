/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2021, 2022, 2023  Dirk Stolle

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
using updater.utility;

namespace updater.software
{
    /// <summary>
    /// Handles update for Calibre e-book reader.
    /// </summary>
    public class Calibre : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Calibre class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Calibre).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Calibre(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed installers
        /// </summary>
        private const string publisherX509 = "CN=Kovid Goyal, O=Kovid Goyal, L=Mumbai, S=Maharashtra, C=IN";

        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2025, 10, 1, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("Calibre does not provide 32 bit binaries from version 6.0.0 onwards.");
                logger.Warn("Please consider switching to an 64 bit operating system to get newer Calibre updates.");
                return latestSupported32BitVersion();
            }
            if (!OS.isWin10OrNewer())
            {
                logger.Warn("Support for Windows 8 (and older Windows versions) has been dropped in Calibre 6.0.0.");
                logger.Warn("Please consider upgrading to Windows 10 or better to get newer Calibre updates.");
                return latestSupported32BitVersion();
            }
            
            var signature = new Signature(publisherX509, certificateExpiration);
            const string knownVersion = "7.0.0";
            InstallInfo info64 = new InstallInfoMsi(
                "https://download.calibre-ebook.com/" + knownVersion + "/calibre-64bit-" + knownVersion + ".msi",
                HashAlgorithm.SHA256,
                "8a1465bf24a73b38fdb84b4e3eefcc813400d2b2434cecc86a7baa644fed9d99",
                signature,
                "/qn /norestart"
                );
            
            return new AvailableSoftware("Calibre",
                knownVersion,
                "^calibre$",
                "^(calibre 64 bit)|(calibre 64bit)$",
                // There are no 32 bit builds from version 6.0.0 onwards,
                // but the 64 bit installer will detect and remove 32 bit
                // versions of Calibre as part of its installation. So we
                // force the switch from 32 bit to the 64 bit version here.
                info64,
                // 64 bit installer
                info64);
        }


        /// <summary>
        /// Gets the information about the latest Calibre version that still has 32 bit builds.
        /// By coincidence, that is also the last version that still supports Windows 8.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public static AvailableSoftware latestSupported32BitVersion()
        {
            var signature = new Signature(
                "CN=Kovid Goyal, O=Kovid Goyal, L=Mumbai, S=Maharashtra, C=IN",
                new DateTime(2022, 9, 29, 12, 0, 0, DateTimeKind.Utc));
            const string knownVersion = "5.44.0";
            return new AvailableSoftware("Calibre",
                knownVersion,
                "^calibre$",
                "^(calibre 64 bit)|(calibre 64bit)$",
                new InstallInfoMsi(
                    "https://download.calibre-ebook.com/5.44.0/calibre-5.44.0.msi",
                    HashAlgorithm.SHA256,
                    "21903563b5bb5817ee33f3a3ea6b0f3b71c3eac1793069f89674d70a99f0f080",
                    signature,
                    "/qn /norestart"),
                new InstallInfoMsi(
                    "https://download.calibre-ebook.com/5.44.0/calibre-64bit-5.44.0.msi",
                    HashAlgorithm.SHA256,
                    "708ba7db84ae9db684b643f81a4fb6b1c65f5e6dac0adc4721e6ed7d20677798",
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
            return new string[] { "calibre" };
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
            logger.Info("Searching for newer version of Calibre...");
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("Calibre does not provide 32 bit binaries from version 6.0.0 onwards.");
                logger.Warn("Please consider switching to an 64 bit operating system to get newer Calibre updates.");
                return latestSupported32BitVersion();
            }
            if (!OS.isWin10OrNewer())
            {
                logger.Warn("Support for Windows 8 (and older Windows versions) has been dropped in Calibre 6.0.0.");
                logger.Warn("Please consider upgrading to Windows 10 or better to get newer Calibre updates.");
                return latestSupported32BitVersion();
            }
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://calibre-ebook.com/download_windows64");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Calibre: " + ex.Message);
                return null;
            }

            // get new version from alternative MSI path on GitHub
            var reMsi = new Regex("https://github.com/kovidgoyal/calibre/releases/download/v[0-9]+\\.[0-9]+\\.[0-9]+/calibre\\-64bit\\-[0-9]+\\.[0-9]+\\.[0-9]+\\.msi");
            Match matchMsi = reMsi.Match(htmlCode);
            if (!matchMsi.Success)
                return null;
            string newVersion = matchMsi.Value.Replace("https://github.com/kovidgoyal/calibre/releases/download/v", "");
            int idx = newVersion.IndexOf('/');
            if (idx < 0)
                return null;
            newVersion = newVersion.Remove(idx);

            // get SHA-256 sums from FossHub (official site provides no hashes)
            try
            {
                var task = client.GetStringAsync("https://www.fosshub.com/Calibre.html");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Calibre: " + ex.Message);
                return null;
            }

            // checksum for Windows 64bit installer
            idx = htmlCode.IndexOf("\"n\":\"calibre-64bit-" + newVersion + ".msi\"");
            if (idx < 0)
                return null;
            // "sha256":"82e0a37fbb556792ce091e63177260d47662a757b21c768e0fe9f7dd4c1b1c06"
            var exprSha256 = new Regex("\"sha256\":\"[0-9a-f]{64}\"");
            Match match = exprSha256.Match(htmlCode, idx);
            if (!match.Success)
                return null;
            string checksum64 = match.Value.Substring(match.Value.Length - 65, 64);

            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            newInfo.install64Bit.checksum = checksum64;
            newInfo.install64Bit.algorithm = HashAlgorithm.SHA256;
            // Use same info for "32 bit" build, forcing switch to 64 bit build on 64 bit OS.
            newInfo.install32Bit = newInfo.install64Bit;
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

    } // class
} // namespace
