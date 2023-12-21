/*
    This file is part of the updater command line interface.
    Copyright (C) 2022, 2023  Dirk Stolle

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
    /// Handles updates of IrfanView.
    /// </summary>
    public class IrfanView : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for CDBurnerXP class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(IrfanView).FullName);


        /// <summary>
        /// publisher name for signed executables of IrfanView
        /// </summary>
        private const string publisherX509 = "CN=Irfan Skiljan, O=Irfan Skiljan, S=Lower Austria, C=AT";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2026, 8, 1, 9, 46, 7, DateTimeKind.Utc);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public IrfanView(bool autoGetNewer)
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
            return new AvailableSoftware("IrfanView",
                "4.66",
                "^(IrfanView [0-9]+\\.[0-9]+ \\(32\\-bit\\)|IrfanView \\(remove only\\))$",
                "^(IrfanView [0-9]+\\.[0-9]+ \\(64\\-bit\\)|IrfanView 64 \\(remove only\\))$",
                new InstallInfoExe(
                    "https://www.irfanview.info/files/iview466_setup.exe",
                    HashAlgorithm.SHA256,
                    "681577dffd38c937173882954e2503b21f5d263b771f1f93d0f9e782655eedc6",
                    signature,
                    "/silent /desktop=1 /group=1 /allusers=1 /assoc=1"),
                new InstallInfoExe(
                    "https://www.irfanview.info/files/iview466_x64_setup.exe",
                    HashAlgorithm.SHA256,
                    "4335d6dc500456a3c4554e04143b332885b5939321f4aab5bed5e6b70c746f16",
                    signature,
                    "/silent /desktop=1 /group=1 /allusers=1 /assoc=1")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "irfanview" };
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
            logger.Info("Searching for newer version of IrfanView...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://www.irfanview.com/64bit.htm");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of IrfanView: " + ex.Message);
                return null;
            }

            // There's a link like '<a href="https://www.fosshub.com/IrfanView.html?dwl=iview460_x64_setup.exe" ...'
            // on the download page.
            var versionRegEx = new Regex("href=\"https://www\\.fosshub\\.com/IrfanView\\.html\\?dwl=iview([0-9]+)_x64_setup\\.exe\"");
            var versionMatch = versionRegEx.Match(htmlCode);
            if (!versionMatch.Success)
                return null;
            string version_digits = versionMatch.Groups[1].Value;
            string version = string.Concat(version_digits.AsSpan(0, version_digits.Length - 2), ".", version_digits.AsSpan(version_digits.Length - 2));

            // Get 64 bit checksum.
            var checksumRegEx = new Regex("[0-9a-f]{64}");
            var checksumMatch = checksumRegEx.Match(htmlCode, versionMatch.Index + 1);
            if (!checksumMatch.Success)
                return null;

            var info = knownInfo();
            info.install64Bit.checksum = checksumMatch.Value;
            string oldVersionWithoutDot = info.newestVersion.Replace(".", "");
            info.newestVersion = version;
            info.install64Bit.downloadUrl = info.install64Bit.downloadUrl.Replace(oldVersionWithoutDot, version_digits);

            // Get 32 bit checksum.
            try
            {
                var task = client.GetStringAsync("https://www.irfanview.com/main_download_engl.htm");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of IrfanView: " + ex.Message);
                return null;
            }

            // There's the executable name (e. g. iview460_setup.exe) followed by the checksum.
            versionRegEx = new Regex("iview([0-9]+)_setup.exe");
            versionMatch = versionRegEx.Match(htmlCode);
            if (!versionMatch.Success)
                return null;
            // Should be the same version as the 64 bit version.
            if (versionMatch.Groups[1].Value != version_digits)
            {
                logger.Warn("Different versions for 32 bit and 64 bit variant of IrfanView were detected."
                    + " Something is wrong here.");
                return null;
            }
            checksumMatch = checksumRegEx.Match(htmlCode, versionMatch.Index + 1);
            if (!checksumMatch.Success)
                return null;
            info.install32Bit.checksum = checksumMatch.Value;
            info.install32Bit.downloadUrl = info.install32Bit.downloadUrl.Replace(oldVersionWithoutDot, version_digits);

            return info;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(2)
            {
                "i_view64",
                "i_view32",
            };
        }
    }
}
