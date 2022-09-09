/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022  Dirk Stolle

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
    /// Handles updates of CDBurnerXP.
    /// </summary>
    public class CDBurnerXP : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for CDBurnerXP class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(CDBurnerXP).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public CDBurnerXP(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed installer files
        /// </summary>
        private const string publisherX509 = "CN=Canneverbe Limited, OU=Canneverbe Limited, O=Canneverbe Limited, L=Goch, S=North Rhine-Westphalia, C=DE";


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = Signature.NeverExpires(publisherX509);
            return new AvailableSoftware("CDBurnerXP",
                "4.5.8.7128",
                "^CDBurnerXP$",
                "^CDBurnerXP \\(64 Bit\\)$",
                new InstallInfoMsi(
                    "https://download.cdburnerxp.se/msi/cdbxp_setup_4.5.8.7128.msi",
                    HashAlgorithm.SHA256,
                    "e92450832b09e32fc769bc94d3b00b04ef5c05d7542cec77a63603c562b757d1",
                    signature,
                    "/qn /norestart"),
                new InstallInfoMsi(
                    "https://download.cdburnerxp.se/msi/cdbxp_setup_x64_4.5.8.7128.msi",
                    HashAlgorithm.SHA256,
                    "af80a5b901100d73855dd1f04845c79511cc2f1299c0ca38dfac8d03ce8fed00",
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
            return new string[] { "cdburnerxp" };
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
            logger.Info("Searching for newer version of CDBurnerXP...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://cdburnerxp.se/download");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of CDBurnerXP: " + ex.Message);
                return null;
            }

            var reMsi = new Regex("cdbxp_setup_[1-9]\\.[0-9]\\.[0-9]\\.[0-9]{4}\\.msi");
            Match matchMsi = reMsi.Match(htmlCode);
            if (!matchMsi.Success)
                return null;
            string newVersion = matchMsi.Value.Replace("cdbxp_setup_", "").Replace(".msi", "");

            // construct new version information
            var newInfo = knownInfo();
            // ... but use known information, if versions match. That way we
            // have valid checksums for the files after download.
            if (newInfo.newestVersion == newVersion)
                return newInfo;
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion);
            // no checksums are provided on the official site, but binaries are signed
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion);
            // no checksums are provided on the official site, but binaries are signed
            newInfo.install64Bit.checksum = null;
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
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
            return new List<string>();
        }

    } // class
} // namespace
