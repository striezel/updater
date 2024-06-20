/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
    /// CCleaner (free version)
    /// </summary>
    public class CCleaner : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for CCleaner class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(CCleaner).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public CCleaner(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher name for signed executables
        /// </summary>
        private const string publisherX509 = "CN=Piriform Software Ltd, O=Piriform Software Ltd, L=London, C=GB, SERIALNUMBER=08235567, OID.1.3.6.1.4.1.311.60.2.1.3=GB, OID.2.5.4.15=Private Organization";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 12, 4, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            var installer = new InstallInfoExe(
                "https://download.ccleaner.com/ccsetup625.exe",
                HashAlgorithm.SHA256,
                "e963abf025714d9cba73ccc42a8b8759dc622db08b11e61eb91983a46f73ecc7",
                signature,
                "/S");
            return new AvailableSoftware("CCleaner",
                "6.25",
                "^CCleaner+$",
                "^CCleaner+$",
                // CCleaner uses the same installer for 32 and 64-bit.
                installer,
                installer
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "ccleaner" };
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
            logger.Info("Searching for newer version of CCleaner...");
            const string cdnUrl = "https://bits.avcdn.net/productfamily_CCLEANER/insttype_FREE/platform_WIN_PIR/installertype_ONLINE/build_RELEASE";
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(cdnUrl);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            string contentDisposition;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.OK)
                    return null;
                contentDisposition = response.Headers.Get("Content-Disposition");
                if (contentDisposition == null)
                    return null;
                request = null;
                response.Dispose();
                response = null;
            }
            catch (Exception ex)
            {
                logger.Error("Exception occurred while checking for newer version of CCleaner: " + ex.Message);
                return null;
            }

            var reVersion = new Regex("attachment; filename=\".*ccsetup([0-9]+)\\.exe.*\"");
            Match matchVersion = reVersion.Match(contentDisposition);
            if (!matchVersion.Success)
                return null;

            string newVersion = matchVersion.Groups[1].Value;
            // new version should be at least three digits long
            if (newVersion.Length < 3)
                return null;
            newVersion = string.Concat(newVersion.AsSpan(0, newVersion.Length - 2), ".", newVersion.AsSpan(newVersion.Length - 2));
            if (newVersion == knownInfo().newestVersion)
                return knownInfo();
            string newUrl = "https://download.ccleaner.com/ccsetup" + matchVersion.Groups[1].Value + ".exe";
            
            // No checksums are provided, but binary is signed.

            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = newVersion;
            // 32-bit
            newInfo.install32Bit.downloadUrl = newUrl;
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            // 64-bit - same installer
            newInfo.install64Bit.downloadUrl = newUrl;
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
