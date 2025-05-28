﻿/*
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
using System.Net;
using System.Net.Http;
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
        private const string publisherX509 = "CN=Gen Digital Inc., O=Gen Digital Inc., L=Tempe, S=Arizona, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 5, 21, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            var installer = new InstallInfoExe(
                "https://download.ccleaner.com/ccsetup636.exe",
                HashAlgorithm.SHA256,
                "57adcfb5e0b95146bce09d71452fd6269b1f61f37474dfe5a14e3603b568ca3d",
                signature,
                "/S");
            return new AvailableSoftware("CCleaner",
                "6.36",
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
            return ["ccleaner"];
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
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            string fileName;
            try
            {
                HttpRequestMessage msg = new(HttpMethod.Head, cdnUrl);
                var task = client.SendAsync(msg);
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.OK)
                    return null;
                if (response.Content.Headers.ContentDisposition == null)
                    return null;
                fileName = response.Content.Headers.ContentDisposition.FileNameStar;
                fileName ??= response.Content.Headers.ContentDisposition.FileName;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer version of CCleaner: " + ex.Message);
                return null;
            }

            if (string.IsNullOrEmpty(fileName))
                return null;

            var reVersion = new Regex("ccsetup([0-9]+)\\.exe");
            Match matchVersion = reVersion.Match(fileName);
            if (!matchVersion.Success)
                return null;

            string newVersion = matchVersion.Groups[1].Value;
            // new version should be at least three digits long
            if (newVersion.Length < 3)
                return null;
            newVersion = string.Concat(newVersion.AsSpan(0, newVersion.Length - 2), ".", newVersion.AsSpan(newVersion.Length - 2));
            var known = knownInfo();
            if (newVersion == known.newestVersion)
                return known;
            string newUrl = "https://download.ccleaner.com/ccsetup" + matchVersion.Groups[1].Value + ".exe";

            // No checksums are provided, but binary is signed.

            // construct new information
            var newInfo = known;
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
            return [];
        }
    } // class
} // namespace
