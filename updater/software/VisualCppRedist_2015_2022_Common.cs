/*
    This file is part of the updater command line interface.
    Copyright (C) 2025  Dirk Stolle

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
    /// Contains common functions for handling updates of MSVC++ 2015-2022 Redistributables.
    /// </summary>
    public abstract class VisualCppRedist_2015_2022_Common : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for VisualCppRedist_2015_2022_Common class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(VisualCppRedist_2015_2022_Common).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public VisualCppRedist_2015_2022_Common(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        protected const string publisherX509 = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        protected static readonly DateTime certificateExpiration = new(2025, 9, 11, 20, 11, 14, DateTimeKind.Utc);


        /// <summary>
        /// known current version of the MSVC++ 2015-2022 Redistributables
        /// </summary>
        protected const string currentVersion = "14.44.35211.0";


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
            logger.Info("Searching for newer version of Microsoft Visual C++ 2015-2022 Redistributable...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Microsoft Visual C++ 2015-2022 Redistributable: " + ex.Message);
                return null;
            }

            var reMsi = new Regex("The latest version is <code>v?(14\\.[0-9]+\\.[0-9]+\\.[0-9]+)</code>");
            Match matchMsi = reMsi.Match(htmlCode);
            if (!matchMsi.Success)
                return null;
            string newVersion = matchMsi.Groups[1].Value;

            // construct new version information
            var newInfo = knownInfo();
            // ... but use known information, if versions match.
            if (newInfo.newestVersion == newVersion)
                return newInfo;
            // Replace version number - and that's it.
            newInfo.newestVersion = newVersion;
            // Remove checksums - they are outdated now.
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
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
