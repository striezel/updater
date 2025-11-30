/*
    This file is part of the updater command line interface.
    Copyright (C) 2024, 2025  Dirk Stolle

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
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of WinMerge.
    /// </summary>
    public class WinMerge : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for WinMerge class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(WinMerge).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public WinMerge(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Takashi Sawanaka, O=Takashi Sawanaka, L=Chiba, S=Chiba, C=JP";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 10, 18, 11, 02, 19, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("WinMerge",
                "2.16.52.2",
                "^WinMerge [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+?$",
                "^WinMerge ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+ )?x64$",
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/winmerge/stable/2.16.52.2/WinMerge-2.16.52.2-Setup.exe",
                    HashAlgorithm.SHA256,
                    "074d9f175a8cf13d8117b3c75180ce978a47f10efc8c34888ee5380b6dbfd334",
                    signature,
                    "/VERYSILENT /NORESTART"),
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/winmerge/stable/2.16.52.2/WinMerge-2.16.52.2-x64-Setup.exe",
                    HashAlgorithm.SHA256,
                    "f0b8094da0df8f3b6ed02ddda01b8c6264a48d7db0d1ccafb09a16e9090cbe8a",
                    signature,
                    "/VERYSILENT /NORESTART")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["winmerge"];
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
            logger.Info("Searching for newer version of WinMerge...");
            var client = new HttpClient();
            // Server returns "503 Service Unavailable" when no user agent is
            // set, so we pretend to be curl.
            client.DefaultRequestHeaders.Add("User-Agent", "curl/8.16.0");
            string response;
            try
            {
                var task = client.GetStringAsync("https://winmerge.org/downloads/");
                task.Wait();
                response = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer WinMerge version: " + ex.Message);
                return null;
            }

            // Find version. There is a link to the download on sf.net, usually something like
            // "<a href="https://downloads.sourceforge.net/winmerge/WinMerge-2.16.38-x64-Setup.exe" ...>"
            var regEx = new Regex("href=\"https://downloads\\.sourceforge\\.net/winmerge/WinMerge\\-([0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?)\\-x64\\-Setup\\.exe");
            Match match = regEx.Match(response);
            if (!match.Success)
                return null;
            var new_version = match.Groups[1].Value;

            var info = knownInfo();

            // Checksums are in lines like
            // <dt>WinMerge-2.16.38-Setup.exe</dt>
            // <dd><code>84ea3821acee25a4489dd428cfbf1c8a38599f29f36ec1a3356ca219041424da</code></dd>
            // <dt>WinMerge-2.16.38-x64-Setup.exe</dt>
            // <dd><code>fab6f8279a400f27788b2c1288f7ae4dd4d3eb7ab2f1fd9d6fe58fc1b0797198</code></dd>
            // in the HTML code.
            var idx = response.IndexOf("<dt>WinMerge-" + new_version + "-Setup.exe</dt>");
            if (idx == -1)
            {
                return null;
            }
            regEx = new Regex("<code>([0-9a-f]{64})</code>");
            match = regEx.Match(response, idx);
            if (!match.Success)
                return null;
            info.install32Bit.checksum = match.Groups[1].Value;
            info.install32Bit.downloadUrl = info.install32Bit.downloadUrl.Replace(info.newestVersion, new_version);

            idx = response.IndexOf("<dt>WinMerge-" + new_version + "-x64-Setup.exe</dt>");
            if (idx == -1)
            {
                return null;
            }
            match = regEx.Match(response, idx);
            if (!match.Success)
                return null;
            info.install64Bit.checksum = match.Groups[1].Value;
            info.install64Bit.downloadUrl = info.install64Bit.downloadUrl.Replace(info.newestVersion, new_version);

            info.newestVersion = new_version;
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
            return ["WinMergeU"];
        }
    }
}
