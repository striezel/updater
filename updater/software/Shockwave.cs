/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
    public class Shockwave : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Shockwave class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Shockwave).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Shockwave(bool autoGetNewer)
            : base(autoGetNewer)
        { }

        /// <summary>
        /// publisher of signed installers
        /// </summary>
        private const string publisherX509 = "CN=Adobe Systems Incorporated, OU=Shockwave Player, O=Adobe Systems Incorporated, L=San Jose, S=California, C=US, PostalCode=95110, STREET=345 Park Avenue, SERIALNUMBER=2748129, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US, OID.2.5.4.15=Private Organization";


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Adobe Shockwave Player",
                "12.3.4.204",
                "^Adobe Shockwave Player [0-9]+\\.[0-9]+$",
                null,
                // Shockwave Player only has one installer.
                new InstallInfoMsi(
                    "http://fpdownload.macromedia.com/get/shockwave/default/english/win95nt/latest/sw_lic_full_installer.msi",
                    HashAlgorithm.SHA512,
                    "eb77b34564f6ef4abb7591a5c33d5dfef9167127af39571fc7d8463aeb2f9977ccd6187eabdb3e4d1d3964a72fdcbe621bc48d5605e4f70321a22c69a8e4d8a9",
                    publisherX509,
                    "/qn /norestart"),
                // There is no 64 bit installer.
                null);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "shockwave-player" };
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
            logger.Debug("Searching for newer version of Shockwave Player...");
            // https://get.adobe.com/de/shockwave/
            // https://get.adobe.com/shockwave/webservices/json/
            string htmlCode = null;
            using (var client = new WebClient())
            {
                // Add fake user agent header to emulate Firefox browser.
                // Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0
                // This is required to get a proper answer from the webservice endpoint.
                client.Headers.Add(HttpRequestHeader.UserAgent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0");
                try
                {
                    htmlCode = client.DownloadString("https://get.adobe.com/shockwave/webservices/json/");
                }
                catch (Exception ex)
                {
                    logger.Error("Exception occurred while checking for newer version of Shockwave Player: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            /* JSON response is something like this, but not so nicely formatted:
             
             [{
               "distrib": 0.0,
               "file_size": 5.9,
               "can_use_dlm": 0.0,
               "queryName": "Shockwave_12.3.4.204_Windows_Slim_Other_Browsers",
               "installation_type": "Standalone",
               "live": 1.0,
               "platform": "Windows",
               "language_type": "English",
               "browser": "Firefox",
               "download_url": "http:\/\/fpdownload.macromedia.com\/get\/shockwave\/default\/english\/win95nt\/latest\/Shockwave_Installer_Slim.exe",
               "Version": "12.3.4.204",
               "gp_diskspace": 6626544.0,
               "aih_ineligible_reg_test": 0.0,
               "date_posted": "06\/25\/2014",
               "aih_show_installer_window": 0.0,
               "livebeta": 1.0,
               "aih_ineligibility_file_test": 0.0,
               "Name": "Shockwave 12.3.4.204 Windows Slim Other Browsers",
               "aih_is_visible": 1.0,
               "aih_ineligible_chk_uninst": 0.0,
               "gp_checksum": "27a4c795d5c8c50168d7cafa121bfc58",
               "aih_cleanup": 1.0,
               "id": 345.0,
               "shockwave_type": "Slim"
             }]
             
             */

            // find version number
            int idx = htmlCode.IndexOf("\"Version\"");
            if (idx < 0)
                return null;
            Regex regExVersion = new Regex("\"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+");
            string shortened = htmlCode.Substring(idx);
            Match versionMatch = regExVersion.Match(shortened);
            if (!versionMatch.Success)
                return null;
            string newVersion = versionMatch.Value.Replace("\"", "");
            // find download URL
            idx = htmlCode.IndexOf("\"download_url\"");
            if (idx < 0)
                return null;
            shortened = htmlCode.Substring(idx);
            Regex regExURL = new Regex("\"http.+\\.exe\"");
            Match urlMatch = regExURL.Match(shortened);
            if (!urlMatch.Success)
                return null;
            string downloadURL = urlMatch.Value.Replace("\"", "").Replace("\\", "");
            // Default installer is the "slim" installer, but we want the full installer.
            downloadURL = downloadURL.Replace("Shockwave_Installer_Slim.exe", "sw_lic_full_installer.msi");

            // create new info from known information
            var newInfo = knownInfo();
            newInfo.newestVersion = newVersion;
            newInfo.install32Bit.downloadUrl = downloadURL;
            // There is no checksum provided here.
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            return newInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }

    } // class
} // namespace
