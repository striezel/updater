/*
    This file is part of the updater command line interface.
    Copyright (C) 2022, 2023, 2024, 2025  Dirk Stolle

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
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Adobe Acrobat Reader 2020.
    /// </summary>
    public class AcrobatReader2020 : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for AcrobatReader2020 class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(AcrobatReader2020).FullName);


        /// <summary>
        /// publisher name for signed executables of Reader 2020
        /// </summary>
        private const string publisherX509 = "CN=Adobe Inc., OU=Acrobat DC, O=Adobe Inc., L=San Jose, S=ca, C=US, SERIALNUMBER=2748129, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 10, 5, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public AcrobatReader2020(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "20.005.30838";
            var installer = new InstallInfoMsiPatch(
                "https://ardownload3.adobe.com/pub/adobe/reader/win/Acrobat2020/2000530838/AcroRdr2020Upd2000530838_MUI.msp",
                HashAlgorithm.SHA256,
                "988e793a79801ea2c7f1126c029a51425b8b6746a7fb9ff7892d55dbfd617640",
                new Signature(publisherX509, certificateExpiration),
                "/qn /norestart"
                );
            return new AvailableSoftware("Acrobat Reader 2020",
                version,
                "^Adobe Acrobat Reader 2020 MUI$",
                "^Adobe Acrobat Reader 2020 MUI$",
                installer,
                installer);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["acrobat-reader-2020", "acrobat-reader", "acrobat"];
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
            logger.Info("Searching for newer version of Acrobat Reader 2020...");
            string html;
            // The request hangs and times out without an User-Agent header,
            // so let's provide a simple curl User-Agent here.
            var client = new HttpClient();
            client.DefaultRequestHeaders.Add("User-Agent", "curl/8.16.0");
            try
            {
                var task = client.GetStringAsync("https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html");
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Acrobat Reader 2020: " + ex.Message);
                return null;
            }

            // HTML text will contain links to both continuous track and classic
            // track, but we only want the classic stuff. Links will look like
            // '<a disablelinktracking="false" href="https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/classic/dcclassic20.005aug2022.html#dc20-005augtwentytwentytwo">20.005.30381</a>'
            // or '<a class="reference internal" href="classic/dcclassic20.005sep2025.html#dc20-005septwentytwentyfive"><span class="std std-ref">20.005.3079x Planned update, Sep 9, 2025</span></a>'
            var reVersion = new Regex("href=\"(classic/dcclassic20\\.[0-9]{3}[a-z]{3}[0-9]{4}.html)#dc20\\-[0-9]+[a-z]+\"><span class=\"std std\\-ref\">(20\\.[0-9]+\\.[0-9x]+) [A-Za-z0-9 ,]+</span></a>");
            var match = reVersion.Match(html);
            if (!match.Success)
                return null;
            var latestVersion = match.Groups[2].Value.Replace('x', '0');
            string notesLink = "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/" + match.Groups[1].Value;

            var latestInfo = knownInfo();
            var knownTriple = new Triple(latestInfo.newestVersion);
            var latestTriple = new Triple(latestVersion);
            if (knownTriple.CompareTo(latestTriple) >= 0)
            {
                return latestInfo;
            }

            try
            {
                var task = client.GetStringAsync(notesLink);
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for the latest release of Acrobat Reader 2020: " + ex.Message);
                return null;
            }

            // Link to the *.msp file will look like this:
            // <a class="reference external" href="https://ardownload2.adobe.com/pub/adobe/reader/win/Acrobat2020/2000530381/AcroRdr2020Upd2000530381_MUI.msp">AcroRdr2020Upd2000530381_MUI.msp</a>
            var reLink = new Regex("https://ardownload[0-9]\\.adobe\\.com/pub/adobe/reader/win/Acrobat2020/[0-9]+/AcroRdr2020Upd[0-9]+_MUI.msp");
            match = reLink.Match(html);
            if (!match.Success)
                return null;

            latestInfo.newestVersion = latestVersion;
            // Release notes do not provide any checksum.
            latestInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            latestInfo.install32Bit.checksum = null;
            latestInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
            latestInfo.install64Bit.checksum = null;
            // Set new download URL.
            latestInfo.install32Bit.downloadUrl = match.Value;
            latestInfo.install64Bit.downloadUrl = match.Value;
            return latestInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return ["AcroRd32"];
        }
    } // class
} // namespace
