/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020  Dirk Stolle

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
    /// Handles updates of Audacity.
    /// </summary>
    public class Audacity : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Audacity class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Audacity).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Audacity(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Audacity",
                "2.2.0",
                "^Audacity [0-9]+\\.[0-9]+\\.[0-9]+$",
                null,
                // Audacity only has an installer for 32 bit.
                new InstallInfoExe(
                    "https://www.fosshub.com/Audacity.html/audacity-win-2.2.0.exe",
                    HashAlgorithm.SHA256,
                    "adb0907d3be543f789bfa1dee10429d761ba858e320acf1b98ca5b4ef50b327a",
                    "E=james.k.crook@gmail.com, CN=James Crook, O=James Crook, C=IE",
                    "/VERYSILENT /NORESTART"),
                null
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "audacity" };
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
            logger.Debug("Searching for newer version of Audacity...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://www.fosshub.com/Audacity.html");
                }
                catch (Exception ex)
                {
                    logger.Error("Exception occurred while checking for newer version of Audacity: " + ex.Message);
                    return null;
                }
                client.Dispose();
            }

            const string winInstaller = "Windows Installer";
            int idx = htmlCode.IndexOf(winInstaller);
            if (idx < 0)
                return null;
            htmlCode = htmlCode.Remove(0, idx);

            Regex reVersion = new Regex("audacity\\-win\\-([0-9]+\\.[0-9]+\\.[0-9]+)\\.exe");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string version = matchVersion.Value.Replace(".exe", "").Replace("audacity-win-", "");

            // SHA-256 checksum is somewhere in an embedded JSON that contains a value like:
            // audacity-win-2.4.2.exe","r":"5ef5ead9c63e265869c6d064","hash":{"md5":"cad3e11f580c2dc35503e6ee11833c94","sha1":"522ff2efcc2dc89b6de70c6a0cc486e53b4a7afc","sha256":"1f20cd153b2c322bf1ff9941e4e5204098abdc7da37250ce3fb38612b3e927ba"},"s":false},{"n":"audacity-macos-2.4.2.dmg","r":"5ef5ead9c63e265869c6d064","hash":{"md5":"98f621b8965166da1dbba7c28009af37","sha1":"3859d0b21f5767fddf5ce39cf343ab33c164298a","sha256":"4730abe5b59d9c3dd000fde22d7037af6e6019a4305195a3e4e714f6c9f6380a"},"s":false},{"n":"audacity-minsrc-2.4.2.tar.xz","r":"5ef5ead9c63e265869c6d064","hash":{"md5":"4a34c1c66f69f1fedc400c71d5155ea8","sha1":"3d313a34d14adc77aa77e325a1ef8d5442269b61","sha256":"b3ea9b85f184cec4c1d0da50edb4a588132589d6d1709f6ef0147d52199d0b59"},"s":false},{"n":"audacity-2.4.2.zip","r":"5ef5ead9c63e265869c6d064","hash":{"md5":"2b5fa02187d6301448f4b9c9557a0900","sha1":"e63460d3f8d8a3a71859af609a53ca36954eeba5","sha256":"0c14f7c6850c93b9dacc14fe66876b8dc3397d92dbd849898783a21bad1fff55"},"s":false},{"n":"audacity-macosx-ub-2.1.1-screen-reader.dmg","r":"5ef5ead9c63e265869c6d064","hash":{"md5":"15bddecf3e69428127d0404515791383","sha1":"c23d9262f1a6d31f7289a6ad8e024f14f019bbb3","sha256":"b1913d3362a9221609bae7fab848a5cae93d786d178234c6018e3c95ddfd9d62"},"s":false},{"n":"audacity-manual-2.4.2.zip","r":"5ef5ead9c63e265869c6d064","hash":{"md5":"084830de81c157d229089338a594baab","sha1":"692645e43609a677bae5d84d9239e873202c4b68","sha256":"030b8da55738d80a181af212f6ce25205c4d047a90f21c15acd083c5a589a6c6"},
            // That is what the regular expression will go for.
            Regex reChecksum = new Regex("audacity\\-win\\-"+Regex.Escape(version)+"\\.exe\",\"r\":\"[0-9a-f]+\",\"hash\":\\{\"md5\":\"[0-9a-f]{32}\",\"sha1\":\"[0-9a-f]{40}\",\"sha256\":\"([0-9a-f]{64})\"");
            Match m = reChecksum.Match(htmlCode);
            if (!m.Success)
                return null;
            string checksum = m.Groups[1].Value;

            // construct new information
            var newInfo = knownInfo();
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = version;
            // 32 bit only
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, version);
            newInfo.install32Bit.checksum = checksum;
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
