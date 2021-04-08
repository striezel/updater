/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021  Dirk Stolle

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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// SeaMonkey localizations that are supported in version 2.48 and later.
    /// </summary>
    public class SeaMonkey : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for SeaMonkey class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(SeaMonkey).FullName);


        /// <summary>
        /// Constructor with language code.
        /// </summary>
        /// <param name="langCode">the language code for the SeaMonkey software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public SeaMonkey(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code for SeaMonkey!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.7/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "e01ba79146e934f80c172bf65b13de87aa5f3687" },
                { "de", "6bf60a6cd381ff5c9486b67a054e103ce618df7d" },
                { "el", "b9a038939cfbd4dfc8616cb0b25c24f1c9c03a32" },
                { "en-GB", "9c108a128ec4cf6bf9a58d8b998ded5eaa29e29c" },
                { "en-US", "78b3ab9ee2b2eff3bc92d700ae51268200c42055" },
                { "es-AR", "0ee0dc67e962c0ae87369e79d0c2ea0d61b16674" },
                { "es-ES", "fd2e8ed27d64faf7286ebece6cf72bd2d5ee356d" },
                { "fi", "04763e29fdacda9744e14221d073dfc9dcf7e88d" },
                { "fr", "8038c4c9c391ad37708942021c663da56fe02b63" },
                { "hu", "c5dba33ef9848cd41107e1747ff895fe8191ba42" },
                { "it", "5b2fb811510d227f93abc495d7e93b2369e0a543" },
                { "ja", "adb3020468ba0feae25eda8aeaa6cea4f32736d0" },
                { "ka", "4a4bac07682eee70b11e2f29bbb0ddf5f98b4953" },
                { "nb-NO", "f10c19766b656b25806756bfebd36791f2f60b56" },
                { "nl", "932e5b720a264753e52bc97c4b5d847f98d38c79" },
                { "pl", "40c4f35f85d1f581faadd7a393f79322ae4e28dd" },
                { "pt-BR", "d1805c16083e368368feb2b21ce3f74cdf168735" },
                { "pt-PT", "8fb111dbf539bb0001715ca2eb3b41edf3607e61" },
                { "ru", "9008d30b449afbf21d7f398a1b03159f04f424ed" },
                { "sk", "adc5fc83ded06f84075c666242bcbce9ae83c1de" },
                { "sv-SE", "2d302a2aa22919cb5e2565e7a1571642dcdc0b41" },
                { "zh-CN", "e7d2db5a4c3c0682677b59a144fe9b2202fc7a0e" },
                { "zh-TW", "b23bf2f2d9d3f33a4efae808b197fec227766f39" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.7/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "6e0a09d351614d65b6a3eaf342a8f5bcb189b3c3" },
                { "de", "d1270a063441df2e63969b8ad28b2916cf9e8460" },
                { "el", "0a70bd57555a1c1e11dc45e027f953955ba9f0fa" },
                { "en-GB", "df7b588ed6db58b56090818c422109561924ec54" },
                { "en-US", "b0e289c28287fa18d43db14595fd648021ed753c" },
                { "es-AR", "4a2eadbc2eb05663d24dfb0c0de5a0ca33783e52" },
                { "es-ES", "00e49acd6afd607f7eb934602519fe37bf536305" },
                { "fi", "cf4afd47230d0d703bc05dee056f71b350cffa9f" },
                { "fr", "d95c20fc8ca733934cf25dbb267bc37de22768cf" },
                { "hu", "c59f149f6debdf4c161d1d1e956014855974e267" },
                { "it", "94e183439787c07885d90183334b7156c0e88ffd" },
                { "ja", "ccac3eac7442f9fb7e9657098e57d623e4d80203" },
                { "ka", "ac92e5d0383d849da8934b8b52f2f489418e162c" },
                { "nb-NO", "0897f05eddd0f0d52ce774e4f88eb946d2e58d83" },
                { "nl", "5575bbe83afeb2c76a9367f4dcc908673e52c756" },
                { "pl", "2b39f60596ea84f4a9c0f7427754c3bc2453caaa" },
                { "pt-BR", "69581be54698a1a4d0013f6a46dbc6a3af5948ee" },
                { "pt-PT", "b3657ef8d75911350b81b90620021af3292b1c4e" },
                { "ru", "d48f2959d3c2656a308b926d406f5ded9cd13729" },
                { "sk", "3eb15e22db7997394d65c48b1e5aa6416cd15450" },
                { "sv-SE", "2bdb7dbfa6e6b362f153a562428fc975acb00345" },
                { "zh-CN", "5b7bb610e2a750291919212f8772f0d1e2e4c361" },
                { "zh-TW", "798b9939acc00665db490532433d0be39bf44600" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            // Just go for the 32 bit installers here. We could also use the
            // 64 bit installers, but they have the same languages anyway.
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "2.53.7";
            return new AvailableSoftware("SeaMonkey (" + languageCode + ")",
                knownVersion,
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/" + knownVersion + "/win32/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win32.installer.exe",
                    HashAlgorithm.SHA1,
                    checksum32Bit,
                    Signature.None,
                    "-ms -ma"),
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/" + knownVersion + "/win64/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win64.installer.exe",
                    HashAlgorithm.SHA1,
                    checksum64Bit,
                    Signature.None,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "seamonkey", "seamonkey-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of SeaMonkey.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://archive.mozilla.org/pub/seamonkey/releases/";
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            
            Regex reVersion = new Regex("/[0-9]+\\.[0-9]+(\\.[0-9]+)?/");
            MatchCollection matches = reVersion.Matches(htmlCode);
            if (matches.Count <= 0)
                return null;

            List<Triple> releaseList = new List<Triple>();
            foreach (Match item in matches)
            {
                var trip = new Triple(item.Value.Replace("/", ""));
                releaseList.Add(trip);
            }
            releaseList.Sort();
            var newest = releaseList[releaseList.Count - 1];

            if (htmlCode.Contains("/" + newest.full() + "/"))
                return newest.full();
            else
                return newest.major.ToString() + "." + newest.minor.ToString();
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successfull.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://archive.mozilla.org/pub/seamonkey/releases/2.53.6/SHA1SUMS.txt
             * Common lines look like
             * "7219....f4b4d  win32/en-GB/SeaMonkey Setup 2.46.exe"
             * 
             * Version 2.53.1 uses a new format. Common lines look like
             * 7ccee70c54580c0c0949a9bc86737fbcb35c46ed sha1 38851663 win32/en-GB/seamonkey-2.53.6.en-GB.win32.installer.exe
             * for the 32 bit installer, or like
             * c6a9d874dcaa0dabdd01f242b610cb47565e91fc sha1 41802858 win64/en-GB/seamonkey-2.53.6.en-GB.win64.installer.exe
             * for the 64 bit installer.
             */

            string url = "https://archive.mozilla.org/pub/seamonkey/releases/" + newerVersion + "/SHA1SUMS.txt";
            string sha1SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha1SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                    return null;
                }
                client.Dispose();
            }

            // look for line with the correct language code and version
            // File name looks like seamonkey-2.53.1.de.win32.installer.exe now.
            Regex reChecksum32Bit = new Regex("[0-9a-f]{40} sha1 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win32\\.installer\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha1SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{40} sha1 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win64\\.installer\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha1SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is in the first 40 characters of each match.
            return new string[] {
                matchChecksum32Bit.Value.Substring(0, 40),
                matchChecksum64Bit.Value.Substring(0, 40)
            };
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
            logger.Debug("Searching for newer version of SeaMonkey (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
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


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // uninstall previous version to avoid having two SeaMonkey entries in control panel
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath , "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// Checks whether the detected software is older than the newest known software.
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            Triple verDetected = new Triple(detected.displayVersion);
            Triple verNewest = new Triple(info().newestVersion);
            return verDetected < verNewest;
        }


        /// <summary>
        /// language code for the SeaMonkey version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;

    } // class
} // namespace
