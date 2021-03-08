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
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.6/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "5ab46fe9a3be4471331b77935997d2a4c1b4377d" },
                { "de", "4aaa79bdbdb70883f0d0c05d797b8263f8965df2" },
                { "el", "6d72f105856e8db9480490d1e07ff91c6f13b161" },
                { "en-GB", "7ccee70c54580c0c0949a9bc86737fbcb35c46ed" },
                { "en-US", "1a07d66427a12d4bd0aa51c63a25d90cccaf2c46" },
                { "es-AR", "bb000840310fd0e65abbd1abb0f05251bcd85ca8" },
                { "es-ES", "a789a74d3fa204ca8a94e046ef963be0187d899a" },
                { "fi", "4df54613f90568491088e2b9c9d2285b7d21267e" },
                { "fr", "a9fa40bd316063a2b8e0389046e626e36840e9e5" },
                { "hu", "c6f8ec692095272c5f5c79ef9423b9185a0098cc" },
                { "it", "ffd03fb94a115b65de1272a064ebf6d2e3fa4f09" },
                { "ja", "5b31eb61cd08a3e3cfdf700fa926da33f0a9451e" },
                { "ka", "7fc9e29843b4fadbfca0841fb66ef3fe1db9b74b" },
                { "nb-NO", "0a9a08543120b798822428c03be7c264b6448820" },
                { "nl", "8055d149d0bc98faa79c9a56de884fe13fd5ff26" },
                { "pl", "c486210ce0f6bed21b78cdc291633d3d05b2ea6e" },
                { "pt-BR", "79fdf02ee2301a2bff8ba76fd4379fae3f518d99" },
                { "pt-PT", "2b40a950ed51213f8a76ca6986df2c246721b5aa" },
                { "ru", "b37f9a7e0d1c339a756fa6317d424fbf9c14c9d5" },
                { "sk", "c401c1a0d611bcd498b2bb66ac9346f34e51cc19" },
                { "sv-SE", "396c1520f77c8762d84a6fe17ce3c6a7f9c85703" },
                { "zh-CN", "f6cbfc1ddf13cac9f98812d8eda8ac34b2b9c0d6" },
                { "zh-TW", "a968fd14ce825ab0a2a157b8565c03aeb1d6d062" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.6/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "b0d9f0fdb0f7ff6922ce2a01a2c3a35e6ed80dd3" },
                { "de", "de2a3931f195831b6df3d3c18094b3d7cacff619" },
                { "el", "a7bc7962ebd58f67c25952918e6ee42e69e43ae1" },
                { "en-GB", "c6a9d874dcaa0dabdd01f242b610cb47565e91fc" },
                { "en-US", "405f32644e8bd162836fc3db52beb0f46bc2bf56" },
                { "es-AR", "306fb01ce5c501e598f8e4ef5e829e5b6319fd79" },
                { "es-ES", "a6ac51932b1241dee9679a70a00679ecccf0f7b1" },
                { "fi", "0903c23de9d5a83ee45ee5caf234554ffd4b254c" },
                { "fr", "d77a3c9436819fa0fb196404e6eb1f0c31b9ce31" },
                { "hu", "6c206bf6ab792c7400262a88a17f7d79ae651c5a" },
                { "it", "a53cafc97cdf36d90225c942ed8f6567afadd6cf" },
                { "ja", "8de8e410e0e9126f160db6caf58b77c477b588fd" },
                { "ka", "f9b9ae22d1cd95e798cea98f28a47a5346ee79a6" },
                { "nb-NO", "8234ebc9109ed77c9ea342cd5218b5142b3c41de" },
                { "nl", "ab8a82d4591a352162dae309e5761550ce3e633e" },
                { "pl", "f27730ada264cba1ccc8a6f9e2907fc05105eeb9" },
                { "pt-BR", "5ae8f8516cf90443dec983800b610f6c46969d1b" },
                { "pt-PT", "4d055e601563284fe8ed33588e7c7471cf8d90f4" },
                { "ru", "ef3377c48dcec060b7a04165ea4c2d4d2e84ed05" },
                { "sk", "78ff21c14356e752afb73c9050704b3cfedefe5d" },
                { "sv-SE", "6efff41668cfbbe4548dfa9bc37cf754da25c3ad" },
                { "zh-CN", "de6af74a84e9ae9cb865a7ab84c3b8be88ec1e41" },
                { "zh-TW", "f776de15463dfbe3a2714f1d350503e60b2409f3" }
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
            const string knownVersion = "2.53.6";
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
        /// <returns>Returns true, if a separate proess returned by
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
