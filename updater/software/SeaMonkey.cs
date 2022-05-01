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
        /// publisher name for signed installers
        /// </summary>
        private const string publisherX509 = "CN=SeaMonkey e.V., O=SeaMonkey e.V., S=Bayern, C=DE";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2022, 12, 13, 23, 59, 59, DateTimeKind.Utc);


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
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.11.1/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "4b887f2960f6e681c9371a12eb17ee6d8cb31f8c" },
                { "de", "136398692eaa7d6dc0f186b579c20fabef2c470a" },
                { "el", "902edc31ad0d44a65333c97e6e7d1ced440a86a7" },
                { "en-GB", "9bb9bc663dda8f4b5c8b8ae1e1a9e12f4a99851e" },
                { "en-US", "4cba8c66d615eaf3b9b6b9b3745ee68681fe0021" },
                { "es-AR", "9a159da7325bfa8c0765f34e6b6096a7e78fba84" },
                { "es-ES", "ee2ab6b64d10c1c4d7e3d0b95676dfe645417202" },
                { "fi", "579ea908b4606c5a03dba78bf045692d20f93c24" },
                { "fr", "0adf4b91fa96c6cdfdbed6d80de4a374eacbb57b" },
                { "hu", "e6ded9f9dcf3eb669c2e49723cbb6f32d06ea540" },
                { "it", "ca2b6cbc4800efa44019bf2d6f0a3a8f43cfbed7" },
                { "ja", "74316f0322052c20d4d0b678864b0e6b58b24c0d" },
                { "ka", "e413c7294a8c24261f6372959571fdbcd174f01d" },
                { "nb-NO", "cfcf607941c36458cc2c9dadd8e57082ba51d9e8" },
                { "nl", "325133be493833d2e3d0f173ec3a669011ca10f8" },
                { "pl", "889ac0b9cf1abba6fe3ac7aa34b0c171b9af3f29" },
                { "pt-BR", "e018efbed7d19e38d4fd9d8e76fbb828b116b00b" },
                { "pt-PT", "e40c5805cd2787eb501a604793a5c830a012bf2c" },
                { "ru", "1c43f819405822df2f9110270dbde1fe52e674cd" },
                { "sk", "5a25e97d195856165386afd6bdad1874fe843016" },
                { "sv-SE", "8f8f3e98f55ed2dc43ed4bfeb86c17b324153eab" },
                { "zh-CN", "7ffa18e44f837a1b6cf9f44c44a6ab88e36ef914" },
                { "zh-TW", "be1a36ba8e94a73001d247fa47c6385fae75d3a3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.11.1/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "8df206fcedcc5dd1481bf6c627d16516f60ce116" },
                { "de", "cdfa4a6c5a2adcd2429f4536c9d5eb5562afa826" },
                { "el", "51b5d5333773261a7b1f3734c1c3d3f802228e67" },
                { "en-GB", "170f9e06e35e3950c0b84374bf57d5a6a97b10a9" },
                { "en-US", "90e2e4ec4df94ee8ec50ad0f663ad1d6b59cecf8" },
                { "es-AR", "c867008091b2ea668e2d1baaeaa18ab97c112fde" },
                { "es-ES", "cb28d56ade07d91015e8496a240653489cf66c78" },
                { "fi", "413f912d0ac4c5cd761e11c7a84c9416bc32a57e" },
                { "fr", "35c53ea9de7f291dfd573735e51f63b439bdc5f6" },
                { "hu", "0943c18390a74d52e847074c700f8be66fbc012c" },
                { "it", "5458998a09c771407022c4eb62abd45b3e5c304d" },
                { "ja", "32d8e52b37c059e2572a6dc6abca396a27cb0209" },
                { "ka", "d3c91f2f5d8f9f9d4b81f005f5aa3afaf7c60960" },
                { "nb-NO", "2d801b883abbbc43b4547b5145243023c98238f1" },
                { "nl", "364778452aab20e0ad20251f4167284ff08a462f" },
                { "pl", "d98849da87282e7e419851796ff6635fdc1fc5df" },
                { "pt-BR", "ac2c2228afe506e1c8eb961c9bafb12ee7469c6f" },
                { "pt-PT", "1ce530433ec6349dead07e23c3171c61e7c57bf6" },
                { "ru", "6e5f653b5050443ba54cd59319b884978ec58894" },
                { "sk", "15ddbeeb640f9ccd8ea011fec26e7ca3ca1ed450" },
                { "sv-SE", "fcfd6a3ef51acdd75be904268667b70f9d68799f" },
                { "zh-CN", "445caf3a8f60c33d85ea886a32dac7afe7e0458d" },
                { "zh-TW", "1dcf20cf70e149300ef0be1934e62c16adee17a9" }
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
            const string knownVersion = "2.53.11.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("SeaMonkey (" + languageCode + ")",
                knownVersion,
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/" + knownVersion + "/win32/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win32.installer.exe",
                    HashAlgorithm.SHA1,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/" + knownVersion + "/win64/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win64.installer.exe",
                    HashAlgorithm.SHA1,
                    checksum64Bit,
                    signature,
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
            
            Regex reVersion = new Regex("/[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?/");
            MatchCollection matches = reVersion.Matches(htmlCode);
            if (matches.Count <= 0)
                return null;

            List<Quartet> releaseList = new List<Quartet>();
            foreach (Match item in matches)
            {
                var quart = new Quartet(item.Value.Replace("/", ""));
                releaseList.Add(quart);
            }
            releaseList.Sort();
            var newest = releaseList[releaseList.Count - 1];

            if (htmlCode.Contains("/" + newest.full() + "/"))
                return newest.full();
            var trip = new Triple(newest.full());
            if (htmlCode.Contains("/" + trip.full() + "/"))
                return trip.full();
            else
                return newest.major.ToString() + "." + newest.minor.ToString();
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            logger.Info("Searching for newer version of SeaMonkey (" + languageCode + ")...");
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
