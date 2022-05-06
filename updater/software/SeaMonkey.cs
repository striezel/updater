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
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.12/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "0297b43f0af02710d8bfa53d7832631e8272d114" },
                { "de", "6e98e0c556ac042446d1d1bceb307f40064df13c" },
                { "el", "569cf265f9683f79336bc5c1d462de1e86ec6335" },
                { "en-GB", "bd8cb4e112452e1bd7e2e772030fe8694b44aed4" },
                { "en-US", "ae3b3b3a0b9cbd5080a530572f360c81b59d0cda" },
                { "es-AR", "da68554024562ac5cf5b3342f5c84b5e7b11d7ba" },
                { "es-ES", "7b41d5f36f3f2951e665a0fd9daf35b4b777eb11" },
                { "fi", "d5411c396543b10730a15418868044f259a0c5e8" },
                { "fr", "197f09586a6f4313409bb468f4f360f3f19156f3" },
                { "hu", "c2dcfe0f5e3b6536cc72a02e3f49a149d1069b35" },
                { "it", "7c324e6d7160367a6323c1287aa53a181d3bf537" },
                { "ja", "60fd65c2edf59fda3a5387d608fc8a367d1c2cca" },
                { "ka", "d40eb967413222fe36b0046f979f3794df0cce4e" },
                { "nb-NO", "b7a04bd409676edf445f72242d5a4c2bb2014f22" },
                { "nl", "c1569078d253eeffc89d883e8258e2fe50a503aa" },
                { "pl", "b1d6615b4731b4ec8a1e2dcad77dd9ceac37586f" },
                { "pt-BR", "7ad4587603718dbe12484f6deba697d7303e3b72" },
                { "pt-PT", "5354f048e5505d3f5de27b3c3ee53bf00311b19d" },
                { "ru", "5b38cb7a6118bfd453b1e995f080799df0a6f3bf" },
                { "sk", "826eefe2906b7f935210b30b549867f674239e0e" },
                { "sv-SE", "42c68f898d686655bb69139bade520adfdbb5a20" },
                { "zh-CN", "2872e9a62f97cac87f79c037ee37ef56c50439f7" },
                { "zh-TW", "198da3ed17311c7554cf2610770ac056e430d4db" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.12/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "b1ebbd50234136cc2b02f69c9b07d77f92eb9872" },
                { "de", "545ec477f56ecacbcc1982eef7d69c53715bdd75" },
                { "el", "692cf2860b68a2e5f8b2f2dc43868bc6faed53ac" },
                { "en-GB", "af8b19d2abaeff208e2d4ec12724fac35ac351c6" },
                { "en-US", "55755b27f0860178e33473bba4a71beda4e75a11" },
                { "es-AR", "3bf4fdb250947fe47e2042fbd694282bf049c410" },
                { "es-ES", "f6346eae3692e29ef8c2960f28050c267a187c41" },
                { "fi", "7979280809960edee18a6cbcc759f3a6292e0b28" },
                { "fr", "2a46dee079b79076b77bee09b41acc36a1ad31e6" },
                { "hu", "edb5ab7622a6858cd85060a75b476e05948a1845" },
                { "it", "b4fa69b74031f40bc78380e3580a21e2d8bdf935" },
                { "ja", "09822f250c3190b1649378d4468b7775790098ad" },
                { "ka", "161d6c36ed7b3e1beeb751d5992166fc5ac5c310" },
                { "nb-NO", "b2aa06dc5a598610de6c550c87d075bfdcaec50a" },
                { "nl", "385728c08b275bde23c32dc98442478303a470c3" },
                { "pl", "58a53246780e78ef7efb754a529f1d2dab05cea5" },
                { "pt-BR", "5f7ebeda5ecd770736bfa84a074d3f6fe9ea6b9c" },
                { "pt-PT", "494430041e8ca68c6854b036ef113565f6bf0a33" },
                { "ru", "cd0987ca4f3d79105a3749ef12aeb45c7398a210" },
                { "sk", "de6d7b80da5bdb6c31fe08ce98e620b5ad2714eb" },
                { "sv-SE", "7bcd666f031a1c233c9ba9dcbe850043cb57a455" },
                { "zh-CN", "d9b2edfcad5aa7c428e72d0363d54a193b88d68a" },
                { "zh-TW", "2a9ad58fb58418208377e22321a9923430504bc8" }
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
            const string knownVersion = "2.53.12";
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
