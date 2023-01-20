/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023  Dirk Stolle

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
        private static readonly DateTime certificateExpiration = new(2025, 1, 5, 23, 59, 59, DateTimeKind.Utc);


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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code for SeaMonkey!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.15/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "f78edf6a4d993462bbd94af0d3f678faa4b45067" },
                { "de", "d22853b9f03721dd4d5a4b04f27d7ce070b09255" },
                { "el", "9ba9eee3e39b39fe87a6e629bca29d673c6da0f2" },
                { "en-GB", "d950b2e9001fe5d3c89a8b8185b98a12269cd05a" },
                { "en-US", "9d71ec0fe951f5420d69984942b8c50faa9db03b" },
                { "es-AR", "1c0cfbe3907d12ad9b78c087f34ff45fdf35ff96" },
                { "es-ES", "5d31870d76a93698708587ccf5ef245284a15b5f" },
                { "fi", "7d3784412685717f619cd51634baac6ad0cfa23e" },
                { "fr", "c44f6d223ab8a4f8f0b1b1ac52ff2278612761b0" },
                { "hu", "665a8025ba665cf44c7f083baa3167194113444e" },
                { "it", "3ccec9f894525d614a67933e2bc4209479c81d99" },
                { "ja", "bcc13c1289046a508a6a9feade371f0cf0d99c9e" },
                { "ka", "d66ced97d77d13ec8c730f44a6b5c0496fdd58ff" },
                { "nb-NO", "e94a639c07a0cc69e96cf273a44348e527233445" },
                { "nl", "127108c9fb50eb0b8ed4f96dcc7ee0f43631b871" },
                { "pl", "9e8e3ba5a096dc4adf59d3b7dbcd073fab47aa1f" },
                { "pt-BR", "fb6dd94d532512b0df6a2d2de595e1761c9cf787" },
                { "pt-PT", "239b5a8306356d5e9841b4e870177da3e9d4a11a" },
                { "ru", "8a509bdbdde36d4f93dd6fc7dea179b57d55cfad" },
                { "sk", "2197e92e19c6fc4e6029d110047498a42d0dda3d" },
                { "sv-SE", "836cd79142ef48dc214278022836b7860cf95ede" },
                { "zh-CN", "c4fc03691e80bc2dde77ac01f0194dd56c25a30c" },
                { "zh-TW", "384a66b4972b95f466ab6fc82108cb50b9930a1a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.15/SHA1SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "222ef17c088b8fa38103b24dd59fe5859784f976" },
                { "de", "14c08e6481edb796f0ee8467f616f8a658e040f2" },
                { "el", "466ee95d1a3ad090fd41748a04aa40f606df90c2" },
                { "en-GB", "617f557bedad509c52bae716ab4ef0cf3c249a22" },
                { "en-US", "ccf1c1f5e8435a759ec37eeeb4407f9144e9752b" },
                { "es-AR", "2f6ab027bcf3fec9aba3574cfa2017c056e130bf" },
                { "es-ES", "e4d10fae40cf2bb01bb0fa9728f76cf6d6163ba3" },
                { "fi", "d8e630ddf865ef4813d6d85293d8de48475d59d6" },
                { "fr", "436cbaf8491f48fb5f69acbadc2b71edfa9e7bce" },
                { "hu", "dc7e6c9806637d8f961f63f3a43954adb1c7583c" },
                { "it", "7a7f693c425a51fbe5a7863ba25f0489629c9561" },
                { "ja", "d1afab5aaaeb7c1fc1aec4fbe830ba35708e7925" },
                { "ka", "5390f814eca53e7420b5bdfe3f73915b4a3cef63" },
                { "nb-NO", "1760ffd8f2e495b04afbd56dbe4187f0c29207cf" },
                { "nl", "61f733e6f59fb32be118ae577356ac7dcd3e7bad" },
                { "pl", "7589b37844744172bff0aea16a82d77d99609467" },
                { "pt-BR", "0177064af36cabee05b5f4f43cec456bfe741a4e" },
                { "pt-PT", "53d1cb73087ed28ed4ec5e34bc1b0e1f0c1496b0" },
                { "ru", "7653dd8c320e7d597ded6d84088c294f3a2925bd" },
                { "sk", "feb048eede1e54f736c6fc834920466d4dc37f82" },
                { "sv-SE", "f34031aab2b3ad6bc5e848d7b3f92e03b72016d7" },
                { "zh-CN", "aea5610507b5745e1234354ff227366e1c2eb4cb" },
                { "zh-TW", "49f0e66dd0a0dbf8fb114d3fb6180ec6d66b22b3" }
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
            const string knownVersion = "2.53.15";
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
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                return null;
            }

            var reVersion = new Regex("/[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?/");
            MatchCollection matches = reVersion.Matches(htmlCode);
            if (matches.Count <= 0)
                return null;

            var releaseList = new List<Quartet>();
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
            string sha1SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha1SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version
            // File name looks like seamonkey-2.53.1.de.win32.installer.exe now.
            var reChecksum32Bit = new Regex("[0-9a-f]{40} sha1 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win32\\.installer\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha1SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{40} sha1 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win64\\.installer\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha1SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is in the first 40 characters of each match.
            return new string[] {
                matchChecksum32Bit.Value[..40],
                matchChecksum64Bit.Value[..40]
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
