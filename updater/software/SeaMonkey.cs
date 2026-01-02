/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d64 = knownChecksums64Bit();
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code for SeaMonkey!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.23/SHA512SUMS.txt
            return new Dictionary<string, string>(24)
            {
                { "cs", "08a55096518f3a74c6a04f96016e0c0c1503668447d15e18f18ccdd8fd6d08e03f2d44894e6d42345dca959dbbae23e415155fcd56cdd4f59ba089fe7c7c394d" },
                { "de", "ddf8778816e9278d1e93c903077636b061008f7e4abd680d5b55a8dbbf3fddf37dd173311ed4fafa74aae4a6e2122cc68d40ae455680998e7b0dcc756b18d63a" },
                { "el", "135a54c9ed3fd1b72c976a422ff796d97f8df8d54b055e04e8ad445bf7784eb2bab4a84800d6c9af0caf77a969821b53b5f4814bb7785da79d4d3be3bab0f0f9" },
                { "en-GB", "c05fefe4a4f501586ca011ac321db95b04bf035ddc5a9fbe48324528d7806b049a5fbb31dd87037719508c0df812eef09da58c43a9fc37cde0c7c6df8227737c" },
                { "en-US", "427d0119fc21cc2244ae730378b8c39d464d772600a8a42b74efa22386ed1e64ae7feae61038192f9f60a5c49c6992285f3c3bc0719ebc15fc28398ec4827343" },
                { "es-AR", "f78b38fe41079b9dc67d752fe53e89e6d4e42bf4f50877643d1cd51b7d2e1f633f6774beeadd075330e19816faec29c50bf7abf9a3e20f21a3768e798a38849a" },
                { "es-ES", "0bf5c427439cf84baccf5382006ecb06ba958add14067aa8d7496b0dadf79cee40064ecb588978018cb6b0abcebb61553e4db4e8343e26d1256b603c6c611047" },
                { "fi", "7d21fe26cd9ce53a5eeef1bc2bf456f9b1ef91deeec35aa9a7c72304fe454f1d72521a6231c3c40bceb1cb6623d4fb5d4cedcfea1375efeb4130c8c01c1343c0" },
                { "fr", "0e6f5e01efc2835b6ec7fcb09818be01e7c8d044fa3236478cb491b66c3cc3909c9601ef1a3e50acad8b6c85835130996ae152360777451c6a89eb205aa7738b" },
                { "hu", "8addce95a0f0220f47cac727c87edc149df9dc2ad9e9ef0b19d3edf83ba45c1e319ee8fe79d85723723541bc3b10a221664bc67d70158dc931c683f943d01f19" },
                { "it", "e8f798a644346c5eee0632d4f2449d840b80b240641d509a9b37281e7ec8d01a090c0293d8346c04bbe570499193952707e46951fb6bdba493f51c483b16f49a" },
                { "ja", "9a422e51537868396ca4d40ff8748aadcf43d679f429c469b480ebe325832fdcf5454da85d5fa3fb4052f53bd7308c63ce5fe5fe8fda869c908391b9b0f7eee8" },
                { "ka", "1c2c19249e72caedebce0fd83411bb6056d1704efdb08b2fd2655af8c33818c54eae95cf613a8cfa5750846d1e9281d12039551761174f3c8252851b80b80e2f" },
                { "nb-NO", "3148c6401a52b7299b9888d57aa57c73abd9c7779c4c7bfdca38d9cbcdc3cf702a2e0321d71ff87d44a1cf8592a3e42111295b093c64a05063c373a146c79389" },
                { "nl", "8855b9f96fb59e3709514a674dc3a8e388fa660334f0e0a6fb03194135b3088517bb096e1b09ed03e56c793382797ea9c6ff6b6d65aef231b11c559728ecede9" },
                { "pl", "44a72884d4d8a34f0c94430e9d340b5a84eb6a0a02012f47b608209469a81acb47f3bd7592189bb48f96129e810e648590442d0261607aaf8a4594d864ad39c8" },
                { "pt-BR", "4930a988892b50281c868fe8c270cee588067e67cf14c578bc4ecf55e63c5b169bfed300f679503ac50b8c8f4e5739ac3cee86cde0fd08e46061c6446cc5928a" },
                { "pt-PT", "d28182b9059e5287b9ad7a7b6c7dd38f10b306f2c8cca9484ee1559e2402c3f793c005e18d80275668a1f171796f74b7ef656d7e270bb5d1cf7e5366fbdc4979" },
                { "ru", "efc9a1c8f2041398b5f520771a114d7d9fb3a3385bf9e3ad056ea8058725f64ad9c63cc5ccd374d3d2b00b5a9aba8cab09045b6a65ade3b113bc9413888f9812" },
                { "sk", "3b26c01dfd3720ccfa7957b1f067b3aa0aba9029d22ca104987198851004b2b3b888f411d46718cd614a4afb94f63ed30a32d35656f98961311ffbf098c1182f" },
                { "sv-SE", "6b6f1ba23c628239093d88e40c130f2cc7119ec636d77b7cce438abf168449672bff9f95d51effd49596196baa84be300d6c2193bfc03d2057a6448b3f8f5ee5" },
                { "tr", "a4992d9d7c3a1544ac82fb12b7e6e8bed010ba5744c875ba1f1ac7bd9fc99cdc694ad7bee4517fab1f54acd23e74edc2172225172450969153aefed3fde12c0d" },
                { "zh-CN", "d1bd2f83dc1b61d39a4128e89af0b7175775fd1eb4dd06c1886de32d9abee8029323e80d640203ea9bf29715bf2c3eb5aa4b10c9da3643191a02a8fa646c5257" },
                { "zh-TW", "5dc7f8855d3dc2e859110054fa34a69491d46b37a67e1d53ead7997a9c4dbbff2a73d0755303d493874b2cd570d51ff852ec6a28deb4b12fe773fd5d011b96ed" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums64Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "2.53.23";
            var installer = new InstallInfoExe(
                "https://archive.seamonkey-project.org/releases/" + knownVersion + "/win64/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win64.installer.exe",
                HashAlgorithm.SHA512,
                checksum64Bit,
                Signature.None,
                "-ms -ma");
            return new AvailableSoftware("SeaMonkey (" + languageCode + ")",
                knownVersion,
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                installer,
                installer);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["seamonkey", "seamonkey-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of SeaMonkey.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://www.seamonkey-project.org/releases/";
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

            // Page contains links like
            // "https://archive.seamonkey-project.org/releases/2.53.22/win64/en-GB/seamonkey-2.53.22.en-GB.win64.installer.exe",
            // so let's find that.
            var reVersion = new Regex("releases/[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?/win64/");
            Match match = reVersion.Match(htmlCode);
            if (!match.Success)
                return null;

            return match.Value[9..^7];
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum for 64-bit installer, if successful.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestChecksum(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://archive.seamonkey-project.org/releases/2.53.18.1/SHA512SUMS.txt
             * Common lines look like
             * "be06...690f0 sha512 40284320 win32/en-GB/seamonkey-2.53.18.1.en-GB.win32.installer.exe"
             * 
             * Version 2.53.1 uses a new format. Common lines look like
             * 7ccee70c54580c0c0949a9bc86737fbcb35c46ed sha1 38851663 win32/en-GB/seamonkey-2.53.6.en-GB.win32.installer.exe
             * for the 32-bit installer, or like
             * c6a9d874dcaa0dabdd01f242b610cb47565e91fc sha1 41802858 win64/en-GB/seamonkey-2.53.6.en-GB.win64.installer.exe
             * for the 64-bit installer.
             *
             * Version 2.53.22 dropped the 32-bit installers.
             */

            string url = "https://archive.seamonkey-project.org/releases/" + newerVersion + "/SHA512SUMS.txt";
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

            // look for line with the correct language code and version for 64-bit
            // File name looks like seamonkey-2.53.1.de.win64.installer.exe now.
            var reChecksum64Bit = new Regex("[0-9a-f]{128} sha512 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win64\\.installer\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha1SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is in the first 128 characters of the match.
            return matchChecksum64Bit.Value[..128];
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
            logger.Info("Searching for newer version of SeaMonkey (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string newerChecksum = determineNewestChecksum(newerVersion);
            if (string.IsNullOrWhiteSpace(newerChecksum))
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksum;
            // upgrade 32-bit installation to 64-bit installation
            currentInfo.install32Bit = currentInfo.install64Bit;
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
            return [];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
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
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the SeaMonkey version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
