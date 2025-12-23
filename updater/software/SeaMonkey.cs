/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
            // https://archive.seamonkey-project.org/releases/2.53.22/SHA512SUMS.txt
            return new Dictionary<string, string>(24)
            {
                { "cs", "51e8b6b4e3112e0333763c84a31508462d52e9af7b04a8574cc773973e7f43aeeddf5d79a64558725244c8c8fb6b55947e9aa1472dc9edf4da6a3b5943cffeb6" },
                { "de", "1f996482b6b677a4cf77f4b9865642b236784bedcdda041e1688f19fc4ea4b5668a697b737d0551479e92f1e0ae2441ed2d6d9c3d74285fa8b9559262155d9d3" },
                { "el", "662f0f9f10242fead6bc24dccd6b9e0961b9d89687ea963198ac18affffa089344157cc70f084b72123d4ff6a0c12872bd65e5640298efb0a0414fb05a792a16" },
                { "en-GB", "049901d701d15accb0abcd9118851bfbd7df95db854eba25ed7f6b75c5557892106fe5ada59c7d038ee779eb44ddfc6568d3d4894e32f4191f6285338ea9a193" },
                { "en-US", "33020ade01ef65dd45e8f019c60471c8ff33ccc4854d28e36553a694ea14f7512dc950bf23f6ab331fd9f13cc2a7a1a4029b7aa7c63ad7987793153dd2a8d097" },
                { "es-AR", "6d7669b6c45c0a67828a3d3083dd1abb03493059ae1b1bf9951ec2e512f4c59f0c8116b2d5dfefc66ce530fb85b5fceb05aa058fc59136d5de0c6815ce639d91" },
                { "es-ES", "cb3acf6473d18615ebebb58989eec6779f50b37a3978c61854d9560c4c138af66b31bcebcd7f414dfa1849ef606e2794013abf3d0063dc784275380ceb54b544" },
                { "fi", "1ffa77d08dbad86d8fd5c816c70b0e28072d0e5bce828a4cc363a7a3418a02d29d6b191ecd95acf4ecc112480ea72d6bb154c8c1d99cda5da8ab6a80f2814fd8" },
                { "fr", "e54b9edcc6c5d29ddbf2346ef23625bc0b7ef05b14adbb64b39242e507186c99fcf667e2074035e879fe8fed909059ed1a8d3f3bc0c4cccfca8d22cbbaeb398a" },
                { "hu", "941d8b1cd2a6bc27b814270cc9f8269986e013206b4e223e30409f551c86d409ed94fd1cfb61a27353ed49dbe2426f662e96eaac226b045046d35b5e8bec558b" },
                { "it", "5dd75747ae51e9b47d092455cb5227f8b56c70dfc3a6d7b531990a04f148537f7b6357edf2852649b3aab1325a12559eb3623b5fde20f1f1048232366510c69a" },
                { "ja", "38abc992ecf10557c77153c535e386f864ccfbdfc9128ec7da1b8931b3bb7eb641136c5c3dce45cb707e934fe5ec67375a3277d97a81e2fa9145bb8168a457ec" },
                { "ka", "b1846e2c1358f19ed590cb903b1b6781b39dab681b63df4d48c2f0dd776876b4fc3faddad9f2c4be247512788ff9563659d67d1a85db61ed0230a7e51eed26ea" },
                { "nb-NO", "af8ddd06eb4c708407fff56153978bcfbf6beafd2a66458c24d334e8579fcf65c92b694d6e8ab6c2aec61f6bc88193af70be17a99e3a9f1fd19e1e2f7a7b5ad0" },
                { "nl", "fd9b757c292dbdffe082d4b7ed6fa2b08ffd8a4823038abab38e475f219f18cc5966c728fbfc72a6b25adaba68605f591923330eddd30fe1f063984f58e2567d" },
                { "pl", "5b5320989d1d9fe13dc37eddc7373e035a887411bae0c40d74e9a3dde8ea6b6bb7a7b5e3d7c856b1da11af2574ebeca68dc25085168906a9918f38466d5d544e" },
                { "pt-BR", "aa48665d16bb9f5a78391013ec225ef6666b332367f7f66bbbc08e66a521e566514ecc4f31b558be279bde24f844fca3936916ffe691e057057bab552c6d40a9" },
                { "pt-PT", "198dd3e348dfacc66cf0bc129bcb17d64cff4bade0b2000777243bbec9c33ebf6a168f63c47d1bde312d824d5223343b4b7b39c559f87db6d02b346828f1473b" },
                { "ru", "5cb5af813a30eca9c782269d7e5d8190e12c674e20ac5f2b83791102d83f74f4fd827f116b6729fb05ff6f1d494317e14f1f3f89089521de017b53d503bb5baa" },
                { "sk", "b74c01e9990e0acfcc25f984aa6537765735f562e1bda035386ed5ba3f5ade878d729664502e35140a2b1b8cd875049533bb4a501557ecc2ea1ae9de01ab14f2" },
                { "sv-SE", "befb3972e4da5c01e503cfb539057e6e1da2af857c28a466352e07d712857b86ec80ed9a091c2ad42c2ad2f45e23d410b857e67fe25659138c7c60b5a20cd817" },
                { "tr", "27e9c3dd7bec8a29b411e25089791d41ab5aba77c19f3fc0beaea8b3f6f1ce51a38b5c185242b4a26e8dc2f9a6f17330226ed2185b18d203a6f3febc07c24723" },
                { "zh-CN", "7771c2d9e3cee721ada270c00b39662bf72de57351c532dbbb7a135d3edfb289c505cbf2ec8e86cdf382e562d89a4b6ad0922dba8d044b4421d22a1a5a1c358d" },
                { "zh-TW", "44bb3fe4fd98d42256e6b2a743f79a4f12cf71513e3a073c72f92090dfc07c43a2266a5ae34b6331f44757267f695ba5f7f127bbbc98f570859d93d1d754ac7b" }
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
            const string knownVersion = "2.53.22";
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
