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
            // https://archive.seamonkey-project.org/releases/2.53.24/SHA512SUMS.txt
            return new Dictionary<string, string>(24)
            {
                { "cs", "658875df03bd8ad361e01f4a0e8393f175bee521e2d8f97658a1db769956501d5ba2aaae19f06903701954b6e7b1e9ebaa458afb5e80b8b1325f1ebce68b44d7" },
                { "de", "a71cf3a53ab9a4328007ad6accc5cc4ddc8f8f945b2d67a8012923e0e1493f1c6b72cd44b41d9eef20f5da70115c9c3d306ef12589142757bc378384f5966d80" },
                { "el", "73f3a517268f08c4326675acda4a2455cbbd56e39d952a3f898b8db4ef9c19a47cb7cfb1650cae87497187bc59d1d5e67f8c9f887056294a147b03228b6e7ee9" },
                { "en-GB", "2577115738761ce6a3cc83e74b38fa3b428e3e551971e5f74558063f51ab681bd6fed35f0f2f7ce6dd66d37604245997b2841eda5147c2d23eedd4f776138c2a" },
                { "en-US", "b9fbd44b7c505f765453d431a4cb9575e6659ba2a87b548148501cb1334e0dff12973275ddc249e6e48d360e6e96499fe0b98c2830da0bc8d58eaace72a8d353" },
                { "es-AR", "48bbb12d5d4d68b614804de7f49ab9172f8374433601e491fd6dde5e3fbda13a848333735d2337e6309ca31a1330b6d3ef6440d4251243237009cf7afbf05f83" },
                { "es-ES", "aff275efad99d9f1007210dcf45ce0b8662100f0e228efae3b0cad72d3901b49f2328190024d7fe25a6414b0cdcb205c00633a93e51e0c843cd46c71a5a5256a" },
                { "fi", "965b867358610fb043ec111c748daf3c97ed61268663f5ad16b8f31638dccea1a439cb77f6572067b053ee585226be929e0c847a61d74008bc5d26adb52ff2d6" },
                { "fr", "1f06862c73d6f34031b8ab31eba4f19cfcc664c8f7e411e61964a3e208f3c52404315b3c352ba4e7c93bd412f2fc29a241daa775c5443c19eec32e33ccb42a72" },
                { "hu", "f52e2ff2b5c27aac305e6151b7b5beb8046c5191d4e4fc0f6bbf9f3ebb8a3a14b65b6a8e3db470f879bc4c60becbae0ed40bcfa330b4e82f44e524bb2cbf405b" },
                { "it", "3c1d1862dc4946b64d15bb4265fd133ca2abbaa65c2e4adce9546fac99bd0d89d16fdde575acc53f58679eac5c778a424d0c705a9272c2f2808662273d4173cc" },
                { "ja", "59b9a94f4b9c563867c04e7f9fccbec2d86aae84f546fed4e51066fea8fb9865f93982c699493057663e7253010ae8952ce4030892ffb421856fba9df70a5f3e" },
                { "ka", "5b41aed57aa0698dce8cba542dfe4bb4872ce79fc80b632bcaf2103050d25fb80e3636663f1aeb8615ef3b0957896b3a56d5a505d43c716edc29ad067c7d3b87" },
                { "nb-NO", "995bc75ab51074762e7f38200de90c1d6b119cc2e47d1a3ad839c9eceff69a02158f110bdd09aec07da99bef4c737e2dd0e91902c41022d65dd816aa52156907" },
                { "nl", "e57edd892c11745513f465577d9abc9cce03643d3838dcc485d614a9d2b142acfb26467edb26c20c5cbda5443327cf57102100760c857c550e081443307b4078" },
                { "pl", "9ba07b75ce50cbc0720509164c1fad9883e63222981534f80dc96761c018797e5792fe6c269a5c29738ab691c00c160d28f675e9dba9500759985e36436958ae" },
                { "pt-BR", "0433c9cccb3654f1eea6a81ea2c97b7d021a8b5b2152c167c5367abaec840c97a6eee82e9fada09b361ca3e3b1579bfa3729d1b362edf1d4b19d630a55aadcc6" },
                { "pt-PT", "0ddcbcdc5cbbc36f0437b2d2a572865c4365fa30463602a71415fa73a7da86d7e190adaef1cb7e15cb1352dbe8fda62d99bbba270993b7245e75ae6447e221bc" },
                { "ru", "5c3349eeb8785021ace6959ab15fbe14340d444b066e3fe661286d5cc01fb6eac0c5539861bafe36d25fb3e02e7d8eade107d1619dce15fc68a8d06600563a18" },
                { "sk", "b64e13407ccf095cd021e45e8d0baaf56061c45d4fb94daca97773bdff0252b93eea847d5ef0749867cb254e4204ee9962c94a26b50b933106a5f1e1aed508e7" },
                { "sv-SE", "83fddc4e96452bff4dff67a7dd9d5ad6ed0079c433a42db416f93310fdddf6d4a186543318a9ac1c65fdf501408c47d9b40ca3117e132d7a28073fa3919bd04e" },
                { "tr", "149c2ecb77a9d5026c41e794188155dd3c414d970d0bc3235a72cdb1976e5439d64d5ac2e5d2b193d8233c612cac7926d0946a5cafd62f486dc93cd179ba4d11" },
                { "zh-CN", "db0318ef0e1cb83836c4514a52904215dd0e959c032a7f73e2a1938f63ca96992476f5b721daf2a935b38417873d35739008e2253a9c5555346d57a28802eb1e" },
                { "zh-TW", "7d02f8e37ea645a62123f1933d2d506037bf483caa3edc0998b149b7b407ba89a2e801e9016e9c5a571a9275d91be907f1530d97224f491b1c324b0534e0a4bc" }
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
            const string knownVersion = "2.53.24";
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
