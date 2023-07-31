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
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.17/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "f1b36382587eeb61f5f4f7d190addf04fbd8f038a6d91bf8423a374676fb537eb8f41bd916fcadbfe88f9b68d2829f8e370434af86fb487e0f10279e54c1694b" },
                { "de", "9e9df682a9f24a0fcd38bec16a6cb40f8d61be7d13ff7c85a1c5e1eea668b8d71d43ac31e9b94ac5eb460a04cc157b89c0f2857f9eb7ea879e13cae4eadd4dd2" },
                { "el", "31a40a3994f76b67395499d908a45b5407f0ce1d7334cd61cc6d644239c26a652e78eb144bdbb77b38d226619a458f04f4f72b8087d62855efe770458ac6653b" },
                { "en-GB", "16695546e9a77cfebdb6e1dafe64f40a5f775116209f3c85e380439c32d3c320dd77129706def5c9592a2684009f1c060e370cac7098103c999b0969bc350748" },
                { "en-US", "c0b30d27aa6955be41db3b178ac659018d12ba2a730c350174b6a76c287cc7e23c9a683808e869d0418ec5b519a6835c98e8ab89e9a95f10813c84800b5e0dda" },
                { "es-AR", "c3bfa43c2ad929ebac5dd731e71cdf1acba76331e4739db088f54c7c33a0cf4ed73cc8e428610c8e0df0a16efc4040bbb580c9b8bd74a872e13001ee38359518" },
                { "es-ES", "2e929f371fc84a00344fbaefbd91cc579e8d49747b06d7c931bfa0ab4b68739e11250b8acf51e282eb505541b60aa88c920aca60db05aa1677087f4aed28bef9" },
                { "fi", "24c08ec9776bda78b2d846d618e7ca9ff0ea73056621d961870263eb3ef903251d0070fb7cc1704ab4aeb9ff14f31dcc8e0c4f5eb19208cb00bbc01dd18f3734" },
                { "fr", "7e2d4b319dfc11a89c82ac4d9104af88ea1d3d271e33b0547b575cba1510a18808639f17b1c8da58bc3976b03172db81c8c59369da783c63fcc50a1d3d64849b" },
                { "hu", "02c0b528eb0ee584d6bf4b6a5d3ee9bf4a958432be7007c5eb61c259c7fa7b6f1dff534ae954fc2381a8bad3aa9d5106c53410bdd9c0d78166d72178525da73b" },
                { "it", "ceef256497d6c2fab1279c3f87cf28d8704b5399bad65f4d5dcfa476d1ee1988defdec841f6023f64f3583fa6922e7097bf2251f27d3c80cf21013d015d8629e" },
                { "ja", "8d21aa6a28dee3182519d88da4b5709cdb9dcefff6a55ff0fe9919c15faa48da6a7faf2a86759259db723503c70b93eb7984e8cd49bb9c2b17e283446b7f8b52" },
                { "ka", "5cea9cf0dd7be1f595c62fd4d19be780b7512ff048d43332ef2d3a995a7de15236d3a417e2869633e62290e324913c64781c3fff415442a0af68443046364239" },
                { "nb-NO", "ecca4639a035d12ebb4305e7abba9e30a28b6ec603725ec550d6328b8a2d802d62bb84b6c34d5fa2284220908280fb1d90a44620ddc8dc2a90e4eedd7511d189" },
                { "nl", "7c0dedbeecbd074daa1fce711e2403a313ff401f81841f1dea622cfc2ca88f2d87c24405264c3810926f365525e1bfd1552c1afc5bd696025ead61846af900c5" },
                { "pl", "8bb54ad5ae28fc4371c9dfc4a6fcff109ef5c3e05dce589901d422f747118b10c757bc671876703400ed2df0b035a3f89879644f1c30a739cee3d5676449a6d7" },
                { "pt-BR", "a99a9c642256f1a512a9b390af3311c3b4fb85851a31e51c519b722a03006dda019d51e9601d20ceb77d1571dbec00d8633d36e234a1a6b49a019fd1e85bafa5" },
                { "pt-PT", "980d4b11fe8e84c6ac21fc1b94b65bbee4ee9c8bc7c24f5c7a5633d6176f2e51cfc45deed2f837c43d537db4e78e9ebd79c039886cb6908208769b5b01659c02" },
                { "ru", "d705d5382c3e9c540ebb3466968ade6ea856f2803047b7e3a69ebf5ebd7d48cceacefc76c17f64008bb1bf7d20eaa3ee167280fc982151f736f2581845e5ef51" },
                { "sk", "4c39dcdf94ddf523a84d69d69114db708696a7d0b174736e1ccecc41d535bf5af266eee7a17308e15a209070779ba1e5076286715993d1381abed02736f43da8" },
                { "sv-SE", "bedd6d1f3b38aa147bc4ae26febb061acbbc5be342c3b248bf1a802fc8e0a397bbd0e2cf0066456f44eb1d8d1630893df5ba7d25ea26a97e9f9cbb659e0d0e12" },
                { "zh-CN", "a692efe6d1d21c6dc78ff37a87e4758659f546e9aaf0c43e844b63427890e594ce3451f482016932db66908693b127f715d69c53c5224a62ce8a450ec90ee952" },
                { "zh-TW", "d3ffd9f303433ef528703b256cf5b89435c7dd6d4d764a967f7c2a873f51db47d12c8579d46718723be272aef068de4c20a76ffc34a571d5d2b799c3b4cb797f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.17/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "9b17f9f75b9ae8995b29580a6e7b2a7db40e90f40dfdcfe69d5027d46c78a2ef9fbfd841a5240d87f51f067e9ee756d89f25cb4bd41da81349bfc8189a10920f" },
                { "de", "a24f410413ed0c1a05241618551da1cffb4b4efaab1140bd7ce0b3031b579e6b6c94cad92069727d7b4cc60506d2c4d99cc83fc1d872f4ec6a627147b4abaf93" },
                { "el", "ee25dcb1f86a4b2540aae7c482dbfe25f6d7841eb7cc500194a41e7f554d5f95be1ef77afca82c5df3015fe39380d9e8b6cb8ce2b1246ae510859324d59aa204" },
                { "en-GB", "6bcf4bf0c5ddef06e8345c012707eff1ebf81798c47dd737332bdedc2d5e69a39dd200ddfa63149d5e540de06eb3accf6f65063a57110dc6da9a731443f0108a" },
                { "en-US", "80bdcc41ee9bc2c554c252db0d5c96db2b6752ec11f86686e9437499c8cb8d570c586d755ba7eaa18c4388578d01084dbd6f2b586d9702d234e126b28afd8f6c" },
                { "es-AR", "43c43ac255c03f40104a4f5213319d4d6fe7528fd74d6bded5e9c8a31c9ea947f65909720f31cffc7b6b1dd8b0d86d9e4e592583cb9fc3f88c51530879033875" },
                { "es-ES", "f4f293e6d94cc4cab70572e5d53fa5a736828349432060663a381c6c3fea37d1a41e8a5c2b95218e797ec8b8c7f8b33a89b90d2781b2e06f709f92967a7ecdab" },
                { "fi", "bc1f26faa03f76dd239295a4cb6b800f8154d3fca06e81dd6f063e2d7807553c49367ef207ef414c9d843531958ba53e5c3e6d4f3ec470795c274ca016da5146" },
                { "fr", "52e7a6b67eaddeff7102f48f4031f97da6913a25c1f8be36e2d009ac98feb47b30d4b230907287334ab5c53ffcd000d38127b0d293ee720f99d38fce668a291c" },
                { "hu", "e8141499cb0d5fe5468f4a7fe6b690ba7cd57ca57440b481f261358e3550f08990a674142c427af7afc7ee4b1145d8e9bc62756bd3f66cc6d4b893351697cb1d" },
                { "it", "f404df782f6b879bd5f42d3d6779b603b955f5308043ed77e593e0e324471b288024d7ed54147af71c0ef81b49ef0674aea3460965e51c2577d5ad1699d472e1" },
                { "ja", "eac36ea8b83d7f9cbc52ca6af0368e83bb3b587f42cf83efef8449a52e31e8ca066c444895ed01e6b79a53396ea8dd1fe524e0560747d9a351ea2fb5141d8471" },
                { "ka", "b2ff00777c82d397c894c21d186c2e267e11ab6903ba1f7bd2538c65bc35c1d142123032e1e49226b7ee40cb44f54aacb694aad6366ac8a67fbddcaaf4ccb2e8" },
                { "nb-NO", "67b5b5c720a2f7399daf54f7f30ab59bbe1fce9cfff61520a408936e06a70c41dd54e8b38b3b4a37bca20fefdbd5b603c87677fb4a90d8876965e74c52a599d9" },
                { "nl", "b56832450da4613ac43c72e0470f3dba4c4a42c83afe27331bbe91a81453bb82fa9546a4e70be33e47512fff0aca1f4914663222092189d396fddd9dd686b3be" },
                { "pl", "f27b52154efbbe29216849762cfb4f4cf077e1e44df99a637ca128de62914f3f3b650c315028abf32715b1e95cc4040e0e326b6efce8ea42709c974ffce0e8ef" },
                { "pt-BR", "fd1921eea1d6dc3496073d4ea41e89e2c84fcfe742b402063cd0149aeae6f4664b75d36ae11e9569f8543921c107f38e1d4efcef8d90c266fdb75e67adb32c6c" },
                { "pt-PT", "ede9596f5f670933cd99fe37e067309c43b26c0135ecc89828375a7c8e85d8cceab0d6c43192cd66883775151e551d61549922ec24e21d84cca566dd0c296b8e" },
                { "ru", "7223a6534e45dd81afcd9d43b4f06c00106fcd802eac7f13cc11c84436c03b64020de1f5c93207ff7bb0c2e281a592be9dc955a392f56161681306e83733488e" },
                { "sk", "8a38e299eb03aba0a0ddfb4913c1b51d587cc2431344f6a809f8224963eb8acf4ec7e22fee764a521aed49835954592494fe4bd3732dfc2dbffb75fa05347a22" },
                { "sv-SE", "96259e49e70ec9ccc5f2e0bd81ad6e5044343933dd2cbaf67b77cdad3c623d725f505952883bde4cdadf0cf7c8fc64aed10a0851b897e229f3b2d90395f0fca4" },
                { "zh-CN", "64ba36ceabe8acb9ade37d2fef035fb59a8ef230d1dab2a60842772fa35dc1c29cf230666bfa3c456226c61ff122c3b1669826504f1bbbd2806ebc5a5d4e6574" },
                { "zh-TW", "3995b5182feff170b5764808eaebe1da8aa9cee78f7c885d030ac87b4c063f94cfa622b6a9bf9488ccf0d633ec31036fbb8573fb23c21bd7b84af52db9895e33" }
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
            const string knownVersion = "2.53.17";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("SeaMonkey (" + languageCode + ")",
                knownVersion,
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/" + knownVersion + "/win32/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win32.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/" + knownVersion + "/win64/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win64.installer.exe",
                    HashAlgorithm.SHA512,
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

            string url = "https://archive.mozilla.org/pub/seamonkey/releases/" + newerVersion + "/SHA512SUMS.txt";
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
            var reChecksum32Bit = new Regex("[0-9a-f]{128} sha512 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win32\\.installer\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha1SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128} sha512 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win64\\.installer\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha1SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is in the first 128 characters of each match.
            return new string[] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
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
