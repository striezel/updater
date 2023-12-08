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
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.18/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "dd2bd35bae1c4e6fcf1c6ebbfbf8765520ffde0870f3b09c4966eff55d1ef438c84a16fc2b36c225102111077a741619124a4c825a7c087cacd2f5f880d29008" },
                { "de", "d21edd446467ae117ccb540809680eb3976c6fd62a88a1f1bf512105860c0c3732a85e1866e4c3bcf9d808b9a7c7d9ed275a57396b97e525ef53c4d2dfb24e8d" },
                { "el", "7f485fe7ecba9a07b6167eb6ffafbbc11de82c2af74ccb06a55238276c9dcba96afe2b7d441aa07994a704cc154d8312595793cb9ede9f53304594bc5a653c90" },
                { "en-GB", "f6e4b1012726784e22da877f8e3db79d39dedaf661d12a7ab90d3a5a71d64831e1d5c4962b79cd6e31667a60ed847e264bd86252c66ab08a527b927c2ff79800" },
                { "en-US", "92adf4bdee87d47c8b740641efaba905e5077b95a0e036275985883d6ddf43b895cfa52dd5609779fe183cd192c59ff57c69db849a0fe0b5edcb927653b40c82" },
                { "es-AR", "fbd8070be0efc00d0ac4a72e91d11175a5d9824a8ed89df3988865101acb4263d24ee168a899cae6d008f00a7ac56544097e0433e71cc0c7fa6160f35302a813" },
                { "es-ES", "efce0dd56c8ddd7406e799d0e09c40c3bddbf7434dd1b8050beb26e324602e5df18e095fb6a6cb6237591f09a98382ebedd1e4bc185bd375bbc6ba7abe086e6a" },
                { "fi", "ada5e59bb804ba2bd671b74d1a3c19ad5394069a8a317f975a7db730b0b38570c4ca2054581314fd0d921d725327a46ffd306b013c57ef32f7908de38bdfcd9c" },
                { "fr", "b1ce829d22496c576d96bc725ee8049512f116da4cd3da2c3b300398392c5881cfd12d3646cf282ad91490cbbeae19b5984303af3f073fa712092e163e309dca" },
                { "hu", "e7346cbf802f74cb898b517f0d958fb21b28af996a308ec16e1cf7edbd2092d973bc96ffe58d794c82b347720ff72e0626d62413434dccaf7551ef48af2334c4" },
                { "it", "3d41ddedad5f38cec8092b1b005ee5a354921acff32fd9fe6ac038cbebb5d4d4893674157576345cbe078c362e1f72f4615c74207c46e350a2b4e6584a122872" },
                { "ja", "485bd4c4714055fbe4e943e5e788e5b37895340fa00c7f0f4451b0635c53518e87fdf821c214edbef47c321eed63eeff16ec8af725d8618cd446e81fe8fc4fdc" },
                { "ka", "6fe8b93c0f2a75ad121eb1c4d896154a3b0724a1b0c9fd283007e6838ba95ca3b024a3c6bafd51c394aaaf58b0395918e1028c271e0a432b9ed6fe2c9d38ec8f" },
                { "nb-NO", "07af6e8958f93be7655394c34f8288b18b050484d5a4fc6bfb254fa1599594a7d43d0acb60958672a15a047e4f7b6beb3084a0d444ee10034edb52b63d4806fc" },
                { "nl", "c109dd2521c040235aa6e12d274ad3f8de88ccdbde5c73f03050890e9519de26fd5f2ea7e869363ed5d1c461085b01908ec439f6bf1ee0c66c7a353b3c23c647" },
                { "pl", "f0494531e6e33e5d642b81884af00a1b9b530fd4074f8d21b273bdbd8a79768725949b59de08abc186e0a8b3f127a09b1bfe117f4157ac55376a57a9a820154f" },
                { "pt-BR", "bf944bf5a051c145b9f653b54387e7b80de0eb64ef191d8ca6efb30f5fafe31402afc4ead5dfc44b809743769ea74a0f30c02a208ec5d71183bfe05e6a692c9e" },
                { "pt-PT", "5b98f8c52d2d09747e06bc2067c79e2cc66170165f0fe140984e7ffcaecf7025f14d9e45846b1735a734f03204f195575445526c81a09c98a30dee98ae0b44c1" },
                { "ru", "28747b07ac1426e921edc026a7b4ee27044e98adb82ed7577c92bd54ee96b1b4025af70f3e1df7edbce8f29b9547d93cf2c7fb26f5dbec8ed2a7b64a8a4694e3" },
                { "sk", "4177092939b503097d3d1cb8d3c97af8a23e8d20a13a2c451da5a951c23b62fdab9a908f49e12bede6a9bce67d4e4545b4109e5c268f795b13be098f14ddd09a" },
                { "sv-SE", "b9bdceb6fd6189f04c9752ed112df45730fed59d78816ff663e9518a5f64376f2ce66a3c5d0759f0f75e0fb514ab43126610fb2aa04a09d5df715bb60221fa4d" },
                { "zh-CN", "316f40f5e4dc379f50f644f7fd9c7bb458facdfc863daa0c59792589a2a2817913c21170f3f81110cf4f3f7ddca866bcfb401d07f00882222ffd9725cb87bf73" },
                { "zh-TW", "5d4537ac5b183a06b6a8ea7e8c4c57ad50018611cd13841070e67f62ad7a4bbdc276003291892f04fbc8b1e1a9e257967f9fb05205016bd83a1ae84a0d4d3060" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.18/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "56a0e187b8e6f82849e46e06d8c8290c0d4b1930507b1389589d813147b8d8c27a330874ab394ecbf7d45d104c7fc61e2b0845a0f2d9b26df72d38b9a9a04c76" },
                { "de", "1038d892bb3683d7cfac19816dd1f165e73d4a8aa14eea0096e493f36aa9721cd82d9504dd3f7d8d872ded773f3a1a8f3c1f63c17c5e89fb03c44b70b07104dd" },
                { "el", "c7f8914c454938d3843a55cebb120e3ec33d5075b5164430699fcb87b7af453fb2bff008527fe2917498cfffc6ecd371bbd89f593e601ac831b4d8fd63bd8dc8" },
                { "en-GB", "4a5833f3c453862a6c63589771c3aaf310230945695247d3e2e780874943846222c5a761839e542d141f667a7b68c6efde248c758ad25399edb763222bbe3283" },
                { "en-US", "50146aea9c91666479bffcb69101e8c79a463ed90e27ebf5d7654e6fb117ffc2472f1cdb3a892ce3cd12686b9ef6dcc6643f77ac3f4432c6c063498f20539de1" },
                { "es-AR", "50ecaeb8c5d4afd5929ec80e8bd7110dc5db8790c50aa8465d51ea318fc3a22bc85f5b7fe26c7dbbc8fde4aefd6dce5039b1bfa3ddf3976674e0ce53479f67b0" },
                { "es-ES", "9f1a372d76d5cc97d30be184e09d0caf411100ab95ae498355ece2268a86f3724c18a61943d899c03c9b9aa3e7b3d83bf971ad0a86c0da7b46e04da124d8ce9c" },
                { "fi", "6581ad848a00a7ed4b797fe0f65aff441728e27807ada8b19c476eb1971bfd9b681ccb36469103a5232437dd364f5fb8ee0027beffb404eb217f4868984ac521" },
                { "fr", "b2a37723e49ac2993b63e9353f685779f20ee993ae267a98dbe903cda16bc52787c0268622927f1d0712f338d145ce024f1ed4aba673c6c6cb8338406b0a79b4" },
                { "hu", "9e5a247e28bb41ab1a29b203a9ab201cffd36a084c01fa8b15b69ccc02390c3bd1f4d8308cf21c7d7576a9853404abfc6f62e65204db6b5b938076768a84b5bf" },
                { "it", "45b4fe56bd569643b904e0e2c3d50b1315d13497525ee53fcb5c9326de7ee1558b646a865d3fcdc3da1a530779c61ea8bde9f5ac7d4599ddedb02aed9176a0ba" },
                { "ja", "f493c564359b037d055c866d67bd16a6bad4043532e9d60b3ebf02447cd0581a77aa75497f8056d5afdd6fd7593c43074b395d581f65536b4b81e2de66801908" },
                { "ka", "43f8e54c7b3bc7b23210be691ca4a761b9015ed2b933e92214fb03f04f375403b0701fc578da551b0c1d2eb84d3cf83f4eaf84005a71abbb4e0e6051f8bbe73a" },
                { "nb-NO", "664363e1a38b0ae140411e27a73e1b206ffb469fb2c7869a615aac274cde49475f11243238c72fc9b5242c1156cfcfa8e0def5c5096c6fd5b62499ba9ba55546" },
                { "nl", "92675208bce1ee80c4697caf83f10221c4f2f6d0b7d059d502f91a45acbb9567700c1cc83f9890dbb7c460bdc0e23671bf676bf804eb4da7083d8d5a7f220ab0" },
                { "pl", "7bf6caf6d9798577250bbf3bab1333ad1e4b8aa381cad642ab72b987f85e712132960c4d7240029bb3b9f6a3462f17417484689ace4322069038adcc78a5e1ca" },
                { "pt-BR", "e651c81baf413dee76f2be379cee319c6e739cd4f55f9b1228dd0947a948e5a039765233afd8587d4c6ca022bad75fc7aa259e8721ddf115bd812ba4d3658090" },
                { "pt-PT", "ffe2343aff65629905dd457e22289b71f5dd188e0ace8a1b8625d47a1c36e3b590d12fe522bac517de58b6894e6e972deadd9c5f1fa103cdab79fd00633d234a" },
                { "ru", "dee8fbcea1099d2ac3139de8a0b23dfaf33f74531b8722f605a32aa1915833e81b742779c1def5f7d8adc4d155664d7f4711623b2d5bd5c116ed78b59d15ccbf" },
                { "sk", "01a3b2cd40ef87771f5c19ca4419d454399df091e6c9b98fad4bb52f7f1b59a52a74c7107dd65489f12362a668fd9192da077267d8943f89cfe2581cb10d6f57" },
                { "sv-SE", "5a701a5a2910967246bc3b9def04b882a474620ccbc6c6d873407e77468eee504b074b6a0b452eec8e51efad18fba8622e379d9dd9e42d4052708ecc5e3fe6ec" },
                { "zh-CN", "3acd0b8940d00dfd183791f07ebe501a49f7eb194d589de67df3338ae2242f706919d1bf09206f88a46f012df50f376e585bcb4276221942b7b260164d97a460" },
                { "zh-TW", "0ff78fc26f9bcdb3bd204edfa59c97075db9f399178842d6b26f7aea27512219c328ae6155db21914f19c35b3024a925e854f500e9b5d5c000d03853f0e43957" }
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
            const string knownVersion = "2.53.18";
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
