/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.18.2/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "4124c79ab9a31e9411560e5e5d2d2d85d0a71e22d8d6ade962ad1bd7adfde5e73985d997fb1c07cb5deeb8c4a01660e07cebb08237d16ff176de07aa0eb9e23e" },
                { "de", "d833433ae9d63089549b866601299c6cee7f68c4915dae95a17759fb31576b0e577181337e8412052e506c1a68682ea3d0f6e67a929761504a8fe9a2eaafe275" },
                { "el", "06c6e158b328cae0f502d6c0f33d80f2828fb4cfee8a649caf031e6806775c872a7c82e83f914c71b9adf755d8471996d95e004bfec536b9d4240166ddc09c3c" },
                { "en-GB", "6ad5e305039a518b7bd94bca8a0645e8644236dfbde04e9952d6ac6c7daa3ccd6a12478bb1840deead95138cb57616e9ee52ec33e91169effc759350e8f076b1" },
                { "en-US", "4ffbcf280887f972952a652c61a0e2b5df5f7dd8fa0e232ad47a4a250e9d190f33011d49b574336d45a068b51b043c03e7d304c9983bb287ffa4a6415fb93118" },
                { "es-AR", "9d7a47111663bc00b79f037a88700414b53f5aba0f166e32ada8bdee7f9eba236fb8713fdb33b05dfb26745217d6e5bae05997bb11e46ef52eb4d1959d1b4f58" },
                { "es-ES", "4e2a4bbaed77a85b29905d2d7b54f288a9cbf403cfe5429b566143f02c390ab124958100da978babebc3dc3cdc01f43a6afcd71b963c24fa2183fe2878f1a488" },
                { "fi", "08d73f711a47e062be776b5c5b6cede65fcf0e748c24422d3976b5f8d0c1f26611ae22643d53734a5489b72352f4e97f36ab13aabf5b81f813d30c089618cc7e" },
                { "fr", "141cb926b14cfc1dd33ecb145e39938b695da3fedf9d0fce1a6199c26a184278420416426629fd47257b97ffa324e79c35ed8c2fa508b156addd97cb6b6584b6" },
                { "hu", "b80c5014921028fa06dac3008a5ee4abd674d7e468e85083e4628b8da230f4fd5c45bfdcb391e45422b8b02ec89123ff173dff9cd5a5a77fadc1e8df556704ed" },
                { "it", "0044a7f2df756ad63335549ece8e64504e5dfc83cb3e6b15f9b2ed70bca1d49055ab9c4863d57c1c753a7023f43262a027ec027a48479bc5e8eba79cf4b33d72" },
                { "ja", "5bf6361f51702bfd1d6e94835504e1245c6ddd4b0f1e0fea837c222b8cd1a63256213158008ddecdbc1f8e586883230e0e4a40ec5a58f26126b828bc6de060fb" },
                { "ka", "ed610b1451a28907e132c2631457a6301a2b6ce5c6249e815619e3bb89ac5486a5e26f70bc4cae3c7f0b75c0bef83a24d7bcd986ab0f5c0e422b91252b9e08a4" },
                { "nb-NO", "409561089de8b2312bb20cf988dfaccbd206a5f2cbbbeddca9a423aa5cbb57131ffd6cc4d85ba497ff39fa04aac4660086a4566572da6523a2517c7acf1a62be" },
                { "nl", "880248bb46d9e09212d13f5ae9ffbc64d0956aa1116f1df3b32c1647bc8a5fc43e1fd6470d1488e8764912a083f0d1aa882a18ab162185fccd1890a6dd32e0b3" },
                { "pl", "039d2668380110e82060b3a1b9d0b0c0efc0b6167646253ff7aa1a52e6ecf871480b4979ad0ce01e145666dbb584348d7dbd1f04743b0ee3cb24919f58c91bd6" },
                { "pt-BR", "500a6ee6b09a6a6fbf03531a80fc9293847714b213ddcf9e78521db416b5cf908e42969b254afb6b3dd9983467fa83baf1944222df9603f1ca639ebabe9376ec" },
                { "pt-PT", "b9c20fd4cefd846765d61f9ccb5c4e22b704c74b1b330fef150b9abb18fc9f7b10938439b82b1536e17bda50b3d7c7697a1aa92e1f7f6bcfc0e8030e2dc77899" },
                { "ru", "77444bf9e30989a0b9b8bc042c2b9ac6bcfff13a0cecfc35fef89fca7c1d5368d2942951834ad881455ccf59209bb51197304a75e8bae6adb19ed2b964b4495c" },
                { "sk", "83be173e58c4037493fdb127a80a499a57c9272a92629889016c194a26bc702fca4ed7fac254f15b34d63c9eaae37500305d7a4b97561e784e09c7a4d38e5be9" },
                { "sv-SE", "c63eeffcc0386d3540f1e2c20c2d48ad66eec48d52df3b83622ff23ab94bcda301d2e33bc81f406f55ff239665d7066238995a0d00b6581f2f8ed3b7b95de11e" },
                { "zh-CN", "3655679682d71e354abe6e77390b1f6896f6dbe4e60bba2f52bfb552af89b016f9b58b9edf79969e0a8243fbe25fa97663c9f3bb06bf564cae34cdbd90617a48" },
                { "zh-TW", "08ac819f287c128b2fd93af4b8c5919e7715b108a3b8b33e8caa6243675791c0b65af6ca62f40489fb16729a63b588889d8dbad7851dee423b6345851d062276" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.18.2/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "c5899bbc8b71160a92c7f91840630930ec7f6999d8f4a568f1cef23807d3ab03ecb057353e109b5e6aa89b9b3970eab61a68729afe1ad799c2253a21f1c9572a" },
                { "de", "cc047cf5db9a450062a7f7441adb427457c5ec785110337f15e8caef0bef009e6a1a829eb0c62979de0c26d6893462c183e0b509026b8fbd2eb4648409680496" },
                { "el", "e5a090bfbf8d25cec85248ae1c524ba371aaab68a62f46131311f4089e92c8b48fe2720aa158b6c2b6b9a1d7741aa1a7c53c22696a8c72d920d692b382bbbca2" },
                { "en-GB", "16dceaf5ef8caa0cc04de861b779eebc6de15b4926431e32a93e01534ec91fce824e3fd3d6fb67a1f97079546e9dffc69f40ff20cf9bf314e26b1931846229cd" },
                { "en-US", "c59f5f645d582a160f2b0cd32aedcf96c2f86dc8667e0b496a36ad69d55bff0346b713ea85364fc5c359a8bcbe043e46ea2b55aa84834cac49839b06002a9d6c" },
                { "es-AR", "8e6d46e33ab1e074a00b5ff9be5a0b48bd4f87977b2191686425ea4fa4c05359e606a2c77d988d229752fe78ee0c60e4a33cbfcc570bbbe11963b3cda1a0003d" },
                { "es-ES", "1e50d30936fcfc7ee8c9c985e5d48e8ed94dca2ed4ffacb1807672331407d57064ba14ab4fc0036ca2f7c2f810dbcf149e2054d5b36485a3e3a6119b42fd6b27" },
                { "fi", "055785d36e766688647229866b5da26a043a6078838fbda3ed08bb4b331f780c97ed51d70926b7dec32bf092daed5925fad97c253036fd5027243e7d6656dabe" },
                { "fr", "f1da3f8627639efc9f22535fa95c5c04d656d2101283f9047854a707986411a1cd9340113c3e10151cea8210ade39a7e292f7588fca6c97b52ece7f691f4cb31" },
                { "hu", "f6ac4f7cbf8d85d466d2219654560451b2b752989c619b4e60a51a6b7b00edfc343e81633403b6160933709a0a0b5f2ca4d14e70b8041593fd50c32225b398e3" },
                { "it", "50edc517a5f6f02a7810324974c8b2918f75aa269d44756d6cf5915a6c63481073fd6fca52dd194290d3035113f1e72949569bd493f70c4c62d49b844a7d85ff" },
                { "ja", "18ca89ac9c0492236b189d9a589140a81cef35e972412d1c0c3718b87b92036806f856f5aea83fde1746f7f6e1c5226cbc68e398369b0ec93575ade9fd7bb3eb" },
                { "ka", "7f4aaf8b96fc2b172e4e57669eb0256e9027065d5a97bffef67db50d27517bfcce44411ff5cdff4ce7c429b4cfcb21d16e30f7ce45c0688177a5e784419ba76e" },
                { "nb-NO", "62ab8529a492311a147d9aac0a7a1e5d432b909b4acba902535f8657eb13ce9e19553a64361450208323a5b440e4bdf293fb5947344f2110bd48f86a80464afb" },
                { "nl", "98654a67f871ef5d643dffe874b6556167f983247a3dcee4d80c428bd07a649c697331d0b7b26a602a5bcadbe24bce150b182a2bb952cd13b589a08e9ef1fe01" },
                { "pl", "777e01089732bbcec5159c5b0523a48e03f2ed6bad48d96d9efa67e24d7f421a661630da9551ff30e7bca6342ba1212487103e64f6c2294035d47ea0510e932b" },
                { "pt-BR", "30ce85d5a8637e59339a43c24383268d38a8de1105d6d0c84f70e135fd76dddb6f92d1bddfbf4f04cbef507986c4fe034211bfa4d50f2233ef6aeb602bc59cdb" },
                { "pt-PT", "7dfec6adcfe86299eb28f93ee68639837c4c3d37c110caa697f4bdc974c99a507b9f55dffd315d38724916b1ea79f128626848dcf047a1abcf84eb9e567209a6" },
                { "ru", "7075ad7ecb0da051db7d48c28089767d1bcce17142955d510c164385f3cca543330066c9f68029ce9ac9766fefc7e6a79f07d9b81dd0ee178be1f5f99f3c5ffe" },
                { "sk", "2053678b7c45fb8dfdfdce53de9589aef94362e80243a7aa0949b535790937c39eed48447c6669791b5c0015e7c996f7d110049c623d972d8913e1f45b1874ca" },
                { "sv-SE", "231a8417042396d8753e204bcff3bf476a1200d500d4b166c10fb00dda6d394b40d655957be9f3ebd71a0ed5631681183db1a1e2ea4005b89540dc57911a1007" },
                { "zh-CN", "08e6dce31e76587777cc6cd311b495bd3a652a41143b3975073b74be9fa3ab02c670ff7217284c37df1c89f8b3cb2ce88d3b3bf322522b399af1217d3ad17892" },
                { "zh-TW", "be35746c060166e58d40839fd1f45b2bcfe48cfe5779a0a4890eac5d19a58c784ac251d387ae5c46e1ec6abc7dfd2b1c693105a7dc7aea041ee05e22c353f2a7" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            // Just go for the 32-bit installers here. We could also use the
            // 64-bit installers, but they have the same languages anyway.
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
            const string knownVersion = "2.53.18.2";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("SeaMonkey (" + languageCode + ")",
                knownVersion,
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                new InstallInfoExe(
                    "https://archive.seamonkey-project.org/releases/" + knownVersion + "/win32/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win32.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                new InstallInfoExe(
                    "https://archive.seamonkey-project.org/releases/" + knownVersion + "/win64/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win64.installer.exe",
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
            string url = "https://archive.seamonkey-project.org/releases/";
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

            var reVersion = new Regex(">[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?<");
            MatchCollection matches = reVersion.Matches(htmlCode);
            if (matches.Count <= 0)
                return null;

            var releaseList = new List<Quartet>();
            foreach (Match item in matches)
            {
                var quart = new Quartet(item.Value[1..^1]);
                releaseList.Add(quart);
            }
            releaseList.Sort();
            var newest = releaseList[releaseList.Count - 1];

            if (htmlCode.Contains(">" + newest.full() + "<"))
                return newest.full();
            var trip = new Triple(newest.full());
            if (htmlCode.Contains(">" + trip.full() + "<"))
                return trip.full();
            else
                return newest.major.ToString() + "." + newest.minor.ToString();
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
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

            // look for line with the correct language code and version
            // File name looks like seamonkey-2.53.1.de.win32.installer.exe now.
            var reChecksum32Bit = new Regex("[0-9a-f]{128} sha512 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win32\\.installer\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha1SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;

    } // class
} // namespace
