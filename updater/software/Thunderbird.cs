/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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

namespace updater.software
{
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d = knownChecksums();
            if (!d.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum = d[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/52.7.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "a4d011d29570b5451f24b56a8493840bac47758eb8c66c379325e8e6e0cae10dd95d6d53c3e58e16a817af7a09f886581fbd50722645bf5ccc01de07471664fa");
            result.Add("ast", "12463cf98907c4f82d5312c831b4c0b2c66da24e90b4bcbff579ad32a0b62e8628f56b18ac665caf9a3d55788330920391546939ad9ce9da28653999de4c949f");
            result.Add("be", "86bb137911f37829f28f97cfceff99f97c44c2b0766040dd1b86e8166a2e2101af9af676ec42d4348d0a1a9ae542711ca896506788bd5427c4a0060c027d2349");
            result.Add("bg", "7c225a0f066fda8041f925aa7bcc2b5745d5cca7f6dd2cc8335495bd858d4faa3366ee3931831659fcd72d70c45a728e385d01a601816f63261ec640db9aa8bd");
            result.Add("bn-BD", "830b64bbd2775b3aecb0ff01f1bc8c806925a2143c9a90ba7d61f9d0bccd40ded3fa225cc3357504f5a5bfd7486a80646562ffe565b776f1649fc922fd8d2246");
            result.Add("br", "8f80c87defb09052488ad4cc28b2a6294e8784f531c246d9ea8ece0ddc4186b67cee7cf956186ff53ffabef84c8a92fd750f800e08b04a61cf222e7e960863ab");
            result.Add("ca", "f8d9b0d947a053c73f318df63e69f0d3d265a0780f15d7cdab6f262e54d68c3ee5cf6eca4604e0240ec69171db3a111c4cdde98b67de98920b07fdba2a18ecdf");
            result.Add("cs", "df1136e3190de283b1e3a76e26504e35ac5edd507697b85c7946d15cb4e00d69bf3bbba9750ebf5a75a741e6d813931dfa86373209a1330143d74437a961f6db");
            result.Add("cy", "32d58bd9446d364de79f8ff9245b79511474a4a3ad1502f62ce4338ea30d4ef30f3eca474500225e28c138f0e4b98439d4c1c783fbf95256b586b9e5dbb72385");
            result.Add("da", "9dc2a6ad821feca55704f0094819a9e6cbae1b6a8898e9bc89540a567aef894786a90e75dab6eda7f6e4fe0310ae82bf2dbc867ea6d3f420c9656df6ba5b5be6");
            result.Add("de", "c0c683ba8318fd490aa8d19ed94929544207f090c5f8e266460d58e234f65f9783ac60a2aad933424855ec717f5ecc69739fdb44b425d14392fd8889a8ef6ae9");
            result.Add("dsb", "42922aef67e122339202d28775d7f3cdbd8ee52cbc8807dbad60c687bedd985fbc82ca5be55763221bb50201b905dc29702e328756cdefdd90d4bc2e00523eef");
            result.Add("el", "b6bc43f032ba06991448a961940a1da33572f139f61d9e33997145368569162503e98642d0a7d2d234a2a032ec82c874e7408f08faafcba19867d6df12411006");
            result.Add("en-GB", "a05e6ac047fcd64368489827235b2568d402306629b25e61f717757eeb4497c99b8a1dd04da0cd3b4c2dbf4c43f904b268118aa560b44e49fbc46686aeaf8402");
            result.Add("en-US", "edb72a3f2464473525a6b631e08ac8906f00cc1e81bfc6e26e263e85735cda525216d7b58acb925a45c4fb73d7947bdc49777d1b8d5781b333c39ef23a8bdbf0");
            result.Add("es-AR", "1b99c179e2f76f91945e139a67c8ca9d2959709acad59eed1195a5062d9d1e0a590a7bd770bd934a3ca0d8ca1d086e7881def9b222e27b9f06c9cb349a02aeea");
            result.Add("es-ES", "0428aa8a13e6bcedd0d0a5d4f7fbabe732c3d2bcdec16fa58716de928888a7c0d95d1adbe952c9fcdadcf516b5f6520c7201fc98687f44c48bacc9eae49c1517");
            result.Add("et", "82adda9ef39ed5f9988c16f132e3aee49ee6aa8100232f35a767cacfd709ac66077f3617c23d93435da0cdf014207a46cf662880e7afc87d600a624813be8b30");
            result.Add("eu", "b54b77f339b0ae5a85000052810fc2b2902bad9b6076cc108959fbe13aa61bd627a7ee408fbc170563ffec6fa342773e62eae6e054945da2ae8d1eef22a3a384");
            result.Add("fi", "ce9bfb82903eb4f74f39aaa46d448dcc1b1dfb74000e3085041ef8bb418adefa527221dad4b6cb34021bdeb1f5362270758dc522bcbc5e8912522e9da9e9a33f");
            result.Add("fr", "afda0f864a010adcacd0db710e94384d21a81d0a38a78a788063f066cd0e1a610cb4f2274314bb4c3f5a27f1ed588b6fa55d93048858363e5b3df5907ce8c40a");
            result.Add("fy-NL", "1c11533729f36fa3f1d67c897a56f2ebda298e7f5ff528fa2c4a0be9edf048473d8e4bf7b6cba97d8e9c2a201bbef3426846ad005b1071b8dda2a0a89e41e42a");
            result.Add("ga-IE", "923338fbb462373bf0977de39a4096fd00e5cadfa189294eb6621ed8d871ce127e5052da57d93eb3c4de7df6013f030e5fc24f75d4ab9f949123448673915f6f");
            result.Add("gd", "26c6f9b1e77dd78e89f8aab70bfee03ed170e85634e1c57a3f8e07bf14bd83e44815da491492fcd459e0030364adbf089e7b7f3010bc2b31ecdec14e90d7121b");
            result.Add("gl", "e326adba2f0f531d4758e639d05f5f4530c679a942a7115618a5ce00e317bebf0730b4699bd56e1a2bf52375bafcd3aa5d91fa08c5b3c39bdb3addf6eeaa1edc");
            result.Add("he", "91cff5b04c96fa0851a0be77e59078591ad9ce900f2cd11c637b21540793e0b895d11c710e85991ac8bf51c4f51693bc72114265afef1d622bb469f151e6f7ec");
            result.Add("hr", "52b7a0e8a7704ac4596d838647b3118c225d6449958ce8bbcb8ccd848aa95e370aab35a8b90196f52466e2fea4984f71af20bc09b501b21447321a8cefe7213c");
            result.Add("hsb", "c6b2258a5a0406ccd63f4515f0eb0d01fd00d63362024ec2e079698c9b3e921ddb2cd24be6c288f33e2e084a74e70e7a211ee115cfd8c4d95647922f665dabac");
            result.Add("hu", "602a7623fc95f43a9e7fbb0454ad624eb2e66dbacad741e8cfc700a5db98152480c533f72eadccc0b65f36e27fd8de73d6201d3e50b85f63423920a6d6b15a99");
            result.Add("hy-AM", "9892d27b2d3820cd531d1b4bc37fbd252f6043f22e12b6281fd9f4e1f85344056eff5a90eded031ed498a852502d06d159f16f5ce75be5810e4b049943f5d1a1");
            result.Add("id", "e8e4454db9123c8e9c3b1cd0a9df8b60f05d5fedf63027c40ad604cff7f98a1fa30687233ea865c3c4ea106699d28a13599a44d234a39db813ba4623a393f838");
            result.Add("is", "4ab2e866a425ed507b01ba6a5720441879f391b3f8c717fd5b55d18959e0c27111955a83550c721891a718668658a89e23ccfd185a4b468010125cb4eec7e39f");
            result.Add("it", "438a2e498458e8d8a1c86755aa619a60073a0dbdf0a6fa9e967e658cb2805bf25ebc8ac9d1d0ee059f736e0da46e9aa686ba0e7f52f22ae544afeab983f032e5");
            result.Add("ja", "d4bcd3f5810201f4510e599c14b81ec635db05f142e596e90f183cb9dce8c4ae449e82c91882dda42295b26bc0df48e14d4b7e79d07ba1809e5615bd953d0d6b");
            result.Add("kab", "24159d2ae1b9cedc688b731644ed7965fe0bd7274ff703868dcce44d081b2e9dc3b51fdb7dfb24add453662cf4e34ad86d63717e39f314d21e1aa3bf5f43cd09");
            result.Add("ko", "220a14c983ad6cac54e7370e200e1007cc92559aa5800d1001041425221519fbce70a4221400c8621ca6e0d1ff900ebcd5b61a7113f77b563eaa7eca41f53e94");
            result.Add("lt", "19c0330113af9be46bf82495f9a1ce4351f19ed974040e438f3d77e7aff8dfa7c09693a926d8a1c382a386d3f456ec8ef9cb36e4aed670d3ee45e0b8381ae8fe");
            result.Add("nb-NO", "00133e9e1379f5eac528bceb87bf612f50135bd4e760a78525a1c1d13c95f7938dce537aee8470628d85045d289c0be8b2bcef09cba1e2460d30fad785699542");
            result.Add("nl", "84ef90d9e6f25f7dd16fd7341d2ead5eba728df66a61e822d642e1243f7111a9554590629b4a118fd1582e4ba551814252facb3b0ce5aabf73dd407606e62f33");
            result.Add("nn-NO", "004a64d958d9700d21c240b02d592da7f60ae21cc895358183580e40a269596f7d2e57becadcfb3d5b7325f01f6a2efcae83bd6796f3cae2d4507134a6296f6e");
            result.Add("pa-IN", "3da4317825efb86a4d6d16c1f66480898cfabe9dcbf2ca9854f0feb753e52adb529d339c9fe9f12040432b5f3d74b4862e77e895d5af4048aec44fd57dc8d962");
            result.Add("pl", "b35399143f50b486f8af76873e71b3a9b6c40ac6ebff3ef0e902ffe790c1e8053ca7966dce5062e21c91762103ee2f373fa1c568c939f6b330f84a9f5a9e1007");
            result.Add("pt-BR", "e18eea9570150c58d8580cb5c438207a85f9be22e4d2779a1a35f17c985b0d36e3de64f02889bf74b69beda042c552825f4a8f298c75d3b6b096426b3103cad0");
            result.Add("pt-PT", "e1f4530c46f111af2b9bf48b5da4fb0fd052928818b615b30608322eafe765a332173f2540336abf5222eef4d62c82324d1b33107d68fd1fa9478d9d8bb28a1d");
            result.Add("rm", "dd4a5ec775dcb97fbbf9c4712254e01cb2c1a1e92e523c6353814efb6cba32ca64fa5492ce352be564ca7ac79faff47337f662417bc2bc952c3943c8bbb82934");
            result.Add("ro", "1cfc52b77fa60b22bc47565724960a2c98cf7a3b419fdc72073e94ad51778ea53cacf970c194a772853b0b386b75aea7247ac7d8047d47cc9982baaa911d5a7a");
            result.Add("ru", "5f043bdfcfbc953bf0dc67c05035e56c5a0f33b9a15812ab735916725ffe0f5aeddd8a8f74eb032bb0c0ee69d5888eefc657443b09f0fa5e8c3dad7ef0982aa1");
            result.Add("si", "412e03799b611a14438cebca1c0becc5ca1c46bcc5b23ef5457aa399cbe97e726fd723da359868979c3403a1c830cb36c70159a66200dfe94f4e0855e9185c9b");
            result.Add("sk", "8f926bc4a3aa4b44cf782aae5bc359a256454644f44b642feed5dcf184a5381467ce46f85f3728a2bc1990d4bba51592aa64300df4cb87f9029eacccdeab0ffe");
            result.Add("sl", "53e542a95836b9a77789bc267f3226e619ddd37f273e55ffab84339893f422e9a4d418c059adde03e345aa6ab43951e8bb0a39099a9ff5e07bf02ad941b78b27");
            result.Add("sq", "918093d5039bf948b3e205bf256f69f87cf0932fb02363672836245fbee3bb4da9d611ce3db111d30820b2b43ed368756221508900d6b3f3f962a48ed973ffde");
            result.Add("sr", "0ce0911f44b75f33c54c531472fc5bd1caf8b6edb642d819cfefbe81fd0dcb40a7a1d77e4e666dcdf3fd8e281a51ca01fd5fd916a5d505d2574f8d398a7a33dc");
            result.Add("sv-SE", "6d2de0410de8b5dca95652da72ef32006285a81f9d0baa325d52b6e7504ca9682cec5fb853901ee78530e909371505b7331a318e2f3668cdfd676752a01558e0");
            result.Add("ta-LK", "b0b2f9bc60f20a5b5bba285447ed6ca450b29478e857703570bec130671d1117333344c3271a037dec20fb47bbf52a0f77542d1a4a19140e268b109f42920794");
            result.Add("tr", "77c77302fee0ccdd9f52ce11480f4811c0def6873f0f3a6b8427e4c76d9d3ffd5ff511c17a9339888a6ba200130b552af51efa48a22904d1bba785fa96d1cf38");
            result.Add("uk", "605c28068fbef1fc80cab74bc4255f60ff10927ac2d0b498b19c9f6b3f1066daf9bbf7ded9605cca79a5436241cf035e77c453df333590c807e9036f932fa955");
            result.Add("vi", "d221ac4cd758c483aae9ccf6002509728cea4fea36e16b31261030d17664d4969c8f908e6092ef77f915f909e0e89906639c817f4af23c70db3f841923fc877f");
            result.Add("zh-CN", "82fe3998ee778794672c416abe14d9b665d854de79095f0fa19a0b30bb4b0bae1db9266e9de7b1237247c855a90b2aa882e017e98cec87c38dc70762e649c958");
            result.Add("zh-TW", "19173e6455c9d44e71b2785454d77d18d548f44a61b264ac1ea10b7323c72b02c2b8ef2798a2e730242af3cef7e49b39e3b1e337e71ce43e05c4e8cb0996ab46");

            return result;
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "52.7.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]\\.[0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "CN=Mozilla Corporation, O=Mozilla Corporation, L=Mountain View, S=California, C=US",
                    "-ms -ma"),
                // There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successfull.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestChecksum(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/45.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //look for line with the correct language code and version
            Regex reChecksum = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum = reChecksum.Match(sha512SumsContent);
            if (!matchChecksum.Success)
                return null;
            // checksum is the first 128 characters of the match
            return matchChecksum.Value.Substring(0, 128);
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            logger.Debug("Searching for newer version of Thunderbird (" + languageCode + ")...");
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
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksum;
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            var p = new List<string>();
            p.Add("thunderbird");
            return p;
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
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the installer
        /// </summary>
        private string checksum;

    } // class
} // namespace
