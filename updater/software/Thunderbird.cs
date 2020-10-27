/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.4.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "3b0e704cc4294f89913829bf5017fa34a739bcd8db69e79d9c38d67ac10795dbfe1018118908c16f0c76fd434f42cf23c838d6a0a93a6cb2668ec41b006e2d2b" },
                { "ar", "384a4d0caa43c0d414fe5ce8691bdca9591d07d28cb826e9149f11d933a759a4fc6d69438e2001559909a6ac42046693ce54aaa4dd5e341a9c3e3f16f4a65353" },
                { "ast", "35cfce0b0d6bdeca0df1dc4d0a77617c8084804ba9e9d080d47dc7923c562f71ee49e42aeee704caf42083b50170a4587afc328c1d29c13d4a3f26562263ef4a" },
                { "be", "8f92f70344060c4ff7d82715a01a7cf8923fccf24fda9b7f3133d80a876e8e8eb82231774c8ac404815070be6035bac2608f501662188904476269bb0bff3138" },
                { "bg", "dac71e9907e25469f3541479425fbf908bb02f8385112fa9edbaa8d784c2b90c4c2fdeb6881e64e84cdbba8d1fb267d5cea46a5cbc4af925505797a5e04b2f4c" },
                { "br", "c5cc4bd1a863b89d2fbb684b5c7dd59a131b713bea02c5d9ae1a937370e6f91ab5ba7062ea386f0757ca8e793d4967d807f552578b93b291eaca6ef55c402403" },
                { "ca", "3db6683cb58b6be885bd5593b8fd20d5b9a42e5c6032b3b2ae3ea8ff0039b60a2f6de4a9cfb75979cfb50f558762673c33e468d6e739fc8115f32183948f182b" },
                { "cak", "ff58a4e25ff752fa7a1025f3fed01558ce9eaf33b2d6b9e0656c4c83f1d8e55a6208fe3dc2da08c00eb3b6acb538da4f0b16a6271c487f3f21559d4a6c684cae" },
                { "cs", "d6a10db1cc0343e47bcd26769740e02e8260559fe9a7b7325e848bc9ead7d33b41440bd0b3cb152c05245c34c2bee95ba320bb4b254dfde6562e2e9fc03d4e88" },
                { "cy", "10731fa3c66420b99e8bb1eec3faabca9512ad23bf850a2cec90f59a41517720770d70d23ec40dde4f58362b307dea51e1fe7211ea0159c4fe4fcb01b36f3af1" },
                { "da", "c196cfcbc6a90cf0aef924448514dd56f0a2e463e43dabe104901e5189c1057dd88cbb5da73920c98c931ef18c49c86fdfd489f7a0c0ae5148ec184bc6f262e1" },
                { "de", "106cb9e77581131c41f88e3f4c51bfdca59f3aee0b24569b920388e39244857012124b7fb78e7d9820edeb9b5d874e22c62a821366821ef2444296facda23656" },
                { "dsb", "f091414596e2ccb13feb9ce97be960e3bb224f7c81a9f6234863a2d8c932968ea9c73ad58cf77ccd68d623007b10fbf5d033e8dedcce5cf694d45dc5ecbd64ad" },
                { "el", "24dfb58a109951cce4f46adc479cebd550151861ed8a73719db27d06cab466bcf205303a6b90b243134d780720c9ec5ffc47a59b46967bd0869367580582b100" },
                { "en-CA", "9855cdfc1ef80ab4d4fe6e5f0f7bdc0305f35fb5ddaf673bb611abff8b8e3cc9a30799e371cc7da26740623cb9b07419c9e731d97eb3762d141b9090b6aa5c08" },
                { "en-GB", "9b5a25c626b67e3f8c2ff43d3188d992a86889d75611c10903759852e9ae91a1768ceca034699cc038f004716af59979b90d7addc7753b1b6c37fff6bae38a8f" },
                { "en-US", "ba2442b8e1f356602c246b590448c1be69e1a75dc5db99c2707489b831cdb1cc46757044f5cafc23127719089c2ddfde963c453401d6c9a065f3c4b52e4633e4" },
                { "es-AR", "4e1c7d995cb8fdd4208fa8aa480c69b01e69f9a133efc92776c3ca7cb3f8cb84dac9ab432d96bb6cbefafaf5214a532c6ea914639fee950d30a26006ef921673" },
                { "es-ES", "394ad30608836051371968cf2f64ca5de83fb2adb57f1b9ea98ba5542a28db168e37c7babfa872c7f190e187c8ea4c52b778c2b0b57b7a42d62d73fd5b3b9990" },
                { "et", "74f8935bd7ce55a2c0f4d3a62794f5160f7ee73214a0294402d0e26b44ec6562a97f23eefef498b7a5b0d82aba64520acbc47432de450768ab2351e6b094b49a" },
                { "eu", "161dd70f31c83e263fa25605fb8b4364b194ccb1122a5705fef5455e004919cc0233f4fcb8cef21b16c2a41b32da7ed2532afdf7c6db49696b1efc4f7afaf5e2" },
                { "fa", "3537744d0320d2b91fef88b67b56e3950d42c2c4fa92f52f687766f7cc21810bb1e2db34e1c2df9cea4ede94a00956860c10bac182d916d81889a29b4cc1dace" },
                { "fi", "09feff6b4b5a7cb581178546028bac12489866d9b4a1e8fcdc58661e7996ba5de649b88ee475c837c25b0fab8fe40395387e1f4c1c33172883aec6cbced43c3a" },
                { "fr", "3b6719a76fd8077e09ad4c56cca95389ef53cc9a71d2e99a24219c2a3cea939685b4ec6c8a9f971188272eff2707d716ee6eb46d468196e2ff84ff7fd72a695f" },
                { "fy-NL", "a4879ad5f95ebe07bba3f6b2ae9bb065b8694f5bc16338f091bd4315e64c6e5c21fd29cb48ca7c5cdb9b99523e9738e33d2a25006b2610bd1a9c3acb494cae10" },
                { "ga-IE", "776f84dde1b84bb7c6ea88bc1d52888ca170f2689eb8360844c83b8e77eb25852ce3059495414c688cfca8cdcdc5e7b06c28f921b687fd26bcc850f27455719f" },
                { "gd", "501ee95b2f9603f215862b6e49d4f12efd4e9c67f50a81d7e624d6fbc5170d7136fca8ba3cb6a58c6a103058e8908c4d4d7d38629035039f93252d106f2b4e66" },
                { "gl", "183f9778bc311b5896654a9ca5d08eee9a47eac95594a40d5af9a88d2dbe1fa2a4f68d5e23a4763261b64a07809dfaccfb39de31ee0a17501b5db8281d98f944" },
                { "he", "9e71f66f10503ba5b9975f43074356ad9044567a86935eddc1b9f976196c52ed7480fa256523e3cfa0798d1547c8e462fe458c5034e085951f2b5d85988b107a" },
                { "hr", "5d8831d2c970c1ce6a41130da64fd03bd21b8682ad9c3dc3dfd19e0693f8f2d2cdb1be7ea97a07e1db2b4a77c5e4152bcc3ac206bfa69e6e3ab0bb34e7430bcc" },
                { "hsb", "60ef13653e2f47437fb70704db10bcb64a30f76c388d908c6bffc69429dd07ccc54dd2d3c50db9ae41f4cc52fae1267601f4831b4d5796a166392194bb4091a3" },
                { "hu", "3b838b1246a2acaa15db50660e0d14cd1216b4d0de7dab9bf14aec1400547037a8c78475011516a2c147eca992a011ca84fc41db001f7365ee6f36b925a8ab3f" },
                { "hy-AM", "dee1b8dab10548b3e34cf60ca3e8c700725b450992c8e2e21ae5b3b70908a3743ba92e19a5efb4b16e3422c2a1985f9be653d3cbb6eaf134a98a972c59121ac5" },
                { "id", "a88e8eb3953e9e171e839d2d15af6b88546a94f269fc5eb3c1d6e5c829448a8edde69e8c667b136a041678cdd5c9101759609a63aae39ef2f7179a48da337193" },
                { "is", "1c779ae938c7d24d9f5ced8aebcc056c8b362cd65aece3f5b1c5b4e8818616ca54d35bdc0374bcebe59445949a72038a73f70c6874b0d82f02e88fdc547fa9e3" },
                { "it", "0ecc930bdbd23d8b4cd5c460cca5901afd45639fa7d942cf60400b5bee5eee992f8379f1d9714061613fdb2da2bbad0cff89ffdaf98c43a945ac419a975a4177" },
                { "ja", "41c0c8cce0d7394645e7bb035f59d0f79503c53a94d5daf37e8739beaeb804640f7050ad822bb93d115ec4cd5a10cd218d996c294ab1bb8b5f1ba18c0583c7a8" },
                { "ka", "e6d3707d2d4a58c1fefcc72be2ab268f2656d2435e89c1e2d85b1a5d420574aa155c218c78a7a9da7f8a2b4e8f226d643d1ade137fe11dfd63459c38326bf601" },
                { "kab", "165e6ed86ef1565b681284e5cf56563bc88c0ee27c8e0611405a11245237a17d840c3625477993f39d1c460775f8e3070cffe7a86c62d50f0f87e788685ea3a8" },
                { "kk", "ff117cf5a8f19b128a7d2862b564f417859691998ecc7cf9bad52796b4db66e89fb6afaec4245130ef9fe741716e3ab5bb51ca2fb06de4441a1f41a404244395" },
                { "ko", "7b627b1cea10b0df3adb2d89bf4561eb4189c45124bde20a15414149910f83ca5eced524f56095d54afab0a38971386c9350e14e42d5f71a9cebfa9ffc5aa29d" },
                { "lt", "3f8581adf31da6e7bf2cbc5f88ee8187fb32cf073827d9c0849b8bf57e674874ceeeba704f6302ea8bdd6f41f586818ec947f5682946d3695fd00832b663dd0d" },
                { "ms", "7f6db7594f930dcbb57332c252bd99843fe87f36ba493fee9b63653adb0f831c89f4ffb804b13834a73a6d52a8cc87f673428410662efd52770577e98d858375" },
                { "nb-NO", "74cff35fe13e93f91905d51d525525879a9eb6a2757840ef1bc16a7c01d0e1ded7ae51ef0b9cf725d636887b92f1ee387c721b129b6764853834125de5a85302" },
                { "nl", "1312e03f009a3d7860b1c2f5f17802a32c1b58c98a0fddec6e371101db29beaba83131ef2923b5ef8eb263b7063e4983e5072db8ddbbe17e31e78f5013986c4e" },
                { "nn-NO", "c5db769871f404d89716e69f4fedf7a2cb8835adfc36d9994f438c8df0f195880b13e301b96eec38269834e3538635dcfd9fddd4c77a44f67552bd9c9d33e153" },
                { "pa-IN", "8982e47bf3ddaec76b768b4649afdbe21ff6cdb8fc40838945e45320730e92b921ca35eb34b40f75d5f3a995285a02390320e0196ad9ec8709e46335cf885d5b" },
                { "pl", "f88da83d5516c8284078d9feb3d9724dd2469d49cabc09bd3b8b545a40c2b5406d7315671a6975ef9a709a50275d10d6fc78dbe78365ab171533fa6e9301572c" },
                { "pt-BR", "87ea73ea2bede47d76e3f6226bb4b518bc13ec09b61cf6a6a214485448c4fd8ae2077b90026d0da372b403b5eeb628eb1bb36da34641ba2664a160d970367db0" },
                { "pt-PT", "b5cf63139f06c7091a288940df7811006520ba90e9a4947479f74d9dcd0865ec63dffb19595b52c2d9d2c6c606c5d1208693cc2b9cc34649c44006692167f5f3" },
                { "rm", "479e29e2ad49f92eef5ebd1efcb7f2bc17e264b117676589b15e8d95168bf905c0c5f347c1ba5e0385921365ec8c2a1a7d58bc0d053f038f2c327f2d1bb2efae" },
                { "ro", "859e1e5ffd9d912e82a37129ca51ba20397e6a60f4694298673383ab723468738516b4ae0e1362ad21ef20bfce1eb3957e6bd077b5bbcd2201f19cee1f8c38c5" },
                { "ru", "d65869e49b0ce6995f995ec7ad12854ade6d2916bc55a9ec9061c4610e70ca4afd0ecdd17f4466f402a525d6eac8a6394f10b224613afc88af38fdc7dbedf89d" },
                { "si", "8a9bb1a90008874635fcc4337ef5b0cd251d7e66432288706bbc4e9d1dda5b7bd8792012c1da3e5aeca358c9b903bcaf3dc70bdcac33a71f608ac9df38ea930e" },
                { "sk", "ddfeefb0b4ae3dfd8b5d2b9f328f4af7aaf67ffa1bb7e62e70254fa86e4103b6250fd1e6ca60be54a1bdc1976ed8f31eb74d5e98564d2a0491ae4cc3b7daab69" },
                { "sl", "fc3df15942a0ca577877e5b845ab71912e981379885576ffba9fc9175b1c210e5f6865b1730600a9fb9eb7e7f7509ea9b48c3383da1dab4190819168ffc397cf" },
                { "sq", "1fdddd0c91cbf804b61f63b2a2ac6c813055b60e8bf73f05d4ab51537c98cf9b2af396fc6d67f86d2793a806710449a9b9e85868f605aa48602746d15ce272c7" },
                { "sr", "c157516695740e09de0a63c9cfc6b4ab0751cd5ea5f7bf72fefdd22a8c2336630f2676108bf3f85ad6b2eaed825008d47d49d9e7d7c577569738f9c99c333eaf" },
                { "sv-SE", "35a7a9658dc4c6a4578e21982ef5f1bf5605a194688861685136c7f94c2725cdefa1558e792928858e26179bf6d01389fdb70e0e48033c083bda7661e1ab601b" },
                { "th", "de2aa3ee1bbd8790074c2b928e57db061b2516f68ca49852180a8c5b56affd6bfd6239bb45e680de6715c7cd45008f923b8bb1faf34b43d5d59943f4c899d5a4" },
                { "tr", "ef77dfba478c3ac13d06b40ab70cdf77a932aa52a958831adc03af7a46a2103fb5d22e890745b0899637f7d394a937fd63c26ecf79155befb20b65e201e641d1" },
                { "uk", "a7703fb9ff9cf0a599d2281524ae4ac6315ce242968af8d894d5257bf8f955c289379528bd0b6dec681dfc42ae0d72bca590b5794c8f731dbe3194abc0a50908" },
                { "uz", "af311a51a4cbc051ce2525f059cb214665caf06498c2d4f75d5fd902c625b93cfdd11a438a19cee747cd4f9e1b8c398a9cdeb15c2c6d20350453b763c95cf550" },
                { "vi", "775184d4c545b9b639c0700ca1b3d3f8d6d9b6f77542c85eac5500c52df2f2d844ecb2e4d1b2f2d54cb3d002b3cac3bd01c4aaf34a2a0caf4a7baf3baf8007df" },
                { "zh-CN", "a4b3f7fb2e7812ac02810b532ea08a333dd12f2c6ddd427626df94a300e54813d8f2be7b8be556ca732409045021e8047099cb4e8c8969a9a411b133529d6847" },
                { "zh-TW", "e64b30872444222e4acfc4aa60674836f738736fec14fb3c5b430a45ee157e9d687f2ef235d7dfa2a65d0009df4b2199baa9419c8dda78e3506ad4aebb338ebc" }
            };
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
            const string version = "78.4.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US",
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
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(1)
            {
                "thunderbird"
            };
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
        private readonly string languageCode;


        /// <summary>
        /// checksum for the installer
        /// </summary>
        private readonly string checksum;

    } // class
} // namespace
