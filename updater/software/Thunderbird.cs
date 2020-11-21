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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.5.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "ff837dc28cbb0e872e92c38f987373a248abc1fd63222bfceb2db04b390e648943f33727faf4af1e34c2ea33f9a8c98174a216600ab9be99aacbc04091f43524" },
                { "ar", "d8869661aca35a875c16aa940b736a5ed7f884949c0909f5f82946aa45fb68de1871c7f758f19415bdd39f120ec3d76f4235eee0ed5e27c698eb8e857ba4fa6c" },
                { "ast", "80a316e306b352e587b0dfc522ba2f1150da1207cef1b507853e88355685830bc6fc5f079eb6f6150fe189424da9bfd6a1fb3a308313e2bb1c33217e4e9dad3f" },
                { "be", "76187c240e45ee87eca476fda40d4fcab6b091fb8407a7901357154b6bce3d2d0dc539e50c55630fc92fe18766720f41f7fd5398fdb052960d4d563e11af6d77" },
                { "bg", "507062b900ac6c5e829381c4f549dae54fd5244a75d2a136a27b6e7e96337acda83c14d887cee27d542b7348ef85a62828f7032267138b974544148a9a3d149b" },
                { "br", "bbbb1c8735d3e41870ee8fedcb76f306590d0ccd8b0d93d4782af97378474db37842874b61b930f3218b386c4ead977f99420b2530f2861464d86adc96c19726" },
                { "ca", "54c321413ce26e98c47963ce191940cdeb60d57dc3a6667a91d0efd684bcf1bab372d88f895864e51ee993e692b095b421b1011111715b1c97a7c3b8c431a6b2" },
                { "cak", "f9276b9e76387ae98cea2a1f134d921a1e4f4811ea0a4f679b051fed73ca355cad6dbfd11db414fc238b3a1cd30c94d970846a7b5c59b7b6ab85b8aa093bf7e4" },
                { "cs", "8b9184d002bd82a887ecbc81781d61cf3ca5bf76b4210a7231a5622f8a7ee243f3cca4a0a5624fd99e38db08ac69ba9d0c8633e9509f14cce983da988aaf0b31" },
                { "cy", "32a0938e7f8c2e0cb6e491430d0019b46b76683904e97c39aa85c6e9b2aa47e2bbe4a62c3399d966ffab1b1f841cfbb583442d1f22df9ab4193778cdc98fd1c3" },
                { "da", "d6a5d8326098975b40e1327f6ba4c0aa25390f2452ceb47feb90132348e740e98d1f8908bbf5f268537a1f91424346eb09833881b276b5deaf8a43dca26b7651" },
                { "de", "107165005760be322ff8a71567b08d175f144f325ae8bf809d29acfbd8dccf0f6da6a57122a9bdbdc9a10d98bb57c7f14cb50f52d8d6d7bb839442bbb80b40ea" },
                { "dsb", "7dfa15e2403d5af3353fff22123a985d5c433f13a5a4d294633753200783e0d63ae6acbaabe6fc4c21bfbfc372b2a57965ce56d6236d8fc9bb81501c1c5f83e7" },
                { "el", "5dfe8b554d5fcd6a966cc522d12d4a337b1ca16845f046bad0b7d3bd07976503445cea2be27b3f6463277b1e0fea9e8c3b5e2d24d0f4938128f0bc88ca269b85" },
                { "en-CA", "a31e35ff9c6d1f4268f974185ea614958ca030ae01832acf5fb2f717c849f328bace29d004be9fe94cb317789e15c29424a3473af9927a746972d2af4a4bdb21" },
                { "en-GB", "1894f8ed0064a6fb496e3c709971c6bcd4064816224dabb42e83c7340586d1f195bf464043ab43dd789e06adfd3298ca5c98fc2d100392ef5f1a59ac95987db7" },
                { "en-US", "a098faa1d51afb2de726ba650701f78a0dbc293fc0bc93ed7158aa37a8eb182647c186a7abd44338814e868a9b2ed13316e2d5737c6fefa096a70cef22663364" },
                { "es-AR", "0b17d7ffad88555d2888d33d73c3e36695cca2332eedba9e7b19ce59613839fe5ba56839565ff8912c9dadc03e07f63e8501aff175b2f27001515cd3cc9bafcd" },
                { "es-ES", "43046cd49d314b2780a47d89ac90ce3df6d5794ca9f48b19fc4261500571399100ab62ee6283426501de512e878d76ec9a9d46038f0e7c4bcc9f4385e7b82466" },
                { "et", "27222d0b88f47ad0d52ce76763c070a38a07c0128547099c61e8a950f038687fa04a3f7da20d7d3e736564510446b78b008114e5652eb9c723e68e95bf5098ef" },
                { "eu", "bdda35ee8c231231977a035ac162daefaaad7370f185bb8437e0d0c4b3f5ebc8b47dd960893acb5e358951a5aa4a3f4e65467ebdc82a76c764bb452dbd9cf5d0" },
                { "fa", "302b46d66c643345c7cd62ea4628e375b89524107452e76e5d7b60c23558a6ec0b9f672aa72ac725fc8660ee7851a814e0628104d3d7eb9093f2099155d23b01" },
                { "fi", "e1dcdf739b3681fc6ed3bcf825d77333f40221600f0d183a8fea442f8579b8d9822b1b3309c87cea668a61c4b94afe1274849d0c25e179ebd04efa1039c95660" },
                { "fr", "be0eda2f97c48f2c964338eae2deca2c48bee2d044f66b6e725fd174d965d368b66d1cd6380f3fb66b1c55022d6d302e5ec3be44e1a7cb61644293ba86d776ef" },
                { "fy-NL", "86e7ef35cc58973f07a048cd3a7e000acd624bf00bcb098b733cff2dcdfc244127c31b62fcedd8f76b083d34c6752e85d4d23aea437cacd32f225f29a1467e0c" },
                { "ga-IE", "5cd0a4ed14cc9321c298eecc4c2bd761cde234e4abf662fca8e1b1e0a193692467a58d6733ec9f985602ab395b1f63fc3a6283a4f9a506dd7713c3d4e92fa0a1" },
                { "gd", "070e4a7229c48c9818ad9a885108696ab299aa7449036860c790fb3a383fe600251af6e3ce752d987d0dded54e8eeb56039db8c41c905758f632e84b4d9ac013" },
                { "gl", "1a9c23a0dd8ef2fb36d4120fe1d1ab3cd002f287142ff87baf42ff3f9fcddc540afcfe2efb50b5891d1164f471308d651b8a59353706041bd734ab60d290c6c5" },
                { "he", "c4095183a8f736b1dd2eaf489c1ed7c1aba59b137979a790f95bbcd50442e75caabe5557ada21ceab9dca306ca3ffcf3e03cf350c4be68ff12944d67a7de6fa8" },
                { "hr", "992745e276787a6ef1b388e68af73aed7eaea16e25046452cfeff214ee97392e96612df78b4a7af6aff63d9494e7918596afeacf3b28e308a1ea990ce08b720a" },
                { "hsb", "270f6f2c82e8e5a58ede15681abab9d36a4689618d4ab19940cb6e1b4e12e110ee58480532eb411c8dfb5fac229343b4e8bed970afe202ae73bf14713a3d5c3e" },
                { "hu", "c324536e4c2fdedd02cbf05a415c806a9088642edb4f80aea8a95791ec8aaa2172b0a2caf15fb04aed7a5f8e8df5a30a59d0a1d57e88e0be2e794ee8bbb18bb1" },
                { "hy-AM", "afc35607ecde0094d019e5223167f570af1c2fd37195a581526a91690f2316e1e8135b67f45a1bb3e33e34b6e2e40a35c55fe8150e197065f0ac46f66f975b4a" },
                { "id", "8f68fda0568f7aee1121e76941b0e2f361aef53db10af5167bda182b7c64eca9c504b4034180024ce714c37a666f27a512503e6d86566ebc5c58a7c1641ea73c" },
                { "is", "57d5e6e92071d5cbb15896f9c4356d2c6ab4d4b6cf198ec16b62e44e80036cee36688110b7eee54496e651bf207520a0cdde9837b8892c7d8b92bf08f57298df" },
                { "it", "9d123a085429c4ea9991f63c6bc00695940b7ea4d3397b63f19bcb90b7cea76a078f1e5277bbfb74e4549a2c51ad06d31e02de4261790106c2d7b7c34c5f41ff" },
                { "ja", "4837f605f697c7f9cf4e4af0c61512bb9e40ed354506989ab6c0f79a58e8ac01c863f2a53fb40fde5ba6c6a9e98c9310d68d6449a8e189685e2116524c60560b" },
                { "ka", "8058b8589ae706944e76fb2f053ef83d41e401aeb4776b9cf9a970d26c3302899cd94db9ef72f9b4dd5c2deebc6500cf5fa9edcd92b22eaea38a30c752797d68" },
                { "kab", "cb67e64e3ae0e8e00308b927204cb07aeaa2b69c362119ffcf6deef1085961aadd3f37cf5be80bcb17b177eb40861434e2224da84a024ed771f87cc283aae016" },
                { "kk", "c64053f927719860b8c1499ef3fbdfebe8d019568afab05a500575a95b5f1f1a9a5f5392322eef2b6bb32965f1fb1af39199a0a65f58adf6b4f92b0d0a720fdb" },
                { "ko", "fda4cafc906a39969b851b90580fd98f6c83200dbb7ffe0419ac0bc4f00046bdfaec6c9c82ce31a3873a5d785ddd1ec7eca11eeb56f5c1be315b01c6b0a8727b" },
                { "lt", "bbbc0b4325b50cbd9f5ded412e051100571db79b783d80aa0f0d3e4b1a9f28a8668a223efd54644a150e13bbab0441e2eda6822f33585af3d521424189f3c02b" },
                { "ms", "2227d1c9bf31cd4761ec66dc7e50a1c096c18b5199b3fdbaeefd597f61256ae3afae0f742f53f8df5750fd36aa30d092c2a5371091dc8fbbaa1a3931759ba1b6" },
                { "nb-NO", "804e34b813e278178c91d2cf1714f31c3068e7a1df810e070c163111c435e8603d375f2ca1fd5a3716cefb67b75a4d8ad9bd2950a87e945a2c8a6c69ab1d93f6" },
                { "nl", "33217cfd4e135e249e4859064a65a8e5995e5f05bd286d5d22e3868536c01827354c2c42ed29008d721d5c97e5fc599de24ac9a8fcea4d5bd5d08f99febb159d" },
                { "nn-NO", "f5fb6456822a49a736661dfceaa0d27ed43ae50ff3f46e7eb072f061b5c09ea120f85005fc6894973137fb23c1a1a302be99160764bc8cb6e92bfc2e434f2822" },
                { "pa-IN", "f34cc6bfa57e042dbb2b573e8c840de6e76d229c79fcd15ef92a2c357c02848030e01904a36f87e341fb398f5195bc6a30df07550501f7e635b5dde62e896c1a" },
                { "pl", "f4cc04e9909e391d0212d0345420f5013b83dda5da0e1d59d065c33fc8f357d3e65726cecc81df6620f83c9ae42d5c78a82818b43f110302f1090d3ee7fec20e" },
                { "pt-BR", "f3482dce9eea179dd4e84e0a1054729af11e23c3e63034e9befbda994515542cffdb23b255e2a812e277e40d3fe697da282fa6f372213a1a01b593e2dbf1320a" },
                { "pt-PT", "33f69073b109d4351a9803c617e1330bef8a5a5e028a7829322c3f3f76fcf9bbaa44b10e7f71f0827f0deb2545f0f31e114a5c5a9d25917c9a6186875f2f3f74" },
                { "rm", "62c0396b256e6fa06280f6817398301a82820f74ff5233efd4b57b18cafa69d23827c9488e929db3779b154d34cacac664f7fe5cb3161e022db0527048e8b5f5" },
                { "ro", "5b44104ef850ecb6dfc1ec5bcc1c902476142c26a15639f8e317e629ffde85af87ff053d877807e47327084bc6b75d95bce868bb797a91ad495f0d7a8621deb3" },
                { "ru", "1feb594f21fe087b3464a420e81c37a902a689ea976d7c27f21299f4d7e3d1d99ec49b444162eabd265d4c6a9e2a64394fd6bc9b49911a4ebf89c626791751f8" },
                { "si", "de5c612c28842f52e5b236709d8aa6688c2e49250267d65e0e7754caaa9ef7e9174473d8ccfb7bf544b1cc181f3ebb1c5b2ce328866ef7da21b0c65c375fa2f0" },
                { "sk", "a2549932f980c998da8e1a7c64fdcbd77427e8c7579d7fcacf306ce77e0d6ba833f2b19272d668baebe433c0c86b8f90142b7b2c0f3058a3328f2e9c866c693f" },
                { "sl", "7291d3b94695a7a943f8171c39f192ab9e8e498dc91f5e57053ff35ca22d5f20e276ec828a4f69185ad8fbe53d3f388a061383c5f64bfa11bbdb0268a4af01d8" },
                { "sq", "c1df9f407a4b5db61b9dfa94fd2b3946c7ac13d8489efe24d0a60f2818ef317079c9df31b4062415d96b0f13b72d649f75598cd3d1b4934b6d2d0b7318e658bc" },
                { "sr", "c9f336079f8a165fa9f7bd9572fed0cd6113b31211ab66308860c1673645fe1f171b3fcfb304fc87e2a6e832cd1a54cfb8ddfe452e6e53be8ce4326e532a99e6" },
                { "sv-SE", "763eb228f53ee252aefeddb486c9dbd136ac4125f0a34087ad95b96f64de489538e7495ef52ab43d073560efe02c7d534a90edd613ce184c09040d7a0da3ae20" },
                { "th", "3118708791639a1081a087d0c30c8f33076e714f19f135351772c6973a482b232f08b4aebaf0564fdf85198452e8cb0987ce90db2c334be290ee2daafe342b31" },
                { "tr", "e84406044b30f94606699861eab14b33dcafbf3d9e8578505928f5760e93fa9af4a7a66f6c698288c65547289f9bb80e66b77ca48fcf41ec555a5ff979e83255" },
                { "uk", "462857ddc0472c5638b1eceaafb7ce26a8010e652243363b8f7d4590d5a7ab891e3c82d3348b9aa92465878ed3c4244c486bb128a13dbd5ad8ca0b1013b124f1" },
                { "uz", "088a23b08c0cd4e4027fb56ef7e703c190ed0e43b2ae9215e166f07fa3b55fd7a6e51c684a5cd6850e3c0b5df6d3ec2467c2f0f740a4d72fab632ec16898eb42" },
                { "vi", "d1fa84bfe3c58eeb4e9e8840f85dab13ae5d7d27b10e9d4d1211ea0ea7d253ca3bc23f8f66e0df9f50c859178cbb66057efa46db282195bffc8b137b7bd17f80" },
                { "zh-CN", "e7696fc8694a71257a0a9ee59a26ae5283e814b8ae7569be8911aa46c936bed773ce001ec3f6d7daa0020bd437476b676bec933c460e2137c59a07dc150729b5" },
                { "zh-TW", "c7aa426d28b617637adb38b826a112027e53ebeee8538a9f7808caf683d900db1c35874fa78bb5ba1310968b5b0b346aa24725daa91071c1ebc0f73a95a60f0a" }
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
            const string version = "78.5.0";
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
