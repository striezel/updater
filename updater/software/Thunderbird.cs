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
            // https://ftp.mozilla.org/pub/thunderbird/releases/68.9.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "623f70173359f7d518f0416b55fef8076c7dec65a6da40e122ebd3189d3f7f294382ded49329aafba5aac6708ecafb1b5236a7916019ac2626343caf1cb9de0d");
            result.Add("ast", "6f32b632f3c8d15bb18477442174493671585bbbdd244cf6f690c984e0a30d09898d90e0ca3e83b73624511db2f4108e374ace82a4e6866f7f2012ecf69d3dad");
            result.Add("be", "0cb8b4b34d5ced0114e094ad26d1b376ad19f33d5a66b95cbad909c2496a4da0c82c7a1be4eaacf2a6ef657969e9e5abb73bf88d2f1e070b5ca7ec76a5713baf");
            result.Add("bg", "62b6f9f5e7a0ff62d07d1425f3922ca9b7ebdb823b1abec827214de03d24297a8090117705d377de87f3f8ed572b25e7cb22e6465d85f29f4adb279f42ddb22b");
            result.Add("br", "309ea9f4793fa50da0b0c17d7d7be7cc284f517780042d0b367e03017dd8853ff5229239a495bf2b78c5d57ad20ed6a333052760a62777eca9d16dd34ceaae38");
            result.Add("ca", "6ee81bef7d78cd7a676c2ff781fd31b716bed046cde3b632dabd7bdae43f09d615db66df38faca3c34bf3f710a8b8b9049c6451314ac6c52e2f9f79ae05bd2a1");
            result.Add("cak", "a7a110b071dd1b429c1bc73d207309a2244ba05791b849da70889e92f3b0cab05b94b0985e95b4e9161e3f2af8b116b891ee632258ecf9b4a1f775e212d7dfca");
            result.Add("cs", "7ec80a0666c2b1ec1c38bbc2bf3be0f68aaab601735ae9e581f29019a1f007ba1fd76fad948f6b5e51c9df9e8263cd41e7150b9251267daa263889c0f6391110");
            result.Add("cy", "04980d383b82b4ed944beb0beb56c92362ba4d6ec6115d32746db2d1c5283915e8b16c37668d76b014534c764c69acdaeead88fa8f73184e6e3b5875819c5511");
            result.Add("da", "fe30bd824ac7a17c6170562a67dfc26562b5c27aaaf37be0d54146ce40a9870d3f3c5f2a8e718c3591fa25d38abb685064088dd8c66faadccda5f720ba6aa710");
            result.Add("de", "699e6ed92b5c19b743cb8ba8083f5d62b80f09b0b8fb44efdf717d0b9165aa7f903a44a2fe9232d202912644617de5f8cf6233c6946b5a06eb16946c329683ad");
            result.Add("dsb", "ff5f4bc6f0529d8216295a02b529dca7c32c0105c8e46d0e015215c20b951bc1a44fec95b0f6b471cdb3da2e156ca213824a5af26b928a35996987d604dd3ee8");
            result.Add("el", "b1a1895952b23d2103a5408763a12580a9492b520faa95bb5228d947c8e2333758f0c92a57058fe28639efd3b7d02a3858404542f0046a099cc48fea35a9ca22");
            result.Add("en-GB", "9fc1ce5540033f119b0be6fdf456b85479d58b5cef1cfcee55ee860d26a317388ec20d8bfd1b1147867da3a1762a44bcbf4575e7a61c0a9c8c68d7b6a68c7e46");
            result.Add("en-US", "dc212638193ce5939f1402d0db498d792a7b3a7e6167dc0f9036b88e1a0a57f9aa0e6be6f07bab92eff5fdab1f7f385e77d465de4e888cd80cb826672b64b55a");
            result.Add("es-AR", "c43845900eec0ba617bf0070949c84c00b880a39b25c17c674834677545a00f4e51b8748782ce88491408887441f6e766f96aa611e54b5e142af6fb5be06f096");
            result.Add("es-ES", "9d3b3f50ae579400bd688f2f33b7b16aec56b6fc2a7e754ed57dc9c3ea4e64bf887dcc03ce50be8a2fe3ace2f35bcb1e0da8678c7d00eab2c51212208d9b43b2");
            result.Add("et", "ab47f9daeef0ef4a72269a4dea26ee1151419556ad3c85a5248c984bc4d7574bfaeaac4625538bec0c09fdcfa6e16da16149cb801bb082c942190a2627abca3c");
            result.Add("eu", "f118d71bc0713b2bf5a810a3b4954162310e6079aaf783e2528bee69efd98858adc76ce9e81e3ce382d33a06fbcef5d9cf851b5b4bed51ddbd73b52b8626d3ec");
            result.Add("fi", "db79121be89150fa1725640c1dfd9406fcb8f581c67a1b92ab00f1939bb877de0f607e0f4df0487b1f415ed797070ddf0467c31c14752fe689eb8ff1b6464291");
            result.Add("fr", "897a8ec6af7b5e237cc66c969e789c9ef9d187602d9dbf3ec03e9dee846006f1ea633a27c2123235e10171ee9c7ca9962a6f32f063afded0e110a8648d6e5b9b");
            result.Add("fy-NL", "4966d243172c613e1617aaf2f28885ff27e6c5ceaf62f0505822c732a5447f745135109d5365716cc11b171f3674813fe26524308377d6340116f281f1d2c49a");
            result.Add("ga-IE", "6abe8fafd5f75a8029af0fc4095e917ebf026beaec257d654d3c8e3c270563d5f1d086dca7e90ff6951d9097a18cc558f6b83d88061c6fa8128f9973f0b01b50");
            result.Add("gd", "278748933f600eb7a188d4eb2a39cc746c08b2a707a88fff3b02ad546c2a33506e3fad2fc09b5392f888a25cd29d592d0af4e06093107aecb487460e5ba97b26");
            result.Add("gl", "9cbf4ac2a65b9d992896ccba4d0a61f850560fd4fac14a15db7aefc9e251b8db5d3637d45bd64261f016da12b4c4bf21b5d4d452de4b1982f1d2c7c991ceee80");
            result.Add("he", "f9a4deebdd490563539754d7e82cd1c0c5050dff6d798f3ce356350972e1f7842fffaf1f48244a7f9cc645a23bf9685091f4a0eaa0e87423815c4f159b41964c");
            result.Add("hr", "b54bcc7e8bbafb1ef91928604a7e603c697d34b8b0b98b0fc441b94531ea38f2f334f7b9778d43763249de2dcdcb476777c962f5de92cc65d2a461295a81adb9");
            result.Add("hsb", "dcddfd3b0ac56ac15888b970326c6570f1919e5ee6238233bb11bc981bd536840c9a36c5a8fade3e969bddc8f51e8fa12fc439ec28f9f2be37fc7c50cdd7d671");
            result.Add("hu", "3680960ade48ff0ef15cfa8656f46a655df56a64cf3beb6a012be703857278421fff35457d133a4c1927ecaa7902edd16f1b740cf2ae7845c5b3773124cb0dce");
            result.Add("hy-AM", "3b6706bc6c8e84ed0f1598352eb353498ac0821672889095989bb7cf441b481c00c20318302511bff0c1eba551fe3732b451c6d8fd34a4434e7b9d25d859194e");
            result.Add("id", "3842a6e3b4a5654f6c13095f4c63ee2718094c1932f55895be2227f9fb3a57cb0fa896a3aa3476bb7f5b7a384b73661fb2a69888d46a5b27806250173ecbc531");
            result.Add("is", "cf69e436bec1933780ea1d42f58530bf87cc70935251613d2c87da935fff8b86b3ee1107a82dea615f8032e753b290272dab7fbd058df779670dbd78ec5b11c4");
            result.Add("it", "d03aef372d82c571cc886a0a02e5ecaddfb498d9aeed34a4f0eeffcf50f57153cb118a9430af07ae2bbe5f331ecf77c8e4b1b54c0b5090657f7a613d6fb3232e");
            result.Add("ja", "5d9fc2eec6f9b0df09a4329719fb77f10fb35e93084da37c4bbf16e1fc6f5f27b4ff29901a4fe7d7376adb0ee0ab5f79ed0900d045b976aa8b4b988d506455a7");
            result.Add("ka", "23d7afb212b6150b7231d58b2577d4cf44b76d519218aea32fc0ff0c68f681dbcdcb22c6d765028da656ea9a2c5dbbe4e070f6424d52a24da2134a1284c825d4");
            result.Add("kab", "53d8cd1fb7fe691a77facb8a21ccf50afc1db16e0338847a1f43c4f3158cb54de92dad90e999d11a64e9ce58a0387aee2cb739bec8e876f2504efccb79f056b5");
            result.Add("kk", "9ec5a64a19baeeae5c804c28d57cb6b2723e4a7d3fde6d30d994a85eece514ab9c4b68f4d8d02d17d66520bfdbbb57fe9b0d91763c19fe5168f836be2b78afba");
            result.Add("ko", "54d3ca26c737406717fb9da40f793324441d5d8e5bf368fadfebf6e7379980fddaebf6872a5681e82867519c5c8d47f184c8d6705bcaf67e59fc64f90b4a80d5");
            result.Add("lt", "01dfbebdbc4c8db79e8964656aa4542568ff51fb2685c94458401bc51b032fcda767cd8b1878ddb9dc61e1ef53665c8d99d4f1548035231fb125ba71450dd108");
            result.Add("ms", "f00bd9a751b6974b4ec4e83b7706a9a80741fac4ccea9da0d150b3e115b09077b9765b4feb82ef8d0ad7d6a4985865327893bdbe360ac6307dde57fb67f2a76a");
            result.Add("nb-NO", "d93b4346e114c127518f22627de35ebe17d9e62fa9a5b2468e5e2acf28de585b5b14e7d6306ff14bee7f1e1885911bdc5482537193bd3c87b63cd47c9597dfd8");
            result.Add("nl", "5e81a34be6bc7926842cc59988099f233c91d8a399225040510b48553c03361c44b21f2797b3498902aaf22a56c74ef62806fbac160e0c0024a9116d97ed862b");
            result.Add("nn-NO", "83fde621680d662921195512f71a0bf64519492e5cb3bd562fb72c63d224b127f595998f1632474bcea0c1f6f7558e246b4a34e5b95e313f3c5b00159318c923");
            result.Add("pl", "977880da515c6cf0c67e3a461b032e39aaa5248fced758fe4668e706c81e57c2ff30703930ce31d12a3ded397f330229c90fd385b117480b09c8a2cbfec78641");
            result.Add("pt-BR", "f4011bf58dd7c585ea884c8f9081042b6e47810f15201b5a9b7612ce3a61db9250b7ca51743eaf0786a46c5383593defc21ad04c9bf5e2c14f439c9391c1e387");
            result.Add("pt-PT", "7d7b5897775fbc1ef8e12ad55d8800c79ee484b13eaae99ec4f5791736f7b8c41df76ce59e35adb084584ed26aa3112098c8115f775269ce7dc7824191b483a2");
            result.Add("rm", "e323e28f75e4a0cbb22f3b18907794ff539cc96822acc0060d9cc7fe05d4a8c7a06323a2a83e7699a398ffb1a824e6aa53607985048b9b493f1eb6076947b439");
            result.Add("ro", "1d7200c24837b34670ef9d8d883af1bbb8c1c1e2b499a3114a79230245a5f28f85dbf86001e08c72a168450a3323c428f3b2b5a00c9ccc834bd93f164c0df9b7");
            result.Add("ru", "c21aeef9190172aed153c39a79680eee5f4632cce471579a98629597be2765ef402247f6881186b093ab870ed68a2a5b9d5ed49b6f70441aaf2660ab4737fc6b");
            result.Add("si", "c5a47437ff50c8906f797eaf524dcf926400ff027bafe74ca01e64c08b652bd334370ec9aae3d66dbbc51c1c20e752924dcd090e9081e95e301251a593506612");
            result.Add("sk", "c46260b1c9c26c9e5b8f3ffa54bc8ccc08065f54285b1fbee97ed44c10009794bb531279c2f6423eb978c772a9589d01b6a69e1cf4d4d146a077835c9cec26c1");
            result.Add("sl", "402d656d1b6a1a537ea3d432f87c8733b707c3b29a8a1c01c280d127041209f6a77088ebf69cf7fdb92e99d39c45324bb3ebf7d8a242b872c833e8060620a369");
            result.Add("sq", "cbdf7f1d0e35a4b8cc9f4bd26e4d237c0c1148c80998cfc1caecbd695fb2ee2e8cc5cfeeddb023aa4a2c13ebff9cc10fcd74a3f6186805812fea525487c7f92e");
            result.Add("sr", "83fea365c370f7a839550aa11657a37527808fd48c4c3b329af2cdca5f711683248b85640f7f87673f27aecd493c227ae11e3dca5f1c59d6066fcf6770b971e8");
            result.Add("sv-SE", "d40ea83dacef7da32094dee3b3d13a219b1d59e56c309e3b0e7c122bec79ffac4d244f284d814511c310941dc827a5b1663e9c5b55514beb4961e7783601d1fa");
            result.Add("tr", "935e366a7640f89dffc786d3f2b5faaa6d0b379299dd5f540ef48a1c4c36482cfee00c02f949eb138fc13fde84ecee3a4d5a0eed9cc6e342091a087cc4877b52");
            result.Add("uk", "edcb23e698aaa410a9ac5e6cdb51ec2cc232fa46bef907e34bb3398ce9b432e7b17a99a25251f989bbd8ff9b7c9732334054558cff6f564b258d427dd29dd566");
            result.Add("uz", "568e4faa32518f05fa025f52ca5842f34f8469a090127447ff48468f5c1fad13b890c3e55fbea86c419cd93e90af8cda96ce66e703e56a0866b4eb1cf69bf7fa");
            result.Add("vi", "f76132d26aa801a236b41d30a66ffa9745d2335eb87451d332a083eb5b8539fd66b5717053a7d357b97817fde728d8be8aa54498873131ee39cb1bde9c125116");
            result.Add("zh-CN", "d15fcb11ca5057063532ea9147377e4a93fbccc3cb7e59cd7f5d211b8fb7e0a8b876c814911ac9b87d1f049d24a3ff2daa842ccd4295331bed7ccb9d84688fef");
            result.Add("zh-TW", "7c72c2183ea779a154639d049b3cceb560277bde1682fd05ee4719414eabda287610e926941afd4d59026d2b80e0c9203163549a85db2d6c26aa4f92f34a7e92");

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
            const string version = "68.9.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]+(\\.[0-9]+)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
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
