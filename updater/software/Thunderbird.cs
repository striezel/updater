/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/52.1.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "72db6cb1224a1e7aca2c5ce79417bb3aeb0f2a8b0396d3d3b5d91b7b150b0046d671a7770fc3dafab182805177d33ac9a1bd66486e89b904e139b9894d58bcc2");
            result.Add("ast", "4094b1928e955ccf5f6fb132d61d08e5d26bf85fb45d2a7d05a52655974677a446a49f268b4d91a45775f03dc4b1934017ea278c57c993411f211ad6e50ce501");
            result.Add("be", "d4ecffc1dca7a8f255f428114f0ba56965bd4cfffe3ed5ecc593a68773623b460168090cf4a4ba3a1a94d19671af0d1302d939cee7c71eeb4661a091f19016df");
            result.Add("bg", "8d3a33864530aedffbf29b4ef99802997679836b57b120eb1817b025a750f026c5a844e73823cd712d57e1eda7bdbcfbeb494899831d485918e2dbff40b5b4ea");
            result.Add("bn-BD", "5e7f3a812ba8a3dc655c32a1606798c52e25db18040c4d4a65593379eefd5e604fbda65aa6a290a2d85bec2e252be21a43325e2bd25925f27e7a72512ba1e976");
            result.Add("br", "89a41e2a1a7215b813b6af8ac2f32485db639d0c50c406741ed0ab7cf618dbe1c5830e4f83c0f186640b93702b0cd0531978d4faafae43cefb7563e328e7fc7d");
            result.Add("ca", "ad116800dafbf6227626f7612fd5af503a8dc892d11fd2ef488bcdb191939023e4f952a53fae058f38410b0c9e1317acc3f07f1cbe431b73d1de419873e0c101");
            result.Add("cs", "1af415377c16342eacd07702ba0c54671d2ccb40a496a9bcc193e83d953d547d9a40fac625d47ad27bd11b165b817864f5b29d33a1190b40216da4382514f1b0");
            result.Add("cy", "a55301bc3b1223954993721d14b56d8187507552dde72bdad281ddae8aaf87ac930b4ee8e5c1c97876b4069e5f2672b3a0e4b7f70bec1f430362bd6be7472fe6");
            result.Add("da", "925abf8efab7a28f4c378be1ffd5b1bd6e195ab8aeae5ed9a57da91ed208559f8c3d956bf9294c6931fe55d868f7841f51070271f4352ce7109113ee2187ab33");
            result.Add("de", "e25f7657cc3cdab70d16d42c935dd878126ff92ed42c89c5e12400782feae1772eb839d517896d315a52136210445d4becd2c12d566c18d8e179f32c0011d0b1");
            result.Add("dsb", "aa8b0d3249d7307104608f3b24b0b30c4012673967ffb7225d3ba686ffb6e71d090bb4a0da42585e86da3e5fa6bb96bab77f3f36881c7a1a089e1ab5339dc652");
            result.Add("el", "c2088bd24ac5cd97c4741d76e9bd0a675be1c3491c201535e9fab21fff6afed6e83be92543cea4d579ddf43d4345637b6a2c7874ca6e7214f5191db249c79dc5");
            result.Add("en-GB", "2fac15eb11dfbf1a61355d6a133decdab0a49e0dd9d7d28c60ea212a68af5fd50aa0d7af0b43f0ab350fa4ebcd70c897fd2d9c19d2c8c3245555cfe10f61bf21");
            result.Add("en-US", "212d577920685fc9050664c6fda29e43a8781f4305461003fa9aa9c97c0d6bf78fff16d402bebb43b974fd198a81844102759564a0c946d9118e966f1b357b29");
            result.Add("es-AR", "2564af53eb463b486afe66ff23ad9e5586a19d83566e4e1ca7d00abe9933f600fd0f3e2856ac73ea2aa070963085de1262aac5e2c2d77d7c0807b7285b2fdbcf");
            result.Add("es-ES", "d852b42861765a2fbdf8cab8b90cbcfa6d843afbaf18ed6929b705f0aa08f55adb6af5d5af6bd33ed5211b3b1ca58e0686afd13f310f4bb992d31af36c697af0");
            result.Add("et", "5d07cb92572c5c82cf7dd2540c65f8a4a8e7074fd6d2935f042b1fb9b2aed298c42e4f27a6dfad93eec18882c9bf278cded9ebf71847924a309362acc8d4053a");
            result.Add("eu", "3169b244806db87d4217f9c28e046f3c1fc020c239e502f1bc7b89b1d3d0d07efced8f3b1c4646e953cbd191f3e99f810042c5253e960a78777476accbd041b8");
            result.Add("fi", "0d434af87a6543500368ec8840f98f49c695ce99082857e758dfc1c97dbd3a9087b7ae1b37d5126b4efbc0ac96ee9c98058175a3fab8210e9ccfff62bc6080b8");
            result.Add("fr", "54a5de959ae564450afcf47866165ef9e1a50fbaebdd835dba23528ffd7857a6c3927cbbcb4212033b2455d7accaed6e53f295059488421d2b6ac25e561cd69f");
            result.Add("fy-NL", "e12b8f2bb83ba9e68585e226ef941b87504c0f1f7555c5436a22e3a194d44859be7714fac1ec396a0c7de23810a0dcaf4ef0a5bdee4d4a1f5c179fd6545389bb");
            result.Add("ga-IE", "d8ada0ddc72a0f4536039d88c560ba6db18836886d38a6edfbbd1caf6d20dabc6006b13971f844b1611c1a21ce83c9dda4df21785fe2051b775bc1c20b44ea4a");
            result.Add("gd", "210cb4ae4e8e448b9c7a5b89e3e9fc3d054feb29edd70f31562d61e3f7b6a12de1529af44906b27657f8b6fa05e77cbbac3270d5f1cb82464999894142d08467");
            result.Add("gl", "bb37f7d6cc28e884d45c59cbe6c94e15d245f675140de82f75fe9e9bb94d27a640ad25591302993082697afce56c452779704de8ce2bed7c61486ef83d0e90db");
            result.Add("he", "61d74c9a913998604d3b28a02d74377d5147bb809e88888f606eb0d18bbb3b17c91a6e0d66831a4b1838150e046c9ba2f9a0484442f1fc21ab63507f960d032d");
            result.Add("hr", "efb9c28958ff3e577eab34f9b9f5839f256fc0a0a2fcb0538f44b7c4dbcb732c11ac4beb74219796e394db1b6a74c81162090605b8171a6fdd0ec763e9ce4c4e");
            result.Add("hsb", "f2369cb615278546a0ba19dbb6a3eea8865a6e7921c8f6c56a455094915f04c688e973bc7a3363abc9bcf73c8dcd51aabff39b65ab87ee53e524670bfb31a768");
            result.Add("hu", "7045d36e2795857e62eac7865400fa67bce6559ecfafa3686b7e606e11854bbdd6be8254762c965fb61ee7ff616f15923f15be7e91519c75684fbed87820656c");
            result.Add("hy-AM", "168747b8514762a52c9cd9b3af59c1c3a570e45ed99a5cee8b504c7de818c4d59020fc1c9ffe7e4fc9d94ea5d13089efaa1ad4151cf51d13be41d7c42833d984");
            result.Add("id", "7d66bf7f72d4242f9642c2452fbb331d00d694bd638e61453bf0e587d13384a4d0bd9318e893d1bc5d7408d387cff36b17b910755b93c0766ba9bcb694705a07");
            result.Add("is", "f4a9a086f814cff61f59d76d78c3af906f5cab106fbf88b77ce08497afb502a3e016b845edb97c90926b32f9ae8503ca61fa7baf39ab5f836e151a0d86abd573");
            result.Add("it", "22fbea657ab8f72f9d878a12c1aa22ae54546cf4cea386b63ba1e2bb5ae2e44a584ed04471e45e8a3fc44f33fc8a141d84f61181bdd066eca4537f0a3d5339c4");
            result.Add("ja", "4e8f2b2d5294646022510d8eed89b23c77bd1a55a30bc2b1d259b29192a63e2745e28c8e7e34b6f70967a6baa354768e482a2dd7fd4a577831be787b785c4562");
            result.Add("kab", "2eaf40ace58b020e0e2537a4c7d02aea7eb5e51c4a51c76d258fb90331b2672e84584d2013a0366fd3047a485a13908974826391246788291fea720fcf322f75");
            result.Add("ko", "b57aecb1691e449a35db789a75649667eaefb38d68295646ae9e2e9d1bf4c5524c13391fb01324a0028a07aada180506a43a51257ace2cab9a59c8234e85ada1");
            result.Add("lt", "71cbc22349f41edaaa73d35a898cad23fb8e0831a809d936d1f4415f8b25a1b1842e63214a965252b82f43d47d7af8433bc44c2697ad2954b0d6f642bd1acb81");
            result.Add("nb-NO", "8020129e5e2c4689daaa3959d8dcfd844bea4da188bdb2e96dc6988f754f1274c9ee3a63593fc799c33aca353a82e0e0732e7358d7e17622f6565d9b3e573fcb");
            result.Add("nl", "34e56f9dad5a5b7b74d0574e735f93fb1aa7be6480c8a3759ab791b7c9f83753b5faf611131be1aff18ec8f781ede4cf9d31b11892f92e2f6d3d8a1ae80a869c");
            result.Add("nn-NO", "1be2b9821280a941196ff2f1535cb02858df4090611f2282b4cc1a171a5f1797c5b329ff309c8b546371b83f9b964a5e463c5f62cf9e7ee3c85a05a0fd013281");
            result.Add("pa-IN", "53d68af202ce476bca9b6abaeabc120658ed95f942fcfd9fc7cf3a27dbb041bc18d5a0d92344480f20d30b5fd7ca74a2bbf4bb982ac7e906b697002ea425e5a5");
            result.Add("pl", "8c1418ea0a900b4a85bd1da2491c365d3e2757cc78efa91c9a50b25db71d413612a5605632f790c9aa3b8556e5fbc38cd75c4cef2450d4ae416ab0fb433ea877");
            result.Add("pt-BR", "6cf092d60b19f6cf292137924d2f87f94439342035b598b223bee3d96aaea6d13257d3ce3c3a073fc07259602a235d2a271ac269d3e7f72703de9434c3739cbd");
            result.Add("pt-PT", "d8ab448e39fe4ef27eac271fec7e4876d062826c79c280881baaef78f3e4c4fae9261a8fb262d636ff157a9c643167d6d07b90ca2ebfe94af1cdf186f7f2c541");
            result.Add("rm", "fe47e811b0a30670536ec1c3b455878f5c43188fa1567e6edd95401b9bc776e8bb3c9306ab56903345866c0ad7daecc0ad6050ba67be629c5391dc805e4e96c2");
            result.Add("ro", "761db4c108ae7a96a66ca849477cb313fc3fe4fffb7d1e7fee4e6f444e24f3b1911481241caa56089360ecaf33b0f39660477c2e4f686b92c16b816928a783ed");
            result.Add("ru", "5b291ef123c1a943b40bd45785a0bd8799f16a38b22583ad4eae8ee7a32f14eaa1508739a9278fc32965ab442a13c89d0cac50de73c7e680eef8444edd96c211");
            result.Add("si", "788bc19f4b13b130244e830cb15357961f7ee1f38a5fa4a6975a96bc73ede31b633a4f6743a09bdb4ef6ab042d72da58703227953c16a2e041e8bdf389f16d8e");
            result.Add("sk", "058d6b92aaae95350c6972af7620cbcfd9d59ba47300e19dae21f4b12c68889c71796f7df5c55e3a29035a4e5dc1f876a3657ed6db5ec18fad3bdadf9f8db832");
            result.Add("sl", "cd43a4294a45ca7b57b7dd037170fb08132f1f0bb9c2e8f01b6fb7581a03aeebde72f14d3d19180abb5e7e4889212cd90ffb1b8e3c9e17e5fbcffe1d0ad28511");
            result.Add("sq", "11986740e6d93295757cd610a6c704a23019b52af1c707a3834e5bd3a0f646fbab155260fb0a708f0a5f78552f8ce2880c5a789d7c5c243b3da2aafcad37770d");
            result.Add("sr", "8a64da1d9c0fc3a8b845ba955b1b69aefcb90bd9b6f1d50b493f32fd4556777fc7426782c25beec387623191f77c04495285f0591450346321c123b76eb10154");
            result.Add("sv-SE", "61b30b991ef41281f0f957d478693c0ff05f0498f7ab73938c5f4733ba6737b5047cfbc2e122959e26c5aa57c53e32357321d32a6f812cf5da0c4ca284123dbb");
            result.Add("ta-LK", "5ca2fa3a371c157df31e43a01520374eb792fdfa3e33702eefc4cb7f8b85003f2a077f7dfea86177f5792fc1dccc2e9770edd31a1d48a5900778242041af1b86");
            result.Add("tr", "ca9947879bbc1855fa4d41cf9f14a64ac2a9f812aa75772cffddefcc04dd72b7e2026444882fe57eb0b1b460b4d21a44c309e2255061cdd372480093fc5bba54");
            result.Add("uk", "84d959b564323adb1d30e52329e6663d1001e86864f4e01497b69423f6f270a7568ee716c37dfc2f284dff5c542422f0b2c98a2f443c9931ba6cd761c0203a0a");
            result.Add("vi", "88e621c98c79c8f217ac4c644e5b77b05e004951078cea6c8c4e6b3968b65218b9948d8ff75ee6292c49ee0f7c61577111a32669e624abee905516c9d77e5699");
            result.Add("zh-CN", "29588d9b401bce10ec8f56b17a28ba941d9fb4e83a8f0b65c018e907b0546d047549d1373572e59c310d9f41e3ef1d45af650ab78e04b42fe2c2ed388eea4ef1");
            result.Add("zh-TW", "1583afedbbaeb6822edcd6c115fe63a217b4f97afccce291c57bc55ebfdb7620a7e153e8f4bb5650f48e893d86c0514dd7740976ddff98437f516db0b93a6627");

            return result;
        }


        /// <summary>
        /// gets an enumerable collection of valid language codes
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums();
            return d.Keys;
        }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                "52.1.0",
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9]\\.[0-9] \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/52.1.0/win32/" + languageCode + "/Thunderbird%20Setup%2052.1.0.exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Thunderbird",
                    "C:\\Program Files (x86)\\Mozilla Thunderbird"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// list iof IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// tries to find the newest version number of Thunderbird
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestVersion()
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
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9]\\.[0-9]");
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
        /// tries to get the checksum of the newer version
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
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
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
            //replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksum;
            return currentInfo;
        }


        /// <summary>
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// whether or not a separate process must be run before the update
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
        /// returns a process that must be run before the update
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
            //uninstall previous version to avoid having two Thunderbird entries in control panel
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

    } //class
} //namespace
