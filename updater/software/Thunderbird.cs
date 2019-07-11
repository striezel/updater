/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/thunderbird/releases/60.8.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "a8db145650f8fb20a6d14aa158926fbfbe8eb65e1457ce0e8c2318d4c814bc149aae567025e75adb1abef41bf460753581bfe0bf8fb8a61cdcb8cd26a286aca7");
            result.Add("ast", "b1904737f176c028a0d0e192b302b002d322bdbf639cc44db36e6bdc35577e417d922eddd54e66287dd6c04a944e3b0ddf4885748b0f65d9daed9d759bdfdca3");
            result.Add("be", "92aef50faacd147de670a4db625a790340e0bd155f403c3e0c5ba6c762bb107447fe0ccc26a15e39f07022f4760853d292afd54d8ce046fd8244d9a73e3282f9");
            result.Add("bg", "010a1c488cf233a1c8fd9012c795365758f163ae57a42fef25e05beaacf338637d7a018bf83d5f5b16600311cf3c78271a4d1de5f07771ae480dda6d1632a27d");
            result.Add("br", "98b035469ef95b0882207aab49551f9edbfd23ed1cd80f1caacf553510e5ee6aaf1160170e5f3a9c34eb240897be721a8ba074efcb674f44507c59ba319ab082");
            result.Add("ca", "6cce15e5a0b7a21dc7148e34095b73ee308aa1eb0c13947c9416bee33de2cfd9036c404004cd0a12fd26db303cd02c0ee0faae63a9f8f67258a20a6fa4b51aae");
            result.Add("cs", "70652ccd58fe9dc24cb4d8dfedb85f6db26b7ca5df5c5c32f780acb3b5f5d17bed4531e1df9f7324f72385918f05900fde947e11bbc444c01d2617f132200af4");
            result.Add("cy", "8fd18efe09a3c5478d8e3c8d9138a2c024c9164e2aba4f07f1ce94dc6deb46cf7c791a7ab4d610d7e7ea17130e23f3e1b971e0ea1c32c776e1efea6616c534f4");
            result.Add("da", "32601370664dffad03ccef58abe137739feda56e6081df6c9a1381ed99dda504a34d509b3007ad12d274866ede53ae2bb8da2471e1f7ac0beec8af6602944760");
            result.Add("de", "6e826c90299f8a4cd73543f3f4143a4523d3f1a631bb03a3f65d70e616b091e2bc2a17c0aea32c2cec7b6a8551e6f3b2256c9711f7ba10fdc4367387531d1af4");
            result.Add("dsb", "13b871cfda0f345d92b2cd44a43b6d31284d534de46999f2dbe763cf59d20d1ff57fe8924fcd72720f776f929cd7933ea9e976ce25187bc253004c17d3a43bfa");
            result.Add("el", "4e5de82e4d9464d1c628a3b8d4755d93cd9d05841c4f2b12322961060b248823c1226dab2ed506aef65606525716fe5ed62fba623be6a91056d895e50164032a");
            result.Add("en-GB", "b473ae0b6cbcf74b38000a60a5f786ecee7176a1a8e41199d7f01ac4bd8c001a77409f41324246a546f8bfcfb7904b9634eb6cdef6c2f69c7687f1f257f621f4");
            result.Add("en-US", "7f7e6395260831e426b3145f8dfed0816aa1671a7870c7aa9abb72ca4a0797ed2437134064aa9b21481913ce98a211d16c02cc1d7f42efcaa2f6efc4c533e74c");
            result.Add("es-AR", "c1f854311164ab34edce65e9127adc700424236965f7cc0782b7824bf13016c36fe4ccd0d5a13d59b09ad56413ccd8ce3fb72d7339a2883d1a561c0b237f55f3");
            result.Add("es-ES", "98bb0ae374ac3054608945695e127dd99ad1d4b5cffcac49d735b696b7ab6b4d2c438191e38a19af82c89582b4386ce532026f256c510a8743c7fcaa29f7410e");
            result.Add("et", "46425657aa95ca50f5bd7ed25562b0704c0c8565cded763a6ff49a444466dcbe1aba66eb2d4eb1a014edb06b3bc49cabe8f6b7c40f13b064ac04a6c392de34b6");
            result.Add("eu", "fffc43a1dd9c2df2f905fac04d75a1c4e685446cc546595bc399b95c650e38798f58b23a187cd20dabf29ec79b6caceedfcbbecf3af8d673f94c0a1ce1cfb3d4");
            result.Add("fi", "f6ddb3650403b38923b3e17e97a0f62551d03e7b8ec5cb710b538d9d2f0f8b1705fdbcff96ee7ce7e0c59d8358b5698ccaa86f0ca26bda64529c6dae4c8d9ff2");
            result.Add("fr", "a174e731e4c969278d65973fb0338aa028da5758b9694a8114d7f26ff35d4ae2c2912a4bf8c785688940362de8728863cff83c45f6dab6708649844ff5ee159d");
            result.Add("fy-NL", "fb9646a9b2b0b15b33d2bd5dbf800d2f1b969803d9f1a40d3d408a106286b6257b89b25761b58886a28e99a734123460994d7048b4261de6d5e2525526bc0b91");
            result.Add("ga-IE", "ebf6e094899dd203d32e23a8d4daffcc1fa6d29bf79b5177f7779d913357db2062d149bf685b31c68f48c55667c48d9b2adcd3cfa4c24b56c6bdf4d843d4253c");
            result.Add("gd", "00ea8ee6677fc5f5a252092f143da7f310e198f6305a2d1d4ea5a1d099b097607207ac58de147269cd3bc2b0c094b730b070f28373a4a29a53d63b80655449f9");
            result.Add("gl", "e2407227eaa693bf8c64fdefbacf3fbdb43379b717bc7a2a7bd754772f95b43cafa0d61484765a401b4bc79f1e2b3fe3a74189d5b161752432f401b6222377da");
            result.Add("he", "adc08e735e802f178789e4f7fd157523dd92700290d7a07a2dd7368816909ee724fc28702e49c023be02d17504c78dcbb8da9c705785edc5ea5b58c638fa51e3");
            result.Add("hr", "8a1417abf1fb80683934f79731c7ff96087f9bb46d7a17c008274b8eb47ddd1b57be9e2aa373fa81e7b220934fed17d1ac6eb7762fb8747cfd22f2129859ea1e");
            result.Add("hsb", "d6551d519c1c8e951c15b38c1aa4cf5b3604f47f074095ef507f540798a793751be7f75eeaff43a10fb95561bf6b847dd8dd46ce584139fc70fc311da3b6d945");
            result.Add("hu", "7af7947835b7b3206d7474d597ba03c147d4f59ad0e95846b4232cb1b5bc79c4701913823914e32b3fbd59b115bedd348155bd168839845d46882f8932c7f8ce");
            result.Add("hy-AM", "fe00139cb4ab063f313b5f59ef8527648dd81e43e92ac26cb9639916706577063d0b32f983a22a932a578d4870265601bf41ee4f010744bf080d3cd200aeba7e");
            result.Add("id", "0b1762f6c68b1a69227d6024259c51be76d22e1e1a32fd8f7dc59692cf33fa2de9ea0e7cd5019253996c3572e7df042ddae5d56d3cef1ba37104ab4b54fa7b58");
            result.Add("is", "10384df53c3eb7ac32561460bb54089ace488b4f5c0d1f2416d685afc45c96c8c1bd5d06c7b821a4a9f2bab1e938b05831a53b026950f1c4036786474441d140");
            result.Add("it", "045f299799b7d539efd0787ce9a2c0628fcd97b26f3aa164ef964e2a40b9ca8288a5a089b3b4d04878257d9acffcfd1db2cf4862b15b36549731fea0d75e281a");
            result.Add("ja", "4c260b7a464ac085d197f025371ca6985dbe75345761f36d3b4b097aa03c5f3682094218650d9b587ad9b72d283a1c323fd194916e4abf91cc779c39a0b9d5fc");
            result.Add("kab", "a41f5ae0da6ceb9653c01389320011d3a215d275a32509198bae21f9bd103c3aad0b7f568a8583a41991123170a1b92d639a62d5b18df6b595aa535fd0ca087a");
            result.Add("kk", "3fa5f585c8cca4d480305b4282582596bd7b6a30b6dbe0703a642255eda8c7746711ce834c8490a183d7096d7de0ab90e3593e306d55bd50b88ac642be4c8f29");
            result.Add("ko", "45517fed8ff9e424a0378c18bc96fd4b47b0235799d637569cd3a557e4083dc86b99054e745e58422b0b45b267e0021809663a05e4607bdd50a2511262a48b2b");
            result.Add("lt", "9d67cf012ccb4fae096a83c82612f4f2eb64691bed9ca5aa34bf46c244329d6248f20c9fa8a965b7720ff62e8fe7f94066f40ea578b4f41cf11669d0f378aaec");
            result.Add("ms", "b05ffba299f67f946e15044468159e433b9b4d44744a3057854abee3d4412909aaa1077e34e21591ad6d79d922e348afda26f314df12f793cd8e52fc22e7e82e");
            result.Add("nb-NO", "a8752672470338ed6b61b4b9312d44a94e2e0bb6f7cc03f0c5b695346ffd10e5b6403fbc89d0c8711becbf695355f4b13b6abea5bb7a4c02055da8fd2590b7cd");
            result.Add("nl", "8c900083545e2295d73ab26e11467b6fd8bc720112befe91f515863353a2b7a37fede453ce5d28e66255dc92208b5ff7467d1e0b0e553758b3094476a42ef866");
            result.Add("nn-NO", "b1cfcb2a6087248aac3eeac756805faca79e3df96b68dea4e567c03e39322f18ccdcbc14f9375a15d18f3add517356fcc27ced693645b78bd615f81f205bead1");
            result.Add("pl", "c344ee6dfe56c737bf9e2552c9129e329f0f100a465849ae3e67f489eb0cd27c3b5f0cf4fbeb00cabbc4cfb4b66ae1add53eda498a14e743c0b8f84ea8bb11e5");
            result.Add("pt-BR", "12ea147a718c187e6bcc3107eec55531ebfc4ced4870b977f6e9c2a74d173556be3a5879d8578ad4879262cc5bbbd05bb9b7538daebbd16b7435467b8714063b");
            result.Add("pt-PT", "9b9306367a3d3a4f87db2782e7ff1bf1c3d95327ce5287eb97b57f25c71cd93cc6cfc7a0dcfc683c99615ca18f4b699c9a2215143a8652b9f10c11238cef5d9e");
            result.Add("rm", "67492ef62eb15a00017cc2a9a04381f6cc3a9dea89bdf5a086fc31fc3740c16ff7e839f8fd7c29f69f6ac378810224afd362b8c67075ac60da5c7b2c12eb45e7");
            result.Add("ro", "f4d31e314274fdcf8c7724f341fec7735b0d1db1a98e2eb77101f2b85db10dc9351dd95650a071f4964156f6b56a61d301e7911828f2c32f379dcb43b74a8cc7");
            result.Add("ru", "e8bef020578a94f8e2744a77ddb2ba1295ab92c189cda3826c8d448d59f8d4fb7563b673bfd2ccc9113deb96b60081372f978bb155ac2eff89898d7b0ddc0234");
            result.Add("si", "dc680c2c5b660150346f6b41f8988bd7009f033918b8fef5c76456bd76a49cebeb74efb2762dfcac6122cbdc80eedaae50823a0d1183994e1e34958e4c02b5c3");
            result.Add("sk", "9b1a01814b9a00b11bce5d098a88f491d51a9f3e2dd9a6f42cfafbfb246d8c00c93289349177239d6c5dd14760eb1b7d27e423ff2e34e637358201de5629b823");
            result.Add("sl", "aefc31e11f0fc84e68cb212dff4380df4e1004ab2a27b5b0d00571c07b75fde4d0e8e14821e8a8e42a16c96c6e2030759520937cf7eacf22db64642777c93b4b");
            result.Add("sq", "a4a19c4010243509457f169c4f9a6c53233377c041639c4705e738ae3f46efbe1510fdb43fad3ac02d6ee5a82a034520b433e450a37504836e29f89024e6a3cf");
            result.Add("sr", "aaaa3c7b1edbad69004962ce93eb2cd01f23c5ca05a9e48475341bd2d37582a1b374ad3b61a87d677558c6872b182755f9cc65f9cf4e5cb11cee2482057f0331");
            result.Add("sv-SE", "cf91084bc39d3fe6b5738a95bb519948a5a661f1dc6e7fed4bd96d2886628b9800d6ca6a75de62f906435e733d62bc455e6d427cc592aca487acaf377fc3220b");
            result.Add("tr", "822e416288319f6038d37a205851e19742ebf3f534d4039d303e471db54b5a3d0431453c003c8e342e018266d9ab461ff0cfa190314bd397b1ee3a0b4b986234");
            result.Add("uk", "f3a946f90e3eb265da7a98c39c3e3daa7b375018aebf724c8fe634321789c2d88b36c825f2d9ef9712f58cb0dd036824e5907706197b7ab00cdad92b398d3fe2");
            result.Add("vi", "d623a3d8be1fab28d268f5b5f52a612e8df7c8dad07b950b11e158286336363ffd4d8b9955b94775810db6056c965a4adeb109319da6b6de39ad3f80c5911e29");
            result.Add("zh-CN", "274d4193274aa56b5e0d6c5069cef8563e47d77b9d24ecf08b2e1829c99bfee95f0ff65fc5cc3d11035b885326bd20b9507dbe85321c4afd4de35a7656d2bc0f");
            result.Add("zh-TW", "5722b1c5d37d7194453c9572480189509e6942763b75b5c0f5aac25d83c989cc299e07016bd00b983490831a0123e0e24c7b46326471a8be3c6e693a3c55dc7d");

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
            const string version = "60.8.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9](\\.[0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Release Engineering, O=Mozilla Corporation, L=Mountain View, S=California, C=US",
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
