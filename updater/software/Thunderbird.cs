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
            // https://ftp.mozilla.org/pub/thunderbird/releases/60.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "4d7113b9979fe8a2fa8af3607092c2abb2336203369466fa6d5abfadba79c9d41ea9337aef1177f3e4d1df88b88e8e6a7136587fbc18c89345c0a0d545e2074f");
            result.Add("ast", "8ebcdf4af3337f8ab42bb74bc89679ad101f9df29bf3b31e0456e21c138408931d50e865ccbff3abab2c4d203f0897d4886c57e741a5f75ba66c37d1d80c5807");
            result.Add("be", "77e9f61c20329c165b18b39c12418b111f53856aab9415d5b7de6a28d263dbfcb4d3461349cb22788c378c5c04d0e09e02a822646ee6c76a04e407f76591958d");
            result.Add("bg", "ff8b161171cba1bef1a19af68923d872d9b70d636f87e21b17d5560fa7b21e81ef732c86a0b7db99c864e959f979a52941cd13d4d54f6463cc9d3557464e6166");
            result.Add("br", "7ab02ea548a0f7bcf4b8097141986d22d3cee257c9e8b546b524a25be0c29329f6c31c4bf7a7fb75843ec6d4e635aed66e1cc7267677357adb89ea220acc5bf5");
            result.Add("ca", "fe1f6078c1b091d4d1159fff14440290fd45ba187f72ec31a1bd8a0e665c25ae6f30c3b8423da2c6ac94c3e08eb919e8c574f679e137f2ea668d7bd8628cb1d6");
            result.Add("cs", "449a20d52bbbdab459f2f83518920b3cbb67fa6644a41d263ad003bd9f5ea84674573089bda9643ab1e4bbe25c76c4e212db8fb760607cc878e8dcd985bc40b1");
            result.Add("cy", "5127ff27bd6dadf0178d92a528cdf910b6c34b2d57564afb0c52db3f0bbc2eb9d36c765359a58ca1ff3485c9101ff9270f13e78628f47d4e853869820ee28e22");
            result.Add("da", "b6664a33175279f83840c68eaa5be1fdec2cb4013f0d91d8f7e456516b5216ee4dd41763bb935c009027802278b24e17f3ac2c43c9f22556f5e4180d4e3dd41f");
            result.Add("de", "50e40336b894f21191329d12a72ee8f198e99231f4d3d85d32b9e566945b327d057d0510c67444044de2b2c6d2440196d09486809fa58ef986636a5c4694ba3f");
            result.Add("dsb", "3ad902bfe9747a4de406c47e9a09e8fa82b014f06786db72dd825bc8e40e850c1f42f42cf66a6cd5a63f83808cfb2f46d18c85a5b06830682f13eef19739b3f5");
            result.Add("el", "78aadb002579289c2f5be623bef6e14761074f41b427d89a358628c86d4d67fde200020bc9741cd1aa8d0ba592ef3275d28283f706faeff682c34939b8ac081d");
            result.Add("en-GB", "cd6332f6c484a6b71c5b1e17603451592ff3659fee25e8c4c029d4ceb717088c43063994f327f6cd0246e8504618cd2c253c53b609720ef430ea458ce92cd838");
            result.Add("en-US", "03baab7bc1159ab3e21455e2faac89ee2e46eadf2317544d42e2755d93c97d9a605be093973fead493a3a36733953e68ed696f3244aa09b9a3828303bbcb57ff");
            result.Add("es-AR", "c02bbeba856aed3745d312f523a44e60df74b07a5ebc63d0364b405ae70b88503372d9515078415335c74b1d269f63d16238025579c4fab4d4454bb153c7dee2");
            result.Add("es-ES", "ff35e7b61e566eac806495b3ffe04587f5b043ecdd5a6aabb4f54893f99051984c4eaaa65a76ca1b3eb1dba7b75c8f50dcc884c61086ecad877c102f7b919334");
            result.Add("et", "e2d0721d793e4130fdb8fcf8a01022a5cd70bffe70714a601de48ab836d064f5a9a6c4d6d5c581218f14690a6db4a38c3f87536209a23b1234073483cb2c4c1d");
            result.Add("eu", "0419cd7490680cd99173344af2ea2ed1100bf2e0d26a6bd83b6910cbe98f6331bdee6a740830c6859d8acf6e3361dcf26cc89449249635335202de56b63ea241");
            result.Add("fi", "ae11728e81267169df046ea8626518d33d6b302bebcc05dc9b4b73c394fdc3b39db5e5d0bd78e1a87ad719045ca88e7b56993fe56d37085c3bd78be8d5de469c");
            result.Add("fr", "1126921ce1d2a3fb1164331adbe0fbacb1b8d26dbfc1646904001dd02eebbcac9c922d232abf652edec1064576cad680499052a8d6d6d4af5e0058ba6e51d847");
            result.Add("fy-NL", "8825e0f87f3099919893ff301fe1ac04303b17bf4b8241f9c1fa1616e3ec10d73ac43564fc2ca7bbd0d5aed4fd9c67de5098e5ca2e51cb22acc4c57c698a32fa");
            result.Add("ga-IE", "bec26bf7d0281842a0334123496743a5c79c380ecf92c77703d92dbf7dfe4f27fedd4301c65c322e8b108fed58b6bfc0a45dfe40d26927a2660d042a9c3387b7");
            result.Add("gd", "bb22e5ca38c545667c359ca0662628b68fda101935b78dfccef4d00f74dc349bb3b851d3287c89d1be52de3f5681213c5238463b55d66f9877a7cf0e102e2bf0");
            result.Add("gl", "772e39cfeb18c76513e3fc213cb9b28841d335b4c3c3f0ca07b6abf6e87a9b4a064f7801a90f9cdd6dccc5d0a58be2a51290c8cd226c2ba6d05376574eeb1c62");
            result.Add("he", "3401bd916157a126ddbf9cefde1da9b242fb0ea92be7a5a80ee6b95b49a094af3af5b57b6f3f20c68d3c4cbbae2832ef4d84c9a0b88da2a5a95bb48cbac6ab13");
            result.Add("hr", "d178ca59572f2e67999b712eed54c2dd9a64ff12dea2ba81f4c5e20e55a4731fc3650fb093042a3f8ac50465d79d51514a7ec98ca67174559b40d278acf64f6b");
            result.Add("hsb", "1d572aaf7a963aea9609d7e59b53a72d59be0748b6f3de121ce7034f8bec934145ddb274249c3714101600e06c9562e33ef5fd9ee37eef618793e15215ac95d0");
            result.Add("hu", "2f7c7ee6c518a65490b56dfeb20fa58484600c11410718ed7c61592fe62a8914cb7e5be1aeae310ee87c746138dcb8f22134a3391a2b6346c13bd66427eaf167");
            result.Add("hy-AM", "ae473a617337be9e1c74fb356f61e75450030cbcdd3b6ac05872bf06c088c8ae340b02f5e20240544d7264791ace9464beb09827b19c0d8629b16e791c5f4960");
            result.Add("id", "47f43c40fc242f1c364ccc2535862ee6aaa607c036df3529538e01fc276c2152cc7d3bbc457118d541d907956fcc9c7f2011f5450c50d9029495db3f532ff712");
            result.Add("is", "c4b4eafc70115d1f57e6220534f67fba15b8d8d5f445374e5553d2a31ec1fadceff2d3dbae38315d6f70b1b8f9675669e3291e3a893fc0eba539bdf4147e4e07");
            result.Add("it", "520d84b8f0be7d41b907617eb28bef7321455b69d99a182dfe7c285f85d4bdb3dfb202a5bd64eb815806a200dc3a157573cdb216f92be314cf759ee811a0bae6");
            result.Add("ja", "b1ef7dcba5388fb8c833486202700f5925b6e094ecea00b97fe069d16fed020e98f1773e76846fcbd8495e0a5cb761a9ceaf5c9aaff788d838e215ab5e37b5fe");
            result.Add("kab", "a9f2b58a088f9638d427f0e26cd5213d5924a9629f9ad582c5c5a816fc5e67d5ecaa6a5e8605abdc74bc42f0430ab5e10af3e17870e300ba39e25a9ee3184d44");
            result.Add("kk", "34e5d1f443d85ed17cbb23c12409041e2ac6707cda7b5366db74abdae240302ef5ae7fb19a6476593d3637b3b7568f7d8764db5f85c0b1b2d718d1f94b99359f");
            result.Add("ko", "bad4d85273fabdd35f1fd96a4e00316be9c4c76722c4a1fc58d281f1398abec68b7fd9350a8baefd8afd692adeef15e68eb4bb1650575be06c6f0255b1556647");
            result.Add("lt", "00a68c860010706f67a3702ef9df71c3832257fdb1ec90f69aa99555588a97b123216e5562ff11fd36fc297660ac0a3f3dc87c99345b3972e2edb9180e281e4d");
            result.Add("ms", "70276bf291f1ca2a99ef25fbb9683b1da9cfa6c576b65c278cd0fe7edd3337da9625ab16bad047347604a813d6bae06e62ae61510fbbc9c51f9e046b3ddfec1c");
            result.Add("nb-NO", "d5d0f669d801bd540222e71d47385a75cf3ffa0c7e85d077ea9d284168163fe436df9d140c32062344123ab9cf5772d78e577f557fbc951d4446e013f42b5cae");
            result.Add("nl", "b30e4b03f062f37ed646bde4fbd2eba86b5437077dd71bccb708d4d43be3a66f64e2ebbf0c993f55f8a7d219f6f1f671b77ac27281aae35368c21fabae554475");
            result.Add("nn-NO", "c9bfa03a2c58ee7e60c1114cc835f0406d580dde56d098a7a514d73dea0e5e69d9ba0dc9da9333dc8dc68ceb2c1d562a75b4a2f0d5677a9ac37be328dbe2f445");
            result.Add("pl", "ebf0f255aa3ccce74f9cbe72afde0232d3fd5d05edf69dfc14758684602cb20e3a084cfbb0aacbe8422be5c0d1cf8500d78c2ed1ac071474940ed4930ae7b1ab");
            result.Add("pt-BR", "f6944f73a452ddc7adf2618954a0cc7bf5153c90db4733ccdb4336c3ebe6ebed8b0a6537193cd0412183d4229b51f8e333c60e878532e7703c391be83065fd32");
            result.Add("pt-PT", "c8770ecfb1a91ac2404fcfbe04ba10f1d7ad9ae8a26b64b58b74ff61bceb8d55d20043cf340691df46411fcbce60700ad8a933f9d745a9ef1d0083dd2e255d4b");
            result.Add("rm", "42c59155d208916af8d84b0cedcfff0558b5aea364b16ed7a2c77c017e9a30faa90e30c185ecaeb0fd4a32a9884f8244d6c8d861ff731506dc63cb37b6f830fd");
            result.Add("ro", "7152472c595854ee98ac417661fbc1db7efa766928fe7fa688abad44a84a71098399a05220e8df15a8758aa2b11433432d24413a05379cc338898b84e2e2f140");
            result.Add("ru", "e8a0d6dea909fcf85b51621dde09d34e2174c0312f319da8bef08c3f43ebe7be6e35324d49a945e603e8980f1eed15cf53dd5861bd2c01c43616fea53ea31c78");
            result.Add("si", "4187294df733a711429568af680464261a00385001a358806e7e30fa2bdf8428c78dc9ccebe01af0811bfac79b87c94418b7c2e67b828f10df95c841bd847a69");
            result.Add("sk", "4aa96f31f2ac574c0aa54f1b1bf53fc1661e2cdf8637d2a494f1d638a58fefa87c077d4ab97c6cdd4af79961db88d2a9adafb9d6ce305947dde245420833e8ee");
            result.Add("sl", "24969b0b0f7a19e7e14f149f8c0da9844274be30627bef7853c0c4c4d19361b3a13864d3f133fa9d1bf50ccf5d3bb83e8727f8e5a2694a70ba7e0e483f399630");
            result.Add("sq", "cb3c1c47edfaf7317f388776588309aa7cf7179ddca8257584d4154ff4b01d808cdcbd604d9ca69d58235f25c48a33c0173fc3a4bb013e98ea20d5d181d4b626");
            result.Add("sr", "a55a4de3bc2815196814a9205cb2718f728c7f4c550f68fd613e4eb3510ac1daa1e4012f7a084e7c4ee5e30fa344b43284061913dc6aef7dfca370b8446efc97");
            result.Add("sv-SE", "66cc2687541cb8386fb76b8832528a0774692912086eb06d6e59cae4a51a6c7a48b20fc49373899f152655b617b1f3265b3967f833ab076b2679eac93d36b519");
            result.Add("tr", "6883fc7018466521c71a68f2732902a54618706feed8f924b97765bc736337a2e40cd7b3dd34eb63cee3f033ca63a48a7ae43f2350616c80ea101b81baa1c81d");
            result.Add("uk", "5e73d8c86e30684182ea9fe45d5fbb31ac4c7b34ba3368ae20dd66692e208b20fdde4b08bca1f4098fce0e9b4bd409d0b93778a8becc07bfca3222c270efb4ed");
            result.Add("vi", "6069cfda9762ce7274a0fe677f2dbbfb9792140d350f6bbc6752a581304a0426af5747887b7d6a75c6a62ed28f3d3974a176fd1f399838ea5b5aa2a3cf464214");
            result.Add("zh-CN", "4a2499de09b921ccfa83c3602646a4c3e46950362767b1c78e73c816955b85a96a73c13b928472a227f95d5f443f805651703263dfbd5379949d44b62ee9e1ff");
            result.Add("zh-TW", "7adb370375531329df19dfaf51a9a94b9062432337121fd9f22659d45afc09f577f60aab27c593850e150d06dda80528df7d20e463c0d0bedd80b59abd0c8803");

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
            const string version = "60.0";
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
