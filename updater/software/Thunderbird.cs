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
            // https://ftp.mozilla.org/pub/thunderbird/releases/68.2.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "6665f89d96370454068bc4377911ce1e3c336e70661f843468d209ee96f1e5d793195bb18471e48d552f432ecedbbb2d04b1eefeed80541694bb66f40247fbfe");
            result.Add("ast", "698e661910597eebab3ddbdd1bbfd66180d4d20a02e814b42d592071c430a6953e5131701d1e518f32f44eff2589d7d4c52759c74194bf3dc374c508eaae1d1f");
            result.Add("be", "6c639939f8571369d549a917c8223085f617f64e4b46263a61ee1a4d0d21793fd099b3fda2e5180872c91ed3b44535ecd063286067560378a63bcabf8f9aa73f");
            result.Add("bg", "6051340ae5f525b83a84b3725e8662ac75871f6464e772f374a57b3d74e501945d20bab17b8c78d5730243ece6fec06935b5354b9b3ef4ec339ab4fc365844e8");
            result.Add("br", "cfe555804797b23da8060a27d34553366565f454c3da35f63c01eec40973a1e51dcf7018170211e84210609308454c61e95499d771f2c4748ccfdaff488e49a2");
            result.Add("ca", "a4d65b1c581e3e3a54f5eec889ee36d061043fb775a732758019c51d5cb23537ef65c4352bb15e299f67a40e1043e2931d9cb61b70e5a42f1639a8e9573269b4");
            result.Add("cak", "4ebaa9caa6e228a073c2ba8a74f391696119ac19a9ad32e8e759805919e60df82d5119e4976fcc07039953ee948652048c5b80aed02e4f8efeb50fc60605e2dd");
            result.Add("cs", "021862a91721034c2a76d86280e87448b7c85ece0db2d986f4dc513138b3772137e5aefc1ff340fa99896ed1443454237528e1902e2334fa19b71a7861b7f352");
            result.Add("cy", "824138fd48cd383c28172659f9dd317f7c63ae465faa783f8108ae127e891b47d5f957d3e0a9e3754445c65a11f50ac55656832c62ea980b776aa1710887e449");
            result.Add("da", "10976e6ad3e73984c90c08ff3783df3c51012bc951d009a7becf558d97a32ed349f024159bb0ec60e97ef114e48200517e597d025e6a4a6bd0c894f7161aacc6");
            result.Add("de", "8bbd058be437945c7f4557b1f4e59107a57d96a67eb07619ff43ad3b09fab83fd5429f079de95ceb15709b41e4c72a08276501f1fa61a704205c9b1a362acbe7");
            result.Add("dsb", "2770495505251c5e71d8a5c3a86430036cbc453e0b2741e1404563af82e47ac2bf8bd32a815e083cb1b2792f0384ba96a98a08c515edcb7a215559bb3a295d0a");
            result.Add("el", "d57b3901c6178db0b86b6d70a8b2092e1f212b57b73036563d213f5006859914f6f1a7959f6f8440f7384189f6b6564f18f23efac00b40565f292ce48e28a71b");
            result.Add("en-GB", "6223cc918aa56937989fd4bbdf96163bdefc88afa465aebe6fd38b777d5772d81d9ea8ba51812091e6a483fe554aba0fc331719e5ff79c80f6817e6247a6fd26");
            result.Add("en-US", "62ede4039f94f34d69f420abc6de717a14ff820195811ce2db08cbfab6bb8b999205c69de2cf6cab8e1ffe7e811db7eb82711b5d90b1c6197d98ab515836e459");
            result.Add("es-AR", "33204d37d184d583ec09b6f503f9fdb663f67a0c8c8fde968f0f7efe92aabd79b056f543a953ae5cb88500187805dbc70c9e15a51a0e6c8cdb913a45d51090a7");
            result.Add("es-ES", "b10db5aceaef1e0397c292689f18b5a76afd195627f342c1365ca603e280c0210d5bcc0ed97a39a4aae9cf3ad8e050c907fef2d391d9542ee521108d756cdb58");
            result.Add("et", "4dd7a34c2d96dcad70f912c5f9353d5c6d8a7639bedb4168934829b7297c5b2f1794602595aa34d1ae4e328ef3beac7fff9190d6838d8df8071faa10a9c725ba");
            result.Add("eu", "597a9d981de7e9d48c44e9d11fcd6800b263163f086f5402c094202524c97fc561b4a69bcec604e220e454a2bc6d523755f97fc98423d5da1fd95a2b7b3e72e5");
            result.Add("fi", "7ef00e6f91a0160db985e0ea676edf6aee1040650e76bfde1f55ad6a7286e29b008c6237302d72587a1347dafe94a3b95bddae722ec08d7fe6ccf548fd5a0924");
            result.Add("fr", "584732fc9f731477457ba43ed79058d584ee277d2b4b0cff4b3a2203c06218b123361de15e6b8bc00e8552b9afb23863894bd99006e8028fbfc77b77dc4cd2f4");
            result.Add("fy-NL", "aefe8a9d1aa165fcf90c9281cbf16b15e99b16b3490ef39eb12bb05ae31a9eb8607e87172ae70fc8031946896895c3ba0bd285814d05520b1b8324a5315412ae");
            result.Add("ga-IE", "b66be1d1b9650cdc6151c4a2c682cd9bb0721c26a34afea166312ed34d0785edf9361fc32319f8f7dacb1b959e2335afdc61320194e0194ae1b6dac449501ba4");
            result.Add("gd", "47bb408bc70913ad3d73f3068e151bb93e7cd0b3f3d128657551ee8c3741ff5c19fa1d87401140bd737acbc8e030bf5f7a3f5b78b3611ffd43236882a3b968c4");
            result.Add("gl", "d785725ea3edff532dd8c9b857ff19637db566f3ad80ed6e641854aa1fdd2ece1abaaff3184ebe3ca6f6aec7a08376103cf4285d21eb936a79cd8d40c294cd90");
            result.Add("he", "771e3d4043737ecb796403ee6e6068800e5ba4dfd4a984ed5dec1f7d749ec0ba30d299c66bb3fd6aaa1ba77efa90f435e5eb250c767857d6f298b39324123c2b");
            result.Add("hr", "c1b38e1ec4fae1c691de9dd5b3b4ac3d57ff460fa5745e2c34639cc299e1ee85383288f61184050f5cb6f9d19a27afaafb7faa5f58f1105988d5a7b0999352fe");
            result.Add("hsb", "45c400902674e3d06c05e854aa580cd43daffc9879f2c3ac4ba4485c5d8ef81b0398a2430a99a24239154ddbaa702f712f0159f1bb41df40f2cab697a953e2b7");
            result.Add("hu", "0232516470df49478e5990aae319c51bf12518d34df459fdd170a115526fa755dd71d987fc410b4aae55b805a715a3ad956fc133b65729d6cc25b1c964156ac3");
            result.Add("hy-AM", "f9674047ffd1d7aab46b906738ad9bd96d596a47b044f34cd46a6b6b6e0dc2f349336cf8a46b2f5dd7340c18136a475c8c83d44cca2c9bf36377ca6aa5b83a02");
            result.Add("id", "843783986352a9ca60f6f5efe285665a145fda3836147d59ab0031184f614c440ddeea9da19cacf149f09b93ce390c29ed1332adef00cbf1dda069abe7bf1861");
            result.Add("is", "32558d7c174ddd9fd280b583410e486562999bd27c2ee4c122818099cd32105fa86fb057ac255697f114a945e388debbd2e649d912308dddbb4713c115c2d542");
            result.Add("it", "45d6347df93a314e1046de81694239e4bcb042fdf98d69fcc8fe4630c20c4d98250e559dcf39d7955f18a0f2d1212507eade5d1e3083d976c776075af4bf1ad2");
            result.Add("ja", "205d80aa9176c0e53a280a0f4c17de3aa5ae2303bd5865d4b2788597830ffde0989b751a43e8f66066486544b1d2db1314a55a734d1ab02b0f8b96551de4fbed");
            result.Add("ka", "350b8dbde68e7f767f2b2980f84a00023b0132ba0f31975894c1dd1f515d3e29bd12bc08f8decbf07fc15e6137b48a59d96f2faa681943e4b9fecfa3a7aaed33");
            result.Add("kab", "9acb5e38e5f503654efd7a74b8511768f5fbfbdf97d1f843c8fe6b5c6cea7c1942b07d4e55bd35d700518da595ff2758ddca834a6512c34b14ccb9c671fc2e8a");
            result.Add("kk", "919eebf2fbffb4e7607517776063f7a67d6a44e93fba7f7ed0b98034caea6816c29062662cb414de26c94906422f0b117892e55bf2a35a03eee7818ad1e07023");
            result.Add("ko", "c1da091e75a4339171643ef76dda5d35d00d51a58eaebb8243d08b6074cd16a250c2abb51d862ca977b36256ac9eb93ba6f903dda1e44dc775363b954e3d637c");
            result.Add("lt", "6c6150908ec4347d4761f57f139968d1aadbd96fc74e5b47fea78184a91ab73c1af1d3dd0d68b2e6e5b21d71c7b95320b2bfad1f7c0461c9e96424557e363c53");
            result.Add("ms", "2eb78c233e2275ac246edfdb728c63f0d493e60369a553e77078a88d7e82c96ba80ea44b8b9e7fbbcb3dbf317c2637ed97b0b7dcd6391b75eaeadccc379326e7");
            result.Add("nb-NO", "1c5986371d5758337e599c40d276ef4734b17239d73059eb54e40ed2031b176bc9013eb1e76b001fc86fa8a09e7918c033663f92905f4a766738ab08569f962a");
            result.Add("nl", "fa9232fb8ba12a37dc1d67e0b8f433ee471226f4a032b1299fea8c6b27f38ff61aa346ca57313c5b45e77ce1edf2c89fd2fd4932ddf44912ff2849e4777d7d69");
            result.Add("nn-NO", "089b63898960771cc9ba6a04869e4891e49035b716ad445bc3f64186f2150cc9fbfdf206de6688df4de420864eacf81c9e9c98c64b57e17a2ee9ad1c736394fc");
            result.Add("pl", "cf713a4343b379c9fe22c68aca4c4a17acbe9c29da8e4b646b51dbb1f21f08d389e76b64f8d73d004048f30ab5ba7705570d156f536e1b8d71f2cf4de64b563a");
            result.Add("pt-BR", "1dc193f8000c8759413a947db5cacd4e8e6704eee24efb7b0c5b93c240785cbf3a9b8714356af755dc87219e196918cff8b778f054e53e681cdae4ef1ee28dac");
            result.Add("pt-PT", "2bc7a17cdc6310c17ac668dfb9c0af29225d5821598605cfb7e0662d7b465e4eccb376be6692d51c349fe973e7794b12fa6c52abb70600d1dc042a4c495bd55c");
            result.Add("rm", "f30af9668ae22e73dec0130cdc7cd40db2b1dbae0dd306887335a9da975c01dc871e69e999f0e04e3e462d072d7a096f333e05a883434cd43f28544f6644a520");
            result.Add("ro", "64b5ee9162d940086159438ad063a13f34126cce3f6e8142fda351595c0c59679b74c45d3e05a1b8b4a17481e731bf8502314b734940f2fe2bdb28e7f6ba5daa");
            result.Add("ru", "597e062173be7ec67a89ad5ce39af136731855c629546fe6091c1d1a0a40aa340d6e3f50089113b268f5e13864a9495414d9b45167e0fe4a4e6da7cdd52a59bc");
            result.Add("si", "c873ec509e78938f8b9483f7fba4c38a6f9f61e75c268cdd0144cd2e1ac8a60c349aa29f628b9abd3c1e77adad9e9f1b8dd1ae25db2eb60a769b7c66f0361a0b");
            result.Add("sk", "fa7e88ec38f0899dfdb8493921a1da81be94db97acff975cda76bfce253bf507436157d02cba5b15c21541a2980ee71b11c601a80954bd740bcc187e03b63171");
            result.Add("sl", "29bc867c3249ec8213ac810fb0708ba877830461dc9f91edf2e5388c3ebef0dc12d79e7b3b06f39b22de63fdecbf32a4d2ee02272e6d621603570489819c88b1");
            result.Add("sq", "9a0bd8d05ae8889ed24ca19be29b854e84b453d917d058c0daa21db632e2dcc077133f2946a4574648ad6e2f900c9f9fd162f7f12cab71c9645694cbdcedda24");
            result.Add("sr", "f0ce3afd5f7c589aa97f70181e9c325f1462dfa840caed01bb2ad30754474dab694e968668ffcd16f5e094c8f70f5277b31dc90e52d0cc8f3f2e0860b72a8f9d");
            result.Add("sv-SE", "4d6dc3134e45f2c06d7d1df4aeeb1ec065b617c65107420e7bc45bc14ac9b8fc7be6a333779d25472776435b4a55aaa140df9847e112c4812fda3574e53d729a");
            result.Add("tr", "227b485180972aa8111c13e6cafce6c147c600109810d49692f4f22f14caae499c8612c1cf4c6ad136580519c5117e6a89e03b7785bf8dfea135bd88d87edde8");
            result.Add("uk", "600b01509c959bfd00a8d4a208c0f936abc7d196ad1474cd6744c75278c45dc7cfa031218698b1255be2c5a74139321ac6acc2860d084de5ec502acaa01a3697");
            result.Add("uz", "93a934570497ef05b683c4d51db15cbaa755ba47e7e262105f949493e317b9778bcf089ea7213dd94b899e60834179b9b5784869fd6379b0294a74013c880cbd");
            result.Add("vi", "6be9bc8d179efba648d8626f01d86017bb671d9648efdfe7b1132c6d082b16525229865b3d1dea047f2dcca9da797f09b60e7017a5cb4cc6f3832741015e8007");
            result.Add("zh-CN", "167c0fce28353fe523f916025f4ae2ec31b4ec0ee8309abdc77fe914339537c5d22319f1827e5778d3fae6100eeebcff3881f16ea9c9c9bb7c60058b42592875");
            result.Add("zh-TW", "1c43deca345c1d94258c5eb999d8d0e3adc0d876f560fa1a87850f33eb71478abef10af3ef3c4bed3c61ea2a36fa5378bc36aa53ba9df32efe743ca1eaaf33f2");

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
            const string version = "68.2.0";
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
