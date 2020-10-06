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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.3.1/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("af", "c85c5f0dd33ac93b05271378ed59f845a503383d724ee4f03194cbf09d4adfb09d859b401de621c82a4d0da32b5aebfb2439fb30217124b34c32d5e405b8612c");
            result.Add("ar", "f3e563e87c528536348ea7058e2f4be3c1c76ffdfd372d9272ffa8e448d36af2b0028236e0896b8ac6d7b9ca00091d19e32fa6588ac2562b3db6d02588edb90c");
            result.Add("ast", "2589efe8f203cdd600a2558b7a4b95da351996b09f8de4209497af0e15f1b2f780d8e588a37c7b30924ecc5c725a6007ead01f3b5b10ac4a725ea12a7b8ee0de");
            result.Add("be", "2aa668761d85730cf04710f6277522b1231c01cf1144ccc1932060c4d6a074a41b5f082d932ddd39f953e58d907e7b002db893b0048914c311707dd9a1a3130e");
            result.Add("bg", "38b27eb11917e73b18661b6ca5dce4cc1fa6dea7b7a6d8f629f8f6db7e36e001125c580f228fc4ed8c55eb39e49a21d8e04c77533a5636bdaa72420f3b59d8e9");
            result.Add("br", "4422672c215772104b2a09f6ded6b1c9643aa5ea1afd78c10edae88977540003aa23335d1b46596cb0b0f260d8a661fd33e294dc7b46d3d068506a6ac31e9be9");
            result.Add("ca", "ff6d7fd1a6907f712d2890c3f71072c4cdc6f93a8e68862deefcf4b0b2ecdb49f00b62146829bfe8dbeba97c2683813fdfeab18ab05a58628f8f4a4fbb267e73");
            result.Add("cak", "def9958b4cbe598657355150203efdb8a26253e88648f627d9db1ec6aa916bb50ca01bfad25d46058d762a9a1d4a3c181546c1fbb91a862996cffdcd706921cd");
            result.Add("cs", "2598d7806dfab081bdf3f29a7dfe606e86e919aef6164ce8d6b74767b50b32e4ddf37107256b8eb297c9aa778879962eb5e22b87c68343e10f99a46f21cdee25");
            result.Add("cy", "0bf6cbbc32082c566ecbc624c4a400d2fa2078a7c5dafebac9e39edbffda648f934de2551c112d4cc453f6119fc9f247311552519237558e755cdce174ed2188");
            result.Add("da", "c69760f698722a113beb771884a512652ef64d9067c2b436e6db3128defa33b6d3f68847f9713a6fe8e511917700460329de4110b3ad3ab1c672b5e7d165f834");
            result.Add("de", "fe895d7a5bfa3c64eb2a58077d34099f9c6d88ba0c16d8866760ac7f104fec53bfa0f05cab1fbebc5e52578106c7d7fde8a672401f2d830a5a8457cb0a796830");
            result.Add("dsb", "6492a2942ca6b71d79493f7fdd9b5984649dc7de1ef05619dd31e9484238457a2017b31ac2a8b8163d6afc7e72985c973afe2626a80f32d4b84dc437bbfa2fbb");
            result.Add("el", "b8746c20479d6e7d2094fb8d454ecaa0a4cfe0fd36afbbcd9425faaebad4a8b0842745fa2d52953bfc08893e3965de878fc99d5eed3920dfe1f593a84afe7a62");
            result.Add("en-CA", "64cc2bb657f4de1cdb912502100079430f33163c81591b17cd94936e527e6d3b904eea732eae5607d90d7d558dff6bac9c95a083d356d43ba5af822989bb96b3");
            result.Add("en-GB", "5dc3992c6b211297033c6e8a8cec94a637508ca753598421d7a68b94a8968aeb75f14af5f22d6839acdb74f3147439e77631897faca7fbec4e6ffb6a89bce8a8");
            result.Add("en-US", "c0e43a9960a63a8584992dbb5420518b4ec1c757b75a1d1701952f4daacf6159362cbd27db7e20c48d04d388d1bcbb7156b57bca6a05cd790868ad2a0311195c");
            result.Add("es-AR", "f3806ac83f693103880c57bddc2ff5727ab03afd7b9ba752f234d0fb91428e8b907fde26c13e51fbb74faf01bcd9fbde795848c84f81efa2b7545ef88cc5c799");
            result.Add("es-ES", "d091acc8389a7e468b6d9750a664fc769d661ac14f7eeea6b5ecb35b601c67bdc450188cbdfca3b9f301eff9e54f37ac93c2f7c2e599b9a08f1c257df82fb525");
            result.Add("et", "b53fe0157d02b4fdb8905f49e1af280394f5fa701db500ca822d0f4b585e9a738f4b1580dcd76c897cd441733adb811f797673f74e08a563585ea6d896217625");
            result.Add("eu", "083891dca93ef2f16b1e35801185774fed973df1dc46303ce19b5abbee7e321d993175a1cd53bac41eb77ffc855144910f8673a8dd5220d92a411e639febec67");
            result.Add("fa", "939bb586e7db734d708e4d74d30f97fc44d268c0afc09e895d7ccc791b702e27f5a72c62eb35e667f4a329787c674611506265096441647f7e3f58ee20c41757");
            result.Add("fi", "c2edf029df56195699a318f601612b20de2167c460cff843df06b119dbdce4322164706ffa7104471e35ae7a0d287eed51f029b092a5598f1c79a90f9341a596");
            result.Add("fr", "bc08f7bddb384355413d24489a0027f9b0a9e4e310976aece617d12e1605ebc276c66f396e0585cb614e0296118aefeef4a43755cd1d3692c9fbca3a8269f3fa");
            result.Add("fy-NL", "ff7f58cf21c52540edb0a8dc6c9149bd05b9d76f860bd57d13fc0c6d540c88b0be436d08e719707f5043ad4386dc73fc413c2f75b4c3c71405fada4ae2e24644");
            result.Add("ga-IE", "ab11d71dc42e883d094fd451d1688f7d6437e6cd728ff4726b3d2419e8b23ef72e2e813e4de1fcab2297466118fec59d8e490ae629e594ceea7ad3ca57023d6b");
            result.Add("gd", "ce7b5d942e2d6043f6a65f773836323b70df7cc232d32558d43e7485f66f29a3a04d01339fb9ba7523f78835bcd1166c2b773af184492c4d14dc522b12323c60");
            result.Add("gl", "b5ee692d0f4fa32f50ebf9c6b4c48b85e97e63f35a189d2b7222e2ea111341a5ce7ebe45090e06803f1dced8bb138236065dee77853cd9c052c08ae03e1be91d");
            result.Add("he", "4c7a081ed888f69465e3aa023e91451dd6e62e9112cc685a791dc37292e37e90e01351d26f82d9dd7d6a0e99e1f4e5b0d607e47e5c5a51a1d145ea6cb3a48453");
            result.Add("hr", "0bf14d1223862af5b4b74b1214f8f9a1d0c651c5c67d642079fc82559100dd58f80d0387bd286d5b839e9f6f0e011a025b2e648a082cbe0aabe3de8e02dee1eb");
            result.Add("hsb", "2beade795fbee51d2eb12b4c737f370b623b82d211aed91b17f11b1f85290ef68a69c9cfdf141c00ca7299c81fd1afd81848007534889975e3402a91f72e67e3");
            result.Add("hu", "07730935eafb5a15921a3dcbb3edf992a7c8c885612f8df93e9d14ee71086ea42b07c22c9d929649ea226c136352c022e8c440a07c5cd6cfb12b6f62c3f4c7db");
            result.Add("hy-AM", "645ede5c9f4fa1fd7b034a82806467abb83d32aa365e7183de3ae77a3db7f757bcc44395c57325bd0626c62c5d151d9f902ec6dc098ac305e5e2ba5e5ecd06ca");
            result.Add("id", "bffec2b0c1a2f51843b01b2af331f93bcda6461e2f63e6cf7490ac37e3fdbe2830cc7be23e69e1bba2bfb65e10564f1c942669d6fd66320ac49d1bdcfbd4fe30");
            result.Add("is", "7743b5f997addbd33ed2ccf43d446bf2d2389717d011ce6e9de4a6f31221a8b49a4fac2245315a2cbf42bd87614c44c3c7c9410fa95083955fe88eef603df4ab");
            result.Add("it", "060c6307183752b4b59e4449b58c1ddedcea3b009ef6ffdbdd221a721e697bb6652a993a0c5238f3f649c12cd4dc23aa99cc32f9b4ae2cc01b0c1257d4926a2b");
            result.Add("ja", "e7892077429597c226369055dfa575067564e017f9dc77e0152177a9d49750f06ec7ca52334e78d9cd4df3b97fb5e71d620caba6b90494a6d2d1d9d2bd1c05f5");
            result.Add("ka", "0e13f3291e0ed0ddfd99c3490c40f20c464a66423bc691c8a1235c1c95d8f1273dc07d2a42899ec66998356b638c7397dc712820e971ffbaddb37a65d89ca5d1");
            result.Add("kab", "1bb19884f588548cfafd7625789062da3c6b02c0ea01e56bd3eadcdfb2a97183b04240947cc5e93707fddd8087f2d8d76cfb75efd545f69f7b92834dc036f562");
            result.Add("kk", "daab998fe2ede7c5e5201a3952ac638ec87d36fe6cbdce0a57a23d70f285966eca1594c9ee036868a6e21b5e4c5deae3b58a637223e95123e3a4ad07d7ec58bc");
            result.Add("ko", "fa8d07f0baf9e60e23bd34184a29edea4ffa5720691eb2430af33157a1e149102699c5e4ff77d94b94c8285f91903618caa220c1e88ac6ebd65e92c18f3d3337");
            result.Add("lt", "1dc935ba2200f8fdaeaacfe1134ba2fb825c314f07055e37b051b1b9eb1068eaad82c28389b9511f6df0bfffea8bdc60f81ad54f442d9cd11f02889288f731e8");
            result.Add("ms", "4c971f693a35c475b56b4eee3bdba0bdad8a149c72cba9555ffbc0b6ce7e8bd4a85720d53f8ece7ba4a3ceee54312c3413927357d1f988ae6b2b8df6a6808e0b");
            result.Add("nb-NO", "7e11096d1a8d145ea3f56ab7192685de4d335a83a93ceff349d391856ed3861af4db91714a18b16f5b3a79a70a1acf9f7c4e1b0fc55a3f1b376a07df94457d7e");
            result.Add("nl", "ede1b75d316dc0dfcb0acc40b78a13376bd2f34a3d242021119e7b8f8f2fc9ad29dc30577441adc86946fff1fec5bbf110c22d2dce279e2b405ac8d24a211040");
            result.Add("nn-NO", "9daba2754349f39f38d9ce32ec1614a262dbfa4fb77ffcd137bf05d3aaf71d55b0fe241c1c004140e1381b186a454aec719e39c29e514d095bfcb5cfa9e1f42b");
            result.Add("pa-IN", "e5cac62d78d05d799e832b9d77d3b0dcf6ae4773c4354c2fb3aec675ec84ce7c5f05d9eea87ac2ff091796bf50ec91e0dd076cdac027a31632f3c670672ce8f9");
            result.Add("pl", "961d3b0d072f842a9f1a5c2cab2483c33229d56363330eabed274425cb6f613693d2300dd204bef9fa88017bd2809679d7bf2bf8841880ca15fe4a94e989c882");
            result.Add("pt-BR", "094bd5733a25055a0b711e33374a26040cdacc254644c8b7ba6901e025852a874673165f0200ecd0b8d3b88d69e16d559b41ddb4625709034f42e08623667df8");
            result.Add("pt-PT", "5347e8dbab261e4c94a64b2f29a1ac7146739cef2d952f6f9b7e59306bf1d9c811928c27f44304ef61a8f2a2670d16de234d43f9d8530a8a6c1a3a384b0ce6e5");
            result.Add("rm", "b804e8879f7b2c3301e93199914a08f3b8437b6a9c63d325709a1512fcb967e297bc1b68da3b46da73ffe3a155e02c437e414d76589e4821b6f8c636488a65bd");
            result.Add("ro", "5ed045a7f9b1c72718d9816157e15488322742b68a8d8f4b51ee295c5caf0a485ef244243296b03f0a495c250f218179a79b7c26c4cf8a1272484f0a923ccb06");
            result.Add("ru", "1d3585d2b0fdb0679957abd07ec0768f9a8c157a67026a545f05d098577fb294ee8aaa59b02766c600a181aad7cf00b1de69450652713a2e45dd340ba9cfef7e");
            result.Add("si", "7f7325c8d67cff9219fe47efe95200a1b50f2332bb421de3da4b97edac887bf50e4699398f8bbfaa6a9e7b17c4cbb033ecb6e894425a2b9c168e07bfe1af9615");
            result.Add("sk", "dfcc4ab37d56441ffb621e58965af927e9aa5d8646fd3e69fbc101406a368b134f808f8f620fd04464a6b54e5c2ae92f83f0d37f60dcdb245909dbc15634c117");
            result.Add("sl", "d732c802b1cc8c262bc5c7b8277858158a1ea8db20f47b79629d22abd2eef4ae1fbda61391015fa7aa1933207f2acf2c82b080722372b84ebce5f2cecaf3050a");
            result.Add("sq", "c0f2601255f7fb68013ed87d1bda3b4bb03f570cc11d7565686b901acbb5f6c1fa3027b12dec06fc116ac5cc42c00e5e53611766b9c295f2236f45bc66da13c2");
            result.Add("sr", "dec2cec5f2b670224b9f1f3a4bc97a05de84beadba31129915e9b8ae57f0697fb6c15a5f43ca03af0bacae7d75896534ef0c0900064a2a6f0fdd4b5fc977115d");
            result.Add("sv-SE", "ec845fb4c8573db7a496022c619098a45f4b0c120664fcafac77be6c9ca83abb2d2504e6d16dfc70d2090bc61afe863273e97521b7bec1f85f46e86fd2ca6623");
            result.Add("th", "2581287ee1b25562fd5068afcad227e1a14bebfc9b0315b4e804a24a68ac57c065773b650b64de7383419c6c3a2c233e17eb64cc44facdd32d0c850d177e9255");
            result.Add("tr", "06820b0adb2fd59b03135a705a0121bd47c27743eefe6f97cc503ed53fde9a56ffd0eeca1c3d81bcc90ab8efd38c1fcf24709c6c75b2268b56b1b9970b83fdb2");
            result.Add("uk", "5d4f625d047c3d3e23f5dfd4ca9c030297273b245bc7154188552cd9caf6016e49ae37cf0271ea91e1ee5292fd254cf06fb2e1dd2fd06ba31cb5ef00de2f43b7");
            result.Add("uz", "7ce064b8b80942cbdd2d1a651752acd34cc829b58a53426641dff7397b697d57dd7020047715a7fb41d47d4ca41376548769cd960577a429f8646f24644ccc10");
            result.Add("vi", "49097cf2b7f0dc2b7307ddac15da26242f9eb0418822ae4294489861ce9ea2ec4322cec9ab298069b8535a912a1e31ba94582e2987f55e4ffe447d0197fdd995");
            result.Add("zh-CN", "ce40b477fec32c46c9c161f46d1455de352d20ca1009b3e5a5d8a9a91983fb5ae7cd09eb093a3dcdd260934562e8cb9e5cc459e63277f59e8196dfbb8a2676ab");
            result.Add("zh-TW", "c3e471bffb6f746fb0fb8222010cda065b7b5dd4fdce38b6c01999504b62e465705204ed9c06b516d65853f4384e2c0652f245bff1086c3e88dbe3b9f258d09a");

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
            const string version = "78.3.1";
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
