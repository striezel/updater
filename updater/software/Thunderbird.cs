/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.7.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "ce12ddb1b8cdefefa8792fd4a8bea0d59399693c9938c8d06950f60cc6b956eff5905f7669151897661123daeb837d0a17190541150fa166f82169ad199216d1" },
                { "ar", "33bb9f53f05c9bf33c3ab6ef68432603f9b5dfa51e7039cabf7721ed7408ca0923d4f601d1f13a4ffcf2cef233077581570fd2206e9751ef5418544f59721d29" },
                { "ast", "1366bf0c03ba7693fbff74784e841766de0b807ed7f8bb39a67cb7fa919a1e0dbe5c261874c5511b70882055ccdac8aca1bf6c551bc56afb6b0cb110f861af9f" },
                { "be", "d2741e99c7d05eabfbd9bc9b634a01015cee692d68223e3136f77b18a91cd81f5892baef4d64358548f276b3d36fd3ed12747f51abae953eafc500747eb72ee8" },
                { "bg", "93c03685ab360b4c5df4b5818056af25ed7b2c40dc8bada57dbc1650bdf52c2fc8f0a7cad279168a54420c66fbab5db9f1455d77f03130f47d3bd8b8161123d1" },
                { "br", "2061012298f57c280f15b4189ec6a51d1f225a93561f5063ea099d26ee30df082f61bd0f4131db03982b4dd288d560fafa16ed837be9b5f887450160d7316a5d" },
                { "ca", "13be85e8a3c63ca2a3e74d7df37b990c25f3cc9bb0ca007998301f808f98b7d3e6750904e3a4fd20d7e2a1809cec3a4924611037209331394d63ee7d7a36ffc2" },
                { "cak", "d2f7fab42f11d1470d7052fe71dbbccd8ae47729553942f120f14b836de89e4020191a3e4c1c9ee05a2e14eb9c71dc9409523df0a813e27d59ab41f3363fc4a9" },
                { "cs", "e6474833850b4ccbcb904cd95628e1e09b504517ff6f1a384a9e4896c763877fd5b824ad0974e5c041f27d207031679fb81428eae2283d997a452fdf17037bfa" },
                { "cy", "9487fc9776a5532b21bfcebc42ab2f13cf33d40f5cd8c6908e8e25be55fd1262779c7ddface73cc0ff1f1231fe3abee77762edf5cd9d15d371975de6df039e26" },
                { "da", "6b8e16fd5b95c216e6a8b62cad0c54fd2315ea20b272b8f4a973de1d1d15c709b557916f45e5695d9fcff249435fc2acd5122752656291babddebadf32c7a394" },
                { "de", "feaafe39feade2731c19031544cf4134c6b4a8f5934cd8d72a26421f4794d29b4cccd8711d6d5a25bdddd35323f6ad405f64bc08125f21cb642b0d4d371f3874" },
                { "dsb", "c2010a01fc1959026ada4e9b4f4a758c48d8e7cd3f0363f6fbf0d9d9f0dab70ef1a9f588b581799e6b05cf5926977e9b7304d5587decd128d58efe3efdc882b8" },
                { "el", "b42cdc34e6999bdb06a1e9982e24604b7cfe3ab9d583bde69578b7d89740ba8570f0fd922a2abfd71b9d17aa700bdef5c1a29e5aaba03b0129ef098d68e4681f" },
                { "en-CA", "d6571223f36137585982bc24148473ca3155c220cbbb5df51640a532d83bc8b057f285bd64b74c69c84967d67b998351632b350f9a6bfec2b511afd32e29f013" },
                { "en-GB", "c76e65ced170ae07a10be75ceda2549fb3b28b495de6b26b1898917f90e43241bcdf4343ebad1765d3951362977f34074d60882fb6d0cf3b72097611f8c0b2e0" },
                { "en-US", "98c51fcd641d28ab61fa02a38f1f7ccbe629a141cb55cffa9e709b1d29313efaa4b590f0e87f7ac173d6e43064a5999c653613e17e6731a2b7c0bc87f84a5dce" },
                { "es-AR", "bc2149dcdea59a46756fa089e40c165ee2713ff02bafacf48c794e5c8badaa95977b5d1326c0c1bf14dcb697f7d0842bf94e5dc00c45f95bbc7d53f53c653d11" },
                { "es-ES", "29a55e64bb42c4a354e898e5e8d145e0931b5960ac57314b442448f407541a3604a61a0fb1c762b79a07f2218f205e5df6c5d442d7d635d7aabce2532177b637" },
                { "et", "4c7ee162f6592baa35262bbc54103b190800c596ba1b3a7193cd7be569a511f33c7f361ce012b2cdf2baa672383569cffdd348df9bd88480083661858451eb3e" },
                { "eu", "6746e6b505625eada2884776d96e903e8c042f79df1d745a7150177836a43504d74051aa740af242398988be438be2f1a3d7b36c15cdad2ebb09c3d15e0c9dbf" },
                { "fa", "987a5b5a5014a58efba7109be9c90b1953f6d0caf8d7a53075bfa2ab6bd3e979f3bb3d0e3fcdfad7f9d3ae068a55ddb4071da7e1ac44baacf4825336c6c6c535" },
                { "fi", "4f56c91fa6f9168e313d73962b0c766eda76ddd5ada337ef4d4025661204011955f25613c11ebd068520caed38a482414ce71708e486a4518ca98ed54fbaf30d" },
                { "fr", "d8e19e4f89cadd214585219147135021ba33f86099400f064b90b5196f50f92f75ca2e565e97a64adb6b730783b4d98d8b3e2923c4bcdb44a638a97f951d1a3b" },
                { "fy-NL", "9ba4f6ecc4cb14289b29284d1414dae8925997e43a0b718e1f2f4e01a9d9c9d162fb951a129909e9853a92c63b8b0e5bb7425b30299d1cdc00f979fb6661aa4f" },
                { "ga-IE", "fc891be1d2057b56f9dae50cd9c46dbfb090d73841cb319da4b9d3ced6600061e1f88956e30d572c351eda78bfb473c6e730ec252365c1f50c7f89994c7788cb" },
                { "gd", "7763455696a6a815731021bcf420c0f18ac06bc1c0ca1fd5df6d12026cd46bd271a3e36a72ec354f98e64ceeacbbaf1b5ca65017dc7acc28162fca635dd7a6e6" },
                { "gl", "d7ff577a7769099f71483a048768bc691660f6578ed12000a02174912d6ddab22ca918f8c0987ce3489a8faf470f0c2c3a01d931e76c67af48eecec312e2748b" },
                { "he", "5a65e4ebe4bcaffd877ac64c5eabf8394584acde8ddbbce79f149455b2152142171562db1a17a60634736fe0c19c88839a0fa18f351a27c6560ac03ff6417fa2" },
                { "hr", "8abf331f677d84bce4a48a0602627226d343a4c5d269caee344a4919153d1ffb753db22ee548be260efce692421987e31385efa4eb02a32808b15c8b5f07284a" },
                { "hsb", "81ea3df34b84401b12704174392a5b282beca17043318128023b714789361b8189b4767e6ebd0340381d2055d6c644a8f2e6717e33cead4de3128be4e65e5d97" },
                { "hu", "249aed4b6806b60798c2503e937d0cd963aa75b5de706f7f6fca6ee35ac8da7ec5cf48b0b2a7d29065f11637ebf13c8a83393e975ec8a9c6811c95f33cdb881f" },
                { "hy-AM", "0d99acd03171a548c1d726247de27bff306ba348135b9700a993cfc7f2ee26b8d159cb81c49b26b46aca20ef7be84ea878bd9938ae2cf476f73a01c974e36749" },
                { "id", "3f7312b11fa4aef64d332eff3f930bc89f40730c38c477a0dbc67aed55aa3d0267efbf39c969db2e49e4cf11b9b4f431faf3babaf857e8a9fcaf56595af95732" },
                { "is", "9bee7d262cce78765a4f3c49178d55dd05ed613fa42de42dd3d070994543279be80fe511cc74e5ccbfc929407373bbe321d4f19672c59592ff76670a4a1a9f8a" },
                { "it", "015901fc5c8befbb4f547abe9b10ad013034d5efe679bfdce7ea55a0cebe205c9aa0c551b19e2d9f7c160d50e49967764eebf390d86adc1f12f70b31c2511475" },
                { "ja", "89946c2b136db961bf475d4c3592e430c284fc93107180d2d8b0ec255afdbbf805a9daf0ec187699fb2b3ca490d2c0898564c349c5fc42fdc7c5b9cc30c43946" },
                { "ka", "2b75239f29ced29e7380dec86eac951980a4db90f8dde43f4f16490d1ed39c65552e42c38a5414ab92467632dbaaac3f4e68e3df984d8d3b521f8b97a35b1724" },
                { "kab", "585936cad2db158410f742df07e8e4c0a478cd32f93cd0e66bf530c8547eda8c41aa19599c73e303b541fbd6e74bc92e8f85ee1877f9cc8c45a89e93fcec22cf" },
                { "kk", "33a818ba4c562bd8e8c7fde6ca5d61187851c07c90e2e8eb3e5bc8946af4a8678e3db75f3b5fa16d9a2f2cef435142a2efe66d81f0cbf883c488394f79a3edee" },
                { "ko", "bfffc83f78c9b1f1e9240646487228a8b54b8ce1edc5f43b43e91cf3c527b564784efae36ed16e54bd91afadf30942c1b229711315c44acfb12dcbed80c7fd1f" },
                { "lt", "6be40ca8d6ea6bffe01153331be9c8e52df1059eba5caf1cb0b8fa5adae4aed771517dd33507932e8f52ad41dba57500f1db59b68a8bf6589f225ce0289782c1" },
                { "ms", "3fab73d61d31317153287c6bf28e06d1c401b982838f276c67d3a8b05511d4d2b59637a8a72c60187a65f3493ac7ce72f2907ab8c3a7d456b614b0ba0c01102e" },
                { "nb-NO", "0b9ffc9bc8a41cb44479cb9ed233f84a3873a85abdffbd29c42310f52abd27ae0041a3ed74979cbfd96f4b01472b3fb082e84f2c6274e941bf6be89a3538e95a" },
                { "nl", "ad91ebdc7eba9057386eab563c46aca7abab96d002ae01d3ef6d815c0b4fa9d2a3de7c70396c0ecbc65e226d4585870e9d71cd083a4db743df90a9ca2c1b08e3" },
                { "nn-NO", "239f24d8e81058a25990a8b074ea7b1c821344336d8621e8e62c88613ac0309622f922938299f30f277e53951acb353546e398bd1f39271a512174dd60197b4e" },
                { "pa-IN", "ca993187507edc240dabb3bcad6b275c3d4020a526f19a0c36e018a236568ed75414ab2046e2524ed0fec46c3abfbbb5db1b44dea01f9ce3d47e580549cee34e" },
                { "pl", "72429722dd6bbd8ed7fc2264cf0b21ddb32437aa8633ea25437181b2d72d2dd963807f2705e355a80a04821fa4fbbb5cdc639656aafbb63dff908c1da8e3bd66" },
                { "pt-BR", "f9124c82f6ee98abc3baf6a0e15b7f10072f2b55bc1a3127b2c6ace04b5199db1d02f32b5f55516fba992f123baf5f601de4a41b58cafe2a710b2fec14def61d" },
                { "pt-PT", "313bec3d1309d569634d276a6d0a66401e49d18cb74693809fc5c6e6a2713a5e68a9f17eed5d288f3d1e698eb467a4bc0f0e65d367b7f6c724bcb1c800306acb" },
                { "rm", "a471a7445dae516da2f27d6480c21f0b98850fa2baece6200fc20cfecb40d05b744e59f3a3b1fdef6442da4cd27fc27252b7f74e6f6bdcdaf214b532df97b1e7" },
                { "ro", "a4f52685695770952bddfbc0948491ebdd3621520d2b4c2cb0b9e693fb7ecd3970f7ad6a77a8252ac9228a4c228daf174b01949755d3eef7f996a576508f1343" },
                { "ru", "ba990916f02aab614f1a1f73c9e6bd70533c4207e3b11e1914dbfcf7bcb63082d299705d8aa3da17e23983f3911b105bbdbef484edef027a70bd81e69699ec4d" },
                { "si", "e0d08a4f62b86e592880f9551498246dfbcf2fc53533cf5edf64b9363565be0a41fc8e25e8e8598040515e50ff699bf14203645440e6191522e647f3049af2b0" },
                { "sk", "f77cf385d57044effc6064bd2b6d5ce315fb1ae6d4872fd5cedbb3d43ba0abdef7f698e8af9f83b8f627000f312e7ee0dcf8e9b71b120263d51fd393fba98c40" },
                { "sl", "d65152dbdc7d27539300f978d6344fc7dbe8d3130b691f27a343aa79b075f21694a4d0230b497f646cec4dd2c5d16985d3b4352694d42cb822776f5d29e1e934" },
                { "sq", "06a6638c9f7bfa39042a7839b020655802a018cc5e673983c6b24ea2947a227fa7766b340b3dd1b0df35ca53e51d6734edead347772e9adfaf475dcea1089b2e" },
                { "sr", "ff262a28cd1d2ce784d2926c7f4c79da071665386bd47be97055bf54b018d757b5c32201926609e8ffccef9e98b7de4979f5af8b60f87aa661945ff59e341f87" },
                { "sv-SE", "7400d6c97142dba09e96a6f6b49cfb95f4445a59df3e25da114fa1ee3ddb97c0c13bb5e50de61ec26dbd5f2ad1f89ff9b153cb088a169713d28a4227b7534bfb" },
                { "th", "e890d628a5b302c4edff495331ee6d0ee26d0df2e067eb4930bc18538b933e3a06dbc3c6059d6fd456be04220e5790e4d68448b2935ffb3fe762eddb4aa438ab" },
                { "tr", "61bc13241b7a36d11c31657a0cd234d4fc3146a114c2e99ea87c28e6cdf7812d1508877c8679be0eaffa9dd8d1c78c014de5748e02421ccec72b4a24977e0603" },
                { "uk", "efe15508e046170c3a4363e71ef108ebb7939696892703c5effbe75e96548d29081de0cc61b1813dd1ff3f6a2fc7fdd58bd4e4d51931807f03dbe777e55f606f" },
                { "uz", "81f8ec20f2daf75f70c0943072a3fc9b49a1addd89504d518ee83f17151f5cdf4ea6d25ad7b7c2c3f798f51d022a14ae14c7afa854ef9a7f93f67d1b0553002c" },
                { "vi", "9baa8d9694c0de4d068592959bdda431024d4cf9aefd62a758d0e2767c0f08e38cf33e2b879f568ee970f405531a4ba14f7fa1ec0e3e3a0c3fc033e700053b20" },
                { "zh-CN", "664dfeb349ac5e07fccbd0c2c235be7df7ef7ec6b6dff921dd80725dd261322e87e5b1eec94a7fd332e29550f6832aa840f71179b5789bee9ed3db45bdd70f28" },
                { "zh-TW", "9bbf0a7196bd828ae7287516a6715a555db2152763b25221f823f6bdb1198ad43ef53f614b63abd16b4902fbbdbbda956f7adddbce0e7a057ed65fbd96c1e3a8" }
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
            const string version = "78.7.0";
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
