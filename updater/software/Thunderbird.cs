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
            // https://ftp.mozilla.org/pub/thunderbird/releases/60.4.0/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ar", "10be70863ef73bc1e93ecc5e2f64c934752d39316f9f89036fde864e42f71826b88f4dc7079bbddd8fb4a0fe3b093a2825b7cdccc1f8af7d331245528167b4c8");
            result.Add("ast", "2c81b32fb5fcefac87170c98a288c3d3c368403b57bc835097be873e26f3c1dabbe3fcd79d3b6f53abc8ac69ae2c5707e3aa4ff2fffc4a938a4862fe29af0c0a");
            result.Add("be", "4ced6c86d86aceb1eda83e7989d7c7b32c7651ca164391dccf3b2a251d5468260ec85ad9fe9690c539d11fec584f3fe80837660c22f7852ec3c26a3bbcf6b347");
            result.Add("bg", "633fa9012b53563be6a8317abeae828eeb31542cc3b562e55b085d48a3065dfd7413c0feadbc6b32c2f1f5f1eecc30bb4fc22faee822f5184cc373b26645f335");
            result.Add("br", "c710a4d900b18deb180fc8983fafab79fbfe9af1358d4aaa0785e700d3b8c8079118beb360500bae3cf1624c5754a07e740f756bc4779ae5d21232cf939132f1");
            result.Add("ca", "3a6e0553ecbff3d0e0276f8af5580e7a27e0a8ae4335f0f4562dc469709fd528df6aa1c256c580274a574e8458d1becdce80ed49f4b7b0b18f88173d9cfd9ecf");
            result.Add("cs", "68969461197284e8099e0111ad82700065d85c3ad40cef9fe3e1e65228621c76407e903fe878673e3073e5e8afaa59484e349086fbc465ffe1ceb67d08e03ff7");
            result.Add("cy", "8b012774b4fa3d5b876501ee8a9c2e5680b6283d2e7847aa37599e09face3f54629f6b051f690554be35521c090885325db61dd2ae4e84217db88f1b42b0dd3d");
            result.Add("da", "8b15b8d53e9fdfe0c45256c46689370f7de3da05d76d06a6b15522214a2fd0d38fd57e5ea787a3719b2acb764d8108a50ed9823abe117ff3456f646a788cb671");
            result.Add("de", "3a1df91b41c04a7bc817d9ee65a08f2e68597f75fb27ae6300f2dcfb6dc03c88bb604ba4b95872b51e25a9a9bc639003c852103ba62b58840df80171f2804f4a");
            result.Add("dsb", "9f420948d1361a73a1551b684f66858e8cacf8d123e0914f623f64e7596c4486e5eac5687b36d9a8ec1a460e421415884babf5978f7738c57bd7e09945596b9b");
            result.Add("el", "842ffc50077c4b470c1178ac637558cb84672e04e33e0b330fa93fa037f7a156c0f4f13d32c50eed2f987adc9f7f01b3ba952c4de4cfa51e013c93e98efa4fa6");
            result.Add("en-GB", "87866fcf57fa437f1d70b727f25c8ab8bf883a65171d13f9d4bcecfa2c553426bd2c79cb0a2b98495b1df56f76cd956a4553c445a5e99e9427b91ddf63e143b1");
            result.Add("en-US", "69460afaeb974cb3dc3a981dc13d2f0fc09c1188e252562c840e519c7a0c0b2c5099d59aa1a927e4c88b225fa7bbdaae483c0f0e43644619c2c3c182933c9947");
            result.Add("es-AR", "59d40734813669d47e0c6bb16037cc107770bd813f7a0e48a769045fc25f8c387164553b2e3ce0b8cbebadaa9d6db45ba891071bf57d8b74d93e574f2641983c");
            result.Add("es-ES", "01b8278ee92fab3da196d06a7405a0b782c29afc872dfb0bf0ed5a14c2fc89d38731657f2428a0f0d7072b4086d53ea61f61acdecdfdeb9832ac3632e4ed270b");
            result.Add("et", "4084041878244ea6bba6cd21282eb0f0eb37073db5bcdd13b5ad5c1ee6202ddc7189bbce4aa126715bfbc20579ef5fbe543df50a20b944cc81bb4a74a9455d0e");
            result.Add("eu", "18b3cc9ce7cc89924cfc591bb91adcca15620ead40a2af4675e3246cfc28c70ea25ccbcae51d24209644dfa001e21ef9e9d11bdcae3aa2a063f27695c9a1be1e");
            result.Add("fi", "4114599e9aaf8fe7bc587e30452bdcaad9b9f5b81281a87d33f40e400ddc5de30a22d17e565f2aeee999136c8d9ff6a284f4a078ebc3705b85fda1544bf13ab2");
            result.Add("fr", "ca4a43722b09cdb72449f6226c1a7799e0fbc1214aefb7061c455ddb8a3ed6d8e4cdbe2ba2f8b65a27475bde977216a0f1a39473f6912e6ded545e4d74173cde");
            result.Add("fy-NL", "d6417d0239d166b41b79a6722ecf89a13b07be54a55bba75ad173e2298149dca06a6b6822d162c6ee65efeda1461066c360bfd6edc04bdba2a04b350390700e8");
            result.Add("ga-IE", "21e6cc35c4a9185911c969f1cf9777afe81284aaf14bef9b9e57b757eeac3f4b4435b47dca014ed2dbac3deeeae4139f06438fb2c589c8cfc13994f16a052272");
            result.Add("gd", "ace76ffc1d8e85d7e6ca78c9675de45944a3c32717c5d68d008e8448670c3dc7d16dd4ac95f3daf0a37ed06f3e3452820b57ac6c0af374f70e3b0206dcefc8bc");
            result.Add("gl", "70d7437c45f4cddd31b6ae8326ece990955163febbcb909f583cefcfd9e93404eefa2b2eb326150e22808fdca1ef135e156b6e7b95d3f42b47b1ba35082530c9");
            result.Add("he", "13d141eb335268afa065801929ceccd71c07b73e68ab38edc5a210b2fbc24df4fb8bb376c4013e9800669b4efba361b137d7d95b101acfb7382f3408753c7c11");
            result.Add("hr", "dcfbccc1bdf6bdb25dc620c0ff6063cb77e5de64f2be9208f05d4d7230741c0c63ccefd0c6c9e02ff25b298b8954c722fe06d1d438986f395955832666d9cc52");
            result.Add("hsb", "9e7a753599f4d8b0fbceef6705d13fc51b9a57fd110a1e6145f8a5292bf82276158a7f6348f0d3a5bef3c20790c020ac2f55992599fb673753fb780772102fbe");
            result.Add("hu", "ebab6746ff7d9b754af5ff0046e7dee417c1288a83bdba8c3699e4a340b4cd14897a892d1671b02722919a5f782fd9ff3a2c32ecabf51867e920352f102b638a");
            result.Add("hy-AM", "72ba5ce9cb72cf7618ddf4d92dc08595d0ffb51ed2a2a0d5c8f2c72ad6e121e5bc77a2788742564f93564d8116d945ba8171a9239bd104cf53eb6c13d137acf9");
            result.Add("id", "e730bb1fa193551a0285a752cca7c8167ec18bf0d795e370fb2701afcd3e0547885ff92872c1ae0a4b10bc613e043edb2353621d4b52609a674595324726c13d");
            result.Add("is", "2cf3a356a37999eeb7b784859046b11f421b451ff1db393e43bd7f15859e47146737dd8ea960fe427b1756c74f3f15de354ceec20d795bc49a3c573ca5266f45");
            result.Add("it", "ad95351437aabe11949fbe522e0ac96601b5c10916e953c022c070d8d8ccab466d1ad82976d097026bd912ee2cba2cb81020fea4d20ed11630e5e30084ded9e9");
            result.Add("ja", "d0cf9983cd094eae83c3c48e926442764e03f67f35cd824b77aaebf7b11ee123283cad630c2d3e296a409b8a8c05def3438d871480611bc9d5b23863bd903c8c");
            result.Add("kab", "0e4c689da997347efd9a8a5c4c8bdb8518178c5ded51fb1d10b46903f2dfb6f23c751b206af60f52ae7002e007beac55b9781f6f672fb0d60091e7a64c1cad16");
            result.Add("kk", "933d422c1147deee77d5ba047f82fd2c28433f1469f5e79e3e55390fb404237f5a910ea87a3894c623ab260dcd58d3deb7bfca233de929ac3dbd356048804a5f");
            result.Add("ko", "9ab97aa6e4ff07bfa004cfe45daa5cc3ea149c052c2bfbfd824bd3519d2e7e7b8d204da715896adb1587f6bb8361efd99dba3b90dd7989e417906477c23eef24");
            result.Add("lt", "ec778f4daa37938840e9a7ff1efbed82ad7e632379eea9c6a6f157e437f95b3a5bfff5adb0f50178602880d495598a0bc5ffd50c6830d8fe7aec077536681e97");
            result.Add("ms", "02d0cf256d7402b943882cc0afdacc13a63d3646bd58401beab5a1a99f85c624c63a0043f7d7f4bd5c39288f18fd921dea2d0bcd8aff735c213a7a09e1e815a8");
            result.Add("nb-NO", "affb4e8797c506b7fc94bc8e922b7d878a1f52e1deaff3ef02d2787c91fff0ccf1d6ebcf095d9f8e8b30ad7f0cd9a000f3a55a98ffd93a4f4eafdbd313b84af0");
            result.Add("nl", "6358fcbecf98c4f02da8b4010441b633c7ef66ec86032a142c8ccc3ec13d7b0058d7639184d51c15646e0399671d2303935757f7a095c0de4deece99c7c636f4");
            result.Add("nn-NO", "96273e0be50971536fcf42f1477af4dbc108122fb1fc630c4214fbcb3905f719e4da84e0e243322e2faf81993ae16fca9011591c1f5b419639250fee77bfd41d");
            result.Add("pl", "1cadf9b760684614c209010314bea0fddc6107ff1a266472981aaac6085df87d485a8032534590737f0e1629e96d815ac4d8d09ee3f484e9a7e8303de93ea76d");
            result.Add("pt-BR", "701ecb3814b9db5ce412a711880ddc9bf22e7c65084e722c1ceefd004a40307f8c2ff4beb92d66d9dcb2063900fd083e584574ad292af700c967180269189840");
            result.Add("pt-PT", "d10c3a9e9efbc458dadcb76f01ab7260aa6beebff09589710da379a24ecd58133f0ba1c022b2501d5971c49ef43cc92b0a38562f5020c88e086938b3934513aa");
            result.Add("rm", "ccd8c23feb6651efdfb079f66beadd1b0081ed0b160265ff9a71655ae9991baf020428d2965e673fae06ff8b225a5832ca545470244c91a575ba8676ba2dfa78");
            result.Add("ro", "180f0da45a9ecf072220a5e555b7098f6ce02afc5f371de72a8c52596002db9ae3d4b5070660231d04c7445fb9c6d242437e4d4bfc2c8ff63521b56ebfa59583");
            result.Add("ru", "1ad67c0a60a437051f77b9c828671816cb65c7944715af10826f805e80a46bcd6d6695e1d95689c03d9ee1c6f5989dbe48d8b96d9ca233100144d426f2bbd384");
            result.Add("si", "b1cff748b043d6158800935d4fa82a1d032fb37817ad4ceceb44717ee2d9711945e80a45cb41a06eb7b9d36a9268fd073fbbf16625e5b4e0e43cb6f802e74e9e");
            result.Add("sk", "cc8c027faa6c5f50a5bca94f1b6bce608430a2a68af0cd4bb88918fd12ddabae8cabbf281ea275180e055da04ba6d66c617798c1ea685420bf1ede9fd0020930");
            result.Add("sl", "56ce2d71c034dd943146bd8957d617a01ec5b6f11a82e434e505299d272fe1616c0ce6d06441c23211dd46be2f692bf989e163351c50613f5198f3214621cd57");
            result.Add("sq", "ee10356cca73da9bbb0af642f41cfe907148b7bc6171928071cf58cdabe7470a16dcdaf2893b2e35d2043012d5e7356426d5d9aaa88489e3b083abb497427e07");
            result.Add("sr", "135e37cc859db6f90c165042fe63647e459840b90fb6e282e5e603ef4335aa3d8bc91ad1a6474e63fabc513e3d68dd32636d4882aa83f4ea5586731d486dcaa7");
            result.Add("sv-SE", "dad9ab47295f0f6687217fe0ecbac2ab5dd46ee3d724dc065771fee66777ef9ed7ee117c1e9e7952a153ccb5a43df3c76702f2aacbc22ea8bf4fe7d37273a404");
            result.Add("tr", "fae7598356fa1a43f1e8fd5e335863b62e712c04c5a5c1de392aba431ce5d97f6e82de59848a5e7264cda24a7fe4d95e2b319f355b9c96fc4f018889abb40cb3");
            result.Add("uk", "ef173a47e941acd80c992ccc3453cfc89bf2a49a7acaf252a8a4a1e74bcb133fe4b5a365e0a01bbebcd7be9effe45e2cf5386fca97dcb4946f12e41f1f60ad29");
            result.Add("vi", "7c1df52808c1ab207e26f477cc9ab79a7069e5c341d894200ff2c7579b9bb2a24e220cc6609d70b925deefa047e7c1586d4ce668a421cf7879f8151cf797c513");
            result.Add("zh-CN", "36418890b5a416ecc3d1addfd0deeb53727091fa2e842b196c66fca9eb97617bb031f3e894b88d11ab3a3029784c2f71cad7dab9369459fc8ad95c58e020e25a");
            result.Add("zh-TW", "85dff6a32bb82ca614f610c2cba894432a6b95171389547449c232f2f3c89fe96cc2d0742b1549614a3e55e1322e7afa5a98e3917c050b652969ed5672a149db");

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
            const string version = "60.4.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]{2}\\.[0-9](\\.[0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
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
