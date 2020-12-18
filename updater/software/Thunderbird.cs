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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.6.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "224050db2a5dc0888636c8e014aa10f4e7195a4db16805f2f4deb31ecc698629abacb34d3a15b286933c9ca57aae54ee762c5a0b1edcbd893397a1c0cddf88d8" },
                { "ar", "5299c328a78d20e42165d8eeaa9369787b33c6083ce417f5eb40f02b2c3a10cc1c9e72ea9bd711f8f129cefb659b0a8abeb6bd9007c6e1c14ba77dbcfc820782" },
                { "ast", "c9eafb50f9d66a8642ab2fe0453705d1ebfaae3dfbc32df5b575b45c422a01ec80213477a81d9432d470ad99c9a2d9e4afb9a1578b97ad650922aad9cd96ef95" },
                { "be", "54281dea1ee4c146ed9c400ca01ac826075441179603be01fc326401deb3227cc5b22e5b619332f901ce3bdd295c7c80fe5147f4ac1e6fc02a82ae38aa59f1ca" },
                { "bg", "5c889732219093578d9e65210e2d5dee498e7d1a1922a39efdf4495f0f21da7bc67d5b40c4ce5856a923d74cb91e4459d2726d32899427de8030947694448f9c" },
                { "br", "1520cc80ea147e5de9029d7c0ffd8f3fb6850a0c25d54bdcbb54acfe66b238e5d253200da09efc7e345011117f685b484680b65213712e3834f2d286cab3c34d" },
                { "ca", "94bbc05d67e70e3890a33d80b6ead4b1a37d09da477e23e22ae925227f038517dd4593bcbb59e212f3e6782f624b18040e52995dca5b81cfc16665e3c6270328" },
                { "cak", "d4ee78533b85e2f081d103b24986e81ca0ccbdacb362b10cd458fb2172b644d4321f5efc129720b2b50201a4868e81545cbf34d9ddce17164b22e38c0a41c291" },
                { "cs", "3d1726a70de304788d08c0c9e857187d99f41df210718b16f941094a660ce870c04e507d2a452dcbe19473d1bb5fc3e3ea47b2b84a722dafba734853b25d4930" },
                { "cy", "978478ffb313477944fdf02221ea9de0573c714952ad1d029dba85384f10de7ead60aa81c0095a914d58647e133cd417d269e95518cab6e919bffad350e80566" },
                { "da", "d75353552f0b5c8381ccd56ffca580b6f4629d958d77d4926558b96bf3333c4f27aec39a5853cc8daf456fb54d5fc3c0cb72c4b50c21cd75155e795a41f5d585" },
                { "de", "cf33a005e8f4eacc48aa7ccb417a76ff0dc74b0749a9d3f08854d99b5bf03f5c9885e0666348b3a7f19a5b33dc47b1e8f72ae27ac60d01c5414309e7c2d9806e" },
                { "dsb", "1de1708dea72a372fa702b71548b598d7f9c6615890b87f1bc4203c64f592246b5639c9dc5e8c7228e7a1fad65c4fe149892e6b5e811baec82adb6341f46a920" },
                { "el", "576a68f1bdebaf1bc0a15c0083ae5e7b58c2af3d7f4a677e473c3edae692ea0654631b812a86a233ef6b8ff0e6779fd1c09ca7bac62ec2faa69c12a01e5ddda1" },
                { "en-CA", "d63c9b97f33c66441caf2067873af8e0df037eec0934085bd78796892dbc18aefc92b50ccea2bce29c8996b0227010897950c83af5b7b252c2613366379da431" },
                { "en-GB", "69ff0e59075974fff68fb6f174bbf1223bfa181700e46d0c4bfb844cec4c4f5775335768786442e8435b5bfbf789b1c153edb39325993e2c7f94d6332dd0c6b5" },
                { "en-US", "45e6272e3a381b9633e0322fd4a42cd45c71782b7c6e403ae5aba72bd0e1dbc6421c89f43e975e39ea807fc409c3ecf0f26db43f0f058c3b672b4b58b951ef70" },
                { "es-AR", "23224eaac85538de098b0f664ae7bace2ef5a3515ecaee77b868fbe440ea56b922ea82050b5ffeaf93d9cf798f62e9761ecd82c0c336ca63a97ade2bd24d6831" },
                { "es-ES", "712afdc058463996833e4f02cd613dc1b4ceb120d5983660702964a46acc7d7070854024cf9b0a79d7582985306571893b5f1f8f47be65c5bfe45fb832f4b7a5" },
                { "et", "4dc83ac02dc2eec1c6dd59980c16575719c8630387a0fa6b536f451fb033defb06b305a30ab99652b66f569f041736c313d13f71bc7123eb709a034a87bdd03b" },
                { "eu", "9c863cb269b9a520ed0e067c0a2d67d22b3ce3094dcf5a69fdb889d0467476ba9c0ab842e458bd7e3f924cc344085e7b9e94cdb7a2d3cb8bd5e6a26245e974fe" },
                { "fa", "b12b6a6d8fe939878bbf6d1c187d629655588071a9bf679be76f8bd67b9b5bbc5191d1c71e606829e97863355edad9928bf222778fb8034ce5c2f6907c7a4e7f" },
                { "fi", "1a81e6ac1a9fdce59e70ca11dc0ab498eda4d445f0419bb495f19a95da9ab02146af3838d40cfab0d9750617102e6df1876969e61dcd73e730a05c2ff57df732" },
                { "fr", "b44917d64aeccd01e7a9fa212777af93ddebbe18605933b621134c82ae4ac36a6b5f27e7eddb4623d0aef5db583667472868122958d14bf752e53242eb946c20" },
                { "fy-NL", "e2c4c7ae3d8c3c319e10af933e0422a1302ec366e1bbd68f859afca2754979b7e016b361fb8454a864de5f3d5e1843817027d2318dff160e216e12b806088e74" },
                { "ga-IE", "7c1a6e67830f04b2148f9f5cd26608928dabc711c5dd965acfe94dbaca44b009f052fe1f03368abf7a52325c7060833f6fef42044c334f15117f6eece789172a" },
                { "gd", "762adb41248c980c2db60be34530774ad1547e58c7723f085db89ee12e5c365b19e03c4fc19aac8e3765ddb76cd7bd9476b44b217f5f526aba5ec6a15fa828de" },
                { "gl", "b9fe32059af06cd3cde7fc48bcf516c8b006b103eff36ad71cd823637996e673997972cb6575e06133c846bf37b164ffa8c0898b0d9c4f4ce7635cba4bcafaaa" },
                { "he", "f0fa094de51ecbdf0f6140b6b74bc03e0d6cbae2fd64dad9f7ea3123382d86ab54487ad98846c09e9e045d031095174a7ac744eb89d9486baf2bc5fb72bdf5c6" },
                { "hr", "7d213c4ec2d1fbf6bf8613b3411516f27994e01333527d1f92be8fde27c87c941a66dbd06752d2670622474244cb01343f61c952a7e10cad9cbad7213da30264" },
                { "hsb", "15b7aab72dd85027534ca006c58f1bf88e61d27ab775c09300c93968929df315d4f5c08963c38dca74668e0091224c5058c95041950f68e9c81c4e9eceb4a543" },
                { "hu", "d08c35e7da2ac5a16d6a548ee57a6f4b2ea2d81615772ff81735d89329c5f6e484e741156a6c767efa71e563c17c1266109bdcd661cec6c67e7c4d09c20c4504" },
                { "hy-AM", "ccf39ee85627f784ee5e4cab0fe959c44116cfa13ec646b57b6ab768e1f8cce3fde0664d2ba78159ebe1000ebb14bbf0d3693cd1cf75e5451293345b71291f5f" },
                { "id", "552c95b6c13039517bab7614246954317c79001f641d4ec62cec2811c9ded819ed0c69a52cee05b0c6a93066c49538e534e3c85e67943dae81865610ab5bbf18" },
                { "is", "1c2d8662fc29a438ec243153f964855e427f7b5d959c6a0e2a575bd020c5fe30e593d723724f8a19af8b30a168cdc07d56b33b3e29b573413f52dbc18839de6a" },
                { "it", "c823cf57bc9be83e59089f8279b4544f0499ca7c25b8d7cd4d30ee0f28797fafed7dc45404effba5702c09b74a17b8b5328fe50602a2cc6fcaf0e5f16c057411" },
                { "ja", "c571deaf971440a01b96c4c0997b2ff5526895f5d4193c35e452d1758ed3945b201a6a29c2b6760cce638b07c6370af7bf576b20874cbea73654b9ef137f8632" },
                { "ka", "c96a783102cf3e2e292753709f509192a06b11d8c41087ddcea2c561ca1ba3267a07c6710b82430af434ef1f4ba2917fb9f8492e57da6d30fac66c193c3aa949" },
                { "kab", "7998784bdc774e0c0b391c4a0cca4bd6d8e3190a1e3347b59d7839860fd4319faf7d1b335d59c73843a9f1d6bae64177143b5bc3ad609e8f3993d379ae8c5aab" },
                { "kk", "fd845082005f16085aa19946f0a95431f01efe1e14cd35cd7e47ec9300221dafd4913a862ec401092e60a8a9d5eabc5734ecac013ca36bf5415cd331e154129f" },
                { "ko", "7e6f487b6849ca7f5f28aa804e6bbf6beadc8655323a17745759da26aa36823cae178c8ad010f958a4e9d0b5635c3ec77bd7c46713cff93c374fa2b891cc81be" },
                { "lt", "16f1aaf5b723e5c4238c5b658bff03f2f90784dbcf938181a53ccba2cc6246594d0e67545c42b2b75f11e33136a9623db185c28b307a731c40b62785c3cc5fb4" },
                { "ms", "71327324736c3aa9c043f325d19cbb8f04adfbf8c8e38968071c7f641a298dbf0793540ae62688ba30cc092619e2bb17562078e2e3b0f786b5779d7899810743" },
                { "nb-NO", "f2b5e6c66bfbea4a630ccdb002e5144e6d9ec2ddf777769e0049d7c074f7772e5457aac18a1734a48595f88c26b5fe54de533b958813a136d478842f3f6fb0e2" },
                { "nl", "a584b6fdcf9d21875fee473d709e191d3d0277ad256d2a2921b4ab4d9aaf170e35141e7d66404d8daff7c2b44abe64c6fe470c0ddc480127e5da63be4692f12a" },
                { "nn-NO", "c3370367e65039a134e1f9e29f4b4eb0b640a2364d5685f0b217728b731648a14689a00083286b9f7a468699ea43fc786bc5c12d24a0134e058c1b02452c8050" },
                { "pa-IN", "5efb624ecfceede9b1618ac954c804b1211c26fa41933d4a90afca3f90269156c309fa4f4bb7c1c62c9de4a8905a86e8708fdcba887d704a86f935e88bc0338d" },
                { "pl", "da6f532172949d66fcf0d5b67f720e45bc18e96dd08863225b5f9cb88fa6b93b604f11df3da7f26892a2012ab403d8e9c26942b9fe509d1d7815673a82025a43" },
                { "pt-BR", "16effc72cc0695eb8414d46ae13378a6e82de7e225a6097b4d589b32cccce7fcd85356ad7ab7be5bff3b1e83197547e18dd8dedca89627cf1a35cbb4ff5715ad" },
                { "pt-PT", "b20fe99e9f8d3384856a1fd2b758a73df4a52126e07e9674700fb2823d458240ed6354ddd6741d94d29e9c6616060fd68207c10655194d7409bb2adc6f698892" },
                { "rm", "cd6d6a1d4f4c12f111df3e15253c7a56b6a77311965dd61d96f273a432c7bf0d0d66be88af1a9757414a7de888f694a97b2f3fc736f692455556f16d50d63a81" },
                { "ro", "3ea65bd1f37b66886423e1e68145d789bb29e7198a98b010adb1d83ddaab2fcc2be9113cf6d8aa6ea4f778121497b5d7e434284fcd887105824afd51dc114c60" },
                { "ru", "3c8cc80d2962c4a1363da66f28d6bfcc108ab3db082217d43819e423435d20a8bbe68524f01f70b848100c6916f506545a4f89ec5bdb9db170e512d50aaa4ac5" },
                { "si", "c94f3ec03111ef3f053ecc3a18d34ebaa8874c9bbb0c5d752dfc6fd3c754df8f9f294ad3f49c77c80733dc21027cf64339a9cb70da877c9f42dcf7ee6d11b960" },
                { "sk", "a98ff2d2c29347015dbe1816fe5d883fa8f32c57da2d42d85439caf5ae9e516291d1d709d7ef5827b6e370878fb4a0c72fa975c9cb74b2aff8143f0242cc545c" },
                { "sl", "cad0c57bc44fd715b074bcd084c5463d71bdc550e0027936fc898dc101228cf3429ab4bef1f905ee74dde53a30509b30423f918dd0e90ca3995ae70f45f5e1f8" },
                { "sq", "ce3a953e22f4be005b69530df1a8054591aef24ffcfb674de7e89efc4581fcb23bd3bb759f951e4c314e9e7be565ff4f28d1f0880a4ef9c8324086ca186a5110" },
                { "sr", "85e37ead76aeba0dbd6ecdae33a957d0976a460c70a55b55e1cf31b20b7f0469e0dd1efa969d033fdef6e09f1b870ee15d07034489ba0b131f4bcb80e2a49b7d" },
                { "sv-SE", "d34dbce5f9d4ab7ae2029aba5b7fbe6bb039325abe0579774e00193af884c96e8cd6a25e4c9c122f3d347f406763925977e55559b059ddfa26d9723bed4ff3a4" },
                { "th", "b032046545983e4bbfe2f86f39e5d4bd5c1df5b02ad24e0fe043922d6edabff81013f303e1b3b20521e78cfa4125fc12787e5437f341a2e531a18a30e07b1bd9" },
                { "tr", "bf4bbeb82661a3189c37d715f5f320752c3d48d3f1b7bf5473f598f64a1641ad1b6edbc9cd6758cc38c862484440ac370ac6e4e2c5be15c2ae36556a19d973bf" },
                { "uk", "e6018d66ea588917bfc6b3d0bb02e602661f5257198a633f204ba590eca80e1519e6660029dba975fe228c9ec0ecf02c37f44e466fbda5f60b72e70e5e6349a8" },
                { "uz", "9da24013c52e0adecc812407a21c356b2208b9ef18e61f1a85f14ff5159482e579f68178082aa124ef4ac38c722f818f679c93cf7536d7948b1cca3ed3cc3b04" },
                { "vi", "9d688d81a77ddf11ef1c260ad78891262aa305cc92b46f4b8defd43a802081782e7b7e8c5144b6a6b90a0a4bfdf8f974d587e10382c495177a040feee2e4d71f" },
                { "zh-CN", "44ff464b360de24a62b3ce4bf63cf0bab39ca68aebb7f73fd72647b37dd98bc3a048bdae50dc6307e752ac70265397ac96de2f8b7a1422ea135699a3468be431" },
                { "zh-TW", "21d37494de9a684d5dc875aa4f1486931bf39fc17d71191113892d38cbb10ff457003a4b67a6350121f73305a620964931a0208b7a3c2f09248fe0a56c6447bc" }
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
            const string version = "78.6.0";
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
