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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.5.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "9912995e2cb8047cfa99e4ffa747897a8a1eeb66376c47da3c3d65bf473261aaa5a30a03104a5dccb537f851a693e392f03fb5a751a686d2a7a7a67699a1d1bf" },
                { "ar", "74381c796f85ec0a0eee7f5bf8e92e9e9959739718c96656c662fc0bc7247f2a823a3480877e5118e331e2e77c777ccc0dd4f2a29395a6313de142ca1f2dabcf" },
                { "ast", "6276cdd1ad5228e9e841bbf972b0afe806502cb330fa7e055d7b8d867c60cfaa2a5ba5b39558373feb297b8c3d6d8e37a64c2bf209b5f0c1ebba2a481f8679a6" },
                { "be", "4e52c927bf65f9ee3a513c8322eb6147a90f1795e576c7c7028ad834336014e2e812a47d218e268d0d5e4d4b126a77c959dbfac509bd38871a2a51e4a214ed8b" },
                { "bg", "5bb72ecdcc27cb8ec5ab67641b42eccffe7cf759eb588cbd29ee28dc41b1438b9f6e77a01af570881fb20a232d674d70290c9d8e6c5f72aec0fe9ec760c87f84" },
                { "br", "d908987d2468f6cfdf1bda48e424f5899b0ca5779695dc3a668c3e2b7311888d10c83d2e8908efa1ce1311ac96c7cbd2fdee4f500e48a07c42a7e0fd3606170b" },
                { "ca", "c1aaf6b8a1cd02a0472135ece219c5bd31e033e9af5691b1bd848aff9ac7a39612f1dd01e493de4cf67aab07569b7db0570628ba2bdb7e2f294d883154e6a44d" },
                { "cak", "4a3610f495c2b8793c9b2103033bc4636dafb91e9b6ee359373bca24cc333a2e4e02afa4fb1aaf6fae4615a3f6fbf17740d1c82100aa235aba2fad275476b151" },
                { "cs", "988e5db1797fc710179f8c56f13d57e92f8f7d3260c391c04ed6a29e7353dc1bdaa53f5660589320a9d237e9b68104e08d1f223f21e0ebe957d649cad80907ca" },
                { "cy", "522da3fa804c8a481312998dc2e42cd03d50e2da51095a4ee674fded42627e8cee4075ca66f6334ee98b1df26bc710c3ddac36bb282892bacc6a5779b8ca48f9" },
                { "da", "26a853550d443a1f046698ae973d4d62514c4a140679e4f2f3eb46524f6416473ccf3892267f5c03cac2966d4049b9440e342d236c5140ceee410e51861fc647" },
                { "de", "52e6c068e1c6152f10c103379ace09c911b039bb6ba2212204023cfcb8555f19cdf5780c389e76a34bfbaf41049549b436c6eee363fb131f5b7f7fba6d7ff810" },
                { "dsb", "6bff09195652721390c84b84a0b759f4c82ed23c39078fc19225a5d0ef1718339135b09118eeab8f8ec883e1fc86c7636ef9e0b45bf5f6bfc6161dc50f43eefe" },
                { "el", "df510439935980e02951995c18123984b795605d3a1f9880e7fbd2305b866eb6128cc9cf833ab2979284d13bd5bcb5f81164df60dd5acf34a7ab8c57b87ccfe3" },
                { "en-CA", "1230b08f030f4cd9752af9919d7313493564b0d65668440ad101df3604fbfb073f2f5cbf5662c7cda20eedf858763f7e1bfd4a9e5746e8d9e7c363923aa8eec4" },
                { "en-GB", "8f091e5a06ced42189df642c3f4ece78157d1271c6e02eb1a6b0dac164b01e18836cd9e068c715b29f0600cb378f17fb289863ac5f8fd667c97dc44f30ae4446" },
                { "en-US", "1474872dd8ab682c0753027605b2e6c87a1f45c5721306f282d023b87f6219377e75788b4e43d249d627092f8c6f814300a1b852b8e4c748b5abb6895cbfe66c" },
                { "es-AR", "335c3af5b32fe9ae21e3052f7dda8f307b7a67408dfaef719b155b3de2e6a4160fdcd725dd19421cdd6016890bc910ab42f4f9033b8ae0335ed8d1d45a853cd1" },
                { "es-ES", "48fd7b1134b94c8eab05a4c0aba564f1a359908f66638324c66ed4ad018e0c6f2839e334898c7f00bb6fe3d82dbec4b4b55dd7cf31e80c77262698aee83f0ed7" },
                { "et", "0bcbf140a1434e69a3f0360041a007ac94c97b4b569f9ea52ecd482e4957b7a85cd4722d3293a2ad09112a72ae67a173eb20270e9ab6f6a9a704733e4b4d6875" },
                { "eu", "bdf5ad1b4d0b23468c609acc90a272531d5bd5d878816aa3dd3f7202c2633d9ad49f5b7f46c4a9fc94e312f933c122a4e4a9fbe7fca20bea6c9969bfca6af7ae" },
                { "fa", "003dde9dc7b713f1423be956251551e3256e63997f132f66fd4ec5530ddbecd39602691e818b10fdb02adcfc12f7eb985819c5fc6e3166a0908059ea08855a12" },
                { "fi", "510f92b0db4618ea9d3164bdb7c971b7e25f7ea39d589c4a6f7bc334a9afbd474e0ab37113d8a43a2d00c606a8fd33a03fbc2ec9be2f42272d4db64a210be111" },
                { "fr", "71cf2372076b40e744717816267122831ee255a6c070e6f778761b8c6fd13c6e7f96376b2f5527a615e47af065a4d419add1246b83d61a198b1cd065fa56f41f" },
                { "fy-NL", "9558eb449ebf6fd75f2e8c1cc3d286313f22531f765210be7db94018f5e9e746db2706ecdb7fe70e6e7998983ae7eab799d203f209833d794213faa6a2d32d25" },
                { "ga-IE", "34e3204a7ac21a44b7f333297a2ec32f19a9353dd75f98fe4943b15cc3f784cec3aa9b090f266f9a06e1b6747d3d359eb12fa5dcf6900a755904c826184752b8" },
                { "gd", "fac7cac297c7adab3f19121a4baa33c52babe73e9f4501ab06a4419bc842ce4dd7683dae880fb188797e249d23d662eacfe8bde9885e5843973f57cfc92db16e" },
                { "gl", "6f2ee64affdc7bdeace852621331ad4dda8716391749ff8c0a25383db8809fb25ae62d72f9da5728dc6585ad5cb920fa452a77b5ea11b6f95dbf792c6f44a4fd" },
                { "he", "933ac9f87b9ac71f25db4afaf4bd6f82e69753c3cdabc484dc855908032a257fd50350e3f86d9e7dab39e702a58e0577958c7aae1228c6d2297b2a1829479936" },
                { "hr", "c2153c424c6a1200e2c69cb0e830d715128317e14fa0caeea2e9a0330676cc6c2afc7c2f565cce9689fb0b1909cb006b0875d912098d95e9ab57dc0f2f6348d1" },
                { "hsb", "b25b5f9859a33d6a620913826c08ceeeb7a1ccc026b5651819e2a8cb087e24d313fd1afa94b3c3e59fbe707eb465cbdfb20b366b3eccf6a52449b8da601113c2" },
                { "hu", "d4c3c182e6149c3f09e67594ba09805ef3197cbe82d1d392b1308f9cd4baeb858cde0435ca8428c62d107227509eb7181c2e65068c84685d0e22697f73683b56" },
                { "hy-AM", "1e71651089272a2a338ad2f0c6e96b93d6f43837a63aa7db138d1b03563a13f0d8bc6eedd4221e801cb102aad7ab9d1b03262d55e0b9bfc511050d9de4419ba5" },
                { "id", "af0f8b1ebe9dc3825dacc9f01c47f52e1e6215e43dd9abd86fa2e4b488a652796c4d100ae2ed489f73b6728ad6c30d915316578c4889983e52a3cb7dfba81246" },
                { "is", "01bc97e82e8c218cc2091a4ee60c7edc1ac46b38c71451920c49b948f1fce2c4b0a384f9c41bbdb1d856f78a5dc1e36a59b13085f4ca15003199fb55b5426afe" },
                { "it", "a9a4610d032804e4218b854af3be5535c9bceb410d02a0394ee06ac3e67b0e1768a5916f563dd8c7dcc6b9d5132ffc1140c8f4cdd7aa4a439363263f442ab8cb" },
                { "ja", "6163388b9bcc4f336fca4ba1f3db12dfccac64c67d2f34d11a7ed7cbcf4e572f4514eebc21242ca1eb94ba31551aae72fa1488ee2de411b09775939125000b03" },
                { "ka", "2b4274d548b71653c7737568f89f7f01c226d7cd5eafa84bc056ff49f03fdbc655ac6642cf5bd82ab9e1a26778e44f145736e4d2243bfa2f3499a9dcd899958a" },
                { "kab", "1be49217bec30dcce8a1cbd1bb81189d0bfe9a7bc15f9ff9752062196f74b42efb16e0a5b7a4f2ff7e3e5461d31f54e52b452f65da50af03fe40387fe7802522" },
                { "kk", "b2042af2646b294f8112c1ef057ebedcdff20ca4fbf17986309cd895d9dda4d18c0b8b6a54b0f78a5b91850fefa27bfd319f607ab0cda78c68620c54ebc9ef36" },
                { "ko", "3d1bfa32643880eaff4e6bb32132ad0d07cbfabeaa70383bb7c1a2f2a4a567df200521615777eed8547baec19e8642141becb2f1e5bf3c398843bb1f3b6ff068" },
                { "lt", "f5c1a0a333bb5ea0979f33e3575467166907a2b0a62214e54215f2d95e3945272e6356f9319e111b183dc621b281e3f65ee18a70348dca1d6a410165e1a7b004" },
                { "ms", "ab21e36647e03356d79bc7682b584715022f290ce296954371036fcad63692a86f64c97540bf89dd62e1b04ac22954a55f2c60a7b3216de5dce8fd7b880b3e6b" },
                { "nb-NO", "84d3aeb346628a19dd87c7799037fb1583729844e1bf86122a00982b90942d16db65d2a0ff18388ee4bb4165a73c66096db5ca6c2da2054c4e622bf5a6d8df2d" },
                { "nl", "f24db7dd2962d6ec357ee28ffc69617783badef87fd6ac0982d7a03021507b5b01ce1351921493009531db9530fdc5eecd4ece16fcc91b231b98365dd9000278" },
                { "nn-NO", "7f16e8bdbc9c8fb0dab5d488289fa6799c2fe09894c13f2cfee7b781bcc847279ae46383cd6fc9984f2884d271910df2e00ea0e66835ed5b931730688116e348" },
                { "pa-IN", "ac7e22079ce900c4d41f4fc21b3194fde0ad0523137aea75d12bdf6466574432e3aa02926aee64bfb35088a262be0b634e427cd64ab87a4ee46ee659269ba526" },
                { "pl", "4ab84cc29fd294a962e80d32bc311694b0bc24991bea0a2e113aeed807daf061523d77b8414e3d1a7225599346e2adcdd21875dbfdd6d4b26aebec6ebbac0722" },
                { "pt-BR", "fc0419e84fdde78c48a1db3569ffbb68e7091d3c32243627237e144397f6335a64775e76fba5d224627a3c527248f828ba0572f78b90a0db189fe8e7643cc9f8" },
                { "pt-PT", "1a9ac22ceffc80e2878fc303a2a02045deb6879e44e7e096f2bfe039bea981b1a7d62d0c885d7f02e328bdd35488eb70db1364c9525ea3199d6d2104cc286f92" },
                { "rm", "3fb92e075b0b5ac043aa77fa6963bd3c15480ca8772fcdbb792bb3637013fbb163a1a302cf31e0abd33f24f258677101c8c51c9b3d7b7cf54c1a60cb28eb6256" },
                { "ro", "b259fb9352bbafd0855c19782e96b54bcccdb362fc21500615e3577c69c14ee3c25b72e04cab7636baa80eb3cffa5ad0c94fa5e0508105836669951b1af5b0b6" },
                { "ru", "e18514117a0a92bb2c3579b529f9d8bb317f76199bf30557feea4c7373c9e7aa83b933c4c4a984ba1c5578af89aac29ec584bab891adb060fbe9a63a0e3746bc" },
                { "si", "0d976b2609b1ac18dede33b2c53a81e6c906c5535dd0b88cb91165e3aefca987ffef96338b328a85e804d90af7944ae8992d32f802940a24f0cc5d099dbf9bd5" },
                { "sk", "f92eedb3b1ef816b6b325e6efa98a489e1bfdfb304dec697f3c5f0f804c3ca0111c9866fc20107ebf5e6ef5bc5a07fd69f31365b2a3b81be655ae0190d991959" },
                { "sl", "5611fb0a0ade690ddb2bde8a2fad7ec9bd0f971328659785f28eb24629b8e3a07e3afbc54779ecf4f46bfbfd7a432d9bb3adea06777347dc7ddd1cf199dc1e29" },
                { "sq", "9ce77d0c4a2e0c51fc804d32d4a7f0afcf777f45d99c8f071eebcb1d9f39791d2c2f7d26f1c636f43bbe9d08239bbad3d7e916f4960f6410ba10d113134d3d9e" },
                { "sr", "6b96674a1705a0f111e7431a925ba1d5f2e8ee69e194e7caf68933959aa2067c80f8450deac9faf6b1e7d9590f52267d5e31d5338e54f48808b409320293e5c6" },
                { "sv-SE", "f1f133caf45cedaede914c28fed0e04d26032de8fd4bd5c8e723f20f06eb7c45bc2a6e76ad4734e448426b9cfe1046eff0ac5e70f74751d4bf55bd25fe076a46" },
                { "th", "cd7cdaa9c88092a2508d0172d85ee10b70313e1c87ac107e3ea9104f2efc003c48e9a16ec208b70532ef5c139d578eca84ce20487e4f0eefa41a163ecd68efcb" },
                { "tr", "bddea8d5ed291cdb928f3164cf9f0aa0de693b5d09e2e859f259e40bb31220dcbab65e65b8e6e4d81db53451e11adbf42d1a647731011512764989da3983216e" },
                { "uk", "4195d2796d9eac9dd71d9773e37c116f0b9aecefda61b6ce429c22365112f4fe60054ee816dd2c914b6b087220c257294170e124ee86bfb5c3111d6cfd1d96e3" },
                { "uz", "da1ff8011f57ec2bf2bb7e9a79ce86e516f491b8216c9f0e81f1293ce386a9a120b45ca4b0ed3a7ffe6c099ace42043c76e69790ef53c6f7a450925934d22040" },
                { "vi", "e56ed8cc43838f32347d0ce98ab5bc3df862e2e21cf31a05b23f25b8e8f19249c79937cef3186170b1f524afe9ac361e4e784e51e0dee30e73abe6248c329733" },
                { "zh-CN", "006d0ce087754dbadc62c2e2a7518fc548bd12aa0b6773ddf9acbe5018cbe7362794cedcf115851725626023e433f9daaaa0c0d893a3f54918b0d623bfde6e96" },
                { "zh-TW", "97bbd7befc49fcbbd795c810bdcdc9e25d9267b5781687fc69e3720eb62e955e2820dbe3a8fd8f490e9dcbba18d5af251d991590a0c4f9b8125ec15fd0dfb2b8" }
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
            const string version = "78.5.1";
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
