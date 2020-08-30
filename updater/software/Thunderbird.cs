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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.2.1/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("af", "303513b0aa6b1f726ef3e0395878e0303c0b0bdf562887ede133851ed4a6fd5183ca4f5a9ffd86416cfc71aaf79398ee65726e324ae642381b64f6a82d7299a6");
            result.Add("ar", "fb1f284f97ba6267a7392aa7d7dc2ffacd78f35825ee20ea9810cb0e23fd6bd7099950e12f2731ee9bf7c138683812b6017ffbd36226951762d1269e812dc3b3");
            result.Add("ast", "69b4e279f62541e42893fcc3104da1040e64fc94b643c20a65cef859bd2aeb14fc60fe23b62018592d5db06e9ecf65adebd317eba33b627e41b0e79233b5ef40");
            result.Add("be", "62f865bd69bf80bef21965c47afff795a578730702588918ae30c6934f462617f31b00ffb34ddc32b6a31eb09cf06cb1d678659a229e3b7e9c915ab30d6261db");
            result.Add("bg", "7d4922862bc4bd47a7264e9f1c8f7adc6aa875e4cb7d907dbf05596100915eb5d9405c46cc1cc899bd9805b1b55dcc8f32967c6f4e4bb45f2113d41722502cf4");
            result.Add("br", "90399ffae9c3aa4d83bafa38b4c692999a619a8552f5c0446a64b1c79fefb660b0d1955b918bd04cc141ce07bb5e75b82aa1f06a040cad88e1892cd9fa00478e");
            result.Add("ca", "c5dde43333fc1f6c7a26a7be58702150b5dbd60cfc162cf1b56e5b2013faecb56cd386472e2158cce2f63a735ed1e0ddd06999b68808565550739e7e9a7e5963");
            result.Add("cak", "39711ef99f81f64c0541c9b1e7ddad889f6072ff9e2bf143a0003e343dfdd6f0826507b1ed2034c15114d0546db23f0853d326d20551024dbe0fb725544f7164");
            result.Add("cs", "ca389531893e299be4264a6208fb18ba738d0ef33340aaa13c739c8f9a9aefbfb9e8da81a92782814bb54e624b65232bd97ce57c61a5f694acb8ad971fd2f750");
            result.Add("cy", "f1e2c151fe3d80fd10709dd713b1e8d97f3fc9bf164107d39537f7571716ad3f0174884f158b7cf8f61957d1205a789bf339e3315b6b3a26f49fcd485b6836b0");
            result.Add("da", "fb9cdd8759f8844b027ae2bc965bae3b22e3e6fac7dae8090a367b5427e8f9116090309005bab465573f2f28e00ad617d1f7b2a6cc30319750ee52aecfea0452");
            result.Add("de", "6788291e8fb8a9dda5d569852750c3b070252654a4cb05a9fd0a239374a17a99c04afe8db54355c2bbbc5800087988678054557a2018d4fda9e5de049813d3c1");
            result.Add("dsb", "be9a0fd26a577b8f3e8099f49ea208d7488fe555a49df2e9e5a2d8245257c56897ccd5b6525ddb7a97c12adb53432efa288b7e13fc5a82a14376d33b6ae9868b");
            result.Add("el", "2ac8cee1019679817df0bdeea0d370da8df490e6636622e90f116310ba21253e6d3379396828f41ad858924c4afdd640645edb2a7641d26c6dc5d628e2af5db4");
            result.Add("en-CA", "674ac0457a533341d9e655747507412f0d639a8b08e48209ab3f2357eca692b2c67cfdd2f7645b3878de665dbe01aadd50bf3a6648046b4c5564ffaae4a7d594");
            result.Add("en-GB", "65b81ee7fd5e5ed762f40a4db19a116cac979e3f7dd40ea809f568256fa33f64d62ceff1610ae2505ebceb340e6bf8dd929ae678f274892255b502b4d5821945");
            result.Add("en-US", "e0cb8a95f4d6e9dcfaa5924a96eb37e83721f0eb84fc690016264de059a4b07db6f94817cc30fdc4d9a22bf0de866d00ffe765b9c46db31697116339622628ce");
            result.Add("es-AR", "53c0ab4a386169fc9df9434f62ec5337749b04fceb52c861fdf9096e7327524c232ad7a9b4da16c7722d8eedcbd03d02f1e9f942eabdf0cc4b293f164b628153");
            result.Add("es-ES", "4bb3bef14aae02a8fd70ae44be3d6415e15c1002e02796c17a3b1ca0cd6581a81887a0c368c5bdcc3d2b2eb5b865b46f2b46cb4aa9e7a90bb5d2a9016f3e97b9");
            result.Add("et", "1a85dc93b4bf40a242403d759fd7e464753a33f23df9129cf1f25d8ff6a011c6a18838550b2ca2db11c48cf4a79b024f862f6c2275710d90f3e5ae1d1a571c7d");
            result.Add("eu", "4e3fc03ef7ac0e98c52cfd60d47d0b259f4c9bd8a9c0da96e9375665dd33ee392b5245067806a50470681f18a1115d09492b1552e83cec0913726254dc5baf8f");
            result.Add("fa", "ae70b56686093d05458ae4024ed5ce1332fcfb73f36ef54c7d1f1e3f784793e7ea08e12ab1471188fe869b2c20641fdf3cffcd25320dd2c246fe3ae0d150742f");
            result.Add("fi", "1d3931d51296a341eb8b8fb7921b79b32840be966930545d1972c584f3fe92deab496fb30a07a3c71ee09f2040c80aed3ec1fac2fc47fc87d8488da45f9de1fb");
            result.Add("fr", "c45d2cafd722594a1d6a8ce054915fb09a35172eaa541e057b668af20e35630eb0164a181026c8feb64e6b54e615e3c6f37814fa30b1ce895f2f6cbc6408aaf6");
            result.Add("fy-NL", "2802ca3b6c015f347ed5f21885dc412f9870eb7b4e340e9f0bd42a36d8b00999403aeaf0f6f62608ca04490d0af047c7265e70130d9bbf98528cde7f2e62a24d");
            result.Add("ga-IE", "821d64fc062e200acd23321fffc5210f5f3cb0f0ad9042401c0fbe703454abc67f2303e90128e94483e4e0a03ba8f6c5f42eb781c65573d13b354dd829eb6e07");
            result.Add("gd", "7a1489c8fafc5485dc12a401f413b534a21501bab57e2a7832c87b607edddcec952922540e2615113480db7084ca4b97c5940d203bf5b83b8f1d5efa1fd4d72b");
            result.Add("gl", "24be80f6602b09eda5eeb58d7ea94ef2fce9b22fd2459e842a02db2036cee32acc022a0120580818afecf4e5d8b846ddab86ad87ec62acf9c17b037b766daa9a");
            result.Add("he", "d0803dd61eea4c7363becb7bbb95edf60161328a6dc57a65758daf4011d872c4aad291189ba928c224374b8bbb22c368e8d60406e27a94f05f5901c02af5710a");
            result.Add("hr", "ca76121a82d52946b1a855829e1084592daf0c8cb8ef3f42938f50a70a5a44cfc293d18fae29c24e72983957d64dee0629469bf0329285f11ee3f24c37c16e82");
            result.Add("hsb", "92917a6847b196e41dc2555abf06e651cb43704bbb7501d66a237b54183ccf56e51ac70bdd204944fd6091ed37058f1dcd517fd69f8c89de8d258753e0cb2d3f");
            result.Add("hu", "defd51fcbdc49ab9d6c61b2d89941acb782164f71462e371ec5f332e75dfea44b58ebd260f5e786054067acc042a0538c4bee59499a5944589c8861860d1775c");
            result.Add("hy-AM", "b8db47f7bbc1ce00cbd707fd8f3c7ad033dce718402597f7e1e6ab5289c675dda1890220563f0d7e465c583c17d584d0da741fe42eafe37fd6db35cdc2882d8a");
            result.Add("id", "bd4d3dac537f254ea17707da63c5e31f9f71d596e2e11cd385d0a1300a1b0247a52a4126a6da3d43a81a7ae9b7c9d85542053adca7ffc33058fc9a09453c4d89");
            result.Add("is", "33cc4a8548f3945e8af397986ec47efc8b6536919b8511685bdf6154024768de54b19560f631d28f111f11eee22d9bf159bd19c9f714c78c5c5e478d49560b3b");
            result.Add("it", "9df8ad4fd9fe448f51b4626843dc750d682c36a19bcacb06a485ee661572421125629a43777620963ee1a4953eb3a0a948c7ea9315ab48bbfdddfcc28138aed0");
            result.Add("ja", "3c9693c18932004acb757f6c3ee3350c0c59bfc6e3cb8b6ea744e5551df4cf05c75683d276dd1f1da3b9a6f417a4a62236d12f9c711f123b7aabf1b269dae1d4");
            result.Add("ka", "712f09575dba7aca5157125364351fcaf94d26e78d350bde41bf5212c13b0856ae046ae72d637f3e116d54e585b8226ba88c4dbb1b2e5fbc6e83f9d865344ec5");
            result.Add("kab", "f5662525a28c31ac41b109ba2a18c59aff8c6b597cb57486521bc258aa4141702068bafe02254ffbc20b84c9c54f86562a03bc2a7a1852265b91e52dadf66a31");
            result.Add("kk", "d17711bfe3d93f446b65ebbe35be38f9b252e8aab4d55e30d288860af0b10111c02bce6dc1808245e00c49f5284210fd2b541b1408f0cf95ba202eed773efe5c");
            result.Add("ko", "635d911029efa4df5aa8e072f59d8841dc45162beb529072d70943efda07a7acfbf0a0fcecb365e14584a5533401f71124f8fc6d16486a44a73efdc9d063b5f8");
            result.Add("lt", "273abe01add07586956176c33f54bae36585a5514ec7e9496069fd2517a37d7d358eaa92e8f54f539e5030cb1bc61ead65318830546af3ad70b1782482c20d02");
            result.Add("ms", "5537723a5e355468fde5fff7157c05a6e2cb70d2cb8c77e4f2bf5b9256f7adeef88bf27fbaf5654c6be3e1c3bb0febc620e66215142c056653a43393c4398655");
            result.Add("nb-NO", "1de71031950edc845b89f48efeb39a3b57e750b6f077256f7e0296ad5f4309c68548a7778c53abddb14068283b10eb2a6663b1721232e3ed47677cbead15e4bb");
            result.Add("nl", "da672a16313ff5cc8d1fc80adc8f81640e047bb32d6e57cd27c7a5ad616124da5ebf24ee1b9f772ebe9a84e9778e49acc517cc1da06ff821d735f8fe5bedaa2f");
            result.Add("nn-NO", "f96087e1af055645365d1aa6373f556fd5fadbc3e79c75a71ca12a0d08e7092f83aaec70ddb21b73552cb393e10ecaa6a7dad5a3c316945569a612ccfb50be21");
            result.Add("pa-IN", "c1314647819ad3eadb0ebbc22ca497b056d12d0ecef2366b4bdc7f91f78af601babbe975e8ebf1ba05c62e04172cd241257e91024d1693e1a74117eb9f0be4e6");
            result.Add("pl", "c33c3cc4f38906664590353b2fdf63ef8034d48772c51c5471f15991481ad58ba59af9bb747938f425ee52105adc64ebe79faf647bc926db16ea8fdb3d0225c8");
            result.Add("pt-BR", "55c65d9bae6d1a31eed646a3335f52503c44925ffc940f3b5ef03dfbb11fa5091484376a12f98c097038035a149791e1cc0deb67c0b3d7218bb08799f5fce20b");
            result.Add("pt-PT", "0f4102edd295383eb448f210dac41a000ae299a2cffe9d269926ebe80bf49c9134ef690775020abe5837473a212b85cf8cb368adfdb32c18d962ebd9c3188035");
            result.Add("rm", "bd9dedf72e35537cd98c9dccf835ea09b6e96d144f44de01de19f95640437d2f5002a863d166ddf1456bc40cc271fbecf9fc331749d644c15adc921373b400f7");
            result.Add("ro", "df86a5da5969cac9a6b9ab1efcd0022d4782b465b3020cf583324e6bdecdc58a285afd5aa18bf5d5a252e69ea67b50a914b716d7fd49ce59250b006fa11b9b7b");
            result.Add("ru", "f198fe5a17d5009ad00c8b641b3e11aa0ccfa23a9522b8af9451221823ed993727c1d3a7a3a47f537e2608cee872a481d702f8cd3dd86614864908a3c36d78ed");
            result.Add("si", "6a088defe64b1dd615b587ad7c86c26b1d0a4163dba0dcf5d650d55ae335d4948e4586f74329d5cf65c4e9eb07b3146d0786c0df142d16120de9f7f779c134fb");
            result.Add("sk", "59ddda6e2bbe7492450ea1a9428553431bf3b38f691f407e641a7bbe9e461378c42dc7b2af72ad889a3d5615b425c54ac4ac015ddf3e733ef24e17c2103c5f72");
            result.Add("sl", "a4411cac5a124ee649858bac56ddc587591f042f53f25347af9467dea1eb59dc768010654f4a70ba6bb22f42c686f8f78466e00514101c134215491cc850eae0");
            result.Add("sq", "8a4c52984c1608189c258235c5f0ce604dab5ea4ffb5f68d2f5e9ace0ece717197ad4fe40c22a07abd1fa8c704807b3e11f468347cfef819ce0c1a2e680951d4");
            result.Add("sr", "82a1559132567d6e50454bd01f8808e73b8c0d254788c62e3a42ffc752366afb760fa4b91bad35e303545486d6ff7837400a87a7d968df6cfc5e94cf7f37ae90");
            result.Add("sv-SE", "a76459cc52674e5ffd5b0296f2dbe5cf20ecdc3358886e397c20e06b1d04e3798c2617ba22e9d5a87e7a27987407fab38ba5e5943a1447c8cd4c7b73104b20b0");
            result.Add("th", "8d557f1c2b59788f891b4685cbbd683529f393639746f71fdad52d7d2562939b714a910d4508b5a307814463ce0e7ac25fb106d16aebfc3b318ced7cf45c5cc9");
            result.Add("tr", "fc740e35f54c8f0c06b27c975cca44b8939fb86a553f733040af4540176004db894b7433c4469b557ec194d5313d0cb05b20ac1ad958e56f83a10c1ed5144b9d");
            result.Add("uk", "3f0ed5715112f989ee74c68464f80d16bb1e6396a229234f8de9dba14f9ae29cbe0d83882ee5bad7ec6e4aaa5323c1370981c12583664a83f43d3357b91b9ef5");
            result.Add("uz", "c8d3657b3a34bf1f7eb0120a45337c3a7d89dcbdaf378c3fbe71effeb8836c7a0bf95e7c3454ca29222d3da2f8623983fdc9ed1b0c2f7a187444c89fed6a9e2d");
            result.Add("vi", "35f92a642ebd1e2e06f28a32d18918372710351ddafaac501dc013462ccc125798e9ec10959aff77f1fbe07ec7699735c74eba0d73c9be88860d658b84d1d39f");
            result.Add("zh-CN", "495abeb0a625ec1a1ce2df8207e62931c287d46cbee2ef9fd50595a56b370319557ae943ea5b024d31dfc8c47b537277fb8dcf5fa45e7989cb14356ff8b3a5e2");
            result.Add("zh-TW", "0d48699436661466079dae938889dbe9726817c922394527e41d7ad16a6af31875b62408edb7d0e6a71e595495001dd00162936d171e4588bd3cf21f3a2d6973");

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
            const string version = "78.2.1";
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
