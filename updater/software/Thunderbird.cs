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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.6.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "6f05feca01d8e21697d09a791c3e0d33a8d307d85d99f5e04ef450ef3829613dc29e81a21c73005d2b701e403ffb506f19b5933052977ab9abeb1f0c5e82c643" },
                { "ar", "2583ebc16934380d829916732b1ba4709f8609f2c2b6c884a367521d2770265196271ff90ed50d63f73177050d06c41e135cbf5d5f0feb444cab109ac4178f23" },
                { "ast", "fd4e6dd433a40dced3fcce886c4ccd8f7c3defcf119cac11b3ddfcde611d8ca175633e9c67a547c90686f0c5551e3b95bfb85078f48925ffca7dc448f63ceda4" },
                { "be", "5c2c1d66077a5f655de53a28ce77e06b46ce9805ac11e8d82322ac6fab99a26e8e9da661e555e1d4d24d74aa3e32874b7fb63dac3bcd67efaa1633dea3c65d7e" },
                { "bg", "39eb814df027cce283c72db90c11c7fb47953b3a216e576323db230e1bafe0535e2b42a688fdd6b26deb34ea4770dcfd238fbfc3fed74fb3ece9fd6ddff347a6" },
                { "br", "224c6b0dab1a806b0e0397c45a1aca88f01ce0c22c0c4c240334dcbd2fda4aef360feb79a077af77c5c35ec5525de3735b3bbc0a7e3b271b146a3141697819b8" },
                { "ca", "2daaaa54adc270d25b4b1f9c518419a26212e0a9d623ab1d87a919fe083f6662e902f162b0b70acba63b85e505b4bee0496ea1599718b1fab9ec00edccfc78b0" },
                { "cak", "327a94d557984528cf99bdfd4d46c25a400f3e24635b788c9c5fdb429b5820ec3871b47ebac37c45721f3ffe841adec4da2fe2754d085c06e4128212e8c97662" },
                { "cs", "e4ea2a54a5ab276a39ec4f620307f8aaf51529a45efc5065add4a3aa70962ccf53866fa3c9b85fce696d8840fa65c6c8080f8a1aac3a980aa8e8193b21750e25" },
                { "cy", "ebe00b6cd27bacdd9e5de8a860cbdf293c969cc13335109b29c170a7b9fc857a856ec3e1f6025b3c34377f160d89fecb14b1420b03ecc7115e048fafff43b5e0" },
                { "da", "7d716cc5f633f93f972b6ceeaf438e80c816ad202f6817c9fca84572c707cd9593c05ef1fcf5c511e96369a4fe1d6ba7a4a1c667b6ab2a2af9aac634260c85d8" },
                { "de", "6f80964aa936bab968687373bb910ea563281bf6b924fc5641bdc37d0b5c52bba82305fd98562db852cb3b3fed6ff5ac3d00a01ea6db78180406489774498de2" },
                { "dsb", "4ac8ddaa48ce1d4a152365f5f56ccda3afadbf54cc845dd5c1d82d9043eb8fdc747ec82eff4ddc736f15d1a0f88484771b0e35c91f612ae59585cb6970d1ba7c" },
                { "el", "a5ec67284345b6a447bca3be8103cb8aa7e3d155c9d34d73be32bfd561797b0ced5f798449b3ced3da3af7e4890e9a243d011b1805dbd7ad6a5015b079d06e39" },
                { "en-CA", "7cac3b081f38ca1cc0ed2f43cba6d6bfe7801ac22ad716adc47eed280a1dfd861886801b626d08951c830f3211bbea5f4c894ae18df4382f9b8ab7e4f16f2d14" },
                { "en-GB", "35273db3d8d50187cc0726e2d65fa8c317c3a64e61a9f18207d99ceefc1fd4b49ea1c89b0c7d068917b1751a382767829decc4db2396470069caa53199e79a48" },
                { "en-US", "a7f9686cb2f59be67e632dea6be96699e1d325c4c027eee8e2f7093f3df052f1048ad6efbb68bbe6368a64b8b5177ccfd59be58da19bde7c5236a7f02f1504f8" },
                { "es-AR", "68bf25c207955d17d9f412d0e2e0e9e565f475450bb3a8c3665b021cbab58a767a63f139765206073d8c3e1ea50191661af3581326b0a165c23957c282701a3b" },
                { "es-ES", "6a81c37479d229ab4b76142104716e9627a9c2aef2084852cb1576cd28a76983b75776e5629f35af8da5c144e9d0e1d92d42cb61a7cf7aae39ba272c1c0b814e" },
                { "et", "b1232408c26641a8e3d20fee0b062b48e9b749fbfffbd36dc2ee589a866b9cd862b2477d55aea5a03d6abe537c726efed01d85058efccb44d5d6adf2305ffc04" },
                { "eu", "04fd087d41dc0892eb38eee837e8bb42deccc57dc7fe428b51db71a314bbe450efdec24b6cb92b13b1190352fb3cb68f3048f41b45a43fc89d2a28658c020880" },
                { "fa", "832bcfdb7a10400d4fd45e2038b68760b8905671606a75c5be6860cddcc00f70066e7934b6d08d36ad0e690e604d8f67b8c5045e5c8d51cb6278f7728d41be7b" },
                { "fi", "aefdba2708ba4f1607b6c76f85e70f86b546489ea2da7f1cba712691d62c98eab917602ee76241833e89d41e12465ba07908d3df579b10e200ab4f31da7bb2a8" },
                { "fr", "1b3412a2a1c43884593ca70133364157f95adda79eb75b550ad5a8fcebce94b319241d2e5b499a5232c0f1212c7ffde23eb88d6bc94c29a4a626cd834dfdd5c6" },
                { "fy-NL", "f7207decba36aa554d47aa6c3ba0157e9effb84552d585d1245c5a074314a6b2fc8405a7e77bbb7b693de6f8383f8f3f0f5efe84b650a6e2717eba282ea86ae9" },
                { "ga-IE", "c5624c149ca4f703a70e421b9cf2ce0656db8aefa75acdaf2ec821c67c1bc1d7ea6a7152142eb103d823a2668ed6c670a312979ee381639b74396f140c6ea808" },
                { "gd", "b74d58d79672f658399798c980c27dee57ef047d8804777e8652f29a8720523b2a0611da9c8b49bfc039ba969f57825a12aca726b15584de22f4a9b4af13baf9" },
                { "gl", "1806826c9f7985accbd354d350fdd5874229199196c721e8de1ebf952fc130580432f9f1f1fe781bae85e576383eb824d322bed50bc20568683583b1f1b18921" },
                { "he", "da72795a81d2f347075fe184a2c78983b3ce1ab97ef92d5d4413c21a6f04331107e9ed0acfa9abd3afa9dc4e79579d73f822de03b0debb4257c40f234aaf7a79" },
                { "hr", "34ad35cd5b67de2e588bd5be68459674e081b9b6d0656a8a8e9d1e27d796a358d699d14d770bad8ec0bfeb23d74a3b36f708865a492bca6f4d9840acacbb8871" },
                { "hsb", "7e3697677ebdfac82a63087dfb617020a8b793894640e13e0e2792a3d59071a60e72024a52e687a3af86388bdeca9bbf6faef2bc3f5daacf4b4de5ba513c72bb" },
                { "hu", "6725c2484b6cafdb7a385bb8d9e546d6f0ac336f689e3e7be9cac81f99ffae0dd4b045cfe10755eaeb72a00d6788480a04186934ca2d17593c82ae59fd07f3ef" },
                { "hy-AM", "408446f573aa24223c72d3ec23a53225e8719ffc8c9c1b5018f833db5f08983b29d43fa7c6e1802b0bff52a06696126de80ce87b3cb61b7636a9a480dcea94ad" },
                { "id", "95755b7a9dd09919b3599a580c9ff77e5a8f37b3c7eabaf34304a680feaa8de71e5c51dac496bc6b3f5e2148a9fd481024f20ab684deb9f3520f31d6480fb1ff" },
                { "is", "f5453c33c53e18bf6259dcc39d9acce1de155fedded7b663f8b0f66e357ba37c0ccb9d978eef46d6c69a916abb8a9f7d90eee931b6e262c6b2b0f3ac07250545" },
                { "it", "a9bc18acb6b3d7658accab6a1fbf20c38d87031b3afdd202c0da691736804287786430399ec9dcc07b054605b5ee52ab1949bee136469710f1da46d8977cb4ce" },
                { "ja", "9f24ba83ba1befdb648ff639e952c34b7195bc1b38ffc5b5901d5b44b35f1f10410380485f715f53b5ba27b01979b7fd72850693f84b90cd73704fd4741c09b6" },
                { "ka", "3f39732345dd793b57ed0bba3cf8704ae91262f5f8b59cec9a2e217cabfd303898bb0d4c3a927a8d253c41c422442b056689366dd3eb5508f0622465fcb85229" },
                { "kab", "7de4ce807d2024ef4bed73d7c7e9dbfca6c54f63bd6dd8a6ec1cc802c4b5bb77d53edcbc0990ab0bc52c7a3fa5f0e137a71aeb79b1ed1d70e605ca251d3a2172" },
                { "kk", "2d591658e4246f268100a19575d309dc4b7f0512cacd0c81d86ced53be9ba81ca24b8e79ea58fe346037691f6b309c4b28980757f516b8c65df2d72e84131600" },
                { "ko", "dae68bc4facba0aa160cd67de939ea7048c836e4789933aba796ebec5d5dd3a9e9b324447e3b3d9871cea58491d115ab5013ef35bba8c82de287fe451fb5abc2" },
                { "lt", "9fc63de7d77ff2f8250089ffa1ed22d7e31f58d1500fba72b55311cd9fe848d7003c992bb3255de01cff995362e9e83f552922964ed3bcd2d8c0d45485482606" },
                { "ms", "08edc21eef3b784ddbad4135ca11100e128199f1feb9c0c833a86615f0b22e7342aa6d9095ee85b38577f720d45f2442be2ee1a503357556cdd81d8c3d6888b1" },
                { "nb-NO", "3236644050496d557b2f423439698bc8af4c599ff59c0f3b3527502785dcaea22555c6da7da17cb87fa9da723312fd435a6d5e21718405fb819039902f43a4f3" },
                { "nl", "fa1e3e512e87697414b0c07d91ede8f4363f0a1b2e9bb31ce3fa2bffde0c96fa231fb3718e94f55976c1805057971a83a1bbbd10d4c75241a3b46742ef0980f8" },
                { "nn-NO", "7c1fef339e779e722897a24c91cf8644f6f57c2389d6fef54bbafadbdc74048cee05c720c4e68b605577688b325f28e798e56704c1b4f8481a6268079d584dd2" },
                { "pa-IN", "7a502852afd3cb5800c0faf6b09eebec56d6aa47bfac970b6ecbc67991a62edfe463ada210828086fdbec2e492d5819bef759a87cc941fa8ac181147cdd83e79" },
                { "pl", "22add3dd78ec16ea3816ce693b42079c520d9296e912e56b365d330473160077a922ac25fc4661afa43821753db353a27a995c923ff4761fdfa185ee3645f2bc" },
                { "pt-BR", "f17300859d4526bdb1c8c0d25bf90c565a8c70043cf7ff40a1071bdb5ab783b12a5e5282a2bdb22577933c7095e36cb1283114a18e6bb6e18ccca1d589cc7e1b" },
                { "pt-PT", "ba463c97cde27a08831a09ac6b47d0060e10a091e3417704a89492670d422ea9f850bf9b916de51b5248514fc8d30f51190c3573e80694070290f0bc517dddce" },
                { "rm", "4e136715e0a5dcd51c9ddd2a745709bad67f5623c22b0f09b0d0904c56c7f875b05f90c668b08e415ae8161852a4a18e0d521ff408bc4cda8d60e9ecdd8327cb" },
                { "ro", "e1de06afb435491fe5a6018d6780c6d3983c6ef1aaeb77f6aca8614565b3e96ec078a5921e20506bc5faac8e15b420387906ab63cb987d10547b9588116d4eaf" },
                { "ru", "4789f9cfb00cfd5f414604b30204e9c1c7867c8569b3f37798008cb2ff6de466eab578e1881c574df3a22f4fd491cabad3a46b21301c63439926c36fcef0ff04" },
                { "si", "3ed2d9370dea83e3d41b9940ae667e555b9701b8c11da62f8f91881b1faf195beada9265a345ef322980ffbf58f4856ee992572e7456524e795c9c6c353bc207" },
                { "sk", "406a5e26bfc7ceff7940625b3ddb0b379d81b50fbc423fd3563daf3aa80be2ee53b76b3aef162b49751e41be022c9dd293091d8302b326dd1e44e2d70d1d7e97" },
                { "sl", "3d89a32a224b91f23099dbe141f76abe5c6994d6af24e03478d5195842f44e83ade3a6f36437bc4341ddf1ae5bd9d39dd833d4dd9e7860f3b797b5f2e3dd1224" },
                { "sq", "810ae11cc39bcde008c6f9b4fd91949dc9e9d18f7a01a935e8283472edb7b4fb8986c55516f0ded814f7333d5caffb024834ae031b5aad3b7fbf03ec74fc1f1f" },
                { "sr", "44e88bf678f8cc2c7345fb6093b8be5b419798fe82495f3f013adc490af80b9acb1cd8c0df8833aaa4df1afc64b7136fbf64e075c53ddfb04f13875a5bad204e" },
                { "sv-SE", "c471e485c887b039b1e90f144209734725fb2b21ed4b3bf3d753758a97c607f24a0f10ec47aa4decc4bb6052a326b957aab992dd4671bf0dddb790297f05ec48" },
                { "th", "1ef802990155124398e4b9b135e2b89e71964ee442fb0eae33078433b244cb71851b872d44613fd41fb794cc2ba387a51d72b60affff3e90cb549c0d34831a94" },
                { "tr", "e7f2d9ce51434af0d8c853ad92de7cdff5533dac1a77ed70ba00175431c4ca5d73e1a6f8900cb310c5eca3813be3c6a26abd6a8867618b737ad76b30c56b3e87" },
                { "uk", "0b61377fee1286d6a084b6a41e3cb9a30d74c51c15713db730125c10af4f051c5c647ad5dba0b2603b29c841663ad21e4d2c51b7791c5857d5963d61376a01bd" },
                { "uz", "47b5c25b6c5009111ed190e8f9e8a4c76cee72df0b03ce74f9a1af57a47ee41aa834ad7e8ab9c56f50618551f60c6ba0a46227b701800bf7234c887f20f4b459" },
                { "vi", "63c0140f1ec5c18d1644d45c027a37df12359738831b8b9ca548643f2b28c9c581e3e7ec9accd19c95799d43182392b24a16bd9b3e48f3c287252124a3c7471e" },
                { "zh-CN", "29beaa128584d4b99c42fd00ac1b7c9d3db4c097a2159719c872128e0510fbcb93d92e022462252715cf597aab95d9a5fcfafebb9678120b65beeaaa93fe092a" },
                { "zh-TW", "36ec177f8fd2429423ceca572f7c391412f2704d2f2ffdad0b16d2b6d566874cd592e41932000756e650f27be496e02842f067a4ce8de25f6bcd79d63c039cbe" }
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
            const string version = "78.6.1";
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
