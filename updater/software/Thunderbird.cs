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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.4.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "e867d49019c4dbb0b53b1fd8d23cac0447691fb7d67e5b4c314eb24680e3989d144ef20b04081d52255481c66594fa1b9a7461acaf17cba80497ad6453a9f036" },
                { "ar", "873742f49ce1bc5a814dee66958e968d809d55d071ef72689116552bc4ecb44727ab910424f803e9670c3989f3accc046ba2ca7aa92002f1e20ee28d9c43937b" },
                { "ast", "772773b01093bd0f26d31e76f0dd6aae59ae80834bbe7af6fbbf1b4080c45d9841dcb668cfa44d0015138a83ec57f16e8e111e9780c917e4e7a979658bd562ba" },
                { "be", "56e3dcb9fd3adb8dcdfdf4445669fd233710cfc40e720322c033477b9a267cf83785c76b3786570f81877c634e53f45f3048bf8d3a244336b7855f1c83d483be" },
                { "bg", "448e45565488c99a946862a3df7dc31e73c4dd3c3ae141d758febe79870630ed276a83dbb1db6544d07fa9913fb50ec6cda9e9969a785f536a3f61ac4096139a" },
                { "br", "ab0d2541d2ad97c0b927f092e6631122a22055780d3bb0734294583c2cf00732efc9deafa983f76361d59d5a1800f2063084cdba35615cbf1cd7d6c1f6cebe0f" },
                { "ca", "8b70e8a7d55d80f371046dfb13d7b101969b50de65343fba527ee974873714511b42b93fdb41952b2705ff106f57561c26a541c1a74ebc12356120f372760ad7" },
                { "cak", "cda52a5fef25520b9819ac8cf8939b04047d0c13f75273798549f5e4d329e8a611726c284f216fee2e5fbfa025aaadd06c6493d137f5c499bca6d530f4071764" },
                { "cs", "a11d15018f645089afd5b2455d04bba786b322f5daef92f3f81f6f84e633d38756f2441ae592dd520cb06042936e2b0eb2d5e93ec7fc2b38661265d9551bf434" },
                { "cy", "0b255e4536f9af2e17d3fa7ecf7e937405fb41123e60bc12db1f0d2e9e87288d2f38937cd4a4c7acd2de213ea953e43512d352a0e2e84444b4ba58a2af4fd87f" },
                { "da", "528d3ce814ed88ebe5708289da8917c3fa49f1276c4a898e2c68f44a1e1a44f3172d7ce39419d33d3f580c50a3acd9bb1244afdd97587a8daebc36192650af02" },
                { "de", "04a5f988c33b7e16ce60b05827cf59c65dadf8aa3a94e4e3b96a1da082dbf673bc98e32fe13522fa195cb0e5092e5235ebaecace880989986ac2e7c3c280021e" },
                { "dsb", "399e7f5c11d1b17a4624fdb0d4b599cc2ddb4fbc4888526faeabc464ee8f11d10e3a98ed0ab4a1b230f4ab7b0d3e4a32ba632b139d930f6bb3c1c607751d8a23" },
                { "el", "ea1b0f181cadb25bae145c467673cb0bc00097ccc3fc980edc0a879c39b14c73a336231220a6ae01817d12e7d79c738fd1d212dc28866fb100b4ba15c1f9aecc" },
                { "en-CA", "b9926d210abd5b88a2e7f2d1f2bee4e975a66cd0164d1082c8c4374ee8a3dfcdd19046788bb48c40a83ccbc6f963e595f95a711a69c46d81fa0160a097b78a69" },
                { "en-GB", "b59589a0abc43bc58155134cc497cadceda666ed49f9834bbc2b81fc58d29bd45069edfdc461581e133adcd0093e976a6639a8ed70f90d3f4480d41f79a9157f" },
                { "en-US", "40dadaf1930c920c8cb2f2e4c3b3d089b9d873669c9332fde32bb00ee37567b0de98c9dc06a17f6632f43a39e474f690a523b4bbb7a3441bec379a80b0fce52c" },
                { "es-AR", "bd9072f347616e55520e9aa636e11e4c6fe0d88f30f01646302554d64022080eb959e8eb6558a2be4947e755de1947d78a883970df56e5cad40b0339230c75be" },
                { "es-ES", "25ea34be0eb71cba76691e5e69bd0cf5a0c3fecab7b91ed494d849ad27710224b26e31dd9d2a424f2e1e8b5d0f5d1b275869be0d676aa2b89f495869300b38c8" },
                { "et", "3c996f6aa79aba5d6fdb476bbed8987c2041fee285e75471857fc2b126614ec74fa7901a1c5c5fac5aad1449cefcabf619bf5f5d95f8b7f5c20ff9e4fe104867" },
                { "eu", "7a25be5178e76a039b9c76bba09f4b9b3617036fb13c1b9c1724f511a3ad02d5581421c4f761ef83a557a09483ffc9119d5deaf53801646132370b9353f14b14" },
                { "fa", "732a9edc13de25fb57edb3f5dfa3026988c82bf1e291544b1a6687e2763421dafc74600f6a5967888fc328ee380a5081f8bb33ad8253b3c8b5cef90c7a3786f0" },
                { "fi", "f3376008fd657e5fc41597f281decf7815e0323141147e0c5bf977ba02b61080e2ab19d1e1a225b1a5fa5c446d543c2e0bfb8a1c34873b784f539a26d53d40e5" },
                { "fr", "00fdbe884ecc9da9ed868cae4b952581ed51a8c0050161b214cab8b09797904101b607f1b30bfe710b42b642df59a7ded3ce9dd72bbf80ab2d64858d025d0f71" },
                { "fy-NL", "05dab2dd96fbe299240b034919ef746dbbf39d6389a4401a175def301e312bf298798a7cf1ded333498f5b95d3e3c4db313950394e9d0b0eb08f3d28d6cd3275" },
                { "ga-IE", "d5d800dd138b5f0b60397b1b487a77eede215870c84d60f025007e4353a03ced7cf627640c30eb991756979aef8461afa747b49ba0a5659bc0fe153679a06e8d" },
                { "gd", "341cac014184025f0b011dfd9d1fe4e15811caccbd5fbcc9e656de674e332a12031da4080743cda84d59d7dfaba8163d82f07bc9b4ed06ddef0f0db95aab49a5" },
                { "gl", "373ff8ecfb860a2baa8c78a018914968a8dfdaf9a6cef1967d6766395db44d3ef769833d5861f71c5bdd202b9c0a2a90cdd3b1604cc259c11877b1f70684d31d" },
                { "he", "4af7dcd1e7cbbc3a4c7476392be72ab388d3b9f0cd3fee3625d963031cee9042f0dc493bac79ccc8514f3389a3745e7894ffcd5b369fc303b87a799e3bc3de71" },
                { "hr", "827b726cca628d76fa5218a5daa9b4f7b6f7cfd741f2afd56c51a5611cde4550d32a1de9125c04b9590eefc07f210099550c3223919475fb36bb39e0b46452fa" },
                { "hsb", "8bcad317cfdce01e3e4b5403304f86bbe9ae0fb1da40453c0355bc05ea06ff02c2c2afe825b719378f7a24d3ed90cbac99628c03a06cda09d6ec37e19b8623c8" },
                { "hu", "cae5ce9809c4b30d2ba713a6b59844485d10c494682ec1326afdf5c223e55fd4777132f42a1127dae4665379ad24db41e09a8908e227eb7f31babd63f7c92387" },
                { "hy-AM", "e7e60e9db87d68a4d0da06faf6280a73a5dc9d09324102ccfd6eed42e5b3c0afcca87fb2ded80dfa0ee378db45230bfd2ace9ccb101adad587fb02011bb4abec" },
                { "id", "8789bcc7ad6d4fe81747318fb6c0ac5410b01a1fb130b6f63bf0598cfbc79e1e6e45c9cbb11def043f78ad4580777881c7c5df5fb2922ee2ab82161e6bcdf4d1" },
                { "is", "93386d06e8f8d60728535308725a981b9aad7dbcc7691b0b9eebedfaa95cdaa46353acd01672ede79b9fe4159142e5cbfa6b82ba765513c4f9617c86215ce2ad" },
                { "it", "930a949850191547dface06dd6bddb5669886ec8bde1517172fd4394334131ba99e47df820ec37dd514decdf0556385a5cac041ecf80b78b570ea36f3183a8c6" },
                { "ja", "d78cf3a37c9052fbf91d3e74f7bac0a37fcccd59fc62808c853117e53089f0943a6ecd1c771606784acf5f965e9a9b13a8e6e9849704f449fd61f905e9e55c3f" },
                { "ka", "2829cb1e95c74ec17dc33917c53e2a6d84507f3dee9aea9101b96d96c9ef1e7e768b4bff71aa0f833031a54755e9ed9f7d651dbde831397a874d98af2a179fd1" },
                { "kab", "07732dc801b968d205d4010be1f95624a5847ad3e3bfee92d00bad696a841802b7f36ddc0f45fecd3d1184133fa39c0045fc3081b2451565c64b823064df6eb1" },
                { "kk", "053f9478d9a3f6cd96c932d946a50b867556636c0312fddff705a9c9e4a0f523f45b3d9d17e3318572408c3f50fbaef1a1b489cb9e54f3d3d75bcb54c36235b9" },
                { "ko", "32b8e820e0505f4e491c64699cbbe06de110127371defa8d5bb6076808ccc0caec2f105e92755001768fd96c880b62a4d8e5ece02003f6051cfaf6e82e0758b5" },
                { "lt", "cc920120974fe6c2cf3b854cd47b911891cc39c4993a8622f6acf7a9088367c457eb65e3e6d6d1ed70426f40c2f53f14e53ab55c481120a408748e6f969b0cd2" },
                { "ms", "750be3a1313224aa221e375c8bc63c15a9f6f451c387279c2ece4ec321c50b79f928cca675872ae52f708050a99c088a24fae4d013f9b9069e95db8a75110f53" },
                { "nb-NO", "cf41eb5aea62b751191443d35cb918aca8cd2f7be21cd5ff36f5e096a5b97952996447044a67f53a25f56f368e87a1b1a5510f125a3b0a008c0b55cd05b5d8e6" },
                { "nl", "b9b9a7b28c2825b7f9b1e6bb2feb1ea72e88d4dc5478ef65636fbab9ffaa42c3802359c9523e64dbaa05337b4e00a3d8529f336a82eae4e49cdabdcaabe7e97a" },
                { "nn-NO", "be33f28f4b423124c2e8d86eb3b5db011cb9156d68f4dd607363df36c89e32a8475b5b27b2c94990afae0effc8ef2ba978865dc610b9eeffc54f9101fb540e6f" },
                { "pa-IN", "16ffa2b2f70518636864423caa38922e9053602b83841c6b9ccdcb0b4e903fcb143b2e76e3da9d524157356938f930e84dc4d4eea0ad42a019e4b2d2614d5639" },
                { "pl", "f138293dc51fd8701c34cbb70a7af19e89f8f4bfd97a9215309f70880c4a8378a81fca839643eef72c12b225bab27f6fa40acfd701921357183dea37b379075d" },
                { "pt-BR", "6b306890a1ee1f26145b60dd0c348a3804dce63b048c372aac166dee37a322759cebc47eda6034a469dffcfead0e1e65f2c31d3e8689e95c9c2bd00114d52c7b" },
                { "pt-PT", "d767e3accfeb1ae5bc300eb34bf463bd339524e315fb8a363c57cd8dbfee4d9634cdc2971a2a6c7d4c3faafef08b3a5a4e6077ff18792519b18b6f114f36454b" },
                { "rm", "d8f7f0305933a2ddcc3cdefab922ee4dfa1f06c1d2e178ba4b1b19581ee706f8a449142df67c7206db74824b1ff0f291a4698f08d1bcf17f56337d2ede8061c7" },
                { "ro", "eb571581d17c8d397e62703ae056f4880394c0a662476ccaf850927f183150601bf9b5f8296518783a51f8789769fce8ac9b67ace20e2cddde165e2d301fbba7" },
                { "ru", "8b30a8e3d99e3865e62a458ab129f081e506fc6b0eb728f52f0f2ad0c51d2b49e313beb8af50e11777e1b5e7a5cae17312f7f956c6657a25330d06c3248d866d" },
                { "si", "1c2ff6e1b0e84df92cac60438107a8be6d39e92839c2ebc7774748b2002655328b50ca6dbf93f355ed91984d38d79eca0fad99cd7c8eaf413d441d2885f9ef24" },
                { "sk", "14ee4d88bb2322f24e1742acc3cb11f0e43dda405f9e3f4c73da28cd5f3900dd9bd0d2bc4e2ac09f139dd8153df9856f2e5438cb7e59036d55a2aca8a45182c6" },
                { "sl", "f17731ef1585d70e8d78509dc85469a397d372adb70e7ef9d2da68b1f074e65f89f008095e8caa4a36a03008f12805888beec6a7b72bad75d57bf5560a9fa391" },
                { "sq", "982ced375b522c18608b8fdb40af21ee75fe12e87228fd257b165b5a917372a3e219ce3a0c10102a99f0f4fa705d9c980db30d4da311b1c303932c5a1da70589" },
                { "sr", "6f8de83c5deff5cefd9a654201bbd33898de677c3ef95791d89962a2099a2ae605d9693652640a5e93e072519c9c8008e3158b72601b9885a0d4e11bc962819a" },
                { "sv-SE", "9b8b87972363dda9b1ade5071e070a53926b3737cc1a8461f6507e31ddedaacb27477d14622aa733ef89da077c06e22297241ff31a6dbcdab2dded2454960552" },
                { "th", "3933ec5bd04adf243c36b092547f0efcceb17cb45cf4cd1f67d1a63a6759670147083a395bfd0f572cf01f05dac779d3d4a028c7006eb3ad15f46e87620a2d06" },
                { "tr", "0f96a15d2560bda9848c678b5e41748e9ee7947967759101e5d63db5f64ebf6620800882d7d482fd362f837957be659a96311869bd1d6f4777fa1fba7b38b632" },
                { "uk", "09c7da04c6b515955f8d7d3096dfec68cf3682a6a50e49eea4f1c50d4c3ab5d3f8d816aeae2357ac1d9591f6063956a85890bfde2d10ea8e2f549d8094af5794" },
                { "uz", "ba7d8d6143a8478217c13ce04827908a09015736f14603a3dbce2570ecdd58d5bd0587fe016520e895424ac78319af57865a27a3fdc2c7d5601f4b6170a6fd72" },
                { "vi", "e80815da0c69d04509565e9149b1e66967c04c1e8c941fca30fcc64c3755028f795b9cf32b43c6c029f025fbf03b7509120822d97d15f3aa8eaaf1b168b9afa1" },
                { "zh-CN", "fdd90bf1561c5175c11b4af9ad7e588af9ee5da62edd98adfaaca939cf74c04f2ea778fc9b05e9480bb263432e4c19cc57ffc01f14ee80d5e32d66c350b8ce82" },
                { "zh-TW", "b876e9461d73abee307d1e3296ea67147a7a74095dfde156cf45a40efd41b775d149181c433c847845fe42576f5c944c6ce0901f83ce08017be578445f446750" }
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
            const string version = "78.4.1";
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
