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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.4.2/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "7a88cfc976bed9fc9b3a7627a26c8d7b7c2d4e4dfdd1394cc23767693ff9e2c6bfb8da9a93b600e6c938d0fa3a718105ebe39368778d5fd19f3347354188eb7b" },
                { "ar", "bf44ce6f72e6eb635f2695676e43c3b5ffcfa6eb0043122ea4e8ed387095918bfd30bc626b0d5d3c04ec8fc26fda3cee6e8da78403e1c9c85f3687497ea6972f" },
                { "ast", "a8cc4c8cb4a6d6d5d7a90b93dfb31e1a0360a8ed1b952b67e97ad60b8e600fc4509083dbebb45f09e576ef3d4a20024e7bce0754dfe608dfb807fdb439a74627" },
                { "be", "a9f98b83922a1462ca1893c4e9f4c8f5ba2ee4dde15b04b8fe30151ece2b0a7c341bdb98430c6d8733a8fcc3228a48f047f252afaf47d0a9fc9b849d3435d2e2" },
                { "bg", "bb684019d1105e0c9d0dee82c310b25f18980a4eb13410f4f6345a43ed02dc1eb45f8390f31365fc4e8e9281dce8f63f6813e6f05646dc968a8fcfa6d1ba868c" },
                { "br", "b8d291129c49331e2f2b0216683549a34dc7096beb476af01b64db2fc55d414469359c182d15d339a42a9cdc613b5c528d19fe505dd5c3443ac14b8d9758a0a9" },
                { "ca", "d73bdc537ed6f05dca1077516768da3fb930d2248bd622c377ecd0288b5cf5dae8826ba17fc12a686588fc5c73846d1efc9c0659176617ed93fc6c825453a758" },
                { "cak", "3e99c8324fb3d3b516f1135c3a0e64807dafd53501037a5df35c6b970365edbd24a47619fd81a1909f848b187c890c12f9770adfb669dd7db90876a72f4504b1" },
                { "cs", "828154558d3901e8ada011870ad2d9ddb217940a479a260b61f8a2351c8716f63dce6924868c00de44a7e9ec2933bd4bdc686ecc9fb41ebfd7b4047e1889f723" },
                { "cy", "c990d25e0d5f2b457fdf3f94f6a3c112e074062b1fac13195413153e3779b1a8f1448f6e5900896f8ac94800da00f9d61b66c031ab9b82a9022edf214b680a09" },
                { "da", "c065b1c9f731ec91dd24c28e2f4184d108e94fd9237343a35e5cd257da13587bbe5b85d84c41a155089adb298511f804c92e2bb2f9dd5ce44c3947eeeb27cf18" },
                { "de", "71222122dc2703f00a8f06e5be51ca42c06254951560557aa50ff84db17d25f51fab9d7691c020165532b710926c1e1054671abf5aec713c38a8851b40cd50df" },
                { "dsb", "c2ef86913e0cebc5217600f9c9d1a95021cb5acb5e36df71662c2c12ed7a751c21451f120be6b9a25e85e78d1d67c24e32bb9a36127b8f6fab5d767780c0efba" },
                { "el", "409f24c91bf61f6f6a87d00c67873dacc805dd0d9e6fcc2b79b9b4021ff27d8e59221f8673a732b66a03c7306960527a978cb32fc35ab5b26a56ec9ae7db5ff1" },
                { "en-CA", "6067cc61838930213e41b2d43dab76924730b018cccb49ec844094f5d4c34a759b3e74e582037542cb1128727bb00a1bee6e13f6648444d450adc62fdae0c040" },
                { "en-GB", "e19695951d6127b14d963ed0ffdfdb85dc620811ab520c15b049ff461245639a40eaaaf578634e84f0fbcb41bc4e61713033b5f45624dc41921151ee1a9c8240" },
                { "en-US", "23de1f2ba70e4a5307253106b43d009b0426b3acf7f6406d6700bb5857f79cceea539cada6777242d79d270aa00cda947e80fd6784a82ad0e43a9e14b5ee29e0" },
                { "es-AR", "35df5bf25f6cf0bffc38954442eb7f5f88b08c0599381c80284af95c26eeec65b153a7825537469d23e8bb16477d5994fd6d10104f34109cf914f6d62f0cb65a" },
                { "es-ES", "2b8299abff5a705c720c9cc032863245ae5e47c5fed95b7d20d4ae601477fb9e09e1ec2ac029a2d9b69423b3018f8d82901f48b28b71f14e118d9ea93cdee831" },
                { "et", "35f90c0e97712fc03ec934d8baf2565840c271c608d3463f4e2b94843f86043e32c6ade27a3609939714748d795beeb566319c0070fcc10b3e1f00fa49d9a18e" },
                { "eu", "bbfa448ad441db43cc98ca2e5deb6b3f857b82a672da1be72f7988839e0421c88f2378d500dfcaa06b16e09db8f2d25523a1fa01c0c1b0c26ae5e8bc89ba22ed" },
                { "fa", "1e8ed085f4b57e036430f77a579278b00fd91f55cb0a7ea5d852a1d7e15739d4c60f568e9de5abae1afb48229826a5a6433593a8d1a4aba73343ab0796bb9891" },
                { "fi", "737b4cba2ca80abc07a20c611d1530b8a9b2d64d451fe4bb6aa12451e34570269ccb90c5f10a463f157850242d160df516e064848c4761cd00652d973b4df553" },
                { "fr", "096423eaae2f1726dc303f5907feaad938b89126556723eb11a427698b4eb5622974bb6d788586c0b3b88445adeebe28a9c668fbf1d6bf1a3454b6b4c88defd1" },
                { "fy-NL", "a191c3eed588baebda403a3b68bbd8c7531ffe5a6f505b0c07c809f9cff9ef2e3fdf21b81530b499e76ce43c495932a98da5b804fe83ab8a17301401a7e6b9eb" },
                { "ga-IE", "36e76a185430893f574cf20232f5b9746d35a2c996898d6991e749cdc8b365fc3084b8bdb95132a3759aafb5998dd02ccd99468432fc71684ea05941229758eb" },
                { "gd", "f167c80ad56d49cd824df09e3684676238307383df9c602c6f2a0b6b2ed23afb55f28ac854da75c189778dea5b4e0e357d861a79543ff7350671f202a9d28c91" },
                { "gl", "d4c38eee003eed818b7d9da233c77a51941fe80917697920a1c95b686de6a19ca4306028e881b54e8ff7415ded57b05100dc2726a7404ba64182f631add415d4" },
                { "he", "541800dfedea7adc23786432473c42fb88cf952b018d91d55bde3ae4d679a32030200520a7a3bbcf01c786cb67dfc978e99218053a11e7a39a7d4fa9bba55fc7" },
                { "hr", "35d34d030df40816fd4bf833ff00ee30672c5bddcf99bbecbc619367f33078b6411edb416c477835b65cfaabbbe93c0ade8bf8f6d55b5ab093bc2c0b7340c054" },
                { "hsb", "80c2ef0dbde18b4b21d8286c6ba16e16da0a53daee91212eda10ef61bb5b4034835e3785667e0d42641347dda7580e889a7452fe44425edadea8da03d07eb276" },
                { "hu", "981d279e9d5c982d0b3995c9f862cc2b0c9508a355f86c62a5e6aa4ea1f6d0e17ad501ea1bf99118649091bae8b0f548ee241b91cb4d92a93ec17ed52fe0c9ba" },
                { "hy-AM", "8950a4c79d42273b8e905d01bad0800a2322daf7a28bc861a67848a0c8f6d5d173d44cb174768921497dbdb622cc9385b4d86fe7bead2f8ba907237eda5b0552" },
                { "id", "cff17f581ae5b2a922854666e3df39b70b6263a01c14f2125f7e5b747bafc951a33c7bc2008a279234837c5472cdf1a46b97f6e20e47d7fa347db805a3deadcf" },
                { "is", "472587a820118e91512afc93b91cca29fe18d64e1413cd342d35d9e2a998606c66dcb476bf99c39fc29b813921e7c47fb0acd947e99f701a4c0a41a0bb9f3f6d" },
                { "it", "9188e3e0887529b93c1fe7c67ca7b1dbefa63940a3f17dcb0fe0be7ddc1f215ec23822e13265fa9909eb2e508cb115ba33889bc9588a91b6c95d09b17c57eae1" },
                { "ja", "381f8ea6debabd9835f9894c8d5074827839a5fedecc0e9f006387955f64994388bf899b01beb86116404a4719e4613bb3214aaf510d679c78ed8c7b97f3ca4f" },
                { "ka", "d4bf9e484e2b5ed12f2ff3df7c2702fc91979804061e31838739775e5f9c7a17ce1030f053ea929064892019f74d52427858af522661ac03816b1cc567375c02" },
                { "kab", "6423cc3c936cb891595a48fd59ba7498b82b56293221390ccaa515bdb91cf009f7611b621ccd68f0b3d403c7e453dde11a8b1ddb96a2c0ecb804b39c43136846" },
                { "kk", "cc23f5b31564324ad5812d3b7fe222c9992206a09a8452b4b0bb00ceb621b1aba3080942d48bd2ccb4c42ed9b62afbc8c1a7cff5475fc5885a48836477c3ea26" },
                { "ko", "b8e73878ec1fc040d801c1b54a138b478db997cff0645ab7b36eb20bb1b2bf6e0f0f13f353df1162941f728b44f032ef0454a52e2dc55a2b760841e5bb7d9147" },
                { "lt", "32862384ba1407929c1961281ec926208cc753c487e1fe5bd23d30009b60cf720e06ca1ca8c121dbff596b08b8c4089219f070e538d7956d372c76d2ba19f725" },
                { "ms", "76da746a5e3d9b525c8d9da88db9aea7523b62167d932d15221071588dbccabcc8d04f4c4d12778577a2457cf0230e42fbc45e9a8f83e81af1dd5ddf895e5c47" },
                { "nb-NO", "0c788b7bcbf23a0fc0337aa770db68728518d780d8f90179dd2b998fe7e308a12be95656e434d71b35c0a3293f5c6c962751025147442b8ce7e9b12acdecf9e8" },
                { "nl", "56c12201e87a6fbbda2aab2711056e58770673d49a6c16941464d870fe0d9aa7a3f57bcc1d096ee6fce7968d4f4e3dad746175bc8722fd1032925c8e2afe8658" },
                { "nn-NO", "13aa8f44890100c23f40be79f1b828629ad8503596ae1809d955685533fc3fa5bd08f9d499c151e60d320e95e22264614a5aed84f37dc590f5ac33af41dd0f2f" },
                { "pa-IN", "c3d93d497dd00ffbdfeedf7617ed79d545a23ef6f19642b4481a5a200b8e41c6560a1a9333614b59a798a52ac650026c0908140bcf80e6adc101034b9924736c" },
                { "pl", "8fcd472e226d983c17edaa42c6f75b3d21bdf8f63a6b845ed9acb6a01d00eeb1b6ce9c3e80c9480df17b89572efd17cf9f07ee636c477390e1b1d16b53d66431" },
                { "pt-BR", "bda08e41faa0413ca33cdd81a7c9b5e04c8236038676c0d37705603a1c513355481d12ada72e6aaac788f29ae77e4fc40b81fcf142c9a9f612287fd73b72e1b1" },
                { "pt-PT", "9362ae9637d0acc709e2d9ce78fd8d6b871080698525dd3ed2a9bac4a2636d99e5ee70f41f79351232db741db0469c99f3d91a8e4558f96ebf2591ea0e137a8b" },
                { "rm", "1baaa5358e121315af9fddaaac27d58f60dfce735ef1667a0e0105be605dc3b0bbf2bcda7c6b0a60c4b8ec4f044fb9d6b3d2ebd83af5dde6f613d45892bc7b3a" },
                { "ro", "32472fbbf378083dc0ef79d4ee87d1bdf6a0ccbb2b026a90d237e442db3f33a3eded1b12c03e00886a03b11d965a295964c2e1836408b2243491238cdc906bf1" },
                { "ru", "346788fb051cd5357492ed5b6a2f5d229f3e2e807dca0d1391b3e41f1aca1e3c5ebc8f4b69c4b3a1c49df8d6a8059ccc1a1153af32aa6f7ff2f0c7f16ec40892" },
                { "si", "c661d584011c4529c114df5f3a0893c3647090facf79021efe1a2f3867123f0fbf912ab86967c60d35aff471e70525bb141229c0b4c9afec3e95286c51b2cd13" },
                { "sk", "70e53aad33236f747fca55ba9e2498506d740f8aebb26d33e1657823eb91c35735378119ee95bb15b1ca53dfc2e53d4c1b5b1eee777028cff872323439a586ef" },
                { "sl", "ecc31c0647a073a3c06378d25fdc98c70e22ead46ba9b4c9909585d9f28237f8aa293ae421221eaeead4f3b0101b0a49e2f3da154f44889b482ed4c4ccd0449b" },
                { "sq", "93e92e22b4dcebeca49c9a1c9022a3623ca67ca4f162bd8a3b0486258d87f4731bbcb9eead49b3738f363a952bdd31bee9577ecc255475730ea55446d4537d07" },
                { "sr", "b495047a27a7b390bc823ac007388eb614c5002f3bb1ad28f53eacc1acdf76a8bd1560f9b21befc22ac277ec6c973be124fd7f8e7b4b60e44a5dd74e86dc28b7" },
                { "sv-SE", "b9f8c94120efbd0b726ba435a4f9e81331d957d1dd0853a4fa87a025e256f9e5599685a2bc1b0fdafade2198d66bbd75a1d927f20e4078f53c74aafe1206148c" },
                { "th", "baed3eba6197a3d31abc6910629cb262fa76d246f268d1c397402857f77fc38d6d5d180ed4d5da0841e9b6273a536699cf3a94c767c47171f53233d2c398a93d" },
                { "tr", "a5f0127d3ace5fb784a8c42f5f4c4e610ea5a65cc665d45da013973844fcf65e95f64f32f2d24d8becaa653afc9ef66b3910438689ecb70e59cdf84f91fcc170" },
                { "uk", "59524005d719cf493636daece79daba3c5979e2bf2de0b9d256e7fceb34915b309175519173e06d1e119e3304d401fc4efe87f1fdfc0d1790208656e0e5e485e" },
                { "uz", "72432240c3abb826e758a56aa0fe5a13aaf34a4eaeae5f2ef77bd0243437f617cfde8437a82f1db9c845029406d6d302d20e70c1506b5108b74fb6ddca805135" },
                { "vi", "5b525f6a011aa55302e65ab5e084e67abe235e17b9e62c6de18f25ee41c58012de26d3ac5fdd46f56da2ce28036273ac053210bf49e159d2dd23438ca1f5c7eb" },
                { "zh-CN", "f58dd3567f138de3f25352ef3e3f56dcbfcdb48607ad933877be28dc96f3b492728e773da92b07106192dc18151eed09736c16f5836445f0f05e751420207f04" },
                { "zh-TW", "8889434b0ac91edbf121fadd1ea1d59d682c143bc14b415142716b227cd72874b0be0f5ff60bb572d30eff5da92fbaa085823c03f191c146a45fc309b55291e3" }
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
            const string version = "78.4.2";
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
