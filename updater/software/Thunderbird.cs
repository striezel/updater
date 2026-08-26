/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "140.14.1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.14.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "9c22fa74ea84260fb5d3fff3dcc4f113f95d64488c44330953b47329eae468741bc4283e989fa91420fa1fb90857b6c239b547517cbebcc026468f46340de8f4" },
                { "ar", "7f5b4ae8bcba5bbc32bce5e41c5a690d47dbef87371eb6fd82db9c44e6e8ee6f21c9b45fd859ad1e672e32b7d5d2511f5e54db851422561faae79b8d8ddd0de7" },
                { "ast", "5ebda89e2311d869c2d232a0fb9ee52409dc4381d11931d77cada27de0973eb3cecb08e412b0433561f97c465ce6d363e0b199c662e125661d8010c8c108a101" },
                { "be", "54fb32f0373334d2b47b3dc323a981501ad0b0080a4fce7d2027452931b23a5fc4e7a2dec51bcc9d328a581741f82355c10e64a6ddb80e2dd314bb09043325c6" },
                { "bg", "243e765d106ea72e77d8ae432a80249818d47b6433c8669dcc3d773fb4759444e536c06cb7d72d0153c6b577e9833705752d2f1b824240378acff5a7680c323d" },
                { "br", "ae21744622bb751ef5fea4ddab1c39a50c3ac52f42ae2db2db8ce436f495da927771934b2a377993d6caac0d95683d9547733bdf58a1bfc995224ca09bdcd1df" },
                { "ca", "c4b3a3d2b53a45a2e70971f8edf08507e9ef6af1e1e0121fdc6a239881a7994b117bd1485691c5bddc2caede8ef6bdf6f9242e17f3763253d402a71bbfe6f52b" },
                { "cak", "75d75b28b61474ae34f4af736d95b68a260d28898ae5a26628052bd210881064d1aa1bc35f8e94f231f8020680546f7518feca76fabff4f419b938518e59c29f" },
                { "cs", "ac5f4295de1b9a84281f3d5277b304289e1c413def967bacdc70819d69d1f4169558d40fcec3314601f4499d0e79c6b674f92f4693574d0515fa6237ec25683b" },
                { "cy", "3a11f64d091eb13f2fbe5c0d4def08ccb854b91742614093fff1dcc5b9dc974df6bdaadcba4595a8fed63e60be5731c448002dcb3cdeda3e591d8230f874363a" },
                { "da", "3373516a0260635de36fa02aa66b591a3622f83efdb9ca6cd0c40b4c8714cdb355099ac7f4252796e4838419cabee7a1a48f31f0932dac5737ff77a85918cbd1" },
                { "de", "188ab844bdbeaa53e46b04665628d0e82caaad716f8a3c3d87752b10d1aa25fc834036d07e517ff05262b0f3789e8584ce3ad715b5a0936107bf656db51c1091" },
                { "dsb", "966d310253f5ca67f1a71847cdc070b1cce1a3c5f6526b35ed4c140523154e8e62084b38c6207151f8a470dcdf8b1b50ab98703d611297c70256b7ec75668c13" },
                { "el", "222dbf906223e2113f387c97434a294471fda6a0255445bc8f4fb491f4745edf8378aa92728d9db3a23bb8fd9c143beea9557e0821837ee9c451f853bbda3496" },
                { "en-CA", "b31ce6e26560f50f1b7d131b441e053e3a810eaba709a104cb0a802a4747a5d8f5c106ca4fe5d346eda169d611da49872643e0e98192bdc43dca10b1dadd8b7d" },
                { "en-GB", "64482090e9322d5f2da8e2f45f357a1f200c64bac87b01c49dc43bbed6c7bb7fc01909ebbcb301a983d16f4549fdb0528705cfa935266a0b9c8c7d543e8fcb83" },
                { "en-US", "d8e9d3266a8e495339385fab34a3d4c8cb08692bae16eaccfe566c4d594c8289b68d6e0b056c7e3977ab348e145f16b5cbb9fe7c91524114ac11db2e4f12ff65" },
                { "es-AR", "69d7ebbf3dc277086ac34e65e4922e43579d415a809fe52ae95971f0a379e3ad25e5ff12188a0ca4c7a6dab587d441fd6a388574122fd5febd018a60abc041c4" },
                { "es-ES", "66ff9b2ff31665817b6840406eb8376fa15b65ff2daea0a11eb1c1fc6b31aa4d75dd3d1200442b67056b904c594085237784940798ab6f40dc9ee7ba6474b8aa" },
                { "es-MX", "90f7eff1c1cced8e8f76b01c54ab821a4c35621979e20e511cff08a6a7a342ca840724c2bf9b9136dce4705161111ec1c6e3e75da6b7c4bdc06fdf9804a61d34" },
                { "et", "f42e617d6a66ba2306ab45557e65b5d746444f914b28feebc71107f01aea1704f83788d7fef0c3fd625a57f4286ba30f0f5f077c8d8fabdbc426677430a768c2" },
                { "eu", "ba766e860692c2800e56861fc3d9c3323e04fe2f4dc5672954d7e5424a954cfc6d0d6ef29460c9d8965f7b9419eb13046f3566babfaab975fa59c6779d1ab436" },
                { "fi", "0ecb2bc036706b7ac0202e1325048c1801c8c354022bc98c8cd17ace5efc467bac3cd1a1a70c7b26435bb81ef3fad65b6f81ff64804ebbae91e323c0b1464efa" },
                { "fr", "b0954e5d80879823ef62b180a921379e60d220a19dabe0506f3d6e1428140166db6a1652c0ea8e2202750a78382a931db5205cc2bfb2b779ca7d67d7f03f2ca3" },
                { "fy-NL", "7b88366f6ebea9887d1e82e06a56a4b07413a367108d1519c1f300dd8df8a2da1c04cd5f7690c508feaa482d0d369ccc9ea61fdb083ba50dbf7ec2c209a8071d" },
                { "ga-IE", "30ea6d7d22395832225a027ee37392af47be2bdff029bdc01d4d596730991573c2e0415b1df506505eb5d4a9a714679fe9f37b597621f888566c06070a22f5d4" },
                { "gd", "33ca8254765b90f7c337004df0d78f292f8ccefd2d4a61c78d9f81f10a6a764a7eaab336f192a438b6ce9a19686aa3238cef51c76164b53e49b30a9661aa0c44" },
                { "gl", "8907cfff8ecfa3b62d804ad0ab3f8a4bf5ef2175c8753d388d069eae9bd6ee748b6b23628bb8e2c84644b770074b344d9c11edfbbf86a5b60c9ef9eaf6128051" },
                { "he", "e79bfdc5b15f53dcb87684256f2ba0d032dfed4e0956bfce635970ab023339f38bab23bd393d48004dc6a3dd0becfc8444080fee10831397e6f7805796943911" },
                { "hr", "8d5159e78b7cddf182f10ad00ee27c964a0eb633808a7a7051ac11ae642735cd0dc1f71ccab9f4a2e73b4cf3c6b2e6b2cfd5a57b14dbd3aec520a1e59a8a66e1" },
                { "hsb", "b02f735072c406f9a69dd055487925eb4a71d58a29f1d1a38f7d5125bf4ffd9a05d8ffa8f1d4cd719f8a7a13a11c2ae2d951a1244b02d810dc9b1c234b2b6125" },
                { "hu", "5a5a4f81c389c7ea22006ee60285236b9806edf42629854a5144c3fab3309a23dc26764aaeaac249bdac3182f9634a5f7585111971ddbe3b130ffb7d6d5a066b" },
                { "hy-AM", "47390bd902f632620dd2a8409f94a087f7ec5b7eb4e01991ab758bd150c5b4b27239aa93a9f7e41129b83b5c27984f602b48341262a109823f5f71bc511383c1" },
                { "id", "c3de34bc1edd8004cfa2a27a6b72b843939d51583bbd8b67d1c9e5cbd2da7457405d156bc5ab5006efa353676fb3a42c18e84556b38510195f69704aebbd3009" },
                { "is", "9e28d0c969e0945fa27efb5a0c36d48e140a80b60917521ae40a58973fc544851487e24e0743f93db488f87ef318e9ab80ba7d282969fa2f9daa83d135ceb37f" },
                { "it", "235f0574ec59595e27169e3e2c2c3faa15fc271d4de8d3cb786e9aa535f3b003049cdc45093e3d198626132cd2278e2d4b9cfb3a130c1011ccd6e124221bd737" },
                { "ja", "6d0fb34fe510bdbca369faff60d14a28b6c34907085f7cafbed605eed2da1453674a8527f42ed336c7d0a1681e39c7d7ea6caf36090360984ef48eb1c2e0aaff" },
                { "ka", "a421a8b5febd2b6b1aa15393dbe891f346d53b5636cb04f744a1359ceccc02d640b8336cba94ba8e66cc4d95b7112bf12aabbe67a408e5db1ec701d0743804fd" },
                { "kab", "89157825408111bb2d5c733d104cc27360a9a75f431a28973255c09e5f0c3d290a1d8943df07286ee24e42c9003d433e8f509903ec097221cf89fc40e94cee64" },
                { "kk", "7afc8d87aaf76b0710c0fa93b89330e8cb06099facd3518456dd539623a1ca761b2abf2261a0eb4761819d4478056ecc0f071056c7682e4f6d8c069d14af7b0e" },
                { "ko", "e2dcebae6b46a8ade3987d22227a0270f82bd3584a0b5e35a3a520bcd451e82d76e7014ec0134a6fe1d3066801bffa07a15ca6e2bc39530948072c6e04c21341" },
                { "lt", "d5bacca00ef5e9992aeea563755fbf1761abf6a34467462982b7b2bad30108473e0854d385e65b4dc8309af4f64989f6af67f511b1db8bfee93041e3385c4fb4" },
                { "lv", "86d63664a7efbe1a2127cd846df00934812a89fd9c912197b4e7f75bc981bf596f50bf5d5137697d9603f45a82c15c7514606128cf4dce4997ed994fcc566e93" },
                { "ms", "232fc1e300933e9ffe917daaa2621f57f9e3a93fafed97dbe6b96446354328a3c30d6ef385e25db70c2905f37792ebfca726eae763fba930d1e97317b59b3d8f" },
                { "nb-NO", "b9045334e9807d6d8865d6ee10c589300c42e331cb420558960d4e65c19a6f843e036edc30326a1e1cb8f610c0da1ec777cec51e6f54bab8026413114e6a92e5" },
                { "nl", "fa99f91c77dfa59aa86abc4d77bc4a613221b702cfc4c3b15fe58c3c8c64dcbacd6d06b836255e4a59eb94079c811333e02b2dfc1be29b2aab41c9ca4dce2c1d" },
                { "nn-NO", "bc3206f84838e6da5746853fddfebc79296acb1efc948b627b0d6437f5ef7f8003752b13c370926af3c31c941a57d4477c6c14b98197e68492312d5f13ef9559" },
                { "pa-IN", "5b98976933df690ec8610c267aa5dbdf1ad2c5b4a19b665a20764d1f8e09fc72fb0af334d11639663570dd8628ad4bbbd595e86af13af9ec34129f8faf06eddf" },
                { "pl", "86704ddc8f51d49ea4a777f26bb840be6015884e67a943275b9797dca68beee38a7f751486f0b392a88effb3e0e9a5c031396294efc5577ad4f372e1e18983c6" },
                { "pt-BR", "9ad6e9925a5397653c00badfc7595019f3412a6030fa717b5afe2a90304b2c0bed38310d915acc51142f88f96b0d7665c1120f3049d99fffdd5a64e6ea2cb168" },
                { "pt-PT", "b79f05a097a3573642917ebc0e8db7415f535af4595f030bf634d41403e155d487dcb1cd94c26a70bdeda85f607e606c63abd0cbba931ab194945cb5b5dad675" },
                { "rm", "4b7cfa0efaa590aafee4dd17e813ef0cc5799a2b623b922f9da1d19f1b160e4130a0f90bd31dacfc58b23a26637fb8b96a3852aca43938400d19f60fe9f5d725" },
                { "ro", "6969b0129a985020b15066989fa4e160f20a8479d6382869f926458c573efba15444ed9f8f6d547590622e1b4d7a341dd67cb40124c15b1a4dcebaf4bc28ea26" },
                { "ru", "81ca98414641da3b4e3b9aa63167bd5c098001e336d93c8c2e9716083efa6c4c391450dc68f61ccd9257259ae6068040f57437248a9e3a1f38a6160c646ffeb2" },
                { "sk", "c43a9e51247cd3b77b189ba35fd5ec030d0b0acc5843e535b07ffe4de4c6640c554b4f2723bd6f3b39feea78d7c43549950dfa0f3f945eab5983ee5dc0294375" },
                { "sl", "bf957893d72e2a4485d4dfd78e437b705aea4bfadc016059d7771df0867775885519f1c49fa459144abf4a6071b7100bcbd522023081a2896d8de38bc0f46519" },
                { "sq", "d7f9dc06d0ddc566fcb6f88d80dc10b96f191549ab0b551743cef08d8d2f75a3398a28bece6f9b96184ffc487440f7d7eb999862c59bda131562fda937d836a2" },
                { "sr", "399318bafeb69bf81aa6ce6134a2274dc7d947e296a4e419243a919a93e6d5bcf1792ae41581897ec460e786ce32dde883e0ae05c2cf61f20d358bfe1c304480" },
                { "sv-SE", "3db013a3af647050f4aac04f2a3be626c0a1ae3761512adb674faf112b6ddfdce71b7a0f6b8a1339c74d9b81fa0f6ccf4d8bdb9ea96de3296799324983a49c14" },
                { "th", "4257cdf925bde605cea7c5622b87ac7cbbb0888114c29b5be352aad49358b9313f02ccfca5c21cc8089af5ac1bca76bd25a7341226200b4cb658f940546121d9" },
                { "tr", "d163c1abe8c2dd8463394f963106e03e8a5cf2dc3bcabbbf84806ba03b0b2820285ee145be5187f65b45a51570451e4d543b7523688ff57f8fc93221c6c1da80" },
                { "uk", "45aba1775789aa88aac918b80873ec38960998a382a72a99dde65b091f135cbd289648ab017c3d394578fefd9d23045cb438c980fac5101d43f5492c67a793a8" },
                { "uz", "b4f8c6bef2c8a694b19c07814511ef5a3c88497a81c6d87abf7a8d1fe494b8bf564b1febd6b7b119800683ffcfc627047c5f37b2d4e24a5ff0f762cf3517d8a6" },
                { "vi", "d1939138af797150935801f6e86d7eb72700f6cbaca9ee7ae1f21def770e0d27ed9624b8511c4c79bf9e1e3cf52dc1f9afc48c048632f353396c77c72d0026be" },
                { "zh-CN", "00e415c352f313be5774b9f68e25255692d9166dd829609242e6d6d547023cf661f3ae65034e6bca5fd6c98cad35e819fcd46f34996e30a96937efe0e20bf8f4" },
                { "zh-TW", "a7dba94251e5cfa1c0bd44d03a802d0d8b267e5579db5847ba0e20982dbbcc96a75d703d85fb6516352015985590a6dd10e3ecefa69901808172695063967256" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.14.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "27cf35140a108fcbb9f11fa69fee5c174a8789433e802132e615a406f1952858645a370df4b29c957fedc8cfc470907927e7babcb45e646ae906469442689a5f" },
                { "ar", "b8e1ea2f9fa87073cce728f14ab3149acfe560f0bca335cb14e635f65a9e5f1172fa953e0557b61742f522cac3b9053ec8d1613d62ec65b5938b8f9c8b36cc15" },
                { "ast", "b5bd056025678cc058aa6e3f9fd027285f64b026a4135a6cd7c015d0d45be318b829ebac372b4cf0288f8f077333e4463ade5fbdd4ec51d9ab4d4bdf35db0aaa" },
                { "be", "5b3769e755025db9e64814761ca22729e3b36ae898ec0e0c3ca9aaafd28ab8181fc3269e83c5a97900a0e83cf4eadd1c5b567ea5025b13dedab5053327c505ed" },
                { "bg", "45ceda0ce095eb5490c0f3b66da0e3d43cc6d5c16e6f9212f1861c2252fe93560919cb58f4b3bc0da1699756bd58ddc21a01dcaac108cf7ad40f99d91203237d" },
                { "br", "3d22f8249a5b6730761944a29bc88114e79d5d98072a582d43b0ef8a8c5db80e4c7e29520bb5714eb5ee72c842f93a78e2e2f39fd5a9d20bb297d447727224d1" },
                { "ca", "e0d0464e3410aa0163ae1db75b7ef3be6ecf3163ac55bf9903f1af7ef3fcfb94cca00bcb5fdb11485ebe4c171155d8d95e60364a156eb5880ff1b5c20046dd91" },
                { "cak", "2902b31bec1ebf4c1c915c09f37524591a1cd83104d2a8c7ddbe4be7782f5c7bc4977e3c31e88e4656de78be3f620a51a199695417d7fed5cecf46a58079637b" },
                { "cs", "ebba2f0caf847b8eadb9dbf3f51e343e7500210b216020bf95e7ae52cf3a8b2fc25e44099b2626357396fd5c5b87cb831017250d4dfb1287a8df79127dc7de94" },
                { "cy", "71a1fbc904c571a66a4165d02fd93710a5610d5480301d27549b91c618d5be00eb16a4ae580cc5f4592d628ff1b2aa669c8bb54dcb017d6347e63797e701bbaf" },
                { "da", "2a28e1f1064874e1535b308e4d542393a2ee00caba8ac970058079fb6e3ee60c79861a4e699771346c59f00291ab33177f8de88a4398cc1366e8a9e7b057d07c" },
                { "de", "0ea77275f9319c21fafbd405d0b4d5080416405f62a355911a2df30ab70c6b54adaa76cf8f920fe2251a229109f84d39a179a6ceb096451f0d288b6554e6afbc" },
                { "dsb", "3a61aab4e7a528837be7ae5617231b618b082a905369302f6d105f5b7e43207fd945732a4c268d943bc6bc40321bde34664e002a17cf95c99a96661ecb19e47d" },
                { "el", "7730b0a7cc72477a0757d979378a7f96fcdee75358db77029ed94cbc5725f4d0f8112800265d1e259a59ba19879b9c783c6f19c5cfc5841762453b23106d239f" },
                { "en-CA", "aa9fce273d2f699f861efc5e453ae5d22264b4bf27fd533709d6089dca6a2ebfb0a846a42998c73d8263e0255fc18a1bc4021ed6e4d85cc8ddb52963ec42f636" },
                { "en-GB", "d830832481ee10e1f08babfa6489e543848390b88325915f9d5a4051368c604901a3b5f1fa08f76a494d12b3aaf83319f83d341eceba703a98357eb608036efa" },
                { "en-US", "e08ff061b5e94487eb0cb7399299fa1fc38bb713fa17aa336524da498243fae37f50d840c9372cf6d370bfef35add2cef99e0b7a266f323851a5708980f7c2b2" },
                { "es-AR", "1fd5a7a72f91689b6cd048893fb5bdb5dbfa3ecfd49181688f370c8d096b08a1be1b1ddaedea455e21cda967802b4e7fd8a7176b458e275ec2d5226161a3066c" },
                { "es-ES", "483d3b8df95684ca73ac7db33ee5f6249fe17d1c6a779f8d01e60e795a9d7983f72fdd43cb8bd2215cae2e6f7026b64f4baffc1b0f3f854762094f141554404e" },
                { "es-MX", "0e099f5dd7a7b78924d47d6a8fe015858109460953889c6fa2449275405f73308ff0b39c6ee2fe4ae7e60c86e0b0a01eb3ed05d9165a8e7d909fdc397bd42813" },
                { "et", "6a5b3ce3d2511dd0e7bdd14d6f6ccfc00ee1c7c30ac5a54e59feaaa27b3a025b57696773c3e41a35be6643c060bf5c132c7a3db0c03bc0112174e265360c92f6" },
                { "eu", "caf916ef44664fb7b02f5feac0d805f70a4c5c10f6f0b6dc3ad063afba856e508ea0da8ce085ff7d7f2df6732539dd47a1a0b11eaef3b0479b214073efddd310" },
                { "fi", "a2e0adebd7e0aec7ceebaa8f731e3bf3387026f18faad3a08b40d8d4d07272a73650bb247d93531b0e1b57c2acc4e905ac640e8a22af35db34857f101db3d995" },
                { "fr", "699adc06d61b88dc894afdbc2a1e37e3a2fd2e85e11ef7d59cfa7e4ba72c08e10911ade7652922e8fc0ae8a7d697fc2654cef84545767139139f2538a45c70a8" },
                { "fy-NL", "1cc43935e2714ccc1a725d42702e33d87030cbc81e490386e314b46c4693ac3d78f54087bbcec9931cb10b845d26c67763a02beea2a5531e69f7af5444d62ec2" },
                { "ga-IE", "59c024c0d20ffbe1c6cf97beec02964f112c23ed406b3c96417c4af7bf89253323a90ba0140cc3b58e222b7d1a9f9b5cca9f9a0594435b22f705f3831edd0c33" },
                { "gd", "aa98d9c399a383ce1a6577de3e93c36b9f83e83281c30f21d0018eacf657e53f652c8260c415af0fdca09680053d2927f45388ee1987c21241aa408e4c773196" },
                { "gl", "98c78f836e02e35674202b54d4ee73b9a46550111eb523463fa0dd48b76515ee2958037b3dc6e3f1798466b40c405162a5c43f41dfc92251e838d1378158289b" },
                { "he", "ba39308c14e1358aba07aaf76aac4d24ecdf94c573a6facca79304b259b20ef4e02585d03e6a66af650cb2f2140ba594cf47ddc1c890f8c674873caa9a6e6863" },
                { "hr", "21f129f303f63399643fa57cb4d7ddf95c0940e4c714520aaa7d2582020148a94930c3ca76dde476e21b6498809a56642f005afb0bfd26d805536c8c5dce14d2" },
                { "hsb", "208e2e8a881417ac185a9208f02f90ac859f74d2885acad189cd6d91d654770cd5dbe7f504ac8a4de2690f1809d1e3ec99553434e8f159997227f8ef4239195e" },
                { "hu", "ae6f2862187ea80d4af4a2eec5aedd74cf6df99299e91616c462b0d23700668cc96a29762e298703b816cd9a0645ef8ec9910968e103eb0ca10db56596183f4f" },
                { "hy-AM", "16c1e7db1489dda20b194795b7afad05dd9575e00ac137f4bf6b7171c15c3cdad3103df65c46caeb9dbf25439a94cf9936a76aaba28f116be345dd3479de28e3" },
                { "id", "0c7459ff3d1216b0e86ed77424a3506d1021fd0909dbdd14c38a81653e314785649b0f2222feedc23f7efb91885a5d20db237f9dbd81b6795e5df5609c4e604f" },
                { "is", "652f8dba3b3af1ff5581585e866d55b73d225ccbad9192e36e15d5091e12b53c654796ff3d5e9cae0a4b4d43b367de6fd066f672d987698fcd936d16cdec3888" },
                { "it", "c0df5dabbc47d1d639bd2b182e4eba43811c3c6395e6ae7b6fdf86b78cbc2ca93680038f7e6ad671f9ebac0c2d637fa01cee103d55dff1292dda8042e69daa0e" },
                { "ja", "a7e357f524f0f1cd958fcea8fd56041ec00178fb9948080b226abca22837223472f30494f5bac305d7ea63f16ea819db2dfc7e0d1ec621738b02887c2901ab68" },
                { "ka", "412cb50d2c6f804e154629b4998f0b20df03939b954e24ae461910ed628dc29b8839ce128c94a83206193abca22d38fef85c6d9d9848137f3cbf0aff00587215" },
                { "kab", "6505ff50b5af912323e9173eb6eb335bc30e1d227679a2b7f26640391ae03206cd3cbbd5f884f65dbc0e40aa4b630c5441d8ccadb6ea0721f20214af889c80bd" },
                { "kk", "cb989244b8c820c941bbb0e72a3f541aed870cbc3f4d4b6f10a22fcfa1710a6eadbec2206ac5aee0fc2f73b9563f5a567afa9ebbda5c5e655d124b6d4ffdde6f" },
                { "ko", "0fb0b1c6c65b2bc60e003818f8fe35311f47357ddfab41a0ddd64185523d9cf65801553635be7da1ab7afdedbe18b2c91be028a838b515d2ebaed8f47b43ba93" },
                { "lt", "3f0d6be93b2416e747d133214e20f1d7ab2fa79dc8f4c977ded69775ae8c388009febbc9d381aaba7724e021d71f9a2a437ccade3f0821b3c0059adfef354d01" },
                { "lv", "6e7632d2f3077d97a046c410415c24d5927d3b5051348e7717b6c09f41bb08b3e13e3fe8f9ddf68c92ad1b075627e7155f568b320c2d3b2dce18c6081bea3a3d" },
                { "ms", "8f7d2ebeda5ed10150c4f8fc2e1b3fcd7c15a5cff44fcb80a7f9289fa1a73c143311fe3e9810f4d5921eff287947048b4e9f41ca4bbd1c2b0b6345ca993fa72c" },
                { "nb-NO", "8c8320dc2b1a6c62fe4fac60f16c43f84eef5301d46828ef4d17588d70d0a9ea89d9b7443b2d3cec11191e59158e11e883838ee0bf713b0e8a8065510b20504b" },
                { "nl", "18249162d63b7ce4410b016a75ba01b390c65045456dc1358d9adb11b77f67a128b1442480e4025b03abe0931b1738e5487559db925069274e1afa36ce0fc608" },
                { "nn-NO", "ed64e80c651039952896336b15745636ea9f306d6d4177106c98912fca838b387e6ae6ce3905bce06e1eb2f1ffb191348ad890d64c21c267a17d48bc40be7013" },
                { "pa-IN", "971eee8a09a4a5efabbe33373feb0a063063eade88ab265d9d1a9fffba4aafefb64cbc5c74b6065a437113f3555604b36e667a3c17761afd45ce2f398018d21d" },
                { "pl", "61e639f95268d4f592084d408703ca960a73d7ccb80289137c7ed28388312407efe9831effa98d55861f069f5cabd60e4c59689cabbcb995fe0b0bc3cfe690a6" },
                { "pt-BR", "95882202a9b01fc319ba77fcd0d2ca6ffb03a1727ebfa3d879cb65d668f5cfe3ff348dac638bf0a258d1a3e41eb292555df52519b1c837cc4909713c0d7cfbfa" },
                { "pt-PT", "193e95b94714268fc928281dbab15bd707139b5926bd7d6845180c8858ebf106a9dbcf3783937cbab641ca4ba33dfdb3d2f30491288f57b3e6ceb1fef070df0c" },
                { "rm", "33d5b0258ea13b213b7613f1d6dc2c0b42daf7f87abc1045d5ed390554e1eded62236cdee2bc66f7b3352850afc1ad6930fbd0ee304edcae881c018cc0a15b68" },
                { "ro", "3a74cb1a81b812646adaedc22a96ff422d8b52a1e5311090b9bf96c16207429a2d0a86b6d0e4858754b8acbaa27d97bde851d2ccca7aa375fe367c4eff77c2f4" },
                { "ru", "35617c18e3a1b53b8c0a4484014275394fe8b1c8750893ebc6d9114c013d704d989cf90cbdb6c49afb6750ce008fdf65da041add117e00d3e56cd0ba7e728480" },
                { "sk", "8761a13b1bb06cbd2828af41ada298a9357b1e7e82975a877151df88b03ee64d3933c0142d1ddabd76f7947d4fc3d62a8a79695282b402b36a96adb81d28d466" },
                { "sl", "70192f35967a3c314cadfcff8a5f25796ec5d987d0a87534e01d287e1ac062256e265d9acac8d800a90091a5446baac0461f75eb4468be135d481fda1f34cee8" },
                { "sq", "0a11d6e5747061edc4b97b22893f9c260ebc0d1ac5d02105ab592e7b7a434c090dc7c0193f24d0c0d206f32a9112470eec4b49d76744b74a648ba76d9890b80f" },
                { "sr", "ae8aa2c47e1fba304d68b2ea8d0f5c258d47a65e564c772a027d8c26f83c995c1077f677e4748e6719561cc0f45390c5aed5d2bc37f687d788ed99735f3a1595" },
                { "sv-SE", "5e68036ac23838d00ce9a57a6b8e3e06fd2d7a3fbb587bf1b35814c6b6befed09f230e8f65931b6e2a2ee02ff139530007e62e66754ad1ac4e790e7ea4756ac1" },
                { "th", "fc4a556091bf731668b846c3476a9f0ad5051c3b94abf62ab39cef6d9803fa903fb6226f91bd657436b8b3b856f5e57db92a0b164db6dafb6bec80bffcbb3f45" },
                { "tr", "44eb19618e783e78ea4532d5aa88155af028d0fdac39a215229d81382c99e567f71cff88311291251f3be3f6f55ed5f7523210fe50aa8ef094df55507c4b2397" },
                { "uk", "9b38d770333e73a208fc666ddb78b2c9c05c26122c8544efac4635d5c9878b4628716d7a135e11d7ab02a7053879695caceeb587c18be1eaf9a0df516d1103a4" },
                { "uz", "6502c99a3d6b17cea5f6ab2d4dc0bf8dc4ddc3fd423555529120e32ac461a73add28f85bfd0fb9a5747eada57051241a397d171a83525393ce5d9986b4265632" },
                { "vi", "5a2ad6a07478b9daaf45f6e254e2978f6e82c081dcf62cb5a51239e92d41d31686b88edeee1c3f0b9a6003137e4ca6054cfdc22d035a2a03d1ebd85907b3b97a" },
                { "zh-CN", "4b4b72c924b290401b87ec76a955b287bdce33f4edfbce52581e8eabcbcc287334f90a80bbacc504334a439c6a099184cb11fb843fca94537f92f366a2ee8256" },
                { "zh-TW", "016f46a030086918514a91a4eb5f36f7b1b2791d3e561d69f85211e579a22f846d184ea9f7567d65667751120850bb367d0017abf72d9510ac67c7cd0c6d3115" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

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
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
