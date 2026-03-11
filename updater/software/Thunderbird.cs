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
        private const string knownVersion = "140.8.1";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.8.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "7e767493239bb64a976e0dce16b67192b2ade021f49c2572c38bf0e22babc12fdbf63901b8b6211a2fcccea2d5f1a1fcb1bc6fe9b58fa328433af00f88c37a4a" },
                { "ar", "e26f0bcb4c34caa6ad620b6a9de8b8e401eb86cf814ca5ef5b4ea606d08c41ec5c3518bf9a4870f877067afc17d9e9d34f358ccce4e9f57504d3198903cb5191" },
                { "ast", "5b16eaf013c712fb58cc86757f9c059c33c0bbe0a9ce494dfd503ea952e6af4c132de798cf18f82a9817e4742d94788dbe0fe9c221800982783a5280a3956e6b" },
                { "be", "15f7076951a95c458fedbe3e193ca82ecb2627610dcdea2b75e89e899b36f28b387a38c3d028a694b36989af5909612138398c496c501454bff0cb8501d86cce" },
                { "bg", "98f0493dcdf2f59eaf12b6fdc323b8e5248b08ea049b0a6a484a0fe258e53fb22becac9d6191d92f3fada227d9bc158a29cb7033d54773a481e2aaeaa7e7d504" },
                { "br", "0978025f3a784fcff559850f52483b1fc854f47fed9c586e1e1fd5311a1c55f2e4d160da1c0ce967812123021a06e9605e0db6f274a200667c619b7ea99e0cdb" },
                { "ca", "76391dfea83505dedb4dc0d54787cfb2456d8cb61528ae4cd00efc8dcff37dc6c70b99e01e1c9a8d9ae3df87b1bf433c8c9498135ac9fb82df9b7f8ccf1ac990" },
                { "cak", "3f8aaa3811abffff70b25f1ee4e749ebee13c5ce042e940d673db5bc1180f3e870abeec69ad0b4e849c79fa5b5b3b9de760aee67119efe4a13450c8bee7a737b" },
                { "cs", "56f89599f303863e07f333bda6f141510f1fd16e873360ccfecc6789e7c345ab762f085d7982a308c7f824442e31f280ea7e021045db0b3510d35805d7659e61" },
                { "cy", "82f74b6679a0f9e8c9b87ff7032db3944a874b19e7274161d44ff30c0b219400c7fdba2eca182ec1c81d7c9358bc83c2cd5cc5a7126a5295678ba91036305e15" },
                { "da", "8e8d903f0f0611a44cdac4829a982f383d1cc5dd796b9f15fb7e748b6ca426d8da9569688b9725cde2c1cd5c4814d67c929d05f55ce45f74462158c8550f85ac" },
                { "de", "f59296509d48325230da7e16ba48b389e213ed1dc59f32238efb495f0858d03dffcfe80ef1e2e5ecc2209594dbd42e1817ed6b195a8c6e85af13ca4381882396" },
                { "dsb", "9bbee9d6c7f1b74ad5158e06afe545118bbcdafb2511fc9f0ce5f28fbbb786957c32c71143683432bb8ee07f839ba3e8cae2fea6ec10daa25f5f2361654fde0e" },
                { "el", "887d6c9582893932ded7bc06619b827f2be60d6f269ed201d93032d2be548075095127cf00ad84160035c0065abef7e17f23dff3d8ee00b98952eead7be7a613" },
                { "en-CA", "fc5d30d9422c0b8ea363e0294d5c051e1915219692f40740dab214d8c980d02d62415497d7aecb9f59dd2d8b09250c0cc3096cb0706a7e29298659daaca10b73" },
                { "en-GB", "e5d929518502bc0c136269c00b1e597c7b96c785136f3ae2f81a216797404ce427951c13926d6025dea6284a4ef3f5c4930d5f9336d1e86e1c050c119c0b1fb6" },
                { "en-US", "aa2a751f517e709f79330ee263550aa17ce6b090f0e43e4f3a0fa1a44b868766ce5f0ae950c1dee6ce0f34439429d974818e476d4722c817d80fac195e462eec" },
                { "es-AR", "8df73b2b2153e7d26a1139cf646d8af1cbf02a4c03bda0469467ace0599aa048a77b600c557baf528bb48f51c1304b7223fb631914c2bfe66f6da9678063a9d9" },
                { "es-ES", "77a6a6149e8edd8e61b39c07124b214fd011d7d524223cb76e1355d8b4f5f21f093fad8439634541e1bd1cf841f87a9f3b6ad634c5c5e66af655dc1993de9099" },
                { "es-MX", "6d9327e45566d1d45ae9a2f5a63b1a92768ef1e9906cd08145fcdee3b0570cf10cc69e5cec4ee69ff265c6c4b4c84daf0ac36759568df607fb21f78fb6c99826" },
                { "et", "e065f9ca8299bde0b09ebcf3c448d12714ef3facb9b91803e8a06874d96af9844637d9afb4ec213385ea5e337e0ac80598f48c0b118cfe8c734a0b01f6690925" },
                { "eu", "3a30c5e3c2976c39cab3f9385413e7b30be869056d79ee04508a7dbd11fcf4e39020c1a09cb57d3d6fa7c56407195ca05d9e185d127a6d38b72ddea53683342a" },
                { "fi", "ae2a678d60f5f6ef936e9ec74202a64049297a5029244ed81c0e6c8b33ba9b7bd246f7f4c4ee4096034dad27b3e87cc32c73f0b40926e9f10ee611ad22f7f661" },
                { "fr", "879959ab5d2125b69dbcd2e0e3a73bb39906098b491babe25ba371555c75006b2d24ec3bc26f92516313eef79404b2359f1473d645d2bef189a30fad1ae2329d" },
                { "fy-NL", "5ee9891c8ad2e3f53cd691308d855df3bf9c4c40a5f65cf008effffd211fa14fd8cef643ba89932d7a7494f4023002e030576b3e5d48986d926b1aa2bc6ef676" },
                { "ga-IE", "5a4b5c63cc81c540be30df4a612f7b962a9a8849b32cce5dff003c8277c5c7b6623c6743cb193924d40324a79e2b379f58952d6fd39549b0afbb9f112056ada0" },
                { "gd", "f18f5dd348ca53a1265324440a73836d5ad7538177ab33b472a48a4182d5b4177822d04dc438c0686cda835a73b791d13ec1445b429b44b653b07d1c6bb8bd65" },
                { "gl", "2e6d0f81c76895032b9318fef9f6a49afc22c54adf1baf0420959cd17cb1a4a0b7cda4d89928cb0e5e296ff3274c0e3e07e9bb48aaf7a6ed12dc28a8ed3cc6d8" },
                { "he", "50cbfaddd7d70417567c2fd31a9dc8d9af56a2cc109facec2d44d5586ca94586d8fd22413dc8697be2abb40b9bc65ba089f4e12adee1cef7b4de9a73317260cb" },
                { "hr", "f9d94ce7c8b6e0579b4dce5772086ebcdc8876cd9cabd26beaf45a054399626629d0c1d9a39a182f7bc00ab1bb7fc92be84a682bf2731e768e33e58ef51d076a" },
                { "hsb", "7c6a33e369b14690b0c768bf40e44711a63bd582d4888e1582e837f74abcd632bfeecba6407d2710d4b72f2cc1c5da7cbaa2f3b17e6bc35792d6b5b585a2ad74" },
                { "hu", "a194f18e9054d844e9dbe20fc28be8d5e57c86162e04584f26ba7db30c01c64db624e5ae9c61a56f62f95fbd8384bb3e875bca4374abcc6f62ae24f2e2a8721e" },
                { "hy-AM", "a39816c798599ea349f8bfcac2978c9a0b5fe6114cf3936482238431cbae41b6b6233292963b4ee5668565fe52188cd098813cdfae98449ca170e3c362537e7b" },
                { "id", "fc26f335bacae90d975368cf23f23b4560a71f9baedad7b41929b3ee0ca76b58eafcc069d50c9f4b521b329c3d865147a5e503dbbbf3d2a6f7eb4a76cbd7ad6d" },
                { "is", "50df1f3f72a07142a56c367770ac883340776b9767199e230b929572bc096b6564410295d47bd370d548e183be0959639e5f35e1be61cf011901334e2eee5e52" },
                { "it", "8f4089566eeb6da129e924810956edd72fabd5028ce74b2b48670c94d3a612dd4df732101b5a5cfbd71146c1fcc5e414a8ddcf922f3a82f5e089e9c007c8b356" },
                { "ja", "d4f65233930fdf4fa26c44d51fbadb575d65596a48f6116163c5f13cb94259e8f2b51392bb89a5b10a900bbe27318a583caf0ce8a39d639b0e4d287fa9a5daad" },
                { "ka", "0001ba265620789bc7bb9d35b0c9e8ea90125654a8cad54b5708d0139492e00700361d6b6b10be6f4c180f2ee9100bc5e0998e0bd3c330db7bb9fd88ffe30a89" },
                { "kab", "4a2c14119b42bd5f87bc99eba7982a44e2d2917b4e3ffd4e17734dcf45ec32dee95a1dcdb549fe57eb3db49a6605674be7b6096605c40b0882e627eaade7b247" },
                { "kk", "03659fdb39d9dfc9da6d330534e00bdc4a39a8f1c713048c43a04029aed7b9ee53807e7cc6b671f5cea2bb3333e638bdab38bf3164772bce70d1108e6d205dc9" },
                { "ko", "da79e3414fa67ef8803a68c8c37b8f1cfc44755effd2585eda753c805c6741d7204cc5c88c5f4a67425261a9d851dc69c3b93d751e6bb6e76290b2c378709bca" },
                { "lt", "04170dd878a5c21ce83293b85c5878026e05a871514fe73b5f6548ef32c5cceea0a2c0e592d31dc120a643e3a61fadc24bd8448c6a029ebfa8c8299e4050bde2" },
                { "lv", "cce207326ebc11ceafba3cf68ce68e8223b311f2d4fd660443b8fa5a7612b6785fe6dd9b925c54522a343bced560937073ded1ee869101869fd8f809fc795060" },
                { "ms", "be53481ab5f2fbdc4e2dbead2d2fc6ff3c617e0744d3840573854f15e9e7b4f301cf7f1ef74f9db7ea28bdcf6932cf1361b58f962aae989063f17796f18ab58a" },
                { "nb-NO", "c53e03978fe358ea503e3cc6fd421e56b35f077ab365c86442d35ec77c784fe3518a0a0500baf37b2651a6c6f8f10fd3e1175969da594c599109128d29fc9692" },
                { "nl", "17633bb14f2e9c6e4ebd6249dbefc60dbdb7fec427d410531bcce7b1a36985cc62bb1f02418dc5bc6ecb53db6a9f6c7a79893e0594ea2edbb8932ed4a84761ad" },
                { "nn-NO", "5fc974fc23fa445fbaeadeef85ad83dcb9e96c556a4fb428218943c20df525f23f62af410ed5955e2bdd563d6da55efe62d31c18d8f5079dfdc31811414dc8b9" },
                { "pa-IN", "f6621de0523221fba74f17d34a51bed4b36134b71bf21d0963ce770d006de7378f9e77f2485a30c0457a53c23a2fb4cc56c795f72a66b3a61e9bf30972c786af" },
                { "pl", "e2ec7d56bc27b3154ed8a256fa3da94c0edfe7d9d40c0a823877b0158da1a3a90236bad1e230ae2781aaf5a63d7c981444b2340e21d3eb3e31094148d8601a6a" },
                { "pt-BR", "c53cd1f781e09f013003e4f79ec74106ae8c2544418b70a103f51130e35b66b693085bbda383c6970a978c87ef0f1454c58032d2eee4a09927e94eb4f3261fb2" },
                { "pt-PT", "785f2e2b35fd3318f481e88daaa8621934ea7ed8d71d4153f90de4a9dd26df0e0ebcff5887dec1076ba5c5a1ab4610c252583e61c49bd71f94c2e95b2cdd8a98" },
                { "rm", "c54a191356e1f9c58a7c5f98d30def7f21a9facd1b32ed114fb66e863994d9a4f10c71f3a0b853e73a85238da93b7bf4d9df66a66ed45fe573ae91241a0de86b" },
                { "ro", "44615c570fae1f615be821ff6e5851b7ab65519acec9bd9cc90b6d6571276c5f987cdc046ff1fbd196eb3b0644e862f2eec98c06d1247742d81e385ca38f5d02" },
                { "ru", "11289435673e1d330b8862f224f722ab4b9d1894886713df3a545d51776468e2eb5a3314df485e3c78f95b943cecc623d32428befebb683dc4d8e692d9f1b35c" },
                { "sk", "4ed7c9c3ce9df0ab089f46b55205a1f17eb4af71ffaca2bfc0edc95f2bbe077c8135043fb01294bcf2267b385e1d3164e6ee6790c563fba9c8e6d4d52603074f" },
                { "sl", "2bea6cf8d0c16b1eb11be3b34cf8db150844b0cac1f6e9272f3901c62501bbc3d7706b75fa93e4f20981d09649e8de1ff822d2735d90dc7cfb33dccc17d58959" },
                { "sq", "6b80dfb8e528d833ea3b66180bf7baf1029145a17b8feec60b37c43e3318602ad071157c1ba57d2636bc1fd616d323828f82e41e6f219f1aacb48e2704212f97" },
                { "sr", "5d4d26fdf0710fa09a86bc299709df1573f4212e6732668df47e953c6a3576d4cc66bcc1796455c7e1c29425f99ad10db6830f93109eb4386fc458a3795ce65c" },
                { "sv-SE", "e937dc635fc75205e6842846fc152c76e7e99d506f1178348c26f6405f5d8b30cffffd45e1d2f9ab97b97eb0fea5f2454a75b55fff6b67ce1c8099f2721a866b" },
                { "th", "4b70a533d4ffb5c028a3becd950d094acf5779e02684f5624540f69d7baa21760b399ee2be0839689a18f880c47b11f930e019eb2a501d3d1875a60c303199d1" },
                { "tr", "b5e3861c11d365f70f2eae86cfa9c99e775ba67cc7ca36f8a89bcd8cd101ac3acda368205e7ce0493b26331730888f730057ef86dca7ef4497d213b442ab1303" },
                { "uk", "fbf8dc3b7f8da7d075a776d57668d3046faf2dc8feb8583b38755dd9995e9a815afe75755a74c1bb3c867b96cd6c8e77fe499fc22040f47c460d7266992b3358" },
                { "uz", "6800e04f4ccfceffeff3821828770c27b25ed51f5d0662a9de25e27500d3e2d24928b4d4dd2bb927b1d850ee0c8a917bc2f498d34b36cd374f2b7aa07d6b2dcc" },
                { "vi", "279c8e85b37eca984265140cda693f35f8039f9a59038a968fcb0f5fbeba28b386683fa2afb196b2f4f2e3b82f6d1693c992d8a77dbac6fee04bb0e1023ed6b5" },
                { "zh-CN", "075aec348f8f01b50f4a54f70ff88e0c52760a39b70f391d7ca78305f3b5f0e3625859e4f9053f25ffe59f8830f0c2c0919004358ae3ea9072d09cc4721a6d91" },
                { "zh-TW", "c86f1ac503a77c912bd0444e434bbb8ef877070daeb8efbb2adad8175a35b54ff788d4e97f1ec1fe02420d2c7b72ed33961c1b0cbda7937b1baad7360a173106" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.8.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "9802012d5bbc7760f8aa9ebd4f9b6021fc1643bb68f29bf1a1b9b3e044b4668e14a3fb9ccff98d461c2158eea9b9c16109d72349ab97ea5ba278db0d1d01d856" },
                { "ar", "5e05bcc14389398cd3e54fd891a24286a492ecd724308728f162042d6d40d66b0b80f16c598a1caa9eae84eaac2a775075756bf0b6ee368528c981b89294fbb4" },
                { "ast", "553e983ed1f5e6bea247224280c95c43f2490ccca11b2cf8791e881a3fdb5bc29c419265169d86c42c6332864ddd0ea5b998abae308e4f7c12700376a08c778c" },
                { "be", "debfe06d7d232db280a5cbc220f244dce3a04479a556f35c000dddd200be8f6243d605fe424e107d2342321bc89519231ed19ef5feb6b2fe9b5b9bba9c729972" },
                { "bg", "6ca54b71f51f4bbb6d24a8852253786142f63714551cd887c4d46cc082cc86a5bfcf174e28c48aaf18e8b6039560bc7c105a1d2f4e9aa2c85b639ce6b5a8b41b" },
                { "br", "a95ddb8f10979e7f93f117f07f710a83cf7da603670d76418acd5c5e95d532e9fcb05b5af06dacae7371ce5277b2ba5cb5d96fbf027b4a47815792ae0ea86d6b" },
                { "ca", "9502f0b69c180251edbd3ead782caad6fb74f9c4b0e936ed4434790e39a7bbbc53d193e5d812ab9c7e5280c1b714176f390c144a916a4e221c2e84af99b0b4c7" },
                { "cak", "b3ca75e2496a9d94c16b2bed435ca3c63819952bfcae42b2d0c832f2d64ae813b635944d4e0ab68f053a5aa529829b56a89fb9cab0b5ea8f6b411550d56ceed2" },
                { "cs", "6ca212d7be7c9306d134f3d4c0d4ffe47858bcaa661f88a8448f96342e05ff70fef89373a717bd115e563803e111d314bf74f02be60c23f1937a0c230976603c" },
                { "cy", "473e5a3f6a41da8ed532e07560d50f4ec4ee60c476d656621026154a526b9e444119436d0313c5b47f6d4a93f682fdf2f88fd5c04b3f7f35e41a240c3e289873" },
                { "da", "fa6c38a772d867e06643b0543ee698d64d8c35a82316cebf3668dd44e6721a7df9a76f942767fdfeca4000543e9e5db9e227c98a3b8a2a430343aea4dc7c2b6a" },
                { "de", "067f93ca2d19ed9acdcfb9fc0d0457622534806deb612ca46c38ac9ed6c6d5c37cf34fd8b094ea6ef3cd210eb861b7e14a92e96f0f7cbcafbf1efb575acfbf14" },
                { "dsb", "58a6c2d05121926b4d3cd7c7c5fdbf7fac2afed4cadbdaac4ddd8755c3ba682082f5c413248429e6dcbedb5cd97d914b6da8d4b068c6b941d979157093eb095b" },
                { "el", "8e1d904e35375a2d570f167251e4d64f5481c1f00fc47ffa355c63233c65df004fa29bcc7a4e959d5fd21ef00a56dbf74568603917ee3076725f4ebda719b50b" },
                { "en-CA", "47762ef3fdcfb6ff982a26bf9cb00686bfa8daad982f9ea3c67987a542221fa6f2fc7f58b60e42d2d88d6f2c1b14d7bd3382d29153fcb3a2e4d5a1701bc7b435" },
                { "en-GB", "e30fa04ae2549a5da3f2e1fd938e58a4147e4ce4031e5cd540198b7aad478dae5b9085d9111919c2d0f48f18c6c5c433c4f54ef16a780b5ee81186904ad27dbd" },
                { "en-US", "9186841193455417ecb8bf183f59d7d0b36a3696da7b04f1b3626caf0b2269fe9351100acec42827be2f0a6be304857389aa2b3b7bb0c24fef4dff76fea4a20d" },
                { "es-AR", "931310d3fc5a66494a4f17afe8f12a428fd9f276cf7a5d6f91607059a029ba4482b9577027c9dead4a043506d906ff4e998e80993453a058adc019acdfc7cd72" },
                { "es-ES", "e425705edc1a23e589c2f897943c203ee5d5b4dd8df3983fd2d938075427d1b30baa32c9dad79a1fece8c2f1699747e73bc797c7b00765595c974ec911ad6aab" },
                { "es-MX", "3a3ef8fbb61e4c351b4785b7aa2545173569985656eef5a6501c166496030f0f10000d14833d116e5345b2742a8ebbb7bb71a4bb875368037fa265e99a20e84d" },
                { "et", "3a1425bab28f1a0fc118e94d95d9fa854620c4792a4861d648f5df54736537600b5f9335c82f03182bc29d5d8761930a945a3ef1650d0c4800f120ef6fa8992a" },
                { "eu", "5b443d9476eb76884b0a2f697b073466a9cf10732eb00bcd362c50b91b47c1d315e4ea8e36844f1def8cf2a67ad0e88cfdb76e9b7582c5ce6125db7672c1e7c1" },
                { "fi", "5abf433db84d3f1676a9e0a5b7ecfc8f7153c1834ca35ec7a6cfcdf29f84426db08dcc1bce08ccf9c343260752ee6753e22f3345400c29d7fef50c5a4c6a3649" },
                { "fr", "e7d548040356b50c1b7c9077e59531519c8f625cd8a5d3b859a4f83a57a124633a4a9bce214b625d06dac91fcdf9ef81f559afd53bf24dfe82fe2e167149567f" },
                { "fy-NL", "4404c8a927bc7e0ae28d70642bf91ba6cd806bc1e7b65653fcdb38928dbd4df159ef88e3ee703e902fe2cec068ba9ebb4c12fd1bb9b4ab6379bbfc5d6a001b7a" },
                { "ga-IE", "4fe903beb9bfb48862578fc74ce9863afb87b9d4425deb4a4e2fde123d960c8a03d951ce9c57ad5462a95d67cb3ea84289bbc74218122deb3514d394da70910a" },
                { "gd", "a3458aa1cf9a565c7f9b46ad293d8a89dbf8f8ba6bd7ac78e99ec12b74d4c4c0a049a95be2ab63fa763f0ec90b39196456acf46cdce5ad845c81c7ccafce04b7" },
                { "gl", "bf2eef2585526feeac4b1e2379b873cd53b7d104a7b7878209c32010ff6dfec93be6622073b2c5b4a9e306f41c36dc868bfc67fc8629dc81ac7f92a5c42af925" },
                { "he", "615aa9d15c208ad75a7af7ff335ffddabe5c8b2391adf0236d0ecb52048574d9bbc9dc885dd9ae4341dbf502a8d2f71c5d07d293905659e48939f8b7761188ed" },
                { "hr", "0517e572a6a6d9478e3c01ef0551c0621f1155bb48ae2561062b0e268b14e64fcd15ee47dc649f3639f301d891d2674559fc33d97829eb5fda5a45a872bdc69e" },
                { "hsb", "5d6e23356a191e9cfe9e3de653d567d063688d0a4cc72354df02cfa55299052a473bd4034e69810e2bf53415d3bb258ed0016078ea4482cd3d5f035259eb5cb3" },
                { "hu", "69ac70d4450dd25e7f2186a58c0e1464e055338ea062faed253e9758324a7ab9fd7b29b8a87dd2466fff1d0db3a08960ae0ed8ebace31d83412d6adb6e787026" },
                { "hy-AM", "757f3eb61111875cc65366411485c200b0071a3524e22c4c55220eb47f3e08a265c7d0fe768cd59a3424d45b2342bcdb2ccb3685a144b97b83881f9b7c77234a" },
                { "id", "dd2032f749b400eb48c3875e4769cea22fc8a45b759bb1a6d454ddacebbc7c7393773fa14dff80b896f1f4a65be42c27f29a66af504454a743eeabc90bbb82de" },
                { "is", "6b43e5a7ad81427fb6acc6433a8b0358cdc53004d3653aaa8844c2fa9c257dd3e8fb93b02665185914974e32aa97f918454f70cf527f6d02b1d72fb128e4b36b" },
                { "it", "cec7791e7ec4d1d828ddd6a762dd1fd2652f496d4312b18c25a7d9dbfbe02daa8dd95ab8229a56700d54b7134aeace72e22fb714e64c3ae50d7571466ad91166" },
                { "ja", "c6058c391d44d666ce70ecb5fc143fd970bdc410a55d370f36993a18b74342ef276cced865838dcadb516855abbb9665b2d9799ae62ea5c8df0c5c2633da8394" },
                { "ka", "31d1242cf0a235d8f3e22d522d8454c33eb920d7eb665067c6aab990a95456ad6425f07e7e0d8a1156cd269c8dd9b10cbf3c423039a8f7077f26ac58496331fe" },
                { "kab", "c0cb620f6f142da3f912b6dc0c8a3779a6ec6ec9a13de7d020573ad2b93c002bc44ace80d2469cfc3df15ad7a98b909c20ee31d8a2739744bdec1aad3233f612" },
                { "kk", "b9de7b0171ae723f26257ab8e66f7e25391781321ce7cc295321f243d4d1ffb4b0e69b4bf86af248ec95eaba12b33d8b230cfd6a4c9227b9bbbe7fe3540e28c5" },
                { "ko", "fdccc5d08a3271a752afbea904321c563cdb0c79af426f494bdf90a08c094945877d3e663b9a42a69255dc76bb750f18b1861fb06a84e0c19657d3ce38382062" },
                { "lt", "d06a680ef0241a9faa97373147ce8cf997873e439626c68da9de5bae9989da8a2cb5dc11a784fbfe5fa6f22f1847ce5115d333bd1f88318526e90c999cdf06b1" },
                { "lv", "4ca8ae30bd72246e407b9a4c5f89ffa80763e906c4caacb96218cc5b6cd9e62cbf93533856031b71f50dcdc8f129fb4db1faba88edfaac65e9f054fc0649cfc2" },
                { "ms", "ca000af0a312d00f9e253527ca5d6506c6ae891520130b3fd22bf1ed3342d666de7924e7f3c22994135d0e53a8074ff6c9e7f424b4b979b38a73b1fd8c2cce20" },
                { "nb-NO", "170f1802fb1569fe8ee6f11ef68d971ecbd0309554eb330b15ac7ef3bfcbee297487e1a91dd095b091f29da48b442a65b848af24318c6612085933a878179b61" },
                { "nl", "cf38af592292b7729accdfd7a0330dbb355377575c00e497ae31e7a71cfaadd2ceb0e45486551446bbbcbb474ed36a018206533ffd2bd5606d143da8464cf2c7" },
                { "nn-NO", "b6baefe47935acafc4f462a41b03f9112c54c27fe3d76bbe2411a491865b3888493aff0850e6baf624a401d0c168f3c77d601ffca43fc6d9037faf952d9b7e75" },
                { "pa-IN", "299981726df5a7f8f4a2578a74b8b823d0d48922d5da7b46b2238d963febda0a3d07e40c4706f4bfd6078538b33b135eaf0406571de58a40b3ff5131061e739b" },
                { "pl", "f745a2fc9750c4c28bdbcfd9804e50f5570f0c68e3e6c4423dd67155d48feb39b0e4ce6f53ba1cbcbb9d3ff9c2daee4a23a2e28f44ff8b28efb57261da1e838d" },
                { "pt-BR", "a291cab430da11ba4b79aaf3e0b33d921bcb39d102bcaa25736cde651b6b677b3572a786902aab8146d0f0c099ea07341c727222dbb382cf3308249310e6be20" },
                { "pt-PT", "a1b3d1a82bd0010e2a27cf71a1cc48523e04019a161dd93f5a6f0bb8f198d84e46ab8cc144262b941a4017576edc14676c238dbec406e11a1f0a9b855e0bbb74" },
                { "rm", "3ac3381018b52f288edb7dc2982e11f810cd4efa0e279d8bc5c66d8fa27dee0a78ea4f824e7fe622745baf6a286c83b72fd7a637e891edef7b48a74e6d2e1cac" },
                { "ro", "d726e47d04af764610dfd4fd73b7442c5e12f5a555638df0e904043e4d208f36fedcfb72f4ff6e3ea91387ac4bb017b7848c3b11c63c0e7804f3fc644009d76c" },
                { "ru", "e8338844006ce660acfffd13cdfbdad9f92ba7a1d99987e3c501d80a18b194e9302fd86e42fcb2f30bb7d61c29bd925fa34916e31ee7598d470431ad0942567a" },
                { "sk", "9c46e292b6029bbafb98f75d15e65eb0c0e51fb6cd6dcccc34d3485226da17cf920cb99ae21e42eb1668aff144d70ae75aebbcc0527e463f45d0822ec5841e86" },
                { "sl", "e2e184cda1aaf7823289bdb459528d86f4ee9b24a9251b3e6a18779bcff0b06c2e582edf133136bac239dccd9a931002a12c35f29ede0b4d898e26cb8a936559" },
                { "sq", "6571eaae0dba3212cb0c464564d200369b129cb6a6f24d6495598a2dd882c8f4da93507dfd12092860c762839b115e8f20b490767933f3bc5f217510daf28a17" },
                { "sr", "b1d64ccb9fab23b9fd2e1a772526039ddfa0dbb13258972a9f741a205e420f43d69ee8d288dddbd636d6ddf54540401b0ce5f796386fcc0bbabc8f898fcaf033" },
                { "sv-SE", "7a3f06382124a4a618711414867659681cd2d086634fcc380fedbb12fddc498d41c598727c6b24df87145442f42ebdaabc9f887664f07d8a0e71713c137a8324" },
                { "th", "5e85288d00b4055ad132eb7bd770e8222de01a93a990a3dff2fb8dd7646aa375d9726585080faa3ba849f0a2e0b37cbd5b6b4b2b82368e6f52c0b264eb1303c9" },
                { "tr", "b443a1fa684f3ac0ed896d78996bfd48eef2ba9a080d3298cda0b58aaf1ba4313a75a6e08ab33e369f63a27c8fe8e35ae60b412cbe73ce6d68d1a70cd6144d82" },
                { "uk", "f821420da8d2275923d289959a327db275ccea16dc4793b0b715ba35f00faf9650f8d08925b17a3d5b7a2df178d7d791409e6e63b1f5597a2d857f1e4027ca8e" },
                { "uz", "ac468105e3dc128a66fa39ed699d875f79a116de8dcbd109b86be3e705dc1e293f350c0db76136990a1db72446ec6bc30079a686fb45be87f40a5abb89142613" },
                { "vi", "4efa58796d731861ce26cf4c43d5c28e58bcc3d17273115d989fcb4a06a701e675533b3c0a7bf29f8bf6f647edc3f05bf0c2616f803adf5ff6108df2d5ff8396" },
                { "zh-CN", "a222359d222866ab367990da3f5af5ab3d02f11992282a722b6a1afd7fbcea9e7bc514b6ebf6d4d7ddd8e8371270f03cc2a34811f9214831a6395402a0029d62" },
                { "zh-TW", "8a5cd7184887017543d9592b1205aee6ecd598e0992437a0c970e0b5ddb74499591ef65f2d8c747c95085054e8fd1a4289917d3fca8bee798a1a1c21a7c89355" }
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
