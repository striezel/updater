/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "0efd35b730a1ec8386f089edfd5d9cec8bac37182f0a4773a1694abe134cbd7c8554c65b097806ec7729ef895d1416d14e95a435220c358a8befa410401f5b9f" },
                { "af", "61c2570c6f74b615986fa6cbe68746f2b85edfbb4615e3ffd60f081bc47e1f98799e0b704cb869b00b2ed510c7aacba405285697c6ebc3ffa9f6fc903f79fa01" },
                { "an", "289cb08d41b32206f407caa633b2ee3153277d1e920beb11788a46ac9b7b5cec837022f69d34a9e051baab2e7da204592c5daeb4c9f0cb135f6ff8e395292fed" },
                { "ar", "450dd3d4362a370a38ce2285fd5dcfb8a23c6312ee22e6bffab8eab9c4b7b687ae761f8acf417bf8fdb9b3ac665f91b837bc4354be673cbfed9df24dc5ad39c5" },
                { "ast", "ff85e4708e32c3531fda987f342e242bd68eaa09ddc49b595b7ec1a8de4a19bf2d701e2d50fe8a9061b809113be95bffe668261f5d095f07072bfb03c7b89ce1" },
                { "az", "77ac725e0e6dee444d8edcf9db6d9f488033ee972c63355977e891b43f3fba484248dce3f030697b54070fe8618208dd14ab885044c6243b4d9ff55eb6cccb43" },
                { "be", "f26a6a2ff64a8ffcecda0e47cbc37fd25a0d799fb1194ebcb99565e6e4d7b9aadde8c16bd6294da496ba3482799492ccbf7408b7eed22056772fa92c27fee9b3" },
                { "bg", "6bda26cad6fbbeeae802a10b108028076868aec676e345e17afd7b15dc76e230fb9969267e59dbd8bcde153de1ea55130cb1c6186ec0be7a7df6fb2491f6a66a" },
                { "bn", "fe98ce5ed05c38803af838e78e7d475a00bbdffe047a970552d80eb8538e9064d07e528a2f30bb0420f0be142bbc4c1d86eb02063838a2fa0b4d47526b2670c9" },
                { "br", "00876cb5035df2a9c57134d501d59d5d2a46eb6c66daedabb578a9db826ed8ec981e0e5feed0320090a94454e8619e7eebbf6543b2a16f7e8c499018426619f3" },
                { "bs", "41ce028708d64377d7ffbd3b0821fd7b98b226469e2d970aa5b5dab21151ad9e0384d62a64f9c3e45786e7a1993080e13e47093bdd2c448178c78ce47a6d9881" },
                { "ca", "77cd7d4dee493e99443a7e79a5092ce3ceee339479da78ffc72c3c6386b51b40b754bb04bd87ca025663ed0fe1bc0526f4607e3526b7f91c01b285ce9a99a8ce" },
                { "cak", "80ff5236c55667d72efeceb8c4b300810291a127bf5aa8b7378f14d066ecccf6858e37e8f44a6a5b167a3216634899d5947a627db72948e8ff98de3df3ce72ee" },
                { "cs", "7f4a46b942c9ce230157e502ee05eebed3a519fb1597cb54896aa33fa9b5a87d718aa198b040cff54ad6f0a92183f80288cc16b56b4f43cd5fe18bdbae138ab0" },
                { "cy", "66415e66b0ca2fbf5242891aefe3f5d22041e0f099aea5d3440d3f6bce499e4261ee76fcfaaccd31dfe8ca122374a4bd3cf21bd5ed8c1f912ee9e8398982448d" },
                { "da", "54096394e2054a41ca22b0cfb88f43aeae3d84eff59b8dc49a5316dd564b085aadc07d267ebf5f21aca508a5d4790a02fa536e33016e6423a305b1f85842c7b7" },
                { "de", "7c80b062804d9aea2c8b12b7ec5ea40efec45c737c84fa6b51c7c9965f493fca07e7ae864bb10d354909f7bd997cf80e3aba095dd4b135573c2d2fc61e837f60" },
                { "dsb", "f223b037dc8f66d4a17c2e7391c7a327041094155207270951d2e44fa968455a041ee5de6c144ee295fac9db2ad083ee3ebc4bd29e20d9180f4f49d90ac62868" },
                { "el", "3e3b5b904c081278192f219803edfe1aee2d93040ff3cc5d7810c9c77faf841e2f933d41ce0dbeefc2c6cf8213128d31c5c21cc926a4939c8057b6d5db490852" },
                { "en-CA", "ed77b61743a5d9085361aaad2a1a6054cf957443bf01e21c593a6c8e69701da1c4a0d9eaf59bd5c324fee0c95c343924f2e973a4f1369fa3b1bdfa6b2347b331" },
                { "en-GB", "1924d5c9394bf12bf1932dc1a085312acce1f9ebef26c11442d7cc61f2d99130f73ca17adc3efb136ed40410f207e8674cb7787164f3b1e2a0d1c2aed97a5ffa" },
                { "en-US", "0f3ea07f388d00c1b8a8c198b654449551a7b1d77f60eea47a377b3b1a0aa1fe4b0972610736dcc560aa354f7da649ecc370b95623f3a348a0e4ece1b7a1156c" },
                { "eo", "eef1a0b6cdc6001b9741f4eccdada82e0ee49fd0360a5413d6b54e4e867f281aba2046329a7400d52cae4920e173b1ea63bcff9a6217802a207d0921197382f4" },
                { "es-AR", "71bc32d0ce41a68001f3cc3097f0cd98a742b4ac6d65511ee6066bebced40270807a483d7369629ad6f00aa47be17bec80bf8fc503fda61c5859544424490670" },
                { "es-CL", "7ea8cce9c7e40587db753db8f023205495a0b6d00111148b289160b000f6e7981a4f9bd7e71f7c7c2b7ebe770d5a07d4b980eae52f4a2ad16a29daf3004f8335" },
                { "es-ES", "74d009f162b676e73cf2b17746e5b8df958f2111dcf1267e1e18113e452ab990af688d43b9383cc2cb69ae6d7d390fa4ce9cf8b0e0cdeac374568d61927df881" },
                { "es-MX", "4257a0d3282ee12240ede6e1732bfd3669cc7550b2b709ca6805906f0f53d3b0e239d62cb0ecc33f34ba9b75c94f412494e47502cd0c2c2248faf940d680dfc7" },
                { "et", "d818270220db48d146de1edb6acdf33de0d97a3cf75db38a32b198e53533bbdcd2652cc68f24adf8aad2dfae081d65b90e5737fc8b562e03b8a3444983323014" },
                { "eu", "d04ab8a544e3fe10ba8325da3ee75422e24bd7bbdd37cd98baef5866e2490fd3ddbfe08a9a7af247462efc284b3dce8fa3568caa923c0461ec15c61d37c00ffd" },
                { "fa", "56e124d41cd62fb5f35b0c9194d108d1078aad858caafb7de5fd0aa389c6507b82d09e61d6ae5c735d9a7f412f0da2fddded21fb741c525a4144b07d566ea25e" },
                { "ff", "5cce1ea342f669ac9cf0e502d47ee3e2dd1ab207a566d64da82f42577e1d7eff6bae7eca0edef2eb05c547486b09f87c2ebb4aa332bbd8e18090577403f9be00" },
                { "fi", "3d25ac592d1e2a7ce0c92f4f64f58897536b24cc18eddec68dd4cf1218e0314e83aec01cb4adcd3c3b6c9dc6d3f04b3dfab67cf0c0ebc84acc149681f11a2239" },
                { "fr", "2a6946d7328155314fc97378ba23e0433a4421ad773835469b84c029d7cd653d1d4249b38449653393717566c7cb2089ca8f206fe791e45b30f9d33b125a3a4a" },
                { "fy-NL", "cfd7880d8b1e70d8a98f15db68b6275c36dc9b7b4a152665e09b71f5b84af823fdf83ce0264903ee5e004615c027cb8c58d76dba2f4bdf5155ca947bab314be7" },
                { "ga-IE", "88a23d794ec68f90347421e8b1080669fcef5b0f4dd99a4487edad8de8adbdc4f961fd73e6e559462b550a2400f0a3c3fffb895116cb0f8947fad46f1cf6d465" },
                { "gd", "b6684a01302942fa5552631261959ce737afa4a18820b74fea5a3145f842946fb317e02f331e5a7862f46743a2632ede4e4c367c3456c24bf02ce4a9e94f06c5" },
                { "gl", "5a26bcdc178a97a6f7531f9953d5001995b32889404e6fed912663306a3e4780f4f981f6bcfef9e625681bf0980c455cd015266445b79635d31a7a9d6c8c243d" },
                { "gn", "5def5306fdb9bb0e3720cb4591409c6016643b3f14005ab3fc78f88b869663316754d8c37299be46aa6b2b1888915ada7138503a885ce834066d9e14f51b1867" },
                { "gu-IN", "fa38fea0fb4919f42821a047738c4ad70682dd32375118face812df677303ffeea719b2b8aa8fba12e0822e6779692b70cee40180262f539b974f23810d27d60" },
                { "he", "2939d2c6b976977765f89a3a4a4c2777873ff3a1a08dca09e38a0928b86a058ff5af8e7d83e8efcf28e0051aa55fd2cff9ad91ff9525d27b1edca5b5340f1645" },
                { "hi-IN", "2a4d322c6e5302ffa15a624370fc228a7b7285fac89b1b79be81429f32eea14cf2054095e13d7e75fd940cd41ea6d56066f7ea50ca4d14226ce0a9556ef56d79" },
                { "hr", "a47debf6af28bfd3580e57453ff4bf4ccea962d4648dd7aa6ca1466559048fcc45aa07297ed8d7c83294fc1a3acdde95fff0bdcddc5d49f71bf50eb06fc1a44a" },
                { "hsb", "d6c931f173b97c906bc42309290962207635f0fa351b32c0e41e6cb84338ac9cdc6254d39352892dbfaec54cd577c836af04abc6eff0f4922f541f01c23c1fb2" },
                { "hu", "d862ef49e05bbb62167d01569aec848d3fdacd5002ed5bb004f160360174a22fa17dd75eb86218347811130f898adea3ef7b25d6141c8af5652f9d06c2dce7e8" },
                { "hy-AM", "b74e8bd04a136c439cb96112edef5608b3f3c5f12b67df7e9d9ee57e2d10d71846eca977b5e95db8c451db0aaa0d89babd20d7297e46d7d465801cdcc980d3be" },
                { "ia", "1b33b14be448eeaa58d060e43d0b1432824ae5907325caa6bf44fa358b31f995a4db3bc75ec01ef2f911cb27fae2088b07283c62fa760f942940ba18bc8fdab1" },
                { "id", "3daf36562bb12f40228e90be3c61393e9a36a3948a21dc8a1553d56a4ad8df24c2b1ea927579467902ca619cdd5bcb912d46d97f4a40d29407cd928f59728575" },
                { "is", "b56800c46945807c8ed9824555c66141e435f8fde9edc2b07a6fb260a3d72f19247e1df1a53b7e0c5f51b64ab8f36372738a159866db0b55481738e10844a804" },
                { "it", "e35ae9a168901fcce1df11774c456efc83da09a45b9b45bdd18b61271164a18fb4c8ff0e01085820412d02a8b0720aeabd05d9838bcd49f1dc2ce540991e9823" },
                { "ja", "4e83de18de4a91a48ecb7fedbc0cf5d36ab1a92226dfe7e6841d3b292cb6f56c98ae57f82a45445bc256a6d2eed271fa607903337b02ec7be33beca5b1aedea9" },
                { "ka", "be172eef3866be208698d6c57a340f44ce65ac977e7cf5ef599079c035945d3ea8370847d5df2101abab71cd469f3c29b59e7a749abb8ab59faf4d25afe38f94" },
                { "kab", "32b90edac0c7888960822bde56e36cbf76d2c16e3d72e5e9e1a6008ccc6161fc09a176e5aca6197dae695c8d7dc489ce77fcf0258b1bd891e271958e005ab90b" },
                { "kk", "d46a8d370b9998f608460e833920db2cd458f7a13f99385ab6a99dae31919edcfb466f9e0df2a06fc714226b768f9e28b169e01301e1d29cf1a73adb5eb54b29" },
                { "km", "ac8dd9fbbb40c51a1c1f03b7d379ebb33ecc84d17d7caa250529238de6492712e011729f71884505a177d016c23cb29223408ceb5ee562134c0c68cad57ccb77" },
                { "kn", "90e85a5da47c6fce1c30eebd22c905f8c2cbb0bddac7509699a67e6a960bbc5d194c4b7c85b782aa256d59ee797937118e3ec51945289076a29c24c0acd3e218" },
                { "ko", "0f1dbdbb0ab99863de7b520b0b8cc1aff5eda43eba8292f160d84330791d8388ab3a80ed28d2260a204147256b724261682bb2aaf66e050f4c222a22d0f211ab" },
                { "lij", "1d352b7020d92fc38c6b45956b9ae0499630a9dc9800cec9927c81a88ef6990842452f9e92ae2eda1f183e47fe6354aa7810c420d66d21d2ff70a9a3112ba1d4" },
                { "lt", "75a36d8b180893dad0c8c80f9be0619f4fa7acdf98c3853318bdc6108337208f3d4d1c1c25b4a3c87da9016a50ab315ba19f5349f1eeb1bc01295fcd96ac7e39" },
                { "lv", "372f2a1654bbde5c0c75eeeb699ba117183c6d56fd1a1b12abfb79534ea80c6b7c77e319c01c2a887b22fcae1f521a41b1ec150660aba2e8764386901d65b417" },
                { "mk", "70712f4f6be6d02702d6416f945bf1c54b2065692c418e409f2ac5cd2f17249c5ddf6e274b64611b59a15c88618c36813f098a21719dafd0b561e35bc8da1067" },
                { "mr", "cd6d6ae9b4b5f8071693370c8d7779e19fa22cfb5db95519736ddfeef3a0ac7f98379dc9f1de422c435e2af51a83620da9bd5dbb78d6b01f80fae96fa2049bb5" },
                { "ms", "7ea12011af36f91a31d8d9e32902fcccb2cb289b187bddb8b92dfc0ebc7a6f7b0959260b94c7cdf7854a14bf6b3f4e557cbf67c7b9830995356bdd8dbebd84fd" },
                { "my", "b6781dc1135009a7ff1176afbc0fbe59e02f88ec95949b428fae38d58abf8eabacf6bbdb13ae4336a723f428e4e63d7a1dc229d9c05274d441fe5e2b81eab993" },
                { "nb-NO", "ffedcea6d830189e7ca0c05d51a595f4e145914c5a287b12532bbe3968db52402501dd0515fd8d8d994e38048c527131b0bd0fbe189df00a97976bb49f020094" },
                { "ne-NP", "b72d326d6ba3ae881725214513f55024d0beefef5811cff591d126223e87d47ac94ac9a7cea7752b99c646434f24c43ae755d51a186324cd8e6aecd44be48961" },
                { "nl", "a8caa2bf92be9af23d47bbc37a9ddcce6846508d1aaee928a5e521098c644d6dd625efcd21cb6ad1095d3b3f5bd5957ff27836f3b312d00dcbff352f7c2a9cf4" },
                { "nn-NO", "dd853b71131bd7534940fa70dc84006c434dfe4395d132c2ef863be8867369843fbb6dbe9eab9284f8906d9dcc19696a88fdfd11fc59ee1e4dbfe132d53faaed" },
                { "oc", "5465df58f00a40377738ee52006478e5c154eb588e846ac67c5b12038e528a01c8d36b2dc4d0fe7763f48ffb75f9015bacf79c953f48c2cb222bd1c04fa14527" },
                { "pa-IN", "ad9d1a9765b14ef2d89c55ba033a2e5209ff4fb4da6a0f2110bf4c8529499485cab368437b4669daf2ce72ada0bdd84d12a147654bd7091aff5c0e15f9b5be70" },
                { "pl", "db04dc429a5b6bd429857d3762e7f50ddbc4fc3f83fd374d927b446298b1847b9a7323f514678dbe744ae0c396b9ad4976c71be4f145c1057c900ae9c1a27f00" },
                { "pt-BR", "8b5b9c30adc5cafd3e823bf5c1fb3f6f7eff5b06310c47bf6f97fff6c24936a7575a88f3f73ba62f97e1b90a84cb95d485d4c4cd0e7c9943014c3187a7e27ccc" },
                { "pt-PT", "3282e9b6c840684736c425c08a030dce25f49a64235571154f4f0ad16765ac135cff5becd54356493b970de7734c36d57c354f297f13b009f769fe61b144992e" },
                { "rm", "769f4d4f4b856f114dccbb9fa7789fabc2ebaa1df2b4c0b5fbd05a04b9a7fbb4117b33283a08ea88d287f603f4d6d47f3605023a7f8ccdc4abc2ae08e611efce" },
                { "ro", "c08c3935d1e323aa067fd68346a14719ba63dcce7c5e1418b293afcb8ea39ef51d485790ab0e2ed5dd255b7b77bd8e09ced9990c05fef2d86a511fc74c49155c" },
                { "ru", "ce130cc37b9869c3a0f2ae981b0d54f22a1eec869596583f11d4fd2eaf16fea87cbc67547c5c0df4ec97060753ae77bf5299a9b6cc0d3200bf24e2eb5302defc" },
                { "sco", "2b102b7aeeaa476d0e27915a351ef5a3a4ea11ece40714327be77614955a9c316cba098f05b52dfe552d3371390652303e2c4e5b20b293736e9698d5812bc8fc" },
                { "si", "2ad6590a211e5556d74f8e5f9a23387f1ad10e0ce85ce7e033a1441867e73e4ed6c1eb458cfcfb69f0c1cffe35a22a4adbd69822141a0a06ffc32b8081101ad4" },
                { "sk", "764aa3d50af90e802f9b56e4b73a463df292b22c34424227132665696c5aed7d14f2c15317bebe2f120361d3317c0967d673d51211b3a823f76ca03ee3f05788" },
                { "sl", "0b3179857ede46974e6302aa97468746847e7d0b79a09335f9f87329fe34e667325efa0f4290f5c9af6118d4ac22dff4d46ffac8f2244493a62ec638f73e9a86" },
                { "son", "e1e7563515cbc765065e25f2a6f5a905028ece8d80395b18ebc86e910fbf2b5ce75d424d55ad0f5e748e7b80311f90eeb4a95045ee4e50581896968a5b048cf0" },
                { "sq", "d56ac8273b02e88f5b53b42ccb51be927937e1b51681a27841336a52ead76776958010364f04f156789d3ed030645409d1707fe3e0deceeadf87f246e98f9baa" },
                { "sr", "3c3dd3da7aa8cc4a96782d3596951b6a4d9c29c5b04bed89e10b5fa9a2c23c3f9e147ef6d37fb75d5811281a89ad7002dabdb014e641dedf44710cc8d2f6cc74" },
                { "sv-SE", "cd3674fd0f6eec955ef414786f845100137ccd6351469f53a7d841771dc07344f4b03f983ce8d7373dda7c85978c1585070362bbd2538431a32df6199129b9b1" },
                { "szl", "b283582a9d8c9e5d051da728292710a33b1613d8fc68447225c93dbecd72c12a42cfbe50d6a063652e59d96dd4d9c4831a0da7a0300b63db2be2e06a0a8928ca" },
                { "ta", "dba4c5dd3cdcfc5ef792c6f7969296849715285b6750a64f0854707db24ce219b01b225285521f9ff6aa8101a4eb843b6e38ab07e4fe996f8759b39001b68c42" },
                { "te", "d8ba74751dbea9cb915cc9c61258603ede4d32ac2cb5a627f0c2528722e412354e035a191da7edb265ceae5b0909e256b55d0df16dead159410d68f2f520cd42" },
                { "th", "e8a49dfdbf02d9e4cfd74b8978d777602fdae3b3dd19a6a99053ec201ecf3a1b235c0fac12a2a43d754d02d48383190bba60f9f0a92dabe84e5c494c38e285bb" },
                { "tl", "4916db21e0af35e808a56583433a4704f6e24b37936875f72b54056d3d08bc0e71a00113183360defe25646abf6bd19f2630018fa8bc013c33c491e89be29174" },
                { "tr", "26698ea6527e20493034858d426138bf44ed3502d899520f7dcf5738e70824995936665c81ef9b4660bff00714e7736a9594c7b8c0b38dfb75d44ab5d8130dc5" },
                { "trs", "188a5b21b5006d7e7f531ba6046b64424f54694fd58702ff9ca59bc1817c154924b2b2db65b25b8e7501205383dd0b12086bd66dc5c883cbb6ed6126ce8b4056" },
                { "uk", "dfa85be118c466f2db0e99af5713d4a894c7e4e740f0d1cf496b5385cb68b705a56064798c7319384423d351f1db106d023176e66df281e870a47a83302e2c9d" },
                { "ur", "c38e6a0c0f67c382e95fda7425cf96d49dfa798138ea5f6dfafa281b3a22aaa5237f0bd151491b4ee987584289160f0db216af315aabb81de1829b26dd990fc1" },
                { "uz", "2ce1d8eaacf60514589818e4195d85a7980eb737adf6b1684c90df644036a2f2e3c8b869d49ae85d5fef1e513c5e2cd1cd5056f08c8bba7395272aac7246a1fd" },
                { "vi", "fa9d2570f75a94641bca5c75906e977deaebc806f6a6d01e9ec1fbed655b6925fc990532c0237aef245513c224eda19245a1e942137070e139b0b866593a4d79" },
                { "xh", "3711516617280a5179fe1103f9c7531631dd77afef47389da5c680efbf273ef6cbb0cf0a41eb65e6cc9cac84b5618f9b45a36d1e0942e74eb12df8bc5d557377" },
                { "zh-CN", "7f9708c34010280ac70a3860b0a10538428945b58244c01f44e7cb37f82f0f4c0ba105278130a535aa52015545bb8e2330b5a0a52e31f89498cd0278c5d8bcc2" },
                { "zh-TW", "0109b50f615f28cffd6a0aaa47f3537ea8a56ee6ba57fe0718cf32213ff260c6b651608a6f3f565a8444e564cd5c5b03b8f905bf85238417321e5152aff4be9d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "d4a8beecf8b59826e3d905f8cb4523213274c29d6749c49cc112093aca252d62080740aabf847ddad8a43f0bd44e213b9b0d8ee67ad2e61e3e656a680213afed" },
                { "af", "e7107b3a31bc7f530695055a555414f1c332a287582c1690544a57a14dbd7d3f4e38dff99050ad95cd83b92d71122a35580e73462189f1f1ceaad69bfc5c618f" },
                { "an", "f18bdf0b324274d19ebc54754beb993585748d15df1551ff64e577e7bca25c4706f0d32f37b9fa9deb2d69a14db0f38947a46ad85abb0b3c1741144df7053a3e" },
                { "ar", "3cdadbf1d19c28ea93912256d9242776d99a320ddbd3e8a2fc81d1fd640afdc8e4ce378d709962a8865a6a9ff047bdfd9e8f9713562288f1a2865cb8a9dbe1b6" },
                { "ast", "592fc3b6daf98813aaad779e7a7fcfa939a85d4a1012e78f0dac7cfeaa18d382b4e96a3f0bf853839754eb8d0780e9116a6bd2385a04c9c532ccf915d0401041" },
                { "az", "1a0500fc42a36be65c4e7e1c4096598b57371efa660d6a92eeef1a26979fa16839961b19e683927ec3559d424bab26c234e195154b3541ca9ef36b16c438b9a5" },
                { "be", "1fad03a1b890ca69de4c3424dec3aa68844f45be9d74eb3c915aa9e8f3f2992f882b2ff2064895fc6cfab72dab14b5562400d83b436725580de1f210586962bf" },
                { "bg", "459c78df59f18b997219a79759568a1e590c5bb5d747dfcd6101faa690b79945bdc4877f59dfb71c60f7f688d0020c184c88a5e8e600bdc15f2cab24ad7723c5" },
                { "bn", "edf5af414742fb4570b9373eb1fffcb2854b61b7ce15f5f7750928a872df0d998394389f5816d95add0b53f2fb859aa5c7c635f37663dd9ecb708d95b3d51e09" },
                { "br", "0905cf15c446a08922afe9cb4a700a91db10291bf0a242c4b6796860655161002ddf6b69e287625da36e82d30c27294521939b344e1fbcf4ff0aa2a1a81b5ba3" },
                { "bs", "85831698ec2266eb9f4b414bb20cf7ef24a3d19e35f67d5d87c9f12e745b1eb8efd6d97e832736d4bc6394f6cd3b2ca0835ecb400cfb5ad1ef42e2a93c1b459c" },
                { "ca", "5aa9bdc059f2c4c0b0a509f10b16c9d51669566be15b030370e31186cf17007db927de78e3d181efc24b058498c799bdad9044ad74d0ed25f40ebd191492516b" },
                { "cak", "4090c301eb9650ddb4bd283c7499cc352c2ec167241e6f85cd097d88d14fcada8d3fb9a20c2371d3b98208837df63cf64db541c2adc90cd2e7b0bbaa610d9761" },
                { "cs", "133a8619f6315c35d188a774136b93dc305dbd28b6dd29a71171e4bd14299c6b4ed6d53ff604cbea70a73dc423243d41069702e253ce48a5dfd621dc0c8aa5d0" },
                { "cy", "039ccde77e41f21a5b1a94586e22d28c18c23ba70bc7b68444b6ed18221505a5c575636d46aacf39081aa7609819c16fa2c08c79d35f49979fe8ac7ad57654af" },
                { "da", "abdac89e00d601062a2e1cd618cfc0fcdbdafe5b6c7148e182a168717b1d0f0beb3947d323ced770ea94bd38f962727ef3916ac556df8246a4afb31f28c47aa0" },
                { "de", "58835713acad0516f0d9a77e9939feecb4026517d0c9dbe50721a9e62ef604cc68417ab94279a6b49cacca55a37a5bd3544f39a3982ae5e81505eb1ea0a4084f" },
                { "dsb", "1f1628ca6c4dd0a6e6e50ccd4838b224ecea0a3e9a5e5dec3afbf9989368acb4aac31182db202d1cb03795a4fff35bcbbf2b787409289c9ba7884930f3d933b0" },
                { "el", "6b05535199dcdf47624e61851596292e63f5d32e63c9b902a71d3b02066ad173b54756136078594dab5823e8af37c5451f84b758df4f85a47e10e1bbc73c392b" },
                { "en-CA", "21ccd56b13a705329cb9efa44bfa3c66c384bef6e01ced5d29228cfb18a2f4d6866b2cdab3eb098fb113a912f640375ade162945a6b29f52b0d4e1dfc48edfa1" },
                { "en-GB", "26c64c12c2caff6a83bfb06c7f12880b7eea4381fb8214072866048a825cf270334aa8c162ad5a458f36ca487907fc280f51ea489f1de51b55137a54162e9c71" },
                { "en-US", "6d48e8fb23e1804eabd0e27d8c433b96cf0e2517f234cd372f64875c5a4d49d935ba6766178fed6f9dd5d42b64a6bcd9f3b93c1e68db2e22ab54bbe96515ef94" },
                { "eo", "bfc9983f04dec14108311bdcce270b28b7337583c2b84e040aefaec8289573d5624298ff5b5c0ecea208cf580d1e697dfb0850167b949e41690c081ccbbf3a78" },
                { "es-AR", "2a4484e91ffddf7ef4cfd9455e6689b0dd1f1797af7f6074f0a090042f2d28b8b48f20be62effd7dacdfdd220258e9e8a85aa148e302b9248c5c1a60fdeb890b" },
                { "es-CL", "cbeb17f2ca80f34452dc90c6ae7781acf13fadb010803bcd8920a8be26301ab8683dfe7aae62c07a3070eb8c82124e076de4048806b692314ae1b0a4e62e2a51" },
                { "es-ES", "b70a9ce806d14b73fde763f7426e1fad679b752c0f24940c8b9b3dbf2cbc2fde4b9fbd0c8dee0f539038f860f676b3c0c9d1a4dc216fc067e4ce5d9f86c39a07" },
                { "es-MX", "fdb27051fc411c044280bd4deb01cf08c9f0d24fbe567e326ae211d5dc9cb74c39d96ea1ccc04a1c5db6fdfdc79b7f799c64842690d2dfac8dd65ebf6db95c50" },
                { "et", "50885374eee05ff79619f04653568177ccc2c02478f62bc6b000d8083e045a7f2aa4281528ebc23fdad5f5641c5de58cd7879a4abe110fe53632cec57c804ddc" },
                { "eu", "e585a1b5bb7bf13d3274f5077e99d40496d264e45b826b53338f0eeec7e6f58d437792bda08fce013611562225e3ecbbce3a375eae6a2df32682affeabf100be" },
                { "fa", "c97dac4d753f528f417c386045b77bf6be95ec75f5e9a690383770e74a95aca7f8caf04f3f9c6744d49ee90481cea5fe8350ef2f15749c757c5fdc2ad4fa4763" },
                { "ff", "a4e73cda8efd882905ec1e8b8100cac9892ee9a49e11f4489cb71ba7fe7f7fa2ab723bf28561117277f7d82b1cefb8aa2554c4b4d8b5dbc5bee83cd47987c67d" },
                { "fi", "55367477f136a20e78d19e9a42da58053aabeea8f0c20964fe9da72752da9504fa4c83e87c6a67203d7184633ba5e3ec303b56263a2ad15edd35d99111cc7069" },
                { "fr", "c6bba796d619afb20031edd32a15f52fb49af6b45d09dcb37d9e2cf23ee986039cb860275f60255caa7c5666012e5d248abca7728fc8aeb8835a5913fd58afe6" },
                { "fy-NL", "73406ffdf66e2d9071aca7ca18960c4e3f0b76496eb53ad8a4c0abfc202f0c0f023655f2046309cc1fe926defa29b03463a042752735577a20e6676fff392b8b" },
                { "ga-IE", "69ab5ea3a69636a6e8fd1711e2f61404bbf8d38e9b6a27307c77d7df462f54ac38a73e5645dacbf3d3f7ece3fbaf428f6efa415cb433b651e3cff604a17af042" },
                { "gd", "76372ea19bdcddd534829ff60856d6171c610897bdc382833017301528a571c9a2772e9d06d07af21d36bde367289937666b5f0954f96e2978ad16ca53dfb40d" },
                { "gl", "62245ab4ce5638504fc1e8d106d9caf22174bd593a50ffa96ff1e62d7b39722eb136a7cffa09de3898883293d9a52d6354eaa123a688a9dcdc65aacff9c5de01" },
                { "gn", "bd008c724156d7e5cdad57ebd9838ccc022b66457f13250bba7d9856aa72337d9f43380764a321186c2fb37cb3c8acbd26f689dbc44343bf16a239831cdf696c" },
                { "gu-IN", "3702454b182136b5e84b0aa548caf8edaa3c97094b97839a0c00868d0583fd94b320de221fa97e249024b3a07a39afb023803b4d17845b4e48a5891c3f99018f" },
                { "he", "89e3dbf543bec84fa3fa97cb1df40bbdb0cbc2b8461540eed3181ec8e1e3df146f1dbad9be26ed992b8a598e95d21568379063af7de2fc69a53e53e90b3dcc59" },
                { "hi-IN", "9584229ca78c97fd507237e4154e94dd29f6f97a0701019c4bea7ea51bc1e8e4345b9daec454243e6a19f568748d946b41734e40f45804869a83f535ca919521" },
                { "hr", "cead88e8a3494cc8eafb4db9cb5f5ba619839a7d56bb6f79043bf9162b3175327c74c1f3015ff22395332572de788942ba9615ebac992cbd742e691c5d226973" },
                { "hsb", "3bd29ee0fc0638769e4aa40dbb194c778f0a9daca6b3963aef1aa02e4339c7b3151c0884a1433f69e1f1983f5d4176a60fba52c52e5f4a0e19f0b807a2402e79" },
                { "hu", "b592965ade019945e18af036c951f26d6c30f4f1b9bb17af60c28b79bba494ebd23449c69ab421036541b35385f7f733f180f0a2079277c80d937d0d86245f46" },
                { "hy-AM", "d237cfcd4a741f87a946561cfd7a91c0979c29290c55c93eee65bee820328b7064026e1c7b6f3598a36f1934d8e85f0d89c21590665c95a273b805f0431060f9" },
                { "ia", "890d698d14da542d657017a5a85544f866e2fc5c2ce57fe1bc60ca5c9795b6bfd408e40c09c1f941eabe311363af282d7d8a1fcc6c0fa7dc198cd7283cdb4a56" },
                { "id", "4d5f5e5cac25dc5ca9759c5fb543796ac85ad7d27cc3c494ae2a21127538fc28f5679afbce08900332dbcddaadead5d0c7be828d7540772ba7ebd54bc6a00df2" },
                { "is", "6f58d618fededd831582b03ce55495c9f500ef059fe842997a4c0122b9330d6bb19fc3dd1741000ad3ace3c287b3b5cb5c0959f091155f6065f1514357a032d7" },
                { "it", "8fb5f54da5c7e3b6456703f268b9538b891f1696a47423ec2213972d503d7a95971a7236d6e763997d134908d051669c22843476ac379751e1228a508211fad9" },
                { "ja", "f411351d2e232a6b29ee792d478cbf128590fcbdc4bf4e5b8a63a0a1327f8279f45c83cd3950ffc6a9636e355809386bcb7e28587c2d7c3e1d549e269b0e59e7" },
                { "ka", "3529db770b4a8543948970351acb66e204d94270c2403e6c90b4bf216f1fc910e89a82315f3bad52ce84c8f6bdcdda0f6194f17fe8bf70bc1b3a3baa4a46621f" },
                { "kab", "e1cf837a2c4cab9556cb5d9457d27e90fb66c8f872a4676461f5a49ef108f9c1fa90d8bb1b758db980a859fb6fb4a71f4f2f3abce5f354fc01deb43f85fb9f72" },
                { "kk", "40a04ee67f01e01c117c98ad23c81a8a0c72ada4d6a9501cc209c11b9e47e34a307cdb87cef4422be5aa1716ed2c78e3c4cb1f0f99506019d98d6f6e1e97e780" },
                { "km", "68665d79749158ec4c25e67c966872ca62c4077ec619c05d0308b115996596d7d34b2b5056c91f8d389a3d572635f019157e0383407ac522641ea0dbee98e705" },
                { "kn", "88575157cb5ebc880a0ceb8848393b1afbd7af3f232622ef3477b25356bca6ea56840519f286c67d046290b9db4399c71d65f4852e1ac04d962b81fe1bf9127a" },
                { "ko", "cc7db470b5a260586bd461da95b0885d726b158aa3e48a83a399305567356d8a1fbc4e9099c90b3020a8f4b8882a3f497254d705952e5d079d3d1bb2daaaf661" },
                { "lij", "0a0825d7e929519cc2134198edde6308b7cc29402d1e3f5de84862c4465e25a5e791f09e587c426759057fe6924e268a232a45ec71dcb322620aeb214d1424c8" },
                { "lt", "ae12544a98a80d865690eb4a85004c37e661ba77f00dd728eb93139ed83ae6100c98b16465f23e4da6cc60a1044fedc4a0b4696dee6550291bfc51643079ab9c" },
                { "lv", "1ee2951fd60ec17b768cc126752b43a616a2a31f3e3f0cc71a5204e7757a7f2818ec2cf8b4a4437330a297f3c30a3ed4dc88caf078e01e978d77d582556275e8" },
                { "mk", "92324c0e86755820db081b875476dbc1921ebeced347c82da7e9dc41ae79c48460034ce2be0135f1ea5df712c25543c9c5306a5cd0b5661d3894a8379925d34d" },
                { "mr", "f62c4ca35b7fc81ab5abfa01ca346c7a042b69683d2055e10ec8af750846dda4aceca20214db1b9a855ae31fe6db62996e0656698a20bfb13023c553efd87dcd" },
                { "ms", "60fcbf6f5cb96f1b183a5e181b7f35426fb40d589a5ed15ff9f88c18d897699b7f837be043b449e9a4343b57ca06af4a9231d393bb1c5e503f8dd22014786a06" },
                { "my", "b18ffcbca6dde02a998d830c94096f5e171ebe716e0eb92216380233843f462d06a3dba807e2f28ad0e526bc339b8a6876dadeb4415c53c755347df9244b582b" },
                { "nb-NO", "2303b53d63a3886b8316a70777f052826c580e081542a65e98bfc0de249dea5cb92772ab3d2b92c5606e9aad51a4b3e109e3d5d86f599dca61f7ffb3143ee84c" },
                { "ne-NP", "f012b8c78453cba24a02ee4951edf730aacbc44c87be441a4810931dc4fe535042491448034435eeb3411b30673bccf934e9abbfcd11ad29bcc8ab751e2a6fac" },
                { "nl", "20d6a1354dae91e64ea1e1af2efe4eb65c2c5532377d5ce150586e8ec7458eb8457cd4dee5f793c88473f55317759f702f3f8f1cf1d9c267e8586782a57de75d" },
                { "nn-NO", "4800f1cd84727652523f3267aaaa8a311a459ba32f4ce000b1ce49d7244f6ead1938e790d31360644add99b013e221595c9f5c1d30f47680bab854bcd235d74c" },
                { "oc", "fda104f771b233368988a236d0b1800379cf8ee8104e2a10afab659e4a14862e4aff0caf1ad75724ed2f4b166c9cf611dec3feed41df5854550c98e696f9f7a7" },
                { "pa-IN", "d0e1aedb4d62f96fce060ab026c24422c0baf2556b691b6eb619e2f4a339f0356175d7992d50ffa8b272a189cd86c524b6a43b7765781a491bed060e7442b6c9" },
                { "pl", "5e3e95ebc206c223ff31e21e933c7fc8d1fc4752b72c3b1cb4d27f8a68e9a6e7df3e732217f8fcdfd23d2028e59a66c327ee240fdc7dbf3af8b985131e5a6754" },
                { "pt-BR", "6f893cf089729d9b629eb209446cc3b8185b2a6f183e597395c68d7e96c1c69dbc763686ff1a3c5350412519b3e86624cc9624aaf1f02bd029f3a54e3f0eca76" },
                { "pt-PT", "83fbabeb1e994bcdc269fbffc661576a8f5d0a5c42aa33f424beb6cef162c3940132f31d31bc8caf053d118aed6c86d6f3dd60dbf04328155e3268c7ea419611" },
                { "rm", "f58964542a13ae319c17ce2c353ced0bef503d21e0bccd29fab146ff8bebaa58588b76df232214a6aeee105ee0d7f38ceb9b67b128e49b879b4c2d1b53d01091" },
                { "ro", "3e6a7243ec05837dca61889f5cce7c6bac770381c339bff832b90f5ef257b8ea1c476024eed4f83d804dd7f19511356f4a554005a3153ccc2341ff7a6dda7c5e" },
                { "ru", "664986fb7110151fb5ed5690474b3785082e216455532767bf5092d9680a75bbafad184e4baeb01905429dad987d7382a64696fee06ccb9065ef9fa6361bafb5" },
                { "sco", "34ff3fd95f80f59545b00b4fe75038d2ea44c6cb8658a4dc7603119cd57850039625639505a263c5577e6f88bf6724dfae13c7ceb8d343157b914bfef146c74b" },
                { "si", "708d72f52f139a76b99fb43bb0c7fb355107de6fd60484a6aa276bbe345e2fc8fb7d13e9d47a429f3df24e95da5aefcd7ef16826e285641e3c59bfa36f074e2d" },
                { "sk", "fef68f801e5f4b32cda2580799de34deef5f4592aec502894cf54170f2f37869a870d1d8a5e48e03499c2f4b1c9063570ab11b28c26d7ceb6abd8a58df724b94" },
                { "sl", "c7add918eb6b6b790973c41d4cdee985b427a00227e5035cbd0af359c87d714552192346c3159e353ea365a348cc5143d6726d3c0727ddee43a0c1e41850b6f0" },
                { "son", "78a0e7d88dd2e64bebbace05445d8858a9ac38eecc2d619364267f7f85bb0aaa5f130c1a673fc049f3d4ec94119a3a0afd75c036f40c9563420c091d6559dc8b" },
                { "sq", "48b2e7fa71f3d93724a555ae12067e4b5fbbdb8af0867826355f2d33cd44e7d887c89c20c65f4fc4f0740bc97bcc3f237fb421faadb87bb93eb3513cd6450186" },
                { "sr", "52c266388abce7e4aa057e510cb389a11c3f69ad23417a218d29ab31d41442aaec46fcbf88f22d6b95d9d5f36657117d0988c27f0434be611803734179a5d98b" },
                { "sv-SE", "f8f9e5f918b3b318d01d01545f01149a4ed6f66046fa95dceaffc47846c87f56127ccd1acafe832c387bf05328a3286c3382675abdfab2379184f69205181bfb" },
                { "szl", "551bf24e8c9d89ec44c6ed3f150ea6fbd870c3a43b442d103ac67546363db5d7862b488b6f0b15b91bb128e579d579b8c20f78098956f60b776fd862a49c3671" },
                { "ta", "ff222c868b59ce9b6380cdc96a8eeafac84526d520c6079bcfe8223872434f1ef6b3782b15b234a4b2587c772b36092bb12d201da9690b91cbeef679963c6dbf" },
                { "te", "976e2a3be14c51c92c9a79e6fab816577a58d1d87884d0a3aef6f0bfa07dde30b2a7e59eab0dda32dac442ef82be77020297219ab0a8d7402ada30320ae3e4de" },
                { "th", "5b7daca376cc5d6a7a9cd2c11a79b42389857303c93917427797cae10dc7962067dd51ec1c46441b9adeb60bc340ea68e47161ee23d2251d5a1f2d11233e0d3a" },
                { "tl", "23b5a83520cf924975dd22021599b875a151216414d0f5d95b6c7abb41d42df428018d2913c087766012f74baa8270f58cc9f11fa27e8546dec6f777cde54499" },
                { "tr", "af864d19253e4c7cd0521dfc87370d0bfedd8a59e2f6e1cfb4a014ba84de24c2da20363bdabac25651602e2dd79b8579be45dc135782e1c05934c5b126f34c1e" },
                { "trs", "f8d3c0d7abacfa0e352872b9919fba4d6e24a43ab4eb6a6b6b34a779fc4e45b53f6d999cb317ad1a1684c049185538c12d40a0ad22e65513f74191cffca06d27" },
                { "uk", "f2e62a312d4d51ece59c9f3997819cd6d7ba2f93cd08a038f18d3259e617336d2c3932a67fc9c3f2bd0a9d537c40c645692b588b795fc6e1bc472c9f75f8c3c0" },
                { "ur", "f8e6f2f965e65347a46a1f4986750b8170829ed3a74f8d996e29e40ba3830c3a592ce72fb125377057f60f5211bd0f4ce1e5e1b986c346f0a956757687c0647e" },
                { "uz", "a08faa656a1601634b692df3b9f8fb5488ca0702b3c2129bb10ff3b75a7217fc8d31fce7056d6342b837775346170a617f33c78bc9111e89cae1e4cf7038db19" },
                { "vi", "a0833d8e76321bfa8e8274093e053a772680a506941380e8c65cf749d8af012f6469b7fd717a56faae280b431635bb94f7b1b1485651e26e45710cc507b317ce" },
                { "xh", "fa2e1a1cf8c900f53b5c8a3fcccdc91888611bae026b4a050a07660ac5b9f04075f418cd0e6045266d6abfc8333c54d1c7630be5768d0d8b1573cdcbcdd895d9" },
                { "zh-CN", "ed9daeae82ccad0f5a712a2edcfa9f04a3f93d0d69cf2c2686501f90d1c37687ffc86c1a5a22c02ad5465a1fd9dc9940d2c70d0f8bfba3827e7863817f180b1e" },
                { "zh-TW", "f1a7d1aa895493026054461eb5bfeee28b4719bf2a1dca6420d1086375d646a0db6add91d26452dba1ecb0bca358815f131dc5a03b1b1550ab4b0b323d6a1cd7" }
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
            const string knownVersion = "91.11.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
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
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
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
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
