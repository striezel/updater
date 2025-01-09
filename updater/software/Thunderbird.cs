/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string knownVersion = "128.6.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "959261eb45597229bc543f6a659bcfb2e8bfd213ce8b912aaedacb92153e83ea096809df3b8cd4e674676d9ccdac5535b37b512ebf2e313b5a40c841c58517d8" },
                { "ar", "47609fab84d616371a5a9820db1fa7d2b63f463bf2661a318c30634d0fd562317f090a4544430d6d01f28b6410af97b921cf4e177dd55bab38c5a706bc526624" },
                { "ast", "743fea3cbd62442c4b7a478e9cbf20d66743d0d18ac25c0dc81131beea2e6be54b631ed225c8c5f707f5d33e5ddc8f3244add4daf7d4ff4a3961ed6bdf53f188" },
                { "be", "be37306707cc98876bd35ddc2d86f9efc771a32f91e7c4dc1e9e5cad0b38878863a496e37e26baa5cbfbfb2cd485ba8b9fe6c332b69503845d34d60dc32f95f7" },
                { "bg", "a6134309a09c65ea279e6e423f6004b101728e84433da85c8d7f15839856bf3d67bd6d1bc67ee77fc5493b70ebbd15666cfba9ef681b99b94d8de40d4a82e01a" },
                { "br", "fadb79ea1c4441f8677d9bf617e138ede4dff388b2688f6df3bf8741620ac7ea0d43d3feba27a8406ce7f93e336abdcb15d5fd88aff5065b0530ab59e8a36731" },
                { "ca", "e236c0fbe7c617ec57570bd6329c7c59c8947f38a5a2b65725ca2484d2812ca4cdf93aea9135512bcb98c636b75db5d182e7380e45ad3feb3ef69e2997fe01fc" },
                { "cak", "90000cd63094ef7dc766fd0e8548e943bd7caf184dfe6fa83643061264b4e28530b7add9a464e7d6ba95f9606e175fd38a6cbea04c84e09a3f25569ec4d790a5" },
                { "cs", "14ba77deda95c88e84b412c7649119ed98647485d94d332fc88b388525574d37afb1c65e0291e7f4dd37b4ccc5b8fa3c82fa25f3e1994b3abb1806d7f65c3e10" },
                { "cy", "36d6760e858cfce520862ff105fb302dea5e014dc23c53a75e90878e5edf8eb934b95b815ddb0b9dea7ba1b9252b2f5b40ea2a71804cc431b43567aff50f76ed" },
                { "da", "5444d68465bf57d02b357aff39ff41c8b76775c2840fd4518acb0f898cabd4018b7c176b7e12320a251d2740bac3bf0ce86fe683216f31805346a9dae15611d8" },
                { "de", "e2c27259731def6e025560b11e1c92dfa8702f84cf673cae34a37009483696d45432646d118e83585c4b340d662c988aa06a948644dd5aee03b9272542cc89fb" },
                { "dsb", "14d2acbf7420f96beb8a8d54bf16f5aecd1d08d9628d82a8f6b28d979621e921d14ca9d8a19c81754951973a6ff176a2890ff794f5f210d5fdbaa1ca78ed98d1" },
                { "el", "877a2910ce37911ad3935b6307fc8ed9ecc3c26ab0d66a2e60c798fab2f73c2d102ffdefe7671132554093a00ba84de917e809baaff58e2bf9978c9087999d5e" },
                { "en-CA", "2833aec62bd0aa6ef032889e16a4d3e67b56b8f56afed30b050e595161e930a87f25b904839dced4e60d920d93aae12d0bd773863e9ec0099f520059c4941617" },
                { "en-GB", "118e83ffea06717218a45fbd8dbb32f7129303a95431ee78b0b08c6bbc65755cbac28ef9b566da0db7a28d75bde43914bd8c01753c10ee301f72a60151cbfce6" },
                { "en-US", "fd03b4c9bb99f7f8a14ad0fea142e0e4e13a5d6811d0802b792df55158511cb91721af22dc491efe8a141514052c8df085c3f7152d91941c30aac26f95b46e91" },
                { "es-AR", "96cad932cf6c097441103679374b60a116e14af3e46c2e62af37c4ecee0d283b5c271e5754e5308efa8c2f3f59940eaf03768cd9f22002bf2da1bf54e723a9fc" },
                { "es-ES", "89bafb56ac2fe28c7b76e2ca7b496a08a27933ccc85178b6337eef965a49ba4fe06823098306af189ac0fedad27cc0fef68d3a2e79961dd3706c72f898820fcc" },
                { "es-MX", "ecf136d4c9e4ffb1b43925db044767f3692951e4e9491bac799f201cc7764affdae8a8151f0ae0dc7175e7a929df29dc5ce9f09d18381dbc9388907e9ef44c22" },
                { "et", "434c8740569f92c70b2ce466feaaa691c183acdbc87da13f1fa5f3497988e67a36b7f8172c818e59171b3e7f7e57a4bc156408b998344f16e619295517280809" },
                { "eu", "6bd5f85defa1ccff9c98bdc5fd4a71c6fc70a91221aa52e5e8b80e1f4f20bc062247d5e48da9ef9554be4942423e2581d1abe48988c6219dbff8d5666fc9879f" },
                { "fi", "5e2c53fc5d2520d4cdbff136349cc98fea1d9ca36f7755ce4ee4975aa6ac40ddd6159c98b6c2f3d3ef7a1c3f2bdfd82190b39d948e14f1454828dcc7b94b926c" },
                { "fr", "750893a1af7a376de475b849695e2a229b01fe6faaa6f546de3db8b32e74c775b26a214bea1aecb3754051d061885e4ad22e64a0aff89d9a0833d874e8182cb6" },
                { "fy-NL", "a0a5f109137f1ef7bd206ca7eb38e947d26dc721c386b4f3b740abd888bbace6ed4bd82b9c8d53ceea9e4bad44b8533ff4c6a5a78af34952df017bd701b591eb" },
                { "ga-IE", "e18c227ac334192a476d8151a0c9b8c5ed6ebab1b1b8e395695840e24643f54b58ee9548d2aa0eafc65bd0ddb461c87558bc4df68f9eecdc31e7d7f5be09ee82" },
                { "gd", "5987eb53394814b056926ccbaafb8fa1ff35eaccc05ea1b569ce9804099542a887ebc05fcd3ad056265cd6db1aa94d52c546a7f9f4543500caa2a44dab315ecf" },
                { "gl", "2150979760e5f309cf73a63a84b81ea365eee326f94902a36b660009568266e5d3160197a0a8d8a6478b882e8944eab660843f7faf8547d3e207f99709aabe92" },
                { "he", "9f61f4908623a2952ec65f3bcbe1b9134c3847cc18e35d5d4429fef8172be7bd2d42b723fd6530febca0d73699db80ba04de6c9da68c1b99295abc9f75acf606" },
                { "hr", "8b007b0263c9c53bd5ba92216ce35346b07077dd822d8defe2255af3afe552852bc53b593ac03257ebc9eb0693418627fd6201e1aedcc0fbe359687ae0024f36" },
                { "hsb", "5c02987d4e9824ed99fffa2c16ad8a6dfa236821f77fe06ab79c6ceb2f3c70e4c6332480850283b5e18334b3a3e85589face17f22fd56a417b59bdbb7e7be116" },
                { "hu", "28b443b2a8591df99f434451746b3741fbf5377b30a1efaed528f2d6d7e524f1681503fc36d57a654532368ea540e241101d874fa77c927a07db8d9ebb0f30bd" },
                { "hy-AM", "3fed56fbd6b2725615eb5318e466dfb5fddd89fb242061fe60386e8e6dcb77a949246d195955f2f40b7e198c6f4aa3417c6ed34cd0bf7110cb84965bee7ecb15" },
                { "id", "4f2b48b8cab2ad8ef92eefa65f3a1ddf461ea87eb3be3a7acafa7df1bbe7dd61e58119e9afd5c129b096a3b4266558ec8e837fb1c4842ff7a036bbe8067000f9" },
                { "is", "3a8d943b30cb23276d73a148de2e9690b54eab3aef97d1c384fc6cb87483a4d3a1aaac1c320d3067e0169e65f2b81e3bd01a7da5164a7a4cbac9fddc2dc87a51" },
                { "it", "445dd0f6528ba262958ee82349c90469f7504f8f73c7bcfb562cb1f5822d1bccb3a3e64794efd999aa0a1e397ba0f8983bdc419790b9f6242b7c721e142a97ae" },
                { "ja", "790b6c59d7e6589404b56e519c266d9b83410bd13660596b6674b0dd7a76048954cd702a66b2b937d0ab6b2382bc3118b355a62f9740d99e989877158b71af49" },
                { "ka", "dd237f2ce3fc5e90ca64519cb0091e5cacc778c6d59f259b050f75e1d01b9a3bf03048bf778ab034fb4f43400ed349502f9680fa5e417d3e528fc58bb855f29a" },
                { "kab", "621b116ae08845555ce76437dcadb6d0831ea8ad35e869e35666889402cfd3e8d23dfbd1f4d7d87bb4a01ae08b6b1e3b9c98e36fab86b0c7ee8cb55d361437ae" },
                { "kk", "ed220bdd5557155e14cbc38567d49dab9af831dd12cd27003a404d0b648c0fda624e3b56d4081dcba5774dc3c1eea241d5b1cc5e86d1aa7b360abf36c7558c77" },
                { "ko", "9bfbcb2605a5ea102efe0157921ce3f06e89e15e6e78afcc33e0ffc78e4d6c460f9b71e8d59ac127a378d94e1a8f9612b8e03a7d7d4fa9dcdc56ee35d2f9d8e1" },
                { "lt", "92d0bc13cb93daae9db7867a6e62145f91da2baafac02b7895259eec5c4e0ea416708bbfa95320fe3aa0584ef67122a41f4994790e074a27439232f43a481b74" },
                { "lv", "8fdbb56a9e6ace59d81cb2df3704456f31c006f1464fc9cbffceb67a68116a51935e14b27a9fb5d85893f6363bddfc80427d1a0ac50c018aad9f5d79a7c7a87d" },
                { "ms", "149bdd397789234a31ae080ec890bd214374adb3e83733823cd7a157d5337dc36c1077bb3102ccb3d026836084183a38c98bfc800c6bffa68786155e7b2dec9b" },
                { "nb-NO", "ba6df1b782a313170d965f9dea092ad071c9d196049e7f7a263ba69f60263433c6c875aa8a3bb4e3c62053c796c4ffb0dd6a1dca48dc70a8c42167229d896989" },
                { "nl", "34d84b275509f04cb27f0b6fa140318edb46de85a4c2977406e5a24ffe1a17b26cdb063b3aee7e8a3e608f2a71b74f0458c7984987a91c5803840f8d540f0d83" },
                { "nn-NO", "8b16bae90143365e43c54b88c3c60556c8554a0b1b256fae6d6cdd5b4aed7be5b2f0414806536795c2b21768e175a302a369769f5288816d695c0d4e55984acf" },
                { "pa-IN", "1c324609f18877cbaf903269e6b25528a29fe0906f70c13ac1351422e761ecb56fdeb39304d0f8d5495a09323b308fd428be510b4ad87087b36fd7d988177bed" },
                { "pl", "918588d1bf9b3d4a1ffc69da584d4b8f15765995d99d9a7ab57069ec4cb5cd945bc4098cbced2850d63884b7af16c5555c4e8eaa038665ac80cfde5898f7bb61" },
                { "pt-BR", "01b9e3e4511d3c24ba4289165fa466d338c501ac710e3b34b3ed25e3899da32a2a68452092f54092adb3ebb4a91d1f33dd0eee1c873e6f2efafc051e8fb4a14d" },
                { "pt-PT", "6ae03fc74fb11d8f74a0443943529c98b3259117b3c2ae078722152e9c92822c46bbdc76ed1e10aa860ecd0e3981d8edd28c39d1d18425996a662d1c67b64414" },
                { "rm", "2a5dedd76f27d80fce5f615795bf5d1c3342818e033f2b374a8abdce1f41244d574c6567bf4c829cd55dccd4c6e9ac2d1bda5f7cfdbc2b0c14d1633ad4b6a2de" },
                { "ro", "b2cf1106a629d89568489525d58021ebbbcbdd57132069eae01769082f920edba27904a8e7a93eb30e2e76bc695830e757f46a5ff837f4867f6e3fdff1521936" },
                { "ru", "cdb606518b4f10ffddfd6b8a0a7b21391513362e8103cbb64af0a09e9288438fd940d8e687f40e0cf433d8916990435861e519af36f0ca5edc92292c5a5be0c9" },
                { "sk", "4223fedcb52ebb18fdfe8f4cb62a9b8a84c5f35b579f9ecc1bc59bc31bbce697f57892e00e877a360fef2f9c10fd8bf716991deb20ce35fcd11c54af46602a02" },
                { "sl", "475dd0c31b6220ba255298d65ca0a5bf6469c50cbd86df4e0ae42c59fba9f976bd0f7885dd3ef1bc6ba7aaa284d058db852f8130dd031bc301b2252306ff092a" },
                { "sq", "a04237c88dbb36fcdfbd20404ffc4aeba9b55050a17757fd33b8567b1ea8df53a0402aba6af09d74fb0018a9f123b1f688f219c4ad6b0991c13d1b41f514ea2d" },
                { "sr", "0430a3a2892ecb5253816ff47559c03aa5050326a2af903592a13f3eb4f146a9f186ac91a8306dfce10663fe8e65d6228b3e821853855b731d33bb256bacd937" },
                { "sv-SE", "d4f4c3d3f257f4854e086638596f155715abd64b12c5694c65c0cb901d2ed831eb20c11c87f6dddaaa1f0e0ea8a8cb16a4e399fc36e5614a221d1b2aec749392" },
                { "th", "66feb700f13377cb0ec57297214b5a0c90999b416194ec0e97e409ebf545abcc6402a46272ae30f772e42380ce60a605da4321c3765ee5b25e60b2cff759c3be" },
                { "tr", "ae4bcbce18d2e90316576cab793b4a03c7c62cfc1a509f269a36a5a4b210e382549f689978bee2a4253ffd4d3569c8be4bf6ee9b128d841a3dd354622edbcae9" },
                { "uk", "e668ea75d54ff6137d384ee5518a4ddc0196634e8fe31f35a0553673b30f2e2fe935117ac3ecbe0cfa46fb06094bc78d95c80d5c9eb5724c2404399cd33a6a8d" },
                { "uz", "1ad0c455087084635e45fd6f7f125fa607d80557f441a04b895ce6d94604a5ccf287e0e95a330c9ed9307b697b035b996188a4545570ff541941a74b13500ccf" },
                { "vi", "c5363631dca6fa25a4b4870055bbbb1c99dc82dffab3f099917ccd351cd244ae181e19937f4cdec32fbabe742b09b8fdfbfd69558076cb18c6e2fde5e505b6ce" },
                { "zh-CN", "3d34e3329a9d0f2f989d89adfe53dd4dcf26cf60914b7e7e6a99ebfb1986f9482fd8cdce439952a09f1b52bbac29a22fdffa7d32850f354de79e2fecf93f29ff" },
                { "zh-TW", "fd9a811769ad89f05983d9df6c34050ce12e92aaa4cf297dc48be750267cb9e53432eb90b070799158f2d4971a182e8dd185295f5bb792094e977ae7ae0dcbbb" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "eec2eef4380d121482e4b47beb939080507adf870882d30f8e9425c911c08af2518ee3aefd71662938dac8520dc0be2d0a5c5d5a8098782dca34e8e73ae6b5c4" },
                { "ar", "fba809d57d0c804437167ff1b6a73e8ab9b551855563f1bec0b7513f983d6e3cd609f384f9d38df4a051c24081ae32679666dc74701056d9d17547fb4ef6314f" },
                { "ast", "65735561f66477eb7af1480db605f17627532c8ee5a1e8938d799b6480573c6478d824997ce7937de732970b0d3c922630d03a47b031bb846f380c79077b0074" },
                { "be", "a2889166ea1d64fed0d7992e27194032770b30ecebc83038a370d97d22c93adeee36a989b8367ec68474de90dae5598c2c2bbb5b34960051abc4a3e7562452b8" },
                { "bg", "e7b536506e74ff41570e9ece00f8007dd02a5ba66aee28a5019746fc08072ec3c0bd33e49dae44aebb38a85e329963cd5ad486003e74c9a4bef37e9e20ea5644" },
                { "br", "c28e1eed2d1517362593822a1e839eed3a94453761e3229846eaa1841369bc7b994e6fceaea1d181df1deca05837f119639b27327f4911584fa0de42dbb31973" },
                { "ca", "524112c244eb9fc4f5210c4f3cfe075c2f076732e3427ae387f958ccca5a34742de9ea87a2d299d0f4e9a70b33398d9a59256bdb1d048d1b75e1f29cd62b3ab3" },
                { "cak", "74e43de61f5043df008a6599015d406f1fac8f1e58c3fc14c626634f916f6af22b654efe488aed41c1d5765a8b33c6c9448e8610844f5943c05d9ab849b89d61" },
                { "cs", "e80d7e8336d6ccf8033020579e753537ba2d16c736b3a90e6dc0337e1976d66f631a89ba8f8c5aaebc11fc1bea62e2dcfde31ad7f876e1fd75cc0bd6a33cb300" },
                { "cy", "4a0c4cb78ff3f703ee71766bbd7cd02f3bf286ec50cef32f70a96e41383a4fa1dbd4c45fabc4ed0688061bc805fba6711a4c4316e582cc351254d97dd7fe82cd" },
                { "da", "3dd5b32d80b3650f64524cb9d072c282150b122e779a942c854ff0b20456639e8cc9166457f1265de88486b72fb3a169c620af723c0e8255121eaf1cdeee0c30" },
                { "de", "6c04873f3c5e0ec765b290a16d1f853e9932e9db6edb38c4b0ebf44d8d5a5060539598f64e35442bd8016c675a9102cca5a1492a21e6277f9a81a7d6cae7ed32" },
                { "dsb", "68cf5186bfe0cff20953168a1bda828a381225884c941388d6f764eca30b7907117669359331672f3053b4280c53d5e812053b14798c9105666ca1068368f219" },
                { "el", "f840d01b8dbd6c867b89752f785c03dbac6ef51c79603a58c16d914115920d39973433bbed8ae5e99244ea90b7cf400f07cd5dcad2645ffee3be8af37f775b92" },
                { "en-CA", "2b373bc047d253446dae3d9ada42f5d16bfd0dceaf19838d893c2c53d1f4a4d1e6513c3887cd122eedcf99e65643e765691b945b9ced6a00a01ee02e6a03eb8f" },
                { "en-GB", "a63ee1e04f652d41188feb6ef451d8015c09dae4dbd8b503eb03fee5df0910a1ee4166476302be5770f4bdaf1ac06482a1dfc99a9250164cf0467ae681bd12cb" },
                { "en-US", "dcdd1cf4071dbee835b419147f073823082cf598c56ee74af8c4b00b7d9584ef74f031c808c0398c1684ebf8b7749343b2a8ceb83262c7d86f3378491bafab72" },
                { "es-AR", "534c859cf7c7ea4ab3054144f86a5e5ef8869a39d0e25f5b74dc1d482002c03d27517ea4a528016564dca3509f8b96be85e9b87466f62c1d85ea9e11d1d102a2" },
                { "es-ES", "311b4eae6e5cb21d9a608b2a9605110a3e00ba257fe76c62f7a708cce9ec921d96d274e2f44e6eab70e30d06c4b5b3ba39b4e0fdad34f439c879954f55452b60" },
                { "es-MX", "fb876ceac172d1b20fd0183b3710a3df1168b7e86ec7a5e882b4766dff23ab9465ec3ba17a77cb75a9443dd9857b63a615c0ef3fdb3dd6bc4db26ec64731496e" },
                { "et", "fa41c0c85305aeefc37570ffdeb2cf1fa54bc206274665a97f272e665cbc40bd6f950d5cde13445ac1f79976eedaadaf80d6aaff1433732b63ce0f67322c6cc7" },
                { "eu", "133811535c3f47e8add60db85fd4d48b10d88247666ecdac467f7b8cccb744b365a63c310fed66ff5cb45a7ecc7aeae4b9cfb84abcc9b5cdbb7c8baa950bdd02" },
                { "fi", "45ebb855bf2b8623ebccb55637f7a996f3d77d5583a2309e44ab7bdf70ddfe34c80d27e6184447312cf83381fd39a6bd25dd971ffc9d09211d6d883b87e0620c" },
                { "fr", "d165ea3ee01018dc1783c809d9b56218210ec0ec61ce60f92c19091c8f888515d54d3a09fa44bc8f4ddd1f547647f571934498c9edfc8dc3f9f3d4809c8ddc41" },
                { "fy-NL", "591bc5c930ad8af2acb4e46c882ad0f3458e762d0c50bcb1439029dcb35bcef50b19bbb5e25b100ff1bdff1e808a6368657347bf18c108046f5ae09a6fbc4263" },
                { "ga-IE", "1c1d1aeeb4df5266fb2ef37f80035b6017e2331cf53c6bcde405cf76043560f5c4804d9d90d5f752ac25b2bc34efcb4e421bbef68be6f2964f82750702166976" },
                { "gd", "fb5c355f15be923c65a27fe40bd6787b7ac02bfaf9f65a8e4de003880a086058ceb964cac02bbf659796efc72e86fcb8d85180da675320852d75bf3a162b4a0f" },
                { "gl", "a032125027bef5a52758064f278f5a708047dd1f6ae96d40437739404a58f15f81643bb921f4a55ff39629b7445557e29e85711e2b190ce26f668fa0053fb1cc" },
                { "he", "a6a85d9e0eba9a5f86915c0bc4f24dac532983e8e69f218d340a9c97ec53d986658c68c7558d61d18c69dfb52c4ebf0cbd2ea735096eff2e9deb2e94b7cd9b55" },
                { "hr", "a56fc0b7cf8644523faa7190d98a8cb5eea89d393a311d54c87dc45b0eb1dd258c75225d702226d1e719c5bb3d904a3cf6084f7d001eb5bf7fed729d6d3dd792" },
                { "hsb", "905185adc9ccd2297bcc9bbecd1d315a8911ceb09a0966d1e6a2e34611ebb52fa1cc07b21dd20a7da24d310752e731c95a132066f479df47d7cd7afceac8ef1a" },
                { "hu", "604e83226e663c54b74bf0bcb2f704755518c32dd63d971d5b53384ed380dea99aad88c3c75019829ae88817c184b9a737463f9bf0e4e8663549836c74fe667c" },
                { "hy-AM", "74af4fd2921ca39b442c5291c1ecf080613ccddfde564ace802b6fdbf6b6fae90b63da99878700e3b766564cca33bed6b787212b79957a1ae14fd299681e4695" },
                { "id", "409ce72ac45cbad22b222c8114b5252d9810b22c9490189098407daa1606356d5b1dfbc420fd4d78dc084356bc119d80e4a5b21d40df62f8b55892c6bf317552" },
                { "is", "92f5795b9e092ec18247e2f805d8a60a4298de916998603d78d3f8cceb10627b233789d6b541b17a2c216c91c018f0e4bd9468104d72bd4e7fee0df1a743d186" },
                { "it", "1cc2dcc1da44bf2b646c2d9ed8f74fdbf57364bab978b38fbcea2814c58958fc043c61a288449b3564078855ba99c756a7de1270d3dafd80bd2979f04c9fb05d" },
                { "ja", "f69e25940b99f0da05865582e00c63271a86a68aa815aa9cae4bab5fd0fd08c34eedb96f98bb89cd6eaef50b2daa0650adaaf1e95aad7a112b6a7cc73623b154" },
                { "ka", "d3342ce97091b252381a83ae0c152197a7cd8ef1c4cf4515d22c968c2bab95617457d7cd0196169d58bc8df7a00a1fd6eea967c33e01e166b64b1d9484d5c924" },
                { "kab", "abfcadb6b609db2b31088bc09ca82c1895291f83b2cbf760e6a0dbee2ecad6c63c9cb6995b89e7de234b0346e8a68f6502b4c5f0a9fef678118406df8a75e11a" },
                { "kk", "a9981e9a30a3625a942307b1d836eddc2b683d97f3e1575842cb7785f0f2eed7db2370bd33ae15500622f0eba2eb498e662671c7d9886882b319adf73ddf686d" },
                { "ko", "c92e2b416b4ff611e2d9f2f63ff0cf12ab0abfad27d245ffc98d432bffb1f86364f49be56d2a498d907c39cae4c511392f9bd4dd6757089de0db0da707e7ba85" },
                { "lt", "75aedaf19e8907f7591031fa6c9887c2a65f6d3d79df6f1bd08b826bd61d0284585733c62e43dd3cf71ffa11e96943fadf6c1502032a850fa4f1ebef843037b5" },
                { "lv", "23e86a77cc04f053f341154f99c4a8b58035890ef667560dcc8eaf3e15f306f92d752f645570fe564d3a3763a84ebf7bed177bb6bf9b668a946690413af2b087" },
                { "ms", "3b95f301fd9227d90f4cda00bd3ea6021e939d073084a233d1ff0fc6fe0e117ff9153f5e2bb718d74fa680fbcc841c619ea57da9b088f843f58199aabe35794f" },
                { "nb-NO", "46a58681ba0218a68b9e2b669fcdf48bb2a7558b78de74312e7e0814cfb9827dd5d0033a808fc6878395a24453e2c71cc946778533795d8aa0a280fed7b3386e" },
                { "nl", "e31e983fdba36d0722fd4ebe25416531b3e94519afd81962f6a4bd76f6e55fb184b13ac9c5b09d11f3991f1f5f7a088869df7fcc50101e2f6d05d9009680dce0" },
                { "nn-NO", "bcd120474be581c3571a91298094b9b7381446cd8008aa187a4ba9d39b8adc3ca96cbdf852cc2942135ee709aecadfec210b1150129a17cf2a48a1cfc51a6abf" },
                { "pa-IN", "9d81974689e19bd8e88ed28090f32d97ca6f60667fef199ca422cecc33331dd7dab416ca7a616136dc1bd3702dc786551841ad6bf57e573c8a0a5f90fa3e4a55" },
                { "pl", "a37e8f6feb2c67a6e09b1fbfad44b8eeafab92f392ead564501629978973b9c69e46aff281d462de0e9bfc45640ff425238c44436b1528eb9b036e3f4255d85d" },
                { "pt-BR", "1fe6058d268ac538179837fa68fc9a7fa4057eb7bf5a1233a4f6b74c9472e639da119298a8228c912870354807831540666249f39a550d1865efa22a96e7d721" },
                { "pt-PT", "ac0cbb52ad06f18e924d2e8ec926321ce19774640f4c15ad5befb8d5660401254ed7a5d4023398d779ff31ed3c92d67de3cf99cb07cfa81ab646e9d7b1bd90a8" },
                { "rm", "1315e7af4efc3d4c162beb985a38648c9c82c4d046ad0f76e4e7f0d135a89c7d73dfaf93cc5a52795b4c2e42aa034dacc91252badce09cd97775fa864be6ad57" },
                { "ro", "bff7b7d53d6c3b6f74f58996e4075fc3f005eb50522d5c2b362dc86c3fde483f3f42d552a734707588ba0fae4c790fbe11a88ee36024a1a2aea6ee41c2e7da0d" },
                { "ru", "06ccccecb96b51170c8ea17f8ecf1cb16091c68581846505918e0075e9c59f4c0fe59161417eec88d6af5abde0cdd138c75dff11f1d16ec019b8ae300fe4fc44" },
                { "sk", "9e79a61cc77e27ec537285f842a73015a2aae2281884a498ec5ba5b0365c9cae08b1e22bda6542ef5c82fcc26818a758a7560e690f91842507c9b8b2c9f48c22" },
                { "sl", "486d345501a8b1bca615308b3e07c1deaa5dd69dce9bb9799c7b14bb1d79078d2cba27612a2714c0b2c76d183467726ac04688afad7133f5978e0cd86ae60395" },
                { "sq", "68fe89d59d586e38a082412bd7b70ece4fefa16fd65e2c0e5fdcd12b23bab3d0dcfe1f9cd765b874bc60cf563bd0f195d32f00292c9920823a922cd07c0c36eb" },
                { "sr", "8c70b5abe33204f00398a0cfb60400751084cd7fbc680832998de20ceaa7b3bd9f0ff6cc3b489721bd06c2de812c9b9acf7866796db6226304149da7f961249c" },
                { "sv-SE", "40fe5bdb80f1583cf18284fa36d5a653b64dbd917b762de49a4b5e3e312d1ad61e0628015ae5177f96e0f8bdbf1be8695252c182b974b260727d6ecc15249620" },
                { "th", "11b433b6e4d6dd282292c96997db9eb21eda675224230873c9c69d25ca7afe90566b4a8237dc1ba7519c213f64e10af6500f2a4de9047ca8c0a3c30cc90304a2" },
                { "tr", "e0ff55b54ee89cbc8b4f74481c4e6f99449843b3f4d2f4b7b737d254001bdd1007f4de2a9417f8fa951cf93c0251b01d95cbef49b9c2e480937f4d6ef2054ac9" },
                { "uk", "5dd3cb5fd217d3e194c6baab6fb036965a2b3b2518c9aacb2a8e02ce7058c34c831c9f4888efb15639dfbed0c5679e41cb8bdb73406caccf38cf9d638eab3a65" },
                { "uz", "67b32b70abef385e81fe522a285eb3671149d42cb43c24968dab4d0e28d35bf475064b6122a49e961e486c3c11b7cbd99ac12944b9f167ba71f2cdbea0da229e" },
                { "vi", "feac5133a44757239742c589be70b7c32252f1d06a711ac77347114a093265f34160145c63d4ff23494a81519b0874cdb86539d9ae777675c56e535741b6c5a2" },
                { "zh-CN", "b30b679eb5d585d978ea795347f517f5e68a03e0902b79b7f9f056a9cac7ac4c99fb8b155346bc6637fe094fe4c2a2dc82c0011930c3e1f17146be3f01eb03c2" },
                { "zh-TW", "8ee7248992b0207c67153790e2097b5993953e59fab22837fe3ba30cfd818ddb3606e0ea8fb970383c1dfa8e988381cfc1ebae38b30432350e1695dd7d95938d" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
