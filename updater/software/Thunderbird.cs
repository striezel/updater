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
        private const string knownVersion = "140.9.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "33952f35db839a946b7256d6eefec53962f92a85ec4c8e36093b8e0d52f7f0e33f673b78f3a2f1b8c55722e2e98a44fcf111b441b274b12e0a451a25b23e1f1b" },
                { "ar", "3195efabea33eb0f96727554d5704da604594c9af59595ef75d586e8146ce0c6fb25e05a05b6a73f7a22f084299d4bae82816af11be56efab0c132e2c93e7ee6" },
                { "ast", "1d3a9f008073cc5b9d8363fce58fa755bd3937c57bc3b280a2f1077151cb90ded26fddb5156dd73da5ecd1606b4a06e7420ae7b9d7d39c7bcd2a687152cdf4ad" },
                { "be", "d2475cd7345db582a6f296aa3162eb168c4b2fd1287e7080767d114c8ad2df1455d30eebd6d0e5d85dfeb41657b0fc3218c0e12a63cd46df3aea3a38c635afd3" },
                { "bg", "490fbd5ac55aadf3cdcbd15d0d4b5956d0b0a617274f022a8b374475db07f1d9199d59725ec61ba1a0ab1cd94e703fc615252cece19aa4d9fd319b6fed924e68" },
                { "br", "0da8ca2746583d55ffba898cacf26188e6871d90e6db113b555100a4fabd9e41cd9c56459d22ec4a8f42311fe8e71b67a9e7c43dd144e6aa403bb511219434a4" },
                { "ca", "279f5a8cb56e19f4b29f976012cb98b604ec31f4a36c9da26c4e8f0a08ba62f672b268a76bedec437ac8da9b80cce16c2d0216f8ae77f88cd83d139c88eb7855" },
                { "cak", "e324166471ddcd4971f7cf1ef1003fc775a7f8b89eff275a622ae5e724b0a3962a828b2b4f2647f4dd8058eb84cebce1e8bdcb921fa46ed5307129fe7edf4bf8" },
                { "cs", "03dde8e7db3e61279cffb1900cf3191a15957b93015b25d8236ec135e5b84bec7852c57061b200fb04014494100efc6ea1b819bcb92d20fa4c5b016a1af5c871" },
                { "cy", "d46b710ca73948458e1195752ae827edcf3ac5750ad2fe2d02b952afa7a019b8990bb771d0e30745319d8b68af80d18fd86dbc3ecadc31df26f3b9bcee8d4a39" },
                { "da", "7bc361f2658924084ade488dfdb323ec71390687866030b46cb8f2869bdce831fa2f17caef561bc9354828bd21428453501f8c1fbbafab21395cf56c34304308" },
                { "de", "81ebb6c9f9330f792f5da037bcdcb6c4dbb60882981f92adf964222353efc603b2c001fc40a9f67feef5f75fe9238bc2cb4a6380bec8da0355b9f6064e8593a0" },
                { "dsb", "deb671fdb7d36e7ad27c008cd86af715222531c393ba48b44e750daa9ecedc2d4f27a5aba51bf5bbfb03fe000b687cc44b340c3357d4d214488f7de9b06b91b3" },
                { "el", "22aa7b1004168210a872f6bae621e3618d52e087cc123e8f7146a198ad88c2f16fae926cf4beeb9716cbde7a1e55a0bcd5d7b522226f050bcaa28850c8a24a8a" },
                { "en-CA", "152fb6fda6c74db21a6dddbb3818275931aaaf0cebdd70088e9ce81b969c84a117b4f8290de1cdffed7c6b57bc34f239bdc555010404b782a47c380d1d6ae3c9" },
                { "en-GB", "e2b280c3e00a2e7975740b1a985cd18720e3dee32b72670a12296951da42ead10a0f3293e5d28e25ea8485514793d04d89fe5583ebb0d295c875579abcfb8fe9" },
                { "en-US", "8cae6eba8d56c748840bdab0b80d80cfdd1bbc26194854f724aad8d8d680b5465cc4946183adf2542ed88dc21950a8a596c444f4c6d51f60134be4e961c02282" },
                { "es-AR", "a5821ed9c211a37c2e4c3f8ce74b77dc91ecfa652fb40dc7167d9bba345488b631c51f94080216eef771fd54d8fb145480c7395608efca8d1d125d0df6705d39" },
                { "es-ES", "2993d32ea044835f14a6b2cd5c73f8933bb140cc36595903b7e2cc0f9c78ebb90fdbfc2142f4d68bc6ebb94b8fccf54b37a126f96788601cce7f94db8b23cc5c" },
                { "es-MX", "bdd9087749f90e668c2fd7796bacdd7ad3718bbb9465f94755fc1933500002a89615931bee6fcac082790478c7054d3d10b812d9dd3d1539c47a149b41f10016" },
                { "et", "f9fce5257fb5b5802aa4695507a3940b5aac61cc6a5c71ac1ac9688d89f525734663c3037a678f458294c4286cfe3328e8e96464f98ef7113ddcd2cf7710e238" },
                { "eu", "3e044c178d44c9b3481f7e8678142e42e0c4ffe6981dc8101a328adcf4ea1b96dccc37ef6cdaeb0dcb1c74947bb1d94c2f11d816a7a2d887d5cdfb1ce56cedcc" },
                { "fi", "853fa08abcc8d515fb2a4a1f90954fb3c92b362a7c9d08341e9f803e6569a24aed5d9293d9d309864f5ced9d3403abf81515e1cb678265bee0c865d01391aab8" },
                { "fr", "79bdb93b9d8b62475df03d99e7966c3a5728834160d09851d6d42488af83f7254e5a6657588e565e3f913846df8e626d00030841b8403427b309d62d7b44bd69" },
                { "fy-NL", "9cd8b2bc9b1fc65cc1e0d05ffff76cb991d47c3b548550c1161c073f07e3fdcd64d0cae0f60441dc1d8a2f7d15d01a9fc230e3c765607c29df16e44753a5a2a7" },
                { "ga-IE", "8a03ea5b2d616d28ba50c2b4ba336df27a2b9ffa4d74ab4cc875606fbb856272cac1d5e5ebfd9c7da05b6afddbfa6aad456a8270c8ce6d5f3bfacb7fdf14079f" },
                { "gd", "3b60a3ab527fb4bbd5886d68b421073d6768f58d90f9bf847ea046e6ef02ae1d47fd4a5458bfa32b295644cb34fbecc86d5f9fa8952809ea6e8b5d4eda7a4072" },
                { "gl", "e87f1079227f62f3be7898aed59af6577b80914af8c500942c61d28a6e3e1db50c023aec698a4c2075f2352e310a1908460c5df9c55a18cb4e3eb22c4996699b" },
                { "he", "c7da3607a75504b908c09545271494d61fe17b5186272335459bc544c1a8d9c706f0ab3f685436e34a9e0ce6ea5e8408ad9c0e3571faef6392b677b8b7261f5e" },
                { "hr", "cbfbe46677e05edf5a44d50c0ff02baa96b7736f1c7baac9d14762aaecbddb82a4d5f25db616a03f42fea307e6fefc813a8be9eee832df281a091da7d1fbe1c0" },
                { "hsb", "37ebbe4e005af45ae1b51f37b76a7a514e03879c292eba1f4ee8141c75764ffb43536dc5c0cf0016578ed887a5e295eb29648fd302b5f550e951929b056fab52" },
                { "hu", "f3b7e155798c63bf59cd1456a625c59285fd14fa31e34b37f5e1097d4408ff3ad230c00826d7bf711d30d532b22bbcf4e4962cf19696f663ced45f70050ec66e" },
                { "hy-AM", "3da3ff0fc17f5e1a1a63d8037e11e090e2cd6fc26547f2c412ea8c8aeb9e3ad15c67ff0b0d4ed8d3e02e4965596439b3dd8e5a186ce972a930cb8d234d61b7aa" },
                { "id", "919f01f87b5f570b9473af334de297fec789b3105be10bc390eab7bcc057035e622999cb60fb022996b7c2e2016d50121fd065dfc9df1a82d6e373bdfae5dafe" },
                { "is", "e758b0651765e15f16a7acf384cf5d37c5d3b66577c86a0e7138690483a06bbe5aea7c1228faf353f4e1e4352e1e0edda2f9620a8bb3df6f3cb816f88df5c042" },
                { "it", "95cf26c3542791c3613d878ffe91a731d5bad6d949d4cb553d3c0193f0123f75f6decb9b502f35fe26b43465e546b9c5b3aad0c9998fdf65009dd81bea016c6a" },
                { "ja", "7c564e92afc151bab889db10f6f30011ae467a62af2626d6a2f50ad4e32f5affbe676effdc00acfa8ff29771279860bfdabd7dae2d0c480b00ad6aa0677dc8aa" },
                { "ka", "fb9000d4308173772553d4d080a2fc554390ad2084288b02ae43eda5ceee231f5d4a24260378e345cb709a7f57dabcd5f4d228ff81e372e8a1cd17483b69dba6" },
                { "kab", "492bd8a4fe6e8c3782877ddd267b54ce14840514a0213c400cacacd190d6658e430bcead348272b1c969576a5f88e507f0181379e523dd1a55e1712bda79075a" },
                { "kk", "7f7ebc36adf615340986a23f0582f4accb2707c484752e73c851a21b7f08a7e9f769bd3f2b42e23e6acae9a12e9f3244fa42d04ab00fc621e32de9c459c1d96b" },
                { "ko", "769ff4f02f5add995313067b663129e6916b8b81ab2aba2b67e4adca11ad66705d317b062a9bbcf8ae02fdc2e8f262a16dda756d1e8d2a84056737a87970ae85" },
                { "lt", "35992e0799561ed26d0456a23742cf239ea432afc82c06c93ce7ed3bab08d0370806e1d16f9aabc065c6e55c8ac6e1a9cabf62520c362b8928b0cab7a17eb9a2" },
                { "lv", "843c4e197d6794ede95b30d553f184a2a002193ddfcb80f61f0afb74e38a857290280ca454571d76d6384d66fdd1ef79b4113eccc5f0af46f4c29e9315a7eb09" },
                { "ms", "a428cfd50ad4eb4520ba976bd859b7f1409655e3ac75775cf371071bcb2952cabcf8e0ddbf2f73d8307d63db3ccb64e451de84bbb7914b2171bc7680de082cb1" },
                { "nb-NO", "ad14b8ce5e3bd92320aad8e2f432da564b73c5c492eedf59b92c5065ed5ac5a0ef156635368fbdc3d162633f20297f6f76c9f5e6339ea5afcc3d4199c4f4237b" },
                { "nl", "cab55938ce61d161daf1e2265134eee139dff5e9fbc6c895c5828e0655427c513615b5c102b47731495265a83009d353447d99631294e0c732fd52b0eb37613c" },
                { "nn-NO", "41115217f2c5adbe03a776c14d647755fa5842410066f104c4b96e8db1874636e07c4d81f9a7bee3735ea295ac4563d766eefe5d99b63adfe9035456f18e7680" },
                { "pa-IN", "0e846e7a018f2aee8681e490882650533accf85b03bf1e6dadfe5c604faccbe61ab9ca4797efb371eda87ce2d3630374b280b4f16fa36c7b655a73b8138b5aab" },
                { "pl", "5bb11003da61675d2772894dcabfb7c329122c194331af61ca489a2e510aa0b8ea0cf8c2fcc25d11440508e0deb1fd771537f37e1a052e78ba197ea273adc964" },
                { "pt-BR", "9a2a6f8e5d3bb55d9a4005a176cf3e851b673a308caf989ef880800f3fa88bb390873b6bf7111498e3bb1a7a82ada296237941a564c96032ef7a8215a8c6c8cc" },
                { "pt-PT", "1ec6d66cb59b1e93351629a1ad19c2b2cba8e361c91e26d4b1856ed60842f7af5c74316e131d29935c975ebcf4af195183e85cedbddcd73e750e9031e6cffcbf" },
                { "rm", "fee5bb138636bfa612d6409f6d5d3d1d5a7e5cc5ee1ac9cfc81cc09f94a7b7bff7b1687a89fa8123b54dc7dfd28e506b7c6c54ec7efc9208fdc27502c7ad36bf" },
                { "ro", "1740c60b441f2d96cc6d2bc92877a4cc69a0a353d8d2970889e8b720eba40621cb0e33d5f8fa6b5586ec2571e926bc6afe534791a7a4f7102f91efbe01a92491" },
                { "ru", "591f0a99e0f656b951c07b789837384810493b1d925ab3f7d1a4561da3f8dfa36803e9757d5402c26423e51dad282c5b4e28d9775a2b58ede8208dbc634a8516" },
                { "sk", "8a327c40d82e923f7bd39b38544f589f2cefe11ccc26c88789834a4c30fe996b50bb0bd71820a057cab279710aad31d85492d8f6f7c7cb1257c6b8a19d517775" },
                { "sl", "93f2340bec62d93b2d68b9dca5005c856cb25fac6fe845764c6558000457a2d35e4711b1c60e60a93b4e5ddf3cc947b583a2dcaabfe37336f9146af0a69de14a" },
                { "sq", "388b7dc18831a4948f4580399a6bcfca2ed1896c1c8ee71e3dc855570d57e33db0373d201e43b6a3c681a2a2e71eb61f297308cb1e73f70b1e0f30d2aac20ec6" },
                { "sr", "9e410e2bbd4c4954cbaf9bc891b7036daefc72962593fd41d412765445a58496b9df9adc2ea5a0169903769e71b23b7a8dfb89c966d3e6401380c6ce08914dec" },
                { "sv-SE", "08f312c825804bdfdf89ff6d125c6f10ab04cb0e1b9135fcbcec9f300d94cd12a36303dd291a230093f7362dfd9100a5dcd4f778771b15aa63d591bb0900af8f" },
                { "th", "0930fcefc0367cada9f7d692a86c76ecfaf775e90f66498f3294036e058db9d83ac0b581a1cb91c0304f984936992a78f209ef4e406c6ac60413ef24f2c37a59" },
                { "tr", "d216e61d2baff19e18c4396d92e5202e9538f1adf5e1fabf3dee11193f57f92bcd1f703cd41dfa6f6b15c40bc7b30bf7e5e66aa96b23bdc83694de44362b45d7" },
                { "uk", "9747a5116fd05ab5cb58a3ab9731acd4c754bb054ba10e5779f6118a522a30c819c838bdaf727ee5081f93dbed67638c7d19ad60dc0fc3d7d764bd8e3d02367a" },
                { "uz", "0fbdf48640d0227841815aafe1149198ae0c1ff226595353a5c36adced84b56a58e48e898129d298a3e7ab30f60e859c8204592602947125dd4c74d3a3d86b4d" },
                { "vi", "195f5a497a95ef807a322b47795fa9a5e6a40297ebe0d8d47cb85905dd2d94352b490275957ddf5c6e69db26285df5b0765e28fa1eb8cba386b6174438d2a8b2" },
                { "zh-CN", "af091f87b3ff15b73cbfa519554e6a0b74e2a9c8e759fd54e29e159a2fc687836e917775b2ade39f66a17c2d754041b26a263e2a6edb99b68652092120b4f35e" },
                { "zh-TW", "3a8e18e599607438c7abc588b99c3a3b78b86ab8de12d40e207c373ed20c5bb6f4cf7d5e96e0691bc712b93425ec57d02b1032e3e7d450d72111da1239aa4f2b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.9.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "efeb81a9b0e5b54d1ec2dc31e968ade105d317d4d747d7f29a86aa29b03ee3267c1df45fec7c6b3949239fb8693f8bb01cf08f6a37d3575df6d5b6597af49739" },
                { "ar", "854301357f6b16e93b9d3a7636879d02ffdfc57a479a82e2ff7d91cf90d1fa6872126876c77a8045fc5e7f4ce5d89716d56f3cc183274b0c2e0958e024f18740" },
                { "ast", "c67a3b3f2eac533df68cc21e62047c4bc9596116f64219ab6c20cfcf4675c93656141a110b30aa75cffc6d5959341352730c45c31dd638b705558c1c837169a6" },
                { "be", "7f988ceeed997d0f6c92d36add59cd7955a9ee314fad2d85460ccc61f183d4e4ad93c891cf35819e172ccf8254ebbe8eaefd7df3d34715532f8cf18030bed632" },
                { "bg", "608d9e6542f323da6e98b00d4ab36d8ba6d2a3eceacfbfc6b9c0bab1cc139a6bce3e49ff6208c68fd9a247537bbc00f5e15e7380b74a1714a6ee17574d4f95a6" },
                { "br", "2a6fd90e5c2fa44c28c3ff5c883cc55f711e6b25ed4e00ba8c454d7e5ead2e0d46f214c3f675e2ceb9203fcaf00a2ec5b19d812b59b27b0b8aa11b65bcef0d92" },
                { "ca", "7a88d322d98700946b0415fdc1c3c2c9e16a17380b851596f0f0c92e89f92cdca71b6a0faf609d7b2a2972f7d733de1f2f399abdd1de65a28221cd892d8749ed" },
                { "cak", "56638d1247c97204cad5752dfa01545feba8907e0652cd6c5569a57c5388969dba49fd6f59a8139f5a70bf67072c10996dd09d69231f0f7dd21095c6740170c1" },
                { "cs", "83c8c3e5b87b29c44edb90c48b51088598c3109411d7ee6ef28ea964fc7532ec28feec7c8c5e7e3e30122300b67888d633e8dbb481478332e00c1f57f88d5887" },
                { "cy", "298122e319d04d44cd641bc03ae78c3572e595f3496c7f86bf562c61c94617c3d71ce8f201efd75d176ba136b4388849a1d1bbdc69c684d8444c6ade41d0097a" },
                { "da", "9a40e66598151dcc7af6d41b8ec22cc99a13ad818781f000cede0740d01266e2a4e351c82ed3558d9813797f0d141ab2a91912daf93d759a772a365345816f20" },
                { "de", "9f6e3b1334179f8d8e335b15bc93f5247861e66abe6ce8f373fe8f59b362ce87c698acb76de79240952168e22ed54efaa9d3388081b80f6c1b22f1ea8b647e5a" },
                { "dsb", "dcb5868242e57003d39ceec2e68d196981bafeda10d5a5cdb61c5be089bc15556e514c26d222ec232df6897a5890376f053bc1a8c9ccf815af36a6e5bb805f43" },
                { "el", "f4d44460943dcdfa61a38c586c01d636a840213789b9054ac7ee40de67fca2a993b63e5b735468b21373b0dbb02e0e489434e1079d7d8c95363e83a060f41d54" },
                { "en-CA", "8683d5ed93c1d9774a0fb4a9ba9aa866518809a9497f393bf035af3774f9c567ffbd4d5be23fb4f5539744071f047861ad543455895db8001558dff8cb479da1" },
                { "en-GB", "f43c9f8aaa99156b9949683c33626199c3c4d2f7f1ae9967f00cb55bcbad034255b0bb271be1191d6078c6a898e5908c83704494c69b3a25bf094347c280fe57" },
                { "en-US", "6f005030c0c6075c5f96cdbda8a901baf705d84afd95c7e7c241000d6f0110a494a4555cb24c96c5c18a8ded6f6bdad8a88155f6ffb9d968a543d62d8c375f67" },
                { "es-AR", "376939a4ebd569403defb8e598b217b7a93cc1bdc8fabaa6b47021f8c7e7b2f49b4ba95016026bec79e8f026efd58ff617c3b001a8a51dd7e1b2d3b6ec823c49" },
                { "es-ES", "4ab169937ac6bf2a9c6e678c6755c38e91f4efbacd196a52b6c6a9f4619f8579915348905f95b60bf5d1edb7c10744c47e9ff3cd5ed0cddc63d766eb30ed9c6a" },
                { "es-MX", "81f2a0de7fb7b62ad395dd624aa15854210b3e5f2211b9c99a949ff928f568b29eeca541f276b823c69cdb8c6575ae16ea8f00e1e37f45ca4836b0c44c4ffdec" },
                { "et", "dfc50ee91eca945922aef84d248baf2b7f62ec0f192ebc1ed55fd125bc276c169cab1a764d5ad580ec672077a80421625723ad8f2e282727fdb59f53abe98f41" },
                { "eu", "d461cfc69ca3040e44088cc71c506bdd72d7c335de251d041565a4152c3823900b375a1d4fac5b84efb4e3fe8453d75bb7a00472e941456e8ec7e11f36ce2760" },
                { "fi", "a544c983c899e69c46b642ed479b4750e0b21309c9bce396c833a2f3ab22d5e872495a2d72a0a498a3b1a48b5220441bc2e92771167ba9c56c37be971a05589d" },
                { "fr", "5529cbe91b7a77060c02a65e9ac6ec6e0b1a06d290fb3a938339578e7b2d1e885e60f77c247eb1c2651391fd8c460ef845de4abbab9c7099638ecb89b311f471" },
                { "fy-NL", "60eb1831cd4e1d8fef4fa484a76f9a67a1e099f2dd8b641b072bd027c91b9d63fd6b2c53df3724f4c515c212a140539801ce2707f316229082bac8a8fe697664" },
                { "ga-IE", "a0603e773120c653d66d73505a1ffef6f2dd89f0d5ffe477142a7ea1728ffde3b9b361f76d2a9db90d95e9a8e76dc455dc37da7cff5ec15c887d8c613096e6cd" },
                { "gd", "61ccd1324cbd4a7eadab7c0386187010c9cae06287524e4ac754b3d3ef39155ecebe3582abef4b92e3bde88cbaef47417d8b532351205512e91e532e1deaf3c5" },
                { "gl", "3c4b34bfdee0f5f2f4788cc5daafa94775030c31f50f43d0aeb34cedcf20022b982bc5f947354e800c3ccc86a885de5530856ba2645ac30ae928201926e10599" },
                { "he", "35145966b176da2a09be25ba35a0f6ee81364a6d7dab97cd896f951f632ce1bd0fcb39b07d737050c7130c3c7273066b85468b3814e3338053413f3bbaabdb96" },
                { "hr", "391a59d0d6808fcda50a6413b07a6fc02074e1cc0633f056a935fb5cc99fdbb4b4dfadd057c5f1fb99d703ea6142873a6bec45c653397475d3e2a3cc08bfd695" },
                { "hsb", "7f2515b726feb792c93a5181490479abfc5d4807345275c6118dd1fa2c296d9b07f731e773a286bf744181f91f14a603cb63590120c59fb2f6a84fa3b4b68463" },
                { "hu", "1d728a5a27c00e69246c7e01d61ca96dec8d905431474c4ee231f117f5ed3bca3ffac0c886c0035e4313cb87d2476cb0139cef416a2302a9eaf4d9b79970b6e3" },
                { "hy-AM", "cb46ed1d2b2e04de60e5eb653aa20982c55984ed75558127d58cb268e0922c54f44a7f8619410c680b2b3e2a4e7251af2532d8db3c13005c9c40f5fde794a787" },
                { "id", "6eb3a19e6aea8b1dd255435287f53f9c66e91b54d63fd2cb3a1807d9cfa298941f853f4d6bf6c55881db7b9410a1967a7161cc7131698caa22a20e20e0af948a" },
                { "is", "8741e83f3d6074c9afdf0d20ab8fa7668146247c23df23fcae658b30a338957f5843a6bb50dfcb456ad108e0071c83c7edf22cbb0129e390c05477ab66b4e8f6" },
                { "it", "ab16628801c03286cda5bad09c26a20bfa27646fb3dadad92e86458249e36a918c16b839547a1f25fcdb0e624d654cc58d607ad8285fce9161810f988484d6f9" },
                { "ja", "bf3c2455a6410792153076bcc172a8c25e183f9e8dd34504f0dc1427b7637d59b12ead4c3cb4aa1a2acfdd269aa882efb7aa595691f723e6c8036f2d8eb64b8d" },
                { "ka", "04364db52a1d91e41993b3fdcbaaa23512eeec7b68b9593f8e17efb902eae0dc0899194fedbe7d26e1af5e3a1700318781091117ce25535fecf41e3736078d76" },
                { "kab", "020923f3e6be9ad0aba7db9e1704967e536c547f8b3773ed8dcc1b52d0de058a55b680631ddd9894aafc14add1c371d289743c1ce304c3ab6627078ea3102331" },
                { "kk", "cc9f9ffb4081e367191ca55f2c6506a10cc8896b5feb2bc2dc2e4acff4bd2872e8523e71c84ec762f909295fef999bbbf3794e9bdbf7af42137c354d4c2b4a2a" },
                { "ko", "ca0969e411cea11abe3c01ab603d2098f84e21832d5d0493412fd420a16b12ba393d766146e1ca109d078633604a8ba63baf3736338c518205aabac27a981f21" },
                { "lt", "220249547acc3907c5fd3fb37a4fbb9087077d6f88185f685010576789ea313b9a0303beb553a6151f10e1efdffb493fbb5d6fd578432b1d1001471f6e64a0f8" },
                { "lv", "2506cb1a41b2fb08782e8168a8829f6c053cb31329c9044e77ee058f6f4de91dd1eb87e002bee0b0a7fd6b3108674c4117aaac6722f9599b99e1e337297718af" },
                { "ms", "6ddac410bdedba790b1f38829c1f258042358963306c1e06b3358f4fd5249b4789ff67b36d9561fbf872d3e1cbecc4b2038da22139c8f61c45e0d412807bcdd7" },
                { "nb-NO", "1cc37698b301f742a999407e4c4f61372a434ee900b96eb91b09ab5f3ddd9978d977128684a71840627ec08d82cf9eab58a1101dc96504eea181a33fd5efdf85" },
                { "nl", "3fcba55a12b2124ec6d97b0d7d56671f4a610d56748c3add3db76ca2eede49d54124cbcb7448834658d0626fecc23bd78a9b2eaa1e20f8e42e89ad1d47e33a46" },
                { "nn-NO", "507a930aac3b9cc8181f41e7042a991ade5f77ac24e40da64daac0187d47082866f4217a59fa17c08814b9a836e82abc2da64b80a9d7791456540b11ca973ea2" },
                { "pa-IN", "ac98ea9dc69b587a7d75e8c2b9b5fe333d7aecc5862afa3abe925eef79f4a06b6fb83802479c8d12c468b18ab6c30855db73ffb5534ecbc816afb25fb96a437a" },
                { "pl", "44ea65fe44ebb35949c9f78c6f4871ebf597935cc15ecbe728b2cc5ff7fdbda3ca8ed3ec1b52f8763d152d72dae8579b07e7475af99d2818b2337bfcbd83196d" },
                { "pt-BR", "e1e6705de4880f8ebc687a8127c7fffb240553bdfdb46d9c2399be024b4a38c208cb94ef74c8434bdb54ff55f7f407def069c8a0aba7a72fa62b03f9a6e6a998" },
                { "pt-PT", "2307b45e57a63ce8540e4be35576828066a040d2e0cb8cf10a3fcc2ce6a3aef29f140ea2cb56cd096c63398ea0f14fe7f82238decbdcd4a9ae885290a4ece370" },
                { "rm", "26d5de8c7847a6a7ad69cb6e94c578366825f1b7dbf012b7fce5d3ddc55e819a5402e561ff869e5b6679b829f33d1043382a51b5423ae81e5953c02eba7792f3" },
                { "ro", "0d5d0eb373acd13110dd6213a62fb313c5a7d8626be7cedea3c70c12465cdbde89e69c36e46f22296745833444f6a1585f6c2a61ab1a6fdb364490cffb2eef75" },
                { "ru", "d1cabeab923a2b6452d66e89320ed7a57e592f9900f3fa51dc16675cb2d087f90bcfee7717fdfd0520aaaa1e5dc267270500cb320775e2404f89419c5b773daf" },
                { "sk", "17f650c00dab9db1a6a3d6abc5c9b2bdaba5bf85dd7ceb677e0f13cff03898cc39e36bcb3d307752f662056b103c8e974cde210e48df41e2d4f44d094f5b987e" },
                { "sl", "fe72d117f35496b229f9da08613e4e8b0b64f470d5aaf78f90268a1c53a088eb398c5db6e5b73046aa78d639fa220c9067ccab1e368c51d3191c6a367276e9ed" },
                { "sq", "029ed63224f42594afe4ac357a002355e3d954217467d27eb4ea2905fe2fec43cfdf5712f3a974aae0623cd2f97c4ca7da8ea8434675f238a552e0e85bcbcf0f" },
                { "sr", "ad2fd7a61776056c81e773fb961e65571eabde1becf5504a9bcd3beeae567dd4fb461cdf32982e71e7938c14c65a8e8e429f6b8494cee0a32330370c5f743a28" },
                { "sv-SE", "f99e35c23cdc7e7db04da802e09078e022a539474a9723f3866fa0563b936386af610c7d2ba764f921afe9d417548e98cd05cc6f72485ab1d00c5adea6dc37bc" },
                { "th", "f528e6a413428b421c496ea6a4d8796c47232d8f57fdabbec60cdc810076a1f93a12c0d1cfc8fb9d5e717a69b7d9cda5c9c0c4d5e1905dabcbfd9140d19c90b7" },
                { "tr", "f25e7ec4ee8991457f24c04e917848823fb43133df0fe5af71e5f25cf6a35b810559222181a251f91231aa5f72a8a595c16aa8bab8bea8cae6feddecb7ec6cf8" },
                { "uk", "4bdd9294f1c5bf7354c368a50d7eff2afac944ce89989dc4372856febd81a7c7a10c80aa5cf775a429b8e2d0355f1802ccea356c09096255720d621ba3a1d3de" },
                { "uz", "9fbe1ceae58a92161ecf209d7cfcf8f34bda6049eafb10610913ed20d73f2b4b958157e24a788582b577dcaa6f89102672345591ae8188d6b18f923d40615f82" },
                { "vi", "5d07c421cf8a45ec8718b0c2f944c7b5c22188d3a50027fa2625ce64110480c847827770e0cf7507902943a4ab6c068defa3b74178ff19cdfa364d8efd2f5852" },
                { "zh-CN", "064d2fac598f79753b8651514463b4774fd18623b5c1e708a15ae939d0083bfd30c25bdcd2b44fb20d37f51e4f09c688660ab733813d5ab51969538bdd49e43e" },
                { "zh-TW", "8531d73a01677e43f82e360df32a9cb4736cf5ddee40c6b4d0b9b6f49c87c4da7f7d5a9634904076696efd8e35ff31a45bd721599baffbbf8e53d032c70c7a84" }
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
