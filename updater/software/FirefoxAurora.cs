﻿/*
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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "139.0b8";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8567af0bad4953acc9f0310ab105baafb6cbeef3566400ad46219862093b45d08cf75ee41ad02ab9a34437285ef3538ce5fcd690cba4ecee46a823e5298909e1" },
                { "af", "c7dfc0407c245351857fb676cdd5c362550ea1ab063411056881bce9a763682bb835e7b9e015b70d9a2f0ce9b64c4a24b3fda9d73ab7324d541fe9d59c9036d3" },
                { "an", "c3ecadb9a40fd895ea6f82e62533dc5a279b2528276756a6a331b03c9698160b42856aab28777300f0dbb1cae10bf646a2d6d043d71139f42aa01f53691d4f6d" },
                { "ar", "cebd3088eeeb176487e63d55dbf78839d0360e2df1383e92684c24143eff08a3c508af5722799f64c2e14338ea7058ec2ba1cdea9468cb86d766e33e757f1aa9" },
                { "ast", "1004093f98d1dafa0d02d620d9dfb89ea0682f0c43aa166ec0366c241e00a4fc530f724fe73dcd1aec8eac67dbaab0d8a78970ea8d054b74864f66f71fc4559a" },
                { "az", "a34ae0c55b509fc911027c14e1071e4ec331145c06c76f60c9e095abc11c45686230f19c46f6b13eabdb42034892a26cc2ef680815a50eb4c5b2eb81e6f8aff1" },
                { "be", "cc4b603cd1d14787ef106bda47c9c48eef700e47b2a8b6dd453d3a372f4d477a0714bf9c72491bb58a6608db220bc77ed9c54993613862a1615a8c6e88607c30" },
                { "bg", "2cf23de50a75acd99cb416fd3623c0c52e6bed4c6deee837f1a29c8a5213e881485b17a04a980f95f7ec8a8af0319a8ca05661bd1ce27f748b17989fb14d6f8b" },
                { "bn", "3ec20ddf1842c0cb22414b97c8acad37b955da075c646ced355b0ba73c12c0de7587951973fefaab590459ec603fee86b644c60ec265ed6ac4ff8995ab90a5b8" },
                { "br", "6b8b8091948afb523b9aba2ba557542ee8b7949429c5770a7911d306d8a1503229cba7e0e23c8de2bc2263a28fc394c6c9ca57bca9effb16d8d6d1c3aee5c44e" },
                { "bs", "59f04b47a0fec30da8804fc68b5369d9190b69fdad9a1f420de6a6f58a639347873f14a9dbbe9278f323213de8d64b1bb39f46630b54d70d851c7ae5b02af295" },
                { "ca", "60ee1d8adb5ed6eb45f97e02b89ddf0b19f51bf09504f23976919113a363b3a5b13d8bd3b83ddf09e6a93f2d7c773dd0a0db4983fced446999c07067c332d1e3" },
                { "cak", "a62356a4485a947ef11c1f3fb3f9517d3650255132d6c0ce2570d08f96d7206ab908c4b8563d185d0106c8e085bd97b3847fb27298ae75513f8a7edcfd10537e" },
                { "cs", "966eed69ca9ffe7ea2cca369620ba7975f72cfa715eb8c7eddd931486269c81ca65e5ed2ed471d728b5abf63a4462e84264e0c06e61e970985bc18856fef9a68" },
                { "cy", "72aabe79e4b8fa77a9d8b09d1522280da973cbdbefb0cb241f322ed5ef4640f7815d7f7f45e8e579204f3c64ed468aaee1bf9dc53730247f1fcb0052c83d891c" },
                { "da", "d68069c62a0845d0728f780b1a9c18738534213857dab62f78e616c8e52b5c1eaf305b801dcc6a589f6143746f985faee47555797dbaa7f449ec6c35d1d5e0e2" },
                { "de", "0de6b11288c68c0ebb2e5fce92981e57237b8e1ace01cd7aab0fef31d9e4430f3b11dcd07849fe881874a7db4acbed33efe9c6c7b03d3f998d10002f34aab3e5" },
                { "dsb", "fb0e9765f22722661c1f5db01f65a1b9212cd06bc0f35dcf87e740cf01a0aa960556267b75ea880a2adc5cdb0050ced6e41f316ab165cbb41c0e62d94247ec16" },
                { "el", "cd70664fb48d3ef19385e48582ad847fb18c1fc094f05621956245fa92cc6a12285e454945945b4ca2bda4ca0233dc5f96c5b51a89753dc181a4313d9a5c772c" },
                { "en-CA", "bacb8f59a105d138fd43a1667f57c3eec06d6d50c3cfebaa79c1e6cc6c334e87fa461f4e3fff0a391016ced7c757e6fd62d842d77694353c19660c4e903f21b7" },
                { "en-GB", "5f7eee26bb3cd8eabbecf19f40a736e5c6ae78d4d3e251a3bdc2a3bf1a329852a368add7da71625b9cdf1a73e6865955941aaa76b859eac6faa0a74123c5c03e" },
                { "en-US", "8f4d876167c22bdd3f5806607bb75451ae9e1ed8068ac7349f05bb5949274ba443ba9488102e54f1c1ec86ae9a10208806d5d221a792b590d329f5af1548ca23" },
                { "eo", "97b56cc9fd6ac64b7b97e5ac2b6d51373b216bf20fd66ab98c3a2680e1059b6df1431e098718290e67021479d61a02e2cd9f8a2386da5019f19f435ba510689e" },
                { "es-AR", "06e1d2d326b4d93eb3fda0c34510f8b4f6298209523602670ecb561e3795b526677d1e4190dd0a41cf528b719cba023f739d98fcbbd2f6ea59c65e03d90547a2" },
                { "es-CL", "f374c326a4cf1ea2ffeba14224afefd5577033cb5ebe465a44b3d20d62e3537cab240bedf9977a256eb6c266d5f33a475f613ece49d67fc4ab8862201aadb88e" },
                { "es-ES", "2e230ae1b3aa851f2efd6f8bcf5c76a6d816e55784d7b019619ea9876fdec2ec31157a234e9d1897c06c74c046abb5edaf3e139907271c012c8edeafdd53e521" },
                { "es-MX", "1557bfc8ed54c43fa60c6ae3e4db4856edbb7fc0598bfa08f40fef1ea15565857753a8136f6acd2288ddf3917d97f9041338dccbf9485e94ffcee6b6553016ab" },
                { "et", "c2acf9a50bc7cea8b854bedc6e6474f87c16143bfd02f60500f022b41d808d72d6e9a691f1aace5a1826dd4ac86480ca70c03c500d79ccd922c42e11bf41fe43" },
                { "eu", "c82ec8f494c1d5a36601e4162ff762042254d424b831c1f097eaa672a6e209d1b2f4c02f1a3616f3eb28ccf6c5193fc0aff37cba9a7151782ddee9117fd5fcbc" },
                { "fa", "d572c5d3893c3856a27a74e63fa8278e760dbdeb77486ac30f9fb4c88298ed0c39ecca8714f465748d98554bcd5b525259a380745819c29c05e2247e9c957060" },
                { "ff", "d6e68c067230c7a5978ca55f593532245ab5bcdd20a80d74e068cb12f980653e131d9c0d6bbd9a98217f0f84247d1054ce722afc971f9479f300819c7249b048" },
                { "fi", "1652ece46e71e3fbd27806f784d342e70f330f3fdf89b222019f5835e03bd494e2a09a73822402144e3a44a7823fec874131458d2ae78c9bf03e460488c5b015" },
                { "fr", "31eb538831b25efcdb593cf8b4689cd9522fdc0c784c8a63c035a5a87b3cae9211f1a96bf21e6b306faba9b1505b0fb9e0b8dc992af88bcc22b1347bac990299" },
                { "fur", "166add4c3ddff7e4f4879664bb4b5fbe7ebf7d4fae9324aebbc9f97b83c8325210817be9eefea70e4d47a90451d8fc89efc50f06ea037657d315f4c7a8d4a497" },
                { "fy-NL", "58cbb6103f8b42441d2bf654d73bf42a68cbe3426f3e4d13b19ab59f1e3db1c0ddc93fd45624a0d96a4861376c226f245c007ee88b324f96a1efaf92c8af3b29" },
                { "ga-IE", "13a37fb1cc62339e6ac6e05728c13ae2d9a1c0348bb7aa6a55540c75fe2ffe332872841543ff705f6aea00ef006c95922d9e0a9a6124c79077fd49dcd11fc2c1" },
                { "gd", "cc0da46b4737665ce80d67e43187bcec0d04835c89e95d1952b49f50adae8b54d4ca62d6237529a763abc9f2b99094871bf829d13628c25c128344b150ca72a8" },
                { "gl", "f67ac765056d698f3575f249f34203618bc53b2e43378f3791183dc85a0627b5c73cd00c169e911d7bcadea8a025262d1626e6de85e64f3bdd951cfc56e99983" },
                { "gn", "452ee94aef141eb1eda3533e8bb56abf45c9af6bbcb9a5b13a0d56215fee537db3aee088c85e6f4328e3cd4321646b8bb9aab6f1624585a1497e22cf36aa379b" },
                { "gu-IN", "3800cf664c1b084095d051e29a0550192a293ec90a269b8eb4f82036527fe968ca2ead79dd3fd4d7b4451148ca83527839e0f35677d18a636578b3787b85782c" },
                { "he", "63d64f79b6c33ccd8307272be2c54036fdf1d73b583ce8c01dff922eeb7668b14b34dd36d3709cd40cf566435cbacf5c154919034a978b3aaf54416457caa085" },
                { "hi-IN", "66461209b89cde11d9b139434c225608878663aa5afd67b951381a2675c58c4c986eb54b439253995c61074fd6473d610f09381c251f702bbec771b773be27ab" },
                { "hr", "7c7525fdd52bc3fedd8e1b7dbc4dd27425f32bc950bf9855cfa67d150e34961f21cdb91f0c933f2090d2dc2aafd24c4881b119bc4b986308a465a383fdf2ea2d" },
                { "hsb", "ee900a5114caa33856ec4ea761634d41986d47d03027f2e395d218c13b844cb3b597696611c5b811e98b7b831512eec41f03738d94fc8db75c84c99d37315292" },
                { "hu", "4cf4bd969deae26d5c18ffed299d7ac03ce5e14e75f38b1893d2f3973597208d9c946ce8362289bdd04cfd1971564729766f9e2bbd8885aa6e9f9430cd00b570" },
                { "hy-AM", "2cd7837080d52b9e92cabd3fadb371c0296dfe6b185dcd535c73b6d4ccd70169f4199b49392763362adaf91406df7980f84716dec2549896491eff6e2e124e4a" },
                { "ia", "ed87d4e870e83625426c0a5776e368e5175cad309e50b5823cdfdf3f801e254a5d38eee35b745473c8ff1ed7d058d67b619bca370e6e7124e17a1a9da8c8e049" },
                { "id", "e64f8ae6db559d96853bb1ea5b7a37ca6cc286d656999065037ea951e574f4c55c33ae9d1466765cb6974ca00e46c72df4cb4fee8352a0ba94a9b6ac4a51288f" },
                { "is", "5f3fcc89dbacbd7cb1511f3268f2f7ced1c44065acd5adc1e5a0fb2976478da3fd33a2a244b81664bf1f3300e8e27b2457d98021a5e5d938a5c9ca1f8f4b66fd" },
                { "it", "91fa1eb214d8294997d592c7998aed69b103aef769d1e8fdb917aa33a143826d5751ae2e87ac9f33dae44c3cacd533fa76bff7f61ada54265ef4050c98835645" },
                { "ja", "e9c6b30f09f4618acb0ad490c460e7c0f7ff27551d57fee93fa02d28a08d313153eb6b40dce415ed50d0efbdb264aac0abeba2a7496f70d768a19d3418e2dbe1" },
                { "ka", "fcfac6f2b3abe6af83bc5c29fd635e9af420492cdeb1afefc936776043db2599973756e1781ef949c61f06e2605eca20bb6205e0b1eab644150a6776ad455add" },
                { "kab", "6e9f5d58fa56411431a2e5860799cf279814560beef48e367eb870ba0a5c2729934c289806ac207dcac00dd4717f3a19ae97bda4db48590beab08fc1d96ea98f" },
                { "kk", "c45897659b3f3b25f104c54677dc7adc72a29611d807024ae125d776eced8ac861590f016c42317d855eadf8029ae23e54211857fedc7226b03e1b288bc06c7a" },
                { "km", "14ae13b21e7752f6e9e262c9c5906d1628c035d8d69e82b0cbcbee1b91fe3ca0c45c1f7c40abf1c37760228d739cdfec7af078252a2bcf36713307228462c998" },
                { "kn", "082a8f3551412b6d91833b347701ccf2192577a8a559bbdb255cbf39b0cb300a209c60eae19a44924796e81fade0d71c03674a76eef3b09b817e8badf38fee14" },
                { "ko", "eb6f19a796b903c2b7881b68e395b9ac371e3e124eb2768d3d2b83be64fcf448a0aa02dd26b397b170b11ab6cab8d7e8cbe38954ffc3efda1c9d9297586400e0" },
                { "lij", "e07bc81e0ddf2ceadd0a2e1779c6fc64c29a770a199a50157d518b4912ed8cb1472489fa81d0164541e0c44bf2582b265271089d0b1c72d1b177aa9f09959046" },
                { "lt", "684180ee1e0166339d5ad3971963468c06515c5495806a1ab1d785e8da8e85f4049483eae01221bd6b54c7efb77cff2f1d70c246d62d8aa5f0f85c9eb1531ae9" },
                { "lv", "999649e5f333f0ee65ee11656e10509cd507e0b6d734fdc1d533667abc43ded8d0624fc49fa4a7bb354422e49abfe336ff210e5f9beddabba7d3efaf5d4eae90" },
                { "mk", "29bf9e8d91cb40223a5f22054eb951e79684ca378eae8e090501329b409e1337e52cc3ceb3f3448dd4a68d1d14c724e8b8e46ae0dbbb20f810c76c89dde66430" },
                { "mr", "868a6feda39aefdff8366c3bc46aaa3edf3127f02d8676ad6ce34c6ec719dfabf265210c1015b1a271985bfa59242747120b7986e28603de2e15a0196b6efe7f" },
                { "ms", "2f43c655f43684b6000901d25e93a27ef5cb7216779626c1925dba1d2c6d4650f80c9dbbe1923225e27106e469df3c7537dca3f03ae7e312002519acffef5dac" },
                { "my", "cd7019ea15f75e4ebc42b1847e8985b4b2ce74cc3b891eeb65faea20ef952a423060ffc66bf61738b4d27d2609b7d87181f2dbbf43fbe565b52176c74db89014" },
                { "nb-NO", "408b63d50be72ea54edc8c6cd84d99edc10c21f94afeb3c5d28272848cfeaa1b341ee290d7186b0503cf985ac416bfdbea2fbf9995b1a1afb16e984bd44624bc" },
                { "ne-NP", "4bde41bd45e87997a5528d058991f99db87efbcdb96977f26af4fc879809da3716c3a4404796ac1ebdc82aa389aeb61cccf96bf9a52586d11cf8d983031c8790" },
                { "nl", "772469e4c99331cdd6624d0b8718cdc877e7f5bed21e75baaccec105c8eb9723ec898d7624960f6f8971425529aff4f4c587496011d95db294bf8f541b10003f" },
                { "nn-NO", "dbb1286135b507e6546f7caa62b29ccb4bed815ae7bc1f08eafa8bb471563fa5182c75ef24272283212bed94dab5245e2bb9e67dccc15ea7e60e08889ec8c790" },
                { "oc", "0e8d479f90102f6bd59b48be152de5b5176d3cb9663cddd437ccb5dcf33e8e25eaf2f60d2f06918b7737403e097fda9380d8dc9f9975136b2296f9412d9afb0a" },
                { "pa-IN", "eb8714eba4635772d1a21e995d670d9df809b3ab081cfadb6fc4f4bf17e71422fa31321639d7536bd624bac570bffad1b0cc014620229301264ed9e4b2206b63" },
                { "pl", "513bcbf50466b6b21cb02a40cec1afa17a4d9dcfb34afc3e3ec83421fb3583204a7a9d17e1a3dfd4d27f27f461183169fcde23cfd35103b1b4ac0381afce3b0d" },
                { "pt-BR", "dc66ff24943ccb09f2fb5f85ca0a54cf962f00018858f13b57be7ef02d6109dba3abb8c447d22e7fdb17f28bff1b21efa2f401f270f2b53df06213191dc3c312" },
                { "pt-PT", "9aa15174f7bb8798dba931b9c975ba048e5c0b8cbc31dc6ab67bed4c85bc938815db66d7db871e37fbd9eca2f56575884cc44f40631a5ce25ae6ff0f12b27e61" },
                { "rm", "bcd8d5e91759c36d790648c86091a5f8dade9d06a2eab27f71b0e539b033dcca65623a89f2f5171d72db87fdca90b8f11ece57a418c94177fe4bc8ccd3344ebd" },
                { "ro", "f2c466b97721a8a7b4acd9929c89f19fb5e241a62b28cf5df63d6582f2e7f7b4c3d7914a13a0061e12ccd9db2b6795f318bc01b6cd9c4eaca03b1b618d6eaecd" },
                { "ru", "941f6360bbafdbe3540dc6fd2f3bdfdf363c3e8918f5b90f29d5fde8511b883e06c58d291aade1827d5f1385c0006738d3dfa93163d2b39d10d6fdc1f1c18fd3" },
                { "sat", "6bc0bc3807a0133b84106e9f26c1ea7b155b892f097f5d8246bf7a5ed6d0e12eb67ed6560547aa85a7515eb2216ef6e1e5037079bb2b6a3c37c71a8b230f8803" },
                { "sc", "175bbe7ac4786b50173d7be35d3a0e90afc067a9e35444e8f30314cfffd37fbcc055993c39e4b59d9f144ee467efabe6840bfd3fd039123f940ada7b1554e1d6" },
                { "sco", "17a13046d5192ae0956f82c3b6d8880c3a78a0f7d6c403734b5d2b4e97adc5c664dba4248d7642599b6843dae16b67aa79ee56104a204f355dac06b209159132" },
                { "si", "4cf70090d71286c923ed094c7f9d6d0896a8318f75e5dce01efc9dd399d0b145bc8795acbba12e2f6d2a4372b8930eaa80492a83f6b661823595ed83c9886015" },
                { "sk", "1641c2ed04c2f63cf4060f022d28c3fc418fa5e188a06c915f79a322a9f43381f8e35fcf2fb9ebb49d45887008db6fb60e84b09f7b94fdd68644f9f50b3e43f6" },
                { "skr", "60633910a631671042d1cf480044310baeb5a53312e6ba759ddb8b216e1d92b78ca1276baa67356e0a1e6159bdfdee4031e9b7fb294c1ab10617b2ed1baf7912" },
                { "sl", "31a222c48263ae227e7a5e51e012d89cd4deb8eb40b5b6564a6ec6f7c5f4b77c662bc70396de8ffe4f8f762f52da3934713d08f890dc6bd3f6a7ede799bba5e6" },
                { "son", "887e8600a9f7908e0940da13475d7a70c890b3e473b69c64915f796b896cf2052e84c26f73856dc7a3f3d70d4006b3a985b91df63bbf37f85d5ed26467eda26f" },
                { "sq", "729d8df2a9d93918f1b0470aa41b8811577d0dcc390bdab035bbe35f7431dc22e5b62176435c36108db56a572d5e3271ace45f8bc371735bdfb67ed1b681ff6b" },
                { "sr", "d2622a89b9082a8a0fef2d5b09838bc631ab0caf146bf81906ee88e6249a73fbf4b624680417ebd6aea4d4cc70cc0b72e98c2e02b4e84b89e8d95a182f1e1c0f" },
                { "sv-SE", "ff4b406861ede003f98207a400bb5c94720e6abbf2cdf80d18b82653d2d1ec96f3431c99e30b14869d932ba6df66a00d93d45f54043e15e450a94f15c6bac7aa" },
                { "szl", "a622ecf5afa3bf9ec88475880dca5c2e39bfaa527ed0aaea7345486adb7e1b02b91be692edaff32c6f8b82e6df309a7cc780199e3d2f490823113443a2da030f" },
                { "ta", "748adbce23198d1895dea62c1c11c6fd6a3883d31b04a68351c601c3cf9cdb85f2940a30f87dece0761d1f727f3f919ca859a987c9719c48091cebc1a68ce399" },
                { "te", "85b09e65df670af9b3ae35271b811e3f5b9fba80326f133c4155e535601e648b7539c4741d8160cef9a346933e2f0ffad4e10dbbd72777a9566958f5ca10cb8d" },
                { "tg", "6e2e4b6f2bce3b680657a573feb5956fcfeba6902438bdccaf5cfc884b5c2f51e6df623fb7a3fb85759c70d92e807cf621797d1b477fbd26edeb1407004dd986" },
                { "th", "6e9721e4ec7eb6b0c7eb63b5df84c4b0c5c38236f6c4ccf201e1d6ecd63432b8a462656d735934d1e5e393ab5258b5523f71e535c8346f955a0ccbb3524b8229" },
                { "tl", "3fd7a42effdce8f6e8bf29a28b3fd45f4d76b6ddba6a6f433bc467fef93cfb96ed6b5699ec1b5e1b5536ead481e7eac3f4f9107f99b9babf454e4904acebbe3c" },
                { "tr", "f4a5685e09eed15846b15a3409e77c42c77ea141cc9409b8491efc17edead79be1d33b6a38a7ab30a8642162d972b92ad6919cfb2df420138d986c0f35d3bd2d" },
                { "trs", "69582ab39e95220e8667b2bf314b11ef509323d0706bc5e08830494ca6601abb153ff2b418553fc43989900c97859ae941f76f9201c66d87c5b97b72847fdabd" },
                { "uk", "ab76e952c059a4c436370de49aeb76181906c6e52846f3ffdd3142962aa465910959c463fec14ff294b4ecd941591c597890e2861d39f43bba80a7ba690b69be" },
                { "ur", "13b0b1a686f64e2820fdd755eb977ec30434921c970e26c2f3c1d2ca8fd386fe1469516e84754a714a07194a37510ec9f5e76f9e0ac8b14a8924ecc3b922c2fc" },
                { "uz", "513c0069d2492e5a4ede29d7d0fae851cfa59d1eafaa609cff738ad1915732c7ec358d928a54ee1c6f5885b84010a5ff9dca53d340cb78ff9f814a9aab9fbe37" },
                { "vi", "861b206a523607e91085f9f4554622260ec4cdfc8b3647c7b43df66865554049ada8bd71275c7a8e8bcafdc88de3477f14e43f0bb6ee2ccc11be45d3c9aee1e4" },
                { "xh", "e9b04910ee9d0e3ef4d981ede18200bedfcd5adf6951ddfc6405553862b96736482ed7972ac9e4d9569723e73d0f2ebcf5c90fd83ef51d0e76e3b076f915320b" },
                { "zh-CN", "2ba14c768c551810cae8e99971716eb76f169c39c219c120a6fd718b330aaac81db2a39b6bdb306db22c319322fd0c944f2fff8816ef1d0235d45e711fe03bb6" },
                { "zh-TW", "683e9ddcf0b31f131837ac07687475127414e88416b551650aaa6d1e3c6468295817ac9aa4ac166f2ad35a464fb596274845fcfdddedbea666fbfaa15b434917" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "08df88452ad38149467f54b8fc08f2533641b77ae657930f7eeec4243e8480ad4baf902a6f2f1db96eeb9070e235dcd063a265cd85f73b4f8f6750e94a1a3a3e" },
                { "af", "b5568016b676e5b19c8ccd93de874b4646b3926e30de569502299f29fcc10106fbb2755eb237f6da5edee8b0e9023401e803756b5233c0733c984077650a0a89" },
                { "an", "341e9eb147a9f85722f33d59e18b19a9e84db080d78fffcf17835a4034465e9fbca0d35e2e9959e6bb0b712c5791b3a866826dd4397d8dc82e85674171f5691f" },
                { "ar", "e7abc32ae7ce386d3e92520351a180adadf3cbfe8ad0e2b2a10bfe928fb53499c12a4db56e7426bb3b58d7b5aed6d229fe390a7af7e683819525a3e51e0325e7" },
                { "ast", "515cce04b1dd667212121cde689fd2c32ac9868c3f97826a2744a5c70ecb736ee47cf865d35efd464cbc33dc45dc3480b6f4e91c995cb135e8715d486708be6a" },
                { "az", "da41cac30e1e4e1bde81222e707ae5e7e2a9acf9e12162b75f11562f37ec1c64674d0feea68052ed6430998321154824486027c594b30efc00cb9a3670c38930" },
                { "be", "c2e4033ffa3ddfde396bfef358878e9c7cdf372c932fccae05444e6e9e8532ee1575279608a65863ad249579eb6e3b4a1afe806f6172664b8e5c74976aaac3cd" },
                { "bg", "19d9913e2c4ec4cdd9881ae2f8e1e046e302def29f1e93c277f13bd28de393d5ef35510bf670e30491eb0f9d02e85f98a42d499040d59aa3e8e70fd7b38a6de5" },
                { "bn", "94aa82e1b42c4472269ddd88940498f0d41e6af5414e29be3e080d985a0db8cc9b46f17bafa15108200da13d92beebe2945094a469cdcdcd3a482750b7dcfbe4" },
                { "br", "e48e387c076d4d92bf41ed7f1e57af1a4a53a0fafe31673a6b2e6d85da80eba5496fdf7637ed0ccb0a2f9992903e0cf8e3bcd32aef8ed201222f7ab01c97881a" },
                { "bs", "ba544d3d20def54a63bb06df6ef259aa79c60b1ae8f1f043bae3fe41238e5fde8f53197d84c8196911df2a8afbcb3fd3cc2567cf96a35a1acad91fbd55ae9e7a" },
                { "ca", "5e35a2fd1b59c356fa02fcab4d2b083181f541169743699878b722f593b3b42f16e1610ecc8d1f6f77721e623a8bca47a920699de093b2b564ba2f26c531c4f1" },
                { "cak", "f218bf3ef785a756b8f8ecc4530b3734ed8341f74e171a8f24c183155530ec8dd9b555c8485ef0f39e6be861acb2e21cd8e09dc4d7e8f5b99ee484263d71a6a1" },
                { "cs", "6a3572b6599b94b2ff512d21beec26ec9d9b8f89a99e2a59562c794c034d533fe1db7986581f7335a6abe18d121b5e2de42ca8c3499212bddb3e991c5381d7b8" },
                { "cy", "6fbad1419b96a209084372308908109f25608f5a517291823a5d578963fe159c9110fd9ad4e1f8146942aa6271bec4b3c933af0aca20946104329d48b1e2282b" },
                { "da", "45a6ab163c4581bbf14c91e363bd7719f54aecc3871284b5b00895cb1ca4843d0d6bf773f2a630c9cb5c1385e611368b23d29f1973a2eff2f8cec9ff2ce4a698" },
                { "de", "f4374554654822cb809e808f6fd48c4cf81cfd80a283670d07f7f2a77125487d590166cdd07816fdc9a5d9298640abadd0a361082e63d0b94781a4902bb7308a" },
                { "dsb", "2aa34aa175954f22b27eef79152eace0933fdf22aa352e0301145100beff880a2300ea9f2825c63b3275986a46149f92495a2272073a72d21d34810625f59e4e" },
                { "el", "34de2f0ee9884defd47f571d07957c3f1aecaabefaec9dac2475acc6f4d1a5b1a83fb44da9c7608f9a129804e2ed5234a6b79206a3b8cc0f02d83fcbd6e2a21a" },
                { "en-CA", "f23711294e44caf990f5d5aa393f224a09809abb8878c5024194ca26e297989ee964cb53fd2d3da34e6fd444ac7304b665c7598bfd2b68e7ca068030fe19a7d6" },
                { "en-GB", "54173c855c2b69bba92e2148ed0d01a591879fad180d7eae7ba97dea519dca647f1736fbdf8795e53e67d43004d0b3b0a69d52ffaf7e7cfd1397fdb97b0e5471" },
                { "en-US", "e22d594d8dfa9de3e9cc3bf55860a93ae8672ac04e8d2163c4f58bda60c0850c120e0434a6480b69a3fce1c36d554eb195080e8c0217ce7d5ad8894dea0da83b" },
                { "eo", "5ce8ae2c5a91c9599126579d3038d691e938d2edece7cf005afe7cd05e9bde45f9a2ad77c2c8051100a17d018b72fbe32f092df5272ddde43a63541b5b0defa0" },
                { "es-AR", "e672446b2557f6ee1005b38c11b26c893b88f476674b08ff5f2054e2aebff984e5bc88e12bd1e60336421c88a6b6c4ad5e1bcca8d27334ae5790c5ccfe0399d3" },
                { "es-CL", "201ee5959a1002dbc6d05c75903757772388e62a1a35b536659d822d7434d8d2a742354271a9d9c784e510b6b61e8c260dbc6bfdb809b64c7ffab93d4a6b3798" },
                { "es-ES", "f2ac3c7c9a6a803e98be469a119c0a384583266e6c3e1920092c74e2affed7bd986fdbb9e5c59449de02bc520260e2efb2fec0e7690f885475bf0d1c589307a8" },
                { "es-MX", "47a7b80516bfc8faac2f349a5c0048f87580cf8b64749b337341661521fb6ec7a8f2b8e70417df34be52d3e7d45ea2dc600bf665ab8b8845cd545eb4718e08d1" },
                { "et", "aef616ada3b9573d8dd4dfabd4edaa98ee9ce0b875a42c225ab4a02c650a3c439410ae05b5ec6573e8bda50359839d9029faf47af871454e4a3ae444adba6b78" },
                { "eu", "443822b089090a43022e1ccf27ce06f4f2c76facbd1754afdb1345c8c9b4496150ea7f8ea93f097a5e683629bcc5e5b3282207811d6cec6ede24618c27484b86" },
                { "fa", "5d09e94fee59f7e005e048f282933802c0c930f0b5947a8cbb94725efc3c964d50b042fb85e1067a4c3a2dba5f9e9fb2512378b5675a22599c332dc8f44caaab" },
                { "ff", "8607e70f698793fc5814e3f8539b66804aa97fde436cad0ab958e51444d53befb19e6789e99ba5f3d31aaaac79a85c27e76ebe10b921d9d45ff6bb151eff40c6" },
                { "fi", "d1471de48cc39b33795063d3741de69c03ff16a8c1d12ab6eec47bb29d5d8bf219afc17aabd40abe2f608340415698383f53af1c468b9d64f66b50ae1e15ee79" },
                { "fr", "bb3b1e8096000d2c5c97004bab485e76b2419750995ba6306c4cdbfbaab4ac74dbba6ac8210fa3f64455098c6e938ae3fdd79d73e7f32e243ef52823c8ca63fb" },
                { "fur", "cb40698eb35f1e3c2cf91c197b8e78998a042db535b22961811ea0e3d356792cd5ebacdfab1e6e61780207286108c1f5deb1c8d6fe3602c5f40032fa46567da4" },
                { "fy-NL", "196964a5e2dfbd3f726ba1638a4a134465d17e9cd65947536d37536bea46478756bde87bef29f06b242e320f92f0f605812a5352a4d483469ec70821f5dd518c" },
                { "ga-IE", "8b930142c000e6a1d11b9c8c8805c7f9336c58ecd9e5bc668b65bd65466dc601c5f1b58a05e919a8e88acdfef0aa2ad047225181b9095feaf23edb9d680a3704" },
                { "gd", "ce04f1a861b118c10e25ad240d2656e265fea53abf25896528e95fbf1072b669fedd172b9afc64a30215c890e6c4347f455489d8e398a39242740acbf3b83925" },
                { "gl", "39afa5119eea8d18d5f0819294467c3d63b51c4d4fa68a974fdbb2a948ed9306fb3a0a6566fab1b355900d1c823c70b138f69f747d4c8476d0d3755eee5bb529" },
                { "gn", "f0884f484684b408217107f464d5a2adebe27c3623a5a9e3f4fc4b609eb3813746b309262d4dc60813f6cfd779acfd72783d3ee8fd218ce7bf6ee8ec51cb3786" },
                { "gu-IN", "eca32a310dd562cd99ad7fd9e9f0f1a89087451951ef4f93768b64aba8428c53992de470c362873518cc8017f805f1150a4283e85d1812d6e09fcd65a829b7f3" },
                { "he", "d4e7dc8fbad66de34372e022153e7517f9bb93a3e3f3ae377b9b5152e970d6bcb7dc8488bb949e185cf58c043749936ef53112e8da8c9e99d8299fd61cfcf299" },
                { "hi-IN", "ff75f8f2c65a36c00108c54140417db42e0ea28343950df288eb749ed8923431f5cc9ee035e8ccab63a178898741a484c619b6873c2e7343186489ac5a6e0764" },
                { "hr", "c3c02e712b2b463a8136ced14ca90fdb93b8489a56e5d80bf0a42625a43e28d79758b25844c1a7497df93953ab50923dcebe268e2948d671f512ead7d72cd82b" },
                { "hsb", "227d3324a2c370d7c4976a594c7220fd342387180daa0c9a4627c65785334a3f56ee470ee7462a619e061950c55a501d601988a6ee4e3400606cb56a3d6eec05" },
                { "hu", "062c740ff3adacb5da20c73aa55925328f825ed4a3f8705e2b4a3379e20968e3342f4576a21a29804948b752aee3d9df6358cf0db6b5fdc6652f939485c704b2" },
                { "hy-AM", "7ef444957265bac5f49ec2831d57bd8fef323fdfc89b7c8f2ba46322dc23aa4b531bfa816478d3e8035d7f9c9185ffb35dcad3990b95a658d48268fea50dded2" },
                { "ia", "54552e17298e7645c3c5224ab207affc0b1514597b8d6441c7546b02e7bafa3221092ba8bc10043d244e89f6d84a8c535aa13efd65d9705618c995a412ec4d59" },
                { "id", "45404c13b016caacd80f61c2fdd8d0d40307959317518bcf8b86d5da1402676996461dd6c96d2eb2ecb85c6eba142e70084dc49d0ad9131933d6f015bbca7fe5" },
                { "is", "1a8b669f978b8b00788dbb13394526384f9018f0299401d4e9e2f650f362a50b29a4a850eb3fd24492ebcb44232aade8888bbf97c511eb3b2a432a7a82dbd02b" },
                { "it", "a27cd8d749d2240e3c782fed903866ab5f25002a92d2888751a32bcc9978fd29b71342cd2cbbbc7ab4df87b6646f18e6a9feb935b4a1d841720d4b80cd998900" },
                { "ja", "8271764068b81cc5d23c64d9d51c99c3c1e514d53f2c7048fc87ae0b052ccd425b8d06ed5992c1b0ab6dc885002f0be7745fc34ba5260824ecaac0683230f5f9" },
                { "ka", "44d64bb7308ffadf15914f3c06707b7db4f144ac278f0e1a64ca18a75cbd422e4be27b33fe32e8d139aa69523fcedd6bf25d0aa2b8b2cef4c1757d508b50a98a" },
                { "kab", "76ff4928f929dd6718c03b77d454b2635a0be5c797750d41e229f294c04f9411629c08d67a836f9022419f7a9b596d4b89fe6d05e576119424ea7554a94bd01c" },
                { "kk", "bdeed134120b9c88f69acea979e0b8992bfbc892b2899d159cf0dd70df50c0a1efa72b7328758fd84902fb0cf14c43a123c39e5bbb9384628d45ff5a40bffad0" },
                { "km", "d9123b7723f91eaa5e4542dfd4f01e29491e5f9e54651e83d476627e9449981aee776b41adbe11c6be0a331bf8b92ef610d28fa523adce9a6a1bcb9bb3ed6c90" },
                { "kn", "877c1c10ec3924fda073f5a25d87a31e3b88c80874c688bcb3440f5649aded05a3e8937679387b838bc540e0a02cc7d36e1cc550eb3dec9752afc5f09acc91a8" },
                { "ko", "d0202091a8ca2e1eb276ae24ba5fc503aaeb2f5e82de98f937c721d5d4c755358ba029d8a8dea723aabc2aa07c699227216954b55f15c595a203f4ed57c39203" },
                { "lij", "9d59a473139e30091754be9cdab1727f40ae9b7dfb3fec7dc41c70077ce9ffdf2686e16ef244331e2c2dc0c04e82d07c93d7df60e473dc2ddb0bffd46df50218" },
                { "lt", "43368d736edb747ee60570d8444a524c657eb968936b31f27292fabc4b17adfbb27d09a685223cf20ca4b1a8a4254738ae963a4ea3ff482e16e3272b208d2f58" },
                { "lv", "24c819cf499593bb5ef2b1ba9a1170ef02ee01c16e124b668dd65c9e0c0f6aab0210a529f7031250f2ff8eb2cb5763812e16a75fdb7a39b6c939a5267c8e854a" },
                { "mk", "cbe6eaff8c7a3654b228c9cc829dcc0973eda3f6bacaf2894b5f6e9111784feedac3487325de5c2009f1bd4e0d0555ab4ce0585b24d43fbb8265d2a424d049b7" },
                { "mr", "d650983054a9120f80de4b3bc3a43b5c38f69d05e1bc2b84b85552b64d866fe66a6b552917b8cf908467fb1782eaee302ba4755c5f59cbb9a4f23b734c8106e5" },
                { "ms", "022f1eef4b67dffd141b991e35298a3076d43be7618e94e9d7ce65a23f3d3bf263658338d434e49d073cff58f82444438d147a57b97ff9f47d3546eb1645c19c" },
                { "my", "25e078b0c485a7cf650b3199f53f55e4968a02af5d2d9e23d612f19364c2203112f9e1b32f78a43e18db67eb7889817076e91ee0d6510fedd3c67fa61378be46" },
                { "nb-NO", "a17093ba21dd7a414eca96bbbff6b94f96e6dc79cc1dc34c79410189fef83883bd67386a5822ad8795d9510251227a358c7f59acd2525aff977300712f4fcaf8" },
                { "ne-NP", "f804ad4cc33202c61724bb21a33ed1195a767389c896a6a1e234cc10151b6854fb9561ec3d90259d1a8eff1b5292379cbb92936fa8f25f5177a875890de14b1b" },
                { "nl", "2edbfcc57da5c6b1c6e172a0967c81c04f91102bd9efb695fa61223f725527b5e089c628898c7ba3f0cc28cb5c787c8e03af9ccbb67fba63c945467e62dc0512" },
                { "nn-NO", "7e2e2e6746e1e1f8cbeed668091581570bad461e0ddc38b7ff98fbcb589dadffec157ae0fd60cd275ac0245674758369cc564ecb42f7d6ae85eea412759df9b2" },
                { "oc", "fae6eeabb5a8265bf1f9b96ac4d00ab4208626784abc783878c181a95c0ba55403b5fb69a830bbb46ac5559fdba91d033252cfde45113af76ecd0786c3aa781f" },
                { "pa-IN", "b80d4aee83895a018a9360be25be622560704f1b6072bdb1aa57113b72771c0b4e380f155c6445e79bc57c56e00b8a78ed02201d3323c007e0ba3e5ec661f41c" },
                { "pl", "1e89e97a5aac2e300302048ac8e410c527bff7e42920a32e81e0e02f9bfa8fed4d67296354cb2f7c08cb5fb13f6ff17abf00b086df70b9bcc96a678b6a020ee0" },
                { "pt-BR", "1c9e0d97bd88d3308db2596c72029ddca366be35df2acfea2487fa553f0e121071651488762c188a36726ffd4fbcad7bdca47fbb55826aeb52895468daa3ad02" },
                { "pt-PT", "33f76c585ed170a49616fe5f591295fa6b9304b296651aebc5dbedfe8e43377cf0956b86c1fec8a1042f9490f42f4afe800d2daa8021057a1b9c98cd55266e2c" },
                { "rm", "1a12defaf718b7a221163f806614419d8ea432d6bebe6da1ac780935282a5b913a9c1f869ba12e1fe4413ccc01cc318a5892853acf61bd103186cbb608087119" },
                { "ro", "73fbf674a565f4a0af79988a82acda6289fb54bb5b581acaaeb711fe6c8d08e943f2dc64ad84001f0343e9582d301ef6bfb3562762ae838278c6cf2373b73672" },
                { "ru", "ac4762f3e3fe27a376cbcc0157a077eabe1b16a484157b4adbed6f8a101621faa9ed66bc5140dd451a18a1e01eaede9ccc2b456aa902a7a3b550ece8ec8fc2cb" },
                { "sat", "ff252e08b0c64f5cc824b638565b91693abfa5e17f2434ec3cba5ba7dd2d24565bfd9a21f887bba5278d81e78be7f89d3c45309966be43714747270e9b5ac9a0" },
                { "sc", "d03320d062dae2df2d6f152053e6aec8ee8eb1353153d8b6180a97e76eededec1cc9442ca5e389a04e7dec07d5643d9c51ed04d0898f9ea5d6fc3d10b6bcd922" },
                { "sco", "08482d2b0946373d2f64293736e36ee66a1eb5319d975cc43923427d9e3f871b1bdfdaf899876d9962bf8696667e97190c2df2a5a3776f348a0b225be4b63eb0" },
                { "si", "60f444b8c54ecb173d70efd83d4b7a1c089d79cbbb26d7926e548db04d9dae894f5e6e65c3769d4c0dfa0236e0f94a3ef890804f1fdae434e213094ac61713c7" },
                { "sk", "608489de1278dcd2e85298cb6a9fd5383aeb66be7fae3a067cd63b694d683db68d1e203b75b9d7666012f18969d63d5988d77c0b8123af20d99856ab0196fa1d" },
                { "skr", "b865327cdb930d2befd5c06596ad882dfabb82def804f51fd5625fa5387496287a2ecc92af5349a09e899c4b91c3659fe8684cda3aa3ba51624ba4532ced134d" },
                { "sl", "878e876cf2b97f8e6cbe05236b1d395bbff3a99465d5d258f8e6986f8caa9fdf6fb826df70c4c29fffd6bf51766e512740a6c391545ae99307b98b6885169ff2" },
                { "son", "8b163d00a1f2d0568b81807151bd87ecf86039af1609c421ae04454517d87b69ba879316d844c4dc4c8511a92df6b6d3846a9d991a63de298d4d5ed91fe08c15" },
                { "sq", "3e16c573e09064a2ebf50a69d518662edc580967e280d9ec60d14fcdcfb78339ab23aa413deb0dde13827d157377c4091051121c3b278efc77663418dbf6c9ad" },
                { "sr", "42d12affe60d18e271514b23de4e3fd38877a8aed7a1c1fcf7c464d2a151ac5a2808c1294c612467e01ceb5def7cd62ec525e8d0ecaf77a39e134990e6980c7f" },
                { "sv-SE", "6263ab471420a2d17d8760d466979a0928e2c8f352815d0cd025e1fbfe43b92b5a489047fd13f54ae00faebebd2c1b2ba22a59b1256712be6d0a0536d921b97d" },
                { "szl", "85e439e1e5d0b27c4a5ac4cd81d27853b6026a929447f150eb161b3ddce72ec3d3a349e4d75b401e7962b1ac847a32ddab93618a331a439ec60a878b545765ef" },
                { "ta", "b6d169e76d8ef076d3f85a2b1d70a602071cdb8b790b21922ce143a7d4f3fa631d6be8058d9c15e0b1c9b6f587b7a9f04fe1d6d09896583c6bb9a25162b20d5e" },
                { "te", "d8512895d7ca0ecec2b112c6540eff91093832ccda6df6967f7c543f44f65ce61e19b35744da5c07d792ed9672c409b05e9e90a4cb98dd252382a8236e01282b" },
                { "tg", "54de6dfa87f74bb1c9482da4319a697709717144310a0d3a11edb9d81cdcb4238794e915cb3c9669006040b0e483cb597b76612b65d3c03745a179bb75fa175e" },
                { "th", "5e581ad7ee73f2748698d35576c09ebae92c8beccfbd6f77707bb54c09e8090a28479381f12437d51c5ff0b8a24cc3cd5f5399adde6154becf5a8fc44d820a58" },
                { "tl", "94927f8b66396bdc83889eb0b40e4dc2e782dc58d2fdc9502ed073faa494731ea59c0df442c3a67aa1d91ac8b967c057058d7e6ce8fbec646bc3a26ae232bfe5" },
                { "tr", "d4dc8a7b909708f8e59b483d2698943b5e5640e309cbc9610e3fbfc284e7c6fcd71fb4ddfbf50e4b2ea5e5fd60b3b2d668f5eee8ad6364cc464f05901ba84dee" },
                { "trs", "d8d15b8ec48f25f96af6fd63775e1abb3f66f00898f7d0aee7c7764cb3e8aa3da2da14060a02b4e2b8cfdfd1182707b20924cdb2188d9e875da27aa339bc9677" },
                { "uk", "8581d16dfe9dd7fe073b3b3f0465c2695c25b64914ccedc8548ecd69eeeacfb9368be23c06e6443baa50cb0aa80168835316a67f79ac9607f847d357aa18f36f" },
                { "ur", "2cef1fcbcbae760ae73276a6d29cde4b2aabf78849d449f18b58f35d3343f4dbdd4b8e7b86f9cc29b601c00b3b4adbaf19a3b04408f328adc758b0411a331381" },
                { "uz", "c56b298a07c8b0593a9cff7021f588c90d5fbf64ea1c386d0c615b4ace0b8d584b4df92e59cd5ccb77c03b3ca49cb13db1094b4ede33a4940ce4618de656c844" },
                { "vi", "c4fc3c035d5b24c537260efdd3fc7a2f892b3c385b1e8f6b7a9cf8b18457befa443edc47b858a9eeebdbe2d03d4820384be06fcdf16fac54f493d5a2395b7606" },
                { "xh", "14f9f0875a074b9db616f33de443cdec902c2fdba2b9f202e3a9768c0fb6bc9055743db3869ced239a31a277c0810f4951e2e2255e135faa1c4901850bc22e6c" },
                { "zh-CN", "27f57a0080910706132180a2c33a97f37c5afb2f50e211cbbe709f3de4cfa5c7c6d922fbcc7cfa7e0e7d11a74569ef92be4cd508c77491c658cb57d92d71945b" },
                { "zh-TW", "0da79f4fb3adf89b384a26347acdd5b29cedfe728b1a6d0492a98ffbea347b930a69556dfa6111a5ae8e5bad8325567f7db98314fed19949d5a3a17bfd15c19c" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[^1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return [.. sums];
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = [];
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = [];
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
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
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return [];
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
