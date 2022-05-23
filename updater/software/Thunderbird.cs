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
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.9.1/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "73bf6dde7820672716e1fee02b636936978a3b8a9f43303b2a40ad7c5b02d7286d15144d3a521c55cba1d2f579eca5f8f4112377903142d8061127d821d4f4b9" },
                { "ar", "62dd521e88139e369ebbe642bae79504beadef95d49b59b8b77e86ab87001e4ed2bc346eebfeb01f7a0bc7994600620fcd16e6925945d0da42268b2bdb26e03d" },
                { "ast", "6f03de2464cdf2e0cd2b129d63ac40b655e3e979c9b4b3f808ae1131d604951bbf570595638e55849c6987088a6f5bdf695b60e2379ad36925a7dfc645cabdc3" },
                { "be", "2999bcfe5b9a6268d7bf2c4e174d984fb96bbe11f78117c4e42ab51f0767a10ff14b520d5200b14ad01543212d807182a788ce62d8d8367df264fb2fdddc76bf" },
                { "bg", "06dba702395cd3524fa50649a01480655480390a707b465707566f2510a0c92260b749b40c1081899ead8f0a5aee2dc687f9724088cdd66ce1d70ef1b71e4273" },
                { "br", "0fcafe486f5b692dd374a122df32c39a1d4828fca903f0922a77135ee25bdc1caa79c80bd5635f4f15480c8114ca4e0f5f081d97addb98a75d005a1861612bf1" },
                { "ca", "5f3a8ea0de666ccdee9f034cc7f2802c73b36aabc5b569081ab5024d9369ca492da65960649b58e0dff3967adbb7a1f713cfda2b2d96ff149609c171daa8accd" },
                { "cak", "186c968ad002253a076bd8838134b9129cc5bf69f4f10946704a9a6007044d8e109e958075c4a4ddde8f1a721cdbb11ce92abcf7b3e3cce1c4b235d9f1a12b80" },
                { "cs", "55df687afaaabe12d56fabbb4032c17bbd8285b23ed640f3ab982d3d1370472a786b64d2b6f856228df3b43cb732728d7062caed8b2fead0aa07a4b9f3c8ccbd" },
                { "cy", "dce01bc5da14691261883bcbe81b7d5f5dea51550b0303bcca8d4aa276140e0890bb99def1afe2758fd3de853fe45c0829bbd2e92ecf6430c7512e51eee5666f" },
                { "da", "da28f8f9565e8ce83becffa893d635115544fc9f163e23c2ee581366458f87059c3c66fe30773c83fbb60195fad74d9294f6a362fc2133f28a704f1ff5b3648a" },
                { "de", "2734fc0d813e4dab53247267c52003d96766999df8332b72f81a06922f2a2f905f7f4b53f48fc40e202bd38f58e387053e815bd57d967b583f7f9d5b4aa3d657" },
                { "dsb", "4ea51a7180b92b61612e90a1459df408f1cb3fb3be0dfab6556f33b779a3f7102ab8294353ac84363501f34d1996986a73e02eb68e8ddc93faf276bf2c2face9" },
                { "el", "7057f6fbfc248e918d63dfb9c9fabac85b735c5a6916e2cfe9f41bb5c2b396e30e9a5eb0a7ca9fe6639906664f4e9688e998c8ed15edd4f2e98c9a0509322356" },
                { "en-CA", "df3099d50ce3429842a2255de10384a21206e7261fdfcc22526b63d0f9b14d72412d61f812038901eab715922b244cc82de810ea56136f7bf9401763f19288f6" },
                { "en-GB", "eefb19b6fcfbaffc20e96c9472780727b2db870f6f50f3356257150a29e2ee3eee209268a826091253a15eb97286fe161bb09d1a9a0003b1fa53f32c35e88418" },
                { "en-US", "ee6aa41bcd11bec0b5abc047256a0e3a20a9fa646e0aa3c19cde090911602c9dc71d72243580ec6521c1fe0f5711907ea169622428afe6a11954e1ce2335c86d" },
                { "es-AR", "4bcc2669b39fb44f140b7e073e78c230917e7243787c887200203d05112c8d58b11f5e282081fee368a00de992b3dc8928dcc8f1c49a00a289a0a427ce513338" },
                { "es-ES", "46f2f190a6f8e513b2593886cc1732c4685f5f85115259d6ab31483addc706b6bc0aa45bf378f076806275ff5222ac9665b1219f2d003d7a29099a80bae64d54" },
                { "et", "66af63a4fe49e81cba306ad33be6466c9b4497f5e4839da9c57f2a3832c9641eb092744e2ff0e0fd6fba797c661132cdd34f4188a9db8abd8356ec584102cb97" },
                { "eu", "69016f47f66b70682ef7ea7672cdeb07a8a12798cb96b09171d1a4348c7c6546fc195e0a0d493ed7c82aa54421a16c8d70af94d588d3962016b10f07dba04863" },
                { "fi", "99ff0419a59dc7d1f9ebdfcaea39ba59b3a69af3ac0124a763d3ed44b8fe0f1003e36348627c7a0b17a53dcbd7dfe29d8a60b3b15db3fcd15b98dc7f6985ae3d" },
                { "fr", "42c28be2423d53eb7c519f27c9c3746dadec1b047f86944f6e71d83c3070aeb551fed049072d264cbd7d3aebceb56fbf160371a6bf3127a18a183ebfb6e315b8" },
                { "fy-NL", "e5a671bfc902a77b33f371c738a6023c4f04ae223bc432de0fdf58d502c10063a7fd72039112e9932149ce91f7e1137026b653205ba451cc5a98c1063307d8b0" },
                { "ga-IE", "195c44a4ab1249bd3d37836f7068edb5fe169e24ef81f59e1cca33bcfaa8a6a075152d1f3e2e2c1a8c447e7c2916e995b8f5e6c8cbf18ed0536af295b72fa265" },
                { "gd", "563d6b4a0c480319dd0bfbf8c0cb62c72ced5e9bb6f2aee49ccb2ae129b9db1e75628106e38780910ac0fd73406447519aed289e317dd96e9e69eb97add3a9db" },
                { "gl", "ce90515d8efe5d83589fb6337cfac4c2b04ee540a26ab640c712d79984001d2c9ce96424372dc2082cde3d45f026a16106485ad8451d387922a614fb194ed0a8" },
                { "he", "692ed81ddc0d921ac8fe28394620043e88d0e1f9a7cbf4723b8fc278ab4a6eeff6cc7e41fd7e56f224184d3ca255f7d051b7ccfc9d2ae4a30042e15c6104c49f" },
                { "hr", "1fce6977fef054b00a24be60871d8c0a2dadf95eaaab2cbe5854d8ef9dd0139e4e948030ff9f640df208f97dd0c23bb5b0da3ac4c99f8ff25f291dc10694b948" },
                { "hsb", "80b8dbb3b3129590fe6cf7b7ab1b921fc46ed0e666c2b403fbee2ff94389ab540bb3225cfd8edc52c3b9d31fa08c50e276d95e54a8339135c7dd0e7900c1485b" },
                { "hu", "95ba49a2b7c6751f4d129f4f66b64e8a76a18c35b2a634f11a9ab8f7479b72d8ce1d0b3988f5170a45eeea5382c6b26c0f077596af904594f6d5e58c98a40d8c" },
                { "hy-AM", "ae5ffa69869ab8f5bccb8d7cff8401b6d1538b1213cb41d87da18323e1a4e5f0431068b6a94bf18ad2a6b7dc944d1c80c081c9ff744b0782b595ce2c5ab49c1b" },
                { "id", "469d67430f4a1e7cb70f6d5ddb907eedc6cf3076626d07cacc59b795e88888b0a8bd27d6f4072bcff88e59431060902b0d66ee3c8bb6e44c9a236063167a1a67" },
                { "is", "429b4525ddfbd7506431e77ac63c17520e69f000a8eabb67c97f865687eb6afe21b0beb65769e5ad0d32d2d941ec76e64f2a833e6b0d39fef3ba53ce958d6d2c" },
                { "it", "98315079dda834acbdddefd6a073860796f78e1f56824bfaf11ef5fff1724c7ea9632ca0e0690a0e3e4b7e22c9bb55dd461580060cb5945716cbc1e6ba96c3d2" },
                { "ja", "3b4aaa933cda0938e7d36bfe3c9b973d875aca6f1ba71409c5644db624670b56222e40947d030f7a074c61d63a9c3dfd00de111431d461b62d9ea568edb7b481" },
                { "ka", "7991988ae73c7845230a7c21b35775129425387c85085ce22f437dc165a4779799c51a040cabe6371e6908313e95856f01cc6138adca41a4e5d2ad8e3f53b311" },
                { "kab", "f2a8636c5095acac6aeb976a826e3349fa5dbe507b31369cf9b0af4e3b6144e2fcb7fb3fa8049ad36a70a7325a3b95629d76aa5ea7d4a8cd5a09200f0af31d22" },
                { "kk", "21d8f596067ce8d588639671a6dd4c9440742dd84625474f58291a38418089836e4fc3ac4c1134ef8782a01341d33e014d295fea03ba7ec771dbb2e64bd9a595" },
                { "ko", "fc0aeb7262694486bb959dcd72824ac45d7797437ceb546d203e4cf3f3bfc94c584350ec5fcf50bce23b91e6b02429ca3536ba908f6337e8a55712812daa6095" },
                { "lt", "caa2d6c33a1a483f9ca743834ed5004f7b4ce692e83c5f1b6e9ccd42aff32799191bc9ca615a7b6150a2d000aa0a19908574502b0ff6355688bab6b27dfcdb0b" },
                { "lv", "0986f1bb8d541fc1b0b9ed781e29b74674fa56c0fbbe09f9d7c9ceb8a46d780b5e340f8e3c7704aad714178e2b757cb7d9c62bd5c0c7d0a51b3c52582a2248ee" },
                { "ms", "978aa21a208be7e173892eab426cb5d07868725da5eb9aaedd00d804e634d979f8ed7505610253640c2c53b297bdd1f0e701e1f90e996cc682882c3722de21d7" },
                { "nb-NO", "092cfab8471ce0c313795345389cdf2c42c337d26dcdefb9a3cad6f578a88ad039c28866d3f076a0eb8b01e96e646d02b44571f8801fd3c9c6bd05f7514b8c5e" },
                { "nl", "4db961d2046714c5c6101f46cd9fc1b7959589abc1f8ded13b49eb9b2ea6aea2d9359a71bf81a7008f5b8e84de354d166f15a27ace24af73651ff5035a82cd2c" },
                { "nn-NO", "bf5e5415419c3c35769cf73a87f337bf1a2966702bf302991b4b88f176fdc1511e9ba99474bfcff34fe6fcbc260926fc950aea5b9e714e25cecd1978462731eb" },
                { "pa-IN", "223ecb084601c7e5401629d03a8a93115c9152afcf0fe5f88d0e0df665410ac36ea197424ab889ac643e3a5e405f59f5f0b73fbdb8b67424cbe5fae87e490ddc" },
                { "pl", "f103ba31ed0f8356f36b6dc41430d70b40d0eb02ab5a7dfc9927078f768a3dafea8a33a23b956354ffa7b9796870760bf37f48fb3070d7ed53d8135ab9a5c82d" },
                { "pt-BR", "afdce2a4fe013c737ed0769b3c2a84fbbca42f6d0bfaef778a683c0dba6a231e1f31701b5ba0a0fbd785630a463853efc52417be58e6b97313ce230887861439" },
                { "pt-PT", "01dd1d37db2a56be51b55c2410815413fd25b9f79676f8700644812531f04dbd16c6d6b976af92323032502a7b616405bb3d5c52d8b523b3b883c498b5edb3cd" },
                { "rm", "e8fbf59e3a9146686b8e520b98c27fbec301f340c8d59da3bf700ee678c64cf508972774405f7fc7562046794bfc01b04dd0c7617a24c56ae2965e1f98f35492" },
                { "ro", "e4679dc37ea7438650956cec45a0910a4a3656efb791efc0d13049d0a3cba003d4ffd4f390ebb1381b6d4b97de19574d1161ee2735757694ba45a1807b30a04e" },
                { "ru", "e2537cfa6fbe13ef34adc23698908e57763e68dcf4eee8310b117615210299ba141913ec43c08b6225e31d3cdaf79801912d35eb279402e5a79ed309955cbb39" },
                { "sk", "fc933713a737fa52cbce4acdd7092b97337c35e4be86cb439c958e71dadece92338a1eeffdb4db62e23524263f1d3a7911d325e15ef23d90b66e00903a2076e9" },
                { "sl", "4e9c7c15805d4170e43f8c51c1afb48debf332c6b27751cf2b5625ee2e261a648c24f31410198539aea6c7778f5f35c467d594b0238eb771aadcfca7a1311217" },
                { "sq", "63ca1c1a2bb9f3c61750cb406597cf96380000fa3d9439b9be68715a427f204e3d48e83a291da8f83b4acfb30b2c2056b1982d20817a31b706b8a372549cbddb" },
                { "sr", "ee82c0fde6f6f3ab94006826961401f7d17ae8ffe7a8b3258d02db258344194d210d9ed5748c214d814695ca191134a3f698fd505317ebb46016fbfb1d60206f" },
                { "sv-SE", "b46cff9c1abad1cf30aaa8b1322d17dc706d1841bf423d483b93c5061980fedabb6cd545cbdd295eec5eba5e6e8fe8563e38469242814cc111f6fb678957f287" },
                { "th", "a21c3233719a4c5317d728a5f0bc1e4fdb778d226d13a176b5ab5bff43dc74003f0aed566a494165e9ab75f483c416a7f6d72749481ed175ad16f3c965fd520f" },
                { "tr", "4447f22f1b20ff94261dc258071109266108568c616ed6a0ff2b903dc6520fc98eb4daa45ffd6ee5bd001da9df1013871ffa014899008cb98a034fa96887ee6c" },
                { "uk", "c320a144f6c299eac61f5a33ee6131598ee36a332ecbadb8c1547e320faff65c0db0af08d90df636625293a683742538a0aca31f26be0ed94d72b8d57c00a0b4" },
                { "uz", "198da36878f6fdc0e2bf091456cb4f4a9565999378b606c368007b84777c11c1a1e38b9229e0ae69eb86613167094ffac837c2fd8f13a981ef87ca6a60dcf84d" },
                { "vi", "a81af11e5fd47d059c5c812e73f3dff87a4ee9884b0d8a264705de6d8b5baa53fc8f45b3eb8f28210105c80be2ee4e4743dffae07b8701f54edeea717b59d4a0" },
                { "zh-CN", "29d7fd419b23af657b1be876498ff71126055bd67ea50fddfc6d8a54fc857bf88935bdc432fa2645dc9042d03121c3d3bcc045658e30b8955633a961317a775c" },
                { "zh-TW", "941c4ed8350eb14723b7919a9ea5be5342d60239458c0801a9cba55aea0cb8e4aac53f69042992fc0ac4e61ef1ff9b22e138ba677dbbf6572468d072d4d1d4db" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.9.1/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "35660abd2c17d9689442d455caf14251a2d758ef2bbe6ccaa14eef45db56c61972dce2f59661e584e1d4969d5ba64ccc80c5e922b7a2ccbfaa9cfa46acfd0832" },
                { "ar", "338096a83cbecc3d739c20ba3d678796b53994d24009f3d7f015f3fe1623f3f5372d8eb2555309574fbfa3d5c4913b5cd389bc8579d27114987aa748da3d6117" },
                { "ast", "62ed5101ac4921e54c6a810b296e634a6e7131f7a94c9107566582fe01f9ab847e7d79fe36874e6a8fd9d0519b646edced739f6453a89372f1f2552a90d0415e" },
                { "be", "7a8ce5e310d4c4567973c33c3b2a53b279f8c378d36955c1cdc02844625be5c1aa086350692732f798d13d47141459c04dfd5fe40d5ff4b299132ffc0a27b2e5" },
                { "bg", "3fbfdede85b79f4d445fb2d2474e00d2b3d7d062dc2e6b8e204d19ccf95090316bae94593db380d4e7befc61cd062245e6e2de0661afc94eb8a534c64e1485ae" },
                { "br", "393de3105edf9c11f8085b3c2ed0ae2342168c46d086ccefe1368ab09aafe2362ad0bbd51dc615bc5f416bece72bcc6d7eceb7e3cbe5db64318b06e5f85b94a9" },
                { "ca", "db0cd0e49a6eaab2332df8456875974dece05909729565505915982829be9dfeecceeb000add68b5ab2c02b137fce54db784a5a2c0970202fededca8989ed0fd" },
                { "cak", "602a88887e3b6a8112fd4e27e7971e61ee7dd4a8c36860085a635e2a55f49cf0047448e55c10889ee59487e961afdef58515875a35e072014fd29c7afdb0b1e0" },
                { "cs", "b66b06b78154028c6d8f4282e2c50011a62a826c536a709d72ad7f2996243b4a8251d06e6586c4f0aa24f5abd330303ff24981ee761ab04f55a9864abf2d4606" },
                { "cy", "404127db7613f8deeed30f1b5c4c2debed3407537f71af99e57660557f570744a8154cbf8a43ebae20b2f15bfc23f2cfed2593142a3061a08e8419d038630d29" },
                { "da", "884542072a549178a8ffec5486738cd1f1d408624c3c381962d55280d562ebd1119f9e07f31fe493e6d78e8fd34025504de94751a002beffaab160c939d7be5d" },
                { "de", "07a79b0befa5fd4acef48a030cbe06832c7e8349b7bb29c78328618257593f7f2ff1c3646a027ab36fc26f7097e431d21edb375d0ab693692cc1399f8391c3ec" },
                { "dsb", "fe8b6ece7459400a886b8a5d5e490f1562e27c8946c069dbf9bfeec2338c2441557df205ccac1586e733607e9c86fc931e03d85cbcc7a1d311e7413cbb8bd26b" },
                { "el", "c514004fbda53129101ea1e6f118215a41bb8532f35d217ca3a5d91bd5ef33f002f029fbd44bb5ed9e96debb17a425685a43f3fdb937a29c5831904b81fce7e5" },
                { "en-CA", "c81ad62c928490c8980a2708d04a3767d6533958e2397d2dbfb93713567578790f4e52952e5768637f7d5dec2b7adc600c8afb2e17936e59dca54244f0f64d07" },
                { "en-GB", "fbe27513e404e0a0154bfa6383a6dd3c7e814c3d343de605dc41ae0a5e9b9d75cf7dd92978f44afaa048e4cd92f94af9aeac9408ddf3662f17ff8d4574a37f38" },
                { "en-US", "033b75e23ec12c439150206a581c05f914545a6764b9a28338ffec9a02c04020374b88282c75a9a82f1b8ec0521f06058a225caf27ddae3aebeb33cc3fb98d2a" },
                { "es-AR", "eca4b2758c24c15d6ea883ea0647a21b2a4f74cdbb15654268bd62171a8216da458534c6cee6b582453e143321b8682a270275f048a53dedb2764422137113a8" },
                { "es-ES", "a22522f59e5ac478f0a63678451034f0ee25ac9a25b58dafa8527c4edf8536e581ed23075bc77840a900fce479d38cc4713de4aa1e7ba224dbc835b3d393f1cf" },
                { "et", "1bbee4336789b13f7191b50c2f971e53251feeb2eb9f918c3efc653359e9935576b28be31e3172cbfa8466a02d595e830486bd8ee422a91a6bb26c080d260f0e" },
                { "eu", "d93ed6c6a7de1d3c8d70874f6eb26b29fa55ac85f16693d4ed09b449e8eda8927e11e8debb575cd73042e96bfb74cd537e101171e96c8964025ccae92cf2a552" },
                { "fi", "09c2eca3c5f04ed403ee8652d2d54b782742aad674e1d79ad5812c8b714927dc9bdd9f66376ce72951aa97fee79ba1533a22d28f570d559f831e72bcb77772c0" },
                { "fr", "87bcb19889da2e75dfb1c40f5058f7c13279a358123ff0fa580f88b1a6da55917064c30b07f129dc6bf55a18cf6a337101a24b1b5465764a6f88493a01777d24" },
                { "fy-NL", "b4be234ab1aed93a8c3373ed426676a3b8c2a4c948303c854394e5d41f719be5051e7d4b3fd363d871a66f75eb5396b82021d94dca1a2aecafb4fcc0ecbabb3d" },
                { "ga-IE", "95ae5adb9c2a2344c16852a0654af3dd9129719baa4e4cd15ebf5651b7e48703af70dd30dc31f9d82b0f879a74f929fd06cf6b9eab72408a64fac2ebc1ee339c" },
                { "gd", "cbe3c6378bfc22ef901d0b975b979e0dc3f047fe4694a9eade2534d8fd3946ca16e2521f1f937bc9417f44a09c7b1d6e99f317db37139b9fd0fa1d373303969f" },
                { "gl", "325bdb9012ba7cf29b33bba1c62e6fa739c64ec1d63523ff70b7da22a45027fc5f8cc6fadf4772c05b5d5c9b3e1d7ff99476eb0688f84b246d113cb7c364427e" },
                { "he", "cd12cb76f1c7b4ecd227b27c959545b2b5eed2029e69955298e30dcadb066230f9517a0e18e84e3d9b6cdaa4b1fb584e5559c4dcb2e377d5cc3a0e94d15c2061" },
                { "hr", "1b75f82f6dd038f99e04f2c661b673149556c7670337985cb714943f41fbb1ff4b135f59d8640bed815b4b93946a650b1663af880d21c6c9f184e56945040642" },
                { "hsb", "c4986d1df104e9c3d72c644c427378bf8ac2340113235efe4e60aac077e8f67382cb51e5f81f1732f7085db6516b6b778899cac69ee7869ade67f3c080079e1e" },
                { "hu", "6baa4148750f675748edaaae32243fb82c0fcd08138a540ae8247230f55d04a4587cafd9aef11d332c7f20b9df4cd030dc29e1ec6f626c4fdb414f220681f207" },
                { "hy-AM", "90cf8f456ef7fa40656308a33e17877521c71d55ab71c852c330c04fc0ea155f90bf3072d371cfb840038d1e21a1dad932d410d628380457508e2abe6c43a83e" },
                { "id", "750480d5a76bee72d309922cd2316e55462aa89e072140977c353a048f7bd65d4fbc796666c7e0fbc60cf36e731f489793f42a997c2ead8f80ab6e6ca9746efe" },
                { "is", "2466fb1eeff257457ffbe2883b0a7eeb9995d5bcab19747ea82e777b561f0f6c2998dfd17ebca6fadf4a786a734aea3ca7a42961b5a5ce2a12a05c3521a34255" },
                { "it", "bba8fccde6e9d6ca5dc030386a197757c38a0e3e2f6d5d2b63d2e2792b9c851e44c3a6772d0a5575db84e66e061590f80176eeda9ae7669dbb7c1b315b3d96cf" },
                { "ja", "b01d121dea75785dfea9cdc1bb9979008e623c4caeeba6fadb02346750fd0be849d52600a842bd8b5c8c25a0ce9d235edf1bc69e0d7d0b7ecdba845ac63ba3b6" },
                { "ka", "07b6564d9968dc949db75ed082f960ed7542eddcff60f3632d08c16546db3084d7e1e70a6b9a28708c0200affbae3e0ad864fecec549dc11f2cb072a15e4bfd9" },
                { "kab", "bd5828fca9b4787aa5b03e7129f007034e80169cb7b0d59df3ece209f4c91432af7b671ba0a6967c90cb49e9b3aa6d07248836692661f05afa4e286524c257e3" },
                { "kk", "82be9529229bcc3c0a35c71cd8ed0016db493ed4af633c632b606dc7c2c8746c0fe4d107a91544d4f1858e186dab857f28f2a72bf48ce5c97cb8d0fbcc544dac" },
                { "ko", "97397e54d76d3e5949f52bf86cd6d22e4640d563955cc3708361dac28da2554f3caf90ccc4b8d72b6f9ad0aa97473ff96577a86106cccf6c2021471fa044c7be" },
                { "lt", "02213c28a511a594df79f79e669283c3581e4127746924cdaa341e7415c1df68ef762c081ba6aecae39b0b36ca41963b27bb97d17910c528df45451dd3334a92" },
                { "lv", "459e6fd49e77bf4c77838bdcbbba768f939f1bf17955b7e571e74e919e4c95da37f3c49485069b4d20993ecb68c6f55dd17c7ff19d29f1dbf504f72a25495d95" },
                { "ms", "ede6769b55ad71cc0cc956712745c52572f07004ac59ae52f77d24e9a4f13fdef3760d2e9ba5c21f53d4fdb3028c001a6b78687f37e3b4bc43c50a26a647ff2a" },
                { "nb-NO", "e54e822acf8b034bba6e5e0ca065ceb99dd1d6b9bca5eb3b3212d4a0b608c78e34e67f9cd56a035b3f9a67544fdc5ccb7674723bd0c6c192ddd124cd42ba41c4" },
                { "nl", "9388f5b443fdccc33ec2d97927063e967ae44e8540f683485a2ececf1c0583b32f41cb53d37307f57b732a88cd017221faa101f57b661a1bdb3c65546fcb77b0" },
                { "nn-NO", "9db7f762ab787a974c88db3a6780948a66e0bf0a51c1d4c56dcce1622483bda22a40af2c500865dcaffa8fe1d15c30d96e0eaf7b049287641cf1272fd2f6bbd4" },
                { "pa-IN", "eb73a8b32aab6e10942f2a3556901fa3288ddc4701540b0332152f4d2f814f6ba76f6369e18ae903c6d41a721c71e61798f196a6d00e0743e9186e30c5123d70" },
                { "pl", "43bf35d82b29fddb0bbd48e6d099664256aef235bed012e63473b309a260e3448317ecf476182834eb6589123f5152e1e46f99807b8434329ff2d32f46cf199b" },
                { "pt-BR", "70beecca9d928538b053345b251d04b79e8fafcac9156f7e77391980a67fade505fcc0bd27eb6b131e525a01acb397a9ca404195f5956076370acc62f76139ca" },
                { "pt-PT", "6adf02db2de59ad5508ac12de2201a251f28e014ebe4692ec1aa2a5be3d9b766679ac607fb263fbb3eb00509dd26f621d1fdf49442f2a1d30c289bc98edb19dd" },
                { "rm", "52e399fae6fed21cdc7e30acd061722a662fd071fcabcdf1591a2ef1961a9c1f4b5ee4d99f47ea4b07b49c50dc02502c3f1da989d3be57a26194d8035c0176dc" },
                { "ro", "43a9f09cf668538d5b0034f772c6276afea06aba002bbd310f9782fe62e5cd890ce4bdf3e8c3d757be2ac9eaacc6da5ee5901113756ccc17b307a2ec8b76c589" },
                { "ru", "19ff661d4b4cb70f9577aab0ec08065958e07e3941cb67c4eb26920b9b9bb36583beacbc034d81f3c249fc4b58fdecb58f2bc0569c5d4a803d462647f44ac530" },
                { "sk", "84ec76bf0cf540e608e86c610d95eacd3c1f0badcdf888100db3d43c576078b8c318b15f4111959c60c7826a80b8c0f400b946cfefd2684c85d46d0e3a0c9acd" },
                { "sl", "6ef0425b2956732471cd513b6f4952bafa974cc88158669ab9608e8f81946cd9ef30786d15b01f872aa8083d2853330f983a5fae0e5ed98eaf9c436ed4e7c1a1" },
                { "sq", "a63ae5745e18a8c33a5a6fdcf9b470cdbc5173bb1f0cc5393e82bd68a8b9588d2c342d6bbe09ab199ede8c21294e5503acdff0e60ed722d12c2eabf0e4cbeafa" },
                { "sr", "1a3c41db7798fe67690ebf3231528f81e85940f4f3047c3be46896f1f5f34c00cfb111c8109a7169cbaf4a23ba2c9147cea05459b1baa4522b3e0a632d6ac600" },
                { "sv-SE", "96ca6b22d9d101f9b564ec9b319472969556b34c5494ea80b1ee11a2f8c21a39c88e855df8c65cc6f4f2389b2821af5b1ddb7746a4e124419b8c6dd18639c0d7" },
                { "th", "468023b83405c5160545e4921e20352464f09a23489e852d250160bc2043c6e371d666bcaa8064349d808f85bf965f12662d2fbcc287f69fcb272328085e7234" },
                { "tr", "fcc7acf9762128567d1a2df547a28ef7d7f7c0a0908d24d73326bd5d0b89962235bfaa418c622946bd8c4562b085f85cf8126be54a7e6175348be9a7228a7a00" },
                { "uk", "f76ac4ee1e79173abb3e83496516a72987101793acd593475d9a8b67376f5845b0f52c2d104e6728c39be2d37a929b338f24e733d57b6a7cddf366aa5f69eb96" },
                { "uz", "27a0515749f21e6dd34ee2965399e5486b2ae935b906826cca972123f75840e1b4625228ec41db0e21407e6653d481ce028343826da1b16b6bea714bf78f3d47" },
                { "vi", "8acff3a5dc76428ba222426bb36ac666834ad4b58948a354e313bb8f3389579521b9410860067876df4e6b4a45f57bab0005cf3455dc8e96299f160aedf05766" },
                { "zh-CN", "33168701647818394fe977e6ede943592db93aee38afdab1419fb772c32078c0ee3de78df851f380c1e95f2cfb4da1e86d1e8e4d730f9e25529bc5956f271b41" },
                { "zh-TW", "ca36e593e81a700c49eaa94d1517a2c0e4e9fb90ba93bdb3c9e2ba7149a3f6d70f5c17b4cb6f7e7b5c38b8073a77333cea73b274e26a97dc1982d926607a1568" }
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
            const string version = "91.9.1";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
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
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
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
            } // using
            // look for line with the correct language code and version
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
            };
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
