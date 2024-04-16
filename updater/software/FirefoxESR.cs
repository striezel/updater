/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
using System.Net.Http;
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
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/firefox/releases/115.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "54b3a1b818338fd6c814b63e9a5dc870c30a5d345a60dbb5dbf1ae9f2d67eaac02e2ed1548c7ed8fbca6bc4c491bbfdd3b8959f6e7cd440b80b28a2a0ff4dab4" },
                { "af", "03a0492cf0b38052e2970d5ba48792b51feaef781b7641b799f2ca12c82bc6d6fd162bb2c3cbd4bec823f0e995323e2f1fbe9596f7baa920b4da303c295cfb89" },
                { "an", "555ae8c33e5fdc3884e2921fcb08b5f8c63cabdef93c7ffaf7ff440a816d21edd9786051413f265e16f4b37c0d2ad1cfd760c537bd54f140c4e1f4f477aff701" },
                { "ar", "ae08dad63f25800c899d0b2f315ee2f6c84dab75e760a2f5ffe060c2b00012060ff293d28b06e22c4906c993673f1af6db52a58b8460fda8fe22398697ed577d" },
                { "ast", "771cc28ddcfa753a2d50e15553de3f66db610199f883c1f5e10f4e90dd6d250764c2e5771b9a4a4f2bf2f424a408257f9934b43735354a654b08814a7686a7f9" },
                { "az", "f7af18e8fe90ec6f934c84b810e45a554d9e3f32faa9bfe13b8ce1dcddce6880a5c062f8cc8d58bb34cbba7e63957cbd2fa929a0543aceef22d38df98df1bdea" },
                { "be", "a678314c6602539154a4ac54d66b06a679ced63db7d7d3218816235c7b98b2ee2f41218c115e01c14264f9dfe858eb4f10b54dac4c4860e9f974764eab440d4c" },
                { "bg", "3cff526d59c885e6a3fbf93e7890688c4c2cc04c59210e68fbf0acb3c6859a0e8d74d734a98e954b6612a4dbac9ecb23b8190df48b05da8dc746351f6f2a6213" },
                { "bn", "c054eb4d1ddbad22d42df263bcbcfa65dc1e5ae102dd7992df7937e8589146e9986a3d4d0e9d4ab4d262016129c73cf90ecf6fc81be9ee32c589215e2d6b747e" },
                { "br", "dd1e57fbadd6580a79b77707a9d5d4584c2563092c68c0b41fb859aa8ebc412b79fb674921b4050de65e0e347aaaf8d348c3722e9e4f8be12c5bdb8d590f8935" },
                { "bs", "95f647136ae19af74985613688669ad48f928e351f87846ed05af5909d86c5fff521dcf6c8bab8077a2e8871c481a2480f81547ecde2557f9d34183e0ee49d5d" },
                { "ca", "ef2174ac1c01295ceb944c678a5580eeb81674fdac4ca45ec7ea7c05d69774c3087fe38870bf1d46a5503f34b0599a7efb8ab53e0c75a6754516e73b57649efd" },
                { "cak", "5ef2e5461ba5028e1c1f7ad1998725efd6f763b5eb16b10a18d98e5f674c53fc30dbb727d6a6235e5657833cc5ed4864b7faea13e9f3f1654b993b46a202930c" },
                { "cs", "50cca262907a8b7de0695d5299e2e5a0322547aeabb7eeaba6d04ea6c728d9ca426db6fbece6a1c252e4c1c7d10ecf776f190ddb34fb29760042b6bcbfc6fc6c" },
                { "cy", "59e4d33041fe0b7c341b5e928f14fb98c019b34d480af63aa9869932bb54d051fa53ddcddb3308d12972b81c8aef840c519b5f7f3c24a62faab00a670d9b98a7" },
                { "da", "3a5dc3ffa11a5d4951be7daad29c97ffe55a40fdbff25b5fd494b7fd6bafa634eda18828ea9de58618e9738bb31b2ea8556e9f05da985beda425a147f2ad5e1f" },
                { "de", "2b5c2ebc8bba2dc62bd1a2432d319bca060e4695649178d49df98c22da904f04aecda1c5bac017563b7acca36a3b4091c7b93a33acf604d188cb601ae4029448" },
                { "dsb", "cf54b795d86b00f9f744fd3b1c7de7b7e77f034b627135739967d58c84a68585aed8bf3200479a3bb3d79d77c4d38690668043fff39462c3f75ef654d3c1dc12" },
                { "el", "fa786efaf9d3df772f09a3d38f16570d014be6af57f4d5eeeb308c44728beef1c6b8271bf9a209274b61d139608a9a047e40151758b1eb2418c758a95467325d" },
                { "en-CA", "1ef83e2fa98e9bcc4f1d22013c55ef877186d631cf00871899dbf535458ef33e82ddf5765e36fb884f7078616ec0e4d45427fe342d296389192b80ccff21eb91" },
                { "en-GB", "b4621636fcd830cf6e0f7a124358a53c4ab57ec18b28499e0b4fb5ffcecde6b5d418fe5363eae96de9980516f8e576c027319715a859855a7db9175d31d5d4fc" },
                { "en-US", "cc9d9629b5bd597162519601b6418f2571073533c749147fc6a69464934acfd4fe5e864c3a8d5cc8653a003c045e5f55da932a81d5e2db872081a684374e6de7" },
                { "eo", "10d7bbd4c7bedb0ed0bee1e07fa3911293938be7c3e2b1f2886d0b565cb208f987e6c93f4a1012b8b36080307a7352e572b98ba2ddc83ae0b9b0f8a974acb285" },
                { "es-AR", "e45d2b50601769394adb5394ecdcc6a6b3098d902098148664662338f3d5c59df78d82c6fa43496b6db464653e9eed5f19f73624a86107306f6df4ace3c0ea54" },
                { "es-CL", "8e0b22284dd0eb7f67b769f33335043521e9a42322d3df48c5c8b4b6238db308799cb82e70fcae79d22b0b6b1863b644717c0f81cf32a7b57e4f839c549391c8" },
                { "es-ES", "9b99cf54dc291b81377f9104dbebfec9562098d2f1078be511014bf62c9d82a29a6a4d752e8ab18155d67bdcf816c558a995fceccc02c603ba4f944ddf9449aa" },
                { "es-MX", "5acc169f584124b63e001f6c09c5b17890498f18792e7465b8d13576a84d284a3093858c4b0c34e1b74f5e15208d0f237ca5ea30814ed981ba0030729bb2d859" },
                { "et", "272d43756aa2edf9560e1d26fc71640bb5fbf09bb25edb8d22fa1505375c1dfd1acaa636c2c8df8aec32b350fe64c2ecd569c0744f5a02867a09bdfee777a787" },
                { "eu", "f1a25c06eee7d32d1faa2ddd0968cc79d09e4f44884bbb3628b82f5c4ed178e6c0d598ff3e302c2de047bd0e0aa88c92eb37c35041542f0605f96ac57771679f" },
                { "fa", "8b8790852d6f704679015f34704961682bd06b94a9ce87d4d47881dd1b210f6bea8c463b4c66b78dbe9ce338cc5caf6d9f034b054047944023d0a59813b38748" },
                { "ff", "7544e80675d9bce83e56080c9e19e150c0e3e3f5f51af83c8e3e2781abcd262490284b4443fd49c5322b8937ea00e4e37ba1005bf1e14f624f5235a51637bf4b" },
                { "fi", "138ac74353266e153af6858dcb4ef446e5c306c2b3bf23b44641c54a8d1aeeb541a73ef6f64bda0dd6fde50624698af446a954a816d9fd463820c70c60af3069" },
                { "fr", "649ce2b2bcd7b0295f6232ba6726363550af8ad234c1e70a19b02ab6e1a0ee19536d5a326c3f08cd8df96448b04b6fd2f2719edf1d81d6b0b24b97e01d433ca1" },
                { "fur", "14ca2727375830adb862018350bc4dbd1bca3b130b8176b9e016164ea4bcbe64eb8db0e0ced0676b28f43cac99b7db775f15a1783ba1007bcaff50c4234ee4e0" },
                { "fy-NL", "e1b53d3ee63f12089de6e65ae9faf86e218e6cf80fab41d5dc49369654962233ceca666939b373c63848dbbecd034e2bcc76cace7582f1c96eaad012a58cfc98" },
                { "ga-IE", "5f62893df2cc59d3117e5ff12f3414367aaaa1791e436a0cd127ba5b908b78f565c34fdfe9ad174999c01a6faf853b9c19f5393847743db6c532a4957ceee63a" },
                { "gd", "afd2408e3f89347d5c0dff6aa217937c25b67278d0284f1244a5f12e2c431f2eaea1ea97a7b6221e35219fa133afef1d00fa9548c1d12a9cd4b375dffe70661e" },
                { "gl", "5d19e9c43a2862848bf8eb26c4b6f48d95e111f3890ce62c1b391c4957bd437a5d9161046fd5b096e92ffe0eea07a9802f0fe965eb8fafbf86781f52d0b24c93" },
                { "gn", "8215a9b809c1600fe12b048d7dfab441a37bb23333e75db5a38ef370646d437b024f880236136177138c0e40077a219ebb7a997ad59b2d33ac53f4fe2d013850" },
                { "gu-IN", "6be2aa8bb48a545e54cdab43314d9714d05c458bfe331defd6ee5977a2c513886f83342a06389dc745d2023e94d3e7eeb3360ed150bd1ccdf3532ac0739d242a" },
                { "he", "53a272090bd5754a5d49fb824ae4bc46534a888ad21b17c1dd231cf935062cea2ef15a551ee96cc7a3acef47daf900e1fb0130042da8210f66b4eb6d5438f414" },
                { "hi-IN", "4f2e4d6f5c4a8c7cd75ea309bebc4a6134e47bdd6e42809359052f48635fa03338a38ca48f68c0b4aed6d5a6986f0487dbb2bbcb92dd2fab851983e674124b12" },
                { "hr", "14f19bfd0d09f73421426198c9dee25671ca213c7349981a523872fb81a0ef45ea70ee4c7db3aecc31cd779b773d4f4b2b55d0c88d3948075c60888c7814a5b4" },
                { "hsb", "862b57dad79cdf80a6e9148d23dd4d650dd3043582e3c3c489c5df464c210e1883ece184c784d29124a06a0ea9e551c37712e862d9435eab7f624e38933d774a" },
                { "hu", "b2c83c30badb8601a7c791dff52b0fa7db15749f1a872f2b6d22854f0822c7d222a7ed66846e8afa5af7ad8db01c35bf95d68b2134b7fe6b08fd48c63deb4db3" },
                { "hy-AM", "c292d3df8b43456bfa63ad271b7cdc287509987becd73fb0415da4e5f591a1a8a96aadce1fe3b59d4e4e69d73ea952eeab94210c2fd1123e215ed125a3369e00" },
                { "ia", "35c7351da160656e525cc524c508db777007d3bc7ebe10d3539837c505e4d0a606e47e38c593ea5c9f8732e395df85bc027a0a0f204c79e4913ead58151d700e" },
                { "id", "3a60d317750aa01dcd0d442e701a9fc9055537bba5cd98bb58c56244ca4dce7a1eb66630f6f220b3d6e4a4d42a827812a0f8de0b01cf2ddcabd0c1ad095347c0" },
                { "is", "6aac4625e532c4f70d14d3f8984364b91f34868c81790f5f7fa08e08d59a32af429d71294ff3801d3434af5d4cd4475cd605a893ab0cfb7a93b3123be8276574" },
                { "it", "0a8b87b7d1738cef7c1c75bec15afc889a28426227c8a170dc62089de9bb34e68006776a7ca5a628ed7ce1a153cf81856d098c145643400c4877abecf5ca9148" },
                { "ja", "02dca0df4c111ffd8564bdd2c6b84b969ccb39bf9d1621749eea085419268c344bcd7e3caf29460546eeaa124c985af0bd6f8c94dd3b2593ed3de3d39cf8d2dc" },
                { "ka", "b1280addd1177e590bafecb69fab5997d477725f308ad9eb309894dd626c56be29826925516bdffb23937ba3d6a38ae433c81915724d9c3d859f485b86063155" },
                { "kab", "bcbb2408dd191823e4274ef3b70360146149d1f9cbbd3da4d78c074d24738542a2b72b136ab3c71781a74690cb0e5f912cd6fea7ea74cd392fb2ae5b937efab3" },
                { "kk", "1a066853e6410339d98cd9ac1f818cc996609cb8374d66903414aed1dff5da895421b6b99048ae273d88bf7d66db7361baed3cb46a68cbdbf43d23929aeb162b" },
                { "km", "26c8a6013d30b82135937dc693d226fcf467eab11aba66caa3af55f616c023e13929aaf0f424d9966d2c01e84c1598ebcde5a12357857761998447007eb075e8" },
                { "kn", "d697aa52fcf3f721c0f1171907e7c962169b5207b06e148641ef8bcb00cd3acc7dfab1f5c821e9361788a32185a41936670bb44ecae3ac9080de7f0d972d904b" },
                { "ko", "2248d3e62bab5043903057ddd7316b59a0d215c52e29c3642264d206bb0cdf4d0581261bc7f107028f0334c656a37350335daae44f862a2929c9e78033175a59" },
                { "lij", "872a1c053839b97f878cffa7dfa1df7f841cfeafff43a3a1709168666e3f9b7d6d1d3c4c46a4efc731f61924aa7ed836f6761d80e73458cd68c1d00f3de54e21" },
                { "lt", "4a14609c4f4fb50f441afddf76886894694117686bea57355921ee5394dec4fa4d7b4ae282e41047ed56fe41fbf850adad6dd08f044e97b54a7c21d675c0708f" },
                { "lv", "4fc5cdb59c6450072ad50340e5cc890049b1ff7146a0b8527bf5d0a06a338e2f36e0af89ac7ba74f75032b7a39a491ed6e49941c1b3a44f714ed74904b1e03b1" },
                { "mk", "b83fe2a785bc9187a367ae45d121504d73e8cf9e089f0405b697677fa4ea60318b1d639b545c0f3d9b5d000aea1228b7a9366cdffa2ce08038cc777f16f768bf" },
                { "mr", "28caa47a9068699afb9f24e6d99295a457be9ac67ba7ec9cad2939c0047efdcfa81fbc2e1e3b7c2cdb57f28b5a28f5df1afa30a416c029077f374a57db63c4c9" },
                { "ms", "d425c961fb048a61c4708816fbfb2c78d343f84fb7316c6dfb94d8706d4c9ddb4b2f9578e447a26e64e6f43dfeb7b50aed1d9752a46bf15a77ad67c3b9b07ec5" },
                { "my", "ce51f2dc7daa1b835eef7d5a2173b0016dc22cc2a13fdcba51dc4311e6b174355224107e04d16eb34de52d4215b4e0902993f2f7df2ce6b29cf21e853f246806" },
                { "nb-NO", "578d5885f2f28ca430ded93904f1d1c67a8c01ac0183b3afdd99e30179b8d359d619633d21b40319c1bb39c54438c811f6599a8f28f8c7b3aa5376f5504400f6" },
                { "ne-NP", "abe9e163029c0f4d56eda8620eddfc1834d0f2aa19ff0c11b7200adb5baccf49997a58cf3dfa0603c2006cae678d64d7af87bbdd3142bfac906cc850efba03cc" },
                { "nl", "7a31d5590ad3ccc18b9bb22815994b3f012b7dd07fbdda80eaac7f0c4fad2728dbbfcb2e91010b076c3b86acae345a651a3d8bb8b0ae6eea3880f562d00ee533" },
                { "nn-NO", "6c8b0f1e8df25c1ee9093ae1431191c1462aa14aee9263d9892dd1ce8f2feeef4fb09b483c14b42934d3d4b2b2774c2272c838bfcabab6a7ec1888aa1277d2b8" },
                { "oc", "fe0882347039417b6da190bec1c891c11bf5901131354e4199ae3ee294a1e3a886447451458ed8a541f3741107822e6638b2ef2f2531229146f7b80db566b8e7" },
                { "pa-IN", "0fde26721d5e0025125efd69205d1708b487efdd24c1c2c90568d03425dc7e6504084c214adbff0ce58d37fe4d4f7dbd91c5226194b8fa699db6326d999c66f4" },
                { "pl", "8bf06c2b039b11110174489d3c670f143301b61316f3743a8a091c48a0f5e6c722215bf7d51c86df59c1cc7ac41ca02f483070d9ff3ced5f9aa5b8883b59236d" },
                { "pt-BR", "7b1a39fae4a4ad3fbc02c18e6c5b1ce18f6ca7c694e7241a72329ac32b5240d008c346f61cdf870571bd239054fb73197fc424690325d31d52cb436def5b5cd7" },
                { "pt-PT", "0839404881aaa8f2f43237da556e2c77b3c86b1c65e475ebceaac659093ac4e4ff70073e9a3ec670add38b0232e59eb696f258b1edeb412a5a3572d741df6cda" },
                { "rm", "902411d73feb8fa7d1475b8d30f4cd1dfbd732a48cdfa78141c35642fb253a1b7028ba2ceb52bdb47ba28081f1568d9afd4dec8ba3b1eef68044f689aac58ccf" },
                { "ro", "8fa5ff7d316a880512555b5e48945a900980330ab3b995c60c6b046f62e4fce1bec9ad354811b0456a50c158d7fcb58eb46240ba489974f85ba86d98d8907c2d" },
                { "ru", "333fc5993eb0e03f38bcc120c8e6af13e043382deb757e4c6e24ba8a33516d2d15d17f4a0527aeb5c3565aad7e4960309f6496773191c8947f7a474a488b96a6" },
                { "sc", "91adea964a603b09894330c6b786f5ee8e844107b4ceea3a2917836bcb5f1f6cbce9b13d7cc407af97c05c004c2ba811dc553fec98ca689427080de45d71d97c" },
                { "sco", "a866ebeb189dc24f5a2a52695ad0227472b694f0a87d007c8e0bb55fb4adb5e9932877a47c3b1a5024a767ab57b9ed8c1f3b85fc5314e564c69cc1a2a3d747db" },
                { "si", "c48e251dc33bc2676d341ce157ce92019620104409775473066d551fc285f9a7ed9ffb747f3e5395d32332910e9bfdd259b17307f4af44510c50c355fad3a1b0" },
                { "sk", "6363c864ce113be250c9d9d0c2da5acfb9937dce148083f3dad6bde293d043fa57d238a6722d3e9b9796587f0205f83da699eefbd3107aaf7ad45a2233afed85" },
                { "sl", "26a894d77a0d7cbed43e0044472538b5e49653c4ea44c802f139ec881fe2c18f55c15681f144f466ea8baaabf083a2d78ca80f784a807c45db2cb35a08668578" },
                { "son", "323c0d2e334d43f037d8ff479d39b274a2f7758b655ef1f3f2e46f22a376678d2b61c2fb48362b991b20c57f8bd72d181d63f9dec97ab3b2cebd2ede7ff103e8" },
                { "sq", "13913a30d5f92df3928e26ce091003e5a2478ce829c512956181a5920c577d91b7a4d430f3e848e2cf1dd5107bd96ceea8edd6bde69bbb4d7487360e12618db9" },
                { "sr", "c9c08e2a9b790471a4891ff6385159df4d0ae105791111148ed57c774ce80c6b0ab12920aab607f41df7793b3b751ad5aed11e716419c1bf612699ef021ed3c7" },
                { "sv-SE", "1408d11083713b85344e32dd14ec7c0190f6c0825cca1ecbf4b5b845dc9ee8e42755404b75852afc06f1e9d57ed52f3656b67e7d5f58da03cf897fc4547f1f87" },
                { "szl", "e6309f505ed2b19a583a3cf675876a31ef25576bfaddd89395ed7aa9e4da47db53adc1356b728d05b315513aab59e446c6b15ee41f6bf38e3b276b9c74ecd1d2" },
                { "ta", "1e9a5088d3af4d54249821712868b88db309febc53495c17ee445af744aa2c8a641695f0b9516a10b1853a5385f484622dba550d2595587506c57c6ba488349b" },
                { "te", "87f5c70610118ff37a2e9c72b9188a7e5847058097d44e6dc2a6bd9d35725fe2bde61d950e5709b8987623d3edbc4ad7d657dc87597c245b26f928c84f782c61" },
                { "tg", "b7455d99888a960c10d334bf913992a683d51bca1a7da3c31ba78b517a08ec0dc4d723ae4feed634d3bafdc5922c23522bd597be326e3eae5b3811d0b3e366e3" },
                { "th", "09677ea73a9f740e365ef4b4d2fa716cde0fdae805809264209b251d90cf0a2340f71dceb9b9918f0fafd913c682af8b6e768fb28ba437aabf219d47f0d61095" },
                { "tl", "3b61c8af363e01d4f84e0cc4cb12e4ee74a41b23d03543d701ff723428467a993e381069cea88702eac10932b7e32fd730b73e4f3867673bb94558cc6ec3ae39" },
                { "tr", "419102650ea48b312effbb8f947183c72c10865b2adbb43143d2d0217916f4e5bd8ce328ad076bbb3bb9cbaadf6a723b40f88d141dd7f292cd349cec501112a0" },
                { "trs", "cc80c2ad98067c8ed07e6bec42f811c29baca37c02eb7a635380a7e4b788c04dddaa26f763ef2d990cb55865da5eb920cc79d8be01e3eea3e8b7d257188b457b" },
                { "uk", "5f5e34d123bd910d58efc857def61a4a7d3a0d7c84361c8a570adb824cea7503cbee0015251ec9a90c46ed934dec3dba83761633364e6db6c9b6368a6e076bcd" },
                { "ur", "8c6e916352bbf9d634169e24f00aa67ce163ed27201050af43e9293bffd93b5c81ac4828040b0f470db4a98c3e74ec56ed39d87d3c2aa4cbd97bd894846991bf" },
                { "uz", "2a9abc3806b78f081b2eec0b998c012c654cd6294f38f7abee53283f758b48d012dca450ecad13201b3fc3d0ea5ddd5f4d867f38a6b7ec522346b75ef413375f" },
                { "vi", "d0b35297581bc01d43432f15aa6c7eb39bb1b70543c0b649894875059e17894fbff5fbe7554d8f3e5a75f86e82dcd1d797baa73447d6f2df86fd62b4164a79ed" },
                { "xh", "83cc754434fe77f8b8900bd1f73792e0af976da60e8469b31ec5efe505f884baabf3ff7eb51530ca87559a949c353773ae43e28b336c8d1e6548708ef761373f" },
                { "zh-CN", "3f62a93ac79feee24ba04da6d14dd26ada238ae5c85506267943e5ca10b9f4aa2ce7041b8ad52f9a507df39d2caac731fd72481a301d542e3d18e699f8a2fa5d" },
                { "zh-TW", "f70c1db8cb406e1b84689140ba2e6517fd4005c6105e62ced6b983c5df3a97871fb97927010ec37657515e2de04c70855ed4ad4ddffbc69d9cd155f91421f1e6" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "c81f85137f21a8d07272c417b7b3cf2ab53fd0d3551b7d4ecb0f15d6337030d8204b64ce58433ae9fd81f81a939adf8c7f199a68f5f50af83633e70d836efb2c" },
                { "af", "616c279e19ba2a6a695be71d2b19240f338bb8ee4f7f7ed3fd07d0e7e82bc356cd9d5425d5600fa68e1500e44812b4103e92855b95f4a18212e6a6e72e7f7891" },
                { "an", "eeece48741b4085281620fcc9575ab144c6bbefe56ec574954fd85f0c9a99640f02e91d980d060a365a0c0daf92d52583238b35e7a8cd96b297ef11bb5cbb988" },
                { "ar", "9156807f5163071b2085a771fee711bbeb0f90c3d9cc1431639727404c13b812393bdfa8c184c3cadcd54eb6b7efce4ff8a5a24fe094bb39b6f119f84eea246b" },
                { "ast", "0d6485dae95f3c1dd551c55120364d1ea43cf4b81efdb49c58ec99b2ea2c7fcd7d479208843172dedad3c3039f5d6a846f0f0426a480ef0ba5f6599495cd785a" },
                { "az", "6cf464f34df31b48da7ea98b35c41a4db2f3a4497f880d17f7940d97cd69873802d59c83b824b96738b69b0094538499083bba0fb420fd7d0ee06eade560b9f3" },
                { "be", "f3531c444ee7c38b9441e69afcb48f9195fa83da127e8632e4cc83d138dc7539a5b7168456bafe938fb37762e6335ac07c736c5f4f7e9ab2ebe02af09914db66" },
                { "bg", "ebc2840f2e01a7314c37e8f0eed41b374e561866efee964dd98ba5cba7fe5b5f310367ba24c142afdfcfdfa5b762dbabd62a79877889e8a927bb36dac8436282" },
                { "bn", "d4eea238fa01dd2c3b360d23239c8fa42c6493bb791ef639ff4abc67013cbe8ca7c6d38b07937cc55372bda20252c1d73fc4c54c65dc5dafc66167cf505a8456" },
                { "br", "1167e4498547555cc85217c0a03c480a327dc397f8748bb265c660f80f5c51e7bb1f58243d9f965baa1244cf7b52e598c58ddd0e13afb0c09bcca132258854c7" },
                { "bs", "90e49486f024009d864f6962a8f57b4d71f06e8ec1fc5da936fc93caf1914b73bc3885cb07e0819828a70aa1a0a237f02f307c9dd8f5c07d0e5759856f89aaa2" },
                { "ca", "24861b85d15bcc2542982777a6cacfadec640c40f3c2402468aff3d6438226773eba26fc01b8eb5af94871e221653e7f4d8e285ea4770abf89fd8e4e10f4ac29" },
                { "cak", "2a573a5a279a1b2d4ce36d3b8d969df2e8bbc3d9238f8dcb92b248867aed13c92294a22c11f7ec284a28bc3b460ee1c8a7af037d386edca2788a991a6de61068" },
                { "cs", "795e154fb5ab166785c6e2e0aaf55677d98866a7a5faad8b3d82e23afa49b96b3370a25512ad17760894d98d68828afd1734541f9d66f892ee7afd3e03c6a96d" },
                { "cy", "e7ae9e7fda4806d5b423a6b02ef5ebb717b0b94cbf144e98d5e08b8955f11181412aa45c127ad39347bf4a6b4131a0ad6582b8734fe865a3d807fafcf1217c5b" },
                { "da", "dde4600f5d57a6c8bfe663925b01c68096265b85a867511fc19011ef8826a594e7e745fce21cf17ef8822557086789e136739f26ed210fce5dd7290ab94f27fc" },
                { "de", "8167efcf7aa73a0af1475f4377138589462b112ac54f951c7c366ef0ab3a5d2809a1658f61389e9eeb16d33b34af97f020aef1c9594b3c96fb3881ceb6342c64" },
                { "dsb", "7fb21caf3eb3565e615bd1f94420a20e015acd43b1089a422cf863202da18f356ab61db936e964b5dc91d18698359cf8e6d4df04873435c53199fa89ddf08db0" },
                { "el", "7226aebc3b30d85328716bb2f88b8061f92b8bd7534e27da613f8201b18b3956ddb29e2d5028892a7b2d6d5445c1b7fa433bb0c841ef803ec5d9212a0f4bd623" },
                { "en-CA", "ff3d22d1702843bbbb9a948c9cc4b55856a7cd4e2e9c430d3483e6738eefaa83f96d3276801aaf3609e2082d8cfc87d35e90b421e7bcd273698d6b1e8b40fe4e" },
                { "en-GB", "957e31779eca767d6ca72955737cfb14004015703e0a08eeacaa8ec5f3a4576ffabe5cf3057df1855c17d4af2e3601bfa90011158387527c56113fbbdd3bbb53" },
                { "en-US", "af065a5cdf179e5b3fc0848a1e747c3df8027d8f7a48b16a48904adadf7333f68bd7df584795770fabef85359360f22327690701830eedf89f0a4c6e3d5bdb84" },
                { "eo", "b7eb72145a2e5f05ecd5a04ffdd3bf9a059d8271be17832c62131cfee57a006a3241b1ead157ab7aabbb25a99bf7c32adf01d8974075365e8cdb71bed6ff6fba" },
                { "es-AR", "9c992348a5c2c697ae8faeac018606139d3615e092fe3e0a241211f84a1a34c4c6f2fe7eba275eff1d5863113d1a8cf7a89147481024e0ed83113336ba04c1ca" },
                { "es-CL", "8047964d3b8779a2623ab1ff685ff35af211ab85da56772cdf49cc4989092b4feee0aba736fccb60db99e1a5d6d589a98199fc2c5a6d33d9d18086f14ec753de" },
                { "es-ES", "6aa24e9356fdac5d1427be816269188e47ed985f3f67da4adcdc6bcf467e2427f59cd54ab3b75e4200fcd25a2c28257344486fb2298089cbc7c2b6a83d8076c0" },
                { "es-MX", "9cf97cfc8b146acd01a5b9f5c988e9798132fcb48e24beca9364169eb45f7a7fff33cf09f199f12f6a9de089c0aaebed382b9ee323eac979b30819efd465a751" },
                { "et", "10223f40a2303b0b9d402ee51f85027fc3f0cc7c94268e7719f84ae8ff5de3707cc76b0f9a8cfd9c9892d006ed0dd1938e6ee09b1ff1a9eb88854f45bf8bfd30" },
                { "eu", "ff0b069f1c2656803ca2032001f8e17375b48e3ff7ebf58ef7565517d296b664a4365ccae37894819c4f628fa414bebdfdb955ffcbf830c6218794f8fd72a674" },
                { "fa", "09d3918ba7e4de15be7ef4a3a72efe4ef630be58d8f14f73d13b635c0f39ac46acee7d4897ef49c649a81aae3ab7d3b6b0586887acb085a57ee879425be0bbb2" },
                { "ff", "6dd2c045d52ea16b18e659dc3e5ce2aa5329368ac8c29221f906ece3b353d589eec85f3e7beb7459e053600a75188e6e5abf0dbc0d637d1820096fec56fa0658" },
                { "fi", "7e33a7106d8d198090dd4d117243c2dd4144a78d355c1158cdb192a8cb174d32ba25f9b2fb570762a7af82f46fb13a946ca7a35d2f8bbafea4c34941c9e4789f" },
                { "fr", "f17e29467ee6588f791772c2b7eebe759f312bd62dd76367cc286399048b2aef9537f317984948753b236b10bd813d5a1378b11c1c19cf3454a28f6381a43c8e" },
                { "fur", "ee1d3e813acf754e361265b2dc3c4f807594d7f086ce5772e4847480271a2e1771b869cc9366839874bf981b47a7f350f6e8d6d4fbf947803dd2ca20b34e7576" },
                { "fy-NL", "df30ce2c0594f2486cf6f0b11b3226aa81253177675830670408794b9b9ac1f1d0fb1b8b8a5f3ff464a362cef036b71ad8f237a5487c0b617d30976e5b3a82d5" },
                { "ga-IE", "8e430d9f5e49cec18b3d021bafec5589a13a97bdc8cd5b5c5f4caed706820e3cc17a5492773876ee897e75f8790da36aca7e275a59ce68f75ac1fbb09bb1c4f3" },
                { "gd", "77cbc35a4ff367ca1b18951951c08e8ec2d9a826ef1fead3b0092d82ab5d0ba10b481d537870c10b6ac48038fb4e20176626d8576f865d501fa3f59104341f52" },
                { "gl", "2c58a15e59adafa8fa5061377e6af7701689cb28759e3cc06b4124ba526fec6c239fc925ec340b2fb6b7bdc05760ddb4555a5c7fb4ddee8d8c18b56dc2eb15a4" },
                { "gn", "1122a442740f2e808539536bc4c1c6180eac3bfa9f3cf2d7d9f625a453acef5d39bf8c6b84d58a5b36e82c16f24e0b022efc726a093b2d7e980e80b4af680bf1" },
                { "gu-IN", "d14c908826b755b88fce81df4fa59e6c2f9bf88d472a687410f66d4ff8f96a5f5af366aa083bc7f73199c76226ceb5fa826b0a30b15ca890139884b237d62584" },
                { "he", "67b7523e9badd60492b7251ca10947e8e1aadd601712398f2261a937a3f6e09d7881c2f314ca7708afbf93fd75c61b47c56cc918cf40b714cac565dd4d98818c" },
                { "hi-IN", "801bd971116d205816552ce6df9f13eb43b7edbbdf3e3fa729233ecab301c3c0316f53acd9f6b0e44ea6874c69558e7b574c3cd84150a68702a5687213abe860" },
                { "hr", "6646e690c30dffad6940d5082477a27d410e1673785e6f423eac0b0c180a8b73b2a4a3913a7c3fb273548ba0e29bc6d1fa5c3681bdf8940c339e13a5c997e46c" },
                { "hsb", "d7495a5f703d5f8e6897c8bfc96052328df24cba7318e252daeb2d679b3133c33d87bf1c7bc187abcae9d4fde583b233d51f40431a2f3284dca40df1e6861321" },
                { "hu", "6cd2bb25165c5e893126b41eb3f291ebb90f04e9727e0d34df6bc0ca2e542554459d90c9a2fad4879d69d305995bdca97cb0db80ae8c0b82dd9e9f869657cfe9" },
                { "hy-AM", "8f4002fc2c40eff677702e4472dde298bab59f05f2869af2ce5ef2064bf4db78fad91071fc03c343e1bc82650d87ca2bc61613b7c1de10c65a8f172c1fa6b2ff" },
                { "ia", "9b8c365210748da6d3ed8a3400ffa21fbd4a10f30ba13a548d8990095de81ca0b8cdc3e686571b8085f4ac96c0d9428d63b44cfd52dbf932d981dc44b6fe1995" },
                { "id", "10ac3394c327fc0cfe3c94bd137bd54d417ceb1afb055bd0681e38a1273bd42fd99592e05f8b80b0cf422aedbc79e8c80b6534d7721fca97f30112a6e4ab4e73" },
                { "is", "9404f67f28f07aa6614d3d724dcf5dd1196445e1557fe5064be0778a71214c3be85a4a0740af590c5d4578a99d2b753e18d49b681f6396d7961cd5507e194c87" },
                { "it", "ff5b7e6f85c72d3feffea1682a15fcdce6273aafca9d93030911a2c88393e4aa31bb4cac32ef758b0da3bd08d35d4945797649f48f3ce878d5a83b69f0260d0a" },
                { "ja", "d66b644c1196fef72e2bb8714e5ca931578e33f0f96602a255affbeeba5f9b5a5965e2ce4fbfecf961937fe690dda553121ee0fafb066ad0316ded6f4ae132cf" },
                { "ka", "9c17183ead79bed5f2c2f0b2f401f630909197cb2568f0c5fa60b4c1c279375226a94b1af121f3e94fbbd5d8f739693484b1947f4d5a0242927eff27e3fbd733" },
                { "kab", "dc2576e77edd07be5482123dfe51d2652a77eb028722444a9b10ae0b01021940ed1d3ce8397a7361ff53e1f20d9ea945dd13beb24ec9b460c4846bf1afcd59b5" },
                { "kk", "e747fcd2f420e56f9b4f0c1efba3b2d321ee99307a3205a26f5bcb0270ba221ce93dd45787d217ed7eee3b3e244ce51501237684f279c9f367ece22a8f0e661f" },
                { "km", "a87cb2f2d08cd0bb6c9f50ad44b4e33ef1dfc7b883e88e5adb82364d85950a118830201027a4f50afa3bfe00a817dcecbddc9a1292dca3a54c7f84003c50e31a" },
                { "kn", "6b8fb918c8c18637470df328a6b9935d92c540260e28b67ae3d338b771b31a9cb3bf0d1637c85da8b541278745f25d9908d38d0493bbb2698c8d2986e9d7fb19" },
                { "ko", "90b16522ddc0a9584df38043d0c7cbbf84a4bef71714b900317763a1a9762afc12fcc99b4180a342d72c9f208395bc7d592c277516da281d33eb7d87b0a93cfb" },
                { "lij", "a1971f23b14eb19f520ccff47a11c0ee2eaab1727af4caf600724c054e330b921fae5b1c0e295a6ee2868b1a37fa726481b5d44699197078bf179908b6e084f6" },
                { "lt", "848ad3040176b8f629864c8f2d7a249471606eddf3a6930fb3dd1662121c3cf70e7de1aba1ab3bc783af64fc162aae9b40e4531222efc851b1923673b8c80432" },
                { "lv", "d3ba44faa2c60824310b65ca570794e0a3bc1ba6a8073cebc7891b6710f1f4d20c8dbaecb3b47da9bb7d476686341bf321c3563be22b5c83dbe13bcc281ac620" },
                { "mk", "b9cc1470286d42a0076f72c8ea024a3fba064fb2815a79a1903b29bc0e19acbb655cad6b61e4f5a09d6462fba297c8296ec34714983a81d13440b78bfeb7a005" },
                { "mr", "bc1e31f7d094dd37005c40b9431ab71616bed93615177bfc3fae9aea283cb61ced6306e06ce7a446ebe3f19e4421671bd25ecf72d0b48c66accb82b940c20bb4" },
                { "ms", "c690d41a78585e953d6f7787744b87e2c950ae44a32b4f294cfcb10dbe59247e4dcb250c88bffde35600bc36103804304e3a47143f38b5225417b3ae52da43dc" },
                { "my", "6ea0acdef539cd0c5ff0dc879b5367f225ed92565bd21d51569d7958635366f79174901080efea3dc6006f53a2671cb3004f510ea784fc89692618b9bb40179b" },
                { "nb-NO", "99169b8a93b5b432d1e365532ce08204576967c2b65ac6d015e56049bac250707d794bb3f762fa2777454e7a49ef93d3adc36e823a7c36f6e20d2c8409df2ea4" },
                { "ne-NP", "ce5c43bfe1c9b722a786b0018ae068512e56881d573843be890102fbe108fde0032382a539cbcc72214474f54285857432848c7ad62fd1997512a55a928aff5e" },
                { "nl", "599a1b5690def2d9efa773d90bad8075a07cd82a0aeac67cd2924a2e093fb95557e65c48b7610986bb6ac5d95286f630927a9ef94701daf81775d6bd7ff81a47" },
                { "nn-NO", "66af32c13b048bf946ee9d17193e37db54de780c3fb0b672ee720b7df6dd9f3ae36a5eba5233403adb0f4038a3ddcb97b680ccda205d735b445c9adfc0ea71d6" },
                { "oc", "6fb39d4c982793339fa6bbed7fcade26d9ce4f8dec4114b8c7a748c2c6ea6b187086162e6424ee57db91026615057678c94403dc935f06ad5636e7513c5b9437" },
                { "pa-IN", "cc8d0702e60cb88f5c43910a091c1e0c3d5e6f4c19550a2ece526737b976203b8118e65244bd99b61a38508508de33452b3a2aff3e03c2616b12ba9f69081999" },
                { "pl", "b0dd98f8fe40e830666177c8b491cce05f2466e192f2918aa48625e9c305332cd3c248b7743e68ba6f6978f6b6e9e958ae05cd1e1dbf5ca2affa726ce85bdbc5" },
                { "pt-BR", "8837ee95eeaa779be0885aa31904089ea4ceb49e1d0abd7d7777d8c0d74c12ee45b1d7fd6225170fc84dc5a14f7c2bcc2eff60370b1d05f227eda90a5349d785" },
                { "pt-PT", "9efcfd7d98fcb8465169feab88f59099217058fee9b3042d3cac6a7d6f9193d6cb47477fa744b40f4ad81d1c54f85ed1b923d2855285aa73f76e8ee77054cdc2" },
                { "rm", "a8a10368bc2bbd3605d4c52b3ee11f4f2c6cb581a4b361c97693483e984abb23f3bc5ea2f0e85e5c6a184f4efff12ee85163d48a6a01cb992e207d971d83c6ee" },
                { "ro", "6cd2e3e58afd60ba4bff128386216f9a7c9bc945d958f8ab0fe7ab5fa71c81d528a979de018c683c300690558010ba19eba9137512a136c800906e1c894f52c6" },
                { "ru", "97f408d809b5c2a63efc1e528514690698157a89801a07dc687a6f657f5f61ed7b1654380e640b079dcbd6564ad63ba0ffb7d3080565396e00863bcfebc9f9f0" },
                { "sc", "197a0fc09f5357d6a55460cbe462f12b3864a4b0fad1dcd8dfe134839fae72232a708ca6f0aec3cd03a647a396e0cbe48b7be209e734e80b00c862a57dcbcbcb" },
                { "sco", "2b0741a93571ecf369be857862358d580799af40a5a6f729b1e849a478e3d8f837d8b073949267d374546541d4bbd6387ad1c25c12742391179ddf6d3f8b70bc" },
                { "si", "5c964926faea17b8defdeb3d5c452a243e850a4ba3a9e5365621d034cb5057fe2fdd2d5d24047488a9d37e4faacd2161bc91a14cfe3eff44e9eea3825c2929ef" },
                { "sk", "eb7f52853608c28e752980346f9f5d8f3301378e4744c325d650abeeec2e87bb58904e3f62889f37bad486120de00748a78cc359a87d1868b9fc357cc8d51c09" },
                { "sl", "c678cfadd7738de0a8b5afa62ddd530d64854e6d1e91b45fe6b6dc42e2ec37c7e831ea64aaf99c82408c5421753e52d2586138c6ee7aeac03ffb3b8fc09f2c62" },
                { "son", "a6ecc5659b9f494d6ca01bd0c21685b0d2d09a2a7a806d1e0d9ac1fded95a1da31d190d1dda5c10a01f6426c5e6fa5a3d9d4e5a4f3ccc6b8159c49090b9d4f07" },
                { "sq", "c65019b2676a8875e9e50e54dacb81b9cc6f8c2fa3803af547355ce95bd67de94790aa053ecd7b888ff21ef341a621ddbe70ef57694aded22115e7ed09dc76d3" },
                { "sr", "1e93490de1dbc33ae56d4e9cc2aa519037b4106b6c2e0f2c7d82d9a34ceee39fcfa2232e27b5802c661874b1c81bc5b3681d44266e9176ce7c5e88c2cb4d587e" },
                { "sv-SE", "4bd662adb6131950eecce1e5853f47a476f0c9de7a9b7d24a1f97abc332860f7a4115b724ebfb05e1edbad81e63ac4010a964b1ee3035d3445a1469a5383c557" },
                { "szl", "72e57c20d669512ba592929a57bde90c142d1860b923f860fb87cd969ddad90500e5e10ec81142539a693250069d26179e2519749907bc6c1e97b34798cd6e15" },
                { "ta", "61b19d35c83492b1dd20db4ddb7331ec49d4face7ec12c41fe5f4b66888dfccb33a14c60b0101863eb3c276bac3d6e0df1f2be37565aa1423f5371622158f49c" },
                { "te", "43f3a736239034554e87d354611385f26a120cdc2569ea60c93f59889a8045e8f0013c8d62bef38790fd79749dacfb97350f0b8f11507a1842087d4b9a2842d2" },
                { "tg", "c26350081281894c19e0b74c51072182eba63dbeb920b56a4df24f095630f0051ebae46d112c83f1d3a7bc13c5ba927458904e27549df465d4eb530148aed9c3" },
                { "th", "c4b5ac5c4b594bb8fe76abe95c6988807db48d20080b4eccee399f29585169a4af017d0ab7062a9625669a21a7613277faa8b92915b9cadf91a6460b6a98a962" },
                { "tl", "e8d0cb3187b85040f4c48bc83980762a96d2195ad368f0994d7161fca015db44cf5e2e9d2a2dc8ec649c84a23b7424698603d8b23f2895da6b804c605d35a65c" },
                { "tr", "0a39ce45a07f504fe7ed5ec858d59eace5300f92bf2af301d930e6ea629e3e9f15cb409e7b8c9d1207843be19bee60ececf5389ad268dbb13b5f5d78f71cf7f1" },
                { "trs", "f0191ffcf36b149ae5902b5179236d2f8c2e28439c6d57369e97cbd77a69c386fe5638df2bcb09634ac4b886c1049f387e71e76c34dde8d16ad2fb12bfe83e74" },
                { "uk", "241c070fb2413145946b10e124db339fcfea82c3e1209b169e346bb907a4be0248b5873a0d43efaee08789e96e76dbf17428580e1d1a7686cc07e87e9cc9ac29" },
                { "ur", "d4eabd23401151a82a7e883de11edf05556f3d51a25347cfaf3631a5c716ebcd0da96bb887634d8bc0d8cfa69b020608f7359069ecd0b60b960d2b08dc444562" },
                { "uz", "cd0f6e1be3722218a9e29f8bdff5c8c9d0af3bb12e352359fcae5c4245ea82920de130b0b6ebc866bfff3dcea2f80784c3eb20e360f4a65e9cc8077988451b6c" },
                { "vi", "78af58657e96f90a242f37e7838b849e7fe131b44012ca6d93d32df67ba66a9c9d67f190b2d0293ff1e13cd2c5395ca5427256d1feba9c08efa31f53e0a6b212" },
                { "xh", "219798a1b49baf405cac1e47d440526fb0dba1dd3d95718d581a2313f145d48f88fe64ec9102f38503458ba80c87be1c95010fee6f5e90e09244b3983f81d6b3" },
                { "zh-CN", "4025dfb027938ee04e7739875b9ecb925dc5ab18a95394b9b5816dc408a9c9e76afa90bcdae405d469e1bd77faf69a92b0ce2d8eccbdf1fc01650b3d2ed7cbf1" },
                { "zh-TW", "009781a38a188fdba3bf9385b73d55935947487bfcbc26504d31fc775e0953ab889557deec08468e5a43e0de5d9568d8b5ac2c8460113e7d8696932cc9136abe" }
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
            const string knownVersion = "115.10.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
