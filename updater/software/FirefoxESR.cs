/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "140.5.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "014abbbd370176d8cfbb866ac76aae82b40c5f961640154a498145c02adab809642c09f5839d54b788435278af03e47a5f5e69eab94510ae0f8917751dc789b1" },
                { "af", "314667be569b3686ec964ddce7344c280209c353662bf5bb16f161c1a2213bc68f02bdd6f155f972a4c73e724568ce3a24049f414ab23a1a0fef839d0202c0e8" },
                { "an", "9323bf664c2999745878e940fb681608ee6ca0c79cce8c7aff44fc0f16f9d4b3e5966c8a645ab8fc22051bf48adf2da7344e154234fbb00d50975af79372d785" },
                { "ar", "617660c29f6ab1cb9673bfe296745ad787fa8bbddca69783155d107cef54cef55149724f0776d17795a8ecc4184726d89a0c865cfe330b02d085718d2fbb7c97" },
                { "ast", "346a7a0fc644c66fe0ee2e6d30d7b0d7b50825a0ee9c8fe9055c79902f4a49ea0321773c75a1734ffcc41dc56c8fc982db6931e9a42e7cdeca2ba2f90301c849" },
                { "az", "c81249420e13f738807f36b41727a22b1fc60926696ddf3b787e2d6b7e8dc83e1a17240310abdd11a2fb5efe6e9cc79f33cf5b3830a9afbbcf2d8d1cf3066e57" },
                { "be", "a172cbb6f6846640563732eb1fe49b1eeb0925efa5d14e18c00613f58942c91e5f16fea2d09cd770eeca9b004e0c78c648979c2ecbd2f7bec0dca216e33fdb0d" },
                { "bg", "2983bc9b3952d5eebd3dfb32b2fa442724911e10b741818c6fc7925173f2e6de38464849d3938185c29eef3f69540239d30a3207b476dd85bc8c7ccb2235c620" },
                { "bn", "a91af62377aebacdfd7132d25bdc8c34acb6c31dc9749e01d43a323bb82900fc6b7f8881dc55198dd668e47afa065450cdf583029b8976137808c21194cd7112" },
                { "br", "245bd3a171a83b39cb31d9ab71243c50b3247fab2be4c21c9fbaa3f9d769ee579150ad8fca03be6213fd5794b7f0952a878d7f2f90c6e81ef3e07c3e25441d1e" },
                { "bs", "e36523e437b6e63da350387be28de910e0a2ce6d638381a57d4216d0d658c738f7d82660dd9766fcd15cd967681d1ed820e5a9d9b584a6c1387ec5b7db4ee20f" },
                { "ca", "60971ff78bb5f2b779632daae77ba3e581df9a1d36a3a7c692256646c343f6f7d063d0bb9107022f5c42b739a80158505cac0e4c51d8c93089d0721752ebaef1" },
                { "cak", "85b2a33b30005c3d956a5d944d15ad47bf5ba6b5cb5ce2d6cfccf841aa443c9120156c348066b2bc38b4465752aa5ef31ae7f8e9b2bd8ca3d32fce88bab60dd4" },
                { "cs", "049a91eadbb7f8cf51599887c21dc617d3117487f2a4263f693a02327f1f9ff2739178d46d24d0facf9ea7077fd776fa80c2cd1330dad84fee2ccc379b92dc9b" },
                { "cy", "3993b7856e5c5529da2b841ac3ec7271b7247957f79b91abb0b0c8536518fac71cf3cef663cdc395292e1047dafde7dbf9f4c3d01f583fa89b824dbf172f6c5a" },
                { "da", "92c5c1e1adcb3b183d8737b7a4a285b4b3501e80f0a162104fc3f589ad45247d73429b9c8522fa7e5730af7372c3b937663d10ec35e65a3dac2b2ab2ceeb5452" },
                { "de", "c5767d0c9f317a74d507019f2696dd3beb45912dd86463bee757176f0fcdf712d2fc59d08c3b6097bf4922ccfda3b227f566adbc31c4a9f168f8f2ca98f81e4f" },
                { "dsb", "2be05a3b826ea4409afc78c1e9c7ad497f7578ef755baa6cb45d3808b52cdf00b25f74719730032940097989ef16f46524ff9044dd5570f77668330fb2505cf5" },
                { "el", "b8a6e3d5ad8afe382cfc40f4e5f9e143c5c3994713d4b3c98440d2b13ef38f3362a9e9b9d6b89750eaece24b79a1032a8d855be9cc2aeda3fc47dce8e3b28b1c" },
                { "en-CA", "2ef1f48cc5fac1b2b95d843dd039d9c2ffe8d4676adcc9815d5e0fc3cbe0464ff9d79812546638c99297b40c57a049f02620390091e072842e1cb5d054b81647" },
                { "en-GB", "0b946c800d7d5b0dc50644f4feea9d41b0b9b6f038b0052cb02ff3f50dc2ff3b3022a56887528dbc18feae3f45f373d7186d5356f79ee3c878bc708c46b624f4" },
                { "en-US", "7dd62a5fdbf552c040d8467bffd6ff49ecbb047173b84739c19483531badb804684a9150e30751f1f4efdcbf58d965282c2512de92d9175c2433550632c94b89" },
                { "eo", "aace65317e79d4a6820aff59d0b5cd664e82cbf7e7946ad03e1d87f0e011141dc12fe6bfbd8b996180a26a4edafe3c05155b0f37958d52d41c88310d4a5f73f8" },
                { "es-AR", "267f05d11a403c393fae8ba7713784c878ca175c1bc398e07bee1c946679c78e0bc217fd97518b16698c7873d57d1edf0ee99a595fbf791a29422328967ccb95" },
                { "es-CL", "37d4399be8288624af291aee3bb5098002de355c6794d4467859f38566e935ab9bc1455d233c3a876b221c366a0235e6aafa85baef5de9e674bad0788934d543" },
                { "es-ES", "b0632fab1adb332b3c9ec48b54b0378b3245873d8edad4dd8b9b96f016f7cc183892119c3de21f50ecad4656ca6142afe0fba52e1c3fae2afa958855570ec74f" },
                { "es-MX", "8001dac4aa6250564589c843f9b815b93416260d69aaef2e61799840888f5729839f24c2fc40dcbe41b4e88ca1702d63c143eaddea3d94ffe345741be72f020f" },
                { "et", "5a24eb8074edd7af2c9dc31b917f8f028de0a321bbd9d73218df7d54c90a78f41530e7ed2a82f554b32882a0653e84228df181cd7d98cf3449be133e0b210920" },
                { "eu", "bd37d66ba0f7dc64909d54cc4e059cd1022670f127bf2869f97f64e0e532587d4cfeef8f484d5dbef04c0477eb1122f42161d28c178049f1335f559cbc2fab4f" },
                { "fa", "dcbd1439501cd4b5a6efd501f82958c0b09940cdd1fb2d2d5ac93b91fe36b47ec91582e0d62040c785eb8009520553db373ba65da6c14725bad07c7d2835a71c" },
                { "ff", "83426f72fb48da8eb6fa7f3700a3fb8cc8a7538bb6ef1637de4f45171ddb53f7f5ecf03af3e3f586cc8c1c55acefe99828dc792e42dbc66ebb3c3c9d11000c18" },
                { "fi", "2095830c8eda153c76d0764a5c6f4de15099f76951c0a3bfabba51e186d92882f9fae599dd828ec596919d29b7d7747c65869c3acf7cc971a1a4f1be58828d00" },
                { "fr", "369bda776fcce663cd6dce973ffaf2611fae13338a5e376eb5cc02a01779a963e97d4f69ea0d1468a1e14016ed25a2a540339182c4caa6d7837902986b1851c7" },
                { "fur", "9eb30187f85ea5fb740f7e4e0c9139a67b86666445722e9b0410911008f072fb12ab582865ba1650e1e35f312dc716218183bb1957180a559fd3c4c1ced1fcb3" },
                { "fy-NL", "b16bfbe247f31420007e884f214198cd2aba5b3f84b66d2ee4c75034e9ff39f64ddf65f3a261a6394f0bb5ff6899c3481c010fb67107843a7982f0c4fff8db82" },
                { "ga-IE", "9da5d231e4df5a3f05e5dd4e77b493ac7dd85d70c9715c7b834522445ab26cbceb1b50af91a64a068a10b1e6ab53386b84fdf576766fc2071478661a214ecfad" },
                { "gd", "baa4122c329c86f557a5871a0ca6f3f07378468643b5a3a93a131c017dba1aa7ac387cdeb854af280524b6be6af4e17ae599a33b93ce5f31108634699eb90597" },
                { "gl", "4db9293ae91a3bd8c0d7c50aa8bcfd2082e0c17485c64d716bd903e970572fdf0e646cc502c22cc6e00397aa0f8c3a02b1d96e0c21807d87a2677fdd70bb1831" },
                { "gn", "53be54461411fe59a6a0fe4c43f2fc7a4fc3f290f71efb1822f72ce549260841352a5d1c09a150277863908be6384c3368b3590d739ec3e4860eba191e54a16a" },
                { "gu-IN", "fde4a6fd8359bd8d6c577e749f77b2a84a775aa85cd615ff6aaa202712bb4efbd4a8726987b18dfebf7957bb1bcdfbfa4abab3cfa06af35f4f9be2dacea6e8f5" },
                { "he", "cdf50368d2f4a9fef1899c6c9df738856d9f76ce46e0799d6205e3e5448f6dc428098f053535e67640d699c40f19b3e3db38c830ab19af8fbe646f1af5ee0eeb" },
                { "hi-IN", "ab02e5d41dccb72fc7264453f2670f18454bf8417f047b832bd404eb4fb59d53e79feb1da119fd28aa2ef2564e783c6425561fe0e1c36d7e511eb574f31d68ad" },
                { "hr", "92625caf586cc8045d984e2e3380906d98bbddb48e4b2e476e73d9f16484a05edc5bea28793b5bf1c9a66f121830b052f894d1aecba49502ffd3c0b048f3b526" },
                { "hsb", "3004df27830a268af600bbd5145591ff880bff457f44070f8f0b1220a8a3b20ace6d662823fda1196a937b440e2edd464e603d329e5a80fb0d40541ffdb13f53" },
                { "hu", "ddfac13e0df634a5da1414d7be3d7513cbe5d6e8dcb7a3b3541c3159bbd648f468f17f33121999fa61ab1da55ab92bf1145eeb199a4a2ff1cc54f18ffc6188b5" },
                { "hy-AM", "aa57c2a0e80a744e5e74b6cb6ed2e6bd9073fc5e200d4aa3a644822b08290ec92fccd50ead4ed6fec438760a5b443e354098faa0c8f4b120f735a73d189f57eb" },
                { "ia", "794249e89198c646a3d1e90955cf5c25ccefaefee631fd37114e63818de3efd7a57c2e7a744a1b0e52fca38be648f5ade4f68f1fbd284b11f40bdc7187fde58a" },
                { "id", "bf323ffeed330cb3d7bbaa57da8c48f917eaf613bbd4f7f5a4aeb5db39e77944a5f5ce2b8ae592ad2d03eb717979797f227eeaaf28f94fbf065bcb108ccb98af" },
                { "is", "d83c0efc95df7c126c48b272f8d2804785157e648ca8a9f3f5469feabc5acd9f08e53389090199843c063cf5ccf56cb1d8069784c01070ed0b26087fdcb39f76" },
                { "it", "5699177975a8be4198285599fdf5fc18ea1eb9c78812790435f0ae86eba8b14b0b2f1e79353ad23a6bc7fc21809e313ab39a3b22f0752c26a61613daeb5422c2" },
                { "ja", "860decdee1fa8831e82e4e6e08a95cb9e6dff47846685a65dfee87b0b83bc5c634b340cefc51457d9e2826df688d899ce3d785bf6b112408ae6553aa7e6e6aff" },
                { "ka", "028ecd8a19bc43c362f54179075b0f26b0d3a120c7fb3860d855ba1677b00d104d5a1213dd40c68cf3c632e6ad7893234e8c4b736a1892d20b04543e24cbb523" },
                { "kab", "cda0e22f81e765a3d8fcad3ad3c5864ded0dced62b0eae361d7f8dfec069cb1c10e76e222dc6199263e18f33cebe1c84f352c35e0dbe685f7081a978749759ec" },
                { "kk", "ebc73664d44be59067dfce3098051da37fb912065b7faa49289265aab2f18f0efa5d00cd8f14f9786f1448df3318601f29bf127561a7b296c7d2ea28025d376d" },
                { "km", "a800d68f91e5db598a87ae118ab77371a45e7d4018d022e2b518f1ae56bb7ca89b9161c47d9e52b5d0e5c3c2abe2740d9cc6c22791bea4cbe571afd511bcfcb4" },
                { "kn", "5546528fcc1ae23230c277b8a05de92dc4f7de6755b48863b8364536eb42fbe9b6c1dc7f730879bca1da3bf88ed013a6276238856f6ed677a6b6060032f83fb5" },
                { "ko", "911aaa79294b72fe57aa90bae2e8306e50308ca990f37723123d0aff1645a8a3e3e92663145ab519e1fdca7159af9b0038edc3d553f657e3de5011f90348a9ae" },
                { "lij", "f45a67eab16f1bc6ffc1cc947ff263bee1ff25ab51b9c3bb80e68a9405a83025d0e3957c165498405164cdea247cd225dcf20f0ef6e97d70520ffa6aa7eceecb" },
                { "lt", "c70e717a941842c21cdcc54a6f6da739cb1e06a17dfd744e05fe2967845c908e06b0e6f16ac380f2f7267f743b5d942f27edbdd0b2d0573d73db091046a7e7eb" },
                { "lv", "b34cd870e2fac4126f8a583951d66302376c95f3329529fd4b4610c231fafc5ffea82b1c64791f502e529fc6f688780db40fe2c7b437fcf0671eaeedddd20424" },
                { "mk", "e387cd432d64e2df9db4a764ce7f16e0a8b6759fdf34b188070cbb00ef9026bb149ea4d6845cb5853348543d7d7001310d20172f901b01c4ad4ad9cfb526251a" },
                { "mr", "2cefdadc54c62acc766e9dbd90c190fadf9d11fa12ad5fa46007fa4f53a74ec2fc9c18fd682f7d62b144ab3deacf56dd908c0521c4ddaee392e5d3a1f35713ff" },
                { "ms", "dd61bed70476b95dbd1a2ab6532db65f26e0e928c943b93f5a6639be430ee7fd0debb8aaa697a3037197359255b3450a8641621b1fb5d3dc7faf60963ed44497" },
                { "my", "5c9c60ddaf18f7a03213890407f01d2d3b2824cee704ee0e42436c224aa692a8eee72dd77c22878a25323cecb191f876b7bfeed2e7981725961ef81d4356b0ac" },
                { "nb-NO", "8564447be4e2d41eab63ce1fdc0fc0ee8910b4afddfbd9618917a908be1f1607c083adb74a7e7e2c71f25a2aa2a71810a5c8e23f6088d3ff47a498ff6d2059f5" },
                { "ne-NP", "40d3ff7f0ff826b8a04db9b966f358e343be216f1b30c211e510195c34a1a72db669b5e5b7e5ec450ab535b33a59f1249528bbd098f56c1de1353397d0ec702f" },
                { "nl", "ae480fac1d439ef86f6af5c27b49a50f895a2260abd7c5fcb1bf7c8b9a2e59a6f09bc5c5dcc76d2ac37ba4d5c9339aefa16a2397d3ea8ea176d80567f30d7244" },
                { "nn-NO", "32a5b67ff9addfbdf597db91e2ecdb9e7a233157f4d7a40e0636428fc3e9a4d1074e5069b777a7f2dc4211cd28bad380f3aeca5c4082e472e74e5ecbc5e92d33" },
                { "oc", "4299af01c4e8bbc5343ada6f92e2eedc3aeaf7b6f32170b9134c0a0773a4914db348828bac20752d29de29adfe44daae7110cb32ab491a7e83bd71d8cf8047c4" },
                { "pa-IN", "69ba770bfb65b69a49f862cda1ad35d9349e5b739c1cbbdb0d3548ee4f9b7f398b11c5530c0d645065e8d7e5784801f471b5ee411ab6675f6915c72cfb181107" },
                { "pl", "1384eccbceb6678a2e0bfb800e963f3aea158761292fbaeeb2f83f5f8b63cdf1fff7839a205db09c08e81f6023c98519086a12bf9b8d757e9977a13cfcaa8bc3" },
                { "pt-BR", "0d4673c18d9fa3f18062f7c467c436f90ee746771d1083d56942f7f7a5265aaebdb30225b59bf4547b405deb3c4af4f8cc03224b84631cab0ec1d91571134182" },
                { "pt-PT", "825280bdb289079da9cf085d2c7a01318b59f643c3c0e35e1ca1b41d1402111ea1d6ba9c37121c955866b3396e7dbfec4358ee68e02b2caf2d8bcb2d4c3c1cd3" },
                { "rm", "eee63c51c2942b65c3c826089174060c77fc00abce0d57c5ea27dc5ad4f06da76e7a1ced71292ae0eed814f250bfeea879ea65abdce2ea5f17829f6c8e80fedf" },
                { "ro", "23b552fc50191ee2ddf7f4a58a2abe41079a6b676fc61a185d9ba9f7d1fa7a818ecb11c1bcb74a8bd25da749e642879627e2d8745bbcf8a7b5e8bcd30fac1d84" },
                { "ru", "1cdc08a785bcee215bbf03b855f04f08129fb2e13731b8d83e8a5af98ee4684f5f4f78863e1c0c4673e32f655a5e0b0689d56ebcf43f62024095f0ad5c6f48a7" },
                { "sat", "2105472d3686b9f4e9afa38fb044c44a2d91c15096ca27ac8e9eafac34cafe022ee15b402ba290a894c323e35837d27cef106bbdaa0519a05edcad20ef1cb551" },
                { "sc", "4736dffaec1d0920d342d90d3d1cc08a937b119bc865daed2c408bb8d29dac6c2746b5cef02a74926470a1fc68cd0f3c7a86176327fca21f3957e8d07d57bf6b" },
                { "sco", "e7b32ea426179516937f10c003f6b1f8e8d1d470dd30c41aee711a216f73fead66bc6e7b313c66b3eecba486efceb987f1d6b6dc4d530dea3dce3ca551f32ca2" },
                { "si", "75ae1331c5af70621ae871560610f5ffcc5df3dd6b1c9324945712257b88657f86efa60ad4cd608bebb8415a65b4c7adc1dc7087408c2659f3767feb80882a4b" },
                { "sk", "c3113d56621f83838d2a298c1988b6d1e158f240b915103a49d465b797de8bf7ca0880428013774faa9d420bdc7877a437810fe64501ab041103db8f44191a9b" },
                { "skr", "81397e3e2f05f318f0e29aae34fd2146fdefa946696910daf3a00590d8aac5d46fb5410a8151d8096be608803e89669571e7d0bde2bfd165a4d12f32aca2e328" },
                { "sl", "4d09f98b1480e770b9e4c501a522f69894ce5606b5cd8cfda7b97756b990d0e87985eccf05e718ea44bd024ae4fbd572dd47d65dcc714e45115b182f1355c128" },
                { "son", "94b27d76751e97a80b477b9c8acfb92d5f4d97f54380a8981db17dc0f68e333dcc38cd7dcc3bba49888deb5c678866f2b8f5e8a2dc25dbc3987d4476be5f0a83" },
                { "sq", "981e715a3b221f6e9a2aac05f3a606a7e02b9495638c4cf6186d65696210990759e24cd1943b9f051f6167450233390e760a1df3bb242fb3b1cfe99d082503d7" },
                { "sr", "bd832b3f782c2048eb15344af9ce46793f29aa9ee7144ae79135fd77cb4ab99e85669c8001dfcdbc9876efc25d091fc1e792042c94824abb6a824347fc738de5" },
                { "sv-SE", "ea80e49e58b51110cb240abdb06f89115d0039851c9c509dd5439273e699f3e7ac2d045c8736b1e7995c219ff787bafeeed1d615040d704d6bf019a812fb114d" },
                { "szl", "1186e5121f08b2de5f01213b5efb547808ca9a7d6449e3c32a81c8f71943ec60fc63bf156d319ea3df5dc8ed84420b8efcc0cdebd6d072335c0a6a3e3e51ef5c" },
                { "ta", "e131dcf2c10695ec1115cbfad0813cc53c204e4ca850a29c2e2ab12d3a72d7e84c55f3e7d967895cfa38579dfb7d91abfb271f711c74cd88dea6307a5e97014a" },
                { "te", "4d2cea704cf216cf5914bfe678ee6a69fe34a50b851c449307791d0353b0dfd01585ce8e44b1ff140cb7028d94e2c89d030823108802da65b1508771f72d775c" },
                { "tg", "4e71b470a89147c41a751569608261f0bca8f910597d8bceee4ce09b3d19cf9aca5f1a15844d461a43da37938e98543f44adb8dc9186194ebc28cc0f0cda4fb9" },
                { "th", "2185027f135ac945ca5574744a898aa76f5a509a70dd68b8f33d78655f5ee32048523465f53afcc79ef75440d733a6fa4d421971c3476ded1e330d6a89ae6282" },
                { "tl", "66cdcf197ea2e5fafad3936a0cbc1bc45f865688ca7bb65dca7b6c0cfef08d80d974cc7280cff75a2c55b7c943276982def04c640a063a37dd81f9bb93b29f7b" },
                { "tr", "f4243a64f1a0feddd9c6d3be0d0469af996e177482e646f6cc3257083007ba10c9145285ce047f17624f6ac29495e3921febce4f0fcdef252a1fcca0355c101e" },
                { "trs", "60cfa53fb9e7e6894546610c6aef262897e910ea557a0d8f28c7f57637491158dcf9ad49096f12e26e148aaf677f11cfbdc37a66a7da38ab0f5f5f53faf2c16c" },
                { "uk", "e3203488a81ac4ada043cfbd0a124a97cce78774cfc64e4ec5d99211800b4247e256ba49b739200a9f964c23268ea42fc3531c4aaa13d510fe68965852cc5b6a" },
                { "ur", "27febaae14e8d489766d63ca1f51ef791a18b0775732c02f9dcbdad0e97802b9990a5c6e4032f7734eb4cb68f0ce6982cc6cc0e8b87d6b6b423507bcc3b9589e" },
                { "uz", "c7a5b92635d13315ee6ba5038a8af6faf2a2b078fc7dd6a83a824c9f64e759b550cdbdea47067c5548a7982ceea89ef1796efe81d5ba7b2723fcb016a568a8ed" },
                { "vi", "728be36bf45102739310be16b4e1258c3cd647e55513daef8868729a35a4b6346ae67a6bab86fb410013ff8885502ce8c3ed3f94bff414937fbee0c193a01bd2" },
                { "xh", "869d2475a77f26c45fefb79a8312ee77cccc3dd7b45b9f2aa30fc0f3cf9f7c57f53568942d7507745ff3651ea57bfc3259d41cb6b0a6593837f8bec0a2e05e25" },
                { "zh-CN", "0d19f5cf765baafa5576cf66a5fecd3739558f0303662435e3fb28d4acf729d01a4c0ba7e68d8a8fa23f7d5f33b312bbd0446aba05a33529c853a3f86ddb795f" },
                { "zh-TW", "1acaeaef6cbe9ce4016fa2887bd9d72ec7957fc320b381413960cb662ffc692535c8a2a46cf53f324f54966ff0be19023b62c8f600de5b578cd5c59a1d98096f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "147d3877da773fa52d2ee6b1d1c30cc464e1509980924603e748d7b219da8cc3182829baa2bfec875828dbbdaa4d3b0bb1fcf64f9be3373fddb618cca06f92c9" },
                { "af", "ff7014037cc3039765e92a5d42a17f5a020b83dcbc308a68500f8aa4a152e6103bad01dd51f4214d18c23670db86930a41b1f4294a4b7d0b786abb9ff6eccabd" },
                { "an", "f88011f546553b324a62c951364dc1e8cb8bb68155e4eea6d4c7b8f811ba35e299efa0efeee29b9dd3b1d647474581027caab46d86fd06c79829bec0acf4c3bb" },
                { "ar", "d0aa3b2e7392eeca50c6d6f7e87e1b96731ee88f106feb4b7c0cfb6583fd59ac7eadd5628574706a4ad1c03cd96784e894de52276323d6912a65f5830a8c304b" },
                { "ast", "6aaa5b099baa9a0fc582476bef3c9221ea5d9d3bdc367910b2813981fb7e5709ca6d5efaa757b9bf67f79c1778a61b0ac9b9f3736eee5b74feaa6bbf69ecf2f5" },
                { "az", "4203fc01b059b3e87f69fc0be0e758076a43d7b19371f49bd1e28aeea34a5f5170e2c792f6782b07e5e401670757a59c44d5ceca29c0e7ba8c9b4b2d4c460c8c" },
                { "be", "224bc6775f258700eaaf4e2b85c79c4c02c699df324d58df1bed6efe92060c8d663264f294842233f81facd36501586c9602bc8a261ec780a6ec173a8a3f93e8" },
                { "bg", "c7650ccd3104cd1118568f875e02f939a4ab2e93a8b40c90eb31d9a75c793d6248acf8077efc369f1af8b3226f60328a4d3d942dab2614e6f74454fa6d768699" },
                { "bn", "d108a25dd8e60c7731bfdc54eb941005fbdea06c0144cdbaeb4642ab53b11b0088c1b1d961fa2b7622ea81744e9cc8bcc6af0afd46ec06be8f1da51dfb7015ab" },
                { "br", "ab3acc6cf31f6c42dfd74d12e1b30aca13a6c1be203c2995a0aada625e609a9ad08598c7a91c3ec4b971113e3cec9c7ac9c1457a575efb0421b53e808a452c98" },
                { "bs", "6eec0b6153a27aaba117294ad3b869332085caed0353498f5309325ea98bb769fd817471927d27f7c57cb48d7a9a090a9b1f07379f785491b3a97ef270f05144" },
                { "ca", "a38d7dd4fd8b59ce04e74d9aae3d84bf6c0e4aa2f593ccfa898750115bac7b62536a490dc3f0e178918a54b835b34f1f25747465344c1d0ca3edaf197b43d131" },
                { "cak", "9606259fa8655edf491cc947c02f246c3ebcd081cd61225061f10ec24fabbdcdd60f81e7dffdf15c1ee32951497715a3f7ab5930cd35a0b6aca1cc0a7901b193" },
                { "cs", "26322d8ed8fa7a58acf85e04ee12303dfdfedba1842d9c03d2f1af7be50186fc23a968410dba6e3867e9bd1ff5c9d6176786d207217efbe6ea00035d64d88f79" },
                { "cy", "906916ea914327919017d3bb594349d9b660f2880279fa5381bf9c9c29872593c6fee313d7cd1e119ceaaa1838905b195802b98b570bfe6d407fc86334bd8cf3" },
                { "da", "04d3119304e5ca90fe947dc232b3a876105c7c8356fc904b52e241897a4e4e80945418af954efd8270da5f62685a5c30aa53ba13993cffe61a087ace74c2af9e" },
                { "de", "cabf03587f69660a039e0ed52a6a9b9d474a7cc63b37a5ec1924578bd99f9fa7e6cf970d3408ed7cfea99e47a1ae2666f68a0498b271339510bf301947475639" },
                { "dsb", "89212aa9328621614621362dfb47676a713ffa39edf9cdd4b8ad711aa8ac7e91706f16050318bb5ed4fef590d85d84ee0d2f4aac22ed940d271abe3e83669a29" },
                { "el", "b067be324c7277f55f7a581e03c8440c0a9097126c70e1ef4c0679a8065f7aec65be97e54d4cd79c9a7ab8723a21c252cbfadfb837a44a131861449dc18b84b0" },
                { "en-CA", "f52085c43b7ef4f80af9d2a553b37475a9d0a5b5fe5a20864d1b43a0548c112ef634245bdf1fd54bec4001c4b95cbcaa3168f0d689ed2b2c16725fd1724d630b" },
                { "en-GB", "2c17b1ad3e0212ad4251f766ff6b245a513871e710ed93e948339d38ebea07ce3548cf68a50774986ade36d995bdd68fa8365176b8510baeb2788398289ce1b1" },
                { "en-US", "335436f7a95d05f575d90da1c4def782dc0ed871a123df6e628334fe86699fcb30a229a2a7e3c2cbd99b92c472d8f48bfd2ae04e470394608552eb2f2bb8834b" },
                { "eo", "c74ec33c000677653edbb3ea322e9e08a85f8366f8a0f0e207ba34e4153fb311c9b01e3bc3ca758c0bc6ce83b8a7d5a5da4bf688919a30ec71e96f9d81159d1d" },
                { "es-AR", "cd7b0b7be2a0609a9ce1b4bc7503ce2137a17fe1926d9b2331baab8d1e49c8602054ba54f689124501f3a1558d81a6bfc7e651aa2fa245d29e3f73b9a0d979aa" },
                { "es-CL", "f4705dfeb11e2c7f09cb50a5b6d2f027e8a7da3c1a2be9636132b16a42e7e73cef0e878d2f3105bd5f44c4a2dec29e16234a2132fd07ba942d1b5b3df5cf6278" },
                { "es-ES", "2e24770095767088ce527fadc9f48282cdbdae27010266f4410dab04ee4bcb14a908db15a0c98ae801dd5d501c5708f165735f5f5c60c533f6a8548575fc8b2b" },
                { "es-MX", "6c5778305ed3cb98c7b29f7d4f8b6150536345b452ac75f5c69f6d573ed1eaa294794df3dffb85371b9836143fa1b401103fe9a2c83941e29492f076d2509862" },
                { "et", "91c2fe3f00fbb4a9ec1427715067d69f0c6661a57118e790f8cc620caef60c62393b22a6af35bcc890e94de06cbd6ced746253aefa68ba10e5eb2fbb44b04fbf" },
                { "eu", "97b8d02b43114d5a4cad3d17f6914b62f925bd56942abcccba01aa911ecdc290e55d2d7ddf93a146407c0abef66639cb1331d38e03d6b232f0cd78ba57432c4a" },
                { "fa", "bcf5cbf3e9caccb6378aa2bc7dc0d025204db04ddc225b94d935aaf1dd446175877857e2b9aea21591c927e519aaa3af9eb5a089f28330621b2a9f078a3a2b5b" },
                { "ff", "e2f355aeb2e9e5535da8bc05c8acaf69e15086c457b88724da8427187a5eab836fa24b1470d91aadf3d805cdd5d942aec87040a855fdfc5e0aed166e1f9f00bc" },
                { "fi", "a6fe0f08c3a0c30fe250b34c6835700a001b09c7c7d8aaf8320a25242e8c364efa5e8af2695223d05b6329a75aa454464922aff00d825a149c3f1a9aa1bd8c43" },
                { "fr", "386d93846f1fe2e0e48231bc462e8a13ce823c5835a53b81a3c01bcfd144ef13734fdbd53c33175d498e2326f1e5d06e48dfdfd419fdfacca9eef87da2fa2a86" },
                { "fur", "1260b451a7a8d8c9f72550c623707ef1337ae70aaff8193ddad94cf8938252d2de6b2dddaf64eba7135c7b96c191d1a97c1d63af81540cde904c736a5e79bea3" },
                { "fy-NL", "8dce8adf62199870277fd0b00fb0aef1ddb071332b7f044b9cd57e507e6363fca5da946650055b202bd63626af2c760cec899c3d1fb64b036d5102d528302d7a" },
                { "ga-IE", "dee9886318140c3e86a9fbf4ea93a813d8a14cf069ac577e8fd98d8d1519a6c61f469a7327da3ea6453df3d50b25b7bf40dd8344ab214a420f299f9d4562ec16" },
                { "gd", "2851d8629330d1291e342046a90330fac47fdda663ced73a6711a96108aa5a5b8c482bb170e32df776049d9439d057426fa5e7eef227dc73316a718c578062a6" },
                { "gl", "fb3820af42a152eb40548089f74f0ceb08ed4d2f5f074cc8b961621344d485409157d63130684c3da3b7b9b8280d273e5d3cdbeca2109907801aefe679ec5f8e" },
                { "gn", "1379506b2788ce1470aa017ca8de917499993fb824d880b7b13ce7e2f280a69e5f79761f4ae142536bde315934c308efeeca3c2bf2e33202aac4e61fc67cd6aa" },
                { "gu-IN", "ea19118d142edc9bbaa6bded875527d406a33de08ad5dfc6ca0dba5d5fbd2718b6786c89e30e06728ee00a3d7b9d3aa049af1b93cfc665864b27e28295592b8a" },
                { "he", "2d6db999be8db7f123135d86180ba5eec9e2294ccc19561fe8210a9087af1448e8dab1bb7a9ec5f7cca8be10df06798167502659a41feccdb8e49294d015509c" },
                { "hi-IN", "dd20bd2a6b7a792b29a847cb22763135710edefd61793861ffe1871c26492b595d0dfd8fa2775948431961c309d8b820f581a542be495ab4a5cdd94ccc538a21" },
                { "hr", "580babbca5d5f9e89b4878c608309272a619dbd45346af8c9bba45b57166c82c8939ec5622a03c16a7f369f8d8a6a207135a988808363e149d756fd7da60c5b6" },
                { "hsb", "9d622e8728f99a76808dca2448fc09c535dc8c984174e54b9081573d0cdbd36f0e73bc877c793c904e6d80d2ba0356332e7c9ba427a0d7dce349817ef9fc1ae9" },
                { "hu", "426e82ea7f2b3d976b87b1375832b41c0370827270ec342a070e00d4bc0239d223d7f6ea2f0df696ee503a664cc62fcd775bb3ef4c0bfabe626ab03510ed199d" },
                { "hy-AM", "b89675cb1666dfff8d70f09231dffd46f3bc17a81cda858d4ba764f85cc676b34eacec0653d8a7f6ded94b334322f527955fa5922011949c14995fb9ad9b64c1" },
                { "ia", "bc35db5d5137fc9205bcfe133bc738ac08e21d77aa0b71462b6fe001cc26233a09fa947f1079ea8ae95b8c3a9ab4f2925815527e28893a1db70fa54970afea88" },
                { "id", "0691c14a1a5a85acef94dc464cb7b34c83cce1875206370be3a98da1a0ce118c751fb998ed3361199ef37c37013d8ca4f8d0c4f847cb7e14dd1541826794ee64" },
                { "is", "dacc2d0b691ab5b90c0b04cba6fded4fae35b7648cc1edb8c8ab91570970f299958da461cd9008e94d10243389aea47c50f4cbf57986ddc7921d61f474a46d96" },
                { "it", "0673421c0ec0f4d1a81754ae007d82a9dd0f5c85435cc7666435210a74792db85de55bc83da17887f2344378c9eb3439a66208e9e38a97488acde3950378250a" },
                { "ja", "ad05fefd11b1d0c77e7fc0e33415db813ec959702f48265d406fa99c870c0e405c69a8962b365bb28865129b3f1e78f050eea06dada210189e42e5afc47de037" },
                { "ka", "8382cd147d9c085d9c9880863c80263dfb7aede228d172f3225ca61fc7da6165d7e09abc9ecf9b54bceb5d3a08de7037353b21439de7965a395845f562e319f7" },
                { "kab", "19e282e0124292123bcd395b27a93860e9dacce1c8ff3c9ee8917e9aa245eb439c97554cf635548f821d7163aa91a7f82f9f3a6582c806003344b1f3aa968621" },
                { "kk", "ac84363417330b664e9ae8a32d146c55fdfe5dff256a6d8a5fda3b08907bd4b2c7d56487b3dc7559debfd72f05d42d7d6a79c48c0dbd9d03c3f5bf50526e88ad" },
                { "km", "f686ac6a1bcf65eaa5e461e64993eed3a0a0d6a6df5075c9c0f8dd1f7a643f6b95aff32084422ec4f2ac343a1d3e7c1c2b5be2bffd2ad13361793b1fc8b45446" },
                { "kn", "8f379ed366a031c9035806eacf107bf143e121df6ba3564069c3883d97e0a22eb65aed8a669bd0feea4aaab00e34bd303341f5bc28adb14ee0a1c4da0af32691" },
                { "ko", "cb898477dfa9d58580b00924b0b7a0105d22b7c30e798a33dd178ca86fb7c8b1c98f50f3848dfcf00a8666d953f4b31266d55d545f95c86ffd9b78ce8cf6302c" },
                { "lij", "1538c0405de7209f7e26f734ffcb705fba08b9312634779d86637f5f0bfe6690a761ff8e98d4460180ed4c2bc46432a6e1eff225a5f4712266186fbbc6dbd7e6" },
                { "lt", "3881820f31d7737bb54ffc657412c36f2d78d5166ec342814510561afd33681ab5ace815588390c316e5e4a4e91aa23cae50def5098e7683b340403412516358" },
                { "lv", "ddd3afbad938f1e33d281bdaafc8f1df6f2502c4cd4ee821ec8ae37748f245f844d6b97d7578f53cc3b3676b64cb4a22a4849e2ea9571ded75be1fe29190d80a" },
                { "mk", "80bb4d5835738d9209f7d3f7fab266e77830c3e2f64e5b5af7d5566c076554ce48f453a4758094dcdb38bfafbb96dc4369263a139b128e8125e8c439297226b3" },
                { "mr", "5200cd1ffc2f489bf9bccbe60559b4d7f5452c1639c7b61313f6fe90eb670a84556368c29b91240c5e2135d42a1ea3d43b84514e8b401336080e85745d8885c8" },
                { "ms", "7d76087abc3d2b907b41abc9312194503a7e0db0b37e19722322c1c2e2943aae81dbc39ac81c35485b84c719d10c691444d750320d19801e0f63b3ac988f8b5f" },
                { "my", "0d2c82421ac4a30b28795895632e18462fe22acf144696318bff20d13a45f012d47da48853d6d58c1d197b9217edfc74c8184b5e9edd56e6ce8e155b51eb0f47" },
                { "nb-NO", "3c4f1a015cf9346cb0b69f92e01af7288f0534c728322c95ba923df0f8f87a75a246c9f0fe61dd5e41fa74bf80d97e5f30fb2512c0f1ad22eb4377587ddcb73a" },
                { "ne-NP", "c358f495c2ff237c82a2aa8c8702006c731d99569710c2807cdc40fc729181893544bf6e9bf20c8aa37fbf18db50e7257af3ede3ed1bbb7f6300c9cd360edc1f" },
                { "nl", "911997973d8dde8216c572557f47b87188b8ed8a782678d1628075ebd010bd997f6772ffda5b29625d1338ddbe43c17e3b7e5282e484eaf0434ca64fd14c06e2" },
                { "nn-NO", "9ffb52384f89acaea0a23fd1cbf24f382f1b53a4d71e06df1386af3171adb57c69b43e167bfaaab244f74aefe1ba6892b0a0781cfd447e1392448d67dc7a5c0f" },
                { "oc", "13778d12f5a186d627cbc2a73503d12f5657622df965303a4005ce6b3c9729654a81bcc28f55165d9fc412a0a64222112d90838e9f394f9363166e7386e625df" },
                { "pa-IN", "19832b38535bb463c0b894e4848bb6b8cc29e8c18c13905b3fe25153e0eccd55c939b4520ac6bd1c7605759436da584ead85a4570a682a66c2477d91b9d245a6" },
                { "pl", "867db400568fb10b40a2bb3bf18032d5946dc54c91d6a5588fb676aca47325f19ee580b74e93376f7cc452f90e80b66156a9c96a01fe7f50f586bcc1898d32c4" },
                { "pt-BR", "26b5dc399cec87ac2c00fa42b7d1285de620bd1b6f91fa1490fc2d9bcfee11d993ff00fcba8175db6916cdeab741d8f7a310f02f515d7f7659b617b508cf0085" },
                { "pt-PT", "9c6e7c3f9d4c3eb88baf5950c2c528473bda5959f7db073733c68f0d22c344c45e4d03440efb53a017afcc4dcbef2a826fb9aef3b5368a2d52fd1200b22497e9" },
                { "rm", "c175544e7fbc8795c290b43abc0b27a830a4131dbf2444f6ba6743deb31083f8211ceafc0c2a022e741b9a6237c6ce168ec39e3ca073b977d1da9b14aeb4c97e" },
                { "ro", "13d77afb3771f817f25ad19e66da98858f005c7afd7800cc581709c9fd19d8243139e060c4797f9db23fbe2006af55bd7d49f3b79b4baa7c71d2f4f862201e81" },
                { "ru", "81a5d8388465405da47fa061986e156a4eacd9fe71407158330de22d3965a63d7afe67ef284a40420b27e3d3b49aad9d3ccf6d02e7036ed92c46345e0e1590a6" },
                { "sat", "1ccb69d5509e6f9572091a0e0fa34bbd69f591e8d97720f55bc1c6c8688d240c763d9e4061f266a05b176d53f85a057309ab326beed90372fa5daab165fa2193" },
                { "sc", "720cc762d25cd758c5e14bb514958d3566cc02b6aa60c56e1ff447d5ce927e9255b17d6c2d5aa5d609a18db18573703c1e004c8b0b220eb2189b2e76d9bc99f0" },
                { "sco", "0d1625081844b87ca34e2d083d0f5a3a899f49cff6515ba392b521088cc14a4f8138fc78c6b396d921b20263943e29477ebd53b3191ce18a9af8dac40705e25e" },
                { "si", "175692691c23608159a271014e3dbe9be7cb015d8820c640aa4cbf7831946cf1c34e273e2332983a1bcc8485d8c2da2470b1e1bcd14e5a4a1c767dc8bf8c2b41" },
                { "sk", "0efbe0fc680b84299bac7a78b4563a926723c3ce1c16af14f18a9bc06e7a06d09b41e7624bae86fdd45b2e1a8516f837af87d60b0d9948150875477867faff32" },
                { "skr", "4c8708de367fc7692838e103d8e564f3cc7493e854810865694bce6047a024e3d68158cc499eb7fe6dc19cd928f3caecb259b37a304da3515495ff392e43e1dc" },
                { "sl", "4cd485b548b9ca58d185c3584b5fc5578d5fbe108d6b0ec1486c30e4dd400de6be01ec30ee3c7c5f0a51556efa214322c39e13cfff7c07c4bfa11a33cbfa4bfb" },
                { "son", "b5791b68681f7212a8d246bbb73a1617b0f2ea22fd4e67945227e2f35556de2c26db5e4f046bdeb3f04ae2dccf1fb476f9b7d8a766db7734aa8ae55a9c9b8604" },
                { "sq", "40cb25f2e6bd60a5ce7e93c7804f71d8406150a0c9e7a793cdf10e19d3808a93af3d46d86474c08dbe8ac7a9046004741eaef797e8ac5cee0b54aafa32618a0b" },
                { "sr", "d0e4d0386ec8374a8dcc447e394a6c1cf803e7ccb31e5ba7c0c352350346bb2b3d6996ebc33a3476befa1318c07663083ed9168d36a116e39bb04a9ed0033ed4" },
                { "sv-SE", "bfbbc8fb5432c22a4963466b668d3993c88ec5687d600a838b551fe80a2fcedbf2b2615e8a1d2e3349ca9659a39cb7a3b90d939853a5e2615208ba222b4a1842" },
                { "szl", "dad854927c9947e0af6881fbb1480ebe0f87964f2e4b25f69b206acbd546e20612eb7d214ab35816c9b012db5003bdec463997826f18c0e6ed9cf57935e4347a" },
                { "ta", "410c6924e68978fdd543a0004a35116dedbc24c596033aaacfb1c3ac342f583c9bc096bc587241b538465d09ae9fbfe12ede4c89134b12df0e524e1e038769f9" },
                { "te", "304729fe7105ae9b50e09ceb7cb46730823011add256458ab858ce22ade521bbf1a4d318a3e7cf7277ec9b89375ab3894cc5d2d5dc06b5a77667223fd70cc534" },
                { "tg", "ec55e9fd8c920c658db1ccd68627fab5137caa7ed25566013ae096fa22ec05294d3edc8f5a2f936ca030c82058782841a1c1a8653ad0e918323e89e8bcde5bc2" },
                { "th", "b5ee4f8831f7f9747cafa6f5493903edccb59b6ee9ab35f76fe4a06d8c1287cc15791a3cf2c719b285ff4d5d434cbbbad0222fe41ceb142e9f1ccd55feb9d27b" },
                { "tl", "a6922354019fbb09dba23db6aa7e35ed193c92befdf97b0d220330bb51ee0efdbb806e6979c6a60c7278235d2874062219d953cd71f465e934df35f716e0dedd" },
                { "tr", "cc12e35160e1477d2fe7ae9d554ae5470bb437dd7b9a24dbc963453afc7b9b8e281f3e570c633cf060f8c039df85f4e09987c3dca00206ac529e6b18e8afa2e2" },
                { "trs", "8b90d9cb1150abb598bb498ae37da8fce6a806f5cc57b73678666dd7b8f87d3907d8512ecda91bfca072b3f2ec81becb5999c2ca4b2cbaaeb6e050a6c0d28cc9" },
                { "uk", "c1a7ada158f9e05944fbee22b51053611de2a0d59b1d8ea02d0383d1c24f971aedea4c747f6e48a633f2be87decb80ec5e2105be7ef5655ceb78531b9392e8bc" },
                { "ur", "a8f7da79f8ee8d1b3f7cb10d127832e6cca910ee4b15c009cb11861577c32b3cd8722516c0e541413cd7f7b17dff34905a3873da7357cb53a68a7d4c391ee62b" },
                { "uz", "b128fbe9ac744f63ca49582732e470bd1295e52247ef2a2fb058d6a0f679de8bea4037852cca014712aea73732d3d7222cccb85a81e4024e582d44c7ecaf889b" },
                { "vi", "fc8e1f68d9ef8c4af6fb97a105099d001a4b6da65ff2cf6edbf6d6d2bbfab43afb3d2705f1acdf56d365a8b828dd6b698e9b736ae1023ac687640b0a71eb9fad" },
                { "xh", "fce9ad66ad09b073aa805d911eded1719ec8e5e99687d59b4f2ab49eb1b5588f736ed8dee5963e0160edd0369502db9d87b0dbf053ca8d145f02c58aff3887b2" },
                { "zh-CN", "276c22324bfb0138802b3a6466fa7230ce845a313c5f38d638ce7d8266b5008f0d4a5735cd8859b0f0a9c171d32dd603df9e3e1251371b969fa5aefc9f87eb97" },
                { "zh-TW", "60b351ed6414f7cde1cfb34655cde70ccb89e8ae38c9d1cb956a39a57c05b7a55245015fd604e7229b5d73d9854ec8720f943238b3fc0d539d8b8205a9c62959" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
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
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
