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
        private const string knownVersion = "128.8.1";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.8.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "9d58569cae462e33f69735d58a98d168ea88b59cbff9b1b3ed34594fb30bac1612ed544c7dc3498db160beab4a79f0b9f9408cddfa8d4ca25835f9d389d964fb" },
                { "ar", "9ccbe15a56783a195857ea19b3df0434ea0682825c8777a226b1763f002d5497a6527988c3fec2f89fd1a9368311c7ce9db2cde97de6d43030dada11f033d451" },
                { "ast", "fb1cc0b929ac76f69b03fd5621e736a777a572e6b486b0dd6793baae08e69af806a133a35acf9895f73b149a3c2932fd40242fa31dd8552ef2372208e981f126" },
                { "be", "64e8884af7e38dce4f443bfbede9c7c4f7c309e3bb2b7dcdd106b76b1e1cbb7edac87a3608fa8a0dc89f379afbf2f37fc0be1c909aa7358b71295e5fa41d214d" },
                { "bg", "5fc19c6fe13cc4d7f6e4b220bfc9c54ca81fc44694933611c9e1828412bd313f7da385a2cb2d0f4daeaacf69252922a6006b685d375c68731b561c5478c22c4d" },
                { "br", "203b1c54c122795e589584286df6caa3cc8cca927e7130ab518da5e15e4bff30b5d48f1d29f042419e9d23a777b6499d47ce5fb2131ba5eade31c7443cbcaef1" },
                { "ca", "f12648f6f77f5151dcb96abb7081099d81f900b60f8dac2535c64bc144a1a132f4a61454b0c5848811bff1de6cb31c050ae3f21b3d4386fc2440fdb16d55f147" },
                { "cak", "d6196a9f88e97d93609cc97c31251419e87fbf40710d6c69bbab172f77989c500cc58fc0890310bfa38eeee895a069d3ef0873899ab1fa9b069bf1e020554639" },
                { "cs", "c1a8d248ad4a7931abfb30873086f96f4d1025ddb3a7dbf91c61bc7c58a3360955ff6ceb7609c15c100903c2f1a3c223aa3ec97c8ce4dc31e44d4584c08e1b11" },
                { "cy", "3a937633b2880010b07c154d429a7abffb6e5f7ea2319e4d508291788edb05ef6b8c7fd7cdecb8046996d5e216bef945165114add54ad756bf1992dc9dd570c6" },
                { "da", "4152b51b2e37fa74163aadfd4d6fee38bf2f7a5c2dadf204349fb090379a97691479909bfca00f6357ad628d9b87a38f64482eac7653062f8bfa87b78509909b" },
                { "de", "2b904720d4d3fd9f179b2408b48c1b0f2913ffa57ae4f3b6536137cbd4b5c47f26b114aaea2a9b8e6ca8933942d604cb6314fce81e57aa89db4b01d3d6a014a1" },
                { "dsb", "e2048e13bc1313b5ccc0664ee745466e09245cb6f6d1aa2fde8220f2565369507c4338c0608dfd3ab79fa19c9daa1c9fbc25dfc4a025b9e157f39ef890ef143f" },
                { "el", "ea8b0e94c348ed0fd7f44fc3c6ac3a3a3033784cbc4413faa750f42997e578661f46b8a4dd1066bdcfb7bb24e4891d7603a0dcc7da31d5bfbd563270b9786d74" },
                { "en-CA", "69faf4687338e5ae5a7473448fa19e2a91e13a2ad9f495a7e5ff4a1e2891892ae0cd6ca967309c8b67b81ead34e088902e8734955bcb82ec38dd0a643fac9c1a" },
                { "en-GB", "6396831e63a52f5a498a437a56653f15cac3bdcb124fc26056223a9b60382158ec7f138877108d62e17bac4389903f90028acac158c66a84ccda4fdb4319cdb4" },
                { "en-US", "8dd00eeba82c923d92c141c4dd393f43a6d365bdf5dbe97b3d8b36a23f9579e8a6fe46a943a58b5f24712efc7ec802c2d30842a3b3b4f0c660229ab71d5fb442" },
                { "es-AR", "bd870ac5ef1a635e143d8897d39c0c286402d1540c380e1ed9bc5e1cf2a8c41899539ea7fe0b5e344361c14c647d791aec0a39e8e3ee0009348481822a21f6d3" },
                { "es-ES", "e79ba1ec9839c4a40af9c621bd65b6a34052b13dbb3dbc3cce41baa0acb260427eda75eed61ca7ae81d425ba86d79d356025a05a65a4ee673925934f126e8093" },
                { "es-MX", "2b59357a73c66460099087a4cd5cf75fdbb1378011a5a34976fd798a86f8d56573d7b486203b935e3aa4227d7b49371866328fb39e83635ac61708425b80f5f1" },
                { "et", "7d6bfd94cd92a51f1fb3065e79fa990e4225ae86611ebe0aee4b4d70264a9c96ea2f8c25d427afc6083cb4995c4ef53b0b25feb4ea1038017f237544a6fb793b" },
                { "eu", "59d11807b380848cda174009be40e94a1977a4d6674d6fa41a0c5c796b4cda27f5cd4f9aea21e7eb1ee69bc055e93d936019834510a393fe84876f6f2324226d" },
                { "fi", "b7a0bc890edee1f1789a35620dccb0f2a10a6fa68a2280d22bdbb3a60f46b1a95fc320ec574b721997b35f6e504e173650b6678cee63a5bc51cf6da067f3180d" },
                { "fr", "289c84a1b86bd08b647ec9a6a5c70db6cce111cae6468082c0090c56c2d9d719812da2a0ca4df6f4dd1f76ddd27b1ddc7f2514ab4c0d2869ca9e8eb1ef0ac6c6" },
                { "fy-NL", "d08b213625c26c0eb31813d9223f656947b7e261a26b87abbbaf1720a27f09c9916cd3ab4342e28ffa16a87c9b72f966f3395c8517710ea891b0ba1e5c0ae1a0" },
                { "ga-IE", "d7cd2ab92323a6671f191aeb94577589ab5c332c9d9381fe12c2860c4d4826eca2ff56cfc626a092c12f85d1c0d53b6efc7f33f44fe7c26fec85ba7335ef9986" },
                { "gd", "91fc8d1249d172b396d8ac96b947bcea379c1faf40c240d2d22f5c6521c7a74d1134f80c2ce3d330b09c7a932dbf4e5a22bd68d3cba2f47223d4944d0f43ef5f" },
                { "gl", "6f36c189cc2b0c9f71e22e79883429223766baf82142d83ec36195149314da1fc974a1c175a28db413ee5cf92da4ba6ccb42176b68c54f5c93a55ca603e65098" },
                { "he", "7a025e643347aad9fcc9170e386c97d03b1fe1754d21e4ab15b81261b1a522af4c8b4c39ececeb0280a3af374847629dd6ffd82630fa922b487379e1ea5e7866" },
                { "hr", "267364a7c942c0f56cdab9baa6da3f538fab4d260b201423b90503eb044dc59b7299cb40c5848a2cd296f16c82b6987a0611424cd39bf15c2c5f7ef85243b85c" },
                { "hsb", "5557947d8fd8e043ed6e7e3d63274f5a3ebfe3097205ede45931ef6372e0b27a845e87689742899672042a323b750319cdeeb3756e4956a0839316bca6086382" },
                { "hu", "1dd6644dadc6968e96dd5d01f250d38eb480db29b9d2351a6143a47a1a0602028aefadeb4e08f356df6a35393676ae54e5e504641fd125c8f4991c08f7bc373f" },
                { "hy-AM", "b0bfa885c1c544d958aba0376f8301f39ffe7ea539ece907c3b396fa2718493599d342be077b9a91ed9fe41596d277a9558164ac5400f4c1270dfe4d0d1171e9" },
                { "id", "3a469818bc1a2efaa9ab11ed628c021407da0a66d06ba796d310f5796dd43dac0edbe162b6b5696e54b69eaafb17c1d68188ba207967ee2fa72e79e0cf4d5d7d" },
                { "is", "9e8ee307dc6b96a6087ecb816fa08876f1974026e249509a4f8da753cab26cc5c4c346151b16cb184211e71965248ae0c4331ea5e50529b2a43cd378fc5e0704" },
                { "it", "c3c2b198b7ad3229cf83bbc2cf1cdc1b3341e5ce0a86d9d60826b208777986ee37c261f3a5689b8b360b67cbde5d1eb5da0a3885565d3af275161b804a465e3f" },
                { "ja", "66df643b8d0e07ef15465ec785ac27cdd8c129b1718a2f6c9fce6bac309c9f03c4e4541ea9f405527a45fd86443a95a350573168f158e82d81b8b34b57abbb09" },
                { "ka", "5d676dc25057153114953d4fb8ff5f30602101c05fe38e229cfd4e025468992aeb842e5d6275944dc1bf0feb42cd0f0d5f2b1fc8b663fa66c903e95caad87dae" },
                { "kab", "a214379d41dd17d81f26fc49da08c03fc7855b2f1de1cce0640ca5ff17144556abed23538089b22d03cbe7f1a20291f9445deca4538ae988dae04fb9ca3be071" },
                { "kk", "e644f1127803b15444b82eee4f3d6cf3255b903e4f2725ac0fa6cf45c5694a7642fb630e4b302e0e9740959819d53d92d8df5ed015d232ab27dd5bca591940e3" },
                { "ko", "8f38e6637e19d0dcd302aeea82f01008bd1fab0d48da9eaec1e9913a208eff58700458a915d684cdf61c79e9cb30eb195622cb4bced39bacf9209fbbf1c87e3f" },
                { "lt", "12672c23130e62ba60148a4b7c2247467b3e304c0f274d853b4fc61678b2dff1ea3a8a67b117c3ae93b8a5b44f1242b6dc009390b111a9d8656dacfd1bf196a2" },
                { "lv", "5021978e68822a9b671085a6e3c3614cbc6086543c38c14bdda476d06e189fb33ffc40b70703ba163f202c209c7d3e800bd185dd2670dbd3e58e3700be549d59" },
                { "ms", "b525fa1c4452b9db5e94ce889024aedf4628e1ceef283b98857b5a53882c2fff1a17512a43e0a1a88ac61f16f0bc45235be61240ae682740ec68cb88d5105dce" },
                { "nb-NO", "fcd886c30e2716a9f9720b6176eef7c670dc719e1d853b0cf8f0b7a0aa4c56230f6b9c1775deaf140f4eec0de17dc1c94f16605e30ac007552cad95a55bc9de5" },
                { "nl", "04fe0a6ded495115c5a3b9f1589d15f7cdf210aa2607d25e9ced2755da8241f1416ca78654c604ffb57d824899892daa0a79dce829de648b175d0701cdcd03e7" },
                { "nn-NO", "c102f8e75ecad74eaeb58b85b09a5741279f26b8e650256b80ce61771a162538bc72307e3697f48b8e0d4d90c889d7e6672396f7c491c016b732eb7082fc509f" },
                { "pa-IN", "22d1a098fc9c9a325c6f65283c9b2d5c6cd3327ce06c4ba27c68e98640a2ce84b7047e531c484ad62943fe8cd7f41468d506137d4e6ab628b2645e70de06724d" },
                { "pl", "378a35c8fdc55a011772452f345c1129ae948b42ba73943ec4d91eb60bed25de10e88466b7050b272e0d9d5749dcbf0a1ba2f3e081a30e22387b7ab94d99fc8a" },
                { "pt-BR", "1f91fa43eac81d252e7d488b07044a17ea84dc3df1fe5dd668e8ca2b76a9d007538bb7a1c539113418471ae79eb45a2be1d64c100ce1474fbcf95797d09bc3de" },
                { "pt-PT", "51601c42dd97679a673b8d5f4e905e52f5dd54223d804464c277c214ab87780145506bfcf00bd3d0392f9f921b9c569caf1a52761558dcf483172243b277697d" },
                { "rm", "25629ce38ec4df00b80ce6463e10d0b6980125fa2bf8b7b24b6e69f7c1480cb3cdd3d549303b5071519b4e507090aafb22173b44ca165259483c31cd46c1c434" },
                { "ro", "ecfbb45f2f06b5db00adcba3e630142dbd73818856bc7b2370e28e1bee670d8f3089cee0b105d2e59ec894b10407b93855a4365ed5dcb55996c600997a53def4" },
                { "ru", "874799dab2f731ce4d55dab23c03a4995b5c30d97a71bc2cbd9a06aca1a2879b3358563edc08cd289724a98691308cd73c24711e2d84f7fe02db4731e61481f8" },
                { "sk", "5d044afc21339811963d886cd259257460b6282e539bda67c4d8e867ba37e9b01637ad39bb93847c7d3dad43cb7d1617dbfc8cb95c850f0e983e60cefc4252ad" },
                { "sl", "dacf018af9e54a7a205605748282acd69f2eb584c81296dcd22d525e29463c04c08b9a41f31fc677d4bc8299622ae8d9bd7066f317918049f3776f22fd6b3f8f" },
                { "sq", "59fefa49c5bdecd67af18d909241ac886ce0481894149816468f7c3710bf894886c423b04b0a12438a46f75bc7dcec2ff1b9a6c3f6d5bb550d97801aa559dbf2" },
                { "sr", "81b380a3c908e86f9e2bf14c6bdb81e1b625ea674e41f84a1e824e7fd33592545aa7ffd211680f01e3f05074ff6a91f410dbf9d1b3d29e1420cb6266d8bb1027" },
                { "sv-SE", "6eae9f590b9b9c945add2b1e03f3f37040e1ae18d470a12d7dda530a1ac12e0bb804dfec4178bcb68906f2ce044d2e44327354996baec6bec120d7d83e828532" },
                { "th", "8028d7690a6d5079bbd9ef0d499b2ea43744a1e50abfe6df7730f13376d383cfbffa2b03c819853009904e94229c403bfd7477a834e5eef3a0f0f627656b129f" },
                { "tr", "2ddfa369d9e667aece9a3915dcd95d962519b30b02e67e79cba3cf8f69d3e17cceaec2d1960c0bbed45b5df9eb6048a171e7c2e88607c319432c295531ccfd14" },
                { "uk", "c44ffad6673fa3bfaf2071b580f26570d9951d1c764cf680be4eda30560ae1cf31c5f2f16add59daef4c6be4539f03a5818050b23746e83a860d53759121e3c0" },
                { "uz", "ea131c53d7c133fb45c8897434cd8507ef16cc1f851527aebe5de6443bae6b1a59a8b4ef572374bb05a351e0539e0ec0dbfb514a45d513ce55dbbd679bf10a6a" },
                { "vi", "9fdb4db1fb3145d4f165f285e4ff179bad8ef200dc4c55213b716b3c50ffe24b89cdf0554d52c415ec5f033717d5717b7cf620ebfaafc357c84ce9b6de861e99" },
                { "zh-CN", "19d05c76aa119928614070358dfe76d4a485652e8e3dc92d391cbceb885684f36e148ab8a9ed61c682f7dadfdd2c9e9d8a9beb4fb33e50f06f85538c69c7ee76" },
                { "zh-TW", "be3ad448bb7b9c8defce9633687f5686c575843dbf466617df7231d1aad023807e6de7c1112c0821ba14eb024159cc4846ae8fe23ef5a2961a04c7a992325a28" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.8.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "832d099ef7950ba9209a141d912012166a2f745da4ca43b6d4f7b83a082e7af5d81f7a182ca297034bbc5717e6df073b500e1cdfb32f35d855eeef43a0ca596a" },
                { "ar", "3d6f0f092cc279bf119a87a04e614f67330aaa586bd8774bc16f7bc6321995ea3bcf24284b9c34045c6199652715264cba560316e338eb48e0b25a406e4a209b" },
                { "ast", "b717a9696a91b33c604b01cf2d03f64cd722a222ce6dfa209cbd40c91dd52f0b6acfad8dff880746c6690329ed4525534277098139b9f4cd60e790ccee4c141d" },
                { "be", "80e926e3cb4b6f9b6a068863d997a8e16f7a818d94b3ac7022e547e31904c4d9b3b24f91a24272b4f2c65847b1852bc39596aebc8b244545f2a433a3d8c85e49" },
                { "bg", "88b809801f56a7a12aafb9c03cbbaea5daa64b89f629867e85b8cddafaa79c982ca82c4919acf951de77a0dba8c4d2fa7783d7b6086736060bb35416619aa280" },
                { "br", "f6a7cacd417811ba73672351b67bcd4961c1e58877a8b5e7c51f81436ba708c46cc57a522ab9516636c2603de0d91092b9218692f8fd2da46fa066268a234356" },
                { "ca", "1f1d2221062426bdfff988a9fe024cda74e656636899b073bc21d8e0f6c61f98516071dd9b9907edf985ac8378d7c6a913c94c16d0ffde4a943950a137f78695" },
                { "cak", "65cadd8971cc6520c3161a5ce10d0818215a422540d53503e150671903d61f696ba19df19bc971be267c6b23b8ee1b087711d26517aab4f2b1694b05e44a63b8" },
                { "cs", "4049b83c773f5467f1b68385e960e5d8499ece65c7b136cb83eedb32d2e4487ebe1d92a615a409c9a07179225bd8d5bcd9800aba9fe1a82635ee65b342225fff" },
                { "cy", "daf1da407727d800dcae14d9dc999b10ef3f11ab8344aa386fa7ca25e576738b1976d36f2e16864358858f7b90094eccf7f9fbb334cfa6b7d5a850dbd66b352d" },
                { "da", "9452d102d678659c97b2973252df7d94d8699c65979ef2125dc4303b62eec8eeff51cb96399ecd13eadcb63173f58276dd7ded932e73899f784da07adc37714f" },
                { "de", "2fd7d7f6f68b98edfc3ffdc98287a619419763339af35030e4da38e2963d8b10968ee63bab23281447ced6a721acfd66989d0cfc38cc8d0938323e76cf555662" },
                { "dsb", "ba951eed671387a931d3a946aa3a9de6eaf61c0e8b7528916f810fb5faee9571a815d8e9cbd16952b4ad2cb7dd46e7d83495bccf4048efcd5787ba36b285071e" },
                { "el", "a8d8ff199ed081968a18d9c35e1cffaedee464d8feffc95e5d64ac6bb40a7f3b6b34c9f95854fa1b1d0cfd6a8ab8c48dbfe061dd2978e80d46721bab8cf36e9a" },
                { "en-CA", "2a6532a5ba603191e4fb52ba66c8fb73a31127580f5a7ac2546b5ce01342e0bcbfc0ada56da277b135cc266725eda098ae2a3dcdf8dddca08340025df51a798b" },
                { "en-GB", "d93ff22a5f446f0c097c2e9bd6fd8ca1791fed4832ab8a2f12c6926792bbb4f43c671f3bc7e4c9029ed4af1b09e945a6a423b83c40ddf53a8eafa3f5cfb1288a" },
                { "en-US", "4e31a80915898d76cea6e60b4fc433771c5827d7c84fc4daa48eec17b30cef6ef90d9652d2e4aa638dd8998c94007e8a372bfe8cc6013b7f870fd5e74416e89e" },
                { "es-AR", "f15b1f33bda680874818b0c0eb21c254e536bfc904ce1bae19a827f66511f0a74f015dccded3d2e17573789932016591018c732242699f7ddca526898537bfbb" },
                { "es-ES", "5eaaa6b4af586ce6ff875fc016d4e2fdc8e3663b8f776d05865bae9bc182ed21bcd460596ed17c2a8bf616bbd8e7d59df85911f1ea4f0f34918aa47cb9188ec5" },
                { "es-MX", "92ac22e7c2a3bdf6e5a5fdf952272bc2518af2f8140cae6f9522ac53b35e94d56dac650b35525354c1b020c97e8de0d1ee3c885d064fca557a152d97d7f67113" },
                { "et", "4b683fb001c2d28c3a23dbb2dd8eae6a4167c236a84c104a235594757fa05164a8d4f87cf2e4543efbeacc3ebdc36e09a73487b9a1a6948c23d2225a5378b237" },
                { "eu", "5d13c7b4d04e4d17cfd35bc54bf60a7c7c6d34c68ef56735f44bcd56690057b382ce10131fe7a1d0c81df33745f68c71a6e0221566f7957eeaa7ce7f8a022856" },
                { "fi", "dd1b838e886c7b61829451c17a96d06b0374072fdc31a6c40191f26ffaba16b5f89b257be76be6310655b261e0ba2e8122bb5213384bd945f515b5c1f4bb0f17" },
                { "fr", "5ed6a290d3315f1e21240a6baf11c54625c772163fc77f24f174db91580a24c401148a6170e85457ab55e350cd6c99253b2312d0cfba0eb295bfe21812060d37" },
                { "fy-NL", "193978e55f7054b7de24f4aeda006af0abc3dacf845d21d883d8704bf1edec9ae9bdca64110d6f6872315100853c295c9fa940b647644712e193cce811537172" },
                { "ga-IE", "e7d5855555e088f1e176316f419f640285ad009dcb16ae45c07ee2ac7296a4507e3020e2b3f820a95e97b59d5726d607b8b321ea60be56c0a161b06780e4b0a8" },
                { "gd", "384ae3307a7b77ddae65b9466158a5aae92ade70577887e719d6f2f3417e4cc6f9939c575b75104ec20727fe3acbe143a4ef5cf47990739e1826ec9545e772ab" },
                { "gl", "d79ade9c4d414f60ebcf16eec97977e69f1af1acc0011f254d1e6ff780e3da5e4c8b20bb4a2de51c06fd7319c18cfea17b662b89ad1796cb8fd32f0bf710f861" },
                { "he", "fd0c761aad9b3439be4bce7b46e0194816c8baf1e628bc387e1f23ef2a315647a28d2a3f4a181b32cef3194435f68b5b066ca7937975a392a636edb0c3443870" },
                { "hr", "48f73b56a6a1394ac89cfff3c7cb554dd25b35d4af904a767cd83a60f05d282d6bd47e74e12470b200031d2b2f5cf2ce4ac979bdf05bff4d4a0f3e4887de4665" },
                { "hsb", "8a2a021a98298aedc2e00d4fac6ae98cc1bec95c32499d108330e6ee225183be356178279b6e468f3afc6ba54bd6c620e432742207ce2f4a08e02bd81e48005b" },
                { "hu", "59f42ca8ac566067fef2b18b9655a9b5c3f41308ab00f1f813ff3d6c31d0ac6028481acd1ccd819a82ce70d3417708ba3cb799a588e17d75591269b1e5d1db11" },
                { "hy-AM", "65aa658552d1dbf6a48017529b50733542204c7eb0776bddebf0a295ce1c81a8d80a9452bff5c3d5ab2f3510ee2a150bdd7371684edbd2a6407dc16a1a8f60dd" },
                { "id", "95b0f75ad574a0fea34d803c6690fc891001dae7be93ac354a79140eb5519593055e1d0d800cf6e793cc6f37326959e30feb12ad26becf58e2567a2e9f27f4c9" },
                { "is", "9cd47f648da5b3051e8b4a3a734ebff5aa46912d5de7fde6b8d10a453760b0e2307fabacb3321f6f0c5fbbb5d461d568974329fdb2aae9dc618c992646e911c9" },
                { "it", "4fecc96bc1f5b509f1dd94e5fb5f8e8355fe9f94c16b52703e8951e3edac73fd95a4d4e3980e0c63423e0630aa18f7cc29b26ebd5b76bc98b474b561103ecb40" },
                { "ja", "3b7544799936091fad4f813a5190eab0292a9e34663576d3f9888183a7fc6257ee7047bf6714b74a5dd7678057f70b77ba655515f8e8011031afb604af8b0ce3" },
                { "ka", "9645261d79c25e30f1badc7e3769d7a8a0387ff4d499abd6981b9a1542af0e9471bc6cc0480aed7e3125142032985f430fff3172e728467e99f33f1f45d68d9a" },
                { "kab", "979cd8b0afe7d0435d1ede40d270a84123478a7b34d1ca2ae8d23e9f72340a7c3a7dee5268c6dfb0e9302a575c7288be3fc6418ef717aa5a1844ea5120a14296" },
                { "kk", "46edc9df6139f411df0847763aa62e9a32d92aea7f0e0e558eb50fb5de59f82af719fa40555924ad34bff7e860dd73ada9dc15747c143e042b060010b9801b4b" },
                { "ko", "30a47bd375be60adb2b180571587ae67abe3b9a05b0086a72480b105502ef7234c427f87c41e5c85737bc20fc0762cf31e5ca62097b74890806acd9261006b0b" },
                { "lt", "20c030a0b7b0b2260fde5af0dffa90e78b0e0b931aa9ff51662bc1ac9357e64c057d0984627c2a6e1cf5a0f4b8726eb032be5bb907b5f0c3f9f249eb0de5cd6a" },
                { "lv", "3bbef3bb93b33f6824692eadb3110e69daf498ebdce0f79a53e1b9755d20d4f7e3fb921ca32b64892230dc6dd14482b08ba1df841af65bbd98e32f8a150d02c2" },
                { "ms", "670432a7e789a0213e1045fdbb6315f0093c14eb4a7279ef0d046fc848b908fd0be01c1e4d3c9948d04425c596e6121dabf986756e2f29f90e394b45f2d81dc4" },
                { "nb-NO", "21deedf88deefd6c3e1bae4ef6c5efeb95a8ac00623302968397d01e2f0556956c39ce5c7517beb2aca4d817f7dec202b540151319fed791e8e968e939111fa5" },
                { "nl", "3782179c1f328b1e68e1315985380917ce645548e68778918355ff857acd7593a9968cfc627e123feec408ae370fca5f33fd0733d6fc5c303a23e7c506161e8d" },
                { "nn-NO", "b18032d1bb466ac24241ba6d1fb0bd406f1e6f1b2b106bd12c7d01897a0f60140099494bff72e92c617c8cd8caea8dcdd7a5e892a0bebc5b3f616b00bec8a0a0" },
                { "pa-IN", "d1826b608388460a48ff256bcf286c325beea6e756c0a832341569e1e7bf0585de914dbe551cfccf75787ff4b0eb9df30eaab704389814f5c21aa43c9eb0aa20" },
                { "pl", "305f028cd488acb9565c54d2c4c05dbd3e5b9160ee4b25912253144efbc80b1011aac1e5a3961bb978d17b5cac2796e6186908a8d6893c1826050c21a29b400b" },
                { "pt-BR", "908383c2bd67ea07b3f0be60bb9fd581013867ffd8bff6a8786b9257793aa582ce049da4fd1c99b0e9e70cac7640195341cc32f09a92d3168bde30aa69f23e79" },
                { "pt-PT", "5ae509e0351fcfb204154f1b43d0bccf7ea1eb7317892d5cfe51259937845eefda81074e8373e2cc7de4ce1d7751b87ae78229a827f8ceb09a166aff865cfa53" },
                { "rm", "bfb2cf042ae45600be83c693430654fb6346d20334433093d1fb8ab4d17fd5ac4e8ebad053edb92554b8233cdc4c175eb9dbf373ee890e2d4da7f90cd95cddb5" },
                { "ro", "d4f193f8b41968c5866b862b2f686d5d710f65537ba2663bd03fa7a805f31965a18a43944084087612c881b0f85f1792e0763bae2cc1b406c3d786bf0eb05984" },
                { "ru", "88b8d45990e7785912f7cdd851a598c41e9d4b4ce126c064620b43b45378e797229eb93565c535456018b09c71b3a1066ed5da1eb4b69fb46212d8128482a00d" },
                { "sk", "bda99298c24addb4cf69909a7e608ecc9412a1d08468743b74b92ec96596905b3157cbf2175d779dabca792505d96ba9370f6d3326df53923664ec6a0bfa165c" },
                { "sl", "2cf886062e0d5467415871f73710f1c9d52c9c5b50896e54ac0df0d0b3b8adbf8ddb450a2ec592f66d28336ae243e4668f3f4d8cb87a3e776e611bd9570f7fc9" },
                { "sq", "46faba3fdb7c0a7322180af15389d8442752aac48c87a6266ab1ea3cf16e9506fe085efa4652c1a108c0c317657e9e945162e0e1d5d8dc16131c387c4bbc4028" },
                { "sr", "3309a249c4f4e406c7dab87ece81cf38ceb8318da8bf998bf7ed57714be5b3b60c50e411ddd6bfd336282c9d95f28b5c7f1c0cbcef8a6c0877b13f67f29e3ada" },
                { "sv-SE", "c9ef2660d23b479252e0bbc614ba189cd8bd2aa3bb22bec443df6a2d497610961f5ea04f0018f524ecd725544ce5327b4dbbc346ce6a442a170cc37a3cac2b83" },
                { "th", "269191e43c45602f0a23745270afae12e52a531531641c1018395dc1ab8e03fbb6015cf512c965abf235ef96a62a9df88835b2fc20f6890003166e0a4d2a5fd1" },
                { "tr", "3d7c7d3fffcfb1d2de68487ea1ffb8c1dd0df33ef5bb16bafc760daed08147684639f9bda82d90554bf3fb6e6f8af308fb9d5264d148d5263e30e6542c36459d" },
                { "uk", "f79ae255cb09738c54013a15042c14c885d7d4fba8340674ffcdfc715cd85c21133f04ba78b899bd946bc4a634e37b24a6ed3855d1ca3dd229d3eff3fffd0536" },
                { "uz", "56539b5d5c84a5440656feab35b945a3c637a51dc03ac6967dc6a7af584457a15d479f945adbd3604a3efb8773418bcdcb853d1389cb8e0462d9cc4a7735d29f" },
                { "vi", "e325447f0c78ba1df9e3c4a9e2b7073b2ac3f58b1b034c0634077583089b1c83d5b6f99128ff9b1b6cb4d60abafce0377bfc0ed8d7b49a7805c170313aebd3e6" },
                { "zh-CN", "25fc187a223665f0b41a934ba4a1c7aeb098df3e71228998a74858f11fa2a691063586e47be1e150f8b37aa63e22c8c88da7309a271179b3d262ee1cba75d535" },
                { "zh-TW", "4ca71523c485e8f9877cfd0bf0a55ece25b790f6ff20987e44e41ff239c253927b629326ba3a19e877b1459d51c0c5f74ea762eafabb5e69a1317d3a1c01f347" }
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
