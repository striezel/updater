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
        private const string currentVersion = "154.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "87015d98af021e89f765c030cd2fe4c1c74cfc2b31a4034efca5109de24d82adbdf17a038de27f8659389bc2315ae9e55de0851b914b8958b53be7bde047de53" },
                { "af", "2721e878088be3336fccb6ad7d2a7bc196deca3025580b8f28680a67ff8d898f5cbdb4fb90b0c0fdc94beb8b292fec71db9ec8d335b15ef8594e1c94325f0d24" },
                { "an", "fcc7cba21ec980b2db93d5c9243058a91e323eef2d9f9d10485dd695df9407c87b526f59ed6a641d16dc8718a430aa60915a1019b66db4f6499add76ed2c84e9" },
                { "ar", "103e192492aaad98a9bbf84906539c7b243f9e6dd820c2c876e0d573bbbe413c36f6126e6b0268fcc0d8485e4db0a47daa929ae43c65f23161a7cab3ee32b789" },
                { "ast", "bbb605326b56c4f94021864881e51c0ea1cc741fedf249ff2cd6fcc65b53ca25a70f23550aeb48afee72e12d4995a33f9d17a3a90339bb23ce4915b7d5b4dab3" },
                { "az", "578938e3044774720d14654c3bd7fccd2bf3836a1a8388fbfaa977fa1fea8007b545212d58d57821b62876fa49b11a5b3390577ae4d014424dca2d897914bde0" },
                { "be", "015ab4b4f1f2bbbe56db01963a192df31dd25d8759077f8c9b5a0fb2fedc92652e04e109d369e9ebb06b21aedf00fdb336693aff9293c17a0fea5e98c4212808" },
                { "bg", "d1cecf74b02f2b96e03f123b55ec79172dee83ad8d615b308b5bab2a47aaf025b796d65ef757bee486ad7e260481ca8f0fdaf55d47b45144d1113311d6b1ab0a" },
                { "bn", "84f1d11c66e5f628d8645102d408fe85eee8d5dd0d155d7a715ea03e0a629a8a3ebca737b171fbc1ec02a499481bb52024da3b44ff4f8ec72897713f8afe66b1" },
                { "br", "130d2c5694235bc0479d07c4c8d0a7e1f10e52df89f1e99f6fb5c36d89379748bd9749a0fef5407ab92d225af0b5ad744bc2fb7c401a3e07cbcb76ad0741656e" },
                { "bs", "b72640f64dfef5a2242487c502db1fad3d8bb84cde11568f7d9dd99d93af09b277ee85c33589912ae5d6f8a6f8171a76346017e9408d71573a734f2c65137663" },
                { "ca", "dd4c3accd8c3b1c27788e13572ab9eee2cd665890e50f10226738f927758231556e32f104e75fade61cce4b9ecfc4b72b7f871fcf583a9729238f5d7ce192f87" },
                { "cak", "3990d05ca7e764f0209479ca3929306a0045a2afe05a8ae79cdca97a06b1cb5f98a9f461294c2edd13b606c43a8462da7b6c03a9304bb1083c29dad8dad4b17e" },
                { "cs", "f5c466b5fe7062251cd6633f15726c257c4b15ae4422a8e88843fde973cfdce7ef740539a8e452d4e0cda7edab785a81974d92cf4b1e3c08153213f7b56e41ea" },
                { "cy", "98a7c835505b29efcae6d5e97f4306eedc99776e91aeb04a066ca162747eb92284da5a4247b93ae23edc0f41eddec7ed42a297fe9d48833605ea39d1813f8609" },
                { "da", "12a832e03e1db4bef46e0e86157a736f747ebfd67c2971c1190be8fcd2e7ea1f51c1743f5a8ecce86c8ab5ed6e359e5bc78b9e3ca5c0c4d3513ce034d9e071eb" },
                { "de", "9d503278e302d450a2a4ce38df937e5e83cdef95db2ab29985eca9dfe82479e396de5006e1f75fe8218362be419542254de5f66fbe96a06336520185cafdf2a3" },
                { "dsb", "ba797d7e0de267e1a22cfb9c8aa54a2c38120f82b162a4e3845e3bee805afc6b0dc3cc1eb5cee2d8e3c0f513496b25f85c87e6e3f438bddc65a1c4418bef11c2" },
                { "el", "aae8584e5c77f85d6115e8e3efd20b3cef693c976ff9c07c0f89871ffc666c1bef72da399eb03a26eb4f0156d0b416dc13ee913522e8191a93185571327d07db" },
                { "en-CA", "c7a3a4fa1c73889f518634cea862706dcbe75ca4b59a50d30c5d66415398c479b00b1117494ee65411e9b758e4d58180e923c3b35686becaea829c4f90563bed" },
                { "en-GB", "f99737794a64e1dd52397073cc3da66f95fda36b3e09fdcd067af0deefb81351d1649fca1ee01de5d24ec544266c840618fd13f9dbdc016fb654fac495fb0a06" },
                { "en-US", "cc76849785abf8006458d79cda98e65bbd97c4082838a9247b316c7b988c17c6edb7cdc92cdae8bc3d3f4413d881702887372b958178e60d4c59fb8f17aef73f" },
                { "eo", "4a37ea4ee1c5aa35fe9f0e08b306d92c5b3f2b55946502fbce42e6437b71c05df96be81953a2db94ee7f02428ab6c95d3cff961ea9cffaecfbadd7689bb91328" },
                { "es-AR", "ef51b0f4fdbe42e17bb00321250e5790fa436c5b5ece0e2a4f5c5fa5a1ee3a6e68cbc4a0d71d6161eb854e01105d28e36f2ac6c3c0f0ba7b4e360c239942287f" },
                { "es-CL", "92c100df1568e35befc514e9a35f98c2ea0d5a2685fcf5d4694d4701f8c733a7154f3911fabc047c2a042698d05d1625e26482d28cbe30133abbb6c15b049dbc" },
                { "es-ES", "bab4edefa9846d4e7a7e0ad1d5126d4d20574dd54c4e24fb4b029ace0a6ddaf70aa866e6279fa139fe3ed16c4706bcf1f0330c0a98130f8ebf87918de9a3a72d" },
                { "es-MX", "f526d87a35dbbdad0a7bc6e1798d932bb91d913a2e99d7e740606298409abac4b67e44697a4b1f80f647acd80b1cbc5b5ff6baf796a3d3eaadf042fa451c2498" },
                { "et", "01ae2862b0ca2e8361b74dc3a2af9fe8e6ab45c284845dba746479f794b4f5a6fa3133644aac09f65fe8e69bd7d5ecb79c0f78706491098f14377763b05e9a81" },
                { "eu", "d6c0e12d77cd725f072e208f025ec25dfbb9e2275786b89a51ddf16e05c5cacfc4543e0d1822f35ec21be1938b676acdcc01ed56fc73c55add1dd9b82a7c2e83" },
                { "fa", "8692608d1c16e3c3b5ba8cd06f13fc1e6c7e34eaecee9958d86113b1ae546b1a4d3b6f69ec414aad990c1a73d367fea3a3e17e0569c9114e54877354cce6d83c" },
                { "ff", "3992df863db0b6d0946ddcf0c667930793ae8ce97542db2a638c0ce9a791506130668dd11ffb702c2cb78c65d055e66ff87e637c4e66fc4eb3085ef7d606fd0d" },
                { "fi", "d06b2d7f15aafc02374cd91c89cb86941c78cd50d5cc23bce065cbd422a979ed0a81e3ceed7e9e8aebf70c506a23a1bfa7e5b24a156b4072522bd3e34a87afff" },
                { "fr", "b1057326ad1d2a9c1f268fea18d981d7124c8c78485187110f6a0c3b6dcee5dc9be7fa28290fac3340e9f64b9da6c1d6724208a3e397bbcc720917cd03e2dec0" },
                { "fur", "47707b22fa3cb33b5179eaf18b7fbe551455a4333682f1357f8b71d8aa2d8be9f9f7bd07bdb9e026f6c2c06ea00766a52f079596b3a3479955197d3d6fef77e3" },
                { "fy-NL", "9523df7a27cbdd618949fd6f2ab6918c43a76e32e8c56bb302f3038988e057e9d97ad2f29581f7159a0ecfc307076530f0c5d8c525e3eac6d62b63e575575e43" },
                { "ga-IE", "415a1039c96ee5b5a01fbca652586fd032e35dd832cda18139d3f4aa92d32b014aedea519d5a266e478d9cb7bc68e60ce774f8e18c4e95cf8381cff30ebcb7e6" },
                { "gd", "b2278ef7cf08c2f0db07e1ec754294c18328be6707be526535705d69c995cb1d969ca57334178ffd4c4e6e0d9b73817380de9c097ce57d86bdb95411704658ef" },
                { "gl", "43f0dfde284b6fe6b07d6ac66db3a7fc577bf312bb6ffee50023503943feedb2af8f05382cc344aeb14e669e66d0b93e7d62c30057a9b50d8c0642c5212a3857" },
                { "gn", "09873d494cb93241a2d3872883a3f37bc5fce3997c48fba82c0f916c1ad3e7a2c4f726cc20cbd98601ae30be54d01cd7457eb538377123ce1c96b1627549abd9" },
                { "gu-IN", "cc3d52df817627a4afaa13842e83d739c7e7ba010df5a62b7d06b7ca7f49b1f80c3ade11e7f6db4d8be7ca17112760a596902f3a0997e02cd8e2069b0dcdba82" },
                { "he", "be20c6452d1fa68001966b04e5e16bd42c44589fb590e30515fc6095db34654d10e3e7098ed15bccd12285e385e32d993ce9c0d2724d8114e0abfac63fe3c935" },
                { "hi-IN", "efa8c6532ec59bdda10cb1b7703231b58471f49411c79bd5459b88fce30b3e6510b843a3465218c1cae015db245af3c08abfd8e3d0062b0cec768ec1231c63b9" },
                { "hr", "57213ce82676bb5a2e7c3f8ec2ceb3fe869a808f6780cc6b1aced61b810c8a6925e9175147ee5365c58b49d1df3831ee3630176e23885ef57fed2aa3e781e0fa" },
                { "hsb", "1523284d302445f1eea3410f535aee73765438f5f9d4471be50d67d0628454f314316f987836be744ab096594d70eb8088d8a6858c1fe623aa00f0c24fd3cef4" },
                { "hu", "8fae977e08c9852bb1a8bf3a846fee8ae77aecb45e06c81c2ec4c52bdd0f2838963340279b19c6c1fb4a63f115d096b69377f884353ad8fdcd6b2d55468a6a89" },
                { "hy-AM", "507f2fbfe849e09aa2e65e52ed4bc01e55b7774d3fdcc5daada1642e45d1c390208dea832194a909c7f517b6495ad2e7c9376f5d1f846db36cfb298ea3d88203" },
                { "ia", "8718535298ddc97216b66569fba0d9fec06c6abb3b2d0126e98ea64a133c2dedee66ab1967cc61f6023c46fa3f5828fe6db3280303b20595706272e4a3bf8980" },
                { "id", "3c08417e0236f63243e29f7b62ac5709df851d879ae96d2eda4772824632189b1d47fe2bf331d924f730bb85bb9dfd245f9e9daa8377997d7abd9f062974b705" },
                { "is", "aebfeb8fb1743e31bcaff35fc668ff9e9517000a85b5a5883f48547093a36e9c1ddabc0cb8d03a53ca18ecac41fa16c319c02be98e8a16d4022bc2a4f69876a0" },
                { "it", "4c1280b543bbfc047319ce2674bc59a527e97dc2726c21cbb273e1236c805364d41c3de4f0f68ad5f73a945313219f62c27be9547c8f056cd950be5e55334f5f" },
                { "ja", "faefe7143a1a56ae279eeb8c0cf7227671dbce7615a33432002c91d59b89d13c6545558387926d5c774a1f9fb1e1559278835099cd76b05f4a7379ef2f84929c" },
                { "ka", "903ec3b41ec5904f11a8ab15586599e4cb103b0326c05c28c09909cd62729c64cd4cd9f34f9d8844070ad62b972864575a37b4755de1ecf35a80c1d0b7a9b392" },
                { "kab", "ab8e80568ceb80a1951a729709bd5d94f97249217a39db6c222f5ac80295cd925b25a817a97b13cef072a535201c1a89800bf5a4387aacf06d474314921b2161" },
                { "kk", "ea11964206c5bb384a90c7a369e1e518c63a1ca54449a4c7ddb7032e71cc1f2cd94534039d6c3338205e1f2ad7ffb32d868e9cc174700175e70a04232ccc07e1" },
                { "km", "908bf265f798223a3442e64ebc4d3b56d2571d57bd088fbd9657e02baa501cb5f91594cd3d1dc8f9bd9df8e2f6770709f41a3aa4cacbc5dd15e04483c3682f9a" },
                { "kn", "b965b20a7a3c438a752df5b8eda3f36301ac76396af99a66e6c7bcd66719bf9bae438df1e2d3d40ae4f04a2c2db2a2d0fac8d4bc45ec63da436b0c858b906104" },
                { "ko", "8992cf00eb37c39e477e397f63d637c3dca5bcb4681a53db511229e50cd873fcc6867830eb9b049e8a6c617a1631a84064a8ab7dd93c89e974b196d06598f52d" },
                { "lij", "09af6a8558880fe119d467650ad20b2cd2ba3829583bdc63f1892cb554e6b1bd64f86ccf753edf83ed664b85aebf1b55bd3056aba91371414740b92af7a1cb12" },
                { "lt", "94e9bf2b303e4d52494c47a64cd60228bacc543d89bd09491e6e0691248219a80db165f327377f667796165d456e7c412e3bb6499b33e269ddf7938a20560983" },
                { "lv", "2e7bc4ae38083a5d3bd7167b669de19e050e2c8e10eda7c98b8cf9b5d33a0a2c9ec902a354fc75aa54937186e33a62eae9deca7e5e4d3c4b905c96261b4d01af" },
                { "mk", "bc4859582f9544d4feaa97be5c1b993558753cbf4ab21491f7eb94b2b43f61abbe491cad56a4d3442aa64fc1523114f77c5345a42752190edae63ed85f17bb28" },
                { "mr", "2f32b81b1b466ae1386abedcab019908af30817d3f64504075a89aa28cf6aa5b275a92c0f57936731deba669595aee29fe4f220cef8ccd5df461ebe0c7d7e3e7" },
                { "ms", "8bde98cf91e1e2fd61c1bd33900f39184035a136741be834b44c1e8adcecfccec2956b9d3a7ce26ea9c42f81e0c524967743400d34de3c002340c723e2e15358" },
                { "my", "b4fe8e39ca03bb1c863307e960d24c3d7ae788d152eb47aa71fee6f8e79048b6d3e9689227ee549f65216ef1dd9d760d0df668de763de9bd48c656177bed0663" },
                { "nb-NO", "d91479c005752a4d8fd795f5d77b34a1713abd0c9cb72c561d77baaccb2a72921f7bf868f16f614c375c122a3497772ccac82440164e779057db15e828280633" },
                { "ne-NP", "7053f3dd1af4dba2783e309ac2285d1a03f0dcd71e9b6d8bec5a316bd4467e20522053c2b4a96513a2ad7b64015e07f3ab8bb0f573ddb4448ec774743af205ba" },
                { "nl", "029628bd11188e26d37abdeb42829284956579082412d571024f6306668098140ad697285f5c3305bfabc8a530797e963f63fa4ba5580648a751c110046a9d2f" },
                { "nn-NO", "fe32096b01db45d1edbe3fd1de74cef1337abd3ad59b765283274f1cfcc600567e48a9bdec74fdaf11c94c95df675ad57e0b9a57a2d5466bd92e084286d84dea" },
                { "oc", "0dc2d17cd2c38f367515e3779c7478d31dcb424046ec9884e59d02ccad8dac15a4aa0da68cae61a6ff659da00e059e720b4406f92a5c49b34b2e3e2b09d60b42" },
                { "pa-IN", "0c1d308cea03bbf02e41a53482e138443d12011174187adddf6e5ebddb00844b2a7ce48ee46f933d27cd0883747f3bfb66e69db2add7d26f80813f3a79fafa58" },
                { "pl", "41980b5ada2e0044bb89c4d79eae3e1193188903239fcfa17a25607ffc7a7d1f0d62f1da67f2f488b4c5bb98d93acb3f750195a5f36da92b7bce92cde6710a02" },
                { "pt-BR", "d381c232eb3411288a8f098a49f9a7808fd3eb11a738ea9b26b064c086b8ee209c681ee66df4807663235d549f3dca7c3e6d3071c619e9cad738f7fb67acda81" },
                { "pt-PT", "0cd2887e2e7ad6875136fd9b7ec330be9e340d243c56d556c1622766d707a0f3cb8d1a2e7cdd0cc77c8b9aa2a692cb83c49f808a50daf4a7193ac00285b54f3d" },
                { "rm", "83c71c0776776bc311c5fe70d2f43296bd947937d6355bd327ecc2a3bf58830e221cc6f4b487c2d8ea334b279701c3a82a4af11c2d26385ffedbc65a81864740" },
                { "ro", "d7e5fe201a7641226ab48239539954bbcf144b58284cd9489c661cbaa652a0de2cc6c7e3e2fae92cb56fe5fa38f89fc37d8534d41e914583676f7b08b1f5bc19" },
                { "ru", "0b8c3d5f4fae8cefe0bc9d60881944a745c0bb818701a7d3ef2bffef55ab9437e107e29b2aa5dfcfcde3f4ff257c8b5751a8e320e8e1c411a9c863f377452318" },
                { "sat", "ad4977a29a74cd99fab3fe307e521118c71dcd2bdb24aa76dd0f59750476b758552e93a92d33661b52ef0c9eef302833fff1bf49ec5b2f28409d83ce2324b6c2" },
                { "sc", "4dc4211ed827e38271269cda58621be3d8ba5d265beec3c2efbe7e50c52bb3fff0e6d1c1b7fd6510aa4c7df787a3c57d6a1757c29ad9e7194a2e1f48cc5d9fc0" },
                { "sco", "11b8a3e4eaa550a574049d0b034da7fa753cddd196ca489eaa31e28824833f5f4bf5428cf6bb014c2915cb3b9c7ab4e0aa9d22be5e7444717346166fe7bb333e" },
                { "si", "228503f711616831a08f9ffe671930f1fbeb55989e6a69a41a562d55852141067ec5be413becd1de1dc02d1381fa9cb3c8332bd846421e75ab258e0c7f62a769" },
                { "sk", "8fa8ffec87b846e3a26ea34c29771b09f7305d3744e2d05cc93c530edd1e4cab7bc20a57b1065879551db497f11ae7750ddea6697d8a93802cdde9048016f785" },
                { "skr", "eaf50182419ab9ce29cf5a1e88e3de1d43bd486f2e63c15c0db262f57a07c0f96329b70319bd3b130ce3e13289cc5752cda9edbbc2c64635c5828501a430759a" },
                { "sl", "7d37c45c276dc04c052d8a210c174745ddb70cd27456f61a896bd52aa9c7f84ccdc0a195cfd16d148558223be378b39edc7519d59ce3bf9a46821057b1e8f35a" },
                { "son", "6ccbbe5e0e4f6672197236f106b0f580d75b23d2e751f28f23145cb791de547a11309e0d9c29b54fe9937018f9c04e9c089d96009e1cf7b10df45b021b97e3eb" },
                { "sq", "6122ebdb53461cafc8e60961331990d1226cdfdba771801e85748c8b4b5704c1354c4d35a7c7cce8325527f9016b6bae0321541bf888788d3681036ae30dd96e" },
                { "sr", "2274e8f7c79b905b2dd9aeb6b932ad3e214e71b5e11529349cece8f3380e0b6b09d1d45cb1175acfb4ffa21ecc423e199f570c5742309adf36db62f222988720" },
                { "sv-SE", "56a6e56fd788d70a892ccf9260248c8078ff950f8aa9b2234b4452c499e991ac4201eeb3822409ac3021aff0bf36506d57db0eddf0716ccb6340f9b70568571b" },
                { "szl", "ac556a51d02527ded334bba683677a5cb2057b596779994f8125f85c126507c2eb6fb56105812fffa5f95e6e4f70b5044803c0bbd6423a77c2355d7833532953" },
                { "ta", "00109f844bb213b3432ad6febe709924b03f631070ba19dfd6ae2453aba3a785d1b07573c2ded1aa411f8e42d4f81090d11ee5a0524b8e3c0d290d23dd9ee9d3" },
                { "te", "147b8cb370f2072abfbe358197d48cc4984360e0296d37da9bd45e23169b3aa9069015ee98d5feb1acce8ce77332657c1cb7459f2eec69feb65b4f509c8b2d3c" },
                { "tg", "254ab787bef3b282815ecff70608c652f507a882db0b76165f95395d90b5bbeac7df47d03da2e18e70d7010c220111fae399f25bdead7f00c67f156d84154564" },
                { "th", "deb04b02d02b5a9c5659c83cf5bb540299e29381c7861e2257210b30a370f230e9d5a1e656023092f1134588ed2fde6d840bb292a1d9aa73e42d00cfbd734dac" },
                { "tl", "37605e10d88b7363bb0d33e50b8bfc1e5cf1b080700244a81bb12c398884696a30ca0ee9e8a9ff5a79a2d4da0e33d99b931dba1638e3bcc58452b08c31b12911" },
                { "tr", "c90471c6d1df67e6d8fade0ac057b2eb77c649dd182e17e9e0eb0ba167dc6e18a3235ff1d2ec5f5d726af9a9e9ae61e4099ab64d6c5a95978f214b5d3d0bfed4" },
                { "trs", "c5e3b189ef8b33dd0e1d5564ecdaf1eedda105d9183b9403f94af549bc69fb1faaade80b22157b52c7d34cb2b45d8ab1c75849692b30d70286151bec80287c4d" },
                { "uk", "9e4715d2496ff4aed1aeb9b11c79d8ceaede267eb0c4105eaaf84ed572b02e3e156e78675a6e6723f8cc941f9eb3b45c67a82bded358a79072569d4b05da7d3b" },
                { "ur", "085b8dc2bb769788bbc840416f5018d025df0a69937241c77a8b4509a901399b7ad9e72ab2a4106fb9545cff73a5dd7fd8f023a31fca796acbb81bcc871df513" },
                { "uz", "b963fd424102a6b1161bf08d30569dafed07b09b03c6135959ab1b29f5f063cd0e3d8df4dc9771bc521329df86b88d59c088f580306045b144faac71c4a515a3" },
                { "vi", "52ee38bcc690c9a05dc0d65949041fc62292e83f8b9d7ea98b861272e01dd45ddab8a6616012913a21ff79ee875b8e09fc2d8145aff3d1d95baea60cc3de7b5a" },
                { "xh", "c37c8d8efbe7c0323f09456f4fe8b53fbc98d58d4677cb309ab8b89ee51bb1ceba77b567c950f5c27418ffbcd3c7ef407c4d50264f744bbdd5517e8dff874211" },
                { "zh-CN", "bf63050db9f8a3caa76410313684174048b4c08aebdbb19ee6a9dd1157198cfeaeadb4fe47ec19472e931052daffa67f1809b37ca1d70f72b0aaee7e7a91e7df" },
                { "zh-TW", "bb1a8c0a438fd89cf28b5d694c2acd0bc8e458e02355d0ed849aaecc49fa8376ebac156c25452c696eea17fb67f6a88f86641989692e9687cf7df5cc53a81e42" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f5b64348cb7903a1547d056217da765783983d718ab2555054e51f58ec60aefcf5ed4ff2f1591d84fcab07563269653a0f84da854888125edab68b8d43df9a19" },
                { "af", "bce9ff0ce52cfd7df6b7a92832858f1bc32f1beca05e61f5c118771ccb009688e8185f55819e413a77dce9662ca8d785a023c5fc1b44e0d558d3ce635e9ce650" },
                { "an", "f24fc4aa2afe1e2df3c1c76aee1f01920371abe0162a75f9e623cdd3c9850c278f749cc7a5649bf5d502fa6cea150d37b75e7a5e8a42741e5f8c3e57a0e7318b" },
                { "ar", "69e096882d2ae1a76e0258970272abab46b19fdf0d96875bb9f28336c5ecf0ec31b673146c0ace8a793ce81e1f382f3fe4f8f27738b65263711142dc4c6ff82e" },
                { "ast", "129ebcb3ff0afb218cf738e4a22d70c82709ea7178671e394242c17c1e0f81fe68850fa055b160593ee592391012211d9585d0f35264b1eb4dcd87e63872ee9c" },
                { "az", "e69c6a35d7976acef588df78669d62d7cd465213b42e0d70bc8349be58f72db72e3ee6f798d50f008f17076fb5bc82331b76963c96e0ac321ac1930788c47417" },
                { "be", "2be0586d18320fa401d9495bd10d272c14c3378e3ed4f830949f21f8b60f43f90da8c20a6ac6cabd01a04fcddbb2000a371ceb4e7df68562ebff9311f7ba8c01" },
                { "bg", "965bd17add4441dfce5283bfe3bb394e42e81c5c34d982562b1066821e46d7ca46f45be68b0c9b685096936d96e2ccd3d9bf61e27c2fddc48ac13e94cd5a9e42" },
                { "bn", "e058c9a64918afe5cf368ac588d9aed04d123a7258c50a4b052752d7919ead14bc371cc97b3a93bc0cbe329b477ed026a8cd4d0dd04c15f49749ec486e414347" },
                { "br", "1bf731c9e78ae44568543462ae7e7016735aa02651ce3c2a3a38618b8f0eae9d5b02df31eb588a42dc5097471bc9b4a1d6b435146f8cd700ab7146c8aa3ea01c" },
                { "bs", "c0416c26a4aa7e03142e2ac305d7b96dbeb0cffc7e542737690ea6d82773ad4a1796637ccab60040526fd009c62a2fc1fe39e15b94b9b6accdccb16088505f05" },
                { "ca", "84a8957166152940914e805032a2a092b24ce9b9342322044ac102cbf8d60e7665ad9a1929fae1df4b8700ed0c2f2006af085f3d63fb8692abd66b4a00b496bd" },
                { "cak", "0c011b5d9badb2d0f16f8488bc45e876560dbece881a52f91e029e6a0c75b1633a43175e7c310b45abd1436e61a9ea5ba1271c17ffac06dc8ff91fb52ae05ec6" },
                { "cs", "d75b8799a239e43502c23cee4ba7b00ea17b179ceaf6783719a1ae2c12b34986a77e511173bb3d5545800cf65106cd65ff0edf13ffd043905a4ec74a687628e8" },
                { "cy", "0c1d99a910e1f2ae5c53459274962e985cb5d80d6d00dd16afd612e4f977e2107de70cb0e1a7753f970af627e4fd8ed28a795754dbc680b7bf0ed75cb4a11d9d" },
                { "da", "045a307dabb3c06a96d6692f8a31d9954c7eaaa49d4fcb47c5d02425dad8d5993766b046c72ba8355b5495f6592d2a5279dcba588720f5edf85a6a78207ec763" },
                { "de", "62c565a43c8de4bed6dc103dca651e1dc5b19e27b921b02ec70fdc57f9888106c5bd5e7512b14b3cd9a244c94691f0502e951da4cb15d36e5e814c44c7d17f7c" },
                { "dsb", "0a14980d1e0fd7a67a913283be4cb3932191a7803edd8971d17632f8811dd2dd6aaec7398d62a31ed8406e37bd97a037d3549ff7fe96c1204866aa36aef349bb" },
                { "el", "2200ad481cc58c03a223d747d2ee61817ea202e39f776e3bd4a15b7aa92a49b3a51bb117ee1555a94a44456fbca345dbd2f2c77e3d6bfbb499ff516c5a38947a" },
                { "en-CA", "751f412b07accff6a7bcc769ac7797bfed49c90d16f18682d37a71e82721f831b0dd44bd5b0c5a8e36d5f3f50b1bc9db76e3760e4d8c9fa3f0cd803bb66ad14e" },
                { "en-GB", "c2dfce75cda2ea25dd5c759a595b4d992df17e0367d4d18b3ce9f28bb99470e603b0556b4a541d09f0b3077b18766e61b7f10703574ec0bb110304b0c5603ebd" },
                { "en-US", "6c21d437affacde5a1a06d42e583911d4f06a6bd0e9e83499119db4f93f496314883adfefbece490f0540185d99f2e0ee9bff0f20bc9ff3ce025b717ca99d6a2" },
                { "eo", "e7337d772bf3f66954d85bedb5822c1fff0de95397603ddd0f03e74916621a545c1c44d48db09781f1815b88a8457b35b4091b0116d4711c67bce38724748d98" },
                { "es-AR", "fa848fd7fe679d7850335d0652c4291229e6ee2b2225cb473463b023188984b7fd9ce8211ad7f640cb375e42ed9229ddad21d60bc85099bea1f9b455eb515f4a" },
                { "es-CL", "4bd555cc1231f20b767b2774dbf547427ee029328b0ea899cc654aa5bdbe9dbc507938a2963a22460c031a950ebf87bb4fce34876d7dd35300dcb9f3cfe08977" },
                { "es-ES", "432b0780c4408163251f325355f065c5a418552c98217f7dd6d721f97220028a2bcef6a6ac6b884f8bfe5d8d054e2b80844c98e50f9db036e2c77d177ac11540" },
                { "es-MX", "a51087a8dc6f886cb48e12d7bfa8940b337144f9f95231562ff0834a07ca247bc0611c51bfeeef6f23781d8b0b3800f62a81c90fd38f65c91e6dc15d3f285e27" },
                { "et", "4453164bb474b6189c729a2608c880d649c21782ccaf3013f81a29ee7366febec07dbdc07d057413a9861b96c7a1b3790b5ef2e95d150d7d5a8031b698c5a346" },
                { "eu", "7d965c3a8a62cb4ba3672735d385ca6c3cb6d460840268fe5f97682fbb5ab818c6ad57eeec76ea9537ef93991c5f5038b49c2b0939e749edcd83620b550bc9cc" },
                { "fa", "446f2e09ebdf7d84ff176986dfcae76600bad565292ddaab074cf2b00c7c278fa0c9b226e0970e0b27b1e5dfa79244d5a94276a63a04cd9901bb18a396a1aef8" },
                { "ff", "4ad6fbe33d91d618f88d66de7fdf1edf2d6601591857b1a29610dcc03a666313dd454f22e1406dc8d9fa4c8b150f385a4c98bc1540df6f4eaf06c9c2738412a7" },
                { "fi", "09545bdaaf17a79e126a20abda3290f5430cdf1f718f006c92e1438885be9b702c29673a6c9868975f76d736fe92105dc9ae3a4840fddf66fe4693141e932cda" },
                { "fr", "2f690f92a871179e165d336fe446336ff5d76febc720ea916a1990adf7787c4dcf51d4b4b36b40caadcdafb5b8351ba83f99c04a3985af082843b154cfc77c0a" },
                { "fur", "9f9d51ad1ecfeb61f1813a2689be3fe7375097579250f4b6371dfe0432a2a20d0d19266cc6d55f629b5f7dbd640b2bbf3682bc7e223a798c72badba7afb9d4a2" },
                { "fy-NL", "c116b3b8f3027dd2926148b8d3a982c4075e2e0c813a0bfe7100cdbafe26b94059c47a15d70ea43df734a6b70d1953b4695e78c4c04e79ede7346b7f56309e2f" },
                { "ga-IE", "3e07298d1b4c6e8be784d5013686629d1a5cf5dbb02824bb82423510f72656d1d62726d01baef5a9f45e7d3a416e68c90d04849abb0fc7f353f4fcc67a570aa9" },
                { "gd", "f398514756459da3c8b98bfa1531b7a1a01ea9d44aa26baef5541e3fb381a040f695cf74dffca7c3e812e3a743b7ec4707b37b9e4f39f9e161488c3976c34fb5" },
                { "gl", "2ba46b72384c3a668111b56b53a5c5cd346f1d488a56b8304c365727d7dfed922ee4f5152f9e5c0709e01ee10ae6ffd63bc5b6974466003f9602f5f8b2c7643f" },
                { "gn", "e38b0ca0983bd85988d3e3f866174ec882e5df0890d55e226fb3c641f9bd28a9c6f4943dfed51020c34581aaf260998546d3dfdf4d7f5836b0a35ac77972117d" },
                { "gu-IN", "c708caa9885205ff8dda3f4153267018c5d3cddc75ee3ce73182ec775cac569b9a29e3007de3273da31464e9b6112b7aa5b6a08076db575f68351e348ac36550" },
                { "he", "284a00f09b4bef1694799eee41db1988d87ef98b5ef01bf1aa60cd7cccb88d307944adebad6f44faa4fb8805c713ef7ba07387c5fe75441521051a81a74e0d9f" },
                { "hi-IN", "558996c8cccd231e61e4476e44d3736a405a11c100183dc6a4810d99f65c4c2942cc47b97f3d6c7f72bc4bb01c7fb15be452e29e9a368dfeb6bbcd582c43d33f" },
                { "hr", "8ee3e6b4ee025ff33c517b8ebb64836af82b9142431a9a89758740114534730f7b9053bb16addf763dd0065abb998162a5af728cd1e0d8dbf2afd4dfe9a362d6" },
                { "hsb", "613a60420fb5bc1d4fc9eda6c86d4ed8f0f8f55b7f43755a92cd06c7379e978cbafe69fb6240832344cd7f4666c0521a72b95106519c3af6c16f1be9f7f777e2" },
                { "hu", "19dc7a1d4868d4237792b579dea0fc374d693fad68e965e32eb840026cae163e443c91328e6acb669f98ce6e3d63db72c1ebab91f28087767428e2a5de618524" },
                { "hy-AM", "524c14eb0cb0ced18018c896fd35ca00b61f318003e0abb7bbc7a4be7f56e22cd83fea9d5e5869fd9148d54c214c063265fc78bcf7795cafeb4e87c0c66e01a3" },
                { "ia", "70ad995b87d9952300d02389342a4115b23cbf2c87790f5698d939ed99834116a7ef6052403e960b485e0793bf9ae75f516e6eb13e6085ad841ea0a555f6c0eb" },
                { "id", "f8d4c8785a835bf410cb4d77790eb61606319695417fb12479077e4a38997d37343166210dd754a2cadf6b8d5282194263b9d9057d8e1e03700ee6484f312e83" },
                { "is", "458423f979d0e9d2f507741f68a4d4a75540722df415fb514ee57dcc93e1793feb1fe1be56d438d18a91ce5682cf6648e9d8eda745b3feca0631d9e385bb5a7e" },
                { "it", "ee04317bbf76d651efd564b0c0cf9b663112b5c5dcdceb0658d79426784b40081595dd09f2a356776beaffeafd7838f3c93aaf2e0eb7a40657fc9fecee16d7eb" },
                { "ja", "b4f76bcb535d9367bbf231746ea9c7a65eb9fc00652cb76e55c43092223baa78e2910773daecddee92f46abee1317c3a225e60ae605113ac52697ec8b8f06a3d" },
                { "ka", "ab5c7527a061af32c191404946b1f2b962d73a232e6119d7bd9ec7568668fbc3c2c78613543c5fd290b6b3baeba367974be47d3ea926c47f1172053140d02a0a" },
                { "kab", "c315386a41459101e68e41e7cc3b3b584d14a48312a5ecfdee581c7a02551e5b02ddd7868ae41d697c0f3423a56e26e580d7c5c0d7e9192ac0decfdd23104d52" },
                { "kk", "339b737d0cd2555ee7340d82fd5bbabdfb17de2ed0fdb7ea7bae506e817b6a0146ba0bfacf5b0cde874dff9d6c3038218bef472977ed3a21aa1c7a58fe971e5b" },
                { "km", "c866e7369b2ca59b2a9f658146a14eeb6ecf1c51bba35f9150e9bec63aa0bd4b22ae57fec3b06f4b999737690a834f99904b1c768aa129a14a275f15268a8e5a" },
                { "kn", "1c4f2eefae47424ca5313e9cb4db970bc61cefa089bc502683c2e8a395093badfa97d2cb62a87e3851be9c3c1e01cc23cb1fdc4a7aa7d7b40cd3879825461cdb" },
                { "ko", "65861b9d748123b2a98ab0997f2b9e365c1dabf0c0f103647baecab770375b0ffc0d740bb32f4d51272a3e42408d2b0156b7c3413a520c2b693d118346243e37" },
                { "lij", "7c50a8bbac3cc8c6346b4720bf9876024a93485785df60eceac296558db10066a13c8f8388e69b03df7eb23cf2fcd8f3c0160f1e49896bfc6fed184d047ddd29" },
                { "lt", "c9d1d46e697c6a00ea7be6e7b2bd00e8bb88b0de44ab76051c26ac91706922cf228c140f98c0c7f090e71142cdabadcf88e729f465530f1277efe3d39bd4b6e3" },
                { "lv", "91462a201a8c21bedf1787cb0906dec9a058410314927ad5dd5661e1678f8bc8922bfc9ac1a96f48eb7ab44222253cbeda206185fabbb0aa6dc7df8e72af7228" },
                { "mk", "427f23b77470e7e24bbaeb1221b2563f8db9d7b919236ef7ca30981252fa43581d1ea89efb5ffff6e8c824a514528e67acc6b8d7492b4e5d9f6ed6e3321cf1a5" },
                { "mr", "7151eea9862115d543c4903fe55439516af3b87ad0c098e7f667516218691bed6a9d86aef0e56ec8b97994d1834b532142698666a09d063b592b8885d63dccb0" },
                { "ms", "f0231002fd47f415b0ca95e38a2795c2768e309b421c1c1558239af566b8dcf432db7674147c50edd81923b2895203af3d847c23c90d5d36d1d2d78a47fb55aa" },
                { "my", "5418ff53e7df84152d8d63f90c625174c68cb06d197d96aa7206059a1a016217ef371de49f2570bcbf5272a50af92ba5136b6d422396bde1903770b01e925b51" },
                { "nb-NO", "fe21e6e7c805346fe7ab74ed65a6823df17b9d169dabb3267d6f5ccec985ddec3814c8f2fb62b747e86af0f717099c8b5ca31b3fc61c6e8b4dad32a794319b1f" },
                { "ne-NP", "3d946eb36320a0d44f2f9fff51e26431d7a99be71b71eb8e243c04f91b2a4838b609c74e8d8b74322b1c58f2899e50540696b63019ecf4a3422387da7632ffb5" },
                { "nl", "983cc19d3c771e0636041384064aa0e0431f398a2d8aaf80a9637e728f060e4fb86a3102da87ab69fe1aadcead69b58af6aa569b848bf9533a82800ad83534b2" },
                { "nn-NO", "2ecc3cde4281ad032e5461b759e43d9a219f55def1ef43eb46449c28a75145d7d1e670e7f388d3d8f8074f6bfd42bf419604b4946332139943fa6cbb4b3002e4" },
                { "oc", "1afe16752f5b2ce60c3991a8c401634643233032437937a6674b42459d6d99d9144ffb8318b09a922cf6cbf4009893b97efda2d9fc7d3bee6807d2e3ae337852" },
                { "pa-IN", "f0a10a0b3a10f9c1509d685ca262abe6a6e22987d5831345adf47c959ba88704f7fef55d93abc8ee38dfd01c0d1e2f72c6aa0e3a56263c46b3d0c139039955c5" },
                { "pl", "e7a05af57f62b81e139d713823c52dbfceed6af1c605415e32513048c85d01e4dd6617961882aa0152871156f8145081bcae41f8c6be469652a4dbaa36b351b0" },
                { "pt-BR", "b2569c00e68816c977c6163c3e0e236544393eb9424174241895df32f2fa21bbe18bf7f8a5969daea3989ec0d2fbe55888a145c3f048b2f0554cba5a5dba37b4" },
                { "pt-PT", "7f1fab822798fb3f909a85d9cc55d7990a9d3cc6aff6183b2e6abd1a9e19152747ddb3c373dad79a605e2bf3465fe0971265be084bb47748075e9ac97fbec519" },
                { "rm", "2fec6d2d7ac655f9f067f958f9621c3f56c7c46b6fc0e1f3d55822f3be1cf51a3a4e427c4d8494899c3d24ccf5ca1250c77fa72ca757b97e51191655e07f94d4" },
                { "ro", "1341ec7e1af071cfecc64c137001af8903a51031d009bb6e1335209feb085ae42f0a3660ad7586adc40f9fff4ee02b75c0ac8ec876fd3919f559d41f748e4f57" },
                { "ru", "5bf76e91403d6d85b4f5b32199d7d0dce7fe7525e8583cd7350036ed19e5377298e541e3b9526bd6735b48aa7c3b8f86a6c5079968eab7524d0a80929a35bfc4" },
                { "sat", "74564922c65f8b21f8b02782dc3e7a215c09f5fa397c8ff73bdb745e3fe0150f9eb00770a120dd2ea833d82bee460338db5db0c5e3c8845c66f68b7cecde729a" },
                { "sc", "f4559b846b0cc03122f096c2e0ce29c7e4f6de7f389609fe7e80c113d3e998d361c771d8f74a663c92aaf4aba0154728e8d4394d5c007f81eb71500696821429" },
                { "sco", "2b77afa1099ee8cc4676071f5858559c70ecbece3913afeab4ae46e95d39c777cf8f79ef4775065c3add245e4d405e71529170a52130cbed8b186a8f53de26ba" },
                { "si", "207d35f19d5d031719e05bb89dbe58fc205b26e09aa52c4f106a243ace2c379689f579b560e4df8c8b84c08631060a38696a6cda96c090283bf2199dd3b00d00" },
                { "sk", "733d566190806328df285b42efe87038d41c43a6850d5ba0b84aa81ac5e51941d020ddc461c8d1985a10d2a2e38efe81ef8531828489f6ff9c12126ccb6cc0b0" },
                { "skr", "6c40c772ed7009f8c7e233ae9e85f8fcc9a4243b97b69f5a8c63b68288e594571ef9d96dcfa11a092184d689e1f549c143bafa1f4b0cdebfbe7ba5f84b1d75e5" },
                { "sl", "c529a950bcd931a7fc9bae8c804d5f074b967449f1a044cfe73b5911f99331eb3edf80fd0f359be2bc82abf1e9b1a1bc62f2ff98f580231e9ad9b7449b7bf463" },
                { "son", "28fa842694e065d91034a0123b5eb2e6f43890422367dde5e54f5c16c4b6889d2fd6dd54e2a94a48a155105e35e123333211c77592c1bc8050eb75aef5ad1622" },
                { "sq", "eadb6663069cc7a53faa6537c87f08e6fc98b3cd4d6977355509887a92cf14eced8ea33f43711525b0d0ea6f1e4fd985f23d0864322c662b51283817a8f61128" },
                { "sr", "f92ff665c4ce5e9d1770d8c5fabdbddcdf628fe711983b4e4c039ce28751c043c9d53a40dee7a60ec4f728ba36c7e66fc756a071717f15c35525c060b8743441" },
                { "sv-SE", "9fa8273d759d5e28243af7783b251dc1c2b42c1444e9c70911cd2c8eb31ba121bcb545293560b4f430173048595ea8886323076edc9f27612a27179e1461985d" },
                { "szl", "2da0a5afdecd964b370bfaa34c41bc9654e6a0f86d2851def5772c089cebbd0b3cd87f6812a7463deec8568cfa6f589ffaf2ba037f5adbb46bf94e7a61fdd9c4" },
                { "ta", "77464b2700a9aaa6fc265488183d20a33a3ae8c078c8b16850bdf8a3421301f4efdbd25f58b31a001d74be011538593ca7d24a2e01a0736119ef62a889e80306" },
                { "te", "4cb000a070899e2525dfc8e9747546ebc59b4e10cb5beeec2d2b232db899bc4206b8914e53c3d40d9892b9ee02391092a9ad216562205886617ea2050bba7251" },
                { "tg", "b8324ff278948070b63d35b256cb98aa796f257f2c4d871f70d0ae4dac18ac7e1a84c2a68aa874bacb60413ff84587dceca70ad012423806fd181c5ca58f9caa" },
                { "th", "91d5527b6aa58397daaa7db81c799ddda4964a36c4da3967021332cf058a2569b332f76d9260b9c4b84ec31087339fbd2c8d2298a4af93138566fb531906bc00" },
                { "tl", "a4fb684e0dc8c137ecda9e95e05b562f6bb565c3aa6899b646939db61790b576727468886140f0bacbaf1c32016471bdc106c70b54c7977f1b48e2c90b3f40f1" },
                { "tr", "62727eba85229db036f3c3080989bd98ee5866e6ed0923127ac4763201dca9c3f97d2f7c45cc892816d040442884bf0a1b64f65b9173f8ff5160df1cd819bd3a" },
                { "trs", "09eac3413f2666dc01eb99d764ed2159468583e12a6d726f54142c2009722b6c56c3a005b810d2ac71687d5a11a1f0614f43ebcea077f04ea06975738d3049ca" },
                { "uk", "dcaa11522743525ce6827449f07f16760718750776c6189071206f93ef16fd3a8e6d1fc56339eb5acc6f1a907e81837744cc1c8fcbc1972ed46f1a3309e177cf" },
                { "ur", "16bfe78036e7a7e861406059983a1339a9035c22c69228928f24c86f2f3baf4f5135f82407d62dc33a7a913cce5af332445f55064368770f19c51c0ce13df65f" },
                { "uz", "8a162fee34574d3ca712628862c130a9a3a2bad40b2ca94c2d4a9e0c80cb3f57a81a70424ff58b97b74a0262bf6fc3df5731a5a20972f6a862dd798ff2d2f0be" },
                { "vi", "d096c8564e62edb6a0a87c294d55cd354e736a487d56f124193369d2cb6aca2b582fbfbe16fe65c8c7ee2240775c82d1013053e4e5c7eb7c584c68eb9ec55a74" },
                { "xh", "4890a30a9440669625772828ecd1158d021c8a04c79fa583b929fe2f4a1804c1842833398ca9f907577ce1e541393b5cdaa5aca3df6305f93d72fef1db6b6ede" },
                { "zh-CN", "8469120a58479ccbc08f4a09b6542bdea29039d42822717f9734e161054c623e8439ff1815d43a7c1f5b64f0212d661cdf4adbf954f88089087c056798417fdf" },
                { "zh-TW", "ecbf0771fdb8cf7baeac719f218a58f10b676f101d252cebfed6cd889a77f6d92eb1af01d29312da8c8b359c151901e23ab6c0e5cc4d0b8ae08b6f4d769af16d" }
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
