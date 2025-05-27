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
        private const string currentVersion = "140.0b1";


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
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b0202395019f948c90e4eb57981f68280ab4ba04c53d2338f118a8a89d99673812b0bdbf0a849132480c0a8c5bc9a261aef2b85a86776ab1cc1357e134e1ead7" },
                { "af", "8c2ab32b877ee12b619d6c5599d55c40a9fb891d2af496157884ba3fd2bb9a0cebeddbc56c6055cb371ccdecc4df109d8fe3a0286c6f868751e5b16f076fac15" },
                { "an", "55917636d16d0c52bfe51d5d1eb68424ec4b7d522f3657721044b9b9bd1eda5fa1cd1c6968d5c308a0b4b701df80d145c3b6a7eba93a7541bb42dd5a451a483c" },
                { "ar", "8e021586ad80e41712f8525a6f5308b5084bc8729bfdbc99b1eb06e89825e6125f44795cb21412463e023c786e62eb728aea1e204b0786e23dec50fe1b228ddb" },
                { "ast", "5eb06b8025a74e3f00432f0223fca35c9e5d6813f55eb5493daef4a626ad790da52cce86518c90c96c9d1a27006535e9769ca5a1e9551607a6a3224820630de6" },
                { "az", "1a6b77a39c4f5b0d92b78bb0fac99dc2b6b5c1e4fe9fac0970bcacab711a9fe3535de5ec6463a567f3eac193e5c537cd180131f5e88f4e35961448182ccbf67d" },
                { "be", "9274c1850f6468c7db49471b6d9ffb3406b65b434aed98f22e80758beff2269e236869e2f4f8000d94032af0c16a5f70100f686cfa5d70e05a43378009e263af" },
                { "bg", "3080ade02088cf5304685e6c833c771a11aae0cc98feed4f9f7f407b2609e086e6472e2a2386dad9e035d3125d727a77865254df92a297dead69269c61725e39" },
                { "bn", "9a5928fa8af9e5a43f77831d209453e760f47d38c2370c83bbc43b1b272dc478d5520e66983586967fe76ce1f1c89e46dd1646a520ac829be5ce828dae68471f" },
                { "br", "3195995f528c09b26c7c6312abe0003a199e1994c71d6dcd56076f0df2278e008b80701f6bc1ae0785a7527a57a93533c40433bce740db0b098f3945e60930b3" },
                { "bs", "7752baf18874cd101c4c2108912a3c1ff89fb0d13f00d7e18499d4a89ee73a65ac1dd8f59cb91f3aa101dc1c4bab2d008d139c5a156d8963d9823bd2fbc2bb03" },
                { "ca", "09971d61405910a9d42ab6370dbd4c189bf0d63ceafc632f1a925071eb6fb77708efaf3282981869489e9c287a7d10ebe9720d92184f4a3692fdf6777819c485" },
                { "cak", "523efe87f2550939a61e75fab417169e7743b1163fbdca3abde8a1e8983a6b045e8d6f9918d951d80ac01c2bf1db144a43c07d92522cee7404cc4d7a56d7ed34" },
                { "cs", "b3f6e9526b8a6a91c874d00793eb62be1c1dfcd7790f8f26e458b741c56a9449644a1d4d0473551578eb044ca6fabb15f8082198c493c14b47ba8302952e461a" },
                { "cy", "6c5cf4c204f3ff63d9fe8356e89a502f2939be1f59cd6eb7c669642ddfa29cb5eeddafa0b7b3c724871c53f7170fe71b05a07b23ff563ae9755feff1541b737e" },
                { "da", "79ca8c33003bd2952efb241d0072221604da29cca8d10de47e010fbc4cd02eac07faeddfabd92b5920ff402cd290c20c567e0610652fae3d663f98522c3e9d65" },
                { "de", "2b4f74e3f40abbd3d14410af784d0ef6303aa7e1bc3cc0236f130de7066656ad881fb516ed36b64bdf521f546c8d00b549af6e7b475ef8c21408c658c6129704" },
                { "dsb", "675e4f219c468c850f81b08628f3bad3342ea2733b273f630445f4073a01a47c50235872d0cc47f950e5a99d05e71164213f2c831000f4f0ba5659fcf8d0387b" },
                { "el", "34f8b82229d85a8ecf04b592fa3cfce03f5d10d20c7977239e1135f86cf047942b2d5b0a067320358e3370708697be3013bf77923e73e4266bf52ca56552eb1f" },
                { "en-CA", "e813f854d169c7473813892a9426ee896eee33bd4826af69b839e76835243087291891bbe137205a63e536071109b7ae1f2253ea04689be068813fa34cd76bdc" },
                { "en-GB", "8a4b107b94783ef50242d7c71beb8e7acc642217b621bd7a4a54c54e38a1ada6a419fa91942e8e9070b16567818dbd9717a12c9310bcc144f9f5f7ba45f2e6d0" },
                { "en-US", "e12e6a3c764c74a04dd8c3db77550aea377f36d0c60649231bdcb3b302dc3ffdbd43f549d75239c4ff0442e13387e63742a0315e5d854529b27c031017ef1b0f" },
                { "eo", "e083f3758d765603b0149c76f6678211e8cd4cfb9a6c99e4ae37956bbc713d9b5e2cc499bbd48100cf749267e73b94ccfd2ce1a183ba128e0c46e1565030fa1b" },
                { "es-AR", "98a7f8fb494e9a15c6e75961c68ee3684ad7f0b8fcea964e98fc8f749e08a6112d74c74a6eab921b7159f44fe262ba400196e4f83d88f28f616dd12bd61e7a8f" },
                { "es-CL", "03c1515050a1f8103c51f4c64371fe99ad4c16700c0f9e502969e0191cdfc8267862fe5a9d139a199dd58eafeb72d31de0e594a53ef255cd578d48d79811c1f8" },
                { "es-ES", "d3eda78688645f063069cdef6e3fac63b45d8ad366659d5abbeceedbb94d43bd5f499418075cbb70d780325d2e8d32cc65f1a96ea911371d898a4f28a885795e" },
                { "es-MX", "f1fd23dc318f492e64758ec22e54518c64380181fbf66d0649a10e2c7dcc4de0f920c0a93caf21c55b2357415817fd58c7973317bc54af08ac177a407bb10df1" },
                { "et", "7cad28c60d52d813b0d1d63b5b66428cd9f5cd775f8329f525560bcc4abc41b67d80720efa503615a9b619b40ba5445d00e82d78152cc659a29d47d19bc4084f" },
                { "eu", "49bd2cc6fab08ba331694a043dbc40db568dd8811c59c80f42b993da69ef4434395a9b6f8b43ba7674275a749e80e4bd4bfc3699e6f56935f928c02bc903672c" },
                { "fa", "f521bb7d51c58de67d6f20d39d806b08fd8c999a5341a95d3256dc5434690b5867c891dab3a088572df1c346f60f6771b885fa308c32bb812726c1e350dee0d1" },
                { "ff", "c4db181a18ad92de66f1bf18c61e24fc5d2a49f02eee54288c33a5117e6415882eb07d0669bfe67c03ee2e1cc9f83f3ec09589d56395212f5ae95e149ef6e589" },
                { "fi", "df68a237523e5186fb706de8d3afe1b5def230767dee11d72893fbb23bc82647df35689dfc639ea26b202f4650a2f295f887009a330a8e7ca8b3f85a0efb6df7" },
                { "fr", "8ac3bf965e5db3502ce212c2ed4d1ffd5e0e662858c922e0f31d91575a9c625f548bd8a190933497a396d67b93ddda1a99594d6d8b15bb36f09b2e9f83ce7396" },
                { "fur", "6f9db8b5fc328a75c8d90a4f1e25c3f63c243ff882a2b0eef709bdc5f01973b843583282f6d1395b42cdf49d64e523b153bb1619945fcad795cda5885a5d22aa" },
                { "fy-NL", "e50d8270443e08e651663e1f1ef5dbe3a15d6a71bed07c900aff2647d51427681c32c8fabeeec3a892b8866a98d443de060f8d4b0d68bb4feeb6d72ebe9cee26" },
                { "ga-IE", "af49a4fb20861521dd35498da3a4880bb128831b25e3627093b58cc9c0a56fb308466046541ecbc6ffd7639da99f4ab086b063ae34d9b553f90688b2119bf6ad" },
                { "gd", "a0119cc7e4cce8f099179927fc7d7c48f24bb71f785c90a182f69c9af2e162a79946e21cc767d2eef6db4017c680fd68e8d48c45209e330f9dcbc51c53ed3562" },
                { "gl", "b69a59aed8395f2a5479d58c483bbef02294c881308ab73f8c03938ba52bf92059ce6eb5731e4b722a67b58a1731d95ebb6e0b5fd1210dd84d0cb29d8c68d1f8" },
                { "gn", "c84ed1b8ffcb7fcdfc92fca28b90309387989187f9ddc36e233fcefbafa016a7c5280f749ed97e6b391f30e496f59e3903e9bd730df01c9f71e855adbf0a6ce9" },
                { "gu-IN", "f886149f5ee10c119ce069f61dbf6cb51fc3487ca12d6ce395668c2bbcb1b243d8a8de320dd97a9e398d2f9024cbdaf291d7f7551c2428e1ec875c2ac5f1b8b1" },
                { "he", "d0f63401a5feb8ce5edf29bdee68fe6bb414d7ea05202b6535a662c484c76137df9565d9cbdd94802ac22405ac735b6fcdaf9944ec19da79d806af11c94f5d8e" },
                { "hi-IN", "e910143cd9a618ddb1ecc19e09157d49bb93fd799d4519f075694ebe0ccc7620cb594e81957d057277d1bdb0a8210ef98b17c0fb82f6cfbe2e6185781a11d0ce" },
                { "hr", "8ff0fb53a952c1f255be5d94569d62e8a481148f847bf2a28a1013ce293d4c4ce1f3d34aa76710a6d69831cb92477f3c7f0be2e3cc04bac18a041e00ab7411b9" },
                { "hsb", "fe0bc4bc33a8089704dc4516184c43d075acf8cc91179c209d583303ab1fcfbd60b57fc69c268c3fda4f6d041a1dc603107562fb6085c54430e736802c818b53" },
                { "hu", "5a4ad365c9417658ac7759cf867ae61f504f53a7a85cd574cfdd1ccc2c75a10d516d2fcec9056be5ad8130d2169beaf238278f87e6f181d2269548a76ced8af1" },
                { "hy-AM", "a99312cf575293373a98f5a996003366b85c1090eddbb99c6cd361760053508980fdf14320e4e0890981a1157c9a1b087eb9d95b89d72998d161623384c86d56" },
                { "ia", "2ab245c6b75098c7f42d19f23c138946fa264f33ce67716c64772fdd6bb9c7cd1f7628a5b77bc67e1aa5b4ffd18d179d406a4dd9ad576185f0cdc05a4c397798" },
                { "id", "9301394e3495be3ace72105de6a9cd2cbf2aeb795d482f409bf575ae2c1949d984613aa8a1aa2a53362cb9dde4acea57b442428f0c4fa3527881fdde3fa8e707" },
                { "is", "0c7e13e343f8ec41bf1bc8f27561073602ebb5deb632a7a3dbd9602d6a94db04b318c1018604e63588dce18d6ffece5d7b3a80b0f52b67516d79691f87c4cb3a" },
                { "it", "2163a2fe1de6dcd7c3b690cdc59327cdaeb962f40422c631394e77eb4b42a26840bb0ed75621136e31af5d5dca88842882e0929ed22afc0275f708f22c53132d" },
                { "ja", "6ae678339050628c35808864c669f58a2e7a108477233c425c09d36e3f9b59016a24d6ce260c82be4f8e0aa28ca980f0969c0e98a0142c01ebea2bc038121edf" },
                { "ka", "87fa4a9250534ed39ffded14d8e733b5314a0ec9d4ac2ab3edf2138dbe685ae6eab39081c05fa137816faf96ba56f1fd63991d2f84fb76581402b783298b4b7b" },
                { "kab", "61507e307cb4fe07f9ce2b68f6ac0ea83da4a452172fa4a75293cba0bb3cf95a4f632fa14d3755b6eb67d0271e9a208f0dec2a6e2bd9ecde3075774cfc87b36a" },
                { "kk", "2aaf622b2806234aeb8bcee1eaee49ac5d94947b6e73e3ba27c4e55e9415f24ec0d98528c36113e8aa13a31866827709ec5a932c40e9f7d4ed7416c8ab642f0d" },
                { "km", "f17b618ca74efc61990451b4478a6cbdf1dd27dbea3ff25ddb4ad4f1b2b97e43833df05bded9f17c287bc946dcfd85133c0490970f195678f889300d603005ce" },
                { "kn", "e59f4705ed793cf2e7ca1050737f3016741fa8ebf147ee0b896f8ddc067a245d0e62f8881c6e5aeae2682f29a9d51f2673dbb2fa7dc5446788b6c4c498a12aa2" },
                { "ko", "2f9f0c0fb9f58791ad66739be40bc91c0d04dea7a51668832c2a785eb74c2549c62229c96cc800cc4bdf430bb699530170949382c84401bb2702047db60054e3" },
                { "lij", "5f6f321856cbf62e31513edd21b8d6b5bfb9c5659d333ea6333bca4f46564728c93b05a397aa91aff5239029b5134b2c3bceae5796a8a0d46dfea7ee5410f03a" },
                { "lt", "c8890219131a2ebee70ab6faf069c4a551937f456b05100ee1b1810eee71999695790df008a269745d30832d2628329f10f3637c476665e2a7d15d2b7b8e5b7c" },
                { "lv", "536b78e398de6108614ca8223d2e865d73be9be8948f2aa4638c87fab7066a1b92a78dc6ef27c124c9f0f31d84bd69d09e07630af36b7254437109c29be3f01d" },
                { "mk", "7f2f95ae276669d5a12da68889fde01eadc021e3bdc95a6b2bdd67f000ae8f71182446607800cefb9a780ee4c8a7a1cd8f972daa70b40e84a480d12c74d1189a" },
                { "mr", "47c1c51acea8cecc4bd73a4dad548163aa4e07a8968fd7a6f72210f03f11ca3e9e8d2c4b25d2a1e56c04cbf98a90a445c48f64c11404f112bafde1fb15633367" },
                { "ms", "fcddad19a59e72f41c815ffe09facad8455bef76742c70a264e00b80f88d2c542ce330fbac5e21a7b2faa52e773e00a32171cb7b92562fa948ba3c3a153c1d4e" },
                { "my", "fdd840b679b177537613d89bd6cd6fbcd9c21d6daf0a957e564f4caa4e8a087df475e090213a79a008a23a5f49fbc43dba8a9cff3e2c3b2d128a9cc91e7f6e08" },
                { "nb-NO", "24ec132014d75a50dd725a59bc037480a6c6096b723fbeab5e57d650c64abf32aa043b185d029a9f4be76f0c5be8384ebdedf0addcbfdefc7e73b8a46c265f66" },
                { "ne-NP", "8bb76851a4a16c45f5f4dd444045b59fb112bd660af478a669c48a181d365a7d11c47780eaaceae70382ca416815b00708b35468a332846585f10cecf5064df8" },
                { "nl", "28221177cf3d1f859c0f42b6d0d9bd88fc239221161e0ee36bb90d06ba24551ddbf3744da7d20b5d5b64509a4e6f4c6cd75b33e95ee2efcd5e02995521cd693f" },
                { "nn-NO", "7ba7004fa7aec3130f3865045bd68da3ec446ed9652d30f34d6d2ee52dd2b25d577e2a0ccd956d23bbc06bf08b94904cc7ef830fecd2c4c06f9a8fc1f3ad57f1" },
                { "oc", "eb1d6cfe3fe84e78426e23d57f1e2da918eb60d897ffd816dfdb7922765a7de052404e5d4e400ab628e67843f6a26729cd3ccfe28367bc810f572a8e447a27de" },
                { "pa-IN", "16cb582da5c4940175af254e443e3aa1f81abb1128c78e990fd4a140dd142bb6176e0c9aff0455c7bdc789d5c875131a84e586067c9d1f3410b71a334ffe3e7b" },
                { "pl", "e21c3aeb68b985f04b86d4d060eb02607bbe87e60f831ce6263e65b3cf517fb9b27315b09c9ad9aa1b0dd56d95022ed13cac95b4be9c058cadd8d2885fe125e6" },
                { "pt-BR", "cc3f335613df7150562c845bd76e03e54496ad05e9b25e297bc5005ed11ee616d18d7ba6097484666ffe67c72b60c14a35ec464fde0d09f144999c599c5c5ba6" },
                { "pt-PT", "bca3762dbed71f0b84eeab328577e22c25357ed7793523b7ef4e1eaca0b665660aec476ee12afee8f9e1bfa04cb40078dab72b3b9ec245a237f135d6feef3831" },
                { "rm", "a79cc4f0d4c8e6ce23fe7a4c7f882a7d75a234ff691940ea0927e554f0c2951e694146cd720ce7263ad27b0bc3f724be8574c29412326a88a3d2b02e5f1b14fb" },
                { "ro", "c816582d7b37ec1075efc4feeeae3524c3f63456c601db794f941959fde7f27100de6fd1e8a9697e8a4ca92a9e581e0df371dc5833116afbdeaf9e05f885dfb5" },
                { "ru", "4272e7e10ffd6b88d3f9c8aa576c208cd9f9db46049a9979075abbe8029bcb59e1eae17efca9b652df4f4c7b3197bed243d4d33fc044af955b33e6b26898b90d" },
                { "sat", "28ea9bcc1706508092b0fe1c4f6f8d5fa62945d32b602903b03ec0a9698ffe34ff8bea7fe62f1420d4de748066c69d23c8dfcfcbb660ab4e84d9eaca171e3e88" },
                { "sc", "0863a813fbb4e11953a0cc8bea6e64570e8be34558212508c1ee768a120a88f0f1d211d54b6a318cfc855b717735b5b9ba1145fb079c05d8c78dc95d17acbc4c" },
                { "sco", "247cffd752b7f03f6bb97926368b935b1385d959b5535135cb8ed274f1a788be67203bc32b817ef7d251c543bd6fde075d95eb464c658417a5c9d28cc4072c04" },
                { "si", "a5d6dcff171508d126d6069de4ca6fb583a2f2e40b95a0b854c3c88d2d3a6c99c689f865ffb70de676a8e04dd90393b6f246a64a0ad4b4982c20152512e6366d" },
                { "sk", "a5df8dfb7bd3d606f0a270087872816ee73ac72b1499ccb006269aef79f3499c92856e8118a1490dfb90577284a1c56b91778bd95fff41c4d75a361d085f88d9" },
                { "skr", "47d6e737defbf7e78a9a97fa09b33ef0756c2ecb566d5a91c2f127c333a9859f867b569c6c6dbbe7ef72789a3c142baaebf45c448b39536bd79dd44c7b88facc" },
                { "sl", "a09b4f5b26e09d74d1e6cb0013796422a1311bd255828ab20f2698a1ef9f609eb4af5a051e21f7f1139b3e6fe1574a020ead4e7b415944b843b63c508cafffe2" },
                { "son", "27f0fed9d2f1bebc0139ba37bca4c643666b987250e8dfc26e4f1f288ff1f9d936adb50893db2fefb0e3566f616d8a80360089e82a15fa366350858882ae2aa5" },
                { "sq", "1178d2615ca02fe74bbb65ad1be9dfd02820d21eff873eee417a33f3af4422ae2fe04755829df066f2d0e51e57ef256ac5992c2efbf7582691e1d9d2aec99587" },
                { "sr", "fa387c96ec03b88b453b2eb875ee53ed445be6e2bc09a3f0b0a52a03f19a991057bb4d91bd40d16084bb3d568158099c5a89f5d4b907a9871b4bdee2315f6ea3" },
                { "sv-SE", "3a98a5c70def1cf62050f534ed3beb956d273cc7bbbeda44c5bdc04ca0d9bfe215241a2936c439a7eaa4ae29c151c3c5e6a6c85c213fe73ebae02380e910901b" },
                { "szl", "16efe000402dc0e6f60073aacb6c561e6ffefcbab8cb2354b8838dbca7673db6e9fe540eb9daa24930029e8ab6bb8884fc7fcb7c1a845ff7d097abbf701bccf8" },
                { "ta", "8a15435ac8915302422dcc0d6aa81a43246bfb5323ecb2f39e0aa763421f748bee98686323c6ac59ce6cbf33ea11459bc5549f0f64becfad580931e2b735dd6c" },
                { "te", "f417647f849506caf3a7c473e7598a2a44c961db6eddf9b4067587c723679b3366abce41d26805cf352ed4e76aaf4d98d7721a23c9433c69202fec74e3e6d2fa" },
                { "tg", "3f68def37ee4126f9ce83761cf526287cea6197b2c84409dc92049f79299267508c4e8764c771fe4fa1e0d2a7966f04b3a657a2d2b343826c989f90aef8335c4" },
                { "th", "3581a7b4fc8ba8fedc924e0d33de25d0e0814eb6937886a18dde1e6cd7da5862c5393fe46e903ef59051576ae9ea919e5c6397c8165c0dc2729a53906d19d1af" },
                { "tl", "07ab5858b3f1ebf11c89d802a1881469275c3691984ba773a7b993b0f8cdada1f440172c7048c9b5dca5c902a8cab7fee7ad835369a7bf224b507ee0f898703a" },
                { "tr", "76588d10bd90dfb6d9f8f80558518e93187fde83cb3f525356106c85f97caa2d04b11333f1623d12f0b0a7f7220053fe9ff5e840953e7b28a2ee167e39c36d61" },
                { "trs", "625f70ae39e75500f535637adffa8b253444ccd6b7b2c40578686f12ebb2e5927d57395ad2d077821af8327f9be9bc1006ab4b2bb9ab20c510981cfd0d8f9367" },
                { "uk", "31ca953aefaf68f50263aba5230233a384ef6de2331a9408043f490b50d59a1ca387003daab91c8e37b61a86d8ce38e74205d45c326d7c602b2cef6e9f6a54ad" },
                { "ur", "bc0cd98648177c08617eba9fa87316168a33d7d7f51998d9de39d9aeab102590fdfc07b709b1e887cf2a45dcd7b746079a79ffdaec588ad416b183f0a1ebe941" },
                { "uz", "889a4ee84f0e6e4776760b0dbda7e3efbdfc0adacd407f3f63f3adb626ffa45c8ec871096624867ee9a687f549ebb896dee6f7c3fee2679c9888e79d7ad04bc7" },
                { "vi", "81417638677c017f4ee20001246b2ff648eaef870a122cfd8377a1183f096163400c1d8d9b251b95f1166df25f4f97457fd2f96ea052729e704f9c21701c149d" },
                { "xh", "788c72684dc0781e749c946f87e1031d056e4f9940558282da09ee0574de7aee6b2b57cf85a7770a2fc1b8b5ab3be263dfc85a67bdfaaa1b2742893b48a2e081" },
                { "zh-CN", "19998529d28d31bc90a885a941beb3f631ccbe9105c770f1d1dc3f539d2a2aa791771e5bf81d47703f9f8371ad0f0875afa4a6faaff9650d54e040429725eaff" },
                { "zh-TW", "deaa6251c9fc667916b1367a1117b7a728335a577742da0d36a523cbbe4f3e69884519f057d1760714b50668257663ca95efdbe8d3279d555019b5d44f7e6cbb" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "bf93d2da35337d8caaa5b5c053ea87484c9eb385a262207588af064f9ebdf0c3a0e090b63a8851727c8fed7dbfb45eb359b9b48a4608d5173b2b3fce0a57d5e0" },
                { "af", "a81c92b9353f81e61a0517aff627798c9e6bac7852554b4cd893a5a21aefe1fcca99cf9254ef636f83cff2c6c63fe2a86e10615c60489015e991172764cbe4cf" },
                { "an", "150a6610bc88ea9569054e52e8221e1110e559a3d4524e63bb97ef98b618ef8c55dc6c55a3caa86e7a4c77475ce397be3a023b5460ff690f48bcb149d37dd61a" },
                { "ar", "e8df34f462065f90925336d1f1c8c6abc133a3e21d3c8da398618db7bc68696016db9ae723cf3d7be6a594b8f162e6ed8d19308d08394f21a5f26e301f86250b" },
                { "ast", "6e346ebdac6e5f8ba7c1d1e4d27652e4257715efa99819d78db44b39326a91ca9830e91ca1d98b41c3fd77e4075e5c2653cbbedabd0d80bb41e21dd1e2fa4d55" },
                { "az", "8d1e5a72c81776bf0d1c1b8495b75f80988a63a26d371af5fd9fe06c78f526cd74406f5e1523252aef1d45c5ee2ac4c024ec51c410f680f35f78767d770f9ef4" },
                { "be", "72dbee16a96b76ef912f04175f89902be2f0bc052e39d4aeac2e41521fbd1fcf6bbd7d24f04e36cd65cbca84d7687d112c17bcceade00e2be77e31ec40f9223b" },
                { "bg", "2052164f84ed375292f8ac3fb11bfc8fc152c985f5a40085d9bcb26bdc96edd385350051681f0a840af112c4d624cfa373cadb844f2ac61527b80a85a515e665" },
                { "bn", "bbb623c3724d1191a3cc7b565bbc78497ab8d1e62f9c436885df993269fa69677b03a95e981ba0c4b6b7644c2b5d30708db57e7c60bde7e0aa67c58255967bac" },
                { "br", "523e7e35113b8fd69962d5afd63add427f306fbc0de306211d7a893636764bb3081bbb7fae43b0351ca46fa9adb4f25dc35f181485675bd3be4a3a22c36b2b69" },
                { "bs", "9e9a1f6711406df5afe1c70ec0aedffddc3ff533c44c28d526833f25140385f52d498aed96b34d14242389b88e1ec7db2d5ec59a3341f598879b4f86eb02672e" },
                { "ca", "56028fb0d1db1b7da4c70c3437644d37098b6c15b26acaee780f01264a2fafad10af6d93a2c184e39740dab9ae0662b48fafdd82985a1cb1ea5d4d2bcc87cd75" },
                { "cak", "b53dc4eebf980341493cab0da68bf15b2aafbecc0d39d9c5a488d024df45e4f2c9931dd941796f132682b7778bb5799b319e668566c3972f1a3b7501c9267ff3" },
                { "cs", "06b9e30e73d360462e20c88983e14a0454e584570f64297f4abf94869d7a2485c2156a9d0ef93e05eacdcb92796acbeb6614132ffa91297842eaf36eafc4841a" },
                { "cy", "36fa9c0d0aff6b582b8da554b951c88523c3abc8aa9cd51e8b7492ee665311b09dfa326d7e26d535472f5b4f4a35846c7d5dfd952970f5568ac64742fb0f5ae1" },
                { "da", "2df38e95a0adb8c93c43434823c5199bf4d17cb1dc8b10fb3bc67a4a2e4fc27405664e1fa7a74f9d7abc308e64ea45f0c670714a37a1bfaec4287996d61ffedc" },
                { "de", "a5a4e2b0dd36b439249a176d7a4fa6919f4d7d367512e290a215876399a6590a5eaf50a600ee5cc4396b3704cfdc32fab525f0ccf78009ec46b6fd8fa696111b" },
                { "dsb", "ff3db04fc5a4442d665e2570229d2e9e46cd1fb0fa0d29c47c13650695888bb293a9c46e1bfec5932c003f2f41e88f47e3dd4b0c01b4c09f2acf934f95f4c165" },
                { "el", "c067c4aa4cf53f87495e90089b00a792e7bf0ef5699ee7861fb94632ee6f0327b216e26c2185f3f1b7e0e5c3c5f4e4685257c8962d413c0948ab4562509c64c2" },
                { "en-CA", "68d5985c0d9c2c6f97fe64e8ebc43ba4fcc0da5c4698c48396583c74b85fdafa636663b71813eda824e01745b04fe78d5b725c4e0aaaab896ec30649923c204e" },
                { "en-GB", "40602361d95d529b31100ec43129001c96c56dde2c74cfb2b3a2340f433479861da79a58133c45e25d49c9c36ea6d855fbe7fa54369eb89114532fe79be504e8" },
                { "en-US", "d3a3e7bfae8914dbb1af3eec80072e40e7a0ea40d4014f65c0c2cdc6948ef0606c2324d76e2778f0841132ff85511ecd59b025edad5e3beac7c872ee98c57e9e" },
                { "eo", "058e300b6bf2fb04e2f463c703da8c5e409728553ef915209fc18ea0f9578ab23452b261c9d25c561b82f745db9a2b66b7f4be907f1af7304cc46bf4f0b0cc17" },
                { "es-AR", "2cbd81d531d9c7fea52b614ccb37c3f5b03d09fca20fa9e536cff1cb87db4a0a979460d023bca8386bf5cc31b0fa5f2bd127ee55dc0e4fa056eeac2f963616cd" },
                { "es-CL", "a3e494f68dca84455e3dc181d8da33cc0eabfdb7e5278a05764c514e66393f36e2bb4e55f40c1b5f2e83f91c8dba21744ef51e221a1b850b551f2e0df4ba6e4b" },
                { "es-ES", "62c6de8926d36c1227a206a1257999f91108ebe7536c5bb1b7f24833a3bd032aa52637034abb918cf3c309a6920acd4e78a001c0c1ebade86d52b963a57be9e1" },
                { "es-MX", "b519cddf6ef778a2f49a0ee606859ebda218a6f274d6d147bf38aa8df044ed45ea3cb6ef6eb13aaaf9581df2d209cf4d59179ed53c17685e54ed808c9abd2e2b" },
                { "et", "b79d44f8bda28c71b9ce76711fa7be3420defe72fdeafcb789e8e88baaa31b8d431da001b93b579f4f9156e606855171cb1b000658e0e246d53451c59038f4b9" },
                { "eu", "78b338587c7290525b831300f45b29100e766d08f2b746e7ccaeadf6f66d3383bc98b106c9edf4d294ef6bda02829cff862d9602d3490aadca5add9cb25d19ec" },
                { "fa", "7c2346dfb0ba8c7aa135d1e980ebf9334c214cb1f40e29b29dd66e8535684f93ffe432dd079cabcd4e17688a3b0837520bc59f287cb07f0f9df2467c7e993f6a" },
                { "ff", "bd14927b053696abb07b28352cc91ae15f4c622de40da10d94011c247418d6d6a9e428c08ecc540d6bd6d582dc647b0b20d88c2f60c3984b2e83b3e9b45b2d4e" },
                { "fi", "63421e896ddf82e52e1b4ac2a14e980fd552270aa8931a58c00dbec0dc2976e97f2f882b2dc29126486dcd361ade9e14698b2e0fc17ae09ca3a6f68cbf535fd2" },
                { "fr", "e2d56877d0fec453c704db9250a3941ff942c0ce795295f31d1801b6026e04c2dba1f960a4d8644c7f6e342fbb72e55fdc30522b7878132f82cbedd7c6d94732" },
                { "fur", "f2fc3b68d858858f9d4b0d93e60db55af0634e67881d0d48e9184f09881a21f9ab06155ca400df1ac8aa6c9c3010663879f4df2a7296e9a18bb72b23279efb57" },
                { "fy-NL", "628c892e006e771ca776548343e7e3efce5f8fc11eb783a1c99f471acd09185f9a8903f477cf4c7100638411402231b7a16fc72717799403b1ca7991d6b21e1f" },
                { "ga-IE", "5bc9da34e0c6b0f92f1191bf9a7c001a1d4ed559cae06c95633bfd43dc209bebc29f7ebedbedab53f44b5466ec96ead98410fbd5e3f37988f9519cf2a02593c7" },
                { "gd", "1c9dd6b24e9b31ef34950d85416ce9ce70868dab10fccf4fbbd851f5e2bebac8ad606fcc7bd1e0f52cbf376fed313a1e91ba0477a9b0868a8f702a1734c79b59" },
                { "gl", "29cf33bddfd03758e250627368e6810b158a015b40fa6b9d4ab4e7bf979a3fcc0fee2a52a10b2a33cc45071d043ad348a038b0abae1fb5019769895bcd8e74d7" },
                { "gn", "f1353771118bbfb3ef0e003e1ee25bebc4f422a80870e1615aec2dcac93edf694c0dc8c50c960bb08d95a2b8b093e5ae960754087588a72ea3de24aba1f64238" },
                { "gu-IN", "f7af9f0c4adbee8241d88e305e1fe1320cafe8d60b58daf9dc763c284144080f8d1bdb2a7a48dfaf1a42b53d0ce49eef4be272262583486fbdc886139178db8c" },
                { "he", "e677816cbe5f6501f7a016c7b03ae57e9cff89ac6b912cbc572b2950ad7441ad9117315bbe1cba640d87c21053d47adccd6f060d9a49138bdafb6d764687e7ac" },
                { "hi-IN", "5f2361b7cf815771b42d1275c1ff2230e9f56cb1ec23bb292e6ec4f6e483e5110b66f3c23be93433eed2eb6106cf4954c6bbf6c0de0b47b0a8da91b40cf70f99" },
                { "hr", "cb883a2a34104f0a6fb534099d20c13466aa1443d457a0042bce0cebd0c552df0de3082c4710a40b73efa172c912d0d3b027c9265b26b07ee26ab32378982359" },
                { "hsb", "26a95ee284ff2ca65e072fd75fa2ef892dedcfbe790e092609f2b6b93bfcdec8bd75bbc69cd380af0c056cc13c2a01e09ba34761190b0cf5260de500d0074d0d" },
                { "hu", "c264bf65947ed9cf78a6184228cdae9c125ace454efe55a6a68f5ba78fc58cf5c84abe99aecf836a734cf0c6261cc8d6ee9af0ac59a4f07bab217f369d80e44b" },
                { "hy-AM", "f616fc00fe201dc2b586ca571812d1802c4eeb0b6c37ac2128f2859363af37a40b5571fc7f7748248df11282ad67e148d2f0ebd8d6e24444ba03576015433e3e" },
                { "ia", "bf6ce00667555e96507a044021e0e7ec812db7118cda97988b17b52c34aea7890faa53da520a9df6009e1dc460955b7d0767ea92be827fa1974da86a6aa950e2" },
                { "id", "34ce6af515a1ba9c98c04ca53c0c791fc5e01c3aaac98dd4035c33a316c980760e0e75cc05c6ec5fff186a4270903c78cb5f17d780bc4beb3133f6245fc3bc40" },
                { "is", "6fe52239c9cce89dfc38a364f62ae13f8c5a8d3c4ba96fed09f74527b074cfdda796d7a2372ed68f4a947b026a2752cfd6e04061a5b79fe0030cf81b84a85d13" },
                { "it", "df0a0dc9a65917082b71b28a77d247d2216583c9544f543d0f5df0c7b6b0a6102b46ebd9438c4b1c20ba2b1139a36490eb350259b871ffbf65da620599955a32" },
                { "ja", "d1da207e75a7250abf7c9199b39c88ff954ea28ad69f15fef0dc8e9c282fd3168bad5b836965c1fc437d3bbcc5e87f58f7d05beed45a7799cfed7a2bf4fa9ed5" },
                { "ka", "4ef797c08ab22ef6f035820fb2c823aba067088622f2b713c2091bc2267ca98026b53c2a0de77f101555e58cd11a1d1379ebea8c959efd03069d2a87654449db" },
                { "kab", "c49c0619c8376b8ff0191eeb08e98db7597d22496f531dc5acbe31c929491c109ac6bb36d60d3a14fab2569c4240fc83540d3fbcabc33b0d315bce9f07bacf27" },
                { "kk", "31b0ef78dc3e087a0fbc2cc6721c3e4b2c12ccb3fd68c0cfacee471d1252097cc07f2cbe4af72ef3f8d9bd0e0fe1af1cec2fbdf5303a02ed653dff9ac96240b4" },
                { "km", "8433aaa27fdba341c79413646c602642d4c229c257b2b15aebe17b8c84f0820ae165406d068f37fd11ea975ca7fd956e2ba31d43074aaa51bd471040959d1c60" },
                { "kn", "f4ca19c768491fc2b661d7a07f4fa86dd63780918be5828c31f18add6f99f54e140c9818da21064ffc0f3d2f144290cd750e2af1b2918802cf5543f8b5764168" },
                { "ko", "ef42e8ec898f719d3d8f952697173d1a3a9a412450dae0109b6c62b51cba2165a88fa3e268af2238e4a6b450b19b7ee9324cae4113452a687e3e5ced3962e0d9" },
                { "lij", "1690a5db253eb124ed1f92c8f6ed528cf940f3d13dfe57ada536d3f647759edd28a8e59c751d0a56fcce3c8046e7c2ea7b5331a6827dce8bc9452799983a07a1" },
                { "lt", "4bc49ab82cca4f2dbdabba23c0762883124946c38ed8c244c4c669ba0c316cc77c82fd82bf8cc96f557db6e564f64d330c9cc570b5e54504d30e98c0f0a639eb" },
                { "lv", "bf60228e91f7a9de63dd1d57901e5f3aae0686a96b3b857c528299d4a39fd7825a8b8de9e7c03e5eec4fcf0c0ea2bcfa1d70bf37f429421d9c6e14b08c7cda2d" },
                { "mk", "81c00a9ed4e1201af943dec8977d92f5d10fa4088aaf38f23eb4004b36f7f5f330e722466561510c90babe0aa2b6a6f1ecaed532f5b6793714dc81082581982e" },
                { "mr", "9830c117e7c3bd1d3c6c785e45e23bf9d380633f7f0afdf95c57effa894fb7f15cbb2271fc645b5f0faab37ec9388da7387ad18ba236b6894e44c2c8bf611a8b" },
                { "ms", "c9e64572749bb7e4f798080e52ae09f7417925b3e0c07c04f85d6b82bc829697a68b86b9e103c6a72b4ad8342d4c6168f1600c46175fe8cc590b8cf084650da7" },
                { "my", "717ca223eb5d9b922758e9b54b8c6cee6a48dfe0090bd1af13bfc12f6e4245b1238fd9c98532b81eb195f96a4180c0e2952ca0ec89f14b8b3432e9bc70f36885" },
                { "nb-NO", "4b0380d0b8a1c761dab12b5719ad4df8f9b7a5d9def3072661dd4bd2e3b855c662de3a7bd4d9f7693fcaf7dd3ade72382f186d9869608b9edd708bf44eeaad7f" },
                { "ne-NP", "14820f2c62d440593edd3996809ea77fcda16945dd1889bc7332ed7fdd0577a6458543d9eb230fa0163bae2311c4d62b5e0e8eb7aa1b795d95d7780b3bee0def" },
                { "nl", "f17984b8e4f59d2ecf078da0c3da70825e2d95a1b9ade5450076fa8d5c85ca30503b011558deedc52bc9e41aa34cc7e08c9883b18fa31bd56b4226202be59e2e" },
                { "nn-NO", "db05157de64f3f2c55eac89d3252aa63b8e058dcc187fe96c512582003977a8ecb398a48f5c7c85875bde78da1f8bdb02b2c4ddf8e84f7f16bf47ef151b8490e" },
                { "oc", "9571d6640f5f1f0a23d4eff4c91c28b4319cd2fce38a19b236f19a26f7b6ef84227ad30988e2a8bb98e5475e867886ac0b6f418d6957157de16428e917a0bc44" },
                { "pa-IN", "f50527cd093e6e9a8d4a7fa6ebc4b73eea194025bb3963d84aec19b78fdcf674cfb359b49593684126c526dd5ea11646b65aeed87fa4def0c5b8b4d7a0fc6190" },
                { "pl", "7f42aed520ef4665e1d4759a8064f25806482cfd1e166bd0bfe6d44970f7ea5f849ecd88b3d594a676ff32924069dcf70316dd8cf34e652e9adaf18f8d50ba95" },
                { "pt-BR", "bd80fa95d394b6044c0a4192aa8e5efadf837cc90c04c6290a84afe07dcba1a7e460f5f6b9aa79b3c8b36ea198d8dd23c797c3ef820db64abf8f5bf534c339bb" },
                { "pt-PT", "d07031b4621d80a26b2c9569da97bf830c5304a1505ed25003f650a2e83895f2e0bd42146a5bbe7f7d9ee2ebbba68b320f8b256a157a20a7fea66d1725aecc60" },
                { "rm", "095a448db1b3a9420b69db62c0ebea04cd35e7c4aa924fa4ee73ce2a5026690c5ca1272d1957738ff75a11935b8cac27e8b974ad02002f07d715a3b454021f31" },
                { "ro", "2ef0c29e745d0b875d5d5df24a3fa18653cabec554665461f69ea2ff35ea089d39224d4109daaa7919fc65c6b28d09a224e5fab58eb51cc855adc6df325012d4" },
                { "ru", "de8b39086261d135434cd039a3c1c9be93f6a2db353431b3132d330677ff0449eb33c352415b08eb6aa3f42cb32ecf524472cd46049f9226fd3cc866a9020c7e" },
                { "sat", "d287e70c1ea1a3e4cbffc5c83e9b90f132833e870ed25d0426b3f65f3a1881fb09c10356b23b7abf6691bb8137714ae90bac932dc5b344bb5eb397639c05aeb4" },
                { "sc", "1476f8f4525c926a126cb5e1e99c37ce01d77dc4258a764af73648ade080500020ae6ebd61cc0cbbb8bed32443e5ea56b2d1ea42c0546be6597f5aa15f45ba4f" },
                { "sco", "5f6b5acca110527d323a75464a5a5ddb8658b8224a5662b493bbbc4ae4de225be391cffecdbaceb948c3edc0ceeb688960e3254eee18e37eac4c4adf6b72de17" },
                { "si", "17547c194d9a6a5fec75883f9e0284453bf4ed2ecd985c3a441a2cf21fabd6296fcfb871f611e30efa17ad764719625a3213608c376aae6934925326886bb1bc" },
                { "sk", "65169b9592c8e3ad2d6430546e8fa81716e874aec83320bf7873f3654bcad1b7b1f6da588d873ce21554e8023a6e7d8ad47d766be95d7eebb8b2817d226e3bd6" },
                { "skr", "312177b3df2a495bed5eda94d513e75d4cbbfa1a85746e00512f6b7702ff9aeee5dadad78a828d47f5d3dc17a94c06968b3d9a2f828c2998d1eb32afa842d0a8" },
                { "sl", "3656ba1e939564a028f86e4a027929f9cab4c7c03cd2466926de9c02b84ced15f777f0843627057ac596ef0c3880a3218c9e46baa3a0d637d44b3d43387c81c7" },
                { "son", "5c28ef99b78cf639a6b3279b591808c3fe5b8eed20124747476e66863a90f3ec28cf759e57e92ae82cef2b43642f0f92a817d06e0b3c73a83bd08afb94ba6f52" },
                { "sq", "1a757340e0a906499d6d2b9793fb9d878ece04c9dbe10eb55f021af0a82b64eafdc8347bfab79b24076ac2e566e392a2fa2cfc25795446e94c09de9406a0b4a2" },
                { "sr", "dafa233000e5cfcd326a6ee7dfea2c471f824be2f10d7de8e0416b75b47b144666cd48319ca4826d0e8b463aa1d5e67cce7219f18a295e819132059204e3744f" },
                { "sv-SE", "9e16744f71d72377f8e048f45e01f9d834554b98020122d32d33df06db91062a0f40a207eb6f09c6f0c8d772d90b5e66074bfd0d4ffc68bcc0012794ace5644c" },
                { "szl", "84d1007c70460282c90c0ed34cb8616584e9a247fe7964913368685662be127fc3e270fed0840d698807431c8f464a2d1b74e6b87b169300811a640db8b9fd42" },
                { "ta", "c8b18a4a95fbd39bd5841b946b78cca104268afd2abf1afaa13414b0fcb50ebab1f1e3e5742bdb6e2b0db5eef9b5d6b8c40832d509f919badf18bf3f12461bb0" },
                { "te", "ccd7201ad345d85d376d54bd473dabbc5d67cef5065515a184145a1130a50112bd19835ef361f3ee6033731ec40d6ed192e32e00058e11318f7bcc1b75a904e7" },
                { "tg", "44e180691e55627bc01e8698b0392c06fbb9c1ed666c714000b0ccd5078e11d90284e0ef621aa26d69aee902c1a01f592b56294b051b9c4ec14aa4d5c369f09a" },
                { "th", "b48af04929a2461c6f1acb1d9f96e76b49824d4e55314a2ca6f4b6c9ab721c4b33a232e5664dd0ce70aa3653ada1fd69f51f94d8707f6d3c1036f686408a621a" },
                { "tl", "a8ea9088ca81d33ae67c340b474e09012ccaea354c5e43d2291dbbf859a431dfac0afaa88e691b7a18ed30e286f829c12eb90eef60fa5cd3b66e727dd810eba3" },
                { "tr", "e20b44f9831019dcde23ea5beb5a2e5788def0ae20f2da2ce2bc4149925d04f078c02026ef6f802a1473409380546cd8e67077132e0f79e86a121eeb45c414c4" },
                { "trs", "e3afb3e11012c426a39b9025ff112aa18924678aa2a95990ced7347ed8cafb568b25bbc218d8bc814c37cb793e0b8de15f6cf4bb4ba395acb44e600246810792" },
                { "uk", "833a794a155e9094afec5b7d2b845df9b72829b2e62859acd0b309e98f23f47b74e7456956c3ac21276e9c95e7863815ba6d01db876361e0c3dd9de0964cf4f4" },
                { "ur", "1c1d1339f3b576ee2cb37734c0de7955215d7a6b438438cdfaaeefb8e4499fc89d8a290dfd6ba2aca2d1db2f2ab93cf6a576fdb6b415aa382be9de074cc34710" },
                { "uz", "f7b5669dfea5fecd58004d47c2e3fd5e389b47749d7f08518129a47c178c10fa58cf8494d69a71c04aeaa4923b6b2e04e0a7cadecfa20f1783715c407af2e93e" },
                { "vi", "00115d367cefd0aadbd570e102a294c3b921db211ddcff9daa6254000bc1110c8be3605b9d70d8bdc753e9932866f9bf02677843c3d065fb08629a2ffd7d04dc" },
                { "xh", "4e23a6faf8d4358d2171ecdc786399344339dd543838c4f1986c80fb7aec7e973e1f7091bf59f2137fe52f048d0051193fa48de018d53e0a09e29662a115957b" },
                { "zh-CN", "d9d45d95caecde90d3ffbe1f41d846130e94f72ab608cec7707ee4a28720eb620d6aa410b6cd7c32e4e70d54982ce45978e583860ea59aedb7edeb6355e790f1" },
                { "zh-TW", "d6b7b5057a0809dbf5016e9eb42e44f1f8167b309e568a3c1efa66488246b6481ec5bfe1f2af73193c7cc17f12c8ced0084fa7d0b25477ab85b78959cfd6837e" }
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
