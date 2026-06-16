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
        private const string knownVersion = "140.12.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "810382aeb606ab7024d79a6e76757994b3e926a7eb2654dea897f4b46af4d9fba7d88901210733c00c2b0acbb67122c51ec06fd0132d5777a8223b6e76d2681c" },
                { "ar", "4efd72419210032c1b4494aa1210e85a57797db43e855290cbbfb3b55c8e5d9d975f04d99e21ca4a8156be00d07a58cbe75e4bcbb053fee2546cdd997a9879b9" },
                { "ast", "cf1d1c13ffa42848ebbebbedb4741e9a90bc2ff610db41b889a73392894bc59023c57c7c6b2ab5ec18dfa7c0b537cefe1a2eebf9865966ac0c519f306ec94eda" },
                { "be", "8b90b86e0dbf610e6808da613065e32f275e4f9062d41ac799e974423c65031b5c3eb55725f0d8ad0d86f6fe601c4c7911aadf9b897c4bd9fee4ee150ec7d27e" },
                { "bg", "92a8b2fd74b68e872665a1596fdb424c2ebd5e2cac5312e041b145467e53a932f38658f4012e51f55563ae8359a667be3b3e9569da1bfd22833fd3c46e2db28b" },
                { "br", "9f1c6d29a6a78182bbfbf4e1f3a61567f4c0e4f977823f2af3429d2845ca7e96744ee59633ae653d5a0aac83a7e8411165dce8afc87ea44908ac67734dcb8292" },
                { "ca", "907c0de1c931ba3d8fb3c2b5f81b66059a8dc0d9369cc2b471c96a054cecf8696993d43ea9902e7db79559eddf943a5060bc0dbfe3303149bcd41d7569b60a7d" },
                { "cak", "6c1b0bdf4109927f9fd5c39023b6ea3846723efad1d95ffa6eac5ce510c199ad59ec86307a24a1a8376b96c137d83156917117022a0cf70625dacf1444a4956b" },
                { "cs", "ffee69bb02d62ab4dc96b48468c017ff0c07f130a9ce2dbbe4876dface510057db3bf6e25cf7c3c723355fc35065ebc38960cd4d970b0abd33c8d34071ab3595" },
                { "cy", "9b6ea1a33ffcfcbef74d6b97e5900ec80e80d84d745b256de69d5875ca79c9bb5efce6e051dc13543b0a4d9fab73bd5c7b4936fd560af594777d9af902fd3af4" },
                { "da", "f778f06a9ef01855de551bb0183102268ee143ecd8b73996a5105b0d36b28e09355b6f07958cf6f80dd86cb00a1c9230e4ecfb527d2a6b621b26f9600c0873d5" },
                { "de", "e6e8508ff8834fadbbb9eee7d5782fb27b5afb83340c87bfeddb56996affac194a8abee45a80629bc295aac122094fa8dbb5a9e887a820f89ae88ec9a447ddd5" },
                { "dsb", "73933fa3c5c26a3308a5ffd18c5f58065e35b608576e6fb7220813ee8563dd54fad281d0c15a255e66a9a26833ca015bba555890b80ef9615aa52bdf679a8a0c" },
                { "el", "289d0dc07a288dcea9a2717c7512d2dc7c1e275fbb4bdb519fa46bbe22ec3b291d5f72228197c299a66f6268f5f978e8b9dd9cc0ddfb6aecae049d1937a87370" },
                { "en-CA", "1c63bceee071dd1683601bb2aac7a08851c7f150b6acc5f5d1888919a4595b1a35499928d8e1fe384db15182b453b245423dfed079c8d24942ac1ff847b52e47" },
                { "en-GB", "6ccd6f9b233e6d09361760d90272c51c8dd9e321b56155fc5082d330d02c0aeac4c0be68e1f97f016bcc34057abcf07a2185d8b1bec7912f7b0c20803adc15d8" },
                { "en-US", "71259f9046468e309922b09fa9fe2a45f286d523d3fd41bc3fb73f1a0052961b0445728947bad49ea5ec8d7c5c1dddea3a9d7cef3de23dac6b3f036f8b1f727b" },
                { "es-AR", "614ef9a57d604c312dc5d233255f7f374c9e163abe5bbd4eada51760103d8cd68946ff1d6bc9b700c680c689f78e21a8073910e425cad7d44706aa2e941842a3" },
                { "es-ES", "a8990faa989a9967439e6cd624fdd0dff6ad7ee65e79c60fed41bc360723d0331af3f75c5e960f9114008f5cb277b03ff1228f62444b9576abec5600e802e1ed" },
                { "es-MX", "0b61faaf206e9586a211129f992707d8e84feb7a9c2624b2240159312f68ca0ba08172315f9b0fa59df4f5593fea230e1cccc90110ad7ee382b04eb30438b0a8" },
                { "et", "390ea826f822fbba5b02cf1a35156d8784702f72d64f5f521340e44705b4cb788e81e1464dead40bd2c0a0aea1496fda146fb02d07dc943546eab3bad266cd8e" },
                { "eu", "711f08aa4607efdbeb2e4b7140acd91f324d9357f9de4f73033b0411c673c72c1e5310c09dea6855b883d31877fe6c52236f9e63360f88d024b3d2b13ffc1f69" },
                { "fi", "0247e7a1662a4a9fd551ba06f4d82c63c92c513fcfbcc58ad5d3237a5b518df93e72f246fbca6c05527d2ed9f8a85997c2ab40cc813a04eb67f5f5dcaba10500" },
                { "fr", "785c1e80cbe2ee65dc6900d6093250456f24e67c6cbfb115f6c42a392b8923023d5b15c656b464097879267880247beb113f474e1f077d58488c088339a9a312" },
                { "fy-NL", "01b62ed486e9d88f3e716cc67b5f9b1f10024faabe82a29d357a338b463597e31695651c16552f732e44db2d229a12c28be302f98999a592332af7398640f143" },
                { "ga-IE", "429d0e5b2c6a8088d7866f9818a50ce75ac378ef609ad57504509958e1e8c81e49f264e5b2a9a033df32c9015b1ebcd710742f961ddc4e15b0a517614b65d6bc" },
                { "gd", "ae14fed82270f19216b212131aae16be10df0cb12eeae21c6617b940c5696f031db3fff2c2269be25f9bb3aa32d371bd03633fb0bdeafcaa3c44eac421610ffe" },
                { "gl", "14ede3039e7a9fe8869d1202a10c8a8a4ab03ba38fa533ed0b148922ba5a9f620d7eba18e83321dc053f84daae73a3a7e1ec5af948983fb93ab49f7ef98162e4" },
                { "he", "9033e1549737077d803f12f96cb8fac8c8f3595ed3a389af5a21b17008728898946c1df6af5d094c2b9c10be4993473fdd6a3cdbebf767a2ecb57a984a2eb312" },
                { "hr", "b0f8c70a6c1b60da5a99da3df28a2bef5e49ef004a79783bb1ca7456694fdb5b5d7d5094c9dc5bdd2f8ee4cf9a6a2a7a11443c26067241fed319df3e0d11a632" },
                { "hsb", "b5300e124e8893e6e5aec32400d1b45a40d7c7e2082dd30d2889d84143a7f46f2322215618923be594952d84c56abc350e353779158adc3a6b59dd0feb9f6d38" },
                { "hu", "dd1eb311a73a855627475705dceecfcd44a5564831c35afc52408a88eeb858235231124edecd1d3c83e72b0b563b605008174ef8f910f71b64ba7afa9a18b4e8" },
                { "hy-AM", "7fc1aa9cbfe93768fc94114b8411a4a5cb7ec660afdfb8f5e98c56f7f721a3df9025cd853e2630c6985f028da09778f799ddbaf3b77dcce2c4aa4bf47391a8e0" },
                { "id", "9c3f6e79585a3e75d3f884277d229b4c6845452c6f45bc05b589e3600d997f30f467a4b881badd742c59f2b7e74a765e0135d14e492bef4b26a0c83e3b36ed8b" },
                { "is", "86727ca0ebf959d1ed2ed68c1eb91e60d0936d4e121d742771514b2d398e8c631dd5d1b96775259cb8f7260c2a90bccc46dfbaee958a92478c1deb2e31875837" },
                { "it", "3cd9a8c98caadbfa31d87446734eacdaa1e80ac016669c75f1a9854a51f1f98131f9298545f9744e4cd908a636f1ef56a851462536f031361facc202c2828ec9" },
                { "ja", "6c475269d1cb15d29bc56ca926552fb3ef93c8c9da677155cc592365fc4f5ee3f348e03c18ac30c0203b8efe7db14e1e4608b1a7dd9f1f9d2064e8bc9189b62d" },
                { "ka", "aa14884a5b557b267420305bf84f360180a4c3b03614ed31ab9121c5296bfcd3b26d92a83dc3f59a5eaf374c6765bec302347b33bd55260eda03a618e524c284" },
                { "kab", "d4a592e0655eae2f94deb84eb3a8c9cd0f48f0c0126efe11af8fdbd14a017256659dc57fa87247b752c010993e6b6af90c75ac4e289f8188b447b311157be639" },
                { "kk", "82d379571b4dd50f317043aca8e01cc42cfb6a40b13cec0049456984a7752b74cc20243dceeda9f9ba7cb70726334d7217625f7f7d5a811e87331c1173be0420" },
                { "ko", "dda37c37c35c844c712d2d60e215c291c1b4a41a2e316fbfee09242ea90f80259893dce3eeaba19b948878d43494e409b83657f5c3a3c4064c1bf0fcd4c97dff" },
                { "lt", "6d6a0370acf69b35ea464d212575aa7920608cfc066c406e6232f9917fa2562d3a7fc5e828bad3d4073455d9501364a7e2165921014d7e4868bc81e020922767" },
                { "lv", "5abc31de80d7913ca1a2a25ea6fbd0101f246c4ce3e66c3f1d018366f0db966b96b5a8481fac3b101964835ee6f44d77fbc7f7f5c5a2edf13f3d9eb8ffcefebe" },
                { "ms", "2063e1dbb660c673788afb6cfaa3988b74cd154df86cafab131260f5e67342179e1508f28fb77afa6f535672c23ef8f60f5f18651cab9cd8e05e9e2deb155a90" },
                { "nb-NO", "cbd2ce6e7756062e4e21649f772b086585a827ab656969e35a1aed7b23520831ae4fa9795276fb4821f9e20027c7f9d1af23cbc46c55524fa7513a8a38182ef8" },
                { "nl", "f05bf2e11e127115ddd35100dd23320eecdf68133dc6a230909f05fe056ba9e75e3dcc9c3143edee3efd62709bcbdfca0232b2252afc869f6ca964f796ca74be" },
                { "nn-NO", "5f6490247b7249935e9f2db1129230e9a9e092ef5106bf17b3d357983e7da3a9bb11815844073784dc746236ff9e9273029284ff52855257a2277725e885d0fa" },
                { "pa-IN", "1e1b0b6650d3be20e430183b740f3c8546710ac129363a371fd1286b649155aaaeab66551a4a91596dcd96aca763d4c736a7c8009636052e508ed26620002529" },
                { "pl", "afd82c5d7edeba8b2e76bb27821366a335e6729332c2e97d80d1ecf62fab070c2754483c5bebcef9b3b1031aa220f970d239ae92b488d8a357b60f90f48743e9" },
                { "pt-BR", "2ae3f0242254b9ba31ac1b5d5106cdc0cfcdc4d580d55a390e36f97d1bf3e55c8d72233e46b79bc322eedd60394fb3459dbfd5729209137e661a8f9bfaeb1eb8" },
                { "pt-PT", "6de7f4b15ffb22a1f2216a2a71a5b6f130fd2368d37949136bfd5bc141cabe815f15a70f282cee3303bad9c6bdfdf8267befde56caa352bf7956ae1629faf77c" },
                { "rm", "21946c4cec4a24c57404d0c48dce59b163c2a92a45420b3014fe657d9c5d6482bd5f971bd4a35b5d2aa3e02b066067bad75cf769385edd6d105bbdf9bbc07378" },
                { "ro", "f305a4d4c01fdceb5d1958b413a9bf6ded05d5e1c565320f07b149bacbaecebf18344ca4b27b88f92c2be5402f6572cdbc32befcb40af37eb39cc1ec3b529c33" },
                { "ru", "fae792002f488ffb1530f86c43f595293eead01d3e6cf3c761525ca9dac8040bf152519b0eeea67511b8aaed22c9e08db1cf58073a96976569431ee08393a31b" },
                { "sk", "bc939fbc82f4fea964f834b8789729f7d1af49c07df75507c980991c77571b58ce22fba724166770f7fd4a199a4260482350423c5ab2f9ba9101902f6c42d0d5" },
                { "sl", "2a870a593f8ff9eb0f04beeec47a13846b22b42653a02718e712cb4a4f8b4f3edcbcdac1cc7853bba5ab41eba121cdf22a1e8daac3ca1d81b60d51a18e0f99b6" },
                { "sq", "d83514af028061f05f00804b90d6735a493da521b64205341880ed0fdd8bffc7f23489a6bb39a10b0d9a3e2c9fa5d73e0c85636870ed661db46d586cdf2edd72" },
                { "sr", "225a0f97b27b8f1faff2fa1fb06bf704f30af11d18b80be50e4660a2635a1db64dadd7c6b484a92b515f98561d413c694f6b5507ba0ac7146da279b80f66d6f3" },
                { "sv-SE", "bc7d686d1cab22d1044099ae70b43bd2d08f81829916b8ce4bf654f0af83e25dea30d0f918b47e81545552e38c301c03846715311fb6983823204393596cd911" },
                { "th", "2757ad7dbba878515be697539fff3c9f368475fa8017f24d6372e5d1e7657e15458b2f4b4b30d07d7b92dbd17a0003fb99b0b97a357ad4c4fcd01171db95d857" },
                { "tr", "fba35205eeb6c2ba2cf46f38f88a356fa6f73a5142a7b8b6fa7f9f9573448b8b45bb41ff9c6f0c57b408fb74581e2d3e4010c40b7bd58d9690f5e1394391a437" },
                { "uk", "116b7058416725377b002510818218e941d7a91d2e886b0cb8e5115e8005cc727abcf6a6cb2d14bd5a85659ce6329c12cbcf5484761bef646d79f70e4c70421c" },
                { "uz", "a59341a8a75c8541e797cd70db9143a4700d4eaba25864782bc74f6f6126595784059418b775a1f054f30709f48f1f1ff9ed0a41074172bf9be3933cbed50b6d" },
                { "vi", "efd1a85e4a974ccb58e9e1741ff98b59faf2fa20976d16e89ccd57bafc4d907de9745857afad87058e90353d2921c2811707ebb7fa343205e321fa176ff58c5a" },
                { "zh-CN", "3450136ff7a8ef48f6aa65ff528b6dbce0f72708db5bf17da33c143c6a316fd68b14c99653af09b4d3641741b43bbc307e90158d854e23729d009254315efed1" },
                { "zh-TW", "2427a640e3d0228d8b33686b0bb340d95e5703abda08286e3c8403f98adc78162cf8a332788af561a162853b33c2ef6d51cf47423585dbed29e490f141eb8594" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.12.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "4a3afe8e0176cbd803d5c609c547e5375729751ced1d97dd7448b32be5264a1f0e752560aa7643eb4762ef33a8407ed01cd5a2cfa8eb8eed5240b4a4cb8839c7" },
                { "ar", "2a32aed704a186bbb556f8b84790cb2127aa22c8379255799dfd988e5a2dd1cbc9ef3cca392c9a6b41be33e79f3998aa4399550f91eb9fbed7fda52f62c65ac6" },
                { "ast", "05a77c200e050b6bf58daa39bceebf00c4f233926beff7ed62e1cfe1381961f23d5cd25d19659e3d785b9e57a02a1173fc880527b13cfa51c0691f090d7c9e2a" },
                { "be", "339f27981cf2e345b9337fbaa279b77693eb53378bcf9f8c09167f7c3394ed6040e5afffcba142def238068644f69884ea34068067b1fd4f64d8fe8a7db35333" },
                { "bg", "9ffa954e1c36ad4dc1feff62570490bcf71d10949a2e9a4bf7e25fbb57b7f8fc26802f4297b53aa73410af29854079d7812987fc3efac17270cd8662c56593f0" },
                { "br", "c84c15439e206f1ae0d9a4cb5b203a031ee90678995334ffb7b90f9e51bbc8982f8f1ea3a8edad24e2262ba9823c57b8c5fe56d46364a870ec116f6542b1e0ef" },
                { "ca", "2e113af790f2235e25ea845b84aee9bd4bf5e95e2067be476abc312d36db28d3e3384df7877a840536d471f2633b096fe1378700f58a623c51e24d652fca921f" },
                { "cak", "0ec298c4cd6b7f00d32d6f907f4138a897b1ff479c6ae47a0456c8a9cc8745f576826c4536b9c2a4da59cca3c09e113da269ebd49f62c16c8f7ded202450c8a6" },
                { "cs", "6d5e90bf44005a041221e668c2f45bdc25a9cce42df886bd923a1975236d161fefbbec1b66e7d5d89d13b363f87e7610433c70eb91d6c012532f612f80853e7d" },
                { "cy", "f9b66263a713bfdf11a93c327b2dc58939cfe31d14717085e1513910a90720290b833d8d0ed5cd7fbd0cf17245e439e3f1ecad9d9529598a00f2d0bb9537965c" },
                { "da", "9875c55422d648ba368df92a55d0a770931108e5900b7cff40d01f9dc5bb2235f66a643e42f157bc6f57d1d0320b8a982d86f06beb6a1850cbd48f39c54b924c" },
                { "de", "af7577a8f6c04f611e0af0f8b5b77e0cf3e9fa080ef06bf332a24d783f74ad2684e912ba3fe8283cb15fd597bb5d7a986febdb5fca7521cdee0c895b4f56145d" },
                { "dsb", "d7d8fbe289ebf914ccab58b160e35833a81f662a3a979c785ff2889d878f810f8f490145344d7487c1b2e3ada5ed81aa825527e73ff699050d109937c9729c40" },
                { "el", "48c63b375080251ce577ce9bb8505ece5bf61382aef8faaf926771d335f651363fbfc7e476164c75b853ad0713eebc172e58bc15ec9597f88d62b4ecbcbad67c" },
                { "en-CA", "066d018dc3d82f6bb454572cbf2aecb4bce92cf69db8356506b52ba8d330f34bbca40c925a1c5e0e7fef18674c57b4a6cf4420512f2fef2b3b24fc58282ad126" },
                { "en-GB", "2b4a1bc76bb680e19a3705baaa824838f48dd68c70daff4a4334142df10059b1a21601f5ff3befdeb42da263daf4dbf4d52d924ae58aa2f6c0c074461a5a2301" },
                { "en-US", "13fbfe4901d620ae239e1db72f26350360cf79873cdc30154c2e982945cecc3ac2509253fe701d76a2b472064be2f617badce01c8ceef2743da7afd653d10842" },
                { "es-AR", "73c895204cada6815ba9a2cf9b93c64be0adc2561b1b2a1a6319dc1282b21b52f83202d5ef07c536eb310469877e343106d1c795f82d555236a84310503b04a2" },
                { "es-ES", "1b96ee5b678d61746b84a61abbb863d2d9c1acdf09bcaea8a17a3438eb34b398e83226301f7f8afdacbe9ac8f651b18893aec60eb522fbc562a5c7fd65bec2e6" },
                { "es-MX", "5602a21230c33377d5f5872fdaf5cfa2a306908ae38c79aeeab0049d33b67cd07f4ff8c641e997cf645de8dc02a5f86e0e2b3efd3c1e510894f25d9fe2095297" },
                { "et", "55d917b46eddf5013351980ad74f1a4ee332ae30d77b75311d4d3ccd64d20315092a71329ac7fd165a429448022ca36a5a4024a7c15a131fb181b8dc1aaa70ee" },
                { "eu", "ed6e193db9258d155fef4cd8ce8cfb98276580842114b49fc0d7e3d219d0ad4cd690902bacf5127f1b1a5089b7206bd7b04994a4a80967dd3cff0bf11c0bb077" },
                { "fi", "ece695e7c5694ae4d957872864c0c1a54a85fe4759c5146a6641cab6e5a932bdcffda792024320c82b4173e1641beb6b0cc075bfec6b01e484e845b6a52635da" },
                { "fr", "d458fd6f1c6bbe104e7c57dbeb29b3170cc2768c8ee542dd55ed5d38503cd988acf3da8fa6c04505159790f97c961e2d8372626270c2dd0cf09efe931d4a63c6" },
                { "fy-NL", "30d6c3674cd9c47a0d47fc31e024e9f3dd8632205839b37e0cbf796bdd440ea49c92220420d6b18fc1cf4b84a198d28682cc7e9c41e62a18a2b5caf3cee60264" },
                { "ga-IE", "b05690c9f5ebe9f97cda2bb3ae18ab7d7cb990157f34bf43814d57a01eeb702dce03a69257852dc760d8d181772385c8d3077feadd64b935405ca5769d55a23f" },
                { "gd", "7d7824eb77d9253d5f8af8be73352de7649b4802badcf3f81cd72581cdd79344c515763ed02803f0b7a9ed8e750af64a12a270f9eaaa85fabdacd9e7ae7ae82b" },
                { "gl", "bc21539cedb600d23aa581c3331fdb238c153c9b434e14e428ed74cae0046af031d73db44ce299a8a2f020b8c61b23fa837434a1b6dc8608658f3cb68d793325" },
                { "he", "e1e9dc93d73a08f0b601320bff749d471ab79e85b90144d677652f5f3ffee0d0ad048d1ef637ea93dbbdf1518a9fcfe77315bb5542c5e1d7071b7f1543d8fee5" },
                { "hr", "b876915b3b4e556c931969b1994a4d35777001d66f799eb74a98fd6aac61bdbb72f54ae65b8000390a787e38eea0a4adc8d903d13f7296aab3d05b55275e4947" },
                { "hsb", "1c1c56389e904916cd2286db6e5a614c4f455e8a99a6c986a017667d6d36f33f9db01499afa04ad22804c26a0906131d11c49c5662b69361f1a19c5d41c63f57" },
                { "hu", "908e9e8a2b47370e9a5819c47ed91d2ee24c54e556862e98f26b51425938999469edec9a214f63cc2b065f2941b153be5df94bded4beefbe0b7f98f186bfdbd3" },
                { "hy-AM", "cfc2949b9888fe5decf44f51096ef891468426036d233e59fbef3387c1f752509b50f8180ea49c31a408c96ac77a618e0592f84ac46dc539e9f75ae7df1e8e74" },
                { "id", "3ce7e26edc20816af0c86f36c29cac48217f206f4a3104e3991e163a382a2a25b48101dff89bb7f54568eaa44052155db1e211b32c620d2c2b986943f2363101" },
                { "is", "666ec9914098fa4cb8dfd1c693e7abefeb1d4638dac3a8c52cb5d43241f5ecc800f35e15ce957baba0b06b580bf4e897828ec894586eb351560724f4e0e24b50" },
                { "it", "062f2a1f5d85ff0e7d6ec8fccc980ae4ce729aed80caccd5e57b32d17c0c0a9d909accd0522ea1823a97a4691256ab929da81017ac7c4e4975dde15363147f4f" },
                { "ja", "e928c1d78e899f130d0be006338e078563a5c98038a8a6a678dbad9b4f19af2cb91282a6f374d05e3b0245520705cc67fa5c1489bf001f388bc621a207427c72" },
                { "ka", "fb5be92cbeeb24c952ee3f667761febc927e4819162e70217d4bdd00a125a03787ced30cf2f53b850d37ac021c953bebfd9a84e330b52dfbc673e17e1400fd74" },
                { "kab", "b9298e796c7c4e711bd71b776d3d6e47a7041023b66c3f03d3affbd73acd42100527674aa8c9a3bc6c3844851025724a7f0db1e1f21153170e7a71ad6fe38eed" },
                { "kk", "004c0a8648e4391e159862a91f5f660198f02c30d3e50fee4320abf05bc00a4f2dbc2ff063619cc7a06ac952ba3d827d10fd0bbaeb67e26f8265e622ded6c136" },
                { "ko", "a73c2b858bad2ddba3a7fe11dab69d4e736f9dcf3a8c5deece9df0354e3a9b76447fce58594d97d4c38d2a3f5aab03b0bea41f1065029dd330f33ce3c86c9c08" },
                { "lt", "1830335259275c6125b9238561bf804175c9ed0421e28459d1f401a0c5dd6d7e0df623de055594869303b0f3063201b4101d1ec0e55a8ba19473c301eb823f8c" },
                { "lv", "36e3f202f65ba5a5a17bb21c759d30ad8e404fc90c658d7587e633ecfb742bfa9631b5ee078c24ce2e6023ce73ed8dd064051421e06626cb5b72919fae6aa995" },
                { "ms", "ed059ea48916ebb06d33deb621aab5bb6f2c7d953efe4e1e3ce1fecf923ea611fa1ad3c0739beb0a0062c92d2d668a39e54f9ec33de76a47c36ad87248ac15f0" },
                { "nb-NO", "09275c76a1ad7f00977bc428719e43c2a7244e4ed8d413fff4da83e062501cf87c566e18a77843a1bbb8c8f1e10f03a21a313edf646ca4bf7008d36922c80896" },
                { "nl", "ed27796a2ac0e9f66285767b5a2528f2d1e9db51dd75274749e7a89e9dad49485a144db5a604fafa14db71e7e420dd7454ea3b859481906032344670347b9443" },
                { "nn-NO", "8ced704082f9b6d7fe113f0625492942c8e1e59646de57e3892db903ff56920a9d670e6606eb2eee7fdf7bac546f858581ea11a50845cebf8a6806a2e47c0865" },
                { "pa-IN", "8b0b9c714511cf45d12cee474dea22b014e87e9f3ab050ff05666c1ca2b54f9c0ba75eb6804c72c81bd19ced089580023e80c7762968de64f11ed8e06a0943fa" },
                { "pl", "8ccf9c9dddbcd36e67a94321d4b8e0dfdeb1f2d57d7a392c0b61df81f031486a31beb9db4d4d947cc62053194818eb7f5bbab7b4bfc0765b05da1ca0f301605a" },
                { "pt-BR", "dd4b60c3478949cac9d29baa0e2c4106c8b2b25a6683bdf9994d640ab641e9aa8bea1aeb1299d298c166a72b1af2d09866f6266923a8a776c38ef172b42485eb" },
                { "pt-PT", "7ecdac00ead97649e67c118106d8ef91be9469aad3f2fd056a81eb68571dbd24a1b372c8db50fedb3e266884561cf902b871c4c6443d8e4a80e2ee83713aa8a3" },
                { "rm", "e3592589807d9f6976f42038e924ba11a49929d9a19476986cdbd1f20b1af1765635be28f88c8c9d6c91998419493f4c1f8cc5ce0cb9f97e4eac825be77eae2d" },
                { "ro", "6b12f598d4bfbcea2a251b47f36f8b8a2b81ac7a2f002d51a7263062a71b7d4d879a62176632d02f2776bac26cc8e79649e7f9eadfe3801a3ddcbd5ea26588e1" },
                { "ru", "c11a687b5af5aa49debad44dfbac19a07c624d928ef612acc94f0f5d84c7f29a28d49fb8f616d9ad72debff98c8c5a25a3867db0e58f464bff405c6e873dbbbf" },
                { "sk", "35b0d97454ccf831942c42cbc2230a157a25556108bc62a50cf057aef3e63003e891df90be15c032c4c9624ea3f83c33a24904f3a9215832359623181dc487e2" },
                { "sl", "1c7634c6c21543def88d5161f0900cc46f0958c4cd315c3508986688f064d78c6328651d6d7f789dedd923c5137868a6bbb7bf4049ea18160cf7fd14597cfbdb" },
                { "sq", "0832d16f47b4400936450f86b0773c62e803da74791dfd617fe3279174f35e9f2a92e4274f713a38d9a3b3f149bf58a79a2363231b787a28b8e8c4efe6557982" },
                { "sr", "fa037d29c51829bc6df72180736815c250f883348ce9057cf1d3804eab1f14f5aa065389c671fad2ab0519fabf76d921a87811a97061d5466664ae1fb5915644" },
                { "sv-SE", "f00d0921117a796a0f8ec5d42eb076145448de73963c31a455f4eba487314eac7bdefe67d5772fb162c96922ec7abbcdd7447b9fe8d5675b3da027531196f430" },
                { "th", "585aca66b3ce342266682eae2c82783bd58144b8d004c6d384df134214acd10a9bc81031e3036c1b38848e54fbf49fc5b75523819491aa55117ae254c1da4af0" },
                { "tr", "32410c10d207549b996124e93497dd294c2605d45912e16127571d9310f35f0abfc204177c59bd8bb808699fe4c70f03bf04655a8ae6b6f2db25feb4a851589e" },
                { "uk", "322ff67eb6a43926efc4ded5c9ed931bf1c8750a35cf576e42829f1223817e266fbaf328e52ad7bda7623355c62c7b73c2beea0aa3107eff9222bd230e25d3c4" },
                { "uz", "ba1a484ae5c9602bfa64ba07b15cc113fd98fc60d776c2fe8ba3d9a52e33c8187c0c5238697cbe9b29f701d907cd36c1baaf16c98e83761cd00106e3211eb55d" },
                { "vi", "4edb474dac3127423922686612df8eb25d8d205032da6184320ae03b2e92c8e6283d3d0587714ebf3a7915ea669006681d483ca4f3de9842b280998df93542c6" },
                { "zh-CN", "0db02fa37c7c46036652a77e605477a4fdc306f19c9411b6576e6ba80e75b5a6fa4c459bfca6a2858fd050067d64878674af182d4dd0295945cdfc48006b390e" },
                { "zh-TW", "9231b7e30462a55db7c05b5f95101060a22ef704dea836fd46614139f9b91055483e6a5a9baca28003fb727b988b7a6c5fff149685f3db98d25612c589a5ab10" }
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
