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
        private const string currentVersion = "143.0b4";


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
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "83c8de91abb21982ace8bf414933c2ce251afb5929ab5d96f734f06c67b165cf355c1caa9f020c18eeb88ef61a0869c6680264022538198c720dc9d3ebc62a69" },
                { "af", "2454ae39b17d460df1a7c98549970118c7148bdf5866517d9773f8b137c2d8a7bdaf591e87982e051bbd7ab3ebe22ab7c1362510741ff8635837d861860d98bf" },
                { "an", "c49651157b8f75d0c9fb3e0d8cb1796417ea8f87aabc7e8ae0e0cfe2c1514bfe8d2023d18f788c085576c131ff93e895a5ee7e18d77da0963fab7d343add22e0" },
                { "ar", "438d837737fae071ec69732ac243125dac84bbc6103db1d27f7e7fe10a709413de720b5b11300f7813f3580eb48196610dd5f7d64845a3925788ff081aeae8ca" },
                { "ast", "f164b6d5023275f6569b298f99cbc73f68be61469a610107a56cf8434f9f88adc792f44ac1a410e4a612e194332a39666df0b1e4a35564fef2168219d7b23860" },
                { "az", "9c2c510c336a4d6e67391a38a9b898aeede9437b06c7aa42dbb2f855a9505269535ab3f48963004d568a1da06eb3bd4bd25d39983e16289de07c7715b1fedad9" },
                { "be", "47952eb68c7418182b8ca5ba0973c5e3d5cb250dbc1edae1811c443e96a1d4eed645f2b53cbd997225bc582d4b1fd4f214443e2632779722f1ff49b951b02b07" },
                { "bg", "499d71efde9ac00628ed2251bb9aebb8d26debba5664fd6e7647b8fa388633953602b44bc4ff03124b1b29eca07f5be0cd6af8c6f5cbf42f09c5e435c5eb60e6" },
                { "bn", "e5532ccc9528ca3fba501261bdf523a0f8cbd52d6bc1366e2451ab3843fbc4da3d40ce1ec6a7b991e889e2a2de0e50f9e5154dbaef2b365c75561f25d93c9ab3" },
                { "br", "f4bba6c6becf0a6020037ba7b4a161d52da935adaafcbbcb804391bd8b01377fe8e480e003300fb60a5f8980ea12c56110f75efd7bb229ca3b2ed02986a0778f" },
                { "bs", "547059e4dc9ca70557e8595f4bca5dfd051d5da083f38ff199165f304720e69cdfe47c877d966ed3ba19aeac4aecb330d8f15662ee55a5cddad76fee2e6839f9" },
                { "ca", "1f1b0880fbf48f853aaa8acc628e7f382578c66ff5db04844946fa55ceb4c0ebcc544992957b44f9266c609d22097986c6e2dbc0f4f7127a82a75e86e837a9ca" },
                { "cak", "203b1c3dec351576d54a571cf35f669170dcae8eb0d7bca8d015d78b6ff378eeef38d38330d8d24d41daf3cb4cc4e7354bbadfaad30f9767d37331c9d424154e" },
                { "cs", "fe51c9de651ce20f59b0ebeb3e00c9d7a61785611beb2ac812bd6c565dea4aa02e2e1e002b650a0aded7b7cdbf5b3f7582c1a34c060b6a121f2cb1e84704d749" },
                { "cy", "4aa2000b5a4d3ac5a49ddb8b9a445a180a1620ba17ad627f767a629225a5cc2386eb66d2a37c82671c9cc5018aef23516b5f557e9ecd068f4df432ac88dea360" },
                { "da", "79a8ae0430bf2083c3ca6992c5b19002814fbf222051e45dab0c267e307cb0664623ef2f4a414a4e4938cdaeb51bd56091a9481de031919e188b8a4fe4779a6f" },
                { "de", "56e25b4aed3726180b43a0a0520c006f7a6fd6d48df669b7326ef776e2bde7bb2235058f24be130e129494c4fec7bd319314de38f08476b2737f5d70f21db311" },
                { "dsb", "d0493496bf3273d6c51b18dd3cf4b8ef20b70168c35c258576bae2ef77593fd652a9d844df63fa70443bcdbe5440d4e23c05f8435bd254e123fe68d32326b580" },
                { "el", "631e053436344b0383cf7247caf67c06145f15c1b27c44423bb8771767253b513cf76d1485fa1c8a6bf8d7d2254b7eeb0e2593981d5a0f29cc3adf282c45bafc" },
                { "en-CA", "7dd4bd53dd05c779400ca43ae4db77d54380ea911a22ba731c5ac96de1cf43be96d56957fbda1ac63090d43be08d738e74dd34f2369e47d05ec5dbbfe5550280" },
                { "en-GB", "a371a9619b71ebb706f6755c687973fc3ae49535866fb320f331257dc84dceabdb221ced0119960f13c3c4d1b763a8d2fba072a0cc3ce95473d8d356c70332e5" },
                { "en-US", "fe725099dbd73eeafa68f4c83f7f2af401231e2ea007bd7d14bea6e4afdd8aa1b7085fb41430f462ed756cd8b227a436bb6146e709d16dce2513e8ceae78a809" },
                { "eo", "b07d31a92c0719e931dc57799411fcd7441d5f392a6c91c9f9065cb6683a67794a11b50045cca84e76e545e084b487dafe6856b215c07c5e8449b0ba9e49e7bc" },
                { "es-AR", "0724dd81f1d41be0c725a289e287842007be2e7ce2602a9b6bdca0909d9d7bfeaacc7457c862459016fca69bd9e49c8ccfefe802e1deabd17653df817ff3ac2f" },
                { "es-CL", "2a3235a2b0901bd20c93c611d1d01b9d6c581abdaa7030a31fbe5cb56116b1b79460f2bef730a304b3223c85b7a8022c2b59bf1ed42f43f7ab72ae5774c7d5a1" },
                { "es-ES", "60ef7a0c26b91696179391dfb4925df5aeb9843eb8b02a78835a62c42bd77e8ee8d1dd5c074f5d1c093a5e4db8e642860d97427f93881b94f07d8df0fb409713" },
                { "es-MX", "0a9aa1e64649bd3c8db2fa2e8a2d87bfb5559c77a1ec4f9400d0301007dd338c92fa3d4d67c69ba25e25f8d8cdf9f2e61349eb7e944ed9763e5df6ca3eba793c" },
                { "et", "02d61fe5423a65559bb69fc061303542bb863f75a7ebc8837729cb94c1d952fe8ba881f7a84307da3161abcfaa6ecf646e96aab383d68f58da0cc79ae5adabc3" },
                { "eu", "0af55b20c2787938f625c2ff68c981c53bb062100f0294e719c8096523be86910d2aeed5527da1a62122e02e0cfc62d04837bf193300207668349f49f797db43" },
                { "fa", "ed4a54cb3a720509d6a9a804eeb8e184735df5423b01c79f791def39ff3d514ac9123bf4ecd56b02c9f02a65db64d48af1e6a6c12ab002be21d4ab6316b844f2" },
                { "ff", "5881500a2e7dbcc2def3d5f44d97bb4221b8c418ecd6d33aa35071d475b8db22dacb76b4a40dbf9305ee3025e057254032134ae13cab2a9329959daa93de19c4" },
                { "fi", "13647d3d427594efebfb260189c16eb9943e73851f4308f1f6df14de699bd27daf354a1c1129b7172b3dc1fe2762ee38f3e7997b49cab0de7e61c4f2aea06210" },
                { "fr", "7ab2f734c2bda9c75adc492fe4c4238a647f789814b8c08afcb16074783b9b8354395edd3e4ed5fe0664f3300b22224021cdc49121bbaa532ee6bed38c132db8" },
                { "fur", "7ab1bd3915cfe2d5588d1605bb771b6e7e69bdd86420260f50cb5dca47c3eea1ba25b1e6d3fe319c5635a4228c55e9a7df6f0562353b24bd3f7fb2d92d0c511d" },
                { "fy-NL", "7a52078d2bb1fefb3c40cea424329e2de8238d801de46bb7e50a9f1e9c21e481c0df1e866828bdbaaee8516faf3d17d66c536f30fbf85ba48e4f57c4e8b7ac2c" },
                { "ga-IE", "ab00231de4e0dafa2b37bef3b0a4c5c54c0b55f7278d71cd829fe60fef413138430971a35eeb2f694c9a4349f4b4fd4dd66aad32bfd37bb8ce19f5c0752e4e81" },
                { "gd", "df4ce5025119f243b6e01c1aad75d648b30d62532c89fca594a847a36f77bc8374d2dffa9c625b028ea85f8f02e13eba1b8d6b9cabd9bc96d7b087d8bade4081" },
                { "gl", "7f0cd322b0f775a7044db780e580b3456bfafff5c818449c9fdcec9d129391606f54db16498180c825cb08f298293da7ae68b29ffec938ba20225c74c940d9bb" },
                { "gn", "0251b6da24b4614b8f9614562a9785c0614d52194cdef6b863be3f7e39f8866c6c31d70f28e497ea73f6f431ad97aadb912748573aacbbad37c941c8d30519bc" },
                { "gu-IN", "a2644411b22b8655834c187a0e4b9509f425c325637e4f9d01156087cc54538bf3f9e005f3b91e4765bf3ded11e9cf6afb134b1cb92e9337e79deb6cf79f9973" },
                { "he", "8d2d2beeb9fa0c8261d7ad72f8379cba90d747ead58e362e128878a65c765d254f973ee3678798b43ca3d5f2f29a04e7bb82ba267ac32c6f9f2059763fb3f4cb" },
                { "hi-IN", "6e87b64c048cc66dadc097d09ee72a32903014bcd5fe7cf5a2fcc376ed8830a219436721b6117eb2a54d049acc489b265d292b12361e75e3a645108f18e59ed3" },
                { "hr", "18eb8b0e6f0b7ef674b6f3aeaeea3bab8f7fbf696e20e2d3f2a18c122cf9832c4e24356f9376c35b3215e62869217396d29c4c06c91b11082bc4bd272dd8a916" },
                { "hsb", "53e05f2f44e8349f45cb9d605cc46f731a1ce2e853c19668d735df6f7e96710dfecea4eaad0e5527ac8e1bb1cdceb713f6a65e8dc2b1a38a46e1f1feeb1601fa" },
                { "hu", "21569c927617cffe8322cd1b11b0c07b797344a77af32b9933c439d7a37aa17cfb66e9b810c2176a8d32a9a5f43df8d238135a81a89ac3e6b3fcc2d611456dd8" },
                { "hy-AM", "1c1214c41aef06f4b069e80c7adc54071129cbcf6e45bc2574e198731d2eba7bbc78ac28c373ab00016a6baf48e588becafe80992629bfaa5c1d160ab0a82f46" },
                { "ia", "c7f1247c4e080a61a4722f92306eae3feab511f374819d96f574b6cb0033ef0202bfba545ad6747d386117022b04c30797a61ca7235c7c294b618752d84ce10d" },
                { "id", "dfde1d70b492be37dc08fe50f7db013ae4aad94a633c7e09e01eae79939dc09e1d94240df1432c29e8cc45fd7224c5e32d7611ad5b10cb2cf0ae392800f79ecd" },
                { "is", "060ed2d30ce98e7c51050c4a4760d56ade7adbfa64f02028aee428d74c12a7bf9ea86412967878960461c102dff5c51aaffc519aaac8c05202fc96d9a6c960a7" },
                { "it", "92e9ab23e3f295da28f70553758394186ed42b48974b448e7b01ec9dd3799f397269c362227ed47257f7794b5ff0c19f40162e0f63e354e40a90a651f53792ac" },
                { "ja", "ac6966bd7b3e2acfe793f3d00cb3bab30b9bf19b7102e1c7dd4f210bf43fa8838874f10c0e0cbeaa2f92cded0e56e3bf8023b7cee332bc6c8f7d922e9b00fe7d" },
                { "ka", "69d5dc9a9e847aa828ca56a980b3b03fa7b09d521c8d6c95a5053ad82ac116522324b4430a40f3704ec54106b3698d30fef78a0735078a652b2891a96119a698" },
                { "kab", "e7c66fe024473df13d3d770d52ac7292c95ef45c9c4ced8fb048357d7bd18e83d896bc914f0e6151665c3d11da95b899901b865e11a48ad26033688388f8fec1" },
                { "kk", "f6fd3d2cd75ffe8a73cdd0511477a42247e9baba8f06aa4b97ba1437367c1cbcd9f21d68bb8d69acd2f6e33cddd73ef5b5da6239a642be414dff40c6cc442f09" },
                { "km", "7b33fb01f634c4aad80fd40c3fe8995e31d9668a48c61f70b98d4a2d8c0d394aa49be63c11dbd537fbdbc478b62dd1c63c43f895eddece86e3bfacf37ca5a225" },
                { "kn", "0899e2761ac4ce68d06ced085ae2defae999853bd6404fd169d8e0cbe98f2324dfae0c926cbfe6243c74064bd0c9dbac7a8b10c3ab1b4e6f1d98096bc0dd3777" },
                { "ko", "da89bd4988a52a492306c8af89bd3f7f4caa8fe4f9fe978fca93df40476d4cebcb993e5b9af07584b10dce5d9cef9378478c041b2d43af9f5222548fce33c4d7" },
                { "lij", "15ba242792deeea2b09ffcdc2dcf112c52e0e06c24069d0eb76dedc384212a6a9ecf4ef610c44a4342d1b9ccd84b2f1aef0c15f5e1ad65c0a9dfe910321e8c87" },
                { "lt", "9684295b7f73c1475bbc2792a8f247aed98c4b9b3206b91c1ad6335a0f8e45c3675cb276e5efc84cb1d73c46e0c0eb4a6bafc39c8c869194dc81c30a22238eb2" },
                { "lv", "980206a354517325f0881af80f20749515f2549032039565075b161fd3472513b8f9bb85cea6fdd72247dc8923f746c7bf9df1bb9562b847c79fc0352b9a7c2c" },
                { "mk", "3ec91bef46d9aadbd6282ce1465f78ccd1fba3ecf09b1abe07c2f4d6cd67494f2852fe0e77427e30974c7d75e86dba569fbb3f0c1747f910767809f320af6927" },
                { "mr", "3c792f02945bef9fd860a667c24d7a0a18c3e774770a9d387504fed0800689c184f319de02982b9d679dbf198c4620542ff5ce4d564860b317c7611d271b9e6d" },
                { "ms", "f884b2a67400283ebff65358cfb1002d5eb07c1cfb72a27c86561f15353b6d8a4d51b39336d79e604661d1a30ca1b7c529687e933dda6a0ef3164e142584f2a5" },
                { "my", "4c71d4520097f3070fc00cdc0dd23f391ba099e37ef2efff6f817e21f0ee37e0cc9dfcfa6762a2fb428e4fae90b3f868d30b259d6c68f2f104c723521878df80" },
                { "nb-NO", "e8c6854126c4e542af00f40e210f52b39b3c41352546d35247c2db346314c4845b6f6783a33e993f12ad257ecce12be79f67e39790a35b9105cdeb8f0104dfeb" },
                { "ne-NP", "0b6d77f161ec6644c3fa4d7851cd1eba133c4d03d553520b664f18c90004fd1f681eab1f526f2945de6122caa843285cd951ea0ca9f9b771a1dc14d2bbc777e3" },
                { "nl", "d64ae0f74a126b733cf8f8e31ec383c12be15033d81917bb222b590f16e2aaebfea35ef0f452bf388fa513fd84876f1599886c1b0cc43643ac55b6ba25c965fa" },
                { "nn-NO", "9bb3697d6d62a6bf52afe106df67d8d8d8a8a3d6c77fda5c1271950a7b2c8fdb7e6045cab0d1eb455f68e6f34f77c4d49e36a8264bcc4afa9577e17d8894853c" },
                { "oc", "3ede1beba8e7e90b861ef04e64fa26ead1a29b0a96caf8b1f7bc5fb2187f1a4bcb55af32fe51235fa48e84fc68983de45144c21c149e36dbb04e8a667ae5cfa6" },
                { "pa-IN", "367d3405d09a56520961dff92f0e4c4a421ea9bc69448086336d31db31f63a7a1a1f41b2f870571c3fd48cb475d9ee3ca3438e655a2dc423467139228d0dad9e" },
                { "pl", "7193514a0f05871a43fee32307e740cb97b07ae1ff9a384397e653c3d0c9940612b3402e69a61a6e1282bd6263ac4b47c25ba5cff2989d3e32a0b1f1a99fca0b" },
                { "pt-BR", "dca29acc87b0064aecf3d1429dfba12288dd415c3e6bd944ace86df98b0dd676eff2b0c5c94a958491b5481d2c888b1a2cd85b25d4f93878849fc43128cf621e" },
                { "pt-PT", "a1d1059176f2e9650e3addd93e697dbcbc51c642d3818dfe213f01ee928640099c91607fd17e843e8f77ced49002e772cb4be7dce355a7ad1206423229264eb5" },
                { "rm", "e4bb8437dce4b3343468edcdc2f869d41d0b5afaee324c3035ff08e19b0df342688375775f4a770a83250ac506e1b568e56852b4234732cd868c72cc3a270705" },
                { "ro", "eb1adbe1d687b4a0ccb3e0e5c0ef6807fabb74880bb594dc2b3bd10c26dce4ec795eaab570cbd7469aa9b1e2801824469e318d00f00bbed8596357f572cebdec" },
                { "ru", "233eec8a79c070ae2364f81d29ee647f78e1ade02705d1a35a913f75b8ee0acbd768bc2c05846bee832cd794608236fcf3fc4477246ef317d56d4dba768aeb1d" },
                { "sat", "2db55d895faced1b85f4083b2154fa2d6de211ca821a3a5ca7b76e5574c21bd86dbadcbd379ea0e2633e51204de380100b958aea5ecfb406fe423e8e703b10fc" },
                { "sc", "becfc3abf084e361fbfd29bf046391a8e6f8c11d1a361fb48e939c4cbce318ab264c1a7049a8f8a3eca0f75a402492f8752978fb3914934ab7cdad9a22b74774" },
                { "sco", "573e5508dec06a906ea483b5ce6913e87b1267426390ffe4a380ffcb487921e75d172f03b2a79e9b51db4be031adf301f2cbc3ef1c413918059367f1526fb6c3" },
                { "si", "39c2fc63550944426c271b570af1f47e53bed796be7d5c6f7f016ee00ea29c356ad5ed59d8bcbfaba669b65f0cdb1994f5e3e44251351f1b88e070fdd535b2b0" },
                { "sk", "91057132a3a77a6e04e031438f660c2efecc0c16b56ff92b1e9c3f50b180f799e310c92884fdd8c7645a593243a25b9e180c36bf0dcc77c85d3d8b72c9f6aca5" },
                { "skr", "dd8e0f7f8948b67fa57e15bd46b352db23f786903278b04c6d57142d39b00f3f389edbc99467434c80c2db7a57899cc44341f31929295d83da1146b2fb7b9916" },
                { "sl", "6c124d0afc74458c92e9c06aa682fd10c4e6bac2ff08c1deb31f9e9e02726e1be719f5285195dd387d0a1d7ba688185353cdcccd9856deea7d3a123d1bf6d6f0" },
                { "son", "250910d1d7a98422c03cf59d424ef20aa23acb99f092cb9026161b4fee7a1fc158bb3838c6719acdd90329f4e8eba57450e7e1500a527bad1375ca8056d7985a" },
                { "sq", "9fedd493bd2421e98842a1276d65c4e416bb47dd5fa9a13f4ec5a6774334f28110655c947f1b668863d78b57fa9190fd837c17900d6c6c80116262099d581ca3" },
                { "sr", "1fd1babd657754f64cc904262d58470406834fd3fa223168861c4c4e43678e726a7214b21dee71e407a212278b3846a53d0fb3b8be678894e78f8b5fc7e92513" },
                { "sv-SE", "ee19c054dc98929fe775d2f526554fdcef011ee5078767bc87fe36e5353b9a496c48f507a233fa61eb714da8d1a967ae153e1035bb2be30eb02e9b0dc218b9fb" },
                { "szl", "9237c93fa418c7c15b3ab6dcf132267778fdfc484271bfd6273a885729224145a629dffc85c643c05be32e31e48b44b3eeb61b28f0e2e056433b843227176f27" },
                { "ta", "5d29bbb251a9a01633537e0df9a7b8491cc298a7832d233bc737f8be511e2588fa5cfc6d63ebbc62a298708e6fdf0279d41c41c8c71a6585c46b15d58b36beeb" },
                { "te", "e9b27be0aeb3db15a1f0be95d17dd86402e47bd1dd4ed26352b73b886a7feeadedab0af386e8cb245dc3d541b94f6b80e14f0644771fe08ca5464437fd5d4b35" },
                { "tg", "5fbfe6e8f25a278a6dc5ac91567068410ae28bd1bf01a5dbd68b1b3089a947656f7549c751dc90ce3dd296acccecf4658da2124a8f41754347bad887c87a7b20" },
                { "th", "dff03d587da76a5092aa29d2f75da2ed293bc389157469bb4230efa3455aa1a8b9c9aec98e36b8a499b09fc8e081a669ae8469b665ad363e259e0941dd17d0e8" },
                { "tl", "8324b9414f31ea407f23ed6ca12e31130814ab20606df95a206baa8a702da99ee915f1018a8591d83b33af69f9eb495eb91088901aea9ecd23c87efb6fac3eb5" },
                { "tr", "f3833eddf3505a276beb5685376ca6ce4b7515ff86df9acf0a1a43218ea1c350632998ab780d9e2cb73e80a77a0d7c594863eb9d211874adbcd9ae0969782c64" },
                { "trs", "f71d87f0cd58a831ba05c0a897e20e9b8a4f51e5d42f33fceb918075d050a47832e886118573baf3a2f3c51481cd6d1588f7f296a8df7baebd3635ce024719e2" },
                { "uk", "54659b2b2e33d8f5866b02a0b93dee91ff8ecf7944a5e1f71fb368aee73361fa6c1bce97b4f27c1b59f63b6f7c93d49075084b37c1486cf84a8c221d51e07c83" },
                { "ur", "a763b277b4101ded93c2cd0fbf834c5b9ff0b81b59c49f3a23bd8f7bf4036a3d65bc11d575a054cde539028afd9e0bfc4dc05e83e5ffa62f136b072379717cad" },
                { "uz", "e07c45c42dc455789bf363172447a63241c89a2c5efa3834bd2a5536e187955e86c9536109eef324be720aa634fa1a7306887c4b995acc5d496d6537328f42e4" },
                { "vi", "2497271dd49848421f1c7bdb1c8225c8a33590031ced6b55b881937ef52dd4c7eec3d4f92ea15702376f6499e8e61aa651f23f135ceea3e85a7b497d827b7c13" },
                { "xh", "36599d3fc82fadfd8319be95c8574cb471b3c021554f361d4219e4592fcc279659af9767b83708bb9b2fa67375b3e735f4f3b54493c4ce6475bc1ec6f9f194bd" },
                { "zh-CN", "84c1dc0a1c568597117d939ff7a948ffab874e75a7dbab332500df1d454a21b43cce7eb793ae0414879f85a5397faa8027c11545fe1bfb50e6fe68d912fbbfea" },
                { "zh-TW", "3406bd51413fcf288d020b4ed47293e502c69cfc847b6e24da741399ba24114cb6ad8978043a56bcfade6f758806a90fc3670b53d2d8c0b3c6c0723e45ee52c5" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "28b40089d5e3804b910c9bab4f0a32ac4a1d4e32a452760253c08d2a08bbc24eacabae3de1051085cef00e9406063317316283d08709519ab39a617bcfd2d6d5" },
                { "af", "4bb19885e4232ba3aeb1d335122beb05627fe439b1e6463b103561a3479a8c7282b7de39cd658271e770d637adfcf7420cccd529c9db3d6fe162f5dc1693c222" },
                { "an", "7c7e6589e5bf8d26d92e1c17826d6d8e45dfe2564c2110cefeb4f7a9f88f7168d9f6489a8ee49756a0e6122d3541bef7a2c31f0fa30f318dcf81b48958d346d2" },
                { "ar", "e7016cb390358d323ca543a92ec8e1614c554da220bff383a52991523d13674c2206adeb324d267405ad8f42072a05da0be8d63b7f2b5fccc487f324e746fcef" },
                { "ast", "3dc544f96beaf6dd045ae9246e474ccad0928194b0c702b92e4553cc5ec185135957a8ee245df5dd897eb40a75e0f251378ad76a6dbf9eb867a6e5643e9de8f4" },
                { "az", "705af7b0e6078d6f9c98694a66128331b66afe028ed434e690e3f2bfe717288e1351cb3bacab205886a1e15f260314c5dd09f78cc94dfac450fe73c4b3646bc7" },
                { "be", "0dc34528008cd9a409bea8c2a740fa82f4fe3a78c503dfc92d9089c3c15487d81799d8a98f3a698f4d9e90984bd7c8963862e27948eca4e9044f168a89b74ebf" },
                { "bg", "4a75a63b93b8f3f1d0d2dd5378424a6847c050c3554f1c9e18f174d7283977f868962da49397b2086bc6d3c1dca050d925994cada9a12a7be0f926653bab3ea0" },
                { "bn", "5403793b15d88ce6982c5c8fdb83ace51bc1835765e9e64e771f9e4ec20e40483c608719c4549325d05ec6ae6c43c314f53f02e0ed9bf67cba2d1f0bc6a04be2" },
                { "br", "99186de708205f114b87824164152da7ef1818d604cd9e31d15c3f06bffaf59aeaf90a71a2205b07583b6e2a6f3fb64e03fe7ecb9ac80408dab1ebb586e658f3" },
                { "bs", "5f091ea18b585b2b0350179c9bc58530c2062774cf071492c0179cb0120fcc0d4440a81eb098c3509a190cb8a987e87479dd87f979ff867fa6c334710ff9da9c" },
                { "ca", "3acc65abc1a713fd57a48b28524c3b79afd251e73b1c8d501aeb45b4688e38b1066853d152c0df0afd3f4616a53aabd5a6e187ed10c17c1d425d357e7d19409e" },
                { "cak", "770806df9f1fd27df80ee3a0bc502781da9eecbf8f54345dfa0b4ac6c13779d7e1b440ff649b647ce9e35c975cde2f787fb22300688ec68f26481a0fe25f04b0" },
                { "cs", "46a89fc9237cc5214933c390e4fbdfbf60b525851b029276ebc3572d1289ac57c16f3332fac12e68cc20ed71fba7eef6cc23ed374f9c3776c909d2e1ebd8fb68" },
                { "cy", "8a49b22c16c721a8016bc5a5cbad3d9352199d2324e7a06cc8a3a1f44574def51d8907616f7f909bf03412210e02e257d29ad627f345f11093d3b5265f9dbeab" },
                { "da", "1957ae7c8315b3a95bcea373bea31dbf38d2cdbd204fc9dff1dcaee7668f7c40e3da4dad876dfb3e8cb0f5147b58f1e774abd80eeddde1cd3d2941afa4e24e09" },
                { "de", "6ac79b21e1389de56d4e94bb46151cfea1200e486d0418765febdbdc9cd7921d85cd10fa853951b042d020e0b711c8c1f51461f5aeae7a367a6cb3db99acbd29" },
                { "dsb", "92b862472b735bc0d03463b0948ed1673ba9cec23940dacfddbce809f8d9cf0b577ee676b5ecfc8e17b30178a713e0be49096ed22656fc7ce99d8f475d96cbd2" },
                { "el", "cb643d95d6fc7aa6816cfd9323002b6c9411e5b50be845bdd9ed1d602f5c0d60bf8fb71f84ffdbb76a446d1ba260128f394ecd050d1c1aa1cef340165d2a2cb8" },
                { "en-CA", "2d8e9d752faaeced7caa9ecadc90af6aa40f8d3e64ca57e3be02f4e3a120298865ebf0777be62f005ad17381416d835d92e7774d4308951175f1c3880a0a1639" },
                { "en-GB", "2e1b3139610af0a4933cd2f571b2a8ee73b9af18e2604f7f972f88ad423020a632a59e4172f3cfdb014f3b4bc1c958d7a6a5a303af4d7d3275aa0f4b6ff9ea88" },
                { "en-US", "7bc855ba02134919c204fe2ccb56944df96d4156cc13a84d139086d6771f61b62175cb0ab79a6bd56d6bfdb793a85bac90fc41b664ec8f03695fda60edf22068" },
                { "eo", "627f773265e1787a2756b4fb2804348dc0a784148817c344a6a3420f96503a8296bd4b7419e7a61f327e699b0a5e90bd92829858e1db9fe4cb3dc595b26adb82" },
                { "es-AR", "888854ba6100d30a2e0fbf941cb3d14a88fb72941d86445708e12e2d8a3ea185280b65082738acdb03fee7ed2d989a6d05250493c31baf3b39a830f476a36be8" },
                { "es-CL", "ed0a19cc2dd0e62de9ac51348145c38d4e1524b7a879e37940962d6058668900db1d181342b8bc4c0b572576de7beceaed52ced7aed3b1a5e8342515938fb2c6" },
                { "es-ES", "8e54810a8481023caf7949ce8722cda7b0bfed50d4f6f16c420362ed41981ff47891540d26394cb0b835309ccf9b0a36c0c391d1316d354322007fb5d455f75b" },
                { "es-MX", "3c9c9aa3a177b5cc1945d746da78024c08f9de21cb4340a09e7f19f43e0274ed4a902baad98e77895828e03f200a203c1a39bc5e8656dd2e8b0908433a0f4de3" },
                { "et", "dee77ee37317258c00d3860f5d1a091a72a42c9a1df567eb6ab2770ec76bbbf9237fcd1c417bd4c25051def0199d1568a45c3b46ee2c9c3ed539985b319a00a3" },
                { "eu", "46bae748a0ee53e0684c4670c46acd4ecee37e4314f2c75dd96e5e08f562aff2dfafd1f6014b5a7f95a063ab53fa5cbc599236b34eb8938a824b5cea29d23980" },
                { "fa", "0b02a3bbe12cdd5f0cfa73bb45da1dabaec35d880793402e46f55e5d4edabdb7320b78230718f4bb6bf96cc8167f10e10300756de7626f04bcffcda07c77edfd" },
                { "ff", "9b3fc815bc33971890fe607f36c55b6648ca8d9ce295da9bf329115047fb63fe53949160628e28095ba49bf3bade11a44caec24808f54b05256a769875f95d1a" },
                { "fi", "0e914234e931c3a5e65a4b87e076a9cdaef9e64a6bc2160b3e6bc53a2a7513d8d9e09317fd8ff3f37177ee0342c2d56c38a98a3f5be05d496fb0b8c76e5ce731" },
                { "fr", "65a9494907196904001e1d494f44b36c9fc6c4ab003e7d5d1e1f26ea6ebcf9f4952ba30e1495de1434ff72b379961c0ae5861d6818003c53d6504054dad4a519" },
                { "fur", "c00db561c88202ecdb0a7761e125eb9c2821ff26784646a418461f6b93d8798bc1a024cfb7497f5221aee946577df52695b24bf2fa26f99322b29d922a83da0a" },
                { "fy-NL", "4749185e8090c76d9a30896954be6e8992e1b8e8482101c3c6de870abdf88f2d68585f04e166c643cc33eb29747b69fd42645fb2e13362fc1bc37978e1c8d822" },
                { "ga-IE", "904465656b002973af7127b1e6107d9a759fd59421d5da6726334bf2de3f2d1cf21f8bb1ead47da66481b08249df8ed467bb913f3721a87ede4c9d2b1a82a9ff" },
                { "gd", "f6423cd737554833ca16d991827f39e5ab292fcc8e6d259181e5b43575be3e362f61f34480e569fa928c19c931224918b028e2970e89651b989631ecb5788d6f" },
                { "gl", "25ea97fa736bf010c12eb0106af17a81b2370dba1055b3f85172484992333438a67cd7ecaf2a55fdef4705c094b3375897a714b557bdf297ee7586cc5cdb3b85" },
                { "gn", "11e5e668293472669e26289dbda8ba7aa4a9aba329b29e59d7a1ff873358b303ed43a1e5247a594b6dc7ab74c9431269ac0f5ea7a6b489afb7977e9ac8e1d067" },
                { "gu-IN", "3822488580acb34e66c15b81693b3d8a0efc245795cdcbb32b25c8bc5e22d5deba26bee2d701b684aa1bb9622cd6a3cf263666f87f0b155c02753bb0884489da" },
                { "he", "9fd52036d7d894aa2cbc3ae2c609f95d21d07ae59d3bd06638c249b05c9e6b0094ad1904c25490e15fde959a8f5e63adae9adccdb28b064e5b83dbe0c78eccee" },
                { "hi-IN", "5642aa31554a91377e8d0db318cc40c12035cfa5b6234fe71a85cf80638b0ad7b2022bd2fe9b58ee5409e0e7d33f3f2b4800970c11d6b3a915a4e531fc42681f" },
                { "hr", "3cd43bfa771f177faa9db7ecac2c293d810fc7cb45e04625e176101d7b4d6f789c197f1d7e5c1faa037a0d4c91707ce955c1fe3663b0074dd0f23c0263769a17" },
                { "hsb", "c4f2ef0aced183bdaf840441cfb92fb4bca91c0e2579a28ed475744844110a2d9bc030d42bf26d9597ddec895074c581659aef1a4e1f92d2c85dff453a0534e7" },
                { "hu", "eefaca5b5782a1b43ec04a76af693fa0bb4610330dfe6ca1e8d2ea9561025105c19b409999aea9b23b98609a3e62da231a5ceeb14355525e2823138f7292e59b" },
                { "hy-AM", "6ed1f4275905ed4903cc4571e4301a566a9ffa01736e260abf1eb727263a3742c60f0a91db0ee1bfcb4cffd779c2c877e18be975884914bf133001d658c845dd" },
                { "ia", "96a717c3f4d93a194420ef4340b7ae50095adc56302436e1ff39d1ed7619fcc2661c47a942f20e1443f3dea076bcff535e5b9d84fbddfa32fae59587c9d3af2b" },
                { "id", "204600c9b579192560d90e2d8d26bc3affa767e8bb757c37c3fc1453954f063b2629f2a3b020090a3d90d4cd9dc804267c5cd71aa34967f2e4e6f21308e20379" },
                { "is", "b3db4d1ee7d5ad2ffbea2244b1f285a29d622b29da1dc7c71593895f9a4563e14166f23d9467197a3eb49c0cdb7cfc94de08c8a303763aa711b7f1f40c94021d" },
                { "it", "12152a492c7a7c7968f578bbaefbb90a868c5cb8aec11972943ff8d1782788ba813d8d9852cd240adfe6b8c9caeffd924bd63183d8224ce1e25be60e0ac62bdc" },
                { "ja", "2f7949c551d01c85841bfbbe21383617f628bdc5b225628e5e2ca273e64802d16a7e1929fb48219d5b3a5675e98a6147a728d51124fe84fe4ed1485520854b96" },
                { "ka", "127dfa71e07c983170bd8651ca390604a5b2f82352a10199890b0665cae303b223ce1517f17cd0a2137f824a64e8f974c3a9ff4352315f28a1b8f9b95e330fd4" },
                { "kab", "b5d8dd796320ced202ffe1de716b743f8bfabab5845061d687bdec84e89bfe6bd31439239b1a2491ecf32bbeb9a89b01c70cc31dcab7b819be81d8296e75512a" },
                { "kk", "bdf32cb2ce38cac57663b3453dbdcb75081f8147a64e3e17f8e701f8ba85efa6ae4895c1bca1cf8b3b487fd604b240b76c5a5c1e0db0f7ec09bf7483293c4483" },
                { "km", "ae5bd893e5a9a12a22ce75f2b90a251bdcf41972759e922b87a2ab650b2afbf1234dad10ca1892e67bd52f9fdd08d804510d41983114da68b85f5677e715fee0" },
                { "kn", "0872f8cc0a9ca0be7b5d1dd3f99c4834af318db204a29c3877577ee67d1e277140bf7b462cff67b5e398cb560ac1d29da2efc547a5fa5a6bedf33c28e0df4f16" },
                { "ko", "52dff100ecdc10ae1c2865823f07412b4804d007bed8299bf01aa24eb092470efa5f39b25e09cc8b506cdf3e0be36edc1c5539c163f69266f9868fe9218ad77f" },
                { "lij", "7fe50d8d5dd6c728c9ea9f5e765702061566191de1bf7acfad4abd023fbc9bd08a4ad257793cdaa37639c60506ad9e942937bd3a6664825ac063f9a4a35dd718" },
                { "lt", "b2cad678a923e1146ecedcc2ac996dc9e9ad6ec4d03cc936413869e0e913cf922124da9e05ec28eeb2e463e0433752ebc4926df7a3d6f3f5399a42ee9e9ac70a" },
                { "lv", "81aa63d4a23016dcd09f47b83105334844cd406e10527b86d00e28982b03e36d2accfc359d5e4857c668b9a62b38caea2887bc11b0230260faea7dc9b64209d4" },
                { "mk", "a277220b59385c7cf23c9548c28e64563e9f6604dac3002977be5abc758024f94de36b091fc0fb133bd864c8f559256f2a21f09bdc0ff8b118e137809d6493ad" },
                { "mr", "b008b3f7ba842408fd2179993ff86e3ecce5940b4ea844717016788bf508269482ba044a7950181420b404157264b19cf240d6512a792a50584ab387eff1aa4d" },
                { "ms", "dbf8fd967563be9b6d0d0255c73f188cbc691faf55c6247015771b79b0a94c4fb37507a84ba8df7864d72e9f4b1a6ce176d07a574ca2849caad85eebc89161c2" },
                { "my", "8a99ae8efd1b766cc04fa97c0ec18f8043da9dd469d5a566a93fd082d015d1fe0384d8752c49c4c8c49c86dc94d87f5c1d90010822baf96717a99175d2d67f0a" },
                { "nb-NO", "62e69ee3eb859f0bb4fe1f3f29b2e293119554ee919f0742d9d75f1fda27c5b23605edca7c72fb8bd44ca36b5fa224b697e39d5f13a8ed76e4f4ae26af6f5812" },
                { "ne-NP", "1e8309402dd989a0c3c16b4be35ed52cd911ba11e23107268ced2da3466202498ed2e1347e9af0d9cc02e6b4178fbd515728effc78f8195c9daac164da4c6bc2" },
                { "nl", "52d8014e9805a74fb43a9685399be3a0b934747a323de9b52dcbaf8590a8124cd1e11582feaaddc0d1dc67ed978a80f8fc20a62dc75c348c3106b4dbc36d45ad" },
                { "nn-NO", "7b2ccba10d29be76508649ad75a5b847fec01469a49f5c5160f4102ffde382628b54271654db99e04d737d2e4c6ab00eeac6e4e5bd9e03962f5f3c452084523d" },
                { "oc", "346ca33e301340af1f219a9f00415d2b7e9334af7a9f332066d092ebdb2f1500617c3b211dcc31806c0da257e5997b886577468199fc5e3e2e08899a323422d3" },
                { "pa-IN", "92c32e5684a3483370c6b7c85075a39d20ffc635dbee8e7dd35e47229f8330518178cdc34ffa589e1a1b0ad04aaa3b5c0fa64529cd76faf9245a0cefc0ce8544" },
                { "pl", "11dafa39fcfd4a9dafeb51ea464f1e26386b8eb98618a9d230b62df89ede5cfac5cef9734f76f0babf885968cb2a440c4cc84eb36f8ce9487076db7f20d10fc3" },
                { "pt-BR", "c251f01cccc58ef73244cc6e665217d9297e9cf78306b4570725e932e2fff37147299d21ff857b16310429a0fcfa06ec245b995cdd0d979cab72a0b469c1f2b5" },
                { "pt-PT", "d21c15f6695341e85e76d6cf6c03856cdebb6ff834d03f60b263d360dbcc18f1e3f9ac725cb7e43a4dbac59a26d525729a44b6191e480c128c98830ab02aa9a3" },
                { "rm", "7ba9bfe08bf50eee6dbd0496b64011135f639193e93c0660d6d3aad3f44e784960a9aaa261671c74f855deb3df2add493e24cf55459e8c863725b237655d435d" },
                { "ro", "ae7fe03f9edc5ec8b8aba3c01020330ac85c4c52d8e75fa17aa26342b8785296d25dfe505ec774e09c7645d23551fac85f8a8ee41e7d5f5975dd465b0ad8242b" },
                { "ru", "abcada635b662e258379cbca0473e60552d27f00371d47605b428c99f057fe4cff5a100fe240d4faa11165e5bf04a16e1a72170cd3377f87b9dccb1b8abadbaf" },
                { "sat", "25a26802cade187c43065a3f6914e5ff516dfa476248139bf8662cd95282176771983af2812329725c9b9a331e947866d99d9e8108ea809abbefc9b5ed70d012" },
                { "sc", "8eea10a3ad0c2b894971e780b32e4b309d6c7a260d79e647a63e8a6ea89186de837d1d704720596daa801c749bef645a2611862d2b4a44aa6f229cd84fd89510" },
                { "sco", "12e3ec1fef9c03a80c995e4f667e715d470a7732e294325052636e15ff8224007ad0afa74c02e20872fca069cc5bb1f8af997d9f4309f6a2ae5522affc3f0101" },
                { "si", "328e8d2c4edb8800366f6f50a71f1781ec3010d25245db994953c560063394c43b6c7a92464e0c49f5e2dfb9b68bbdfa0a549a4a6fbbf30576da5923207602ac" },
                { "sk", "e461cae663aae4e723dc2adbc088fde594fffaf14afb08a80a2f931deecd49d0f62e541de768864f963b2070b9367c42a818c90faf514ba27406b97e1261a770" },
                { "skr", "0fd2aa4a47246d400af4115fa7e3fbb09b7410fa6071d7495f12c8c78b03789c55cdfb78e865f236784d66beb52ffcbca3262cd87ac55f689febd6414777b913" },
                { "sl", "282621f2e5acc1e453b4ac9959e2953b9762b131fa53a14d96a85956c9900fd3c7fc2647c923dd3fe36ebced754d7bafeeb2787649333bae18c9d585933ec436" },
                { "son", "e8637b9e791424b4dda8e7b1c367de44d77db802ad796784c6cb806a82a2f388f66cd2a77ea7191552527c8443a013b606e0279bc087d57356f609f9cf0878f3" },
                { "sq", "d3bd445e3c643a91cdde172e0bb9c2fdc0f64a0f25486391842f0daca831722ca2ef947c42f0f0d67e5b4e214111107bef85428246241b5a2f796de762aa1bc9" },
                { "sr", "0d6887123f7fe3a8bf07494c27d7f4c181217fbac41bd808d7271ef2467abbdfd8f579d39ca04c79a3462104a5aecab980d451a9b20bb6dbfee5776ab45cb370" },
                { "sv-SE", "54aebe09dffd3931337d47065bf9a1625452aa4a1ee2fef33a4bd41ecbc306aef092268355a477ab6e826b068105737e60e0926384cfd61ea5588301b6ff8563" },
                { "szl", "0da7459673feffb2afebd03923334c7df97b7ed401187c14fcf1c70565224afb7aa45df2567ccc15f27cc9dda68ef9d29e639f044b4f2662650eee895d73ff6d" },
                { "ta", "1ff8db1fef06acc3156da269329c4ac9b2801bed6c5ffdc41edd6a4b95f81c97bb83118f06ee807298c18bacb6027b161f1bd39a0a919de46d2a56b04ccfe3f2" },
                { "te", "de3e900bab3d4162f96f78c6fe6e5deb0a8a9b1d53e1f3fa4f238952376582e61e8b20b4839093bb6b5bba37b4347baa30694180e442169fe7059727e6a125c1" },
                { "tg", "08aa736b9c75963cbc5922038bc9125883ebd6a22f3e012482b4d922166da689f14a1d0c02ed4516b8e6136ba020a88023f626f24b03042c9be9e4f77de8d649" },
                { "th", "1daba30c8c9cd6e88eb68288b21b0e513b5c1e2a3d343e41d6bc7bfa89a8ed9e78dad89f39d71dfed78ff7611b56ec07d9dc6d4d6b5ceff8317d5a7b2fc52308" },
                { "tl", "4cd224efbc89c312dcc1d3b4641f0e19c0644691cca38a84088331d1434e504b4385749d25f2e16ebd0679fe2107c75387ac59be64f2855f406eee232738c356" },
                { "tr", "1899be2a5a9ac5c44610a6985f8d958ff5032a8e1d544f96afa5e48992b4a9aedcd7b1562723cfa18e97ff58ea864c3f2cdbb23701d77298363e2d294e01faac" },
                { "trs", "fd85b0da89dd1489095231394d77e7e1f1f15d8a532e1d6ff72b7770a5e52047ce39eaedde77272713348ec516260c43f816776528cf23a0224657221824e67f" },
                { "uk", "a6ebfeb3d9582cc9ff8d60e1e8c767cddf8ef2a6dc86131089987245aa6f6428aca3b2e6454b978a58fa41d3c20cbfb8d0475edda6d5f5cc0b092a2db3cac8c7" },
                { "ur", "a66aadccc62a5f859c14bc0fc9aa1275589ba9c7f14e90e6e3661d8634ce247c257514a3deb35079a83be4478bfb16bbdd3b19aeeb9097e2da8b4fe247bb2196" },
                { "uz", "cbd061a0e2b57c06ee3f743e8df936e769552d1b9efb051e15fdceb61c026a8b3830877e93709090137148a8951f21bde97a99e9cdd6757e6f375243f29d99b5" },
                { "vi", "430967b1ceefb48f6f2b7abf0a97955ac4954756d03c8606795867adeb1902c8849145cc92a3c23e28be26ec8af75cf9f3b7f9875ff9b9dcd5fa0260fb3af44a" },
                { "xh", "2b74b5dafd1113c33e6d7c1ded08600785002367e388baffe76d42fbbe6b57810275e597d9ef56c712178a23c2599aade9310e3bbb1e597df1887ca7ffea26af" },
                { "zh-CN", "47280b09545ba147432d4a0f4545e59fb4f7f9ee75b39fa7a3d53ce9856add9ef964dd5d2951ec45a1fb19d853f9002a384cd1f5cd777d8f9196f0e483e1fb37" },
                { "zh-TW", "00e461e82ff62a7a00f6d7823c93e99b12da69920c8dd60b00039b7ada2c5e6b14473fcf6f6a9b11fefbd3f971def845ed3dca6d43ad62b435b5cb79d282e9f7" }
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
