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
        private const string currentVersion = "143.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c88bb38d4c32e1b504b9cdda1febe256eb46fe7b764fdfb29f213ae36e03a47c104ae6601dacfc5237c3464523388b7a51c9ff286e9c34d419756deb7f31044c" },
                { "af", "1bbb5fde2d6c7c54138f3bf239d6f5f88f1d40b720ed2aef1d39c59a6d715559990c3e975eba76e7fa73f3addc255f37645dd57f9a6dbeb991bfc7afdf946012" },
                { "an", "8f3ce23209a14cb2750232146cc1795527bdfa6cf3401452ee63aa7707f0e5a99fddd19b7e1ae0e80e0f9fdedd68b9a75618bfaee7f344f8f2ddc8ce23ac7faf" },
                { "ar", "b3c6075e3ed318718bd3c89519f438778981239ddfac0826105bce174ac5dab7384234551d32e5e4f349e1120768337f71c6ca32dea179298a098afa626bf22e" },
                { "ast", "d3d4931311d6292485632b84c7c3d66d545a84a3df95d573e1d6f85e7af9b002ca7cb44c9648eef5ba15b62cc8673b6fe68126ae6cc243a6a0d6b613345d3039" },
                { "az", "bcaf4936e289070dee370d846564599ab35b99cc922bf83b30a11a9f08d7ea1b6282c2d55527f72711fd621132a9168cba62cc95276a8264a7bbf52d7c31ee97" },
                { "be", "53f756bae1f78183c4a0f98291d1376a720bc9935b23efa51004a8345fc6431ead324857e18cca41700f86080448ba55834ef782d6c640c5d5a65a05bd9d2b1e" },
                { "bg", "f110192d2ae63f83743ca04758b417c0c0a789ce3fbda80fce914052751b57f421d1566d1dab09f04190a7b21b9f6f3c3dbb5168640c7f507dc787fd2deb4929" },
                { "bn", "fe18ef015af359251182fbfc554d4e0131abb8c17d89c9278692aad7ce83335ee07a63c00e646e46c0762df2e94bce24e03c4d1529c2fc2ffa62e201ec891069" },
                { "br", "dc9c3c5199675bb21b3161682523dfba8d501d92326ed1ebbb4a27c6d1ad86b5546cc9bc5b419cc3b5ecc7a64bd77cd448f1e99140e30ba528d386c39d603e04" },
                { "bs", "58e318f862dfa3e686ac19213c74eb97e1da279dd6e70877b2e2b1bb4a8f86a5d6f8493eb47861c79bd8e65b714b3b474db2d21252d9b2f0193c8700417aa4ce" },
                { "ca", "7c80ac6c07c11dd5987e695d56591743662789811c9d08a85bc14000c903f4d7aa0c1caa230396151ce4fc7e1cfa7e5098bc86196ed61f059537d70e454e8e0c" },
                { "cak", "b00b857a77947adc537681db6620bb297c755c9531dc037ab05a38e0f0da441a7cc0d9febfed33f2b107d86297cfae473810f146dd3cd67e5643a5dd8f4f68c0" },
                { "cs", "114949e352493aa9a641fc3bb8f311b2d7dd052e7cba51859157fd23814a3f8ce8a5f1abde74e1e1765806d3ab258164735d170b7b2af54ddd343c81a439651f" },
                { "cy", "df155345c5842751a6d97dffca968e3a55bcbf6924474f2eae7780509f27b7b0ea2d82b1ea938f8591939cbe78cf32fefb0c604fe9f4421b74c7883f1e0cce04" },
                { "da", "7e88b09ab0a9bb344ce0e3a2bdc48f9de0c991f67686937f13b99bb076879d9b63f2fc2c9b32f6470660e13aaa5a8702dfea00d1b10cd1f7b4443df1acdb968e" },
                { "de", "8ef7574775aaa8873a5e142dd58b1cd7ddd5e8ef860b8e5dcb180d9c360826697f83a9d98dfbb75f9b9150679bfe17e243e0eaab4ddbe5ce8087fbb67b2015ba" },
                { "dsb", "a3c22c25edd93072e38b15a8f1959f8499bbf8ba656906f988d039a3f243db341d3f5467a493813968caf566db5fc9e4f69f485931af134ed91a21ae81e6baf9" },
                { "el", "06eb87c03d7b7d76160be7644f72457e4b9627d2d0b43eedf8ce1dffbc1cc04a08f33cd69824679bf857f99178849a7f815fef6e69f47f8fad16b353fb9878d1" },
                { "en-CA", "7f46ab1965d9ff80a2b07b1e16ce404bfabbf93beb232ca23f0de6060bcae954de5f83eaa021c2405bd6216d9dc6a68ffa2e48b6de3812c348caad28270aac85" },
                { "en-GB", "a1a6495d4582a3d24c85bdb2d43df04461980f862dbc26fc1f403a0903808ba18a7367f517530d3f37889915ebffcefea0b1a7eb0c2a0a6f85189001c24b1913" },
                { "en-US", "2857fe1a3f2b641ffa4aa0181a65b245d3877383f743a0b06f349556ef2b4a3efe034a81e14794c6fbca146e177eeb2c41bc0087b2f3c0e812d170fb4a6eda25" },
                { "eo", "ad0b9a9d0c7913b4bced805e4336d232d4f8342ee275aa98852a04e963dcd79dee4aadce26cdb907e421f7d8fcc86ee5a45578fcd1fc3d4d515accb448dec084" },
                { "es-AR", "adedae90604738d73aab00e99e20fda01bfd5e840b0d16221462526b35afce666cf4f94052fe30219d7adae30b3526a477db0f29e3aa8b585ae8b784796324e9" },
                { "es-CL", "fa72bd8fa647f4eb3e78f2143cc98e0857d4817466f0106e8be61ee3d0ca451a238c512de2782028c7071c6a8fb5d8afacf7e63a1050bdc2a1b46e490a1083ad" },
                { "es-ES", "c7dc765cb7ca9e85874c7fee95686aa06ddc8968d83e42ddc46a2fddc5aeed944e3156da3b3ae982c467aead0bedd407ce159f5b3305ad8a2f19d910a5da1ebc" },
                { "es-MX", "6c4137ff561d498edd6fb105ef4550caad972c9f94846095f56000c47d8011aa935786a68f2839a889b8444eaa3a08327d88d354e95acd8005bb90fd43553f51" },
                { "et", "778917661dc1a547342932a02ab4cfcbaa6fbbe0709732721323e651cffde10bb61530f3fe97bb09ac104e7de086ace901803ab15fb61656cbe4a3ed34ee7741" },
                { "eu", "0c66e16438077719160fc2fad47a50425be19396b1b5adef51f4f508d1e4bfa15f1c532e65c7ea1fba3824c0d9d29e6ba280e8c01cfb379d7077aeea21ffe3b5" },
                { "fa", "012628e37bc077204b409fbe91fee78dc21904f05541d9fb643aecc371545f9a01e10bcffeb0b639fb2c16859281369c721cae0a1b4dc0ae0a9b265bd8644acb" },
                { "ff", "f68ec5ef36cb813b95ff39399bfdf562dff35cfb987b398f60c2fb0f8736e1fffb88bc4c95f9ab53dc9818b03189a1f4467fc47acce85c4d275ca442604c6824" },
                { "fi", "1902106c1786bbee661841abde9d11a5137ae6b1cd6a8e7fcb616d04b11d6a37aab20354c58349d57b96b6c1ee22a6a8b913f06e3d472b25bb2cc574d484c1f6" },
                { "fr", "236ec165a6bc04871da4403aa45a4c322d50703e7f794996bd2b87ac22dc4fd2c93ce87f5c2f38d2fdb37c587d175d4634222de30a6dee18e1a1a5719e0c23c7" },
                { "fur", "16408e0faf6d39a32c048b74c08a1dfac7c4a8afa2fd4b495067fc604fe7a21ae96f6defef342285f32619a44e6102c2cfba113bfda6bedf49656e3ca117700b" },
                { "fy-NL", "4abaa0e7f702a74158c37d68f54bd9b9d4b4c388d28ce7a7c2996f4b681d7ed05493ffcce448e16636dfa2949c978c7bae56f117422a14757d2166389e7a106b" },
                { "ga-IE", "bbacccf70a026ef1d6705f6301fb93085c76246a977b77c9954488d1f2d8cef45769af625530d6988770fb5615a111cda0f6611789455841453932fe110ca2c0" },
                { "gd", "bb3e72bfb7dab5cf0050f433f7757f6d11747b73c56546a704612023b8ecc721e4bde4795b641c921488ce95a115c07100fb4921f1566a2c47d9a6d86b620ff6" },
                { "gl", "e81e4cd579136159d427116bd7ce5eed1254b84b778d56f5b018fe4397bd04bc863df5053b0df0a3afd6ae1bc017022765aa8e530b6346e9bf0c8f60e8ea6bd6" },
                { "gn", "ec92dff0c87830e2c2ab41edefd43d8c8ba717af198010ab31c689619f0b9a47edc78bf5ea93acec717a463225d3cf3fb1d13c2434986f82eca5dd17b1fd2994" },
                { "gu-IN", "bd0350f1b455aeba753cd33e5adfe8fd83787d3fc38ca5c694ed7e57575ff071eb87268c7f7eac279a2c0543edc67304d1d7e92163945b09408c9bd175bb0ce5" },
                { "he", "1dd11ab2e4a7420eadeb3721aede0500b0c651fc0e710f6574eaf969ce00124bf224dd2bc19fa359268bbcdbaf374056e20220cbd0de5becd83791aafff1be1b" },
                { "hi-IN", "d66192ed7efda1ea0fb69915ae98d92dc8c7735deb15493ecfa85d66d0985f2ca036597b18c37dfbc926f8ddcf3a036805ef61ef440994a25ad3724aee3d8504" },
                { "hr", "601882d3ab1c36d3a2bd8a3383fb80b77a6a38ef68cb4b991ca599732a213dd090622b8bd93b149648f389fb642112347fba4785bcc74670a07a1ed7d4d676b6" },
                { "hsb", "bfeeb798162aa0a8271341e77d8d029643f0e4a40981ec2a36f233b4928ba194800731582d23d36647d1ca56f8b7455a01451f104dafe4f169dd4db15704d055" },
                { "hu", "ba68771320ac637e14bf0e8ec81f6c5e308cfce5ef44ab0e9e45fd95a981e714b790c78ccf548ddd7f54f15027489f9ab5135a6fe890b739acc8fc242d01e9d9" },
                { "hy-AM", "e10a98fde1ff8228b88fdc2cfb0dfa548e273f679dbd952e7fb8f2682fc8b4ed05d60969dff002d8065e3179d0fc9b59ecd95db7666f25fe6d027406828c1622" },
                { "ia", "e27e3ba19886313b5eafc1bf49564f3caf6ef7e16b8867a87e60e6a6cbba498eb1f12952fcc83f4cb0cd284a4829c4ef1b2b56fa1ae7c572620b0882b3d71a21" },
                { "id", "aab98aa5f626cf032f86ec8409272e62571fab1142bc83f25b9b4b7881493ff820075cf5269b957c3997d42d87d7099bdd9994359378a158e5bbb7b1694f70b3" },
                { "is", "2c94939defc44fd2a1b4032d63405ac351fc9d9bd63aaddb19b7215129531e8cfcef158e3c569bc425c05fd5dbbbe42b5a38445db624b44ad67a2cbe928031a6" },
                { "it", "f92dcbb36368a6abdd1911aa4d4bebb2e0c2897df76ba4cfb0cefdf09fe591b7c1ffdde133f9e38cceb076f6666c9559b6772437ef5ae111265359f434219515" },
                { "ja", "b34293f23f0414b428ac2d95faad4767c8d67e48a79e06c545396aacf6c8a2a7cbeb93b2075a9b9ec418466a7f83abd2ed269edfbc1ee9f729c14cf2cd11035e" },
                { "ka", "de881ba1d4e4b04efd5ff523ad50558a3db1381da57daed9ced4a5c9e16a99dbc23c519cb0138e8633cc2a4dab893850bfc9e43c12228940641380960bb85e99" },
                { "kab", "461362074210c3e4ada8e1089c12a87f5678ba51254ef4e31cc6df81505b732cca6110980ed2c01d1a64b868099eef32d938f091caa9e6d4d1eb89600ab41f9e" },
                { "kk", "38d7207d8480f1c4cd8e1aa41145a0f476275c1bb7b8d3feb4c1493201360e5ef3a165531b9963c185cfd95bfb24904b96c80ccfec7c80a56903775085f978b8" },
                { "km", "2305d8bf290243006c599e5bdf4374f9133a5457201e07a8429112a343a10c6ecdb0e203e909ab35fcc471a6c43341c7e0ba6717bffa1bdbc91430bcb449b231" },
                { "kn", "21bb470bf84e09a81b3f12e93a3ab936ae8403c29d3533f5c5f3dd6fe14efccbb8ea7fa0dd1c08b84192b505d97d0274e95d126b2002a4e140c259e3b507ab0f" },
                { "ko", "f19ac92a468e3ffc3098073beef6bf4967c1cdab2d7e099d1ba3f1b60f504bc5d9f1dded0a0124aeba13673defd3ed79bd257ed262bddff41eca6cf142670cb5" },
                { "lij", "27a53dd330d4099296217ace56f34f4b79d7b6bbb78ae31dbe3de1ef72e4090ca5f2d0c2007ec2be755d1a8fd7849693fef30d470765ca88b20d27c9b8b6d0bb" },
                { "lt", "86c3c10038a94ea718d54d87cb01592eeded5cd2ad6f5168cff721c497e74ec736290b820f4902606c165d4e6798a947e145a14a6124a5ef2746c4f99a87bab2" },
                { "lv", "07d8a0175c49723601b491cfddb2704665cf68244790d702a84fd46bbbbc239bddd49f2286c6f40af4bbeac2838bfa5c9b88397ff6d33eb63cf2eed8a3e49776" },
                { "mk", "b8f39fab8789911784e5dcac0edc37c7f3c7e69343cfed21ead39c0bf20be18b0293dd0c6b498329f8c25617365f2e083086023ae683c1717820d9820d0d829c" },
                { "mr", "8f62845a77527e64ac17f622e8c36a4423ecc79a33b601b722cde0d11c2734867640263ae3e48fa503dc8163a92ce7968aad1a5a079f721b378e72c36f2e2eed" },
                { "ms", "e8a68841baa547d8aa5c397d6f95376ecb4339ba40b150e9ed3e1a59549beefbcd98c1a0220a0b4476b378bab96708169b7d20283d00930da6134c87a84e5e1a" },
                { "my", "e48aaf5d1bae87dd94616319edd03b0ce6107917765fe0aec2af1859e199633371b0cd8ce6aa1d2eb43fb032eea9c0ae51da9cca0cc5e357070a548f30d899dc" },
                { "nb-NO", "07dc7061a6956c61fab16ab8210b5cafe46d107d379922d73cfa087f0a7deb2148a225e093de247169c85a5b25cda1946d6033c4182b6f47df23e2c6f28ef990" },
                { "ne-NP", "b335c1048e8c378d610bd7bab0fd77813e7f2575ce4f70a00f31aab4b3320340a096cf32fdec3cc6e0b21a247f9aa2391f688432da2469ca571bc3daf6897c98" },
                { "nl", "bd2e6ff1ff2672ca3e3b15664594829ef76d18a3573a7a948c2c86d15350e1f42f1e57beb86efb1cebb4d043df58d1985684e40f4ffb79b635bac560f9de58d7" },
                { "nn-NO", "8d6b1dbae937ba8fd7c4c6005aafc15ca50cd76f8806fe7f96ac98ec7d3787d565f4cbd9e32873719744dc64f76e8356093d709df1b04028f9854f0ffa27bcd5" },
                { "oc", "4b10cadca6257d909608704c5359fd7ac37aa492d496cf84fe7a77351517c91a15c7f540b21b951940bfbb5b742d709c29d350989ab40ff2a2e78d25a7343d7c" },
                { "pa-IN", "85ff68c9671d6ba032aec1814baa7c30bdc93e9d942044105be5eafcc26ec22d00429e3edfc8966f53a2122d313eda33ec4325e8a4308b8d1ad4fc25e84fe186" },
                { "pl", "c2e683717843018817ea97aebb66d1a8ac953445a166ce80807e6e4b176792204a6ababb9b8062f4f6dff0c27cfd70f8a5658948a2c9ba68848c5f6484ff7f1e" },
                { "pt-BR", "5e62498a9a3638974aaf4de89dce7712ff51897157253fe187e7c774899a27c5bc78d35b2d083566b478da8709176c5e15f4e01bee3717c5d458b9d1913c8fd3" },
                { "pt-PT", "08c559176b2626cd579e2f5e22677018b726a67725544068b0b8b0874f3ca3f44b00e3a560ab5a1437dff57f6e2e966024e50fa9d04ac09f00cbd9a8e49974ad" },
                { "rm", "1369cfb748c8c2ce4f4b6ebed4a819bd80f6cff53af4937837504846243166986d9136f2b2c461c782f7559f361591135af07a47735aa4fb95740e1fb6872e66" },
                { "ro", "54364601af95f6e8ffea844ec979731eeca1f2ff02c67af9384b8e76627b4bf099e7f162b320b2ff58282a037fb415915398c9aacba477dbdd25d634183a5b7d" },
                { "ru", "9fc6694ccaf283f280847e1f200bcc55633a204dd126a4ef85d25c7a6fed29f73029c979b7f9d7805d2c89f4a32a5e2956d21f5d27e4e6e5968177bba535d79f" },
                { "sat", "00f8867ac08b75f7d7e9e14b9b6b588d457964bfc40d2ffaba906805e50232a6c1b1a00d389a0f566ab08389c0d166d1944388c14e16e58d837921a1aa58c131" },
                { "sc", "8ae84cf68163be002f94df9a500e062c4f6a9e03ae1118c949b36132b202f1217e925fade60a1753b781c43d2a72483b1f1def55283cd3d3438d499b14be432e" },
                { "sco", "16a846d2615683de11ff0378734d766988abf618fe8aba2eecc2d7b00b292713a122e8e372c6576977e9bd6798d2b61c2a9dcc294d83ff877a606d58f3ea7756" },
                { "si", "9714f375578b15f1f04dd5c74850e08d481ec1c92c3e6c4eba81c70f5780029eb584fff389438de56af538cbcbf5fb36a293bae40b56697e8b914fe7dccbe7f3" },
                { "sk", "db67d9f0cba3300726af67c01520a4b793dc0810e2297cba97a068f00df73433abbc206261bf70fd0e8b9fef3b905501134cd0c1c418fc548c2afe5ab5a338c0" },
                { "skr", "d7754a8bdc1c190c8f9d7855593d2958679581abdde204ec1f268913a63df76c81c8ae5b9a2ed942c5b563a436c41f24ab3c3f94aedd853fb302a1f86784eef1" },
                { "sl", "e32779d17a4d6c18aefc89f3a4dd8a18c08b3c62272570cf26dda89cc87e6750939d71d2da7458d33692466ed1a3431263ded1fbabf555bc6114a8a6d7c6b57b" },
                { "son", "fe2db2126d2c8cd48b0a0eb0c2068efb02e0f953d066668cb7c4ce5a4d5a8c63a356db83ab99269bfd50f64a0142ced9536549eb6be3e8cf84a2878630f761bb" },
                { "sq", "ab97d98cce394ec0579cee3bb09192485efaded075f106181d9b4cbee1aa09afbb3dda9333286f26e31df1f94262fcdb12bea0dc4ea66793003f915b023cfba0" },
                { "sr", "8536bac8f2c2edbad4d38a7c9e6c4b975cb12420b57726ce345b3d55146c9e8912c1ea10db4e6b51ed8ee068d09d715207d6269d23627b2c70f281edcb778ee3" },
                { "sv-SE", "e731877823a289a9ae5209b0e3f35c47e70aa3dcfd39c2b2053b3aaa0b02ca583c645dcd5a4c0297036e3fe963753550391b26745ba458cc821f5f277ede903c" },
                { "szl", "bf1277d72ecdd60140f42ec0e41f3eb6b9efa11b87e2c481c9d5049b9ada4d466daa5ef3d189aff454ff07eef1ffa4e26c000eaf7a8ca882a0b3983306125957" },
                { "ta", "b709eeb9cfb1039818d7c4235f3c702b38e507d713c49420fbd8a4ef41a025eff9a8154efcba5aab7733588d3fad6ff99c6ae9a2e0881dc69224b99331f45f2e" },
                { "te", "2f38bbe40807b98a4db358bdd4d74d70a453a491cdf2c6d4839040ee67affaaab1ed2f2abd73708337b9c11cf54fc0602176c4426fc58e976a69ea84b87f3477" },
                { "tg", "da37cfc7587498c451fa6d02c3a706c053c8384cf778931471b13fce45b24713d5ef9d7ced5f20c1e33247b8c1daf9b92c9670d7ec713c85d159eb2dbf7f7464" },
                { "th", "77cd934c0749a6962cd34d063f42558e0428b4a3135c9bb6837754433eaebbb3f697fdba52d0fa9f4621d2ffe03e6b700fe626de966ab59864451e6fed3cd811" },
                { "tl", "e2a638c8d708b1b6bedefc47b1c1ea39b4625bf0e3b250ff3394a565658294770bf43b22d43197b62b743efb6a6642004fbaeb602740a82be3aba340b5105017" },
                { "tr", "3bfbaf9d648209cbe8fdfb5860adaf51048a937d8dba27bd5ef8ab6adf60940b622efbe0bbcc98830e59daa48c2143e17c8c7e45cce2f354534b2465da804f83" },
                { "trs", "bb998ee229d590b1409ffdf58be9bf4aaa27f87754ae6bdeba60d66d5020abc80e38049636bad2bf5c6542c11223e5b8d5ff99935c5eecbb19c805797ff76aa2" },
                { "uk", "860b4218394759ef9f8d07e00f671951d8263c4ee1b5612379fc83a1aa9c1afee4c4059c18b17e2700c4fbbdbeb53967aa3fee33e646d377bfbe18ba621de82b" },
                { "ur", "29540f5ffa2e5c4674777a5254714a9a53afe5a41ffe5125db478697ffbc1830df788222cca9052b2591c60b09d673fa97b9080b54e2fe4597d80f735d630665" },
                { "uz", "06114dada9d7052fddd6b0c2f66613501386bca96c2cf087eb12384e8f1ae665cc810f675fe5ade9351d24dd8572be0b0319ec79c0e3d900810e9e83d7a8989e" },
                { "vi", "a43290a46c33ff732ac57aa4f1de5ede498e46dfd8620deb15458388818f5fbc57203195e5055c3ba53ce7a9e3ac3e1fd8d8e1b6d9a436dcb2c38e5729c14919" },
                { "xh", "2ebc9eaf63558d53cc657b9f5f9a12d50db88f1a603648b773f6cad7e8c438cce5424238351919555e68bfafea5036adc818d85baff4607e40ba50742e15b240" },
                { "zh-CN", "a43f1799f97fe35a0e16010dba8386980caebdb5c91c6f59a13ba3523e61333abdc42b4cd71be3b29ba90293e5001615afa5393649461258f56a159e6c280580" },
                { "zh-TW", "2348db1be9307164f792c04e442f6cd337982a64f01285d2d7a6ab9acbe4fe3951a838ae54f35ff60d736ca2a82f87e17cc0d0c5e8f48c88daf46405f5335ef4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b9bd6fb39d74071b5879236dd487d31690606756ecef44c85ce71ddd1013c8b76876c27e41977aaa8e95b8a14207025d96b9ab8f7c6d5b1d2a07751c3766b8f8" },
                { "af", "596ced7e7b2e45ed52469589f68859e0480a20be3bf78e0e77ebe49141da9af1897b07eb413b9c8680b72fe47b62d1c130b754946dc6a1c96d977ee3f4f85d78" },
                { "an", "fd770f73906ba006a2e6d175bb1313328371519047a1fc03c697fcd6110c895a1976b87d7875c1b264f988290409a6bcddf0e751c94641156d9d52c8783ca708" },
                { "ar", "61a15dfad3ce858fa38870206aef42d3ec73f79e5d39be3117314ecfc03aa08b6f2f5e0f78bdbbc4282d61dadc6404d259f71cf46a521244ec93e13ecbb1f4cf" },
                { "ast", "b6ceb5d78bd985949738f1f056aeb8465c3efb21df9e98dd5011489f94bdfdbf5f70fb2bca3c8e60eb45cfd2f11559ee4688d7cab227e249eb7dc5b18668e691" },
                { "az", "08ab2d7a0bff509259eec7ecae22665dbf3d614a647f9c421d9aacb7041fbc249fc788e2fe4319445ae047aa5d1b151da85028fe96526bc5fa656e9255e6cc00" },
                { "be", "422cf7058b76e197043e68bc7234da82b4d51715ce87df61cfa81505296da6f179936602b33d5a905758279214e2399d567ad60353da61017ee4ce6a5064d494" },
                { "bg", "19a3b1f97a51bd9d53b0c38a38bde8699f1595e093245bbe73f49f0d30c85a156212ab06042ba696804aec83b4d451c665ca61836ebbf729c7163152051a7908" },
                { "bn", "56eaf1fc766e973c6cf7cf675a6b2322c1268da5f0e455f1b57b5be2a6237fdea977ade5568f9762758d7984af9512ec4616cebac610541d74c9e89efafdc996" },
                { "br", "a88218bc20e86d94cfa1c24a50be9de40020c3f01e8b7aabcb43fbb6740ba1e8eb1c1541f7a9cb057d1f2553e5169d105090c448fe195862034013571f150732" },
                { "bs", "34f796bc00773462e5a416fbefff2277a79cf8566b6e779d424e0fc73efb3bf454f9e6e55e4992763ff56c91d94c7ff03dbea415e144fe318fa4bb9c115be009" },
                { "ca", "90156f2a8a1803b0ab2a7fb2abc05aba4e8825dba2729b8b844b838aaa8cafc6f09ab14fc3d5d196f7aaa5ec73f41da5d77cd5b7b2a3e511a1e23020f5f31c8a" },
                { "cak", "40df23b1cbed7747ad9bea9511dadc0d5f7af70a318180bac7c18b5d8f63a9bb69bb70901cff2ff548f4e9642a09dc998b46a3b1e3445fc5c8901acd79694720" },
                { "cs", "8989e553c94b036476e8eba028f82abcb81bce531dcf08c1840e0e1b9921d5c42317e98e55e99f47eaf9a88ba530e51e7f2b9a224c8b2e65c38bec9a3356669b" },
                { "cy", "fe9416793ec47bd86ce8e9b31b29b6520506ccf529b9c649c794d21e54c1af0c51c46d67a619643a4345b50e3351f506b4a251c1268e9ddcff802f3bc71c97fe" },
                { "da", "4b9a4670e798baada14575d53b08602ece50b6ec733456bf3296b412337335d5b835b5f9417a43e4dceb9591aa4cd9e77d75542edf1779c91ed654cdaa689ce5" },
                { "de", "dbcf6e4c55ae6e008d7e24204b69e6fe4239fa0ccbc982995c5bee3b27d8cbb8837647235f81c79b6b30f8997f49539bea4d2ee178fd12c93378b284e9cfe07a" },
                { "dsb", "8f4362e4efae7fdbb95d2051941b3f116e88e928c125ebc55555e4e878e1a873caa3f06ed69945c6fe6af6f98a955cc9f0fbced4b2c5ee816246621a8b3aae91" },
                { "el", "08352d557da55ff7551dc4134fbdbd43af2fed1be0f460bff41200c4c315cbdd07d8819f2b5a19d154954d3c49138bfd4bbea3c49bb50dd2d93df4348179352d" },
                { "en-CA", "91c90d019cb2077ea9eacb0dd358c0af239cec0da5379690f3622e97e5708bf7db907cc150d044d9a53c5d93ba0368a9869418c91e26e2581a5f89186a234bf2" },
                { "en-GB", "1cb4160e7ea06ed45bcf99226a4feabb3f45b0dbd4433dd81fa38c4628dcda0b8b51f5fb7836609319a6f00a641ab2d75fedc8cf4059d2c6f99653c6fc04b3d8" },
                { "en-US", "d627df68ebc6d71a24357ab135c3203152b6e4db8602f1f41c20ff7bb4e88b59332320031ac0e23f6f7106b0332fbc015bcb62b7b8e9fc1efb09b96206cb3fe7" },
                { "eo", "6f32a78fb6614ff2d7fc407c9e106d0ce85c9974c09c663924d65a1de8ce86f85cc152a14265bc8f9fc9077289398598063d5d9b46403b5f43c550e4b56e4313" },
                { "es-AR", "a525f354ea8cb092030b6c43d862048d09e6f168e95442f6251149b9c674a6d38a576529ecc7544f88f3bb218e352253364ea5ddaae2f45ce3943764ace68b46" },
                { "es-CL", "c56f7af379078630450a48bc0150517d5e1dc9ff31eb0d96079d604ed50f8b8f6126492210da4799787ab5cbab6cf16ce1581d2069940ad210e4e34805d7b529" },
                { "es-ES", "5213072df35bc0bf24d5b4dfae5477285f76c41426079db78d1000cf7dd8d5a1d6fe65b60241c9153e0271b380d90b21e3b61ae2074ef50ff4f4767c01d1d1cf" },
                { "es-MX", "ca158c0b20439b469130799c20266dfdd611ab4c70ed1064bfb5ea5c6d98aed57f7bd9e26d58a90e427ce6b4b6c6f0ecafe541b75454110dad48af5319b32189" },
                { "et", "405ab5377aecc783f5990a8f2c945c50fbfe0b9b7d6eb0f6f103435fe1a05d3aa8be83b3cbbe0c87a2c1a329d8450764bf0b7e3b54e38e143b66e5a4c353c536" },
                { "eu", "4235c73b59d0bd19b9066a23c45ed814571d78fd07efffea998f0f6af37d424cf2c48588eb32e5e8e20e000a69fe9b14ea91cdbea5dd14a0af7f6e6f8956780f" },
                { "fa", "84f0ca19a8d4dfcb795ba5a7484d549f8a0cae54c98b2e41a67d98783ece075b9cec937d3535b6b5b5cfc751bcc755585d785cf93f9ff8adbada9368193e17c1" },
                { "ff", "59b32497de84025f9c9fd380afaa79cc7e93785385814e04a90ca210b3d1ddc96dff19925752fa566bb27d47f8a275ec532a5cff9ae0da825cad59060e7786d7" },
                { "fi", "9eaf49e4f0bc7c022fafee1c3bfe58a34eb4ea43a8ba192feff439ab5c3e7dfdd316fa77c8115c906945a49b7d6f18951194f89712f810dfee44192317b09232" },
                { "fr", "5878659bb436b5e74b102af42c02acd0d0f6f76b861238233cc69ca1f754e8515540f642c2207a51c8beafdab5808b20ffae50a736554a101c1b58c3932e30ce" },
                { "fur", "257b23faa1a596a16ddef1cf79bb153a98ede1c2953099c7c4b614f894a49057b520ee175a562826c7c34b285d6d0464792232d6b1184f07c196f265a1b7a776" },
                { "fy-NL", "d830670fe4a3e7fa058cb1d411f52ee703f18a65c64f80b004423f4e26159f5db5eba2f822a38242e204aa992e1a6d7c86eabf944345356ffa72b13328fc50d2" },
                { "ga-IE", "226bfc547d25d62547ae76a831d2cd8a37773b6fcf12ac0c55c753792b6628955b9309ed6128783dff34a0a01a9076560a03ef1ccbc00edcbe958cba993a6478" },
                { "gd", "59a61f75d064bf148ce3158f7acdd20256f62567027ed3ed785748e30c97cc63ab1dbbd30c024bc64ca48435f964fedab158e2b0696c93bbf94564df7f39eb2e" },
                { "gl", "5d316659c5a2a19e3c304fb07daca1f9ea2f293e071ba2c2e3a034fb4d10d3ad601adce39514eeb6bccfe963205f6c5e41616012d3cc523ebe3e7dfd9a74f6b1" },
                { "gn", "13e6e1031c6d9a7236ea332ed409dc4a170ea7557d440e9af3c6f22be426cbcd29a7307567a2dd841947176f95f7225a45cb0fd3c003e000856dc17de7c8a853" },
                { "gu-IN", "bdb36adcfb412df646092e0beb9868607d90e9475de30cad6aeb084aacc883e18df996482803b05170c92635bd4aa5f6fdd2d8c2ec76ea08906fbd7956f6d670" },
                { "he", "26b5d9bdfcca53d99debe8118d97962768644bafbca3442538a1337d6de6ff084c5c290347250d178483312c00b7f1defed4425cd86297c5145e41858526a8a8" },
                { "hi-IN", "516425b00e2f6db2aeaf644e4a37449f391c30c8223708fb45eddf7eb517aac58ea9cfe37961fd3ee9b1f2956107c241f317079cbfcaf5cfa212bcb90209a048" },
                { "hr", "613063c67e8e1a80fa89ab2ce418510c41e98a8dbf36ac50a7ba5c902d4e072ef28c406ef2cbb0a4147a6c82cae531c27625908fa1b2f1e7c84db91e6654d761" },
                { "hsb", "bce26747cff606941a1783ddc5b3ef2c9744e73af9aa586b734df764c898eabd96ff9369a9c17eb3b5b484a2884b4a7b05c4e584ebbdde1d46aab5d05fa88327" },
                { "hu", "2d74d200f0452c55dad92db29fe0c3c06dfe2d50d0bc22ba006fae00b58fc4fb58daaa133b6a9c2f63ed505f22101e81f5fc90bf22039f4876e751d2762d82c9" },
                { "hy-AM", "2706768b07774d6deaf2a4bccb6a1819ef8e6186a372aa43e0f41c468a270efd9b7fc8e5fdc7425246032202ae2e95a54ab432e30ea27cfa8aefc7b1e8e47578" },
                { "ia", "ae0c9dc401ba8191045508c3ac2e0d8d3097e0ae5acfa8123b97b10cfd7f821edd7812b1de030a9a5b3a2207443e1074489df9c9818980f5d16fb19ed2eb2d1a" },
                { "id", "2797004dc3f8847231b1323a366161479efb2b791d5d224d9f9054cda2603ae1f30a01cd03832d33fa627007131b922a59f758a313713ac64ddb80c16da94efe" },
                { "is", "ac333c2879829a716dceb6cfeae5ad43e8cba7445c5ceef62af51aacea6e335198d9768047ecdac5f4fa6780c4648ea3b0f6d73f5174d038c013a7858ac85af5" },
                { "it", "195fe062c5c1069bcaa4fd3cb1a7807ae0595fe1d61957aad13241facb30147e0f29840c4aa452c44d8981c3bda20368f08f8b3036a40edda6e84da35e0c5801" },
                { "ja", "44f500c01068afd961f5cd4833296396d157b39d4170592251b1f4896d5eb4a0c0028a864be68c0cfa5920899f195f8348e3f4b3a50cf50bc41812e050e3d14b" },
                { "ka", "8ec8dd066ff9fc745deac741d3c33022c3a8644efb00afbd0922ae1fa40dda85b836c6cf9d68b1fbe3abe516965290128d8bf74e983a4b40410cff027c8fad48" },
                { "kab", "3f5b96c1cbacac709ac0002a5e50123f801e5e98ac1f58e64982a0ec1d4ef826567b82111a1309750a88151ed761f18552e0a844db8a23c14fddac6495e19857" },
                { "kk", "91f8fbedced1a6013009d9c68a36a1263521415940e47eda8c0fb9171d3a21fdbfb4dda9a8e6eb75dd7edb8b2d6134d58ed1b4505a1f45445bd6e3e01de2987d" },
                { "km", "4a716142421f2dc356bcf9c4dd18ff4f82aaecb9b282f177931f27baaaad9723d0d51dacf43e92595d0acadb664084e9df8df700745f68441bb84ad88a95bd02" },
                { "kn", "ebd57d10bc4afef26c316622023135767e1e063bd307bdd4be7b85e9fc18d7cf484bcd61b8637a3e0df414f19c51fcbcb5d808b4b3c11c46896234a1e94e4bb3" },
                { "ko", "0bf1f0251e6983c408679e1ed88d07ed7ea77a8c47eca0152aeac9c2222754be635b406ba4e6d830a658268f543b447db4d84e3af0721fba843eaf980c85830c" },
                { "lij", "5086d092f9d9abdbc96debc1e5c498ae3066cb277e125453e4ae3c9cd14fb00261cb1322f6d4da7aebbc77d6fb9a2303a1f26f78fc0d55d8e6b62d2bc1f866f2" },
                { "lt", "5e7de61d4884293bab2d6d507354948cc9aecc53372c30b245c389b2aa5bf6b422a02bfb628089063585ea5da48b4a88df0e5569b4eedcff9d7ec79ca4dfb1dd" },
                { "lv", "960c57c6e063a0681dce89c8ed5b605f837bc562ac752efb31391e4230d3c407369e65d1a71cd797b25705be180f83ab8a9dd306ed9b9029b1e571c48fa3d1b6" },
                { "mk", "92cb009c6c847d2e99ef120ad78bc2dfdd85ae36d14499c523ac97581cf8415136986d2154776a5396e17ad3613242b32ab5bd42dfe0aa01c672c62808854bd3" },
                { "mr", "9306f7af4548922cfac1912d3a437a4f52376a8d572cabb33813151c01b4d6f5518618e6561fd3b0922f2413cdcb1e6d6ae9b2511be81de3bcaa4cba2f5e51ea" },
                { "ms", "0bcc953d8bede51ffe660b01a2156ae5715b5535c8231ec21831ca74c1f50f4c1c83a18149be27d456ae9573c20a88a53318cac3da56e5c7c9bcb4b1d223d15e" },
                { "my", "9092a396d9e6f94b60713549e23ba0236d2ebcbb3132bc91f336a1f313049a828d7570b16f2c8e2881994a1173dd206e41fc7929f7559f4ea4dfdd1503a54cdb" },
                { "nb-NO", "690567b3f94a09bbb6da944c7e07731662e45391a9fb6deaddd5a017b9ea2285a9c1ee89040b0bede84cbe267e1ecb490356dfc065ee5d6a5fccd073746e1ba8" },
                { "ne-NP", "75c76eca0739bf263d93d4f1824a7da699d0b928e412a1b0b042c5a2f51d69faef97e480d8f02d3b829f4a7460eaa3aae632a376ff976ae653a43347457ba212" },
                { "nl", "d29dbb43d135ffa84859ef253a54a0455c5dc2f7f4c1327630524a52496c65a327435c1b2f7cbf541f02af9f1084beeafce0d41331bedcce5235075f0000814c" },
                { "nn-NO", "88e007259fbb080ff159351359921a9209abb943a1054e4752e315970473f7cce96e4ad456406bba830001a43f81ecb3ad6b75479f45d7abf450aafd8160dcdd" },
                { "oc", "59fc6b0695547809cb033fd9c6a2229f5bfc1aa722d10d54bc7a4d4cfb164d254c134e9775cc925123770984dfc554186cb762f3c92a9b912df0cd545ae2e1e9" },
                { "pa-IN", "e4194db3dabc1cf75e1ddc83a8156fa74346f8d199bbfdb29167845161649dabe18ccc7ba52b2396fad0270219a107fe13ab034f4c4146696aa542e5dec6f3ae" },
                { "pl", "7c36b292005bfe7a33a0b246245b3f9789a5b638ecd98e6b7f3c73cc985ca392f11eeca137ee71d43c753e69f4cc0284c1d116307a0e1dc9e167c97b0e1aebf0" },
                { "pt-BR", "8dc6cf46dfc38b1d5bbba518d782b37d26f990fab9c81df7ac08d60c8b65fbde6160a743297c819f63c8478f1e01c8f7765334af3d35617262514653f4182afa" },
                { "pt-PT", "8b2b5c018f1324e856188b281399803cd53ddeb161bdb7585db28eb492cad96035831bca4986e0604fdee97d040552d573fcfaed04080ff37cd5b9a17b7551b1" },
                { "rm", "72f18ceb1efd7ef0a0f9f557e6e09fd176dc5f2e6986b4c448755a3b51d97eef9d8c93b2262db94d551cd72a991ee1bcbf59d693dd2e7d8fdf24fadf2898b9b9" },
                { "ro", "8122ff80e1312b49060ffee38ea0115293f3f60ccdb6dc7ef3b1925c80fb28f6570c2fbf8759b55a22df6b38979e0cdfd83f6895cd2dffe7c3188fabf685dab2" },
                { "ru", "e93aa1278752aaef572033295f94f76afc1cd36d211c743cc08166720129a7a596fef3a387c2d8971f1320d808adecd4b47fcbd0cafca583ce9cae620ef2d6ef" },
                { "sat", "7c5138dbb7e7a7f2ae435b81b83aa34b27819a56316b8d824ecfdbbc851478bd3ccc196a70de55e4b94f34151715118b82e4d28d9b3efac3d26bca054a84adbd" },
                { "sc", "e6f6210600dee9bae95c6e8727fd35ee60efc3d1e9fd8f59ed160554f332455ae5ae002d6b9eec58c523e2bf4c931816d0376dc406895f665b1da21de9001ec3" },
                { "sco", "a314687e110194e2408129c15a8576d8378621b6022d88ca45b6debc8e6bc58d9ed56bd3d9740cb3597746b2baae7c9e114b6e2c39dbf897b20b1d12623bd916" },
                { "si", "658f2ee482c9102f51b602cafb3de99420dbc9840c59b20f2bcfb0e9e36527255aeb333efb5ba028f074086cb2ae386f249c828fb80d038fc7b9945b36a6cba1" },
                { "sk", "6261308cb2f4a3248a090189a96747f1877df0aecfe1124492923876e2f9d5ae36e5618802a99c605c84569d41d972d3d57d6adc41e94a2c1ecd9cc9b625d64c" },
                { "skr", "a15dd0d4177d566c3e4b1cdca6c3cfb09916a9405ccfae92e2648a4e0e96f63dfd0cca72ab248578a4750c79e5ceafa14342d5fceda11cd57d02bd41975a348c" },
                { "sl", "c6dafea1df8a269fd185136fdea9fff923d3511b0b566cb1595eb60b2a92d43616ecc7a5e3b9d2c208e3932c0087919ab0d8080ea9330b3c5262ad20aacd8918" },
                { "son", "a68f79fdd24c67d579f750327b6bb28e490465ed4ee66655677a4ec67e6b25834c01af5c261fb6c69de95f148be64d973f2d9b5f0f6158902ce9e2064c41ffd1" },
                { "sq", "bee8bbd87bd92d098dfb4cdc71c42455fcc0a920c6d150032ff76f2c3b51c5966726282bfa7c06a4b61482685bdf2832239251f5b8ed5cbee788012f3cf0079f" },
                { "sr", "f2d3136f37f0714f80f17dc80cad7c3a28e814e98c0d5e4cb1a609742326eb7446549517763d9ad1c33ddba7f8a0cc8f155ecbc9dbada79a03c9b5b774cacd2f" },
                { "sv-SE", "806779a6bb78d706e3d6f0d42907b0ee37422dcc49a817ef72201061a99a52fb0923ab1b9f4f264130610d55a82012d746867c720ef38a6eea5fa940f8143fa4" },
                { "szl", "09dbc3f8ca5688ef9449bde5094097e94940dce88682e9fa0177276a8fc20011a79a9ba1aebb8dfe3d05340249e44ef8f62caea740390c27a715e0bfe90c8386" },
                { "ta", "bd2de3562762fa9c1fbe629cde06ee5acdee9decebb8fd78098a453faf2e9e0f998602c8b882ba9fbc6cf38fc62e52ae73a942e4f049990c33a4c29e62f82523" },
                { "te", "9e93a16578492795778b43c4367d636964cabdf4ef412cd0c214c26d71d59d72a89c5f0b9be99c6acd2b2dee09b9f87cca4843820adcde14698ea471b543b67f" },
                { "tg", "937849bf83bd60372fb98ea3f86a6d076e529d4ae8ffdc0b4929e3b431f77f82013616c14fba955eecb5cb6056263817781e01d05fce947b9ad525baaeafbdec" },
                { "th", "a20b8d937c03c7ea984f483037b7a5d16b53e75ced0034bbe3e89d31ba4c547cdc7ebc61036c529384f2c600eb7b9f28c155a8609418b226575a142b070984a2" },
                { "tl", "9c1446d8aa405335a9d4ed83115481c1363668dd3125d4a14a59f4eec57b255dec8e1e7f0d4d21e19a88728e40daad002dacdce94dab3f4ca0c4f676643ad882" },
                { "tr", "5843fd7c7402bb7e9c7c1c9675011efa4a2a585af72bc4b81d02531ce0a11dda025d77e7d27c473f5bcdb31701592e365fd6fd2e050610c6fa5f1fe9b2c01790" },
                { "trs", "d646288e9ae68cb887f366544f2e08a0564af76c9814402137253a3b30a29415f67a43b8552fa404de588871a96687538e3f809c9e07b743791c518cf5ce64a3" },
                { "uk", "c359369031b187689989c93e6ce97a91990c1dcfa75c6c7b7f61aea259e75368a73955fe9c9272539f7def02f337a554a268a819a64c97ef7ba1a5e5fd87f9e5" },
                { "ur", "433527af846273923cf722f3fb761e9b3d0cf106c719b3d925b2567fdacf4aed7777d5ce768f18eda3c0034a9581e1c26ec892d53ee7541d35b421362b4c0db0" },
                { "uz", "87612f2a5753c34bd8ee94c158cfca0fc9cb2d5c9e9e172be9f91711848c376de22f56ed93b49c474fe5a4f1bfa718c4fbf889fed0418ed1b61b730e08283104" },
                { "vi", "78371b9a9f6e09faf015f2fa1525083c5d4aab16a87b6ac720bbd6bdfd479ba7512639a0f21858d7bbfcfe613e2cc218300d5ec27fae5c6489c63a69af4ba457" },
                { "xh", "3a12592572bd0bff050013c3e07b681905b7a68c09477eb5f2550fe4b0c66df8bfbe3a08f4ea71fdf3a81b5d558bbb72429aeeffca9de563a66794ed1d0af6f1" },
                { "zh-CN", "2a958273333bfa31da11b52d81556f885b311dc57943a7a2b1d52e9e743998767f83c2271fd48fd234b2124f81c3aac17898a9052c0844ba4f188b17f14e3808" },
                { "zh-TW", "8f5ddda1a72f1773f18484037576dacf67df426621bdcfcdeea9a6a9bb43d06ed4cb75e9269a32c4a0d4f9ae673721f2f50ab0a1ab87b75b5aab7fefd44f4c86" }
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
