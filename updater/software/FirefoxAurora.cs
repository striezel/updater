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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "107.0b6";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!validCodes.Contains<string>(languageCode))
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/107.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "2e64c9b947919df2e63a2dbf47cc63d3a6d258e65daafbba3d561ce9c3f11051fe30ec3acca3803045e54037869fb4f38b1d98bb9530105b5a015587e70543ed" },
                { "af", "de359d9d2c31dccc1ad6607f44f02e0b69de3a3a72a4d1d9c2faec13b8d137810790b626a70ab9c0a6f5b6c1cb626dc64739e14f776b14474757512ee08b4188" },
                { "an", "dc730c8aed58b6bf25f494a8feb314a6480c1d71c72d83a7bc25c92dfc5bb5b07beb54bf25ef6713272303fcd0dd62e39ff3c6238582b27711f85e484a13a315" },
                { "ar", "a025c8f1609885b5cfb0e3e4786a8e699778dc20034b6b12686aeee432c25d71cb0ddad2555cdb1c7abaca26094767115357f903d0524e349cc99e56b7a09272" },
                { "ast", "1daab06e15577d26c10f92e2be1168c8438809f367a135d18be7ad860d02d8cde00a38fad900c26ba0e9b810237bf70e5f503e4721bb4cde684710e38fbf137d" },
                { "az", "fc8401b7c2ee42656f34be98c14aa93c4ee15c2cd463a17362b09d6f0373db612aca40dacc30d6b6cfd380f07a9d5ef09b737a9d233630cea3444c10b1b70ceb" },
                { "be", "bb2a5b117a7acdd80787689b9a6cc03dca69e2d1ebbaa644b2b2b869ff6555728e10b52f1b0faec4468757b8201f063751260d1b474125984ffa924d9ec75c89" },
                { "bg", "bfb299085df23c27bae239e75b5b38c4b61b29b400db29be08028268b83a32f1a0c26d09bf22626d8cfe0237349bb908eb9e4d0c66c09c3071aeca2ea7f95f82" },
                { "bn", "5b96380f3585a81c03e5f0ccfe5e179424a2a88ead467c99ad560c5ca8f143e93de1daac0dc8010ddcef750289c98e34bdf1953fb0ffce62db8fb555113637fc" },
                { "br", "4ddb8d4356c926028e742d80d910fff3a340384b0aa85420c9d09ea243892407bf81817445dd368fed969f92a29c7d65941f8c001625dcb295fe2f4388a41dc6" },
                { "bs", "d46d736bc30198c2ad4aca8f02f28a4c7e3277e9df1d1c299441ac5abc5080eaf5b3c88c891336da21dc339d207c8fd9c3496b59f28b0c676739e291f312e1e3" },
                { "ca", "fa0d6969b2a991c41fcd857c0f26b7865de54330f429915caff308f89f986c220b893c8924723d73d7b7dfbeb2ba7932e0e144a0c9db62891766c3a7e763748e" },
                { "cak", "fcccf0a346a9aa5a367adc00bf037ccec89cd078997417754ce7bcc486df03f64d4c13437d9b4bb71aca5d069e3f5956ce74c506e79a355d4b251ac67b1bce62" },
                { "cs", "b4b17ff408b35050b3c393937ef17b90b0925d12faa7e0a38c5125f024574f48b40240fba3a3d40027a0bf531069f1ce5b75f253934c2f9556bfde71f9d3160d" },
                { "cy", "79e68085c9f1d0654950daeb7d14111fbfa382df7a860b5f1339e669972b016ef27331e5120a1f73c4917c7a4f87ec1728cee793cbf033cdcd8cd13c31532247" },
                { "da", "e4bd222cd87e3dd01f1ebbf9ff196bb3a293f85ee63db237f9ee01f1bf8a7e2737cb663ca5a9b7105348b80d580a0b6a827decc3ce7e101b932b83063c1bc1df" },
                { "de", "ad1b36b49ed681effafdac1321b7dea48ea0277fadf5b50a80045991f541b0f5706ae707eefc40d8ecadba34ed2fd22a5f4c6b5e4691df79c81b7b4d6d2e1bbe" },
                { "dsb", "5ba129afa4343ae348eb5b0d8b95f8bf7586a55c4c5a24142c53846431588565e66152556cbae42975e60b7340f8d418107f5b880e20f40c1b78cd964258e2f4" },
                { "el", "a75502f9a31727bd810410ae04e73069489de3d2e590f04d4d73f7201f46cc83c34f43431bdf38bc13df3979ece2bc7e1c60c584ad893042470ab333dddfc79b" },
                { "en-CA", "0addbbcc7594f02af77ca2cef567ad8380a58cdc13176cfc5e4f35ee9379cabd7979fc629d2e1f15ac2657d3c9b6dc35d85d8a08295a20da371e5d97a7a96d65" },
                { "en-GB", "71a71f132d19779a20a530d302b1e6818b813262c52082d4f4029cd7d1f716a3d94dd55befa8e12e8af21e0f8d19860aa26edd0142959eac36d06d8d3b95bb47" },
                { "en-US", "0d012215dd8b44738e0028cdbac3913fbfc44462c82fc26bf3fd9041430175ca23dc080970420736ffa63efc2193a7b425cd40cd942629c7e72e532d1d7d1924" },
                { "eo", "07506b7995155dddca0490532db562aece144cd9e4631361af2f9653c4a509fbc2fa32ea4097a360b9618c200563b8b3e00364c36a1ccad27bc7853dbfc665c0" },
                { "es-AR", "eac5aa7c0da3c34c0742bfec3914def37d13a186ec2cc4305e747ab8b0b5a1beabb8149e207a24332ad485d521e64819353205719f994466395605670e858bc9" },
                { "es-CL", "9741367385f098a7ba17661324fa8927e63f25296e1ba0e8e2f0c7377b1d8cdcba876ed92a17c9973a0f7320f53619a83ad421a6a6b1e8774ea32aac823ce68a" },
                { "es-ES", "0751f3b36b0d3127c85fa7d8bee58453fb0c9d609756203545bd0025986eccbabf0d2a126e249a32db7fcba5aab0c684bbc31793452100e0cca0dc94ee916f13" },
                { "es-MX", "3a956920d8a8490f977eb8c98e9bb0ee5482cc62552683fcf7ddbfc844f491c9d3275e612dcf0e6f12788d75e5903406c03dce56d27ba5ce03ee09ed496e85eb" },
                { "et", "241aff24d262a2e4126326d7e20acc1de7357e3f184505ac98c2bcea7b945d3588978785c6a0bf8c8f4b03acb4e5fc9601588630a10fac811f78f4df29a9eedf" },
                { "eu", "450b176c11383d51db01c60858287cfc214a5bd23c223c37e0ed91e0cbfcebea7aae6af787f1f0dcf6a86bb216bb5c24d3d79338d11528ba315698b4bfa31fc8" },
                { "fa", "1ac28ab8f181049597e1c81359f7646d22bc6d1768b59d9a75ecf0682523993af2a833fb53a16457132ce9bddadc45accf0af147577f7052606824c0554419e7" },
                { "ff", "b5ec51095a388630dd8f2fd981444348b549b9871d731966b9dd6f7c230d3123d403921713b6e9f69b6903600eecac7d43b1ac9974f010f9ff09b267297616d6" },
                { "fi", "3218c29fc6107785776f79ec528770b08f508503245dd851a9e45134c81f8c17584290057a3ce1a0b6c465208588a023f5386f785e4110f42bb00e08e1bfde7f" },
                { "fr", "9a4137e6d6b9174a5d2bb8d07143b14e69d285b37ff25953c466bc7f2da040249c0dca25eeaa40bb19e1dd997fc12b0406bd3117f9d9bb26e8e6aa4191eec156" },
                { "fy-NL", "74893231f01febd6158e00c5c018aea749c715cfe23125d09417a090ab16af1ef1101a47f91e4c2f213ee46f55ccb41099fbddedfb28d4f6dc122e842492d099" },
                { "ga-IE", "9f2bd504142aa7c1c32c2af6f04c24f0d493d3c2b76b0122b6b2d4bb85b150c565f44f4d12820350099936e81b1d244250ee2ce9344e9a9dbe95fb336aa6d49c" },
                { "gd", "1741a7523f5e24e9bf99038959f5e2013523b2a974adac64540db1233edce7510fd373d33d87cd35ec2338bec455356acffbbf6b1ea3b2a24560650b021db280" },
                { "gl", "91f973048b32adb5e3630084aa4b09332fb6d9320a0e90709c2cbd3fd7be6c4795cc56106d5ba013a7ab1a40245cc15587d9a84267ab2f36667c5b9f589f7ffc" },
                { "gn", "51b766c0bec906678e8d1fd29df35cffd1811018ef6b24e717f1481a448a93c24cb946add54f5602e6d3d66b7b2b9a9dfce7aa608cc0a52e0eacdf2e0b3c04fa" },
                { "gu-IN", "2d6ef79343f4b0f7b0f0c9eeeff3947f382a6cf9201c80854b10d0c21abc306667a76b997d3ec84d3b7c7e39323f896458396f6ab11eb9b4dddac8e98ddd791f" },
                { "he", "60dd4f1c3c1be6c0e482e84752ab0ae1a56857641a3485c663220be43fbc06175f6206a2147f513fd1bb88600620711cd1c660f842c9c7ccbfd5b9966b14ffbe" },
                { "hi-IN", "ddf801db517cbd97dd7214711b516944ca007f4c2aafe4ba5b853b63b2c7decae1953ba44b5038d335e023b63186738929a2192aa61952d5987ae6eafb10fe44" },
                { "hr", "e729dca894cf3858ef3f52aee69edc04413f1274f0ac0e4823bce7563b1d0fac71f77f8d4d1636d63896c27f4dea7505bab0324cfd5b0e7fa3d7f8038e425486" },
                { "hsb", "a93e2a3ae30de10b8b5195b60bad3a3dd89ea953b5e241d723c31ab9e6d2e6406d993829bae3b5a3d5c90b73d73ca4e624e9bcd4be0148df8bfdb4c599e85c70" },
                { "hu", "ab6c6d206994e12a9d360d04f04998c78c5aab8db2baa69da478eb5495ab7b1db37ee44214ce2a2a597ba8036f81811366ddc5c93f4dacc6fa3bb173be93fd49" },
                { "hy-AM", "15902b6cac0442663bcc2ae71b910ff651411db2d1fbddbc95bc0eb18d200661cb49cda30a9e9fc0babd2b2dc79ab32910fed63669253321f35e73c765b04f37" },
                { "ia", "66a62b1266cfebbf4e8a7e03dc3414c2ab15e9a33763310ce0576cdc5bd59662ea0a5a15ce2320a7314f41b326f8ba781a359dcecb33c97e64f7b37dbdb5b722" },
                { "id", "986a14642b37d634bf7354d580d87bca501d4cbc3aa292db38f23c01a8852e610022abce77629eddd05f69c5c39e4b8d480c69499a8cb5a42a859aac90a71637" },
                { "is", "6e7145d8c436c601dbd3c2e8141631c0c94089ee4648f069cbb3d03e672e584fce87d4f480dd7471f701eb802a916321ed036ab949dc1ecd674f2d2154eb1eb7" },
                { "it", "82eda6dfaef04647b701e3477bc7c203a67f19f26de4854a56706356d77793e6fb92e624359d3c5db0693785131e53cce787c2d64329dfa7b666a5733a136f0a" },
                { "ja", "eaf91108ab3579e0255d3fdb2cb9ba5331c229fb8f00cedd80f890715485eecddb0fb27ef60a773040e1ae8a7d6a16995e0521843cfa2b0716bed0e9174ce529" },
                { "ka", "5febb71d4eddd4655d2e46108364a58fc7c4dab2cdaada0a6a3e6a2808d653112509792523207dc21e20139b0f28ebb9de6047132ff2cb1ed24fb82c64dc59d0" },
                { "kab", "8754099adb7a39fd059fe04e210e56065f2e8470fa425323fc05453c39fc5eb373f54af86438f5cd6842c2e67e97b654e4806447c1706ed9c4a3da4117b5888c" },
                { "kk", "9265dcc4f07d6d2d59a5fe0cbcca7049715957070abb450d4d8f84a8553707b7a1b88f3a0d0bdb53c01f066ab6590123850ebb44ed2196016503471758133664" },
                { "km", "3d303cb119088124baf4a354993f122738d51db4900d00f51d819795f9741016f9712b37f5e99bab2907605d1b50fe0187deeeca9f6b41ea3dc246bcc878e912" },
                { "kn", "8a4422f968580fa866e9ea60a7052482e6866660f67ac68a5a1c5be4204d0f0507dc960cd3cce8fa3032b06a415a1dd1b0056a53a937fee1d5130e74011ea337" },
                { "ko", "b40f277d362b8d00614b84ba42a03342bee920d8525232d4a55588c077525b1e5dfddcc5600a154468d3fb5afb246e4c77075681fa9c6b26357017c379b7d60a" },
                { "lij", "f0ba586d06759c051d59307f7ee2803abcefc8877a322604fa9318c2c674ba66b0ad1c0b4d3a3059a9f6032da6f8ac74bfcadd1e12552bb75accf5898bd45bc6" },
                { "lt", "22576b9434987fa3530a3757dc076406b0bfe5d7a2dbb784bd9375d7f8795c3a6a90d14356f630716697b6b09d9e521fa8cfc3931fb574cf5c1aed5dbe1488d5" },
                { "lv", "f2ed0479fd6219317a0afd754315eb76d1fd7a8a99bfe0d427e36e0bc3f47bb0f55320433215f7e90b7ac99077c68d5ade2610c9e44cf3d0ae142cc553811504" },
                { "mk", "4bcb9c06e2812581496cfc69d03cf85799c8111702f348e2a07660229bb828334335cfc21561641b25ba69fbc7e7c5f9942fea27c4b17f5a9d710ffe95340ee7" },
                { "mr", "3eca65737e5a5f5b3f1db1081474527f7cb54218dfb1c1157310f2f53f1fd4bc263f90529930d168ea22b89ebeb8424cab11623237c4eed0f9ed4fa0185875a4" },
                { "ms", "40e9d9d079c5e1214078176fcd925a95b8b126a1f4e006c69fd9cf7773c329d7a51404f4c127c8bf6beacd973d203e9164e54b55e0b9b289d20c0c8727956122" },
                { "my", "0e29d4db318efcd76610e53702155fd21366b730477f7db2f188e54281a6e919280d11e9486dcfab667d276d8f9bb3af9520b5f75131851ca08da432c5c85af3" },
                { "nb-NO", "fbed0aa3ebe441bc7a5d0554b9c1bd63ecf5c01d5952b574d29d869ea3914c30b00e80be04901313dd059b6b89c3e58aabae94346acec9b5aac781e09ee13b33" },
                { "ne-NP", "b6c632fc620f13a717bac7dc44621f16ae3be5f4ecacb8874134b7960e5dc032a7bc8335ac37fa24ce85b2a32f570d1fd7ea4c830232b3842c64fe96eaf27070" },
                { "nl", "20d85cb7fd353a9441f430995d4e7c208d218d69c455ec9ad3763eda69715f3b1c3efe99970b7c66688dc0b5474d7b62ef23f38ffdc479d555b9682378caeacf" },
                { "nn-NO", "aff5449cf906f125575acbcd86c5c0720e4b5d2ef7d6f00dac989740f27ef1cb7f6bec756f42a35bd583d7338d42d8fec66a3a6e877d07c835dfbd26c4265713" },
                { "oc", "515cf507487353c666e271fc28b2660ebf506b9a90107bd49095d3f9f1949b957fdeca7c7d4ef35718dbd589972fdca174cdd5b097c90290ac9a387b617032e1" },
                { "pa-IN", "0ad228b9828fe458427c79d498021c5fa35898e8780ce4e76f51d31eb59fb4d1240522b8756a308a20d3a82eb0e31bb2399b5a8b2eb0f8f27a7b2d5c0df16b1a" },
                { "pl", "e9aa5e9437485a4b9766fe3399cf19978f0319b04162127cdfd7cc4809129701e1b809a0dcc026481d2568a7292db8706358a4a25dd0bd00858b543d438c3060" },
                { "pt-BR", "eb9dc35ecfd8d51359c8320b07d23a13f9d5330982b99694f8367f95756103dbd3fe7cb66af2d66446b8be582e0dd968c099154ec37b497cade05368af4d0d39" },
                { "pt-PT", "503d8153ecf689bb0faf1a5fa64338cfa1c10ed8095199b96887035c44c0a94476db6e632ec554413821cb76a9b6ea69e672c6fa66d02f395a4247083c5ce2b5" },
                { "rm", "8992c1e1f17fc0b77d17381ae153949cb84af0d7d238d9c1222331ab699979e6c992cb3e06e42c7985daa471899d71c83f53e97fe40ff24ea032f5d81c02771a" },
                { "ro", "3054c03d44b8552db60d391d2321f5fd3780dba8f4d2eb972e87ca41417134342315bd4f602e4bd741f191cc9863f71fe97e9bc7c02a0a77645264162a4beae5" },
                { "ru", "fe7a45450755ee59530aabfd9a74792f486bcd28a99bba6ff8be2910f1a591ad3ec3643b26e3faee19b426e46ab786e0a7b47f8845db69eee0a4a221c72c9aad" },
                { "sco", "fdd5746c1db50e163fc14b2f8e9147ffb1f2d9bd5f7b004b8d5530c51f6a852db82085823d9cb97dcf3caa934b91905e25985aef04c4ef65102a8e37071aeb8b" },
                { "si", "60fbb9ddb55a90fda0695d1324077538b16d39709a483bacf7973925e986eefd3ea12c087e0bf14aeda49cb45953d771f3ce15d34eb1488c7aad455ad296e918" },
                { "sk", "b13900b91104545a8825e77299c4423397a038cb64e404a396f7a31dc70630521bb23effe50700ac8f35102f17c40ce3ea24fbc1a807c82012b309075f1a40bf" },
                { "sl", "fef8fdf67b417ff171ea7d0756b812d5270f76f91e08a44ce7a5ff3ed2c4a1a1b5404b6fd8b6583d1b12b4c9105d41b8a2430931acf4aa51a0809f8957af8ac3" },
                { "son", "e9a24b3a281f214b9cac8b9600aecdd342a58b8562952b8a53f0f3e829c6dd16d1c7885996cc4a36b0b7c11033061c3b1e2853302671f5d46d2ab95af2f3a1fd" },
                { "sq", "b420cc55982a1c40a83f6fe45e0cc7bcd7b3b6d048f2e591097cd1f806dc0f9b1bcff82af3ba7b84ea4f489171a0a611c95a7e22fc6473522f5faaeacd8450da" },
                { "sr", "100d95dee9fd9e0f7802a9f8def7dfaf346f6a8a43851035714825f9a33ba1ace7bf44200a01a5a73303e65d17780532039d2de3e496ee87701a795d41dc4c3b" },
                { "sv-SE", "fec57abf5a8780c45748b7a716a0487dc5d79dbe7b38f480ce7cff1d4dc5fd39b9cc150f8e1dc667888f08ff585ebc2dcbda251feb47efeaf972f5392f804418" },
                { "szl", "bc603c31318e975d9a8a2362c6e43aa9886301b30f248bbdcce90fed6efa05f49509fd2174661fee8588fa2924b1694d2653572a49598638ec4a9f182b483066" },
                { "ta", "28a8544efa2225d1b784e4da1b64087c057d7d78793653198f95bcc2f81f6770118c443d9c5e0d967d0008d1fc2088538a4176ef7f027a48bb796623d749fd08" },
                { "te", "b2b2d8d881ee381b31932a9a543d6a810c3e0b4d2165f5ae7aa8a006578216226beab71a9762830fd106316eb82f6b08310e53ece170e2c96e1794f35967b44c" },
                { "th", "883d49d6e7567eddeb7d32e51c66192537fa3338b42aa220d01919df6e6d9589f9d7e7e62b9560c448c120ecad40dcab9de658810142c3435071e93ebdf873ae" },
                { "tl", "14633522502c89bc14ddbc2e920d57ff451b1dc1b6ae906324e09a7020ad8c325fc4551c96a1d8264b560edc89a8061ff010f4795b290fbc65ca200f64437869" },
                { "tr", "521cec6348320ef11d3624dfb26366183238dc599d99e3e18f9a6f206ef3d3e74110db93cd8f6b0fef667d7f3019afbfb4499ce05c813aafd686e2c9c4a11954" },
                { "trs", "ef0ac6077d734eac9d1624ffbb5c69b2a0bf8ffb3e40123f0496ec9c4382274ef8a6f3b6a1a797be26b707104c6512cd666ec3ec9c542e42412b9b94b75646fc" },
                { "uk", "319deb7214c8d0a63ad32de159facc42c32e914bb8a7950e67ac1e1d271c621557ac75813c823b1f19f6fc223e9fe3492ffa6b0972f7522f50e53b52d1aeb073" },
                { "ur", "bd0200a22f5b324d21f86c0ab9f478d614e9d6b3ade733fab26ffb9d6e080fb99348e471a87c8b0993c2284b55d2eb7f19d7e7c8036ab087d0e5c7b2cd804374" },
                { "uz", "10296eb660ecadfa99ccb439afe3c044262e9d467f19182616b9e14a83cb721d71b5b7e0a6cc952599e6967a2c182d28032239157db694f7e9de440579592305" },
                { "vi", "2a91b2d293752a1a3d7ac9dea49627fcca8d0350d72350e7d8fd24136bdeaf8f36eacfc352f113fb779767a549f40959a15ae663c96c24a53e64b35494e7de47" },
                { "xh", "9fb1c63b764be96199b3761e36aea77e6c45786170ee72e23df60edc5b8fc9a1c53fc04fedaf20192156fb1dec124712b47a4b063f4b4a6ac70d3a49d522f8b4" },
                { "zh-CN", "8e7d30925bac06b6389ca69f362b7e0db984a5aec9aea9c3c0d903ec7caebb98538488be7199e3219040bc628f80c277efbff2751ce8a40c6ac0bb93b009ab33" },
                { "zh-TW", "b8d5d1208151fb8e3483f3734ae4e69ae3b3e4ab6eb1d30662ac91df1a0aff274b77841cdd5ead3a24184dcdc92295722bf85df6b8cdd7815f9687bc08d92d36" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/107.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "d0425244fe3e8885aac9f719f7e1e3bc09713cc50b4a92471d5c3fb1f01110d350adf1f57813f54ddb812336e54673e58a208ef8dbbbb7ec093ca8fc52ec8764" },
                { "af", "9ebe8fd7bbff239140dc381b3a064a6a45a0eb821094cf8b5e41379c41d356970aaebdea48724d5901a68b24d9fa438fd915e0cf12ddf5855dc3dd7778c1c51d" },
                { "an", "10cf2ee744252d876ef167c897153913b04cfcfe0db867ed63118d4ab6996ad297036d83273ad20a491ef15aee120830f68d2910056b254dde07c86b114928b1" },
                { "ar", "7b6c397f148c744c44ac75e73032eb16d5c734c6d4c7571e322e64e071c6164b1c05e1e608b961b0e5d8f92a2cfbf4ae372dc5338f3606ed75ae797dc6dea89e" },
                { "ast", "0db1a1c7ab42b2bd59098f75000b163ee8fdf52f5486ac91d1b82f65c599ef8c9dd73d67aa1e4fe6f8705a233ab7643bcf861e4727548e2ff6d4d22b90ccdede" },
                { "az", "80ccf9d598c00457c3454ed611fc8538d816319672ea607220597dbecc335cd4bb20166923380a732db6cc83bb4635aeb633975caaba0409d1d3655d59553282" },
                { "be", "b50c5812449ec0e641eb323fbb3b3b718393510d2d2987bbe19a8d4e288619ed72d670228744be5beeb40b3e312c8098724e0622867575c51395f97b1f6e6788" },
                { "bg", "3527fe51cb470cea703416d396a35253ca967cdd9d253b7a79fd8c1f76425cd4118297ee988a636ee2af5c2013bd12c5d8b39a96c3ed7a4db37cec419822d1e3" },
                { "bn", "07b17f9945e3871bfd9a57e6cdc1066ffe71fdf3e2b2bdb461a54fe4c0c442dc2fee99cfaa54bb3c5a5993ac53a7c11c47ae99da5e7d3c4d0f7e1783c0c37c78" },
                { "br", "7f3beb74e2d566bfc599cd40bc3f190fe72e3b2c9b0dd1fde6bb5c786a191b632da5602e8f926d7f8c46c2856daf58df0d999b084ed0135397ebc29b6d4cad87" },
                { "bs", "2b0ec246366c1ac7831775540b7add0bc9156ba8ade2fe52d034e9221df79b47d0171fb5da8a776e5526a101198105b455008d55817769f2060e0c7c70d84898" },
                { "ca", "de7253090aa93115935ecd9f3194f1832eb5747b0684eec7a4a0796390bbd3225c7b8842935c39ba94d7e3604a7d90f72edd463294bb41f45370fe6d80cfb55d" },
                { "cak", "d6cbc36cfd1ef4a61d9b01b97402b549effca96acb8d1c6b5cd4ed3b694d62f071979b4a3c45e42911f1bbd70c867dbc92128c8e52813ec6072fec8f0e9e1672" },
                { "cs", "7ec1685e82687a66a18f5accd23099e537a134760dcfcda1c030636cb3f7675e3591d05097368570a228df3d4ad6c5f82f4a11f09288ba7d4126840acb1223fc" },
                { "cy", "59d6027965dc2dbd1a214a56c8f1326870318a01e5d83469da83eb0af238032510a44854b21bea08bb3e190128715d04cfa554cca0b923a6e90f53ef134bf693" },
                { "da", "46f897848b166f4eea6c4b443bc133aeb0b7728904f4faef315eefd00131c1d85a8f35566c55827aa5eb5884f6358c03eccd05c489aab3f0fc0220945241b15f" },
                { "de", "c6986429f2a9261aa42f60913f6ce01ade76a0b533a962a1b8e938b6f9037bdf2647f08c546aed3294a6201822ed84ba913ccd4aefde7c8d6bcf5f6153d639d1" },
                { "dsb", "25abe0740f34666bd419ecb78bd47c3139aea82403278f535ef267315b9100da78d8988b42d299a1f4ba24673ff2e3d676f438bbaa81f583789ac2c63e9ab24c" },
                { "el", "9de1ea5e51ba9e9cf540439bafb7e4f407d443c1a9b7efa717535100ee8dc7589c513f052146988d6c32b72721cda78a391e0f399301dd3cb10ef4ac2a08b4a9" },
                { "en-CA", "811980ca09a172b0d9cd672e620ce09cfb2baa551d01e0376c1ba33ca3585e8fb7d66355a3e86a6c1feb2feafa18b08e70104c2a1afac2cb6f9a2bbe62d19e9b" },
                { "en-GB", "76eb922baa04211e0d4a2364d44bf189e9ce561e1aeed81bb7bff7b765883c65787a8fecfa9fb6cd7074d4ca47bf76695789e0e7b3f968eecfcf08f34784bd60" },
                { "en-US", "0c674dac9d2551a5845df2ecc722d1264d18381338d4cdf47b07885cae33ce86d4767604f949530af7cb28310e46fcc912769b640803deddecc015e45cbe0ac1" },
                { "eo", "50943c3835737903b4f3333c604423082c3a4a973891f200168cf075af8d1218734133edc4ae76bfe5f9e4853d208306fc76f9bc8b383b659fad520dfdb62133" },
                { "es-AR", "13e46d25a931a7396682292c3beff1133a15af11edfd11bf14d84f509c9f50b13e26b7f9218966d5a2471636bc90ddbc748e6e9abeb9bb8b81378aa60576d56e" },
                { "es-CL", "a99d66ed21e09e90893f8197e7a478efdbc7798b00424b3ff82ea413756cc162cb6ed06235ef209d01d84e4945d4d9426aff4075c3bce13ff92f7debf4a94ce9" },
                { "es-ES", "eeb32f96f80e82c796fd01f29f5cbd26895f967464603137113557444c99a384c37654f43f22edecb8d9767b3a2e9fa81c001596de34e6fc1eea4bcf0d92afed" },
                { "es-MX", "486b256034fa5a41353077b629fa1869f87f2b0e25f224b74ddbdc9c3644ecb376679f113fd024b8e18dbc8c749c0949263633199de508c900c860ed5be375f0" },
                { "et", "dce854e6fcbd5d95eff76770d5a5e78ec25465038a1c28aae03e5e85bbdbf02c6ddc73ae2cad60fd6ef6d875143d131e1b3cf0534f311433e1d0a450bcedb87b" },
                { "eu", "37aeecd57f33f0f73cf3377f77a019cc503f9e329381589c808af87cf44224200b474e07ec6d6b9c2ed4963317963eda9f3b7e336d63224e9ade331879e0429b" },
                { "fa", "e5252a8e72459022b526de596119049927fa4ee5e504cab558427d23462b4b77fb6dd3c5077b496bfdfc721ad664e174b486672575bfed82876f5d1585d77115" },
                { "ff", "bf4be4a766bd897ae316a3676b96a3790b22f602c46527b9be8dcd0495523ddcf069a5b10f99aec08c74c33bbff0978ab81ec6c8968f515a688b16f2d798e48b" },
                { "fi", "0cbf21b646dfd9c713b5eb6565bd83bf9130c1ce72a3109bcc905776f54759ada7105cafed11fa1dffd8d908ab7b8dfe9843442c38cd1037dda462ad732f171c" },
                { "fr", "93797a2fa767e7bf6ef60f47897461190974ddc4b5ae98adf20c69f1963e05be53c159ad2695cd54703fd0590fc8be0e24249281ca1eba008321dad6e7bfe436" },
                { "fy-NL", "e6f69ad436ccf71985d0a61a00639e1cba7f6e61347c593c1bea71d8e5046e5048c23ca12cc15d0e8f3a7daa1b3684903ed49444398a034dd9ef28a701f6a78b" },
                { "ga-IE", "f05896f5266975d691a793cf4408e14dfa09cef848eed4712d49e35294e315d74e23733a03a528797515a6def026e044a6e7260330d2c489ea9e40ec49064a05" },
                { "gd", "d7bf42c78a5e8b3bd3f73c019eefbd9810114a6555580eb79af9539f2fb79a743f09f9056ab12cda7afd487c3fbd2a064195996b24ad7d584515f0108cd8c2cc" },
                { "gl", "966351333ce5e4c3ec0c3ba60cdff8d1fc2f385491150537d2976acca82a4e399e2759c157c7c5321b61b7466a723976c22de793233549ec764594c3b7721b05" },
                { "gn", "cf21e1a682e201a30ac4fba2268e25dc757824881974aea94f8c9bbef8c90386a6d76b542bba97ebc9ccc017917bfaf3528d5cbadc50f4bdfe706727263eb1e2" },
                { "gu-IN", "591bbed253dbe903341c49322ba4c7a8d83155178e9ea8600537b138d1d99d7e8f517a8eecd8a281b20dbf7fb9f530f805878258bd33e46ab751d3d82c50a7aa" },
                { "he", "9fbc4aa9e91b5aee4e1a342e55bcf78e39810c599c9eb772395a229dd8b3a523306e540b898e990f03795c1095f3ab0a38d259bfd769aa930d8054e8f2f01bab" },
                { "hi-IN", "7ac9abfaa97d5def30f4ebb32132ae511ce9781b6769fd2285e4424a554ab2781c06c36e8b5caa7d40633a0c89616484dc47399d6dc12c9fc53215b7b9025f35" },
                { "hr", "cbda26907e17100fab9d799228b406d80555c15f6491cb570b1a7884707f0ee9607e7b752e271022822f1acb5af755edbcc5082c6e6c9f288c9e7c0adcf09889" },
                { "hsb", "e0f1f97db76901cac64a53a7232923970a375f7541dd4fc0671003acca4f7ff629d9ddfa6fe809a4f68a0357fe85ddf80caa2879afc580d817c3c6f6f77b24bf" },
                { "hu", "b5cd3e9f7c1408ffb1f70d548890b8611aaa4c4a5c600f6ede408f55bfa34f848e4339ca26d716849496b1c7f1dd8b3061d0f9f6a47caf571be4e1700457c762" },
                { "hy-AM", "18f33c1eb3cbf78a99517f47658399b930cb8136c30129b2ae2a63969144eace79f3d479da17e1327e689ecc8d6b834fd0c2e1102c3ede06a4c65d15b01aaebc" },
                { "ia", "e60ef00026f08cf029d125953d08b30b497ee0e2bbb28e3059648300209528df19d48fb593fc1abf4ad841aea1bda38cc7cac8d21a14e02d26d8509f95a37aba" },
                { "id", "e60a64d9fdf0fe019f9f90938929a3ab20f1f5a6c8a885fff112a1022116eb8c44bfb61e9cf3460542497da110db5baeb17735dd97c64e94a2388ee2d7f9104a" },
                { "is", "3e26395972ecfc2e3fc184bfcea1d51e13ee5ec36731c7c19baca424680d3a8e51c5295ca4135bc0151f856410cd9151d6850f083a94bb89b520914481d60b51" },
                { "it", "aef1e7a61fe348e572cf065bf7d86e70dff855321077af2453f7e8089a9fac4b48f43689c1571461366e9d045978fb7bd0976d4f6a358c5ed411cefaab65eaae" },
                { "ja", "7969695d9f720e0eb8b97d8d9acfa86ff2ed02254ae4ec5b23c754828e482d85cd7b5cd51cbb7b540c2e5e376eee7f30283090f32029abeaaf0a8847c1d675c6" },
                { "ka", "4049bd68361b5cf5882743f85dc2664d7f082f31b0600b37bc2909da2797390d2ab73540a3419401c63806a7b5972f0d2b1cf562d6ac4d926b90897e1c6581f2" },
                { "kab", "72861d169cf956f5fa76863e26700cd6c9d52e0c0304456c11b82973103f915a767faab4beeb044ee6ab25e7cc6a982835cf893e572939f0103572d10d89a331" },
                { "kk", "7854a8ba4f2fc5ac6cea8a5a4e1c394064182920802b4babacb1035098e7b2d9bdad0152d22209bdf84a499e21b6bac76a6c66dc652bd6e6c4b943ff39bc3d53" },
                { "km", "b2a1af9f26044712914bbca91d455739d789070acda147c37ce95fdd00c82185bca467d11558a84ca09e8ec4b8fade7727f26ab9e739ade8e8b8d2ead54b5fc5" },
                { "kn", "f25e2d0a63491312a4ed80f71604b3fa8413200159de820f8fd66e5ba028ea9dcb608d8dd451495fae73495d25606baf08639e22dac613c481701fd5f586564d" },
                { "ko", "03355389003362ede6f3963c3f433d54975e4d176621831817b714f1921834f6e364e47a228676d44cc2ff4bb43b1138febe98407ccf8604835a2bf048d4ae7b" },
                { "lij", "bea17728c8940549da1f7c2408234fa5d78d665bdc1250bc1a0e47f37e01b5eaa4224d3382e360653af0af8224772e2e6d44a840dc5e0990dd8afdc992ac7678" },
                { "lt", "21c7df340440b0c864198ead7a81b0f41e199b457cad06064b46f5182011de359ddc8490575b4544fe9107071e37bf76bf5bb6ea0dbfc71472bcd084200ab3f5" },
                { "lv", "ee553e1e70be6a5343dddbc7612e71e90c11ba9056e632f95a2bded1b91b046a8e902480bb008899246346ee56b348c572819eb014402143de430c7b62230fe0" },
                { "mk", "c746e4ddbc9b7cc247123fd5fc703ef92eea702fb0620e6d44f5889b9517fad3cd3519133f14fff2e9762711f2e213245133a85edb4908260a66605ddcc145f2" },
                { "mr", "81246c6e5e08d75544fbd79c4e315afe5fe70e10ffea249467732aa859ce9525ed0d34e921087f5ba626382d5f00a80ce476f0a1688ab5e2374ed5d947f557b0" },
                { "ms", "cc055df5e738fc297703e60177c3e06de6f19ce42bbfb52fb9311156dd575806e3e2429f2e0e4e6c958a653906c1c5b4794f8caa528a31174d8122d38948b7f1" },
                { "my", "90811e82d56a28a396248fac7844cd1c4bf42a3651e3235dc82a0b03d1da742ff6930e7eebb5e574fc5101458b9713de69958aa29ebb5f85ff3a833b9daaf16e" },
                { "nb-NO", "155fb2221375c9c2b9663a170050020a5b58da85b6115c0317ef801290bec12b8f989b9342cf37df2c4fae53178c6a04eddf7e036126844460ab666b2b85fa2d" },
                { "ne-NP", "f04571b7b0e0144bdb1472835bd89d05738152967b96a11272be8a741d3f4cb06d8cea946d6f3d00b648b7134378bcb12d7238cc16faebf4aa45781765881c98" },
                { "nl", "3edaf28ae51fd8c54e1af7631a2b02fd5cf6489885407267bade4a4c4fac1911c4eeca510e616e3a1439215a55a53a1483649db665a1d5bfab3fd8e8096cf514" },
                { "nn-NO", "eee2eb7a7da6ad101438b9568184f197dc4f39e02c3ba41f1efcedda28e921902105bb6ed404675ff87b8969d0bab5529a10fd94773769b79ff41620ccfdc5fb" },
                { "oc", "95a30f1f7c2500e58336bf20f5e11cd4363b68e492169f17b6cb64fae126e39dc532dd6f4129192624c9d22c9e37b9d5dd00b1cd9bc2b8471ccb71ac5f71aca8" },
                { "pa-IN", "bd657fe30f37149ebef6820f584925f18d0720caa4e8a0f32fc46d0fb0c4f98c761781af8040c1615e3c9dca956c9c88cad4e3b6015ed52ad69352effb057241" },
                { "pl", "6df51395686756e1eff89f827104756ad3621c3f64b1677308ece6df92e0539d0e055174ca5924cbf4e3d1a5d9db1a74181c223d08602b2e3836044f135ae627" },
                { "pt-BR", "8e90a76c0206d58dcb32453008342422dfe178a113c52639eb214a02239006fa2bada9d44f8c79a542633343227b8267e7b0b4cde4b1b28787507c506a6b68bc" },
                { "pt-PT", "611664fb1bb28e14bfdfc65761613d6c1f1f9cf1f82a7669b83dd6d387255e33866a5c0acb28ed3fe761ddfa4765a983895eba64106a7a558bffb920266a932f" },
                { "rm", "4de92794a55faa0857bc50b4127e607a10698e195b3d6f70bb4026ae0b56433ef590ddaecb8085765ba30bd5e9e0b427eff06de73d22f09a2c77d35a18809d67" },
                { "ro", "855fcfe8bea03045ecc85dca8afb7e60df762e35f2df797fcf73f8a4215e08a921655c5e277c4bdebbf4b99e3642775f02d722eea4a4ce5310796ba800e4f759" },
                { "ru", "40aa4ab637c6a915750f900d02dce041017185f3702ccb55cedd93b09f4c7151705d4a9d2912bd99f310440ddbe574f4e613b7dd72ff4d67db9998ea308f794b" },
                { "sco", "dde3ffaee8c92ce578dabbfe64fd80ed69d07a35705c23583bfea18ff6a553ab0852b9a28365067515ddb157dc931c0d8ac09fcceee92e20233ed3b23301d0a7" },
                { "si", "22472257a87188f39b7ef19fbaaf759d1123f9200ce270f8aa7e1c85c6ee92ef3e2d79141df76a633484e25510ed22a351153ffe90d38ee466a6c112d1d75e52" },
                { "sk", "8a240a4c7a658c1f129534808dd3f22ff2ce1449096a4e297b5f604b53bfc782d76e4d03d38e62ca54f90fa654a2099725c4b7609e03bd232606a6f06e87a168" },
                { "sl", "9c1e123d83414ab2837143e51fb0f8aebac5b790fa6df41de9a28934fc99f6ebf3ac9144307805636df029a2a5694288f623a0312bbda999813b1185f0b5e078" },
                { "son", "180157ea80ceb39fe7af85973d002be6b6ebb7648c3625d9f3f9d31f1f2a82488f68e61c95293921fb04fd7e47b530dbddd64339381bac94b7ddf59ff53b76d2" },
                { "sq", "521d3dc6cbc2cb57a9d94fc0f48b0a79cb97b61c2193f05eda1a7dcccfe22c4a714ac1101f8fe97b4075296a3e37e427ddbf15ba05b00eaa9e323d783eb30000" },
                { "sr", "7950f490fb5375397f7523cd445d05e147cf182ba227fc86ae14608fe2d7d014a48f4d68b8052a167dd6e2f0b3e83c6c6b9b6b5c9a56800d69dc8b928dcdc4a8" },
                { "sv-SE", "7fa7d34b0ae3b738a740ebc2e4be4a6032a8076f909c247bea1f03dae8e6eed9a74756cf119bb6d629dedce5462c036b2b3d523350c4dbb4c4d21a75df875e9a" },
                { "szl", "e3e21a8a77791ea59478fd5e051830c53df85f3cad47eca41bf49c5892199b47d2bf5fa89ccbf3041319bbca53ca81afd1aaf36dc904632eb18a5b95b3af5ce7" },
                { "ta", "5361d9e1c9074c815289c522f5884169515f92ee8a9928c494d83754dadefc8eeb71188a8a53ab4f8e8c7d9594427d25416aa72943889237608096d4be805b74" },
                { "te", "3061cf5a769bd9ab0179f67c724be4bff54c5390005f8c634e4e4fc13bc83433b3c22da708422b4357acbca84bf86fa48a22cc250489008b6de716713cf79e88" },
                { "th", "c7bda3d3d3a4a3c96a31280fa6201d5e6c31a97269ce6a43b62ecc596691fa3095cbd361b1a25d06539676b34ba927e6facb6902a53c6f69d50ad55d6147db29" },
                { "tl", "70b79459fe5ee2caf5f100dd08fb35bff97681fec5e7f079f296ce8d60f5435cc045635ca4580b57c3e7b385438e685104499098a68937cdbb6dab26fa4ffc56" },
                { "tr", "c1d90b4dda612669dd3256f645f24d3470e023c7ff8d371fbc043266311271485fa04e8a261c5cd23737670c955c020d364b8d1e4bb693cb403524da505e59d9" },
                { "trs", "b519d2609ccabc9a14151873710afe22c00c2e1fbbf5594ad46d06cafe8c03ad2ea659f1fa24cea6e54cbc0318ca0a5eee8d9512d5f94d77d650fc1790bbe332" },
                { "uk", "455a723d98966c075e8e5cff5c0fd801d341d97eee11b4c97639ebfcfffcb75dcbb18f1b5c6d97997effc44f3b74b3b39028c9dc9274f78f5edd95ceb96ed972" },
                { "ur", "d12155aa4d864eecb85e3602d8751180590adb0225d52ccdba781358f48daf9606b2366f890ab1c90653e1acaecefbb4fbc9b84d04ec2e66969a9d9de8eea2c6" },
                { "uz", "2f0f52717847a234644b80ddabd720ead0ac6244dc73dd8b6865a7cd64b511846923ee17c33b389cfcd15b094b0c9efe5bed0b14fb95518d9445183d19eb95b3" },
                { "vi", "5a36a9b8d168068c64873b163715591c669b6579e687c8c7a2e825fdd5b73ff08820e135592148e4badb8c6cacb77173373397d7c4cdcfe13ba1ce9368c618db" },
                { "xh", "698c549e8eef95922428cbbc4ded48fcbe674926fef771391bf91551372c36686d8e36fd2ec3af1baa0abf8cd1c3c4d45dd22e5de6a27aacdda5d2ee7a79d012" },
                { "zh-CN", "7af07e8c4c2bb675161c0271b366ba2d941898e61e84c8f28d4510208ba6fa2238a547ce915dee5f5632a2abe96240287a8f4c717c1c6243e6c2b6077ba0478b" },
                { "zh-TW", "9829e1b92dae12fc71120175297a3cbcdd1320ab3dcfe61dbfe2642d7bb93cd0ecdb474c4bf182cbab4735769aaaa62b831a6e773bda6d640b627cbec36ebe9e" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
