/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        private const string currentVersion = "119.0b7";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/119.0b7/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "f9c9ae34f1a4803fa07b6124f55e90384fb8d5dc2c2844cf05132946e822494f85361453e823aaac58bfdfac9c26e5bfb74a5f21173e54396ff34ad81f524c0b" },
                { "af", "bd01cd82cfd6abd5ac922fb3b9ddf2330dbfd0226accac5e9e2295311c5676d858545ab65403f4cce791abfb60efc730303b38de828041810c443533abf552eb" },
                { "an", "d033a2703f49c6d4525329a7397fe400999db917774e79cfda83ae6091f24b29d6f276e1729460766fa43741e8751456deee384ee355d3d84e445dd34cb778b4" },
                { "ar", "005868461dbccff8c1fd4c02ca76ff7dbbac5633e0018101e0b2aab59ba3ec39eee71cbcfc4d72d25d7ef1867811bbc2a77b56badbd211e49c33ad8b5b5d11c5" },
                { "ast", "023996576a320d2998bc34352f4189804bf931eaac2e8ae9e59915c555317890dbf942d5c6309e319dd559c939d54cadf927029b3e2b1c58d3ed7f8b04515471" },
                { "az", "4299774cadadb984358225668c613643ee40a6a9073e0cc5e5cbb9303ba663fcf12bf5beb8341acd0074adb79e7898e625f189de2dc1650c2bb1bd1038fee867" },
                { "be", "e4d046a8ba21ac7cb29a10451fbbeaba99c8631e0ddff6b22ce91a7d1032f71cc56513419b2adb54a78c774b41c73ef000f5545629962d3b2d2d8ad9cd4bfd8c" },
                { "bg", "cf3c1e56151c80860d162bbd1b214b1a4591ed45c8589d4501a424865fa9b20f4de49f476c7cd49e94f73c812e4afac261d67159b6519d3478529d038a969986" },
                { "bn", "8234bde28b8d23d8fe0bf39695dbcb808c6d5a7f023d9d77f98a613506ba5f387c632951559788c3302472a66a03ab7d1166db684be89b6682ef7ec6e5986a6f" },
                { "br", "58f9781be29d5448dcc65f7dfb3881e842f410d4327aa22035a6d126d4fd052e2bf0f70a88031b674ca91932887cd5ec6c611a5aac421875ab40786098f443e0" },
                { "bs", "188364b4e9f2df949650b09128fc79946efeb1e44f3de0304c86e8c4a01649fca7ccb71b7cb13344a4e062f11a8fc2151c09ecd5b7b3e3266dd2945148949a65" },
                { "ca", "077b9de972c2c26a42ee759bbc1a48aab500353f0a6568c6eefe8cb11238f6b6855c5254817279883eb75b23c86371df0438c0fc67d749e99740c6379e054137" },
                { "cak", "fff919404ab1ee4f21f5dd1137b6f413b16f414d2718425ef21530747fc2f4d1997a20ecd4421426a6cc86b478479da8e3a48bf6890e4d09b164745e4c129675" },
                { "cs", "2b823dea127a539b44233b5d6f00797ca0826dba0e89956756bacdb8fdd6c5732610fba1ce9be0f6a1a563040968f2b807cf933595a7315cb5f3aa8996cccfa9" },
                { "cy", "906001cd3f2af8fc1891ccb40e34d8ffb2a438fffd81f6a216ae3554aa3faf074bde4b735c74b74d2291d5f49ce8881ea93f64e0941eb5fb60de84417569b3a1" },
                { "da", "e35633c44fb20571fe79d085f5de395c24a735395179e777c2687a1f668630bb0211ab91e14e4579c08253a223d7d8262ee90e799473061a8fd6bfd66caf9017" },
                { "de", "69cdab37a612a463d03490289389be257515583543f66db4cac9fd1a29c7886592d939ba65e16e27a16d64cf62466b2ccd3cab82ef69efed6ff6fdbb03fd0ab3" },
                { "dsb", "98a2e26fc1e2e105cc1d6404cd871c7979b8f1aacfab268f0d1c5bd04bb0747dd095d2fe9faece103cb4351c8f7f60416cdc50dc0227d5db56f36f2f2d537356" },
                { "el", "047b65cadd7a2f58ae3b4d96f6b1b44ee6fa9a750fb96d899a31581d568884753c6c5f6702d95b234f7829d5f101e004f830f980746e2efdeb36c3d41cdd3ecb" },
                { "en-CA", "12333f16861d92b16dff5a24ed698bfde94d32dca92805024b8e30751b5d9f9a165519a035b235247ca956a1b401a0b66ecd244ce99daa8c145938ccc551db47" },
                { "en-GB", "41a4c0e99bf66e5a031acbeae517c7235df863cd9eea4d27dba7883d2d06559848277124849957c55b4db0dd10bcaa1c15f5ddf002983a4e076538f97e82a801" },
                { "en-US", "8c316d3185d7dd396713bf3c9211a299c90371d18a2c3ed584ec2d6b95b3d00c7169c6303b1156f5785fc6e058a2457fb4d04d765d78a46b618066046a68a15d" },
                { "eo", "7e9111e5c7905304fc0a8cf8d481055be98d3118ad46ee2230483bc8a106f4e6809b245c8de9838a5cf29b50327c6fb4942e3d6269617f0cf0c0d05643559a5c" },
                { "es-AR", "7237ccd2de7bfead684f2d667d0a82bcc4b6b3d1af8e1faef960ff55f339faca913eb3de496d009602fadcaa3de2c9aa8c328061667b6ec5d4151bf7ec2744ef" },
                { "es-CL", "99e22a5a96627c41b8c1289a713511fdeb279bc5429ee68e2a40d6e5a90cfc24f0ec456afed5e41e14205bb7c465085accbb5199d85350a61af7e704e1c6e1b0" },
                { "es-ES", "9e53e2207697f94f74728afd5cd6521533f8fabb5a2f98bd3dd7be738a27e445c64e8edf4696a81e3b2449bab4e8f5a0fdb2efec065a878e176faabfc534e4b7" },
                { "es-MX", "a921752343eec1569d893bb331db3d5d4cefb6bbbb9bda987a22847738eceb9d37749ae86dd6d4aac2e31e8e29ddb49e7102144e4bdd8a2828bd64e82fdfa378" },
                { "et", "fd91ed169315112e2e7e904d3c57ad171a70c1d8d6052755e21b7d88361dba933dc0e28231b6547279623db4681b57d5071b682a65ebee1acd4989b535733726" },
                { "eu", "f2a141adb60f17b7a668b7cbc90813530fc92cc5b6a1678b8524b9d317fb9ae261aff3eb11d27a04d14002cd007091ce59476313ccdbd0f3527305ae6d406491" },
                { "fa", "41ba68926900386da74894d350ec5cc6dbf8410292c375af2ae471e78071bcfb0ba08cad7b867b6d6f2cd1d3ee133b2332b0e6a23729429ebcb33c3883c50f0c" },
                { "ff", "7aa2a0722193c08f125789ff9a60574c0a1e6cce056da21ad7e18f8c5fc1bd18b05184221ca3c1fb268a6703a8384baf2e6c3e916c798ce81689f12eab8e996a" },
                { "fi", "321feb3e05bfcd8c10f05ff19c84051992848c67fc5b5ad585d14ad58222e04b833dde3ce0670920b630874c32287f46b7b844ff2b8fd63ad26731a8c8c7f4fc" },
                { "fr", "998d5cecadc002d0ae98ef79680badd0951ee09847ba851061138712ea431e308eaeeb7fe0d7aa3154ab87c950e8ab5e46a1b1a2fc306adf6640a9dd452c1213" },
                { "fur", "b6bd245048375cfe5839602680d38ff674524fb9cd6637fdba603ff6a83cf135fccdc3a0160a5a29147790088c0ad05fc48862bc99c694d0edb36367f24089fb" },
                { "fy-NL", "d1f4cf3175438d58a6952f791bf22d9009795ef78cfc2d461f576fe73ddf2791d7730f072f845abd0bca8edea529aa0fb017ff01beff85549c23e19659ceef7a" },
                { "ga-IE", "3d22ae8e691f1a384e4935021fe1a5c542de2b4ee1f94e24a793728705df77ad5225b3e0f84b5c4efa9bcec80236a1e11e5e71543d31ded9c2faae161a60b388" },
                { "gd", "2fe7264c19c09f6c65a538ef8eb33236eab3e0fd296a54841355cace0bcab6eb313ce5616062728fafa693c52036213523a559dd032a3a9a06b20746b05f9bdd" },
                { "gl", "a87214ef83df5e97e32e5d3ecd2f875c53555d773253d5dac9c7191a491eff16416febd9c57ce634ad6a25182dde6437ab8ea005e9400a62a067eca2008377d3" },
                { "gn", "4f33269cd3d7569e61174fd20a2ef62c76c4f2e0846c6c7b2a3d84a6f8b8f00a2755a41664f9017a368c9ac0b5e04b85755158b0cfd872bf3e3e22c4bcfa512b" },
                { "gu-IN", "3f14cfc069140a264adf9268e27a87ead26927da3fea34418bdcbee83ba73f0f7a7411b1a68d774a6801b81896f6c932315727c0c8011dc5c830e79cc76ed815" },
                { "he", "1b7675f33e077dd9f0486c74d0c540dc17fc1d1e8baf959df0e862b85ff75b59262ba121f50ad8c90344d2a32ad5ccb5e9264890f7ad8c1984bdd8c60d24cabb" },
                { "hi-IN", "faba924f17c4d79923a355ccd73572f75b0c9fdc0492fd11e180b4d37c583370264f906ab92cab09e251b5c4d0070cb2d9a991bd1319b316cfe4c9df5e972270" },
                { "hr", "d7ea78af296567830990b85028f7036060c71a777faeb1109ea49daa7189e1409656ae923a22794c1483ee3f5dc5e028d3e1d1cd2fe6fdc9db8f1e72ae2d4a23" },
                { "hsb", "92d694d3c3e614825465c44992c6280bb2c86c4104ee0a2296988eca8f7d2c4937b2e4d38ec94fe31a46fd6f064f8646e790ae76f9a610ff90bd41254dce9c67" },
                { "hu", "cfba4c194cdf3320996e05838abed92e0d5aef62d6954de95670175ac9c5a60ebfa37b4cee3ac16b26d55d4cc5cc18dc1a85c19f2c7bd4bbdc55c0fa46bb770a" },
                { "hy-AM", "69a1b66dc6da7ed1f8f61644963e19b9f33915c541fed9ca5389ee751af3408bd077d4daa2cfd6441ee04afecb78ad950a475b0b66717d82085dfdedf1fb246c" },
                { "ia", "ddf02ef4efa0ad60aafa2d23473889114601e2c06d55ff6ffb513678086fb9e04f622f5df901fb32de8a39c3675af1a5df293d80ac5ee28c79dbfeaf824bbf33" },
                { "id", "569aad77fa8460c53f9d04f91a4a93b94c4e65770e53d49c8bfa6d550acf4e8e9a415b3db4f4caac1f1f6a884a3502fc3b625885250c524e732130acca0c060a" },
                { "is", "05a2fa6c551740a445c2781e73cf69171bec90fd9aea8f5fb866fff6507cac7ef96c56903b2dec67dd7c2b575850685d99c9cd571bf645dd5d24d125339e94f2" },
                { "it", "e3a690e0e5cbbcba784a3fcefd5bacecf8aedfc5281e288318458c03656f98fef7b85144d1d66f50d98fba70c0149e9cbd89872d3d4ea759729e8b71c52715e6" },
                { "ja", "b792dea4681157eef08aa6ee8d1e9b815b63ac334edda608bc40f971035f552ec58a1751fc5e93ff048256e9f707491d22674e9f321efc3a492ffc8cc5b7903c" },
                { "ka", "e027bb033b543031d2873030d57382d9f8738ae8a7a0cc7e3cfb4ac869b360112b492a5244fa68531eccc0ac56983bef13b0d37023be88b79c3f5777b50c4ac3" },
                { "kab", "9a5ec552cfbb05e59c9c9ed8925bae5b6d1ef6f5606e7acede4548c27ecaad5eca71aa83779294002c9b56030a032fdadc9ad95177b41514eeb975198d0d3962" },
                { "kk", "faf872857eebbba20e2db7c525cb63eabca986b02696f87d85477591e5a31a64d3e07cd8000b2f3d1f91db037ee3d4b8a9cc0802a18ad5460446534a5fee1b28" },
                { "km", "6bba2b9e93d076ca39e461659b0d768a74f25dbf091fc0ded806aa90f8e2fbfaf45c71fc588bc2fdbbb03dcb437488b8c41fa34648727d869b2f41627729c7d1" },
                { "kn", "df33673459ab98bb1e74da5c5d07bd1f10709e87cb301d5c09492eca47726aa61ee70c1cdd665789a278bfae74e314ba244e11fcb3e7faf9a0baba44574d4102" },
                { "ko", "a45ddd7e906b05e4177aed66a8bd1764a12737e6d86cdb09566e363a62f71d24527d65c69d098de0a42d89b0ae509c2cabcfbc893ca0a62e39fd7b0a06b03d13" },
                { "lij", "62601e462a7e0cd7886450f1ebab8dfe6b6c264512f6753628c665a3c93586647fe9e6898af66d76630fdaa5e2a5b9c7cc578633101869495562a50b0b0839a6" },
                { "lt", "74840e1ec3ffc9cd4acff404fd1d836c356690dda1ebb69916045735172f8146d1cc61c31a34499c66ca93dcaf814624f26c33590f178550916b75128fbd00e9" },
                { "lv", "c28c3fc5a48d3fc6867330d537cfc30908ec65152c0a452da25e74ff18ee574a752524c807a6f5f5231ee13b790f500ef613d07bc43b63511184a0f52fc5419b" },
                { "mk", "c1e0296345f33651afebb776f004808c422a448de5571d38a78563c899670f737e5f170c13464f981b714405d2ca2108a2acd39737613dae9bee70c4e867f0a2" },
                { "mr", "e0219d80532076373b02623ae7cb1ac26e6098f067a96fcc5c8589e966056c72604ca3d850e281a654c1db042f4b09228fc81f7435aea81f840640d0849f685e" },
                { "ms", "650238d2285b66f9ebadf96edd1fa796e8f1336015a9106562506614d494ad87f0ba4cc7c6238e3a0c32e388234eb92ef73f7a83440d3a9827d5c3221b85e6e4" },
                { "my", "c9807591086a98b848461ade29a25acf6a6e12590d22112527a1668b741cecec9d44567fd2851fcc4e8856f3c15c7fda3c14c5b0cb4aa165bfdaa50f8fb8d0fe" },
                { "nb-NO", "615842bb22507ebd308d211c12a3a6dfe8809ab2ce6f32db579399a414371f6cfb0ea1d7e9487c5cc0c7d2ff73162560e90218b3e635b7f6b5de000a8d8f5a34" },
                { "ne-NP", "6e79d8c8d64081e6b56fb8e8c6233336dfd2b22ccae2d2268817f6fd3138bfad31ddda358688c34823d0edc5a4274547c278fd07381dc31d33323e0792a86a51" },
                { "nl", "841fcc748eb679902760d9af84558f22b10cb07be702c12d40e148b1a044ceba0c34b53d8a0a0af52de49e5f74068f1ac27b4d568fa11a90d8a5e02bad159308" },
                { "nn-NO", "3e95d578d9084ad1125aae6aea5a3b820c6e2c74accb15c65bd3a2ac03d419ad20784c2bd047e451aeb6c6a2d0ce73bd372a368e1413b75780fb01bd51061922" },
                { "oc", "03e1963ead77324f2bcaf47c4b317cfe7da9052fd186ffea0cc8abe89ae0e6b35c3bc22c8ad5f23e4dd41a2de10b2da530b4a4c4803b1cf47c4e958bb0d067b8" },
                { "pa-IN", "9086ad38c986a757075bad5f716cabe280a25cb8a630a4f2f1af48296020565bb7c2ee310275c4a24e1ade0c8033b7819694c2cd509efea4e591ca41a1abaf29" },
                { "pl", "0ef27f08bcf4ac8b7a344b22773a0801cee96f4b8ea5d0b58e17a71a7294a330e31178c734574847be3eb3b738484be1d8471800314b7d1a4c03b9e83ebcfeed" },
                { "pt-BR", "a0e043f06161e9bc3e6158496b78ed9155f0cef8ab069f80db6f60d1a2f8feabf249784c2fb407defc674b0983d2b416c17896babcda0297f556985028f54348" },
                { "pt-PT", "01d8746f3556bd3e8641d0225448869a3cd06a9e2c64a818deca15d67a821f06ab38f0f836e9561647e20e4ccc4160aaad3ba9425d37ab4427aa5b8365f8fed6" },
                { "rm", "831bf4fc311210ab43ca14042cfde326966ae6a90870b75b3b416d29f4b935d727660181dfc41ab137bbe15517961bf3fc2f2f06d403c259701442c08de38334" },
                { "ro", "b87605530161c37e0353f4d9631b952c7e975c804ed82494decaa68caa9da4245e27b56399138848e145942b6e43aad7f370081c2291bb3572664013e52254de" },
                { "ru", "6bf46a7f5ec12acc2e779d4ecdc454e6982c6d03840d792306df20bdfc0748f901edbe509e3d48b2a8fa1ee442919d75ad75c443ac3f7a7c143d039cdf4935c7" },
                { "sat", "5695101be6ba7cbec6c0173bb258c524eb330e713b1c2b8e120768b64b6673dd0c93e481e42aef5f491cecf4471cab7ede770cf123b153ec35366ba8fc847fc0" },
                { "sc", "730527a6761e40264e9ccaa8c2c5e2da88eb694ed23ad6570db11ab29714d54d0680ea19cff6ea4717d3f2e46087ca3f6f920efd74bba2c72c88ae06929619a8" },
                { "sco", "fff6fafee3d99aaac9c16a8ba42f8c645b2ab8acc06547264dba385dacbf5e46b7e58b5903dba5e8033bf0b19ea06624ea3d577824b3b4fb939e5a7c8ee0452f" },
                { "si", "ff69fdfb66a4799a7db50d362ba538c88534b60602bb4b6417b4d83ad91fe632c573018d871e9b4fad2ed86923cc37df115927039cd0c5500a82b22b91d74e29" },
                { "sk", "74ace5bc3e87e4149841cd217dfac1e5d1b7f5eabd69f9f783273798e59a6a68b5941b1bc754fb690fd00da8cb43b2a00e129cdce2e61e365464397ba0f775d6" },
                { "sl", "3e38f3b0743bced377fcdf54df793c84ad7f1a90db6ff5627d317a930f3eaa081cbfae9d04a005076f9b7b52f38a31bbb7d99881f4563b91155aa5b4e22031db" },
                { "son", "8f7a59fe67b09cd120ec685cbde76b01dd2c1cad740a95e8c44d86025123e10c7df674af484db55c7318a20f244c2a2d17297efcf55959e76f8cfa4394d43245" },
                { "sq", "b592bb56e434f5c626776855a3ae051372b65b99c01d4b429ff57f6a97482ff5283824498dfc1f1da92f6000d8701e2514ef4a38bee5c7874e1c2d29455efadf" },
                { "sr", "53aa28ad21216da6524dd7b06bfe97c7df4eff5f8fd7c63c42395030865599504556dd4c77ab57f294e7e278e0aedf587925fe520ea28ca30701163de0b5a83c" },
                { "sv-SE", "66ef8d450ddf07b7071d69f2840286c913ef098e9d1dbe093101ccfb441ec3db4c4ae48a07d31ffb24d907e7524900d77e506230a0dc16fa8946cb1735577840" },
                { "szl", "1230b0471c3e18a2bb764944dd51389ecf31f90ab9441df9e97e6d18064db837e749f548cf7bda5df611c452bd13a66642c98411e9c754c49051a77de0ce7394" },
                { "ta", "9554e3e67d95a8f91b35db59d3402f77094a1dd9c6d96e812cecbfee3864a3d27b932f6f8893ce02dade76e4dc343dffe5887181a42ccba0e173001a9b7af2d4" },
                { "te", "07d5af7484ddc76f1097f93ee086ea4d93eb40a94096e8a02bc3f56ee09864c3fd47d40a6333405e3c18432c9d1c27c1a81c0f9603b30f4f91cbd21565705856" },
                { "tg", "f21266b905211f3c3ee7c3ca8daf81ef8c5e25a8f39e5841883fa040f99bb9f82ce6cb7dd9ea24271853c54efc8a8736c2a30beb2f143bf59778dc079a05650d" },
                { "th", "f79488398b4160dbc64c0a767b3c4517100177e458a221d5d710d83d0f4fc887e7d39cd7a8402c3b3f34af3fe4d3c3bbeefb7161fd3101796c6cb06fa577d830" },
                { "tl", "823ce5611ed456e03015cfa42bf92e105472baa0c332f353a931bc15d69267aeae09bf912b81648bd4a14818656585f02dc62e600de110cb316a3c46c4123110" },
                { "tr", "eb47069cb921e9ba828a8f477efd7717741046e3aea4bf472b76e50565a38f50d8904f924a3717d81a6c31a6e9603488e4716eac6d01973d9afb9b1cea3594d7" },
                { "trs", "ca8128992e18375183166ad3a4e8aac02d6ce38896ef5a112a2538c8fb68451b48cebddbcdaac7b37e8ec3ba59803416f5e13f2bd946e5cfe8a1405b9d4afbf9" },
                { "uk", "1bc0de92fa86ce8bf3b6b046c8cc32866e60433a8576444ab70c73caa0ad0bedbc070859282f23b74c5d680e90444e2a70ed9a2de40d7a414b323623f8eebe06" },
                { "ur", "c18aeb64bc05888890db1ee94df2089e1ff2a437fd6bc5a5495c150616d7d1027db427524671fffef289e9f853fb744e6ed60c20bb8a13821c5f9ca81d784cd8" },
                { "uz", "83b67460f68d3bcac4460528d1a0658305fb9571d207126a95e435e0c5d162e8d510bc27c6d4090266d081a1a1d2a7b5320e7bb6c36a37ef25b91e1877d0fb5b" },
                { "vi", "0fcb6d011401eee4146ff790c85d975dd8eee778a438234350518629cf23c0d347d7bbd0919d98a6757899b9c6616ba18dc401ed860ccc0b3c9ab085513ecbbb" },
                { "xh", "7971f5ee1926c18f806d6ba0bd289a213058bf870fff492efa0e700a697c9a30f799fc648aa614ec7a3b973397d652eddf5818c7c82e045a2b5913f12daf9ab6" },
                { "zh-CN", "c8684bcaa5e2147b2ffda00ac990f5b79b6c63a9c7f9b13be74df9b1f18cd8f62674d5eaa862d487af19c537e47538dd3748984fc3c9e120990552c26d230d41" },
                { "zh-TW", "108ce0292f4929a81213a462cf86e0d53063ef6f9aed7b73c62d7f3a9a568526a2574a9b745fd9e189e34094ab49b5827b93442b4c08435e8894e4af4e8d0e16" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/119.0b7/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "016af42d483c74aac07a8edd80656ba29a77714b439954d7d0287a41d1f097f9053d554c3223ffa4c34f45af124579ef8573638a70b0e6601db71221e6d8732b" },
                { "af", "fea1ce8e87152d2ca2495923be0eec465cace3de18a3806497647a3805f512951cbb0c07ab475a53f62400a6b21f34877b3df185ea4c637e669db6206cd8ed3f" },
                { "an", "93cb150454305d17e3d19aae786b0f6fef96c687c3914916a9e80159e77f5887d02fad7481658d235c19ebb62b2b95f85daed7bcc460e2908d45b52ebaa9318a" },
                { "ar", "89ff784d60c939fee8d33a542e7380fbbd8377cab436d9148979715c84ea7dc6ea8a3adc8c5fe8449bc4e16fe3760a8d2e97e398937d03ef9708abca301d4043" },
                { "ast", "3ba9808bd36fe3b4464e16d7a9c14f660e1beededb03a2a1d892d8867b27d68a1092baa787d96816b25b98e345174108496beecbd21e876327a692d925a1ba44" },
                { "az", "b5cd6ed4f200106ffb8466c73dbe16536692cfcd36c15bfa8b342d1dd96c358655fbed2d06ce8b0b132e31827e2cb6391a7b28a166bacb1f90ccfea3a8fc4b9e" },
                { "be", "5b420d928a8114abb679f0b9e8950fd772921d859a11503f1e276e8a9fdb57318d01e6d5d1baf3b8a984c47adbbd9d5e958229aad51ba3d6d71e0a47a1ec4c9a" },
                { "bg", "00a0445842bc9d8860a1a1930edd1f24fe48d4853bf214fc1bfb10572919576970808669f180379009bbe99f72de9555b7d7acb9caaa938e2e2a1df85586739d" },
                { "bn", "3be3b368b521ac9b8adc3a4960dcbb6d28ead5c7c97f0accd3c465f37540a7fb3145c3c07ca86da2889b4182f2a369bba7d556729ba13ebad2d4cef11f6ec20c" },
                { "br", "db91f8de226fdb98a61641c2f522af190c7080319b3428f3e864ae79e724e37d601e4a702dd2a2edb8ce9f829bc3d8892129a9e44a0daee5bfbd567834037a30" },
                { "bs", "1542742910f53fe93a8c35643e5b7bf0a5eaed54c2705a680cf555bbc531090e66ad7d32687050c853c7ac60e173f5f131984141d8263942f4ede6d9cc1626b2" },
                { "ca", "076facae9463f0a9355eca525d58ef467df5371b8cf0a5a82854dc52a5a7faf507f7580827d2b873f38fe1278f5e1dcc0eedfee2c7a51b30622488a6a2913bd5" },
                { "cak", "e6661481313eb3360e97ccbc98ade075b43fa38fcef2170392a99eb65e5b085c3753d1454dcdff5e9741494def71532ceeee25e0589f61caa6ba0f3850f63947" },
                { "cs", "04bfcbfe14a0f3ff4720cc8b92560f3520eaeeca8a72281f0ef14413d411cfd34dddc9a94f911bd93ac4174970b51e1d2397ac15738bb95d759ababd2e064237" },
                { "cy", "0dc05312d0ab581f265860d8327aa68e2782b2ebb7928ca9aa4848443051b1bd02fc150c0a9dc02a51747bb7fda0ca5f5ced3bf6b86028726447dec05071de68" },
                { "da", "b75d1322a68526e796df0f55adc0a967d21a485a919a92d0e8121fea0c1949cde4f720e442ced02b5b394584c4b9f3095c6b61234f9559b068596546cbeb2da7" },
                { "de", "c7f9882a56fce516eb1b620b435a4865931936351a97ffd19d0c2ebe1db8d93bb76eb3c01046d1463652c69e1cc30c1e03b95861cb0dca663dcd834e59448eb2" },
                { "dsb", "f007c0516b901c3ef014ae1cf606ebab1e930a77a89d5a518f7bf44cac048057b5820f523ef2a124a0e62a7bb15ff8b8718129f629698af9afeb60cc67bd0157" },
                { "el", "0091ae4f447561e6fba23a782b82dc27cbc9bf9b696ab748577a73e82266cff430159a6bd6d74eb5f084aa41ececc3bdf38ab067b39c7a6d878fe6a96bdc474d" },
                { "en-CA", "419e704b02860360ce27a0631d1b59ec5c27a8e845e6a2e2db7dd3630d43e4551e5713ab47d2b766cdad1f81e79e43025cf570b97c709f09280be6b394011d2b" },
                { "en-GB", "cb7e3fed95066e332d081b8a0dae065961a3b4ddfda866bcf83910b82ea46015ce1a3a381e112efdd66979581c4cf6059d563272a956a8bd0560750499532b7b" },
                { "en-US", "0fac48030fa88264821a2fdc054cd1496e1a1ded2fd507890998dd8d3ff2d41047fe44674bad31f2dd3cb37419de3e5db8af93f9f6c02317cb0a3defc499816c" },
                { "eo", "7208d778f181bac02ef716d8a386407fa4f8a0f9fc2b4e3d20d1138d6647b49ce21210911ddb733bf4d44f32eeacf92c3a90886d23b0fd1217c60dc3d94cfc49" },
                { "es-AR", "2c59b94d3a4291d314fe72c82702c4663d1cc6b39243f5d023d1c09158b6320eb477cc5604485e1d81af6b752af1c266ff3ecaacee1e331a7138ce1c389fd1cc" },
                { "es-CL", "2fbfae4e7288cb14076a5e330919fabb6498e410c734604def26625499d36c0ce416e006d8387e06a9d10198dcb2f23cad31838d04e78bc31121e5cde711390b" },
                { "es-ES", "4ad643dab3647a2078ad0ae44c6459a301e06f528a4c23d7cb686f30bce321fbeab0ae067ed6fb621188f0f791077252de36dd819126656e80a4df73ff8e8feb" },
                { "es-MX", "95aac1c92b993e9af21e0cfdd8d97461f735efafd41a95c06a66ce9abd589ee19f28068fa43bb4ba1f9f1bda09e3a727b96366c6556779d3f12a27df6f118458" },
                { "et", "8b5340dddd5a95cedc31d585113b09b7962170998d555719a50601abf21db131e7e9abd25d0d5d9131bc3f7e698eb0e48f90fd91ece3dcc380c572fa974f1830" },
                { "eu", "d2776b5bcfad6d7c69fe60946fcc9d7065a321cdcda76aae3549c415019b26604a19304b68fac6c558d238c071bc5cc4e323c17734bb8981c6a938596c9814a0" },
                { "fa", "84780e12dc5f47c4faf9383a090ebf0630c0605fbb955ee7d79fa7ec88a954f0cfcdf79e0de450bcf384428536950ace4261a69b40af4830f40bac6ee575cd41" },
                { "ff", "12a1832e96eadf553bd3312029d3e630e19c497fc132b077bcba050b5c3693c8b7b81a96d359e30cf69b0f6d537cbf1332b33045f9bfc1eae21bfc22317c324e" },
                { "fi", "049347b0080a978d6dc12a2bd7c5bd372e3965dbde05b0c69865b7ee729c81e77d15d96113a9654ee97b28807466ca8988449d0c4544ff9ca1aeee93d1a1614c" },
                { "fr", "f314619bea6f42cb9139e98f4a6b168c742d00a6bca1bfa93c2dcd8e11e5c51395ebbdd9d6c6a5436a68638179be244007fdc398860bb05d1d848906fe4e7404" },
                { "fur", "877472d1ca162d2f629136a948eeedb1f16c9f1341c7107f46499c567a3e9e5a9866341a648895bf4d5559859db377b372131ac611f6f72bd234db55ec943392" },
                { "fy-NL", "0a9f38592362f62cdcafdb3a19b2951d9cb1f96468ae8f7f316bdaa3092c1d137360c8d2612b6008f3caa3cd6c2d58d15cb979bc88a2ca23c3c61e5760071ef5" },
                { "ga-IE", "b61f9182888fac3295cac7653a64860a33e37782a1fbb25af948877d778efbf08a62234be892baa3154ed0c37ec6fe880df5c2050a0212ce57c84242635f9614" },
                { "gd", "031461eaac893e7d5fd0b77b6d717afe8fb9ca42720461c80d95acafcc0efa5ec6c9a43ec56ed84808c5bb6f84a35c70b9e9b305efe55fe9245807f3441a36db" },
                { "gl", "da49e9d300e09374690b4d2bde4894ce2ea2f21907433a37cb647cfd33debc22fc621838639c4e5aa14100d96f0cca4d5a233d319e8a9ef408e72c8430784c01" },
                { "gn", "b4e681b5f42e257622d50fa7a6e9a66a3e42821c64f1e2733fb8b0c936adc9cd1594f327ba8b167b61768a2fdf050fcc1b7ebb1c1c7eae64503376477963dda7" },
                { "gu-IN", "f30b99c1dfd21468f6ee2374620285048effdbd06e5c75bcd1e0c8ba924dd8571aef67c5a9f2668be74993fe16ae39b1d20a6e7e7df4ca2610dc33fe5f0a6c8e" },
                { "he", "5584271f879aafb019c9ed8f3fcdb120d354db510f9823ce003521386936a86b2d5628ddaa0b121ca91ef2ecd2230e5616b08bf72f978c1f0dc3d8cfeb386b54" },
                { "hi-IN", "c88c89686abbd8dffc8b9a6bc62e38f17dad588a41b665ddb6da15abe84d8850521d51d1a7e07f734e4163af877a29003a5b83c31c339a08530615446a22e827" },
                { "hr", "21a112390d855599c870a109ce9c3f85b1980053d52a5a5ea0d6620f285eada5baaff0235dbb0957384b39fca164921cbb49826a2af5aa92158a72e07201ce5c" },
                { "hsb", "be4b951a688281a9feaf95d01bb2a03577367b40d0daea58251aa6fb1992e4d02d1cec67ab664ef139fa04ec2dd97d3ed34093ca6d9a8ad79b4bc14221f13784" },
                { "hu", "e96ed8c931354fc544eea9e589a7b8e60ca632c561b130f17b0587a1d2aae3bac3512c2ce1a883e65ce31a4d1c6aeba440c13ec0e272eb1320c1c200a07c8203" },
                { "hy-AM", "d77c934e46eb86bb232f26eaa389fb8c3cdb5f22020fced275ea8c14d1c1853ca5f6df1439bcfbdc6d7a76e2b6ababaf3d879d3716d39255f132e71846daa357" },
                { "ia", "574befdddf01b043e642f8657e66519dd1446290915b5a10b95f36d0bd4edaa93659ef4785d11dd3b657b0163627074accc8cafd23ade56714c788575b8193a8" },
                { "id", "d34247928c82734bdf98c040c59487b6655e0933e21b4186f44424191657c4cd4519f7997d34004bf60788b0cb7f5debd354abbe29e767f4cfab057e0531f7ee" },
                { "is", "ef0d7d40eafd2307ef7abafd2be926fcf1b8ca3b92001d1476aab1f2b8994a5e60c2bd2b431ccff87cf0ba3658a0126a4557fff5e924898ef66ab8dd01bcc79c" },
                { "it", "d595321f5213d78ef40429c738f29d572a76ea539a1f70cdc166462d54c4ced6a942a3101102d6bad6143ec90890b640437f42025088d741cb8a6f68c9356cfe" },
                { "ja", "001b778ed7dd9eff4279fd6dc68b5f69a1937be3ccf6d9dc4538bf854181067f33448f495e3658fa999d5651d6dffab4039da132bc726fe36f89085d9a179817" },
                { "ka", "1e990b26f0e96d153db31ec776e7857cc40a548299e8bab3467943cc21228b067134e11adddd5f8c8d36c16b1cb8f0cb24129ffb5c9dfa4de7f6d264a9016c46" },
                { "kab", "e4f34943c0da9c051c7321a7439a90f0eea5b78da36ba054542f23da0c848f5fd21d61ac76ef164336eb3abbd426e8b2592c7943f0db1acc4a849fab36a3ac5d" },
                { "kk", "49fa41d9bbd37aed7afabfac2a7175659d00330adab937f2d158d7d4b259dc911ddfee9553fd33fd163033783a5697e1b4719c55c4a005c4f010a1c1420278eb" },
                { "km", "e02e70d69ea90b76e6d63094bd9977e6f6a3346f59b520864c5eacd171db10823f93baf6e8a32371608905e5a6039fbfdcd779ac0b7bb9e407d18b2da3b2ee8e" },
                { "kn", "10271a17723683d0c0b802449f8b6bcdfc2965d1651661843b3c5a33cd411c3b31c06e8f89e75643dd8f79c15cb757ea05e4bd8fa45e5cdb076a363560f89ae1" },
                { "ko", "1183f46cd281340e75ecb5be81250d76e99bec35ddd7b908fc9833783a3e382f2e3bfca5b456e5d9dead45d246ba2d77d971e10c76817d59430f3c5a037e2bac" },
                { "lij", "7415990ed8e3644434c22933c88f0b0e16120b63d2c24585b5cb565d4582c02d4de98a9108e886aed67479d233fbbc6aa2abb3eb8391a7a5b4ac951970c039bc" },
                { "lt", "2ed181c7b762957de8ced69c2bd4ae214cfce4471fa09c84c59a7a469dc97d6547c99aabde6a0f2d90c78236612a068e50f8a3b4e8a942172fc26422bb6af889" },
                { "lv", "b3459bda52e0e5e320102e841e1e58b58bc7377fb74b6098544e8bdd06578bf701125d39f905191f5750adda8fdd24990838eaf2070fd2908c4f94bfb84c8531" },
                { "mk", "596a5fd4029578295f04fb4c75823c3e58c1f2c8602e502a674c36e7c70a1d68d7e26b99203416bf095cef97dc02dceb9cbc9e0c0b772b67278974ca0d5c392d" },
                { "mr", "187c141629d96de5609cc50b32f3bc3a7a0d8fe620a3004b05eca585f1c6110daea958330797d3e0ecf58f541e2d49813042fb3c3ce8b003503748388981c939" },
                { "ms", "1e5d818cacb2342dabdaade6f1abb68b4e34d944ee66b94399391a7bd0e23cd44037edb7243a59b0084dcc428017b087d1522512c1a94ec4102b86e6d14f33b6" },
                { "my", "78daac88541f92eaadc19acb249ec2e9a9fda6ccbc6d0598a17eb9b43e699a79d84f8c9353afff7aef58bf2c52c6b74684c844e9fb1bbd1b19d4fdce07d23af2" },
                { "nb-NO", "603faf9d4910b11dfb0433f9f038b404e530c03c6f59497dfaab2b59854630123c5ba1e2097a6d34164e34896075daa7153db74c266224df04f1f6bd19076be8" },
                { "ne-NP", "e6456eb13f88eb536a1bd5d5633af81a8a975d0087198c783aacf8a96897cf4b4e7387c17c341dc99f83bd56d6c8a8ea30cb24061091d48336b537a62df0194e" },
                { "nl", "b5456d96eb15451ea1e2a2f51b65391c76609834e34b37c89ce66d5a5e04f0200d1b9235d0d9a1ef9b7f8d81e67db23d744ff965f56ce7b99af016075e93707e" },
                { "nn-NO", "30e585ab9406ecabfba6d9b463a953f82efe598faa64accee83acbf08b479e9f3863421b233ea49ddb7d98fd548937e1ebf7455236d97792fce1d3f21315c4e0" },
                { "oc", "f1c57465af7e151559b1e5e54072385928842c2fb30f3028810371ee69fe4d23a0fca361e8207aefc2ac0385221517f1f880f98749ccff0f465673ae4cf93ab1" },
                { "pa-IN", "80e802c04fe78d5dbedb57888a9f3b90845eb552afb8b23b9c5684ffb9046022ed0af44b414441c1018d56f9504bf1b9637572d99f2a8f4a86250172366fe0a8" },
                { "pl", "2a6ab609910b0f7ef3ff3b74ac81df66bd8c176d8f8f1dbfc615dfc7f29b61fa7022f964495807362501cc89e02d26522c52522546964dfc8ab3dc7d28fb2eef" },
                { "pt-BR", "713237e2b6c035d36c2b053f0b2080cbf4cffa8c9b079d4f046fd518542f22e18d0fedab9212e025d5e914ae8046bf6d6fcfc25943456ec5b1a9f091d78372e3" },
                { "pt-PT", "38e7a4d3647ade4f7740c07eb956e35f3a83418db4c18ac0022a17082fa0511777d3397a610e611f3287de20a804059f05527d03876c1c6e8d52b88bd76b5ba9" },
                { "rm", "c4b3c286b2a56fe9802572b700a2d5110d551be5d3e66b9cc324c5da4fa75a6e89390980103dbf95fa998fe169c5440a3cf430fbeb9a9b10cdb483b60b00436e" },
                { "ro", "39ed8592489b9534846b92091a9e865733fe34fb823f6753858680489c2d0c853c34f1101e0e78611ccc16a5c57ccc6970f005099e1fd313c45ff3a289b6937b" },
                { "ru", "6c25c7a0237a79b2e0ee19fb0f66399da4fb5a22df74215b553675395145f2fbf0adea0aa14fae2b35672070017bf9281c659a9a851c31821ea1e8334aacf38c" },
                { "sat", "aaff2502faffeb2b19a50cc703b92a2675f624621762d71bc8cfb377596fa4f887f22aece2ca6a022b054a0a7c02a7c2657ded5380af30ec51f8d11527119725" },
                { "sc", "dc41905f108c917217021d9e47a7ac5b02a5713020de43547bcf944805e1cc540e2d4bc45177eea14a7fcecdb2735b84e644c5a0afb12050a48028395590f19d" },
                { "sco", "5ef90275b60e9658d69b71ab1182cad9e6b25e77f2b8bf422827d101a2562e5110e494c2cc9292776e58c259b3f8351b5b5229e704ecfefa4cd8b3f2b711e0bd" },
                { "si", "9ec62cd21c31d473c6100a83c74214bb878c7ec05d9f023aa70338ad34a3f2c3df540cc74c6d31994fca2896ba6a654b94688835f2e8540821fcddaba4be7f3a" },
                { "sk", "12f16e7e596af5b111409c379291c674dc487a281659c311a7717045886ae9ae73c63e461adf1741327bbe0f8a5a3f4ffeda0da0fac2b361beb5930038e06459" },
                { "sl", "f046c6d380b39fe01776bf26b33b3072f562f60ef29b59b60db977ec5ec5a9173e086e96f073da53d8aaed5f41780bfe41b1821081881a9d43456f6c089a4190" },
                { "son", "e4c618df229dc71e2034685a09ddc497c4a8f52bd6abb72ab10df4573d303e7b7b8ff97c7e0a8d577ec941ed38acc7b6db9073184757ccd5189e434cbbcd3360" },
                { "sq", "c91ac2c3b64b420acc7999bc178c2708ebbb49ed2a1bf6b904c4f83a84c3e5121d7bb4c7e23de6e344942e9ebc0feef22fdfc39d91841f6c8dfa1f0925f883d9" },
                { "sr", "a19ab14cc0985159310395af662e85e90892dfcbb947dd71b6cb8435e86c204cb2cb3573b103fb4d63b553d26891f07cd71e0edcfa134009d71902116bc4be20" },
                { "sv-SE", "ca577b8f94fb428fc4015d8ec2278d73732c828a43f1543339c9f01f818e9069777e3ab2d4ea5774f6505d5355745996da3ec3fa29b1f95dde264cbe01d03082" },
                { "szl", "249cebc02f3b399e6d630cf35f2cf9e8a3ab26a4c708f6bab026660a1fae762fc3bc17407292a23900efe39f6d74a59d5fcc7c005f861f7b9712564d07eabd98" },
                { "ta", "818d902cc9a0f9cf2105df8dcb98781f2f50b0f6a7cb12432f5c74f6e9065f6e820b08ccf11dc2b397f3b4f01c0d2f4cee54fa96140e323fc13e766deddd2e77" },
                { "te", "d858155f5ae0879c35f5818c5c66cc76b4a14daf520e84d24054b9584bb8b28236688f03f0a3406c95afaf2c20017045ef7eadcbfc02b5579306f9bbbd3a0976" },
                { "tg", "ab957aac731d0804476d1679f565db43badb3e66fef53174f5c2cfc0af8efa86c9634660dbcead7483b27375963be22cfcedbb5cdb6f1c8c7e0b264aaccf6bd3" },
                { "th", "4e13617d0441c6a96e8c82f4cdf36db408db15ce86fdbee70273e422400ad19496f302be0a643815af4704cf3aa55e176660122564f7e4279abf05f92e59bb7b" },
                { "tl", "b0b791b61a9fc21ccbfef0474c490153cd159fc69d5fe781e282335ec77758b233846037a4644bed27a360f6dddf788c11aaf6823add146438adf7bafdb0e6dc" },
                { "tr", "0c807564c476d1d8336bd4c045a20cfc392cefad242ad027757385b14a389dea1689d70cc1a8a0fc21dadbbcc592f97e4c6fc082180a1d7383c186de10592e71" },
                { "trs", "8d1c425a6761c080644e93a92f2166e1f625d274b38107662c3eaf6f8d84b5edad2f1ff4fbd6dcb586c1c2460cb79f9b6790f9be3d24455c54784a255ef8e93a" },
                { "uk", "0622f5b5b5c9c84ebb5d9ebda893723d801f8cfab19ea6e51154467ad84b51950645ea6c4c46689e93a3bcd100b5a46911219ba054f06b339bc54a147a68357a" },
                { "ur", "2ae77c9ec707d527db8109cfee47a649534ade117f69e2db1315797083275b3ad29b79ded827a41bcb51d4cabf7aae6735afba8a53392974b2d90b947e26ae26" },
                { "uz", "9858dcd4661ce7e9c9aa7572496a0ddf9502d62c07b2e297430eb14e4a27a813b704a8deedcb9886b8e6ce5bad7062aeb8491406c5fc9c27b84aa25c8d4ae7a3" },
                { "vi", "88b07d19ee7113e44e3c991fb0fd169ca29e15c6659cb7453c901f66306af2cb1e2d379f33fc48c468e158a1a2c30272ec0f8a6fa558e1d77248347efe1f8d93" },
                { "xh", "2f6f726b408489c00d7482ef16463dde2a6b31722f2986031e2105b0c3e8fe561a8d763a924bdeaa7429a49b1f8453744a42e83a21dd3e4cc35bb266033f3d80" },
                { "zh-CN", "df6263f2a7e5c1528b9c7c40b185cea1b4446e653ce8bbc2818c9572bf428e49c733bda016e473ac247e459e6d3f135eb92cc22edc6a130e51ed757a79d4cc09" },
                { "zh-TW", "fe27462ad7e0a62d98875dfebf5ca238d995078b8e05cb64ccd78bb2092568d5c44cce78087a9e4e3f46aa76107141ebe1c1a5f5a54951ad95166d47a568bf5b" }
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
