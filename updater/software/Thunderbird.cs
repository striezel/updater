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
        private const string knownVersion = "128.2.3";


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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.2.3esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "f4381ed19cb5634ee31dfafdbcb2c678882b16c7cbad8d247b3f2a76c84f1e3060ac5618084cefd6d6a5405d35dd9da4ae43da3b38580caf482d5ff67bb7e934" },
                { "ar", "5c16436471fe9ca5ad86626a5b2f7a9bfb9a1df122bfe98a544950f77e29474c5d60f0efd0c5960ef55a8c3ec736b1ed011775afeaabf6d13d6e452a6a3e68be" },
                { "ast", "e245cc29b41294e0a39d953cb40fcdb2227f88650fcbd04e8e7cc5ceb2f28b8f4de9cfb36db0662d1984d9cc91be78320c040709f968e16f2bf505e92f4a563f" },
                { "be", "e6c55d802c9823795a170c8c38a75a5d70eb92f04f0ceec333f054b3272689d51b06ca2c9625bf13b590548e50b6d9f99759610e90ce6610b52d297e2c845844" },
                { "bg", "5c9fea0bc77699f9a144eba7b8b6aad06e2637581bb6f8d8ab6cbc75c2f40cfc9d32bd9e6f50349116bb3ce7c9e12658e60b1da8d3962b3246d337cb128738ea" },
                { "br", "4d8002d3b7d4788c0076009c7b484c9ee5fcf43d5319ecf5a6bc9e4ba1790c92b94002114d9a9d02732a5109f620754880c1c024709f7d0082868c4a116b2330" },
                { "ca", "76faaf143292517ee93cc44324f194b81feae2ceb6ae39505bae8144663aa95a472d90bd17ad57b9a55ecac9a6a65584b07fa0968ce2aa7611eddbaa6efd467d" },
                { "cak", "7e234ea8779d0cc768c9bf2c0fb20c2fe9f3f91962fc67383bfc0599f49fac82c873aa0649175438ce89cce852857230e5dee474c01249f340ce9fe17c99c5a7" },
                { "cs", "03ab849dfdb32360f6d34b52062330d798b29f134711302e673286446cd3b6aa2dcdabcee5101d25517f5c05a9af82e091b74c2dd5c658413e9ae79e8ebcbc77" },
                { "cy", "b60447d36c5659bb2adaf41143a4f5925a37ad2078fd80855ae9eb719d6f99f1489af486743ee8c1aa802046275f27dfaa89a1c7179e22781bcc12d802dec384" },
                { "da", "63e7fb6e959309ba620fc909d911c1bdb58fbe2d98a0eed61665e6831a851911446d1e81355d4cdd07e906c3abf364d954ab7fe18fba66d67e901f9e3310e269" },
                { "de", "182aa1f8fb911246316f98ffa831d2d7781a1d3cd8b7efa39a16cc70ddae8bf3b638c8b5db4cd6186f48c1a760ccd411e31cb6346624e0a119c1085b963ce9d7" },
                { "dsb", "948976345033ad657e923f681579b9d2ab63a68afb45bcdfa133e52ce936b7934fa8c788c2f65eedbfc268e2a00f87786fffeb256eae28be64bb990a1c3ca04a" },
                { "el", "a8802d9199215beb9256be3b56663679793b95508a01e79a932f9e78fba7620a2aca7075ef238eca4dc252dc94de2b26031df9d35418bb28df8e827048987816" },
                { "en-CA", "f02ceb710b710ed84ca25391ff5f9cf7734a4849c4e34370356bf20272c2ebfbd58d0d09f61e3ddda4277ee33b9edf86da859ae61ebe57db197544e0c39ea68b" },
                { "en-GB", "85750e61669062897eb0141d126376db1176ecabaef5b141ab048fd321e92175c974faa70fbd7104c857f3e7b020ea30752d9bc2234a38bc403e092e45c3586d" },
                { "en-US", "2133a06784d9997d317c81b2caf5cce794bea562516d124995ad16d6276a6ed2d85c8ab8b8195418a279d27c2597dcef0054a3ba0227ef22e4f5f67b79c08f14" },
                { "es-AR", "826f197886354386b569fa7fdacf0afd6ce7f69dc27250ac175ce59162fb0df69c39c80a135c33238f28103a5c1fa6fc94ce5de864f49cdfdc32da3f09d17c99" },
                { "es-ES", "d97e1e9478eaf79a84c437de23d5e3456ecd7e087257d3cdba8ace2e51a8bcff8782faaef80d44482fed5f39dbb78cc619d1e60a9f974b93bddcef4842fcd125" },
                { "es-MX", "3b50d37b665781dd92fe60eaa9c2311a2cc75a5483c79923ca516040f25d1266eb223b1d684dfe5fb193bd727ffc5751f5899b74872bd9aefa2597b9e58b1502" },
                { "et", "da7f07c7cf28469ae66b1950cacb0e7ffd09384566d57358f3b95e5adab63dfc45503755ee7a7c89b063d0475b61170788ae2ca83c5231b4f65ae8d19cf7a417" },
                { "eu", "6381914cbef8e2b7b0fa34d540e626032bd83eaf0ff367547a2b4e6a406d9c4c5eeaeff73e02dddb1baba4cb240a602b9655757d6efb131047d10d5ff59e945d" },
                { "fi", "920a530685732d0f0942cd3e8d34105d39fb966404c929e8b73aabfdfb787c7bf7b5a0cdf565c6d2912cc95b6987e74153871d013c3d64e9b25ba9a112579433" },
                { "fr", "e2f166e8a022420fcf441593ea8b269f1bd29008e59c458e1305d17f654d35f7e5eb9da0b32e366744c48ff1dc1170fa47896baa4d51968344f26b659d028de3" },
                { "fy-NL", "9c612772bfc67d9b9f4931261e8923dc2cfe38f64a5fe33168ebe7bc91bf52359f8461abd5487574f8f9a8817a1c532bfa3209f97562486b1791628660b42d36" },
                { "ga-IE", "3a59226c9ab465fe9b0d9f385301e44fac75894f407d3151639c6d22bb9b50df912cc90614236224ad33652ddbcefd8641d8ed0fb9ec47e76c29b63d5ae12ce8" },
                { "gd", "34fe4f1555ba2830917be2cb4d2620c73aeb60e4f4f1bd9895772c1591a62703537ced29dbd57df6d5715fc176163075c770dbaccb3a246920993324786b2a18" },
                { "gl", "ec3a4b03bd98c69631fb31801f269b153c1c7fe3e478e57c8bea2dc94057ed29b41e30973b98813223c54ad8761a3599642a3f2b195449135fbcf30017bf671d" },
                { "he", "94d3a35f3aacc89bb1458fe55a466afceb77d8a8c5433a52c4be63d39f2e2214451ee70ccc7d9f3ef7a81b731839b6cf969b7eeec858c89723f6f291dd09d084" },
                { "hr", "f71cb743ca9121f0a601339bd94c50d57c93cc2fcedbbe442b397ac0ea29a79ca9e648b7d4f0b2cc874af59c922f43802422f5048ba9486c097c315605266368" },
                { "hsb", "283efe32dbd4d6afd6b3f31f87185e12ddd65323a1c62e18ebe659a31aa29e1b9b9465398206a0aca4d03c345c38a68077d6bb16ba15da9f4696e4efd8f6337e" },
                { "hu", "ed7d3729fcd5e5d5b399e21631e5ca95bd372af86d8d1ed435f862348e92c9082a962e4b5fc64d6a1d8b1ee2ddfb929fa6dde33f605ff33405260eeb682346fc" },
                { "hy-AM", "7ddcc33b9e4d204f1d9107cfe78f8ce2ded11f71e3d5805c33cae02fc67aa5235f60cd2378307809a3e05c21be9d3dae631c70974f9b2ef8c217d49533907185" },
                { "id", "9225099fc25eefa0e26585c512ff9abae8e22d241a85e92038a237975653e5545103d7755a81e85bc607e61af0b93c0e52b15ec2fb9bae2a9ac281388cf8a8ca" },
                { "is", "c728341ce192736a647f662feb68a7deb6a4ab2e1f7464f6852aacc8b49f89d52ccf15831e38f37cdbb948be139c1c5d79e1070b035f6ea1d335f2247961eae3" },
                { "it", "ce2233ed19a1357e1cf352de89f369b934b1c35bb402fbf8022261a318a3589e725e1030f641f478b092950a1fd175b015cd453bebfc5cd14d70391df830e118" },
                { "ja", "429de3fb962b55d86c205eb2d1d32eca42e5717a076724506665726cc2be1abe3f62537b8b2c480be2ba84d3af0454c0f7699dc3299a080c52f3b2a7c7599800" },
                { "ka", "fd7d50ca0313e3240d5ac297d807ba967a92c278eb59d39b7147c0c21d469c629e487ffcc1bebcf25811354692407dec6418c93b150ab4dbe0970ad2a7f8eb1a" },
                { "kab", "883cd46fc0bad314aa2a3f0bd3ff655b86c65893f15a062bfcba9e5c3a4bece4eea121335351936a255b2ad76c1441c1147c7de5586c610069252780623e9af5" },
                { "kk", "a3d598d3712d0494273a61ca72e7db754cadcc2f94a41a29d87448995f3d3c3bbe0ff81f6d016d0b86b82df2b2ff81281c135e9fd7f8ddf8b2080b5ebdede463" },
                { "ko", "d1d62f075c4d002f7291a0e1a2a313504e7643ed0af127b41e73cd967c752029232da9f5bff87ac035bf1d44e2e0646b68deaa2465fe3089e180610ace54ee13" },
                { "lt", "6d36d6089af6f2fc99576b50c8ac9451c12521bfc42a1e5d7892aec1269b9c488ddcba5fe7b6ab3796e7ea79ead20423df0c68f16922511382a801c5fb75a3cf" },
                { "lv", "e2dd0e6a379380ab8a494ad3f3ef010ac0688fd6958a372f2f82c08c915f753aeadf13a0bf542633b21aad33a0e5159de3f2f0379b494caa0dc22e879c9cc8f2" },
                { "ms", "3e8b42a342fa35369bcefbb6523f4f202dd61a1768b10e999b57fe21b431a8899999066056dccb5aa65bd3d40549586adc510fe2c7ac6db4dc40bc40a5d90d1e" },
                { "nb-NO", "58c7b44ace0e25309d9c9f6e9a0d198ecc3466a868ddb962725d2ec03f1c8d3e6af5eee4612c33115577112f2e407b29a3e10b668c95bdacd7d0c55dd229ec86" },
                { "nl", "c4a3ebd5ba6e0f2a730157e1055a77f2cb6ef80227821ec52c73788a16098816afa430463bb95faa5996e79b31d9ba95453d56dccf9d54bec6908082cdf71739" },
                { "nn-NO", "a0223ee51054ad6eb0ad8fc7499e7bf9f4c0557db6c71cb0a2a2345d6b11abf3a0145196641e1c687379551998957c7ced079d1d1e4e9a0077066305f382cfac" },
                { "pa-IN", "74ccdfe3334de8bcd20e4157a9524f9cbc63392ac353fcec7815acc34d3a3641bb94e64504af6a311a647fa89c9145cf2ca968ed514f628a8362043f64f50f71" },
                { "pl", "e1af770afa2eb420a2cefabaadd694679f1c3ef5536069c3f211805282f26f736785f438c987c83dceec987c2cf82396ad3ce1ad76b2b33b6198ba7e90e474de" },
                { "pt-BR", "f6857c3f86d419e438fb1cc6c36a7858326c2670af485693e27d2e7e8b02f27087e401826f86fa4583182a50a7d461666765c07c6201c90312e98a2c9b932fdf" },
                { "pt-PT", "483c9bf6ae3e77c0104886f87e3b359f954531200794a2ffb5cf7d6fb21bc6d5b1c2d36db0edc827e8bafe7003747a629aae09e13ac70e1986325578c3cfc0dd" },
                { "rm", "c58f8d3427272b5fbcd8d960afc67ce0a5952bd091d355b5dd9a871386e647d9da12c9e8f251a1b71bfdf484296ee2eaac72d738ff516971f399db7c55151ee5" },
                { "ro", "8dd359b8d5418faffd680a6f64a9e4bb9fb7da1798497b8a7edf4df98b45f3e71e378b3441d9cc50845ccffa71d46d721ad974ce5edeb69462205f672862e6fd" },
                { "ru", "865391d8df5e907ae4f54df36047893ebdf64a0378f93616e9b657e0a782bd9d4a22b8510265d102317bf3d74111653a901735619850796e603196c0c2f73892" },
                { "sk", "adfcb5ac9bfb0662d2668d27690cd9be6c21c2f475623bae460594da425b383fb2e38b866af8be7735f9b318c98cf2fba90713fc23532fbd44b1d42eeed99eca" },
                { "sl", "12b8a376b13bd211e919381bdfe367aa97305704bf91ef6edebdfca707f9b9948b34aecd18af121acb9c7c234d4805b10176b6956280f39b2a8f9ef9e09c37e0" },
                { "sq", "ae6b1096b7b7d39cdd6caed2c5ab5365c44508d074ddef382cc920ba1ba925c8c16cdc1814b63341254a0183d67a17ec526868bdc5919a88130dadd7c4fb815c" },
                { "sr", "a9a47ea422a397c1141270416e3ee311c4139a4d5e2dd6a1e6afa0addc895e765e9f3a3fafbb43c33029a5239fe01c712acf819069451ae5a6b73566b5f896b5" },
                { "sv-SE", "78fdcbf7f20c3cfb29cb02ae83525f79950228cef5b2a9f402b008d5b255ce84010c15a9dc53de8ebb3a6ab8418dd4971b92889186b952d0cf440fa5b23aa57a" },
                { "th", "3b5e5ea33dda192ba1bf72d76372a5b677261bf9d64b95cf2605268d31a723882c13827f3fbef47a8a6f02cda7da0f1d95ade25b79457b3553e2c17d9ffc1686" },
                { "tr", "d746e06ed55266f522e81a96c425b355894e33dcdbac183737f03b1f88d07d4a9ee7267c659e84b36687b3d4ef97ebe350bedd852b18b7b09b16f234225272ec" },
                { "uk", "df965c86141e090c1d8cbe00923e807c45891554fc72ef330e43c1b80123df6238587261be5c8daa065ba766e3abf2c8a9ee4289aea1979384b304b1d1104f21" },
                { "uz", "55583eab3b64609934dacb78d74825dca7ece7f7755337b38685014adb6b8e517eeb46f48b4a6c201657dc7ddb5ced0d4a9de7b7f0780ee58bee200260831b12" },
                { "vi", "67831753139f707f6683d5945cdcc14e985a1b99c44ecd5a56119cea3793cf60269c5b74d07d73e14bd58cc878a508221c9df633d9ea25932440e8e488d81a98" },
                { "zh-CN", "66cb4f2860447ccd708d1bce5546f769fd4b497d7b6000e8beaeafe634b2f808716bf7f3cbeaf93581603e51d7a7e897925da67097c2a65aad25d24bd0e64f4a" },
                { "zh-TW", "d1e28caac5df9bba0b93181baf265ac9a3b19dd218088ed5e9e57863b7ce9dbbd6a55bf3bb787f55784bf47da9de25ca597cb06cbb0ba4e4b9315267acf9c58a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.2.3esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "1d7605dec39e8b10c02ef55c4fa7ae9679da5e4c07e65673229532de78b1628f81cc09f5db9336ddb903994c68f2355fc19b0206ce09fbcc4ceaf4cb918cb12a" },
                { "ar", "0fdd87ed56fa347f6cae992dac3f1e7dfcb68f714e98ce721dad9c09d80d2b255ae47fd368f570b6f762918991afa435c6065cc986da5d3cf3ed52fd7b2aa495" },
                { "ast", "e74640ed8154223c8d758c0e9b67b9cf056b5c42408a1da06d551dbea90b6ab11643f27219dd50aa4164a7ff80c5b21efd4a49b8d160cb27f35cdd02301e30c4" },
                { "be", "0b16409ce27e7ff4a5b07316b563d9ec8aaefd4ed17b10c157edb3449afd112fc666f46f9ee4fe14665ac8f5f846bdcd2af06a675c275311314a1a70295f5716" },
                { "bg", "d6be40152c0cc298efb16380fd149b6767f8d636008259e2fa38318c850812a104f4113193058233a0da5ec3ee3c94b1c8735c676b80334360d0e69d13308978" },
                { "br", "6b970440c2dbcff8460b1a204cae8f49de771a59e97fe433cfa41e9c06c6b9d928722a1e30d34e90fa873325154b243aec666ad29cc776a3494cb08f71ac983e" },
                { "ca", "875447fa436f178457e5fa97421e1c1cd2a44d8d119e3074d4b30475f8efb04a2942e86166a8633a4467b7888d9a4015723256525467d9eaf665fdfde8ba9588" },
                { "cak", "033d1fb15e699cf37562b772a672190d8ec0bcac4444383ea4e2bb33f1e7905e0d5db52191f4f0ac26f56ebfcfdbdc0ecc05694808f817f4a00e8ec3f7d24d1d" },
                { "cs", "2c135cac83a62665e71f454e4884f93c8acfddba0a9be63081148bbd24308612e11c2370f993cfa059977b706a05935d81665f2fd8fe91d63c220326c6c4a44c" },
                { "cy", "05874aa7ac117aa03cabd59bebacbc218a09702fc3df67d9c2bc4554c671b79575769d4b28e001674802841c012c67f02c1f3043adfa9e407effdbc82c147878" },
                { "da", "90f7f2f7a92863f2130b0b87ba1cbfd211b75a7f59319c74e955972bde04aa04fb31e57c1540dd381055530f733a7479104115110dddd0febf0207fd840b104d" },
                { "de", "df9cb90168a0e6c46678cf249f6fd6b06a2f0ebe6f1470c27e7a7bd314d32386282facdce42e97fa1f01b870dccd7363c685af642aa940fd55137e7e883a5a0f" },
                { "dsb", "2bc0f277bb22b4e2bdaa06d2dedb3e5f6c56c019dae2625d1816c02c2b69bbccffe2eca9feb9f3a3f895a3b33d404cdec12d03ae49c5ce820de2ef97b08628f9" },
                { "el", "5fb20c232666efe9aa9f1b1e7c219fd7e0ccf66390cecc1b91bc90f2af0f8b882f18e06587db411582be44e256d8603ed7e820e5df5cb4fa360ae9e7acc7597d" },
                { "en-CA", "2a9cc51437768b65de1d212729f1276211e989f0c38a1e9395f9187eb9ce9168b7c2e5d0b8f218ab5a4392e47cc7468e15b83e9c3d67f5ba26227ab9d88eb374" },
                { "en-GB", "486f5912e4ed9b2bef1857c4c19162f0caf76285d1aec7dcbe7cbc1263240a9a03f04dcab13777a85ca9455c5f958e0302dbea8ffd634c3deb2d663754c9d03a" },
                { "en-US", "cfe14604da6d9ede39682c73d1e6735ae742225d65ef71f1f7d7d1734c7ef184fa780629c11a0f8ecc7f772fb72f0f91781566ec5990790364b35721976843d5" },
                { "es-AR", "4298ff0b1ebd725c67f1ed9ace8ca4fa4dfd684409eccf6413e4f30346355b71fd17b95e7930266992653443403b19e7abd777a3ba4c4cce51499d5649e7ecbd" },
                { "es-ES", "8890a47e543a78adaf5e3d37e4e59d82da43d9f89b0c45e51b2d85999369f3a588d3b71cf3fb93cdb1630f0a6b81abb33a281a1dae16989cf20c810b35be7969" },
                { "es-MX", "31f3d034ab90e73511acc5c6e103c3e29879a9a953f220dd6cbe3c4ae039c9fef62bb512877cde82acdffeedb0203c10d138126439dd8716c0c75f0fb87a0fd6" },
                { "et", "8d6ef51daacd223e852a21313fcc1e3583f2cdc9a408a8f27c8db22451de5cda9cf044c664d3d06c853e08af1232966bc19d9f8aed196675bbed9e13588bc102" },
                { "eu", "61f354d606b81412705e089c132320877c1edfee0bf7347f20f8f1462055116bcf7faf3a8d84e6a9f8e1a1afd4a240c0f8c190113a3fff780bd0e6f0653b57d4" },
                { "fi", "0e4f89019cd5de25c9cb3bd8cab3c651699c3704aaef222495e8b82efd24f6b9c01de0c8d544613483140531e21f2297fad1bb007314211849b32bf49a40a8d5" },
                { "fr", "9b7dddc8d78afd14f7064945675eedf5dfccd0e13d3e66a1ebbf45b8be4d20d2627acc665ce77426a1d3ea291f5c0d2279a7f3beef07dd2d511d47b29b87ce99" },
                { "fy-NL", "5d17c990d4386ebf9ae9d0156bf087970caefee1a6da8735b793aa77a6475f00fdc38fb42ca6eb254902bf903a587c32533dbe478e68952e9eb3cd36e4f2ded9" },
                { "ga-IE", "181416b3ddee7e6bf563167561a03f98171179bdfa6bcbf79c27e3e5921d16be3f99cf8dadc28eeb6b212d0c9c3e72a05655a993b9582e1e0e8338c8875f4e87" },
                { "gd", "9e19aa54ac6e7f9ce66a7158146bdda3e24420639e687e083a2a7994075b82bf19f0af511161c81e84adcc45e0cd8108e367b1b77eae61c3d6067161c0e6e15c" },
                { "gl", "d620cc8c0e83f62649440f1ccc38b39ee0fbdff22f61497f2df9109e4f9f90caabf474cd5647665f311471e089eb3185c635a7b246eabb22090bc60a0b4dd83e" },
                { "he", "c2f9ba8ef5e6e76c16da49edecaadc99a75791e06a0f7e7d939f657acb1fdb44c1a6b96d46a9610bcc583e92f201e5e6a3b42b965f6f6948b80acf09fce517f4" },
                { "hr", "dfe699d8e1c149ea710e49d67d1341535041001f41fd78e72077d59bd0253400604437c0f2451a75639de17d0b9a2a872187d72d1e6b7faf76bc4fce8345df06" },
                { "hsb", "018dab51b44baa6cdf31648cfe81bd74b1854c3fe2d7f187d3be05bc8d373bfa5c1e710d8c52f69d1c67db8b9b97f13e3c875056f78caaea86b30a077b798741" },
                { "hu", "d9756772a7c62c5d2820861e0172d64ea55d3531a76fd5a2771b499295b9a0097457173ddd50120995de153726f860fc41970c79ded1d29e0a50ba182ac67eac" },
                { "hy-AM", "957fb18e66aa1ed0de751da06c9379ca8f87e9d09ad790c692e3a9eadb6cfcad533f473a6a2b3d95ef61705981621828851278a24350817491a50d38be803f2f" },
                { "id", "16db20349f3cc2b915c8be4d601e89a769e07a1c84b616fe58a8cc6225d62230b0a36f5f68ba9fa37ec4a7639d6338c41217038c5f5e7235809c0498f82b6fe6" },
                { "is", "4422b26fcc0ee08d93f872e006ac60699bac5a6e5896f2bdcdfbf83cb0aa22a05c56d1d5211525496fe6d23f27590021446ad06107e65baee5e135f675b4fb90" },
                { "it", "6f22d5839f15299d3d50fd597928f8e1981aeb7fa25bbe78ce463579feafaa0acff745af7592f976d6b7d7095c15845d96718e752b0ac6307b7b101413b8437d" },
                { "ja", "e6124cbdbcc730396e68f485e7599fa8b3f3af0a27c549ddcaec751c2b8c9b1de7e758dfc721aa3e437762916121924ca0887188ad4a02444b883c98651e7f09" },
                { "ka", "5310c1706a4edfd62a3a37e13daccd72339957010b7c801055a710d51e061805093f170a882520ba8c358fa18e521cf365d4224d9fa07fc07dc69afd1a26c732" },
                { "kab", "6c3ce4c45bcf954ab5bb204056861ed9c3760702aa6038d9d1319533441b9c2bec5dee8a4483c41f749a8cd797d6ab31967d1269e326033d62f4c547e8646f79" },
                { "kk", "40927e10472c0a95dc5a1317f59ab295626c21ce9c177b7e870ea3f13fc77a04a9a18e560f8dec764703283460d4511937e6f4bbd1b4a97065dc31e3679d3a03" },
                { "ko", "75c58e75938d0bf63867fbe0ab1e71133492a604c02c346aaf16c4f0b720b62a5b4ba0633df022034bd8f6ae74bb1e1429c40c056c9af08364a7f8bef56abcbb" },
                { "lt", "df8e0dc8e41fcc23471807c334e1a2341b243c8051ba39554e736730637c6098dfdf59e65a9e51033233436453ef1aa011925ee3a720e95743d7e81646b5bf91" },
                { "lv", "d65bf574411cb2dedb8ae4c6d0b87e70d315f24a11a55142d70b8e58128ce1e6158ac0c37777cdc9166882d9e3d86fa667661e679e838d9e460847a95109484b" },
                { "ms", "b0520669136876de45b4fd85c5aa3a8a62bf3aded82a08e8c53579e27a23bf839297cba3eec23dcdb459b3d54371c3f9c036bf94f662cf749ee770ed13263369" },
                { "nb-NO", "1564b2925df5b2f3f420d5c28fedfaa7e36b1785ea81f4422a827d22f452aefd9c2cc9f5f655a5c667509ee4e90ee89b1f39313710ebdf186a22fb5120f306f3" },
                { "nl", "ef2400ac96462e90044ee709c266f899711d06ad247d2994ad95c188974ddf6a6753f0a6ba743275ab7e2039c5858f62fbce5ce7f31289ea5cf2993f87d3349e" },
                { "nn-NO", "10d9a44faa08686605962a6b661ee1b5cff2189475a167a72e2d623919c10e07db605e0e6baab0e36b7c3a107592c8ba09f05c0cf7600d337af8893748c6f3c2" },
                { "pa-IN", "5cc8d7e5bb96d2872d8f5f87e86d4685ff1f83c9a32d207d438303d6b6b776671eb41279d6668c811e4fab7386a7be1b6449df093ceb8bae5363803ae0638b92" },
                { "pl", "9ec5b1c945c94994a1e5ecfd5188e7313088621b01563c3cd257f510078a92d34fa036a65a9f984b25a30ca38df14d9320af38c44390ea572927f356b2677097" },
                { "pt-BR", "242325b23751f7b8e3ecd2b9f3381d765da7c48f07559c2ba45a99441ac906975319d586f0845ea9b5f189c6d7a4103bcedbe9e01da16149821757d2845eb30d" },
                { "pt-PT", "2eb44b14c113abb07ced851589aef3003c254358d9d782ca5cadf4c522318eb9834222eb288e5dddece7d66f69f19fe4af9c49a5689c66361de29bb8d1c9fba9" },
                { "rm", "58d8f89eb87db64be7b77107e982c20a55730a3592a815c949f6db8467da40bc288d07dc1d28fc302b63c0b8a07e107079b0d029345d4a412c4485fc6e72ada6" },
                { "ro", "b983acfb3d526cdc09bab43f69f00b58d5e178a7e40302536e96c106184627684e7a18ce549ca3163457c854c0937deffa5ca1d5e1b9b3ff5da845c77f9b9a33" },
                { "ru", "f2e182ff9a6255a32514c9fe66a10b890f6689663f0e7ff54d4675d7db31a113c0fcd1ebcffbd849deda7e336a0de73ae88488ebfda6ed69e05f26cdfc2eff10" },
                { "sk", "8e654dd111cf0e995fdf21bf69b17f008575e313192340bbb189eacb39d1467ee806fb30ba5821114016bd8ca00013f6e098287ee4ec5a79432547ff140c56c0" },
                { "sl", "b6dd49f37e98e0876510c9407753b82dca0f2377d8f8780bc06097e2ffdee5323cb697af7085be271c4478fd3a1d99dccdbd691c05b1c68c14ff52acb0c136b2" },
                { "sq", "63473d3b1e8baef1d674a2000c84dbf7ae659c2bd99e66281d3ec71c8be51cb057cf6bdeb8f493b1814f3d377bbecd20ecb120ea74e03996e107d3bbd3365ea4" },
                { "sr", "3d0b4efac7bf6bda71517698d7229d377f2c141726e54154da4c63aa7c94f9480426eaf49fdcf40af03c998017278422e9c7fe9488ba80ad8d24ba8b991371f6" },
                { "sv-SE", "99decf51f8cce3869b1de5fc6541d68348462edd788271183cd7d3dc924b5df4064eed64a23a8ddc853d2420d7e2ad1392f5254331b99114af0e844adf50a255" },
                { "th", "891d48b06e1e7ab64acd589def714d9da2eec6c832d6bb3d82d04e79fa43cdd76d5bd3e6c575e34980d052db900e650000c3fbb796ce225fdaede908d8368b89" },
                { "tr", "6f91a37da6bc9e09432ab2402416b9f057e3f5fa3ab7699d92ef199ff9e1a791bb166ea1049be3a591d4a0a73586bcecbc58ac274932efbbdf3a72a5c14f2b0e" },
                { "uk", "b3f249831af6b393584ca1025d66aed0e0c373071a52e9592bdc13b273b257b0b679b0433cf1c1ee352d543473434949803ae9de61e794f724505344d12287c1" },
                { "uz", "f2b421e812b93b1512e0d1c0571664f8a5595f5a560e2f035134f80fa295227b6ce21bc0338ca71da6ba8aa097b3491ad01deff08a4d92bb3d4d85f91367fa45" },
                { "vi", "bed7b430f53b7bbd907eb036f052e2a0eba1dce00542aecc35a38ff3f90e239ba55453555c5b9b9ca906d6406ab4e9bd1ac381013fc6ef3e68e752c05625b8e5" },
                { "zh-CN", "ac2a0d0de01c2b8749cadaff5afdd1af58f4615f0a9ba739d0cf7845060958326b749a2c756305998e1dab808afed721084255a86191b3cb5310f6afa76ed4f9" },
                { "zh-TW", "39369a0b121505c0a0a26e4e4f889049c652df70c664f3ce30e8c5ce07b019f7d8068bc4dd648b5144efc6d9b437e23fd9909afadd5eed872f4d883581d85d34" }
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
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
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
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
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
            return new List<string>(1)
            {
                "thunderbird"
            };
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
