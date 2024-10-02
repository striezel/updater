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
        private const string knownVersion = "128.3.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "08637f5cb328d18fd2b467485c037a6cc280d7b85e35508f75e7fc0f80118c975a4d9ba2a73482df23487070c12c0ef0b8561945edf4f1713f382e45fe14c195" },
                { "ar", "6539b5d73baa18fc98cb157d4a9d3b2a144092cdab2211751946f6a65c11acf3a1e2d472a42d23011d2515fed0f49ae0edc78f6b2013bdbfeade18af94ace13f" },
                { "ast", "60df2a8af79b1c0c299509c3b2df5f2ff7a3225320ea0bf56ccf8f4d32a07232b6f4a2c100f24bc61cc536054390bde544c333402346b4ab459ce8f4b056dd69" },
                { "be", "d188c8f472c26e214f16cc5f27f59006510a4ab78aeb4bce3f90bbb9e6f6c7195e88fddfccd2f945aa828a929688ef23bc85f75b89bb78acd79c864ae21e3a92" },
                { "bg", "edb5acb27bbc1d292acbcda1ac003923e57a6c5c97446ef0d1ffa25b18b30e499085d30c8fcbdd59e12f6afe7df9c472150eef35636f006816bb97800132d715" },
                { "br", "e7baa104e13844ab3abe345afe7901b15c62ffdac14d1e06b96312a51c80e7625802e332a178d8f1705dd9178edd9cecf33c50f43ab6b1c454de206629a7d70a" },
                { "ca", "a8fe87502965d4820fb959256929aaf94a2d265c7bfbff81ba7b5b164df0d08e2d1a6b3f3ccbbce166f73f006df642aca278de0e9a3a50b684d5c81ee7fe2ff3" },
                { "cak", "16347f3f6840148d319c73c3cfb1fe8ddba22cf5273e950da8bd09ecbe92b1f8b48a5f8e19614af6eabd7cc711c20b6db046c527bac18cb24d1b0af7b31e8c44" },
                { "cs", "2d3b32a48d4470817d0238088c2ee86bf4c716c05960080dae6e182be448eaf990e0c60ea59b9d56978a3bc69f8468a39b7be76ae85af5249288244efac17c14" },
                { "cy", "6867824441d491113b000de0b445086cec3aa504749573e97de86802c0cbc7942506fde9a709a60c7c8c8d9451d3db8f3dcfcb3675cc9e3631380173e2a8d58d" },
                { "da", "2fa1b1aa70716f10025454d5ff411329ab2ab1fbf4e8436784a40b2a8af99e884912a24302f745e6f93416b5306921704dd38f974fd98366f8de38ed32bc699a" },
                { "de", "c6a79c4cb0a87071022822df882f025847c1aa2c0ec487ec01a8c283b40f78597bb2a43a80d93dab2d6a068e33e934b082f70c9d72b9ba76429aa6a79563bfde" },
                { "dsb", "be94f4a59199085cc7e823d92368eb90ae78f416f132562381124e82d4e72a092b30879e2536fe2e8ba6f0ef6f0118c49f7896b7e8e0e2310481f6a4dd4adf76" },
                { "el", "365479fd5ed17e99eb49adaf84a32bbd1b6e2038f49e5b552eba065d069197f93ab799ce931293bab5b43cb9bdec66a895ff47fb43295f634348c67fa98c2c0c" },
                { "en-CA", "bb42a17486228d61f0722fdb39e1377385b4e0cab9d4d4505d2223f4f65b60e35995f5d9fcac71f2e5e6e0340d2e17137e7b71c203f7463007392bc6a0891fd1" },
                { "en-GB", "8b868c98223aecd612a69d27ce1fb34ff8680c753a6527da1829635d8cf88a15540c4911a06a95127cb6fd49b1083f4e5ac2f3fdcf5479b845a82cdb41d881f6" },
                { "en-US", "103ffdbde0047ed5643a77149ef58c74e671ffd3806849714bcd2c686fb6889fcef32eb68d23cda7bcab07efa5a9b0755f2bca703873ff06aa1906eceef132e2" },
                { "es-AR", "148bb2f5c2c726e7def72dde1613b2f6106f757b0ac625b75c2feefbdbd5945ada9c13e4967d050550165605be996bd274e5aff57d0bf8e0266762a11e7192f7" },
                { "es-ES", "e972db4ed292ad730c519a7287221b52ae9dc878742485851596b65820d41fe14ebc3c28ad82310457ae90be1d7d510a4fc75f284e1080e4067c43f038b1424a" },
                { "es-MX", "8fa8e0b8580e217e9042aad28f7db06861e4882e479bb85e03cb91c712ec5fb5e40a6778a4ebd8899bd3a98961f33d41fa5b381d4a5b97e2073a777209e6d4c3" },
                { "et", "de3709b6887a4ea15cfdb2356b1c1c30de3cdfe0f0ce57853d4612b5c8b4de01f06547ef92f7ecd6d08779059a0e83eb030070278b5707fb4732f77249ff8c97" },
                { "eu", "b006a5be3fe698ee1e004ac5825c9266b3ea7630b0e17e15aa194d44d91102ea88a2c865ef9eb89226c45946d3d2e5a58c8a2faa168c98b706117981642a7218" },
                { "fi", "ba63214ef32cacef172a2e688401bef1f3d936980b4a60e5e03bfff83fef4f52e0b0dde5daf8d3ccbce91e3dd744ad1769bbfdf13b6a001d1e312626364f6b27" },
                { "fr", "8d86b1bb7245b72c5781b756e9eff139b8d92d9f3c6f7efd28f4b1807e934e7ddfcee1e45cb73936e6a35a118e0a0872db311523c45407bb3218f209462ad6f8" },
                { "fy-NL", "d53f9b66e6157ba4f08a22be810bba41643d1822466636023ab0ea6dc0f0153923cb528847413e777495c47b5d088803674662443015cc112e84788ad63df420" },
                { "ga-IE", "272f2b6a933bb1cbeb477c06b826900fe5681096f790e99a5f4c6079f3a10daf373008a0c5220b69659f5698034057deed79a515bf73a4e9ea59b291ef3ad938" },
                { "gd", "6d3f6eb0213e6ac90db35d595723733289542c21a9e3133e381e849e3db1ddde3df7711c285a410fff8981da9a76f3d48d2f8b91f0bcf77489420adbcb486520" },
                { "gl", "13d0752deff287a13d0e14afe8ac96f4ab468647aba0b791355e3ae6381ba0a39db24e4663901d9375c4ac54dd15a0e26e9d3ad1e365a6ed0d51e02a7c80650f" },
                { "he", "94f3178eb39c5c0b0419d8ea34a62ea6e393aa7b785050ca5d0650ef4c71ae1fbea23b5a0e2bdfb7eb518bb73c75964d2d75599a39daaea0971c87ced03c7cab" },
                { "hr", "983f8c11ed48f1e27b689fdeee905b75c0ec96b8b21768fcc8d5e1da6748b15148a293c4c9ad771b94531a5d967c11f4fa300b2d638f9ae961a9f7fc7ade9d28" },
                { "hsb", "62a1c1780080b2d217b8a92fa1f1bef47752c7b853bedbe1c48d78fcea2974e5fa6dcbd9c145399bc6241b01987f4b112a09800040bdbbc9fa9f0f7be05260ec" },
                { "hu", "53fcea3a2def991e9329c249fe39d56c21de0c2e64b54ffa28f6406d3ea84da38388043e7b31b6c5d13ee80668a47a7b264f054e1a08a3599962656c0c2b2441" },
                { "hy-AM", "d635a27607d37d1e2ab227171d2b78767217ece3749291e7a76ea580868b31ac20593e37f4c700eb7ee0bffa9cef2d21111ae389a72edd4579e243a1a171f318" },
                { "id", "1270cf614c79aaed4f54205ea5564200b7193dce2968097ce0f6fafafc3f34072ff6d862cfc782b74d48a13d7aad322030f6576041b72fdb40d5a21359bab6fb" },
                { "is", "44c2f45728e9b8a8eb6077a276bf57af57c69234301074ecce80951ce79ba64e7789a26279e262063ae804f5b22fc25a5f8ad1b7c5910a6bf70be356818e35f1" },
                { "it", "096d2d0304196e50ba7c092d591c46e4554d28036ce95aa4467a642164b0c1da9da74c381364d5d6a5c7a1dfdbd9e86553067120fb7b651b1b2382b24adae76f" },
                { "ja", "56dcf21b049d21923eea9eae18ac6d97c71b35aad1440e1cbba4af04c2d5a65c2f884e9b4d4b52ba07092b1d46093c93d94268574feff4614ef281acffb9c15e" },
                { "ka", "1cf4b4a242f61c357132be8d39fa5f7657f475ba9ede9f17b47be22567fd9794dc0063af5d1120653fe63919c00c8533d7f1c3f0aacb4430c6ea2fda7b1efdfa" },
                { "kab", "6ea82c55e811453e056d7bab256923a0801c2f6acbe9d0a7d2a88c0e14a5b76d8439be619b477ca83da6a25ac2c0a550e9465d2d076f2fd7f4d3d6044cf6ba8b" },
                { "kk", "5a248d96593e9b8acbcdd5f1051e6ea5d81acb087c83ae458c5642c9bf5e4276390196e55efba1454c109444d817d7edd2988a3662ac10c938b06a0fb2782e12" },
                { "ko", "f294e91074979e21b7fc2ffc7210b9cec5a99ef246edb67cb7aaf6025a571be44ffd99965954ba79a04dcbd91d1eb9cb39f8263e094c9e887d367af761ad3824" },
                { "lt", "5ae814e661c1dc5564a51a9fae0468c29e5cbf1aae1ff64cae301bc10ff8cc23721c31879b7bbf8602846dd766df9a35290537d8f5afdf9407c1b95bff7f0505" },
                { "lv", "43879b4780ee472a68b52dd4f7e93c6671785653d9bfa9cd433389326bbbb0c8bfddcd6a8dc07e935848daa6163571c91b7cf3fd68c8c0d7e8f9f01e481903af" },
                { "ms", "b24b63b73cc18e74a6bf416df7e05269a202de55bee4a34ffbb0441d1bbc345573dbdc50bc1714e626a292cc39876bd5f9d6f33eac738441238719e3a42c899b" },
                { "nb-NO", "01ce219955987aaa428c29b30a6f4b3cb2d6be5119f59f870da18ed5d200521ff927f3872bf1dd59d9533ede86137ba054451dd6c87895526668ec516c87ce73" },
                { "nl", "d361f24335e7cc27cd5141df560800bfca3d81304ed193f60dab33eb4d8a27f51118487ae7808cac8d9a5f0d6ef91fa9c066794f99ced249c0c52e468213ec23" },
                { "nn-NO", "3514676f12c7b33d146736a19b7a1e3d476be41cbffe0392e9a8283a171b9269e9d46de87e919a69c7a5e9a66df875e252c1701aaec0a206251c00c7043f7694" },
                { "pa-IN", "9f4aba9efddf449e00ea7cced86616af8dfd03cf083c5bf2f47080501f2d14cd72d0415b4e76e607b3a5063ad1db88a666837e9f1900e41b7f5f93cb451564b6" },
                { "pl", "f1603f5380d18c50b9c7ddac089dc93066e3aa5aef582e221bcc97ab096afc98c9b9aaf8fb4d45e7fee783d24437b8243e3fb9517a878ccd922862d9e7bf04eb" },
                { "pt-BR", "68d981cbe2eb6898358a21f6153409db9b558db6600c0a43bdfd5b3675b149e63560cfa4a881f1df55d0aed4a4f03ef32fe060b9d21a92754e70a65826db6f03" },
                { "pt-PT", "66695bbd1c0c5ec698c590ee96b56d8b970dd84182493b9489b2d4771d6289077eea88e71a642194e9413ea47c0bb998c4350351d4c0929bcb1bea04c580a781" },
                { "rm", "e976970d9fbb94387959361ceb72e439f96c9a9a7d390f4aa5b75ab4975dfbb0292f87456c06bdffddd140a7a7e97aedbded7385d56501040050e0a761a75e8a" },
                { "ro", "5ffa0dba5c6c3d683526d6fde6d4e27b93f423f2e29d7e5dfca6b67981b105f4358c8f1eb5db629ec69c87674bdd8f630f3f19883ad2d146f146d87e82972809" },
                { "ru", "e43528d735318bf0ee2b1d264665d0b45bfc44e36e45bc7494045a8719fa61d6a87c5a58651370dcb0c5fc45648602c578eb33d8e49d41c2a46534881bbdcaab" },
                { "sk", "5d5506672578571ce66c43beed15e200b9afb94964de446aec442801ac64f644cfcf24cd02d273f38ea5e91a8dea9e8b50e6e17e6db116c738044423a8edbe36" },
                { "sl", "f3c9800439e67416e42e720e0be63c521a086c26962149b5c3c8c897e6db6f8e5ac0a5b41bc802bd5ac624930e1e88f48e2e5b933bc3d3c84e0aa60b57743616" },
                { "sq", "e9923c909bda8a47ceadfc27228eff9ecf4957de72488fbd514e8d1426f1779de56ad2b32f65524b096b66acd836620c14657c28aac7e3b5413c52abf38ccc7b" },
                { "sr", "8e0ea853b2c9a328228a450ed32a2d5b9774d418d3e51576af86f86591552b1b003a298211c0ab254e1a5d581a840f8a7c8c2c5cd98857a0fc7928d5da9193fe" },
                { "sv-SE", "7699133c84b4498a4e4aefa1f20814f2b50422d1e6b03286c796ccb0c1972348c0752b8ac2ce225cd555c5a7cc0a71ec8d8e377d1a0f0bc3bcec62a87f332b03" },
                { "th", "480c8ee2dd228d0089cd590bbd673fe4355c830cb406c4bda1be6f787b31eee31e5fe1d0689bc5ff95a48fed211b31a74efc933e8c39c21f458fa8b1cd7ce58b" },
                { "tr", "96257a3d78f1386ba9db52c43744f40bd93f6873a42a72afb0a1fd334a84c502b31c822640c15f3e6f9dfc6ab54b7b194a1253c829fafba74533a6d8f97a0c34" },
                { "uk", "52bef32b5fc7858c04270df1d66a942702c67433070084f646b08ea945fda2ac9f6a207c63ffefd036fd7fe4e493372eec592da347444f4be3200bd50729d6d4" },
                { "uz", "adf7514078df57c7df652f59e87fb83ec78751c58a608c0473cdd7fe423a2e1de664c5fbf7997588cc75651876799c41e5366a0d5bf5da68757d0a1bc8708300" },
                { "vi", "0838c0e01e13c611d9bb82fa95c0b3f7293576c89ac234cb597fe64f4fe31833c3673b1486f690d757e700b3fdb6abe1a8ac69f0deb56976ad03b2e2a9b9b944" },
                { "zh-CN", "39cb10856d099aef9b938527489f3f29617cd543d894d4781acbac8b5ce24235c77ab715de5080cb628f7ca758a80536b70c03274bd00241b494c380aa9bceb6" },
                { "zh-TW", "b4e4e0107b77f7486b05d49eaeaf26e370b40a5ca14abc2b6aafaf7673394184e8076d55879e30f8bc04c92dbcaa15fdbb10d77fc976008da7f57fb99a6f1261" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "b9575b138d15d3de7bb5ccddc59b305848ad8e376d734586f62cecc40d93a1f641e6d97a0db140adc4942ec2d757b5d7da535cb526c87a8ca118ee793f8a2916" },
                { "ar", "a2872c961111988a846a09851b61424541b77510df5a3d60c543ea1cfe53238832000eccfa1cab1c3b0a054b13f40e06af1ccabd41f52878d4f7072f8b309e33" },
                { "ast", "aed85824e140bb593748a3e19a8d3b1dfb4b7fe4286e4fb283ca1f868a93f16990eb116b0af81360b4b27f2b25b23ce25c1da059cfa5a724b0603e63208ba60e" },
                { "be", "30f3737585ef331001c14da34b9e68081d15395dc64a5e88955d760e20eaa0fc216ba98b72ff25021e7ced2155bfc56b1fa4b67a99a261f2a5149944a41c3c9b" },
                { "bg", "b4157b7f47cc95268d94e00c066e2424d944c24085f8f32a7d8d5d1ded5d9793f86fc9767e852c9204bfa9610931b1b4f897e90305a3199e562dcec3dbf1a1b5" },
                { "br", "5746015be2277ba0c1aae4fc70c4e9d33724f1a10c2469e0129caeece694cb78966adaa381e428947a0e90b13c74897015eb17f6e9ecb2ee33df0fea4d4b5807" },
                { "ca", "5258f04210fe1b6792ae1056b9915b13faf8312cf9ec5f22a633972bb409582b292c8e7a03e9f5f3a0dd7e82bb8e67218062509d08a83fd6cdfa3423dbf5b3a7" },
                { "cak", "e4c2108ca39cfae04c0e3c7d3c77515322fd404e4205c58cfccfbce9b9b538a855f36e1cd3a6cd17e45c67ea4e7ea71bd111fdffa62dd2c87b66f63cce452948" },
                { "cs", "df7ef38b6aa8e453fa89d5b5f1e1a3911b6f99076992eec4b4bc9db2f1c25bd274efaf4701c21b714894049d1a58e3a344c69def215926ed3a7e5619e0667784" },
                { "cy", "6650239c844c03435a994b83b88a7cfba76922201feb2d51419ce5cd9fc04eba6a7d114ea501d68d7cb2dff72afa740e263e4ebe8698e0db49c0f2ec6b8647a2" },
                { "da", "d630c65cd01c2bd9712027697f02840025c13545623b759565f4556eb6be5426d6c40b99a8c7a1e698fe116969885183eb603f74087421c8a962e695fa3d2f29" },
                { "de", "0df9cec8fde0184bd4b69676f96a81e1da2a3712ef952f2ed3315ef36bd34d9dc543e9d470916a35221fba310a95d17ad31067322bbf556075a5030e8d1e9535" },
                { "dsb", "6f9279be92daf31c8e29399f338fc17e3b33cbcac6886c8106918e2b3c20ff49dcef1abace4780a70d62ff16f305b532a63ca6ead6893a86443d07eedaf7ce63" },
                { "el", "b61677c4374a170a524a1970833875bac6bfa42fff7438d461a4a1743594ce34a274593f23246569c6466367c9360d63be13ef270e28623e03f5dfa96e603bd8" },
                { "en-CA", "7718b7a9c6ec0c8ea74fd2bf75dcb3575dc9c1d378e0cdb3bd8cc63146cfcb3c9e6100008e95ac20e542cb9ab9ef3d53f47824aae2eb5effe323329437528e77" },
                { "en-GB", "553cee0847185cb87ea442042b4e979096dedac20f85820ac3a90104dc82d84418c454c4035531550c560d27c3110e6cb18c9a428a0040c7c75ad28c96e94cb8" },
                { "en-US", "cf5095261f2df1da255805b3baabc8d62ffc6755bedd944fd6bbd6cd99cea57348e706fb25e26c8b378e656f852de7f392a765094000e778fcd23fff1400be68" },
                { "es-AR", "baafe3f5d7245289b313688b3307517a04c80b1013fcc810a5280d1d2a6c9f2aff9f69b0e3cf50641f52da3e4b89963733174c94fa3d53d78991323adfe1882d" },
                { "es-ES", "13d55a8053e5c93af0483cb028995e410502339fa6e5252560010504e5468e814fab13a99edc82ece3a261513b4ae67411bb43f6381c39967866ec48072326cc" },
                { "es-MX", "652157e763dd40915ef60e0ecf301514d52affcee8f3e621235f640943fc0f2240233478f76c563786823268dbaf9bed902a904399a0cbdc90a9e8324e0bc0d1" },
                { "et", "1a59121d89e8774357a4e14697c290b841480715c1e32580ee529378952eb7fa11d448705257a39820609e4df182f01a0bce8083bcfc5876f5cad48daadcba64" },
                { "eu", "688ee1200d44938e04ca2bc45599fdb303d27dd1f3609cc8e089d879d9117aa3fa47f7873d1edb46bd7061693d0421a364d449ebfa244ebe2fb1d6323f3e64bc" },
                { "fi", "be7b37ec5a1842ff529527cbd22035ef38ab025389d3cb3213aef3b8fc95aa9ac392a74516c82f0e3578baa74b678835dc677a5b61cd518749f1d5a6bac25ff0" },
                { "fr", "5005ed69f29542e8c8872c27519dd12c938aa2f29922d378fe401c3e3bc744a3b33206a242360ea2db151f8b1affab4e25b9dc887c520a0d1c92f70cf08d0f26" },
                { "fy-NL", "6424563e5484d2cdd212036f7e4b3ea05a881a230b6d5f906f9db80038dc45e5c2f19232e68e0573c26d7bf9c342c29ae81b5a9b910ca07522d639212ca06b64" },
                { "ga-IE", "1aecee1742c53ad0fc046fb1ee3967f80a893579c3d6078caa06702fb12f8a107c72285ceb3c57df93bccf3f50b009ab47181a525c7333150a51dbbc92f0984f" },
                { "gd", "b9bb41cf26862a6591a7c101603e1488311fe9710f67881721cd50e783c17c0847f91ad55be6c746fcd4b2c3bd8eb19a81cc54148deb8ea710e72b03f0f0fd8a" },
                { "gl", "80c42770a025c1522332949394b1584530c32c83635c5f9d0d9d0fdc3023a5f1e15c91e912e147084c586e9d408f096a09450a92c12542e6eeaf305d21e719e9" },
                { "he", "7578664205e548a9eef5def94246ea962ebe4148be23910787a6622d523308d4ed480512e8467977d3d2ceef0e217b3fdad8baa83a3fbb270cee545a1234c2d7" },
                { "hr", "53e8d9fdd8e074b9d4d63ef2aace4bf941e13fcdf9350b72d285ebd9baac566335a2705c6ba8b0c517f82de5af499cfbfce9f96263159ce96c0eafc5c67148d6" },
                { "hsb", "fcde8c5bfaa73ec931a4ae5db8c025188b41c59c2f04972acdd42474260cdb723cfd7c18808f05c9d5c4368a65a85352b4c491e94e311c5cb39185fe87aaa0e2" },
                { "hu", "0835ebd6be9e2eb2416ee063ebc5ad1a3eeb2ac6fa0f08ecddaa07a35f2fbb4d9c0b019f8a18bbaf1e9c4ba8877332f659e6d34679d23fbca2257de414e3839e" },
                { "hy-AM", "a100f4c66b55d38695fb7938270c7c82b84083a6ccaa1876f6ebf4b9d2097368a1df7110277f07518c4b05937d9fbf3c61504fad9805f0298bd4bb8e2417f4fb" },
                { "id", "34d48d0a38585afd5e82f17acdb302b8543a87151db6b00ea49eb8a3dd94ad90a4f90b81ed8546274b9647ebff6b29ad616272dd3f3ae9edb7da92c923475ab6" },
                { "is", "4a30c2203668dfacd1d5f34dd463fee97756083fc1974dca7f0251f585137c8d479fb119af7c140c4af5ed6ecb343e89450ff930bbe529e23acb7e5a14d06d8c" },
                { "it", "90aa91118ecddedfc52a5a00005fb77237baff79bb62f3f1e5f8de855a60a18b2e0d2a5dc7030d54f96586512aa46f95a51623fb13e2e54b81190461fcd9dc2a" },
                { "ja", "9ee1626c1911c33a50b9a5ef6d4fb4597f64c38aa8fd7e56b2118d59192c6330a0ba86c12eb7cd63ba0d1f4962b5951535fc6f2ce8b346054bc9a613883607e7" },
                { "ka", "20edbc7866756f7f2275443b20324e2f5c8ac08a17c12733d7691d2a6684b042f3c76cd4158102ed35bd1323f905b0c339298019641048cc2fb812c1afae3c99" },
                { "kab", "3e08a219c16a7865d83ccadaf30525eeb24141fb3edade9ea54c004a5831704ce4ef7045cbab6cb954b115f62482ed8fd58a7c984a6889b5576f4fd4dcc18ffe" },
                { "kk", "4b757e2976e5d3d22c798e0ee11a6681db1be3e20b9fca6fd9a86cb9c91887e422813f2bcdfcbd5c5ccd40c7b9fa681c2eb2edd4faa270fdbcb4eb79b354291c" },
                { "ko", "d6ed23c07d72d22179e21370d47d31b2e6a5685c357a8be8e23bfa2e560578dabbde448f9ee089fd57ece5020e6837206b423cb05f097c624e602365944a2e60" },
                { "lt", "7f0ef790cfb2b094c54c949a56ecfc8ecff88bf1922a5418f9825e2b0c3f4c96f70e77f4586d37becf6f4acb63a64299925bac321408801dc4ddcd9a8665855f" },
                { "lv", "357d0da50149a0e3a9513681f95b5b376b5529902ffac2aecfac4d4901b0fb0f606f02997a678925e8a2a8ee6a83a65d0007964a9b03961b8daa53eb0035370f" },
                { "ms", "0e0c64c8633a77730e0b82b1f9854c2e8ee36994fddd5527687c94857a7feda8be005a65773deadadbc83cff9b0b31217fc4ed2ccc684f4df3b1faf1a13d3d12" },
                { "nb-NO", "959bc8b5348533c3b7b0f512b2639228f03d8b80c0f3c2c3da0580eed7019c03b8746b7d1fe4a57c7e76d95b6b3094c44972fd0e9350bb475903de4506b83d53" },
                { "nl", "b552ef938777d54da5b51deba601608feee9c7fdd380a11077c883a6512220162077cf2ae60a82db430d0fb32d3ca9504f55ac9dd34c6e0ab54caaeeed4553ce" },
                { "nn-NO", "b46eb2675f818644698e39b026779621cb57013825d09a9702b4745d4c6da7e79e33aa3d17e4479cf3100cc24f2e62faa4217ff9d056676dfad0af9389e56e86" },
                { "pa-IN", "e97e7e2d559d1f088ac2e3c18aee1c2e5762423b5e5fd6531821dfb31610e76c1c32206fd3b9e7d5655a4f79f61cb7654586f5ad9efeb0f741db9037319c3349" },
                { "pl", "77ff6992506e7ffbfa758dd4cdd1f14dba97262234f987e328128b44d34f6601302523c77fec02ed8fcc860cecedfc03df7b1fdd11fc8be027d9c771a37d3673" },
                { "pt-BR", "be1a73ddcb09823ecbdbd24f22297acafb3ee522f5e2da71b60973a06e8e403c89b09e6ea51395865d43a57b793affd0e048526d7e040d28eb19b16d68b9f601" },
                { "pt-PT", "578cffc3bf8596eed6af283450f542ab93706ebf5ee094a395421bfe4cf98d68c1fee7b06e4fb0d3b36b4eaa7f5352164cb8677e11cd3919bdf466c9ced88289" },
                { "rm", "32755777d68942dfbb2be04a9bfe70f3087435e00490da32b728cb640d35b90233977b0ec6309b6586b6352261643cfa9c31d1a53789984ddc69620ee1809954" },
                { "ro", "5d38c56adc4bf9681973815180a0f3f296fa2fb8c0d508e116b9114a8a375eefefc00d7b7144bc3dbf7e27b45dff759d4f4967b5e98233c9a3a0e51ec0f7cbd2" },
                { "ru", "8dd9cd9846b84ba4f0318700310ce5e3ebb5ed6572c5cc260e4a2b940094e93e8d6a19dcbb7ef4d4e1bef4a31217de91a9a8d0927bb0500e52e41ff5270cb41e" },
                { "sk", "5dbdc5d07facd1f016b2ce9cbfaa5dc2ccb54fa75f2a3097aca0c368a33ff40be227a33011f471e24db5ff8cbed13c23a72b7e55cea6d3720db622fd9473974f" },
                { "sl", "0a743274650f4c75e7cfe04145f02992b770be74f6f61a03b3d6c27e400dc9b7bfcfc8d5c5eadda4f9347f71aac61751ef7411ee81cb83022357d32cc8ad3d9a" },
                { "sq", "da1e70d3991dcf908cc2d21db23c27680db0cfa43a09f9b046e634573980208b3df2221e5531ab7746b41f6e5eb028e96a309cda68f72c66f31c8cdb7bc80f51" },
                { "sr", "ed0c820d65584f77e9e02599df321c20378f936500e34a302ee8e3816e0303a139e73cc2852ad4404c732c32da0d827814e21df534aa41ced13ae08c5ffde63c" },
                { "sv-SE", "3bce2b588060b7968b21ea788b3e05cdccc3415bd08c68e2e7a94a3b204b5c475e5188f29623f23955f7820cab9a0e09ba6a6dd8ccdcdb16bae6b897d7a2c825" },
                { "th", "f01fa31971a409e78fb36c7437a4359645aae95cef78c59dfef5e5df2870f521cf388dc8e110313c83f78b981ce3c466fe29d069c1df30fd80b58ff65d87dcba" },
                { "tr", "73974ad5eebe96792bd736f60b6696f536f09a33362436b27e2683ef023de886e62e66c3c4881d48c013fa88fda4b1a0179cdbeeb8aa79f941d20665c1acb52d" },
                { "uk", "c02b79ffdb9e70241a1465d58af20d7bde27e263a2d15ffa542d1e9ed097184b3cc9da7f79a8e89af4bcaf0db39155d0796cad97c09ce9c85b8b70a06086b102" },
                { "uz", "2fe6c1657b3df6996318aaf93b9585b25d7542f62005c1f0977c65fe5faee9172ffe6256865d5172895dbd6e903c5f19d504f80d20a5be8cfc21dc75e794e9a1" },
                { "vi", "8a423d92878edbabc1af53cfcb52c70db9cf6d6643096ca642129ba9751e19e66643bc5f4695284de80c7893c5d651813f660529b0553da62d37caee1ab1cd4b" },
                { "zh-CN", "313888bc09c9dbba0c1cecb3edcd46a4ecf95018ae0211d32abd0092bf68a4ffc4757ef8eee82e1b49d4b2ea19be8b875fe3f07cf2e9337c9a3c918f7b72d806" },
                { "zh-TW", "53b1da82cc28e12385c14e27d68fdd75a35d578c785419b4c92619617439adfa1eb4d9122a35c284406b16d16a40f5f21beac3126389a3c4e29b265ec3c209c5" }
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
