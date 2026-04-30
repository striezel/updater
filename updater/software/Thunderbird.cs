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
        private const string knownVersion = "140.10.1";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.10.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "7a7bb65f6e0017c1a6a6a72e844eb1b199f2d43b0fcaf9e57328bb0d76c1fc3363afc0b8f0a48ec8f2baf0e1c829014606d71fb5f8b460af6ae733d8746cdefe" },
                { "ar", "8c7dc02704975949c146e0d16b9f113073d5e4f73bcf299627ca543868238551ff8f3cb62d2e3128267967babb063a78e4c7c028126d8ae3b4b37ca39557dbe6" },
                { "ast", "f2c61ae4363891d99a83abbac1d9b2f18da74e9d32f1d3059df93128a1cec65eed6e214e6311864cee0446081470fce4fdb073b4a4bc596b6aee074029418588" },
                { "be", "b4228a124f74a581f60f55be813017e8b4ea1c26f78a323deaab7f44adbe4730e073fb3d1de52bc39b3d62674835dd2e24f6e8f4506732e5d8013dc2a03b01c4" },
                { "bg", "6753910e68a4c7f40f4d75ae97d32424cfb9f5251773ec89220b35a441a91cdf35b2ffbc3576b998bc07beaae9ab32b545537fc7224744f2fc182e3447129bc4" },
                { "br", "7ed1e0414810af8eaf59fc99ff6a66161d6f2ee80121d9765d1f83cb39c809344e9419d267f75d18eb62bfc215997973d6a4ef7b2537bfba0ae070391adbdf85" },
                { "ca", "af3896a991cd11335d11f2ab9379aa5b5e1327a7c3c42cce49fdb9d6e1b192c58963e35967e7ba1dff460a7181886216d211f41c732f78ef0df920fb0196aea5" },
                { "cak", "5b0854161ce4bd737dbc004a839b15cdee614c581e9ae963cddaecbaa7545013efa3754099f3869cd907e7b289cd3ca26984f7efb44c7b17f0ee6114626627f1" },
                { "cs", "bba8541ce96b00aa4fac398d36ac22780905084c90ffd7bd955978aa90379eae962f25b229274baf609f9ccfb7b217951d6bbebbf93dda7bd049c229a3318cd8" },
                { "cy", "993fdd8a6aea0a4dc68ad5739e943be2d3f3220e7293c978906b09c2c878869688b6b964312b00e053601bcf280c16333e3996b622f005dc4160cc4e14a4a553" },
                { "da", "9fd06ec72fdc6d8718d9e4ec614d58cebdaec0860aa8e65120105663eedd973094bd8d5782cf6823054175b2c3e3d271de63366653a2b98552b1eee644001cc9" },
                { "de", "b57582927c000ddc99fad8c7b87f36170ef551c9a1dbb05729763ab75a5ce18a7dc2821087b86d56cb6611a18ad141e6546cb788a3eb71f46e271bcbb65e11ca" },
                { "dsb", "d38f27034d19da715d79c2a4a545ce244a3307013a8873dd8a0ca796103857c5e44939e929216bf5d3dfd91066e7afe148d5e79a47fbbeb8116aa3af9a7aedea" },
                { "el", "975d29d644013010c7f50bb754a2990838229596e678175f96f58ec6dfe300b1be0bcb0b13b1ac36273549dee45e9b08752fb99bc457e371cca3e45a824d5378" },
                { "en-CA", "6c83cb6ecb68eab014a3f5b4c97367540045d6bd9db3dbde5e62e98f7bf1f1725ab9107aed58e899b1cd745e5cf3c2a54c5baf4e822b3b100567a20cd073c973" },
                { "en-GB", "58165d39e69b59912ecad909584e47956c7a0b682847391ed3302729d33b325fec039eb2e50644d4078ff1f5c3fb198e49b2bb4e6ee5aebadc0bc7a11ac5c19e" },
                { "en-US", "a218f1ad081d9991e3809e35592d6f9cfaf24d7707062d4ddaf57fabf06f22f13230bf142df15ec7d35cc793f53450f4b4e6afa95459a3792feaa42454e1a271" },
                { "es-AR", "afaf057813f71963dd1f897bdf70267d4eebdd9c71ea6401041ed011ee9a5bc1d5a4a6dd95e773fbb9bcb222f56dab23027df5986ee2cb48bf243bc7775be8cc" },
                { "es-ES", "38a722b8e0d7f3d9636ae5db33696fb1a85badc72c74cd4a05419d7fd3cfbfa7da174e15c0e7a4703a1d55a6ee675b165e6c500d5efb4094c794acbe75b811f2" },
                { "es-MX", "d868aa1851a3e40a58369facdabf3050946d55032e83ef9f980f5a68afd4767d50ed36576164b2fb47bb1c818144be654cbc88035f89f27124d023133e3a795e" },
                { "et", "f1d456334c80095da6f1437a999fae5c828e6e4e6d39e1728dd21e590460b0c5a8fe8ee3edf337d99514e99eccfb2b5f57e37a4ad5e2515f9b20c8386d9fce26" },
                { "eu", "c81647f301e45eba7552364cb42626b56f943ac9ef5e837ad3aed8484e9b5e4e4d7cf3fafb5b557b3573c7e762cbf09f5c4783a247ea782d34d22865073baac1" },
                { "fi", "4118aaad86f0b6f462922dc3eebd621ce79e52a71171a4888dbe82b76313b2f849f0c19dfef225fefa0e4a1544bbfa132730fb3a45d8261e2ed95b507c916acd" },
                { "fr", "f5e6f434b7e9258dabff50e81c9f741707d052f476f7a386bd387f0faae188ed4f1ab432d082d6281398e6e77cb4a9e303172c73530fc8e10985e06b573d248f" },
                { "fy-NL", "eabfdcbaa145d043ce462b67f3ddbe20d7d5d09774340be78937e3cf21ba8a3db34d545984cf8f1bdbb35e4fd0e7781a40fd782205a5a38ba5d992a18bf31963" },
                { "ga-IE", "9cc1a974939db4035f77c3acb27cd54d0f06dee96acf7e5587b727f10cc2a538a2247ed4cf75ab6d29e9c0ea0b3bce342428c8b884b86f093103ca53d24587b0" },
                { "gd", "06679608555426d81705053c22054d84726e67a2175791d04a8e886e9f4575581d5589317401788a7d7dbc51e5353ee9eea0881074845e55eb3d8d4f9063fceb" },
                { "gl", "6fe04701651c07fc8d680f48b01a69af937aa3c8be9f5309dd029044f1b4eeacb94faaa82eac2bd3e3acc4ac276a0e1ba0056287daa7c3c549561e39c0e93c6c" },
                { "he", "d276a1b117ea639c7979011bb0f1e6568c0dd501132de577c57617781d35ad8b1e734d05bfb2683d41fda787e6ea7d6fe41db99dfde70c8deddd49b65e268291" },
                { "hr", "5afee45e6af467bd57e78965df61e7a98185fc66a76330f0d80423fa80d2514ab88847dbeff26cdbf2c1f4f091356fd4c5f72df626043d1404619dbc961ab265" },
                { "hsb", "8ecf0262059fcc49cfa2b7d57e7d87315d19de4f84d4bfb912283690d72aac76660dc4642b9c7d508d3dc55c1a32c5280eb7800771e96adddb47593767518022" },
                { "hu", "1f1de4664b7ce44380bdae633fde60b076b13d34f0db58b0b549272c21f2932a74e628be175ef78d0c22ec0e882daf2bad07a30b2e239a30a58fa4f1e2fa36cf" },
                { "hy-AM", "9c5235754dbd360ad4fdcfb03816d2ab7fabad36d57a4d9629cc88e6a6e6073fb0543d09bc33cd7f617af094a95a54c41b8be5b9b26da5dd205c99831140b5b0" },
                { "id", "bfb45b98e62711aff5583662775a4f82f43a280cf290d5e689a2e0b08779d65d635ecb36f8de256239c73cd0105155ef6391054051981003202b9d7914135c45" },
                { "is", "d7e52f5e8801b5e69049c44358ec7412e703dffefb5e5963c905aebb6b0d1d7cc12c917a6827f2c62a5f9a60d01d7975f79f8702f91c4e132b9df4eeb7f1867b" },
                { "it", "697a13c46cfa924c507a51e38b31f9babc2d32db099325e41f01b1e9ced4ddb6fffd2a013141b8d57e35377c5b94fb6d83ac47cd1a90071c3976ff7d344b4adc" },
                { "ja", "20b3dc5213920880bf0023bcee1bc4f89a306da387b1427cb1c15eada615a0f2cf2c985de219fb59ee981236d877179f576cc5419d7ba82ccbd5ee65a598a8e5" },
                { "ka", "3acfbcd054323bc7517ff0f3b284b922d1b256a0f559c778e1013ff07fdfe928fe5a651e156346b4fb4f1efbe1987c80e32731f3b25bb241816c7215b60381ab" },
                { "kab", "322878a75e98511f35d56fd32adfa28e1423d29eb97bc5d7555e4abcb16d8b56f358f5821f2d1b6f4c6617edd36d80105fb9dc72da6e9c0df79b3e9b2a392ea1" },
                { "kk", "79a4b577d756e2215c5ea435c55ca777b18de93605b5635018c68656f054bc2466aa0dc4aee8ffb2afc7beadcf33a2fb03c51840fb4affc6149450744be92a40" },
                { "ko", "a8c0bdc67403966c72f78d4a44955074238f7ad3f39ec8885d6cc1f31af82983443ca7f7c8cd02fb154bb465e96f34b3963050d8470c20c7f1d53c2f4db4448d" },
                { "lt", "56854e6ad179bdecf242ecd6aed0edb3b98e78ac708008288b88ed3cbeb23509cd66df454d35115b2c79cac0d3bbd1431c87bc890888edf0a180dd4e124edf21" },
                { "lv", "79daaf15d9137d13bfbccf281d25a15372d5de6b5b4fac52f4e768ff134b9e8de5e5e640dac36a4575f2dbc6058055056819c531c66943cc90717f73072df5fe" },
                { "ms", "90813da5216eb4a201fcf34396a4114f28924d3a3b838798f4549cbc06ccb30f522106c6d5bdd05621b5e6cfabb0dbf0522d663e5544d399a070188bdbd7f660" },
                { "nb-NO", "ce767f69265ea6b6f4075fba2d22bbb222363b882eda55853761c297b0da669216030b39061663c780d888f8eba82d59ab5d7a6b102fe22e26d309e93c658396" },
                { "nl", "ac1ab2d5272cdbb9707e742fc8b6052195d322d16fb746e57b0eac5be7f0b3daee44063da4eee34c369f248288e6c44d69386e113ce0cc253614fa449aae26fc" },
                { "nn-NO", "bd9273e3969929bb14c7269a4c548491d3ce83b07c0cade7ee910d70f0c262fb2a3a135ec8a61833e4c87592be85eee32b5f1d752e6eb7373fb2bf929aac8d58" },
                { "pa-IN", "21926978016bb047de5b81c647cb3e443b28604d9dcde851a44dc3b75ac5781d9fdaeb8e7b5b44b14c2b0d4bf7b4cb9301c59475632bcf214a943aba46d3f6d3" },
                { "pl", "fe1492a3d6162a3e4ac2d745e04e62dffae1fe702583be3a516a281bc070e360bd2594212a0e549e25da9ffaf0af03a8ba5e39e7c6d6ad0d7dd15798908de5b0" },
                { "pt-BR", "0522db1f307da6ededcde919ede41e7dd0608a2ec892f622ef5ec63347d6c509984b7b49238d3870f6fcd5acb034339d3f25aa5dc3b52238978ca9ab8d46caed" },
                { "pt-PT", "2e6d8176c3e5f199a44b396bb57ca50119fd3e19acc76a61564f8237620db1ab34969e951e1b1f2f7317a9c5eb654104e94a35dbe4eb3a5ab1dc9f9e1c1d148b" },
                { "rm", "4fff804774e1b1469dd8769a1694d5aa01e1bd676ed2d1b5f772e7c3e24d4cda605275a37a79570a623a2e6f66b06afc950a83e96ae9381b2bdab7e644242d21" },
                { "ro", "77a489d7dcd08183b3751cb6f42864b695f57082f5956c741047733b45be33f8a495a5da022340b41994bc311b46c2f0cfbcbf8040eed4dc101a53004ca5b2e3" },
                { "ru", "2db576bfce12e12706a10f8a665ba351ab040a074909e52cbfec5f3ff8a388c1ec7a9d605be7d451ec230ad1cee156950f8331f8926faddd9e3471a075e7781c" },
                { "sk", "4e7eca4a46a0afd93282d2fb7abae2734725f0b89c08f54bfdb6ba80d1360fd2c7fb0ce6733cd1c8209ac3a2b2b89a5810713620f2579a7f81f4b34c536ddfc5" },
                { "sl", "a5d6960dad18410b823863863d87bf1d2b038a5a7565637e1e2727f1f68fea6eac07315627e196c929c14634cdc21890373301f0d53acfb0e9450e81012e6247" },
                { "sq", "5539c808194ccaa769986827dd000982fcbcb910e49e7720f033eb092c81af736b3934ebc88fc0b2e577007db585c26b8ed3a73a0915f4d7cdab31db9180e0da" },
                { "sr", "4a4cfc059f3d165647be015bc185cb6e28c5e13cde0225e98dca41be003587e850a4500de74e75312ac3efe90686cb7f7e29fde14828cae0286d1e6a69951d44" },
                { "sv-SE", "d0ec0faec5613b93252f816ba8993e9bebb263ddeea1c1e7f1491fbc90f40ba7cb45a4b79889f06ff020c8eeed3cdb1a57a5e3b0144cfb7e594aa82516cc0917" },
                { "th", "7bf0ace7542f8573666c23c8b0bfb19462408196af6f7f2477da7cdcfccbe9bdefe365cc67d61331cc3fb91152b6f4fef0cc4623553618aedd3a9100609839ad" },
                { "tr", "51c5194525266e0bb2c29f182b8433386d63ff65260fc108dbe04c5e96e8e2d7cb1cdc23343a018e3c24d159521164fb285f05663b6f7ff29f47f9479e4e80b0" },
                { "uk", "0a6147a5137ce04718931aa8b7136677e605e055128181bbb22090dbe772873387e2d71ca3c78e61706d8007b69b83493d3501de10d8f6a2285e0e373b197709" },
                { "uz", "399f4afd711e4b1e388bf1ba842b38f7669d0091894e20b6cfe7b79e37bf4c36436490fec502da3806868e4aea26dbf7f6186d9fda97912ab9cde6a33e98c16b" },
                { "vi", "bf0271c603f5e3aa454f598886988d37e219570392ddd8586a990f3d947b83cbd9eb042fcaa568f9bce3a5dd1c7f6d988b6a49447aa95528458b1717aa12ce28" },
                { "zh-CN", "76c4d7e1221133903eec0f7bf788fcb46985ff5d7c16f4a55f80816b93ec022260e8fbfd117bda66b050b977785f2d54bb3434729cbda52ce20b00c92c67dd90" },
                { "zh-TW", "57e01cec6e1cc7c36a8397ecaf33ff4ac70d8d3b0cc3f8416335d32090d55b76703bff01a1a6d4dfc8ef69c8fffbdbe9253923edb44f7051cc98826545cbf33a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.10.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "287be560c6de2cf7e03344874d76d60bf12a9611e6d1cb4f2bb4d71da23b7996494dbafd23e7dc61568058d2f282fb9467867e21ff5af574aa9506712564ee1f" },
                { "ar", "9671fcdf426b583133a3cda3b31fbffee40054fa21200b78fd282b1b9081d666203bea02cc44281e3c54aac486c182cd9aa5210eacb5b4a09c0bb7cefb5df831" },
                { "ast", "054e49cec8c935dc41734b6df4b37d2192e74286c2d67a166005734c168f98f5a016c2f6988b1b9e7d75bd1bc3994fb9fed5e249a2149176eabb0c9c6ffe0cfa" },
                { "be", "631227679a7e5b09365a8830ad968c72444adf5ce46708a30abea5bdcc3b99e419fb0bf52f325871fbd1163917bfcdbd50e5e66154732627ea69003b16178f21" },
                { "bg", "445827f8ccb97a81e6f7ef9bd19d445131b28fa39f1bc37c285bf1ef2ca9125a17ac5d46fb40a14967f8de51c26dd46a7cd8072fd4150ba3359ed779436b6b49" },
                { "br", "eaa84b3877718e0c776da54bb851b1e27ab564ef7c4a1fa4d8814a417543e103bc77140eaa1edb281b6adb7a3f49861b40bb5877bc8d4442fba82354af1d7de0" },
                { "ca", "e1ab3f165580d7657fdf2ef8bf805943d4c30f8776c79df06409079a3a31161648341f0491790f038d5b38a5586258dfb19f7b8ae0e70fd8b9a9a802595bd5da" },
                { "cak", "967b2d541c0c4928d63da37aa7309cf362d9e183109acac002069ae466d14a8e201d39760d67acb7a8ea03bba530167d09d5e7da893859fa6ba1adf1cbceb9d6" },
                { "cs", "fa099c1629613cf8e90da273332bbdc499bf2f500f16805e0bd7bc53f269a1d5938ea359cc57ae7fb15a04ad8322068fa73e58032e5fa3c5df6d76b279cfe3d4" },
                { "cy", "06c56e0be1cb0da43c7ccd3dfc820f913b7e3ab1103d79351b420f4d02370f9e79a98956e33638ce49ffee376d8b5e5a19c109faf88a6b70b27f2213ce8ae936" },
                { "da", "cd932538e8662e98bcf7b5713b3181b831cf7e687f68cd1fa6f89a5301bd87432ee4dfeb0f9c7fb7c17f648d3b1793d0b442e399a0a03524d14174e60e39738d" },
                { "de", "a8d79fe50e118e570ad4d742039e1eeb106a6d0821ccfa0c7c2b8750365050a82816bacd232a87c80aae3362df9effa4b8432e218bcd81b155d363fa34d93b9b" },
                { "dsb", "85ec5c32e8d97fc8c1f31af00b10596cb5c3d2b8291a36f3d65f74073ae9bd5596c450bbe6e056024a76152ab2e519af2db3785b7ab6a3066cf845b8a6da1d13" },
                { "el", "4709dd3ad66c201ea4d3173a5246016fa2e64122332a7e48761eafb5434a32032770394bbb881055ae21d3d69581c245c8b6869d2e5efe3143ec1471a30dbaef" },
                { "en-CA", "0123b9fccbe58f0451f2f5903d5555d049ffaabb4c19391f22092e3244bc2aad059bfc2dea7385be17abca56ee09f53b20f35078c692e741d589798511678a46" },
                { "en-GB", "3778dfdcc69e4b846be00660325a696ef6a4f49644dc5b60d939238fd1c637e8751db4c6b0eed6a836137ef208a9f810697918eab56b3a4c01d12c6d37221635" },
                { "en-US", "9a476ab6deff3e078925420f2393f0868b87ca7b4da0054b5e2cfa9d367d2e5da9b80b5a1059e4dc1dfd6cc6d5bd299cb3a3f5cfb901d84ab34b48c88deb21af" },
                { "es-AR", "475486c976bc189aaccab8f2bf412af39f900bd02d37e29a4dc7550a83971f2f472d9ecf477d19a5c1f600547c6b82c8e9aa823bb5f3c44b16b03e9a1a7437ce" },
                { "es-ES", "aa337bf100773b28f5a9afc681ff368922bfa58f2b23337bd0382b2de4726344ab03322235d176c9314f6cc976561227b11f2cdf824571f707306655e044390b" },
                { "es-MX", "c486e579cfb2f2c5c0a6f8e2da51bf5f6848e4f91ad538332ae6d4fe04d9bb2f954f6ac4ae671f17cafa7effcc7c9244c35ac24253db13273f826954b3013ded" },
                { "et", "26ff310131cf0fd0b9b5cd7e2484701033db6f9cf0016e9a41cc873fbe84837d9e844a517223fd12651e3c2442a0952274182484e5e462c1b22cd892d3dd85fc" },
                { "eu", "e8852c5550e1a37ad73139bfb905fcefd0033fff31bfe548f4b8c8a38f9913d2a9197c2860e0dfdb43f11bb3681a4acb9629b6ea3c33318d641e33e587961b0e" },
                { "fi", "681fd366878d2388073b9d80dcaf44f0bf363804331ad28d16fa52c1cac8c06bfde350c653a5e2bef7cbfb4b0e5d487e1921b4d1830d59d0d171b496e1ceb392" },
                { "fr", "467f88917c86e584a77072adbbee596682ccac34cd9da84ef4fce5d6e3dc1ca58fbfd50af49921ec2ad3f8056484fbd3ce406d88222d3b03ab75afbcb5885267" },
                { "fy-NL", "4cdf7c006dd3b53b6df5b819f21001090e4f3d63350465caa9219cc6233e98f86aee0441afe5b2cc9d032f86d37bb6d58344523b2562f0832f2f92567a985175" },
                { "ga-IE", "4cdd34a881deb440aeedc817fd744d63760b681f8d27731faeabd2185643c779cfcc7959c710b217d5e595779553e47bd35ab6ee844b3b79bf5456f82fed62dc" },
                { "gd", "f8f744ce1fcd8f0b1b66c7869965263d2540e5cf2cdc376facfe6b1cc7b0b70ad8dea2398c80fd79e50e0ca2ba1112d952b3a866727ba57b2ddf5c4e7c83a615" },
                { "gl", "09939cf90b299316d596fb39ce9828cb4c3e90a9e22c39f1082ea2993598a98f852bf71f4d34c9e3e9b3faf146b5fd2f1f2d5f21eb38d1425b1ed585e74690e4" },
                { "he", "b51d9bd817be1881b156ee07bf7633d39ee3806252ab24faebc753bfb4945ebf86d6b11edaecba2f4c38eee4d2d78e165a90d9e1c4f9f6aeb69ff11b7717d956" },
                { "hr", "50ed78e5d01a5818ec5afc4a538c637cc310c7ad6cdfa9b4d65dd15bd90deb41d7c2e8323ecc9daf7d124cdede486e8965b3edc5ce4f70d64f0d65df9feec6ad" },
                { "hsb", "24cea252a5d6f4860a5c45f26ebe7c0521e395f867acc3287b902001bee3a162777d95c83586d81a763ceb21e78f71d85b18102bc4f17cb23a43f376501da33e" },
                { "hu", "6b0487350ee19215e5d710b472ff03882135cb8c5558a5fd69a4089de939eaf970dcdc7b741b6db31034ba4b18020547e9edb7d12756300bb75d5a08bcfad1e5" },
                { "hy-AM", "635818086da58e2f1fd75a5c1df90d82e562dca167a301f2b26ae39690fbc8686938c0ef20ee41975806667582edb7ea53841c6ec0ba09a1cafb8edb66df9188" },
                { "id", "20a8e9c964cc5bbacafdf672b90f0ec03cae7498436e100a5fd2cf9090bab2f905034b33eff7ffd24a3fbc26dadadf4c5c71c856f54ffb10f0907b37f7da8774" },
                { "is", "6c18583671ae374d7c6e3fce6f88b545c22ebe636b0c9371609d6d108779abcf17cfc3bd94c729d15c729e708986c4ead88e91264d6db1eab11550825a02a8d8" },
                { "it", "ae64e0f9e37c899b1061bcb9bd502837bc79e5f12dd0b3fc5e8c8a3535f803552ce99ecad64c6f5de30711baf482df1c7c4c48eaad2ad0a48ef624e32d0712a5" },
                { "ja", "4fcdc6d0401c86b666643ef9e2b8a14d023874842c43c01dbba1945bf9e2ff9481ca27b1ecc9612e325f8087a04ddd4a7cc87d7fd291a221702b8ba2c95be65e" },
                { "ka", "1d51d5fc724b2a858e6ebcf6a1b3b8a8459eb71c13c7de27f83dad9b1bfcec0c93bb7908a895143bf1f2705967a7f94a6485c359a1acb7ca00511716ecab1228" },
                { "kab", "965e4750fef1beba80665e1d018f0620cbc3700af4ceeb2d0d7ab852dbde4eef7c7bacd978c8e308beee245fcc2782de90088e07dcaf89056e6ca15d353f18ae" },
                { "kk", "0412da432587c9251ce4f21a8fd6e5161d0625f9923ba53101edc713e9da5a3ea4df27427bc4db136c284a03799236acec60b6d7247a479b6a70dc45a106cc5e" },
                { "ko", "97e48050417c2b2f70bf4098242ff889de2a059e943177b7c8e028e956521f1f5433d3744214041c9869966e83ab8a0b5d6d6e8a7b608467be54f275ae22b980" },
                { "lt", "7193ffe9f0e6c3b9eeea19f0a932eca809ad6e7e955b6475b99e2e8768b7bb8b3cebaa23d57976f2e1afe36d22c341769b5c6769f5ed3444fc12909841226cb0" },
                { "lv", "ed1e453d7543b10c2f7dc92451bfe2d5a7f2b2fea483fd1c961c0932638ec4f3168f8425feb0620118960661ec0026f1e2cb617bb91851cb9ec2a6e7914572a0" },
                { "ms", "bbf7349c376d459b970e6c2a461649ef2c411b63644774237d02a9548d5ed588991ba1430e3dd1e03ce05452af0bde4c3034db01f706005a0969de44cc84de4e" },
                { "nb-NO", "4f3798655acaa359d7163877e4370cf5b2f7359e333166418c1b22e60579913f62019a1b56ad5c562de4096b1f16b5bcb36507a03fad85b29397c7f47852133f" },
                { "nl", "7d04100e9e8d707c394cb7d4eb23665c7ab34c9eaad1b08e386b9db3da72d09c3ec524d925da08b777da51df012386808eaa1c1f76334a0f9c94f95671db0211" },
                { "nn-NO", "68ba27c932f189d69ff2499e735d3493fa9c6988c819f045104834454687d6fe258ef4ab982b3199847dc4cc7c5cb84947f45e6e07c8702b6ff22b6a75d6d292" },
                { "pa-IN", "c2270ef9dc2d64b8626a721e7809f0bddd723f6ff40c2b06cbe2c21c376dceb52749c9b0a935fc3b2c90d5777cdf0047ba79f8021b3467ce5009da527058f29f" },
                { "pl", "2cc600e3d62b66bf4564884ac6a6dd430e3ac92fb331fa624818589afd8aa5b8e2770d37c417665f5fe2786bc1d53e1f2cabd4a066daf6918ac76313c844a817" },
                { "pt-BR", "e7b3880f4bd4b08a41cb93fa32f03e025dd51420ca427e9387654b613e3d38a323d0c1f5cc433eeadcd871980e96e0fd2e57893a79e79d31e9ef2ca3bdb27a8f" },
                { "pt-PT", "f5064a6948d706772548497a1d4816bebba7dfee9cf59149a70334b0bbc9ffc61fdc30acffd5be2e9e5cacb120f708e855e0f4456c7a46a6e1cc86ee698d5b87" },
                { "rm", "aaafa225668b7bd90efd87b33249546d75d363f169f796731a2914ef1f64f99453eb16bd36462f83e1735c445017839f112d4682479ae01960ab6b92a2484885" },
                { "ro", "737543828aad24e4717e2bdc1612ca7c33921378d6331ad3a8b5fa6104e650b20c7ded4d0c4b78025d72f0b409e8cdbf0d98725caf9b4fa9c67071743488ecfb" },
                { "ru", "126ac1004c71c4926d5a7fa028ebb07bf571d427cd49c82fd27f65f7c785d8c5d813c9cccb21710538c845e62dbe1851cadea45dda5e059c556fe89ad4c28211" },
                { "sk", "b5eb03ce854b23033647b38389daa33c4ab1f23b730cf1273e4eb7e948e69dcb1249d55f70b840244a512ecc800d949eb9beaa49cdb0a88bf97cb973edceddad" },
                { "sl", "95f202147e434e483d15457db71d40375250ddb4717bb6df08b5878c456e9678cab4759b387c1c9f30c2202201fa4c0166bbd83310c6f7e4665c79b8bb85c7c8" },
                { "sq", "747cda20326d36c74e7e250e6aa27c54d26d2510cec77eecfef5f956b8cb5e6ff16a4762b01aa515319d630db0933d04db25706ade6260eb16ebcfc585dedb3e" },
                { "sr", "4ee7b301acec0851ef0b773191d8e0062b904b6ebcd4eff744b3b620deb56a54d72d522c41afef51b4e410157c66b06fecefb8be6496a632cd843c2cb4949140" },
                { "sv-SE", "ba6676ac3ab7212618886c067c6058ba0d3a19867e28939134ee698b4d1ff655b1366e3b1f87e410d289891cad11c3519e417293984d93df24e63f4b9cdbe10b" },
                { "th", "d3affeff739012bf9a179e01ed755ead26f8e237037657a7a9d1daa223081628b3ee01c9764d76ded2d8d8c23411ef64bc33c0152f835742de530d0cd2d1cf8a" },
                { "tr", "36b3c4ca514281425d9c7c9af00d8f71b7928b6f8cf1d7601b34066f5701ce5cb6a3ed9eccff08ef26a762622982b5f5bd17f0eb4b26ea16b9d6f1e9a9461d41" },
                { "uk", "173429fd18f2552e926360ccacac10523a0ce1d7a64e84855e466b71c28921fa92b28096a3244d1af3f524bfd823da7ea54fd34930ac582a53be44e88632e785" },
                { "uz", "9cc89ca04b9a5d5373ea91b6c91093e1136ed42fe51e44b0bd6343eb0b8943a234d969345058b1ec8b26dddfc6d0680cd1f86044264a2027b318a6792a7d7ff9" },
                { "vi", "61343e24ae72d3f6e147d56c54a3ddb77d8c198def0e387e639de005e4b829c545a66d8f7aac6d86791ab43f62d875803573483dbe400926ce08e935cf109ed0" },
                { "zh-CN", "a1f157f3ea3b1ab82d46393c2e2750199cbb0820f50bd0248b16934a47fbe3bf69d5d1ac2c46b0709f9fc57a67c0155ebc07909bd41be39a7032ace846eeb6c8" },
                { "zh-TW", "b4fc6463bc41be04d404a11dbe634f641f94729d12e8846db27666187c3b4cce615be0f542e19036568c9b73147fcc37c23f209cbfba922cafc73e30080f9d52" }
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
