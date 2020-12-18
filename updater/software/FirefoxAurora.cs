/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
using System.Net;
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
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "85.0b3";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
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
            // https://ftp.mozilla.org/pub/devedition/releases/85.0b3/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "f9e6af9c36353b2f0d9d86ccf1980abb837ca628ac8fac967afb4046f813bfe3e4a4edea8a772dd8e2c80040472bd80f32ef0021736f28b74a21ca5fdd034205" },
                { "af", "f92b4dcc0ed03783bbd983c76ad54283622253a7135598cc475961b0b50502a53335d146097f72c555fb3dbd3568349bcddd3087179137791529a54d74bf7f8a" },
                { "an", "84137c9cb90cb4303dacf66936468aee622866445fed6add051efd1429963e7e7ea7ea645082a2dc9c462e648b82c6317b69b1bcecf18f169b52cd06b4e8f62b" },
                { "ar", "e38086bfcdcddaa9796c0441cdf2b585819012707d949cd56eff8e85684387c4bd4e18637d3d51496b1b00e66c5480268380a24b603d22cdf7d2d3c443770121" },
                { "ast", "d39d5bf8506c6c14229510281c4f3c91421c882424ebe299acd3dd0adc3ce9f7e766ecba9b1b2d7784dd6b5ff6872fba0a474f21f7c563b7b0f0f3f00e4f01f0" },
                { "az", "71c75747bacc1931f8bf9d4b786ea4f8c2f22d0c19b213ffcafd1722b401a1e3cf4be3f8b8e60ecf28ae17deb51533eef32ae225b45eb37da89ca60650e07e13" },
                { "be", "aeb8a96375e35395c55240e642177f71fbef0c642225467815333c5b67014a6483a3dfe656345bf1f5db6091c42cbb1816c0bab24e99ec7319797566ec56e69d" },
                { "bg", "81c055686c12e3e2ea5f71e1c60954f7df3438a7adb95e3d0aab8b93de98d939b8603c9691fc2ac6e8890a3b3c2be470510abcff70644016682b030071ab3d60" },
                { "bn", "9592771e7c72ff4ab90ab5f2045383980aafb14fc93e318dfe8d9cfd7cb2f1d01b2d6ab260af773ef23d257b0de0c0dfa6cc151e1c31dd0df8604c6f30e75baa" },
                { "br", "124e8494c859cde06d00dda72c6c11d12fd470c2a6fdbd876b0912bad11eebac2fc8329206e5256aa84fd9aef7f0a43d951f880a810a00a502a7879f799c0933" },
                { "bs", "3737db640d93091c8bde3cd0893649a62f92c0c5154fbc7ea6b22d3a1d6a505c280cbe26a457e54a3d12add9968f4cb865da96213eb9881622b6e1141d1ff0a2" },
                { "ca", "65da744faffc4a961d0ae7d242bacc64e2525fcd7996922821b5c19163699bd8f6bd27de8364c0633eaa409772e0cd5fba4b85aeece2a40774e60512a77eccc8" },
                { "cak", "1dc1ff6c7dce6d5d3ea1d03e966fb24b8af6a0c3b826b3b405bd4869c37b2c3e65941efdf95f99f9c9ac4f26d3c9b191b1d9f0014372a12d79a590f019606489" },
                { "cs", "e656eb203a59ea19487cc342f44d00a46b717713d23ec29847189b9a7b7f4053415749c1b00d4714cdb4157993379e6a2deebd0040d6683dede2b10eb1e0306a" },
                { "cy", "f0c7cf09e4b362fe303f2141f79e43dda5624f2309c61379abb2393153755bdd02fd3f48467da9373d66c3adc22d3e2e2a542da82b3c0b52984aa9377ddbadf3" },
                { "da", "8fdee2909f68f1217707a04ada46d3e91d5936fa6217cb62fcd1a57a87040899ac19b18d79ff8baa3374d4ab418d3d466b4a989ac790f548d7800afcd948b8e9" },
                { "de", "4802999671774941df373ee21f451c96f90062438c32aa32f78af737266bc7b4817368f9a099fea50dc2fc65a6f9fb9bde232054f6059c09a7c450369d418bf9" },
                { "dsb", "c53d01badeb5b21a4b9e0c6d81d0000d3161dc5baaf6474e37a6d090eafb4a1d9744917918849e625aa01655d6f4cbe76855cc51362b904f6725e88a3cd90def" },
                { "el", "19091312fff2a64dd559db8e69bebbeeb90ebbe33bd792c6c7ca173dbe9e3c0201ed7f358977b9cc1bda5d352f66bbacc603204cae87c505a170a1eea6431275" },
                { "en-CA", "f829a8596256562ce542fcbeb949ea0b4be08b9aa354afdb0cf68bd1654b37670dee8574ed77efbe80875e122ece4a96190cfdfd458823a153d9f61e2e198494" },
                { "en-GB", "c8a5f32adb02976c1c2044c825945968cc8f832a8b9816be81bfc9fa4f7f206da3ebb92aa08f81709b7ff74058c95f96d47a08ef5fd75994a30a9411ee641603" },
                { "en-US", "9875de9b075f0d78af7c1339e7dfd22400c05f29aed5af05bb7ea8210883d7f14a1c18c776661f2203557e5164837d5bff1cb4266147b3f33fe68c4ff8b1f2a8" },
                { "eo", "3e78bb3aeaa2b30583e30b2d3549e164c5925a9dc51fdcf9e241119d5d077c1e40366549f93ff7e31a930f0c6e59caa483ce21e219a96e44477c97086d565c3f" },
                { "es-AR", "2105796984266d16d647ad3f9e8a6d9b8d12bffd75cc9a611bf8f874d5be9be7650201af24b06edbc6feabea4a7f2272695ee8b170417cf7af740aef6a972e1a" },
                { "es-CL", "104a5cf089c98f9def5137d7a0e227f4cad6ef7cfb49f7cc649575caca406b32329ae8ca2ac31eff6348fe0fa4c7e6fcee16269c11bc575fd8c4da7232bea6ad" },
                { "es-ES", "803090d4aff85506872b48ade927bdcc03ef8972851dfee0fdf1fdfbd83316099cd37533cfb90d7e6e25d9dba669d7830581acce5d86fcd6d8c18257010d979f" },
                { "es-MX", "f4abed78bc847ba23de3412ebb1a49ec3517fd7e1b3620612e56372cd7d51ffbc77a88c4956fa21c0c4b3a59d180bdc9a954c67a6d0aee2727df4be57291f8ff" },
                { "et", "73c682196bffffe9f8162368b2e3c2bcc309d36ea6a6fcae877e5542c4d79b02e5b0b3dc42d925defcccc21479a920b56cafeca5fbb30f20d77974ff361ed975" },
                { "eu", "db23d24ac0de4805bae130f5a8e972ae03dd8b32ec24168aac454f540ef9dfa3519b330dc7615f366239aecfd6e038c51bd12adb6ebc19f53964355e0af9f9ae" },
                { "fa", "515428d7d6a5a1288403432165719779dfc36020a3721c7bfdd81c6b03a2d4cba4b0bf4c639e8cc8854f1e037e6a60e770e913ce95797471d0a48be600fbe1e3" },
                { "ff", "d23e2a9272751756dba8b2d1fed7a1a0ccffdd158f4aff4da64ccd317d97a9a0dfded14ccec53ee88d0b5eac68ba732171a857f5fe73cb1b1d0b42a9f023f4f8" },
                { "fi", "5f4c9a8457ece4fe9710139949d4531aa834db45b4dea158acd183e0663af269a2145746a78d6df0a3773186f545a82fd0892b1d944b5f804e4310738ed28fcb" },
                { "fr", "a632ed3ccbe976ae51fd012b657d88c5eb0b740bb2b85e6d56fbed75b3e14d7a69436a5922211d4bca2ff9fa68a79db042280633c883556695eec310b3e7896b" },
                { "fy-NL", "f98d1ef7549bc2c9f8817485c65c93593823aa4e9a6cb8abf7b1881dccc51546db46fbc4c44573d108a3cc2395b8a4ad8c0157008d175034b0ef8d58f817188c" },
                { "ga-IE", "f4d01b77df6fc324681d69d343ff8fa3b10f3ff6e7a5f52cbdac0d2e8c19447ea4d4c6e2026370244c04c0229f694e51150d9ee6b9ea1cf289a423289ee8d69a" },
                { "gd", "e3c58b4455e9a6f61bf588dae9b42b6bee74f47500967b368a187bd4d9327d2ddb1c433aaeb2bed55a8f538a707b7c76d4c01eb0001801fcb76507f0a64e6fbb" },
                { "gl", "4667a4d52aec49c7c7e34bc3ae2fa59c02d23929d32e5aa3c54c94274dac04bbc3a0b3b75712830c6d2af021a372d3d5e26a952db0f6e97c5112131c072668a6" },
                { "gn", "768c14091bc1d5a17669c9b027f12b5576330370eda9de35fb9a0c23bee76a771f3d721a0fddc4ec7f2735bb769b8925aa088c431bd0f5e8000f428962f31474" },
                { "gu-IN", "4aad491be81de46ec5cd37f09511ea4aaa888cc281089e04eaed2b18f0e00ae7177c173fd33e7db089d438cb115df72dfb0a204470e4b960a92d627b002b0be4" },
                { "he", "c0c63d13cb8ea07bcdce601e38d4e36340e20304d628f19e2ccacb355de6d4040a4ad743f9483a35fd9b34706647d6fa20d79a434ae26f6708886bbae5f1178c" },
                { "hi-IN", "5f2b56604de42b8b6377192408e2f42a98be4d19efbf5dcf80329c1e46da152404caf33fa8c6bf307bf852f28c61fb534e4df0501b7494f7a2f68a6497b41ada" },
                { "hr", "2c71a3b2d3cb32fec21f36ebdd7d95cf77546d22e3d479b7296b09f3b0818e5548d083bff313d94196652b9fccdf039e8a680d5f6cada3057f8a020b25684067" },
                { "hsb", "014d9a9263e4dfa064c20c5c56144cf5aceb81a6d575ec9d97e0bedd213f0759da2fb26c935be37c912b7ad264c1a38e553d0aac9833b4ed3b1bd3a27aa00eb6" },
                { "hu", "e7fe3af1805161b57ead90473afd33a3d143bdb5debee10fe394cf69d914479f190ba8e3787ed74ca7220b8f55fde5965a7402deb29c3d205e5cd86b24ad55ab" },
                { "hy-AM", "17651bbd0e5998e050264b194055a59ef51659e8e21a784e5318093fb7de7d7f3641c7775250374625351cd28f6ee45e8accb3126b6b0014901685ed05c35c58" },
                { "ia", "992fbe39c2a4db69a9dff6ad227692e6aff3a7cd8a109aea3c6d46a6ecf6f21c94de879e101f964b18c231b0dbf8a55b63e01d1e5c38f0a39666eebf92aaa11d" },
                { "id", "fb4f0be877059507d8f6f98ed008a3f9b00da8f0567cd0b6e935e264d44b32648f207f68ec5616a7155631b969df8b353eaf92dfe646e7dd4ea8ac713783a8cb" },
                { "is", "f9b7a0404658d73aaa06508908e1ea6a8ef9aff89dd423817c203a69e40d7c743fcefa1031f2536e26c5dacff82da0cfbb4e28a980f1e2b6673575008834b1c2" },
                { "it", "83813d8b525a966d8ccbdd067092d13fe18ec1c1bbedab3aefe5178c07916b04cd0cbb3a30988054bf86c2017a7f6db99c23f12753deadf3dba921d12c1fa0e9" },
                { "ja", "9660056aeda986d45842207269adac12ab760c47676442e859ab204c8a12e3fc4f445118c6774f599dce1b2af4c01e1d89af782998b8d90cf20adfeb0b7dd4c1" },
                { "ka", "c9e936a41746d41394c4e3f0173f318e3632a6e37136d6128292a2c3d428aa7f2f4055ad92bd5e81c19259eb0d7c75941d0a4cd386ab427d8ea53bf17b3532ed" },
                { "kab", "362d5111808ba60f4fb8dcbaee1e287248bba6b7bf5e6f431c774abba17d1cfcd0bf582a0cb4ede5607177ca2421e5772ee6c3c52930ce725fe1bc8bef99180a" },
                { "kk", "acc9b7ea5a125779738ca3a292bab92f81f412feb48d64564b9e615bd61f30126ee76d2f24dac33be6396d87da62745e6afca89c4041f401d5101e16f3fdda9d" },
                { "km", "79d158d089a1549090514fe2291fe0135fd679bba30f24ca1edfd5925cdccb6004fa94c50226ec8b6233c2d044ac2cd32395c3e09e78f5b020dd8ffc2c51f6db" },
                { "kn", "221ae4b8f7ab12903c82f470442a232eacd3b8113275cb4be3b12d8718cac90cd67d749b3f3c5db14deedd7576db4f8775d4889dcf937b2c0be6c926961825e0" },
                { "ko", "001cdbe327f8553e014f30c1b57a4987dac92338fe6de20d718196930a9c1f9aacb37ed4df74c8dfafc86cb7fd7440e25d6c85e7f82cb57754334506f5db6711" },
                { "lij", "e8cc0f3880f46f658abb427bd363799e8379104ba1509cfc3b00f921cc3440d52b32d301158c8c2f7ee96588a5477e0a9c4dd1eb22201da875f4c7b84e494b75" },
                { "lt", "6fa85c295d0c2564aae6bf2ba113222a84efe2a097ec5ced7a9f870aee41f66742a8725367ae3bc7510db52b56d66936f42d4e5e16603fb739d6658b82c19c3e" },
                { "lv", "b05caa4d77489403d0e2b880e9811b9141e50e194e52dbf04a5f49d0edaa5cd5d4837e76dfd166d3685d84b515251a9dcc55b2b95f314feed871ff7b53fe6edc" },
                { "mk", "4956e3ff85f698e61c4b8438de182e8c9961f840a74a173a17110ce74e6a3dc3f2b220bd91b7a7aaa714f59c09cac91ca3f1e021c2705b48c20dcfb1a1789307" },
                { "mr", "255bd22fdf7c47d416b2b21cb8ad247fdb0dbaf3caaa6ad8f5ae585bb435bd4f6d406f2e103dda63d99505825bdd36f30fca28c4d86b3f8a5f65005c63686901" },
                { "ms", "cab25b92a52679b67ba815516d2e617152e2dace213eb3a1c543b32c0075dd0faa6011430da420290f47d31df423356e1776e8b05c1f9edfa00acdb7fd33c066" },
                { "my", "caa46e596d9b27f581299b111aeeb0f632b911608c5e6fef37794a3a6a3a1224cc094b4bb73c70fda7733f9576ebaf34e2070860d2dc1c491336bf767b1439e4" },
                { "nb-NO", "2e21ebe89271415dc4e8b89cdd947a9ef4d571fcb867ba820ef271dcc3b31cb763f762a30fad8287374be42f5a606327459c6a0dab047abeff1d381b03fe8e31" },
                { "ne-NP", "facba9c08fa8484eefda8854074b2f499da89efe424f864a984ce9782d4273ef720edadb64bbc93760315d35ca1e4b1136e2eb434fa69d884032051910ecfed6" },
                { "nl", "9a8dfede16d1f10d134eabcbbf3d3ebbfa90f6c9be04ebf2ea328cdd52e14f8a4b58e1ee592387a9aa89e4ad01b325d61ea167735319e5b95b60c75ba4f7f994" },
                { "nn-NO", "3ad87bac5bd900e8d997e282a29c60f7494775cd28c0bf40273b37a03b94aee08e282355b33adc10484c6cee75354a803c9ff2177d473eec7680737525561c7f" },
                { "oc", "081f8db720d2c47e04a67e507d02d1af5e04cc0d8fa4d041fdebee31c450950843a58b5caf80c35ac9a8ca18babcbe0f3581b00fbb2e15502840e95b840ec23d" },
                { "pa-IN", "23f10fedceb6e927af2ce52f8318b7fc511ce4660c29afb59767f1a8246705158a91a9b778a9fd26e99984bc953372d26ababfa3ac5a13010e8ab5fc170c6e32" },
                { "pl", "5f835ef1849cdeaeb3cc02b0333450f1ba26ae67cca0f87e1b512b440a8e1edf808053bb41ea22ccda2c5dd804f7bb75c85d01a5c68acfa497ea9e86475ac6cc" },
                { "pt-BR", "d9b5a207686371a05e896cfcbc92813c9fa91b57866c372f3edb37940620fc60489bdab80eca81ba0a77b157da1c5ac447a779394ed3337ce334b7292e28ecce" },
                { "pt-PT", "66d35d86d898dadb596a22dbea6eff4d08b09900bdb08e01cef65cd102f6cc86d2a7c3e74da330332ef7ddf50472f2a55d647f9b68f23c22f61b798ae57df526" },
                { "rm", "c1024965d5c7144ba964adb6f6dd4d30dcbc6034236767bd14eb4b9922cd41a7294ba0efa611ce155a92e366217bd2dbc68ee5d4ff84e024894a23e9b8db8d9a" },
                { "ro", "2545ad809c0b31470ef54d1da5e44bf1551ea631e172bbec85fca72ce046654aac169c04ad80cc9676bd2e7ec5f8b510a96e718b899b72193cee1cfdb48b75be" },
                { "ru", "15a44e22c838393b9aed7e7a122c91dc221ae24311d6ec152695fca51393886cc4d4bb884430ad2705f311bdc5b37e0a4ed938952294605294a83b596f007a4c" },
                { "si", "364b0f30561f53cb219b80fc854a27969be992bfd2cb57fadf7a3d247e5ce2a1f0bfb8515859c8c1d70f774ec9f2e92d23a44e5e8a819f9d5724998405947b86" },
                { "sk", "71105f1ced7eea573e505a4ada2c0678ce6c620bb1c3cbb6082385750ec470183849e8e551d42d0bf54ec8420779bd7dfe6da5a5f0e9a5215a16d501c35dbffd" },
                { "sl", "84e0c61fae3fca9d713dc29a17f4afb70ee8852c336a62a87e3d48e2fddb97b27f5609911a2fb7df408000d2d1a1938e8440f1c2e0ed2bddb4288fe894ef4875" },
                { "son", "d6952c18e49a0b0318b9f78c7a91b629b78112db7ffb04115366b1f94758bae4dd3c2b1f67a3315909a647559a946b8a8c206e65420b02f04bef9f7824f184fb" },
                { "sq", "d169ae099910e3b551fbf84f93586821882a0dc7cfde4d21f4f40997c9c53c2460d16707871a970684cb2ce836fd50e8b9d7bc906c82d7487aac38f21c6ffcde" },
                { "sr", "467afa580610e7a96dd76be83bc9fcd2baceb7755eb24ad15a62dc949b81c5ef89c6b0c5715d251d270a8de7bbab2ce80d7dc4d4a2343eea01318fa8a7a17683" },
                { "sv-SE", "14357b82c0640af431851f478a437486f3afdbf8ddc495c6b27ebc4f78d6f821b8d2c42bfc0d416cc98fee9f8fdb13990c6965cb8aec2815b58b1d2544295b97" },
                { "ta", "65b8a101737bd3d1cba0a559c15d78cc7cc70bf289892821786e98e223ccc27bd84df31bf1aa223934ae76f90228045e238d4819457a326dc6903151cf1005cb" },
                { "te", "9829ddccccdcb1f705d08bd2ffafd1dccc29e416cb37a4472a8084e762f993bf13b0b3b88478ab8c2b1c03a14cddc2f85a28cb4064b613dadfe19c7701979a4e" },
                { "th", "f454ee22b4653d207f740395fed7302dbfc1e4d8844f595dc158a28eecf06b41c9b41b453f8b944219e9438e1c8cc24e05fe3f69f3fd04969512123a5976a544" },
                { "tl", "697d3774fca393e70e568c09b8c523b9d846b90d8092e0bf6409df2e4bb8b17afe2a2cc00457c8add90a70ae6c9306f41cba3d0d95e4b658792bf64bd74cfb86" },
                { "tr", "d6f3b9d3d74fa496a2e89aeba5ab5cc3dfe4dcd52267b177f9d77b2f051c0b75c0fe7316062686e01c40bfb6dcca81c8e6eab20d9db1caf9f5016164839f880f" },
                { "trs", "90b5837bf3462b488478a9becf873eb89a0611007a6b933e472062cc41994bd87be66d9499cff427666ca821cc1f5392d8a6465c2ebd456c3ed250006fbbf9eb" },
                { "uk", "a403f313afce5b373df0e71fc0d5e1d928d7e3cbbf18dfb645733c87706589785b573838876c999a1e523db2e6ea57ae647bbe51f7462b73266ac9cb227f0e5e" },
                { "ur", "ad29c6086809c1c46f6e67f85219e6fbd0842dccb237c1a0aed8e74a855f0cda30ad78492dc5b5a5612faf2f348c2378da8cae2aee9bc8b620b580425d0410ad" },
                { "uz", "e6cefe24cb23ae019318cdefe358f2b11f1070bb01b4139bebc2f1aebf85543f021529318ca72df0c3c49b513d1381a98a86cd40b383a1eb632c88e66d31816e" },
                { "vi", "f889fe983b8995c4734e79ac7ab8796a3b46cddb79355bc7768a92a6aa086647f162090396fd4c74ee65a8a57b1ab0da74d926048041fe9b56e482ae5715b17f" },
                { "xh", "eb47ca64ad1e2d68755e73ce67b9c2ab0d93ce67d388d70960538abb7fefa100e7fa28f39049c35cb1e822c4b106bd4a5dfc34b8cf272a15465f1cd56f2b36ce" },
                { "zh-CN", "61e46b34889159bc2c96bc31e732ff7745dbae1e4d05b4c9697b5ec5f89f20a88ecf8fee660ae12782c169ae396ce71d6d54603d51f6311ba0f9376c513a6de6" },
                { "zh-TW", "c5c1815f78f45b32d11249127bba8812d30774eb449a8a76f199f422579e7021053fd1e2a3a720612ccd5c97f10f2c49ca8559fc79ceb1950740df83b4461df4" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/85.0b3/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "dbdc4c53d02a17b7e0464b73953f42bb20810d8058fcbe130983e2008352a1bef7f44827b51ad3023c74183fea383882df3f0dc314a998f7585bc564cf4a36cf" },
                { "af", "2cf6bdf7647a6a4474530edc30f506dfced97af8d255da4b79d587a6765fa01e87e2b382418a220d3b88bf364e825cbd65a20e9b61c97fd0e3d61853f9f5c9d0" },
                { "an", "e0f3698d08dc6856666da628c9d6fda59feb1f12acd8eb57559319f2d1ab439675a826181ad6456a616328983931e8e0aa2daf6fcef51c4c94417386d456d77e" },
                { "ar", "2bc2af274b3680562f4dd133f3f6d83f23e642d855c83d445e70f64e2449b19f7e01a7fae271fb71af7e55be13a9528184a6db4ab6dbc123342b98c9f9b54a07" },
                { "ast", "f40ec11c48dcba142551f90a0ded66acebbec47dca94c6d67ee7d337acd4abfeb21a3514a7808b33fd4650ff2780477bb146957b28be54819d3dbf9fcfd38692" },
                { "az", "c1367c499260994637150fe328c3622043b277f92d76971e68a21f448338b0415d92fa906c70c54c20f263cebc80110976d858824708302b725761f42b6be892" },
                { "be", "255c70999f1fb9f1f7dbf77db74b77532ea6c00ff1af05e5239f9d8071996723f265e166eea9f603d2dba6a195548523276bbc4b1a1f567e74a38d9c27bd4584" },
                { "bg", "e8fb9b829ab756fb6e5e3bc5cf07a7a594f2247966b64b2b67710ca60fff31e26fd76005b82f472d457b89f990ab7db8163bdcfb78cc1be2ce939a3fbf49c302" },
                { "bn", "a1f29b7f02ff76c32817db3fede84a000f7c5ddb0dcf78cb429cfdc9ca0b74e052b330a995e764a5063fe9d09125e3877536ffed86f7a34efdaad1cd8e6e8004" },
                { "br", "73c01193491019d2dd5a60515b9f0309415f3a6e0dd664685d0ce40ab61b320510e2d426f1514bc198add2e2848c0b74387a850f98f35c31c766b800c268b921" },
                { "bs", "43ade0a4c07c1e4fca34d196afd4dba1f89984c9710650a2525939b74fe16d9fb6a479022ede42c531874d0db017401dde692212d6b900b38b9161d7c4b8ea43" },
                { "ca", "944b4f1d90f320d27f4820714fca489c81c57b62be4955b7370e76ffdef247c37451e6e1f3f8c49a74f0fbd44db683930dfc2400692eddeecda3836bb767a8bb" },
                { "cak", "becafe3bd37853987ff8a79bc7794a60064e660fa2bb058dd06ef25058dffe87a3afa09a1a41e5c1ac560efd91d7dcf0ceb4610ebcf350a752358a64a5907915" },
                { "cs", "13cba2b55a1c45f8c8be8126f3938ffcd9e4a2354bee1949021b912b04995eac433e8dd97daa790c8d15a7ad23eff2dde932bb3b9d4387ff54648180eb090c4d" },
                { "cy", "325682432f5f9aac82136ee64558d6be690abaa345634344c0aa7830729a20819780d68bb2feb0509472e3c0a3e1230136d1b491a2279d7716da8acb85759ac7" },
                { "da", "9da04afdb4108152a226a7c98ef246a916bcfed78f4ba93b04d7e1857d6f5001feffc1af8f25421b8c6fdfa9e89d977f01ccd7e2a1419147bc98dc61ff3d18b3" },
                { "de", "bb92b975649d0fed4ecfd5351eac01598363234d17cb7e63f9a521e1f28af9f8daba0f193d03b0ae004b654fc661d54b156fa9f2689c5ae337b13f8fa68abfd8" },
                { "dsb", "a850e748480a18cb9f94c1557c52bb89b2edcf3509a41c49281a5d084d8aa197d6179d962aaf2d064ee63b9ecba6c96035a2da4ca0d46c6530f12fa29e97d202" },
                { "el", "ac30de33db75e5e56228b4af95856faf8431aecbc68fba555ba4b30012ce87b18e8379a91ed5a6a93f9a2998b3c8ce34347becb8ce33e7061ff7579203689adc" },
                { "en-CA", "5d5a55786c8387db16173e07f10f6a97ce698ffa66dc42018c735cec46f608c07e87da347f66f30ae9e53f168ed95f1234646d7c1d88c965e833a34f5736e2da" },
                { "en-GB", "95416964fba08a8cacce2a5d265b30f444b73ecf84b13fcc865421ea13bfbb063df77ea1bb04118d1f4746567215cd5bd3eb49b8b796dcc6edfc1311d5738940" },
                { "en-US", "52e87ee7d83751b6e0585a8c42ea6cda0a2c45677646516ef78d41d2e858c52a49cc1a5641c122a4f23afb35d3c3d5197c7ce89fe2484e098aaa9e909ea2e30c" },
                { "eo", "7e7a30a80d1db6748ee0acfd2f920766038d02a71f663b8ea5af0bd9afc4fc0fd3fd71f7af9f28c13a65776b5c2b83b26121d264bedac672b936b3187981d50e" },
                { "es-AR", "6677d9deb6c0f6be5576972c306da6da3879a15a54156181d22d87e75ea0c7996d6887aae3459958c05089eea6e53d9d5ef9709150a478437de097f5af2b0538" },
                { "es-CL", "d8dffd9b792e662eac32578d33ef784e30f5f4122e5e8fcc0c5158ae20aa23b9f5e5daa9116ce986575ff2646b9a8aebbfdcd623f4e7d43ac9ec78205d320f43" },
                { "es-ES", "2630060cf4bd5c4bfc8712bc8e790a32287d0028764f28bebc031ca69bf05c3f7fffd450c566ae33f3663ce82a77ccab3508235809ba6d967708419cfd077fc0" },
                { "es-MX", "91a8be3b10228b327751434c394064d9174d808627a62ff9f903174a4b7eb9b74fe9ffabeadb6d37a5d07633602e170d03b627ab0777b52523f1a79742248d77" },
                { "et", "ec21a1bd66549d11d12bc1e1f9b7e424dbde59e1009a3a432ba172c388ed973051970fbd84b3f962e9ee87e09b68fa008d82b447ba1476ddb754cd36f5701216" },
                { "eu", "8ad7ecb16af8f51cb25a5840552d25e11a948326a3a436bb234549201d5d5a728bf339809ef96cf21cc4fc02c18b3c23b6fe54a2b0fda152b49238c26f0dcde9" },
                { "fa", "276f9d3761fb730a1ddbea00cef8d8b0cf75fcd4a8f03350e02172561f1f66b01341d1b990527ee68ffb2b6cdf8e505f70270f53617ac3c082be57fe092467b3" },
                { "ff", "7b01d14047a1e370bb39546e35bbe7edd5306b38a02c63b864cb482678c714e37606841e2e36c1eef1ee7913c7a4ac1f359a498dcecc0dd53ff6ec964ea346e1" },
                { "fi", "deec1cf55e885e41b1137762c2a7ca9949984b61a230ee1f6204a3b775bd9f729fb5819a0cc277d36ffcaf3778f73975614f7c38154237d22b253e62da760f7b" },
                { "fr", "24121f450cf47f8c6e5b10fecc17fd00c743dd7fdab7344ba1e2a9d6ad1fb76cb86c46df5bb72ab24b8e7ac324c9fe68a7380749965a3e5be6b9cb1e5b5fd333" },
                { "fy-NL", "eec295765ec922ff8b943e01c2686be6e421d29ec02f49215896d873623f636d5c1a992d12f8f9ce0c4a4c8d3ebdb1f0df7c4db51f345a92dfb3b50d4fb8827c" },
                { "ga-IE", "7f6a665f3634cc5d4f4d01d2a92343f9c4812c25f36d8b12481a0a35988c0dd8099cd1ca55633e0843e7c21be16e34be0155c07cf50462a2fcccc9d6b48b2be5" },
                { "gd", "9e991372e0962289b991a5b8f942fbce9da32e1fe124df97e14987620af2ef7e48ce8d4556a746b5919300f419c66c4076dd1a88d5d9df2db2b207e9ac611105" },
                { "gl", "9e9141c01bb9497891078cc3e7e14650b473fe8b7a08225d4e98b7032b7e80226b39ebaba6a49c0c99293d3fa2596f8ee9d1e4a082f7ed18522443d14e9f6d50" },
                { "gn", "3d4990443e38417c7e4d24c7270388b39cfba103a04c04c11eff4411cb79ed89fb8530e3c069fa91bc23f7d45c41201d5941fdfface179fd87325ca9d7cf43c9" },
                { "gu-IN", "356a21f433d3fdec1c18395330315880aba6dbadf7308581c784bd644d0b355129370cd3aeaa2cb33a7346ff3bc76784222ba6d07abd9a3f64ef7c9c61af986d" },
                { "he", "2d1cb68dc72ad0021f8112929b6b9c196d3580de196e1fc74aac7105d3bc1f4a78f5fbfc1930d9ce448676a1b9d5c2292016aa6d28ec56459a7b3ad38ea347f7" },
                { "hi-IN", "7f4c73990e40e69a4af64c4f30290eb603cb984a2597f0e7ae5f714d557a73d6f50f388afeab1e4ec176b63f0253892c53d0e75ca74cf346ecb58e35def3f264" },
                { "hr", "be27a4adb00e3125a2435fc56d8cbf6a97f360701def0d66e0095a2722aa81b936cd39f5066eeef155892c1748001e8c9a019c2da437c69c9ce1f85a7bc52f70" },
                { "hsb", "d94029b8c557a98f9d679e8e0f7cc08a111e7ff8d44e3a420ab32edb2d46cf7332301d9f17ba1a1ad6c448a181924c7c1c66c1e82bb4e232dd9f4e737ec8eab3" },
                { "hu", "d4c0776b777c2ab359375ad0e911821369ae9a4dac22ec1f8c312939c3cd4443f3dd2a5c75924dd26febbbd7ffbc5e2b679fb8e71dc7f4d720b274ed5a32935b" },
                { "hy-AM", "1fae95ec707b3ead308fc05f93bae96361b4476cd9750a5606ff8d9d119f3264f3984b815669c9130d47c3315e48b820fa1584bfa5cdc622e38662ca569ac40f" },
                { "ia", "af045d564a5811a961ff2007c097d19bb1cb329519fb0bc6acad4f24d1a22e1fd5b6b2fb55270949c36ac208e37a6d8d86f139112cc6d90dffad0b4493f48025" },
                { "id", "e02c402f981d8eb53a99ec756059d5f83188d9ed74dc64e165900ea8faf589571fed91cb39b61d136b8d35697c25e6b0ca8eee42ec3df08cd2cd017ef7b7482f" },
                { "is", "8eb0153b841f64de5373ce835a44582f00e038798a079995eaa39cefbd594f31dc883396d79fb08acefccdcf007aa6b8d92727bc6d2a204f4c6a73b5b2bfd01d" },
                { "it", "5da9252778944e3c2356b32442c3261467130c8d45ac66f544c91b0ceff6a11e41c21538e70571f564be048ea684e12fd2108a145564d74a3da68c58583d4e7f" },
                { "ja", "bfb38cdd1d1d40043ebd9ef07d951c15547e62ea93c55c9288d836a972b6ef80b03590202689e36b3c3324fc3f08d0081c4f0da58779c7c92ce785108bf19be8" },
                { "ka", "7ea6b15de602da797ff8a4a7e8a3a57755e2c9d5d5129eb5a8c518b00d2cfd1d635f7c14c74be6ef73137e48f949254a076b53af590eb2ae6897834256432176" },
                { "kab", "474b3d2b566c478c3e4ca407906bbbda3932431dba808c7d61313c2cb84d038607500c16d8e392ea7b6dfdd967cf19343270b4ea6bebb2a68d5238867421389e" },
                { "kk", "e52e5d8946d22fd2af7f86e8306adae46251be20b7cb9d2d345ea49d7e1b7fa472c5ea10bc9d01e1ff752d4763e1fe63f8693512fbe25e6a7862e1e9e839de90" },
                { "km", "004a0a69d859762cd1ed718e52a9ede2bf7282fe3db96a406404200a9a3e8ab3541bb66f4a6d96883ddd477bc0af617c79c8df9f61677c5c11c4afae434afa07" },
                { "kn", "e9f20b85307a29d89b3ba39fe8dd30ad66163cc7ecfb89290b9f087ee1d422c79f158d6bb1380510a52044ed5cadd35d236c9c6c4bfdd79e99c9df60f19e218a" },
                { "ko", "2ff50449ea024aebefe3339326febb80b23e8d5968aabb9bc7accdf7f2eadf9f0c8c259fb8697a5851d3b74e8fa84afcdcacdfcf3780b885d0f19b303a937eb1" },
                { "lij", "745f3c520e7715bc3ea658876b20162e7e95b2d1380dd7877a1b5d4b0c5d69ef22844eb850b53bedd992c59201fad765cd7410ae3455d22406dadb4800e3a71d" },
                { "lt", "47d0f947904d1d0e1c6df60741fab7795c86ef820ae658506a199b926cf96725bdcfb99a6acd63c93ee7a604c4453803d496341e75ea15205a3e2eefe445cf35" },
                { "lv", "7f46e6d2cce0ed43f8f538888fdf4e686c5202e57f0e9d0fb53edfb3aaed8f9cb32a77bb0276d5d6a2c502839f9730a42d2a03da1f93eea5ae69dba7f6d42424" },
                { "mk", "8ab2376ff11c7269abb03bab10413baa50b856b0912c7db80ce96fbcf7e9b0ef6514bc7a49b31492d060551aef35bfaf97cb44cd443ec2319f6d55e8561eb41c" },
                { "mr", "359130c39b6c001bcc721f74b3331a9dc086c24219c05632116b28cc9bbb6d306871586027b8db9f63a85e76b640a9e14d2927febddb31ba8386c5100741e737" },
                { "ms", "1d477ce745e56019c7d350e95de84a23f8892965e5666c8a91aad28a338be5aa1c412b07cf40f345349f7cd38e83238fd475206586e44dfce81c7cf1f23188a1" },
                { "my", "8bf29ca92a2bfecff6e9954965c27d3f7fde06d2dc8951f53d9d2b1a71f85042ff0c0fd638fa20528ec62542b01c780998a8cc0c7c30ddd2c0593df6a52a1053" },
                { "nb-NO", "d94c2abf75c876e7ad6ae138597e50e310f4c67d7fa2b4ba7fa7ea5226f8b87beba0814d217a003bbe61a2fae9621c65747840cd5168ac59c11c2ce7724a9745" },
                { "ne-NP", "f95f753d6e3c740ec68c96592871f8ce6724409fc8b0a45ab8164fa0f7c9b6bf50f4a1f9693912f372989ef796bd558f2277d8337f2eec024259e6204cde5a0d" },
                { "nl", "5de275c42d1c3cc89a5365bf41fd20fa9439f888b4b4afc5f628a0c7ebba87630be52ab081b971bfb01bd75eaba1004f9115eb58619a3408b0e7b71c7ba5df14" },
                { "nn-NO", "5cdccc287d2625292e9455af7ffda07af96cc0a9629192c8066034ea2dd834bb01e00c121d22c85abb848d23c4eb8206ec08cc7715ffbc233244df172622ba2e" },
                { "oc", "c430f124b797e534547b711808620a8b696f812f0eb84926e8be2492be4f0b38d961dcaf7ff568f7cc3a0c517301e4ac2f22b3f9169b9bd4aae39b44948d4aad" },
                { "pa-IN", "fdcdd8000f2946bf93993baeac0f0d6ea2fa36985f05becd6768eca8bdc35aac3b75ec6f6c02ea7531802884860b0c3510a85c6bd9005d76f64ba187fadf094e" },
                { "pl", "fcd6d40b3cdc92d86d2b823563296cfee3bacc31e2561325b1ed7eb926955950a4ca3c26258cb07b037ddf35eb69321b22bf799862845d16141c267244b479ea" },
                { "pt-BR", "a52442c8f705de177f70481b77872645844e1358928b93f264cd8aaec5d30fa3549b6bf0135bf39d91ab5347decb3f953943ea1ac38fee2408608f759ceddf8e" },
                { "pt-PT", "35b16fc7e781c56b698517ab76beb35177f569f4a1746f0b1df2bc0db8c4f5a991f55323f9bb41a5305683617bb483d9ecfe95c6f9aa9a123f9cf685d8476ce5" },
                { "rm", "bf4408434311b1d3e2d3d7e942b627e6a9a3d50eda22ecb1c1b8684406b2cf0b8d05b59056b2590286759e3e5339c045250bc6303e0f09966d4e7074d93bbcd9" },
                { "ro", "8b423229afd267875660dcc461d97dbb620d8322076d49c957352c2af7b433c551fe3dbb7e9852116e223a9d29ec7c6c6209fc34a5f712967818865292551479" },
                { "ru", "34e2c08532efc689d2330a3abc01238a8cacc07a3f6e14b6d4894ff8baff7cd1672557d7e17fe810d4512d70aabf7d4ccc9d5e91961b5058c48e92aad68b3aba" },
                { "si", "aae34d81cfc14e47b71ee6a0309dbaf8a399f23d14d3758e496fa8169f3a5ea573417fc4e6907fe49ea3332eab2e802b6e159072ab30d1b9213072a11b777aa1" },
                { "sk", "a4d30652b29456e250982dd61834ce0e70a4bb0eafa78e43b215c676756daf58fdd711a5885d585516a8d3c58d3d38ec85d9fded059eb3ef8ee0b21423727b60" },
                { "sl", "fe9447f7ae6d3fefe03e68d0493fae385e27607161d6373c462d4a92e33257f6046a96937537ecca889e41c6e72db6a94bbdf1da30bb0a25b147112cf059fbf8" },
                { "son", "d7d89bfb6c90ab01353f5d38454e4934a0adb3931607aa4bec4d99a95269b967ec51ef5d3b670e32a77de94f81c928e9a7794c1058d976645831ecf8f35f8f3f" },
                { "sq", "3e30ed9ddcee749e08e2b960a19ddccdb1c4f0f3590df3b0447fbd80f6ab5b7eb7e509325e1fbe979f4c2e537e35fd5903c4549ff5ac6c7c951e5320f99f42b0" },
                { "sr", "4840ce0677b4e42076a44b6f5d489500e2ae55789cd8ee1761796ae82e90153d69c15f8cfd98a0c456017839df88f39d03f24dd04f6f1799e891fc69a59e795a" },
                { "sv-SE", "1ac4be70f02392af2d3999c9d1b52ed9f9d53e4513e1a2db426ee084bd1b80ba39eb392ff4918008e40dd1d77e84693b2bc0b7010b4ccc2badf77b49cd0ed38a" },
                { "ta", "d2243352d2cc5cc412b66addca1b7414cbf142762b2d9fb4212eb07bb00aa4af8170a19782cc5a9db0f287d691374bf1aaec09398269693352eb681ff0c6b4ce" },
                { "te", "0e0ce43e2d8e488f2f531694e69f7757df8ebfa9418501176029d1131e229f26cb12b0dca148160a2c535fde561bd509792236596f606bdaa8cc128cb24b4e67" },
                { "th", "8044f26ffefc948fe2b14c1878260d7f7e568e7f11ee27e3e8b5993fee395e6687cf10a88507e612720fe113d0464846d78cfba9d144d8b1f89076f28d9c0587" },
                { "tl", "1ce3a4ca1618f40ce1907c8736f14b5a1a93183d1fdf31e35385af7ad2c84516cc00333de1a1a175cb717816131778341c97bb41440735ad2a602ccc07229141" },
                { "tr", "594e0f365f8010b4680165bf6bf677e7e59be69fc55b0fbba7a331329aa351c5c9a151a199ba9630eeeb966fe018de90347ed5da6deb4930968327a69ba83b3f" },
                { "trs", "caf3b88f5ec5a55be34ed452e663b85a30ce273a5fe14a5249f11f533f9e9c5ee60d862796fea0745a5d3aacf0137349e6a2be00f21df34af5ee1542a478ebbf" },
                { "uk", "82cb891e950d244248fe1832da3c1f8b3e24cb3393b734827e32af941af6fe1c273ff8fd3f480bf00e63655bd5810593a30c0967a072e3156c55176a8f29b055" },
                { "ur", "0d4de3fefc6e55fe0861b7811514ca91d615dfe337de30a101b3b1ce13dfc605ec9f9f2bbeea5e24e8cfa203ccc33730b6ac3afeaa685079650021c6e84c0ed3" },
                { "uz", "eaa685e7b92dab1362517d827817a7062893f5cceb636f9cbb8e2b7bc7cd9c8152b81fc4c62f07c9ce3aeeed8c8d287d65bb4bb21508190392acca11783930a8" },
                { "vi", "c4776a3d2f1216d8c19431602f17c2d11e15035b4e827aa6090e8e32f31b3ccf62e4b260920f38ce8e807e708f620a2088255e7270e11ff254cce468969d5ddd" },
                { "xh", "dc2ef51544ea59c18973112b77842c91290f6c938b36529bd19ac2f93d66fd5548fb881c0ba958f08201768f7e78a96fda0949de80b3b6ca955fe4eedbc98df2" },
                { "zh-CN", "212ee846ca849d3fd7ce166a209e178a7f6c56dd6540106f53c574c68cbb742fb1e257f233c9d3ef915d484b6e6ea0c23c89e78147fe6c3e83acce0b6b5edab3" },
                { "zh-TW", "683c95b507863318c4f74a6fdceda6fbdf219958b5a6fa6f9bbddf46c1e97303b8c6adb9bcdf7349d2245553b10359c3a7c905a940e9bb44790840d13c41d93c" }
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
