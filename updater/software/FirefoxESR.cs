/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2021, 5, 12, 12, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "8a77de7d8e0515511ed95ed781dcbf9a9435ebd78e31f6c0e50fb987c1e43446c4d7496582e11f3969f560dd0b027188aeadb782bd38a03cda39a3bf1b0ce3b4" },
                { "af", "8819b1a8e5355e92577b9ebe5deb683540845dcaff52d34addbd3b73ca8ca58d0c738d7d699d82ef0512211ef1c9b51b2ac3dd71ec6ff0a6ef56ce1b2d9afeed" },
                { "an", "4e08a51505e858abbf70ab1244a75e60f14a3e0988d3db4267679e6ad416d91ca6d7495d7d74fccb9cf2212804ade9311046b8e2aac6696059166edaca60a21e" },
                { "ar", "d87dd84b299b99e65efe7eb67ca25f81f4abc42863eea65174cca69e02500eb765f7bc53ae83b1408f8cec5fba677f92370a76539cf1df9775b51605e96e87d6" },
                { "ast", "49e29c3fcd7e6ac1342dacd03b9da3bc10a51caa0ae8cc3785ea0c858910492fa88d2c80e5487a7c9b978db1bc94fa6269c1bae23755ba98e1fd3648a0f52400" },
                { "az", "c2d520206db73cd3a6f2151bccc54f16731bf2dd3da2356b8a5c0fccb83735176c73c47f0b189d67492d0cfd5e690102ee80547e46cec52236f791aea303e2aa" },
                { "be", "263c0702622ed0c0b93d66ba45b5aab240862844c478333a6dbcc474da03c9d698ebde7c8ff1098dff3d369fbd2c89084460d7cf336fbdbaf32e41595728ef9d" },
                { "bg", "bc6323fb77f741d27a68d8c0656cf0327e8682c9b8cacc8163f3145796f9cc40832a68f89ba66771f4783c506334d2f82a4f1bdf9c4eabc5176bcecdcdd8fcc8" },
                { "bn", "e619670c796ab5dfe26b9267c1d67b2cf7dacc09c6281dde2364a75c015d32deb23e06cd6c6fad24ee958fb1eaf5ce7b4d5bd2b801ffb7132edbfc069ffc62ac" },
                { "br", "255382b1d347f3d369af31d6846a5c67ae62b9694ab0b8e037532db4e7eedac773cde3a0b5d6f3d5d98415fb86d46b8d48db87fc3fc60e277cccba7f1de37d48" },
                { "bs", "1d2bcd55aea6e19e163884cdeeecabd3169d457d3cc4a1d46764c7e3cd0e53c510d1aa0840bd1a56ba8622e982eee53bf814f0c9f020726f2a6736985697ac8a" },
                { "ca", "562135dc9bf2dc04013086c8f946fbe679122e7654930b689e43ee7fd0db2ccd331088a90f26238536de47a35ef9a6eaccdb4af08760248cd8658f25f715d56e" },
                { "cak", "afba52d0aff328477c4e784c5b4c5b7bbeeb2caed3c03231144ded03a4b3f089f2343b8f6310ed49529c0e395304aecc24f9c091b8e2ec9e00c4e97726fafc2c" },
                { "cs", "03063bc7d457fcfcbb1c2492fa7501bd0b304cdbf2527fb02fca11e4acd9a580c9384d72eb791d9ca9caf71522cb347f3fbf8d3d057f5be1afd0712778acceff" },
                { "cy", "295a5e365237694b454561148780312c1275c8f977827cb921ab017a78f5d5a99dd6ba7f72c489524c335de691e3141163ca55817b11839a157135c5f5fac0bd" },
                { "da", "75a0e5a78549bef389d19e8388dd0dcdd11506d84cf17d566f2effc8c1938e92ffe1edadae635a3feb1f9f70d4f282089c03fe01490777122ca13f8969b6bcf7" },
                { "de", "ce729937ceb9ed53805e3c03f161e5f25f969356b5a2e5e1e9b023e88892591e3575f03f32544dcd148599915e445106575e2a2a809e64174b6c533a1657c297" },
                { "dsb", "f8593eaf82c99f5acf6ce0daeecaa38d963281c2b0ca1e14ea1dd25e0d60d69cedceb2d4d4fbedb70d5213dd74fbbd26fc551409af94fd1428245915cb394144" },
                { "el", "07df7f53df3364269df42905154c2be3adcabe29092fc36cef59ae0e63da3e1cbb5db3efb1bb9c925edc39d1a7243310e50d555c19181f01eec87a7f26c87b33" },
                { "en-CA", "d8af3692da0f8410933ec15d3a383e0266531878f5e69c7c884389cb8b696cd30d8b84db5d64f91e8e41190b2def9e6061a2156c0dd05a0ea8b7c5e51b3db973" },
                { "en-GB", "5a888b97c53228549bf218ece486f17b745415f3cd4d3653146a179efda81c6a57ea21d71a13bcf24c2f1923be05050505457a9ab7390cdb3817cc1a6606d261" },
                { "en-US", "ae4a28a13895b9f4cf949f77e2e11272e2a306ee9b1bbdf38827bcb712cae4f230bc533fff710bfc3bae6896eaa270c94aa5ac9bd57ad597410fd1e830469a27" },
                { "eo", "7c1fc579688e7bf2916ec9bab5ab97986ba227e66f18b5c2668cfaca8ad8503a54c77bf26c445ee7559958de5d48323b2e821a177ab71fead60439cb01a55dbe" },
                { "es-AR", "6e810f6c212f26bac525c596926a3bccaffa0dc674ad8f3d180f50448489476794f76d44a57960ba77daf951b16dfde09eae6292929dd4631335b2d0f970b303" },
                { "es-CL", "0a31080a43a8b4d12aed4e78bba102a14a955a314096f580c8610cbab2e9e9e55d3f934ba785d31206ddd52fcc45320cdf69a221433a7355d96b97601b539ef0" },
                { "es-ES", "bef457256a5f95785d811564699d8d6cde1debb73f7c526c346a0e01505d5ac88ac74c8605d0f4102a7f32591d5301a5118f50e1af6dfcd3a0bfdc9de37ef8a1" },
                { "es-MX", "91b0a4f3a4c1da5105ffae281b46e7642c10861ab8897a5d6272bb3f62f0868fe582902b16669d23305fe7fae2dbb98313d8f87637196434c2213baf2635213e" },
                { "et", "94be0d988c0a6f010e7c3a8ec40da7a977337808ec9d4a8f692effc806d91023bf81ee566729a453044c36895d18db8b450e942fe28c749c640a965fc1b103f3" },
                { "eu", "4e26dc1eb9f495f00ac139d6046aea55732dacd31a1c74ad16b7e0e5e9b991e554cfe97423582c3d222f33d4541fe366436aabb71006897e91d8a02116d26321" },
                { "fa", "6153a4742ba4799c52370c6ac0cc1d56744c0c7adcb1a600435c552cc53d2be418d3b80a9187ce2d66d28454a6463d7b5e3da9840f7cffc18d3a881b229de4f1" },
                { "ff", "9c553ab0a56c025bcec7a9672dc0a336879f8fc063b47672630f32850abd3cb5ddc99b265a75ce3e453c5432c5c4fe4bc177122277b3233d14a2f6a64f841635" },
                { "fi", "3f2762b1b0ee6daeee227c57173c1ad03c5a71a5048a0a38193883147c1417f92c44967a9ff82dd7eda1e16410c5212597b97bfbdaa7de3a94a77f318902837b" },
                { "fr", "99546646c41e7ea47c245854fb2ae3147934385b92e58a48f723cf48d5202a2987addc0b3601fcdabb08a226c2b0ecd524420540df8c55fb476a61ec4c597962" },
                { "fy-NL", "7f7892d1dee97e6b574002d187baecc0661df7d5a3c1f21d4573083400d45c4fc09ecd152aab7ddb80b033930161294c7210690996dd5eeb752f7437c039faf8" },
                { "ga-IE", "6c1805c9321596cafa67ff483885fd392952f59050368c6a30f0a4a349c4008c6e4dd29ece54526bde40eae73f3b8869cb69252c25bc68c810909a91954d5380" },
                { "gd", "949c35507ffec356df33dadcd5072bb6f65a06e29c89121e98c338c47b76bee727fd93842b5eb428940483be994aa7b1fca9450e875e0bb1b2260f4fb827e628" },
                { "gl", "99440790f2921b291e99444af9548fab43f8f15f3e82369105eba21ea2e94ca8684c036fc81c185e7a1b9712b05537203db1cf60fa4d1ea5769f4f0a93aaf0a1" },
                { "gn", "329a3f3be547d02c3cadd48c2cb6b03da8a7795904cc5b10b158927cf147db8c10ef245a28fb2aa68330614898d8c4bb50d206ebf5f9372a5cc3df5fc6127253" },
                { "gu-IN", "3636169970fcb9277e8640674970c5929b608706d85ac344551707ef45f8b7b7a90f2faf4b4ef8467614312ce62ffb88880ab061a2d270660889184c4eb43843" },
                { "he", "bdaa844029d912e98a7f13145ddee39c7a424e979e8bfd8be7129eb893df6d2c215823d68c1faff4da87dd8428c63cee4384cb843eefc87d5ff31b9f22cc639f" },
                { "hi-IN", "01c2e676028606da7d3e8aaf09973db7532e38c6ea7b8fe0e0eebfec390657ff5f02dfe5266b4fbf213ae99b31f222513c404f582e750b9e1f84ea8cdb78bfb5" },
                { "hr", "d36691aba73162a31bf1c04d44a2bb7296eefa90bb20d17702ec67df39de186e1f62cb7e3bb40a8ea5a36aad06c67fd66c589ea083eac4b08c43d7afdc3fc6c0" },
                { "hsb", "9a61fa7dba7a169d412cf113eab42f829ac555504b1dd0d6df78d8fdb5d7842ece0a6223142903094c0cc60b83428aa640d91b443b32c56bae613d8cdb6fe3a7" },
                { "hu", "b199e8c183281944aec8339d0bf9db363317088626fec95d70adfbf5b9bae1c7ddfd0e516cbcf2fb03a8c654b55c800d89f4650c16439aec7d938dd76bd1b209" },
                { "hy-AM", "bc3692d712cc994d6eb13978d785e59b6d68c75272a94ffd57ec767c130f3d2ee95bb5ceafb5dff15fdfc09174d0f9cbb8976da276ec39128d44cb77edfdf239" },
                { "ia", "892d59b3fba70d4732a57cc33c580dc880e332c31b12150811a247ecdca2bb9b9381b52d24aa312db5db5c5dbf014673df240cd20a037b284f5ad5d554fec955" },
                { "id", "cbb9b999b15c6bd22667ab1c5236fb1d64431bcca55eae7040ea85d4651ff12f07ebfc2608b173d3f819fd7d55ecf350ad304246070d6aeabcc0607d1b5de518" },
                { "is", "05d577538aad7a6925e191e3657966fc00ec3cfbc1bf02581b68f837015e88f80cc7c018190676f75fae6137d0790230e3930a8a8461cf16988639f51143e0e2" },
                { "it", "5f3c3fbcf8e7e07d68918ae539d30c3b412f3d0afdb7e6665c9979a51ee9187ede83e8d1acacc7c32bcffe03d62eedf1ed46c077ac8db6d500b929fb6fa72f72" },
                { "ja", "241630fc54d70e80a7331e79af8194604444416d52f26622f365b21d3c6e609a4c7dc623ed8c72c9ca4b37ab4f451e625681e41b95c7f693ba3e7753b6233d4c" },
                { "ka", "48f156918fb1194021ada23ff8d5161b4c870082662cc0910a362bb95e4775bbeb82cd98b1c8298b66d3e7505173f65fee0ad4b560461cbcaef3859b9a8335df" },
                { "kab", "2a66482b7882026b22b9e11d8fe809d9dcc27011ff207d473d3288fcf7e4b9edcadbe80c413739c5b2efe764f11a8a25af231275c940fb26ba3628e215d296bd" },
                { "kk", "a60aa342b305b4241e9aa62737792a3da6f496e09a517a803dfe9bf8bbd04037e4c4e5634d5c295cf410142b67afc1297f38fc80bd2cb29fdb20fc6266fc6084" },
                { "km", "09eb77f419903b41e4d65ceda45f36edf56ff5d86c8423afeeaba3d5eeecc27b590d2b304ef879c77ce0052cedb622af009be1f024934016a5e2afe888b3df17" },
                { "kn", "87f253cafbccfbac5018c2a6943376ed2054a1c1089fa51dcd90d3b48d24795b8baf65458ebdaa469cf0e332e8f812f931e4a5aff2c53d43fdffa258ace6e0ad" },
                { "ko", "e591f174c6ae3bfc69e452128bc756501e966d179b00b9ef2351316f3082704b339a5786b849428f23526ac43b58c6030e3ac5fd33a7c390386dd01d68e3ae9c" },
                { "lij", "24d27e0256fe358456a51472fcb0c94a34d1a1216b6a6465ecf7f456a6fd1a18a4a769a9aafdd89ac13b48d3727b44859485599b3fab3c3ac2f5345afccde1a7" },
                { "lt", "8ff81d8f4decbce1984cdefaf77ef9a0202715d0ada24f7bfe6d28c7237f17a00ca7f5f054a86d8deb7ec2f2f1f7a04ce7deaa2afdb55fa771170de01e19bc3b" },
                { "lv", "c2ea4d80b953a19e97c5ee19e601f2110b1db0b658d783007a648468c6275c6200bb58f0138efead691a3e73d2300784a5b88314904f04602cb77b3505e71098" },
                { "mk", "0539fad5875fb197575c57d00f4a70bcf7444e8cc45fd674e029cc8749a3355fc1455776804fb161815e22212064d224cd3cd9cde972709324cb4428264415a1" },
                { "mr", "38e583c51a0b0de254e665ed64ee324f6596214d5948b0d91d605622b75ae33eddff779b0944afe9f45cee883f078b38787447b69821090b5c79b4d5e190c192" },
                { "ms", "eb60216bbd727eceb98fee69dfcd64d1f1c771e10d16ed59df561929829dd0c5c3264e670c9e604dec6be48e7f8f0fa1dcbf9fc88e89b6ffb3128c102663c259" },
                { "my", "8a49a8bbef0af6381cee1b8df9b778412b6c1a2c1781e0fe8641c2dc37a043f6dd3e44e29c700bd06667154b08861324bdec48e1cfeb7d6bdbd896d23ec6ba0c" },
                { "nb-NO", "46d5d146439a450d09a4ada216f64250ce58797104bea4fa8d3c6e3443b5da1b452ae20be45d6ddb36073dab3047ae96b92caf1512604ba42b113cd08b8c144e" },
                { "ne-NP", "1493494b18e6f0b87ece5f148f292578db64e3f3f869f4e4711722c2222516618f52788fc69ed734550fb27173d1141da4ff8ccfe7a4199f46496acd9c55588e" },
                { "nl", "b4c70391a41510903db8324c4a9dceb912a6bedbcfb9d182d5521b512b23cc8c6caca940c7ef154775093683a7e5d3398aa1e44fd36a322c4281df93a93d3361" },
                { "nn-NO", "f6dfe9a08f8f56134166437bb407977e2c5d0348eef392d2f0fbd58c39d9a52b76140ec58c24c8ed46bd805504411e4ee0dfc0405f8cc923e19daff86a8c8ff2" },
                { "oc", "c5871dca261ce3dfd0ea3b9b0be65262b0bdb2ca06453c593ecf94d0f28058e75b882b162745162405ab7c9c2f982d9b59f4bb2d5e2c430e8e9706e5be5e8f68" },
                { "pa-IN", "23c6d72f5b52fa487804eae9592141f4add5b224fdb88c325acad8fd5c2b1df27c0cdb3cb56e10fa4af059a7931d0b17886f4cabeeb4a0f8b7ad960cc12129e6" },
                { "pl", "d1f5d29724b7cdcf71e442f497b35be56ade8eec9d41ba3b80daf0319b2f25de4e6c840f1b886c0fde28ef1dc6374dd48807a4a5296c54c3b924d5a6441feb3a" },
                { "pt-BR", "cb4eb0107a2030178149669871654e6f5ad2aa5ee8bd3359526ccf4f6ba1676da29ffd6bde08253fdbe650f9cf4f281e9212105a4921a12378aec8bf040665d8" },
                { "pt-PT", "f6e2538560ace7b3180957b971d1b74d41fab65e969022c63d4fa6aca80716bcca61d30928642cac2b089e08e0dd11a15bfa6d824234199dbeaf79a0f35f892f" },
                { "rm", "7af02d3eef0be7197d96b833bd254138ab90bd45ae531c18110d3382799140df8cc00bbcfa8371f254b233791ab8b50a55a3e44860560ed6dc12dae193f5ba05" },
                { "ro", "7a6d6e4fc4825c06f0bf22ba4492da838250bd444f025b30179cb0995bc1a3935002c611d502db166b03ff98df4857a0a16e2736bcaec02f49876aa397a782ce" },
                { "ru", "3fec3020773eb235eba561ae093bdb34a78c85bfb59c4ef4fc24159277dca11339ab46b68ed00755856349d18f8209c259b6962d0fccc3304fb0759c8f99c367" },
                { "si", "06d4c01f1e9fa1f16d00262fe719a10f4d6e1dcb81b1d9e5db1bb7cdfd27af72412ff77ddcc27fb1afbd305e15fa6a1ca2fc08f37b5e944b024c3ffcc6fdba1b" },
                { "sk", "ac49045b82e6889531ba7dddd483c5e5c0dc8ee74ae87afdbb1f8848a1989eaea4e60d303f48d686088af1b82b1cbf8777bb4cf72609b9ca8089bf2744afc753" },
                { "sl", "3762000e4ad1580a1049f8e1d7d1c9677964742ff44a07750435e7fe6847330fa4be38a88e824d14aed22d7e2d40ee4fe7636d2dcb6b3fef03686eda1e088c33" },
                { "son", "3240cd415b9a4fbe1d657e9f9f643806160baab4f73c4926ec93501b242be55fc439a945aee9eb57b8e63003c95150c2cd09a27a110903e95229ca378bd6285d" },
                { "sq", "ba2b4f684db446551fe532cf8131020dcf188062ae4c4b2c5b5ab457a21987b2b350e89ff9ea1a2f8a1ac946767c18afcc19e7c70f0db62ef4a6907954e65ea4" },
                { "sr", "6d2a95251a237cdc4653c756c673a4d7e2cefdada177fc109adbed2c2569d15459568ed0f817d925daa726fc984c08c110efb8541752d856972673e49829e697" },
                { "sv-SE", "b5a6cb356f7ea4fb3f88a338bd5d896497a07c03e6823dfac14c1a747509f22e59b4e72424582e08bc3ebf8471e7127525f84eb576fce7f02acae6b3fa1525e7" },
                { "ta", "86e1cd31766614b796d1ec530f304d6064bce53bbf2e854b10afe9bc6bb736488748fabfd7b47e989629c6ea7533e9bc088c382b15d60981e03ac9c3882979a1" },
                { "te", "0a652db8fb2297d08740edbac4917a4311980fb029434a43415491577ab45c3a061660ad44ed65b93fa546e2fa6af715d16bea7f6d40fa0260fa4d8d7e9082fa" },
                { "th", "242dc521deb1c65b15ca4efa4e0cdf3af1d8fc6d3ff94f936203300f56b73eff37d7ca217d7a9bd4f10a6c737a56ff094e96cc4cccd0275d88cffd877c2278f1" },
                { "tl", "994612911a1c2cd29fb5088616701d08a4397a928e596fec4bd121e55305d4857d8c8008846764d80152e31fbcdb3344d8ba5723570e1ee77b5f359aeffe68b1" },
                { "tr", "06cc3c49cdf40316a8526ebafbbfb522ca61eba3b081d1a81582e3983be27f1195397bcf122bd966d20df634c93c3a7e9ffffb903cf1008cba38f804bb486d4c" },
                { "trs", "17f7d598ca18afc7b085ed702b3a8a60fb549ac594eaecf1b3be2e938b664dd1ca2a0068eebbcac6ffeee9361e908e09dcfbb8983d80bde643dd7f94171d33bb" },
                { "uk", "66b230755357e7f6101139f8df031101bb7c5eadc61df5b7d9faa8491d6184e40216d19311f5459a47891e1c232cf43b9f42ca92c332ca5238b37dafc1ca2d53" },
                { "ur", "bf42990736f357302bbba88d91e3f2f8ac88a38483608989de712bdd56e4fab4bfa8bbfc9c70202a1dd81e021c703df084527dbe02e04feaffb3ba78e0a3ec27" },
                { "uz", "0c12e80288a4b035fab09868ad79e4277cdc3556ce5930a87a29a7589c10e213e6c4bbe342b6bd9fd6ee0d795b43bc844068bb35e5652800a50c87497964d55c" },
                { "vi", "7d5f74403b5d69dcc0c90e22e84fa712f80cd9d665c2aa3acc93e15e0ba70fe1699908189a4a909d206a7b1fda5e2f07a2342a62ecf8ce412b2e003171b558c4" },
                { "xh", "1836b6c4df6e41a7ceb3837c36157490a3bbdf4477778dc1705f55bfd27078ed4072950525b6af7710b53537dfd1e42ee39ee369d1f89cab8a87fd65cc0b50b4" },
                { "zh-CN", "c759dba47a0543a59878d09c4b8c71a24008f5cbd6b86cb366b51f622f962cd1d8c2b95221b0fc0f5767c7b8db9eaedd666dffebc0158f38bea4635e9cae9e0e" },
                { "zh-TW", "69ee079f1696b79a200b5028243772ccf71f4667a5426a80bb0fdc582008b14bc91a12bf794fe444bb45845f2a5d67f733c47396789a75f38b8e156820567646" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "637d2ea672941d2fd1ad9f0085326a8c3565ee0eca6dd7d978356e0164e6549dd0902acfa03808be024a0a3560928f5a6e2582b574883f4c32bf8d2095301d05" },
                { "af", "11fe740404ee5b5113d9b8abc550840cfcb32299b9571abc8629034012734b6ecabe34ef2bb3ccd8c09772857c3914aa3922bb76858236f5965b8d02184505cc" },
                { "an", "c9a8bcf9a33c0c8ce99a43111b2cea9cb6d583bfc1c4df3a2c37742816dd26f2992944abe6696a4746b8f6682457e7181d7eaea3224c9b11686d43f97137db65" },
                { "ar", "3faf8f766bd14cda6c40268079741cb194c07370d43672113c9e5e0b6a2d3acbae4c9e7bc82dc2adbbdfd7de3968c55f48e979396510634b4a34e32d5fc471b3" },
                { "ast", "d885351f388248707ee3a092abe1e1654e2acc42dc667398c55674d84214bf4741404b70d67432d8b9561440e515aafacf5a63b607e82786ac4b59806035f1c3" },
                { "az", "82edefeab022205c797a26fa9009e90bae6abc232d36b607f93a59195348e7371d11003ff2cabd2e95724208d56dc6b6c8ca4d89faef5d1eabf9bf25a5c5e6be" },
                { "be", "5b780211555980e61c5be08db2ec07660c8b6d7adf359e82f4166ea4d74cfb3578a66ab602f9c766b54b63ce88802c6f1ce89254abc6546b7bea149521254d4f" },
                { "bg", "5a01fe9628e4488d05ddef3f742ea98f26e8b55ad71a075b6a0174b0c23b147d3f3a6feb0b984eedc6cd00bc35595065af02dde0f3b41f7600360cd2a6b3f6e0" },
                { "bn", "b14c866f80142f4f8640511a8b91aa03759fb5bac87f9c344593c03ad25306ae8c5b425ca9e2f8df14875cccf6d4c057a42b400517777b2e81aebfc34824852a" },
                { "br", "c8c8eb7dea103df557f00a15b105686294bb4509be6c9f432735c4bd558ac2969cbed486e6fa0da4068331901078d4d2d48645a628f6c37a284298317ef9f1bf" },
                { "bs", "8a466ee098cce728b5365a255191a170a77e6b4d0e63d5675af583681d8df2b1fedfc74702e8685604b3d854ed632c02f78ac564675bc9bfb6ee2672040b51a2" },
                { "ca", "659fa4dd085192dfe63eb3aa67d165645b4b6d9fb1a892fec2164983b4bc9c3c244d1f148f22c501fea4762b5792c5a88e52391e95bec03f31679cd450321f00" },
                { "cak", "5168371bbbef62a9fce92ee8cc72c05d8473fd75cacc3848ed3a4a6a8efbb7593be3671cc78a74a57a66b08ff6e8e14162a607ef8a6014aa059d81a8be992a65" },
                { "cs", "3a176109082373041d7d05aab2c3165a80596ac312feb90e3e2768fb0d5dc756680932784eed12d1dec248af5b9f345b0be35a1f6c7112c7b7612163f5697261" },
                { "cy", "3fafba217e2350b4cef5c02575421d3065ba08130900cf7e97c2a446bafc08b84b5929e03c1103959ffe246a59ef02cd884b25ea668cf3d1fb69faa843d416a6" },
                { "da", "3d2d90ff91a235b9c21842a3b56b93d82e978d2f3026b935a226562dbaa35dd3313c02fde32cd8e4945969b72b5431ce67a5feb88f0fba807b47de53fcf46dda" },
                { "de", "7143d8e2ed07404ab2740a6ac7ee7f8a6afb2c4c73e954f005c478e037af00845b5a5046a65e3fe5c4cd0f96b96fac6ddfebe79480d08b0773203d29768464aa" },
                { "dsb", "ad267e262b7b6afbb8de7bacc7e1e0422f766eb305b49d4240091c34355c5a00a154626e0e7e39358b5a6af53b46cea9199091682ca80d700d14ffb4cfd43edf" },
                { "el", "638ed22fdcd6f3196e844597efa8e1a7b3b57171417b4f8c9c5f31fbcf12237fa0c038bd7a180205ab17063237aeb5a1070d0412c9e5f3688e3785c9fb68e334" },
                { "en-CA", "9cf1e053eace7b6169354ec57208f7e72aa88ae8f097ce25df9168bc921a1840ef846b613dee3f165ecf961585909e60ce15e166f513e2d63d12f5550ba4dbe5" },
                { "en-GB", "4b40f4072213a7787ba0916807577ecd2df47232dafd8ce19a5e986c92f89420abd3e383cf8ed2732c45de953e245732975b5ca7215d5c71f52f748d5e0c0c85" },
                { "en-US", "64441be1de275830bf2acb67145bab7dc59227b1f94f7118fe7696403ccd8bab9127042efa50843de206a8997f03d29e2f7215390fac3984a1d0805cc4653d6e" },
                { "eo", "99d2a5e959eaa66c5af7fc8ac2df047ee37dd64896de6f13031b7f476a9d60d47e6e0bef699669ddf599a53be7f05703265b0865d9e709fbf5214bc2e5daecef" },
                { "es-AR", "22b109fa7163d689bf23761500b7a0b9b296b8dd28f00dbdc00c0cc061b35d7c4748b48c9700d9fb9b584e310ad198586739dc079a39eecd66b1e376f9613178" },
                { "es-CL", "49a6c120715db71a499306810e3fc045ab8e38ddd0c6119825003ed7d6fe80a88d11d8696e017e013959e4bf97e6e56e45449295a8c4e4bdaf48ba4a8f22cff8" },
                { "es-ES", "8c4fe33be29e8c38f454c93d6c04a3206ecde26de333b4231e97bdca8c44dfc986abce08d36cd503a9438029bfd1283847ad00acf46cdaf048df00a2792d1691" },
                { "es-MX", "bfe6d1d8163e6e7d5421f571a14565bff66119b9d364f41041c12142d51599567649977bea9f56705f1d2494e852111694510067c3a8816b76125182288841a4" },
                { "et", "3c8b68c357fa47261a39a7082b4bd469f46f2c4422164d739d297701dc4d12b13e1955ef1339f4c8d332c68f3afe709d5b43263747c3c1e7e6b4682eefe206b5" },
                { "eu", "e32fbd78c679210ec290e9413aa02d6b162606abf32467aa3dbe1fa8940e788552870dd96862363fec3a0f38c6971acca00c9ce8776d045b58ec0f880a6f8d5c" },
                { "fa", "fa87447e22b302c5fb83131e0b3fda7803039783257a11044ad932db545822de981a4945289dc35693bdad2662d3c1eeb214bf22937433ac26515f31a7a57f0e" },
                { "ff", "96b5cbb1542d902c367f32026418cee9bbd4c01f9862d3fca8d0686202dbfe0cf79e3174135e8c28be4376488805f2b43beb33802e31a88bf85f96f58eeee65e" },
                { "fi", "40418b8b45fb0a97227fde26ce2ef45646171875a2d7f74813c50763a1d5ac7979eeab8e3d453e2388d47f6a144c0d950faf00c22df7b869be6546f6f8cec1e4" },
                { "fr", "f5b74404a207456801dba16d95686d613938f83d18d8bee74aee9ea2336c3ffcbbea516a875d5de3cb9d07be89a13120448a996251bc911c3653764e66cb291a" },
                { "fy-NL", "49749e9888dca591c9128a326467355d722b638e08591c4b08fafc47e301a477fa417fda065d66ffb57c175252801e5f79f1344e45e982dd40f89ae45b58a4f4" },
                { "ga-IE", "76c0049fb44efa87fdab3f8fd645c7810a76c7367e016354f5a18ca2e2188ccd69994da5bffda4f0971649f6209d82b9036844c3f9b34f3a5eb368ee57e2bd79" },
                { "gd", "53f310ed7d4e3d4619f783721f11f56353da05543f06feeb6caad6dbada7e04a806e4b95a99018f34bfd6e8e1ea1c74b2c6b8eb2e1bd52cb6c2ce6e27ec8db54" },
                { "gl", "09d9e173f9912116405863c49b9cd889b0f92cfe116d18b774eea1aee32d8e8109177a0428d660b242421afa8165fb0540d52669053e07f9320d78ee62258286" },
                { "gn", "6e6a8217f866e9c3fa29d7e2b95a2461e5173a47aac4ed655d721272bb7bae38db3fc9b12def117f414ebf3fbe6a186d26507dca53816e51ea31644186225659" },
                { "gu-IN", "6ed643d8cab03e5537275c50ca02cde36a20cd1b08634d98844e6f7f3f632473401b4ca3e75a272209b80b60dc68e15d23dc9cd356e3426d2ff7833d98309679" },
                { "he", "a5e10ce542fb67f039917ef95b79e0c9e13bd5c9edbacff3bba1678241c5c5ddd48afe78a30e8185096ee6ab0dd687b920f69866a8473fefccbbccb1f094478b" },
                { "hi-IN", "a505157bab9222e6e118fe4b6cf40acd7994a4728bd458fbde522935533146388ab2e09363dc83960eec55488ef541879dff8e3df4e9011d8734c61facc1f05c" },
                { "hr", "ff9e0a3df9118aa5ccd6ccae650ddb7717c5abae54c55d5ca198ec328c0e4864ad784cdbfa93111903aad2b970a0c9828eaaa2f64d78d6d2441857c34e9eb800" },
                { "hsb", "27fa1aa979f4106425fbafd8e5e59805d48d7321d67ca9cb768a413974a323c7c98826e75bc69864e409e1955a91f6db00861d8198f03bfda9d05edc2b92f87c" },
                { "hu", "e84f2e5c696b3e4ae4a381509a17611d7d8e0a5fb87cf68aae1632e99684d921b536115969bda399a8fc6ffe3282821aa4283a770bcc0bf4189109d48a65fd71" },
                { "hy-AM", "08be4be47481e1a04f78fca112236fb8ec7ebde9c5cb0506fdd452c3e8341fb14c71dee1bb214bbaf515ebbd1d0967381145b1fd3e598f6a19826a5535e94af4" },
                { "ia", "f889d2421ee9ca4970ccb1464f8525668eaf90ff07c87ea203968c9fcc25e37d7605c45d14de70b88f9761e76215a815720286f69683dde24660786a17309024" },
                { "id", "1595b58dd27cdad3b41c64fb61d444da42971f3a2953a11364a1ee6a275f473a5f49418ea41f8b1134a4117613b5fe5f39a6477f0b9ee363bd81f2320cefbfef" },
                { "is", "f2df2f13e034ebb88d763f6999ce44053692f992bbbc42714f5e571e0a5a70ebf342b07bdd4d73984df3ad1213cbc8ce9d1e1ceb8cc92c583a14ffa5d6795b80" },
                { "it", "de5b96714b16a9d7af37fceabba7a4d1993d7106a1c7a0ed69cabcf29aabbfa31bfce4f2403cbec7807ca5924d2a2ede8e103a22e94f9dfc9cf8c3ea7152dcfa" },
                { "ja", "4bd07a082e7658456d373148fcbed4d944bc293b3900e94110c20f93ce6845277973474c7210b3803ef4c303aa2e1613f9eae58b2b36a409aba3e404f388fb85" },
                { "ka", "2ba5ff6cb4ef8280948caef13e9f040637c3868faa21b5238b6f798551fd5c9df27fc3751701d5c0a9264bd34847f7ae62217380a5592d5542bcf21f5f673264" },
                { "kab", "ddac809e811d54884148466780b0e8516c1d33b1e7e3c3e78a41971e7678fb4bb04bc9093621993c4d2617a7c0ae2efcde87a9e987d1db2ab402dca2bfefc5b0" },
                { "kk", "9f949463f32152bf8f1a1d41577dac46bd5abf9e2561b5e583190421b1dd2b5544349fc6464a2eedf912cc0c7a2e5fa2772d809d4215db4d31930ae7c5e32848" },
                { "km", "6a676300e86ede8e3dffdf162d0df1fcd66dffb8262b66ef0b2629a8def7a5251753e741dab528c630a93357be353f7082a5e2936c51fa508d5689ee3c537727" },
                { "kn", "397b1294cd704e69fde887d0e64927329131e891f08015894c062198e4d57bd203bf40bc91391f2d077f6e93b1365340a9d3ce939c27ee822df4a7ae06315a7c" },
                { "ko", "f25d99e5258afbfa64cd066d2ba299f5904e1ef18ee7ad4bbf739abce697c3c664340b6a280a4b343e23a8a7e1748e08098713b13bbb3e244b07b2491e8a63ac" },
                { "lij", "c329aced0b3dbd57e11312376ae5b6cc29a5759716123ce450cb17c5fd0f06201968ee270e53132b54aff1fb9d6b801507750b9964859be1741c763dc63bc5cf" },
                { "lt", "77164fde1a61b3f0a6b817cce4054c5fa501637ff62e67ef791efb40f557b670bc43271ce6983ded81112ab77bf1a1fc21b1a82d21d5f3ed02ee0a9f94966d4d" },
                { "lv", "fb8e0b6134bfe50a29976d94e09816450cfcf3c58c4774f3481936759dc1ee682541cb25b804338f24b91fa52017b4457ee73b4a6e673e4473b9c1b286fa9000" },
                { "mk", "b29b0b8539f66cd8d768c324d6fffe7ca866a2063880e4aff401ce221a0c4cf6711b43e40365206d39be1625ba936dce8e55f715377ef827eb5455bd20cb1cd7" },
                { "mr", "63b6f42f444f9d45c947f338f7e9c94c6fc1ee031c68771b3519b7aa74887ce58216992a2d022cfbfa0ff18912eaf0f7e437c66d65b4160a65f0f1429ac0fda8" },
                { "ms", "d34f05d50af9bc79bc6f76a77c041a7be25525b343a7f1f10cc3d5c6b12f1c98de89ccf390463a163c685818713fe3f69076e3ebb3bca695040dfbb27bd16e2e" },
                { "my", "d68b9e1f8fd641e1851ed8aeb0856b2f5ef4e8dadc195325a49f9327a16412866f800acd2181b4b9f8cf5a99216e1ca744047e0a687918740b030d8b2aa5b487" },
                { "nb-NO", "f1cbe68a00804140e0ab2c1f1e0a5c08ac05319bcb853649edf254fc4995d623cf798efd17a29e06d2148df75275db90f3c5920bc333bdb36d730135017739b5" },
                { "ne-NP", "43dd9bc81eeabc0ecf1165d7ee48d270d28c87074daa6bbdf0e5fb866623164ef6509fc1a353e749e67bdd218f9c87442e02f29bce043a25f2b79238f1e9b289" },
                { "nl", "b8c7469edb7327003a993fbc5741f61855f43bbdce3736d081ae5fae8252520d25f7b1c2d6ba8f327380083d15efa4ab5811d4d18badc9e845332ff6b139e599" },
                { "nn-NO", "4e0f4c3c5295040e1ce3f10be6fe7d67dcac0f04545c2ab87ea619e9394d4a3018ffaa3299daa6e49cbd304c2ecf3309ede8bdb248da16810256e34c35c6c21b" },
                { "oc", "34c03fdec5ff3fbb3ad4f506cbd05709ca987e81ba96e16dd65b9880a93753924da49640819eed7a8ca2b84514faacef3022f2cbe92b3d92b87281d7c94d1201" },
                { "pa-IN", "e8dcad89a6afa29f7d1d0fb6b569b5e4051324b9bc78f9133ab7febe28ed8db1ea8070e928bff6b8b0055e6f65be33d4236582dd0f7ae04b221b9c50a5a43cbd" },
                { "pl", "16b1c8f20b2d68d04b2d5f70702fa86f6bc2345760f73ceb10e9431363756531a67efadc4229685c0dbe7c1ceb1f7ca56ce97266137128531bffb429e0ab56e6" },
                { "pt-BR", "20dd3ec5871c0f5f102e91bc4642583513f716c549d3c287f193618238eb47afcee87333af0324351682652f85f71ebfcb39e0731bc5705f8914d4bd78126de2" },
                { "pt-PT", "4dc397b64362e50c523fae22694c2666608fa270c1e4a3a1148346a19ddaf28ca4606bf0d924817765d35b45973507d65ac1d16bb102ab5fdcb45ae6297c0dfe" },
                { "rm", "bb0445bc061669b4d2a0f5d714d519c2b8cb1f97f4277fe7a3fe389caa2c229a56ff4ec083d1a9e5b3b1b395e178600548b94ac467848cf933920b0d317af5d8" },
                { "ro", "0e609d2db15677627e4da52aacfbccb6d535679f0b18115e1d4546345e48d6e62559f15b72778ea643733066f5e3a626bc40cdd4aca3b8e76bc1c9e2328922d1" },
                { "ru", "8915ee1e77c7508730b922ca5cfbd9c77509d8fa26cd5ed761fa269a67702ddef504a4c37b58946485bbfa1d2ffbab9b506b42a8c5d848493f17295ec25c935b" },
                { "si", "fa633e153406476baa4d45412afbd5e4820176100bbf67e5d2f3e4ce63716e81d46fed168bed623319308545b4769c42eba70ee4ec784af020f7e80be3da862e" },
                { "sk", "6a01847f13a3fde345f999be3ece188f985a8573eaf45a4a1cf1ef1c888ec0259e2f0823d71284e004e471fb2ccbbf7d89370cc98136e70a34c030c13ad3a6bb" },
                { "sl", "0ff288a28ebb444ffcc7dd99ba0effcdc353cc01fb155c5a98b1863e2c8b2c1b6452fd2a3874937bcd2f88142bae2024edb2deb9e2af273af6d4a30d6128840d" },
                { "son", "37507fe7fc2aa656cd8f2d2f657c8504d4c2296f386d47a1140ed4f9787aef30f457d7ec22bbfee092820fb17b7c3ec93edcd2b5e99ac4a3533fbc43145b6217" },
                { "sq", "45c1499b63a6d13db907331406e05279e87174428f4276a9224d5844b30b2df5e2f7fc74f53e7dd9d3f49d77844f2a0335ccf1692ee7f267b3517f99524551c6" },
                { "sr", "71deb52edf9ce96e6f39017abdd532eff483e61f8e0bb12ab064c19127556fca48e4a6417fd4c6d503f499dc03970d280c6e294ff05559859683e40face7295c" },
                { "sv-SE", "e1972bc5ed697ffc3c51b3806a2716037d71f29335663442f644f8321c9c28754140bec6daba7a0023f7fc2255d40b71843e4bbd2ca8a56e56dfa4ce384fc7b9" },
                { "ta", "b41f17a5ded3cf350406c050ebaa8e346a245afb6915c8316bd39d5ec2f4e531abcbbcaa6e1bf96312068d2ac3eb5c9c66986ed5fdc01e3ec1bbd29105ceb51e" },
                { "te", "6c216e28055a87348e036ef89516a86f732a42e217632f1947baf8861179149fc0e201b8d574f13e0379af1b5247f73a0b0a286293b5f249f01ee7ce4bd6f12c" },
                { "th", "93bcf0b8fe0087305e5c84303945c597205cf7216098e9ad3419ca3718e11524b41b858ead7644e1b00a9fee401737a3fa1504710f8faeaa0cc7ea1de0c8a40d" },
                { "tl", "564c65a651395bb8d902a1514e7a87c8f39f0ae3dcd16790446345fbc6732cb30ccde66fcff98ffee9610b0fae5e997049057fe1f1d38ca886b019a06afd5896" },
                { "tr", "c2b04db090a8ad5607065bb1c8f3fc8a42ad4423ab62afd1991db7763ac0dd055997a2414d1dddbe47403e58d8b5b74ae3f773da713dd9de3f1ba57b889305bb" },
                { "trs", "34a7513f0e9e7314451aa01df2c11544ec5cec99bcf7da8758b4fbb6f743a449995a8477aaa57252ae377fd94d8d944621541309fd76193c53f02e177b3db91d" },
                { "uk", "6d96875a3fe3458b79f3abc63bc6ad6be01ba228a91fa34dbf910d05d878c11f1ef72d69584c4fabaf2df92052be5e08f56bd660066cad37ea57395337fd75bf" },
                { "ur", "47d14388a04eb3362e1a90278918249a428c92659d243e5cdb9ae963a48811014893578ef8ee466f2d658e7107f3d010f01e6f61b639f060908fb859ab24bb37" },
                { "uz", "85f4a0a81eaf691e96bbfa16a5d2c1f2d82eedf73f35c6134f937bb5acb112e379131cfd17a5e188983e9b7b90a34bf5cb28a6e5f1ba74b99b84e377d55ac014" },
                { "vi", "d9c5fa78f531d600b5ca6ad17c955abfbc9c1341e454917fa99a7eecf1bfa40a79f1d3d8cf0db0aca6313c62555669f81c39b80c9140acadd95ea91d96dd36a8" },
                { "xh", "f20d03cf2fdc1f9c383f7b3b9b0c15633404080375658feb9fbdf4c965535fb820239660e199d7c9b30ffcb5fcad5292d8e9637f0bf507e6cd32da980d589161" },
                { "zh-CN", "5f2d2b5f445e973411be2301a1cd286822f1b9589e1603e82043c82dddf12a8f72c102206c16990864c7bab9e489b4add753b0c739b77809d23fe4d0499683f9" },
                { "zh-TW", "1a0a9bde639137ffda5e110435e8e1a9108665c46e9b4acf81ebd90e58abd9795c3c90b4e5eed32d7ba5a9fc139c504195410e9396aab65462c28166eb29099f" }
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
            const string knownVersion = "78.9.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successfull.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
    } // class
} // namespace
