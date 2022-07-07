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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.0.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "d19b30ce66dcb9a7ddf6ea8586312b1ac4e97c8e2163c42f284e045759579be9f1a2836b68707662d12cfdbcec171c43be1de95106d634c63fd63000ba3e31fa" },
                { "ar", "df09a2f251b3c8d6aa4dde1ef18b4e5f5acd8d06d395fa9e04212924c0efdb8c51f1e03760f3b9998d9b61d9df22557696e109deb0930f9ec6ddf35b8a9bcaae" },
                { "ast", "6583116936d0a137ea5ef96b70d9da1717abd168c025761400f145af50a62c46b023ef803c9519edc958df373fa11349ae056aaa5ca4da5c0c10f9241777509a" },
                { "be", "57921d598ef1c993e8685a27d2c66549b0fc859e3e8e0e9436d7da24d66a251c6013c01f809333cf174d7ebf22ce4c71dc84fe2a61249da178d93e1d619f6649" },
                { "bg", "54f5faa4df19d8134d0ad261d4cadd36db82475e21067556e2970a29454a835fbecf53faf647e21fff42a66ab907e12c0c1851e37c9f00bf50139c4205160069" },
                { "br", "7ef5b9e9b8dc5a1f4f86e9988fe3c3e8c83582fb034b9f8331685a977144f7e8bc1c299f36659029d2f2b4164b1377ec946090914abad2e1cf6835879e668d04" },
                { "ca", "25b30bf26bc4c56563113a2e6879ba354b62177a0054bd3130ab7a760793f6b4d4ce43475c3a5c7790256390ae3562d309d9e46927a5b2befc3733df19fab3cb" },
                { "cak", "29b698672473a28e09eecc51e7f74ee35f343fa45a780559ae6091b1329ad9ca519612dda8857426b3dbaf3f397a16f811628d46ffe64612ede33cdb878698f9" },
                { "cs", "ff54bfffcf8ec5f6d99ff7ea38a3dc0fa8396069b7ade60f7f86dedf2edc6b727c5463142b8833d219acab2bb2aa0e3e8dd46fa0636d6a0a15eee39da8e73cd0" },
                { "cy", "d497a78531c942711f927cba8c158522f48b32cd8a8f2cf5b7e0ec989bcef7eb4fbb6724ef29dc71cf55ff8df5715ecd442171a3f5ca192229011aeeffd9a0ca" },
                { "da", "6bbc7b415041b3c779b0f33a55dabbf1e5bcb26f94c349de5b1a0738fd4070b4cd04076f6fbc4813171d17e8a0d0273f8d50485acd5e8db643df34e662702bfd" },
                { "de", "7c73808ea00f5ba5c8d7b9814367a19892f44617d1bc719641e01b5c2698ddc3082f5b105c2e07c4de7563a43b08a6d32b233109a2c84d9c31105fe897e63f40" },
                { "dsb", "0cc334aa212cb793ee4a7ff2e72a9e313aaaf78b628adf1d8e52b1ae211a201d26fefa692ed7bc4a4209e033b09a0b7a125db44a1d3820ed81d7da687d5632e8" },
                { "el", "3a8abfddf62daa07ebe8c3c61be203d2ad0554483f09c830e11730148fdf63d59c353ebfc00560da99d720ae901112f0f4f1416aeb1382f5a2e2d057ea51e431" },
                { "en-CA", "82b4b439da92cb4b294f3744dc4cb9b91c7187e6924f738ee9ded007b9c5a9d9b6664cf21709764cd9411e3f1d499fc455f2cdea245a4a9874324c666720ae56" },
                { "en-GB", "978a134315399991c67ee032075abbb16708563fa41f1bb5f088256915dbb2b2aad8d10e7a6e49a8cf760ca07dae072a44b7698e9e9ccedcfd9a2e96a5330151" },
                { "en-US", "a44fe0872b893bcab79804f7d0c82b8d48536983e806b9987aad0f71ad162b3cccae6a3356175a4702952f94e2d9a9766910c4731bfb195c619e2629f3758d37" },
                { "es-AR", "c4111d361ad06354dc480da3d0f0415ea01e32d1ae93f187e40155f95f29bc721991cf5e45b1588f248b1fa434b3495dbe6ba727bf76250dc83c12f3aa76ee62" },
                { "es-ES", "d753cc07cb161bfb225a741326da7a0cac839b18b88c20da4b0f371d5af97f01f1ede7e3824895100b28b9b3c136eec161d4255fdc8c95f671de2885e8e43117" },
                { "es-MX", "eb5204c07adffea8fbe607b957f44d52c4dc48c9fa7d1d6d4e43e0c489e1ad04d9bc7bf4d8f6f2d34e1a49ff4004cafbef4b9f23e4450529f00721629431cc62" },
                { "et", "75b6898a67d6580ef4e312b0aee6f5d144a149fa523eca7dc14f68cc3ec319308691c12f25ef1d54c0c1be3d1735cf4028acf4dd1ea0b0e5d4750d12e63f7276" },
                { "eu", "720b752e42aa9c623cca941b76194cb247bb7dc58662b2e834bd93c29ab439f2ea2eb96ae31adb9853b148df3b53c5c28f0cf7126fde794fdb044555fca34985" },
                { "fi", "46d4617ff33400c3763e0b58b0a4ec3f0e67a46ea2eecf559309e38babd6c4e13e921567f8ac7f8f78c6819812ce9dbacaf8ae62c65dc42083c628a71bc621e6" },
                { "fr", "ec3de15176a5bc43d154aa970e31349c8a6f39a5d5cd21886485029c2e22dcab62d86c885b7527d3298e412b332d288fd37f36d88ae98b0304bcc2e1cc1f54a4" },
                { "fy-NL", "9fbb76e7f612517d39b0e08adef43cdeff97b975e22f735a304d85be8b6a8af1ccfee8b787cf322d0f8029c3568ba251a414140a3d05308e3b381082a843718d" },
                { "ga-IE", "5ee3c4806446969e73d0ca261a845ffbec1fa07b4a1d7d5f6dc0459f26422f837d7fe2f70f8655ba8c6d3b3cd5ab781226e61361772f993f7167b566d4fff817" },
                { "gd", "2175a305b2f093d753aca81e55b5c2db1de2db140d9b426285921bb54106ee9474273f5512c534175cdb08df4a5d4ec7b32a36a5c3fb79aa24e46fd9ed6de6ab" },
                { "gl", "3aca759159acd51fc575b2bc6c74ffca812e9f2317bbb9ac5e2d70352983905c0e6e767e3d8f5e1592039b77ac022ae759b6d5bbedb9faf4f220c1c2bd16df6a" },
                { "he", "e825409c1cd85fbf823ae160cc45c1ae31bdaddb644b705559cffc264cdfec895e86aea69f1807794be37eec0da282462a768bcc1a88a70951e75390f38682bc" },
                { "hr", "1c1de941f75c6f335060b5c8b0083b7741785f90f6ef23b79c053941c15068a0cb3a816159ad30b9b32dc419c0fe576980c87c5ad611e74cc3af843fbb1d2ce0" },
                { "hsb", "a33851262e8e64ef3cb03715d61ec01c13687b87c6a5f43080db2a2578e8d953f2ffee5e379ae7104875acee24971d3783d116342a324ab35e19d43cc7e4b9e1" },
                { "hu", "774adf3cea29b9aa2ca4bfc98ef624f4cbf92d79ea6c0db4b8d6585c380e08931ce899c45aa7a1191c3dfd827ae943b007e8487ec849ba4d4cb9e55fb60e3379" },
                { "hy-AM", "0e5db693de5b3eaf0488ac0cf6c23621b33449bb3b24d61ecff5cb55da804eb9095a453caa644f7932c26f5658c415aacc54440fe936ded4dd082863acaf6ed3" },
                { "id", "164dad605d7510ff7161f7bbbd15591f9afc9fe70e993954dfb0013ad5bdc9b380ae22d48693c742a55c5981c01e6fe611acf239f2a06ce1f6360dd81e09b95b" },
                { "is", "ee68a92c1add87679133464927a0e06c9a45ac139a4972d4486c963878de98ca1398356450130bfc6089a662c66ed3d1b9358d5be79bdc3a7011347838640407" },
                { "it", "697ebadfb1a3e2dca154c6923916465dccb95e291f860f3250a5b67bd131d679414315e93c2085efbd28dc141a78371e913018354029e4d479bc555c57ecc47f" },
                { "ja", "50d506822dbb1a260fcc52167fe25f48cac3ca59b62357a42f1ba6e55b6482867afa57a65f337856db6492a86a51c99d51c6487c96f87c00bd160a4755af2ca9" },
                { "ka", "e0d2729e4193142bb4ee832e71117961f0ff77b0b8b93e3afd64b57af9a15f4c1fccce3f7dd3bdac5b44fe3a1b411d904b35329e4cc6b06c330cf893af6ab20c" },
                { "kab", "b3eca6dcd7e71f04fde670463f11e134d6ff8c75d3b9d454a7df15cac81fd3f3e0fea362e254de5c554ce507d6b1441780e23e5ad28a84a25922f39b1adc8ea3" },
                { "kk", "5971adcc2c16940994abc1e17fa91eee443c0fc45069f80576cbfe35037793c01b634eefb8ed01c29f92d3dd2c96ba1b8e3c60031ce708c6d65395ced1c965da" },
                { "ko", "8979f0772fe2e599c7a26e7941f7d71ddbb0e9700e0969bd6a441cd4725c73a029ae4254d79d30c6837f060e9e1d804879a091ba853217fae31816997ff15d40" },
                { "lt", "8e358a480ace8160cbe737a1895e6ba0c64afdb074e7bfa761395937b753064bd21c68147a01baa413fb9f808ad2c10b12c8605f00209c958ed4ec79987e2ddb" },
                { "lv", "e1f9150f1a3970b81d46d5c6a29e99480bab43148b1e16a49c6df50acbdc5f4b471524af6dea699ba6c6145774470686160926fc9d360416578c9c37de9d4007" },
                { "ms", "66b3f94ef2c60275c00f8041b000422d456f8dec1de027ec612b8061346ae617f1002677f87327ffd46f307ca5c8d822b00a309b36142fc197ae933447a923b4" },
                { "nb-NO", "adc069d415e36fef3c0edb442553b3050bcd7ead0659e0b7903aee4a736b5a9fc51cd2cae178a491995d9ef9d61f5a72358634fc6c4cf1a540458d32f33023c0" },
                { "nl", "ad058c7f0343a4996d02846e35474000ebdfb03df1513425e0c7e9ac16a373a522820ebd2de08bb6cb80d58ea8f268de1a1ad957e1867f8515931460cf8b498d" },
                { "nn-NO", "f385cfcd27d0d2effb1dc9450dd0e559413a45e010be1b51a769f3d7a109b24fb4310486b026dfada0e15c64253089d74e46538f3d217ce1419a123fc9e2f8f5" },
                { "pa-IN", "04ed597ff1156c1027e46ee0539847165edc7912a733a051c2ce88199b47d9c4d9373eeaaf9147b745face13b464e36b85d5c92e1d52c7f78e901ec9301579dc" },
                { "pl", "ec1bc3ebd0072926807600f34cf41b4255f16e477a73b8364919e9a7e83c4281d39424a633c375fa7c71b44f3ce4034607df4aed24de6a702f6d4d2c342bb59f" },
                { "pt-BR", "39e74def394b08df5ff2141baaa84aa322e72aa0dbdb92617ce4be1fd5c41ac207d712b7883b0d1664c89eaedef1ef0dd219517f35b2f7916125a40476f82d37" },
                { "pt-PT", "b0558d4493a30269e4de70d5d0c05ca652a3bd8c37ef7d2a4fe2d362c7c98c88151c78b1722b1d68dad160cd9870ae1a53a9275551fc539f04092a0fec07e614" },
                { "rm", "eb25ff7ba3a075a9d6b1d2eb6c3643a119d7709c981a848d8f4987ae700c10589f444c17d2f32da2f277832ecfd18999054f4448df2ee52a70a2f545e1d04dab" },
                { "ro", "2142f82c7a6776762b9b32a5c4e7fd27de19a4ba577410f688a226d734b6aa00c5d03a82078bc52799389da1283db10d0db11664ac79afad062f302df24725e0" },
                { "ru", "aab395cff39126212e8b929b8ea6e712ad8195aa0fe66c46fb31c30ead7aec1d86d99c7c1867150ae1d18f3b2b77bb254f61794cbedb6ca2dd368da84cbabfcc" },
                { "sk", "8ba1414cd6046318f07f8a3fd515063d73efa352f3537192875c19be362d6b7adda36c8fc7d7143581b069d0981bc7946a910c95c5a52fd967048bda4f6aa96e" },
                { "sl", "464818061cd1609675209e3283908487339f58ed42c1386df47bb57af96334f37a78b33c9882e0477b4833b54d040acfcc059c068d0cf67d874d7acdd2a7cbbb" },
                { "sq", "11388a3b4c8a4bf490c4f1b263396148c8caa14c43009c5903f9bbfcaaa01b62055a62b627d7cddabe2b96aba1e20df90d745a43c79eba1a034bf1ddbb2f0871" },
                { "sr", "4d7d681547247e785477485ee47d417d737bfbc87a08548885e6d253714f74a3e4377ca3683748c976953893f905661946600ba6dca156dbedee9152b564b6d5" },
                { "sv-SE", "3e7623be875dcea5c55e852350bc95286832acc36e3b8fc6a1ce5f3e33a6236846aa0212434e1a69e00839ce4859fad6424413028f57334813aad58e10a9c61e" },
                { "th", "82013d1ca682793760426d1dc1b5d8feefecda47076d1be933c16a653e5fc8a33fc75b0306ec8169f2f88d3f32bcc35c89b7847853fe99b37672a0ae80a4d4fa" },
                { "tr", "d0d52128de82f5dfa90332e57d1ddf2352681d8eb638a522910efc209634e48a5911b22e0af36d7589ce0d8c4530deb8829bdadaaa385cac9fd494c6aa61158a" },
                { "uk", "5a0a514df530747f6b6e4d424793ec028c5ccd116c7b16411e9d038aae16ea2d357d15bdc26c16c1d420fafb4ef19b7a589757813c93666687cbae396343f2dd" },
                { "uz", "7474fb5ff57c930d6534de7fd2405354881e11280d119f6de2f34e46ed2026fb55ac0926ed80e7e2957bbb98174ffd25891e76485544b1d10a07aba20b31671d" },
                { "vi", "3f098bca25a3a4e2770e50b2a9b6c0ec1b1d106c7f122f6879d678e51cc432d52eb482021982c1c98e7cb1bbc2d4a2c21b451f8b5f802b47fc805c5b02a3a655" },
                { "zh-CN", "0f3d2631b47d0f91244e2e1bf2df007e126c8207f625be962995d4f5d829522da4fc8274315fe1d22a28a51dceee9d34a8b8eacfb36f97762a6b3a50b1b027bc" },
                { "zh-TW", "7ccb87fbcdacd61d1f72901e92af33ad8dc22e6925f88912e25ce19d7255306f7386e35b3ae94ca11ce075655607d52f65b318cef442c1a990883fd925e6653c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.0.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "72862bb7d667a0ca2e95fed35b976e01b90d65c418d2a087e9760339cfaa3ab76fbcc3a9d9816c23effb1d59453f356dcfb6d42eb5790a8b16b5ed3155ffee26" },
                { "ar", "469085e53193412e4bf1c026f49f1b561403d876f9efa361614a11a00320ad25e0be42de716c43af251e225b5afb17f362885cf1195d3bc3cd2ef8af2b8f56f5" },
                { "ast", "aad33d55ecd1119738f6b4240c93d4e73c2ca0668b5d0568e46acdbbf9cfad72d8eacf17f7b2ed3a935a677e343b573d1f73d87935f7b1859abee374e3a97476" },
                { "be", "746cfb16b6b622e3128eb6a4dbcfb3dd70179accb3d6a79d9430db04188d29d4c5bda67bf40c592d59784034d01109248957a96b4cc74e9f1da50ed96990dd38" },
                { "bg", "940c4b84ea9a1386225a948d206985bc45d0804aab6f474337a29c0e16a11167ba1ace21ef91c540210cea1b87921e6f2e3663a350fcc7ca35ae1152dfbf9e0e" },
                { "br", "f741b6ec22669845e26e1e1de7d928b172956136564e3e3a84ca50f3f58730d2c64bc307caee605cf795c397618e8f41b7bc7f3d684364fe178bfecd545ea59a" },
                { "ca", "4a28a344d4d0784a900e8f4ee5fe13b9d3c465fec09b1622e07701e9d2d0e104249f0b6c096720fd3a763470774c629da686589214adf84d33fd546be0852f7f" },
                { "cak", "670547adc3b4b54637c95a176fb3d5117b01665e9705401f7c6a337d0a92b378394d9e943f5185ddb13643d51e075ab04b02e9fc422b38cf831e6049f7b7e393" },
                { "cs", "ec8281fd74c6b6eb3b0a5ba03142abc6f60b583213de6759ab648ee93291907070281720244155340309b854c2a68f81a3a5a9e80588d2ae06bc3d6170a23e78" },
                { "cy", "22abb569c89f5fe157bbc8015d032c90f97dbdf60b3ce41c7ce1193859bfefb05161cf56047d24d1f9c5bc39a45ba9acc11b3adbb470f3ce3c6bcbd57fc6f9d6" },
                { "da", "471ec4c81f9ef1fac9dbfe59d002f123867e173e7db305745f3e2d46f1b8f83e8b614bfa79c317a435fc568a2485cd49cf16ac29732c3fba15e2ffba7605e9a6" },
                { "de", "032d2a791e1f77aecd1500893148aa8953559985fc2dc33edf8842341f2baa49070d681f9a94e44b6192050a0e5d548309fba49c514dbbd2d77d1f514ad395e9" },
                { "dsb", "115d2f42aa00526c102cd8c5f107a91aebb8dc2475a1e9f5c57b44a1ae8bd357467f9858640ead7bf5845a19a778cbab3af96bb18da68f1565b4cdeb9f026c11" },
                { "el", "28848da6870ef9c2f3e932565b76be00e085e8fbcc840a809fd9dfd4050954a7a99c56e205fd461d489cb42dce98ccc3585bc5f1a349d973cd4845489567aff3" },
                { "en-CA", "4eb0143764a5972ba248a3f4d6fa0e86f490cc06ac91c61e244420e7ebc6459972836a57a5b3592012c4fc98d299625a57afe16b940079e76821ab4efa6ebe70" },
                { "en-GB", "4c92a06750f7be0f6de56135983e58bd993fc734f1b598ce3718f453a4829a55c2739a067bc14df945bfa751bea7f3fcd9134eb5d2ffa8286739cf688566ec90" },
                { "en-US", "6c4abcd0bbb81ec74cc6e8bca05883cc51cf9d478acbce0fe77bb77d20e2757afa2c6d3e40ae363f8448d8d440059de298cb3da256064814647b38ce6b16be82" },
                { "es-AR", "886c236ee08b8c9f5674bb2c384af594bec1764e4ed552cd6197afa71c6ee12f7ccc242c0720a69d6471f8d16a41f3e0435703593ed4f04431f0817539e2b397" },
                { "es-ES", "4f0cc78693348722a4bccda911fdbb6ec5e97709ad2460a687d4a8cb239248a5fc17bb5b86c2e772c76822f10fd8a6e9a66caa7571a0ec94b461631c07744121" },
                { "es-MX", "7e7b48378294f9d31b7cdf22330baabc913ab965c2652f56ebd2998c0e51080dba0f0cd1e044040a11acce800144a15989e4904eb461ac06400d2efdcde81fbf" },
                { "et", "b6e2f2576dbd75f1a0e056c459d6a1a1d21c7a5e14609c4eecbfd925050a14606b108a841dd6d669536a37314c37b7a136d18bae1b4d5f37ceb5933cd2190633" },
                { "eu", "0c8d1aa97344390d1d1081e59f35cd43246f76f4a5b0995d30c0b6edc863cab9ab9416165dcf1e0c265369ffa1042561353018a69da745dee7c0b59f0f634419" },
                { "fi", "c74b5a5d73c9fc393cdbf98b3c313b0f25486605386b93634eafd0f2d653061acde899eaf6212cabb994f57b055b7d737b20aa0f84372e7f4d31ee19d37e1030" },
                { "fr", "da78e7a1f94d0d2b22e11ab3c887dbc10bddf3303814f87c20e94a95ee3843eeafc1198296f77abc939d0dac064af2d8866e53003f130380f82c54d2fb96cc9f" },
                { "fy-NL", "687b1f795efeaadb0087dcbef20fa0fcfb6682e82208aa65f60d7b05e6918d85b93a763be42d344de40252ed3df7ec5e75119fdeb366452c9a6134421135719d" },
                { "ga-IE", "646321b272bed9f82795c02cd2de64164dd4801ca5c88900540a15814c0e3083c2e2bad82c17d0026f670bf63ab2b3e78f4b06b375a283173870410bae268923" },
                { "gd", "749252349009d507772c1d068011b48f8cb4502894ce4eab3850886fcabdbb7487f18fabf9fc839bf89c825e136668928ea14b97ce3f769585eab7ab8e62d167" },
                { "gl", "c52eaeb89a92fe56da97143491f9d010b88532ddc9e39faa7c9ca6ea042cb4a573ac6da94ee022cd4e6497434305cadd4f55a43eb59a4bc7bf9140c5d7fc1f39" },
                { "he", "eeb581b59a38007b00125b5a0978e0e728d0662a358c7c127149741f18524d09b7979197bbedfeb83736b609544e3caa0e1162ee6dfadb08ec4a8f81b4e3bac4" },
                { "hr", "53c03563015000b52f6f5149a1dfe6465d7b54b097abe3cc37903c1fcd50d267c4e6aec70def7e4bbf08a9c3ea1c90ce06cea32c2143773147e5723b3ee0de85" },
                { "hsb", "05184cff278c0f76fb9776a77a35ffa9bceb6992c3988384a0e933a3a5bf16843c6d4ad0854e976e3dcb68b6364aa02f1ba5c54f376511dec0d2e9e61157d5d0" },
                { "hu", "2175b457dbe3d083d82871cf5035f29c31067452bf219dc5b9b283abac034511afdafcc3c3d4e2ead10ec81c37a3a14b26e370f0f3b85dd86151a0b7a49b2159" },
                { "hy-AM", "1e875cb079ad5e1dc9304f86fc24127fc3d475572608145a3acbc5f6232118fdfddd2fa7e778fe46825a9290f0a01d76a59a831ddb5307d5ebaabaef54e597cb" },
                { "id", "5dbb80a8ae587ae169d3873bf1c0ae93b0e80a5797c147189c96f68a60f4f4a9fa305c7564c4e20826a129d207f5bbe426bbdffd74464c9897cd5db747ae5af0" },
                { "is", "a08e482bdf2cc57b95ef96014b318dd66beec3303d30374c625497c09992e667449115f0ae7db8ca7c083277912e6de9928a5a8e61440063291d4ed2828eb38d" },
                { "it", "a345d53fcd63383fdc82fad1cffbbdae18fd8d036fc4ff166af776cac63969de1b23a4e7da048864ea20f49e5a71d915d9b284129ead63e4dd5be64a6a5e2f9f" },
                { "ja", "c211e6bde5ecaa35110729a03f30fac77be2f65876307c55f5c0bad93ed553a2e306f3b76efa1540911ba86c7350751725d640f68834d158c1f7feeec596e0f1" },
                { "ka", "2eaa1ba40ef7d562b25e80c71816eb7e18c7052e613bb6561a94a24d7649b12f7c77508b82a2bbce41f52d10c439f320ead4927e265092c38c02189f4c19caec" },
                { "kab", "fd66ab5d11470ba5f49ce994ce51f0fbf26129ff7bbb3b30a9f5e4d59ba0e68ba172f8355494e65592576fa0342b5459f858b15bdde0c2f6e692fbd2b1a6a529" },
                { "kk", "aa4c970becb1fd821a4730c28d81f3958a09e2dacc5166f06b2b1558bca22c8264422837432eb0a23a6861121adcbc4584d1e5d99c02a632a1bb59699745be7b" },
                { "ko", "428d675416f07fb9936424b5a68930466d1397c7a77905319b1ba010f8c914bbff965f218ef8320a0ac183d927a9de071bf426542c6b418a620a424fbb95f2e9" },
                { "lt", "dcef5bd20911cc8a52dddf95c5a82f14f1c7bcbb9305afbc258ebb64a841205d42c94bb3185b41dbc97167e7ec952d4dc205f5ee5e92cb6a7b69c10debb4cc42" },
                { "lv", "4a91b72aca709c383923500d63d4ed0ab39352b32934a485370f97e49a8685348f8a08952ea85c9310be9cc8657c22ec072a999a5d2ff8e3e6e8caef621d010a" },
                { "ms", "9266c633fcbdcf4158b82301f5b4aa40ff6ee93212eeaa842edf01637b8d5c318adc28d8281fd4990f89f8800d5198373e59b714cd7a0c06deab849f164b2de9" },
                { "nb-NO", "ad80a0f4b2ac61130b693cd3e8832898ec33e2678e27967983705ef721a0e1b64f079a2978650b8717b7d62ab414c74cc05ec9695fbbbc5f6641cd87c0586fe2" },
                { "nl", "f078e059fa93eb751255451499b9865bc5d7c6bfa4cb75308de3fe544df2b4b01e639943cc013363b05f0c3325001777cd18bb2f486f2948f90961e511a6b9ab" },
                { "nn-NO", "2305e9258934cdb343cfef7abe9b8e7bed9cbb74ff63ea1cfc6447066d9fca087fc6d986c9aa073ba2ad92709242dc2a8b1f6888e89897304cec9f8743ad5483" },
                { "pa-IN", "2d75ee87b3ef7e2aef6f9aa97fd15d3f8b89a517671fdca47ebf762284c19e6ffdede2d57b26173ed38a4d8f1a2370f8cb2655194498e4d06a0fd609e3a998b7" },
                { "pl", "bc5cf3af2397a56b6f24948a38c285438c3ce3eeedc547913c690aea1e310fb76148769d7ee8038dc01744284dec13834ca77022dd13a2e0bd9261051d8c7241" },
                { "pt-BR", "9de37075195cd7567408615d8cd52bb79e60a5f34918acc589f772689163a488a251d6c19992dfe62f74683401b4d2a67ec1326024e25d4b246e0741aac47330" },
                { "pt-PT", "5fe0b8acc81bb4be001b9b85960003fc72f8c749181c48415f56cb3cbae01382e0440f0e2374934c55ad6811f5f2ba6f07a193548da9dbb402a3c43dc045d28c" },
                { "rm", "22a85f4833d59031657e464c7260a9d4b11decd646229b6c6c002d21f2a591cebf1c870f5dd86e0010dd448009ef536c1c9597e578597ae9fd2ca39cb8eca89f" },
                { "ro", "bae59497e0a3961961df951f0fd47988ab95637d27738c190dbc7abbc38372324c8686cdf2557c94c0d83dcb00de85598e618bc41fbe2c4f9ee67aed8d22c89e" },
                { "ru", "a99e0390bd95b250850684d7d102489d82a938742a37c629d2740da5da9cce96ba3bdaf83c00e1e225a76bc6d7c67b0d5e541a69ba155c67b225c2b7f9c701b9" },
                { "sk", "422c3fddb27834d3481fdb5550a6b18bbcb026af5dc62bd7f2733660afbac3acd628c4c5058e9c8cdc3ccb2f9b9b49c0b53eac5a74db449903c37f1e76d90d84" },
                { "sl", "f597d0e2f1a6bcde05dfa72e8e360443e5f398a3931284672dbb70c2f127fe3c47f1c179356261a30bdfe8d20178cc3613f506c14b4f8287ae0c05900e0c72d0" },
                { "sq", "048517b87345c6a62a2afc938666b475792b4047e41e406731b82cbb23f11de6d4c553c4691393d085b154d0aabd2ebe93d793e871389d41319ca8a535cb5eec" },
                { "sr", "f8f4acfb3559119062cc4fb359e4b54770c8201f1a93b9854cd650af7f9e4d78254a340ac514aad8f1cc79ec30fb51495d2589c172c8c92e582d77f1119b07bf" },
                { "sv-SE", "652912e63617e036b6df2b5fa65d1aeb23921867c0622f3c47e208f19df2925289a6f8ac06c2b4cab65c5dd2cb4e362ef09194c21035b0f9341fdbfac9fd37f6" },
                { "th", "9c54815bfe4255e7c5b5160d8640c2aaa218557295f06ef2ee0d62a3602029ee9f09717e26f676275dfa9011faca0467efc571de18e7f09be852c4d2f52ecff1" },
                { "tr", "05f686055826b3b9f5a61f7c88b7a5e7b14d41da30d35bd60d3fa63cacce7d08dbd65f03fc1f10283523a3d37c0e89ac36d02e0eb78670d6d4d334f785d6d9df" },
                { "uk", "2f05d1ade7b8ef4e00140f82859de7bb1428714a1136e31b52ac1b3c24101e64758406112a7ce906682f05bdd6ab39236d61de9fe547293ff3e262d554c4487f" },
                { "uz", "e65e4a9b598797a521d11e7aaadc442a52ffe8544c9dfdcafd6fb2c5a902a96f0edbaf5d39e29094b48f337066ba1f7ebfed2f9227b3180c3b49be5de92a4c34" },
                { "vi", "9e4632267d3f8d9f04fc2944191f5d7ee10f3fa3ad997bf153c5c5fe5827e1c2e48319fa4c113fb3218b57ea18bf93d2e081cff2cbd5fa74fba306c2c8c6eea8" },
                { "zh-CN", "e872291bf1baaabbd47d796642a2b1b175ddf3a9eb994f9b77ca69f2777429bf0a46f8d6a25c4008cb6ef972394b77e77973f1e94b4561ee28991ec4ff84a7ce" },
                { "zh-TW", "a819b3a95c79c315ba22433ba952b2390c1cb9b75cdf2eeeb6cd4e66c9fdfb6c1a92003f07d592f53d4ede19718aa3eb32db3580fe9a80a6b12715201de90112" }
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
            const string version = "102.0.1";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
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
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
                string currentVersion = matchVersion.Value;
                
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
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
        /// Determines whether or not a separate process must be run before the update.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
