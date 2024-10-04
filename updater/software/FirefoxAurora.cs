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
        private const string currentVersion = "132.0b3";

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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ee38af1fc60ce29d21f470050bdd7d14de41b982be3cd7db21430c91d23b5472446df5679b228e71bd700a99245bd6c484b6c693b80888d0ad3090b707da656a" },
                { "af", "9d90e1713d2663cbe76a366ff44f8c93e4313163dab4eaeae3c7d511b7d34d9a5240fab5bc9cc22c9cbfd17bbbc699b6524db16ee025c53c844ad6384d9ff94d" },
                { "an", "46ca83542ff48190290407662ed5c28cfbf1cbebeab91be22bfe9b5eb9e7c4083f1786663af8e380e8740c1599c1fbc4138bb780e8ec83e8a940848a08153a2e" },
                { "ar", "f26b70a83e2a2c0e47fc05c0eddfefdc4379984ccfd5037c7e5ec7f4c0c0bd0373d10d2a3f9c76480a697f05869c380eda109772ed57c081287912ce5084857c" },
                { "ast", "77f288b69a890d6821724d489a809176b873a5674d25b2d00e3f5c449d88593298350fd15b7dc3ab6673e36d673ede51c5fed88df642c7147e2dd22b18c72698" },
                { "az", "90bd0c8477d40c88c05575281c288645bcf566b6921f8a468db8217fe9bbb3d74ec21ecbfe851bd562bc7e1510f39ef6c131850da08f6480dcfff5b3c3af497f" },
                { "be", "7ebcdaa88db082236d918caa82c351d9a600d14ae99542734e733f174a04cf0135d38927410dd306cc58a97b0fee8be715b1d5abe541484ef314357a52c966df" },
                { "bg", "d5fb225c13b08a2e6b574af5868b49b6d49bb959d76f4c0f2db23b9b1e3cd727f3da27ffcd240b8e468fbf4bb88801bb5181e6e22e7cd004821aab64d8f28e72" },
                { "bn", "af27fbe38266b2b49cfa5ddf5b1af789f73599476f3a9d27e0439d4e55444a51f8aa96883234884e89b38cecf121470b22bc9b28a6c63f0e88cbedd412a805fa" },
                { "br", "ced7ee409c9d355830fb422c996fefde3d39951418c844860cbc887ab5f635d7e452c52c8d0c5d64de20feacbffe24a02e79b401b57ee8738854329bb3c8832e" },
                { "bs", "1d43e5344fe9c3b41b8df8cb7d845c3a5feaa30f8f6f9b80075b075656651a85c0a5cba1ab8563a5dd1d3d0b706feb27d2f743613a8386353ef35dd71b1d2be0" },
                { "ca", "4740783df1c7621ead9d91ed55f56a43d972997c69ef8da265eb7e51177462bd8b2d07d2cfa535c0e052b166ddd5b8c552febc550fb59bfd36763ae192f46d2c" },
                { "cak", "32399721b9d426a7341e5a3fac191038834395a3c2af4941d3ea3514b73e6f1e5c7e5dd7439f7af6fc8eb78d033515de9f504533b1e87656bf12022adad0c215" },
                { "cs", "a19b1aaef03542e5228c01f068ab697bd6ed621be7f29362fe8e217ab3cfd5e271d3ff25e543ff7f4f9914c1ee761bff4094a80378b3c21e7c8d2cbc39208491" },
                { "cy", "94db540bebc55a7c7c300e25afe1e4986cb74922c0ec4ff999b1cba2193de8d364f8fe8056719d43b27ff12ea192d38361adeaf375fb8a8ec8d2181256a9881f" },
                { "da", "e4c96bd307c207c394c35af8ffd46394fb9469598214f3fc557059122625e9ff4caba381d468d9ada48bb6d7a497930f86e1c07bf1fb3265f85e5e3100710a0a" },
                { "de", "a74e6970f0a5d0ed9f2f4a46556ea9714d7a5794c08ed2700927aad8726596b2fb1f94d080c0e2fe137fb36964b9a3fc331551a77dc5a269cce040cf5a7ba37c" },
                { "dsb", "ecef9e87408523373230bdb6bc04b43176f0d74657d64a8a96aae93ed348681be3855b41b8369c91c2720488199734ab6566a01f7763755df1c72b75634dea34" },
                { "el", "35acef1db6736b368f357063aea7fed030c13e04fe99e2ad9fb3f9c4aa766b43ec019e9f81208612380d7459d4d57f20d0a80f1c5eb4e7f6d36305e1e88cdbe3" },
                { "en-CA", "d0b5d0680e2e5feecd1e30f2c7befbc59303f82de2a4408ae61d887b233397a818b00698a4b9249762873540dc05a0dbd452bce27547c43c1a37010ae9396eed" },
                { "en-GB", "1518012f9c8ba90f75206d1bcf48cbae84103593c3ed25557d76390d54298639f6673042fb97e4847e6db1f94a23f18c4d876e509189b1fb56c1b6bdceb22fc8" },
                { "en-US", "53093e7be4213345f504a71ae731b9dbb83b5a6ad33c690614c28e24c3478ecc106fbf62ac379a0dc990ec4e7dcd543a2e9a95d77dd487293caf2a21939d1f59" },
                { "eo", "a59c328e5d338e7867c8074939262faaa59bd8764b3c52fd59d767d6513ec74df4d3bbb9925a975bf9594614f87cae3a81632e252a032b1d50f8656b1d74a6d2" },
                { "es-AR", "5b34574d56f1a1e5d691057c1d06b657723d23158f060e4cae8fe42a491e41f0bfaa1dc6bdd65840521c2ab0cf59a4d584571d15c104c67fcf2911765ca1a427" },
                { "es-CL", "8a5ee9c19d79941f01cbadee661c81e81c2311ab5d073be7562f5488f01f7887f5d0409a7cd40415574d57f1ff0789caf39681fa656cf6e2795d1469ecc1990c" },
                { "es-ES", "f4e1b962a9bc20566930eeac19ac2375cc809030aea24a0d9913e67ecd91df6e41ab9869a5842a596443e8f30a0e6b774e3323eeebfdd7f0d9caef6a2085e7ef" },
                { "es-MX", "8a5c8a057524cf08d351cefbb4ea9e607a91c53b8a640bb8cee572cdf811a62537582de39519a59cb666541953093f17974afbd8444f7fcc9b1ce6a31d428023" },
                { "et", "9d03d902b158b320c58f76d30524deb2649c97a54561ff27592eb93e0cb5c21d65e65092c9dac0003fc34d4a29dc41aade13945fcf7d974f0d225e184ce5693a" },
                { "eu", "4ca090bccbf5ed4bd9df729ee8b755191a630706364c0f1a184b675fc745a87024febca0e7c206250c1987973d62de639b4a9ea3bbbbf419c89149c632f79791" },
                { "fa", "c4149175139cab0d08d667c10861208d41e738c2a1d9008a3414e40bcb8b3ff0761670bbb82204d46f087eaf3bbe92abbd0a70f9b14aa9a305a97756c0a65f1b" },
                { "ff", "a6d7fe03c02d50212bd4aedf882189a213bf8c5790a962c661904e97b9b5254aabc3fa4034b569ee0becb4c5081a2ea1d1184867984a462fb944aac983b18839" },
                { "fi", "04af16bdee6b0a5824602e988cb9da920d643e14b8455b9ba4d742ed92af480c649aa23ac08848c4e35036fb69aa27398daf6675c5366918b37ac5c19081c884" },
                { "fr", "c745849d83ca5a4c174c832307e5a10849d05470ec7020db9d393847a03a12934ce88f8d0f6511478191ddeac376d9fdcf4ae8e798847b0769c145b9ea2c0279" },
                { "fur", "8ac129d22ccf64916dc7d760a9494c07c15a3f61b2d48f433cb495379e34473541ae7a3bf6b87082d2f537b568e357e70af4c7080d14b5abe1d99ff2ed3ffff9" },
                { "fy-NL", "69e201ca9ef224f532fa6841cda2e42be405532e8bc2bde1be1acd2438921ffe86395f3327f5920709d4fe6daede8ceb2a37202c92648f51824555f05f6be3e7" },
                { "ga-IE", "33a595192c2f49a1473c22b5f7178f6f1831bb4c90203c0b59e6d577ec0a36bb9d64562e8c5f77cee01cb33faea96d3c468a7b64b0d8fcc9e2640ec8ea04eece" },
                { "gd", "9304c8818ac77c4d74696d1f43dece0845b31fc96f78bdb10330f91a0066a5d3f917bc5768a339065061675a743b234b8539c68ebfcf313e29b2bfa8d8a2861b" },
                { "gl", "b9aab4d1bf2d9ed3228d493a7498c76077df9edd5e928416b979f4e1bee1a6232336ade644e9da8088faacd7cd1ef0c50ef07e39ca6213a1de9e40dd99a5c98d" },
                { "gn", "1905521532ecc89182007ceffeef3209cc3160d67f61f35b078c7a0531e004dea6cea800df4af18afa2500b669db5c7a1ed38551ecbfccbb68afa75f0ec3e8e6" },
                { "gu-IN", "e50a7121595d4b68e34339db5db09df4de0ec119b16f464994e5cab7a777cf9b9680adb9cc18b7ea4e7946cf9e7abfb0727c9e0f51ab86e5a5b0cbdde7971e2f" },
                { "he", "8c6d1babe708120337a7daaca9f2a37acf0880cfc87f77345dca68a29c73ea67859a9e0228578eb723ba79d557b2353652a421716003bfc2d91b5f037d4d78a9" },
                { "hi-IN", "257e72df0f880bcd8d0a6baeda798b982e5e80de8dae134c6871b8b3ec679db1a081346333853693359956cf5f154091a7dc58a574ed55bea6f6fbc20eb91987" },
                { "hr", "b5b38e9171a3a23298f4809eb7145df659dc03473389f4cfabd175414bd5f5f7e50399b090db19bde2bafa4d41efec04ed21c495dfda5e899def597ff188d570" },
                { "hsb", "045473dcbe14fe9144bba4787fb0dbb4653936e8a0288e6e83d2be263fbec8ee19b8f287beb49eadb1fe5855f6051cae0ec7429d9bc4730e85e081f88fa4e014" },
                { "hu", "c108ba9ad9736b0af5f36b88b83c025a16022c97a84290023dd439b6dcf06b504d355630bd8b1d1f11734062ac595962cc3ac3cf362d05b45dfff2ac5d30b0c6" },
                { "hy-AM", "c973a0dc464a0d92c3dc4e76cdee2d7cbe3b1dc36016afea2c5ae257273de546dd83c7cb9b05b96d5b435bd279ec74424bc0eb709cd31aee7945cdc67b564a6f" },
                { "ia", "834f6dbfce092ed2594ad9f81b0ad0b2468548efce45be152fb44802c315a49c300d6627a6ac515e6aa8fd3a3f782fd2840cf25d262b7422745ba55b7c2b7794" },
                { "id", "5ec41f94d7cfac4ebec2923f2f858f12d9acc079e3bbdad58301401c176b7b53de7e769228aa3f85f4b0bca92e70417816fa00c4b89a5f69dca6a6af2e8a7d9b" },
                { "is", "e78caa8cff399d1747fd5c32d77f127af9dff70edf259c491f0594a62d39bbf095b08fb155087303a0fc612578ff765a479e75580ae7039ddfe6d7bb2fc11cf9" },
                { "it", "1d0a4585303bdddc305d3e2d78c6eac8ebea3cbeba3474e9e1e464cfd079ca67a2e7f144dd6527f2baf47f526c410913be90173944f680b3492b4c17d6e63328" },
                { "ja", "3fcb80596e17d02d80781b8b9e5f833afe7fd0ce474977d856f10f50a259e3f60e53bf0addfabe4fb320ec7376b7a75a05a9b763373ef12717579a52aab65a2f" },
                { "ka", "df3a09f53094746403bbf4d680cb259af6a24ddb49a9cad033e79247db11ecebe686522ae9b7b16dc93474223d800d44636e10c61fe68854b21ffa8163579f1f" },
                { "kab", "c9c2fb16e1d3034a546af21f8f4d91f831fb107c1525ae1016a6a2c8bc97cfd09dc8822af9bc51806726b78b698087426dbc1d3685e7ccee99c47ac0f61e2194" },
                { "kk", "8545073dd6a79f18971f8cc33647c92524aa57deb45b8410c213161e7b2fd4e749ee73127f5ae6d7df1c6fc64faa29b907bd283e51a01c6be28ec2cdc49cd05c" },
                { "km", "ede84c979048bbc23f4df9695a934e2d48bf91ec7c538cb8d568f319fa759dffd8808cfdf89f2fe532a44c24933a8072cd0a1a06a656c545561289e8e664b4fc" },
                { "kn", "782756d2ca4fdec527b18d96e2ea46ab4509aabeb0cfb6278eb39b0cb7f4ddd1f0ba7e113072aaf50fee033bc5ad4c64bb56ddd0411ced0906f6ff87eea75b21" },
                { "ko", "a236868147a4c5d5365e7b6e6e9fd97a1dc2897e89a3aa2e65e3be7c77953ec716da66a4590a8e57872eb840948af82f2c8aeb25e829e10548bdffc6dd729878" },
                { "lij", "7c04892ce049c1e193dfb16dea5097f715cb5d8f50b1ebd46b55c786f53e43660d7b17f1978b5d7a646f99049e7ed483c38b46e7a52a59fbee341413de642f0b" },
                { "lt", "d04f827ef31df4ea3899cedfdc25ac8581930375000ebd7099f079ae03af6c6df47e287e3143326178825717923d4db4a908c1ddab80bcac34f0beff35936c45" },
                { "lv", "c47e0b7ae097fd591e00809d90002c1c67a15907ed20d8f150e06d7fcfb8166a36ea2ab237c4a23fa925271ae46ae047e45b960c8ae3223275de36dbe6a8557f" },
                { "mk", "f3ed266dadf9d40d8f76c36820314e06dca35d40abe0d8d5ab06e15446c7c248c214ea6149ccb7caa591d8e27feb269af1c78f2bd39550ecaef999d6d58dd3db" },
                { "mr", "afeb18e64d48bcb155d1574b0c20255e7a033e04f5062cc581aee061dd03bed7c30f20a56ac3cf5c7c617784c03f5d743138dc33d281521df5808a0ce2acb385" },
                { "ms", "77bc1c576c42a42509708f20e999ac5c1d8614d1c3283daf6a96bf2de3d0d7a2e91d015aed86762a98279f7522cac1a65e781e5f450938532f9154205280d677" },
                { "my", "ed2522b00c6d181177761146681a541071224dfdf64744a3c07881cade2afb145d7e5a58634299206bab7e5ca99aeca77c1db1c5c11aec5113242968a5ac92a1" },
                { "nb-NO", "41a90d38e3de17faff0bb0a5fc442eabbb09ee8373158e11a7447af8c0bd98e2018ed7fb76ec51360e1e6708e3c15b88fb4699d0690ba492bf5d4a9c4f13180f" },
                { "ne-NP", "9bdad7fd951361769ed5ed698ff194e5ead5a81c91f5d033dcf4f76ebcdddc9629e1ef62de93f4547c1cd0b0b0873253f9b034fdcb6f9464b8947efa919787d3" },
                { "nl", "774b8582a0e3463da246dce879111c44d475c3d6e802284deb47b69b6d03c0a3d9a55556071e1d037b410954ab7df3e6ebf8b161cebb35ff1e492fea891c7358" },
                { "nn-NO", "ee4c4ddd3b272d62987d752aaa42eef38e3a5fa2994929896c4f3ac94108a3b32ab012040ced2f3f323d245e873f9d4a26005839284acab1ab045e0b19f4d1fe" },
                { "oc", "cee2bd5b7c13e5498507a78d6c6f2238d0a7bcd2c650d245956e98b17a6672d268b74df0264762241acbd669fb054a05a0ce2965c4d63097b231b604242b7018" },
                { "pa-IN", "466132177ebdc2b6a90abb1a0454282cc9ab0b8342633f0a104b58ed9b56722cc94d7d184c463acaa455d6bd9fe6fbe71cf01570c5d74735662862a5ca220a31" },
                { "pl", "4852676214f089cd439aaf77ec6d90e07d564eb797b55bcbf406af8bccd882b2d70f96327970f88a94d5295f77f95faf433432af452510aea32df285a298f528" },
                { "pt-BR", "a55a4f724dd0b5736b4fb75ce1ab6b7bb99839407806be173b587c507a464f5191cb0b3a45368289979ea603548b076ffc5d4ebe665e0e304b2844d5308f0d39" },
                { "pt-PT", "2e3c6d75805da867242c5985ee0d533b481d0b4aec61a7b21d3611de96d6bd4e6ca08bb1aab2962eb8e8b54c54d4fc75cd51e27dd36a20db8f02840c5a28e0c6" },
                { "rm", "88e3cf3b6a37089581f258ad845dfd6c0710743eb3d2b632bd0e416ca4de55f033be2a5658bdb88e2abcca0b1ae34de4c9201bcb1512e6ab770dd78bf1c152f2" },
                { "ro", "b36c943d4d25a9237a395a811f401baeccd4b2f20f918bb9a53a89079c5287c71e0b0e90c88be6dea7d4ea330e8262468c120aa2b6a98db587c52132f019f1b7" },
                { "ru", "dfaccbd6cb6557bf13b54f5ff42d323dbbcf1e503d03764a7b00dc865650e16d355bdb6aaeceebe654ae5e3da83662ab2ebad974160be603279c09f590258c25" },
                { "sat", "a8b7c1305579099d8bc3493b07f1b9ceec3749c6e423ff4fa49d177a7ee177b7a2bb59465c75b05208b6f7d36e65a2394e6d53a222a0512854c88a706e2e54b0" },
                { "sc", "351cd4562a094a11d9c86aa00d459cedd48b7182756a4ec04755bbee18912deadf9f22482c91f096a5cd35ee5f6b36d85d2d79c1e046b968a5798199dae60af5" },
                { "sco", "8965cd6ce7c448ba302d4bf3d9c49d5b7b33ee7825564f7d3b18673a1e08a63dd792f3033eb7a4cffd9d6d504d7e8064e9c96c9fa6bac32593cc6e5e65e04078" },
                { "si", "6afcc62be4fd098df6641541abce1d49d53166755276fae5b211bf3d6c4d9695bb13032c43237e73c6055ef4549527b7d37a27144612c14188637f3516ccdec1" },
                { "sk", "4ad6e4af58a91644a92b17190724d3f77d0493d8f4d9c533ad3d2c71b258eeeb1fe1377c23e5d1e24f9dda3eb82c63bc7e1bbe36724d3d8cfa5bbec2a470408c" },
                { "skr", "5da7e1e27f3e1746d23963c7115c1042474a51318b51a774e5cc2c1c7579a96d667f3b1fb6fba2b03c8c14c112d81b44d2514c3c66dcb3ae1dd2f96f1c864be7" },
                { "sl", "ba00c4fd854bc23a95c975b60979553e1db10371599c4e49c76ca68db0dda9dd91e1e1e51f5f3401497dbfb45185a27381d264fbfe7575d2961b6713a26c806a" },
                { "son", "73d85c3e528d3939e3f1b8c196540e719f617c0952626bcbfb69616ef364174475bb2cd9577fc5fec9d59e52faa717cd2de046fffe767f54c7bc4dcc1d6f0cbd" },
                { "sq", "2545caf2919aac38dbc68640ecfc8a1c620af4ae926c7eb0458b5ebd45aabb9a0afde3db23d8e56ea067ccc188476527e2a99dbccfcc9e827af0c6970338b7db" },
                { "sr", "95d04294a196ec4cda227e2901e55365e6d0b10b25d19c5573a8fa3e06a21e7b04a0c66d5693471cbc3c35743208efd3c68bbe279ed6faa071b97b5af6c4cb4b" },
                { "sv-SE", "5d8347f19efb87523723b7d3b099747ffe411a829395c0f9e6fedc98e4f9b9aaaa50be7b467872e44730800c303af9242fd2f7f5669538ef33bc46de7277037f" },
                { "szl", "163e7d379ae6cfc5494b663a332b55196ae7e16592634a2043200dfd5ff3e0e18543dfc12e0125264423bc3e38555f48523599bf22a1be4c5e1a93ab8990f990" },
                { "ta", "2eb0df292781f32c6280145c0fb3a79fe5cdab22c446f171d2cb3bff48c192b47918b1772130d78ea2ac57f749d0dfbce667bb93b2c88b4df1c4c124df75b858" },
                { "te", "2b00ccc497574fdd734927498c961090eef6c7b465f2cfac659e54521ee61714d0972563b55e7c1bd6715c191d9fb393fa09275849865d232d3af6f68d6f3855" },
                { "tg", "0510d5e1485ff587a615d53aede7d00434aae683dbdf8f72edfc2bfcfc699a6b21ed53a5ec9ccb8ca64db733f7137927123aa033190fb86146cdcdef256c0784" },
                { "th", "a5be50712d6ccc73805f28803f7390e44978c26ae4935224a05cdbc59f129ef49dd5a9c38def2a2233001d3e83445544baabf7f9e46c24d4c4a159a270831fea" },
                { "tl", "949debd29a0a1df8bad462bfd027d41a3be216a3137915cc52c283c9643d65163a4bb430317ffa471436866ed137e918afbf342de4f1b089539ffbbc00763423" },
                { "tr", "80322aa0383ca54067588fd07577ac6f25834ea6a50928189538be78ea7b24307a3690b897299460dce136179432135059822abc1f3bf3c0fdd7c97ce7afcbb0" },
                { "trs", "b8bd036e96df91a5a136159bbcabc681faabe55b0a5b0975634b69c290a29c019082c5b58f568c4e1449ef64f6438cfa6c5d36a4750d08175104ad163379f2c8" },
                { "uk", "77e6afb4157005814976ce7347d1768e41e5969da2b47d6131537e9daba8c0c578093590601daf9ba0ed14b0bd6fa214494e409355199dd14d54e392219ae2cc" },
                { "ur", "3ec062872126e8199188119e00ad3b134e51c9f4b6a6155ee16e2ee783b0f450385cc7d55fea0f62bd3a218b2db6627c83c4ed92d31113de81927a7b18780269" },
                { "uz", "039f686e7790fe37f6f5a24b6151db1a9203fe7ce7ed9eb20a5e5e3950150a9ed0f079597d9e097dbfff8c5c357b9113d943fa588c7f56755e626c9d1d9f82ce" },
                { "vi", "4ec0ed92c18bcc9ea997b46893d9819227e15a386dfcc2c01868155f7ad0533b091bc259ebcff47affc2d6ee1493f649d3b201eac63d488aecd72b4518c993cb" },
                { "xh", "043c531f4c64006cd9f10725b249c384a49607ffd48eb14e507c4a9abfbec6e778c5a1486ba4855a40509f0534114ac435778b6b731ed2861bc0f58daf5e1b57" },
                { "zh-CN", "42b1ed5bf14a7b0f44444738e45a9b517cf8a64daa79e5b24624f4d7d3d33145f00047742544adb0918b87679f16149a741345aa8e1b2325036507e57191b8be" },
                { "zh-TW", "ad62c245d3557873f46bb6cf269fa001f8cb045651cd659850d3294354b699b58c4e9248b3e7eb9a3f4a163fa4957665db8635bbd7d97eb335d20c0b1cd27d0b" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "60a841100967a961819dc434eeb2ba5468bba416749efde271b4993e709369906cfaa57b41c65fca1d2ed1c362d00482acce9deba3cef9b66209777dac958305" },
                { "af", "0603500c470dc63c9675d310d42e3cd2d259caba32b700198e97f55cf18b5ca10bb404e8e988123846c00cb0a24d3dab05f84ae9ca4857581ba78955752a5203" },
                { "an", "de034392d2f1b58246a548b366134ffb90aa53d34d98cdcfd99db1a4f479ee34954a435e7d249ba55760e91480bb9219903461cde1e1425a22ed265f40ec6494" },
                { "ar", "749e843c6c454c55ec980f22f19ba37997eae73c5cbaf89787dd433c25d85e32934dda2ce8d66c53e821717f957c8351a13ff45bfbcd6e27a7f45a52d86c5ba2" },
                { "ast", "153dd3d367b8d4fb017e59d6e6c647819848f95379e3ede6711b5491f0c84c2d497450bb53c920756def7af8ff3974f561d5601d0747e697988e482c0ed1b5cc" },
                { "az", "d2b701f87042a63ad4b5695b66e1912e3198b47ecf6eb361edba525c85e6cebbc48a07603747a79efde9e84aeb0df23807f3c99e1f476cd5bac805d57abbe92a" },
                { "be", "31b2648679304c3dec317b51d4aa19b3b582a596b7b5552f8ce65650dca73d012e74e2a648168cfff0e93a7003264221fa15829ccd668896454c0490353927e2" },
                { "bg", "8226d083ea797aa4cc1074b3337adb98b7189b3ccec013d2abc6f3f4d85304381ec9b3b923dc842171371f72e99261ac65b5855c033a0440225dc1d9c50c14b3" },
                { "bn", "25905507014ed139f2faee355ba238c92ad122d9fb6d6663c1caddc7042ba81ab8a7f2ae5ff2ec85308140cbad31bfebf8fa1db67c2401bc92ecffd156d594fb" },
                { "br", "0c9e992ec69e19612f99e1149767a2e8407cdd1e16e01f012e2165bc20da9db7cdeb0354c2b4f881497682476188415e0ab45dffc1026f520484c15f005afc43" },
                { "bs", "ae9edd41e8e3190d3da4c473478bb89ea8278a069f0d75bf5ee4c072d818e6f4bad6634c909cf9b583a9f97dddedc3e72fb92b609e2ac5a4f2d206181f809ca2" },
                { "ca", "e60e721860d752cdf2e35c1d8f33798db8f09d1c7c7ae15c737b64683d050438791c5b07d8cb9df9f6a3ef96090a053b7ba2cddc116ad5e3b67aa9248217b670" },
                { "cak", "a5e71e62d270b39142624f246f2b90ca0ff8da26b9871079553cdd7f1e54777871c7e64efcb7c3b0551a7cfd95c6a6cbde2665234f2923a787b2d2ab198f149d" },
                { "cs", "164019d15e29013879718b3c244cd0566c7c19d681b1dc6b354453cf5c4cb3463d95eb2ee4c893c1f5a87dd4b5395755796c7a8448d362030f033e2b33b5482d" },
                { "cy", "a9c7fabc3843d290a242d6bb00271ef0d8da8d0e54a73c0cabd1ce92d76bfcdc4845268b939d3878ed3ae9d6b4691e4010fbedeb7a358b67628e76ec0985ec2e" },
                { "da", "df9586cab64cf743fad2d1232d849a6ee6f6b3b78a7f843658e5c62e25f1292131adb666306b24cb5c667e0a7ea3a5e284482fa2113c3f7f27af45a973b37bc6" },
                { "de", "a5e9e5b749bb540a35f0b4f1f34425f0561af4563de033978413b41ba5558cb1dd04f8b0be35194ac80fc3431725bb66becc8bd515284ee85463e09fb2339dbc" },
                { "dsb", "785ad65763590ed9fe710a6dff1bc79d955ad53e655b9d082cb110ae5a9279c473335a07331a62a2e20874d1a0b4b6ac36955b2c79a837c5b2cf4f8feb4954d9" },
                { "el", "aaa894f03b755a1e384af2df447792cefc2b30ad9c3dbf13a25d5dc70e735b9db450723bb940df9e1b43789cf9aa02cd9b10d7b4de9faf3d5fd64e922846ce50" },
                { "en-CA", "d3820bf64c93afd3d28d4acf3d4e50db2856ff5f89e6eef0f976f3994389aeb3e3a87fb21b9a3598b5bf581f0892bcc9389ab5a195f4ac50641da33da4fcdeb8" },
                { "en-GB", "9d24a54b8422fe3a9c1a2e1b436ec2e27842e94e471d47f88294432f5c4336f0e6014581c40597e2b45da565e9583ff0b68b56a9d450d47895f6a1f2bf81f642" },
                { "en-US", "fabcc840349f10b3042c09cd0e3661d3560b29720413f7ac6eba5c4c067197ff55edbae0143be7324f08986d41e5c623552c5ba16c52ec4d5e8af8edddc410f6" },
                { "eo", "c0e85e93bd164d9e63bbc865b0e06538a475ad1c00a0dac344401aaf321a76359c0884e8f05c25f936efa10f1484aaa8875faed9bbd252e7546b5218337cb3eb" },
                { "es-AR", "9c8700ee1b84dc98117d205fbfc10e2c35d148ea3ce342a32a1432ebb2fb9df1ffc233c9e99555ac834a861da9a1678b5afc9141513f147e9ced919df95bd2f2" },
                { "es-CL", "3c9e39c0c4c5bf5fe61e31bc512e4d9a98481358243d62a8436493123f9a4f700e1e89704112ad65e40f904e348bf5399f32461e8bfb89ec0e5859249eb16168" },
                { "es-ES", "a5890e6d22ad4f4828c92f0a073501c9c25e06ab190d7991ff4a915d2392d7df9b56331fa74af74d52932e2c647c08d37c1e16906355dcdd564d3497cf657948" },
                { "es-MX", "36b677f42d7fff3485d8cbee4f094abeabcb66f248361f75a3e1d2b0b2732df0a281ebeef90e000e3634ccad82a0d945c72d368b30a8104b59c132468c350ecb" },
                { "et", "44620679c87ed7ac11951726872336ad14ea95e38c7b16afff08beec99e3cb747ad2d929ca93e44e7797fe8f22b7ff7e28b9b4bf1b90e59e076b8420030baa7f" },
                { "eu", "350b615d1c0af8e0ec312e586a50362a6dcc5363d515af8f0682934cbe9d08da5f13282bd95357e7cf92bffca6295d9926b464d9e2127de498df82d428eef300" },
                { "fa", "a03880c1636ba1ae8afedf04710f033499adae342009b5832eeb41d34726601cd061ca7f17339fa558c2ee3dbcb659e36ce8d959675020a5fb821284a3a46618" },
                { "ff", "64034cf58b6bb629cb700368e09583442c1245d5de93626d1dcafa8bfc1c20d2db1d0130be2aa98dab3638a04eadbdea388b80d3f926554d566c505b88c952b2" },
                { "fi", "c3d3ccbf6f13a8c25f09197108afabcc66c1803be2ed57f4d032f7c55989f8324eef04b8cf012110d7b6030e579350e877784b3f1ed8fa360603d106368091d2" },
                { "fr", "151180fe276f1c1ee0b7cdf666cacfbe7423913797a7c436ca6bb951371148f30e4c255055bc77d1364908d432401ae91abb76402e5a82e59ccb1ca928758b92" },
                { "fur", "fb124bc2d07fb14dd7881f41d5dcc3250de928cf3aeacb3f4797bd59700f0dc4ea9291f8783c872f3c81997408d2cbd2056f4591c5415fbd7df64aa9fb1d9b09" },
                { "fy-NL", "54982d2f023ad396ab6ddbef79325f02e314efd73281f9022b5fbaabce7009a4a3c38d31af4a46f010ca3a092202863e41f83fd9c33c0bda96516156dbf7b07f" },
                { "ga-IE", "5b0664a089e81475e78a6f9d91d96b7f8d3b74aa2d3cc530a4e49679dbdeb14df5d0781a11beb3e07dd77be87372d45c0510cfb3c0c5dd4ead45d236239fc016" },
                { "gd", "2d288cfe9b18795135b7a86ae5c04dd86d51bce79f4c82d2d00bab1c28fffd613c3b9e4ecf9992507cd9255b83203b7cbad98e98be9e3ba447781602979891b2" },
                { "gl", "2ff1c7341ddd025153ed28a7cf18d31bf6a80809d6e52b57cc101ccfc82ab3b0449e1f390b3334dc3a7bc2701534777144da948809c47334dcf5f02b5cddd16f" },
                { "gn", "bcffb13df3c332630a0f2afa2a3bc2698f8669dfe7bad67b673b1f602444b0c82535ba6b9ecc460c0cd475627965c2b9bd26f89f055ad20bb6df888e4fe29972" },
                { "gu-IN", "5d4f392a17a1b9d9f780cf419f72cfaf6a35d6ee99bf90974b9204ba960b4f412cc82109cc7a0deaa82cf4731eb83aecf4ce5d38e5568fb51c51b9610cfd527b" },
                { "he", "7b1a9394dbca4b2a2f446ffcca7f055f59fa09a64254a12bfcb94056a16d751181b5de635670a5f9e1130d7c60e26ffac4eae48c6e86cc766f991ec2c0133f20" },
                { "hi-IN", "e949b662cd0b640c1b1069fcc8fea585f02cfe5e298cd8b9b6f4b4bf816a2a585194b62eaa1819efb027478b54f83930497dc10de4d9fee6132b199bb7252a6f" },
                { "hr", "cefa5286789c9af99af6e680e7c0b560bfde9b7fddeed268abb4167c55d5e58cd0fe9bb6bdd8397a3e847c19e5c4a062b5c70a0384fc1f6c7f64a600e6198d6c" },
                { "hsb", "26d885ef07feda73593b597d0d074f1478bfa84d7ea09622ca90ac379d3db8399e93e21ea8d201cd1ee0c9ca5c7524db9d67aea219abe8371378b2109d959940" },
                { "hu", "c838726d5a33a49d0a083aaa8d87aab0c38bf7da854774ea02d3fec268947a57d802fb2749dea708d5a85ac9f7c111ce45df3354549f227483e8e134e480e4ef" },
                { "hy-AM", "54a26fbe125bd10d8f63d85a4a896bd4a94612ae50d5b36cc3bfd61a9d57e7088ba61ffafcb43307023c6d925cd104fb2bc165331bd6e4fe50c81d629eb852bd" },
                { "ia", "42218f09296842a69ce19e85a88dea3e6229162fd4940de277192d6d3859ffb6b215defcb2fe7dde647fff41c283ae80be7ff3d9a774260fa1c862d936a1ee21" },
                { "id", "cf50214f4756c2bf6edeb53b365f414c7637940d9dd23a77480dc9930cd4745adeb23001fc10e8f5c8d196f2a45920e8a3d9dbc690e81523503748d7559265d0" },
                { "is", "d12b5667f7e9a69f6187f894e14fe96f388c0c00ab08ed7b8566372a430c58aa42308d7b6f138a99cf306a3cbb8aaf4d22129f7e304e774c256e652ef91d6077" },
                { "it", "9f2b638bf0f802efd51b87113e455dbcb057ecac2121d214db1eef16db3e995612749c7b90383ce12774466859df8df1da55938be734066e9285236f7306711d" },
                { "ja", "42a555e09caada2d9a1a358a47e84678ef111927df9d27498c1add520f62c8097b1ce2725804f9bd7b803c9acd756b30cd387adfc17f731a8f27563a0922b7ca" },
                { "ka", "317bdd54fd2f0826a0f7ac79e48f37b15f335abfa65b9b3329b4951e26e1562671599e3b665e25d87e88077045dacecc93cda6a1224dc6c580b5e8c6c64ed97c" },
                { "kab", "24a23853a5e4458d26b6c1d9273c02cbe1410b8fa6204fbfa3eb7b0075f0b30d33d0b8d3c7a2781f2474222b4c2a26d6ca666bbdd7de1fbe28472fca8df42310" },
                { "kk", "4ecfeae3771f3a5f2bcc2a1c188350f44377c7365932de1a9c26a035217f1abdcd56db2c95a8aac0288f7c40a3434402b22413c7fcddce6a994311baf34d9f89" },
                { "km", "b3dff7acf6ff1bea4bff804bb7dfb3c6c3e5f8b7fff37114bfbd3da884434850bd14cbe209571bb973ee36eaeb4f91edbad39e99b25e631027974abd4e0d08dd" },
                { "kn", "db9eb506ec397fa8a1ee2bd93250a470e01d9cfb56a4655b744ef192697491068e53da15733f53860e3949e87eaf6666c9de7ce6e54603fc97a5da52b19d4f03" },
                { "ko", "7a7dfc2a3f4e6ffff0f80bd7a70260d67a297ada6c56af602941ce7d045189acd2cf936e42e1abc90d97dd9864e1ba383fd056442383a49318bbde8062503007" },
                { "lij", "a65e73a689646355b09f670e524127d20d97da9d918275efef1aa64e9f190f7c2d82ea5955e8062128601bc63e40318999f764cc2cf6fb6fe85c828daa514aad" },
                { "lt", "3c77e92c1b4d224053f173ffd237650ff4419ecaa273f84da03ba6c3e4234b4b3708468a72d4fddfaebc724c5280ea0d47a4755022b6087a877b9b6205f75c05" },
                { "lv", "3f9dbd79804e3d02080ead34fe17a11e6dfe24f884b5ac146f6bac446c69509241be07c1c30f147a5e8748762914f44107dadaec93d30ab5dd0ad3057be20a5c" },
                { "mk", "e6e301857d230698489f0d5afde2dc823a39b604884acafdfaa26524abefc321c2168f23c88df37a37171d00cc0dc1bbd53d59ca831736b8edf2b80715154efa" },
                { "mr", "4716938a424f5e8f4c8d0dc87aea44e0ef3579727ecf76ef1eabbc1c1b0a03e5a43ca1bbe1986fb18603ffca5d5b08cd108b0ea1b25538c8434ecc05aa2c21f9" },
                { "ms", "4a818355b6be212a1db39776e1afc2e6bb534fecfae4cf91c6cdd053c68135a16d31b608b7153bea22d50f6c788e9bf983bfbf00f6a18fe0c367ecfae1553085" },
                { "my", "590e14e13505a71aeae9f4a1336127bd301661e76e65661c74398c9505dd1aa96f0de50d931a3683c9c54da6dc2a91c840c435618a3d62caa262d09faef011d3" },
                { "nb-NO", "30356d719ab89b8c0e370e4f4e32e321bae647c44c61d06cc455d40e0a5661f1110eb6f2b5c685dcadcaafb28cf59c0a1b429e281534c7ffaac391b752bb693e" },
                { "ne-NP", "fe214216b0e9fee36df9d3f4500720fdda710ac525177c40e5525d4c9b2b49dd1f153a89f30ad6d5c831f09d94cdda728cc170f44ef3ac6a94a80d4a449d70e4" },
                { "nl", "599e34bf932caf50e46549dedc9f84f1f67067dcae514afee77c5ee0632a2e747c382aeb00de17f08de2c004cd75f70639358db2be6f44aa450083745c4195f9" },
                { "nn-NO", "c5474ec8315e86f0b7557b048022f73989eda214c2757d82072b3a599e317ea7a199f80e4dc338c921c9c395c00986f319cef5e7d83e75dac39f317ffc0e3c42" },
                { "oc", "315976850e3df68535c1dd1570fa6a3389cf78e0f3ac0e4f84a60b7bb7e8905033475f93fc8cba65908221c112c58d5e338d6ba2a5f18eedadd9482a04777f52" },
                { "pa-IN", "4a44fb98bf9bc392c7ef6eb530996c06d9439fcedd836e1f105d5714ddd4373587ac97043edc764ffd39a6539bdcc1990983c28f5c11c90f5cf220bf609af8d6" },
                { "pl", "a87ce273923580461f82b37a1f992b4e19ba27442e2f31ad9a4b50b3f37da20bd298d12f56f6b82a4d57c4eb0c77bd18939a12658dde8d5225655f4b47ead29f" },
                { "pt-BR", "5041818b4c5d4254040b871ddc88e5ef9cf66ceb99fbd7a2fe71df1c170b29f00f8c37fbceedc544c76a193932d459a91e00c5b698a5af170a91da40b1b698fe" },
                { "pt-PT", "55bce90379f91762b23b21d7fab2d62f5d77493f5b1352fea89b9bb21eadc43a8487776bfbcc798c207dad4fb5a79a31fec61491d36227dfcc6436e8bb2d0126" },
                { "rm", "0ca00c70aeee6e3c150d901407091298a3d204e6836af76e89729ffc1949001394ba63c32a4668f79a083a6b084c62f99490c9d30a8e03f13f50a596777ac436" },
                { "ro", "953558ab07c753b8d480412be519c833d85afb4692a89f78ad0394a8e7924df3e16970fa55ea3f1ce91a55875c52eb8ef22098c11b4ba8151c6f917b2807da06" },
                { "ru", "ad31e1509f60f17fce751dd28eee5c80e21ac62b40503476946acacb8323408368dde035de93eff261f5e4151f53b8d08588ed165febf200783182ba04879ee5" },
                { "sat", "2ee8552ae0185da6acb4b4c2dad26aac505c7f15b10ed90dcf01576a878d07b4bfae8d343ecafdc3ae603375319a809179824d37a29627dfc4199aceefd5d446" },
                { "sc", "4032728b377cdf1f8b06557e166243951b02dd3d498e5579a0247331591d36d2053ce2083d93e4451f0c68ce24021a7c0bbd0715008d269314267e6bf1a0935d" },
                { "sco", "bb364cfaa59dba36d320516ac6d7de5c97c85cb06a977e1aa9c02abee8926862285c346046556cd941a8a86a6a43f13baeda1b6691bb3194e821beb53dd3b3ca" },
                { "si", "d2291a9651e4fe7b228021da6ff11cdcee479eec038a1b041814ef0cada4ec420355a3cd7fd649f0fdc7476933e9a4264060eac967fc581907fcb544dc852d0b" },
                { "sk", "47d6441a3f668824831031a2df423b09533ebe1a847da7767318382178c5e8c7901afd4bf0db53caf0ad34afc57ef94bce28698240a3be35e0c68174acf5cf88" },
                { "skr", "d8d09dddbf4149a934104ed42e293e20ba6761f8913925f2036c82a58f84e3d21b0c98b727d7173a914c687138427850dbaa9ef553aa0b5061358293cdd3cee2" },
                { "sl", "0e16bebbe45af659d7cc0180972542003e6c0848aac93d71c1df6909bb37b723c7c2b09257fa2da13f4f82bfa206ffbe00638b56fca6c492bfd2aa1f136e77e3" },
                { "son", "f6288a51c351ba6b6de076843d3e686a57697301338923a2c6aeec9ad5b00b6aaf9a0a45bab1bd57e8e4439cdf1e71d932b383c9fa36b7554af79490045ce4e8" },
                { "sq", "fd3fcda1c1f38a54b144c2bfb7a81a4d5c0b4584ce5d5a9830e1f70a2999f470f27eeec310c208a3be1cc1cbf92997484d6b19097fe8bc0d472e52da0bc1d281" },
                { "sr", "28659f9ce0f0fa7f6b620495dbad96fbcdff9013d38f5ece5a8d049d177437a9a8450f70ad77100da7b7c64fb82a5d2f353ec857803c04b97596c1a4f9cc3613" },
                { "sv-SE", "6b677034433ed9cdc12dab58c048055fded2e5b4fd58ce897cbbb0d0d110f3a64ecf6573a7e6363c641b3f5c26631d22d7065ad572d773368beb92f3010a31e8" },
                { "szl", "114d6fbdbfba1ac4df005c4957cc08be794b34957570d10dc83cb6f279b20f65ec30db1a966e6469bf11eaac6a76488f4e6c24fdba3170a60282b9eb66b14ef9" },
                { "ta", "57cba90bb1ea80e83c6ec67bd86d961e26b09816cff8d5ac479683ab7166301a66e136d227c7c76664e7849e551c9b85060bd2ec82d85fed3c9614f0f13b8cf9" },
                { "te", "732e922fd60d73f2b398bde521f41381fea761d49fff64c88045cbf53f5a8ad63ceabb610a90bcc8aced7dc8e38c3f8734ed693b12cd37340282976f240508e3" },
                { "tg", "33e668e99b2254397979bb4a0fefa216a29a7018bfff1d6a7c99ac090a2e8032b3165c5fc1a89d79d4120a18fab38e04897e5283e5390c3ca0d47e65b52bde6d" },
                { "th", "e0d1f91bf80d760b3af51951d0d1f160b8499245043dc1d4b9e0499a742948a4e2e847136812cdc67ea5806c854d69439cb8bd6a96d7bf3f5a9d33cdb0ec4b8b" },
                { "tl", "36b84d993199848ecce0c8afa7a5bc9fcb7fb99a589854fa21ebab7fed81756873dd904db5f7de409c0b64261936b797d563b95f861e22c6afb4ca0a679fc41a" },
                { "tr", "ac9769abb85e2a60f3330e96339cb964c631d7090b39c3cd106252f9e9dd740229590783a5cd1bf4d4c12c407c7ee9a60064c1fe3c26224ae419b56d4f42361a" },
                { "trs", "f97b39c8a81592399e2d679fbd285ccb4800f5908d82e649e06cebbaa147b7d7e0d4e569adff2714417f48899bf40409eae33e0a89554f29b2e2301c33bffff7" },
                { "uk", "88e18e4cd143c824e0a72c37562322d774c8ff2d247d02f2485c9242735f0d4b5ff39cbe0dde00e0e58a162627a0933d10794ea4ac86bd4b38cf3bbcdd0b9061" },
                { "ur", "aa5f5a8ab1204e5f4c5b2a3b65d5520aae98d556e738d5a64e789bdc04221e050daafa7b42cf7c7ab1c063ed0ca3013a1fc950e9d2790df692a923fe8a6b0d52" },
                { "uz", "a1a38a3ca55860bed8de43f2af613787431e127dd2525222f7315a49beb4a57f4a4381fa6f7528f8c6cbd0e8b75d7bb447635c3efa044b73edfde10b06289aea" },
                { "vi", "c4d198fb7baaeab706472cd03a2bbeb9314c5a519b9f386876160e62a0433e4a767e02001be12aba32fff7fd544f64d37c9116b04abfd1a1ef767711ff6c52e1" },
                { "xh", "ae45eb97943dbbf163277802406c28684ce6f80581fd536d9121aaccba14728126c6d8ab7ac57bdb3cef8f0cf0a96ca90c4c1c5817e49e205e244a72fe730dec" },
                { "zh-CN", "13321bdfae124b6f9129ae9f6e2eafae6de9304c2fc23fcc764faeb35bf0ab0ca491037d428d90f7faa189bf0f7cb06c0245ff47d3070e81e347568ba6aa7e52" },
                { "zh-TW", "b406586ea7f7b1e2588a407c4f0f36f1634a0c6bb5d9b04279dec6302320877187c7424a3531f86a1a9957c9efaca41498c6afcbcd78b17012f9f079018a316b" }
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
                    // look for lines with language code and version for 32-bit
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
                    // look for line with the correct language code and version for 64-bit
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
            return new List<string>();
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
