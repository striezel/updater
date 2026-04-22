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
        private const string knownVersion = "140.10.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "0cf1985e05d0780fcb96c891102fa21384c9f12a97bc3047bf186b59ed842aef25f006ffcb1cf8a99c86fd2fb58d9a6d1c9719746a4372b59a185e5f3d7c3645" },
                { "ar", "00566f88e3deddb9607a9f315d008a02425f35e533ec56f72b88342ead1742ac81af147ee644efb0e837c358a81689ea60e6f5a0971ff31f97ec6a144edae42e" },
                { "ast", "3a5ed5676eed59a81b0c5e6024b4a6fc4f6fb3cd67680b9203444643c0c8d360903014d1b04bda29af4e05c219c41b567843afef79efc1628e9c18f4e70196ea" },
                { "be", "c9c5922f9630ca778784e4b3eba3343704c6df70d363ae163f9bdeabb203eba23ef69c6568bfd29d24ac4619ac79758199a4ef164662e7e7409fcbcbcb423699" },
                { "bg", "94fcf5ac2e276a8574f1e2d266d7a2a0bd9f264ae49feaae4298426f4149176a347a119fb726a4be5c8500e07a4170a6e0d0a01aee555f91523be13054b52d7f" },
                { "br", "3e511e13e227d59e1a3ce44a1036989813d297baef6bcc619a16a128ba79db04ff16cfc86a819c2c1f99c793695451cd804b96e256eaaa76046814fd73817006" },
                { "ca", "448a721fa1e447449e85cb233d29e11756e3aaa587c8bf52fcb896b4daa61fdad752bc3f9d79e7952a2674b02f4ba85dcb97d3be86d3e4e4bf550b26a2c7f91a" },
                { "cak", "f98cec77fbb23f54fd6e00a4908b85277a1c922562b43b12ed462d3668a64b1cf61cb7d52fd668c560b6d803e2e0beb2ae5303eeb81926ff7070899d1e57513a" },
                { "cs", "946b451715c6ee532d80c910e2e81ff94878331a5c3bcdc73847fd5c2f49979e61e10bc46842df16bf135d0c851ef49f9631226bf148af00346f0de370c8b94b" },
                { "cy", "5daa8bb77a4f33bf0ba5e041b5d684b5190deee88324e39de78c05db26234639bf34bd808b9a6b9d1a0bc96245ee2391d8dcef77fe0ce04582c271d43365ce4d" },
                { "da", "0801117430d2f233f19d187c169389bfa0df17b19ac3f4b054c2efd264317829693d4cb54caa6caf1f6c9ee31c9e14880f894ddee047e82d24745a82082a8715" },
                { "de", "19dd38167c2ac886eb222430ad52b6ad4a798e52a0169e586ba77016f23920c58c13c7c6bf091a363ec816f97ad4075c720c04f29248d52cedebbb49329f59d9" },
                { "dsb", "ef3e4205ab25f309577dcbc4fcedca416daab2f161c1a8d2557153af4d0f445044395c321e64d5997553cd2c11f0f95ed4db2a071ba47debff8e78dbdd736c69" },
                { "el", "25b4098d218de969ee36308a409b5684bb64ec60599a01bcc37514802531e065c37c1f203b3c7201633cf44c881281fff68c91184bf97c91e467f8a6f56aa810" },
                { "en-CA", "969d189eab41124bbf20fc4423b7b4197955639af5146849eb7a8a6515f7a4000c5af38379635d63ce658000b7716bdeafb093c97a4c667f74dbf24cd10d8986" },
                { "en-GB", "d7313eeb8d0937d809a8d7519e56901dfa92f5aaeec71a24af6646a419b2ff37cf1e677bb20e19b2aa7c34881bba8d8cd89664dfc354ecd400fe0845b6e967c4" },
                { "en-US", "7cba320676f9271ec0245213e1942cb120d0d6a255d94cd1546a5c4ba25dccd113108967a528041017e02599ce30aefa22df1dd2420c97e2fd5a329a6c1b21f5" },
                { "es-AR", "944c85b905f8dd0cacdf759e5914c683303176dfd1c02a19938083fca1a3f0610c3cd0537279a179ceba824ce2e6d8159d4d74d8eadfac800054d7f6cae647ae" },
                { "es-ES", "3617e8a1a9e20a6457621fa786e223e29f68cecddfc23c2cf15215525a629bc4d931dffbe79a264d1fcda6ed46783bf14d7c2e73c8f105450efb213fb356f026" },
                { "es-MX", "d07b9e583c24b822450a2e703a67effff7d87ee056f304b7af9a533c5a45e2e53c522a83ac7aa932329af38040363d477ce5d8a0090592b8c8f1620bd022a10b" },
                { "et", "4445c19497169ac9dc5a57404c90f4ea37e734c263560c01ab4fb557ca0326b568addc030278401b6c92482b2c3735e601ef92d731dec92c1e0cec8b0c64ca85" },
                { "eu", "43d9ae82374b5393b76bc99437d745fb47b0b2e65331b706976fd85c528e3e1408c9d0f45f9320501552b595007cd94227056784ca173be5e1c3d34bf35509bd" },
                { "fi", "ce166e65b3804f862df9a73db69f5bc089757af919b205788933011f84728071b82f6afd80a5989c0d67793f1b82e0fc31cc055ed13f0b220fc88a8bb90e8043" },
                { "fr", "4f5d6f2a892a9ec39a5f30fb32df0fda44d7d2207571ae62deda69f20cb5976a2acbb1ef49cf8724250dfe2d38fe753ff6c8bf9444748009767f3ff608cb7409" },
                { "fy-NL", "1f7ea9d4df8c1ef08c5a1e2a590d3163c085ed5e4b03f92a4534caaeda3d55557eebd014c09f7cb1ce4e635ebe83d72e984b43bf7bc38c33acd06e85ef918c86" },
                { "ga-IE", "583d604d89c659d01d0ed4f80d67efb99ec691c0235554b2fe99411a205c7f8068d16db48fd2261ec08b743bc4ea85c76b7f16fbc3ff7a1f0bdce90eb6b1befa" },
                { "gd", "6e839dec125f0435cbc0a5b9b114f9b6093b9083088aad87a4991af7035183739c61fb9b3ef4e0b09e1ac2ebf2a1dc103390e4524564820d93ccd38437c5410d" },
                { "gl", "2bb670e15a592556e81fad3a51d74557625139496dfa9d35dd6dbb270006a52a6e5d49bfdfcbe04f0d2f7ed5cdbaf6368d76291bfa51d14e4e79f8e41cf996ec" },
                { "he", "cd5b94d998b2b463b91c9d431ec3634d8b883db7183a84727c02d2a1b60ea534b07b3c8a3f2b69cf8fd503dbdee1d01f7342aa19ab7918973277c730341f10cd" },
                { "hr", "306d7ba4e45dc691ae2733d7a0a212ecaaf08540a47fd9d9af0460319229dc8a5862211e8a93f4d98bd14d86601e411c075f3e03120a12f5211bcf0b37a821e9" },
                { "hsb", "bb1cde841dbc53f605666c72cdddfd8c12fd1c59821ec4eaa58b23293d870a66e5c100e27f35184c45240b93a36aa0001342d465528f8dc50036c0c74b5d7b77" },
                { "hu", "c9f9d8c8c661a620b8a3c3f740a2749ef7f5f77bb74fd286b02e1d233750b0df825f33def03529709eadf800beadb464d1454ba36b0dfc7e1bfef98fc7f2f11e" },
                { "hy-AM", "723d8743b44cd245e41ffa7e48e72eff0ae7dd8982e872140f7c0369054461eaef3ecd709161ec57e5751cc0d5a66798d35b50d8c19e72f0c553aa6303b10f18" },
                { "id", "1df1b03a2fe226e5d7f289a181e7d14342daf5af1da7dc6ce4167a09ca2b8f3a071734c02ab91ff6767c1408cf0c94a5adf258df12bcc7ef3d9daa0e53907712" },
                { "is", "9a9cbc04539d1cb8d1a6d360c4a8111e6a84ddcdb9aae51f12b286c733a0d7485e634ee5e8e72550e1d366f58dcfa87747c0510eb247d3e31682e199702ce520" },
                { "it", "74b4ce5c6701ee58e0cfde5fda46cee92815d4137747845b8d93645bf26b0923e7ab7ccee649cfc430623833be126673567285832c10060678cdc11c2b656c43" },
                { "ja", "44e2763f412ce3e8fdd3e45b62e44fd4b28fd8e504cc14aaa6ac2548931b3a73d3ef97c6c2d86a64f17088e43caa342898dec605038918947ae9edde38e1b18e" },
                { "ka", "e0271f4421fa6de15c9996102d9affbc29992c28b4df74f924c13f3636d24eeb04ccfafde2153ff88cfa5da050ede08a164d0327fd7862849405028eafabe823" },
                { "kab", "3a908118c3dbc1a85c018df0696a131aeae83abe2b7090fc785cf304670a4fd4feb574f98db944805267d2373c427dfcd39d182dc7ecb7142e6d3a4d149f76b1" },
                { "kk", "98dd2f17b3a3ccf33f3185b343a75e402c70188f897147ec9949345a5cf4ddc12fd5ff6b31da531898989c1983250d7bd4f3988ace25f13e293180f5c63a85ca" },
                { "ko", "e9e427b31c78dd71a6a0a62be0d956cfba17e1df913dc1853b33966c87ebf2ae47fbac70b3e199c41a9b9672d7a5bea9fa0ca41b201411aca405d373c37c1f6f" },
                { "lt", "4c6ea47ea57435cf6502614f7ee9395f18399e1137cc696d4488dd4dcbda5256f9d3dbcb5e852f0421bc5fe44e1590a9acfdc93293caa7028ea166512b499504" },
                { "lv", "dffd4ca55f3cf2523efa9b400940a99d1090a771d5393a80172e132c2d31c4a6bdc8389d0e891d7ff94295f1ae2940ca38f4226ded9ca9a5e5a1b8d113d9c74c" },
                { "ms", "6cd165bbd51c4167dee56a27e4a3d5dceaaee98dfcd8285c2bb06f1284697161e9f23ae0d90d3087e7dfcabf5ae98253b4b677ad5a8f9e19538146bb85080912" },
                { "nb-NO", "c859491ac01a7f85994df9a3868e47b0bbda995701c2673b4f103d216cd514fb07853665bd2197d3ef34b3585905098cb680dae10dadf98d442bfecc6ea4656f" },
                { "nl", "ba846d52c655c6611609b7136f4a065fc47b9f88ef43604bed181604d93267a7c6996e8b6553c1db096afb75d6efb5446db282440bcdee98e128591a34c23250" },
                { "nn-NO", "5198f656d0d8fd3517f69aa3ba905a04ea775b9a1a62936906ba670ce33dfe3977878efcd54d19366bc19c47e0d09403f1a75d2d1acd279d2fb4f1fde0f1aeb1" },
                { "pa-IN", "42175ca3937218525da92b7f9b931c36273a55116665db4c95f02a2bb81598adc5bd8529db57be183d90cba11af32c2985926c5501a8d1b5433f5c0f2424f3b0" },
                { "pl", "c0558c37226963fed4fb4b19cd16872fd095767db87fb274c91357b569b8f6cfb5f240b43dfadec5b50ced8dc68ab71ee26bab66cb58ba8c981d21c380388849" },
                { "pt-BR", "b15e96ec32e596d35b1b33d287c2ca7078c0de906a2bdfb0e05baae72e97548503b30759e4a16349a4e4dedee108bbd49cc736f30d4aab42f91beef712785e13" },
                { "pt-PT", "2e005f4e04fa284cfd4aaa6c6268dc87d39d291e94fcbf8b3051b812b9e8d39167fcc9e56b12aa69c5fec5d8badd2e7e08acd984c0e9bad1ddc271529e2eaa59" },
                { "rm", "2734d02e3b4977190ba0befa11d386eb30780af0d291fd56e42d69e78a0e67c635a3eaa2199cd699799fd2b4f716b5bdca7871564c1a37e6d8ec91440fd30a4d" },
                { "ro", "de0614546e6d9b4f2b5a6cfffc8dd8e7dbc6fa7e888340c6d6d7e80884e953f963bbb7996709ced413c4aea149a18462adfacc867fd2ae501fa848e54bc814f3" },
                { "ru", "973c096f9318a2b7a3faeea4c88bdced494bb7afae47423adb7eef22293a829da8b1df3d225b0909a350a7756dbfddf81e20efbe720ba4664e4bb6ea4292cc51" },
                { "sk", "eb76ea952043b7bea6e942683cfdce60cfc3ad377a32a83f68bcc534cca97ed33767cc9ccfa9d52db1b299b1fff75f29b571054bcd36da453556ae8918a094b0" },
                { "sl", "57578065cbe5544de078105a7ad5d6e5ccb6c9cfd2a116b8d04bb61cafcc7a7995549d4c8aa20898fa796c20f7bc4c271294c0b082782c83b537582e9995ba6f" },
                { "sq", "ac5849cd91034cd6aafbb28cc1791c19aaca0b4653c869dc2b395dee85f5f96a4ae20dcebeae4bc5a2194db1c861255209f5b61956bb04c34c2415fdbd59ed92" },
                { "sr", "50fdba47fe1fe75b091696dea6a51142297c2fe03013dc0d4de8199fc4c7f52b81f37a29b5dcb62be91786c58d1840fbf7301d18d5cc61aac5477ff8d2b24a15" },
                { "sv-SE", "2eeb13bc76dff1f0622abb511f7619c168a9963de19ea5dae19fe8b700e110e3fea104e37bab397e77ce21e10ecef90f6db1ea22ddf80fb11768b8bb3503bb9e" },
                { "th", "7cbac6d5d0c5a84063eee321a53765bb018430974a4aea222eca16853b8159621727f6427a06d202545abd86d76a52670a739f269f343b72be43791748314c63" },
                { "tr", "061f467c5da9d730b6fe5c3f61519d52d06f0feeebf0fecebdc742241fab405e00681b2692c37fde072aea49d1b590557a61b4c16db50e599b034144b69382da" },
                { "uk", "a4064a9fa03da55efd547971316204166e52297dafde05fccaeeee44d7157258e5b16fe9ec002e7d662114b328af7b56e05fc6b4fae8df6746bb9595fa37605d" },
                { "uz", "dd15589b5cae64372765e4f5ef6144dd419fd66019cd1015bfda6a136d005adc74254032c152813f0d2b89397c777c8ecb1fdb652d6282bf19af73b9b7771f90" },
                { "vi", "66c9e74e83b35f786398fd3a9ef629c4ed06288fa50a24be4dbaf3809eda3c2718da6c1ee295bd2d75a2f9f2ef70f990f0a8c4c572a81e18b185e2d10e09fe6f" },
                { "zh-CN", "38d4c8d3706ef584eb05eb52ca4f0fe4a298dfdd4e3d988d25e2c853934f6465eb8c7aed12535a35aae62760d9c813dcdeb71e8a5fb410ab19ab4ac68078d5b6" },
                { "zh-TW", "6b17db68958ba1ae1f5a44de10305b54a962bd3b314472cd38d886284c0aed8884c68b0c8d33b055a83ad4465fd3762a52265602bcb80883351e569fa93216d4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.10.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "2e68553c8d233ee93709b5a0a8c5e973786f94e6328ff3e236a29ed81185de4b25a93149187e72856f6b23224a77d37b7aa8851642e70ff8986cd1619bf0039a" },
                { "ar", "8f7b72c7266cfb0998add414b527a345042007abb9c2b8b8daa320260c4d86931f6ca800430463ebe0386240941f1d97dcc2cdf9b02a718187a96ea2b3da1a07" },
                { "ast", "7596bdc423d894cbad6c681a02e0420b0afc05607fc7114ca216f7e1548c44957c4ba705fda9512fbf36dddc4553e2ffeadd71d7cf6190f59dc03c8bb6ba9a27" },
                { "be", "dc0af577bfa9d0cf2408c6cca2fed2163902720978ea8d730f6bfde7194ab710380b31f839da1d430d33742486630956f394c047958a9c77d16f9a90b66a4e5b" },
                { "bg", "99e7d376ea73372cee7cd623c22853e062a3aaad38c3cb224bbb9f2293e2b60d49d732a68f54ef6ce4569665e1a9286326ca0a7575cfb789560967d0b3c64731" },
                { "br", "80aded0a0a1be5102df73cd168d6a305f956edb21f326f6406db3eb5333937c1857b57576261c2e60803b6eab29c45755cb00d24a6baa109688ba700a47142ca" },
                { "ca", "5fbd7cb08d866db49087089a4b072fb919203e8d97f52ba8e25541c1efb49930767f4eae16290e1667287bee8fd3d0de4855f3f54d59ed23099b87ab50896fca" },
                { "cak", "6584761462d584cb345392fa578d9b6aed141afe354bef78f687a9e99d5cea43eeb7aa4e542e35f1996e3bfa524feaa52885807c51a7b8fa368ce89ae3b233c8" },
                { "cs", "24136e75f703b5a59b0b0405eacd5addae895a383d1035abdc17944f583eb9cfacc1b14de599000a4e4458a73a116c560e6e79ece213824f983442a96824bec5" },
                { "cy", "33f908c5307f635c5f8c033a818751618a63e6ba65f90f079d76a41bd99e8a7fdf745afd935ac3a5d893e43018d82ca54d1ef5e9c195da03b68094427d8e3d88" },
                { "da", "8b9ffc770ec7b209bfa7aa6a6ea7ad95cfd132a8f0afff0f97ff83fa039ed0cb265118828884c2794ec9f7836c688f4b1d3f98686d4d2c808e1ced7112dd0842" },
                { "de", "c37696aa45460c1853f4f9395434f5d8f2dfbf2f8a608c797e9d5b2a38155cf2ba3872752e34c7aa9afbbffe69d9ad12b16461162b8b3f9cbe6c79f95cac0bc2" },
                { "dsb", "67153f257343671e4e1470a7a16860448cd012d77ff3abefb7fcf9d6c32d622d68bd81898a2ee01e3c1f71ada879d5ba79a1a399746d6511678db2cd8868fdcb" },
                { "el", "02ba1a4d9dce73414ace64701e4fd512c26947d51b160133909bb0c18e32379b39dcf6ac17ea4b3de0e164e0a6ed90a8a969ad15299a682773f786fa1881e702" },
                { "en-CA", "5c9aad3a0a8eec8ec37db758a0edbb8a31f595bb7a1dd5fa28d79fd8a0795a17c38499a88eba604763b5e9978349e2a03465980b2544f79ad2abc2a54a98268c" },
                { "en-GB", "54f0be0e87b2df20051ae2316d3f42e70a99372b65c8a3d20e04489f34c02e30968c079a8922e2380862cc8a961e8c958ed68bb383147611dcbdc10a6dec8eea" },
                { "en-US", "9f902ac9cf9dc2a37fa61159805e1e3d8e16f71daef5fe949e4f115dc6c14dd508d98a270639ce019388dc5438278ae20555f3e5d1874d2f978e479f4647c77c" },
                { "es-AR", "65733d7212f54c24dc30c72de3025e89a997b07b3efc5d01a6b76a4b8cb2f28ef49171bb2722d9dcc542d22e3c8ae86ab1af0bcdec28c674c51245fea40a6871" },
                { "es-ES", "7b9dafd013346fee684243406096f461b893bbacc5cf48f5c236edf561ff731ae19abdb74e8440d850ea94a53e7ca966e931ba80858ac494a90dd7939bda6f32" },
                { "es-MX", "b2ed05288e94c25f480b466883bf4385ea23f81ee061ba86bf36c3cb9b07bfd6d257045617502cc53812c39e43b58c2e3c43e8e753fc977538d9c239d1e70d26" },
                { "et", "1c1bbf011a8676c53602e35a8af80139bce4801a5cf2726d853a7359a682500551b696212a588d39fa6cfc7b95159109e1f40bbab11b8a21467bff36fbb906dc" },
                { "eu", "5f2fa0b94da2243de4f2a71ebf58477563a4dc8153427b087b3d2dc3442507d40ab6b33bf90d0a60f1b2a310776fdb832c5bc860085e64b3f139ec28e810fd6e" },
                { "fi", "ffe72b07ba28c01d4467ae3a0be139eb9f96bc5435279daaf58871bee78fc1a95c98a431ef18573c6cfa872b2395ce5e626c93a9e1a06fd889b0a37e06181ff0" },
                { "fr", "8450ffb7fd742880fc58b817f78d0a721b8e491d404f1e897ba0ac426a52a1ca3e5c8a73cbda65276d59894e602debf203c7be9e1ec044c1ad532d00bde60075" },
                { "fy-NL", "6d7cc50bf7e2858d3d3c073635a7499d34f968f732af25c68535693be7a894d5fc1bea9dfe553b6df107795bdf47ae4fdd90f0f082a8068c79872e9e3b7ea30d" },
                { "ga-IE", "87b750e3cf06b0576d4b628b058522963e5e7e65952311ec1ab2c500768c7a40ef1d179d348f105d2418aa90df8440b70ba21adf505d67a8a5970164dc40b106" },
                { "gd", "c43595f3dfb4a3092911bc77f805002d2bc9d4dd2c63419d0c2b53dadac70a9c0a54231e68b15b21661992b266d7a5938650baf0e9e899ce0913ab59bedae094" },
                { "gl", "f83ee828d315b2d1859b5b9589df027c56428e5caebaedab8c8d693427f153667f88414b795ecfc0b8bd3761c59ac45b4836f07be7261164d40c1dbc55120035" },
                { "he", "12c6d9c9ef65ac465c8387375fb3898325286e20ab088ca197b75cd737ec803329c47dc7d6c40f63c5717e69480a000552742c67897efcb02f0c4058269eec54" },
                { "hr", "27b9410de2a3f3fff8632481ecbb25f7f60d736285a02e4c35d527122ca1a9cc3d70276bbb5721daac126da99bd52b2a28ac742719ffec7af37bd3ddd6935f13" },
                { "hsb", "0fca730935a9ecd3ef90f50d528fb084df70c336c2cca4abd57de25dc5a65de8755c2819a81f5d5241162bcac1b90735ee6dc7add35b3d92e1e6ac18ea1e25ac" },
                { "hu", "6ebb1d7996cdd174ae4fe252ffb36c5bffdadcdaeec9b7f352e610657d324b08b10b64cf0d21604289639dafa47ae2508c1c10c4c83dfa9d796323dfde43ee74" },
                { "hy-AM", "6626a3e342b1b9ba9ffd27290b1e0938c640ce4f5243d429fa326e000fdaaa4df66821d22ad16eb6c1b20d5bc1b31cd78f613f589fd9c3fa15f96e388b75a101" },
                { "id", "6f69b60b310d9dba4b6d2240d1a3ddbc143be030f1cb84ab17fcd35162c2ca8ed94f20d4a985d075c246dc2c10648ca500242e10b2c1b429511f19b1960431aa" },
                { "is", "9d2277782603da44e7bab2037ffb2e37662f894bc51f5ad47c337af6976484c02276b0018a96d78adea1edea15159b6ed2a0733f56081012be367ba79c5b8e35" },
                { "it", "6d5eca233e9fb5be7cda022d9a9aa598acba694edc13ea49acb5f1355ac6b547d6b02332372f2539f15a2d0116be4de45803eb37ab495e8b21a9eb5c3488857d" },
                { "ja", "80ae11b4d6fa3dde7376eb83923723bb4adb1aa35e24925aad8f1ad2351f26c7ce9a93c73f55917a835c7084c708334e510801c657bcb866065918ed3ac1ea20" },
                { "ka", "4ac0275aec14eec2da8cda8e43266962ec5a9cc020bf08dc4693334422e4870d536bd340936b61ff0198f6c3d049165293dba70af8d2c012ebbe91677e1b8791" },
                { "kab", "0abb47836aac52732f0b4955230d13f5c05c32878647edeaa1013b009df324060430438d9e1a7c903b01fa22395986e7e05dc079948298721e961928f282d6d5" },
                { "kk", "67b6e25cf4133987a9351ee0692351a186c45320b0abf78eafbb9cdce561615c1bf861733f76fdde163ad5329969c14ae8c98f6615665273f6988976c451dbb3" },
                { "ko", "a36daaf47cedb50c113fccdd0133f6b817409f8e67c8ef697f7bda12c44ad2775ecf3690bc0518457a8aee0ec4905cac2ae5b79075be95f05bdc952aa70f6b74" },
                { "lt", "a63edcbcdfb78cc8a149744b7bfdde457beaa3eec3f00112c982a32fff48767fd48cb183e1b8b43c5126fc81a824c8a1ca58dd826406c472dfbee9afb16ee098" },
                { "lv", "29aa79a21c4ab68ae19392b13857fbba825c01570b6944e3df4190b5844308f05097a4ee06be52fccc2389d1ced71efe09625463d8347423e76452f2f8f18828" },
                { "ms", "ff9c26dc4523cffa027feff96f4a4b3b3d9183765b849aedf2a41d381482dbdedee062d264a96d5987fefde317018583c6a4978757d6a840cc7ae52405517da3" },
                { "nb-NO", "80db6ba955bd41b4841fe354f67e2fd27dcd23b5ef089071bf04480e1135920f3bf44842ab31398edc7c6abdfcd077622bd0861cdb9494abe724afb1118c91eb" },
                { "nl", "4be9e920136ea4b8884c03b1679ff2e4f26d833cb3f540906093c75b3a8e83cc824f9371ea057432129805cd402a357ea5bc9ad211495770afbb92c4bee6a5b1" },
                { "nn-NO", "1645f4cb437ba7bb994d856adf94cdd21f19972c6b05d8d315b8f5a2a2755a403ac0c9865ad41c5f7a4bd03f2c1df223fe0c34083cf6d43e5185d1b9aef5024e" },
                { "pa-IN", "843126d5c17558bb5ff60e99bfc944a87f5f26d29c18fca4f7286e2ee9c1e4d6948d7fee5a26f2440b9b4ecea22881e5dc05811908e6180a2ca8b8e48a7d3ad5" },
                { "pl", "36b599738c2273478001656f2e65eddf1ddcb51a3dfac4de4a8bb3538f79d85478848c4c9399082ccbe9c0f658e258ce6492d1b09ce91423177d2e8ff75ddc8d" },
                { "pt-BR", "1a00172927d55c0c782f41dec2ff83308ed879941265f4627e7a65da96b3648a2a5b804dea901945da35d0301eee9cae25a534914bbb394e081e93d549a4cd47" },
                { "pt-PT", "aa1e5ef25d58f39f1fd1531fb35793845eaf07ac67c1190dc3dceeebfcde4114bca65b4d63ec666b4c153ea325b3f035e869ddae1e21829d1d751566f86e7f7e" },
                { "rm", "60b7d444355997441eda6d2fc026c34c5e279b49a1406d9ea49b44360b8417b1398abd91a59739e4b9493b77b4cda142d1a0f7bcfeda0b7dd379a31f59057c3d" },
                { "ro", "138dcb9079e0c555eb1756b075ff5128b88c5b8386d34bb66b8651263787ae47512b70765ec7a900c857c901a64fdbc183e2f28a2c9a4f277ab518c61e8934a9" },
                { "ru", "3ddf19d5f9452f19d519af6a617b0128ec43eb70fd199562056675e147864b426dd78b35bf3eec73427ad3b9db6760a27414374e986293f2dab159ead84c6d11" },
                { "sk", "8f04c1f7ac19f2052624c80f7041a6aaf700eed406f61ba8452cf87299c5267416714edae7a48121edd154754bd2a98efa3e11c545b7d27ca4cc8cea11c0184d" },
                { "sl", "6b333ed2cdf123bc7b66cc6401757805be251c80384b8c8fbe84708d7ba2ff2839582e83b03b3780ebd5e20b33deadf21ba2987b5e5d32c06cd8e37f83277855" },
                { "sq", "1c9698c93a59bc54e7779043ca7150ebb03ccb3fd5d061bb296f55a39cd798ac29a2fbe32d31570455831a935f6e88f8cfa50ecbc360165f47605f3ad8372604" },
                { "sr", "9761a3cb66791241f800ac4039a49e3f14ddc4fb64143e6bab744fb68c547325368b3bdbc0fb959d696591eb73ace93501c749698b5391e4c315ffb318213583" },
                { "sv-SE", "1b77010dfbd9a2be57a5286effce911f307c601a667fbb98ffeab1d67b5738cc6308fcbbec85ccb8edfc6e5557ef666b661a7fd208d615f76c0493a66ed3f84f" },
                { "th", "0c8112b0fcfa60d9e6976b1c2a58bc7b32fea0de5378d5c6d1370fc6cfc0e794408a0cf53fa41e02a991410c5a093556c4c45354dc11c79884a10f2861ed7b82" },
                { "tr", "24a6346536af50eaa0854bf52a260544a7b524d4dabe82ef3eae5d1e77142d4c100650d28bfda440d875f14b7099deb50cc937028c775dbbe2a32bb753a3c421" },
                { "uk", "e1ceb8defda17096b9c7b0797e2370bb9612ab43a4d9544373e58de7a7743b973f005d5ef2ba21c9f2482ae08280907837c6b9c4c858dca8da0fa6d49a79dead" },
                { "uz", "87e919bacdc36dcd862b64b468368bc072e262043b5dc9c8f8782c8bd66e4037a01e034fdf2f3c7cd1e2379e456ccee5e3370caede89775cfae9859009bd23db" },
                { "vi", "2ae200f79493607aca370fa301eb45219a851ba11f099863ce955888f9e751ac60bd5ef3d4e37aa5550c15a7de4b4e895b04d6ca91f89650cae1620ee5c4a43d" },
                { "zh-CN", "302ff5ed6e1ca2a95bc0efff7b332a3e300afd0fe09804810e43c2a4516d5b8c257e31f89752d044236bcff8fc0d54ad173a392c54eeaad19f5c2b1a69fddaee" },
                { "zh-TW", "42093bf0cb6fe5aeba08dc9d608335a3fffb0f2ce190baa3fe53bf17fcfae282bd108e1ee93cdb0ac519f6105de574a159301f47d156f1aa7953e18d9a094c0f" }
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
