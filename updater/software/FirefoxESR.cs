/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.5.3esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "8035021bf108d890f5e13fe17ca21e54ecf66e982a52862f614a6ab6d901f7ed1fefcabeae5e0757a588fc22b08e01b88d2723ed7f279d15d0bd2ef8883accf9");
            result.Add("af", "8db946615e0211491d92c81f6a6f26e1419e05f104f20efe7e2f2247d4c1845868c6cf537e38c6987b65e51c0456acbad3b1821502fa9f9c0dbab7de4e2142b1");
            result.Add("an", "9d3dd0e6799c1147f213ac692f5e10cc3914ae0dd11c0a93a9197472d7f75624a664cf054ac8fd1e2c26c66adc93dbda58956102221a9a61f8f10086b2065b5b");
            result.Add("ar", "4f6e4423ec34b2daa99155b58552e49734dfcba26e1c59f578cf78e66991ea983beeebf2176143ef7415573eaa00219f9cbc322f05ff0feb9ec63f7075946a6e");
            result.Add("as", "6dd5f9ff1ee03f9484362361e39600f9008ebcc85e3149f06afa30bcf0118a784f8f65e2a5724df48e29d36c6a7576e3d7eaaa58af7a27101b98e5198014c8a1");
            result.Add("ast", "b8dbb0791d2b50f52502a1945431760ab06b7da173bc83c149d94c22c0baf1c7e4308bffeeefd8492bc41188cf060adf1169d4d8471be3eef5079df9d4e88f11");
            result.Add("az", "7782777d7940374274e12dfd3dba4a6fe26f1d495a9720efb012db7ed9e5d4180486690d750324473d5368a1bd26a579c993e23b45806fe98999bb93b91e7d25");
            result.Add("bg", "3bd7ee776bee6ace66a0c5697c79f48cdb4b5b8401ae6a833e420cae781ad6d1467bd126a3086d3f8559d4aac88007e5009bec915616247375da46276ee7611f");
            result.Add("bn-BD", "46583b5e03ba9bbc0028cbf0308d0f5eb954107f606140da573449be06d9c58de63dcca2486e8d42325cc106abcfd3073b512dce4755de8cd8b0a87eee538add");
            result.Add("bn-IN", "c5fb21c04db0aaf6de6a44ba16755c7a68b50fcc424ddabb2cdbef69e65b740cc46d32b757869f50e80a005be71372ec5a397f0a6f37139cbeccb9db8e022a43");
            result.Add("br", "7aae38040b58ecbe1da8f99ccfbcf01b981933b6b25db1a25f7292cf25182a6cace5cc15557f263278d4dcda2214c96b2e51568d6c381750f423c89d4ec97ba2");
            result.Add("bs", "d60fbaa6f20a5a72c1c2ca9a51a1fde77ca8f46c61dbeb8528bb72ea6215aa6989af4a8b19f8e54cd9cdc0cf343f02c0a41c602da57733f8c27f93cca87ce4eb");
            result.Add("ca", "a16e96b5ba000ca4294743bd17144e055dfcb35da54fd7ac05b6fc7fe059209ce884fce457cfb39de2ceea36287e6fa02b5b61da0ef2653e1f173ae3fa520dbc");
            result.Add("cak", "851e412f33d7bf99b884cbf652a4ca788f24c92a41ac9895f0b46a7571df4fb7f7ffe90ae8b791dfc32588e573f84e6cdc489ae3f08bad6052b0dfa5130c7991");
            result.Add("cs", "faf92eab0d78146e16148719f84f782ee4b2183a522d67be8a2fab54b07c422a8ce064a7091579b19238b7b9c856da3458c07dc24c56655d40fadd4592492f58");
            result.Add("cy", "cf25d8892b471eafaa6c96b541c8ece9ae5506895d8039e5ee0ee8c1bff28084aa5c5d2787db57cbc025b69ff97a00569e7d35f1c6688eb75db28d75ca4e84cb");
            result.Add("da", "cf90b2651e202e1e051ea956892a2789eaf28cfa696f53ce501aabead8c3fd3af897f49d4b5f3ee8deebcf139917ae82577d7bb600f85d3e51e1d2701d0c80b0");
            result.Add("de", "444d73a1181abe39dcafdeba6ddddc4ec3055afae2925190d446ffe3152e7575a3fcacc874fb213f415f8cfd2fd32fde267a5e59e2006ca536dfe4959064a1b0");
            result.Add("dsb", "701de157a8babd0fc1a7ce52db3ee718ed98e2910919d8ceae1732aba85d56c820951cb1d80652529eab618c06120777c1490758550d578a3884f81f3b1dab30");
            result.Add("el", "373206ee414040454c24b8451120422475aa6eb301190ae0e9a9fddd5aba16186b2b686758f23ba661f21b1e722f72a0a697f4940e3194b9743bc06c27eef9a9");
            result.Add("en-GB", "d087fa1095183af8a6e788e660db94a21367d654ca5f2f22642428540bed5092173769015e4d35b33fed9482f65d7675a9c46338803c83130efcdddae597bd04");
            result.Add("en-US", "594e0bc41148379cfe5127b7e62a45e3b15d0dd4659f3fc302659a5a9230d1d195c137c1e3502f113754ac8771297097c02ce1c82d7752b89a03c01b2a936e85");
            result.Add("en-ZA", "434c296ea7c56563d2be73eaf836bc5ee8d1099183aff1c599239cc95844f160adde1e61d8b95554ad1c5efbe9bfd1185957c497c21b1804b2c72c42c0774ea1");
            result.Add("eo", "ddf9d012950c61378ceae3e9e41947dd8bb740330d80d1b8ba305bdcc7cf46def2fe389cf761c2104063e48f31f865ae50b737f464d53136c12a7808484a2687");
            result.Add("es-AR", "ccaf237ceda3a890af682ca5c48f6f134667bfd2c9cd62724eb4cb27dce6d47cbbe9adbe7bf44df9287c6326d6d4c661b4b3766d834e3e8dd54cda7d4a6d96c4");
            result.Add("es-CL", "78c07cfc6295d584fc48db3d6386c6edcb132d174e7f65d7f0edea0fac20e6507bbf61be7c61b20673bb654ab60f4752043d219ec290f02cb24ff15e3946c8bc");
            result.Add("es-ES", "407d5ff6e33862f9671fe742ff2c048f7d99e616ab444e144ee6b960fe7c2047d2cbbefd273a20390e854fe58b9b6a68d5546de70f0ee1fc464cfc2a1fe8aa9d");
            result.Add("es-MX", "1a223940fc0a4ce45168944eb33d338769b99e2b764b28835e6060ecd866c926a3dcda3c1002b36a676f1ed2631e5b769665ede6a7d67fc1b40776dca4bd5256");
            result.Add("et", "813ba43e842f8c0ce6a28c8f4252df3655e3980ca8072b5d825330aa70460b1e7b5fd0950c49151c9e9d89be829bf3ed8fed758684c39cb03b6c77c9f2bccf58");
            result.Add("eu", "d2a5c84683636297e2796efba4d5d44588ca6534f3aae3804dbdeb495709e86fac09d71848793152e9e3677373019e9fdadd25c1aee41fdac4c16ac06c85b624");
            result.Add("fa", "0ddce6da67a97511d1408860aff1ccdbb22f4cbc74b3825a49bdc76b721020c854f00fea752fd83697a2ca76234ca3b5ecb751bdf1c62bd2934bfdd9f4883ee9");
            result.Add("ff", "48817d33c8588fcd64927dd7e6c32d98e722d11c1f18f7f8b902a7e7da8d8b9f772abc53a6aec1de5f1b1a726ab0abd7c91514fa3e5d5e3366010b99d05c19b5");
            result.Add("fi", "fcf9e56c11b91039a2d83a05335de758d78e7f40e213e81fb460327a4d5289d163c9568b4ca2b9958268241e3d067bdf83f49e52eca257739024c186d6b7a4c9");
            result.Add("fr", "afe7fafecd8a5b6194ab4f3afe85a341bc9fd778f15c2ac8dd6463dbca3ff183c59fa9e969861b88a8b3d5c6ae7fdf7c3491da1ce79558391caad162b2a1f212");
            result.Add("fy-NL", "223e8e1d076cceeb5e9705827f0e4c322eae77be31d5b303729be91215b1b5323b846ccf3857c14b443b4e436ebdfe5fd19e72ec085326599e7a97a47109c3e3");
            result.Add("ga-IE", "9c05e1e24feb8611ebd0ea1f190184de2870d27e345115aebfcbe557322c8c4fd8b2d57445442ab3304d8e49bce9e05199c3d46876b5bf179fc97d61646632a3");
            result.Add("gd", "5d94d344bb8534292d0ad56d6b09f9119fa73e015de9b748abebe57ea868138ea2e47900ec1991605cffa505b827e4b8e4d4fd530940a8e1c3c99bdca0146bd9");
            result.Add("gl", "bc9dfc9d3714b72028b2c36c652cee942e650c119bca19ce2bb7af81ba9343259407c0651268e62fee87f664f254924eec7c86fedfe26716991e8c2f55bc2493");
            result.Add("gn", "55cdf5b86795f8e5c389994cc494a7ae6cf9efe9936659e527afde79efba24891fe852e433d0af943f5588470e8d9226b38092e58c4a1da6e5acc499b628e938");
            result.Add("gu-IN", "b1195fae454193fb09f96100b0f4aa3b2f1a522c0ef579ded061369fdf7921a774374c5e3e006e29cefd924cf1d27a8f25d5f42b5300875a19e0e7434e52b75b");
            result.Add("he", "0a637080c6b10e56174b63e82246154dfa7580c175c1ad520802efa19e6b72b4e973be74b52aa07ee116ab7ab81b5fb6bab9da433c0122350aac914224836f7d");
            result.Add("hi-IN", "30951c014408c5032b28155861a479e07f3f3aaaa5e7991d739cae10d1a9e7416bc72d8d96087860499f3443a7734b5a6b81fc9a14053505df82275328ac56d1");
            result.Add("hr", "d7d950cfa63be1a846fedb7518b0e23be0b0fd5345f5ab42da3dcfdf9050685c0bb068cbd4472196b62e276e8ff91175e175c2af51c5aa8d48e069e7d20930f8");
            result.Add("hsb", "02cfe81425fdb2f4618c612136595975ebf3019b20342e948875271d39916db3b7d5359a5d9b5ca4fdde170973c0e8ff9d35770173daffced5dbe15a918030a2");
            result.Add("hu", "a40d3c832e318575f2b94dadb3ac0a4b79d78ffd8c486a92fc3587b04b068c1e89607bc14c414acc88960ef3aa8ff961a2a8d875a2c54eb64b7aaad430f56b08");
            result.Add("hy-AM", "448c7ab7cf335ca09fbe192d35a3b829a741b13c57d7b07dfed5eb97e999e92eea01a12dc586b9f7f71770b95ae916eb21d2ad9c4207c2a3d28a34773938ecef");
            result.Add("id", "8f89a03a9ec4aafe02f1dbd4d097e17482d4ad8bfa24648de50a84ab46d3d3554651d1dc2aadbdd6a6e3700597ebb1747dc26d190e4883274f0e981be6ec56f0");
            result.Add("is", "9cd9c8434bbc14b9d3c2a18272d9ef61fad284f59158fe9a1557427257fbaa432dcc18db4c73fca2dc4cd17e033d5ee47bf12f8d55c39b926a8adc9d91c1b12f");
            result.Add("it", "d37aafbf946166071dd52c0d7915806493632e7c9d8a6563b38e0051200cc3b5de503dbfb1215278c6e9580d4521e4804dd22ac557d1bac62c2ffe3f573d7112");
            result.Add("ja", "e0464bdccf1765d107ba4814907ca12add13740f23c7ae9f827e311d2b5f293976b8c72ee7574a133163e026abd61c50578125d506a0564eb2c5fb1b973aadb4");
            result.Add("ka", "a7038343062acca5e2c3b9ebc4e131e314e5df4679e548d848e2462632d45531da6dde6ff16e850f1eaf4df1e753b164fe77b340c19a8fbce478dd5f8b33a3f4");
            result.Add("kab", "10d8047f92e638036b094b6beb35e30823aca30ce51c2304a890a6382269ad7f7f13705569775fe4583f7f5aee1c727c6add4e505ef8052fd685569ca459aab3");
            result.Add("kk", "fba6a6c6976ecdcbfe23e6737d5b81297910320206a18d2b1baab5a825ae674e3f96d57db21448744351b8bd27c2a302b04002f2263016770c5c1757a5a0cc15");
            result.Add("km", "66fcc37793a00075313ab6d56ca88ea162a27ad5e7f3b6b0aaf5411d0a7b12de262cdffedcd79fade9e0de8d08ae2e33dbcd1ba05ca7cd67ef3e000e9cc315cc");
            result.Add("kn", "b07ec23c0c5e52adbc68b06c17623b224da42dcff63fa02b2d286cd04f7ae32e586919fb4031fc85863fa72812774acd9dcdd94d6e7b6da9fb4b6ec7707362de");
            result.Add("ko", "80d5d328ac23159ab6c4e39f6d7dc5889fef9adf358519f6adcc49ceeb165d92803246926a74113d8de5f6f192f8b592ade41ad45ffa0afc66418e8644feb271");
            result.Add("lij", "233c91e63dc71599a7118af022124e97052b9f77ec13ef44443cb8d0ced31a10a7fe57b20822cdab39671edb079fa02c51c28d1faa298bed6e4da8d1db373085");
            result.Add("lt", "496fb22196a00eb2eb9357ae6128173eb0e8f877ded8dac10f5bf933e82d1d4dd149b3096ce827758f4a4595afe99bb2dfc6a8473ffc24adaff2bac5009fb7e7");
            result.Add("lv", "f6cf1d26b1fefc201327aa3b19d5eb856d8ea7d3426c75cf5fa7230532fe6a4c1ab30fc2cf7d2ebb2c84c37ff746aba1a339e6edcd7b00607d608501349b7fd5");
            result.Add("mai", "676f00ca2b426b6691296b60334c766754f34e8a910bec3b66948046eb468618d0b25a3c7221cf5213a4ef438ccb32eee42215ac19a16a9f7815253512c7b09b");
            result.Add("mk", "21d78a9e353f57439771d8f4df60e42fc4343d80b5a56d54eaa62c24ccbb0ddd7f27760a7bcc6928659158113ca7ca2047875f46e011aeb83e3f18a3919de85c");
            result.Add("ml", "4508944e5b5349155cdede4cd7e208a3d769cb89fb63ef38a5b757b7e77a6c2118ab10fd551690c09b647b454203a7bff38550e69de345df68ff29f04ff0e9b9");
            result.Add("mr", "3b34684b56a31cff75d4a5793df386fdb7d5345698099d4aba6f7d33f26a5f0a8dfdf388a1e56222f560b81d39dc7f507dc943d06c98defb49eefb9f72742c95");
            result.Add("ms", "72b2012486bd4d5ed707a3cd4498acd11b4bcd5d0b2fd450ec43e7e03f71d9bef7ac28b9631a3cd139163ddfc6e4c32ddc441fd985d5eef4a06682b24a419253");
            result.Add("nb-NO", "8e7624417dc1638f83c52c059a94104abc89698c4335a5ee7dffd987b3b9304e80bc66d5bba6cc816d3e5ce6783619d406cf3ab313eaef3f13139d0588bfabfc");
            result.Add("nl", "023491beb97146b9e5731bf42994172b1d36c7d6ba94db15b56376b2682b774f2ca6dcee653fa9253cd2b038a4765ed6b00e7685a582822ea3bc9bb5a80add22");
            result.Add("nn-NO", "496334f6bddb71757a5d0703eaa8cd27e60eca102009167b240bccf973b4d852c853baa0a91d4e1940fb5633c5863de32579a69416000f026970172a044141fb");
            result.Add("or", "6d81d404be54e6920bbb40859ac1ff9b63e4c808ea081f0193abfb3f6e67c8fc9804739e0181cf500306b1ff5ef6bc3ef4b698623a687a44c4e0ad9429e93ee9");
            result.Add("pa-IN", "fc2a8a668fac4f229ac569366b944ee7723cc9100b12aa2540b39090260b57aad791941a7238fefd3c09489715b3d3ddcdfd682450b574ebcfcdab34c0b1c4a2");
            result.Add("pl", "1ca8fe4d3cacfd07ac0d231247b912e0b6cc62835c5b4af6e4011768b127903872b2a80c23f99225c860880e00d9fc1e43e395d872a9c0465433bc305d9d98c8");
            result.Add("pt-BR", "890a0730e8f7a9ccd78acebef1c8f6ee28455973c1fd1f8dd9766ec58f339f78c7b66f01c87704b9c889e4990886cab0295393269f42a0beaf1f870d9884b918");
            result.Add("pt-PT", "a4a6ab94f7ad74180393ba2fbcf8fc20ca111dc9e8072d150faffc5e107963e53cdaf8a12b79b56bb163ab2fe9da2bbc5b8ef5fc029721960dfe44ced3f6424a");
            result.Add("rm", "cab19b47d731a0c9018b389160d25825c6e0912cee08b7390222121b8609149d40648356ae0e09fedf75b69f282f45e73648aa1b805930ed6836a73dd4152bce");
            result.Add("ro", "89e69c089c43d4ac8d46d39289e9df2a3e21e148f3b21dd9f534f807d482593c650c4aa21a1169e057bf938cb8dee1fa31cdfc54661650c64150c721957eedc8");
            result.Add("ru", "b7201e9ba791d29e7c1199c88d067cd6256c1c6a95581bf8d65a30b21d8c7248b838d8803df038ac776561c4053c427a18675b62c27099125ea4c065605894a3");
            result.Add("si", "bf83060dd63fdff38d14fb2d30964140f420c310c8c09da6d185b492e3c5f357c66fb9994cba2a0ae104d08782b4a25f4a944970c727c49abd787fcd5d5e14f0");
            result.Add("sk", "d320c33c472a888bef127837da4d11d0816f53a8bfdc4acd2d377e65ae90e54ef2f15227a0cf32f5cdd7adde9fffdeda5348073ce192dfe216cf8c9df9948df1");
            result.Add("sl", "56d0a77d78dd6518c475556e6cd9909e23811fa39a0bc669c4d81203006d91bff51c22c89cb58a4b6f78b9626ff690b5ca68983971ff29de57f7d956ada17ba7");
            result.Add("son", "04d8e0ac1219e40127fca3e0eb2018b462fb0dba92593f232223eb2298480100739cde261bf535a644b5af6991641a763fab55ab939d97d8db0c5594f7e8d0b5");
            result.Add("sq", "c7025045e9d3de8aa21b3dcd999f0e6f6b158983591cb0eaf6f3ee7727501ff95c2fbed904f0ab41bb1884bdb696dd1618968b59945bcf902ba6cb545b038344");
            result.Add("sr", "fe588c00cf1c824262e4cb0cef19a4e7a7551c3dc705cb229a0f989313ebbad1a4ea11c9e08ea704578b724259f79ed4059d6ec1335e8c94013f56ee7a2f2857");
            result.Add("sv-SE", "1d253da2e44b49284f7d4dcfb5d748a4e11c735deda52b2d526a902b622bcc1237e2f00a9157f40e7317cc97c8a632d91a922d4ec88bb5d6e3545efabe4c4724");
            result.Add("ta", "8fd72eceb5099b9e5363878d1bb2f7b473c361779b76da2f95a27a633acb646cc0c29cbca489a6a67114e9f56c3d4748625c65683854e48aca2b3ed9d6ba29bd");
            result.Add("te", "ae64d0ac1129bcbb2d22739a0b85a1a85814d87582cf158fe4a2dc1c75d02ee571241a071b66882bae5a73b10acea0a8bc3ccda8760f4b104b971d5f6c264e31");
            result.Add("th", "73cd2221215dbb9af583ec297ba5e1183bfce2f64cbaab6acc0818cef713626d362c0c24d0ef23b8f1a8f6076db270eb201c99f308cd489f332379be54c058fa");
            result.Add("tr", "23882bffd85d7c34d70c3846928e141a7cfb55ba5bcfa0be17b541a500d005cfc754349682ca7816f1570e417705548247b9b6882e3c697c31153491e4ae7ed7");
            result.Add("uk", "bd9d901bb932353c70d161bd4d40f7b0c60cab328cd542c4ce87b9b67b7fb253a95db0be8c2d6fd599fa0710f156421fbc4ad235b27dfd89e6edd32de439ea6c");
            result.Add("uz", "d4f5edfe0a1c35a42c14004c93a57c4022418b4e4b5ee6ea85ebd1f97409bab54bd8f5ec5ce308d6679f7f7186fc952e26beae513280ac959f59bbb5a735b2a6");
            result.Add("vi", "2376e531e7d509ce481e41c5e23ab1266838933c7cf811966419b7083b828e0760baefda46013fa7727d4774d6b4d080820db9fdca726d7f682192e1c3a10769");
            result.Add("xh", "dabeed515e4d95fdf1d887133da4e8e3d70d6bd3c3487684839e47eb28afcea43e7e2eb44b35c88768693c90f805781346657de74afa997deac383acd6d694f1");
            result.Add("zh-CN", "688f7240dbaa7b6c6fc492a48a0ac0294f00fc7643f9f9dbccc75dd2c75e11b0563987c1f8d471d6c30ddc47a0550c17b5db89fef68a777ed910f7793eaaf214");
            result.Add("zh-TW", "2f9f42931cfbb53418ff761a07d52d05240967bd8b558f38627b723d15e5da5bb58fae8a807f66af1e47f48494e4d4d67b002708b40f4b325f4f4aed652e7b61");

            return result;
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.5.3esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "619cde95145318f231e8c4568ee65cdf8c6490235e85eb0e09a99bd8054c0590ff16b5a2dffc3d4eb6cd3f18e078ce41cf4265898f0fb646535c3d57bcd28d53");
            result.Add("af", "857dff99bf5b54491af90260eefda9e5832cf1968b2de064bae860e3af7a3d53f91a6b49af27a143d27ccfd6b7a05d156743112b99fc2c8cf6af0edd0c6d2a4e");
            result.Add("an", "d3813530cb7510b04c13c3a347762d5be5feea683e90c751e4953bb6c643065980881d10f5aa53af9a742b521a151e130624266c16cd2fa97006d0b04f3bbe01");
            result.Add("ar", "435e43e9a1d1ad3639acc81fcbde4a6c0efb876351211213bb1a23364880b6dc5e3a85e58024ba6a2496d807f59c157cfb1415d50b7af6765267dab77b0d5931");
            result.Add("as", "2b854c1d4e5cb1dd8800224dd862e51affafb421f794dc6bb0d58cd5fddfd0f93be43fed1f0f268e99dea7b97c81d4bbffb457da41b1e478f6444903e1eaf4cc");
            result.Add("ast", "bb469815cb1eb8bebb644f3178319254b58def8c477822690b3ebb75fd4ae7a0b78b0711a34fe5efb1940086bc17fa25144e21106cae3908e904ecb13a76ee00");
            result.Add("az", "25e576fb1c224aa976cb08eca0919d3092dcc7a158e672b1a72b363fd48162e4bac2725e3720daeeb98e991d818256b35a20bff4caa0c6c1aa4c15e7afa9974f");
            result.Add("bg", "c0ea6368507d5b87f05d2bde60d58182aa63cf19b83182e4eb39e91fce46597971972379ace3f78b9bb07166b0bb6cd011564358e094e1e9ecb00963ab3732cf");
            result.Add("bn-BD", "a21ce797f10184dd9e3aee62d0087eb099d9ea2304c790f0e5d25316642fe1365344b4836186fc1da815b55f2004ce97d3efe4bf4e53bd380fe771e004e2808a");
            result.Add("bn-IN", "dcce751debbe96c5f9041d6bfa1adf7dba95a870c6f8e5e8f71969a296bf27aa0e496d273f2268108058638634026a6f60ac3e6f427c5dfa1f1d82ee616661fb");
            result.Add("br", "5a3f60859b1a5c567de4ae4160d446d614063d1946f05a4ec7788a6d7623923daa3b8b610eeff7e5341bb927e60f6fc85cf628a182fc0f1226a1ef1197a3f7ad");
            result.Add("bs", "2eddd429cf889e400bc845cd0700961bae76e87117794703e508714d3d908138fcca7dbd6056540ba6423aaa20173a86450c154be8583b432d0211597158f48b");
            result.Add("ca", "59d6ea61d6430a30c93b7ec6c302f0097916a3b5da7a6228da6ac64e2c4e3213439f7db3321ed6dc8782d9db37cfe5e752f336a330cfdc99a7ff98d444df238f");
            result.Add("cak", "dffea0b228a49047dd7cf93369779353cc60d19ca7308891b28e460b3d38a65b9057b8937d9437ba262b7ca70d6efc20fbdd83883d065b73d65777b012e9e352");
            result.Add("cs", "44251ae5aa59ef5f908efdf10c93e0d59559131b08cd13afc571d111bea1879b7efe9cb890e58755ea17db74253651bf070ca41f93481caf0e92197acd5f5858");
            result.Add("cy", "bc337dee3339c9782a0e7ba133bb4e87bd651c6456b962e1c7f43ce6787afcc9e2c1b8f0b9c6e85e91e796adbdf6e06f8f4b1aac3d1f49fbfee48428359a1da9");
            result.Add("da", "22f8e0520d8ca2ea4476347624b507f47074ccddbfad69f0f4ed71faa119aa045f521caf321c72a4bfbf7745ff6347bb8b8c208bbcc47630584a53dfdee4123b");
            result.Add("de", "b8ebf99be21cff2a1c3899b18aef6b86532f970bd7e8b4e28bbe965bc9d57bc51f889362ce3db75640781ebf718e10d10e66fd271bff937b23cf4385920e0625");
            result.Add("dsb", "47c1bd295f069abf0ea32d5e1b9e5f21b135add6f12b39b12864f959af6636b9091c26f145fe1e74d2925f1640d7bff704919927978fc11d5bc33be83b551a8e");
            result.Add("el", "b43beac0444e7d590bb1913118eb650a5795a50603a5eaaa6077f1d862a76e947b071895b0fba13c3135649a96afb88c3dbeef2e182e042320b6cfb64aa42c1a");
            result.Add("en-GB", "ec2911cbea2750a99fc9bb2e05d0ed84391a63ddbabfc8aaa582eb2339735fe5e070ceaaa0b636a9afcdf1d3d769ad3f216eca084c3e27ea874fe0573c695f66");
            result.Add("en-US", "321f6a03d356abb14bac6ee31f1e36be1daa03a542a57c3be051303ca3b0c4b0bfd55af0acb28b55dc970873fbc6700d8e6fab1aeaa57e2eca7b26a947550280");
            result.Add("en-ZA", "fb8645819e81ba365814d4b2e3c0a093490944eb3085ca50ad5b0239eb5d4ed848ca4973a5b1fa9a52de9c832b652840b0055f17fe0590ee3d14461909bac340");
            result.Add("eo", "385d4a4659d445f36c5ff658621cdda82dd811798ff88f0247b9af221e1ad8564ee5e8cca12310e2c136079ec9cfde8f68b14e45f646bf08ad63e2401065dc36");
            result.Add("es-AR", "d30d3ff03428da1981249e4d0708dec198a95ca42a4d656cbae61c96e6b83a953cf24f78649d7836a018264c330949842c17b6114f4c82a1ebce869a56215b6f");
            result.Add("es-CL", "431a45623883d6738fcdb022c058e15dedc450a22e7b6e46c39b702acfb6c5bf6744c912769ebeeeaca4fc94691b99a2c30d797b58f37bf484fa9fa3fb1f49f1");
            result.Add("es-ES", "d40d0ba5eb85afe4bdc291442a33b4dd6296d48d29e07faf6efc54e99f52d43c4bab2e830708aadbbe6bf3f04309d1014c15b163bb7d07c5ca485785681b7154");
            result.Add("es-MX", "3304dbfc2cd864775f88725cb54564005898dcf21e9e4dbd7ba5ed881778986c45967c1c55277b1b759f39641202e0727dc11fb676e99bf87da06cf7a1688f2c");
            result.Add("et", "2519d1f473df2302af8c448727519257a0fce27f8c6cbb7f008da1051e6b267d196b5dc6cbd931d53f396003256ab109e1d58b5c5d604ad81fe86993d62adc31");
            result.Add("eu", "8b74f1ca19fd3e5d38d392df069de2997450d49a398937ba5d7774daa4f8d3f7701e9e1cdcf6a8f54d9a8d1f4331be1f396f513268607f6fae4e2b8a5f45fed6");
            result.Add("fa", "12e1f4743f6564e17560d9b32360da90976e4a32bcc99fd1715fdc1f3ced56398c95ad64a31324f8000f06bda67131bd8d57aa992f6aae610582fd9fcf9497a3");
            result.Add("ff", "e60c93095781815a8cb2f7dff46067c5f59742e3cad3af01a6092b9b6c95ed0bc875d5c0ab6db6922deb9ec0f0388ed261b308f19ad3b86ba4174ae98afa79be");
            result.Add("fi", "68abab625482fa1b06d7e9d85dbab607c5e6671fcceb84724b236f03a71d558a830e46a566bd482d4f3ec107fa3048780fc7ff53f18a22c43c7ba6007116bcc5");
            result.Add("fr", "7b162db3c6ad631a0168c0b19cd2676c211d4066b962238d0adec75a7440bccd13ca230cf0f9b9f13d8418d5c92d0c4b39274a4ae48c88c32d7381f14039d123");
            result.Add("fy-NL", "fe2718499834b1359d209f8541ea50045f0b35bc232794242ba092371db1ea8086ee010ae71b469913f2bf0982f69eab9f86d0ba8205fd9ec6613b71257245c5");
            result.Add("ga-IE", "6feecb8efa3447a7bc6c6aaf0dcc2d9265252bf256cfd5bbe9dc0247791b9b6836ef4573b3610754ab340cf6c517b6f2bdca510d6eeb1b469937fa58ef7808a3");
            result.Add("gd", "931e898e83d23fb92d64b6d7b93a049f253ecefacd8b00edc5442fbf808a609ec133159fc59b93e7eb8e39a8a4e5ffb21d7810fa93310551e0cea381e87b3a2d");
            result.Add("gl", "b7901913b0e210e629dbbf0315fbaf1c5e5f66087a1edfc9f1b7f467cfc5f11bae93a3afc60d963bc6dc57fe0bc19b58df972c55e91e12574da58d0808f942ca");
            result.Add("gn", "fd242f6742b82c55b50be8a5977178b3e4a7b0fa5534199c6296c72c3b171ff702a40d6ac3a9ee24ab2115d3568c82413ac94bfc45d121d50526825f7b898968");
            result.Add("gu-IN", "414f0f9e68b87b89827e850d44121c2aff0446e6b8de137ce2a9d189726f4ad1f06dbdbee328b2e8b6d5a0b7a66422540dd94ae77a91d3a7d5052a6d0715cad9");
            result.Add("he", "7ed33e951df7c3582372c6e332cdfb9e2cdd2f325b42fab8c17526f0a9406c6466e9ed48ec0011aca0806698f51d746dec133e28c1f98e26ffc740331dc95f7b");
            result.Add("hi-IN", "bde01175e942b73f23a7aa07743427feb641d77ffb702d98bdb8c7ced890f9029b61e348934bc430bf5cdfc08a4f5b1c7fb55b8ac54b137fb8d0be429e633c67");
            result.Add("hr", "fad47b1f3d82d4d930a4793f5f092d34dd81f8fce2cf58c2ae486ce1fba7b80a9470c3032017f62c2c210aa66a8bd94c6baa3de283c17187fbfcaacbcb5a06a2");
            result.Add("hsb", "94022a11c0684b5c463d4795a82d25392542ccc5949a1ee7cf51236c33d51cf20b53745ea6f9019275c8c0ffc840f24e93b059bd3b7aa90b7646f79a2774606b");
            result.Add("hu", "0ce7cf1d12ddeb58ebfadd0d084bd728757fef0a71c75855af78831948debb98c26ff4b9819bc294d7d4a783c99282d623595775db5816e51a0c0e6cdcef9cd3");
            result.Add("hy-AM", "1b326f10c7788869fc9c651d26e05368a2f17d82a592877e29ab3d727279b5e3dae102482fe7be231212acf17db15d382d9f9c8650f569400094d21acc1846a1");
            result.Add("id", "8d92d3ec0dfeaa124700a50b649a6ad5d61a9d3c5d9bc01265e7895669de0641377b991d64f4de5537e22ab595cf2eae6cca06216df7f34f19798d531e42c7ef");
            result.Add("is", "adb7588888c90dcf1dbc598d8e5e7609761e4f9e807bdaee41d1035fb5852c10d3db3de0fc1300f0ccd408337ee85fe2233b47933ef940962e07a5b2d937b3b6");
            result.Add("it", "41292f38c11857e5e063cf2776973c41104e7ecbaff412101ca5c79705aafcb67feb69a9d7d756fb2580481ff0cb84045dfc060739ee4fb898f78d92407a41d3");
            result.Add("ja", "6d6171c4eb275db09729bec50a729410b944eea436383563d36c922e3e1fbb792fa1bc05448cb2769c04253dd8731e4db07e8e6346e2d7e0ec7f4939ccb5148c");
            result.Add("ka", "dccd38faa81951ca98e720874520ff15785e84c26eb5adfd5988dc39f5329ebb55891a9b5f78da925b6c72aed5e97c5d582fef196814eb2c3c8ca82b2c28a043");
            result.Add("kab", "36ca0f036a14fe3c873f7b0ed885bf1afeb39592a571564653130646bfea5b8c637f35a85c070c759afda063b74ed97bceecfd736960baa5ab8c34f137e7a109");
            result.Add("kk", "3d38873db96673136c4de5dd02f5214296c53ce9840a6615dc7ec18e575ef08964e0ad9debabd8425564ddd1e152ee6fc934d1c42d8015ef0615f5c56577754a");
            result.Add("km", "2ea3c1f7e926bfc0ef534d0ffc407432c25b6aba31edb99752fc1cf8746eee6e9e132dc426df43d40351b60fdff6a03e432b42004007554db2a0b509783c20db");
            result.Add("kn", "3d97033d24a624e37c1a252d86c4c9427eef9b817fa0dd070728174b33569de0293b870cb155eec9da9d7ac38b06c8f443eee8eb931cfaf562ef5b2c0f382993");
            result.Add("ko", "d7d37a045ee4e2c8d0bdd9c972aace5daaad447fa6cc925c7e48b177af55f90a047772de960579f79c4ace60f1ff6aa3a76ff288c9685074db68359454e62b98");
            result.Add("lij", "d1c95e0ff91a559b4283662dc31eb6c2b74a73a3a15c4b390df80b0a2a6482d7f5b4cfe7dfab42146ea84c73b319c596c73aa216323a17bafae92493e99c89e7");
            result.Add("lt", "357d008a6038e65b5585d0dbbf1ae0a557ffee12aa7084501d96a3b6cb0d334ef9a21aae1c6635a30d4e2c6ae869338b2355d76068ff146b048b90cad9e98e78");
            result.Add("lv", "42cd139e218a5280de7f9508a6118320411323b3dbe71177129b868c4fdda962e239237e983b5ac3fd222ae6e123245d6b71e02b4e6f6542e463ccfcea56ec01");
            result.Add("mai", "0226700bd2b47feed7c2e1c0b9cfe22c426524942a8bcfb26d640ba38d2f00d06ba8cf2f26f799e680fe4bf5bc9e28fd7838aa1e1a180c7085e307717400d0de");
            result.Add("mk", "ecbf60794b703df9af03fb113d3536ceca5af47214ba44bc9a8907d7cf8b5ad7a34025e81ebd270a9b0716842dc71f9ff94aca0191183564784b549943ede969");
            result.Add("ml", "00ff1e9ca1c40b2e6ec72916fab35112c8b3e34b2fb07c8a21270b48d897491caddfe034d7e86497c7a747a939619e70f1e8b5ebc82868974b8d454f41a3820c");
            result.Add("mr", "d1cee0d94e8376ce355bb708a568e46ba671bab8478b651d5b137fa07fce78e20647d5e0a6c28150a3f9a4b994e4883c40e71c5b447c0720905585bad0088b57");
            result.Add("ms", "9ba0b000f4cca2e410cdd5cf5efb98f7cdf86e3795f60097c38c8a6b7f9fcb444e2e96190b0acacdc7a3a4c4fbcc67d2ada8a8c2619f517e41f8066b2b2d6c00");
            result.Add("nb-NO", "155acbf312ec919627b4be85543fbaf1818d82bac760adcfaa8212bbe1cf4baeb28bc81e604529ad64162b56cd3bfa58f379ebc0af3cbaa953a662a973427b6d");
            result.Add("nl", "1538fac7710078333e9542b45b68458a27130ec97a27551b600cf7377bea5e6b863ee5dbbb623390569bea3eb015f1e26ac3c2785af5d55d83b8736b453f4605");
            result.Add("nn-NO", "1ea6e675012692e3fa4d3d5fb3ccfc034700b332b6da6293f58573d2d034c07c3e643893d4addc144a17802ae7fdc1f9db448164779034d8b8bfbc3cf00154c7");
            result.Add("or", "6bd2e8806607a61a59d33c0b3f23d4aba642a329fc1b956c623ad173ab61de42c9986594d7e2f35a3632748d168ea05bc17a10c5c6cabfd6c5427b16fa9b9b1e");
            result.Add("pa-IN", "575af4b1c425bc338de6850c2495f4d771d6fa7237b02b3bc8962a09e99cdda6fc30a7eaa6231b51e3bf85f1488d5b62217a2cb031b5792b165cbe766828d2ee");
            result.Add("pl", "c85e0cd48e07c671d95e2140ee89bd73573c8b1fcc99a6e5381abf80703404c3870814705bcfa11d7bad699508c3b9e894c6b07b62c556fc1c64436314663d4a");
            result.Add("pt-BR", "cd5cb0196cc1177e1e19026dfa306b0fcdfe7ec7f99a5d1057bce483a3b47b679e4f5c6e9291743bed7bbc4b4b690ad307923ce5747a81374378eaadcb7d9964");
            result.Add("pt-PT", "484bb9a3cf96b404b7ed71058eff28c6497061fa8ae93d80f5ce704e7cdb8760a15cddad9725dc1f754d31ac178b7424a5554e751f3922281a13894bf4535ff8");
            result.Add("rm", "d54a393d497d73fe6a791418d843a39593baa41ff41680aee05fcf0625f3f3c93d784bcdebfefbd0439c5eb7c3f16ad30e0bee659f7fd4166f47e77b9b43e4b9");
            result.Add("ro", "03167fdda1e93fd1a5ea4adf2327daa42e0fdd680b9750d7478e358dcf8cfdaeb3c1bad334a3f858727894e03945db34b536ea754a7321035f8b7146df837189");
            result.Add("ru", "f5fc8bac8b4a9a33a851ca65d9b40c15d6793bc947a568d940ea756f6259a5efc2d5b95b88ed2865b7a8b11826cffe2a7abd3cc96cc5539bec60a016e0953272");
            result.Add("si", "43cf5e69e9af58056cb83fbc503840c9333b7054121f8978909f201610b6c4f21d96debf4e52e09841674097162442da4dcddfba9921062ee296faaa539303f3");
            result.Add("sk", "8a8e5417f2b30a705c5f59f3ada15a7c81be7a0d0f1afb7eab976538d067aa66ba7b7ec6ad3254dd395643a1b2540069cb5f333475b281e49c19c7f5e8f3d1ec");
            result.Add("sl", "1c1da2110147338f78db793c6fc3b4c6b5d2f710ea187cd41f98b4c5993db8046e5c0f83707cd16a90559182992837cdb31a0c39dd93831a402f10e039b18615");
            result.Add("son", "5c93cf748935b7957bea024133b3b0be1c8e31e3f4b7090121c28d009d4807bff1bd4ac976f4e94a3558ae8c9c90f51a0dea9d33de4a3a7fb0321cc5f922b143");
            result.Add("sq", "65314e3f912cb8f34d3cb138b7cb271ef5251ffc437eee831783f10f9e41e809b594232625dfc17f5b3018241c688ab59b67106f1f4cfc9f7487edf4cee37928");
            result.Add("sr", "9e1f0ab4232216f8388b6ad08fa0dbae2f05850f5812045bf66f6aee4c0b01d0c5b5544afa473392b09ebaddd38bd1e52d3b71dd7a319608fc28addafc3ec7c5");
            result.Add("sv-SE", "1cb627d3faf83f17ed5cee0da018967e4ed920fa0ddcdeec97872b7aa5f20efed296eabb290ad4767ae3a69395bd8c0b32afb1108c8bc3e099c72655d8de3b58");
            result.Add("ta", "8c7336324265c303edac1639f5a8184dba9387d5fde388c00990bc888c73d2d1b49ab51c1c5e4f50e6939275722608b85d58dfbfbdd36f896a28d2315175eb05");
            result.Add("te", "81ecd7d50432f6e0b0cbebcc0f7d45d3b767c424afbb0bb5c60f7c7cf0ea4e20e9661336bc46e1860bf030c5c6e9fcebe9a2dc7067491a0d1ba88103d7ec1805");
            result.Add("th", "62c4be665d968168ab7c5c6791807fcc6e5df6f1d46ddf358725a02eb9926b5223c3b8a40432db4b1f925ade1f6bf2bdc8ca04969a49d8370986864de16dce90");
            result.Add("tr", "7f6c50947025152dfbbcef25f650a9aced065b3d14eb3d704966d32c87fb65c4cfe2af146b944e1130d38a6c44785b9eef1dc078fc99d52c1bfc4c3bf63ee337");
            result.Add("uk", "8473bc7e4de9b33558ab27a2448a2f619e472be47add120dbf8797c34710f4b94c056ff476b9352e90254ffdef2ab4aba378e8475dfe298889d8d8372676684a");
            result.Add("uz", "ee834663f0b6eed4a89484bed416d163f4cbc4bdb36263eca270887e9eb09f832a2608fbaa7e5ddc295bb1d378212cff01b20e6a4847217ae3824e839ac3f1c6");
            result.Add("vi", "6b81d961688342e893275c6ab066a8514f928dee2ca10965ffb0e3df02453c42aa82f83ff3ab50945dc7445f55ca373e744d07cdc9e3fcdb82f93916fc478127");
            result.Add("xh", "71297e5e08923f69df8847ffe8550f5ff01893b414c0b0e6c8d7f1719aeda710f4f2ccadf589c350158bc5b08500e4503ee538021be469f4b58eba854432cf62");
            result.Add("zh-CN", "05593e703ce80d99fcca6dd73807788cc8861478de45b5f80a0f114ce0911c11cb8eeff636bdbe83f2a929d50e3cd481d43646d5709b8c8f7d396a7471206a5f");
            result.Add("zh-TW", "296a2da959efcf5a7edd2f7923a2e0d446ed995b419dc08d6ac8cd7c9b70538b6383dfd7f79271d6d66750fb75f516d230e5bdc9c4cb340b7553dc652fa34673");

            return result;
        }


        /// <summary>
        /// gets an enumerable collection of valid language codes
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "52.5.3";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                //32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox"),
                //64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox")
                    );
        }


        /// <summary>
        /// list of IDs to identify the software
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// tries to find the newest version number of Firefox ESR
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
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
        /// tries to get the checksums of the newer version
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            } //using
            //look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            //If versions match, we can return the current information.
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
            //replace all stuff
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
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } //class
} //namespace
