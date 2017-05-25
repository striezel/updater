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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);



        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            // https://ftp.mozilla.org/pub/firefox/releases/53.0.3/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "bcbc0e561ba0f03567800ab4c94ce95b2d557cfcf40051b6490b8dc6c95cf416497cb3bb9a415526b8164c8d478842536f296418157e5cdcdd28e7a5f6618b7d");
            result.Add("af", "3cc4bd5faeb86d14ac997372619008f59fb027de33c3fc1170b22ddc35cd68bf2bd2c07ba76306a147195a27c1528735b0119a68f9ad3cf181b8a8f09db6641a");
            result.Add("an", "7c4825332852f89e78c8646ac40c57784a19d61712ea8c6a4342bc04b302347632a927a195075435cb018041c58b689728a5b0b8afd6b721afab5c8ba5949bd6");
            result.Add("ar", "7c39100f42b2723b538ce189730a7726689f362ecb39e5e7f2dacb2a5675d02810ce006968deef73637ed1979476d415e70bad1c460fc93818f813a76ec8bf53");
            result.Add("as", "873f363589f3192031827a492d8a09a5563984874b36f5ef81690c664c9f263adc0fad8f07f2a2f4048060a4cd68eaa8a11dd13b95f670d8aa7f96151219e0c2");
            result.Add("ast", "5930a817513a18bc5a8f3b1ffe56ded5c2500386307fdc785ed0892598b7d25815ed6173d1bf4f28682764b10b30b1e53b35d3e7d36a0cc1df4604c5149bde03");
            result.Add("az", "4183d77a7068b1e27edefef7f26174604025855936479291bf4f73c99aeefdb676d4b0ee489646b3eb1743ac6efec0ae73fe14b6ecfe4e01f5f72b79d22d88e3");
            result.Add("bg", "e1b70027ce8a6dbd5a92795de558e5506ccf009643033226960100dda5eab381abf25c707389204cbbf6535b6319c42e4524fced98e1b1628e611e198aa8e3ab");
            result.Add("bn-BD", "39cd0930e24d62d7d8a6124684dfea95bd3c648784a7ed205a7d27488f7319880d13ffcc663ec196636204f7eb6ad50c2573a59dce90704bc40ac41274776d55");
            result.Add("bn-IN", "2f5f48e1ba00ce3e4356a313c0c68115bc40451d72ede177acd9662f82d65fcace22ae0356b3d3de5cfedda32118a0ddef50e28d8d70af83f149addf94e8490a");
            result.Add("br", "78a612c2a65661ec3884556b77a0838f0c7069ac88709fcab732980c377e65b7d4ff8130b6a3a50dcf5febfff132974e5eab5c668554f2ba274620ebc01edfd5");
            result.Add("bs", "d839be8bfff89fda4df5e78502893f3d831bcedd357bb2fbf95d065bf32cad7e5bb290dece4ea94777802ce9ecf9af91c2f49a6aa12fe1f9b748df30bc4a7227");
            result.Add("ca", "311ebe249309534f5a308dde507890a80364f0e884bc5441d5deced896f8fc013121bb359d18ba26b942793600d172c24cfb7b30380bb30f91f3193e17f7427a");
            result.Add("cak", "c972750667734454715c429a43a87da1c26741f2f7532c3b09d5c1d9a451cd894bb40ef53196a105bcc6d2680031270c59011e56e448f480536535270fbdecb7");
            result.Add("cs", "b0e52dc72c9d97198c8bca8bffaa54f3299dde1149f2d4ef7bb6e69aecd0476267812638bc13b805349b896ff4149ec8fd8b883146fb4ce6b5edd911d58e9e6e");
            result.Add("cy", "2af435ec6ae40da99edae7a384df94a1fb1b36fbfe1c6fc64201d49354d8fde00b55e990206e69689d9805783901bc2715b52128709b20b05a52047e5e9fef10");
            result.Add("da", "8c87c67986f4c511bd290529da5589db6255d26444d4487e5f2168952d141660747398c71375ff9ba8af3b392ee99ab4acaf6f90c68316df4abeb48316b87cb1");
            result.Add("de", "84e052634c0b1adb3d0144fb0b1653b251d7b82697e119670dd05ba7ddef6907b844412efe879d358017dbf793ef22f1e012345bc798ec5518cfef0b210e737c");
            result.Add("dsb", "2ba4a4c96e2a7d0e91e34306c91272091a73646b74b2bb7c7e33c403bedf9c1007a0239d9fa0ea4af1522ca9bcc203db7305dfb16ad928666fdc6f2515df7492");
            result.Add("el", "1df97c3e2bab2780944721f1efa9ece3db8a51feeb7e2ed1905a579947b4f3dcbf66108434e24c39e75d3b2c80fbc73de9a38953e181772fe56fc8afcb14c859");
            result.Add("en-GB", "8a748ee8e09951ae0fae87059282a90c0147ec3eb421a0524252ce9dc4ba0cc860448d20deafa4fd2d543ce85f1e016634d43cb71dbd02bb7d9788ae5d1fc915");
            result.Add("en-US", "29397f8fc15388c0af3eadaeccd285b8ae3775ebce66d28921cb1437836e9afd7847fc7c9c1b2b0fb8f76359daa6fdebdc40094c1b8d8ab4581640db0e70229a");
            result.Add("en-ZA", "5f07f996f291f20821314a29f88490e5c0b16eb8e1d14b968db8c24211a7b5c5e21685186864071b418bb799390b03806c8a743dc0e4e8e06af3fd1c1949da50");
            result.Add("eo", "fbe39a6f405ff6b0d04d39557d933d235629fdb94b23abf2ddaf55c54efbcbd971999ac197eee2a1ebd0986f4a45848ee05fe151bb200bd3c49cf65d93b5fc37");
            result.Add("es-AR", "a6416358ce7f3c311490939282b7b0df284e4da751e42ccd4ba9f6df609af5703a343a417fe4a66425c8c6fcb44dd3ed0982a6036795a7aaeea05958ca946e18");
            result.Add("es-CL", "baaca0fdaeaaca1bcc875e44fc65700c500e800fa5c867ddba3fa2b0602cd5676719324a5047cf759683c1d2362f1d0a4b8c10f0a2fc3baea7eb3348fee49129");
            result.Add("es-ES", "4ee9ed0b58f9f676884674d6d76d5db45f4134767236e145e5605296fb536de02e8e77ffb44b22d1e38826e81cac1baeb10359aa027096daf053472c17703ed6");
            result.Add("es-MX", "ee27509e72c97d90f988b95a16f9f1b543f934bdc70f864bffa56b90cee8076801fb64bfda93c285fb9540c7e6d87e07909128c8f18496a462b5d55008dc262a");
            result.Add("et", "90fcd04c6209005b0cc1009817240369af890b7fc61d29e58096fe38e334e6b456f8b8179fa545e3d7aa3b63a0d875e39f7e2534adfb93be3219842eef06bfa1");
            result.Add("eu", "a891920ed0a4ce9dc3383bc862b27b3ccd6f29b845e04c471a1c3066e5215914f25d1f4e72b87383ed8e883d68b840b62e04ffff474d33d9d0836212c5f89ee2");
            result.Add("fa", "505b2454db5f4530d0eb459c86fd068a74a600369a1dbf871164c5c728ed883793a9a7e386c3a1ba154e9b36f2f799bd3f97c3e69b3d0076fa8890de47f1c770");
            result.Add("ff", "e05ee5d2fc4920f3256c4bf2ed968ee162e8716878fde51b5d9065213e550a2676374a1c917f8aa3e4c6513d7e3850b8834cb7adfd33dbcf1c362dc22d892bdd");
            result.Add("fi", "43982556a782b216c55b7d1873c86db04fda45fa95cb13c4c51374fdb6adb9d8c458fe9fca10c614eb98babd98727ad482eb88220abfca10c81af282fc61a456");
            result.Add("fr", "0c7ce84fe39e1a830038b394a0f7d084320e38d5f77683daff37cb9fa6024e495c041b50a1a117dea75b37b985157e0d42f941158fe670f348ce3d632c49e124");
            result.Add("fy-NL", "aa028c368fffce2229ac83d9d8ef983497b26da0fef769b5ff32f1d8f0786e2a5db87ff51ec39701a8798306469aa7af2cbf044394f0a23dffa45ceba11b3976");
            result.Add("ga-IE", "f288d12b12476cd34b087281b33d011a45b60b5d59a7754f5478a0687e542e84720258f8eee869a9533df4cf0ea01e554b01dcd748f32dcebb2fb4de1eef3996");
            result.Add("gd", "c9b38363ec7bc9328bf8708c551778fada0741bc1550929b1717e36a0c87a4462378143e86167260b1eeac6cfb7a7cecc8dff94a4498ca32cddd4dabd0ba242b");
            result.Add("gl", "299d13674d1f74f43c1dfca116f7a33944de59f471bdaf363b7788673209580e1fb4d4d7130bb419ed33e023527c1be82e01157eb8e56c9913477b9682245a6e");
            result.Add("gn", "f9af0f750b5b6b06ba8e10eec220c53d59483568f07c1e12673106d4322c0b153286b5dcc90faebe6827c413a7bad940b55a266b5fc0191cd8392e5deaf66cca");
            result.Add("gu-IN", "d6930e704c6cd7596fe14057359a099111e898433e85d9397c844585dee780c085ad43add4e564ce31efadd6f6a494a27cd42df79bcac0ff9abd4ac29c768568");
            result.Add("he", "8905e879f3ce7910760c98ec9a619bbb12d37c5d9592ce206b802036083773dcda13e4a8c1fe742cac062dcd46252abb77016ffbe7a7e46d22b67284d6b1556e");
            result.Add("hi-IN", "f74e57ac56e381c643c02522e9216e05c288d7fd89357ef1718c35090d982a9c5d121c81d1199cee50e3ebba0fe366770ffef7b100a0ecb638ec9751aaef82b5");
            result.Add("hr", "4361dc10cd3ecf043bb9b8b9c47d56296134a7a4eb1f669ae087cebb4c67a491c94d8bedf0c4dee3d34f673d782d36f8b0bc02e927f2eecaa78e264b6720a1be");
            result.Add("hsb", "b4e7fe848783794a7b9b2a305a77aef06179f53e301e62b25c0e8e5b8ba02ee025af475b1e5e9dcec9e206cd82368e1dbc474805fc1becb79ce4d582925929da");
            result.Add("hu", "c1fe4037ffa4015f88a647e751e3e33698dbf27d7b9f5bfa7c6d7e1b29fb34cd30d056f6bb5b4c3a9c8ffebe29c444732082ddbd9688fc1c4d4f1b9f440ee368");
            result.Add("hy-AM", "7b7b52e7638d10f392d417a222175d4fa89c24215a73fe0292ae5cb71f01ea69766b9929efe7d4dbfdac5973a0c764829dbb511e16dbfea8af1a4d64382593c5");
            result.Add("id", "ebefe45e3d5f3be78628bf885aae728bc3175dc34ea33c9fe8871351436f88f2deaf8716209a8a60137fa5684a98f2b2b8388ebf4e21fefa23412604b4363164");
            result.Add("is", "94d115ad11e9f4c0cfbbbf26eaed0d2c7272d45da5219e70eb7b924c72af422217e4f4c18a597146a55914e9259ab52929b2f94a66929b0951f685c1bdb9c099");
            result.Add("it", "c1137ba3b97b3388f40eedb8f5af0dc455c3f6f7156a3e57510baddd9be0b0eaf514a2b0fc5dee3f09f9c4a425958174ab40972aa9d5b0a322d18ca9f23cbc49");
            result.Add("ja", "7c2a2f70252e9bab1a53e34d5241c25fc355c39011d5c98de0b08417bc19bdb24d1df49917386b8a6de82821d2bddb136d7448bb1efd7454512b1d953d48ee52");
            result.Add("ka", "e702d813eda80d67fb3ae1fa35e5523796bdda83c28bf7f8b3b3a4c981753c4e3bd2f5160379603f34fc8ad78989663f4cc42450924f547263bb100735d381fd");
            result.Add("kab", "9b851180ecdf2de65a580440f2f7a27e2cc1814c96d1b198d08a03f2ae121e09e65b85f8fdf36f3d05b5f19cf5046229ec6787ee4725eb14ba3531baf7d728e4");
            result.Add("kk", "283a4387029b24e8466953e84a5f44695218cbcf3f5815779159e74fc90789bb4a0350c86e12fbb1b2569b4d3f8c09e46b2e91c4ea6a4c7f082c41999bfa768b");
            result.Add("km", "afe3c31abbf933264c26ceb13d2411f21ed6e915d8e910ab8cc5e75d66c03ec41fefc960f90fdef5d4f49bbf546f8fc62b3fb621db3727f6f0a50d47e9601431");
            result.Add("kn", "ab36cc187784d771845c877449af72cd7f8567d51b8e14c6234611a8a23d64e200bfa2965512dea0aff312d8182d330e3e078c4d606e514b78e8cce1f7fec307");
            result.Add("ko", "190717459f741745dd59fd5c04e060e99b834b71b4267cdbec36556dfdcf21c027cbe03e336a0c906a19161eb1bc8931341bc407eee3ccda7eec4d2e6a2c269a");
            result.Add("lij", "6441bddea1403fceb6d6ca14e870631c366597bfeef1a65a264f53b0867199472498a18216f078176ee0ff372d2dd935aa5e968cd6e9982a0004230d648b6587");
            result.Add("lt", "40d6d7934be27a050dd65aa428ef3e26662adad3b3a30181cbe931557f6400063153be1d2a4cbd696aebf7c9116bc12a3674bfff31f47ec216a15e281054961d");
            result.Add("lv", "2247014d8308cfdb3ea364d735e3f95779dda896fd2d3457a24d03a0e8a86f6ba6101c10b5ed3258b32820f2dbcaca4523ce056f094e093da57e6d3817ef879f");
            result.Add("mai", "574e1af4009811103618ff4cdc7cc7aac4bebdfd1770b06ec2c389d7a34e374b57b0536dc3c3a327fe893fcfdd024c6aa0338d6ad38f95891c9d069875940ec3");
            result.Add("mk", "d1668450e74455183010700681b10fb27c3604bbf2e3b9e7dc445ba6e41a6089c090ce3dbd5e8d833331bb9bafdad1a8117d2c180e7566493e242d7af3e21173");
            result.Add("ml", "a384c74753bb1779cde800c82a77111017b5172bb921342360ae951ed0f127e37735d7dfae5f83002a325c2896ca4bbf84722819e7754e42b610e7225606f8ee");
            result.Add("mr", "086cfc9a4e6a70137a2e3cdde101c0734667367f40d8e5829947ae8c6b6a9fd21b46da846097aaa50bfde916512bb03ee3a01c85103ec807ed592a516f56f06d");
            result.Add("ms", "c945c3f9a84b6ce60621cdbf23ab1466b33ecc16f07110950f825b3ac4cbbdd2bab5f476b7ef1b9e142a717713a3ba1476ac78bae82950f80446094709f8c20d");
            result.Add("nb-NO", "ef19debe0d890c670c0a082624db0760f57675529cd31fe18fc0d78ad90b4ddccd618f73e049c11c5d2705aa893bae44ca95e79372a3c9c71b20eb20c4e2cce4");
            result.Add("nl", "ca4b77ca30646e566abd809e6c20590312d2430236ca1c4139921f6a87953fc7dc6f3b3c66b364e40bd8128b6c0c74b1733e9837a43fdd24c798637135fa3713");
            result.Add("nn-NO", "c57b51375b576f5e92cb6a504448e44c62af1c3200500a4f8d9708011620a9e29621ef9e629e10f23971a3412b027c44e279e38033c65c54dbcb0014b3095f98");
            result.Add("or", "d329836b01f21d9ecb50ba22354ce6adf1ab0e847418642645ceabc9c930f942e98a09d63f65ea3c17af0a02d6a0c7c49612f13267d794844dc8f71d06bd5712");
            result.Add("pa-IN", "a59519c385459adfe53c77d3e42443ec2131658a4030d4bd120a59fca589da7893dbac9cb5e7f738274fd6ae9ad0acce2897cdc07644ec59aedbd62737fe5102");
            result.Add("pl", "fc9ba6d97cf302a0e9ad446fbd2573dcc699c72ae47ff5de6b80a57d30adfec7b95c204e84021b0bc19a1b225e22920f6a39051add25c694469f9fb8d8ce035a");
            result.Add("pt-BR", "ae57db37bf2b61dcbfa4f32a24573e5ef4fd01728fd15d77e9da0d8b387670ab1960c9ad3a1226e25d9c1de1b18dcda3f8d79dcb5c0eecac1521a8b3a7bd69f9");
            result.Add("pt-PT", "c03cdec606228669314f8fe8bb6d60ad76c5ab76ef0834e924d899e1812fd162ee6e20fd0717c892224483eeee583f72fac4733418dee4949e75ef1a9135800f");
            result.Add("rm", "0d4dc62f0d2efed8156b0adc1446de338ea93853c6390a91ad32ee04d03af64d78d4a2817a15cf3bdcdb03951f3aba6a324ed4cc72ddde08f94fbbf69c71550b");
            result.Add("ro", "25695c6ceeb6dfb76c927e3a01a3df48811749b120f66d5f61ee6f9fbe00dd69d260b4093c9a57f05284d71a000c58f8c24987e3ab4250f7b1b9f5d1122723ba");
            result.Add("ru", "cdf34753b825da91fc2f42e91041d8cc100db890ee391be91e73b394e9f700883eca345e3bce9cc6f6d5c1aa09b340391535a833e6f183c8209b611629d95628");
            result.Add("si", "cafa2ab6e4e034a2e28bcb0e5d986b62052743fa33e20bb1642be8d38851448fa332f4636fbc35527fd6cbbcf546bbf5bc373917446bfbd8f537e976811005d8");
            result.Add("sk", "d95626e3be91b7e0dfc7a378df8805c072df6969f62d4bcde646d11de8e7baae41c0b05a7c0fafa7d4cd22fcc4d5433e776f86f96938b82eaa132c92733f0c49");
            result.Add("sl", "98786b363a85780af71654da25b0f8267cb2f8d2c644c56440687ce4f503cd8da0ece1169e6e53bd5e7d06eaa2deb95b4a936387f039821ebd17b8e6c2968c89");
            result.Add("son", "d9ec20b781c7e8dbaa53d626a3a24f32d32f61e5354c23963d7753cc459470452d07d6a0952a4d3e6da6d29b41dc1ec1940f6a8d95259d5a3c6847571605f072");
            result.Add("sq", "0553d90a12c6156d5f89c93ee608bedb11d7a820d6b3c87dcb445a81c139c3205f9d2d274301ba911eba0f09587c2d124b51e51554701d981b5698ba933bfe49");
            result.Add("sr", "8a08407644d31b80ad4113157ac9da4d8c8ced024a54297effb080606411035c2fa1eef0c236d9dca825df2aa19cce318a1ad6398849532fff49ea041544697d");
            result.Add("sv-SE", "9a7f34f0bd5633d8ae9702d115f88e5a852943c4dee3861fca42d0222532ddfef3262c9e8ba2dad59644c9c4a53eff28df3a98f5ac1f317a17802c9afdfd1ccb");
            result.Add("ta", "dc0911a1dcb383a2236b9652181d54f236e560e2aaac30bb919621142c1ee03842e994477d971050bfc72717805d78a2f33a3e0fa95e72cc4d2cc240559d28fd");
            result.Add("te", "c15a60a037b7438dbd0fd2d8083f9f71f5fa616db34702b921fac51049a01e9fd8c10b83443395f1f86aadd1c5f4fda037f31d1ea016079b3b2d626ed260b43c");
            result.Add("th", "6421cb635df0514327417a5770c320e5c5343355125af4efadd52f906afa6530d84f12c1b1cc98f10fd9627c9984f83775a2058a661f30e6b3f1ea37fdd95693");
            result.Add("tr", "fb974d2c52367d3be23e2abe47b1990b1e5f1649794cb27d0755809d69a084b58c722537e266fb5c573220e801d67f1bf48dd4a60e325f78b3c7ea3dd7a64ec4");
            result.Add("uk", "dd95d528d0c27184097e3d4a2309d76f62dacff019a23734440d98d7c3ae44739bb86901d639a7a3f5bb8ee2ca834d96ace563d12ca19d9ec82c2f77bbe50377");
            result.Add("ur", "4e11e26c2a67caa839e1618bdd0db5cf2d31763f0c6d7ac06a98d54d44c13b57f7265632b82100258871f7ce2f29c22ea1e3b5aabce1bf82191a65fad7860e46");
            result.Add("uz", "12450a305f5f98f2cfb6ccf9c9cde36f7f8e14572f53837a372ac43dc1e914389b08ee7ab8b34d6c038cd1a16c906925b1e1cac79ce3263a97dc9e66ffdb7f4d");
            result.Add("vi", "34da35030f21d830b71850cd01e70acf63dae26cf23bc2a144119135d214dfdb143bd5d2867f10feb7f02ace51120ad8245c208bd8a0b7cb6047ca856a5df9eb");
            result.Add("xh", "12a9ee2976bd1d1272f5418b3ea0092ec8836384f092c2957dde9065665b0957029e147f10bd2b468343001f1d6ae5663f345440e783f4a90ec0eb69875c0bd6");
            result.Add("zh-CN", "64503923d15e6802951703db1a078221006315af44e1abaea7d04c1573ed24a264187de7a62e75c67daf6a60325ce7cf03be0217d6006cedef8618e9768850f8");
            result.Add("zh-TW", "a72832c00c0ee892f200e89c408f1b1a6454f12fe70e1b543a65401ade008cf75599f1c42e93c74c681c6830c35c74a02a93b3460ceacfdbd1bc28fa39335806");

            return result;
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/53.0.3/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "c9087f7c5ad2d66fea3630664c035ef7979817c9cf6d6ce63893e960de321b874a5183dd442fb44474e09175e23fca7c3f3e1348cf250be94dcf0a5b83774cdc");
            result.Add("af", "cec1c679b133a78f010cc5d80fd8f111dcec56f9b9111554f47c78a6944db877fc53a9126e9b1527f2c2737be620093f79a03709c1e9a359016b36b560386176");
            result.Add("an", "012ea2315fc8e5136dbbc31976c13bd2b803b2217f0ca32bac0300d8c5f685dc72468ef5d1827a06b57e14f6ba69490d5b2eff13d5cc8a1074b06aa237d0cac7");
            result.Add("ar", "eb06ce207423301d01cd10f064e9fa60bc1df03d53f10b73f1f6934e6193a82622ea7a28e221d7546ba2abf6041233ed0973c033f57e65b4202817bcb7b26469");
            result.Add("as", "cb859de8a7a0daa3e0f15f1d68403b82b61ab990bffb6203eed336ef6a93446d3a959641679d3000b2e6daadf53d6fde8dde47cde061a9682a2a3b56757db288");
            result.Add("ast", "07324865afe7b27a6059095343efb98084ad6fe124b30286361f566c852e017451f7f1794e30508ea9071a3d1663ab40fcfa6dd14702dce2c8057fa3c8f4e869");
            result.Add("az", "5dd8c0617fbf1a867dfd65a594f4f463fec09d2632c84d5c5f14659daa69893dddf2ecc637982e67679f9f3964b3304e824910a740a14a6c337f76fc65211569");
            result.Add("bg", "530a79d71ebbedc85a3c8ae4c4644bc504fa8f836871c4a5c98bb2caaf8de7e72c1c4ae6b3636dd050e79b3634bfc0c965671238fd2839e491b3d921753b2f82");
            result.Add("bn-BD", "ac1189cb37bcb85a7137d4d8e9f8def43918f6fd4fd3a01b150a204a20296b5a38ff1a5b9eae99c47cfa398b8739b4ceb7cd904951a0754697a171152f9e8f0c");
            result.Add("bn-IN", "616cf0545b30ed23e0fcc09b3781fba4e2c50bde58d0ab0b842b02f5d1e5bc7785dd9429933dc58f167ffc2d0e85e64cf9573b280cdb52da35101137562d6134");
            result.Add("br", "55ddb1d835daadf293f2594145ed345d7158d15f7be39cc1c8e80cce38124a747f143000f4ecaa0291f39827bf9b0c5b0ac11924ad2a2cf44c1219c8adc433f5");
            result.Add("bs", "4af707b198f130acfa564443c9d3eee4c6e60d20c07c50684695dd940cefa673bbe7b8c88d69cb1e66a4becd240778a030e43f76045d70d96e5eac6c47f43956");
            result.Add("ca", "864223128af0bfce8dade036f91905866ce17e88904b585ffddf1f9d9ab42ebb6f0a658ab68e5c1cf23cd1fe804e80045d3eb6ff3942ee4d9f98cc9b8c2bbf9d");
            result.Add("cak", "fc90e9281c87530e8a75be0087277ee6db8811c7e5044f01f7c7e8ecdfca9bd77bed92c78d54432ffc3b17cb167f3e1ce169d3f01b205255574529920731d6a9");
            result.Add("cs", "95371611f626e87c406720619ba5bf3e3f98c493e96ecb4db74bafe662e30500e538a68126517d8a8b6aade2206becf3f1e38eab4eb933a5c135e38b84e72aca");
            result.Add("cy", "7e54111542ac31a9b3a1f4ffcf511b81da1dc5377cbb2e83ebc99305d822537854349cb00c706ff47b534d23e8f57e73226b29a48eae2aae9e91d60206980e24");
            result.Add("da", "5e8b20a97c9355d965aff72a4af96876f292360c870dae957d9ce261160b6d1f726a8722bc4939d04dff79aa80b964b4484cf32899e353efd023a5b51558745e");
            result.Add("de", "cbf6f0e7981ba929fd42049c59cf44920effa98da18490a3916ab795ad8d73fa90f7da71da11e162869bcc60679fa9ee9a9c5e66d4c4be99df8cc0b716eb0a73");
            result.Add("dsb", "8bb96907d71473fd1b8e298372a06bb032f928c9fdb7c7fe6a63feba7e317c6755f6ae14892adf561c1f231f6ba41e216d74d634ae3ea4f29142e38ac1c106bd");
            result.Add("el", "460e1118bbcdccf8554464efedfc661399f663ae7fd31312a0a6c81657d3ec9ddc6556b481b6f43bc500d2359c93ceebbf234d4ba9158e7ccaf7f5a6d315d084");
            result.Add("en-GB", "469a48fb2a5bcba32fdeae4018479d81a9a6dca2b9eb3d516ec6aa6567fb6fa62cc1c163005556d1967bc8167ea1eefe5bceb8b2d8e637124edd7674c74dabae");
            result.Add("en-US", "5139a05b2b7f9b90699c4ee3be94d41e4a95111f9a87810fd5053ec493b285776fc89cfbb985d063253a22568e4c6b1a539877dbe3434f78801b56c527f7a19c");
            result.Add("en-ZA", "790e004eb2bb1839a5753ec1057648ba77c2a6d8ef0eda35c891eedd08225b22fd1c5ff294ce4a4667c9bc28757d0b77ba1fe77313654fcc6f584b6c99531259");
            result.Add("eo", "532dc822a4c6e893428be7a7b51e294a71c0a25cb9d5967702f1a98209e6392d33815b7b4ae670053b4f961ee64e14147d1690c7c51bf1901dd5737a5efde2b8");
            result.Add("es-AR", "1d41ba342929c2995bbf3f3e10cd7fd7cfb8ae451fc6b55967a818af2e1936f448954de911545c41ba989d4e1e14725f619cfa8f3e77cee2a20270dac71cc62c");
            result.Add("es-CL", "4577876457130e55f2763f86ab1b57e23c81c3ae9e20b13967799a2b7fc91c9ba3cccc4a5108741f6cb10c5315526cc391b5ae6bcc0944069bbb9d6a05f06f81");
            result.Add("es-ES", "0f033e3b986fe1029cd4731168c6ca8beeacd9d04dc079335913631dd0bdd43d063b5eaa3b727d0e695921a4b189bf2cbf50ac33dcd3e1d402d9522e6e0ee120");
            result.Add("es-MX", "9bbfddcf8d74f43e56b7f2a73cf085606c459fdd3013ddf21763216cac7458d1a70e3db1ab773c01f5995186b99fa563b11cc77db8b2dc4d6d51348f385464bd");
            result.Add("et", "76831a44d34609183cd3b4b185732487621defa14b2ec41b62a63697ce29ae4f972f4e2d313a9989010bd5a94d3b4982f0f880229c01f9635ecc169f779642d7");
            result.Add("eu", "87ff01f6ce4eee2fac9632eb3368364576d076af6c392d68850581e636cb5573090a79edf60d591f10c5ed6bdee77df27b9abd09aa75b1decb097faf4e53c170");
            result.Add("fa", "d4db0cc87e2e0055680d4f52c68864366d5c4bddb6bd8fd6ad56745424a384c6d31a857ee50d7fa7bbcd06750c340f19f48f3bb7a015894aed58f30b1a5b77ed");
            result.Add("ff", "dec4caba0d923151f2874cfe33193433009f0bf09b8859d0418fc2fcd020b79b16601113016053c20812118679be9da3e460880b5e20e51bbce3aeb5ea9997fa");
            result.Add("fi", "3b60f30f02d52a320f60962e6f663b42208a441d517cf22c845f7c5117c1e4e92d01ae8af1a8bc7511c12a49a2a761eac060fc7be58c1bd9a054629557092b69");
            result.Add("fr", "933fe530f5d4b86675d31c325948aaef3b7433ec806b34b4f750b8a67661a1a68dc0185b01df84e062d6900ef4cd115e607747dcf2e7d49298b52546cee98bff");
            result.Add("fy-NL", "d0c8f32cd961938827445c078a71e05eaa7ec010f0ed08f380563edc1367de6e907947fab75202cf84216478fc722be0386c9374fbb8e0801743f12fc339541c");
            result.Add("ga-IE", "af9caeffd69662c8cb35290404769204bbccd30c7f36e9049370d2f9c4dbaab3a61d63b00a5ddaf3072937f026c5ca9e99feed04838c200ee60fa12755138d3f");
            result.Add("gd", "c4ebc4d61e2abac7a9bea5c54284c88ce6564a4a9ac7157864dd819b78f19b769bd121b6b89b7bc90f8bb446509aac2581c0e0fe10da03ef8c3e100d5ba7ef70");
            result.Add("gl", "c0651d7c5a6f6893cbcba7b93ca1c90eb07af1c156e3cc2fb6b702bbab86e92d15f714243a70c282550ad953153d56dcc0fee2fbfc09a38aacc777a2a28c14eb");
            result.Add("gn", "266f46ddc6e94cdcdd7164fe80d64000399e7ce3da871214048c53f457be55610a21731fcf04a41220d24d66467c6723aa53c48deafb39a7bf82e22ef59de928");
            result.Add("gu-IN", "fd6359411411b53b1c134d87dedeb71782d9e8bb2d432e96e9298ad40751194c3c0285110a7fac13ee478a0339456fe4d7dd6cb437a5bb9a1fd2f51ec4a9bff0");
            result.Add("he", "3106d13d61d23990e070b474c249b4b45fe95b56072bffb3d29e2f90bc827a308c02bae7ea9681b0b073ec74307ce6947b20e85594fa06bed40ae9bdbd3ab428");
            result.Add("hi-IN", "8f05dfa62a01dd37a6af5e80c21df80fb4bef8897ac98ad277b3a9fe82feab3cfd8d372d56ca64b846fd443a338f5e559e75aa2102868fc0d09f0c7bb2fddfb1");
            result.Add("hr", "b0e89e0ef748a35fbb95f38916521195a374a9f765d17044309d9a598e77946f8b7189494ea51548a67a611560804993658c23c3a585449fc798b9ebdd2409e0");
            result.Add("hsb", "c09272bf78760bf248fae29cc470f458fbe529a07a52a7edb3185d0017555122a1ecf4d8e29e4624c8f50afe3bb7a47727f3cb66fc6bce286dc3e2a0dd7428f0");
            result.Add("hu", "eae26866920846bd47fd837a8d751ec97bb30f6c5406b9cfa73a22c0af6d482c47c4ba91bdbea0f89d3027973754abfd2580d87b91a1e013fc944d6f25db304e");
            result.Add("hy-AM", "d91af065abf840efd713919af95a08d82071723b2978bb2d841b9d1a5267bc2b9d7a567addd52266fe850792902cd07960b3804810c5b1b63c25e9a7ff990a12");
            result.Add("id", "70b4d07b361ba2e0f8a74fa13955247648ca4e247301ac1861b2be90af7e5239441e6b3d1e54da1d9bf767c1e0c3f2294d489bfcb95478be20f9a072a9f98b69");
            result.Add("is", "a314610cb7263b0834683578fcddfe5b9008c151630731d1cd21370fab7841b64e826426f5ef483c23a50d03f97e52fc2815a3eca93b095291663eb7705ca914");
            result.Add("it", "6d716b6698a907a4570a569bf1d7715b2be021fe1334ad907a98c68ca28678dd90069ac490714959516b5a8ab1e8c041405862cb2072c1bb40d765b887a1e8b8");
            result.Add("ja", "5cff4bab5a26d593bf8ca95777e4d50fd1ed5778afaceb521ca9a34fe412f17b2a00e9111c8cc747620c34e7f4d595cb2b760b5004c282a1528b823b130ce504");
            result.Add("ka", "24610fad8bac4ea8ec8a193358aaddd4c5b6ea508de27321e6dd3a6c16c1f77e4e0cdae9e2058b2d08f66b979244f28926de4040c5c9ec41819f56784beb6e36");
            result.Add("kab", "5dc1b90777aa840a4a107b747a967fc89510cdaf6adb55d63c07f13d344ead876b917f4fb42ed66ae8392bf0fa10fde69f80fad44185bc4dd84521e64dc0e38e");
            result.Add("kk", "64659c288265647e68c4f5bc385e5e9156871352821211280c67e984e6a20008017d329f052bdfbf3f709f0b0f6235b810e092d153b8a5f2d75c28870d302e56");
            result.Add("km", "275f0637bc93c46aae97c9b0526815a33ea24212a9494233d8c42f4d5409361e3baa8fca9286fa30b878686dc8b58bb9b6d115a14c759a85b031e397b58e3f9e");
            result.Add("kn", "97eec6696004b495cac675f560c58d7f7cf37a3884c7b49f68acc67ef7de147c61285860a30e2be55155dfa190236ac082e0f27f373ea125a1ed1e570acfa209");
            result.Add("ko", "418cbb4b7ae4ad57e36a151c117de5c3e9180ecb69ec81a3f35e6125dfdac11189b9be553d4b321d808531e8b7c46ef79a011f3f4c29136652396e53289f13f1");
            result.Add("lij", "d2514988b71a5dc122b606d8eb7612a97d3d9afc48f5fb0a26a4231d0a880891c46b7f355d14bfa988013ad80b05a5b738712b3f2e47253e7eb6b32a6c8dd5b4");
            result.Add("lt", "7718308dfe13bc5103dce358ab275182348ced86249d1b2fd4872e0fd2ac5dbe5cd6171f54e4149b64de1dc561aee81c40a099095b9cf888adc11adce86e9743");
            result.Add("lv", "d7acdfcda02bf34c6814ca6961845208ab06de4b031091dc0dc2ea27a987046a34cba6a40195add01820b38cd67f4dd7e0341cd94f0d823e4c554ab763250cb5");
            result.Add("mai", "e262d9c1eb5229752eecb22c32926233809eed7e1cf7ba252649601d580a1abd53608f276d9b2f6435bf26533ddf082ff11be2356db9aebcf54dcb0f59083d00");
            result.Add("mk", "503a937a8aac74262bde30cd58bf1db45fdabe521f3caff7d9e40d8ec9a78b196872d62af31170cbfcaaa449b612f9e3cea639780910499cf67f15e59a62adfb");
            result.Add("ml", "314c50b5762a0c5a1dddccf2ac238815c80f4eaeb70e1c2f73665ab757d7776b51f6a98b225aa896a41212b0d02e3cd3ef13055fe4dcd69153c5c3fe4f644016");
            result.Add("mr", "5870712a5aecd909e8c6021f4ebfca6e97266668771ccd62d7b54d1459cda98117005d56f0f8c297521567018262064256611fb4408539d4cd7a8579d5cf1f28");
            result.Add("ms", "c09b9e7d9b8b57890204722186b7c55d59e16a888a22612fcbb87d4998b0c1acfd80cd8fe92cb633c00761a9d5e05a3b5a83775234e28680a8159c58694690cb");
            result.Add("nb-NO", "87350ad0e24a1ba7929524907bb590e5d8bcd2a66cbf6710d88ffe7f04bae554bd16644c8cf945ad83e462009136e3f5df998bd5f6e889d16d4ce3bfb3804f6c");
            result.Add("nl", "38788611d0c10f4c36bbd0e8382ce6cc647ab6c1387cbf625d205b414a74158897082baab00b522d904d02dca4ee42c6e8484ea2a86c83e80de489ddb86ea134");
            result.Add("nn-NO", "bdf0abab85a9efd3ff30e676752be3ef94d3606620e5b1cb87071c36d8cef267c57b4d074daab3963f319c96042c9983dd07a492fb96bb94d8c5a6612cf53dc4");
            result.Add("or", "12bba91147a33dab184c3a30ee16f9d6f3da3ffd3effdb1149fc2a573b9f5412ce1fc4685b6a59de93c15d4424cfc37ba8a4884871b49f6bc5841f439d56e300");
            result.Add("pa-IN", "7547bb9a7deee2fcd3f64bef54d14b37b46a06b7ad05580a88652f2e7bc5b0af758e756fe4c7ed69f48244ecbc31ad2fb0f4dc397ecac532228567460f846d0d");
            result.Add("pl", "6d8a8e7a9ab78140367c7a3c3a7e063c286a120381e7feaeefdccb2a50f01eab949bfb737b553459ffed29542ef2a2fdc334e80c993a063e5787bee645db4b29");
            result.Add("pt-BR", "a6856760f927cf6fd4390834078aafed6b21cc370b83f81ddad85715da3947bf90963b09d089f6872de436299abb19235acc1ef8ed6fddeb2b561dad49569eb4");
            result.Add("pt-PT", "7be5d467473a024761e1a8fe895daae3ae04a3a3687270f5aaeb834ed10e35a4f35a360b9345f0232b80dda4ce132d0cc9bdc0c2edfdf0133d88558980ed3349");
            result.Add("rm", "2baf0504047a650db22e9d11e8b4e939b380d691018a43ea796662da8e8e6b7449166885e30ba8582461dc4fa377352d10ee39fca2e37ea78c04cf004c2c92fb");
            result.Add("ro", "f03e144713283a689c89abe46f7310a4a542da09e22a4d89ea4c489e1c69742bd7b356b63544861719cd1ab8fff2d8b13f4eab4059fbcb5be29420dab5b9cdce");
            result.Add("ru", "47143a8ac31ad6d21387f03e6aa0b9502e8f6f3abed23645bba8afa3c081d146bfa88d82d6193cb6a98749cbfaad9913cd5a89f176ee9e9341f24073bf3dccc1");
            result.Add("si", "8b167da3538f747cdc7984ff868f0af01b56e4a813af4ee43b1720ef6ae640f3a28855683054d3e2b6130a340fcbdc85076aa67770c7a78a032d9069691b05ad");
            result.Add("sk", "3209d56e103b4cbb843588129ac55eed0aa790776f23390aa52dae95d57388cb99c69e8637ff60b1f577a7f1297653d79ebf3a1f03db4a49b4f1169ed1f05b22");
            result.Add("sl", "1966885747dc8ff97e047e3e0d34807eb97f2a960f9da0e32467a26896690e3268ed9c13eaa9f57babe76b826dc9176d0a66a377a10e974ffab9818a09aa47cf");
            result.Add("son", "e5415a0bccd512eedea4d8d674f7d3f4dbfa1f0248c2af1740f7d2efc93e63cced282621ea21626dc8a37d1db153265093ff35aa1bf164236dbc547d8261b333");
            result.Add("sq", "a6f03822dcae693e2a9ac3e2bafc4abd7922ccc79a5398d379a9ed2e840b4ba6c6e7f5e8a406f0143d823d104d545409a6ff64da3afb1f9f1359a244a7f437bf");
            result.Add("sr", "2b75d0c361c04789588318a0c1243b193a0f53f316aa102e542bc89f50cb70c8b01136da82906ffcd9affa2170facb403dd7e35ba8101aca4cc447b5ed98b20b");
            result.Add("sv-SE", "a0649f710a1f39586048ef959d6d9208f56a56bd3fb8ee3f489a3efcf9c8cfebbebdfb33043113a33101e2339d73f7bb87675d1d5535f5c23e14126a79285a8e");
            result.Add("ta", "25de5435aea4150fb42836a3c0fa541a26c96c472471ebf4afbddb97dc267bb9f92574b3e1dd2b581d2ac882e2acbde22436d7ba88523da0e0789e23be947525");
            result.Add("te", "ef8bc2ff1bb772da45e48e460cd64531c76238514bc9a4103099b6655accdda7e28d42b1aa2cb335b09fddf2a824e8a422526991bddc19daec4d5d6f589648e7");
            result.Add("th", "712854d15c61cbb9506b92dd6ce330ac83c0c2a133d647276cacefcd0abb3ca42be956398e509e85897d9f349d5da879fc9b392e5d78fd5ac456a653e8e10721");
            result.Add("tr", "14a61e83f3a4e576ca4d0fac825c71dfaaaa7e487fc5132521a87fb937194178187f8820631178c401f9daa0cb03efb44679abcf6a1cd613e0c043c6a2d7c787");
            result.Add("uk", "3c680a711b19caee3a0f2034508ed525573e80f07d3645e4521dd98ddf6661235483beacbc2b9f5c5d7feb3f58b8cacedc2250ae5e785673f4b825ab2acc46ba");
            result.Add("ur", "ed1527a0d208043e3ca3d427906b798721a4bc3900ca5e36e09d00554d5c31a9ae386b616ca06c773dd71e06b19ce3d5b33e07e7d923174d3e4cd662e0aec5e4");
            result.Add("uz", "bdeb3cc4ef4ca4eb0ce5700d34628e4abd630e487383869d412baf3d04d70cfebcc6b0416912f6bf1b658a74f7798289baca7569723ad32d2717fe8f137c93eb");
            result.Add("vi", "66724d499c0aac7194135a6958e58b853e9d0c295d9e183630bc3963a0ef2ce83d88a0192d1863036555c5ebb736341d97c58033c76587dbdec8dcc328afbb7a");
            result.Add("xh", "ff04e61318eb438e7fe52d321d455e71437bc81078dcea073d3efc075a110a9b2056c2b9a3796e392749b14276433197f55f6b1e00bbb5af4c7db8da9924b952");
            result.Add("zh-CN", "e4fce57e41b08efaa8bc1a0b54192d1d9bae4182c66b3ab9fd48ae57a1c38a7303c13b9894e9ab179514cbaaede88393f92f2c1960fcf09f8abcbe484abb2f42");
            result.Add("zh-TW", "0f310087ae4216e2c1fd0224e8c017f367435cf328259bced8beb9e311b814e47a6ffef6707eb948334cd6c653291492c22c79aad021b39156b2c251af6d3cbc");

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
            const string knownVersion = "53.0.3";
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                //32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox"),
                //64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
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
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
        }


        /// <summary>
        /// tries to find the newest version number of Firefox
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
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
            logger.Debug("Searcing for newer version of Firefox...");
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
                // failure occurred
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
