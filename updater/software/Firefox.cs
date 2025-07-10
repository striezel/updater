﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net.Http;
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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6f7fdf4f9f519eab28d9091d8aa44515c44f01964f1d3be2fb7567f5a866f8f177d77264bd84d9b2f91be2e132e30e6f79b65be9444f9a565b0b57400d64bf9e" },
                { "af", "2e00fac5070978da9626a18c6a97872438615dde12e2491afb81247c3633d0cf02f16d1c7d3347b6073ba683e5b38fe8e3978ad97184eed0979cb884da9066df" },
                { "an", "eda6aafcfb4820ca95c6f525c8d1ee6a4e1759636ea1786fb4fcee7c8a061cfa78c4714fd48be47e14ddb23a36c84585b51536689000ed1c498aeda0677556ff" },
                { "ar", "442e30b59d420e270dcbc07caed3629adef429e3938c3ab06ecce70e8c182b2c0a4c2df6ae3e9e3353888d41af5e53989b9f0e256dfca964b4ab33c20b95a132" },
                { "ast", "4442aea374350a25a4fb648029e9034d6c612cb8b30d4904d4badf38bc599c9ee0cbdebc17648d89c5ebb18008393bf93852099fe4dc2ab285b274362fe28355" },
                { "az", "8a0adb6efa1e8665995d2dfbd0fc15f67f0aa53e9769994f7590e18b5ffd0d45f802edc522d3867222933a69a232d813a8d91168f7ad66e6c84fe7a3985215e2" },
                { "be", "a53a8438bd2f9240545ca0b4190546a5ed1da3dd9853901974932dd348703b831120b5a9e09511670c02de16a4a03063d31cd2a0612663eb9d2d29c08d186bad" },
                { "bg", "20d81d8568265304b04915419c50fa55df4403350c3a044160d9f46dc31b540bc33cb83035536298c2c4e7eccd354d26a196da59560fcb4b9249ab16ba4d0f92" },
                { "bn", "0d881f4fb6b9c0b5ef11b854be67d95632b1e80cd604255c4292c0ca1121f987347aa1568500509902e48a328d424f21b4711341c67df9a64b97af08ffa53b32" },
                { "br", "98d457d3ead3127190d0c4e00a1af50ced31cbde5ca1888ced5db3b74b1b6b3abfff800e95bff7211e42a6137f122bcfad85cacba6e3da56751d09547c6011a1" },
                { "bs", "a7d50606f302e2de012207c35d6805c6b13118a18aeee154f6bc059e372961fdc48d5b5de9a848de27501e8f780e91cfacd4e2f9885db0df3a929848ee9fe8d4" },
                { "ca", "6b432ed56a0801b553a6bc35bb8ba9c61347ebc4ef38878862df280b0d09e13276a3f5d4df1543017ff9765a77466b8e665458e35320d56ae6dd71f4fb898b84" },
                { "cak", "8503b020499f46c2dd44a46d0e3a4440126e5c093fd6d2e0a814b28bb34e4ebc3146fc75469a2ee387e09f671dbd2fd9eaf99127f7aa9c0a90a0caa8ce9e6b59" },
                { "cs", "679e2d306523a56a7da859c13083d005c4f7d1c5ebd3fd0183bbb1717b32b399d1234ca4a669d7046abe3da97b5bf435286775721afb9f704efb7cafe0427943" },
                { "cy", "a524c4da02d0d96122b7900ecc278f7ba443088017d09ee7df266b5b9ee34f848c26d838a0da2b28920b988acbb3723958a5581fdf56f0a806f24164eb55c9d9" },
                { "da", "426236d317a1def78962c277166ff7426613f384fa9b3c478531b45735d6f405f5facc66e91eb2764e08e8d1954866fbc0d4a91111a27face6a9cee4d5eec37d" },
                { "de", "1bd56c1db8c3c7897f4420b484c057363d5dfdaa5120c9d094a1cb49d803affa2685fdcad6827f1ff4d46399a41f32b7a9860fbac11c3eacc6ec4933c3546b65" },
                { "dsb", "7d22cf6497025f13005725e1e9189904806755d69a8109bf9d23ed8af855542f8cfb64e537a583d5475f3865cd098743d10d3f59e02278ea9717fef0c1aa1251" },
                { "el", "66764b53e31d2a657aa3ff8f32121913f6816783dc8c82124146001edea92d06fc782b6c8980ff66f2d93b86aaef70d49b75342f844726baea2d2eaea79506f8" },
                { "en-CA", "6b3800af974b792f62a5745c95b9d4a5759e5f8e5c583b25bb7bff42a64146f38b35d96ca86b46f4a7f5ba57eb5ff3e5055a387c9a04e9a19be9ec206812425c" },
                { "en-GB", "ef29f41a48c336ecffb31708540701cde45d3c750a6775e5aafb6e58444091bab9250ea16a34e52c57792a44084940b1d617f8cf10bd1c68f78cfa6429b1738d" },
                { "en-US", "83536ef32d0b597b027ac8d7dee65195036e262ac94980f4f08c5b1fcc816fef186770039c6a335c93c544c0b57a0e0c301fb9b0bcc1d14a4abd04f4d047a644" },
                { "eo", "55558970ace8e5165b955fe9e2351cb00821a172f04df0b8e0d3a3f2353e03dac4765a7d41fc87fa63dad2f2b0d5ac9884bc5f2a83aa6e5407db582b0d6e38e2" },
                { "es-AR", "cd084c0f5e0cc96e0c2b9c5a1fb429dad5745ef4a8cea976852097e4804f1bb89010780a30f7d5c199248b77184cc732f72bab0acf9d24c38ab83dd0b6b366ed" },
                { "es-CL", "8602cd828ff5a43196015dd0c8973b95423c9c73908ee93240e206d219a1ea1f436a48c88e36cf898b29b3dcb8c6f7f4bd5ed5d982252b60151ab3b0c22cdd6a" },
                { "es-ES", "c74cc9e025e25f0fc6fd1108406a78272199506ebc9b835b42101b2c792fe1f630a5fbe348c2244bb054b21472e05934eaae1a129e983cc59236892b800eccc7" },
                { "es-MX", "4c544cd3041bae7712371d707640ac3ad6dfd0c1ec821f47030a26cb878ffaea1563798385415c243488dd496fffbcef210beebe95759e110fb9344d74d0c929" },
                { "et", "41a6aae612ece43f565ed51b028d89b4189c85763d96b62c44eeff1b70e4053f1ec895386f59c8c8b3a31907da8225f2dfe2d244e3280427fb4e85b67aec1b6f" },
                { "eu", "4cb8e856f732947bc41fea8be209436133f3c54b5edcae558b25b70cebc914caa97796ede71bd6a016cd92d04ea354d6d3e28c85ec62187060cfdcf516883bd9" },
                { "fa", "354524ca2ef5e9b137253477975ec9e1bb69b3ca4c6cac6b737f097bee80ab36d51de55d677a28f85b1e5e11772b0068dbc43a8717d933d722dce5ff2df75dc5" },
                { "ff", "86b770db5bced1abab45fbd405a6a30d6d73458bc06eab7e2b99753f23c3ddea6f85cd870b9dd8584ccdfdee42cb09fdca8c530cef5730a4ea2bfb6a89076e74" },
                { "fi", "8a78d77dc89adc18ff756067cf5f41c603f05185f69f623a1dd7738b88e69885399d265793f8e7bbe390824952c43d63c0864922803effcdb15978ec84b163c6" },
                { "fr", "7b63498e72b9aa70c79ebe7a86b64da4dd4d37da96ad31666ff2b691ecd9c96271663ef578779daacdfdd4f817c95d4d6228309cc5dc6e6f2251ccb8a3318036" },
                { "fur", "f5d33badd91942ff436b47bc9c8e236876cee4b75d9251c36d3f391e75531a5b3b811c1e9c84cd8bb430618f9c6a8b12006283bdf061afd4e99d79f29ac07ef3" },
                { "fy-NL", "c0b66fb0049043146cb6c030d48777638a48a453355e7e71dfa9cbdfd7d600565b39dbd1a6d12a5e0e8a93d39fcf69f5f251ab86e584ca796f5aa94a89605573" },
                { "ga-IE", "660b05c4a213c656a2a7007d57ccb3aac0d9610dd37bd6acf6a03eebba88ac1982a45744083ab091ba1b47707e26ed5e5218724aaa8dfca87f3fd5ef2ec0d8df" },
                { "gd", "ea63be95d4fb61d0e5395ce77981d754dbab874a29f1cefaf4e066c00faa0ef30fbc2d81b81bed846ea54da1979626570957dc842da77380345bffa0f1412dbb" },
                { "gl", "99003e3f8c466a8e33193257ff32568dad479fa4e30d35ca5a340c6d222aade34a1ee5b3c2963f6bae78aeaabb0e1b0a199a5dd7586b536af222ec17ac655820" },
                { "gn", "4dc05f71cb9997f7394cb14de1e7cee200e6c46952e4edada94b49cf61746d8a8d70f2d97250cee696fdd80968053eb4f916bb47b80c9814758237b468e5ec87" },
                { "gu-IN", "1fa1759ab086952f4b7846babd69a2d58b494f3bd2b15b449d5e211afaf908578135e1aa796f9f93036d2168e4ddbc917d95f6781fe3c48543ff1e27e26299d9" },
                { "he", "d7ff3dcf9e2673d6b00e4b3ef05b1d876eda052f844c0502fad753d8bd6c2fa297096cb4f0b892bde3eb9958f4e4e84beafae7355e4401d0512f2c8a74179896" },
                { "hi-IN", "f13b48590951c09751e8cb3414d730fdf25b6f5e9282e33abdd6697c58ea430b0e5e957bc76972bf4755c3463d58db078e296d84e8b025edd91825fbfd919ea3" },
                { "hr", "3e0e3296db3e2f7ee7430c7e870035dddf2bc20496000b8a13e3ef8401ebc35c848d36c562005575df1ef8efaad34f6f0a32b850711e7f6d151c4bb94cbb4fe5" },
                { "hsb", "ae30e0d281abea50a7d5fad06734cd16f2dc1266f3eee66e88b4bf53fab81303399d5359a669312d5f774362542fc36748b0c7fb998174289792b0647b88e0d6" },
                { "hu", "6f5935c63127d8c83248915caf671a2042e5bb5acaf3db3fa55117f545e4bec48a408ea733956457fa8ef2d810bd1cd3be5dc995c9cb55e082fd906ea8172371" },
                { "hy-AM", "362f7557caf6291218cd09a0e9dabb12208e8b96723a032b83ed038925c22d5e7191d6b9483f4659cf82b8bd570b88052880cf5dcda4a8ec1e37333ea6d03721" },
                { "ia", "885a30422f47da94a919caaef7e10110753425321ce07564a227bc2d1d2d5e790d7e1b48dd50684e57f7a32dbe9537fe87d3bca183801985d291e4b05a969f64" },
                { "id", "30c6b4a8b8b35e628d2c8d899a4d39c99e33bb4fc7b9d2d6bc6959d2777669f60c850a3257cfae38cbeb2a053ab28bd1149f1263e728333baf2c8e301127b150" },
                { "is", "66c448dd7dd7acfe50ba43c7f3e5817545f3f444e114a1269599be01eadba2ac817b2f14222ddb6a47cf8b4bdc0fd17a4d5721f8fad9cf6d98d2936146f84411" },
                { "it", "e7ab0e990241b79539e69493a4e28a92710ed74b14301e1cf35de57c3d58c259cc1edbaf1a31aa670faf03d903fff6647fc795d6b901422b480246c899fa869b" },
                { "ja", "45229b2a4f5963053715e970f2bcdeef22f757e27f2d264da25d7065ae5d1c3dc3aa0ca00a7eaa76e8913022d4b7546bdbfc00ac71d0396a96939ad32155da88" },
                { "ka", "8fb2b36c8c991d2480f514a57b6f06385d28cc4ad89bb74f6e0b109b8199bb0192ccdb9c0bfcab502a660dbc77ee65c363d039ce47cfddadd9316a59fcb7a905" },
                { "kab", "d2448048c81eaa78a787f743641a8b36f3aa0bf8eaa1936f2e704c83744f2960b4d781025d98ee2646a2cdfdac790b0827ecd580a13524f6a8621d61e9cb6d01" },
                { "kk", "15f6ab89eddcd76acb954567d21e54747c530ce61a7bee047a1ef62e128e1a8634a65a989a00317fcf7ff008d20c40431b216b8b5208792c4c52f9d53d726b1c" },
                { "km", "1eb649d044a53b2f8d2208e9a746337279b92e235f92675a0a4e340d038abbe592fe1ea58f19c2a8657beba5e568c749a3939d919063f2911cf893369877da8d" },
                { "kn", "5895fb2703613f02f26eea7f6c152dd5a88deba773d35580a49da9b4a5268bb42b84924df14b652ebce4c069de8bacf5fe464c58d0e3630138f1bf1ee276237e" },
                { "ko", "2b7e88ce03dcd0b4f46372887cfec56fea62e683accc74566961229f00c22873d521f3ded69620a9de84fe87abdea767237e8272e915f852b8b17d321e1d8ad6" },
                { "lij", "ee5c2f0ec3b056d0c020cea2990b066debf40079a51a3119de18ea36b4bdcae67462280475aca58f7a3618144e3ae5870032630f0c72e30d60cd51058ca7901a" },
                { "lt", "da6ffcfb753c314a4f2f774c60fb7cb907e5b1240d56f71b018dd202a22db4d7ead943d6231b267ca6a5c8706d0966b3e29a11fbb063db355f635963f2946b5e" },
                { "lv", "e862652d96ee86bdb8429ebdf75171b3290a64e4d8513ad42206efd68c2ebb6848866ee31d17ba3e00dcc73eead33414842f3f751dd25ad2297817e51502beb0" },
                { "mk", "320f3d2fc8cccef5374bf94984f1d0b33d750afc89af03a13dd04d572fea352cf59cd1c03d1a8140ddd57e4c807580fb06008502b1802b0ba311cc9bc19277ed" },
                { "mr", "5cb52cbcb3f2a7032a765767811a5174b9f0450be5c3a4dd466b6d3146ed119b442101f124af616916ce7a1e9e4f6dd70af5e0b5892bec1382da47ed45d09161" },
                { "ms", "467653142299bd36f7cf916f01116856e074b8b4d5eb3c153440d4115bafc78a52c8ec463fd528de8a1e038b28d24ae72e505fefda823596edd3ae867ab047a9" },
                { "my", "e42b72d6d7315694ff245b04a76abd8987212dc178ae069ab62c53cd67831c68626da514b94fa47d69ac05734e34f645529140e7e1d86ebbd19edc5d3cc65e54" },
                { "nb-NO", "e97b670c3fcce6057ae0aa16702eb28414177a40ae771856a230b91ec7876e4250fe571a745561b3817433e0d00fd4669c36cb79d6127274baada9795a106de6" },
                { "ne-NP", "f82e2d7d1d95f2aee53d4e38c46855a7d9128727ec27658024fcacc607ada93e180630f232512a0d2de12188e6520a53e9b68750e6d4b77cc4906086fb4a1441" },
                { "nl", "ed7b2b62bcbe0573b0c97327d76e3f767b77a4d3f35ec67abee6e4b17d61583cce19aca309b03868b444b6fe96b48bdf392042d0ac9571662e78241f0c35594e" },
                { "nn-NO", "47cf1f255b1899834650c3b9f2886ec2d8c03bcfe27a245066c3f366c0d1e667b4c51e1d7d8855002b93350c149525174108e1e32ec9485d5884a3419b2db8a8" },
                { "oc", "267bab0203b59948270e871b8dd213f8c1ce37ed1017e73ff68a46b43aa0fb3e4aba31c5b7b21e7924102b57cb19569cf7cf8dbb54797b1e8e3e4ecdb9990fd1" },
                { "pa-IN", "099c04ee204f6a0bfb0e5e32987704418b097dea90180d925cecd16586f3111615a086a9aa54e5c23737a013321208250ed92dfc5b38077a5d4f046e5347421c" },
                { "pl", "b92e2983e77b39cfe10be23ad688cb84c54928df6873a5e563a31597b30c5f471dada80c945f7163c4ff70e92a93ae0a23ba38d2abb235db63a5f9ad9e02b09b" },
                { "pt-BR", "c583466055fc70b027014e0aeb7c7a38551299379ba9da67da104567a38dfa00cf590d3475d1e58546d23e769007e63e96e80288666ffd74177dcb9651c5a7af" },
                { "pt-PT", "6d0fc86df8ac3d7bc844e9b25377818696d59eb441a336f3277b8e956582cc2165602b22152fcae1559454918224d85f5e81c1741e40333a07a88906cc006363" },
                { "rm", "932452ff1fab91998e18afe4a8ace4c0617e0e2b8e9e3fe38d419e79f07780b9b3853affb1033cb64acacf1779817503c4c0e3125e5636b97980f848b20ce64c" },
                { "ro", "726952ae862ae4a7b19dd246de95d030e0a6c4219f21a3cdb0284ed38ebbe8933ebbb796b2273ba28c7310d6bbbe4616b5641e4fb6e3466f60adbf3a51517861" },
                { "ru", "cd410c3c5a599da313f4ec17bb888b832a008885b1e05bc341f9e55b9c82029f8095b44890d0aa7f199dd228206501a9f9a63d87b466a812d17d4ae9b73c2b7e" },
                { "sat", "90401b277867f3ef7df8e80eaf1ab766615607fb9f68b473a5cd647f21f000f05912a70eeeb0e85b9f8c8a9411754c8d5f056ceda187db58887946a650cc9485" },
                { "sc", "e035845bfcad0359ad55c42883d4002a90be3bfdce171de35067e0fcd6d94891483e49e6b2006127bc4f8b689d2b4c8dc9929cbe5cf5a5161e607188c834de7e" },
                { "sco", "4a3abf64e42b1f67e83221589dddf13c01acac87ee5010fd6aeac8459488c9c3617bbf9b7662fe950e1a4468899911a148d4e392319756918a276cea2df4067e" },
                { "si", "44722306520ffda510e12ec721c8bd696eb60e04d22394e372e17c44ee27ae2643b9fee93ad03b6638141f2d9c21917cfa8ce79f3f953141b8d800cd776218d9" },
                { "sk", "ffff918849d82df183313548845d2b5ac00027445ad3e1c1c5d5af1a59410e1fabaf8343c68770a7e3330ec5481bd85d7b4c088729a9e6e9c46fc188707d6ada" },
                { "skr", "bcbd338c8d281479ae45c405f3d2bad689710f45964dd51605fe1419d04f99c319e299291fe24c5962f8aaeb48fff4aa3e50ccafe6c292fe2a6645d0cb6767af" },
                { "sl", "66c6455b88b87f4217b79830b138069211e422bbd69a27e267918bc0ffa79e92614ad43429343e304b39c7dbd3632b5823edb6b613966e65eea62ade22e06ac9" },
                { "son", "4923880a6f7d2559f378e4270ac0f61b8a36d00dcfe08ac8e24c0cf9392cb7b3d6222526bc5b9a6b24f451ce2be33c7aad132580949528c6590edf43936837b0" },
                { "sq", "aef0ccd5a37f374407bde18dd1177c3011dbd58e0bd8d1647746531841d6387adaa379b24ac6e3c3250ccb176a55031b1be4be306c26c4897a6b0bbfa7195742" },
                { "sr", "305427478417efcfec501a014c52a0890d8a1a7a5e02eed2ed6575650bee08c58665f0ea3a347bf8650af378358badfa04896f86392c11cd59b3bf7d9b689cd9" },
                { "sv-SE", "e19be64709f6797cdf8f28ec443031cfa0c1f9d12a96ada5bb5ab881eccb18caa9eb2fd8754a28c2158a0a09ef4572759ad9cd444be76c9f854a690de2cf68ca" },
                { "szl", "0a23acd46fde1a48c1ac1c50465d819a0171818f39cad0e7337a47fc7098bfa615d16cae7f3fe75f47f889d3fdafbbc77f7457c707fe783c4a65a99a17a20589" },
                { "ta", "743b618e7c3a976ace54345fecb6afab31e9aedf58919f73d7aee2e2ba38aaecf1dae20007f9b8b694a523b9865dff47b1b1a3ac94e604c75faf4688458a275e" },
                { "te", "5a90867d748414317ce8424ebd5f6f5a415142b147f5e74e270fbb48d60059b6181700ade87fbba7b222f74b210462ada4670b6304cc2adba2e9efcf797509d8" },
                { "tg", "731b21bd86e74249775178598a77ccaf3f33b39cc45556a4a793f70ebe47f3b916df05ae50e1f8dee879e87e3f52f9c298f312f75bc438657dea1a920c9a7394" },
                { "th", "640a8eb99d47ca08980b59cc8e642ef8cdfef71c32d62c260bc80079b3a931bc97df9aebef4580f1f94212c514038de480b564858d3a460815da3900e9032a90" },
                { "tl", "5b10a832ac2e0ec3972c5005247ff0082c8f5cabe4b43e58e99a7d43e6f875e84ade90c6f4d8182f107ace55f7daad2d3cc6093cf85dbd4c42e66c273751bccb" },
                { "tr", "6c16ca93cde3ddc77b6ffc2ebf2ed3607ded4ad07b239e2db1a5959f567b89356838916f901e2b36b3b2fde3cd7e5072f5c485444514f2af907b32f9b7f84508" },
                { "trs", "e79d0c064c274c5c272ec4d3fcc2e04d7a6567c3c940fe93d9c06ab14dd25b0eda54a5c89763c25ed080bde175ccd19425e595777e5c642f49279b298bc33eac" },
                { "uk", "f62261ef8cb33c72795aaf99c21e08b201ae8c196ad626876b5a9c5a2550dc729959b705cd89e6825974c5e0047a724818f6087be23536a0164c132354eb21be" },
                { "ur", "94198c08a41855022b9bbc5a6e10ab1aa0b626bf00f035601abee1e3a150942bdf51cd48d8f4ab6dbab2c1f8b5300a53312017039dbc11778440c8f860b974cd" },
                { "uz", "60d579dc635852183159e2856af044871f05dcb5d3d0957f8bb714e6922a5b2bf83553afc039b9add9a085f0d005110e7c3dfaae685ea0edd06bd75c1740fd9e" },
                { "vi", "9db65e14a3fdf31a9af929580106c97b4fa2b1797489a70a0862e862e6ad83cd9bc95af96d21840e8500fd14a73d3b7ed9366c42dfa42da806118dcbf266c018" },
                { "xh", "fca97aa85b44c09d5c2040e472d50d5bbe2e088e607d35c5eb095985bef95b71485ba84daf70db8b2e63f31d77dd6ed4ee35e24db1debb6ddeccbeef1b158fd5" },
                { "zh-CN", "f0055e31377aebbf315e3b595746999a2754235bc0494503ad560cc5a7d55bc07600c4de0dac11a6c58ff46b504a68fd7b7d0b3db46bd73eae24dd17bef4fcfb" },
                { "zh-TW", "c5c3da30257c61af3470508a73947cb7f3fd55ff12649e9f7faa106553a924b553633a97d799b5dd47ba125bba3c1963d41a01c86d2c20a30076bf8f2b75d451" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "1ca2fc74b34b63e8073bac6427250a2b816d9b94c0b8d2cafb64c2866440f71c903e76412a39ea5871e46868ddd4ab8ac4d423cb24c1ba8f8755c3d71bcc4161" },
                { "af", "538b1bfd4f414406bb5a35b7fc381942085219bff2b8b665cfde8d5d12be88fa08e23d61fd6ed7792a17c65adb59ff8dda8ac72a2c3aa71860a0fff22ff65120" },
                { "an", "6a2a70390ad21f83a68df1518830e3a2c83f8082c96f7ca53621aad0581f530550f47cd6caf229e8c57fe0eac9cb42f463541b39d83108623a46ef861d35824f" },
                { "ar", "7bc6de6a344c4d1c3eff8df1d984a3ec68d171f39767b3b3313365340af3dc9ab6abc0f06b1525c2b05151125a25d469c78195b3416c5f8cab05cd4f4cdee1bd" },
                { "ast", "0fd23abc235aa6a1f1969d68da37d0ee63ce756ed46d6498c72c4b11dd0721d3d98ac029a8e97028b9c89b274fb641c6d0f6ef68af12821b846105c2ec2d4e50" },
                { "az", "fa9e5e635d041884dd9f778be41e1e58f2f55cad5c5e47dcf1903133562b7ddb923010d19ef604faa5759e0d018138719570ceac03e7109f1a031a057331013b" },
                { "be", "3c92c80afc8f354a53d024774f22f3534c6ea909dd52f9343ca82d0183cb5985c24f79574438bbb4e5de72867848e849db52ee33b7b43a55425dc75f5e842d3d" },
                { "bg", "3fc7b806fb84087506749a8630988bd7b8d3129556c0df6c713f1bb5fb90890453baf30e087c2cd83eadd60b6d587df1d2f5b89da0172a753cda2c1f37fb7ace" },
                { "bn", "895542b41ee2aa0ba902cee968e8a2714a2196c89d0d7f609996ccef61c77edb24a1c388a30b764a2c0ebc00b3170b484fe5138773fa3ebfc3078ad9f2072636" },
                { "br", "e46f055336c480ddd8d3d4fcf324336a7ffcdae8fb4df1720b00f5d6ce7aab0aba4f9aeebd22bbcae25a9bcea9bc3216ea350c54d7f09293af45f446aff3c339" },
                { "bs", "890e0ea4972e7adec9f2dca83b9dd09156df2db76f537dad8b6851f3163035c509912e284adec00d94e377b1982e555b901a0a6b19649c25daabcc971caf8df9" },
                { "ca", "71a576799a316fe3c67bcbcd3db9fdbc614c1e16c466786464c2eb09160ad2072b73409442b9b74d4692255b7d1143f67904e9f16e4c2059bbbcac8fc5181e38" },
                { "cak", "2b07e3dc868fe63e8ece1b20c69996c259a03890d41002b86529ea8f3dedadc47d77f0af4f21e966a2cf256b62a9dc28b93e38850c800da6e0c26b70468bda16" },
                { "cs", "86561d7aa334dd22d9613973c7f0d504fb8ed5569ebdbc84fc71d1f931b5ce995ea2d261c97f783c4cfbff4b51fe414eb6734e5bf6d30062048a7200a95b2d0c" },
                { "cy", "d1b6216cd04c1cca7effdf8fe725be45a3cf5d7b7d1cd86c5480a0b323b991e1d09564fe835d7d7c681705fc1b80edddce2dfe42e75d6088b118a65a6e4f6c93" },
                { "da", "f9fced1603538c39477ce3015598d202292b9e0f063a23383fc1a94cf1fe3731e7ea0abb2ad18a638f31f809f391e7cc8fce01b9dbe12c90bca5e9df029ca8e1" },
                { "de", "229d94ffa1ec86ef75e19407e3e1543a915302c48d60b6003c8e1a660fad89a05c88291dfe790ca54efd45fc2195cbeba5120d6f7ba9e5be6debd345c16e8a3e" },
                { "dsb", "d4eda3c7413ae47c968aa09664bb23b5256e9aec9658abf05bc78a1b2264178186e4ec68c185571768413eaebe4e0ee50bf7d965af4c99ffe1a53b3530168d7a" },
                { "el", "5bae4ea67931b5d3ac62eed53684660a5c310eeabd4a0435a5fbab80496f71df9b318ae3f7fb7d476e0aa8050d84958e2396a25f24d0cd56566a07e0273794c0" },
                { "en-CA", "6072afed741b718c565c6c8b221e5774decddfff3dc110dd2540a34e6a90b5ff9e5bf771b08573b5489aeca9799cb31edd306180239b7d98ca83985db8dd205e" },
                { "en-GB", "18ef3634178e3b0f08b37e66a712374ebd4513bd4f79f37aac2ae76db74805e15ae76237d993d765973bb62656da80bc20d4860312fcb21aad46ac58f1a3a14e" },
                { "en-US", "2bb75bb58ab8a3a7321ad8bd7818167bc9ca410fa770ba7b402d25f967f477fb5e8518f807df0c8f1d74811ff8a30b2a96f4f4ea41c06a019ba2e6b777638119" },
                { "eo", "a87e6b0ec46e381fb2abf26a8e35b1164a3c1ab53da382d25b848fce7bf9f5271762d14741040104d25bc59e655a8fa9f72495587369422fc601077da7f03ac7" },
                { "es-AR", "017f777a3a688dae175cdf1f6c471814c67e235bee0359e32e741ebf20f707a648234f71110c4464ec88936c2d1be6d8dc459eeaee424f4eea32bc6f51e14b8a" },
                { "es-CL", "7e1d80764f0db05f60353463b54adb75cf2a9af5251f20e4101d84d973b8c67508f3ca380a5862a8a5f6cab0e7e40b576763bacb9a1e5d533031ba14c81d2a11" },
                { "es-ES", "e60ad51baf46e01aa6bf119bb487eda41b3bca358234849900e6ddb3a287e84d33602fb0b3b1019df9f5a8f7392740a775d3d011facf9eda782827211bc4aebb" },
                { "es-MX", "6eefeb825837aa35a24df95447b48c4f7e6b1243176eaa1735319b297e3f4b9d66af3ce6276026068074c44bcc1d75b50e971f5fb3ae44373f1f6b68c65235d8" },
                { "et", "7e88094f2c37642cb4b29a2fab4bc3fb92bbaccc74445a6ded4b501feeb3298152d390cb80abdc0d162a753d0347c6b86176034ae6d6e256dd9d066a2edb4736" },
                { "eu", "af71434558d266b0140613ca4d174c5bb2cef7be8c4b6ee9aa2eb60b5fda08e967f5e694f6bde3e27939edaf160b882325af7cf50b092a26509927fe610f29d0" },
                { "fa", "cd200364a52c1b397e7b7a482ebbeac658df7d71958479aa1fd6eb134a02a83bc7e4fcec095f2d52ff9506ca01c2a7a7214879004194272348d1ac238b01679c" },
                { "ff", "a33401955212fd2d3846e047d74f8c4a01263840d33b70e46d87be0b5cef92221dc9a8afcd9f3bc483d3884a6357e5ef50178ad49fe1d00fcafade607c053acd" },
                { "fi", "6fc141c5c01e46c715594124569f8064859133bf68a5497544101385d8c527353421f388a225118b0c32e6e9c385ab7a876c8ea69c0a92ac5f82590b6ea0de39" },
                { "fr", "ebf9b2e59d3d061f600a64f6c5ff835a591840ab256414609094682145868db08bec40239f78397f4934049d3672eda718b6a0740d0e77d5833242b169385f55" },
                { "fur", "43c237daaf893aa698e5e0fe6752ece23efdb7bd6259e68a8d459a9416d085ca211812d0589d808904ff4487379e6f230db50fb5de58c92feb6b58ec011eb38d" },
                { "fy-NL", "22ab877c3b814fbd4edd2776ff5ea76d5a277b283fca7718114f4c3daa9f9f60479ed8603e8d134e4713023340934aaace5db7d6e6f9d3eebce048b0c836d27a" },
                { "ga-IE", "7c8edef4798fb61d29edbd55a4182604305340129e3f5ccdff6a8e1fefc753522596e148999f507b439fffbbe6682a474f5a7695bb6dabe7752f3f9e6d470eea" },
                { "gd", "41af24277bccaccd6ae37dec47f2a54117b50f083084096f40a527772c3e426a6d337f6fac89c77e56900c6de7da4179ab5d5660a65460ae0ae397b655ee41a0" },
                { "gl", "731b9e2b477602a01631ff45dc65f7a3adff0783185f767c58e6450369d6b2bc02a426cc5265a970a6703c47f67dcb24ac24801b53da4be522a2ec88667196b8" },
                { "gn", "cf292503cc4b35721d56d66be20b5deb2440127a972633d55b9c588e4f1522e06875d80b6983e3716e3c81781d886652b25720822cb6fac5ae3cfb23de829f9e" },
                { "gu-IN", "ea07f3e815d3426e72948a8a1b857f1af413f4ba100a67ec4fd4a683e4ab8bbcbebc0f5443c7235bd071f3050db9011479b2c278a4d7a2094ebb3daac8db62a1" },
                { "he", "0e5db22683d30c559fc814bef49e75341bcf0c9bf12ba47f90672fb59bcd901c08e16f92c4afae128ece08dc62cb27d899676cd25a4b3048eba4507a86401e63" },
                { "hi-IN", "6a2fd39b024c75a544c9e886c640806607734ebccb969849a6c604deb8246154c0b1dc4d824d37eeca63c51d2ae7c4ba1d3da1fedc426ae030bd1d19e74cbe63" },
                { "hr", "dd220ac17ab8b6eb56f3ac58017d3461ffc06e9c1d32778614d855dde6375f86a4b98a5db1175e7faf81260f6d9f9d6ec8dc5b80ebd0143d6bb56f34b480081a" },
                { "hsb", "0e9a2d6b9405fdcb186b82df86ce73026829562d0181772cace8dc6eb3c908415c5393560c9e5053a5f9ec73eeca41f5e615e60b30067f5d9a50fb5347105325" },
                { "hu", "f2d3628d9b026985874f725b0378d1c36e4a9b7463118be77f356b04ed1b570f64c3ff1a3978b0365e5c651358ce1b130d8994ceaf9d6a6ad3a6bb6ca6785e16" },
                { "hy-AM", "832b3dd2ffee1ee5a0b8e4eb34ae9285e66c37dc820c7402caffbd8aff555ba305898efaa80baffa3e5190ad4e8561a1b04a9f33f38b11aa85051981e34ffd69" },
                { "ia", "8f090156ffdfd30ed21a8a0c7dc3d0e9f93f52e7e754d3f68dca4ebe01ee8355c695c392ef2c84f83440f2a7e3f8e619437790d28ec582c20211c86f8448df1d" },
                { "id", "043d4f278e7bb0644441c56d02cd8ef67a39cda3e9cb4f34f43ad4755940a3fc5d1e77fbc91982d97abe4a81aed016cac6cdad1703378a0da890913904e79424" },
                { "is", "acad513674d72a5135e975684e8d4b73a6fc0a0c3a741fd36946a5ee78c59d89376dee35958c27b9d5f9f9662bd554fc8289f217558f221b983d0b1820a98cd9" },
                { "it", "8db226dbe8b6015be5b285ff1e4251ec4253cc22fbcca0fd0483ba2cccb32d2f680bd87e79bfd8153cb1d12187fd0c5816ed3ab788f8468881cc8f2026456517" },
                { "ja", "c1cc7edb459f7a92b30339a020997fad567ace3fb2c31c3590ff018596dde30bb53cda364feb41991effbf4a918a4f062c020e9a84a75fe9dbfd953ff86ad64a" },
                { "ka", "b8c3b7007e11898e6a214f340977cf9e739f81f2f12b3613f851dcccab5d6b181c696a179966d3aef94414d06c49b1706caa7b9ee0d7418885a52d70454aeb5a" },
                { "kab", "727dff3a6dac59781d3f0e0353da655f056938e97f4c4467029a40e507cec9cc12ddfbd963d8c43328e0d2ba9220b50d237eaff9f412df158d9cbdf8b6fd4b9c" },
                { "kk", "4659fed5a1dea60674dd7c38798f5acdfb9e2b0801266daaf5d9d7e5866c711c07b3b4059c90255d946219966376f40ded0e7784bc33fe02e68a84c1bc62aa41" },
                { "km", "d7c843c451107801dc658b08eeecb062eb464d86c1abb8a8196fb23f34e6caa296631ee21e9c35365c2d703bd95e59b7256090e031bebab2ab129dcff78bf9e4" },
                { "kn", "3499f1a505a575eb63fef1551aa29218e9e2dcd17ec88994a8fe11128b78a60955e69e70540dd0e29cd063d62e4bd677ad8d2f38ed7cd697f0847c65d866bd69" },
                { "ko", "13135c958ac053602fe4d47a6a63c1dd9ff3198edbab3ab4449c15fbc1e0b14db0ebe9dfd26569ead4dd1dd4c823c0807ccb9c0ebc47779befd303598dcca4dd" },
                { "lij", "22fbf9fef14aac9eda2135a7461e6d0fb92f2c507e36cb4ba85f56dc5cc417595cc6989f7c379c49f71f1f4f69af5238e24a953ad15233482f8e5582580ab809" },
                { "lt", "90f8c5697d7ae0dc15ea97c7afe17b2299e02f25d7229ec28873f26cba339184909cfdbcf60856097a0d0b12494cf94f037b7343b669d3be5f2a563a5d99f62b" },
                { "lv", "d4f98cb4a103567edd981c40b008d27e2e5d3e7e060a45c774604be445bc305e05b46cf9e49ebb3be2f59e25509733d1fc0a062cbe348025399bb7b4cf972278" },
                { "mk", "eb53eb54d0f9439eb1a68ca39c95f12ce036e9de5e19e7d0afa57aba72ba6c1e462d43985f596d6110aedf7454950c63b25f7ef20e9a291c08fad52a5609914d" },
                { "mr", "fa0cec14ebaf10c2154e8c16ddea4e67e54a0fed253619d9122d62d47211d6e8bdace77d9777cf311f64cb5186fce49dce96f24603a6e7bb3d9c8abdff0e6f6f" },
                { "ms", "14a8aa6e8a6de950a1b69312ab722c5def0a7e29e0e25b996fc4c2d8e7c89df743e58e2f62eda40bee281dd79d7a2e5e4734d01838237cc6aa2297b045a7fb48" },
                { "my", "ece0192e6d778dce0cdbf27a39eb821362b65a70f2a41cffc771127435a31edc9a94736b6cf93a4f462ed80aff76752577e14ac255739d7c38a3d994859af5a5" },
                { "nb-NO", "776af7c84382a8f27cdacda401fd542ae8f9a4b88443d10130646d0c500bfb095efa8e1aacbae821f5d2fb2b251cdf6cf5cf442faa4254922ab963c10aa7eb69" },
                { "ne-NP", "47f5d315c527e409177536124d111c8ecba4014156843ac736d3b58521113abebd1175651bcadd4cd52d51035eb52c3e4707daf6b968f79233eac6dee1ada66e" },
                { "nl", "59d6e7c52a2c43e8d8462b0439d7c2a96ab3361c421ab6e9167752c7bce35f62358051fe298a11a01637108534879c2d8105c2e6836cfada9506be25b7ed5d3c" },
                { "nn-NO", "636407324a78da79d4cd5e5d240efdd6c89c8ed0043f1a292cdeb69d4dedf20f49c863bdc93ec0ef9b1c0dfc20a6a634d0f19ca5d5ea32b5a052fa98add973cb" },
                { "oc", "7c8c57c620647521087d9e0e3061fa39f3e1859174b4017f2b3c718958bc9c524f38a7d88992f42e7c76af7b7cb4ac43511302b7c8518bfe247a797a262132ad" },
                { "pa-IN", "3c17cc04e740ebed4371ffa34edcaedc306e4d4251f0c20cd04e38ad61146c91cdfed56b3d6734b230099967d8984a72b77fbfef5f89c8ae7d8e660a2ed12730" },
                { "pl", "a97c83eb9c8d6d1c990ca0cc8dd3cb678a141e0070d488b4e713db59a63521ac67e8a0c927398c6f04d2c3794fd35a4697effa467094a780e13794b5d6b6db3f" },
                { "pt-BR", "99f5a81a92a90549560f44c227a9daea5fa0c2a452cb50216a06b83dc31b4ce395c38eee3064f8535326ed7ddf6fef3043c9b26863f83e3353ca8b626422a722" },
                { "pt-PT", "7df94de2cc4937ca898bcfaa0dc43dedee04bed5da66a7544d15179cc7ab8cfb5b2d824050b035633f79bb7756554b42b61ee13787fd3ce3bc04dcc59943e551" },
                { "rm", "391850a610b2a29ca4086b3eaab32ec3b46a355cb50d7db8384b75132961503873b802b07cedc63c71b652236468372883443123b2e69783af7afeb36b616b67" },
                { "ro", "a16d561b74df15cc64c458cd8fead80a34b87870777c02b346379fcc5123ea725ed40a166febec8490f29649ea4d37d2f2f918b708115989a68c4762528d7878" },
                { "ru", "b83c097bedd65475874c24e12f6eab412c104a4c7e4fa6a6b09e90f94e3d276fa59b2bedfa8930e8bc69629b010e3c76ef6216e5a5f5e3d7f5cf298fbb55df50" },
                { "sat", "c690a888a5403a904d6a67928536f3545ee2c7330ce1c8ae26a51acdc0b336681c0500dd8f252a55ffba5107f12390a6f905e03893849f60fc7027dfdd3f9a11" },
                { "sc", "45ce38a18799994875885f3144eadf2281fbac24c98cc810661bae14e0da03d1912bb5f1005e3960d383c9e6d867b150fd6d8c9e66f58c29b442ac283c62867a" },
                { "sco", "f63f15861b1b9a6132f985434d79b3e9d0c89ef025eea334abeeda414f0ea65865c3b2488ffe3996a4b3103de3a33377052bb399c0a522ad85db3aba771ae40b" },
                { "si", "9aa8e8e289da8fe4847d81bc9d0280e1caecf88500895b8a8625c599a111c1bed4314523bdfd7d0706eddd7a1446c571e647910c8fdcaa71ce065517f75d6cb4" },
                { "sk", "3d44c53c3c46a9df934c66f1399391a47a3c5860fcbcb84709630c1b53b0c0f3c2ddd4c17743f78310d44e07ca6b318fdb7ed2e7a35be08972454653ec0c29e3" },
                { "skr", "925778e8b9ae687d7a5b4101ead53d8da5109ecb718e528075831f45775dd6df2178f962225be04129729a4f11c9f7cc3c3815146dde297be370d0cbc33da242" },
                { "sl", "66f4a55ca5197b32c21f93ba5a740143e930f630b3daa0d676b095cce8f3ce581a5498a30691b3779d91f654c521595e77d5329d9d94ce0eb472c2ee2343cb17" },
                { "son", "6166813e8cd9f253ef9e37393a409d04fc68d966e9d8740a38fdf559cdeebdd4af2b6b33cdd5b9e8b035e6c008109b89e9af2d211fb7973d162bf8f9cb0e0c95" },
                { "sq", "3e8dcf23280fb89e18c6a4e4d47cfb49fb58b4579e3752563a4051db7aa8d306d522b00f46200162495adb1b3a80cef40397ac6ca9fee39a4ceddbbef2c6e10e" },
                { "sr", "76e65a954f186e0973bfbd5c6f2aa793506563050ae53c9c28a734fb85b2f7246b320d89e17c1dd569b514c9d00a46e1219143a092985a2a37c51dd7099a425e" },
                { "sv-SE", "4b650254fe48053b76d976ab3afefd30b7c9a1fa562d834d916170d9f535c5d9c45a4a77ac575cb0e4b80b24d8078d423f3a735105e61096e2190b3959327849" },
                { "szl", "407c909710b8aa47f24f21c8552fa55f95e1ecf453c417973852b98ceee493cbd7f8a368aab7041a00f1ac2f9c0ec1fb0a67edea83e79646dfa74ef43e9b32a2" },
                { "ta", "065a31639c75e3e90dd1321472e53683ebf2b348fbb0726059c4e01dfd9ee7de5c3e6d459cb50539710c4302a04619208a4f017bb909a02e4941deb1fa43170a" },
                { "te", "bf487bff58e047aff430643f76e7ad90f02835caf869882ead8e23c1640f91f3e20ca0df5164fcc473d83493bfe7979dfe48618fb5d04554882c078f06b92e87" },
                { "tg", "9c9043b07e8f3751be8ce1b5db2491a32ed410a51e1645bd7afe7118276d6592b75a2e6879860015426cb8e398c179808a9b005aa0897bfff38e88767fe2141f" },
                { "th", "eb077a40ca7fa720deb66aaab9826d90055f8c90a247c65beffa868f72cf5f9aef6e9c56de9eed1ced4b20c68a7c08b0b19195349c03f304b356426733cd2dfb" },
                { "tl", "f75848632307c97f05f508c5f86757780979b3709020534051e0e048538707f0291f4b3188f5792a6dee87f98d2e96b33528fa96deee6fb6e3e3f55965540f0f" },
                { "tr", "bd16e49b9759b821086eefbd3a6e4e163de8e0593f633522d2614f019479228ad7d5551c8215f053a11c6b23fbd97f3ed68ed0b9038680ebf50554246ca37910" },
                { "trs", "9bff3bf0a97f54af75b3777f1f2226b8207ded5b6bb0f883df89eac51d05f6f45549ab7c1baeb5427dba529b78028b812d3709df3193d60dab398fc76221586d" },
                { "uk", "82cb71dc29951f2a86c8ba209ad2749a77a2f1c2b52669e068ac65c03ada9a917890911c9251b535fcffc13141adfa8a3f96e0e6159cec4b5c08ba2f3a516f7b" },
                { "ur", "15ca5062872c30b62feda4e1be49fb3be2890072dc7e2b09f107284c74491199a92080e7e202c183511c8c0481b501234e707209285427565454a9a2fd66689f" },
                { "uz", "100a638a7c39b99f44ebd8d4080bacc8d71837f15d72ddfc25e657277189ff74797d7bdcb50dbefc5f707d6e2a2e9777d8ec2228105c04d09cce6986a2d61226" },
                { "vi", "7be856c12e2ff88c74133be442bf7573b6d113582a99f3cd88b12108d5a2fd004da3b5d795046031823efa47ce99f6a77b9c44cd0884d4cd61b22125abd145fc" },
                { "xh", "4d7aafec8ceb52bb1416a7b163e05238dc3a4cb0758955de5d40b9d49df9d6d1f10274d44c3fef97f99e07b3efbd5d086ab8d6ddab9aeaf5de6590285dab5638" },
                { "zh-CN", "71696b34bba27883dd3594b04448011f52c9eb1e3933ac25e3a9925a2023e317f5aa3d8b0c60a69aa9c0484a4c114a02ed71fffdd07e811713aea787b60fa3ce" },
                { "zh-TW", "822ddbdc49cf596b66351388570060ea3c9500aaabd954ebe2361cd0b9692b2308d73ce21d046c3109e3e63424fd4ac297684dc601b5a1e4378ac93c6d2b6fcd" }
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
            const string knownVersion = "140.0.4";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
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
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
            return [];
        }


        /// <summary>
        /// language code for the Firefox ESR version
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
