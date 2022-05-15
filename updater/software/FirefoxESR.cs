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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
            // https://ftp.mozilla.org/pub/firefox/releases/91.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "0dd7874cf265dd57658ba578b9378150eb606d646fec6abe910a7ab495bbc490d6c5ecca707c94489754e0fb14636d1e57944777cdb3454729359072fb576bbe" },
                { "af", "d49b8544419208fe3bb160d5c499b1f47c603195f6da4e682d311fce0ac4029737d572541391fbd3e928bf27949e61d6b965514055fea5dd1c5da968da184f0d" },
                { "an", "0fece04ed5a405daaef728c35cbe27eb3015d0950f3e0eefb3fb2db2ddd8be8784e22f68283f189158a5f08e2d4817b391081a7ed2d1fd575885152aab26a636" },
                { "ar", "9582b1ea1408376ea69274f00a1f30ace4ca14f19513e569cf9dff9b822118d1fb1a22ce265023f20a42ffe8a32e5cf45f819f0a67f530c8af2cfd3063a8531e" },
                { "ast", "44c8d1ee93c50c787584e9b60eb13b120206ce6d5f86721c3060cfeeed7af388ef3611c77a701af09b3c532be352419779fa7de1a7facb77a71ecd17ebd11131" },
                { "az", "e848bcdc7ac487166151a8abe86efd9d31705afd18cf71f183f1048c027d207cf69bfd9b9a16f928cdd6601dd23c41990f58bed0239a4df93171cc4e1e4ba82b" },
                { "be", "98ed8a267b09fac8c34d6564fd929cb2d9778851581072a483dd7e364fcb2fd6b6277541df2308382a663ca00555d01e03292cb8149d4f341460ba3da18fbb7d" },
                { "bg", "f3bb1467c1e4741a5399d0c61aeb6bc108a0e33619f75745f39a381a7bea82e35944a0fb5ff6a32d818461dcdb1674305bb0a99f7d29d9bac569d7803f49e719" },
                { "bn", "4fd9fa9ce22aa1c3c142f6d39133fb8e40284684f61e67963e66e612a6ae40f98025e4cec0a6b8216c08938d6d8fdc3385c41b269cf36e262ea46207eab0a843" },
                { "br", "96113fb4f749c30bf9245f409ecd7f03a740ccffe29d56ddb3be2bbdbd962e0ed533417991286c6e43aa8d4d2a5656dda2e028619093f64dbde9dd5db6e17386" },
                { "bs", "bfe4c76a6d195b43e38b98198748d530c6ca93e870c4b56db988346f1c1b08342e401c5086ca8faf9cb2a29cb976002410f2f2cff11cb70b0cb96223d6094474" },
                { "ca", "8429d7042d25f4629e8bab24c73986dcd9e708a807ddc180890b496fdf1473e1b4eba4dcc45fc2c723a310daa7e09e2f11c8b20576c250b3ac12bca3bdc199b2" },
                { "cak", "12a81df78df4a2fac43bdcb7eed98974ed7202577918169bb476b29385fa2e2874452b4aaf8bd4438a1f793045afce18123417b881ed28a27518de33c544f7a6" },
                { "cs", "14eca1fae41d69281737191f84e4c1f237e389bc9ed7545993ebcf3caacd326758b68ac512a043344b03e2e6690b4ece8a6ed877f86c745171418293e7a29a6c" },
                { "cy", "43af42aa3b7bb06f7f2dc9b00ab39c22472acf135e411f141308f7f81d1335472d40f4f5c7152a4f8b08f2f924ffbd8e19e08073b32ffd241bb0d4c4d0bd01e8" },
                { "da", "1b7baa693f8f9766488a02ab7390517b3d80192e17cab00e11240c83ca1e1a17350fd0c870bbde0f78aa49126a617f7c7511edba307a397a6ff93ffa65dbb405" },
                { "de", "5f42c862e9980dd30c5b0fb009ec27c60e4d877fbf9ca4ca06a2f982ad318e73b9e76f4d3d264e423067bb68bb1e8d5aa9321a51a7d4ddae5a50369943d0a9f4" },
                { "dsb", "f11a1bfdba7ddaf74d77d2f29760dcdf711c7e4a69b08a90c486053eae355a8bd9a0685805c6859cbb2634f92efbb61606f8eb976e9356bd1b5316af87db0fc5" },
                { "el", "6bddeecdcf633dd87b9a4c1a1b812350cebc941b639ebee65f046e15a43da659f5450175c7b69f59214a6c979f99454b123b288d8ef53d23765a70d98b882b20" },
                { "en-CA", "aa8571bb25305a981c940f4fda5ef128a49ea738d42516e9aeb260245a40f88dffeab07c0b70a33cfd32922f51731893c06369d5bcca3e14db4ebf44dd608cd8" },
                { "en-GB", "ad59efad2178083884fb8e2c690ed58bf54aa79b2ffc8cf8611c510694dece62769e4b75adde815cf7fe76263bc88c689b1df25a7aa548d8aaf192c91f0b9194" },
                { "en-US", "d0b52b07ae868d34196304b590346f4f0934385bccddec1b7f11fcad3c54f4e235762cb86dfc1f7779be9ba6b3c52999e6fda8454fa85381bc988d28d15fcff8" },
                { "eo", "7a095a767fc424b8320866f11f1d9ef5abad9ed6a0cfd22fe685c39cd5512152c7563552c0b7e132608c31a27026b85f053edef945c2e606cbaefddafd461735" },
                { "es-AR", "6eb7881191f102ab6a1c0555e3dbb3abc850ebf264b2e94793c6c269f9d0538f15082101bc2270206040f3952d529e75af715984cef0c207a2e1deea5ddb4e36" },
                { "es-CL", "9ecdb3093f360233c9797d766d788ba5e93b60a39956f1186a0b331ababf58a19e8f42eb2ab76c0cf9ba872363a5a3d28579e31021fbf62c838722461cf1c72d" },
                { "es-ES", "ae99ad1dfd53f1e38a94e42a4800d2070bd33815fc67bd7cabfc107082e0b87ccdf190ade1b0600898bf1c6f4277b0ed2331d5b4977848f72c8cfe5edb0569b3" },
                { "es-MX", "a8f3852735e68b010f2dc02ae2f799ce1497bebf4bc5920cfc6a012a023fd3c9a95cb51aec866f55d600a56040b0c9ad2920d9ea57cd68b4f268ae738d766d0c" },
                { "et", "56822d479d75672ea152f9e1347954369724885472cf8b0ddc3f4640d4f7bb02be5480030515386608180984768ae20394a608730698b7e6e3a32cbaab93bbe6" },
                { "eu", "bc225f61640495f95bd37a4c4f05c343ba737d7bea8280ce6cc3cb2dd72cd9446a8204c23a020b57e7b39f77778b8ee4ffbcb13d7f8cbdfbca01c8ab9417b580" },
                { "fa", "5ecad46cace2758c26ef5db2cba41316f83fbde1f2921955348faec24c5a13a0846a4ca2a19b363155bb0724c980e3652d36dce8c605e1bb5803333cc9bcaeb2" },
                { "ff", "a533cbcdec530a708a137685dbef4960a0c08bb5e8c0560f5a17dc8645ad4818af6ebef458d14f75fe288e87c58cb73ebb597819ce7b8c27df014f333adb4079" },
                { "fi", "9a7cd0d6a70ec4e291f300265249dcba6831dbe23f8649ddc558968b1bad5b7e2dc4ac8b06888b6c1445a071a3db0d2933102ea9d03bb6d2a14d9dfe55943dbd" },
                { "fr", "c031aea76d0e24715c2f2de9e02e5ba9988a98e85363cd3985a064790053006c3f5bc633380ea56969b5f4a5bccead77b2aeaa4f5ae6341201c3a7bb46c80678" },
                { "fy-NL", "22b596ee822ff0b798a87c6a2b36592d1f909d8a00fbfa63a06fc09bd5ada31d48d804bcb5236bf93dad85cf33a6644bfaef41ab7e1ac44102da5f08b74571a2" },
                { "ga-IE", "683a620e2da7b6543a841f5e91331cbc848a2c10cfc99cf987f82865616cf43fe02484cf98025f89164cbb28ebf4f51b2128faac3e0cb741c3493acd0c52c9b1" },
                { "gd", "544de216f37f3e6379f764ca51a5bfee3c9754ff74e54b98a24b761063e3d402e82e7d82bb62e15596682b0842c6d2762e0d51f277fe4a7652e7048b4dc477df" },
                { "gl", "317c96ba4c2299b58236c36458f3fca0663342ee87a8f725bf128c2184b5628169bc03eb4831b108ef0d9b4d2c51ae90a5089369c8a9e495ab1b48fcdaf2bbce" },
                { "gn", "be3807da1a61a0ff1f4e50c568c16ab9c2771316c6c4dc024ee5f2048791ca8da4cec5cd292b9e87cfd9dee9263cb4686669d73b004c71e4f1b5359aea0dfe21" },
                { "gu-IN", "f320c128cc21e0beafe103e11d49570cdec8e294cfd3416f28c15c2bc4a11785801e16f912764395c8da3fccc0f0fe90304c4da0fd88615d6757da75ce190f67" },
                { "he", "b4d3aeeaeb055015574effe7a984ce6adce58f70c40a214371b41aef14f8a001a67eb31c2e0444717e9727f0f077bc5acf94d49432e07a8343ad1731256eb16c" },
                { "hi-IN", "577ade378cf5da6df81e05f7a74cb1f9e2e869dd296d42bc07c4298d64c50a22629f7f0e0f2165e1363af4662c296929d6cd7ace1a5dbfddb9add4e293d1c220" },
                { "hr", "d5cbd5629d705b284447956264eac72a2fcb0e03383dcb6bf2107322d37b5188a9fac8507772907f4e13ede5a5957d12e19e672d71e2e312789c87e814e9fae2" },
                { "hsb", "8ec517e4878b99169c478c5cc67784b9f616de1152e70c6cdfb24371459635cc38e2f34e0fac0581e842b3a5d60133bb5535784b5a90526d1ce5253e804403dd" },
                { "hu", "8bd98ee921589b9881e8fdbede5093dc11f7af0f4c5ec998acc6b1ead94df8e3e291f6b6d0592781cb8691feb5f28c246bf8fa75e2a2e762db17e9b15ed4dd94" },
                { "hy-AM", "8399d4251c636c7b099f5f632471a89743701d0b80cb639dbf9757ab117c91b969a8094f194b290c9b1a4621848a8289d0d27ddb5de949e800582d73dd23315f" },
                { "ia", "d87b2728d265b7100d25d97378111fd30b572279fa72502d11d592e87f4ddd911a079c6353d1d66a85632d5179a8b6aef57ab0faa00b7990ac95a2369220783c" },
                { "id", "ebcbbc891216b18c04a82ab27f97f1170ecd4fe0b24461c6f2afbcac7a79f222f9c21a76b70111d0963814901a9cf592649077a026e6cf01d20ec167c22a62cd" },
                { "is", "36db2bce5bec2a68596e49fd1643013428c5c66880a4ffc77fbc6309b8febb906ad22935a25ac13a24ec1d9ad4e75efd48874f0db2120ff5196a64239add3268" },
                { "it", "2a6b29fe9eaf3ca021e3377f17dd60adfef3e9876d86cec7861bc13d72a3b64cc7c169f3a801c7965bd12dec8b054d86e47b62c4578138da897224611da5e0c4" },
                { "ja", "a43844fbf10e27302abf7845a2a23ccc041089983849837463e641d66dd15e26e61caccbdac808eb5d6771de9300189acd830a61e616a61d26a04baec1460b7d" },
                { "ka", "53e367a574a7d93d4a40ef8973bbaeee49ba0b2a38e00964731df27f638fa7e592afe41b0adc02e7fc2c5771466a23fa46d703105f2aa31a7365735899ce001a" },
                { "kab", "c18a6b251011a15fb2b32d01174f28e21d610acf31f64480d0f23005dd1abd494b0437e9daaa88061de9db5aa1756de7d19da8d3c5e635db4c1ceb89b9c179c3" },
                { "kk", "b3bba368904d071045e4eb955b137343d1b73a43d067a5b693150dde5b28ca05dd72dbdbbeb4092383a6e169e3c2dec9bec7dec6f5d93940b546f37e9065f4dd" },
                { "km", "79458a4ffffcb4e9cb2e4164d51b42513244ba72d55d7764ebf6d04f15c88a692738ac51a84e36196246d6304537ff66004d2ad38c7142e4e1e8cff619d0a278" },
                { "kn", "21a6eafcfb62d95c7b03719a8b6afdd488dfc162dfe76296598bcaa2884ba0241ec03c650b42700abf424c3d32f78a5496a01d28eac8057b0e87e2f52e9fcc5f" },
                { "ko", "9690aca87a305f69b1655ff12ad2ef16716233868f2e54fe327d05d9f9807eb8b688ef427d12bfb580b44fb598c679906334a399e1de239ab18333f475c1733e" },
                { "lij", "a6a7e3813dd46f4c90b3e13592acf2ef2adf5a53c46ebbc1e542c881e10adeff7f740893363333b91f65a6a02d5c2f99243cc84cb931f32532251449a78a4593" },
                { "lt", "183d07567bba46919377c90835678bcbcee8d9ad09f25a53dc91a85bb2286c7928c8a35f401b35b55ed05c7e63c678e6f7d5654a0f23a5caa55950410eb78657" },
                { "lv", "1d53fb6bd3974216adc7cae3635c80983d81c31fb774876b9fe26c389925cbcad8810da82bf9a437b4808cd7c166326fd2ab308ed3343f7f97c76f87401b3059" },
                { "mk", "ad6ae06114c939aacbd95cc03803321c45135449f55b1865a466c61014e28aad2adfb8c5a2ddf38b61ca26217ba9f639c927433dc359031c7cf65cf57f8c4a4d" },
                { "mr", "fb6f3e6cd07effcdc9f3e40af1b024cb2fad31b4e5d96e6089f23a395927b231487f7f7bffa28c8675d57bbf88f43647d2bc23cbea3b34223c69316d304f2de6" },
                { "ms", "baa376f11d6d105e0d743846f57e2608d459be188e43498726a3766ec6630d596fdc8952f505a51227bb2a4e35e1f1502524ac4c625e7813947a309175db0a97" },
                { "my", "5b2645aceedc84499a9e09a3021fad6e67b9b28e229c7c5e27b8ebc6af53b5a63e8486394d6421bbae1e99d4245576c0ed0909800bf020aa3a548007c774ff69" },
                { "nb-NO", "3339f95d76f358cab7676aca32e6a74eb21290afd23448898d631a43cf6020c83cc13b3e0a40a16c7fb3834a2334fd4251d8a18749eff15a2460654049444253" },
                { "ne-NP", "9a3d258aed4dadf7088362d3b4fd83a7f9ad6c1d92e84d3eccd903b171bebed1472bc2d3eaa97cd9d54d5ae7496afb7e9d31849a45f8d1b28424df588464edcf" },
                { "nl", "6affb360dd912f2d3aae15da572b6f435340d1e0f47e92c8f6c265222481457cfcd95f847c9f8f9a80cf53cb16fd19197ac4ac13ca2c81876479dfd783332f0e" },
                { "nn-NO", "e02b60537d9768764b8f917a8219c1280e37c10cd68b77d6d008c538c0abbed2285ff4d86b94d2bbba13a8afd05f1931faa378f09a342de240ccea45946e9117" },
                { "oc", "33fda7120b520159ba0d0c4294745007df2d4853a22b602f9d8b7e538cf0bc4cb65715b63411ccf96289525bc841a1d51efa04123a6e1f4ab5fd89cf4b2d1cdf" },
                { "pa-IN", "8b2d212d19319d7220254f6d1bb13c7eb2d864a7300f122cc694c2e3bc75e56ef55881492cb457bb846a5f26b412330f45bb4da845745324eabb7c9a67da6a48" },
                { "pl", "5c25f23898fcee9f4579a84dc75d339f14f92a281b8e204ec5352f8e5bc0551eced1f672677b714529f87adeca1e2d510a2cfb4244363e21355534ec4651d671" },
                { "pt-BR", "540b4309d110f086ac67c80cbef54949a7be7bb3e0fe7086c0496e17201e9f74e8304674553cb6901b3fab2b6200fe04d38f9cad65d54169f7585c5f013175d8" },
                { "pt-PT", "5c8717e1a3d6b7fcc4e96f911873364bb2533f68227fafe185c9a41626f18ad4e7fbdf216164a758c40634c578acfb8e8610de6d92bfc406e07c9ed8a2e2a494" },
                { "rm", "0fc2cb98a75b4e8c222468a31f7597abb508997b325ab5f6b50b57c1d68a90efc27e60460d0a639d15db7f6b54b2a4dec75c25f3f3731f50b7309546adcef125" },
                { "ro", "0e30f32be8b85bfed0c07fe47ac3565836f937e64ba65f57d45142059a6921b60e59fe96b06b2d99d224d08f0cbe3c50af05d5ed3d9474202e18c3cb7b16370a" },
                { "ru", "6997b16839594dff7bb4822a4c4bc9c0d5a03379dbf89bf0c2ddf58f11dd2610425c9a8dfc7d79ec6a37c81385c8762348122f070b808cadeae0fba7f1f47163" },
                { "sco", "d60ab809f1fd529e43cf34d35f03b7217a70323363b3fb2dc9c685d4305d203d719f1bb9ee253640099c65584cec59c4b193ce1a9bb784956a578a9d5371ba5a" },
                { "si", "c9d36dda8b58d211fad74d3962d4e3f79e74b571c9340613c79d48238cea17292640b88666fe5cc5dcfcf772a0c2dee48a8fd6c46e3124fef60ca7cf0a5bf0d4" },
                { "sk", "4579e3c97652ae670b57476ad35e3fd7f56f7e0b555c150bcb47f541aed9c47e043138ac3e47592b5a5135659d9421ff9806a61352844ba6302b661c5214143a" },
                { "sl", "8aa402cc2b6edfd82b9af6e64c5f85ae3162c4f955feb747a32d86e94539ceacd02dc83818fb25cabb6faf79c31d43c294975a4e121e648b8bfbf2fcf5a7dc0a" },
                { "son", "e4f306153d107028f07a8e9bd92bccb6f43d063517a384b75653b195cfe2d9d0c9768c645912556e10e16a0d1a822c2a80b1f12af6e39b0a6242bfda3f5f434c" },
                { "sq", "8981ec0266a161b636cd19793ba69854ce0401182354ab7206e0258ded9d462ed61d041dfac0edd6a867eec790044eaf36c7189f9a6725d349bb54107720dd72" },
                { "sr", "be4a0d49f35e1dd044acfec5eb2928939834fb49f1af335ece5ec92c819dc9acea652d33f2e8baef71e3509bf05de11c03a2973a1a877747e830145e471f9579" },
                { "sv-SE", "9374c134aa669423c0c4cfe8d0c1bf94a5c9d285fa3016a366f0b23859ad95500bb64065589aa5f2a4bdc096a9d247e63aff78606d63d2c28bc54f7a7f430e9b" },
                { "szl", "02599d431636f3dafc32e44f209e9d5e3cb37ebcbdffbc1d1bf54941266065e7f93d448dcacb9cf4ccab9658dc9c1cfdd220307458e68016b4c68932abfd9092" },
                { "ta", "f4749ed7362ca011af80e6aa5775a23473d451a4d06cf49e998d78cb5bfff11a381f5fd9f23f220d586c2d36f1798960ee95221ca8437e3b55e304ab060b67e8" },
                { "te", "aaa5a8ed1dbafdde82da382a6618815c166efd173b5b0893b78d0b9deb83ad2940c30a26a900baa7e11ca2fa4389803f094d681c09c880d72609087bfe4a6ae1" },
                { "th", "555cc0e4d2901040d9e59aaf1458d163c41da48273f011bbe3c1c4c0ded8eed8da8ad4a5a566e10cd36cfc45f36b8d57abfd513c64dff5ecb6edc079dc728e0e" },
                { "tl", "5aeb621d7f12376ac2519c273b8fa7e632a2358f73d50aeb3b7c0d4c4fb39e35659eb443a9a143fd9d333878c788bfd035fef4979755ec87482cab4adb07ad4a" },
                { "tr", "7317c8fbc30a3846f8ae16638fa34787a34334bbdeee7f7263263f1e69bd7347c95eb9630f1b3a88444f9e594ad3d0bbe71187064490bc0fab960f7c2701e9aa" },
                { "trs", "c7aa885552194ffddb562f8b687670bee992d64bfe2384e25bb6f0228a1352807476d6b69d1a3504f11cdce820651c69bab1b882f5997230d69a9557383c1079" },
                { "uk", "af6a0e36c55a693db1cf287aecbc817bcb1cb17b9a5f1897c62f7ce9bdf9e61f1b2c0efe88b95d3dacc8673d7a4a0d95ed4bbfb99268d4d6b975cdf4e954ea44" },
                { "ur", "9efd49266be666221dba37482af5c8b3025b261e1f96d024ae88a1cd4e43356531bbdcc833c1df95157f55bcf0af3db51507a74141669d37c2ae3884a24affc5" },
                { "uz", "5dda5ba0f99807725e220b9e11a11179a8ffd9d1cf41863df28ec38b5917a1a0868cb3b8f8535ddb805a298945361370c156713c00673e8b8eb3be1c843f6f4e" },
                { "vi", "548b23627d7f32865c3e911c16b86602571def369d19558ce30e75a2122951f50159d826ca07be4329a11789518c1bc0f4d23e0c7d7ad2045d8eb3209ddad183" },
                { "xh", "1128d50652581ce196bfc4c80035455bc3d31f8d625f93cfaf960f901ad55a03ab92c4839f440ecf3ce9920063c90442e9d2a683524e3cb9e627ffd43a22155a" },
                { "zh-CN", "f8765ec5fe61a72ba0b92269c07568d69b0b568bf7aea7741a3354ec806aeaa22d22f86dec8de531acd8032610817ffe9142c089b8b0539e0b7214ea0bb1ae35" },
                { "zh-TW", "858f1435721336705ff72bcba022b2079988fc00337a4300f5157ec4a6de3ba9471b15ae39ffbc4cc9f5f97071105d67916e856bed1080c7075c48d8832e6136" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "883ecb98b1c3e89d12640244c8889ac27eaa4392bac6b643a318fb684985a964ca0f51ed0505ab78a795a1f6871943ce35e024baef305299062260c29f6dc76a" },
                { "af", "2fafb68d0039129288475514ec1ce267311a96b6474f9c69818cbd8f0dfeed45246c9b04091151c1f38ed3627a2c0bd7730d4491669fa910d3603b187b495a63" },
                { "an", "7834c6f7646a869a3135e6abe2784d438bb21394d4423840e01e3167b35c783c573821a58b5b51f33a3d7253d5f5924387dac00eadd3c66edbe5f45caddecde0" },
                { "ar", "7ff75f6d070fdc0dd17b2ce3977044af3414451e59125e3d1e3a006b2e8f56a2f2cdd3ecb8b7464b53199c59498909ef9bac4b078899093ad7532fd5e1fee58c" },
                { "ast", "5227d624ec7741b3ef9996be064ab2e491a8bf47867dcb8ddfdbe29327b4554501569b6b1b2c19019909871c198cbb195b21225bf7ec9f4de852fd2020a4c54b" },
                { "az", "e5b8a9963ebf1d2555598aad639a6c0d27f2050a63d58cc89f66fb5fa24dd372f4d86ce41c493af82e074d5b72a6bb40fc716cbc27b87ff02e580af03a5c63f6" },
                { "be", "7f579493f5e8d32dcb2b0e4cf2f2a07d5744d3e1539ba5bc56cfa27d6cd63aab0d7bfc144879bba1b68a0db885816326df39d603432ac1c54497e4dffa3aa1dc" },
                { "bg", "6ebe0cf12cab97b439c2eb2539c533f7fa6ae3693e3520bd8fdeae0dc228513be72befdfa36a2bbc1380becff9a5886c10e1fdc52ecd9fadd2d5c11ed42f11d6" },
                { "bn", "b262b5ee4cfcf9edcdc64e57e5cef0e9e72c9fff2146862e342e2223ad9852f60a65dfbd177dca5ad4e2a890e0cf041808f8cc44bafad3d73fdad36c7e65be2a" },
                { "br", "cf59c9360bc9e16d0003a1bca6acc4e4e83ad787640c0b943fc8379fced94ed8195262c2b82b4de584334ecb487059b2f747be1e0040a002cd8e7b40cc3dea58" },
                { "bs", "df7183df7df5ce599d1a15f3f4886e380f2d645d23b78e183f91fb92270a1c3b911bafd7b55884d77114befd98d78b89270c7353ba3c53f695ee930eafd9a4de" },
                { "ca", "433af239177340b86e86e1e71ede73ab88169d54efcb3cdf77985ef70dc0e07fe0d689d0de102e13ad1ba3cc77acb0b3fb4396265f7a3d155ae9bfa1bf29ed84" },
                { "cak", "11abed078ce538d32d975b5e89e902a5ff600bd37821043dd66ee3157c2be83e423af3ae2741697817e19b1415d322151312fcd074e2220280967f96fb5af22e" },
                { "cs", "4ed758e9c6bb8942c51612ef074442efba6a9099c8c200ad20cf0d39ae0cfb86c3112056ad398e494cf73a2cec60ecfd25b0341f6414cdd1715dfaf8ad1bb9b0" },
                { "cy", "6d8658c9d2a1c0a6a668f7fcf03bf5ae5895b2c82542d51336f7d2d2a15f004ad42235338f296e6e2ac77477c6b4c11a800fb95ccfbb37a8c8bbfda497a615c8" },
                { "da", "0b3f983191a90c8d0e5730ec73eea1885ea88d7881c7c797588c12bc4af05fd0f8dc5779c7321a58d3dfd1382d592b18804dbc0e2d7117713238d8dbcb069a7e" },
                { "de", "3d84d7cb8c4bd19e27b9d2e429ac656d266f765a8ec1aa47c2bafb0dab7d2765cb084c80f14bfeb57027273fb8b07d78052dd441fe64d90fba215ab721c92b02" },
                { "dsb", "7d29c4f675a84416c631cc2bf88f93d13aa37809ebfc44bbe54064cbb5229bc4e3e877db4bbf0733a124d9120993ea966e3e4e73c34bdd359fbf31d2ce1f7b47" },
                { "el", "c682aef83a57ce76744302591897d7b67cb0785e75ed0d383487f90634cb3a6f03969c8c20c244390bd36a1ec582020aaecd8f9ad5526002fa5a6ba9517db4da" },
                { "en-CA", "9c06bd6e25d64437a5dc1ad5951cf9b7c14d369348f9991e1f4e044e6401a28ccf35b23e15aa61d6d2fdf72f8e4c80b5bf786cd9d50bcc9e115b397f7d071787" },
                { "en-GB", "861eb57bcdc9d4e612b87ba3349da678c443a74af3868b1cc4379918cafa846c75b2551e2860fec10d30da2aa34e21d8dbbed45988dd2f620ae539e02f38da60" },
                { "en-US", "47b0f0157d8807fc98d5f107d821420a3c9ee722057814bad7486c075f51e09f1891d1531c2e4b5ae1159d55976ada37dbdd72dc20e9badaaf3290381e505196" },
                { "eo", "79ecf3629f750ee879df3500badbf54f5364d18be0afba20bb3e9ac82cd892046e7adfa93a57ceb6e74f469ce4fb8fa6a534aeb16265a4764ea89623702c7dff" },
                { "es-AR", "3f56568c1a8627ce177afd99d3f42dc022a4142ee21e0328918d1e2c6dd572d5100062a38a2c23cf0ea3292dd477da507c87c98ead5bba0710a97844a2f20c04" },
                { "es-CL", "c41d8129286e776576b3c793f6fe8ed9cf5ce0fad0e3045794b3788aa7b6960d8d9b09b8cf26616c403fc8757b2f4a8477f31ff387b0e7de5e4bd3f52a377fd1" },
                { "es-ES", "66ec4a27d4b994d09d2e16a5e66ac0a8b466650c3150f4f9ee9b9348c08a928e68ec0254f3c7dbb0b975817928e70b335ed57c59f4b0e7859606c24a5eaa4b02" },
                { "es-MX", "8a9c8aaa731e51c87c8459e25cebabe0d42898d35353776a56cfcb488900d01bd3ad65ea92289bad4c69faafff562d6ce001a3aa1c0e98a199850f3f167c9d87" },
                { "et", "f417ef8653533d91ca46a1310d5ddf0ff60e483082dc38d1d56583699a116882f197ded34d1cf806197cfd6835ada3693815ee5f69bbf8a6767534e202ed8e97" },
                { "eu", "89ad924d2d22cbf9be564aad11f0df54cda5cc4396906da9349a291a70052c271dc55dcc668c2f02fc9ebaed7832939a1a860468c14433252d496d278465e20c" },
                { "fa", "5739ca9764596a6a826bf0260659243ec8db4385c201eeee4efa2023183ee2dfb82448b11d7905a15e050bc856b5391da3ecf1bf19db60be9ec4a7eb7f7eee1f" },
                { "ff", "8c99828dd8acbe566e84680e0b1b35695f240fdf7446db7dc9407c64f8a0eaa068bef8d1b007ce46c6bfe7a75bb0366ac5926433a6ce94de730515c8b0222037" },
                { "fi", "396f99a53de0ca63f7c6729ab04af05bdea82a4eb41f5191767542c7d60838c841fedba00e5181363edf149f9a6352d15c1ce0dccc93e3f02395cc08a46fae44" },
                { "fr", "5d101cffeacefae58721a2f0293a07240d39d96cab37831d6aebe946a1f63973273e037ce51e75e9baa0ace04e9cae59cbc5962cc2fbccfbe81b16514febc871" },
                { "fy-NL", "7ac038f608f3c706dd51013e3d46137a212078b754f66e1f85e92df48208f4b2f800516025a31eb122e46a4c55df73437995321b28f73e2e534b5e7739475846" },
                { "ga-IE", "f803db012d9c9ed6e604bd57f568b7be731ffc7a8c8358b399721c4077f8cff36d5253de5b68ad101a32e9856edc75ff9df9b1dc8a7e8e269dd0daa643921160" },
                { "gd", "8b9c6f516a2ab0fa5cfc7e104cd575f36adcc71c5dc2bcae552a94c526da0078165adf3811c0a6d6eb97413fd4ad2ec052654b66b40558c98c752f21aa03c1f0" },
                { "gl", "5ada71d40d93b7436f3a66b0aa449e78782e1364c9e7945f1bd784f657b730deab14731ed6bad886b7123be548f50244900fca79fbb5932d5fb19d3f5093311d" },
                { "gn", "ea3d3da2f5e11a84463a27bb10827ddefd7691635a2ee2f3134b0111d657f4dbfe0d6ad508a9394d904de456cfa72a8d892ab607dee4b64e9e78e1ffe5fb35ed" },
                { "gu-IN", "b6e4da53bea8d9c9dc2df205740934a59dc4ae6c5244d663592acb46bde13b3285059fb0c681f0f9dad62d9fc4290c0fce8ea589c0e237618b58fdea90b9aa02" },
                { "he", "917d9ce40343ebf98268845afa33a6cf6e3d4d2977a4e12f955e59107e25ba3be0a9c701b518c29d70778a85895f787f48d0ec6abffee990af854ecf12199b58" },
                { "hi-IN", "67bd89d8acda61bbfbe03f92f4c17fcde49da711ecf4a52f514772d32c3881779cd058a8dfd3fc6fd1a67eae78483edf3f609aa55bbdff533289c13cfbbe1ba8" },
                { "hr", "b3c132eb1bca029c67932bebe2e4385ffe2a9ae764cbb386b60c0d2efe2da3fed77f0f1c444a923705345614ba06dad99b6a79d689f6161770a9433e4d07175e" },
                { "hsb", "bbb41c097dad2aeb07ad8e6e3313a2626c396249ff756ec2f7a0b050362eab74478b2ef9b8e9e3de82a88369a05bf341f01d028f18aded8c39209f1cb1ad3dcd" },
                { "hu", "25950985c5375cb9096ae604167779a2efb58088b7e1a6df9a987d6c05333f89b9bd229f1880b59f7588a6fba520c9aaef0c5d277a1c83aeb57b9661ec65a0f8" },
                { "hy-AM", "9fc9b17c368a21ec2f2850f09b7340076df659b7ff4b91d0829b1b39ac722b517c9054c9f17e550e09ddbeb5eb38ff2c20fa85ae1803e8ef42fffd527acb2259" },
                { "ia", "446a43700efc61f0f283654dc34bc86c7d056ef59dfdb0ebb73ef77b4fd8506fdee6d01d7a777c38d46abc031eb26e1d2dc77ead12272a5b8179da70ad193e06" },
                { "id", "95bdf196fae51df2c7eee68e3cdf2032e05facd388b18888286f6b4da11a120e89d345c9f18622d2d1cc366be89144489fde2132e05b98c90bcd044b5bd753c3" },
                { "is", "b3153b37a5cb423e84ad8e52ad88ca0a5ac897907442d0633190704b118d75eeb32d8b967756a051144df82e1c1a54816f3633ded1cd353dee66b619855b5750" },
                { "it", "7df6e736b8ef5134da42c7159d6d45191225a85b59c0aefc6f8e07d36e9e5cae9f4144de2faab12c6561551aa3e7ceb29c9108e464dc264dd433a70a28309534" },
                { "ja", "15d2cd04424ffc82b729a5c2e6ef0fa9d5f6054f8e750e6779a00ddb6f86ba32970466cc6394e320c3f185dc76993a068de4d196c7ad7d51934becd0aba3abe9" },
                { "ka", "163506e56a343665117a8e45bbc0c7e50a339ed7388364f9f8450f214c10124861daabe2989fa760c7a4e43306d062a3bf6adefa8ed20e08b7aff613a309cee8" },
                { "kab", "d6890d4866068454b1aba4c070e21475a5e27581bf030b1c8d3147a86748722ced1ee9c747fff1e7626b69cd91a0b4b1eaa51666c0177f8e95f015e19b7e1261" },
                { "kk", "cc1f7b03959f35acef951c6a2a7b9a9523f028db3e79cbc92187b02e9dbbfcfc15f06df19814010832ce9df589825575da0c47f500a885f7fd6ec52ae19d1765" },
                { "km", "d51e68975612bc16622965ffc032e89f892e5c32725b3f4855046a2b0127cc1c85928639c3b5a9f11d83099bd1e00c92bf0391b476a802fa2dc3f29ff8bbe6a3" },
                { "kn", "a39ed95b514a982ee051d62b36a93e1fb54aa1e9d2f0fce5d01b6efa729b6630442db60b9d672eb843ad279629e1f5080622bd258319e74e54309c7951c4c32c" },
                { "ko", "4eea2992fe9e62a652b3ff0fa4316164b1178fec7412078ee79f99fab410623283a3e9017be901692ab2d54e4d681be781324bb5c7f38cdadb3fe31c58cc3602" },
                { "lij", "832fd2c5633c4980e427b69695f7b5fc1650dac3f70b4b3d2d7fb16eb085f0edec653d030735760d7f08d62226e24811aa63bc3797c04fa77efe4398268d25d4" },
                { "lt", "f12a294aee0caa0d034eabe1be2889746f44bf6d5ea393f12b31c1192219c569bb40bc323b1ef423df9e596be523d04d994b9b40cc943d48f0d06a29fa3a7b4c" },
                { "lv", "611554e91a62352769b084430e9f6ad94d43c8e62bf0e594e271ffce638ae87c130cd4d5f00d7a8e3de16cf175cc8e75cfbceed443952646bb63eb1131132c0f" },
                { "mk", "bd071fade02548ced76be3dff0fd0cc6da33be290f452d28b5a810030b7652090895d14f972f9bac3547f8473a750cc1914163e88434cefd5d181084d1d3509f" },
                { "mr", "89880534139964c150adb0ca323223d82596e3161ca4db1527f00b2386a0b6971d1a99da4520d54ddefa2f33db8062b6c5b37d25541a2849a5a09767904e759f" },
                { "ms", "f98ed15eb0a0d484452663a3fccbdaad2c49c9e282684860cc0c8efbf865b4ba1d52225e7059c1a6b12666e724621ff176b7ab9852d0212c36447469e6b70fb0" },
                { "my", "d949c5d76c1bf9b27841484eff7d9e9462d1c886bdd6bbc7c6705d91a1627a9a21900b8c6367ee15bedf4f702804a4d57df1cea98dab7213d4cad064db64a6a4" },
                { "nb-NO", "decedae264b1f15b85e40f00073c35ec820b83b194944896576062c69c622de84368b0a00b80bc28c6640950ac28cec484aa97d2a89f07a008d142a1c7cb5d5b" },
                { "ne-NP", "dcef30e525afe8a4ff207676e9f8152890dbc41410fa313d8c861967c62520592d0cacf44ea755554c8597949e75a41c6fe6e1757c48626bfc805ae66f01ff3b" },
                { "nl", "485014e49aa27a73437a4ab31c4908dc8041a6a7d6034452d8ba05bfed3967d0f12916b490e841b78937ecb05a448661190839712f46f18f768124a90f922f2c" },
                { "nn-NO", "504410dea55bf92856cb2945347e87c25a490c29d674564cf682f5dd04136932fa8fa28a86e07572ca4c69bd7ca3da0e73bbdb8e9f89c80dfcc625a8b9e16b3a" },
                { "oc", "48e6efbffe4b5152c7ff445355aac35924838e986fbfaedfe8cb796c82bebaff1c5cc1957859138fda49a2d43b33664f1bfed95abff05028adb5de592b78e749" },
                { "pa-IN", "0c1c520881082e1bee1e71c32cd12bd96b3b9272452559706623495f5a4c722a1cab5e48855587ca2aa317ada5686389b31232c644fb1cec3d8d79e6c3b4f08b" },
                { "pl", "b00c815c2972025f27865c19341db7195c18718629bd2a52a6bbacff4138483cef64b750acd38abddbffbc57dd673b47662c81ce6225d1fbf8b7d38230b1f380" },
                { "pt-BR", "f758e69f0c5198a860d53be946dc597158265c70d9bbd58eb850878bb52a880764c64ffba1bc18b3a4df734cd8c9c3b9e71736074cdeba2bc2de993b1c634895" },
                { "pt-PT", "b788a257cef9de07e0cd89a0e68c2bd138e19a253cb5296091ab689d262758e4e1fc47626c42e66ec6787ae9ec05fb414159363d2d554f0eef11d696472ece06" },
                { "rm", "086eb85217bfd23330b289972ca140178fa1a62b142d0fe480e1adf5d99fd15e941e35c2b2b1178df196486942e9d94f1b0f7cd226b24c9da37c288d547ce7aa" },
                { "ro", "1337f113539d717a4a032fc2772cfce05611dd54d5fecb7799483c99d522130b6f7a3092f70a7596e5a52b5ad99aab10c3cd35c0644b08833b365afee23bd846" },
                { "ru", "1074d6ef86dd289ef325b60986f1f10e17c00b1f9c148d3048c35e3fa346dcdd6b5257dcde8bcf461ecf4e72ddeb80ccb420d1b881aa75ebc224c66795140f59" },
                { "sco", "e8f4b42920e8734917feda644c1219492e4b176dfec7a4e6150cd9330a8f1b904b24eb6dc6ff8680407581e63a90988a91cfa9b9be70068098c5aa95a7d2864a" },
                { "si", "ab556ae9939bdcbef743767f9de5ccd1e7950ab850b59e75999fab11e9b507ef636c1b499f30c8fcddcdeaa9002d0a6c6d3b637f3a9776e78a9343f12099545c" },
                { "sk", "c1a9a36e4a872390202c4b723460992b6d392a862713a9d42cd7ddde38d4232570610c9c45d6fa1b213aa1df171cdbee5ee3a842e1dc30d6a8e9a5dc362c33af" },
                { "sl", "d7d3b48f026f72ed7c11d2d6232f2a96776e11297f76a7268878f1e636db98280b04675b9b930905803e1d3b19e2ae018dee822860a6e6849b9b3fae3eee095e" },
                { "son", "b793dd1f062d302f2e1c807f6a1d9344338b5e48f7b61501afad66c225977ffb21fe158b15794c1fd4c462baf0e166fc6fc935b9c8763b4cd26179b91325d441" },
                { "sq", "43bdbd13df8da2e92e4585eaac791156bcea9afa1d7a69eae67a775009ade5bf5908a695be8d14cd72b95f348689ef7dbec55a0a9f249f73285f64ceb5ac55bd" },
                { "sr", "c46ac19a95d6b16e69ec96bc239df54dffa4f1f4a2d6768a357c880b2bdc7aa4fe273b276dcecce36d8d1aced3570e1e752538de0cf11bf2d2e054c03f66cb80" },
                { "sv-SE", "2ee5d11c322137b9417b7b58c33c0c0ac74004cd7a0d7c44204b8c01570b6a73f6ccd56597ad599039c53698116788d793596e69a2dcacbe222d97fe8ce34673" },
                { "szl", "f39562165cfcd278f46b738b4ca4ffff8d005bd2615d7bd43f1a58f18009323720cf9953f497833c3acfd9ad186dad92b671114012548a16b38bf94e54bd6fa4" },
                { "ta", "579eb2f81cc193e54b374f786f1d2d3154033ebb3d605d2c476e9bea2393228b688f3b8cec98f27b2a325f8536937884bdbb3bbd6852b9dd7c40b83aca41d177" },
                { "te", "15746ea9eff8503a4cbb2667da4c5c9f1a3b0f9bf98ed20406731a385324c21c2adb5e75b359bc83f75e5f69953a05123928d97c0ab1d99698a9845cd492cfc1" },
                { "th", "5029c06518cc11d528fadd83b980e820cf5ff129098497799be7cbcf78e0746d5610d4780bdca2ca62711e25f31759f7c5ef6b0a14fb633b2b5677c19dc8e1c7" },
                { "tl", "d6dd6028bf7b6ae55913ecb4fe724d2e6d812b687ce6a3fec9c55da7776313fed09b8d4bedb9fba3628ab83a81a5460fb00053b81e76d2b41c4eaa8509cddb9f" },
                { "tr", "4bd6e9e2bf4779cbb5710f0f1931ab6546d2085ae616389f9f9122ea00608ac579ac4d145966d26c68d2c187275697f20a0cee034def538908816dbd2b334ccb" },
                { "trs", "61cc6482c8511c80c0c4b473234696ab314b4fea73bd2ddcd8c75eb616b1f02aac54e5992efb57a2876be53928653fc4bce62d3327efb0290ed406caf7b4f0bc" },
                { "uk", "12d3356de17a6678ef45a5f3267a5392392159ea62c63d805efc3ba7b625790a360b06135410ff220ff8eac80df0b0790b983908be4a46eb25d1eb42bc73af4d" },
                { "ur", "af42f55f3c8321c53737cfb94532ab7384da5933d735a85bfdd5e319bebcfdd00f660a0083dafb1328c474ee2690f0100d5b22b30a6f24a7a96448af3b4652cc" },
                { "uz", "3a8e277535884860f8a4e57b8682e01c8a8afd33828b02a9bafa33cfe82017c63e5d49541e36d40b58cc005049a872aa0504abca7568d112fe1d6edd4a9f9caf" },
                { "vi", "ea67bb4534b65c32b16fd3f75a34d736ba938a7baa62f5d67a2aa655f3e52f03da03df954fb74c2ab4e591af7626ff2378779f8d8614ed92f6d4378af22dfcb5" },
                { "xh", "85896adc9839d4eceb9b11bbfc5f66d604496336463466daebccd61d75c60abd53c96a20c65757597772b954d5d28e8ff1b3158f3624b93528df33f215cd9df5" },
                { "zh-CN", "c5a1b6b7b9aa426052ccc6d471ddc255afefe8a81da5b9c909dd87021d83def291837ad32c05a64b52d61b1885608a63512958cc28d9ad7f135b47902c8d2b96" },
                { "zh-TW", "3ab1b53dae2f1a316b3cabe14079828f10b0da161564bf8411cbc60979d34fafaa233b507d0590f7c5029977d0ece0354c2a36f71d5fc4c72adc190978b2ce48" }
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
            const string knownVersion = "91.9.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
