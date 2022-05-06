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
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.9.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "9d93e541e037719a19ad23e9a85b6665d615334bdac9d084852a4d2bade2b753e6b1cb1a6e16f50335e247fa07826626054e3910eb9b939fceb5a4d042398604" },
                { "ar", "9bfa9d41722721af974521c10573bf4de3d660575a8f14b98495169c5f1db97ab0b6ec2d21bbbc4730fe1bb382d8117c0f449b55506bd750cade7d84f41ff276" },
                { "ast", "647e4119b7fe89508126a100776b1378e98247a1d432b09a36031af9a8c48ac90aff7719ccc04be3d708f0f7a16217c5764a5b82a482cbfca45fc4c0e086e2ff" },
                { "be", "89c055389c677d641f36ad3a09138d463d5475861492a285ef026c2df61f85e526ed243a444e49351abccfc7ae9eb965977b62b3977593c31755501a53267e52" },
                { "bg", "aa9831fde50f9af270c11b8adb5b3bfead2a07910b3fc89ecf0fd91572c85237bcb359a46a0438c63376fd43287d38ddd55a6a937d4d4581672787f260141b20" },
                { "br", "c1def15b2237ea08c1227c5c373b1584e5940d11b0cd9a154eaa14e0007c94608aefc5c67d0a5e8a0f27a6340d7a5462c0a46fc6a3f8d930c81e43fa4c022f46" },
                { "ca", "c9ef9a315655470653b87e1d4f78c5ca94010ae7226f428e95b560ee043af2731ee85b4c67d0955a1daee3aa2893ad1997944c9c57b68ba2eacdc32f4336d0d8" },
                { "cak", "3ec5e8039bdd0b7df891b16ad3aa2d4b60b608a2b250789f8f574fa771c38228a9316a3f6a48f662989d81798caca741072e25e897ca5978d63fdf3536b73d01" },
                { "cs", "f20a0fd3bde69eb00837454fb000c6a3703e115c1d78635503f17a9247f622973ed8fa2932162d6fa9390830f9e203c7e1e3bee275ae19d226211447404a3457" },
                { "cy", "0981079f5b8b767192d9a9c794b4bf1020735b93c5eea248486d1e9819738a8d76123e6bfeed10bd5c63f978133b5a0e8d80035f98ae74b5ca054710971c51e5" },
                { "da", "fcbcad9ae36b665a94b3ebd797a92c596e673b584c45693a4ad7ae9159504be5bc789eb192a1e63d6d2d9869a47eb184fbc48b4fdbe19d05d5c04435f7a3e0c3" },
                { "de", "29aff877bc6c4820208327c745f0f93c1dc7c665e9f6eb42c9f5c6ea6f7980925025842e77c23c59469aafdd12269de95b201d111c4cb378d7b07eb081666200" },
                { "dsb", "f0a741d5793a5601fb9a19460e853984af91b321842743e7c6acc8d1339f4aca9e2b9c795f88934cf38579d307c50702450bf361a20c8adafb525cfaf414fc1b" },
                { "el", "73d2c31b0e6ce81d69594b748959c2d052a2e3953e63112c3b531aab7ddb36c81a6932454cf2c5c245e93d6e3409f95199f753da5d0df6d95eb3c9dfddd1735f" },
                { "en-CA", "325559009e5a720ea57d6ec41ead8923d4d54422008362fce9e16875a0ffd3d1e6d46e8e447b657eec6a2491e7acbed52b733cab74a6a826dc5d2640b7234ce9" },
                { "en-GB", "8a53a53c982f88cd32e3dade8e0f3198e721603c3df393e577a189d26fc65a5b73c448936e1673787069689f9236a703c21b864cd6474d6ca804f824b6f6296f" },
                { "en-US", "1c826dc91bec10fc542383920232fa246bb86eb7bf8fa5723911b169cf76d30e951ebf1b06a7832ff1f59ea02b8d2aac5c5321ec263ff1604e1731e9eaaad78d" },
                { "es-AR", "b4ab642af99e1a9e413265c75a363048b8bca0b45e3d816717e7f4fd4175bef5b7e02d97d8edf1028b2c8bd640f78d8c6b468febf99be8699b14a396f682ac00" },
                { "es-ES", "f281cbb24a37981401f491c7dfe540cbda4b4210350c9033f8572656338bbde398456fdd1273da71ffe6713248e3f883603cc69480c4f1293165f98932398c87" },
                { "et", "18d5dce51e6dca52185597724e07a9e02575b8582a3e497740387cfa59f3b1b9013a0046c134da56deb416a0e2236e8becacf092c25eb117e799a8e3ea901e3b" },
                { "eu", "a863dc182b2b3e4bb795047caabdba47dcc866d1b610a2fde386cac87030e1791d4096c6d57e1ffb94e8041e035b4f9b3bd73efadf11cb544bae23f13a54a380" },
                { "fi", "9c6fe83ababaf414e44c3a449b83749ac16d6d25d5487612f518a6776538b94cd16c598576a3dbaf8b037fb53d2fe1f05ca08deccff7a2bd377ae1d78a5ce351" },
                { "fr", "ddcdad7404a2f5a761dd47b29e1657e70209c328d03a710e67d5c7643f21aa2a510e5c3819290d38b48257b3c2b2279470c25e3b5227c57a8a491083c992fd82" },
                { "fy-NL", "eb5bd921f3f784db5c268bc9382d3013c48027d006a6367be3dcb2c5c3c47cefedc480c7d78848641513a13dee8b5a92a9e7c7be1fa0c9f702fcd4b9955cbb94" },
                { "ga-IE", "08fb8c5ff3a7f6e661c7e8f2a8428e5952e80c542f91ffef36cd8ebd01c91ae8e6ef0966dae2f735c61735d52e8d8b3f37f2203c57a00af067212333fa6e7ec1" },
                { "gd", "0264262d12c071800c4ac90ccbfccb10e8d5cae7d08be438e4e551dc59ffdd4edc0552cc4d79639e3d4d1af534b1e94be91aa4e9006bdd71d509f970f3f44a84" },
                { "gl", "6e3ae8c202e93cb5e4534e30a81231c6b8201e1d4f5f9e60cb3f604f4165e5d44aacd8fa3196acbef18853be3a3a926a919c703ad78d94e584ad363b19faa299" },
                { "he", "02b040ecb5b9e50093d45b38cdf9a4461a1f5916aaec116e3b8b5a90959f1a45178a62c8a700539edc5ae0c2bfbd2bd5259b0e2aefee3fad8ac12cf15767cd05" },
                { "hr", "603561a89828965cc53d395788f49a26d3b460e1327485faf5085766db8a07a1e0ce13fc2665efce029dbc1e97cebd320ab8fb9fe42f5cfecaec93ef306b5b2f" },
                { "hsb", "83f1000562e5067c9d06b7f9f916a1521f42eaa2c11f8c5b80572780999795e40e1278f33fb4f80e89ffa3ef805106bebe36f4a7686ca0a2df524751e711eded" },
                { "hu", "c59c9849621d0332d522408f8853eaee5c95f4f63d7ab32cde3110d1570ef6508486554a6741a8d7ef2a01f16c3945d3c9959f5d4fe8432c1041d6778ee4d9e1" },
                { "hy-AM", "a00e94da90c1a741d51145a3efc78c5f621e9393c80cb6cbf50127dec0b2e6374bee0dd6bb7c29ce00b6868f874317950071c657cbb9db13b8b2f92304db3c37" },
                { "id", "1264b84df6dc927741c28f1a9ca7d2325a15afc40bf74c4f529ab9c9dbf1bb35a3fe07fc0eba3ea15dce1fd57cc8d9f9ab5d221adda77707f4ac904afb173ca5" },
                { "is", "73d07c3582162ace87b7d721a8fa13e69be1df39b25bfaaff358b5e19b9627b095a254849cb09604f62395310754ed4fa4721177be828c3c2ab1e3d5ed74b122" },
                { "it", "8e136c28c722b75df7f6f8cc09cda1b930b6a395d9156f48db21f2a1f0edb7daa823040dfc02ee042fb33b8f6dcbe0c03f24f81d98a4565c21cd8ed799e79124" },
                { "ja", "9a5be1a71ab404dfc20bc39f7e69e1b3083c238082a230834d0316282fd42b352fd8f393ab79577e463655694156e13be7cce72fb577f449037740580b416f1c" },
                { "ka", "46b17773dc2cb65d28098e44a3e3b70a2360fbe73ba1f22a2a86161a63a4b4737feb73ff691c818f60e7756a504f015151d602fe46edc256a823ac04fb4664fc" },
                { "kab", "3d1cabb78a19ca04780093b240810585904cae331abbd985d91b052031286efbb2486006a563b654081a0062a90680f8ea906f4927e7bcf1958a7de936d76284" },
                { "kk", "4a73a9b5abaa2082cb34047979d22045c4a879df7920dd7638148e7b789d3e86298582844c408e72326a695489fb12e69479edd6c0d5d28ab0de9b95bed1685a" },
                { "ko", "a571038f57bf4a70ea95a3313f421b4818102888af918a433cb123d0cf3c2faeaf608f644d5229aa448955257cb2de9c59ad6526d69383ed41de8d5d6c8f1fc2" },
                { "lt", "f7151a0d551256195f0e6d4fbdcc97ec19cc0af2ed90c092dea0c020c58a05c9f511945f1b886ef3f38893c5903b39dfb08bf5835338159898753e4ba50f82ca" },
                { "lv", "dbfe248eb883237374b23d073441cdceeeee9ecf68e058c6b7877ef367816fafcb6f29cea8ec7541fd43323fa5f432cf3cda4dd616588bcf1229c2806fce2e89" },
                { "ms", "6fc4a76a80f9549c42a1657bc44d831d44f08f36c53d546dee1c3ec57cbf8ae222af9bb159f82f7cd7a7c918c5a5786380f33afb30cad5116bd801d963166159" },
                { "nb-NO", "cb5b8c095153602d0771165994843b3b57b4309e59f1f7f14894c3aaaff43275fb736d1d3f8f5bc902b2b3a83ed694b79b8ff38c323f1939ec53120557c9a4bc" },
                { "nl", "0a0e4dada2dbebbf5e997125f220aaaa41e3f6969ed709dd33e9941f378cfdfa9f5dff16b214180ad880ce912560f3b58302aa9b9144cf77fa5a47a42be93efd" },
                { "nn-NO", "04bc971bb9c14c30c4f1fa1410ecdb27918010615e0eda3d3c8fdcbd380f6f6d83fd8e749b154d4fa591ed022dbcfcd64a246d3246967702339e7dcdd3e013bf" },
                { "pa-IN", "99df5437ef5e5f158d9d7ab9d4385f594c7eee80b5019ec6a5321a0576f58c471da233ccaa055bc674af2260ee1dc3a4d4bfdfcaee30c519c42509048365d074" },
                { "pl", "40b45ffec372b4ac5071b3c1dcd189d31d299879374fd67cb71921d49af3b28260cd8bebdce14ee102350ad3dc35061418b8d3913f009310a744227bb4098942" },
                { "pt-BR", "e31964fdb83c6b693a035a2d75d6835e4616ce664ea00642f7f8666555324f17f72ae074f191575e5cb878bf62edb9a8a07b903ff59cec992bcfa2e8a260b3e3" },
                { "pt-PT", "5decd191eba4ce8a8373151ec15cc200e172ce91ddac7e004a0417ddc68bd2abf1e5b0174fa6db12e46425cb2c2e1efc63d1d48d64802daeef234e7945712353" },
                { "rm", "3505bc542890500235d35fa9272669e723240cd0b0707e78cbf8844b3b5558db72c22e6811911bfca8f4b491d05b9c62120e99b6ac8361f1b706f34fc3984b58" },
                { "ro", "94cb7b2c55d0988ac8736db5b21f6c88a3d09c8c43d5211c2be1dc80428368fb2e76702a795f24de759d973124acad36064e3594db145df0cf593eaec2872bcb" },
                { "ru", "978f1b7204c746487e14a0bf5cbf4d0eebd44fa07e6578feb022a39069d0d08db98d47fcdf600b8bdea39db604b64d96da6b8db4ce2a0d2250244e383a6424f8" },
                { "sk", "0ba69249c4a3e02c0010f6bd54524b01a1b858d9ac1fae8061f09a8cc36161ee694d51acc068834b6a60fa32412da8103388f1b550d48528020b34e936e1a210" },
                { "sl", "9945376574af0a38d8175ed33b4f1589516c87ebf6d810120fe63fb4a78351784552fa80ff0b16e20dfac88ed94cb51dcb4971a17f13ffe3ccbf96981be97a99" },
                { "sq", "5fc8d840e41e61ddf1db5080869557db5643ea5c98c76ed62a0969cd79a5c68eafe376ec2ce75959c29143c4a1efdfa3586a912ea8fd36973bcaa1d2b923efb2" },
                { "sr", "7c6e7a551a9aba0585b669fbebf2ae1693905d27151ff4680e0855ebaea57e1470d8ff7ad8cf883e5bf3d41b12e32284b40e51bbdc2c35a0ae5e9b824c33dad3" },
                { "sv-SE", "538352683eed2ac7746a2ffd333c1251761aeb785f921d01ceb059b353e83a6cf3ef48a03334eb59f5dad56096cf980ede3c473ea6cb3b4745164cb4621c6dca" },
                { "th", "2319a520f8dde7ce3ba46c7115fa83dc520ec36f0116c8e4dc1d6db492dcc2b120f03eba6e7d5fa1b243d8b5c8372fce05e62eee6c1d4589b1a3b70214ac05ac" },
                { "tr", "f5060e14047fa88811cea0dcbba4d576f04bfd8350b9a970d87c6930166425d14c89d8e9a8f44059f30522d438b50ef80db60f852c53f1652c6c8f48055b82f3" },
                { "uk", "778468349486aed1c1a383409d7ecbeee1b2dd427b92c3a6fe5cecf80f16d51818580f3a78ace1bfc948c27eed3968cfecac5eb8c9cccf08a310e0e78960d966" },
                { "uz", "5a7e49c7140172063c6ccc40418de4f2e0fdc276422424b87a180bdb604fb17309bf9b3ea9fb2e4ab5fd1648f727ef3f4216199ac1202aa7a91913dd4430ce1c" },
                { "vi", "3d418eead0404951576ab21d5e5a8638b6938e7a6d272c71107c0cae0ab6537179d8ea4765b6af543f1605b4084a3b5a8852b68e61ecc9ed8859c16b144e06f3" },
                { "zh-CN", "4a6a711b78ad391e0d1d38378e670243f71ce032f28db7a4dbf479d85ae814af640151e13f3356b840ce539d43578d033ed753e6058770b100ae853baed80653" },
                { "zh-TW", "86a9f6a656ac3b182d02162936f5c31facace9ad39b0df190b64c915db2c82b0e00b390074285587ee2c967304a013316fd45c9508c3215d23a05210a2938638" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.9.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "e907f164a5fbf416b9d21a603d47e1385755884ccef5dce3cb38f441ab95f3cfaa3f20b79e3aabefb77100bc70fefd9871a848161db4ffcc70bd44df52488bf0" },
                { "ar", "0e6d1a067a267c3b52f501c67b01e03bfa2106090eaaaf1a06435514a436972bc2805c4d2f0519e81bee5e3ea8b2ed7cfeeb21dbeca7366d9a059f15786285e6" },
                { "ast", "37e387ac0285981aae0bb76b47a5055a18adb92d456661d5440aaf20d1e554d137e6ea2d3dbf0c02c6c44eefaf158b9826c7bf52ed34c12f9a273ffcd8610929" },
                { "be", "245f423931ad49422965061059d0ffd54b860ad57cc1a8d54665dbfd3e7a28d076ddb103531be21a96527701d3fc00e23ae75c762f1e5664baa25f2e6dd462cf" },
                { "bg", "ff82ce2e1a14e9c24e9d83d05a91c20a7654dac4cffe201657e2256735184fa76a10b94aa733f74c0b7bcc47e659e602b9220a6412e4c4809e419fc6021db6e7" },
                { "br", "37f853fc8bb24e1cf8732e007c2e9344c54ef12770acad80093dca6b763dc67a7f13a83fe9d60c062f8dd45bbe2a452bd679356696b6a7fca3755504d4f10c62" },
                { "ca", "527497e9adf3135985afb5128981b31c9c210e0239fb39862e4de9af58bb1b156acd0b87993ad2ad615d20d2a8e06aed062da52c26693d616728af60b4da080f" },
                { "cak", "9b7cebff84f7167f48aa82b60b8486b86e628e2b189970b243689a633ab2c6c4c0db2537ec98b4b737cb3987bc859855cc20143723dab30f3e24d8b1ecd7a1bc" },
                { "cs", "74d47491de65ef55cc3037571428106549d73a1bc6ac2e38ee6ca17e3635942eb8be1d9b34a597a8fd4f9dcd6cf31dcd2d856c2944132664f8e29a7e0bb56f88" },
                { "cy", "6dc65dafd9b6d5cbd9842b223c1f2eba4f13750d48a153efd96572e93aea0bcfcaf867741eeeb0645571b35310cae46b5132619eff8097c2b607336f8b54360b" },
                { "da", "fa334ec5a990184b863a7d27e1763af709e90c3bf3e76ff0c520d83c2aa277079ef5a4f2b5b1f6cadfca8299cf5a41d0a91b882617d0d793efbf38c77e9da613" },
                { "de", "2d7a3fade90956b8b7a2b7bff41a2b72f9238f95069e996bf38cb5a1a36871266d13a57466d7748f4f98c42ba0ebad9658c64f18ff3f351dc498607934c5e031" },
                { "dsb", "35487232a172d5dfbcb6a0cf1790edb775fdf2ce555f01cb3d0ea0d5b9a6d6c73b33bdc28d186f18a2ae319e183795e07f25a28503723f5c6fc449ad76e9d54c" },
                { "el", "7d7fa4f02a7379f8184046399eef29ea2c9ebcd2d33b884ee2cc860ae8c6c20753d37aa56cdcf5a10000c7126bb2a02eab215333764f640bac0175744d3769bf" },
                { "en-CA", "1051c0f86fe1c112e1b3d7f1efb09521e3d7d79b537953e7d4ef937e849b4958412d7d755e1f7f2733024e81d2bc02c14962cffd4b19ca77bdb1f1f3917c96aa" },
                { "en-GB", "565b961ad1ca3aaf0ab30d5a40816fdf32a6241c448467b56eba8e9db217a213609f331f82b416f9f8f4c941272d64eed21c64eee41d21e988e66fd3aadb7221" },
                { "en-US", "939ddd9c2766488a9faffc273d17f3ae7157d0a0456b8449d13592ec488668f616ba128ff057c722ef0e783556589a1b8cdc36ea686026cddb710b8e1f37cd34" },
                { "es-AR", "e5221bd97b0cd29e1a62f95ef675d4c02bd88f380928b08cb4d1c71ff3e5620ccab3a605fe1847593f546fa94386ddec365cf5ae6210a6752e1f257e110b12b4" },
                { "es-ES", "cb6a0f56b32667734992ec820500c0742878b642ff3ab32e30db7842a726c3bc4faf8c7078dc6eed805bfc9c73459de812dbb9b847c0cf4ebd880d6ec1979cc3" },
                { "et", "31f349472e5c9d909758a3c2497cf034ea29fbaeb2afda76520a63f84e95ee90c345077b0482f8701c050e60878f0a1ed154fccddcc868d8ee860193cb931d07" },
                { "eu", "3a40d1123137b813e8682cfd63adb30e23dbc57d84d9a0bae302a5d7a6593906df8e82a830578d2adfa03abd984ce62f898faa07aec076c0a90101b41e028a1d" },
                { "fi", "301f245c137bcfbf41e1c6a7efae925030829e8e04d4177aadbffa4fdb7837cfb02329895771126299026bf6716276b94d5480b0a925521c7254ce16eadb1e99" },
                { "fr", "c08029d42f7e28892d17aecb88342990d52cc448ddf51ebe356c4a761c5be3af812c5ca757b8ca60181a9d1cb66090816630ea506bd4541911b314ec8c5fbc44" },
                { "fy-NL", "1ab41c44f05b8a871404bb13c65e88606b43acd5587471682a196476c8e8a6a280ede140c78a575345c37cb6cb66704c8ca920d0e24b116968d5fd689bebbb09" },
                { "ga-IE", "517e25c15f3ce1b584cd42bd2c7d10d50ae440d2105032c028b75aa56dafcbca2d1b2ed02b6e7ba417b46a58f2108346ea855a518d4f66851fe1159a9bda349d" },
                { "gd", "41094ec7793915c026da1cbdd257c944a83cd839053d178447ef7316f36721663527701179d961bcf487bdb18c68f73ce058614aa07acff5ac9d72674e442154" },
                { "gl", "6a8c5f29e8dd9d4d184a4ce9d881a3508d7637a1cf616fc452e8f9f35653b8fd3470731e7074e7f692612de4009622ca155114bf8d0f9faa997d7c8d61032229" },
                { "he", "23d97bc2196f9f8196cb89e83255328b91c9a45fcacdc419a353deb0bdde964190358977a702e413e6f1221009d0cca2b9eb46c2f7a5789eba270fc56526d94f" },
                { "hr", "cec6ffc3864fc3fd6ca76a2238d171a4206ff9e96fe24394b8691ae6eb43c9fcb1391b45659af75d0c8dfe614c6194f77d89d89bb5f552bfc7f03882485831bb" },
                { "hsb", "06c156f9e127d92c96d078941eca71541874e532b24e67c2cf7f6147586e9e81617c16055ed305ce836cd7f3636819cb3e2daa798f3b89ddba02a1ec7e4b00e6" },
                { "hu", "9c196a6714c31f9ca1f2bcecb684cb709e3222a2f652bc22f0c84987b4c3acec838d6f788bee803c71a7b11cb8f090e396f06a3ad599f0a5acd63b28723a0d54" },
                { "hy-AM", "1707fc514192d8fa834438ab85279176d2f7425f67b9fe9e844b6f912fb0ed0c3f3df903c1d9aa263b10ef7bde2a0c80bc04df82abe6463e4e93619683d3f419" },
                { "id", "739ca72070fa408e9d058213ac8a7eb59b032c6407f67d69a4fb1887c840da345662921fe596e460115c57408df56c2b23cae5de27c36d28500857313b9c7a47" },
                { "is", "a2f892a066bfed7e2f749b6b5d44a76d541f39f0a0da516a3ccc736dbc8e9d81068dcb0f74e79e6a85ab95b9acc8f17ca0e89b8c117c5db643bb5c039fdd3791" },
                { "it", "41fe0ff54ae75f4c2f00efa11051d49c4868d003501f6353adee812b8fcc3bdfef51996e097d33a367254f67fad4eccb0f2f1d0bb58c38da4fd3da1909bea79b" },
                { "ja", "a6f6ce2752cd083ea3532ded1b1a655413ac018c4f968100be9685b6a9c30f0e4ae2fcdb8a92a7eea07934cc029d4ca1db488e3c595865a114734a3620703870" },
                { "ka", "fce55d337f624ac7566c7f82c2c5cbe2c72f8081d8919ddcd32a97c15466436dc9a8643d4cc9d63c10805f80c9771cfdeff6ee28501369a9da0237eff0c7fa4b" },
                { "kab", "33c815d5142f0fbd476369b8c3e75b59e27b19b07244fcde6b2fdae5fdfe40992ff6b0d6c83806e6bd2adea8e758a70d2111bbd85a36087ff2fc99ed02e90eca" },
                { "kk", "f3cd137177879577929ef76f68c7949f7f1d663cb684bf7987b68ca44a48194d7763e338836cebaea647bfb1ffa746c6d05270cbadcd22c01e18c1d91335ad86" },
                { "ko", "78cc4095aa43279797115f29e99dd043ad7fc09de11345897e677cc8261a3449a2856cabba2b9f584df887940f27a799930c193fb98a0a1f8d4f1beea0352e10" },
                { "lt", "375ff1bf939b38ce655806143a2601b2a51ed8a4b521958e40ad44ba1aea0e04e9fd7257390e4336fd78422f89441c412cb71ab172d43673857b46d2c674b433" },
                { "lv", "22065b7d8d0d35c5b35673183d226f7b1af075bfcc57ad2f923d7df19d666cbd22917cb13d8bcc1709b44ec4385e930178fd0cf735c8783b1ef3f37ac0b1d91b" },
                { "ms", "982e95883ea83b10416c0773feab8406fbfae0a10cc1f4fcc11bdf340451320224dc6ec2b705a65ae7b01d7129e3f88f7a20fd6276729b5f610fbf86bb2e2efb" },
                { "nb-NO", "118730decef46c461cab30519c32ba5eba8c61db34606030ac65be9fed5330d1102a7715cef5c0737acd2264f3d3d1ec062b08b3b0af88ea7ee29a99bd30c928" },
                { "nl", "96f4f391eb9070854d3207551017bb8e9f1efe8aa6eb7d33af9ba585bf5f57c5a6703e4108060bc4d2078e756b6d0a7bfe260b5909b6f3dcb38fe7a47a2d9f5a" },
                { "nn-NO", "d84116127d7c40140962b348069f8cf3c6a4645f973b7fe520b5512318badc26a71b1ca053bc885e723b5280c7320793fa526e6468f5850f62054b70c92a1003" },
                { "pa-IN", "361803259dbc30e4fd4fc553b7fbd1fefe7967b162a666e9d1198103cb36713a8ee8f1d18b358c12a9a11a9add804bb0e341c875cd2cae65abf6b3f34522a03e" },
                { "pl", "525e9bf34fde2b768f8f06c9f87d88de7512bd6c8724dcff2674b1386e7034b20eb400a4a394f7d69bc89c835e7db84abf9e3e0d3d0942be94f7efeb760cf50c" },
                { "pt-BR", "f8c2ca94bb485393dc4ad0d07faadc8a4a5807e3c9316cfb7c4507ab26df8f2262f7ab366b79b2d439dc13677ddce37311e2ba7b8d437f10cefe6756716c3d7f" },
                { "pt-PT", "b53af8130065885aebe6e691099962284eca783965bf2c204321e225a2ce2c00f0b8cad3926c3be11edcd8d13832e2b3be05b556f253c27353cf41c2991df507" },
                { "rm", "75bd08a50390d8b8ea6bb8fd03eddbe8c28d429a85a784173647454cf6b333c686755f25754c9487f5fe28cf9c7f79e04972425d1f6e493ddaa0daf700980430" },
                { "ro", "146326c2fd2a74dba90ce9cf644c5b7e306acda670c1ed8984066988fc5fd869daa686e317d09dca24f321cf9c38baeb668cd66120351e8a6beb1afbb469623a" },
                { "ru", "c7642792cc16daa8f25f9512d1372fd875366735d6b6638298a89fcda37f73feee8163d04b16f25146c2b9674ed46ab0fd4956aead64e56241da003c2d43a7bf" },
                { "sk", "21fa9008ac17484b1be9fecd768cdb6d1e3f2bc94170d4aaaa223d534b5545046f0fd803d64efe9410b41a8e30fcdc2224014e7947afaf6086aa64d10db50cb4" },
                { "sl", "1aa467204c51201270fc8e047d47cd2072744e371f63bea1c1d375d14bea35d5338b67e123995722ba09e660a40565ca3481fa499e94b72e8ae17d6a19f843c8" },
                { "sq", "93a12f754590b8df359460353796e1d097c1ad041995b5ca6bdc84ad3b9786a5d192071eb9d53b5847bee5ffa68ba854e2c20a70abdcc15d9a028b32b11a1474" },
                { "sr", "d7e272e084ebbc3f7686c6d37a2aae213f3008c8ddcbbf1572ed61a9a20a5a6bd62772557f12df28a48d3136e6960d8d5328450f518f702bef6c150811031e65" },
                { "sv-SE", "a368ec343e0cd0861bf4dfc6d7e21aff1f1e60bb865fcf56bbd53061f40fb7b2cea5e454f4dca1ece6c73d3698c647c35b8c2c233c30eb88fda62b8c28fd756d" },
                { "th", "1867ae2c9413a60ec1333f7e1d99e77679e93927f5096dc467775ebec14ac28d3fb0b05fc0716faf9fea9a978482ec8ee2b657519e51122be1c0299dc60490c2" },
                { "tr", "70a83823fb4fdfa014460304455d2d8560d01b2c0c2d71839927dd17f7bf566f49334cacf6c60ed6dedcae7929375345461adac57eaeccfc3bc7bd3eb402facb" },
                { "uk", "15eec2b38475e93be059a78fc5df3cf0fc27afe94194eef8ba947b8173a82ae36265b5e1be5760977b434ba9830a473c4eb38f15a1119bbfc76ed3806dc30dd9" },
                { "uz", "ba18b360da1c512ab6715e12d6a69f42d76de6777a9d446962f52124f6657b7664410ac4335d126bd6747e51a105b2dae557fab804eff2acfc01aaecbd5281d6" },
                { "vi", "4ad53fe7343b541a80f960cfcedbd1b741faa7a94d7f1561f10a3057fee69df22b710391504a83ebada7e4226c744eb5d0b078f69cc2ddfe824fa39c727fac9f" },
                { "zh-CN", "bb649415fd0aa4446924e62abc3c92bf048686b3f974eb2b95713f6844af849373f300e3782956db84aedb007dbe052b5dce6635da82ae7235381b51d35de6c5" },
                { "zh-TW", "3c128bc46db20dbc664b0ef3baae67bdf3421018bb7adca5595e5a1dce2cba42718d4a124be0aebf9c889fbee01bd8bde3d5552ef96a7a5f53929d67802242e5" }
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
            const string version = "91.9.0";
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
