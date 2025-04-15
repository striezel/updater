/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string knownVersion = "128.9.2";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.9.2esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "d390048c550e221a0fbe7f9f5dded75715a59e064701e136e2e6fb58018eca4e8186f5786d008cf11616e8ef2212f7e943e9556deca56fba0208bbf9e5d49274" },
                { "ar", "303f45d8b18ffb5c5e0b7221b9a5ee7496798513e54716d92f8aef45b6ae484d98f2bc5baab18e7f7472db1cf5aec9e58b0caa422cf7425648122cf3044c23d3" },
                { "ast", "8547e5bb493af8118fc252ed3a17259c7a255799be80075445771d5ecf0cecc82c2f40591b1667aba4d40e8c9de1230e8b2a8b87d32456473805826c7351cae2" },
                { "be", "6489a0a5637064ef32f7ac7d0dd6b5112ffc296f363f8d638db29f9aac571fd0bfc47cf4069d38300c200377f8210c8a4af0f752b4609cecbf129d74c7c4bca8" },
                { "bg", "87232b4270a13cf30d743bc1dddd4b98b31dd39c8e0025f8a8e589991f2d4ef861c790af08aa4459e0a1eae06c75b9b85deaab05dae181611a7ee22ef2f33acc" },
                { "br", "440b5c5a031e0c2cdcb393987eb28ec1ff551e1e3dfd4aa62812d186c49239767a80806b8e1c5ea7304280c4030beee967a4e53281ad568e3b9d1a128fbede68" },
                { "ca", "c47a7cc569094d27bbddc2e71f31d70a69f7ab9f3317f5aea54f28360573ae608cc7764e371b14c97afcbf4d985b426af3177d2d570658539d418024dbfa88c3" },
                { "cak", "24bbb82b5bc486a05201bdbdba3f9ca47e4207208bb656a5f3bf28db295727470021245904d59a6cbfe98fa79c9b935766ae32e99931925293155af18a7c167f" },
                { "cs", "51410f28de0f649b21bacb58ac3b808029cbb8b266cb50bdc1662dd330e738e230f01c226019081e6e0b4d09aa3b7222e65845deb443cdf3df38ff461db60078" },
                { "cy", "8782eccca90a9fc94ba9c414f0caa81530223257a250100d4b737be9e5e7126aad92209842299349eadce44d91bb1560659d28e4173612c6a726e270d94981f3" },
                { "da", "517c65cfc427773291791d5d48bac8855ca296b6bbbe62b12f88b7474306396a81fccfd730aa8249992a6edd409710fc693e1070daef8b716c7b2570418160bf" },
                { "de", "f6eee145ac8f9722fc948f91da5ccb9fbbce94906cf2d8909de92415f8e2454c37e66816932b5e00f265dacc2dc154780c6db4d8fe917ed4c7e024bb1a064a69" },
                { "dsb", "64a3124876944ce797a1fd63b8163ad0a1bd1019fb189ef3b4dd6ef5b44a9a5d1a7336b4802bcc99e4be96925cda782cfdbf5a6e8aec4473d1551ceee8d15c5c" },
                { "el", "93f0afca2b8425611991dc41badd13af973cbe5a758d121dcbc145b8cdd9a4bf7401e3e75ccd905f7e26d43f7d62aa17e0f6cb3dae9ac19887b4231942321f35" },
                { "en-CA", "a0f716a837a1e275cf9fff631f90c6917a1c9e66d1ffe519bc17f374af6695669e87ff73e65e37ecf4b55b04dd5f779c81223a8dfb8d7488ec8b3f0982a5e7bd" },
                { "en-GB", "1a1b0efc7d3cdb231d866ebd9bb7956e49dc5ae689246a76feca856f549110347781df53924327f3f56821e4e40fb8dea24b0ec96565b014459ae951f1d09ee6" },
                { "en-US", "9f9f98777e7b2a4a906287dc42ea21de8b3ebe2e65239a4f5ed70138c22bc217ba9b9cc0b4708334e36d1f13e6a9fd3d418ddf220fa3a2c4a6a8febab0a87a14" },
                { "es-AR", "409f41e4c97474e96c1946bb6b468cb928e0cd92292ba1806e2a92b288888a81b7464e4da5ee5c65830f551227b1faaef8191545d8d3765d78459bb8d392199c" },
                { "es-ES", "117907eb16b2e2147dea2a1002e54b46799ec8ff02abc8d5d480726d77eabc3a739bdfbdf633203d5ec09bf27fade681b9d929fe1a9f751edb910f40ed33ea2d" },
                { "es-MX", "fc0e49bdef3326a3df9f71ebe92045159c234678488e63a80a87f463da01e5a10d53cdef6856a510451b0cbb68aa45f026a16ea03d514a3cf4580a251bc38fc5" },
                { "et", "38dd177d9469471395bf1a451e4ecb2da98d42e9a0921e6cf04c7da4368412f31bc75f2ee484ad6bafac60afe85675f52539861bf4054821bdc1d2fa4c365601" },
                { "eu", "43f09e3580dbcb8765b8dbd6ce06abe78db28c9a27d189311a7db27d307ce5142d517ac44cbd88ed0caa4dcdef9093ee7bd626ba75ed6eb28427a1d6a18a1dc1" },
                { "fi", "be5fdc049bcff3e6833f638fb8ee84b032f060c25bed3a3e655a4ac56b2257b4929c8b265aa84a81c7f48bed93785c63f25bfd3d8db6511e4b3445c30116351d" },
                { "fr", "3db018d63309c23489f0556dc4e0c339355edc575628bc749653bc7216a9067725a2126c3453b516de62b20ddb5aac2fe7daa2d7adeab66a1cc9780f62e52952" },
                { "fy-NL", "9de8399e373267a5497012688b8f51a0792da5936bf22e43ad2f24259b129b8b15e75f978dc353c4d41be64b3b880e3d4dc2c58c2b2f6de71b7c03759665bc29" },
                { "ga-IE", "e0b28186e37ad7da43673386a2f3d3372877404ae0171915c047409e587c8315849b6df523ab3cc8046350e966e2e643b1111d9ac0be4e94669bd128bda24401" },
                { "gd", "4931b27d3a8ef27736ca96074a9af3dfc68d6755743b99b7adbbc246602dfffba8d3fe617331d8482ff79125ed4d3eec3b855b14884913e4f816ffce1355b20f" },
                { "gl", "27a3c27ccdd3a23ccce60eeedae0d1c404de3318cbade01a39c9b761a8c7b75b9fc14d7275d265311c7c89e964f639b68f15286c269bc2ef9293a7519a66e508" },
                { "he", "cbe95595f46ff3aa7d946284adc80d301bf8e1251325bb95fc180d7aebb100f33fd99e3547af85b1bec8bacb5c17f045fcfb42dceb4ce77a0c30f606a3fe2a0e" },
                { "hr", "c254978dc9d9bba7b25ff78dbb6e764add24e098253df65a212f4f12bbe8c5c15493a4ff1532d8c306a8f4444db4697997fabca29de7e8af9967bdb69ef841fe" },
                { "hsb", "9d8a1bb2405bb2e923f09608e89d250eb8a74acaa7b63093029407ec68a51fa791cad60e055eabd9ba5ecabbbe4b0a3838c846caa9be8c3423afe787cd6fa9cb" },
                { "hu", "31bbdcff97684f5600180ebadf20a820e64f019301d0b4e4471aaa37a8b22a7816ec22a0b91a54b88d131440f20b7e918b8c3a719dbb5a49323a06078c61d62c" },
                { "hy-AM", "b85c4944d08d40fda332c42372661c5219f7a46daef39657af976eac55d7b49a9a736134f232f9b7c22919f7986db81091d11bd3bf6e85442791b761c7bff7aa" },
                { "id", "59308eeeb33d4ee38daae2523cf531e823faa209a57278078efbb6a828f10e21ad58ce59c9de928a6ee226aa3d5ae94e9b82da17c2426124cbc1abb1555fcfac" },
                { "is", "f44dc974745ffb6b62413acd0afe9f4fdf393af6f25ca6e06826d403f6f72886506f88ca18eeb5755c4a2b364606fb3f14a9cc28ade62a610aabc58fbf3e0786" },
                { "it", "b43e1303c792fd9d41bb3df3a087dd734cfb41ef5c1baa43720139a9629ee3d193b7fe5e3bd942d4ae2653a8816a8534df99ed15cd813a933e4e37a862c798a8" },
                { "ja", "fd5f1cb49055cadd8d7f4d78e0e0b02e7eb94f4baafe46b097e5dc48a641d384b10a0841bd933135194c580fb32225b3d60d7b095f8e9f35919f90df9cbdec79" },
                { "ka", "26a827c0f29784cc62c5bebeb805227937202323ad4b0960fa7b654646fdc68d23c9a438ce0be04ce1593871bc7b0d66481817a166863ec5023f05635fabcfa5" },
                { "kab", "44dddacd26636cc85c8b279853b1ce318907eaa3ca4a4e1e07b6f76703051f535cd94a427775f3f602d5f9b37569d251fd42f3d64bb1d55ec2f1ad83bc475e0b" },
                { "kk", "dd97071cc0d2d34d99f452afb17632bb59b825f64663f561ea2725f7043db50368a1e5e942c14451bcf5ac56b92fc12cb866e6acb8f7253b74f18736ec2208db" },
                { "ko", "80f8b483088437fe5d44bf040ff85cdd468c8cbec78726af2732df7d33d5fafc139c0bba0079463dcfa8f0f88242e744d0a0c084ba495b3996ee560767a9d77d" },
                { "lt", "1a9ddaa3447a3d6cb8e24988c35d25114e70e1a277fcfdc6002a99c371c9944001f37d92ad8f60480e31460cff7ecf4b75489f370aad115685648a81fbd31fc9" },
                { "lv", "6547ba17e2955794cff794ff2a12f878ef35d3f00a85eef1047858b9c52947b6e103f49dc23a973e571549efdf8d85b4c098a718e9f43aa0faacbba3d356f610" },
                { "ms", "5a749f0f15fa55c5cfc1fde3a239858f6dcec4db46f66e6f10d031e5f243b5f288606aa07bf843fce349196e9e37d6503a79e5814a465d657cdc52ea5204cf32" },
                { "nb-NO", "ac52d1c75a6820a65a8704d1859e875647c2df3fdcbb021c049c6d3c4032fde1fa068a54f877f515230f53d820ff8914e6234acdff5bf385fe15312edf449734" },
                { "nl", "5093c16df08ac82a72be8ca0b81f67d597f4e771647402e3fc487c4e0abb29e676cc11bace439eff0304b5c443d10efd82afea28b105524732f778368bc0f61e" },
                { "nn-NO", "d9a3933ab8fc7e9465b0b04a8a1b2b52195e98af0e47a76b906ab0ddad3ab873cab457769a58aec41837696375d3828a27519ff3543fee7643299e5ff91e9800" },
                { "pa-IN", "4fbe56b2f7fa32ef35db07557b0f6335b4ea0daf2fd1bad36e2b1ee5c372d5feb2319be161b707d4ced9935c15fc23ff367771b99b036eaf5ca99e500235c06e" },
                { "pl", "1bec415932c8d9fbcfa566f6488ca0db1fcd3b7388bfaa78e48ad6a11d98dc5b31bafb1007e406ec7f18f62f5e8b632f8a5d2f25cff0abf3eac669bd9b93c348" },
                { "pt-BR", "4717984ec29dd1039f5c8a9450ba480eda3e354654dc786ad18e19fd123de869006eaaae424c800012b215212536cfb86abf5a5cf080eb3edf89deb0df323b27" },
                { "pt-PT", "03af910234be09122e87c99dce3b71f07c06bd42d4eb5edb650ecde457fb2b6e0a28d2892aebc6719449f1e90eb2659b112167f2aac0716f7dd44aefc14ccc59" },
                { "rm", "9fac77f78475721553f38369805b672ea7a12f15dfd8dfb0b87f068c1d685469fb2e3bbf9d062187587d03d89175ecb37c906b3d415cb56c756c5bb8c0e9b655" },
                { "ro", "ffc245aed88567497bff686cacfc28c7e4732cc61d9c2f26074836464497ab8f0595d33eb50a0f2924baee94128d18ba6b039d3d26f45f2b442be9fc775af684" },
                { "ru", "7aac85672578aaf62f2f29cead62c761af48f39ae05c6da8dad359734d96b037ef9d106a51f7c4042f8be381d21f09f36796c4e97403c2fbeee1cab609bb9e4d" },
                { "sk", "3fe88562c56a2620f591ebdf239c841bf2c3fcfb24d4e50e15298c8345b18c34f019acee96d38229baf878177421ce48ecd08e9c653c7e844c397494768e8f20" },
                { "sl", "750e93982dcf18928542a29947d630700c7ff440eca6c9c5c97f793fb8beb0c815ef1c69d7793fcd1152a03da45bf2c9f358937e980c0b65aa17a9fd02a6e85c" },
                { "sq", "210ddbfbb4c0ec9e1234b5ce38936d1dffa075595d253515a074b6af54ec58283467bf68708584a58c06a28e600dd837f0363ddc105dc8480c8de0a0ad8e8141" },
                { "sr", "7f208e92142498ca5960182660322e16072a9e1de51179b7708579ed19b798516f57513dd91290b15971b8e14ea636c24d55e9e45c4fc9e07ae0be4863aa7c7b" },
                { "sv-SE", "0dc50a1be7e0988f99cf9b4f9a86da08b2bc0ab4e0811b3c9a315169daeb0921982b083d7fe819ae860794ccf81623560df711c266ce7dc93e8529f0e0e8fe16" },
                { "th", "801994fb6f4507df41c7dba5f09fc9d54025774b7627471c58a672054fd89237dfbac2ec27a5bbd6ba931b212dc82820d3d0d3009aed205431e3c057be415957" },
                { "tr", "62075f93f42c3e743924be6f0090512fa08471a4867539416492d6b9d96bd97827038db973175d3a4924592d3baba7e159c80fcdbf7f22a4733f12bf0aa13489" },
                { "uk", "e7d98b968cc447dd3c934ed8dfaa494f4e99c5de72b98f9d60c9033adbce983fc96f2a3db327c4a81af3549db61143a149a9f6ff3386e7008e44d13f531653a7" },
                { "uz", "a9d12636fa4b74f0baa50e3368f5090d65d34ee6ea60813e9c23802b5bfc62805ebc0e88d0dad2c79dcd8efbb0b51f8d1a80e35e4eefff52f6807598239ed14d" },
                { "vi", "00678c8d6767cc039c42f477e1868e5047983eed780913ce2776d70d378dc59ebb8d227a6469778bb18b3e5f1dd8e8485a9e7522d8d028438b8734c00e9db074" },
                { "zh-CN", "7ecbbb70de23e21f089cdf280eca83ff385c5218ec29bd4af4138305c071b4952b2b7a79664b3b2e03d16114775c482c60f6b2034d93a17bbb978a4a9102c82f" },
                { "zh-TW", "adf9dd43f7be5d5d0964563dbc4f3ffb1a7e1050523bf1f1f054157919650b78cbba1376f87b7740a5d5724eb48c095e66b3ee88d7689998bde726f35b49c930" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.9.2esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "8d115c0836f64e2be1d4071b5d7ba340db29051b04b4466208e62e52298d9cacf65747b38963bf715261a5e8d2e4bacb65ac0c043cac3be775ffd46bc926c6d6" },
                { "ar", "3e3313a4a98ea2c9bc3162af84ba59ebf6bb3d2b28ea71cdbff47d38b3f55701dce04dff60c6bcdb85a39e4b04986a00b42fec0cdf77ad66f8256f6c4545bff2" },
                { "ast", "bd2156f9b0e32b29ac75edc8d141f21900840dafd240032ef7d8dce45fe8bc60def7a359c0ff233703063ddcde7bb3bd0d4b4f6ee0bc3e50f28d46d410edf3a9" },
                { "be", "0e62ca8efcd2db3f9e2402bf8b791ad8a77aeb9f87e5013947811da48da3f0b273c0785f25cc1211dc90c37090e084849714248976fe9972389059d3b74cc318" },
                { "bg", "db4112fae5444a692d2f998cae48108ec35dd548f9ee662c53db38a136c0595c60c2486f7dd918e76dabd3927821eefc5d66fe81bf8a4b37c129c4ddd0a5323c" },
                { "br", "ca688cbc417306b8a6d9bcc50fdabfc095d3a05fc578f29d5e77d85ef4c1f0a248db360d5dba5526546ffeb47715b9b509d9a0dd3be3aa7a51e7769c40731226" },
                { "ca", "6fa0930af0407779983fb65ef5f1f6b5ae79304898db8358c8e4ff13f9c5a0f958cc74623bcba76018f6b7d4d1ddecaa636ebeecc8377de688a1f2bc6c6e76de" },
                { "cak", "44a9def56174d163218ecfda4ba648abf1f32eb2d74582dab6a4dd46d7eeb0834d3bdc44003aa9fd57ff55decd384be371087623feb0b2520f5208598bffad70" },
                { "cs", "7202fa9721fdd24adc84a2dfc39056f9990353a452aba62bc4250dddae39bcaa4d6678b2a9f7937fcc87ef84457d1ad3c94329d4ba3e192c43f24fb7a81ba089" },
                { "cy", "a4fad61656a7f992967c5dc26a806f30d5d4da00dd82cfc20b4b1b5e9480704022035f813016e43f026b4288a6edc999a91e222fb7ae238971870ef3301122e9" },
                { "da", "06b450ee922d4da5d480d0a123ca5d6e5141c35264692bede399894e7aa9ae84699eed8aa04c7d069b42645a1f335dffa1dfb4d10523e65981fb6b7e93d2a600" },
                { "de", "d984667023ae3aa0d0ee5edfe4c15cd61531693476b490d676ea02ee23480b56229e690d329dc926d422e37ef903b46e897643577bddd821e986d95e63100e59" },
                { "dsb", "3d21f8bce4b1dd16a4e62f878467f02a88cea1ab8b8772492a754a106b56b7efc9a998488f93cf507010169e47a188270cc7f57d4b37dcb45bcdb77041d0f1db" },
                { "el", "3f333009af3c1786390f69ff451b2829efff9e99dc9251207e535b0fdc2768277269e47f8e5c112a5e1ba7d9e750d8763a883a123c00ac866d1a06a1e6a05abc" },
                { "en-CA", "112e860064265ea7c087b2b4cf0c61757fb9c5304aba79b26c164fd339bbcc1a00a698c3df41aea850e2003f802fdf67134d6ecc50ed5ed106ff634795f97cc4" },
                { "en-GB", "79b4e5db7038e696dd3679d692ec7d460a3d8b05c0373fa57c8bdbdb2a2dc1e57da6eeb5e74e991e804af40808365c81131e526ee9f0aface10ff0160b2ba03b" },
                { "en-US", "2b2c2a0199de97c86bbb24b3c44e463716034988b74fa23cdae133d6e99d0ce1856642a47f98f46d64885ba1ed74c741017f2102fc48f03b131704202f6b059a" },
                { "es-AR", "2d0521f60c0c573fbedf48958cce6c0cfe002569f4226f8b48a1cbc89d28bac6adf8d6d58c39944903c75a6edef04530dc2b5a20f173aa0d4dce3a546bdbbe7a" },
                { "es-ES", "21bbfc21068ea185ea8cf54a1557a2bc540a47bfab991520fd8e36329ccbe2fc534aec2ec668c5fe22630ce9073f19cc24931b92dfecc2f5e7564ccb3b2c859e" },
                { "es-MX", "26dd647d0929b271899baa4afa4816d9eff6143ed08046e0cb8d6b48e7d99bc6755ade5fcbc313bd61dde0ec4b7fb86ce9e14137c75e12d976364d753ef88fe4" },
                { "et", "2ac4e2fc6fb8bb47b44618f0c9d8233c7cc6b12b8237d4c28052666eabddb3035538a5e530b708c768e759f91b6432946dc19e5019db29f558103d18e48f8d1c" },
                { "eu", "7e7038f1036d073091642e67590769f9e73edf0627da1aa1cdccebe4fcddcf0b0ef8d0cb00c553f2c9108c038b1c643c44fcf07643b71557664b9ca5f3010ab3" },
                { "fi", "ae0fa103266daec6f921d6c86ca8eca6b5f54b5b82751c2af26f7aa5398b6c8e01cd836f0a17e5928c8e2a3831210d02367ce1c2c80c59e872d45b3a87c7152e" },
                { "fr", "b4efb75926ac24974618eae17d4cf16bf2843b1b5d05e1ac5fe4be2dcc56723bdf067d027c9d47cc067e162652bcfefac076ed8ddcdd16be81715a4cf153aa67" },
                { "fy-NL", "38f6fee44f5d35eda3743817a0b6f0fcf0add58c5bbfee9449239c99a51b31828c6768a124882c8a902cecd957dd3828a1c0a4e5a0348a39f72de1477355b095" },
                { "ga-IE", "92e9fd38d0d2234da396325f900a5a63e9d370b4eaec4a96dafeab85e077ad60067a8ed7b50b3dde71055cdb783702ffdf9c3a9d4b3ad97ed638347f448ffb3c" },
                { "gd", "f134f39ba9d8fe7645a27dedbb7fee1867b2981240b82a67ced099e890b9cebd2124e10edc09f1d2a582a40feea458ea8f79d5d054871bdbfe3b8de342ab57ab" },
                { "gl", "73667c4899b3b90bfb4ff5fa9a9cd0bc3931945e2e62c7fcf4fd925001c8f13e63dc6a2208ed9a044d095578eb1dacc8cff3ac6f4ec619a5e6db9213e515482c" },
                { "he", "4d7ff291152aaee7946067dbf2bae3e4ae59b4b73543022a76fef14a46ad34aa3ea0aaad1985733d5f96b5859e4aa76076cd5c84a4baec8d40a46d265219e994" },
                { "hr", "d64d35b2d67cbd40971293372b8fb82bffce56001ed319ad8a0dcd03d947980283108cad2d514874b33f0230a910fbf8cd998abb14d85db9e9a0124826403161" },
                { "hsb", "d9c391e12c05f09abac119196dda8e2e93d345b4a7d6d4dda2fdcc588d444a00264532a214ff7580831f30a2a778947023887fab69910470c4afd9543ffbfcd6" },
                { "hu", "97712fe55ef479607e77eac8549dd08784371bcfccee0dd206676ad15ecc6a52829baa0bac8de98616de8796166608ed994734f6cd621e18cf74818eb76b1fc8" },
                { "hy-AM", "d71430f4447ab907d17ac738b7f8db02594d0ab43021c28660d64e5da73e3c9c7833538e86306916b30adb8412de82ff86ff18a25cacce7f4bb848ff0f79eda2" },
                { "id", "636842698fe0d7071ffac1564d6953a49cd49f9aa6518031ba3879a802c3c9a509eea027adff81edf1edefa49767900a93d0ac8961e574b60c033b195e09eb56" },
                { "is", "645cd12d077f467ed77cb8e7440d97fc45dff32d64068db27f1bb0f0f0158848a2c5f0b582b12b9dcc40d93c86f995783a14677816491b90530bfc5bc1f414b3" },
                { "it", "59372ec9d823630a3d8d981176e1032ba36e865dc1b6a594d2fb8018af5eea9c6d1dcd7b9b8926cfa82bc13f1f6ceae99102d1192d0276cf21eb0d582b01ee33" },
                { "ja", "95e363490d9f295dd78d7b899e91af63920469129f80994cfab1b527f4388bb9a4eb3653108e88c815b2bedc656f62155bdfbcfc4f882912c211dc19e982535d" },
                { "ka", "c4641750eda14a2641d120acfd380c34503dec7d9c30e3585fc93231360dab5281b96e7e5eae21ceed276a1b6bd82a9d5ef355976ab98fd94c4e7a9fc61c2e3b" },
                { "kab", "7f474c8c4f21f62a1f4015e0e1ae91c60b61b9602ef9bfeb78c934f1b773dbccb065d41470ecc337ae7469c08acb7474b6a058a36f5776800df58c347a672bbc" },
                { "kk", "dcd59c641b0a5af46ff9d3a6f3873342b34fbf5d05d7ca844f50e2dbd34c0ffac98b3601d79acf4368f5e5fd038cbd0b92f8762080e95e42a4eaaaddc66d4877" },
                { "ko", "e6d34cec5b9556028787991bee7f36e6f075ef6113493a664455d64d47232a23f6f90409eac0ca5fd6c1d1e75a3a3a2cc32e0fb246a34324b252f8440f045087" },
                { "lt", "2765276ee550f023d9d7b1a68d53d21caeea7ad6c9e54521a759266a7c1ef7a08c8992c71ae8629b095158633742d4632fd30f0e69d2930eba35a9f45892a105" },
                { "lv", "3b3db761c862f582bb5e4e16781bd1cd57cb4e7619f8b9d4bc2acfb06f56108fc2fda493ee4071a9e5555e6c8fa995bcdf6ac20698d3ef4e947e4a025c87fdb4" },
                { "ms", "d5ac018814a1607ddb37c72b4d10a3d7d8d15cb9406e23e0f1baf5382b8e65cdb05e87bbc819a2b926dad680612132bb6472a3f5884d1d00fda4765f174c844b" },
                { "nb-NO", "3f71f43eaff13a0f77cff8e8594c3c82e4db4bab6c32319b4cdf85ca3afa6f3ca75652904673b1af7fffeb21d46d381173eaa8cfaeaa7cada57ef4d6bf7dc878" },
                { "nl", "938b58c90a9a1252c8ea133c1eee9c21ea3b0fc6a96999b3c087ca7993e8261bab311a0533481d869071f57294eed2a1d5364f49d2fe17c739d1f344cf41a9a3" },
                { "nn-NO", "03330499ebb3a4d8cadd1777c7eeb87b52d409a8ae0039a0e9795cf70c45da78ebd164264ea717ce85c1d785661aee9fb2a657e5e80f1020f83031d4baa73199" },
                { "pa-IN", "46e39de0bafa54bda397ba72c13fe46df38afc9620cc57d2bfe2f5a3d37f9d3f627225d3fac527cdca508cf05246c4671bc24c7cd8b8b27eefadbd7a8f103830" },
                { "pl", "16326edfa4d5ed99417814cd3407fa1c58b0f9ab7e0007a015bde0d15704636a65154a552f900775c5894c65c89d94df07994c0b5f2fac31193a35df16e59c0d" },
                { "pt-BR", "332733f6d4e8afb143b9f835da5ffde973aee166dde04b231926221250ee9ec21794c5ce8961060769cd99d5c176cdfd3283f24058d103a39a30f96876fbd400" },
                { "pt-PT", "a85d50daa8d2536bba26a85e559c1b9302c804a3d6a5a1abae9eababf7687d8ef6ad6965d7a33990c3504cfb8880fb16c7b1ee008853ea64aed2f2a74c8c5c54" },
                { "rm", "9eaa960884a874f4eeec409ec1729d76882daf9c038df56314211fb61d6107863f9abac2677e5206ab8c75c160f59fea5dd5e84e827fddc0fb7a677c089eae31" },
                { "ro", "33f15925a6d375e01891ff7f1968e5aa7ffe9978e839fea904a36c3bff9f8118d8f0e66122a98126a89bb7335ec4d12f9a15f703affabfdfd6be7509c2fbed4e" },
                { "ru", "6f0dd5ac61694485244a44f142dbcb42bc25685d0ce4a7ed3f1095005b01d3ff2b68edde93a1b71b908e82a7f21c88adfefa3b0535bf57add27e287a9bdecb83" },
                { "sk", "98eb1d7dae5a78ba3559bca3c7c088f0ca1aaab6311664a834680ceb6e5e2ad3a1f4e3d7c99f7bf9dbd93a9b03a4c2942f94d46f24348c648e1ece881c64e6cc" },
                { "sl", "3b902a6ec97825b24fbfe34fea4e5afd1a5ed74fd865c21d79d51c0a0920e95e78d7e82b1185987ee4750c437c36dfd5ad6a4bf0b7607f8d28ff7301277ed1ae" },
                { "sq", "5ba78b9181c4add8b9567052606e582457a561c03e95a3e06b1b81dcdfde328348083c294804bfdc7ed0b664d1be3b4000417132887016905eeb099aefff02c6" },
                { "sr", "87bbc2f964ecaa317fcf2a3f373dc77c2094a2ec7117bc038079e7a6a02f0f3886271e8606aaa2daf2bbe92ef82e29904df14e3fef33bf4331d165d922b884c2" },
                { "sv-SE", "e531107f246611d269b3dadef603aaa2a6e736b039f25f9a676f035b3f77cd929ccd912bfbe03c9e77251ead3530c79a21eec41a3391364f7ebf7d4c27ca55f5" },
                { "th", "adb3b695b3178710b71b96a92cd219ba891760f3eb1aacf2c6d9ce4fb03eaa85243c7b93db10ab83542eb2763cc47c4d604fd763c9008e74427409f09acd88af" },
                { "tr", "a7564e2833411e8f04f4428b849df1f3a2cdb3fa561b1acd362314e44dae1593a161cab2ea82a9b1b3ca24cabeebd0a41ac788aa2436aeea0ff0e2e0f13ed0c9" },
                { "uk", "9a47b02b28d0cc03d66b6c0a7d13bf738d03b019cb922d81685ab6de884d1cd63bbef12f280e4d0b4402b57f89718984db75e577b42b75ead28a35cbf98cac44" },
                { "uz", "31f7b1ea9aad3ebcce4eeffe9641963dde28b3c41ce637103a36d991c72f1d7bb9cdcc8280b49efb3d13811a91d1ab26a32196ab5aa1108ff2ea3e3799c0acad" },
                { "vi", "ef545b01217e9fcdc39ef6a57e120195763aece0e1eac0713e35c3c8736996131dc3b8267528fc617d816812ff855fe539bcdfe0d45894213da49e81d1e5f166" },
                { "zh-CN", "aac50aa70882a1e28ff5dca2a613e4567fa0f703da90b9dab25a77564870affb5707e36f7ac740fbb7d9c409a880a38e5a4585aa14ff539880d77b56d91d3599" },
                { "zh-TW", "8e0b594f9def6586438a70fe1dd7003e8cd5d79e7652b5837c0f0da261ea661a5b04945e16ca2c47ae9f6f50ab840f052fee9162b2d9c5fcc1b6fe574983dff8" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
