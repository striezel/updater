﻿/*
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
        private const string currentVersion = "140.0b6";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4a6727f1637927b94d59f003e67aade5dca512315b5cb429445a353d20507d33fde69431c2cdfc00d8a7bff0149b929abb0240a1d73c14ada868b9d2e6e97909" },
                { "af", "729bd6bfb721a3a411d9a9c91a9c14ef6b41023713376b46d588ea6e8d45d01c6ce40a87c2c1c7889e01a26a352846fd3330430a7200441754bcf33fec9c5a45" },
                { "an", "340ac03b7f4f7e0579f092cbe1b77bb9eba834d2d4ef7146463e10f14d1ff04dcb64ba01602c8656fb2ee0054fddf6b09574798e6dcdcae51cfed27ad2c78636" },
                { "ar", "f8628697f81e20cf3255a9ffa3c433060b0acae93552c7a515dc0af0c70d1ecb0c5f0578cef523e7391439e5ed156d93468e3280c568a07a283021ef40d8d19d" },
                { "ast", "aec458d4ffc7261c1e14978530dd4c114ec020dda07e58ea741bf1356ae730d17531dd2400ecfa3087257e4a2a703a1cfa26c127d7636c2a39c0f353f02d89db" },
                { "az", "9f564e2d370b52de70e382089cd2a8e0b9b2350bba55e991dc0ce7207d2b1b51405215b9be73439fd812dd59c50e5b9f6b7381fbdb08b874c02fc2803f957f59" },
                { "be", "639c033f2b601879602a60ed176c9563d731bd5e959687446f01cb1772f981358f2f63902322eadb90308f2490baf63c8be5b7846de79c0ee37497a44ebd73a0" },
                { "bg", "92ec38622e46f9af481ccb4c39e3cc604d51f8626f1db438e41f92997f55d524102ac5cb9bc6d4f5cc9c8d27e4bdc2cf2a335aca94354d6b5d4c60d79c8fa704" },
                { "bn", "2309049b4575744d5c784f6bcb7996098f70b536267e214305b59673320d63225f98ac3c04b7cfd919a0b83d679bc86d30081c0bb90e58eee7fb6c6f14e78423" },
                { "br", "5a4043d4a183827e99d4c8713fb8e19d9d7356ebc509ec6bc7dbe2c968d7c066537626292f971c1f6d0043a1c2267c75ba2a1b21199d3eed1229b23f87a17d4b" },
                { "bs", "22a0fff5650a827ef12eb52e9f5ad92e60f631762455ac54d7121017e1a62f3c84e58399ef1e3a80651e733a8c3edc06551616bed0e5335cecb25b975d0051ba" },
                { "ca", "a78e99ad9c448fb0188e7f305a3353e971c17679b20c454b54e744750b6119aa0ef9a5b89ec844e735fd27aa3534861a592a8bf66ee8080c04103a06d1613aa9" },
                { "cak", "6a94c6e2e2049684748fdfbed3663e7c4c6ede1408b396aee78137e9c4eb16bd231d3485f149b98eb7b054ddda9bab4cebfc2165271a9f06982378d70d06482d" },
                { "cs", "8423114885447c9a1562059b2a566c6f89c1391f73b19a8b97343ef7bff950dfd31457f395161519b0ac3e6e686b7b0cba15f9b079b57eb41796c14ddbb5cfb3" },
                { "cy", "9cc75ff1fc3af5ee8e8ecc3ad25dc72258ceffd65940b726a8de885ad8f01510ea071032f3df53b222f144493cd40d2d6d8511dfd9e3a80e3d7d0e7bb2594a36" },
                { "da", "ad28c8ae4d33af60a80d222068d352ad2cf407c4fcb18420a45788d205a4360b24f27e6f45746b5be8bd0867e353acd3fdcc1d722446f57adb1b2a9febb592c7" },
                { "de", "83b238777d57eaba11338f6cbdb8761c4abd250d06282dd919eaaa648b4cc83de418590277a7bbb1544aee392a8086298711c1b943f4f16abc89b23c98ea9219" },
                { "dsb", "0377de5bcb854cd01272b157d9dd5d94e5589deacd311b401c3ee74556c86e084314d3e2cb6e8778115b08a6def34a4fd039c944b4ccde74c84983b431cc5a98" },
                { "el", "0fb3a2f7694299cdf25443194abad9a2a7880aafe27e447ad00bb0939017a440d0d2f7e33357308b4a48d4e51b659bda17f5369b594009a011d3a5e58712bbf2" },
                { "en-CA", "52712f97a4fe9a979ffa61e2a98a085be16526cb94586303df350002b460755b29f7a28d5624d4644c00463e77b82eafe33a6dad60821cfd95ccab0555e53bf9" },
                { "en-GB", "5445b9a63d2f695a14b357f0c55ddcc76a2ed74dfa9f9eadc60bbb2163d92e4eb975dec5e601fc60be3580ec9ad94671a217d5a44a64e02dc17411b218e33ec5" },
                { "en-US", "78d2caca943907022fc42199dd06a065d6b70f3ecec880a1bbca28dd2d37729c0da345b0315ffc78807ada2e8a0d9a14606cdfa39531d93de4f17391dd954815" },
                { "eo", "3b5bdfe08205846b2096d7051c643aa241dd690e6091cb8dfd055a1869cdf8efa3cc1791cfb2382c000166ad0c7f691f0b6edcfde2b06ffda0ba8587573647e8" },
                { "es-AR", "767143bdc900bb7713646f0a4e13081de807412c40259ee4871317203ed07405a8b33963dd9bd0cde62fb6bacf00058e83ce7fd8382f3f25dbbb0d4a9ab692fe" },
                { "es-CL", "f21e994fc2168b9e9ba606f157b3443ea3d3eeaa3a6a92aa3c007b468a1de777a2b6193f244f02058e44443b35f7278a8d677e20090883e72b9fa7e48342e302" },
                { "es-ES", "eebb8276b2dd3d57e474e208bb910c552463f764211cb2449e56e1902f3b9886dfd6de54380fa2a2a91c04750cc274a5fde9bb8d297789ffe9888ffaa5e28344" },
                { "es-MX", "944f50a2b569ce82ed5aefa948fc423d42d5e1ccaa5d5b79c240e5705de878db6eb41a5939378dd9c8ce6975a86ebfb67a61bc2a701216735ccd0908a623e90c" },
                { "et", "b503f8b1ec557de7d62d6aaf5e66750d2f2a3e95058709d74eccc38b2aec098d71aa20ce2807220c38eaca22d296ece7a2acce381fea25b77db261f6bb1bf258" },
                { "eu", "e37688fdb63dbe7a4bec9d541bcde55faf95dd7b3b4ac67db08dba6e7e4867c4f8394be3b06236244e72b995ee8cd14464455737728408153d5262e61ab85bb6" },
                { "fa", "1200c7db8733f8cbad58efb9daa69e39a70b87a2aa77210bb8029cb22db6978ae13ecb3a1fe627606eb6324cc3d17ad85c764fcc133ed9d120852910dadfdca6" },
                { "ff", "27a2daa3560f4c956dddf4a5860ac33f60e35a3ded1cccbd148cc0feea1b478afc541d2c6faa83d8f47427aeeb4a2df9a88712e53abeac1543f871061014403b" },
                { "fi", "9540d09bc86d06e478a80d915ee8546b47b10a5f74a9515d5dc1ada7f6436b58170d31b30e1eb4f884b3ecf9797b1c5e0d3959cf7ffab7f66eb4128d50975c92" },
                { "fr", "0f8c223e14f957d41777de778fafe5f352b2dcd08bc2886db3bf050b2e3ac8fa2d915636906495bf77dba547f56e1dc4f53b35a3fe6d2d45b64666b946418759" },
                { "fur", "fb1f96198d7ecb64fc7d879a83a70fec49f1dc416f1b80290622a871f48d65452f70d711de9ce8f469ee50e02a81d19a1f06f99c68fba2fbc896da8fb59d0c67" },
                { "fy-NL", "2ef603f3e59beae8b7f68be59126646be7a13afff41ca4e5a43b3fcbf3d590d95250dded8c2fc004e9e27b1d96902b7df9331a44b4169c09f42348c1bd996ced" },
                { "ga-IE", "e55f947d34da5194607b217438e72969ff10d7bf4c96e679dbcab9ac9239abbb27a537dd5d31a1abcb6061caf220dc32d3b63c56bc670a57868a71c7d5b541df" },
                { "gd", "8582a4fd72d1ac28d3922d19832831f5171214552a4b405890c8cb872e97d9b2a7738d89acd7bb503914f1d27d6146cb93c4d37228b04479cd11416edca97134" },
                { "gl", "5b56133c604131c7bb3a91ae9065593a859c7b0b5012dc366b43996a659ff9a071e9f90e8aadb9681fe4418cdb44ad35d5fa4864b8f842fe512ca77f3062e409" },
                { "gn", "1f9b58c4c1edfbcf36b1d4684566f7d53ee5d6c3bafeec7415d21171c263c4e8afdb7841126c3e3440114c755943e18311f02185c16817b6cc28d468e9409d32" },
                { "gu-IN", "cec63a803e8445cf818ffffff45390c20a238f84bf52e38481c8da4ce4c2e036c31dd32723ab70d4eb133a4a0a69d130b8ec9fa088ddd93c014df24ff97fdbe0" },
                { "he", "9eb951d6e2a7ae04ef3ace55a724556d03d297c2ea67c7e0b3de869a8648cdbfdcc0309f97714fed3c3932828e6c7563240209752e6b8754ef31f88b3d464f5e" },
                { "hi-IN", "858e222b88f015e486fe7ed5fd4900ef11998bdd022f6ffc78e40e6abb2582e04b788bfa8ebeb2e4e4802d6bf20f9d28b9816cadfe7531ba056c82cf8621a270" },
                { "hr", "65303c3c7e0fd22a8aa9118a8f3cd277df6946b7079bd1a3341c9cb57f98092abb79672293294e2433a316762686b4b3011f12ebb76ce362dbf40cf35c7b91c0" },
                { "hsb", "406e076ee0b5ece3895a650d309459e804c152a7b02065b72e0395884c96651668056c82797e7579756fbea4eda367ada94ab94ea1089362bb6e50b3258fadd4" },
                { "hu", "7d6390cb5f700cc56eb8daba545262d2b40d51cbecee1f77a2af7b7fcb1f46b7590f09a5416877e4e4dba84b86f7c4cde7081771d334f87a07db713d6a315ffc" },
                { "hy-AM", "2131ff515b83a3d40101fb4693bd48a9cb74992e2987cb843eff4008b1435eccf6159913727a58847f04271432ccbef9201de96355105735d8702b48dd4fca86" },
                { "ia", "7be493991cbe4013c6fd5199d0916355db6659abd1dc5da4cdb16c4970874ace26081249d159db99729b00090bcf9584b3c668c04d253f19cc7cfef47dd567e2" },
                { "id", "8c9cd0fe3f83731df1ef343e9e891cb554a6b1fea3cf3d52dc8d1be0fdacad0ed336c11467739616fd664ed962fd33b30c2fe0c341ee1f8b25cb6c4d5e76dbf4" },
                { "is", "e08bf6cf376e9d81e249f472629b1d137c244cdc85ad377799c43cd20e0063b65f552263137c2be944f057bd83f13f6548a59265c4fecb554e3be1ef0ab4162f" },
                { "it", "353ea9dc7a1e2f1b26d7892eb06c4b83b3b3221431a47c62e8de07f67142178d12dea0c32e4759650085b772162d2346151cdd5b5fb372016fb83addbb47d679" },
                { "ja", "ed37bd767f45c9189ac1451eefeff7a03e5fd7b74794705bd6505c7a7e59ea3cf08a64f73239f2d1ae0115ead3e780b1712296d2a60f767460ee32d300041c89" },
                { "ka", "0a1a522b6285628837ada1b75b90de5bf3c7bc9209fe17706c479ab6b28708d3c9926c2c9fd39e2f97398791fb3f74942e2459cfb2270d8d0fd70ff2fdac4e5e" },
                { "kab", "7162fb0853ed2da86108fff8e7c24b38ecc2549f5df40edbd1e6376d1b387cc5deca9e3175f75c386804de98ec1703678eab420053125147d2cc681f5452e3c2" },
                { "kk", "8658377b072c5d21c13147ec03edc50308e3f4c54c91f8fe6e0790ede74ef3e6d5a6392c3f50e5c037b15aa23df9ac6057402689b90e1d6e867f4e1314c55c87" },
                { "km", "210d9511455d8abaaee52d52e0418b64ce514a6989af7e595e49a9132a82e6265a7d04c99d0397f6df7590782b69a0b28f11d63d0afb24db654625dde7b0b7ed" },
                { "kn", "d5f3b4ba9ab0eae8cfe19995cc569c9b6787a582a71b1722607b5d1e395750748b310c18e2d9d565f40628cb8619ba696b89b1ac18fd1cbfd60dd553a7abe921" },
                { "ko", "96947a701a6ee903a707ea312efc077c5acdab438ae3de26bf5282cbeb81b512e60e198311b3c6781cef009b5740db6c654eb62e8d496026d433d7a077eb9942" },
                { "lij", "00ff3fc27b98b759aea955e9f4b9a77ea7ec9b30d8781f01661608320a5f11539b11009480f586925d9d022648f5c318e6e2dcd9862e67cdd2030e7c7987fa38" },
                { "lt", "dc84feab3127fa93250a4c36321840946503d1355cdac1b00e68a522a07b6426a3bfb58d313478556a376c1f87cef03385f386ba47e1df8f9d7de3a3326a4493" },
                { "lv", "dad7e4cdf47dc3d9370ef667038f89458700bf7d36ca88e405867bb1d2139274ff1da29d02233bc98fb908663bc8896ae80244bc82867a373f2906b020f40ead" },
                { "mk", "3b35b81695473e14f21533094adb11cc2ae6daf6e077e92f959b279fc5f747af373b6cbc2994e977ab67f4f85fb8a2427719f9d4b27af9a7ef375657b82bc125" },
                { "mr", "d036dfa4eebdcf5506edbc80374de2065f542785fefe760f3b80018e6b707f392e33cc1075eb25e8c9ec3a73406f41198abf3da3a7c7aa1d8880147a76aa70ee" },
                { "ms", "eea890240d9e6272eeb277600ec1e98fd5f4444813043b5658637d5d20cbac096b7d6b373b3c27edf3b2ba65d40092a9ce20f07fe80160d45f451e07f5a9c851" },
                { "my", "ce2908da1719608aadf086901e5c35d9f3157ea40705ab679c8bd7dfa098416996fa822dbad5c039d5fd74f34ac4da79e2370445b218592ae011096f5e5f5c26" },
                { "nb-NO", "295a178fa2ad86e1dd8f6f69554d811ef73e113d32341c9fffb36869172b9f503b1a8fe77568c8cb99027eb00b91fa8125a030c09c5c83396acbce18b22c71ff" },
                { "ne-NP", "4ce5e09573e26a4d1999dbe6345cc679eae858a6d32bce1b7fffeb249e654b6de53f15583459f91cc4501cd140c441f6f7b3e9942a3489c42ff52fb4bad81a01" },
                { "nl", "c20f831e26ac69c8ce9b027b7a6021907bc6f3174275ecef6a4378e89132517701f2d62c4cec1f92fd1e65cb8961712b05ed5acadbdd2715d060761f86c39e81" },
                { "nn-NO", "fe677032bc0d9ca48f026407586d790207d813a2ffb49e77971d62bffbff6ac5675589fba5f1836c1e171ad69f029d5de9a4e5921f7c1bac219819c6e8bf01dc" },
                { "oc", "b1caa86954520822e2e26332f921bbed952c6b2dd71e3300f006229efdc9542b4856c09e935d4ec9db0a3c6aee4628e944759fe6472060146fa1668044cbc68f" },
                { "pa-IN", "a8db22a1d295c613f35b61de64a1b9e16cc4b6a67134e854a0560372b13287ab8d6b8178263d25c4e5c089379663646c026963c8cdb6fa09b1763163684b14a1" },
                { "pl", "e05242d41e1416786d110c35857b16dd91a05b4fcc404b7cda6530f9e1a8437c9e3c694a39455f2d1f4291ec2dd88ed4224073b8fbf47ef8f8cd0745ef88918a" },
                { "pt-BR", "8a2544f2ad4463ecc67a2524a44241bda60e2ec21424d21fc7c37231fb80a01f1f1ee37faa705ae73fa04127b3c5bd5aac961e4c947cb09fe12c933deaf150d3" },
                { "pt-PT", "6b3192c93af4b181b1d9c06de063f1244ac5b596593a70e82c83a31e02886c7f169839a60d7328223b995017f694d3a4a8630d11e3bf32a92fc810a085ca642c" },
                { "rm", "71c71d33e1c69271a350b74a1030ca2b6a981b9110f7539d938519c7e6e15160e0787fbee26fc80fd3eb8bee1740441e9f853c20c2906f99d4c90d746614b634" },
                { "ro", "926af024bec6574eb879cc177d7ecea0938867b39c49d8f7493f54c89a49b5613a7052cb312c40850e193d3e2eaa55ba9a832d334ae4acd423995a0b7db94460" },
                { "ru", "dc618022ba6d959e159226158c4857e4dfa3ff01f28390fad438078f1fa32ba8e5e5a7140f873c0ace1c7093ef596b137e560827807f51540ac59cf949a66760" },
                { "sat", "406986f9c834a9806274d7e8e43ece8b854ae87e68f2c0af823e8f35446d43faa1e4c006b3bdcce514cc07be9cf4b2c2ce8963807d0e4b73cd3d8d773c16d182" },
                { "sc", "94551a1ad049e330cc3f0048b6c20680e3830968fd2b2a250b53ba52357a5cebd0c504eb40b4f65e98dcc265df404e7ecae7297f271fc3f41a47744152d1805e" },
                { "sco", "99c7cad18039e73318afe36a3ab83515c3efa68dc1cf115e1241051cc5e61a56717599990ac8378c9fcce597d33e46d6ee3a0495e442b88493bcc872068cf045" },
                { "si", "e96199d707388dbf6f5f4b8eadab1a9c6da67b28231d2071104827a7434b0825a9f1e8104de8258b295fa395e5e157d059f0ebab97a2325a7227eb12e72bc1fc" },
                { "sk", "065306843c41f2217397d34febf7755f692dba61711713e3bab447f032358ada6b4f9ac9c15efdfe492b128a3eedb2b9e83defe572ad41c7797534ebfa10e89a" },
                { "skr", "a1d7168deb36254650cd271ea5f12cd2e0dbd1aca3f4c86660b025ce3c21e6c897a49924e639e930c7a31c1691a03c837f234f976c3d38a329c0c1eb41f161a5" },
                { "sl", "c7e69c18af280e921eb2641c4d90455be31f2efbc97e09f804e3468403574308a08cc653be02fd33e70bc7a13811947cfbd3d9d4283447d8137d3d75b8248c14" },
                { "son", "f039d7345af55f9404693cb012cb4beff3b0f3ddbb23ae9c861cfea84f73ae2e261d363595471ff90f388b7759380a456d6a62c0f8b6c915a15d9824a7108359" },
                { "sq", "4e0dbf5122508f91a8339864aa6ef0b3250e960aec2e9004a30b5aa286ce4298c01b3d830e625770912bd95f14269e3a10ad7b307de76289667d593971ef25d3" },
                { "sr", "e5fb51ad9394942d157cc80b9f856f67dd893805d7be28685ae10c56e0745e06abeeafe66d04611e0f9dea797b3c076198af16a79f54c7e756490d97a2e99a58" },
                { "sv-SE", "9c807232bf2088d2b6f696405902aeb8312935b0b8da200cbf68c5c4ead5723aa56de3ac7da705cfabf3ff7f91265c68e1eafbc2467bbf9988fc7b4381da6d13" },
                { "szl", "2da52bf625d2f7d48cb3dc2a48a31c3a71c46f27c32cb7bf945958f86b9e734494a62528d08bf930a215a4652fe5ecb47a8b8c43d0dde9dba6284d65fbf9492c" },
                { "ta", "f95645dedd4b3a7cfb8ced52f24feee030e8bebeb1a677cd41b16a19b621d673484223e47a64ba2bae218b44c325c27a6c87ee1f5e9ad45c6f13f848b4b62e38" },
                { "te", "42f45770237f02a8d9fb50679fc4a4fc642e94f6177890b7429b29a0a167c2a65838197b31d8575542c99c45d299be63c5108dab2440b762f3b16433cb352fc2" },
                { "tg", "837064e9b49261ecf2c99188d6e8cfa7bb30b116739b8af8ed82e169cdda41466daab77dbc0929bcc17b63293cd15ffb7908c9d99e266370861b64b7970c19b3" },
                { "th", "030eebc5f5178a35b86cbb61269ccef4877612f4b8bc980b31017912f7d8c6f920a57016f4ffbd4ef6f0ccea8521bcca434acaf6b931d22c9ab1ddf036a083a9" },
                { "tl", "878c0931092d7ba26cc123d6d0cc87c5bf2096bbb0a020160e897c7a12418e63df52a70bc3bec979b28b528dff039d22ebb19c771d947a6659f5c4c189543591" },
                { "tr", "63a852c9d7c5d35bebcf631f3d98480bc7679d202e394a8ca5182ce2321608cbc4adf81ab267bf250d48f90f45edefd5e637db179f04fbe3d3d1b1a38fe09750" },
                { "trs", "98d3548d2140531117503691bc599f17357d4ff94e831d4881d8a364521249d54f11a9ff7a7f1e61f45fc66ae844ae8e37bba1576570d0fa6518b2656f717fbd" },
                { "uk", "1cdd71f4ebf653da48e5ba818f4966c870ac2cbf5f112b72451abdf3bdb837067619775fbee3333f802c13417039382215d7bddac52852d57e39935e22373dc0" },
                { "ur", "6387b3d124780cf2e465386985cc52b8b4d463e2b98be85ebb409e9c4a2d4d9465c9ead5ba12e3cb44ee0e9c80bec9c0ec64a9f5c5f872389fba3a8142663399" },
                { "uz", "6a6000f52707336163f41fd58821b6e84c27fe57888bae49a717d0152508bc5c753d3f5d7b70c9946b59171eab1a8d66d4684c0bd883e5825bb20bddfc6f0c0e" },
                { "vi", "ba513a24b939d4256130b2c7f8025c4cda9175463223f2263971431256b6ea8d5eee0a42f0ecc2c8e4b4a12bb46abeb0bda6feeaf7371094a296534a28981e52" },
                { "xh", "34a180151d7a64d2d4ad8fdd33956e55f3de4276cbee9a85f87fbe838579c6640b334d2b3cb1df512787b852a15aae3002af596d9164f2b90e2d679cda00f38d" },
                { "zh-CN", "88439abf56f43fc8696593e109f76e17f6270f2f32b329a57f138afb866648cd00f18f89a853a797d711b5400c0d12590d29d1cc875e3a277533c2e166fd1c1f" },
                { "zh-TW", "fa100a0892302d95099bddb01d4c4ad9dbe7a12763ac3305b9c76a333fb92f85fe9c3aaaea531393f2301fcf1f7a2a54f35eca7df0fd0b86663d6001efc97ca2" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8d8beaf277961c7a26f7450d6dec2fe6f85e8c1f80dca63d56f2e48d506f64477eb138395d4fa256c5b3812943986ab1eee4cde813d65dfebb35bf0942afb2eb" },
                { "af", "cccf5127c75756da69e5bb42b749fec73ce725bb1091c7fc6eaf34f067fe4faebdcb411dddbad5a729de16b64b8fcdeffc73276c6a8e6b5be0e7b907d69445a8" },
                { "an", "905afbb24b65192b5e04c8afd448979e708f6f7303a63754e79bfacea1a9a2b5aca60877ebf752bcc6be641e0e72b3dfad75489c6beee01dc358bfb8c3927196" },
                { "ar", "e3ed5ca45e17e713bdc5a168f9bea4e1ad218398589489e950d5199d305afcb5886a7c8f17c09279c943bec1d0edfa68a4ebb720cab774e32006eceb40e8a927" },
                { "ast", "c835c15d55f9f873246bc4cf933c8339de8c32812cb8c503e60309c7e1fd9b12ead1c6a5d6fd46f54f15abf04f350c2233ebc9509ff8c4a10fa1ebafc1dc134e" },
                { "az", "5115b8dd4122ac5f22c3b252d502e1d1b877dc9f18e9669f9fd618e1e84b7b67f4ab3c7e65fff66bb258801a5d4c8970fffb081c7b4f6245f435436888cfe047" },
                { "be", "ffd94b8084d3e5a68cafde616d61d014700f03b26b5035e71c58de23237eeb39c9475cf591417e8b1a06c9981ed6c7de3eef45b71bcab12803c383ca80f3df9e" },
                { "bg", "e0f4c9e766fb8abbdc10e3e81026a1852eaa5ce8e116e78554b7e534ee621ef2471f1de4816319aa4c7f6f17eb1480c94ba51448f954e2281aefba0fc0a40cc3" },
                { "bn", "d120ea131d991cd9ac5b9452b2e1de2dd3a7593028a511edd2a857d32916c4bf30e846db80414293d73f6bbb5a26923f129209764e258f2b36b616874795234a" },
                { "br", "ead96138bea0b46ffe62568033bc62b433ea264e26c54adecbe906c109f70ffc200f601396e2b8776013ce1ac7ecd734fe1ff89fa32e30907f10a55b0e5961af" },
                { "bs", "643d27a0f2e65dee18995246f26a4f961fabc759f9598759fbe3b934a03322a28d3c09bce0496b90ba3e9c2ce2ad9ad0415a895177b4db41a1caf7f0e9eea9fe" },
                { "ca", "c3b80b025453bda7924065927d20aa411eb39b7ed4bf4138f2d10080321d2801a548d5446509af19ab4183b90dafd9ad64b6516908b07db858432a347ef54785" },
                { "cak", "959ff6376a62753ee52b60ced3191ccbd02cbaa27d432189c26517816b35febc5f69bf2241a02e78f229197ab7ab96f5e8041d1d98f3f1186904fc735ed04854" },
                { "cs", "003914a36be05f2e642ef9bb221bfb405cab17893b2c5e4e5d58b35ed2f3bd238dde07a468079ce2b5220b04928016a327b63eb4134016de582481ab8e329f32" },
                { "cy", "9cf5ab574966e2f52413da60ee812e265a3fc877b8ed4651f315304ec06cebd57fe9f6b8920924ab7c3aeb3b5c13d1e32c0f66c824d7a33d63feeb7bf1a24773" },
                { "da", "ffd5d3cf2d96684956a696c39d08450a82c40af1fc9dc8b0d98d104036e1983fcb37bc114ea24e48dc1fda835439932e0083ce6cff8cb28dd5d5c85c85aa24d4" },
                { "de", "e44b55b21059c75e701046dfa324fa49747505c4de6396a7802ec077291b9a849f6a0f99b692a116ead8f5dfcb9e44c0315ebc7a8ed3e8808993a9e0a1bd1095" },
                { "dsb", "b1a584fff9e2ceaee695f0e840fa58199b152b8e31e70ecf2e8958311f1501eb4b57f756ecb71d37307c0dcb4ba045c0d91e4ba0d2a5a952ef133421ba25040b" },
                { "el", "1066e4349f8476fb26704774c4c228924e0f7669b3d47808c20535f39b06c18ec70a076ee5b73c7b726119b11944648a864f8c6965cb1ca499a83c9d50fe1868" },
                { "en-CA", "cb93818c12f0a7becacac0fe7839cf4eb271ce1d31247f6686053f14b696669729386ffb9e3405d7caccd2dd0530d1fc29593e80f3728f2f1cce5903a1f22b91" },
                { "en-GB", "8c761429179b11f2491d77b85ae79f2924017c2880d97cf481078b90e9a98236fe58c3c77f80d23c611f9e615e8050e97a892d8b10ea40a85c9695993a622836" },
                { "en-US", "143c6d1fc8555402ea5131e671568639aeeb45e8e838d3178017cb2f506f6a02ca94ac5fac6bd43c34f743184b439851d932f1a093ad347abde413d11ee5e0e2" },
                { "eo", "bbc264dbdfaa0b9add75f175efdc880006a5f1dd24a6b78b90365d804db698ba6790bbba83cf9686c9314dd95394b50edf2b4c45be242368ace5363cd26c50ed" },
                { "es-AR", "a51de0a8a4930d2ff45c4a830e3ed0fb8c615a25ec677eb6c3e6db85f115453af053084537d11d0b842ba9672b3ee1e9d5725a4e7c7fab1d1acd81732142a292" },
                { "es-CL", "d48a555227fc99444854875925b8582e0618d3c97170dde44079d9ba899a6ee1b448265dfea369140dab615d230b2532fe62dc1ac42a661afbf8626ca209b13b" },
                { "es-ES", "3c4713a5be6847a632602c6bdb1004ed9dabd05d389619ee1a52f8b73da50c510f2a1ca641b731b5992cd5ab9eb1828e37596149711bcb61e856bfe314c3a600" },
                { "es-MX", "72b7fd3247ec9a30d99032eb794171033380667254ad0a83ec778990f3dce726499d27e0671db0e535e2d94f92bde01fc238443e4cc1911e65c158c0c9a87671" },
                { "et", "1b1701ec9ffd872d14a715954f42c059670327829261f7a2d93d05d9000f6982ac7b701439c45d1a4dd013529732503d095c8f9c6f195dcd149fb7149c8ac784" },
                { "eu", "9a8e8f86360bba2dd33cadb99abb968e2627e7242dfc6c43244fe2be93408725b02404768402cdb3bd3639d02f4233743103e38086144d51abc92acc0626ab47" },
                { "fa", "9c956f49c24fd7274255838219f42627953294db041cf0a124cc31f8b65adee2087cee769a0187142dac0a2b65d1dd43d7d3538d2cbc590b1f6ccddbcee8236e" },
                { "ff", "2a1397a83647186c6105f2b138d0ddffed82d93087f066dfe43a305e445546ee684dfae7b6e24c9ab9e7db3ef4b9fb0a3f5f227c651ddf140f867c38a3b0a57e" },
                { "fi", "b429b5f847a22fc0246c92c4b1e452e30660644c22743d44301ace478c465be803be6c3d1ef119516bedb572190649d33f74e176d24aa7cefb1157af61e2e88e" },
                { "fr", "591c7a727cfa877dce2ff04aa8a29e2bfbdb4ee8c9e9009cafecfc3c7004429a0d3584635b8b5e5805e8cecc1e0f869f51394653869c2ffa517f727fb06a0b1d" },
                { "fur", "df3164b7374c15e9941c33c3407b8506994c6fc8a39756646f8c286efefb96656ece7cbe5dda53f7540d5232cafb7da227929b4e53c1b59d2c16e5978f7694e7" },
                { "fy-NL", "1e41f71bf763c718edea7ecea4426eea535ca90817432721a5003b3dc0f4181836fbf3bc17c79f12c3c8f6b12be4409dc01f3c2946f3bee39be41be2068f2cf0" },
                { "ga-IE", "9e93acb5a219e959c080618ad32ee528add31d14ad533f7fce92eb96c6a9575893ebb4771cd81ff3a4b7dffbcc31430bb851609104df2b41480abb3fa140ba46" },
                { "gd", "3c91291919679b34a10216effe4f15bd4fe902d32b3c9cd542e16a65a762b0a49cd1abcf498fafb79ee880b67f837c8b5d66c208be6dbb98f3ccd6dfa17d9c3f" },
                { "gl", "3bbb31f5adbd4bba4c1a7de00dc602803693c8558cb5540423998b2be88839aefc2190109c18871305a0ab9812a3a6a38e6d08e56c53465f2d035e97f94ce353" },
                { "gn", "0e0d1f4020db17ff9eb1f20e7bdd7403b90ff2753c543f8024cfe67e9be91725ec1d3e738e74166cab9e4a67e349383b9a4e892452f488c468cf0bfbed3aea01" },
                { "gu-IN", "f3730e3e5dfaab6b6ce1d5e21a2f79fd08d6e4fa69aa57c2513cde99b670142709177071f02bdb7074f8b88c3003a890506327926f3df08f06c2b56d19449adb" },
                { "he", "d622e3b5c05aa91dced45d90e48542a60e2590a5e67ee71354a74dae38e60e3ef8de8effe72cb5b7596c4ce078ba5bcca17ad45e8ae9f0e3c764e38832b7155f" },
                { "hi-IN", "96bb87988f79e3eb30b3e6dd84e04309e31679459596b6436e336bc73159ea631ce636dbee5820931787eaae6f64607aa07319c441eb5c06d2c83ac72a6c5a3d" },
                { "hr", "f8be1ac5567fcbf53d1f3fa56d3dc0a07af9c1160950cf13514b61bc31caae2498e5afe56bf4f613f4359752f2e4f264e141d523a576f6dc91686a71a8e4a764" },
                { "hsb", "ee26d482bb393da85d0740908a18914db40f6b74059cb93822d877636da59ec417a9c83ccb7fc29c38af906034c5b1ebff0ffbef7498940404588450535bcf5a" },
                { "hu", "240bc03052e0b3f14ce3af6f4f5c44c76d01006fb7d377ef2c93491d221ae5aa1791b5c0ccb03ae316cf9ffac549485b6415d799909afb4dd6e1bd7cdb48ad73" },
                { "hy-AM", "489d9357c40cdaf86c024eada7999dae4829b8ed9b502df66ccf29aabbc6a77fed7ac83dcbc2041a69eed29fbe7e414967ca4e80d55611f18538ba0db46b8a41" },
                { "ia", "dd4df6404972a8fe4c922129c43496774436f2efc48d84ec19ac6d9eb92d3f4660946638075eb784bdac2260eb67342d443c9a7d748ccf738c6526e49d889269" },
                { "id", "dd6482fe2d979707b1af98911be73c995f1730b4d9f06b8cc949ec46623f2b084059bbce64694801824bd91072d19ff56bd52d7891d17444539c235cf1b20cc3" },
                { "is", "38656fc2fb3ea11fcc4d815149df7f1ec200b9cc8ab999ae39549201cd6b96c6b441250612594a7d236af7ee196cf4592bcd2f4106312f8a5cc4a3cc6b11d259" },
                { "it", "bfdb51c45ffd4b12da88f5760039c853513f7e1f6c9cd1cd0491deb13680f0ec71d0ddc52c66a52a5437c607bf5cac4fd53a533c9a0c6f3f07e7d10788d7995f" },
                { "ja", "773232de70e69697392d40a4756adef9eafac1cc1321c7b02642a504935dce0d1b8e989b65eb5fd8803efbc35f7d5173442fd01145ea5da9cc636f251646e0bb" },
                { "ka", "559a8a9d3a089d258083b7c7971377cee922e3551adceb8066928aa281b7ed737a9aae4ae0f23d7e1d99dc83c9f596a8d32949321b8d6cf20d162a6194f81391" },
                { "kab", "b0191643c018997cf80a063ac598ed35f81f8d8abeb0c07e83b7df18eecda27971bdc2ccd24d3dc5588131f5a5b3a03774cdba66150e49bafc11b05c031a100c" },
                { "kk", "00de5eeeae9b10698b6f704e7a520fce903eb4b8186f87d0dc06b60edeac6b2112a958b48b819a3426834771f91130fe8031b00d5408c1463122464675013557" },
                { "km", "413f0db1937b0da9e38e4b7ff3670b56fd35831f86628aaf7c5ba0f5c4465635f9ef41b5b60039b309181503544c24b5ee55780b53f2ee003077bce1309e00ae" },
                { "kn", "6dd1f507c61950648b7446ea196a3bf729e15bc42b47e41ae6d6e30f70f8a69e5566c059b0119e803a1a2a55e81d5d9b6c975b394c5f69ea30f95c69acf095ee" },
                { "ko", "1821e2572b4fbc3c96255071ee2ace7aab77477b30e176890e5d56bcc62545c1322dc9bbf684361b49250c5ee03b9eae52c4aff106337ed6f33ec95e51d49d3f" },
                { "lij", "2d4f759cd2bea1fdb9b2516376e5401115f31da2b713a2dd7b67c0a08897a6156dba426ccdb96bc498dac9887b17e4b70fc17bb9d5d3c3c03d0a405e1dde54d2" },
                { "lt", "f82030e49cdd8bc5bc729cf2211dc5ae61b46e41a0b520a7c4eec8cbeebbf348e5d470c29f3313e5302e4fe4c8eb3f3bfee0d550b32e2e6a943a5e996e966fac" },
                { "lv", "816ac0457de75abe4c2cea3d2373e2c494195e9478f4324fe60daa28a9e46387fe2640a4bc8af71e6f264bc72d17a6aa1e2227fbf62e06dac2f98893a1afe933" },
                { "mk", "d4e3ffe4b57a45f56cbca5a5beb8b546f35906b48c02e03ccd399929ce81751f7e807ad6e352c4d97356705fa8c322c7b17ff03e3024ddae614c959fd8cd6f9c" },
                { "mr", "47ce7fd6fdf5c312b8389de539596683f082d62de6cc62a3a8a841d328b5115c4e16deb15d3fb531e7433c85f3c865ea1968e59e49a559951c1921f6e05ce194" },
                { "ms", "c678b66eed2555380042dce048e0dcb95268b9df128d08e2fe308ca0b87dcd8079d8c33b8a1b03817f5ebc9780115b5736cbc60194a0f5144d9f7e8f54ab0cde" },
                { "my", "11bdd4f2d98f7ed53a174a190c0f517c58dfb88c1fc9fb440be60d625a0ff636487db695b5e39f73b8714cf9b0890b565c0e60a7ca622fd349dd69744b9b18f1" },
                { "nb-NO", "cad05b7777b91cf7e478f65044acf10abc8ac95e573f87900a78013d6434571fb831eb7bbea252d104cfecb96aab75bcb170f6e5e2d9f1e16440a3847ecfae4f" },
                { "ne-NP", "0e1ef9bb576af174e5f382724c265e0f92030ca4aecf0b7282db1b6222e697cae87d5513c70a83c20462638b7d2c1d3bfcff8da16e5be459b04a9db2bb5d0b72" },
                { "nl", "37a36a604aac73daafe1ef89072caabeb23743b4c4e2d1368ba26685215fac607bd61e199b1abb3bc012659336fd4d8c99a47f7d15cbb47b23e58fde2835b34d" },
                { "nn-NO", "1f6b1d3bf33071dd37932a994fd8fe75f0eac4f2e9f9be80cd17e57aa6927248d44b49bf50de27fe1bd9214dad9e35741514ba9d1d8e79fb570106d77777a06e" },
                { "oc", "ef9166925f93ed8caa6d8fc72b98537cad5ffe4a63d8d199cb335ea6373a7d929ebeacf56d45e1cac63dcd29093d79cad45eac1dc5fa44ab7ab6edaedbe67f3c" },
                { "pa-IN", "1abedee23705fa025154531e7882498cf2993938a810a97ca27f5d24a26332977252c85ab86c235f687253f4afd1c89262b5754eb99ec903677b70f42f01e4a5" },
                { "pl", "3565d8190d99dc8b1eb1c3670b139399573dad47ec05b8c44a221dbfaadf336a42691d022cfbdddc4f4636afe040556e21ddebec55b6942d75b2914a0c3eaa93" },
                { "pt-BR", "e5c9bf48f22076d7ea65640e2a74c841623dff3894ad8d199ea1116fc98a14c0ce89c532781bfd6dfd7423ed7fb989e045c658c1335b33a2159f382ddf2ac610" },
                { "pt-PT", "9bd8f81dabc0d02d2e25573e9cbfa0e3e48f981a7c0fd316f63ab062ce1f623c04db2ae67496942b308c3fd514e0e190c2b70625c7a674c1380237125b4215f1" },
                { "rm", "75000c5ee2c668956f230b67b1a25429df694d2a5648bf33e0826ab67f4e2dec3a93dc5abdb1f305468e6001a584a838b0ae82fdbd37cb8d1bc41b1fe6b28ae4" },
                { "ro", "6e9145203ae52f320cbc4470310a60d583af54f7cb3305f85fce8abfcd1d1737727946e823acc1b64966d1b3b0c78342f350b8e965dcc94d71d761a68c83f325" },
                { "ru", "6331eb175a6f4812f8ef44dfb2ab303c33bf671300a412ef4e0a18697ff7ae7021315d2c9ec2a759051a980976c87b7de661597072e707302bdf05a1cd422214" },
                { "sat", "2beb09c9996cb27c3d85a00818020cebc5d4542b22bcfa214e53b3f025d3569ff02d3ede2e6762bbf61981fc7371c9fb4f17ef2336dba7a9b8a144595d676d59" },
                { "sc", "0ee708248a96cdecb39216c207917e923cb6b50c148e0682ca492976bd9325239c6634decef422b0697fb137c0bf882a0141a54871665a63274eb59d280d5d57" },
                { "sco", "2890e0020a1a34895e006a782252e103ecd2bea51f4820105a8c17f23eb93e8533cae95e91adebd0fb83acc4451227d11ded29c6f596fa8565f645d97cbcffe6" },
                { "si", "eb5e672316e771272f6541e0742b2a880ec07e6eff09fe427ac9a39ea9864f4a82720b35aba2862c26c29548bf25630a0562d81e8777d39d2203d85dc82229ea" },
                { "sk", "7d877e1f17ef92e06e58f5ffb4520749f4e466de8cf7485f783907e22545c4a08152da8a883b78e9f5ebe6f84c00010d5fa872920c1a4cb56600f0349d498316" },
                { "skr", "6ceedc1f4b92c3329f00e1ee20188249648a8bc88ae9ab5a2195476186aea9de1342eb2cd70856ddfaf2fd3b6e2189125176f84687e1fe88b5d28aab72dea961" },
                { "sl", "3505ae4e628e559279b9ff25f1707632b0da750bf81a34d1f6102ec69e461ee70b42e3e1ac6c2c46d41551434dfc483c2fa794ba25a6300da5c17daadcfbba92" },
                { "son", "795725d9fe81bb1ffbe7dabc30a448e00673702170fe7c330f5eae407750b3c5bfa80187de602a7d201367a9f1697f5f8c78214fb4b6aab40d21aa4943777016" },
                { "sq", "1809ab6bfd19fc6702fad9facd06caf22ce30b23414c8fd41326d859cd5991012ea7270bda8e18fdc7542344d904bfcc2f19eb3224b2f6d19283d3c408d8a24f" },
                { "sr", "11ba0874ffb1cf309a7ab5ffbcae65c22920da9efcfc01136d624bc211b066ccc1c789854fbe8f174039389b2b0dddaff0ce7be0e1b69fe1ca922a52875784a4" },
                { "sv-SE", "d96b724d1bd7fc48b03d0ba8bd373f0b995919f32bac4b4feb3609b6833823cfdf155cf6531e1b46e9d0324c15b8a8cb524d4f813a786e24ccaeef78a60822e2" },
                { "szl", "184977f425f72ace02fa4627726f71d6ac3731b5df62b84db6e491a6bb8d4a25ccbe68040d9e624d2376a284b147ea04f1446b54046c6e2c88dad722b65b54aa" },
                { "ta", "1b632e6ef2957514c1cbee0fd6ede20ac223a37ff11d9ede646f5714da9c19a2efeb6f004896a0fa353e7c9f029638c0f2edd904884ac1d2ec0986f583fc1425" },
                { "te", "6e94263aa14fa9e0559b985680ab0e3c5b14f6f9df6523656b6d3d07789e1811c8b46c23fce2743b0fb572b49e4d63ee19b460c8dc69bc1fbb1f5c569756e07e" },
                { "tg", "d70cd84a6d1ef4786b7d99204d2c6b377c370ea49d98008ee4c6e13100d584ec199c65843021d97e16709373d0a89d317217ef14a401c193cd36818b368e5b6f" },
                { "th", "7a733a974dbdbe8702efe14d992d2444d6236ce920e78f53cca18018417a7ad9ffcb287beadf01c743f1a316bed0ccd6ac727b764978aca12e94b10bcb6681d5" },
                { "tl", "93e40c61752958e99f5217c3728b527346bd6868073a04d53ae431ee2456dc399213cecd80bd81305d261416dacc5fb10e767fc6c95aff58629fd2ae2909df7b" },
                { "tr", "a9a76530fc0ac1b389cd813bdad523c0b3aca660d2b8afc1062a7c67b4b28c233c2c5017958dd60192600235a1cd4115324f75b53213cf6773e09030b4868003" },
                { "trs", "5b656ceb0667eaa54aa619b0dfd2f7425d85d2a6e0dac3f95e5381f20e862231e923ebbc89c27d1857387b0e44dc69dd2857f27ee9d438690e470cf9e0f6aa0e" },
                { "uk", "cedb3776f183dcba92bb5e2f431ae6d21802778958099c621787dbcdfe0d26ae1bb79b44354170a5a3005a5bad452dfd3b009e524802c6eae8e64e717b1c5df4" },
                { "ur", "d29633ef687f4e78a5793f6cc2bc11809f279e0ebe0a241b9d0db44c290268a0758ef7473bad7e2386879a952ef24f5980f49ff112e9a3b7f35ab34d150f067f" },
                { "uz", "097887e8874ece6cfb7b1eadf9a1fee4af205d6d2d47ff7a546515768a4b860ae8097ae3bd6e8a5340af6a06d264f41c21ff1ca648047abe33d900aaf965cbd3" },
                { "vi", "c7203598c2868f8149a10c2a6ccea473d42d9d19afe1126ead26d76494be8e2345fd5ab907ff2fc7dcecdbd6e0cdebde988b65067ec3ab57aec3795e06325c46" },
                { "xh", "c6ae314238e788f06796358ee421920efde724cd293bbbacfb88127ba50d120d7fb9fc5ff7499d6977e2568bca5a85dca8c983b02697d5b2a3ecfad8ff7ecec3" },
                { "zh-CN", "9792bc7099743d252848d9ae401707e2e1dec0653ee4cddb85dd8c29f06273a69badbae487c85d2805f68ecc8cd49d66e1ac6b3a18cdc805c2327a7a4a840e1f" },
                { "zh-TW", "ebed3cabf1c3420b255e8de9520ce54a56673c68d0cf7790f9bf14c527c97a80f0c6dad91fb6c502545a6381ec286bdf545e397cb20e841474434da30ac8cc8f" }
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
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
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
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
            return [.. sums];
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
                    cs32 = [];
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
                    cs64 = [];
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
            return [];
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
