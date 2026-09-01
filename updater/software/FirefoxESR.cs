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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "140.15.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.15.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "35e0fe9ed4ef55c6144dd1686405d1166c04b04a14979bd8caadfe4fcc2a6309b9b3c96ca428900a3b93c6073dca8afcef6acd1c7211f06871bd37f1a94b89a8" },
                { "af", "59eb8aa4776418fb08c32685575b3257312dde9026f077c34e132ecda22e71500db00112e3639babd05ccb8e01eb9e6ae1137251630057c51c469792cbf20ad7" },
                { "an", "7a5b3388edeb862b8b879587c74804842224735f9381764b85dcf696c7400b8df2c417146688f445d2ab1089eb39837cfa55bc09c928ed7c706254ea8169e175" },
                { "ar", "0a15cec87d8525267acf26d7c1e8b534777fae04a61012d5b4050d4388c2dea465a7c972d607ecc92e816c891421721c131453e7abfcd89e0d92db5648d13263" },
                { "ast", "7b2ebb730c96c40b600cd988c7eef09f84f58bb099ba28c8ce20099d06ced3dc3de8611102d3d385ae5da0b64689b90eba075210bf843603818fe09cc7a907ee" },
                { "az", "92cc2ddfb6915375b8f47db6b5ba58d9ae5cec78b5c517df1e250e0bf667a75326b7ea0668001b24224eacd18f399f7cc2fe1b2ae5f59962ad1fd1ac1d65e561" },
                { "be", "8a6970b117e35687edc3a805a8ad290f335bddb4ab81805562c3dc75b9e64feae91362ee0f06de557ca4f1716e1f767329f6d249680593d0fa97e94658274978" },
                { "bg", "ce5e22e88ee5303974ee5be301a3d49876a68c547d1119659fff2c9cb6436b7ecb038e27aeef72a43bb287aeb598e8e40ea939e37ae2f246a87f29a247ff0322" },
                { "bn", "6c5a14ecffd742cb7b1249aad6a91667f355857090d7e5a7c62113e4decca4aeaf314bb3ddec82e254fc2fcf9e96d03df85525ca4a24b1ecc8bf8a783b16f024" },
                { "br", "6f64b5c0427b5898982340567e696117b05dd56985a2df07aaa3f1861eb9e834907977386888de8c099f4c7dcd69ac0e81d6584e11ffaac547b9a0698ef709d2" },
                { "bs", "83093369ff9b81880246e98e2119a03a968553fa0a3bf4618970defcc74faf4706180f806c53fce70a93bde2f923690ae5dbc2b3df0e1cde10686a7d976536af" },
                { "ca", "2b79a29db920739462f21c0d463c2ee342228542104b71291c16bddad8e54c980bf9e4e0454acff5bea99d20620cdae9194cda6ca7a6d8802ae4f72d51498380" },
                { "cak", "636142bc580dda1a70ebba06f49bfbad9ada2bbc20e2ee2e1135677bd8e45359101b026d11457d74f78539526506b2ee04bb03dc0ad3f8f4d9c6276935f6738b" },
                { "cs", "7e3b486a3f3037c57b9ad47ac762004a18c61e9fd3507a99e775297ec93ff39065530394e0fcb1435ec8ef3281027de483dbada6caa1640db16952d064e30ec4" },
                { "cy", "50b53659769b3e0547d1332b6ff2289e33462ec09a0c1cb7cb3d5f25b1c3f9ae1160d243cd691f69d1b2390a0d61079f3cead4376b4193e9bba35bc80524ef2d" },
                { "da", "6bf6f9a1759d67ed5283af1bcb82c4bcd2bff7713bdafb4d39a1917c3d58f394088b342cce48b42cd7095f76d4363af7630340cdb1706b7765c84548bce1c406" },
                { "de", "b818ecb52e9fc2b4272f64790214dd0e2fa5038101d7564ad66ba1830e67fbc466decff08039deefd711211e1efb637f2b5ee2da6f1c05e9b94efd764323077b" },
                { "dsb", "cbc699d1f5a3187e24901ec9afa0b6a71a8670bce3a8855fa9a2b99a3cef792231a33dbb34da25487af9e2fe619547806ed34c2a26de34461b262a08553f06d2" },
                { "el", "6484ea1e26a71aa1dba60cc8c1098bff7126b4ae2a173ee305fa3090d9fec722af197fa6989b1c75c6a6b6c5aedafb2f266f9052dd67bfe32de5ef702af53033" },
                { "en-CA", "4cd66f93dcfadec6ac984d712a1e18f5f537bc6082af5dbdcc1bd1be08be44e08dd4cb94fd1023d813c7ffe73312e3c1ae72037f1dffd8d91cadd3ee9cba7ea5" },
                { "en-GB", "4212c1c643443a5e56bca491709470967e1779547171ee8420156db740b5d8475144aa56fd7f5b5cb0619122b5f4aa550b5af45fbc3e1a5e312ac952673b8529" },
                { "en-US", "d27025cd044acedf5894fe8c65828442f07e564589bf2d905b4da79f5cec51f3eb8924e837eb36d2ece84e4fea0bce393d877973ebab6bcbb2e89a89a63dac50" },
                { "eo", "79ce3385f6f52c938085a962690b3e6293aa19e1e6f5413499215a4827c79e3e7e2e0844b9dfab4905cc6ec235f620d19c8f9bba4b8618decd4cdf6d6a910121" },
                { "es-AR", "980142f51c40fa6b4462f2040f46afe76a5a132bc0a30bf8545dd388c1c8e8b8fd175ad630248998bb8a6c9e61aecbf83267b0898a6cb46fd930378593f64521" },
                { "es-CL", "58251f8607e96aca04604132d9180c33bfbc6f53f12371e6ffc141909d264c5a6a11d342c6bdec64c8a18d6053f1b1d1288ced6939391b3713877c5dacd60320" },
                { "es-ES", "1abb27027081bf491740f92d1e7e70aea2ab3abe53a83b02b182a6c46f3c36a168ee0e753cf2ebbaaef505d45c33c52c1084197c107a5ab5de044c65620d17d4" },
                { "es-MX", "40f54a0de2ce1bdacf8b88e5be26af1a8a96ac60d63dd9bc154259057f2f19b68e1ab9ae50b39b20cf8ab29f3c6acefe1fd22474d680a0526fe8ed0f7c93dd70" },
                { "et", "4d70f454f4e6f45ad51c936e5939f63fce28bec64869812b57cefee85f40c16352346d64720ae378b1ea2942845ef8e5d5dd3e0ea25dc4bbb5d36cfc24527a69" },
                { "eu", "af17fc4cfb6d0331d0ec584a3987bdd17a5ec67d6b1afb1350a93ec3ca55411ee8bd36eefde74a5be62f1b376d969f0f34f865d9b2ea2131944ef7391435bfb5" },
                { "fa", "b39501bb45afc3d2f1380f9b8e5aa3bedf7e8d191ad9c8ac69236f6aadb01596404870826a19fb8488bd681e99ae6a9781cf2798e0c6f9a6f3911aaee62a06ba" },
                { "ff", "79b66fd94bf21e35ae9731ee05d305f5f412c657797815dfa94bc17d3d875cc1d446949b6671a8e98ea076173896bcfdbac3660a7b987c58f7108054caed69f5" },
                { "fi", "c468b53729360594b5b1f463a354b82804be286b612567deb8bac60f610c31dbee789e3cde09e5e93846db68e63ee053c6bd4abfa012164c86388823ca1e4c06" },
                { "fr", "046768ef766e53d46e4326ef70c8fc5af5e2834d956eca82d00bb1f7827cff99eaf84b4db2c0c2b29440ab5b56f74d3e475c52e1cd88ca24445abebdc9a151bd" },
                { "fur", "7f4024d7373ea7586a4c1c93c5c1c59b90621fc62360bb195388f10b04ce6cdea4e91ecb5945d48cf39c160db1494e42099ff1834e040323a9f93aa9d6b1dace" },
                { "fy-NL", "f4d8afdc541df7b82c434dfe1b3fcb8b8edfe97a4502b6a3b91e8c81d940bc80b796ff5557d0ca0e66cb41a337154bd7f793ef3e3b75fe3371883bd71501aae1" },
                { "ga-IE", "7bdb210b733e0a9b13d5833704378f75c2d7aabff6fa1f2f6f1f1e434bd6db1005432da7d4815942bfee92ea365ab45831a29f2166408d2d218aac5f73c2288a" },
                { "gd", "cd854ed51cb5127ec9adb11a37293373d3c965de03abe2753cc0570a55cd1f0d1a586b225b047312f8b1bc77b622d863d035c5741d3235382b75fdb199733706" },
                { "gl", "f88ff59b0454b2bc2f330b54e31c40a58271cbd6fd06c631076d2d69a9a025a58b6eeab31ffd018fafc8ced2e05b72ae40354a2197ffe3da4dc1e30b809a7791" },
                { "gn", "13a5768ab5e8b1ec39d2c9ac61f13b8c784a8aad36b95f8d3695e4a56db76a9ea2a352b029c930863de86926e5df98e56661b32acf6781a4c3780c8bf8974833" },
                { "gu-IN", "951a4f9266af0e5f1245cd0dbd9c345080360434ba5669ecf39d383b5be04dbbf39e48dc23ea37c43fc17bbe186ff8da5cb4b5b3ec1ec30787f395609979c21d" },
                { "he", "cf0cee229ee83806f09ab01ac8573697448b0960c10cd5806cbe5adc92120e73fb9e69d6ab34ae3ab4edbb3bf8dc38911c6c994e6d2f656bbe6f95b8824c5bad" },
                { "hi-IN", "7f1ab9da67bdf44abb195db24e61239adf7cb05f523ecfa4c800583e84e622335c76aeccb233613df990b94130fe4e788ea7910d314ef19317b09171d5e139b0" },
                { "hr", "dc43caebda8502c49b00d1e54e7ec68a7e997dd0da6cca59a715448639b55d90a7c0a520efc4c324899cdab38f6f32d0eaadd121ad0a4220a97f3076acb9eaa5" },
                { "hsb", "d45cc8d991090241f12c36b10b88ca94417e7298954f341d844f7c46a51918ef1bd343c9deb5414a3b415cc10242ec92eb6f77ebe47b0bdbbf253f7d46004f6e" },
                { "hu", "d4a51ea15a6e57b6a98818aad7d3d21efabedb691dfc455d92d70c7ed6da848e48531c60f58d17e247132ea254d93137bdcb8dc20f49c0f9ba449750b3ac0d34" },
                { "hy-AM", "0af07fb17a3b8a6fe92d23be0411b0b385f68342daceb070981181e3a8e0aa8d6a714cef4b8bcf63885fb00292476aafbecda4c8bb718a696ec85400f960b41d" },
                { "ia", "3e5879582a551711f810a93d3a92d40cff91de90f85b05ecf1aa48ec3aae5b960c2e668f8ac88268bad1f3812f06e3d3ad66f34a0ad5af3b23a18e7fe475c117" },
                { "id", "dc95a121046c4307854f67890487806594bb520d919d65a9e9f148fb3976e0e2240542ce18218db9fd515b08351adb0de9fe72d078954c1c73233c3b808a04bb" },
                { "is", "84ee5b2e7169883e363452b08161ded77cbd260804ac4566a08b452e823aa7256d66d2af0bdb8979c5d97ef5ce2ae955f13e322c1790f74796a2bff6ae5515e9" },
                { "it", "48d1d992e70a23cc254473b71ea3986142283cb217f3e2ef695e7f3f2cc69ce3cf6b323ad5840f802da4c06e0a73747755719d6dc3fd88b8591cf3dcc4b4bc7d" },
                { "ja", "ea03fe8c9fcda649fa2fbd1d8922df6e9f6ce5730e852b6baf10a72b2a13e087e43c66ac8dd357aa1ea47e2370cc30535adc05a219a0d7af8ba1e1bb0085e4a6" },
                { "ka", "be2c405c0541afe0a40435a2cfa2d9ae0af887882327c111273dcf400ded377a874ea056a1f6b70704ad7417674f05143ca064cc456175438ad1d083c4f795a5" },
                { "kab", "adea97b0bd86d369968421a8e0eb0bdf2dc567ecb2adb992e72df30cac96a81e501fb20b7578f0ab96a0acabe845467c354edddd33b52e78c93f60f72ad68292" },
                { "kk", "66fbec7fd1f831e898d92f9e63db9ad126ccd7389c91f8934632b3474da61de547d46e0ad6e5d962c4862996e0de360c7e3dad280b65c6e4ed1885623a8b1a48" },
                { "km", "6dbd72d0edc74d17bed7815dc6f4479cf481bf657d5b0bd991046fe9cf9f35c1492556b5b96535353031b260fc6b024dbec4ccca8a3c5415f076193fedb7125c" },
                { "kn", "6b44215f04ec7ef4a018534ed39c2baaeba2ab79553ec7df0a84e97a707ab72b315367a530c9391bac876fd81564662f62bb98bba742b2720a3a5d83c06e12e8" },
                { "ko", "e54b98674fd07eb97e897d7c4893c2024719782cb1de8effc57b4ac1879d547b79509b986bb65aff91a728355f64b66346a993e0ea964850ab93c2eb411aba95" },
                { "lij", "3110118c756dee0619b3cc4f54bf88bb89700a0ff17f47744929cdd198a101c90f87f50553c259c06a1afda78aae0b2e4059be94316db5d48a69d257daeb4242" },
                { "lt", "75ae44e90f148192a9b70cba826b77d4298f1c14d677756728b7502b401a9f1ff35a003732543b0b9fe768900c9d96578ea1926106c4d207cbbb87919bf65aff" },
                { "lv", "fd4fd05d01a6594dc842d53445fafa928182ab031cc97bc8266c9b62b0c478b0d8b88a43c60ba6274b392954cc1063f3d8ffc789fb730f0315ee599eb0ded2a3" },
                { "mk", "143f26d1abd450c8e507277b951fa3ce76a5004bd0a65f23e1071b35536875ea0443cbd623dee1dd0e9950742534d20f9ce59e5954a2ea37d57e4c23f2bee0bb" },
                { "mr", "60d8be96316fac478ec494099daf9db0dd4a329fbd6d09b7d1ac545992c25f8d5a5b2c4c546d6a5cb1b5990d60045b59ca2e3ca16e067773e714ac7ead608274" },
                { "ms", "289bafc37c67c65f118983a9504e5b1c38bac60169833a75adaf0c1f9cddda0b83c30b227d786fa8544328ffbdade89e7a14b01bb490c349d75a07df9272fe61" },
                { "my", "5a1386e5ebf53dbceaa9c701f4fb560de73e996d04fb8d5499e15e06929fe2bbe932e00acade1196bbf218df74282bedb152e72cac3f90a304ada6ea4e05e339" },
                { "nb-NO", "58e33dc2de84da4d25b2366df7174a6328c9bd4a2284ffdcd7ba1f3d665cd04db0fbc73ec61efddf8ba930f67adb7789f69cfe5f714ce3c36db7a7c1f6a6528a" },
                { "ne-NP", "396bfe75c179f3ff57111fccb8881a945e0d74cb817745353e770370d5f0889143be562e0900be7d443c8d397cd9afeee438c339ed98cbaf71be15ee04073c52" },
                { "nl", "5e5764390e5082567ac86ced28bd8ef234a8b69d40cdccf3276e3098ee21f92587df779358a11a828c7e03655179a7a68bd1c81fb938a50850b4ef613be1e0fc" },
                { "nn-NO", "87451b36becacbf15b237acd12b9b9f0a9a619fc71494103593cdee6352c1b8ed3b3dbfbb45820d1d403f0891590d91336c373300ff62fb9e1fac63436f50893" },
                { "oc", "db6011043a4f476ec077c2462e4a3bfb9b8c4bfe2df7b02e8e067b97a2d83fd8fde33c8dfafe062d40076570ee5d86f3d28b65585d9b4749adc133f39140c11d" },
                { "pa-IN", "c454d924566048879bb902c1bbf97ff7267a9e975cd8c8c945a2c570d9f25df09ed2432a563a80e7a474c1a38f9198714dabdd068d1bd7c8a74a798e49a92548" },
                { "pl", "94a08253575f6c2612301f9a35a160df637bb2326130d0cdfa8f02363e77dac807f7d483ebfe855df3cee7e549749ba6ad2b152890d5077f6c776001c66a186b" },
                { "pt-BR", "f65be6caf7e5d8f8f79601d51178c14e8ac8d3d4d10ecc7194e6a871c00dbdebe52b7434aa62188ec10e999cf50c9d17d406b0a5b11e89f848959222aac47991" },
                { "pt-PT", "a3603be37b404167e923b87c053444c4e66908e976a0fb665b0b91cbccc22112c81f5b6a74e5b67bb61485c75b6eb36f361ba1761f420c636c3af52bcc1447a8" },
                { "rm", "11b3919081b4e13850b271064eadd87f81cf3cd98eff5ab31bdafbc7dc3c15e0ba8b0c40e99acdbcf65b899d5c35200ed73cad029d8ea95b4873161b61585092" },
                { "ro", "fc22c99f0ab02b565bb0339f935676d2fa051d0cf3ea6360a55a41e5ae63da7f673c7442bce8b8886bb6517acd123606fc1c5e91222c2d03fa2e938e6d0ab7cd" },
                { "ru", "44004aff1f852c340a3b11cc6dd662336042eb6afc8cbbbae6fdd56454e69d68266884ad67119e3e5ed5fa491a4239fc0a0e41979de9c94d8a0f2f22dde95fdb" },
                { "sat", "7ae25093bda3255f5eb1b05dfefb3f42999110b566108118d2e1e2bb0c5c676d5aa3d18f59d49da596f28c9df7bc5bbae911318ee1b1dafe98ec9c9526765595" },
                { "sc", "77e8dfac8910b79711bdaa8b3056ad0625d56637b656a1d66df0d42385884f4c45aa7b620c1ef8c3502dada9a8dce1acfdc88ab7c132b4eec5cc0709ef4df771" },
                { "sco", "6eccf5cbaaff02dda3dc3a6f0d8899162f4392f3c0ad2cc9ea6f7edbf2a26dc8e6f846c2f5b3ad89ae977a7a1ccbd1830d3649358ca7748d7ed26ba5109569e8" },
                { "si", "a5469aa07df347d0e8e93aedaf143518f7f45e78756b609ee764f3a3ac9b808bf6242cdc6a3faf4864382be0bba819c38b4383266941cf047cc41189b2d83301" },
                { "sk", "f8c74dfe8ba3b3d690affcf2d2ec51408c6695a963a44373b48d464dcae220cd339c945242f1a783efdbcf8096fd3e55d9ce0f17f52c96ab454da9b5e47042d1" },
                { "skr", "4931d34b1c8859daaf580b7be46052d994d63387c58c99d7f7ffcf54ab52c90ff3c557ec1207fa3437d30435c585bdbd960624470ffd938908039d8fcc9cbb0b" },
                { "sl", "add4c08fa7493e4a48e38fd9dc083ae911fad616329b586fafe04ea0cf3d670fbe72b19b061c10c828831b77068f381976b5fe239de6bf3bdefc7cbc34604010" },
                { "son", "b9ad033546efc1680df2542b6f8f3740e7d6060789d41fc3e7ae0f7c011d75cfecf71794a2e53ee2d1453b78e419d127f055fe53df85887e32e59476cf3dd5ee" },
                { "sq", "ac2917c3aecf0b03f15cce9bd658f4887b3ca0b25d811ab0f2019ad078d8b3da728f453139c346759174f78ed7c73bee8f41d27b3483fab529a063f1e8ce59f4" },
                { "sr", "7c6fbf3429d3f2e3395620341306a586cf28460a2d8b475894edb5afb803231e8fdaad02602b43f20c076ad629e07d286d5001e38a7305f14ecf52f8006e03e3" },
                { "sv-SE", "82f0200ad022d213aecb1344e48ff94b71c7eb2d3ea32899d806994a16fdc659291c2e5312430bf901eeed9e1bfc7c33bd36d7afd79d22d57d67203927baec6e" },
                { "szl", "7461fc41dd2d302dffa019c5d8f63b7ccaa845096cea12dd41f3b1d28c0741b69b7149e0415500702e406242a6847e0fb0aa71c7ce7bc736c6c3803e14b1bec3" },
                { "ta", "4879bbf8316a52548363572c2ca471759e96f63ee3bacd1b8d7bfca85f772297b301fb7b5c6ae02dd0df56f4e896d43225a360ba62317dcb9492950ba62a205b" },
                { "te", "c902b481fdb14254905cbe9be5d082210a6a381b8fa756d6d71ed7ef266cfb7724955b2a4491c342de45f6bc84bc7de77483bb781f2e52bbad7bbd205e6010bf" },
                { "tg", "e1a62828dd6530a4f2b397af2a49bfcc7e7cc6eaf902a8cfe56cd96fde3799fec56757af5777cd2a260e360dffe69dabb85b2af8294997adf8052ee4e2a36ad7" },
                { "th", "d22da09d04dc47635f52edc3d31b912b9bcf1b06b16345f55d07134bffb5be94f377102c2d90afc3f2b51a85f7a32215c10548fa702b58747329db5db39e6ad9" },
                { "tl", "e114a93b0adab8a2da436a7e53d9430395537f45d895e620ce597e044fec29908b6e3e5606034bae5ad019bd9e607a423a934456a4485c974a4f4a0fbe300a3a" },
                { "tr", "aad50136b406091c4f954c69a25795ff2fb03da922a858fa0cf8160767627d4b6ae60a3a654d0dfcf6bb79396bc0b5c4a5b412e837d6662f461eb9d7185f665c" },
                { "trs", "61f84f468fc2d36cc12dc5727ea41199b234bc5c0fdd986453da9ea4a0557a4e9985913a7cefceda93cb3a58ab8a75d16cd8c3610d2f3be4f01b269db1690b2c" },
                { "uk", "9decd2637c8c5f84092dd3e7ac3109df88411d0e81cdd1df761b5c41456f4804b5138006f23c24f085582d81144fb2ac82ce99fa640f46bbbf5cb1a2b1569ed7" },
                { "ur", "2d18fe48732d4b54940bda19ca8a6d2b1058e627bfc850bfabadb4d124621cec703e748bcd518fc64734f957a4b29bb0ec57169604ef5a3fb3b9f8365330a9ca" },
                { "uz", "638135467a47da0f08358fde70ebf7978c5a5348c601f2ed5b9b34a79c2f92bae8aa31f4ef62bf7972ffbcc0f69b8ba78f26f2fbe38a94861ecf57fed788785c" },
                { "vi", "e8df4c4669e71028bbd09a557c05f538d7fbf72bb987871ff164c9b8f517ec058164ddbc9eb0b4033fcf7146c4e56059a8e2406ef313d6665cb2cab677a5ce57" },
                { "xh", "fb4070fe3a2c3f041403fc53da4263a3216aa68dff3f5d12b0e85cb4ab6f55e8063816d6b5fc722b36f3b937d66cb3f6117d8482f8089b77a1d1ecabcde59d8c" },
                { "zh-CN", "9a692ace87a95bead2f2007b66b650a79ba87aaef9ec2b32961cc4e80510d723e05ef770cd0f7a473b18b60aa51752a62aae8733019e458ee9cc82bd5d616d48" },
                { "zh-TW", "6cc67f701b40fb87827812922bb5fd45766e3fde6bf091503f873e499793fcc8fc63ed50a76e3ba96bf9dfaadb1413c7a7207a91006239ad881e799ef7519334" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.15.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a68fa63669222ac739b387c20821d4dd76fbb4e816ded5c9a4a66ee97a11ba5296b6d805810bca0bde9169cd1ff6971effbf66e0af845780cfd28545d057acb3" },
                { "af", "6a383c6428479285dbdd211569ba5c4cd330f28795ca11a1e08e986bf9dd6ca6086b2a62374b04a83ceee6803bd9b430981c2ae3b4cfd41c8388d81f48d4a859" },
                { "an", "a603dd93a44889c438d3ee7dcb38feae656513562404317ee4d4e65c4b66eaa717bdc6436881db46cac12ec3f811f4cb2902935b5a3bab9d5377ad6bc8711b23" },
                { "ar", "475cae47e192f0c786a9604c7ea5d2efc86d6d63af5c6f060c1c6ef40509419f260d22187c96a80fb81310ca6fa343473f2975ec43f02876dd55d5143971edc2" },
                { "ast", "3ed8bbd9d379f96a076e755760ba6858046eeef4bcdb026ab02c4292264bed6b6f70fcb37b499b63bda780f0fee848e72c3cf9fb5599bd3bc715f9cd44507cda" },
                { "az", "1ff01f5a03c7a00ea100d0430528b4278cdb777c59e77994015b497050d06407e0f9d941b8dac97c40f3d57bf896895df73f5ba5f78b42b6be04ef3aa17d9f7c" },
                { "be", "2499a60db457eed03f56a71cf34be78c56c2d5a3a68e2af2c98b2ab0707cf7ad8768e52f058c955a115879fe4d46a9f59049b605b8f0465bc84be16f07fc0f61" },
                { "bg", "8bc01cb70757654c1106d5e3e092dd21652038d6ed85beeb00fff51d92e2baa014de728c13cccae81cf835609d40ff187fccf12128c503ea22edde4cdf38f21a" },
                { "bn", "ddf2813f47ad505ed968e7aeb0807711934c438458454c7fd9fa8258670a8b52d2f9cb5d2a077e08da859f8ca4ba41fee4ecfcc125a987817d8cf784c25ce387" },
                { "br", "213202db5532fa55a4fb9025591e65c9962b55ca004558330ef3a87df824553c3831620d65c9aa10ec5e13acb4ca64fc0ca656f57426d498af6516abd58e18af" },
                { "bs", "fe8048866fe744395d4e1f4facc5d7342e24dd87a9d7ca0aa7ccae6d54835459c177eec95c946fe3c968afc1db051b5a4316f4ced00733fe3b3042fafa859e61" },
                { "ca", "17e07db2b4e147184dc8c49c92ab2758b94e4287be1801f1c53d42cb0134f42b591c1cfbd169626bec9417adb7652ce19cd031335e05e109369d62c3b2e667df" },
                { "cak", "7b5f0519ffcfd02bcc2f4a067ae4fef30c6c333e5a26a7ee26d3519b953555156dfccd7d4f55329a0a34ea815aa32daecf36875b320441c323ffcfdf841d1536" },
                { "cs", "6abc4acb4d05765a6effe785ba7e506b8cff0e1154a5a41ee3bf85e78fec0fdce2d70048e3df3978d99d2f8a8976f87067c92952472a7ef0455dc121dd933df2" },
                { "cy", "fc1fbf0e161e508f630659f97ce59b82c32852ef8bb7096eeb4f57774d897aaad27a1f8436f926692548b4c80d97ab55ec2ca8c7c962e9b09dc90c971c0a1e0e" },
                { "da", "17857979461ac792e6aca8864242cfac5bbce23dffe12432f1cdeb7fc30ccb06c78cdaa00be54fddb6bbd161ad6d9cb34a7160c9382b7e4275e7576ce1e8d45f" },
                { "de", "7dd5753e8775b03eaf78bc3ccb4fb72bfda047099cd6eb553fad8c91966cff75109620b1f2aa9be205091d1acfb2825796a77eefe8f2b4e68e324e0d478218f7" },
                { "dsb", "126dcb83f5319e251d2b1a6268a01ca126eff910e703f8b1c7272736e6ea2fdf95a993418fbf34d2a6ed52ad876c3e36514124a7eec109ef8737676e1ee5d2f1" },
                { "el", "09ade122d73eb999261bcee9d5526ff5ee22d4809ced8901db4e65b987eb97d0c422ffb9f59165df10e88c10ac836bf32e582fbd73259959738b299c51d625cc" },
                { "en-CA", "2f343dd9a7b61a8543c141575d88da0c93fda9f5905b62835cc2fae8daa0915c374922d1f02b8c8819cbf9d3f5fd0ef115367cdb8dd0f82c2c3c2a2da4d1c66e" },
                { "en-GB", "6b1be5e252e0f98b3d11749adbcfcba34a8ba9d8f3eac03477c202e0d195dbb75ccd06861e6ef84f441967e7e81a522c31679f99f7a6fcbcd93a6cc42ff780fd" },
                { "en-US", "95b523e4a048f22f22590ed6db34d8935fa9d527cb4c20663fb992111b81a00df7a17ba5e872d89163a4e1553753045412cb9d12e7f05b595b6382e6020287df" },
                { "eo", "2ed51df1262bb0386f1a763172e91bbb3689e9e3c76a899df12f55174da711e2ba9ca359663b2cca9d5e41119c08e9578cf051f4e254b83416312c3f75cfa328" },
                { "es-AR", "81ea41d3c549b7ceb063887803d2afe472b12f3ff1c215b0ee809d109382e275680c73a52cc8ce1272cb3f569bb78c8e2b0460974beb55a25d8d9972c4d4efd4" },
                { "es-CL", "6f57d59baaa60dc22cd3817a9d2392ca8af2ef27f5618987e03b087874e8b5a9085fa2a4f4e64a36466be56438c371300c26a5050277dcf04511d5f94e43eafb" },
                { "es-ES", "c3c58f82c71b6c93a67cee313d417d63a619545cd763f2eb4e704f7080091034a378ffeac62253e4e9f30595a2195777be215f901e39305ebd41d25d9269baa3" },
                { "es-MX", "58988bd67929c36bb1defad6ca8bdab4075304ec8168ae8fc99137fb79b4adeb2eed501cc437ebdd781b326edb1b41ea1a77c8ca8c3d53b48a5953ca92cbff9e" },
                { "et", "9aa56dc43b123b28bc47a5e64ca193ccb53b5c5ef7a036d85f1cc969fa0685769377379ada7395e9b8a7ef4adb9bbc85215de4e8d2a84b611b9182674b45ac69" },
                { "eu", "d2f64dba44b2aba959eec8b0590291ceb68754c32fef04ccfb2c9bbd6187794632c3b7ad9f17724be3b397cae176605b722716947f51a208db211c2f633a2bdd" },
                { "fa", "e656c52bbe7216a4af3aca93a524aaf67f9aa0072c92bab67fc95eae9bdc327759fa64f2f9cef0ac04c59041a77216b9c417def131e81cebd1f71d5fdeb2cb48" },
                { "ff", "2b7fc1544fb713aa6b1314c3c53219bae0aa929b1bb1699f9be7c25e95c4d9153f104eddeaa19a390050a4d52886a60a13d86a4f906fcd4b586cd32dcd39efe4" },
                { "fi", "98b2dda7f76f63ebf3ddd5656e8a34cd0a1b679ee86983507b2b3390a75f78007e899888ef2d74f01e174cf7c313e0d16ea0fd22eec43698d1d89dffe2ef5462" },
                { "fr", "9a8fa4ccd73a0d4032c09f9d00714c8f24fa346f6291f18afca9bd08e7ed74efa091a817163cb528e7759f502cb820dfc711680c4552ea533602c7bceb31a9c1" },
                { "fur", "c01f975d78512cf8029cd795bf83856122373b23cf4135af44689f7079c7d58f6463982ffa87274e3d85f9d98d3e52ba05790424765e7edbca5cd59cc69d09bd" },
                { "fy-NL", "ddcefeb1c184dbfcaf66352dc7f56aacea245dc174b1fd88ee2a35473bd4669e26c80377cfa66bf61392d15cdf40518b59af276c1cc4860e793289612252923c" },
                { "ga-IE", "e257b4584e080a95060ff31adee058f57baded6ed279baa4f09eb21c54c83068879270113885b59cb737bf5a727c20ba6a79687f818d9e6c9beb24f233b577d3" },
                { "gd", "e380d9dc41a7d95d148c16aa25e232dce674df125cd44f90d5d9a95073e0c96f6ec7c70505a0e066e5ff1a5faef3187c751ad1f243fd3040057bae6ee51c9919" },
                { "gl", "b0706de29b267d65c185e7ed88ef5f97eaf831759039b3a9bd3cff36283bab84f5f5789dec540ec4ddfbf6cccc96a988d6b0c22db273cda74f7bdf59d128c13d" },
                { "gn", "5b2e2d996063e51de0e8f538cb27e637bf6b4ab25dacf6f941427dfb27700e02576a671ebabfca8c7952f38fd76f343796a7c949b23792c652aab3c37cbfa1c9" },
                { "gu-IN", "979447b5ef255d8590ba3be0a4e43a19e2b6a0d12a6111e28b70259c08fa31358d5abb310421124481318c96bb61187e861a15abb7d98f182b88646ea1a72e16" },
                { "he", "2d2113d49cc62a35a7751420e70a75f3d0d02493198f668d1df4137079f4c058a21f99c7231cecdeb34e8c1bfc4e65c332d74358841c1f3fe42439608219fd4c" },
                { "hi-IN", "9d78f44b0a4c4e7867afc32f75ec195e829497344ab712da1ca3545422df72a0c48855e288aa0225ee4e0374eb1b46d5270e79ad21327769ba50acf572b129b6" },
                { "hr", "f50a082a157208899feec6f9cff13043e91f7ca7738896dde4122ab768392f1b315037e878b55ee756dc8900efb400464782f788a86c4452cdbc6a820dd5e0a1" },
                { "hsb", "51a1612ac6c4cc580a5508c8e6c295fa3ede3d6084c726b0ee73201911018071e662cb2d6202c5d3096b7c3a9653d889540d779fe85c499c0be143a9216ddf94" },
                { "hu", "b2bb4a8c0c044da033f825172996d94574818361ff1aa79b51f4bd6df9be07ed4bc61a3ad80054065e27b25d77862325940cdc6782fd1883063958ed68707be4" },
                { "hy-AM", "3aeb52dc2d99432ba5797c28e878ad82f4d58fa3cccd9ee509fe6bafcaef7b258a1493a4d87db671a71ff253a96d38cdd15b36cd47ec4408c6fa75014b9aef53" },
                { "ia", "05ba2a2f150892aa5b70bb2b2e406b91536c4c6e382ba7b9d969ab2fdd36d1c71622b0a92af5b9a542df25a1994c1cba7b56a28704f4519c00076c17af4c57cb" },
                { "id", "9bdbbbf2da6d322932391deba6436466dac430dec4cfc6db79b47d0e414efbbbf66438428fbc5f30f7e3e5e41845ce95eed4a8415d0020e6e127468e84a87c79" },
                { "is", "ab1a92bac0d80035642a0c6356a938cda91aa2dafea1199c94af1ececf6c4b5b5d244f06387795cfed61b661c8c6db36b6f3b843b40f3edf1a84b049c0b9b3fe" },
                { "it", "0fa257651bf82bdbcd0cc56f0534d196d2bad9a0ef46041b88e5340f962eff19e0936a7551c4a52750ef317aa17e28b0158235b67601c331df885464726ad7d7" },
                { "ja", "2174aa8563743f4603919f26c2c7e84eeb18513c2b91e92f6a2f65b046db9b611ab6611aaec76a48dd67925a54897a9dda49ee8605a00ed14987a69f788a3251" },
                { "ka", "f286a67e0f784a2e8ac1a7e61b8b369fba781c8d3861f8605ded6bfd811ab05b758cbb1e909aeb16db27528dd4bb805197d884c77c2bed387189501745020c37" },
                { "kab", "3d938f906b3ef7a68a41b270253f1bd17337cd28f2dea4ce4dda0aac6f9a26345761a64f1b6e588aef2b290eb8a5ae27c76d5aac10a07b0076e64f7f7923c04d" },
                { "kk", "080a6455dd0ed16fc0291b3455a086f53e4bbe9fef3797bc9ca8c05005f3846a680ac4365f0395116038d123f8e2daa088662876025c85cc3c1e57dfc6f85e4f" },
                { "km", "50273325bb52eb392e9af3e2e96d526f31ff00f4e92f07dff7ce27b3a8fde7f92e80ad22a1925754c8dffc415d95071edf8da7f97ad25f338c802ee0f8d17d1c" },
                { "kn", "adac7b33a1435d737941d587f95f91e236e6742488006bbe2b570f66628aa07e6d11a1db2deb45fefc37a3422c4bb52442346110c90f7d3748f235497afabdb0" },
                { "ko", "2ec954b15973c6f2d9412ccee39ec6b7c0591785154f94dd90ae3a7422323e5fb783a3957a7a8bc73a52414daf5c71135d8182ff3153dabd2d701ec7f9bcb17c" },
                { "lij", "0fbbf173f85597d330e0ca4c86cbff4570f28c5abb72fbf27285e2b4da32ba017aa592c185b656026dd1d779136453cbee5a426aa5735603625d650f166e53f2" },
                { "lt", "e82298c27c863c58e6be83191963d428539b44d9b85d87bf744d8ba634a99ac8f97170df47fa62da53552e515a09cdbb879b9c41148f24031b6ac68a47a5ee7d" },
                { "lv", "61cfea8a836a13c38b731da57e7a3918b536d5b87976797b471c335931249adf343b8e19b1eeac96fd87a15e406481c5e79e9da4f17165e3ef30bc82ca2c4e63" },
                { "mk", "8073403536c2a52416d5b132712f4a3ac9f846798d1bf32655d7c360358f19be35da97609887d7d7252b85a75216f9d6d5d9610beba0b64460283a43d63da221" },
                { "mr", "5fb7a7e6803345a5f3783848983f7ddb944f540d6f13f0235bdc1542fa2732d2b8c434c83c24369e2f0cd454a79d9205998dfd09a1db16d30069e76b55d8d365" },
                { "ms", "61d6d81c60cfdd7a65794d2aaa60ad19a1bade36e5d9034f5790e17d1b565b5e105fdbc1ff0aee342cd86700441c25c4359059581a9b6ce7ff1b673483edeb18" },
                { "my", "54ed2cac0f0648b102385271f5a0c7661026b85f7e2334af41a4df85e9f30c3ad64977f1218b2778772cb2e7f3f8768bfa6bfd2413791e3e9746aa409e8252eb" },
                { "nb-NO", "5eb825e7bb9834a5586a147b0e271bc7c3a3cac35ed93b41026264c36466c2076db1d0b1e960bf1be7e4319a3a55949d53c25f5ae474828127285516a0333d38" },
                { "ne-NP", "4951362cd5723d8601b99d758f4cb80a6cc7ba0d1415203a5b397cee29d262ececa620fb6828cc94849458371c0e22dca42af1b9c7d2527e1680d76df61dcec2" },
                { "nl", "6a702b26b49f5052988979ce33b6eaf757a7f373968e58031c03c0946a488885c79dd25817542b434c1005d6c428e36720e8546fde3a8a4765be5b9854d1cf7e" },
                { "nn-NO", "497cef97dcf32b08f7c00ae5b0d5f9e23ede899f1a43b91ee8d3cd4b168c9bf768b39022f68c1b7fd703d2897c70214218ce1558004ba0ab17852de119879fa1" },
                { "oc", "81a52d33e0e8a0c819cb8fc6e077e3044109c6cf6066d38c535af5d26e6599ebe8f854aea71ab6fddec2c5e1a3f681374b24d11391a16bef475cf1ad5760ead2" },
                { "pa-IN", "416008f3f5569a8aaab1db91544b837bb99d7c4fd70b77fef7981738627a2a16fce9ff5b7cf05e0e52b07e70ac95ea9740a629793ecff146062aeca9bbaaeff6" },
                { "pl", "f247ade4d78ca07baa041f3de7b816bba759e41e0edc440fe6a23cab0d03bc071ab72aa9ff50d458b471d34732f45d764aa7474b2ab2e547c4bc267f19a603ff" },
                { "pt-BR", "2130c629476a48db2ebb92d880903f91ac381a6f5d76c723daa7e7838f288438b0561af5da97e6c4e8ca5db7d25922a6b1398edb44b2a8077c2bff383cef8493" },
                { "pt-PT", "18a423e747ea05ac9f5cb16159a3e05c5c3c67e5e16fbc0654504cb538b222efd405376f75ced03b1e7eec6c0674b4c4d31a23a71bb0fefccd51c4b4d59abe83" },
                { "rm", "fd83d56fe55f1ccf28a13c6a3fdd6030253b363bca1c388e58a1913d9726a3c61f37cb002eb813f9edb6576d83a4c698cb32e37ff88d2d367c878069733225b9" },
                { "ro", "65915400a95ba62b7f31dff3bed0ee480983e8223a6d0b0de49669ed646f267bc93e08484d1a70b81c467aa63ac96a43b26fa2caa9d0f96b919c4a25b78e04c2" },
                { "ru", "d4a09d9b94e027362bde2b7be99fa8e80e6482eeed880b499f68d82a9fab87a3be2394fc2e08d996a8530441e834e8e3a5a779220072ebcfbf4bba3548768ff6" },
                { "sat", "6be840bb8b63166cc7e1342ce341519fd88677098fd7809e79bd1b4aaca13f0020993d3dc868aa34d4d3030220a8855b1f89b30d6ded4732fb1f032965176123" },
                { "sc", "30d695398dd4fcc950bf38a5ac502c5edd98cabb44ff163cf96dc212caac220b723de7f2839ded9d9d41020e92a343d2f03792f4383af179d1852aa1b2a391d9" },
                { "sco", "258ded54bee7cb77a3b77e773116261e9012acead1e8878936008e2dcc121a7ce2797fe5af316d735fb15801f266ad5b228d020493ac7bd63d54dfa8d714fad2" },
                { "si", "68e72f104bf1651cad280f9a1275cf8c7fb29541740cfd055c920f265e54ac8715c5dc8dd2d98cf2aaf163e41d44ccd035ccf74a69e169180484e368de68a907" },
                { "sk", "1e839c5abb423a40af6cacc20e27ae6b915daa39a2e4c30756e9bbca4b3b067b7bb173c23259eb829c23d4f67711c5cab0ab9e40f14ad19e0f6a15efa65df88a" },
                { "skr", "f2c5fb6fbc27aebf757e8b9a2a8627b6935fc210383ffb6a1f8e2c6be81a743c345f348060b0371f50ca50d84cdc445aab751c4ceaf651584733df0eac4fb2d7" },
                { "sl", "92d9ce1f6b2bbbdf75c96dfc848382250cf0bfd6f19ba9ac9e92b2760ab96059b0088024250801b6f953f16115f721926f153742fb75eec3c85e2e936ae36636" },
                { "son", "b291887ee521203f146c0bec32384663995cd13259fb3fe3216db17d2f5443d11d9b86d63637245b7efa8073e2c21354f53dd61803f7213e8f70744a9e694a88" },
                { "sq", "e90961946d24dc6df38bcfdc87d86158eef8c37f988ab7abbd3b0b915be713ce721ba3d4c8aebb7d605b540f4f97a8a321726242b3dc5b06e8b47d59d1a5dcda" },
                { "sr", "af7d5f89b95a46cefe2bc68475408c634dbe9193720c9c6263470706d9be64f76f4c99d30b6313ce2de6bfa788e7a74ae7b5324485177cb810f2cb1cff097e9c" },
                { "sv-SE", "aed691e1a9f5252edad7548168c380e8fcd1f6a094f0ed2fb83e11b09fb7a83dff891ba60f87a5ab05e908b2469d586065a11a6dbb4854c8a52136c8426073eb" },
                { "szl", "960c477687765bed6f4260d37031da643c3585ce9fb3814764879695f9241e1908912d27c8d929a7fa263e216ba911b637b9dea4ca1a2fd4d46fc9a67ca741b4" },
                { "ta", "2c331a3279ee3ad8ac95069bc34f1fad6ce6202bb9bb4a401a2f4649dd86ab320ee954ed908953e823ccbb08ecb5f3ec4a1356ea925352ab061b066931c765f3" },
                { "te", "cac00478f2dd00a7fc59a8c0bc62b91c9a895ab7928597ab0a25e6dc1713621f5ee0a7dddd386a5f39bda393eaf68a767681f9663bc08665c4b36845785efcbf" },
                { "tg", "e58f2b98a80ffa68ef62488ebd737b98a17743905982888007e328a91ee2a678d6db103163efb87b31d0e8f4c7e4c6aca684d38f0e4b83ea54b5a0c2f1a14de0" },
                { "th", "8338c8ece25ff9fb4c01efac1f036f1ac7cc7177d54711dc6c7a4926643547ce914d40a376f334bf26657df4114116e1f765a88834a7d48d78539db4441eb302" },
                { "tl", "3fcb65419d530d07608774d5018b71664b0cfeb9e0b09d2e282dec4181ee26640cd86ba4ca6aaf2abec868541234ae65c72bb0151df65cf1bacd93568b88e174" },
                { "tr", "cc13c0f31f2d1b2cdde15c6b8e270d768fb20d1c82a7dd39f8f16899e6f3a2a6ab60a259e20d5c59158076ee2b618be9945c6edd66295c746140fe5572ab9c8b" },
                { "trs", "0d5e2b8c0b6e57c3dd9f326e8aae3b17937286843210042f48721f321ea60baf91218ead7444b7d35d18a5b02ffaef35aa10bdb50926c6a41fbb04dedd6ebad3" },
                { "uk", "b5a707cd52b2a3b9b6386f165708e53a28c208cbbc3b1fcbd8393f9927457ffea0cf1dce384451e42b12255dc0659ff95d03373279601df4e743d8d5549397b7" },
                { "ur", "20c59e33edbc73d5fde4ecbcd0729470bab6a5836a7714ebe8c58a76b09ab165518ef3c8a46b4ee0da1b288f411165a90eed5818d0f70e259110db78fce94be3" },
                { "uz", "5eb207326f10c424a6b98d7adc6738153f8401511298748328764dcff466e0f3429aff6ac9794d7c542fc93387913e05f22a5c4d1ade325ec0dc416225153878" },
                { "vi", "9150de534cf2e58da733068298280bb44ae77bc73c4752030ce4cf8cd2f0103bf009b51ab90dc17e438a45aa8cc4ff30c302e19fcc78d00f435ddd76baa82114" },
                { "xh", "466ebd95bf1acfb4f6a241a2e9ad93c039d096b6f602cc67a91796d7a5f4979a08ba7e3affd3b1287883bce5f71cacf5d3d8ca77b6ad2c2f0af3cfb30012f474" },
                { "zh-CN", "ff84aa76bce6e4c3454910d1c1e73b9e281774598b3c9312be9816e9500848547ddbe3b8f37e5a761ecbef9e88a3aa02e1312dd434fc8c4ac3f7511c40c6c89e" },
                { "zh-TW", "665a042a35868fc3fbd436e951a518d523764da08206c5c5756a0176cf0c7c473954748de05f14e10cfc6ae0dbbcbb39bf1b08b857c9aea075c039dc6961b293" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
