/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/firefox/releases/102.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "fbd92a40bad8da6be8abdae29b002343b4285c08aa1d31df938ec972d8fb2a804703d0645b2d178487df4e91fc25b6e2cab1750c09bbcc24d6573f20a1d9141d" },
                { "af", "b59714122b1bf011f8c296164d7723b4eb4257a8117a83bdb88b29be35346bf9319b03518dfc391e753bf2d0034c6be2bc6efca2be1bae301c6fd5da382b5b2d" },
                { "an", "912cd0d3c898aa1fee0629c22c7d781a157914cb5d10e53bb174230008fb29f24f61a8c243aa3cf88cd1ee7963fe413848ef0ea8f548a9cd0fbfb7997b9a432a" },
                { "ar", "2898e7249e2e726f1a74a5bd3e2e0f35e710ecf235b2c5b1aaecbd933708f6f91dd141cbbeddee49615676f9721e39745297a2004ad94f7b7d9d87b92f150718" },
                { "ast", "5ec253b987a274da163f3eb2f79e4ca13cd8a428e7fb4cd2fdfac3c64a8a3a0d43d0ef02d3bbc191a9a1804a689ec42374fb78824090189082eefbccdf4da303" },
                { "az", "64e7f0402de4d8854338c865aee6142b56de32a5bf522516ceab717fadac3fc1019f55ade98892e83371c6887594116327d433f9bef8d06fa1d61baee57fe8bb" },
                { "be", "828af236a92c2c8cbe598eff8c037f6d33ad306591f7c11e79eec21240ac70799c168203d2148b2c608f212aea8b9a60569a2aa29c2b36f28e9886b8942229ea" },
                { "bg", "fd8479c64a16f73cda53a36ef1075f4e81203f5a691df980ec87bcc0a4fc2d3e865c8a1f828c66e0fce7ccec0389ed169f4e971308390a3e6d3de7afa18c11a1" },
                { "bn", "42dd387a8f23d5cb411d5c1386b2648d448c5843294bfa04043bea052a4ddc666c30718b73e8d5e86cf749e222d09e205aabc82429695153b2224bc6dd292608" },
                { "br", "dc9626845035e62ce1301997c3b41e2b27b411430ddc523715b32d515288a3723cb5475d135b8e7e727eadd6c1169125a57cf4e986979e3dd397f7d56ce8f8e5" },
                { "bs", "9cc3e014f4f54a8d314cb39f7c7789041f221c7e3de80dd5b4bc4a1ef3e393f99b80b08125fb38f4e87be17e0973c61cb510b836d9876d79fb77fd45f2d2f330" },
                { "ca", "c33fdb73da457fe853034d29f814225a645d9549472fac27a6eabcd2b7265ef9ea4b08fccb2246461384286ebbf203309007183e40f975056c6030e856654112" },
                { "cak", "3e6dfb548da8b278ae04696d82f4915327ee960da721d803e5d86ac3b56fa37b0841a84152f15e91e23a3ae989dc89896e4659683b7a48513b4d781c9e940eaa" },
                { "cs", "e58bfe0c4873ca29c9a92a2da98cff3487a08efa0756ff6f2c7f7d364e68bc01144881ad1f232d51a541785d2074ea46518ee8bd0f84c0c73178fcb2fcde8305" },
                { "cy", "d0767125b811aee4aaa23c5c5eecf818efd70ee5776d3bef301b6d6715d652e18e275b7de5ead6a10d6bceb8a0919b5360cf11c4949a78596dd237f6acaefe4a" },
                { "da", "28bbb3b406187d31d8bb7899ad3d81151b29c8810ce0016a4c31991c7525406589015e185d492f0ea1f24660ccbd5dad645b58b0b89432277108a94cd608ee29" },
                { "de", "35fbffa44e4719cbc3382d22ffa65bd6a04d214efaa7faaba311a29f23fdc606a20c24c643b8d1ea7a15f5cf7e8fa4664d10810c885da5d77a66891dbb97bba8" },
                { "dsb", "303277948213d2e05c88ce8232d7376f56d6b27bc124ee4c1bea1580d3404414e56373c971aa2465361ba7bc442b29c6b404ee41a8b62b0d4f13a96916b0948f" },
                { "el", "82668b637e34cd96133a6633667543822cbd7dd5e9c776014adbb94042d9a9e9af17ad88a5ccf8efc821709d2f98e2506752b214d876d53a9f5327988f30c759" },
                { "en-CA", "0485fdef4abb15647530f263686741a1c8a5ea8b651a951706081b936ea0a27abda39bb463e687bbba40f82294b8d3b299d92c5b7b7294c576718f9e51247c98" },
                { "en-GB", "6ed98e540af8179b358c5fe4a3523c9e4e21fd7e0f07158e2226dbef1190dbf198afc2e703140814c31d3ec6aa658d23aa884075f7cc72a68e28a4e6ceaa0823" },
                { "en-US", "d2c48e7a7f61f4543e8a09fdc111f75f5fa11cf2913c4c6777bc660789d1fa3ecb34c02916d233223bb65a20460ef71b60ce71492c871eda5f28bac6bf7493a0" },
                { "eo", "d8e8b4a6d4ecc923561b922d1f70034fc0e15dc2f35903e7544a21f38585268327e0c08d32d153f8150d1f5609efca6bbfa3a473faa9fe378771cfc4568199c9" },
                { "es-AR", "74bab986f5fa246a7b962929ff80d0729a3458efe4d146ba0783afe6b4e7a790fb889c9f28551e27b1c07875d03a09339188cc820ed98ef0bdb7842bfac95ad2" },
                { "es-CL", "239499b8fd2e684d02954eaadafae80ddbb04af066234d944ea1a0e6312ae5ac1b3f27720c8aca98d8fce45c27be68637cbd0fd8b6366197e39d8a968cd8f34d" },
                { "es-ES", "df21d2e04d0bd29c7692d020753932e41c2ef71b4fd512d2f55f58e89382b495451f0739af25cd8c354318c9ebdc6d6dfdd556e7abc7d60e3f7cde28b9659599" },
                { "es-MX", "78017f9767c61406a7232d35f8685985160568cd3c9ecc5ab7c4537c249a28ed08ee7454e1efa3a1db919ac2ff44f4a15c514fceba386275abc34ee8173db12b" },
                { "et", "b3b69173f252d04f19ce5fe4eec1d43b3bc823f586e751cf605d531bfb72f570f09d887dd783582ae809bd38be2515f77ab7e7e561ad7945df5f2ebe4b7395fe" },
                { "eu", "0a2bc2e45c5a63ec8c1b89be60d408af06dce1bd9c30dd08efdef3ea304a542616815d36f3aef90a1c07a623efe5107b2232326b4837440b2f987db5374b7b70" },
                { "fa", "5c2be228c2739ea6a3492d4b62f97efd1a02a45b53cf2bab3bbbe62f96002bf63c3cf450e8181b4d81f05a97c55879fc83963027a89e0ea48e57f8a4d67a8efa" },
                { "ff", "0f0160b709273137790bdcfed22bca1cb2812f20f8542704a35f72512c81d1b4c6b5b68e6c395be37703a82ecb0edace62a636a0cadd3c99c9faa546fa91b2cb" },
                { "fi", "e9ebec89868ff1850c69d147a1262dfe3f32b37088942260be142bfe6d85d20f16c6b4216be3f51d48749f442f8267f0dd24836f52de01d2d5c3501ff33782c1" },
                { "fr", "53de7ca1e6646576083c07c8d71a59d13a1c26b1ae00650f50566cf6668fe8a6c5004471e7b60d532741d8c11a18969e879e18bd6620f01eece78c2127f2c669" },
                { "fy-NL", "78985dc8fc7b47ca9df2bbdc6c8e4693dd0a13df113c6da2c50494b7c4f42f0304f6ff7a4de46074599e43de4ac817a1676f793d8449c9760b9cc3415ec709f0" },
                { "ga-IE", "de5f30291dbd6ae80a011ee5bfc8456b3e5f4496cc90b9a10bbc2f73d4917677c33ade8ddee2de28894bff53f8d7476ae4258a50f3185541312298f769a1aa7e" },
                { "gd", "d4db71d7d198cc5540c3deb90d8282493f3736f5c52795dfcdf4912973603e1ba5211267d90830949394eaa8f69d78c6d7d49dac501ea995bd7b68e97a280769" },
                { "gl", "828525faebfcd99fd00de74560f668186d4c93b170c084c0889a9d7b8dab56c814827a55151f3d770fe1d89580443d4b39b76829749e6d15980b2f8eb897adf3" },
                { "gn", "02191b99edce8bf000811e936ce98b7c6483ac3da5ea553bc7d3afb7815058555475de70c3ed167245e18cca293f5d43bc58600e3b967916a5ec4af66ec0bcf5" },
                { "gu-IN", "fef6f34b7dc4674f92482e7cba4dc469a5a920d0d52b246f36dc7102c54210edfb80b68f42ef89ccac22a6198a4e19c4e3381d87b618d0854d31d568bb73158b" },
                { "he", "fc2ba1c9b75d0ead2401ac7295de4e31f728851ff2801dcf066fd6f6e9371725142bdb5ef1d617f9a5e739d130d2c69bb48108d7a2cc1ec2ccb75e6c2ade7b45" },
                { "hi-IN", "a22545d29594c5a5a43e0c863aa85c7ae120b8bb85d3608a6bb092012f75fecc3363c3b4339875763cfb9a3887b085f0b6fae1d7876fe3a85ada1238121b81a6" },
                { "hr", "e1da71109c9430b716f9b23bffd3b5bbc9623707e295e06d8c77e783dbcd03b1ff81cbf84ac9c90fd1aface85e95ecb3561d9ab972965120b659fc88633783e9" },
                { "hsb", "81151f53e47455f6e0923d759b2e3c0db45317eba1155848b1b731ac9216d8dbff8531df9f160bb4d28209330f7d1c1d01cc179d724d25d8b97955be66e95571" },
                { "hu", "e8b0b1ecbf4b2c3eca7baf8957a0791acbca8da25ad10bb008a6deac79871994ffa8ae45609cbbb3af0395228de4cdaa5afd14ae67a46fd1dbdfdfb6e45da078" },
                { "hy-AM", "d2f7869aaa2157d9bdb0c8726e54afb0193ddb0df962144554dfa8b84d1ea756625037f06b5f1478912f845ca3516ec3ec99b73634d6866b8425d839145e6189" },
                { "ia", "d61fd92d90dccfed159ebe0ecf43c618bae631b6cdb8f9134d7eb545e7557b94f715ffc21c002f8301172749e34c231bc76f497f57484c53490270d52978f98c" },
                { "id", "53f1158e0e7458ddb0258986299d8713f41ad6b88726bce22baab59f5efa2231f0c03c1686ebda14b72ab73fce953c7cbeeb14b5ad7fe8146d87bf22b186523a" },
                { "is", "0f03ffec5bdd045d55c2519e004df465975b72dc7cd400f070b43757cfa53903288bce439bab81de96831d02f43b62531d35c68eab7dff78cad5ff8ee5242f46" },
                { "it", "3bff67d28c087b8b5c0c93cfb40c8a9be923435a33b67965ed958b5c0ce62862b5dba1461dd49d16665c543aaa2d9457e0bc599139e1443f8fd1c0969074c6f7" },
                { "ja", "619fb8c096d667f07f248e74785fd4639458c2af9505b8a0a359bfc45dd8f2a71e2ed46686e0ce0d964cde22401447dfaa22384e7bf25c800927f75a6f636421" },
                { "ka", "d225a1d9970d934911bbeb6febaeef1f1b6c1c49c2e0738e7f05bda619b4e0c49e12298cf383e705f5bbd4969fb0cbf3dd9d365af803e4746b182310a1d51027" },
                { "kab", "47dbb9593735ce9c4272c54b39aef6f708d9fb575bad7a8bd43a284be2a040fd3e06c201ac04fd637a73a92a9b18618ae982ee2c409b01fe5dee0f4461d0bbdf" },
                { "kk", "35cc0ee38c00de6206673be8929efaeb7ba7aa662d1a1b36d73edf7f7f42acb65d31874133741552c3959cddde895fb412b4e89e867c0711d50aa26552bf7399" },
                { "km", "5fd7e0b22b5df213a37d1cbd9aef3b188d402aa158a7bc453d8e3a58ea2e8c437b5c726e665642bc8f5657cedfd6f0f70a4e2dd36399e94b8bdc2c1b6bcfc9b4" },
                { "kn", "8c5f691c3ac30f2b0915937512d25a038acfb4b29a1e12e76fdac64398dc060756814a07cbb32610251c5a08babeaeff94e7cc2157631c0d83e39abf24ab2470" },
                { "ko", "015b1b1f0c55d5ab3ebbddb83c6ac69d78f7c3f47281701984efd2e95b6c004f9d5f931c4f0ad34cffe36fb6d4a80d18d7b77c73bb9e534ef3e8808e6a4b163c" },
                { "lij", "35a381dbe848137cf34fb3aed2368f57df523b2192453bd0ad47d3b208e4cad18dd8f057e1cf84d2da5fd2ed4a0e67fc8612eb30a94a890a0d150d9d62595e85" },
                { "lt", "8ae604bf96f9493a742af37c836ed969d4fa71c13f4898d961bb2ec6dfa93a4acabb2b31754c7407b4bd71356156235b74f4bbd70da35d07007b1a9baf23f77b" },
                { "lv", "b2460c3377afb690d5bab6b9b65c0de767538d69faea67d4ba76ceb64fa70b017c510296a3e41f6e1ce0247d3048922a23ce93f6a3fd8e8fb7957e5a64b656dd" },
                { "mk", "6bd7bc82f16ffa5c18206fdc25f0522316be1078beda7b338aaba24d1fd157cfdc70a0c543895be1164ded4767761c02c917e21535e0941c2ae1c93551ee7847" },
                { "mr", "3feee4afb828275040a69eb75eacfcab1849db30bb0a2348c3645a6c8cd779d80073aeb21afc966c2c0f9093a439f4a2f94b33e4b106c50c3f4aa48b5519a662" },
                { "ms", "e75aa394c82468767eb94f62c9cbe9f6a2734c9f585ef8654f40b6e273a8187f813d0a5f18265a529a548a702a31d42676e04bf15bee7a59ec9e1cf1a2d0d4c7" },
                { "my", "ff791e9bcfd0c2e026e8a511152a756c55bf46f621e6ae483ed30e2d4c6444e2c2af78981f60341c9074c87eb261fea16fbe89621dc64f7cf7974a205cea5ac8" },
                { "nb-NO", "fb5c09684f4acadc1b33c992180307d7332457979e3a8fb0b422d9f0e3ec56998494117f891a11bc15c0190c042e22f4b389c3d8dfa9d331de9261e929f9daf3" },
                { "ne-NP", "4488cef23cb9dbfa6b3b37f8eab96fba226a56729ddd70e711755c94e07a49e40b04a2703282fe6f05a9184fdf0f02503ab9192ae48f22e94ff71124fe5743f1" },
                { "nl", "6414b51390ba435398ceb243fadb4727c96c5ba95275b00012e5657a5952f0ae2c5d62b995d015b2eea0e885a6090a8a195cd4827b1c355161a35657ac6fcc04" },
                { "nn-NO", "a96dc1494cd4503731acfeca447f1262e59cf8e0c64e9f52a7efd6fb45a094d4ac6ea58d18e781596a28bd51149de2dbf78551ced4883fa329195aa33bc77bd3" },
                { "oc", "219ad2a2e705d3774b61cdabdd7886baf70255db8c08b04f68a02fbe8c5e6aedf1fe4d1e8f1a44af6b9e500b9ba51a8230266e92b882bb3996a9bbfdbcf0d757" },
                { "pa-IN", "93a10f2c85329103ee37cbc7015e36f82f2dbc37e54978876bc666fbdb2571ce52906b730244b0cfb89824fa7efb5e1e3a13aa3e4da3a4dfdfd7399fb0894914" },
                { "pl", "07a9fd88565fb68649ea4955cf89601152409ca321cd140aeb3d9a9afd6ed135c14cd184d9dff1ffd78dd9621649f4fba2482de334fef65f6db9a46d69188d8a" },
                { "pt-BR", "f315f5a5f7fcfe29a5f1e50d1b7f58e3833713c231f1e395724a321cc67d90e36f7e8de9617fd915705316a31bb6ac85119cba88a00c444e5976866734558ac6" },
                { "pt-PT", "01eacdbec1a536263487e2636968e98858df2363e35dd7e109a371474da432af63a5c017e00c87941700aa7c39af503e193caadddf0e136707f5e0828a9272b8" },
                { "rm", "4759d9a8b98e7b04e2cc6ce63cb23e47c4eed9c3fd36a38a4f0e3c52e4b7ea49dcc88604870bc1397d65e954d6f695f37299f595be3adda12c302a96266879e2" },
                { "ro", "a1268cbd1ad5810fc816a7c38d763611e523f0c7a20e631005990342c4741207d1bec17d183461416b5ae41790181eeee8ac7b2cd6c4df4be97ec8a1da4e1f87" },
                { "ru", "ebdfae1017415c0e7598bc3130cffce609c06d2887e576add2b48e96ad518a2be8582345238f1df8486f2586de0306e0ec54bb9ba4fee8b8e7b629ee393c5a0d" },
                { "sco", "2eb605cdb76b24b764b08702ad1288ad4a175a7f916a2c491816a1c8e63d3c3bfd4c672f5018eccaa5e95c485f16c1790b209a1401de2bd6da95b11993fc410e" },
                { "si", "3e6524fbb54a7cdcc3121d4fe52d07e7dc0e0026610254c704a1b334c0142ad96028a01fd9ed6ec3f29f369d19afcd45fad2f17ae1831aaf98581708ffc363b1" },
                { "sk", "20969cc64fa54dca432c3b074990c30ea76c2e2f7dfafe7ecfd18011453701d476c5b85e58422c93bff29b8c8e0b95bc2837f5e60caf722856918032ee073caa" },
                { "sl", "952fade524058dcc38c7d6d0e5ecc047d94d92c0c021f70350235706d995dfa77bcdc4cb1cb42779b5d04fccf55593e45fe74508b871a8332ca3972920a93ccb" },
                { "son", "5fabac032b270554e11d099b0b84f949dd9a158525d1efce35e0838b8b63c7107e6deb1cb6dd958a921e6d853b0d80187e592bf629cad508cadd4951aad2312c" },
                { "sq", "84413b827412e574055d9ff8ea6471430268aa78e0fffbb8387e63ba19883f63871573ba903c7ecf42cff595193b7433ec154c2675186f3fceae0447c52bc183" },
                { "sr", "a10b78d8eefb00c84bdec0d0dcdd57872a7b8667533bb48034af3d753db2e7af010944fe8b579940e2e79f0b5e59a18fae3c796873ace27f5c97f1b4bee99545" },
                { "sv-SE", "facaeaf46c0a0d3ceb7e8e69b937163762c7a46f5ca36581f933bed82fdc121f685a17657517a19f961b95bffe5c40e41d7b224256ff5ace7da60086f65b664f" },
                { "szl", "a83d004cbea9de7da2203689cbfda34c5be91ddebf9c0dfd84af3a6f933132a52452e56af3a14ed3c834af1027fe739bda9e3acad3b2d35b8b092aeae952b5d6" },
                { "ta", "73b4783215d87b5419ee3b92b7acc40f1fa202d0d0a6760f5f7ff67d22ac63a062a5a966246f0ff8c807aaa247bea911de7e8a87d0c481e19211efe7a64be07e" },
                { "te", "97e602fe0a3de0e6d4bc5852ed5dac2124c93feb379873b0afa2aa69cc7b1882c7d3ca2364cf5f1e3e65310fd93c0f247c081cf820aa86ad4cdc7faa7edcb9cd" },
                { "th", "83e1f11a12474356e300a7c83f6513951d329cd75336f7cd2c30f5300366fabc79a490109066685a12ce54e0b4c56c18504317839feb5dc04d7d94b1109f5a0d" },
                { "tl", "138d88e4fe2e0d724431ae13f7f558471797602ae6e7b616f2adb774b6635ad9b93e682ed699944144150195d82e19af0133d44329f0a130d22b48a0177442f2" },
                { "tr", "54f1b44112d09d4dedd2d5e6028e44f2270345e6b482eac3b42241d32d6673c367742115ad42147c3bc86dd1a61668d965e5439b891e1202039f217d3d2ce6ff" },
                { "trs", "5117698ba2417be3ba3946769922b7f85b72735878689f26445d2afce8bf5d2488f7b39ba21d509a49f6a43222f2b597a2ddf4cd825a873c8e486ada366b7b6a" },
                { "uk", "57b6b56e9700bffc182ef82ec7b1532338c8f8d8b9c28991a590508f89b5f877f7604f487f50ea8a326ee9fcdb291d1d46819933be9c39843fbc0008c7f6d599" },
                { "ur", "b18b650f40a8e783358eb6af7d313bda8f27a3474a36cc43c5f03c70f2f06ec45b1da3f47bc89668717c3b84dc77f452facfa33e78258b1b4fd7c6019f969209" },
                { "uz", "dbb413e8d8b13a2896f9d30453f448ace79eaf8f8b855991bb7175bce48a444b6009849ead406f271f97f538ea57ee019ccab7e894f3781a8192b709a3d1c934" },
                { "vi", "76b87e77b992abd64ac62e0e9355431bce680fc74a56029ac3e72bd5af72fcf6fc6a32d271db5168982090b6d8d7986738f396bcb5e66d58ea50c063382d7f85" },
                { "xh", "3ac24587e04915599270f8faeaa3ecf575a088cab65e3a05b0c0d9e4243ebaa584209c3cbbff8590543f72602c74dfae7819b3a09940c0b78fd75d54013eb799" },
                { "zh-CN", "47cc5cb7bde04d48c9dc0d333e568be6adab916d9143b58e6bee11c8b19477ab5ffa9f5e2602476d1a7006cdee5ab33d92f24a82ec2a41e19e4a069513d334f3" },
                { "zh-TW", "12f94d4b2674d5171fed0cdf6808c54d021f6427c0b6226775bdd3610ef83771352d33836ec1fe68a959bd354d5011c2d5bb472f29ccef529251cb4159b03ef2" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "e82e6b7b62601deb8fa47feaae111bced6bae1eea4dce0f2b202e4cb0b535c941636561f9b810ae84a436148f1a2f3f14de00dbe17a2a1a966b0c5b9384e5f82" },
                { "af", "5ea88517e5c8473ec1aff9f246d7a89a1ace050ce83c237323a7a7495c1be6bbf567ede25b5c53053d6ec488c38b00bd466b9c0d3d61d7346c1540dc34ae6693" },
                { "an", "a5cd67ad00e38b0cc6e1db080874409671e9cd7cef63854398bf99d8cc4cd822e8cddc85cf36022f310d85a5c9c1b14666ef7911278cef0c78de20772df8e76a" },
                { "ar", "810cba11bf2290f423c7c1e5bdb1d42a7d000ed10629ab425680ac028a686b19d155296551a89864bae0046a98d077919fe32390adea82c79c88d2974288ccd5" },
                { "ast", "5ecf85e779d947a43909f66d34cf568b087774e334c3d5597c9077c30722bc3f4a2e0a31b0f042dddd50c756dc07cc47e5fd5e602cc6f7981b0bde3e4d192a5a" },
                { "az", "43d0b51eb9ca7486554247cef3dc94fca625cccff8c88947d7c268dc4a617a2608806099878bf44d256402aacc02b4b7825ed2005a82464d6b6ecd09ffe6e9b8" },
                { "be", "e159ee58759839d937bbe24aed49a06a5cfc603a6d8ad1760aeb8ba70e3663b2500fc0b9dd91db9d8296885ba5e39c2359dac3272f94a76c1ce63489d6c2552a" },
                { "bg", "3c28783a93c2089bc8407a4437c690c5cfa50bede3191c646b384dab4700b15aaa22e9d2711812cc277a65beda2be1f44a310ca4a37e216fe0611077896b65a2" },
                { "bn", "c7a20740c8deed05906f96bb3a5a05f5e95bed8c37b4ceade75d3af62c266c0635798e04b8d4082e2e2f4080e32d889dc5da7c3c68e39f903c69ad1c5ca92d42" },
                { "br", "64a80d62bd2ac45a08aa55db3c5d0f48205578ff7b5604e4c7cdee4cc8dde9bfb309240c0c8167a4d1def1ea5d0039cde47308dfca32c4d224f085ac801aa86e" },
                { "bs", "0ede4b69eb77c9808aa5ef6ca4436753afe095aede48504c639203b21934a8022c32557ff3b3770bc6a5cf2f0dfd66273cb50ff2ed05c85026984e0b4e944985" },
                { "ca", "4a8515f181db459999602f758d4a4c72af182ef1ebc20bbf9d441e7dee7fd92cd970cdcc8984b6e650ddfc3fdb8deb3afcb5ba77e8c37cd65561b485e88b4ee6" },
                { "cak", "90a94788b4ef83c126d2f5a7e426868052ca3ed10340f15513ee72e576538a5d16913a8a0c753ee66d7b52a9f838673808363d0191e1c56231c2145c57e01a20" },
                { "cs", "e4173022dd50f9f48ee8134d866ab87b7200ee1df64866afc2628820f33a20ce4f06ebd5e1c0c2b1d601b3b4ec64da450afb2317c51116aeb954f79888f8e340" },
                { "cy", "6cce22efbc5fd32d65767d1453e751b2c1040821511beee0abea6ad022e01384ff2b301796e0a76c17c86368b5e10cc962c39b75c6f6698fcb39b7dc4e250aa7" },
                { "da", "3542e675217502d06c73cbb07797b0c8fa04d7ee3f158dbf011332b67c35ef8ff4f3346d0e698396f773291ecbc2c361e30b587d2162e9848fd945c478164edb" },
                { "de", "d4d7ab67f66392d14911ed9e193de08c44e1547a730d2063d6c1084eb8c6360bd13672fba06609694db4f411a75e714fc87b915c309726f87aa580bc735e476f" },
                { "dsb", "004ca317bef1fcb2bdd7e13c23b42c939c35e7c554a623bd60c39d74223efb62a70b9d9213e5cc0f30983d09b69e7bcecb405359d754f36fb44f92a02f550876" },
                { "el", "71f8b2e073d6e518bc57a18339e98e8897ed9aaabd96605e701dc11bbaa76b725c6561e9d94bd2d035c4cf80405807889fc291a702b2c6f86518d7d5f0449dec" },
                { "en-CA", "f25d4cdeae6a5c787eaa24ed0e42530968388cdf8849bc36fcc6977a73756d0a0036d1de1b078363310b9724a5d9de06d955805835da6c105b232ea6ba527ae3" },
                { "en-GB", "e659e7961a8e8c616819000e9a16ef3f22d24a0d1763fd85dae8f02fadf683aa3dd5deb3c42e11760b8ae15da8b3e9c6253de54bc61d18e967ca1aa9e4efa0b8" },
                { "en-US", "8b8f5798808491f91a8b77bf7fe8b8ec36989214c69b2810c0ea0b2b42c80525eb9d0a21b16b830b5bdba943145432d6d8ab6d7c4143cb836aeb51499bb7d34a" },
                { "eo", "c786617d404caf2f1b7dc974aff87e44353273ebe8f08d3edecfcfe6f8c567a92c0930a916ffa134721cfe33ddeddf1fcd3ae0240e5babe21ddd616b3cd10e4a" },
                { "es-AR", "9f0e62ccfbeaa52a93727be65150871129c4a79113131e3b86b5cda0ca87c5ecd074238581a1a36e6ba2934006960ae49ba7880a0bfd4ab7b0571df03b5814fa" },
                { "es-CL", "2d8e8dc4406c2fa81199fd0c3b84db534c8cb3d029596c1f4ebac0df3d2e8f43f0e3a91a2a16e2ebaeb998c6f5655016d0ff7c14d6771ce804bb1973ed5e395d" },
                { "es-ES", "2ebdc5c64cc9b5eb78ca87cd839277d5d1197ddf7b58c46618b82be7af1890a5881eebaa07eca1483801a88b6448c9e74915579d4164e8a514196861281d2c79" },
                { "es-MX", "e23813fc3caa818999e3686a80a989971985688fb7f83403ed3026a001e9e91c35fbb9fc513ccb89c718237a44fdb99ec32c762f756c16705755a0cb13be6f29" },
                { "et", "bf395c34b5ef36779a843cf0d7dc35d35408cebd8c3ea3872b400a411f49b9bcad56306d292a5a350dc3c5961b411ff87f6b2a587f635eb1bb101b549dd5cae5" },
                { "eu", "fff596aa29df39e731e69917f2f009d794d093524aec6e35929ffbe4f7da429623afaeb198637528a4c03d5d0a0966eae0fb8274b961eba978b1a3d6d97260b8" },
                { "fa", "99a7705c8f5ef9a20fc15e78279bed1f9938983d2d6ba255a0ddf4a60072c250cb387d99c5f9b50dcaa1a094a36bc1a50d254476b9738b3c062c146aa7fc4fc1" },
                { "ff", "740884973bcb35f626933630d17f6473e54b9c3d4e914656bfff0de9cede60af038bb2dc182443918d450708fddb8856929ac3aba38f5af97a7c63e4225f5fdd" },
                { "fi", "7c509cf41e386f2a4085e4250b25eb5c321aa601d83f6c402aa7892319e69e3228a58261edf1a4867d8ba60af7bd480c6b6cda133cb0e5b6c0b27f0f575ceace" },
                { "fr", "43fe253fd3400889ea664f5619e23672d23c18f273a05bb6e526139b1fce96fe5448b8d3f2b900f566d1243c646c0d6b4481057fa7710f67aefe9795550a49ac" },
                { "fy-NL", "0050f86f4f337882ed30b76cc1852cb81ff2019d32787a17042a37f2830ca00d943d9e8557ec5c491e0ab8a8fc709a420e1f218430a2b9702493a5dc2447c294" },
                { "ga-IE", "0e3c1d41778015433b6ad19ddb49aa7690897db3d3f1564e25fb4c3276eaa6d4b305603b6a540fc3adf3caf46ae8ea3243e07de46c0d258b356854d6cbc0596d" },
                { "gd", "c70d0db8322a5610bc8f59ecf1856ee4eb8faccb3709b3f793b81b8e77d30795b9877bf47e1192afee71f5606a4e3c5f2c59f481db419fe42bb29b74aa6a4fd9" },
                { "gl", "c02f3761abae7a4f9ccaf5d4265bc6db6ac31c6346be0e1f66bbbb69d1c85e43628741ccb95b44c76cf39e95760ae7b41b787e68e6af2edf3c87648af61e2882" },
                { "gn", "af79d7e315c8d124e504a62ce74125ba7602a968290b91e9679ef7446797375e503360a830352bfbb23e6f5a2fb9408d670b369bbaa712ac40c2dfcf5a261b93" },
                { "gu-IN", "cf9f91093174f747f176afb49bcce21f3d09179233e3ffba763a61ad0e5ed1015e09e150c5742d74b1ce74f7c7c4d4600fbda694622c3218114d804ee197ec8a" },
                { "he", "8f9a2f14a0a7410cceec454d3d9b0405263e675deec80b4a7cc9593fb3c757e8105de387a8f6657b424af3d8d48a6d1e368445d7c30150eef241d2077be28af9" },
                { "hi-IN", "fe99519413287bcc30a8ad229e56d022422c302b6367913038c12f526cabefc53417c5931e479f22077cb54449b7aa633089530e7a6cec780773a6ac71b5af3f" },
                { "hr", "512e5f781b320fb30642e2d1617d5a40dccadee0c331caaeed41c152872bfcb06ccd2d6106b299575e5887c29e59306a70c0cd4018517ae150315c0ec1132e0e" },
                { "hsb", "9fec34061b397d1e2fa684b24074812c5ca614e5609e882b586ca105eec90d49d1ec66f6c98b7bd26ebe04830a2cc4d32df23351a2090953955c5f18f5c041be" },
                { "hu", "bfd9b0fa5474ee0a8f14bd909b004ee8d795f4248d86be2c8d6b4c38458b07159aa7d90a49eaf20624403d41cdcd8d2070ebdb52772a12d47db0e663c0d9ce14" },
                { "hy-AM", "d512cb56eaa0fd3abdb23ac72e1431ba90f3b1934f5f2bae5181ee08993b8628fd6aafb9c0f268b6f365915fdf21ef3347ab729a326fb1fdf9bd7341ebf48b50" },
                { "ia", "8ee8094f9a966caf9479b2f2a96825f0f50599daf893582cd75213457481d64506a98a687692f33a27ba2931b6387e67d2b9399a549ae3edfda4b3b36f4f96ff" },
                { "id", "950072f5f907ea169f80dbf9378714419b553aaf0abc90b34a8b5829a0d14efd4bc417f3875175a152ff8b88dcf08a6f62ef85a162a6bdc2c7d42103b496d09b" },
                { "is", "af52f284bdb0f1e1de8d9538881b29d06b8b76f4b99d1f62caebaf4a0326c1c40cee3121673b8f0b36936cd27965fe72d8c23c6236f0cbaf03fe37624a450cfe" },
                { "it", "85618d86067470580e2d46c15d5979f25666dc6f43cc1efbd58b9f35cdf4638046f3e4fdacabc0ccda6c1f61b2ae57c8d62241223460d9aaa37b7d0a8a0f67d2" },
                { "ja", "9afa3990cfd1cce15210832558a7589ccfc880a905ed0b9e3a54735b6e1983bbb5f3db58981d970b9c2fc70263b3c6e15a124057ab5f62a041ee567e1c75c605" },
                { "ka", "555654cb6dbdb86b3770db55ceddd0a1555e84bc9a0f741f555ccea225f3607469066012a7e72f10e9cf3c5feb4d69ea34308e8fab695cbed7eb70f99cf65249" },
                { "kab", "3fbf2f0b63d51dcc29317cba74984c7821f028b4fe547678ef3b2376f0f00f0dc18f868a198e06ed06ed2c1d7be2ba2e0d596834adf95c23a314ebb60a492c23" },
                { "kk", "2cd60bc6743e5132192d13225900d9bd19ed8b0bd0fbbb8401cdae8b5b9ef95f4f5bf4ec27dd8bf1fa9b98d12fba71c443c8741aa204e1bbcd135829ecaf4b7d" },
                { "km", "ded8c381e45e67ae98280402ce8893757135cd613412f062b56a8d5932baefed0cce585655b0010a665f284c7d2d0c7b5aadd02c5513f037d0cc84b9ef21e0de" },
                { "kn", "20a2fdf8c0f2829391c38f76d195aa9dc1f13eaac6e630a489589534aafef0dd012e5ddcfee6619c42c3d5b3f8123d655d2700a4bfc22e49af77d7e71cb7d2ed" },
                { "ko", "5899c2ad59f541ecbdaecded6dba660733751d83a254fcc4dc93593238ec40efe6f1b61581286b33d2b8a0a4f7f0a48dd94fff7869655f11b9d0a9021ec555aa" },
                { "lij", "2fe569a2981ca0c77c2c9265953a57a0877467a951f8f4068b86e1d6773f35bb6a538f20b24be5d5c6dcca88debb4d750a9c85c652d8a6d1ca7a817d4bb4e534" },
                { "lt", "9661eec7acfdd745ab1579e83d862f40d06efc75bc0fee7203bca065ccdd78655b09916757301ed22f472417849918b4a2ac230370b8db0b76fdfc4a8f5337cc" },
                { "lv", "2e4e40a83e14d6b55980b39d1b0bb4976c999340016632aaad51cf886742acab0054fe551ca239afd6e61a306e4aa250e0edfcf698f57f94dac503f32435c9ad" },
                { "mk", "19ac34d9fbb9a74e79306b9f33001f76dbc66d34a7fce80ec4598ccc54c1af057922a70ce727fcf13b46ca8868327a735262681162307fadac913bfd8939b0a6" },
                { "mr", "afe109222ff8b9b47844b62a1350e586292051c0f17b80eff9ca0ae6638e31bfcdc2f6692444ef5a6ce2c8503bc5929b37755863a9de3bd175b58a05b8c1541f" },
                { "ms", "321d3dfd291ffa489dd64166feab549c714c52b99d4d39e29b056d9ea43cd3eb520d80177939ea938065f681d5b70e317a1248ffe36819f412a00339c9318abb" },
                { "my", "4a972bb416d482dd224e961bf8a1dc5e0f2837ebaa67b751ea0323b5cfc47d54ce8f5c01bad69d5ed26c7e7c5817b4e528db5118459987f2160cb0cc6856ef55" },
                { "nb-NO", "806096c3cf38d39473dc5d304aa454e62393129f815aab0934667307c97841bfc309a14b0c5c162a7805769143d560195e2dc3fc4f9e875cb0fab766e0bbc6b8" },
                { "ne-NP", "d5736d867fe9c5d61c1a6e2b84e05957a4bbf91794447a75581c8073e7aa9d5eb5a48cb53918f08786fdb11adc07fcf096789737220a0d984666c30ffe390c9e" },
                { "nl", "1ac898fb052cdd96083881540d6246764532bbed1bf7dadce7e17937f1cbf31887914b1aa4c2b93935b37052b5de93dbbc037fc059142cff7ae9df273e0ca6f3" },
                { "nn-NO", "5ad74f40d427ff8d1999acb2ec3ba61d836240c2928ed19bd9f146627c8b6dae3397f3ca038d5b35fc2b226b04a22a5dafc4797cffc97cdb56708b8297207c55" },
                { "oc", "7076c8683de019d0355a47eaf5837e5c34addf2ddedaa67426de8703e14e73ca09608e7b6b3deffee0fb47afc92b310de1a7f39139dfaa90d9afc149f51c81ef" },
                { "pa-IN", "b0a6eda757b5e860bcae621e770c892541cbb39cfc2755794a4ef8b58411a9273c6e008c958804f5177e6754c1f050bd03632c5986cb8596f464ef941cad2a16" },
                { "pl", "c0825a3e315fb34dd355abe7da0d625c093b61171a1d71a55f0a3944d056ee9c50a7b67e77bfeefbedcdd6ad895879ed587c2d0233cce5375c0b96fc05eaa09c" },
                { "pt-BR", "6f4091e1f57992e7ec0acae02ab05596d7da7e0be32043df0780dba5b07364614edb3286b3acbb1b4c9d0f5ffe76e87509b10a6cbb968e9fcc0b85925f7568b7" },
                { "pt-PT", "70881c20fee017e2d5c194449ba86043e26c38c2b1b32acaca356fa3ed7eb64d11f1ac1161fb065c09dbfdf6f93cb82a51f6a4ea83e82410f89390274c477b52" },
                { "rm", "e2939cb4f8822b318f041fb2f0db7d9f5ca987e98bcf8e0b27037042937a50d52ca2f569f0c5c69409c9dd3caeffe7326a36873723e47721b3bf400d9f3ebaac" },
                { "ro", "9c8b5586ad19b2f095602b1c850145ae7cae04cf92319ee9c327764d3eed1faa0888bd6dd66b0bb5f93aa852a7540918d1639ce65a158ab3914d226eb6d3806f" },
                { "ru", "37ea1697bdb91b981e8b6f12650763a8318c402bb52fc53845a908c1413c678658a59993c79324d9d4e1f82c2e073a602bba56c1ccef491dc22ab2b7236cd5d2" },
                { "sco", "2f8e9b455c25e451ba7ea3b944150e6eb179e6638e766172a6dbab76411fa5a247ee35ecf82dfb1c354c831cd1261912fb88c40e2481867e0c61b8f78fdab7da" },
                { "si", "0f79a7f2648b7cad625c78c34ffe8eba7119b34bc93b83d20d60ffa20a25b3be097fb60402f8ff632ddbe6c2d813d99215147b49b1b7c62338fd27bcba20efe6" },
                { "sk", "b2d197f733c62a58493263d398e6289bc45525e164454674984e2f1e34ddb8c2a7971ed9eb9491faae246aa0caf659324eb3db06e550bd93a56844c164203c45" },
                { "sl", "51dd2d2ef429022b7fa3762f5862a7a793b96153b990d7ef4e3c992b341daad5a8f035a2f4884c87a3540248f065d3bad792b6b8127b711979d3500126aa3faf" },
                { "son", "9be7920442ff00749597bcdd435149678122796aa09dde43d22819d468a922a9c03a5bf9916ed8d76d8797ef37f75fd51f7b5a847a03fdeae918e68c3b191065" },
                { "sq", "c5b56839aa5e2f35f84cf08d66c6cc2c68e549e4ec27be34ef3a5e923db85d423c5339be986eb2f90827787c270baa1fa9b22d912d21df895e4cf7f251c707e1" },
                { "sr", "0110a4a7f88a05685df151a71ac03b62f6063e903db393f9a8ff24762e8d6b16899cd266d8fd07dc1df0348bf0d3481bd309c33923faf1a493327e0eb3f249cb" },
                { "sv-SE", "86f9f92311c52a3d05c828b84be58fe8e28a4ac445fb947f593baf45c0d7dd577109a2d69945db22e383a583c2eedbc39a1e1b41473073d1be18be86e875c672" },
                { "szl", "5cfd216c7d9c18c03b7c89c8ed38a6be42d783ce7926effce4c23c0dc1a4a66a2844aff6608ed9114f4f6a264a6002b70647a218e0f7a518fa8bf734c25aa841" },
                { "ta", "c6449885ad1d9f6cfb30260130cd21aada17eb2d169c277943330d97b8857a0990ced044473f37beb5c883d41df92d997e885e145c89d7ca26989ea7ce92e6c4" },
                { "te", "713a0ebc8b60f94a99f9c0f3b56dd5b5cd16c1a649a85f5fa651cb683e1d3ae481a45e0a503ce6d1067b4830b069a0d0f40925568675772b685c21cff1a1f5b6" },
                { "th", "017dea5adacef80d8c272741d9d102988c17284d90610c3b1f03b071bf766e729a83ac7253c42aae01dbfbc5aa1aa36d9b6a9996b83d90ab06636488e1fa1b05" },
                { "tl", "4976a14d687a0bed18954373d4ec615113974d37faec4c419bf58df890c90513342f65a559430ede71d90b4e4c2cd8421eec7d4140eb858d447c312bd359b864" },
                { "tr", "57e47ba78e6050158ae28905cd927821c05d62507f329e662e4ae2a7249468f6cf4e1b77d3a544ef1d76d198ac285d214632338a588ee42c66f6f6ccc6f779d7" },
                { "trs", "cf0b070059d76c975037f25541ae4826f4a4bc9de8aaf543e3b99329ceef3b1ffcc0764efb73f53f4739ff4029e57b7df3feb1ff95e1c651daf9eff92eaef12d" },
                { "uk", "2ef846aa3564539fa4adee23e95438dbc08febccd49f6672f112aae8b88c955b7c86a55ff0ec41848673c800bd06ce9e8149f2f6033ce074c0425785a2d88854" },
                { "ur", "95d7a92c1220674e85dcfa42966d6589824cdb740505e5bca2d6605fca6e04e578a1ae3e3f729d8d7d9007794bef86611c1dc96e7a8aa62bb1c23b5d86a0a51d" },
                { "uz", "dd15bc1c167c3cedf950b93b9f24ded6737e7ff269c575552048d53e777cb269438b7d8b4a8c08bd67df2bad411a3b46ef91057c819ecf64cf105aab6655e88e" },
                { "vi", "b330f07d366bb24cd8871bab5e49cda30fa778608987e72365b69d6f8cc8ff2e9f424815808b5e81fe80f363125235d5afb3d850db14fce5bfb8d0ab9442c8bc" },
                { "xh", "825826e685bcb7621fe752c666a0b04f8c4c108088b8b263f5c3a3eb446c1767f26c9126ccc228d090fcc1d9c91ce53a90cf92cfbe22beca86fd3ef7806db79d" },
                { "zh-CN", "801753778bde2e40dba767095a8dfbaf0820a88158066a34c0fda045bdc57617639fc9a2ca141e19e81785bd595eb3a23bd393b17dbc7050be5ddc91e51d0337" },
                { "zh-TW", "5811730af26ddbb40b19b498e6fd591ba74ce1112cf72091a9b417137c143614188ac137b1ed2365da8158ad7647fb41e525300e86d631f0678b4352586343e7" }
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
            const string knownVersion = "102.11.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
