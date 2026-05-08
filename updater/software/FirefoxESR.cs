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
        private const string knownVersion = "140.10.2";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.10.2esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0c3bd6c46aa83c808fc49e9e410c78b091a037ae2eea352b7b82f13c22f2c3b2a5792238df9135849f3c74f0906fce8f31e1a0ff893012a887095bd03ddfb571" },
                { "af", "87a35cb7fc8e9dfba5a743a5647b228f461806928c4b21841caacb9506a22b3d37ba894a6b9d1abbab9aa86a346551a79ffff653b1dc9200fb3fbbe91857faa3" },
                { "an", "64f92c95bac85444d06c649a0fa4e0b30c19e2a841d48f00cd6a62f85a6d5079df9f90a6018fd5569a4de406768ab8a7e54bc215c029714ef4bf046950156f30" },
                { "ar", "2ecd99642aa5ee3aebd6eb62de630837e3776d9ad171744fd589d59395e5e4645eebb186495d8ea2cd3d98b773657e20ed0de0b4bf3403fb5388042031e52a45" },
                { "ast", "8d50fbad2e2f65948b66f4c8a038ed2391e9015dae6eae9ad354080bf624d2ebd955d7f514a90aae3e5cd1513b76ddcc50144bddc1f68f594f849dacf92bac70" },
                { "az", "50d29aa819b78867c32d607fdc5ce675efa7786f30675c3b49f59fe7763e92f5f7aa38397a3fa55f035f41fd8c83f91b27fe50fbc24309c4660e147a88fcc584" },
                { "be", "247e98c48b187d9419a7f95d354275f677282820d93830066b1d44dfef89f0d9421e8a212e8a732b7be20e09bc8486ceb9a52fa3343122610a306ea85d4a510b" },
                { "bg", "de37e3806691d47f87fb5677bd76aa0884b4849b1fa7c3dcddd1c6844335ededbe4e215afeeed6feea8321ca86c2a5e33b3477127fd9d47effd8e21f1c579203" },
                { "bn", "38bbbe2227b5e18693182e3588e31233e72835d7fb42b9fac321de48dc9899f0cdf5e39cd6b53c67ac84bc23b878aa1ad00765ff04bdd22fb7aee63803ec6d7d" },
                { "br", "3d6d4a1d2bec03576aa1faabeb98b94b641bb7cc67eacac41dcdf9119a57cb2dcc529b6bb6d76a7da493a32c286ca71e3ceae0d908849dcb099c5e0eb315193d" },
                { "bs", "3bb74f8414e8a596199afa4cbb97839445eaba4caef0cf8f6e9e96558aef693b382810b7968e303ee09c8f1dd1c4b3df2888223c341dcd1c8edc25306017116b" },
                { "ca", "831bb87d07a3db1c2206c1f7688001c6f418a107ed1840e3a240e3ff6a23d4a7173a8eb4a92555397f3c13a63a7b68a452a3a338bcd725b00743604d7fe66471" },
                { "cak", "21f4b36afb0f654e9fc27a8bf93033c0a2e9f62673dbd51abbc71da37dcbdb747a520b38395e364ac647e63449b40e95e9442fe951fdd736569bc5c4d92b1ca1" },
                { "cs", "73791b3140d5edc3b9299f0f04e329758950b4f2fb669c68bb2a807b900dd70a44b56989b2aad4ffa53c4a91692bb4b911ee462260370ffdd1cfe66b9b8d8e13" },
                { "cy", "4b93769df8e1d111dfc14adbbc5c6074393334b9c8f10abce11e75a68f2f7d39050bb24959ef9c069f91b002cf6e0635e84dbe9f40dba20b00bd676e91a8fd84" },
                { "da", "19bc3b27d62b14188e52451dc17253f2ad4aa97b70ec0a09e13611da9cfc536c21294e063d2dacf13f3d7deedc188ee928d1633f8934251ad0155aa43a334674" },
                { "de", "f99cb2cc1ac64f9c998a3d174fe30fbdb5c5e6449049132f082fdeae991472a35cbd850817bb82ad57d86acdf51c27dbda99c4ea58e731b74913fc0520d0122f" },
                { "dsb", "e08b7b663daec920fa1610e437f7638782e03d4a675efa8f92dcc1070e745b222429326505e7dac570add55f6c431f726ecf124bb65ae0b12f8b4d4cd5e44291" },
                { "el", "9b58932d63bd45369a36cbf6166a40d0aa81d5c7ba693a30919f01e72f24bfaeac32b80059bb53e095bcdcf06b7dbff6febc827318b527ee6c46cfd93c9515de" },
                { "en-CA", "77aab6efd45824de7ac80280b52c0814749d875ccb5484e48b7d1558955328159fcfa6207dc430edb24775997802d7883cc08daf6cc7e2f3e1af07cea2882ea9" },
                { "en-GB", "7d4c42961d58e02dd5620cbe96013cfc0232cd72a98a7d2b4898dcdf7c0e53cf7efa2360cc234e0ce3dbb22fa83ae9fcb1fa929d158e03032e1cbcba9bb65ee3" },
                { "en-US", "d41c7bd9b2a22016df15a2e6d24e07f2635a9022837a159ddc7208be61947bbf198e26663b123dc371d80d240a76a9a643dc7fcc8d40cfd4d3ea6529bd2d6739" },
                { "eo", "409182d29d8f20da7086b8540beb631ef968d80385407c0b80cabddcc5bde8bdd135543e16009ae1e196a8c295cb3972c3831576cf6689923657ce00d9b7db40" },
                { "es-AR", "80c6da7d760f9bd7f389af40488c4b00271254b0f22a83d93247b78845a0fc76e209673339942a5d40d2eb27997b72281d57734638c8c05e86f41892cf8d885e" },
                { "es-CL", "4baa0107dac230b9a70583c6e2644064efb86625981d5428a61cba4eab1af8515a59ec4a640fed3fdb4f26ba543591bd17bdd3da52870fa22f32e41d83d272bf" },
                { "es-ES", "b812f84a3729110a14b626b1d2e3dd91fec0b8ab8afb75220f40dd355ff16eeceee382ef71814bc77178a174a198b27e43d196c7e884df5db1dafb0408d2742e" },
                { "es-MX", "86b10b24721e33a3ecd313684ff47af2ad307560d033ad2360272be237b8522fe53afb8eee87839d247cdd3b412e398034f57a8e12c484fe4b58161fc1f1c5ad" },
                { "et", "60370b1182771f34871afeb9bb5251392ba243a1d8a040eb4d23c618f9d2857bef3d3cb8a417fe7d355b791bb379a626a94192435fe3645222adcb11f376fcd2" },
                { "eu", "9f69a6e593a5a28574e431be5f08a77a966c91b9f55ab12e77d8d1540926380da31757b89d8cb7579da2663ae67b6ccf38c259c5dadf4d12de3eab3aca515a47" },
                { "fa", "f9eab6ebd4ee61ccd3347fc9cef10f45e9e82a03558db8c2ab03455e141adfe156f4a3b375a90cc2411b36b6d0a9302f67a91a92ea586078afc4ae7f03ca0824" },
                { "ff", "329288f0b34db356a44669cd6f3e1508593499abafb0ac7cdf72e87edcf7a954b79e22ec3c3d64327ee73efceb75f8ee2643bbd3bc72636f7141a193223d7ea4" },
                { "fi", "b93cb3190f1afdc75ce8244d2c354d5f95b3fc8d6aff12524955f09cdca918d180667d9416901d374d12be317bbfe9b63b315b4f3dc2cbd8b3704f11f20c4391" },
                { "fr", "92209f99cd282a23bd6fd2b68de900af79a670ccb07f46a668c402bce1012e5c4fd1d39907a8fbb88cb937a14dea71a909209ae5e8cb434e45d3b6338397a5f5" },
                { "fur", "84cc4b331466d70e53468698ace1f134d9cde2e48a2149e16034e1a1c30d91ae06f7f5cc8fcb5847d69bdb22b3275d3c04595d1edf067061ef46806b00aecd6e" },
                { "fy-NL", "a331f69582e7d09f32118a05aa23cb8ecdff79322d89aa068b7eef06142a59b99809dccd8755415910d2737195993a1c482573365e0dfcec96b207d030022b2d" },
                { "ga-IE", "4981cb014008395f26cc707bfab31abd1527909b420cc59b1864bd53eebe51fc2c340a1d8d48932fa74b176835a2a8ce7b3acade2a69e84d8aedf4033c9923a7" },
                { "gd", "7dc42b513df90636716d751f676dbdb883d5fe802dc3809371c81fb6aa1c85bf566b436b24df69844076ba1050d6975e5ba3cc291d5d80a6d62986cbef9177a4" },
                { "gl", "c6d1180fc67fdae06b61c583ef6df49c2d681a60e8b139f4694b4fc769cc4781ba16841af4139711212070ec5d2c117f44fb44df67248799c8544ca461a95789" },
                { "gn", "26765b49386008c06f274db801f9c3d543f4306b32eaf673433e9796eb4826d0fbfba64a279a94cc0a11c3fc4b5b9c972acf8300d6e4ac08721e996e569635cc" },
                { "gu-IN", "332049989d3e971a948e7db33248e4aca977b018ac2908a87016b37481dd6ca5d51627d17374fc5508d09c8b0e6595634409eefa0e22ac5230b0820992fb93b4" },
                { "he", "ac81faa0651a10e3707c97456c5f4000afa9c3581c7ca0de1f521cadc3c4e37bba7ad319cdde32f829256d3cf4b2599199bc05a64ccad67e984a3e434a8a1291" },
                { "hi-IN", "94bd1d8909df64bf6b5a18835432436ab7773f01fc9743418a4d5c551ff1cc3a50ea103cddf13e5d2ae278b6f4ba7f9f5693dd9ab7aa418819017f2085367014" },
                { "hr", "b3b4b40078d1055d4f150fbb6094a72930ce73bb9923b9b0a6d819ce1e2f81687a5935c756980e29dac04d081253a09f6e9ba343bb81eabbca2c7bfe3fb5a9d1" },
                { "hsb", "b1370d2c181ca4c8975126377967fd9e25c67bcfd7bff708c7baf91bde773a06d2fa0e24197d78a56325170a89b2520e00ba9477833f37a366fe77a18048a7ad" },
                { "hu", "44972335e541cda505675b0b222ac3c3fc22532396e7de3f7221382e721bbe1d81f32e1d8ded319bebe30eeef18a8d14ad6ddf7ffef06998db181cba9145ac9f" },
                { "hy-AM", "61c823190ba6c63d8af2702e8a79086e025e3b3d9ede4f6d2ec825ef02708133c2e13f0e119cdb84c576cce1dfde6af84c577be6ab92b2c4ccd6c69e6a5eab15" },
                { "ia", "855c2d9cd67b19eb6a354f448a0694c8b939aa683035be2ff05b8d69c312392ca4fb93cc1fad062bbd146beed93ab0e6941a654dbd45c2b2a8d1b1adc3f64ac1" },
                { "id", "134d0be2a189e9b5b59f54f086981304f787bdfe67249153f9e040f67baf43b2c62a80bdf6c60f23d2c2c7ac8f62fd9db5f11d032a8aa34034af5af2b55d5f67" },
                { "is", "92d193d199d0d194f2d79f236568ea954109d5d9acb0d879d36a36ce882185aa4ff99ebba03b874008345c5dfc557b2128d457cb82cf977d4937b40864199982" },
                { "it", "8660a38ac3fedf77cf46a0f5bf220997b98d2704adf0ca1a92ea912b6fb9aba790169e592f9ed5278267f767d0c91d17d3841eefa6de678902f8698150deb197" },
                { "ja", "73dd69e9bdfd644dd0bb0a68e811fbb5e521476f8b8687d686294847e9466c42753b5c8063752271e66838b6db0a696910938cc3fe32d57d86ed067c785056d4" },
                { "ka", "d32536a3a64aa301e9d36c37bce6ced2f257a627adbe46632e4fcc385e6f28306e409b328ec4769ac9e4da2a49136d830a54c296ea26dd98944e89e0cd80d579" },
                { "kab", "a4b5cd548778e79643333aee5cb2573bf58a6aea12e452c154bfff00bb46d53cbb79b8b3460393b1464e6a1981bd9675fe9b515283356c5a8fcd1c654d5c9335" },
                { "kk", "18bac26b47d8ee6578442d54112daa94fb428f075bc141d7a27e043d8140a5c2a45f85b27564cc6e477ba9e009c9cfa1ff15522a10de76fcff316d3cb72acfe3" },
                { "km", "fab810a821d32e98e941cd528fa3b35d70b3f42340a6da940fee4bffda057916b73aaf44ca82e2400d26d2958cad6c5bfd7b63891f5589da5c00fde596a526c5" },
                { "kn", "04799e38bc11dc45ab48881864a48435033f9de7c14887e89295503adf10fda4773d9a5320b48a394740e0892a2d77f0bb33ce901cb13c5219fb6345f737ec6c" },
                { "ko", "910183cee68a244dd661e0dbde143c60b6c44099597473d2ef374cf60b2fc3313cd12727924da52d69d85bdab69272cd75ad89d7ecb9d4b443bfcef33f4c88e7" },
                { "lij", "47c90c8961434d371d0258cae71cd0e7cab0e80f1b6a5f226678a2b964e13ffc9a8b77f1b4d9e78cc62473637be511f244e1655de26b8dfc750b9ec33c54ea9d" },
                { "lt", "0ae54c84e927041be501bee37b9a5f48f68ceadd55c1fa76eed2faee36095b6bc34debca45221e66646250869866a262dcd08edbd4f7c6736b4b158dbf6c5b2f" },
                { "lv", "b05847cafb318c9c0fb586d5f107a431d5ba325ee0324147c14d0e460d3de09e45b97d17c85fad3fd6ef47503207f2eda1c1b009d4c552e0537bee6e7eabfa16" },
                { "mk", "2710084bd13765788c4a4aa3c28961f120d7e66af82fba9581595b3e550a6547a205ac4fcab132b6d4da3b3ec4af0702d4b23a301d2720998c53c61992f5018b" },
                { "mr", "68201d383322ea2cf49f74645f1e10c09a2d7626a4bf3de869677ca3180bc3f1648b50ffc6376d55ceebcd4085eb7bbd8b84fe1fd33eac0c5f19008ed7b45ef2" },
                { "ms", "973b6bec22124a870422b4a4b6b501a22381650265e38d4b3deb1b36ff494e2d268cfdb529ec8b9e58a5bdffbca73feef8422f59c1e31f000d4a297a41a32adb" },
                { "my", "28c51495a4d00baf2db3a2017597987557105494e2f84ff72f47968085dad4b895133ef21d13cf45f0a17dd508c4f4b6ea91b07a5dd9b9f498eb0a19aee5f615" },
                { "nb-NO", "b2775b87414d3533fd23f409e2d122c7f9c836a674748f13f17d63672b8145e829b20ba3bfa35c51c47bf238a13f9e65f74b29e28329ceed4f9564929c92c67b" },
                { "ne-NP", "400fc9f9f2bc64ab5740e20eacfc0231d1288c624848675a0f57ea967d38a6528c2f4041ae228a35b3356da69c84834878419304ea35b08ba4f37d763e931933" },
                { "nl", "f761fdcb5c98ce5f68a7f2a2e0b404ff6ccd7329e616d148d1c3ca1af0229db0a54955ce04af83023f2a911f20b3b65983c3eb148efb431a9935933672077b7e" },
                { "nn-NO", "c10d8b7326a4a12e153a753f86fc503fbac1f651937a5f24718d94ca44a0af4e1c3aae399e5aab139abc3b507aba4266de1b48eef87c84573c9106be3367f669" },
                { "oc", "6b5b2b22a63d345b712797c13c8d1123110d0a70ec0ede6ae601b9f4b70e9aa5fefa20469b514a93c5b0d0de5795378cea8705eb73dd73c7599f3ee730d29bd9" },
                { "pa-IN", "fb0401859bf59ce0a53702578c3c29d976edc67b7383be57211b99a5202f94caa8d7202b161fd92411c033eb8c3b9776eace602ebcc00858f1edd063c7040a5a" },
                { "pl", "712493e6cf5778562a3a8a65a64bd36b55df23ffbd924a040c7d6959682f96ac3edd9a57779525e4c9eb2276c4a031372f90f3492a6a8a7c007f37d9961ba0c6" },
                { "pt-BR", "701cc2d431b936a0db0cfe0207cb0c5e32aebe8307cf097875305ebd0c6d9da326878fd0f51fa55618be027efb6496e65fd3ce87d8dc0e5d6d60d123b27b74c6" },
                { "pt-PT", "6fcbd13f037a2ee472ac223f6c48ed1c8ead71f137ae56369fbcae0446d04ff1d728494a880adf98b91cd8a89a26e8af53f375d1c92cedf148d62f53c5bb16ce" },
                { "rm", "0bdc1b785f3dcae7749ab6627256cb95b9709d90eb1b424d31d878feb4aa1d75a91b6093ef5eae6837bf8af3cbe44439047579a45ef258526d2bab89a1ff9491" },
                { "ro", "c38e05b176825833430bc9430885eaf9e9c08274dcb7f726c637e4fd335f19337131689fc64db7a0ad83ddb4b195c323e3d849cdec49e6c412926dc889b66395" },
                { "ru", "f5c03ac916013a197add2c6e0285562b7b782f01140590bd9d8bbd080413e7a1a8fe1655680ac6702ba76b8e68dc0a84ab4692203d12f45e55f12140c4dd3fe7" },
                { "sat", "07be029daf439937629ddc36442e5cee478066bb77d892c2a246fdc6f58aeb64c5853a332021539eac10cd1f34a8f48700c4719aa260ba23eeb78c814ed7d4b2" },
                { "sc", "4a0040e2377582f2307091d804d169d48aaf9498852e8172c451e4fed3b193fd6b4db359e68cdd444755cca1a0514a79e10214dd6f73f1584bef9dc9b5ab2a04" },
                { "sco", "71848ed3cf88c494f4df9983cb55c5cabee89e6d7e1e37afb98ca99f61302751f809d5100efad4491a7d78fb7376f5acb689b3af0065abbe5aab17d55b16a918" },
                { "si", "b07b9f3ee2f57624d4803025846e4d10853d8322cd5befa7d56ecf5b6e18ce6dff856e4b9a32d3004e3cdea93a919195e6eb2cd336414bed074f01c7127fa6be" },
                { "sk", "23cfe08e29b78f0a226d70a5431be5b954462e223e0ef672b8a0f80aaf94d5daea4f7546c6fb4cc2e0b37640ba9a8cb10c7dee3661073c0cfe5f433a95f371ba" },
                { "skr", "fbb36fbaa4624b252959db31f9d71ffef8042fa4606e5ef0cf32b75263d2b1e8f8a0dc3da101acf30b150688cb329250fec5741d215d9171295a718e0d56fc67" },
                { "sl", "2450f16fd37c088d4d975cd0c5d038a615053e1416e662ef69ba76ab66c7e5fe1f85e759a7bcf9c3e75c2cc19612015f626de6841780d24f4d1514898fe8eecc" },
                { "son", "4a612be2dfa16058a6911266489e06eff0c01b18f0dc60d798e18fdc9b2d863aa67b56578f8de70b27fa7cf8decb2301a1ac92e470fefa1b59ae7a027156b58a" },
                { "sq", "177353e33a637a61508b2598d79a5e92e945cfcf1334eea07f62795a1fa4a82c4d13b066ea7c29e91e6269e1f390dc1a47e1f6b1c38d6f19e46235e07c6d637e" },
                { "sr", "84b0f4768af233c713fadc4d56757af204900db7009064328aaf78fa0c86ec85fcfdc3eeeb402572c946c1a2f19dceb904d871209ce6c4c2fc438c18a7d80ea1" },
                { "sv-SE", "b8ca193c89d1458b270aff52c1744a4efe4baa26e3919499d02f368684dba10ec2334eaff3fe09e82b88c44d4df3c0d0530deb45b9b9be1b0f34af63ae422871" },
                { "szl", "30212b5515a49870e1c626a7ffb1ca5ba8db77b5b643271ae488d00bb5096d5c3e8e10e3f260829d245c83c2a31dd967d0b017a041948d85097670dcc10b3428" },
                { "ta", "3af3761ed59ca0612d7accf5e356b029fd4303491fe6deb02fd19803191ee45667ae5a0eac7cfe46f906a7caba0badd90bf0aa8530e0d6feeeb69f313a5e9a82" },
                { "te", "5b88396ee1ba53e682cc93412b66003c9943bed929a83b5f45c3dbc35515a9ff2038bbba7327bfd1aaf07645386c6b74ac1af5710905ebf440a5f52ee69ecf92" },
                { "tg", "5e9d29644aef5f858a2d2a4536f28a87eb2bd17f20b311fe41f1c6f427134b8eb9195a892dee0fe2ee6428c95106eda3afc9dcb693df1b91262f0f053eb238b2" },
                { "th", "58c56e2fa6415d22daf0a33423e17ccacb327c633cbad2152685c9853a0006327786e51019024d8bfc700d0761ad942df461742d0e3059315d942e83969585db" },
                { "tl", "d52bf157c57dc9b9884b54b7d5a3b0355c432fd4c1ffcd5da4f02fc701bea0b145cfbe54ecb40a7c4bcfb6f1ba157de276c5d570d252384e133c82224502479b" },
                { "tr", "d84c128f10c70f0c644f4ef85b760b8330562c07cfda396e6b2731c4bcbc448a387bb220373e4599c11be5040f5939c5e41e2c9b5fc8d8cb15a9b05baecba0bf" },
                { "trs", "a6ead0047cb883790f05e6a1be1bc041dd4860f97d7fd0105412ac124e1aadeb3265bfaa48a3311049c96dff9e1ca8b6ac6193c2bbf4c1688f335cd5ad5039d8" },
                { "uk", "b0c6c7dda84a488021bab159f001d74e7d5bed82416aba2e255d182618316af0cc7df9c9250df585f41f652892415fb5fe11f784ea250bdae262d0b2715d508f" },
                { "ur", "1ec5031834eefc95bc67c6ce39c7c42a5311d68fb9b515145f3b2d5111d17ecdc23782073c8a054b2fec9f7869be61de316adc50806fa772606a750dfe80ad49" },
                { "uz", "277241a65e92d1bfec99d981561e88c02e75bd2810b9057ef426c9096be6c21de56aeab9b4d4e1369a139ff155405297f53893803aedd0ac6052c488d297085a" },
                { "vi", "708344af94226dc0c5d0419210192e9d1dc9138275cde6a8ceb57e20436a2015c75b5379a453988e97550ddd3fdb3f2ab8b5d82a6b10bf7137d61c1743e20842" },
                { "xh", "fa225d0d20a913d87071047107de3b163912f8396c87dd84ccbab584c6db08ee45ad99f206f2ccbac71ef43f9370611ba13a403c85a3541f8dbd652ea62e9c69" },
                { "zh-CN", "1eedeaeed6e32a14278969afbef9a9fcfac2acd05cb21ce1127e6638c26b8bcb39d450ec6933dce72edcb5b1639d8384e7a6e35411fb119f82518023bf2d0d60" },
                { "zh-TW", "d3bfbedd6d08df0d805b9a5cb714a7fd1663fc0ba150ffdb140961e654d8465d93ddebc3c95360a59072706efd0339eecfb3bc95412019d4eaccffa3fdd63363" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.10.2esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d8793281412947fbf7da7d51e11d6b36ab755388c0acfc9c1ef6bc792953aaadda8999f7685d95854bca7c06dbec639f376a8f3067eac31795460ed5801dfc62" },
                { "af", "c5f93772464fd42ab22779c03addd67ec94bc57b8d92a5ab8311fec7b299e4fa7c3f15b75b4970eff81bd3fd37fbd5ba8cd1ba549e04a42c4bb29e8f181de924" },
                { "an", "30271923d74c6dfbfabddab3c1917c4779f7124c0466c66d0409198d95dbaa3f1e8adde672af97f1ed53f0f4605847f02eabeabefc2bf4744cc3e2c79a87324d" },
                { "ar", "735ea0623ef8bf1f7967a2a9e4919958f6cee8e5bb71b68843d7dfa8cacd332a235eda316008368daaa064f9b9ca18b9f1493ecce61801c4c4b785367b033a92" },
                { "ast", "dbe0476a89848ab65d61e16c354aeee928b2adeaea3c44ab738392fbea47945ac95bc207753e0b4462b99da2efb1b96d98bcbdeb1d1527a7535f5150df5e4672" },
                { "az", "484511fca3b69c8673c9f1c749432adab0a6422679f9a8c5e3a1f396748f0fe672faa678840434a4cda5f725bfb1727c03091a3483301210d22975a59b2a7ce3" },
                { "be", "037f4a8973562d9a98bc69a5936bba81dfb9352fa55e767ad2798a7588263f3c9ca69fe015b3abb2fe3e9f48193116e62da82405edf8ccd9a88408f9fc49e386" },
                { "bg", "807b64d19a0b4e421c37c224355e82115edf48d9fefff2fa31c4502b24293db9dc595a6957095bf6a8aaca1b040f3125fc6cb7d182eab5b9739d9eb066e20c84" },
                { "bn", "f97f03de318d59e322f17501199041522c25b22297cd1b5374e2cb155880118589c0fe630a119f589f647b4d11961fc493594882855bbda9868ee64fa86d2de0" },
                { "br", "292d3599a827b9f9e152e5a35f353808fb6fe3ae98fe55ebacff37fb7619800bcf2f3796b49029c17e27dfdd4eeadb83187e918d71d0b5e0a1125bc5c5b8bbdf" },
                { "bs", "d097356faea2202d8e775b28691b0000f076d1b47c357bb8b354c8f14c982256cf27cb92a29a440d2c9ee040f1ce00620d05e3d51b971604e83f08a6e0d98803" },
                { "ca", "8c0fb85a6233eeb1fd8f03bebf8ff78b9c8a81bd542b973ccf9cb7a0b559e0a3f7d067f4a978a9f8ab21f14695b85306889c2a8e0d3784bd9083cfaa9bec0176" },
                { "cak", "747175186b7ee3d18afbd4188b30a26ef3a11a72eefaef64f2090882dfb7a217aac54b5a08f45dda5546389fec5cdc3c091e4f4538a4af8c624348ca5bb50421" },
                { "cs", "9fdf86028accb6e00d57e1088f361f56643a04062a573a8e311d2a27bc31743d65040b344da63800dba5ca602c299abf1bdca4328d17257641167acfb6c27239" },
                { "cy", "7b81bc1ad8f4fc853b1b61ae6f0366cd20c8140e7891f79a60bc7bfd1e3d477cde42f6be8aa7295701d8360798ebfcbb858975812e3af15d6a5f12776afa6ac3" },
                { "da", "de2da6661aad0e360ea189499d28a5cec16e5a547ff5feeb0b66defab23e7f71419b45c27acc9a5f51f73ea43ad1518ead4532eb155e44be4c4cfec733965915" },
                { "de", "a34d9e7d0ae7f08331d65b17d8790327d2e33fb3773a245fde716ad4a01ea988caf87e692acfa636eb38afc36ecd05556c1cb237a5e07eb79998582261d83fab" },
                { "dsb", "512afef093d7e12df72e1a308333f505c0c6ed33db7708342a4aab83be84b80ea8f87d11ab1e5d5daac1cd2c162d7898de8ed0765e2fc3896d6205a6da684bee" },
                { "el", "62210f70c585731367efe6ef5e28fef5f30f2e0e88a2c848c0d3ccbc713e75059677392208eae69588609943db12630666659a360279d8c03cecbf0d6a012630" },
                { "en-CA", "b3551a18d6f7df71a6ea8bbff3843fc562f6bcb9bd2ce182c7c8dbfd1e3d000230d1201715e1af6e5e83186ee42e76ef895cbc948fa1193926a4cc47a69813d9" },
                { "en-GB", "b4d95103e5d7c4ba0fe4fe31efed2fea1202c2a5bba175002b1a6d606c4c276865d5719f1d1e12c4a9b71e193a20c8aad047d57af4a1074cecae1f706a6b7107" },
                { "en-US", "f6bcb4315d956c51927163db967763ce2c7819c9b62efbaaf2842ce31b37b41667e7ccfcfba14e94c308b969daa0fcf52fe3d4652de419883f48c4a03122cd7a" },
                { "eo", "badc4642623dea03d223b867a7adb157559aaa1fd9524e3218211dc77711e0fd63da38f8b06e5fa55b8016ac86523841b80febfb1d82dec9c7278b781a5c2300" },
                { "es-AR", "f2c6adea224e18f6b5890efce8815afaa24c3880cf0208f2b99b06da6abd777edc4717b50c7b2c1dd10855b15a9fb08c5f98db6d727adc64ba5577ad4fa52ad2" },
                { "es-CL", "c94824bbace8befe1924fc8d603435cec10f660c35b5d40ae46031a80cc95b30ed7da3fb8a99644a10c736270a25a669d76c29ce446a46061dfff24774362645" },
                { "es-ES", "ef446420d08db37dd3bfceeeee6d5d1f5983f32156d9b8be138b6ccf4d6304504d2b2db337f95ba5e80b490ab09595a3241b6eb841a214cb71374c247aeb4d0e" },
                { "es-MX", "9e1a779dc76f75d91d3a2f2c5df028650f79017467607cb9a311ffbe60af092d80df20496c9168d1f6df83a3cef7b9fd2e920d0b6746e79af302690594b26364" },
                { "et", "7914f612497d8a59e9794f20b181f71940a967ada1ac912f1bff147655955225bca59167d9b09ee26929000a95751c958b349e183bd274414330a8fd82472a8a" },
                { "eu", "ade63d16382c85812281f69684c40a57769c6fbc39795b09dd55f924e3dc6ef72744329d66ff9e102823796e195f1388c7b22629f43433b0df42a3fe8e3e7fbc" },
                { "fa", "70b46eb761252f81aff3b8df0cebfcd5ef89d34844221e5d115708a31c8c32240b777c6420d34ff3a8d9592baa318edc0a589d08803a8451ee49dd208a4b7d37" },
                { "ff", "1ae69d1c3712d0346331dab332d3d4487ff48c688d6cb00b24d70ab444340ffb61553d5a8d40e101a7d021953a554477dfdcbedc65de8c5907958dd410fab8c1" },
                { "fi", "77c831925541f28e4d7d7cd962e91474ff75f5cfbe286ac88d0971241680205c3bdd63a2f4ef73171cf328076eaee845db9f2b11a481b9d7c43249cd74367a45" },
                { "fr", "7aba17cbcff0a6678a727e7ec3ee1529c527346b6bb6c2f43499ce3fe901977ac84c67f56a34392e1c2f90139d08222cd551cfdfe1c5ada82c7ec9d5f8340438" },
                { "fur", "63504b09a751f27f6bb29364a16fde4a4b067bb1f9e3abb91d59ce4252ba4c303247417c01b144096f02f37cf83fc888cb1e800036797e19ef6dafe96f72eab0" },
                { "fy-NL", "b153cbade9b523b7decab479103d5ba5dac3f7cb150ada1fab13dda877f19be19ac693fce1c27c083587177999889bfcf9d2cb92732dee32b7760c445b3e5301" },
                { "ga-IE", "1a82cd6eb85e12465ce80cdfe057eec9eca8af1fe6ab330a3b3e017e480c4f76b86adc06e02f01bdcb4e5b9c5ba2340712a254c7b9103cf3d415cb8283fd31ab" },
                { "gd", "82e673a96af37ebd28c2b6f15bd071edd110a8645782fd9bba4d974c8518a1c3d498867538647e20226a57e74501917495181ccc7db4517ceff1e44a675ebecb" },
                { "gl", "6e65826edfa21c1eeb0944c1f6ae88d7d36dd54fdd5996b4d1b6edc1b6201ea263812f5b843b616254b9b63ae397443db4b427271171108651cbe37397b37c66" },
                { "gn", "a4c8dc7dac7d570772ff5e43865099252ae18b05400c16c26856bd046f8d7fa30d757735a0be93447aa9a2916e4b51739a010cf4c667fb81bb4bd41177df2938" },
                { "gu-IN", "c1955d36aa1fdda17c01e369e72266ae53940921c6fe661369cb2a26b88c2e2529c85fc6fdeec7a203e520ca199be081e32c06f3e6bb8e15287453acfb1d0c87" },
                { "he", "be6bf6e10a652a22b8c888edac3a26a37c786cf0fd5360066bfb2ee130546d2ca55bae69b233d3f96329ae8c362ba4c4f9a9a0ea59370e4bdaac738db4282904" },
                { "hi-IN", "959586124b1d715d893ba4007dda05a7477678c74c3722cad4e3d511b04e42928b984f3e7146b154a990a9cd9324b933ea2e162503e97febadf84729c9dba0c2" },
                { "hr", "05d2f87fe4983f8108c52fccf635c822117969412d7d0de9ad8ffa76280dfaf047a5db0d275844c176d05678f4766f7bae8aaaf60bf1a68d79c8364435ac2db3" },
                { "hsb", "3e579e7334ac3211478aa7970944b2efe821f9edbf7502a7bf15310814ac3613fc487a06cb8a2c6667f036a03fb85ae74c144c5ba826f25fbe24d5e7b5cc49e8" },
                { "hu", "71ecc22dc5a54ea106075b859329be38cc950cd1e3cdf771d8c0f6c9edfd3621b925273b26f89fa1656c85d55f9a54fc936a9766c8ce873393e90e816f76e2ef" },
                { "hy-AM", "e92afcee3beefa576e296f2dedc760cdef21444a849a18e6e54904108ca14e9674fc447f94fceb21beac99a399abe31f61bc60c1b26db9a523b7c52a087f620b" },
                { "ia", "043392c57db2489f2054fdf1f30c0a094321a83c90c99ee6a72fcc95ae0305971578a0bc9c6ecf4ca79c03ef7a40654cf8b9cb490dd8f106a1a971572fb29d3d" },
                { "id", "483463a2af7f1580e8f019f1a85e2f7f9f3ec6016c4c0d2122931d58ce194173b056c9f1a55d3abca7c29e9b50c263d05fa9b710a292c89e13a2a17481f9cd93" },
                { "is", "029b617628395c31e6aa41b1b7327b62f413718487993ddc4afcc69f25222b12ec862fa300878801fe1257b6f82771b990128ede533a025d80a0d6c2b428169b" },
                { "it", "a67915ec722c2e6b12e6fccda13472f799bacc703555c234158f16d895c36957f82432dcee24c37d8e67cbcb80fe68341b09ca60b6b6cabf6f8a0a1c616d64ec" },
                { "ja", "2e46ec8a4209146b3e36550761c1bf722ebf787ca6e33b5c21f3902570260c44de2c49b91ebcd53ca9020253ed6ab6fca20aeabc37f54287786a9e77f301375f" },
                { "ka", "8b7989661d016ee51c83644a9a66a43019cfecea4caae12609f640af969f71d8260e8ef3b9131a149d1b14c09c27b2c323eb3e43339f0fd15a59f5680ae16009" },
                { "kab", "9981cfc4e3e7101384f6aad59207f87285db733196577a924262a69555fa0e2c1eb38934a4d7cd96835c8d2338bc5b319d20f8ca6311f302ef26f5e48f57439d" },
                { "kk", "51529e231527191c53ee4153422462e70a6d576c5a7db12036fe6f242589df9aff6ffde91cc6927b811af505e2b48af52c6fdc1a0973b5a12afbf9618cef4b24" },
                { "km", "eeb5ed0be9c76f126b874f112e3b31ed1c853618679848ddbc4437bea572dead72fee51347f0cf14e78d58bd21fc56465b966ffe142358d6458720b10ce8e6b0" },
                { "kn", "5ce2505beab260f1cd97f60360c1f69c7f7b6aa732023a9a07afa60491a1bc95abf305a76a9bd5e11221e6eb024051f9ece626f0768d5f5f2f05eef1328efa62" },
                { "ko", "5df934fff543017cfc3a0f0e23cb6180190c8029d23a536fe03e69c71e9136f41853a57d2c7c328885db3aaf8e88e38eb3a59adb2296b6cd273e0aeb69971d2d" },
                { "lij", "2cb5f93a3171c27068c0a9cd4364253a644ecd7b33a73d2b31e3611d31ce74efb1babdef4c38ec9bac248e50e64b4f1d6fcf45848dd9086b85d8467a9a243fa0" },
                { "lt", "cf09364fa4b86954e9926c4288d9fe74708d3c15cb8433aff302cd52dccea6dbde396798656b6e471cdbe290924f6c282cbe83671624eccf8fc1ad5496655f10" },
                { "lv", "579d22a249fd8ef89ec64d61cd6069c3a8d1ce9bec505e5381b5d9d988128284fb8f06a2896bf5cadbd92734ab04eb527b8b8986e2ae247003bb106928c6af18" },
                { "mk", "fee92ce33de00c91563901bd0bf7e5238277eae0b5b82e3d7c8c5a89aa73b9076e6abdff722e7b0f8089f538a3d6685a7e14ce895bc087019df96661fcb1482c" },
                { "mr", "490f5fd5ef02de891afdb2cf91b07d84048122974ae024f528e0f4ae682b79e4e43b46540a130f02e0cbb6eb0f7c8d4809cde06bd416464996af43f839e75864" },
                { "ms", "02b32f53ca0ab847b5f9734eeef0271aad291c371ac28c806187addfa6d95a7130f6da973045deca56ab05e8d84fb4afc22919f11aced8e3042abad7fc177d3d" },
                { "my", "9f7362c0816d72cb4a70755c0286af8fc87ce8b778e37a9af82e650a7829f39e6b3f652275226d64f693e7ab3ecd78585612186d2db57928893067645c358f21" },
                { "nb-NO", "295781f5d612752efa81c6b58547d5eddfb5bdd56b12601279d01556324d07540dad3a1ee112d5e7818b694f99e91138b042952ed95c5bd9ce384c3920b6300c" },
                { "ne-NP", "5a3551fe4c0d6034c1ed95583f434d4c7b798505530b546aa14e6791fa04c2181b9c11d9fe88f9ee3b4074ccc7714f6ab0b7ac5f1b0c460db6a088ad6b196a34" },
                { "nl", "8d9aeb21f87f37aac7aab5acafa8c1c06c8d0471990627990a3c08d5c46cc5b76c993819f34008d5269189e0e325541eae48da4f32165b3c6d9131124782c9f8" },
                { "nn-NO", "abaaf247833229cc51f87093124570152595deaa9ef709045a672c7ef55d065a0c7475e02912a2d579ba10e3a5d4aede8a0d4e338f85cf60e049fdd2b66157c4" },
                { "oc", "5d75acc6ef79912f87735318407b49e3946db5b76e751600c901552c2197045a7a5dc52941fdbccd1d4b00cd3ac79dbc046ed9df3de80139e8a0fa7187386ee3" },
                { "pa-IN", "1657c0c2fb7bcd24530812e2e8f82f5d51390bd19b6efedc5275f3ac6e679ed9d4c50af11e945f8315133a3b0abf724a00e857fe623b712812e10f88845b3fc7" },
                { "pl", "5c1e2ab9841f04c94398f6adb9c98a662e46853e83082ecc9fe968029c4d12d69adde26d56b64c38432c557d241d70f9e8f383de0ec1593cfbc4cd6a3699fb12" },
                { "pt-BR", "21275adf61642b5085d1fc59754115acefea96a86790327a401c27822e108658e09c79a2a61c1cd34e1805edc9858817a59319609b271cc699a3a23dbfd6ec74" },
                { "pt-PT", "09a090ab5bd019ed17ad91a99368db027df4cb58fbcbe9e23404da18dc86022c1b9eba29ee45cbc6312e54895eb6e024bc859271b2813ded6861b199e8b15b27" },
                { "rm", "ef6437223357c078e79a6a37dfc2a3c8af8c31f7ac8ddf5883e4557d99749bf846230e29c01f0557e3dd607c4efe35863f707a56b8df665dec9c2cd7fdb2087c" },
                { "ro", "a576070e4e05e5c29f87379b4d1e80f194e7bad4cfd4063a67bc479fecb71cf0368dfbc531cb07df31b555d3e96d0baf2a03a9ccc4f94f9d5fc91b6b9461c4eb" },
                { "ru", "d646f45b43a37ee5d89c2a6a226f2122c856a8a199e633849394995d64d64c496b8e6e16a1387aace38c5da9579bf306890e292a91bcb83b847aaa9585610c6a" },
                { "sat", "6cb2ae17277dcaad9a4a249e1ce4647ed28f618a7a98755c04ed60c0f1b3118952c19b334bb8210c54700791ce68cf81bf8daf309ea3fd33a8a633aaa3a02597" },
                { "sc", "6baf902dc735107c5d7ee9b257a917b5141506089d9162323f4cc9d3b3683c32e18880730a408d0bcd0f0c3be32e8d05d17898681d5a5f57005ede2d748e81ef" },
                { "sco", "f1de843e5b91540bc911034a2990c1882fc90fba43905adecab5b979fddd90f96b5b3a26049efac0823a4371097ac49fcbb07630bd71c2db02027c770efc4338" },
                { "si", "70eee71f13df8fe5315c6c8ab4b965e6802d1391d3cc4d6529889f9e21bebf95ec7b03c35fbb5c4e30f1e12266d1112c9f5057bd63dd9c4d1fd78f6ca90b1bd8" },
                { "sk", "2989b20283084d0732f34075220df91a07748927b6af02690c5a04e08c4ec82baaba4fb70f1794598a84186ec8d2d00f4e064ddff26ecf725cfe19172f8997f1" },
                { "skr", "834b52b8e25b027fce39aaafeac4709faf69259aeb54f081b0a816d718ac2af2032f2960a1012ed6541613245316cbe968b76ee0bb596766e9e2e39a2c5b1e41" },
                { "sl", "bb72f79144b8170adde13680f1066117b9ff2022a99299e83565e8e6a390df8ba0231b3bea2e9b3f712908863ef870809f028423a92551a06bd5c7ec8465f083" },
                { "son", "560af5448c5717c58714c7b6b68634ea2140792db5679a02f3a98dd1a21e715273cd47f9064561489d1a40902e7d078b08e72d1576c3ee0f6f003b57d9469633" },
                { "sq", "a2f6ac68b919dba1bcadd2e482dced0156ac1afbcafca5539fe8214bf0e2e08f7438a768ae791849ef39099b19a270f869df9b63428b1a5c4ee7fa1d80e611a8" },
                { "sr", "6657be14404ce98ffea3d329d1880519e4b55d62cd25ece6612794bf83a354dba1301014c0d5420b44f5a2892397fc15d262cfbd5ae402ecd4cafa78b30a5dac" },
                { "sv-SE", "5589308e0d50a8080d4267b60835a25fdb0bcf47c06a5cfe98ae1753be88deb1b10925a0281f1dd3bdf05cc96eef978b098061cdd6d8cd422e709b30cd50edd7" },
                { "szl", "fae1454c377f85d6539b7be70513507e2d974515d05dab2153afe3a30c7c15780a93509db8a17d2cc6cd35ef0c7b558b39703eca2cc28bffcd83662f4f1c5d3a" },
                { "ta", "478c6694064491ef66277746f8cd1bec8f02dde6952f5f8fd371804faf9ef13a9e6420a03ba2b04d39c27527835986b4a941355f7bbf7722f81acab1ec1161df" },
                { "te", "2175c5a0988ee61c6cd2d9aef4b81064bfec10e11c1b978f48642a30075f20e029c18250ccf0c1397581e4f5fa9ab48cb0228bd3843e472dfa1fa6e273ac5e6a" },
                { "tg", "e9f5cf48caab337d76902d2eec252b5b57c3e6eb9325f2ca98c9c430f00873844d0628b7579cdd87657cc8a5a0235fb3b14babfacf4f30dc7192e44ccbec592f" },
                { "th", "13df38b36cb5c04e14f0cad96c2bfcfb5e97dee9af2ca74cff5252d9697250a8902d2601c6e4048cd1a63ae0d030730dbfbe50aa263b59aa7c67ab3c442ef1ac" },
                { "tl", "cb938e5c7d472a779db2a0e1ec337d7bc778fcd41147e0d47091c8740f9b97f7050ec15b62f4589cbfe6d93b2f26b860ed1d4d6942044faea46d468de0812dbc" },
                { "tr", "59e2bd554da7c88746516f85470c0c791d48e21c4001738dab770d63fa30e98efb66b48955b9eeeb84db054d9d593ac07841f79eb7e529591bcac4eff8eb5d6c" },
                { "trs", "3a564fdf9afd898baa83011eb3a8e4831e0e620b53297ce98be39c2bb26ee93762de67a85250f9ac3d22995d81c160617cf1341245aa9a7ada6c9e2a4f057f71" },
                { "uk", "b09ff78a1c5a42f4148dfdb88c0fd42520b3ce71e5be7f040010d9457f7187ea76a795211dde375dc571972b573cc566f8e82a118859c42f4aa9076795b83ba6" },
                { "ur", "b1faaab6213dfdcf4f94334550b88aee248424c30ef45bd0ad1a909c9e51cff7aac6abb9c220f9c595cc1eaaebab9f10dc8780247b4b209a216d5ec2a580cedb" },
                { "uz", "7fa9c7e6605a51e5897db94838e4138a9d6f60c0f3a8ef3e992e79108c614fd33088885e7310062a032dffb1c2ab27ca22dd5327a360a0e86dcde1b2575aa11c" },
                { "vi", "6e42a64c70e7b94963ba58e67dc4067c745b91bfe0a98fcd3abdce11dffb940284c3c20d0e053023beca14d071f9329fd4597d8170b70e5dace11051948b66c3" },
                { "xh", "ab1c3b5754f3afc2d3ae44548f3e439da728a90a051e0b8f578228525744e8f2a243ae2ca42efd857886ac870d3142129c98643548b140cacd489b17742bda51" },
                { "zh-CN", "41e7ad987072d987a76c2e89efc6293dc85732c6aa8d2db1cb615beedd3cc7427ea4d671b2bb35c6f205b17e73a60d9e420ba1b3ebfd10bdb7c02dd7055babd2" },
                { "zh-TW", "9c5605595fc839f67bb0b7f50a62ed89a52bf43e96c19eed236de456602c717eb3841ebe944e2f0cf4b9545ecdcb9dcc3378b0f3a599657c0388a7af0e7a1ae7" }
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
