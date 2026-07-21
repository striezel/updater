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
        private const string knownVersion = "140.13.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ed3853ed93fd880c06bee93e5382f3f5345cddb125ed268a42921379ad1787d65851e2d96c3fb8e8d806f7203ee6b3d61134f7406d2af7608e048f25c2f88e3d" },
                { "af", "06ddea3bfce4111ca799ba6e407812d79c0a9f64c640d13e4ffcbae23cbb7d0e6acc138a2d7cd4f8737af81e0cad6567345994a8084b406d5c203d23bd06c8b9" },
                { "an", "032988a5738019d1b8975cb93872055bf5cdc44655c333206933d7e9e264b40fd98c6efa10bf380ed97a38fbc3f212721445b31f0e744a7c6012f99939dccb69" },
                { "ar", "b6c67d5545a0e109cd3657d5d1d241974c56cd699d9f6cfeaf506fde10eae95aeb717e05ef32fef2a606f1e2101ff87c0dc60a19794f6ec4a6db60e2b019051c" },
                { "ast", "49611e7d5550108e4917a3b8e85e7dd1c3c4ee23fa7528ae1a3ec27335dd8fd236c988364e6cdd9bd13b05cb41261979d5c26cdbd847621f298d0a0eded8a8e0" },
                { "az", "6bd3139bcc1c4c39b85b5650f481ff589b05493cccd3bfed4e6c9c1d54edc323bb13d5acd4cdb0f0339cfa065fa6a02a01ba865729d8676731894ef2196a5acc" },
                { "be", "ca97c1b081f430d2a10bb1db46e73620ab6be1ad1a129deca398d0978cb559c8dd3be77b23bb651db055944268491580dbd925a09b5546d5a734262fcc71f2c5" },
                { "bg", "ce88d7a28bb9b7286fe7bb3f91a77da80b16248e3e257bf788f71292765b80bdeb796eb460ae6bb36f6098d1e61d937363eba0872d26c61b651ec020fb438fef" },
                { "bn", "2dce521716e0cb4f8242359e7142f6b71ec6ce94a9fa8765ac2e18945bc9b3fe3d1ea298f4cb5822b2b76491caeffbccb04e7c32131c12d4e7ee4dd75fc0cedb" },
                { "br", "0f4ba57dda783b81d37bee7cb1ddb3460b2c89b55c1a0340d886ae552f3e4eea9ef05067ccaaebe33ec09885b57fa7cf15876c69f0a62feee0ae1b9f05f5260e" },
                { "bs", "59ea11413e5b9e953dff89953596bf75526c697322a8ffd13ef703c51c3bf7df487c8829a31bcffc84075031ab2541e7ee7b1144aa03c6112e4b9772e54091f0" },
                { "ca", "bb542f90331450ba915a0f98fc34451cbfc3f45d21e202e6cc598468633c5e0e6d0f77364ddd3582801e2810d98372603e31f8dfbbad94294c92b902a551ac38" },
                { "cak", "a51a5f5695241d875e809b0152e755d2951e71efc3eeba48a760701e64afb8f5d0053e3ac427802902fdd4871b5a5d4df3a99b0c4585b82e4e43f6a06e5ac333" },
                { "cs", "f7ed2b22ae8d8fdbf181e79e1bf2af5c01cbbd0602e3b8ec6ef06f4c201958f33bb10d52d4c2e7b5d5657f52da14a1e057351b9bb74920159855f3a9a7378d74" },
                { "cy", "3959eb8ceb97581c4494fbfcf1f674d50de26fa68da43cae93f43da58e82b78c2958c2d991ecd2f81a91ed1911f3642d5a202b0b1cd80dac4b22caba435b2ca2" },
                { "da", "4ddb66cda06c85fa2ff89a9107a70813c975abd7519104b42caac80eee2b668f86954eeb0dfb773214f74e7b700ede35a030efe84128deab3e0baa8426012633" },
                { "de", "5ffb6f1fccae4d372118287d066bd13c47a95dc500ef8f34f4cae785d2623c5a4ae7c174bcb60a7bd48761b70c0e7e6caaf80684fb9c6698dd95afb68763a802" },
                { "dsb", "ff94e3053874f04d7a40c90992a684af6c687501ee3490c921f081c0215b6cea7a8f438a988dd8bd2441b3101253182b6a55cc79ec1a9cd6732af508943618e6" },
                { "el", "5cf2f87572a22a43058dbd6b4c4881eccd45cdec9f26251ab278ca4cddccc7605f834a4e5f29afc5947f1875429193ea7c2c4ceb0b6746f7e88e212d4b5b3765" },
                { "en-CA", "3967a373a24b52348782b7e5a1c946cfaac58e8cab0dbb397401fca864ac6e2da16ce33385ef2f5d9defebcbe849b7e352886a5f6dd1125fae4755611d461d7a" },
                { "en-GB", "258bd75f8e7da416308cdeb9e24b52dcac4a0da938ac07d4af4658f2aa004fea916d53efe8b58fc7f63a06b589a70b0b7521667107778d3144e895ddc5dfe24d" },
                { "en-US", "3d9578f6db2c488b7c931ebd7fcae27052d521fc982d10a44258a560283f303d51fe7af4450c168227f43d38a950e0868ba6dd5e46b55ab400940cb9b5d7e6ae" },
                { "eo", "ec9ccd5669193b65fda38e5ac58a681ea912e9efd4b851ec7784f8288295ec5d088a0adf8efb1ea33619306b15c36aa6e3eee74399629b49459e34b3b807c6bd" },
                { "es-AR", "7d15d90ffdc0c92e0a6d2e857b0a4cc3d54f53ef29d6dbd45ac9a08d7f8cea81bf208b5dbbc736b18b2f4a3742e64d4b56f5eba0c8846aecb53f58ae8678d36e" },
                { "es-CL", "307c0dcfee97ede9b5a4baf2a7a17ea80bbcd490c9d178020a2844da8a0ad3fbad3027cbedf91ef720a84554e835bb5c7fd50ee19315709417eb7770f15b820a" },
                { "es-ES", "5ed4ed340d7ebbc62c3ef85862f310dcc70ad1601fda0cb48ee4fe00a5eb62992bb4ed10d702f196800d090c8570dd4906672fcd590f9445a10eb682992fe119" },
                { "es-MX", "a73c612f8027cd6805d82ee198da7e4fae85c2f621ae613d783925c142e3f1a58e37211d6f44df5eae1d5fc819a460c7cba15c44b4d409622680d51893b52e74" },
                { "et", "e64ab4ad0a3dd1b54817ed31e7f48d8772f09a5a04ac3ce837382d2ef2ec041632b866f7d2852bbe23192fca05fe41d2fa44accfa0db2c6fb5c1e55b12036e38" },
                { "eu", "3f8f8546095e1f0c6686da0084be9b62de1757de15c0fe6ddc4a7e292ff8f5561444c4ece85b1628631d557ac5dcfbb6fc3594aacb5423275d97ca9a85f78c7e" },
                { "fa", "ca3154a87d95af5046933dab34c18f110f71202a0ba9686d0ed7c0f3dfac29bb65c14ac44f63db14b37c38103d86afb9640138ac449551ddaa796172d002152e" },
                { "ff", "763f41ea8a929401109c2fd95e946fb556a2c2b4d055ed25a8d64067070ae4c040b3763527a215ae17fb23f00c45cde14230d0920f601e3e59c58a8349aee242" },
                { "fi", "356b63dd91d3b10679cafe46bc4fc1afa47c94b60e386dd88c331cdc84a4c7f30bf75ca7a40a175bd30e651e5d57f3bbf932c48067b38ffc07a6fd0fc9eafb79" },
                { "fr", "5a94df858cae680efa8dbdde9d1c807ff59c2ce96b956b5107709fc11cfd723a3a27bbcef868b91dd5f49fe5fa851ccd61fbc8b6adb36a2b142e5fd8ff2df88e" },
                { "fur", "700bab852fa3df48e502e318f51492df1779e91f095a6f58c4ca5f77b41f0594d019e36951c6bd173cce317be750733d94e4e2cf67d224ee1bcf55ad833b7f30" },
                { "fy-NL", "0cf20210fd35cb16b900ccd4013f17267598d42614210948c3b1461c7ce73b815f6690c69d5b76ad4bb9bdf20ec4bc646af5f879b59e0cfe5273ce48d0113765" },
                { "ga-IE", "c5f074849c7259fb65a0a539c285943a8e058bf5b3472d7ddffebd9e831180fcebd24413024417863093cbb116be80c41ab4463c1022a82ac97666de364d7b13" },
                { "gd", "7e7455169215577ffc9ac2dbfd157d72f6b048957f9a996c5d3a337ac52164201744baaba7de73a15cab9fbbb1873aa399b862eec81d2b34cf0437960a1fac80" },
                { "gl", "cc103401e647d693b4667be1286a52e2f249c89d5548b73faced494b6cbc5b8b385764153515df7e438a47f541d3599cc1608e66d65c5eeb32446af81690a814" },
                { "gn", "69ef5c03ae4e2c60ab2032af202528ace665955b7c4dfa15d8c22aa71883777acbdeefe1c8e163d66e838adb78b94e403bd11613dbb50adc0bc2e9acebbdc5da" },
                { "gu-IN", "9aa52ad27b630eb8a26c158cb850931df50da5bf14fbb05705e5012a3e7b6179b1ac0118fc5d078ea5ff9555cbc1575f26f976c4a8c25d0d4352273fc93ca88e" },
                { "he", "2916b88cae8e819468bd29d4d53aaf470fb464e8e6744bc5c74ccbb9f64c42ba5ef812f31e629b1f69fa16c28ae88bb7f01b7c419125811db52960ec1f327050" },
                { "hi-IN", "161d99f1cb897deeb5141d5569a739d7bc51cb624ffd0c45784b814944e8517ffcc1c95a24a9781ac0d6d9d4b393ec3001284d81607f3b91821263c5ee559455" },
                { "hr", "bd121eeda2629e855ae2dc3f093566458bd383867bc450250cd7be88607474bf829b8f8bea07bde3cee59657b1b5aa335546647edae6eb25e4b4f4787ce13660" },
                { "hsb", "a35f137ee8284079020660912f281d12614a7041bb19dd31236f477bdee94f44ed9cda88d50613fab89916ed99716d3b7b5275cb751b1f0c007e4876bb0356ed" },
                { "hu", "12d37c99061404e0ff605689a7f61872151325670ac60075d741bc340583644b21fed8a2f339c4f2edeaf772c3b186a750ee6c37836285d51bdf4b033e25f659" },
                { "hy-AM", "17cbc5d5b1ecb63e31dc3c6e9e3a9a39cfcad8ea5c2b9f9a487f8248274eb3a14749aed306c073be71c2a11dbdd93cca675c5b0af47531462dd98219d7d5ff91" },
                { "ia", "467ac42e316dd33f812c3ebd895ca6ddf24dbc9f1c2addc98c54c8aa05e5ff0aeaab9e89b769e5770c713d429fa9be386ea18f4c1a5e815a4fd586c97907a5b9" },
                { "id", "0f4c84ade7118f67197ce99f9304cb2ba1d6189694a90b32282a1f2ff749cd3e74375dd784a7753da4dbcd42c0c6d2a06b90c605a86f3050b82417dbbbe1abda" },
                { "is", "816bbf3b56542f77fc6d2c07c0bf76d16c6bd48abe4ed505e28cb94b7d096dadcaef8d9625ebe37dc310f3e5591dbb4d672005e5fb383b04ecf996c7672e9114" },
                { "it", "3b83959188954b69eeeef05a2cda2f970263f6d34195ce5e25e9ffc62fdfc08cb920524539981e4885528c8c2615d832065efca77567a3ca12adccc11ca9a674" },
                { "ja", "76d2a3e2fe5aecc7002809b6b164a15a4cbff8ea9c10be0ac9478fe6ff04a7f54c05d51f024bdea0703d8273cdba5a60145a80b0b271567c6ea6b49039cdbed7" },
                { "ka", "dbce6659adde4d89e484a1107c5be6f02cf8dfdc4a333b73ad1178ae5ed6f41cc9df89e9c44a866d140937549f8c99042046cfb2b8282dd479eb3075fdc0c44c" },
                { "kab", "339f3b76fddd4d4b1a38eefac88afc97073e72a45e2d7c7780408a7643d7b40027b8e254b1d7142d250bc23e5e33c0afacacb4eb92cabe68146c089566f1bb47" },
                { "kk", "09a37096f715ba29c62e04b13a1ad486a5ba7689660b9f8dcc0bf3ef4a0cd26ab6c096e25b51e8e9c913c1e0fcb526eaf873696e1351cf598b86fad3f08776cd" },
                { "km", "599e256ef26624c6fc120b65b879036464470e7ea245151a2995860487fe37c90c4efc6142d031f767334a1cd12b35e430ef73005665cdd4c9cb4c39a840dc0b" },
                { "kn", "a2f4de67f5eea063821f5a92c212ce6b73558b3de0d6c7e249c71307b7c82f4e8fc643a12b214981e3df79358e6e3dfaed43cfb3dae5a4375277e3a8cf245715" },
                { "ko", "355daec6cfa192bf206cbad51e9fa4ba2ee8f88086c3316880bde4986cf192b798c37c5f71ef4e5dd1e00a42a77609eaf949ba96247edd7afd4c0e7b254169bd" },
                { "lij", "e853fc345365839f945679d50d02b32aa91448f31945ac9e2e2245a79bd26713919a806cc72a370ccfe29d199770a227ea458544f582089805ce0358ced0092d" },
                { "lt", "a58c50ce25642d55b140ec434fa2eb651112af971a423276afe76b982c537a06fc4292a34520763df2bbba631123357e64b779a0f2faee7895fe9f8f059d79a9" },
                { "lv", "3b0ad0148e311d0626d9365bcf88763893af4cd2d785179d2c36a0179d1ae743e6659b5f4d7e02dc2b6fdc362d276a4ea28fab1d2c83d0bca0ae65e0435cc696" },
                { "mk", "78574cf8ec6dec2fb02761da8fd6271856a2b2dd36efe95abe40ba28acf1c5a4fe918ce4447e952bf28aa12ebc04af7a15157c39222c0d37153c363ff7c21b4e" },
                { "mr", "ab61372dd58303dfb5c5bf30f3460c8b466f4780b92b9c099396320fbbc871cdf1224de469dc5bf07bfca939260329d8e1c6762daefc2f52e8c955c5721ddad4" },
                { "ms", "c4da937e5498a3aebe8fa90452ab966f378d273811b87ebe575fb9b69db83529c6a816b161a99478d09d14f6ea2a71a7bd8bab7cb9b23347baca341e403b852b" },
                { "my", "442ac88ce5e9dd013d3bdf818b42ac3eaa46ed8359a966a51c2278a27435dd19bc7fad17812449bc9480cc62139d5bf38e43d6538379e162b8e5debac6e1f762" },
                { "nb-NO", "b113f6f0c56f0cf4dc889bf91f6dda374adb97df847b344d30937efbab81bde7fc87b3f1bb8a828c3639cfb537a29e4cb5f5f410e955e2b16ff62393e1ab53f7" },
                { "ne-NP", "dd61094f93501172ced773ad5dfe66626fc393b8f5002879dcda53d30d383b705bde32f006ece1ec59558ac2b3a220f1aef67081ac8550035c2ba0b40ec64a9d" },
                { "nl", "672b950cd3faf759dae6b83b62000b680a209a2c7a3aaf5c8bc17b93aa0702473793dc430ac08e942f1e30ee4d91777e5725192290601aea146fa970a1756870" },
                { "nn-NO", "1a5823db3ff95e597ffed309ffc801294febd840ebe9a74494498d72f9697ca1ae57bcf07d54bd8c613a4c590d70e866f6ad8bb29c4ae564967fe3932fa33e09" },
                { "oc", "3dc986408b7d74057069125014c0c891e8564dfe288650bdbe542938c363dda82dd18f3a549e08a12aa6390897786c30153d281160d508a9181e2fd04d34085a" },
                { "pa-IN", "aa57a966ea1c2ed4eeb3ef469070ca2976e9e8bd53a2d4950b84ba20c479b372641bc7259c038a1cdc1bbf6e58f92f656b18b4df3c6df7d0802cfe597e646af6" },
                { "pl", "0aaeb70984a607407c4fe52d0c38597b635875cdf2c51b89dc352154a2bf41c24589c8e0b56998ffcd7a9cf52b682646787c0b2e5320d3b8cbb09b8577a1233a" },
                { "pt-BR", "a8a4aea876b0947e6fe3a788f81c6d046ed03731a3aac91d225db0471c6b15bf035dc2ac32f177487fbc30d63d591c0ef3ddf5dbb05e4e1c05e68cf7c87aa8ae" },
                { "pt-PT", "f75bec90dc4e4cfbbf6dd9669124757e90be81d8ee652ecbeceda06f0f80f544b34f99f31c90ca22a550f7d5c3ff10d5d13af5cdd025ec5a9c46f5baa72ecc0c" },
                { "rm", "4ff6488d022aaad4135d54d43fedc82bb161dbe302c33de2485c0ded1442a9ef99f496eccf3e8f33b0352f7847e90c5b87f041adc1d3d34fb60431bc035aebcc" },
                { "ro", "95e0d6115eedc8a41471c2d95e880a56040116715cbba417c507c756cb4173733e03502c6c72388949029dae1088fdec2679cd19b67c3872adbf76751825ee54" },
                { "ru", "a53a7dd0c80591d24ea058c3992c84d355dd98b66f40766d6e75334ba607e64f3772d98e7d97639df2056f567e22ab8f54f3f45b020a0e079ab6429c7c17644c" },
                { "sat", "42c4d7134dde5cd9f9f76b9d793b028e093f3c8e78caa6e6c7bcd8291bb97637b4d6c0b1b0634901e82d867fa5abd06d63cc3865c8884295adb7a4b2b07d06a8" },
                { "sc", "3a5e4d3e7c9122aee3e153af1651cb6ed2d5dd214f694f8baca0269abe608a6b59c6a5aa8202fd4e9486250ffdc271ac91a64884248fc79212eaa61cfc488fc7" },
                { "sco", "349ba15e33dcfc71be18323028a18f34f20727d5b9fc6c0763ad10e49cbda94fc7e5295024aaeda2855c75ee93ade19b5026b97ff904b7a5c760df62dae159b4" },
                { "si", "2d97af098b8a15ec7c03b80630ecdb4d5913bae2031d89765ecb94e4bf9eb0d6ddaaf0f95e0ab2a539da4fd138e1cc8c2ed6d858fe40dc93a60764c9d7b3f414" },
                { "sk", "b98cc499507f7371ed2484b047b21dd89bfa6602058156b52631ee38826be7ed57ed32559c5761154abdcf098b44bb1d680014e922514871101e9ebcf58f169e" },
                { "skr", "45c7de9203a72405160e59c9d1254c9ee094916952c44ee809a9f30935281bf761ea85cf84fe8510f687819dc71c4fefab56ee8e851f0b8392932807e7b8ab8f" },
                { "sl", "9a71dcf386fd727d6f3f3e391f68775a3724b1ee7d76cf9f6520368beef39b374e316e99b4bb9836ca4ac36c888db954175407279e30351641c92733df59a521" },
                { "son", "8e9e0d96df2d185cb9b4e3f1e6d59b66328663be9ab37188620f5537fb5ab50cfd424db30c00079e88079e89105b08eb006050a2faa99e07d1ebed5a53cd8a7e" },
                { "sq", "c705493e771f40186930dfb073d8dfc4fe6badf4b74da6f18b1ccb425e504a0bac32c8498fbb3ccade2fedbb0117e91df3cc4b71c3e028d6b9c5fcb9c074f450" },
                { "sr", "30198fd634259ab5c17f9b38a7b1553662aebab018d4d2ccb903d4ef7d4a385b894161b8b0f65478e3557041ccd957c9cc227554895ccf3dc866503128c4206a" },
                { "sv-SE", "f9b2d5a1a2090b4b4f23fb9627966bace56895d7f7caf87814014bb2e8c4b62524d9b26fc30dee7ca41429b59218ad271b38abf8af948e73cb1f4a7f21a0c5e7" },
                { "szl", "5fc269e7d12c0b88799294d7dee0ca0ddc82189fd44b917ae35f5ec44baccd96248673c719c7b97ab2d90214006fceef1590460df57a977f7fddd94935eaaecd" },
                { "ta", "824e736345ad5aeae4ea87da78c41754fe75a883097a76ee76d0eb706cb6d558114f8ad50a3a075139f731e4194ee4d41fbb587baf8968849183a6bddfae1970" },
                { "te", "492a314cc2d283713696fd0afe904099cd35e8dc9d5645c910f665b29544220300e4452d95a61e647b24e5fc01ae96394cd9996edf773094348aa64be24bb431" },
                { "tg", "41661c925ce6fda1e91dcc89ce9757ef5aa446979df98174648ab40cfe88185c8bb803c86f33b77dc08769e678c902868d02ef5eae029cd020f38b6c7cb5fa47" },
                { "th", "0f9aba9dbb52f309f9c51448240572ac119bbbb23a9a1563634fac967d1b721c291e031f5bf8141743762cee3704674993b196aec584bfd15997a4c23106f538" },
                { "tl", "0353abf62d78bad4c2d93a5c4a515c53ff027df96710055288f4af6e315408c1131e030e911ecc48236b26f95d29c5cee3d1dab4be8f0fd4e169a3f70d9b8d8d" },
                { "tr", "66c3401bb15cc9a5a6196c71cbd6ab1194fdcc4a3e09ca793cf13034c4fb018b24e191624eb9a803ada2207ed495a9063d0d7afa1d09f886852d44b020fc62c6" },
                { "trs", "b614f8098312a7f38bdfca8ba5a080833718693cf77ade03859ccd114f4e3e411d501fc1dd385bf7bee722f8cb75829fa390b94888fc75bb20d870a7cc8bbe9c" },
                { "uk", "0c84dd6606b74c99c84b2422e49d7a06b71f9806e62e0c0edde4c2b6fe36436c752f8b4270761c700d869f8052ad8b36da91380824b3b642d46935139b9540f6" },
                { "ur", "e95f9033a203d1f5739d53d869ab6f97a93bbe976aebd1b962c7623da280427fa7ffea06a24c62aa0a65bdce71b36cc00ba4ac02445cf4aa1f7f3860c9ede38e" },
                { "uz", "da2de4b0d40bc1e7bd5490942bdab283be0037219f13083cb3d7b6f70cc033fc6f9383683b5c525d4bf98e3ad53fc19a5fbf96f18bdc596b238d56db0f9c6ead" },
                { "vi", "ec1e119a3192c995cbfa9c61b5961ea91c2f117cdf5830b7ee579b8faa935890a31bb2292779618e6b9dcbb623091efa236408ef51a0eba2554365f97371aecc" },
                { "xh", "0fbeb2f6fbb8acc4671dbfbca3687a0ba6235d3226f718ea6eaf3154b3f75f3c93984926e6513c97b8f3ae9d4637b11d696392bb24d4cfe59198c819c0ff664d" },
                { "zh-CN", "6f6420faa0e1ceeec8112a0c5b0b376c98b42fef6486345297099b0a5d6bf9a1ba69cd238501824504c87422241223fbcc75a44e6c00d0e94eab69901239c991" },
                { "zh-TW", "ca2ee83926a2bd8e4aa3db20aa8eb120c1720d3e410c45cc91cbf9d4e519a2fc0d482e9d629934249d1b7e9b1bb462fe8030c2da4da576da1cd976c36cf1445b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "39955bc33536bf7c96368d468013f7481c8307ae832cd5e8c6b47f323e90472b87dd8496b28a61b5908c7e4e34fceff0939c01f24e6016d413be8ba102d41617" },
                { "af", "fb7c0d1c470ca4f7a9b3f6ad8258486744e388d0e971375bf532e639c89b608450a0336e3f59a8a00abcccd41a253e4c6de724859d6358b2e5b2bcc8ad9f16e2" },
                { "an", "8e786efc5f880ee4437f54c5de7fb16a13d62bc9ba82d792e3d7642423e8c68d49877ed715d797f82417cf71fc41980455252d853b1521598e861c6a967c2250" },
                { "ar", "ab21fe08f4e0e53fd413083596e5a4b3ab70061e7e624dafd923854214ec9179ca9fa10d7cfb4394d0fa101c9dd4c8d93f3f8e030d080465b58f4e5f2a5d3acd" },
                { "ast", "21ab2e517be14de7e1511ce038e69870b0081c6201d778e3e9a2382daf0be53ecfa1bacd291caa579a889d9bdffeac56872fc535dbb7de53c6c2e3920ef1208d" },
                { "az", "15fa111a7d54e0ce45a1cdf4b0c8d94277852c01c766b2b7cc723c600c5cf2765cc0201f9257cdcd88a352c017eeb9d0c57d97d9a936c5074907402da8cb16a4" },
                { "be", "cda322837c4931f7c49e973006f0655a04383e463d827db4d5e4902f75e18fef5ce7c233f65e108527ca6dc43f87d8f20f18dc13914a3324d04bb4a608ead5c6" },
                { "bg", "1adddca9105ff69bac529fa4b11b11f6a22ddd6a7194b3fbb447d3f760e9a0e1289c1738b17b71fbe0e0198de8e94a9e378a12d1950d8256110e85688707d10b" },
                { "bn", "81a38ff6fc492d72a9496d44eb5eea2a62545226fad12deb84857f6ed13549809541b546d2f6bd1fd620265b93808ff2334562d4a7064db3d0679b04cf8f5eac" },
                { "br", "1b54f757c2a97abbb5595599c8b0916a6c4f127e970948894aa33039384cd4174e2c37fcd77e93e62f8735fea893eff63e79b85e4b20238df96b16f374edf6fc" },
                { "bs", "e0512f8bf5cce12bdb9d7d0c6146a2785e3452bb65e9a048d4a42e964a87c3a51ada432f3691e47cb7ed6858cb23921edcb01c884515c90333d006270e565a91" },
                { "ca", "a8e2806ff9dc8a57aeb3dc2121e677cd4102b0f57c68306005cb2762bc0bfe8d950fc110ea66095e0ac8eb70cf8104d080963a92523633b30290a7ce884f7ba2" },
                { "cak", "5fd052dbe3a000060d5a6c0e7d528437f640ebd55acf700309d2f85ca9b935b6979d7cc5a04dd8e4a4fd3a68880738800129c18981a1d5160b1a00af86c333b3" },
                { "cs", "82ba41804ad9c5fef81ab8f2eaf564973559d4c57a066600f22d1016ca6697e5bfb237cba845cde6b8580415d531b0247025e8f31053a67f137beaeb91f22c72" },
                { "cy", "0a05fc03188de8c334980f1775b106fb2234bea11dd348d3c9d8637735f570adec0b3cf95cc762159d77953a982e4346310c086caf135deabe7144f1d730f26d" },
                { "da", "d6f46dd18ef824f6b10fed6083cc38779891dff34829245c3c83125405028c10652a351130f529108b37c0d52a9a17dadd705673deb09f0ae5bd52ecc9c1db2d" },
                { "de", "f2e23a9eb35e8c59df2448a01d9f654a47ad3902b2eef2c6f1aba3fc8a03f5b39cd57d5c63660b102b421424cf41c6a585ffbe09fe8ecd300df57984ed259ba7" },
                { "dsb", "63805e6feaf6665a98a10bf4ad505e3130ac6a673d46535e3a3fdb4b96cf042c2962fda8a23952affabd949d02bcb3caec438e7a3f179075d7a47a347b31b446" },
                { "el", "0a1fe41494b2acf56afea7d844a638bed0572d88f7d3bcb7b95c5cabcc269119b32a571e7e9b7d802cf4b22741cf88e97950a584bdacbda0540f6feef355c93b" },
                { "en-CA", "080637cfb92a3f08cd32cefd1ed9522215eda2b9cae12e23f39fdfe8cac3350aab2f75e9cb1ea2364d15931fe496dec0c04467346ac3150572fa23d405a9355d" },
                { "en-GB", "6e62f94a0bc6e02ef5c62ff052c6b8d733a279e73da6cf17ac5fc7ef713b5c786f45cfdbb45e9c25bb4ebcf3d6cc3715180aa18266f2a6ea2184f986b60cea0a" },
                { "en-US", "3f2ac5d540587b438ca61bbe53525b65785d8e40e09c1e0634a06583e3cce40ea89ae9a711401afcfbb1df1dd7e361e756ae4ac382f78dfe69b7a671039ebb14" },
                { "eo", "d20d0eb26574d480b3b3fbbaf3d8eaf4330a44a9c4ac55d0924bd5fa1b9c72f3f8deaba1acd412c148687f41197276ff54beadd51386e22f876ac98ea237f5a3" },
                { "es-AR", "b6c5daf394be8fe551b3deb210a4c887b3c3b3fe0d6c7f6b4dc7424642c683ad01431d7e52241589cf9b2e23fe4059c39d77c40556b3ffbc06f9581b67fe41fe" },
                { "es-CL", "c09f422c46140e841caed369188cfddf9353153cebf686dde1b4a1c04c828075bea867a8e5688126d149e844a077b5e55b7d2d579511bf9a9802cccb796e88ec" },
                { "es-ES", "d1687a7dba17433317bd13b0e348430a7cefa97d20554173b823fc4d657f708f728d286f57b76f3efa33a77c6855ebb54de45cab7e401bfa52391091e07a6a11" },
                { "es-MX", "f59e0aa3be25afac9dce697f00e886c6a36f7613ca8f373483752fe70b83b40630fe5aada6bcdfda590688b02660fd35f9ac830bf1443c224f4161a070d062fa" },
                { "et", "1443cebcbf942ada9b2f7a3283240b8c72ee94c4af7840278f45bd8feeff7b89078b324e6027a28c9869ec622894aa6b2c3bf86dc7b90f499c70905988cdfd8d" },
                { "eu", "3c328e7003ed1b4e3998dcf26f9bfc1a92838a59f79154df379d99083e8c46335b1ff00d959b9300ccf17908e3ad83a47b9bc5f95abebbb6fd2f8b364afa6baa" },
                { "fa", "661abf03493722c771a1e2ddade694e78ba033098d94a3e7fe2b0bc722dd6c144b3722627af8edda9fe8f5667115758a8096d4a2fd617452f262fe406c912fe6" },
                { "ff", "80551820568652f92fee80baead49ca96125922e3957a5e752ef997647d49ad0d68923d4e0d59a8a208ff8752dea5ea091fee2bd6a5306aae8305bb51512854b" },
                { "fi", "6741f584a3d616d329d15fd9c9fca0f17b8a480c65f6b91668bc0ea126e5338550ec4c0013a73e8eeaaae904eedf00e62783672b611989a39d87958f561a60be" },
                { "fr", "7650f0519660261fc8dab4b75432d0457d7ed11c0eb984a9ae8ed6a5cf30457ba687994368575251dd83918ebb65cef24fdde8c1c46b70f6dafa767b042feb13" },
                { "fur", "445d93df88428dc565be07528e2272c6f3077c70a0ee411cd98af0e2b55fed71a7f5bf60daf63a15d24f480cbc2b291ec002cd7ac9344c275d8a84adcf05d6e3" },
                { "fy-NL", "d6534e8b365ff1dfb65876afdea985b3fe1f8ede8bc56ddd19a70d458eacebebfc317d4d8cb3497fb189096838fe697804a3395e72d59ac48549127a2229bce2" },
                { "ga-IE", "b73bff63df25aad392e869c1b2b82373365172c30df23489364deeaa9acd0c4783933d85482823b30d5b9f9bb9747a1d35dd75a413b562ed66d894fb1c05e285" },
                { "gd", "bc4df84e161352e849d9b9b858e0ec56cef2a18113a2f31f4503cbe63be91165f48a9cd435c69d988ebb031fd535e9618b92017a7d9699252983b9a92ad83d45" },
                { "gl", "396d6d73a98927bea4d73eb12721f257bcdbc08ab35e69afd349cded131d3d36a6255f7aad4e90592c5077ce39aa7a3da4500c33ebff21389bb0afaabf2d784e" },
                { "gn", "f62def0547d7a6601d75e1f06259d4236d11b83daf10a60c54b1c55749fe80b341832bc3e01143114ee419724b6ce2b41909f7fc2f40ae1a89525b65ec8f59f4" },
                { "gu-IN", "e4874cbee3761bbe2cf440fa3aeb70f897047fc67095c1398d7b53d9cb61196bb245cd087e02b0c391cdd0d619e19ed6be87f27e4b1393814efd4566f8bd28e6" },
                { "he", "97ca66731b7878635723bc80075a8a924fce55c4f3261988c346fafd8336c3967dd933d58049b576d27ae87dbce1a6c203b0c9e582aa41ddb0c5c7e5cf03e913" },
                { "hi-IN", "6599dea09964ddab52f509a6cb74bbc253908c129aff59427c1cb82bb10fcdf03816659048b7c454f60386f2820aec0ccc42670ca5edc5161fe56d21d70c9601" },
                { "hr", "4243ae06b8ea5be5ae8feb0c96c2b9d26f12e65e8ead542642af78b7d5157d5ba879f996af0b76847987ec2df9dffd2abbf6063bc9d482f5e8b5108f32967615" },
                { "hsb", "cff85a5257e8d8d7d7bd0db57be8d5e3c351fb39c889a3e5d9f61da71626dccebc697d0f6b335eafc5ab6756ccd94b7875334d480cd9cd4d6bd8085db4eeed58" },
                { "hu", "223b7b98db161bd8a9c6f5e8f1fa1e6d31d170ebd2daba448800a2286c0377896b175e4f429bc7bada764cc18d3065095fba7a3f7dfe76ac0099bddd6c86a693" },
                { "hy-AM", "7fd56f1f7cf3163152765eceff511a79e1555161db7a51c928156fc892bb4449e5a6741dba25aff0cc717c061eaacf9e467cc79c26f97ae3afef76e1eec821ae" },
                { "ia", "1ebda76cc7ff518609d4a625e6283710a9a1a3ea2b237b21f56d6aa35c38b826a1a089b6c66cdffb733de2b937c98f77d34dd48621162fe6f759c3f147e48f88" },
                { "id", "44ef2b1da75f5020ebe268210d635d12f35e16695395ab8cb28a69b940325c10be90515f3c197b6c4823fbf32d59f0ef2e546f9b0f73f336a2416ea35b029a6e" },
                { "is", "f59cb38db768b894e85013e5452fcb79086187534f4e94227746b05210749d5e49a4ed2c91fc991f360816c95cf0d08873cc91697cda32715c7af7d2638094bd" },
                { "it", "e5f6c414ffd4e0d5c7b07990d76a4ee05ceecb5ba1aa876227dbb05ad1c4f446bb8a1ea1443401cdc85bd98294d8cc40a61175cf4faf606d5a2870ca825e9eb9" },
                { "ja", "0a7bfacc320485c2f38bcad6643fa297f4271f6f7dc4c121330af5c54da638090db8d1ead8b453cc99e4c152e92154c8fe21fc2802045d44c07026d0bbbbb111" },
                { "ka", "6ce41d96530eaf2f3919a4b40c5f335a5ffbacd34cd1e9409d5f5f5cf638de491cf70e209573364298b9bff75443d53712d95b3509832e06bed339a37345d1a0" },
                { "kab", "86aeb33765b1fb04a8308d37e19db54233232272f4a583e9f349a1a0e1b5cc356e6320736faaa10fb5cddd07ffa5fe0ab2ea43483b7564492e6e97aa8b7b8f06" },
                { "kk", "f20488d63fbd1128f133f4da7cea420033996612208b67047595be895418839ff9f21e1e6d3f3b10c88b9032cb111bd87e17b611b6cf63cb2c94fa81f2c71674" },
                { "km", "257631d5d74ff37e94b2444b3ee00624b31c7c8d9724322fa82b9dbfa63a20a1d2e66e495d91c3225b7f67818f1395f00f663173b534918cb456033283d93a78" },
                { "kn", "fcb24a7ab3ad5ec1809f9078b8db4cc1f6ea6e375db408ce1191ac6b90fb32d9f057c3ce40e1d2900137ce0e6b2158c2cebc59fce2b6abf9c711ab86fb3ec326" },
                { "ko", "a917040e078d4269092d6b6ea5066dc80c669cddd7ba4540aa8cf170e1e710c35d89b2df14e09d1f45ffdf3c8280d8f1b4d8565ae767686ef1b1790d37be2e10" },
                { "lij", "532cfad7a080943560a626167f27037f02531fd1b4f894e1c4d7b25d2885ec4ad396876c26eb5dacff6c6b6cf8994c9f3e48e244c451958ac6f2acc72f018a7d" },
                { "lt", "47a4b785aca1ed34c3f7c99579a4f6de80b99b341bc0cd29711d9f50ea2ccdc589766657cf7c6ed274c50551db230d150975904781cec8ac302e40ca84a40ff5" },
                { "lv", "0f2c7d4c5fd6ad2fcd626e622bba9342363ef8b3203a8c173c90aa19bbdfe918824a2f31938aefdef0962baf6e84c3d863b13a660063387decbadff95c3ccae1" },
                { "mk", "444e3494ef0364abd535b0a1c5ba14b3d3fd9e3deab1622627ff98c14e41e3a8088a45bdc855dfc3062cd26fa031d678dfb37ced8003087f605fced59095c4c3" },
                { "mr", "edd5e6d6e80d3a2ba85911f6d9ca36cef3ae2b429d2bf89c5b99f7967ff30338651e064e573843888004b06ed4cc74b63321230db5af9b48f087510d792dcd39" },
                { "ms", "1133fcc29eb80d5f03d89fcb2ac5b726a5d8ae968760a4fa191deeb6fd0d85177924f1d091545c3d836718df8c5a64a646a12ae00d46c21b6e1fc890159d3048" },
                { "my", "e6c2adb0705901b5b5ff8b37a6910ea47656468d254edea591e3ffeeea4693c4246a1437eb2def48cf34c98e41ba6c660192700510d2d90e66816c441fd6e6e8" },
                { "nb-NO", "01aa9eaa17c5273a224fd66577e2f43c981462e6acaab80b780e44c15837e3970c086ba4153b4ddfd45e304f17899fbd685112c264d644a404238f97b3fa4a68" },
                { "ne-NP", "c5f1eea29edce15fde2827516cb22fa97a723fb4392954606fe708210fb7d57471a5b0d9c227ca511e3d00755cdcd6552f53d5296f191b2e2440e3950591bb79" },
                { "nl", "ee4714bc744c271e7e03be00e92d52033dc96d0e294827ae0440a57b97374be3d94ea90e5c4bafde9ef270b0efc9ffbfcf1d2062703f2f8c0154046dbb1c6b59" },
                { "nn-NO", "3fa7545f3d8b425a13f22375cc10ca8a2f8708c9a8b29c539123efa5bd7d8e78d4975e2895700c482cf7716b09eee7b35d94e8a956e00647d7996f6e0eb8fafd" },
                { "oc", "bcc7fcddba06708e1262db82a9bd7a66bc8b3ccde9c7ec620133561a37e678f6d28263a273bc86d93426281c725fd73eb13fac818786f481ed7586e264ba3a8d" },
                { "pa-IN", "2289b15ee3edc5bb5ddb3fb0902067d778ed490f373f9dbd2d0ad3b09f4a03eceec292422d0810a8fdafeede4a2999e5f525bcbf00ad9e973e0a205688abc67d" },
                { "pl", "f52d370702a9301dcd19d6b53ff685d0182bf3dbe58ad9355d6c4b7e56321a587951b441c8750fa9272446b49f24ab70b3f38fb8f14fa27edcded3c4c152bb90" },
                { "pt-BR", "7a55ec6f945e66a1512c4d05755fa620742b5241ad40b21929f433b0428ef88f4fafdcd7104b7807570440441a9e0fce940894cd816c81cb3bebd19247d00f20" },
                { "pt-PT", "9aea7f636a97c8cfb76a23916d462408d43af5ecd44c1a65c320248b75c8672676c6434352e07c90ea30a6a73b592dc1ebddf21cf9ba2327b1411cc032cc0072" },
                { "rm", "990c75cbbf2a5e19399d7dcea187d48992c0026b38e5e85b848b00d8e276ca987a56fe4aa91d13073c93ed457743783e152b552b7db34a04b799886dc6810b8e" },
                { "ro", "a245349f8ceac58d44f0fd34441167cb668a837b862843976dfcb2136d53cdd244bc32e1e54debdb8c807057c2a1b55f7cbd07c1b61ad1e60151a4bc23ff42dd" },
                { "ru", "56627f1a993a0c3ac788c2a78cec9f817da3b69259029bf19579792afef170261eef869d3a38158bf6f75194dfaebd259ba1b459ffcc186f718f790148998434" },
                { "sat", "105238482f5fea1900270b6c7003d79d1234a3b60094bc0d098fe13084f9a510cd8a8be1325b27d87ef26b45bfe8a6bc85ed456e4302db7e63bd4bd35b4c2fed" },
                { "sc", "2dbb216ab04915535bbabe65e4aeef6ef552209bef5c7edf65a209bc25f3c1f57a8572d151bf3b05df367e124bf8024ea6ed7bb4941dc4a83be79905cea45fc5" },
                { "sco", "44ce4aeadf14e5880b5ca41ecc0ff6e1b22eea556d4ff0ccf89e033cf1cf5730a08ef8503ed60e6f884b083a316c0f22f80373f0213b2cec6a0f63130e09546c" },
                { "si", "cce3b7ba236d20284344750ab3172d012b3e76939a519f28084368c931d5f66b8bbb805db924f8c2c5ac1d24f7ffc9e3aa69022389fcd1cd301636dc44c3b1c0" },
                { "sk", "f315539e805156281c9c563e785865667cb2e0ccf07dee7c3f55d52f790cc791dc6266ef135b42feb329adba25c3079dfb003710b3b8372c1bd9d1a274fe769b" },
                { "skr", "422c41d9cfd6117e5e83d8dbf1c6613014515d92ecc1a3c3eec892d72e263109afaddb8a848c95a2ab9b60f28c89d67c9aaf25d0b58e7a9fa1f9178d391aab92" },
                { "sl", "9738b1b63988c0aad1a2b9afde1eb710f468e9451622d7ba2947f183d546c5caf849b54c0bf30e068953b83cc2e7918de28c15ebc219c8d6509421edc513020d" },
                { "son", "e3e4b9c66730c8853855dd0a6306c12cba1de64a1cd45b55fe681d8a4c26f39f93ede1bbaaa992a7f0f8bb869884855a7f4140f86fa83313a306ebccbb5db554" },
                { "sq", "85e2149470c91079e21606c14b545e84875262fc991fb63267541efa2ee9ead386f38dd2ff245ca069ba2c155f013ceabdfef0f3cfc70f01186c6e68f221ce9e" },
                { "sr", "3abb78bc10f73ab1a3669fc3501ed59f6af4d065797c06b1734babc8486e21760a75b77eeb8ad4996945376542f66ecc84a356e00be65c28fc28abb184c888db" },
                { "sv-SE", "8b3a20004364627202f8fbe01c37a94956d58406eeebba99c0f7cdbbc02522159cc0ea8afb544c657d69a242938f7ed71a6e76c2f3e568d6eb19d2c2ab18f912" },
                { "szl", "9f6d510b5fd7bd4d15f66e121e7a9aaf99f71fb7a2feffa2be668f4c618f821d241aa8efc54b8dcac0a8cd07dd528ed69cfc88efd028b7928233dd56237a2778" },
                { "ta", "db23190ad666d89aaee6f71d693f7e479d59e8920a07d028be7137229fb501f32f0a47503a4e92e5586703ec41d10f8c7b76194f8039923bbf430bdb2cef4fea" },
                { "te", "6a0a467494b68f2b596c57ab367cd2ff8a7fff1f63b5a1fd610525e93f57e35f8aea3f6236e003ce5c843f1edb5ab7973eae2c55cd8fcc9c9826bb343fcaf3dc" },
                { "tg", "72397cd3fc927903f837832794bf68154bb797beb56d618c2887149b4d2858678e1a3f5ab2a573214030d5ceb9704ca6d9c7fa49ef92b2e932a0a43d327d8ad4" },
                { "th", "dfd9a15f984db1bf8c819e69809d21db10b34bf3a37812d72f054d17ad0adabef684dfe886e743779bf40bfa828bdf9c76c2f90ebf21b4fb92f6deb68a51aac2" },
                { "tl", "12007b85839436273eb46775b7bc8eb2653e6fae365eb2d6715319cec8c997b0c831a3bf93b764792719e26590aa762085c8be0b6e56dfed199a7c50a532aacf" },
                { "tr", "4c834c3f574d3121ec0f32dabab562b27be18091592cd918fd1ae85c956acb8d731dc18c6339ae9dcf93d6f6ebe7f49864bf3a298350ebd6466ecf24de78bb52" },
                { "trs", "d17fc08acc42faa54577ccc28f006febb98d6de65de7f07b1077dac86a95d1849f47df01054b454adb63ad6bae590aaf6789eb522fad49e906bb11a4ec9ee9b5" },
                { "uk", "99c0df1a524a86b63d64fb72bc2b21394487b4a386afb712c0434cdd66bdd231097b4646ef5906751b77338f418c5c2df7a4ba13e914a1a8e145eb89114214ad" },
                { "ur", "7bd0c14e485711cfe0d7a768489786b27fde220c4c466dab813f327a6026ec6e0f791ddbfae00f6c1e702a38640ecfcd4ceb3fdfa6002cabb725f092d46b3688" },
                { "uz", "cb4c323d7bc98a26300cb91d3b7d3db591556e72bad07a36456a73267fc923d401d18bb154f1125bf3d489efc25074994a21c4cc1abacfc63cfac731627a4f8c" },
                { "vi", "01b42ea9798dd09d11cc3afe923cf612dfdd45584929dd620b6c7d326d542a1cfc291a2fd6464874b191781f29867ab615b4ff5962b12abc4f79f20083570152" },
                { "xh", "50617707fa0acbfea81b0ca640d3659d1abaef0809cf1711cc37f9867f5024cd0e68179d683d1a157dc248e594b09f21780a396d8da33eca01352080cf298c86" },
                { "zh-CN", "8b4e7c4467fa448a00f181a92d01831db78a7c07a91426415145109f8aeaac6160f4d8d7b0f1e1b2384fc651211549cc0aa6566ae04e62b9630d12ed117a21b9" },
                { "zh-TW", "1df4b78bc8c2706c0b5c35f4b0d5b69059d9f1813c7349ac4c7bbcc17369a4e4cea8d58701d13cd6d5dfcfb6021db437a941cb6435de1df8bf2b457028e3bb5b" }
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
