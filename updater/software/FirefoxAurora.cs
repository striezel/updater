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
        private const string currentVersion = "144.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "fd296660eb386bea99573f6a7ef79bcc6e93e6b69492a83fdeecc2ce19a807bff64a2ccb42594bf6ae4a75ca64279f51483c8350fbc89b5a464b129f8dbf323e" },
                { "af", "e1c41bf4f1630b81b3eea5424c49ac332b697ee460b14a4ebdde140030658dc68a55182c9facab7da939c7cfc22873a2484be7fcd1eec90e1a1a940a8cb8dda5" },
                { "an", "7e068210d530b6c873723e81dff5f7f3a6d1558d67bef5008e1de3bf516be9edd249660338955a15841a333606a2abc6f922a762bc364838fbb67db714cc5618" },
                { "ar", "046991cd3df728edf4504c19aed66c5013796b3809bb558400aa2c1443bf88b379b77d3e1a9a1fb7cbeece05169265d9834e4f19249983adeefce96473ab1b06" },
                { "ast", "f2fcda1250b811432573b9bb4c194b8bc943f9b91dee796d2c3c06f654a0bca3984644b0e08feec0369236c2af2f8bc24aa9e039d1b299a9d709821de28c2a71" },
                { "az", "422becac8703c9c54d4ed8987d0d8e2347462351c90b1351d9a985d838106877088dd03a9dcf56493701f9b4e99aefc31a59259fe7be021e7400df60fe1670aa" },
                { "be", "a3b37b0a4cec255bc8ca5326dac0eda300fd1473166d7b2408d9b557e1b2dc7b7345091702a602f8f9459bbae36949122f5a45faad21d12bac94f82f2e3efd3c" },
                { "bg", "db0c07e943f0682fdf5a1e105a0d5af0e09f913e6e5efb23115f8ce73e407241fdff9c215724f96183480439e7487a47e61d22d68adfe67e2dcbef0969607954" },
                { "bn", "852cc5b68577f7f2e911ab69e1d00e74cc806adcd05b3c915f1768a1351bbee2e37d2c582e1dc75d91d952775927016efed43d199fe144c259188efe98cbd22b" },
                { "br", "6438b515a6f6226b2213350c930d22a406af99034bd24d10d8929755fb6ae57a788d5e98394fa0329612803798e6cdc96c8c26c467e0ff12c706d26187143c4e" },
                { "bs", "6cfa61fce5e626dd1076078c8b2d45af26ad89e75379972ac432fb80b19c27866c84a7322d015d67495a40f3feb8d5fd2e96bf1a426044529d2d4d04e3fbdb7e" },
                { "ca", "7bde457ca61f5363086b97d3a8299088bde01f1c8d5f3fcc619fc649765769fd263b5672b3b550a09e51087af5dfbfe425153d73e714a7ef8f89fc33ae7f3aa5" },
                { "cak", "e62552827288270d514eee0df236111c75f05759d7acbc5c9c86a701fec8a01c8fd7ccce4eda70f448ddc054aeedaefc12fe98a123a5e76255d62c5fa30c9915" },
                { "cs", "1066cd71183be0d9a4ca21695d769dc34f8bdfdbed6f37aec93756f6cb0873e46b8b5411186155aaa252a0153e6048aac52494f34a12b77f9402956d85d88d48" },
                { "cy", "cbc4422bc86eaca1bd57134a6baa42229a170c572f06c46ce998da332950797d7ad89b9e0c7528ba2bfb8e1f869841268085db3ccff9b11dea87737ea313a2a9" },
                { "da", "7e68ae84599600ae74223002d4bea878e933f74c125917b90f7f1f86c73a11ef62933ae7ff2031812a109e9262762939f1c0fdbdd6fd1c12186ac2d3b9fcc7ac" },
                { "de", "6d1dae22b1f3694987eb42f139a20355ca2a3fb12e8e29838d9d31f8ebb088737f54cc5a43b320e5964e7c99a16aef05f3733ac349114f11872f44b22b1caa24" },
                { "dsb", "fc80b928c5d8e31d5445630be3305fe9956a803e6ee935865813b2a9247a9139289aeccadbb5cb34cb9d62cc1c1eed8f8c87db7ad401db1a6a82ee9ed26ae2c4" },
                { "el", "62a6ddf02071386b766cbb461880cba1b14371bc18dc41a10f201bae45a6776234667684073eaab687ac988585d5d3a17f17eca6eae7747b590ba46a67f94a58" },
                { "en-CA", "e85b2805c9e35cbee32e8a1ebf12f56f893fcb1d133306b35b223296b69a86bdcae8b840cdb6b8bf1ba5477058608b53b05776397b47013499f224612de530fa" },
                { "en-GB", "2a27df30cb3b11b70cdc00d6589de914344eb1cd3032172d27e2e870103bba720f553f8bc71d6985b63f3bcd9e58515ab2261ee15d690c8809962337070d3b7f" },
                { "en-US", "90b633a3f44c3f38b0d5b8d475aa2d54c5927bfe4a30d763a93e6f7fc4efed9689b6fa43d9a3f21a5023630f7bcb0de16a40d8d8c526eeac14eaa58ff46a5520" },
                { "eo", "06562a484ff00f05ad6e8364e05720c21de2a17cc539330202a5322b027b67839ecb2eb966ae281523ebd8691e0023eff83773906815095b854e70d0b3c3af71" },
                { "es-AR", "0aa05788e89d87ded718aeebf322eff08d53ea3b2d2c5d7214c86215aefd64c906af59392e40092814d327141522bf91ac83b0ec1ab3589f909ce7adfd487065" },
                { "es-CL", "0ef15f8b762bf80a6b8666389084c7f2692b9f46a93a14d1121e4c42cdf3a2b74f48d15ca95f42c9ad28e08c28926654f8a4eccad487f82dd452c7cc56f49cdd" },
                { "es-ES", "18c5d3a33f5a0d5d3e4dc3738a6111ded527f3146140852e21afeb8f9beba3a5fdff217001ef4d72377661e1eb2f3a66d41f2948ba71d896c23b3464b9e85703" },
                { "es-MX", "1e96f2ecff96a8258c8d26d416ab84997284e04d6ab0cf799613906d07ab3eb2f1190e57ad58ec3d9fd10685e9a86f97957746a5e8d105f2678fc88f904b8c42" },
                { "et", "cc9a0d8c9568dc078a4db1011a4ae5ee1b21db853c34a44dfaf9afa0356089e45ecbe9228a45b71ad3185f592a3cf013cfd39fdf4d5c9d436f9f4fc0f858f822" },
                { "eu", "e4ea724b299df162fcaf75b4e0f2429c3295e0b26ee07f748ec8e34c905b94ee5e5ffaaa31cd92b3fbdb4882e758c9bf589776e1b88cab9465468d45d0524bbc" },
                { "fa", "004a0d8edf4a4ec021cfcf8dfa2bcf580ef3d766f762aa92928e8a98cc5881f5cc3e67adbb03cdd90ef012258ec348bc94cd3e46c68f96f12caebd409e2a78b9" },
                { "ff", "d30de522258cae434b36d4772c3a2641228c7fcb3db7f99a4e2753339a64fa77c8222fa534b0b6a43219cd4a8f8e5da899fbf66cf7d6f02dd9fb391fe16b0ced" },
                { "fi", "e387a1e2c83913f0b60e105a9222142c9931bc00351da0ac89e612aa09b7fe17d34fcca28dae5fd6fd215263a8c6d8c8bdbf4796d498a4345826da1d1b8633d5" },
                { "fr", "6af3c4cc80551173267e3273d98054db437910b9f77283c77e1b93cb3c5a67a99a42efc6082b1b86a99a976f04b5e25ef72b1e51a3b2592b9f9432d8e3a0020f" },
                { "fur", "1be2292f1da514b87fd2a4f187bc2b9d8d7b54633474c46065afce81c869cfe25f68a9d3dc33ced9109c98f0c95082814c738b914c8827f6c36a0d336bf97e6b" },
                { "fy-NL", "36cddf30c65e4ea47274a0263a34d237352b5e11888241971fe6ac96510c1fb66952dd69cf8edaab207e93402168b7bdc9164f1cdfb5e8dddc0ef07ae3fcb71b" },
                { "ga-IE", "eb5f3c026b6ed476ad2a1d6c362af247afaf206cf7c910f1b517e79aee13739b16ac5d409ff887ebec514235bf2b97bd42624c9bf4ab9e31772d195a31be112b" },
                { "gd", "8ffa2e7a3ffc468c44d454c400576c7651833fc8b6807ed6dc7769188efbd6ca41177beccaeb2fe65a15890a7263bc56b3341e836de7572bd101eebf78e707c0" },
                { "gl", "d644ec1b0fd993a8696eb8a2fd2fcb0579f62a9c43174e733e0392bc2cc8232fbba5d6fb4d9bcabe028308340dfb5b6ac2b5250c6e354a633b0aee61117a7ac3" },
                { "gn", "4c9f9dd57c12549b37100ef0c8db3865ba887e0ca4b07b888256cfea8f4f97cc70ff7a20ded1e9a5dcacedcb6b92da65b5660affffc489c6de4f3d92e842ff19" },
                { "gu-IN", "f98f420a00fbfa079128e24994c930d9ad890a17a8f41fb27354d671e94e5e31780ce3a9ae675020d172c090d050f66620292966f4912a76bffa404b14aa1c2c" },
                { "he", "684e9bcd57ed9482e504f7e376b9b965aeb7f1456e785852bd4bb6d57eb2eb9e55cc5efd18417dd7b09cd294602d69d4baa7a74fd605c9124a93025d5bc5a30c" },
                { "hi-IN", "5f3645a721ef325d9eb0cd0908d72740fa6fbe30f64310c46ea858aaa00c1be39d3022c57764b9c8d0eb5c872b2f910d14f1be51646d7ad80bd91ff6c45c4746" },
                { "hr", "2c1793ece93f521f0d19e8ff0072d0b3e1848343443aedc9cd4f0e77b9f2e228e8e9ab407650537e6a32d15e8baaab6a5e2b6933be0ee52092e52d3d44e09dea" },
                { "hsb", "7a67a965e1f3afe597edf5ecbbea264bfdb66c29a48c80611c6ea640d62ccf2acec3dfefc25ef643c33cee585ab3d6f514000c60e3e001cb867129e134cb4d3c" },
                { "hu", "43773c7892462973dca4b6cbe81999ffd09e541dd3cb4cf5ddf6d37feae990e431ba021ee4242334d0309977f448534bf37fa592ba3090d4f2c752c7ba566ded" },
                { "hy-AM", "27f4a1ca2b3b7317c9d22ca03b38930d6922ecac318bd83085e0b206774c8acddee07fb7a222e02f523aac8d4980c75d8beaa677fb56ae007ad1c5dcca938d96" },
                { "ia", "b2f9a5e251e6ef40811d9cc9d374510769c067862984637b7732c42e10515a9c898c691eb615761204a6283ecba954d25df4f1421b8b1138f626730d1f29d4b3" },
                { "id", "526d2898957c739cde8be02142240e65fa5e0349609c649c42389dcb233e916d1e851904360fa5f71c2731ecf6caa4d8656615f3d12ec0bb0ac2ff317932e180" },
                { "is", "8c3787ba49bb74fcd566e88f5fc6aebef858cf6491fe07e79b9c51c323c82f947d2730aedc950c96490b074c4f3aec98b00ddb24d75eba93350a45b5e45b4819" },
                { "it", "13c50b20ce57eacfc650de7dbc5367ad2a4bcd06cf030d3b6c8a9b38e9aec1d74d0368e1920ff84e427f9584cda5b40b72353f5a69f0a349052adad5ffc12501" },
                { "ja", "3d6fea92ff3aca14a6c73c0c2da024113bde54b4ad6aca7b2852519204bf1afc9f04c460d28af712ef9ac8fce92deb8df12c9203e5501b0867aed1f0deb9a49a" },
                { "ka", "ebf1e978cdee58bbd24565d41af43171ae6111d261e244171205d2bc8f174ff4cfaaa63ace1200ef6afd030e8814f5e42665973f8a15acf37666db5df76485b9" },
                { "kab", "3a77434b86d09b033deb2b5134cb5219faf88968ef72a3c170326ff52247e9e15134dfcf69f21ce1426708aa3971a1702397cd9966524ca06ba9a184dddff8d2" },
                { "kk", "a39b890dbac8e2d65f73b3776809c59bc6ab2aefbfdd3873619161884f53a1238766b7decd09bd25cc30ed4dbecb0b2b2a05aeec35a4d5b2eec560a26948693c" },
                { "km", "61c33f7a4c85feac7daedb5d9eadaa58abe011f3d6c0fa4c2ba40dceb615967471e876ba6d09bc294b27a293332a593abacfbc0609427727df07db075c201b19" },
                { "kn", "98ee9799a1bccb62978b9143b6422fd78767dfd250a7ff2bcabad801f9a247a89d3451574a4d9906c56667c34353f2fa6ab7294de30ac70bf6da6b6e30d26366" },
                { "ko", "38bd70b087811c4686289a241b441900dac86cd6ad81aa59909fc286c0c8aa859fbbbbd62531f1a844867fcc43afd360431dde95b0481cbb6162fde6d2bf02b8" },
                { "lij", "54e1ffd001dd8ec1cc410bd671cc0c8265478dff4239b28ac9e0a529194a1397a41656196074ea0515d506eac4ae29df1329aa42e429fc7415041bfe10614df4" },
                { "lt", "938252ea38fe194e647878cd048fcb29f986839b5aa6bae8d8b7a9ee5a399f4b1e6cc8583d7fe01a39899b3ab0ec4add1fa79636bce34b79bbf5c462baa451ee" },
                { "lv", "fa808a0ed989578c89d4b06f6cbc1f4ba1c0f915197b0d747ffa5dd80d37e472334e4987c8e3684c00b275911a281bf1a18ec69f118a136adb6f053fdc61be73" },
                { "mk", "4feeb9091f232208c2f2929fa5a26d30b7346de2ff894291508924e8528287270f0c1484665b322790b89cfb8146a92a234913f26189f57f4865cd4a208dfa29" },
                { "mr", "c611e4cc24e617a39718eb1fda352a444175ec582831fdfb3d415022a81a4c2492bd824dd5394eca80a2865460b2550ba5414a08180e96b805eabbcb2257e679" },
                { "ms", "edf005c186a7be433c6f2aea1fded58b0f38d50ce7d742c0aff8e1bd7f7b03ae4348f141fe8aeabb97a730c271f9a91bc105057201a7ffbc11e64ea53a275d30" },
                { "my", "d21f87c4ae3a50d9e7625b156d5df44b416cf2a6d3ae30f6a297b40dd7a2a1ad6f3aac08b7e746d7a15eecafba87cf1e2b2fe50c32de48ff51e2a5f3b87692e5" },
                { "nb-NO", "7ad7df4aa32d9b7f6a4f58477e4df2c4f84b3a4a74d600719a9bc5b5fa30eeba51725b436c2193472177fbc15db9a05bcde0615eddf69e9e3eb2b08082b5b580" },
                { "ne-NP", "d33cf781d0a7cae3aeeea50d788444f5b3e6266af4ff95e97a72b7c55c712b5950f278db400717f67275295ccf9198de3a4dab199eac94c540b715f765bf3b68" },
                { "nl", "385ec80c92ddd6ffc79f95405b289d9eade647c7e5cec22456b9425c306d098a125ba9bc7542661f6c0cf277e9b2d983609fe1b557a818929dd4304b00804499" },
                { "nn-NO", "3aae78ef648489fe4457c4f8bafd0dc8a6c6b0c90dc0648a834a7935c07b2047bf6aa371682761932e6f3806821e45b6368e11e6bc56b77d8c11071ee3e8b473" },
                { "oc", "ba70b3e0011570411b3491cfbed43522042f29e3a5a04090dc26c5e9af930bd72e02318f10860e173451b0be53eb84485b9d3b39b9179b0d6edb86ffa71dad49" },
                { "pa-IN", "6cdfbd8fdc3850b93a22a9eddaccc233b81711e44b0277872345e67ed34b6b43b7229c89d1d9cf6a99f3cd22e55390ed97affa122cf3a015f622083b0ce6ddb4" },
                { "pl", "316fdd0b96ff30ceab1daf594c6f266b1c39a243e94138f495cc0ec2dfd3d9eb8cd5d9fcebabb773abd80944802e8b9de4de3a321fb82a71eb35f0a8489ac9a3" },
                { "pt-BR", "6867e038aa039107e787db1fc50b236f2dbd47c8d4c9f631fddac09143843155bf2f991db2ff9c05ba60a34da7cfee80c7211750f3605ad3100e14e80871f284" },
                { "pt-PT", "124ec7f99287d00eaf88f6552a8ea6613d8982cfed7a39c1df7ec93c2c461335bbd6fa029193deafb4cae19eb30726a30069479cea606ca2fa6b8d164e0b3831" },
                { "rm", "2b37a2b6b1583620c7a7316aa3ac1881d33ebd56223f9583314d2842e6531cd2e8310e45ea61e61116bc459769b461fed9e776031d53d0b13bcf5c63032009e0" },
                { "ro", "90f87fbc1483f1fa1306e5328865dc299d8da80d7a6e914f858d0cfb041e9d0525bd68d9128a119b2fde773c09e2a350534e2a1b11bc7b38d80443a950d5d3ca" },
                { "ru", "d5064768e53ab1c473a155fdbd8edc165854f37b4e25fd4dcd5225979f75e33b5ccb65ac90154acebcc1226182f4ffb93ca4abe1f4565e32fb2c8820991613b0" },
                { "sat", "45ea2587cf44be2cb2a444d95524512baf86f69383d01a16193beb74ac2bda9ef17b02d22981b15e08e47271d8224462c01282332c2963e3968826def004bb00" },
                { "sc", "3d0f931c15dcbe3d414382ecb5e6d5e227efa2acd5d25491ecc43916f3e33c0f74cccf258bf2d84054fedf940cf249d6bf73e708e3d4ee7d8d6df57ad7bc3e12" },
                { "sco", "7349e703b6ccf96cd3e6f587db6d2c05dcdf2ad5aa9f52d12dbad4927e0c75341085d6ce8c0e99e89f21fb7f182f353cd0511a37d1ff26845b5bb7f7b2cb1bcd" },
                { "si", "aab7c2db1057006204a22827f0302d91b99263414247edcda885864d564d48c595c7991e39d269c1d9afa9daa175b4d54ea9272891be3dfa36515c832a15f2f4" },
                { "sk", "a83ada123407f2212dd6a8ffa021d7994a1a038d88f31e844d64fd5a469a07037f9288abd9685b6c3e88983bcba1c8f68afe6e7e7ff5f3f2ed526390f3ada851" },
                { "skr", "a266150d162a214f50c8d054d29af4371b55ed6d66d7a3c3b0d40a73ccb9a3f0fa9d883cc38882be993da2abf83df7d287c4bd5dc832aa953edc55530976e1a7" },
                { "sl", "5c67092ac8c969c6b595f1e954ca104259cafdae0a98bafde8df86d4d94059e80f396370fcd56c6c317ca16a1bde735ae018859fb6a25ccd09a482bf7075d146" },
                { "son", "848f4a134680f7a8b271634fd1ac40ca5b15247cdf819b283653b82f439fae241fbb85b218b4c746e72bbe4e106316ec4deed38dc78d939aada2b89de5e5931c" },
                { "sq", "44ee0fd9e1c7cb8e24d2dd4895a95ebdaab19d21a63665dcb5f207d05133c3eb349e88bce89ded53be9e2a6a7ae68c6f450509e5ca8d73d550599fac859b6061" },
                { "sr", "22137499ed2ca7e12c04787d75cc6b6d4613d6a36225ac4accc44fb5a9872bb6a666b0e398215faa61a7dace2c628690112c91490d84b3c8942c96b56ffc1f2f" },
                { "sv-SE", "d2848d99b6ca8e52eddfec6794d66ec933d8d0c2be071d863d53117007e13c3a3bdcdcd12ae8534472ea1cfdd8271e51391628feddb5ad7f539a6a4c8c7de0d9" },
                { "szl", "5dbd1b37758205dc5318669b7424864dcdaa14ffa5d1587df078ebe2125b230ba4e0450e2fea7a29c5085cbcb63a91a2bb544376258129bf2b1ec679fa05ce8d" },
                { "ta", "4da2c6a4ff68cb6ef9cdc8e156aea94ff48470abd7b22c37da6f7023815326f27624a4bfaec8e08cc85487f31be944e9ab3ddaf4b5107c3faadc7be622e3676c" },
                { "te", "3dfa4b636253b5018feea0e02a2fe8c1c61b1ff09afb30971b744a84bcd520294dac48739edc81b45160fc4ef496b4fbab913ff07498964ef318ab2fa3bdf778" },
                { "tg", "5609211e2893ef363280d553cf53c587165e127c4a61fa2c9eb25361b3518c79b4df72b0913fd6cae1fc86fda844b9de789f4ca6904c426c0e9b0a98c31548c7" },
                { "th", "32c0242de807386b9147807dcf94c93de81f822b798427d65482170e84652ada2ff26037f5c6aca749eb02dd2511c454fe47296c1e7597893c307fd0b8bbe9a0" },
                { "tl", "5517f063761e222b3720b2137fed9d285cb814cf5433673a14cb4bc0e59b38dc962b763b800729dc05afe15d76621423e51d2e3ff3269240828a1f2d08177753" },
                { "tr", "ba90d31a15fc4e091bd18efdd4a19baec79bcd6ef53861a302fe473025990564867bd64008cd12f7ea59bd5fdae00d45c09015922e4264bcf60e6561631d3405" },
                { "trs", "c9a7e3f7afd37fbb0fe4c6452b06d9c571fcbb5bde2c2056675582e8045c0b5c9e9eb8dd1986a930b807a9d783b728874bdaa87da6c16bed46ff3e3a7499ff4e" },
                { "uk", "2b989b6a22f4c027ef7d00d2187336ee07c2a7ff2f99be5aabe7ce26a3641ec3f46519600ccf24e55c0dccbee0cf71025a15334d59d9b86c150d91b0c059c8c5" },
                { "ur", "4c11a571abfb1b8a072c19d26c8ae7713ac1cbedfd8e0e57c7685ad1ce8247013783b6b9054744b08860297842163ebb79a5b2548a752f97334d48829cefc2c0" },
                { "uz", "7bdaefe5aaa128809c699b0b9d73164d3504d3e5e50e1071d0dd878c7c3fa95740b87fdc82584de03456f02d0917ec5c0e751cc02e17de6514da0d2139be7c22" },
                { "vi", "ac0b5b53814f0f87bf458520e3fe722a0172ffe97bb9999dc3efef7d43e4476cf85169b930ee74c14ab8109bc8cf429f57b50238c448ed2febefe0eed28d9229" },
                { "xh", "e89fee6f910fd20489f7ac00bac789a58d4f4c91bba2adfc791718f2f81cadd338637defb33fff14fb4b315a869559a0605805cb321270a3f55aa6f50bbf7678" },
                { "zh-CN", "9db64c4b2dd3b232bce7a39be6e2019b73c9654f511bef29d32ade695bd53462086076ddd67cd798369f9adab557da06c0adc717bbc5b3ec5ddfd4b794b6795e" },
                { "zh-TW", "affc5ebe9b50b7a44c791131870ebe0c7a89b684197c6b010b8f3007673f4c8fb9db4e80ef432b0f9e5cbe5fb53c5f342022a97336e62f84ccb04f759a192807" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "35920080cd8f5ab68c08b3d32fe60367dc3f7deedf791db992884114423f6e28deecb77911df61e1b67d1490746c727148ec468b6e325fd7f551cbbe3afc142e" },
                { "af", "edca3b07073d160034d0eafd91025b8b0aac30c805cdbc5ae776d17e40458dca7d3b462a82816f1ccc9983ce8ebfe23c11c0669132a2835cd0c6786a33c10d6f" },
                { "an", "d36af1c24ec4036e0e9b775c515b745aa4f625df09fe3053a36346572aa8ce59806f94daef7db0041d30332a33e7abeea9b421f67ce1b5866048108071d87d9b" },
                { "ar", "f548f5b37671b5f94d4ff925616553699d5db173b55bf70301a55cf2fbd8bb957ad640da6697b878a5bd7bd413fb25b888a495018009d7b15857bfb8c4217cca" },
                { "ast", "70e37888a62c43cc444a576dc6db343a1c6543363c18f7ef06c59655c718a1868d5db1c21bf70e6316e73458e0f458d35f61eaa7f906d0b6ccc387dc15cc51af" },
                { "az", "7e658348110d87e2d07815ee5a2f12b8c266545dd5afedfdc0e20408d225fb46f0e78dbbb2c7ef1106452fcb04641d6619aaef56597c84c00e28a509323e36cf" },
                { "be", "d9088d02f21f6a827a591cf3f52e730661d7d07fc77deb6d907a3784ea33c470499ec5419934397cb492809434e3e6b1e3406de796e66af0050bd2cba87ccb86" },
                { "bg", "bd4cf643e66f3c622e3d79b356534e98d7a6a19b07ab5bc82639cc7ebdd61fe89ee0cc1d48a41a9925b9c508c6fd7c684a1053937ac81f0ac16e972a10298a3d" },
                { "bn", "d2a7df552d3b3055d1629a8eb4f81f7749246ad34e69c3ce5608d6dfa010af705eebd971a91f6f55c61cc1f16d80cdfe39675df6ed13e60ad1b1f642db063e29" },
                { "br", "33cfd05b65a63d7011f021373cb5cca3b032a37e774179ea6364b597e6404f2aa065a7788194965f10d8e4fbbe2d065d4189100ca9ba982fc386a3cf3e05656a" },
                { "bs", "c827c6dfd62ca6e46d2c7fcfdd2a8386b37f7288d39cfa99fa52665818436621bf8e191718429867cf46f2a31e16bfb6d821592f898921cc39af9958bf51d579" },
                { "ca", "ba44377e18be808577fa350656d10782d47a24ac312ca05342c38a1e058076f31ea20988e40dccbc7a2586073c356c01032c7a623ae4b68590ca86d50e939e74" },
                { "cak", "53307ee658b23271f23aff72cbdd138736776a04953b616db079629d4221dc1db539433464a0cbf409580c8730e22678fb1984a16c5e5304251d7efe1f542189" },
                { "cs", "8c63f4c906fb0875f68c8b9a779ddc2585b116e9e987e41f39e3d646a9c53c6c0305abfef7ff83a9ac67baaea104ef6e1396aa587e4d97a86f4486ef5064a775" },
                { "cy", "835f696976d93059d5feb6b284cc2df955c7fe769d6a37ae985229398f59e774daee98d4aed19c70d49f1a54fb3592180b00520e1727a7655316d307b0f5aff9" },
                { "da", "0de5d8babec0476066d44295b7f097ff277c5826a934e4751ca7149561348f35514ccb61daa67e6344c20264ce15fac1e88b1694a7c1bd656aa5cb775e078dbe" },
                { "de", "679586e0c0f7b4e10e54f9549b6244dc5df00705dd72f7742bf5ffd104156de3bee5c95a41045c2a56967d65744bff400b47e2e33399fd5fc00bb415b8f3a4fc" },
                { "dsb", "1df3074a0f130f12de527f374b115f33c472689e6827bd86e653cbc631e0fdbf0549cc6804f017ca9bf3e7e0fa2802ef6b1730141ab492c116d1fb3b3c106705" },
                { "el", "c028c9800df3b6f90b0aa945aa5b23fce9057d2a6b9f90423cec098a79bacc93c65a02d16773ead77ba584c2482924f817dedcec6dbb652740d022e86a8b13ef" },
                { "en-CA", "e56e30706a5a0eb82c1dd99a862b2fc9248fc7d0d100fdf0ffe33289d80a47d0cf677ac7eb6b573690435364a4105512fa089a4b0421fe0ec82979f6d15c1b78" },
                { "en-GB", "11251d493799c5a9b41500f857881173d748bad68dbd1958e7258876d59df54bdee03151446ab26b7b01f486b75454e4d5883fa56d6ed8917cd1542a7f979dc4" },
                { "en-US", "1f8afa95b21f3dacfb82297106924f65f415f55f184f51d380f74fcf393e8d6fccb595ae251d2606d285fdda083af9793595a9bffc2ae68a64fc500e55445a15" },
                { "eo", "57d4509ff7f0e0f9afa672d0274c9840fb0323ada2ce3125b0b1367773f01f9c6ca30c563fe53f8f992b2dcdeb7f60263a9bb43a48136de86dd8f8cde422c696" },
                { "es-AR", "a2b20adb1d911d198f5c0357fbecec6e928cec7032f52f2d2df4a90b1697617ec9e75c88f1a9bc972d735f792dbb92688716b47e6bc6c5ec5084d43c4cd25abf" },
                { "es-CL", "1e60a1f03a8488986022ff870ef04947716552c2e2d7245be391c3db0ebfa5175553a9dbeb74e8b7c43ec16feba1fa18c237b6aa465d51df5f40336806f5af5f" },
                { "es-ES", "b85b03ceb7a58e1ecbf31302a298b8b8cf8800ee057640fa3a2c2cf585f0f5acddab9f6d46d56602f1ef3e529ffb0f2a09fa673fc3cdb65c71a80386920e2ad4" },
                { "es-MX", "996f67a52a242f090b0451b1753c4a848f05d77ad132415320a7aed8cab773baa1040b89ab24c72b369d0a76d8f4ca683b8efe2efbed512815691c67772660b3" },
                { "et", "0d7d8f160f297b29a1ae91243b732188c7377c213736829f98fa0575b12b4bd177a79acee4c54fbe58c644708c2979bd3abb72ba1565ace0e8d6da289151f85c" },
                { "eu", "5432837cf881070efdce9c1812dc5584c642f04bab4336ce43eb15fc1ce93607390511a1c2cfbf281237620078460c0cd7486f7763fa992e4996332101e02951" },
                { "fa", "bf3fe4c3b3255e2b0c5bd879216bee2ea7e8db44ded54deff00014ceed7b34c299b35e18b6f44edbc5c54d9acfd54ea931cafd5169a429a78893abbb0f5d9307" },
                { "ff", "927b91bc6bb731368f5ca6a7065266350c3864074ae7496c1111c6586d2b5efb54ead7faa61a79e223fbde9928ac5f551cd7d25086d104958864b1fe9b206f1a" },
                { "fi", "324f6beb0540daaf996b234007fe6df9d1c61fb3c9c72eb6889be39f1abe72fa3de85ab76049a50f5cea9992f448abdbabfdd7a3d629bd58c4407558a546a858" },
                { "fr", "b4854c7545000e53b160b1be4a0015e740c310e8c398ee0bdb8cfa29656417a81e1ed0e1289b304966712d00a75ca457266c674970cd9e3fadfdc120fd19987d" },
                { "fur", "9e769d3590fc563bac22484f5b07f72dc8abce4a5c4453d0711e8fbc28406a9a3f8bc439b6881f976459fa109b9ca51b70395e99ace46f052bad60f4562ade37" },
                { "fy-NL", "da5fbcc3c2a37763bde93d59b12cb4768bf454c81e895e9f402c235b5c2bf12a2f3a2b0ad84f4cb6976fda8044eed985d8d764f13346c6e0f7a2704b0edbe355" },
                { "ga-IE", "69919d195c6a0874365ffd8edd194edbb390d8c71e14813320b552d20606f8964abdde0d2fe954fabf9517f282ec2ae24f1973d23611ef6dbe6662d7ae70279f" },
                { "gd", "0e5ea452333130242a4a3ac1dfa9e5aa495eb92890c4d67036b00ff6f17f12fb20c0ba841ab84a0a7581e025d80c520a38eacead77b6a6c665f1a4ad6d86c1b2" },
                { "gl", "4c8cf91b910dfe87c3b06d9c80b28b1abe38d4c1763a7fa706d9acc4fe256591786eb3ded6e588e33b93c0b964cf0c9d823355fc083256db87c6160feaa9c80a" },
                { "gn", "59484f7677bc2e9ea182866ac682423f09a6f25e59e475b82d0645ca7dd199f7c3e3d501c2e8f03dd2ee5fdee3ba55acd6ba80bbf22ea0a1bba639ecb6e2f7ab" },
                { "gu-IN", "9c4145ed05b528c592a814a855f3db7b68ba56136ea1d5733e220ac8f804e5603794c69d1d61a2c9c63ce9f8bed2a004d935e4df46e7866c623e6dc613514724" },
                { "he", "700f61b3e033fdd65a430d4433283e2af1db23cfac0fdcefa341d903094b8a48a1d270cfda1e449905225df8770e77f122cbd6cbb7904c8645108e84bc9c570e" },
                { "hi-IN", "8a84ef3798e8a915475a697c290f8e9a0612acf48a601f0b1b0067d3affc1492a3460ef8e366771b40e37eba18d1a60e77291f4648f7f9d3bed80274f772aa56" },
                { "hr", "a843bae937c70629a5b53961c85e0bb3fc9098f2e4a262debb11121d4d40d325ec33adf123b7e2c07a8b37f8cc71de3a3117400188456d6d27d0bfa918c84ace" },
                { "hsb", "70790b5e295c5c4af31b4f9f85242d95501975c551213c04cba44bfdd2498db698f3ab2738798e06abcd587436e95305c67f9ef5fa6a7590836e38b8e58983df" },
                { "hu", "bbc7cbf704065fed441c311e67167e6f2111848dfb0b66d7546aefe2933fe9fa8ac56dee9c1a45eb19aaef14b8b7feaa0262e616ca02984042ccdddee3271647" },
                { "hy-AM", "d272903e169b0b82dbd67b9b17a3f501bbdedec4b48930b6a30b00948241903882b60e2e86fc95ea9c1becfb9548a732456ba8dfc26667ac622715eb300f4b29" },
                { "ia", "d164186cbab5b218650654217ec8bee3cb03a73848da4444495e1d19c405dc8ff411ff347c3d9a450fcc1096b6c76fd5b6941997017f440d5207062ffff64211" },
                { "id", "b8d7ffa367344dccf135dfd67a97fea99c9d66417490b01a6dc9bb5e087092e4c1e66d26743aaece93d0d929a1a3470c00f532e449bceae1f353e6a32f770434" },
                { "is", "f558117bec500838743c220b29abe63f3bccf8cebff9ab087334d8ac7f2fd80f065d6c17e6d3ad9d0e0d18357b2a47f58f332e06d2980aa7697cdb2e66ffbdce" },
                { "it", "327998cd197e45702799a5a781eae85e2b6f117b77516d3bad16cab986dd8e06b96bfa65b328abc4de875423befab29873580e990c4ce59b72b374731064ad92" },
                { "ja", "43314cb650decb25e89066c396d1cd6890f16641c1778d582f2decac18a1dd6bd3eca85540715a563bf74e1daa123b00895264032ee6d508a28b306855754f14" },
                { "ka", "cc9bab298920b4c04341fe039e87253f22408a0191ba7d4a6ca1ae40d7c9253bc110e8535df63a272749ec8305c8e256953f46a2f6d7c2f8c80178108965d19f" },
                { "kab", "842b54b958274b1a04f464b9dc571f98a161b533c02ea0f4094038fee19aa32f056f9f5b4d6216ac5696f2298311f1baa1da7e1fc34ad7ada551bce3a7fab2b2" },
                { "kk", "6bc1db7d2e0b22c119265a36f4793ea888a84b8f2bbb9c085588bb7773131375756e888004776558d63577bca75d5ebcc2de067363b4232e0bc3021657803b13" },
                { "km", "7878b5bb5554933278bdc9d597187af78a4aa8ec63c850cd31999e8a607490339bc65ba97a7b1b444ec3ba60fa6959d8c5fe0e0d08f8fdd3ab44e8b9c2ba4666" },
                { "kn", "75b5bb4bf429376497709f1ea4ad65a6a28e37b91d5fa97cf801bfdc9e63d964b94c7febc30aeeac5cc218754b3d70c32176e41f3be1c56618a26f3f1fea25cf" },
                { "ko", "3158dc63d4f0d5174f8c756e4f3a3a535fa179acfdabacefe8b9a91aa3b293dd6f32268338fc46ac786bfbdc719d473d81efe4bd31908c24cda755d5768a6e2a" },
                { "lij", "5c944cf78aa8aa062c5f8a610f8981f8f6380999a000fa503756b0fefceac5716515ef88b33a7a7fab5edfbf45d867b9c02b8fee27afd0ef8f50c63614402878" },
                { "lt", "a13bc629a1f226a3139234c653ac8aef6a5b21046533a5940b07845538e0f1378af317508ff244663eed48c6e81220be470e037dd7d785749e081ddcd78bf870" },
                { "lv", "981d2ec6f800895b609753866fa6a717628e64216cab107dbc1fb3bf7fc73261204f81f5e45474c5c9b19ff0b734353faaa2c4f13b1fc97704f162b615bbdf23" },
                { "mk", "ee43581a02a7cc84f69e29d693bf12b6adb7871eb8faad20e1b23dc3d94b2bf8ec3947d7294f05907a980186f7edfa9867577b175758faec0ffdcbf316f5fde3" },
                { "mr", "91882897649d1c6e93b9c794ff0c6793b7d6c34d7ef11fab14e14483b23af7b1732d2eeeb2edc5bf4588eba628ab83ea4491b6567c70df04fbb7755a17c7e7b0" },
                { "ms", "51ddee73192712f6836cd80f8942132cbbfb0a6c169e11cd1ef88f2dcb472a4ea8842370ada0bd64176126d5f05eb8100ab28b05fdca41b754fcf421f71cb71f" },
                { "my", "b7e14ea1b410b2d314351b1d98e2bc1df7c3d92e3a831f36b14a78c086137cafdab1d46b4f395c02118f3de159ac1f22bbb32c830b8630b94b418d55f9758ecc" },
                { "nb-NO", "a118f83799f3f04c7ad783aa372704d92d124d3279c9faba88d7dc17b69330bfd60a61107d866d5560d5a8556286d40e77485c61d312931c18a5bbec9649427c" },
                { "ne-NP", "0e33fd68cb72705459a922004fc82f15258cb9902d09704df73fbb4fa7273471aa5d2876159ebcf691c02fa7e639743cd1d719216381d5f4ce63ec4840e45cf7" },
                { "nl", "53e4af20cc46fce746c61fe648a033a1982506644d64c25da202359275d64ee8f861473bda888c10d6898287fc5ea0598a86fcdb853de710b26e94ee0a081ab0" },
                { "nn-NO", "425ae4eb1cb602378d7a84bde9acb10c4f9bf53dd53d2853d31064cefc0a679369ec3815ba9f3d657377c24d6d07a21ff508095c3932b83c56611440af903cb1" },
                { "oc", "4d52f14f7a52f59b444e9303a2572d0f1591e0a72c65ab6073fda80e32d81da50c22627fbb118c027d66216f4db8bb9a4a42b7d30b1ead4bf980691167a81c72" },
                { "pa-IN", "918a8e73dbeea936c1529e4c3c21eaf8e96fa8054ce9923fac383c2099f32fcc82c9a01dfc19bb7d31ac9f1b2f631e8d821737fec44976db168d2091989b3859" },
                { "pl", "b647c763bff6304cfd211a5369635551a45accd1f623c1fbee8035e2edc3f4744aaeb33ab82359f404410a34225e5b7c4d81b660c2c2f1a75de08d3c4e5704f0" },
                { "pt-BR", "1e211fa9c0affd22f7f1cf8d3199880a5c9d86e86d331a49093e5b69141d21bdbdfae2faf6f2051ac0fe989ac9a166b04d82e73ed04e5471ec3d01b4d980f2dd" },
                { "pt-PT", "1542eb597f17a851b4eb392395a6481901b84e6a28a260838ab188e915b97ad26193b58fc91090a1f2004545cb5045752ac577baf49aa50e043c4151a34bed0a" },
                { "rm", "bdb94454ab759fb4ba2a8265212ae0e3142f6e52a91cc78672747955252e05f99e445886b68b0d0c781f06f58da90f157f65989b53ed742e66862dfc856246c0" },
                { "ro", "d0b8037a5d2670cc2c111101d3ef05afd8826af71e2458c045af781c540259c4b2039b00aba48e9533b9c0b805a09175749182b472f4e90ae2763c257a69c13d" },
                { "ru", "198fec04a8fac4b12382ae54324b40993ceaff50e952ede6092e803b1d0f7aea36b0ed08bf9dacce488627476aec26e858420f499fb9b52f642b4b1f2c698bac" },
                { "sat", "3d1b8f24a4adcbaeadcb6f871c808b214618acfb72b79e5d6b589dcbf30ecde4e7e75b18e08b5be9268bf57fa5950ee9a7dab18036b07ee78cc3b3c6ef749b63" },
                { "sc", "9a9f5f2266a7df82862dd5dced52a088cd9aca3b52fdc13d6f891b3099e4b50d099ef2522c007588041ed1bee1631e21c351bee43b8e733b99d2be85b4a90474" },
                { "sco", "a900bb0a14246e8db22c3471c70c0ae3b6e14bae154eb797c4efd1dabedc0a28263f8646ac5e3b5b5bd982c86f982922d937ae252b7ab94b5a49e268934f3789" },
                { "si", "228ee8c9077f34b30f9cb27194a65da6f71854770b0e0887e4ab1cec5eac862dd49e033ffb0ec8ae4696108d2db4ed86a03930c97ea138f47ccd3c96a4cf01c6" },
                { "sk", "82d6328eb49ce8619b952fafa71727b63826cad185fa5bbd9c3ca7f7531cf4a40377343eb389370efb84de8aa4becd649cc2d2ee88ceff5c8388818889aa79ed" },
                { "skr", "e0205f88dc238826693d87ce816e0f98ded66a9f3d10eedd4faa3ac92ab5a8efebe8664eac4913f57abb0671b7d52c30e1a2c8663d6afb0b5dcf2b641ea64b62" },
                { "sl", "8548f5356fefb2ed7b0da7e4af86483c62cab28af314a8477a359aadbde4c34f5593d811213038702ca97bb5ede5e6306f03b7bca6f37071820b8c1ec38375e5" },
                { "son", "72f76fe6e8e60aa074ebf9b774d8a217e52a6e93603b55826e7ede3e4b1343dc29a0d9c6b90903c35f8b6f6ff639febd1dfac60a76af2562f236ebb58058abad" },
                { "sq", "084d2cc086f2f7f766733668310481a66b0d979147e23f317992c7864b47a0e8c66a6e97362984c58b64dbac6d9bd145bb1745635fdc37857d86d90af24eb3c0" },
                { "sr", "61516e9c674db798c76d5f91d656243fbf9a0a20f8f39cf03279fc150e5c92525145e8c54d9f6147ac807f9d9c7eb6c1b37538ad98c8f32fa61b8b10b1903291" },
                { "sv-SE", "ff3a754fabd201cb03a4f7fb3613b33e2a7d005678cd63246f1ca18dd455c5386df65cc2fa18f5710aee822021be22648af862b934b54a3f6f7903d138cd1af8" },
                { "szl", "c0a873e2c76831369037c7590040d2490e0d5e0dd8a7fd280e2d5c8f9a22cb8403630a61f1449e1c8ea7892ef272156011a763d343fe0a887df9bbbbc58692c5" },
                { "ta", "b44d60c5342990d2e1eda6e6a8b59333c1e8cbed1200f1677b740fb79ccb5dba304a7631ec9ef3f43ef98e9b5febe996a4a889eab155991f3e0220eba5c67e31" },
                { "te", "049937fe5fe623efbe65832ada9e20740f835f51a679d9ba6e9a0ce9eeb88669b98540a71a464a0ed87870070247003d3016b380a616f0310044e96f864d4d5a" },
                { "tg", "02a00b7353e1b3741bae21494164c8faeccbfc1f9be2a7e226577cfca065b15bf40d53478854e83436d843f7695d9cafabd2696f57f9a80d5db265db239301dc" },
                { "th", "0807792c8fbf0756af4f4a9293b083029380797cf0da34af5ef98047e2fe4e1cd64ad9973ca75331c0c741557ddaf2e678461e76171e28485fdef6aa85592456" },
                { "tl", "b72f62c50fa24f4ca2b8899aaa4e67f99f0f535a7d2229633b20719fc79afe0807e7c7b886da0e5737d73b4a0a18a6157deb6d3445d061ee889d969fe996c5f8" },
                { "tr", "b43c0c6e53fd546b09165a7f094663992cf89893d2a96c06991d80ed1e1857a05e7749392a8add838a4456e7cba5288d41507f1eacadea4010ce5d122e629f1d" },
                { "trs", "30a067a916ec3a4340fb81fd9ccc3485a866bc66662a8db3f5df81400e68a755b25fcd4f56183428d573c53133c9a21b7eeb8fdc7563c1d02085853c55d78c96" },
                { "uk", "6e8eb76a220c8200cff941fa7daaf278a921dc8891acb644c37f10ba39ec71fa0d8b8f315b000b44c0c46a9d6e8288364930bbefeee8fddd11e54081e8534429" },
                { "ur", "a62505e9ab4d0cd5251b0dd5e503119331eb12cc0bcadc722f03b22b2e2ffc1a3d69a890432ccb71ca36e52bee29322e31ec2679afb4c5383ef6a56a0da98512" },
                { "uz", "9e161737749211c3911197ec1caab4de0cad9d71e30fa740385cb153c7576fb9455a1355b4d0605b01e3c305d65e42d6609df46300a929c474a21009271e942c" },
                { "vi", "1b20653f713d7e692105d38954d86f80e0ba11432861c0db32ea22b9e2dc9bad119cd29283cc88bec9c0e2213c0d056cf9da104676c0d809179d10575ef2b375" },
                { "xh", "1e68afbc89c04ec31278636458683243006a25944a619e28cce731b1077a84ec8ce9b437659c2f79f05a52fd216fbe375675d7ede5ee1e621311b5f40b870ced" },
                { "zh-CN", "cdac00bbdc251c9693e6495042122aeacc52451b5603cd31e46cc82b7a38b6876275357973428546ada4cc5f84fbd421b0216ecaa5e5665522b9b8f1b081e1d0" },
                { "zh-TW", "fa0f22c82a9dcb568541e3c5972b10951bf7adbadb6e8b5dc4473b3dcdc4e878e2b7dcaa024e9a134312ef15a41bfb4d143f94468d71fcabe7f19085842af8d2" }
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
