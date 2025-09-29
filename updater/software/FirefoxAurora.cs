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
        private const string currentVersion = "144.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "15f0123f50ad0eae56ffd899f69cfe1f809dfc36256018e977d7ef4cf0d4d42dad820efa223edce662dd08e3f4119b9da753d5ddb0aa957e2decc3846536c3a7" },
                { "af", "09308bb8f16e62c76dcbbefaa0a852c2cab7406e8e09d5171fa7485ccf1343870f8a3f19a03877de034bacc38e212d6001c6e666358f6b2033c75bd25f458a82" },
                { "an", "84831daaedd103b3e5bedf0d78588d4c4fc8ca940c48c0b0313e7ffca7eae9aa8e8f8110559a4b60f0d585a59d6ad20b645147c17f9c0bb6347cc67cf9cf8254" },
                { "ar", "e22d66813581dcf2aeb41266e37ee017c708d349e27938ad7c80d9ae822e16c5227d48fffcedb01ef91d7a0ca24f4d960011cc7039b88025ac27900888754a81" },
                { "ast", "088454cb9b99c5bfc90cf740ec65d52dfb8d34d3dc151cf8ff99118c508bc5a2e38eba6ee2fb6de67d16d0c02488cc6c049679cafc96c18eff334150c8bc3845" },
                { "az", "b174b91623a10079df140a523407a691b5a6cd572d66e7936ef2b064c524ed8daa4f2403d18e27cd093cd80fb650eb79a2f2b23ed183c29502a0eb08b7b580e5" },
                { "be", "7a3a8494197344e93369ede5fa7f6aa15b5cd8e3905f7ced5e7fff4421e01370f252b371fc681df2c09bdd9c9ec6d5d242b1329430dcdb33f29f6e9256a27072" },
                { "bg", "c94e3b1531983cd1681d0922f2d75b24612c153f1e357dd208d2556ebe15c2c09c7662f8742bf79338b33426be7099deaa4b2568e9742042abac9142ccbdbd43" },
                { "bn", "9b21dad24163fc1ba7043105cf992585657e5ecc478e0f7c537f3133b7c55314420f118889525d0d7605fe2f95c88d1b8adeb5bb43057508b48981f239a09dc7" },
                { "br", "568dd89b3a2bcd1b241a95ff33d69f69f409477a313d48e8083759ae1d8c8952bd990ae009652d3b0219556130dd8bf4b8809eff4d00f54d5f640036656922b1" },
                { "bs", "e62c947220fb25bea35a6606a5757cbdcc56ca2ba8178bad07d1cf3c0bad230b00f07a025e14cc9cc5fcb73dd82d6eed1f45eb446c15dc7b09a983171b701c18" },
                { "ca", "5c79d918f161e9d75c330d9897f763494ebdbf3b21be7f5fa0ef2126451ab953b457d0adcadcbb0425c64f2ae29c502f59e8cbfae53cc4f70379902c68a9965c" },
                { "cak", "46d34dd4b5919ffed984e7adc5fd61f2792eede3730e0b97cca172fd89552ff4f7077078b8bf23ba15091ddc27ca47aa1354ec066e10246e53c3c969176e752e" },
                { "cs", "a4c45f3ff603eabd014db5e34a2b8cf0f1353f26cf0486a38d9309cc6e3d134a9d88742fa11fc66c7279b54ac162ceae834fab2ce526a85de712fd3e1bb3b4b1" },
                { "cy", "d4f20937b38c235494b9cb112ad9a3c51e4b41fd83285e37a96651e2d6ad4a75a3b6dd71bf6ea926939b88239e5ec484dfe4bdd12ff53609de61ec48f6d47e82" },
                { "da", "1fbcc375acf66317232088a3e992dc7fd9c55c6fea5c4ed4627e945fced1a53247586b2016f09f9bbb0082f30d421c174eb49267837cb132c5463e4a9fecf1b4" },
                { "de", "4457f74462677f01fd2fd530b51e69f6f714b9691a3a72e86259c7cde22e1214ea5585f60fac52777f851e5a45e887e546bb29c6b2ab83401040f6a6b184ac1d" },
                { "dsb", "6581013ddd6f3cdd35f0df21cc3c765ab7ee028f7f1fc5ef0b21dd8af044fabd4308b76cd2ab29df5fafd695277ec57ddaddabdace6e916a4cb5fb8b5da69797" },
                { "el", "85c7e41a3128e706803c00b180df95fdd5bc5b4b6e1f6953d1cbea507c6531f9e18146947cfd457b3c94440207327c283b0db30afde599e9115ececc85890f32" },
                { "en-CA", "1e518038bee1edaf30fad1547ef9494b16e3360064001c2112b48fd0645c2a8ad8aba50889a42742c73be6b6bf9dee13094723c7715dd834d8bf07cf84c51606" },
                { "en-GB", "d9ca056718ce41a5b388cef0409e810b94e10eadc155d68ff1a0aec5a4667b0608df4db49df8a3c9feae7d611665a76b214e3b38b0fe3f85ace8bdd499baa38a" },
                { "en-US", "0220fd8246c606d958eb514189a9fe7013e7a184ba1cd1b9868d6c47d23a85e56f49ebcdc51fd1467a494b951a0d13c082f1a24aad205e01111ec3e18a833573" },
                { "eo", "df6475afe293cb09a51c51930d72dc1359259ac4c1747eb75bd11b99a37b58588614345074fcdeaee9d52b87c7fbea9c7cc1aec550eae7deadd13ab2c0ae1d5e" },
                { "es-AR", "ae4a64b8b0a4691b33fe908b76aff63c16235e20d3d1ff88d18ec24c079dab4fcf9906da1d32d5c9b83dae38c53b301a5a2dbd17f914c38e5b8793653e26fc1b" },
                { "es-CL", "a5eefe03e04d1364b23ccc39172574753f298b51b0e05880138f130f4c8cf6fce61d36b93682fb6b4c759ae4cb7158a24c13e00f2658c0fdb2d18291b6b5fe00" },
                { "es-ES", "efaa787c253680ef04742dd82c14f235d9c4d8736ba620874c1765479aafd4df9c69e9534578074cde4fee82be83fcd3afbb1ab91c7e1f2c2d325b5aadd5ea67" },
                { "es-MX", "113dfbcc1f6e177b7b6949ea77c7b1beb7713afbfc68db36f329b0049ce612d4ef84555f0bfed5e3df72931f461661180b2479948b84116a17917fbc64619357" },
                { "et", "7fa4e1a90cdee77472b141c69c2bee7c290136ac01d765fcc6e6e0e8c85ae15d254873a8fa00a51ad2be3ba9115b684c296605c0607231be6f68a7a75d357914" },
                { "eu", "25336d234e7e46c061b5039f39a9cdbe9ad4f6121d3b736ac26cb72aa2183450889679f16268f214cbfbcbfd9ec01411b3dccb53e64c39223c99f84684207dc5" },
                { "fa", "e0c37d74cea43e7814126cb091e5e836d6ef80ee75a2e899ba4b3d7be8949925b7374d754b134eca8dd4e015055c3daf13178b9489ceea13f691c7e3ad009417" },
                { "ff", "5c26e2d8260f6ed12f267ec92fefceed10e03817046853e1b07852bc40c1c9062141679a5b903b5ac2d90587a103cb75c0f2a2ef5a63a50584609fadc6ad568b" },
                { "fi", "2cbc4f453a44b6693b5870f43412ec21eba102122267cd9199e9a963d3dbaf32de05eb06d888a65273e294b9a3cdae98a556434df932c798a1e45821d51c79f9" },
                { "fr", "7efea21559e3ee6dcb8728fde8f3fb6853d2d6ab3081c6c65a3af87c2f0f2f564154a29b41908a5f8f2058e3982d3032bea1b73d920616e2f43450b6f29e0244" },
                { "fur", "06c3e2de2a8c19a1c14e33781bab519edfbff65f45a8cacebaf49b8e337fbe08f69823a02b1f6c14e96810944ea3f93e53463401d9bdda0895c21e836dc902c4" },
                { "fy-NL", "a780fb405bacc17baa231663f44243ac828d8ded33bbdeb8d6930662d659da077815510c2bcbe439a50fcca205551121e99833cdab588bbbf9da25ac8a1d8b26" },
                { "ga-IE", "de9699ad2488c1fde4c5740ffd4b099457361dac3bcc3c0321fb08bc3889ce0f14264b62ee5df84343ff5092b7858343315df3ff2a58a9597e59714c0df198c3" },
                { "gd", "22a321a31a3d0ebf1255f69fb1072087e816ad41493cfdd6a3d3c059f4f83f314684c406be748c48c71e23c25bc3c7c023d9e5eb3eaedb1813ee8273899bf814" },
                { "gl", "2fa9578ca32dc607f0ac4bcbf3231ce482bb41cb1936a03aed0a56c6f8594e3ef2f5f1743d70fe8f98ae5f42be8fadcaee89867f8e32be94a202d641a4ece52e" },
                { "gn", "cc55ab833d3da5b509b4db45e9d64234e14d74c9b4dcc4d6062be2e868d5da4e76d66204f9abab58002b7e05969db19ae8576a970528622bdeebd4eddb61740b" },
                { "gu-IN", "6069c69cdf1026877d64f2d57f088faebc17d2b24d4bd6af5f755018d98746d1ecbdf60f98c275b846aa19f75fe23493b283b3c3a47bf9a94223b4c8eca7541f" },
                { "he", "9ce5ca19cd37eb5f18314d1a00985ccc0c1bf348afdf33dca9ec611d16d2e38f5c8820765999bccaa62bc4187b73e57bf51a58fb7e7069eb700f8b0471416c9f" },
                { "hi-IN", "faea3024dfb779270302bb493b69a3912f04bb313b670af99e0427fbf6d8f3e3bad1eb7f46762d8c9474f4c3d45639f8a437ab39892ef0dcbb08243334e43f04" },
                { "hr", "032922ad33093ea2f169c53b968200e62cc1b41312735d552bd6725c37ec60f2e317215c668dc2c2c6ca583217c398a3aa0021c417c1d6e7c8ccf711e644d1e3" },
                { "hsb", "cc2606034d1ecddfc7e13b6ac2befabc9f58a0c6dd68ee220fa2a17e74f163945a9c129cb9142024313ee6ff661a4ce62dccf80d3ad6e3d0e9aec87d2e7c0849" },
                { "hu", "5d03da31d1ad34dc214a0f6957bc974c28229dcc5d0844bcb395a5c93482064e724039eb1fd270c3a4209668f575f7bf0f380d4314cd08585788b80a77ef214c" },
                { "hy-AM", "ab5a4e2209a273d8b3748a317611e6261e4fdf0779e703f8bd0debc9e6d73981d70ad58daf7ff558938070ce95e8b461e0c62dfde91481d8960b2cc4b50e6a3d" },
                { "ia", "e69daf2074631efd482263a9eecbf05c3d8d8d2dd038913ba0b1aaa62a2b2acaa158ba2dabccc776b493dc6707ab73c07f0186da84aafec10b158f1cbd48941b" },
                { "id", "f447b3b1dc4cdb9bbd38b19f19f8d42529ba74eaed17ceb22be9228b44b5544b0e47d71f8b0ef3989229e2381144b78934c33ad37581c1027740c2b36fb1a73c" },
                { "is", "e90a9f912e4dee55af2a291a230588287c8283d6bdef78d254e2862833603813e4841cf3445d29c08c19343dd3a78972d53f65d5df6daa58e52160aea4f6de27" },
                { "it", "48a50c405aa5f16438090c951ff7ad4efb25761e232e5365a1c3d87da2b6dc780013435ccbd35b60e4ae0b0ddc96bcc4a6367f7103bd9defae50c3ae2d7eb38e" },
                { "ja", "89b4232b2d99b9ca99d839b8c316b09192b30b943dc342809acfa2e8769849c214c65f94ec1a3c110b734c1bab82e5cb19ca09585490384f27bf7b84d4a7b1af" },
                { "ka", "d89a3bb0a131c7653f1d0009a761c1c1b2d454adc9d498d908c4c846184ee7ef8a3cdffa86a78702f0f8ebb459dddca7fd4b6e9704bf5edaf3a50207dbca1bad" },
                { "kab", "9df8039a788c167190753046e7f69c1e14fb823d3017d844a13b0427d2674b4c19cc6bbd2fee9dda6542dc039c5ef4f13cb7e2719f0ec01295afcff7e5e59ff2" },
                { "kk", "af42d829efab69d8be59fce8f8c8b9b548e2f44937986876646c1fc8ecaeee439d4e6cac4284ca09869ede6539d9fd968d115520e2f756b9cbb576c7b9132faa" },
                { "km", "7708e784c5e9b266e7f7fc9c7e7ade6eb7fb442358b3b21b30fbf67600ed2cfe593eb5ebbfb1bbcd88a2e6be6db23db27a6eccc6bf62b04e2b6909eeee163d43" },
                { "kn", "e31104e75b2137315c62e21c62c1079d35c3d4751edf08d9f731dda70e32e316db989d31e18d680c03b35ecf380416f92d8e364afd2e1256bf5eec68fbf10f06" },
                { "ko", "fbb067f190c2150357005182b71d7535f4211d0dbe000ef78d06997ead88d78af70e3de54ac0d7efd1983c7ede7e38f25d9139cad0db8e91fd5aee8b1d947ad3" },
                { "lij", "d0348dc84743424e4a6aef9fa9a6a7e1bea81936b72734b4c1175ebb3fb663727537998d7ef3596d35e3b09683fdf5bdd881e798bf3a1417c20ed0f69d5ddf69" },
                { "lt", "1d933ce21c075b4853ab4d5f8778cd33f5058945569d9b71489c5ed00c03133d7cf0e13573c37a66d2be9c6ea5b988e1c9f0d3e35e027782462e6429b89519a5" },
                { "lv", "78d829e603e1fd113b81e3dee1a120a2da7fba5d77be55ad8e297cb47701350f90ff6810a17ba6a7372ff4672067ba371e13e30e682fd770c6714f63c2a5a924" },
                { "mk", "9161b1392c670032fe2ad3b7880f243180e277d47add27bd06e17bf49bfdac13f2d7231ab1c2383269714d9364a366c99b47e9dd7d5f66dad6ad419872f5cba7" },
                { "mr", "a745932cd610e2c60f895b9b7bfacfeb633e7d337a028823f9720ac6aea07c8c30a867a793f92a547e84a03398080b84fc3945f8f5435b1477cdcf773c074786" },
                { "ms", "2ed99c1f12dd6962274aafd589cc705fec657288616bdee1629adec0e76c88e1ec40c7312633e1c0d39ad35e27aa4e4d645c4de5d0ad58b5c1774cca9bb34371" },
                { "my", "4bc6d24e66179ed60aaf1deee4d5d814cc86e52e0f9d430ce50905beccda7b31c8e8229d157de365adfafe307509af7fdc145191922b1066e734f8476ab81d7d" },
                { "nb-NO", "e53d3a377544c7ca3fb1fb468b90a09e6d5060b6c113cf8a81bef68f9ce327cd859fe88c52b82291ad0c5e0aea5230c9c3fc6daa7038acf1f43909a05a537a21" },
                { "ne-NP", "e55bbb768b6ea891c989defbdc41028dd921d4a04249d307cb86901aee7fd389845e7b48252a8c080079a1e8f2dc79d9a60d98cf6d49f524faface642c3bee01" },
                { "nl", "6a100de1406b4cbc7fe763a72f44fb874df297ba9bddf645aaad8fe42148a9484a8da6dce759885fca44a792d1141212f82f97c08cc7983aaa30f92a987662fc" },
                { "nn-NO", "9f8d03fbb92198f1010cae64858c317b50e18ae2238302b4c316eb45c3a3b6283171ff5b2e1ae57f6fd983f8b344af05f4c8a416473996b30f0bae4b1a442d32" },
                { "oc", "39b9f93f319171f413f8d8f6121df771249bac7b7da0e9fbc5623670c7d7070297ed2b7d732554219663867b5fe07fa907b00533ff9a6547242246c9c73b1afe" },
                { "pa-IN", "b4f4fe8c93a94d9e9d3d3663c4829fd8e03ddcd0619584b0d9fda977e07213a5c4658c01ea757b294a61aa8383f34209d361c9186e02dfd19eeaf9522d451b55" },
                { "pl", "46c19c849d64e09b51c636e810e48cc939677f797c116e5f25b96c4c92002adbacd3813548415e74d442b55caa93ea262262f53180853f748e71e78548f51f18" },
                { "pt-BR", "8b24b27f94104e3c164c88beda7841d2cc7b5ae9de95e54ef870cb14161483938caa3781d9289e4dc9a2a98f80852485735ac066c2e89e59a2d9c01ac7f8ecfe" },
                { "pt-PT", "1ba6a012b40ae6fa6ecdb23b360c204fafc8da951ae353a68ab6159b62028e51c57e766f4b15105ce2a37a254932aab09bb26b7bbdcbc4f23c3bbcb41cb33bf1" },
                { "rm", "5d5a4e2981fd1629952fc8efed2839387505e5e05fbd878b522fc7db9178c0e32c4c6bc40f14558b7d19c7617fcdef939ea259d8dbbab68447b59b00368959e9" },
                { "ro", "509667edf8df41a38e270d4af0a993516dcfe6fcbc6ce2598f86d0fcb24224972d7107d3869c50dee6b8099b355e80b28c18eb7e108a93785a91f355276b708e" },
                { "ru", "44088b053d8d202ecb67ca9bb87fd479700a315dc70a8c168da351d96cd4e4dacb63cb967a78eeca9fd4587e99e92ccdf6e529c6a2d3df65dfb4a4c9e5156635" },
                { "sat", "b43e7a9179af64104b68df7b5826924df97eb1038ec23ca63ce90fb321affccb4a28bdac0cd420217004f367054d839eb5a7b0d41c06cfcad635788d488456d0" },
                { "sc", "c987ce4b6d5fe182958abbb40bb3479c19c8cae41eae08aa7140d6f8583d521a838ceecb706d9fe99d073b3cc5103d50c04d4472a8e2db5a454b4174f60aa0b8" },
                { "sco", "92348727fcb56f695ea2804833efdcb25b380b758ce54c7bfd6e94761c4ecf03d0ac1b9799b089d065bf7411ce59d944baf6e2a8417b348d6f7d619c60ddd08d" },
                { "si", "e43a357b7d6a1ed25c8b605cfd3b08fad09fc12f2388490d67a7c1a8d1888f191c50699a0e14ad69d812d1eee53d7bc11a151c81f688e3006eeb9f689b07f9e7" },
                { "sk", "12a22231528a689084fe1522320089e393b7d6d2c36bee2bdf87dff27528e23b464d509d1dff5dcdbe524c98cfb538f87347959126d711cc7b95a8489578f498" },
                { "skr", "a4f5dd507e2350a30ee07b02f26dce9424e1334bb7efcac1c146eee9301725ab6015ae158a3e571d1f337099ad2a80f3ecdded910290d9401ffd6884ca9e7df9" },
                { "sl", "b0d0d93e590b6c780cfa56feddf9acf221b59637f72d5da903b4a33d7afae8f29eaa80a5132c9c1426a179a7c2aca2d3788ee896deda1570aa59097e00ed17bd" },
                { "son", "3045e1573d48230428397243c79e2756416eb3c5c9da8231276ecbd5ec198706dcdddfe20d8f50c1b3339e1e1585af03777c9dd95ee76fd0f13373b93683c314" },
                { "sq", "f103ad24b29ca966cdc1ea9dd15c56aafd1fe29bbd7fa63d59e04c39f5378e3e0f3562fc03abbbd546947bf4dd9eed5d26fc6ede49ce0b38994e029ef5aab848" },
                { "sr", "736505a79b8f7f5866e923dd6a632a042ce31c51a8cfcf173367f85cc0bb797afcaaa66a3cc2ec0c59a592e259023044ee35875f1f5dfa3c8a513db1d363812b" },
                { "sv-SE", "bfb35657556e3bceb8dc7a8802fd382bd2dd7fe5c40b8a7fbc0bda101d3d32234616cddd321d999abc7fa75dd61bb6840b9b2145cded9ca603291f96c993f91d" },
                { "szl", "e0ac2c07e4e4f4d7bdd4c8aac308077f92a04bb5b8f75d90cb4709514d2acc57afe1d3c9d3847fb8e503868f4106149f765157aaac02a68741e48294644a6bd0" },
                { "ta", "a4af484de854239e976dd0b4452af9d93af8b8a2a0c87200601255536e7d37d695e717c31aa15327389457130c9a8768e36fe07b325a4bb902dc6717ffbe4ca6" },
                { "te", "d901112b4e686c7b6a1e1968fdde1843e225dbc9cc2891ec82291f334eb122a624d1992764cbf14dcf99aa63bd6ab5aa2f0c72ef729cf8fd81bd26f1f479cc9b" },
                { "tg", "33d873f5637a38166d39b741b984d9dea6d015d060ab06f49bacb7394e6d3597df0d1c2eea54cc633085174fc8f982fc70f225c97ffe28f702304b973ed3dcac" },
                { "th", "d6456aefb42ead6271fc975f8b0fba6e8dc65d410ea15007ecc05071cf9e39fa8eebe6fa8c4fd6e63462d5f90fda9243ec993af2c736d10d21b13ab3c7313055" },
                { "tl", "8b81d4e03751a9eb9d00baaaf57a12c26274a30bbd349c87563fe890232582a5067f5446673e09a8c8f43ff533a3a945bed9567fad49319a01c9b11a3c19ae86" },
                { "tr", "5856871eea439be1cf655398ed6114bbba2e1ab7a0589ad2455c5afb1ca77fa56b8764687df35414ba57b77345b158c82c072f4b3b950c6168c27a30b1bbc95e" },
                { "trs", "b6abb1a6b37e2a7c4b800586992e290b9594c8a97fa5cee6fee1480195a0dff18e9515a06ab8b289bcd75046634629f9bfccf5de3c61db1008c7104c07a0c361" },
                { "uk", "36025920b5bf8c6939c5c991660ef712e8cc0dfc1fff3e01e41b482d2800c3d05f883637e434538abd876a39dfbf6501722125ad364235eb85a6d528cd1246d4" },
                { "ur", "b9a1ae3548c5be7501d30c7717d2fe4f798d8dc1ed14a9909c9b1afc3777c17b4bb07b8a4a63536564e77c62274bf94a4cc85ea718fb0a8a31f633a786ae0d7e" },
                { "uz", "e72ff693b41b54650c0801bf1f1d4d4cd7a19975db55746641ca74bc93d30a0cc7dce3fbf9f8859c2a957448f38b5aa2bbd65d09a5064847d8510db92cc6652a" },
                { "vi", "fb70bb2ca16999eb66103accf61b975aa5d3ef0ef52adf980534ac52bf41f176b91bbf107844ee9076394859d9def50f1067a3b79e714569bdc1dcafcf025cfb" },
                { "xh", "9e0912ecb5444752a457be5286c95b0e1eaad73c17f0221cf12f337b6d8eaca53c25892f66fb521b8fcb26112d7d1c9fd5c6e157901ede30049b1852ec726219" },
                { "zh-CN", "e96452b0ea74a655a1579b90cfbc6302161bdcc9978f6077d58e7441d5e0f2e3bd13bcd9cec5ac99ba19a325601523f02d9510d27d2e6bd7bce3d69b66d18772" },
                { "zh-TW", "b653ab445e9e978c0edc99aba21c1e8055c8e61e9b7f4ad2e8c4564cf3a8289dcd004f4eaec253b9899ba4cf798a633987141bfdbf0d8c209746d0868f00e08e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "eb1d543fe746ac595e48b61ea83c343b9dac3784821c9a392a49df575e39d008b15e6ea94022441166113dcbf870d2209648443cb7c5426a1772f20bab8727b5" },
                { "af", "90fac767a1cd659125e0e912259a4081daea80d0e4824167b1ef4ef3334fc52c03e847e7ed3172ba61b2c741817fa0f88a4039636bfcb143f20fd09dbbc784d3" },
                { "an", "f501fabb387abc38bede01ad3332c64095101083e3aef8d1b2c099c80a6ee00b07880332a2837adb5cda20dc779cf10b178f55f43c9bf2fc0e2ca1a5e7472693" },
                { "ar", "ba26866f860cc3fd18f82dea66909cbce81bd2ccba28b4e0a3bd84c20ee2a7e72496c569d806e0f4a01048d4350fb81ed2775a04c52e2c0d1509e3d640f387a9" },
                { "ast", "eeba433ab4ecfa1e08fe4538156466f40552d5b3c8a3f313e7cc7423c5fa854c9d0ee96b21f8354feba14cafe031f6c07bbadcbba0fc2857837404ada41b2bd9" },
                { "az", "0829b629f62ff385d05a44d574e6f7df6865db389819f49175c2ad4cc20574cdbd76d85f2e7dd4c5bc89edb6382858f754c922c0637bddac5cc08244c1a9c264" },
                { "be", "1bf977f41c42cf4b7627827bced8cbf70be87918a058a9e1f66cd78ddbc7785223d932573c92b5148237e8bcf41bc83c8e6e8a3c64b4decf839a6b2637fb3fbf" },
                { "bg", "56c5d89a28dd76cb50a28657690bcfe6b1b3ec10de5efe104e636eebf2ae0d6f0df326f9c9a169a5f634cbbf51ceb8ec4c694253050455237ca4dda1ca9dbc6a" },
                { "bn", "b0b2fe3a18a97ad199870aac825731b4fcbd3d16694f060cd4dc5d7e86ed1ae76db2d720681b83ce8d1ff97c0d7d177dffc3fbebe8a5affbe81d9cd973f0fd20" },
                { "br", "0ef9bc5e6c035808706babf00e04295a5ff74497bd28b9e8245760a8250f870ba97ff5f059dcd47f5f0687acdb3281276833ead028c736397e7f74845e8a70b4" },
                { "bs", "d360581e5b54fb1bb081bd467d094c33316fc305e831fe91efcbf8adcda7f9a3140845a599a6391b8d48f4942c6deba851f69b8e4595be0b2b43774cc2035877" },
                { "ca", "2234278efe4fc5bd9fde549f6921cd3a4803304ad7fac163b1f297cebe2dc10b1f0d09a67f165158a3977d89957998c46e7e0780d24289c5a0a5d5224fae17dc" },
                { "cak", "0faa5f4cb14df29a0086ef7d1cfea95f7083f4754c60488a40e278c4a318c92831215d997cb784a00d0cafe52cda3d1623b035fcfc7efbd2dcfd0baaf5b42b25" },
                { "cs", "b67398e9113090bc6b83f9c8a7c1dcb027d4f4993d690c97399bba6b57e8ca04e498ed31012016d3d010f467d5083ad4f04bd9d9142d19d78f70a381d2b7cff0" },
                { "cy", "a7a6f430356ca651b81e8fa85c4169d6a0313dfdf42fbd75a6968a5f0255d055cfc40ec084e75cd50960dfdc378b2bb53ca4c3cd751efd4152dff65fa19f8706" },
                { "da", "64ed0a0cd3151d1d017b27ccb215b4ef9b3c883e48c26f62754a13c60e25eab1fb3ed628358a2ad23d7b1a58747331bed97ad90b618a896dda02aac8e396c3fb" },
                { "de", "0b9ae24c5ead27d8954a3a93b050bc96eb0603a5825050ba97f0726806180410a6e56737c8e3fd48c52cb29ad04944d5a0941e02fb4309a55dfdd1987f4c08dd" },
                { "dsb", "daa2419f91c180134c7b9d891f1741b83dde0a054b20fb3a9c407bc5f7a3e37d977a4148feb2d215f54decd92da50baf9e7cf2df1a4b34d78d15e9ad5e827e54" },
                { "el", "b562f21c32557a493416c02f0158c0fa62d4d857d4327e01955281bc257d66f0479d6b9bd6a56e9851c2a0521f0598bdf8f6046d09551addfeb038559ff3e0d0" },
                { "en-CA", "e33bf6dfbff7929a46e7cfb2e9a54a6f596e7e0fbddf47ebaed8bfaef1c9987c1fd6ab43256c3b3406f3e5e3837901bd6d14562198f9a03a0c7a711f59914c53" },
                { "en-GB", "0df5ea3cdf9c2bb8f538d5ee0a93ab5b1371dc46e67f5c46b8134190c53b9416ad995ae1dd962d3db199bfef02d5eaa3e93ab77052f9f2dd8887c4c8b152b8b7" },
                { "en-US", "8dc045bfcc5fe49ae73399a0ae117e3d146c09717043d4d1847c06b8fecca1ded60aeabed3988ede4ac90184237ba6def170d9b2b69603e3c8f825a359c7dbc5" },
                { "eo", "00598e59029d7c2a57f27063b2db47ca30cd29f71577838b66fe2a42415cc771e0fe824ecbdb973adb2132146e9a56f40841d57898a23223d3f13b0e263d94a3" },
                { "es-AR", "3c1276bf3a7e69d41e93f9fb9ddde9b0f8281f7df58f94f5722348a500c716f36da7dc6c5d63562edd95c77d2bdff99c2d1c1da20c7cb6c9dfa07a244492285b" },
                { "es-CL", "0c0fa559fbc15632562d053bf500244def3fa22d4796f02a47ae35e39cdf4b7617e9baa18d3599bb518b74123d8fa2c657cdea2fbd8ed1deb4f06ff3c940afdb" },
                { "es-ES", "2ab2904c0e2d59f9396c902292d2202170514979dee8a2a1102954799fa3ce0b128f1da8111e0ceda65c44e0449297bb0a2f217a18c6d23b0115b7582ee7eb05" },
                { "es-MX", "fe5038c5bda7032bfe854c55ac5075c46b502f9958ead35e87b49ac8f32e786b6310e82446e51171e81d38ddf506cf4434fbef1e30d79b2924177df5686b2e48" },
                { "et", "af389c17c753f7d1c6f001e64553b2b800a763dd9ba6fdcb0f31f888b7ac8b9bd3da0817b1171b6b9dd26f40c146e7ebe3f8834968842e004a99dd45f4f4d94f" },
                { "eu", "b6d6ed1c0634c7ac1d3de8b08bc4dd930867cd95cafe1dbbb92a90ecb7a68b00102fd7b6adc42e9c0c6cfe61a96bbd1fbe79d5cbb2374a2d27239cffa15bfcf9" },
                { "fa", "603fc0861792719fc5c7fe7b284e5fa1765fe05d2d7eeeb4161e14d352644c9ff398e372d8f98f174b9c2948bf7d9b27a031f8869046b4c176d7d4e600fd944a" },
                { "ff", "b92b44d8029ab73b9eae14a93088baaa89a52e9b6d983140c969885e893a2d1e4a69bf0dbdb19156c629d427a461b0e9681936b5948c71330f1d9d7b5a6cd0ac" },
                { "fi", "b535dd654245db06e5c9f9840559c346ab1654b397f56ae02e5431863126fe804bb2b9ab6e6455bdd326d1834c96cbc16539191abacea89f7b5971820ffa54a8" },
                { "fr", "52de9bbca310beddb3457ef8f109bce08d343bbc83d75cd66584f172959537df3b1f16c64596a75037d6bf0a1cab0afe2eae9c1c4f5dfd86dab53573767be47a" },
                { "fur", "63fe8f93f41a81183425b98c08830cac7b1828c93e74c98ae5ffbad3952621706877c78596c06104683e9b85ae58169bd5d15a5b66ac12b92a998a452463bad8" },
                { "fy-NL", "6e647095eb0c6bf1f4b8352465dbd0fb4342f038d3db8c17ccf3cc5d7f599b23c77c0f1553d593437c7303a7c2bf3f4a946c8fc2170b5be0e7727f277d0c330b" },
                { "ga-IE", "a86f9ece9a40b08b1e69bad15b46774fa70a10f7b1b1d2d791495f41f07c1c4e99a1aee7a3cd4925ad93a41554758e5f195736b9201c73b2d67d7f5c84fc7c9e" },
                { "gd", "56dae1ed06be90ecaae0f243e2a63580f6d8a76e74eb7cc19e053d327be718d1957c3a142a0a68a85bee5dafff2bb529e4ea5722461476e6a320d64be81aded9" },
                { "gl", "89c0b8a5088698595305b5c2ae10cd573a20ac074a448be621e94d25e62138582649dd7f479103c5a9e4c02e938cbd7feb1eac15fa2fa73e8047ffdaa2062514" },
                { "gn", "abe6f21a184dd2819d23caae91dcb3982ea2437c645b6269ea0ee152d6085d9050bf4a849a3f1117aa859d35da940e85ad0908b1c9e2f964438ffc23de5b1606" },
                { "gu-IN", "0375a22e0da70296efefe435e4842ce337949ffd57b6241eb27e174619da25f5c24877c00f2ea3648e25d4a850d5515c2a352ce94d53c641575b362836df6e5b" },
                { "he", "fd10f44e67fb41ec51e7f8947700c4af63629668d177a11ddd7c011f605c2fa59a22f62f79b341e783f3baa3427bb3f0e6f33dd059cfcdaf19335757d8976a74" },
                { "hi-IN", "bd5bbc3d7f76d2aa3ae38b58b4e8e0a908cdfa060187a76cae57a4c18f9be65880efa204526b3e3420c2b993a6bccc4d0c18673d0176c92da9ae9b62eda49f6e" },
                { "hr", "38d7eb8d7635a49d42dd8f3c52692f4d7461bcf00afd16f3b4e34a343fcff57138ec92cd80c97da1182392675feae6c1604bd3f5078db8d628e396d23fc58b19" },
                { "hsb", "b05f847db926f8fce0097d01811ece071b9d8388e973171357dc133338a902728537a9b5fd33696e60e30f1dd1d1b8250b68ff06a7d4e7b82258a8674c0a8df4" },
                { "hu", "5edad3ec0f07d4c17c816c268c91c144e9305f9b241d5a358833786b92e17ff5bb9e10aed8d0b4f391cab98e3c92497c508f7bd81d04629c0a1e63063068a326" },
                { "hy-AM", "d7b8c1f870591f62132ba08a98afc06e5245958d7a002fd2a8b41da83be0f6474fa396c89fd01fe897f56f1efed1ce212e63a2ca3d1b3def017561a2f0417179" },
                { "ia", "0dbf9eaa13b9f417857b993a291598c794083d45812414b63807a843c6f27279b0b0e2fe3e9445ed2a16b918ec079adf13cb47dc91d2ae5922bd757d6f5d210f" },
                { "id", "0c2474a57684dfd96ef0004843433945f925bc46c8fbf9e5637a546496f3c27334a3a8741558ec36b74804782608a69e240f5ff5f62e4cad1b747ac5df98f21d" },
                { "is", "152482aaba4e7335ffebc3075674155e7a9807d7407f8e67f14c496e84560e4831e2bba97e4e7d43eab7a85f633e3ac986667e15d835aa53cdec819670f13e07" },
                { "it", "7c3d3e92607ed8caf17c58e8439e06ccb39821ad246698fc03b59e03670739c3e32454b5f7d4b601331abbce265cacd77762def270f68a18698b4652423767fb" },
                { "ja", "ddbb5f2965ec4727dc0a955ca9ed32f8638ee0e9243fc089f03847d3df1351b512cee6a0fa37cd48f8a83a5582c1c06ccefff2b399a9dbfb35a5b80a1976ad8a" },
                { "ka", "0212fc9f6f26bbbda25816d8b77d92a0cdac0c17918e8d5d356b8492a15b82cf9ae81da1c68dec784abbfd072a2762e4aeca8baf7d0abeb412dfdf3d40be91e2" },
                { "kab", "1b397ada98f20d0172b43d404720d6fc17c8486f7b63613bdd3baaf4a85fceb94a1ecad14efc668cc38a77257b6c5c20fede413aea256ddd147a3926d0ff4a8c" },
                { "kk", "ec21ee75e2f56b2fc57881370323c217fff4f889202a47fb03fd13158e55a173ba14c89b4c12e56330eb17838a356e5bc916aae2bbe9588d58dfc6a6a9c46b00" },
                { "km", "517b4900a15ed13f793af9efd4beffab71d292e34a50ecceb166c386a6be27bef03552e0ab20bf70c57534d1d5e1cefe287f80b6f4773225e5744476b05cb192" },
                { "kn", "3d5d0c79058fefdb3ff9c61e1ee994da105c693558d13f46abf253f3509154ed882f5d5823182e74493623ba601e358724455e1aa4a2f63603467a67fba242d6" },
                { "ko", "de68bbdd0cad9dfcfb8f167b755902786d91cb3224189d7ecc03ef885ae3d4b039f5e994f7d6b9ca7b8df4830360dadabb7c05d08b99c33908cbf8afd53b3561" },
                { "lij", "733909cd0f50202a733915f10f04432bd0a7e520c9a427c011ce7e107850fd5e5d0b4e647da53c61f3553d3db4bac23603360b5153d5b85221fe58626f42a176" },
                { "lt", "6e68cdf2f54e7f960b2895ee73dcb373ecf9e2439c5d8677f975d92cf5774b874d1f00a0170eec721c18ccaea5aaf5e02b25ee25b99cd82b301c6529c8a67b0f" },
                { "lv", "d65ab7869e527a3a32ea662967dea32a92dd1036d6751f1e51e5d2f1ef234a9727b0bf29cfde2eeedef287ea0b5ad97931e10e967022945463e63875f5fd5626" },
                { "mk", "d175cd532caa5fce761734206fd3dcb172fdc464c360a4ae837979e315632e32d837058b7b5a21374c8d64a6ce8bcfd75fba67d8cd7973037dca3abfb0b53e3b" },
                { "mr", "10e95f2c548a6079abab0618a57bb34a9b3e2badb660ce142e8260ae3ab810c2227335fb5172efc595000553f595acdaef031682be0c50e83e67548fab8eeba8" },
                { "ms", "2a052f1c9a88d7ff498151c7c48e84141714a2c698705dd6abd2fa159cf867c77fa5fc748acfbb8582024d053a8eb5d0a44b019b3bb24e10348676a27a396160" },
                { "my", "4eee758c7c0507f37a3968501fedd2fdfd43db57e3ed3add6a9f83d9de55107c82c7d0a0a07824f1daba21f5c2ced705711161a990b24ab9ae3d1b98f0ea5153" },
                { "nb-NO", "f59a6d20dbca04da1b61e709a484f98557f8e071c1e1035c69248798b3f3ca1bd22b9b7ecfc8a19f83ee5bcec212fd9497568f868a81c6b83c8b8376d6298178" },
                { "ne-NP", "9069bbd7de447549c49cbe78abbfdcd683ae58cd07aebc240e6e30fd6b94a900f42a28c2feb2c36fb435965ede95234abc8caee4092ecf1086ec94b772e467f7" },
                { "nl", "27e01d85cdcff6446041caea33a3cb818145dec1a47156cc485513a0ea1eb7413f777e8f0b8556a2ac022b50eaf46922d0a451de9590894447f6cd24c7905044" },
                { "nn-NO", "907a1b3f371255410856039b01ea8daef2608d15390674673dabbc4e5bf9283183858ba72f0f0edbafe925f689dcc11c6fee33272efc3f6096c3b8563d0bd367" },
                { "oc", "8d63b6757bebe244a797cc987277faa27f64deed47b48e216fdc94c706d16f2d9a0e04a6dc721f241e618ecabb0862d6d7df94f89c80804013e8552d95467ae8" },
                { "pa-IN", "1ff9058ea67063801b4416a0b875a82139800c59af71a31edef280936968d314dcc34fc4e0bd9375a66ebbeb26508eada6b299297341fb620a465a3a1c92ffb8" },
                { "pl", "0c9ed1be874119619b4e9cc69b24fb5f559a60ba530738d2ad804df74389404c13d4c0af4ce23a9885c647a3215885a01cd56f816ce7f127d4931f11fb72a34c" },
                { "pt-BR", "89350163f61b631936a9722f0f96a8edffe2fabebbcc02035939bc83ba538577a0d02aa5b0dcec5ea5cc922d52515c1b4ccdfad4bdc172d0aef7ce5ee2fee57f" },
                { "pt-PT", "f8d27f43b3671389e6914d4d6f1dea63562aac5c78fde02a0c2cf18e7566d47071c04c285e0382632d384845d0706db9a6fc8f855d116270cc98fdccda4c91ef" },
                { "rm", "e4775178d570b5e70ee6e3556df9110a53e170e3abcd4f5016e9bec42a8e1d420b99534e65f2f58a01a6ca7fae6bb8f21f1f02fa0bd1306fa1b44a92441b3dad" },
                { "ro", "3a388d15c16ed21e3fcf73fc9d0673889c03195afa1839b2adb433e9d412b445279e6267b8bdd7f037905c663ec4bbe931a93279fe2cdb51b38fe7774f811489" },
                { "ru", "d03a8d14d73bdd9ad6cb0cff6df942ccea5c446a8060c686d13acea2d27eea41a424508e8d2a0d1e8dc73c3774eb067aec572d6984be1b079b04058b6e0539c9" },
                { "sat", "48db2e465b7f58d7712e1a429ca7339b37cf89a33a971141e9db46de522afd9965d529e515b7da8ff87b4339a94100b21c76f3cf98fa870db265fc25e19bd666" },
                { "sc", "21ab9dfbdd5964f48688c836bf72cb0e8268864b8714b221cad31f1ceed91e7b997d7c3eb54b593327dc8c2c35c32164b981c71b838364af77564ed8db38c9d4" },
                { "sco", "1a1bc446a86c088cc1f16139aec6233f67d3aa13469ea7a16c179264677900db03a4d3e1ce51ddd2a06103d3d68deac091725df122754425ab6ec051801d3d71" },
                { "si", "a516b5f75b11511c8a3d4ab124fdd22dcb0a47b2a6f708084080dc5f883cd6fa131e3f14105eee40454b47c066aff75610f500c4d55974e99b161a5b1a8eb6b1" },
                { "sk", "ebd8bb8b4fbeacdae7ed6aea8f5a674c5874190f39d1759902e55e45219328ef93228d636da14f307427bce06b3681841c5bac9d43235a93c956a58e403f2ae6" },
                { "skr", "3915ae4ed94d19594280f5adc84c8b73938bd01acb3233cc05817d891b26a6182dcb16e164c811e37cd79818ad0487cb6cc16a80beff0109a78b5ea526b74cec" },
                { "sl", "ebbf4ecd3f2d5e3a5dd40051a3c6351544f67d87fce9c6cbd6d9e5f531139e676a3f6a82d5ce1eb33525ce9cf9067b0c0f5daa354d27a3af054c2762f5528af0" },
                { "son", "19dde2cd10801aec1c178835d8a4d11f09a554f2ffa40c288a0aa6c784028c44f655f355a7f94ef94a65693caee1f72d87ae33bca6c89f2bdb823c0f9aa7f2a1" },
                { "sq", "de856a3f45f4a69860efaa77ee4b2f67d7951ddeab8f315329bbb79a63f7394c34eede1ce12f790c7799c63967acbcbbe7bc83b23029e54e9360973e1398b071" },
                { "sr", "fb25768860a7734fc59ff5344fdd6d26fc228807707ea379c24bc3ea03d34ec9b709d05c55282633b5dcb152399d922dcc3c25b26c5b579de36fe8b35f6354eb" },
                { "sv-SE", "893b4df53120839905765b1c514e5d8bfe30ee1aa5759bdb8ea27cce210a157c92de1bf1e0f2255b51d2461e58b5a5ea2cb8758a9172e53f76e345669a10ba2f" },
                { "szl", "2d70d34ba450e6b8d06bd6a843a30ec803fe6ec09abf7f75da22a7038b06a6cff76720465cec324cf2915d5d878e38d7ffd29e1ab32cfa58eb3076a426c7f837" },
                { "ta", "8c0d38710ccbeaf62a68e82d345c3bda11591ee31c87c14e27ed2acfb1ade2632dbcd9c6dc68998c2e52de8c3dd947f00cde3e65f231e991461aa7cd03136c58" },
                { "te", "676417e05d61e7cf3f304bb11d69a6705216b38d884adcf29d8fbcfb0ca0130261a963752f3f1899003ef2f994a8f1d11c872b4c95969755f414b553ca064654" },
                { "tg", "544003e7ae480258afdbede59303d6c9133647c9f3078e132e866570319b31093905d7f1c496b87560e87b6d2bb5fc2356587c37c87273ab083cf8a19c1850d1" },
                { "th", "bd02366261d80ac8e5e164bb6a1a2282eb18cb676b95128cb99e4069bc099ab6a0ea59cc307c84c362e84cccb76daef361f23645fbf5188886c84edb3fb9107b" },
                { "tl", "b80de155e368f8ce49edae219d6f9b88cb4199f8886adb5f9ee2ec0f78a34d6ce8d3116240749c39d615e331c5a07276517bd226cb9ed58e9bf965e487005e8f" },
                { "tr", "78743e15fac0b7c9fecbdaa0f1360c5757b880083bf22638f2d593cf55a4875937a5229930c5e9d81e9100089b0621fc580bbda4fd878d0807f1338070a0b8b9" },
                { "trs", "af797ee24e74c7a2aee6d155258d3e0c9052932285a3f8bd7080cf1aadeb615dc995fab27e9a84dccd7277c968a90d1ef2d1472d10397b9d9fc058682acfaf4b" },
                { "uk", "e85159a5555e0cfed39d1636af4b9e8413d03ef14b9df2d80429529e19eb633cb460908627bb9371b55c5679078ef31120e7f58373e21b2c8e484ec9938c8605" },
                { "ur", "3d4ce22d8978ce3d3d949d9a27bc593143fb703da49b27af76d345f065e8169e2724873b78c6d759dda2287e227acb941141a3881341ebaf82d3451dbc03937f" },
                { "uz", "b603b29ac4d86ba7cc93cc306650df6e73a3ff26e599afee45ad64621040b51a868086bb0e700c93c1887b4bf230515fe84d83fb333c222c8aa287a51848706e" },
                { "vi", "0d6c422856f1c7f2739b6c34128d4037fa0354806528c3646724e872c5f5926ed1c7862e8d9c242177a9caca53bcd9b8e04768ff726fe22c40ac63974a2281b1" },
                { "xh", "859ddc5605d4c89d643f196bc9382fa6bea232e6a31d04c06f888cafb1f0db7a8e55f0d7df0f62e54b91f94c5f5799cf1bafa700f34188945ab9e51e27bf79eb" },
                { "zh-CN", "8874606b14424af8c4c71f3fd44bf8d9f44d11de1719f4fbc5a9f4e5bc45743625e5af2aa61ca052df0d8c5f9a3a60fc88c98c4a808bfc4af39b84fcf636a4c5" },
                { "zh-TW", "ac049b703e515251bb332a3841eb9244a86e6a55d0156f2aff2385a17950a8477ce12dff8216857684244adbaa36dcb2c65635b4469dd5fdf0a9ab88e12662c7" }
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
