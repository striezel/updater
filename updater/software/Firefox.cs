/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/153.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c25064f0663c8642ee0e5c0909f4a4d3e1444103ac2f89bd7081c9b6be872a9265dec3d181688f5d12f363560a4d63da0ec8acd42e0b2848677ffb20177c10a9" },
                { "af", "30900be0a18408f0705fb1f4579d9aa6d8d161aff39bc6256a7d8ba5b09a13c96e2398a7afba584734c602247ab69c6c5b58dff141e78c357439bdb510c8c48c" },
                { "an", "f9ca47bd6710447fb545add26818134214db14f69252de7a5ac2f2f84b0e8437f613cc52160ef2663830529dd24e96716d5213ff92d3a4c54102c72f2b0cf8b7" },
                { "ar", "4a2e997eb7edf9b0ee76dd76b482cba8c63a5adc32d92f47821071cc607a144cfcf5a7a958833d835006fd2b1e0691dc5698af9ebb18d78d08db99b8e8f7c1b3" },
                { "ast", "b9329a7490dfd6bd2c070adec66b47d4076505bc7596bdff80bb54be4da9547956a544a669ffbaeb4d7643877697709116d434621de645a32186337245e2a08d" },
                { "az", "74517875d38e3061bbca7edd338e04f90fc6a61fbd663d10dc29c388094202cf569521fd4acdf0a0de47945c5cc6f265866b407ec602e8fb0dc2c0ce8fecd917" },
                { "be", "7b2d10e455b98f6187e5e9fc4df276edd59a17bcce9381c57b790cd4e074e54f1460d3fe8d3f1dabad876ca1dec177189d36b1cd3d39427c133e193436414e7c" },
                { "bg", "a931e4e3e1c82613be0d5d7a72ff46f38f4917038204b9737967eec56ab0e44770b3ab92ff223f80897d56eb64860ca20feec947b9ca86f6885dc6805458a130" },
                { "bn", "c2cdcc0b88ffa56230532b9fa5f6c8e0f3a715ada7f98bfcade302634e289a2c583f918608903ef0f2be14e2ccb8c7e00ccd7f1cb969eb75f72d7edc57e99994" },
                { "br", "eb737ecee67ef1a5d33c6c764911e051ffbdc092749693b3352b300b1eca1c14d42f9918ce687abe395c7db887dcf721727207cf7e9ada78a5e7abc36c51ce16" },
                { "bs", "05972733d2fda99a92ceda7e3e39874e04a6963e26d14c82fad4a8cf36dd2de61dfbd0d3f0aa0fa4ab8495ca3733bac892729f4ce5c888c666d28afa2e16a954" },
                { "ca", "8dc7f9d9d94bdbf540e784b6171bbc7c9d3b2e85e92b7287722ed699a14565c1105e18b6d28cb44d95a05602e3a6f4533663bbbf8a857597adc2bbb0b7c5b7db" },
                { "cak", "55b979bec220bd73296410e9a21e94fc568bbe233ddecd8732e9b80f3edfac9fd7862c24c6f62bd9aca4f4416ca0c3223f5035132e29e01794fb8e589f999d2e" },
                { "cs", "806cdfe3c863ba56340dbc09eca79a57c6a650f4a6cbf27324ee66c1137cb24b4ec67d05cdc374c12b85f7d1ce04e0923665a629489fef10b8886cd5d3be9c71" },
                { "cy", "756c25c5de2a6efe9b697e0673a1683d2d648bd69e27276a7b02475cfbe87273f6590f1a2af0869eb2232e6eefec55616378b4579ed1dc0210ced66ae4b41463" },
                { "da", "b1348689adbbb64e813e5a329ab067afdee1b7591aa44fe2416cb5b2247eab4360688cb1508e8a350863d26f767ebc2b7eaea0a20b8e47f738bab96979994150" },
                { "de", "d1ed3b2fa0518f2c1e2307a09588d87ed821a09f15f8e9e7b6747cf87ba31c8110a54e4c0461bbd4f034bdf21dcb62d51d0856dbf1a10f634ae661c5a4b9f83a" },
                { "dsb", "8463adb8bd0dd96025266d9abdb52c283b31587d8051cc39ab27ad447d2d826d37bbadbd538c751d525a409416fa72c7b40e39dc84958a03df734ae1404eb57e" },
                { "el", "e7777e842c3826beec2ca24d1a11f651538f170afc2cfabdb326ed8f52a18912b4a22de14962ac524784a5753fd1e9e95761f607ef2e3ff66af922876a096ec7" },
                { "en-CA", "7fbb5a9773203bb765820c02fa532a4adb5a9d5a6393af3d6a2ed9cd4e907a10b326cd3f7ee72b3cd945ca1e24c74f3f4c830025dbcfe6c855c1c8543937c63f" },
                { "en-GB", "bcb0c82fdcb2d306e9eefac98df4ecda0548ded3dcff7f16ec43613b7255fc7aad5bc4efd0aded8af88c7632f1dce1db41cdefdb95c4ed16210ce03ecc71f176" },
                { "en-US", "5aa0060d40d78574e3d4866158c7094097a6df2a5340158fdaaa337cce23e8988bf84d8047ad09b933eee54face8f98e9058a75efa7d5489982e9c8b109e2268" },
                { "eo", "0e328be212c18e96661dc9b4c9d2ca8bf9ffb18a16e0abbdd60e5ada255185853ada5dbf10d742b0b53da6230b62bd58ebd738e9f1cdc39d04aaa4228edb9eac" },
                { "es-AR", "f1c44738c2c35df342c1c786d48ef47a509048ee50184cc8d309eacc0e470089ce492439bd61fd4bf17c1414fb601198942a7615be09f30f6f3f24938963e625" },
                { "es-CL", "e79ed7eda536a3093eeef3db6c23ec31d6517465e3edce2db50152f05921c20ba12f3e8ca599f7ab316305414125e1f5cb5ed90fc7bbeb1e6d0ef13a7b31ac1e" },
                { "es-ES", "cb0fdfc06a5cc10edb551d30a9e3fa735bff308913858952c3aaed57a392e6faa9d995bc26b6293f984d5dd2a8409282feb5cdc8c98c0bcc9b0a740b2bca7d51" },
                { "es-MX", "32135ab8d91fdb570a9f9ac3cc09c09ac5d8e73c46aaf9be6dfbb2064bc7064f4a34c91bbf63b8dd6dbcfee7c7b85d12096b508b317776f72c8aa955947f9717" },
                { "et", "3f35caa1e2875a4b0a1f4b9890416ea4881fb1c5e1497a69b7c7edcb4cbb09e89da36c7c73bc665aec42691a90d933224e1670bbc6319d3541b8aa7eefc50590" },
                { "eu", "c5f24c5997b48803c267294858c4317c39e975a2440b84caf3a8cb61c4fc32ed347cd2f9e6a4437bd3c5bb55185f20ee7d46089780b7115c4bf1fa8578723961" },
                { "fa", "052855b7ace6e57b010985f99a1e8b4d57a9e6b8a498e24c4f75d9c1fdabe5c33db2d6874e16b67a3a6c123ecd13faeffaf45ed078a4c44127d3063b12baf9ed" },
                { "ff", "27d2962c1bb11a8262899a4034c781e9fdb3a6ebc8ef7ab0cccb8761c1a392b1e9f6be2548bcb7057a4d901b9a1a9087e51c73d7ae38905b04295c0f08f5c5d2" },
                { "fi", "b4c5a71ffb02494196e0a7228d1554027f604cb4704b59cbaf730984135983b1ef8acce2b93e94435f185b8c33c4f914efdc342585bcb1b43f932a35bf44c1ee" },
                { "fr", "2ea875132ea0ef6ccbbbea73b8d43c3ade58f495a1c2cea82ea674e3f29715ce0059f3262df5517943c04a0d1b7ce8cce1e22de15263fd9c85b32611f6bf7aec" },
                { "fur", "86338e2102ed29f61544ff928d4db74683ede35adc546a833895907580d07ccea6a934cc89a2f74cefe65676628c0ea99a97fff8f63843e4490012a6ea1d3c48" },
                { "fy-NL", "5c85a2660979b9d2b88fbec647b4e2ab42f30371631377a8f1e6ba9e0f30fc84653629d057bfb8baf990571082b1c482c02e28e80adb383d0e9b79fa58803351" },
                { "ga-IE", "ee6fb39897cfa8687933db4c4c8d8f059454c9114e01796ea848ecad60a1d91af8cad2e281d3f7c71de1126591bcec13bd865becf59c76fed37f4ceb1ebf2605" },
                { "gd", "a0f4a96ba70d9d188d2fc5b83eadb03156a16cf1e5bd74990d2fc6476ce0ad114dbd53d585ddbc4e4340d4b501d85a2a6b2603015e9da60366f22510b5a4cd32" },
                { "gl", "7a46c400f5508cd91418b0267c9f14054bce3205067df0a440c69e0f73d81818a56d55204e161a2de79a7f17649388aee4b6868a0b83e83ff18489b6e4aa9841" },
                { "gn", "bec609a11563a0615fc3d2c8816d519f8beed031ae6a3290ae618d086efdc46d5900363c1309e469d6c89940e8715d29554db7e4c8b0ec4d8f5c50ecf241cf95" },
                { "gu-IN", "560d607432e3461cc5638dfe3516b4af26cafbd40a8e7c8f72cdaa363a3cbeb27a130c1306cbbf0fd60afeaacd5cf27f8ee4b84f3e3537f95d01111060c9889b" },
                { "he", "a79c86afee24d99e9fd25491bf3309aa749717eed1498a924f851f699d0581eaa78776c63395298135433924adbb406fa00f5386fc3a5b1629f1e77e872deecc" },
                { "hi-IN", "7489533d306adc79fdbbc745d14067b3591739ea2a0e72f5f0f717e045245f59fb9263e38886117cd29975c633543b1d9336f8b0e9c1c31c99b7c05db84b3110" },
                { "hr", "15e35e1d9a6f7edb916c47797a57ed28561cfad45aa12663cf4f9fa519f01973b7a7887e42771746870a6dbd272dedff5b1d4607537811da7b83179db0e2d8b4" },
                { "hsb", "50fe6ea012092659ea422187050983a7b4df2f90bb52ee1a54c3367528c3bbe32897cc15ab4ec18593dafbc593b29f43b3bdaf278b34e1e23041e6d546088fc4" },
                { "hu", "af13db50d22720a6b8f74b098770b50470653f84ad0538d0aa8d36a5fd7a196cd75214c939e977b5fa151a56639fb3aa3449b771a8fbd541cac6e865449026d8" },
                { "hy-AM", "1a975d9f4eaa5838a7fe054d11d46cee64e4a5073201deae9d4adc137033c7d14cc6a8943ba0634a11a69c8aaad8647401a26e789da37d739a114c4314081f35" },
                { "ia", "714e044a3350967933dab9feba79cf0e0732cab8c3bc06871dc765217a5e6bef9057bf3e67411ffdc3c1e4d2a25e922714b466e3dc9acc4d71ee53921ad87bc6" },
                { "id", "b7106fe0bccf96abdc41c52efee011a91b0ada81950fdf4f78bc9608370c1285cfc06d3d44a8f1484b4e3cab4e750469807fd3b4c99ef09bc9179b6bfd36d45e" },
                { "is", "6b7d562ec30ee57ee222abcfa5583d4f2dcfc1b7e8db2469061e3d77b19aa3c8b6216b24b2ca1eda4abc5eb5ec05e514130473f078cff4d482eae14a110b76c0" },
                { "it", "f55c39a512bb12bfcfbdb670adb32df1b8dcf4ea3e21bc484b04d81f4b283e7451b391832790963d616bd90de6beaac517340ac74f5e18a993e1b1b5f25b66a8" },
                { "ja", "e97c9b883c6581066e764d7431fc043e758ba6f24fbf2f21684a09c57c3c7a4969ff8de11fe96cea1adcfce955055e9a10221fc406260f16c68065c8136f78ca" },
                { "ka", "c194bfc52352f53ad810bb62fa3160243576d28477571dfebd707c45d7e243e87aea931982bce2043c68cf4370b74ad6c9df64edc953e769d39a709daf475edf" },
                { "kab", "1178ce7669ec2bd03039dfa2cec6bd515ee25a6f917ecf30dc6bed2f4b006b91ffac651c7c7c4edf8d4ed7155189b5b3ae0afa9e098765cf5cb394c6bd3c8312" },
                { "kk", "14ef330c269dcf1e0947ee4cf68f86b2d16cc0c823e3ff8684d2b5c3237252149940f6856fc081bf764ee2f9c6b4ccc3be937c8531a464a710f4eb59c92fa580" },
                { "km", "76d890003933d39670e3d11a25be59268ede149dd0b7ae5d2cbd9387aa88056adb069493d870b0b052a879b875284efd7d9d1692b07cfb292e7a4a6f3e057185" },
                { "kn", "e8e959cd428255c09106864ff1b08273ee587dd59ea27afd4e74ba82b8bd35954fa65a836e5f79d3deefdc02b9140a35345e647d5c024a387d9f7b35d517e5f2" },
                { "ko", "229b241413fc3e8207c7712e06f72cebce12f1eaf7ef780de5bbe39ceedb7d1f74bcd2760bd644dab1aad4e4b7a4d43652d65f6165b91de35742d18a15e7fc42" },
                { "lij", "f2d44ee12364b2e20c747f7c2fa3b993173c060148c202ac422d748dd221dc9c0ad54570fc9f6340e3076421833a5dea0ddb3844e9f0b3b2dc801c7da17f9639" },
                { "lt", "ec14b1b6a182a4416fb2294bea9047560714731fe2ca7cd1a4fc1df1d9d2f458209ed26b7533b34671a64315ba32901da3e1fc2031cf725868a5c2af438b9b1a" },
                { "lv", "1a3d77fe5fdbb97d1b51330ecb3b3493805efbd7dad1ac791a85c2223c9db27e983fb35d82387c33dd80497bfb44f5591b07dbdcac8afd9a30eb763dded13ec3" },
                { "mk", "fb4cec4aeb35569a26cb5ccaa8357dcd8efc0eae80bc148af5426498cc01855629f17a3d18f5079bb73075d28a275d9a58520c7633c7ce5fd26bbf3298ba5e0f" },
                { "mr", "74e21288f5a30f811553d72ab698babcf33d36c024c692aec2fd7e411ecb483ed22e9132286de9d9f6b03b4449b4b0626b4443e2fbd6b0f62684b4853c5c10e1" },
                { "ms", "8d8caad2eebf4fc389f9fc95349d8c4f9d02806d4e8400bad48283209ae18de495a0d43e143ac94f258e52cf59383543366dbe725215f6969b55aec4d767846f" },
                { "my", "2c9d82db6118ea8df51e1363cbd03d9cad305d755b463fe4058cefa30639c06f04372473021674402540cc595a6f433d190d4a3c75cc65e796bed7c0882f0e07" },
                { "nb-NO", "7a978b4326f22015742132491809d7d2dae4adec5816c017ac55c4d256d53b52b021516d8e91d898b9bc560878da297fc657ef305cfc1b1c4bcaead66a95e8b2" },
                { "ne-NP", "9ce0a2d2f30a3d80e3871a0cea7d22def5c982ff4b982ea995e2aea5dee286011f67ae8099984ca3f70bc3723ce0dbb0304c70f7e6d143ffe84fa77158971a4c" },
                { "nl", "9836ab08332a251608c2dd05c0ccc8b28cf6575e5b683ba4e378b3eb2891aef0d1dff5583cf44bced120177e61255f5acda749518d1c9f45bd87979bbbfc1bd1" },
                { "nn-NO", "8b3748d97fa859da558eb6a0e2afbb34e6ac78df56a3e726f225f99d3e4b410a7502ab02f7700706fcf238c13ff19eb1e9f8509f7120e9b4407dfb4cdbc3d29c" },
                { "oc", "43d4aa6291f400dc9aad9b12d73ba37e827c4872fec2f9d713dd8c1be220d38f88afcb41f7aa5b7b2f23b993028921591976bc5af5ac93381b83e855e1ec31b1" },
                { "pa-IN", "6efd6d0fcd77805bb7377fe69e6b94025c95b9a915dd072f181792762c0216f6e11afb384477635f94e308ef0081a2b17449ea816dae669cca60cc1e5b1f9e3b" },
                { "pl", "6944872f1d08e41efe7d350580144c494e92969c48b45b6b8703655e92807def3b531158ff17f7dbddbb95971c202d7c4736b04ee5d785d49697bce1ccd49fb2" },
                { "pt-BR", "dbad0d294c7839ae1527f676571e3355c425f53a3b683b062b3ef974b587a56ba4659633fab9a9465b295828e1d86095bfc6c86411e84e26e436440129407440" },
                { "pt-PT", "6b61dade40be5da1bc86658a7689d4d4009d716e2a47abe8989093a1bebf9dd4ddac80e59f93fea361c3b9c9375a050b0963f546135cd11710b20da8ae67815a" },
                { "rm", "a0df08765c45930bfd8920bd899a917e910da6bc42462889d810342fca5f49e11aa227840003252d124c72f1e4213b1ee970a38b12ca34203de67937acd32059" },
                { "ro", "291e6b49d9e0875239aaccef15feb051ed2c08b89370752a15084dc4d3a1b423c45fe4e34dcf658e2087457ce164dd515c86a754553bbadc8372b79dec0effe0" },
                { "ru", "c869681633b658cc113ece6605883b2be2664d562bee9198928a82253bdfb4a49e3541e86f74bf5b6da15c0077aa10e66b9bed454aaf553a0f815685580b5078" },
                { "sat", "1f2c5230b6ef1ab60c0f67cef4b750f7afdcfdfcbe8f42e602c048cb9f49ba5d45ddd5fe22d76252f393dc4a5019fc52f9001e1202916c4f0d967fc74d17d69c" },
                { "sc", "817acb945945641cdc13b2d8e631aea50a3604cc61c6872808bc8c20d808326de61339e2ce9be117e9fac387bc0bc9a7ca5911564d8b6124d67d72e4d5d1724e" },
                { "sco", "e952bc7a5a943241bdd764ed164396c728a8bbbfc9df48bce1ff9c12fe9a4205d3f104e391f086e34efa6951344dc48d5546436150cdc12c89767085538a9985" },
                { "si", "bc5db675e821eda6fd6d15d0aae97b6d2864f0e7031590ee46a372b2a53f51383225879149713df1b6e3544b8a91edac9d1daf39539cd5ffc5a89699349392c5" },
                { "sk", "95c0d883628b345e4ca7e8393963e198615a42f1b0ace139ae4691656e9faae5d38a129edeb5295220e57d0d6129df8801ba369dd58af033a0faa3a9e4a865b0" },
                { "skr", "74c9155a2ce22d734942d4e5f78ddbee84188027b84ace47b16f52d272af5cdf692859ea76d0c1f62a18cf6b6a8e19d0429c57d7e6b4825f7ba0b167403704bc" },
                { "sl", "bdfbc11c0901189593e8be9d96c0a5afadb89eea7e44eb7fad8a0a951ecd5844201a316ca0b855fc0fbf2db9e6d6a141b818ff4ff8fe7c318e28249c393c03c0" },
                { "son", "3e479c4b56259bad87ea639506a2d0e4d542c14245f55447873a33d205f18cb3cdc1da78a8ecda4eed8f39201df632ec211c69d056dee72070f503dafb2387e0" },
                { "sq", "1dfe222da3c3c234b0e988c6d0c26b1304059b65b59b82b4c76edf4ae6252449a8d50cbcfe0df43f1ed29af09fd279571ef613b5ed25a2739aa9c6916d620f2c" },
                { "sr", "ae2c770cfd27668e756652fb522a5aca4d3e70990e3a1439f1a774f123f6f872f9650faf72c0063a97b5db7cfec4b01a1e56d675ba9a948665744615d251829b" },
                { "sv-SE", "f9231bc9f1c583d0974ff580ca2b3a828f1a0e218ff46126c5bd8df5e523201dd300d85e393d9a84ba1440c2424da19a169ce7e95d14da361bbf21aa98af500f" },
                { "szl", "48c5637c00ca0ce8ae42ddc390cba20be2eee58c807c1f42fdea1bb009b1f103355e575761876a5166fe97e4634a5e6a3624586812df6a2be9a368d2c7230d4d" },
                { "ta", "4deebf3a62391758041ac4ebeb69bd1643a1820968e4afcecff879e2a5a8a694af87c6419c6ec331735566ef34d205b6de7c7a2c49e328acd4f1fa330e21c5b3" },
                { "te", "d7f88e8fa9728d5fa924c01f43131d031a032d1a2413d3d5d48020936532c637ee2722f52ec1d2a78fdde7eca99526b709e77d8eeed236631902e9bb9f377503" },
                { "tg", "67199eb10b54fd24470c600d36ef70e6334e2f48e055cc7d6698a6a04ed222f5b28ad8f4432db2d776d1f4316608a418757c6da5adcc0bc259d95bb27196deab" },
                { "th", "03574f1249297b1ac62ede6000668b3ce42262f8e8566b4d2938eaf3d24690dac65f9b68b21d96c28e3179dd51d8cb4440609c37aa5780b1faad6aa8e9c5e317" },
                { "tl", "58a29550001a6b0083714d26e2ff1cd43937e2328268e02b8c7f9e9ee78d4dc83c968f7046ecf1eb5508318db9117359dbcce624a795694d5df2879569b565a4" },
                { "tr", "c24ff35f974a199a7cc78effaa1283254964c49db3dd1d6d367fcf238f219554149163c5a4ae7937d3c000bef466ad46e39e177ae83e4019f64401a36d723aa1" },
                { "trs", "84e3833c5c13e90268e24f4eed540e6b790b54b4fb1438dde504e8e355c4123416f1de1c4487f3a307705f86ad8ff8bf172bb5b8829c8a43956c0286a8a00935" },
                { "uk", "f9bbde5621fa8a8a822d30b17b47ccde3a5e940bb151c94e13c2f70ecc2fc4a704f65a42e7fc853beaf41ac2cea6ab349cf3eed5dfe60b1296c9dc6d904ac10f" },
                { "ur", "912969e34062cdf2444917488f9d1d788cd8ad604ef98602e5a2d08e10ce6436eda53efec4fcb63ab7252a88850ea4d47221ea80ffbd439d55ff534333944737" },
                { "uz", "ae3b3310c6cabeddbbb082a8c071154a8e07b20c9e40ffbf306857344159a402caf8323179fd28dc2c0c71b9ad3ea1ed25bd07fc23d803dcc57a4e812d7d8bb7" },
                { "vi", "685e35d32509f46008270c75aa223b9eb658d0126358c27e4215a3a3c82abae3645113d2b4c8f7e29465b26d665466b93e8d5ce67237f607594b236786a2eb0c" },
                { "xh", "028e6aab56b275f4ec79bc2191326dc5bb88b486f6d92431b45139cfb08473199e579c959973ec82c748a19aa30a50176951c47ff772c21ce6710418becad28b" },
                { "zh-CN", "b12822fb1bff4696b46a5d2d0b565817abbd8780327427ce8ba3eefa3f428dc219210fd22f8d2314cd711b40f532d1129922ffeb4e8c5fa48b99572687fae22e" },
                { "zh-TW", "4e6524838f81acbae17634e86f5be88fd6a4fca4149215762c28114908bb4f5eb42942c1cbfbcb314302cd96d862702d7e51ad8a84938ce52afcdf0630ffde16" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d05fe8f38acf43139a1fb93ca215876a4c76b1fa28c9007b49b6ef268ad9bc37404fd77494ed4033d0e4bac6ed088b652f4dee1c9e063595d5922b36bbd1ea40" },
                { "af", "cce95d27f7083c0262934887f0c2daddd8f6a6979fcfa117844198cccf30a7968ff47099008d6b8b94c8bd0e20a267a99223a919c2b7e4f82379cbb401bf83ba" },
                { "an", "83ceb629f1a09f2d2b4822c1204dd4713e78f718a0cedc283ac587793bdf5985c55f9294fcd3a3bfc41270d3e95f50fe7694664b54ad85795771c2aa51391602" },
                { "ar", "ee3fabfded934eb0acededddc16909ced9a29ac28c1ef402f90c2cdff7c5623f41a17607cf232b7478b9e908de8ffcbd5a6daa292f9582f7fedabcc5a21b038a" },
                { "ast", "63b804a4166fe41bdd635732a23cbaadb03e1616b98cdac70e9648d28a4c438ffa29065d9746ac690ac897559d53e3123e6b0f987b6a396ad44fa62319765881" },
                { "az", "713c8e8631456b30f1efcd1d6005725ee1ddf7b1da0da2402ee22d98248f2929b59f93c6761beddef8f030fe8f9feff37dbe60899b9cb7c7df39c360bca7e98b" },
                { "be", "ef1c95906259d1abfef5dc4a518a1a7d3cd1603066041f8a63b07ea9fdfd400e1ef0f27c35a6d57069bb2a03310633b1744c36b41bff6b746aeee55afc49915a" },
                { "bg", "5bc31f4bcbfcc3570f04a4c89fed805411d0bb36705fc87f0d7ed8b935f61d764a3de065e168c35e3005a88bd800c423eb5ce20cb0661b6f805834508d9a77c3" },
                { "bn", "ab6df6430baffd7b876ed2dd7263e77eceafd1ef05575606ae4328ee9d0d5ce97625246e9e18baa28adbdc50f4470e8a7dc68122149659ca09ce620afc4305b2" },
                { "br", "095b110665a0d803ce619c71576b32319e623f93e837f9a92998364d7dbda3e59e131fa579321c3be83ffa8406cf1a64c6c6cefe56b216a6b6b8015cd71b94ed" },
                { "bs", "a5deb99c8f7ce28c35c9fe2ec31d5c025807ec958cf9c7f61267783014df5a7664e92afc1aac13184d248eaa881cf7f4815e528c5eecfed0df6f8f40d0754548" },
                { "ca", "8e1f858a064d30513a9359bd0fb12b0b7c24c20e52bceb99047a8dae3176fec886c5b5df9e03579adede0ff72eb16164675fcb0bd0329f3601e5911fd6e83100" },
                { "cak", "fe85500932636feda0ae09265c6d27fa644592174d62984ab74945fa3bffb30aadd67b289b9c4431a71c7c14bd60d5e13ef0f4cd1e7ce326261213a986bafeae" },
                { "cs", "ca964fe2ff92e1b323a5fabd22eb14b5fcd4defb3421f0ca3fdf4a65d9fd293b033bbc4ec85628a08218e02c017999a62c6d5959cda67cf88dba07ed355cffc8" },
                { "cy", "47f0c2f66fb67380dc52e58a6ea213d1a4441f86bfb27179679ea77e40a1040123a303ea7fe2791af3327d06e832414cb4b090adb5d00af393d3dcae1ae66420" },
                { "da", "5144f1b857cc96047a5cd09139ac243f830a2a1896dea5f85f66632646d34cd72d2b7a39baff3f016fd97cf786a516cd1ce6ad67ae1e58c228131c9a3ac42679" },
                { "de", "5917d0118a8b77d04e64a9a6541f170bd3bb82cbd58f78792bc062b60a3d220162844522f2a61a22e9b951406e3a978aec7712a054217b40d0eeed8ed3bef2d0" },
                { "dsb", "cea3fb51284a7cbef5b7f08fb4811f13791d0a154111598520e10ebdaaaba3886cf06a13a99651f37f887db3ddc6ac6ceabfda459073800ce3e836b298547ffe" },
                { "el", "871dd7a318b4edfffc7e32766c6549c08028d02f8c97b3e5518f1689ee7db35edfcdcf9ccd3699fe6ef62b7e8744e703d0d00939fa2af4e3c0cbe41a4f3f7196" },
                { "en-CA", "0b684af10ba8cab370771705c17f23a896a3ac57913096f4a9a92891d16a448698b40ba1d39e9ee18c27c17093aa48b6044a7dbdcb5147075eae45dbea69fca3" },
                { "en-GB", "3d50888b2ac34b35c2096a5db76644d541a4a6b3934e56b3714f93e70ea449aa35cd05de283722f3dc9e41c07618fecc955798ca8c542c451b26eb77ae39545d" },
                { "en-US", "60abbca04f234a535b8d665f5d4c982769b83e7b1838eca2f92906b63bd635aa8eef9b843b2a45303dfc87f1ba74d11941664b84edb5e305d22b30fedc6fc70e" },
                { "eo", "258be3089a5a97655e9195e381b8491bdb3b6fd5ead8497c5f286eb8b26daa855f618e9805aa9ad516ed32477c82065e5a01de6cec6829d73c9bb5f669cd8835" },
                { "es-AR", "653b8cb47fa89f874e742d53341b6f7b050c172f974325524045ee2a2df09d9e5a5d40352893081192b88bf1e1ebaf9085c268f4c68568d21db319d50648a17f" },
                { "es-CL", "8fffb307e60c24a473caf50235f2b1291061795884f99ed5a392c953ae389b530af3559609678a7eeedba1eacfb4cd3840955af65da815eb6e8e71e839048001" },
                { "es-ES", "74d6dd8619dceda85a0ff7468c9dd95b4b605d31bc34e706500c0160d4e297019ab2f5239872b9f0cbfd672fa82c60ffde066617fcb451677a265f172a5a4abc" },
                { "es-MX", "08f931c2f5a57c31246c9d253b6152229c3aaf268dde4455d4895f9542ad24135eb6871fc04145ed54f204e64a2765e34d16793b728c768f82981217a4323811" },
                { "et", "c208a73705a7cd94e0744a405812c28d9320e79da424c3a430be5227c7334ba5b00765b990168ecd96ca3bf07bbb93beae2ff22e98b51e06538770a889191b5c" },
                { "eu", "10c123c6f5a4da64965a60e39454ed4dfe3d770f7113b9c1d644ed8567a45f57977c6dc53d2e35d171ca8633e381b8085e70965fcd439e03efb61a27281c246e" },
                { "fa", "a393e93e6bc42c622deaf6dcbf3ac5fd58f6d0db3d9f7a25e9b1eafcd909b022e96478a44df78b88a7eb45e9ce7f61d64c5d34a7d20ab5848a2b0508ce71766f" },
                { "ff", "d1ec356e361f7841d241a9edcf46113377f9df503beea1ec17dc52684cce6df4c03003f9015aac26967a0a6d75e02185d96ec4df2b3cb9654384d97820030536" },
                { "fi", "ff1437d9d2fbec310aa9f2a881ce3056b88a3d1bcfc29eb58b009d82f2764a6d4a03e6bc8bb20a24927f236ccb865621ce74b60427db96e6b25abc9d231c0e45" },
                { "fr", "79b17aaefbef955363b5307fc00d0ec30857ea08924a5bfd4f7915092c09d36c7008354436bd4bd4293824414cd0d98bbf7ae323f70034277246334b354f8d9b" },
                { "fur", "652e56159153644008f2e8045f3ec9a57e31eb527ffc86d227dd9a06ce89b6ec47b50465d3aa8ee97f98d5a4d162e8b5f9349058f8d2bd307b91fe679968f309" },
                { "fy-NL", "94d33b2bfeeba23b89e4ed3b531defa69c83569225cb6a5087a0f447dfaf1186c63897adac01c7b30f829c79c405c9c644e9e7a725b308e5bbf37df75c236284" },
                { "ga-IE", "82ae349a1009ab751029cdce67b4048b97f85ca9bb8e2f344b9578c130d47af04f172b0d5fd5a7d79b9531b5fa3660887590fdd82fdb3bf3da10d97e1b75fcc1" },
                { "gd", "6520a000be9eb4e092d2bf2428ef9cf2f7d39c67ff0fa2cf59218d4c130378162cabdb7d0668847f529137f03b93915a8281cc2f5f721f4abf618f1cde7e5557" },
                { "gl", "f5700559e2ccfd03e996e3fa628ccfdd374639b31e3b4f26c498d1e51e7fdbc99cb44bf02732af521ff06000db77067b4666be5c5f1eebf426f046b6d573914e" },
                { "gn", "2d8a30fb8141b2ffe660554be1f2861895774a45f3902c0f45015b8e576e87074d54d8fcba361ce2e040cbc5c83d7fcfa644bca59f3af3f6c755b7078d311f5e" },
                { "gu-IN", "32d78f105565665ab370f6f1f406811ff5e5580299b26a2b7e0d68e0e0ad2386b1d2cc7101f87a1ee543987478b853bb5704465cbaadfc6f61dc1f5a3fea373c" },
                { "he", "d2cbd8181a0757bf69d3a4cf286c3a9591777fe7e64a9f4332a954c27563be92b088e219a3a0f3dde4f77fa699c2ddc32609cdfed3d2c203f6dfc7c0612553a1" },
                { "hi-IN", "50972272598c62978fde673750afa974ba0f0775cf029c28b6bd668d880f16b71129643ddc72164ae38533ba451d1bcd072aa66dca6a6f9dcc8b84f39024127a" },
                { "hr", "8c6d44c97f00131f32aa38f29d023018161d067763e16932b48ba3d372113f45cb1f6539b05a71e5b31b5a42320efc606d0e88e4c75a371ed0df74d73e33974e" },
                { "hsb", "d7d105c6d063d86c7e77ebaf7544166ba9d9ec2485566779c7d5e9124811d8d65a8cce9afe854d1e9561bd749d344a797f13e14169db02db65ec447697fbe1ab" },
                { "hu", "b56e6a4648e776d9106fff1dc5fd34dda5760cdebe7353f5d64966d75ad3fac729dadef4f723b57444580f545862efaef898bc8499b40ed281d465a6386fd37c" },
                { "hy-AM", "6083f2945b2663145956e4c6e509d532ef05cff624ae04bd5feb7d563e05e507e7909ec3d92578e6edb73f07a7bde239bfdf0b6d7c233eb865688c8b4eecb722" },
                { "ia", "08cca586aadf3eacf085ac633d1a71c8abe30a0432b53390fcead157bc4be02dac0050a7a178beafbaa3d1ffc372b18f042ee6f06a2bdd942ab0168eb60607bc" },
                { "id", "e58fd4aae5c1b5f031b2ba375b37c9ae4a4d9c35a7e475fbc68b158a062df35584b128e4ddfa71f99ecdcc9bf1efdc434d6c36613f6c779d4977bab3c9cee458" },
                { "is", "cd3855af3df8a517c9ba3dc0b7b88dfadc5a41e5c711dd997c5fdd7da8b71f8aead8db7f5acd9f708a34b4ff4f28ae828a861ddfe554346d112a9007d0e1b619" },
                { "it", "d99876a9be8a72cf34c49ab83c698d1884f58c482df8cdc5363c900f5f9b498282ab878ba3508cd7e29c8cd9d1850c5acd6f43cda359ae9bcfe5467dcb7d45c4" },
                { "ja", "1c153495877c724981dc80d60fe6e50c40770385ec291ebdc1ee9c332df994d63e2cfc1f8c501d08b3f2de24ba8f9ae542ec6fdd4240f45232e01d916e8ddbf2" },
                { "ka", "3d1f0e80e65b8dfc4ef384eb46630161f799ab7588e96f25ba62df7fe505c2fc10ca39b4dabff8c4defa9ebb4d902af9c05a3312b34a9ba9373f792bd96368ff" },
                { "kab", "752229d4e1d2c217c88ad39f5807afd24aaa68dbac6e75969c71f9076300c40b89b1f883527a4fffe5a9d29a93ee180ca8a82f69f4381222ac876d5152f372dc" },
                { "kk", "a2d4813e17d8ff94d5e7140cdbf6244ab09ed2e974f4f07189d7ac32e9fc349ccaddc85a69042012eeb194af0a4bb84603f21e36504d5a932095b26c152b95e0" },
                { "km", "2c39c61d1d66f1569a14c9c53722a00a9483e101c82825f34c053de1bea1d4cd2420bce7a21b9b6ab00515ead16d8982985a036c7feac36dbf3721e90a7c4741" },
                { "kn", "77c1e5cc3dd6c85f18b4ac1674a165b67a662ee2479054e22c70c39dc9eb008da0a423819cf155f31cf2108fb47ca8e104d950a9416609bf6d0de05f673cbbec" },
                { "ko", "81efcd2ee1dd04b1f124455f1c56cddff617d25461daa0320b3428f15bc0bca80c228c9ef45217e5450b2521a4d1bbac0fa42e01e078be5866368093ae56bfb6" },
                { "lij", "fc6878eeabfb7ece1a0b72e1198c2294a5cf534dd346c5977da335bff04bebf35e321853f3a4cdeb0b0324bf7e5c0faa1c68198e97fe1b303833a6e07faca1b0" },
                { "lt", "a865983ca73628440ad544c1bbd3ef44fa30f7b2e9eaf543fbf4fa4fe85a60cc9a8341a4a379f3c660f0ee88dd5eb1d621c379294b838401af57f5601d3e1e89" },
                { "lv", "6b8331129f2069f4eb053d66e5f200fe60f053ecd480effa8df430f5f1436e0e6064cbbb9fcb95575aa5274e535cdbcc5ca7947ec6f3cc64e53a89d28593ea7c" },
                { "mk", "5d41e86246221de93979a8357b4f4d540e379f1cc1cc0a58a162846f1d9c1687c520a836ad3066ae67ebe54574c5d845a55da2e0037999c648a1b10bae160159" },
                { "mr", "8e96f27e964bb100c15666525906878c931c8a317556509718d5ae126c7d26da6e2469829f0b00359cb7a88cf98a8fe67128680ab0b547223336aab42a1a708e" },
                { "ms", "5bee9540c4dc12803db6da4f94fc2d92820e96119220f07e3dfc8e572d61fe77ae1f071f11b58bbbd3b11c8aebb213362a3d1feb4d19682fe011b8ff6ee9988c" },
                { "my", "a292fc73550cf90356ca330ff2e6899ee1c792319e5cbccf8dd7775b34c238cb4fff306d5368ee01e030c5a1d5d2499785a8c757de8656fb7067d47df201ee93" },
                { "nb-NO", "eddccaaf7b4a396c1d2d412d437f07617a6bfcd3d199dc05dc104e2613190b88ce5d4e50d81bf1d3acfbd4e82c65470cecf82a0044abdac9fc685cfb43d1a5a5" },
                { "ne-NP", "b765ee16bdeaafa9a7bf071d4d36711a48139f52fb8e378598723ac91d4cba874d595086c0cbacf34f7fa012f86fd28ba785a3a4df43cef3c5ef70617a675dc6" },
                { "nl", "8ce33f82fbaa5681673f0abb27c9c0db976c2a72abebd5de089b0c2eac04582e947c12e91bb8ba3350b0654c7df036cbccc0d3fd95785c87adc6c599a11c16dc" },
                { "nn-NO", "42d1b46c242489a9297125f0f8675273ec58cc65c828fba4bc9d5a9c4adb1af392ef5e9d7ae85084b15a95cd6fc0ae1b96997862eb4cf078feb13fd5f5a31ea8" },
                { "oc", "40f8d4d9bc28c810c5cd78a67ad666bb190449ee2e14e3a5430869a501b6be566314cfbeac44280e7e8391fb4035877b84dfc2f9d12dfdf76839cf686bf8a8cc" },
                { "pa-IN", "b0a4534ddd3f01ae60925b5ea8288006bbbc9f60d9ba9f37e90c6ed243600478a88a968fbe98a03023539ee8d961e07898df6cba7bdaeb6afe5a038f84e626e5" },
                { "pl", "8ec06efd2fecc765188c54de4f05c0fc90bb0d6291f2b8d5a5ed8523ed3cd3afd4f0370526710f44cbaa80e5da43eab98c41955b0f08da718fc346775627668e" },
                { "pt-BR", "7bec9c5a36e4bc75e92064fbc03843d35a7a91a29ebc41b582672dcdb8c57262f54c2cc687c018c7d95d9a21b1354855ed845f54b1aef48687fcc5301e916f1e" },
                { "pt-PT", "3c98893a0504b9c32db8d73a891af84b1f888d3808bc03dbb27bc6cb1dc22d47555ce8449f66b7d3a4a7eb8322bc6195b680cdde950633e3d0920452f2e21378" },
                { "rm", "6a9a51454ddc50dadd1e6f24e0165ce4bbc460710831e415483fcca28f74d136010ac15baffd6fdec1fa389b316060496d04a8dd1836ca421a3afb7b9079965d" },
                { "ro", "fa02e20074af033713a7e46597db0d33ecf75e7e9ead3050fe36b8a57601ff8b9818de1e0b34210cb9b215801d11d818701a101216febb92de695f33ac833000" },
                { "ru", "a28a3fe430c6ef1a20380adb5dc54f0e9d5cfb1746a7b42bfba3e740228d55a34a8237bfff15590231ee34d044a0bb07f83471961c77671ae526f99b3a06d3dc" },
                { "sat", "a156154c443765dc81a8de6ca9c48f459c181f87acf4cde758e35dd3db535d36bc513a4005fbb6e9be7a9bafc9c56035db78828f5aa4daff6d846ab2eb26a68e" },
                { "sc", "e1e6216a9a5d209ec61b3435baf2a1cdcad5b5548dee21d3125bda2b8997fc99aeacffb8b99a124d406907ea58d25dc5d86dac922437c39e2b4ed0b509f4f1f4" },
                { "sco", "b38287185832d65f1fa1493cb77ba56501b9619eefc1ff725d0e3dcfadc0a6e080be5bd8ef4023d077a334c6a73f98eae4bf765afa14e29a8cbd792746c67561" },
                { "si", "319f1d51f1285212e5d23953190039c249dd62368f191677f18355bb4b4014a277fa6bcf5b40829e765cb807995adb128d73260b2b21c7a522e379e95fb4b185" },
                { "sk", "d846e3ab3a1e315178e3fc8adabcca504e526ea188a2ab667b4438a885591445ead0379f9bb06ba341787e859f57af5e329ff40c7df8c07d0212e6f5c057a12b" },
                { "skr", "7e16cb43a300c6cd5c9f96986c340d0646cfc0ad4cfc185dfbd8c98230deb0ca5b2c537d8aad86a4734be1496f54a127da5380eb421d7d0066175e6dfc7f8b21" },
                { "sl", "88a7cb8eaad9481fbabc7d8b8c7d382ed16af3b68b3cbef00a8fbeff2402df519eeafb2a31f46386df0a3b4cc4cbd9dca6fb63cd7d5c3e279a0456665ed6be4a" },
                { "son", "24e532fbdadfea0bbc781f73a89b43780cd66da060ff42367777723d946f33fe916ed073db97b027de1ab45a2e8e58bfaaf26dfe3304b19b172e67278cdc35f2" },
                { "sq", "e65a56c1d913095ce4ac8df4b2c2f227fc5f50a0c7bb31e4d4f13c0afbc4653616596cfc8890d23c182e262cc5f681e19669829cbae175594742d627f0d3cbd3" },
                { "sr", "e9fa99b85e673eb5feb6490c2d8be04aba9c52765d06919f09358ecce8254fc425e3032ee6fe25c96d022262e85febf4f7f3885d687b7a4ca260f2249ee82870" },
                { "sv-SE", "57f2f7a9c8bc4a4697cf06b9bed2eeb07f5be65e590cadc15b3441f746c073295edfb987224d9c91c5187ffed202bab70f8251d6231ffc25b820c10b28dc7979" },
                { "szl", "b9034f8cbd496eb75fa1ee5cce40a5d27415b7c674983797ee9ba48fdc454b53c8e6e475e83a55e59118976bad6e4bdd59bd95e07e4dbc8970506e54c5ddf7d3" },
                { "ta", "4165e8af49e5a388f4b7a200788e86bdb017650f4ea9b99b43295378cb7434cae45c3f0e1e30f3942d48f88df59f62e50312c12240b142e7a62a4cf92e42a179" },
                { "te", "11133caa7e45fceb8964d30e1ed630e2fad4428edd80484bc11afa0c5a482b49f7dd8b562aea1f7bd43c9fd03c4e35e36ea18934307ba5807f6be54918fe1996" },
                { "tg", "1f3e2cef8a19221f7bad5d301e2f18135227d4bd4b27b64c3a2e8e9cc32fccf292f6cd9667e554bc36ba94a45f0f64d451716a8d306eb5282711c77466669188" },
                { "th", "790e4a9e248749f34e8803d865048c47cb8395d8d540ddc5e3560edc02fc46ea14066c35eccef3518cf918c6d771b0d78384071b992790716e8834321fa78173" },
                { "tl", "59c980b04dc635ec72e2d500c87ab7cd4e813510fbf46e196a78542710cb93e401e1b6a38c7087d508d6f78636ce324c4d77de7f4aac75512dbead59b7652529" },
                { "tr", "d7fb156252ea26aac00594e110d9886f4175bbe0742bfdc73f08204aead6c55ecf74e176f5594ae3eb17857c95abc869b387fde8b3479804cb05193fce2c3d77" },
                { "trs", "549b100238c8ae0bb477f63da53d919d1bb96489a9c0b131d76593d222c7f72c690ce772eab8515ce1024aae33781d7e27831a9dc0ffd5c20e2b2f108bd9b06c" },
                { "uk", "7f092bf8c12318a427d9dcf6641f5ff4f042ad39f6d0423cde24533d1938baec9101f324ed9afa59cb496b7331447bb1f0b825eaa7724aa3a8036ef23d0defcb" },
                { "ur", "81224ecc2caa1d7bf309dabe3fee98d1df0ab3e73ee9c463023728f071c2ae08011f5a0d0947718808ae336a18dd17c50b17cb4b96256d923f30433eb0e061db" },
                { "uz", "8067a46670c113830e83752a1b4ab638206bcf582928db7f2f3ae968559d9bbb31456b79349e70ee4d49a351de0d2cc69c506ffcaadca5c84690b387a39fb587" },
                { "vi", "b4dfb1467523549f30bc50e4e32b4a76b1ba4577c5ee0dbe53530a281338aafc795791b93d3a41e068f9a96c793c122d76c2b466c3819eab2131e9634290ddac" },
                { "xh", "cf95aa62515f35ac5bbeeaa94f669172b8f3782ff1e7a2f88bbd7cef48fa7753f3977c1fdae686ba8a616c862b991755d54fccb0a49986d457b3a0fb94764abc" },
                { "zh-CN", "4162d3116289621426ad2e14ec104de79da3e580e177a15ea1da8698c01f4e9d88c5a3c0b91ccb35516f11852bd7946863f37599fbf13e2b3a4e15e82bc8b166" },
                { "zh-TW", "20098de508af12085a22d0afc83bf78d353148f6a2e0f042eecc5920570d9e675bab746c71d1240180a676796f7b11bea3438069474af383d55b44ea7f41b647" }
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
            const string knownVersion = "153.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
