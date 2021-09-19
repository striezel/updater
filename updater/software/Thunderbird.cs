/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.1.1/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "d276ce619fc62ed45f3964a52ccd14fbc9a1a5bfe06215fa0d9a4cee96277ec5faee94491952b3bd3481f20acf1395a18d8f415f12ee0d310bf7eaef07ccac74" },
                { "ar", "6321be82343da6eb02764a3118de4f5ab269d251b9c47eebb203cb8f54705308bb4adf067ab806c4e1ae2918e8892a11d983274a3c4bb8f4ae4c423bd764a8b2" },
                { "ast", "2dff9382bb926e714e0486e2b2d3fbc1a25389e0ce85dbdcebf629247a0c3e9e5bf5d40617d57c3b019c7905b8eab44506a4c0487dc04ed585c1abeb68840200" },
                { "be", "0eae4a0b487cdd50ddbe3f8ea320cef63b63459aec75a831da28ce83686a7935ab1e3b05db3d3dc379dd1770c2692fd30f496c670eeb90e879e6ef927a96b118" },
                { "bg", "60ddb9d1bcf188665698f2b357ef1080bac6c5c89988086e7c17b51542969fd4e70ee16159f2eedf15f4d06793d59e566d77a2fb9c50bce852b6948ec0fc07bf" },
                { "br", "bfedbb79731bd3c1d044acbc03eace84de43ddac7a4f628e631ec77a280b36d026f2258ba50ba2082d4f33088c991baaf0336eb459b9593aeb63c5e5d7e795b5" },
                { "ca", "959b61fadcb7ad15ec41ba7190801f9a9ef93c73fca89d3d0be2bf85264a061903c5386df275484a07c436f7782271889bcf40fb4a1d42c51035a15318bab13b" },
                { "cak", "cc3b7e3073a96e674683afd23033b2b3a763a507b10e70d3ec184fda13bb59e7b7bfc886129dfcce493c552c75e1c16b0b81378b5c795732507c6437cc0df91b" },
                { "cs", "4709210896cd1a1ef25958a305d69e2b1cbd446885f2f6694c8cd13c931b969b3c5db236d02f06fdc537043f0753e834e0812638dd53fa799fda4eaded505920" },
                { "cy", "ee59da26823b66cc63976a1e48cfe20926e473aab890585de4928e2100a93858ee13a33123c9dc663c5e83855a58023bfa0e7b3376fd30ddcd5dbaccaddeed34" },
                { "da", "0c7c9a12ef2b2d9d0911b7a975d7def9b189ab4d900db02fd63fa3224f0aa0fa454f4df03a4e67cfa14be3b86583cdd96683f024df2c40d297ea8aae72db0072" },
                { "de", "5010fe709c940d90f8faa5c7b1f642a0d8d817152404c1016d0538aae5a61bcfc526068ebe5eb11b6abfcbdedf712b97efc48fb35bace739cd51294c94f5e97b" },
                { "dsb", "2d64cac43c0ab02f74dbaef25d31bdfcc0ef2d8f39149c8fa3cdd3c133a1467bf3b2460599d652c1eada3f55ca4a5b201ca2f015199c094f88aeb66cd76b1749" },
                { "el", "54afd78e60bbcab86fc534fa3e8724db7ea45114985f2d325df0f13f2c6928db4c1cc1fa471876363b97e83ed5d8f2e58367543a21e74ff7db661a8989127b57" },
                { "en-CA", "5b7a261dd132f9a47e3d8f085fac22243262dfaef2cad934889556de53e127c54bf87bce75561e3c17fc4db5cca6208b327b19de289958b77615f913c2a02137" },
                { "en-GB", "1d10f28ca61d73eac47987e30c61a874dc770a372ff86daba90189b44dee25d997bda7fb95ef12f12dbebc439c6abab2ae3c217cdc37f891a2c6281d799ea09b" },
                { "en-US", "a62d91381010ed3890c3df24e6e21bfbcb36272e81b2c6d7a644daa88b14c8bd7d75ba6871c3bdc09a0b903afa5d831ec58527d0f26f3c24744fa377bbbb4cb5" },
                { "es-AR", "b7131f3a0644a31ac482fe33c1485bf99a03326c7feed98696f4aa3c389257d06355b818f5c81b3a0a1dbc6478b795b29d58b329eda0035d847537622637c210" },
                { "es-ES", "6b6315c451363607e2129312cfec582f996eefa673166e06109bb447c640e14a271e48fe60f78620ab92796e90bc940be43735f6774869080c025924a05b7aac" },
                { "et", "057300a9e87e5552404e05fb2fd83fa65931eaea8518f547f80907069bd9f07cd0c8a36d0ac0ce6f5bf2c1aae329139ec6019b3230e9285318df5aef844f54f7" },
                { "eu", "3a176fa03c225d7827794ac8c8166a833ccc121f76b38073c9216ce73cabc87ac30f078af52d5eadb6ecc9f3c9dc1bfa1e499cda09aa114a1aca9f5b5ecc1ada" },
                { "fi", "382903c695c0c4d1c206f2f6a18c18fae00add285efc9645fac35b2192d72b026f860d58c67fff0f1849e9ab795ab7a87ef1758c3149d645e64eaeb2004052e8" },
                { "fr", "4127d2f24e755a73bd3a00e976fd0c31b10c7478724ce486d605223ab9109c7afbce2762458f736f00f672599b8797b2dc08dfd07dce2df12c75aa4e548e438a" },
                { "fy-NL", "5d5701eb22c0824f35b17286de170c1e07a2f4ad042fe8be6c4b0ff7e83b5fc57a993adebb969ecbbb8ee2a03e39480981640d2be3cb6c6b016cc0f18abdcea3" },
                { "ga-IE", "d494931a9cc1d25c310777007911347fb6ab430350d4c7db74853e5a10026747394b85e7794f8b42da124f182722049f9a610c9ba72c29e8e598c9df4a5296af" },
                { "gd", "5a01af921ba7c46576a7ea9d4708c92e5fbb62d91f82a13860ead4b2be44848589f6ecf537c84c687762b5ac8d24757fcc36479334687eb19e7d4360361f6d5b" },
                { "gl", "94942057030ffdd2d398818fd628bea9a2a506989640a97dbedeb4b8273453db5d9c24c2176328e256bcd380d1872ae40fd84187b8dc164d4c94ca9623f4d89f" },
                { "he", "219d836a77434aacb7467b64237e06819f1384265557042a2e06d35892705071fc9533bddd70aedf7683229a83a6a044bbd81f173364dc20aaf163b4e104915f" },
                { "hr", "23a6c2844b0978d32941054848f35a8ca84b59778e0b2bbd231421c0fbf99f8b474c4fefe1b9fe4c06ad0f07f0d232844bd95c6cc971954461bee5b212d9a935" },
                { "hsb", "7c09782c850e500d77daeac36cf38814bab4fb4974dd416660a70994dfefe56d0856250cf42cab507a36b96f34b857a7f62d2bf9111f2d0cc5df6ac19e3802e1" },
                { "hu", "a3382462c19f884e3694845a81b13882a004123bbadd642c6851c9ae7e54d72cd745a026975ca61e5ca0e5d7c4cfea726e1407b3bf57611594af477a70bad4b2" },
                { "hy-AM", "1a311b40bc2758fc7c1697b894d3356a2ca6ffad6a1badb24e2b603f53d0ae889ea9b52ba7995b39b2f58090e00cc1ce9ad4bf360ab639012e1ab9d6b77e4e43" },
                { "id", "ca0eeff8cd44e765dd32e8c4a2458422104701ede2ca28a2e29a8e0d57f92889a55e39a90814d8271adec3b291cc7720a31f3a7b8d4a47cba0ee16d375c92056" },
                { "is", "a60be8d2a5f4ef18049f00a24d221edde0db518a2a30eb39a879bbda6e9e65503162e5158ff1888586a3e1308514f534bf701c173e309c74802470cd33877e45" },
                { "it", "7a6d34498ac6fd2639aac750f8d7b01621dd949e7947dcbdfe746b7d2767e76d555bc5d959d5ee5ff62174931aae43cbcbe8af0963f26b43797ed818ed6f583e" },
                { "ja", "7abf11328c96ae3a1f31ad0222c4878cfac50d29513ae947f29c3dbfe8ec0589c9c171b25656a41db986510df4e2e79152b8261eecc64306b7ccc97de13e1cb0" },
                { "ka", "80e45aed872ae6248b0982431b29ccd3ec0e757a1321eb4bfa620455fe1c38564ba5cb057f5d0c059e756e1c278e01f1e0b7b68e6409adb2bafc2d6d2de22ecd" },
                { "kab", "7e09057c715babaf386d4696df29e3ec79c86fd970915b5ece1b3af63af0b1531d465a988369ce3d72f8dfa812d84f0269fe731360352d8bc4c1bd975bc6fb69" },
                { "kk", "9ff454bbcad05ae71761b4df5883635e8ae249e53e89be52aaa01bf2bc484e4a0c22ba19a1fab4333fe04bbb64e704dd1f4e4b9418f3ba774bac1a2244df4906" },
                { "ko", "2249787d9c2e5ce38d3932f2925f341c6bcd10e3fa7375514cfcc73fd1cc459ee45c705d173e121bd5092d6a6f35ac693465ece847390f09e5eedb3e315ec5b5" },
                { "lt", "eac790285e49f3a5164ea40788bb88af8183ca94db0d6aec438237f6739d6cd2dc478d718619e49cb7579747a0ea6a0400b222fb185515e150f7b5b99c1a573b" },
                { "lv", "ba1b9cb8d0d27c626d2cd42a7d70202af846fe039c084adca6a60b5eb6243cb586ce2dacb8f8a9642fcc42f73f275ff57232815826e30e6e6b5eaf4f69444687" },
                { "ms", "5cdc12faa10fe17d2d8dbb741adaa45e3b18c1bbfb8e7c3078bd111b407518c8d7c74a14ab339cfea0e49d252daeed9c7a08c0af170c8709bbf5290fef609f27" },
                { "nb-NO", "a54fba498e60cb6be5e16dcbafe5a730430d154df09cb01986928a4e974f9e15679c17321c2aa196649445cfc150073b28f969222bfdda83419524523dec7c6a" },
                { "nl", "ab9a2c7c7d7ecdc878e53d5ece72b1e8647a1054ab96c1248a23635b67872ba202d34abcb952f313550ca72961df749ea3cbc40810b765bdff9c7500430d37a8" },
                { "nn-NO", "d7b4f9c7e8a9a629332fa00e2f150015e9981b7381f09f421c4c6a9790c6897f8549fe765fd59eead677977ec07877bc3d99208f7d844c3360657f7f8ee280eb" },
                { "pa-IN", "d788424d923c9ff3045b840d0e4bc2ab82bd2e0beb00a46811ff95a7f82c8342ff6a34ec598bc41ca98745a37480f8cf204745721c3d349ca4c450a609edb821" },
                { "pl", "1719e22348ef0922a96107b5869c4ca41dbf99a3f23f73e50952e3c44808493656d9dbdc181dfd126ca6ae85cd969a8306e66cbb367da51f6f9ac1b626449d1b" },
                { "pt-BR", "ec9780c9be3bf7a57adc1d14ea7d355d4c184f93d61fe2a1bc0e8e01ca67d513c7e0b051df660a3789313873110cae8ab08a2b2b3d4ad35c9a191d381f31f75a" },
                { "pt-PT", "898d2cb5611036e5be7ff767c6eb556dfff21f1f63c2918d684de2ccec5ea40d6dab62128f4fefb9486c7cc08e754bcefd30596c453761940470f1e9f98dec64" },
                { "rm", "041133f1e41ba90eaa5e85d565bca3ec0affe4570d95baf7ec4a22f8ac6e0084d2ce032ebf3e20f5b52de97fc2930c4b70131cc5e7c59fbf78be1ca3996e4f61" },
                { "ro", "f8eaadf7e4f7dc67c6f03840dada8c7c09ac3a35c5c17bf000b22810a5f437d84b469428a626c73cf43736d8b59de0db905a401b8bf7249caf84b4fa3d2713c7" },
                { "ru", "8d586a97a0153c073d3eb3a510625a3c5edc36e4d7f58cff5ad5125c0750215e4af50281c361a355e02d9f17af0aad65dc382177fb2b21f165ba38ea354c8d0e" },
                { "sk", "49a5bd3c2f49b869c9373244b72e84e4032aa6ed52aa8e01891df1bc51aab0caffd48302dfde20f7f72f1e9aeb8a85f20fcca2e704f2f071bd60559d202edd79" },
                { "sl", "3e1d4cdc6fbbab4996c0092af5c297db54dedbd190ae72377de4bf0b7241d1f3f9408f615ba3b8f50b7eaa044652f31c1f1c4c2067521a57cb45737ebb614e83" },
                { "sq", "e9f0539b77033dac9964f4da1b6e0de0b77d5aba25dafd42253dc5d6ba983b69d7f8fa05dedc9f574eebf4c5e400bf5b7ccc433c8395c7fe4921c911f9f4d3fd" },
                { "sr", "ad7ac673c4efaede66183f890b09df291a7b91973886cef94e13efb7a2edd16bd2545f4ef056a915e3c7f24738029c1dabf2920e5e8e0e653baf12395266e0fb" },
                { "sv-SE", "95f648165f18bb07d9098415c50624d22667e1c3f6373518bea3a9a43dda7e234ad1a08d68ae70ebaa4aa9bdced1c7445e367c5bdeef157683306f1f063ce12b" },
                { "th", "ef2324c23939dbca924dc212cffbab5972cea04e67e8441adb158fa6a369e0d0712d1e40965e231be3e66c84e350bcb17848feee6257b2cfb9637df9d0821c54" },
                { "tr", "70e3b7308ebc99d0c5fd2caaf9e1a2901503dae5107f1b941c9f40d6284152cde6c9560305eafdc8cac4355eb375053080747ecb8e7a06d2df623ce86fd029bd" },
                { "uk", "c1fbad7b91b8cd51c551ad7ee0ae2bf76325dbf001b2fae179597082b3aadb925f0f94a05d510dc10d0b5ee1d7866bad671a92688cfdc7c8a057977e7cfeea38" },
                { "uz", "64baa4e1fd89437084bcbd5aab76313ab690256905fa3bc4a270fbfee683c11fe4b0bdeec1e54aed86d7b785721700c9380009a425fabd48dd79d99655a514f7" },
                { "vi", "0aa8d9b9fd3eef189ea1cacf9931e7b436188239bb2a8b5e81b98af44aeb6dc576490b9a2232d543e6edf93270794232af2fa0d9cab60e4a9c369d7837b63cd5" },
                { "zh-CN", "a7fd462c23a41d13771994fb6284a48a75ef93893afb35c0d35e046e24ff19a0286dbde86a11de2131a497277cb35fd18f719573028ee175aedc9959b138f3c2" },
                { "zh-TW", "99186a44380e2aa37b41acca2c836344296d1b0d4951b287aeaf5219815f2453e91734ad0381876798aee1c18806da62a7079be41b8e8654c79e9f728b544778" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.1.1/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "c8facd9fe3a6ce8bb16215295c762b899778ab41e862d2d6a8d0a0a6485e11c1db4b3eda99c46fb22ea1dd76ce8f40c7290600adb76132cf341b5ac2841dc238" },
                { "ar", "4c6015004de22e59e0daee5c2579904af6a5af2e555b9c84c2725144865604ad8708ae9fa1523750f25929223cd1619538507c6df4aff0acb82f01e047e141cf" },
                { "ast", "59536e5ae601f1cbc88fd95b5d281abc7eb1ade7d22a6a31cad4c34db82f505a9fb9a7b4999ac173cab605b26dd94891f4e73e03757eb2c31f447253abebbddd" },
                { "be", "ac20ae491af4a9b06ea7c64cbd29204e92f7eedcc58828e8a21aeb37268578ffb909d2ea6aa7c690399ab3e355847a3faeafcdbee198ca084c5517e1213d3d5f" },
                { "bg", "a50e9408a3ab80d644d61fba948e10b947a67e088785c8be8834a619f223e4afb5975c732b945ba9ba14912c4bd3fe4c157afb89e727cf347dc5918664f7dfa6" },
                { "br", "7899a10978027c2bc6dd42a9ea6a4769f95409e13e883d37a79780c13939c5e115b0fa516a4aab754fc6137e225fd9eddd92a961a4106531e0c5e9bff2bb9ed1" },
                { "ca", "8548a883ec3fe0b1cb9d43f793d6bcf2f14176b57226fb084d4e9cbe6efacd0ac4777f61536a9abd35245437a8174af28944dc6d4e03a9411eb231e2c7569f16" },
                { "cak", "468c59b627ed3b6ecaa777c9a277da2d9a68375d024c83dcec8495ad77ecfc6e9573d801c6913ef4dc33c0e61d3b6f333a06d3078eab84475dcc999212143379" },
                { "cs", "2672766ac5c4d8ba42db249dcb853368358ea0f5a5eb143b297fd4ed607bb444d471e357acf7d0f665efe74f0937cfaf1eb87d99ccbb0f73b28e2e300df588c5" },
                { "cy", "7ff20689dd1c83b7c2f2d3e25440ec2e15b38ad2bb679fe6ccb123cb226775bf95e899c4cd6b153b8b32b7e9762df7de09fbe14d25fa9cfb4ff8b113ff1c2ddb" },
                { "da", "3b011c3b2d164b988a883d3a1b3598c374c63815924732418bda27ae7b449e4bd3f7a60ff91e1b72f42799663941edb5c23ee8aee8da788801ca5b4f4b421b43" },
                { "de", "651c27094b4252810309892fb69a81223585088b95f941d30f89f50e1f3ac97013064880d8c56506466d4670d23419b612d20beadc19161ac7a38a5574fa3618" },
                { "dsb", "7b23a86a207fcf6f96bf3eaed74dcc16b3d9c7866a3de7055ddc9f4cee4591afed6a9d051e98d93c0751ec80e0f910737badeb1301da78975709923cc381845c" },
                { "el", "df1e602f97db02a4971c506cd1dae7d6d110388d9b936955edf152769e541c0821c67cbaf4e63f3cc08418bd87f3e3282b0a1bc24995eb66f3be6de6bf0ed191" },
                { "en-CA", "6734a3c711774020461c588df98462389f6d7586ea1f20042ebd9dc108bc6b62cd6bbc90c6020921bca0529037f67ae57a3b083629b3748ce51e3adfb8c5dea9" },
                { "en-GB", "935d18e115647a0c81e39114fc75aa230b970f2ae53b53faa57243a8c441b273d71b89657e3078dceab95525eba434f336327401591d53b64a2fc3314fe03946" },
                { "en-US", "2fed965bf346424d1ee70ad748013d3c60b28b42ece0e568627c46a409410bedec871fe6ed68f6f0907d4f2b8ff5a3b267c64faeeac192b9df0e4a61caa26793" },
                { "es-AR", "5ca392587f3c50492cc07c8a36137396bff4fa644d28e95448777fc42782568e033cacf908ee91ccc529ce01c39f23c960b9c123f65ab5833b23938d356f32d8" },
                { "es-ES", "b3074dd50d9db67d58f05b825219e4f7b9e87ac2fb8bcd335787f4bf550b5ec34c8ca960c28ed61d9638947e7cd7defe3106e5d45c5f761513edb442bfe84745" },
                { "et", "774dd9a70c148cba7f53e4c6a3b15cc166a68a0ed1b50d262ea7da680b94458e7a36ed2395bbc1d93c7b0150c78ed68ca5d76720f9dd2f6b6142cc7f5d656e8e" },
                { "eu", "9140a1cd54b991739bc151be6a4dbb871df5c4e1baf126f71cb0c1aba0820e015cc4b58047d11691b0cb17dc8041ca71b335280b50cd845e082b25d6c5ffafc8" },
                { "fi", "a36bb916b26d9e80edfb298d71348ac6be124bfaf23bbcf91c79456082d69ed56557ded7a4aad7d6aa2f62db627015d612638f5379828558e66dd96e845363cc" },
                { "fr", "c3ebba6a8bb8b7def404944e03860f3b5b2717bce3d867ddc7fce1d4468bc0ca1738c41d4d702adbb11b6a4593cf4ae3a7b48effa5ed688724daa2f3514e1640" },
                { "fy-NL", "423a16479951682802b42b6499c1ccad61db0468a5583de9f7ca895cf517c3b692b67ecc78ae2ac35a0b8a212d772750b193f63cc5a95e1200ad5fc7c688cbdc" },
                { "ga-IE", "ccf963141e6b27e16408af2a9ce603eaa134d35e89f609a487bae919e2f4bbe8219c7135ba9e316b55ffe7d2e21c8b147da360c5ddc7073dbe56373f6b342dee" },
                { "gd", "34ee36cc40056bf1550a6819dcf1fb1bfe46c769a3132994c9305a65e0ce34480744f144639d76214b93651fa00e408c8f8fe39da14787bf3f6e2641b6808c5e" },
                { "gl", "e72a33941decd4a7db2d09ce9ef1152563e9e870e1edf053bee35ba68938a86b7681f1643744d95d365f375caaa692acb7842b96e9971978101b28de5df70515" },
                { "he", "57cee72ea6d71afeec4f19d51c31bdba4acc424f58366ce77ae57823c7a1f034decc48a89903669b220333d6d77038d2fb8819e239a58f86d8c5d4470299e8b7" },
                { "hr", "27be35ff9cbbb9e9dd13bd26b7235c141d035575650e55b4326f4a6e60a7811516b201e24e2e733fceb840c460142d1eeaa70c0c16479943539cdd4f4f25c6eb" },
                { "hsb", "b6889ebaf8cc8c1d84b6e69b5de643911bc38fd1e688af14858912380e6d35ff2ef8c5e94abf37a5b281887f1aaf55b028af3d3864cb159b6f9e8751d2d83358" },
                { "hu", "c633a4fef14b6e907b028032aa3f96656438beb55021b18f545bf9829d5b264ece503ce0d7ef335c51634f8286e7f0db9c5520ad08b7336e924fe3855a3d89d0" },
                { "hy-AM", "55bfba8013ecb9f1c091838ff49f4790a9691fb8a37db0c10e5a5080680de0768d87b3b2372fd1a80063ecaa08373bf6d475a3e5bdd0eadb349bce071f439efd" },
                { "id", "cad1e85a063e98dcd22ae15a7b278146d52ab0bebbabc88f7ab17f412a35a8f23e1befdc728c992f13f986decb41ac91c060533d7312ff9707df030ebcc0ac3f" },
                { "is", "5b302ab738406159d6661171e510ee08bab400672631a66d6826c0f22959fc0e73fa418a895f1e3db1f9f2415f6838a0cf2783ee469fff1ee3fddd91847b9b04" },
                { "it", "7cfb395f2a6646ef73ab1dc9886d2990f5803dece217e6bf1d1467b3bf2414a75b6cc5c481dffa8bc175b737e1e6b0a24ac43fe7ee90cde4022554fcb8b0cac1" },
                { "ja", "adf01ae21cddb9297795bbac96b27333a7c5a3a9b4b859f0ba062b9b4aecf68d9fd70864af1266f0daee93c09d529e71c85ee0f202e24bf5267b49f979ffd97c" },
                { "ka", "a74d89b30aa7b3059dd59f56b6f08161907587b56bfb8dd56ed51ee664f1da75bb7f85f6da826b0673ebc5668e7da0028d11dd03c5a4faf0b50f8f789f3f3315" },
                { "kab", "8976bde614207fd7b5362089090d69b3aa7d3007a4369be2cc3a6cc8d76e65e6e1c2237e387aba46670cf54a0aa76e917d5ba4a481a126542a6a14b41e8a8fe1" },
                { "kk", "9b8aee23d7f9c72a93cfcc73b98d047237c099e7c302af045cc9cd1c78103554e7940ad77f003d84c5908e427dfcef4822c3a651fec64e5c0a8d9d606f8dd6b0" },
                { "ko", "47a45b62bf9a2e2730596cc7a321ca880e2b24348208e5262e13b4ca2f31903c145d958774bbe6d5593df1cab293ccedd983e6f719cfb0a946c57acca6f43e9c" },
                { "lt", "113531cd2c774b0aa724211d329e9b1d505ab44775090aaa10e591438ddec2ec32abb276757987c17ee15d9115bf714c43224b3fd1242e4032044d6d208f8227" },
                { "lv", "f26365796d8eb6238724c58d36664abda1b5c3ceefe2c0debe6bcd70c6831346ad808f3594049b5164a5ee9ca3f389efff08a141d253297fcf09f88f0e4efc10" },
                { "ms", "177b99a9eec523ec6b8bfaf78e09ebfea1c40ac412805e3ac49465377f5d62e781a897c04eb4c6bb6fc2099b7a28913f4d7002475ae3812a1c819e13e6067036" },
                { "nb-NO", "a5863218b83ff397c2dea9e8b19a26c9c3ab33937453830f77bb1885d127ac58065175102768a5ad84ac553c51e05e716f9825872941148b2ac294320612d908" },
                { "nl", "09f01cf29df3aa8a0aa446adf1beeea9311b541cb2862e76ac9a85cacd52d605a011488a9d6490001c6170a38a0031ea23d3989b5cbe2febfb8cface023999b8" },
                { "nn-NO", "af8a9c1ad1701d888566c972748b46990afaf8a4c6dbf80ae8e65f2eca973412e6ef1afff184f5594d5a2f8e1d6af349797884146fd8d95ec38ed9b027fa0716" },
                { "pa-IN", "aaf8be2d7915a5f012673055cabd2580bccff807b3f61b8aa1a1aa9532d0001646ecc586d0f4f17ee90c421af9c44cff04027da18ff2c5709a7ce555abddfbc9" },
                { "pl", "370099bbd2396bb3dae3fd7e1dc0be753100b28f9922cf7c36d9e164ea71e8dcc46ca9b27d3b53f45910610a32441afe5458afe8a9940d27ff2496652ccb8c30" },
                { "pt-BR", "36053b8506948be559afaaead5f7b65fe508896479e0bab741a5d2d9484c856cc26bfb9ab8da6bd5ed63189ddc162cadc8dd88fbe8c3a915bae78a783fcf76f8" },
                { "pt-PT", "203a816a56b60ce0b80aa389ebf133dfe4e655725d93bfd58d4810cccaa0d0028aae9d937feabe6864e6338af5255ca1cd2e7557f11973d7fa7fc3a042a484df" },
                { "rm", "2d4d8211b17a39e907c4804852700a64fee6baf019483a768a18cf4fb45b6114d60faabf6630a2437ab9389fbac508763ced27123579333238a89a6b2410a9aa" },
                { "ro", "49336900af556aba8cf71ebf25818bdae8d2161a9b7530232330d3a71c308b86c7825a5c268e290ae9ac57dd9084aa61e01287ebf662cfb8856d66ac555edb31" },
                { "ru", "3ed41c8c13c8c76b6eb2359d4fcf1b2d6035f45453d81e744a734baf75d22bd69af27abd999081a5600c2191075a18d86511b1ebed048707c156e0aa9e8399b9" },
                { "sk", "80fa93f33d5e15cef2a39d9ff4e07ecce2b568b84788feb5f06c0126f7f9b5c5ebcfb5c71725b421a77dbc8a584afca333892392ab72913f85e9e5df098672c2" },
                { "sl", "1466134ab3ef14104b4bb9c19047eb051b6e1fc7b9063a6f4eb961aa25c2cc678888a7a0085e9d6d2aeb98a59854d73e34626ac7a551c10c16806c73e0f53e5e" },
                { "sq", "2cc6ea935927185dab4ae4b9ded9bbdebcab5eaf0b2533d08e577d13ad4fa7fc3f1011848ee37a142e5941675be407669fc204e71d59242cc7db23d0e72a8148" },
                { "sr", "a48b0ce26cf0c6381debf7acf325409af390b4985b999ea2e0ddd459479999c6a392e4fcc056e128a4bd59bc306a41ef26fc5d7b98d79b234168010327de1fe7" },
                { "sv-SE", "7e2b51c0e79868a4f5bdd237baf6e1b345347bb84a0e2a52f513af2aed0efe569b4bad9a5d713ee74fd7cfb3491e446404558f2f5dc3855cae12fa70afd38617" },
                { "th", "f7fbeadfa76949393af184a7cbfc98550186898b914d104b9e2094eb99a3c69d6989f144d9345a2745c8f7826b56120268e8a124b0ab62b81ffdf6088ea0fd92" },
                { "tr", "b96d1175a759f471d6543e8b0e7818b7154a3588bf1ab2f2459ad5773aeb21b37b0041753724ecd4f4d9a886d09049f95633d6e56f24b7f7c2b50c052db10ec3" },
                { "uk", "664be50c460de821f06125c347801b688ef8576b4b2f7f63d8f8abbd1e3245742d6a581a1c3ba2354bed454fd19fd6ebc6e2e788cf4c4246d0da884734ef911b" },
                { "uz", "0082729555c4519bdd2f751a9a6014b0016ee7a4a7b7975cb1035c94ecef1602fd2e4c2a2cd000d6ed5dc81468ce1000ee1850c38363d67ab037c2672aeb24e7" },
                { "vi", "e72f735df13f1d68ae3455f586ce6c97510cda27fb60dcbdb5025c8bcb8eff444b52e78d6bb8dd3e21c8743d6ce0a07e7649dadf8d0f0fe4298413e2d3050246" },
                { "zh-CN", "421f8aaa73619030fb20bbaca1018e264a6e65575efbc3c519784712d559171ddc0d77ec8d949ad254d21a8252fda13b18a27d32020d3a2db8b7734d88318498" },
                { "zh-TW", "3685caa663c77a7344d8810dbbb28aba64ecb0bff05a240c347c590a21a40e9bf9c434afcbe3d9d165e430db969aac4cab3f5ad0d1eb880d3ddb183577477595" }
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
            const string version = "91.1.1";
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
