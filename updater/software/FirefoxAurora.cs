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
        private const string currentVersion = "154.0b10";


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
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b10/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "eecf0971aa497f66048bb03fe39bd16b0abbd254bb9b841a634a3e455dd72cad3a68f7b22c06c0183dc90e02c36a3694c3c49ce548744cdcd43e83a3b940a53e" },
                { "af", "8b5bb5ac807fa2ba901b62866e66a7ad1431290eef0caaf0b26a1d91b6194e7a90e6a75108955da1907e35a28f03b8c12695823b2f37266326bce732a728048d" },
                { "an", "ede20e60caafa7f66faac8c6d5c5879139d06bb763bea7ba22f70c91987b8f110aadaaac59a7b88c8892e19859edacd5c2a589c74b7643906c2056bac358d143" },
                { "ar", "03670ea941299118751582313f98163b24f346dc27d08acdb8da98966972fffe0082d589310e56183a6065c5aeeb8d55ef327cfb9c963f19bafdf4cc7ce12935" },
                { "ast", "566991574967f1b207d79df28c3bf122f83500961ac48451768712d7b5cbea7cd2c51055aed5f899d1c49e82a3ddddd237777563280b587e92f541c50bc6c445" },
                { "az", "2acf52b9827c653b6a557821d28fe48a13cc6d9d9e44d6be5b4b3f73cf2c6731a6e38665ad781cd2eb70bd6fd929e77299e166a92185f1bc2e9884fb419b44d9" },
                { "be", "8942430b75e15df951573999f0db446dde7d98553cf8b4e1bb47cc7e1bd6e0cec0a19d0cab0fdf64b05fa1d40c706e416c396db017f5177ac5f6902e0cfc244c" },
                { "bg", "e4c8ce94324d4f49845df63f3bd78ed9a4b8adfdbcc84407aca281f855c29d8c544b6a018a231e4ba042b500c186384723cd9f7f7b61cba9eb7efb28977480ba" },
                { "bn", "99df6b35334219392b1687c823fa88b2b5fb9b9efef8cf02046f343e7b6656f3e9255213f141bdf3acfaf0b83c29ce63752c097d8c1b035bdfa2e74e32d0f65a" },
                { "br", "1e7ec1825ff3df303ec00af6d9e55678c2aac3641021d0b5022a4247cd9c62569f59b8aba51fd17069b6436a2aa014bbd3815c4bd17f285aff37d90a98fac087" },
                { "bs", "5cc2e0f7c2a23d5aedc011409696aabcacebc5fc4d9768b8c6599f8145ebfa210b11aa40480beb098655b4ddb6176e4fc97fc950fc5143a920941d3bea6636f2" },
                { "ca", "658404a01809d4b968a92d7abf7e1b044190fa08f4e265ac2cdaa207c46db8d3a3cabd4f98e04e24d730537e75486866978087a8f658bd90effaef77635e650b" },
                { "cak", "f395faf3f5184ba71e2712b44b87903798c599459dea8ce291913fb7d1eb6fa9a236835ff29255f719cf499b1f2d40efcf21b5f1e16dfb78a95e9e9431a6aff3" },
                { "cs", "9563b2dd8e04a67e1e2092ea37c72a228ce55df8cfe1da8fb180d980305ff23d8d304d5e8a18d96b72a9fad45f18cb743ff0db46d5eacffc27437f7d77d89556" },
                { "cy", "72108620140459e99fc254878300a8efdd389454c0d1041d25122e3314e87b229dc02228aff117fda4ae25cda45a3088448ae428ab7c0ba3bba1c5d15a6d473c" },
                { "da", "56775e53e4e402a5db3ea12c1dbd6dbf9d179cb8f1171599fc540649eb304ce83c98e86596dd2b69d8b1386bccbe577fee1600338803c2c2c04e1dc823624266" },
                { "de", "7ea9905398618f1eba6c269b6f55d3071c444a2d6716b539e810862de7dc90d247430de41250b2641a462ba849dda0200755d3c024796e5e1874c29f5ee08af1" },
                { "dsb", "8a86e7007b7255decf88a0d10fab52e027f6b2f0581aad4e1c07a49508c96d3cca743d6607b7e541050011093795ae9d95854d1d6d753e2d79546a8f1cc2e192" },
                { "el", "a661e0ac638658a42844573eaf9f22957b04f1f5175cef6086de016412d693b9c5fd3840c6acf304d2608a3d7a2a2a44e7e14a3681c5099e7cf6ef69253d2504" },
                { "en-CA", "e4cd8e5ab89873f316c80f4f9b032b42c0368ec0c131c9382e7792e9ec7ea678724e205405b97acd2f5e6421f12f706bb9752604a604f1b215bbc1b83672e155" },
                { "en-GB", "f7dd29aeb2549f9f888298b802c7f5b1d422396f93076d4fd616bfc9a9f4f725b5d68fad189e2a114a42556559dab09b246e760508eb50ea210aa3412714e523" },
                { "en-US", "f6b91072db7556eb454789374fbeb45f0afb840c46fd6bb5867e23ae23ba9140cf0dc7eed6ad0a63e96d9772470b5b2cef757307350c194582b9ea7114de973a" },
                { "eo", "2b4bb1d05a3d977818aa607d2c6c28ae87bef36814908e9e80aba5ccbcf12a92dde4b86e8965f4c01343764feb4da6c3a5088a6d547923af51a4ab444c2a718c" },
                { "es-AR", "0544b19aa042c7661d67420c4ee807e3c30389711b0f3d81f8676c95fe02c92fe65bedabd5f9925ee5f95826dffcac23f3e7c61afaf816da4f66ddc865b7e9db" },
                { "es-CL", "0da392cb98480ccb6a9dd6a24a4570e8c0f00a6d2a41ff065a4e620fad633d69e774138ec6c38f9ea07efa0613ff819aba074e24f236423a591c872b5bdd7cc2" },
                { "es-ES", "716ce200d6070885c160900926c3958c0414348d45267935422a69768b5b44a9bf006014a32680376048d24f62d84e3144fdef4a6268407a5b16e53713629fbe" },
                { "es-MX", "0b0cce8af3aa79a4797bee16f699bc1e7c5485bfdb3b020493be2c89b5e67e83a6970ae47ce4b78e32132677f061239858f6fbf4072170d64aef8d4b3c69ee69" },
                { "et", "7c99068d490413d47193de1716097cff5d009570865ed846d17e70eeea39b5147acf2d2b64695614327528e3e498a9d8bf81b3f319c5e294f1c264ce156bef68" },
                { "eu", "a43100acadcff2aa08ec6caa850b7eee878e30ecabcdf50ec975d080abc784074661c1c6ffc512867f381a2ebf09479dda007d713f86943dfe1caaa09c00735d" },
                { "fa", "0144a9bbe68e6ffd1b4645029a06f4b983d27e3088b91e0bb41154b8d48a1a1d0345271b182f2ea2966a890e563c2c35c752172834f6db9da7ab5f366ccbefce" },
                { "ff", "7c5c63b720d364dccc5474b8cf9c0195797f7469fe62166b4b961dba11753cfcffe2593566115e7bf9cf7cccc4ef159431883fb3ebbd2f35fdbbf7e371bcb3ef" },
                { "fi", "4ca9b86d66fd0a811f0738d2f09b3184cb80f131e2b1aa64abdf8da2bac577213a16af3618db56dc7fbb2e6a74eddf3559faa4dc72e513a6f5dc0312a751921e" },
                { "fr", "87223c05f303991026e1d52a946c3c8432a0fb40234ef0467bb21c747044c9a1a4a95fad6bc616729193296983e9e1d0af4f661e9482c7bca2d92965946f1e8b" },
                { "fur", "ffdc8d27be2e803b6345e5a24f5e748d8a1d984cec0f6c17b38fbf908b375efb3544e54510d146e28ab6ea190dc94492251be2bb3ec4a17cf74b4edfdd4f8269" },
                { "fy-NL", "74067dc20d2fae0acaef5e0b66a4cb4fe759a55cde3a4063d6f80d1cb1a7fa97d6a796177b258f93e19b2a45da5ec2b2efb6f1a66ab4ec2943bece62d33c951f" },
                { "ga-IE", "138cb8449503988607d45f4fa1873680bdc329950ef269dfd8129f61860e2ce56cc7f4977463ce9ad4e017d268eb8c85fde781951d6cccf3ece18b2cba542bd7" },
                { "gd", "0664baf610c23414d56307ad5f050f50e307f83d82c20e0b37c013c14a8c864e7e170f403801c9188daa5a61a228a6b671a723d1fb075e690aef88060fb07109" },
                { "gl", "6e5eb1b4b14f1ef11367c0710c14ea201f9d4d4473845958616f47f26a85584fd8e9fe068c45e7eb49444f4a22a7de065827b9f12ea8abb62e5a55fc34063fc9" },
                { "gn", "a4f87f060ef898d2dfd94ecbb40bc18691e7ecd9aa73b0ae97172c731be8f227a392db2d54f20a7d2260574c3ffc60b0040b3ac730e5001a64b3e8c426837098" },
                { "gu-IN", "5905d8743bcb7ff95cc79f3dc29758cbcb2be0f5d8cd0ddca5ed949ad78a763dbbabd2fc42ee342e6b365d8dd96f3bc5dae3efdcaf2750061f9291dd72c07043" },
                { "he", "849114164af3962ffea93a42a91bce41e62bf85fcd04faed96c3ad93b0c8ad4494ead8605efb00d561dbdffc4640ac2ee6a6fff58290f63ce8f910880cecc377" },
                { "hi-IN", "d9adfcaab5a424e976cdf7758027f6a2c87de6226442f3169f9640b292a142757a3993facb7141e0192c67d8d1a15fa4db2bb983f624f00d869b3c8fa5aa72e9" },
                { "hr", "71057f68fb8ff6c816b0ec0e7cb656b1afb520c46db8923312d222b9e92643cbe16f31734e567d43e4ee6ab13ab03c947a04a73a4b351363c65d4168e9b54123" },
                { "hsb", "1091e503f41d031782ebb120fc92f1807890a1e4f67154a4fd9b33caba67e4342da43e3ab69dc87ee99ab7c9bc1e3f10132f920434758dc502a4cebcda996c50" },
                { "hu", "116021d486013111282982edd59c61ddad9ce7b4417cad223067a18241a9ae51eb4f2b37ab4dc677498ff776331cfde488a69c13ffffc8efdb3f8b9b78aae24e" },
                { "hy-AM", "c55d113a2376e6dbe44ba5caa6aadecee265ed59b813a91de82a2e5524e01f65b4d37ace21c0b27fc7d0e1826d2fe0a708080e1a3f9b92a55b6cfbe6443c1e43" },
                { "ia", "7823f8a61902f1491e09a4ea1721361d48785da69d921137f3517f2f09640f521c75a3b92eb80edd90d384ace1a7a7c3680db229967560018544d65e661f070e" },
                { "id", "ad693480caf5ecc8d87e33e61e3c7c748298222c701cb776af6c54fb26357a4dff9af34207d5b62055ef33cbd7b15ea382613983536cd3b43b45a6d8c76b8480" },
                { "is", "c4461eb6e77a3b739d35b9768003d258c91f9952da4e5e5cde9116509c2eea115caa8287cb6f937def36f58c0bd1b3a0dec117e65245360c355cede4c0be586d" },
                { "it", "87f60b54bba001f891790d6e43e6f283a93c62efe009b19820eb3e2cde84270ce5a3781e474cd486eb9ce4a93941b4ae95c024b2881bbca3a65cf6b6d833027d" },
                { "ja", "5f795f4200d678de199352dca2ef7182340260804dad6c26e36681f35b55e531ac0e9058992724e64c607c8df44b48f71da4ae13c2000e1ccbadc659ae4827f5" },
                { "ka", "c599f86330e5b3cac3095ee2fb6200fffc2fd10f23766d806db6d75cc5f798cb5a38badbcb577bd1b1ab3d3dcfa0f0c73ab5ef1bba4c6c07dade99f398cb010f" },
                { "kab", "f8b5e656e999acc6987f221a25fa4296ca1b3bfad7d373794c89d513d333748af5dc637311054ff79028c31eff9d51106be4e3e8f64d9a9622dcba357307f656" },
                { "kk", "b6ad75b63bbcc714fb2143349205b0565a9f159272d4053cc1446a6263a26e1c850591799f3a5010065325b4d592ffc1099c7a8ea8f05fc0d212de81ca775dd2" },
                { "km", "0b143caf88149257f6afef51d6686f7285d34ab521031bde0321191103608535655b066499b7aa1af974beabf166fe811e0675659a4be8779f69b4438f28a6a8" },
                { "kn", "8aa4df31b1353f4fb97dadd204d51cf071169f9a9f6803a2415fe1753f8ced1a1c5f48aaedb867719bca71a4158a4f2425cf0e5cc3feec1cd1c1c31e93968187" },
                { "ko", "2c1c06b1b6055e9d38d5c31b3af697e501bb01919696bdc7ff2c581e7632f7e226b722abbeb2c5a7a7c68418ca717cf8eb0273306348a9835deca35837f3e198" },
                { "lij", "82411f8dee91ceab96ef3dcbdfcac4f86ee5e25b0b29d9a4bbcad43832595d1577ebd5a0d0f1e946e89d023058e96faee54995f0ddd707bfdf8ec163fb05c918" },
                { "lt", "46b99782d77b75ebe2f462ca4106540170d7145dd01feb5aed8f53d26f933b173782e0ef91fcbf573f126a45d4195ccfc4a163e8b698897933ec8010194d0cc3" },
                { "lv", "6f41ee6e189e377b79c41986c59dd0d5d0579710707a325494503ad3badc302df371ce8e64cab6ee87a71672ad0f37f49c34ca4b7de8b72c331935c43dca8f56" },
                { "mk", "91b693ddc5dca6449da181a7ca0e438c005b0e1d114636a712ead0ffca9066c76d3c3b1dc4ed1ca97d5a64549670d06de05b0dc66c4dba36e769aa1e1a65c73f" },
                { "mr", "27e36037c49f58e00cd83337bcc6b11242512127e9060a9d1326d3c21fe23f27049c6fcb2982854d68ef41f364708719895cbcdb6c55578b874f0f55dd57f901" },
                { "ms", "c6a9a733691c898990b6c1dc275c1e46fd8cdb5951397761c889b2ff77a6557d1ab745e158c888c1b4da800026e80527e56e1d5a8ce0a5c022bbce7373b3c7da" },
                { "my", "446f0ec10b73cddb95e5d9fbe4531ae55dfff1808c60be5eee158814a4157507ae453561f930717c81408246271fe99fa3217af4385e63892473f84208a14e71" },
                { "nb-NO", "158e75fe2723477a507e3d2698e3dc7bfa5e41091b75928a3f4eb9f8f1348c22bf2c3575c41b29a63998e1a355b88a03bccd5380f7931bc3ab171ec04197f733" },
                { "ne-NP", "d69d4b532cae40ed60405db2106ffeb0985abffa9e62718682c8ae928c7d057ef79a02678711e997fe1c498493e8f0fcded5ff521e399ac3d38d48e124ffa096" },
                { "nl", "5b8eb6185fe3123b270758cea1f1f503e34ece8bd216a082b17c3845d6e51eb2bd439e4f04d77ee67bda8a01aa87ad7b64edae64a8b2cb37401e62d1728de629" },
                { "nn-NO", "704b619984b03aa724b4adc5c92cd15d9ac10d0a45605cc9afdd5ad1503b77cf0cacb38b97b6039d50b5ca5e8f95c4136d0086aa431779cb9f27585c55d6cca3" },
                { "oc", "2b08ec3caf589ee69ef4bec634d009c0ee311264b3a37b4cfc4168865f99c68636351fc0eae471b9a7106e7aa54cd6b4932989e56d0a8ee4dcedebec926d5003" },
                { "pa-IN", "38b5a80a5d0d867d2ff8ea248f2b4e00e38c0fdab49e3225996328f08ceb9b61dc2ffd712cfd788c6baf5d933a6c37533929721373aaaf67b95b94a89acbafec" },
                { "pl", "6d30773986aeffc4683fda596963c5e353b240d801ea82dd9788e0404092a58b630391b7d40fb5b4e0419de8b668e4309f0674e70d33a14c19a9408eb35df7db" },
                { "pt-BR", "f66fdf4c382f5331855764c581cd2612989962881b3d2d3e54f19f1aa260e0695daa12c72dbd9c7410fc953488df0d86bc29719f64a11835bcb51f54fe0198e8" },
                { "pt-PT", "1e07412db7eaf94e6fb98d920cee5d4f7de375da67e879bbcc12794c0d8bad769b55b4f7fea33be12db44146b853458dcc0bb2814e160f81d6f563805e5458a7" },
                { "rm", "9076082077d3c24b64ddde4b1732b755401a9b4c7c7024e29ba0f58bc1c1d8cc81203c197fbb45e5ebc63cbd6eacae3767e86a20bf09aea3de0e8b5414e1da4f" },
                { "ro", "704ab69155cdc76e93b95f0b37e79f17e7bf484d513d44d3b6a101b53e10d57129c430ab43b32bab5b5a2bffeeb1d15da8d2cf778aad94954ec8280bb3673df8" },
                { "ru", "7ac7e3c07f88cd92e2c36de3830dcbcd7d8f07acfe980f7bf34ccef18206f8dfc964853bc7fce40e63b0eb55c39d0f5ad86fa5f828b52e02e890cd472e4ad5d2" },
                { "sat", "8aba16a2daff2cfdecc8c610d44c049753af10046f93fc8389afeeb712ae210a4438b4d90a114ccb15fe33da32fc849d00221ea7d1aea63012233c6000cbcc28" },
                { "sc", "f605c8aab249983e952e8664df903f70abb3b4aae4508f30ca906366c3130cd7f6f61fa3463fff40f9977b35bfb5e595b9833935cd6c4aca71d5833ed325c315" },
                { "sco", "94c3c67099fa6a7de1b813ff5ef6d1aed01510bc3610e7ea3c9da30a3b3e415c6a78ca520c492985818c40b6bab994edd14ab1e72dbfbabed01957f9229ef308" },
                { "si", "154c3c67016e4bd537d4741a32406f01b0d02ec3ed41082126be9c696e59da6071f2ec42739cc89d220f761bc61b86fe734dc5d02fb091bd9638f88c44e70134" },
                { "sk", "0c05cf6739f5f4f8273e42bd9f8b18724dde754782bad87c08e8a8072636cd167e3d8184bc617756407f10eb283028e3e7981dc95db35768b2adab5d159e4200" },
                { "skr", "2be5c13610fc8d8769732eec974890a8af851bbecfcfa18b94ddd251a7cae223b2ada07eec237f2e6f4f9564c0e0fc7d187248214a615daa785a1abbe4e4f30b" },
                { "sl", "2f982f6e8dbd371ce373f4b472975bbd777066f4fd0c164640ec96d6be215a97c0a82404019ce8de7e5a88398fa00581c21de97ed52d23d885ddf3ccdf0a4cfa" },
                { "son", "c5f493f88234b32ac2d285643d3906171bdc4cd20bd424c17b2cc5d2327bd190d3584e053def72e576425cb65d5a0592aa6c667a984b2dc824f7c2aed6c0a0c9" },
                { "sq", "5803e9f55552f4f65eeec3712021835cfcbd354a3ee036260fa59447bc802fbd03589a497e0a18cf32e3c1764d90354fe1000f45e0ec26bf3088cc3105be21af" },
                { "sr", "8cb09ade41f05f9df0946ad11c283722bef2d7668b7d14d35887798353a8e32b200449c99fb2e5645f6245a479a6ec138637f34b5856b9a9bdfad49737feac46" },
                { "sv-SE", "6d52f46eaa11d20553388b451420da03f0b32a1b0e8820bc8370a70eb69f196e3911d65c1c014b0ba741324c40d459d9e9142dade14bea547be9dd38679c3f9b" },
                { "szl", "8b67e8adac88b94d39352d6ccb3230061a1209d6626cb2c034ea56abe1973ff22947418bf6498c8c240cd2f28a7d48a23a82bf96286c599a46e41f32838f26ec" },
                { "ta", "0dbea089da1076faa78980c7dbb4d27776207c12af1392a01364a6d5750444e750847b6d260246261e07ab4c192b864407ac24473483d1bf245340f5a2041606" },
                { "te", "236e010b723af4f4e8fee5f379682d9c5effd7115da100fdad64f16487ffd44fd6380328b9ce626a42019a7cd16bc019a288a7908ef9fd5de2a3365d8d01efbe" },
                { "tg", "a44fbda8433b733e34482240ee5f743586abe9771c3d25926d73e5e52094baafc68f2cb12d8a968a759387a6055158c5ca97fb9f264f7aea247cf45bbd79ca02" },
                { "th", "a9a3a62b88292f872eb16bf6e2cca00e02bb2fc8c329245456bef3a98166c086798a4d6e33f3d246addf612c6c616650e12c2e182b79f1b27219d3047c4b58d4" },
                { "tl", "993b7694a245132bf6b14d3ddc2cbaff60edc479f502df6eca22cb2a0a8947607be66bdb21cd234d306d47992e065b553b87bc4e8d66f70b566086e0dd593dd3" },
                { "tr", "e5262034d1bdcde726f2a0788e58a9a2d8f691de6fdc5ceb8ce2f721cc9447872b9099ca1d9b4647f39e7fc0e8788359f4663c7ca5daccbe2bbeaada9e89c328" },
                { "trs", "2b37e1322d9a2356e9066700640e101ef3a4c5b4021016d10bd5b6cb074435a02ca348999b7db69e90f5d60698e26d5ab3b35ce44000bf687e87e80ebc7a7bae" },
                { "uk", "ee8f5055a100b976bcd774a2afcaf9cf2d66ce332aefc7302cc41b84865424313e369d279bb5c0e5f39a185549fe06797e3c5e8f4b105cb9d07d41b297a9d71f" },
                { "ur", "cb18e034d3b1bb74dea9c1a32d0f2e439d8990049515b09f1c1ce512f591aa9704feb57d818c50aeba0430072cc40090d8faa1120c53600a9485f6e959cc1da7" },
                { "uz", "04d1bf890d68a538cd38d4527b97a3743a98f989fe96a48e4f78b99c80e7b354b3630a07356826f69136e89fb48a6a0fe91e1274bfe2bfea837d18cb4f923cd4" },
                { "vi", "d0a6dbf5eacd7185e0a12ab005792786224b4b544d2ac4828a084ecab4f2b07fdcf19ac4fa5df2c5632cf14683627ef032fcadbc019e2819d883759bea18cfea" },
                { "xh", "27161ba5278a8cd43412083d7028316d2e3bea8311e67704489f4b576b80b3abef5876ad87003955de50064fc6956e3d1a6fb75757ce11cebc41c3ab587996e7" },
                { "zh-CN", "37d9dc5469b0b3931a6af529173ffb0f6ea21f319d67c805b8537f54cfa6b483f27ef979b685dea15047a24262b1468eb6e65c8752d0a51c61a065c3e05cb324" },
                { "zh-TW", "2c77221f04316da5a43e8a518864b80cd2ae55c8bbe313378a24f275834fea99f6e17aedd5bc90e361d7ebdbb703eb993228d04e73d30449024362dcd82bcb86" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b10/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b85286a2e300a062a8c50efd8a35825a09f6de432cecbc6588276d905ddfb0b60d797c7c84b7fc8fc4beb97548f6faa220543f6280b9344b2e4e7bb1b9b889ce" },
                { "af", "a7c777158aa5bcb611cfc7798e27616177cf4c879991fa8088a7cdd0a4218bf25f443e0fa5467730ee837bc4469fc6c5f573913e2da89d89b336d965b08676d4" },
                { "an", "b4f141630791baa7a9695444742ec108010d50e43b4a90488a8165ffd2989de73ef68cb31f258caa6764af3625f4c60a027073f7895826c96a3bc97e52094146" },
                { "ar", "7136b79b346c8b7ad164c2b26200861f6811d15855e91c7fe54961879ca7570225423fb711a66bd0cf0599bc1764b163d5b7aea348b1869f74f0ad027a442b9c" },
                { "ast", "ba94cc5b7d675897c17e606105bcfb325d0c738f624452b9c5c9b6d682348a0fbacac0b1d0b4d63b2cf66fa0205841e63d16569de0b3fbf81f99d44bbe2be64f" },
                { "az", "bae6b93eb4d7dd9130fc928413cfcd86e443b8c3ffb064b94137273acdc8d37314344f3b4ed92e524c9ab8c862a485dc767f98a41c18f322ad77da83c9da5d0d" },
                { "be", "41dc54d54ddbd14ebdf5cf2b99f95f00e2eb7f719a8be7999950e242c917b8c3a793d2a28cf0dd95e0c888fc8c8f7b672ae81703a2388127e61fa00bbe49c123" },
                { "bg", "2a4e7ab6c50d68544b1dab0eee4ae5fbede28dfc0c39f9c3fb8f32935bff3b2aee15e30cfc225439f789031199bdda05366739f1edd76abdc3e430a0ec09f4dd" },
                { "bn", "872e3f0d9940833051693d10af0a0285d4e052b5b28b0673fd5c6fb7141d874c8a91193483cc6ac7509b4b7727be3cc025657f99c956fd0d38693372ee27ef55" },
                { "br", "b82573dd35afc36d337a49db0965a2a4f349ab09a4297f8fa1abfdf5db14c489b6f55ff53865cb5433a83867fe959cf6e59baaaa6cbbcbbd0ca454c48c7962f9" },
                { "bs", "4a61806199d2a15d514489b8d12366ba4cbbef8575c93e4071aa50eff875808e6b1a5eaadbafe4ea9d15c84799bde9d3da612f35155aef1df2a505107322d094" },
                { "ca", "713bbdd398ddc123a90cf4bc92b662c140557ee119b8fb392d5c23d6954a81779e3efa5bd91859424bffdf09db44864450cdb9440512e379039169bdabbe8b7f" },
                { "cak", "17a2f5a93b30f81965ad33da99214e51de9c53b24574a51c5728c2ee72ee96211c453d9e3a7aaacbe82c21c78ab406536dde5cae82b0f1b1dff72993f2d16acc" },
                { "cs", "740f43ecc50a8b21f17b7b3f268e9f8874d99b00fd67cde858d6201fbea790b3deac2bc13e2dca0efd49b52306ef29e2a39c25582e202ed1b55ea85293b1e654" },
                { "cy", "384973c5e88e34815b423c7d61baa560672c4296a9fa5ff876fe201d80430c238d3fe6117a1b5131edae0279e8f2b3e5b8f83d927bf3d3c3af2a889b2aa08e72" },
                { "da", "d93cd656985b9dfbf4c128cb726ab700425a34228dd4c892c31028589536090bfbec06125ee500a6c961029e8a52221d15198e91acb57f944eb48cef43e06b13" },
                { "de", "76b61ee04660c219c0354ecad57b39b58d00f3f638357894198b190f5f85fb41c931dd42a1dd9a50f62b56e8d0097698541019edd5e72d9ab6d3f6273ca42603" },
                { "dsb", "f9b68672aa05edb2bb56b1ff024e80609a3b0726b0c7ab8aee5cfb7efa7799257a718fee9c743b31b03677006402b493a196ab783c03d6c183de3186cb9e5d53" },
                { "el", "e534a84ca48f0be3077e72e7ad2dfe476b2fcdceefaa2287ed1b6d52dfd2a903d77aace0cf6aefc4d64e4fea2249d7e23eab3d46c2e6f728fef822eead981c60" },
                { "en-CA", "481cb1f80718b4cc6d5310456609f3eaf08239b56a7f31808ca2504c08a27eb15b56f386f48727d6c3207437aa9d69e68587ec0256d65170b2eea48d83652f42" },
                { "en-GB", "5e59fcb1f8750b30d29bac890c0506ba82ffe8a7d4e367f5445996a705ee6054a35cf0dbaf5324a69e1e760df4628c3d219019919ef2993627f61a5abbbfbae7" },
                { "en-US", "57f3284ec3be8348bac47c1343e52ec6d5478f6f8e93203a3fa77437313603713be1186f52304dad76f5cfcd158e221e23325bfb41f560881178031e43c3fff5" },
                { "eo", "d20a30e2574e8e09a75f569705e9e16d5db6df0850794bc7a734d2774528a450085f8b6f62b3fd45e01498ae73427e6e0ff2a7083bc746122120681aa556d2bd" },
                { "es-AR", "3a87653d038c47868212ba5050f8a99a4ad3248167a16655f16bdf8053679081bb140a9202c17fbabbc2931fbfa5d13bbe429263f6856d4a88085f477de6ee95" },
                { "es-CL", "274c61c712535a3393df13972c5657bcdf7831db49efbfbf191c7ceca2325467324087e9b02262dc913d5f58d522b16c3fe933a72ba1df35a3112b8aba759a8f" },
                { "es-ES", "80a5dad6031577c8a668ab18ab443d603e17b3d0b80d71c669c27c6f0dcb6554c15fc2181fe5624d7d49c877565832e59be6376e6074e4c1bc427820baf061ae" },
                { "es-MX", "4de7f1582a6322f8ee40a9133c6bea1ff2ce92c546887ec91c37adab99e03abe2601f0bca59938b28f6f77fd86789cf7fa76454c6c86bbc85e11746dc2351dc4" },
                { "et", "da0dd4bb6a35fbd16375ac86aa48a401c7839adf8cf7d32cb9f69b5683d1db700e6bf2181c7eb8bd7fee63a97ed8c046a07cdad218c31b69834e17ca9a18bc4e" },
                { "eu", "32d8573a180eb12d65c2f4079696395252acaae5ceef7280c0fac976b0adb179f65fe313b3b68f490d3a8c1e9ff3e431d1e38ebf40e2a599ed0cdb3c2472e27d" },
                { "fa", "fc6fbb3430d89229b894404bb962ede58b7624c670cc3217da1a311a090f8627a7206131495fee762d8642d864d9b615271a65069efd0fa77f0ebd3666f323dd" },
                { "ff", "89d5085924efad246d1abef699ade5edf16df874d9c3c81d2a17b316fc0d4bc09331971570b57aa50cf1bc499e8a8f6ee6872db3057522e64fca8caf078e63af" },
                { "fi", "2b8c6eda19a1ce090c8348ba3411d5b93816db71aaa8f3d4a7516a2d4a3ad460d424143849c58e29629a5dc14ad7a51a7d05dff7ce0007674fe659275703e654" },
                { "fr", "175c6cb0ad87bfb43b870517d07820a4d496128b1bae3071f222c570671870bca70fde35686fd34ee94da7311ee3b9b3806a6e54d768b11feee3f5882b632e9e" },
                { "fur", "ac77a201d0c8d56585893a3ff4c972ceb1ae3020db483872e6c46f6b2eb381f8e78ef5b604f24d9f66f01257cd9153c037f87a66160dee0194863e1f862dd500" },
                { "fy-NL", "af1680191ee2f92579a9769fb016861202cf0a7a9a074fb54a1d33b34ac3c871ad4e8c01ce649e1fe0caeea99137cad7f6d6c2dc4a47ae43ff7b531c806dd3d0" },
                { "ga-IE", "da53b8445e7722bc4ecd32d25898fb7ef4a4568532375249836017742f7f588f9e811503389b2e67aa5c4dfe2d13a7337eec54e7e0b5450e732a82a69020f367" },
                { "gd", "91c9cf8a33da834ff5e6d1c8627e282d15d5ec99c5e9d262c737149be6f6f71b3ede275cd5e5843ce2c498f5443c8853e96c5057c5243cfa2baa91b75feb4aa9" },
                { "gl", "b0ccd7585bdaca9adec2320a36d3f7ba0dfd5ea76b6a1f3550de39986f4230e6812acdea36adb3b689b85536742bf3a5e948288e13d533dbcf802100cf832c26" },
                { "gn", "6175e2a34d544729caefccd30e570f77fe87da23449ac489798e03d98c11a6b70c160d29fe7dd82f6e61db3f1388f3e6b5b8c46aa25cc08cf6665bc3a172caf7" },
                { "gu-IN", "9b87ce30970ddc55439a12163da378412e556ee6b980cb7486cc50f11327b48a3bac9605b725cec0c07d562d1d6c64adf098105712d6afadd8e239a382ec6a45" },
                { "he", "3ac38d15c672c5af7405b16fd59220260b16caaae32847db80d1c0022aedd98aa29bd757459d4cc342051bbd98b0c44bceab1e0f396442eb6cc1d371a3e7ccf6" },
                { "hi-IN", "34434f7dbe2ebf36b681293cd4a750d0815205c506b86bd16f6f2b4d0223f0f6a5221143e8168098f3d9312f4e3ed54f5dc15058ed47033bec30ff4f84b67241" },
                { "hr", "4531a26292560aa687a257b6abe5ef00f87ea50040b4fa056947246ab709847711f459c4675ced11a1a427c6ff0c98555c11b8893c6e537c9125fddee2fb893a" },
                { "hsb", "e6b44a84436fe2793b7bbbf07b6ff0fdf4fb7e22b2538d12791edad4e566a3f13670e774e2acc06f38bb680f16abc0a1640ff467c5c82ba03e6a9d4927265e19" },
                { "hu", "ae2476f7c1efbce519e88e20b4467965a589d0bec9f58eb05060d69065c1c74a853b40187f2ba3cb59e278433cf895f97968e1fd4b59981c589400cb513fe529" },
                { "hy-AM", "f375639903a22880f145ec9a5c8619e26a7954491360e8987d5611b2cd9de6ab99e911cdec6bd998e92535bd745367940d7deb0d76f43936ba9a410f0dea8a3f" },
                { "ia", "107bc858b78bcf15fec9ff6012386e7ee41ad4a7efd62bea09b437ee043fc00caa741c17b74707aa680842f2ba406123c7a4ace70aa23d3bc132b9e8e9b85b19" },
                { "id", "39352d602c42ab382ed7c92ae6f38e5eb0e349e9ad7f67810f1eb0b81805b28364862a3a6148aa253792057563543fd41e1b8af2cd3d7b19350343541967d557" },
                { "is", "516fc1950f544b0e505c51ab1a058cc5834c0a3e4f429a4fe73e4d482f1c78814c5c37d1a50a5c21118261a07d9f5f838f51921c7a45f27ff96163e85de83dde" },
                { "it", "53b6c88b91480425c80883c9edb440de351b27adc3900c7beaf4f565ad8cd03dab3b736f4068f6fcfb7597a90bf0930d07c4273d4e5075313a839bafc095db01" },
                { "ja", "2d2b8fd36efe698c9b7c4c9c9bfc84b48b04eb68c1a92d03dce715eb28aa7a11a3b1f63047cf6b7abc12a22f9740689cce79e50cfab220fc01f01b1a95c40138" },
                { "ka", "55528fe6a8c3116620db68d8edfa77a12642c1ea83eada9c4b980777d7501baa3f5459c7c03edcfd05306cf90657f1505e0b1ed6ebc737f667cd7299671655e1" },
                { "kab", "3d775db47dcc4455c3f02b2871f69431dde62680edefbd0be30e3f573d7d54a3ca4fa543367ee4588fa073e1a1cae4fcc76ec2addcb379ee54867d8bbe59c9f0" },
                { "kk", "021671175f23167743a08c6e455ab9e1fab7fc292ed7f074373afefa3bb83fd4769efff1a5f221be9543cd65734e32c2b6099f420b8a2af32468d063608ec8ad" },
                { "km", "6311e4c00d473555053944e1a993ee9c7d76f49b56216024abfa136d0442b725dfdda52e95fed18aba6b9c57ec1fb88abe3130981adf1df811a673a3f4ee15d9" },
                { "kn", "c31250fbfb8f2188eaca7e3370ad4e77625aaee707ac42c36a32220e23936135f5e2fe95779caff088aa4fa8803261c7ef2ff24725003665642715bb40945d7d" },
                { "ko", "7bba9bb92b9767d61fccd6274ffb9f1df454ae9dc9e3473197faca60461afc5744d4939c035a5dd50cd36d5058a4bd57b7974941c77a6e85a2a17395278a379a" },
                { "lij", "818a92cb4de2a3d2f61a495a8a0017bf143218adf5ea27bda495e81ad2c6c0ba9d95468fe19d0792f32b4a696f173f349db5aa24f412673fa0341441efbf5fdc" },
                { "lt", "d746a853b89570019ecfc5765cb41fab81d25b9c064b5d5da78c406c82cd450776226b564d1a1e77530530087bb054641f7c126f047149a7a4e2725694c69914" },
                { "lv", "102fc63d07cfe937f9cf9f96ed4b9b38279536893ab5b8f68250a747dba407106bfa1387f28c805246f22a1a48aa1fae69dc4d6571aaeedf700608f45cfbf928" },
                { "mk", "3223138faa4dd170cbc58cadf8a74f2827264bb9cf83959aca48e5121f8b1b733b3091c7036189967f54e69f60c16cbd54c0efbb376f1d3f7461d91f27a4c767" },
                { "mr", "1015923b0fe70afb5d76cbf10204a5ae543cc06f2cf096b9d945a7c10591bdb6c1ab874e29d74927352d15adc483c8ab41e9155d73668d36e520fe555c53b748" },
                { "ms", "d49a17d835f863620ce53d9754f3c4083c76b46cb063e5c892d21842f2fba3614d43c19504be1b13c1d81c235ecc9f045155d6bd9a9b5841687942066c2a144c" },
                { "my", "2f7de6433d170d89a5573c9c4a7039b0a3893227f44f94e2bb91320dac82c6b4fefb0230419420831c76b18e7628bd18c426428901aa2f2c3deeb077e1a09e50" },
                { "nb-NO", "8161a7edf59c7deb808a4e26383e974845a804079cd8e6980f95c4cac7b49e59ca55a275a8d92dd1e872c4f0efa270a6df65bb138a0a1d04749797b9fe3854b4" },
                { "ne-NP", "6beddf00a41f383729874c32e337e82c5c6ed0f09b600d11076b69a5017074abd88b0325cc03a19541e55c952f6478ea6ee3c9da1711de4bda245283c9feab4d" },
                { "nl", "328495a36fdb6184b2c78f4929291828152393b02310bd3a9b206ec36f70aed38e213ab36552c9d810599c8038e9a7ba36b4b57c805efbcaa6aefb6b383724bf" },
                { "nn-NO", "c3eb1f426edf9c3ee1a310bbcaf55ec19306379479cc1aaa24e82aa5e1fb25f28852d9763eb2024dbd76ff212def33e6a5fc56fbba1d5a42f3d6b467a40a1b15" },
                { "oc", "5d4a96bd1887fe15ede13ed2b5b75088efa0189c30b4f2a9d61e624e713ff6c9654c20c3bcca41a3b8fc67c55957c6a966011a151264ac43762fb1bbf121f2be" },
                { "pa-IN", "81e05dad8903acca9141e3653c474038697c65697e00856a72813b6dd24b44655d92853387c10ccbc259458172d3dc0ae02f35c98abd668c69b16604c9e50e29" },
                { "pl", "1cc8091684c809a4d4e065701dc5cefc62479a054008d0c5ec01b1dd01dd5fe0aaf4b7613cf805b023fd7573aaf38a2c03b94d4de31a0996be6e3169b06c45b1" },
                { "pt-BR", "c1349f57c61564ab8d0f8ae9fed72999e8a2b4dee741fc0f49e7fbcba199b3a4dd699f7001889a704eadd2e3e1eedb18f0add4d1f9b73f6ee80de293068fe0cc" },
                { "pt-PT", "a78f4c7edb89671f1eec586a5c1edab008ca48977726187fb57932e3c0a32f20f31cab4ef917b749e40af1e7251a86098088889a6d773989994b69b26681f9bb" },
                { "rm", "6c8551165b78922df7e268a40f584411e0f3304acfeb3de586d48d19131c96d1424c06d80c98cf4b577b6080e68d8401adb12e6f70ce0718edbadf6ed1315464" },
                { "ro", "c80416a9fd15c1e68754fda958d807e8bc32a440cbb5f1320092761c715496b460ffc6c83ac7a442ded00e2b4756197e5a4a65ffe681be353049ec975045829f" },
                { "ru", "1580a276870560cd8814d14caee72064c59cde2358c467e9a2aad90af2dfa38766dd8bb6939f8e84a736b820ed75d5e5c0dde0b7d4d0c045caae2c0072005b01" },
                { "sat", "e0c3365668952f01078b59bddb75738ff0cb7fffd1492e99c32eaefebc6ef79cab3cf34e2463d8abf1db6f94367e0b53171704951f5507e0683406cc42d5cf18" },
                { "sc", "5d17d10d43417ad95a59fbbd1f4605c60f2d1ab48443023d99ecca2f56eae5356c269726f8ba6f59e534607da947b2c88e16018996e8bcfeed08358f85801999" },
                { "sco", "fe450d04f85be4fe6945bf1d4d0f39c7b1ef0c79545ed497c64c0b75ffd877ae17ae503bc09ec4d747df1aac32912c471471cb10c06465e8f910ad9a6cd7e051" },
                { "si", "0d5ededfff6778ba0eb5dcdc6cc0f306aa74c64b81bb49e0b00f3a0dde7256751dfd565885fd3869ce5cc07b0fe1f0ad76a491490c72d1ac9c5ad97d131ebf00" },
                { "sk", "9b885a7f89c92a82515fe3ed8dbb3dcbe5893f3b07a32cbd2176865b003568806a7a0d203e246c135519b525baa86cb303a182529ebf604d1ceee577e73c5deb" },
                { "skr", "f3b9574469987695026ef37e18e6c3c3f4c20ef76a4ac49cb7612128b352aea133f21dc1eaafcda9ca59e22caea98d17ed2cfc310e25fd22033f1b42eaaac18e" },
                { "sl", "a6baf4b481cc21a244c31dac2bfd362d52356ed61f3b8bcc6e561f4d9f2e9b7ec2be32bff73aa95ba45acb7145d66a4310806876100b73dea17f028e8b21bb30" },
                { "son", "233b8e1e41ed21b24ba03cb5950be824e93ea794e831d59cbde0a19e9c064f4695853ed3f1b8860c4ac443390696f12c4a32bd6b73afce1ae96e33cd1ff24c5e" },
                { "sq", "de0635c3d4fb0c42b03c55e1a4e1c06487d088ab405b793630ff90672d19022533fd23f43335a2e24b7a2be30164da02dc37e75327837c37c236e91bfb74499f" },
                { "sr", "cbf10dde0318b3d47eb716f6f6d6cda8245ba59bdeddab4b080b149b2ebb82ec2231b2745cbf2744b5aa65ad97867bb5bfcbabd3056592e26d630b76acffb7ba" },
                { "sv-SE", "bdc56aff6baec594b9c5cbddab55e9f934cd9fd49e1d3fb98fdec69777ae6b28ac05f7135d08b725a75740b1395c6e3e30e5e31a87a551bb0bc4b48febac8d05" },
                { "szl", "3f38f7ff31a787ee19fd383711bca4eab0058855813c4df11eb0f7c3935b22e75a34ad1c8fe39b3a39c5327d9aaa278e60fa590a2139801ab934b7377028c847" },
                { "ta", "6b225c6ee6e5f9ce70d67ef51b4b56715aedba4758e315f0b136080ef99016b0ded0fd5128746375df26b5f9a944b965040556673104f270560c81df9b8902ca" },
                { "te", "c3fc39be11bb602f58e7b256bd5f7f83df680d881e0dbfbb232db4b4c49c1019525f96fefdf2b4e8a2d1842ed1b0aba4518a250ec6bba402c01d8ed4d3bb7eb1" },
                { "tg", "7383f007fd3abe61cee65f861500c21b75bb49b0fc7878cc3ba7d89e9e7ecd57b5cde93ef0565904ce1f705d641cd46c1ffe87c31a54888eb7055ac1cc01a719" },
                { "th", "95b44d530e5da2918fe917c6a9a4c202530bbb98f047318497a8e2b79a1cae49e2f583b2aeb4f1ccc47c096d42931fd1b8251d2665b15cc92c34dd8fd3d86f9f" },
                { "tl", "b244dd7f7bca41597124a10b900257cb1f2feb700b787c81e9eca6fe75088cbdfd569310a1ca12b9528b6819ad94bc6cbf00689937f4cbf397a7adf025a9f79a" },
                { "tr", "3348967b0bda617b4b5149006730b90dcc674b331a01c203c5d15d8f492ded153fed638b9d891a840836c732f77b351633a89669084228343c67cd28dd5d5a87" },
                { "trs", "6c54b024df45348055a3fc2c630fec5783476dcd7537330a8661dbd0624ad04cd686f308374c6dd3ee0b38cb9ba333eb864b8be5e63fbaaf1b66eb4e5aa34ad4" },
                { "uk", "f7b9302b9dd4ff6c7300339d78948f6604462dfcc406442473c71c97ff54ea1ffb585f4063ebc9646dd5231bb65dcdf951ab489d102a292356b8c9c3ceba78b3" },
                { "ur", "54771931ba9018cf178ac486baa43375c643ef77c3945c56b184a4f31f66b7ebb80601df22a661321503d48d4cd34cbcbdca1155207e6a1d950305189ffcdc2c" },
                { "uz", "7e705a6d3ff4c071e7b9aa223d5fdf8e6d291a012aa05cadd4fdce29df05524a465e20bed92e44b5737500b36b3c55de80370bd8bedd8bed8bedfedf72e90b30" },
                { "vi", "84cbb994975e88813e8c375f48f321401892f0e976575fa16b3f98433b8d4fab34e23809afd17b87571bb2cd348b742bab95574199b74c10c2fe4b966f3a7504" },
                { "xh", "a29667c411c77a424d1160bcac3bbec56e7fee2da10586ee2ea4e209fc75dc2cd2fe4ecc191eb1717d3e4bd2ef23de7290bab4d0140b0973fe354cb70632714f" },
                { "zh-CN", "227474f9b3c8c764381d38d482a1be5cd1a5a0c2265c8d086a75e202478ba7a94459f6a34da45d42416dd6b6a417d49bb7145fa96568fb2fb145bd73bbb6e3d2" },
                { "zh-TW", "60cf633591a78959e25a7afb73e232b2174cd3ddea23139bc77e979e6297f584d315490b619ccc901a4ce2b5da2e946c2e492a3cb8d129230b72ecdbd01aa09c" }
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
