/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        private const string currentVersion = "132.0b1";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f14d416e60aee5faa2207858b8ed77c18279c9b0adf5472a05247f156b04bac025a0b616d707ca5fe169f017bf877aa6654907f8ce7d7d833ebb54a668b98835" },
                { "af", "24eb85d59fab7754ed9c050f7885ed5263e2929c4a3ac1ccac3b80113c080c3885fd19a5f67a1c0a5abd22d5fe95be76e47fa12b42c839e348bdb2043ec48284" },
                { "an", "98b96f1629b2f16c8610aaf35299425fbc40c63215d6c996b20a88e3586a50456288facaf3f43c8dfe49392dd093ce053823c647ab3c0c9b5b6a3861ba1ac3f3" },
                { "ar", "16280ff08cdb96b3dac7ce21801a40489951c5a7a3d5e9e6c4ccedfae2f623c5901b83e68be6f139616fa59a65bbfcf4ebb0824788232e56ec152cae43f1f8cc" },
                { "ast", "4409d89e81869a86c97558cdcdad95e2b66af4ab389803ef93592d5fa9fbb353cfcd4d5b24d8ad52e283afdee01651325c3bbbca4c0d544684c8126674f6f403" },
                { "az", "8a65327af2392d884c64bcc3edf6229202ce30eedd2f3d54e670dea6325d04c34fdc3d72b96942333a39278a7ff5e0a773e1c423dc12b5ab873c73652be72b94" },
                { "be", "b0de7d227cbcbab8300c1083409aee340840470397ddf206d5d996ec532677340ac23f0704ceab0023c0d6d8c7b0691eed6c58b53378894bcfeb01ccdb52df08" },
                { "bg", "06bfa213c07a89422ac674274bf3fcf79d6fdba2307ece01ae93c3c454e7fab96f62f4b0e4259d25c8c091d87ae464f07a944fbd4d52858520d5c683864c2aa4" },
                { "bn", "6afaee3aa704bc349d0d3a26d66d33caea980297db6d6b88052b1cfe5da71991d38043c8c5d21503f648d163e02b991a90f7e4ed31dab2b0cec9d2b268524f89" },
                { "br", "22236d56ba0b5f770801cefe1e86b03f9a0ac9ec61a0f19fb01f2f410f0b3349501af6c1524edf8d700d5f39043282704be8d0f820dfec70749d4f79dc9d4df3" },
                { "bs", "75d41acb9032359a46a0e51906574375a6e3942e4b18933246c19f0bfec8a12bc72abcbca69381c48f9e7ff35de0e23fa94f6c033de218c15d834531bbe81488" },
                { "ca", "5d2127ad019d305c57dfbef68a8dcc916d326cec40140aa4809450ae916a6479a026a692e8d028971ac18ecb86ded773bd3273e8118387acd98be15810f1c78a" },
                { "cak", "4ae4c568f31f4401135553ccea140335a3b7932aaa8a18c748a3f1f5a1dfdf9fbba7bd1cfeae8a3efa360b95a1d11e48ff90729ff6e7f3077c6a186a99500989" },
                { "cs", "fb85e1582f83701ef7ac96b9e7fbd7a56916f244a4d9b9e0620698137a52ae3318b38644f81a247a7f6c03ee2aa66583b4218fff04c61f61b2edc4e8a1ea7c39" },
                { "cy", "4af495655acd137244eaf88d97c0345bc84f23fad6d32dec263a3d14ad2fa9f7319b2b6fb98c6156cc05fb95433eb83311f3623039da156ba6fd74a4bef1e1d6" },
                { "da", "84b534e9035be62c7a9ea4abce7ffe5225d65e24d7eac3ab61258d0c9f36bab8edb458f64f72b07a48525f8cebc0e784723032f75d4a97ed70816e1bbe2b9a2c" },
                { "de", "6f5bae492ed03045f4696a453c601d0873fa874b8bb886629a692e38f3635ce99ffed856302d0bc9f54e7af9a510532e0f2c1f8cdd46193fdeb8cec475767401" },
                { "dsb", "b3d934f77fdee78d5708247833fc42740219b7145458166c964d467ced0334fe45210fb1b3429ecfa3ef90f3078f1c5bdf0ecd7c3b1f86cab1a4c32ba6bda638" },
                { "el", "38627c9322c580df087089c32688f0523cf4c5dc74caa73ea3985e6d3baec7db1e4596a76ab8d52a547d5a2b0bd8f94c46596ed4caa675eea15a098481f21e2d" },
                { "en-CA", "3a850857c189f9b8ce538a4cfeb7c787c6c1c88216d29af53fa4c46152cf043bc7247ea584a2e3baa33fba3c53c4e466c5d2a6530baad12e3db2e8aef531a9c2" },
                { "en-GB", "2664a09a8d72b9102e34167c7a6ab0da1bcce4ca9c2df78f43aaf6022f9a1ed88df12d097741fe5a2b58cf1f9fcb398a97d84c26e9796ca866a717a231e1e89d" },
                { "en-US", "bd0d19c8560a65bd0ca99774ab4cb83d793e889f4e90b14c0d6fb5e711c5e9639f9d52a64ce59c0b436aee252ed92fbe59b9c8048ebb8d7784e71cd883d45c32" },
                { "eo", "8be9f5c008f959a84c56419c3e76919db5ff464c8ad803a52a0eda270222b6e1345f09733f9db2308a5d68d96b2c6890dbe17bbb16d4192efeabb7f106142b47" },
                { "es-AR", "111955c7c84fca6f9b9863724f827567a7973ffb33b2eeb2522415325b7560a89225b0d4111c8e357437c098b464fbd4ec4760fb698b1019a636d68c2012ae24" },
                { "es-CL", "b956fb880f571aea79dff5b99d360d7a8e06356399b5f794530d2bf358d42d7d2df44b8d85bb74d95f77ae28059aa863a5be40bfbb50d75c68fcfba3294a657f" },
                { "es-ES", "9863239230bc392ad75d682ac31cc1418552b3dd3b8389a11f7e64f1630e1b1d463db2dff6c9f557fb82b279a5bd59ee9b8063043a69561d4f1504666cefefa4" },
                { "es-MX", "d74a2bc12aa305ee9902ffe002964971069862789ad8f7e9d2b96739267d920ce9d9cb6ae5620e1a0217b7d526a4191bcc65c116e4bac018ece13b304ab2420c" },
                { "et", "91647e96a8cd7bc035c6938a94558f1112ebbbdb906e50ba14e632fe965d4e2d36d41d7fddfe731dca965836193d8a5626ff59868ba52d7b4f7049929a8f010c" },
                { "eu", "5a01f291a62d3adb9024260753ebb039330306f09c436db0a7037464fa4ad2d58c8f8d75c1a9f3104e9002b70c85765cbdd100e09d9cb550b7bffaa37797fa19" },
                { "fa", "fce793a8b4464ee4d5f0b74406c150615aa6b1d0e762966e448b8aace5f4ce0c73d43445bad0c672acf8fed9d026223957b37554668466ff925ff8f82b99515f" },
                { "ff", "c30ac51b402b9e2c313eb5b1ac1c8d6c3b821cd107202611ee4f37b03c734cf3e136d295e86a395b60462e3e7de64f1f38b6f4897851d2893432fa9bb58890c3" },
                { "fi", "d62b7821724cc896cfab0135688b36010a6a1eb67fccc9109c1c370e3d0eb99d3acbcfecdf7aba8e417ebb0139ea74276df9cca77ecae785213e90e372d95f09" },
                { "fr", "69646bdf52202a20a3ad66286049a161e2e7aa3a260dfc345587c2fdee9149dc48fd3be48025c6722dc39c1fc472ef0339f3f08446ef54c8f0794d61213c9572" },
                { "fur", "cfa734f9b6f0196cbafcf1a5a9a1ce3af19e5a356e6aa8a7f401d4c73b0ddaad829a262ae728c73cc32e082a37befe92240206dc2348e2b3881e98705ebbbfe2" },
                { "fy-NL", "6253aabb9a7405d1a5a03af0f870d1509591b0b3c1aa1fd759a6257c3a433b416d5a65490fa31e61c05cb4f911847b6e877901a36417b26ca9dc5ceb09365c32" },
                { "ga-IE", "b92c43293b134c5ed290555d5df04fba9d10bd9da32c7771c2e5a1f7065d2c96e555c7bb3ef64ae81c5b19df28325a09ad9e3cce58a3f22fdbeaa222277e15df" },
                { "gd", "ee1423c479811251f1b4989e571bf6acddebbdec6a6f1d598d12e139ddc2cefb38ac597b92383366dddce6790108e50d8306b037212e46fdb5ef6c4e3e900985" },
                { "gl", "c22fe4f218d205cc0184e582da1b787b1a0944de1e385a8251ef9c06f8e5decb2c3c0e0ee26cb07a1d0f2254ebff6096d67241f1713d4031f9e82154282cc83f" },
                { "gn", "8b6b1e0058b712408826fd4522cf40f28260bcd78bdac9bb030d6bb87f6efd38458295d2ac5b64480c1bac031c7e24a490726bc1413c14b1c23b8a5e3b7f7bf6" },
                { "gu-IN", "37e685c788fcba6fd8c44bff95ad84aa5cad05cd109a54da20fe779b676240ca2d2e7a68a591a43d010e541e0e6a7e794857be3b1d6d49de00c0a557f43047a3" },
                { "he", "70cca0fcba94d471a111da6e6a7adc043027d71582a72b61036cb90817b9b4473f98cea768b287cdcbe665cfa909d43a426b19fd3deebd138818499ca22355eb" },
                { "hi-IN", "9734a932a9a2b87b1ba537ae7ef562bb739d266cd02798a6faff35e655b8b9bb62b0386c5996f9185648ae9261c95671795e65ff90ffd4129b653cf8cee782ba" },
                { "hr", "596b3e434693646b7d17731a52fc89573ec894a77b12c55f9aa5e5312ee8c3bf259493ae6f60352c0a32ae3e1c3dd5f75980c2b766f55cdff575d125d889d494" },
                { "hsb", "f40d2a3cb10ffdb5154c462d70e65eec1e882b2ebc7e3c5f7ee35a5c20b036e911d5b87538162ea0d47f8fe14c53f8da7a1d447acd3943ab7a71a2205690ca92" },
                { "hu", "e1d3dfc9e6f5c310c098fed29bdbd52717d936b752ffaa6a02f09760a146a3a73cd069110f42fcec0126009e2654aa899fa3c335efea3ece26cc39463f887787" },
                { "hy-AM", "474d99d98c6ab4ff6dd587f34896d524b421fc3768d9e90700966272cd1283400334499b3bf9fa3f3497f4d6815d7053be55da56961ff8e2142b64eb6b3a518e" },
                { "ia", "ecd1576cd84d5c016dfe8b06e47f4e4497d756c18dbb987c300ddf16f6a48fa95fa168cc0dc9ee4dfa441a1152c4e3d1fa11c0d7b242334754614296f49c58ea" },
                { "id", "fc28bedc9335293111a3b9c7e862b94f066014fb7fb223c9885d849bd5749454369ca1b89f98ba0227686ed02d2c2e8c4bf67d3e04a208f706280699afd5b0d8" },
                { "is", "8b106b67d6a348e867a6688713bb5e08eee13572d65d00e928907a99b54851204d13648652fb6c4c2305be76af602fcaba835708cab91cb7506a7a1a4c1b7a76" },
                { "it", "ef922e6bd65da0f929808a77bf4b443770fc82c71917de7fcfbc1757eb58665730cc368159621475e7a3ec8596dc1f8b9791b9db0266b2f073ae67db3a469054" },
                { "ja", "c4df18183d5f91a10c2be2a2e9fab998c7b79ecce576fc43ddc3d044990e6ec1cea322d87455574abedad282ea40bc84509e0355ec1994984fbeefc6e14e3471" },
                { "ka", "eeee1dc5a026c73e48cee859de949a5e31abf0df12ec5c788e787b506d221ad109f39671042859027c4ff759613db5246fd78f78e41af863e2dbdb4fc1181234" },
                { "kab", "47fa4d226c098e997d63ff76692d0e2a764a95e6b9305e0f84ff2bd3fc9a2ec09a41b67e00fc96c558ffbf2988d017ac74ca3f186ea5cfc7cfbceb17a649c070" },
                { "kk", "772ff812ebd5af72be245e418df3687b7d6054a27858cb793d7e401edd6454dd725e65eebd82e29d5e48e5131315529aad584b1aec647200d735cb474a0c8193" },
                { "km", "697f44cf4ffeeb842697faa6397465aba516f679dfdf9633b13ce5f9689fd20b8665480d400290dfa50f3753bf4ef65aea32dcebb69cbb5ab3d1834cce686318" },
                { "kn", "b0854426fc23f2b03ae96cc8803436b8e191cb4e346f3cb0ca9a3bc2f268f6ee01624c41322d99b9896fd223ae4b7f4c8beee46e8fb4b2f5867474361cf9c4d3" },
                { "ko", "71435bc892a0123d9115aafdb286986a279302069030b8a53ea70ddd83c9d22a30dd4ff460bee40ef9604d1d6e9946c64332c49352e29d39786034e8a141bcef" },
                { "lij", "5d3c9b4b9938070a54650c58f8d074a722c26441119a7476ab0901c87c5fca54e7e3e004a77893cf77a766c0d49ffd3fbb799db14c0ae1d37f25feab0fc92a69" },
                { "lt", "2dfb9eb4952d0f128184963af0e6455e2171e3b1dfe98c85aaedea754b5d078bc5a2d4884d89f41d441e03a2665da197b01dbde0af17f50fe3d9f19114fcba0d" },
                { "lv", "e5bf647e3c6213ad58804b48058afff3fb9f5113becd381c4da1d2c6606ad566b26b81790bf95194fbaebcbcf8172ecf148242cbf222567e721030f8dcdd876e" },
                { "mk", "9703ceb48245b6a57bf82650f9f619067d9b2bfbc7991f70719700012916377af99ed677423a5515e5b72e8b953923dc84273bd4caa54257107df76d47ac2b28" },
                { "mr", "7f4e691c9d13e28df49b203fefac6b6acca101c916822ae2517f77767fa2a5bfa5636e8dc45989977ff48435959a4afbc30139b1ff918796eebb31c963518fc6" },
                { "ms", "5c7b5d0edb387c1d016deb409cb89c05beeb0eb32429ffc24fe45bd610e2cba84933cc76c6c3d7a277e7b3e173d0970234a827c235005d0611d61204c2d66cac" },
                { "my", "f27fd912c1bc9b351f97a4225fb17544ec72832845fda9ce8635cf0bf4347d1fc92ff1be62a6d9058133bcd0ccee1732eebfc67b5f9d0f73ba837807be4b326b" },
                { "nb-NO", "4cc139a97115087635355eaa9cfe56a92a010f0327062d86bbc83adfd2f704553312b92e37f5ca60db16f0d894984c9116dde3e236d6fe2265c5cb67611959f4" },
                { "ne-NP", "413cee7d01582bea05c8aa2f9e99eb14dd666b316fa312e35b56d16ecd96e4af21a1bf11188a5c18046d6c44970ca5e3889841da2b1f2a742e9f6d838ef05860" },
                { "nl", "fdaabb652d9b98fdfbfb13523919be2283d09e3586563d6fbd4fb88c63054115924727b15e9a562a4636ced9cf042e022e2b2859bd8f19538bab9511a01f2f23" },
                { "nn-NO", "4d4e62a30832aba9d714e7bb1baa22693a8c411659ad28b7e9af02ad0fa6a16760eb6127f8e2b40876065d8e4b60f2065d5ac36ecae296923faef74287ba9302" },
                { "oc", "1d52e11190d87a91146f52cd00ef1f7bd09a10f5d4c0380e349d2449835e4b6a2eb51c2d0f63d1af095fd2a92ce77e938cadec922f42e76eae868c5ffec759f6" },
                { "pa-IN", "9b3dbabb4e7c528f2898a069f73785a16dac28747d5627f3453f5b68d1cbaeda63b1f0e45861bbdc084c4dc174d25d6b12dc925d37a628c6748ee778369c52f9" },
                { "pl", "9f629f6de765a94d305af03fd68de7998cc4f5a6e45595554d8bb5c86fa7b3fac9708056b74e985a8a3b34f3a2bba9da61cd55029b4a7b17de054d9d13b462f0" },
                { "pt-BR", "6f38bd94cffd66bbe028b8030091dbe878fb6d50cdeb86c1ac0e7c626e5983264b656e5c42263fd13ff01b61e4e2978194e1829cc6706336cda9a2320b950e22" },
                { "pt-PT", "b1310bd2c26c980e86a5ee74993183399fce19a94f9ae87db3b21e8bdd28dd512a505eb570e31f795b3398a2ff9f16f1d8faae17a31ea0f750fe316dd7224fec" },
                { "rm", "166b97836136c157ba34dba78553ba5a9bbec3e12ed3b97d7254ff54144c56a057ca9e11011f9964a90300bdcffc8386279a5b510a02452b5860a3fdbc2484c8" },
                { "ro", "123156adeb1cba543cc78105958657a95e1bca94b0164bfd450eaf68f4181c96b716d74bb531e30cc311201068f9d697afa8bc0db4502e7ebe9b3f0170d07c38" },
                { "ru", "a3acd96f7fc6b2454c81a3b42dab860826be6e390a54eb7a7974d254975053e6a4e3ad6e93c4881bdd4e7e6dbedfa817e82b3c8c788df90121cc77e494bac605" },
                { "sat", "91d32638733ccd9daa42411f7236672717d78cfc001a5b408235e42f2212099ef88d435ccd1e9bab7c5e73658e50cc20d7543f6a772968e2b47364ae5bc5483c" },
                { "sc", "4099068a1d497bb90b6bed5697f27d58084b2232fbcac3bc09afc32f57f3b25ec4c7cc854ae930ac937d0f52fcca41891dc1dc8f10132e1d43d42bf88cc20237" },
                { "sco", "bb6dfec4ecaa74dc2e0c85f8dca13dbe0f35ccc493afb50bc3309b3b4ce73484fddca131bd7f129166007b11f478022cad9b07cea4c628b6aae92dcdbe5e2191" },
                { "si", "b2aadb726cce3effc81edcda44ecd5a44dd5639a399338a33d66bb3ecc4544470613f030e83d944b5f12e27893548fef3e507c095844a9ede0d68d86284017c3" },
                { "sk", "e0ed841259536f523e6d7eb96327000e46d897464ee2927ddf2ae04de6fb3cd6d516a8235af6911370e784041db2f1dc39c0f4471d6d3041c571c5606dc104dc" },
                { "skr", "0d88d3c761688428d9bb730fd0c6a8586a2c7b42f10c066e31569f0dffcf7cad4cac5e16621c1994f8387b3ae1f8542adc246c638658cc21c0463aa87547edf3" },
                { "sl", "04cdfef9320e450801305ccbba005cdee9612bc0b737b933dc49c787443a7cf664d046f0736fc56dc202c6f2e5da6a36ebf79d48b29eda175f1036fc3b4d887c" },
                { "son", "4df0eda1635990a69a01e26de4c7f338fe36747475ad6a00918e2a116acfa847c65d576158588baddba4db81c448a0ed5e1843fdf6153b06c60dba607f0aeb1c" },
                { "sq", "a6bbaa63daf9bdfd4fe717c4c49dc8a06bb178872f2c82ee6af653da70d3296f27940edd04c260c017c76e328c0944e38b67e54da01eb0f2d342ca9255006f23" },
                { "sr", "47ac903889cbb9591530ef59613981d1928ba93849362cb4bf990bc4534d197cc44dda9d3655e9a4637291b72ac050e8cb68df47a9f2b4c1ee59dfd4acacb5df" },
                { "sv-SE", "731c5488b6b1de190182b00448e43e6be4b8a16be6f0b4ab8890f277f38f39cc1c8da1d923ddcb2bd4fac5626ea071c9d0e8bc1c942b76909be397ba1d6f8bd2" },
                { "szl", "30954f5b6b487f216aa1af273cc8a8d917f2ee5a9b0c61b44887842464ddb26ddb1b05aec46055a8bd1b9d3e57c43011af024fa47def044524aaee02ac1c26d3" },
                { "ta", "372daed6348cfdd0e9512be06e8c81fbdde3918fb782cffa34ff8c06989833fc01465244b7e5bfc819b337e10f0d070b25720a4bd2c3a8f9ebae4cc1cc79dfca" },
                { "te", "84d827bc9a37ebff54254ba6bc84db960f923d4f595611fba96c31f672c35e96748846b9edb128cc4f94d40dae4b7bf9253114ebc176867116bf21d88031168a" },
                { "tg", "c7e52222b5ed4a393b96accb860833ace99d160c6a406e560e62653ab72268c3df6a32dccbae6364f3372f5de90e6ed7cb113ca8848d408b336e99ddefb2cc2c" },
                { "th", "e4a5180ca890831a160a64b65d9c7fc1be0299553be12b2956d97110fad1861d29d5bb83ed9b5fb7e87bac9513bcc677cf4990496c8994a693928292f5a96e2c" },
                { "tl", "98b56a9b2059775a9efa6e4d3d16c0d69b7c898a05cae029340e025e64ff6ce31f70a0ed01b2d5f60692628a084e2f280496551fdd8795f7ef1539e77c8be341" },
                { "tr", "b8b8abced881d9a54c5ffddcb0b5e699a80ad312c9cadbb319e69479d7ac4ea89c4c0749c88f82c0ca8a58e2ff1ea03693168e2af979abb62838ae322a31f46c" },
                { "trs", "bd23cba7c49b6bb1b6a4675f787beecf0e18d48fcab4cddb1fa339aa14a946cb4a79aeacb814d613ba67746accba510e6857a6165c1986e304d9deba27e168b9" },
                { "uk", "e2a7047db6c4d8f128da3e5fceaef10da80f5bb60e5beeee4206cdabccf038bdad00442f71472170ab7e034ffd6f67b9a51e64bd39b88ef6ac6488b6da341420" },
                { "ur", "5fd86d229572479abb6268e1a459796ac5c5738884e86f2bd0cf20dddd17671327afc1c867050101e3ea09c148a56dc3c4e57775b8e563422457cbede71ce5f3" },
                { "uz", "13cd3fb4e6b08b60b800cadeecff9d006c646b35241f87a60f7e5a60baf2980f8207d71d124fe64e03d2f25ab4c86decb0ac94573729f3c9abf77dc65afe31c2" },
                { "vi", "fd0056e755e0940c6669a740f4f26c759fab0ebdad725513f94fe6f1d7b610bd84e9da3985efe09a2219dc79d05da4d405a12b7079b9e5729adc8bc7e012e1e9" },
                { "xh", "05380e3fa8e3494cfc90a6cd13238057c86ea834a540f917b20fdd713b6f89bce560e58e7c7cbf6f4c2d83a486889512bdb12a01e854a73a6c74e4269e5de984" },
                { "zh-CN", "3081e1542dbdfecd9f1553a85ba80a69e30233577460adf937935ea0d118a051ea2db9633a97e0dc37f9c81dba9f1e73c212282217e1183894654481362416e9" },
                { "zh-TW", "f856e552ec6c2bb5a6122b646f6ab4a0ed6b1bac5865e18f22865736a486aecb3440b61b79ea7e3e75b08a2be35fb990948a7250cbaefda7ecfca6f86a0e7d5c" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4a05aaa3d7d9599f99bc2dccaa3f33c3c37b462cae09a86e9d41464f0fd342f77a5eb84981ee8f5748f455b65bb9edb94896fdf7832057f41fd89d4bbd9ebe5d" },
                { "af", "b4053763943f604bc2a3a40231c1c2da314eab0f3cbdab7e114eb7ee99cdc70c3a3295bac4abf2a70687ebfb0382f20b5f6ff4fe1c1a4d371572862c2af8633e" },
                { "an", "d258072e9f8636e79054a94e715b2445a0c8454004085feadd2e508fa0be8cb062a3eac52874e52a6f75a6dd2ee5c0e20ea7b71d24bd91a781125fd230f46dce" },
                { "ar", "04a55aa1ba7a4820ad2a3a90b2a1dc48cf8085925825f614d7dd4af77d50ff53c34f1e5e0c0a5612568f249eb013eec65ffd39f7a491afce7915bc6fce7aacd2" },
                { "ast", "c9bec2f8b1cc3e24277e614f0262b86fbf041127c920f93b6fd1979091da8320965f524486889b76adfb49e38b47d6743a8c9864f9717806581b1d55c3865e67" },
                { "az", "04878e7385f6c02a564b34b1e830ca87a49d78e1d37bc563c9d3ddfe9244d279072e4557bf837f2425b554b0d56359a88dffcd447e05000d55cb31b9c499587a" },
                { "be", "66f383d7847df23c9e9a70b1ff41a3139d9e5eb3273553c0b240f9fe0eb2fc22e82d81a03e82c4f74e28c4ebf5016444f1a9c0a97add08c78c4dbf93a7732a7e" },
                { "bg", "ac851c08e33384eb91bae70d95b70c1be4b5cfbee6ceb34f3ce0658e6280cdbcc24108c89a2fc53dd7388da7293a79ae6528ca14d4aeabbdaa5c942ab4f3d3a1" },
                { "bn", "ed8e65fb9a66e3f9425ecadb66f256a20237a90f2ba19abcf1785589ff04551ddd84fc2c6bc026e35ca0b09bcfb77607ccbe5dba2e48fcd56de11f290feba883" },
                { "br", "3c33f3af108a55f842c62e8680450e6e528f5af5ce4a10290227f0c7658b5e8ac3e772d3bb0f0694b7fe8761ec80876432031834640782abbde70663f58d274c" },
                { "bs", "a9282b47aba825ea2f339c6193a06f3cac9d9ddf61f66f7091ed01f234e1a529814e7cbef0b0433d98cad7f76b8578c3ce963d244e28c2224e256e20f50cba1a" },
                { "ca", "371607fcff8bd8abf8da96c35f2e9a5acdf93b68ad18e61e3aaf286501c24179110441c51b2aba162dbfd42cf87184cc13839773766b68f9711def36ba21d3c5" },
                { "cak", "0c903665c52185b21ea8b7060e9d11c9fb1df982737645bb26ec592127d609485c6559a729ccf168e8952e1b0f1c865048464ff2abb7f65c02954781f013fd6b" },
                { "cs", "1be80c8df4f75a02d2e5db173b0f863ed6bba31a134d408883d98e69bb05db2caaad960590c75a47c19287a5b4029468896b969e2ec35656a8ac156b0cc85a00" },
                { "cy", "76f1bb164db61e92e3cb13e870e640aa3df06f04b555595b7b3986abdda792b7b862ddd771a554b1d2a9413e5667326908aa01d61a037be244978bc5e2130c7b" },
                { "da", "e9283a0ff1be0d0a7de42c483a6f20c55bc0d8a3a277c21740d4b806fbf6e120924f65b2ea6451434fa2b39312a42b3fe2be57316ba00184da3ac3580087fe30" },
                { "de", "bb9d65e9196537792ef8162af63406e6e670a05624f1f7380b09359995c0d3466af8a1f6c93288985f4ec3b6b05cda006579ed9eb66ddbc4fb996e1e7c7abd7a" },
                { "dsb", "94048254d6294bba4b142749303749913a6bfec296792ee68b01bf5f40ac2ac35be0cf6a2b234324ac328cff2ea180a4684e11baee10653a914cfe65ed86f6bc" },
                { "el", "164375a27a0093f466d6e342432362b03210077f8c82af7dfa5a3d6ad2b7057da75f7129ca38f944ca9f321fd866f873f89387fff4aa57038b960e45f8e4836b" },
                { "en-CA", "809b04accc6113033d5d9f8066f285748eebf96c4cd6d7b8730ecfcb152b30805a38edf0754f58307a1429b4e6bcf5164a04493ed54c2663af7cdf717c6f189f" },
                { "en-GB", "225a858d6da516090eff69bb44f4f293c69dcd4129d6e3fd01177b8a64616d14da56766e72fdc4eb1b9b3097f4e70cc0cc5e496f0f58020fde37ea980fc08586" },
                { "en-US", "0a0a9d1da1e4db6ab9e23b7f4ff9d9e7167dc90191ecd013c68d1e182be7b0a8c73ee27cf838772799f0c158a8b64dd5fe8b0035e92398d931c77a63ca9f0901" },
                { "eo", "48f62d9c525bbfbd1ad071a9eabaf3365e9cc28b0a6b280ac8d42325025e9b41396f539e7cc9afbb78f7ed32fd03d568c682760e05a00a2f32c302dcc5dbc868" },
                { "es-AR", "b01548cd150cfe7fbf9f78fb350cbb0608f8569770d5d8f937722713c3bb020607fdd109c5ae363dba095407b1aa4c7b137f7ffd6c582b835de0838f2368860d" },
                { "es-CL", "ac0f826bcfe995c2221921e34bad32f03a7b79f822722850b508befb6b8ab6ee5e4c5f2b473f9b2b79689b6e663ee3b72f05fa4f9ed91a66b7ba3ade797c6689" },
                { "es-ES", "d1f783b34aabdb13521ff65f1927d11727368463fe6cae57658f751392fda15b33b9f2e7d655a8bd18df67262f1ed05bcf34822eb0ef9520d42697329c596673" },
                { "es-MX", "404486cc9022d2dae6cc268aa057c32b418ca076faa575acb292b9766c3ac6391afc661325c9cdd41981478cdabaa78d8b8f9a97d4a9622ddbfbecfaa0956e99" },
                { "et", "2e3098d645b8e155a6b3a3a672fc287089cb580a37f45650ed1cd1ad853197e6c36fbdb05ef994010b5dea5ff070917c2120d518d29126e1fed0349b89a187b3" },
                { "eu", "0e52a94e152ec28cc87aae0ee23416f81d9c5b865afbb3b2ea71eac9f4eb4ac0390248fd48ceb19f4b6f14344eafc2664fc2f72ee0021ce706dc0f79160cf9f8" },
                { "fa", "dd33914e42339e8d90c21ffa29755f08fe5c1991ce003119dedc016577f843d28d9a51f69f40291772892bc4233c1e9f2aa7805cc38c6e3af2807484397e65df" },
                { "ff", "bcb9034ba11300bc9bb6b5db40a77325e98aa2c4639f9817af93b12bfe76d8de22f79c768b7c988858d2a6ba939e483bf339763c62f2f13fec7fa2241cc54940" },
                { "fi", "6f55eed12c34c2bfb4f363099f18eb10634e96d2e13dd958bf63637508fd2fb6612f81437bff210a4802eadc7591212983d0e36667e0e44d8e9beda6150b2d8c" },
                { "fr", "66ad291aa261103e0157612922adfeae41cda6dffe2d8b4bb6b2591aefec3ed8f43675884db5feb48a05bb52a9b74f64a712630eec622e748bf87a576e6b7eca" },
                { "fur", "f164b5f04fadda0e4f61340f5ae8ceae5c40de7f47b122fff094d441f68ddc0e08f3dd1afb68240748c577b99a405981eff49d6e8772e8a69f76887c45367d7b" },
                { "fy-NL", "f34e23c1feba28c8861c33e0ce695fc8aac3f5085dc15dbbd3af1ba9e55ae8bb2a9e7c1054ee777bcd5e1a4cf2a6a3942d3d2feb2be5a2b118fab43210f65137" },
                { "ga-IE", "d769553aea475ab991e6f4acf71039b8f7b61467b05df94fc264ca7a4376aed8c0487796d5b5bda91023ab23c94d52f26fc7a711d95c7114b34b7c5ce662df08" },
                { "gd", "334b0caf6889577388422b6592fd3620c68a59f40ab2ddfb73e9480e27a5b008c3f7eed0aa79546174fd400ea35624e29d0a127a2b9b64b399d8f7deee0beb00" },
                { "gl", "747a379f1805f57e7fcf7025188237d9a1211b64e6d3488b1380f597eec8321068dc838939f04721c47d75476381184119f522cdabf418c68b64395fa892f9ce" },
                { "gn", "23c05829e734c614f2ef38d9b2b83a7a68d4a6b5a4b97049df46467fdf05385481db5880fb7574b1cc8bc1617beb1a212b6ef4f7e4d1f6f1499fd3f64488fecd" },
                { "gu-IN", "ffd3c6ca807f235e0bc0930cdae3692ae0da638777c3ba313ab8900195cde6fe6fea4af75c7f1ba9db519ba3adff4700900975ec0021dd34e68de7c3249bcec4" },
                { "he", "f059063faa6e4c25f22b4d963dd3a24bce6dd8b571adc610492f42b47472bc8c59546b588a6f7bf68fc7940a50c7ad84bef472343a5cdec1892559926e9acdc8" },
                { "hi-IN", "68f794d078f7e361e1afc75ae5c0960df675d942b320439029d0a884b54dd548a44b42f154db17ce2e6030b4e014a78bd195db4d4269ef3971a55b14149d2cd5" },
                { "hr", "a47f9374af26ab4fa061c2045f2bc84b6eb3df58b9ae988686ce44a152230282f8d7e65a1d04ba8717536b0b01832e590fbc530af3cd2370b9b25ecd50d22c46" },
                { "hsb", "54b43d04663c6d71bc650e0bc4e58daf413c470900a5116aa008d7941236d3089c11374a7029f55f87fd6b53649adeed7e84dd4109336d362bf94f0770422d80" },
                { "hu", "098780d0be57e43f92e1997a8a456ef51556e46fab3bf28bed82aaecdac73a47e1994365d9e548556b438640d13b32860952003df07821c09b43efca25da99e0" },
                { "hy-AM", "0635cb6d1e1c3cc1f01113612d2defd7b4363d77f62c5b5d9b376b3da19b00f477c2668cf3208a991dcadf1d0bf6bf64c746d0a2ac33be1b2b1511299e7e73ad" },
                { "ia", "c3c7fb1a1d21edb1437b427df25cb0d256ff2b7dfabf94494305bf3499c65c1df8a2d4e4941ad75d118c8aeca8efab06e4b645f2c0a83d0654f06387fad46fae" },
                { "id", "fc3629966375aedcc292bc23cf8dcfac68bac9831030b1069593aff232d8c848720df6c5a78ac4092115d0614b9b8fd75affa244c142a817c67c90adc0d36c60" },
                { "is", "e728ef3db8ab0a42fd4eb9989b0ca09d97e5b8f3f2977232371fea07b9c8030e0cb95fef361add22ca73fd5f541d251ea1fb6d1167e3df351718442755c8485c" },
                { "it", "7d8f7d0254843e3575dd60677a8f17eb5104a0cf56fa45671c32817dd39470f58e18c4a1f7895aea7d6600f329af6007b8d998d519a08455252aae8dd54015f2" },
                { "ja", "00ca68465c8b47d3253cf09f49d5fcac9c65bec1f8f1395087b803c9f74c5e2caae017d689c590a795435c257310cdecf01e7fdfc2f5706a018e29b99b45bbde" },
                { "ka", "3135dd0793f8eaf823623b1e82d450852f92caad18032c41dc3ee0fbdb9c0d2413d19394e45fc177c0a1f656534153baa0d7839ebe2550bbb0c1815a31ce1191" },
                { "kab", "1c07d1923feea581fc93004eb10c48ff418391788570ab8038a3b094087ef9818833e2a0b9bf8df964750f7d13497fc97722de6c5501f35a89fa3d81b33543f8" },
                { "kk", "b3e47d56640c3f532c01dcc72e6f702d9cc7d10dfd816dca5dc735961ebdb8b722b7e0d75376d2c626a99be47b95ad0a6f228def4b23d0d0ffddd3d113e22398" },
                { "km", "9ecdc35e381e7bc68be26692ca03dc902e1c4b13e0e3f9538ff06ba22676767add220890b2c5d43c5ef45d13f39576d7ae06b568f6d82c2e79fecc4198aec2c0" },
                { "kn", "d8da8261606dde267e8a0860b5d6b00be5b658faa05196f393d58faa1f82e9d39f95a0f2d66895382703f48e70c60f5395af680083aecdbf77d3587c292fe0ea" },
                { "ko", "766052424cb16964ed249191d5d5239c0cc74c7b8a24c3eb64c40c878223544f27826972b4ac8b6caeb6b93ee5ac25ace828326df530db5009b542abddf2a032" },
                { "lij", "227fec19b63ba262c15ba987106fdc1ad5b716950df53b568c335c6c2544ee64658613421491cc99e5f5a2edeed22ad90e081ace2fd458cb5bfe237cd5d71ff5" },
                { "lt", "c90d94584493dc048d0d910feeb623beb60d8d17aa09710bae6f30826299d2186798d65d8514830fb9e0b89ed9772ed1fd65f159d7944f97c50341ad980acf45" },
                { "lv", "d5d889b129dd024e42ba8ce45b8f8bc3b071845103675ec1a95121035feb5558790a0817a9854340be4fbf2b3d4ccd2da9da9681a9566368982ded47466cf7d6" },
                { "mk", "72e7fdc48ae387c62ded2f4e2ea6ebb9a0ae4af7a2fcd47b247732ed8e816ad2f4c3e1d78841958e1a2824530f37c51b3013293650c96692edf674031ff2ae74" },
                { "mr", "49ff1a4cf813f4c1efc80fbfaedeae49b056156d61a3852e673feed16d9a2fcc8df1e3d92ba94202646b431120c2d2c90a0225bc2125f94dc7513fdfb514956a" },
                { "ms", "4c17d10bb6fa680e3ee60627df711405c90ccf6dc56a87df05560049bebb298f631bfb3b1a87f2e7413b6ccf744234e30fa6cda92310a8a47db1fcbeb6e5cd62" },
                { "my", "c9e3049219fd7d6125cc06440fef4ffe377aa977c70bf796e398d44eae9069d58ec4d21018175fbc28f2e4d19843944bf17e3b567fd82a1ee3703d8d1140ae15" },
                { "nb-NO", "4f8557b8a27296b7d3aa6f5c9620e1b409e49bd9681cf1e8fda492e0a32d7fb238de48a109f6f205eeee57eb71a5336d3e175569775ca4546d0ad2aa7332d116" },
                { "ne-NP", "e7208a1eaeca2c4bc5d2a7a01eb097e1c8a6d7f58f96ffb5be1952fceedb86cfa549a906dd4ad12f8135055fa0ff5913b00b6804f443451b0354a3b3f6d9a418" },
                { "nl", "5a55f2a7a8498cb9dd19f674349efae85839079328199d71523c45467a2e7e5499505853b42ab6e13c2990526520f7ebf1d603765e42b5d59d1c1a7097649cd5" },
                { "nn-NO", "1f17d160f995b4b7a908b7099f1feb7a3c56fe18e48b906ff685aa70427900e763875dec90667980007ae9ef94765b6449f0adc2ce297e03ded01af448a7c89a" },
                { "oc", "fa7cbea4e20d64957af8447347c5b0856b876fc35c0fe92bd9f4600579479554dd48da69dce255820f0d95c8fdd5f434b48b89b0962e9f4f77a0e84242a9a7c0" },
                { "pa-IN", "4aaf18a89e570232b36cc981905d9a1861f32e2d4b9c69bc237886f0a9849363c0a7858670b0c30b2813d02259692824e235c961e881bba3f19a1444b26fbdb4" },
                { "pl", "3ca3b14d9275c14c4cbe7d72a2cd964865ea2636bd01ae58ccc391612c50316a9e4742188e5882f95d9ebfcd1075ba1dfdc4235608eeef0b65a28482f8a4ceac" },
                { "pt-BR", "d50aaca54a29c4b92fc69128d0ff3ffb30b4a00dc8b7de590e62ab32abeb6ab38cbcc7f774932f8d961fb2802d82d92113178b9e11fb1d05dab65683ec21c2e0" },
                { "pt-PT", "c7a9d4252c78255f0f4867049a93c628d57d9538f9d5cd7480e1240eb7be3d966fa1679e6691708f30e6a646dd6ccfa3aeac229d6e8f3b81bf28c67f92bc3fc6" },
                { "rm", "bb34d28af8c0bb0bcd2b133d2aee0478d9e31d22f0647b75ac87efe0decd0f0f65ae66585ede9bc83a37ff3a1c2a04bba9b28bf78b84ad69599552d51aa0b8ef" },
                { "ro", "2706497dcfc9905b1dc7577f918b297d3083b80b98d47eeabc1d84eebbb7435f2ee6bf738b0582b85e86b1fab21e046c49a1dc452a8e78c3db5d2ed34160aea6" },
                { "ru", "4b2b0a376c0c78d1fad1db13c0c8f728bd7f23b0336c23086e3314c87b9d8f0a92952aab219bf58d489d57494bdc10f3faa0e01386674140ecc58df3cca64906" },
                { "sat", "eb61fd8f66e0ed3057e6d2506f7de55dc104b89b3ba2468091e24f52ec88c5d8f73ce04fb6eafae1856c896a593f5884616496cf1bde9305b149ad90ba0060dc" },
                { "sc", "69b25e249265c373d7b463c9c919a3417e80c024c9cbb74576a7a55972caa3fd181ef9f51bc0e99c4a6919bfe4ceab73e7bfdccacceec382921fbbc1e7493727" },
                { "sco", "15f0c70990c43b5b831a77685efedd23faf5380d575548f47517b016698c2dfcf6e72d6b32272215512dfba1bc57263d243b09b4dc5524d6025f70da63d33cd5" },
                { "si", "48f20951e0fd98015929ad7a8a7418acea0878090831f77bc2b9b488591eaf5a80fc29d8371195667f47a05b166a17cefafa0ab05fda8c8be0eed4e96ec9dab5" },
                { "sk", "7c029a1640cdbf7eec2c0c65f3d724a14215decce087933a82cec5335dbea08a6a45777f29e402b19deec95700481c18a496100f0209fba0fe75c24d272ccb7f" },
                { "skr", "cb9bdaf5bdfb1eff87bbf71c2a0d04997b86f4c8c97a4ce9efe227cf9faf1f210fb78cf4c97cf586d8e22e2c57480af89b83c28cfddb141790d2d888d59af271" },
                { "sl", "748e114289888ae6754aa5e47860ae5df8c2c56ce7eadac92b383cf9c7365414093c7abd7ed3ee77da2b16d4461852d3706b1c1bab60e59cdaff48fe586d74be" },
                { "son", "c2793ec974c9f8b76779cab6da690cf9fb587c321b6beebd4c1c60a7f0af7958eecff15f223ac37fd0c2dacfd41da38368f2e6ac3a10139376a939a58331eee7" },
                { "sq", "23c61cd30266706b305f1b0452664b8d85330ffeb34bcce5f4e3b9d8f152959e190fbd2ac7eca4df6b989840e51dded45941b8ec6ab93297d0e79b49f1679093" },
                { "sr", "5e156a702cc4e1c27f7a3f8c633236b81353122f1f6689432636f8af33af3b8e63703191f8cc289e89685bc8e4d135d9f1be8355f0b07b20d2956404ebc7b3c6" },
                { "sv-SE", "341790d9468c30788b3ad13720461e885600d322717ff812858386ee2b0e34bf58c7ba843820818d9857a16d14914c9e1defdcff0e58f0b301ca51729861dbb3" },
                { "szl", "a48fadcaa9606c153c43368bc4538ea5bfdaad07fa7c210445b194cf0c2222edb5819daafd961321e79188c129cfdc5d9e2ff139b87c1a73bc1be0f8fd869f6f" },
                { "ta", "b6ad7fd323312b781b8006b1c8475192be84e181f878418aa091fb97db90e06c7b8f3b186160b205342e9ba9b77aafcb6d4877bc6b959e86218d62688ca636b7" },
                { "te", "d0e601ac7b8411ae3c150ab4a688f664be6844d0d9236fa02a711cd8c86d2750a68dfa4a3798b6e79b7f5adbc369001d7d76ea4268c58e111507f05b00a1b94c" },
                { "tg", "bd75ea7abd2e09c9d96f9641ca7020b7d857a959426de2834666ed49b3b108068d697fa416b7c1b8afa7544876d8e66e9fe289add600a020da8b3b93c1f1d823" },
                { "th", "fce2e2fa223b2497d84c7ed806e1edb783675aa5b902e9e0a6b64ee71a247413c7e96aed43eb894b81e8fe3285883ab6e732307720fce4d189aa60b213dbc1ee" },
                { "tl", "76a210e21deca2565f4d5d3b81a69a397ec4715aeddbeda3fbca1ce08d3007aadd9fc4d85fd41a88b13800c250ee5d3a5c8a53fb6f952dc984de537cb80b7434" },
                { "tr", "744a03c76c740254a255018044700c10a25203c563617d81abffc0c42a8180d9dd9d6454bf5422754be09606299ec890d07a9e4d132528e6ac18db671d34e55d" },
                { "trs", "e746211b004926ea6f35cc7a2cfe2d994be3239b9d011379523d2ab8fdeb3e8269369501414458a99ec734a24a344ebecd4676d3f332c8b1fef1de9731b91ebd" },
                { "uk", "06c7690b966615a1cce3b4dd22f4c01829a8cb0d9fa3d15daa5c5d322480a8e37ca59265621c8f1d50b3ee6c9241785b912b3a73d87b78aa8467057e6ae2f7a7" },
                { "ur", "91738226430fd2aeadd05ce654e66f30707b2091752314e7d47945937dd1e8798bf8a53b8cf0f51dd8906f211dc41d49cbfad88edf7409d9030f182dfd31b25b" },
                { "uz", "e9c25983a4a47e97deec32e8b55a5bbba598abd99378e4d3c4eaf3919d8631f083abe78550ab8a05f8547fcbab94aaedc09adf91daa79fd2d8ebc1eb0f714c3c" },
                { "vi", "fa72e666a13c791d59e639528d198e1a0f3a4528495b43a4f3a35b4230357a97f020b950d38cc197347597feb3f3092143c5429d552c279bfba9028e20a589b2" },
                { "xh", "45a0b5a7d1abb1ff64d3cf159a796cc5526caa8e00cbb14cf5879f609eca50738b0a83db4914ff30f82dead1d005029ecefa2884ebb807a63d14c402b79a71cc" },
                { "zh-CN", "dbc0bd141c5e5efdc887c2131f2d2e240f9d6eccf74aa68c08575d5959b48b93fd9f5dcdfe72edddbf354060c93a972cad11645e865a754f2336f05ef0fe9e45" },
                { "zh-TW", "cc6297a6c392cb802313a788a551b47d090474777e37aedecadb46bafed31bbee55efcbeaa47fc92b907cc6136c5277efdeb8928c9f4bcd24ba8c3bdc8a39610" }
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    cs32 = new SortedDictionary<string, string>();
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
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
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
