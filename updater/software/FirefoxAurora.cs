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
        private const string currentVersion = "130.0b6";

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
            // https://ftp.mozilla.org/pub/devedition/releases/130.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "447c541913d0cc7cc0413928641e4af3a7cde8c1f32bf8451a877ccdfe937d7341c0a659b6fe25b96f2a1475d238b73318b8892982acbff6bc4095a7464ea0e5" },
                { "af", "0285065a5bdd11c3fd7c78df0d64b8bb3a83a6a7179edf007319404fb90a85f4a344634de0a0341a68a4124b6c1076af24d17712c8fded503621fe6282f4fd17" },
                { "an", "c3f1a50b5142955e55296a9fdb84c6c060bd3dc987bb0669eb36665399ab9f036e7accc62152f9260abc9fdec22dcb49ee72321ffa45ac4330eebdfd1e6881db" },
                { "ar", "8e09c1028de16713809d6ce200e98d6fea7da35d5df06b496ca0a544ad62741efa44f5ae02aeb218e7cd3723437a0f45c6342e15a98dee63754343d520d53740" },
                { "ast", "8e479d6ec7bafb8e0e1b169c078f0d8edc5e659bf7265eae52ba501d364820bbfb68c1aeafb10c1734c4560d91d508bf78b7ee8be9f3bcc1a15fa54f26d68ae7" },
                { "az", "29dad3db65f60d0ed6809245d7859cff43c2fcb4dbd2155d7094c9a6a8c70b37269838dc0a6b1a64f266d7688663965bc931115e7a7e02b0fec664af17477b11" },
                { "be", "827cf3377b2fe13e454fcb6dc10d19e20cc633cc25166c0aaaa7cbcdb5ebf9a1fd5aaa91b48b36206f19171a07b5608548933d5b5ff7df6b3cb153f6d204b85b" },
                { "bg", "a7157880b5f03159b5b559a07f74b066c542bb0dd3ccb3e081f1558fed527260d9806dc3246e354c45cc4f3de60f87f9a5ab0637e853a3902fbe212b89725959" },
                { "bn", "a649ec2b20b2cea7cb5e081dd98d162fd18a2c1163df43174b0e84abf38a71784e9d278b181c201000a05edc4fed515b38faf133ea972204de3798d4960301d8" },
                { "br", "28bfddae78881c4106d5bc92d4b91100ef168afb6e4981bb89417170e131a858f38b28be5c1e18522b350dfa63bb6f6e851483de70159320d0873753dbe2dbb7" },
                { "bs", "acca85dd6bb848f114741230f3f11ee08b8015729716f4b46d381bd139a0cb7456526d3d36ab6227668738603911bf237dd9f7f1d3378f72f5f373ed32b081f3" },
                { "ca", "63ccbea9e13c5d87d61d0beae960124169253abe84a512ae8692bc5ca105d83edf6e0fd74eb7a80167a70d6e82609cf9381d0d613d32da5abeb8b31538670132" },
                { "cak", "03d559499b17553c4dc3ee67a10f2695ab7630c4182043f4c4b5c340ff424efb035734b94dc4dae7aa3ff7082f27fd2baec5ec7148d65ace99cae9d4a1026d38" },
                { "cs", "84854be3872fbc8686a857711afde1bc8e9285ca7fcaba987c0a11281b2543070f02314fda640f5869dbfb57e857fa0c5b9d57644998a9f416613e0841ba6c48" },
                { "cy", "95f1bda3c090884079b72575e06f428d33cd63b516e6f3b1d4bf099e8940807c9c1b8fd046039fc030160509b9b93bebe52a5bbc7a706f8182fbe6af85a71fd8" },
                { "da", "e3153c58a4408380fd2ae9dae73c520d72343f05dd11f4a9291169675d4c46f0779e2ac023f19e97fb488c401f88141315f53e6c407da3d5fea29883b16bb2a2" },
                { "de", "c17200804e624761dcfb114945fe8155495b5b1b70dfc0dcaeb6327995b33c35be220729bf84a3a1c6a16dc19e8ae51b1c9092d17d8ed2414b7f567092be4831" },
                { "dsb", "8fad4873f287b299da9ac1e79988d4873422c2b43641130e98ecb579f3938fb8f39b1f942ca73ea90492b5ce5feadb235cefa1deced47eae7fe3d6ee7562521a" },
                { "el", "0751957b59e3da8e7bbd5e32c3f0f6d784bf7dfc9ba191f15511e7bbe692a6dba1ca82a0aaa142be1d0320b366ebbec342e7277388c70a2efb8dd59ec8c71304" },
                { "en-CA", "146b3fc4906167ee76ec8d97417fbc5286e3f592f083bf6f3a99f5809cc5c5afaa8380007573bdb8bc912e9d8d9fc71388a9e40a7585db63386ec15e542539e1" },
                { "en-GB", "a826637d5e88200249cc0ec8a552a6893524ec5fa330a47a76527a80a56e558fb3ad15bf00b3e8a19100735762d0c66eb2ff39fe4300e5922e9bae8d880665cd" },
                { "en-US", "06ed34c7c5ab4c10daf2057f4776bb6295f79c8056a8d2e4fb7abbd41c3027cbb0243b93f698863309723909fd0138bd4b1ddb9336ece1b7030b62eb8afa6a85" },
                { "eo", "ac8be8085e4d98cfde3feb31ae808ff757b54b494e81234089ce393ce8ab6ef76807e39692de0a206983ab8b67515110570fb93def0e67e89061346884df1d12" },
                { "es-AR", "709940728163d2b153e1b205d889fb6fe2cd9667451a773fe20db1b9f34bb6b13cb5a5a4ecb474b0746b8c50da7fb5d7c854cb14c8fee6e2f0122ea13da4d29b" },
                { "es-CL", "4b61ed885c1554b1abe145ad2fda0d0d9bd88ab48a881eefb9d086177a6c0495147cc2cf681742fb1bdc0e23244485d139f5568c8ec5a9536e41a5936fd4be79" },
                { "es-ES", "892de6df37775256362aea4587ac7cd5862184f7b6a281a06dacfbd0e69d95b5ee87708aeafb664250f1e4fd5fe494a936c8c436dc1fb831162b472d1163b297" },
                { "es-MX", "dc7b8f0d3f563c3cbae0bbad878338945ffdeda3f0b5fc6a4cbcde07b67bd8ba04af81540e4e351a34de47d6b9950e9176adc8f0ffa5e12cf751c8e1ede5245d" },
                { "et", "eef56b37e92c89a316432f7c34cca090ca12e616a5aa601d2ccd2b8d18d385c3e1944d3a3043526cfd320b4522bde73d5afb6b845d6cadb4337c41470194adcf" },
                { "eu", "4689b724e022df82d83b6c59f464905731fec58f54794d1965e6b502f577e1bf5816fb3b437badfb6b0ca7ad572c48c6fada020763878ecc0367360f905a232c" },
                { "fa", "f054e39ed525ab94d64b9a8cb444596e539edfaf0bca7b9afbe6bcc5e91523cebc5f8b52a9917800373b89efc11f2b61fd6253a8aa4eaaf7c74b7c5583a99f10" },
                { "ff", "49156456dec19eb9f3ae989f2cdc90f14f543a121d4d1c606dd1226d1bb411831763db3c85d1de1e622a83885708de272fe70fcdeb5c04116fa9fca6caf6fdd6" },
                { "fi", "2b75629e4e22fe5e49b904ea3acf930e88f8dbc36a1a0d2795010acc417ff25383ed17afef5b450cb85e8d513fe8c533471eead68c3edab78eb595699678be9d" },
                { "fr", "84d229cde0c2d1524351d84c08e6ce15c72f15eb0abdd30a90c575a62ab0289c4a79ccc6c8b36ce38ebaee71a6eaf655ed901e87c93f64cd22c0bf9a01314bbb" },
                { "fur", "44c2f198b248b2e8a544e73e7e147e0aa0dadb28a426fd5340b3c58904133a806456abd2c9f4bf27a23999688cbcbca4478029a06656838ad1c8096278ce24a9" },
                { "fy-NL", "7deb284b9c068ef30ac6a4f98ae55b96b043dbe9de068880a44c5c90519ebd6725cf50aca5c43624f8104ccb620ef40cccccada94484113e0b487f12dc0b1ae7" },
                { "ga-IE", "ab0d5d89fe9c9382c7e60d7295e352b49da18552ead98dd71e7bf2679bf602529f8e6504d988985414493b0162590d4bf78cbd736f774e9ab7f7ad8dabc3eca4" },
                { "gd", "7b96682d6aa2e7256ccb731ec86b0af3b9c1cb57c3befccc243d191a6cc9a708d9de5cf165aaa3b16b610df592e8c464ef87184898f514deed08eec4d1f4f345" },
                { "gl", "6005befe3d7eab56f6fb3dc1149076380aa8c3de880ed3c71de15656b12741d5b37c79012becfc87b1deb2c81fb64128acb25be667b74bd9c2a85a4665a1aca5" },
                { "gn", "4745ac0b70fc465f38b98bb0bb6b6f83a3233405efbcca95ebb2d89f4ee550b5f818e6e865e3d5101929e436363b28c4622566f3dc98516ab53bff73be8d924a" },
                { "gu-IN", "4b253731a475b9fa3f81ea8bd7c19f339a9eb493a0236b87ce183be924dac371d40d4e616fea5fce7fb522ce5039f78629fa77e7cb3bc5ba36301bfc897b5c45" },
                { "he", "c476058226ae230f21d536035404835644a3de767f327aa9c98ff97c03b17c39a4dbd951890bca5320e84f902fa1759329b6bcb8f451ec7cc9fbb00f16edfa7d" },
                { "hi-IN", "217c508d8d6d7e4605a00f503335154801e1b6c0f283fae3ade475954f300f4629eb166efedc04d2d98b636b840a9b6319b300ebc2b4ae1844145d11a6b46fc3" },
                { "hr", "1dfa475bb2c824306970f721bb441e62fd9053407384a04c4c01045db8e54e37be27c7e57607d99c300b19df389b1a68687c536a22c3a1c1e4ad6a34d9c37195" },
                { "hsb", "b47ecc5c32ffa453d44dd70d8f8890b5af4835554e9e34b25bb810c58a7d50e4cc3b7888febfe14687d5d5e51154f314314268539cc32a3c1c2057f241e95e51" },
                { "hu", "305701e8c50fde7ea0df42407ffede4d4e3f944484bd8526ea54c98ab023477959651b98cbb029fce062ad381f165794b17243cf094f012ff63258ffe9c98f5a" },
                { "hy-AM", "dcdc1909f87ba1c1e23f0f630eb5e5d56bb1a48243bb9146a5418e2532537e6ccfc3dd9cde0342d0c38e05ada4a3f11e4e862015308c5be8727542c0cde3b90d" },
                { "ia", "85a0a60d6fbe36c5041d88e1a9f1fcf5d5da2da2446f239486d83c9a6d5109bac21278f9000bc11485906cd033f8d4cff77c3d160eeb9b9708f2c2407b7f6794" },
                { "id", "4a995d0a83b17dff71824993e1aeff8347b96ad48c02c00a1f22d3b2a10243fe67e05951dce7409f46aba538b978a0020c448ac8a882031f7452feef7dd25d1b" },
                { "is", "6347b4652c968e819931ba00c32b72a57ae9fab334ff45b219d597996c1368cce20e04338fac18c06a0f7140e8203be04047b65cae00fdbbe74cb505e4dbcab9" },
                { "it", "84ee230161ca5511aaa0c179d646351d4bd2de2b6215ec1bc37c23c56f798b80b6bffdfe9584de474ef5336b421e87424b4a8faff09be9da669f43bc9f1a7cc3" },
                { "ja", "c5115e897738d19aa96ac912ac8dab227d86c6582b1d2a1cdcd5f42614bb160fe335270d48a5db466775603692c0b1503e37d35a343ca57800f923e84195728e" },
                { "ka", "beb0e2a1a69ae433c0678aa30772494e9b016652b08398ac5d6a39e495ea8ff144e93f178a080024131d564569c1164da907ec1f821ba7575fb9d5937099a44e" },
                { "kab", "b92337462579701679da01581ef58065de035f86b0e161ca4647eb56107e0bf21090a5a5b311565c8c5d2e1a1ce874d88c9c0011b0df815930a55791f30e7a99" },
                { "kk", "029902523f918b4da10319e84cabd52a7df7ef233b9fbaa599a3e463c59a1ba38eb080ac875cd603b93ff6cc6162e6e87f1b669790bcc93c1d83f2eb4bb039cb" },
                { "km", "4e29b34e77f54ad42ff2db89a264eb214d38bb1d32fb9ae296b3d336de8266fa3a673b1c3962041777404d977975fe0eadcd0e2b4906bfde281099f2146675d2" },
                { "kn", "7cf67ba3bb4ac94519eec2eee731a7c3dec008c1482e135f04ffba90a775a18a2032baa8a188e4deb8082e5d062dc1de886442b6d2ffd9f820998779ae9c512f" },
                { "ko", "4c4b5275887d7eb5b022fea73a4152ba1d3fd579bc5f63e8c26fd9ee821f299af9036c7c72cb2afc9ff9ddd11452bfc91faef8cb064ca0549adf31e9399130c7" },
                { "lij", "fda88180b9c7e539dd2d7580b3766957d4b72fe8048d14183f323b0530d6e3d1aefc844c49ea8c9863149f74df03bca3d5a9cc8ddd23fd205f40e9670932b2ee" },
                { "lt", "e057050549cbe93067345f12cb90ffef5d20f0df7b510ef88785bfa144a18e6b591b2ed4bad7dbaf9cde01d577d2d354d3a91037e8b02d1ba114be511baa8578" },
                { "lv", "c8cbf8bacebb0e9fedf50799f5db7aa80047d03c5e8975c31532240f3ae5eecba2ebb48ca8a249f42f9c963a4f6f89ca84ef5985eb408c77cdb18160e48024d9" },
                { "mk", "8531666314e55b1edfbeb4fb7682412d852ad2aeec72e3ed9483134bbfe1e1d5bb4c412ba433a280abb06021d25e1fdfe91d90e569fb296203a09c49616c5d16" },
                { "mr", "8f2372d7ea3c123500e35430bfaedfcbe701080ed85549769f11ea749de1074301d88a111472aaf7245271168a78ea353480c6f8dba8d078c999df9dd07cbd5c" },
                { "ms", "49bd73e141b3e5e3384eb67a3860f178526a6d7333e5beaa0257604e30524c232f748b98bcb60568da9ef9ad259ec553db141ae9c54ad813470eab6fe2363783" },
                { "my", "7fd900f4b0ca3d67571429065071f642609cb399925f18f79cb95d1177fbe9286b292845d1f79f9f37a79234b6460147d9aa9810ddf728c0859cf52a06cde659" },
                { "nb-NO", "83354e53c48177ecc879c17a40498bb2d3c9eca0877189016ee44e333fba8287ed4848fcc0bad41fdc2aaeada9cd1fdab50a4f27e6cc20f333874cc869721996" },
                { "ne-NP", "30cf5866583d67974dab9b03afe7b1862366218e945bba7142dfe3c0d6f44739eb146c1d06f7c407e7d2ec3a73ff185b9f6d52f5f553cdce8ff55ea28a4e2b6a" },
                { "nl", "d2ede9537b6ab81353d3964df4809cbf42ae0788bf20657570abae9d821266d703a91b01d587b0b673c8e5843c4866c6a787c14e3ca6fef95c67a4edc2a0d439" },
                { "nn-NO", "cb0747b5def6a5402970b69746b3350c4d0ad7fc4235892460dd3fede31d7fbe930d67f05463d30d5750d6153fda5d908fb8e76c010410264536b638c5f0722a" },
                { "oc", "9f21d87323141bdef588c5a466b6c83b4b4f40dffd9c898de58cf14621566b1bee312fe03c41ae3bdc3d2f1815c6302033986429e2e6c5767270a3e46f462e09" },
                { "pa-IN", "0dc059e3c6dbaf736c57d408a990e537e1d3897e7413e0532aaef3f632599916b29f474b19f836031ac3f3e5e8a6d47796d5ddd7d66a78f0ae7f9fac3e2cfc15" },
                { "pl", "c1233d75d475806234f31b21f3b6bbc88f9d85a67dd1a29e162762a952c6c29e27bfbbcce7e5a48425be1d13cb505265e514cc6a624dc938602ea003bfcc3d27" },
                { "pt-BR", "5ed46a5d8d8b670a681ded3c70b32987dd272b952e21aefde2a22259e46282aa699a8b2aee41da26a63ac7d391807ed98c63fcd15bf51134256cf1cd95fdce45" },
                { "pt-PT", "f24515d0caf0f42ccbdb8c94593c756366dfbdd5dde9a45d520c281c169805855416c87864909c2598917d1759dfb247c62f590db4ba2daad252ed74e320fc8a" },
                { "rm", "3c09a27ef31c1672bc649a3c0b92311bf59c007ca3be9d3413dbfc3899b331947638f72dd5c9edc9bcff75d4bfa15e9c9d6b3023ee4dc9411676e1270baa5a45" },
                { "ro", "fb46de83148e9256aef23cdd29a0817fe708ef82e693c2945d7209169630d586605f051c063e49d1cc853cbb57afb15d043f532339901e6c956257f367962970" },
                { "ru", "7ed75e71290a2331892b37e538bab6836bec0b3dffc7f5d1cff9122e98a3297f3ae1a428889489807691d70de85f708a3e5dc8e2f07ea6c07dc6c08be11a8c9b" },
                { "sat", "03231a8766961ebb97cebb9d42a969179c9a4eb3274ca95856d29861a6cffa915c59ba48f8d7866c5c1897934f31d8bfcd57d87e272e737487797238957c7ea0" },
                { "sc", "cee8493d7b7e665874572ca6c652dd73eade64eaa5b4f7a1c8181a23e4aa750556739d88241a241b8e56ec1fbea2c904a000f582f3345086d18ba4aebc999cbc" },
                { "sco", "170a349c719a43e08de3a4af8d674ef32d6abe169afe53967e1c9e215106373436997cde7c0c6e0beacbbdd193c4fd90dc0b3c38db39ac53d171ebcb3c97a8b3" },
                { "si", "57e7b3cc6ee0e152ce99157a2715d3ab5e49c652f8e7ea5e17e8229c44f94e279747c853e20d0f7706e81e1803d1309dde95050ae17fd370a00938dea34b0add" },
                { "sk", "592aa43a3b9df51c79e7a1d88caa7b5146f98265631a2ae33f08eb5e1983eabd15d88057a544fca8603da793c6c9405b762479436f96606a427e8b90f0da3a0e" },
                { "skr", "5bdfa2e43afe15168a13d5e73a21be8fbeff0c200a5945cced8b9b233a0b51b3b85e91979f112ce0503967518335342128e263008d80391dc614e9152fe40fa9" },
                { "sl", "e0d16be1cb13baa5e6f14953cbe6d023fc2bcfa46efff0e17d2faa0984b2aa21cca793c0afbb847f4982201c4c60d150ee3ec888e6d6774fd587c04ed2de18e7" },
                { "son", "cfb7aeac613cbdaaea657536ff313c54517b7c49cffdc61b2920d540a41381c2703541daeb2a1bcd3abda8ae60fc457c52a56284e0e2e13b9935dfb825d4791b" },
                { "sq", "18c46f0a1aff2bd01b439e2b9cab86b33d676bf40d6d7e6e67e207ab43ac3b8b93eba1d4cbcc4fe7b89b85e359c296812748da8d8421346c3017a82a285fa3ba" },
                { "sr", "c7609836bd122a93c3f8f4fed1b90b4c95d97883ab8ce32be2efbd064dc7fe7e87acd2c67c59639f56976ba22be8b6ccdc6b9335abd3e6c5757668be39b73e27" },
                { "sv-SE", "e62be2f1244354275d6166567e1743b6ee97c24e1a00492c575bde3cac9f70aec05641bc6ec2c92593ff53bc2622b207d1143807121bafdc6b844301a6a78671" },
                { "szl", "b30f18b7febefecd7869abac9461e3670459e286d4b9582e31a32f46d049a36f9797937bd6bcf837df93e8c0e38f3bf4abbfa904857b2b47013140e34e43d404" },
                { "ta", "95ed31d2ecd18a6ff585c8598b670686187ed8b4a8efa9ff99b2b2dd65345b9a2780e3b45a280c3fa1ae268a58b91c733766d1fad6052db2d8006499620ebd62" },
                { "te", "0dfb2aba2cc373c22a1f6c371b6bcae9cf7d4bc18a50fc68ddfb026a67425e029f4ebaa79fc78f2cc3a3e6274d282f39fa301086eee1c2f5b63ff90ff81b76ce" },
                { "tg", "b46e6708f54b4d0598d79b2b5efbc95d8d697880648016581b0f244b151536b1241820eced6cfbee503cb1d37fde43f676dff37ab158b226f7948f6aa14657a4" },
                { "th", "81900d7ce9581bb42f3e64c80fcb5b9c40617df87b3a85fd494e3643a79825d1ad2186b371397a0f065d676a0a8d788b5f346cd83838bae3ed65c5ac4097a7cc" },
                { "tl", "5282e723908a6b4764d8cdce0616f8675cbedaebfaaf08a793aa22f66aaf25a96e7436ee93c8d759060efbbf1a5193f707645bba94c2190e599854cf5a523fab" },
                { "tr", "33fb8de517b4b6d416f39e200e7134c8b92a7d401de1f9f3168c6c65dd877080771ed41fece1d64283a65e03473d3f02e7ea14c04e626c0851a4d8a14588af3b" },
                { "trs", "b56209b966c9a4534a4357bb64714fbedf4108b4650e337dbc03826a256d1eb6aaac39b065f33e24d6653ffc64087c296442e0e33ec013a9f7572124945e7a17" },
                { "uk", "f029c2b07e018b5ef6823fbf51c09a39cf58269c82aebed5835c429022b7b37c382cbbc62fbd213738b4308421a0d86b9456d6b537800f2f3af15d00d7ba072f" },
                { "ur", "08630c4fafe875828fb6a9f9627ce1800fd21aca4192ff4f748f51a8bbc87e3d8554ece8f3d45d53b8e8a2a9c5f2bf581266fe70d21198210697995630e612ed" },
                { "uz", "5f4a238c566667edda0599449b11bd546e5b4cc698a27260391c069cff061275804d86a3cac301439d0eeea30154f392beae0c71b7064ac427cbb809a711d471" },
                { "vi", "8ccd2228a5cffe671ec293bc950e43f8f26aeef39372e2684301e9947b49cd4776628f4a151e4edadd2a291c0f3a88ab597d0c87ed93b479cd6d234690e5667b" },
                { "xh", "22fa83d727093176ec947724478ff9b14258f8e655638991cf54e3f643639ea8126b0fde6e9f1b39f884be9b698c6e94f70158a59c41a2bf95ba515fee2cd281" },
                { "zh-CN", "47efb080897c3b1ede6fc5018cddaedc8a8fde6e219435c76fedcbcd036130fa1ff9b819d2c9c10c08cda2cf1e5b95a3e7f99b141acb605f557da6300a872e24" },
                { "zh-TW", "d769936650a51230fbab16cfb97ca32c970f5b90ac22f56ec7f25c9d378efb42362e4a72fbb96a965247c43a47acb04eece2de87ad2989fca9f7274c2b514a08" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/130.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7c6efa6db25d5d61a6e965e55cd582764a020407ef344c03d3ac2dd25803c5251958f351da13d7c85f45e9f10c447b7d02b38064a1512ae808f1f042aee8057c" },
                { "af", "9c2bf0a12a651641b9f3cf8163e8c57708b25e3046be95d8fa7c978eecaad04942357a2a418896e46307c230b79e84c9dd403819f51c31322a8d021781646022" },
                { "an", "88d5273c045ea5e11dfa2c52cb8cf769bd5f4e1dabfcd90e5f6c8eb45cf62b7383f4a98a2e92f7e3546634ccb937cdb54f76f2a4dbebd21b7ad903ed6e923880" },
                { "ar", "3ee781c290e12b50001a8ebd50335638b8f199ef15f578ec7ec7567b9bb46ac08da395d7e24f5dcd66fce68b8ae3446cad574030bc3c9020cf5f5878354eeea5" },
                { "ast", "9ef16553873af697e21028eeb9d57b0402e74cd44f02951b1daa580fcfe74e2e72df54d81cb662cfebe800ffb4c695e1986fae3c7a90b8bc701b41596a858b5b" },
                { "az", "057bf56f443030821debbac49f90f017219712463918dda3519a24e3d3d07f1d3fd94cda970a1fbc821378f3ee7da75c04e8fc99b03c393b290746b8bdbe3a67" },
                { "be", "48aed2fa84b739d1cac437008f20fcfc28b59b216bfda53af383cbbe3d5117b1dede1789f427c6b7a0455372a412b3b6f0e49d64fcaa65b09911aef1fa4a4000" },
                { "bg", "b6975f047f72fe026fad2dc379151241e4d8948abdffbc65248cc29ffd03c6835a8c8e1f561f63c01a54d3da06f95edbfd4dd872c7a6a13a23455842685099f9" },
                { "bn", "7f00a0c015b44363dd89f91c819d88995365039c2e08d9a121a196bd35b76bc93136a075bd44d2155d5f5ebe7a7db5a3457ef389ea239d6deaabbf0fd7f369f2" },
                { "br", "2d79ca6038774b6e0254672bd0b2db6ca12cc23abb87a3d94e1b1fb30fff679b27bd114ac94766d64c199fc556d494b4b86c5e9d823c7edade38180c14c56238" },
                { "bs", "a2009490d9d8f1eeae3e6bfc1b86394f256d2d20aab22de4f8f331f9e648e6fe14cad27062715832789c0d35013cb7aa64f82c3814d15d78c27826a06da94e2f" },
                { "ca", "0c6451e164e8af5d6dc388726e295114005531c4f7a02ac1069d49abbbaaa6dc3241b4239394c6aaa610680137fd2e5bbd16acf78d0968c1a51d7e7490aebe9f" },
                { "cak", "e6e97e06a2a705a8ea6463b2973485cbdb8f2268ebb6f6d7b0ca70eba69c129ca24fce25e77d6f6f34d5b1710cc5e3b7ed8b3cf21d66091ee39952fd857dedde" },
                { "cs", "e76c5c034ede0f0add774dbf577ee2f3700f4b69ed47c213fcc1a6464ba702c4604ac267810161f27d28d9231c4856064829f1a0af7d4a99ec04ea45e929a531" },
                { "cy", "ed1a7f964d4a8ae5e0c4accdaedc393024ec1855db4b1cbc639d1047d9e9d0838e9ff4870a68b9721b733f605b1e7b0ef773e79284d8cf1ba1004697bb8f7e36" },
                { "da", "99d47ce5c0cb5a2474738fb506e20240e137970209952245cc8fa0e1ae2b985f4e407a50d77e7ba937cdb123c683f093a74c24bf9e0ae382e835bd30171340f0" },
                { "de", "a779413012e6d3f8baa86a914c32f4552e850d559e324416aa038b907f330ca549edc918a6c2f8aab30f2529ad9d487a4a5453f8acb24ef2e04592410f1340b9" },
                { "dsb", "92241d8ddf18d00db3d37d1160d1905b63cb591655cd09e7cc7c9463857d3a3ff315fab35903f566f1598ceb2ba1ff28e4cb0faf705dc07e40dd0e925d93dc50" },
                { "el", "b81726cbb96a4659d4ac4380928c01bebeb9bd4efa52354263f5ee18a06d1d6879a715eca2d2c33c7d82fd1fbf8c92c6018e28942235bc379503771e0615faf4" },
                { "en-CA", "58444df5b7660511bd9bd3ce74c7af2e837e61d1b94d24f1aa17ccbfd23c90297bd7e231b6e256dbb0a53753a97d8406a4e9af1d4685c91f4f8b74a2967e70b2" },
                { "en-GB", "d22ae0a5dc7cfe71b1fcf04d61e70f0ea059f79692aad8a67afa42541f99fa9c1751211890cf16169d783ff5a8b37e4157fe11ea451bf95c6e1e3305b38c5900" },
                { "en-US", "f56dcba75a7cefe9f7cb585dd9353daa1c90ee631d9ae91aafddfa16d0b16e8c172dfbd071a67b2de1c56fc9ed7a948f75f30947af84cf24578d9fbc9770544a" },
                { "eo", "256b854bca09c72e5bc31f06c9efeab8f0ba2ebfa18706816cbdf87920830c82ce5bbca69a8fe137753c48af2e5a560d11789ec99d3cae42d8e520e6ad830f12" },
                { "es-AR", "e6e5c63cbbc56612b79e6fb10259bbbb6353c977b574a6212cb008406367c85b6a101cc4d51e5dff54c20d234679f9995d7001c105b2922c40217502e52140f2" },
                { "es-CL", "e091f877ee12bfda1a858efbc5a5ca54615f4bbff750de8cbcb7ee6719e71e0bc2ce51a2f5f9a0eeba6f4a6665da476131ff4df1d7e579b481eb677115f68e3c" },
                { "es-ES", "751ce74e708cb74ab2c01344b00ee871f80157a039bd7abcff0f35cf426d1328d2e53ed1da885101000c81306619d2f5ee1e6855fdd56681b3054f9e1479e069" },
                { "es-MX", "0684ba40c245f1b2cdf2c7867bb118a3efa4094400fad6c2d3e28148284f192db3c9b39f7e044c1f51db7785b51c35d4869a525c80318f0a0ea46d0dea14c4d2" },
                { "et", "5379ef6998f8da66c9e4973cb83368df27cb591b3c4e44f2cd2651736005a126b346d1ecb0766cf453b8d7a136ca4f40356a37893b02c2044e77d08d7cbf0d88" },
                { "eu", "81d844053c44f80aa96bbfefa3f804bad7b2f2b1130463849d1e2f1cfe30545478c230f8aeee62bfdebd8f65c6a820077bf01a7d9a3f2964d7f52cd32cb26ed8" },
                { "fa", "e597b250e9250b90f8fa491a228f4700b73b9af2330a6f1ee5aca03f26940fe4a9ee1c24af680beed203a7adc1870d0ee4ec796f9500ea54e834997f6d8f99a8" },
                { "ff", "2181c43d82558fba1853fdeff927343f8c4d2af868a00b949dc95e59a3a9f55a425528fae8b3a13beb40efae8f99080a4872adebf2f575284a94f8649be23bdb" },
                { "fi", "5514d213f0dda63a978dfc7c443da8d44a71be92d4ceea7faf35f7b409f85d08f4d460c29cc8d5319dc63f8b8bd025573107bc88ad89e497795b10b61baa5ed5" },
                { "fr", "acc25a29e544e982be2027e5910802ca55ce53c2863a8a1041e3ab2af7df5117e0f4d067a21b04f0f1956c5380548e16c819751a69cb422d397bb4f9a38fc161" },
                { "fur", "49e5884f85bb5f94198acc660c3dbe5062d7b15b08de19a09782a469908b93a7c767c22d1fc64912da331bcebde262d15edda84c3d4566a495bf8eb56da72a4e" },
                { "fy-NL", "ad3589d4a833c970a0f6ae474613a2b7330b85dbf6aaf225dbb11ac14d8fdff8c49c78e20e1d4ca336df4be278d0b349a5ff94303913a39564be681d12b9edb2" },
                { "ga-IE", "c1ac22d747191816aaaf2f72ceb6065773007246a9800df38b0fb6936329a9a43c5c58667bc3a4ad080f83cead501d5ee130db80e0d0deda11fc09995cb113f3" },
                { "gd", "fed1b608bacf83dcfedcc7319ae823233bdb6565563543f0b6b17b7a46717fc9c0747bb85d4e61f27b1ad7d3c4ef0b67bcdbbe71480131b01f8c37722621baa3" },
                { "gl", "40142bb000780c849e78534511e88c04dc037dff96b7124a9e141942dc437c1431dfd684099d62270e6296db52fa1a1660e9f7375296bbef65baf002bafa9f6e" },
                { "gn", "d683f78db7bf26149685fe3cb3a2c6b4452064ba72ffd72b2e7259fd9eba6a05593af858c3c2f306fc95fb607cc1563bdd2127951c879e492ee4a145af53757c" },
                { "gu-IN", "d0012ea7850004866693d49f36e2069f1579b1688c60facc3f6115a3ceae14fc195db6ae5f886e2ae02a1e7fbd361492850046210bdb59ccf19eec755d4f4f86" },
                { "he", "b2a14f87c7eeba4fdc5cbc0cd84bbed3d95545f23ea7a3259ea1d36353a86d2c078cc80c57eccff79de341b483a818f826927696cc9fba921de0dfb445d1a39c" },
                { "hi-IN", "dfa09e508555410e20a7efa6906c4fa0725a372563e618ef88ca1dc05a61b0486f317a6c4ebb9d59892e6b9b053627607d69476e9b226321543a7561120f2679" },
                { "hr", "06621b9d1361556f6d70cfacf5b47c1e2d2aa9a4ec03a6c43362f17cdd7ec1a8702220fcd1110d910e5b4b2c25e8b8f9d33702c6001a3d083c03c5e999fd83bd" },
                { "hsb", "861bf3bc1935efd9d22b7bcbd1815aaf613ea6fa74861534f2ea6263d11b0074f937a7b5f76e875d7c6a982249d9aca2f91e4ef44063b5d7d3ecb9a97e72cef9" },
                { "hu", "c5e315869968e39e3bda4b639a9ca38552d95b42deccfc4be387b8ea41bffa370c467baa09ec7613148350021e04fed10b5d4c222a23676593330aa6f8a39cde" },
                { "hy-AM", "ac82672f2ccf5757a0e2e06867e9991173c1737d2c2e5544165fb29260c30935f085be910fa7385985edb4f5c22c6b293aa0f4d2e87f9566f70ebb20d2f120b0" },
                { "ia", "ccca40ed36e03bc757fc2e0f42fffdb8a98e10ff97617ae72848c7a689e2a691d5e1ec37827dd3de7a01d62d2305baad4071afd904ca42460a1f1789c4cc8710" },
                { "id", "e075cdfadaabac046024938374baa1a8a4acacad2741222bbb87470088812517073598cc27780310395dd087cbe28a389c4ad0ad585abb518bdc2933371ba728" },
                { "is", "f83e4fa11e192d7ce91371f8bf3b21b7fd2c609389215fc771b2554abc4b2ac2c7354b598760bb1404e663790b90170db4e221748943d6c0212ddc867b7692f2" },
                { "it", "197f195f4a46152bbe3c0bac57a9fb25cd55f126ec8eefcee38873c4d7e33150054c03518970788f9b66424449e33b37bd414789dd2d0df4cdf5acd66b9dac7b" },
                { "ja", "4d6ea9be189417bd805c38f185240b452587be0fdc53b4c464d5e10e5e23fd2108c77c824aa12c47c9c10303b01c2b8024bd7c2cbd51f657cc4c739ef5e2b68d" },
                { "ka", "965595889425873e4a15d64622eb83123855a74f8bb7b6d91865651fd7568ae699405585cd916341f89aa982306fc0292ea49875dacd593cb8f46fa77ccdef34" },
                { "kab", "5643041a76d16e3104c2f686d12552201e538565da99e7b27d6d3ccd6961b1b5fa710ed4ccbb32fc5940fd1d11c1842d81008553436841d93d6bf2024a928f14" },
                { "kk", "83ff1d20cddb2f0992c208bdaad9817596539be04c2b44e8cb08107747387bb6569a71f49bdd998701bee7e500534f9fa8276fd4919ad8382c396cf808a44fe6" },
                { "km", "0df9e9c31b5e3bd382f078e5f9b527bc8390b7508eec39ed11cc2b22d978cd1cb5da35cab6d7c018598d7725019cefc2e818251c9ab84f8bf4117788a568f078" },
                { "kn", "2b96e2c09f69ec99b2d82bfd95205f8ca1e3edbb22c132ecddadfeac73223ac5e0fbccb536dc7e98bcae8f2bfd505e6552f21f3b5cfa392e95e37c53aef0282d" },
                { "ko", "f9fdadd763b74803316134567c52ee4484010ad02e5336535f8899bc87763a98e1522037ee7665bf0c087453136f738647334683bed88a8df3b19d34ca4987a5" },
                { "lij", "09960abbc8cd6e34c23ede0010b98e6df748b2bf908b3a25a98b4cf0132b33eaf6123e93c4095d67977b9136bce2941085a8b5f1cdf7017b13558e2595261623" },
                { "lt", "46879d8c7e934dec4f7303fc34d042989025866f98ab1f679fc174149360823b23bf37f74d161c3c6fe639dbbb252d2af78fe979945d479da485cc5e060fcd16" },
                { "lv", "a524858e7db121c97ac27b27b6df67f587d93ca6fa85c2b01a65c2ad55e5d9e80fb72a88339e1e0e5120d269588e93b072806eb0c6c8b9a473c71d6adc77ba04" },
                { "mk", "320bf4b6fe9d1706ba25a946dc42e2f56388fafcd2ec4f818b8a75431a1bbf2cd897deef6ef69dae2db2ec072e9e340ee3b02cd2d442968527c027fb16ef0196" },
                { "mr", "4efec7a9628eef6fb524f857943b6a85388d298e4296058acc9eb58fddf7d7dd5846a2476ec69dad2f558de078da44bbed12a205886c7744b10187f608891838" },
                { "ms", "ab2de6565e352e149f84721beb178101d7ac29021ecb0a810fbbd4b8d115543995619bc4885fb187ddad10fec3c877316793b19e68b88671330feffc712d1296" },
                { "my", "4b13749a7cf05d0337c0550670dd812e0c8909060b1cf311b59db35c43af59377c6d555238a54f54cecbc5cc05c5d387d9d4295926cf2f23dbf22d2b26502f17" },
                { "nb-NO", "f69fb2c7062095d2bf85599392d1db6e83c8546f9afb9349210a2fd5cfc6308f2785c6352b6ddedc932acb5d5ceb1df308590166b01ab4a0a31994e985f1199f" },
                { "ne-NP", "b184d84b080d7843696d241c8fa129583b5f8aab74cc06a13471e5902dd744a158086b3bf97b2371e72cabb089c67ccf08f39470c9aca5300e84718733556972" },
                { "nl", "b6bebabde7c1db7cbe8ce172fb8470a183a143392298c4f5f65c6a518ea08946f0bfe8cd1f3ea91f05ec927ead028e288432725366cf443a0abb16cc495b0405" },
                { "nn-NO", "293a71942451dec7ca829daa7082c9410aeef692be3c3ebd4716f9fa3ce7f7dcf1ee32b39d8821903aa21272dda71a76184d8fb5f376172b4952591c326fb108" },
                { "oc", "3fb50fbe2cdc3c074446a1b4f2a6530fb432b2e416653f444951f309f54e716cd92c44b24ebb6948c1073d4266836a504e8d963de1740446abf047248dc7be47" },
                { "pa-IN", "e74ffd6c34d0be56a9c7fa0ee67c8655135cf93b8b099d5d68d9df0f85fb575ba4dfd887105bbff26c5bcfaf8239717ecb338e9ffe15c5e720e76a50b422ae23" },
                { "pl", "48b523d30e636e22491a74467741fb3f67bfae95b0ccd796ef344a9d361e046076cceb1d134adb5f6a0361847b04533e0bcef031969cb73af5f5b8aa07fee8a5" },
                { "pt-BR", "0a554313f7a030d097c7f27319c6ffa2785cea5495a6a1277993e04f0d95388d60b67ce7afdb9f39c761a09d872363b032abda4ca736400d2219fd8b98cd203a" },
                { "pt-PT", "364727f6a0ffaf84d6a1677eb92d9103fc15d7e41d9267224cfa1ab41a0c0bd97429c0480c8b87ac351b291c9f19a11a001a7ffc8dc5e50eb3d58f5d53c0d3a4" },
                { "rm", "b0652047a7fdce5d540f3b6f75dbabf2dacd53a362c9bddb67b03138e6ecd83ffb76e7b913c3ec71ee6fb8c3c0230c49873e42658d2c4c818d9774fe68f6f6e2" },
                { "ro", "e6ea7be2e3be26398f50c82bac3ef6866cc1ed89bf30c2d0d4888480b9a3c8366de8ab0b2feea22cc9878b634c4eeffb883ae4bd855db5b3bdf79c3efe752918" },
                { "ru", "bd3b982cbfc5daf39ebefa8b7ba95f77c193e69a2c7b150a0bdefe7fab3e7ef8c072f5fcc6c6fd9340a687b6bcd8a5619518b919b35b5e5a93516ea068eea60c" },
                { "sat", "5a3f1db12eb07be84024fa66db25c37976c32b2a01677562b880047ed8d95382ad6f820ab73013bd39735cfc232c07c8772029b28fb3519ef368ca4cd86ec705" },
                { "sc", "3e9e2b7b615a125d5112263bda1c141133aa7162dc60aa68b5daf7b3b178f4eed0d1c2617f3f126fde16c4598a2596c348b8b80a7ca0be9138d8a391a6e83644" },
                { "sco", "55876ca0e0967e247bccb76c54a3e663876e3ab16cb631dc6d802558adc7073ff6ebbaf619ee39c14b4f169085011b6552093bd4f5a4e329a5c42aa68b5fbb9f" },
                { "si", "d898ab3a3e7709bdddbe0810f41a30ce32b48c037655cb04bf41ced09b9e298de23b1ee6916572610c6dfdd94877b655db74ce9fed318a20f812c43055339a18" },
                { "sk", "9e0483348eadf825d1d3e5f3f9c906cef2f172e253a4ff8f7013805b39d021a7c7f52eda294b73a1f19c402484e6763e0237502b910e12d60e795b7fd5b24126" },
                { "skr", "0d51684839b2f764915e06312de4c5fb9f9d18b645de790b007fcb30a197885d713027c50df081632a13e4dd292689d703e44fb34a1ea223f65753404947bef4" },
                { "sl", "f18cee6a1c2ca3c0a791a5f3ddb9da19cafa2f0eadcdcedf12222baae251b7db7b26d8f2e7733d24c54a95883561b727c02158aa452170229ff97bbef548b57f" },
                { "son", "21d97e84865731ba9c2e9984d05f8bfdbff4724a4d225db12841b8e420e259c0d4ffe5cf81377355a868c73b267b0db9e2427ffe82f5f673792d73a4698485ca" },
                { "sq", "be1cea86e3fff6edacb5c4dbdf4ac7a79a86f2bc4097e1e659f43cd67e77710b871ae39c79b502f50d9e2624b846985efb208402abb993190cbc5fa47cab6092" },
                { "sr", "b222b6f60fd884e347cb5355c887a56aa941365d1d99036d8f02c8c9e0febeb5d985903d7fb7b55e5a5e39439d235ab8d83825fb6412a6456761420d26c962c2" },
                { "sv-SE", "e0acb9a08cb3b3d88a713abe78da9652c7b365b1f42bfa46345685c141b307b8f8ccd74a9dbb97cb5ae779c3c1007392d92e80b812f8d440d003df5f9fc012d8" },
                { "szl", "4b55a6c71331e637a6295656ae0e031ab1a8af4f7130d9400c854c63273759782bad0bbf9bc9df734b5b621df18000f5dce580f0f8c8083fdb7504530388207c" },
                { "ta", "b3022c29b60bf9c6d2bfdcbfc5ac59f2b259c44b57cb80e3e4a701b00d49f690d8d1ac48e237e895c5806b139222cd358944d7eb1b9b36ddb0b5f5e6efe5bbbe" },
                { "te", "eddbe68e04583db92606b4c0fc365935e48566391cf50124b8a6d86b6e1377c600140982774ab4a721f55aaa365b6ab45db1a0e4e84144eba8ad006e2beadcc3" },
                { "tg", "1c56c4d02a30cd954fc11b8574f60211fd1dfa5e801bbda6f41712a9bd5672ed682227cdfd580bc45a8a6cf9329ee8e47829b3b51f2da0077275fc95b26f1b68" },
                { "th", "8e1457ed8c94cee65726095c55197795946df88d59ca1c3fa7b7efbbf5d776c45636ce2115e65cf02ad59e774728aa5a2e0a4bbc4ddfe5510a9ff249dfaeadb9" },
                { "tl", "d6e316104cd27ede44d969060e7ddc5077bd672b4d617a4207555cf5bf624acabf9ad217d4a634112c9d07a4a7d4cfea8be276b69e46f725c15aacc79f9aa426" },
                { "tr", "1218dbb990f4d8952f843ab7717864b4725903917747ed8177d7fa3589fa02e9225853567e3c99057067776a6fb8734f764e99d21e85e473c642594642501067" },
                { "trs", "8b4a89aceb9176f8b125975a515543ce6084b260d390a946c25a8e8aaec6653862fcbb907ed80566c99d80dd9dc35550262ed3d1088575cb5c78734338e85879" },
                { "uk", "5b3e88c5e618a10c83c69333e356ddadac0d7dbac60b1fa12800d63ed7088a7aab3fd0febb7ff8423c2f3841f8a3fc1cc37677ed0572d49b0b7652a9a6561385" },
                { "ur", "058215846513bc12bc2c4a9764bef75ff4fc0cbbea32a64c9857861098ee12cb7e22a8eeaa997389cc1473d7b50a17d2532377c5ff340eb5553fa514c56d621f" },
                { "uz", "c29110204c6ed58d6def374891816edaddb63308fdbb0f9ecccba5786e29056d1d351370ae89eafd20e5d75fb8d577f18ef025dc0744d1fe95206015183bce68" },
                { "vi", "674fdfe3ce25c3c41ab6fc698ae7f45a036f80241668138ff2a8669a0d05040ea4a3fc3dec54fcebf0165c713d98d66306e8ec41abd783d8d6bc78dccb93b97d" },
                { "xh", "f8c68ce8d52e78928c495cbcda8a60c324df42dc8aeb7a3e15828da31eab966804bb91649b232a2fec93e6fff83d6042876d70860cde1da93a91c5f3f577c53e" },
                { "zh-CN", "86cbc2df7ff271d30e77f676ce1f107c697081f2851adde1a0ec5d26db354a6d0706715a899957afb9a10da0e63095f88c0f7d73df18c92e322b18a1efa4b888" },
                { "zh-TW", "7b863a93737dc357c721632f73169b66d1b4febb78253e6c6d4db2bb330bdb1b8a4d09e6b2ad4add252db8ea24e0a05736177ad94c2be62212474f7948ec7d54" }
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
                return versions[versions.Count - 1].full();
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
