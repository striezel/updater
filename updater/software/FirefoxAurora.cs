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
using System.Linq;
using System.Net;
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
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "89.0b1";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/89.0b1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "99c0f4229a35b2abcc2a5b6c02cdbc550c24a3649c4f16d9e64bd709e147bba3e43927d9ec8fd831f9d9bce7fa36c27e6c2bdf81c1015f6f619ba2393996af86" },
                { "ar", "97a8ea273b800398315082e4350a477ab4f66d089c63616d5fe69ac6df8382cf33e0b58fc1ac0ae8397c293e9f35cba4d5461a05e24411dcb374dcda88488adb" },
                { "ast", "a2c16d4c03d02a0e17ad53281ecad3c8b84bce035dc88edd7ea98a66401a453119c8a0be2affe17fa28975fffcb8e41720c021d7bd790a12a8978684686a70fb" },
                { "be", "95601d3494360bba8d60e567d92fa15b435a05ec0accd21512e2833dd67e9f810de6378c517440a4d97e16a980774f27e88677ccae6cb87a15572ee1fc0685b0" },
                { "bg", "c453cdc6400b86d21c96856c4e1c0e079af115f2ef2f262941e20e21180d386544b68bc3944023f72f021f0a4e856d0236ab6b0ce69be042e8361f668741a93b" },
                { "br", "e3f79caf391f06defeb357ad9c0467df1d372fe0028c8070df258a22c8dcfec98ae3727515e038f54966b8509b6b20c4f3081a604d1789031a82ba1356644e4d" },
                { "ca", "4d63693df2a769e64c10882b14e7abe199519c1e940347d7c8d76bd1ca9f86d1f4fd60b00fd6ceabd830ae37557d9128057b0d91c290ec6b2c702e8bcc96e8b0" },
                { "cak", "ad0d430e409d50dcf0da31bdf7c635135e178472ba9b88140da8254ebbb8d9c548294a43ce965c6148b211688cc2251d37c280759c592aef0a71d3d7c68da100" },
                { "cs", "5effbc48cbf4b035a5bc8507c13a80ab601ac4d761dc38972f82e5d745cd90f371c64d6e3db2a897cb1fc285e3aac9678a2c0ecf147fa59051087ef8f5372e29" },
                { "cy", "2e2b97676df903f9ef7721583fbeafb74d8b23e88162f4af43e158c218eb047d8b94cb9d5770c5c04c817ec8abef42cc4794e24d4c7e8e1928be52371d8882dc" },
                { "da", "843aafead982aa1f0a14664d1e63b45643818460c6233ca17c2b7f17196c513dda05f8df73068965bdcb7642b70dc147731689e51ac0880b0831cf77b79f87db" },
                { "de", "ace3ab3e26c0da7aa39ae1ad8c57a87905ab7a04a7394112dfae6f072f4c20ee1382a1430e8ff804c1b1f33da6bfbe2c35a11df7a9638aa69566807388a21639" },
                { "dsb", "3fda465ca4f086e5586c62bd11b7d14fffef34d566b2e60582dc4e57832f15115a325efdfd6913f3eeba100ed78e312553b5d2c20a7fa29eeb5ef665fc230d39" },
                { "el", "e14d420f9b1cdf879c4d6970a85efb86bedd7ecd0a2acda8b175a725b6f5b51f2345b7c88b4bb0d71161f026fb6a95ec8926d78aa15608c4da2142fb1bba9733" },
                { "en-CA", "a93efdf4ab5dd75e825ebd0455b22b943f6c9ac08a36be1be810113b3823aedd69dff29059c96fb8a7f559e2b29a46921f059c0cea6a1d3d6877fda56d02285b" },
                { "en-GB", "45cc238b5dbb594126c8e50ee53dc198a6ceb1eacea61b326fbf040a7e72ddc702667fd326525b6bcb6a0ff0830ed3e8f263c55047d668a6a9d1c5349c74e593" },
                { "en-US", "c67f7550325e81595eca392f1f18fed8469f49b29ca3b131beccd8811cbe2341a9be1f70ad5e99d10a2a4187501219f1f824b68742efa5101cade5ec9ec1fa80" },
                { "es-AR", "819c3b6464949f192025d54acefc3e12ae8c80c3c51eb8159ff2d5375895ee79bc9e3f1269ae7133265d1079f380199ec0924e583a8b02dde01d4afe20c15a5c" },
                { "es-ES", "c62f728b7de87638704e3e212d60fbf7cc38061e8ed815255ce64d4a95270004079c4b4c0869c9a4776dc7affb7964212eb93d2509b0677b8f777db2916a919c" },
                { "et", "043373db1f49f32d8a8b5745b6e1adb486f35e06bb8f568620279875ad05d89af731c47600b18f5ce5454fb24ba6a8ede862a372bf661a1742d7ac3ea10bb57d" },
                { "eu", "639c91b9def61560821acbecd959a1e72dc14b0f73249392f682fa8686402087e3b8abeb4ce9ce15808bdcbfaae0625d27309b517ef46f113cded4d53dff14bc" },
                { "fa", "5889299020e100dc5595e9c21f0d3f339a3cb44fc8aa5eee2ed8e19b40def9387372ae1ccacd7a193c7c96d556ee6378eb705a3ed4f8f2ab342156b2405f569a" },
                { "fi", "0d08324ed24b6a922e26f3af09e7f592bf6bd0ef654a5d25c6c345ed5e26fcf4b8ee61774d116405f1df549f8baf9ad62f1c10f089068c615a32a55ef1a0a8d7" },
                { "fr", "2a9e8d391556ff81bb3db7f8afe53eb71066818ff8b82dd753a76c934c6f223dd405927e4542d39ee055fea51952a282cd027eb34b96d978fec01252e4bcbb8c" },
                { "fy-NL", "baeee420c35d0292c6d3d18debc61186063a66acec7b388bb82ef8c9697adb24e7221a8014d947b320c852471e6dcebcda9eac80b62e2a6492c291a8999ca9fb" },
                { "ga-IE", "d8b42baca9fdace86a1a1f52051bd8910211a3449a2ff89edc7c0d80fca187601fa34e865fb88b4824aa0b0867b0466c1f6c0585e0d478e2c1c548b4775dcb90" },
                { "gd", "eee27c70c8429ea53a4cbb2681aff44b9427968ee7669de1bb91cfc2030895f67b4123b6ca4172c3eeec811bdb7a44bd5b92fe94ea925c7e178a4e1a743c873e" },
                { "gl", "e972ce975eaf875a07ab2e900b9edde77466c8069a30c8c190625ae07c284a9e8a0ddedcccaf543d2acab47994e7d64b805ce2b580734543115181ef456ac920" },
                { "he", "25670e61027735fe59dd884209c5044238da11df0032e6f9da90da088004e64a69693bf07e56b87d46ca5317647f66f2a286cc0657ebe48c243294f31260a699" },
                { "hr", "b1992c91dd761520f1172e6669f55a5056b3b1cd2e80156d5da2824238c91ff2e064d5dd9ed4a23800704f8c97debf8aee044c3cdbd0dc7ae7526402b06e69ba" },
                { "hsb", "cab6b36cb3114ab16eda6afe24aa0677773ba098104cf4d35d65cb3704110fc42977bba82f525bffe6bc8559759a4659e516b1cb49e1ee7b85b9e75daa75eaba" },
                { "hu", "8b7be2e720dadaf9bd37fc197cc942ec7b19b4c78c94d2e14e85fabb644bf9d338bd6a568d05e5965e7fdf742a71c0ce93737a5d7717405c7ba629e50a65b7ad" },
                { "hy-AM", "7b152d38ad9750ad31fdf1f88c691854ec6d901424cf0e121214d9132a25c5ba9e4458b259a3cb9d1613796f80b0de6d2c89b849ab19e12e25d0b4b658c6aa44" },
                { "id", "38d98c91dd6c96940f740ab0e91d778fc20be6af14e1de9ce1c96172daed1a03d3913ce6024940f3f6a1d7dcabffb5373139aeae935641e70cb2b9e3329615f1" },
                { "is", "9795816ae0bdfa6d44c1ed2f33b4534f204da690477716ebdba8a4cc8a633d5df3a4680a24be461d7ba7a3bf2d0d50d82d28c7ead3cbd1cd6c950b9e266cf1b3" },
                { "it", "605adbca38af5e69d595974936a78b68e5d9bf43e5dfd65aad2a88287b22e0b8a16bde8a9b1b6d4dfc027d1ff8d1f1425968e1e8b0d536c83993d24e11c87287" },
                { "ja", "cfc2c892f9a2236d42e63e5f3d2ddd9d65262b7d954afc4b9ae911392371908c1bc44f130092919eeea27ca4bf4393ff5e646cac2314c45aab0a558ee33517d0" },
                { "ka", "10680db645ccad54dea196bdb361b60130e2c2e6f055b022ee6693a3cc11ec8a339706ac11b7ab0aff932d63cda79e6cc173c6b67324b26950700e8905e2f898" },
                { "kab", "75829eb247cc8fe9dc5a56aa76a3016318fd7c57d1853a9970f43f1407d3c9c6d16b57f36ca4030ef813fc956eb78edd688d6738c89c9e50645591b2f400c49b" },
                { "kk", "c1e4304802f518371252480f522d7ef63ab294a5678503e68d5078e5742f90eb7239e3fb93fca4661fa7f5166f4759eadcfa4c56d73250d88f4ab38a6741d9e1" },
                { "ko", "a2c39c240cd4f7ba831aff3562f85e3eb314de85b5dbaf9f959193bfa5da74b1ac4f53e6fd8908254b31ad4f61247a8a840b271b2c4d38a92d461ae2f8fcd952" },
                { "lt", "bf956c89df5147735d38f2ea8d2f1f9542e45b8f95ffa95bc3d3221e45694323fe19ed87e2c4b500e23e3ab07c4478fe812274c757b0e97204fd58d70d5f61fb" },
                { "ms", "bbaadc1bfb4b8a2b6068edc43d3055a867ec37fff8c5018f218576b77ea844f38ced103b57d9d5e6b607086d271e83d934aed9c2fc1b895fe5dce5216ef46822" },
                { "nb-NO", "bba5e42a402a8dae58384d50f3e469475a64eb655048bf37a3f54cdb210f331529e55bf45bf9356ddbd8a84c6fc1d9cd49bf8e4b5a840d05913e053d0ef26307" },
                { "nl", "70852508def71cb966d540f0143583f75bcadd36def233efe4305dcf1d5dd53f6ca255242375fa14837e940fa3787bab931e4b99cb85d0ea178b620d3305f0af" },
                { "nn-NO", "63f45ad4918b8f70bd77d1cb1f5b7f788bc522958bd63c648b120852feb4007386e069ab9033300d8c455cd223ec052acaca9b3a06ef744f215d0c0ea746ecb4" },
                { "pa-IN", "59bb0fcca9527f3392413901324f656fbeb8cec0614251fb221efa1244c63bd081068a32b51dc6fac71fee4b74f3e5f5d95bb014e9c1c5166d5e5d26e6474458" },
                { "pl", "b8bf0690fdba013ba66f40cef1e4ac03399ef6bbd18dacf08ce8b110889be2cc4ed75358352c484b7ef29e7418615266d1b43cc6c7e42f3f1357a4290bcf4a09" },
                { "pt-BR", "5ecce45a61a5876156283cd3417874383b11c59a8d278f466f444748ed37bc5d3a29d52aa74fc69a2ce20b6a4743ebc6eb7e7f040abc6ad3b4fb7d826d7fc9db" },
                { "pt-PT", "36b4388db7bc27d67344c55e4c3a8592cc8555caff6d1ea3b74dc0df74c12e9163ce5e5c81eb7a38be84b8d3fe4ff6e63559f3236754eb25fa51352ced9a4250" },
                { "rm", "be555ef09307bfef80e78137a3f2a9a6d30d8ca376b1eae1307ad0a817afd54c52f6e61989e1ab8fa290687081caa4a1905120b74e1163f5d3d15e5876a021e4" },
                { "ro", "a6616d8a5c33016d78ee64e3e6c0b055cdf7266e776e5ad6dc7d38b0a48ea6edc588be31d904b52f323677ed4db4aab851db6af81a9afca75f19296b9dad9fe9" },
                { "ru", "6895fddb8c354ea362bd5ab3c3f7701c31a877f16fc94f4b349f91837dc1ff0eaee8e42498556fcf294f1ee47dd448728b67fff83360e53e18e78c9fcd1924db" },
                { "si", "2f5c4d75ba5ebf292bacde95f19062b6ede933eecec636522817c753dd1ae6c957b57ee9aa28794470aec2471d8fde775cc83ecf7694b1f217bf368d2bbd51f6" },
                { "sk", "b3f24f0749fffbacdec94907fc963f1ea5ada283639f050dca050eed075d18d2a509b4149b986341430d3a9a384b6345160fe48c2aedbd9e07d8fae4be0e3e98" },
                { "sl", "2d20db8e72b8d8d42e3b8bc6d0e64e471d2cdff14ef2358cc0882daba998f9342ae46dbd24c77e55004a1e08b82d8cb846d22c771e31e893b2209b203ab3a1ac" },
                { "sq", "adb8ad9f4f67c6bd1602810a7669950ac83acac176183d67920748d7dc910030bcaa5bb7601c21144cfd6808604461029b2511d49956abed21eb55469b3bc4a2" },
                { "sr", "3b260f5c0412db2ef77113c26090d40f7d2150b98df6962e0eb7e7f79facd03ca72abc6f9c942b4777351aeab29663770acbd0b90215202325c345eb3ff79995" },
                { "sv-SE", "eab98ae65243f3762a08f4a385e651781c1b3ae7ec5b7893becf47959957b11dcf9e171db3d283fe09662bd5c81f577abffdeb3c19dc35080d03dc242d2977a1" },
                { "th", "14d1386c7addede60ea3d5e03cf7822bd91991d57772cec785b4d5cc5b67e229feb0662f240feb1490a7ccea6093a54661380eed8a36892a4b5becf997237f9b" },
                { "tr", "dd4535236d81c4e1deda98fb9c020c4c4e257a71242f3c8c4525ce75228371b4fa3506289913ee09715f2459037b00a70889a266026b37c054b9c51548747ccc" },
                { "uk", "9b916781c071e8866d5d6833e34dcbdd040459428e402fb6c6b66a5cba692d40edc0c6226f20038c6ed8a2a2518f36a728d1873a54f2990f5a4de2218b7d7e9e" },
                { "uz", "5b997c0d94c1fa5204eb35796e80769dc9e4e655197fb8e4a92da295340ddf52a4f5ff2e25d58d152e9477ab50767e5f0622c7a5e223a5215edfd3c49a82f83a" },
                { "vi", "acbd29a4a9da960ebd0ea5e03c6e58e7a741b6f147d6ad70dd55c1434cb9c513676d2bcf4a7638ea8e1d80bcc39425a1b2b2be3813e6db029b4056be33580623" },
                { "zh-CN", "a1586bcefeaf070684106392959665acffb409f911e32ad66d8d8e85f00ffa4c2d6bc97bc8d6c1360aedd5d0b4e742b72cff5a8129ae684180c60d6d37bf6d81" },
                { "zh-TW", "48904cc876b1a152bec2ae1d15febd90ecfbe21df2a52832f879a90711acc7cb37fa685be2385335df3930389829de1dc071665e71f42c22bb1b47c1276a92ec" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/89.0b1/SHA512SUMS
            return new Dictionary<string, string>(96)
            {
                { "ach", "8009b9d50a43733cac20e8d2568b6bc133d426766d111c1bf63452821fb7d1ae27f90364f63980616c93bdc9b04560e6d4782a198f3b9e62670f7bf9fd39f40f" },
                { "af", "140ff148bf5c369b3cd2fa4548f18dfc9d908aa669c7b74a5d053e7aa035f4d49032d1865f5f26aa7b0508ff3d0606ea57cb107db8effebd0792c08acb15277f" },
                { "an", "f28b684d49ba1afd155ff8c0d55a840c1bc2c77d8e55864498b2304dec53bb993e136e2ef31294f7327a5d02940875b853b69b6ff43b1728f72786459fe92131" },
                { "ar", "6a2d5c7812f4f2cef89568512c42bb2bd6d8a97cc0adba3e40942a09b5a8c5a045e137e41375cdc2100974b331c71aaccd1367e478b4990181a97ad469dd1eb9" },
                { "ast", "866ca8d955501dda9dd430e2daf1a9c0a1e53faf1dd9615966cef49a7699e3dc126933a57f177284781d7e81316e2705f75901d5a8d0f949c63bfcc4b173fc17" },
                { "az", "906d59cb7732c8966d775e9490e1d40e3857861fa6ff39da92026484c2437884131e855da3b54b449267d9013896108b8a51cd179c6eea6d27b750f79a92b560" },
                { "be", "6c225e15197efd28cf383e677c2665953d156e371c351d02f05abbfc51cf900f8a18edb476d1690b8d9914a72ae87fa284b36b1f24d7d0212988f4e65126a9eb" },
                { "bg", "94473cae08d1a5c9b4c550c8a6f397e2d736d772b9c73a22e7ab8ac4d50ea1f5c99b9c0c6abbf7efc2d2561fa537818e2722578706e2fcd110afb921a0fcb787" },
                { "bn", "6b9496d6aa7655d219473584ea214060508c136969c3ba8cf692cc93f3f34fba30bfc949e3014cecf6803bd83d2f02fbc38c80dcdb4953268eebffc92369cb13" },
                { "br", "a55b1de06a7bdf34453bf86cec4d80fa2b0ca3daac4ff9078a844183bfd37fa8b4caf6982eb80ed0d2abaefa0e2b9c660d1f355e8beb8fbdfb5a9dfc849a01ca" },
                { "bs", "36087588960a64798ced3ab93256c0332efe24ee8d259ea5ebdbfb4295c00fc753528df57d7bd50be0685571e6b60cafdb3ce6906e83a43a151cf19a522bc749" },
                { "ca", "b664228a045de7e84990c8dc4be71edbe6cbe7a81c0397fc466c2a7026d67893c6bcbdf39785f2ccaa9a79d644980378695c3e4e58fe63d5d855b7667e60fc9a" },
                { "cak", "0d2fe553e0f7bcb35feddbba02bbeee551fb0e4261bdd25dbbfb0ea56eaacd3ab6e11748cff5f45b8fd45628ea77f74aa089efd8a1f6cb1aa56bc4a81bffa364" },
                { "cs", "e89e310b1392a905862b68ff0abeb9cb7a5bd9b0013c38543ecf534d6069a0233d7071bc6ab3fa5f45fd018f48ac5c682885846a811b9a3f286e715a869fe79d" },
                { "cy", "09b5ed78859b626a86e5d4136b5c6a6d496e291cd78b7b360d0ca5c38a533d3f78718f0203d4be38769b0c1541e922750dd4806a74b4a85c76205c7dbdd610c6" },
                { "da", "cc800c8197b5e6e520e6a39e079a4bb476ab0726348b9fff9fe372d1e43d50efe86fd4b24faea4afab14d329338dd2aabdfddaab8e50b052917913d87a0bf4fc" },
                { "de", "5df131516d6a341e6422cb54de6cddc1bdbe3221bbc84a94528af3a91766667f128330daaa148e09427cdcca12e35184de73b6a16edffb68874da931dfae91f1" },
                { "dsb", "d0d7b8454ae70cb5a02bce3e0d3594e65d821af256b4197ef4a643e2806aef9fc2e36bd59cb037e9cb28c439c3a6b3eac78c56135fe2d3bae0e4b8979ea25b5e" },
                { "el", "991735af81183390d14a59abc16ccbe08253112fe1797d921f2a04a84efb401557e50ed59e532edd97afea4d1725c8ff127dcf778d3fef705ba2d620e41d1874" },
                { "en-CA", "fde57cb0049f5b2519fa0b2507a05e11bd0e218c78217ec06d7f5b42de0a4e169ac9771f0d5b2f3211f8127764b0c583fe55d97378cc740c62fca8f0cabea455" },
                { "en-GB", "b96b71029358a7f67731662de648d5591cee281670b54438f5f0b6e51fff6f8c6cac113bace019e4c38993a746ad392351190930a8a8f9d013272896acbdeb0d" },
                { "en-US", "3ca629b46225d68669c8f3404848baadacf1c20c08438d18ceb7bda2c957e088189c049416eacca1e2b7413162aecd9df0673eba3ea2bf153776c228e7b731aa" },
                { "eo", "56d4bc0202aecfe679892587eb4110856c4871a78b16b43c4db5edaa4373224e2d7db257fa5c053b967c8956e727db62ea7ad4f867ae5fbf37511da1c5bcb0a5" },
                { "es-AR", "17047c49d4fbc72410ea6d18610ff5f7ae8e507803f89a1c44f813fe7fbeb24dee6d5f129c26801dcb32af2a2e3c2505b0579ae8366d9e60ff8b40cd8a99ad85" },
                { "es-CL", "f1a638c6d04d62668c59b2d09cc7338c61700dd2117dfe862139b9968de00e68790679d5f0018b7d387382011e0fe1afab7c227e025b3fcc361b3d72915d698f" },
                { "es-ES", "31f624a150f2007d83f449f8f2e15c46968b182908eccb64529cb7369a676053b1d7d73f9d4836dec24c6a1cc8b7dc4623b4a54b9cf78a30ff54d6ef91e27c33" },
                { "es-MX", "12d055e8c381c5186a7388d0b66f72286cfa7c272232ebd2d127c15ff94ca2f5012da01798dfd5fa090079631a2df419d31fdb76217677f7596782fbb75ecdec" },
                { "et", "a912350c48ec200657d971ddf57a03059e5b8775cc67a6f2dfc4d2df6057592d23011480bfb9d1398a4764744cddeecb3f155823355ef0d00c8b084eabe3fc10" },
                { "eu", "43e81b0a31df748f6b72cd9a8f5c1973ce8af28d701566673384840f29b890f95ebca11adb1633f40e62b931ea5da617dd5c6306b5cd94ed3b7f9a4a1af3be0c" },
                { "fa", "ac2f3c770463f027f26c8de1a436a5a8b216ee4c65cd327d2594e404cc87200fe3250c394712ce1e7d7925ee528ae740e4f246d00d5b06afd830183951ef711d" },
                { "ff", "8fe6546ab3db0f097bb4d411169e7f47c07e5f9e4885757a4eee11bd7d741bc00ed908f9aa2b0aef042b364c26e3d8821ef4d1161c880de24e611085f4660d91" },
                { "fi", "e91dd816e092349744f8de5610cf1f9d09839512d0556d50713a1cc30036229714c2ed498eecbad7bafc8633e1a6e07e7729b965516bce27188ce93a9a9a3d34" },
                { "fr", "c7c37e0a4d470ef90561ae7cc0274f41532fdf96a6630e0d5fd28898ac325679b41edd15fb4563c86c2e2efd03ff9947919b9482ba99db3f2abfd66f92d8cd41" },
                { "fy-NL", "598961a46228842a5c470a86ba1ccd397ead3a1930818baf56ff09ed8e6f427a041432d150ce401a4232b7f2b70bad67c20032a928b9c7fb6f712dfcc934ca93" },
                { "ga-IE", "7b9a8af5dfe78d5f0c3fdecc25eeb2efbb517ded4cedacaa7056981abadd0892a903cf51efadc99d1a262a62fe429e64fed2eff179e2d4eb6c4ccc197cf7ad54" },
                { "gd", "86011defa571c49f810678b8293ca01b0389ac464c16a39f88e757e95e34551a1cfd964aacccd5d7b3970a9f7357b90fc3fcddaa12a017908e162aa7c6ab04e0" },
                { "gl", "d45aad2b695cb99dc1978352b28588d8e93717f9ebbee9c96a45587fba7407ede39e91a705da6b209683279c0cb10b8284258967d09e5c779f28842ff51f741c" },
                { "gn", "970b44b90fe9391badcb6500eabf133ced0df5581702963b9e6459ef91886a0f335ce6777db9d3fed6ba7d68a09dc64531327bfc01f72360bfac36e202b7a9ac" },
                { "gu-IN", "7306bca7bd969ca622cd095900a91e30271d8274f6acdc6ed1f419cd972e65bd0053ed820bf1a8d2955af7458d343ff937abb0bbb25cf45f08b072e1712a2538" },
                { "he", "9ff9172547c8e4bc42962da8800304540f8501cdd8cbaae3a03712c14a140f2797c20098eb98a7abed56538a12224684ec73cc47b184dcf9adb7eb6da69928be" },
                { "hi-IN", "5a0e1941eea9ebcb70c4aa27fb2cb06c42860d1bee847736d0785ed5f4d28521744f35546af85e8ab184c7591d9933a42cc2984fce20a2bc8d8820926bdc5205" },
                { "hr", "3031ce1c18d52c722452ef051703d0a39764ec0bf52362bd6afa5f6f1206ee0fe60f44a47140d36f13eb00dc1346d6368a1fd72881ead21ae984ec0dd6ea9630" },
                { "hsb", "da30136acf24b5b850a2f13f1b4aee77777e124e1c8d81d1ddc58193832ab081b63a7438cd1104409ad38342f1375062fe59bd5b6bce0f97e542d6645441ee5c" },
                { "hu", "ea2ef1aaad7824dba1014910fc96b8597d3df364cb0871c758bf2756e7cd68eb9f7edb7bae71ad12a5680036f4e0ad536f37061e6ca2b3b2085d9abc95f6c622" },
                { "hy-AM", "6422afb3a4abb47d0b1e3d746a60348f3d14c5e79d2b8cc8fa44905fcab8b37a2cb4401ddb07abb35541d56ada1b7ab31010ddc1961478b6b3fde10b169b8a48" },
                { "ia", "9fe529c8724d5604cd60fbf981074f4be84928aec3147c718d4d91994758e0559111bcaa5aeb7a972e865fc6a2bd9f5ba0890f4778a5a6e6182ca539b6b2076c" },
                { "id", "6c7799afffca30f16e9815b9dbbf2a14cfd51c872ebf6f8c862f326f503ae49cc1a7b7cf8fad3b5387c6e76e8eb1d84bb595b345a546d21a7ea43618222da449" },
                { "is", "b5408dab49b8637e5c862b7912e6314bfca23811e15cac19b075d97e95140b9a382f076518c333b1251eb4c9ab6aa5d087292f3fe032276074ef055025bc7868" },
                { "it", "a5c02ae0923aa1fba6d36ac996095d7e2a9daf9527d7878b8a82bd84414eb332c62a1c0cdddf82f2263bcf177380b2026dd09244ab1087a90139befe570e6270" },
                { "ja", "f09b2e67c9760efc019378b49dcb4442fdaf821be175489d2e2cea4be5b96dc94ed7c71117d94266a26d8343b473bf49f9ca5b35bd1c8f79c315a7d216985af6" },
                { "ka", "d9b68594a714a4083262aa4b4b1cd92f05bae30ea1cd130365104c1efc75f6a79dca4e0081bcfe66572ed71a20dbf4a178915a267d2ef4272dc1767cae2fa0b0" },
                { "kab", "67a9ac1b15cac50014bbee7e28155e34cc3826f6fd71395c8351544c78c111b1d8db2c661c5bb53583ba669039c7ba78e5600fd05be391135310796116401627" },
                { "kk", "10c39dba31346e76d339566cc0a8fce082ab38b98f12ffd9cfb621671f98d4382e05baa43fa159368bb526ae7e9eb7116414c14dd99085807c72b45568b08696" },
                { "km", "b5f21e0b64b4b8b1360a134473c3984253ad04a986003354894c0f07cc59ea9f09eff2cc09bbc77f653624aa39e3d123c7a2cf3717fa5aafe920f70ed6c5b3b2" },
                { "kn", "305c4161c4c649ae7d01ce58063428b980248904d35170204e38fab9395f7197b6264b9a1f5413dee7a209972297d1be2f779c510e66ca80b957f4a81e6410c0" },
                { "ko", "528edb6a776cdfe1daa4fadcc0614c06653167f059251819cffec9f69b43ee31127658a207b3afceacec7d68dba8d0d2f6c9fa0257fcdb3cbe402582f35088fd" },
                { "lij", "aac5f3d85f3d035cd4203a9c5014a12b35877e915466f5c4dcdb8f6dfeba0ce93079f3bb66897018a32893b8a52c74036e175e8e792e804cab773b1cd569d563" },
                { "lt", "544e867b4c78034fac3dc36b81230a8f4f9f9b6bff8927a6890dec6a59f12f7b8217f1177406c6faa6f3759f28f7b8d345aa07d70b84cafe9605effc03d6cc84" },
                { "lv", "9de27e469e04ace86ca119bc9c7020e83c947f8f2cfb898bad94f72c4cbdd92a198f3fd2a93e6fbcb4911a0b6dce5ca1d670d71303a2d1b0a7b282b4f60e7b90" },
                { "mk", "a3592a73ecbb904f4276b0e3a23ca8234c9511bf397c710d10db8292968c9e9d709a2a8f49a3bd187518ed9b58239c1702193ccc03c6661cb9321f747e1a6605" },
                { "mr", "9f910b83f27a482775b6cf68e934dab9457a958e35faa697434b524295aa2730eb78dc1d70b1ecf40ee466750c76b5db573d18c03476c8620b2fb13956373ada" },
                { "ms", "e47d93519e60b5c3557763d0fbfa27ca345ce7308181fd74a2f7ef250444265f54d5de539572886f7a99455ad2217b7ad584222592718b0e6df793eba8384fc3" },
                { "my", "fce0a71ae0ea0d5ae3a89cf0ad55f1d9c5200571e46a27af20ca717c3b90fe98fb0334ab63f91889203295bc964cd0ccfbc8a8902e4136bc9a037e20016cdfe0" },
                { "nb-NO", "0f8bbadc55fdc7fd11fc091333a981e852d2a117b009a2e1c0cd977211642cb11446dcaa87bbf8e5c0a205f5b02d8b66f84bf5278a14a1fa1ed26fcda802f792" },
                { "ne-NP", "b18d3e1d75c5fe7843d9a4e896cf988e5e9ceb831d82f6444a12a4a343d8bc245b900d9d583aeccd0dc955102e2bbcdbf80804883115b1fe83a4470e2baed1f0" },
                { "nl", "0dabbe1a44c359769ff648c26ec9d781ac7a0563b77e9896ad8960942406ba61f40207a16bdf7ab6781951f7edec2aaa4836421e40661ae8dff6e1cfb38d4e95" },
                { "nn-NO", "73388f702f411008c11e5471e92b392eb5b961dad940fdf9f7484a8f24a13d95adf5036c17cb1b2ed31870d18d626d10468fe41f2bc1fbf8f375e1ff7e172c1d" },
                { "oc", "77c9c4cc32a084a60f8112621f8809d3b9d04f2387a68b377443d52221135f4f8ae16442cbb55cbeb73436223e18eab8c1cf0fac8485c2101fb165bf11552803" },
                { "pa-IN", "e81571247aa666256e46910b4da615b336ad0b2e695b9a9313ab6a4efd2b4bb994e23f2b81825c54c3f18d6022097790da171b51bf1f705f60a74dcad0376b56" },
                { "pl", "b0e7624752864427a8f1e01ff2c98bc09e896e3f40d7b66b728cb8c0e12d9a709d58cd3145c3d5903a28977a5c38fb7ad40b0c043be6d92123534e78d0aad37d" },
                { "pt-BR", "0681d0c95e6df3bf10fde05dd95b61b4dbfb7a4b6c8de7ad1bbec97c013b94092618ccdf81275ad60f342867250de52ebc26577cff86abd2e8c2ab40468b7a95" },
                { "pt-PT", "7b714871ad3e6faebf4f939d6827e0056eaca10cf6e4cb44d891330420f4c1cdd7f92d694edf0e7b118589192214cd177123568889e8273398e8af127819c05c" },
                { "rm", "f04c251b083d65f73e3b4efd92c60ddc8d681ffca438ee1f1f66c6a53d15e73fccdbc91d3e00748a431ad253bc622821bf78a2597281a5ce81b9028fc4148203" },
                { "ro", "9f085817fcde7f5c84e6156294082d26ab38d4acec62bc9bb9c7b73f4adc30f79c5e35a54b82cc98634362efde4a58f41a79033e834dda47a8561b4f2f11e179" },
                { "ru", "0ba2835d6dd02717b2274e08cdef4371d525e78c2baa2005cd7abf0dd19a56f967546aa20fbb80bd2f1695fce2694e3d639430f7545ff7312d59a65c863d03c0" },
                { "si", "9e3e1b01370ab6f954b40e6e5f9ad5c838e97a968984eb7a013904067e613c449c7373f990db3827516278c8699adec885d91cae6c5de7b0f985bf5738605b66" },
                { "sk", "a60fd33ac8a76f04b7e19295076506e287fd1a12ccacc0c1ec1513e9cb9c8f002cd94faf389c94f6549ae8e798698eca278c241e720c682f16f2dbb1415092af" },
                { "sl", "88c5b3bb6dd2fc727e06db30bd5574b9502218306893e02891a4aba184ed83dddf26ffd9b1a9d39b762e7e805ffc201edaf264cd5bdf59c753670db45f4a4b77" },
                { "son", "f6448c551f233dc00d222f7384bb6b37d3b3a48047ad3f44134355168a5bdf9d0bb8c2d7d3a969b7bcf594c947110a9586f5c2e3ef01d43acdd1355eddc9c4f8" },
                { "sq", "715406bd8b63fdc72883b270c066a512b30f79d6591af5b4ca33e58d1471f929abeb46549f4b02db9e19fafefd3649c63756f834f67ceebdb56d4d6ea7cea670" },
                { "sr", "4976b45415330dc3febc3573bdd94994d2cc070bfca2d14bc817a35da52dc4c28dd8bcfdc79adc8a3b21835320b3fe842371243de0162b6163ce7226b912fda3" },
                { "sv-SE", "e9d7d59ce5a52aa27c9471bcc291fb2272b8a0631f5587ea67ee0088edc2c0ef4d55d3209aeb71db027c804db2c4bd2f4fbc0fe2a28154920c3ddc9c8711a6be" },
                { "szl", "27ec10fcb72139f8cdbcea853b6f6712b255a14459995018a4c6dfa8412a366040e0475245b9e2e99e1c72746a8ef323378f3d06ba3664fb91b0021719c9a4c7" },
                { "ta", "5564652db1477d70ac587b89c82940d0399a68947d19ec44162af5f534b556f8ccc66e2d9bab727ce5e95c5a055adefa70217afacc9413b236443e10e78137b9" },
                { "te", "a106edfcab5153f4516fa8b69ebb51e15f1c73f155aef4ea6d12ea55889af677a22a20d4b0eddc89cf4ec3c5a8d4ae93a6905810d5742ae7a216b5ec4ffaec7b" },
                { "th", "11129cf8483228c4e1b28dfcbbdbd66ba89cb12210c8dbc0e8a5907b02b2e901c69319d035516b8463989e50438a9765a56399380c77a7a5dd51c397cef5eb52" },
                { "tl", "2b57738a5c5fc086b5e0a99d1c95e02a604ac849a65ed89063e9c3fc78d994b2955e3a2b0ff3e67e59d0966c4efba8bd8f55032b575fbcc6057e0c7027efd451" },
                { "tr", "fafda0cc5426416fa09ded2494702f4fee606a17f037592757ba41292bfb86e04434da39b846001609a77c0ab55e0177e659c25a61318a27479883a4b7c096c1" },
                { "trs", "878230a24ea1da120319f1600f1f0e4b66ff3067cdfc3ede75d0c9d4519f4c53e51e3197763b152bd467467f9c9ce760e4b4deb80646481cbbab79e6fe1f1340" },
                { "uk", "1f749d67133d254da8c1573b02e472a736440c74d4080d57aefdf1f2610f0eb0358bf3335f75d0d80ffc5bc7d20be20f6476e37972b42c3d95fdc68bd0283845" },
                { "ur", "4e64336a96b6f1035f979a2fe2678cb69187073f7260ad0dd70620fe3171f8574059ad52dfe7312432729189fe5195975af8d5054e0e5c5e267247f60dd187fe" },
                { "uz", "ae21c8de85d6a08619a96435ea6f4a4f4656d9cf24eec47b1c62d1a1c3664aae4bc4b9062bf391bd9bd236ee4d238ce81b459f083ac4b55abfd2990b7e5f56d7" },
                { "vi", "4be117b6c5615e5ed73891b1117cf3fd2a0f0ed28eed99d6ae05f553102d655e849e23edf18cb11149f4a51ba2e14e74243fae2713d1d48fb05f6fe5a93ddc10" },
                { "xh", "aa443c9728c36bc1a9c92c08d0104eb0e3abd12cc5f4a1dd4da1725b058bf3e38799841525582bf027efb14091a1f7121fb8fa77ff6ab801f04418f3510cfd52" },
                { "zh-CN", "f682f8ae3fb5c0fccba758ed6ab87989b292f099b8b09c783b6e0306ed59036ee0224142b6a145c156beed6fcb885111f8cf1fa1073da25f04af0f01aa93b61d" },
                { "zh-TW", "9b41bf4d3f418aeb9a6de313b4fdf1258afbcf01fa2fe1232dc6e02e18bf18c1fdd61020c7da2fc90b278b03c84c34f6d68e0e1b5363ca81d7a9b872c9fb93e1" }
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    Signature.None,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    Signature.None,
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
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }
            }
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
