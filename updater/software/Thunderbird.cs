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
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2021, 5, 12, 12, 0, 0, DateTimeKind.Utc);


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.10.0/SHA512SUMS
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
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.10.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "c2f47b22e78eb80f6700646d89783f11adb7662b0cd067acd8b3a9071e17727858e45df79cbb54f1ade9d0906c84db7ddfa4f7915d15b1eab34de271d3cb3a6d" },
                { "ar", "0c707576525a63da9138feca638ba8bd3c69a482139b27e6030e60730bc59ef9cdc15db364a8b0b78263d0c5efebac09ae6f3603a83e2167cb34b7a29a3c1712" },
                { "ast", "724f12dc9c9afb2f01de7a5333c34f195235512fe275e0c8b153df30f529bfce38179b4806c414cf8c95f483e438557b1b9cacfc494448e872e00ee65d2037e3" },
                { "be", "38361396ed95eb37711a33d7279d7587d8c5ba14ba164ea20a759b65a27bf0e943fb3076134b29a773ac1d9dd91aedc5e9994c7f1fff2abd63029db068fb2ae7" },
                { "bg", "89cfeee4098fceed1ac3fd6ec2b4a00c17b82c0fcf4147d9e197dea7cf679d621c0dec83650061b83c61152fee6bfc296552cfb3bdd31407f7f7351a4f8a0829" },
                { "br", "365f97ced65971fcc3f0bd40bac6475538e17d00fe890d4f9b769095f70075f001a4f336c31fff269fd7d1a82bd940290c13111367b96c52b7df8515ff639a3e" },
                { "ca", "9f215ed8f69abf7c899f8c71ecd51c3f087990f6beef5cf1142c1c79a2aadc44cd48e8b170fa207f7dfc434b00cc8549e6d776579d830cd5d40d2f14d1d5a262" },
                { "cak", "34bfed93f7de96ee8dd450c09d03fbeda2deafa88e92feb5759ecc167b65f0744583df6401a7a10571371bd4d6b868b370e6db635962064937a790b6b231b527" },
                { "cs", "74ffba28d5c2750eae49aad16039549f823e417039080a3d8637f633a613b40afe983b92d088c28911dc9e29ad6571dd9e586f4ff9496887ce5f147ddbfb05ab" },
                { "cy", "86e4a8bb291eb94517c58ed7d100419043db4b1052b43f6d756771159ac553aa19e468c994ce8d6dad8f6148506f77e3ab233a94cefa8395ac15a69cc97a9d16" },
                { "da", "c123f353b3a80b5c427368ea4f41e7de2a09d63683186d072446be27cc4543c7ad565960427afbf325618460fd55c7b9d1251348ee54189137edea5791e9da98" },
                { "de", "00607cb57dae80a452cd430f284f5379e50805218f9d1428a5517a5582002c8a80a9ecfadfacd2cccd76336a396b1503100fea1342c0225d6c8683442fb6858c" },
                { "dsb", "cdf10891bc5de2d94e2e0435022edb94365be6de18603d9ba1a3bbfff9dc62f6ca257a4d90788168642600a0bfc2c72d2c6df92efd83d6f543ec15e01d46ec8e" },
                { "el", "8d72072c21b46759540200ec3df6bb1715523b3a73be7bd5c838db82a7f4153d8e5bce4e7ea314cf89b7ce16424752821431ec4ad91e6445cd987a97ba871bcf" },
                { "en-CA", "2cb45d5693405b401e99bed6055141da0ae6f3961a485db68b12cb4bb82b4479a556e21ff13fcfc65a78fc418668e40931019b5442b9bc1dc366d10e0a7bf3ed" },
                { "en-GB", "e712d56f1fc99a6caffb1bc5a01ec7cc907fd4698f825aa4cff1256538d8966508c744a893cc4b65cb35a9a9077849d14b482fe0426173e7d8263d319f29bfea" },
                { "en-US", "8f22fa7e2dbee6c0a7123e7e50af5cbe7c273ed2849e5a52f9f6f12c266a6c874000834a5b36e16d56c364e42a0279d6673030f454c5a3045f180032ce8f447b" },
                { "es-AR", "e25ec7d31ca526dc664a4ce3c5c1c163d8fd4b2cad3d9f3ecc4ed630b8a6bebe65dbf976096dd86a4e14fb54077caa697f4c580d3dae800bb146c9f2058bf3ce" },
                { "es-ES", "aa03f07a42902994bcf6ac9f6f38329a1b7bc02cacf7b89f4dad020585d2d5d1dce61357779d4edb670a389429306cf96a51f57701b2591b49c3689aa7009844" },
                { "et", "dadcc0ce7a1b7372aeffe856e5b3a0ec095444ba77614f67b94429cd24800f2f72e4601f66f42085466ac98a846afc6c8c01a82099a20d6d7e9f4eb84d6bd8e6" },
                { "eu", "4d6a7d0e290684dd9aa8c4759b62d37c63e5615a3a947cf6cecd7cd4febacd217e48b9f529e93cef069d60bce9675d012ec960549ba3e52d3575c5825b619ee7" },
                { "fa", "a29b14007f2702022b23ab94a13546ba730dfdd556632acaf2f3863319c2a5090c51a3d66a5e0479bebe9248516c1786eed2456dc101cca117df13609cef40f3" },
                { "fi", "8cc537625eaa894423be48a59cc8672958d7e69ee8ac4c075adde8b205a1fb41d51f6daf86060f10632375a2c61fa4f8912abb07e52cffca327f4e2b072865b1" },
                { "fr", "6cc63b7739cfff2bbc18b5c07554c2078fab08850430738f44ae412c07ade7f89b4c2dd87ba8f8882020ffa2d5459df764a3175f45e207e8a461c6b73a36bf3e" },
                { "fy-NL", "b89f248715cd807f61874cb0722bfcec8831180ae8d17d7254d27abb5c657e2f2acf908a2441aef4e28a9067c8699582f25c1b0c3d0d2fd53c7a529f764c46f5" },
                { "ga-IE", "44d9d3cbdb7d9f66b9f375dedaca4e8e5d5801d69a3ec1a7fe88d5248a16885f3ef0169ff86b4112ce9279d70251a8fdd70c962760bcffd75b8faf7b95036d69" },
                { "gd", "b992053934e8219010681fd228778c5c0f3f809acb643a20e24ad6a136b36682504c5753617f940ac092d0bf0a5916cdad3ed9646b6f345d8ea1534ea1591864" },
                { "gl", "bd1f5e746d998c9f9e8374e7a584cc2dac2d021419a82539271839786f4424bdfafc8d1e8946bd57ab85a689b5695f7b4e26ae2c18d05ac689ba36464c69fab4" },
                { "he", "e06754bc755d49be70c72abeae92f8e6e6a082f2b9e6aa696ca21326c6976348e90069a47d4e31d7eb60447039906d0ff8a555f4153e4c2be9591df9fda128d2" },
                { "hr", "5de340da6c01441c5f030dbd295f2d9c825dbf3bddeaec9209d80456e4034df61445c6d0c923d248330c10ffd0ef942ef5c4d1ab8f122b8aa1f7687335196b8c" },
                { "hsb", "fc4b075b33c27d76e8c8f81dd353883005de4d021f4cdba49c87461140b90bd95cdde6347662913c3d0e788c154edfea48d459d65f19b15a6f2e69d8f938651e" },
                { "hu", "12ce01fb16187672f3c9c155dbe5aa6b5e42353be51cbe76a35733489b2ece518e48a4046ee91db16ea1e0cfe8f4c4dc3dd952d953476f8b4f448bbe12af369c" },
                { "hy-AM", "a791554c7beb0358e7a282ff6ad42b05cdeb4ce06a3547e24e6d80211f5a4beebb5fba242c567251335e4d7b916f2af0c375d4eef79a3492f25c5876304c6b4f" },
                { "id", "d8157f19f75502e7cbaa4b95fa547e2d8a2349d1d6f1e35031bde9007292977c38d83364727e31fee0917b3b1dc48c4a31741718f48fef4df2285fb27f601e63" },
                { "is", "890e21c365cb9c3a7a6f4b30370ed8717bf08b862ce19a87fd58beb334ae35861ee79a7fea66801d2271b80d5c4f2a2195dd00e2d30719603da8de648ce3bce0" },
                { "it", "ef75e38040cdf38b45bef6b66d932b2bb543f1e27fd790e3d33c21747e70397d5a5ae9c3f3f91ab238ca66f8a2c211a2e2fed93f6882a7925606fdc9a0197f9a" },
                { "ja", "3df6f040aee6f2c8bdd826861db26fc0e3e893611b12ddd709e91e97cd8892e2fdc613fc3fb65077c815ba1fa875424f3e6aa5ad56f135ad193619851a2af52c" },
                { "ka", "edbf7e88f589eb7f17bd3d6ac8728443ad0ee596c406324d400e89a274897445243133db5265f956ad795799b216240070c58a70780694f0cf387106300d39c7" },
                { "kab", "19eb50b7b1e351f4ab2b8f2270a1bf0d55fac35912bcf762e4334f0a17f74f1a5bc67c4d89fb3ac4f9680829d92f5cf5525bd5f05263aa70db5c11097eb65238" },
                { "kk", "38e405d7ba6fb3da0791a6b99bbc1dd35ed4cfb3f148e7b8c550b7899e5af253e2e236c3fffaa3ff1c8a587d973f9edd36c851dffbb3ede52cc345246ad35b29" },
                { "ko", "b05d51f463875654b5ba2ab65eb0119534b377eccdefa24bcc71d16284f20aa6a1859439a99d6493c8121d41da51c3a5c07d36d86bcca46e9f93a5930851b827" },
                { "lt", "4c1025eb468a9ede4e7e316d1e4297b4517a051c9459d4babe54a4357228bf3e8876e3b55c69564e221eded185950682e96e37ff8f184bde86daff88cbbd02f5" },
                { "ms", "52418af8f8f3d8194481b6ee4d506b0235680644f145aad1e320fe8810e4c4d6bc28f304c6a2d3248261d9476477da2058c1afe1262c942ea0612d4a1b76ae10" },
                { "nb-NO", "d2a1b46eaeeed13f92f935487657efd4a358163b30c925f9a28ff2d2771f7119571f3fb358111ccc8d1b8d397c2aab854f3b4098162303f0994b0ebcb5f6db1f" },
                { "nl", "fa5f1398ca6b6deabb84c4ce50e67c704f162fada0d69b713a3f0e1e51e6fb66d89b5679d3bb9a663583ab214230674ab29918ae7af2c2a90e0a1cc791b6030d" },
                { "nn-NO", "2abf5136bd5bcd8e5c45e29c6e810f61ebbe4e890ddfb2aedb57c89b0de61124adae17a071109cc3a4988143717542896871242af8cdceba3fb33d85b633083f" },
                { "pa-IN", "9e144f31f30038ea22350de25a59e5113f42a996220f455b84031029833332d4a5d54be86ae2ba4c47e6755af5830e2c0975b646c0151d9b80fd7c94685a6252" },
                { "pl", "e08f9e04d99a0c901ec213917f7e7edc4feb796a1960350f20ec7aa185a9de2b2b72af1e4c0db8a825611f12ca694cefd7927ed502262b87a2da8401dab44547" },
                { "pt-BR", "b855a11b07d59395ff25263471c3aeb363c035d90d503ee3566d3d636f99b170384bc9dd997dcdad11f4d3c1812ce0c6a8699de7b65b2752017dc68d936792c7" },
                { "pt-PT", "6395bd8193db220a7ea16e2db659452cfee767932ffef9acf23c7cd6989b6e55bbd4ab1bbe435786822f48f550bf27e6a87d8aac901954d07a5434681d949459" },
                { "rm", "744c5623d16bc30d033079f4958287bb01e14982d9a93b21c05e6216a5de0e1a9ded6fee8eb5d2a829a9e727cc6601f11378b2341947ca30d90c2d67832b9e00" },
                { "ro", "421d6998bdaf6218a6f9f936a0cfa07c7221aac6c6b734ddf23b0acab58ee7c832a36a54441c3bf4bae5c480817f85d8c34752c54ec972f6ceca81373614a4c7" },
                { "ru", "29a9fecb65af5d709d55b5117f440cae803e9c2c7ac7ae799b0afb715dd7483bb6382fdbe17333360ff7f75c14a009d5eca66e215774751d67d11f4afe900a3b" },
                { "si", "f3db94faf3a76403f3c1e2eb0f658edfd7664609456aa6608d0f9926456e2dbb1d4cd394fef3c4fb24ae720997c5efcc607dfe879596ca0db942fe55c01e0797" },
                { "sk", "44ef00587746ed3184edf61dd6ab27867fcfa432514c11f0b5bdfc06dbff445f32e79c252526e1f5a2743f4d53fb14d67f9b12a78f200c01f56b0cc16341e55e" },
                { "sl", "6e267581a324eda18a1ceeb3adf5f15e3528ac9e8d592929752988b70121736489fe2029aa62075db529b95171316b89a722bac21506d6cbada9d63d9ab36f39" },
                { "sq", "7bf716a9a62f2603cb89c223fdf2f52a6c582e1efc90dbb5397891029df859b6b28dbf390c16463f6ba135a44f14276e4fc4ce7c9740191ed759f90052830b45" },
                { "sr", "ccea57a5cd09f0f20ec396aa15f7e057ef50b928bde98cafd9697ffc07ac56836dbb936a292fb172eaa2f286a539dde7f3e77ed47f8117787b234a6f60a77e4a" },
                { "sv-SE", "d9eb6b189537f277057e5ecd6c4fc41279efd1085701e3d49941962d4a1d455a9772e53b59131afa0ad0ea33fed11339045d7619cd51d88ebd6533355c66ecb4" },
                { "th", "c03b81da5004bf1368f6dd53b73a95a0ca628a70a922ad8bfe30d6dd54e6bbdf93b8c39fafa858df5fbf7ee911c6634a0e7e92a3cec35055d5c587ab9aa1c8ab" },
                { "tr", "2db43c2f05817418661c491a7b00a622a8354f7d8754dc3b14d4c97a4b4d8238f4a1f698e7d3938195937b39c095c8842d984128ae7a825784918e0d9fd66562" },
                { "uk", "778c5f6e854743e6aff403fdc71a3d2dff5da108d24331d54db62c146b914024bd8427deee232d20bcc5e4aec344412266b2b354650b673ee0d9108507bd8774" },
                { "uz", "6f3d8e9abe816c368bb21ba8690f96e23ff6e27c38e4318592a9ed4d4a48dc353ffc79c5e417b781c8277d97d75b50359d315d4f8c607bbe6ed884ab3614a980" },
                { "vi", "4fb7b0e8caa79dd58f8e9833ab0c27522067a354031a33672546373cee3bbfb07c24f2d966d310f662dd5b9f17221dea12cad0a203f079c509d563d984ebc849" },
                { "zh-CN", "c804ecddef24c9725547188070bf6c279e13f26a27449f4e10f61122901d819106e567d0823935b325e536e6535ff5d52f4b199fb219c8092750c7f8563f3765" },
                { "zh-TW", "e0bddfac462847216ee5c94ce857d4b19f74130bb965584b571cd6de2f01fa4dfdceb722ad6fe389250682f868d828854b283507a934c0755d795937124eefff" }
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
            const string version = "78.10.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
        /// <returns>Returns a string containing the checksum, if successfull.
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
            logger.Debug("Searching for newer version of Thunderbird (" + languageCode + ")...");
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
