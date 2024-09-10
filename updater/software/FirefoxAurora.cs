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
        private const string currentVersion = "131.0b4";

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
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2951f78637bc33bdd7b78ae3c6f86ac9c6c00070e2f8232fb9e8d60146fc11a3643dc630e219c4ffcc555568a97ae131bf04bfcf0cac2602733f0c281fb0432d" },
                { "af", "cbed9754b336370dd69886ea4a0c7fed8467d4341d9d15a86c5ba28e308803a61f3b4828b4800b2d3a621f6b7e4f0dca8a4cde4b8b7f80b9252088bc6c07b801" },
                { "an", "7248dd8da834e9c7659060a410ce5eaa68dedbf6f23cd00a1666002f304c2dac9f4ba5cc6d9331547369a4f5c1823482e5e3dc0557caf010715b846ad25cd5ed" },
                { "ar", "56dab0ab3957cf7cdf1c6aa36bd243f9cdb4bb9b43fc1d205e8688c419a3172849d129b9899ba0dc4fc2daef58424da97c42decb81fcd02293eb7a69a11ba32d" },
                { "ast", "6b37fad503fb03a914db3f463b7ea5ebf27c433140810526685208468213b6159d317c50f4205e14c70074cb2f88949452d7146f15d9160bcacd917686f98fc4" },
                { "az", "5e4a28877832c6b358e3b8c2cc0cfe9ea3f23cbed9d0c6fdea3b00ab0deee29677bb4749318c8a8a44797291fbaa6bfb1edc7daf27faeb31996b749b87b4d6aa" },
                { "be", "2cfe069605faafbff9f570ea6684bee5649eb03bd6dcd118207e6fa765007fe7306a5bc7afa748f647687aea3516444d5f928bb44fc19b23215f4887acc64413" },
                { "bg", "700f1b1d7013b8dcdd85d522f79a915340fd80428c3e839b2c70b4132b0fe4cc1a4cd80aaefbef68a4d0f6aa87938156b722b3b92a3fa8e0daedf7874fcbc364" },
                { "bn", "22e1511ffcf4503c9d52d9092f183679981d840a98747caa24bf214e88048451a75c521d2d6b39c8414a0cd4b2d6470672f15b54bded67fa6382bae63a38cc8c" },
                { "br", "f509058006e74ddf0a09d47e9d63bfa408190b8af9b0561eede020e68683bddf2c165860980f73f48d23cb96e8cefe4a26b0749cbedd55e07c6cb2ca26b17cbe" },
                { "bs", "ca6186ba5273ff84ba0524b4d477d21b77564d8747cabd449e077d1c9b0377ebf9475dbb15d05c7f11e3d0c2fa1ac2135a432bb35d6d1a9fd712e8b1b6d143d0" },
                { "ca", "3e7084432bb52bae222d7189a1961bc122c720794e51d4f3878e22ab70b629c1e7234808775625abf9883c9f984070ee73ae60c3a26595cb5fa8c17474d92fd5" },
                { "cak", "ab6c390a6bbd79a95ed7c50c01ebec6d006f4598275f4ddecbef9a0c16ad1132f38105bda873f31ed4ba6481ea929249c860fbab2453e1a41fa2ce8ff9c0b003" },
                { "cs", "42649c3ee8b7703809a22ee811cca05bc3c7c3fc56cb809cef533c66c45726be3d132adec3aedb1aef25b2c584cee909cc13f6cba12343f7a66eac915346eecb" },
                { "cy", "8fcd2d4d54086004980dbdb710278b4008a996b5d4094878662850e54b823b409ab36bcf9818c794a224db4a0bb778666c1363f52ae06e91bf5a729e863ed75f" },
                { "da", "8b84be602f565222d3fda7b2826131ca764e7b813eddbbdc66f0d527233fac0a456416d399bb2b9b92eb3e662bfca844305eb16afaf9137bd88b60e52b2aa881" },
                { "de", "0e697489c793abc08ae75aeb72736d35ad217f32fcbf12dec5ae4d83c584784b76413f68654ca38678a9733aea1a0ceee0df36a4c47383d59c4c13a5a256c84a" },
                { "dsb", "f053c4ff25e3ab9145dfa0d31ba26db9048fd4965e7eb9446bead7a4087927ff725750cda1562317cc6562837695baa9452f2416c65d4ba71dbe59e497d1e40c" },
                { "el", "607505ac4b52deef53ccf8ce64030b755c47290781c21bbeaa2287a45ebf91c7032a4af4bdd6a6afaca0d03bc7b3220e15a03d6106f89c3ec9bca01b7bc29534" },
                { "en-CA", "a0a0a24a92ba499fbcc3d512db9179a22912c2427f770aab127a4a9ec1c01e489fc88f56d2a426adfcfceebe2c577e4433fa71b993acc50b59976a8f6c46fcf0" },
                { "en-GB", "b1d06c6e6d2edf9a457fc6b668a6e1cb2e82dda51251eb95648ca4651b7a54b4f782f99341f76d0fa8f7d9651745daea1b991c73837a5342c16247b6f31d1e94" },
                { "en-US", "b8dc712ccbface19c6e9de7d733dc476bffebf5e4c064919ba4f49d2a5507a2086315c2db8a9b6a9067051f9c2f17ef4fff59b8e8577f280b176f203016d188d" },
                { "eo", "494fb0f90fa62329fad0968203ee616863475589c34de61fae7c08d12c65e92e43acfcec1cde662028b89e6172fe62030c9f455bb59825f6c27da0f7f7d1f953" },
                { "es-AR", "1d313892daa844975b1fb3cf5d3d70a80db9d8e0b266a698fbb51b9ded9e7e128ef06aebd0d66b6e4b888db31991bba996eb65504e9cacea4d7216f3cdf4fed6" },
                { "es-CL", "80e7f18b8f6b3ad1223cad89f362e32567153887904fc07b84a26778f8122815e29e255ee2ba5a5c2ae9df49a6a9f851024a331d73174495d844eb0ba7299e92" },
                { "es-ES", "a4e5ad432487ae37e9992fb70ba488a4dd4ae904d287b8c7a56f626a2a3e33aa9d35fb6217d25ba9cd1b7a8629463f4dcd2a0e3267783335272e91ad30841879" },
                { "es-MX", "a4bc4cc0654d7308b5c90294fa992b32d69dc7fd953f97e2088b224145888e0b10e9786c386c84ec76d5160fd3a3d014c0fd58c07aaca6c3002674a56107bbd5" },
                { "et", "0825167ccedcbfad9fd96186cb74d6de33dcc84e1d76635261e3242305fe8a31523a0d21d2aeebe0e54228b1ab328e0a3fc86859b0daac41d8da34f1707f513d" },
                { "eu", "4eab17dfa693aa7660363ff75ff3995a1b0aeffcd3b3902aa5d810c5e1d086aa89ca920553159088ae8d8491062c2ae69ede555a81b806d1a74b9480ed6a7324" },
                { "fa", "c2a0b9c5ef7d8d0f60a5da034eed1e4c3aa9ac645d2175986e6e19c26559f76d5e7e3ebcb05ff73cb89f5b7aea203eb94f7008dc4b31a31b1e65986f973703a1" },
                { "ff", "d8295f2457f8ebac43758e1d8a96419b9d81adde9e914d9aa829e97b807f955a56e86e38ce46f550864fb33a8828584b2cf6a6fd6d89562d03fb9c624c1bb135" },
                { "fi", "8413927011dc1e70935752cf3d8e09b72ae734515506aac43b653f0d7389dbf5055940d65815d26378d51efc2ed0ebc052b94e8c7afaf15df91dc18481ecaad3" },
                { "fr", "5f6756bd70e58d5578957acbe15fdf795d02d89470da040c6a56a28ba023251cb55886549be08a903d22079bd820bc9c8b108185388042bab8269819915f502c" },
                { "fur", "75e967f1952d3a7bdd9b9880149a9e0faebb643141674500feda58acc5030850332bbc263c2b7c1d8203dfca0fda3d68e3b64f5a71c6836b4d95b3ed12c380f9" },
                { "fy-NL", "88f89b3e85caf75155d69f44afec42167b530b337bd8a5765a9258fe5a060290821ff59fd6ac228b051e8b44ccc2140226e8fcddb9c9d1187705b775a3f77884" },
                { "ga-IE", "fa5ade549ba29712ee23d619de18ce667a77b5f099483b59519cb6d64183989703bd24842b3754ac06752967f8f722a6d0ea9af9fdbc53179b7cc8918ff823ad" },
                { "gd", "eb50dd7a21b1889b7455d262c07596ee313189573a49bcb0ed1a587b08736aa722c65b676993fe99600769d544a68a8ce21336f4ceedc0f157a73d8207476590" },
                { "gl", "0238cea1959bcb00a2672c4146a2cb905cd086a8debbc84c76db8a88688104facb851835b28f01631f263952402b1176fdafdf20e43ad0f16d96f34c83df8c66" },
                { "gn", "290b42c51b9572e70b20e024b4f75879748afa2e3140315cdfeb65db2151ea220d3ad78836d70255a8be34caaa668ea97cff901283b7448edf8549da4255738f" },
                { "gu-IN", "35878cbb589154c0d4edf41a6230962fc67b03d77ff3d1eeb19e88e3549a7a3f491998b6e19f78396730f2ed5628572c7997a4e15eec832261512b63132d2323" },
                { "he", "5c2d4039510d2c89babc2fe90ef38c443e35ce5b583129d8ebf0d9f30c03dff4869aa6b2f397892391c8efd6270daf1fde8ad5bb77c80835f1182b752f637b72" },
                { "hi-IN", "049bfab83048ca34e731913b37b37a1115eb954914ec609a9377e4d51e2fc02724982189be3716d58d5c556e061090fc0dc8f809dd2133bded80a9a45de6ed32" },
                { "hr", "c432fe38712edc14d114ece1a475670e58944c0741b9dfacb88a9a5c2e75564e52182758dc5e00fd26c0fbf1331f2cf6784177e1d5bc1fc749b6de8ae23076e1" },
                { "hsb", "efbd7340b7cb215cbb33bb9f688ca6ee7c71c20451d34cc16d0b8b1293fae509c726da0bc5befa90eed930bc41d020fef0d565898f00ba6b907eb2a23f01883f" },
                { "hu", "f9775a5aa4452a957bb79adbcabeb5b7ac9644dd3732b8c170244dfd746894443d2d08c6f7f7d690503d64b1071dc41c8b08e9e1aa5ecce88ecddb11a7c03a5b" },
                { "hy-AM", "133b097cde10571aa4d65df512dcfdf2bfdc03995b24913cc31afbe0160c31aa09f9b5493f14f00a8f14cadb9549f22f1fd4833b5e334c5ae2adca68a2d02675" },
                { "ia", "a720c21de75b74983e9de6ad653ddfa85b114198e6c0a97f88025e1261bf528c1f0d913c0c0d13ce5e29bcb437257b392f36b2cb90655f299fff16e0ded0b159" },
                { "id", "251c2f7221b4dd79caabf464061f58cfd24fce67bebcb528cda7d4eda78f335de8e240ddf8c3fd60e624b80fd7b7a5787c12543ca72c6db04b195094b4e80f11" },
                { "is", "1178ab64a8385f289bf6118126dc0499f0aa39d92c8b93c0db9b5c8a8c3d58aae297700b346a15e735d6ca3f153394f2aa08deb98b19fbdd60750c7241e1c64e" },
                { "it", "15d6db856cf93cd01d1726c7014bab783af4d27942f230dc7e2ae48237cfe9a1b512654c9405890d915a218fd7ede9df686ef1fdc7e51d4f49405963f459ef7f" },
                { "ja", "755f9744346126247ca0dd3c054d6b561e4e2b9b6f3868ab7196a69668849e5ca0899f5490428b088a1c0b80739bd9fef62673c2cebfed77483f7bc60c6e5e2c" },
                { "ka", "1fe0f9f4e2a71a8b91f8be49fb7029017c6c8607a6fe85890b77e84505bd0b2f2ab8701551283954701c06e205ae0458b6c840c5bab35083e9a8c4b5556e49f0" },
                { "kab", "daef7bfc4624032cffdf6190c7d0c0d3cb1f11a174b6b08e23e57a9448f14b271ad669db36ce017fd91039d58caded1af2370f5ae0cef013ffe260fdacd4779f" },
                { "kk", "c4f08b2d028a2f11c517be1097220b91e154da9e1baa553ba639a46fdb08026959bae08eada687778f35ba51e6821bb872d2a0e56203c14a917b9342ede0017e" },
                { "km", "abd1778a9aa2fcda5efa24ee0727e7a4eb70f7899c2bb8f42d1e7539c7f02e1f7447d75d4be382bf7209020c95ca64bb133b87d97cbfeaedd2148cf620844b3c" },
                { "kn", "b9216a0cf859352985cc233e89b8070eb3841ab2d28b4f73142ae30fefa9529e2a172621470f7119aae02cf1c97016ec694d0b462391b9cad6cd3e15c24dce14" },
                { "ko", "e20e44e6dd769ee1aed54a9e41836a5e3476a51dc9b325824245463a103b6934a92e0cdaa1f5183ba132f04b6d2f1d28791a2a52d9177f22bbd9b0332bc27a88" },
                { "lij", "04c7a83195a899e7698fb409e41d16c6616cb1e8eeda64b1d83fce26db7a04d10d41ab962d5db68fc889086e926e2d76894349109b973ed80c4e02823134f100" },
                { "lt", "0ebadf5a3be734c298495538d61539e91efa023b5856263a491943a5371d06822c9d6dd73f74ba8c3c323fbd4ab43bdf80df6ee737a249b35926c4a2bac456b4" },
                { "lv", "118b409145ff97b104deeb56671d61246d1edfe9f8c2284f67089f3bbfcd5b787cc3e9a70de892db09d38513a97357f8ea094a52d9e23c521e9ba106503d7681" },
                { "mk", "1baf4bc777a65d5084deed1adcf3de63a472e69885cc6c9ab5657bf552ab88ea405bfd4360bed2f8b03896fd5d8b756d33e5511d6237165988b6a9e03be017a8" },
                { "mr", "2cb5d378fb89caa2962bc77fa78dde1aad404a6d786c8b6bf7665916fce2c93957741122deaedc8473b2f488783bbcbf43e3399927e3540e3a4e7c117cb0f468" },
                { "ms", "6e66322e0002eab105fa741123d3988a3e9683d75c039ba776c2dbf26d556d619577b7dc1d307bf08e6deae40f4dde2bda274612f259cd100c0c9d0c69c0a48c" },
                { "my", "0e37e05dfd74f7c8ff11f63490b1f1ad25f5d9d6f42b057f89a2ebf24414ee95f3e788e5a2fd6b941ee9a34dfc0d9209e73dbae87035d7e649719905957fdbb2" },
                { "nb-NO", "96359cad1581c799cd36bd81c04e613439477475099c3bd39232e477914316ddaa3274e345f93818a17d9df717353e6fc9e0ea5cb8f02d4058c6c53a36f45265" },
                { "ne-NP", "0ac964a64d9f9dabd43232588cda9551b77dfeb98a6082ea2798581ce5e8f7e029af8b4aab80a8cd3a0a73f1c29b06678295d63b7789a442ff71c61f426c9207" },
                { "nl", "f447590acc2b826332eca0ef2ab96428b51b3ea7cf978dadbbb65800f36f7f55fda4844a9523ff8f60bc8a89880186eeb598c208f310ac8c07dd783cb9b55069" },
                { "nn-NO", "2a0990ccbe1c061e5e485eb0f0a5c11427a07cc7df9feb3bf2a8b456af1cc1039c42314bbd629e31b1ff12e5e02f00d862bee13d4f176599c25e90ccddf0c1c2" },
                { "oc", "c72fea24185548329a705b7a88fb2dfbd49f8aa1f8050af0ba85ed948bce0a77105e00225c01fb88f150da870921e82cb81beb25c1afff8334392a1cebe32ac6" },
                { "pa-IN", "9133df2963f956b003e49cedec6613a28ff40c22cc56777839da5df6bc815a06ba9a66395345dc9ce0cfcd6456006a11076a84a063ec578728f1db84747bf2ff" },
                { "pl", "57bfd451af49548cdf2c36a3d31a93c874a1647b44eef67c6adf6ba6d17c9681a6ef98644c99cecbe136cdf2f0a9ad5e6362b86438b310bd58178a7d7afe22b7" },
                { "pt-BR", "b516f15d27cfd279581c80a2be22fb01e5e3182c1c1b273a157576b553a62408103171469e5c0b0915967be002ecf9260ec10fb84718d66b9995122acbf5ddc5" },
                { "pt-PT", "0faeda8b969ac5e96d108937fe4bca7241a882f34aab96b079ccb640f5cd58f93a6d407ae60d9bbcfbf42eb85fa67f61d64936fe177d23fd1243510a224ec371" },
                { "rm", "4f6aeddfd368e5cc9fae0e394775dc56229e88d976290ffad298fad4432ac462681328c08c6f61decf40f29ca71fc5d3ec68a1df25e8b9197adbcb2d39c39ca2" },
                { "ro", "13321c9afda945a64b2ef9aeca0df008f94d075c95c9bc301d15dec22c8d834844b3eaa06d3b4fb6fae24e8e7c1b964d638f4c82e14d81e96c39f2d153053ee5" },
                { "ru", "3000e65df9eb3d6046cf80bc0226c25ee69a3a1965395e582def4b1be166f3918ba9671b7d023086311dc3c3133f68def80246c85c513752067e21831348182b" },
                { "sat", "593bcda53937ee13f6e232eb49f78339efc61b906efbf32e3de5129d6f9e6af48a4b6da533355638b75d467765db6f29dac3b55cddca2f186dce60229e34369d" },
                { "sc", "507d2a7e4e0e67351bc713e3ee29f0878d4c4b7115538e385ab3cc08402f4d77ea649763fa0ce93c286be4ca95bfe7ac9190cdc57405d4cc39fe179cb4f6e325" },
                { "sco", "4d35e9f924d4ea85ae1c58919b995a24d52161bc9fcceeec4d057ad8e5296a4d00dd250778b2dc764d8748fc9d213b453ab8cf8f1267ee1a9247a3658acfb899" },
                { "si", "014ee266d065ca89ab54eb8fd4e7a3f01404854a685bfbf38026641359bf18f2a9070b140b8a8004f683ec03b7fc403f79951b85a1682f7b33995f7cc2f1cb40" },
                { "sk", "143a79d681221ab013643009c9eaff9f47799870e131d9beab3cf8b438a9814708d77b849cfac1bc7772f674d98ee20e409d982ee3660a95a46fb7b895fd8b2d" },
                { "skr", "ae66c48a0f5d1447b7c5653129128f23641cc205e0b9d9531d6d4000c13bc9f7b5b967c4d6e8341addaaf55c1f63de2630842edcfff681ae9fd47420780aeb5d" },
                { "sl", "58839d2dcd734a07ad7e6aad6313caec0376c23524089d9a97059417d70a2ec414c67af64433f471210f4648aa2f9cb9f4b7ac54f6ec7ffcadad773d4b5b659e" },
                { "son", "34e74f3ebefef400e7e9c81ebda93826b5542bcc4e13a5ee600b00ebf39ef1ea1a47d887c1c39a5eec4cec765c15f9bff8a3c77ed9a862590ad946cacad72e38" },
                { "sq", "481e3ed5a66a9c6f9c40521ea08c67af77853fb9bb51e0408ab2bb6c60f49e1fc733aeb0d13a000a107e36981c26847f2190a290180f3ded79ac52c60ee40d6f" },
                { "sr", "f71211f6cf5dd66a38a0f521b8fff843f18b51b23804bc3b682fe4aef286912393f0a7f32fc93201534cd36c2eb273c67b3298cc2d2a4f7706bd1408e40c30f1" },
                { "sv-SE", "1ba364450b77a58da737c54e1e73ea1c2ced9be1b6822e761dc56407483794a381777884b8a3a961721e84ea04c8639d1a7bd98ca68734353636b06ee9736b0d" },
                { "szl", "fcd309d795ed8cd22de28d667661f5919a82fa6a169ab44b0c9ad0d4027ccbc53c4c22cb72e0f1cb66f9df2e6d2af98a35e74cbb4ea6196cd58c760ebae4730a" },
                { "ta", "6cb1d9f35c7709b49632cf9bd12d11d828fd5341ddd6d5e81158f655732cc8086b00907ce56285daf4050da55ec876f0969058bb1572d04aca9cea14810ab4c0" },
                { "te", "ff4dc41e8841682aa0b54b986bd2e4eca3adac25e790e425f509843e393c9e7c1262348f653711a6a08418cb91616168bc364b827dd89554428bd81ce2883c2c" },
                { "tg", "8457349022abdc03358162e29b986190208f1056df7957f2d4e6b62d90934e270f8cd612e2b0d1f5a5ef5e812e78cd30993e54aa817c952359070c7ddd503be5" },
                { "th", "ea4b648cea7e0b37628d9d11c75e9e8caa81f26aa9a09f2e0f88c6f4645e98b07b879e821f952236977526a44b9ac6a510a92ca2771952801433c873705ce970" },
                { "tl", "9b4c870fa585317b49e6a664f1f8da2976085ed7fe90197ad1681d7049252c99d8e506d69eed4d63055c3dcaa307150fd5760c84fc32801c96b8c3f2b4c4c5e8" },
                { "tr", "215c63cb3d6a5436068a41489ff4c798ff2437f800e0d60d76bf6137b88b7f17c14bf296c9fab1624feffc545eca14cd8b82b9dab1d8a384d0e2e60fb2c9a22c" },
                { "trs", "aaa8de0d2e3da1006bf129b9b698422afe480ce516a36bce621992079d4f95955beb5c36bc9d556cbff091b5d937d83d0ba10690b101ca82a96e7e40f735684f" },
                { "uk", "1561a7675c327c2387f3e96fa260b8c44ea2189154f428f09b8be577526a7abf5328098593566b511ace01c121d37097713ab64d71cd0b2da2eb16e2e729ff26" },
                { "ur", "c87d8f62f8369beb36ada2acae165bc736ed2a9617c2949a9bdf71ede4586a920332555e04eb75b67a2b43286766c8b3b87c4d8a31b9d2b582f230aa46a44b63" },
                { "uz", "443ae1542f8b632c1f6045ee33c7969073767f48adec40020bcce64e9739784a00c9d0842dd9f256351cb393418301d789da7c4a67169231260e2d2ecf653534" },
                { "vi", "6eca2d99bd12c59a908ea225babf83acdb222fa5d3cfd742d1b356ab861215911de313d5e92a3ff6526beb7c3ff37e3309361c1fdfc87385298e988803d2b157" },
                { "xh", "0e20626098fd75ab2630daa83369f764d614e52213e03572c6ad2c78972519ce6db2cc4949a1368bbbce9d728daf870773a963a28ef798f45c82148feed1b395" },
                { "zh-CN", "322a4f671fd1a6a336a3cd03d129d107f74780d589218b17a1aa4de40e2a8dafcc35084f6de36cd2903b817bf1f772c9c242d1444072015e7bec7cb1cf42a465" },
                { "zh-TW", "3ca8c85298f60a2bcb9696f512c85fa772e443955b7db1e609d2cf1e9617bc6d70f936cdfe6e0ae86b1f4610a9ea1a89de00e963127cd6c7fbd885821366787b" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ee0296ce78341254acd2f8e8503befb0f38a09b111d5f522b2b13df8274bf3af17f1d4419c38cfe7e375acdd2e93a481678761c9592f89578ac59d0859e2ba2d" },
                { "af", "2cc80c6149e3dec47c1062d2c77ab77940fb5ccc6bd694b69388f471006caafbba3746493755679a97d25801549359602ce8bed3effc6698a8607894c58eccc0" },
                { "an", "135a286addea6da185eae851fd1e4cdcc331212258bef695c5cd507f75ca4a543435622f00fd64ebe7bde3c04a9620949db29efe7f786edb041cdf1f1c48bb7d" },
                { "ar", "fa9ffed5c9731dedd847313b9b99cda3ee10df0381de2aae51e292f1dbb1b0a23e79bd0c6df3d65140f98d9da76b3b2a7a3b5757aa4a74ab041b54add56dce17" },
                { "ast", "498b1401e87a739ad8743752701362b5887f68212835f9ff64079da20efc270bdca161fc92a63d887923f7308287ed6c4d6c0f83bfc669a15614e3f5c6231bf3" },
                { "az", "6078b5aacb7b3555d3764d91ff856b09b561b8fc2a9af903096968c41ba31b544c80c4a00ac2bcb6d9895bad9de81b921cde0d98de0088fd4569c9cb5f28b184" },
                { "be", "3c446e98dde77fc52af2b589c0c174e9de47ef3207001dd6f920251f87ae05f09bd02a6d358bcd5fb8b6a7c12e29d86523fd779fdce117790eb8d4cf34645d3a" },
                { "bg", "35655cd20a8ed5bb59b1b2f0dd10a4f1aed9bbea52bbe263c60e91956ff5c17c10b1afbfdeee0522a6bb6d4a7168b846d753a739f3f70244cdad5fb60a9f0b42" },
                { "bn", "6940a26b977c995550b8797e0d6298fc13a92995dd3b1005057878147e15ce38ef31ec32441254075241cf334993e7934f0de093d1f448a6c10e44a7f4a9afba" },
                { "br", "087d9393939b4674092397306b25e7a6d57eaad5228f47f67edeedeb6aadb1a00855cb1763c5f5548f9a5a7a32440e48224cdc3dade45a50f5106a3c7c221530" },
                { "bs", "2d64fc2dde5b848f5fdd273b5a721d4c2fca8630fee1472b3847fdd72915d284a9034e042246cc23efbb0186d6fa313defa6dc5c0d8955fffd3811d82ed784da" },
                { "ca", "50c1e76dbd057804fe1264e9f98973deb44641c231b7d4527b69c3f21381b541efa13bab7785c362749809466dc87fa2bb3634f359ba9db99d122a3f5eb489d3" },
                { "cak", "947dee5a65add0389805e1fc303e7b37ed15e93edb95ce07cdf5fbc3c10ded5d525e93a43e261c5cb66746f928ac4ad51b81944d081447aedc6ffc8feb756323" },
                { "cs", "db39ce36be41848a11af86a26f48371058e7cf064a8afcbf8d70e7bba88c848ebab46c027a522bb55b5d24867ba4450b73898c368aef4d86c600cde473ff8d45" },
                { "cy", "12c4eb5c26682380863f3458190c5d3a9e21c562afafc950a92e6bf3e3050401fb6fb0e71f32a6c538b514fece4f1ee805bd5f9911a0b721272dca275604ea46" },
                { "da", "f0fb50a9229c17a85ec390ab0fd730d585bab3e06c66d50d4ce485efc1ffb2ecdfa75580369d704962a1755267d33ddc215aa1724aa89f9700fc2a375ebb4b5f" },
                { "de", "43071d8df9a72dc2e47b0b2993e17427cd63eecf5707579ea4e4670134f427c199b2e2174730d7ad3c0339b1bd0c954b03837a8691fd0dd9e4fe99adb9c1cd63" },
                { "dsb", "ef99d04467aa09c70617fd9bb36f885b67d57886af8c914db77b56d933b6df92165c7ae9ea72ff3cf044690b0f7df5847da91c214c5a4314da2d26fed4ba388c" },
                { "el", "7bcb8ffee6b20da337b3e0145e51fc79ebfe33dbe960611262096c6ccdd6b916d2ebed52589dc4fbcf0c1f92a784343fdf22f9eabe6ea3b686e01a43e80726f3" },
                { "en-CA", "59e6683d7134f959c46101731ff820e92306418a9d3552ec3e56e918db6dd257605c9961935f228b3f762c62e1b53bac973db0b2968cf27ce49956903fc0bd32" },
                { "en-GB", "eff0bbdd2ec745b60b1c319bcf3778151fecc65d34424c4940de44b3de1d8ac73ca9e3d23104ec1db636a8c3d3878374e9ad2281b3109d4000822c2e4dc28099" },
                { "en-US", "1bb5b0f74921b924a1ef0587467c24b61e4c9c479fd62842decca0b3963e3440d892c5b28c4cc1b13b2b5d26f4ec22860753eff4365186d3b5ea64c54a98c8bb" },
                { "eo", "a51566cbd6d03fcce86d8a882d4369c5d2bcace38b315fecbaddce525e6a0a39399bb1c298e3040fe6b0442504487947187310ae23b91f3418855caf6b5b42d9" },
                { "es-AR", "3cdd01229409f8d19ef64e2c64339e7a617cc773feccf52c1d23a6793c733d4a7081a9d1b775e9b3e35293f94cd1ed213b1e586201039b026c3419b4c06f1d81" },
                { "es-CL", "7edb5fed6143fc5b0d9a2fa4ecada8ad4f324977aee902fed3b00f49c44ec8a059d5d1682ebb5d8590329ee24a8fb4688edd74281e081874897d7928f70f6fcb" },
                { "es-ES", "36069baa27d968d11a871ce2c63337d3c6b06551947d2ba89b77e34b7903066674439d1b495811ec4fe03a4d63e54476b293610c5ffa6f9f278a6c9ed2949656" },
                { "es-MX", "532d9795f9779d50db66823e7aa0475bc27f68bbb30d8f20049a8d2f01b04ef0f6d7f3536f00014c825da750ee90e5352640bc01b24eb9c4a5e7dbb30b7289d3" },
                { "et", "11ddfd8a2ceb45591ab48b6920e35236fb109cc52868c6143e2a4d8f9cd3ed6672ee22b2a4cda70e478e127cc55e198395146a98ad5fa8b76a236949f47b4da4" },
                { "eu", "6b7adfd0aec6142262621b9613d55019b853d2473b3dee5ed6bb24a078db35c69818f2252d1e723655e72ca204b3372c90188d1c51306cd4bf9367cd3764f86f" },
                { "fa", "0134a0da61f71db253631aaabc158470a41951252882299fec946e2715104e7e8857f3338d6e218a9f975e87dd64cbc7616dd34f35dbe9755424dfaa7388a47f" },
                { "ff", "5c3480e1313f125fd9a2ad52c272dd96d2e4e79d76c8970595d9c27fe47944816e524c27a263b9964f4a0e9d34f57c23a00369be509aec6b5c76087cd1725428" },
                { "fi", "989ea5c76137696169b9847c44b197a3e9175eafff6d8581f0d5843c7cebb027092bda24814512dbf3dd4d419995b846789bd8903882a0797588ec380e49103f" },
                { "fr", "2d1488b4036819d748c4735612bdb33c3181eeeb3728d6088ef57289a5cdd90bc64b9d30d736493f448fa3259fb664ced40fb2b12d69706035812dbb6dfdeb34" },
                { "fur", "1c1d6506c7dea98b26df48aa5fbfe7cd2d979a922f87bd76c487c73fa13bec5851fb809b165da9e95f785ed2a04c9c0f19ceffa21922ff274e882e6540d7d75c" },
                { "fy-NL", "b368247be223f3bef63772b4bcd7383ab59704c9e27f22509e758d1f6a20299c099fb941d53d32dbf854c7a0e091ed775eb54adfacfc06082121e653500bcae2" },
                { "ga-IE", "4c3d55a560fddebe5f59b496f031e970ab9ad1563b403114c357bc6a1d47a294eeb42e133bad88461abd3dc97f9d821455343f0e3384ea6ac58a058205bad932" },
                { "gd", "13d51c1f1111acd6359f919e7dd3963eeb1f38af3ac66c3098ad3970b4ab779acaa2a5ddeeb3d45f403013a1ef1c4238dbbb4892ba2cdbce7e327e847b724ec7" },
                { "gl", "60885d924c535499d79a9ee8da0a90839453037896c37999582f1f5988bdd86693f167ec9afcbf61784e4d34884ca4d6ca2e4129cd0771950f2d61edf1ec53d1" },
                { "gn", "ab295d080bf7fa3f3759b2cab7b811e6bf36da5131c650bbb873920c784d2fdb35b81f07a2bffc7bd6a1566e65fe3a5f9fe2540e7123ecb820981530bf76407d" },
                { "gu-IN", "0ab9462d327c3e917c414c266e0c7b526c197d8dcdd712066bdbbe275e61904f26feda721bfa4fcb3295234714243c3afcbd4249bd1ff022ff06dec1dd1498e6" },
                { "he", "68f304d5e24d6c29b44244477efd529a2243ab392a1f1dbe7d31613c35fb53016c9d4bb1f64811820e36c8df2f3d8436ed22f16dbbe7d389d811e049ee07f63b" },
                { "hi-IN", "31251aa184eb26bfce2d2f53218b19142f5185d83a30fd354bc71dc86ff1886387f8de05a659a0eb14d2f6fc8b555943635e260046c83bb8f3c97719159f9740" },
                { "hr", "5736ec6072f669f9add0ea1f68f1b25cd230676230e3adcecb332a5cd0e69e2b72c70ceadec752969e44286f05ba5cc022c61f095f4e47d6a6b5855615bcc03d" },
                { "hsb", "a6e09c6c67efa34c97e70ed6151b997cf2ad3986217ac9d36241997bdcb0b481389f2b66ee99b9efb7bd69a15892c62c0235d165576f8a169eef1d15e75c4c2e" },
                { "hu", "f107ed95ebd327a78dfb93617bf78e1a362fb2e83e1a7497857b6e4c3026659b8904105822748f9b86572c5f2566842e86357e506933bddb1c4a549a5e8ef2e1" },
                { "hy-AM", "08f87738ee1384056e587a5fc740d3bccf8e051f46d4ea17f351911bfe1e04556305c4ce2a5e3ae727eac644b01f5e6eadf96186600deb9acbdf39318e98f389" },
                { "ia", "81cc7feeae5984b9c2a59e6ebd71f360d8f8e42768a9597a6b4971bc2092bd2bb61d75cfe39b7a3a3d21b0681a40214457fda59c31531e7aa3d7e62e854aa18c" },
                { "id", "058797965bca2c7756d22aaf0666e3a7cdc43e0134a9edf700d5220c0555e76c2845f1a2e0c31296196ef0f713202aeb0d08b89d4aceca18a89cffdd6aec821c" },
                { "is", "882781692c332fbe2799470f070ff8b5786f7064974b302aa43f18152877df1278514c41338f97ba5f669c2f4e4a8631ea9463269fc15f867e69fafabf58698e" },
                { "it", "82f62b15c22a53f3fd179764425df2892f1f55dfc597827050b3d15d9b49af43d467364e0f25706554d6382d2fd1069cf90a31b7c46b29cae6979d1d6e607858" },
                { "ja", "ad6d3891dd309e040a65dc579ae500bd94fc4503606e864dae6273fef34f87bb0e9a1ede5baac8921599d1b19d854945d6c89525cbab4192dd7bcf54db63cabd" },
                { "ka", "dd513b28a56839c3fcf6134e8789a169333ccc74501ffd486495f222b9f7d3c0a30dd4e4065e7715d73c54c1f2648cdd5e6a1c5c0cf51d7f60cc8f3c1c8e821b" },
                { "kab", "d2047e6708b6a8823bed49acc35f4677a219b7664dabe779f7cf0d30cf2e65039692f9f798a21e2ff391d35fcc03e47b0288720075b178466909bb23948c7831" },
                { "kk", "f8127a9f4c321b91b81e94d68716685ef2567f36b1d446da51b282b031ee44c7185d22b46d06d8ca6d56aa9e68aeafd8f4a1057cda7950952a3989576e2518df" },
                { "km", "28c78e9a799579aae6bde4a731fbf38bb254571f7a00245bebb20d9a6c7edf54fa319abcd940cd41bdc15990fdf8e2c7f758943e6e16230414e7e60191379be7" },
                { "kn", "ccc983b5d56ec757624efc6b6807b4e32e3fb0c30d00a66340d0555e1e1ce4655c7b130d8d7c2ecfce5f48b05a36c702434183ea847a14e74b5ac3ee3090af6d" },
                { "ko", "a4ebb97ad045594f921ff714580ec11a661673815cff4aaa9cfdeea5dac90cae957f9e855fcf9b371427545743e1ade5da2abdf4775c159a60112f3cae7b23ed" },
                { "lij", "c61a871d50b20edeb19fe21380538d166f9f7e33e2a16718ad99b527914aa1642644b9b27aeb04de3f0deec652a379d869bc8e4d7bc02be55961016fdca7eee9" },
                { "lt", "64d128d6e5d9690f8e22eaa2c4dd7f2ae0ceb63b1a39d2f40f67acb35310eb2c38d670ceb77930cb2742f5e5f5571799a977984b24762ccfd49218e75ac52690" },
                { "lv", "24f8246aac6069c39a43dc60b29c33e98f6f11edcf6b767c88a85dd4776164c096f9d770615ddaab5974a1ee2ddb5a89ee7fc036e2328b6b22015e7154e2a2a1" },
                { "mk", "a6b01549c715fb52143b6eadcc0a989ffc139411703593c14ece69c8566e00dab3dbde0667023ec85eb7550d0a1c94afeba81a9b022b550297d8bd4627c02e5e" },
                { "mr", "ccbfb716b82e443c914cf727bd4336d337f56b7345b457db20d47a2351f5fd989b8d086ad96bcd6096276020df76a128c0e4fdd31c4df32486ae0d2bd9c3dcf1" },
                { "ms", "e1eda1b4896178e0b870f1aabf642c4b12648c3b287ebfecc4cc91d85ea48738ac6da6357731e2d642ec99fa7f8c56b99dc8af2fa3fa349db6dbdbe1099e3118" },
                { "my", "44bcf5430d01ea85710ff46726369fab04f522632169cb149a5a9ac7659395d2486105994c7e66e3e78836fdf5c2fbedf51e97d74e58fb4e2eda7c0f12ecaa10" },
                { "nb-NO", "5d39e930e1e580ead7c110d1a2343827f585d190f1e46531feb02e094497dcc36c32d3c3b16c9b40bfbd1a9c446d92a8a012885d09e359cc763d0d9c23eccbe6" },
                { "ne-NP", "6dd92cfa3c434c75e9292e926103c9589159c450153cc20dd1458137c799870ea775b41eb1dab3fb577aa64809a51f5dca2475363616f5b409612e2babc706a8" },
                { "nl", "69761fa8801967f8bca3d85436fd2c87b5addfe21cb32b6b6439ea3a045565339f168f58ddd0e231e33f5ca22120706fec4455c9f53d2e50b6a748d1b0bf63a0" },
                { "nn-NO", "d39c5270d771a2efa0f78e86727a5670d5e1bd39733410600c5b01d585bb9cde1fdd93d3c1b692e565daff4546f2411e97772adf535d4479884688853b05c73d" },
                { "oc", "4cd1cad8e6dfcec973b13930cfc4a944359b13664f6e427a11a8e637811e4dbffbefc2b895b12ed313a29b0894a1a6de27995110fee38170590b0318dc87dfff" },
                { "pa-IN", "d4a682bf540ebedc39e5523632c8903bf5d57ee7c036702b93570f121dcbcc2c18ea7e4edba8e7582970134b78fc04ec04d8da22432fea1cbec9c8c787228709" },
                { "pl", "66962f2a4e78bc1e2d5347ffdfc062d39fbfd07ea4045866da66ddcbe5936ce898cad789b56ec69ce6acc184d8dfb82c57df241dc06c131231a6a74310f3d22f" },
                { "pt-BR", "160e673cc9427629a7663912923c5fb9bc59552dd66ac9d4e4da89f927dc6662efe5009bebc47b7ff8b658d0d9847a7e69fec21878d4b4437c92411856c2cb5d" },
                { "pt-PT", "cd03e6086afa65291626e4bf83dc4526a33ffce1fcbbeaeebda79ca757d0a643388581c5d02401bb761a98d9c37ce49c0090c7e08c093a5aadc2b6b4a687ead3" },
                { "rm", "3b428ab6587d990afb6ad7807cc551b36f95276ad3d9ac6e16b50f039ab139c3fd0e68aaa2adb5655b4b21b6d3ccdad5f9ce219e77e3b7db81d32d02d82f8549" },
                { "ro", "87137320dd4e2793e0fc3ed5b33a9d890157713761a82ceefbb44a2d61d0dcfbb52936c8b3b4bbc662d8eb21a1d8c1dccc935f90fc09ab97e589b90670901cde" },
                { "ru", "1992563573e030f59e1fbdfd979f7a737f85d34e884be83d32add4ff1cafeac697a9d2965f0db0b7fc6cff5797ba96d04684632a2caf4a7bb683d0130469d2d9" },
                { "sat", "98c171bc0115192eabb0358496efb028a058b206683d1ebbc8eba8187c9a81c32018ddeb843997e555ed66510610874933b1017cb2bd743e06d39d1fc11a6c53" },
                { "sc", "47a28833419fc1cda1769a38958a3f70d2c7025009d2f8f2969bbe0a2a06b9de19e82982d9a4b35fb48b0cdd75f1d44356c6e43288f169b225c85d29b691169f" },
                { "sco", "047a9824fa2406bce8b5b44d41b3bd913ee147ec8483cd454a707294089b14e6556f9c8df566ca61e17c0a332bf7ef344877c885699743a12d9a1b0b26e1e8a9" },
                { "si", "5757a643b1f6319562e37329590afa88fdcfa688c4626cdc278e1b60c795343dcf8144039ff6ac7d91aae1abd1969af65121fd5e0b72f7fe9cfae7a3be3122f4" },
                { "sk", "086ff11b059729cdebfaa215b190afa106eafcf508b2c83f943167d55cfde9d25b6bdf2c56e9fc39b142ef1c5cadc6c4d64aa0a4c0536b74fd50836efb8e072b" },
                { "skr", "ad98417551c4d15b6a23e1f7d2d87a444c1569fe20fb8873d60e18a80cc0338d5947c8f551994b3e3cc1b80d16447cd72613cefd6ed642caf17d724a241504e0" },
                { "sl", "fec9a1ab21ccedf0179d93f9fe4509f5aa5d45ad68f065b1d2c773fe1c733fc3dea9fcffd78b679da91ca073a3905d34105cf322b43bfa180444decf28a89d7d" },
                { "son", "cd1979f1b2f53becc867f05438db5792b83ac1dfc2dcaeb2c013fcb64a1c83b7661f46f49528d4ffc0e900863f1ccc54f4e3a35490a618c6496be80e8fc97b2e" },
                { "sq", "cc2c8889f9d0d66446f6dcb277d9a1d73a8f6a409af6fa8d02267077b9b2bc78c3128445f19084103d9f6bd1a88a96a8067bfba38df3c386a8bd85688eab4899" },
                { "sr", "859160be2db4f5586a3bf161784308cce083640041aeb2af1f44bface1e22237baf9b0a406bdd320b8e4ca6e8c6108fd73bb42ee37611190990a3fee3cabc457" },
                { "sv-SE", "a83ea492b8571a268c7d9977e155bedea8be592a24aa3cd7991ab0e1a9636939f64540816d9b399a6487cb692f0cf865666c27cc99ce008aee92d8298f28fb9a" },
                { "szl", "d8da3947fb21ed1acd8b4029b3c7f4c94b9f302850ca9952dde4023173eacdacb15692fde630433c4d563fa050704c3d242eb20f859c5cc6a38f76b6bb1e89a3" },
                { "ta", "72833356deda7cb7d2553a0653497b350f54c89a25ac391090d97e07867ed8b0d0092aac6e30f2bfbc161143a4540644b760bcd309b392e59054ffb27111c0f4" },
                { "te", "37be606c9e9ad1743a45614be76886c1caa1b09f0f462b62d4817d8d167bcd9cbbe258be58778835e710d24da649877d0c61d82b4301992dd39f3d7e88fa837d" },
                { "tg", "5956a542d8ac514c9c57159a7df48ae11cb0e105f02a1fbd55a018ec6f8f16c13b48ef23b7bf59ccf16ebd9b4ffc10909c8483b3e6c0a8984a370e3df730d7af" },
                { "th", "929505ab4d6ea6a3fbf9fb81169c23f68184468625573358261f8a73df387776c873020c8f988ad9f209af9858fda3e4bd9c3638a4cf44c6aa8e4d3a3a30506a" },
                { "tl", "6a1b5955d4c5ebbd749f89182fb8874971593937f5f8f3874367765e1c8b389e2bcc167c49189e62301f428488a78d382fc90dda7af17167c6717723040d6307" },
                { "tr", "e7d45b999afd5095964c05807ed32a3492b6e68a3f62eee4b4e862a7adcf9f54b62b97e972b27542e1debc05c424da167ead372801c2535ffc903c38175a395c" },
                { "trs", "bde6b8be11ee02c20bbc070fa2e9a2a220661d791687d5245c0a64c28d6907405a168748f6d19f62c4144e18d0dca82c17d07a095d3856967d25c598256854c8" },
                { "uk", "536bcc867fd9918c8d85c551dcdc3f391254eb99246fa16db3ed78ded290f39c1aa6c8137e6328ff83e5a2d48253009b4b44da8588c4ac8a181eb73355665244" },
                { "ur", "3bda0b293b17c49cf29fa95b7af8eac8c66a7b08baeb36f84d828ded63a7ebbb8aaaf09446195154206d8c1a3a11828be7130ccd58bdcd4e11bee40976ef882f" },
                { "uz", "e50c27bd98da0812ca59787352495498edc8926928414946f95784a629aeb7e2b5fdd202955150e3c426a5253fac75d3a98b11b70ab16e98d637f7bfb888240b" },
                { "vi", "9767bce28565848b0c23cec0d03cf857350f59c78ccf2ce4cb810f22e2da88482f60caeff91f351a457dc088261e5ab4d494d67eefd70f891cbda64face26912" },
                { "xh", "fec6ef4088ac8a8d32d9a426027deca2e62a7c5e623901e76d0987d7dd2e500b4a12374ac0947d90d2ed577472a63ca7e7db9969edfe3cf5783bdcf45349d40b" },
                { "zh-CN", "499cbd2ad0f5c62bbb8a27dd3c3c2611f926171137c43933ef0019db54c71f5abf0de6b3491319864213a01689d2002d4b2aa5733c2c0d589c0ec4ebedc80c88" },
                { "zh-TW", "48ea36a0e365a98224b8375ed54e9a84e1f3ea3d603e2c8744a9dfb90347d119d23abe310309187824dbe0dd7cd632a32a2c223e2a56dc491f66a4601369ff53" }
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
