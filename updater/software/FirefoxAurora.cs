/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "114.0b1";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/114.0b1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "f9c123a9c4f77c1f142aa861cf56b68c3577e6bd38eee0bb08753e3f5323ee12eb985b077b39b10535eed0ca9b2eb753b09604f45e936a8c5f99e5f182decd39" },
                { "af", "ff7fea0da50e67a6c0036e8a62fc2b2c1b72167a32777acf924ef16149347b6325fe5c537df5c48640fcd3182e185ac11d4244b7547e88821025223d72e8b340" },
                { "an", "e764ba1356cf450ab521aac37aeab11dc4f764aa5c42230d2932cf005e1c2cea8ea773bf9169eb0190930b2b74eccf13d9426e344a99525da76e3168cea94f69" },
                { "ar", "9fc6ebdbe0df3269f75e92b0fd70e273bbb6cecbc619ffcc92cc39009d90e9fcded87d95cc084c80dc4e918770ebdf11b6e846a589cae24c65236b6a7d109d7b" },
                { "ast", "4f27ac5711b1404d5823d6cedab9613b4bcdbbc2255fa2509aaab6adb55deb472ed02522ae3036d712b7e4d40e4cdd25f34095a8a2adbf88ebe2249a0c14e7ef" },
                { "az", "6bacefae4c5e990ddf28df1221eb8e37dbdb31fa7f99bb73ba56c1c3baeef03ba3aa03a2847b626609fb739b7efa5f2bbb46ddf24f8eb1c85442ddc16ed3e27e" },
                { "be", "5c34c2df885ea569acb48816fec6f4331f2e5b66d9a5d033fcdf0804131bd3dc806771463e153c627de8b9294e2a90a4b3ea8a3d963dc56d872c5af55f19430d" },
                { "bg", "b3b6226f3a3b107025ec1c9c2b14285ef1ff5985b6216a3cdc523f9e0aa9b6b0ea1be28900227c171504674e9a070ed400e0e0720ae725c0d0f1e147f2db72e7" },
                { "bn", "7d7f63d9f75c86cd7c645df6ff0a185acb4ee022ca3ccf5f0283fdcb27aa06dc3aca9c2f49a15759143057b3e8accf8dd394fe5129cb06ff69d91e54d033cc80" },
                { "br", "dd7c5396bf049797f1ae124d4f616ba8757de6f807e197202a04fa0ebcde32330b3a93eb4d0f47d2777e81b1e1b641ed6ad7ce446f94b8c522ac5ad674d5d4d2" },
                { "bs", "e2d5db086dc5a3c49a5fb0a36db5d07fcda5600943103b58adcc26d17d967b550a171273288f436e0b9ff14b10ac525c8482d21b677acbc7181813b9fd5e7543" },
                { "ca", "d4689eeb54e4570b6c4a9921556237dbc9990c24b7c909dd27dbc8861ef44ca5558421d82495a84f52247ef5f2fc3bd560ef4eebd40fbf29c8b9b3de1ce9bbd3" },
                { "cak", "ec6513d27ec1a42e90db36e10cb3ab8fed342f82defe05f3d42199203ac46daef316266c52a176956b3f775489bb62e42e5753b25dc26bdb8cd78eb4d7db5f4b" },
                { "cs", "112c524d08aa56d2a780265a7eae2acd8f8bbf564eaa634a7fe1b2cd5525d633c25e716301b30ed9547292ea8bf8152c1bd7f2d678e0ae7c1afbb9b2fcaa5be7" },
                { "cy", "466daecb55016eaea388acf711bc09580138b16315b33fb232366fcd9da75ca035ce292eccaf388a93f64fe4e1ca0902b6763ac3fe2a427c0c6d38bc95847b94" },
                { "da", "652b80ddf325afd257191b5fefb2a424a973af160ae1006dbb709c4341ab62ecbb977544d8864647851b66cf5d8dec6921dd58a6ad6698e957cf600bff97a970" },
                { "de", "e1784e004d551bc76b57d9fad56b299b55b13fb6fea68d646b6351603232e7ccf47b241a525439a8df66a8ea8677459a71f5eb3ca7f42515bce142a0df7372a8" },
                { "dsb", "5aa2be1e0e328494eb23da73029e8e66d5436210f1ce517554ab36adb8ca22094d0e4e603d24ec6ab51cc6536bd67b1bc3d6adae7a881b6494af2726178b31d9" },
                { "el", "c50cfce9909d51c46be3e22894969975788ec1b24af5e201b02fc07c38133f6d9c2820a5f38a95ac1a8671bafe89f62fe5a4ad39b5af6e443a4253e91df2ee8c" },
                { "en-CA", "f55eabbb0f09eea7cc233c584ea13c58a3c58a9c8aac167c87d8c774f496f91d715ce9cfc9bbda6ce69ec2cf8e8b5828fca322bf7f872c287bbafe6eb4239029" },
                { "en-GB", "092af88b2d4ed9451c734ca50d694a7a0b741e4f4a34501d98e9193692fd5ac135d1c51146d66f38a440f2c505514f05c640e5526b862d0de202f37eecb0b000" },
                { "en-US", "6a0cf2a26fce1440ec3da213e501cd9f6c43ab63f7e2c4f8f9ce437102f772a607cdf5380b778b0dd5255efe5a3cba82bb01d81070b2be3d0567f3da7d7dcd7f" },
                { "eo", "b6a037da67064d9b891b9d44724573ff537d8deff9bd45e6db440cc60c2a0d13a2986e5c9faab4c5c6d35b4d83f85fb60fc813d7abcad997373c01d73bbe1a29" },
                { "es-AR", "3c26f8feb3e2078a880a619eaaeba55f7afb9a31f3cab1bae4826276800703d6f679d6a88e681807c5f2fa4cfb57daf313a0f51410c290c537253465e1600613" },
                { "es-CL", "2ee2a2904412d2b51ba96438289180f05cd5eb64d830e340dbe361178d7bd802df4543d937703aac576ca2ff235189e8f6f8f64c6d613a96c7ce6bfacf488b17" },
                { "es-ES", "cba03ea609f7751d60d0c58235a5b2394ef3f99af4d3db1ac6b7905f3fc744131558f57dde94956688439e4f2258ade0c1be2899c7bd3a9f84a2902081ce0e37" },
                { "es-MX", "2b9f80e1b3cbad81dd969bdd878b3adfebb22c8c47a39926f7f4e265467792e4e1efb647e0576bf82c3da85fe20d982ec981b39b1f44774aac65a3dee17998a5" },
                { "et", "2ed9b48a030b2ff97f53ee46b1502c7242f1951e20efcec8e428bae85d268a7e2ca2e4cd81464c386191a7bd3b0f69efda127978b5336a85c142f209c86cc1cc" },
                { "eu", "bbb3ae22e0888965c3e5b52a2c575e86815723da696bf0464437114a2922f82fef5471b4bf8b322966a3619cff797917e03363fdf0cc837e78eaf69183351e56" },
                { "fa", "e73d2cdc10bf4f93db9aeb1367178dfdd61ceccaf5fb1fdaf9c4bca7bce4dced55b8c3f847f482c98cd3089ce47f55463ac92ba26afbd061e1692f570320e6ef" },
                { "ff", "fff464bf59666789233961c6391de4b8a7d08cdf8969d714a897d871f02fcac74e3022f8723bb3a4638c5caf20bb13114dfd3e10fe68eca7b478d39e14d13054" },
                { "fi", "3cb04bb68827ab25c2c70ff42a719a57c8a5f4e8d2ad9d52c2aca3435d3022c7cc159badf94b9a02ecba3498e0f0c64a4816cb2f7c410a09d5a34a3919c922b8" },
                { "fr", "2017efa99e3e29235a6de0ea3dd77deb87abe08574c5bd514369d573748c276115cf608424716017d71ec3c3ed2686d59294456f66e5aecb5bf90c2802f076c9" },
                { "fur", "ce2214d9c60eaffb717b6713c69b023a1bed7508210717bf74b52463988e072ea73b3cf717c92e61477c4c78be421d6dba91139714bbd6820a587cb2dee90550" },
                { "fy-NL", "60f40e75c39bb504afcf31a71714214540f380a4e9d818944147678ef57d28b8bfcf9f75fd2dc9b4750a5c6cc4a0054e24e2c0a808e214fc49168ee5ccf2f919" },
                { "ga-IE", "16baab281da32860665d1bd468d8af159e9da58f9d4ff4181ff5fa29c262fa5e1b35fdd0af238e6fa8929195d1e63f3ed3803c3ae803216629328380fbd25962" },
                { "gd", "eb2e73a524cbb00c8d6230e0bd2fd578c7e867b122e5bdc9569c797de0800d7bff4539a0be1c7a6b89571cc99dc2c374404802badbb9babc70c3e45b29eb9df6" },
                { "gl", "033e731e79c265a5b136f5beca4b35f1d24c0fcaf7be225d3093f9f821cbba65db09a63a92011ed51a5e33b9d4d4c6b6abf8c639bc733b92ddd06d37b1154b18" },
                { "gn", "b84f3c7ff106307d0ab3aa993b109fbc9ce87d2549c1e0734326f56ebd1e655d8950a24d187e97fdef1fedfa39a5647f5e4a8148bf91a133f73884a4b6656739" },
                { "gu-IN", "525e568019717cd3633adfbe2336791f7272f33b3ef1891395798cb4c49a17af94899e0eb6ad7757aac78b170671ea954c9a7a01cf0950becb30f51921011e65" },
                { "he", "e64337b688e2ea13d2dadf861db8ecd99b682c2a404f314f093894256b6856d591e84f374bf7b9fbf0316f40c6c5719660ba4ecdc94cedc0c19a2a96276809ff" },
                { "hi-IN", "5d142b0644e9e04a3e3123e53ffc31bdfdd61c9c6a052ebeb1b566b26f790f1ea9ec39894d5cefc6812467c992314e129e3ccd082f1b8e3168a2805f61084b6b" },
                { "hr", "210545164a6292bf5e0288c55a052da3b60b284ec57aaface6b7f78fc2196be84f5ba7a7efc3173829db46e8914ba2c338ca3c6e72bd98421901d7509e9cf847" },
                { "hsb", "f9199741c94aa0f84e5595d356346fdfca2bb02cc2ad3a2d9ba2b09d7eff5365940892d45aabe82e8e524ae1ee335cdf9e0ac0638bf13cd4d7e16d6e8753c244" },
                { "hu", "f360005eb91621e3edc2c401f9a015b36769411396b9412af2042af61ca5bef65c60a145439a33de803a1f1db48482e66365509a1ce1c07633836e77a65698c6" },
                { "hy-AM", "b46eeb55c95b73fb3807c64b618c2662df9fd11888472ffc585053c2ecbeb8380e2848b8e3e56e4c63be1267bd12e4c4ed82441212c6b708a3ed87273556bac7" },
                { "ia", "8391d87a3b2acd37729d056650db7bff941d84b31d86414c1a1b39134f9ef0dbe31eade62c0ff931ab64b45ecf383d9c9e44fa1a15eba9900a4bb117afa30f38" },
                { "id", "9d30769809a1e9ef90f24173fc7e9e9c8a8efd95bde6905198d0d083a197149cc53797f89121bcd5cddb482d0a7d5a057c4f407566a0a2eedb9fce0438bc6336" },
                { "is", "395d584555f399045e824e4a9dd9b216df54fbbb139a76c62c93de15fcbbca9c8ecce123ce4d29e5e49d0bdbb44adc2a84dbf6f5bb6ac3531707551279ea0a81" },
                { "it", "f3829ce30c63337bde9cd9073fdac3357a2b2bf448001018ad9910ca8d10e92fef1566e91d2d087c17a1a6aa1c39329abb38fb84d29ec818fc2723a07747c442" },
                { "ja", "2d595f5838378d8372a7a9257139486844b46b35f86b749bd58852392e22358b8b9553f0782b6fac93f2295fbedaa0815f7549d55313d0c3edea2e2a892cacfa" },
                { "ka", "67bad90409926639ed58467d29a9dc22129e0a2f640fb427a0154f51d49d17ee974ae33e026b600dfc73c94adea7a628a3490bbc5a92fedf78169a2c2c5875a1" },
                { "kab", "96e91c215178cbbc85f3edbaaea8b9ded3068220101115ea717ea3369404073d8b85269f5acdddce172f8c26b009516ae6f51a6536c5ce8be33ce37d015e1dc6" },
                { "kk", "83f742ca39cf40e75a29684d99cf6f3a10d80c64a3bdd21caaf648f367ef2d995fec9a5a27f6d47b19fe1335431082d7c8ec882c3d310a6fbaa22071ee102f8d" },
                { "km", "2e265b19f5e940cbdeed19af689b9cc0d652597db182c6a954d1a7d9402f87114321c3dd352716691a03694e243cca461ea9b2696d008fdf85cc860c04c18b5f" },
                { "kn", "35b7a6c21f14e9edd335d60f7c8824e0463984e29be594433741c76c53acf0d22f675ca69d3d81084489ff2e22e153d79deaadc90f248eeade820b70925fe8b5" },
                { "ko", "c2fd375fdba6e09fb1a1c9405818b53c5ba88ba3edf897453632bff966c8db8b24c7622f99b1f9c375f80dc2139e17e5df8cd1a446a63850aebac5da8db86dc6" },
                { "lij", "acee92e2245120243779e4716b77b8c92de73f63c6922e6e7bb431590fcfdb50a1fb9cadf379921f8e097b8f9471e7ce4fa3e1558bef633e44513a9714205e43" },
                { "lt", "d5bd52a97b02d2a78208ea27467d93a6c5a05b8f6704464f2b0d90d379c18733bea5bdf22b2ad93a6e8d6da930d51e44013c18fdbab74fcd064a0cd56accbc3b" },
                { "lv", "83fa588ec50838bfa81907b88d58f12c60129b8e978f4e2c8db87d071aa906358a7c956a706c7eff44eccb4a0e021605eb95edf8e142dcee5e19847e46f7ffd9" },
                { "mk", "5eb6e1b824bb7fec98cb409afbc9b8b220376eeaf96fde6f3d6cc994176b83e9f8c3431030e4c45034d3b3710eb045ec2b9e317aac7fdb7a9362b47a3c422991" },
                { "mr", "5c4fb99c72d5fb985a4cd39924377869b22712caae03ebb5bf47ae8f4933e9674cfeacb77825ebc8f627a43625825877af7433a41f69427d5cd8b38c0aff0629" },
                { "ms", "adc0bb3dcc10c55dcc72e3bcc88d4fa31be898972c605ca61fab963cb40d0f8cf21a890fa39d55b2cd783c44491053b5805928228f95d5aff1c45ee226e96b0e" },
                { "my", "67fae817d65b84f8d64743cd3f099e1e1e4ca5e56f3338aa166c8df4bf97e64f937627c846153dcc5191621c13f1c514fbfbe0b09e51ca56c7c66125e6c7e74a" },
                { "nb-NO", "d21172853366b469b7a6e91da8ee7795f109f2857edd198ad60eba41de3341a65dcf1ca74ee01b083a18041edae554e15fcd2a11cdfd7785da71ee1a8a7c5e18" },
                { "ne-NP", "1e6a7f05e6041b39247853349bfd5cc670b01502cfa8536e924f211ee2ae3f012a635ef3cf43cab180f39b1ebbd470ed87008a060b9543743b0921b4f56eaaef" },
                { "nl", "58535c63886bb6bce6d4cf71dda0b2171dfecfc00e6d9d5959a46b1bc739b503468a0d78d4adee4b86941f656c2fd219ae67837b700c1c5a5730d68e24060cce" },
                { "nn-NO", "1890ce8541023a8803c78f2cf7f59c49ff358e2d813d6768b50fda2b0ec90ced6eb18b66b10c97cb0ff02b979e7bd8b5588054574fff4c843f24ba36fec251af" },
                { "oc", "c9aabe2ceb6685e3dab323730a523d532ed1aa545303fb7187f87f8b32f91e5d24853def8debe6f0bdda45ee4bae0115fb3c2751cbd63ab0eda83bfb6c8464f7" },
                { "pa-IN", "168ae4edfe4812a38046f90ccfa1b132329bcadf62c00ac9b37431cd9a6433f989aceb120b09394ec7b887c891fb61736e21127f8edeeb5cd84a4b92f2813de5" },
                { "pl", "184afa672562b7d2699c5978f8229ebad60b80d8a4011baa728144198ec012ed4c03154474dc806dceabbbed6ed3dd0e7784530206b69bc6eb22b611aa342226" },
                { "pt-BR", "253e030fae864b395c51253d6df735223aa20a1d664593240b1329a2f4cf5bc74d3b06054ae2a6ab5f97546e748d02e9d3d6da8363a797c4c477772ef504dd26" },
                { "pt-PT", "110705877a723956444b2af52b90aa871c93d6dd73429be9a242846b484b1ed3bf8268d26ea4bde12353c81f69a9e69ba34e3c0562b3f4e919ecbd5b62b3f0f7" },
                { "rm", "271dfa3dcbbc72e5003897c77473b8fd45ba74961d9ea601a36683daebc6b8c6f8c95eae236cc59f6e3e51587671383505741856939134dfc8f56bcfddd8c829" },
                { "ro", "786c330cd94cff13084b8ca8b5a62984a7f0a2b67aa36f56055690761a51ac41645e67c6ab159e013426d8ed51ba5ab542326d171db8d14d90c3934e8ad205aa" },
                { "ru", "3b2c81f3a81a6e9063d9e8748978203fb5f772ebe6b909e6347ff657616a9ef86c5a56dc1da82609388bffeca5249a74cb5f61de07625c3cfae13bbec4352447" },
                { "sc", "a0b439834631a41944e7a0606af39e77ebb8d358899556a991b998b991dd952ab480e234f720930879f682f9023bc18912843396adf7a35d78038cf787496b33" },
                { "sco", "05a57a40e34491ed851ea63124bb48226d87cf135dd61cd804069658e08e2b276f515daa9032b815526ff033a2f8d1740889c2502b20c36be416c1585696f146" },
                { "si", "076ff146db889d52874df00cb10c3016ebe76c336181bdb066394eef0915e5ecdb02b66891007a02be6d2c3178708ad91f4960d95b2a31ebb7ce9d71df867b02" },
                { "sk", "d449dafc3d01079dc72ca2d400ce96fac8324a85e97a4a7057abbe9a756d13c67eed8b5c18c4060b9e414b8eba2db90e41ef7f0bf990048d84ad1f0a0200cbbd" },
                { "sl", "25d1d333e40946387829ddd9438a191a3bda4fb212798229b0c8d73cfe9589fe7da90fbf74109e1620be2a0ad680a006ae71fb2087e97045bab68eb877678ac6" },
                { "son", "59beb59ba8847c94f72c96a7bc73ea87b8d69be9306d30b6f82ace24291ab6dc776fefb8eac8a4dfae6d187e9a94dd31dc53fe73f101d52eea942fa7339ef521" },
                { "sq", "7b223504807d1f61fdc712c645f0d4d21c3359c7e8c5f967420bc51c95ddbe6075b2ee9dd01508d9c93543330221b43205da9493083c028961d266e7bd2e582d" },
                { "sr", "4239d72a44cdc480853837e3d718e77defa2438da661635835ee07bab342eaffc3411ed7702a535ce957dfbc46d02d62e4657f603f050d399774bb8f84b74925" },
                { "sv-SE", "ef08ad75ba1aa842129db11e8c7764811dce50c3eef3efc29336daf2e977df00240e0c267a4ae639e2c8b8fe2b51de804b1f283074499b802df9dbb72f5f1a0b" },
                { "szl", "6c4de6004b71157a25e1b47843408011f642d48b39160f442c0bb80e0d427ba14a4d14fba250b47bb9f70d33537777b0f8207170001b0be2e4dbfc771ed57e02" },
                { "ta", "25d75036154d0b91c2889b124b483e5644ad725f77954beb797f2fb90df4ea6701e9c27a5482576207f561676c0c4e1c47fc6b4f0b2ad087cdac3b24c5426f63" },
                { "te", "e5aa55d4300cfaeda2c01082747798df8f57e6053415cf414bd08eb13a1d1a424b699edeada43099b0acde214512e118a723a864a336288b3ad7b5e3744b1ef0" },
                { "tg", "8f91466da11c30cb3084a72d25da586378a106e7f95352adebf2b631f67a48fb9f09f5e6f57f8c39bf053555d7bf473c327865e9f0b85e5b714e9d8054f73c37" },
                { "th", "87a95694b73a02adfd2e1575aef521b9c7ca0e28edf68c4bb8929f9280629a550d8412ebcbb892e7d5c07ba3771439a95cba13e15308fa59dcf670f4028ff5ee" },
                { "tl", "e733cc25b2cff67a8f0c9d8dafdf6eaa44e6a2903328d295641165e93eb9f8f09c8a52a0389b918482c7d6fb69f36e60aea5290af6ea23055a5c6c1db19e58a1" },
                { "tr", "83e760996ff6bc61639b467aa4745b014e88d1bff141d4785c50f6b89439bf74c14666faa6a7abb8805e99bd9cf71d210e21744908ea28be8e72973f6bead55c" },
                { "trs", "cf353f3415a4e81c7be60051aa7555ff4013d7d17634b583e4bc00404020a396d85ca1e39886836120ff9f22fa9aefe76ec9f00a2b1144cced55fe53b4fbdcfa" },
                { "uk", "2f5070f9852a70340b1af84f6aedc21ec2a265b604063b72eaa83db49f08797d87664cc1ded1997409ded3776915a8361c07faf10c2289355a2a92dc6130317e" },
                { "ur", "1e473566637851a802e10f6b0875ac8fc098337d27582abfbca4e62626960b621ad0e07897385891ce1b11b160c202821909f337ea0137b3086bfd57a33b6561" },
                { "uz", "73ca81115457945fcf42dc0bd502af4f51f1b25ab1348a9b3c85e191f7c2539d8f9bf3d2dfa22935697309b1b418c963072e83bea857ea2aff63743b6b774b47" },
                { "vi", "6699d520f640b39f353501d99754cf850a4e38707a0ee5ad201008067ed10bebf782b27c3d6a27bdc0640d279508e0bac5820fdbfdf7fee0e0407762a9f61758" },
                { "xh", "507b172c09f905df00615de338b61e093d868176cdde8de37c84dae4664a3485f33239780b43ae87755acd413809d7247cc41c1d830b079ef411c78a13b9f287" },
                { "zh-CN", "39f8f562691501eb82f040d1b2ee5cc302854a01f10cb97c86d0ac3ab15e9e714d7e2584f55114c3f842bd4b7a7d0077b017b359960f567971f653a54fcd277a" },
                { "zh-TW", "a057b6139beac3ad3a99dd7c8c69c77a7e64424335b86ffe32759386ddc920484e97bc62a1128f8af1f47395e6c53a643c3c496a2dd3cf72c18c0b7603be7edb" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/114.0b1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "0b8e883fea17937a5e83eee4b1b0ed05de1476d740b154d3c51573204e3e03fd028c0997fabf0b9b3d8ac7c28cf67ea4ae21e75907f3e1cce76b433346a8f24f" },
                { "af", "2399e34db58c37ac2ad596d08e41c6b5526de53d11a9a6a3e0f6cd1d7772aba0175e96866bf7f8afc5e1df32420ae8ade1cd96af26bf55f37cc47a6d9a9b6bcd" },
                { "an", "9f505161a42ad4be99eb660f34dc47d1ea8dd4e12710a357b2e3b6cd2f048919db50ed3b85c12ccec27598d4a7ebbc7234e9ea1e2e16e5cd4e86962d13a3a65c" },
                { "ar", "4c5c5e853a2250d309f51c9b33ddc1f85ca2ee1f54f8835fba3a80c41757a74874ba1826f8db41af0188eb78ac64d82b6cde931dba98a48ea6054e1d51037004" },
                { "ast", "0f4c208b772a90cb71a62bf3073a78b7511bb68b0b3eec641c34b8e11407baff3bd00f8ea29cca43ab717007af38fa2ed930ee38975365a637b8675d3f79c26d" },
                { "az", "bef87254ec96280529b199d8d12515f698cc1db525f35af3b3fd00754f011cc68a6e3e791cee73ef8146e536acf4d2886d2e4070a92dea77b01d84d81ba085b7" },
                { "be", "09a938dbb0c73d98856bedf725fd9d71e900df2f8607b23d38411e0e7f3601dc559c477c728829a4cce07f7b4f4bffd8bfdcc232b7a4aa648342837ce873d69e" },
                { "bg", "07751ad3571e910136e2aaeb34f99ac39e33ef50ede2bdfe527552188ae8c94479c4f7ccd09467cb5e4bfa663e1bc99312ce97c9383cd6a866015fca8e9b5431" },
                { "bn", "e0f9f12d28623fa13a3b72c4a64196d3d74656698cde1732a40ad73262afa9d13b2b783e65500963fe52979822d1a4c61fcfb591fe93cdece088c61f3d1744a0" },
                { "br", "6e9fc5b854d4f9b833068b837ef90320ea0d14d6a820ed12826cf5e372611fe2ec74c8da7742d00a3d449a7bf2c585c043b099c22c423dd4ba1e51a391bc45b0" },
                { "bs", "d65e60a57138274a942f45db1c7d22e4201f6ac988642f2a8c5c4bc50af63a546c124d62ed4f83867b9134690b89cde12f62adf56744fe761dec6fbbdaa5e606" },
                { "ca", "7cf367c06ade593cde0630dcedaad614a101cbd3c467f31f29b3dc82f9edadb69164287933710997da9c05671d1c8c7f69a5a2286b481290d1fbead79e46ed17" },
                { "cak", "1c3d1dd9192d0973b275eeedf7a9cd35f7f15d04f126c4c4f072d4b384680780b5156d5994c385156e285cad6b18e1b153c77c5de723e4452cbb087b703e7cc4" },
                { "cs", "260addaf9f69ce57b1ee97c5269f158bbb639804e2a178f5fe2e0946656fc84b5706224e9dc6f62bf2478e72b7fbec1aa2e7c9512e5a37ac9f7f78fb560ff93c" },
                { "cy", "bc80b27eb5cbacb0dd5a6986faf0cda18a2e1824f6892f15c9afac79abf5e4b7396f5e28734679f2dcbb6057f05bf51df58c753f6671fed790ed85c4b43bfc64" },
                { "da", "9dbc016483ea480ff1863b5dfda839f80ad0391eb990825ece0b693696b8f144390c72527726bd7f814b282ecfc2bf42017f5eba9c861905e54dcd94c31daf7a" },
                { "de", "3099b508c5f5d44352262ac1ed8115144075d92462be16bcf856e5bdd8b91128c685eb0645f441412d6c9df7a55675edd3d916d5b250354d558c3124a54c2346" },
                { "dsb", "2fcf5d894d52deae0e0a30c91a47fd16445059b28c0043500addb31f9d024b1e40bd1ced08a18cacd90637b0d0794791e8712fe163996a221ac45c9995da4431" },
                { "el", "abe711c9438704b231ad97571dcbef0aa2a8ca154cd42cddb6460448347829b1c01ee327457dacb7241f9bd094e860643f5ffa2be4f4cd3e8f349a9f9cce050d" },
                { "en-CA", "af34000d1303caed9ad592209c37c0a327f3e10208be18f6b30ec74f7d960f334e8fd3759b6446a3f98314ca1ae744c5ae9eccd62480b40eae47f42105f95b8f" },
                { "en-GB", "9f8cce6b1348dab31e22a0a9c282b2708bf2dfea5b23793b2c463301f16437992429ca88d3866e0eeca62c7719e2dc667faa6c938877b97e2b7f8c4328579555" },
                { "en-US", "f9e60462dfb807416a106de0387d5537f6e3bc1e8becc36fc9e87681db66b80fd9a646e5816435a899ced8b86116d3d51545669a9da7ffd56cf60bbeff7ecc8a" },
                { "eo", "f1317a73def608a9a98974deb1dca076291022fe1a44f5b93408ce1271865bfb859df17f2057ffeea83592574bf170ae2dcc8440195d69cf11b5ee8b75958318" },
                { "es-AR", "70baf2fdb59c790675718d0685648925dc3a2593215291a4211db8b8d690c0af4480141e1003be881a9f47f6ec25038594a87e800d1dc552bf85e6e0e20106ec" },
                { "es-CL", "e239ce618c092b35f7bc94396dae02fe39e26353e280ae8caa4cfe29b59bc8e195b01016271037e04443a9f2ba932f6f7566bb6f8c12336a51e9703071f8f7c5" },
                { "es-ES", "db017ee120bc25e02a188710053eae62778c8cebf0faff07e8dd7ab65507f3db72cad8ca2f8800af4bb044694dd978ad07be00e4dd94a13fa7c10cf7c843077a" },
                { "es-MX", "d4bdcd1b55c27625f377a6e5743af37bae89c50b403b58dc360947593be72f66c1a9f3cf9807a566f8507f346abea0d75b99b984bd843bfae5291e6bf6a78288" },
                { "et", "cfcb1045c9768ba4ec040954e5df3dcbd0bb9ee1460fc1d17429f72922cba1ea20bd8720affd9b62573cb87e782789c45f8b22bd6e6ec28df0019cc5ad40e8a0" },
                { "eu", "b4a4a2fb343994271224968b929a08dd7ca57914abdb122f03914b81bcc6d08cfd48b21febe2018788f97d1b9be48322c1da057f2cb46000a39a99e1da3d79f2" },
                { "fa", "a540150ba349eafe08f8f048093759bf3eb0a92ad63f844451a764fbb5ba61ebd2713eb8c595be81b84315e1e0ba36a6f5c0af51162686fe9c8d7f6a3147fd29" },
                { "ff", "985c50209abca58610896e3c67401406b8f43556d3320f8ec14f3c324704a849999510762a61d6c99ad786e5d2ab7dae3f11b359492734053cab2427506d9ed7" },
                { "fi", "10a135bb36f638eb51389b61b6a96c0ffcf37d70bf908c9695fdc29f2b6b0ae2d8ca6028aa8505a09926a71a0dd0a5eaca0c8d804f32c97b8d639d97b7f7b4eb" },
                { "fr", "68856864a5faca6ef198e73e485f05ce41b2e4c716e4e7a48159f268f0ff275f81f8b69ade82d1da0ec65be1f299f33712f4eeb83c56db177a7315ab6155ead2" },
                { "fur", "d815cda454cc3508db4f385e127b518338bbff63499383cc714a42ad6aafe877e948388810a7c2d2b96d53612d78525585a728ccf41c1c9462f7e5bc810a9329" },
                { "fy-NL", "da47ecf059eec9eeef6e4363e46cd3a82839ccfea96cb1e8df0c76741552cfc1c9c37aa92d03356cb05db75e28dbc57a293af3d3ac73b048c875759bbafd5d40" },
                { "ga-IE", "e65f082fcf17bb59dc312af9920e43c0ac713e2a8e3be5c91f82291675ccf10de1222919789f535fc87229b42b356086db829974916c40708e6f1debe1357fbf" },
                { "gd", "75b96b16f607a7be8006983068bc883e102cc8d688dd140d29296076b211e963991cb2a929f67ffb544d2a07af4e9fa2334ed339f9f81c2e6ce52650c9caad61" },
                { "gl", "8554c3b4e32339603da95aef48f1d0f1e4938c2b1938d8280131b3575bbd33d2f1978ae3f226f7f3b1615936180c5307d59ca1ca52fb8b7fa56b88a5af8720e5" },
                { "gn", "321443efad3651927e9f5d71b9063e50d76b67099c508b60e027230b1a88c5f5e6f21158f27db79b118e7047de9dfb539106b56e1bfca5d40423488a04067f34" },
                { "gu-IN", "6b1e2b09f530e03b087b56af76f26a5d60735fe5b01f7a32d891bc3ccd9cb5d5ce8172bff0a99d99bbfd4c38058331709fdaa8dd45928acfea4a925aad366b92" },
                { "he", "f9e5d0261d9b672c94301b62d3732aee66796bfb3b53c61b83a2c3bc429302b8fd233d8c75620c1b7a7064a9f7092a4ca77519ae4d0445124afab7f03a029253" },
                { "hi-IN", "9ebf2d32eed4dec82a1a3b64fe0ba35ef1b542c65fbb19d404d6a4cb005e1ee7f77300556bb4353039dfdefdac6393dbe9f82596e3b79a36e5e3359de22c3099" },
                { "hr", "ad112e836480da8d21c1c8fd2363183b15ddd01bd8b9efef97d4144060052434e44b6ea936f387ea4131aa1aa3dee048eb891cfad7b993914eb62f36d74cc58f" },
                { "hsb", "4e1a257a2731000092bb61c3bbcf5780ef8213b9e337a202dd7e26b2fe0c3b01531c78a9fcb08b33d477702324b38a8044535554d6f4923c919e1d493eab6964" },
                { "hu", "7c926efbd62864f9333bcab5055ceda51f2165fa934784922eb76339b39e3484ec0c4cab83a7d6ab86add5f1d2c425e3bd593033d6c3c11d03e677fddf4d5105" },
                { "hy-AM", "52d94f2aecd516b92829ba2c5331b8161fd2a734814fe7f41f31adfb1d9f4c778da126d488d86bf1a43d39b8911aa82057cde36fe776cc3da091f63320d591ca" },
                { "ia", "608ccb7f30694d07f838e47b69fa675109b6114cf7003b789c522c20e53956b1bbd874a209b52014394f8b4e5c8d2f804c894c5c0f2fee6f1fe38669b5c15494" },
                { "id", "b20209aa3ea8d0c753ca6aa608225ff22c61a371e1a5ac31cbc1023e8aafac0331269f213cc803813f2781bcbc846c051fdbd8bd5d7553409d299e6781630190" },
                { "is", "cfc8ba85bf6ea20bcf40694379714f052b3068db0b331112f23619e0cd15f46be2e5c687d1f3cd05564e3e9bf9f398ab509dd8bbc23fcee536bb836eb2653df2" },
                { "it", "8698624e21a7f8b715cd423e22275efa35d8c2c375bfb032accd95b866b291359428e7a50311c36602674db18b778f33a7d4f5910801b4ffb30a0a17cc104e59" },
                { "ja", "155b2ab8979823d914d1c755e8a270bed934e8b269c09713a939c420723beab82ef705261411a54b7674d16f39d15af52d50128e8aba4a89fabf63910869bbfc" },
                { "ka", "f48545981cb38774a1925527d1c189dd0d0d08873e9b21c96a8aed5b0e47b872f95621561a17d4c0ed3365bc267a4d3e747062b3172232ecd64842a6ce902fa9" },
                { "kab", "4081b071ef8c044f2d9290cb895aa885de014b4ffefee853a32d6b1bb11fbfe3d0dd0e02276a01826cc514e9194389eccced127e5c4a19ca58efdcabd1de3f6c" },
                { "kk", "56867b96e36a7975f1854abc38383e1779146f915e2b186a1d48c022ba2ccee4664f1f79f26341e3b8418e3d5da097c7692450059fb5c399cd39fb329f04e637" },
                { "km", "82963e3b50cc36353d07a7ee274fb5700ebe1b2ebd8af5b20371e268f025ace3de7558cd1fa9ddf6e8b6b698d93e0bc2d0e5708813fddfa54119a22b53b7d5bc" },
                { "kn", "1cce1f9a4cb18b6e05769b758d49ea537800f99d2ebca5738b7774534e7957fff54846d73befca70a1b36596248fd8bf4a4842688f192b9d45628e18fd239d9f" },
                { "ko", "bf2e99677d7b6d71fcbb89b5cf22d3e87b47278fbf6572a7bda7e97c25b7f7e76034178ecfeea99687d32ed5f55d55d44baf6df095a0abfa677375ed39ca19ae" },
                { "lij", "c24f61a06a5ec85560b461c718255b71805e84beafd9b523a6b0e0d30197049915ebe4c7888e4347ba572a6fcf0833e090d7f83740fa5c52b3d29a765b772549" },
                { "lt", "50af27e6f0ce491a50d7cd3b0eb22f0040c95b5b6739215bc4e5aa71a97039d1631bd382bf18606e1f672db53869546c09d93ed07df39421502e4e2ce1db5785" },
                { "lv", "5a28285e60bdd63fbbede1706c29f8c6f239c60002ea300c8e0b27fc39f5140316b2f054eb35b028364cd2caaa85d4ab1f6477542fd4d604c5517b7ee3a788c7" },
                { "mk", "14fa62d907b8b674c8c2ee66b2c741bf525ebaaeb6379d376669f8d2a612deaf3bf969719e6f1cab52078c8f73703d102a62146f4b925f2cc188df99361d1598" },
                { "mr", "0af9f305ce3c4cbb6865021905e6d985ac501242c4cd15e50a684b6830e73d6bca6bee6c49d86b5574b4d8860422f21b195776351946d9a315f4258bcf407348" },
                { "ms", "20dae186d6b02135495406804254b2caf1e2a489742263bbfb6203a8babc57c045cf225a1fe825ef2ef5fef3ea6667902cab518e80abbcfee4080e65e73e2c1b" },
                { "my", "637258e93cb29e49ae396e22058a3c33ea31eae3f69ff56996bf1c3726aa26a82ef2be93449c11126f15d1acf7d246e9cc7338f5f1815d461d6ae1fd7c054369" },
                { "nb-NO", "512fa17fd072094c1fc32dc654589dfa1b0f857899c7af9a3b4c90f1068ef11b5f6501abc67b5fb15adab27f328cd6ac8a2b0706b9fe77eb22e084f38c20e059" },
                { "ne-NP", "9d331581da128771facfc679c496c59a818121d1db5f7bbe4971401606ced2724db04a6d059bcc3a1a09a68c2bc5382d6b64f404c699529ac7a73c82dd129bea" },
                { "nl", "808db1b7d274d350b696cca1cc84254f809c27336d9540ae94b999d32f16c76c5bc03bb3ba3b882186c5089aecd1a6d827c58d00d34a209e3ca8b4e4bd23564b" },
                { "nn-NO", "218ad2df5e082bb1a754d89d169f9dcfa90fe3440557e08f2cef52c4c527cb1400a60ece33e03435451618a90ccaebe55174dc038b9bfbe34a2fc7276c5ec5ac" },
                { "oc", "cd6c37a2363eed100c52e0293a646da5746944246ea3cb963af1a4bf4f99b8e4d2e66df78d371b63ffe83612590905a872e1c40d5b44266eccd23b4b29b9594d" },
                { "pa-IN", "db85c1b5fcc31be7b7011c88541c80dabbc5e801458551d9b0e92c3b4e1eb9aad7db90e5a4ae83dd6358a700a7febbe14a0143396427db9273206714ce7b5ff2" },
                { "pl", "1b0084782f05c9bf8a5b8af149cb545254048f699a226caaf139a2441602a178ccf1bdaaafdb6ba088f03f89172ce7f75718baf6a5f597110cea5fe8fbe58737" },
                { "pt-BR", "a2f12539affad8784d97c695e1cc6155d0ac1e6eb83fcffcd37869dfee60822f74afe316773b1f6f393f31ae2569bb819bdce0a60556238f68f7c3192520f1be" },
                { "pt-PT", "7df1d61ff3a5be3233a1c345fe3aff17cb253c5dac1d34273a89e859319e2490a17f334849d3c1fc5da2039874641ccb53cae5a556a1607dbbccb689258aca40" },
                { "rm", "d38c6bb6cd9c0b3f291089782dccceb682efc458e793914b39bd245521d0494718aeaf3c2e1e0cd1833bd017b408c59e63bafb47dc5409fb7a4d3dc84953362c" },
                { "ro", "b3a867efbf44b4c993d46b7822de21e7910a6d5b432a36f89b0462395cfe4a4d70849b7e4b2b536719d3268cbed94cde949337da0076b9e8bf48d88429f2be92" },
                { "ru", "dc3f9a5222c9a798f33e07922735afcf54aad1f6c27fabf7b15548b854ed130cd875fe415bf166ceeb2cd14e84e56156d0c1bfb47e43208c72daafa4a435f0c3" },
                { "sc", "7469899c99d7b8949a26e81ff27965a98dfb3b770f2cd20559dffe053a06f2025f191ab67c3861e8cbe243757f01e1b8e11fbb9ed1338491fef9a303c11cccf5" },
                { "sco", "a701531686f90d62a8943d8c9e3d30c7f0bd9710729ebf017a144c67fab0c1280e49739ccb72ce63d4fb74b95b3bae7e251f53f7c587efc6031af7feb9112376" },
                { "si", "77b39cf6448f353c338901598c907cdefbec98dc32af2ac241e8d4fb524cf9df98e14383506f0948b67a92f5fd57acd6576567399b27f9cbdc7c3c7432ae99c0" },
                { "sk", "00c341e7985bb8fdf61440da7c6e916de14a63ecbf505ac6cfecf5088147ba583875d0575bd59e451fdb6bb81cba8e6eec34e60e4cdcd408a6657be593274aca" },
                { "sl", "4307b36ee16cd670713dce1158d29661fa9c865fc8f73b3c19d2690bbdf692ad3a07d453997cfbf525b80484a6ec59a7847453bb0a5f42b01dad5b0f520646ab" },
                { "son", "b62b8e989f44c0ad34e98bbd98a3a4d3bd195d88501f33ab4ff73f91284fb8c4ff311c82e335ae5c8a3fb5bfe9ded6189b7f180738243b7a72e3db8cc9b3133b" },
                { "sq", "f4944ef4cab3ece48bb7c2b202135cdf1e9e59bfda7d06d1d3495a405cff0bd809c19997642894f09b14acf8e49ed74a7481f84a8dc353684ee94f357fd3c833" },
                { "sr", "3b6b0883316974543b7d12d6cb0687e6a311ce2fafe3f9aa13dd2ddbb3833a153a9c895e8aa4e6fa8d85aa1deb4c050c8f6fa98811ce527c0c334eb6754f401d" },
                { "sv-SE", "5a14b92196b8eb102031d702a931ba2a76e6bcec484dea61cde121d1ec631b3b2f0f0ed7631526289976dbaec91097c33466ca4efa387b675dc44af2a7619b3f" },
                { "szl", "e6e6928e47fce2b99dc7c90f8ffb6e69a4ef729e0dbd193e85114b5de566fc25ef8abd2e4cbaf94bcf8f732d53a8188373e5fb5b2380c38764999363ef861ce2" },
                { "ta", "963876b3da7eb1eb6d1ace3a631e0ab9846401b62c308a4a24e5b4727ca28cb3f80682088e10b9474fd53868246bc925475e8b1fd91c32619265d6f444b31cbd" },
                { "te", "dfa1e6c176164ac738ea1421ec9b0076c1c49cd5523810334d62c5cea0e76b16321a717c124c13b2e39593d1583d1b8f4167734f142fd75ed3e13c259acd4fb4" },
                { "tg", "d54dbe8fa0b0405d4230dd75182e56b3f259a9050aac529b0291f51cbc27e1f76df3ac86510953900c2a53397618a842a836b2cd6b9631327fa332380546c3ec" },
                { "th", "1896fdbabee8585d01ceb0d9872e192108e2962d093a90345eee6a1829ceacb3001e4da814bde2c86243f596762a53f7c53a0391702718a876f539abc6328772" },
                { "tl", "8d93354ee86b324f0c8e855f35dc09f746351155023ecc7dcc83988be3f784469f0268e7b169d67b308eb3f028b6dad06c4c6268c52f0a5e66da8b9796e94b9b" },
                { "tr", "2642e61f353b10ecbe78afb2fce087d700f582840783a4f827f86962ed04106a4a786b556cec9513f1c6d549fb9d549125e279c8def73390cf38002d0489d3ab" },
                { "trs", "ae23b097e6b6bf1e137130ee408c4f4868892f9cb9d0e8360432becc5657620f419350aa6f4b3522f871af7d962b8b412ea899c6c3716ddf291066deaf3f1f4e" },
                { "uk", "9a470ec4caa2676f7cf5c5ef5ebe7f8f0166fedb184286cb80f9c9e92540ba9e149665dec07a739f1a7fb2cd24dcce320ec0a4c16629d7e3b7937f43a2cf7053" },
                { "ur", "2eee4a175aae10125a71572c55d6a57eab3d8402826ae5d107dd72f54bc46b1d2c1534d54c7b24396148a8c3aa678d17bd35d2fe4539ff3afe6594d4f1c34bbd" },
                { "uz", "972b3f54befadac91bf3b8504d5fca8f1090dd695f739932cbd5c850177d9e9f56b6e2f9f132fd25a8b6d55fbb11e87c112fe2884d4aa003be7c9b2baff4e83a" },
                { "vi", "1e058fced8350a821792df673144a4605b8eb972b17bbeb3b23a3f90a44c661df8eea3e0d912e1ccade9462603054bf367c9eca35b89d8b74073789077809f04" },
                { "xh", "cc6d048e2ff54b07e6bc6954ad1d4b7594b3b378ed59ed797395da5dba4305678f512580c0ff9b97670a79a7187de27ec6cfdbc5a38913543a8625af7567334c" },
                { "zh-CN", "70e5a20cbf267f4c6d85d3a45ab8eda6581b2673de08147716d5af8e3d5532a6dfbe180d5517ec4964ef8fe475ec9248cb4dedd83680f292e489f0ee5644433a" },
                { "zh-TW", "c34e1efba4dc4875ab05420a58096cd73292e4d0e17eef9aba057310fb5b3373d3c588b4c98ba8bedf7df6953d2e7e62d49fba13be27cd0c547f6741bb8be5c5" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
        public string determineNewestVersion()
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
                    // look for lines with language code and version for 32 bit
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
                    // look for line with the correct language code and version for 64 bit
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
