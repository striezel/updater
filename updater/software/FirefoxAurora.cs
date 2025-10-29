/*
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
        private const string currentVersion = "145.0b8";


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
            // https://ftp.mozilla.org/pub/devedition/releases/145.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e948809ea578f384febf8b0939fb309705d39f55b414bcc27b9d8cc5e6ff6788739fad36bbaa63b2dca5df71747e602539edbaa54f7dbf4dc9cff033c086bce5" },
                { "af", "9f9d08560746fd6b979ba6951027293534caa8a843e35aa1e41ef3ba743b2450433399ec7d2fa13ae1473c78a846221c62978b6fbf423582ca9f5fd8cae994cf" },
                { "an", "68cedf5e21f970726eab3a52eba0e8df7836a5784935ad97bcc8d8875843e7e807c145fbf550d047930e8b00e5c832f0d0d188b3b5014dde901652cf26f28a03" },
                { "ar", "7c878bc8f3e420a590753ab71f56fac95ad4d4928db3166fc1b6daac5114890190ba00da7867534b2c90ea1f875b2ae00eee1ffb6cbeaa70cde8a366ba4f1634" },
                { "ast", "551daf8619d725a4d42a16a300216fcfe6a61db99e64d543126de82f38b2c519fb7f62df019b0f0d718fe0cbab24258e46c2e2654fb760354eb1448836f060fd" },
                { "az", "056c879c29164b6746dfffff21944381a92889988a9d4595e2fe4850b7f785215d79e29934f2a2fa4c8c9e384536a0ef86de8ece9abe10b371815fb2729a775b" },
                { "be", "64640541928927cb73e676494de709ccfc4dde50d9edc68bbdc29d4a093ba6a04b7b88688d1f5658f378e9336911307127ead0229b112e46d28312f76613a111" },
                { "bg", "af3373fbbb4b384a1d301d5228e77393ccb117634f325ce6ec6595be04c7c215d06b09588b3c25974d44c3d9facc46f9db729cddd41f7779f04ee7c85670bcf8" },
                { "bn", "0d230ea7437022ba1a91abab22a4429acd157dcd86c56b4fb7fc3b14926af73b596b6373825f600810250ab027bc7028c3e7a834072b19428336c185c999b947" },
                { "br", "14ebd205d33dbeb3cb738e58a7931d46e79eec49404d30f9fec531279e8c15853f22d3d6c545060562e2b930ebfccfe19627cd323a3bbcb46126f96a4a00b989" },
                { "bs", "7de8b5dadebeda73aebaa677b283df27f6faa6cb41dc6a229cd7b6add74e9cad136a1ad52e7e13bb4850cc98ef5d2ee3f0634308c63ffc655744e3f0d1a7d2c1" },
                { "ca", "e86f583779d142423b1996fc66caa40b5ac7f8370842d2aff95a3d434e71664ea1203149ee818ab7d68c0c277c294792f08484743de574ca342932cd06454ca9" },
                { "cak", "118622a697b28776d896f832797acac4e072fcbb9ce28f405f853d099fbb5df4f6cae443d620638812fae76258fe4e8b1b12156f3526245106447f7f1d3df64c" },
                { "cs", "d3c5194d1d187ae4d06e98cf81b8d8198f9ae0b844759828224cae6f665b70f869c06294bef6c104b35acc57c26727d334a1b2772ad93dc0b954d2085baf250e" },
                { "cy", "66b83e054a0b59a8f68bcdfc159341140987b46ad3e0d02f3430f5d8eb87310be10e8bae517f5778483a07d32a3265eb427ccf48dcf89b0baacb61134a2386bc" },
                { "da", "7ff4cac54eb4dfd495aeaa7d0651e479e899a31acc33d28adb092dd9f6d817da0eec04c64e45e1dac872365ad65792c2be675573b32ada9a3cc0d67e4e2cc066" },
                { "de", "5b3d10a01ede63774a41bad836abf8df8ab3ada1965c9647b342ca774173737740d1d5314b97b69faef326e0f24083afed2f4ea2703ccf462563a585ec8a2504" },
                { "dsb", "4878243bbd029a67c591d09b27840868276251a6de9ce02f5cea2310baa54d8bb92be1ce2679d5ead3e7f456637fe6e5e52ecce6e533cd36bf15b6dcfa90c792" },
                { "el", "9c1384961edee3017594f87f6378d259d90c2c800e2803fa01864bbbd374e69b0b62b9e09204d96468b0ac824aa39b42bf82be0d24204e03c22ae64f3692053c" },
                { "en-CA", "4a3a32b9a7f0d8e5b11f7708e554d71d54edaef3f89ebb10b87fbb9ed5f9152a1d14b377bf0b93c0f96c09cb85ab5d9bdfa082cbeae5216d653e6e899505588d" },
                { "en-GB", "9bec528a7f96d78da8b13335738478f850b503c3c8402d7922dd8e3e2bf6c4711f493562da7aa541e1a95af4b3e74e262860d005afaa22a610a06cb38263da2d" },
                { "en-US", "ec12aff8430d73e9e5f67f65ead1fbbe62c9a3745627092d655c9e0958f88eaa800129e10f8074047ee009bc5dddace92912bcab9d62645c3fa29f1e3b42bb2d" },
                { "eo", "cae09bd3df7a17d4db03be0a86d56106abdfbc3ce3c1632d98411b92787163666d273476d6defd6bc4fc3ccc7dce2035d02249e74d3df0bdbe71ea7c0f1f9d5a" },
                { "es-AR", "e3bcf06822b28ce2a0d7749bc57a0841965fcef737974406e749eeff4efde492d7c970c7d4dfaa5387304238237de738a664fbe668c32a7e46148d6ac1edc64f" },
                { "es-CL", "1a74d6a2daff8009bcb432327581958f05fba2e6f8c0b03d79cff7efe95000bef5ec08f8566e24c5202c081e120a4f1c5362910b72fb06c15d08ad7dfdbd13d4" },
                { "es-ES", "0bbe36708f4fdf850942ebbccd9b518a21a671ba24d616c67cce0a4f15a70bc93e7743728ec069b47b5237a821bca07dd55093b553c154fd959c5cc586ac1651" },
                { "es-MX", "d3745a43c3d9b97f164ef0527281d03490048b2e10a99f14a8aa03e2bf84e758a9f3b8efddced73557c2c70cd13f2131ca4fd8acf64abb9f303e170bb4c2f23d" },
                { "et", "1b89f9f4f3f68ace432e8addb845aef966aa2fd10e8bbed5329cac8b2cc16b5d534a33e7bf614c436d9289dac879f5f746084602720c6545fa51f0570d38f8e5" },
                { "eu", "4528d8438391ebd1bc28bd44d5f0916a296214903226330b359c11d18286cc8918f8996aa60e0d293f4ff02147d0741b953dad0864fb5fe77c9adb11b15ea6f6" },
                { "fa", "c11eb45720ce9648cae1952896a1e65fe2668afa3fad4fb84e7fd6a47e69905138fd11ee0cd95750b692b0a021015ae15fd47d286adc3c821472d3d6bab4c1f5" },
                { "ff", "0795f6740865d08023a628f128dce260c6faa1fa57c6e148ba22327c7b2c2c86d04acde9ccf83008bc54bb7189791d0c82d85e0770615f410144fdb86fe22fe6" },
                { "fi", "e4f043e3e4cca29db898022c793e24f40de831416e5b3f7a15f18120a6888417e13285401df9b1c122c05f04545a5a39d6ae25f3664b82930639eb63f08e5a09" },
                { "fr", "aab67b5c3d1f3406bccc7362e6749538e77c53f33df23d0a61ecd9c40c2deb69ebe036819005a620e1198805c203daf46b506c9578e9967637610b215a009dc7" },
                { "fur", "bc80c7c678912d8bd7614fe9008fe8ea259c362136d925b37c5cb49365f24af629f7101cb2d4bcff2561b0ff00614ee17ce523b568a59a0d0be97f4e93ccc06e" },
                { "fy-NL", "0b5257e53bbcee3b79169f2b711e0c9b0dccdcfb609f3137a9f29de4da6132130a8949115243c7f424eb56ad3cf9875d53698f88a32d47fa9929be19f23ff68e" },
                { "ga-IE", "431e0d5261c9e26eb4acc8c1b2d3da920e001135ff77dd504e2205f1b3021a5cd6545e83b4b8d225944cda8e2701b6f3e3490dddb283318b65e642b55ed5148c" },
                { "gd", "2c84b7170ff0b8a21b8a8b11c9ccef01f9fffadfe25bb7ed90484a900307a0743762151f4e055ff45edde8002da3c5a3224ea97715057f731711c3139810b16f" },
                { "gl", "011ec5f4d2332e9da927635a31dcc7141be8cabc36e00a53d9aab94fca47fbc76d036662ae58e6b4d71a6dc8468f09a6bb1d85a5558691635fd9de32c3799031" },
                { "gn", "0203569804b8c23c194f501671a32590567ee5d3eb6b93e9ed1124e0232184456dc7ede4b162b48481bf9f5d1ffbcb3010e7dc3dd9ec07d3762f9dac3b890305" },
                { "gu-IN", "b1ba217be5346efb4ea7db83f11df8fa4bb1f2ef83d68612534612fb5839fee9adc52965c70331ffb3f1b60440097e5eada4ee4bde0101092697210bdfc4822e" },
                { "he", "fad21a42f69f51e9a1dd33d2ad32fae0892d8e0b32f56f35362c4a2fd27a948af34e0b62280dbdefe44b713e8e68f9b641228e72b7d70f080b771c26bf077f45" },
                { "hi-IN", "16e0bd96e73517fd6cda44212f022c371d46e9b3661b2f5773260ce1532bb3b4ab8fe44d763a6eeb9e0b085500e890b9982fc0f577038bd98be3ecb6bb286898" },
                { "hr", "05423bd57d4ea9c386ecb20af186c3d3aeeea09c5bd0f305acb44478c394640efa17781df3688a17502a6453761b572f45e3e31a8c03a93d28993271455c0aa6" },
                { "hsb", "f842aa1b3cf9f70a42e72a17460965580fbcbcbdf1c8384820ba2f0c0d45ed3bb62160901c4d14448f75da2cf4f840b90b2b748a61352d1425dfcae23583ba53" },
                { "hu", "937c8ee72f83003f1aa8e22608fd0a63d1c0e7036dd4ad46eb520eb799d5851be6515e54f524157324cc14e773d9c65ed70ea41f7a2273add409d2b8d703717e" },
                { "hy-AM", "047190d91226e3201a54e7bef246db54db10cb36a85c37c3ed4340c04c9e464277c26c3793a92e7fa12ef40cf4bd00cbfea310c67230d8e0419733de399e1720" },
                { "ia", "bbbed349c7b20b95d0d3a06c94c31fdb4c7933d499809725faf71cdeab0879b0c7c0911c9aa89b9a6de286f02891671b77b713937688003bef444b32370950b5" },
                { "id", "4e5fbd5982bcc6c0c291ea02b88be87891885e0c01f7c3dc6baaf741219b9d069c91f8a889d7bf5ec7bf84e4d092ed79778365578189018e868db2001650380f" },
                { "is", "e8f6219a8c08d4d527521693c84bb5a75963b673cae82aacb73bde958030ab7dd367e129680e0c75749438cf81573732f11e75ab455cae901044e4b762344164" },
                { "it", "40095c1380e7a85bd417ab2597174b5198ef94a4a531080568db76a374c345910c2f6db7527c46110f949aa47d6bdfc321568760e1efdc1db8754593448a2cf5" },
                { "ja", "9cc1f00238748940ba4d99a9030505fec1fecbe28ca8cc29ba36c61aa7249fd6b5c3ecc70b0338e00809e378b144edb3e13fa7198ee223de658111bdcba7da88" },
                { "ka", "89c16ea08566cb00596e1cae3e4bddc759c08718369927039862345f882c9418b2dce76a42b8c5129c47d0a092c96e930c76d4ede73aabd611d0325eeaf2c49b" },
                { "kab", "ef9f97fddbb763fd52f2b773fac928345dc57bc539d3471b6c181338540d2291ceb40132b43f0a5d6dd17e12b7aed142799968532bfab8d3bbb499a293265769" },
                { "kk", "965cccb0cc6110ea8d03c128100b0fbaca71f7e6190405eed30f0f2fe999fbbb16d8ec90bde4cb7c2bc1cbce64c315fb1beb50717e09793712bb78b6577e66de" },
                { "km", "959405c641fd0f885d028caecd14145d1ad86cecfe308fd17db4d458c97d97c9a10156e614fedf45e9c82108c7bf20aa996e2ebb81e353864cc618a51c89dd12" },
                { "kn", "8a38f2efa951f41e95fdf6f89fea06ec00b115453fa6d14c17cc10a9dcbf67eff8fd619b651896640b8e1f094ec29d0ae30e9d4a254212783b398b02a22748bb" },
                { "ko", "c36d680015b79ff9530c7b5aa0484db4aa13925d78966f94760651d186bda9c8f9b38ad2f500cfc708de9f99485c3b156c5cbd37bd1a6fd83edc2f85151e2d19" },
                { "lij", "b5244a825a66c0a1445881b1102f0e85a419d87ebab4eef2076760c2b0ccfa1f877a971a50038626bfc71c7a05070988f22fe3105abf00fe41e07fd49e499d66" },
                { "lt", "31f1cec8dd99a6babe9867af725ebd946e2a117eadc95124754bd27e66729634c8dcfb432fe903afb4b99e9c5216245c5ea50b25755766eff0e3fbc0cc71b764" },
                { "lv", "263f230eb7ab901ad506ebcbf08508a557654e11975c644ff080ec9ebc34ae30d346e1e6dc3a090ccc32b4eed8456b97a6dcb0913971f3bfc771404d6d5c8c91" },
                { "mk", "6a062a7cc803db62a605ac2889ba07e7d699966d9a17c5cf8f6c3b029eebb785c02e1227a20cf0f7a572d605d0dbfc4b8e633b4a12549408c44a2403169fdd0a" },
                { "mr", "f6056efaf3eabacaa54d1d8e6cdc57be1517d7442297c5ff97240446f994e9cb9088d332ddbb07ca9a224d44279fe82a74d0913c4e47fe4dd18b85a0a3560df5" },
                { "ms", "9c76116823f6ca8ebb1953cad90d1cd7e451bcf9ad6c6d3fc2398856afa3fc7ccf485c0bb4dd16cb1b4e77290906891970b44e129bc02803cca44eea93f78c93" },
                { "my", "0c86f7626341e797f863a984e598497f37010bc466a938a25d2e2f74026d66e7e220376139d4059065897e11ebac775b3309c34c47937b9e898f85aa51966505" },
                { "nb-NO", "417ced8fabf5698400bccc31bc5ba9b6f6e92b7b2b8f393ca37fec5664305713898fa36aafc7ca18766633b6372bcbd9a17b04010fcf1538957ea7c469597b99" },
                { "ne-NP", "4dada47359db163267f0932681471c4f6aa7d8c4164ad203ad8f3f7533fe5853d1b720b6d85be76e30ffb67c8e14ae56e7e360436414345e7ab06c1e76adc6ce" },
                { "nl", "194fe8a4ddfa370a83f0999ba78951471dc1576e030825ac2ed4210a971f341bb0b6a711f39ee7f3ba707f09e687556921e6d3aa7c645e9a05639991dc2e6679" },
                { "nn-NO", "5fd6a7bf0c11f21d362547974200d68960286f370a698a317f8af7d9ca70c3a5c27952cf0be47fcc653bd3e920f7df2eec57217ca2b6d4780ffdb3f844f9289c" },
                { "oc", "e63419d55b79b2bf0abdc88611feebd5b547c848218f6f85e373ec523a11e7fb9b1aa44b3c65673c04b4682d7824b866d465d6bbc15fc0c495ed9ec9ca589a9b" },
                { "pa-IN", "af57c240eb4cceb7f02d6c6b3999c09ca85f5f94cf3e47a2493f315ee85d88453a1836c9f7c31e35185c08ac49d657038d30d99464abea393c29d8035d195b6f" },
                { "pl", "04c111b9aa9fafb2a86b4832383f882fd63380724051e184a37508c8377ee08ad1e8fb075265997c5eb2a37789543698db87ae261e1d5267c8ff2bbff51db827" },
                { "pt-BR", "9e977bb12695f58562c88754e602fec5e00270ce76c004393d00d8943ba20fc1f0f8912ec099c4508daec8b3ea99a4966e62b0f06717b695542ba5ba3e69cb9a" },
                { "pt-PT", "39debcc5e62b34fb328441cb4793e5db05eaad36bc2fbbafbbc7e32e22477cc8aeeb91ceb90e4a5ca4721a323c29cf334cd38d60b773017d8304cb7c75e62495" },
                { "rm", "8068e7f7cf65a121b5a61dc80d73ac0c81bbf02cbc50c483a9e6987a3f09249e19aef8f1dd7d35e280c4c4d8ea0bb8830b5ef24f6a147caf4f938d893a7e6ccb" },
                { "ro", "98aa92f4de72089b6449fd199a32cd5cc9095a23fdfbc6db6d41bfa0500159a7a2d08f5e40f7d422fec39855cc97788b2316cd820bf6b400ddde456eb29baffc" },
                { "ru", "d14bd65eee84731d81f9f31c558d674928858877412425c6488169fef25d5590d8de3cc49fdbc0eb8ba1ddff0066618ebc6001b0a7db9caaff82e5a469e627ee" },
                { "sat", "d118d7b9cf4cf3bc171eb1f279d934f3c2e069f00ab8542735f4202d2bfad92efb0c908e875b57009f6db5fc597e5e0076ae2a8cb99143fe18aa5900b8e6595d" },
                { "sc", "e86869bc172eaa06b9cd6a8ab2990e5e75550cac187f06aa755e3e7e664c264187fc05b6a553ff006dce5540c53cc6ac3f4ae9c354b3d7a1c912a0560e7731f8" },
                { "sco", "efebab49023d6fa65f6e62dcc3094b6250b8ee9c9b5ebbe26d681a5a6984cbf12eff6fa7a8dac21f126b8ffd35dc8240221753a57e01f0616a673e3b820597fd" },
                { "si", "58faabba840058bfd854b27a307c909d8c01db07cf8fd125bd8b438c42ddb9aad2f8c9f8ca1dfba6d69665362483e05f12f5bd4b48e833248a879e46404a5f0f" },
                { "sk", "fa780b4e27ad05200a26979499214e680b8b543199b111e9cf5e5fccf372fbf78b173cde23c0049757888b1f52ff3dd7b035a48359fa605165e89e89c96c086a" },
                { "skr", "192f356e2365c55a579f4d0ff999d16a9e2d102e7b18e8aea83b3edfb936945940ade9b129899a0627c75fc3537a792344b4ddbde0fe4cd861fdd295f956b467" },
                { "sl", "9a7da979126047b0a97e683e55ed9ca43de634acb71489216308f2ce919eb45099632569148d3b840553ff378472fb5da83f831e6a5ba0a30bd3f5af447221d5" },
                { "son", "aa84b81c08f11daa931eaea8d7dee6571851a879571aff9912c7fd9543b49c31d0ddbe5def05b1bd98b5a4552b95abcd6166f06bef0e96852a1b4c232dd12e05" },
                { "sq", "88f2349f1366353e6b2bd4663c5d8df217312ab17b17dea90959fe3daa39f074f1d6c9f13560cd27e333e52aed525d982ed6fa0091c7e64062e82e632f90687f" },
                { "sr", "8691094c78d934a1fc3b6105e48996a6db7e99e053f46637b0962085ae5bb24f19ea908a3b6188072187c1d1651a69926f411efc5ade15c131920da89de9bdbf" },
                { "sv-SE", "ab10c522c139d1ed8c4a80d7d8d42323ae50ecdea7595b105c44551e6b417eff4a65a2a44f2d043477e80d22605fb5baf7b8fdefe288b17fc2eb8ddb597cebb1" },
                { "szl", "566ed106730cca2fab83cb36fa95d0ce55709aeb0a9285cbf6a809ef7a34e1f6b3d72bdb5b6b862b9ad7c3858f6794625b563ece09afab49aa45029afaf4f919" },
                { "ta", "027684050de06b14721b664d535bf42a6c2b9ee073f44d7bebff8a702a39ad3a6c1cbb60b56b8e7f55bb592081ba1f23c8fde479c1634a2a2526e34c0727d679" },
                { "te", "79cefa37b44ba0fb094730a15bdad07c302308479324284a9d97e34eed603b1ffb67b3f0fae70cabedc41a5a1071f8ab24c463abb12fe3930e3aced047d341ea" },
                { "tg", "5cd60cf21b232d9514f28b258ac4f18fef11b2e4a90249ce3a49edd3df4dd23d34e415b8684db016c2792376665510b3dc24d90ff8dc08c781b5c86241f6cdbc" },
                { "th", "27b36936a87b7e5a5251f1f4ac8a7fa9be91fff9321780f8de47fdc96d037b15e02e9ac0cffde141d14b29947fb29e462b782fd0ff42d7fe277237acf1937871" },
                { "tl", "82a21227c965897d1701e79b57b823ad4698808e613dfa56e1fdcc7096996062a9b5f136cc0b2267116b2c1c687572bb2db45fd48722264d361a7583c0a84a4a" },
                { "tr", "279538ea47b13c1d7ea4e6dcac22ea3a7da555d3352e54368edad6933215804272e43df548538f72d9ead0efe39f48987504fe07a9f374d1b8eb76bb4f1fcb88" },
                { "trs", "78b797cc3842ad34415a9149fd4ddf6e41c8888e5b7a0be1f4ceef78cf8e5f9aafcc6c6a909465a0e09c8022ee3bb82959f54968e56656435ea0ad8801d89d91" },
                { "uk", "30ae9b74a33bf1c72e275d4cc2449bf8ba270b01a5c01d66c3503b6fa50476a293e409e23f54a363d2db32408d764e1dc2aee88286567ab7d2e457d31a9960da" },
                { "ur", "c6354650feb23feb3ea72eba3712b28565c898672af27835715202af372769a41598f669281838b891742a8fb4f05cae410da2072d5d8ed071e909d6556a3726" },
                { "uz", "55b729dd822927b190180e1ba17de9e61a72d1eb081863df00cc746f6ed4a5ec84ae9127cdc688954a3a1c5564d2985df97fb3f2c8c0320ca93f0ca36c9e2735" },
                { "vi", "51d4c5253d3de4dbb86e6167ea7073cc70dbcefae3af554117244a097134c8681d02b12f2c4f9edce5e0fc1f6827fa8fdc55844940a895eac5f9d1e07181fde5" },
                { "xh", "1e81623d3075b655674fb84e9e678a9735c7b94f351906e983d1b068837b17912e735f8f3e74a9ff44daaf9adce44618844fdfcc7ece20f616cf9b912172e588" },
                { "zh-CN", "4313508fe67390bf27c4db81fbb6c3d554e754a43c0ddbc01a11583d066ed685c67a2e86ab96370d5ca6b319f23e13d35d4692f659d6ef8cde9929eda1508638" },
                { "zh-TW", "0af3974139fa6ca7002fe8735c63d86ac795685086e288f6e777bf6b8d43d23817ecb6c2e5fdda4072f845c7fb41032b0ff6f7dc847c5c9a331f5215cc3dbc4c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/145.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a52b499f4fac102da177048bb1eace3b8e987053a4fab757162acecd1148e816fb71409debf9a7b293313d599573f4b05970285ad23091954eac9652819f7242" },
                { "af", "bc29e7d3e72ef87d9e4896991467c17936bd040188d1384c64f46166beb14c649956fed8274b4233264a7970eda75f807b6f67ac34dd33080cdbc2e7eac4e081" },
                { "an", "bf68be35e6e92260c905c68f83582a7cf6f146c2faec7885a8aecd2f8130fe85bf8168edf08accc2e2f9c35621431e9936452c86d4aa24a7e0e99535129ddcd5" },
                { "ar", "d6a107caffc6cfa5e7d4a72e19057a12db0bc4c8c1432d7df698342bd89f151b4595f7ef9d270e86b3f74bdbab719dc68394ba9dd09cb101195e7ee58670f8fb" },
                { "ast", "56782d3fb1f5067dbe89338b37a1d82219554d299426f08ded46d1bd983ffc16a5c7040c54573ee087a2d48c168ae7f01b84437fff236f8ef362435acdce2f72" },
                { "az", "b180040a187edd95675e74905fd42a12b56c1f8c52464e10477ffe6f5b17a91fda90f80da186c42e437d966db00e6c3bdec1a0565b0a1e7010a6a47b3aa591be" },
                { "be", "9f6ce0085bc9a60086a4e9d8719d5ba618e001dd2cf70024e5cb33b5261c48ad2fa477e77ca8e41e6d9536f145e56fcf9e7f07bd1584dda2b60f12477f3e6a03" },
                { "bg", "d8cfcfa20a727c7714eedd4cc49190837c2bf3de37544c5195150939f427ceaaa226fbcbece218b8fa7ca7e99128d8e2598b9673ee77b80fec10c4a1a2c7b2e8" },
                { "bn", "90a0ac686ee130605c5f8168940f8fcca5af434fbb4698f0b18941dc46e46830115fd787e22e9ea7353231afa73045be9101252093febf87f1cd92e9ba5d0442" },
                { "br", "9b468ea18ade0d5214de8bd9267445b07b33390c586f6a86815069baca7b26a86ec15908c52b06d1671478d337d20ffb6f4eaf114e3a0ffead97c2508be1b99d" },
                { "bs", "3eaf71a649216b84e649980f67bed6707023ce2801b16bdb46a3af65637b1af5c1fa1b8eec8b49220517439a5992b05d01c91758f51dfb7a09f8a80e50cfe23d" },
                { "ca", "f43a0f7055008f49851d8334accced2e912be8c4b0845cadd7cb662e8ce96c5c2384b1bd47442a1a88987b7d1a164b7e2b89818c459f57f54b77fa6958f97743" },
                { "cak", "532ea219f2b37b7fcc04f9f26a945386d58d19cda1d70936099b682596b2eb24a9792fc92a66095c24fa671e8a422060f9c36f30c72fc2fd015ffa2616a2ea2b" },
                { "cs", "ce33320e117d09fcad9e62d472da19a71069ae60aa411fe414a5d0472e1b14918744fcb4578e5499e233aac1c15969eb96e68e53bdddec27b93881c80ac01421" },
                { "cy", "730eaa6ba297fd498aed4ff058e80522fa8d92f873ead45f27b041131f44c75c2b26ca06544e8cae31ab2f002906ad2db6da8ab27a23853a77b3f55b00f55c38" },
                { "da", "735f67f2a692600acb8af780cec8be20e6a9a47d8b9f41ab79d185e5d41a0cfc614f5df94e0becf6e16f714244c714820f34a16ef555b832128f50ee44facef9" },
                { "de", "520a4a0c624edce4612599146d5d885f9ad8107af1c4d239abe9853274be796ca8ff9bcf922310894bb646e49606330cb2f98f21d6f290a8844833cb3ec08f36" },
                { "dsb", "04e62e547bdc4624e534cf10d4cb0394c85925c9eb85fc60d818a7e691efd8b022efe766cb2e03f2a1542b6e298ad262270fbcb1ca812dff1049c79d58735709" },
                { "el", "f85ee41cbc2d75084e80c8be5f8b9db4ee6e3d1ec1e9f378ba9cd57a91fe409e6e035a26d6dd868d01691babc0da24391fcae4c2a73481f6438da7f19fedfe75" },
                { "en-CA", "af748ebbaf60fd0fc54c8216543233f00d224ed0665c472c1b5937d6fb1c3e92fa17384d82ee4c6926c3d8e809832ad5c47b79acafcbd07916f813b154c169db" },
                { "en-GB", "e76cfdfd8b240aaee8f28a40138d6c7266e1852bd760c27c409136edc46fb36c07c7b74878dd763a195235b831c2df82f9c96fa77142b4a7a2b0b015ec358e7b" },
                { "en-US", "1fd537ee042404bdc283cfe6532a7e0c2143cc1a35c0c4011a735b03927766d8990ad1dd463894ae6d87697fd0f9d657afe98ff91053347de07a28860dae373c" },
                { "eo", "40136da1884654e70c254017ec79dc1a4782cf8855847b75ffd6e27cc245ab2f4c14fe1a2484eee23848f88c859401dff89a3df2858a7707823e0b614e80aa60" },
                { "es-AR", "74791a65c9c013a82a9b17e7485efad8d8b8f91153f4e3cd3f64a21e0dfe3f113e2bc5d1bf6413ad8cdcd1588657bed5f5ef5fe385c5d61f29b320189a931ecd" },
                { "es-CL", "76ad0ec747c9745d11aaae7a08b6cbd62efff0ed0bd8bcf084a4eaa8acd0cf034853d7c64f19a5303de912a90659a90509aa6552b9965a807a16c95eb6876315" },
                { "es-ES", "737b48eaf0454402de60e261231788d25d52e025d4296e41e47fca0cc690e20fb0464d21a0902b84daf0f045cdac2e729f7bdc6959ebf7de130c444b9abe71ee" },
                { "es-MX", "377a42caefe0d141747c49585be430cab7dbb03123ff1eb74e2516cc932a431908edff7da5c19ac538bbb96569ab92e82000860500552d32bd1099aa0f524f3f" },
                { "et", "498c86c3b1e73089fdf03f893af10a58bad3c15daae522566a489783b888ade77da83bced9f4dbb0204bb5ddcca759a30b319da5c3aec2a7b69112eaaf6f93ae" },
                { "eu", "81a93bc4e03cdfca0af74bc1be74d3251ad85f88720440f23d90144fd87c28d41922b7f6c2b0002a749159ead476b72ef37604344f782fb9ec839ecc75fb4d3e" },
                { "fa", "cbead8678c8eeb5cecb643a3e42c251e11a97bb7e01440550fcebbce9a3652b3e9b9beabcaf98255075b5edc7886ce4fb9affd3eb2be249194e6f05223509a7c" },
                { "ff", "e92b40a4b6dcad25824b73e3ebae92bee4a82a09d3ef3ab4e26aabe649eef3a028982064e56829f7104bdac74a96a1101d4bc650681ec54f913dff4f2acb09ac" },
                { "fi", "d85d2ebe69e048a100cb91feadce14a3c7ef035d28cf8d1d29179c47fba875e95dfe7535b682502cd02516ac72b8629a686f962a59afec381c46df92b0c07598" },
                { "fr", "a30e42459dcce39c7a6f0c0e53d6c0d44bc11966ccf5c116befe1dc1d9f26ebc0e5850cc8851704cc8596d713db20aca45ee5b2e81f32d067886e4dc5e68659f" },
                { "fur", "432e6f05f55953c61ef229565551bdd382ccdedb79a27694e58f34f1b63ea18a9255d8c349b44e39f823124fa6d1fd7da1a7379c815ca8c8bc56c77e30e9e92d" },
                { "fy-NL", "07c3b6c333b44fe895440093fe60461c66dbfb37ab9c39619ded3cb35b1542527678a94173af067161edf30dd912dc69cdf3b726c37fd111f01e5349c2071286" },
                { "ga-IE", "c87baef9ebb2169f7a467f2258f19a08a157d0f4a79c15a6a6287a55c60a1a683776d5eda6898a9d151d6da4b7ff858b577420702e0d3d37abc866ac331e15ad" },
                { "gd", "bbdcdcd9718bac99147c7ee912068b0835973e274061c4f475af64ddbead02d256473628d3686a0c294507464cd86bea0748b93f4ca84230a8ffca40cef70e9b" },
                { "gl", "4edb9e789a2fc0cb0c3c287c22ab8845ebd269ba647d7a479774aac02278d4c3708208730b2e25f32b2d62baee8809d624a255f9e4462d4f25a8e6fdf76849b8" },
                { "gn", "8353d5b72d25716f186f3c63cc861c07b9d55b2e8860bf973d911dcec551dd07540ecec46ef31cd7e50b563af45212b2748276f8c31058f4c84b6dc4754a9eed" },
                { "gu-IN", "d5b2f4c91834892f67dad9b9d4f22c8afdb703f2a6e42e6044a22e559bb18628cd54893c5d9f825c7dfe4ce81be71bcf506dce98a4ac555c4b065fc6372b579a" },
                { "he", "a803132fd692e4f9b855da4bb5782ea19d3fcec849b9ecfdf7c8f8c91eab59608d4fb5f803a178c8613a9c1806d8795070086f38e45ffa3fe1ca1cb539344535" },
                { "hi-IN", "e0e9beb69c44ce1ef32db57c5ee848e65453a792c52a9e7bb6622bc8f8074945b2f9cb4de8b8a358c5b71de7c725ba2bb5e75ee5fdec561582bad393dc63db47" },
                { "hr", "7c28139ea39a4650c71ea09e4cc204c3dc025d56fbbe89b153cf154208d097786e106a2c975fe79eca5cf1dd6f8268b4f24bb9dbd80cc6ca99fa254e65cc1be3" },
                { "hsb", "de0feb3bf33c1b84b4ac03186c9632c1cca2bfba3a8fe66e1841b7c77ef983efcd1c42c395df59f377bab92d11195e5e4608bc685b3ade66069707427a53ad7a" },
                { "hu", "4f72f281995531498411ca65dafd262f371e1c5bdf5332d90d5c98ff0e4ea2f2a3528b2bf0187e420383826fefe4e053a120c32bcbc6742e0653279cadb36d73" },
                { "hy-AM", "bbde46629d6115c47349358f2bb71babf47f05176d7343287e6c0fb59e5a2d11a2139cad5ccb91023c06dd52de5a6164c2ca99de96dd16f3093395320228892e" },
                { "ia", "28653707162bd470b3672ffd59f1146254707d771ae89163d444773d118b1c69a29681b9b55f03d4c855e4c281b76a937b956a940f3e782d911f966beac70a7f" },
                { "id", "e8c7210ee5a421ff403b995fdd54ab7e5c0b82032a63e01b70369df863affd90322cb5b6db01ff09a3c0afe292072c42fdd57aedf67903983d49336573e65332" },
                { "is", "f3504b89a4da2c637e1c67a79b23ec8ce66b2742d61bb1c0ecbc8aecfa0bdcd46f776ceac362bc577d483b29eb54cfeb4d8bd9eab4f6b9d112154bf011591d23" },
                { "it", "7e769a47fba92f8e3bad66ed87b82c7ab075c91220986ee3acc0fd7922bbe27b98efa4ebba97436bd42da1eacd4ff5aee31959a88567ac030fe5728316683307" },
                { "ja", "7c6fe61492d348375fc635a641d47e7cd283304cc132dc145d37c0af1db9f648bf3364fd0785749c6bfdad34d7e9a1cdd108442cd78b44efa38d8c8c803c0cf3" },
                { "ka", "718ce9233e9ed1b19da7b9b94942a51503be3914d9288a28433efe6db81cfee0312bf3f022a6064f2da7eb11ecd46a0b31ad719c4d8c4075eba6613ec2abefd1" },
                { "kab", "3d6b3d8853d49a90d2b7b0c444b1ad7a6d222cb046798b84d88199f34dfdc7353d3eddea51476e73b75043257370e6c4a383e262e4bc69eb1a90a9f19179f5cc" },
                { "kk", "a6efe14fbf01a15efaa835107ff13c05ae695add2a06e3b1b6933242c5821fcb42142f0c4fa497c1a474ae2d47b024c91de2e80dc9b4468237d8770e0797ff67" },
                { "km", "7c04ed30bb2c6579cfe05df7edeb6dd561435ef8fc71f48c2031bd590015175f5ad3831a0f3eb69902f303b63726fb90aa4ef8796522e51aaf6a98584fca50e4" },
                { "kn", "652979fba9377f75f1dd0e217247c7856663db92e205b30beba1acda99f7199613f082c34dee3aaa53d64c14db1865fddd42ab7b1db50c2b10b0765537643ac3" },
                { "ko", "e93f0fa0a23e8fbb4bce4ba3d7ef4680252bcb9380a770c4ef2a15165a24d951c7e41a00be43ab5f8609b28e0b271cb35affc684a3bb77f26740e7e21226c408" },
                { "lij", "44a348d6b6e8b811d56919b622da1fd64e75c8304912f3a7165a96dfd3a5c8e682c59d6f2582781381262de170d303c3cc7c9e50241e05c4eef4f6f2435c8d92" },
                { "lt", "dde1de4bfa1a33272052d07d763713568e27e9908f127a0537a40691057386ccbe03af2d8d9ea9457439f9a3fb9a9801d24cdceb76df30f9561ff54b7a23fce7" },
                { "lv", "396cf53afcb336a0dcb7396720e62bc8cca3e7070d113490b7328746e63b348716d33d2e7cd3e2cbe915dff36b0617d0cf3478f0458e7e0ba079e05c0d38e87a" },
                { "mk", "028c3f346669fdef0f0aa095b2a2800c1000562b9dde0e0ec9d64b249bbc302558a94543306de692c3963cc8b848556d0939437b83d4d619b01c4d30acd29e4a" },
                { "mr", "fecac667c076092d3e78eae9af570a7dd767f783eea03a0f4351ed37ac8e7b9daff5131cc76022f891dcfcd2915710b593579f8d84c67be08a95952d2ff7013d" },
                { "ms", "90080196782388b0c1b28e3e5814465641bb3861f56b6518e48ebfd1612c0dda9bbc32cfcb6d71a9a8e9aa6a4c59fc6f70b02069eb0d8faf19b1c827688e1d0a" },
                { "my", "7a5f22e4de8807d1ed59a67c8f1228c6920833c55154fefa052180c00bd7ba4a6035609322cab6252584d3e3c47aea2776e601762d00cfcf400042d36972bcc6" },
                { "nb-NO", "94b9756fa9f37ea548428ae806f3e7ac70baa548bbebe99e19052cda42964ae18f7212f0fdcf12ac9a2dea23981a3813f3efc808d34d879b12ab852ebf6d2004" },
                { "ne-NP", "91e0d9b8c1e704510f27ae29cf3bade047fcd80f1da95188be53a32bbe5ffdb1967c44b63803d8bbabfba92a792ff16827dd393378ab3edd59e4afd00ae28afa" },
                { "nl", "4fa89fc9197ef572186e9a8fd51f31e6c6106db7c538272c6543369a2f0ed4ba1a363b31aaab4760adde678b2615bd5418f82fd45a91f2622032f862a1c99bcd" },
                { "nn-NO", "cacef8943009457ad8c474b1d083291514cef12d5c2b0b7e8849e22f41bda40fb5d7f4806e896eee51c6fe897dd216866618db2b5cb120b6ec615881ec74ea98" },
                { "oc", "91e97466dda7f8ebf210d7436ba0ba1abd7f33d7fd05213d1eb86f94689ed7c5e267d555d3decd97f4bff059daead1d4e61206736486429869f61bc538654c6b" },
                { "pa-IN", "85dae314277d85f00e84e3cc13af644f72a752a1bd0d410b65720f64bc15022c7e020417b69f9c0ae6e207752c43a1cecdfb4c41d312092091c88af6bf67394c" },
                { "pl", "ea1bfb21f9b5478320886b9fa00804f0910a7fedff4ef9d059a391e15db27357e978ce05bd6e999fd1cd47156936a6b8636c178f696d1fd9ddbc6800156c6b33" },
                { "pt-BR", "febfacd90fb40a03fb0890ed0765e5498aee345b6c320074c5791262a6fa34f75e2048764d78f461c7a93d3cb45558d9edb09633c6ffaa0ffde70040302479ce" },
                { "pt-PT", "bf0aafb1e72409f4e337b25177550cb9dc334fc87d88f9e6a0abefd59027664e1ec2b91dc5fa96fa4d556da275a83cecb226c2d0e973c31b6a47e0181c1e5e87" },
                { "rm", "6f67c487823572626c06ca939006e447af23705058de0759713e8ea835454feb69c367d175ca3b1e33f5c793e4e9f8f7a890401e9872e6acb8f61338f441bfc1" },
                { "ro", "05e3dd83ac0735b586e750b88d12df26246a5c9aae31c52909dc6c5a76bcacbeee7244f68963ac5e67aae790f3a3ffeb291bad22c4e9c2927fb91d9ee1054a64" },
                { "ru", "be1a79841b70723a8e43e9f3ac4098eb250a4d5689499ee32436557692cd18b6ee3f9b909262b6d4cbf80a65465785812f3d82ceec28fb74a60c588507e23ce5" },
                { "sat", "143ce1b9ae2092430c61447dd0c7c9c478150c4ac8f34bc4e52bc4900eb45c64a10a30d77850d983c603ad27cb45dff4efd2150b824c98e32e06ba23e5099977" },
                { "sc", "80e0f31fc1515727d96a5679824bf3761288a69aabd7d409871aa3ca4032eb21d6bdae5d19082eae390b3fd2cc8143d4de111daebdaa875f099b8824e40ee7bd" },
                { "sco", "7e40182c43ee7ddab767578d537a73c98a9fabc5840cc3ac2c90f2049e788e1424df883455e86d23f28be4b5868228777e18b5a0af9fd692d201584ebf7b1f73" },
                { "si", "644c3f65aef53dad0bf9e2cfa0ed048383eb01589be89d2e65964f61d1231158a832d1c0379d9825739c6783e91643f5539de962fa05425a369025e2ed402dfd" },
                { "sk", "d7267bf425cda3ce43a76ce4d42c501adfcbccd398e584fc4c6f6d67351e0cf02907be982a23e34dac60b362b524bec31b02e1e2cdf8d8b948aac94720d9833b" },
                { "skr", "9920e16529bef4a9fa4089e55090970fcf376da70318cf416fb0a18e539fc6f54cb19e02888e04a9107bd7edc4c0d7ddf10b941a4f63a22c28f317a1d98927a4" },
                { "sl", "16890f2bfc31b17d77627e3725c2cf296c8f52ced78a4ad5ab5673d8dd436cdb7be5f1a1f2644a25a14cae09347b5831dfeaa0c4c8ac434b64b38727dba3c184" },
                { "son", "6ce0627a76f546d805b5e94f4a5746dfc492dd587da1f09114ff4ef9764f5c1221062312c723d5fd34c3d678a8f695a2fb86b2312a683b27566d735293032b8d" },
                { "sq", "b7ac87f01ec07eab0646119338530a55ad7eba7a415fb8c3f932b576cd63a4c258c9b9c0c5b3a69f523c3f1c0be3fe4d7982379198724f0219e840748aba9a75" },
                { "sr", "598f524e12f52c84ad8954c36ad3352525aa5517ad27fc097257e14fbd83442cb4211b3aa630b189d3fb529457a7ae0184a0ae3b9eccd316037e95401f3fb667" },
                { "sv-SE", "7d82cc061a99a779cea2e0b22f6881e974f0311a89ef3bf19e86ee04550a8fac39b2d4bb9eceb59650de3646e4492bbc3cae003c44e79b53de51661e7508cab4" },
                { "szl", "c52e85a1c1c2723b061565d5beda1b4ec9a909aba8ca73449564176fbd969f274bd745f7c7b2e022128cede1cccfa3b5fd2a46ade23f8bce6b1825d5904083e9" },
                { "ta", "2f4538c22d24b20bd62b9e913007efcf399a3e4be37464eb48df08a6110520c3df2aafe39e00a0ddec6c6e41072faa41f9007bc131c6332db37c7688fa4d7fd4" },
                { "te", "c21ac2dab1510c3348caf3fb3a5d6257e67ed3966004abe33c446756921edeb570b8ab30939643953329825d7e19acc0a9476b769b4f2a334d4bfc6a192d8b83" },
                { "tg", "105618398c61fde3fa7975ceb19c44e3794fa4e2bfce7285321743dab887f31843ec6bff3a0d4b990c4e179c1a13ea95b3f1e926fd818ec83a1aa0072c557d7e" },
                { "th", "315dc4d0d60100be6c847c276108168232471cdee0c77f1e86c39b3ad291e04dd22fdfbe8400440d9cee797638abd3625c60cfbb4e5f478bb9866e6c69b4f291" },
                { "tl", "c892b30b113cc95889a5221380128647e37e4e198f2de058ce1c138a7ef839b91f9a68ea704bcb2ee52c7eea0e467b899f318b66d55e9ab7dfca4f9d3d6c72d9" },
                { "tr", "7d48c36e831f01e83027aaba63c3a25633b456514c6018c8b7baf1c588df585cc0ebe2ab7e488c1827858da57be976a4f5fb1acaff14ff1581e3d176e3c95887" },
                { "trs", "b2678db171a94fb8c62563c7112a218745493458836b6fc347359a5e6ffbae6d95d6cd089e8762b137259aeb50757d9fcabb1d50d72061d80c39456ed918c7da" },
                { "uk", "958bdf3b0f5a6f9c42fd3d1a02b5bd512274376517334f5a927a1adda94e18226a7189de2076d5af8c030f14bcbeba2ad3de93c92dc6aff87eb249ed5e812706" },
                { "ur", "51e990fde750cf665d03d60d2f0ba1bf333df0518b33b9202294e6bf03a2f321745c011cbdb79404137d543829b2228d3f5e43ba7589cf1d15918b9dc615e059" },
                { "uz", "f782b89499d997c1f10e9ec4cc8f76c4dbfac290eaabace908f32cea7bfae6ee1c3f4e25c8ab0c85fd7ede7fc6ec4bad897420f0c514f11ff0304f9d70b5350b" },
                { "vi", "eff480919c3844c949ba64c7dfc92097cf37b5779cd2852ce70679b63a9901224221aa23ffd0edf06c756df969cfe416a6fb0e621a6cd3b7accbad2a6f0882f0" },
                { "xh", "f87910144cff1c67aa07a3afd48cc442dab72d162f8f6197b984e807cc5fe3925da55407c6fc9a8d085eb74c4ff7b0c3b06966ae11c8a9473376ee1c0592b5c6" },
                { "zh-CN", "8b60dec70c1c364cf50b1ea0420c0c086bf436bafd48c78d1a6f9417fa7769f604a0f90b1d78f46e22fa53a1f4d2e674e8080ce6c5bc544e34636c6dd6b1c8b8" },
                { "zh-TW", "395f489617a61db011f006f5eb8bc4d86af24ecb241a552219a2b0a9e5f71f393433a0d7f376852d173c276dc71ed5c1ae15b9ad82d7369851eab7ced548a991" }
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
