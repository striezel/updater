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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.3.1esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "6bdd8792eb73a2c03d342827f3f49785d54caf7afeb54ad80b1eccf1ab2dda26c93c559df137f524614495ff14985c6b7859045ff233f2388482a4834df5c80d" },
                { "af", "f87933d6ea5698279963386f6f75628085ab1aecbb5e180bb5753e2960af8a661a9b4fc51536d04bdbab4195f8fe7e2d449590a2f7a9c836d8063e33c3d3dd89" },
                { "an", "4539fcfacd83c3b760bc99d16a410ed0538179fe50dc41f4411f7d0cc7d1ba0818c8264af21f680cc1464fca79dd69df6f154b9d89ab6da44e27406ec6c92cd8" },
                { "ar", "b25baf4983695ab05ac574e3a545b94575a294072ed0f00249ac5133ecc31429471698ac43318e6541ca99a73321a0fb701ddb89f4cf8806d6875b63feb631f7" },
                { "ast", "2853da7f9650d286053791c9815187b5239e050306f9c5f603f78a11bb414eb6066234a64595d7e1470fb1aca64824877271523625554c372de873a2a793931d" },
                { "az", "b495fab4fbba8fd9d0e2b9fa3c047ab6d21181956ed358d074e1e4ddea83087ab501c17988b38f1dcf3d2e32690b54b0558113af9a01142b1f85ff32fc8a8d4a" },
                { "be", "701804bba3c6cd0c270350c610c2b996c6a3f479fac7e47992cad8acf07a8808ee9c67e2b8028180ffe1013384d6eae1fd1f37c98baea342263c031d5923e66f" },
                { "bg", "85a455e87807282a61e2f4d981ca9a9b5582f13ebe81403c2d904c9148cd99fe98a70f4db9b0b8bbe3c1cad50cd077b9c1177e9301220f9a8053bd95d083362d" },
                { "bn", "467706b9ec6a594997e8fff1247aa0a77cd657c101a3c4137475f6515f96b7b77f41cd775538422c2ad619710a467ec3ec015e92911a47cf9401123690ca4e3d" },
                { "br", "f322684d6d06815320c8bfff22cec36ad99356a1e6b1909a21fcc7e70e67da4cf536091bc88ce63d122773a86aa9ebae5c89d3e434270e31834f5f638537f083" },
                { "bs", "6de6e23b637fc4c0d2abaaac6552a431fb2d7e04f2e4171aa9a3631a8bb3d5fd5aee3c2192cdfcbb6b50cfbbfbd8a021d31df78fa2643176ade0c06679249abe" },
                { "ca", "b881774e8b611ccc1f0c2c7753d5272d3857956e8281b24988050fc14bcc1210ea8f112a2dc49d76a66b3a1d5d8778d654e13a02639e5b7481317c6e2d7ad7d9" },
                { "cak", "fc1894d46ba50e5f48d563d054a123fdbad7bac6bc66f13385f02730573935b6ccdced3c85f77ec109ea6b8959f0b551bc8eebaa1ea8a8c028b06a9f9de04771" },
                { "cs", "3c85edaf70823f1415cd3c5c6575e71dd626154864f89a5fd0ce7edea83ed201dd8db5e3b19dc3cdaa865080bd84debe51215666a2bac35a7562fec212d8f499" },
                { "cy", "ddff9a8da3bc7c5e8570dca139679b5af698cf6f0ed4ddffa2f7d64e533a5d52ed7ede7a9977c9d5945d14efef91c14a72a021704301bdce7d251b763e5fe229" },
                { "da", "610756de4c2dab617928e739d0e370677d83b9ea6ec7b519b4a8b61e8bba0bb598bafd721bced622d790368d677e52ef12c358de776dfb626bbdd081c7224849" },
                { "de", "68b7ca2172f9de93bbbd04adf5c596c5f282834b1eb46f0aebb34d2dee7d1ea0b9282b6129afccc3f3d81f240d382c750665e67d6173747fd4adf9f353e324b7" },
                { "dsb", "34f706410a0f2e8897176885eb3f1a0901922cb6e82533f3a6cec8d30ee8128d108e81b6b54ca00cf1cedb8d4e4da91fbc533733ae0b8208b4c70beb3ea7504e" },
                { "el", "976b1fda17cd7644ec9e41ba3b281ce4fbcc1d1b4e3858b893c36bd2f22e18d0be5990f4eca4f6e4a126b0d129a9fa81df93e0e5384442fe6a548d9fa9280007" },
                { "en-CA", "5382999d0516cbe69be34d0abce502b4adf68ee66a3874313082a6cdcb15007bae0495df0b3e3f118c5ae1478d9750c71a1e1e535ae1b8aaeeae494238d6b881" },
                { "en-GB", "2d0cd9a528ef061158eedb6dff722ad1070b1450373de686cea352e0f34b1681b16b6bfe5fa1db33739e9553b2795ee0a8dbd316cb4c4e710e007e484472a539" },
                { "en-US", "40560ace0db96f34d91a4e6a5c414bcab554a54d7e0a3a953a32951fe8f75bceafbed3a9125543f1238e0b8383d3a487a5a95379bbecf500854d0b9d81ce2649" },
                { "eo", "39bc35856594a4f23f4dfc1fc8a696d8382c1a03b04929b1273f994b127c136e6bf2ae1d11db6f1b88d30585ddbc084736a5eb7e998a77b7320032906e5fe3e0" },
                { "es-AR", "5c59a162b5bf21a261412dda9d3b47e0b87223ccac97282d73813562c858e51389fefb72c5fb9269346563fed10b63041b520deeefebe701bf196f4480d2cf35" },
                { "es-CL", "3bbbd64b47521d6cc95b7e7180fa73b624ef946ed28c51d2c4124ef3dd00afb78ab667b3b048b0c38e027bb326922596aa32bffe5ee47c17cfef97c8a1b43270" },
                { "es-ES", "f236e6f23b4c0c0f933a4b88ba4059da65808eb5f3eb86ec15193cad932fb356c81206f90396742e69b56a10626fe6300ba5ecb3157b65b369c9bfae1acff175" },
                { "es-MX", "3f23d691a81d0f5c6eaa72259dab9df422f2da7fd9914e8adb878142fd332ad6ef32f4db7ba579b4398a91b2267e93c3c79e8a195d966d71771d26795f0e2edd" },
                { "et", "e41e29d10c24d10b4cdf5bfd3123a55fe318e15ddeb3cb4b88b0defa961ffec22ee3e2d3bd0e5adeda28469f72ae24a18bf7e28c53db3531018c1a0526aa6f4c" },
                { "eu", "b6d4056665c578b308dcd91faa8be14fc81ae503b0e3f11660281bfd3542ea72a4ac3f70fdf72ecfdff518b26d199c13642dd4b2bbdfb0c503a7f4db9cd17838" },
                { "fa", "b5187790a9a3826f67a56e402530b51d705719ad54217836efc70a8227fc5f93338f4eab2a6c13725b24ae0e5f4a6f952ef37b3419622beaa13e5fb1379943dd" },
                { "ff", "52daaa954aca28652934297df2eab6b0e93e7ae8e1ba6a7bf57bbc29b02c46b23d7d1547ebe04a6f016ee69e25950fefc211c4ecd82849686f92fb9fe5e97024" },
                { "fi", "bc97442c321e682d7c2e6babffd397fcfd45338dbfe4e89048789e9f9cce394ddae5d4ed4bd62ea2b3e80fb05c1b79d96a3f05e2f9dd8ef10d3b56ee83d16a79" },
                { "fr", "11c1883e8bbb60df07b424ee43635b7316711239dae2658663bb222b15ee8ffecf14460c931d268921eead1a5e721dde9dd15abb7eb46357016ccd43f1747b39" },
                { "fur", "7369994a0e63bd879d7d7a9b2e2779b69dee2f402b5b97bf8a7ec4ebaaf1b5c073e5a1c43bfc7847c4d6b9c224eb39d6aaee20b79369d6d7b34836a078d0f673" },
                { "fy-NL", "958b82d8a1818f2dc410e604707810f609e919e5b8dcdee3d2eb3824744f6ecc39fdf4565a974d3fbdeae76071d33eb3387b4da6299ace209d11383b673036c4" },
                { "ga-IE", "f437883a0f8fce542ae1548dfc5081ba9a0d8f68921984153e5c89369fc62e813707af358121e853361429f605e242155666734aca9a8e745b589d33f822a231" },
                { "gd", "efa1800f90214858aca559b061ceab42687a667c3e80f5ad8b2a28ebf224411d6ba0a17d2f3d840231655e96671b53a5faedd94eba71c6bc0efe2c82de9c7d84" },
                { "gl", "56c724d5692e9b16b7dbe01c5c31741905dcf5131a713950627214015bb2910f57150d23c86ad5429c527e11e85bcab8b2018bb674466fc6dcb96b67f3041f85" },
                { "gn", "da6cde4dab89e388d0aac19d3ef7be1b279ebb5db36c28774309206cc7aa129cec8b745365d40b79a3a9f66b0dc7dbee22a223b2042133c61588d6aaf5e2e1f8" },
                { "gu-IN", "d3450544452e472c66d4bb1a2d115115b99b7e6be5e744510a763fc2349602479d691af298cc1e5b8987cc2220333fee0c452557ad09571210b4da43ca996616" },
                { "he", "4d081b1fda3405b341db957c56864a6ac92ea2fc1307a326ab7f9cc21898069c224892d429d3a397d7e5ffa30fe93220b732ee62b78d7f3a1d6d11ba653c4b24" },
                { "hi-IN", "854e6f9c077bf3e93d61f8c19076199e5aabddf6bf09716d4a64ae4538a77f08b03efeb462faa519a52642b36acad9fdad424f2e2816ecd8eb79dea5127ef9b9" },
                { "hr", "ce179c585b31a6f76d342a23d312d625c438b09a984a0b609d88a2236d1ca0cb2a791bbe277e9993ad35293274725748016f857cd61da8227056b1855ca57d82" },
                { "hsb", "e1027b0a1a7f26e11ae08be77a0a1b001cab334ed02e3448c22f42daa09021aa6098d459c257c6b8da87fa7ae7249b40f67eb5c95c9c3e80d5c894870e42a4d0" },
                { "hu", "b01e1b4b418fa62c350e6ed6fb0f91193d7cf4bb7cc4935652ef5c53dad94643ae8b1a9573ca3fa7c5041f90a068258cd114227b183df9f9d2bb1a4988e92297" },
                { "hy-AM", "f36530ab154a3a4917641e9d12682c758ea9f6080ed917d6e3ef05b39f007c71ae72416748bd22ed2ebc5a365288af6783716b226b1f14a62c7fb5cb57bb2c32" },
                { "ia", "1b63e622048b25da123d26a11a5898153e140029c5a11b03d8d1a5ceab8466dc1e7c29a67c0f320c9250f7294e754fb7979ff37a947c51dd1b85186a5ff6eaee" },
                { "id", "397277c79571298c591c6adb338c2a0f8e6e1b5403bee528a4f5507f9e7013de509ef390fc8ee7cdf285aac30b4f3522119871984634f9d0031e66780baab3c3" },
                { "is", "dd2e9d90444b8cf4ccbbce28a1e81bc2d6f72833278772c7b306e804161e58b0718ea5ff3a7acf9f043b56c9a03c09ea606af0b34789269698634c6e4c3aa321" },
                { "it", "14e1f33ff63b228b067b1b70a279df4fd52d517ed7b7185762f8a5209e9dfbb17a68fa4c417f9bfaf276ac1b1638899d2cd248358cca748232dba0e87e73efdf" },
                { "ja", "5aa7b9cabd8ee905268dd8bf38f5c269b600f8a1905f6b6fda5d3eacc30b8abac15606e40b0289db443cc683ab90870cce21fee4fd91224c0e83c43393f3d67c" },
                { "ka", "815928b8f24c82c3c23ccb73e9cc680fe0fa7fdd79b55ec9e47758585fe76df00894a9f494aaf30c10305f2c9352cd9456ae6f7b94ee4818c2500af6033d0c7c" },
                { "kab", "1a762e712e16dcd31c05edf3c3b56ab7f669dcfdeec9091031efa964800341beec3493bee767c770639bbe7487cb4c96e3c6571a82e6059deb172c501a957851" },
                { "kk", "075e24de65ce0efc8699a0d74dcc1512b7acd7aaca275297f00494074eb7c45b98151b1615280e26054cf3a231e5e4388ec5e2d059a4db6361be79f7f4c4133d" },
                { "km", "9bd6eaaf873c252782d8eda2ad74510570e5505ff98523fb43be3d2aa354302cb10fd90f0d70d17d710793c03ff467bbdeffbc2c47cb2fd96bb9958fd460b45b" },
                { "kn", "d939b073a9a93e0f339b09bb4a3166bd8147bea5913faac3a451bbe8f39d43429d83c9f489b2bd48c5b082b0a4bc6ce833610bd59a8a9cbbb79e31c80676a62c" },
                { "ko", "3467f126a861a705a83dd4c5825d2475f76e3b4c4592eab5f13042d238f8c66d4920f12d29fd6b2238a140f5c6e87009617c9d6da295bac505cdbf4e61040222" },
                { "lij", "202592722c0a0cffb6ee50a225c7a4896c6e9396d2a7c28ab6381643187a2c249a01eaed87ddceb39e6261df101c1f493afe38663ebfdbe45a909333f68487e8" },
                { "lt", "52f020079c7e25ea18d5807a121b9298f9765208ee34e3bc845811c84c07b669b6e56585e32edeed35b233679f338b9beaf4c42e6fed0e5f3e06afe535b549fb" },
                { "lv", "53b0316f0d4c669232b39b9f551bfbdd95ea4ac707c3ed9b1a32a18dee85cd2d5e427672a5af0f6ce6fcfe6d09f15c50b67784c707265ca2025c067dd394cdd7" },
                { "mk", "7a6964dc091a8f7bc2603d6a1f89ff76958ed84e49476d725750d205c590d70839e1488d2b7919f4b25f271775dcc5c3d18511ebe4b5fc8902fbb8dc3874523c" },
                { "mr", "c5168c8dc8f622484718c465588b91ddaa40b41d550636f64b88ce3e148ef10f168298dc62ae2f98655dbd6aad4b0b141b002cdfe44f0a48f64b86e834fe411f" },
                { "ms", "147a0c8b8076ccacf10a0ed9468ee818a3bd3df6a8c9c2722b091a7f440f4cd5897acc32b5ba412f80c82840967a8656f010b2f0dede694b80e352c2a11976de" },
                { "my", "b9ff18dc2f12784e4028ad0328b5eb317230519e56ea4715368e18626d9b18c2dc9c8768ffe1df0f417fae8a876eda371a5a6b8757ee8525da6bf20ae5f71746" },
                { "nb-NO", "fce6b82d7b21b9c2da1e7c6b007e31a30e083342d8df11531d2bfe1d546a5f3dd01a297f329a345e12debd8abdcd08a3651b04b0aaf99f6ffae903e328903aca" },
                { "ne-NP", "19d58093ca5d69eac0a54eb62d650273d9d52a052565a9fb4e509b599f8c8d05269c54515b8d3774282d0446b8e0d7c840f38ee05116872f545da11190e893a5" },
                { "nl", "288325e5d729fe1b3baa1ec2613d303ddff7d1867bdca4ba1a887d99c449e97a65926322c30a0e3b57495e2a1908b5340fbe629d33ac6365a54ef3bfa357080b" },
                { "nn-NO", "5f4e325fb87d9d3b448ee2e61b05fdae019efe5110f7695a277584d498c4ecad6dadf20a37a0c186152224de611bb2026200e22faad53634ab26d76beea19a07" },
                { "oc", "13aa039d1efb4bcbf88eef25825112416a6707861645e3975378f8b5dda411a184ff01854f35597c295fbb0682c6a28324e7262e3f4d16602b5da501686e08db" },
                { "pa-IN", "8b02683fd2c0c9e649b057d6ada9779d836c302e0b14f18924e80c7a6db2f8c6d06c5bc57dc51e3a203f612fced6593b59d58fa6f2995c3165a1cbaf33d7b363" },
                { "pl", "976e2c9ad6da6403d0024abcd0acf481d0630306f46176670d30dc0176e13862a446529ff0de9850e14a954be630e54f1d20a7c4ea46ebd5e96e700b83b0846e" },
                { "pt-BR", "3e636935929ee5ae44aa7748e9bbf4ee0e16193134f24f63035b7dcec94152db023f679d1c11b5547c4a776adebf9c5eb0ff6c33683eb302799e59a265c24c55" },
                { "pt-PT", "1ec5ff33a0975619d25ecf0c4e0b63f2fac51afcf579eadb421d83a457a78d74ea4d9bfe0c4667f2f81363ff5b29f05087f0283d4ac2e22787e3ebe27c448e96" },
                { "rm", "0e87dda66a0589735d418b5bdfed24688aaa9d73f5f9919c991d03a29785131162af5ae8c2b5f2db73646e42607910b8cdb8ea9e54a0dec63664c557170c2dba" },
                { "ro", "d27521e3fe8b99114af64d27d79d67ae6f0d6e0a6448d8de059ab4bb4c3314476ef06cbc544b57ee4af57f3d58192592e0485cf7c4c5dd00258680c963ecbfe5" },
                { "ru", "c20cf1d400de9664c17f42562df72c9ed7da316877a62dcecc6485e54676de4a1dff031575aa84271c357bc97e33711e00d21777f139d12a17f1b03c9e1ff5fe" },
                { "sc", "0ba89f1ad2b39d97efea97dc24be01a068e65c324f79b231caf4d7f2c9a3b6a40f59523957824143522c941227b2c9bd1a481b5e9ab2fe7b40665e75e68d3b70" },
                { "sco", "79b3aa683189a1c3b4e3ae190ce26abbc91595626ab4a7e76e179df46a104195b3e01571abc274198ca7ff9dc5f53a35bca6c205a0be13058cc05f674bb56b5b" },
                { "si", "d95241e86ba3924613599eca6f243ecf9c2b13e2fdeb30ca43a45ed9b55d2a912b5f14e0c1bd46293137722e824dd80a99e3ddc741a293daca2ca486bb3160fd" },
                { "sk", "66829e6d9787554e1af6b481c82ac088429882fbf37915c0681ff2b0714cf6effa319708d280d8ba9493773afa6582c3c07534c521acfb83d8f6828f66805f53" },
                { "sl", "4d5b373481c62c4c20ae6726ac6f46d20df67ffaeba3fabfcde6b2985bd2a7c868cf43421521170b490b7e504786dccdcade14e372fe63d4cece5344ce31668b" },
                { "son", "1baeef2c4fcbbf1de794346eeec1e948ee43c06cf14f78deac6ab3320942ad91ed3288cac8650b95ff7cef08f13c5b0f1ada135fab7da3f260c54680c29c5d49" },
                { "sq", "929c0d4723842499da1b14511bbdf7956994a3ea3d72062fb7ba3e2d97adaa4d158d42d30654328833afde3a07b8ea71661bada16dafe8ad5b3e50640191a70d" },
                { "sr", "0ba3f8c189cfda736679f5fd69d656ea8422bbbd0380a7cd108532f3680f5833f1387ed510523c6dc7601c005530837ff5d045ac1af0fc6a3d954de2b91a7302" },
                { "sv-SE", "a86f3a1e993ce50abd21d1c4a5b0c739dfe7b9aa944d4496e52585b1bfa6f32a77f9724d0ebb32252490fcf9885c64edc303bcc75ef1651f0c05a442b0b08377" },
                { "szl", "ee01cc4d3023ed2e044c5aa49fe56c9a92f2b67e42652fc40cb1a3b648d6cf2f2a5287bf805f89112d22d1b7bd375dc451914b276a9ce9695193df300f0812d0" },
                { "ta", "2683db212f72cae7b9578d6e046872c34d94e76f87f078e58c81fc62f1485ecfc5dbcb5ede7152b0a3a305776c57f52e9a6a55c95c033be427f1644357d415a3" },
                { "te", "d1701884f7d08e750104bb708bc9c77207c6122d1dc016bf3afa9b26682e935ef194017a6db3d9e8c43d236bdcff41de831a3fb17789f3e6579c7aa1f26e5001" },
                { "tg", "82b1f0ce318be4418c9f32b202cc47cd13f21efa5c6d343562850b5a590d98fd6b01cbd0b9876088858f2a200f0a7842b5d5fab5ad87f53a8dc10ee0d950c606" },
                { "th", "de5dde2824abd0082cd6f07298d0995440a201b3f75213b028434c9320182c37f1607224d1a58454f4ab6663da2abeb8c683d17725f65d9da0eb322b28d1db71" },
                { "tl", "98b01c7db4ab374b4ba71d90ca8941621ff4ac9486fd5680948aa1dcd6e85ee8333582c950e9bcf731782891367474fa51f1156356a0b55506379f188d2a6025" },
                { "tr", "4d1d2c875bba444e58facc18b254ddc5714e28cfb8e39725cff22a9b459e2b0833badaeb2c6736ff2f6ff0a1f3994b196e762438de15898c41ebbdeae661dd25" },
                { "trs", "1ea81a35d1d19348bd814755f6ec54ac95fa7a9d55790adf66aba060e135fb0899d36a7b2738f85992d128a705d4f453969d9ad124831005c1ebe39e021ba481" },
                { "uk", "f97867ef036de1f3ec78b4e170a78940da97f4326bec8c72776d11b8d89eec9165a2cbf5341a1b2b6ff05726c603f9eaa686ee8d3900847a3763eb914711c5d9" },
                { "ur", "7c9f8291b77b4d15ac6cb6d8967750e2c07a0b522f0a012883dac40a8ffb398d4b54b63f251684f6c94dfddba4e5fb80f29c289708d3a78ebde4147be84400f2" },
                { "uz", "7889b2ce6a88c409433286194e1c1cc8d2c53bb18d3ed7e9e956dfb64dab2351529df991ae35076386b201a8d1ac3f077560e9165beb7e855ac3da9d14db2e62" },
                { "vi", "791abb5f81d1fc79a174428507d41a9fa3bbbf0156537b085c023d531c12df20eca2370ea3b8f661e1f4c8b3608f151e657c7f90922c262ae21661c8f6783a1f" },
                { "xh", "46184a7ced3f1d19f9d290365e39a2df204ec85b3ed0de20a69ebb66bb6b4f11af409931ad27e003431b8fe70c26dd0e4cc84f887cbaaed29679db119f884c36" },
                { "zh-CN", "d50611ed224ba9585f061047cd2a4706ef730d85d70e0388a1784a7bcf72500d906fd0a4be9153f85e1a53b2cb377d7e337b98e54e7ce44e22381f5a0c86cc25" },
                { "zh-TW", "5452dfe3f81e8f155b0c4f4e71777aebeaae74b11df2280a921e94a3a0f0fbd1028edfd99086e3a91ddf4c63a64c19a952c0a6be73d3957bee09fd979df6f29d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.3.1esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "1f7df83a68f82d0584e5d71f4b28cb7bdf88c86c4add604e4ff8b6346f6cf7847ced735f2badad71fd62d22c71afd6ea3a2b142f69a457b1d8367024952f08b7" },
                { "af", "788f772968102fa46e24740bbe29d56d8860cca9fdc323bd36cf9d0110165080207325caf4f2db269ac0f22402dd751b866b5785fbbed78977d0cb47aed314d9" },
                { "an", "36a9da32e96323f689038648713b6f6e385a208a1ef0de2cd83b3a2b4e9bb5181cbef80307ec7a877fcbbcb4620eaa8ae447d782d56e02554740d7e1884817b9" },
                { "ar", "30f72112c19611b76b3c99e0b7b254bf229fda295973e15926d80fc7c3ad1b27afd4486594ae29e00701cf22906c47e152a3c665da29d91064c6600f9226ec83" },
                { "ast", "6fdaad1e2532cd9f4693ac95330e8af59435d6dbd1838fbae276add3e6110bc0c054f9c5b8f2f19dd57869d40bd1e0cdb8a4ef1ebaa491dae6a0817f3003ecec" },
                { "az", "c2f25a43a03e75d14acf57e2b5bd425f1e47ad94be65ef5047f276b340a2ea512dc96a8b3924d9076ad6dacc6e6873a24307513de2d69c6500d6dea9dfca9236" },
                { "be", "1992be82bd620c10db1eebb81b3fee97a3d45e64ca42fd0ab2ce7578423e1327076fb4beb39e4328d91e96c14a4e0dadb35f7f172266420199b19ecf4b05a7fa" },
                { "bg", "e32f9cd9607548ec715553ad1bc1fb3e84c48612660f2072cf13253c6dcbd7f5f2d1ba11258058c39f0dce7da12f951ec408b6d17c5945dada281e456077a3c3" },
                { "bn", "7710ccc8f3599cbd84394624648425f7398e9139a834cd6464456e70b889df612eeb349cd8c28c4973d60d4615a662adeec9a5c6e7289f9d67c3ac47f8588140" },
                { "br", "171b2bd468c56d59f8688279281154e599200bed9664be75a998b21e471686cd0e96ee5506d34ba79b39708251fa60347b951623f42c26f401bbb915e61fd64d" },
                { "bs", "b4325dbfa8b6c0abca823adbf8da5d0e327d9ac7f2bb333416ee33a09206c9eff3775181a1b078d25a0c39367ebc78965852035a209c802cb168aed28f7ea2d8" },
                { "ca", "e18a61f55e948fa40aff778a20981375aa4139f1ced9f1e88300290fff2c0427fb2be089f4e08902b108b31a49e1e82a7f2930cd026022f8bd25295a64f14d4f" },
                { "cak", "a20ca2f330e5d526eae8ebc8d730fef56eaf88cc724be0266bc951c98b5a45b6d8674c3225e056349f93b892f26b6dcc53c6ad2b62ac8545354058283bb64cde" },
                { "cs", "b146d7fb55e6c4ee27f31a7350c7acc0b752ccd0e6b740db788b633d3de7db7adc71e8deea93f8774c3321257533aa94ed7a51db5192a605f5c351cf19e6d4d8" },
                { "cy", "ee9e5a276aa9270e3ff74951615b7a2984a61c8a0aae23b1dab30f5ccd7a7ce3102f4d54384c35617df349658f48abb2db7d4102d243a189a7e04b9366e4dc0c" },
                { "da", "9f0912f85503cd694632d65614200dd879f079a922ff109aea489486f346c741dc4ce3898ddafdca4fdfe87e6524f02562b9db68d7aa3fb27f89e2d42ea2c29e" },
                { "de", "db8a6b987a198dea7a8e3ee8fe5ce7e7b87c1d10693b243e62e60bcb227174800c10de20df8410fcb1975a58ebbb4805abb1c00ef0d8d18192024f0938dcad90" },
                { "dsb", "e9760ad6557265501fb365353b9dfb2fd383d15939403cc8753f5a1efd0c3468c9a301b97a05634c7b6c6f21497bd77d26dbedcd66139500834d52d47be53e52" },
                { "el", "6b5b60cdedafbb309495cbd267bf3285232652a3ecf7cdfc8b792155fa56147bbde53311feffd43fe5443c32118c9e29127f20fa65358656facd2fc245ca33b4" },
                { "en-CA", "21ec563465dbdf1575511acc27d2a99186af213bbe8cb505d3ca29a00f662a5312a5987019262062ee78b16ebd5d68a8cf02ee9116bc373b75efce7a2f03dcec" },
                { "en-GB", "78bcaaba776c2acb9b7d5845386ccfd8cde38e4384674bc83bf11d50b7a54eac99c6591da536d9f28dec6a002edb839044184ddfa98d99433666292249eaadf6" },
                { "en-US", "e7ecf53a58eb09bbf19e413e6c524283c6aaadd891303294340f6684336977608cee8352046b637fac5f25bb9c16f86a64ebdbfaf74c08baa1418609cd96c1d9" },
                { "eo", "2c7ddbb7a0d5abdc1abb3c28cbe63250090624fbc2110c323c63d1fa22948a1ae5f7bdc7e12ac70d376d0db9b6001f90ef3b0f4e6eefa7dffeb314e0b7ba3953" },
                { "es-AR", "ff48560ee559437e33dfd29adb082019fb05e74837ef6697b03ddcca1c452f4f8a8419a3f40551a0111856b6da0ba055918bd4d6e4a1a42b084f1d2bf02517dc" },
                { "es-CL", "d1dc6d64ff9ec891dd6c85e333f1ead6b8a9faf8c3a2737413bb60624ad10aab43ea45cf3e8f90ea6cadec62861cb0eefd4c9ab257f3e0f1cb642a51ca980805" },
                { "es-ES", "de4e9a53357c44ab38efa476086fd3a6692579fb0aedae6a90ee3d37652de553ad381b13e3732f89056632759db709f26729da0b3510585f98113f24de0e4655" },
                { "es-MX", "6136d363a97a4ad51bc74378398696ef2ae3d4c4f9c1dba4b1caf53ce3820721631f250e5ad1cc7cbff9e94ac898d17089775fbe8896e339b2e389c53ef5fcf2" },
                { "et", "2de109594f7868724f0f1edb2179814b3d56321259cd6836bbda5bfd7b1b0b9b61dd0c15e096bf3914df786194c405cbc968bcf29f1bc9eeb9c6553426fd3b6c" },
                { "eu", "5724cb0198c68bb51bbaae0930ac8c1dff6a7d374c46d8eb5abfa8a167fd4bffaf1a5e2eabec2d537cc5fbde5a656b1c90b58e43218aec2fe31c3f9586230960" },
                { "fa", "300c7fc87cd83a9570112d51f2187ae54910660933903d7cdf4ba3c5dfaf0ba8012a4d7ab874220c09e7fb272d24d745fb67ac0c9718dba0d026bba650d9da7d" },
                { "ff", "430c2d93520fdbb1acf37f4d99ede020df21f6edb946b8ec57d9bb65f1e7ca4944aa5001b4bcf703a83edf8e9aa6e9eac6b7ac8c3ff84f33c812cfb240989ab6" },
                { "fi", "bdc421ccc31e3a3bf075d303a21e2c764a6b8cda41c69d4b55d21c672ffc35395372800f1251fe4ee6383351927dcb7973ae7ed865f6f06e637ad3243ab88a36" },
                { "fr", "a579e55e89710afc1bba170604abfa2818cf236b9724af1eba51f6b45c8bc344ad8b8c32c591b7d36152ff7c09bfdbb28edf641b67540da5f73d3a8934880586" },
                { "fur", "6611d9d18fd88ca96f239d2c0417ebf99b847bae53b24a4e7e34d663ab3477f8f59082b61431ef4c2bb0263557b224ca6bcfc57674a6cf7b867ad58c680d569b" },
                { "fy-NL", "d991d5de90ea1fab37607a7bec1e812c1bff17525d346e59b30e2e8f8ca5a3715ac24555ce5488501e787d121b24ef74181f7e1bb212c8afa7cd4061548ae3bf" },
                { "ga-IE", "004ff2f745759c829576d472b8880bc4b3934a26962136f57b4623fd6723c7ed6f94740c06ddf4610ea3a179988143a4508fc09deafad0acb964ff34e5ff9067" },
                { "gd", "451b8a28281272ca88487c7e84e108a863b6294c500cbfc75e5da4d093d20ae6f6989068909f5bcf206705b2eeb665af939fdf9543481dfd4dbc703734c99387" },
                { "gl", "1273bee19cd83726b7a1f79976fedaab5c1c404e04656de95090abac2ee5420c6460d68ef0a097bd41619e865a771e4ea8a8fb8c43c920a6b3873df6a40d6e78" },
                { "gn", "f3c7b36c083937c47955a9a4f9ac63f7b8d12d0df423285346ff13d02376124cef3717d8509148fc534e1e3bb42c9617af87b2d012da251bc5e9f47e50fba4e2" },
                { "gu-IN", "2f6dbe56f8c86edba1b4099968a29ef0efc99ccadd307f4d0a3d0d877e612dc11d77c5ddd92b56364e388a9fa34e6094fdf2703992d8fa2680b16d26e7bda889" },
                { "he", "33960eb541115203e9d0235ac973d61a802152dafdd4e40bf7f7afc43420c9368bb31e4d3954864f8f7bae674b8ff6928e812433cb477cc58ea9c3a3ff62db9e" },
                { "hi-IN", "e3e39b876f6ee1849de4a2ea3b1f41072c7dd41daca12c2fb290d35009b55523cd792b9a8801b335f369a03b55cccabd9ff5794ff179ddd6c08880e7da9e4aa9" },
                { "hr", "a3df0c0846cda69d15c69e781150e57b345648f136a221fd580bfa1adca411a0b5c36f68b23020e08d1163972a5536f9e8e67d247f370e5ef00d12807f3b9ca6" },
                { "hsb", "6dc946459c200f8b3b0e18e64bb8b18f977fdaf7b2e917c49a05c32937a034b288928d8411439f910789a0d23b4c21b01ddc00a971fadbde44109e052a5c7d8e" },
                { "hu", "af4190f7ad91292dd7faaf4865f1aa14b8fd641f421201a0df63186b728fc18cc8f9b796f0f4327299f5144751f50326b106d0e9db6593cc7b4f84f1d47f2bad" },
                { "hy-AM", "53c52694a6ea176035bb20891110d51c345d06e1e9d7dec5ebbbbfa96d48c5519a3476970206614c3e7971927885417be70853d1d4e5349dc71f55c2987ab5c8" },
                { "ia", "c5399110c8f2d0d2bf5b903b9db91dba3b97a73ef330aa233c2eea3600ecea5463c65b9f81d3c105e8c809ba4a515b64437fe3c3c4e508bbbece6e750d36f9e2" },
                { "id", "9ebcb16e3844c8ae538161cd73a3e6fa5329f9dc9e153b1302efa439709b0bb7828eea4a4f188ece801979658ec8157ad5f9530d91da4b939b3a4b2e4b8228a3" },
                { "is", "9b7384a23b9b8e90d54d6c9c153c1e922965da1e31e6e70856832a543a6f1ac908ade0b1d3daf38adcd4ae16bb7a522eac14dcb1101995292d32a2adcf164483" },
                { "it", "3c894654d7e97c88acc09d77c60c25633f925bed56659fb2afb53e6d560895f5eb8064efa879493333535b483615880aa650f619f3a805b884eed6972a9931b2" },
                { "ja", "7041ee47af05fe78010e1ab11f247bfb2fd9fd1c36f261aa31ec7c1c23aec656a27be24687718edb1c876e3a06d4869ca56bb68b74fa1ad528b40d7c85a3b351" },
                { "ka", "4185dd6f34025fdf9cabdd53d5ae67d133029a5b30f392f982e4ca24a7b678978736864d9c1c6b519e2d8146d271a6fe0766f69bf7b9e8c1f00c6f3cb9b04cb4" },
                { "kab", "d35d4a3f9ddccd75ef68e434cecb4becd512772c9cfb861c23c197f48573352be6557a49d317ca7d2358ee021c5ec721479915158a41c15e9276971ea65cb270" },
                { "kk", "4a50b16adbb52e2747b47ac7ff7db694ddec84091f922101203b6c0afdd71568041f5eaeefba78a104e093404552bc215fd2c8244df6769dd607d3a35eebdcc8" },
                { "km", "5b7f5137687839203c6a9b1705fdaf0a0c6f10429efe4c225c6bb9a5919b1cc4706911e8db196957903d8d4ffea8ea8a2a0acb4ac475abb060ed5950f1651975" },
                { "kn", "aa32c8db15eb7c768113a9d8e61d1b4fac8fdbec3db7785ac81d507c9f51cf1111315c4b47df3ab8c7ffc5c3dd56cc3765ff00c74ffa7344a6a8077c468fd815" },
                { "ko", "529a880a181c5ae48443308c805348fa5a8870c9c4d3fa9e829fa3929586748102cbfb9184892d6625c56ea8295c10fb677e821be77bbf93821d3e3fe4480319" },
                { "lij", "4d8f38961d7cbd262b9c977eac70f65ac2e39b4347f06c25559db8ae5e532fc35b586b7ea07a99150eabeb931920a7cf94e6645784a5434759af1fc43c220e57" },
                { "lt", "1e644357034ee328095a00bb4a2284f4da95de4adf7f5ed19f67b50f6fbf4650cc57d47d476a159fdbc35e9ac0af7c40f9549dc86bf7b42878651d41f429e3d0" },
                { "lv", "734703ac4a81e845f1f52a08f98c6e6c2402059c2bd3bf62a5af05ca1fe996137d8970f88058abef3b851f92ffa48fdd9264ef95f61b21e90da9762460547827" },
                { "mk", "552324252a3bb91b9dbe9f3e3dd5ac4bb4a3e860fdc70bb9c8877f78f1f1c4b69a11cf0cdf51edfa26d92b4fe32a3f1913cb3a837fdf969a02b6525cb806e76b" },
                { "mr", "3f1154c01e1a231bcd6b3857ec13ce89b74fa56e03fb47e8fec20e3a24e7dd0a7654e49bbcca000a5dde90ecc5ba1adc8b366c86180fafde2ff746c164ad5d9e" },
                { "ms", "3ef1d2baf9d9dbfbad4be1c91fdce4f6e29ebadc6cd232d5ba3169f70df5ac655e9429f70441db4f577c13b0d9ca98428b0bd02a5b858cab4fe25b61d4f624b2" },
                { "my", "a0676436be62df235d4385f7e5978dc4bd3538f0193bf728405378c075866e7be7f4e1e4f4bf345437d191db81585f34f8a29fcdd0c5a7ba8d8820cb8d2f03a7" },
                { "nb-NO", "5241be98bafd85e86e31740bcc8f9347285429369c2baa6a88ea6e17fd3f5213858c3ffe389f1e5d17ae500aa966fc32206671a2104e3caaf19cb3668b11df24" },
                { "ne-NP", "4a416b37384008d131dca02cc83e1474544f2d8e05d59615b16cb3c896d6ae55b519a120b84137f858fb9ad5bb66095d37b6d40f19073a55167062b500ca4c14" },
                { "nl", "354fa920582e3560b62ca5752686e22a621424044c423597ce1f04cfa6b1e7f38eadddb148c10b79bc59d3ecfec91ace986ef3c3ef3930c1382cd995a39cf23f" },
                { "nn-NO", "23f2cdc71ef64e28187e77dbb2d9053985e42746748ce406ecbd5660b2e1a0e01384c3a72025894ee9c1d2a676ac577b22dd1a69dcf07eab237e35c98c411c66" },
                { "oc", "77ea13bc34c47092ac4f0807e7664b79ba6ae4b823c05c2952b349eff28176b234c563e706ad69762913ecd5150e8c03bcdc2657c6f60f1081f6c708ac3411d9" },
                { "pa-IN", "e2e400e1e6bfa6d5cd5d853933226eb0be69907a2f6504d3b4d0b50e5ad49bd81029f98095d538f11911aa6b48998d039f9a070265232b0cc2359ba785f0d363" },
                { "pl", "7ad0d183138cee83c40428d39eb0896a679100f56ca9e2ccd2528fea523d6b22eaa9fc026afe96604abb5de8b81f85404b041c31bf86c7c5b74c8e7e5f9bcecd" },
                { "pt-BR", "0968bebe6408cdab6760dbff42c71ebe995f80cf56a5c2bb8a7d11ef73be02e6eb06b4b852985126bae2b5af65a8fe346c3dc63387583e5a29c40ac1fb6641d5" },
                { "pt-PT", "0d22afc58a1f69a80701412250a25c1941d0ba2d8d2465976d4e3be475772da0a5a3970a295ed1325d617ca2beea775a5d9f8051dae172899f62b586afbe0e42" },
                { "rm", "66f36b1032e6494f55a11906eb7e4b296630cae6af2942d84bea08465ed4222c0e1c2a2a7782d14f065d865e62b64e47dc9af9fc92ff16d700bfbc0c7703c360" },
                { "ro", "d02ae67b3cee3070542fa9e83313831ba133bc36120acf3ecb3e8e68eff5b31b95bd1f8de6d9ff7f072850a349ba1b9e253957ed2aab4eb429e86356468f859b" },
                { "ru", "d42fa8efb89d4228c46880e7994651c2a23d0106a5bd3c2d9bf0d05b5d565537f20ca3a9da3788cba78958386bf3e3c1ad2aefa558ff209f4f7d2299901fc3b3" },
                { "sc", "8d6d285aa32ef0be851156060509cea97d11ca609ab80b698d48fbd9768de7a47bb87f8d44e17d13082dd58e20ada6047d13b99b2256597dec66b89ebe31008b" },
                { "sco", "3a018780e1cd9a7f9484907eead930dd142bbe0432355a127066daa3555a3078b3eee66de0893553e152fe084305c923c93c2854b2bf4f97f69910ab39dd024e" },
                { "si", "b33fed89a7848891395a8055cdd89d7a52d9a611a524f7ea3c7ba3263c85bd2b6ea70ee6fbf86674fe6d62d537f511ee85ccac7536e82d8e46a65d575023730d" },
                { "sk", "d4a76045551782e371b162aed646324d3718b2c43bbcb700cca9fea82a2d4bf08e7217c39c4affdcdea77a022258f027ae4a98012158c6de78cd9e841ca310b1" },
                { "sl", "77e27b96ffd09e4fd4e6c1032d789399eebf31a0061220a50be227d49566139d86e27cd4321808e93c319587db24331c9385d13d4d7826123a98984649217f19" },
                { "son", "23412c2f35738834c1c41748c0823fbe5259d82d539d8517198ffc705f8e756b87de142f5973dacfe9d4751fa49fffdb17679131bd4c2bbc5832fd981fac50b0" },
                { "sq", "b81f8e57864a917ede5cc6aa322b8881b862f52ee0d389855ba7cac392bde7782415bd43d29ec02dc191f5becf0a0c64688d0c3f562b9900fbc2870950ab6bbb" },
                { "sr", "6f1749f05c5559c36a8a358f5760c6288b72e966d27a126c3e5d65187ae385b8c4e4f3eb5f669fa0a3902971b9e3f1340a5ffd8a193ebb617dd4a784970930e3" },
                { "sv-SE", "8b4191cf64f5d590c3ef432f471e43dc5a3002cce6a1bdfefc1ea099ba379001b71904781316f8cee4977a7577b2753d46b72b6732a2b5c9a70b53c5d631a378" },
                { "szl", "a86bf38c2919a53074923dc0f43e9d31c78085972195c0778f220cd0cbfdbf63e69c128e42c6b1f3630d11c903b3806166abc66a8c18514531718c914bf35084" },
                { "ta", "36eb9835c26906f676b617654618addbea2d4ee970015e18c369a3216fda5c44e52d97f965eb18b8353e2b7516c09b6f7df2f16516322b0df96540bfde489f34" },
                { "te", "af812c0dc3737063b1aaaa05d29426f86038009f42c83787c399974f9c6c2c095ffb140ec30a6296a9b6ad7552e763db55079dbc4f4019074fd6fbb99f1ca6d3" },
                { "tg", "c0d5bc210fcb8808a845479c82d37ec3dec554c36fec3b52d374bcadd84519ac10d967cd3935eef2758c851a7e2086a0f6a73a052e286a40ab9739ea5b9461ff" },
                { "th", "80291a0190d43cd4ac14673850f6d393ab085543002fd6276217df0e02a12381dda43e63aee46eb54b35e10c67ab0bbc728b344b5524bed7d84a4e3cdc2acc48" },
                { "tl", "6b4cec79ba11326d42f4cb5f846162725a3d57e1ddaacd479338936e0e471e421b5b97b8ac1eee1a2276e0c74d8b357eba02cd4ca1fcb66ed6fa33d41815ba84" },
                { "tr", "4b2fe5fce1077fe3410e8a39af44cf249ddb2ccf0138dc5d382a60ac7bb386107c387863d0d97f02210e75c5b8aa4de1f1770c0671c92d69aa854abb4945b992" },
                { "trs", "fb403381914cff1a6ba6fef9c2ae4f94fd2fb098b150d8b52f2c91b694427cf2673bd680cb67e4016ad886bce5f30c30a13a2b42e22986b8cf36d672d2ff8851" },
                { "uk", "719f218a57beff7f82c6a346ef8dc1e29d9c6e60f6fc55af61425ebfb100d093d2320e34ee0c1b6e5dc9f124851950260954fb69818f36742f58338c1b1df58b" },
                { "ur", "fe24c63e7daf58031ec5c9a7185b9be011b6c4282c8984dd9c2adfe1c00af53a85b8e8221c7b875797dc9b0a73a81abb40142c3f5750787fc8b2e89f0826e42e" },
                { "uz", "b628749ee89d5bd99f781e181282b9d960eecbc80216d017b8b1cc64dcc82f51a32a247479859cf92c5e9199669675030d80c5d77ceb00312ecb16e76f669988" },
                { "vi", "0ad8dd6efa0206a3a320428a8f2302bdd0a8b8cddc4daaaa8317ee007c58e5af6fb9da505c583fe9d190639a40bfd29cd15a33ebfbeb66b9de4bc3abb60dee30" },
                { "xh", "cf77082174ea340dbadf15fc2c3cbccf8b5acd3cb59fe73d2524cec80a6ccd18bab1613767755f037a729f913763cac7993b286258001b6342eac453fbe0aff4" },
                { "zh-CN", "747e3b1bdc32f78040006fc6010d2c0b8bce26185b8060f787d9f52a4d0b5ecfa828c2b02289c2792070626a0f0a12385c30749ffdcfdb23ec85d4a00c52a52a" },
                { "zh-TW", "2cd902892bb840a59ed8fafee72e6d5d3a9ca1192698e240d0fe276cfdd46f108008ac6650a3c0064051bc0b6af17307a0d0db86072ae9df12b9d321c7213d9c" }
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
            const string knownVersion = "115.3.1";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
