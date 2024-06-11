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
            // https://ftp.mozilla.org/pub/firefox/releases/115.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "18fa5c799869f2a379e0a9a2bfb892dd866cc6dcddf79e11eee7f8b3fb98c499c9ea827955cc3105dd0be10c2831843da13ca6c27355fa566553ec721b1ff0bf" },
                { "af", "66b3bb6a1a73759f53d507505ab828c7da0bd676e3b3ad743ccd6294ddb71784c3e1c5ed30c528272b9e18b40e5aef871773c4c9fae89ef92f3eb9af61b367c2" },
                { "an", "e0a8955f898f5cec34d71e1ab148a2aa87ec0d1df76cce57f0903c9a5dc85d3d313ee05f367d885701d2aa9c5c95c27496cae40711ff3055cfec52c54a8a227b" },
                { "ar", "42099c895fc2ef875b038f7f0a54a63f7dd4bf7a17a74e5191dc410f76aec02f5154109fb806c971b519eb9d1d658e81e1d7e8f1ad30b5a0394b536488568b6a" },
                { "ast", "ebb15065a6c44e8c7e07490dca6a9d7111a503f18b42977c4ca89ee4ee9fc13a9a4a62554a90362d1ad75770ebd5b0546582e99b9c5b8dd31f5ceb2a6f1f9f5e" },
                { "az", "ab6ce9e8aa521beb79fdf9722884ba6d27d484a5bf2918577e5c6eefff3e83d7df324ea0788b8a1441c6477a77c0a7c02e83e7c5053ed4b0c85e70bfd03af330" },
                { "be", "76675274cae458fa2a9051e00d5010b0e4f61a3e55a1a3eb81a0223e1a964ff3009491528265cbcbb51a09b1f1c71210fc6bee755b0209dad8d5f94953243354" },
                { "bg", "bc08017349aa6ad4129c13a8da4f2952e8aa139ab59240d020b79299bf49d68e3b93dbffad7ad3833617902438b8fb2229d470abc64687d81bb95d49556977c6" },
                { "bn", "1235499d5f82f3e8e37cec9ed6d5ed990472947fbfea2e81dd7b663f98e551609d9949dae03f2ed09d2fb95c73c48a7b8ebfcada7dfb3267d93b2656714ac740" },
                { "br", "f7e796589988137f63cc6fc44da7dce9b969adc1e051f875f566bfe4a51f521f3d548f9dd3416f0c4695359da438bd1cf4e52e3958a2a6e721c5c2cd27fe76c0" },
                { "bs", "680c162d0e2ff2b287747b93323c4f2ea8bfa8ee2f6bf5b0b1dfae3dcd61e5e0e2c82b83c25ecc1ebd1943db9b874fb6363673ea4c08dbd7cb9941e835ad05c0" },
                { "ca", "972af62767b7f13e112bd5205958816d087036ae6dd15d9dc9c636cf5d52886b02f9e342a86e451097db22bcc411e72eec81df59d7189e88afc6a8c2ee560cc0" },
                { "cak", "c9a12dbb113cc17bbb213d9bba5456e9a3cb111c2585e105a9cd56890b0b8d04cbe4c0f21cc67d3f195c6749572c0b1874c9fcd904cd4e24facc928191b6e8e8" },
                { "cs", "d0e1d6612834c6623c09b17c5626291e9f4b1459a167c1cc405568d511b597b2ad98d184ff851a011ab3e5be5e6664a54ac0b19f6faa6f0dfac492a374ab0289" },
                { "cy", "661128caa74d6d5d32ac88e28d886495bcd41931fc788d5e523f8d45a676340ecf3b3de99f9752c2b1c9c2c577998111a4151e9afc8e1c1b4fad4676e7c828ee" },
                { "da", "4933a717ceaffd03eddeb622925f04c1a0cbafb9f1fc488d83efed4023a148f6e938af926ae8bfd5797d2b089dbcb1af419e2809aa5a6af1e65e9086c26bfc00" },
                { "de", "91c22ddca045cdb8088565eac7b3ddee513294bc7aeec97dc52477c37e158df88072a9d87224cf148f5f93e604aea48eb7230c45b0789a9cb80e988159e4746d" },
                { "dsb", "67b35fc652912dbfd4126bd2691e9172684ada26489626d688acf9930ba11ed14049cd52c4fcd032cb0d78f0d68caf4751d54c8673068705ee1f1ddd88c03317" },
                { "el", "09ac0825cf5a44a4d51e5d3ee1551e8f843688ba8ef4178d1516c8f0bb6cc86268c0177eb08a357297db89536d9c8e512fe049c4416426667a5cb8235f2f3575" },
                { "en-CA", "a18fd684671914659cf1f3b7497697474f22fa474efe538cb0c87b5f5b41292fca5dd8c4b13899092cf091be2e5ebfcaf401ddf81c02b2d4ec6cb9a1f2b50052" },
                { "en-GB", "9b0f560c3752277c58b781dd1442e4732ddd6b0454fe25982076f23732d9f51f65c35bbed693169bdee781c75bc8e7cf0880dc34452e83398cfee024df4fb93f" },
                { "en-US", "6e323e22546daf137207abaf1b1c4ed0fce017ce364d2ba73b2b122db912c9cfc6f5009ed25badac8896697453f428db49cd4afb484d9f209e29e4104b87c1ba" },
                { "eo", "75b45d77b1d1bc05e00f0e85610a029d2218845d680250745fb895ef7df43768da017c53e837f3ad4e93dd3a4fce777857cdd9336aa6409c3d6f5691083a17ba" },
                { "es-AR", "e7b91fc9fb98e473aa4f07b2d2403248d872867a80ec0ec35b08353ea8f8a2bd772645e9891ec91f334b4d4421cb5d9d350128ff5504b6c456b5875698103fa5" },
                { "es-CL", "048ec8b767fe1d5cb8018a9af966cedb1e039c57bd4dea8b4ca514c18284c4b206ec5a31dccb9af4d9417762dfd75d9c2968b2ea09c7c1db0abf7555d8fcc171" },
                { "es-ES", "e6d2847f2872cb2af7f39dfa91e75ac04be9f5aee3235a028d1a5f8455ca7c8b9f4a443dfad1b47d97d87503669e9b0b74150d8aaf44bb03734df9a2204ea190" },
                { "es-MX", "3db82a5c9cb7abc4c0d93596c8d2f7ccd304282e415d91cf3883cca3196d524ac2fffcedb78319fc2a82c483f2d8d0650286d921e2131141370cb343052dd81e" },
                { "et", "9f1ae18520f4d412f2ca0c7ab1e07ae2fe6a7f8b595cf24bf408cc89876ea0ff6a55fe022c18654b900d57c477c2d7ff657619daabec4121b5d259ed08e4443d" },
                { "eu", "89ef3608c63dee6235d743b6c9265e6cd1f5b14223e7fefe2fcf2fea588ce6f40a41a775d78845839ffd27fbac9fcc69895696d6d1dfa1a7c2a25890c72b6780" },
                { "fa", "a01323da68525e654cff531665dd9ff0d43527d8bce02097525d94d98cc2602e444d6216c7ee3185b64cba7cbd4791a50a5f98ab5e2a3187d10d9463e694674d" },
                { "ff", "7135dd7adf7414fb176bb2fa04a8b4806c8b19ca796ca6ba4533cb43ce1c78bfe9cc21fbd1312f936892fe80db24ed16267d47b198524961324c83e47b7fcb62" },
                { "fi", "5b58bca1678b142bb14e9b370e8dc5986d2e84d4bb73987bf89c7a6f39352a096903175d513166a3ce665a0da2198dce00fd35ce261a850631a9971549dba6e3" },
                { "fr", "51c063ca4dc17bea54ad92519eb8adcb4bac52e67e4846b4aa5704809edfa4f03cb7478666843be7e92385145f48401f14f8688c66877e4bdb8a644d1edae454" },
                { "fur", "18462034a3628902fea3073731f2931c37f61b0925c4b30c4534689ab71c832393429314f69f53308c8afcf8963c3c0f693ecb8c03f481415d42b32a39e3d9da" },
                { "fy-NL", "26ed1467f4484e55155940be0cdb2845bcc71f5ff712ce9c1a72897f9e84fbcb6c807c748538207abda4f94e511ce9cf0388dfd38e20ea5d3206999d7f89abda" },
                { "ga-IE", "0e551c4a14a8ce7254d9742db678d65ec52d87ee12fb0aa44b1bf56a3744c29b0bfca5366fe545a84080b89f1bb61232d294fbb69fc5994d17110bdf6c229351" },
                { "gd", "d6c725fa12bdaae8078da0cab1f414d604114a11cb39611e867ee535ab5fcca40736c5cae46defcb859a05fb9f74f15a9288b4c6e7fdec8eb1a96098cb9fb1b2" },
                { "gl", "630b09f8e9dce5030af8d9f39de95004eab7aee425ab36f9219d2e9c32f7d252ed6647f116256848e545971c320352d81140968a4c0d492e65c99b658193b95e" },
                { "gn", "766f5827826a266abf35d855fc284784e5728ca27a9a14f6fadac04041acef288af7f29d8418f4c285fb3fb9a465ba0f8194baa87d2be53daa9de9e250204067" },
                { "gu-IN", "0be8d6c9bbef8075fba635ee58e9b781117dc821e073efa0a1a1c9e46dcf2d585e0c7a4f336895e0aa49d42a4bfe10e0f594c3e22f8365bd3c84dd4dc612fe4c" },
                { "he", "70dcf3d270ebc07e19ae2b0ab7040631ab414f394fe16a77fc529124190025d9dc1d05c985c277ca5b38d0e7480daacecdf0a63017b02d0ca42c603e2e056577" },
                { "hi-IN", "0cc40e63978537fcc0a66f62582577394ec82c836336cd44af93f1a75d09ca2a42064f07f31904d96e838f6eafd01d14933a9c6ce7b7a56ae965a1920830c253" },
                { "hr", "8a9e89bed3e22ced25b57fa36ddbd305726eba2ce79b93ed86de14d6ad53152664e0117f3953ee30ad0a5ea29e34ff196bcfe1b557c3a90a96c5eaf2bcf0e65f" },
                { "hsb", "48fefb1ff7ccbcf84bed76b8998dac44299c47bad75e0cbbf0115a0fbdf5838fdab6db4dbb40bf0a3c283aec27ebe469ee829443d32158565c585eba48d3a114" },
                { "hu", "00a62d71cebdf99e5f2fea2374ef55ae8c93a19eea11b532b1950bfe10a0ef61e976f6f7b9bf06c531b5060d235eed77851b81f327b9758fd1cbf54e21e4a0f3" },
                { "hy-AM", "21290440dd3ea78abd9cbf2d3ea242cc21ed297351e833d91bb45e4a52e2ac217fc730c832f00301fc202b6c3c88fa884ee05c9b1365a5d556382ae0405e77a6" },
                { "ia", "769970716ea7aeb68e2422f601161ce009a133c4678a94771864b9582a52fe380fd27b074104935b80939e39142c359611f3fa2d345a60f96debccb8ff0a7f27" },
                { "id", "6e6b4bc8ea4a824f3d4b0ef1472f6d5ad42ecbb282a23f1578028edc3abe1caae1dfaf6c38d94bb3f8df04207f59e9d3c6d5f81afc0d4372bcb4c3b9c5c68cae" },
                { "is", "28e2064f8d6fbd874b0bb15c273422f6bfa26ea4e62339e4761c5f251577b476d16698034a0ac1e82e38ed18ad0cc7918e22d47d857bbac4d66277700cb21efa" },
                { "it", "431d83ffe5415640b038293d95a09f9adb3d65ef36791e7973335d87fbf917c9cccd2d1752b98aeeb5d7ea6015d8972c2d0facd7c60c4a08f39e7a7eb062b06e" },
                { "ja", "7582010532c2b6a10353b26677f5ffe674d86074e479b264f8be8e75f2cc8bba9fce2088515bb62376f2983c9177403033b08fb36d6830e922e36ac0e37b3507" },
                { "ka", "8b866ad5bc78047f68d0db02579d37a51b8786a412c8a51ac4bfaea4f13378bc227d6879e25f826552df6480c86420f5bf57820c9f97fe1f6ad4d8d59fca7e92" },
                { "kab", "40db24ff6ebf1ff8f111130565d1ad895e120a23f58fe1b2c2f7ef973a4d3fb541d3f53d3a2d4e354cee048334d6d70b4e73dc45d54ae233704c9c15b0c88d64" },
                { "kk", "8e6c6a2bf89a63933db67a4afbedb5dc91caafa6638b30d961b0727c3cd7329311429623a49f8477193ba899e00bba4bef56efd7d000a0d16c90cac32f6b14b0" },
                { "km", "a5e77faa0bb1d011b49194b1fc1a21c47bb25dcf73b19e16c59ced87246f13f57f52c45371286a9fe7c2a7f70b4cdc9588665d109f0abbc75bc5726dcc93fd81" },
                { "kn", "8b00a549951fd74e6f2fb29e8b68d77c6215a21b8c40548b6fe0eaaad1c227a0cc2c3946ecfaa19c40db619c4909f0492f4f7869619caa6c7ce14c4e3a34ee85" },
                { "ko", "5daf2867dd791df827dac76875e1fb0bed5fe5d0fe0cc06c9e88a48e4efc6ffb8337f30218be6a70fdef331f3bc8e4daac25e0eb82e51142187e040153aaa6db" },
                { "lij", "c869c5014eddbe29392d6da7968cdd7ebba95658ab0616eee6ac7c32190cfbc8da9a70f944bab082f9578b9a01c8b17293bd871155d3fa583f37395d16d1079d" },
                { "lt", "af92f1bd76f81c0c75fa85568f58b2a975c152235672fea33365f502617a7a52da6c96598e96efd4d376248d48ccf4744d8d84266bfbdaa1a926c891c31f8286" },
                { "lv", "5071c4a81d42415fbf6ed794a26a949cc36aaf184114e6a1f45327a72cf6bd001f70646fffe971a63b528f0f0126c91ecd494ad9042661c2e8660ff478e85318" },
                { "mk", "da37488b41dbaf5ac9f4bf6640673313957a6153b2bccff92bb26c1c62b306329e6feee454dac16bebe3daf8645a5efe029f371800bdea50eb1832c0f2c83a99" },
                { "mr", "e6a1e9abfc4b5f8e1f0672955d2ced27e7a16106ce6efba6969ad6904ccb02a6ca1adca11abc0168a30e3e27fc006981fb548c72d33810501d58fa414ac81d42" },
                { "ms", "1d7699777266d3241c1d826bf84fba6f83362694b8a979c5b032fc802b9ce0831790ee48981c0cc91069982793371dad3eb09e1349a22cec7438f0cc18bd7ef5" },
                { "my", "ddde1e179a8897328ea6ef1c210562e544ba5cd7c2d0bd1fd066d02669e1ba843e989ef86c406a5fe5369da86668ae1a8949031a8e5a62c85930a514b88cbe4b" },
                { "nb-NO", "221ee4ab84ef939a4b6e0bb1514cb15dc6a8fa3635b16d327ffdd2b01e85f021c64765bfbde9bfe237522ffa1fb70db4cbac6b84ae5e36bf368cec84a2a6ff8e" },
                { "ne-NP", "c9ef1501abe6b9a609987855545d23cc1edf8639e2529682a81f2761424e25b6cb92ffeb4910302787b89e279b98afc379ea321b495c1ca2c6a46808e3835ebc" },
                { "nl", "ed2b19a29e6f12a3ffe3bf073b543d56c9b69b5fccf5725edf1f05abed419166ce9497c26da106eb0cae7c76c88100ea9eb0d93999c043480c643bf7e4496a07" },
                { "nn-NO", "c3d823f6fff6fd886e86f7f18525c540b0318923d9b90dbb5128f913f4ce7b72e96c0375f4efdb1d610e9de9a64b6c9432165408ce265af91df3cae8f03e0b05" },
                { "oc", "397b7b136761738aa853bbc07819c80b5982cb90d4f5c8ea3217b1060a738002236db75af9491622af6838516b358f0ba7e1f94b905262f211002c4861897773" },
                { "pa-IN", "9cb4d03f58933af236d84c9490858fd0882d714ba90eb34b7557af61b856eec7f4bb1b1201d9fd900f9a8ea8e38413893f1774d6dc455fce388d832ae47b3b9a" },
                { "pl", "0fd07de7316914cc5c4de414712e4e6d2b3f2149abb1a2f1225f317bfbb34be08283f930237e6ca816148c3be0514aee317e48df4c4c9c3e91671a733687eaef" },
                { "pt-BR", "b504cae1ec930b0a1687f33a1f75803d3ac988c559a2bfd70d4e6228668ad6bd059627f17b166c4fb5954ac3c5467555b2e6ac285502365efa2fae8508c5394e" },
                { "pt-PT", "c7d585e6a2bb9fe9a2015cf6abab1096f96960c5c05500fc9fb05720d9b2c60ed14ac75006b5fb524588e864a6d9916ad1ed14ddb22957a9898b25e87ea789f8" },
                { "rm", "dcfddbbf226ec5b06241fa94035bd038b706c8d896c50932e9afc0464eff953f66ac19976acea07b76f1856c41a767ebf36e337ac09f245ce230402733d999af" },
                { "ro", "e2879b36666357ffdb541c5e38e7e14cb5877a003519b28e462e68ac10adef6989c366c16a125e8e33e60aa9a59225660357d5660e24af2c66e50df72badd670" },
                { "ru", "ea57f0ea3ab3e7a50f976b26b6d559619785aa70889dea8af53a62330eb16f62fa9ee76e99d340fb0ab0103453a696331edf7ceeb76afb794a9b3cb5ce2132d6" },
                { "sc", "c8fdbbb73b859a049d58b0b788eef349cd7f516b86ff51d27038ea5fed77d56c78defb3e3b763f73175eaf40034eca48e26f49179c674c4c40462228bd93c3b0" },
                { "sco", "4756f5e81df50f0e4e038e9947c61a62deec1a5025fd00547dfd08aa62b4a97cf63441a459fcd155e6cec94860aa0edad7d79f924e74d34bae49efdae46b19fb" },
                { "si", "6de52f6788538166e8f9a43d9a6712ac1b2c593c92f4508810dfa2192e8689cfe4065111d47d43520db50886b5cbe71d80d3dbfcc995ace7cc53c9b6cc86783c" },
                { "sk", "0a05a988d15f77aaadc0af03d58179d81d5abc85cd8d357a96fe779a467d094c4960734cae157fa2309f47354454eadce7b61ff34b769b0dd77b9d02bdefd2cb" },
                { "sl", "d391e24dc4e8c093717eb741f89f9ae8139da6847a58596421c51dfafd4453b28dd69b76d81aff134099f9e747102cc6725c74fddf522293c6a91a35940762ca" },
                { "son", "971bf82b5583ffa8e90b026eba620439f670452554ac5c601bbe01cc0e7dbf4a3e9e0e13090094b06261f18d484cf65c089a3aa6bf6f3c77bef66a46b01d6477" },
                { "sq", "bc23c253559bc6e12289509ab991167086e9eeb164065b0197c06848785da01c6ed5da0f8caec1f5bb9395ce181107ea45811224bdc08fcea08ac0d50214e44c" },
                { "sr", "5bcb5e1f63cc0d59df70ee8220f7c83aeeb43f2a81ccd130d825dae560e30b94145ed8d19b010fbbdc03db6d110f2fd6941e06c7d0db93f9d35fb588a7a62d2c" },
                { "sv-SE", "f912f06bd77636cedcb315872a57dc74b68f93b43b816ca451968b8005280ac3cc91ea52039614b7bcd651adf1a4c7ceb916ff5898158bdb35282d15ff9af92a" },
                { "szl", "beabe4401788071d822ef17b325dc1008deca0ec8e92473d8b8346bd901ef2752601b93ec9090b7fd1b51d5fd66853dfdcfce365d05e42c432a8f6d95838ed3d" },
                { "ta", "33255d44eb5a4f6c34a0f2e40f7c0e9af98f61c2f7f1a4db63873c4a96fff8173f72b30a3e0b4b56f3453a6d25d50fe92e8d712e7d6e7009c831bfb2c9dd7b9b" },
                { "te", "72101a95d4879370bb1cc61dc588f5a79f2b21422ea9dfd6c5d8a5607eebc5ccf0607c58200151368d88bb0f6052aca867f6e14765f2c86a4a1456d933194a62" },
                { "tg", "e922222fd531ed74db09512227071504e9c963e253356d36f9159a79a7d1f2f99c5d8401669928cafd64576326d3a5b21e9ecc2fdd319ce044d67037a203df63" },
                { "th", "2678b7b9b53eb2ac869aa96caf37bac8b58a477eb5d4bbca3d82a82d4031e61c7ff082b74b7b3830a1874a6e5dd67268d87ac00da17cac1acd71e6144558b2c3" },
                { "tl", "9897914390fe65c1d678b63932dd3ed720fc44d27518422a5a4fa4082ca023eca7e8f83708d1ae3c017df064a8f71195a6ac111bb0bd45fa852b9edfd53245e4" },
                { "tr", "ee70f8150cef5f6241923ecc28a454746c9c26abde7765986c1d6089d05c64a3f76c9b5a0fca737c51bc1c72f5ea6be026d36f00887a26dcfefacefafa5940ec" },
                { "trs", "261b6cff0dd45f98f98e406c503f88bff1e76f306958c46c543d568db0c437bbaa75ea96251aafb9dd774e2f71f7215237e59f0f4acf198a187f527636c44e3b" },
                { "uk", "9c19f5c0d887efc51c3892a153e56e0aa8a493163bcbfb7226fd4f8b863cbf2d997edaad0c6eec084703a310f7490375db4bc24bbd6762f2197793e9441f036a" },
                { "ur", "9806ee00847fb48936a143aa823c59d6d67b627af41df8f40697efee96ee67ddbc7d72788a3c2989164eaf0896c32556e480edb8cd266d7a51dc8faada312f21" },
                { "uz", "0c83a1a4d407df901abc3572098ae22a0b7ab6d5bc6b4af81924e1a215d4f85a97a48e05bcaadb1fa497d66623b0c51c02b8fe86afff4106e311286d776dde2a" },
                { "vi", "584e7a63deebbb95fd3691f102d713367d0260c6c96db128fa64a242749d45c368fe6cfba686654570005fe672d4be48265291cbb33a6a8c9abcef1b9bb1f41e" },
                { "xh", "9ff3eac0d36a6163a04eff9b72629f75f1e9479d2643f88a3241a9706551ee1f8084043a1bacfd23e7fcf5a6b0d55ec148e03961cfb52daec877611be33325ea" },
                { "zh-CN", "8dab087573b41b39f8a2654399c1ad6dd2534bc4bee795c64a56a5fa312d6e009fbce12292024d324362596a8398b320b5e2c587e25f85398ffa8382982f47ba" },
                { "zh-TW", "a046d97e501680a0bae028996516a1182088f092844233ae16136685090e5d979dfc3e333f73735e382fdc6b5885ade902a6c8276dcc441b8113542ddafcd442" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "79a2130dd21a66fc0204f424970cc0d932676a26aa39be78087b868f3893a0168de9caec7977cb91df56d71e0b30eefc318e6490b49ee0553fd5b83bd763c3cc" },
                { "af", "729621cc8811876a087ef5c2dd3fbaa22f1d249ff0a853b52189c0db7acddafb149c4dfd332f4e15a55f8874dce9434d2cbf62e77759d5c2370f3ce5384d0faa" },
                { "an", "ba094c618daeb4228ba9524ed4c1aa81bf81f7fd8e4da202f3ea0f34ed6abf353c9cf3df4028239b6948d8a02d9f5d77249a466a3925cfbef4deda79c6fe353c" },
                { "ar", "5df71cea5b15f13eb783f40746f539c3701f7a9c651511548909877afe1e68ad102473c319cd939a4bce9684b6067e86d417bdc4e6cf99239dd8dab49c8ab23b" },
                { "ast", "2fffa0b9e639bec061b9b5ed2023a12a17b20664c7e49815633b66195249223927e32486c1c2daa4751853ec13514e5e56ad389dde3c27da6780fa66e209663d" },
                { "az", "7849c0b6708c6e83e0c913b8a6136b01dd8efa3ec3d02bf4ca270ffee38b46a042f49fa819f73167b61a693d70e039bf7302e3cac154b5dc8cf99cd1de20952d" },
                { "be", "73dd7e38e4911285ead54cce3b60a65f84c1ab50a9444c068913f68fed6d2d25beeaa51f74e3563536123266f600b17ebc96c1a5224362f7ad3650c2627d5343" },
                { "bg", "49744968024b62c41203467cece0a4b660d229b82a78f9a4ccbbfffe60a078ed319059cb37832d9b7c3e77de09eff0bdcd73679d07aafed99392fb9f7930496a" },
                { "bn", "9752fef60732c3e2d191181d03bfec3595cc0c995f65e1eda26a8daba020357476e61d835a92d384dea518026de70c6f00e903974c80bb27990790a9ca76c1b2" },
                { "br", "e3980c7e0c4454604762ed6a36c33ad2950818f17e27d2aa77640eb6e54d5bfd58331ae3cda188961fba9eed4c945ffe400412abd050b3a7e90a9ec7c65d21db" },
                { "bs", "5ed2d9dbced4154499a87854765c300152093574884de8851f5146cd8457c8c37745b723e4720836e41312826be8012f30741c8d19de1b9401166355bb087336" },
                { "ca", "d8ad482ea5aea47aa75da90b538c47d752a6b589111c1b84df02e3d073033c1ff27e19187b72935a0c6d1659a6371522ae47a4835d7697f34b1518f7462374f8" },
                { "cak", "91c82bdc4637f716fa1661db066ab954246199023ed8b72f4b1ac0c5afecbab884c7dfb8b9f45b1c6ca81502a3dde3d73528d62b9b6bac979cc0a9acb9d0e54b" },
                { "cs", "2c58fe5cd3b520efd43d0638af1453969500631447b172eba41a20e1e3892fa3a9fc84b4d2b41d562d23dfa93ee39688e3e6837cf8c12be0a3dc9355fce12534" },
                { "cy", "630d149583920999dd6b05ff1292b59be1481aaeba24efed3af61a4d1214585f90dff86c7b6d4a205a056655ad6b725323af2d54c4c155489b1349b9617503e9" },
                { "da", "bf188dc98c8c73a9569a41956829d92f349e4f41ae498d458eda9917396d60dc0640a65223f854e191a33273def462fc1bfb6928b0adc19d8993392f48d0eec9" },
                { "de", "d3d38d2cd7dc8eed8777207827b28153d4a852c0e2a7a8fed5e4f66bd2f41774345475f34ef0e2bb750bc5b6bf923dd52a84386b1551ee68c4efcbc5c590b85d" },
                { "dsb", "17dfdc59610e7ccefa105e4d6a7ac99a9e720b4f3733408052968ff36f5285e4046f57d7c216dfbcf14ae5b28fe06427f3704c3a5c4bb528d571e37afafd13f2" },
                { "el", "1cd6e5250b27393249c25049b1e8a66c7d8984285077659ead28ab6ba6a479f3fbf8e4898763fda132e5da5c24cc754389d00efe1b3628b4aa1e093683e5704a" },
                { "en-CA", "427864125842e87e787541b1057765f28c8abe70c6b66d6eb04acd4224ce2c511362c8c58616c6baec787a7b0045b53325b1794eb5b2050f29f2070e1905094e" },
                { "en-GB", "65d751906162592d3f23d6dff7b29be38741e19302cfd680f7b7febdbe8b3d064d6df423cba08cf8d4c4145591e23ba3d736bfbf8764576e2f665d777244f9c6" },
                { "en-US", "118c780c4aaab7ad478920a788e69b79aa8df7f7216e9b990ebf81893f30178d96eb92eaf3e30d5bb921fa3e8ef6ed345aa64deebecf8b2dd9aa9e1b98b37317" },
                { "eo", "4681c71349efad769c3fa51844f7069efb396f5ce21246cdfbfee8a0e2021ce28cb60b8f116e81a4a854de9d2c2e6e6a4dd8a29b42547c6687112a339af6f2d0" },
                { "es-AR", "f310bea0b53828a0be426b5d31cbc5cf8743d8c83ad03ebf6f7ebb2010c9a30e071da9434ea77cf56417c633b9cc9320d40e569da3fc1cfb76edae7cad727ba1" },
                { "es-CL", "7ea2f9a98dfd68f206d811a8d6f9c79678822e86bc8d8ded7536c256042fc310bbd86287ad10cba4f7b31e5226f7f7964220ebec3f8b5e92350763bf454b2334" },
                { "es-ES", "9dde74e56a5e175dd0d55af791625805f88f6904468af92bf117baf4fd673c5e55abc9f7eadc26a245c1058d98406878cf31f632200cd0d2364031a6f59f480e" },
                { "es-MX", "88d1eabd0bb423397c9622c58e20cc2c06710d4feaf0e0325c989c617fd2667cce5f2676a3cf4917784524c12571893a03b51cecd481969fa6673704f312ec9c" },
                { "et", "634f558dbc601c07413d820c99d537effdb60bb61e76b584b458e5ce78e5042dbd9216032bccc4507eecde0d4dbd6c492b26b759e4bfd0b59bf6937aa4c841f2" },
                { "eu", "373390c1a63b7c7f737e4aedb9ad4b695481f4bbf6810922bf2198d8a094570f98828bc02325e63ad6e70a913434d01a5e73c0a396c7fceaf3828414e38f9f7b" },
                { "fa", "5ef49c65992a68c671474e9001d60fa9e69011eb281ab46e2583f4fb94c88393d8023872749cf88c3226b7061aeb0dc67945897c0b50ba18ab3d6a7e657b9e40" },
                { "ff", "5b1afb11f5fc0cb426ee936bd54c82bb304a3121e1f35819cd1be5224d99a234d851493caf222c90c222a67c9f7064bb042fb35ecf7129d160cc570573af2e38" },
                { "fi", "b3d7d47737bab8985132b01b1c8daed61ced47c650b7a0615afb67697b7c3bce087658f8e791f39b4f4c6cc8522a424826e80caa7a5ffc3bfa7c47b20f86838c" },
                { "fr", "b6c0910f716501fcaa036463d9073a3f89cb9ee692bddf90f4f4129b7146adb24ac943591ed9be42e223b342cd1dd0cda05b4799e96e367d88156bccc37bb13b" },
                { "fur", "2463a47fb935e5a0c49a582ecda136725ac079ffe22288085fc7a97b111ab092de45865222e49ae60425bef27c637cc098d3630ac0631e620896dc986cc4a08e" },
                { "fy-NL", "c6e3c31e9d36a01e91e8380713de53e1e46bb592b737d5af6e0a1a207c23f422cf6260b341822609c96b1dfe43c4dda36a6729d084ed0a6bba10e5e3bcf515d1" },
                { "ga-IE", "287be3161c9d9174b2425632c5dfb42331383f957b6b1f62630f1fb9c4c73f39e0a3d0f39f4ba98418b44889847f31bef01e7aacf06ac334e768c81e13062ad5" },
                { "gd", "8ec8e711866f11386b2e009e12d40ed4ecdab0fe4f975a8d286129092a654c5fac148999f939b992478bc59bb2fbccab96bf15685a70baa375ed1dc7a306f147" },
                { "gl", "05b9c36796268073804c6d734c35ed6eddc870ebfa777e3f97fe2f2d7675eda1ea28b2e0ccd2319f84ef4c5b6f879674ab9a0eb7a5cd9407501b7bff88161a3e" },
                { "gn", "977a7f7fd55a3fb64eaf2a9ff22b3eead9353154f3dedb56943b0971490f32235b41fbe1c4fde2007d4fc908f804f1a9e2e58a1437bc84681d65b08d8d6b4e2d" },
                { "gu-IN", "d8db67bdcec32540b358f661c46ff3f304f27ef07067eed0f52c99d3df65526914669bb9f5ad18855ee20d6a9383d3a16aa5b782b15b5070c789b4b91d53c7b7" },
                { "he", "5e692b354e2b74a8ad005b8de56766e65077745eab24d83f8aa6d25454c46eedfad4804b91127d1d5467fe7d149e80d9ccf98825d36fc287964223683788306e" },
                { "hi-IN", "1be24b47f893d645279201d2ecdcdc692c9aa735de2ecd0430bfed86500e00dd55f3b057e52b1abee61ed349c0afd5e47f3015bf1cfe203ba6243d5c135d4ece" },
                { "hr", "44e54e44c23e6ead5243cddd1a5cf2339957e629dcc2eeae3db8ec099e65088b440a9d9e063fcd15ae319d6b7f3b63489eeb5e3b2cda86a8ad219419a204b471" },
                { "hsb", "d87e93e6768ae5a9a726f28acfd85ff9ee5b89f5db987ec71b959bf651f9c04d79ee0ee8bb1e0084011042a4868b663ba6b81b45fa1d850f788d988066ac30ee" },
                { "hu", "2158b5206184b8a04af2dd95003317df55e919079aa468b0601b6913e0c05d780b2a7ec69f0a05343bcdef71aac7af2349fdb72837d0a376b5378e7a145b3675" },
                { "hy-AM", "5e9037021ef9193da858c6c2682bd7d4d8673b9c11f92729abff562cc91d5c82796a1bd3e1a22c4daa58655246683e8ad89ed0867a2c2031c2af46aec3629ad8" },
                { "ia", "66380265f81fb6bd3a2fdf7f421f93e308429535d36f2cfab7be9c27370609cbf45bd15f395a27b600e365080a156ac71377ef20f96b9b51397018159c873aeb" },
                { "id", "35c9dffc322274c6ecf94d658c920dc3e0d0e16e6b56fcb8ef8a41bd55731bc3492b294042e81852279199cb5318aedee80724a2504fd2692853394c4503407a" },
                { "is", "b0f00d42f106f85f4b80828f2c893ab182f555509b18d3ddb552e23cc3ce2d55eedbdcef11a9fbfd50c15e3f2b2d79b52c41833d368c92fa1bfa7b339aa21d1d" },
                { "it", "5a2f5ee56722252aa68841b7c63c5d5a34f02804b41132292e5195fd118942c9a6fc8218ad3848cf6d35311ab7cc584d35efd830ea889393983deea1597e7199" },
                { "ja", "48115d918095834bef342a04dfa26062a7f22a670616e8737da35f6ce199eeb7e8e37ddaa6d0a2268b3a0d1ca9374c0af8d20b483786cb15404cc6f3c669d2e0" },
                { "ka", "ad518a21ba8cb89d5f2cc9e64fc0f34eb40e643423f0fe039066faf1c0e99999c90383cae67554e00238e2e28514e85b5666ecc759ee8694ecee520e2febf59a" },
                { "kab", "9b4d9a9a9e81defe9660ac558b452f0b42b19a2f1a2b100b86dd6f34091c66721d3ec3913b0336bc5c9e3a4e09f521b440a14d522d34d46a82414058024e0352" },
                { "kk", "97edd0b7a9c69ee771818bff149316a2e5e31aaa9f90c669f356d7e4605d85745781f059d40d8e8a9649d1e5ae1a1b595ceb2cca795adbb2853bc121a0d4e7f9" },
                { "km", "4a1081d9e1b13e8d945e56657e4eb05c0eedf1876ae9101ac3f4c74a37a9a5c12930a47b205ca62acf87891c1aa929f47ada50d4bbeb38809c594575870bf5e7" },
                { "kn", "1cc34c1f3c5cf5c92d66d0f5f1a9167aab6cc5f4347fad148cb53ac3702c747d04217b5deb375b68f372e6c622364c51ebd1dc3829e2fc86602b228b243443e0" },
                { "ko", "3fa3b98db1d113777248ce5c658c425a15c9e850bb71053551c555d0526eab2c53ac50cddd3162da86ce35a4e16a892edd84aba111938aa708e92773c923347f" },
                { "lij", "18439136ff78faaf74f004944a2c72df6a78231d740faa6a466dac2deed683dee0020d9f407c9e268922bf0f3c89dec1aee20e08f4a35c125757d00b4de522dd" },
                { "lt", "b455252f1355b48d77bc4669fc77a966b90c91d8c39bcb7cca6f36c6894a8405b54ce44f42e24b47113807e91bcced041724a7876a75e15c229bf0226a47cfc9" },
                { "lv", "f7f21707ebd70f396f83df517df7066cd0aea1b62010c6bd983f419afa1f0ac5e5dfdba60aa1d11639bc1b3ac956d8be26fecac1757bbe5471a1213ca2f8abc6" },
                { "mk", "0482db86ab10f93c806589232c6299e3a43e813983c00c31e3cce713a127ee7ffef6e19227410c98a6f9b333d13c6a917f9cf7bfe70798e7545d5781521a738c" },
                { "mr", "5b1eed34eaa39732e98e5833367380cb6f75517e43a79b1813277fd207ccec73b5a2698774387d6a8be3800a28c0d7b57bf4113239cadaa246b542e5a4ce216d" },
                { "ms", "0593ce89946b5cfc32c9f1ca50478b672f670d0987e91de25c515e0d3b890212c983e3b6412d1715d954e012676a149ec178d871f39037e415d6321059d4afdc" },
                { "my", "6854bc5a8da1dbcccd1ecea090c54e9dbcd4e50175efa27d1698d87e3bd1ea947a5034b9a1f3c8d34ee9e39d9a629f43df548890d975eaab909a75b710419bf3" },
                { "nb-NO", "28764d710b946eba8f34776ab50aff718bf11f37590272873b893af924ef18dee41121afbcf232325466e72fc8dc51d36a5221ff27b310e6053a2246049e3515" },
                { "ne-NP", "e45c8848e9768d2b2bbb10bef65a5ca4f004faabf08ae401364d48ab5489a77581e0b52f9fd048d449f0d96f193ba3f52e3134ab4982a23d60371b6e0324f26c" },
                { "nl", "89c088d23cc90b646c7220004e256be78e90a59bd161fde78ef3a6b44469ef11ffff71cfc60822ecd5c5d70c0b5442dd97ade085da7923b3865dd16fe26d1cbb" },
                { "nn-NO", "ba77ae7f6f745ec6050ffb2ae090aa4ee71255f05c5791a1dafc11e86a57042d0765477d41d1390c1acb8971b2068c20eb092afef92b4a03bb92ecc20172281d" },
                { "oc", "7ed8c343d7308ab6354c0d4815ec2d4b6e8f40a6c226b2deee15cd800d7b73e8101403d1f5401696a96c670cede74baf6b0121538dcc22f519351a1b07d25a63" },
                { "pa-IN", "c5677bdabfcfde558a51976067091e009dc3d28530ad1e72417e9aea6d4e002d16d9d1e8828466735fc9673aa8e482bc9291ddc7c928c5dda5d28666f12391ef" },
                { "pl", "99ef8a9517b4bfb835246fb9a9a5548978ef1065d9686cac16a9f211b7636fdd601ed36bb14bf8ee38609f89d8447364e16ef5ccea746faf043c9bd1c6be7757" },
                { "pt-BR", "15de9ac7ebfec911cd5a47791d006b95d76579cf914828692098e7683d0378722937e1fbdafa4d6893a474575d91bad5670cfda1dc5d600be571d2d9618a5785" },
                { "pt-PT", "682abdea02c9371dcb89d3a61d29ee8456d3538483e274a1c9a5653777083f2584b88528184257be89b8498210db8a3e75ce5e8cad38d161aece2531842fe4d6" },
                { "rm", "39401d83ce875d3a2e5f67727a55383fca3ca13cafe3279c2544207d2ed6e942ee6348181ab2cfe7c036976d60e5edcdd6667669cf1ca4dc924169aa694d5b78" },
                { "ro", "10b9299c75e6baba25833d265b8e5da0441d38237e57e418914c659f98ac0edc0c1bd392d654bb8503db71394ba99da4e390221c7e739d6d70c856641b416011" },
                { "ru", "90e5d7c22bf5b87c66f5acb1d2c036d642f8445b6029783781f1663d80d9210a9e984a043946c418f326882d0de35e153cef55aabc51e1ab99747ed8660c864e" },
                { "sc", "9cafc7e0fc810a254541dbe7c66eec45e512b094262f50d5e71c5fee635f2b55ea6f73c6697d0d087662968443b091b9fe1830e01993958c065a5d65aeb68cc1" },
                { "sco", "dbc8963dced53c74e434df1c9b28c8d75ea963777ed54ccfdab01ec84c396b275408b3816b1838967470ea55a64e663c03783e43038dcf00f854f414ebd493a1" },
                { "si", "1b344f00d403d1227bb0a735b93ecc6d770d256ab5dfaf521bc6b592dfe02de09dba572334279ea3ae2ccd89f2734578e9f7277dcc00a9017414b4ebb8dd8551" },
                { "sk", "540a4965dbeb14ac9c313279a4ec0870d2a16dacbc4cec73b0b84529b594fc38acd119da02e6589b7eb22c1a59543ac7d7e64fffedc0ea77546b68d681001406" },
                { "sl", "8455b07ce7ee305ab104bb1a76d7de144d8102e25fec3d1e4fdbf4a467732a59fba78e07124317ac82b0d1c8bbeb957468e154dc99dcde6938583512ba77c2fd" },
                { "son", "e7cd01fb72903457d21ff7e5c182887adc39a8f9db7b09d98ffb554f1810165970276725bd5810d72dd862a03a7577f79a8f6ab0b5e46da20f5fa14ee57fada6" },
                { "sq", "5d0ad4eba4fd9388c5c0bf1b7f9f0adc2db49b5210beffe0e3bfaa6b6e2510144e66ea9765fb2be78627b847166aacdb05b80f6924863a2ceee56c43938411b5" },
                { "sr", "29dd8332b49e03def3cb4bc80c1970feefd518ab973661a308a9d5c576d1d920038e0cc2998b0c5f3d19d8880a1a0853e88156bd35950b58b6a81ca294fd8baa" },
                { "sv-SE", "3ab9982711c6ae00eade96625844c2eb68e6275529c6f4553a2aaa55fad4266035dd120b359f1ae8b50418114f84d2de8752488a23839dabaebc07db155bd00d" },
                { "szl", "3b6b75f17cd1e5081b9c5fe689ca246a1888c1185277c00fd69ee592ca9a4b4e1d98b3a6c793b8f3f14a95f38febcf537e1b955888b1f2403bf64ff447221f7f" },
                { "ta", "8a92608d09a2fd995405b97d25773cee66d7dd6abe4bfc0dc9328d390b3422b380f41d653b9ea12d7f3a30594388da1c8877d00f7709e107b4de7dd8ad227ce8" },
                { "te", "cd04b4aa29f3a00bd6931fec4f5e6701e249143e3f6c6625cea27c5c46e44276f0fd7da36fcd7011d7380bf3e30d09879c0e2c2c08505daaf1b09bed2fb47f5c" },
                { "tg", "113c267a8c511ece74c949a5d2b2c8a54ca030cc052cbf60935f1a036f38b0e6e845dda401a95227f22deda8ed62d12b4f018db6a806997a0819252f9d9f7e56" },
                { "th", "da330ba65a030a25f9e41317287cc85ea3e02b7e4134f90fe4c6e2a2990ec6e322a7addd1b78304221ce0c3803ab70673836410659fb386d82ea12885ae6dce3" },
                { "tl", "9613d0e2e21c36ef33f575489ca399033bde20f239bd4cd23f04f303956427722394938f93a5afffaedc8971a0f3fd884cebe2769f6837d294c0d255f656cd3a" },
                { "tr", "084d428a7a4a8d8e4653343d737784ca999cbb5498da819a0a85ca76ed2358e6e75691482dd25f810161ed21eeb38ad8e436133836b98cb34f6bfe44db7dd2a7" },
                { "trs", "81986ba058a6c81c69877d43a06cb93ec93cdf57402d4e9c2a6619177bcf1cd69fb7a3479883e7b434b50c9d330a51ac99983665c7b6191286a9b0d68edb4b48" },
                { "uk", "a00b123cc3aee0cfe97ebc992978fb0fac38cc501f989e8f53ad9098770c612714c0340688ebbce4a2e53d4a1da2a761fc4c1b506a7a36a1b4e94e9e69d38c5e" },
                { "ur", "e9c1fc894be02e1b302e229eb5913cb5deb705fc053a11565b9bb64ac8099762fdbdfc9b3e2730f4b1e248201cfe44fe98242a353501638583021b02daa44322" },
                { "uz", "0ad897f394f12beef854c6a6defeba5a07d51a932749aeb2da98b60bcc5222d7d02de5a5fd127b029decd57ca9c5c97529d3b87b7aea240a545bbeee44647d76" },
                { "vi", "cbc767c7d7005abb074f9f6744599ec7b59bbfca0c178096f97119e0926de8dd9610d572f2216303a6fd19384d7ed0a1173fb97a4029aff0e7dc7e8b7a874a44" },
                { "xh", "fd21ba1616c4e23d20ebfa2310314cc849e932f88f5f9a7138084d9a117968e4a0de9b2b4aef000bb31ef610db1677b9dcc38d7b3f7b531cf8e5e38e7319027c" },
                { "zh-CN", "cb12cf6659329ad32284aa871227d5d2e1faeb271c757eea2ebb40eda54fdcc616f848da9b3b58456498521ef45889b6eaf8fadc6f240d19dd2f353aa34dd34f" },
                { "zh-TW", "bfe4da1ed671ebff1a7dd3443e467adde0445b4fd52c4f50009192d4aa8340179ccd816db64dd446dc29ec1824f89a68ab811d22f7167e9d1170d79b133549ba" }
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
            const string knownVersion = "115.12.0";
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
