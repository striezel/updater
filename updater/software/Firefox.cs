/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/152.0.6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c4e1d193137657f72f16eb3def7c1cf39a4d11b8f6b91a17e2482313d36cbc91f5167839260dd0b2d27a228d0e1811f203beb84a7831e91e0ded206feddbad18" },
                { "af", "44158890b5a113b18bdf26e7fd7d06e461a8ca26568ef5dadf7eb6d60c7f89a773e9009cca9f37c8e5ba2ceebb4d8135b2b69804cb08ba2adb6194a41710906b" },
                { "an", "ce5afd95b043090055c8111d007da6438b3d4cd50d3a9f8e3f829e7f69fe2289bd67bb7b8c4fd64ff15d4586cb4db3ace9f594bd4a49fc79666b69c471d3808f" },
                { "ar", "0fc39ad4101361c3d2f6e6ea5be31f7335eff2871cbed37300b5fd6b0e2fad829ed5e39c4f00f3667e34c5b806fa23b956291f32aefd6d8fad5c5a23ddff661c" },
                { "ast", "2dfe0e8edb953363ed07ffc23f7cb471cc460a96865c679577265685c584a9c569cff0b3993727eab35a88fe2547a4428417636c4fd9595532ba36911a572de1" },
                { "az", "f09b32574b8e549df74bc40c8f39256b93486bd45ea0a66b24dac051681f9d6db6d16da53d3da7c790bcdc42445f199351f68a3eb7e2254a7deaf2b26f66aef9" },
                { "be", "c3f01eab7ac845d14ae6df815391d75667412f6ac0684aee8fcee9e3b884b07d8de3d2dfa340985d7248bf65c2f248526ec29618f5b734959e0de4501d11119f" },
                { "bg", "edf1e41fd12ea3657b05aa6604bcd2cf327bc7cd8ecc22e111e2665f3299503304c90b34e9a191eb08fce1edf47ead75cdc6015d83f7182d3343922e76fb60ee" },
                { "bn", "df6f67a624190f4c23ce605972129a610a034a2f2762df72a859e39b689352b92d79a816b1eada3a24d32d590903401068b9cd9ad6970462ef5ffbd79700abc1" },
                { "br", "a972a6f9e79f19fc83c1a9b709d9db6adeda304178782407a2b320448cf38cba773f362ccf68f6f09f03784d0d22260bc3038713d73e79b385dc1a8265aa4776" },
                { "bs", "27ca491b8ae81c335a5111016b0b5081a73595a1e54e5e9a0a7b1c42b2a83c762a4f214d990908f00688fe9dce5b82cf550a827b1a236a70467722a0b36993db" },
                { "ca", "584bc4157e353064ec60d233271a15ab38ab926d6720b580c058f3a7dfa14a0aea1ac78509679bf164aa277639480580f886603675ed8112d5cd5fefc9d684b7" },
                { "cak", "fa17f5d91aa5ae7ad5e6ae0b278f682b3a82e77b91efe56425eb93de715cc8b14272b17b5a7680fd3f6e01de0252856545090320d3f82ca62d4f76368345ae06" },
                { "cs", "52a214244e692db5249ffdbba4eba17c9d3c49a6d2848ed9351bef807fcaeab18af5a59534cfcc0eb7543df11b7aa9de6ecda60a828ce86611a7a9078dc6f99a" },
                { "cy", "e447903c74d7f44510ac67cd96860f9bfdf4394e4597337bb9a61f7356e324988f4bf25c1ff9b51ba79e50c6c41b19e08c9f03def8361855057a74124b5afefe" },
                { "da", "ca48e4cc77c81eeaf5dc63897638e2160f733c4e7be0eea7fe88c0190378cba1aefffcb6598435fa132811a3738cb678a0d26228140d1cd6b06f0a1c235af5fb" },
                { "de", "de2aded3a061cdc51289eb6d45416d2c6464ac27a7fea8a3007f148e5380702aa9ea4658452160377658ac590b2ac763de6f3a98f66bf68abf6d55bcb2e35432" },
                { "dsb", "8107990130f95eb4b315090a8e81b4a0b7502c1003453969c14b7c121d26d4b5f5819f71ec7a3ab197e68e5c8e7c1eff04b564d8d46d7f2504d7301200de764f" },
                { "el", "7ed057c57023ab5b530e766ad3a4b97fc416427a72dca552d903497fb10acc10b0a880ffa50ab9f33ed81a87a15b9323928cf37b1cb9398a341ad5f0f8964274" },
                { "en-CA", "68cabdb084d22e7c0aea5dc9ae10d1fdcee3f3ffdc28a9626bc771b117db23559df93c04f5c0633a6c5fc2c7e897944dd75e0c122390b9830cc8a6d8cef6dc67" },
                { "en-GB", "03a18cefaac3680dc6a04259fe050fb0c40937766e0a33ba7e115f0b067fba1dcc3fca5ab94ecd20b0170c21e7c61860d36f0442aaba6e7aaa1b54f7b5b32feb" },
                { "en-US", "c8618f5ceada957f1011cd34aa3e0f16c9baef913a5bd3f69c3d16d94ce12d45e684d68f274deae16ee8600c6c57b7830446bd261d85a58585cb4e100f6a0c4a" },
                { "eo", "eb8a0674756d34d415cc77a054c59e550ad373721faffc17cdb4331d07a63e9c2b82e7a9cb2f7030b7e6286989975d4f1f09bca3b9073df7b26f92c6b07fcb8a" },
                { "es-AR", "568f4f1d088442b985faedecea818c41383ee31a9e317bd20118ca506df96f1a71eabffb669f43e7ef5ad4062ff4584a8195bec0d2c59b89bfdd71c75017dbf7" },
                { "es-CL", "ef35a81716a46cdf622970476dbcae76c24ff25f6ec46089d1ef9573724bd8bed76e99dd5550c4fe40b23fe62678b781f9e3c07f21a585de58d552579337f0aa" },
                { "es-ES", "02ae0d8de67ec9ca8cc350a599d21b3acc2c08750ec6dc63d00374274bf69f46d7e5684c0793ab22d6ec7a04ec9d74305c75385a5c86115a54683c1ee4cbdc7d" },
                { "es-MX", "8af2b209664b6f1d26ade401ee688d0f80f71816cc55dd2499ea528af049e3a94603050efac696cb1790569e9bc450b1970b84ffff1e9ddf29f4b55dc89d5778" },
                { "et", "c9757ef6ad708e38611045311d6d38ede9ac1d828d1aafe57cb767eb390411ef13578bf5dab8b008ac80aa2e95737cb1db99ca5e3e62253c880c3f7ed9932a2e" },
                { "eu", "ca450a437d1e2cb4ccdb789f9f6995f12846b62297376b76fd33fddb8676aaad8ad2b64ea103414fe5b37081e66d99d3c131a24df696f9cfac8c8e0a79f14242" },
                { "fa", "6eac1c25d41d9a2ba6045cad8b7e136cb23166b467af7bacececfcc0bb306af22d6acb896ac9698c3c43309938795c47501f4c8d9e00a17f454db71d04536c5e" },
                { "ff", "47bc209f6f50a7c5a5c91828d293661cd9bb346030e800c3091147a37d7755eb769cce22a9796938bce080644e1cb0e252e0fe3880084183639de62e986c000b" },
                { "fi", "6be842e39957f789f6b4dbc828cc625ebc52bc4091c345d27ae25b3a2ec1266afc3f85de98f471bbffdb56aaeab18c00d0457b32c9763005e736d126c431077a" },
                { "fr", "889372b25092f34d2c39dda01eaa25000b7871eb03be8fce27dde857e3deb86527d0556e2dbfc5d331a7960eb334c3dbadaa216dd804c070310bd1578a7bf6b1" },
                { "fur", "f7f434c0e96701a2ecd9182f08c0e78925bbe81333de52ad9891c3e5b3ec9f354b00eb4740c6b09ebd6cb72fff82ed4db28825c3767241d1266a374beddb5477" },
                { "fy-NL", "e6011fa68ad0020e5d2510407b82c4411f19946a8e2089dc32fe3956f54b8ff8a28d52fe9812f84f971657b7786d2a1016b9c4d246a4878ba3770d0f5ad5582e" },
                { "ga-IE", "92d1775121ff08dca3ef4d1cd17c0b74e12e20c06b05c5f67e168dcb4aa3f255fe7b72615bdbb22ac0a98432230dbfdbdc8aac49e9146a44dfedc2fc579b411f" },
                { "gd", "10aebbc3a1217f91a1080ad7b66eda934d891e5271130ffdb2a5d0414b3964f24efa70d60388d269b8275e5c6c237508554666a994eabf7613e8aa8d142efaf4" },
                { "gl", "918409f83cfb4729cdae6f4b0d6d758367977a500c079baf8763d10a0a7ad9048cbf6ae1be50521de6bd3bd79f298848da2ffd2eaf257a0aad58cb4d55b30a33" },
                { "gn", "c3f567507d28b72ae1f6b2cec8f4056f18ba556069d9f897af5370f5e7dfd216c1b4913ff7933a190629a08a9d220e639849f34b2df14cdf2024527a0db1cb20" },
                { "gu-IN", "1615af669cd630a19aa47554d4cb0643acb49c9c787c7ddf1beab563dfa04a34c46516f14b7a0d795bc9208302266c3ec92afe99d861eadba434cec479a6b343" },
                { "he", "b1702e50c9ebdac609cc1551fd9e6a3a070abc24d314616869db1371ddde0dad73a1277a3086807985f3901610893bcc22a5593002bad413c617277e0f51f689" },
                { "hi-IN", "50472e762876ad657e64a08b9d324b676c0afe41c5be706f0eec3d2db2eee44685fe98202b9a3c6df0be3be23d66370b34551a127eca7b2a3a2f8d1df250b0fa" },
                { "hr", "80a42f8eba7a918aab65dfaa5699ba655d932f328ffaf5fc281e135a910e45a8f3b2e932b962b56807e09765ca99af25e52d1b23bed6a9ed4a938fa1dd56f5e9" },
                { "hsb", "3ca57fa6578867edf15cd6a17f4bf20835e914fce0ba0bba205b756e7edba45492c7f3f485bfbb65e32e01202005ffed81883b93921babc9ae85a3e1f65e1921" },
                { "hu", "229aa8a0ba54452823ced0280b1e0b54e8a5e25efabaa5e0d0bd444bdf941a41098ba098f6f39e02e7df7e334fdaf10e4c2a37ebba0309669daf5dfb30d466d8" },
                { "hy-AM", "3e9c7962d10e74029cf5fd19aa7273310476beb3d92149da623491d63156dec664eb69f7b79425eecd0ffb6b7aaf78218440fd2bd26d1ce422c524c6073795c7" },
                { "ia", "04a33c1c275c0b6df0dc438afaf08402dab68c1c6f80829a3436c7a0cf685156443c3ae0a02af4471f5cd3ed03c788a7152ea1de8ed71003d8637c34de0b4e66" },
                { "id", "1307fc9341766a0de732aa19015ac26bb17226a3b7b27f73b4cb4252cb33ea7b03ef7cd74945ca0cf5fd80c1b18e123845c2e96f95c2ab68b6f1e8b2b3e61c9a" },
                { "is", "93a7f48bb917d4dec8999b86ac1a2ca1c2e09db5db50a375e62f3f1b032e14337112eb5e1306f72f59cc04233ce3b00e5df91320ba61cb398b8b5ea2fc06da5e" },
                { "it", "c7a24eba11c6c6e5429a66749342311de7583fb0eaab1026d809ca7fd849f1a25fa710064c789329083acd6b29ee4dc6e8bcf947528c73aa7b3ccc913e556c30" },
                { "ja", "b7b2674f7f1725005b41a96f1e8e2ea4589afa76a9f99fb8364b2c56561205c8298357bc8973ecddc4fe27adb740069ac024885998af29f80dac38536c8c3629" },
                { "ka", "be9772a32b6ebcb5c629c0cd78aabb1dc12f14b56373b9ea320cf4a0aaf88d6789bfd04241d13aab83a7c171a40a50ae9b84596ad33ecec1a71920973237d439" },
                { "kab", "30f0b138418a85e4b379e5c717d06df502a83be7142ba95c2c8ed1c4df6fd3cd1219697f2fbf6efa473f984a4c4b9415a5e25278dd8d6cd16f869b49ce7fceaa" },
                { "kk", "d6047c563d3259b17e232ca972bcb1630352732dd3c0456ae917bf3a12c432166f616a8633a460ba87c46482675cce675105507fc761b64bb1b2ed97f940062f" },
                { "km", "fdc400d6a257a3e5334a044b0df4c2b921dc0f36494bb5a266487e1070475e85e659726bf48070dab3c1227086098742514f606d95f3283774b017ce160643f8" },
                { "kn", "300e535d140edf8bd272cb32b730b1bc4c0a8992fc582458ae15c4841a7268a95cc6faae74accac520d36827922437f16525494f1d83d29e45df7e5e242b4263" },
                { "ko", "11e380e7b13956feb50935ca0fed7be252c11a12060e1395afecccc565164db14e0b803807637acfec9fd34a11b9ebbeeb440e4d8a796b51741d7559d942225c" },
                { "lij", "51fe801445ee238047ee9ca6e1850f6ff9d4a4d2cfe178ad22294e32faa71dddc676a50ed24185a3cc7ff4c813d424275310db3997463bb5c7c84afd7cf4b3e0" },
                { "lt", "13e9dca39927ee77530a7d32a9f3323adac7e9fa276fcfb43ff674604e0b00e208b088243b4ec9c92a5e50521fda981f8aa678e07c742dd86a2fadcb5592ebf4" },
                { "lv", "bb0c64f48fb7823b1048ba326968cac96c1183f74db963d30b93779584b49935a1f9af45c04788aa035933927c27ddcff1996df1de765a377f43bd116d684c9d" },
                { "mk", "b7011a2b7d56650af94a94760d8140d3267495736399e43157bcdae41a1ae29a34da46253d0b2fb4a7deeb43f0cd6c0b7751d4f53327e677e00d771fc6444363" },
                { "mr", "f4e543856c747003d1b011635fde87335ff00b2df0fad84361b299a197fde72527dad099a11e9ea343327c3b44edad74e9ae513dec36e9c8888f0997afc87045" },
                { "ms", "8a7aae24a9aafdc6cb6046ec69dc9be30f225513766983f3d63f1f3eb7c43cd8b7fad330f1fda8e9d9816d65ae34b05f3bbfb53838fc9e560090214cd16e6a62" },
                { "my", "026c3f82943ca3b69f17a2ec4bc8c7302685fb1d7315b7ee9ca80257e118b0c843545059a4601cb4b7d7c8ba43d0525c58fae2d4963ab2c30365b835efc8010f" },
                { "nb-NO", "ddd1c932066d31530aafa7aaa78bad5fe83fc53918dc16ff3423664386b14833cad512dd234525b5347d997b8d5ab219d993dd4a36cff33aab749c5956415a3d" },
                { "ne-NP", "d5cb8ebf28ec3e4d2517ab6a756a00c2f2dae16825956dfa4868a4bc48bdd16b1845c7556559cc39bf52affe3c7752f826572d69de634109422adeb4a96b88a3" },
                { "nl", "7a3a060a96b0daa1dfd04406a77665f9be2bc7d4135f9b8027c195e5e01cc9f8d7c2555e852b138877a1035e67ee1c3839e1c86b77234274d143442b31bef137" },
                { "nn-NO", "74a7654939c65bf1a820d86a8c76113488af478c18d4c0b66ffe2fcbade2acbaac4f032d35db913b21c3c70925713773c6533693be20401292efc857508365f4" },
                { "oc", "baddca2ac9abeffb55b0ead228fbe7b9817da42784ad4e6614d556cf951212fcae6f830396fc607c7ad7eb45f4813dc4b8b181c0f0623a5a489a1a46c9cf1ff6" },
                { "pa-IN", "c03e44b0076fcbe14783fa80d41afb55af737a7212fead05b67fb3506e91b63f37c0376338a0a90eb4260be3cbe93d16f12ca5fd2ae11faff52c86d86f0ea59e" },
                { "pl", "da132d8240c4cc5a618823e34ca8777145e02f5cb4ce1c89c94b87e80c6d8521a74040571d81f6920294e9e843d555059faca18cbd386f6325f4a95c612d22b3" },
                { "pt-BR", "dfda48a2f6666df8d1bcdd0de16dd214170bca76c9b2aec0051c08a2726ab0f53818b63840f0de003d6b6c35c5443451b7f648a1bf7eeec42ff5001e8419ce66" },
                { "pt-PT", "58d09b762ebbac7f971fc45638d039a692c4ba8becd0de53e9da8b15885cefb2c784781c48cfba2b3d316bc9232dc42237af02705bea499e67910d5fa4666b60" },
                { "rm", "d50a160ce828877d63bb0ee014e2c3e90220b1105235d2fbd9477b03e985aac2c9bd60e15ffc3c1d72cb624836c57bd7465927c93ed2b2e88ea7a6f6ff8192d2" },
                { "ro", "2a719057fac78b2c48136101245b5fddecdc1408d6da11c6a14a2a316bd892d7cd240537a0017eb07ec3a9982446efb40e3f7b8c9323c91fff820f343142f09e" },
                { "ru", "ca192cb3ef5fe6c54d5ce764014934376fe99e0e17a11118f817d6b1613960d967ef799b3195e7ca2d7879d76b5f35f55f9cbfc89ad07715784b57a6ebac10c1" },
                { "sat", "0aa5e7fa4dfb4d91db196b82ff3a3ce1f1eef713aa932565b1297f3e99605d8c1712c28b8dfd8c98b427bb8c742bb2373ac35032a1092cec65c39984a9f72362" },
                { "sc", "a4abb916977ee9efad9218aafbfec23ca4b7b9cbc79885ad7607e003e243ab7c8a45beb5aa1fb60c742fe91472981b4d6b3851627ecd57c2d07beed81d622ac5" },
                { "sco", "0fee736af7945a2d03e269c64bbf69a62a3ff6bcefaa09bfdaf23c9bf5b83658f048dba39c77eae8f99af4c49e0de29594787347ea48d3f25027fd0e160f2fb2" },
                { "si", "cb9ba4bc56ecb8d8e8f260c7302997664a59ef76a00a9079c79e97fb48983c55b1942b1b9b38ab4bdf7b18b196a7d9368cb450a4e295a0f889bbc528a2108bcb" },
                { "sk", "bfdbf5c39b7cf426aff74ff8602203b62387c41ede1dd87e5e9708ffcd78edcc41d9bd2d2eae5a5de9ee432c0f7fe8ebf7b5c5fb2b816929b4b544b1fed90745" },
                { "skr", "a83c5d61fe6737a19fb17412955d557690f96caf81cd336ce4c25873dec5e84a40c9c5a4965a8a23e4a000f2709f93de1081768edaacd3b136e72b23e54845b6" },
                { "sl", "1d749f5015261d60e0513329e94adada858df783fb7bdfc60016bee686d866879b762457ad2bb1257d708c4fe65572ef341ce75429146e3aed61621646c6bc0f" },
                { "son", "d8e1b996c98ae47e8fcd4d93cb3b231de44ad48155523f0a9daeeac025d4aa6e0312c105d6dde75686d1a3ad2fd2c6196adbad829ea4e9438110ea2a8256bb6c" },
                { "sq", "6d152b5cfe68c718803792d40b1e0b88d5f90faa9fa6d8b00c872d171ba9a86b166fc27928f93048aecc5c5923f5d1b1bbed622147322445fa2f8b283c886cc5" },
                { "sr", "0268b249431adeaa789896273fa9189dccf5f44ec779ebfd2fd13a2124254f9e706e5657e867a6fbdb126423a9dd9687d1df6d7f5c4a2d63e5cefb4985c6fb2f" },
                { "sv-SE", "9802561bff355c33809316123432cd7b167d7d2815a0ba0f6c8ca6e8e300583e6244a46dace3cbb17e272d79984c21fdae41db4a399dfc777200cf904a8c3656" },
                { "szl", "172f48a2d5891d6b2486aedced941fc95e75d1ab1891185aa988097e6e2ca8f151eff19639f96e036e75481ead40666ad6cbb1a8cf398d221918c1573c3d85e9" },
                { "ta", "8b36926dd20abc36ce9aad89b735aa28ef9403246e5c86a28939fc85fcdf0d10542e4e444f73fe68006dda6850113f3f4264e80ffe3585027c6de968467547e3" },
                { "te", "64ca0ba05f2c5510f7316dd5033143eb9df4b3e0d37c1c582fe90f12109b6b29f9736497c0d2d27fc3aafc8b79320ea624461758acb128bbaa299398f0c38ee6" },
                { "tg", "afc2144907f6b186c4afa79445dd30f1e808fc44f0ab289249f6dbb674ce6273f3447c3fddc360c566c1df6b468917e6a4894900aad300602e91062166b29593" },
                { "th", "a8413840885693a7e388f3a7746dc0b6b2859ce9bbc64c99a81f6bdfeb98e853521cea8db44243389bac90ea32c79a6016cd15aa88fc8021d57668b1deb34d71" },
                { "tl", "1d011bc98b3aee591ff1f503b9c19a3815d325a5efd0400757931dae8b0674dddaadb45cca0749aef5783c306f5ced8017c9cfd0ce11ff2b1865fbd179651a5f" },
                { "tr", "560eba4e0dc15a3dba6bf66bc0090c3595c72e26537c0d74ee42be1441a3b5320d6d5a3b8b14dbcc2f8c09b800b72d2651189e0b698c7fa397393066c534510c" },
                { "trs", "3bc290de4ae3033c37343ae8b30f721b2607d084f7fe0f65dda0a8873ee54f95670f68c9501b72a1a2682040d1a9c39cf7854a8014e0411569dfe1aa5dd40d0d" },
                { "uk", "36db8c1644a8c4d279e43ccc2ec216a8ebf0be84a8561713a4d56fbedec66066d67405ffa4bc006ef541d38706e465b61f67d73da539a421eb25ffecf9a51064" },
                { "ur", "8bc721efe6fd41df23475e8fbc0fcb337d82073783b5d87b9644492f1849eccb73862da1107500b5ccfd89a69f36a2dde98a697f03503e8da8ee42f81a1545bf" },
                { "uz", "c2db88e9c30fa706e50cef5048f0bd6b124b4780851d04bd0e229bff141688e1f17ee8584a694440da49efdd9d2315aede4bc6329494acae1a15feb29b4fec6d" },
                { "vi", "3b4826eb1d660359c8fb1d8342dfd4287cb5d75813b94b3de2e51c47042f3b460e53dd41b593f824aaa372a3731b4ef519be6a34bafe086e049080fd5cab6ef8" },
                { "xh", "da1ec179d475abfbce7621694e80b54a9cc83d57b840b0ec900a6c86c6ca22f49633da8574d375f1fd220323cf8bc569ce6db0698b37671dd659024d3eb7e224" },
                { "zh-CN", "b797f8a4299c5014ae5cef1b544c671186d09988e09fc1545b6f999339537ef21a4f59cafa0ef5d1be871ab958c0b4690978bfa6820b7686c95331462cb75f7c" },
                { "zh-TW", "bede45f771e38a6267fc3eb5427c91ef54d9b0ac9395ff6192774b49335cf326101353c8fccdb85d38c780b045b2c5df6251ccb2e87be4305c79f15e183ddaa6" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/152.0.6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "df4f08480fec0a58f1f2ceee99d3706e2077f6bf1ba510d3a069b79b7edf720dde9756420ec3a4b8d582bcd49282d7c239bc49ca5d9747bbd57f50b346bf28fa" },
                { "af", "19f4ecd9d304a3995cea8fd40a420dad4b72039da32e1dd80535f0541e62f22d18c90f59697ca38e5767aff8ab45d5c811c46909ab7207624c2e6f3d484ae522" },
                { "an", "c4c3f47928e4fcad1d7431aa376e826968e0f8a7f1781db1989cc4296ea86393154828180a05c1182083b26eb0bac00b43edc1675ef1417a568e07aca5d53e94" },
                { "ar", "ef0955df93e770e1df450ccae3200173071964565a95e0d613625a9fecc68dd9513d9875ba491511dbd9f876adfe6360eb19b3363617c647edf150d69f445910" },
                { "ast", "c89c0aaf98a38d94cdcb0413fb5ecebe6c80d27679f986499454952ba5b9b969e86481f72c48ad4887e1bce049d2044063bcd7c11ae2b87f06944348465a5577" },
                { "az", "5cdcbeceba3b9e048e7627047acc6dbf25ca1d890203e14aa0b8c44356b1d0d2236889a4f0056a982da3a2258b0d5f0cee72d4a6ef4c33d0bb33941da32ee863" },
                { "be", "f0c002691045312ae2d45b816bee18113aa0c91fe177d1fe809a5ee524715eda1901019aebc75cbfdb5d899f21809495f5c39b9c6db70e71c46d0d2fe6e2fdfc" },
                { "bg", "5a71cd3de65a3cfa9b27e9c33dc1533de349168915461fd4c7b1de51ee9b7b347f64f7aaa44e6479caed9e8ec3e0febb51f727aae27df7b17638f0c5258bd9e5" },
                { "bn", "6e7185f677c2f03fc766b95800773d642268650832f6168f0a193ab8a4a21e5eed8e0dbaf7c308de53482e6ed7ba51c97725091984bcee5762cdcbba3f91c983" },
                { "br", "59ca014f4e5e9597b0d14c8e16034e7008ce6d6dca35e83265d313f1e06e7db1aaae52a91638c60c111432c9b9b6c3df0826c6c69e204211b1052bea6462a0c1" },
                { "bs", "56ffa2df854a6e0316b5c2da7039e709949459cb37fe327d49b5fe17498eb7a8ee3246dd020cf00dadc5ce0587af6fdca259b840e70733f9cebaa3b55a56ab89" },
                { "ca", "854d500882f91353cd509cdc538ec554899c6d1131df8a7c6b5a8b5d63165f1d11638fb4ac0ed99019bc0fcf17600e67f589ede8909200862fb5fa17a77b1d5d" },
                { "cak", "304e503ba15d09c4e888e3d376f718b07cb33bbb89cef30565089f96f00fb084f0bbd778160712bdac7dd42b5fff43e69073450913611d17c475a7edc81683d9" },
                { "cs", "42fdf64dee8d9234add585658d73c1e62b0acbd4b049fde62868282d357641bf6c3ca514987c7341032a3f6821cc9dd1e8984fb6fad27f7a03093a960d1f633b" },
                { "cy", "c64d72adf82cfd45e3c23fa2fc3e080198d33f0a539d98a72471957ad1348d455a1148b0f7a3eb80afae7edf0e278fae88af9729916131ec6bf19d9cf2591c58" },
                { "da", "a96249cd1b713d88492df1b069658718339927fd5a0412ce70cbc8da5592020ec5c9e33a344cfbe445d9f613e8e295fca7e2875b9048df5a96f7aefe500872e4" },
                { "de", "94cbbd7fc888fa0e9a2b3ff3f8ed95fe341b169a02c87fe9bccef93f6141afbcef57f7040044d89fd5e931057a1ba17e4378bb3af9b55f92bc99b3147d2117e2" },
                { "dsb", "cb3f1df7eb7279b51d5355708f7f957801d698b6624c3c4f65bb83bd14e920773a25b183df73c1b895605ddc9e4f5b844161ddd1ceb4ae91a0c3d770c0ab2340" },
                { "el", "951573853beae25dfefacb041631b2d3a15900ff68cb2619cd48d01cbc6ad326196eb0eb44a60d3ad8ad8225df53354a2c8458de1893569705f637465113a4e6" },
                { "en-CA", "108677cd841331ff64f633ade1b02470ed0eb2d3df1dfa628efb7902b05d9032bf45521b8018c717634bcf259cb79d17c157eb83b123c57f449b0f7bc2ed9d7b" },
                { "en-GB", "8409d0c532ef3e5b3282914d9fcab9db4156485e3db9fdfd98c4e11f6ddbc0bd36848411831bc34646d7d73db0a25907c177775eb8d87c78902699a3139135c0" },
                { "en-US", "ba2d219809d2c498088c0f6f8149686990f1ffdf27aac794b534f1e7499345b5ff5b0fee5dfcb553821bf5d39b4f21b779d6a6d905a58952db4c7ae0354722fa" },
                { "eo", "766d39903aee61fbaed7111c4307b0b3e55dc900984698245f9828002d419b00ca7f8b089963938f94fbbda6b6de65abeafac586cce25545384bff8e0e15d5d7" },
                { "es-AR", "bfc5dc11762a8f04ea41892ab36a2d0447514c87297440a14faec31322a935f0315735f373f9f0e770b732274a635f8d63603ad6418f98e4798dfa4c36074f0b" },
                { "es-CL", "bb04414e1027f87b05355e7bffc029937006e1b446e38c0755f29909c1c3734b101ab2a5409ced656b88e3dcbc7cf36c84e0c39d5b4a05220a354fb96f113846" },
                { "es-ES", "c628154eec58b22e8866eedaae17c8535fd26bf04b8da9053be4715ac40308feb0391840f9317f17ab93a825bb0b328f55e7e5f6271d842fa7087cc7c8840a4b" },
                { "es-MX", "9b8b63e2cd76c4b6731f054da8f35e17858c256ebbb1c76428e3b46584082fdc270b895b5822374659f796f72b4ee5083a8a2d4b34687324064d7a0e44677d34" },
                { "et", "d234cc6a08de0570c22f078dc994943144225d2a3a2a99c9df64e2ef00959cd1c5ac30b28afd087de6e59d2c72dfa0dfadd4f65a81f004497e898a05b17e6472" },
                { "eu", "10e532d33e082421cb997b1da8dac407346d2afc8363dd40c6c55be505aede37b5e56556b4471403bdbfaee30924d32685f49147be2953e062356c8daa228d1a" },
                { "fa", "30095b0abb34a1d74534a7c517be6592dbe6952225c475bd359642c47aeb64fc013c31437e5a1d688a455fd03aa74e17c87d28a51d1d48763b514792b16f5ffd" },
                { "ff", "0cf23fa0e98fd5dc1b5f8d288e1fa4dd79eb1ddf75cb939d86de9e4c8e09b3bb928b8d5cd785b8952a56105e3a1a29e52fb7206fa5ddabb377723bfc56a03169" },
                { "fi", "00e940f77273130d7c682ea5353969c7eb8799b79fdeeabaad8c8ad19c8ce03f14a46b6a58b5aa9bc56558fa6860e3beef5f72a2b3657d23134f6077e95b3920" },
                { "fr", "edd57750a43f102bc7233b16dc68be84b3d489767c2088fae7a03b20295b6f27e925b908b4ae91583fddf563f6b256220df3b27fcb893de4f774e929af3c51c8" },
                { "fur", "4a41ab478b6a05cb43886e0b897b978f19a5b87db66536333cc29fc48e06fe54c1f8b1973a5c9dacddcf8704b5c95490078007e3912e4dba6501c374f3c688cb" },
                { "fy-NL", "5188c95f0a11d5d8c85b65e2259723a63b9d7879e42bbae02060a52bd882e042a9a2e0fc658f2058ae2af35349abda4fffed7b9c65a244d4c7d4fad39c17f0a5" },
                { "ga-IE", "a6f90542fa7348151a148592305d4e18277ea05a14cd3696a02fb05e62935654e3916f39a2dc2a8de413b89fed9b89ee9e0a9139d0f5c6798ee211325750c608" },
                { "gd", "2b906d56951c4bfc794c9c501eeaae2dce622e5853162070095df6760a1f05fcc81f20c2e015a815774b3b250e32a69eef96f8ced1b569df54d5e9b3284acb54" },
                { "gl", "9877174d2aaf9bd67edd5c45d1f871ca9e046886656719a7f76cf1528254340af6a9b7e4a97b1dd3f04845206fc7eddc0ff1cc904d76ba72e0636b9ee396d942" },
                { "gn", "6773281902ca2cc6cd7e79ec289ce9604aa59774f3b377a0afa0a2d01b31d9e7863d9a423ffe398272732c715468ad867a2933fd96d2109755f4903e38771266" },
                { "gu-IN", "fb9b2c155a64b31f9f6da1c13cb473b21679158e538a7623428d2ad059ff59248f1fdfcd3377d6798fdb774ff8b371e1e816cac716521715c16663558385404b" },
                { "he", "f165c91f1670cb87659b7a3a2faafc71ec5793f02ee4f689bc6135f29c67c301f0bbbd85304cbc301fb0f454556015b621755a5d41274724e897a4231e1207b5" },
                { "hi-IN", "a110dfede402323a625b212a2fa45de81f6fb591f39af9c6225c2c2b07e80280396cc2db7937d00a25ccd57225b26789a3e282b8cbb675ae9286ba440aa40ab8" },
                { "hr", "d7a7c94e294207b8a06cc830828d85a8b8f8baef53b7cde59a2b6f1cb44013f817713164d654415c1cddb57cd440bf8912daec7a4c883891ad8da85cc1c818b6" },
                { "hsb", "dd344627319725df6e98d82290787e578330c6b5846fcd7e37562d20b220ba887410d267277395b6a0d4b630ef295d099adeadd3f5ee841d72025498f16b716b" },
                { "hu", "93e742e71cba6fe74916a6dec5a41fc4e1671505556cfd61f4aa2b11e899d52c29cafe9f6674889a9ad3007fef22f491b7732cf016c894ced3da113e9ba8ddfb" },
                { "hy-AM", "d37c09bc6c026bc8df69fb48b56fede37e187d150bf637d167258e5758625f0f2d709529987fe6e6247a3bdc0a789db76512ace031da3003829652f43be20d52" },
                { "ia", "424770e02599744aa7efcca1e396901bab15d5e62ffda90de42f2115917014ed8815e32fd67eb33e9e427112a4aa9d7c2d9a51e987b5b3106aab75fe1ded28b9" },
                { "id", "72fff71ac4ecd1f60b0a77505076f9ca38fc93c2c463a3dbcf50a057bb8ebdcfa380ad13c6ab53004de7549b43079acb28211090f6cc200efc257ef21d4523f8" },
                { "is", "5f8df1b2755d08b5f453b625bd5dcd7f6577313d179791eca26711ef90c0d136a92dc337f14ffc4a0ef7f3618414da1f2cdfa53c600901697f2d713e96b01950" },
                { "it", "a442390737767332368b85ad6604587538a1aa606cf90106e2b9fe56af2216a4f9e3cc2d62caa13ec99fdc797649fc9e3aa63f436be7165101e8c8cbb1df9138" },
                { "ja", "794a8bc0951890f91192d290a1f7c57a8be583a2af36040668ff40b48fca87ad89b13cfbef513a783a501b8c4266080d6fe26584cf05e1ce94a30b086153056c" },
                { "ka", "ba2e3f76ac8db47c8635605e17d5b1a26e4e24616206db5f678a23af218f83e6bca2d9d6571d90c7cc834364b6087bf707774421a653b0babd67f390939d049f" },
                { "kab", "2b16d27e05e2717b9902da0a8b70acd5890c6c9c4b0a73d569b31dd7f808004eecccfd05c4a2465224b0e42eb11d2e853bccd63d35b459e515a3a7f0ecc1fa08" },
                { "kk", "b1e32a248429e431c39a5014fc208b83e8250f522101deb714dd12b509db84f086fc3355741c050690cd5cc853b8eb0fc790a8986e2a01bfb49387feb736df43" },
                { "km", "a9737d1492b3b9f4310aa2af3aded25966a649ce44018531e479216a7bccd0518813275065325673a01573ab5d4ed6282276e513bea12c31782ba4cdd4246e8a" },
                { "kn", "299704a859588963a5f8f5c3675f26913b1cc5237d1e042d994e0975eee5312a6dba65e4cb1ca21d0e6008ba0db0c28e96e3460c213364e9104c1621c32c094b" },
                { "ko", "0e7262ecffa8df1594cde3b86ad4c115b7431d4d8b862db50c6e6a36d1a6455c9657722dd3a7bbe7addcdc8f852243556bc0bfa10b14129eec247af2a9848390" },
                { "lij", "6a1453735d6b506209fb77c927d0ac2db23924a5121b0fef12ffbd57be4e13bd7e554c040ded147970eaa04e90fb83f80719a2c0f6d086d1652ab60b59e472cf" },
                { "lt", "dc3cd4e50d5bb60fb525787dbc19b9b94c38a2ed2a57ae58c1f82b77ee43292740dd6eec44cb4a690f5d0acee8f6fc219af9b3537dcfe23c83932f103d6b2169" },
                { "lv", "5b26c29bff0b834c1f4abcfd3ffc11dce48a081d2758a3e64751b79f03e7bd2d6c925a9fdbace53fe1623732bc67f939d2a0dfb31a7efd9b569c864967d25b06" },
                { "mk", "a5433f5b2045e9dfd9476c19d8db182160e1ecfcbe4dc6af2a7e535d29b290185ed36da48b58aed61c287f312edef763e8c563dd7b5d995cb03456eba64103d4" },
                { "mr", "ad23fc6e27235d58385caf00d9dd39c2e7258d99db565a1852ffaa921faf2c77e7bff785abb34ba61c89731b1c4aab581d9f8939c36296bfecbdaf1690d4bb82" },
                { "ms", "bd23eb4bcc4dd13f763c98ffd3cb63bef9c45403e552f62ca28de829f007b5e97b2891d5df746893eb55915f2e4d7575d59c47756657851003ea1db60cde137d" },
                { "my", "36f32d15e16dfe6163eccdf60d87dbf3908a2cd0ab36c4daabdc27253daa298fb270bc19075f5d45e9db469c37ee91449e3b4cad4d4676c9d9424ef329c8f288" },
                { "nb-NO", "c8bbec46e5de937c4d056ce5ea9f97da6f811a70ba534d83490c59a0f070f6dce64eb5d3ba2667c963e7decd48513700a47baa4ccd6e88b834c75f364c6159f5" },
                { "ne-NP", "8214188b1e912c2a01bf7ea99a4abe872c9b7fc3483cbf7dd97b3506799c6b491d41a11075ba72faed64e00718713ca433b3e9209742173a15a073111d5c0718" },
                { "nl", "307d5e852f6dda8d07b7a0787fc40f06556ac412b8bce35a24598f50e584c8a77a8d753fa14b7dcf259cc065d7e63b6d75753625d507deb86a90790965538123" },
                { "nn-NO", "123d635e93cb4e226b70f7891432bdee4e4dba514d23490ce81fbe69eb669dd9bd7125744c11b92c0b4a422057fca7f15aab57684cd70349d0236d3efd4f601f" },
                { "oc", "23c2e4832d87e18838adfc38c62bb57a2fb1d8de7fe00128406c5aef18afe1e77215c38a9f60c66ede7242b98dd606ff65aefdad18e4f30ced4ca9e4c0260a37" },
                { "pa-IN", "c959e325e9397dcae742f6b969fc6836f84cf7149b982f826697c93a0bca2a4c8fec5577fe6002f707947c6011216915fc7d77e35cf02fa0cddb591bb2d8ee43" },
                { "pl", "49dcf2cfd632200fd2f6b2441245c67a1c2cba2b206fb245eac31220ddedee5bcb5ee540e55043e17e5fc1a3ee817f89c410c36a45d57e455724719053fa9cb4" },
                { "pt-BR", "56417aa766047d6ef0a6a790f2de7242c9e5441fef2d734fdee95531930a7cbbdad55fa25703ec853a672345b9804c1257cdba36f1ece4a4baefe697ca5d2ab6" },
                { "pt-PT", "f31bd3de72dce6f7961a3ff52757e1ea56b55a0a97d93a4d2d667c216303e50e5299d7ce59330a3ac5624a629784b1a6023baf2fa1ad0d4f63975fd997b0b003" },
                { "rm", "0e34fe61a591fbbdefdfb23524eeea1ef633b098451a9e2437de6c633180beb741d45fc13db36a5c153853fca33c465e659d40eb7a67bb037ecec84a2adbc7a8" },
                { "ro", "43f4cdf5045dfdd50729acba40bc3a120bab053ae8496565bec0076666d2c642eeb77928fb3125bb4170b787895224123b120b8eefcd91d8b7e891f0077e1fbd" },
                { "ru", "47da1b60de05d454a05b559815ce259cecf0c5aa4a3dce5ddeb6ca4c35a6bcf3d0d260c316c191cc1adb4f971da681ca4d9dcf6475a96ba2209d529d2e272335" },
                { "sat", "5fbb43631ba9bd895fd3e67316462d4ab56012159b193f366de0fd5b7de0a3f8e48e797db8245ba9924407f7443673e50215b2470410f4a939d8d08164bf0448" },
                { "sc", "975fe68c018c22c762999eacf4072caff279c1b2054317c4ca113aaa8e5b6d976c96b575cf5bfadc7e88f6c4dff4fc8f9c3d0ab0ce27426a561970599aee7bca" },
                { "sco", "065c76845d69db6b2f949e43ebdb017d26f3f7463806ef89ddd3fa9a726f441dc927df42cd389cd9ac573e8a088f2f836f359de5784f63ef0c90075122d9f2ac" },
                { "si", "a310c66487d67df33ef9e535146555a4087140766fc8ecbe525f2b3ea2b5df4e92c828b3ceabdb6d0e8a4d04814775be21913072998946587baeba8c7bb98448" },
                { "sk", "848a29c4166e6033ca8f4d5017b5d6ba09764726793051c9580bcf5ef8e598ae028dee1f2ad0f59ea2f0417641acd462798c4bcc5b8adb4161030c9f1e265393" },
                { "skr", "d3a1a7c4370834f25cd16c0f06f472b6d5775611c4a2cd263a6f1600153005dd97bad5fa506cbbf8c0f2f4f5254911cf8c9aef204a9db31ffc11ef0a091a4e87" },
                { "sl", "8a621839939d5731e9c26cb52475967d713a75e0876f9f2734161445d5afcb407816ddf8025f5ba221387ed32358319b422e5ec0034c0e69439ec3895a9c7953" },
                { "son", "bfb1be001d2866a09af9a35c8dd44af4e3ed1da52b66f42089be0e33796b793cccd20b986e2796d7b1e6faa286bf07352d233b2283cdf361048291eeba5c13b1" },
                { "sq", "090bb71897f3923a6f7bee2f7f2bddde0d7cd781dd22d1a9a99a9eeb819ebeb935d897d5ccc04a46302964c6966c97b672f4d96c224ef67945f3ce8bc71cc79d" },
                { "sr", "f6d84721bb02cc72413bfdf8237bc2c1a0d0cc1ac241a45f91fe836884a5620da8c3dcde0b879fe8bd15a0bc0c9e74227ee01d30519ea56adb16440618486227" },
                { "sv-SE", "069171c33cb96bd306f18ae863851f48ca198e35dad1c20a9de0d78320a443a3dc6ab1aba9307ae83fa4233b30723bd8011fbafb8566c90747b0befb96389e96" },
                { "szl", "9827af78a44ccbf2d996ef5ae194267396d42e6bb3c2c0909de757a3d6047afa4416258dcb332ff58bbe7b20990eaab1c701a7aa3f843e3090da6337b8f57c8d" },
                { "ta", "62fa135c65058e180bb5a2162b8bd27c7a7e36cef16a0c3a2c1576b126dfe0fdb20e9783af01bccbf80a802137db26be2bc485aeb8bf66095b39b75be0dd2452" },
                { "te", "1d5bcf5792fa24dbe732f6083b6e01931fefa23ae62bf82ecff53dc50ebbc20bb8a0d1cb084dd5a6c85b4b3e10541dbb9c76d206771febf76e637516e1604841" },
                { "tg", "cead00b97ec551acfcd6bb192e753a87f3c82d67cb3d497af7135a498ef52f51a1d1be84022729e53f2c50d60edcafb84b46a8b7f76eee10a5fcd435ecdbb7ea" },
                { "th", "539bf59a53f4fd9205284367054015870a2feb2169ea8b994a13b44f0dc2a1e168226f629259dfe53501808709578a01660447e6e8553f645653f5070e9f807c" },
                { "tl", "2a17b1152fc35dd0fa00ced4adaa3eb1e83e8635c8b8e73ca6f80d72d6b6df1227cc5dc02f6ddd06626b3464162a4fab702f4cbedf2c9bcb8796343564526441" },
                { "tr", "c2c54c767cf62a52c858f5f8fe698f0be33245873633cbe580b6b7823e921ff74f7c5ce84419d10e2f837e1fb5e065d656ce94c3d7a3dd09c099d67cf6206420" },
                { "trs", "c297eef6aefee6743c72db7c537a435922a6e5535f0017eebb1bd5569a31cc0c4361518418ab446ee4c75e324c49ea62d358b12cc05f0facee2455d33f178312" },
                { "uk", "68e639f9c7c9cf099e973d141316acd9eea17b996ffc641c02f083a572f4d7dde4636334eef3e0d25c781014c2c79680ea12cd071f63447045f27140bce70bab" },
                { "ur", "051550e1658c75589079a893f8a6e6b0d3996505845c3813c9e61559f4f63ab7b55db7824244aef5102031c74ce5e72c7bdc0b0349c12c9910ad695d8f663596" },
                { "uz", "b5c593190d09ada4d79491beef9d4b33a712187872b1064d3c38f786e808af1590bfde32c64f7a06b85c63a4d90e34334787144ac99a1465e763cc558bcee3f5" },
                { "vi", "49ec4ef8267e22f23452da2fab75294c78433b2cfec145b4ed4df2511ea1d1aedf5aac5609c7dbcaa3b4e55687d8fe885605511936081f891e5bf29e4760811a" },
                { "xh", "b25794331ab1566cd681b344248d8b718169f3277e87ed75dc26741facc99f3005f4e26315e9a4afd60a461a2269937f8f75e57c7f6e25cbc9dd61b94ab253f6" },
                { "zh-CN", "4f51cc673eedb9876d71a485140307d0fab2f1dcb920ceadd7c0f1e881816f01f66c6ba58712399fe5946f9964c1dee2d9af20ad657c3d5181f2d83ffb69b850" },
                { "zh-TW", "b715f22b41d54c02cb36c6368ef3ff949f01df4b38f054e628b01e4d9b319bbb9c729db2e502570f91920cd891ae2fa4d19c3d2fafd53cdbfd7483ff2df85fc6" }
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
            const string knownVersion = "152.0.6";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
        /// language code for the Firefox ESR version
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
    } // class
} // namespace
