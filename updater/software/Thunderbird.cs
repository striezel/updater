/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "153.6.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "4503681183e659e41e06c5e593d02f67633894f0c584a0dd36c27d9ca9d2f26eab15d9decf6631cef1f4a4475808ef3837ebef1aecc97fbe2fe1b90794371d5d" },
                { "ar", "ea81d201f04fa1b92d3b92511ee6c9eee9356e7264323cd9ac666d7daeafc86936b7dcc15e959b50c5cc1ec21c408e1fc92274f5138feab36741cb3a5471cb0c" },
                { "ast", "e029eb1fd3c6ee0e9f1322b9ad2ef65399d4c044829252729ce9f74756aa066201131d371312d500ff51f1e25f5faa144390c1183dac1c3f79acbdaf18902fd6" },
                { "be", "dd0472264a2bdd113f6310f20b9c2a5955bc76ada150d452424dd054035399a7b7a8c20d17e67dba3d4add2c1df80f91dbab1d8ce9aa790cd9d87321030008a2" },
                { "bg", "5f74fda841149bdab98808c320d81901201c8428354be500cec65d384bee6ff4ba84548dffdb61d55002d7e0362a412c34ba8fce95b8f678a69b8fd3ccdfc883" },
                { "br", "daebb3b6c29b6a664b28da83b262bd2121d99352a8adbbd6f5496ce03598943b02e38fdc5abdcbd6a20fe2287e563d9c142cc2899b18d3afa97282506e4d4548" },
                { "ca", "472c0e4a573fc9c16fbe3ab38a3b0fa1933f38049d56fb7aab7e6257f132424bb3099ac88d26e7c82a5369b85fceab37d910be17bb4dda71227252e5a037de9b" },
                { "cak", "ea09336be950316e782a744e5c3418b95417b6c8409134efac168fd112b2b860cc189201fa549004c093c4b8ba5fb6a401b225fcf15b6f22ddd434157dcc77bb" },
                { "cs", "c5c376a6c65fe2a24b2308d0505b11edae34428d6182af82ef33f78926d305a4d885b74d89656dea7a4663e48f06f0937e00b3b21f84d52f4acf3baa9ef9641c" },
                { "cy", "481abed208947ed853c68fc23fb3fbe940f5526064dcc0c5bee73c9f7dd5c989d51561e4f148d5106d88a294b8809106969353091b8a01b00bdfcccfed72c315" },
                { "da", "404032b53958a05c386f73edae863dca67e94ec2f7e4ee3ba74f3c83ad065d55444bea310c2976555b3b8c0512e6b88ce33ea1d7f7f187b0cc0c791d5ef430e1" },
                { "de", "711006b69704d99f0464328b602684eee16d79a72193803d57fb198059b05f0ed923ece19aba3fd29a502eca02a1969facc3581fe6f27acb6680b0ef07ac1303" },
                { "dsb", "7c95ddd6c2e36d369cc6431ddd859d07e06c46fc6ead26acd311966f5af8253e2b1c48dc7d65a28068e95b22d89cd1c88cbdfaffc9de8e49cde9b2553a2bb79e" },
                { "el", "49086553123eb11202f3c937ddf2361344d3b5fc3a6c4a1d681d10d7ef42302b667fd8b7d8589f7c95689f0267c5a1c7c3ac6f8491de9fc6cf56041bea04474f" },
                { "en-CA", "5627ed9ad8aed8a431d818b59db674fc39b6b19cde90cdeda15bc76b1b772888815523cd41ed18f5b0df06c3a2dc45760ba043d98b918f2f29863fa5baed859d" },
                { "en-GB", "91c8c4b02ca4cea6ec0dbbd60451bb794a1b231bbc5bb00c1f920a0dee9e05b46d995f0dd084ab53661360621cb0152d3d2ca015decdfd84308d44533d6bc04c" },
                { "en-US", "5870a843864ca4b8eaff51cb0d4c498b652fef3f865c1663fe6f7d067b5689d4c7e8bb91b88b23c504623188d357af1af242894246cbfca58bf6a6d95c0bdf93" },
                { "es-AR", "803ce276fdc7e765196a19a3f68d2c673b7bfaf9ed737ba383adc0279da332ffe14ece374a7b31fe0dfff3c8368441b284d87772025d145af6e13fe03fdf8256" },
                { "es-ES", "cf345d1c2778ea85107a6e8cb6c204284e05ba455adc4fbf7cfeb8138e9737dfe17ab7f4c0e88ee44d1167b6c911109162f8efdb5bb1ac292efcda9a1a9eb046" },
                { "es-MX", "e70c84514e9b9228411232588fda1d7382f44075649f4f36befc8169f13ae5ed30fcfca1f087e837e87a5da53216a4963a658b135279479e42f5ddc0e7b4157f" },
                { "et", "b459e25f49462c39a96d1374db32484e7fc7480a2062ca8a3adf9632385c850ae1c2e7f7a947fdabd1b5b4a2b6f50bf618cd6877c9e0c9610daa7d3fbface99a" },
                { "eu", "f71be8b14bb21a8ec84d9cff3f58c536e1b0bc7b88d2e673f81debd72f63e39b1dc938a6a1f725a1770a59b9dee7bef49b910c976907fa89fd5ce915409edaa4" },
                { "fi", "dd42903a0b6fd88d2d0003f74e5d62087baded42d6db5b6641ec9d38864107f5e68dce976349d5bd6d515cc6994837c345f763996174fa48c79e1236ccc64bc0" },
                { "fr", "593a32f4625d2784d9bc0d911b06579a58885bde537763b80a160cbb9504c84f19166bf19627c8aa7bb68897d0f2c6542df91d303cd598f09945a119aad398a2" },
                { "fy-NL", "7e061019ab0fdcd2f7adb87ec7506fa92ea24624e34deaa17e3b3533e4bf8cec79781bc15fba0695b441ddf095fe0e51346a053cf6a6daa229cb518bf4e5995a" },
                { "ga-IE", "36dd58bb035e70fcdc810f29c0cc81b7d37de139638a544af63b9f529f09da63256c8660a3be14748e90aa4de63b41d53eacf585d5cecbdf534c977f933cbe08" },
                { "gd", "ea8e7e48e3e376bdcb51415be5aebaf2cbc4758a96eb6cee47ff59edfd6015c4f4ac0f9fb9bb431792c6c4f73a65318f59693b1a4a23a0a9cd33c50d7718b957" },
                { "gl", "5db57366b2bbefcd414dc2ab566d897dc58b0646115d09e25511678d9930269686c93d8e3fe0f4b597fcf943b5feb5557fb201e43e3eafec7a345e5c2e49fbbf" },
                { "he", "4f070ecc80eb188a35f5516ed6081f3c459c89fb4880914c049f28db21b2094fa3d9c601da1d91587c74713b619b6b9404e96beff0d48e6edd087faacce8b44b" },
                { "hr", "2104a318fb485e0157ff0f05f377a1e054fc281c41983a6094de1a54040f541e59dffc103919bd144be15cdaaf33ce5f5a812811682b6468dc5dd6df31bd5d44" },
                { "hsb", "d3adf536482b71295f47d1b5c67cfbb04c185fe734499aaba4ecaededa332b04ebbf416c8804f43fb2e41244f93d9d0c6ebf274c2cbddbf32c0023bf50c85402" },
                { "hu", "2e403aa2a96b6a5f002d1556c187c2da355137c93b97cff82d7834c08780c2e00a3a6e0108f5049db010d4e9ae93e1c1f5e1db93a6808b360912f7f1167eb606" },
                { "hy-AM", "93d94deb5a69b2b8d5ded161731598d707265ed73dc94cb0c148b8322dd7b3d40e48a01e8afc8ee14c71b864e2a6fcf69b5eceeb849777df138ded65a5b3d48d" },
                { "id", "d197258cd9638b9cf78f13db1812d373b2484532f1e4b7ef497cb2830ce34e35e49a04da7b653dd67037cfdb1e64c7e6f01c365b31636217de8626d698c9bf35" },
                { "is", "f956f547fa1aa3b5e990f75e24a03e46e9175acf561ac218715df5c1500a64a06ef957e6f67674b1b81fde5e6ce9bf26dbd9b884e4ad7b3b020a82ced4f985aa" },
                { "it", "ffb882700aa0b3937fdd7efc589d3177b70a94464fd0a4f5b312ee0dcc76abbec29938592a2a21e52b6205c074f5b72a5676b91c1967438d1f7ca717c7efffb5" },
                { "ja", "f604335ee4fa2d142b449000ceabee5da1b7ed7a2d21a48231f91f92f4814bdf6dfe20bed57e9abb0b2f353a3b479d86d8a24dbd06829870a046272b017a5474" },
                { "ka", "f8a93b672b871b134cff3cd7f73d77d3c5898d78fc5904bd3e3815ecdad20c7a85c87b41ca2a1b9066fe93201eac71ba86982d689b9456a3fdc3bca56d7904f3" },
                { "kab", "cb685fdf85bc2c08a01cfdcdad1f9625211fd74d6b667a9793bb80f6e857bb2753ecc2906ec928637038c7defe685c5c4441177372feffe5040b84c942bc4aba" },
                { "kk", "128a5ae7c33602c2f3988bbaa567695d127247f37393a2651a875dfb02a4e96a2b4d749105a87b56180fd58e04c476999d6545379affce23ddf662f2f4619736" },
                { "ko", "9c7678dbf18563a1db89f782ef2ea00e9c0b419e4006caf49af7f0b2b8944fd2da22f39bdd0ab65cfcb3fa0dcbc34ddbe09a364fc9dc03982ccd9e9cf4e67904" },
                { "lt", "c1d72955d172a6ade6d3021480a11b2375cbaab5a37ecb77bb7382e6b46d439106ec421eb97e735a8870ce65de59298112339c714be1ff8997bd490eda5a137d" },
                { "lv", "729c6c9346e0eecd27423f953eb906fbba6417cf8db456566e8213e171faa170b774b31cafcf6be6525c8074bf808f144b37974b617eec33a73a50a5a494a78c" },
                { "ms", "f80ad81ea696b62589be01248447b196dd9f9dd8f0dc27679c7a34e03f8ef6c11314ea5fd78632f14771c7d89e9ee2bf803e7449c49b4134f99c1261bd48d7ac" },
                { "nb-NO", "74028623d5f548672771acad93a283daab560e93b115dd785fb2be6a52976039f51591c2bf2c7747f382e33edb0334f7df247cb50b1f169b2ad0ddcc373dbbd6" },
                { "nl", "033457f10d6141d17151f5f793d803b6e10bc4d7a3b532d154c9fdba4aaee884f31864cfeecb5a5eb29e1576ccab06a71a56527536a5380286dbfccc96d1d052" },
                { "nn-NO", "927227be81eeb0ecad60aeb458434763d4cfe7ec4b312f7ef16893f256db11b7e0972f9e53bbc04db8c2e74175ed517ebffb2b3a1fb57a1fdcc3c072a5f1bf8e" },
                { "pa-IN", "78d2f5b5d28a32f34e7bf89becffd3618b8c96a5f47b5cfea28be468e0cab2d3406b6fc2aa3a9c286dcb6c56c4aebbcb59980675aab1eeb00c969cc6564062b4" },
                { "pl", "44d791392ae179d1192f56d1329ce48dc2a9ab6b3cd6400d1c7fbac3a9a34cadd100f9a9f7471c69c61f25295b6028563b8dbf3829cd7b5b95ef69b502bc8052" },
                { "pt-BR", "0621f8d3b8a2670a04c75507cd0f42873f89b304ad227480db0543232753afbf56e7fdb435d856fc5e84ba7691f62c17414c378eb32709375587293f0b65e827" },
                { "pt-PT", "293bee4b4c223198285605a521e35eca3900bbb1f93dbfa619a14b77ea19e6a4cf4fd49b728b1eab59dd4052ca16ce6f09f33afee36102117875cf766f1913b8" },
                { "rm", "fd7db45271982894a2136da28824d6a093232bf43557056d52a0278ba72bab950c8c34b24a214ae93aff5864453e717c22212ad33ca21f53532c61a5a60b5e12" },
                { "ro", "38a7069422ef9ae197d4b7c156eba311ff0a52e4f5295bfd1543f5d2f2259c0400d866e91af50bf712508711cc3df4b25f97734e27db104792fd12f0fbdff305" },
                { "ru", "eb16127753b997b2c525063ce24440b7b0a488132d65a4336b63e515045a15bded0056a98b734bc21e36b38fa2371a7201f70cf5e8d232625bcb253cb140c8da" },
                { "sk", "110ff97f8c700e1e0fa3a4a51ed0035049ea9b1b3b9d04982bf6d502a6883dccba7f8b7e4041847092b1d5ec7e599d4d79081c553377857c4d4be97aa5d899e8" },
                { "sl", "7d458ff6d4de2b22ecc097fff658262b08b7d8a76efb050e9941f877471074db465090e0d4f30c3fbf3bfb778d5e4f7b4e7974a7c6d66d1e9aa8032ff4e2e8e5" },
                { "sq", "19f361492ff08f4364372ce11392146587bdb0a9f7c1fa02da4fed5675dcc9ce2bf198e622decc34153f4c2d9342d2833aef08144b1733a7d9bbd85b3f137fc4" },
                { "sr", "6b7d656c82054b7e7568c4a59d0e1e6755eaaa6dab0663f65eb83b1e009b8c27ddfce28061b847caccbb404b2453047ad5eb7cc569f2522d664ab9e12c7fe0b3" },
                { "sv-SE", "afa18d3819140bcd1fc3fb920fd681324b2dd336be629168f23c494216d4ff2224e93057f252091219e0c6638018e837abf9a64f472c87bb25e936f2227bf96a" },
                { "th", "72772e6b69a92c082305fdad1d82d266b564ea1ed8aaaff293a77250db411ee1ee842b2c7d8c29cf17b642494ff0f243c381ff948f8df4f9307ed33e36363ded" },
                { "tr", "33382ee39954bef1a23c956aea0b5fccadcde1db6ad197906f0a71798fba0d893c2e8e8e24b58448bbd612dd1d6225f009c0b0cb851d2d16a0fd47f635039909" },
                { "uk", "bed0a76658f156241c8c9edce2113f0ce83b2c56fc2d0b6b1abe81bf3406b00e25a641e80abacfb0e7957af67afaa0bcdcaf343316ad19535db7a5fda0da81bb" },
                { "uz", "e04a8bdd12efc159d7b4094e1368b49ed237b61ae1ec77c7ebe213d2ba9cbd51ad2bd95baf1d6bcac2149ba120f2dc8c09673ee98a818956d0d219e573eff691" },
                { "vi", "f0633890da77a98ea6c0cf74720e6370e2f2904eb1836ee69ad83f52206d4a0d7d2fb8df0aaa8036412a80836449b43c7cecc668bb1a20a9c73ca00c4793e92c" },
                { "zh-CN", "ac000fbec88deb9a95dfc64aa15e8e647a783244eae9b7ec43ed3e277ca1ced21a175d1a795141b83aa647116a374367957e83e58c774a1c16e04383676ae060" },
                { "zh-TW", "db7990a39dc2a16c50c32d126f14a3f3ae20be0b0c28a07841d9cdf64217e331dec582ecf886c7d3c381a2d4f9f2089349d2a2c4fd26ce18f5854cdb2ed983ea" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.6.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "bcf530fc379263f26e9c6c4458a1da426e0db2595fee37d5f78c6f2261609b7606ea94efebfa619703ca3252b2e68d4d24e4579f86eb84a16645012d4e6bf3bd" },
                { "ar", "af5ea4dfc1b7cf230ba796fcb90d095089544a0205cc5dc2f3f7a518e17e0d893c65e26897422cd219774866d8ab7364aff93ac464f66e6458d2f0e14939634c" },
                { "ast", "1620ab0f59aae6df3311cdbc2fdea53c757b379a4cf3f1b2e7aa6885f0e57516c91e6aad0b639f45d8b2777cbfbe89a44c6529b374b4ee2eec3096c68b0f677f" },
                { "be", "9f4ec894fb9a30533c3def6b82dbc6759a83d6b98936863087cff1ec24cc09a610ba248e482937b01b0f1a0bb9ad878473e7d9cebd1a90d0dfc039ac79302763" },
                { "bg", "5032f65ed8d73782ae1f7df3f56c9ef38b3b965537ce90a594e4925d58d4b8829f63ba134dee290556386c5bf88563e59460e6b18935432104451c75da2ec05f" },
                { "br", "61614232972ff3b17ec0d51d60263758cb85cb6f5c4ed37978bc9c18ebbcaa69e3a43fa9959ceccd0301ab4962306a6c8c922fd1d4448252d0e3b91ee9309fb1" },
                { "ca", "22908a994cc84b346900b5d5c69ac60620166f6295814018afb0b63ab945e10b48668b0c3385143135da710d5e60076881fc077a616d95370fc2effb1c5edb8a" },
                { "cak", "39b3a536639a176c5467449e92d1af827b192ecf1b2ac4d7479c6067900c479e2ecc38ec183c354ab8de29d88fae569b07ca6ae7232678497a02eff18aae939f" },
                { "cs", "164c2522ac2a62bd3383fc11516987a62e25a071e90b482e1159a1d52d18df1c7e193939ca9446360d070c5d256008ddd1b93fcb914fe95502770c10b4281ddd" },
                { "cy", "af490356eb4f420c5cd7213ac6fac74d71a576bf590163680e33c865b8b4959cabb5347a613adf1dd7cad4c31995456031ad7c55c58f61865edc7eaf9eb1e8c0" },
                { "da", "1a27efbf187c5ec2fb98fde487d1b1a77d8bc0cef6e55a4b6ac549af395c831973353a4e4bbfeb3f34a2f16abb10d009ce36deb62d072f0b4201f5fb359d25c9" },
                { "de", "c081c65a24ce8b6ff6e6cc5cee4c14655dbb952c53d9d87b3d716393087855556cc5ae986bca344ba1acd0461b7e88911c878b246673bf97a627d450bd5d5676" },
                { "dsb", "efebe974574903c3e9d0b43cd8de119b2ef871ffb0fe197be0caf712aad322a92e1180d8ff824bf4267b088c16f0222c2a97e76199ec9c9e15e5299a988f9dae" },
                { "el", "38773abb8788e8ba99c4490280d40de252d1c2930314c6ae5bc8efc0a7a6eb1d4c0882618b16f16bc73c0319a91bc3a88188d71e00c37ba67104f6074c079518" },
                { "en-CA", "a0123e062c03a56d15516929b9bdad4e2a0cfd50e6a414145d57d64c59fd06fc315160dc55626b08292565cfbf3e58df9fda011f09ab0404793b036d371ac763" },
                { "en-GB", "8ca050418400cca772c5a55e35ed4177c1be4551d153e06a6ce6826a3fe3f636508c27d481d26108647321198b7fb0e0825b4adfcfd1273bf8fd765dc202fcf3" },
                { "en-US", "36113a9b2ece7feb12fc36099633e6da9eeb58a61dc9ea8da713d489f749ebb6f5f3a39c621d6309676f4732c0eb7211022b0934a1149d5e79376a23aae8b9a4" },
                { "es-AR", "8fd391623c48b0156a601f7c6811681e7efb1a3a0534571c09370456fb80b2e92019379763dc921bfee5f05ed3150f934b1b3c29986d988da9cbfc7158b905ba" },
                { "es-ES", "cc4198e2e86ee4c40e6920900c337db4c6d5fc92cf7ccd0f109e7ef0ae662d81046252f51b5e552272fa91dad79e595bd3073223440863b5ea2ed68a5fff802a" },
                { "es-MX", "34ad5111a500bd16f8d2ca35590cd68065d9547e14984732f32029a81b507398467f711dc5acd1ea53777673195c413ba55449d85687e5c2e028ee6c7eb2f5d1" },
                { "et", "4a59db95dec3bf20181a0e8f5fd193614b44efbc2c74e64a68d08607e786c230b1e5f8c811050bd66e79d23508eb040535210fe4dcddf7e2989687bd3f4a23ad" },
                { "eu", "7322a3587bfde65886afb390ab224eabbccf86f13f169bcf35983b54318eb8c2ec2c81f35c71fc6c13f80ca23369dea4d0195700c624ecd061102cca65504f7c" },
                { "fi", "614f845a9cf3931a10de27fdaad4ed14c5eca9fcdc8043f913607493c3a788bd255dc590327589e821ae924839423c973ea67cf92c175e2499cd27ed35314c74" },
                { "fr", "7466f27caba0778e02c1e960b50a1c6dc6f5db4c5c5350baf8659052cff285a8c79d823613099abf0fa00cde04fce64711dba872e256d3ccba3f8c72c1bd247b" },
                { "fy-NL", "b5ac939e30d8d79d30f44ce4ddcc78367a68138aa9bff3c54fe5be91b99fcb0b38b9971d57e0d7ae37d072e535f160be4b96303429e7ea639d5ecb203f3cc8ca" },
                { "ga-IE", "3c39eccb941309cd47cca656f77aacd591f33bebe17eb5db05dfc608c7f1950cfc1457ffca4312f0fcbd90102ba7bfd5127e5f062cea0ee621f2d5d636f2646b" },
                { "gd", "dc630ead99dd70e7882ffd9e6739d084ceff1e966b3d2588ddf3113eeb49db8bf726fd8ab132aa217d17b897dcef0e470682c4f1adb21c8dbf9fc54d60ea3779" },
                { "gl", "28d50d13c219d0ab94de1b11a6fe51db33fd267da5038e3cf392aa48fe3eda7ec39c999962a1386bdf8478ed81f72b45c2c80603f9c93358fe97c0c2acbad4d5" },
                { "he", "5f11fb2bc64c83eaedd906c636adb41ebcaef6ef6d2e921343c00090685c084f2f6bf026176584575880ef5dbbc0f72ecefadcecba025c5d7ab86c1e3fd4547d" },
                { "hr", "d8991ae2ff6439a7620dbfdc75851e00235b20b659e61e21a70d4ea69df87835f247cffc707d5f4ca529339d8443434f6f2e8e993fa732980767b784b0d7b39d" },
                { "hsb", "2464329abc560a7934504053ef76c785ff136f09681abda572a5e94410dbf3bf7ecddc8b6718426fa6c9c8aa00ad488b4427d434ca4acf856b6f657c8f57c85f" },
                { "hu", "b7c29d5527b9f02598a48919c1a1fdd9c6843fcda2e3220fb2c624f26eacd6a7096e3a5bd0bc82dfe062823c4ff036308eb8e5d6be0fcf3604a7c72b668dcd6a" },
                { "hy-AM", "f3cfddcf6df2ac9d6c6661af3a542f26fd4929a945f93abd43941d3dbe8fc27013121e2ace397d9d0455a9f59007d905ecf2078b416be45555de862792e0a988" },
                { "id", "2d9fc3e0ee70fb6451202a346270db6067ec07fe797a2f146abf3b18232f6b6aa928b88a01b8d5bb0e83ad3c95a0e6a0143dc8341b181242f5035987f462e171" },
                { "is", "79d8bcc13538059593af1a8bffe7f479888c8abbeba9f6b919abd166a826d1afa85ddba5c93916553ea51c11e2538cd2221ecddc3498adff0e608440a9024e80" },
                { "it", "9e6c388a165821c3bb0a1eb29536362c0deebe873e1f874b08e2a9b198acc371efdc6e284cb0427ded70343d97866b2aee4e1764b44f9f0eaf3f594b99a1534e" },
                { "ja", "8a2543cdfd33634f224da1f40c7ad2c6cc96811ea0e1dfa631a299580f55ec589298385a5995f79032845cc84169f7c32fc7ba2e6b798d8fc3f0b7bc34c042de" },
                { "ka", "afc1f2a175d30c83474dbf7af5153a44d0c91e6b85c7014b9baea6b9874ca0da4d1fae104c7da5f8ae4e6dec56eed49c15afdd129d95fbd8f4fa1010aa1e9328" },
                { "kab", "9f7dad46a5d406de78356e43d573fafaf01516b0bc2782013e29e6bcdeccca92c7868dd878f439121fc98e410742aa541ff8786ddb2225ce1b69a99face6b156" },
                { "kk", "f11470dcfc0836a4347d5de4b1ed8af5775d3bc7e83c9b2b11aa45c7e960fe6aadb3ceed5dae831de0a544dd8934cd436c359f097be06c94509b41b72d2adf18" },
                { "ko", "16540859ab281b66e422d626aeea04414be68d7a434abb89195c55b832d50080f92cea50a43086e7aafaca8ec85e815938398fc10a766bb575c3769d54ae4019" },
                { "lt", "ecd3a429c3a817e14a9b4a16ee21d9787caecff986bc0a02778a6d999cf6c8dc1bf6505a0938171cae88d06fbb5c8ef2616c941ceb20827fd09934b9294c57c3" },
                { "lv", "b94ba7b0b0460c07b1789819b3dbc4f91476ccd2bb4d4323027f4ac90e59a910e2a97cbf41119219ccf9df0e1cc6f78d341a9ae3d29b7884a11120b7d03bde43" },
                { "ms", "5bf5486e9affb540300ab1115189c7a6b561e01c128bc4a4069394eccd91e5488c8eabc68959d2757b04d0a4e4c0699d830921558801e97409d45ed2d2b6a532" },
                { "nb-NO", "d45b4ee27288fb846a9bedd00598e7021088a781f031860332cf3091426ca4d807e3f7d019010b72d6893cae0b747482d95a2789ef60474a53026595bff1402e" },
                { "nl", "73d9b78ebe115803ca4307992608610e8cba20ae7b6d62bd3e7f9aae9ab85c1e1f93f6baf628be78bd543914fc30eb8697eb73176b176fc8e2c80cc9e85229bd" },
                { "nn-NO", "ec2ad327e743abb47efe63c95899323704a508b8de19d773819adcdc6a117e6ad3d27c817ebec45e2ef3e4cab5676d45eccc153bd46c313a30319fbca25d3526" },
                { "pa-IN", "92bcc8ddd6578cb0d71e96558dc7d18fc7dcf747d9c1eacdd68cd6501cc1d797d805a669a720e1ebec65042b1bc621c65ac179e6fa024cdb8fb6d9c33c3bf148" },
                { "pl", "f7e1c4d42aea8ca7c84f23397771c5b782a1c169ddea2fa9154a340db04aa45bc83ca2702dcf1818fac40ac64ad7da1e4a72572ae2a066e3b7da8a83825d913a" },
                { "pt-BR", "bf5b42208eb473a65b8fa35205f7b09114e42f081273999508747357ad7f133dc7cb5a2e87fa0e1bb9c2c90f8d22fdb11eba2d7ce3320c7e8e8dbb191489c843" },
                { "pt-PT", "5cd34722e6787388cad3f017c0c7363941978bb65504a32a98826f7ac8d36d49fff276d23e94ded56d73f1395b1ab0e38d6514ccb8ddd89cba4ef020e3a36fb1" },
                { "rm", "9a4be62611cd4a923256dfe9c22e36bb39be8f8f68ffc1937e059ff56be8e11bc55735e0ef4bf6d364817f80024431e40ab41ab819fecc961077d4c8114a252b" },
                { "ro", "cb5bb664f411dfc960d657b999bffbe77eb1c61011653d3104fe4441c5f78aabaa3e5945a56d67d0c5ed3385e0b4d2d880e4d431f697c6e8e2adf73c0cc83692" },
                { "ru", "031db2fa26eb0ca168e58185ba0e359ef22159f7c759c533d307c96148b29a9e2f5a97a7e53d06404b32f427ac31aaa241ecbd178fa2cbfc81bd65548ef99001" },
                { "sk", "eaf8f164cb45193fa12be549ed8a2f17e8e663c45917582c90df033bc41641add8d33a0b4037399e9b54f6249fe8daf472ab96991321a3e762fde17a0e178852" },
                { "sl", "5e1eeb4ed54167f5a92c2a5c1f7ccfe5d32a1e36d429ee88e1d0f8cdedcab06a44c0a36f2b56b4e130de22df40bddc9d8760ec51839d761163fc0f57f59d4672" },
                { "sq", "7d57f58abf8d091d53c22e71bfa88ac4945ab97c81aa660cc797442cff09280510c173ce42c4bcdd7aab0cf9c5979e9bca5f0341504405b97d27ced35986128e" },
                { "sr", "55f50ab5ea44f2bdab4cd8905eec7f29a5e7e60e0ad2fcd2cb1f467d20e5123f3472380d8e65284a4f796a5d144c2b3bf3bdf4e950ce6a59b1012d41925a80e4" },
                { "sv-SE", "70d0f122b5e40b513183dc7d0da97685bf1a464251c319526ad2c5ef773067dd44246a5deef821bba42114ec597e99eaca78923b7dd9a2f963fe8e3eb95b7e5f" },
                { "th", "52d7a423df144729d0939b2a0509b2c547236ec91c1fd1e81a52e34ddec9cbb5375d2376fc7ea530c43bb53ade9b208ee8c5f9825255ece1609df82f6fc1db92" },
                { "tr", "e307d3c277d356b95d11ebea882e07bbbe3f409d5c48a514c190937804811c8d27f24cf3f5d0fbccf5f57b53709ba06176d18c093bedd0d813e32d13020c52d1" },
                { "uk", "9c84a134c50e818c6a845cc3d682363c3a63e67669d080688104ddb678a839cedd58fbe80f0ee8a7a8e11a1c1862aff60675770de9c954c09ef86c6dded94db7" },
                { "uz", "bcea97c668f8bfa9eae194934e33c38bac0ebeaf677f05811cdaf2107cbd8efb3c4cbc071c6d0d3ea5cb188173699941aea387a150e624966d8d56959ba2b4fb" },
                { "vi", "e379bd084eb97353226e41840b3c46934f2963d59542dc85cd9da072493b62fb1726f930c84d54789964c4c71779ef6582491abbe535e57cbbe57ebb09be8214" },
                { "zh-CN", "543e9e8bceaa10d89c406921d18edbc28b41a43c0c3c35c86cd04823f217963a5d4b032f82066d625cd3427ea683943244c250646925a1804fe210a57341ebb7" },
                { "zh-TW", "8ebb80a329df1cd2591ca8e45fb6f91c17054ebc89d5d855aa2e0d0d17db57677de95a0c08dd0513a683edff4b2c63db9d118e8ace54850e1b25889d24a7bf98" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
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
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                string newLocation = (response.Headers.Location?.ToString()) ?? "";
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

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
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
