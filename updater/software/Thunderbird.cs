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
        private const string knownVersion = "128.10.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "66de58d70e003c38eb0b165e37658804c0f1190a8a2b9209a337a4669613144f6a85531869f55c7ce6cddca33434d65632c0a13ad5b11c8dbfa5e1070ec28f10" },
                { "ar", "7ef849a5c090b33a31425c9fc223512389ff2d02f073c1311356ad174e0ec641428055fec35dd82a42c94b0a907b9899402a813e9257b2fd62315d3908a72874" },
                { "ast", "cc9c70fbbceae9411c2d23f8295f5c916bfeab0720acf434d7ef876f84629106a0ccbd245d0e76d41e049b8283cc3ed7c0a49608d11abc6b74e22ef943703ce4" },
                { "be", "c2a91c11801d8cfc8f011cc55e6076e5dcc69ef9eee71a5e0cb30b89795ece789f1cbcbbbe5f9b8acfc14935072a4770e5de1be021b795820fe1ba2afd34e252" },
                { "bg", "7370dbb15bec64065e830a2e75997a4363d4ffb2e1c9ffc8952f4b3cefc6a7ff739be1ccad2e18afb6861bfa57af0828019c1e408c9fa3cdbd7450f4d57a495d" },
                { "br", "e03d1548b3b7bcdbaa13857d3a30b1e64b6f0ecd21b6139c6fc50f49cacbf2d58fe1924a8b718fab4fb4305cd50065c6c5392e4482d146e7857392621fb55445" },
                { "ca", "0719b2ed646985b45ad6b7960fb7c0f4ebb727c6afa104053283045ae071ab9f5c0f59630fe9e4d43fb53d68bffc1f56ed06f2d400aba27a5fa39bd1ef49c145" },
                { "cak", "327f39d9da705ad2a7f348426dde6ca49cc050997149a7a409a0e78a75ac1eb333562615241f237f9273f554cfebf798c22985477789b8788a3c12d440b9b8b4" },
                { "cs", "273d5635a626fb680aac6f842efff043a7f8c5d0e7b8e6411c1f0032f96e17ce85f159060897c10bfb7343065c8674fb78961bb68aaa63ae68a7b34142a9ae1d" },
                { "cy", "1177bc0c2a039fe98213e1840a793b3e6dce114b41f813bed1286343dd4599d2d8f2824ef0d6547ab768b402e469c3b9bfa148a28fc07065ce942731750f3676" },
                { "da", "c677428ff3796956fd00cc381ffcc5f8cec07cdd8c241aff484e8cda7126968a7a854911bcf15b9e9f762d7723e5340a4ec1b2b37c00aa59d1776c516c5bd814" },
                { "de", "b060f18a6a112e5ae6ee66442e8ca7d649c1f073738e9f140f0463e7448acd425dd7efd03ea5510415e56755f2ef57b47ca0022a348bb6a11673ee0867b0388d" },
                { "dsb", "bcb5e22636dae15d0fc2749a57c5944f256c1155f00b459e28a79513937e277a8c23a15f2c5d299a15fbcc24a02ff64d1ad8fd2f7ac353674501ae06cec3c082" },
                { "el", "91ddeb4ad0abae85e56e2e531c5e7fd69ed1f6d73ad5fa6971fd75729192cc89108ca727db1f9e6d849d95df8827578e784f32ac600f23a23b3d4de9e04d7a5d" },
                { "en-CA", "bc04ea835c8c7eaa849c21e96e6db801b33e9b46c1cdeef17d48ce0c5e63e1695eef00ae64ac167cbf71a3538a327124420fbd9fe81179b899bef0d577a8484d" },
                { "en-GB", "ba236cf1c2b6fcb9f15023bf6c6f34d218f21477412ccac33ea5346045727a581b42897e786c234dacffa04cf24990cf2a53b2c2a3f358e0266ac07303ba29b2" },
                { "en-US", "a420f26ab24d6ec9cf14284582738ab709487e625100fe76648dc5857c5263c35f015e2657da1e58929cc9ac2850289c53bef188bf11e84f1e5ea98d9176b181" },
                { "es-AR", "3a4afebcd5c6e8710c71daf2ea81eb9fdd09ae0070af24ba2afacd91e7ae22b4afce9dd5ac438b1242dc1485abbced095499d5004909405e0410be0408ebda47" },
                { "es-ES", "310b2d7f9b243f12cc429534b0b4f7fbd9d6148d6729df44b6d8bdda19c060ecd5801d42a1afd492f2114f816cc0bd6668a791996ac2e828d5a892e06a3bfd97" },
                { "es-MX", "8383c7e68669b899c9845f3f86a997b8aa0633791dadf49ab81aa26e71ea8143bc4e1986417b0c9a0c82273b7db17022914e5211ede9c41f7b1ec4a09cd0f4fb" },
                { "et", "5096cf8a6ccacdeb0031caddd6b20293230327ad2797461ca58fdf033579ad8815bb8168083a3eec347ce22a09459d8c59eb879bc9c2949e52d379c3cc008135" },
                { "eu", "0ee46f4e6ef5963c335d99489cba4e82b0842a3798034e9ca3e62e30543b06964976fdac871296135319bc85487ed05ce95da1ee3a0d6a82b25c3265b354291c" },
                { "fi", "fd5f2a969c4ffe347f707dbcd23045bd2de0970aff0bce5e4595ddafdf6c9d000c1069d2deedb8ab63dc914127f0a212b5e3488e60c4dd71bccd1bf6b2fe75f1" },
                { "fr", "405967d4395c97d249293c581a2127d8c6828447ab78348217cee9cff41ad56fd31ffd6026b9f07c1f4add0ab0871e6ad0fddc179168c94f28b9ce25d42fc018" },
                { "fy-NL", "c2a9ff84042c23fd0422a9d85adcdc0e1e0654ec0d18ebda2783a5ba6ed11dd943d70744b807e023313e52ecb67794c83c832cbad94851458a9aedd78ed76509" },
                { "ga-IE", "8b4b155c29b1ba9b9dbc4517bc500a474275a4e2f28e587ef67166d25a5599fc12ec22fdc25be50d6e091f9b3482e07cebabf7c1162cae607498f13499eeb4d9" },
                { "gd", "05f44bc19c22df3b97b4e51713b085a30cde679c5dfc39cde83d0f6309d11a45ee19213e8660d9182d6e86a74a1d17dd4e972f4d7360ad0d0178a77440728932" },
                { "gl", "6ddba05e17d5ae78dde2155256eaea5bed498d3009f3cbb3fa7efb74e473b540b926baf2783b9b3ff3a9fcaf9bb122c326becba2bd24f48d8d19d2d3696cf56f" },
                { "he", "12103e9f8d15d3627a460301ab2ae59031d6d4ad3458e0f48149213befa58b0fcfc1f2dd6262afb416b916e9b98c328f5ef379d420c3ad578017462471938781" },
                { "hr", "dacae92841de7d51cd7c590a7717c48bc207fca78db85ea1de42803fe3a360af7473a06e68681a0a911f828a4e3272f21f757aa47da33ed579b8dc6f24ce5cf2" },
                { "hsb", "28dde045bdba717617b36cd30270f1bfa1134538b988276e4e1f7868255575899d1587245581f338aa8ebaebbff132dd03398a8a3da0e8e28657788bdc32f6b9" },
                { "hu", "771af61b75564bf97951d9a1f4f2e29991a3f00cb508c51677f3bf28820bc81d4261c90237fadf42848784c8548bc2be32ff0c096d59d77cd624e15c54ec15ee" },
                { "hy-AM", "0b16f4e7378529669d62f169afee9b1190cb0d73c70ee5cdb18f8a6ed358c2a4156eefa1ac07f9c76cb0b79247db67d9d23475c8f0499468b935928995702daf" },
                { "id", "241d4f1c9e3e2547a1c3aea1116e9add3998ed5b169c2785c7d43aa00f674dee883010fb109d430e30862c7c1396d2bf4cb2d7280c61af0a17da837a4590d382" },
                { "is", "f6be4ee4d96c428f3ba14fc65f52bd161b0b6d79d309be52cfcd7387d8b7468502ab0684ba2050aee2e5987a51945e6420dfb7fe66e5f38dc908309765a6280f" },
                { "it", "9627077ae09ab0499367cb138a10a39c16c5f86f42ecba9c2021f7e4de9699c620d2f2edb4f7144648fb8259ac6c7f38ae4cf13660224ec4b3c9f34b24484dde" },
                { "ja", "d2d2840c34979c675cc68641a17531b9b618a51d1569233437cf8a6a4fb18b030e724ef0d8daaecf5d226fd40cb7cd7b6a2f1a5190d035b9d4f236b8fcda28ee" },
                { "ka", "0408a227179b2fead526360c684f4fab53376b4ef8bacd3284211904aa64c851d3661a4ec741e58de7abfaebd19e24cb4241ce8fe16559cd8421f02c46a14e2e" },
                { "kab", "24b4eed2eccede4a14dd0bf2fe9f496ceee6e8c04332f1292ab94793d9e541e135710e8f42890b99202a2ca59432df7d2ca06cd9969aa326dd5cccb51cb0464d" },
                { "kk", "aed13f1ff92c74a09ac7b0f0bf1f4713aa8e68e9b8408da38f30032e0e226917acaec18f34077d0269b459dd67c98db52a9a2da8ab7842fad465d5696dbd6936" },
                { "ko", "15723c520e2421c0aa71079cdd8258c2b170683477ee8b455dbce58e1d739a5e14bb0b9a1b85e4782f0188465b0006e4175a8c2896cd0a3f7bdaa7a78b50e9cd" },
                { "lt", "832698958019f5d5e904ee687f167c4aea496cf7fa7f5e0fa1440abf70cb0655efc4eb16fa93dddaeb754d1e48082878eaecd176579f6bc373b6592fecaa5d9a" },
                { "lv", "d4de3c1b7a5807bdbd3c9a9300e3c5a7876afb3929febf8f2f1d429ff1367c0130150747e89c876cfd3d52c6cf9ca70f90607b7ec842f84c2ff040a2a95733af" },
                { "ms", "6f70151ba34711d382bb76fcdb543fbd9763ae349148f72b1ad4cf3376125e2a12f7ed615ed96ed67b5c952c1582929f6014631abcceb94ca963602e30c327a4" },
                { "nb-NO", "c44bbb6b532d3a59249264d91d8e0a695f7c699ff71dadfb8a44117560166f1bb8235c0cdc1317ce0ad51003ddec4a21a285a284665477a13f62718d73283a21" },
                { "nl", "804a9efdf8ba3f2268e6ff96ce10a2a4e89f6a93ba2936cb475ec7d8df3eb6b6a21c24f7b8805c9901bc11449cf5a821a304edd60e4373b96dcb33a82fec5426" },
                { "nn-NO", "b5a6a4dd149250f8210df9475be7b948a918155269dcc7351d72e63984ecf569d14ecd63cdd7cd45541db571814e92009b9aacc2d438c201a77ada367859a437" },
                { "pa-IN", "dc6354706c0486807b02548b7928f8a0764f99dd140a89d1cadf209f7e5db07abba7dd03b357262e0ba1f9cdf09afff0da4405b96d8328dfcf8c0aa7c7290491" },
                { "pl", "ef2c4ca156ea4a7eaaf8dffa079ff19fba43161ea17dac79029de21aabb5b63d21466e500f37168a64b75411433311d0a83db0381bdbf7a68829bc949e6188f6" },
                { "pt-BR", "fc4831d06478c4a6b4fbb6fef12dcf2ca0196c2c922a87acdd96e87d7cc974d94aeb2a1eecde1a97cb0b39e82b94bcd652ee3a4ffbe88bcdd3846d0538691a6f" },
                { "pt-PT", "e48c0f2e80d398219ef56146733a8cbb69a3ffce59400bd69c79c2bb97ef3a80e521c3a7951b7a4eb46668130d56ac561691f6f6f7934f8cf647b5db31ec4071" },
                { "rm", "1624aa0ffe9e446d562aac20859e86c320531a620de2240082378ce0201e8af9e66f5289d219f1b1a497fc2cde6516230331f9e617c85360db3126af10e5c320" },
                { "ro", "c651795a7d367ec41aee93400df034e59d97686b85249edfae53d71c7f09fa6e4a41c35622ace59745e257d9cd616c51acd20cb2c5ebc68db4f5f92429850a7c" },
                { "ru", "f03d69e2ff3608bb07d13bf27476786b25d895be4b0687d27446e15e6f3236516687aaa95fefd23f93601d4313e62b24a5be88fae096229ade6873af5d6e45b1" },
                { "sk", "10dcb67ab81d0ed71b8e12107ca9f0cbbfcefd83433d999a61e3fc360026f432fe7c1712373fc07287cbe82f9a08957886d652d6b64cb9ffc9962ceded9e9b98" },
                { "sl", "4e31dc17ffc46f6c9f314c284b048cbb5c5205bca683c568f0f3d45a1e9da4192f73f5a08f434da1c31b756f9b3ad2652d9042a3ba1e6b617c83a8f98de0cb57" },
                { "sq", "8f9306d3c18ed9ad5ccb69e4d084c1f674982270f398850a6bc3d42fc92ea08d2e51876abdfc7ddfe610399ebaa12b81881f383f9fb3f1cd51911e4c0b79e6c2" },
                { "sr", "54e2c1622c4498cc683c13d8cba0c9c793aa0d0b7dc48e4ad123325b49bd7285fae251cbbfe1450b5c4787caf4121da5308da01fbf1d97504a9a6bd8f9e8d02f" },
                { "sv-SE", "ca34af2349366ecd61c462dde0eb79365a59212615dd7eb04d169973b480b11faa6839c696e614465e1c56ec072f9bd4bddb56daec5af262eeac2b8787626b46" },
                { "th", "1f46340371894633a1cb91ce19afd15530f2044e8a3025e73a9c8c4ac3bfd26feabcef42ac487742b16ba53c85fb5b72d3d23b9a196d16373a9e185260bf91f1" },
                { "tr", "c85266d0259502fe63f786dcdd5dd33dbe3d5317f85c065ad223b074c4c5c7a75bfaa368651e83f0ec1509479aac767fcf96f91a120930bcb97c939681d9336f" },
                { "uk", "7989fbcfcc43d45e1fc9a27e36a18b01f83acddd4a65d3ba06bbdefdbf4bbfb8eba7310b205856498347bf323f2c3491122196c24c24eafd0e91db6b4d39e63d" },
                { "uz", "ec7f16a2e247cb0ecc0ee0cbb2e479c029ef942c8d2e06d6412823d70582e4c5b5b8bf05174996e105e182c9c61b83ea4db5d7033ea302998840a1b4a0a9426c" },
                { "vi", "00fc503d7d051dc9d13b9b81eb6aa11a6572e38540cc4fb12b669f620687ac9fd5fdc7ebd6fae3827d107379d2b8833cd4f9a71ab3de065bac694dcbe3f4bf23" },
                { "zh-CN", "22f8d38841c69649833be353ccd51d58f67cc57eee61f442bf7e2dfa0d3d1426179d6465c8bf7ea200d4ae542a0b85f93d71e1791106cca330cd465c97fe3efc" },
                { "zh-TW", "9f059246ffd69a961bc199a85c25b37a4060686012f764f1c35b99f0ee34b4ebdeaea744c083f2072fb11e222984283b257f6480a3b56282fbe9ad0d5762a057" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.10.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "fd3d71f2ac9c8981ed5c07a6b80118c06067fbd8b8e24ba7559501c15397b01bd97e48442879f22abcf938453351724f1ef344937667bc33a9d2483ca86b9192" },
                { "ar", "ad4e7ef31fb47d4c2f4f15167c5ac9e864d9e5751e3fc64cc46c061a6310392d74740885a17782743e496494df410ba71a2654604fc58cc7551ca3e7080c5470" },
                { "ast", "6a0b66aec5233f4c59bd2b9a78430ae3725b6bb10795878ef9469af840ad27c4f32290adabfa2333315b7703df97848dcbe9654259bfcd1c79f3f2ec4e26eb85" },
                { "be", "444f5502cca4ca39431ed227faf8badc7a0a3677ebbc4e98b4fd6e2c0ddb73cbb6e401651194ec1dc042c57042439a996d999ceabd7bd6c8ccd442a84d560db6" },
                { "bg", "2d6d85cd96b7d2c7ffbb0a4c000d1d7bf5b10f3628d944b3f4691b8bf8fdf323edbbc0bf42cfbd3c665309702119471449d5ae5a3d98a5cb863d07d9b7dafdeb" },
                { "br", "f3be3e952e1c852489f9c1ccd175c2b477e9c978aa987b78965797e5e390645416537837576677813204c03d07012cf7182654d24618bca0549c44b754b32311" },
                { "ca", "7ecaf732583b5532b2fd446f2c91e062e2e650a73a23e40a62b914d8daef34acc070749c17750ae1f75dace6160219660aefabc53ac920805a7fcd69e7f6c779" },
                { "cak", "efea2a292300845418189a86e5aac14727d7b93a834d1420096d25624c2a670b35d5e5f175506a574548599428d39e6d09ea43b79270c882f32b703e6fef9ddd" },
                { "cs", "ab3e4ffae601fb9e9bd64057799e09c40603003196978da3c2f5340394ef185a44e2ae66e18a8d2a192c225ac460641ece72776abdbc938096c1ba9c683524a5" },
                { "cy", "b164ca0f53a805af6b530f2e32ed31a7f87b57749f0d9c75a58ed80131092c93db2359cdd56337967f724c7c7268d6323e2d02679de66e8ce38e8f4912031a1c" },
                { "da", "4569c23bd30b4c6c9ae1cfb2fbc1f14c2128247a49a09f820602d5a6a064d94b2dcef14123519424c470ec211e52618db149b04230616d7194b55fe73c03562d" },
                { "de", "1c69a885ea5628fd977dbccc027dba5438dd5fd93d53116563890984170547dab86957eb4ac08b281aa6011f5888300c82e8b6c61d966dc50873152c0576f0ce" },
                { "dsb", "d653b14f7e5e9047822a946775d0f041cbdec895bcabc06aa109a113bea71003d761efc6a3b9f1e393dfbb372e561ff857f3cbcb26f403e008ba380662f8ab94" },
                { "el", "d63052767e066931cb8c248566bd87716c61988e2ced0505714324af5bc75652100122e2f50f7600d6dd9e715e7677a33d6d04c7eae55660da0ef8dcc33ef36d" },
                { "en-CA", "a2244cc84126e217a963d343992b3a43db56e661b0fffb607d3222210bbfe791e9ebb5dba72993fee990b7427c0417d13eedc555145489d4f05bc167e6a01703" },
                { "en-GB", "0f59a39a3f5c4014b1f14551f36d0812381f91c6556235b7ecb8d49e237a941f00b94a5a94bbab90460960afc039ba688c6680c6b9f86ab3372853650ae93c46" },
                { "en-US", "75ffe169e548feead98a62cce109e9cd76c1d1614d05c9a34a3706d050e9dbccaba4ac8bc24bd8280d89ce12f222234f952df2618bafbdd9bd7b546e152e2448" },
                { "es-AR", "b8168d0c5cdb6b5f9e390b850cf3bab044bd6743f73723357b3247d7b1e806adfc89b6ff5d07b5ed8d701c552ffc63e6b5bed93bf6b6e150c25ff21d97289dbc" },
                { "es-ES", "b3ea8594579b602e83f8c70bec58269f8626c1c4b09289a984fcb2846d925f4103b7fa2acee409072b6361978191b2c9114c1f0fcfa0687195233aa52e7de9ad" },
                { "es-MX", "2ca2ea609c2df5ba2521d870ff36d8b04658243adfd15bcbf3edfc980fc28f2a083a4e1df1d0f71150032cf55125b8f9959f1efdd14fe0d45e4fecca82114d38" },
                { "et", "4789d06ace2573c2d256158640471a9bfff1f46450279d5a27c007b6e6c7ffd2f28c025807ea7626b8152fe0ba0c52359243a1a66090dc5117083262dca65b54" },
                { "eu", "1786d7b13139f4bcc96aa7a9f4dbe8bd54aa8beaaa33699bdaa3783c171be3778d4ec20c68b6f2c091225dcac687ca7e4a1333371fc5efcabb6f8c4f9b9a3632" },
                { "fi", "45f8857cadf39548c6e87a1d56ab32fceb303dd9bf793d8ac8ebec1646476b844eff9ef1d37edb73e8b04e380ae9f0e433e15ca381af570653d5c56159cd153c" },
                { "fr", "c513869ac6cb6a07d9f3fea2d51cf063e90f0d4f18b1950ea70cec4016dd4775b75359b42c900b44b3de793caf5b1f7ba7360702795a19554a125ce9194ddd5a" },
                { "fy-NL", "7826c3c18f79c04bd7ba26e8ab0cd87ea44bc214cac07c9efc4b1b2e01f68a8b8913fea183378709f0db7ce1e87a155eedca892f786776c68a4f2cd5157762ca" },
                { "ga-IE", "262daa65fc5460e2cdf26c543b78b3c43ed3ac056c77599488f1399024378eec12d9fdaad07ec3c60145da1b322b03fc0224ab635fd09997e10e183e2224dcf4" },
                { "gd", "1045151d5c74864ed1cba6ab91d53ccd7856ad38fc5a8378bdb98e5c7e467b94af4cd2e6c3970d35207839472978385e8660135f96b67ef41a67f704b33e57d7" },
                { "gl", "2a427b8e0bdb1f6140c48787e290b83d1a08e0dff479bd9c50911fc3e54f9e872fe5af6b58a802d8e273e946d65df0499a5c97a5a3cc5fb11a439ab617fa1cde" },
                { "he", "81798e76c0ffd9b0da06a10be44b79dd9a2acc34c1f5574ee51fa0750492ef848b739e7981c9652ea4d7cc29160db9ebf75006e153989b21e6fd9ab56e9060ff" },
                { "hr", "46d1fc18df6f76050d7529add17a59c21ebb8e7356d45dfbccace8b67f0d5ae7d2541e8120fa1c0bcd838a31f5cb98cb6d7297450be21c661e2a59dfad047bf4" },
                { "hsb", "c59d677719155ec4f555076c86d249163e0f0bb49167a4f4d099f69381a5331cf04c9ad0b44fb0fabbc078e81bbaa010ef8040bd904d215998dc2f3e2a906589" },
                { "hu", "84f07ff3d459def393cfc6e64d824b701da1c0c392cd6628c1f06534645ef000c285fb4ec6d2778e82fdf09f00df82a8264f31199ed9c23173e2bd879fce5c9a" },
                { "hy-AM", "eea207445780e706d3c5ba7565c16b3c79e1a93569011bf6666f6da57d395da5ecba6b0942205359948750c8b0aa5c137578e0d4a7f268afb02bac4ef5fc8649" },
                { "id", "fecb0938dc1bb8aa8eaa745c45380067e639f15323428468869a07ee3b1d1e0ed02ea78b7fa6b34848ebc4721aa60e670ee30d63e323f7fc418746f01af348b9" },
                { "is", "7eba4ab5f07a7a85c46fe2290b16144075312e26d299ddf777ceba33ad6759fdfe18720fa303e0019114222bd7133f51046b43a847c52fcbd1e4d0986f2ad42a" },
                { "it", "8321f73351c0624e8885fd2062e8073435b1033ad048880ea2b5481f89cd3b0eb4f33cf6e9c589ec1d5e165bfdfd2c66726455819295497529e2a15e2100a558" },
                { "ja", "877fe58b3aabcb529edef1713fd975a1f55d37a99f8ac9709513ff87be44fb27dee42a3abaf93f81413e04676d36a23c02fc428da127670d35c9c6317a0f5ddf" },
                { "ka", "47db32c73d421cb156ccbb912c7173185c1d3af2cc44f177097fd12e958966810ae0d6d8efdeedd4a18f0be2be7ca63c3f19d544a45d51009e0a27bcbb24d7a0" },
                { "kab", "3218413a1dbd521e567e7160389450bb70c392bcbde787d7f41e5ad1dd51ac6e394cb08d8492c53ce990d0e5c16362073cf711c7dffe386c18456d99db3a884f" },
                { "kk", "dac99b0013a69564d185dd506d1a7bdc103af30989508121e1ea6b3e1d3f3787fa2324166892d0ace6526663b259871c77daf1e05115cb58a1168618146d809e" },
                { "ko", "73404d4f83a2b798fea5aaa0c789e9985e4e452456154728ed55315280881528bdf2b04b5aab981d0378406805f9007e6cde300c080f143416a1ee7c636d3b47" },
                { "lt", "a9e8408e618bf68e37c158eb7cc9215b1c10f56c9cd58bbb4603e54bd3b0e007c61a2f1c28543ba52f3c0d52efa316baf8f902b3d0cfd4e756748464dd49f786" },
                { "lv", "47c9d286ee751ad4b3bb3508edd4b7eed015dc6e69847063d85ae0a984b853ef55ac6fb6f7c47ce1c8def54b790363582bbb16e7f5ca2c4938d5667b5c74ec06" },
                { "ms", "f8f402df833338082e7b54b02699c511c90cfb723d19963a3d5d734bd1c6678c1735722d2789157c08c36020de471fe84623257b9b37eb6c843854c598bc1e7e" },
                { "nb-NO", "2012cb077424253a947b197b2329e5d84e7c2506b7c8583d40c2378e5faf06f0c8852a1bbf4a768ff1e373d3116af4e43c9487419e5e6b36f432a3dbf3f6a688" },
                { "nl", "32125d4c5ea5a9c9b55ba3c1b1d68b562d32b96806a77ce07e0cefcfd067ab73457cecd9ff371752c2a9a1d502185c69aa8bbbdaf56a02b27b7adc911fc3cd61" },
                { "nn-NO", "4b323f53ff1b82ad16c5bae9146f7bd4ba1102b6dcdedad8ec4fb4ee2d3a2287868ac380a48de625ba9f9a49e41ee4583b8e1c0ca9e2aff479e7618c0bd60a65" },
                { "pa-IN", "77b2254422bfde09652320b91ced78abce2d335cca580999b0d9dd412b4281c7cd6bdb8c3a19710f127abd0dfb11e16ab081875bc909ef25fcabd5a683a22fed" },
                { "pl", "9369eee59f50d81aa94c26096be68434d39d4cd60f5a5075b78ec5515c1d3be3411a0bbd3c463812b75fdb65026200d097505b8b89c26bfbc19bc54b11957295" },
                { "pt-BR", "7b35167c79c48fabf897b9ccb8e7fae06c4c3b1bda2ccf616654e89f7ad4baeac56c6a9b1185778a606a5ec376cac2bfac414b543352e29d54d82b1522b34fec" },
                { "pt-PT", "d36a226c1479df898a881b0bb21a536dbb273aba9b69794f91809d5192ce064b9ca782cdcf4cc3803debf7e83f9624a558c34f76165d0eadb37e050fc2d00a6c" },
                { "rm", "de6458a6723ddf66deeaec74402e3b5fa7cd877fe226135ae46c5a1e8de7984e974e6aea3216506f5df7f4c4ac5ecfa080f559db69573250f5f8ba67ca056563" },
                { "ro", "9cf8722ce96b6fa658e9627efe58b2bef02ce537f65d07ad64afa883668424675929a7a742f78eedb280b8a1a9ccf26c21feb124a88e1deb4f1543679ba5f59c" },
                { "ru", "47f2453a674a41d76325f474203364b1844f61586f6bdc922b93cf18618e27e8e425bb820f85eb7b7d7aa108812d6cb1e965d895cd5693d5f03793eb4600ad06" },
                { "sk", "5f34d2071e427f7bc982df8f429ad11e05a8993318bc07cca5a204631f4cf30f3fc35f7afb057aaa6ea5acdf34ad03f924cf3fda84eb0281655e3eec3615c22f" },
                { "sl", "f9fd93ec6844cadb283745e08b8f285781f38b4973d4916c37ec27e6dc551f7f5870767d2d36676a48d6802df03788ff0bacadab7effe1c6c8f19d8a027fcf46" },
                { "sq", "d1c64e48ed206d3b08caa693c7f751a31dc549cd4cd31a5b473f092f2d2c093a096210b7155296bcc64740dd164aa735f41c69b8cf93f3a53540398cd9900e15" },
                { "sr", "6bb86fdf403608c4c903ca213d357c8badf0307dc3769bc9fc1a20cf682592ffa15e61d3f8c27e95f873a7d62b2049e8eadee3e01d69bf569bcf32f9e580ad74" },
                { "sv-SE", "1e775308706d06a15f91b8ac8203ab5ddd86af2f72501df1042601d04c1baa59ef23b641df35c9113cec4de47e0231bf79de0bc525bca2cedb3cb18e61a7feb6" },
                { "th", "c0f558383c1c9cf27d465ae98365da15128a36257f06bf92b7682054006a05c6b3cefeb8974bea351b69858797267421f4ef938dffc574806480cee38a5ca848" },
                { "tr", "2fd0da09a3e4311c9fcc3d2f9ef67219dcc2d044f927d2b4cb8c2bedda315f6ab8b6f88a1aa20eefed535fa2a2d4962952854142d526557400526380c33f19e1" },
                { "uk", "3f41591c261ba7e0297693dae6db6da16f0fbd336468c5e570474a2a20e855a5fca9b8b991623f7bf1162faf3e4adce9565f5f899a20500744dfd79f52205706" },
                { "uz", "6ceae1f099ae1f7fc314ba1ce2b9e8a996ab556c47a92246f3bec3b9f66d3ea69a26f137f7a583d3c1a0c230b805140fd5fa298720c1956d538e033d6b8c7ed9" },
                { "vi", "dbcc399d4825ee59ddadce2cd0b8b96f40747efe2d8e3727ee6a02aae99db43bccada29148d105addeca0948b0d60f9efe521103891b6f49e1c9f832fdeea3fd" },
                { "zh-CN", "7949603dadfab6c29bf615be672ea1cd9c3ef99a6ea576e93eeb931de0746c963e1852d6a747762ab17c0d50d254d90817e1c695496670bac182e93cf7505fe6" },
                { "zh-TW", "03535e0796d4d2ff1d8d8beebac76a32adcb1ca18de42fad926be66f6c69a414fa0354b70d8e49e3df0647e618e47fbbf3b559c4fac36e0b92b7c7a33759e270" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                string newLocation = response.Headers.Location?.ToString();
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
