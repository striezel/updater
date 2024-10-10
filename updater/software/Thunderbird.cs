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
        private const string knownVersion = "128.3.1";


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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.3.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "fe54238f16ac519c2af0a4935c39f99a144b7659660ff1ba67b4bd556eab0143a06c8a8de7e8b63060951fdd0adb1d087a1d447a79e02e264b4d056fdc015ed7" },
                { "ar", "ef9f35fa733e081645a8029cef24ad713a053518fa77279f4c896d43fe16cbeb396d8791958bf2a22554bbe1f4e6a9f3117a2cf03a5b25c91803f723e26dbbab" },
                { "ast", "7158580528797f7e1f3a10d06621b058fe92404f520806c63ecf6f2c905b007f3d68a1d603356df7d4673c6b4582249b5a072064208da832df729e8692dc82c8" },
                { "be", "ff53f498c2e5995de8c9059e50fdd41bf362a4e466ceb063deba2e0da01bc2161a4b2018cc74ce465734230a11eca9f41ad3b91b8ba49fe966480fd8fa3cff99" },
                { "bg", "5a6aad7c302e0b2acfaa81e9f58544442d9cf7fa335384a306124a74ec2cd7beb32e08fa0c6a0297dbfffa93daee16346f15aed993c04f4406df6cd3bddf59ca" },
                { "br", "86cabcc979593c556c1fab48588aaf6faeed5df99d5d224f4c0b611dc09fb141dd29f3c10074490d4763fe604ec5588d2ea4cf9563d7070a1b305230a3b4eabd" },
                { "ca", "852ca8624bb56ef616f04039be6c2009e13b366dd0d62441e974232899423e82085ce7ea19e2774abc1b75d3fedb1060990b05f568d44605eff9a4c06633cb6d" },
                { "cak", "ea771120aab880e1b19baf27ddafbe65b006232cbdadce54418b8ab8fb5fe03368e212a3f137cda0fb4ea422268a6f7a42c3b853743972c43d439c244bf0ca07" },
                { "cs", "0de237e4214e8503fa9f9ec20114b7603031fdff8959f4d8818b255e6a3a9e06ca04389a72af745f8ed9e5b56436beca8ef834fc6f7378dacff99da02bcdae1b" },
                { "cy", "6e60dd2e5c11d25ec216f113b275819719cf03a6be4a705a957245cb55b355557974736761c1adc58f56362f9a655b5201da6f3b81dd0e715835748d8dae7794" },
                { "da", "6fbe8c69f823eaec25d7cf7c0ed8b11c58134f06522f8f5689eb4acedadfe0ad1786ec67d220a1b1cb687d189172da4d6093596975282537bf8bada99186a210" },
                { "de", "1c9d38b18f1615410b6d720f4b3002776e8d6e10c8f40545649bd78eced3865e1ff93ec8246d53c7278e358038916b2baa3fa069983fb521e4ea5eb330209d2a" },
                { "dsb", "b2d59cb57f53256fe800a7e41cbcca7da02557a1949e984ce765d9a9eca9333d92f9d93ccd53936ceccfb8c23deb756d15b03395ab13f778e990fbf0875d4a32" },
                { "el", "e7fb654cabae8f1b5c0729aabfd3449bb2540c7397f8646d8c70666762efaf456da3f0bfcca0f04a69b3e526bca4cef917ecc682a948b345b5f92b08ab0e50d5" },
                { "en-CA", "1bf631cf638377c062455570edf89b81de711d3ed3d098d7333c1219ad849ea092160e33629a17c870d8f4d2c0e15ceef91a00f6d7ed2e812dd7b73efe9fdc06" },
                { "en-GB", "434f12d6487365f5c3488fa6e10a7d7d01b2a38eadf5732a03f0e207db9a664f4b4a6018be61d8b953031723d2b34fee37383ae127241c77f5e49104d22ba520" },
                { "en-US", "668fbe9245b17c2f9e7cd804c43a3955ce6df0103059225a54467ef43768975fa2231efbeb0b4b90f2cc8d239543984255f532d44e830542eef361a10b317377" },
                { "es-AR", "fd7070add94f26e3671c3c5e55a40fb87a4766299c25285b17787325d66087d2a39872ad1eaa15053d54aca96ac5b8c32331566fed882abd176aff36d3088197" },
                { "es-ES", "e356167c526f97081053044c44b00c96cea096293768556ec41cec90d6fd713a1513ec47d39a9d448a328a8465865786c7d7d80148f237dc0f8f3b142fceeb1c" },
                { "es-MX", "7078b1cac9020c7e8c9aec33254ebbcbba07be411925903e235aafa91055bf6caa331ab1fbfa9c9abaa3168e9f1872b8917705821c099b11979904b42bc73a6f" },
                { "et", "be153b0175b8371810f64400d3b621a141f84dc88b90f82bd53d66d38ddbe4516738138bf891f0cb77eeea30d5da1c96e33ec6fa74a4e9446615533d92fd076e" },
                { "eu", "79ae27abb9c51edac2491ad9538850cde03431d222bb5a01527639f189436ffe345b82d359a40d5c2f57c6a70f4f5bca08b444eee3f2df959d307c5d8c51ec9c" },
                { "fi", "c42914fc83a44e61a5c28d5994779af3a84b1d430f3e04c135fe2fbbb28c1e800f8eb42a0a9ec533ee033455b7814d3489252095a4dd61bc9b626dbe49faa2fa" },
                { "fr", "8c14d972314d3c4ac9d6ceb9258de6ed9f7f6e466488025d8f7b690ef44839bf9802589e7d567cccebce96ac5f4ee98e067af8672f39f96340ee5d9c148296f1" },
                { "fy-NL", "605dad3b6b34a08148372bf10a7c2882bba98cb94a1dec7ffbe620cc6819b5a99a5c0188904842ae23788bb9eaab697dba4c3d0eea3d6c52f45c194f97e69f4e" },
                { "ga-IE", "fe39dcb925a9ed14ab4c631268f9d29cbc372298fe68a9144761fb590404933e39aa5008e8e86f3bf9a2585152e5b6fc78338463f31670af1a45e72df38e4a61" },
                { "gd", "6adce9630bdab99999a899445dff2cbed8bec3cd34fe83d66d3b2d3c365501d576a61e4fe5c8c5f1e4ef1d9128057ae78a3e59d68ec72d94d717726264d668af" },
                { "gl", "1b8e1c3bc8069440806367dbca244caa8dd868ef4eb099742b693976ee3ed404668ccfcff3bb0eb3c42ed1537236272f51c774c582a1d70a34ba328993b3afa8" },
                { "he", "f7ee6465fa2d0d40c804d5f184ee52977e659b5577b48b15b89ea6bbb3a9c8e3ad6f7222d4ace9e8774eec7089a60bf4463dd89eb1513000dc1a80db81012d50" },
                { "hr", "06bcad7ccc98b20945b1ef4591eb9b3c230171f4ec1de35c4417d727110ab53df3a243e281c24f2f3e34451ebbe52543815b86940b1ff2b3a46f072f8e7cf39b" },
                { "hsb", "e317ed5c5c7e7afcb40f9e34bf9ba4fb5c6dcfe875428f811856f4db6440be553ca990e2561f6f6c8736227f13efad422e56f01c7c37df26352df34e744b68a4" },
                { "hu", "43f12521f193dd849042c1eb93ef9c6e911dc0f11f11b005d491d7727220e2e24f57e8d372e360c332ba60b96256e5bd5467ecdaae277a17c7fa8c9e9b946f9e" },
                { "hy-AM", "e3d3f7cef33c7538fbf20423a604cc9fa1313ef21da093f410fd5a992518d8a6fe9bb0576c52800f64aecfb69184ba4ab4e7e692bc1e3ebe0252185f2a87509c" },
                { "id", "2ef6de2e95475481b01df13ae74d2c840a3e73b58ef4a61dcfe87b586a68375a8fbec1cf68b32e01919e36b80e0ef5c7cc017bf5a749c52e9f17dfde90889fa8" },
                { "is", "ae8b66d3f106dbef69259829467e67958fa6a8e149a612a2ed0aea0a4deead5033144406fddeefa6806fa353c23ecebec00c8680a7199aa81a541b2f6efcba25" },
                { "it", "ab11ac642ee377755cf4a4fca787ace1f5edd40c8fcdeb0fd049fd30c30cc3a717769a9df7f2fab4fe653a07e547f2544321bcfde1746169143d9a494810f11b" },
                { "ja", "a1f7fff27a49385bb2da14b269f0fb3879d322dd8a58d93597e55b12a910b77450edd4b0f4f0aff467c04ff220dddcc6ffb51c9b8ab002d1716047cb022feb0a" },
                { "ka", "325184a754885824b7ddd376dd9d6bda32a6e3b0668e670f8ba72235d36462d368d6cd71a6de123762e75cbd668da8b50c36d4eb0673e868c1a2c5a6e492b00e" },
                { "kab", "4b2863e5a546ade31fb0dacb409e405d14a2e57fc2053281b499ca0c6a0907e327b0f29a02863119aabab6ca9b7580d3407a308a9525bfa606cd06a5b3159689" },
                { "kk", "1d24704b9325fd97b6b46d6bc77d4d71c479f59c63d709d674248b2af056a4816dd2bcd4ded96648c125f67d0389690206f677b5837653362b90c85813dadc28" },
                { "ko", "36af4b5491f2b1ff3ecab8834257f79513dd9486c3ea6e38154c0c5009873812ec527c95d58080a7c7b517705f659827d43426921a1065575398a0522263c4aa" },
                { "lt", "b52fcff8bfd46e59e019d1eff362f3a59c60a2bb495fc531af64984c3014ef3dc6a20e568fdd7cda089993ecc80e8acfc0d2566d336329124faf66240b2fb334" },
                { "lv", "24321a2cfff7090392235b46aadcff064b208ad4f1a2d5430b42357a356fa49e06f5f692ac370b4308e67e2ebfe75a4af9dd62088c271a98724cea1e2d93b0e0" },
                { "ms", "cb6798b1e1f3ff77dd01716f5317b87c40c91ce491e6ee67336826d425bbeef8ece4630f9b036b49a5dca47543c163043259c7455028a9ea250b151815af9b72" },
                { "nb-NO", "74ac5aaa027b89a74711637a2136348d5e62b787a99b24d6b7edc5c3a470211dfabb6e0bcae2c75695f45f43985a0143e7bdb097dbed33b3368f362ee34f539c" },
                { "nl", "2d311fb5362af699abf1e2877a29fd1947892e5f2a4e39077e9d1793617c5b5ad57bc72825f70d75d5ace5a4bc81b8a7b9992f3d6d1e0f9c2f852706cc84d10b" },
                { "nn-NO", "f7aec098bdac84cc91dc488b5a9ee094153df8d9b4745458a10f659dcb79f0650fa06175cec6cdb99525727e8d1f93792efb6ba8851012fbdad1f5e5d228b530" },
                { "pa-IN", "7da0dab780e21819b9c8ffb084cf04277af329152abe96e7daa8d32b3e6a0b98e4344ebf089263e457ea4ed2c256481b53bd4628279fd33190d5f85e28b801bb" },
                { "pl", "733aa6654933f771dc52d45f19800e08e45e1ab35d7b20470d081dca95e8ce5c83d87e9288fa13eba77ac383fe749d67b0dd0e97b5fc2dacafe88035ed0fec0f" },
                { "pt-BR", "a8fab91fc2e9353a8944e1062eae0eecc3082683e69be2bf08ebe060d7f3407a45d2bd2924601fcdfc3fa282d1a25b9b41ee4e570dc77c3431a82df3a3886d39" },
                { "pt-PT", "de0ec98ec5c34eb9fc09e72368097a461dd845fb177492c7e4fecefb5b3665ad0a8ad7a16201d49937d51d5806287e5030bbd5e3f7865861add6eb3050723b0f" },
                { "rm", "d2cd40f797e8061ccf7b3d589500bc5e9f30817c5b274bd5d78704ac47b7aa8e8b15787b2d6b26edd94dbd5ac62b3d7f7e63d06466b62dbb2baa0d5a546c141b" },
                { "ro", "7ead321820bcc240c68d02ca17a60bbad6ce4c7d356cf571c51cb074741ea3d4fc68ec157da755aa3122a73c7dfca4beb632935201c19d5e17ecd3de38ac386b" },
                { "ru", "481329b765c1c72522c4c259d86df67915e257cbd38407e60e60a2288ae845a66d3dc7bbf16af5b4ee2a566b0f938debf8978601651387f6aa683f207ffdd523" },
                { "sk", "2909b1181528b787ef432353a154eb6c5cb84abe2e875fc255557035d1efde29df8bb5a77f63bc2e8eeb4e7b8ff0dfc826dcd50347206fc376f0bdd5be29dfae" },
                { "sl", "322641c654ab7ed2af6df503f635e247b20e170be40d0f8f428d8f06c99dc592a68650939c65c075579bb844787862cf940ddb0fc3aa764e1116425030b055ab" },
                { "sq", "53d561dcb7ddd9042d0e3ce94d1c6e48e4ceb4a779c5d643cd1d7f04b7f619474eaa95a839c6e95f1ee2fcae646520fc33241367c111777fcb1a7b01c2a65878" },
                { "sr", "d37f3cb0b324f19d83aa8e5a292d85d71bf7162f2de02dcffc4a6c205255f9512fb0446ec03586aa213a6bebf6196adadb4992bbcc5f11d03bf4ed91efc570a6" },
                { "sv-SE", "29113890177e0855368f2382cf76a6fd4ebb5d7d0de5e393fb135bd47010efe156437779c995407f6c14d0f93b7d0e6bb196730d4b622c27bd601c205a6ab1cb" },
                { "th", "74d8b4dbf5b09f79e52728e38be388176199dccd6c16f8dd0a46a8306f9666ff4981ef9340216890c1d061f282e6810c4d31754edfe67049cda3fe0bce76a367" },
                { "tr", "e4ba407e6f2aa0589925d8884a90a8e1476870db971bf74d04904501084d508f5dfd86215beb4c08d6693a1a1ee0bd53fc8a902da88bcfc1a486ec2cc40abea5" },
                { "uk", "f134471ace6ec17c2460c01b0323ad6c79c71b3e261644498540696204ffba1fe014d3a7972e571a1686463caa476d88ac4d562486b8224cb8875579963c8daa" },
                { "uz", "bd7b42dc53a6e9b9cbfb4c2696b31e52aa76ef3a922a0d1c564dcee93f9a7a840967914826d1292ac2a3fdc2197a557536080aafd7f9df716c974bc40bf54114" },
                { "vi", "1fd5258649c5c3dacca14224c4a969909cd18ad78b9ca200667976fc4d6925d36c5ca4fb4eb0e30648b1ae0133302f15a8012c41f4befd44f79ea69b5bb91f57" },
                { "zh-CN", "71bc69a0949d620b9c80f0f8da0d574df04759ff4e809c76ac510e56462bd558ea838cff49559dea4ffc5733b063cc4b7308404044eb05057976153e6cf6c306" },
                { "zh-TW", "1b522a63fe2f4cc369a24f81b9eeab88c7e1b70b1795f3cc47c4b815e2e373cc3c769f415ba75c20fa0ec15a5fe33d073a09e8428bd1d1e84f17bd2e72d52f44" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.3.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "4672d0caf522782b1f40fcdea724ecedf7c3b88c919cc0ed8d4a9a7696dc5c024543809d88b7be72083bbdb3256b6c718340002d0bd0da3766d3d0c718c6e66d" },
                { "ar", "7d3a2580b8c61a4dbee3da77212545cd5a54de180f4255599de1cd4e85118560189fbd1c7111923f8edb3eb9b8f0c421742898bb481b049ff134193cf5bafc00" },
                { "ast", "b11a83bd55fadb3e63ec3102a844dfd892b0d80afc5dc805137d12931c6e9d4e6b040f260f506214937a78c294aae3837aa8a6fe63f7261c68f9fd556cae8851" },
                { "be", "0b58232a3090eebd601225915ab4ac3ded11f1fde31f741aa124acd0ec4462bb8970ad6be1d874166ce38a14312fd1f433917d52757c5427787c32d490694901" },
                { "bg", "cbb432ec6da1158d2e30b2ac7393b8fd1e0dc56c291b23f4fce78082d50569e3c1b93ddfea721253ae69af2a6a91d39d34542e3baff1b5218baedcf28f011d88" },
                { "br", "7e123a8f39aafabee259f7379e54ef98048711c77606ad4ca42f91eca42f4fee1cd00b408efe97527547e7ed3e8d8e499bd0d6041c9760226fdc5700cd89d6b0" },
                { "ca", "5b7d721394dca4560f0753491251e8693cf2299c047883fb0ade7e4514f09adc9df9e2a5c184c81869cbfdaa2c606c462b81843cda683e98b070c7323f7a6849" },
                { "cak", "2226916ee1946dec0d5d1127d596bbc7125192764520d66b088d607ed0e5b72d70e36e31776503c94f8aaefd327bd7bfab14ee6eb9cef9b1f3b71690112d2f86" },
                { "cs", "d1632144fdc85eada91cd1fade96faf6948d3acc832b8dbc4cfacb1169c2fea0584fb644e70b7c306afa5918af3f26b5c43d5f89430a3e857cc10329903db7ea" },
                { "cy", "ed2614aca7efa1958312c059e7ab82f8df134e844f1f66997c3ca56e8427800d229abbce9994a727f8e5a8d91af931c197a4125cd31cdb1a4d97a82ce25dbf7a" },
                { "da", "2f96a521d3c11903a7d131d863064f4a993118dca071e6947273e37e8854075b1aa339187063ee7e2e56a4a45a6b95af337ba2c6e4f93f1e15ce9c0d6d50581a" },
                { "de", "50d74e8e7080ba0f122963a900752cc25810b3337bd6a3b030a60a8589f79fa99dcdd6999b2f8cf4bb8de6aa39a22aa6492682708219305234d239424684d0bd" },
                { "dsb", "344ece6428408eb282edac24bbc433eb41a9589daae8da8b6f4ee21fd677c14bc458e5b913b9db787c34ce26992e4e530d52269cb987b12c5a962da2f5a39235" },
                { "el", "9a6a9775011022824b07553990bf136ad4eb62ffa2edf74aa803132152c4b6fa5015db4fb8c4eafd5ea35040d417259967e68b3d0d4f8f4f130e8077bdb2d29d" },
                { "en-CA", "ce0c7429796f267fad34148c1d3ada74637aae156b02e1e69277dbf28a1c54d630088382e56afe1fa0d0497c462336985dda1dfbd7bc8ec7c35105c53547f869" },
                { "en-GB", "39402a329327ef3845ff3846b059180ebb83c3a3e32abd380656fa3ac2fea9ba71acba309fb63884750b1165b7bfd98f0f4b0d19ffba388b103b7c85f848fc8d" },
                { "en-US", "10669a096d40ef2baa44b802b2f2cfb0435a9d71836887a02b2ecc285ee09b461cab1574d1e70d133d8b698a25dedf045a1d427a2a76a3ee829ac5f783a5dfd7" },
                { "es-AR", "72cbb17526f9a5b4ff28202690e542cf04d55452328afb113a75155a89e7b6c35577c44e433e12e8ca856af1d44674bf095863093d39c264cfcbdb94d8c805c1" },
                { "es-ES", "9e83553894b25942ecc89a7a762991a17ca263b51f4048090451cfa880fb50dfa790d1f2f1b3f41092dd4a5da0130ecac00abd49da37ca488dd95f4e68a0434c" },
                { "es-MX", "46b747a0ba4569767b1b53339e55dbaadd3cc3d536aa3786b12447bda3ba6b826418941cec4066bbce354420014b671b3c9a80d0122a0b642e0eb41c59688a3c" },
                { "et", "015ee737d6d44fe5daee9c22c064480903a1f71ade52756a5bea1dbd6c07f4c96aa62fd6d88407241437e37f5f2ab899200e5864c182776f76cf24e46e3d2429" },
                { "eu", "bc3eb218b73275bc2c953c405596adc6f0736f7d31257289acfdb4ca92386d61c7d149ae3f02879ee5f950716ee421a7584fef546932d123b984c3cffa0243eb" },
                { "fi", "2f1e06613a81a86774f7add581f4b15bb8f540bc5a606b991f799b2ebb4e2463739befbf96f1a312e6651f3ee7c4ab322a501d49855c4bc3a9cbadf661664564" },
                { "fr", "ddbaf93305f494b9c8be905dc2e91c0349f3bd5ace80f74bc1ef32edc4bb0cceb5d865b5fc7ffe7df595783001b8eedd606abd8891a667c2ed1c8423ce6c1628" },
                { "fy-NL", "fd1b1fe04f894a3555c51ddea1de23a84759943edffcea24e7becd5d8ad83cc6b7d473f6636a85305c958070efaaa3065c7487a7b518f40a3f03c5a60e3eb745" },
                { "ga-IE", "eb0630813927fa54768715cbbea6e6079961d49c3776dec837679e9a676ba04c70ef1a91defac999c52f948e0bcd9d6d6ff8ca6ad8e0bbeafa98158f3a24360d" },
                { "gd", "8d475262e45e79bf6ce27db103fa5b4c413c6eec04f103c1848518a1ed477f831dd63a2138bd7be03b0e990d6056c6eb36594b679ad3d110423f12d50c67007b" },
                { "gl", "6adcf43cacad9c87b36ebe547e6ef7128fd50e4f90c274af80ecf1f332ba1adbdc12895ba83760e48cd4bb502432af1b5599ffb8e53dba0aa3be4dd4adceff47" },
                { "he", "544b73d3b2e0b30cf56205e9c093f9db05923d6ab0b40f6b4d14fcec7dded1e23bfd1f153de1207e3913f5d2c0e593f7691f42f722cd2dcaddf93ad133060623" },
                { "hr", "34a54c4e0c6b167c353890a373798d7eab02899625ab1796e27a9452010e02d3f3af98f2ebcc9ad0c3c75f67f13c657c7b4d7e113a403ce2ab4a6671133f0f63" },
                { "hsb", "ee2f175e5007a56329d8d0e00a2673bfacc54a0a1116f8f1bab9173e3d59c98181ddc76ae06ec6dbb51203cf77ec28c7d22fea00406890d37caf0b9adacf6b74" },
                { "hu", "ca9de7a8212d5ef548723a495aaf2fc496885b818cbe2751be5a9861257c4682dfce91a9646fcf03286c750305018730ab11440332fcbd1bc4125d8499dafccb" },
                { "hy-AM", "465c83b46169e61aaf1507546d4a824c52a8bc1204c0207e462826dbb3c8ef445409b398d53082d880536a0b24e5c24c83e2628653f224c76d5a371bc79826f1" },
                { "id", "c2fa57476e8c2ce9e5466a2218d9deb47f7608934cf3bdd85f8959b063b89d34271c53f84a9c79eb672684ee39f58e83220e140d0cc84200d0e0582f3fca2253" },
                { "is", "1b7bbe7fe621e91293a3f0d61f02dafb5447dc454ccce4699652ed7c42f38af5891c881cf8b5afa04f2a9ef4fafcbdc8068b3d8826a652260961dd5f0f85c4f8" },
                { "it", "b58277a82317550bce802db87e9fa91870996edfdaf2fabaa7140d2d753f8f628945fcb13629b4dfc755d2c5f5c4541e00f5e01c9da64262ca2406ce558686eb" },
                { "ja", "12ca0d5035dd2ea45c0f8cc97f3f797dd79fe4b9dddbb20740b89f1eb8f5c858b79846596cc19b723cd8ee8204360ba27a41acd71b3ea5319999bcf31fc4449b" },
                { "ka", "a21f04dafee0b4119a8a24dd4fbc4c1e52ded09fa799243788b7a2b861341e5171e12f1c9bf86f4392f5a9ce36a6af871b17475507b6b738949c46cf2b357592" },
                { "kab", "86927a461c95e2c02bb8a7be9d3a2d5d34a9c9c0d468dcac3653483beb67888b93c4cd67e5ed56a5ecdd3acd478a0e27e3d11984ac9c4a35d5a00fedfdb4a5f7" },
                { "kk", "7e86ea679b155b42b0fe08f9ec9902b968793aa85433584c11b27977cc03e58b2b965776d0dcd167576b53a263a6894711868818f0807da93da704fa205f59c4" },
                { "ko", "b89015ac4188142fb4f8a4df67dc83dfc968017019a86b99257bf7b740c326049f417f046cbd530006161e4943933dc0176e6e1fa620b6b4aeb5515a50b77066" },
                { "lt", "73e5ac4b83e369f7fdf4f4e05f265d0442b232677a441202cebc2291db3e89963c4902ed68da677e7622d8daf6ef55d7f41ef3c8b329a7d223d947480132f088" },
                { "lv", "fbe6afc701a0c47ab82a097cec6d5c6bc52ab3da9c3fedac8bb67a7592d4f574215dfa327eefabb6d62329140df7f2dcf01f07eb3b533adc37783ee0468f2d55" },
                { "ms", "7270f627653fb620a1b9c811831d24e0ce0a505c4f76bbc0ef3daaef3f44aaff11e3f876099207188136a7cccd4dc7b85d7c0748ba24ad312e6d864ef10f640a" },
                { "nb-NO", "0c4767a88bbdcba2604e0e722db03ad86cd1d3fbf0d23b70f02c3da28621a40ac35f987f3c38b67492e747fe9a36f37dd24b2feef616abae1d465224dfd37725" },
                { "nl", "3a51d62d07623a92a47425245475e71e50fc4b06a454cf49bc54b4b8c06aea16194a03288bc1f65782ab6acc1157220c07d65f07ce1d1cc78a9275e09dc4f63b" },
                { "nn-NO", "9876ed042a7fd7fdb4c4659e0fe7a60c4e34449e315c9971f35540d1172c45aba7c68f0718fcd4625824ca650d20b78b13c59ffabbc36e83ddef8d16ed5fa6bb" },
                { "pa-IN", "24d1e8715e658d757fa8ae2084602551628275dc168507554375da65f2ebf05ebc2554f7e281f96d0b49368dd8cf07665bf0c234b7595021f00f82a5544338dd" },
                { "pl", "04af4d08deac97856508b85e527c45f33d021871785c8960ce367c4cac7d3b937beac1ba37e7fc09d55dc4e4d097e55bfc07c1f231733c36c84008700691f658" },
                { "pt-BR", "4b9252b4a7179011478cd5b137d705ddf12fe8586e6923c9fcf4b7c4d4c9e585a585398fcba06a7dc93d688c809b9edbbd9788115af001cf5ce566871f612a7b" },
                { "pt-PT", "4b24ad9314d8e1ecc8f8183fe028132367831d127594ac3ceb7ceaab55140b317b99b95988f76a6fe2eacd7ebe85639df035a7271a548509f4e9b1a925579428" },
                { "rm", "16db91935cbb0895730aa197df45f3ee0e68b71cb7bf6f444bcb0705c39022257caff2c700a79df9ac4d1b0d2a7ce91c22f55a3b7f37f13fa3c35d29ab45b066" },
                { "ro", "040f2bb14961457d473e2d29c2632dbacdcef5590ae3b124c531dcf241e4e2a4d88c164432097119b86aaf1fc5640aab3a0465c48e2a6ac0a766eb210af33c82" },
                { "ru", "0940c82082a04c1da42ccd021eec1e6b73ae66d3b2a07162cc0900bb3d274d1610aacfff813000a094a5a1441bace42d5d5b8da8935a5a1069013ad66d32e2bc" },
                { "sk", "2e5f5c67a3eeb0ae968b386835e472f7546171c8bebe3e3a7133ded89021d454ed5aefabcafb733e739dc97c2b607ed918d827f1dcc6eb25e59d0c5a6a515af7" },
                { "sl", "75973c08e9186ccc261e68d0f701e95d6395c0e311fa89b8fedf08080ba3988e13e96d558b2ebdaac53b7b5b9e40495ff1302b8ef85c376899b0b838fda2e8a3" },
                { "sq", "e59bd486929d37fa7d686316cd915e629947fb0fde59fdff74500bd5d8b200add378f200631eaad7d91fec83a8c889f738c9839d703e6c03209e5338469eb430" },
                { "sr", "3b1b844e0d8f4841162bd0fe81a5eb9f4592568d8921b12292bd71a31bddf02aa6c157394afd0421cfc78d82c1c868aaaa25b8456c8cc419e8493f8f93e49f5b" },
                { "sv-SE", "aacf5b1f699adf8dbebe94fe57570e6a7c03310abb9433027071784ee9fc1613abf2f285086f1430435cca2209a882d48ec352a5b8630e223a549621217cc151" },
                { "th", "f13092848cf583ad4af4a0ffe9cc132de6ccb1a36e57bf407e0b4218ce766a1cba9ccb3ee144ca25500f2ce528a557da8c6f9b8a989b86c6d3c26d45acb7cd57" },
                { "tr", "084d73d0196b94b7c8979627103b51abba5f66401c03f391e502afff12244bf418a0c52cc4f9719afb615417286b2b708a856b3b7bf8d524561e25e6a6396b19" },
                { "uk", "92535f91e18b6d7664ea944a032b3c90cab352c960b06f1d4b95e9882de1a9b9461b0524d3778badff262b2bd7f1b49b079d6d8af2e98ccb3c8bcfc15ba145ca" },
                { "uz", "cb2f486df0c87923b7da95e9b2290b3fce4c19eeabc889019e1ed494ed7586fd5ec6b06d5ee2b50403ecbcb92ec900fdaacf366a15627f47761792e52f823048" },
                { "vi", "31833b8b2c529e758baa2bb6a437cfd45b01d88808bc78abb885f1f22c29569460c8ef8f9ed27396f71d8976a2b38a2ba98ba7ba998d3421cddbc1e33bd574fd" },
                { "zh-CN", "3fc918c562ee6d91581dec0a388cb6faee501372d4ac906f0343fa354daeea50607c52e88fb65733ebd33861e954739d36362959eb3e9658be886c3ad3a92a3d" },
                { "zh-TW", "697737c3ef18c77204b97592637710ca1596ce7f0c7e65f7a680b08dc26f57126be23c6468884caf4d455d007e5f113e0f8ff9e3848988ab021191f2284b7c2b" }
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
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
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
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
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
            return new List<string>(1)
            {
                "thunderbird"
            };
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
