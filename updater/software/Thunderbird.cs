﻿/*
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
        private const string knownVersion = "140.4.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "1107ae9188396f1d20b7ad4ff5837e43116a81f32900ac3a9647352c7148063c960da1e6e0492839df25dec4265af2b8e1381c14a094d878c617923cf7a9accb" },
                { "ar", "ca7ddce8e7189c86229c7c7c5c4ef674ce2dc9990194884da5839d97b94fc1f61e8bf1a027a1b967d8f460368b9378c3a54e9159b44367359afcd9975f53a4d0" },
                { "ast", "9652a7a763cb07a175f923c1737087da4a626c1c2b51a2a9a92879c0afff7eb4ecbc6e2f20a6385c36a6779b25ddeb4dc73d7c387bf5c1681092c53f1a0193ce" },
                { "be", "0e0ef1dcbbc428f599bd2af44435e2f8062441a24d94dae6f8b628b9df6999ef5a6dd36accbe446acbc307f06ded749f618161604ed67c9bfc66098955b0ed4e" },
                { "bg", "797e26231cd74275e68dde17b19376aad494a064006158710836da1afc00852860942af5d3d1e73ffc806cbf593ac0442702c063e4331e8b5f0024d8c3404037" },
                { "br", "3aec3d419824080e6d1208d2fe56e04e4c8c1f6416a7533687eb09320978882b3a461b9792ffcdfb430a566f138f58a4e2f0e5e4763125688f250606a353e2ef" },
                { "ca", "bae816b09804a5ad154df97cea4443ccc317fe8a3897f61109f603406dbb1074e477c77d3bb80b59eabfb159c912cebf009a4ea5a091c62458235963104300a4" },
                { "cak", "b225af97b99275d7044c4fb822923cd0fa0ec88e5e7e265224deb3e9b4bdefdb298f5c50fcf06fc7b619ddf027c17dd57649d3e92a3c42fc92b9a453c3049101" },
                { "cs", "01cead10fd9a63bb41c7b03b15004ec72334ee07b5d9a2a7a5d41d53c55780224fbc982cb46535ed01663868bbab33cac977e4e1ccaf9c4061d284c5c38ff8a8" },
                { "cy", "34a1b7d135c6e0d236ba1d6e07ec90fd221837a267eb6d3744c68f8c104262424c3002c216e1e2f195852aa4fddb4fd7ecf578c7a081308b84240aaa9fa05a37" },
                { "da", "6b95466bfc0c0704c881ca00551687f46ec9e4927d698755763f3b27b283b7f114c3f0a9669f3e40bfce20c34dffc3caf0c51bfd23b5e1e9f43ab33c365a6a25" },
                { "de", "770daa46eb892a46f3c28aafdaf2d82cc5ee6bcdf3e749ad5f4d52aa54f44ace7732d2beb0a9655444c3784298596a5ead8e50dac4f4b27e28b316e45ac8624f" },
                { "dsb", "21bf945916b800a7726a814e8ecaf221b582b8d3b8320ea4c0ac88ddf6c422fab7c7ec849743aa4f65ee6eb6a0d62d03657f3eaf90dc4c7a64451ebde7e55282" },
                { "el", "68789ba2fbb492584dd801c2a3dc3eed44aa13aeec840f868430ad1c3a7d68109190ad729e217d7fbd0a5a108444906c5ab5d912c6f77fcf10d8868cbcb02999" },
                { "en-CA", "8b7b335d7b17eb1acde90369ad7db766c70ad1daad94c3801fa0abc0c5db09ea8d3d5c99410870ad8c872325e83f2cf6258e60ad07ff1a722a2780b059d1b532" },
                { "en-GB", "5092e3aca6e8e2ebe9ece9af6dc11e3e31fa9c6e69d0f1f20c554ffefbf0310a1f973b0fb3069187cd30a05be8589c816c7c0815ebea3b115e94b9f5317da1a0" },
                { "en-US", "d5c095206734fd2c81fd99276ae9d4ba12fc187060a8959fcda3cc487d7d5e445d7bc3a1047620022765f2c05c40a6a20ef74ade1c73590a2f1570c2919d647c" },
                { "es-AR", "c1e307bd6aaa4bd2de9feea7ccd5097f3b0a3be215cc8ea02e575b936c65cfab327910a7d53b414f4b4b2e07e1e05011db781b909e1373f1e6b566763b8b869f" },
                { "es-ES", "25c185c0e03347862e85983d4c21df6b9fbf5b6ccc67a46c30b4a7939e46447951a618eb85917e86cc8e79226d8df9ae7b62d72c16b7d8a82bcfe45d37aa2a8e" },
                { "es-MX", "2fd5e89964540131fa4ae596821a24eeae975a9640e874f5e4606a0576e98ce0333deafc0ea30f98a532f4354a568fc1c5df3174f2a8b3626185b634d7c7f2ee" },
                { "et", "541735802c736ca6fa3f7d9d9c1142149228e5e044a89b799d239b8f1950326daa402021d4ca699aa842bb2b6cd96c92c7b7905b9186f28a6a74c50fcf6b6f81" },
                { "eu", "070daf16ed4c344743464c7818173b63087c1d4633197c07fa90d2674364c4174eac1e5c71678293fed547a36150f13b96e1681317a8cb9c78e677c23c5a5c93" },
                { "fi", "2bcdeba19de2e1509abe5644a54a7947457c996bddc20e4c1cb18d641695a76ddeeef104ef525777cba69bf331840f899834a84767355d42c9d77db1613a5505" },
                { "fr", "8d64fb2d6a260260c26701c9b3ed646d31fa68140b9d25ebc8bf3e689370b4afe10db10b5f2d5c5acac16bd490bd88c5e34ded73450c81582255cccca25fd531" },
                { "fy-NL", "5833a9cde24048128f45bb3d6060dc60cc75b39fb0115614feb592293a0732528db2c3d3892b0d5616b018dc88a16e98a33632e6085a2e9faed7ce6d4c77d3bb" },
                { "ga-IE", "1eab85a91d38466472d4aab2aec629fd5fa170d8181ab7f8dd8ecd1f29f1cd04a3e6fb36772a3359d8799774f091d0c45c194bcdea62c551e11664e668fe5767" },
                { "gd", "eeffab0a464270c3fe17c7c03554c9171dd4ff41fa702037edaafd0167522a092f087af1fd84e0a42c6279885987809243ab3ab0f2ec6f7c2633774ae644dac9" },
                { "gl", "4cec5b61708229a27b8f57e86a170039c5a3055046d8d0b302e25fe20fd8ec681a9268539af1dd5508aa3df01894007e33270ef07ae7e2c1b188e93655277f5b" },
                { "he", "fadaa78e4af55b13be2112d842cfdd9f184e1dc94ed21f68af4ae7ae7c8b93d1c08dee928792ff22e1416b330d000a716998296eb668e99c4d66ce46d523184b" },
                { "hr", "f18c6fdcf988efdef112e90a64e62ecd66dca3fbf827f3b82e6b9c15b956964ad0e714a24e53cbd83b14480f6d5a6a000dce0e0b51bfa48fe100e0dee5a51271" },
                { "hsb", "61a2d6f63c66e0124bf16716188b3babd7a58d09d8e41aaf55f270339bca15ab548e02b1efae458283149700493cb64920a55fe36541d76beab3943afdc1c16c" },
                { "hu", "0f7826dd8f774d0f2caa241a06e695126d1630a0796a78bfdf5fdc92a14463801da7068212d40a77cf91006a01f9bc23d37d904440e75ef6b6d086871d89d565" },
                { "hy-AM", "753852c4c6889ec6c09570b54bbef32385e82f2b296c4d782e8956caaae2a3f48a153d3788669cd0c6ac1c9d62e22d5a368413709a9e98997664d1829e2d777b" },
                { "id", "839a1288036814a0f8809bb158ec0eb334fb09d1706789179e891f37c0f52324af4acee1898fd67a687e319e49cdcfad4e512f8f0e4927472ab65cbea7a032bb" },
                { "is", "09ebf5acb43bac61bc4d180061ac51bdd3e2317dc89b9dbd94183d8235b7f2d9a451fa8c94e3e2596adf1ea52b1771a7be791c71ef792f14e65bd0af8838c4a1" },
                { "it", "dc6e1c4a2d32264fe421c80b0efd59231191927f13e9228049add27996f5e291d842e9ff14f42dcba33d075093dcf8998cf8fd03814fd7a69e24095428ee936b" },
                { "ja", "2aa059f6c073a24a75762a00b83db15c3dea268023865fd760034e3cca39abede42b37a06972777e49230ed03a1e331cec86ed290a1a833a3c6c16752306faaa" },
                { "ka", "563b6082fdabf1a0e578cd6b340acda8c8d043de108dd7ac17544847108bc86edd45fbce15048d64c0361063f9275914416980eb33e3e39179c1031991449f49" },
                { "kab", "23fb22ab8255d1586c83882f124706f4a4d0c3c294f52ddf816b9e4b4fed5a7f3f326f61fc33a9b284bc17e539f023a428c4ee280c60016818ffb9b080e6b1f7" },
                { "kk", "8e543407d94794684e7df6d373481834278f12ca5ce4fbc3106faa262ca3c513831947654dea91805b9bd2a2a74bc922816a6ac78d7726e14d22f82f4cc39ed0" },
                { "ko", "fe5e9af06884d0cfdbb48d2b997dc6bf923c6beb46174b606724aebdbcc2e258885cc3d2f11c3b00cf2d4195beadd196d5a806703ceff5c9809e27abf1f7d037" },
                { "lt", "6bf60c4c02b649ba16e8231c7c3cd85b0644ca1ec069571448abc587117289a1c4c5023a72303b7eab2883ba66ae757703c908db974ce05cd28bf0564051b0eb" },
                { "lv", "65df8bb53557de202d87de21fdd9d76fa4e0105a85f7c22919ce57993403c1149e1a19a245e2475d65857815f0ab6735d08e2adc1b614c1845d6f013fa574494" },
                { "ms", "868fa09cc361e491ef3eda599be4f7e2e32b89b8d01fd9f46a9de408eb0ae289d3b90ce5e3917493ea009af22af46f75f21805bc352403fd518b49b33b24c5e3" },
                { "nb-NO", "7f9bd1d64d81bdc85fccfda8043c49224f47a6ccbe9a79ed1ec72bb4d54c5ce5f489ded774dab35322826915b88879d56594e2137e9dc5b296adc44faa18a87c" },
                { "nl", "d8cd99e63e42930047bbb7e22b7c45f8940178698188cdda17b68eb19ad934c0972bc8f9461e9c72bdd08c4d2f55b9ad88aa5ef44b6219ec15ba7b57e2875df1" },
                { "nn-NO", "289eebe5e72caf5ff1c5068fda58f0bf51643d92851182eff246619b6bd1f9a764b01efef6ca9d12e401589daf1905da8f78dfe97d910e7db45df79ab7cb10a1" },
                { "pa-IN", "ad542022568e4a433d29a6af8dc96b26a95477d15388ff0469520b02e1e83ec683e30e1a8abae20211bc6a6eef285e09f42b9d87e6478222762f9f2fe1f28339" },
                { "pl", "f8c0f6e9d66fb7b06ff28cea6bdd02ac8edec8d3e784a316301ce877d93b01f20cc6cd232c4767ea807615a01ffa061cfffb16fcdec9e140510962de0d8308ef" },
                { "pt-BR", "fd170494052922339e88f095bee2e516a71d63bd1f33e6ad9713edc337982b97cb4f0e3165e6e43abbac8c63a660ca3c5c951ca888221e2207d5ceaa3a895eb1" },
                { "pt-PT", "614c48d200268f1162a2c932ca24c235800617769c5f9351c307d75c48dcfa2e9a48f5b12268659f53551d3cca5fa8a998b5fd85c756ad6bf0876916ef503741" },
                { "rm", "f35aeba21dedb0841eb57b1c6a86f5b1e612d43dd49dc5d5e0af34ca830084c54d35e99d036e0a781e6bb5166d5dbce6e349bb4f1f15b5f1e5bb5804acd150b9" },
                { "ro", "c7453aea159bb6868def135df366db248547c86fd9407ecfbaa8b444aa4c911c8870e7f88cc9e6f9dc7aaa84329e8c5c393c230705a11fde23ec1967390aed05" },
                { "ru", "992b64dbc6b5e19e3c8be70311157b45eae15dbaf023ae676a9a830c17e0cbb37dfc0a437ed2a26c4dea74b229fb1f5c09f62acda776160e96e431aa34d259e1" },
                { "sk", "ce5dcbc3b3d99cdf90399e9c11aa4432adc7273fd3a04abd593cb1cc781bd535f80dfe77ef2e78ee21f6896f67f5573cccbe5940e73cffacdc8d4b9c5c61a5f4" },
                { "sl", "453a17a9967b6653c7dd35b40f8319ce51c0fbbed317146e7e1df54df0170da6c8e6d4fd8a657e037450c561ce9ab31f11415713a54e15831ff561211d98e2c9" },
                { "sq", "7b8d39ff87c377063117c87e767552fc5c2af8dad136f6ae483962ed55e5c3778e718b9813de8ebb7bbc1d809f68ba82c3115e0fd67514794123a055453c3438" },
                { "sr", "ac1bf34aab5b2f096a340d4307c62808fbe40bf7861361c0fa89a56728bd53ed3b9eac013c24b6517b86d9b31a9b976ef1c8454b2823698a1866d708d3692722" },
                { "sv-SE", "97acdc8d39f5009d17fb4c8d38ca3cdc040223fa4293da54b14c030c010eac26da7635b2ff52a78cebd98014d216f2b502d637ab6c20c67cdba91d7b189e02b9" },
                { "th", "5b6c65c5428fc1b6a1cb3feb9132fe1b17342c1df77659c3a94c63003377d03eea84ed602524bce714bf6ad9e2364a534e868a5ada01815395acc50b3c51c065" },
                { "tr", "fe1f1f5eda0a46d71876ef00479e36fd5d4eb9848acb767ac5d2a4a68f080208bb50707ec56151610f2808cd98b1b18a136a42d7f3bc05ab12149101e311de57" },
                { "uk", "969d3191b45febdf261911cdf028ed21f40bd8e8300af15f76040cffc16b62d709d5e916e13cfd1ed5729bae9b6ac1dcdb4bda8eb99f2e12532b824f55cce212" },
                { "uz", "9c31543ec3e5111f05e9b66b8076cbca5c4d650fcf254915b714cbd2d85338d205dc1a33b94e485ac1bb9eca3aa7b935a7f957405e2d36ff4e402340371baeb5" },
                { "vi", "a9349a5d075f8aa7a7d049cf3bc846bf14c693eb105e584924a080a4e6f4766dfb5ca6208dadf4bd69b0fbd9be338637fe86c68df3296d72e2258e53dc967dc2" },
                { "zh-CN", "262c9a88d066740ad8f5a9eeb9626b1e7b341f1b15ad74ee14b468748cee09c3cc345fdd6b382ae2c884480e020958c0c57030995cdfef419c28e52f37a7ddab" },
                { "zh-TW", "a2b21665ee29a4d754ab0e19215a3186acf86a26966f59db81e4522c4213ffcb50cce3f150e9b6111da9f31a9c234fa77e02696a7f18cc17aa45790b68dd016d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.4.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "6683fb0953656c0ece8dc160328312d931f0f8f91b34e4db22b196076823e062e7f3ae6efd0b1d99b8d649cbc0eb0db5978fe6ce1ea4d7486ff3dbd22338442d" },
                { "ar", "4e8b404b314b6d5de420e3f0a670ef17eb07191ae531d047e4baf127af3bbfd42bdbc2a114ca3541f7d40ead1068aad70fc7167f3dfda7bcfb01bd2d3a87f439" },
                { "ast", "80d6846a45ba44add65e8e88aaf9cec71f85817c9ec38463e7a7cf078c4bacbc6a575af8afa3596033126f2197454bf8ce73bfe003854de2420e2905ffe96c81" },
                { "be", "dc3a1483184a9261fb9c36f7d7e610fb15e19c4eca3e7fc83bd79943ae11e2c168c2446e374fa4d9d0e7a0e76155e14e40073537badbbc6ff36bb6daaab1e485" },
                { "bg", "b68fe71a22023899189690b7013757f8c3b2d76f34e0796530c38b04c4066841009786611731b18b74b15083d1c8145d9f2fea99d1cf2768937ae8f89c18df36" },
                { "br", "f712379de7bada88dd00e48b61edd9f2a738417ae37d392bd28cb38f73e8d42e11dc4139cbe98ba6c9922bc885da6ee801286a06c22a7f6b31731451ce19c593" },
                { "ca", "8537115fc18bd3642693d73bb1666fa52e31aad5f89dabb34123cec9a19d3753578e663d142f9641c6e44708824b78f45d39bcb7fc710b8eb3abb3beff030178" },
                { "cak", "5d8a767affcd9b285ecbdd1be04a019235d5a52eaacc5ec5f694557208273bcefe8b8a93567dcf38c85561857b57accc51d5fc7b45ca89face94614565f857b4" },
                { "cs", "833da97dfa0badbe0b31bd3b7930d867ec75ca038c44249bb4f3f15db5d7918d8446fe18fbe33fe32e35a000ddeb651ce3594d7d6fc7a6c91609ff8515c550a2" },
                { "cy", "4942708c5bb2bb1c2533dbdaf1412404e5f1efbb3457d7d8507ee29ac913f41533bff729856d9106445ba2025c84323882e583ae22f4fcaa26218ae1a1480dfc" },
                { "da", "978e36323abbb34ea6c3ccf67f2496dcefb46d1434209859ca67a3439181bd468a3a6753ee7b07f4ccbde765158b00eb76ebbcc51ab7761bf89100c1143213c2" },
                { "de", "8f75857b4eb1bb5b6a7e1bae55040a5e3de13dcc414f6ec9e90a30dc58ed1d89770856cc738ac55f5898ee86e9aca04c70538a90f4c0f365b7116ece0d696645" },
                { "dsb", "7aa49c3e03f1c487071c4af962cdbf8dc7c4214fb28a1be6bb95fd3309b808f86c110a0176b348f68a4ece84913cdd3d01f0a1d4c2531824a49b37930352ba15" },
                { "el", "edc81a828efbba58f6425b0758eae37bfffc0381347c3867dcfa451e2a603504e492b3f91cd0ceaa83095f7d4fd2370f493a674165225b7b01f98cec60456c9e" },
                { "en-CA", "434835dedf7cbdda5b7368362cd6abfe71659989ef8d06033d7e82111e78ebbbaa2bf927cd004c37bbfe581aa009e74048e38b6062ab89d174a595955168d7d4" },
                { "en-GB", "9fd4781be52dff525b11cc6a36e27a3e5ba4d6357bd45b97106d5f5603c50e48ab4956a71dcf1cc53c7c464deaac482ac49ced96f1d68aeeb80f1c11926a4836" },
                { "en-US", "21e8ccedbc34d97ac5fb9697e9375e659ea0a91423d4a36e7bc281f89f305f5a29c161c4d4a976d4a7ca26db841ace182d9f08868a6fb9192b9c82d57d53148f" },
                { "es-AR", "6534aeeb05c4001c495c7877eba9e0487eab1517c9ed6da9dcf4b0f7c5ec3caaca100e2972170a4e7edbf4c062fbf5f7fa76e85be196c4a2b68bbea2b3c16364" },
                { "es-ES", "cdfa78a2505b0c7719aa0874f43a347e3f863af9d396efd3b0111a401312ee81748f896d858b9966368e3013e718d4f465bc972a9817c97a1aca72746641f886" },
                { "es-MX", "0ba5319c5ab129db9a65392e0ac937cdb46d14aa277c075c33a700e8d8f5939e5653a69f10229539b34384757d5da7a47fd415fbac1eda6a7a4be055d94adced" },
                { "et", "596f7c8d9786a9c2be87c25d8604e9a031f8808050e1b63fb374fd5271251f7519e6c59719d0df87ba68254ba245dc350f6bd3865f747f8abb6d190f9cb8ce40" },
                { "eu", "791be7ebed6d8360ad4d82b727b5bb17cd14c3c7b6b0bf4f8811c4605b32aaf72b6fac752afbcef0ee142bbde48cd5a297a4fd1a06b9e3e19213811f3e05b7c6" },
                { "fi", "3b45d93564869a550ddc5eece52f6bd99323573f8ad3b9abf6535ae85c22426f5ee9c304fc21daa2668485c20df9470aa70899911c12318e79f4d9e1a845f754" },
                { "fr", "bc6092ba6a46d6acdecd0ae2516de43c0c8518125859fb64ca5e9b9a577561ea2598c3aeead911307f747be16196c872da0d0288d7be984a807c2d58af1a1431" },
                { "fy-NL", "79d84c25cb34ea1510e1a2dff6b876c3946a06c639d18ccbf0cbf4ca7899ccc431b263863d436556087f4c4c766ba3b4dd8e5eba24f15326981cebce2f4f6356" },
                { "ga-IE", "a1146cdafcf2465a121132faad0215b7b5774917847ab0ae2c24474514a4b3a4221ec6a7b0a01a9bf2358b04cff7740cd3977c29a105ce2030d01f80e200c96e" },
                { "gd", "68bb5ebf4802ffef4c9bac6f4f193182585dc94625e37fbeeae1f6c716dd17fc732be86f9f1e43120ac4e16e6e99a88d3dd9950e82b827061c419215798b4e32" },
                { "gl", "74c2b53b4cbc099b7e743589c60294b7ff52f452b3c6c84b9baa5db74d0c8c6a47a6d2bb68c6232e6eca3fb045a0bfc949ea696ed94e22511451c48881d0de1b" },
                { "he", "95aee07c57ca482b5054b106efcc863bbe2e7a0fba8a4dcc24c47132ba0eb2e77d24e8bbcd1c7d5a155e06d3b64eaa3a93b404c51dcdbb4b62408cdea11d2c23" },
                { "hr", "cbf89b5685ce0a1fb5282665970f81bd1567f7d40d060d75108e24b81177eca3f645b56256e0540039402ae7947b4468177fd701bab6d4822628baf40be9430a" },
                { "hsb", "efa0d734b03b17b2287ca4bc16e0553a0378d7e30d8dbb9144a335e3e84d50c3109082bf2bb380c37f360badc921cd2b046f7736884bba380fd54d28be8d1166" },
                { "hu", "2065f734f87d2df27cc35b793b6d3d81156f53424324f326526706829be541e068549922ac175abefd2da500c85373875ff817801475553d79aeb8964c3b48eb" },
                { "hy-AM", "47383154e39cb65183859cccfad18886935f47d474ca9a3e1a067a13f615538cb8cff26305b75a509c79e7cd011eb68f94cfa25f4c0b325a276bf1f69caecf00" },
                { "id", "582eee63a33d438aa5e67e3cbba61d5311428ea0825e579e3583fd604438eeb590a58f10b86b72cee71bb9c90f54597e84a530507a2f7bf5fe3be0f7165666a4" },
                { "is", "76c0b82a7d0acc397984e0cd025d63d29b25c4039c8afa34e2d1ae006021f470b2d9bfa2b49ee1004a419b87ca1ca98c571422e30efcdb9cb3c0f61fd3751c9d" },
                { "it", "909fff43e382d8a5fc283601b6e7efb486ccd228088b311e9600891f4994ec85a32c446747298538d8478427795fe5a386b6c21d416d618a429ee8156b1ae29a" },
                { "ja", "f028595a77acd0020c2ac5dcac59b62b0e8cad2341c3742df6b0d0525128aca330d25df853325c2c00716f1c1547bd1454cba309110683456a3faa359b3af091" },
                { "ka", "f697d9e06834175245146c2b2717a38078351fbe72071ba83dacda61eba8e42c0da9b198d8687c9f175625b8e11641ebde54cbb1f995c6729505fc4f03f8949f" },
                { "kab", "3e451978b68933010b0a42d3d71e6a6f49833c946cde3492fe23f52cee86ba548ba3b0f28e6c921686f700e3f6f5133c70f8099fdc15d40ec9e4da6306b852b5" },
                { "kk", "5027fe4d6f31b1d7f1a890ecd725713c559b0c9a4e3361fdbd60dd65e17e2762a12bb980e0a339b67b7aa4a37c4bf694b545b065f08e8f5dbfc834dcebec27e5" },
                { "ko", "7ef27f1daea11717909a319b337e1e1a53b81aa8b3fc9d82f6669e63f41336f15f97db3934b511b58b4ea810630afbd917c5c936b01c2692ec9d2b873bc32333" },
                { "lt", "992de753b85d1ba6cabf6d46d4979cea09fac6c829f06a5fae148a826c643ad956045d05a5dd94d979e80bc2cad43493f4734034a1bbd7ae26801c19b9d0115e" },
                { "lv", "af0e67afb4ee109512fc4949040dc1d6cf4b142e21c98c3160f1210b2ea15388bb7f1a31c50ab1db1ff4d20f9ee0a89166f28d1363674c479779e4c10bbe056b" },
                { "ms", "78c82d7c4bd96fcc7d61a44be791927f53046821f1ffbd0748e85e1081c9a94c10943a7170c9e7f63f82184db1fe28213cf5a13e20375af3a2772c1d1473573d" },
                { "nb-NO", "c610e93938128c468716d15e4c2836bfdd3d2f75ef76156b4853d375c93701e569ddf142abae38725a3a42067bec702f63496a68dbbf0cd07aa6ed02f2668deb" },
                { "nl", "fadd912e021df5f7f070fd9381d66800e5d44bdca151d79cc79752ee5df5352ec762a62a48579356cf636efaf551394e1e27e0c2d91a0ad00c30bc1a01c079c1" },
                { "nn-NO", "bf470d5f43c7fed3c51147221f37865f02e74bdcbf5d1a4bc5a8442a7179604290acfd36cecffd5e6ba4a57b3e0b40a5a5e5721a9f02bc5f35324329a2d38be6" },
                { "pa-IN", "cebec0a5df55e2839cf681ca521a0bdea4b31017a86ad5fb604082ad3b5ba28cf6e1ab138f99397a680c0fa3f560adf5787863c37d627b45085b447ce3e28ca8" },
                { "pl", "84d06005834a679aa94adc3134efeb2e3fa58359a358029abd18786a49b2b6ac2dc541d45db45a4ce7ea26beacdf6220bf8672df00a1cf25c1a0c3ddc9967381" },
                { "pt-BR", "796b1c655df73d62ea9adaa4be1b9884328a0de95cf6abe09d6fb995464e054bf4721442bc704ca5f30996243760a56688b1978790a1117cc36c1126603e3831" },
                { "pt-PT", "8995b3b207ef9136cad4bfe06915a6752fad1fa4393e40239db2a51d208a2f0ea69b4d548a031f1ba1592661ab3e4becb1a1cd4857cca4e59a9f22fc480a41f3" },
                { "rm", "cec84e25450f9eb4c73ca315e9434bbf084fea7bb2992be60d1f31c6ed98186f663a0034e75e67a3b303db9626eb79d243b3da50b454c31b7054a9b9ebbec0e7" },
                { "ro", "f5f0578bfc3f68e2bfc8421f84d0d1b8c30377d4c0af72c3b154c15d47851f7138766ab5e6dae8a75fb5c0288ef4f0df2e4f5a303809a3b8a7dd2f845385ffed" },
                { "ru", "058506e567c151a7447d27735fd29043a3120dae6614bc0b5a6eae3e83482ab72fd224e968d55ecd28d5a446f829317d4fca679a25a24fe7d87953f09bc33dd3" },
                { "sk", "aecc06997e5f231e9d98ee454eec20cb3613e2b8c0eabaac0d383de34d214f44aac5bb9899d7c3d11309e83a1daaca9e950e6a09869705ef434fd31ea1327b7e" },
                { "sl", "b988d2f2034a7e8b25fd28baafe5c31a5d2e501db68c4d2df52f753301b961723e996ea3104f1652070009f3e7212187142d0e0f91f075e080a51c7299de1da9" },
                { "sq", "9fae778a3b2e3a2104f3fc18d20c69e751c38ff86d3dea7e4ccf72b9d0a9cdf2df169b0dcf18bc540140dea5ce558b7c5bc92c5f814cb525a629b740e65b5789" },
                { "sr", "f3c732ba4658adbaee5b3d9abff2777dc06dce875f662b10bcdd0c7dcdeb90d0d2c5c370cfc9fe13f612f1ccdc33af18b2b0d728bfe12cd60126bb99cd998ce8" },
                { "sv-SE", "d13e5bcb1bafcbbfe00aa700ed441633a5ff05eb65bae915cda91992a1b506aefd5d0f09456d262da8e960ce398e3bae91d5a5dc6fb9af74163d2efd95d4e47f" },
                { "th", "f7c79757a5a7a0bd698a593ebcf7966051842aadc9d99f69c271827f83ad9860c32b60743baaf8b14947010003b29aa148d0145a30575f8f37abe42a69ff5960" },
                { "tr", "68b270293095b3c467f4546ba4ef699a6e2f980d716748ed796b5d80f604034bd93b318c60684e34c2299b4c3eb383e1f1b83b337e4328c7b34975bed45e6a84" },
                { "uk", "f67fa6c802a7c14d9229a869cffb3a362e7bdda0c37726f06d17ef3f351f22902faeddefc6e9493ee64c999b687c570032f80b25824c3532411751cf8b520961" },
                { "uz", "0505331f0f5d46e1ef48442350977b632ab3871dc3bc0c7b14374f75028eab82a22f163339fa1c106991656e724f853323108341bad378e59541e1acd9f5388f" },
                { "vi", "3919c4f2a66df8e281f4f95366d966ce5e493e69c6ea3faac94e66ef0c450db165046742e3c842bcf2d0a253f6e75fdb49c3343707f56b63bd5a5750a1d19aa3" },
                { "zh-CN", "aed4809b2235a5889a7b2adcf53c27f616a9f58a2307f89592fdd64124932e37f5a09b5ccfc03328164fb7b4fbc9a386812528daea9de5273ea9aab96adbd241" },
                { "zh-TW", "623af98c980cb69792f35ad2f9d48050de8c2a0c6b7197913633282b9ad1192494cf336fa09d97b7d10c2d19dd38c88e55a0996ba3d52a1567348203a357969c" }
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
