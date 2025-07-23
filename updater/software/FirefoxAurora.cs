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
        private const string currentVersion = "142.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a29fcde642ae301da7bd5c119d516d98deb020a857185e1b205619858b83ec2efeda6f1bbb08e63928e43455169a0f2952a36b1f294efd245790fd872e97777b" },
                { "af", "12a5a24fe31e740d4f0c50969f66a68e89c90f30ebeb2175c2de8f7ff327623974a99b2d4077f166ea5fa5a565cdff2158ce01fa4a94acf184662a73d2447618" },
                { "an", "1bc2100c1b1cc0151448e6c4bdf6ab0c6129ab49d415dc825627e95248b13738d82e999b0838030246cd688103cee3fb3c826cd6a9ef05ecb9d10461ff84739c" },
                { "ar", "5ad4b2ac39544e0b3db9ecf9f4c8e3e385e4e84fe56ba6fd8c0e5bc253cbf2a7ddd80f9450ba762e52ebcbb9cbee98ef43742c1a64efb1c8837007eb547653ba" },
                { "ast", "e58120a1320e69221798e131195310360848386aa5ea9db380c81735749a825354050b789c95cd8fdfe467183d32fec6ba2a2c142c4334ec07aa4f8238686006" },
                { "az", "4b7d9a28b1a4f380ee83345d3b1888b67b861261bcdefae99b2be2c549bbaf5d56651cae5296b2d120c9d68823ec5d26eb0c11e2d337c84805b2e8dda14a1908" },
                { "be", "0022a6e40a29a69b833b43da68bfcd4674793910d8502eb637a530b3a5c5f37de8f14a87024c6cf2989009327864fcf3463f918751d3ebd7a391bc7a08f25319" },
                { "bg", "d643977257d90bba08c052a7b85fb171f1d6875306e66b7a864bebedba1a5c68bb2fa06342b1757a23c9f5825b9c06dd25a721266b04ae313e497a079246022b" },
                { "bn", "577aaccb230c55a59ff18e9913fc991b15e6f4fe1c4bd7bbb921d872045ccdf0f1bf97a2d3134af85bbdc42fa5b5b0865723d3df9f237690d1c4a8271d8588e6" },
                { "br", "fbd73b540e5019dd9496b406e424fd34b1b09ffd27c54d22ad7968ecb6950c54f5f474f884fa26960ce3786722235204b0227564796fe9e2740ab17d72b197b7" },
                { "bs", "a435ab495bfc66be418aa7fbdbb24fc9037ed9f09ee3078299ca28b64391cf14f41dbc4a4e16d93c4c9a234b89ade51c52c0cc3e8b2ce9962c6c1ada68a89a5b" },
                { "ca", "9fbd807579b8c0a25da40d347b7f343712c8d748d0c87981ba69abd16237b10f1f8c3bc54cb43255a34017f8e2a84688e2c004d617623004a74ad8685a8f40a4" },
                { "cak", "7c972c4a903fc716ff53c686f34943d7be1eb68fe65248a8d151dba1e3a158842a5589a7f9462759179816841475d5ee5bf722a41265888d661dc5ba513d1ac1" },
                { "cs", "e42cf6f0cb0beb61cd5176cf6cb16e18cc4a37a89eea26e9d285616b40887af40bc04a160498cb893ddc06ad3e0b37a753b17c7caf142f5306d59605e4bd6063" },
                { "cy", "5c5da7e51f16838811a9e6d36baabb4eddf68b6fed2587030d048680a54d215bec1fb882a9743b1c571d14ca05df0e21d04f84f9ab1abd561ff2d1b7fe969b44" },
                { "da", "8e9fdb99e649047ebc1888c8dac8c6bebc5d80e7f06aa7eeb75692c7fc16b65eb02fe5cd1af187aea012a6256b16cf9a77f6be597d56a02eb7b3b2923c0540f0" },
                { "de", "2eebbc8a1e8c2c415588223c86e6763268e0a85fff5718e0cdbd056081db3c5fa8adc557b3a894744054badd591fa55d4afc845da64e474e31292b77c4cdd976" },
                { "dsb", "27417c79da76dea3e1568e0a6776047a6e63802e0fdb845f6f0b66668343767e3a83c125100009aa41748a46d47e90e27d36ba83321cc6dc21fb0d88379862d3" },
                { "el", "ee16146dc2398c10e4979f7426c8c388b330180646d7c84511fa692658ce8efaacbf981ba261a60e298bbf27a680e804ca8a435e79e55e05841d7fa40b752a88" },
                { "en-CA", "4107acec4edb5c06be46538d4fbc61062c67b9c2d56f437c23cb46012f9f8ccfa89f168d19e9a1c8f18f03e526d40b610b59004da0773e6ffb47e477ba87d327" },
                { "en-GB", "cffe21d662c07429cafcf0e1ee509868b20d9f86d2afae08f7b6fd6295238ddfb3e32c92ab2fe605d1481718f02f8165245a76cfa96be0955ffcff41044b2701" },
                { "en-US", "aca0027f2d2acde199e3a67b6c434ebab243ced2f4453af1b7c439930bd277f37fe9d56dc526e859aa8fe77742878369fdefcb412511e561a960fda848427288" },
                { "eo", "b50ec5b66eabe6c9fe74995c0446c0be095274e2d2001d98893899d5d0ab8e4a6279fb64f3d55dd7e236486e580c843fc98a5e0c258599c72400750d53ad643a" },
                { "es-AR", "a4f4582e326e56b30681e7704f1e7f310371691d13400331a14f495961c3d47031f2eba1ea13f072e23cd72a6c2df92b8b3060ed142fcf532669890864fcc3be" },
                { "es-CL", "9fded717c1a1909ed891570d755f4c753cb8598a5a963650fb1651293c9bef8b620a012228b01e5811b7d7574e4873f47ff7c84bb4dc8a332f6ec212d0055e42" },
                { "es-ES", "128768c8955eb467fe4abba06dfab1c716be4642c56a22e061b5d36c43e1871161d263c52b26f898e7a10f918f283968d77c6617ff98594fa48b59e996c84b9d" },
                { "es-MX", "503026aaa501a0d7ffac4c352a0ec3d4720acceb29636351a26d2c8de900fbdf2911f53272cb34a70e6ed861ca51d4a431efe764b6df1e1b4f051d334bee3692" },
                { "et", "f11d8a1ff994b4810050f046bcc6b2dbb146c0f5d84a1b3ce6dad42b143b8146e88bdcd5e7bab8ce0f33426e9a4296795e20321e091302539a79c37fbdbef2a2" },
                { "eu", "aa5d867f4fc97b05cb9563f0ea657887604bc08856618ec86a710d028d1d07608a91883c5e6bad2415dc1b711a961baea99a628591945033b2fc943a5b8ceac0" },
                { "fa", "9736bdb89b5804bdea9d3699fee59dcd6dd06c977e920055522a8b0847f27aa24d6a3aaf0b0d2da46044047ba384c22399951b5554c40dc52a10fb7214e69e7a" },
                { "ff", "763cd802899533ddd72a9e499906b98a42d7382200a8798a8761923a375c5b478694ee0a5bb176aa63dc74d7e5409f1a5fe1ff620b42be96e109e6e0e8098f6e" },
                { "fi", "dfe89b553ee45783b558030f9727dc2126a2236e0f0c6be85f7ad7035bbd33c4101fa28a9cf8f794892b2113958b1c72e731816cca03353ab2e3b1fe4043a2e8" },
                { "fr", "12d20793c6cd575aceac32169284e31cba004c4adf3f0d546f011816b8dc86b51e06a90969855564d81114f3747af8ac84c733c081ccb8a7078a9308ad0cba15" },
                { "fur", "e4622fc8cd844cffed00f7132df5a04671149d1c878bf5710239a879688747084ee87cfaaddd25abed99efe493622c908f9e96888c4dd975ea1418ede8ac17c7" },
                { "fy-NL", "7325bb54a809aa316dd8069819658cb6e3d8ebc50eb5e2aac6121d0c7a3446806ed0d43767d7f0ff46ba83f74a401d9eb65790bc487975bf684d612fb532cf8e" },
                { "ga-IE", "92e608db08b7d89c89c45f48b8dd5e667a7b1105d5988ac0095e3ca509c11c206a7d214e5890581355eff580518911099317933e8f6f58cbb5f204f76c0bf7b5" },
                { "gd", "9211eb52e390767c666e9e7251553f0f75a200b48fc9f614d62d07961737649bb0e36fcf83c81e56929744a315186942e9ce813744327c9d8c43b69ad0c608f1" },
                { "gl", "90de0de37892513bb7600c270247da035c74101a48a976f197ca974af284a4ea2b1b0d096206261b789ca6e18b80349d3bf399ff05d472bf717360fc58720c27" },
                { "gn", "2b513115adc40efc6459a020f62e053f42c54e102c6752ff63d566bcf52f5c1af03ea022b4e0831f5b1b419548f8bf6f476b8c6c97f1b22835a065350687f16d" },
                { "gu-IN", "062bcf9d94ba1e1290041fa4a7a0b42d01d014ac3814417fe7ae34714374812e32d44d18c04a34e42162301e9214eb87f622c09ade8b78ac2b88fb6cfb1a1514" },
                { "he", "7f253f3ccba35ba8fd2b2dbff3258eae17e69d71c6bf3586df9cf03477c3cabea0135f1742f32d50604c3401c2f5020ed003f002fb06e7172842cfffa2aaacbd" },
                { "hi-IN", "71572cd7e5bbd89a131e5e096a02d292f5ffb3b521e9e7f26de953a1c1bbfbd5e9400fc3167467f933894523123f108846ba00d8ee1d50d6858b304f51448076" },
                { "hr", "83a0ac7880cb35193a133def2ea5d02a33b814ffae6015ce055c45ff1f9957f5fd93b5c79cd30805594b1b3dba7d791c5840fc531da350357c9a2e769d6a6f14" },
                { "hsb", "c1b7ec2acce6169b70ce25065ee07643aa707af76dc6d3e6e8aafebb704a86ec35a3f960e6bc36334d8b47f9f88bb81022ca53f3abb38b08961c6c72a5721834" },
                { "hu", "c3244b9fc59f5e8bd4f94acf9b69d99d8d4d106a473e5b457a8df41ed682c5481f8e0e8cb689c8b803503d25b8b5710ab3507fed6a4b36ed5732501042331ee5" },
                { "hy-AM", "bbb6315eedc59638501cb561122353cfc5ecb52b7a44ec909c70d0b28e317ff4f7645054778cc3004a662a71874a6482bf6f2565252af84c35880e5bc321da92" },
                { "ia", "41818b483f6d464126e0a24d53d506729487f5d35c3f57b3988916622583842d1381dc103cc3bff68b813d41b534f5529b8f79648e28faedf795657b1c0e56f5" },
                { "id", "fee43bfadf6761d436e8b08809381d3caa38091196f8a369d1e5882adb721d5a153d79d8722441412374d0ee23c9a46f1eec2d9e9ca6747251194a2908e5391a" },
                { "is", "c36c432ee76ffa0410d687f0c808c8bd79a395580efef054de6e12da5b17a632299e50693ad9e5e7b42e6415a70892b11ead4b075b92f73cc09b80b10ee2031d" },
                { "it", "74a571128b3cc77a3f743c5b7c3cb914d24c9e41b7e6338cd50e22d2cf13c64ba222f124112c06d355352a89a3d1a62e1d8c9f02381ab4a512c9c61d4e2ec0c7" },
                { "ja", "69b4425213a9cd504b65858f0421773311130da24613f9b12cb73dbcff2ae108b2344995440989296e235addac35e3e3b9b906965563ae3ea608ffe4b831b6f5" },
                { "ka", "05ecfbcccb4cb68c74ee2ead2ccef1c0ce193a35915bc0c1236d4ec91b47cf5a65680f9209a22ef6044e2529e18dd62c42181fc178a8fd61432066656d557289" },
                { "kab", "8593aa5bcfb163cccc775891df27c7579706e78bbf1813f29b04b2006be31ff249f839426d025335292f6b7eba856beb580089aadc14a14e020712c256c18d76" },
                { "kk", "79d004f8d809014182f1e30d86c35bff886c36a6898c7cd6c138fbe12f30037b67e2bd9347efd6cf23da3cc7da2bdbf8496ff7ed16c977c47551ab620acdaf93" },
                { "km", "f86f36f267ccf556f3fed0ceadef5fa72bd459c9224b08167eca0099ed31876b1d27c0d2211346a3c21a4639df4669f1f798e723451bfb14ad5644a6ef8e66c6" },
                { "kn", "d0ea13426d96fd216a17154226a5739d38ebe233f2521c60eaf4d128e64508f03278074dfcd32192f7f8c2a2c8e285ade8f67833eb671ae54d4f6156f9800392" },
                { "ko", "26f9fde81cb0562ea6d5dbde6cfc6a34c162bb1185f1efd28a12f03c6dc55dc5f51f77191bc1859a37eb58c84d0f5867865f8b06e6fe8ce1117239ef3358efc8" },
                { "lij", "d7a56eba32d8f72235b26e005f6c1372fd8fa6679471fd4dcf4033ee30508e9bb12511c0b41d1f018bcc5a39a72ce6c41f208035cf8caccf1d866c57605cd769" },
                { "lt", "4ee3cbee218c948fe70af5d0a66a19a9695de6340765b8367a4410434ee69b9c8cefcad962c3acbadd3b53c21af8fe20ee4bddac85bbf82f71561b5f1f30326d" },
                { "lv", "e6faab5405542ea40c6d8cd7d902bc97120ed6c4d082c49fd4c55c795fa9cb4f03f31ce20f451649e7134d8d706f5f45740e2d8ec6aae41c8ac4a68fd262b416" },
                { "mk", "d76dbca409b2f91c24923d9bc1051b62e2ded880d6219e0d0e0f214a4f7242bfb544ed4bc26b8a58bb9b56e55128bf2f20d36566e5f6f66c53bba89233ad4468" },
                { "mr", "44977e70f5b6324e52cca0518c4870a3ec122f78bfbbea7f4ce29d0b2a22668970baa4e44aa7447f9b9e148e2e36e93ecc3c1818a3a6c46b066277cb0dca419e" },
                { "ms", "566bc0aa7f6e4d216ca6e505be16efd4f8097cbdbc49582a44f73fdc6b41f18af6690180f4261c5a5e26557a0cd5b854a073485468b4016add2e0e11e5cd79b1" },
                { "my", "5799b591c9e53be2c4fd124bd36c359f6e7d2912c686f3df4ac6c08d814a9339a4195c7627c7d6bc36c475609f1c6db0b9fc2d7c3184c60cd251218618996a46" },
                { "nb-NO", "2ecf3189a9d6eb409d4ca19ce841ebe54ec45d0a9461128e946346825a8d956c5904e806a6ff83d185a656fac482cc546536dcd0aa9e641d39f29ede29ebd71f" },
                { "ne-NP", "f0735f37d5d49d22db02ab70c1fff8192c81013781fd45957602e2f3c7355f9eab7e6b8188ff97b388b5c55ea422224e1467debb5ae826ff599d429740406e94" },
                { "nl", "a49f88bc8f7df8aa39fe9dab4b5e6dd6731c21348e258633f791f8b7cba7cedb98b702534220ba23541d63fbe622fcaef93b74f31a9f5c5b82d69019f9aec1d7" },
                { "nn-NO", "67473bb27eb203b30b55bae363a4ef3d959140d5d40ea9f489671e15f5111c2be770e0bdc44630904f3f80f6fab01069eee9816622b754b0971478181dd4815c" },
                { "oc", "66d3e64794f5752aae294ebf8f4bb37247637ff27833358eb7e635c07ea7725f9f01a523d95049203eb32ce8e4d99b56f6a6966a7e244532fe257079fd7625a1" },
                { "pa-IN", "de5e8c5190c9b5964146466f22f12b2eed7934aa9d12f7f8abcbd523f5150ce9bc6dbc321efaaf60f9235feae924ab0d7ca5b57c992355b089f6b5a15fe2d3c0" },
                { "pl", "3d30d23ddd2b916addeab625a1f500ff7f3d25797907177739fede0917bd113cd9dd2e4b7608c5af8e2e2aa27a1323b77ecff03927bc2d8bb6bbb2d73db2b6f6" },
                { "pt-BR", "b0144b6162fa932de351bbeeb32dbb9eca1a24ede2d431982b2e126f15b36753040b8cdf68639b91bb6839389b5a23deaa50c9eeebc1cb5cca46093a6dc46e9a" },
                { "pt-PT", "db08fd2e2bf546fc6ad1b2d0e22c67b3b65f577a714d958bf07331f353ae691f51a622e46e24b99d2f4710b0a7dfa8cf518f2fbb91186440b58c5fd45ffb1eff" },
                { "rm", "765113e9d5d61f77bd4eee1de00132aa0e8c1dd56c8a188d51ce418afc9d3571cb5d7b1124e528d35a9e4ede5fad3c383a864166e0c5fbbcd5702626832990e4" },
                { "ro", "54c5c2afeadca1a2594d08947fd6a96c2bac06a58eac1faedc6bf3b4fb7e6a511834e5d26f1ba95939b75b645d06b1a83a72adb311d57ee3c48812cf5a2dae79" },
                { "ru", "e806db7cc6ad40deae36aaf7a8b8bad51fe250565a19aeff6432d247595164479aa5fb880f83dc2ed5eaab327411d6a4a01ec07833aab0c65899a396d8c0ad5a" },
                { "sat", "a64dd201ce908ad893c02979ba14267f8512065c420bf546baecd8aae33c3638904277f60220be22076c0c54de448a0a06af46b8fc2ba6c42fa0d9e6cb68b1d9" },
                { "sc", "fb53f85c26b39a8931bf4273a15f12a3aed57fd46b91a00c1db61fb3e2d15c2221315f6f14365498c85080c994fb32babcb2e5b50e03d1ae412bd9c8380edc3a" },
                { "sco", "c1ffdfd42d6236ed88305d936d636fb9036519843b51ca1072910826bd786c890d6e26c04da6eccbc683b78877d6480ab4ab8803e836248f2658e24b065ad28b" },
                { "si", "fa10563994d881daf6ba6a8170e98e9d2ecab63356c0a95fd9f21b7f83de77517b06268368fd8911ecffce3a18e6083450ecd3379a146153dca5ebbc02f82cd1" },
                { "sk", "273e951cb900073acd1a17e078562c53ba9df9bdeba1598a2320840368acba15ef360d11208194cd2df9d6bd11b42a585a54ad760c449da792bf05e0ac7b6788" },
                { "skr", "2313fdce1ad478ae874e3ef4cf6f99f72ef4d4b6d18b37d49b1e456357c498744f5933cd2805463570c2606794d3458963bdbc701b34ede12145aec9ba53104e" },
                { "sl", "29d461de4e0bdb6f40867365db51d0da71502c876af8914911f9430c77d57151b1cb7540018917eb8a5523d9f5a9c6d045adfc9b0c5fc08fcaaaa1dc899f6a44" },
                { "son", "4ce104632740cf17af18feacbfa9afb27e00fb7c8556f03e07151e4544c6909f4281c48363cff76eb04c130b2f460b22760d55446426f449a12f5d292b8d6660" },
                { "sq", "0c697baf005decc1b476e77310a6cfedc095f5bb1a7385852c25f0b0423ab79c96dcb0641ad8b310d1a15b199c0a1de5f7c17400933ceaf3a30d3b98f5429020" },
                { "sr", "d57b30d935dd7408efee8ad4f979db28faa9c2b9038b8cf69237935276985774e1435ec54740ebcd42b404356b12020efe44fc047407fa5aa5555c7d0a69dd80" },
                { "sv-SE", "465ba7b177dafd6745635884e8aec8b323d98ce36c524e2ec602d4b9e56ecc5b50eb7edc70ec89031937c5ab2e7196aa720612e1ca53bbedc3895dd066dffe61" },
                { "szl", "341722bd304b1fad03122b3801793894f22567521c6024d78532f331f90d9237947bb589b0dd6a5a00ce86194ccaef815f63966f548b8534d3710ba3e8bf0f32" },
                { "ta", "f56e2ac94a7eeca34b161a8c7fbdb7fa25383eb299c0339870a814b0a69ef241abf0b917bfc8c3183154bcd2b375b5e15cd825054afc6c54e18773e2ddbefc0a" },
                { "te", "159d432bbead5d4e04fcb014d39668817c05d42c56af11bfd79a38930296231e55ed149c59e5469f9cef5caf4c098ae9073e30d8fb504f398ec58bee3a2e19ca" },
                { "tg", "b261ac4c550f2f2b5f850a07bea73a749447687e8231a1133be2368bee9b7723fdb89b46b8d078b73881a62b1e6e58e75426a9ce3c16c36518d5d44bb5251b29" },
                { "th", "d1704e1705c802e03d4acdb4d35fce77186679efc587d0a39149e578df072e6e9af3b40742d334550008fd4c6e07878e576c487dd5b41dabad564c6628fd014b" },
                { "tl", "0ad7f578488413248fa1816dc3e5cfcbeae5630dacb5f57c0176be544c992fee4a6e90d4ef6b782e8043373576e0f733905caead9b749771540e40ad219e377c" },
                { "tr", "7d9904187f271c94bb601f2570a70fbf714bbbd0cc1ec09fd0c0518f2a446d2e77b8762fd865b12446f46b0514cce978559b8251b696469b4c6a0a79685105bb" },
                { "trs", "143aa0dd5bd3b8943258c45a4b7b079e97817e541adbd0d18044fd98f414197315191ec853d3ddfa50bcc07cbdcc016e00afb895657d764d8ba98d9a4fe6881b" },
                { "uk", "1b733c293ffe67878d774d37a12b1a6b457970dcb0ecad070afca1c6846f679311a1b651d615c1786b9c15c98dddc632ead331cce07923667c2674cf50bb11bf" },
                { "ur", "415a48acf2c493e885858cfb9003406499571ac0d9ca4cbdfa05f7ce9c854d208792b20bb470df33c0ed560936aae9cd5d71862ba09c12357f2ff22f4d04b0b6" },
                { "uz", "94cf1e322db1b056d713425622e4b0c4684593f0d21ae41edb75c5fb59d59bb4f565d60fadd4bf7e35c3256a4bcf4a84acfc29019c8b00ab578f822be520092c" },
                { "vi", "3680c50daf93c3e036ff5265183771d29750599ad1aaba35a95a606a9cd11153c2fb22f060c25af82391821f0ec4589959767e0b92ca2a2af4a6a7c263b4f29d" },
                { "xh", "736848769d32a4666f220361a14973015cf82a71d1d8a4fef3d757553d57306fa189875f7b73ded1e88b5caa00f57402273e67635507e89a4f4a0af438da21bd" },
                { "zh-CN", "fa2d3ed05a7daeff24b55e5264d19d00cb5c7b704c67f25e70c4c7f58cb09744955cea4862fa2a922c610b454d7bb60b1acbcfffec4529c1403130092c74a329" },
                { "zh-TW", "93395bceef7aa91b90cb24202f7c7d7db6f71e1f25f60a94d60e8de9cd5bf660c8200b6c19cceb39b62723ab7bb88cb385a9fecce67a61df7f6ec723d506e290" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6ed92bffbfed38528fbdbfdb8aa2a5831aafb33af4ecf9166d111ab9ad4bce547d61f1abe878945b489901c8119fcd1fd3614b6d01080eabedb4ee8a860c823b" },
                { "af", "3e7976e3124335dfae52f8bb8e7794ccd82dbff7812e783aa797eb92ee17b8492f5b3dd47aad08e14b80e925b57d6a63cf1128160461e3f50c8c161c9e16908d" },
                { "an", "c5ce4009136ee4584581c233ec7dd57aabc02146f7f933b5fad8d26405bb87e6d4f0b888c7da10100b31e0ccbee41b91c3e15753465c926e1fa77cc3fbde8971" },
                { "ar", "02f65d5c07e63b0160df9d6e7fc5247d6a1444fa400a0b3095abe27b4e410a0971d5431bde2944ef6f6041ecbb2829a033ae91ff54bdd20bb4bba2a8ba8bd10c" },
                { "ast", "eef179d0e65050e23779b1df62e2a8189cc2e6958087faec2b1002e2de28ca87965640f156652b389112be090b56ff88771057eaab3d63a2cfbbb59bcf9bd131" },
                { "az", "f38cf73433611894f3b696effd730c73b6338e734ffc4b66ae25dbb3ba3b965c654ba292cc39c288baf102786ffd59e772c59445cbf045f79cda9c2bf908cc2f" },
                { "be", "1e0d738e60a30958fbbb78c35d46d5f5111e79be3cfa4bd7fa20f8e499d97935f23e8a0d7e1562693eee4b4b3269091c0ec5962aa96e1fb5aa73c3c9ca1ee182" },
                { "bg", "161596e3bd5334a31322115b61ceb18a6a2622dcd9267720e1154e0e77f3a26774b6195aa0a5adab7112c846bf9713a60decdb2e9ba011e78a7cb91671330f64" },
                { "bn", "a5a849f44e1c54c0634ac7f02cbe460be3f83586a7b3f32cce801ff20b7dfd1bafbd32754a11ae0560af70063aab5f6d4b8ddc2565121960111fbc678ec4da66" },
                { "br", "e3c5296f83ad5b379fe0c839bd460ac9cbbf80f6f1cf66b5e86137bb0db4118e95f33ed53edd0482abfe91c2f016dc43b5348c0eadcc6e96deb312764219b44a" },
                { "bs", "363ae2ea88fd3c07cde11f65c12c54a679af6a16b05dbcc9e84f8a5b1a1350389648d040e53e0c82bb6ce167e3992ebc304fcf76323f05c14c2154cae6a3e426" },
                { "ca", "c5e364b0e1867c3cfaff78636f33ee4e2659119994a9da0dbcb8f90e82827ba0a44f84c1da3154c83db73f13d8c1611781836929f3a17a7dac4d07025a3d2911" },
                { "cak", "25f701d4acf9bcfea4e70e5e0e6c9bd79f1d6c5f45a012249e2a09e8d9d7556bf848c6d9ad54cc0222d0077661259baf8f811c84742235344d37907181224241" },
                { "cs", "8d0ae00e22af6f6eb5ecd0054301541e39f0b4e326d0a920297cce8a65db78747509df5109f4c3e004d95a8a759f723fc31b224bef8574a6086b4ba019a4bc0e" },
                { "cy", "aad863fe02f367ef2174bcfc26115ee8524b26b10282c01217ca8a66ada55c9eaa4518f451a0b5a9433c19c568c5e1dff10076ff3de2f5b6b1a0fc0f9459555d" },
                { "da", "1aeae46a5ec37d208ccc72b981999cfd9c6085a624ede02fca13b25cc09af394dcfd28ae513e486c38d67a68dc29e7f1a645f738e8fc407d9b3132a735e4eb96" },
                { "de", "083f7c733b1985f80febce682464bc3870094cdc5cdd1c67ce40aeee2357ba55619044d7d96a4bafef9a2edb24336a35d58a2f6ca872ecef1d05ad5425e7830f" },
                { "dsb", "501bb12aa75184511c7989b9836343d7e048fa2f6c23a31da617048f9c1b09ceaa9bb5961fa65012f81c0cc4287680ffeb74143877bc53739f5bd28c08c0fe95" },
                { "el", "bc378bd93f039ad25eb48337615b79b3877990d64e8314b327e18df0658dd267d50801f381c71ca7457f209792e7cafc8dab1e53ddc5450fdcf6a22b9bfddb0d" },
                { "en-CA", "7bb4a1a7e825c35549873522ca0001b819984d088b53d13f83a3ce1a67538a93e64310e73c9f58c29988873003fe8babbf1120f97d2a42f0042b8e202aae48da" },
                { "en-GB", "2a5ad98b58b654d45b7475f99e67e19213bd71db27fa40e866d59b32d7a6abb8281da4026231b2f73bcbddf46465cc578a5f109d6a6b90268cc9100e04b08d0e" },
                { "en-US", "de41ebf055b0bd6cde23cab2a62e8ac44bda7d91458b16adfe8bb4b31ebbfd9a65174bbfaf7d2d217810eb69a3dab83efa862775113a59c2dfdeef97226ce204" },
                { "eo", "a6949af232e37fc0522f99afa609697f31bc149cd213e57f665a6f37f4d7d5837685ffcff6f7c7ed0e7c6f793107bc2ce0fb81b3d13a6bf8c828b20ca0f6c738" },
                { "es-AR", "0bea72afef6e92c2caae3a1c5da712ecd8da9e850ef52fcbbdabd41aa20cb404fe26bced9472119e2959daca8012d4d8dd1900588653f08204cedab8a9383488" },
                { "es-CL", "330451c3ea9c9a6dd8e7a7f001dff5e8678657e643535184a4c695fc224f7aecfe94900f7c5d7635fc6b13a17774464c5fbdccce9d3f632b14265290f008734a" },
                { "es-ES", "cfc1245f805e1773d4c78abb75e89aa650df718a1c37dcd6ea1f4fabfe5f9d117ffda909a310f8f9293b5ba1e506b6085cea5065b191f6ed4107067b9ba1e3ff" },
                { "es-MX", "c80eef408e0786263438b68697d34715a00e486ade805428b3d6b6b94b5d6aebceddf80dc6ca4018eb20fe4cf429371160ebb449b0709eae312a8fade3897041" },
                { "et", "b28fd1632fd911973a17ed3eb812fd9eb0400184f134c9e3d7fea5ed112e328e57fef6a3ce8d959afaf0d7ddb56fac8645482698a84f03e15c57f03cdfdb9e82" },
                { "eu", "1cb39272bd4a65059165d9c4b5425d5e1de4d4e8fbe7effac7c43fc943d61e0a84890a760809c1ef32ebc3eece98fd91ab96534e09ce35f750393d3e01c53785" },
                { "fa", "6645f8df55e993f1da9c39c7e520785e4c657a7c0e62ed83b9a3b57a0161c998c1b29c24f06ff867d010c2c10cbc9f19f61ebe6509543c1d61ae33ce1901405c" },
                { "ff", "192a495de63a927c485d7c4cfe1857f0ec4958f3c4805d736ee3b6d5fda840f360d7447df804b522fb0ba01f6177633213ca7a136e623e2576433a0bf9265876" },
                { "fi", "fa1bb4a50f46ac0fbe079745c002cc31472e4478a238e558cc86257abb32f693e31abdbafd5b6d9b31a4a7e5b7331cd3874ef37b6c6c7f4a877a23f47b13e21d" },
                { "fr", "968d6f6c05b1c4685547a1232e77ebe1abf17480b7a7c86c86c915a2a39420e7ad1a74b70eb6d23dd0e2113cdf190d1f67d7a3910702066ddf0b3d63b7647bbb" },
                { "fur", "71c71b108d50a11fde4f1edac074883e930d40710a2e5c3d6039d606910cb0a6b3fc9edfd583452372edbdfa8a231cc1860d4e792a95168607534cb6a95fabe3" },
                { "fy-NL", "7aad6924ec61d8f5db5523e48fabdb4d5487e9f9c6b66f10c098ba0bf5c7c8b3d9d5020bacf25b41593968d91ef1d9b76e3e89d2a056f8185defc7d381cbc08d" },
                { "ga-IE", "348190da258dc2060c490cd568472e9aa67af7003e5fb9d64e96ce72df647fb76801821bc17354112c18deeb1083442f737bfbe5aaf5279677160ad6fde78dd9" },
                { "gd", "72fe28dcb0efe1c6e3c38fded433bf2757852ca4605643c222b9178da02c6ab51150830e428a84b44771f91c276758875d6ba404a866d55a7171f94e2ce91e4d" },
                { "gl", "50867e2f17bf829e498f59d7c4a484a064c532cbaddb0fc2b3b42d27ceb7548c87f37f461436758a328026363e747cb13b5f26836da96b133309104552a0ce14" },
                { "gn", "8392d4533e0a1539fc9b94549e0fd907c798415f1afada9490813634477e34aa139e8b379f3f192e33db2ddcf3be3d1ef29895adae01989ae62321b49e790d23" },
                { "gu-IN", "98ff6e4df63a07bf9d470087ef96dabd9bc0a8da13b3563b18feff9328168df27c4b85394bd6bbb072e58000a07afd14757dc8f544fef4867a759849fc3b5fb6" },
                { "he", "c45cf99f6c66f4b2b2095c06d51212e4e5b954a3c12ea4a33f92eb414961d47b208743fb248a8df156be35b6ab75212d738c1677757bcd77dcda342b79a73ce4" },
                { "hi-IN", "bcbeed12a19c61f141b5591163d8065126efc0d9007b4a3d32419fafc9629d186a6535a1ed39497b0f707c52f70df040ca9a78c789c54507a4f54bf35ade70d8" },
                { "hr", "c1bf83a29b347c77c8c3751d01ec9bd04d2e8510695ce599e490429e6af306f5310ff39ee1c22ed0fe9799930a217771f67acd86e54c67ec5776d61cb9067f11" },
                { "hsb", "c349ac0bd1c1b5a6e2ee247633b8142e3d344f67e027e6c79c8ec239d8d3efde69dd5c5fad897acbfbbaa6e5fc666083197da536538d4e8944b505e6b76abc77" },
                { "hu", "6f14fd3bb3a0849f450004dfce4b5824f21071f21729af26f5c0a69037d5f4f22c7e37e3caa9704a148ff573ce15c754188f83aca979fb80f55649f834a9a300" },
                { "hy-AM", "dfe7f2cca0c93cd5e640497d18cb250bf76952c0635e30de39ed8a61e35ee521cd0fa85ac2473d71c40172d4061587c1fec5956ac3693057bf9207c525a4dd15" },
                { "ia", "2a4fdce21393425b3b8c978ebfc0958b5071a6d6657413f17157e9fddb83dc9deca8d80e30705af86c037bba9d16a30117a8088ee5c6d0aaef2624b788c53162" },
                { "id", "9c8d56999de711d11f4a784a2db2af91fe2dc3bf650d5ac9e1a7a3d34e5eaf809758e0f25c9ac11d45e1cecb9b48dbe99f2c723a795adea214f6c0c1c59f3a4f" },
                { "is", "dfc59195fb3a633e52883e40ebc1bdad2957ca097f5d9231edc56b6f5442b112dd405678329310f0c3e278320cfc328562e3e241304f0585de090ad436c1ea1e" },
                { "it", "1856235ea4761da35234b89bbf9dbf435ac83557e5e8876460878ecc2db4457107bed2667e0253c216d13cd0d42a2007493c661c2a0007ccb58343b6549ceb1e" },
                { "ja", "ff2be80a91811b0c4249332bc0c2a0be804853560f01482d83d8acac61b3a7cb941e60d0eee51fd23bf785d9bc3c2c632965b64651a4ed94b8f8e3b36c74547c" },
                { "ka", "eb7ffad60e71c9a5a2d1c31d40bc21fdcec15eb6d81e6a39a561aeecb986c4332aa5920bce99a94d8384332c7d762c2f99459179c47f39b17f8411694fb4a322" },
                { "kab", "30e57f66b99fd87dc051c36974c897268f9ab59307c4356cfdb9a9b4c5892fba8110f5eeb56c8c197da4b7f783cea09a57276c2c317d99c150ec6a79e8257d60" },
                { "kk", "6383b23c0a81a7ceb3131be3430adf69f92d475e27f559a1e136bb253ebd92bf10931dca3a207b57f01d220dc35c7314026b0ee9141c5256321796028593c806" },
                { "km", "cb7e1a7edff36d1a33edef6a9c0e04af1af48c25585461f279d3f6ee4a8bbab76987263f6d3a1b61b4387231e2470fdc1d392e80c26794c19ce169bca1a983a3" },
                { "kn", "20f6e6a14addb7c2124d587e035338058a93a8d74ec11dfd79df488b9a7dc780e4a83329f28373c1d96fdb66bd82951d490e2fd71c98afd2ebc055fa1e662a2a" },
                { "ko", "cba7f81c741c2fbc0e1de3328c30c0bdbc90243687fcaddc728bb710cf3412fd79c9cffc191d754b5d7b47c93546b8912bab7e74dc8e5fa906f367d301d34908" },
                { "lij", "e3810a329bb7106a961e21421bbc7555f8ebd64d667c275f640b0edfccf73130b8ef3730c6c0466c654d857184aafa590812552e907eb43803a8feead54633e8" },
                { "lt", "2f3b0454a501dc5c229ce00a4b77612ac01cc418a58bb12e938a6327e6a8519eb2c3d257d5ab8bb84ae9c1fcd7224e93455e0573672b156e0ce466a13d5c6bc6" },
                { "lv", "27d5806341d8c08b452cc38f9090176432c9b784f87e28d5face8cfc484c1dff222146c4666a292b6114dba69f80a653df4955441347fd7f23fc16f69c4d5d72" },
                { "mk", "076b87229ea90f7e94019828e4398f0da0e0225635481d6c5474cf99a6fc45fc54663c61fccbb6b8fb4e313fcda091fc2e025d618c7b1c7b96d7b86cfbacfe34" },
                { "mr", "1eb2a3bbeee45a54023ec7a70a29a8d39687a9ac9d53dd59745752ecb35991d519506a879c41689bcc85d61db529bf72882ddb87f1ace76a077c01d2d25db193" },
                { "ms", "1f9fd3136ce3f469be3fdd1344250568fa0067665570b206a2ed64e4a9eece5910044789beeb8f1e5569ac034b174685d3e2d4eba181bbd5a18e6f7f044f8e17" },
                { "my", "9e104b089ece5c8c3961752ffa520b24329354445ade09b2b21c34284227ab18d0ae74cbaa43f430bac0e3ab323dfee5aa98a9b72ff438e23ca10219acdf9a06" },
                { "nb-NO", "df180291243aa5d4063d9de938cdd01bc73f5c8eecb459056c7e4c526f40caf6eff468dab44f893beac25f861ca6a1cc13d33a55902c1da392c3ac7ab1cea964" },
                { "ne-NP", "e58d502039efddb44a5e04ecc9602b65a516d1d01909faba619061def9e05bb79336ef1e25b7511f8161ad832c01865fb1597415f40d4c5733623bdc80d689c0" },
                { "nl", "2f782e9141348777f1623c90009190b038bacc904b9cf5e922bdb444b95e26d3922eb9ecdf0b1b4147548a17b8a860842f84445cd32c148993c20f058abf423f" },
                { "nn-NO", "1c6418b81768dbf4b4f5d75a09486376121cd8d5312167a2164627a7f1055cf499d1cb37243450de06bd4c0c8fab955177008c15b9cfdfe36c9de195277b923a" },
                { "oc", "89d77f212ceee27cd1b7851cb67812cbee97ddbd68132572c47053c4320ff299f4a25bc3cd9399e077630b81e1763697bfa2290f5cd14469a81c70fc9d0a2266" },
                { "pa-IN", "069978dbf5caa0a34c21ae47aaf238ce429b335b43609502001e447cb473c1dabf44ff7ba94e9a022e036ae026df5dd091622f81c4ff78ec73584f831eae3ca6" },
                { "pl", "051872a0c2285ab617a1ba78c54585f7a71c8e62c5d1a60b2ead3d653292379f92c8e0a61be5dba926227cff7d072fbeb821141c8976a33bcf2c40237124354f" },
                { "pt-BR", "0c5b3545ee98a34f0537584cffd3c8f9149a99962b87597bcea5be476a061a25297622d0c54c9974313c6e2a8b27781970f5b8417062771d474739e84ed7af2b" },
                { "pt-PT", "ccd61aad798dbae1b2cf2ae20459bb17e9c856be0cc18fff95c9abd67d957b2cdfa2f4e60038705f2677565b76e716e8d3eb4872f4e6fc235a6c9a05a5591fde" },
                { "rm", "3f8e243b8927365cdb7d188fe355de1c25f9d46feb91fb3831a013b4df0d0e550e4e62aefcc5a9e1b584bc2e94bdee6523d8e99d4502604de181136ae9262c44" },
                { "ro", "5ac25225d8ebc229c84be72dcbbefdbded6f7123246a163bc119a9e36bbf6f7a6ba330df8594f43d3d06f3934c8d7ed9ecf6cbfe3c90df1a9a23a1fb4914f12e" },
                { "ru", "7827a95ce6378ad4882859a6b9dccc19379318d6612df7bea28eec20199f2a993e20ea1ce54a386a19f3ee40b9b51900ad1051b59bc9ee03ef0dc0ed9ba96357" },
                { "sat", "d7fd9a9964d04bc97c0deda4121603349c96f7af6ff527a8d8e6cc3157e125aaf833a62ab0aa17fa9aa5d5f1489b6be0392f5c5cf0ad04cd086aa0c84ac14d61" },
                { "sc", "a5986469c2b29d79d49fe8f8f91d8c121d97ab704219a7bdbaff0e90fb90088be4a3fbd8701ed9bcb3d3504473457246fa96f72b701953d33b9dcabbd19474d6" },
                { "sco", "86d948fd561eb7ccd553d4f6010a6a8535b3cd8ff17cf3e9a2d263502bc75254f7e3a3b053db021c532e09a2d18ad897a0f3e8cc84a3c6504e949d3d1b224723" },
                { "si", "7b25104016f3eccaf2bfc6ac74f54cac1176a7035fff9227a0432c81eb582d826c57ead5928c3c468b780c99b21fe0d32ba5689cac3ca2ae3092592f00223c6d" },
                { "sk", "86b34a3feb3a60a2ada9c1deafbc085df5f38976021421962ecf44c1bdb54000b3ccc2650c18827efd4ee0b0aeccd0d2afacf84c212f33490b1d4a5b7849c72a" },
                { "skr", "46543acd91da815b45afba29f01832a5988ab6dcb29486486e9dc6c27b66c5613aec863fe1848d3dfe21a6ba9c28541f5e8b9d640acb29ee80fa9393ca5e866a" },
                { "sl", "ea5358c2926c85e721b944c149d7c5687971b965424c955db8cae059a63a1cc712f8c3d2187ce2ee2861fa4e7e74a489ce3e5126377d747da69d86c282d5be7d" },
                { "son", "4fe6428828cfdca7678c658a4a6f8b45b57153d24908c7fb22fa0d43b8710e091e031d130aad9c71d2a986fe99dee2e9bbab8cf1e49097896028c3c1de0a1f7c" },
                { "sq", "0a1dd41886059b35745db112876cace5faea7f8699c1baf67c5c8620c26ba20af01bb9bde47e4812daabe1bc91cbe483e9666881e156869b9d3d8be23526c0bc" },
                { "sr", "e6efc1ad20646c3599009c6ab098447ed17605a705671b19b8e0403c524a07db125795aa00610612ae40d6f8b034e2baf3ac237db9c6551c73e18125c1d97993" },
                { "sv-SE", "6ce91e74e02f0243764b4b68b427fbce345aa82e9d5781d61b9717d1c48453705518b22ef720048b0cedc04128391ce10cef95e8e8d64699b728d842c242e008" },
                { "szl", "b2c15552b7c40eb40cf5571e97da26ca22153fcdcb7ebd00748570c9e72bfa51736c4320e106cf307c047b29add0209275df0cd6d83fd03a2ac4fc72baab39d9" },
                { "ta", "7d69929fa8f80f5b79f6f6d290df7622b62afa7131a431e4f97b0ced018e61e8ef916b09fe3f26e145e18e3d34363f810f78a6604c1d56764ccda978e351ba53" },
                { "te", "770bd8c9cbcf80c9c70bd7f697a9116c290f673020eed38eee8b5342679d28e591c2c183e9c46df05bb81f24a6355a3c753354fa4771c116ec622662e02de80a" },
                { "tg", "5c5937421c2284e247ccfea7718712ed83a9a0c928042a8c75d73b8fd349174b34b83f4dbba5ac340f1ee721c05746436dbe25f82849c9a0635c1f1c2de3340d" },
                { "th", "2df607f7e768672097997abbfc84b5f465154e069486dbd9b4ff3a70690e26e0c8cdaac04ddb05070ddabd09936bc3d36252458c7f2d6e1aa4cc80bf5dd818cc" },
                { "tl", "9f66d5fb3c348b62b43a2af2b63d5fcd1665baf5b61f45abfb29115fdd064f428235264f9a1a3aea4e1135a1a231ebed26de98d1718fbe3a3a60080246ef86a8" },
                { "tr", "d92505cd8a179eb7f6af8da6e37c15493c0d58d6e4ee3fc89c0ea195b072a7dc808164460db588934032d08a5c97516e18defc42770f207ef0d7661ebd6208e0" },
                { "trs", "fcee66ef0f0399e109a8a7af005274430dd03f206366decb76cfe0872400121306b54a5c057d0f1b64469185ab06dd224da6a34d2a1d4294a2d3d8898b9cbf8e" },
                { "uk", "6a2a15eeae06756ed1e355b38f30ad331b3c70ce2744c9c88ec3bca502e435628c0e2cf69afca7940e20ee84f8b06d557aaaa9d9237e8baa513d967280c53344" },
                { "ur", "16c29a0c9ad19fd0072bc3e3cd13311de215b38ebe846bdafd3114663d3447e0a640b86dfac20a05bb72101c8a5aaecbb10e2fc3e5fb138b720648d2f0d63c04" },
                { "uz", "a41d50b1a6b2751085d1ed366d59a44cedf6e332f24f530f5cec9e9a8a6780d38255f68b9e2bb3f9b7dc4011be9b4df645b3846d6fde0fa8508ef0dfe1df031e" },
                { "vi", "4a2db6b5e1f6fb53c909f98e403896450e957c287c2dbac21d8c35847b11c48dbee08c491e1327c43860bf02c2022ab289680ca42ea16eab752f9964f6cc1898" },
                { "xh", "297a5a5f31ecc16b70f0a0ccadf5857a367144d6ff0200d2028c345063f36a6dfe61a495c9389d3414a45e8199fe4ac243f1c0e3ae7b97e2c2300d09693ac9fb" },
                { "zh-CN", "aa74dfd5685773afc13aad969cdf9fcad968aa8de68a833d166da3c00ae2adcacfcfa85641eaf80a48003649a9ae11954c410812bf7ef85c3772a8050c68cb54" },
                { "zh-TW", "02274418bee57f27e9fddb3940792e28655ba3a723c4dedace817dd3c59e33766b613379c0653f0e26eee43d3b323abf0fd50ed9835aa91500e2a8bb34929048" }
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
