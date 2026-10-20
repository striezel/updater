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
            // https://ftp.mozilla.org/pub/firefox/releases/158.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "88c65e98d9652898d625153f370b8c21deb20a074fc7462ccb01506e647551e189d1abe111a55d97f7f2b999d736d281c0ce7ae85209aef0bcfc5c46d6ab64db" },
                { "af", "a8122f7f9d37c69dee88f4b08665557ef6ea5fd2ff716046fccac0f9cb0ce57c9ae6013f7ca4ff2a39ac03c1a0f716811ad8424c50bf8c64715e1e5e63a3580e" },
                { "an", "7d306529ae69a37cd1648c261500ebcd1764ccfe1e95d80d88701cb608fdc21edb0eb4209a5c0685b7d15554e8e523818cfc1005b316bea6ce77fc2b123313d8" },
                { "ar", "1de9ceb3ef51f9ef2d9216155adc902c0e81afd408f03550652fe2e2d62600eb2089a8ff741f06094b24b5b3919055f0499125620c8d045e6f3db1ea9693657e" },
                { "ast", "9d2c22e977f715fc5753ca1d4237213579936c1cc0997aa80e143068571b6d5ab45ae137c92cf7f11a6a48a4c29a8f8eeeaa4d048bcda8b816bc32e55782adb7" },
                { "az", "c8821769dc2586c483562a0ca90889ef3711449483c65c1ccbb71660fe05d3aa13ceef82def0edc4a3d6e0b3c14d807478b5a6f61a2859e0b301d44382610700" },
                { "be", "c253a09d561eb3bc28ebdcd1dcd669416aca7456ca76287c5f5499642073e4487eeaf6a42ad86c7086ab5f14f3abce7bde37ccc7747c09d3e9d6a789d3fd90e7" },
                { "bg", "9d12eb91ec4107d855225e915f5a38a6f4fc30a70cb14bb8fea95de845ad6c8eadb9a28a235f5c05ad56f5088bd533cc9931f721b0030050d2a3f845a9d2a752" },
                { "bn", "847d27d8b11aad645926c1b309abcd3a2d7f2cf7ab07813360208673464b95b733bc3ab0a23c2622ea581da550b294d49f8c13cb292e391ff9751f86378b2561" },
                { "br", "7b604ca6dddb0fae793ed2fb44eb356ec06ce870864e320a902703c79bffaa83ac5eef54744ba84f7808382f6e66b2c4d2f64f58ef930c7af7c88e302efb52f0" },
                { "bs", "0e32f11b45cb7f06b7ee7752e84ee7580e722535b3fffe95fd83d426e4ca962f849e1ce9800945f0388dba2fc0b80f6695ed8f1354e1ff26a25c2dae4d1fa5da" },
                { "ca", "5aabc9ea4dab153d73ddad892ec08038f0e4c47debe46e559e48489670cc1ce8f2c84eb5f58af3502ebf6215ba5335955409f63008747b1485e182e6fdc2be76" },
                { "cak", "6313eb88a3240bb150ba1d21556e4f3b6eb2d8a1c83640574c4825f4dc42d883e2d0a8cf38ac27caadd0a1f945b8d436f58ec6572c00e6cf13742dacc1d13a17" },
                { "cs", "fd1c0e61d9a5cfb8dd1df924d9be5c180aa2d01e9d63e4a0e861a37da7c0e900f0aefb0802325f42976c326e1a9d166e5fd43b14fd4a41ff5d69a2cffebf3d0b" },
                { "cy", "59e894e5bbe9c57cfb5fd7b3935c5fd9b719a3c54df89b806dd18f66e0d4a24f23f318b4b951a9716e7cfaddef050d4d3f69d956f41c0990053db5cd24721e8a" },
                { "da", "2db52dd57033834b97cac1a978c878c26aeeea13aad988bef575da55603549f4ddd9706b84ab7b362e1f9e5c9326a2a33aced832c46406348d97241756c510fd" },
                { "de", "519e2576d61728ec1467c5ed1106d3b55b6f040dad95d137ffa4b91e05ad4506874c4cd312c2fae265423d1e5e75dbe8250d8720812634e299f504d37079c04d" },
                { "dsb", "62a8b1ed9839d3e2556ba8c06644fcec8ddfd556d3517a5670e985d2a2fa113d125e19e323e4c6675bef799bb2e23b72699b896e9dd18e74e3219ff80839455d" },
                { "el", "dc19deffccb60ddc99db711c4bf4cc88b256ad5594a1c32512e77fdfe5883fef2d9e00e54d9f9ad2f82bda7f7817e13e2a374cdf9c4c43cc7cf5471f5f27a430" },
                { "en-CA", "6cf9cc935a9c6113720116bde7ed32d5b9b21e911adbdf26325cff3e5833b94b838b9a07d92fd11e713d27f49b9fe07c0376855f168259f2e32fd466ace9ea95" },
                { "en-GB", "7cccbba4fdcd153589c4a2a828b5b4e1569c2d3cc1f2ec122cdd5b30445a8b1c567ae952ffe40aa541f24989e48933067e3ca187ac700016198ea6fb773a1810" },
                { "en-US", "34ad9f80be0546654f1d471fe3f7e59c40df51e0baf50abd4b83a7b53469194d3537f26e58b7f4ef49e242d7214446e3f37ed4b94f63b75310f290f2903afcc0" },
                { "eo", "66fd69a72dbcf45770c8b8e9e9865273881786b23d476951f29a8584d9383b8377702dfb94c6d14da552b71ccbc1f7993cf7c61828218a2d3ee3384268badba9" },
                { "es-AR", "88a84d1b5272f792d5740ba3d42f1e14eb7ed4d4633db767dec7fcac1c149c87b8e1928c733fe456944621eed9224e55e4a88da33c5624bf5fb12fe30fb4462d" },
                { "es-CL", "10fbf1b9a2e432dff2f5b0392fa6a14aa71507f0e41b501d0b79a60d2ac2a6efe5fa1506aff5d813ec129d653ed1af15453d3eae4b6e08886891897e124bbb98" },
                { "es-ES", "83dce1a6309714731294f804d86bd5d4e657d67e00b2675c4a72a2446aa234119c21705f7c18c676b33b7c54abb465220713598cc079f8851609ca769ffd6efa" },
                { "es-MX", "a39fdc173fceeb439698f92b95d737c794abfd16ef1ef5e117ce48fdc6f7c65602f103e58eb1047e8962b36ea6233fa7bec1d24fc3d14cf4561a46d67af5595e" },
                { "et", "967697b9f4fc2f4fdd6c43c3284f104b51718cce6b2f806e297a7a21fe94ac8857e7948d8ce1305d9535e8b28303bc4a1079163c54c6ee57cc9cd6d0b35d0e3c" },
                { "eu", "235e4de8aa1355030e06da9b0bd6713dde80c76561295c126a742a25689995cfb9acb017f3985abb55f60d30cb0c59c2f8aa657c7c901ecb9cf6f54e03f71e94" },
                { "fa", "bc2b3dc51d9f38d8e5cf478077a1b6bded2583ed34454d533fd160d2b207ed425320c16174468a11d2a9d9d4f061bfe918a8e5318256507b70fc10cf7f5de239" },
                { "ff", "14c3564e972351e220fc442591a801d1d670f4bb35ad03335bb7a9b76281c5ee10750d37b0d0244e1db7a0b598d1329ea5042aed6936e9dc843bb1732075aef2" },
                { "fi", "156125f492a13dee76b8716c473a650c3af23a5205bd1dd26513d112324459600a1d9d34aab169579276f288c2559cf876370e1c014dbbe38796bbc2af04fcc9" },
                { "fr", "ad78cb555aa7006c32d39b80b8cf651174e7af1020309afd6372fac38b7a32cc8aa63223d2212beb39ef5ad362a7c1710fa9bcecd6424e9f6363824050993e93" },
                { "fur", "d47b236b91fe4423231dbec4d4849b5a7d249edf1d89eb26d7ea33eaee292900d693dae374455988ae1a9a1add5c02ff4f3be1249ba798f1122aee74b66232bc" },
                { "fy-NL", "a319ae36c32ced45ee94192946cbb5949db2c96532e504d75049267e2bc1e2ef54f2388a95def62afe01a4ae6696f44917e94be54be8d840d8563821a3ffcb2a" },
                { "ga-IE", "a90062bdfbfcb86e8b1b0a0fefbdecd6e72741c762123bbf7b244754cad82ba722ecbec79b848582987df6471659c01444b0a66a12982e0ce621a64c8ea24d0f" },
                { "gd", "a66e5641e5d00e73e6cc0e4156fa22736ce45de3c327a19cfaf752296b909ec57ef22b863f3972d8297495849744c9bf7b7019100ddba7ac08ab4b057b6590f8" },
                { "gl", "3f003ade4fba22f596e56aea1cad60ae648c7b67c16d7a71f99e87c1d351a9b3b07d29d1482c3e61ab1bdc4b57864b1d85725124ac5275b70e1ea48f16291d7a" },
                { "gn", "5fcc8665979341a7f08df0e80caa9361b203bfaf8fa3eee4b46442b20fbb66c8b5077de4df470b14b5576a21b8278e1cbb52a327126d90d0e3fe6b9b5c316418" },
                { "gu-IN", "c40d6f4d69ad8727acae58fd601bda81bd191fbf683d836f912c5ca3f05aa6356fc11112f3292d91cf9175a367a5c838e8d1dc9a11f6c66673bba710a6f8fc56" },
                { "he", "a4bf95a5d6aee4423761e08a7738d04341166ff83aaabd79540cf6f9b1ff1d173f66c750277393f9194b0e0d79d1f0527924c88593406173a25935a12249bdad" },
                { "hi-IN", "51c0804551ea0d54d69591d0489557634428ba62f3e489f6ac17afccb28eae94cfe78c1ed4676bc781926fd8480108ac2814695197b7eb7a8f9a67b06cac68e9" },
                { "hr", "5f4d2b064c63a739aea02a40b8f0f7c12889959bb102c8e27ebd8189e6bde1d8f7de5856d36973fbb0e17e74ee81d4c666ce2a4e827436c6766135232db022f2" },
                { "hsb", "f42cb6393c4f740aabf4f158ef4a9350028929b34906fa55b129e2d27cd17423088ca7fd9207ce9f4bac594840000bad58e12cbd4ff4e58d06c6f7ef6da54754" },
                { "hu", "c800600a43ab341676b1d01be98f373363dbe6ab759e64645dbfa2f96f6ce460e44f84434187a0e0512514b65faddd9100e20a7b5618234eab6b912ff6e6017b" },
                { "hy-AM", "7c4054cc114ade460b2ab83ec1b37f425ed107ff4cfb1383f63d695aae6f19ef0539f213eb1b6c15186741764529f5d0b9d5a387f44ca3b8ab73bc72677f630c" },
                { "ia", "61014a1b46880f021ff5e4275567597d052fe6da99a28f4a793b1deba10892da8fd1957c902ca7404b8c4dac8325829a7f69b53bd1c39c968c786e67677dd2d1" },
                { "id", "b4010692d62849fbde4d400c1c76b80a04ef3374f1cc8b10061683a352edc5a5ee0b1a038f6675366ae8cba3759742b1aff281f58d165a13b3529365ad11d1c3" },
                { "is", "3ea0fcc1dcea975998faa014458a89362799fe6590f7edd467714d2feba467a0b8fc771b1043d879d784cc35f5785a97645844b0d17b223db6da136ce1c40091" },
                { "it", "6dc7d7e285bcee6649e9979e7fecc340bead797d746c6b812ddab19355e9603623597761463fb226c802f33dbeb12b63910971b570bb51ce20bf4827687ceaa1" },
                { "ja", "20934502b48c7c475cdf0f73cf9ce8fd63a0cdba51a6ff4f3f8da60e8cd3b82374cbe923b66ff150cb2274d1e57416fe955026159102a6b8d76415e9e553e5fa" },
                { "ka", "911800d881e2d6a0078db19c7153e192ab2aa29bf4bb4c46b593c43bd3de6393ff5ff5a256c57f72973fe7098e2b152b061009850754ade9d5e9c5cb680cd9e3" },
                { "kab", "49783b5c44c3b4d8125dc6e5435b4d933dc4deb33ebfb4470325625ceeee54a6df1b98e02ed0b49f064e1ed74cd858470ab69bec963b25275c80cfb8ddcab90b" },
                { "kk", "ea5c36c35b8c3e9a7fd7844567aa7b168936a29e8e348d4d160b0355ad5d7f377f478e197d019c6b1016d6473d333ee9e207b5af8db203b214ebd3a66d37ac1c" },
                { "km", "2a79ad8bcba702ddc1f14ba387d2dac60eef136bf2eb04d5978eb43caf679f941d208b03abe19a3e437c116c679e28cfd98d364b91ed19f30d0339b7d5c1e622" },
                { "kn", "d9fe5f5f725b2a74c6854646cb722b2a6c9f3f7079ceff248ba512fd6e1f9e25a1afb560aac8c1d77fbe1856c730bf8a4b59fcfdec86df9da835e5203fc09dc0" },
                { "ko", "610d14726fea309729c57eea5ca2b684f32db4a67511c708cd0234fe6d6b141e21562e31ffed5c0484540f0938571c76ea5e5e550521043f87a4ba2795852118" },
                { "lij", "23b32a675e926e54f7b45aa04fa90a246260de66b86ec568867e4274738d815414f4c2f75a11b06328da3b3dd0df52f54e832ef7a0fdf364515f8367ba39c3cb" },
                { "lt", "2da9d195fd76ccd72066ddc4b053dced8f11f3a1d0ca1d092ce2b39d7eae9cbc874a512e47f799d99dd6633ef973eb2d42cf80b65a3af27f1132072fcb3a40d4" },
                { "lv", "6d4be70f31800875cbe73dd6490e79f1be1bebce343712b73e45d22b242fb6cd4afa180dde20e8da09304d293334f0229e1de96b32cf4abfd8d2517bf5b181b0" },
                { "mk", "1c04d7a78bfb610613ba6ab9d750d52dc1da438449a23873ac6bdd296132b2531ba3688ad46540abd341d41b8bea109b87dfa11fe3a7cd6f7479a283d99033b5" },
                { "mr", "5e1501428dc28673a22b17b922c56d1c0e0adda1e7fbe4641567a0a44bca17ae842c669b3ea6301a1b6c9eaa4e2126bbece28fa867d713621354836dce5ea9d7" },
                { "ms", "aa8a681d80c86a25304a9e32b074e424ce6b8fa6ea6b20f6ef9886c710330532f273d1a7e0fb6b6471b0db392a11541f2b868db23a573d3c2f10a24a99ab1705" },
                { "my", "dac38dbb516d3cd6b6b1b7f8402e2c1267a4c409592620d390a9704630aac70d4f28ca92e9a226e5bbc0ed302586a511ebc13e95ab8a118155ee30c09934b250" },
                { "nb-NO", "35374a5b6064d751322a8121c4579067b7bac3ac8bd8b8a2ab258aac9bcaa12e8b8d79160450aaaf46a70d7424fc7cfa2fb7aee652a993bb77a63c5b5471d686" },
                { "ne-NP", "e8cd220227b313a9f521837eba5b867ae420ee97b0217f9460ff7cf766061fdbb37d82c716d10798559a178c04076f39a4dbd30b6e97203ea375b828631fccc9" },
                { "nl", "fbbad2da37ef132d654e04c4a6330e61f69ad210eb50c4ddce619fd2760f4681cff988e8aa6e7d373ed26f698fe902acf0d997200592be9c9d0df140b25bf7ab" },
                { "nn-NO", "7a10bc051e1f4f85a372df3d1d60f9681dd654e2f803a8bba6c241f5b4d44ee576dd4a580f8071e15bd978456d965a444dfa545c629ea86bb3d272a2eb78ff11" },
                { "oc", "9047d4dec56f95397c49c92f33791251b6546704ae25cd8ceeb26dcc931ae51db809b2c281dadb4f9313d05a1c574ab38cabb26cbd95dc8e2efb686fbf4d06c3" },
                { "pa-IN", "848343b2259862abb95a2f2ace1d29a0c86d5dfb447660ae2c656b29fb897673502519063a0811d6863dbdf10abc9964d9f54a6bcb06cc19d731cc61441e12f2" },
                { "pl", "297f66d1e970d7917007993b25c427e521fc6f0f77c7d736f5b492a986fbab1d4f91c0bc3ff7f866537fff526a319e2a8f4da9e20b0827c0093079ac8433da2d" },
                { "pt-BR", "d49d6ff960cc986098beb44974eae0b5d8205b970b11a55d2c4b11c1a0ce454f0b1687e8c155a5d109b1aeb2e56a977616fb003e70ef73204fcbee23e3d8b7e0" },
                { "pt-PT", "3a4b68f5bd38005a9a2635ba41d6a71926f467924626935ad6d4b94452365bd83418c1e6410176396efca2061524e258e0f604e2b693f913aa0e94b04601db2d" },
                { "rm", "52daf3a9cf8beb3f9c71220b06e8ef443f619fc073b57e82e7f6430c46c3d32d62fa841189b9c16ed9070bfd302bd4a0da044cc443a944d3db29f51221ccf219" },
                { "ro", "b26ed8b84f1daf32e75a2a11ec800a4fdc3d87b7e8e541d83c6d20e4f3015808ddec372e29e9218571b9359bd3b348ae93876de29587ae0fe45d7279b61c2219" },
                { "ru", "58145343b7dbb51ac2b558d36d583412009f90bf1040c619863675c33188f67e5e0ce178aff4484cd20d5a5db38269a482aa56bfdad678b6c307b05664503ca4" },
                { "sat", "315f263c17f11782053ecfe2b05611511f9dda5a832c3bc369fd57bba41b88c8aa6a50143dee3227a59fc931896ffb3601abeee98ff92fb2e64393edaf5db727" },
                { "sc", "d97fc6597c585112b40c1b87faa44f6e1ec3ee587487fed86988b796fedbc8a7c24e56ff5f9753c319c889ae4ef501c319e6f15525260efb27b9ed594e24ee5e" },
                { "sco", "bdf3221118732f7806fee0d2df11cc7c4417a5efba9a23dfeb0daa206053ec6f27cab387fd66f7b3e8f97b9b7f837cbdb9c86df32dc5a9e2966bed2a09315865" },
                { "si", "f33280fecb59671bc6c712b31065b8b2636a5e7a094f772056aac137bb732776f61fe7fdd35fd2c835149f686e1a4e8aa30846e7e30d1fd507717450d451f363" },
                { "sk", "17a5c20bffffe54d430b2b185870aad33db77c2d1e20e6e7299f0a893f8c9c31ecf1834c4b28a51f2fe4d37a822ffbc8e56e0a5e03f73251b0e5c700a8d419be" },
                { "skr", "bc5484b7da88d38a3b841efe6c5f8b4d98d9661b980a830f4b0f48b437e229fbd19b94a8297db276d729ea664a76814ee92a182913b2790efe34e914e93ea93c" },
                { "sl", "1369ba1aa78f2a69b7976fbd90303af968750b3233777e1df06216434467c266da352a42f2dfac4529ffa9cb7718f9060471e5fc0f85296ef108280efcbf3c4a" },
                { "son", "e621b2d6863f0602abc699bbdb52a972ba912764ec980e52fc0a9ac4a4c7a1731df4f363215c095e1220e1fda071499e958ff5254cba6059801bd42733a88ac0" },
                { "sq", "51c6d4c7f848618e9a622b5ac53fc143dcfb903b75de5871123fb9ddf4971a93cdb282e4ecaea1339babb60220ccbec02c99b2c045da788ae9e9e98c24b1160a" },
                { "sr", "cee230e6a0109711f62b8b32e7acdfea3a62dc9ab9814d51520420d55d46419fe25998fdf2a72bcd5bb1d673fed5358ce023f02e80823758b40391641bc9eee0" },
                { "sv-SE", "5b3906091d99f9c6294c32539e50549362a4d785f39951b489523ac2ab465db244aeb471cdfa10ba1caa3b2d463379c2bb73ae9632e92356cce6f7a3f3d23e5d" },
                { "szl", "1597afc7c7fc4008847216d70d3994f148670aa71829042632ed024000db55ee20d1c31fb63216271e69005874b6705e49c7273ddef62719dbbc19fb415dbdee" },
                { "ta", "cbdcfe6f14c78e58da9bcd1f9c99ca69c0247a1e2077c305bb5bbd694cd79447a62bf124d0e87ac272744983695b13ad46f174476feecd132690cc9888406001" },
                { "te", "fabd7c874665ba4e612c209fd5ae79387a5a9743f7244694635f37df872cbacadb6b91fd8a9ad55425aa23632756d4ed0adf55fd3a33e961713c66b37956a8db" },
                { "tg", "c85ee287eab45b7b0092044179a2607bca51a0267b99aa0b37b18e1051c6b798464f055201e898a7f0b9525ef870d4f65e77fdf1fdc3b3cc9da24b4c1c5d49c4" },
                { "th", "0e43f7443aee1c47c5931f5066d8a2a4af44c4bf8bcc2ca9a0840e8fe98c2f0df774fd1275431efc223aa33e9e65f4e439d68890c17a4d6484096ab4567974a9" },
                { "tl", "6f25b78381dd689950ceca7d0984dfda2ae0b3628d6f8b472afa615f5fe24b39691e57a315162ea89fb4d12c09fc72ffeb317f1355a3ec7991a5a10853585e3e" },
                { "tr", "66efff822bd948ac76bf8f9250d8ad128f69f9a94ab94345745f1d2a89cb2609611a4fea3fcc9415b66bade37da44863297c6203b7bc5a6fbb5b52a64783ff12" },
                { "trs", "c0784680402377ad102a35b351ae44cb19978bf9dad208015e87a6133ed08732af2e10ca5275fe696071fd4b054508322c5b902c96fb79ad6ca3f55f0b4ad11a" },
                { "uk", "58c7121b86fee8bc826054f2b3750c053b4dc9e6debaf2b3236000671c31db747398de1548aaadedb43e8a55ef021ec7d05902a520ac89b654a402a430760f38" },
                { "ur", "f202bb95315904bc82e6da4f802a4f63fd5e13fc305091df80d9fa0a9a2f4d094fc5b3bbe8d5b1f1ed67cfe29b7d8dce3885a85ff46124e4865116937566d787" },
                { "uz", "19d6a1e9154f54e6db1468e494566d5d045cef58ce456f270a38334a19da178eadb4a4f96adfc5e6f746bd83478524c75520208bee67c3dc2556833eab9f6e3a" },
                { "vi", "d0da1097bd37baf5d827a724481259fc7fb272edf92ee74104629e9248937158ed17194575ce14a0515bb68feafe1587a2aba45a1b7122be763b7143ae234408" },
                { "xh", "1f392ccb008e7b9e6d5b97d773b6f912aac8db6214cae7c3b13732f24157d7393b355b9f3ca4ef68aed1e68c38033d80b7465caa25191f15de171b5c6e87e5ea" },
                { "zh-CN", "57cf35c990fe1fccbcd60d726425923131974c765bdcae19c8b72ce27769b775f25ac07823096a231917b8fe27e72735af32d1a91d9fa122cec9a6e0f2a10706" },
                { "zh-TW", "2d2d753db7c93d4dd99e591d93e087ed635116826f4708c7e50a0e12296dd67316cb7bba076862fa48619f5fd325cf12542652848e72e92d0be1acf808a3563a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/158.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "781f73536834eef7165a94625a309d5758a6cd6cf382ad396fec0d403e0b1f22f4de893d5487e253b5f2306a95e96b14a78e4793a5b98109040c4fd8d914e039" },
                { "af", "ab7cfbc036c3855e8dfeddc78019d66a29a44ff291240103fb1a2e23cd14bc36011a4c7e02004e0ea6188bc04e701cefdf210b260472480144c487daa04077fa" },
                { "an", "c48769547ad10af223385ccc806869f45c1758433159733e1227c748e3e9d97806dfcbe537e6e8f4b1f97bbad1d5c65908d8ff03bab9b1de8188c4f7aadac7c0" },
                { "ar", "26291ddd9786ad9eb05719a7c1cee5964c008e9c598fa8d499d3aa298324c4cabafc221033063a7d6484ea10544c7655bd9af8442cd78308108084e0a2c6ea15" },
                { "ast", "850052ef4315cf908d619587bebb1acd758fdd3c87205cde526f892185b050ea96031b726674bbc6d87ebda73d5129d2f60b6c4f7f78052883d1be4789b92acb" },
                { "az", "208beb338784104722d1e5a28480b2142a353e40527bc2b644b01918bba77c205d580a922b43c20d863d90d04f9c94d924f85dc8d3d21812e9cc0b90463ff586" },
                { "be", "790af9d0a1984602acb70c3fd57307bab2afa8721b8c5d981e66e775020d9a7baa9f77236fdca527c40f8bbf7e0c5ff93b4fc0131d1f81c9ed4d1c5e52a77950" },
                { "bg", "607e322656e70351e61b0ec9387f24a12b958bbdd65850b8e616bf551d49a927ef3249c4cacb241f476451dec45892fbd6ac06bd0847b0e2a18765d1d7347c8b" },
                { "bn", "7b46d29f1dcd42b9d7d6456d07a007a4b4e9670d26ad5852d2eee12f5375049f2d45e16f50e31b338b3253a77fb8dd5cdbae2c7c911fa67df9f040ac7fdfeee9" },
                { "br", "18d9d70a93a2055ea2c5b22d19f527f0119e092209b16ac3b5b6a553995ea16b4bb0a520875586808f905154c56789bffba6aef9b47867a9b043c05b7303ffa5" },
                { "bs", "d2974ddff381871e7ba5adbfb8ad393bca947aa3eaba613fce4dc5733b4bdf160ec582e33886746d56d6e9bd9eb262aae5c15dd069fe37b512726a2da17983ee" },
                { "ca", "459f1f17c9e844dabd7d0cb90a4e8dfc5300aa613041aa7202e11f862704337e733b4faca46f4066c5ba8076e960e3da47c7adfe5cd81752a886767852dabc42" },
                { "cak", "31b8e1b0c194983c1482d1a98d031d80756e9a1aeb8ab298dea403cefa3f02712eb9c09e5e28822b1d7c5430d00675041928d7bf7709bd956636743b17d6a328" },
                { "cs", "bc9c8d40b5d8fa8b757e9fc4b048f96a0cb45e2356a5f3f74907848b5f1f717eb88b08dd2f0c048fc36531b80ef8e6935f94e19e5a17b8477d641418ad014b40" },
                { "cy", "a4338c8f098225a0732bf90e6ab59d6d0ee8e41ce79e34834e92a2cf0ce8657f2a4757a25ea08b301d5ac3005b3fbf929c2021e85f1de714109d6343188b1657" },
                { "da", "7e9af54224c7db5d312b19411f9a86c6f7ec46171a0a166bdfe713af6414c02b7ee6544c1ab8bc83801579f6d9473e991f2d86dc030bd57b535889f9034a05ed" },
                { "de", "cbab2550f9b6a60877f2ca2750b8e712ecc63c6b292a928fe847696756070a190e1e64e7a8083075630f45cb402f128063728143a79fbb302e0ad45e505cde0e" },
                { "dsb", "559f44b04ab69de2912114fd960d8b34e34dffe82967ef879c797859815a6abec4c29a8645bae4c0663c5d3dc19cdcff0ba76725e1c5836f2536730846fae305" },
                { "el", "70cbabca1acf6479494c00999c5c24fb42e0f626b0092bbb4545b297a092286328e9804397f46d4b0a42cff84b3ef8fdae06194f972b54fccc387276e5e5ae8a" },
                { "en-CA", "c0d7c18acd18cd56c453aa14811d34bca5d30abbf6001303d27b2be59d17114b3197a48c4905061f7c0c90926cf41bdf7766be80c7a25316bd66f29c8e26732b" },
                { "en-GB", "24cc90bc503a33edd21bbc14097cfcb97ecefa66c23bce590f35c1e74260a2a58d0b217a183a9daddf5c0dd7445df319ab403f5acfebfe19b30c096b23b4335f" },
                { "en-US", "4cd87e51e033406ea5bdd4fbb969843b41365570c4e59e95610ed5074326221535279c616fba21ca5c89b0503843aa746f8a3a65a593221e77bef6a18ee38ac8" },
                { "eo", "45816d34a0b4f2d17c3c7030f4fd9fc99d64a72cf1eb6bf862c844f9d438c8356f4ba5765d80e23186ae0276f9e02f7871c453f4e9fa1fbcf42a3cc70791da9c" },
                { "es-AR", "36714cd7fd8e5e9984870964900d86f135065836d64d3fabde4fc82082fdb5f9115b5653ef3b7bd368e916234465c9cec74687932e30728ba12b9e4d974010c6" },
                { "es-CL", "2d51bc9c332911a2be4bad28ac180863fcd4533e0d1eda644a4e2da78dd0199895b26f350bb2f1d478126623deafe234f267549e87c6a709b90921658253fcf4" },
                { "es-ES", "a645f64929945863f6cbc0222ba2d1f511c74ff5383fc7c4bd5afacfd449f1209e89225f6c8f30e11fd0e53f3ea1d851d6ed1b97823506894db056e3e9323ab8" },
                { "es-MX", "2a9cb9acf37d2f2a274f36365154ec35a73e40bbe49a5638be488673fa02c66d9e0223e8fccff31f916faae4a068705a9a6557adc2cb18f8689105c2728b91d9" },
                { "et", "0496e780837d534589aaa8e5f73d84e9d88b1b7ccc8749035aab36da674a65dcdce6ed3058f5be9eadad6ddedbc386655baed619adfa7f69ae2660b41839dc95" },
                { "eu", "1ce8e37a8ac1024ed4ac9179822046d2206e3f101759953453b7506b588d817cd96d6fbf1511a166c1a515967be70dd46429098c540dfecba3bd6be76c8e846f" },
                { "fa", "8967c0cf633c7f3893b4c2d3a7e41a2f133d7411eb1115d9462b9f75dabeb6ae2a85d51128e6f65ee2a1edd018449f4ff960f9d2d359fd92e502f51db484ce11" },
                { "ff", "4609a7612072003c79c1a833bd93f27b24ae1b7dbc1528fe72c8e4af2f613d0a2844151b4d35d0e98cc40cb2e9b82dd22c7aca721af7ae27b1901928136c5a69" },
                { "fi", "e050ebad8e5a1872c5aa6be9ebcb2ffaf03bde6f2ffdd8ea81ae47120928b5d25b32a80d7eaa853a7deae53a42b2e3c9467ff30e71698a9fe79ace9f949d0d30" },
                { "fr", "0e356acdc6e118b1e12d93f3ccdfb4a883b93a6ff630d40cac74d49265c8ab185d18406bee763428e576fa1896bb18a7113bc590ef974abd7e0f5156ce1b8322" },
                { "fur", "e9d76ddd560da9d59f8338feea3e8613b11f217223c4dae216d9eb69119aeddcccc79bb1874323270e10803c00de8c5c1b510e6105376fd680fadbc9e1ac8b52" },
                { "fy-NL", "87708d313d1ca7324972c4310f6f1add6e52e16c0384ea005aabfa6ee62a807eba49e4a77402a9beebbc7156d4b44872cf5968997294c4ab19015fe5a7d7cf05" },
                { "ga-IE", "9cf81777b7dcf222e2e724fcbea934d81b5a4e16b7e97f4c3471d57b42e35e10ccf2d625f0127df96c3ec12b2ba78f6475720924e01411d694671ae51c2eff1d" },
                { "gd", "064da2e581fcdc1d75bc07d3f41ab601725dc79055761b5d853544b0546d59551ff1d944b82779457f6e0faaf611d24d889d1714caabf39c7c528415a99b16d8" },
                { "gl", "ed25c9f551ba51db429b0a8e1b92b6c5782daf145052926175e721a83ac772ac4ee41101aebeed7cfc768a9ef1e00f53a0c62d2689db9b402e7506169d59a24d" },
                { "gn", "fee5d9a53010fff292e0ed454052206e5bc8d40b990918f3016a2f463adda538d04a2c08db6f2360ac0a824d89301dbb1c50e281e19e6d0ba04c532d974c051e" },
                { "gu-IN", "6dac9b66425a75fcacc761401c3feefce41cf0aa8578a2cfee3052185dcad07c217c5eb2c3ecbb4c91b1c53f108332b36a0a8a09b0570b333b53711d3296ceea" },
                { "he", "cccabefa7c37d86a67a8059481c3d2b2d31eccd73a43375a555a6dec79b0e0d9e8dc613d40c634404753bc61bc88f59672f94d1c284575c57f7ecdcc3138e902" },
                { "hi-IN", "793392d2819876ef0b8365e25a7a949f7c255b4d1b1e4f3d6386a538a07695db3ac886cf59cdf681ffb8b4338dc80069fee2e263d8f043e5bda983377dba438f" },
                { "hr", "e5bd28d7c316c81ab8d66c46678b2b19be5140ebd4abf86bab5976499ef9286f2e9cbd6f81d036d5def7e2b3487a8c71df4c9e3ab466fdec0360d2adb7273e47" },
                { "hsb", "8be5d0c1ed4361eba5c4beb02043d5a812bf10e447fee751f6d182b116f56683f25f9a50c934155919bc667b20b4603a01079fb7489a23c1e0b188da76c0d601" },
                { "hu", "b150829b9b7b2553bd5245d2b227b4c60494df53cd9550e852ae770681990e1a7a0b73ff4f4340bf1d2409ad96be0489f1e8cffcc1ced0141c6815763ef1877a" },
                { "hy-AM", "f5af87691a4c7b7e122f08c03f24cef2de6491c27eab1ab20139e94bd5564eeff1828b2d18529763dbc351f2ba4b16c88286252da6d7a3aefb3fe1758cd393c2" },
                { "ia", "6d6f4b346f6c8d19d16f5c08e43506da79924558a5d9e95d4d0f5fa8e1bfdba79337a60c8a35a11f1f39d95b2ee1a428872daa675af4de9831d27b521b58f0f0" },
                { "id", "1bfca864e8fcf119f8d0cab6751a7512bf693163afcc4afaee8c92078149ea260e4cc892f7ae08b327d7b04b192e9014ff855e6dabf448342b8311683eaffd26" },
                { "is", "b95663dd8c91eafc081c550b769e485291c76346cac9de8317d63e254276c6d0a99dcee6cbc03273049f85336c5bbd71b384f486476e26cb09210e8e2b9dd286" },
                { "it", "07201100cae558b6c82c71ee04b1be7aefd924611f17fb7933c5646cd62d543a2eedee77b12f146556c1825105760230702e279a0298ba3eb841be811904e202" },
                { "ja", "8694aeffcb1b0e53a750c0dc6742426c44b61b5747ec4b9342dc01fb2614640d811a0652cc723cef965812841c696fd83b1664a528ffe91ece3f1a71a898ca35" },
                { "ka", "4db0b81242a3802d15faa6b3ecb9ca9a5ed26d7adbd45420fcb3360f46ef63a9642b4e681732ae2dc921b93caaecf365ebe2a87a27d781e240181910bd731834" },
                { "kab", "030410dcdd5bd2991139caed10e5392863a304d15a9e4fb49a1f2ed3e95e1878cd827f9fcfc02e6fde06a9289f9b1082956542601ef672f0d1d98e22435bac4c" },
                { "kk", "2420b1926e8b88ea727d6f108d3bee151811859c6bfe7fd0afe82c35d0a44c891e034bf8d834acfa9b45bb0103a68936f0c3ea9fda4da8c5fb7f393332765448" },
                { "km", "cc5435f0bc7840e8b36514f214a0319270f9a75c78a922ba653c4252990f4b9eb20060d90ff5e1637b65e1784a2781881ace651723c721cc377771c80c2f4141" },
                { "kn", "5d18dfab72bbfd54375f3cfb2845a320d8a72a80f3117758d255c51fd195c774f51709a276dab0c8e2726b2a1846d38e0e9efcd118b848235617f84519501ad0" },
                { "ko", "22aae00dee8946070cea5d7e0572b0c5739dbade0e79b4eedaa05556aeeb560440ce989a287d8fff9e98c35fb902f89843e57597c7726ca21bef44596aea7025" },
                { "lij", "18e11bd7a4c3c406da8702aedcf75e36517cef3feb60f356c6880170ca93992260259e3bb90c4698d3f0d0db2c3c3ddec87afcf8e0d615dd44109c781a0f8512" },
                { "lt", "c98b1d5893fbbf4a9006379b7842dc5c2d8e1bc8c2d28663d27ac54cffc6644aca66732d7367ba65a8519671f064e6ede6ba5629933dba42fdad8a73cc368092" },
                { "lv", "a01bf89aa314564ca1c4f3a0b9634a2113c27064819cf164f4ffe78ef1f1264bd6c6c4193bdfa63e0ff3b01591dfea39e500c6861e3f51b74b010e2101afab39" },
                { "mk", "4211c1fdd1d44b9af2a6e051e6b41166ef433e08d4ca15d1d81c7fbddf47836d2c979255f7902d3974637f20112d499787e92aa27053bd8f2c081b3d25b5e7d4" },
                { "mr", "2af6f942cf9a22219d4962fbeb5a2a022c5fbe65981306fedeb8c9a046e0e2920d2f9ad390f13be67fb59f6aaf6931dc732db4e5335ed04845a13de5411dd5b5" },
                { "ms", "72b9af4517738d8692c69dd9ca8ca231dc6fba80f5b9b0cffb0f8000fe1ff8ee98aa6aaba71cdde8887da2351ecd7730d8f7911186f66c5297bc38308acb7d4c" },
                { "my", "31540016012683a8778d7ae42352edf3f7ddaa6ded781a4ac0f16c7ab0236f69cecead3765a6b9e1456a5763df54ef13f589549d46dc166025238482dc680eb6" },
                { "nb-NO", "a85148a70a76839377b9a3e7741657d3908587a80671637a5757823cc5246e50e33462895e015fbc5b6c2e1c3f9ee3e64dd15f645c215605ff9d757300b35749" },
                { "ne-NP", "fdf6e6004564b16038e2c21a9deefaa8d64b2b57bc32048c30246da5abea6925356d512c51cbaf4f09bc61d81e41f10679545658166435a025a3b92cff46c846" },
                { "nl", "46405fa56b612c1a467b77465ee05bab88a8351983af955d0533d1e3e5b5979af2a505cc955d3cd94540e2b97173a55f7c9905facb5b545f8d9559e885c214aa" },
                { "nn-NO", "dde18d1eae347313d3989ba81022bdc8972b833f1993edb4525e79f397ec88b2e7eb53841247269037e10e98ef0b97c7060b396ba65fd290cbed916d9da6a0b6" },
                { "oc", "1a422cc59c71b347a3042c1e5c4c01f6123726250b083515b609cf82c1479beade2a51c81482decac170c4594081292ab8271aa04fca6b2582512a4a6f9ca5ad" },
                { "pa-IN", "1a0b1a3f5f333124ece3c982a40903bf0b84811f15f0698d5f1fda258d100282d0e3953c9d45f89bf1f9ba0233837cf6659c3b8ecacebe2edcec8c3d0e482923" },
                { "pl", "4700079480c3111754e68ecdeabc5c723d9a86dc39e253808c3c03e9b97ff1af8b7ed84d1f78940d9f0ef457861e9dcdffa612494cef21375849fcb366a4b4f8" },
                { "pt-BR", "d19d811adb39d8904a8a19cd253bdc16ca832a1e3e7af6902fcb89469361c764d418ff3efb28cf8c5fb3c79808c77d18d9e083fa587cf2d50132b8e969f119ca" },
                { "pt-PT", "33b39b8faade87a5620d2a93c82c0dc5813315e1c9bc2b0ad8c22eefff0debdaf87536b79765b45c1942cf7c81940d486c00cd6218d8dc4ad92b27fb9ff14321" },
                { "rm", "1c15caf459cdae93c3c8ee30fb2f064940a7513b14b7aff8504b9a91d7da6223c18256e5d337b3c2558f18f61c10c10f09f5743e33dfa53cfc329a4b5f87212f" },
                { "ro", "143511b598c0d418871481eb0d721898c6be8542650b7bb73306a513f3aca98090156600727f5cb30f78e95abd2e387c0694d682a1ae77ef724d40145204e842" },
                { "ru", "f28ed1fa48a5cb81eb4a3b20c4bd8376f7c15e1374e56eedc14bd5642d2b0bfd867c59d8b4d8d43cf3d3b522582c7a6561d20db57a39bac467d7f81ca5267a17" },
                { "sat", "662fb0729e3c9f4997202e0d35f160a9825e901273d832e49d20a55dd4020294e7066c7622ecbfa4144d5f4738a00ae6e9a3ddad67adc2f1a9386e408e6004b9" },
                { "sc", "b02080c5e9e433f3cc6caa399081dcd6b7a9c4c1d6f6aaa8e30ec1e9a229d4dc0a4172198329e1f5784327ba472348002628385a66a8e668b1d8ab09ee84aa15" },
                { "sco", "44d40d0ee834ea48f157b52a951da96008463c02376d8cba65ba14f50e9dd76c73f4cf555b49d97030015987c14dbb4d8fc163dfca486d79ef96eb0b224ed4d7" },
                { "si", "e382964acffb6b71b317ed4b95e0160725c774c6949385744a269a847b3da3808c2fc9569d4b2c285b063e897851993c3917b4d3e9be742ca4fa0a9abbef45ed" },
                { "sk", "c0c503136c395f7fd7ae4d2e76878c848318c5447475ce1e84243c38b23241818a032897621544c32b46424fdc398413be965b909a4bfcef0f2e6c67d731ef88" },
                { "skr", "94c12e210091f7a4db87d7220eb7fc6c0c727b17ed83524d9c99ed62535f20a2c01c65eb64b097ba154fba3c4edc753a7969eb83741fd636eb8a71cba9d77e1d" },
                { "sl", "eee3204c9f50da9db4d2b218f7378e01ae950ee8a0fed29a34cdc47c66b9002340a85ae1eed46ff904a5d65cb86075f1a08b5b95a15f649f7b5c67baf257fff9" },
                { "son", "7552cbdbf9eebe03ce6bb15b8c96c80d2ff91ca9e72ce46228947034a165329d11792e5211314d63c703caefc691a163f01e80ba4799a5164c8d9e6a4562d344" },
                { "sq", "9db9d3e3cf6ce7513be175cfa5fa69f57e675d8364e14b1ceee92964e9b03e042b14d7400e438b648a7b6e42748ec3550137e9f7dbfe028c4bd2d892a7f0ac16" },
                { "sr", "59d4a1d2488e209cc607a81f58f793348f46367323fac4fb17e8e4fb2e5b19f5863cc76802b4c61c5632e83d299ad28f0cfa7d571e5edc2bfe59641bdaa6d635" },
                { "sv-SE", "cf183d23654e765505eef40ddfeb1d7d5e9f18aa903f36beefe5aa73f160b12b01be3dace461e9010e085ae84a9f726c0fa3f96ad33f30cad825b612be04193f" },
                { "szl", "eace241fd274673ef03573cf2500a82211682398a920181b7c57f81db63104fc3bfbc0ae8f67a73f06d476cfed2b73efb790475c79ea74d22e3f90fb58ae4181" },
                { "ta", "767396ae3d17758ae12cc8246f9088c106bd42d9ae7b96130e04c849e075b7b09db3195ea42ac03ef3d972af6983243ec76afda33f10561021b7a0aacaeb6e01" },
                { "te", "fb08e0004ffc91aa7ccaddde5d41e63e1077dd12ac2d31918b1be843b57050ea21a0fef3e7a0c411e286b3854830fedd589abb24c3fd33d4d3a9b10e304414f8" },
                { "tg", "3f31b3940eb22362b2cd57eda14819bfa6c38084b096d1ee329baaa5329cf64840b173eb6b4c994b997048b8ef69e428ea77ae87c081413d1228aeaaef46a286" },
                { "th", "65ef1b20b0c2f8f63ec59b776e3a58431a95cb818eae5670a4fa7bf39d66d6588736139e9447f969756efbf52d6e9dbb3087b536aa8a79c12d84b76f82595596" },
                { "tl", "d0dd38ed1a0b31625bd42600a420ca7a10e2b90006c7a95bece5b23a2db3f607ff2d016dfaa1c664a2fbbbd61bba2dcff49ac6b4dc072ae564e7820b3d577329" },
                { "tr", "9cc041fef0d35cf335f7fa23a11d24681c9a7502196d624004494060d499825215d966e1fbea1a534c03004df4df9cd13eb73a74e21307868b41ce808addfb11" },
                { "trs", "c4113a1f0a05e6773678fd9dfdc471233af51116710374227bc1f1ac161f2587164f4130d503d15838d0c0df15ef448badd9deb2920c3c69f031a42da69ec490" },
                { "uk", "eb3c4138e175f4eadd41dd016fd3d27df4852f8a3b5cb60b6957e243cd468e03088d181bbb66257cf895d6ddff743eb0bde58af4bdad4f81bdb7605f60dcbca9" },
                { "ur", "cabb90d49748057f95944be002eb1967f44b57793789096396ba7fff90dd17e2723e0d3a0bd82321cb0f85cc568ed5844f519270483958a857bccb41cfc1426a" },
                { "uz", "ea3e18de62112e1ae062f86b35b10bf8d0d48efb6c30d695f893f40ae16ed4dff19eb7b047854495abef98998fb36c9b7e08684b17de68128f8174a3779668ff" },
                { "vi", "7899060e57f6ed90e8ca82b11f353538a9600941923a17cdf8224f63ed57bfa91a532a34580ad662ad5b7265d34159cf95172f4c9f6b28dc5e6fc5359e106325" },
                { "xh", "4bfe788ff2a5ed26b2d0052e255cd784e15c31fd687502416bd30745e56e3e6caea0ef909142bd1bc56270128b0628a0ffba13b0465d9c6c5000078dde23cd34" },
                { "zh-CN", "911cb95091c05aa41b2a1ffcb2b8f11b431547493ce97db759d2b61a4198300333387cd3c6ec10a710cd41334d3e2c5953e2b736f32a055c7c9f5cc238a792f5" },
                { "zh-TW", "9956f6c6bd9e03ceb4a4e31cf8ba31a4abd0f0330d0ea34e810069446bbcb94f85aaef2cd6ec0a3057a30d8cef0bb75ce943db9970f529e191399f215d400441" }
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
            const string knownVersion = "158.0.1";
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
