/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
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
            // https://ftp.mozilla.org/pub/firefox/releases/115.0.1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "e076b673ed6c0061f6a7d3782a13abfc168c1e9cfd6a60ad6d180db2d1159a58d306e34e200f6cf8f5210c3cd0da086a8f3e7cd7949df9acf5d39fa5e26b8f5c" },
                { "af", "84d50014ea0e8896c2ef5297ae740af3f98c46ccbc866763a8fa2bc64351ab0e1066368a419feceecad2bd4a09678b365d0bbd4ffcb1b69e5b61050bf36afb76" },
                { "an", "dbbeab28b549fd78223d3bc6ec3d5ad77fa61bd1dea82e1ab9605acff8546cbcf5d6162dba7485bc2dfdce05012b7d077d8e6bdb06add82cc8c4afa8cb4e8080" },
                { "ar", "a3cb72d337b8bdc702a4b3f819d32aa54394c24dce33d9f290d41e98f4122c9d238e57b7175a74f40ca0bb13c84c2391364a40eae9f485841d0eee077e2abbca" },
                { "ast", "ef9a2c4c31116d7a6a5bf09a639af3eea87598c38405d71f2a367133d829af69bb1106b552afd858ffc1a67e062feed9f0faa1e56e2471bf910001e7cec7622e" },
                { "az", "3cf8b60acc6ff218738fbadea9279846fc76670cb0a69308ba80494b387deb8df88f776adc997cbadd2afb160face8d84059c93225563740f3098956637568e2" },
                { "be", "040bde63c83e0ccedad5ca216e944a5cdaf979d29986e2413d48128b68a03792bf206430f71532e680c2de0d19a8a86fe5af6d53003fe5e0bfa81cbba6f59483" },
                { "bg", "30cc8593a3f3802c8cd944440c99c4c5536d8cc6ba8123b89ed3e9125fef9532e5260c9a452d174bd47bd238cb919d1a63621325d16dc902de641fe0d3b92dd7" },
                { "bn", "c814f34ec429d71699c6874a3290d66b25c289984fdf4599ff33dd44155ac0fd3bac52c7172f016482a43221ca9054dce446edc78ddf5021325d54a589d3d1f6" },
                { "br", "64dbef081de40eaca2a4fd4f4c07a468b1d8d9b18bead7cfd26875485a9fcc5b59791987b753c8b7c69db5a0f1a9f9e43f28995cafa1c2c8f3ec1c894072cd62" },
                { "bs", "19fecfe6b920235a35e98593acd348da9711d403e2cd6f664a07ca7d6827608c9c00cf7faa8db4d7b5013b0aa6deee6420e510f3f60a7caaa11997810aef13a9" },
                { "ca", "136d31e0938d6a7b1e76ab57f9dd03d50cf09ef5f67fcd92f10861eb6fcc5b2e0cb0f1e52189eef6f1a87f34e8407435ec886b85a5ebd92fa8d2b311d92d529a" },
                { "cak", "72db8a09a9bdf80f6ff9dfbac628b726bcf920e1599bbe24d0e2a12909a8cf996d40077e9e86b96926f688c01318913b0fe7d47bdd8d8dbf11fbd6b6e71732a5" },
                { "cs", "58240e537ef53a9cc27eaa3cde00b9c3519450190374cf4b5d35b4f25eafa441119ff62b49e8203e6f2b8bfffb95cc3e46ed971d9c65fea79b1c1aa906280249" },
                { "cy", "af9bbd3a1000ef2f1c41462d4fc0f7555920bea9949d99d4b1f1b9e7ef0d9638d592a709dc83a5ee23e53275c1e2b1ebcaaf96738330ed642448db86e1c588ae" },
                { "da", "a0813e7c20cbfcd2ea5eec66c664966e90dc2c005bf013e1f580bb00a74e6e5c098347a995113bc098fe5edd7449f9e696246b35a95e0ab00f5e4fe7e3c95101" },
                { "de", "7bf3321cbbc1488e6fea8ea4658edb16996757c4ad1cafde1720cf1d915aff26e6f0fdfb4ae04bbb29545f5a231418438001b687305a9d869f6c8fd69d3bd7b0" },
                { "dsb", "62cf3ac97cdaffac7a7b3f60a17c3a3cc04612a51d33c0200abab93ab605def79de0df616654b39b2b78b5c0ded330ef2822f6b940e0d38e543ca19efa716d91" },
                { "el", "a7ad90439253eca89a5a50897c8e645bd9a0ceb3861eebfe4bdd02c9135306d1a99144f3b0a5209cc4274c54cbe5e998ba4223b6c8e7046dba0d6137f6184a75" },
                { "en-CA", "6a68972457cb30ca7089cb6a3bf31966b5667ef59a3a56c353d841bfbf9bf1c58a43770d76cc1a1251615f8e2b852da1541788b4e16fa545cd6d28c3462433e4" },
                { "en-GB", "e9beb51a868a1b9c2b4352206c1c336f34add448d3b963928a1e2e3f8ae66ee70ba627fe9c77f985855efc21bfa7fb0a00f1524ecdfd34dfaee0492487f51a69" },
                { "en-US", "acaaaad15654c6e078a0314cf7f3c715eec12043a6ab79ddfb05798e1be4650cfab7b8ce85964eb1fccffcbd9d598b4a1656b2475b4d08b5daa8dd0926f5946c" },
                { "eo", "499b4741a7ac09060aef8fde01d3fbe6dc6a60d99e54728fc9c28bc203a6bb9913357480381f2afa27b375f968be310fc43ef4c5003b570b514603c1ffbaab9a" },
                { "es-AR", "36168fe37e53b7da389ab29015a988e424777a3bda387a5732ac3891c98fa289ad05ee97b5004475071ffd14273a12237bf21c85b994c08adf16192e0b4eaac0" },
                { "es-CL", "de60659e7528b935fa520db930cd755501c3bd009df8e512369a0be46db573bfb1a559174a7dcd912b13c4051b576bfcea9ccdde7ff57086b271def37cd78eb3" },
                { "es-ES", "88d4274d8310e97c402baae24f7ed73c69772ed029e186139fc204a89b2a25d5e8a917556907cc1fc098ac85bad782badc638abc62acfeaa0155d8da50698da7" },
                { "es-MX", "1145e894c1ad714683e4e311173fd089d93bec6a45544b6f4d16c1b1d8a97c1a0df1b433d3269067265d0ed9cfd02afd757ef8e7ae56ced2b0d9254fbe1f0a21" },
                { "et", "20fe73491684ba5740bf50dc0e9c645a29736e95b2e4f81dc71eece8854e93d749838aa40266b137a2e7144bb599b88565d4afbfc8992acefd72b33a9266ca6a" },
                { "eu", "dfa258ecab706d9af48478446fd244164493df4facd439ab44fe6837c5142d92ff2110a751c345a836e4e9906becf4847f73139d822cfe9895c3f1af04a5bcba" },
                { "fa", "f7de45276462291cd8757c8883701f5014d0e8d0a4682cdad013f803c0fc0930c7ec71c2d8e211d3db448b7b0aa9c745c796e3489cfe5465d4da7088a6d939fc" },
                { "ff", "1565b0fde5268251a2cfec26913efe1caaf6595e2cf2bdd5c718ba8b232c8b67aed22014d8936ff025761df77acfb3470922df462af509928d8037b3cec896d3" },
                { "fi", "49819a8dfc50704f794833594d89a71aebe49167043714774787816564e5b5a72557087793f386e3ad0a17be88a87e82a4a50d2ce5cbe896fcf78d2e60569730" },
                { "fr", "2f83cb0b70df3f886e7d05081f5b69e33ef5a146a9607dfa740e333270f5e27688407f357275aebab0860b2ca55edde8d00ec85e57cded651dfbb08ec7595d77" },
                { "fur", "20abf90bb160813e5f22430482a84ab72eebcc7b75a9ab2d0dda8b6368a4575e23bbc1bcaf427062dceb60c82485183effba1fc29c4dbc4bc7c1ce7a4cc8a5a0" },
                { "fy-NL", "41391fb1626a740e6b02e6a555cea5b70d1a35a428e9cec23873349ac5f49f575e995455aedb17fb3099def7af467e849a19a910549f2f9158f95c5ed99462d0" },
                { "ga-IE", "9be571b73dcdee1ce320f1cd8ad76a13cd9f74597a7f9bf7c07c8798d8405c84f603b89c4234304d8ce6c02de7196f35ea9fad934c3d95354d3420118368f702" },
                { "gd", "de2d1f79c2166041fc071caf925fba6d7fd6ca5174eadfaf9200a32e8c400ae993fb0c84ec8b64448c2feecf5ecbd8cfeff167be209060c55fd40f805e830876" },
                { "gl", "e7179e3f11bb435ee4d0e1668a8f49699f10bb36ebc97934bfddb939a96de199136a8d92996cf2b6adb1e0cfe7c180b7f519ee105b85815fff6bda070263715b" },
                { "gn", "237ff5b1f666b2de86f248ba04b999f9ed1d46bd022f25c1e80894256967ff35e54719d136c507a0b5a29643911b26857ccea743194247fb1d66e3b297088734" },
                { "gu-IN", "753feeb9940164bbf7be18ea147638bed2ebc0721a400af6cbfa1f200a751466b13a9d298cade6e6ca4095bfc2fc9c64a6e2c7beb5f2fc643ffca45e9966e032" },
                { "he", "507cde31fc8ab7c975da4ff50f92a49436480ff79b2b2b6921f5ab80aba7af0b37662c642306584eb4f6adfe61f8ddc930b6e5332dff96ba7940bca9dcb8dfc1" },
                { "hi-IN", "a4a260c6d4e3d7cb953daf07ab646a5233ae0858633093c009982d9070fa06dde4e6a583c9e947b6d837081ae56cb267c83214c9febb4971bd86d50f724a7486" },
                { "hr", "10ce80a20bc00fe5e5090bcb62bc2434733be9260637634fc025c846f32c4527a287b7ee536dbdcc1ab24237cde95d6ea92b04dbaa54687a20e142272fda892f" },
                { "hsb", "64e09ed7cd60676705c0e4f8c87f69d14875151886ef8a153c03b1c5b31deca5aa71a5b529bf90ed65f30e8ff5875e38839146b6f00aea87ac5aff8034035840" },
                { "hu", "ddedbe5d1a2413f11a94a0455767061c6fc918d5e7ae6e100df1b4756c0d11f3f04341eca29adff317131858a6138c0906d838b09f243cc9ac7033c500f2af93" },
                { "hy-AM", "b3c276878205d725f2b5a7f3780e086a4aba6582c3ab3a894dbf08637e66e06509dcfb615ad7ad742c56bc71b59f123b78536f9079237c4416761b2d5976c51e" },
                { "ia", "8128e92b3850c0c7e7b65787b32226a07e871c8f60adc8f5a8909dd73ce5f2bf13be386c1dfe3efde1845dcfeddc26f8574dd3f8c9d7dc39aa4f396477371bc9" },
                { "id", "da5bf242e4fa1078f0f39ef6752e47c267c69218193c7511b2ee30e061f3abe341f65febd1ab03288363011c38ce26f91c3322865e47a253598395ba4570d54c" },
                { "is", "2393b68562e558d4c0a7a1b05d2423b150492d0b09c183b0d0df241de8f713986c804993a0d949d1e92cf6b5dea6aed6539aba84e92f9039ea33013b91e386d4" },
                { "it", "caf8e030db83400eaa3777e24efaa7daf5a5fdeb1a57d37e1c08b596d3e06b03d4a81014246ff3a575d3622fd90e619f6be7dec4cb20f6bcbfdc0b1cc82dd22e" },
                { "ja", "5b4895824e79c28e8298a85b05ab961e986e5b0d5063e3f17f2ceb922d9cdca33358fd162f34c78f9c8a039dd57ff931634aad94607c828f45e71350bf775274" },
                { "ka", "8e1e393ada2e431ccf11f5ea5733a106676f72957c0fa4f1c7406b5d773ac2fb23b59e4d079b18f5ebbe6d7cab1441f5954684fec33a7d5c9a2ba1defcc08480" },
                { "kab", "93f1fe3ad15a9dcc4870c5049f8e2685cde948b1f001431ebef607e333efdb63c58032b3c00fcaeac7084e480e0a736e6d49562c8913bf3bab0417e71e561316" },
                { "kk", "ebb19bc7597d6aab86810b6d5a40d51326a46bd97577da775437163fa693ae53bf834ecb42e3a23c3525d188ccb2ff5174ef33b212b1ee319fd91f085b015b7f" },
                { "km", "2790e2404ddbf1afb9fb14f84c47975e1ca818699ab5a4752453b7474374f738c9cadd16ce0c46901b78356da5e8dd831e047a5f70d81169e39ac5bd21304315" },
                { "kn", "4b57faff2554d30e2b6436fa4d5b4510c1974bb42e534857cdc25314cc45c9d434b61285ba2f94613f28989178e924c7c7774de2363d92903d2f3c72e2c013ab" },
                { "ko", "a4ae377629862ae92f33686f0c2b47c41bc85be1990a1d43ae14d87f0314544ebb0c27d77c923a6d35c25000d5a3e9ab9b5173f5f5de3b5a830635bf59464f20" },
                { "lij", "dcd2ac88151dfa115bbd37a67d3f1ed31e84fb46fe0bf74c8954e2f6bda5af5d65dc024216df086bb4034c9beb72d4dc4fceaa6127e8878562af27a1470aac35" },
                { "lt", "92bcdbfbb847aba8f93c1ea7dad1914126101da1194b489e707e33ed32b671d3d2f465e5a827e83325e698a3e60abdda72af194bedd6ae4e68f1812093d824eb" },
                { "lv", "ecf6ef8043d5a51f80d1abfbff510ff7b8704950d66aedc07bf87fda71f3a64f3b71a4ceb46f4f26f6ff9518616d53dcbb594010c28c1419691d601ba2fcf0b3" },
                { "mk", "506ef1961aaa961afd6247a8972ef356a03ee87bfc0facaceb884a674fbc14d4dc4e9caed16e195b814829a7681e350308feb48369f936d5f52eb6a98f062a72" },
                { "mr", "6e0a695f475a72b34d474dd660926256d4df26b2b24fab2c33059d4ab2a127ddede1dd9903cbf621a50868b42630bc9283cc7a8e38a690075b094d37c08d72ff" },
                { "ms", "d48135c3b894920c53e2c671573981531434e7b51da902403a1d9a4b4f14747b778504f2eccf8524137af3ad39653f0cd7761d9282b211eb0d195f19c54f46b5" },
                { "my", "7672efb62c2447c1b9b6a9c93e2ab4fc587b4328e068704ccf392a3501684af19947bbf6c59ddd6fc5b43e67512c8a0adf7e882b9c03d6fc76c8d17cba3ef03f" },
                { "nb-NO", "0ab37cb25450eb8ca7798beb18c8b54b202e79cd40a42f7b6dc47b233c84faf13cb9f06e6f83685f91cb430fcfecdc3dcc8ec35ba22794d0835f7b5f1dd5540f" },
                { "ne-NP", "d87f90f6905ad8076515c25dc8ac5aeeed9549c23a7742c4984a6ae5f3ede6a54ddcb61095c8dcca074ce37688e16883de2921f0cb58ed086f0b4596e15caba8" },
                { "nl", "e7eccc76d0dd6304e3035b2622060b1572feebe64a85b78977c62955fa8ee006d49387c739a6f09b23ee3f3a61570a9aeec4a472f8777646e7de09c6f5312be2" },
                { "nn-NO", "05db1be71779d5ef70259bba47493f37f8122f4012b10e6d797fbeb6e2fb5154585eb3ce6c8b6bde6927f569193fc726b2c81e4700eb92ed60ddb947940acb9e" },
                { "oc", "879cc9e26e2f4e12d38221008c9762f605a5e05befd0725402de44e36ccb054129a122ea09682419533ea53a95288155f071ff4d1da5b010dc92049664a41a01" },
                { "pa-IN", "7715f47ee0c7cc1c059e71de69371699db861d5be399dd097184d888d2d6021eec173b76462c8997c2f269d6e78b0415c1d2881d3b81542161776aafef5991bd" },
                { "pl", "5eb0ff6caaec93fb2172d77f171b85a37feaf194b26e76dc363c28ad93e190b31f8fc7efa86c7080ad17e6874b591dbe276856976aa3ca1522da5b9c32d332f6" },
                { "pt-BR", "0e5e877d19c2827839a274af73fe3f8e9b0500f32064d03e436d64b084fdf378dcb3d9ae215c1caba2abddd712af6db5bd2379fa0f22b84898288e118ea3ebdc" },
                { "pt-PT", "37d779cee3025aa80f40133d382c7e327b206550647edad8113b73deafd6207983ecb5a8e872b8e675e7622a072e31e6f7a352fe3c35fc0a8703cfe5f1dd5125" },
                { "rm", "de185c740bc5d2973a0bd0231745c5a3e8cd049b9936691504293fa2fbc9388b847087f1be70085750701b9865e20a6d3e26a6f7e48133b39d7eb0d86aa60e9f" },
                { "ro", "7dfe9c63995749b87088a59a6a3e9deda9531d4c576826d17f41e2980fdfd11c49899408cadad06acbb140482e059eeb8ba368ed6e32ce3f848221db772f9370" },
                { "ru", "b4241dc176362268cd6d9ace6d034590ba80e9dcb31386dec942b760b70e9388d99f5ae79cad0c883870fc7c8f3ce87b8365995f3bab47a3250fcfd27d9e3677" },
                { "sc", "682618d492fa0a1af6b6ec153f11bcf287eb1aaeda65f5b7f010d1ca1a0bde12423e23f65bc5d0b663342215a452e504bfba57501a28e6a14c92d0b78431a972" },
                { "sco", "31514aaf92c62baccf599f2b0d6f25fe2bc950886bcb869c8a8b29fc7f3f39bfbeecc5a6d332d560442b50ea7dc73fcd05fa24c8105c0bec6bfbf3d52d6e68d2" },
                { "si", "18cc95539a4261666e9259904553d9c51e3257cbea72fe75c12bbf55be7d478564f7d6576049c4b48acc3a23a359bb42dfd0a0bdcbe11bf6ef0bf665f85447c2" },
                { "sk", "61f1c1871d99eff053ce9bf965024aaf92cda7a25c0434d7978789f07b995b97e63245a0e5076e40a91938348ce93fb478a7cb0b8576468956d7e794a1aaca20" },
                { "sl", "a7e8b2976ae8d606a4b4fa7b60ef6d85de40c24f9f7aa5c7637b4f0fb5176bed78b79d825b9fd684244c443f07e4ee083263ef3f0bb3ad27a8c73fb4b4fc8a41" },
                { "son", "50787edd8d9d85c64c0b1c7f3fe42b0891faa881177e8d7abb5177a261a7d003ba57e165dad7fdb64ce679e1538da4c541db2cce1007e7b5b87ee57efcbc6fe7" },
                { "sq", "c577a1fa426c33fea27ad9e09e7bed9afbd832784dd9019a4a92f4d534082d432e0af83bcadd5bf6a99bac785a9a8b6628071e4b46740e89b6e6959852f50e29" },
                { "sr", "e72c195ffa9134564ea69071761942ff69f20d7010c482db246575185d7dd1b51f1ca42b79cf9f2bc2a26a1116267d55ed74a36364557a02788eb16e4dbd1be2" },
                { "sv-SE", "741aa380b91e68069615edb4427c44328e8883e3a297c8914bd9b1898765864abf57eec7148fa2998e4680980586ea8e3bcdd08606eb288e021e59ee76b7217b" },
                { "szl", "8c7d4ea016eb19bae00e59d4ad8da9f02fb1da138fd679018cd84dbd8507c59f65e0c8c1415619ddddd8a2078a4e421482f63c72abb0e77391e57e11a0436211" },
                { "ta", "2123e27279a7059ad5c53a21ac8e6caac064903b78ea6ab5f8cc14ce18383a7480b1dfc8be2afc926893c9ff69a18251aaebceccacf58778e121d46ea0d6d981" },
                { "te", "32e476e07e1e7a9ec5e0d0030498154852c6ea15a24fe4226364af9961f5c82ce1220412780394bd6a08991b84915a0e9c10e8daea70cf2cddb42b1cef90aca9" },
                { "tg", "0435232cd4b7ff17cca428778aa2346f66b56737e5c79b2632162446a525a82c8c6f476b9d74c2f59fe5f895d364a5dd1a100eacb4ed77a7b3df9ed321b7087a" },
                { "th", "cae31e47a339637a8536e697e36d726e53c4f9a6d1f8fd478626add73a064d45e0452d3c77ff19503715ba9a94677619d188144b810e383d71b2e647042bad02" },
                { "tl", "fad41104ca97522b467813294ec3159b48e117bd3097793ffd85ab58084ceb9e11af8f288907440bd6b9645989acdac6119c5f8bc794487fb1d861d1295b5fb9" },
                { "tr", "c60cae571578e2059ac4b7d4733fabee8140bceddde9961b0de10738b4417c8bb6f4d1273ed4587049f1d7ae09b266c35e63a4d6d800f65e6886c3eb56c1e080" },
                { "trs", "f6c7efa9964971fe96a08b14905caa6e76c97d01406b6969622e4e9cd4d4a7b566862c6c9a6e3c267490cf62c4184d0cf7d78de309f4595237ca628f207e9a08" },
                { "uk", "9d87c5ec4ed2ccdb92dcd113387110dde48916a2deb0d4493667be0da4201f7fd33656bdc27c9ff56ebff61536cfe4d79c7b493c5bfa036929fb2853acad8eba" },
                { "ur", "97cc77f8ff56c7a765e73370dbf70be6e0644c92a2401787129facab1b00cf5fe2935520cb74a55880b81cab1caf8f3b8cf1f1a77907bc723dbffd7154c3a388" },
                { "uz", "2df0abf8107fd3e2ca47edbc33a0d4a760b1e3fd49edf2cf1d8af961c66973b920a2429e020d76b47fea2b445b4b4c2f87d6535de03d261edf308233a58bad5e" },
                { "vi", "4b73b0474920de45ce161f95e936670502298a8395493ba56949cf6f724ba9ca163c5ae30043e50ad846f2caedff8ff9b7f0661744646e7a2779b445ea996f49" },
                { "xh", "1a69348dcc73e132d16fdd933f25bfd50bc3bc987c9761092a937d0dae205972d33cfaf2b17e74d0823b795f6ff085cc846776416ea831119e9163e37533bdcd" },
                { "zh-CN", "d9902862fdc6e72fec4643906d0f07a9fb638df1680bac5d217b1e7501148455117adff35a85cabf7dc143361772ca87f2421d89cc15413d98eda66abb9ec230" },
                { "zh-TW", "aded051d84abe821d998f281349bd284eddb978f9d57e857ab03fc0f458b1f769940013dfa57374a2b3ff5052e0948e6d8195df40a601923b8ead8206548ef89" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.0.1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "a56724e1828fd82b86583174579eff97235cd2dfa2d12fdc519970ef66d347ad8c45cd3f3d52778f28d78c479839a6fcb60a9f0108816bfc77e15d1b282c5862" },
                { "af", "f6a478cde533521432d314a1025df50c6594841226d5d3e39d2bd2d0c1d6a99cd43ef53867ef8aacb9b2bc4b28289183e95e71692bccd0c8ccae84fc533cc137" },
                { "an", "2b617493931ec1109dd822d0744d94f1542ed8fb3a074e4c2e2a5bacc5fdab66cbb5f56615de317b549f257d583cc071c1cd622094cc6ceed641af111d66fee2" },
                { "ar", "06c3e6e8d5624d0a437838824e55045c5affaec22f5f65c0b68fe929ab9c81962468d78fe44f943df06a8bdd3d9d0b79a832131472a83fc2c4c54c109cf6aea7" },
                { "ast", "664149d760bd8d633a4a4bcca3f436de645c2f4fad70cc939f2101198d2bdf2ab01cf1fd508497dfa3b0abd23b821ae4242e4f89c4866e5f1a5ea44ab03bceac" },
                { "az", "6341976c9906ee1674332590b34ad755f8b5099e56206d0a16a4a639dd251e00b7026f62e4e56ebfe027f1c1d1be24fd55e314d5e6362b541db43b2f403d7e8f" },
                { "be", "2916a8f5824d5948c9e2fedd9982f41e8203c07c303127cb735ccca87d0c4842e08acf064d1078155995107aaf9cc41aa4466fd9fb24eca01c25271764f2e039" },
                { "bg", "e2d2bcc8270a4075d10687693b98ac418b7db700bf32ddaada6a6f3f898b1c12d1885e4d36ed20ba30fe9efc6b317fafe3ae50a8a8565ea0dc393ccea13a0756" },
                { "bn", "59dc1793461783806255a3ee432fabc253fce9c7a47ef2513336610006a0abab8d28391747e982101b6ea5715f0d078e2c83788b059efc3bc77cc0d242fea9fa" },
                { "br", "19916392c48bcfaddd0719875ef1a69459097fca416c66c52bd9b66da41e6b03c1111cdbbfbfbe666318c4230e01d1eeec83513db292bf20dac7ffe7eca73194" },
                { "bs", "ba79da376052f5d7a40e1052606d7e98ea3f0fbcdd9eeb7e4e0e2fbd5fd7d34c73d7072816045306aa90a7cf74f2387aaa74d9889c68b2b7d0d0706ed849ef35" },
                { "ca", "a0bd2731fc6ebb751c98a77d3678133799400fd23ca48b92499a8cb658a4a3b5317e28d35445f9567da09ef126295b7af51a441ee9fa34aad00c2f4869d0a1e8" },
                { "cak", "f8cb4d203d81fe0b34874e737e15cb4f2afd89d7b7361571592ebbd2dab25f1039e31b774152ce7fc9050f72e47537ec8ce120a345c94144e8d0f894ee359f31" },
                { "cs", "5b7c842d1581e95e3e9b62bf79d61cda2cd04c3a4146e04e118508c4f4c4d231f87c034d11e8888fa98292caae9421cf839374fd59782747d9001a921735e7eb" },
                { "cy", "fcd00324a1dfa36521abd4e6487ef6db2502089d1f73c00b714e30abcd33d846ff21cee108bcfb7ffabda31f3e350c6113a80f5b9b5b9c47c74a5150e3f025ac" },
                { "da", "10c92a94d3fdf431a436163565997af0d65c5a17e30d0b07ec0dfbf80b4a16147f18a6d30b6a84bcf47d11b1d885285331d00c94d1af7fe2b03af08e5f7504bb" },
                { "de", "b4d46ace386d6c7893210da1fdd86e652455c6e4411be65d8056f562749c1f166532d50cc977675cc334efe42c28d65610b70104ee8d5772eec56af139a6128b" },
                { "dsb", "2fe90dcee22a01aecf02f6d910000fe997e33e313addbb3d3a61467abc7a98d1673285707abb14fcdfe8747c6a676848e20e735222004a575216739858808f1a" },
                { "el", "68a01c67a652ba0c993a7ba23921b3179edc65084c1ef25a930ae581d11d0f777a0ece3c566a51d8dfe0455ce01709ff5a68a5ec663d135b1c91b658e6c3e33f" },
                { "en-CA", "5b70f5b4f4f9f0d8684e0607d593e6b43a49ce45c6c34227ed93801a2c18fdd280028705a006d433f68d14e3a017bee352446f8a79bf252749f4a99f570019d1" },
                { "en-GB", "8ba7f33d39484dbfc2176f57298060e22f349df6e97d7b663a2b323587f120a3fe117b7ee50bc136cd1e0d095210ce2e4c71a997a0cbab9c4cd072faf1eefb81" },
                { "en-US", "44a96ee4cc917085102ae8ca21104f5f3d20d1854600815f13a9181a428ac4f83a140ffdaf9c8045c301a66f2cc6dcfb92c26f8d6ac4f6185060cf67ddf3a967" },
                { "eo", "ba7a4ddf5443f1e3f569ba861a6adf489599e6e530f8f3e073b4ce78bc9c63a14893896ff513a950274cce9517733f6069b4da64fd7ab38256999c5e9f794977" },
                { "es-AR", "931275b1f89c1dabaef0b0d3cbb24e2475a6605a07420139719ad2397097db50f9a9e4bd178f10fab712c5f8315643e1e428d93e3d03ac08a5e2285e69e3f024" },
                { "es-CL", "4545c95425699115b554891d678f1a8403ecdb0a1806d2dd8ad6337ce3a3d9bbb0edf165e070727f6494fdec716a370c9aef20d2aaad2f798601b1b8c826cd40" },
                { "es-ES", "77036faba678feb7f8e03d0ad54b8f11304b1b2cd1cb86f3240fb698f748d74cac07c79fab1635849a99ba78f8924d60de9fdf9d262c45af60b3121409e4183b" },
                { "es-MX", "6b79bee8162eff9d75b2f5fd3a0e94f35edf5090b59d261415253824654edcab7b7c0661212fcf0ed47badbf5a22c93180f98bbad27b1cab9f6f51872cf9dd9c" },
                { "et", "08f6bf4fb5c338d87f63958301274aae1544218ae623a23767e843e078724eef8b1b876a26b8bed1c0180b37d8f5ee09907a14c79ef01f6ad3b312e2a6096f2f" },
                { "eu", "0896f889188779e6712863d0a287afb2fb1ac863e3b4ff13bb9d686595992f638e17d9997f16de6f19b55a9a896200c918bce6ec6d041ec49e55cd1e10f99c49" },
                { "fa", "1f4d03bd354ffad397f42b012c4797c098bd757e78589916196029a85687a1d3d450648b7ceec91b3829e536b910b42d9d6d67ec8a4cfb4dce76745874e68384" },
                { "ff", "de8cc539529f0f6c2d21397465aa1e9f07b51da4b5237ab83e1461cf04f4ce9c134f21111b4f872b5d5ffda0d516be67c6c853d6e394a7e09b8a86d919e997fe" },
                { "fi", "75289d324f6a46a00173d8a108ce7f771d2b3dde3845247e01fc15e9242dd11dee86c8ffa354179194326ac7159b78bf009e5080ef0f991cbc63ac0bd4df2809" },
                { "fr", "d23f85488af82e42523adb19e732bcf19fcfce700d1b5563fe2685b2f5e25782f4705dd04762a5d54e424e8f4457c7283261685bf6afdf7f5e88ba68fba5208c" },
                { "fur", "aa9de7560df2fc90df07578906d9e7bd3d1ab71bc778059574ef1094625c8198d8ffd0a1e06298a891298d988c24be8b8660a33a15afaaf1db9d3e187032dfb8" },
                { "fy-NL", "50745298fc1b1f02ca13e44b3e32fc1f5660cd996e45b55b5d329789a558d8f7f799a5104947259f9ab02c7f345c77e1b2d2e3f9c9413de54f8f089b63231918" },
                { "ga-IE", "448dfe4ab67ca31426b7c9e60ce4f3b9729ce91f377a8abaefa7180741c5cd4d4c319a3f15df1fdb4188b701c6af058f02702aff09c6a4d9184c01a5b9cde1a5" },
                { "gd", "aa61a213308c34208b76217b2cafa01d5a705afd7a3d02130fa115f5acec3de6560c55edbf8ff34c72db021dee88b5f99336956b8359206e67aa4c5a7078a56c" },
                { "gl", "5559ccf6fd8f71b2cdecc632ec1612a56a8f77ae7d9085fd4235834ec487568b68d94a4402b3fb058b97f24c4a1aab346e33065a70bb61b2e2254ef14fd3c0d2" },
                { "gn", "65d23bea5452a2dfc91d6d5dad878186cf9bf5f7d7ce54136a9a74be0744bc5c954f37478f1a901c1db4d814f0df9c851b1d12b7119387bf26892ee8c6ed74e7" },
                { "gu-IN", "e5d0cdd80010800a17d0c9a1bc50199513d90263623ce120faea3ce96bc2f2b0aee02b3ffe93495fa725a597ef0c1de2e6e769337910d78eb111ac023dfa38f8" },
                { "he", "a2536098bf0b28d808e334b245bf706a2a184d99708295e68918bd513ab9cf16a737ffd6dd9f66df122d056a87a161914e0e7c18b69ea072676adba0237d8f1b" },
                { "hi-IN", "e399a5f5e2cebd8cb2e2b9631059e628d988d507ebfc04621729e5ea8b71057054624a42b31630332b484a61d972e583ec095b96f33753d47619a6490d1ffcfc" },
                { "hr", "53a828cafafe7100312fbea09269eb48d9678a96fcd882c4660a378d6fac7392a0ddf3d4aa375832054f1aad21955554da7224cf1085d2f556318d167178da5c" },
                { "hsb", "e9042d6ca8ac3b7b8e2ea39dc1429cdbdb9b1d73a68157d5f5a3e08ae5e2096a6f86f09fc0b8df10c57e69e4e41733d5d7842799c6ef3e77e028662022e2c7b4" },
                { "hu", "9642ae00d5c332b4731eee64724829b9d989b604ac8550e15acde93e3e35da64812eba46690db9065af7919c67dc3c3b00b7b0bb2b9041640570654fd7759094" },
                { "hy-AM", "f70d86dfd21ac9c28628584be1f38599e258ce3ca7d835c82883505fef6285b01015788e0bb4d23ba8fd8f07c3cacb722415c8241b9d7535d2885176424c078c" },
                { "ia", "47b657c26b923789b272397c62234d6bbb3b37bb76c15701400fcc0ae5d31ea35e69f91b7b7f5f76fdc023d69e148d85c163778adfee0b15955454a48a20bed5" },
                { "id", "2f115856253f7598cabe1b02d52b1d7f21c75c91339f2eeec5020babaa83c4a2523690b3d94ef293d790211037e26900ba45a59707056f658130d5ee9f47b391" },
                { "is", "49107250752752ccd0b25b8804e6d78f63d2943cdd0e277e860bcc58aa874f6a78b7986fe562f2fef8f9521fdf668323135a9f95d00bb036d5aa6e5368d26bbe" },
                { "it", "01f5e621d14451ff50fa43ac60f6217340945a87fbef8003e6b8c5b77c59d0d671daa08f186431f66cf199de851ef6977731e66eb8960e4357e077974c16c62b" },
                { "ja", "00894c6262eff6cb509dbe617bf0981d040e816e7b356c92c34ae5c25c521578e7d787b547f37ce50e53fe0d39f0691e040ce5094f168b15e827bca2d4f5b524" },
                { "ka", "18b9dcb6f545429387bef7568c48c204076f92c5a0f5f70149d1b31abcf3b25b5e6f06f1f85fce7f2be77ade9f1ddfd7db1537f15269fee44919b05e7efb5d45" },
                { "kab", "114e4d8c3e979f25333a4b40fee5c0d38dd96b6ec5984c7ba0d7507c2d2dbd67564a2ec50a5cfb36d008b6daaf64f1ea8c71ac413341caab11d1278a1075238c" },
                { "kk", "2b2f6a3c8813dc6a4cd0195bd80063ed71fd8a562c34ce17b15f5f23d893b0530ce4f0fc99bbcb02ba389e101bb3e6bc615295c841bf84fab44cf01cbf8f6e25" },
                { "km", "d2e5cad682792fbe7eb648e42390cab3fc94461d56c0997a6351d5ccb001d05849dbff359b28a75ff44c9a6673049f6b88e9965892725b362999efa4f03d6ccc" },
                { "kn", "f13af6ab75e01aee920061ef859f498099eeae4c1d4d463fbe4a480a4907ba1184e6233e166cef0f30d9b1fe662bc87c87fbfb42b27f9ad07fab71a235790136" },
                { "ko", "4c4604b3dbab04350a012629d7a929a0622d2bbf601baaf613ae0bb719147f89347f4f73081f587de31bdc44732cea7a89fd0466164ab52f90240121dbd009ed" },
                { "lij", "9ed8417f4a7ad1bfc5b51f8f468533c52feb02265e9a5b7af6e682176805beadee497b41cd6da816c45576e5fc397df937320fbb20de261317e0592c181022a8" },
                { "lt", "d6f861c0698b1c4902b8db6a900bf7fa99960f62a326f991520b086dca0438c2e170e2ccdd32abbfe5500378aae79ea1d0ced6a2d37b0b8e83d5e8dc7130ce16" },
                { "lv", "e556c05673e83973415dd0614c68c8d4cb15dc7b1817c34a3a2eb61eab976866bc19efff4cc01379b37f6e92e12c4a1f9e4530f6d51f46bbbb94ca84e9e3c29f" },
                { "mk", "bd6891e72fedc826706a856b288a3c29d650b1c406f2a45103614e0191993dcbe2c08a732886674c070867676b5cc6829651b66cec2a8487fdd795995d1afe31" },
                { "mr", "a3e3789a052ef824224f92a14bd73dbab839de104767dc860598567170127c4e15e7b92c8e9760e186bc639944855044246a3e37e35a8681e392b20452f3dfb5" },
                { "ms", "4e19f4180df3c03fa5ef44b810b820973a79ff2f2e4f37959073e33929935df5a58ac068530b9a9d4feb75fbfc315c768f84f14ad40356ffa6701f34e71a4a31" },
                { "my", "f3971412f4a24fcab143afa30e30b975eeeb6780922869355663b817562dad4615f3b6073d8915b2e7f9c8ca66a95c91ce22c7651a7991631ed1e2f96faddf19" },
                { "nb-NO", "b24b3c56c9f2d73034a1d7ac572bbae219e3d63ca861217d42a50a4ce2d5aebfa9a3d4e80dc7b4e1ba745d2793ebd258fa0ab28ba18c72966c43665959c019c2" },
                { "ne-NP", "f08586efac44a3358d8e4c37c131ab77953514015f430fb53ea7b57e36f93de611dfcfc5748871d595e2b0026086d14f3a333e56b400d1bbcc960f9a1522706a" },
                { "nl", "6e5860be46c026285238e01b77fd0a078f8158afe043e3fd1d2773e721abd59e2d1f630b0b621ee39286d95e53cc660c44def99b1b897708ac49d5d55b9b094f" },
                { "nn-NO", "d8387e92a04a5a8a671ec9dce341eb4d66a8bd535a6bf49cf6feb6d7621b15d6926f4a79f0bd6b80486280427705de7e1c85256615c30f9fcbb9cb1f75378678" },
                { "oc", "f7f0d226158af33257b4ae759d5a9c51d65a35e107b89f235eb2c168a232c6e6a50f951a6f67097efd6cc8ce822223a87e5c86d5108d94c49f946ca33a398f81" },
                { "pa-IN", "8e046f7718c494d20f871df0dd1906bc80585be7d020484a964968c0ec66e59c422c52b0d50d3a10e88ac991458e3dc50825de49c1505fd0d2f9b0db1dbef292" },
                { "pl", "3474e23d65f01af7bef9b523dd2431a6f011beca988d473e7f3b82bcee08c462fd59743bda72975cf2a05517b52978c411826c38536162dcc1bd3b98ce744de2" },
                { "pt-BR", "20f95f9767fa7cdb5b017068e8a9992e6412a7b8d69014b82b2ac22fe39edd59200570d52fedd2d89a86823c4ddef15c4d203f4e6001226bc7aa30f0ce7fe51e" },
                { "pt-PT", "0e0e5cbcba1d232b48d472eb37bb4de40eb9ee673ec1d92181b6ec1915d3040be71034d2fe9f0194aaf1e62a6a7785cd88d857a62ebad8ad681cb337886c91fd" },
                { "rm", "c7b65ef8b793c138d2f5fb1a1c1c27ea7a8b71bae95608e21f4175eba3cd5bbfdb7c9abf9220d41eb9cf729e06d5c25ddf29a11db3efc3512216b2beb7dcdd5a" },
                { "ro", "2638a6c2133ae72c66a7f761e9a16914f74c279d35820d16439b1634f0962eafdd48d8bf413a7884188b8a68e118e24dc1273842130597fed0088926b2d1ae9a" },
                { "ru", "4cc2353d3445b90c05eef2157d5290266989823504e77610e2add8bd4ae1dde0abc20c55de8f55d417b0bc3261cbae3d7ffbaf5cf7def20026bc9c29ec7e1c89" },
                { "sc", "d6c26207308e7c298db53df211846f2fc6b1ef9e6fff329ff88ca08b58220a430d33cfb3f031f3b5925b0078a44507750f1028e59b8ffef8c1f0f5d0fd26f29f" },
                { "sco", "d2618b87a53a930a0f5bc462c4a2743131c54364bcd5d693a525eb05e8303145649e26366090469256828648ea45b5cfb36fd04cfe1295330fa4154cf61a3b44" },
                { "si", "0dfeac0d7858021e82769e24b17b94002c6acb3fc9d1b23227d2a4449613d95175543aacc890811b13963a6e6c2a6a3290150a3469d8f8a1a5501956c8f160c4" },
                { "sk", "1169dfeee996e4c5f2dec1082038f51ea8c5d6248c36a3a5c78ea6ddd41824f18f4ef0ae95efa579992701afd33be5f8404e15f7e605330c1999fbeab25123c1" },
                { "sl", "6468f65221fd3a2d3b8228495c6468ee81aba723409324cbbfd7f11e1b6245ea1d2b82e93739e5b963398d000689266deeae27fe6d2a4a31830494a856e4e8ab" },
                { "son", "9477f8dfc73bf2ddbee9ef559f9e6f8424da497aaa11c4a6ed6e37af53a74a2f260d4d436c99ed5abb527c776e45f3b2544c7ddfd07f1d9c9ef8943acff65f11" },
                { "sq", "c3824d894ff6474085d702d56fc90af2b993f183cdac40b54d2802353ac3f1c3f0bebe987287461e09b436facb129ca40420457bc4ed3c2d503ad2ffe9e4e7ca" },
                { "sr", "811ce92ce7a893510f9a8d6c7e6c7f95abef4b81c9d964dbedea3f5f7fc43387acb98f93134a882974d600cdf6d44ffab71676334b4b113c60d0a71409824dad" },
                { "sv-SE", "5563c9cf474d66167f5d730e1fa7245efc659ee405859562f611b9f35bf7e83b18ee002b359119eccb29bef4514e36ae412be37f33dddbf388358cc2bb9555db" },
                { "szl", "12449128e0d4a87cff045d7be745edc7d80bb62353e36c4bd3d6374c07ace10bb52796f80d650acb280939360a98b65e13b1c831f82d05cb5c9bc9d186022165" },
                { "ta", "0bd1c6b56025df7af0d0e7a2d0107cbca7c51498b5aa1ab6fd64316c0067143e2bcbfe2234a8ff4581079410b0e2b4dbba82dae095b190b0ac3d7abeffc5771d" },
                { "te", "7d999db38d45fa324b16b73babc6c6f000973ff7a4b0ddc963e513cbd1daf3a85fcfdbc111f9b0b84cf6aac2f87102bc2f04b7ca16bdc85b1395441e317d092a" },
                { "tg", "5c08288184048f96a1870f861b294b076caadbdecf0d7461f67e4e7e4ac3b86de088b826e92a140f7c907fe058c9d570a06251179b6727e146ecf60fdb9e8a22" },
                { "th", "4037e07906580e34ff8a6b061ecbb72913908ed8ac8185952eb8ae36511132acfa1d38b6bd09111a67faabcbd387c64438ca240e0c8da323f1a31ad58f248215" },
                { "tl", "82e2645605372d59af008535d4c1b27ad4626f6b0e4258b22245961a0c539fefe093cea3cfe9aff1b227f594430afc76c49b0fff0d10cb2226ac30eb29e32be0" },
                { "tr", "fa2bb1edc549b876d1436fda9e139f6c70078442a034eefa666874d126804f08b9acc4d0f0eaa28cc339605643d3fb097989374e7c53edb0e7c798317f85c015" },
                { "trs", "2ced9cbba05374a7f91b557c1623325818cc1cfba9b8acc575c4b2080a9c5fa022ff242e96cca6f353c3873a1321de17950f879700c72120cbbb755f96ffeed7" },
                { "uk", "5f336503f2a75aa975cfb62ff41102ef04a9436088fea1b27d51b9b56bad120748a58bbf5688885a57af164aee1592fe0febc5d200b5a65a76b8d8f28bd0fe59" },
                { "ur", "99009e6fa2a6ec1c1e613425a79714f2398f52c308390e10191301f2f52bb2b2af44b4072fb4f922ebc9c157c895a0c5d56629645c1d47fb20d5fcc3e552f97d" },
                { "uz", "7a43796b5708a682e2b1258c9df04b812edc2b950f7e9f6e22ded32fe31b9840eea972dbeb65fb70997f0d4d83f9e79ac35f09b6d3a5578af547df048a8c8922" },
                { "vi", "82bed1e34e5d3c04fd6ee783eb4c972950ad40c5e6756da57ffe34ea40260dff510701ab0e8604effef19ec5997ac2f2f156d541aa144cdffba3f0916ef0a783" },
                { "xh", "d99771c3a82fbf890f353bc21b6620a719433067ab4de7aa84fe1c719fd620c1db02c979e06ed07fb3492066b19d74f871766dc8a8ccfbad872807196c1e0561" },
                { "zh-CN", "9eb2bb04d9da3a1aed119e0c5cb8c62d3a190590dacb9bba8bb16e294594ef6cb880c64e631fde241b51d85f8f172f0e18fdd6b6ffa54115478800f621b14318" },
                { "zh-TW", "ceb24247aa7295fa5ff56b262ecb043ddbc723ebbc5ad9c9dcc61045d6fe05fb704900fc721f7da59091076fa6553659c4005ae31f27f1311c36c56c132719bd" }
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
            const string knownVersion = "115.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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

            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
            logger.Info("Searcing for newer version of Firefox...");
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
            return new List<string>();
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
