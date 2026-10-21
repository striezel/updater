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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "153.5.1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/153.5.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e9642c5e1dcc183a7daf540502c20c0d4b4389d4d69aa23370d67c579c49ee87ff51d82424b23642f89adaafddace9efe59fa239d47a09f2ce1b629713ba86a7" },
                { "af", "8429aee3e4bd57fedbff25adadfb9a699c4943b5f298d8da2ce4aa59d89a3feb74553aa99807894aff38926a6b84451f6b5850d1a0ec973167f21077cd391489" },
                { "an", "c1ff9d4217fc7e10590a1d95bf8b271ae47d41c7e4736f374845d8a09ad02bc7803e73ed6fbd8e1131dc6ba45c48dd6f81d385f91d93839f4e632164ddeffa18" },
                { "ar", "812f131dfdde65763fdc603452ceba0309077aea23a053e309257d4a178a6e4a4234a8a629e18d83d6d237c5758af76fe2d298e65df400a2bedb4116ad0bbc1f" },
                { "ast", "9b46e9c78fdefeaf4f409aff2ca18004ba03028fcf380b39462bc284e446175f3c56a3349e71f7fb525e9f64f9ae1919f157af1f6b99a9c9f77d1a113c94a34d" },
                { "az", "4640d921776b9c4b25065af9d3a01b73c5aa1b4da55241032a056acf557d7dfe77c1e3fe2e5908d0e9ba7e28451d0a49f666f96e7e75fcee5c1568f4dc1b29ba" },
                { "be", "1a476c65a48b3f2327c28eced152bb223c3473b5ab2415ff616de97342c3af069b23afde6e57fda086e68f2d2b85888d8063b86e0466a6d1553d7cf397fe1869" },
                { "bg", "78b41914dd15580b5619555e05bf7f1151f68e0d5e201c152bf440ef3a381f9883b77ef6a9f7eac8eec2fb15e704bc62696215bb8bb74cb94c2fa3399f35479f" },
                { "bn", "dc949185a4bfc09168bd1b99a3913a7840ec25caf9055ce6efd0ce03b97a4208545ce3910315556b351392aee2a68c7c448d58a13fcd76c96a5ef9de7fce6b23" },
                { "br", "1965f1380e22253a2ac9a904a29484c299ef0a2f9314c0a098cb2d1baa8e57d6336162ad9366c63a042cefb9d55102dbfad52b680182061f950485ea400a6943" },
                { "bs", "fe4865b484391c383785510fb1a4888a35dfc9a466bfcbd081e81e81ad6cf7812c197b860a2a82bf08bf312a1e6a1bdf22df971aed3eea561bdcd9473d2e6fd3" },
                { "ca", "9390634860522b75a7ed660baa25eec3948022cb490d33be8d154aaf44f7ea755fcd98edfbbf76e175e49931768526bf2fcf0d52d184b3b0f2ab3395c7c922c0" },
                { "cak", "dfec75a0a6970ae1c600bfe8381fd69676d1b3b3fe830423909b49745731203859988e018a9dfe6992ca6efbd2c1512a12a187456804a153cc2f88f2a883e3c0" },
                { "cs", "83a5c3864c469556f00b6eaec5dab7f9e8f47ec9e072f5fddeebfcafd5b10d02f80d9da45581d14ecc0b55ff062f059bb2162a765e2650f173684227c532d631" },
                { "cy", "d28017b307e72100e4624eda0f9afb0ec0d311de40b496867be7957b6202ab765e4d6ad1c91d601dc9494ce6933ffcac4d13ada0de2dcfeff65cbc8cef40e321" },
                { "da", "23d00ad6f75fbca3655bc6ffa5fc2090dea257ed440f63af09a007c4b29289eeb5d5766c85cda0d27ffda2dca7a4b293a166466d77babf3d58b3b7086e6f8572" },
                { "de", "e26640c3ab121328dac209c5a5bcd43dadf23683b3e4146c803936c1373808607cdf4216b4b4915ddafef7c7def20161dde4c6cb97b088294052a2532c1e8519" },
                { "dsb", "5f204077a7e0d13fca64c04f52a2bdf858b73d50575a99a9a5a05f068ff739275bd1dddef5e0548a87883d7480225eb3b202d4fb53604b12e0fb8c35e2457dc9" },
                { "el", "03ac747b7b9b09d6d984a2f8b6b050352efce97a8e2b30587bd141071b644e5c95136233a9443c8db2b2eac987054849a882b32ab0f09929c79db0c4e79274b3" },
                { "en-CA", "fc8470782c98af7b160548faa65e96476d1bf024de32812a3baa0b08e160c985c30eef028bc9f257ee8caec730ddda0c1d9031711d5bdcdecda6ac773038913a" },
                { "en-GB", "d4c67807ee843818196fafa071f0722bb6e81303b2aa73b180e50471d2713c8112d6ffa51ffa367d276032b4cdb81942b43353ab1b5d1df740f08bb5da487823" },
                { "en-US", "57a6bc8781ea655c925011a5d0309f8311e82d7058bffd99f3bbe7a0f16ce6ac495484f4f0f7e67abf3d13a2ce98530577df90bca9311c04e1d1f511da942ac2" },
                { "eo", "e0ac296cc71e93affef6bb2d271b4d53c8c749e1fdc2dc7e682b3a02ae6719f9886e5ab3c4f0530152e9820073ff527664fb44759868b4b00524f6b97c944239" },
                { "es-AR", "8bacbc9bc4a632f766ff1cedb3436c001776e5717af9abbb89836ab9ef5b67f91ddb88197b6b4f4a813fe8ae38a72eb2a13612169b1e1807d2d679d81728984d" },
                { "es-CL", "86e4776209cdd5f770ca2208ba3585744c17c99bd2bf9688c732b11ef4dd59ed8e7fdf64cbb5aa550042f9d21916f3b8f1bde1febdda8fd4c9f0cf837427814c" },
                { "es-ES", "9a82d7de6446b2191db9d3e82141872c246d49163e9a6325f44e4eada51cbab78e6c76b946ab16a7d3b187c1e82bf5353e054fb6cec08d53300f2f3ec7ab6e28" },
                { "es-MX", "1f716d8a9d30386113188c21c6fa31571630725c3449e49c69327fada617b4c22876d68ea43d36a37433d1e5f1a6b139f85bb6d23432bb8b3a2a99e1ee291209" },
                { "et", "d4fe289f76c7c0f84ce3eb45b9ed153d7d8e2826f213c1d69a4c74ffa728dfa05ed9ce1336c94261c867555a1fc3fc5128d204b88d62ed1d9dd919606bd12754" },
                { "eu", "756fe3a0e8aa5c2ad9e54fdc9c8f67fb10c57ad45c5c66c9c24e20f2e735419e51e1de74df84be72258a4c7963190f699b939b88d1f442945a7fba75d5421e65" },
                { "fa", "06c189dd2a018ec953eec9c60df92a63cf437c06e9b55a0e19467fe96a41b5d5da3193dc1b3bd8853a5e9d244a6ad2638a63e8eae12012fa75e28a0dcebe0d6f" },
                { "ff", "e606d5ab142c244b610f31b5eaf0c306c28eb346dc8c69f2ef0e25a6374318730d8daee7f43b1b3234357dfa8141811982d2d45d145179e84fa80b9b21f8adde" },
                { "fi", "406c9994f94db25e58263a818b68448dac82bcf412304709349eed8a68be9a2f6e65e98d9092a5e580f02e8ce910709001d92b5dfb1b5c4ef1cdedb9a4ff07c2" },
                { "fr", "090bd00ef01dbf6427aa6444072d48e22f548a2eb27188cfd9e2102b9dcb2cce856e3dffffb1b62527ecd129e20580c8fed16f4beeac5c3aa3e6403bae0c8899" },
                { "fur", "347b06e0486b107e907035dd5394ca0ac8517250fcc948f66f67841a620b90dbcae37f3a85fefe8b38967441f2671ada8ea72fc8d3bdf1ea21f46cd84d101625" },
                { "fy-NL", "a3ba154cbe41de146b93eb4e0635fa74f07d3f42f3474dd14e4ee8b95d8ff59d084e0a18c5634a5883ae82ba4159c1808b258d92a0e41629e35712b192ca2400" },
                { "ga-IE", "d918f7920ab5797e6d34173a6750b3b024943fe2555f4ba350d10e54d0b29b73adeeec179c8bf9874884f40ba1fd081e10b1c561f92f559b67bef9f92051e04d" },
                { "gd", "49ee8d95ad3b2ae88cefcd5403c9413945270d4b2fe7b2f1c4ba61f2d6cc2b1913ac9185ef2649144f19f888ca167f50d05c374abc275d116fad9fc913ed389d" },
                { "gl", "b981952ce0ce5b0e595e3b28cdb74dd4185fa4e81fa2b418eeb619596de558bba90737542b7ee42e5df7bd76b7d67406d6cdf1edf0655476bfc2312c0de84f26" },
                { "gn", "e0d0c1f69e315e12d394fa6a03cba8583a8b807b9c6388102acb335bcc779814528a85c3b9e73e25c9caf4bac3a5276f47482ac52d4cc902b463790062d76b08" },
                { "gu-IN", "8b29150fd8e9dd6647bb2ad6445e2722f0357fd842ac773719c4b1135cf04bd20f366b88456e9a9c2bc2723d428f52c98b81ba54afd6b644867b75b10613ac54" },
                { "he", "687e88b68c4a006c42a0b9aaa0d799973e666400bc7767279e5b69af72295610472b3da932e963cb9be3134878735b84f552277fd74de29679944329d1624c99" },
                { "hi-IN", "c5af2d9f6c5eba19e7265db654fa8e933e0290e0924464c7a70ebd1dd23fea1327b35c6b1e44844cad39b5c3c072781636b27cbf90cf4664f65f27827aea9a10" },
                { "hr", "87f7c69aa7b88669846ea6a4839baf4c92783894c9a14e0a152ab8b7e4a71fac54bd82af3faeed4c1e4e6be92257e2e39a0ec6d1c2507788d2f761eec852e5dc" },
                { "hsb", "6825e92c6a3d86d78378b4e6ff7030f8b75bb0febfb385520a86c8aeaffafa97b86bb5f379d8de3589d9da2aa903ab076aac6d5abf45bfb2181582c0c0f77d6f" },
                { "hu", "33709434f07c961d6b38e06f0ab0239966f1c3d35cb1116a527f91d904cca08d437f91ac75a678b216328eb968c88a2012bb3f402234e1b005196f1d0ad335d0" },
                { "hy-AM", "4fab57ce3a1209bc64b78b17d8a699cbe93f451536dcc64f4d9e7690913646777f210edc410e4a184869e906e222138005d20b6f4074cedc28205cd984003730" },
                { "ia", "3eef4f5c4e99ad3a5983a38e1ee64e1a946c5ce96fd05635dbe2fdbffd3b790c0fc3d1d96fbddd0ef0ca3e7906b5c57c873d6a98786bc33e5955551391340963" },
                { "id", "a90343a6134cabe44fc5151b2c80ad48ca12f230672fe35c171e92a5f1c14b04e5776d0e6810d223e1582772a04e640e7514ea9f63ae781fe8b28c415c1e38ea" },
                { "is", "8e919bf5d3d64b06009ecf81872a9360e37910aa4acdf13e3a7ec0c300e932c03d1f37149e0a6b73f09a2255dfef8c9800695fc58482834b79acb8819dfdf0e1" },
                { "it", "fe4025008a11b69f29ab56494c22b71e2841c55c020f3ec333f3253654d9affc8e8bcd44aec3b9a3235c2d68605bacf55670013f227f78d8c83b07f7c1abccd5" },
                { "ja", "40172566a035f2a4a6a45ea3be98268a9f50ebc7a69ff7395a1848451d546568c38dc1e49f5f993b8524dd00915b62eb42e364b7e3054db07960679420e90059" },
                { "ka", "8b8690766f5d84740e8534ed665b27f0d4a89ecdd3e482ab376723f691fa93614212ec78eea1d0c3a0dcd0ee9c5231ce8bc30a7707358914986426c51c83ca00" },
                { "kab", "3c6448f93779df9cdd3c7b4a069f0aff920b8e36d4403089e3f2b563513d03106b2a92793be04b4dfa2538ba503cc9d7e4eba6aea13904f02dd0544bd0945c1b" },
                { "kk", "fe11777492028ca15b54c816cb370a5d6252aa8548b86018dabce8e42d4c8d36b18aee7f83d4e06386fa6d247047867d50e213df8e0da9a1b965545e3f294e0c" },
                { "km", "5973d6c009efd16db843d4be390ecc1aaf3a275ec99ef84607e4f64183bb70e2a9179d88b86316b38741cc055e96f161e38b937250cd6bde35912c797da1537e" },
                { "kn", "d791e20e5a4df0b3ba888bda3a1c740dbb35221486341a00cc1667b64b89a2f815c0dd66ba89a1b0e1d2efe8f5bdcac78535cdeb762f74446eb6eff726a0d931" },
                { "ko", "f8da7e364fd63d1463ed2e74e329c34fc6f7feb94c295b6fb34e954e8dc7fe67850d877e0fbe9479e9c863a496e3385ac601036c474f1f195f56214471aa2043" },
                { "lij", "ea8d653658ff7a3edb7bc5fc52bd902f7f4939793fd6766bb4421e527eec91ab06caac6d383303fd8504248a2240605af458765d78cfb90ead8462dd897dc5b9" },
                { "lt", "e68b5ce6660727fd23500f366c60ad9b5ca9e32cb99729d33f3993c688d465fc0ffa4225a98a7341ef99ac6e15795082131e2d4056c595c89f9a4b162e13b21a" },
                { "lv", "8b57f8692bbcd62db68896cb3ad918025013d004c3eea0558e84f3d152e1d5aa3ac326d11a9158075734b6f514dfe69054a11d309c1d60b2ef58035f4c9a81a1" },
                { "mk", "80dcb0b2c614c2ae64168bd7b0214700bb77a800930cd4fe6565e22cca0c3d831e4b78dc36c880eac3a664468c283e1486bfda462849a788ef54ef1c6c8a2089" },
                { "mr", "7c28314a7860797c347238b63e03f84851a214fc77e6d38c372b9fd4e39e6161cedee217a3273546ae2c70d4b75a62f6a48ead0447b7f631512385869e331ba1" },
                { "ms", "bdd60a66544358e7e93077fe274ca38eff0afffd19396f6052eeb279a9aae6ecd59dabbe5aca5e50f35e45ed0c955dc6379819ffc58d7a955cbb8403c8e91c26" },
                { "my", "ba42075f544c1ba60c5a3b7af89f7fb772af3f7cdc114f4bfbfcf49197c2689f2e683ab661a6da3da9c319715b2102588eeb692af7f73b6f7d40f112466d8928" },
                { "nb-NO", "f46b5e3b5396c4322fb10eed41411e9c4027a79d6ff5ebc543c5eeec107cd63920129e8fa6d0f6468d154b986b8ad5b088112c15c76ebc10ca68315dab986ba6" },
                { "ne-NP", "29ff3f090037b899e26cd22602a576b3da6c9c201c056732dd1c98dfa37b3f419f0a978121f45056534208f444e2da6960eaefd21ac2a8e0c535823fcb9a98c4" },
                { "nl", "67cfc4a4638b0bd48360eda8840985cb2f501e70814c4382c0f738b2d571c6299a5fe5479e4b7543f64f161fc9ddd695026ea06667970eff83fef7104f6ee420" },
                { "nn-NO", "f9faf45fa057b7d65b102f3eabf1969771f4b8a8326ac894f68c8bd8fe7fe3636071a8749c7d6e15c923cb421c9293a7b5aeaa4b1e51278c84fe6256545d67e9" },
                { "oc", "da06ea8bfe7241be3c172bd9d07f2ce648643a0aa0322f8da879acc9017ed206b1aa73fe3ed8d1a1ca29d4ff69749cb7d9a2f898cc598f7458893886c43a48ca" },
                { "pa-IN", "e4130776109111ab2804dc5e56349735bbdb104f2ecda97497f3cc70ce59af6056649ef1c455c4729b8981752dedc1e91d95d695d59fd559ed0405732c689e88" },
                { "pl", "41af10c9c46a199c688a7931a2735cbf0a20c1fa4836c52d3f1dcd2c03ea3fed25cea53c97b538d83d3162ea6089139a82e1d251a6c43fef9cacc777f380fc73" },
                { "pt-BR", "322b61ddf1433002bd0a7181bd17ea17d0bd1257d7888ddb85c8bb25224396c676924496d8a1c9da267735e7687c4bbb266df1b80eecab443e50146a59797152" },
                { "pt-PT", "ccdf47d9719632f5d70e6ddf5aef4a16e36ba4f119f484b80154db469e5440161f28c1deeab76bf58b0fd5062af52755276548e58647928529eb01b2c5ca0f22" },
                { "rm", "42e8ad16bb51e7d51c8d5d9f3add99b2362ea2f7f8f440aa467aa25c9cff2ec544775afe56fd64b420b0b75da81e8b995f54f6714a610b2cf41424141c2e32cc" },
                { "ro", "11cc77c5ab0e89927409eb712c8a45d84fc427de6a619864972a6fa9e116d59332e0bf19daa025989bd0ab473a6de4fdb39179b12a2dec7ead22c9b5c9b7952a" },
                { "ru", "6b16457180519fbaf4a2b4215903e27e86fdbbd2728f799bbabf30be855050de2b4f98900fa9d971f15480441ea77dad426645e6e8775e4d6a04136134e02f2a" },
                { "sat", "b86f911e42cdbefc314d93594f868a1a0d3d66b821f6ada85aeb7bb2d9c03defb04f06ca1b39360fa0878caa15263c115453b14f13f7eaeddd80bf8145b49f51" },
                { "sc", "b3a3429b519639f8b7a3fa092cd896a0b9eb73e4d57e19213dd2a7332a43da9883c49ad1d2606b7267c7f25077eb2c59cf87758593a7ebee853c47bff32bfbb0" },
                { "sco", "a84988e170d5ef32791166b2b1b3d397e671689a039d3288438000ebbbcbf0a3e509aa10c6e391c4eaaed7bd8e2f255c7bf3192a9a6733fb6379f91e29bb4e5d" },
                { "si", "6ccb1e5a7a1e40673806a4608b9ae360d2924100a542bbf4f5278a721d13f22fa9c8c0be0a665fe9806f47b4c1297219c67a44dbf9648c601c65c69bd49a76b0" },
                { "sk", "3a67baefa2e29eedac95897160c862d98a2625df1d2091670a0e4a00916ceca5d3554adb2de99f60735750762187f5e028519cd918a895239c48427b5423652f" },
                { "skr", "d2f2eda8d1ba859bbc7a97dc7e65f0fd2db16960757c90efec520ca82184ac4a0296ed4125edfc4f9ac4638f04febb8c9c1c474903db329e80867920e05e729e" },
                { "sl", "55373cab71c3b51e237ba72ba2021714d7dda703e2f1daf29fb04698d2e7589a4330a0ef30192e7b2bc0bfd639aed0e0f3521419f524a0fcca3287ee60a8978f" },
                { "son", "d2e6e7ee596079d97a46bd8401f7083f879254701e86d45e432322e3fce01f858067dfa29db6ba143608acfc7326b7c7089579d5908c70f7c4b29b27496bd730" },
                { "sq", "fcc57c5b2f63880f920543c1d013338a0047205d0e65e54bd2c10ad2b1ff3e78f0acc9967618ef00e2ec781f4c33cd6d8d4a6f4f1756e594f70dd9e5b202d98f" },
                { "sr", "1fb0556878194e1a1bc0c25148ce034e9491b85a5b9c237293dc9930175fc42500c3f15f21776061ff5498e63b90ea268619112def71267e5a7d4891b012e473" },
                { "sv-SE", "a89d44a436d205bbf1fd537893137f850123d09e3d4dc3fb9fe9ece0e27a8a50d6e7f61bb3d2b38a39fcdf18f1763d7fbb98dd076e029a3ed6bfe2eb24d590cf" },
                { "szl", "4b3a58a964fc26eb7f170d508b73b0620486db45d1892f0bdb84d2104d97c84a1c00cbd091b44d753d23c4c0469355746f10a6940ae995ee83277174d5832ce0" },
                { "ta", "cb668ba4afb66ad75b7a8830378c2402f4de9236d0051a823821cf9bfd4647db436be679dd54f7e2e79a95b9e651977a2c4f647d953eea6870a8096156fa73aa" },
                { "te", "b88ab49ff7e7b9ccc5c175c8c7e30157581d6fe1d5911d1f20ab48fd9ba8fcb1654b5fdb600081043a739cf58d5abb1bc5250e2137548792be59a81dfdcbe021" },
                { "tg", "4c43ffcf2242d8d5f68e83841ac3acdacd474128b1f962d15e769f74998c742960e7b9f646f89a4ae456ca9504d9a1a2675a6cadb33010c1ae5e017bd1b19e32" },
                { "th", "76be72a70cdf04400ab33e8c79d87151c5f346ffd185eb1007ca33e5d71cc2d49cad699c6671e50e4ae0cae251586c47ca77adea70144979b6f9987fa9a033f7" },
                { "tl", "d6c850a26e800c42f6f45323ce4a8dc12c9e48d5618f8c9aa6a61ac388d99b8d07b34b32d783d1328f974ea00510c361432a97055b50a89b58ef904ed2f520d3" },
                { "tr", "07072becad36575745f15763628bc59d58fc7fc15a97c77098b05b7a3ad63eb3b53b95e46f4efc7405ad6d7698b6c641c55fbc65e3d4cb814bae2ec90b5594b6" },
                { "trs", "3d55ded400671546dd31713716a1da5cdb580fee2d385c98c4976c09e6e89fb935552eb8ebcb19d8d399e90cc6505512af445a506d5001587ad20580e86f0380" },
                { "uk", "1d2fed0e7a2542e1aac02b6ba7eb7deda1bc570fbce243b0a868f849a5c7dc4d8881e9cd45c1dbb069d61a0483d303b290c2b604a97c9a598b6e0f0a1287cf61" },
                { "ur", "2ccd314d177ec79413dc16bbf02315bcab5d213b82ff02d9c7329ed8c10460bf7d0a9c8efd443610bd66fc6bf2920aa3034e38accdb38c5f40f40057d53e9479" },
                { "uz", "df7027e9294d88daabd2492e645fc471c8f83a4ba207b13b021fcc226eabcbc0a19cb04f3c40fd1cbc8aabd05436e969be7a7680f0405132d6014d125f505517" },
                { "vi", "1f21f020c032e9591399a4ecf02343831668d0b59424a5e7a15209e5774db296e4dc785b566975a1ef827f9cd8718659c0e920ef073f4b7028d11ff8e7fa3e22" },
                { "xh", "f72c1abdc4f5b99af5dcb634c304b2c1c36b20e6789456aff82cd76d1c4dca729f45e07c33a3d93d1090d9ad6ea69cf1074df193c9c541d273f9d180052d5dd5" },
                { "zh-CN", "359cdfe35e6e39e07e74a8ec5c05ba47cb4a06c34062dc019295f350706601029c9d181268e6972f6da690c37857d9b9e1c7bbc466222adbcf644d4f4a7679da" },
                { "zh-TW", "0e20cff2796fe2a3079100ed16f153e539379bae147c188e062e6c364fa45177dfc1e3e5fb118ef2e725cc0c38c52f44af070095b388c495190714dcc0c24516" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.5.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "915a43200a1bc84dddd16ea043da22fe2f4b8f7e52f26ba9dcf3fe07f2072b0b12bf1f599ff63a819e7db176f69ffde4c48cd130898ae0bbf251881df0ed082c" },
                { "af", "0990d3a922dbd8a173575f8b2faa2d93a40d780d594f53c920c189ea139b73314173fbc512b4ca0ca3f2b5dc6541eeaec805a2f32f326132078e7ac4cf8287ed" },
                { "an", "ea183125fec0ce7168deddd751f05fd345646502cfef40d9304e2e403cd053f1b1a86dd464c8b94bd006c84ac927f8a541975e59f680d85b17987716534a10c2" },
                { "ar", "7ad18c83abba452ebe0f2c45ef0f49029fbca04892cdc4dca9435e29cf54450f8edf513a843a77ccf71e5aaa523c9888200db5cc7e7c0c9a3345ccc3d72d2acc" },
                { "ast", "34cf23c88d7c81c7f1fdbc7821acb26f25f6b7e3a645d64f3068b34b439ebf9f3b6d95ace078001725bcbfe7e1fc33cfaaade3759e105676680708581884b32f" },
                { "az", "3db2a47b2790217c70b7085bceb54c57e6a74cbe5439e037e857df222c573cad417d9efbd71c43852d529a6889eb36faeb136051a12d3323abd22ec821ff50b9" },
                { "be", "0fdb732db49206ef7205a4db00ea011ad3d7fde66b384536325bdf25c62cd1bef66c7b969edaf1e68b2c940350912c9798750c6a43f00a5125f04d49dbcb0d80" },
                { "bg", "cf443bdab56242f725b31bb149808c42392312d99c277693395359b3d855b4b2d70d3d1c8343e1ac11f54a2ae0c1227b702a35294f64fdaffc6bfbe26c42c76c" },
                { "bn", "c1b09bc3a261fe60dfec84776394d3ad834a653e219fa5ec52e4457f3c47592a3c62b0db321b07b5889bc22995d02b44d8db6c7a6d409e6a5dc4e260df874119" },
                { "br", "7f64e46d2e120c4ca72d8d0c39612973362322a240b7540639a01add88174d956971b70f927387f75babd81f8e5ec4cfba7c3fdee9c5e3a7ab2ff4db0b63bc7a" },
                { "bs", "05ecba23f8bfcec331d77b4fc79c31aab75d06ff058d8e918e865c9cd3898b9651d28530660bf32f3eceb835579809e96cde40dd62b5fa319ed356da5548acd8" },
                { "ca", "dd8bb42978d4a6bd228c277cf151dbbf08e4e4c1c5b6616bd5b3013bfe39c17d367297b354e8fd107a1785ff000ed4c33bbd911420c755e66b0eb05393d25f4f" },
                { "cak", "92aa4a6e711e2ae3e5611048901ace5ed867931b03560492cc61cd50220dfe9ff8b647cab7ba93d3b5c1f5f04b5be835a4713c4f9011302f9f198815ebc13ff9" },
                { "cs", "4c4424da50171c6abfdd8d6457378af7870cb280fe6f39e6189090cde84f0b682366c411a8d0052e2bba0216ca927dd94412a77e121cce9c3b42c92a7f812057" },
                { "cy", "4b8f1e851d9282ec5cda966ee0da9681e57ed1c47644dd3f68473e1e95114f95dd3548fe6c0ce87bcf740fb4593e90dfaaed5c6482dc82f845e06540ff9004ae" },
                { "da", "1fec61e7c34141e4f4888fca5e792494e4081878b630c285b00b7c94126592d3fe86ea8ffb8f95332348171b9ebc50b5e5f10dc656cac63c2a41cf09ec002fe6" },
                { "de", "e9a3b012ae4d02e6be6b75860f9536acb693c692d0699ae7d372816bd073139dc2bf7a9a9a18e813ca0c272d55cbb7a53dfb968895fc89235063cdd8d177024d" },
                { "dsb", "3183aab41ffb58d9db04cdd9ebb5e749dbf4eccc879e9da53b2af150e009979d7410944f56d1c35f4785e1dfa334fe273503fba47b150354bd3de19b6bde93f0" },
                { "el", "f3c470115d8f6bf88dea63354a014e287c82cd3fe8f274c1acfba244554704d23a87de78661c005c88084737d27a4833c617bccbe572a5482ef1d3e8102d0478" },
                { "en-CA", "b81937a675645088e615db18ab8718a97a0ea2a87e35e00a24ffd4ffb9b3e24dd167c6239b3e013dadc5e6102f77f3a03f8f774bb254fb8a9b05ebfb688de9c4" },
                { "en-GB", "c5f613ec8915ff245927b4975c56b1b20ad0f5053d45aa717484bf125d0b1c3c9279ce1c720fef010f18d6cd87eba68dc8e82d2cf05721bfb8b190581c0cdaa0" },
                { "en-US", "7e26945796cb57670ad136f553d44c0618559eda8222c18c1f85e276d290481703ff7582aaf922fdac2c84505b2f974f4281230784e421fcb07a1875ada9cf62" },
                { "eo", "52cbb5f7c33026cd45f5de83534f6010124c15b466e07ce04fc9b0ef5f611d4746fac4dfdc0c9cd3996e33f8ebe28e6643fa9d87e2fe35ceae59ae72f29536ac" },
                { "es-AR", "83d66728d57ce8bd038671e6bdcf331005b180351163ea4d67cc6099a03034e0d7cf13f734825c9c509bdce6f65470e6f5aeb98602858c807f90b62514d1cba9" },
                { "es-CL", "22be2105cbb9c1150f5a4dfa40a54d9600ec4c3a75a3c6e647a37f87f5299ee1575359251a883a44ab2a8de4e27cae9f127a575019e2300dd331abc9711fd9d4" },
                { "es-ES", "0925abfa8d45dc802e6c6748e14f5007ec83ad794c2c4bed537a71406a8200db8502d70adbd688651aa8cbb563c047de870c588a526f238d404faa6613d81b66" },
                { "es-MX", "b8c185b452bdeadf7ea3292760ac15209c1c0a7925a713cc5799f8ade8b397a394e47830bf3aadfde708cf03f0c1f6f18b02b507775b22da533d7aaef6fef086" },
                { "et", "55cd3817d8b74c869c130e552525c56e4c9aecab35a3fe2a9da386bb0585684876f0aa86d4fa07f5864ccc2169e6641b19559b5cd6554d3c427bd310dcc80754" },
                { "eu", "771089752107ba17900717f4e9b3be74b06065d3227b4edc98ea77189b61a6b514cd95f3bc75fbf7766a74db74fccb9263a3fc5bd534c37b142b216a55e927aa" },
                { "fa", "1c54127b44a63b60ca170960f1b6d25024d3a66fdee7a679d88cfb9c888c0594131416d3124fad8f6f61be2b2b0bbd466db107e2357d334f12637f5c203c93d4" },
                { "ff", "b2c197f16d049aaefb443bc72423b3c31ce49ec19e8a7c7e7d0bda73a8ddbb9d013bd01bedc794b017a6c7a110b4b3f4b32e7d5ae0e017af019af7731d92487e" },
                { "fi", "b463f3352428348efd4795e024e5e2f108c7d653687c1c406c78cf65152c549696d8c9a1888913433b5737e8534f633bcc72360d6814be3fbc7d003dd150a2cf" },
                { "fr", "142952c380ecb8e9dd7dd40a05d15abafa977f7bfb306116cbe386db0a4bc89ae1dd4e1878a5a0ff0b12b47d4f9704dabc1538350f523dcd990b278034b3a075" },
                { "fur", "87aa0150c52505cb2b8df56ed3a6fc51048d5fb54f97dd214395b128d2670a0298a4f3fa4dfd40bca2b35043087fa80a5a2fe51b73a36ba73904ee449d953260" },
                { "fy-NL", "417b9fef41966f4c75550603662a128bb12a7fe353ad54a44fa382fd78ab81e53863c8fbd540cf391a3a9e31e7c7c417ce6ea618dc8555f00e15265472918cdb" },
                { "ga-IE", "f5e9110517ae344d04b2f87dd9d4478c928b00cfe0592e65a9b42789ca402d86cc2b762dfe535ad2952866cf33227c27c2d44282630d1524f9dd99534b2d4a3d" },
                { "gd", "e9d9b4b6db26c33db1cd32334d6b499b1ec57c634f3f338d1e38a86584cd0b4f409a585f47d5f84e5c44a2433d7c0ccd78c699ad1e1f69466684a4b307aeafc8" },
                { "gl", "3334455ab2f28e5aafe8418da71abd7332c50b4e3da38c5f4f793ca2820e1e0f071b27a554cf0d86b99bfde201c0862fa919730d3c97db6be3288ee700211205" },
                { "gn", "6674ccf1a149522b24586266e690592315d59527e148ae3bbef6ac5eabd0637ab721c07afaf340ad4253bb2d1733f7d08b7565c0b978f45ac744e082aaa5d947" },
                { "gu-IN", "b833e4acdac802d298b74792a1f043ef614c8bb8069efdb2ebb8cc97b0ebb44d10353b5c4f4b92dd9b194b99d83eaa000e2a0c3c16d7fa12625c1e6f47f39f8d" },
                { "he", "6989ed1d6cbb1df0f297b96cf00a148163cfcf65c5435c3ecdd90835ec4a848a67c33e93ce861addfb42d73ffc7bd48974037afa9477e67dc0d4255cc085eb48" },
                { "hi-IN", "b1a70ce32edd5b96326e211542e3dcfd75be4951cd7fb069aaf17897e787ece43b15deeec7880c1294eb6c6ce4ace48688f20d9264a955a5dbdfabc92aa3e816" },
                { "hr", "7b050b6f76e40fc4e64ddc93e94018561437299f999d37651d113dd22c7e32baa6eef45d73518c3e46dc2c9d7f86bd34b09a7a5d5517e0cb9fb81afc1e924725" },
                { "hsb", "447c0fe4fadac119e544dd07e1740c77bc0744f2f41ed5a3274517e9294d0196628738f16e915bb9f73aceb9c228876f610d5c4806147bf7d907576627a25a53" },
                { "hu", "55fbf5ddd23ae3cb60aa0d243dc13379be7bce72aa90bdd00fceb290638264547a1583fdacd5ac1407290155ee9623b8016111dda662976f465a3eb8bd84a996" },
                { "hy-AM", "da002f4a9246b06f66a90735aa5fade316c6b4e9211cd931168afd04aab78260d3981046e5aba41a5e5119f0b4e1b5f2d979c314d9031186534ae73136a6ce79" },
                { "ia", "ac06e1376c7c861b41af65c52b4770a64d97e24643475e4dac9c338ecedb2e057573f190f13e08a7f03f66879b3b961f9493008a70e0214e9d656da9e564dd82" },
                { "id", "7e2e2a66b802eba8d54ea4c0ba91af9d06f8c29570db2c7368de05178cf8e8cbf6f852355a10e40169415eb012024e48422de32b133adfee2a357714c5bb0b13" },
                { "is", "6db949655e0e453abca6a6349ea5ffe92d1e408b5d1da80b25a40a5c10eca667a6594556a18eb821a6afb68c4c1fa87e53f11a5156aeb200059e38842c89068f" },
                { "it", "c104271d284486b7f2842d5b13f06705228fee98c1ae6cf2190e0000d61b8927f12aa0ff2f58ac5ab2d3f93f397be240ff5fe341c99c8a75406616c032196182" },
                { "ja", "205c399533b8cc2a5d935a9f37c1ae358a54d49005a33469ebed984c3abd3fc4b429461365c978fbf91b95ee67ab4a3ebb2b0f2f6f8243a4d8ee4284f3f8f6e0" },
                { "ka", "4dcd0846fed48241153d41847235d345e357bc2108bc422bce9b2e81453dcdcf4072a6b730292d8ef4d6d1bf25a3eabb887310de2e05f52d2813ae2f77aecce9" },
                { "kab", "ceea5aa1ab43660cec622ec67ff8e4aacd76cac111f473e1f1d0825984a865dc07b1be8235014815025fc7b7f4d63905b0578405de41184843ab1b95f96d04f8" },
                { "kk", "add2552aac67735b59b31e12e2fb813c5555321733fec0a4e1190294f3acee6725b9c20b0a717a7ef41ed5a7dce7f275cd818be7e7ac17cd0ab98861d3d57ab4" },
                { "km", "639ce083e4d68f14cf2faba717a8d0ddc2f6f589fbe34bf4d459dbc198788bab4b7634800b438ddbeaeff2b3851e8caa315cea89ca5da4d62d2d2f754d03c69a" },
                { "kn", "45f5a299c76f213967fbae9e69b34a82622a4e101e0a51a6480307aeebdade927c606b676e00a5cfc92a88b1f550aa055d33dee7998abdc875667693ce529982" },
                { "ko", "8cb926960f5a154473d664cdab42dcc8e24098cd804f92720d17c17981e921a22f6f42ca37067391eec319c8598b376e37584ec6cc3935e5bcf3d9d909302466" },
                { "lij", "a32458426494d997ba6ab69c22b6858bca85f387c9d95e7d2fc2f728965e36d0a801c7ce793ec4fd0a37328992cbd8142ce832041d260cc8009f8f452ecdb080" },
                { "lt", "42d51ae4f31e2c6979fb592896ef84ed7d16cdd274e2e16116bbbc58175daa331f7edb4f5d335aeda43748c98dcfe9cdac1dc2f1f875dca5808667938f4a97b7" },
                { "lv", "f9df6efdbf6da5640104e40b5b775ad20679f5b00ecf411315ac63cc1f715c86ad7e07c81b89a5bf40d59345c6324c5222539460179223145e5cc15b0f6649a1" },
                { "mk", "d7165414a0e5251d251e72b1f0f11463268b9403635224dbb03dc81c964382a1835426175fa578a393f98e35778e50e0edf927d505aa10cc71167a14f882721d" },
                { "mr", "91847b544f207f1a68acd81bdb3284d43191e48287a91fe4d0e37bf123aceac129311aec73fa024a032f4ad8905304c5490a1549b86b1d15d11713a6b9c7ac77" },
                { "ms", "c853513aacfb3754904aaaa795468791eba8997ece74f0a596e26f0002124bfd7be555da1bd87c27760b4193351edda2ff488b62e342160cf91f0082ddcf45e7" },
                { "my", "d7166ee20d675f9f0f1eddf9d1195ee0f62919945dd49a9b13fb1229c3ea2e758994f337a2aab8ee24beaf2ef18fd71e6930b58e52b76e0b37e680c2bf0d1a42" },
                { "nb-NO", "fd409ed1d11755d1c03262de0b67057a3cdaca18cc84f7f51efb23ece58a73e9b21d57250730ad038bb177c6628714774deb79c60338a04ed388051da551651e" },
                { "ne-NP", "4ed03b20b48385c2cd303e90de06a319953e713e80af81e45039eae470cb5fb4f5679895638d16dfadb29a135accebd7cc298cf4764017af79aa696cc07e92cd" },
                { "nl", "7ec060ab8328ff573abb82a6c2f5e2e06398579f01ce9fd121d62b1d65557f21373cde16c29bf149999589d7f18dd63b0c70986c7f52bc99ca9b6ffe9de616b0" },
                { "nn-NO", "55cc45303654b2608ab40dc8e400d66e914533b71d89dbd99b8051506065e62bb68dcc8863eb67e7d34c2f5bdd72e2c9116dc565cac13f499643f32433e7559c" },
                { "oc", "0a95888483ae8a90b160162a700635ad6fdc54ff8c879805f972b964c049eb061e43a13ce9d10d27cab06ceb80d971d0e0f434520d501fbf049596932a8762ca" },
                { "pa-IN", "5d5835566dfe5765b2d2977f567cd2c882d6397b6076179a8b8ba2973e707621d2d585471ab4233a9f8d4664c5e7fc295495b2b6037617099cff1d52fafb19f8" },
                { "pl", "8499b06420a4a9e8653c600367b3983543932d51299356238fa058a9fb66bce27591e7bfcd6b384b39b1f46e0412642b441fa2a302a177db6222617987cbc6bf" },
                { "pt-BR", "ed877fbaa93e4a1d85ff3d9f993b5325962463fbb867bd84d3ced279575704527d6fe9fa29e511521995c71fec2f55d10bb86bf508fc7017a454588c0f62bae0" },
                { "pt-PT", "b28b8bb895ff352997b9d8b848d1c6361cc32653b081f218efbf6b8281d626439de8fbe5a406e1f408a44fd889be2f1a078469da8cab4425e88cdc76feeb0ffd" },
                { "rm", "0ac19667a610beb4f485ffb041ec259d3ef1b829bdaef4f86d767538f340397824ede22fcf98ab582a99ac45c5c4f886174395fffac77ea6d2db2ea4bbfcdb50" },
                { "ro", "1deba9901de0a88a300c5318198048058c4b405e045d08e335d14714351cbb5c798a89f8a59aede21ea0ec88a675efa2832ceac455e58965cdfb5736d385479f" },
                { "ru", "188856ae96b4d99b14e44e79ca78e00fd7859feae0165a15c13e1673193f23476bdc42dbf5efa74e1aa84e04ed6deca70b4ddc1c7e6529e747782acdec871b68" },
                { "sat", "839dac99f603529557e981f061627eb696518351d5610e7e432a7c41572877dd67b7f01da7c901b3bb1ec799b4eea796b326b290dfa96b73f1d386572131488b" },
                { "sc", "277d6638a3a60f6d662f5cbe3017e3da3d787200dd16f610d6b112efc08c1f366b9064a003e7519d67d87c2d0f9808685eb6fbed1ad2918c29b84e1d953bdbbb" },
                { "sco", "60c4332207a3a82e0903ff371c1d105f4d7db04d8dec19a0017baaa4ed7b0bd44d675813cf2db144bfcf8eb5912fc0b01a9fcf23acfaad42faa76301ac4f8598" },
                { "si", "f617510c445ed5954aaa828d4a3c1fef6f4233452df47ab83a5e6d0f5562b4b0362f085a5ad5a3a04531cdf89ef03f8d7428ab8b28e5f62f47f19b641ed812c0" },
                { "sk", "6fbdb281ea75c40b1d9eef3e6cc4d11d2cecf9351261a89856a350cf1869ad8fd0001b9afacd78c997f1af5949a15065a0a2e2d40c1d9f00ef1597e2fb08d917" },
                { "skr", "159fca6815a27e82b67267e62aa5f7d965b42dfb324d8a64396a48a8860c6f03870d3e6e28e4bea406ae8957d1603cf7a5eeef9a56fe1465315ec10cf0a2a31a" },
                { "sl", "f35be821c4fbf89ca320652e43dd2f7b9040310b5cf589296443a07d96a8a65b8173a06ce27eec513679377db719d6e70063fed13e96ee3546d5cb01360b514d" },
                { "son", "e4d4258f70f1d211b433273660e93a1f94b2b7a77b28a7a2f8e022348ab22ca3e3814a4125d0fdaf98d8af975eebc66f8deba512bc4653d1d984577ef84bfe97" },
                { "sq", "f674c091bb09df2c957fae411cb4309b21d746d2f7dc3848cc86ebaabb804df55f37dbd9c06d0333595174231b9f2ac1c252a8697789cc0c1949042decc01f6c" },
                { "sr", "ff792e5b54a0e49392ff7f11648793e7281664eb639063841c2249bef49b3f942d4a8e71114669700f2a6ed0537a6ed2c2c1c2336aca06d1b28fc166d14cdeec" },
                { "sv-SE", "90258da8d768e4ddf2b65b8eafe148e375b6d6ce182f05c77cc0611100f72951148cb9555ed6b3a5ba8c784d61ad038c6e460bbfa295e13eb7c4ddebfe9f8292" },
                { "szl", "4f9e6df2ffd38011f9e134f293bce1631f2bad10e2f588b8febbe676d496a46e36c26ae61e843794b53eda8304c1e399a2e657cab4542fac5afea95d1b6aab8a" },
                { "ta", "59faed1e1764e975791a5972f94d0134930d5d860df1d5df03c4c7c4b6edc8abf3d72eb7abe59522cc62735894c41685406bf36e971b25dbca7c586fba5f1e33" },
                { "te", "40cfcb51e4ba33e63f45d1f747d3230d2bbf2b3522f5725cd58743e271150c811f482f44cea08e827b3b0b54a94a852332e04a4dd0262dede911670526216a3a" },
                { "tg", "7644b4e3c25113e5ed3118189b3420093ab72ad84be073c66c06a0d6ef71942b064d62431f6c3ce23227c51c16152756a1dbe64fbb1a6565d1d48eba87398167" },
                { "th", "81622f9c3a4355658722b9b0abe29cfc19b5e470c14def05a94c9dfa44f693dbb3cb396fead987abdebb8c8d526808e6c2d036dd89d33aed4296d004abf5db77" },
                { "tl", "c0fbd282519ea7eeec484378f7b681eb1ddd7f702d2720847ae26b5ee059208c6b3323d3343651300a039a967b98e545a7293f7645880f18da44f804b4f8bb4d" },
                { "tr", "3dc83291c228627852064648b1d38d04c129c94ec985d6f49193c24a236eed386c11209de3a45ba1287b1594a4c016be17695d853c5d6b58ba9211465ffcd3fa" },
                { "trs", "837e47459cd16fe03e950f521353bf92935de81270569b7ca3b33c5f4b502bd495fab0f6d75f4173437f28d46922d2eb810eca5dfb8eef715dafa3df96bddc77" },
                { "uk", "d2d6392e7c00a32645b20ad21b198ba4e33459e694b101572290a8ecc11f381378be8e3a81a9f6b449f13234174f8d0312c72a86d33abb11046761dc7f136b3c" },
                { "ur", "4bc5352a5f30c775869ef8ad3e890a00e2852e9d7361313029a01280a73f5a83401c1230a6f42cf2013a682caa372a3b81175c038eae8d2c466d50986a0a66c5" },
                { "uz", "90dc7a424dedfeef5b5698fb7e02b010a14877d249e265970da1c71894d5c04716248447756f1dfb6841a8dc06e22de15d64e556ce74cc450bf9c8927d7134a9" },
                { "vi", "57a7749014b85c5261adee53c3484a47114552038804d72f65468edc47896508cfbe0d8928e32c95c8d6cd2016ca7843359572cc568efddb9c30afcdf172e6e1" },
                { "xh", "71e3076268927940a2bb2023b33a0fbb452e04513e92273f8e73996b795c1a76fb9c7b093905c895daedd49f21f3eea5cc1ed99ff3f51258c14c3bb2661fb0cd" },
                { "zh-CN", "9c58c9393e78cf246e2af0b5d2aa2fb55b509f9fa1fc328b7157bef1b5bec786479fc3baad03f30e7800423dfbdb5146d3b3939638f94eca024a4a4e1c021078" },
                { "zh-TW", "707bae5588268b01c10949c5f5faf4b9732b5f5ed8fbecf4f95f5a768f78869615e3ef471d45ea2a92885188961057619b30e644c68fa8af730ffa2917f64b2a" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
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
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
