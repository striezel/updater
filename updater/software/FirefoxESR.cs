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
        private const string knownVersion = "140.14.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d708ef707411ede00e8e4b3e3f9ff63ee100925f463a0c837831105ba56983b0229719d234f95372e5eadf59923a6052c97d85ee3c191bbb68b1e369b2e4ab24" },
                { "af", "c3650402daa061adbd07e6abc7b3474a4c96510465e1a9c5217667e634c684948d7d534c7bc573b8457a1deb558ba0e8e0902e0e6f06e67fd3f20d92065d64af" },
                { "an", "27607131644d77364e17f87594c7388faf1ff5d367ee08f83c37cb4b804429a92336427d58cf994933c2fa1f69667d2fa1df24b663ba52c095671743f2d1e02f" },
                { "ar", "63c485b5223d696bee78aeb0e6cf77f172ee2e5569dc7a3060c3c5e7c023dfa9fbf1d6aefe692c12798138817cd015216f875979c4fba7a82af771ef17d150d8" },
                { "ast", "201ea28545077c3489efa685f8fc0ef104ecb27e886bdf33bf48e00844be0b5b88793d1bcbe6a2f7c92c95b8879a5f2c6762451103f1293a6f5a512c09066d88" },
                { "az", "d6627847774940bf8fe27f927122d5655e8392255ee7b835b154934748ac03aa73fa33457477bf90cd238b2338f968c573180dd84d38c85f8ffd0b4970459edb" },
                { "be", "123128fdebbe4839a2967fa6d8d0ff121440e329e72d644715e3c8cc3ac1d2efa0cea63c1f22a62361435f12b9d4d8dd8e92253d0a5337aae3b08ac3ea9b38ae" },
                { "bg", "a080650324c7c7bfee79f843071f37202d410cb09f33a4a763286d14211a8fd8bbc97576963cff2d221ecbe143a58805f33783d18407cdf56f767bd1216821f5" },
                { "bn", "746bc0c81277d41746f2587f1d133a31fb4ac7f912a2897cb757318c6fa5f5cad5cef3e5431348da0beea8352a1597ab7ba516081fa57e279aeec5d3fa9da960" },
                { "br", "f48db2911678b48fa3a4f16d674866d3a8432c7bde210b50d1d186988ddba36ba483c6c502732b6d2d6350dcb1f174bf0878d2b298c4ab45cbae1df6dd70e509" },
                { "bs", "357965f5a65fb913e7b979321f1cd414ae8aebba471fc2011d82f35bcdea58c019cea8241b34b521b396827638a37188411f7adba06d92e3364038c587a5be01" },
                { "ca", "5da37dcd0f12434cefba0542b721607655645a3eb1655e8cc3a2640b355fc9c45cc445f7946b44134e6c4931b3c6ce87e1b1aa923667588981a6a7a9b5916572" },
                { "cak", "7f5f7f25c495dd95ccea574be46599272865d11eaac2910be69bdf605b9f54666f16cadee03715e035d231f3e6685c4dbb5a3ec9e45d58c4e5038318be821c4f" },
                { "cs", "8b018570a486a34ec687d2460dcd8d1e9f990caa52b4060ba70fb78a3c19cd9091fe583b97796031f15fdaa884bf1428a31e80db411be3e400e41cf6ef62d345" },
                { "cy", "6e7db699c6e69e2c300f5925520dcb11ace7b470b2778e8febd37f100401ed3f663fa315f448c0851c81550f45d788539ce13c465b4abd7f9f836a8c2a9c71a9" },
                { "da", "8197c4f095939156346518291d67be26e1eaf579634edaa0ae51f6503c64997af7be48e6a36f50054381d3ff9d94669325ec3037eadb69d9e8edc36ff60a6264" },
                { "de", "a47bbe3e3f2b830f8e5b63d67a892cdfd40b5ffdf9db2acda380dac332428aa790b09fde25583191d3585b42860faab02c2e62d887638da891fbd1ceedaaab33" },
                { "dsb", "6fc08074295d82c577363d1c89f2c4cc049582d1a951f703e07c827e84267d64816833f1bf8f24ce7782a40cbbdf22588af215213a4ae1b819aa200ce1e988af" },
                { "el", "426d48c51fe047faf6efca4d59da4463dde8a558dfd39c97a32c52ba5b382e2e4e5ebfded872e7796c73ff5ce677f218747a5e05fb9214b8f82fade8a03afbac" },
                { "en-CA", "f7166f78f864f04fc65f4207a50720da7e5fb4a6b1a6153887f3389652fc7f3e980240129b98297f10b54f072ea1b80e272751e92dd4690d5ff7e5d0a45b13de" },
                { "en-GB", "b6499bf45d0cf98826a6fd2dd8e897d7ff31679d159cfefd48828b3196fed050707b5ac6a4eb7b1f6a7f5c6e03ce580b8016a9bf1d7f5ea01cc306e324dcb1b4" },
                { "en-US", "3d405209a243f44dd803d0deff7df14e259bf69b3d7eeb698e62c951a1675ff3892cde9ab3076d272633cb44b763b82dfee1208df883c26c2a9b61b40d67eb96" },
                { "eo", "69f1d52d2b109a78ee1e5c48d1f504792752849e977418223d6aa5144623bca5f6e3ed4d1a77421a300c1c11a7fb6e4a02f47af9085b22cc87ea65b641e8f1de" },
                { "es-AR", "09ac88e96a5b860a3d69d7492f016d9245fc517cc09983ab9622a11f07929b0624626907a03063cc7491df7e1f36f578a8b9da322e4e742d1b7bf3982c294024" },
                { "es-CL", "8f98cbd1aa83f38c66822579f6066c5381f24bc0c3b05b0bc8d54915df4dfdbc5a663f48cc68deb2fdd4b12437f0a41dfad7d961c42b18fc52bde7910545a380" },
                { "es-ES", "6cf653df6c0db7be0eae061a4cf98d565f89f665b2fdcd2ce923eeac169188ca3e6bed9c43118c1890bc5aa4661e781d7366cf52955afa77120a921fcca7ed58" },
                { "es-MX", "30ccee43836949798c861a0e5a1ad6242c74f48dbf915b886dfb96776ad09d60a69eb77978aa71582a9c607601d1a827f009511630183a5d8e648261402cecf2" },
                { "et", "285481359067365e50f0d61de45e4aa624b6c7fc49679f2d06fb02a63b306652fecb9edfb435eed3afc7b0cfdccb621717542f8f229639968199b0c33d99a765" },
                { "eu", "3dba87ee6e3311fff31b840ffcf42fc6e4ab7d74b5e5489999baa746d4d0ffe46cafb7b2bd67472e5369a479e639ccd1840972ceb4141b3381f04b9a8127b23c" },
                { "fa", "07312779b47148918763ce28cf00c79c0256708d2fed22798e8c763594612adcdc4a04afe139e8eda91e4e53ace9cad6c83e30bc24495d2208759c3a00c4f244" },
                { "ff", "d9c37a2a09a99ac0a78b962fe78044b6111ff467119c74f7b0bea43acb884467de239ed9e7694bfe0da7713f95320e5e73a7a694c4185659b95ee0490d14cdd7" },
                { "fi", "97c18c37b9f28cfbc39be65e92aad6c1d8d7f3f53b876fdec11c0a96fadd466d89185801089795be25f8c91c646b7c740236ed099b3ab334a98612ed6d09e641" },
                { "fr", "e858b3f54ca6dddba9594867dbf061b1fdbb5dd9f0414af86a1f1d5a19c3e88fea6e749b61e06a53f38864b72a79fba6c2a8cf23d47985f1f9fbac6722e1a04b" },
                { "fur", "60c318f995e1356bdc02e8396a75124c7ef7b7cdd2e4a597960d0b08f9ee2c905855bdb6051d7682edd1da8a9c995b2c56dcd530f3f7823bf4fb350605d43e46" },
                { "fy-NL", "c82b0e561c4bf8583b2c09ed50e9da235825a44e76b6b2c59aa87f7c599ea0fd09bdbe7c96690802003bf7c3b2d0b312bff06074a7afdc99a33a1ca57d5a30a1" },
                { "ga-IE", "612c1e3e7683e079393a913a730ac9b1bdff8458f1ae65c4c09f3242114a42c3bd440d3eccb75175c6d71e3398d5184e89c319bd8ee79cf3e7a315f8f10e2bba" },
                { "gd", "c4c51b7d0173275abdeb588f57d9c48705d5166a9c2b8586c07b99bb2da170b8df4db0ae05e430bda25cb1475df71d19734a9153722b7b042789caa1c57623e8" },
                { "gl", "6180c7f409d186059760b0e6a5902e5731bf572e79665d1319d278ddfed3e353a819de623521cede371fba059d49dabccb9e8657850f3f834775c08ef78eeebc" },
                { "gn", "121830f4421e3e43e4a4915ec4dd70c14d6cef012bac3ef27ad5dd929fe886cfe725e48fe2d6d0eb4f7e50d6b6009c4a24ef3dbea0ba16b6754b113758cbb1fa" },
                { "gu-IN", "65b3c39be583ad4d81de0d854dcbc1cdbacb28856d1263e6c776403b2b87b3df1efb38aee99bd02b801079255b45c85ff179bb53fe2f7c56dfbedbe9ec2b9fed" },
                { "he", "3ab2a05b468883054ab0b6172241fd9bf91cd179337f784129eb66c5865082772c95149751c77db8dfc32435e14626801c97c25590fc8229449162561cfe107d" },
                { "hi-IN", "748fc9acf18ea82d2bbf6b382b5e4a6327e24a234b67df8207a0970b882b8afeea36c1ae13631dc6c0d0187079f7dbb274e90d593d1d7cb4312180be7b4df80b" },
                { "hr", "e2460efdf1f389e0b5e3737ef4fd5fc869a12cdede31c7be24ca8788a4c89cd3a2b0630049566674a91cff2f6836c4e462c08496710abc9244e8b5932512c647" },
                { "hsb", "3767be426db86096e74e990564792e1a3c4d4d31fdec81b62410765058bf6d9489fb1166ea4d7efa74969923d2f6aeff7d89032b279c365fdbf993e1f7fc0de1" },
                { "hu", "10abb2a9a9c23e4d815f81636f3d063aefd1d7db0c32054475c35f566476aa8c5a3566d25570fa1275cd489a14ffe2949bdec49c5a7a8e97bedb5baa600b9959" },
                { "hy-AM", "25a2a82ca2fba27c23fffd2e96ab11a3bf5c504e94a9a13b1955d2472c9ab54ce8ddc1c881ac60dd7fe44d938a739289550ac6d0a736015ee2f9721f01bcb3da" },
                { "ia", "f7fb25fcdf76fe791b519f7d8a416fedad102310d5e51ab1c2c49923447d2a64efeef95547336eaa61a25c65872fece40a403e446d0b1148f984674665e8751f" },
                { "id", "bdf6c97d5af612024b5e2a5885b6c9d68a9c0124e444b36d716361955c0ba8ae03d2e79a792fe5ba48daa27a04e7994420c67f518707146ac010b8947333d4f8" },
                { "is", "abac311e4e1a8aded573581487328ee2ca2ad8e7f2a4abfac52bbf0fc19400834c3dec6fef2cef8fc1721a5d34a42d8a92c59259a94f287cd93dbe9c8bdc2c24" },
                { "it", "1775a2980bae854f9521470b157e9fe0f31e4defeb6818f8ec04ba6b8dfebe725b79067e87c1bba810be65affc6e93dff3149e953af6a7fa97492beba68cb8e8" },
                { "ja", "b3582fe2d093e056ede7d425fb980f692cf9884e47998a10f3805649ea6f988bb3951e3e44c1ea7ab69297ea4424be29cc8d5fdbe0e30de65b5a174dc967a925" },
                { "ka", "a6d22b43417ed8dfeaf602118867b344a696618ee7778e1c2564e50ac17de58fe598fd90c3c0a43331a30928ddf9fdbfbb85bccd5921ab0579306b026f11e943" },
                { "kab", "c51395539877e093991ff40243d6d860fda7daa592590dfc0792010281feb3d19eeb7dddcd903687945fdad5bd462f1fbb20e1af4b96f3f911a1aa201f840e1c" },
                { "kk", "b01a2ff225ae9c6db057957de12e7feb40764e9a9b039f9bf371a17a3bbd4ecfa3cb244c0ae60668187ddd8183429da583dbb0b1c42fb65d2bee54bae108995e" },
                { "km", "1f96c7c7e5f90686872c25daa0868c2487ff48d3741581d22354140d380f879449ccb26226158f59c01a986472e3d2103904d4f46e67b6f26cbc0dd0a14f4252" },
                { "kn", "2402fad4455dea62ca44579fc5668bf351c5098dd9dda083e9b860afd45ae67120f3e7071649d7d85d0afbee4615f782a4638ac9feff4b052a9968d6fb77859e" },
                { "ko", "e6ab8f38b973b3db764c913b47824a04821e117cb39ab68cafc42b3aa418650125c67f185a06acadb10413e57ef3db37a3bc651067fe6d8bb7b1e4d160595936" },
                { "lij", "f0bd63637f69042d0448565fc7b2a1378c86724d540faa8e71ca20b045e7bcf0b497362d5b1b93b8bd37170c8169f0c86669295263873cff26ee650e1352ae77" },
                { "lt", "8c6b37ac55666f96343c2f9a037b6bfe147ab77f2c6e7a90c34e58f770bc552167617653cf28bf94da83ebbd197e8d0d10ed747d6db4ec0ae323c7464cdb7b76" },
                { "lv", "2333d5d7a4ad8781e338eb629bca4f24633d87f1baca106ae1aac3383c3996dfa39bc32f385cf113b5c9a590894097cd1ef85240439f65e4df3e5c3281b09613" },
                { "mk", "10b29af2267e57e1b09fb967c09cb4f3adceb145faa9f9d11586f79da510943e928fc8ed31172a16f4ccbf8a4bb2be07850ffba66f23c677bfeb5f93ac2787a0" },
                { "mr", "fe451ea4b932d37c604888fedced276ec3581ac3c3e37d6638e4ea7c5f7cf70108986ea21f13973413a722b365c05442ba9cd42cb16481964460de080a420a95" },
                { "ms", "2240999821bfd776e7ea64d853bdfb9efc9dba65d5ca4236b34bf46bb24a723bcae40341f3cf58672ba15f961581070c5bcdaf94c6dd0d3b918b16477c2d68c9" },
                { "my", "6c821457068fee5224260143436abb54c56637cbd2956bc11adaa5be2ac3126b343822a266a58f757ef58dbdfacba948be38ae1bcbb4a387b16a49352e11a99a" },
                { "nb-NO", "9459f7775e024da598630418a92bf795300c4b7f772dd37e978bcc677a44e384e422e8a65e9ce571969ca665ba70a6e6f8b2c62fdcb783be5589e259295433e3" },
                { "ne-NP", "e20bb4c9b49d03721d8342d639b0480e22d08cc7df4493df4fddc566acd521e3f80300c609183853a1bf4516c55cae9fc671c1e58697de67dba8c68764a407b6" },
                { "nl", "5b771bff5e9186bbc212f4c9073b5eef8f6fde642e38f534b982588e40c04e942a0db5960ee3ccb729380c19a2703514602fb6f559d6495fa4924aec62bf8e90" },
                { "nn-NO", "247b093ac380dc50b8124440b3b4603674d9943384348fc946c063f29f45eae3f3a533679c265b2a93b593f03e1ed9af51a8a629fb72d85d2b84c367690864fa" },
                { "oc", "dd53b01ae865868ee8d1682fb1234c5a5fb6f22898a725df33684e411665b97530a4bb7f0f0f657f358581a9ed80b5a776ab27ae0fa780807dd419667064e9d9" },
                { "pa-IN", "8561b4602f7c5b214530cd11d5789b425650a1cba303034cba888b52b8f4c5bd19c68f5dc673e7bb585dda0a454f36135703210ece2ba31dc7f9d5e158188518" },
                { "pl", "b501387e2c0d5269fbe9a070931245832fb3420279ec507d0f1da3a846a9eb4b0c2594f7d1c336b05ef606af988e1ca56ff7b48eb1841efbb2b397035add9e19" },
                { "pt-BR", "ecd177f79e69678a11d2aa5d07d66da1859fc34f90b0fdd6142a3c2259861fef62eb5e9fc52f08fb04cf914d46959ad33e1f61698fe42868258667ae1d322e29" },
                { "pt-PT", "e79a2b10f37bf5980c2b60a3dd6accd5418e848fb65ae4c8ecf21880431aa9a8ab5b5fffd7a8722f548af429b133485b4d3da84504e4e823061f96ecc20c3cfe" },
                { "rm", "a059ac849c8bd2e48644ed5952c97c4df14b9cc0ae5abdde1c0441e8864a5602a4793c461032b023b9dc51677b52b40cee658361f7551fb0663de1b9745c1d71" },
                { "ro", "1ac7609e6ed1a8994d2006a70b61de25d93df5053e2c27076ce5604f0d4a1b56c65960bb2bb5715aff521d6987432c252e9a91ca2344614b4781178f18c7bde9" },
                { "ru", "773740351f82b92ac8d37ea99a78003bae5a751627d07741f74d42d9e9a0caff22b9df74d0646ae12ebaf3127bde8e76214895b89b8771f76f81855dffdafac9" },
                { "sat", "49b2e09b7b81b35436edbde7de06717a8e12976ffbf3d7a15ac68193f023956dddc5e82f8ce2b3b8eeed44c0c9b79957f876fba0f01991c18fa913172c1cf40d" },
                { "sc", "e446532f763ae0f9adda67f7d52d992e87e9c41ac24a166cfa4cdc591284659adee3e03e401e8984598383c1befb9372de91db71e8a3f935b515ce2868d6cd46" },
                { "sco", "9ed24a7822905dc39fa66ba765447eaba33ae29470e6290e6f81191634e412b5c9f1a483caf4be30d694109d5c17618b77947fe4e6ad80b8709701021880f6f2" },
                { "si", "440676ff674f08e0792ecc48e02f9d0a988ede1042a6db3c105bef2b083dcda6e356327c632bfc52c2da90db5c78b7925178f5130c411927e67da624cdbe53ac" },
                { "sk", "9ad05904c8c8b2246cd5dc87f9abd20372e1b22fd09b86523e794c1d64243abc27bc842ceb15a6190bc47fa46dc50987112b47f2e1c4746f681a8195eeb403f8" },
                { "skr", "62a6584d14d509b21e5f7876a9f10af29b72a7d5e37cafaa6d2bbb3efdd76f459d256d030edc724fcba77dbf3fd5eb7e6469c0ebc9b62d85076321c21907a207" },
                { "sl", "7988e5a8e3a269dd7ae32ef4838f4e781a23f1c0b88a18ac8dbc3de51ffa3eb36e0ea6e12d2a6891cfeb347609d2c5b4abcaf4342f89d4f1f982e2b5009665c9" },
                { "son", "7c7d88dd90c244e9d68fbf555c2b48bfe4f031636eea6b8f796c2402a8f41fd56443dd29f04d4714ca0f2ead6a6c8b160de22092def815adc6d0ffad40b1252a" },
                { "sq", "f69cb0b372dafbde8f2d994f6f6e4d34b4c8567ad82e3aa867013ca26d1b9fe95d298eb3ebb5c991ca1408b08e82668f4ad1849245fa15d088898433ed1c0448" },
                { "sr", "85d8095c964eb5fef081ef49bdbf238f134cb2f4239eb0cec6fc354f9593ad6576c5efcf7960921df7c51d457c7275dcebc592f26adcd55cbb0825ac07bdacb4" },
                { "sv-SE", "bdf4c11adc8eb3d7cb37b36a2b5591b3a4055b9086840194f21f8db58f47f7bead79db0c427c9616fa861aed12c4b78d96a8b73d7a56a334e77892002d51fe04" },
                { "szl", "8bdf16a6fa70fdad406d3c217eb4cd9d50344e6fd532950847aef030fe233bccd91062ca5fbd0458a8e061289f3bb8413ae4af2aa693ff8a8744bf0799a6ac19" },
                { "ta", "dab58e23830a1c9005849d31487f5cf5cc33c52b3abfe94d8265f8d96915a53139f6506e569a413c0e9aa91910f6cdf7c6c2c9fea527bbbe93dba6fe128074fc" },
                { "te", "4a9495a658054f22489d12b200fb39e60e6976b62731f262cd4e025a322049686136c0143d9c73d48fa84bceefc4f9f4bfa37cdcf000d3856560bc230230bf8c" },
                { "tg", "cbb67f08ac0209a8ec05dd05557f473071c3b09c4e5f95c3148c2398c924700fedc04c702531ef4bd2689dc6797e45143846522892ad49eaa2cce7cf81f0c9bb" },
                { "th", "5225b7cc95d328653056536437dc46d995696032a773ce758c760c01f2e5f30166ef8128049e21cd3a7d41798c218d31bdc11a232fa6eee84e7f3b184399e11a" },
                { "tl", "07d0c1d3ce9e7559248747f0039154ee27fde4f76dba8a9ae3a3378dbe4dc5b151e2ee77ed219803ffc7fc4bcbd5e29e20dcb91c4edf48ba659b29b032aacd76" },
                { "tr", "acbea5b783a30d8812f69a51abe261a0d163083b02bcb9f079bdbb0cde9e8ad8475f213c91d53e19939df13d21c25f72407e3b0718301b2e1ff3994bcd85199f" },
                { "trs", "f278431ead07ad6cc808e171ed76fc59955cdc063389ae2987b34fc3440ed9088303cc170a6d01c540826970a19aab2fb722500c360d6d8109fb1f3075f64079" },
                { "uk", "138ee1bb1b40af06b291d811d28f25f947dbd3057f2317a332e7e8c7eff5ddbaa5346ae8bb65a7f963acc9c71f7dba7d757a8ca39f5f2e328f452fc8728e439c" },
                { "ur", "2a0a259982d1aec5adfa79b970bc04c2e0bf5f9eaac2b416822f098711d582cb41ab26e1a0aab461e36aaee5ce794ff9b722a47c07c6ab849eeda0b2321091c8" },
                { "uz", "879b992d3feeab96ccf6ecb8eb847fa55ddfa623950e89ee0388ffe4467168e09ec053b1cc5d4355cbace74cb95c12da23ffe12a90ca401bbbf01e13c0164a1d" },
                { "vi", "9502cae1835d71d3d5ed8a4b0b073c8447c3260576cccf6d8517533a519599dd2a749c07ef579630e69769266435ecad2dea7bb32a7eb6f21c1c6df6d2b65f5f" },
                { "xh", "e33a600f67d5f21e7c492f532500e53930902cf3e5888ddb2340abd6bf279f69c93603e2c292a2778d137b88bc2ea6c7a330275e50262fc37f80945769399438" },
                { "zh-CN", "a7b6809dceda8725d98efd6a30cfeb48765e49673a03d6bb9b898ec9c3e26214593ede18a533ef8e690d443740915a421c1dba4391d9953db7ca21c4bb428af6" },
                { "zh-TW", "b86e345a3ed8c7f23e891855b8c8f85925232978eeddaf02ef4135616287bb62fb889ed6315e354e22e53d5247663bff90da501ad95a860be04ff9808a145fd3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2f57f1d23889be65b3f60ffb168128bebce2784ef0d03150eb0ee201074ac4a28b5b04c749797d603119b03c696aa0b22faed57ac80373ca8e43570b2ad282b0" },
                { "af", "4faadb9b66bc5344f6ffbdda6dd9f10e5f5f3d0333cec148aa1ed844b9964f9ae010137d5fe3602c0833eefa67b5d20906962c4bd46f02cbb15410afce41e9dc" },
                { "an", "16e06f8c2bc4c766b42c48e81f94e53a97271aa3d45e3df5d860461484690b7d9f3dd55674cb3ada83b4e808b0d5e204dbe4fe0acbb90650c7fd86407edd4632" },
                { "ar", "35769eda4917402edebf48808aa9c82f5f9e19797740d4acf29118040430116e45ebfd19637f12ec4b8e77c684d7a1c18e8568b36dbf404b9f3355e18a1241ba" },
                { "ast", "aedab370b2d4394289891628fdb3bcbf0db36b87659667f88fa3f21882abbc298c3c1bbf35eda404d3fe73391ac01b6177c7035f4ec79b16222b33f69a1c2b9a" },
                { "az", "b493f2e2105bef3d1c12362e4a8e602d8be8c5f82c91d73ad04580b02e8f2862031ff8ac6a71a54fcd72a4e301108c9580a4fd1b7b2505b06de452c5ad0ceaab" },
                { "be", "987b99786896fb9a2787f3509586777e40585a35fa0a98973790e42452122496d2b04bfe2467031389159b372a82235abf32a6f87805b1c25b16145e40d5cade" },
                { "bg", "325da74d6366fa0c8a5021d1c8a412910eccaf03a180bdcbabff757a564671ca9577a6afcdf92c32ee32addddd5fafe018e8874a1116cf727714b726c96980e2" },
                { "bn", "226db623acf240d9b983565e630f1f41e6724e5f5911f2a20c718907cf69041a3c7c91845ca74ed5904f0438f53c3ded58139e3329f0627ce5b5db08394d59ed" },
                { "br", "e753e90b0b91271e9e07933013f8aa72db66b26774c1604bf41f1e9586faaf3d3277b29b599483ee4a0f95561b4d636f91d603775ec9fce245416028eb6f0311" },
                { "bs", "881ab18429afa9c236608eaa56b9e948b14d8466a78dfdeb1b4c470837d498e8ca39ccf9ec7c0c8865c7322e9d380c5ee671d44f14a80a5cbcb16e61b1f0fb44" },
                { "ca", "08dab94ded3c46490285e81e033214cf82911efe146028f804cb718303aa542942adf40169585598a5f9680bc235481bd4423f89c05c5517e3623bacb3a57914" },
                { "cak", "4de7424e5ec70156e199c0f48dab10919ccf016203616bb48eece576c5303e776de8f81561286181257e4dc32400b61d32a6d3901a642f90e5423dedc7417927" },
                { "cs", "b43e408eb7c8845c0a97e8a821f88486ae0af24dd7e383de3e10862c70d1797d186e532966169ff7d805d951e7432b5c719616d3e0d96addfc921bd6ff35e83a" },
                { "cy", "57e28486398cf3d92cea0b7e7c955dcad8ab59ad69430afdbd1d3ec3d404294b8285929b907b5e0e6b84243ca564b5b34c4f4d0a7f31ad33d96437806a35d254" },
                { "da", "0ad5ac0dab8e288f6b292eca3caaf4d9453e295f5f830e5d3f32cbe6d3eeaef88763de63f4fabca29e9818253bc91092c9303369860012db831c55c6a75d51f1" },
                { "de", "9f34c5e14d9dae901fb850f65c5b33e4aea9b2ee58d0160baca89e95eee1d10215fcdb4dd89e8a1052ec673880f25c8b03595fd35d2355336c8c193aabdbd021" },
                { "dsb", "c87a42564d908d77852add82f35d383b731bd3d49c37ede897b5b8bec7ab0a76616b1f19dc7557388a3a4507928c5c47c8911b5301a6af55c779ab208a3cfa96" },
                { "el", "d6c8c075dd05f78156505920008d06ea1989c05ba4b6090a6304d2356759b57b9f08e4d2a42ce7ee56a71f2193b8fc2455373d31b9c3e3886596c752411b11bb" },
                { "en-CA", "c4aa7fa692b0c330977ba0524a1b1335af4c6a702cacc1f54e387a870070e9c87eb8873c683eb7256f8675e28cc81b9c0c97824d3b147baad424208325b05b28" },
                { "en-GB", "3298d1a09386d551bb49d03ba5c937b24f7d780d18516b6283ed8f84346c6429a84cc6834722a1dad22112ce35886a4ac831403360b4c641cd53abc5746ede1d" },
                { "en-US", "0f4c39472863058cf9007890621d19038682c661ef0eaa971859bc69a639c6d4b57c5d3284a813e8d67ebd9dbcb40cf2181bcb62b211d12860d502cbac55fef0" },
                { "eo", "9cd658ea430cd5478453122b86d9a69cc8ea6e48570e9f25d2c1d5ef288efadeb6909c5c3457ae42ea99bfb53f479ba7528b2f900abd735f2a7f45422fe5e7eb" },
                { "es-AR", "71396284f86e015b9e4c64e70046cadce34202a8606f197817067b13940bc1f91d65c28413594e81ab0d248ad9ce319df1ded003c820e8d27d017e2481a00c65" },
                { "es-CL", "cbc208601d6e772cfbd62ebe2168cf846305efabfacac5ca1f8761da9a4598e459e453d718a417df15c1427f2ec642b4e2b93fc5066a1b000761f18a3f42d861" },
                { "es-ES", "38bf2fe7610d2cbc3b7db19c9c0de1ca5999b43ce1daa48ad50b17bd9e5924378a16be7de0b05923e7a8c87c91d395ddf426f4e2db1050810f14910994906837" },
                { "es-MX", "35e3a9b97bb5d5d2569104e5db67bdfe99b61b95207e61270579cceab72450bf253cfd2f1af16d5d4a45a8abc04750136a78478fa3c3cf1c6d5d48dbe1ad0522" },
                { "et", "9587fc20beb62424fe804e72e2209e87be4a00298de9573f26b36aa89ffffbd70c2057a183bd7c5b15964e156fb4220d33910b9c9cf63d1bc840f7598db5c843" },
                { "eu", "c41a83e79cda93d2403fd9e054ecf99148a93beba2a9a787c292b487357227daed96dd08f5aa0e0b1cbc43d17772d5748d1d662352f3166303e39d115d1e696e" },
                { "fa", "e08af08d8062983dc51761d7774b5f8ed724784f6a5c58741219684ccbd7025590986a6df8f759df963f725f822cca263f542301a8e8e39e639a00b6f8ac309c" },
                { "ff", "e63b158f16d79af171467b136d8760ccf40f236d1b8d84668ee8f5db20645a5a6bcd0f9908853dfe4d23ec9b312f46e5ab704f5ea853c783e0b89bc47084a0a7" },
                { "fi", "78d6794a2c55c1eba77e64a3fc16b635a8df02a250413d3388b8ce33e8d354a673d7f9d0b66d737a64ab73c53eff4336bf503ecfbd79181a51c050cee2dbcfd0" },
                { "fr", "ddc07faf05afff54cfc937e4ab9206ee574935544e5347a2099b4f6509c533587c2520031534bf02a523b664cbb609763a93abd020fa98e5cb416d477d76df7b" },
                { "fur", "b078c9278efe900dfc242d50d0768487b7928b1e0f8bc1c5e9eb2127ff1c42ee911c25e10e20896e7e4539335253bff5a650dce528f0e5bc8afd1545c773c4a0" },
                { "fy-NL", "7a2a0eca1ac340b4e968ab22025f592960dda34ecbfe967dbff674faaf6b733d60c6013f560896e3dd5b36076524df1672a1d586e5a292d2b85d880ae7f9d675" },
                { "ga-IE", "58a85f4bafad156eaf9dd9938a390d81a996e3a69d0c17f9d3b42fa12711226ffc7d938b8a0c198a7bf6c2021f49c8ff4f8cf7f8c777e45d7f9f0212dd48b0e7" },
                { "gd", "748f36f363a99b88c22f8976e89c945fd76e9a7b8f0f7768b3dc6838aa9e553fa94ded9de40aa31d6a4ead2ed4968bb3c6936ce94bd0c65df96e2b68da7ce79d" },
                { "gl", "ef87abed2bda6424a480a2e890e99fde74b8fa429062f038e66ed7934eeaeef1390de46b0e6d6a5dd6f8efa5b53a6e2c1f4d4aecf7544b1d36ce63eec5b43218" },
                { "gn", "ce1503ccad2f70bfda62895348a104e4e33b1a55c361d55e433b19b241429d2776c56efa1867da591a718719f690c10921f7b5c3a5102df353a8034b114b1e89" },
                { "gu-IN", "f254e46c3a22aee5036bd49544fadf7a2314f567422a30e7d7cf557a193e61551445a8b948d084d1375c31c6456aefa96c6d321329aab0f7e28770fb4656ab7f" },
                { "he", "842db9870b65211d613a91c6c603285d042d31f60da7a28fd10a78c358e5afa11153e7b82ff7808b98bdd58ce727a8f6c7b1c6b519a09319ad4c3f1a1688fb02" },
                { "hi-IN", "0e33b613e886635c1ace5cd33ab894fea46799b02f855cc546bac77c77d868b13162340c395a455e89f0071a2752c1c82e73f253dfff5b898c49b3231345d4a3" },
                { "hr", "f4c7af2afc502cfeb59a1f0e069cf9f70ffd22618317a213db8a8d65a42af2bb37298ade5f7d825516bb55dcd4b10816c7fabba9215182bb36dd5e0e134bef06" },
                { "hsb", "e99cc08e59f4f0c6677f6287a0a2d50b07ee02b5a14316e62fb58eea86fa6953b16618e7b97fbcd3756f6752b73dc21dc0271f5a6f8c1dbc50f8882f853b34c0" },
                { "hu", "68c0bd4c923c2ab18a8f7f6262b08d543a855fbc928f5a1eb21418f59109855505ce7f2547f38e962cca5c19ffa81a6175dd4c1b9c5da8bc9c8cb3a8ecb98fd2" },
                { "hy-AM", "eb0d4d636f2adc07163c782007069c1da3ea072a59e91a1788b8700cc4aeb66f04de8d93e3bf45c5214a67a5485c3a58147b3f6cef62c9a7f52aec4c005d2402" },
                { "ia", "6ab207571a1ce407788e35e30814b1fbb11593602083fb2c8ca7ea0ef273d8d6fd65915a9c3b54dc59284d6b42cbe9bbd780cf28f2b68766ea6f0be220532b30" },
                { "id", "256d9f67706d98312b0b93aa07f6fbf89b0253dde57b8005f690363fba5fd3a82a2d804f0681545392842a05b67a332bfbbcf30f26aaaae891e08d86b9b57ff1" },
                { "is", "9f542b500b0b555c6bb157bf26f5df7d9eecfe780050c5cb33013a28f8366b60104b1ced56ff95810c95afca8b68ecbbc3dc836e7a86f08f30e5a87fa0a5b050" },
                { "it", "21e702319d7fad0f014d2b59b49bdec7e4e09c74cbc6a505e9a1fdd027fafe75170535107382ae5ed3b12a89a9e32ca330b41292ae3897a14d20b56916f3d8a0" },
                { "ja", "761c553f64329b1425248af0bc6047395d7470e5cf989bc138195e4ff99a562c910cb4e81b0d3be1bcd2b8aa1232f005a297b727cc7301d7004c981146bb0a60" },
                { "ka", "69d70bf0d83459086ccef513b036aff6c214aec724ae1c0fd7a98021dbeac5e2520acedeaef8a3c19be6fdebdfd67d7a61537a8ba01072e7b7ad4375e68399b4" },
                { "kab", "ccbde63f110820b550f204d666900faa2bfe8e421e343f41f7e6519e947b671258de396809b7702c2b8c21b50ca02ecd3b9b0f5ba68587630a03b3f9024d2eeb" },
                { "kk", "89c00ce5dff5f91101d67dfbada5a19baf47a86adcd654132579fbe01e7b02cf4db2d6fcb7ad105c908c975524caee6fa9e71e972301d4eb163b01c27699db75" },
                { "km", "375ca30527b947f137b5052a3a7ae6c83b5e15bd291e651d24ad7302f0e1361a809f5d8f3b2b723711021da74c7b5df0880e9f00978f356b24c9acd96c40ee6c" },
                { "kn", "b773b34c16a5bbe8be0e9c78ed4e60005691d38a5e80f3d03bcf281ec94a2f841b635b05e9e596208976cd65e72b8331db465581384d713c4ab56d4b3b8deb4d" },
                { "ko", "82928a16f0e9fe39cce3c8278c2cc3a52ccd724209c43f33aacb708957ccbaa44b132ee3b014bdef42e1bd5ebfded374600bfc92ccd4984d5005182584bc42c4" },
                { "lij", "18016ecb16630b3aef9e59f8f238183bc2238a06fab30367fff48d6e8de4eb7bb90d0dac75e45d934399e9e5209b4f967efe6c7d75bf6c976149dc55c2ec52ca" },
                { "lt", "8f89bbd2fe5268dc530da4a7f01cc3b2c02211f42f92335f7069eaf23691bbd2684da424aeec6fcf8e3ccf5f591fd79944ad28c9ba71f181047b58a5eb0590ab" },
                { "lv", "e315f4d287411f583749e502f97552bbd9c7a6f8cde815963e19625f5a5a8716e49c52d480814f342f6ccd877358295023af6184031eff435e071620d1e3b375" },
                { "mk", "7b100acaba2c831e41c70c674eebc041774b7e286a1a4dd836144700bca7d4a23b1e07e54e64666bab45a90064f18cda98d5f11c5c01779566a7c333461e94f9" },
                { "mr", "6312339a5c731be049d47a597380043ba9cb8d0600f1dbe7e3b7ebc371d46ef79123a865b6cdfc5475ddb43d9a104ee0790b761ac4320ccc01897282d73f54b3" },
                { "ms", "f15d03f27f3b27eef82080981f89b9423dc4c80bcf3dac617e9033d86e7a08cff177cf91976e784e03a05f20a2894c8007f4dd8ef511e61c48f51009ac10aaba" },
                { "my", "0654ef3ee43381531ed8af959cb216fddb834f245bb97b028ee176f7360b908445825773aa7f4b856b24913b8e7bf5970c68246cf3d9bdaa39b1a507c18ddf6e" },
                { "nb-NO", "106133f1e32ec6b39f7bf18ec7c8f21cbcb9e6935effb9a6f293bc676dcb0a6b33f69093b8fbbedf247a4f0802c4ed2cafab1fb139ecfd8842603c2542e69d6a" },
                { "ne-NP", "787c86bba971f3950b5848eb44e71e188b1558695332a589904f222b0348773d142f62bcf48dd22aebb3a85c73421381c6082c478ee7ddd3864936b090c8342b" },
                { "nl", "cd01d2930d80154f37dde208785d4ab1ab9f272d31cb340ea243e20ed33391c0b44e70540f8b6273464f68da8160444bba93269f55488399099c1e77274dd769" },
                { "nn-NO", "79b69bbfb4f9fdad3f6a977a61fe45603fdc780f9c4b3debd5b04a9602ba1d149e28c5cf96098979262630fba24dc36645284f9ead9b171619f25a59cebcba16" },
                { "oc", "132aeec2aeb534c6b6d74a9b5126cb3770b7db26161f204b737dfeb9f6fd1beb5487fba64ef0ca1746491639cacd1e7affd25d294dc617a87ce9d8990ec7382c" },
                { "pa-IN", "6943cd0d9d58577f5b29e75df1eaedad257e6ce17b769bd1576b5107a16059cd57c3d4db7c91e6b604ee9006aa621db95d3c48cdc80ea33943869e1cacd76340" },
                { "pl", "d6eb2e76c592246b045254c7fc9cba90e666b92506eb39a41d9ca44faf257bb616ddb6b0a7621a51794d483fb0b69573cb7b83bdfc365ccb3f1aede1aad0b7d2" },
                { "pt-BR", "98e8213d2ab24205540dc33e15fe8f1de25b274af2be03a8bfe73491a6938b29221b34d8654105725c1fbd29e880c3d06000cf57bb405593d21c142f2535066b" },
                { "pt-PT", "fb2380550713980ce6e17d8c88ab50fd5e79aff58a318cdbe6ec527ddc601b7ca3d4937b1a9c51e2ae5c39a82787053db39d164dbbc76821a10f6cb8c5d99466" },
                { "rm", "2490f235c9d14315a820ca514a1fda51c1bcc1fd014f960b0d3847410052f672247d88c6429985bfbd111339f6ff86db3b99048ce689ba4138881ea1b91e98f2" },
                { "ro", "321d2cfffb003295d7a78ba89de9522194e4d12f84e2385266c4434d07b073d06ebfa122797b1f92e447df56f565dfa6485ea02cd3796911387090593508ba93" },
                { "ru", "8f50198e0ec3ef243e8fdc7d405c80f0ab8b4dee277e7480e9dcb75267c5230c60192950fa4a8228ce7d0b50e195fda3c93c62837379d566f60078eef6e2e92a" },
                { "sat", "8743c966deaa40243a09d8d692dca8f96e76f5e18e695652c46a5843eded3a35c4cac46ee652e7895f22ef976b890823681f826cdf52e1e4456a4254805ffd64" },
                { "sc", "edf051169e3b196faacaa918da459222fa1968cc0f49eda8bab0d5ed30e8d90320c661fe887f9a31175b1fa8000bb9810abed8ef3755b800522fd2382122894a" },
                { "sco", "837e5ee2cb3037cc3ec48e195693cb0c8dae869fad9e1a81dd8d5e00debe049684b00d780d63ba45ff543a6d8198009d0d698444c8ee4e9190a07d22a3b576ef" },
                { "si", "73a7cb8430a46f9d0e98d70606b28f957d0d5e99cde3c048d7ab7d1c137184e2e36977c7fa8eef4b7893e9ec9655b1e9fed1c33d58a1bd5af676957f50fd543e" },
                { "sk", "3307655876d4a1c0dfe47c79bc5c1854c5a8684725ea0415aa92cd50ef1b5bb7c11cd0cdcadee1357a8ae84754115dbf9f70bcdd7cdd8c55275f6a595354db5f" },
                { "skr", "4f3140c7ba2949d2e9e71af4d4eb1ea64035f10821c9feacd1c67570b03b4ac577675011e150462772788b645d9745ac141be8e9bff704614020de59843349b5" },
                { "sl", "015fe059696174edb20a92b9c5d02b9c66ef50e58a108652ed8ae8fe9f8ce6e774c58f66f38fd93b922d0a923c63087a964a912ec1349518c73c065eea2df5aa" },
                { "son", "33d592f5be789618ac9b55b5280c32062f04c4c63177a6b1be800b1d9ebb1be0f96b35e0e4c26ff3ec4b2c40febe51bde29c8139d17ac714e47e9bc2f9727754" },
                { "sq", "3bc9fb943c90049e157feae9570ec4350283f9c4b36a3c2ae6375d8f477ba85da7d89144a1b24ab4c4203a799bdcd08590d2f6656b67ee3e67693e7c3da466a2" },
                { "sr", "e9f9f85b2dba72e5c66a97f1701d60e5241fe603b98b527ef3bb4256f0e0538eccae162a64e0ae833418564d077646759ef769193af98df37f31be75482d2068" },
                { "sv-SE", "5f0ec302ab8987bce1bb9a09ee05aa9900c1757eb86431e23e53ef1b2b995bd422b20be248fd15c0b1c5600dab3a58e827182e7f31b019191cccad3fea902fae" },
                { "szl", "2273b0980457e4e194b23c1e13cca555e6ad5359d1633e4d4747a79880e07f90746425a863cf6a566ea08f9810f504ce3f2db6d131c9b9a7c7c1055de510b997" },
                { "ta", "03cd76167905ff87bfa341fbffb34de4ecae10dabce645620fed5fe5c35eeef16aef854e124e06905d146217afb598b6c87b9049df19d961a251bec3156af7a1" },
                { "te", "636172d83c113e05cdd56bd9e08952a632c58424a9b14f1c793b6cace061f8af14326de76c2fb870d962852e361bc4dcddf7cbaf738733ba5fb350bb817cb2c3" },
                { "tg", "b0981a09bd55ab06b8bc49e4c56c68d0114bdb0029224f3d9dc19cef8b623d5e49ee340d97721cc31d87042923b8f7ff66e55c547557730262b6de37edc9fc0d" },
                { "th", "f204189c2bfc050b9ff9f99cc0cce6da22796f52878c7a667c798db37bf8ae4a69df0b0b26ec10b855e48da72ed4ce9bd635c91e08a9c6a1a1318cf5b8fe097c" },
                { "tl", "e81bbaf51483d385a323af417b71342a6489ea7156e649f0e1d80c802018d5d8aaa001bcdef88e0a98e9327bca90ac82268f5633ce40129c909be747b990856c" },
                { "tr", "95ffd8e43d076931ece8f0595c03677851ef423681c3e49c23616e4eda150fcbab956824280ef7bca2d1d75ec139ea4267b844eebc16713c3f80952df700622c" },
                { "trs", "c5ab5d1e317abe184bad3160993616be3cec8abcadb836c328a55ab8808946211cf1c0a2fdc74ea4f69bd93fb6b8a0662b9e5a517a15d7f7862b2a471d7a4056" },
                { "uk", "8da3b40c0981e85aa17cd574f55b972aa39b4362202c8c89ee24a2aacd5962a415d1f4623f057ffc5a0ac583003d25d879bd326423311984d4f9f62a35b919d9" },
                { "ur", "e36768c0ed1d79445c0c20502abec3cc87bdc431a1c3595443f0ba263d0a96d0a303386294d47d2a70d059d22c422f0ccaa0ad0f66db971c9ea6c7ef2441ab26" },
                { "uz", "d7a8d3c7f9ca8313220d68a210630021cf2a07cf7aaff4ffad4c9f41d701209e0d97edca734639ffd0c909eb4ed82d34979b5a20a8a97efa38748e3a8aabdb0c" },
                { "vi", "b9897bca4ab9ef1b079e6a51bd6fa5a11567096be352176ff043b45c59b9c0062b90b3c75c03f9e11b1bfb94398b7b4d14b750ec2e5307365532d4783233501b" },
                { "xh", "0d0d95c71483f90dde3a48c7d366b9aed0ca8e77b9a6c0782d3dbf4a9ab4bcf3d61ea766e1db254b623e2627133a9cf8069d1adf7e36fcadb375b4a934fea70f" },
                { "zh-CN", "93ff80d972ff3ad5ee7aa1affdf0184f2664d5fb8e39a0666aa96ee74bfba35852f91798a7d3df5e7700ce95777067b9d173c99ddd0e1a6a9a2bbbda16b24ee4" },
                { "zh-TW", "5b16a65f0929375d874d05cc4cb1b69e52fb7b8b09266a5a92fc8ad90407540ab545f40860647a9ceb4cf9864a593d13299b61e6ecd6419bb0e55807caceed04" }
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
