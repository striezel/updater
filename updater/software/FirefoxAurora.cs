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
        private const string currentVersion = "139.0b5";


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
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "25479b85b416c5efc034d8045bc5b7d78f96b3f4c7ab8d6ac5dcd46b125fe7c9d447bc4dc49c04f3343e422996ac6c12d9a159b023f07874f8b546cb80da9a03" },
                { "af", "e7f159510ed9f28d89700ff5ea9f2cd89d7a165d53b969a264883d10d3f68d33d6615168dc1904f9977843c9f93b9d7cdaa51eb39758a810a5b58f3b56e5539d" },
                { "an", "b4ccdc904398947d5e5b39114d814e855145ba4b710fa10d73c1d16df0aebee88f881a5e38ece98808c157b6aea5be94d903ee621cd80f6a433bcd9b05c195f0" },
                { "ar", "4dd1e5fc73b3e62ba4cdf356ebe37d34e8c82bb6083ad5e136309eb7cc1ff4cb1d90b54201ad27325b8020410e62a3dd3140853e4fa21e9176c230fb40471ff2" },
                { "ast", "fc3b1a3aae697d3dfe3c9ec024009ee03a7e061219d9422f53c4d993a154156d922907d305e460351a255a44c0565afa9f94ecaffc09dadc951c64341e60e12e" },
                { "az", "04f8c2febd3b23939e39176c43a6e3a599300f116129362e783a392131f2fc93554eece8a6c1efbdedcd5aada803110ebf6e9913d183fef89b376639afd43275" },
                { "be", "f93a95ac647b1fba88261484a81220e798c9093d5a98153e8d76c9b0fcfb7c3891989b8283083337fbf00d9f77c5c58ac941932f04100ea7b548a2d71340a34b" },
                { "bg", "60ba10bc0a16ad12fc84cf2069c2fb1b2dfd39bb2ef2937ec8a052574c81a1e17eb824aa536da9947f5d1e5d508a42ce9f51a487e83b10ed6a638f90a01ba35c" },
                { "bn", "1deef996a65f2be55244cce74161de5f1153f0b5087bbda9d01577ce4bc1c3e31c379481c5972ca22e2e4083d23cda8ded89ec76de82d0b52fdae0d5520ac86e" },
                { "br", "2cdaaa20822a990efed7f1ade86c8d2fa9731f408445e80da275287f1c5774fda7653bb896bf3cba6ed056ef98d1b30f7e0f3b38739ca1a5c2740ca7653b0ea0" },
                { "bs", "bf39841fa08877421f0ad7252af39fe602f04d7d69aeb6f214d74d92d52f70bcd650562f686ac6a533c2b4951666ac3725ae8479fbe7e07d16e8e64511edb289" },
                { "ca", "bd5c21328a775d217d3a9841a55044912ee55466ccfdac948892979747ad87cd735c011b846f2556835670293ae024070aa556e1d40a7da003968dd8381d00d7" },
                { "cak", "22a73a27393e23555cc4701798df6f895818f017055d6cbeeaf642d5dbf00f1844eca375c2fa23989f07a5f2abae6c63ca21f4a8afc7e1b551584fcf319e147e" },
                { "cs", "6b34375f626b8de5ba7ce25d3a9bf07532982c6fe7f3820f99c905d99bcf9fddde0602303b84ec7e40496bf5bd3f3071c23014ac296f48b73f03c077837aa5ea" },
                { "cy", "1d7ea2e186ad193f1e38e036d2ea5d10c241677668ddca495209350c003fdd5baf05f82b5a27e7449f70525d29b88d5b76f1c5afb466b9603bd53f8bc3bea87f" },
                { "da", "6f77aefb58b9af7994635b54553908c8323d6681287194f1688188e589e2a04fe891a887ae2ce3092cb63ac3292825f21ba25a36fe4c7ca13c0145b000866e34" },
                { "de", "1e83d18da627664ef112215bc8244131080b82d89e394bf864081f2272b08f8e57f8171ccc5ffa82f5e9706d3ca8552a88f2e4b001068046c7562ade00068ed5" },
                { "dsb", "874ff19c9bdab2f5a3dac649362315234a3622b76ddb37c08807df4611b66993e3e9805cac8fe17278ab7ad676cb6b0cddf611acd0a327c0cb8564d19299f0c4" },
                { "el", "b215b7f4cd076a3fb2bdaca391fb9223d4825eadfaf9de3bfcc1417e8f62311077a9c6945b658ea298df226b84f0816c2b4ac879480244ce572712791dee4b76" },
                { "en-CA", "e01b4e03b39cc8e411bc7fc98d2a037e50fc3e509aa1c4f93a6f176d028fe230d786aab0c364b541b56fe98d97c8b03332597b0833a45206573b4dd44547bd5d" },
                { "en-GB", "b3136eb58bfbbfd52c1fb4342b93bb7a3ec547cdbfd4efa31ed758098feb7854ea643cf0691833d8a58b5f7c44a11b1fe7cddde8b78a947e2ada506b712c8679" },
                { "en-US", "49e2c87044597e478a274ebbf3ee2ad41ab3e9ec639c37c16aa01b92caff81ef571ca129b4de711fb698ba6e03751725d1179df1555bbec98d1abe628e0ecd4e" },
                { "eo", "d90963abec3313f1fc512a8e836c4bb55a9643b4d83c17a9316d84f4b13065a93cee296146debd4610d183de277daf2397dd7101acb3e6916e68cafdffe0282a" },
                { "es-AR", "e7f9312bf690b9120437c25ce072d73800e984953af69295da1d423f499b8e11608e0430793b8e0613305e61e613a1ecef9ffd5aeaecd9792b35e2fb7502e0e4" },
                { "es-CL", "6990059bf8f8ccbfef391f68ef15aa54ee92ddad5d70c4a4c712984318d3457ed75121e359d2503f8689f8d48dfc5cd821752683acd06738047678ee2eeda385" },
                { "es-ES", "fed2b16823c2aae997e7334f1125738759da2b99e2c1716d48b5115d3798db655a168354d54d55b96db7edd6a121348a303bd22ba198c49ac6094f3cd37e69e7" },
                { "es-MX", "e37d4f6c2adef34f8c69adc318e851aa0398f562a41d84d0bf49f52797fff73a46e19a1611a775de56c208eb2607b162d42151fae1546b4e6eef208274281e1b" },
                { "et", "150074ef45950a0cf3bbcb9582bcb76eef626771f8c0ab3aad2111ba3ff6d2d7e2f3a834ca286bedd33599ebc8fc8f15c4032944f37b79d5c7889cb633f18165" },
                { "eu", "f162ae7c13b64767059127e3de42f1a4aff5951e6e6cae3c053c97b299a7a685b2eeb4af4238fe0092a1fe2781b8da560e5a2ea4317e0bd82b96dd8ebe374162" },
                { "fa", "ee0893b648268c04bb49ade973b4330c8904d5228e2750879e5c57eb6d2a36b3f266d49918c48628b713da552cf6b66f0e13237d1e49f7901b87bf3bfd6c73eb" },
                { "ff", "44f84e6f58f61d469ea0783b08485b5c2a7cb4b95da06f27a80fd0dea3f270f27eb7bb51ac172113fcd5b36ca9ac6a23b6d32ed6c17efd44875e933895061bc9" },
                { "fi", "854cd3832c3e0a0f6d7262e4d638430595f164a09ed3943a68af5a727868d0462de13916b3cc3ee0bbd06a34208ea51287d16d468c0143e16ea5e39ff92bb926" },
                { "fr", "13b4d9d014abe1e0c37b44b8ee48a46c5554d06ed46d8c8b16904ce28605619a68bf58a213a53c52d2f9907069193b537e0e3165fe88d04440152aa2c8dba462" },
                { "fur", "f74e71b87ffd3859a1f4f6156d48923c743a19a2c27487300ed1f51eeccf85f205af824b5014214a612b5690269b9caaeb3489ddc0afacc128c028382eb64468" },
                { "fy-NL", "e726bb5920db8b92b2ea24f18055a137d898f5ec70ee602a1c54f475ed6915eaea30321c514ffe694fab776661285be4d611374be9118fe041109406e0588012" },
                { "ga-IE", "b1dc80cccf9f045731dd8aa516bb533482d0182e7bf0abd8fdb9a51f5f950be7f3becb2cd8469affe06fadb46c73e18a6e919b24d5cf04c7dc7a277065382f0d" },
                { "gd", "f13f1e0640a513a5b258b338a2285b1b0f5a58640d0a27013443f0888cdbd8b0c3539c1e314ce4668244b14af451c4f6871c83a19fd383ce00ee9f2075713b54" },
                { "gl", "0ba3a693da309d1e940b4c876bf7fdb2f6ea56c4a7cc97a13b1da9734874f8d09638cf792aab4dbe4cc348477f3869edf9f10ecd510b76b248de40975de68a7f" },
                { "gn", "47db3ea76a943e745af9b676a418ab58fe92846c11b995e708285529e1f09e18519ba685998acc595364a493a34ae80ec005b8a9fc1e9f186db47f655ec9e697" },
                { "gu-IN", "6b7e858a5ac8386d3038c967df087e3a846ebc23e293027a3fbedc750bda43612fa7a76885c201bcdfb80cbc88a9bd201306e0baba49f2e1ad1e0021b2e973c2" },
                { "he", "63effdaf07e604023b1c6dd36e5808cc75275d15408aeae499f3fc51d1123f5dc2db18232b9dfb3b156f9219ec1fc524a08a168bd72396bd08472c407b063585" },
                { "hi-IN", "c4b6ae4bff685ec5a820d77574283212e204b799770e5bc02b4cadb55c0436f4bd6c317d2fbb4fbce0ff3048073ee575acea0357bd292622af3e9b2d2cee2d97" },
                { "hr", "389cde182a67bd1bc46443de966387e9fe4e2bc95165d57ed025b93419af6c97fa7ebff1d81dc6bb94417dd1a400d7cda79d1a0cb5af0b7f3cfbe89bbc094200" },
                { "hsb", "2629aecbb8e74cc65e38504b806eed4028f097aea0a519e9a5372bc076a97ddd4a0dc074b92f677fce29c6368574f60852a09f20861446e8cdaa5a2aa6e02d8e" },
                { "hu", "9fc2efaf0a10d8de043c93d7a41ca9f01549d42014c1c3068fd462098b1cea4494010ae2e9182f2e9c8475323e0b02927ce5953c5e28b95573e6c11ba9d51f16" },
                { "hy-AM", "d4825900aa98e21a21ab5577cc430b76b74ce511cb680572f0e12286832a154a44dc1ee9428d28b6a325b63e3954199c4f90229702c9c60b45041db0ab588bd7" },
                { "ia", "ed2866393927256ba9b8e85ed86d7ae7c572a165897a8f51f90585620ee386fc1c093b03721574c77ac6ba370443fca8ed4da75a76f983d23d031d1037fb5db5" },
                { "id", "6c7f66e5dde917d489154032010897b754b14d7937b67f43f118d5c000e65bc90a2a86d9eba3fd1a95cffe414546c5bed31a120873c1d4f7b3bf8a0043436074" },
                { "is", "1cc6e219adc045c45a62c7ce0a217d1b33ab0956cc676fe8b3ccbb32693d53492b3af6068ef3374008a99553b7dba8c824119ef2bacc318b1a3acbe1a1120c7b" },
                { "it", "3a603d784d920232b246df97e75399840406e8f0e9b8b2a663c0dd2b2a5782582c9e28e60d4d9db70446bd6f00c981a121e4475dc8cd1e54ffdebf71ddbff5bf" },
                { "ja", "ed037dbc858e6293da4b252afd05b84ebf54464f00a73365a7e3a881aab558e23acdac3865b20004f7c1ae9524c451c562f83c5ddf925bb8cd966f48636f8968" },
                { "ka", "31130c2c48c6f0ea8ab9ba197af07ad5c460ebbaca4471e47c6dca337f2746a73d85fe3ca7898e372d83cb8ae3edaa02976bb4f910e03fe7853e8020dc2508b8" },
                { "kab", "31e44ded6f463cfe3d05bc1b161e81bf24c218975f7ea7dd6fd136abfb3e0fdd32edf94d6d4e1ca19b9eada30543e444195e3a424d7b9ad7eba62d14bc765559" },
                { "kk", "602ec399c81b7f5cb7e231b51d92453c750898a35225ad804499542c2def51b52816c85eb50f363cbbbad7973fb9f99eb6d90b2dbd48e55a5aad55a2e7ea43dd" },
                { "km", "257b06161e3a002cdc1a739cb64fea9140f909bffa12c38b8418aa62d82e6ce8f373f728581acd838b25d52f50629932ab52348c4f6953fe1d45cab3883f0f6a" },
                { "kn", "ca168e7dceafaf7e66e9e2419cacc0215147876eb068a998a4e96b1750ffb03c2662deddf65727667ab6dd636c5afc093bd6b0e95ccb567fa0374556213bf8c1" },
                { "ko", "091cea7c08b6a6f588acabfbfb5d533d9971e167c9a835a401f2893ea0f7913ee91d15a5cfbf050bc5653cc84d223feb9dd2b9c3f794360c1a7dcc65f131078c" },
                { "lij", "76ff2b4b06d2bea3497069b151205a5e6b9280a53f255a6e5fab7139d3690d9e510e5e46952e2cef6356ba5157c9d26add2f645f06981ca7017f315a148dc9c7" },
                { "lt", "71beb9f7676bfb265971bafcf6358ef8f664aff53decbc35293a408f4245491521fa610147cd44d991a1406cc58d2da32b26f8eb68c97dbb47b44653054abbe0" },
                { "lv", "670712ec44bb3b3fa18c8012f06f3d1c0809a6705f74e6cbd2beaab5b8e3e48e9fb80a8d021f39edf0a4eca0b423cf74daa2334ad9eca47bb406cb88fa54ea5f" },
                { "mk", "60d0818b174122e181d69af08f00f10761aaf0fa9dcb9384bf3961f88275dc351bad4aaf2cc7e77fbaefa266de79e70865f82828ae9771e0b10c1818912402ca" },
                { "mr", "ac9bbddc12852f38d58fe332b6b7e2b251996d275cc1210997589fb078c87b65c598042c28c88178a0cbd17bcbe99ce4f137595ae28d285328f246d835a7254d" },
                { "ms", "ca68449fc160d39ccd34df034fec8ef93fdbf006e4ce1d955be791ed3689409fc9d5e8dbd8dfa869b45f9229f283543bf63ee676625732bb6652d192c9aab41f" },
                { "my", "20bc878471bac7ffe34777c766b857f7c5768e8606358f188ddec4326c4619ba2d498aa2521d636318bcbd908772a4988d9917cd00fe419d2f63e4ad742c4143" },
                { "nb-NO", "e783c23b8272670e85979a5a92a9c930db0fa31cb85b1e2fa04a251ceec0d6109b8432614b5d9a4c8ea4562caba4c7b0d7a479672f6841a216d739b1b8ad9d71" },
                { "ne-NP", "0bf6a65aa2d25bf7e00f854323e9831080e925c1eec03484f06dd88b84bdf79addea554e66ddb1f1b2c8cd5b25fd22debf13aae47f02c837ba39797a62f3cae1" },
                { "nl", "68ff6d150d98426cec73a68399f54a7d8b0bae544637bf98cfde3467e7d46e4fd1aa9fff8903fb8c032305d5ca1b0cf095865fdad916d48e90e5a5cac5753e2b" },
                { "nn-NO", "ab33cef3c1158a47083c7e7227dc54b1f60346dae80efe28c6c2bdf8b3f4cca4ebc575be93b7475dc0244c7538b28032626c7916e7a45c388eed55afc1434664" },
                { "oc", "736297f3171a8b28dd46fd60b8036bc73d124cba41521cb8f3f97e3ab406baed8cf49ff80c601cbda4d2b2b37ac700cd632c5374deab42d64002e58b2d6d239a" },
                { "pa-IN", "3c803e30baca45c58684c3b09534a45600df4c9b91b0027deb638d375b6156e1a1ecf3c33a8e8fdfc9688e14aa99fd4e93246dd2958330a7cd0ad9b3e75a675e" },
                { "pl", "65dc1a418f4f7c75b0e054c7360a4487f66acd433d11a675046f56c0c61adfdcc65b97007f2ef3787af90744e30674a6542165b60c22b9d183d9592288e0dd3f" },
                { "pt-BR", "c08445f3420b078b28fb484ea9f58fb8bbf92631c1f814cda4abdd4d58c81fc5d9a7c511ce0804591308af50c50c601a3d32452fb2bc7b4b4028b58a61175ff1" },
                { "pt-PT", "afccc8b88bfd35d5b3f42a5566a9c8535aa56f12b728db7550d912ad516d5e6f1ab0d6ce05cb033eed92a00ec955071670e43f41da22b18cdec78ac3ae4deb7a" },
                { "rm", "8ee26a11378dca097f3209d92ca2d1555287d31777cc3f734ef7b5423eb1724df471615aecf2dcf33185e2dc9853f922b7feaae18a363bd6b7b8d97523f646b1" },
                { "ro", "fa4094d03829ffe19facbaf11a66ee95d45487a4b931b5be5569448c0a6580028ed4591f983a3fdae96d8a61bb2bba5746f6966c9feb4ee37aee1667525eb935" },
                { "ru", "0876c92eb4831c60687e4535b85c4b7337711ec8553fe108d51f1ea5d96de358a82dc981f118a0479c813461279affe656e106c022013c39e8928f7f86cc5535" },
                { "sat", "2bba7af40ddd5baa1bbc856eb93ec0d4580a38fb3ccf91c5918ce0b4e4d46cfaeb204670684b0eab297303cb10494da09971117ba96be70f4b2ea8e40308bf75" },
                { "sc", "01a864a4ffd09306e63d3db61b81484bb5d11238e7775bc0f539087f95c37581d470355f77fe13c1fb430a08ac65d2ecdcdbdf9957a53d874e874c8574befdf1" },
                { "sco", "3385282304bd05b0933ca6641149be4c8df7adfabfc835e654b7e1fc13cd4802cecd75f8325610b9976bcb7515c30de13cdc188e3ae475909c4ef6c2e0f4d60d" },
                { "si", "bd864b2639316dd417224c88ee927d87bfd3352f177d4e8815240c368882d6ff6286c66d6a0c8f208d698dc5fc5888951d6fd1e8e257223768b9eb8be87f2f87" },
                { "sk", "f6663e0f2d4567d6f26e4579631423a753522ee5a03ef55b59afb2c164cc5adaeb6df51d71ff4c6ba66f16908cfc9671157f77fd90828f0bee4cb722051af52b" },
                { "skr", "7731bae09537495d7db053109e728ea721cb7733a42a883d7410f368d2389d54f2fbccc4d82e4e581f200044c36ed1a6ff7d946d83a548bf64541e0452d6b8fe" },
                { "sl", "c0a0584407e012ce8b6cea7b6db6d9d03ebe63729387c5d61bcb7f5c30f6cfeaa8140b3c74f63574195ca87788d97ed6846543e99001d08b2004c87baa8bf9da" },
                { "son", "082a3b882cb5957945beb9faff2014406c8eead2d76310d0d1eda6bc0599dffdddae564a946a9c030da0d3fad4d5f8b3feb9f1b779dba7406dfb034058f06f36" },
                { "sq", "49aaae1890d93643539342a1d967eb95c9e90cf80497d21f1bf792f192ef8e8c5a430d66a4794ef934fdd310b2dd8f44453d3d30eb191cb1d3234f26d2cc96db" },
                { "sr", "954337f6e1169a6be42f56ef32788af4e5483e778896bcde92ad3239d6fb2c98c278ffc230ee002f2f1c60737301c8e420a37b5b15a7f443a561eb1ab9b9c173" },
                { "sv-SE", "e37ceff08b50611d9026eba54260d8f5814c9f422bb4bc3de3fe7b7ac3efe2a92d1a23e662de8830a7a5cef6c235d0ac53b3a87494b632c15a810d89280f85cb" },
                { "szl", "c5f15a0204ee44891b5ef16891bd7f15c41acd186dd3a8517efeb3b3093904bfc5cabb7745709fb995217f4bf91c7efe410e726b498681716d034937c46b85da" },
                { "ta", "eb785b99cf4b6b86effc5d30e0476510aa76be16b2a237bfc5f7848b1372bd87b21d191a06eb6ec548e6455f37e9ba3e505b6c458b3c2e27ffd687b896b4ff1d" },
                { "te", "6e4ff1acc1513e00f7124f294c7e90a185e0b2cae397a6878f8f0e266e56a0f9a692d5a0870a8cc76bfafaf3f0a02af4d07efb3a9b337ade7c2a64e664e36277" },
                { "tg", "5c8983f3f475192e7c064cbb5d1c036d81d4ca175d9a533984c5219c0ee1dc70fcb7255ef5cb1791dbd923a2538305c483c746ab510f151029a0f170d70efeb8" },
                { "th", "d1934973d4a65770343f958fe8c336ceac1aa58acce63d6deba53423e37ac31d8bcfa179b8fbe4c1eaff94ecd75e0c80a10907896a194488f3f188f7459cd2b0" },
                { "tl", "31964290081febff78d057852b8241b680287b78f332dddc86a60d62dee635f82d976042508f2bd30b711faf17d5f9d232bb4d0340feee23289293f4774a29ff" },
                { "tr", "57e4d1347440f22f504a02f92b6c6e5a0712b6f73797b5bbf8cd3312e80f11588bc830ccf5715c0f30dfec5ca80082ada48d88db3b1cbe36b0633eac536d7b3f" },
                { "trs", "25be421f1275b5803f6a9b8f7fef680998d2d19e7634e69af4e8e2983f05dcfee0296eea999b65e4d48c6a7bf1bcbe033dfa3076a7254e3105bd7233d8431030" },
                { "uk", "5fb809bfcc1179bdc0e58ddec142cab44946664b343f5e0a03e78ad63058b8e3854d07639f3731da8b116c87f949a036f9d09e705084a03ae62feb493ecbcea9" },
                { "ur", "8e7952723f0fd7890135c7e0c58a3190913e3a1e60fae2e7f7e5ecf53fb0b6cea35622f6e07540f7c8542414a6dde04e1d006de1f178f3b0205dda6fb54de493" },
                { "uz", "a2fad06e6f21d8e1ae369208ed0e28cb94255072a76d008f1a4f75ecfff337c006e7b669f72171b95472c80faed99478953a80e73bfcf01622f6dacfd1058d65" },
                { "vi", "1ffd14730c7a94020bf5a9eff9f75ad754aa455ed88b736b9ae9f9e4b2450ee2a2d0f9cd9fa4e62f4cb03337ff92997372db71d6b64840d63d0c4759635802bf" },
                { "xh", "1580146c748955c15055efa28857c541c45b0f9fdba3b1634d58eda4ed583adbd863f78f2567fc414a51d5d64b0607d212c6d2e6daa1c5d343678366692b7b6f" },
                { "zh-CN", "28aecd1b92b63901c99442bc425415b86f915da46b4cb14d21013a1859a62a4c4c0e99578ad9e5ca4a804ca3c5ab80e992111ff00d425cc0993f635218659244" },
                { "zh-TW", "ba80e149f37a7b9eb79ab5831a75d2ab100f3abd1615191663f1bc76d5d6d77341be255661f64f9a71abb7d21301aa6939c0f27c0ae15ac03a1f726dea6b6727" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "88a6a32484f950a2ae89ed5d9ff330e9b6e4df896e3409d5f2a425e403bfa63179684503240a81dc3906d9e39b598263ea4c2a8bc6410a71b1fc272cc4d47ed5" },
                { "af", "40c1d284e8a3a6d31b2f82b9c3981e1e0730e0d43136773d28c126f97901f3a0a498d84fd6926a0eef26bd7efd0f53e07f8c627970d10ac77bcabab7c697afb2" },
                { "an", "5f3efb78c93f9a47a2216e9b2997585b6aab960f91c43a2b5417efaca52a1007ffa1390a2bbebd09dd206029a1b7cb03da8bac796c79614de74e44b2637992e0" },
                { "ar", "3644ec097fef2fc1ebb47a3c5156a417f457dfbffae97e0db5b2d299f62c42daabce26997950720ad70dc4b3347fe793ef3a31ea863aadf76b6b197a222f68e1" },
                { "ast", "6a25cf75ea07b146253babcb0518669523f0f2a5d18ea3525f97a549125974216cba8175102756785085ecc079f261cabb59ae7575146f4b1675923973ac2fce" },
                { "az", "52cb4ccbd326f0cbc21d06d82b32b1f289bd199f9097426a47d7ece87b0c980c8d9d987e57b998536d0a14921eb4c222591801d5ef1a4b705c1ef6eaa15b8ec5" },
                { "be", "7c407655dde1cd353ba768cbd6569003de6d40025038d4dacc5affc87ff10bfb9d5b5cf2e317c4dd488c9b7fa14383a7d2d437cc0149c8c0faa1a6aca84db5bc" },
                { "bg", "9c4384c5af81469ad3e80f184f1a50564848a830729ee66ecce2c386c30e6d550a14f10ac3c8cc4856f7a792e0b2c4361a8b090d1351a03caa1b36354eb9b2ce" },
                { "bn", "37b9df0bfabe74ed2069736e0c770614d2b7db3da50880ee2a00986fb260ee362beb232beb0406e9a93703727b78a7c2f95a93ac7293fdbdd5dbdef877e23607" },
                { "br", "8945ae94fc35cc2caa08e9dcfc019a0d30b81dbc1e80737203b0aa32d402b0f5641d15cc77d57eecee34b7bf17c8b413bf4319f2428cb6e22940940be8b1bd47" },
                { "bs", "de63bc93ed03d987d3b6c330807546e3667ba6db348d9ac36d306abebb8406d6e5cdc5348464e11d6ad5db0167be89f4b27afcd1fd4c5fb5b85a032a717c031a" },
                { "ca", "36b7b0d1d7d424c599e1902124339f08ea77f30d3e6fccfc68c9666d660d9f38fb8ca1bda4a1e73075bb0506867829d9cde87dca3fc506776502ab955477fc53" },
                { "cak", "edee4bc3b5670d26dcadbe21100dfc97c7c3c4fd948e13d9bf4267f2f86c3e7f9812d3883dfa2f5b1341776585535c58d98da7580307839454ca79017bedc4d2" },
                { "cs", "1aca5ac2fdef0d3ef730f6bf1c80d9c5f36cbe78ffa68a9b91eecb5d52dd9a17adef70463f822406ab2d0ca9a03487cab89f4a0ca64cc856cf053d99ddb750a2" },
                { "cy", "f62cffbed0ee9f3b9147fe21835a6c902e216c24282740148d663a9f9955a1ac1fec417b7271f4f5a353210beffd7145669f7fd9d87a5d0eb5754c5bba98eac3" },
                { "da", "b6dfe81f8c1d4534d637d4fc07a7806e7ea75f45cbfced4729ae6034099d5d8023c1eda888a72c4986edf553a32d2a36055c2b165e5b56ebab34ae6ae3971ae9" },
                { "de", "f3e0aceb7d3031565bec63819bf6312e950d6b4daa64ff28d4ac7816e183eff4a28d7a3408db886ee6412e54b46a4aa79b86e14c311d1ccfdadbc273f2e94e85" },
                { "dsb", "32c64c162e674180a5e6533a76ac5fc0129e139e41f19d9e935162b31de5db27a3f14c43de65cfbac14d93370b993ebe1a795be849bcd6b2e227627de4ab7d67" },
                { "el", "9e44a309ed87f5ae304f1c5dc09a3f1166471ffad3c485c296ff73fe318108f41c3fe4aede17212481c508dea1d3363d072c1ec6caf07187501c9a75b3afd81f" },
                { "en-CA", "a21bc738cc53e354056dc25a44ef5ea35501e4fd81ec960564ee64a61780ccb8de2d9ad92e688467e8e9c65c2bbf9af3be9dba7c576ac45a028a328301dac125" },
                { "en-GB", "53e6ae2d6c6385e643cdee26d0d38bc3573a17cfd3bbcfa6a2d19d46dccc865ec163d00feb39888caa309c18de5e1187bb2d66357de5aad2268d79274c155f9d" },
                { "en-US", "08196c667ba89df1cdf7bdd1ac1d6e5f5553b4f7b0e39ba53c9f3cd1f6b9d29b4d1d620a98970a24ce2a1b0cd4d7edfca30dcacbd861b74024eba6403411d48d" },
                { "eo", "dfd6e5275f3948913382b86a8c4f581ed56b20020f0891ee718c416f3b0fdd671e07f7b0e9b22c8672f25e23398f313f046f25246d4c0b89efefe6fe1ce50aab" },
                { "es-AR", "81cf0fe45512443f94ddf5aa765fd3280203d2f31b87c8f3436f6f4c955aefd361fe420ccf84053dd2bc736f8edf2e8f0d5a555cd31dcaae9995b40092043205" },
                { "es-CL", "f083916d12ae7c0ec3cfbddd21ef2549875ec65a27533c00e74344113fd85db5835e9d3e88083636c14f7db1c8b49fb1348f8429d3446904d6db08b7ceefd215" },
                { "es-ES", "b02ea1ecf6eafc3f3788515ae2c6f420bf95df866f437554b32a35b97bd5c0e00b39e5d15ee5d48d9ac1734498aea17f97dd1389123458418d3186aae326f06a" },
                { "es-MX", "5d6685c3a20b47ac272e670930944ce0c99f77d47f1efe6b2ad64d40b5010a2cfd1d0e3e63150c0a8ac44c5cdd491c43e89b1384f95ca9c7cc1f8d3fd2139987" },
                { "et", "4820eaa232d28b741c780d3565ae05d88876994f85e9252d5b09f7be78a80eee6d7f53fe9de7ec09079feb82073a41daced3bec484c0882d7badd98fb2009397" },
                { "eu", "d08cd05537cfe83b26abc17e8248249926beca593b8ee60bbcc9aa56f0c2bd40f3ed0c58365ea11224b21a81e22c9715d3d83d33d4cfe586018e95aad2bd19b2" },
                { "fa", "c77bc18df8e878e2f45870308521e0f37d4774a155ec318805c139708fc9bd26b1fda4824f15702c794226afe5803b469ba90866c79a72d46174363959658160" },
                { "ff", "a680c814a539c273d3b39fd7710968906977e40dcdd24738141b9444d5354c7cb8bcf480fe6fbe58621ddef5d429346a7ab73f332b6139dcb8fb634673fb1e46" },
                { "fi", "f815b330be888326d824502218ced3cd1ed3cc4285e4d0f0b9f44ad21ff0afbec3c1b3f5dc4db3c52777ca412353ecec3118f1c9adda2b52f51dc46be081ca5f" },
                { "fr", "f000b72c81c258c9574d53015e2b69866dd2b773b112173d3b810ca6329f16ee7fecf84bc08fbd1fd27a7ff1880db60c64c2f83a1a2a17c9c97c1a1ede58570f" },
                { "fur", "99321d0ea437e09a9f6658482759c99c3883699096297a8d7dd65cc3aa90f3ab18159085974965792d4decd9518b2eb3fc16c28fe484e6580fed9f3845d3ae76" },
                { "fy-NL", "c0daaa2aee45d96080bb5c868ead7ee9a46e143ae1a3c7e0318f3b88e91cd3d78b0731e436e927e06e9e1597095a4da732612b419a045af04eaed323d0f2ef89" },
                { "ga-IE", "6428679b916f294934bff5a2c958cf6aaa3fb940af40e83b60ec8ae33f51cbd22223b5c31b74f4e1e95d385cb20854911cb20412cadcb276e7d00a1a2c28364f" },
                { "gd", "b14facaaf970f6382a01c7f519ec83dc940c29b2e82af6dbcf926effaee6197c51d0a7667e69d9a3f49461e9c840b079d9d0f6ec6d6600ab968753865b34512f" },
                { "gl", "76b2bd787fb3b61e8c8d9cfcf27a21be5fb0b4286e614a4eafd939b6695708d6f954d9d87c93a0551103c5755cb43f8e69b47e77527097f43e185bb3174ac7a7" },
                { "gn", "a27fc3515c3da7123082c885c3dbd858c797aa233bcf30d4b08f8a816f69ed6462d0667518f541cd1d05f07eb293766bb0ac0c4b3596284275560b7f23de0a03" },
                { "gu-IN", "06539ba2874ea3acfda7921c11023734a54fc8e221752347298b553ab173be7e10516add3e9427a755e1f743513dfee77b323163a9074f78b25feecc335e9b13" },
                { "he", "5a0e9bbe8ef257a3d05d3b13f48b6a98509ab76bd12ed815a46536ecc3d744e67d894f5daf33f302e522105abccb271515616710eb1a4b0e14c8afa0ecf38927" },
                { "hi-IN", "89ecc7dc106340de1883b4b63266cbda5227681e1127f0f4437f5d314adb79a28c0b622232b590a058a6fe66a84871fbe162322ee1e19ccdadd45fccbbc7c519" },
                { "hr", "bb10921e720b7864de740960c2c46b07e633474b6f37b4e1d9e5e9baa558919b14bf88aed4cd5cd22b2734d8ada9dc9dc81b127064df4cc145fcda731aaab25e" },
                { "hsb", "f1cfe5dad324c158114b30c520dbb231ee7eb1c514f50a6de7effc191c83dee0099013b3c821929e6622ae4c23b1a3fa22f37c6cc95c81922dacbccd0dd29e86" },
                { "hu", "63e6f4edc878cf4e0789e7491433586950146a4688e91f44e413c9ac7141dea88d2de7ae9e0c2e50a5331d4ac6d48986f6752b3f11dbc33098596c5e069ff0f1" },
                { "hy-AM", "4311e556ce4d3f7a0fbf6b45b664ee2d380de45a3ab14b7dea1d6c8ffac898c55b80d59ff3d75d0cc154b05ac05e5d9a27f473dc868fb33f8781d2ad3544abf9" },
                { "ia", "87f598834cdf23eee036d2c03ad483eb5ad9ea22bcc3f23e9e380cc349e489e8f4d249b7dcca12b498aa4ddf19c0b369ac6450c76e8b6ba77a1ed16d2291eb7b" },
                { "id", "6e15e4260fcc25f22a9eceda2b384c1160abf5bfde24ba4e84dc0e657acd65d0e682e8c057502db0c25852da6feb5fc49bef101e888f64a535eae13c4df541c2" },
                { "is", "0faa6d6ad83b892fd2b007beb11d02fa4f39587453e0f7671455d14adba815e9d8ee6097708c17acbab9174c882fa6ed2d73d68c85332211d9bcda812f3842ba" },
                { "it", "21d907dc1c4c3b1b0c79ab7c4a615df5e83732ceff40c59fe9185abb4d83ba2837ea988842651e26f2178bf1984226d5dc23554e3603511c10870f962bd39bb1" },
                { "ja", "72d14aa47bde30f92a621d92b31605749f6bac206ce09437e03d3eec1f8eb1fc4f664b72a56a21c301a7e033f1900bbb40c12d26c4363d668ef34c5cb3e020e2" },
                { "ka", "90463aa5e7b07bc9e1bd392456539cf08bb999a2411783cfd1e0a008ba28f3f7621b19bd7917d496e91eb3293cfe97fde13809d800616d0381cc37cdd969b3c7" },
                { "kab", "ad8878c5e0d839b43f15813105c66c743082eb709acc0e02620bdb0b9d0edf039889987ee7b6fb402c1de4b60b3930e291c5712fea2f36bbe961dd3fffded818" },
                { "kk", "86637f496fa2417f865fa14cd608c18ddc2e233841ef6fecf23ad081ab807b7bf5944d4aeea9ae34df0615da82eaafa170c46cd925708ff5b680af8167fd402c" },
                { "km", "598ff7ea2e939fef776878f09e3fe9b2d321e2771128ecdea07554cfb08a87ec756e58a0f5650666b158b5de241ce26cb68c26d6185fd4989dcbff39a7a6b94c" },
                { "kn", "5f753595aec921f117d3cbc83f376f79da80d55698c36df7877bdcc22f9c6639430e2bd840e392d7f96ea42803f438fcce3fa64ed6adceeae3ceda23bd4139ba" },
                { "ko", "515de06d4c7bf55ec81c3ca83aa41accb540f4e0be611bd15f4fd6265fdb9235c561b5f6220c92fac0d8c9664d6ab669baa4a8a0b758d86c4d2ad12c7138f0d6" },
                { "lij", "f3baaf5815e802c8dabfee42fa8eb7089fe85e5e0e63a5915bddf808d884c6d8c5e2495ee78381df44f89ef2ded20c8d0098c4a1e54c78cf9a7baf685507c1fb" },
                { "lt", "f6da628b3a4ef12bc0598428ca13b5f1e1d47351c23708e931b8e07f6844a94d4a183a493e7405bb5d4c367760db12995435de3791e95bd0a5e79779e3039053" },
                { "lv", "aca220c08010a0141f7b18f64407f15a90c3523ef2cc25eae1e6feb1353cad5266effcddfdef41a72e891bbe7e417120c083a25c53fd1f9bc0b69cd646ed2b58" },
                { "mk", "3348bbd39c0c0c2e7cf2e8162d90a10c522520db9a30b6ab9283486ac0a9f1d1105f5b75bbb90f349b74dadcb6e136efbfa629022daa4ef2664bbe9e963dd457" },
                { "mr", "97866867c162c04423c95fef559ff3ca1cde0416908b9acc1cdda74aa5c0a46c6cbbb439b213c115107b411d2c1410cdc69d6f38d925339d3978956b4b3fabe7" },
                { "ms", "07042781b15de42d2dae22a98cd4625119eb35d0333206e50923d2dcb33df9a266c4de78515c754507bac152fa475c5b3b9915b00ba02ef2e83775f3fb6f05ac" },
                { "my", "68b7a8bd9277ab74c1bc92b234bb195aabb1917bb1f667c9eb86a85a17594d763ff1be40d70a4bd4671f7464e87da97ffe5a04b971ef007b9c705a34ae023764" },
                { "nb-NO", "81ef88f85be213aa6d2bba8aad2aec370ef75ea6a66c68358b506feea786b568a6b16d2a08a0551b4f097a1c0ccb6cfc1c11595debe73cdbfcfadb21aabe3eb2" },
                { "ne-NP", "de3f18b464b0c749c55b7e648f7604f8f0768bd95df6b05a7302435339b5b578b35a25e41b8639c57d3f23ee624f3193b936983fc962d60f38ca66405b94214f" },
                { "nl", "be13fd122b1929a4e5c57f4f0ee8cd1098345d51f5a265d2b2075ce844843f97b5543989337fd8efd6b3985398dad25cf40803b9a2e9fa929ffff79ee9755e80" },
                { "nn-NO", "a77a34a2472c56ab472a547de1d80bab415997e12fb31ff674fb4c6c5fc283b72175f8bc22b4331d5ff697d56dcf761099443ac3a79d905e3351b4882a1e53cd" },
                { "oc", "9b219b2a0d385f836cade5f06c300836ea9684da451ef54a950f388740d37f37470f708ea0afe2542030981a1e5769d4742e379aa6c1e8fdf63e1b8c6022321c" },
                { "pa-IN", "f9657e6d51ea4398297460a14aafa012a428150edd460b03cdfe857c38a1108f1a87fd045682765047b9f091da311b0a23de9ae08722c1c510e044097d7d9521" },
                { "pl", "61b1f419e142565d78f39105dca006a8ec594cf713182ba88e6a351ed5b29a933873461268fb77ab1224435dd86bd5e53692790e20bc55b4932733efb9095743" },
                { "pt-BR", "21381a25fd6bd62621f34d84b2649baf8db3211c0b3e322cc86971da7a76a4763b24ed79765461978b8645dc28ed8c9ebf096147e9202781886893d8f0331773" },
                { "pt-PT", "8a70b582ea603ec44d507b1c591c3c958b60eecb2f1cd7d96684e4999cf44c3306ab146707a53ec6be85b27c52d989cec21a0e8d901ab8e6d7973170a2d5c59c" },
                { "rm", "19ed477b8f8a32bdb16e161005a361ceab9729a96efdb8a7a2a4a6adece362ca0eb643e609485951d6d2ff414c1d1bddf361d406054b9b9c875e79a2ff820fe6" },
                { "ro", "9cc5c04940832e52c0e0257c1ce916719a7cf79f3025cee9e0c116aeed7ce68e34d0abb21d086e64fb08c11abe50aa4d2b4b6a759c88047541061469792b32d7" },
                { "ru", "709aa5015a79252601f5f5f49ee7e41faa99bb1f49e3facbb3ce999ecbaa0bee8ab3355362d01d845f99467159d83ffd11e4190727c1c065b4d61c1a9548b604" },
                { "sat", "517f08cdfa71d86b270a6b43ebc57f1ee63d56538da45c00cc6912efededb378159f4c208fd381a73f613e3430dcce1a984168fab5f7318f65c2d913c416d3d0" },
                { "sc", "86883dbab77f6a2af71384b6264f6d373ba0d9e152476f4a696880ff76c49a7487d0c74d947065c3f0f49a3e4955d7921cb494c29c99840f5856c6c1dff06920" },
                { "sco", "13268e3a472676f5af27bcbf09039c04a4de8da9f22fd1c3bd4054f4fa867b5687583ae0be5278ce8df481d561732a6e11f2997a236e163c0831c457eed463c1" },
                { "si", "c3a47a03d5dcc8c3a8f4ba2900842718875b3a7e2df9e7fe9d45b86d3f3ad3c034dfef83f07082908f89a75cf915b781e16689a35e2b1227c344e0c8ecd96d7c" },
                { "sk", "6ca5e14f2faf8e86092b5828e438cafe9b40a504f0d775856db96721bfed139a944b2b6b7128fa9e36738f299f7f4f91403a3ad96c42ff729546db131791ff6c" },
                { "skr", "1b74804a3fa96e15b19598b56d02815c258799d0e9125261525672846610e559736abf868512cd0097603f85fb7e3a6f4d60d52c6d858968cf20b5870f0c5d44" },
                { "sl", "cd2a1a2d7485177661a1ea29ca248cbcd4ebfddf516d1248f348be936e72f9242414c0e7d13003c480ccb40e0fe47d509358ac3b190eba6d8453c0ff4f120b0b" },
                { "son", "7091224ad3a990e6f5231afe25028f7359c46455f8a8a7c85d32b83b95dc790c37935f99878e0a1b48e62e54fb1866859c686afefc43e9a0fbc5b5a9d748cac1" },
                { "sq", "d5e4fec7bff2708c17cad04091c7763694420cb9d525276fd87de90ed9bb41a9d7c0df4aa4c86ae85ff5b3d68335ada66d24379a0c029f92c45b0d774c44aaeb" },
                { "sr", "e2c786a7ca1ca8b8b64a228b9ea27332ad2a09379d048e99eab5b10d1450c137fdb2cf8a6c3cdc7bb4215bfa3270f7587409f82f8b995a5cdc167e6bd6cb9687" },
                { "sv-SE", "bd0a2dba849b8a07466a56ce32787635b4db6ce15e43bca4ce811771c6049dadb2fad2c78c79d75e2cca102f7745ce9d58fe485a1cc014c5d6841b14396575ee" },
                { "szl", "baf0ee28b8541d6249277a80bf50c640557f3e8b9660641634b354c82605a17bce0497b147a6b8c2a641214a765cc49614bef6ea14df6557baf4774412efe9b6" },
                { "ta", "e0d5963c27023287d25f48fc96e5cfcd11c3c162a223857fccd9c1f23c051ab2db324092ace4c439a476b40b64b52b74d8cd28bd32dcecd78c32e0afe51884e0" },
                { "te", "fce00c5cab1b4d3c4eca12203a67674e7a7dfb9ada05b1f70b13d1075a24054fe9fab6f0c00e0bb4b37c5a35b00aecea684b6fb7ba26cd96874245547f96bd1a" },
                { "tg", "7e46cd91af3fbbcc14ffeff39e287bfaabf5e5449964b2beb8910347f2850324f4b2851ea4baa923734e4ac7287d1544ea2c6f896c3c531813c92b3641de6686" },
                { "th", "0d2a7a37e56023fe1bb1c24bf2442f1e39fef27f3ed1f0081840b9b0a811e0ea39e4b83b44bffc0bafb4a92e553c4ea85260a1d1c2c569a1cdaad18672c5951b" },
                { "tl", "1d26e38bd54f009517d2ade5fcde1cf86cfda7bfe9c5c86d3786e1e123f07589f7119916677537c25a017f6514754962e20457b04c464224befdf6cafd3c1aac" },
                { "tr", "04ad97f95dcf630ed4c413235dc49007bcb85fdcebda2c45b9f762937115121a535dc26fe4eb66cf970811a59e94daccd4f9eec88669920a315f01f4d432ba17" },
                { "trs", "24dc261f6f342c566c64f8e8ce314b98f9ab0281c0b930ed279b8e4bb96b1257258c7b4c52a39bf7ef5d1e3905c6688e4c0ba827874615d464a2d6ea1eb34960" },
                { "uk", "a189879f8c83644c0963ab926718eb8748ad48ff45023515a945cfdfc0c83e823a927a53bb4a200e463fd2ecb7f30be793aeb9df81f1e4aa0a1bfb0c686429e1" },
                { "ur", "485833d80319534b92e07bafa9ca4b91f1bbbd17f0e710eaea959fdef2cd3daa9ef7e815aa447cd7e3ce7623c4b7f5ec8e399fd8671a09ad1d47d9765b613e75" },
                { "uz", "ba0cf7f49ef01c2651c31615120f7666f4bb94389bfae0eee79eccec4e26759f3f549ecbe479fb5be61778c47deb1ceb53f7065964c7b3ca9bb738b3624e7813" },
                { "vi", "881606ad7984e31bb08e1c52e2d2df15f54eebd25834a8d5bb454fd3e698a6f0ee42f45d0390457a8f33dda7a127c879cfd3a28a522aeb23dafd044a464559bc" },
                { "xh", "3302b9d47220f0155a1f072ce2d7f3ddc064bd3304ff04d960e55ba7ff2b3e265ec2966e2f6627e2eaa7bb22729d6ed4a6a0ec9a6cb5e11a216b25b9fe1e677b" },
                { "zh-CN", "d90f1509b4fb361e081cae5c2194fae137b2b99f19c7e837f213dc3bfd8598e09a0802e303ca9eb008e7e83a836a566e8931a63253705c98be44d1f32ebbde69" },
                { "zh-TW", "42fbad0e50d380e60664df1208fe3239736ff9d72285b9ac2c6f642bd663edfd92a72ddc523b5a769b1493f292c65ba4efed89812cab20df36cb534f88ff767b" }
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
