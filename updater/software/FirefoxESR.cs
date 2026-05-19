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
        private const string knownVersion = "140.11.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d5c28a7a886f39cc723fa5eff88a2e9c19ffb4899c1ac2ed00f0f6a692f9576110ff7c314e7441871962a78dd1d4722c06a1284d445ff19ccbffd0bd3c025672" },
                { "af", "fba825881e8d5c63f9289a69133fb82bd196f1ec8f949a80cc51a9a5705048e62b316ee29d2381f1dc12e640df52acbfc248934b7ad8e5392c2d959c8be44985" },
                { "an", "85a45dbc3b25dca9dc0d063069d22de62bf4f73e2c3fe8ba0cd5ee74f1b79bdb1f0c1f4257c2d1de785da03748b5c8b2b7315be0140c2dcce84cc6cd0d37c795" },
                { "ar", "8783fc0b2b081c6982ae258db76c7a216807ecf3ce77c12b36786af961817d536099b5cf29fb3653d8b616f19056581b3b184a7c4f63161c4fe1cd4d4e058c84" },
                { "ast", "3921b560d2eb2b62220544faead5dd9ba7d156827b701a52155fa94ecf11c199a00b143f6595c00f7daee57d5645a9c14b3071b468cfa3e2620306a1222c9bb0" },
                { "az", "be410db50e9b6e605a5478b84495fdbe2a6eccdeabfcffa7af171d7c9760966e10846abda5455cafd7497f4f26e3ce7a9f61fd7d850c84dff0182e3604fe9e93" },
                { "be", "8aa10ee3f04977d941739a7d19e0d2c86501e7545bf052de732c58e53a63783ce79adade005cd864397fa4146ac3a41dfb9c42826002ab4543b180649bd9b756" },
                { "bg", "9209e0c67f77aae6e0d3a030cb09c36b4f3f21c0beba5ffc8818fc89a3d0bb132922c275f71582231b60baf7e61669d0d54fd33d8f4c6b7e1475f4cad407e721" },
                { "bn", "3386b3a5a010b12c3cf7a730f8e90b3d0a48c37881fc44bebf4c745e5ceb2b57daedfe08d88cb5b785ed9a663598834ffa2a528f0882ebb58d491b958850ead2" },
                { "br", "8a4bbd7969a8651006460e2309ae909c4a883d7a1c2d87c062fc3dc852a6294caf5f48a9e82526e5926dc2688b47682cefd5b128518ef82c8f3c72a6753fa32c" },
                { "bs", "d163d84476c3edb3139ca970fd631cc937fff17d8cd549e5400ac5dd0c5040641aa66e9dc7b44b67f8a28a01b05ef8b8bea0f09ca621a03972d45d871b425220" },
                { "ca", "df59cf04de7fda32251b66783469226db62966caf45a54cc730f406805d7d762708bbc55ee894b57095446d2a39c64e038ab50a880bfebe38ca4c1ffb0ab31d9" },
                { "cak", "8072767cfce65e5ab60e41bb17eabbcf1a2e190b4f67dae05fdfa860b34d4f240c3cc54dd4aaea90d8008f62899dc7abdc82d3c85b585e7645999ea2a5fb0449" },
                { "cs", "48066d14f89e5a3018c3a7d6a1b09e9cb81b805a27971387551c91fb7f4a7832c1c180583f3432c3865ec6b81971d39ae26da95240fb16e0163a9719510391b2" },
                { "cy", "f059bd6002cdbb8280e321f88b7c128b9d23a4e8c450ef37a981aa90ad484b48824d23006cea43d4548e24ad551122bda8d33b0102136fbff9936b10c8d81a76" },
                { "da", "39757efd74c7a2c40e76e4ba0a8b9c69afcff425a33d19a032de3f0a47bb5efd9ad8c0088c20bfbbe035bbfad3e2c87a3f5577b2b65d59838aa19eb88e56ea0e" },
                { "de", "ab0ec080096c0dc7a530fc382095daa13c362ba57ca41f32db727acbae939a7e4c2ef5f066ade21ba4b75efb707b8a8b348ba2d558929d9dda6f6e10adf0615c" },
                { "dsb", "2bf28cbbcc23b9eafcc826d3ace6acc3d1573ef1500f77156178128c5b1c87a16cf1ec79d96d0b55d14115b86509b8bc218f698137297e81244cfaf48277c4be" },
                { "el", "f76d2c27480a4073efded9ede3a8ef11c41998155ac0cff1e33ddd2c537540bd56e2b03de785401b1fcdde25c78e743eb84f023fce296659f52c68a6b0018a33" },
                { "en-CA", "fddfb718d6f160e0f06250562259ea59e7142c80e2116633c0273257d2051ba7fd40869d74d53b59e4b538f747d42608dd8c1d44db56333be624d84d2181ec7f" },
                { "en-GB", "7214340ce5887edbd45ed9ccf3a36cd8c7bb752d3ccf6f58494a28e36c98c0bfea94b14b866dbef3eced3d833c5cf00671dfdc0603fa8d0afcbc9e11d55bad5b" },
                { "en-US", "fb0dcb5a3c77704830921df6594e63b112c48892110adba128f1eee3e9a11665e7bf88554b2080ee1fc1b44abf5de9d04f65843a68a49ac856e667ccc1def05a" },
                { "eo", "b2cab3a95cd01f0c2d8be66ebd384f7ae8e102113b59111a71f8a48f294219b6db56e2749009e203a02e58db316f1550262aa449c896ab523722dfd91d38482c" },
                { "es-AR", "f1ab5fdd2a5e7375e68ef11941bc32348cfd47a09381b4d8c5dacbc2855cbbe5498cb4f8adc4dceb77a29ad0866bf85f9f39767772d5b552cc2071878e496ec1" },
                { "es-CL", "7dd95a8303cc198ec4009b6811ca9e709882b046d7a04ee71da336993f65c47f4e3e2138573b19f30f3c89cc046ea9e3201184061de1e7b0b214915d05190d5b" },
                { "es-ES", "dd05fd185b3eb86488afe48072765a7a6a31575b59e4569bfdf8e292e026c77c2eceeab3017f5c06408cab5171d870f868f1671f1feb82dcfcd5080f89900221" },
                { "es-MX", "5329eb5f4597d99784e6b25574b53b3ca38a8a167c694643d4c7d0774c814c15234c233efc2fa28030f5fb35747624377f5bf5ffa1519875b30e1b68899cc04a" },
                { "et", "9150514f45e0b1e7a4b3229888a75f7c35aed325c27d4875e60cf3d155e4376feb0d3bc36931a5b2b74b927dc4190758de57301b724b9488686d2424af70009c" },
                { "eu", "d957970fca611ac226cd7f808ead6c919dc4aa72cd390e7cc49b9f11a666de673b2ff51bfbcef950d9afb4a1103f1bfdb6adb73f32b4456ff37388708a4645f4" },
                { "fa", "ef6f93e4076123883ac80ed2973d2afe36173bfda2287ce59071609673ac0c194de4d44653dc7312f3d446982dca4249f301892f4a3e33476293254a3a62da03" },
                { "ff", "5c5b8f56c3bfa4411fae902c73277628c32bf72e91e4e0868ce138276c18729559699fa127399afd2e18562e0689766da7e040e5ea40e09b1a44b0ed63511f36" },
                { "fi", "c38319909ae79cbdfe4134e049b098c04739170d2ac02a61d8f4fb099a9123dbbb38fa2a375064f0a979a1cf1d296d876c9dad4cf7538cf5ab9e53863cb03eb4" },
                { "fr", "1f596e7084d8766eb9501fbe3c4d883f67093c7fcb51dd7896f9a6fe74750ebc1311953ea530331ca23bb851b164240b6bcc53298709fa9fb9ced8df658fddd4" },
                { "fur", "3b1242de9b50ea4e9dc6381fa1d55e65ae44d454236acdb1ace56c9f76c22b9a5cb0c58c775391b8575e4087bcb5fd655d8610c0f77ad46bc2fada78c266a8f0" },
                { "fy-NL", "378ec33fe79fbef9145412fd2499b28af5e95eed7e712bcb9c5e27df4cf58a1c097021a964b34f6d598677c2c8fe3a99771f78d1942187bd3d3f6c2dcc210d0f" },
                { "ga-IE", "be883153c267a0bb4a584065673251ca232bc16c19a293e49593f9398d47910b4de8a6e42fe509eed7d41e7588f1d01a7cd9f2644d079d6b2ac2e6be56c834ad" },
                { "gd", "ca1e35fe73d08a836895cb1e2b8c1466e9a7429a0ca65d59575a58baf1f48c31e07fa62bd7a311869fc3b76ad316f2283b98295e20392dab73c0a695751516b7" },
                { "gl", "2c5713cfdf16e6a7fce5d1244d1ed1496318707df17cefd26c8285ddaee9d8bd95eda0ba35d8c73255a9dc7275c9636f53a62a2279ee8cb1cb86704b18284420" },
                { "gn", "4fa3c2ea002a76c3833de652497281be6808eaffcc89e165666d11756349ecd6a3de7a2a7530d7150dfa2781c12249f08fa3e989f3146acbb3f02bcf7faa9468" },
                { "gu-IN", "a8e19f7a2b0e942d0c1c7f4ee6e1002db32daac1e02e8ae8dca258279e253b33d669951832fd727a3c7a305a150524a611022f526c47bdbf7da33d2b67f6271f" },
                { "he", "0e5ce65aadb3ba5fbc533d75bad4836c37eba137b01f8cd2d0bdd464061a3ad6f946e169340cc804d68a145a065369fe221a91d1af226b60afa7d4c63eb4f840" },
                { "hi-IN", "8beb03165032fcd30ae51045459f644a8ee84c14e8d63bc9e1f6ef9872c6f7ae61987989d11a05259be796136a967a531516d7e66ec8531c4b81ebe8307e31b1" },
                { "hr", "9d9d627ea1330e8570e292c87d51490bf8705032d2c54034463d99acc679aaca1515909049a199d3d03591a723bfe22032bb0e44ea10b41d1c6db3ad44b8bae8" },
                { "hsb", "b56a406fb15a23924a0e081dcac6768ed8e236b4eff18150f62a7924d3c03109e667b30c3967876bd752231a3fd5e3c3d3f88ba682f96fd0105be7974532134a" },
                { "hu", "701a1d35d4d797cecf71a8a3d039c5d8198ae7a757ee4ebe3dc24672b8b011341b3d161e1e8f95bc1068bab59d3100a3ba1ff00459dff63729023333bb18eee6" },
                { "hy-AM", "3a48d2655581d9bd4c09ed4c7d13b2de4d0094203a2a6310aa35556770bb5053879d4e6b3bec8480bc65833a3a2c60a5f301a5d65c048a9349f6e47c9a33d5c7" },
                { "ia", "ba032f31a69c63c4b6298cea38ebfe947ab15889b6a780aae9b31be345c452af2e23881a693ea90de49fab65575709755fb79cc2c01f72f34344980da794074f" },
                { "id", "70bb1b1a4f9e007c0d0bff02c7db4f7e463572b89b886c3936f1a056f6bd2a0e216810db73727c91d14457078cbc0ecdd160847fb3014faf0946d76597c0f0e6" },
                { "is", "3f328615073eb1ee7dbcb26a5bd6485b78e70f6a249681910ac197ffcd20dc39946410f9b5e618c438c62f4e8d187578a4fcca54871bbdf3ec6bb2e5bada0419" },
                { "it", "50a1f1d1880b1221a25b5834cca00b602631c93ade1edd74cb633cb3db70357ac3966276eb0aec1d33b8154dcc8e514e36360ca8ef81fe09697e344b26681b79" },
                { "ja", "28e4af58a516eb364e671334f3e0297fc039e445614db7cc2f210f437fe5615a14d87624c75b3f38b412cca2e48ef8c6e2219879f658d54a5fbb048caa6ea2a3" },
                { "ka", "2ac3ea9ec6b6fb808355f74515b566dbefe88f5fa631f53d51ba62e5a1f6df33f442854f3066f28d04e1b059d469492c2f7711e40e4c99872d6a9b5623feacb2" },
                { "kab", "22f1a36bb069b60e7dfac885c19af342fd3681a2ce1883131a9f29ff5d0c15f21840f1996900f8183a5b2afdb7a7110301d96b7eea398a023fabb9e1ac304909" },
                { "kk", "8ee92b8a5ef4d6424ac9b30ce4db117f96ebf887d169927f192d139cb207215e2d3193be492d0c6d02262c73467c341e85842f92f8df7c44f4397f7671f21811" },
                { "km", "389dd9f1e0d139b103e79a8bf7146bede742eb0771eb497baeecfacb87fd90e8387a739850d9aa4587882cce81b9d084b3502650fde8250297d53b2f0d7e9c32" },
                { "kn", "999f402eec8d9c7f3364c21fabb6a08151fb9c55e6d1fac05bbbc2beb8c41e0020171e1c344958b7d1efb56f36a60de1ce760176159fbbfbd4bb426dc5da19c1" },
                { "ko", "e2e46ebd6c497292246a997ea99bdf4c1fadc7e60f173e7c63825c06f4d70fe3b5d9081821a4adac05576aae8d912face0ecaa79765d9aeea5e1ea5d4867fd9f" },
                { "lij", "e2fa7c872d463dc919a2db7af8d3fa44407e7b7f3a65d8c3d334457f3d69f8f4bbbbf7b3b5a8edbdeb6a95e687a97cb37ad68e97e21261da2da69702a52179d5" },
                { "lt", "49097934269c4feba61ac8522207c5c598fe11c85940c21742c1780b1f71bbc957146d307bc7bb40182e7c61347fcddf387069ea424e72745b309b1f263edb48" },
                { "lv", "b5f0be0217ea2d1da6e0bc397441e1b611fcf796cf7197603f6590de0861de7e34ccc68d865daf0c6485610a04571a9a366251e9a546a28a31ec5ccff1707049" },
                { "mk", "94bebce9c1d28dbb8b4ef31e36d988fc01d2b6204541cdb70d3364d5ef87c6e0d7fd16652aeb2852dc831070107a564a5225eeb03fa6c0c03cf6f272084553e1" },
                { "mr", "c943d61d5902f3984a0c03687cb0d7982bc10f482253fb7f8c47d84497e18e3d24300b153ae8c67b0d4c8fc4e2f1b0e23370bc72a6612c0f06c8ee5cb79bfca2" },
                { "ms", "b9f8322e6519a74b8b61b5b14388c84b89cd756d41255f01a909b5dd4aa0927e4ba92b743b49ef66d0a1e14e7d45a00897766a7d9de95070bc6b81936c61ba7d" },
                { "my", "2e1836be56ade7599d2c846a3e9c08b02d198caaa323f922a3c44c1fd0a93dcd70c0506661c56c9c4829eb1fbf5dc567a2b23b1087e9490cc99667e2a2e19087" },
                { "nb-NO", "e84beb07ae3fe259fa722b33b826816150dd6a05bfc5a4041f27062093c05f91fe9f0c95660266e74444e7c5a4fae0877a4b6023c616314487df313faeffaee8" },
                { "ne-NP", "f044ce7915094a1a79e6b24229086be3125e533e00e543b0bf96d08da7ac687c84c5e78ae3ea624f00d4605e3634eece26f634ed4a028d755162c2ba17f9b94a" },
                { "nl", "bb276c40a6cd0bc8c4039cbf7b566cf5ab4a4d8a6dc328482e37f9ac959504d920acaf4cae57a68eebf81c1804dff5a8f41d8b28acd2c8fa12b9b1bbcadd5f03" },
                { "nn-NO", "1d8f169586f4e53aa3b7e7874b63f43236264ca92f241c2eb3bdb66e9910f195e732fe567e32bd2e5ecaea9af2e1af087a471edcf3c6287e385429f16ba90738" },
                { "oc", "43be79d48c219eb87505c0c46ca3d11dca472e6b2eebc8978095529114ad2f962f7c19a3c6ca9035f7954a61d13cfd4d350e7fb37b51ff899bf8a01d36948369" },
                { "pa-IN", "06280468ed22296613f8336d5eb14076398a35335e4f28e6855279a2630ad702c4334ab8ee4f0436ff14ac7637477c34466cf5527854a661dacb4b1ab6e38c82" },
                { "pl", "47e11260ca2e77ac4a4b33752b0a805b1b9e17a318debf89206986681b1f20626db0c5b8fbaebcc7262826229315d9b20f4bddc334f29df7954e41e087e65287" },
                { "pt-BR", "2029dfea9f165da495d24138551891c6af8ff112c1cba14afff7665337f8567fba40dd9b9bfd7ccb76389ffc4c8de32e14e205083ed0683698bb0d2c5bbfa34a" },
                { "pt-PT", "0f4cd2aff90bb307fee709050ebe879506d191280d7d52156df5e77d1a1bba26ce38854e44e4f9ac18c54ece5c0ee9408a5dcbeb35e94c2b3ce27265136dc421" },
                { "rm", "3c6eb0381d0fc8c9e700398455c706b3687c281b554cbafa144320691fb50bd7611f875694c23aa34d9df26b8af728b1d78d6873a460066abfdab12c9ee8f16e" },
                { "ro", "e22b3132d8da963c579a59292e62b1f573e23d78ab449724afba207cfe7dd114a010cef0f58f7f1db1cd15c23bae33e2590791408446ee1c5e7dfb5a0992c3d8" },
                { "ru", "5854c142a9af677c5899d4e553f8d6e9679b235d1a3968b6b65a8e27000d3fa5cd6fd6ae591db69ff1da912b9c3649c7fa04f4c0327c6c6743048a52dfc0153c" },
                { "sat", "858a9d3c3a5062050d0ef387d14d25941fefd5e370d91a2f3a1b628ddfe5a293ae878f456ad6e19191118f9075d57a0adc2b0b643f3b209f66cfddcf2725b2e7" },
                { "sc", "042bd773cd1507c27a8a7f2bdd9c1403c0cdbc80cd23fc20bbc4c58d2d8e9129133f88f9cb45d8da4a1b3257e0bf321385cdd0bdda860136fe53baa608402b4a" },
                { "sco", "bd6bd5be016291e30ad34c2a3ce5394a53036e11a090b9033114ba5010f5c8c8776ca15e98a9c6ffa5c1c1cdb63804c17512f16f6c1efd76ddc3a207195e8a65" },
                { "si", "983b8d26130d12389ef2cfd930840ee334084a341d2f07fe17c1057a41858965d90f8059a247fdb02166243faedaf98c31984d83a6aa7824602ee15b028e1fed" },
                { "sk", "36e8c900550cc8723ef7cb14a885d882153e84839e992b4818dde92ffe98a3c06a067ae2923d899584ebff09b6e15480d614c097260ba9001fcd1af1c73c6763" },
                { "skr", "860a35acd7ffd52b67a48a0f2fb2799aba580f70d2e68079524b9478bbdb8a1d66c161895bf4b49ce96bb43d33e4f85cd4f46de2b42c4291f81fc28548a2e7a0" },
                { "sl", "9bb9f372003200710aa7e548b9b6e02d5fbcbd2163397448f052e1e18740730d2b76b3d6adbf1b745d115cf212fb4a372b04efbef9125e3fc8182f59d23c3405" },
                { "son", "120ebfcae1bdc6182eab24e192f084e063f5f0d4404da47a387b41dccf5bf3bd1307d3e198d59ddbab479254353fdb24d8b27fb7245cf1902c996d063a219867" },
                { "sq", "24ddc49471dddd84c132275ca597012560e641f2772f23c8eea87251f14f78cd08d5c8a1d793ca9365a006ab22002dee88d4c8dcdbc9d2f485831175808040dc" },
                { "sr", "3bfe74f1f90e72ccbaf65b2892577a2c9dfa9131b3df197b23fa15b1790d5dda7d0b0e47aaa83cfc50bf28550b48a86231260496a1abee5423fc2c3f17283c3a" },
                { "sv-SE", "3112f8022dcf130cf99dff74ed855aa81540654eb24ed92815592e1b5e702c728e4b616799874ae8994ee3c08ded2ea28cb5bc81d429f9c2413de347348db292" },
                { "szl", "5e34f4795c7aac450b052ddad2679984513df103c24c8a876776acfc66b33af47f86d58340afc8890a0744490adf37f10cc82f6f4e22b361aef4a9ec9505f41f" },
                { "ta", "6615bb0aea23330977b635ac46b4a3bade0b19855d9d6ad79ff40c84c46af23bbeaea1f3876be39697c31f9f0e8dbbc4c331f96b4a21c2b34d043fbf0a044e6e" },
                { "te", "f7088780819ae3f06592b9b63d9431c9f6240676575aba8b43069cf65452fbdcfdba303553f2d9debd16edd0713315ff8e70872dccab35749db2b46dd1545d3e" },
                { "tg", "6a2108bac46e05c3ceafb36e30d4e77c5c299baac78a7c3f47602f57db4423bc460c3ee61b6eb05d18d6ee4928798b3380b13f42799973308d3b3eb93014ee54" },
                { "th", "90c4c4b0bd89d596df7ad4a38499c8f6269991130367870445d872a17772d4b8d37a1f0845b155e30c97be38fae79ae1ead7ec422926a244a96bd88a9373bec4" },
                { "tl", "eafbe5df1cbaf2fd82c6f944df99539593e30d3a640e7894efd374a21e18f2379c6a867a72cf22a197bd56e2fb6b6002655722f28e6ba71e7748780247c9a090" },
                { "tr", "b3f446b6f17e537548f5bbd8c2c83cdbdc9086029beadd1980cbb562ba471c0875e77224382c22a861c7dc6726464a42939e5055aec173165d710edfa56a4ee5" },
                { "trs", "1f94ccbaccb53cf43ea65016ae347280559ce76629df166f43e73f41e40ae627d8fc6e670e3798aa344e429a7f0ed8efd377709375a13040576a7a592d256947" },
                { "uk", "6902d03bc92d7c936054c0438e9d43cb57d845dd856bf2860eb03888a56db46c1f4c058466bd6aee7a23bbb10c855ae8d5f9c338b80ccc05dbe2c01147f40208" },
                { "ur", "382d95529bad8c9fdedfbcaf25774d70e3c91cf6ab82c58f90b2015b2b0e32b5cd58ecb84b0c96d6fdd864ccce2b3dc65cffddedb3e151184eb2c4edb61b5ad0" },
                { "uz", "aa5e839992376dbd236d34326c2ce8479696e5ecc5c39329721454823a0643d162d2236096c3c52e085425cb9a88d3b48c12f7eda418247fa5f8292ed01750c9" },
                { "vi", "594665a6a1a666bb17f8c9d25389c04fc16e9bc73fc80597d6071874bcaee9b8a0e54df47acf7e27943e3d67b32b807489a0f953d286e9a8d152e3415e8bbb96" },
                { "xh", "26f8a1f2a4ef8690e1df97b59aad5d561abdbe7d8d63fcc9560335bb1ebfa1ad120d3d7661322be3b734d11242ae3aa22c9089c3aeee80450ba96b0f87104324" },
                { "zh-CN", "c7ce5ed7a9f2ecf842bf8b5a3dea1cb878b800251344e1121d7c2d5dc083472884b0b15fb2a8a4e4d092d2b179656bc51320f7f23cca5d9697a30da7c5085566" },
                { "zh-TW", "a4cecc45d42eccc78a81895965d4f8c76870d998a52d7ddbdaba7d197c307094c5c891737babd158f88b5992dc5b96e3ca65cae406196aefa1ae4cedb6fab135" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6f85e881d9c4f79ba9d7e6d674c2bf732f8e1065006b1d0aff961b070fb98204cb8ee97729f0542c2b7c2c00c96c4333257bf8a31d60d00df8dbd610950b6e1d" },
                { "af", "2c183c63eee06add08344f38e51d6661b8aca7f52a780bc34bead1df081fde4ade9c7ab16b7d8ba1a8d7c9f46193a4a33beed44dc4c479a0bc7c2871b796d4ea" },
                { "an", "67ddcdaa6828c64671daeda4c6af3589d6e48c9b57f1804a9c850e74aee916b9b66d2bcda22179e56bcf586eee1e76c92e5be6f3446fb0e2dd7a1eff999ceedc" },
                { "ar", "4cfde1d9c8b12f1f4a8c5fc2cd3db3808f179afb4a31bff7eb0c79dfc7b109d5f815341f5ac17ef7ea91ba441ce8237c74ccefb3eab7a4dc48187415d9ba14a5" },
                { "ast", "36a458ed568e5e9f2cb0afa1f0a5b329a3bdc3839d382918cbd0355f7b6179b6cf9c86feb082e942b6a60b5c0a5de2e73824fdb01584ae5a273fde210d39900c" },
                { "az", "bc8e2b911d17a3c256d52674cb8a8aeb367dddbf190f6e66820c3457b0432a81f29c8d28557114b1b2c725e386d1fa5be57a194d20f9c20ab5e13bcd947af2b5" },
                { "be", "17baa9e3ce6e0d4451ec6019a11966a5bffa5e9455374b2160b29bdfa6a1f2c1fd58a2dfc5780642618702dde4eb5a1329276734070bcbdf49b13e22152ed2ea" },
                { "bg", "0058e87fb662a031f7afe21326fc873d195056278abab220bd56bd71aeccf20c0f0d8a07616b9e4ee52c5e2d93a421e9f961acdbf45bc380d17bc0ceb6a4e9aa" },
                { "bn", "2537fc6581f1e20a55297954e5dc735150f3fa985e6ce6723fc291c1bd707fc81e72ef9171619a46133f1b482d224027fcafbef00dc1056961eadaf7ad220a3a" },
                { "br", "e4a0841b5c2640fbbc24b344a89159e173387dcb3457fc29456d23c1223c9b4ac3a7feec4eaa22df7fef1424cda38b1a86e9202f8442e2292a02f8b1c767e4e7" },
                { "bs", "f8f9792f713161bae5f1b3adc65bed705709506c908d90789832e59958cacdf5c6718b267001ead529ed9d410c805f22c65283fa347faa7199c5a852f5ec56e3" },
                { "ca", "469657771f3fa34ae1b7bce3ed6b41a15c47c1c28ce9602ae508c2988e0c999ea6b7b5b268cd95db5f5efded9194b8f5a8f86ec09e8fdea940ebb909a2948058" },
                { "cak", "bdbe7c08435fdc39cf0108fd4c7bdde7b77f84e2c4d704cbdeb4ee32dc45a132076a0193e3cbf55d4c2b39f6841d844695221cdd1d1da27bd9d7a2af18836521" },
                { "cs", "828efcb1ecaab442ee4e405b7a966ede0fa74979663e8e15171d5882ebfdf9512146102ee4605468e9f8fd2379c38ef1c12973e913656ad8dace2c7abe0cff27" },
                { "cy", "e34816c35fb46f3a5be40baa953fb559f9a67c96f28c239008accc6823d8de098cefb87ec93ef4a5cb9dfb1256b2349f12ad409ffee2d51b790257795ee8ddd0" },
                { "da", "e4ea72b8c4c40e34f5bbc0727ed8bc0d3298e4ba385edb0d2b0fd720fa6240f5012dda3d4c64d2d8ff4f95a157a58b3d72663e23a01d873c4270a02653019305" },
                { "de", "a300eb85955000381a5dcd8a7b964c697e5e97ecec8c889f2270c4911563798f9437e49a1f8edef984d74247138121df076cde9129277d2dea30378010b03b18" },
                { "dsb", "844025b9c19d1b47f4a1d39da17ae495cdf2f65118df2c2b15a71c4f79c43d97fb2d85ec7022f5a1470e408813fe1c7d6d14a4b5ecdb9a40457bc154aa64beb6" },
                { "el", "e1ef8f441aa8bfa53e01b5ec54fb5356d193bc3d478836618a7d295dc1602105029c649fc69f6d83d9c5c280024f0a27d6157cd6686189cf2566a56831c12ef1" },
                { "en-CA", "5b60ac3286dd50585b1f12762717ccd48f44a18276ce2e362e47ba1ad1c12caf12cc822e785084c3c3bd49731e15c310504fa888647deeceb9bd50181f9af7ad" },
                { "en-GB", "19aad2b510555688ea98e6e3a2eefb88c5c22b56204e32d0dd14639455d4fcbde1ec82b586582a639d240613f3592c5606634f685e820dd420b5b76729c1438a" },
                { "en-US", "e6e542ee3919f4bb28a6aa2ed1d91dfcb76a76d2c067ca8656216ef5124f14bcc48acfcacaece56221c82af3f8073d021d8195d10be9eb86e8a6b2d34b9b3b67" },
                { "eo", "63f99915a59364914813ee8f8a329cd0b881fa8f41ad43310236ea1c797a2e33c4f55db5bf5afc0aa641c4a8a04038073bb971e3cd90f0c7d72de1a03cd5504c" },
                { "es-AR", "2df054fe7824f7c77a868d47ee435f891b1204c5bf08e379245bec4e241decbe5e5ec0a97fa679ca5ae5bd001734344b3eeeb0dadfda6c84cf5654a6ab1783fa" },
                { "es-CL", "824a9262dd5e2476e3a4c6a589c80148b0a7bac2b9d163c371bd178e0a0f8991ed645f98b96939de83cbd1194b183652d34ca40972ace757c885ae0d329b5688" },
                { "es-ES", "753df76d76eff19ff83a2329b7f2291152aa10e158fd52a4593ecf32ebda7c54de3e98f671211a901aa21b8dd88c163be0ff26c99b6758407ae4d572f31c2a4a" },
                { "es-MX", "4300a9ca5a21163b621092ef801b0df7e752dc6acd4edf4a283756482eb4d5f53f946e633760c98044354324aa298251c53b6eca2395066cc1b07dae19fab57f" },
                { "et", "a88eec47d4352f20de23ee16b2d03fe7171b6e5ea3f50e1cb66db188f157b7b961cb3f731854f7c99b6a0ab4ff5810b6ac532e98ee7fe6841611b2fe0e96c1bc" },
                { "eu", "3e91ad4926cb4319d06837f8aa786a21549f4498e463023e7862a4f0e6c9c0714abf281dbb81093fb5cb0888a095825b62252518ccdfa551cebe0fcfe8788de0" },
                { "fa", "b9e6db80c4469abd6f3915b15aa412d49f1e5caed7c8aba40d953138719821f443d30a044c5d42d380fdd3a0519a146588349b657be1dbdcc4c352e3b630b00d" },
                { "ff", "bc19583d589c1c132e2888d24b0eefad4101b0cd7fee604a90f08dfdda8bdb02d2896d9abb9425f35ef56cd324a21e15d07031e03a7ce4fa0cb510823b745053" },
                { "fi", "11718c30c657d7adc152b5bda57c68a39df90cbbf03d670cbca75f93a8d31edbe5d3388629cf786a67023d3961cd0971f7fc2b3d07fb45d2acf0d866e838998e" },
                { "fr", "dee8b300d0c8bd0b333f9942c8b58f38271fa882fc507fbf3d1a135ddbd8d93613baaa840376d11b88aec09fe9bcdcba135123eb72c93c0a47f4a0588a798b80" },
                { "fur", "9a39c156fa73421bd92d890bed774a84525616a355464ec9a6a78e33bd7716e4176b03fd95678dbf5e5209ac830a155a47fd5551fe65e4c014b5e75557790a06" },
                { "fy-NL", "0060ac1c6998665d4b4876299880c2690a2878e8cd3117732e65a9208b47d40df4dca41f146b98f0cfc63f29111609717143f020afb86017b91317528e8213af" },
                { "ga-IE", "973c243649e85747f13f3112d9825cadd92859daa6831dca6440c053b10ac6d5ffc2db247da2cb1a729bfb711762903060411d11ad701987025061850328af4e" },
                { "gd", "8ebb269011db2ec93543b69ac4e94027d668a4837b84634ee48687df6be1227806c1570e69eb6e4972c6588f3880039d0c502578d96362a01b513551d5d720f2" },
                { "gl", "ba3422a68726250fae4cad051847228aa76a892a947f863ac576f815d5c33bd48990deb5ed7582259e6b7d385602fae494d64d22f33a135ac4e90ab543ba3184" },
                { "gn", "acfd72184b17cc8f937994d836dee340c674f2dff29433a1367cc281c9291714c7e6ddcb90c4a56e4e82f08969aa23d29360fa8fdfe0271e5248777c425e209c" },
                { "gu-IN", "7f312bb6333096197f5f8db71c492fe2f3e319c2864b601b910783b2942eab3ea8d113be0cd2dfa37dca8e9b943b9bf024a821b613f18d6a03537096a8d2722e" },
                { "he", "b5d03b24add058c493ed2f6408eb19ce1b43af675d7a0b37768dab8536a41d238f51fb108cbe1ca086b93c6986577b908ba7e710d6b3c748d65a106aa7247d08" },
                { "hi-IN", "97529438c4e44800d8027ea28c87281fa7362106e7a36d6292c279073731b2457b49582d77a21f8700b585002cfa7ff3f7273316d41a552135cf32777a1fec3c" },
                { "hr", "5a7f7c82e358dea46c88ed57c956eff6e6ce3663b500300902fa629bed179cc9a47d8ca99500c6ef2d67900a2fbaa9a819d412ef84f6444b135bce4bf30087a1" },
                { "hsb", "80a10e326f8235ed3d97786f300016bfb18fcf6f23d205440cfe973e79cdab74798b9c3581023f1c03b99cd75771545a07acce76e90adc1cc294d1351f6860bd" },
                { "hu", "8d72c42e2f5bbbd7bf0dfb7314b51c8b7d196483c7dca66cb0c9b5b80532fb185a728e509851ca8e2dfa8f5bd904258d38ba05f30e6c92150cf9b8e00c6f71f5" },
                { "hy-AM", "38b56316e88d2e446ae9f8c80428ef5c89754bca3d26f53524bcb7b3fb93daf97243021851f221b36200c548f017df3ffa4447a8af50f8c55b932dabf5761b81" },
                { "ia", "3b68332b379f93e04310cfc124ed12591ae7b9efe444abd12b04229ebf34e2ac1bf084258e8599bcd3c82173d785233a1d96f98fdeebcbfdd731e949a31dd121" },
                { "id", "322925b634462d36a52ae0b5c36098d7d0ecff58e5df2582365083dada72203b7bf8a148cfa5b980f0d736abc8f3bcd9605faeb642b00746971ebfa03b592fb8" },
                { "is", "b0217d1cdd314e2458b1a79553dd270d310ac6e56aac3044670f0b3ba492f66f5ba0980ecb1bb5a4c1fc235240484ca8ee699c173f9fe1a9a04fa0c5707be934" },
                { "it", "030653b24c95a4f408631893ec1bc49183386f44573af18ba4cebb03ebe0735cb857fe9cb943717779c4b75f46a5271c0f171bbdac367891fb2ede5fd56fec19" },
                { "ja", "cb3bd95ca7222fc1fcd27b5d30f607d6e6dd06f639b9aae3e3011def8fcbc5ffc58a0247dfd4afd410c83735fcbee348abc922fcee242b261abdc2dc75f1d141" },
                { "ka", "1258c0f43d18ba798ec4dd211d500a35a774d6064990cf91762fb386726047374adb1bc53302cd5b7b97a937cf39caf4419624c0adbd999e75929efe1dba91ec" },
                { "kab", "1e7c8731d0f7f5456a6d649a007e12ced1c6e8c1f917980caa7399ff035b6443954d01fe5599b36178c9574026913c26ebacd7c5813610da360d09170a78e017" },
                { "kk", "9aa763f068209412321f744dfba79f88477aae2719387544dbf8ade0954fd3e80bf31345eec3ca024e6e1fc4c1dc099fad5d54f019d71e79107532300b362eb8" },
                { "km", "1079066d617775ccc5312d8d59a1c0d9baf91fc8f56440284e2485f4db93cb03b7e050e1462b1223d2859ba4e8727b6e6258c0243bcfe68dcb7aab374b7b7427" },
                { "kn", "46f2e0f62beffd50639159c4208b2aa65f28d9deb73e44d973798001d2bcae42739d2bbc64a416b19deed18b7b9ad2d1d75319efd6c8152a13680ded63984848" },
                { "ko", "22b2899c9e22f315b65dbb3838cf5008aef1203c9df8de3a08f6a72bd6ac974e93f5f466fca2d7f7b7afa28cee5ac4bac5ff5800193aa317eec884be7e6aa60b" },
                { "lij", "1aa35ba7f73921956166463f980ecd55c465237933fc3333aecaf89577cc50e140809da1fb5cd67a995e1ff58b780938858077bbc7931dfcd1afc92dac7f636b" },
                { "lt", "53af7924641fd991b582e8c5884d2407acab3c4384e720580adce67a289378c24f624d3e6d1c10e5a48700b00a5ddd3a76ec6ae56e4609c8f0990f9709c80ea1" },
                { "lv", "62b17a83792ca8ca8f8a35bb458170e4be49124321c165da686fa54cb199913ed14ff35671be961d9f3051fe35ea20a93678fe538e64372e16db388c21c66b1c" },
                { "mk", "b8ec0408fc3bc5925fd8ba4ff8ef07a10635410d594834a07c75de178a99ca5cef4c1b3c990efccb5699f2e56207fd351d25d106cb6befa1be69f22ee8ce6865" },
                { "mr", "eb1631d8cb2145f9966714ed02b2df2dcff2416651c43b62603e77df8715a1a1a2220cea0c8cafef3d839d0dd163b9a3ff44cc2b85fc7376f9b326723cbe2fba" },
                { "ms", "60e5ea0976a7ff65ccc485da178b301fbc82fb18fbbe188069f102c82eb950629f1bf3fcf4fbb88781a4bd4f7a14f2103962f0a892fec3d4dd18a374c5b30380" },
                { "my", "c328c856e45247cca125a6f48b2a7de4fe656cb5fd5afbf0d54bbc26eb93d2576e29d74a88db31768c25cfb6d3cd72a90e5ec1d65dd036fdb99739d69171a5cf" },
                { "nb-NO", "b9f81e072f9ecb54e39e8cc3b6089ec903bed4120b5b2c7e023d10a7e42eede7aa5b826b9967af693589b51eb9402dc0ddb201c628d23282f5d8afe260429d6e" },
                { "ne-NP", "052a8f881a0942d80170e540828e950de7d2db7d0aa281ff80ad1131f4fc0499e62fbaeba45170af86f074c809d801831c810a03383f75930a4e27d4932a12fe" },
                { "nl", "2067ed371b4bbdafb2bafcb653859e97889dba6648ef9c9145715619317487b97386f48c152a676e05a04891f5e2fca9310fe19685f7aaabbf853867f0b29833" },
                { "nn-NO", "3725197665d78d5d59a4f8a7a1890ee79d56a715efe4bba6bca7967ea3cff977f182f8b12b53a0c3f68b685dd6ba28605010c2b669a832a9bd85591ba72f36b8" },
                { "oc", "0dd502c38897ac50ddac42d9510090768fcb70eac325e086aa870c31c8964da02f9777a51bd09dc5b90148dd2b077e18423b52eba43a3f1fefdeb01f6af36c7c" },
                { "pa-IN", "762179781295a8184187d9d9adbd23394377c4320877ec83c8da2e73025bd6cd1f65ddedc414f58e6a06bdfc8fdeaeb08cc59b89f9afc73bc40c3b03e684480c" },
                { "pl", "0eb2cf8486de62b7215693d9ff3a5ee423f55da2071aa879b0ddb57b92053f91895064d7a3ca74b63e4c623e89d908df8c5793619182c85bea4424d3b702611e" },
                { "pt-BR", "fd493fdf49af7e7a7c59f805a9547fee0eee21839b49324a824a035735888353ce3bc0ce4a8310bad7f5c2d30bde8fb64b4c89a5e4c5d445a4b73736534eb35d" },
                { "pt-PT", "13026e0c4abccfcebfe590b6f97c3677d7e14927c694e9f28b3cbf3836f4e415db4de534370784489d3ed5c71c5d947eb2ce953218bc6912529f18674e30ce97" },
                { "rm", "fa447904dd27cebf0a19e028c656dbe6e27731e33fa1d6ec8c98d927a113b91a69230f353a3d43f096632dc512320724718e75f2b9a5ea5f00be3cf24d2937e4" },
                { "ro", "441460f01e525532acf792f4ff58e7bfcf42594ae45acf2b787e549a63f669a0bc509ed1b92a53ccf500bfc2e744756d3e75ad300269198e3655f76dbedba8c4" },
                { "ru", "175b299f910c4880013a2f8ee856a41fa20078c3644644da7cca7b385e4a458be3bedf2b1e605a644f77d26f29ec951dc55e7ae3c270b7508ca2d5f1211eefb7" },
                { "sat", "558b9dd3c487a3abc711bc57518c25b95762c3a90abf3fe5d3c9a84aa63eed966078ead212bfee76346e6b397b2bf6713533e05dafabf3b51896204d2483189d" },
                { "sc", "f90b20ce0e2ebd5af1e3aafb6c959ae7043c470b3ac14561136ab1f2e4bc3da2dc9179603fb1aa2fddb52f7707210311b17e09098a3fe19032e8584b376c83b6" },
                { "sco", "bf49d6516366b16d81f5aa85d3858e730b7b409dc19ca54f58a83297bc7320c73cf32e1a948b0dba6224aa8fc7ab2299e2af585b5b0a9f338c1396a56c85cd49" },
                { "si", "350bda082a1ee700536e03c352e09380cedd5f517eece0fd6da17ec3fae6085e75634ff79e67513eee5befcfd34d99830993f7f5d48b0b84817838e84d001b05" },
                { "sk", "1cdb27442de2bfde0bf713d0c430336786f012164aaf61829f0bf731a370f8ca1bca328ce626549adf962c98c8331cffdb79b3792312760606a6fc154e29b6cc" },
                { "skr", "fe4f6a2ad6dc2cbc1eb5e0979a93ab0a9c731d16778e1ad0a1a6b5a9b5d64e776115a18c64f39319218b945614b41b368fa4b23bbf7d2eee73cfa302bb6cbfd7" },
                { "sl", "630b07e199a1ba584d45b1a779f7894a98de19ff1d440bff194dfde9ac001c61040dc8b4fd3b2f9d7e44955356b556d6a3b9a28c55c56e6a50523ae877ce60c1" },
                { "son", "694366a6a0d9702df8b852a8a2e7856af9eb80b24bd9737d863927af97c7e5682a11303e0364e50bb3d7994c7d8e98af4e1dd0c9c8c2a857f69365f9db6c4a94" },
                { "sq", "7b77de3239b2f8f9e7c88febba74618251bb0f43b26a5e82fd06913b129d9308fed3023bba6636228262420365528ca9f854e30e79b70ef978be541fb9072a84" },
                { "sr", "3302e36c84b4249f1e3ecc102cf15c6b3f70d3f4faff0316c13f215b9a5e27d498bd5b81ab8aeb0c9c3f9edaab28fffe6a9ae4a6bf75b9b87bf88bbc60a7db88" },
                { "sv-SE", "7f14fdde2769abef7df209759a608eaa5b1225fc71c37fb37f020e81bffb1c6fc43bde069cd100778642ff8027cae98b81dc5aa62a4956f801f919ec86e8d048" },
                { "szl", "7c0984d4bd2cc408fc5645f4388cd1540e1beb72682e876140cf7cd2a15629573d72b8474f5106e1dd9226785df5f7bac1f6e003b62d4f209fadd6a7183f50ef" },
                { "ta", "147b11122d69e170417828671881c3c41936918908604f0570e27de5387c3e085bee8c3e31c0a53f2734725afa98bba15dd1780145af3e200a96f4b054ec44ed" },
                { "te", "9f0986db5b6fe7988946394ba163960402a95ef36077731775c99441d72d2168d2c21f9e5a16fa2cd2bd3d52609a8773901111a59733ce58393463f4e3442c46" },
                { "tg", "ea4ba40f51dffc59415a2142108db6184bffdaacd94bf8dd11648c1aaffe1d7f4edd16a4979dc84fc339eaefd2cfd97dcb724d2cd4e019cefbf3c45b90e7083d" },
                { "th", "6ccec1ea4bd5f4cdbe03d8880322031084cfaa222d9c9e73b3861fa9d0dd5dbb923f6a56adab8ed60915784f2c7c93326be46e3944bdd7af231d0797a99f5ba9" },
                { "tl", "c8ee815efae7d09058efb3583d0e5c2d0594465abdd08ac4446c23075f088379d22113e65099915074abdec5e29bfe86d554460611478abf6b4b07e7925d949e" },
                { "tr", "6f028966e1cbcc8edfcfcd0e2c97cc30a5ece921e53232ba659e6a4b99159338db8e7bf95343badd661d9a3d9395baf09aa7e4bd86a29b6d24b0848dd7c57d08" },
                { "trs", "6f2cfcf7d9d7ae7ca954e4cd9aa366eec169357b81a02b2c3190760a4cef47b8beab242692b74fa5707c3792a73ce229a75d18274761d630da83db56e079fc3a" },
                { "uk", "5c3d0e30cf97ecf3f72909b8e33d171deb4f23ddd0ce9a49e29a650c783d8435746d12bada3f52dfea7736ac97f51945e95b4a68aab8cf289cce87bcd1bb0489" },
                { "ur", "bded095c6ed2f2f52dd989d6f584d1c0b3dc2a35d634622d8b2c3d14435843b22b1f00a30639d745e4530aa16f5c17a15188d83427eff662b698d5316fe15085" },
                { "uz", "b7341ce56bd0a891346656bad157b0ad03d4a4ca5c52bc6c023e110168d20b4f24ad23cf3d1eeb023b431f8faca15e02c324d37d0a33c1ad3f7148ba928fabcf" },
                { "vi", "50831c567008b337f08c4d919595ea73ff057ac49c04b915c69a6f1d0463202bc62d92aa9aed5b5a87e69048532d242b6ee313d7b6ac54705d76fbecfbde9627" },
                { "xh", "e60f513f0142c99ea4db9597a70e607e36386a06f564d50ef21d04012815a03a0b1ab87010cea357cf41a8649fb5220b8b504d84d2bfe7af9b95a8591afe6aa2" },
                { "zh-CN", "8934551acebe5040d5ff652afaad1483e7878bc2a892772408a7c6a5313f020a2928851427cbd29b398cefdb7d4596fad6b6bf71a512ec46aad12334f458551d" },
                { "zh-TW", "798319dbf5b8c7857b3adc988776894e6d8fcc1cd714ece9c9816b1007afbe8151f47226040736ded744493f043ccf4c2a035a091c5c3dd188089d41cc5dc7be" }
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
