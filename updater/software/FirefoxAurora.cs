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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "123.0b2";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/123.0b2/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "edfcf994fa1c0052755e519921bd5e33612f74b824d82709181c81474eebd21241b87ba29410155f30f99fd860898da5551785794b7156524f3a15d4282e56d5" },
                { "af", "75eaf10212bf631a23ea21105367316c10b94462af9d04a308c8f712cabc2569167ee50683c48cbaf964abe1f9fe75e61eebe43f9ac58aa857716641c99a2216" },
                { "an", "3c473af1b152853c3e719056847c1c86d349707fad6b8ab7cf74078857c32e75183905edb5922af84f509b6bffaf39a13f49dbbcaf535992bf0b9a407591da67" },
                { "ar", "78f31bcfa06a094ab1cfd464e096449990a76bcae6f92bd850dd0885d6db27d87123f9b22fa171db64e1fa35ee37ae65c694a3c00870cf7c348beb465402dbb9" },
                { "ast", "31f20476e9825b16644361433fa3385e63c656ec335ad6b68f2d6761089191b314f3fcbb8099a5d1f01f448f576d02c58a5bcbd72eda2c6a8637ca7122e956b2" },
                { "az", "0d11fc691b34a4035174e957de0404a314b694d52515a1dcf0bca51cb6edb0320d99d0209035a40f0e4d858969bccb6cf7b44df7d8ceb5272ae8a0c219194bef" },
                { "be", "a6fdc8e68973e8f12c8fe332d962e5fb32b7445d617d3fd8d7a0376fb467b38e13a3caccdef2a874f84d746cc294380797e516216243ff5fece03f134c2f5a51" },
                { "bg", "e5528a41d20ff76b1bcec1c4be27e36592d0c5c6edb886e89141d1db48de84eec74010b3da1e3e7f39e5c9483314fb0ce3fdf5c7b78689a3cd8c6b60b5cc83d7" },
                { "bn", "bb2396b1e4894124ce683b08421af1fbc6cb453d5d01f9cc47f677e5e00ffa28ef92b8eab10ad6bb54ab78270015ce7af8812bee5fb0914508abc7e5b8f849ed" },
                { "br", "1e3e4717ff33bea0df7454ca62cdfb1e4fb00d9932b682a2d0df5ea33fc5cc9f456eba9eec562d02447643661269d8c9b5ee60a4d87ec158ace734939fca5b7b" },
                { "bs", "6ccd9f6bffee8d0537843cb735b2926031daf08e075bd78020cd3edf400bde587c9ffa2ce4c7d1b5cb6f6fd88a086baf3a6b0b8d9afa32ab9c030c6496f192ac" },
                { "ca", "1fc05180b3a61ef3e790d78acf76892c0f7d588fb35dde19bd063c8fd581a7b1d96db20ff2892580aed686f6f42db580d9a7f02db35cd879b7cecf60eca07afa" },
                { "cak", "3f7b4860ac1bd63c5c8a9af4714db5d78239994f1dde4b5b95bd8c1a1ca3c4c8b502b6a52cd750603053d30938a41a479f4ee7aa581c8d3fed7f74f68236e023" },
                { "cs", "6e690d2c8e40710163940f57b436be444dd683e3d43cfee9888e525f6081d74d3a2cfb270f6105743f189061c3795327a7554cd4b7d7a5330caf045707bb6a76" },
                { "cy", "1adb898e338baf79924e58d01c2abd2f4f9235730dfb2af0d4e0a00e549e22a25ed9e3f297f13b325b6f85d354ae4b6d0bd3066c6ec63c61c99c275513d6f249" },
                { "da", "3e4566a7d4178cdf186f97afa28d9507e7df17cdf7f2ddce24abaf486f8c328ce2a708dc12d625be2ff6cba284d27e76f21b3677aaf70cfe2646365406f88911" },
                { "de", "be73652a99d44bf3bef227b9f6b515be4dd1987b98a486eceb48aa7ba9c03e378420cd1d353e8563f2fa45e92be71f48d999cf6182479d6e55cd6b0310625125" },
                { "dsb", "6e5c89c952e3c53b6d28e295eb29cd0ea471a1a83a388fd8446f656a58acde191a742c72a00457242d707003fdf5901b0e9bb9a61477b2adca42b59982764ac5" },
                { "el", "a2b22f5b9a3ea42eb03f2f5c4974231d9a136ba4c0b0239e02125b54a9a94196f5f7391dbbccd1918c9e0d9f82c264f69fa337c2aa671d805154022ab5af53cc" },
                { "en-CA", "cfd1309a3bf271c0a30e0c957dc427834eb46089a00e16e1f9b793ade8a42954bcc1fdc42a3f493c20858e140bf4f82dec97d6f2af86077a20454c4e5b69bbc7" },
                { "en-GB", "ac64f14302c16d7f41f39d3e04e3359884d321f65695ded422e864fe033ea8e4389525949d62b294477400850ca09d8af52bf236b93a41c3b7d86d77ba40ed4b" },
                { "en-US", "2c71ecff28cbaba14308465022432c0794c6191ac4671b5de637e1d56a814d668bc3c4dcf3886ebc0ae349f45446abdc5143d51dec4ec7d4563bda57d5327ba8" },
                { "eo", "9b6eed8a4afbf5c041f8a48c00ca18945010f7a56a107c71455b85589fee4c13b540849d84237f8e5e151f0ce05d848269bd914186d0feb1aa7994c594fdc4c0" },
                { "es-AR", "4990046f29c758c1ce88723b23b65521b94b6f574c73443e7032c874206a09942bbfdb70477fa3ef5e482960bb51f6963896843e8b0e3d544657c2ca7b9b0128" },
                { "es-CL", "e5bf2176d31cf07bd1dec7160d423209c75b42a247e1e6e01c98b34249965c83bb355add4179254613c23720a63f1c2c995ffa475d4903a11760bc1344e38d66" },
                { "es-ES", "8d236da3f50e7999ca0851188b5436549979144d42a9ef589bcc49602ce8b630e517001b037b03c87e488d9386bf185dc7de338149d054f5921e15c49038e5d7" },
                { "es-MX", "7cf585d22d619c97e07d92456a3a69286982a4d04075ad90d07e1acc89e003df3c38157b49723720751c3a1ea805a618665a8102c89255c9a1028ea80e121679" },
                { "et", "851f4b98fecf0f6651ac3853295a646404b1cf42e3eebccfb23f79a227ef86c9dd5e6550c80515f6d779b6abd8f8c97e89d1ec7414013d32048512925344290b" },
                { "eu", "4d61fd307ea9e1401f3b6002743d99bec21da74c7c809e17c881c633956831780bedd40151eb859536981d4b0e98d15a5ffe65998c7c961c483be356b185f8c7" },
                { "fa", "a7f3348632520dcc8799867383ea308662bf9e08ce6b46c77c54e3168a086527297a471f545c0549bff84c7e6b9f8cd1ef17ac28f4a16f70a5aa9b7c74835202" },
                { "ff", "63ce28713a0c0f9bb21a2cb82a86d4112b27a63ffacb8c877b3b42efdaa51a66c49dadd67aa8debe4089a581a7060dc0cd6fa8e640e8206783408f218c85777e" },
                { "fi", "a9c12a31e9b5b1899e72ab4651b3d5126c9a540537ccf358f2078d1b0495085e2fcf82889cb516ab2d61a27d47422e4cad33bb178da5a45f741d928ce44acff5" },
                { "fr", "fc1afc9e343bc4afa09701b6679e4991ff14095db3309a6345fdcbbcb973f88b8d603a9c3514ce429982f3c033e0a2258e6a84144000d027d77a8d60dcf164bf" },
                { "fur", "12898e04eb290b70f88bf9c3b9333af77849c40be493169c0bffa84c13e9062d61660d6cde0eb705416c48b9b827abff432ade402b34896a74d6b9ecbac47793" },
                { "fy-NL", "dd52befa294450d94606dbe040701d9fddd68256fa9bb0090ec77482adf7c9f6bffe0a51a3d2d2b9d0deb92a83bb1a906b2e5c5993c1eb062433249232fe8d53" },
                { "ga-IE", "7954f4ac838cd6d1d2a822f82df945fd54bf0c69b3546a7236f551c584b7465dca7458a3c4668a17bee5d73f9ca2e6529cdd1548671f0c70c2dad1fbf76c76a1" },
                { "gd", "85a132c7ccde03719526989a6646001e035cf14210eb9843d954254fef04710fc6d2b516836f3883327f14d85736aef1c0d5051414da998e37fc53d53f622afb" },
                { "gl", "fd97cb04b4f93b911d3fc17a6594d0dc949f21871eeeb5ac25f0fff405e9d09924259b3ff6d2015fe686faa587c0d42e160763ac351d6257c84d94cf32b73de6" },
                { "gn", "014d76e559698ebf6a2a89108d5e0a27c18bb9da035a5a2beadab6321104b01e9abc5bde913a82dab0dbe28e19b3d468ccd779dbb135487dd7e7755a5451d06c" },
                { "gu-IN", "4791646b902a8cc3104a8d5beffb7a0db3bcb7f6c42e462956d9b455eacaac3ea45bd4805f7f6ba24516b737cf6e8d2fc5062a6555b62670e1c62c8400d33907" },
                { "he", "0a7d226256c4ffdad5c38c1a89f870f232a72116fab836c273561b8e05399ce8f0ba420b8a6be83f088c1eb6cc3de1b859cf30e1d2cd3fe66dddc6f36edbfee3" },
                { "hi-IN", "3f027c3adcd953d0092a1eaba666c9ab36250435fffb7e2f701a3919f5f25f35dfa424fe4438264ce6b628b6ce80650025253606b622b742254a6f21db4d3444" },
                { "hr", "42a29126277dbbc1ae82f875fae4864d50745d14f5a00ccd915857acfe02b73e2c0ada678748a169481ea3a259dd19d9126e82bafd861c29da7a52e006c68e00" },
                { "hsb", "5082d76138ab023734c866898fb5de36a30b911fb0eb494d813e284e1058bcca5ffc6e05a45210bebdf42b848f61ad3f61d5f643f48ce4d13b3bec8cd8024780" },
                { "hu", "3f640e4a1e3eb071333802579431e61f45d2ebe59321ba18f588822e603c9411e92b5461bc0686d432e75777f2d5ed367860b80970c1d6f635dce77456a4ba49" },
                { "hy-AM", "78d8561e67bd63843fb68ee87dc4d5e4abfb6ee80cc3f6d2f4ab9c9f4bff915ac591b5ec3961ad12deeff5d3b3295e1cce85e0dcdf43485f1dcc95ad86b6b02b" },
                { "ia", "c856f4a55cb6937b21c6f30e432752c3c40c08c47724eafa02640e11e77360dc6b3ea8383a30e713af02d8a37e35fe2b47d2530a832d3960924eeb86d3f93169" },
                { "id", "3bd7b6918c14eba391e09684078f2ced43ef2bc77b4fbb0694e51111f1b886fe596dd5944c78ec6d8bfb775195dd26ab4ff3639c1533ffbadccdfbad7bb90ffe" },
                { "is", "48fb9dd5025ec6b6c2709d50726ba4a0ab357824d5c6994721a18562d88433d497d6096aafba449da59c502ffaa679fae879daef4882cb1f39dad65123787f10" },
                { "it", "e630b18732ec4484b8562151c745bead6c92c1f1c4164ff22ed4e017c348d98315c9ec9e0369767a565500c4e9bc4f36ffe3b92c038a7d3a34a8372ffe06b8c3" },
                { "ja", "badb4b2c8686d513917b1588fbf7af382c80e255e1f5ac82e54746657348872fbda8bae71bb25cd7dbaec231e392d016561f9a659246b7632fb1776ab857bb67" },
                { "ka", "4e2f7dfeedb14549cfdd1b6846fdd030c3c6b67a2b1ca2bad815ad31cd01d61149522ca2782507ae5687def4e53ca3c59082f8bd45e4b7aef7b607c31eab5b08" },
                { "kab", "d5581328a91931d008e5189e2390eeea2e67eb9888ec1b7c93c162506052fa3145a2cf1c3fdea169f2973756c05396930b810372624f82cb8dc5b08610bc672e" },
                { "kk", "d8931bc561a8f0ab8ca2d565682f3199faea725f28d2cdd3142dc5aa638acaa782dc3be9a09468a1b339b8a8ca5e92307d533c28ed7025dce225e9f3d59a4dae" },
                { "km", "5e7f17377a617173a7d8830f32e4e1b8efd50f4dd23d907492be477d45c4efdf801f22360967f9b4b747d124869b8e78a677a0ad4e4d8eaad834f94d2907cdfe" },
                { "kn", "8c177fbab67320a95cfa504bd484f813a09e8bde6520db523ca328a8be3f3fb12a1bf0b5f6f3091a0903875052d1a25ab0cdf571d39074f526f305d222366957" },
                { "ko", "bd020b899a0a90daff1c459b8b66611e134ae51f000c605deb21a88096c311018e4205b5c8a98f28e419713511de7ca4978b206d9a043655d7ed5d2b53141519" },
                { "lij", "2cce49e71be5ef84468cd63558634185dcc0123f387deed5c81a097cd2c2a04bdd9a0d4468a2d1167c48b85f58b8e50055997e9ecf0c94ce8728384f2974d702" },
                { "lt", "a5e64654ff7add0a4deff95f49210c9ba4ea04feb3fd15d89f4fd39e9e96a071e04647eca94e81210f43863e5bd9cf192dbcade3915630ceb185589aecbfb90d" },
                { "lv", "d0f5b957c763342bb5d0f24c071f9198f7f3f7b25cd2f0cae36a79793560d5244304c170497a4b252f8caa8d3dbdbe06a0cb3419fdf862afa19e5a18ff817d54" },
                { "mk", "7ff1ba2d03614c73ac7d6ff15ec47a7e7ba21de773bc28ce23f21a789bbda03d3e3cd604ee33cf367e60a661bb2ad7757e33e5573ab134bba6cfdc32ec8c3802" },
                { "mr", "3bb89d576597058e08a86731addb719f25330ab31cdde42acc65eeaee8819e31b9e79d03c8b9c20c98884f5e1e176186acf43e21e0b119dfda8cd5ec32890a16" },
                { "ms", "94b1c33c08a412dffc5bf3d9cbabb33a51b4525d1435f0b6554ffd19ef9eef9d0e07389bef4361ed68d71de2e90ec5e22efb06b4ee35547f7e586d0e0dc4386f" },
                { "my", "c1d62ccfcbaa338b0a003d9fa442d4a0162b7c6a6c67049ab4d03eabc5d153843e70cb1919017919cc6498415bbc156bb16ae4814ff2a7b005a367ad8ed99d40" },
                { "nb-NO", "041aeb343dc8ab6d67a211619b7d6e35efff227587b7c3ac2213603d6b70a574355c684ae57002772ad7dd42c7ebc72278607fbb29ec341d8e4ef94440005ada" },
                { "ne-NP", "97b504c1c4052d15d61a88abc229f4565497333bb19589b115f0b846f8b0887d8e136ebbbafa4ca43f381f1b5d8e98c38eeeeeeb3111a50f94cb55ba1689cee5" },
                { "nl", "f2797effa5e40278c83e630be1272e2152878abc00c14caded44a2a16c88fa9dec69bcdadc45adaa96532943794085f1cb0d1d70b61f8ece5629bf429ea1b331" },
                { "nn-NO", "b5e15e2edcf287d0fbe825484ae2b138b151c11de29f7cb8c238ad8927964f58956e8b5e8dd67a45ea2666f1cd0a3449494adc73aca7f4cb1d2e5507e44dcdcb" },
                { "oc", "6dab2c87b0bfdb2c97c871a367d6a37a1af4f0ef14761c2616039657da16af4623c1ec1b13260c4261a405dce12619b82d0e63b36b24d49ed6692665d8ad44c3" },
                { "pa-IN", "0574b8a801adf0333453b70d9c73057ba7121103797a279aae79d5abe8d34b36852af7047ed65e577bad1b622225eb4565651395d20effb6222c1193ebd8a3cc" },
                { "pl", "bd0f218ff20bdbe59bd2b6aecd7da4b12004d570064a50e8b4710da66f8b831b560fa6f9e5f07263af5ba9dd1a613a43df098fae2a724fde4aa55966bd9de42c" },
                { "pt-BR", "23f573fc8a2538dd9cf916c783c65e8970e91b568dc1d2b23cc8491e539265d798cabe16c5f6306016897e4c27df1547e27c15b90b17015f2dd042444e02d129" },
                { "pt-PT", "93798ff178cd2b459af9c7738762d709b08c73fe6fdd4ae52e73c94e041baf97c7718df34a3c4640e54c2d6e7d88d91589ecdee91a9b24f843e755fb25c2462a" },
                { "rm", "4d23069b50b8fcd934450f6bc4023523d9e4b5ebbcfaa9f8f7da31522d9eba5a8fc9fa7d7c41ebca69e487fb5a40a6da495f51349d5b60241454b59eab240a11" },
                { "ro", "76cbc9b78a2f732ec4fa1a0b40510923cee3aed496765ff3f97f910f6468f8b39198b686f20ffac410d8d3ba91e4d8433377b35870440b82843d86b40f1fc5c9" },
                { "ru", "32ecc32a8a14473f5d9aca41825f8fc335894c21d8f26a16c0a4e48dcf1bacd65d12459be1fbd97f489754d62636498d7bed8fd83d5cfc5560705a176aa11588" },
                { "sat", "9eb7783a7ebc836e2b1e6cb3a8102487fecf32a9693298d62ff36683af3e73db277a4b0a0842391c2b8ec2324ad16f52b5645f2e10b99b8c8416c8f87d470a16" },
                { "sc", "e4abf5972fd1b339add26aef48e362b3604565927ee372122aa7b913201db638f68a842888100a01a5f12fe68ec7be0f89852b26065f5458bacaaff2e8d9d4d3" },
                { "sco", "ebf3168485a77fd7057963913730eca1cdc7af93b9f42a18a12b297bb2d0b38ed68d3bbebd571fafe3d821fc16424eeb8cfb7b83d40aec438b78bebfba4ad9fb" },
                { "si", "2d5b5fb12da071aa7d104720f075cfb8504c2f7eeb5e1b9e2b1e8d6e30c1ef31a0d0fde7f5e363a0455bdb9a5b1b4aaa5a291cdec3ff2c83f1cf40a9e066d4fa" },
                { "sk", "e5a876edd926d4a7c5821abe4482dff02b5307a437017012444114028730304cad0a3166b49ce2d8e8373e197abe51d71d0dcccfe90c6a027e66a0cd0f4ae60a" },
                { "sl", "34fae3802448f99137ae636ee47d4be8b349b954158f586d0f2ccf6833b3c4461d6354f685cd91e08f052f2f0fb08c81d9d385bbeb79aaed26b8fcf167b5807f" },
                { "son", "3555664dfe8026afcd5bd3160c7bfd3039105903bf3d6cffe211388ff6ab96fd094c75eef21803b2d0f2b3ced4a6fbcf6e0638a139e8842431548b37f22bed90" },
                { "sq", "62eb9e5a703eadfbb349257f6ad711bd49d2364d5a53b7f169866228326523875c694032b4116c75a6390d7ea99e6678faa184ca22aee40e945c655f91bf6796" },
                { "sr", "62f06db757b3821aab2dbd3e0fb96b432b415f3801c3f20fe8da846ba70426ba9a6fd2e6582a73324ecea284438ad2302c18b1eb404c293ae0858f8f05acf311" },
                { "sv-SE", "ba0c2563c8efa7ef3536e874b2aaf2c4a9708b65ec4c6ba5fbcc24b7ac05cd0e85bc504ce1c321986fe14c655ee59a30d37ec9964d0760d1f4367400a6a69997" },
                { "szl", "9c3de9d25e9a8c6b963be2b73eea5533b5b12bf3adcce83d2b7d210cf8c2ad85d65be5cf3552ba2cab5520ea26b29df4a029255495760cde3fce3063b69e8ae0" },
                { "ta", "233ac7f37fbde66382a59d4873f03a0072aec9ed2404648ec589a4a23878f39b706da0026e97a0e2b0cbb194727a2c2c43388334047d864aed895ab38e252849" },
                { "te", "f39afd5707e9abfae2186928d0dd4945efdd6acb96c5052333380cf05ac2e0aed54d409112f7daa125c7a53bb20373b7f5a920649048bb2e529f1994cb9ec933" },
                { "tg", "1603126ae2fa779abe9f54e1b00bb9c62b3206db951b40864760d460da62d5af68078abb82ff8c74d5c03413677fa6a65f10e3efa82182988973c2fc96e53a7c" },
                { "th", "ea305d700edc0ba76d51251a0cb3a6d23234ed34d07170ea58c45685f9db1387275ca852ca16c87238f36a0a3aa912ae1d3813c5a7ac637c310a0f3240a4c943" },
                { "tl", "8cac218e8af3183779c2b835a7b65f1a7dfe97feccc48fd292fc5c61bf8c76d11e45a0f25cf9dcd5beedebfdc519401722bf1db026bae72c9aab9705297c7f53" },
                { "tr", "a770082d398a6738d393442137f8bce2cc7ab0f44de43e1c9545b1c90a59579248037494bbfc4e10d15c4c5adc77c932369f6cd37e4b763cef721ffa00e9d4ec" },
                { "trs", "1a0fa5cef375871a5268c9b7dfff7ff496baa3b39f5fa04a9b6284fdc45c36db77a929d484a4cd7ed9a09a2e7a641bcdbcaecfa698371d960f097db058b15a99" },
                { "uk", "2f70237aedc9195dca605ccc97899ac9f4e6f43880d431a563de6ab0540829e1e4fdc93f8f3f7670fa7db06300887944c46f8728589a0bfc3e86582b8a9b0561" },
                { "ur", "5a602f8663300dd566cb23c2bd87e662bd157d7bd522c0462960e4efc1a344cc10d7328444034aa7447d5856db637a1e595385dee55d294a7c376b1502c3e6b7" },
                { "uz", "865ed67e41c6baca41b64feee9aca869a21c97e842987e3ae9211b18fa6968ebb07a9c21b41f4213aa23e37092373ccabc0791dccd2dc383edad6ebfc700fcb1" },
                { "vi", "9f1e0b48ca517208566d31cdf79635dc57bc0cdf6bd8f38d16ffc0238183e685c924cc83f77d933b57bee950fd361c22395cd753f90c7055732d3e446e9ff2e7" },
                { "xh", "f65bf784399520b702d12328a6f66d20020dd0d16bfd882ed851deb3de9a5fe9aeab40fbb656938737d1c9901098dd6fd22fe4e173154e51ae65d985649d86d3" },
                { "zh-CN", "6d59c8749855f301e9d98e1f8733c5e8c821e48302458f1bf2b739e7ab25ef19ea568de3ffac16b9776c8a8a5d8ba4f1c4ce42b13bcbbcbe9c9b352aab519dda" },
                { "zh-TW", "37a8c54f54d1e06f9025b75e8146054583699dd087ccf08c3424bbb9c26198ca96a01a45af69b5d306b4db5b5a42adc8b4f97ff63949a7c57392838b7311b36c" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/123.0b2/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "dc5ffaa78882c3bb576d960bbb3c84b5d013f5d1ec9652a9501fb3e66d821040cad46a793842c77fe70339b15ab657b6a6c0b03368096ccb10fc32b0f0995979" },
                { "af", "835b7b15b5c6054b5765cfa13130b4ee751f3ffe7bfaffb7942e0a343b029061e15cbc0b83a320b394e083beef0344239aa9fbcd0a19ae28c38cdc7e36bea6cd" },
                { "an", "8b88a70d3013e6970d08ff833aaf686cdaaa8686d36d2ab3ec6fea3a10f545aa4680903c301738796810e71ba41ebc80b134ae7ac91018ef229a2c2f81ea7fac" },
                { "ar", "7ca869934525c749590ddd2562eadcd4e47c964a635e69387581f1e091ebc607285e59abc963be431ad9f98ccfcb18f8abdcbe5d53129d110471621318faa4b4" },
                { "ast", "21767f25dd39ff08215fa64b2c22533eccb6575b704e80092765b941e80d59d3f366037ff952d613c465160d240e64ccd52e1a8b579b21ca2c82170d34061f29" },
                { "az", "9895ec7ebec2f4b647a7f504dd98c2ebefbdaf1bacc8fb71021c8856133676b869fa5365782d887c9ca579918f25be06d41c01db2c099397dd322f177a801576" },
                { "be", "92105ec75530c467474b79e98fb6ac81fd987053bfb97fa549765a3a094a4b6549534a443f27b83038e227b9eae41051309f85cb7be7b657691934e352ef7259" },
                { "bg", "3975b1738067365c5a84300651de3d71b84862507b6cc02aa0e64def50f4c11b961c9d21aafb946e5ae57879f87550fba2e14e1d6b549c1103d0b568b6d51f93" },
                { "bn", "ae0fd8c236f4c5dab79eb5250027a0f06afd3a0a4b85541809ab54a3a5a533d0df3f7ddd2015ed2f46e20c0d16944938a9127c987b23050bd54a140eb8de3ea5" },
                { "br", "2d4bc78f99a0e008e460fe1e279de354464eeea506959242afbd38ed0ccf54a3dc5e13f2dc543989d0643c53ecfab0c7bca2bc1b75794d66b1caff97e2aa79c5" },
                { "bs", "10975c3c36bf9130d650ca42c84d86fd83f0bdd7a433edfb1b13ac3a0dcfcac283ef1d5ed1d268ad88b88ff9634858cfa63d076a2be00b5f405c867328a29489" },
                { "ca", "64a12f64898abcc5b48364b7ce84c87fa607d0c25c2e4233443226eef88769948b290fe8824b8b68770127451be9b8fa16d7ad26cd05fe962bfad99ca2dc1cbc" },
                { "cak", "d58086e5bc805d8a170646eb29e60f96afa42a2ca355d7925dd7049fceb44dca1118dd344f8333775a41a9c0f590a808ec0e32caedf0ac31bb22599e4374d006" },
                { "cs", "8debde0780634328d0fc9cd1be6fa308ac4235db71eaf8ebada9544e59a733fd17ff4a38a857d48186eadf37e9f3c8801a4c0acfabd15dcb8c0586dc4eacced3" },
                { "cy", "ba45fc554b653bf7ca5bcf8eba7b043c76213d3a3bf6cfe5f632c904f1832ed5d7f02c764fdd37e64d98d5bba548320aa1c0fa02099fc2e9ecc0889df4a6130b" },
                { "da", "0f53841857c9b2b3d9f54d76296e482b8949724c6292953137dff92d410a83229c9427ed76792cc2fc547a65bb12c34220c4c970139f1cff3044c2006ea153f6" },
                { "de", "5037bf25df47abb4826049591c17cbac3e74f6c6a185dbab64a7f0654448a57fada4d3a01bffd386a32dcead1dcf8507d9ff7d3f26dabe645df4a21515e84cbd" },
                { "dsb", "19caad24d7f07ecedffd76dae4deabf02f46edcc014d5464501170a2ea43b33c80bf4a00fbf63171c34e64fbbff7ca8b06c7308b13a5568ee10d11b2fdf1be35" },
                { "el", "7b910d46286febb081d32ecf9b19b13b83e0bebf1a65e57c95c906760ca3054b258effd56e8554527e6a095d00156e1a4f068bd40e8112153c51e351f8ba2956" },
                { "en-CA", "60e07df22eacc7f427aa1886f477127446c1b13d6ae53838f0e701b612ef090dfda53776a5547e6d2a716d7bf38568f9ef88aeee8caf58a8c384ee2378c64013" },
                { "en-GB", "78ec1d2ee16d7ee1fde48a9c5ca293ccd86f56dedf94134bd943419d8bd48925f57da4b9ffd1045f34f2e7ac5c1078ba81ff7614d8add8a902b7637923c91c38" },
                { "en-US", "87fb88a4372af6692fcb1061af479418ccce238548c392e1f971a3eeeb3af5b24d66a5bcc1a7ea060ffcb3b60548e25978609dd4418eab62f29c2e1f03be0acc" },
                { "eo", "c6c34f0345b54fd13c8b24a9d60fad322d4678fe27a881141b15d3940377683ff31bdb139a4c5c991b0044cd12435d9dd8fcbf4a6b578e8e2ecf5de4670e69bc" },
                { "es-AR", "3749893a34f85805576cd0719b717cf89d2133a90e42c6718e46cd812ad8d9e2b08fccbbbc0adad40ac9b779ae908f247b51ca51dd1abceb1f80e5f9247a669e" },
                { "es-CL", "86e3b1a407d26b3a282a69b02f5797cd2aab15080275c8df5e4b9eccf7cb05a661e5951db9ea3207baad535104e5206d32c03900cdbb9bf04cfa90248536c834" },
                { "es-ES", "f87ab4b357c4c0e044868a0b3e5750abfe031aeb0a1af9ff96cb612294036bb3711c79d0e168905e54d401d1c9ebe1761b43a746e34255476818478bf73e4a9c" },
                { "es-MX", "e5f1c9e33d2f3f95de787dda19bc70f80edeee30e36dc1daadfd66a038821dfc33677ba99e8acc5d3a7d24caea877652da4f4ac16e0da7592bb6bc5bdd0e6639" },
                { "et", "a55e6d599a8fe4b7253a4930e8475a9fc216da2cce9a1bc157fc813e5d6c7d27d327143d2d2bbe2024d824a62a1ac71795e2f21ddc684e851181bdf97dfb0e05" },
                { "eu", "18df95a59983f01056ff1b3693fd0d143b060cce62c3fe92973be48c54043b8d295234ddfcce50857a41f93d32f66c48a89f9b6ed3a15eda8ba0b53d2fe97063" },
                { "fa", "b3d875f383f4ff2b5aa65dcb5b0e8cbf62da98b0736922fd8b89ed02d4839798de74a478c869f5617f06884ef3d36e4e5c939fdf121bac029069d1640b46a377" },
                { "ff", "f4f78076d16de4e0195e10265f38c7d60f3cf83e0a62b8ec2247ee65c46e92a36a6077b64ab90825fc33d8f946b48b636496d7470d17cf623bd0eadf4ffd2313" },
                { "fi", "229af75c1422755498c37a6415794eabb834cc049ba76505252aafb231697c95dcad3c6dfce0efdaed6e5d4fedde8f0d1cd7688df82d246f1d9cbe37343f1a0a" },
                { "fr", "0b1b944c21b0c6f00c3c6b1179b9fc676b0f43da5b151776482bdde6f34114dec41c391228927793b42683a207fa96b8d1d2bd3c97547d7b183ce437f6cf6f30" },
                { "fur", "fbe4959e11ae2cba865563fbaa413f4e3c73857fcf0d58c4df2d9d75386a81bb41dc34ea2fe5ffc368be24252fbd469e3ec8eeb34560f708887aed1a3549bef2" },
                { "fy-NL", "d6e12bea5c8955bc8bbb6074233b9fad6b918c4b17f4a2c9063348ffa091497d2679c67583db4a363b65acf53deb0a15f37e97b48db7c1bf0321cdb53ebdd003" },
                { "ga-IE", "e308e7887531927b49943b5abfd38c1d9e1f518829474ac16efc0a3aeaf8cbe3b525675a30399be9def0730497716c0a0c4dab9acdb52aac10ca04ffe4b010e3" },
                { "gd", "98647c515bd7cc5cd9d4cef3b02e0e064e135a4f05df19060657801dc72d90b447ef76670058ebe1e0280cbffcb0e08de9084c9c3bded0a961de137606d65ac1" },
                { "gl", "fd436eb5dcc3f0d2cc5f7ad4d440049bd366b40d15c67445470696640e7ccadf18f0e51d780448feb1eb3acc0abe47bb72a475479fc11c97b3175cca0915f471" },
                { "gn", "49d96a89da46664e3aaa7be28732fc651515b7491dcc2c802062ccfde43c5c6353fdfe09de449d06d4b7fd4f828c6c7920c86d62e8f5e3522f2bb26d70dd9af0" },
                { "gu-IN", "2f570e98f2e206ceb1bed3a7d10bee6598ea3b924e46f84f224b93876b940b0f5fc8ba4a19faf763c3ef8e3961f649a285d22bd572d68b59ff332352ef83a389" },
                { "he", "fa6ed9c52dc308ac9b0aa9f4b50bd7254c919f25372deaf04d40f0b95c32a694d413a8e8aa4f2668b1c5a9254a261d446cbcaf7dce893da293da1b448d3ce6ac" },
                { "hi-IN", "7cba5fec03e525560d033a44167e2b6b406992d91a12c27c54554bc8b0a35c4a915f080f0f63b502c7eb167121827cc40fd6eb27591eacf380ad832bde43642d" },
                { "hr", "a4da46e104067c2eb772ffb802e9197a79ea8c877cbf52dd02d3a89f5de6f9def6920a117aca9596dc76d7f0183bef72662a5eb6d5c784418e452d736dd25d1e" },
                { "hsb", "3685346d91405fb1d22a65e71d3191cdd2c7196c2c99bdf4daf97b81a25e8bd887642e9d0ecba7d4015df5290da7cc63151df7c3abd5a19510155669a7978b1f" },
                { "hu", "e0bf310eceb12b5b1981cf8f4ca1605b89f2e73833ed67347163c3e68716a50d49e34bf55d861826cc96720b92bd4813997c9226d5e463caba8d51201c5e087d" },
                { "hy-AM", "932658abb207561d4919f15433a9a325a186ed7101b6273d7d38a2cd837f42559f487a167e3c42c1fb6a97578eea7c635eac87a3d02c3eb9e7da1e40050588a9" },
                { "ia", "9f84903eeecf49b7cda725608cf692a723862c595c426debb222d85683fe63668bd6ba4561d75db79b7d63c5c831ef78aad0d95c69935d745fabbae00eb5790a" },
                { "id", "32b292698140f5f8b047d94bbd381038d48c414fcb79c8a38234fa119661a38b724fcf769b24ad6c6825689660a00ed56e9c4c8923c6ffa2d2f1bd75336b6c91" },
                { "is", "8ac55c762519254b6667fa6de867ba2b1505b63054b8cbc12ce2e9337b4345363557d8fa4063effd1ce3cdd44f4b3803896048837f179f00ff4a5279ba4bd549" },
                { "it", "203d6ec4327208593dc5c1c36fbf27f55ad633c266e1290b19f2fbbc3a728e697d8557ef75d549f24735a300caae5aba3372c11fcfdc0cf54ba79c36b277fdbb" },
                { "ja", "3ec0aabf53a3380921c81805159631df7830da3658dee8bee88df1b9f3a818a878d3356c20d73bd2eaae618882b42862cee44a929894e5e5ace0001ded382b5b" },
                { "ka", "d6f77d787403654e839eafc9a71e24c5a108eb4e3b98e2d3e6381bc9aedf7955646811cf451629015861545b4440e2cd3ce42d68f7c71cc4818573c0a78dea4c" },
                { "kab", "3495c1c15ba0f28c8859b75e576849d6053a6d5fcc1fc40743967f3cf98ad27b45761801c57dd306a63b68f56392d716c00d92c4879763550dcfff9e03f32e86" },
                { "kk", "0db2de3bb5b5909a54fb246c9d0c54535777552f79410b09af9da888b0cb409cc75ed961bc5cf8ee7111fcfe82bb56c02b950f4511179fb533ad19768941e2c5" },
                { "km", "0c4854c5ed7ffd9c3ec4a4379572622e00dfca831057190e12ffa7e9d35aaede838124a5dc0a49665662523f735a58c70acac6a8e0301051d236bb175f7c5119" },
                { "kn", "aefabd1de5043f6fc8122ab606b716388bbac4af2d784f55ffbc8f259f8c702e3a32dbb5f44a3ee7ae598cbad61b67c0ef2d0fd6a8659d38222f49ce431cb8f6" },
                { "ko", "fadeb87e46cc8a6d2b4ed798ad8992625fde534e97ea604659d34f86d475ed2403c988b1cbe51f5cdd373d990c6872e1f69fdbe62fd9de38ce6b9af697c5cd91" },
                { "lij", "7492e968c0f652c0190941f312e12c0f2a549eec06dd585b7621a185ddb9068a31f54aac895765b1760415941a16228cd8980d14d5e7d790b1b23e1ec854c064" },
                { "lt", "d10bed4ab91cef24fc9f8fe541eda210a4c71438cc69ccaae61df34287b121384009079f944a957fae63977108d65719f39b4d21a703cf1d205d2cb7c2eef9ad" },
                { "lv", "e404c96528295f0fa07a1aa5cf904c120ccea40079e4e6e27f1a0b2f632385421bea01cb1940aecc6084bf748867b9e37a5b0b4adf33215db5f347b6ed18daa3" },
                { "mk", "8361a2e3ce653188d29f8e4385fd6f99668990f647797dcea678c3d555623b22fe37edb51ca384e23c93a74617c106fe92c1b61594a78665f0bd96136ea20f9f" },
                { "mr", "06bffc8436c83d86a727e4585197b8357d31d74b225fb0c5ff5eaf2cbdaf617bbf5357546071e2af7e7bf6916d7aa8f4a8219844b10de5a34c0ceec933e22f5e" },
                { "ms", "36ff4efea9e6c2aa67765dd501c8faa5fdfef210f61ea5e67583cf52f04f3a44a50ba240c2203b6fac28b6f86797511c54c235943e2a287eca16c269743064a0" },
                { "my", "f6600922d2c8c720cffe3acf8b9510ff4d5acede5f62ea2638d702fd3f15dbda9c6a9a8e11cca37a5bd069a6610144aaac17025bebba2d335915c481c675c940" },
                { "nb-NO", "8d2675bf552c1925fa050f3a024de5fb1d1da4d309ae1cf7595c1e97ae775e4ca91ebb5968023424961da988d3dc43ce342032860646daf35536a734d49063bf" },
                { "ne-NP", "f0d5f4b05ec28bd50f51386cdac4960520e2c0e44727dadfa829e249c6e9466a94c6291ac1886b78aca349166d3ca35acb4da8ff6fa2a890eab3094b6ca077b5" },
                { "nl", "38dea6d947612d88f1e093f56eb6cdf107ded42004169a875258dca2ee977f866bcfc14719c9856cad174008e1e7c0317adc6454fce3b78686dcbbc06c7ba1b4" },
                { "nn-NO", "e6bd3881941ce162a56cd99acac6f97da816bc7f40f2cbce9ba9ad3ae49ac81275d844c0686f683ba65bfd14fa4c73622f4682549f699a24bdad44bb9ddd5f92" },
                { "oc", "503162f1a5f8db3ac11ebaed4c84955a737dd3d38e3bcd28b6fc57e7e7d8892ea355576d05b4d1652d696fda45d2676f32cd02828fed9444aeae7c75e59dcd0c" },
                { "pa-IN", "f157e3a933ce8fa8c887b5f70ec97f74dadd46b1213b7164e05f62f6b8d53dbe64dc6619ce88d86bbbdbc4fffeb14d56b60f81743b440674c095effe1622fe74" },
                { "pl", "01ccaa3a98fd99a999bdf37e29a7aa2d7fefac60eebaf394db0678727f1c73366cce23a31f7888f037089e835de065fdb1f7c8b544c2840179d3980d9769661f" },
                { "pt-BR", "ebac2154e6dc71d4258683fa2d354757ac9079bf5867cf5315d38c6df9eb8b1f801fd7220fe4857f7cf4da0422ad4fa4de7a6eabbc2d5cfe4077a30223a86925" },
                { "pt-PT", "eea530edc04fd22bbd93d002a65283f100f80d838a84eb090b86bce57c000886c06260769018b01e788812603cb84a21cf116ef260cdd7d2ae486e00d9bfa05b" },
                { "rm", "0111c55b5b414c136fa52e32e44dcfd4c88eb14716badf41d271a6901a8b0f89980da82cf5728b0b1d025d4b65f1265fb5925e3047ef919da581151856c5d153" },
                { "ro", "395876b92b1bda1d488caafbe82f48713e3976ee7a82e44b588e438b99ede490f7c3b2bd87057a4e757f5dfb669e27d5efaaf42f1cbf94e263b44e3e8b1f77f9" },
                { "ru", "f220306228cb0e73af616f21499239d041c38ca66e68355986b3d0bca88a001609dfeed123f2a0dfddb2dd66415bf2419acbc963ca5a6fa7f0dbfafd278f1c9b" },
                { "sat", "8d7ef49c94cc0d08fe2aca0e3b95aa536fa93a4f34d9a09302ae8fb40d42c1949d3d8a00bf31fdfc0bf44c6166f018246293057f5beaf89ed38c524e5ff4150c" },
                { "sc", "b460ccd337a5eddf16c674078bd687f19e10d5c8ae3ba7940d3f1e80a2a0de183a3a7283e7e0d5b110fbba1df5ae81b7ca12a44b8b1bc6eb019509f8c60abc57" },
                { "sco", "f5727424bcdf3085ed2e6c84de07f6ab65d1873d14747572c9ea51df28971ac9ac8fbe80bb3c54aab946344e2722b25fc14431c342eb0107070d3b646b202afb" },
                { "si", "8cb9b3dab5ea8e284985a9e58913c96151e09f6b63178e5fa5319ee5a5f6554c339cabaa14c829aae57552121170e6bbbb88c23166f4754d013bc32ff01255cb" },
                { "sk", "a5385ebfea70ea12766f6878b69ad8b83e41d8a3cebd9d4c70108d292141f95dc3c52857c502a0581b3601cf57cb8ddeaff2bfa49c7534e599fa37030504bae3" },
                { "sl", "f7e0088bd2759da9de94ab71206fd1c7f38bc322b9fa3bb7b63d93142d609de1a136dd665983b3624227867985a98888d5df5976b7aeeb1661e074d4fc248798" },
                { "son", "643b9d6150b306a3811816e4f26a26b994c6fc07353af5397195fe32d95ed935b287a1c7af9873395e215dafd3e1fd3ca4238cf811c74d5f64ad3761f0eb23bb" },
                { "sq", "3ef6709a026d3e91ddd43854f30fb906f356783d0f72dc43437dea121ba917cb5bf6c9b3b46500bd3bd0134ee3aa151046f622f6810de1dbd36e42ce1670f2f6" },
                { "sr", "c2125f9974cc7c94b86468205d6be7e7b27a128a4aa3b922f3f4b91fc310dd433319f37714615626218c2b66b964ed7cc51fe7d047a6a1cc9a58947fc93666f3" },
                { "sv-SE", "492184fbca9fe9e83be89f0d934806db6c9af699a31da05386ab4dd4c79635e04ef50df33c6801727d381cfad1247d82fa427614a0497347d2458f0c2b92f52b" },
                { "szl", "f24e11b39f3337debf67cc6762d45242df696f8dc2f24883a86d08e2d5b7f0a5d31629426ba94f06e51e7da820bd57d946fc0f265e3ac60d76a74b4e8b161546" },
                { "ta", "4d565419570429374940296ffa2e4d9275b67243e7d858be55e6a044201ad00add77fb2d51ea041ce95b4aa27cd6e9758e2c94cac1f73d09fec2ab3f871372cc" },
                { "te", "89bab66b6b0db766d77a17c221a65c545a609330e086829b3d765b1420295f5254b425b0d87ed5a88606ae14c5ff6bae27018c3f30bc6554a5f1b86d8e6f6721" },
                { "tg", "412f6991ca53e7129a5a81ac53981dba60809fc33b77ccdcf45f4510eb06b40922356fa2dbaac03516798a9236dc0b10d45f9be7246f2f4916941eecdc573a7b" },
                { "th", "ee7a073e2c4175aede45011c6466e03db0e8112c27906ef7f7983c0e743ab408a7173db48d26afb8eaba35809b5f66c111fae6c0f7f6fc6e7ce6275868414bfa" },
                { "tl", "3533de3aa6f99f9a032f2facf09fbe114113c8cbfcb87052ee0bbee0fbee9945efc8d3de753f9cccbed405f1f4c19e35973fe685b190ee345c728b29e12645ef" },
                { "tr", "7d157cbeee5a82fcb7e967eae2505d7a8cc0e1a177c0cbaac784f9458d0ce45676c8246c2fc90293a98a21a0393a258129c93513f5dc5d382e4798ec757a3843" },
                { "trs", "6afb578d5708257d975c246ad03d90ce638ac5333211728ce8b2a1e4fb547b9654a4801d147ffa49871b664da2e3abc60eb816554b5c7c37ff942e7ab49606c3" },
                { "uk", "3881940e154e69c0e7718a901cb98401745c5adae7979075aeb6c2f77cc72929d1c955be4921bf79f63360281d7ba143d45c67cb34ccbe9a87fb4fb8db997450" },
                { "ur", "a0ae9b93460205d0a9be55367804ae519b0c8798b973d30a3e9652b9cb0b1bab977513302bbc4462de531da77cc05b8e0527f7cd584efac39d3f7f861981f88d" },
                { "uz", "869f4f178ddeb36f9ecb5cf0e5b5bc872bd145a2ac5ff668e88c6b93afa616f81e3d73d4aaa3dab22f6e0d36d1a081d26fdad70e4bacec3503177d1baca08aaf" },
                { "vi", "43cc416a88b40294b80a505857ef131d69ff125ac5bd2bdea437dd1724ca660eac22145aa80f25a19873c19e302d8d8a46ba2577f83c03e94b8b35cd5ecfcb6f" },
                { "xh", "02bea049af09de2a9f8602a373033dd84e834d21cae9d5aa48b8ceb169501ffb5f32e801c7704ce09f153f88b9c517f3ff4374251486f9a81c47b38cfed0f0d0" },
                { "zh-CN", "b7cce1ea157897a3e79dd9bb0e271513572a8706ee1038c6872eeaca5ea0b430973340e6dcef165c75706f6d758d7aae58deb13c22b56da12a5978cb2cc578d7" },
                { "zh-TW", "0e15a8790123d8efa692cdd288b2c87a0dbcd1b9c76543f35e1a579c137bfaf924409ecf57af81f1f10af2c32b772a48d84a558114fc4a4c886d6527ab761bf7" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
