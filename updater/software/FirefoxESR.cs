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
        private const string knownVersion = "153.7.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/153.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c1b502f3f638def134ed3236f7a691b95c7a0e7d6061023fbd06ceee6bd183b860886da8d2f0cc0742d1b559021be20da38dec8768d4257c14018755eeed55a9" },
                { "af", "2261f3f223eead59df67d0091031a3b6bf5d8e369de70ca24dc7f884ced6f662b0d8fa66e994f09587c9921b051f2ce8e175c6d4f79f292e47d67f76954414ee" },
                { "an", "3d0a3d203353ffc2e380a4f158dd27822c8a89e37ece80b7277e231ba1689b3b324afa58107d931415b729fe2082824a347028658d324e40bed9d881ba6efc56" },
                { "ar", "e0754241452fbbc9ec74d5533b5d2deded8633dffd07786f9c8addee008951dd6a9ca45240e5bfab4b67a2715afd7a2e8f6ab3e68826cfda611ef0ca733480d8" },
                { "ast", "649da437f668a9b49e6d6230ffbf748efde76ca8d1274fa3e9afee1bf2b99de0d96d356aeed8e10f53bd9d2b65d1ee95b58d8fc12534697c179b8c6e147bba4f" },
                { "az", "f19f8324193fe0fb108718d14251be9b1ccc319f170dd9bed57e9c4de97412b5524bd2a2b99425602505ede8985cd3b57a1f38bae312df854919b520fbff48a2" },
                { "be", "53bbcdbdaeff0ed25ca04f2cb925e3d9c074a7122d1317f5633c1cf8d2e9cf3202f9f1cc78ecacaf86aaad168a4425e2ee402e8cdfdb938e252c3b48ffbc1e77" },
                { "bg", "5803f2465d2e54b0739cbfd499afd4f71a2a0a0160eacc96666965be884808cc54aef00217401443d7cba3e299cb470b6afd893ef6787928b8f3249388db14b4" },
                { "bn", "369344f44a39831dd90d229bf664d24b035dcb0d3e2b01701117dee7fc8a7f73b05ed0ae154fbb3e25e4200640474c66b931318cb3e80313e0771fc2ac515e97" },
                { "br", "1232dc3726ea660a0c69484514a58037b3786aec86156b593435863be2603eb29d15229974b63513379b907cab6e38df6aaf714af7990a1a505a4ccedcea72e8" },
                { "bs", "a5ead1a05783b342f53b0c85bf7c722f0acffb9d51a747d940878b7c8c0e8ab994c8d90001140da2df22ccf33e953d2ccc59baae7efdc18b7659b25a4e554c0c" },
                { "ca", "0548445397ee8a12806be2b5f3723234e6ff7edc73fbf9c11574b5be9c88a7873c13e700769a4f3216e7bc870c3096f48f867aaecbaff8855aa0b5679ff1e7eb" },
                { "cak", "2ddc6dcc587da912a6da51c7a783d15cfe2d006e82376c4180fde378fb0f5465efd77ebefa9df24a8ef030f979e11f2ad10cc63b76aa400409efc55c655f3967" },
                { "cs", "28e5bff88083d2fb10f16bf02f51055c49e71b23cb8102d9cc1e49d631cb46354b7c3c5e54a5b7294bdf0ebeaec2d1d1512689e2150d1adb88b41c1ff2a8b24e" },
                { "cy", "c0054ea93f3e097840774bcd0a70c118bd5be9bc0210ae0d9c8c407fd4b25c694986ed1d8bf36f23af52ed11f5e28cae33a2b69809539d2ec754764ffde23dea" },
                { "da", "e2cace7d535dca7053742a41678e5c61461b1a275b24f5297a6472b8059a6a72e767a518862fad5d2b1726cec5867cd68b73e55c43c9dc3f3094dd6d811077ef" },
                { "de", "14d00eed5f139eb7743885084dc18dd933a58261792ca602240f5a5081835a5a30342951a6ee745dd8f67022c2544bf719860870fc4a9d07067f00e6f27c9e36" },
                { "dsb", "fb218545bf03b0630257d87375b0286d8daed2caa1db1be0dbf17af2715748b09ac781ef794d7e717b57b8ce33982a5bd21620d0e4273bd631771a1516483dd4" },
                { "el", "cf8512355b8175565fdbad0802e372be7662332cd7676273112fbe8b1bdf07c1adcc1f83526c4d338506736a6ca5052233be99d8a0827026f50d0a9712fa5eed" },
                { "en-CA", "1438f5f5d5dcb445885643923ca31ea793691f95e8eb37861f3a2cde96017f043e5d509bde67a3752bb296274f18d935a05130e15b8f310cf722ea3531d8374a" },
                { "en-GB", "135d24279ef6bf89082f8b7fc4ef5f31fff7682f4b195d97fd3dfef25a855452e70625189e8eadeac72db60bbb1807933cc4856478d15a6e8a47e58e34a03af5" },
                { "en-US", "3ee4d1e65b9a045baf57e751a6fdb617dea7188b4c64d62b2464025de653fa7ca42d6654869d60fe089c8c4721739cf0e4d7ffba065931bacb993d3b70155f04" },
                { "eo", "7fdb6fd362dd335b0812cc91b0f2fd47cf95c695e1b344100dd26c191ed9299213e0c21a673b40b87cead517c7f40ba7acb1cc6c5292467b3ea6b7cbbf38df03" },
                { "es-AR", "6e5d2e63bd3874c65835706d5e63925c7a5b649e85b7881ca9ef5e97c12e1d96a0d95fb6421f94f78a346a50c76b5eea09c8e8ffddc0d3dedbc55e8751bc3dc0" },
                { "es-CL", "0e59b5e6d878a6db7387e04719724d3171f5499664753abb31038309d33c38bcefe9bbc975d64127640e36e07de38346a12c85011410425602ac17e3629252d7" },
                { "es-ES", "8ed32fd20a50101c3822b034068712613c2cbf6be5c157c83c0ac70d81e06a6096371e0370416856bc688c32fbe456eed4fd88ffdb31fadbb9b154497a595100" },
                { "es-MX", "7d277d0437dec0fdc96533055bc43641e4ae53a7153bc6787e8c23495c6553d39249bebe4d5d5f01cf2000083aef7e14c4a333155bdaaebd49123f9dc4aa9450" },
                { "et", "5420f1c4e2cc90e8bb898adae733656ae34d1783582962b1c7d6d7263ea2e6656825105ddfd30b97c26d2fca978f7c89c9fdb837dee07f174a9ff713d730319a" },
                { "eu", "00d0f33eee28c914fb659a4fbe4f1402f5e33a1fa7f02fb081f61d19cb2a07014e045928612e8912e908d6a9e6a6146ed8919b4758872f62f8616747a36c5850" },
                { "fa", "657cc4d9aebf86f87875d2e71873edb28d5f7198060cdb1e7b5f318e8a2485dc250071aa09aee0cf65fdd6cac2564c188aa8362ff91b5e62d48fa91bdc186403" },
                { "ff", "cd393ab37a980a75a54d5ec18a848259392239518a877ffd445402331174ce9492e2c47062a092eaf68400565ad72176cd665b503802dcf866e29759aadd9de6" },
                { "fi", "d48d46ba6fe2b4f79bd36a14bd992c7b7bfd16ec91806b1a56e1b57e5cff75117df3974436f13073a8b049478def55d0d70212f4d873c41d303412ea4c0d574a" },
                { "fr", "df98d4523318b52a8c51c833f80fcec52f778ecf9cbb511e2872392f6dec84fc012d3b18be46c7ad9452738bbf5c2a8fbbe15d5971721f0f7bf6eee428fe8b88" },
                { "fur", "265387f772c2d4df66a7065d8ae046de216cda109a1b92e160abcc46d8cdd2575ff4765a5538594536ed37eae2ba31852d5450c7995fd36bc744a31d5a8a77c5" },
                { "fy-NL", "40119c4c23a98f950750bf8004277b0c9fbe2c321f4c00060785bd71441da5ef83851c3a516d5ab4384155383aa8423997c52ea2eec205c2c0f35313005de77e" },
                { "ga-IE", "72dc7a5762d0ad6ddd4c2548e623da381265d44cc862c46c3f084c74a03f38ebb5fa1a6d3b6044a5f43868e162f50bfde19c1c8825d94f7107f986331b94e77c" },
                { "gd", "e1973fc240f0c792718dded356c9c30aa55d275db1b797f57c9aef976836709b10c17e066b810a0a5279dfa06ea5b2496d525a9ebcadfaebba4569a2f4694e0e" },
                { "gl", "b71152df8dd16cfee81e95439dd19dfff90f84c672aa1831e237108762962943af06372febee30b52997ef27eb8a178a1b25a32fdb061eef0565ff1ad58ab910" },
                { "gn", "f0a575d30ac3aa4ba5224baee0f35cadea2321714525d897241bdf7a773f4caa0006042975be85a1f4aef0299991e78a2ca85de8de60cb6a308d50343f34b803" },
                { "gu-IN", "8f604ed2b950741f376d19fd894897061fbd5b4eb06fa28e26c0023293adfd9d9f9182de9afdc92e05bc76cac130c86017d0a0faf2ccecd5f54ef52de408a162" },
                { "he", "6a42131124c51c534d1243b127447a34eea33865c008cb698f9ca1647a1ee3cb2faf283a9a970f61b06f430392645ba30f5aac2b069c654d8d945b5829032dd5" },
                { "hi-IN", "e6117ac492c726c5ce53cf58162c31053fd4b1734c767ddabe7208c89427292dc4e209afbb18537928fc56af3478e2d70934659f523e3a8b8120cf551d5970cc" },
                { "hr", "b430feaf345799606ecdfa4278a40bd3b7e0d1b95c8d404c03652da6e6f4145f7211fd15a42f0c685553fa03802c861755b0e38486e3fea328cadb83bad2520f" },
                { "hsb", "e18d66b385517e65d40bcb318ae40a63527c92966c19dad8fa9fd65863604d8f64a3be1257136e58f501dd4aebb4e6744f032befeb06f617e4037913c76a0945" },
                { "hu", "de5e15894eb835ea5ed55dc593e59eaa98b16c21fbb576748cae5a187f02a87645b8494319b82e95cf587aa842b7cd09c550f6f7c28f60f5e98f06b490c4e3b0" },
                { "hy-AM", "ab7537ef1c1bf6c85460bf3d7f19a85e8124e6c7f7e23bc7018648155566402a18c540fcf81e095f57d7e6fa363c42d3b72a3a95559a264e1b3a719e47069317" },
                { "ia", "5aa51563e95edb034538920489b731a99454562641d5b5a9c6fd2582f502a2c99ff90fc73009c6279bb36bced6e3f76bd20b72bdd114ac84b46f3f5e2939cd27" },
                { "id", "040793b2b224dd5e9e6ee7991da9d514a72de1cb57a1591d82fa6ba3c56c05930db0f1c76422b9e099e186ccdccb0f71829261a499c88761431ca82e4751dc8b" },
                { "is", "396a5e1e419700364201ba125cf3eb04b29bf1025c98f33e0423525978d3ab9db5a11f227f043eabd2320a54ba58d41453ecde1cc40855fb04de1f20afaac1b2" },
                { "it", "db7247c74a0ca4faa03e90bf5e3a742b3450b371c737d13fb540b4646792b59e4689af5c493f89f0937fe70e92aec89ae9cb0a3c54b58237895946525029541c" },
                { "ja", "13d2381a4e220cfe4931aafb8bacd6b47f3a6ba804337b52d2952db55f7a83c7f8371a754c160c915e39f75caaca41b74e1d5d09ba47324e4ec352c92793a2ec" },
                { "ka", "80ff1d229796a860b8292288b252d7de44843cea91ef17acfb2381efcec78c64885d5dd33f68da4ced8cb513dc3cd027bd7fa8dfd2843269aae0c7ade447b5b0" },
                { "kab", "6d5fa59861b687298719b1333c44449e3aeebe760efc4bb2ab69d7bb3d72543a1a4b04485d8cee37bda0d1529cf5f521055d5adf0e4feec59a1d28203d4fc023" },
                { "kk", "5974306523005fcb820dfedcf5d00a5f865965de1407dfe707bed1acc90c5c9c34b0a6ef60d4210c113ecbe03a5532f40a548e627a854f30209f469363c3d28d" },
                { "km", "d2a696fb7f596b08a5631669d562558f19300d9ff4245b54f307dbc21eaddadf9ceea1ec0fd5bea91bea0692339b40e245f31cc30807dd23cbaec5bc9bac5cc6" },
                { "kn", "7ea43a2ee25d106ff9fcc0c822f7f28ecf874c0c36afab96d1797a6a089da21e36d84f7eda9ce069de55807881bd2fb8d9c2b4adeb8de6a44c709caa110a9a61" },
                { "ko", "225d033b4ec8b9f6ddf237eaca3ed10df900a54709605e3461760929aeda69a9cd565d503e23e337ea288a238ff6822bb406abcbf1ae36f8641ba03ef2424631" },
                { "lij", "8f8da9ec9b0772c6056f497320b988ae6e3ea8402f197f01caced28ec0506ff16424074c98c5abd7340bc9729f088e00c70f3d77d3b599ff051a57df05ac7b21" },
                { "lt", "e5b7806564445ca97064e06fc53cd466409a10f4cfb4d0c3bba1b4b2f09168193aeeb48c76c37b832d28396b36063a92f841e525affa223909db26fde5a3947c" },
                { "lv", "7a36e4f472dd98e9c5d290dd983362d5ed1e630d1d6cc26bd94b4846ccff7885c649d19426ad91d28ff36c200b8d0f2131efb555ed17fd5dcbb3bf62520ae4be" },
                { "mk", "e8c9a61f73d846efba04846dc654c6c6d73d0c045ff8fe3b7eba5dc4f8b6db3fb74245b5520ee5792bb6ecfe411f391679b5d182dac24a7dffd4c9888ba8b76d" },
                { "mr", "67cfb614a2b61fef981d61e9c0e898eac9b4e3cc670ad2f02597dee0dfd836a66eabf64c3b4fdbe1b3465d443d5f5523f466b0e288a7e2d47edd71068756b688" },
                { "ms", "2846c91781d0471c8c3bfa4b7b35493c7e5364a0de3ebbc4869bd7db088cf56f994513a519290007b23eca01dc2c712f3215ff0b0d026f28ff58129299543444" },
                { "my", "964614abd6a3b8b85aad93c9b3e62479b35785ac4ce55ff77f5967a91766f5b864e0d1da9c7ee6927f3d9501bc4ca36d0b697947962eb2e805f8b83b6ec9f78f" },
                { "nb-NO", "b2701c2de9c5df513c15bbaf17365514173d2cefdcf5308cbbed1922eea89f2867656f8fab531a8e032c80978c6aa0ca3ff56851feadef6ecbd3a3b561d5895a" },
                { "ne-NP", "92ef4b8655c0953a969dedd5dd1d87c03682933ca8715d6eadfe6f4847f913a0dd6944da4869947c02d0e943971564d814803ac3a3c8205434c0210d23f148dd" },
                { "nl", "4339d72b9ad018b347c6c509ac5ac4e8fe42bced993a8d188053a17fd4547d62eed830d01881f3af2a21b8f2b24377ddd53663aab9d5555b7a8c40cbd0497bfb" },
                { "nn-NO", "9abe5fdc5b2d7d54dad711003373013ad71c25e62c3405deec1172e7b1e9de2007dd726338e73e4ffbabdc8826e3047d463f9da58af6ecdb10e64c3141f1aa69" },
                { "oc", "5d5630218cbbbc3f2065089cf48f013568c0be997065478443d0b7bcf3292f21ead9cc3a10d218f22327022319eef33275653e9ac0e7ff076532620da1fbf12e" },
                { "pa-IN", "897e54c18c00dbf0dab5650719cf1d6b314922a7b4267ab04fc6810bf261c8c0548094fce5cef93dd8e74682bf55978de207e45fc431fb34bf44cb8325def343" },
                { "pl", "6137214d71cf2071d67ae0682e7b4607d9baa252b8043146eeaa91674e2f6b7dafcf9e28b6e91c0aaf7888281950284dcdc9d94b9607483d92754afae37c113f" },
                { "pt-BR", "81ffe310eb96ee25405c2353d1b38c0b90633dc5d3e1e15c361f5820217780f979efcc98e1870a2673be1761ecba9d972559a194cc291d494c728e9eaa8dbccf" },
                { "pt-PT", "04e7967acd08f2bbb6ec64a19cd1a8051cb8baeea6eef9eee128bcceedc6e019af833921c8eb3e0e3d2a23489d717c8b92e55952f6cec5c4971293d7db7f75de" },
                { "rm", "18940d2dc4c1e2b85f181a25c7dff79a2cd95910894034d8d91cb1a8cb15850c2932c99cbabfcff1e7f1cde2a6045a57a673689e05b37f71a260ed2b51393b01" },
                { "ro", "5b5d2595fe93d7857ca5268af917e4ea64e24f36084aec16af221447b14ba91393ff99f17046ab11ddacdc7f8ec7879fd189e6677ecba283c42a9beaf8698004" },
                { "ru", "6356801bb637f365f4e22015841cf1f42ebc8c7439e924d4dda2580a604782731624c6c63f3ec493a7a22980c795c419c9d996b81630f84f300d7aa05384796a" },
                { "sat", "b73041edc9727d1ff68aba8ce576a7bb170dfe46d11b2c220fa13d074efa18b14a869ba82799d5fb751e40383798429a9284405c967e0fc336eedde13f5a3d0f" },
                { "sc", "999cbedf1fc9b55b93e5150555f297271ca80e8af5766568e81389c2d87b33bdb16fad14f406b4d991c2d56bcccd2138f9676c502b9dccdb61419b0c7bc36219" },
                { "sco", "c8a876b23c09849373a51a4b2acf653de2ec8de1333c5a39c887e0fcc6dba4e8ac926eb8af07d5563989219cc49b7c4b0d033bcb164b80d3447359985211677d" },
                { "si", "fa68d3e504162254f9b3658956e6bea3d472270517618e4bc0a0ed2648ad21ae38798eda28ef0f04b6a6c6885ee26e0e43dd7a2be8bd6be2942bcedb639e1dfa" },
                { "sk", "21d1614beb7eb8a5919a7cb7b0036d876b320671e71f898f2fb6a75ac0aa8ca4bcf5ebcc4c675cb861f02d98aec31480f72aafb32cce8f11da6443fb816b256c" },
                { "skr", "0672050a962c81c98e9416f99580c6a638c33c180c7a1244436ba09f4772fb4111fdaf5fc154c128069e23df677b32764079593a69e73c380d88b5bf22592059" },
                { "sl", "f3c7376cf73b5a368a9b297a3384cf94d18d86b07d2ee6c228ac158bb6d1a8e10b6bea2f69ff0bdd04cbe15997e1e50a2fb2e23aa3ac18b3034ec23d84be913b" },
                { "son", "b0f4ba6e194e22d98789824cde81e5c32a2db7e48337bfb7a4cb98aae85eb5bdb2e1174441f697d1e55a507c052a09c0c54ab43f80359cc169f8dc60b9bd4c50" },
                { "sq", "bd203f3a250a58f5b13bc09778c88c7d98336925408c8852c918b180c2171d708b974ab0d9501cec9610d9ddb8feeac2ae4b9d72da8de2a511a516cc20c4e079" },
                { "sr", "05358498dff357e899458ffe9fb35bbebf0ca0954e266b88b8c7f294c6feaea76ed27537e947f99bd2dfa3511d595cf62f8454aba7305d38c83144cbfd5c9526" },
                { "sv-SE", "f55195a1e24c6287bfcecdc58b5c8e0b8baa03a524493b966ec305a557bc4bb5596eca9b2ec3e7ba702ac7df0010eee772a6d563a8dbd29893f2c23f53b8e705" },
                { "szl", "b916618bde82494e779c92c567fba4164750856cf9a45abe6ea945c3aa70a10a0d8967fc80a80bb8c063a85265b6213df4faa10cd92a18a76668d77b908034dc" },
                { "ta", "737935e85790fcf8adc3b694b3c51dc04b3f389137e47791f91b977ae58bfe183f0dc7d4df0b042e04e8d221e2bff76652f498d07283ea9d898c9d46538d6468" },
                { "te", "13828d6aed19144439e6f6dad60515743bf364fecf6ed21672a4111d21957668be8413c82862e0c36cb6351a2571f2d965203624f069a0d1499903bedf3bd8eb" },
                { "tg", "518f2acec2a5c31e20308e74eb7293d21d84b04cbe73dfa8f040bfc64edf4c6092a2308f3ef18fdcb1a5bc9734a2bbf9f5e1745b090b000389b2c7ca15088984" },
                { "th", "b980907e8003d1079556e255a37223b4fae830f89032a19e6d98ce8ffa66802ff7da0456ba09e6593cd32182e4b79dae121ff60b7242c2b0feca2e948c3c247d" },
                { "tl", "7c71f6e68a3b5d628cf55969a253d7ed80c2caa70f6c7540765ad37338f08bc495445b0a2a69160ef762c952fb7296f83d1cfd44cdcf05217fa8d51a3dc345b3" },
                { "tr", "70012aeba71d2f9a337b9b8d8d9a71a2a5643b97141d951a568156c65f8a4ef8d17fc99fd86f7b2a4fd450a3a402e67ce7440e1db0ee6e40fcd9e589c4e1609c" },
                { "trs", "bf725fe1b447d3283a1648f1d4c746b9b3148bb21ae0f1085073a12ba111479537665f8382aae64bd1241f32eda34167b99955835290eea120d92c200bdbc3d5" },
                { "uk", "252fba2961c1c6459b8c2b1823c6c5ddc1a8afc3396aba10389a54d3d7575962e1d3dcb5bcc3014c2d89ee8c04248eb082cd3e8ead5881a59e362ce276582155" },
                { "ur", "1b333ae250fbff4843609ea9dafff7c970690b3069a87759a2d2e82d608c117614154a81dfe867db2de459925e07663b948efeb34b6024ada8a8ecde51c058c9" },
                { "uz", "8ce608fb33c407ae6d0dad8bce85813b2a1ce8f9fda17dddce292c6a92061fd3dec1bc2b230ee1d7250658637c9a8b8c55d5bf811391745d489518ca51b1c59e" },
                { "vi", "9783c663e1add47794a1a632c057d87ceb79031020683aa2f82a5f4dae094500074fdc242150383117286228fc581f504dad64a24156f193a3edb0c04632018b" },
                { "xh", "d5e7ee381a887786cf1e546cc1f3652577ea6d866bc08d70ea53cf631347a13a4f1d5bce77776b9f2bc5534346619fbdfc2c3da2a429101a49d382f2832d8a92" },
                { "zh-CN", "bece545cdde2ad99d73a8ef179d9f3a85303753ee256b6ca8a12fdceee59609a936012dfcf62a69e568d2aa8318074510aaadc379c2ab753574b01a0d303b997" },
                { "zh-TW", "b9dd348c8044598315934f2c6afed6afd88b4936574a9154250e759d103c832f3082683b1029fbbdd2fd18920707f0f29ebbe357e067ba7c57b0d857271f9ff3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7e752989d9eb3c9d37ba6fc6f80f7c5597673156d4b950c8c3454b0e6277ff92c9a68a1f3f0c3333d409eded930a0288d8191c1301c8584d12dabe45b0cc7383" },
                { "af", "875c6a476067fdbd43191fe7c2d861ed609a883d7763dc092a4345d3ae06c6c080a092a8920a717b705c27fd9edc222d0f8bbd2457e0a39bc57b4ce4fd63276a" },
                { "an", "5a6e7905f9218159f2a90261011da8f0c5e0a510fa1d906b5303f8d2136de6aa6e1e0a90f1baa7c09fbf4395aa80355bfd783eddcd612eacaa043fe166fa5beb" },
                { "ar", "c8c057a7bd7fdda46618e35224f79241c4f7a415321f95182d07d7a077b1a45712412ea92c0c57b5de125c85f26d6b073ff83cf9a545f54127bff57580c36c19" },
                { "ast", "2015e9b1426905a367ca9009fae88faeb5a1ffe3fd2ac6a82ea7387d6bccc1924ec835774d553739ca5c62f1d723cd0d6673f671d100a291227dcb75b293c011" },
                { "az", "e939bf30cf7fe85c7f8fc5e68529361bdf848936df6a08a3640f407e50fabea5645186ee37195307354bbaa95a64528a76c15cb6274ddb014dc040ed286503aa" },
                { "be", "04c016e493577e24e83239452867d4fae26c0d62ac90cb59296e534d4746d93a0d5dd993d96d0f61a02dee1a94a4e4333538a26220748d0f192dd54329c2a173" },
                { "bg", "347f9cce219528b975084ef8d4d101885bbcacefb09dd1db9a75228a2cddd80cda07a51c96e37abdcd8b4f8c1557be7618c31de91fbc83d34fc7646f81381f59" },
                { "bn", "6f6cb969b7c0a30ba00c9f1046a0996e02c27712cf9ef5ae3dbe0ff01cc1dd6a7419452e8d663122df2e694845223df9fa90fc7c1771b9062786c60c9273adf8" },
                { "br", "bd8ff17ce1049377cb09910d73e3ea481f920b9b0db8a7415b816e73da94b6f3ae4b959a593e26f2166eab6fd8271bf3c9a25477aa7dccb581584f8af043f484" },
                { "bs", "6d5125a9b5017943cf528a468fdaec0055e2f1c5512da93d4b156d8cc237e9a0a6f07fe6ee4f6b6b9135e3b5634ad0670ab3174b2edfd033b7fe174523766fd1" },
                { "ca", "b4970cd7c4b7d5f52f597793c06400f1840ef4b8e6ec67aa372acbd6523cdd69c0299372efddf5d7dadacf07f83ff45dbe09346aad14d56875e0c31b1fdea78d" },
                { "cak", "61fcc7f12d2c6b254d054d209e757067af7f38572959bc884d3e88898e9a640fac0844d1cfb4f426dd247246c46c7d34c66229cad2eaf4f971e6b942b5800994" },
                { "cs", "5697d3166eb656ce01d55734543ddedf2e8ee6312db130dc640ea68ecb9fabc76c0a060ecb1bda88d3ad1ccfd4e595beb96487772ad13df741cfd38d194cf147" },
                { "cy", "388483e9d37860722988654868c8e2a035976ad194110b6a7c5ef7dcdb86d2978abc77196a5d3fa4f8fe0660272343c063966b5bb38f0f2f328d3f4b28e79172" },
                { "da", "3825ced772111a25a5ca4e5a2f46b36cc51a963be554939af0a9a60d5e13845be4aecdf51338874b7bc0f6c72d57f47b56524a07eef901e4921d4b1d18d9a83f" },
                { "de", "19ea1507314a41ef9a4ef7b0c8619dcf43a2193b41a086c1d998b21d6872239a4cf713d87a7fbba414b2645409f39e8fa378b2b5505fb979fe1301e036a58cf9" },
                { "dsb", "a5991f9a8a696373e5f049075d82c2c9c5a71fb8b308e613c077474ea0671766e9d2a5ef100ec8e2523990abe339768f33bda8eb90455bf4ca8523c3ad6b5d1e" },
                { "el", "e39a0de5d2291dd990bd33efde366e8777d5dbd956b69dd29c84cf565ef45c2d94b1bf3b4d5131dea674fdb467a5e4c510c0e4ab5072842d3b7050beaa1f4d96" },
                { "en-CA", "5d32880df01a8f4dd29d15a33b6fc0f89b58927706de5c2e3ead6addf8033992aa70f0f793e3fbf1d27ee6fa5bb36138d55d05d447cc5b0b84a6bd0bd3e9c35b" },
                { "en-GB", "a39ed6c6ecf999deee735a763ab26c2847508c77ed2ad65ecce132ab4075a414ee2c277e8899ea438015145013fdca89848c12d9df19c4727af210b40a67436f" },
                { "en-US", "9f67b4965d3a20a6450e229953ee482d24e9df5ea15016bc13c56c6c326420fe3f90777d10b1ab875a37b884e7d7997f958e5e41fd045b0b1d84689319c2f88a" },
                { "eo", "5093caff33741c9a64668b6644bb8d686d612508e934589063870395120e3a9969b454dfa0b4c346ec1015fbc7ffc1f3920d53b539f3b1b36d163e929f33ca4a" },
                { "es-AR", "982a316a4d61566bfcb4c1cc77c2f2f42d8e419db867d5f58f737ce165ae31cb455fa982e216c3e12e17ee427be28f71e56985c8c12c751cb078b3352513e9f7" },
                { "es-CL", "3def4be1937aaa14630b1144b6fc6ef08262decbd71f252ff99444ab9edc1e9cc1159888daef013aa398473d4a1afbda94c5d010a776130d49d337a607d682cc" },
                { "es-ES", "f37f88253e0a88d949c92b4968d1badebd5a87b4556483bf294879b9e9fb896096f2a9111db4319d11963067dee2a78f7f48f86826f19bd4c37e23a9e9becb5b" },
                { "es-MX", "804456239c33a5b9f7e40960917d75a685f35b29060fc758e73cd76787ffe192d5115dcd110e22f557aef0937f4dbf048f08ac467c61b46096f6bdab9fd0a2d2" },
                { "et", "93aa0139453ae6249b116eb10d74eb7c08a01ae5769abdae928d877b0399a80718fa5e7a69e94165ffe7911befcce88e5fcd0d71785ce806c24c9d9b22458acb" },
                { "eu", "794f4bf95fe040cbd12611e5dfce34fe071996cca72b71799fee86bf8ce34d525fd7df4c3d864f34ec84ae33a90d3a2f5c41e4d5c75f4908de64feb515ffbd2d" },
                { "fa", "5c6ca8730b3c74fc197d1f76f4d8cbe7cf9e2d1d046b980b9a2276dc1624e5a137282ac26bb5d9f1bd4039cc873fee6a358c17adc501ba4f0db4f00a58c451de" },
                { "ff", "bf5afbed0a9d553545e00b22d598af8fc6c060591357daab334cac64a04b5155beb26c7c4f49b3ae15e6ea67ffc96a7f70bd75f7d2b65a9a16a40716b7834167" },
                { "fi", "652c83a6d3b1b23d300ad82e9a6801346eef8ac87a2314ebe4b8f17518271002f46640084e324e4764e7f44c26608b229536a3e6bc7d3e2e099c5bd1ee6dcc02" },
                { "fr", "9957865a259b3ba170198af0a6a35f7ff684f31adc0cfd7c11f340c83a5f149f8928ce45f090406f02a36f6a9e92c502c4d623eb5398e49cc8385914568902c6" },
                { "fur", "2d3d3ee9b320eb32de2b34ed9e6c8859c374f5d8f546f2d255fc05c6ff4ff1f68ab93d93c0fc7167e9c290b30bd3a71300209f30a4be57134cc1459723449426" },
                { "fy-NL", "57bc03753711b0e2489a6fb654e7cc5362b8d0b10d1b580aa987db671752013fb97b13563c681c433403b4c3aafa29e7af34ccd368e4c2b370173d742942b00b" },
                { "ga-IE", "36c72b94ece00c27beddf01dbe37e7ef8c83e76db1ce42bbafddd3a9eadee508638bbfe831dab0545b27745d818ba3c0c6fbbe0a386c9cdf09b28f61940cb2a5" },
                { "gd", "2f4be077acf9a1d52a6a632dd6ced4199aabcfe9e1efc6639a73f46a6c8b737f1d9274a91a246d65dfb8b5e571ff0da4ead2e07855cab610a7c3159c7ff593d6" },
                { "gl", "52dab59df8a84447c215b130ff2a813c525ea10a785029fca6b958f25ca46c5ddb146b8470c2ce5795bcedac3bd92eb2b3b458d91bc408ce7d28c8cec2e9f94e" },
                { "gn", "86355af0860e21d9b3ddab625014c1496e2f903673b879b3a199a9a7f43d32b25f0cd25fb42224d254780ccb5fe9a5427292534042fb6e030079ed67b939aa1e" },
                { "gu-IN", "eb3ac233f9504d6f393e68682f6c1923547cb55cf027e6a169627bf4a0bc16f2527374e0a847c9ded9d754d66082a00fc850dc54d743f1394d28bab74a9f4911" },
                { "he", "7e31118da4d868b6d8cc0bb4f050e2c5ec563c671d98ffe6f04df0a747f02b7eda131b82e2b5170c6c6f2207d8e24165578520d750282ba11024a57f7f147f3a" },
                { "hi-IN", "909e9192b0d784cffcf75013f9da7b618ffad837d3f6d911a5f2e124b96c92fff927322a06a1a2946a18283a3e1e4540ab874cbf98ccc3bc339316cc961c475d" },
                { "hr", "95f459148a162bcf2c587e48939b26d554ee8be78fa74389c22ec21465374b2802dc19f447907070e930251dcbbb7be551fb00cd24d2f36d47fc2023390912c6" },
                { "hsb", "898210279b8a9b3cdb99e71d6a70c6c24e51312f9d979601f688c952be55557cfd37c0b5cc930ae989fda63aa47aae1ac37432ce0402eb2760d28bc2e55b139e" },
                { "hu", "fe245ca4090b543a9a53e3bb01af1668f4542ee27912eaf49d4f77d0c74ed4ac40c869f422da6bb3a29cd2e4b539d547a1d141356cfad6f649e74c5ba4e178ce" },
                { "hy-AM", "e507f844193f5238d2ec397044fa4a550174f6a0a45a0f6eacc94e93352556c62e616fe25dcca6c7f40f5737aafb566df52f4b24935dc630472e69617ea13974" },
                { "ia", "bb4498e200bedc089712f162a1fa81a212de0f4bdebcaa834dbc6b94609d404daa1cc702b233dc5c472d2291896fd1e3c704076ab8413718d4e6f977eebb0786" },
                { "id", "f7fcc2fa9cb3b804d1fcaf96df7ccea55dbc9c6b8d5f56224748ce0906628d1235bbbff421f9a42f986b25945279747b1aa3f25828956d06bf6c4437b0b2dca8" },
                { "is", "0d086662438378f27bcefadc924532c63e63f89de98707c9746a95276d963264f63c641ef82c45dfb46e6c9927824176a1405126fb36fd2aac102eb34394f006" },
                { "it", "42e6d433f847fdc84f950fa6673fc9604761585f1c6b7b70dc70c9b3018fca38e5af7cad9522c9c178c124e203a8f2661be8c67cfe1b58accbd4240add05abf0" },
                { "ja", "9c88de8f3be65b4c9efcbf0ad383ba91f9b3daf5c9f5eee9aaf4c96c11ac8877b2c213ffd8f55a74e58c910cf0848b3c1fb8cb406e1acc6f8b1de548fa5a49ad" },
                { "ka", "36b4cf4ce347bc558cb1c8d14063d828c8ed027977f6a38ab226eb979dc76e588f4b079671ddbf5e423410b7cb2418314caf5fb08b592e7beeacae8b2a9e7104" },
                { "kab", "1906e07a9e42cdf7a67c11a3dfe4361a137a40843047b7c5b95d5fc8c2badcf7f021fe5a0eda4ff02a65ded6a6d61608525a031e0992f66da35f73cbb49503db" },
                { "kk", "c2632ecd076779b7734fdc9bc8e7a7ae04532bc56036f17936f9c914f5b8cef2d78e68298edfc3f179f9ae457383cc0fda52645f89c6d08c4efdb41a3aa26751" },
                { "km", "f97ceaa9c70655384c92b576b71a30260bff7ea5aa3c32de75996a93a7d9c13e89025575c84746fb973378b039ac9f6da00a130401df585b0d0fcd7b61544459" },
                { "kn", "83f407c859771999bf2529e49f5b32eff14b03ff20db67642226f4f778603800f34b3426ea823f8e9a7a7fbea3638d6cfb41a9376462709528345b16758328c0" },
                { "ko", "fe6f81e2ac7ec2289957ffc232797bd21f584ebac5395a5e081971faa95df8ecd57c5d08fe94c64135157046d809da1c1b2fb8834bf2234c01485129e38a9178" },
                { "lij", "177a0746df4c9ec19aa2655b45930c138ac2ab08cb0f853ade62f8cce1f9953ddf95a01a5830983f88cac93169a628ec1c0b045b0ba65db1d6b2bc5308be6f96" },
                { "lt", "94ca31fc4d07e7bdb74c45b6ef71130d1868ff7dcbf416d4d01e49bfb68e7bb2b369bc6df921bb7b2c3466d8ca887d84c5b18e47d276fb6efa7538c19f05bcd4" },
                { "lv", "2fa7e14dc97c8a44578c06b0b04f3cd050bd5e5f4a1275f7fc8f4829a7e9b1542f029ea0fe079a3a69767cad587754dfd968f1332c93bc0438ffb8a7b87337b9" },
                { "mk", "a3a12bbf997396c86553f98a95ff6d3e2dae3e51e502613efdfd85a0b15110e41e5db1ea4c2364f01b2a789a59f47ee67f4746eee961a2dca148eef8cdea6081" },
                { "mr", "aaa49a9c1eaf3ca5d36421b8d36b732f3b83c47cee9d22abd8e4c692e483fb50083a7cce96d481d2dd3cb75591d623fc449ce1238f012e0b77939d1ab3aaa498" },
                { "ms", "26376da2ca1215fec0ddd9919a55fae03f0f7365c601f524886df26925744ea78709c18bcbb32148e05cd500356e4944c3b40adf3380f16d4fc1fa717c00825f" },
                { "my", "0dab5862cfc4c52dcf981015514fcd32a932495aec0150c08078d5371601a1076914124cac53839ce12d0fd7d1ce4b8bbf211bca2e30cacbf9f95698d85a3b26" },
                { "nb-NO", "99fd599647b4ef399b81b585dfc3681097541f5e518e9d7ba3789317b42ce7b557a1558e35a46b76306fd007309d5eb384a7f632d95307f6803c49e5b8b9668c" },
                { "ne-NP", "bf7e0ea72d97d8deb89eb276109db3c470fc392cac9384655ee525ee0158f412609b1ae8a8ed6c3d55d354767ea0ed341b0750c018ac3f401e62feec9830ee3a" },
                { "nl", "12a6cf0c3c0e7417c83b24485a6418488e2ca87cf0302bf11bb7fb4ba3804465a621ca71cde360d27d594d83671108c237733f1a62244dfb1bd4cfb2221e9fbc" },
                { "nn-NO", "620f2db94ba1c9109972f339e9f70ee0d4a4e94b704c09bcc90504796f3949609b752447f88677631dadc0a5abf3be8112fd9b962be782dd4b1043636e2a0a9b" },
                { "oc", "21de668a743925c489c2df73934b2412c52c667d0acb5426cc86c74493e527672e7e795ed44bc782aa7da365bbd90e5e842d6a038d015c180435af3818f7f32a" },
                { "pa-IN", "962341546b7f659d3c3a5dc0884e0c59cd306eab4db30da6cb6cc5bebf6af070a8aafdab60227fc5a678fb2586d4d76a9cdfc75daf965108e52660a1f6053332" },
                { "pl", "87fe931783736b752bb835e373eecf5766e300589c12c050ade56d2c1a03cc6fe520548240b74ab4e204d97dd623ba1f1ac0a661b1bb2406b7533614af8b4b7b" },
                { "pt-BR", "b08bdb9cc40d873bb05e559d8df98761cf899e04da478ec1346af66f3f5c65673ad5f61342f91faeb6a74284625ffab390a7ca74617a9c32c09248b8a51a02c7" },
                { "pt-PT", "df1b9591a810ee603f50120724a5874ddb204de795ef2bc7d5a66f322cead87cf589fc266954d432c63fb04780a67659f1b29b7ad008ad0a7f9deb31c726bfca" },
                { "rm", "60bda85148f6fbb954e096cf0e8f2527016870cabdd73c036500557a56bd7b354beafbaab3a09430401a99fe1e90dd01612525e47eb04a9f78a11d51bdc07976" },
                { "ro", "bd38df9a400674206a7a546b3a29640ec019df7d4cf88762e02fbd0f1c54c4e0f3a3ea3512d32d197b25dc0b4fee9a20c8bc9ae46dc2bfb5946e04d7a6b70914" },
                { "ru", "ede7b3f1adaab98554d889b798740c2f047666524eca3bba80991798931c24ee0e19aeb54d7dec2c478f3c6a30c508e4e38b8a7afa845077bd28c49aaee6b06c" },
                { "sat", "40d637d36e4eda7376c585da8117a83db7eb9ba1b00ca7de1ef03891c1a38ac2914404156d52e9aa36fd76195d8023e3eb1ad91df6d663666746f77e4be5defb" },
                { "sc", "351ab5ca359b640a6ba2b619de22f1c76e26255b0986a09ef7ddc17992214fb30ffecb57f0a1b741950833dbdbb7c9f4ef6f2ec81f430fb5f40567e3d9fcbf04" },
                { "sco", "eadd28233b4d4b70dee29b6ef514d7053f7a6acde4049f568c6e89d78fd2b28319dfe44b2570fabc82b698e549277399fec6bbb27902450bd22f1fc80866c6c2" },
                { "si", "9aada0074fa949dde205f81401f983cb86ffca028fa5a117cc27cf7ad0765dc66198a35fdd90e8a418e6cf63320fbc598bf0b92e8ec3d86d5f8b2490252f698e" },
                { "sk", "95457e5e804bcfdfd89167a2ddfc9be271ca84b1775694e148b41b43016c70fd4e780bbb033dc4d98645bb716738b4072cec31eff5402e4b4c9d5866fffaf3e8" },
                { "skr", "f64ce59ebabb64590339169265c82a952a5c593eef0398f780f2827dc5dc018f098f187bb1eaabf7a9b97bf39228e5111b08f7da4d265ff54265e5055e74ece6" },
                { "sl", "03a6f8783550b1238b8b4b63e6c3cad263d659aed51c5e3de8debccf96af5d9d25af44a7b7ffcf4d290f12ed646710c93e703077f6246ab88e6a15356d30a7fc" },
                { "son", "63e8869ccaf23c123051852896f91590728edb3347e3b013b440425dc17770e0bd6a72827da5471a9827d2ed745a5293503dc4449ab8ab4866127d96f9ffa403" },
                { "sq", "d2a66cd3503dd7b78226937babd7d5c84904c1d0943e8c83438ae3c6ed76e050f75f286efe98cd1b18d959f73851e5ca9073e4e43f0434389255b2347f0c22e9" },
                { "sr", "fafcaf7d9a68f0bbe2c65f4bb77b0304553790212c1bf4a50628342c93a5b1d87b75e96cd6eca8e1206793b22d08b0bfebce1e665c6e0efc34d528fe4de9101a" },
                { "sv-SE", "3f6681cd47e2c15968d7e47cd9a5e0990f37dc41d01b998c425a39b820c1eda1752a268d67ac8052d23e8de12adf41cbc1313eb46ec28cc1016891f553855d81" },
                { "szl", "cc65d114c5696ede259a200ccd6368380b1c05ee9f268c09e53abae7df47ef92b08a6e889d8090413526f66102d7332239841115ceae6b58bee0ead6cf7b56b8" },
                { "ta", "42b12781ee0ea9ddf40217fe4f14234be8e8cdbf10f00318bb052fa48c3573c8b16fd61dee271f5ff814323ef9b378459bf1d23ddb0e60e616f4ffb983805c36" },
                { "te", "2682543c57000cd107c6dd931b5e6438f4dcd5752fc9f80722763e068f46e954f04176be710f7d0be6076957a5fc45e3dd8c6a1160459fdc1c64f6c908b3234c" },
                { "tg", "60829622bfda60f902b5fbfb9d4e9efee420cfb449199a8d8d6602f24fa989af7af44b30ea247d24ae891a2414a662fbc2601e7ce49b7f389f7b100934772dc4" },
                { "th", "95cac16076e3caf1c706a9c9bcae3b88c8db5f53125e1fdeb50cfb141e8d4cbd42b665b9310ac08cfa1e1e2a0a3c1178b222373cc1ea9cc5f09efe44443e1a58" },
                { "tl", "a09e6b28b684fcf33df2fd2b946f128c8995232eb8eb4597f8d798016d5afc88096fd1fe2717806a2ccfe19d1c6281da3ec19d7b7c13dc9f95e3f88ea80eae33" },
                { "tr", "312fae98edf6b093ea59ea7389e55a63a092fd797da52bee0f3c990de034059a33c171161ae7cda149b56bcbb9e07501cd9158ae29e9c5f676c731655af16439" },
                { "trs", "0cb46114a396a3322f9d5e6d9c8805f8ed423293018e1a45993b4501c674c3bfe4ff97dad65e1fd55627c50e0e54c0bd1a1ced781f47adfe8f4afc972c60bf1a" },
                { "uk", "1719fbacb74ac5c84c2ca437af2bd0344bffc22d34b7c7b736f964fac020c2814fd12f9e90460fc14c20d550a6b7b2f81160e344e81a5143fa27dceb58dc60b4" },
                { "ur", "69c2e5a1f0087e7be3e30754d4d5a1366933278d85dcfa47236938f0953a3aa1430c50c8cd05088783b9a5ecca2320475ef199ecb68ad39e8f3c75586cd8929e" },
                { "uz", "410f915a012bb9359d00f04ea0daeef2c8624003c2d54472f32f75fa3d9b23c62bb071539b7e608802016cde44c9921e520dc25344f5100ffe0ddacb23c6f98f" },
                { "vi", "40d9ba2fd047955dab7570e9b3eaec4b34dbf012b79bbbb2788ea8caa6fe340972aafc6bccbf8bd927ef3036632c5d5575e17ef7db23de309acba476a797a2c1" },
                { "xh", "f978dca79db91471304e0e64bc3da17208d45a254d4abb5b39da2895f5bd63b26e9f2d98c25dd943ff2861c98202688574b578e498b151e7e583d3229f2b8b29" },
                { "zh-CN", "e3d20ad9663d5c8a0060fc25d6dd48201fa8aed43a8ed0e662d1e5cf055adcd19624b2cbcbfdd77aa33be42684448d7ef012942a3512b394f51ed7f7b700a99e" },
                { "zh-TW", "d7150a2f7667e06beb5d7cce233b6b7a24c520e67f31665dd977353ee9b466cc1d5966eae8becf5bb98541696e9e4067e0c533693465f88b9d303b9663be97ad" }
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
