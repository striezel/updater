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
        private const string knownVersion = "140.7.2";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.7.2esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "95cfc523241dd66ceefd207af765934d7c90dff93de4db942e56a87241c04e7fe5125d6fbc25043f6cdd99e6203ab516caca7ca9a33022a69958b38a6798f6a5" },
                { "ar", "e4c7f89337536e1db7b2d59427e2c2d1827b6bdd8a84ae65d7e4f2c846715e7a96f8369af5d31882f674ffc21c0d309138fef95823a866680c0979d98a88f147" },
                { "ast", "b787c3dacda7504e82a8eb3173a46aee35540eb979a97abb30dcab0e2b5712fe0b6a837808e814cbdabfd0eea650922d31eac1a0d7622ba3e0e2f39f2b653e65" },
                { "be", "e1778e6d3e494a473d36cef28cd977192415d214517b43e58e61fa1b6b31527f541d95f5ab955b44e83e8a517a46a54eeeb3d3100c7fc2830a94bc9808ff185e" },
                { "bg", "66ba6467d5fc9b76abf135a02224dd9dae1580040b8d71b25e0987542b1340fb25b36e34dd28ec4e49ed2c8bda4545b440524b4f2be9d464009f5f149bfbfd0e" },
                { "br", "e2d1fcb111f56d6976b73bb655ea5960b735a5a3f80fbea7cfca873c191243a6243dd4587362b04ef285f49bbc513f31f5534a5269fd7603572c466bce6d0715" },
                { "ca", "b3ad7bd297361fae7e3932370d907d82d625a4c22753b39cd6cf9b331c989a85980e4316bb8267b72f8759c409f5cc512c16494a4457e49c2cf9f5a54e796ef4" },
                { "cak", "6b59b32d2c6b15eb727916da3bf3fde3b09a992da33c8a8318117054d78f25ef4b02792501365274e00ca5941c77fb01fd769c95fd367c40db1cc14d7a4580cd" },
                { "cs", "d43f8dc2178caca607f1eac618ad1f61e8a5ff282f3233a0f951c90dcaac05a53ea33ca0c9b4a2f4d48acb7002b6b74bf5f3f4955cc20f62bd7390842b67b69e" },
                { "cy", "cab7b1cf146965589debd4499bec05ecafaeb58376e8d1d57f1b15edfe09967e073a29fa3313240887d38e681f81e9206a1c72570dc506d10d751d6b5d7bd3cb" },
                { "da", "67ad6aee99f73136df2f64c5e811a03f1e7102f339740211d692788a3136d25537678a9fd917c0e968fcbfc9e68216c39d3e759a56470cd0909511ba9986dcc6" },
                { "de", "a2cf277956100b09c073a0c462d1ad18b91bd0f285952571798a86eb47790fa24b76262d605da2bef3442113e4004043825a01cd5693368686fc42aac8af887d" },
                { "dsb", "af4af250af24f16192e6e758778a8ab5c4f893614f11edad5ac7fb053f0c8e6d143fc028be527200a811dc7ea5eb61fbf66760b4a1d48f08ac3255799a3a1650" },
                { "el", "15f38ef039865904bad700ca06cb632e0310a332a70c855359bfaea7af89fec7b749d427071aa6b433fa3b5d15ef2c7554dd00de455bc7deb2861ff6d1bee062" },
                { "en-CA", "8341b9356743b6ec663b67ae4b934d6f8ce4cc3b17f65d348ae7bb1537f5f44899eeddc636232f38296d06ffe15d1b8f32b154da2815aed2bd2d09e8495d0a5a" },
                { "en-GB", "b8471281513eb7d81f433dcfbbd162ba3f877c09f129001c254f5cb55b25af9c464af36acb974b58893cca422131d1db9189b094dfd276d1566dfd28603b646f" },
                { "en-US", "0fc8c7fdef389b3e0ce3bc73394509e6f89c1545750dbf64526d2fb58d002ab5fb09e9cb5fbeae748d21d5e0511cbe95c13eeb7b47a3a561ddaee20b302f3800" },
                { "es-AR", "42698677f9aa0a64c46d8cddb5c3f7f8f08983bcdd2834e6335611c1eb17fbf65dfdb125d505cd12894afc393f87575c152cb61153f27921e3c17d6a72cb9206" },
                { "es-ES", "b13b6ca2b50f470d789b95220b7fdddd77dc096c571965cfe2978d05195d129cc5acc276e2571214483a8696607cdc12c8ca963e6a60eabc5c05c31dcf6518d3" },
                { "es-MX", "47bc695baa7ceaea02b65035999d1fed5a5a1ce3b41dff56fd07d52ecff8c15e28080ea710a311323dc4a5586f76069703bf3b295a7f97381784a9367c3b5b38" },
                { "et", "dd9b19498624682f960055c260cdf5c1aaa44b60a22b4a309576be17b3fe3a5656e9d282cf398999bc0adc1c75e78d82aaf12f80bcaf6d9b35e628ab3a87db22" },
                { "eu", "32a2b8c3689dfdd73263553fb8e21b7d01edd20640763e8357a4e1ccaaa10fe4fe195bf66479c2c90cda1fb25e9e66b81781c61f78492069e5003f674e0384a3" },
                { "fi", "3b45da4129b43fb0bfdefae69bd337545a2a51580cadcbbb95d8004e4cb7d622c9ab9cef7dd53d8983b08eb6b26ca0e3cc09221e95a701d289ada15389e426f6" },
                { "fr", "ad3214a85036839bb06df6467d55cea830d3bb6b5856d463088e7a2facfad84d7e03eb3dbf581e214cab6e8f953b31eea9c22fb328111feb65fc17a4d6e5da9b" },
                { "fy-NL", "d9b4cf0f3f03db0a72dc2f7c79eb8cfdfd033193d27bb668d65b931bd3276967e5ff2630be19cd82b0f30c275a4345c6c4da0b1cf6ab2375cb7bbcba71892cfa" },
                { "ga-IE", "879b071d4c6a8bcd2e198f3d477fe513d9261e4ff68f3bfe5dd2cd916ff8b04317f080dbc198fab22eb48ee338df9ca69220728db1eb3b7839427ed251178606" },
                { "gd", "691c22338153f190c7edc8c42ab9fa45ec142017d7c4a87b5ecba38f8b970de1ec78d3c1b1a71091b864534d1318f9f7fd4a7eba00de35c65c35c2d03c7f559a" },
                { "gl", "93f14f2bded6fe5bb1128ea2f7271097eea786149a18dfd00865c7cf9ad033db59b95f2bcd8261cfee070c7156c35128378dc040f092839b6709d4278a3d4a17" },
                { "he", "24e2db04547e3d36233353c8e508f8b0e6b43d94b9fc14cfb7565c83f256d1a6a03846a8a08507c0c9b80ce1880b4e052e8448fa5800f584f6f60c154a7ac963" },
                { "hr", "b0a33f62ae0d6814f518a86eaf20f50987357f688d968bae475fce09c762d270b0d55e562bfdff85d013451d464267f1e605eee1a9f1025abf2ef5eb3aa68475" },
                { "hsb", "a6ead73fa52dcb785424ed5c12f6f3e5b1d8ded4df6aa374fc4a0e2650b60d1680f78db0140e9c60dd7da0f6fdccb7b611209ff4c63bb31515a2ae20cd4f8ca5" },
                { "hu", "c3856a7dc74b84c68be25e97e45a54b18955c1f20588c2984c6a1773a4168fa85caea2774f161c382ab7c683df88074fc435a27a7dc007d826fa825924f3658c" },
                { "hy-AM", "2d40d5af8043014fce63fb96da1fc0ee75003be08b47c0294b27c765408747260f237c7f762559fa577242e15b9ea0025281b880a699269493fabbb5263b9f22" },
                { "id", "41ea1d029bf0ab1f6c62bf268d78ee80b73873952960ccdc61cefce5d5fe3301b6f3b9abb66fcd286a057796cddea2f7550e7eee0cbfcce2fd3e1327f08dd079" },
                { "is", "7a21a63f933a55bb4ad4bca7afd1ce6ebba2ca25ba51dac233dd0f0c6ba3026f3f977ca59fe0eea980e4b92986351deb92ab6f55997785e40488875e7587bcd4" },
                { "it", "84a033b5a420fe30fff4e464b220c8d36d7cff42aa27aa4441db8ec752dc09566d9271d3bb4331111bfa64bff4570e9d2a64c1c3093b2ded28e1c2c716add03f" },
                { "ja", "d513cacb383b797e94b71dcf879b1458149f7a6a6ab6f2c2a6f389de3862e26e92e559f108bb6b85a5cdf40cb30dca254a155935f1561b405a8c5b6ff434d938" },
                { "ka", "9e1ed070645208e123d7d99844ccbce777b72cc91bcacd3a6d666d2876d8e6ce421a4315ed065bc45c2ff3d199bf451ede2274befbd24276205adf6d38f6d674" },
                { "kab", "7c1e0779c91cf0d922b73e8cabfa6149047e7a7f32fbf8bd4d446299799e1ce774c0c8bdd15636c6c2adaa6db2850a29f4f0f3032db5dd40ca0913324bc7d022" },
                { "kk", "9ca0862bd3b1de4825198de4ef570a65064d7c8f86781a15eba160e52210518d0f58b97b9d1bf5b6cfc34a015f3c48b2d87fe06f14a5b7d5e38725bdf205a6cf" },
                { "ko", "abdecf8ff577791f8610956a30ffd4df541a7bbbe26e6b9aae62b589aae2b4e957c81fcac635113ee8bd17ab2ff63764ad8bc01fa6fdf7abf9faa9ff1f58bb4e" },
                { "lt", "105a3dcd308cfc4b2b08adad67fb72c7b2a2fe79727a9780569fe1812f5922f8fb549d561d9d966a1588451c4c575ca97106e02be45723c06fae2865cd523542" },
                { "lv", "5820498a07c871c5ae4d06eaa9bcf924a5d9df66e12db53fbbd879cabc0e2ac6b314dafec12424c771456bccfa7868e7be7c748a70be0f84058182d807519902" },
                { "ms", "e9e15c7a5215d4c0591250b448db2dc464e72d1c1d2227407edc0eecec5cad22e6b0782c503230aee719e14d6b38764547944799f29f609ced722c3284864daa" },
                { "nb-NO", "f5483fdf752f00ff4558ccee262f4bb9ee3a9c02813969d0701e64a62774a1315825463811348e33299f94b4915b2a73c7594839387b5fb5cb6e096d4eb5c539" },
                { "nl", "f9de013a89727d17da3fdf40c49e6d7e63c8750db7069a9062f2e58a518249a38fbcf5a965eb1167fbefd9b4dbd209160cf326b8104b72de993e59fddee3f61d" },
                { "nn-NO", "4ed37045c6b26458df3937c95ce3654e2b6d25bf379407d796f6aff699cd65208672b1bdcca626a9a64cd8c396edb578fb72a81caf758bef183ea3f549c92acf" },
                { "pa-IN", "febf0a6ee1f5a83540c625bda5f626c1947aea6bff50362148b2126f15c94b06d511221c479ae8e6e606b01cbee38bd7ad87c8f01646ceeacc2dd26296dd580e" },
                { "pl", "e1dc68e043d656f60cd7200295a005c3553430da1dee8e3162290941619faaea4e513a65e34138d7c7e86b1097f88f3b3c111df4550ebecbdd7d87a1a202dbb9" },
                { "pt-BR", "8b58e82b1a922cfa61d43360ff63c0193f1bc428d055ebfb63edbbbe344689aed206a53c2b3a3ddb658e574da6d0697631b2f9d58ab92abb78c47d24a6aca1cd" },
                { "pt-PT", "b2eeda430ab48389da8215096c9e7f98f1e2f6447a10ab9d169b8d0aec75ec737b57023a6ce5848f6f9914f559f35fb97b4ecc0a6b16180f91a4c1134698f902" },
                { "rm", "2e99d8af3cc857e371621f04ac70e3d2457ee3fbdce9e81052caeebdb89e7786616c32edb402925e607fd8404ee6c2b19317c587de4e2b2163304c8b73c13010" },
                { "ro", "3c1f36490a705abe63ec6c9115056f61f31af71f9218cbd4496dfcb03963a560559e18a2682365ae5570e10e79f9afc606ddf0adf10375f477d5c9bd780bd3d6" },
                { "ru", "e8f66ad6e928d67adefdacdd4ab7bfb3e0838cc842df92e5a76d957594dd5a80e19360648202cd33bab7e3dae711bf4f86fa36058dea45e523cd78027ee864e3" },
                { "sk", "45a23a6ba179246b39e487c779005c6059254f1ff84e6e06373556f1a4a7863359fd93cf3d27af9336676999ff5fa10f5d0d9b58226a92035bbdf805eb6e9983" },
                { "sl", "d7423705783fca8ce5dd66a4fd880721ad5a44e4a1931d6fbe4bd7983ac989f4bcc27e9e30823d1de08e10a1d1e4b8cd9cc19ac5dad6390b494ca49b8025b0b6" },
                { "sq", "13e922e9df4eb7ecc4005d57399b5108952452288c5216d7f0ded0189ea61b2bf22edd35afcb52f34cb4ceb8e33d2382e73584dc909c33e56eed0653709c319e" },
                { "sr", "c04a21048b30e5130ac85056a1d2cd8dc8fab6f3c53b6b31877a5da542349e802823b876e3cd71d20bf36b76b83600e68092c768b754eb38351c04f75457060a" },
                { "sv-SE", "a2ba11d47c6bfbb134aa90193bde226976bc7f620c72383d801b555538c894e8d69dcde695ee17958ccbe03970a5bb33320bb8319ec7520a18588b2e07cb0839" },
                { "th", "d0dabd647b5567e85b4a8dee70db8a685149f2423c6863b51738b79e83b629631b360116579b9971b261f4ed33503931b37c8818f038ce62d8ab9d76e984d916" },
                { "tr", "6da794a29096bfc6b3eb95db5c729247b77c4212f063fd0331923ff59d88d3a2e8fcde9c1e0ec408aac721df9e0c5e84403fd5c687021fbd8fb330007dc162b6" },
                { "uk", "a8bbd1fb321cf3cd4b994ac089be60ea25461908043419587f9ffe5f76f368f4884e77ae1aefebd8210c7398567a9da798727cf952cb4963b514b6e2c648ba7c" },
                { "uz", "b3804da42845b6bc5144411cd2fca7900d898e14008cb7708f67a95cd041635ce79d63ffe7d612f4a09ac02a6fff195fe97a17b0db7be8bbf38e1ae8f9681039" },
                { "vi", "97fe8295a0f43ac52a69a4620698090bab24c21206f452c3c383d9a7220c71a791c97f58fe74d888438555e93743b9b2f6427c96167f630b9c8903588e4f42db" },
                { "zh-CN", "1ae4efd05026f89db21135bd54dd4cbf9de75264bca3069f562c31cb41c4c791a78f12e03146d6438b8f4c70abf17f50428beb2dbf5ce2dbff1b413b95d73003" },
                { "zh-TW", "6950b631ef7ef6d0eafa810d02dcf759b91900e2badcf4f277e4eab71e6fcabef16e4f008f38908c6ce237ad01cac94f15b3967a4f9dd4f85ce3efcfdb085097" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.7.2esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "0270df214762371748b5e0c164ba4227fd8b0dad2012b8deccf351066e3ea2eef118736a7e6c28fcca225060e1b48e88e455d236dd525022901f6ed585521086" },
                { "ar", "9a6a88ef47d37227afbebe041c22991df99ee07d0e20b33c3fcc0ea94b32594a3a42d5f62966fabcc1d4df0e8ddfe533130b345bfacdd3992fb370288add4119" },
                { "ast", "5dfdeaa0aed66ba8ae2aaefba6015a4a483e885b1b73ce08de0a5e6651ac092abda74962f2ba3261a9a475842215a1660fd73dc702a718d293d822f708ad7835" },
                { "be", "21be96c20b56112381705e5a59408d8d5da458004a3c00bff624feb3ea0e94e1f3d30708a5efede707b16ceaf9aa06a7f21ac3332e0ac1847e19ac96f090d833" },
                { "bg", "82b1715adc45286a28d42c9bfa912ec9aa7b91363df2f3941463ca923ecbf30b6bda69f6b34ba0d5316220cb591552cbfb7c96e68dcc6c59a8106c0bffaebb8c" },
                { "br", "daec0ef5d46ad0a65e882c89aad07f4710f86c871af0fc2d4854bb663ffb48114da8390e829c8ea704b894a32ece1bee80d62c9bd78eaf0211fab248972c0f99" },
                { "ca", "837c339f1eb6df0304efa0940b0dbdc96bc06c50ab4513082dc501c6446710ac75e8ad06be92d576e38cd2707982ee6b821f4794e4e949ec8e44951e9e5e2380" },
                { "cak", "b069419cde026c03e90006668dcc5d2db089a5fb6f97a9db48d979288e19a9382bc1ffadf910236f3df9dff549ab5c050bef598f1ff844c17d1ea369ca6935f5" },
                { "cs", "1087e1a87eb7777631fbdd6c3445afa4ceca75699560b863c14e5ccaa1d9d3f8f86baf71a5a7eda86efe197827d7f1b8ba42d73c64259408aa31e26173650a9f" },
                { "cy", "8dea966ab9b7c8df677e2be22d55d40c748c85b6562c732aa311c81218027bb5c93c1e8edc3941597ae00e0790d69f66aa1c24aaa036f5c41eac59e4887ee014" },
                { "da", "bb1d0c22f328e36c9c0649374d95a1fee2844fafccd43a3972db46043211f1f69bb9c03efb124d9607e4f447aeaebb16388f5b1d4282a2eadabe0ee39610373a" },
                { "de", "0a64e6e74e0f5bae696b850f2370413bcd9cf57f1b893336b3b91e4611fbc6d0a8f59eb3b46e236e7d2abefb8f5ad94c4d2cbc7b39bb18880181795ff696c15d" },
                { "dsb", "9aca65ce45e691df6fa5354f645230a241cf267aabc3406c34208b904d531f1a682937f7c1e3e005ac6bafa9d66d86a6bcd1e73e0bf548a0c438a9082d3a3b50" },
                { "el", "5e12dae063d67fe81259c3a0ec1d4659d1a4a79064b178a97e224f0e16ffddccea9e318a9bf8ac7f154de4d42fd5f2d953d9bc88158ab556a022b49306c05376" },
                { "en-CA", "8676f1d34e55c238d2ae5cd2498f9aa1364cdfab8e6a4067805143ab9dd5325f0b5099bce16b271ded75e58822cf6a1857f77f2638f8ec46a3d680673dbc4d2b" },
                { "en-GB", "17cc5bb5b1d0582bbde7ebb3e03ab04867a46adf24f24bc279ab136d15d9b5a603739dd573aaac1b5f0d68f9d6e9763230f36d6b61ed5ac4553932a0e6734d8f" },
                { "en-US", "8e2430664394aac870dbe66c5818a48c3415c587b3a6f8a5d6c8177d7cc8722d7d815ebd5ad154d3551e61d4707cf5c4a7c682540a43f0745750cf190b0b5e2c" },
                { "es-AR", "9df40de9ee57f72b0a4a759c8c8208aaf2b8ad9ffcdedea3625c703e08bc9db1283d581b8a78bf5666cc082575301d50287793eaaa90c7d216216e6cb534908d" },
                { "es-ES", "af492efb18e9524c8c2fdbac5fd4743c5d7706f11884732500aa7e26c3864f956d17b7b6b46f6c0652a6966fff2944eaeaaa64da08198d21ab30ad1bf7fed1e9" },
                { "es-MX", "0ff45a00f0dd4ff70321b3d5cec04dad2d1453b544f4ce0f8b4f40cd63147323c6c98dee99edd7bb41c1fb3fbc8a318be8f96abe6bccf2a5219e6c21e3812525" },
                { "et", "47215b35baf4250249cd66d09e0fae68904889ffa45eafe0ad3ffa5ad43a7b4a2cf143e792a5a4c4eed20f2c06e8fba6f842f0ea7f2b9c375453833a7d7cdf90" },
                { "eu", "ca02788fd6fac34819136ea89bc02d7240bd78d258b9e19c6aefc9eb603c8a5b5f610db27de6f40e767a37528cdaa634ee916c43612a6366e076b69c38eaa91e" },
                { "fi", "d72a57a88a1217790abf398f6a46a85421a75772833081c3b89f8c7541a0b7f9eb4041b94a7fdea79d201b6cbf7d66eedeb34b2c426d1c7b0446d2893200a23d" },
                { "fr", "18391daf1d562421e9fa18f3390e46711e6036014476862a73def7998825610dc8ebec50190df8783ea60799cffa15fe4db63b9c83e5377016d4bfe4fddcb769" },
                { "fy-NL", "2a80fff5e8e8c56cede279a017140f43c2e91b1928b800ec99847108777c4e363bb34e4e8329af1c8ed1f41c776fb86bc2aaa5f6de9881b191ccafb996bfbd6e" },
                { "ga-IE", "ddc66f4d5b2ddb92709b9088323b6d83c13cd9b9cd2c52a701ba375c2391cd259a83133b95d9c6bde6986f96285207b7ef1ba2f54ea91e9b33d20001585a231d" },
                { "gd", "ed27a1269274a58b91209a6908c644281bcab52bc5ce2687cc4a994c7bc1e81403d1590e98ad17f6f8112ad68bbb0e5c296971bc003f2c52390154ecc6696ab3" },
                { "gl", "2221eef89518f6a32290ef0db9b5adef4eb07dcadb5ccacca2bbe12b88662eda6d7a2c34a0d0488c89a4cb06084f191d4a7f66fd49880cdbd973b47f5727bdbc" },
                { "he", "0f471280d87812ff176733459c2e904ce673fa515e2b09fe5aa016df606e9cc0604a581d0a8b51e26fffdd08cd451adcaab25dab057890cf6837c9e7cd37d115" },
                { "hr", "5bcec4e22fb80c2e06651113838ff1f8ae2c0e521954d237b1e05f4f89d3a31ead440848a213a6cae10c385f4ecc5aeddbc0f79bc56e175bfa1a399556cd2e5d" },
                { "hsb", "5d59e1fadac05474f342ac961f5b8f3338c50159da91d129cfcfe2c5beecc0338b5d3a6fefbc5acb24af6fd4375c4ba791c1b9563822212e57f18957a3de232b" },
                { "hu", "b7eae0147774a50a1c364ca70bd71ab5bd7d6e42572892bde8442ccdb7dbe5e783a90599929a34177cfc3bb80befface9b9035d67b87b746ab7a1f0c2633354f" },
                { "hy-AM", "948872e7ec7fdabe6e06f3c7d915a66e9b0f98119916995b1516e26cc3b18bb33289bac5da72906a1a218b90098bbfdb57ec78d8a3b4ae1a00e882e50554268c" },
                { "id", "10673d046db50d8aa1edff8fdf648d99c11440c867f9a0d6a0294cce49c6f5eedd36bff9535d23e6b0a29b78d392784928122940344f7b9511708c56adb269c9" },
                { "is", "99dc45527a43891f0fec5366af883f1ce5350d6bb5978af78fd47eb8f8863b8290badf4f461edb795c447525df08b74128cb4a0df0a4df7b2c63a8286110e0da" },
                { "it", "dc7de7a216bff6dd8f39fa83a1dd57bac1ebad4d1c2bf9410ad87a0a26f64543564bdfe90f7edf39c250a9dc150be905f194ac068cd156bc94e513c18f6a9e9e" },
                { "ja", "d195219db22e656d1b7e9bb5af15c98a80396264c6516cbfba3be87239d05f65742e948ad13e72763b25bb403a2eeadd48482224ba41b4ff80539afb59ad3346" },
                { "ka", "e84e82ef03d0f6ec43428dbf44cfbbcb2cebf7b7930370feec2050f3afa9de5aecfd5fcc9905b28afbc5f4ea7b80be0020f982e53e10c621a6294cb7065cb9a5" },
                { "kab", "6907978eb192d2e9e84b2d3427c9e6af25da857c17e3eb2bbfe9513f82f5d1d9b37fb4c9ab4fd3b42616e42fa224ecd8cac363511b4a9e5dbf9603ad697c4129" },
                { "kk", "2a1dd81174071ad9b3aab6ad5a1de9c703e6ee3053efa83498a2a8f218eca057db9f03ad08f6012044cdefaee4bd29359e720dff4dd717559de3ed5b976d02bb" },
                { "ko", "5d0523890a4f4485445057acc90c1cb2188eb916848c40efe264b45d6ad7bbd176234cc8a08d4beb554c83f98fc6de317afd464e28532cbd0bf16ea416e035df" },
                { "lt", "c79c7e6f10f51f734d0414e2f882698136e682010c44c94ac811db799972c5a49574bfa92ee4885b44d562a90a17b89218e76227d031e4d1cd27cb8be0c6239a" },
                { "lv", "1d3000675aa00cea71d1f444649bce688f2175e9ca0a293bdeb04ab418747f0806932b4b4b1a6c00da084091299eb2ee97c4a706db8da759a909073bec4aeacf" },
                { "ms", "ecfa7a5f94729206f36e7ab2c54688a9e8322cb83b23086b11f6b586b5fc719a15b6c1db65c278cf98c4468e751723ec520f3a0a2d6c3ef7707f0766c4a8c3c1" },
                { "nb-NO", "ad3cd9b0a64866051090efe2d97a5eb649871e7feebf164b61226e81760efa5032e7482a8d084634e2a1b157fe4911005542d701dc24b775cb153ce0f9322d1a" },
                { "nl", "07c615abfa6493b9c5d42f06e2e9ed51c844f760975e3d3f030a9d8b117c9956097dcdbebae40041639f9afdc80155650ca443f6ba78a1b7ff76d0a64051b5af" },
                { "nn-NO", "1c121069d786e1cf81ce5e9009f8222f4af59292ce7cdc64708d210832d6da86c697a012ee03cf463c770b57bf981253b2dfe37bef5e153663b2f3083ae68ba8" },
                { "pa-IN", "3c9ee70b53a59a2d1db99a246df9f8f2bcbb9f7468bc48761485cb525c44ae86bd681009da69d07f955f8958b2f1bb3c97840ec79c2dd3db10c04b767dc57a96" },
                { "pl", "719871bd2a5507241a8e0c1f13ee71e5ca9bf639ba72c28b0821b71dd1557578145d27bea0e206d6dad76892d2626b184552f862692332d7a0a41509d75bb5a2" },
                { "pt-BR", "b6a25b7150632ff5ca640a6c889fc7ea371c972847b51d34bf47ebfd8c46867a8243d08d85cf7defde3d22ee0b6fc1d630322e12ab093998063e87b7d96ad1e7" },
                { "pt-PT", "894faca301f94cbd6b56e1ce323cf5b6fd659962e9889939d6f7690ae0178fad65e6d17c1eb5a58847104b76b1c63b2e65ace4e7fc680af0646a37838382a8f7" },
                { "rm", "b30526bbff0bbe780a4c68f2b6b8e3a99decccf2490e09c61e87092f4123f77641d40c567f26352f3604af3bdb1c13f7b0180fa04467c3aabfee61582cea12bf" },
                { "ro", "9287beb686b119434fc385732536673394673814328698738af9404fd8247ca28e0904a66afbdda9e2eb0408796e7a74ba91ab4d4d3b0455342d3cf7a49e45ff" },
                { "ru", "bfd1b9470832ea97abfd1c2cd4e80f4b25de7d5cab8ac2c1984cb53028ee364d7597feaa030c6d59e87feef1158bdaf9ffe8ac1eda0b4f1e7cc625a0f8b7534b" },
                { "sk", "37328d1bf326135b84d807896b0d4966295bbf2a640f9083a1505943c629cc8343c59c9d3f5188d5f8ef4fd581678bd65e4d8e78875a242a6ea2ee102cde94ec" },
                { "sl", "0547f4e96896c0c7cdeeb1976ffe1ff265b1aec6025dfa3a52fccc9ebd49a3116664b248755277e6a92b8f28e59682063b8d2f072de2c677f4953e1cc74c8d11" },
                { "sq", "a4ecf7722842c8381f584da873cd6104c20407c1e05afa045955641ba19f77473125f598a33215ca9764df293d8ac69916009a33077d212c83dfae340e1140a8" },
                { "sr", "baa034b504edcfce0fdd8f2da39f3853fde86028116aa170332794a4d4f7062ffcf4b3cfa6316a80af79e64b34f8ecb234f1108e42f8ed79377a8a0440103a97" },
                { "sv-SE", "16002377cb59e6a39a310ede6e1c35d8c1853f21a0af064721296cf6f3efbdeb58da817789fb4ad6e964875825528bbfea34e9fa5ac93ada96eac4026f92e985" },
                { "th", "b41a7053a0393e05cfb1bc2fe2f7b036527cc92b4d39d621b0371234aa28d9b0b4091889ee66a51a76b9d82ef33d13e79cfc7a46023ac360f8832c4fb7d537cb" },
                { "tr", "095c090eaf25b1da10b64d1f6845ac4e4bd19c2acfe23de0af0d43acf83b67d9b0b3eccae6e9b32b2c1b80f9315f652caf13b69185d86bf9b9aa255a5fc65a9c" },
                { "uk", "972add2eff6c718f56d6b27b4e25e34bbac432cc6a5d50e8df374164c26cb7ffeee1312457c5a0ae49f4952d501544946cc01b4e7ee5a447b836ad6c89bed1d5" },
                { "uz", "aacd8de486cfabde68d30e25926d7a67e6ef979a72203fa2ee59c2a6863892dcc7d6b45845efe6e2a68d06aaa059c42c2eecadda208933294bdf83fd101cc974" },
                { "vi", "e75379ce521e95b978562b5f71d9535cd84cda1642f19616f998a2fc816af11cfb25fafa6c36f40f236cee43db5b9d707a794baff13c58df6573942673a3da2b" },
                { "zh-CN", "79ff0e06c16cbdf6393c744c315c6fb7f8da1896919e40fc07d2e4c3aee4c79c6e27de5078a08bf2fd1c30110f5cd591f046d2d3a029bd8139330075b6f2dd67" },
                { "zh-TW", "fd27d8f79b6b127a16bec3934b32d2715c57a4fc2019d67103cc025637971b4efdcf2900885dbde13c004711144c638c77eb9dd2cd8bb6d3357186cc33d3819b" }
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
