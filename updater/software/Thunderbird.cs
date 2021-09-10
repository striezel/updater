/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.1.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "ec06d55cf98f8f44b061a5f27dfa4eb12638d1e20dbee57e406cf95cde177231499fffaf8c5b4e8382e59e6a6b90e2f5b9f1a68dabeeb77352619939a603b481" },
                { "ar", "6edc4c591d7c08c7b2960c72257e185c00eb98df7736ab3dc1390d9ff441240db164cf346d2ddf39604db38cf6a2ff24c338ee7225997555d9fc2a9bc2530020" },
                { "ast", "cad201439f12f122b4385c3b4725714ed79aaf3ca0e7fdd5326bffb9f44e2319de3b812b4efbf56038ad22dfbc420e0c19f98d7554382c252130117ec5c0886d" },
                { "be", "6161e2a757c8b35d9b4e4ca4dd004b08aeb81973a90d198b7758df83911e73b02b9a3e9358c59d3207fb65db5270373b7de2c513df3fce5b204bd2fc9baa6591" },
                { "bg", "6dc6ce8bcd1810604e1cdee6e935ce292d8278b037cd7b524b4bdee6b571f8ba4e454eedfe1f665a01183ff6388a0a93a5163c46310d93fb4aab60973e9c9778" },
                { "br", "6de8979ff048cab0989b5c17740ef12e16de606e40c6afa1e062843af6bd792f755775a367c8ed89568b5e4524ed0449c9510e4efc368a8fc5546c3f1cb05572" },
                { "ca", "5622d20a4008d5e5d77b5a30326c9c58653b75ae6a367b80a31e14891a3e0e167155ce3f7d6cd91bffd4beb043d2a351022a51e8d68d7949385b282b7c7f4c8a" },
                { "cak", "a99eb512d4ef62cee200af77fddb738394f267b14dbdfebe18f2460fff795943c02e3728e78b0a56e48001748a8811e438d534f0e4f85952ba57b9f207c7c48c" },
                { "cs", "d7768d6da3001b6e8efbd98df1b3e6fa7bcb78ee6e6b9c3e5b70993ec29c4972c0e8f048a512cd33dd3a70c3b2bad8da9dce77784f581699c8a4fd4fef88fcc1" },
                { "cy", "1ba1622003ee6686f558162289d0363c7d791adb359dc05eccb6da67ac30486c807b5f8db3b2f4bfa8e47b6e3188137ad329701a8b570a6efb93ce661f25991b" },
                { "da", "cfc8ab9082bfa8156d2eaf64ecb28f0b828f2ba6d81a897d2634bb07eabd816b5fb656ff800c1ba3cda123b25996ee547387f72b23209d9b289cef10cb33a802" },
                { "de", "9108ab24dcfc358939004e4c4031f07cf6effd5ce275355b151a6dc6c1ee4921ebf94164b8bd6cd75904fee60c4bbeaa57bbf5f7a1aa8cd4032c23ac61bcf83d" },
                { "dsb", "936002d362f2c67109d1d8c97afb7dcffad9b7be8c6f24e52e6fa7d86d00e4a0f34f9bdcb09f9929bfbfcdfc11a94def00ad7cae0b2f48a0f86af2af6f1d7da4" },
                { "el", "a65f35d065b9c98c429786e9d1e1dd7d550317d31b754bcc6941fb5e7a4b43e869f8bb050f3236b118e94047885f28a2e37382dd9eeaa66e4fb92416c185eec0" },
                { "en-CA", "cdd5ed7e7e6b1b2c9f3ae0deb3af1e5d9ae68ca4c16d8a9de9372ad5e15705a6e2c4faad5d3cc2cbcc8ae4a1b76859e37f2c90f51023d07be56744b84fdd59c6" },
                { "en-GB", "8b05d270e4c892b7b1fd1923c65505f48db13e9754f53b4a5eb11ce8c22ccac4177101775cbf00c466cc4ab5de5f67083c08b5e5f0f4856bb2011f2aac53f364" },
                { "en-US", "00a53ea5975d7c35b76adb2a0abd18a716b1364d676a96b8f8a6fedbbfacb17c5a80df9c628189f606105d54ed74defd66540c05a681158f93c816c6e221010a" },
                { "es-AR", "c05db8f89a16ebe81055784ce64700b1e438f4b4e1b77a0e895e00bc056a567c446b32e8e89a608b3ab5e1ca684d9618a6d0777eb48ec63c3efbd20a3af83106" },
                { "es-ES", "de533f3e2a0dbb3b5af69c1f853935c34cec11c8d9ef4c266e9b60cd33ad8e9bd234b9d02782f97f608c8756e794a19ff5b084d7e4193c6f892f392622c2857f" },
                { "et", "844265b1c8fde4a3442b73a172b4e295837eda664c8677b9ada0cc9edc2de3da782a2678b7e517b30f9eb1ec549f99f7dd6ede277cc9244e2842897d64755a4e" },
                { "eu", "742eb9b210835beea91202893cc6eb2dcfb2ebe1f98f51636901482f7d9fba215a493852278bdad8a87295d7da24caa21443749e95e1f1ad4a51a8039320a139" },
                { "fi", "be2244a6637a39bfc25422a53dd42afd80488009bd6900222e4b4b9bb8f4d805efbc88913f77bfb4296eb08a05cb55538613cfe5e5be84fbb5ba8883c9cabe9f" },
                { "fr", "74fcd0c7145b7129fbf976f5ae33ab5adb21d3b49e1a631bb854b95a152f5eac44f2bffe26e7b33ddc89aa76d14458848fd7feed78814b683c63a3de7a8f61e3" },
                { "fy-NL", "466e253f3878222fb083d8dfbfaa85fe1c660ded607fa9e0da8bec89cf49fd94cbd604f4037bacb422a4f4d934a1897de4ab23e7e082601c9b3abb273253cfb0" },
                { "ga-IE", "06c8f32042073fbad4210f85d8433e7390e8be5ddfa074482ac82fef7264e70c492e1aaa5562102d2dd8a8d7a377ffa00c8f8053ba0995aa78834b0dafa42b11" },
                { "gd", "64b9d54bee9d059aadc5e98c26d2286f7531feb1315cfa9d7d4b529ffdf957ef8e18305fdb9c9f35f0f3071a2a0026af42f697fdb4a0474fefdfc3fa9e9130f5" },
                { "gl", "c3a14d369014aea74770c5fe5973e67fa32aaa6ba5939f6f6cf5aa42d30d5e9af2de68bed702df80fa68cd53de3c1a2840be6d9eb7076440e0f4b35b28632fbc" },
                { "he", "adfa784f1658bc4884f71d86d97fef6f34f7c8da246f7ec85a857456747b8a7be2a4460ee790d919585da394824fc3a2ce5fdbc68ae6ea579498121bacef32f7" },
                { "hr", "a23bbb53d1cfd9ebe5e76d3feaf8c108fd84e659863757bf43e9a465bd6de5504459138ad5fe4c0bfb138f977f197ae3dd7f075818fcc6a2cd3c9b84d2e3a78b" },
                { "hsb", "36120a307c9ce1386d33b7eee0ec99322cad691cc409ef6187eb902b8a9a86b6f92f5a6f6a83a781915c9a482661d4083c8579abfc4a466634c5703ca36bfd5b" },
                { "hu", "9f13d082031f0e6e47b4a9ecdccc1b67ff7a7e823564531b54eac351a07f700abae78ac236b5ee297144931eeff11a2e0439909fc9aef8f42c2be4a42d0d20aa" },
                { "hy-AM", "c87cd7142a414f183c8cf3d0ac3af5e15d8debd0293767c35acc2154d528fb3dfc0b072a9a5e3516f9b1f12a5b5b9ab96f6a0beb250ab9b388f0547e2387e567" },
                { "id", "4f83fd3eea1bc47cd030187adfc803fa9b71c0d3b412abf26a0ce1f78145c53a1cf9167b100042d85c365e5d2c72712dc7be7192d3fe35dc4e54e4ca58621f35" },
                { "is", "2f64b56cd9fdcd2b8cbeee2f7a2376eac085d43e74c0b284b384d536f661b7e19af5d2722183c63c001a2397a2717b77740540d31cf52aa72092063be38ad7ed" },
                { "it", "7d89fb73e77178d90f92388bfff60026cfda0a3a2f495cadc8d1f1abbc4deaa39e04786c70a915586abbe527e40c67014f84e73a50dd222b0346ec1b3e8d6bfb" },
                { "ja", "e4ceaa91ba97af8f35330771abacaad42d96afb0bd08bd8a55f3731d35f50b4f87b7d5a65decc4925d2d1d8582b3d06ac0a14f4aa371dbeeea3735d0971c8bbe" },
                { "ka", "e8f6bca73ef163683cdbb62195d3bad2d6cc74c97ccce51a1d74b690d703e68ef0c92435929ed439c9fae0fffa1bd9a890931ab2a9267dcb4bf2f40e96a73fe0" },
                { "kab", "95567a7ed3f42fdfc1941123622ed23edcbcb81bedaa08236c83c1a5485411fb7fcd95aac4b647fe556d2eedd353bcfb780639c68359e5d648c5d9b8180d801f" },
                { "kk", "442ab7cfd1d49683ef68511bb4d150adf8e2bfec89f7934110013926fd18da63f5adf5199463d796563ad8f8f50d728f625bab3a5d9cf71ec637e5698f574fd2" },
                { "ko", "ee02d6faa8b28a9d5e807a24c7949bcbb88f03c01cd870f22c00325cd5d39b5bf1d74d12b26419fe8c8cde72a10344e9b4e66245eeb7f6344006a68a2458bdd6" },
                { "lt", "857dd9cc4c5c40756565e7df15e2408f975c585127efa2c89c0305c65318274e48d573a7d04a4a3dab0bed27378c580a70dd254731a97450949b0b6eb132cc48" },
                { "lv", "c9a03953ab5047b8144329f110aa7e8d8bdbb6a028be5651d1440f7a430c92ad85f6a98fbed8b05bf1dd95fc36864031bfcaeab0620850c14f5ba019aff4debc" },
                { "ms", "9985232527b7491ad9cad2fc17d1c3f75973d75277d1df1684600bb910e194eea51cd129f5fbc5e792205e3997c18f3bdef31cad562f8561ffc4fc917f7ca9d3" },
                { "nb-NO", "6166953b178e49b6f9ba51c9cf3d0275079813a10bcee1d1702a8d8e583ce8bfbba9fedc024f0bce98b1f70ab9b4d162ef71c906a5ef3ab6f1146fdfa1626c0c" },
                { "nl", "1ff01e60675dda48ae5105a9806fd8831c27511913eddd8e17fe6654e7a589db6e3c6251f9ec2ded8501b2a4a1bafaa3b8d0176e57cd3f2f4173b436281b5ac3" },
                { "nn-NO", "d10f22852623258c244e9454a2af702143c159c33f111290523716f6f989b7382cc4ffc04e6a95830a8dece11e1c85108866b5b155840750159e746e2221005f" },
                { "pa-IN", "b896a667a64901000d271a1555aff17de42cfc9ab21ee2054da3f08d146706f4d200717980d3f3a2c9cbfab9ccbed98e87de70cdd35811cf31daeb599eb94529" },
                { "pl", "6761d252c60cca24c584c1a0ce85a1e37324b2e0003c5f78535089b97dfc0c730346b4395fc8747a11756a52367fbbd816e0d2dcf9c9154e7ab4724aa13ea8ea" },
                { "pt-BR", "43a32a081ff0f3f7d1a3bc849f68ccfc6b3bde59ac1138decc9552fcf78d0cafb6e6160c73b150c715720e88f21564be2eb46bd39d7e4729189b29fbe9b810ca" },
                { "pt-PT", "756d4a6889b2c1e524b25f3f5cbf727e6904700106e67164d130a2602021b0f731e42c1becd1dc74f99f15224fca543193183e6d026a5245bbaf77eddf82cbc6" },
                { "rm", "6e698b61fdb8ff79c750959ec1736baa6afdee2980c444426b7bc3075f6f7a24e1e079522c515bca06caecb84f43fd125891b57f476b2a042873e6df3b337914" },
                { "ro", "c07ea3af27bcb2a84afb35bb8f9d594f25fd0cde07881cecfdb1e32ffe7d04b7f9846b92128f426df0f6b5d364d31f49b1e61d1c5b1106f77269a6e3aa3f3d6a" },
                { "ru", "c647fdd65610f6a3f96749b3e4609ef611526e7fc8f49d1371987242c8fdb32eb68aa9ba01fa3e3c89298ee437063fc610dd326e5cde756cc09b23ef316ef98e" },
                { "sk", "6c686add776061df50add8ea279adb3617385b108a507f5aec922e8e974fd30ec31045075aee622d79b92714b19bdc2b0fb6fc25331abf840aeeb3f18788a6a1" },
                { "sl", "87b1c5e929633eb692f61530a1771dc6c112939bb5a65b0ab93a7b7cf654c3de86dd7a374a30fc9e1b4f8007127571371bff8b5846c7384a3ae99bb2e3dca87a" },
                { "sq", "af259bb9f9f5f7d6f4d4a079243fa5769e4177265f40e3f5c1c81b90bcdff21aca06f16d377ae9c78fe44d6e1049e66f0930c8df3c20338fb6a90ae50bb98831" },
                { "sr", "7d3512e32b8bf3d2e7ea14dd2ac7b1f577ba1a867144bf4f9230313c1ee840c46a4eb6653a4701a8e28fac103499002ded74f22807c97948a3f25d358faf16a5" },
                { "sv-SE", "da3c832f56f19d912bb07bb21342d0ccf51a0be6000c5256fe65a93e1abd21bea9f661793c98802c11fd387c273e8948a064211dc62bd22e77251515fd382b93" },
                { "th", "7fa579ad9c6bea75198787692c0d85d901fd02363673ad1c55afc69b0a899d9e183082f2d663cf0e49528874dc35c8ea5304627466ae86c625e8f067301d58bf" },
                { "tr", "b3d75ceeda0301d54a6fd969c528cf1cfbe49d3e714ec05b12201bddd1c72369cffd5845171160c92629cfd4d13755c8fcfbd61a4640368bc12f89349298609e" },
                { "uk", "1a1874d9d1a60319c140f9047616ce12f9e07bd88b1c4adb61d57b9d36d39309e609dc570d160b3de497567a006adb7c1628cf526a503cc198110e09ac6d95e8" },
                { "uz", "12f38ba17498ad0856361b4d3bc0eef0321c539562e5ac4883a2454bdec8e22218bf58ff09b0591371d0a0f2e08d0c7b14620f9c85906efbc634b7d1d01d3457" },
                { "vi", "36c28a58d210f75e770d49912bce56da999ed7a489642075557e514fb389fb659e6da217e554f459635f13459cd3c7afc81d5fad75733258611e327baf40335d" },
                { "zh-CN", "d971de378a8af6fbb35fadfca0eebad6beb37877d67268ca4673c39d95922cbcd7840330124d720f3b0b2f0db344d372e97d12602e02bf6af78d1e8ee6b5464e" },
                { "zh-TW", "5812deb7c369b53558646ce03e5bebc18d782cd7fc65b1ee5040a54c916b3f1eca76fff1b96ebdb2a1ca991f9cf5aecc04f12171b817c8511d5fca26ffbf447b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.1.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "cb3efe24c3d84aef80632f850ba516985b0b116b16260e739e9ebcafc849b3728290e46051326dd1deea9adf4b25fbb00e4b5314c9c8b01ae9918a93242ce294" },
                { "ar", "3d2d827f32ee1bffe3c87290b9a739cc0d73f6f0e6e8c01fb0464e8989f27907d89b974f6a76c73a6261c5cfc660d97253c8c103874df0da4d6bc3043359aa54" },
                { "ast", "ff2e0b0f5f5d04f1d24a7a70fff7caca2f33f243ec55441d45b4152cbbeecf3016eb4edd6d1246224c9f7e1a5c5dddb41eedcf86fea950f3670c5d748b5612bc" },
                { "be", "57d1dd234bcd1b54f4cb3f2e2b590ae104796d67bd0f86db7c26e01907a1d686d807ddf2fae909ee0c4e40aebec79fc1240b6410227830fa1daddbb61401fc94" },
                { "bg", "5c893d1be790a3dce6a537f4ca01ed60718dd3c5c9052053afd902df7b000119f370df6d9ddfdd4bf732cdf4225f7083f2d2160a26a429ca733cb20366e543eb" },
                { "br", "a19ee33c34765195d88dc0c40a41791743e1782c39e3906e76036902b74a63d9d4aefaf4a0fd398bf4766715d590eadc1bc25f4d3dfd2bebc96c9ead2d2c1882" },
                { "ca", "2bdd5df7713647d1bb0c5c5ed87917f00d521ec9c3072c7f42c6ecf14cd942f4896598cac852a881464d4446cc04af77e61c11ae617be8a6b124ed491c425463" },
                { "cak", "520fa22dafc4fe9846403b4d2bd55d4df90f87aee6cbed6501ad3de313e86dd91ca83e9a60664810ad7c94630f91f2c7f15ae22c4359efbd12b45ab40b816d59" },
                { "cs", "99e6e0105c17778a4516e283e8a2bb6bc62efc643abcbec70c0ce2a11100ed5e9531e9dd56ecf132e9a29f80cdbdc065233e637988b2fcbdd62ff9d860942d60" },
                { "cy", "2064309da780dc254db54c4cc07f9e8b3abf7d99cb1a361907788dc59b28a35492b0cf891eebdff8a7d84d2802565065fb4ecbab76418dd6897ac7133e128444" },
                { "da", "557d95c42bab5d5a84a9f42792657ae61d18dd2e5fdba513dde2c1be7048bc0829b0abb781fe525f347f03883845443d9d4f589314713d6cbf73db70e55b1a1d" },
                { "de", "1d7e494d034eec02bdd7c34899e1d1cc9144169f86d89625b9281630fdf79bbf6e739f6fff316003b9093580890b81fc5854d7498c125a11398ace896b24e69a" },
                { "dsb", "33af01938da72b5383e6008a668caac387ac8cca760a783530610d0d4685c565e6a86af7ee067a353df61df453938d6fffe9544173c37dcb95e67d826ffe3c85" },
                { "el", "91fb0089914bda1f8d62515efefff4f0538eb50778a7a2da6884e64945a04b5a889503fab596f3bad79130666df608977a279f74d4862c06926ac666c798c5c7" },
                { "en-CA", "96471d28da78f232578e51abd677bc8c4ebb4b880d8e38c0e33d11104b173f2af0e42d99085ff4e6ea29a5c6d3bfe2b2708f5e77a4fd660fe83fba6b30985d83" },
                { "en-GB", "0a7988dc2ebed153c1e23a4ec9cd2d41c76b10f232328d269ce1475878ab7f462c8beed169162b8b7a55d33a365679c416f1418a8bce34427c73faef95f65134" },
                { "en-US", "93c208396b5397a2c0ab27470863539856af08ccf138f07ce81de007bf4cefcdc5ccf69115b9d623686f09a51863fa5a2a7f455d68cbcd342a6567d9d73ded14" },
                { "es-AR", "fd563adb9b35eb430af652b10d1076b1e41d57352aa9b96f0cb077b8e2389e510948b0d81e7f8fa2cabfc574b1930901634104d50b43c7d1352c8d2155fe248f" },
                { "es-ES", "c32a1560d02c4f63c612fef9d59542ec4709bd48130dfc803a036e6d288ffc75879aaee61121b2140f9299d885ca3a3cdfd68da44979013e0635a9e8ec8399e7" },
                { "et", "ad101e2ccd267a174411a138bc7b407604994923a75b7e51e4631690e776c47f19a0fd71453baa5fef779eae1e04a8b398ebbce382406c533a6ec85be24981a6" },
                { "eu", "762709180e0f30fd112bd151fdfbf8870132477d59360ee29add47af4c27dad39892347fca7afec0285ccbf415bcd9be17efcad4ce5504978c7de0e98a0dd9c7" },
                { "fi", "edc73e02ef137531a4fc694f95f5b0dd41ea3c3c8071b191afa748fe1eb4e1a94c5af7595630429cdcffcd6c118fc48f20267299ff02e8553d18a0f48671b43c" },
                { "fr", "2f22ff573706d3046b172c228a99a45736eceff22cd8f54b3348cfa19bc67181c386377beec3ac70dcc4d44eedf8bceb2e7460a81ad1863f2bd8927fb215e771" },
                { "fy-NL", "a70acbf698f2100899b211c7d4c05663f821e7f7a824fe2fa624ff20445517b53a85dea7b0e8f638b61cd79420308dbce82bd7cde7a826e4e36916e8cf7665ba" },
                { "ga-IE", "2942043526ca047d27d83487590f58f87a03ecc9e50151926b743be6f3985bd44e34b1e20d942656ed1dbd1325f8f5598ceab991b6ec056735187e16301c11d7" },
                { "gd", "c6046c2f4238deb68f694657e6192345c3925b56fb2ea9e853d13e83f8d516759326ea45e982283512b49b169af03e5b917b24b65f19b15e0f223830dc9b146d" },
                { "gl", "05bad9817b4f3ca3d61ee38205e14fdd8c3362373003de2740e5361a9284668ba706719d1bd35011b8cdfb9f497a98d2442bfd62f2e748e0c195000318438072" },
                { "he", "978fa9ffa82d4561d7641f90fc6a0e6a2e87c1818d117f267861e22382bb54cb94bb6a9ade18aa30f6194967c62f534cc38942388aa0ce6fc3852f469e987a04" },
                { "hr", "9a3a8ed53c9a0cf8e9c6e854815905bbea3723a9b576c1ab4aede1ccd5cfeb017e844d676752b4e04e25bda2868ca9f3957b93b3247b390cfec6936bc1b13bd0" },
                { "hsb", "2c28eda12c535841fd724d8b253f96d9ccf1f37f97f48085b7fbffd5ac8584f82ef4980c17223fbea26dfc2952dc20d545a6d3cb75bcf5b5b2f5ac82359fe0bb" },
                { "hu", "564af9bc7b1b723d115462b7c441c54f8288231ccedf64a455e18bb761d3b1a8f1fe724721ed977c2c60f98fa254fd202d79fc92e3db014684bbf9505fc449e9" },
                { "hy-AM", "49795f44becf78c16ada4e37e71f019acf6465f583b4f22371d44dc26bd9f4af8ab9895c0e4f6e6ff0977659bef0662418615b646b033b68255cf70b8f7b74d8" },
                { "id", "59a1b4141ac50475b8b0956aba43331be110b67536d63435e434d6f8ed136b7547c5c6084e7b9c3fa1dc6b444bb51720561c7b8ab91eca19d6ea3f99a7ed5c49" },
                { "is", "3053a0b518b27648acf4144a28054d282e9768c4a38ae5adb7af2848bac0889bf67d96fe3e8b4657fbf1a88dfe4f1fdd50e5f748ac9f36617e1190be890b06c7" },
                { "it", "e925f8ff0debff2c6271a93700972fbaa6f37c3003e8a8f696ae68c37e520e6c2feee8a83f42d7f25bdcc05c90caed31400e7f5b0b08194b93065377428858d6" },
                { "ja", "baf32a53a63742b34630d782d1e3a52df27e9d2b2bf77229b610ef014f6f0ac1fe55617f3a069a16e3b4287b1c5a4e53e38c8e743b3ab837c2ac542507ca7a0f" },
                { "ka", "2fb147a92e88ea0600d87f67ab8cc28388eced4d7875c882321c696633c58fdfe7636b3c06617e8af8a033e35374887da0516a670b107b4f64e0d022d0eead0f" },
                { "kab", "dde62bc8b5ad9be17ee6d42b282d2ff1f5180bbf74f7762a0b989609a94dda0cc92f457fd194a19612c9266aae958da2a2330ce550b29487125f8021db6f22e0" },
                { "kk", "1b43b8513fa87bfe5c8b33f6313e10029a3fbaef23203574f50d4d9a401c8faa5846283eff51a80b0cbc26196b356a30a01da067249a9cbe8012208e20323348" },
                { "ko", "f2d760e57035d4f5fd2dd01cf0fc42dc7ef3b3cfc59a05131ac121f3b01531dd460a733c6ee3612719f7abde9b1bc85df79ed4d211739f09456d3f36b17f2b97" },
                { "lt", "0b2ca5838e72b0d2d7fff3ecbbfef0afb1af704dac48ed49d8a4203a693d0f4d95db1dfad00b14897981bae7f5011ddc3cd37f2262b04cbdbdb665c5071cae58" },
                { "lv", "ddc59f3bcb0d366969fa802cd680f444fb8e53c21b8bac8068694e92936249a7e3a223c902df6299d52efeda371e8dea4eb229a0a4e9b097dddbcc2c6ec60609" },
                { "ms", "acb2c48f26d757d23ed8cb472994165edf4becec4f9f7781379a0c67ac5b7ed88d5e3a580c0e0fba6ed8942143806eb4b1f8e8957f819866c56da4d7972b9331" },
                { "nb-NO", "02041961236d57089e90d2877e5e0c7d24eda7416134ec358d77663384699b72961bd5600c5f531e19f6214facee82ace7d556a2706ab66e8f8858bcfc7f56ae" },
                { "nl", "01a08c98cbcd6f7f085579d2d4a193d07b9b76de35198c63d574609ca229e1d1aa0558dd1b150df9f7b7594d91fee6e078aded8ade0c5b5fe42ba197ddf87052" },
                { "nn-NO", "0e4b11d7e9602c4e1d18dba9970d0cc9ada034a8f03830c36afe1e771177120678473c6de2f67ae80a63720f789900997ff965370b3622de94ca5eeaddb1f78e" },
                { "pa-IN", "ab1e7f99354b96a9966d1389bb015263399ab7f5d3cc6219a50045402b00c4d1b0a648abae607b3ca2ff3ef9915145d285a258a91a21206c57e221214d2e977d" },
                { "pl", "51710d510547d3c148bb939b18c565b76a4b776e6b2c31265b75a7f62f71b9ddd0e76a6db722775cf6eccad94c5c173de9db43312d0fb714fa2c64e23c27fbee" },
                { "pt-BR", "f684141bf469280ebf078d1205a42fe5fab04ab35a9ab9c8540458b406015a896f66c2cd1b475d6874fb66251faed52791128209173952591603b9ebd3948c63" },
                { "pt-PT", "82d14a8910cab2260254c9e55b4e3af493952213d4041a3c2fb358e121dde4661adb2c45c41c877bfac2ba1418d98183aec50dac35a33ed51aaeb8210de5833a" },
                { "rm", "e1478df584802a3d678f9529a5c4338d4d004568b63c23ee435fa7c839734cb2ad352e12397689b2dc91a584b6d7b109b8b0ed67a2ef2c85ab1bf01011ce451c" },
                { "ro", "58b2d570c56b71ee2702232eb45fb4ec53580549f3acbfe4b5ba294932abdd082631b7e880c97d0ba4970a9b3739cd3bab7669a2aec45c7758fb43832e23a322" },
                { "ru", "b8e3c2ef7d24014929cdca381507eb9688ba6df141a12797b4c6d82dfa8b3aa4c7f5e7ea1a85f5fabdeb1e5b361686fd0105956f808d186ada7922bc706de7e1" },
                { "sk", "2cc60036d47c749f3d7bf7ae30db2344c2077f281a863a2c62512261ca0a03b3c590fb79c7d9ded407392aaf99a062502f71f53f7e1eb2cf8df21f1ffda6b3cb" },
                { "sl", "977f4fc0f5de3c22a8ab105a33831131c7ed1470930ba7435d0038f8057bb39c3060717e1848e698243cb3bf3cbbc03bc447abe6780f58c2dfc6e06e16d251af" },
                { "sq", "0f6fe100cf4758d3c544785502c6d189290ae680ec7a791f5e53494eb7693c2234110abfc3f698a4b71788dd54ba73577f3e2cb56b98d6e379fb823950e376c6" },
                { "sr", "b23de4727bd1c751b833293b93e54a04390f20675026a5fa9b6633cc3b82cc5c09f83ee3f2b6a4b45dfbe82f145c1bfede3b37ac78f4160d6a8631d615a7cc60" },
                { "sv-SE", "9fc3a4a5c28de975178e3e71321f9f3cdd538a88cdf03648dbc2f9bdf97034b8337b6edd456fb063ad4f03d410ad6c67f746a881402ea2f3acd8e339b967c935" },
                { "th", "7ca08568da601945bd0905775286ef72996159b6f7165875e901fd1ae23031b8eb551bcd8cd4cfae76f0ae11983d52be9b7defd8c180d59698423cc23fbc1dcf" },
                { "tr", "1cbce3ec48406958ffcdc5f1dcfb168d56a1c4d30aad31a24cde115da461b309940e256630c221e540f9a08363b314b0f779c8f3ce30d788468d3455d94a9055" },
                { "uk", "cbad3609fdcafb3e5f2a94b91b78cb433677cdc991a1f3ab571d0ef7df20eaa74103804f30138d66dac869576e98142c3384fcf7dbf9723e7f0c24172c2fa4bd" },
                { "uz", "27268be7dba2e4d7e52841c1ba34b8c0e56ee8c1fdb718f3d1850a075eabc3bb6081dc76729d73551d078f5e5a80fcf7b9f424ad9246cbb842828a722b4e320b" },
                { "vi", "a254bf64a6a5984717f7b9f9170da652672bbf9bea707d60183d85cacbc403649c9d626f629b8599476bc3dcc5d315288a81da146b4d24afe7b6ec41e69c9964" },
                { "zh-CN", "d2698011071a4c4b91914ba2a7ccc69bafd49bc9feee84916a2ba6237684766cf4203aab4ef23b29580bc5191d34ddd800532b1565e22f87604ed55287e954e0" },
                { "zh-TW", "8099d2b8bd5dd36c8b85053c03494132daec64608f6a32e3d603da1e8446850d10df0d208d39dfbb2bfafc79045c46cc61d3ff2b9c23194aadbea099953e603f" }
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
            const string version = "91.1.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
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
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
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
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;

    } // class
} // namespace
