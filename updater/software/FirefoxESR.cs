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
        private const string knownVersion = "153.6.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/153.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e7043effe34eb0ac0ae5c5ebc25090b04a9019fe6911d9dbf8c30f85c91ce2e91e8c1ef1afebe1923f7ee65ff776fbe035ce2f15c58dd28021c324f94f5d5ad4" },
                { "af", "8b0e943e5e5972bcdf860bbe9ff6f4cff83fddf9f66e60a5c33ea01bd9ae7993fa1d25d20292a84d71670edcb71b13574cf8161845fa0235cae5bdd6623ebafa" },
                { "an", "8250a847df0f0740c492f49f99befcacaf1962ee5254a9ae214e7aace8ecbf5921232c7cef7a08cc29fb57ae2779eb4978da5c688501bb9f4e97fc61017fb90b" },
                { "ar", "71a5aea61734af267e869522119b6345ff0ba005464946ea8b07e5c8f514ddc121a6a166c4f369c8712efe829faf1e7291a726fda5d57a45767fd7d5d79a8e29" },
                { "ast", "a85b915ffc9113d82c4297b49aaabc636734434984bf4549ac3e3d145a1664f9385ec5ee9545369434284e0e4703c25ce24e85d4f949231e6d41e57ce8992c7e" },
                { "az", "eeef52bc7ef2f39c49c2e41b75e1b103a2b142d159510e10d7dc0aa3a7ca60fd928f4496d167b40e45729ff164ed735117bf7d05b85b26527d654f4de7c73397" },
                { "be", "9a55fdcf3885fafee1c755aee0063a052d47714208fac5f4ccc420a2e443a921971b46e76daadebd5c675a544be974f06ecb65a4ed0a52add92008d517df2049" },
                { "bg", "d3539d5853c63009eba0e563b82e50113f9db76ddc67dfb4ddecab8cdefd8e3fc2d13ccf765c909de8825b96fafa57da365bbd37c8220a52825c5cb9ba23487b" },
                { "bn", "0c258c4b9ec4b6e5976dcac2e714f6189104ecfbe85e07e9bb47cc501b4f8dc2db134f5f85656cb19e4702ee7d2b09449bbdc9c09e9f4e78b1d5274f0c6fb135" },
                { "br", "5e0fd2250c8abcd8f2b18cec3fd86e732b466d5c02114c69c6d849998e520e12db7018f2211dec72fb7f652ab634a5e8598e4a144b262e5fd4cfeea5b74b4198" },
                { "bs", "0a354b584b27214ca32f1f107dea7581ba844474b6063493650e8c231a811667a4cac200e69a589ee34fc90ae47005265276dde2e86d60e60ac2f8b99741180e" },
                { "ca", "3e09612682da6dec37a41ea0cb7ddf3d5c117247457f6f0beca4bfef5f0e80f6216a657db1c7e7c39140a44aab9da57e4c91625723576f7e58e1eaef1211c7cb" },
                { "cak", "a973345b38b0979fdfe6a90db6785811b50aedb7d2b32fed493d6e4ae940a0a80691965fc57df3857f64775cec7971f3d5349baa63f710e17b366edb72beca11" },
                { "cs", "44adf71b40a0ac0b227e00e0fe6d5445e463bf8c5d441866691a3b7c2189dc2a3170c9e2a5675616c60e2339b3e528086aae2ae7a986db28ae476bbd5f1117c2" },
                { "cy", "55fff9d22f39bb51c57e8774b1ba34bb691dc81a7bd325fda4cdce6b383a40d78557adebc6176d2a4cb999e4cf5d3474eff3811bcc44b1a07ef2c35717a8e5e6" },
                { "da", "c41dac244679c99db1e034061b5cc0e16cebf2540770d84c1c8b5e2c30452b491157f4cfa4e543b4a82626e922838b5a378e84cf30dbd760246a9c429dfdbe83" },
                { "de", "3a1fa8ebdb8ac807bddcad24b35778a5a1004b33f228dbcdeef65d19d19e5f865e48b0e9627598223cf8507eafb9bea08e5441127059161f2b03478707f942c0" },
                { "dsb", "9d108dbb58274a75cbb4e1e5c9babcb6b015db539631a2f285fbcced14e534ae1672c68367d5ac466acc3a993e904b2540c09fefbea038e7901141c14f0f3ea8" },
                { "el", "cc4be84a533d13a6935342158e07fa766020ab2e1595f08f15629c69b0bf678c89a5bafe18952dcadd989d51505a2eb44c4e61ed7ac918098a88633734654967" },
                { "en-CA", "42180f963fd0b5c5a1975071c1fa40a588fae55af8db9bc5eb4aa677af76bee3675036f3fedc7808d0bb9c926e94aea5117c401dc53522df103742ee096f60b8" },
                { "en-GB", "eea9a6ba742a777afc9428064032751af42a7b9428ee1617956e69eb66258c0940348aabd4eb09c6d695930fe0cb9cd7e1626d0945e30747b8c20df1771934a3" },
                { "en-US", "04515dcdaa6b2bba2bebc9f5b2bad5ff303530933b3ab583c7666201924009567ef3401609c6c888e3720034a7aa5d539e2f57891e35fcb87aa024c38fd3a7bd" },
                { "eo", "8f63cd82d65dc1bcecc6719300d17132ce4b48de380769e2b4bf269b9d0bf89f023379c444d1b0987cca655c14049f9a91b1649a22d2b0608fc1414454271065" },
                { "es-AR", "f9e330895317bf791ff6079263bc5ea8c35bff26d8398667a9f14b11bf066680984c7f306fc9a76e4a8b2ff1242a20afcdfd061c7942a5a7b41d6f9f4a14b78f" },
                { "es-CL", "25844fd0cce6143d7e694880e90847585e8267af0427a435e23e53b8d65d7d2c129a09511f9625d329700880407a3b59101d7e31481cf67de5ecf2c6f1a15ac2" },
                { "es-ES", "2dd56e3b01b008955516fde1d39f9f40e08b0e13d90852da2bdad8f662d3f0cd6bd924302c729ce630c74906d88b1ced601591a02ab7ae0aa4719d18cd4e321d" },
                { "es-MX", "496b14d1298297d2e84ee4baf2a870a9880f18b22090f5a761f0db883ffe0e864c04d2c9056eef66a7aba99ddc318b7e8f8fd7a3219a9320174ef01a0049b3d1" },
                { "et", "28e6937541cf926057944889d4e8363836f77fff924df25c52a640dbc40495c39226761e6513009904d0ff48ba66a70730bf5c90e795e575278c78e7175f6029" },
                { "eu", "fe28f327bc4bfbb19247d2bb6b6a0e53cd04a6a9962ed14f561e78130c886275842ff10e3356e98c11974efafcfd31795763f4b58bd5baf04bd64029cca444ce" },
                { "fa", "b0b4ae16bdc475002a7c3e3225c559598aadc833089c86510329402567131b055e2a37c606496537cf86b119789f90c5578fb76fd595753474e1e312f44d1539" },
                { "ff", "aec0d7fc6e8b62c48e2bc2958a24ee715ac3d66619b989707f62f3fa5625087f7e56ee99f7fc1769f429410479dcb8f9a096a831f16d2965e42a02b3f5ba7ced" },
                { "fi", "fa1adcc55c901388d537ed4f84ca1ed3014121011c5316049dfc529a968503597ac62bd328f0aaa384f721a58dd2e9ed62518612816f8b0a40049e806d6ac743" },
                { "fr", "40ee5e1f95c1a4459e30287ab4c335f633ccde822b0c20c498d5acf134db8fb01841af95b6626836e1571f8299ca5b812374cd14f1b829396b13136f9ac2d9b9" },
                { "fur", "45ca20966563d741d1855b9c9ca01fd7a6f4dafe4d3d87628314bd061e2ce9fbb6dde303ed0048325fec189e28a2352e0946a87d9ebc5b7dcf51e70243ef6794" },
                { "fy-NL", "324cf656b4a61e7b38120080c90838ae4a2c0774ecc28010dce0dd6b4d58b9385c36a8286992cf5280526214a8e719ddc690907a38aa5df0c9d456551e8aea44" },
                { "ga-IE", "f95425adc74f15aa09d1acd1f79dd25d36d8e8f5ee3a373557d9a831461909060cd820a3037872c60599910772d45416b6972eea12618b07ba7f700b8c8ffd03" },
                { "gd", "37060b6afb81d13875194199c697d7585e0aad2f2b23e1f35d280069f81255b5b9af117d8c35d370565df940e3167862df6137c221efc7538088393468643c91" },
                { "gl", "1714a0d95931d3dd64ced94d8e04a2fa65d1f768f95998db056c6a12a8ec5729bb8d1b203ee73ce1d0eb97246782f78f6f283715fdef27057c6f904f75df76d8" },
                { "gn", "d42d43d2295792c9bc0a10133030621458c7c7ab5d4707c2bf6bfe5cd9c334ed7b8905c59afdf951025d52f03fdddc6dc6436505cfb25df4c05ebe765b29baff" },
                { "gu-IN", "a4cb5b54ff6a943fbf9d25dd7ffc439c5fc9d70c477ec3f5c104dc7970ac4d51b2ba1d448e6a2fb12f1757273d56e32017ba923059084d464dffe7786dca34dc" },
                { "he", "1717fe0d82f02175dd89372bfe47b354b88a047c71cb50bc42463260d74ce13b334ada2078c3fab6bed717e5fe8a9fe0a2f8fbb9970ba448184a7d42dfc4677c" },
                { "hi-IN", "10db3602a85df346ad73ea25ddff7f8fbbaacd9ca6c4b8adeee904b92ef27c0702faa1885c332578fe305142e5bee102393a3e30c199f8c96ae94506dad7f181" },
                { "hr", "af936ca4506a364949a9d50fa5827e5691e67de8eec36415f221b70997057b8815411c5e19c91292f8a37f5f038d678033ea461bd452356eb82eacd83aae767d" },
                { "hsb", "93623ade823f2585fb2ad040144b566d2e658dba6cd7c5f7ad6634aebc9ce06cd924fcf0d5b0e88a887bb1060aa011feef8a66372d4dc684ad53c6c4974a8826" },
                { "hu", "83b40936c5b2c8bafcb0c85365a4ab2f794773a7d914521acc9e3a3084ccbe041061b90b71978361c7ed3f307f70e958f93def604e5de44ad6dadcff411dc7cd" },
                { "hy-AM", "b024a2b08975f4642b1a79daa6650e23eea0c78b13510bc4c56fa6c5362afd4adf21cd2b45b6b533c647c813941f3349ca5c179a904816dbdf35638c645c9683" },
                { "ia", "dc2c0d53886693fb6d4ead4c9c709c1a8b7cc247f75e4f933f3aa57b2ddfaf95d7ecfb42500356f4c81c10c48f0af6da3c6299b92fc55af440f3e0a4b2455790" },
                { "id", "beec026dac2c9de973697808aab4f040a135f3706e8db0494e2d17ce3dc99eb553d848905a3663c7a255dfb26a3064f1e554f3966bb02e620b8b30a0d3ea1ae1" },
                { "is", "de48b2013f0bde581a910b1701eb9a4cda2376a7dbf24ab69fe04d60b88aac0bdde75c9ddf53823ade8376225c256cb755e7e039fd58e51ee6745f5d14f15c0c" },
                { "it", "4acbf954dbba89df31aed25f52cb318abf2821e6295268708ea1c84054b1d6214bc2e6a7cc635051d6e32650cd51b025ac6f682f06a2760b38a995bfdf85ff34" },
                { "ja", "a57212f46f0dc64ad3cd351694b1a93776fbf30ee405d1c03b9fca3d54a56a6d62245e9cd5dc6335b79368db151dfc0a8db0ba87f2bbeaf3dd4a6da5dd8f0df6" },
                { "ka", "8ebb5044e1350a60667b20d21e99383353f36c8eed78d4926b99b91dae806747c8f1332ea93e318bc4db261cce31245271e25959592d3aab8f675fc5dd2d5cd2" },
                { "kab", "6ddb2a1dd93171926e0c46d7003dc6cf72e44c96a1f66f394d09d1839e813fdecc9a75b454d4d48b98aa2b1a2aacd9a44d15c139d322d4ca0431526aff2a6b4e" },
                { "kk", "d041106434545def198f9c0f3953d026f9c321e352adc6ce5ebf9335d57d1636a3d46223157b8b1d22f9cc3a701b0fbf95381fec44d65deb433d1c8ff03f42fe" },
                { "km", "6d2eb7e7bb7d53048b4b87298ccc175cb3503704c0e937a954c63462f9539029faca7dc3d68207b9478f9c01b6c81130f1aa65918fe1cf806fb47a5356000778" },
                { "kn", "8beb616486015c8312da1ad0280df9127e0d2eb54f7771cfc8c230564e21fe309b8a3b95fa528a029d126a22cda570c851483970529d0d08a7ba1deafded5fb9" },
                { "ko", "ad87c0aff503457044b5e1b3f9fd04ab4483f7ade6be9a175f5f46774fb1c5940cf7be422222932248cb60e72b763e6176a9ed0d22a52db4372a958dc233e2dd" },
                { "lij", "ef78c355bf6dafdd842d8bbd2472f5efc0341c2aa973b827cb669506278578ea96b44ac284b39628b1a181d2ed9d52f319039b2b7aea0cc3803f6f9747e9dd3e" },
                { "lt", "15b2b2b8fd2af63def5bf3472d488be93ade26f28a519370149d52fdb6d15b1aba133e66f02cba93f0dc033e0f1f703fb25a183751c51613f12656901d83bc46" },
                { "lv", "1155b966d60e52129b9f1cde0c9e539e070979f8dedd43b9cebe4dec682ce72d240a447b7d9c4a1e54e036dc3ac54725b31311de569c7a19aec9fcea9ccc2da0" },
                { "mk", "bc6d7c548b4c9ddd435e65b328f8660d36a59f68c35398845b2cb8ed2c4a9f3192d8321017b0c7fa34fa869281c6f9fbe45ab0be2faee27e783a06c5a12f1a30" },
                { "mr", "3eec083f02abdf1423d69587cffe8942eb7fdd09cda90018f80dadc741d65f457dd9db5fe37941e59c1b09f6d6affcf03dfc8b723f3a527849bd03ad6c019d5b" },
                { "ms", "b935216de2737349034849ec0fcd15754c7a03ea0e99b584191f37a165cfe1c58a7d39bb66f93237e66e8f7ec67d96d89ee407814392f5b0decfdfd99443d815" },
                { "my", "6cadd7ffe89f487beafb40b757e3c9c88e7d52f75b961b7dbece7fd44209dae8ecccbcaaf8e837fb43aa66b9c31a44b2888fc2d6894a46ef60395e3bc7098c7d" },
                { "nb-NO", "6d825ada0e73fb26127804ce71156dc79af1bc65ea8db131613029f661bfb4d5d9033a28a1bd9a38fc6b337b038f366a4c5b095d76ebb7eb77872cf8fb380796" },
                { "ne-NP", "8b020c53db35336ee6c9e80fcd4fe2eb9c8cc0e4b8983f9bd0edd155e0de6cfeb2438b48cb4e9c40adc60f1fc29c65bf78438bab1d4edfac0f4cd92a47c26165" },
                { "nl", "00c1c5d13abfabb71f3a2a34ec6a7a513760a9a6547cb6ad1dc756eede53f16deda64d03fd694867240c74fcd2085f4a101c986c4e47fdd1260a5c0c81c7a375" },
                { "nn-NO", "3704199a1b412388d4d8e905e8379ad7115a23ccf1b718470a08dc1af98b15f76cd64067e138df10dfbf42bf3f227920030125536e2d5f2c0d8914189e94b10c" },
                { "oc", "aa4ecbe1adda6b2b164b6727d0607e06fde96f712d1d6e8a7291ec5a3fe00d15c6541642af77abae459ac40dbde5886d6448866e52bd932f5bb9c1e5860525fb" },
                { "pa-IN", "a467bf259f2729c834cc90e23b882f41679deb6a9690c42b240fc2a5a48cfd2195be6bbbffeec22c4741834bfe238ab65c812163c1ca8f8f169f8d57a52a7e39" },
                { "pl", "67cac6b9657f83f635dc29f4b3af72a7263c20259caee9b4f8e0bb6c97ea390433bc1d2ddce1005b946027f63c2694a12cc5d93038b032e89b70e4f5984a741e" },
                { "pt-BR", "098ceba798feda571037e264ae5853496b7f94833602a29b48a96dcf6b26446df8765365208832959e2ddb061d03ee5f23a2be5eb454ef4a3b1442edf34b4025" },
                { "pt-PT", "e1991520af3a2ce227eec0bcb01f191e179bac05ac0f8307027a62d8aeef57d7161dbf4a372d9528c8176570f9f49587ccef83d1059bfcf8ecc8deb886ad56c9" },
                { "rm", "3096c558573d59848c06a52949249bd8b62501ecb5da12dda70f7f3a13fc66b1a5f940428163609860e8d481286bcf8429020381aa3e5e26efde57bc08ada6b4" },
                { "ro", "8cc574de7865d826f499c723aa34ac01fe0156874d78a42eb26c3b12f1bee54751c1a0ecd70f446967a63bf25c8691448608e7b4bc5b32093c8b47500b3f3150" },
                { "ru", "41adb3af6a17a547d8179a09c77c665f320df97deace9e8cd24d1465e9a49031572fae0d75999841e3f095c8fb7de4475a11d45557af7dcac4598ad52073d058" },
                { "sat", "a480decc94ab25e61387e73be66334cb8e656b1ed298ded2dce496981c46d095e12bf2f8cdf27765b0dd2764d6d3b7a8916e5491ce065004e007af41c8d28689" },
                { "sc", "823e56c4ea8d7bddabc04a814c001520f5ad7755162f110bb9d2c8cbc8cec986fa1004dd46e1e6449354d3976f5509cb6aa7c5071bbb8cabd590d071c7d64972" },
                { "sco", "e851f754409fe5e91b8f780900a07800a1c632482fabf1b8c18023c319b8356337406456c7332a2ad6ca18de5e71c04c70b64bbf18d30067add53dade21162a0" },
                { "si", "9c5ce40835085e887dfa5e0ae1dc498b91f79c9232d806497e60a43908719b4735d56343d18e35a3c6ffa7493556f6a9a5a4eeb21a9dac1aa5aa6b4dbc37f8d6" },
                { "sk", "e51069ca34a796e7e8a4503ce76ba51533b35189e8dd5aa27c84248d0d5f6940963584e24b5ce06639c8664ed9a8ecc7208e0eda0dd447594d7c90cc74dc83c8" },
                { "skr", "2dd76b66116a6a6bf29047c38558b6899b1303b48aca78aabf1c82e5b16b38987d355ae6529893b9ca916aa768ae6dc511a912a61f2914591ea34bfb468df574" },
                { "sl", "996642407a711e37ef15807a096392bfa293231988468bb98497412be0c81114c5cdff17399b8d4d450b7e8997c7a28ff06ebb57e367eb1316d306ca9a5ebffc" },
                { "son", "983ad4d93c6f70b5743a32212fa03d2d63fa18e3d6549f423617be7a056ce9afc161ae3583dc70ee8d808f5b7840350cf1a08e350533fb1e5fab99b9d8b81221" },
                { "sq", "8f67e1d1039a66d1e96f2817b415f665c9075675a8e383c84847ab7a5ba78d23309355d0a93c7404d277fb2cdac3fc9cfd9d1cf23e4feca4035b5940d62cc2ad" },
                { "sr", "9bf4b7a00fe93ac2b9995aa0e5c5ce529492953c8c8dbe5140f290f6bb363ecd6e3d5e5a8bad6c2567d5ac03f6d090abb1ef77cc816bd85021489d49278d237d" },
                { "sv-SE", "a605aa54d58b08d751519965b4be24feec51bf094f500b749a1c7e40f86f9300ef2e0897b134a6c8fc538cd47b63571bb6be288838e15bfb18dfec6f51fc847f" },
                { "szl", "f1885103da27c8d098b8a4bc6ddd885cdb1dda63911c8b6204d47a79e9e664bf1b3baa704a64f328d40cd8dadeb9e3c52b958094c1a6d9d5be6d11035524891e" },
                { "ta", "3e049a89e901c6b20fa5c14e2ae2986909311e838b55ee28b60d6df2b4abf3f6f7ae668636c4c6ac0ca26d0648699f261ad92c45ebac8083f69ba1e538e5a103" },
                { "te", "3994225af113bd36acdc953fa2cd8a16b05721d438a18b2578ac601f8d95734d6b2bb38262b2a673c371847dab16fe17f9db9f6a62d67dedf566e4622f6765d1" },
                { "tg", "2f59911392f071cc2b86254ffe05e52f2792e633858da000f2dec39e35bc64ae0bd320ed40c538dfa98d9c153957e89c88f070cae84ed7a98f26a2a4b40c1a7c" },
                { "th", "ab542ffefe634d3bab12cd726f7aa4566ca6991f3d3574d61b1d9ab6eb066b55ce7d162ffdd4f341eae1d39b1e8065c9f36d0c9cac30123a1f5770094a437909" },
                { "tl", "e865aecdeab6729d8687a83bf4be2fd145a14d1dc8be82748750173e42c2899721f648dfcdbb2fe2edd45cef4a93572db4c8a0600d0ef2a2d1f0eb728fa8cc06" },
                { "tr", "bbc68cb1ffbad74e1bef58818913048bcd71f3760ae7b0438169f98d041a9abfb9554d2a8bbb6972bab90dc87b60cc0cd492a3a7dc4dce7e367995e8a57f0d46" },
                { "trs", "0e5abd2c32fef5a5ee886ae53083e5efe85cd297bf83e885e863f420b835d2b48a32322f701d6b2e53ccea01ff84bc24fd255dbec5f703064991adbfa58fec66" },
                { "uk", "62573895bfeb6a4e025a1e8e37958152a3c0aa908f4d058507d1553bfa0fe77a7de203d8b1d17a5505afe65fcef289b00275c104b3e4368dd5d3c0b8a198cc17" },
                { "ur", "366cb1e1cd708c5674f93f74ad5f9fd1003eb7854ca68928c1989f49d00cd0c29fcc582ec90225b81531d4535eae07091b9b950a8961a0ab379afd5cebd3a71b" },
                { "uz", "6024fafbeb5d3800b4bce4a29b9b57faaabe09e78aa9e1e52d8823a9ed1d520cc47fa6d8f560608b3784d6b44955342c9a6b713910983d0655503bb064f1b109" },
                { "vi", "f3e9f99640604e1e54b1d39d7806d90cbf24a2cd733ae9a3c3e13cabbe15d87369fac255eb4f81ee4bd417db7bde62ca3fd46e28dd8eed905c7af9c871ab03c8" },
                { "xh", "4f30184421ac77ae52da511420e519dca227547f3d8191193ae13e57096ba248ca5635acfc5c9e36d7ecdb494a8b3136846af7b67272faa8c31c8afe387e609e" },
                { "zh-CN", "f3d015b74e5906089cc925cee9dc551d9635f91f9052f3811ec574bf0c759d81a0c76297c224746df8667668e110f3f95cc86e2f3ee0ea82c8220b1dfe0b090f" },
                { "zh-TW", "52e4e1196eace5b0676857c88be7e8489090427f778f0b7fa1eeda595aa3dcbb48e7dcd23201dbf448e8a3787c9a78ec1150788e004eba85c51ce55d7d63b8a5" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9d79226d36382cf67c06421499ef5797e76f5fae1da785ef04a3ef747e5946932096f90e8a7a0588e2644b1b53b23537849dc942863f99813850ca4f4813fbde" },
                { "af", "00e1bfb7a636c438386757a18d52ca9f89d1a177d413352e5b789a2c4bd6bb35ff95be53e4ba2fd600d3290a745253270d2d1168500171b3f95e636fcbb336ee" },
                { "an", "3c513fe4d3731c8d3b512f8017b2a04a4b0b18cb7d21527d67c546c1d5319cf9c2c3dc6f7d852ff38c992329fcfcbf5812181d714172718d5fb671d724296c71" },
                { "ar", "5ea9e169563fec0a1ca10fa87a5a1e0e338f9945af816af8c447f0612148f8aa63967da3e8b37c40652cf0dc22291afebd4380b6fd35889e5dfcdabfafe65174" },
                { "ast", "79ca45af0d5bb74135aa646e42d871d91d0e1559b2c915863ea745029aecf68abaeb5b0b175975406aeea93d68c489c6cff76bb55497b6cc194b90985379427c" },
                { "az", "6b4aaa29b8cbfa642e5670ecd97a6cc1aca3d79c25fb7aff08970002f02fd624d5352c73d10d82e93003b9b75c66616dff39eb08a314b64ee01c886fee2af0d4" },
                { "be", "8eb0ec36984df92eb30d960a46abd3edc0eacb94bf4ba1512d14173e38ec5a5a6ea8c67f3d15cbcf531cdc56bcd1d2345928e5739ad75615b6ed7e5512c3b6b1" },
                { "bg", "33206cffd13b368489782a41404b43787ef474e47f86b17a8da92d8eb14f3b71a97b4d35929f7bd5b028d52733bb68a35689fa7953643a13ac063605339567ef" },
                { "bn", "e498533dc38ad675a898216202a97589b45dc92ef974cfee9abcd2129196f656054bbe738f3883cb7d0aa7ed9ce80ee5c233ab5fc614fab9bff506c952ee1b9f" },
                { "br", "68b67e7046b5959e153554bcb37d5713ee87ef082cee7e85a02095469a6a982aeb87f3af809e74cd80e36a6807f5d10ddde5a2b57210cafd02ec246f6dd04301" },
                { "bs", "85a3c63b54f38a58ce701e2093c2abb9f6935f2aeb004c3b2753a390f132c7cd34356d52b02b3ab8ee2a1a4cb87d429ac21b3be4366ba6b6e17481925e41e700" },
                { "ca", "dac7ef42b441b0e79ef53b422a19b2160565dc15edefdc9bbee330f3071fc251f38fd95cca19213c9fe3a030faf170d8b35568166d48ca21c2a5d527a7aab817" },
                { "cak", "74870d1998bf6c07d1db05c896395deedd4c0bbd4779ea5b23fff464da19e453c1a09842aef382c3c978a44caf159a6ac91fd2d82fba69419fab3be7df9e8d17" },
                { "cs", "5f7a308ebcc9d14c8e84fce83b6855ff5f6f1fd180d66e84bc716edd8c945eb767988a38740495d524b31c05c47dec722d3c5ea00c24eb363d61e2359630eef6" },
                { "cy", "7e1df3b88a0a517364c849ddc223b78c896fcf22a568651d74e429bccae5d4567bcaccd5caaddb61f05fcdaaf542371cbc80553754f7dd446abac3bc75e494ad" },
                { "da", "8ca113c061a99f92cfa0d45990663ee4942347f2f6eaf741ceecc19dead03e10ee5650b66c86e7783057afe0f1175bcd8fbc5a38bf95236301f9509f92ab10cb" },
                { "de", "a457bfafabf625b5439b30fb6f5ee1009ebaac3d1625f519c685abcefaa227b5820751c77c06a9157d0872d74ff2d97748af6a403a096d3a16707c46667e9fed" },
                { "dsb", "9cd89761781cd5261ee67f4c2c35205dcbd251c41c7dce708f1305f2265cd4ada39e36ac6e3795fc460412f1f9fba2e2892300a928c04873721fae55dc26573a" },
                { "el", "8ce1bcb853cc054e6089290e94447a5d279a2d893f860504bb49fd53bb08e4e9528e08af77a59d2b37643f8b34669439d60ecb01d3f4c4d1f7643cb0df32c8bb" },
                { "en-CA", "0107238d71a3dc2cdcaed46393ae6b4c8a2dd3c7d107524f0cfa2cb8f8431163b8c2ae9f67dc5bf77cec466786e4d9d4067f665ff6332e54bcc81855feeefab2" },
                { "en-GB", "a2f73b265ef4183c0c39efbffd4d0e2d554faca9a68f2070fb0b9c63cd916580c2076739f21dca14e065ae41a32f1d9ffae8a2fecfe02d504f970e0a44e7f99a" },
                { "en-US", "d6d73183ae947775bb93f95879a88d6d60b1f64276c36997bfd472097d1945a94d902b95c2174fd63181e6f6bcbb6695843cd3c711118201f23dcbba46fae1e4" },
                { "eo", "f783e3eea26d1f6fbf6e09c00427b4d672785ce3f82f8da371885860b7c70ebcfac5d7079c0426e75ba6a4b259f3c1c616efe4e3a45b4a74c2f2dcc7c11d1604" },
                { "es-AR", "dfaaf91f34c42abd42c35931450a469be7c57d113d04ccd1cca1de145223a1df8597cd5189eecfe1d9a6a14257c6ea8a19eefae1b9f186478301f1a15ae3aad3" },
                { "es-CL", "817713ae0c5c750ce965c685360ed85e9dd1491733463363e8fe2b854ef2e19e48c853c307bf3b38b9ba5835c23eaff0b0d9d4535da45dc0297e9260dbf0f58f" },
                { "es-ES", "9663059ff8f0bffa23fac395bc333b3fd5e9247dad15038f4ace3e439da0bf5adb1fe8ad6c443d315be270eb0b402deee76746dc82d4e41b24eb22e67741fadb" },
                { "es-MX", "22dbdf01ae7342600e5d16def4d90a0e2d774edf5bb2388f75aa460fd41ef53eb7f3ac550527db2d757d7c33a98cc061745d27131f91076538c42665d345bfaa" },
                { "et", "6d65d3a34799221b82affde699faba7541e5787bd0295ab9261ea1c73515a46c8a78dba79fa631c2c9a6bdfe645b09ef66840fb4e811d22944873d7b130edcd6" },
                { "eu", "1fb1abce9e7e3578bf15da89ecd4f9731508830fa5943bf1c5eae6a6a7760c2b88447c45581f7a1c974df0b4aa0b19eed627c7aeedfbd97cebb87a05bd48bc24" },
                { "fa", "95b662525ab98066b668e3fcfeb87f032e03185544cb2191d996804aae5eb3f19309cc2391280edd025c29aafdaff9753e4047e124d8453d7a49fce3e4d190fa" },
                { "ff", "c0452d834085f645e070ea33a609d9029d3857529d04d1b5a29ba3a624c2926e4088e3abe578cb5839b033b0096da092f62a101c0f85244babbd6d1dc4efca71" },
                { "fi", "ba7e8b3016783e65a9ad957746f10679497235fdeaac8417ecf88633164c3c1f44cfbc9ff4e29a615f94feb9e767665e82f4ff85fbb1bd85ebdb4bb9f4989d7c" },
                { "fr", "5ab730d79b63ab353e374a75553c18887043777b4f8887cbb92ebfdaf956c40557acdbad32dc1557c7c3d5ed855ec916e29c2c724430c3354161fe118a9921a8" },
                { "fur", "d836d15104dfef996868e2bb9b7ac93baedcab50a29deee46232df40967fad4ea9111027fe49013e8583c92cfe6481a3a8e49fc8c2e4ed5376d1f4c185313111" },
                { "fy-NL", "90f2c11e4fdf0e8197ab4e295117a80a7f8bea23f54161d52f61ab5289883a9a8a8b1dce242f7c584603980d8dab5005b5c344856ba8d79b3139c64bb46f9f27" },
                { "ga-IE", "ebd5645f75f3a8a630ad38f2437b815b15d97c4ff21b5e297f73c306089a096b08b6d30e656b8728d6c1887f38a8794a2d5b6dc41590e336fab27880a9a4ff8f" },
                { "gd", "1c53571e5b69dd9a09b7db4e1cf38c4f76c9a97cecfee279afa24de4fe776062de5a175468645dd96645b2704060a4253696fe5dd6746b38008d9a0738a715e8" },
                { "gl", "508ccbc3fb66044e4060f3098204bd08d7dd5b0af55231646c810149456ee309e705cac675372b3719a1b6578dc11cb7c380238ce219928e20e74aa37ed06067" },
                { "gn", "a2ab569839c638a938c8a392aad1de8898e6b16855a8cf9ebe95505b2d3c9cb42dcbe2371141921aba4eadad7123d2628decca5a48063acbb7454d500a898dfa" },
                { "gu-IN", "cc75fb83f863c1765bd60b97ecc14174a6bf8608ef934f4b0e8fd30f4d889af1c408f4ce7288189a6c1cd367878e712162b7f0d00171783bbba96ff800aae148" },
                { "he", "9beba67b36e3b2a7ad5586478ee1648aef84904b892cdfb8fb2ed44d93bc20bda41acc6adc0df1ebaf0230b671adf88cf2e5a098900179898b62e1ffc7cb83c2" },
                { "hi-IN", "3a5d807019b0c4d785a4c11de445ba6dea96ac8d616ad657f7b8f4b5462a3b291ceed79c428365a7e2f623c5678f94709ca2dce51a1dee35c862af632ea16192" },
                { "hr", "5df6637044276fa8141bca08699141167f069a633fd991e5fa3d3399056fa854ac183f1f90ed4dd06cb9f3e2c84664f0d45df738b23d9b0caf1f3456b23bfbd3" },
                { "hsb", "addbcfac0b56d79278986081b2dc3b0407a525148b7316dd65aea9c598d3f20c88d9b8856f301a19f830a641d82b47f9edc9962a68881563b5f81f6dd7654172" },
                { "hu", "f73002c9e07034f41c7031e483e508a6f01b6d60def45c7d8271ce20916f5103160c9067d948fdf652e6e160004e79553d24154b11f14a940c5f8f3dcf4d061a" },
                { "hy-AM", "bf64e4bff7525360f4fadd73354d49f9fcd9d26cfd14b50e6b384d064df44934e4ff86446d7b30ac87ed5bef5d772f060154514c0d7e27866a8eaa49c59409e5" },
                { "ia", "4b2584743e84ba8857c39afb629d0b42c78b127b97fa7b002e5b95212784503f65b26b1e819c22e91912f0a7e7a73aea9120b16853713f18be79aad4e022727e" },
                { "id", "f0fbd73b301cdf66d5e7c6944fa75220b82b972fefb780263e7553b6fd2015c71490d2c8c42a22b0d9c32735259a576e589ade428b38fc379ec22bfea53bfc94" },
                { "is", "231f2355ae5788ddc5e8db6b25ea0ef26a2e790ac412f76440a4a3404b3c5f85f7c382871dbf437320fb982649330de7f228133671e9437ca353ec9047313738" },
                { "it", "8ae453482c4f31d1cc43ebddf8de851f8df64eb6d557ef98e58fc318c054a4423efe73708fc74d5bc1791d40eb203b93f26e829669aa65f988592c14a9102b70" },
                { "ja", "f8cabd2f94fbc32935ee0fa41d89bcaebab41edfdcdaba08221d88ed4c6e77cf6cd3fcfb8c45995396fcebcffdadc20c5e6d538fed8d46b79b5abaabb6d111ed" },
                { "ka", "7202cd37d45f379a892c94e77492531e1c56c16405e8005d12294310014a803e493f534b65e136b46cf9c2cf6445dc246d507676610f00764fc5e223d39466c2" },
                { "kab", "4a0a206e6de9131f421da7e2a8a0890c57dda007adc6db2e7af82d06c6f6dbf158647397c4fab9bbdd318aff930caa9d7a013cecef64621e608fc8b97b2b1ed7" },
                { "kk", "6ec8e8eb286bd5b58b75962aa2bcce5348f560e0a42fd31a31d804587ee5aa3c443bb9b45ebd864f642480a58b94aeb811969ea03328886a7a545dc490559c25" },
                { "km", "c04376489c13425bea587ec0652e8e4c7ae74107ffabe136241e94a146317061bc515d00895dca2e0eb709314a269f62a5e5e01812fb0cacb93e59811107042c" },
                { "kn", "bed14a86891a384670113d7874a164f362f78b872e5f3d0a3837192b969bb695f278e935f35f742bb849ff0dbb553850280a2fef352d71d9f40460d00b50fa5d" },
                { "ko", "6d53890d248b94707d5e7628b1834e0e2beadaf39cd30ac4ddc0556f154119cb1379af16b32238bdd596c8da305b117313019d32763b124f2c09f1aa0008ee2c" },
                { "lij", "084f99dd15b1dff9537e5d27515c0a73d0cfc227e33ad370211407fdcd78780ade60980d92e587c1d2633a1bbd29cb6e63834d938ab17c1322108b2e45a2274a" },
                { "lt", "2bfc563eea9c85b108e0b261906d00880ba9f773e1a56315e26168ad124a27ee778fdf4432397b04d7dca065e413a1630c45f71f4ed2d5719c964a05461b451c" },
                { "lv", "591ef34ae75ec64b445333dd5731f0ca6bcb9e4333ae8d4fbfa5aab5c83df7797bcfec24efdb9a40acb94b38f4ab8dde076457b80628bbab01894bcb3b60a4bd" },
                { "mk", "d75a899903cf910fc1eac95934587417e6ff8cc63989f49bf8d4bf5ffe4ef9c02c6fe67e86827bdd26f7b2b80eed6b55bb390919beec838c8f46b19355877c03" },
                { "mr", "03fcb954b59c7c9e42e2804565f56563e8167fddfb992463b03e17f4263d5f0509aaf8d538aaa84a3001ace89bbfcb814db36b4810210f6638f037776ff98a85" },
                { "ms", "bb9fe065eeb21ddf88dd3475b2e6862d8e4418abb8b106016cbfc83d979b2186518855520c4931ab61cb8098bd81a84851ef6acd34f7cd61157f470abd2a93bd" },
                { "my", "3847bb2336939e85a732963efbb831eb81302963008dc18681c7c5dce13f5011414da424a7b1eca72f66cc7aeefeb9bd335cddf8f2c24135839dc1bac1705171" },
                { "nb-NO", "2ef0388e2e931a7bbc4cf6cd261d0d1e9fee4842e70614386a5bebd314b2a6df962b08d0a2b562fd028230171c4fa167a2aa1433e8b8ff82128384dc916e7857" },
                { "ne-NP", "5f263fb7f72b0cf8f7aa132d8b81830de7fee143754ecfec9d224a565240c1b8292da2ab60a41cafa07f3893c916e5126497b3b0e945676a3ae874971e454413" },
                { "nl", "e28bb73db564bc24209c7b95037425580fd3773c1393018d165d6c30ec86bcc549b2d613e5e9c36c25c39a20ddf01362b9e82a72fffa8ae2010f8d7867ecbc75" },
                { "nn-NO", "87e3882455e4c3d405add519a034fc6f2b05c7107c028bda69b8d25641d5196e083fb73f9c238dd0da9145bfeae1d5ce2e83cf0347d92626ff6b036d8d529f3b" },
                { "oc", "ddf1b669833802525a4fff773d742bf2227a885f52926944f2a962b02f142434c1cc30ab24c9e98ab411233c86c31e773b4d72db227572bca4b785531e9c4e3c" },
                { "pa-IN", "560c341982454640f4348312715542fcf1c6d077bfec768eb62d7f6eabb36293b6db93f3a2862be4069ca8fbdb48d1b4fb7fbfd9e18461809edaef1acd90f318" },
                { "pl", "5650b8c27557ed5f03f8b582d2daa028b49de0eefdbfcd8108758511c3cc35a2a6e5b5ebd7376102b4b14167271e35eba038b6c669dac8cb63f77fbbad6c7a8c" },
                { "pt-BR", "bc681950298655c7fee383d9e8ad59802671bffa8d512121f55c072280b6e43e563b6b8524a97ae2d82a6bc702ccbeba19a30d0c817e2c1428f9fbcf696b9b08" },
                { "pt-PT", "aeab264fe6c823ee999a900ee86bcd24c497a4dc7a55f523c021ed0ead5a9863931becd850cb3673436cac022c620be135bb48c2fcd4f6b6f3d6265f232125b7" },
                { "rm", "220a2fffa92f39a157c5fcfaebd5403f28dc425cbc9ced00f78bfeee1797119a3c77996d009f09117f78332ac0e6ab619a48b48f9fcd1282f629ea4a3f7d43be" },
                { "ro", "4232768e31dd8b58eb56fae055ba233f163621a0482ef574697a44a1f71985cbc487da61ca37def30cd7ce3fd8d453536c8f29b28e1f6e461b58de4f021ea4eb" },
                { "ru", "0e946a061210aead074e93cd0a99668864be373d897ba0fe207115322a9428d5d9c9dae1328f22d1032992d7dda86259ceedb9beb5b0285d63985e7ee5b85ff4" },
                { "sat", "e6fd61aa878e2c9779ffaf711b37b168ab6e7a6705a4c692913efaf0b1185849261303f6ca6d7c16b431f87ca26e403e13408b8fa95be42f180f3121fb16b107" },
                { "sc", "48117b70e0b63389233acf537a63a014b6396cd79976177da0034a8fa334aba62ba2ed65f46f52c584f04cbdd8b96e0c534b578238a5efdc1f2e7abbffd8aa8c" },
                { "sco", "048c537d28ecd0856725fd9791bbf99636ad621cda5a3bb763b5e78d6acc740310d66f512cdb9379da0ae2cb7f0e5fecbe37f4f5908d8a33a9753114dda33b2e" },
                { "si", "a252dfb56db8947c5899bf896532bead8542805aaff6eb4e959036a8228080a7759e4890e77f231e98ba39bb2605392320bf57bf52c416b09a44669f78fa37c4" },
                { "sk", "f0d9e6bc619b2bb506a6067b39b64c0d1ff3ac0c731d46653836ac37c9b4774526c2bc279289740f133bbcee41ab7e339c1d3ba314e34129535917cd89ea50dc" },
                { "skr", "def722d281aedde93a1576d21c3bf0e5abbf686325299aaabe74f7aa619031f93cd083dd15cd952fa39618f2a255d137e0ef53811caf96dbdabcda4d56a58818" },
                { "sl", "0dcb7113bb160b7f9de635b7694e0e90fceae1f99dbbc12c4221b508a671920c95720970fb5b00541790bbb7a953fa16f540103b3a23f06aa6dcd85471eec0bb" },
                { "son", "95452f3a967c516a1f27c10a9ec0514d7280fed09498d9c6718ce71342e848a3a91d4481f09b2cd7cb9ac8149d4c4b946e7ab3365fb881ea1b62b9bfd1edf930" },
                { "sq", "f5d898018532339b069c3122ba73609cf2a216dcf0deff17cccfaaee45d921b7a5d784b7dedf07bc69a67f81e3b5c5f9394ebacaaa2b984267f62cf87a35d6b7" },
                { "sr", "b31fa837b71fe7aa38a0ac0e1cdf696af237f73f870611ed540c19e9add19d08a2b2ac47a19b8c67552a0baab0942a6bc790efc723324fb3434d035748c8212d" },
                { "sv-SE", "e9bb82f026de34e19e9763219118082f37260f1ef94ec71895b6f20efa0c7cb50de696c2274e6bac08167eab55b18ccb79fce06c29641f0028457e1a022bda2e" },
                { "szl", "5ce9c3189ce765a2be9d233b4fffafcebb3e8333289c39c1572fb74307b3b2edd2eb7f8b523036d894ef7cda668755d82a09bd3cbea84f2872ebacc96951a278" },
                { "ta", "c8912b3cea93dc01ea838541ae4ff79f3b5598fc7128dbd0e34265aced4301a780287f445ad93651052bfff8bc9d2dce8bb76d9555112b50904f1bb99a2f6797" },
                { "te", "ff605d7273675efba06073c5447b9261b2a0d3bf9183946cd71152fab234c990ab57232f6c74dfed85c066b07a790f827dbbf2ce0f6a5b296435ac8bcb5e2b9e" },
                { "tg", "744b4fa4be6260957412f3ff800dfdd198706b1818b11055dc75940687741cab51a099accd0c3119292d8c35a401fed3505ec28e040a2f8c099823eaedeed96e" },
                { "th", "5aef7ea95b00993f812885b3d89543a760c6edfba4e1072ee4e056eadf567f0965c76936afa6d6f89dbcbd9afd17fada71c3fcb213cd3f807e7441bb0fbc8392" },
                { "tl", "ae7c135c93c85f7522ad3203f3b487503cca0c1bb5334043c5065f82bcddf66acd0f22aa973250805cec3c0e542edc4c41ad7cd803309067d715decf7dd0dd49" },
                { "tr", "15c0ef82434bb3ea783a6b47e10b02557be5304838f29c3b131fd1c35677281cf5fd408e1d2b989d4234fa5f0d1166c70285600eb28598a8b2b447e1154c99af" },
                { "trs", "a67c60b9c2cf050209e7bb394c9499a7d316cdc87e7383d0926cf206cd2269139a55f7bb759e1afc8b9382bc93252793ea683fe07e6da9d150b8f2de71ecea74" },
                { "uk", "a5da74d98ed8186e19d085417118d9b9796fc8ce2d48cbe7fe41411770e55c32225e3d7d0011b72f8e89f0926fe6e6e21fbc703920f70a834f6bce707f0711ae" },
                { "ur", "b293101db406836e40bd53ea98886cdd8df1d565361bb21d3b80010780f12a24fb3f5680ddd157373e0737b230dd67f8050e37b3493a01ebeebcd686cb2b327c" },
                { "uz", "f5767908967210f6b1851e7cf80f5cdfaaa7743890f4c83b2a72f8c7914515657838ef0dc44a204b559c3a3bfbf128a4f9ff0f4f36a627fa0bc345b0db1d4051" },
                { "vi", "577b5e4e6a1b917c1c102280d0ed52d821a240e0aacfd6cf36e8003c5e38ad4e44058f722dde58614eaeeb7d0810bb2716b3502ed9475d9ea9315a430aa382a4" },
                { "xh", "fc309a97c98d08f1dc9dfc4765f66b0ea02de8f37848b625ec07cec9f52154130caa2370023918ca5fadb04a9de50e7c5cb39eb527655ac888fd023cd1564706" },
                { "zh-CN", "2d41fd155a331b7400fe709fe73bb823e22c983b9d07f11cfe5e6d56ac55bdc1c0c418a7f81b163152b12e461b9385f17bed53510ba678aefaa1f21c87bb1927" },
                { "zh-TW", "da8a90bc2af7b7bcc75480bfe09398929b720af744e956016054de6bc2584c444c0562f2324510f4347750feedef6456a594caa90b1299f124464f0d2ae518d3" }
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
