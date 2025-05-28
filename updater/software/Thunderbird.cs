/*
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
        private const string knownVersion = "128.11.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "f7c36e773475b3db9ea005ba630b69e4bbc1c9a68787f6c3665ada724b2be35b5ec70b5cd1619d73fd29578949255866c118c6f0a689faadcef45e2017b03872" },
                { "ar", "1e2b1955f982533f8d36210b8d680a704d6fb373028798b5a3f6c2507db4603a00e32785ddd20a2bac8f1b3a53efccae59fdbeed08eda381164ff1b8a5eb5d96" },
                { "ast", "aed9b438080837e710aed29823cd6628eab43cb8f5e5d421418b0912b46174007a0e32426695f284d81f552c76f536255ec523ac8ac995b94b0d037632a97b6d" },
                { "be", "e95630c4d32908ab63baa1296892ae81b8e618b99ce47fe109d5dc57a2d5fa430f8bea2bbccbecd98a819a4a56050aaa2e5151b536bda7b89bbd6b946fb538d2" },
                { "bg", "92568f16d2beca7ea73188fd4e4240a5b25125ce3fd65844ab96d9dccac42372fd7d3840a865d8bfb792e14a0723312d6a6c4106e9226cc7cdad3ca1087aa77f" },
                { "br", "afdd66de6121c0041210251e0f1ddc79f50354df6c57b0b6abb5c4d583b573fce87e539b46bb0561792a30dd4688e6255120479a67f9c1f010a9e5a133604a94" },
                { "ca", "3247edd682aff07aaeaa6c7bea1077a0c77e7b68c361f1dd41f79775d27e27e1f6479781b45b8da329153c9922481667e6a183f84cb14263d127028e458141fe" },
                { "cak", "fc31e7f4a0578b22e5daebe3a7980894ac5dbaaa8550928521ddbd05be016f49278a83a160eea07935f5d45529b243a91dc439126e4e555d1155870a0e115278" },
                { "cs", "8165c117b237cf365f28be991d30cdce5c5fced12a362a78d12b75625fd7c4a9820d69b1a1095e775138f1d1265b63d438ec1174db4060075092ea630dfa1a27" },
                { "cy", "bee1a02ac5ff141a2973f9d1d16edb6a8574020b68a27b4f34a747cb16b7e71e3706d7ab47ccfa6a817e80d9f4cbf604ec1202c8b2751501ff8f8db31823514c" },
                { "da", "66dcf88e93501e6a5e0f5cc0e7130f1e15b52da1e942f68037024997d3092cca206129f3b3f1758b3cb44cfa6ff5c5e7c69b60c6ab609f7418e02a9443a464e2" },
                { "de", "fd74b81e167fad483cd8347e563b705fb5b56555300bc0ec184c10f0e2f466d12d615e585f29e7463db0fc20c847c7c279e14558e43b31781570cf7150f05ddb" },
                { "dsb", "50a57df225eba1e57854c86500e84272844798f93dca3fe7fb62d9d97fbdbdf6685a7cb8278eedfe1d85b1258aae8d5600f3ada85de8e01cb432a947461752a2" },
                { "el", "d96136ca7989a033621f1ac2106ed5f4aadef23013ab4a4cc99c939d4c2e046013826f772395d2423508ee33adab165363dcc1dba9252f2fbd36af6863b2d2af" },
                { "en-CA", "6aa30be893ad483a433ebaec839d1ebdb16d4e840a58707ff529f4a44fd9b6f2c2b167862bc048965a1956d4691fba84ef7af89752a3d2695f325d706ae12586" },
                { "en-GB", "07e6a6f624d6811cde3db49d9d1c9394c433d482a703037c53a93efa1b22761af3d1b8cc6af1758beab9b9fe73917ee85745f8be7048efc03aa8f8e9d7111296" },
                { "en-US", "c82c227d750297733dfbe1dddc2fb429d76aa8c096b13e705faa87ea0cd4949b3da45e184eff9d67914124d0fd0d3de51227626b4e603755329f32c11742d3c7" },
                { "es-AR", "e11e218333e499b71b70201dc014351ebaa9a091680aafb9ba9e455c5f03e096d57ebbabc3f6a0d0413165c4f1b323a0e23dee44a84e94093f38d92696c26a4e" },
                { "es-ES", "87cd77123622caada91bf4a422725966b2564a439e53e925c1c688ad137144da1dd2765ab77cee3287e9b4aa14daee6c682d3659bee1960db868e808300214e9" },
                { "es-MX", "5a829580a352d726475e7de2a42ac47da4f4000c9380a67062b60238cae4a093b2235415a21e5446927d427dbf67285de93e68957fb4e9a701c337d6a789ab72" },
                { "et", "d3dd20e06af2ca7e17871e910099213a33135e4c2d8c9b10068e078230f733220b3dde4ccb3c76e649d83b6ebda9eafb4dbf678c238683c2f36d3ae062baa7dd" },
                { "eu", "7efa5c85bb4d45abcf833ab1f1caa3514ea6021e56ee9a165878a8404d6baf222a2cdbe7852b3a4af7b43dab0d3f81d5b9219f5ccea99784ee7cbcce929f44a2" },
                { "fi", "1801d9b1d394fec0d7434cc3d91b700f3ca0ac516fbfb0ba4e89ee2b0fa635ad525c119edc5548d9a3e05a81f539627bcaafe03b8bd31eae3c43f41036eb2a04" },
                { "fr", "a3aec4de227ab7bc1f7aaffa0a35caec094086ee7fa33f131b7a372963d4d3fddb45c65dbfb214323767c8b322963d8d4d36d4e55057e6c2ee3ee499cac383fa" },
                { "fy-NL", "5753ac127a2422a93462f81b80fa07a30b2c4833ad0b868a3edc843c65259e69f45a26f148c97d921df626c93f77587107db8d437196f21338d0b1aebc08b396" },
                { "ga-IE", "fbe1ebc533a91d1bb048dc399ba4e5582b740f4415e7cf25f9dbcf37ba0ee40a4f5fbef09e9f147c03ec7966a1511f79a28186857b45046b8bfe823014559f28" },
                { "gd", "2f81660ada87a94645e00b1f24612608d33369625b5e50444d993ff62de8a219a8783903eaedb7819ff8aa206dddec16b68098968a0d0c1baecf078e532e0188" },
                { "gl", "8694e32036ca20acae78928c91fa7ffb2fbb62d1809b4948db42dc5c512c79e74bd28ae288602f06b4fe4027823916c5d64f801f53d5fa7c8f213ce8e5024761" },
                { "he", "ce14493b3f693950102bb8d31a7f51877b32f08327eace3260e9f33eed558e185243460ef6085ec733205dcd6e4b545ea71d399726d6bc213a48f3817a915c50" },
                { "hr", "63d1c9d4b97fef20cb32b7ad02e1ddb0022945c532c0025096ca751bd40639c9818b12840d556c74d712ef13bfa1d3eba0cf9b81e7a0799cd9437b20e2e3148d" },
                { "hsb", "211aab9a591d7e6c48ff2a4b7bbd05e01e149c102dc11192fc251d5ae97a9f9a3636dccbf904a15c68fd1730718df16155431dfc8614d7970ef0be08e107388f" },
                { "hu", "030700e5531019a1f2e246e418f4921ecf85f426a159980aa49505c1fd7fa8f5a19cae202002eba6e6e8d14d51be933c1b6abb3acbb96e1e8848b75b18c205b5" },
                { "hy-AM", "d0b15c79c26f929c67fea222647cd75529c3c563bcbde834244afd08e4ebcdc9a80fe3ef53e62acfb7e2d59d9654c2570183ced0d30038bbba59f1d56df558f8" },
                { "id", "d6cb7e8d348ba604da9b5037f9d308da7150fefe8c93227176e785fc1ab83123b049607c9928433ca6f783e5f5ad91aa5e824b2b5658d323817ca656b0fa165f" },
                { "is", "f690b3721aa7d74ee6ff25132f8135f33cfc1234c011ca1e670fd52f6f6bdc2a956bc7385c890bcb4e69ea66ce1f6584c4121edefee16e82223f203e3f4de0be" },
                { "it", "d516cfca390a20b9b404bf261ea16d68fed29b10730fee6b365e02d6ef6a972a119fe718f65a07743689c79b0be2f0fa83a6dc81550fbdb61eb0bd876ed46dc1" },
                { "ja", "22ef677f39e0483687645db0ad6d2a35de09503310cca92b458c42361f37ba294d8bb96857b7a28f561404ea8b7f486981c56e288eff41230b035e73bf831c59" },
                { "ka", "4b1354e21c4f62d10ab324769bc035856608cb09725e29acda85848697f708d99f6cedba78b43b6036b1e1dcac0dc8cbf97eeed51aeb08a987d54b0f14e4d57b" },
                { "kab", "41cbf10fd8db1ad63fb04da6560cc97cc6ff56c48a9e8d1e91a332a42218104dffdde01443bd3c1375dc6d11dde7ff4899e41a0613c0af7027ae9f290a031cc6" },
                { "kk", "281157be306170a82b68bb392be97680d0d5ae12ba17e6b31e7aa968e575123c1041ea1c395f3b148a0f519d216627e4d8593dacba50e50903165fc50f54d2cc" },
                { "ko", "c9b805951b6d9bf56770bc9d4e76736c90b1b7fde23de3f447b7ead4e97384ee4449d0cb3d4a7ba03247a618ece011c37c4bd51f258a5f02616c3e85371ef23a" },
                { "lt", "153bfede01a020f428c9c39c3b3f61a1611b2f8711a04ec7c6439adf41dc1d9e584e385dafb560b82f0de34ed4e940892136045862ada383a4e39f78f6311e7c" },
                { "lv", "f533534b022ce57cd5fbf5fedace0958a732b1cdce0bc7b973d7138c6f4e633787e368bf42ab1d81bb0487433fb398b8b89da796c8272704302b87c7177b7bd8" },
                { "ms", "6774deafe4e8692fb3721621cb8a7fd7066a22e4862e6281c5d638b5469ab7a5fd106a8fc62e98e9f6e17e295086519c2dcf266d2dbca6f567ff5579371b5409" },
                { "nb-NO", "6274e255d84b089007d197c0f4cfeab8ed03bc27b752780e5bcb3ca66a5665c8ebd8e2723610a1c0ae9c56d246b0a0afe64ebf8ee8a6725b201248ee4a15cce0" },
                { "nl", "4f4eae771561f96e1dbf2280b14ec40fe35db14ff981bd033c48548be75b7795e7ce9f7457b6b7f89839e868ad981a034b653bc3278d0308277d2a489a2c1848" },
                { "nn-NO", "8e69cc94108441eb9393bc007080ba07acaaf8a45f4ce220d9af694c1de732dd86f0789a63388c8330438553aae22c86001b6fc28166a350a5ab519db405713e" },
                { "pa-IN", "776ce19b27d795f59f0466fd1ac7f33dfc74b8eb7338d1b0f9965b24d6ded30ded99d3e3618a47c9a934cff9e6a5474374907a1abc507641b1f4eb890e98eed5" },
                { "pl", "e98ff48231f91d3bab1a249abdb2bdee4ffbbf7a6696bb5fd12fd48615408f89fd4f315975d50956e62124e7a2c83b64b163c72761494e578118751d7c0b56c4" },
                { "pt-BR", "7c5936124afe71c093f52a06c1b808eea470392a8b7d1d32840b22e7be02e53bcefd7424a95722f5f8580bec20ff3ffab92b4695c32751f17f469a8646aba644" },
                { "pt-PT", "ed5acd37f4cd077d17430fa3c8107792c4f6293f45176af33c3f223e5f6ada6ebb4fbd5f24bd83834c95e36b21c7b78a0279b3900c3ed55d8cb27ce7a9a3bd93" },
                { "rm", "3d3370accfaa7561ceca0b9b900eefb79c1127485582e6c70dbba3a9017e2b882dcad9167f2395462c725fc2d28f5afb2a30c4ab34befdb049b804a3f25cc16a" },
                { "ro", "d67969f6c594835443ede38dff9f8f3a690cad131a8bdd51fe85d7aef349b2b18d1f0753c494e7d703d9341fa4ea090a9c674b1370d86842d50ff6f0ff9d1172" },
                { "ru", "3aebdad02ebaf366c0bd8c1a2cbcfc0e85108a2f3212a947d1e3da1c7f004d58478a10675f000eb1cd6a8a23fb11950aed4802da6b9ea22f7431b6b74a8a3684" },
                { "sk", "cac6022ccbffb9ef1f7944cb8e73f462590f9aab992c65b68568ffb816cd3b3068f2af83c710e8510e0f427bb1984a61b70e419bb62b918a4c10a873eb6e8c10" },
                { "sl", "93b9101765b96f126a68dbfe451c97c47580a7810853a3a701d09f9b5eb7ea7bc3bd14e2559990740f741f39815cf3c576ec2915589da2e0fb15ab2d029c0e3a" },
                { "sq", "b1d43acb9c2648b913af1c1de689cd3ad8a2507d868dcc32ff9c579e449b66bca4208aa82cb51cd351834193bb93772ea4835157c9225579eabebc3eb3e80a34" },
                { "sr", "0cb89bbe8b8825c0c09be924c9f0a9c4ecaada8b0f4053a236b88df1d0f1f6bcea54ead88306a8d08253b81b5ad28632bea08e2a0c3377a6dc27c29219ff6bfd" },
                { "sv-SE", "bd5c10b43dd29d9778b2554867b47e193e5d687c2ec8b24853f0f844026f84cd5063dddbf1f9cbb3d1343c877f46a58897c55f6749863c407f26928485af3b36" },
                { "th", "7b22cfc0164b31ea7a20b40a4a7763b53f5bfd117f398b45190ec39e60188683cd08210e4ab14f2a732d9c0fdf7452dc481ba294659bdc020a7e165f66734c5f" },
                { "tr", "5133ccb82f432a67d4f87e2b34a99c035263e4cf6529cab9d8a6fe286aa157eed81332589dede677eba64e308d0c8d6433fefcd7922f9c1b153d19c4caeb182f" },
                { "uk", "c101e899bd8e304a20241147a22f89c4e2a6110bc58a353d69fb235525c0e85482c5fd11a8ea2887ecf892015615032f8e8e5e4f6883092a351461c017cc9b82" },
                { "uz", "8b8b1b11a077ceb858fe41502d5dfb5ac14bcf7a97b70dadf2fef872064e74bdbc1ebc633512f0450f321b5b4f9398e81e90cb9a590769301c88f067a2b2b39e" },
                { "vi", "7c7b174e35f25feea646eda5c3fec29dde01588053df42d3ad2f2c8bc515755a7ad0a4fb3e3ebbc31f313328a5da35e75ac47791f0a993cc9f456de5730ba90c" },
                { "zh-CN", "fe5763eafa6cc4d0766323724fe8bc1b886ba157ffd5acbfbfe37bc35e2d4fc96bbb76539b9450a8b03ff8aea04fe953f0322911c7c8c3c30aa89b8b3a6e4bd0" },
                { "zh-TW", "4f749b11bc5be170bf72b79eb35fb27213d3625ad7a262bdcd38b48702e125d0f888f2bb0f5cb60a6dac77e8c3f8e4a1fdee097f869cc69162210a075c3685bf" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.11.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "f61a5608c9ffe81198e62134dc0c8350acd846e5f9a6cad05e602f5e075fa270105f091f7e2dc806c927fb45e38d608f6df1cd77ee999a5a562ce9186b3f2785" },
                { "ar", "6b7a29b62391cee4e98473e9c1d07331d7a1f490ee8d0078d6911156718f5b342e621488b647787c3ea04c80d08f3467cd243fe69d53a66ddeff5e2fa07a544c" },
                { "ast", "19f851bc2c798a363fc9fcf908b92dd51fffccab53c26916dfca522c57a8d1c86c03f5a2630f33f1a2e89a30b3b9618b06a0f4c9c5074b2d633584f1598b050e" },
                { "be", "b7fd44733338f72169fab708dd5dadd9f0458c5956a549cdc9a7f2bf7dd47b180c2c61edab6ebda129d0008b016dfba0e3ed36b98a0879a906f3aa30ff00a757" },
                { "bg", "6cea791cbc91be5327155d1b68911884bc3004395a64282e0ce68c37c64e5bb3cc05e0acc0b4153c02735d08b014fc62ff5651f813d07ea00c6da5368663ffe2" },
                { "br", "8b713cccc54180990e85b2577e06ed069a1a911fb4f7399a55f96f89b8bd018b5bb31dcdf11d73cdedab6a2dd1fdad6ac0f72c2ca80db95aebdd2927d6096137" },
                { "ca", "ab5417fc6c4aa1b4d1a799e2b1de1118e3257f4461be37699cac7d85db7ed844710277e370f9b4d97f44fcd68977ce62050654f965cc53822b1f1231551d5a75" },
                { "cak", "b0c8b543744b3dd9fbc54decb6295c534d1e4b3ea40568f04d1340cc0197c373a1f2dc7747d57b24203a5f7dd482bf930a06bae66a5e0c061b466823d1889dd4" },
                { "cs", "4d258dd1e1028cf98926879de3b4b2bdd736be5ec917f2e149d4ff491348eec3881d03fe46db891e5ce25ce5b13f7af491362489c80970918898259ce3927cc6" },
                { "cy", "a354b122fe74df44b54ef1959ef441c86325b66bc799ec95eeae26be6d09df7fa17d660813452a446c5d50435f128ba9e57a3c64d6fadbfb8b7e37ec8569ec30" },
                { "da", "5c8bfe54bd06ff8818152220eac8172b090e33f11852c0fc3539b06ee4689396758aed03696040c302d7ed7f929a9001813d8402841136d8b02e8dadb1899bab" },
                { "de", "d41e6d92189e782ce809aa104b79fe4bbe752ec54b2fc8a8420a00dd0bd14ff8e18601bc90fff28af244f9111154f2c63f356ec2d3b353facfa39a7b3530cc36" },
                { "dsb", "a08510d8de45fb771b9669abaa372ca73df574b808a976c7f997b5f0f1a67b7c06e5394dc20a9b99090b66e124b570140f081d410492afed42ff5e81c28d73a8" },
                { "el", "7c4942a83619d5c1e42f970235706166f950174fa0493c4f698d3990c4ae698b26b5006cc8b2f5b53a93cdda9b53ec84fea57d792a4f0d68ef555429e9ca3ff2" },
                { "en-CA", "ad557e9375d3cc7b3e60297f1a861f79a7d660924ce4d20123c54a20c723ecf04ec9ce3595d75678185db68c39e1e82307c6e9d9276238730325632f7747b8bb" },
                { "en-GB", "770af6e896b3768ba398b7b36d2668696595b88d8fdc4ffdb044ff77dd52283ebc4fc35e73668cfb5e439fb62cc9cc8fc1c0ec8c45fe490d25540d081caa5286" },
                { "en-US", "05a0ad67b58cece1fc9e97c44db53c415b0fde1eb206e78b9d89d4fb19d8758fb1cf94522cc73d953d8d4e2dd028d15864104c363e2582eaa02485740ef6025f" },
                { "es-AR", "cad42abedeba9cca01d3d239b3cb189772d55b4f8781be2daab9aaecd8624f3049f997cc82c881d82868aec5c6be3e31fc02e2529c9ee369c74999b427fdeba0" },
                { "es-ES", "b4d025bf7a5ce1cc07e1fb1b2265bf8679b2538dc83206aeb154ff18927a4c98fabc8711ac8c324081bf79e8977ddc6278697af40db3ded848a7f20be83bd771" },
                { "es-MX", "b45627248adaf48bda475ae5221bd9cfc0981683d32ab21baa79a6be9d2776010e5e18284ca93d703d52ae8c745f790d0b3a73b68952a546f59cfac36ee7ebcb" },
                { "et", "ac3d5bacfc5ff2519b09d3da69a120c51ad7f4ff3f438ce4087b5d840a17cbe6c17adeb88938335ba4a4caad35e1fee52499c9db6e128e30a622e3b0098c7c04" },
                { "eu", "bde3908070fdbf9fee7452624b8448ce0f07cc415f6f1a8594cc735682b950a041fec912e4acad526370524297946fa2f03f23f47c9ab97164b0144423d37de8" },
                { "fi", "8f4b0159599b929d7e414e806add9e6f81fa9e6abf10eba51320e2236c7e4644e738efe3764cfba5ec3ba277676d2e35971aaa56238099f8b126a928919afd87" },
                { "fr", "1539a852ca053b3dfcf66d139c289db39a2117c5ca2ddcb2d94f68cc8d3372cb48ed758fb2b5fad5fb4efc3179013727fe4cc1357ff897cb05f8991cb75cb0fe" },
                { "fy-NL", "090c11b6396a5997c3c5ec1e027e6f8809cea8dcab727572eee9a8351e6c7b093f3eb8f6f929f5c7275dbabf6f05a74c8242099374cc60a9385a05340042075a" },
                { "ga-IE", "f7e4e344225244e51eb30c998e7bf389b4548c060f72dd711142b13d5e4a8e8d5ba4873c97778b978b91b578d2441f5d5c12600b3fc3c084c0f76ebf0a0d6845" },
                { "gd", "7a7cd5ce58aaeee4f6f0facd2ad37e9e1631d430d08c5f27220985879ba729c19d92cc3f8be976a0070a19f3d562e52bd38f1a0d2d3ea4b87b1d5b899d1dc60b" },
                { "gl", "f171d7254fc26598c1f5c41d6524626a0534cb79c7d2aa840b0f4620f2e361f0234a1fee4b6f91ec3ef2fe1d2c043d2d7d503eca76508d03e379196ae9ce6abd" },
                { "he", "18af7a51c6c0d4b8df2414d9c7845b16ad7a2b9ed067480e1d75cf4b54631023f5593e3de6a28edeec77aaa813fb6b0a8a098d882880e1f6ef4bc474a9679709" },
                { "hr", "86b5e3f41e466289420e7840d97a124c8516d1ad99b04031c33e2393e4e8852baf2707a6884edcc495f5ee5dfb8f44be551250ff9527aa9de247b85e92ca8ac8" },
                { "hsb", "838b184a36545af36a69b1f4d9b2f058612fd9fc107d82a20452ef0d14f2b04424a8f4294a99da66ba674a097b1b45c532930602fa45b494f074e58ef707a347" },
                { "hu", "4e272f58e5b6c9075bd87f74dfbf4be68939d0c3d13c3a83c358f2b4a99d5e89cca492c64a7246b257b6f7b4e10736b027e2ceb36ece3b58c041c510ecd6881e" },
                { "hy-AM", "aa280d0ab2af6b13f963a3a12e04eff7f9f7016a48e3bdfdfed32156c571a129cc71e381f3c9e00d07fc1e51a994323582c8fb738827edb73b425ae201720453" },
                { "id", "645f90fff7b8384ebd4908e2564c39484410715996523b23735c5e825abf15b7a5020e223292e0d612c0b59f7e7d366aa756a7fbda291f52ea730b39bd300921" },
                { "is", "379ac5561832dee9b5b5570d77cbb5ee581f6489f5700abd74caec4129b9af026ce1aa33f749a30ef26a2ba40b4dea6ea47910a38c51475333358c7c235c0868" },
                { "it", "bc33c3c25fbfdf71e12ad91f1aa067877a8fa0880ca245eabfedaf6049b2c53eaa815e5b18c631cc9d86aeae3f3c548d9b32bec1d87f736ba40231eb545c4f24" },
                { "ja", "8bc0549b112333c3f38b7f99469ba221e5e254e620e2c0b6843dc10b06146e0a8e50a3b22ee0e3425f374982fb0d7ef20abb0e8a107329f3270c30d1bd45e088" },
                { "ka", "c8495cf792cad98e310cf104246dbfe13538f7d8988056d11976632047c0fa5e12a78e1febd49a29b49257f320c4cef36bf5a0aa077d6984e96ca395db1544e3" },
                { "kab", "e773626328aba43c13f02c5b1f6bcfc644a8632b0613da13dae234711c110d8e1abc88ea1cd9972ef886965e588f017239d270130bad24cd005f279095679a2a" },
                { "kk", "5887824336cd8911dbef2b7e1fda5659fecc45c1c48015ad1aec10962016af4fa3e93c7a15d6784f788ecf26c896744f7a728f32e629bc5826eefe8b913b6dde" },
                { "ko", "9a146d730178aa721ebdc36bf2195ebb154b76bc371d1d1d4ab9200ec0450fb4dd023f9f7aaca77a761d7fdb2518aba9f54ad5cb8cf19830421cfc0c79b4c802" },
                { "lt", "a219972f9242e2cac50ce944ac5ed405e138897db1fa80102fce2eaf74d45948a39557a3614b9961686191bb6ac44bfb2b82ebb71d37176788344de09aec10a2" },
                { "lv", "f822ff94381dbea2d4f015ce42255fb9d7e5af2947381a172b103a67c0ba3c63053bb4f31e7b0bf0b1efe095a25392d79ce09e0169c6fc18c597639a9761b581" },
                { "ms", "6f66f27320402d2fb5c0940fa549456419a54e1d305f53d6c95b45a4c3a29961e95a3c4044da4a96501b2fac1ad0517065e1231c7a875de6bd8c6efc34a9d31d" },
                { "nb-NO", "c48e778efaf267c5a723b9e38645c4429a4a3ffd46910b700afded34fe20843532f20d77b07c55afbf9b2531ea3bf3609522d2382def421cf71a9a9fee54b764" },
                { "nl", "4adf24bb716eb190c0e80526fbbf6c8a339e591c51fe0c9d94bcf8de3addb5abb6980b06baf923ab692fc5ce6806d68da466ba93eeac3da8d24ee8393688fa2f" },
                { "nn-NO", "1f143515d234b5a1a65f4eb7f36b8d43fb327f900d9398f78a02fb04b3367e04f40bc9efdbefc2ae106286a40e7b60b3e2ef36e2a05ae63326fcbb9b348674db" },
                { "pa-IN", "712d6d5ca3d1436002f3cf187419da97348d40ce974ebacd99934538dff48438c76a7514312e6593e33a9fb93844149e8367a48f3b96e1e6ee35e68c6c3ea713" },
                { "pl", "a02599e48d654f11b161b1fadd075b360d18f2fd42fa352df59e87e9098d562ed6e515685b1bdc27ed3b6af1cd0191cee9d18d41f145c2f711c18f9e18a16b4e" },
                { "pt-BR", "e8a3ffd8325a0bca62e457ae6a70e2aa64981e92f9621afc448c8a7524af6cff8cbc2fcb03cb311ea1910244617cff46cf12dbee3018d35110cdce88c0089642" },
                { "pt-PT", "f9632c1c46532b9c2ad77a9289b6fe27465de5210229521d6614083352d364da21d5b127e3d9dcb5b7ba3d557fc232b5f0517119ff53574957c555316ef61e75" },
                { "rm", "102e6325f0ac3c5c5b7d246bae59e9c70a620a704773e57b182d538e635ca5c1d71d4885423f0f785c4da1337b1c9fc4d51d4a6ce706e3eb4d1e0d753903efda" },
                { "ro", "215a5815514060ede6edb87f74a1575c020c0c47e2f0d46bb843243bc4b3f0299e46a95ab35f974f803842b0954effe07ed98f7d2b3ca72f7d543587f6c23302" },
                { "ru", "865eb2b89baa625cc7ad9e21af892efcd8ca81ea39674eabc0be2aa4179e0f5f7787329125fa4d188b1c109e56a15944c74701c5b830f9b638d206d43777344f" },
                { "sk", "5712390a92669db3d2fc9a399de96e8d8cb6135058ed8ea1ccc6ef97607969226ad550c558789da3dfe991392b88286c929da454400e7da845061e58be1f536f" },
                { "sl", "bfb1709668666caa0ab789c2ccc178ca6d63003fc98b92eb002256bacf884da71bcd1348ca29ad9e400a32c312a46124da334a9bf7c1b14a8e618a924b285df5" },
                { "sq", "efc8e520e13c7535e53f605d26bebde4e44ad885b75a86cc2e9f0afa9e3867d8b95a8dd3eae61d590704da6a30edf7bd358571b85b6c02665b0202bfd1b779b5" },
                { "sr", "f684b7e64f4ab20d36936c870522046af9fb5ab4b96c2700a01db1c685fe38fd307b17574f13e100afe2529f692503de35cbcf373e450f28c7d0c729fc44e3ca" },
                { "sv-SE", "5090391b7204949c133fc01bd87bcf2fd073d46c1ab30a22c5495a7c7e70a842e6b4ad3f8a4385b6a44417d7890717b375d81a22ea09bd5790c569bc5f188892" },
                { "th", "49ae1ab90b3513735f839f3cbcc90894e687a171d93604bdd38d26588aa69de444d3d1eb48d280662ea656d1054d3d5a88334fe38269426597184e2885b7812a" },
                { "tr", "9ab44fec1fd00e8a5990792f012e62f00b6c277637dd71ea513e2880ef68a832b84fe9217c9109aaf9bcded16f2af370de4e36a692356ffd415f1b38b48fe544" },
                { "uk", "84d8ec00c794cb6f9c8251da7f3a1d495fd10df5b0dd24f7a1ef71d5bcd39adcbeceea6f30d875b20ed79313284d3611b2935ee5344181c59c880d48bcc86974" },
                { "uz", "0b516c4df8a3984d6b7d740f5fdb62a13f4366fd2d1c8f17c6602e3a523217145b56ce4587bbdac529ac70afefb1c714b215772c5a108197188f16aa4091c4fe" },
                { "vi", "68c9679fa898a8f4b5c652d99aa3c859ed5e927fbb6cfe8eddebce545219dfddcbfaa46e0346d316e37f8399bfd79538748f75a82e4f18a4376c0c131e2f0489" },
                { "zh-CN", "b3461238f0391130b2981956bf75e65aa791a3dea55443fce0a6e1eb5d35be410010cd883bfda3c387556ce76cf41e0f779dbcf309ebd9717c5ab66b48e9aa8f" },
                { "zh-TW", "1eff37082034fcb24bd0515f849f8e155fe6b15e26791edbe2e7c719a17632d84515d199c58d970d7f3508b2996e9e308b58e0c2f1a5808cf519fc189c1280bb" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
