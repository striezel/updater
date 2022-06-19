/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
using System.Net;
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
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "102.0b9";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/devedition/releases/102.0b9/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "bb5010c75efb1b38f6c8c767ca6f699433ecd51815df9ca22de3cc61aa3d3649044bfd56cf2c1d31e4dcb2af483d29b332789bd0dfd5dccbe7d4ddc047b72fcc" },
                { "af", "f3ceed0a1797f7ee4d022d39016882bf0b3d2b1a8abcdfa70a1cceb72cb6ba18fdeb6e12263e711c804e22d6851b3bb3b5320841847bb9ae03b7f804a142688c" },
                { "an", "c696117c008f5b646e41586b2465973dfd647d967feb8d5de0fcee09a35eeeacfbaa7bc62f8ec2a43e7aad51fe076bde2e63e4665763691b1f2718a73373e620" },
                { "ar", "05e6e99d6dcfda46683fc336a9bc239999c71b9ac2930e214bf43517d4dc122082ed63de7507e4701b3b447b1dde30564a3c5c996dd42bfb78873a74909e2d1f" },
                { "ast", "dd7560d8fc0e47db7fa50e95b74a1c26425ba6ad8fc7be1d86fc7feea9bfb7b42b4c73101b0f7719b1d5693be0f905c3e82b7c3c79b8295159ec7bbe59611bec" },
                { "az", "4829fc9da2d763ed560bdab3d4e1a972110bd63b6aa389154ec6ff77b6e9c439fe9e481f295019636ea58cf20c0682115ed9bb923a8cac8dca40f9061d96a303" },
                { "be", "aba58d161e00b060a64a5416898ca974bca6e0577fe664e3697c0216443455d1933176febf8faa9b52a3cc9ca0422290522f03f33f6870f1f27d9bb8f302d2f6" },
                { "bg", "9673cc8daa39d3db520380726c6e5e1039e3ce1c8247dadd90a0ec365fc34771e920603927258763046d085357a794525a9c85ef7ce0c5b10563560ff8f25bbe" },
                { "bn", "0be39f0d222ac6ea94a4f8873d9ac88b652d1602f8936a2c5857df6af51c24dcc0c33bb2006e9851d6d463724f4bf4178490e5c25d29ed1b8192b49e01bba7c7" },
                { "br", "58525f65eae976c2aca7260628e865dcca26b0425521dac822fe359338491bd874d5cf16e74c0c8b56e34221711f1f688b9da90d9e6855a8da4762ec19922379" },
                { "bs", "230b1a469282fecc45d8c03e6496daee059985c427a44e4c992e082582f306028a7a9c6dbc347a1998676db04f65cdbeee41ff0c3f179c2bccd30e213acd52f8" },
                { "ca", "d398b0c38c9b777140a83b09836f3f22e876642257a87bf195f9d4dcbce508b8973a93190f356d15a0b74457e443c9222d06c02dc496fabd3b74c4c868806c8a" },
                { "cak", "077eb001ba2f4a2a2f9d0cf1d9ddb93aa2583ef736ff79d44dc7dbc40a63af8d6e2b7a6adaecadb3a3fd398089ff6bebde76e63fbf40a55adf4275fd3bab8318" },
                { "cs", "3edb53fa4736ab9c1146beab574cfadfb6762d471cee5430f66f072a8a90b92cc8d3354e8c43d6fb955568a1d7150df54027512e757bce371801bf33d5254554" },
                { "cy", "b60155e83e6da3c762b9a6e8fb506b9c32623e1d63086f478c0650e02d8f6782f45c7b76512e94a2066e94347bd48f2ebbf338d92157e2bd71a80e6036e9e62a" },
                { "da", "5f4d4d5dac21a784c69f0c2bd9bc0f65ca8a8c8b525075acb67a7e73e6099f02ecf10304341e1347ffe2a794c539a108d17983f4165070be97e1d21fed39ae99" },
                { "de", "2a5f60fc9722139da221dbd10b0c4635d16787ba7a464f73f8089acb0eb669fc79a0ff1ee2f8cac59769bd4b81d0f54818f0454a3c9446c37c922d7dae8407d5" },
                { "dsb", "e664e2c67f3630c4008990e77ce29742effd69495e5da9ddb3e66534425173475495ca9d947b761ad576cb877697e9e5e765fde464b139c2559578fd255a3fa2" },
                { "el", "c6a61acd602fcf284c9d7c583746d6d5d5255172659a9a38f0c8e6ac4ac49db7dd64f19c47dafe8e53d69d77d11764eb045d9feb8acaf8060a801782f7694e1e" },
                { "en-CA", "de7be7238eff31c7405a43ef82786333f6aa21a40a1af83f05699fa5286b39fff341409b73cbf7692481391f5bd217bd1bf0cd45ba2c1fbad6379a94d51a51ca" },
                { "en-GB", "69c43fc11e1d625248f91bb09f2381f71c7b23050cee6109e8e737cf66199e2b4dacdaf8b3b220ec671e766b39fd5c4e7796e7a4fcd44479436d84d45010e2b7" },
                { "en-US", "3569332593726fc01db586f62bd7d2df8e2dec34dc00c752db8d7dd4a731ec248b3cb00f2f9ed8e7f0fe6846dd7b76b6ee61292ee52e8ae744ac631ff532fa91" },
                { "eo", "1714aa2ef40f2a5aa53d59b51a25f6da2332d9219cb9be64d8a5e47ebbb9a2080ba726116b4499e1d473bff35b2cda21f2e295a0a7fcd44f5ab70a40a982414a" },
                { "es-AR", "f8dc8ab55e2dc5598d0783e17a7cf8c4a0dbc234006215bd674b07cf7231a9c663af2cfb321a0a76cc1d03d3eb23d26b1db2d93512e2af52a86e9efdd7c7f7a0" },
                { "es-CL", "e396a6da29b0a360ad452e7861ba2be9dac853c6f968529c159eff66f0e6303a8acffdcfdf029e642feb6e120374f1e126540cfa45e2b8031f6ed2553805b3ac" },
                { "es-ES", "f4d3d76101e07aa581d0bb0b0a270dd00c9a1f501fd9800ff4cdbcf155102abce825ce58ce5fde628c81e3ed7d74305aeb7d9f7370570f485be29ccfb62b4be9" },
                { "es-MX", "de22df5bf14a746f0cacbf366edc87bb070515aa3e20af759c35dfcbc862b8872d83c47b418069f7c9881054c75e614018b42ffa871f095f9ac8d0eebbed15f7" },
                { "et", "78d90803229b114f4636ee8d0f702aa6b0c37c84fd4c6d22cd57a215bb61b3a9d78de1b4bd5773268c8d72adffd626ef001708283b2947f5af2119e5ae0a8d54" },
                { "eu", "982ac148b2071202052d3d43f6f842e67a5bc4ca458f83be082e48f1a7c617e3f866397e8ee2dc3a42a785146342006fa0aec9717a8e45d4c728fb92bd90ad9a" },
                { "fa", "ae95ad2cacee7cc1b254dcd002467ecb5ebd1b1c4ca15566d0fdd1cf0dfc5d11af1a16f13e203fdea7b355de68458c9f69b2f03094f199f4d1410850a4f448d5" },
                { "ff", "bddba5007229bccbfa7f3518d2adcef3ddd3b1cf8c16806dd9823d47fe20003ba972d9685eafeae8e3ab0999b8219532bbc73be932d4743e832aa993ca006ef2" },
                { "fi", "c7b10915b8a05fd5f70deafdec982c4a5291721cb5cb5010dfad9acab54bd687c5514460bdc24c0c9c5a8f5e1655fdd20c2e23c7aa548fec34eb1ec03eb6bb90" },
                { "fr", "d2af6261795697dcdac8504988b56247f69380e7b9c2b12c77e56f6ec09b34ef5398d354d569f3d95cad370a343b9425e5ba17c0b5952eb8e6df62a3d709397d" },
                { "fy-NL", "88d60fb5862d3443d205b2d5f032244d6680f042071ad4c87672798e8294df1b2f8369027331dbf11cc94284d70a1befec8ce99498e7d68a89147416d361aff6" },
                { "ga-IE", "f4de8cb6c1d951f1961c605d71d834298d49fe1b6f41d7d1a7519fe2f205ecd8cf7d977ef081287d062f53f663d401359ae4ecb93ae5618c734cfb9cbfcbe484" },
                { "gd", "8999a85c16cc7c55cfb04d159377347b20f934768e5000304891f743c6d1ae3be3c6ddf7502ade4b0c583c96ffb6fb5e42124bb2134bd86add437294da2ffaa9" },
                { "gl", "03f9a3c6b64f714164761df1e8f451d4a0a804f5c3347be27d1336a178e763c6017b1f3867ddc9de983eb40ca108db713ad6d5258daa20dd63fcdcf9fa46f657" },
                { "gn", "9ffd807d06c002850ac6e3778b6ed824c417c4bb872630e52f0046ad22128aa23136f7dcc38b1f772df8fb67f80e5b43478965acd637ef70da29e395622aa4a4" },
                { "gu-IN", "e5d4e3ab228eed68740f7a6feea0b529a9b210d33b3cd0a2bca3eff81b0bef7c3ab44709be7aba67850e37070f111e867c562ab42b42d0ae5d500a21cd09d41a" },
                { "he", "1b5df66dbf298fbcb56111a3f44232e7b340a41131d59a1e99256d561123b44ede1891eade545637710872ee515a623ff86c66a89b6ccdf2ebaf756cb7a7264e" },
                { "hi-IN", "a65f60597e6c7a0c5afde59b9d4788eaf513e729d898baad2f89fbd3cd035c0d3629dd853a2fdd23a61cdce38bb639542d475c5deee83749e17f6fd699a80334" },
                { "hr", "139de806ed05843c4bdc1aa82a94b5028fb702603c89f8309b1c4a991e25ee7a19eff607e19faed094dd1b19e4ea72f863de1385f3df264c8dc4cf681c7833a9" },
                { "hsb", "fb4bde6b0364390d3f142741d6f437a71f0c6beedbefc8e21db3da0e285e981d25272f95ec8e49098c241948955d9be1a1e1be04c3545440f58b644e5ab116f4" },
                { "hu", "49294a705cd01e239a8193916d8c8d3e9c15c6d176a5a30d849d4322b84dc87dda814f711fb9a48b2c17cb0336fd9639c4f346f17bdb85a72e07bd5dc27b611f" },
                { "hy-AM", "4dfa1c590c29af854e044af467f236159f494b737d0f025f5c28d4d17f2f13daeed690033817d79e17166650b26ce56dddd65eda201a648e6e2bcc566d960662" },
                { "ia", "dd14233a9278c7e93d5ca10104e0ba9e8aa1139122dfd2ef5b247da722aeea9c2cf1389d31a35aa14273d3eb1addc582d5afe02a298786a3ddf7c2a9c4c4ff70" },
                { "id", "57d4f080731cbee376c8ad47f41b3f4b0386b5ee50bdd49f0c1e7e9df666b1033b887cd77c366673813d865377dfa58afc0ba44741dce25461934e6901c1e041" },
                { "is", "a6086e0d3cb0f820bcf364ec38cd43ba4a10949ff8d0bfe54263898e9ec9bf4e240e1f9fe76543e0678876ddb36efbe17dd8d43b9af4739a7545584cd868a63d" },
                { "it", "ba93ab2a2e902624e90ffb6da38b4c089834a7319c6b65cb27923e1bab3648af44ce55fb5646116e787c487d8b328b6c3435364e61cff31032610fec3eb679d9" },
                { "ja", "934c225cb56c40388fb1cdde4e8f974aac8993e4f18667231f950e5fed816ffc255e42fd948ee4d029ede49a4c81c04eb347ba188d9b8b7e3ae0dd1c75e3abf6" },
                { "ka", "4eb8a82f41dcb08768f2f052b52487320a3596c1aac444b5585ccf26281402f87e9d302d65308932e24b81b924a4cdf331549a0edee03f34633b7e2709dd5617" },
                { "kab", "63a6796b17fee6f421991705aefdeb653f243b75926bdd0cbf0b9ddf36522b91e30b1b16b0692cd430fda384bc7e087151bbe45f79717846e9bf12c579cf7713" },
                { "kk", "f77bc3d143885a9df8882679cafc28ecebc8a07ddb8bdf96b01508728fa079bee0982d2db08704988c8e2e311fd1fc9b31eca0e2b8b220fc2332aecb94b2e4e2" },
                { "km", "930cf8753ba407a2b46e7677872079d907a551eac33682d268bc9d1aa745761dbd985b6d0db322ca5acae3de76f16ff38757132f18cefe721d8bf54d9f001dc6" },
                { "kn", "95ac36b4371603f699bb42fff0a7e5d10bf70dfd97c015acdc1e1372aca50d799745a43694dd0ec263c59829d9cd8a75010b336c61dc948740cb92ea04bda4c4" },
                { "ko", "7a13afc886b962f688fed0b49f8f24a48b01136b4eb0c37e962f2818f15494683e8dc03991089d957b3fa1282210c0337525ee59e027407b28bf015206125102" },
                { "lij", "1929aaca6c9a077e9e404686624a5bfaae53b2681b7dfa2e1c98abade36acadec19d913ea6bc8943dc97578ec1df240fa2e6076074dd222a33c24fb1dda09392" },
                { "lt", "879f52518416158bde2f113b90e3a1d851394762fa18cc984230644391a7d3eb2ff24df5c986d35009bf6b8eb4c44d9509858b1c864dcd839edce2da2d66061a" },
                { "lv", "afa61fe1a36f5187693cde18f7a75203e69c9b38326a81e1f1a32442378b133e6f0dc67f0b8df7775abf966085ad9f3ba823fc525a2775738a3d2c727cafd74e" },
                { "mk", "57e480392bf1272a28fcb3f32b8e49fa86ff74f0ae57d2cbe5c15060e534ffd7eb5da99534f3df28b0110fd7284fb87ce8fb010ce0aae402aef4f3763a980ba6" },
                { "mr", "1b962a4c191fd6bcdcd8c6239b4c2d652353d373ad33b98b912cffd194ad48638fb47c7f7b49c8888105070e4a1ba71c0de2e414058c3aa3a9b43b3da0192458" },
                { "ms", "5925a36adf0e7070a2a6ad5c22e66068d156f3a3be0281958bbb1c0a7ec18667ee405df915c71bbb54687efdc059ec99249379d003bd61ba1a72ccf72adb360f" },
                { "my", "b812626b6440632481efeabadbd4b2374ede490c082739216b9d8a1638c11801f02e0a8f19dccc02dc507cff2d445200519f71840d70d5c32fb4199a7d62ec9d" },
                { "nb-NO", "c68cc4971473da03bc22590771a11bc775f7b35a5e741ca8199429ae5ec05d561f5d7ef80b520b800758e1494ae4274e85eb704c6459527798747593f23221c2" },
                { "ne-NP", "5c2c21e4465beb708113dd805cbaa74d6f3ba0d3b4d2f50158fae2661cfa9e698a5321b969d7989f81a2c81ae5a16d3df0528c16b778d7394a73c9093c766f72" },
                { "nl", "a48ef13bed4ff3a150c31c8bfd074b567436f8b106563d99a0fc42a61cd33ef135eed47d6f9d3b945c5fcbde9419d5655b985528d8d6c15c0b1ccf995e2ebd3a" },
                { "nn-NO", "638eb2f6ac9d1e915efdd18736973d926f5915ddf93f4f1deccacde01fc43301a0a1890880c4b9082b02f7c514c521c80f88908cde996448b298a281e56edec2" },
                { "oc", "aa3b1a68b9bb858e9cf68374bb85e31f9139da468cfc9e197e3698716679da5900ef026d2d8bc1c62f6517ae52c01d47c71285759154ba4c1f7019f72fca4c1b" },
                { "pa-IN", "d2dca5a2123a407b601e40bcc747788df0ee1d9e397c2818391dcc8ea1aa860f1623600f9840328694610c8037947b41b19c57c80deacbd11e6dd26081dad2cc" },
                { "pl", "9e025ac832e57e2b70022f106f4f1b0f2a94d0d34f02254fd6f358ab2bfde3c968c0bcb5e35591dd71ab969d1492225d309ee04c0e98337e4a87333035f69baa" },
                { "pt-BR", "df710a87ba2c7b2bf2a97f4f299db579a1dbf09c9a4c7aaf22ad5ce9380ab7c333bf25910dbee3e800776e1c7ec38a3f834ed53f9506e623f7f2ad423645e07c" },
                { "pt-PT", "bcc1f7bac909698fb1cef894d224896d6c9cb079658e4ffa1665bab3883393f9866c75110fbf27df336131ef58b51328c9de6348d48b734ffda243380b50c78f" },
                { "rm", "f8f955d3f3e876db58f5f3d444f5c85d6397e9172328e8a23bd4841c77fa95cb81d3cde8085c01480519f91e87fb28329c86e8dca8fd068aaed2c4e2ed56c0cf" },
                { "ro", "0a350f344584b95441705f00f234fb2504373bf9219d207157a14b188cc00d171a7d16895201017a4011cc5726b50a2c43d749ed4808c475543e4923747a934e" },
                { "ru", "3754e046f462bb5b914910efb64284e2028c6cfbcb72a436cdaf470ee2e614f9e22c7dbef3d149a604810af896ab99ff8208b91bae8467f52154d84484f64d70" },
                { "sco", "338aba8e37ca9c8d9130dd281c5daf277ad634ab12b8c1a6b9a747cc6c38f67900e2271a9c60746da2c4326aa6220e79ac1a9eea386715f4a354f2eae076333b" },
                { "si", "53f8da97cfeff930f1ca214570b45d8ca0f12e3c172ce39357d383c88da48ff9edb58eed306ea73a61851984d96cee2d77f35b141745773da064a9ee4fec9096" },
                { "sk", "fc94e472884ba499fa384530762c5ba374e2846adc10d1e8fe5cee63a0bc5d480432220ece10c3a25e8f105c1ed8333fe002d88241f97c7ce6c9e67e56784af2" },
                { "sl", "1a3ec8b2ac7518f7665ff43b765baec86d90d89a590d75b37972a3ceb0fd026a1643a6ecfc7c204130d329d8bace075c75e15a282203ad219aef5869610329fa" },
                { "son", "2a48f54b797f154eaefc93c90f9db0ee3f0ca07201f3a2a30f5c87db311f5d358d9f65d7dba6261224c045bd733dc4c1a436b828dfdfe82fe5bfd76e4699a546" },
                { "sq", "2032e4287093a0105aacce10a04421d58b0a0b5bb1de8418df850b1880b6a13980195a1d192413d9ba25dfe69266213c3db90a0ab6d359579a3da6e71e83dcd9" },
                { "sr", "022a5ef22706b1532b0a5465b8f808ac4211404cf4d59967e9a571346def7aa8e1c60b284254ab5ac35cdd5d603b851701d0753fa54e933ff34e3485c11a814e" },
                { "sv-SE", "39a734fe24e9f5df505c28573316f5681bcaa781014279925044e36357f6dc933c5bbac0e10348537c0162f93976e4d1ab1b3765de59678cee0cdeccc53c7b6b" },
                { "szl", "79c0891adf5220628a7abaad8753f8b5686115f4bf012046152c049e6573591a424363baaa55572d2be0b47a9f37c3e09ad17df2c8e84d046f3ce5ec9cc4d72d" },
                { "ta", "5bf0a7a61b310ad9ec4d986485daf20deed7eaca83abfeea6e3aeda87ba14c83d0ec1917145ce3f68b98d8010e2e35d73c839599d7d2659a264fab0f4d71aae8" },
                { "te", "64656c753456e3873e7056a6fdab2c59d9b8e3ef741b0bb93285beea51b8bb85b3cc3d32210a56b599b9894ba2e8d2b7011e12b3fa9eff8e48aefac67f515703" },
                { "th", "76b3bee34151347b248a7fd5fe591f059fe3d35c165a1fd25f1a324b470c16207d6fc982c1fe76057a40f2fa0f023fd6e598f70bcaca1b32ec427631222d5f93" },
                { "tl", "3358b7308a359491c72848b5ebfb30b8496d8cbda29de241fa4f4486b1fb82c7091690f31df8436b9d5e20b0ead10577038bd26e0b0e7e79b9cae57b720b7250" },
                { "tr", "515d1397c91791cd6ee1270463b79df0b49ee17be3e115802906394b4fa3f759999d2b4d8aba3d01a1b4b08e0550527808c9055863a50088aad34779119d53a0" },
                { "trs", "3e7cfb57a5cb7eee302433c1fa2d2418a8f440d1f24cdf3eb03868803c68ae9bd7982dd796d137b641040e6f78c09fddbfb636c1d133d91c4ebf0654b8af1b14" },
                { "uk", "ed06ca1474f81ad268795124a274ae94e6d32d8f58c88ef00588b92b2fd361a0201f774fafe1e6cada8c3b952800b34f889e4daaff821aedc3d9832e2202259f" },
                { "ur", "29dec228f021d1a1ea5dfee3c918237fe4016a52768e962dd8a89f57b856e89c16d30c2ec899449793b7cf77febd77bb518a03a18213dc7eddc6f9c3d63a6ae8" },
                { "uz", "60c36d19e4c812ac98b4791178d159c98c53abf6e9ad10cf5efffb380290411bb1c3c1d54e2c72475684a6b9f2552db0497949f6669fd06716bbf80bdbec087c" },
                { "vi", "4d385851d2b672028b8e76aeca2a743b577f6a095eb40e6cc1e440cf75c60cbf76b512ffaed1570966f4f08390eb4dc47741e1d21032d6dbf206fdb27cc111b2" },
                { "xh", "004e9779b968469c226775f6bbc6beb228f0094e9539743691e36bb95c8ffd9de852fa97ba8eb51a206721a6f90a4db4c9f0f513f0fbd9fa58289f3a6e5178e3" },
                { "zh-CN", "77fcdd54cdcdaa34bac653197fe77f2bb1af4053aff9c435f2fa66a081352bf15939b3c94abc45ae377ddbe09157e463e3e7fa2f2d8fdb0162a952b229ba81ee" },
                { "zh-TW", "ad6267aa2f0a0cded29a434ec813b5aa8f2a6838b55461d2e3849400a55fe7c004cae94adda36bb5c69a8b734d68917a92989edf73225a9e5794af99c681f3bb" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/102.0b9/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "0c079da48505a05ee55bbc0f823acbedcf6b1123c6b347978587b79d9f8915b19e54738989819c6dd2301f5dbfd539d64776b91faf611a741eb1b1febbed72ef" },
                { "af", "cf2b3a4033a8e28eb8a8e30c434e34b267543c06c1fcb6a791da798546e406727f6d5e899ef3d1c378706101cc27397639638c05d5339275842c66fa523d026f" },
                { "an", "beb1f156fec34ba55ca6d780f73c868e2e15ef7044fc857f92815e85b170dc33eaae6f48ce294cbc77e1316d47f6195bcadcf79a4b4ba214105e13f3d3feca6b" },
                { "ar", "690984a6a1ed46d006f75ed7f94e1719a9a7a66dc7117e93b7c2b26cefcf0b56730a5d3055a6993a4609fa7563acba6634de0ac8a33c2a5da3bce8d3b03ce182" },
                { "ast", "37801678272e9fb2717e05891eccac7ab674a8c673b020cc1d470d824bb909ed28b3959d17917e94dc208022055fc72dae6fbe4e8642c80eb2e8562de0a6e446" },
                { "az", "962b4df6d5cb58e98056b146cd808346345b07dac9b682caad17343ce7ddac105a5aec6056622c46aa03574d21dbd639d7d118c99d1b053de1a4c0570b916532" },
                { "be", "807f3ed8e887317955df3d57ebcca42d3b8e8d7a9ae4a465dab23b2f00ec7790644d4da92d7d98c8fae3ba5829c87a30957a26ffcc7c790627ca4f4466f1cdc0" },
                { "bg", "4f476f8c6bdfce4a3d06b6f1736c275298083816f0cd20cda33db90135590866783888ebdf52c9509d86fb1d1e8a0639afad76610e9ea3a752aa97693cd99259" },
                { "bn", "63f9447f44049ed7694a9a6ae0dfe7bec0883b15714a1ba0ae344798c1c356dbf0dd6be563346fdd283e727ffd56f87da24cfd023bf876058a7a52dc1bb2f390" },
                { "br", "227bfb310f090ba42b1c7411e9980a65b618af52765edd282e36f4f407e69ff7aadbfa6e8e472b3b582d76d464463b4af1b4189e1f5ca51c94c50a608c49529d" },
                { "bs", "cf6243b7721b4a3bbe34ee169c0e10b49a64b6a9d84b3544600611cbd4cadf780da0cb01cd67403c066f3e4a510f2da9688989c20ccec50a3553600d8787f814" },
                { "ca", "1e543a7eb343634ad448a5abd7b00a628080e898b15704655d50e0403fa55198ff9c868f7edf4987fb9be84ca0317ccf3ad7a5689ea7325e25f1a8a9518d4bd5" },
                { "cak", "ed913ac887291a0f4dce10e46a36a2b5cc49183ccea24744df1a5e38615e94e9e4a67881c135f0831d3ea2738e2bafe1859648918a32efe5ceaa9590c8d9053e" },
                { "cs", "fd8602fd6de4f99b182a63e69ae83a17938f43684a69ce0b84c5f73c43e51c7aeffcf1831c6eca29e93e1777f0ea1620b1269ed932277716ead8d840a48dbf5e" },
                { "cy", "bc51e93434f9b9246f32cc1ce7aa287527d1d156683f6d6d33c111bac87740c31ffbf6ebbc6d45951e21842aa8fba08cf771d039b713004ad6a4b42a5b3c919d" },
                { "da", "e0b3d5d78a33efca8bc7aaf8702b15fad84c138525c7056641d2334451e103694dbcdaf15ace372f48fb9ecda7655a928011cb1bb6032ff2917bb8e68f294216" },
                { "de", "2cfab89d72c16a406908570226c4131c691e916013816cebb15aafd53fe2b2d00f45534d4464de6ca6a12ef47db9306fbb341e61dd33f9c297ad57f7299c4c2a" },
                { "dsb", "3fe65350d3ef0c2c97a6a454efa2b4cb9377546bf78f512e0416c40812a4b01cf56ec061f76086b258012e50db9a694e32d3af49bc7ded24d70e5e93041e26f4" },
                { "el", "d664fc693536a80c304198cd23506380b6c7c72264ba8d2abf9b4c47f0d03b19062ef60961554947f3dd05f005f4164a07cd463e61ae06191d991910b4c71fc8" },
                { "en-CA", "2a4197dff9737b7fed9e8b64d397f696c8fbcf0a19411e9db8b8360b64e00b40c9c72880f65cd8f8611c20c9548134de26ec6c1cf99ed9f3d3a776a4352a9aee" },
                { "en-GB", "9c9a36198883d40974009bf1227e56caa593778bd09a082a7a7f737de501fb15576e867dc3e5772511c51a2428c98047adf449c6f643aefec8d2611722657541" },
                { "en-US", "39d1154da498dc93f1292891d72aaebc6df7cd0e657384f05db3a48894ff28245b66b05b6328c2e6cb20ad22a6c3e05c0c7d405f78e6744e4a60d9b84ddc85ad" },
                { "eo", "3ce8875c5d8074d129d00a6aae18cab29ff38897bf180f2cbe400fdf5030276295a257a2277f2ca9f40cd362d63624d2a946ca4d573760f151e2edab06da52ce" },
                { "es-AR", "edfa82b58784ab584e7df8cc4fa0359a3d2b9133243b7e3417a27ea81ba879704319f2be2791b241571fa2782085962287308f390f72254d1a115b6ee9d9e542" },
                { "es-CL", "e6ee70cc5c37fc7f9bb1315480cc4f03f72246cde91fc28a200fbd9d53ae261017b4481af4593ae13214cafcddce08f479e678f1115bb0a7a47e6f8d4b8238c1" },
                { "es-ES", "819b0243c9a170cecfbbf00ebf90f159d893361ae7c1d0627cf4b78f18413d306516e0d5fb6271778f99306a340bb6d1f0606868b5d2c3e49833b03f1cc03206" },
                { "es-MX", "3a35d7398d1241c1c058bdadfbab6310353a51abf9b259f9632c4559b8f24f648b3ce718ac1d799aa51f78b0b8f8640f74fc6a9f54917b645393f76da4aafaa2" },
                { "et", "88a933ec25f1472071a9d7401b04b40971ba68638278a2ba1793772ab4aff836d55eb6efe5748d8943588fffe6cc7e93a09ffa0bf8a7909b813a5eac54317164" },
                { "eu", "ec748c02a4a59f3e66802cf33921b766ed637722284f5b2e1b308cced063a74bfe4b3e583dd833e883797fd497f8983115d472314b2bd52a23d3439167f949f3" },
                { "fa", "ba62ded3aa9a4d2ff6118d994036a032395318e773ff42a1e354ec3185709de346298b19b186492381d135142e462774c3cbddd80b5ce2119535e8c2c0eadb5c" },
                { "ff", "26f03e72e12e4c8e04ef713230a121a5c8e6ec940f5c2739010b641630a7f3be0c12ceaddf18caf15b7b3cc6f140b22a3ecfed83a04d1b9ba39f5fe726fc3df8" },
                { "fi", "7403e749201252e5cf9a76315cd2801ec727c2d31a5c2d9fdb71f2c189ada038d8591d846b5f55898a05a637d3f00dc6ed151a1d0289b594c0ffbb51a25dcc50" },
                { "fr", "96b100288db202631e797d03bfe4874895d9e4671aed3a604cf53662f92ee3cd5c081345dcdaea57f2ff4f886ea2eda8d2c05e1a163829c2e0bec150fc4d2682" },
                { "fy-NL", "b0a3c1100727d2468ad4b59bd0dff415c82904f7c207258a1e9f05af78f320eb6ec14ef83a88ca7ce5086bf0f0b69accde08f384f6ad56f0129b810f1802c808" },
                { "ga-IE", "d095e96951403e50760e9b583dca3706d6fccda785b7ffe10b1c88dbdae80bbac08f7b9c07cf108e3262e9e9f33211a2dd6f417e3de9a8fe9073e831cac1f2af" },
                { "gd", "ec3d1fcb7ea51420acd032441c2fe58d11c048f0fe4521762321da27c6d79873697d1608a415df8af6e771a1dbe866921b303006f9fbb45baf176728f5db45a1" },
                { "gl", "c64dbb41c618739797c57a0b767bb7cd0969a7298a40dbfe8532d6fd069a8bf977a8d3b7be09121cd1b15b2e5f046cdcdc9d03b3161d8207c095c27aa75145c7" },
                { "gn", "e7a049906fca5a24b06e9275f7b20e5e5e5a1ebec821cfa51583ea9e214c57b1c510c5e1c274f09617297e4d9bd67eb7bb8267d44a9f895c4c6004b1db350fbf" },
                { "gu-IN", "8868919f661f3c60c6f9e480292e22eaf91666bd8ee17887f860befe542a6aa6cc9d6100eb351a96fa42c9b958fc957259add92329fcb0d1d88f0c77e128872a" },
                { "he", "426f630d7910c006c1a0609c41b32dfc277759559949bda276892cf9bd7c5c3cde011762dce2a0c9284fd0f90d8aa7f5e5935acdc5be3ec284e580b4efb163f0" },
                { "hi-IN", "a82b89c5ff0751fd1f9bc9bea25c336ef7f8f6175a695abba44d147efe65f8256ebfd1380bd8f710b1d2b8adec55348cff693e62f088893db9ce9a4692a31ba6" },
                { "hr", "bc1f5157d70d5f1ac3683b9ad1b699a82c297957b39aa95bcdec0a15e1ff69fdc98cd899e91feaa21c7d12c0c2a1b2627c5ef0a81c6f8ca11abc5c69badd3a45" },
                { "hsb", "bb6390f7e3e60bf1965a25db389ce1588026565e83aaf3b705411dc2e91758e5617f20995b45fa4512eb5234b1dd1e0461885c45ab374fe9c5442570943d3c92" },
                { "hu", "ebc85aff5a77be6d6b8ced9b559b1bbdf4d8dd5a3679b186af9f5a13cddf0e7c6cabdb1d41942e8d8fb80962fd16a8340de5c234993b65fc86b93f18b9c33b99" },
                { "hy-AM", "330aaa98714677d499ffb26a740639d94ed23da648d5c84b79eda9d1f0511174cde565b04a7eefac846b82a809ce085c261bb398e4bd8a9afe934a9e223a1c49" },
                { "ia", "802d26c67486986e42e6cfc5f72f32f2a5f41161831494ff1b2f101ec9b022e136de9b8eea487ac081c3e209e25bd11777e001f94d7ec255b6a2989d132aaea9" },
                { "id", "024df143937db0d1fc6e02dd739c381e75b50409fdf9173fa19d03d803a3549156d4a2cca94a896d66bbfbd18748602575cb7d3e9c30a4c21e1d7c563a563a80" },
                { "is", "87de41721c9dd0148820e9272d5c71ec07fc8e131436e635198c6ec1e428acb74959b4be389ce4e06a8f84ebeac3a1511a3adfa5df68726d582000b0020aa3fb" },
                { "it", "0d0b3aef24c32363f6e54d1f9365d9586d0708df025c6832360043daa0f42873c3ba670efe70603863e87c0edd64c10093bee945ed02931205a5bf05bb93ffd3" },
                { "ja", "7ebfc6df7a887c6db4b5c275028cfab6565265fc20f4ae768610e80de713bbe2be0649ca0545ccf20e2c967fcb9873365c78de88dadb12b284b04e3625b2b2c2" },
                { "ka", "69dd41c23f32186ddcf49f8b18c89c8fc5a690e6d106bd408a7fde3cc1635bb6a568f7da830610967612b9b97918730d0e87ba948b086120402c585ba9de3622" },
                { "kab", "462b1f558cf41ca44524061e32fc496fd0075b1e1147128cd2045e90c7c698c9e0855a56ccf6c15a59391ed84656838e9484eb8df1a3f7d4ec63105fdec36510" },
                { "kk", "6e301f886911a906d4ccf7579f80614a163182fb4e74e0265ab864177a8d64f64732ad7233d37433fbb30274f18e771c24c916a747577e486bcf16d957014874" },
                { "km", "22d77eb1c5e5fc9353a352f07f1054f65a90126be6ab296ca85a2fecdc4099b7a3025d553d1cdad57bdc61930312072c3d0af2940348b8a04c28887fdd0e6358" },
                { "kn", "6a1dce1895b99030fec879cdc2e11fb654420654cef495cf40a0b9b7525bf3538fdbf3b0469a4ec938e577ee1a7479a83b42438c0d58478df65147648e8f88a0" },
                { "ko", "960ecc834d13ddd0efca330b395bafa4f4283b68bd3139d596b6811b33aa219fda3a5e20228f22d839c795a6001193c60a954eaeb3e6bd7d0c02a3c30743695c" },
                { "lij", "dd887d69358e36b69b53f58d0c226f2752465b0ee50b8d0d44c771afd44146296596e5580ff10337696f4ffdd0490778830bb6afef4a0de871ec43b657abe6ca" },
                { "lt", "ce0738b8eecf79d7c3d71d8edf05bed0492210ed85b0d53b443ec1a070c202a7bcab5a799b5bc95efd5986d3f3b58d7025c3505f04ec6c32f9b0a3d063bedbec" },
                { "lv", "4a78fdc3691a8ff7e7f8bb12d2623502a625040e42abe2334e446d995035317abed22ce9de4fb021ab01cc901895e50679d3f53bba7b07a644a5667345ade5ed" },
                { "mk", "cfd628538d82b0c39a490e38da78def531261727e17e49cfcdd5489f31feaabab4169f4eb22fd3f149dc21926ee7f58ee423b1f5bcd9f9c84da47a5a304ad78a" },
                { "mr", "b7a8ad5de300c2b2319266953c5249b89f2f2cee1bdf0ba3618b9ede81f01a41914fa5ffc0f2bba676b02421743cdc1d23004d5308b4c0faecceb891b70c5fec" },
                { "ms", "932623998bf259083486c3d6c126b6d171a2f3f8dc0f81316f0753e2c36e9c919bfde5dc961682909aada122e562f89e9ff14bf346079b51848d67fcd12bb1a2" },
                { "my", "45a3c4bd173f29500ec752db233782304a5790d99a98957ddeb14a3938d57025beae69ae6a16874cd62f272beaedbc416bb1af9041e18ae6d052751eb4e55860" },
                { "nb-NO", "6bef3459e82744137aec704761a7cc2b0ddfe29c59d68e30c506be9912c8e7c7b67524c1986733fd2cc7d1ceb10fbe993a850b4efc1b67e35e1a539530a1e8dd" },
                { "ne-NP", "7b045a5b81a390b808115b1fc2335dfcc85afd4c7b2cf60bffa56cda0112032c8180cec45b9bb73597394680e9be3e2b0f71d1057daf95e8ad72453d334b2a0e" },
                { "nl", "395df07d92b19cd1d8224a7f6a19fc7cc1c2dcf9042597869d09ff3a844048b85373a8f7094c6434405be827388a08f196faf7ed223486b13d4b94246660626e" },
                { "nn-NO", "bfc3ad23157be95c5ea3823481b627a2ea6dbbd7b1c9f3d61c41c113ebb431eccff5ebaf75f7bf7ed4e7dc877b5c6a22dc19039ecafd306850ffe723c7c19782" },
                { "oc", "08a74077354f14a41f5a747624ef7bca42ec2de1692efa0f71ac8c8e14a31a88aa5320c02ddfcb75416a26a05f8911f681d545d4975432e98d07e4a15690de78" },
                { "pa-IN", "d25475d1949c01751814c881250ac716b598e28ac6ed8825543e4b94218334cf6c512dce7269aaa597b7e024862f84c27b86c7a5d8608f84f6467cba0db62b8c" },
                { "pl", "3818ffcc6e20f3d8b8c00785cdad5364c11964833fe327500307e550ff361769ffebf6735a2402087da73049d39385658b055724ddf63a0cae9855e330dc738c" },
                { "pt-BR", "18e68acc3d1c4604329bb131d8fce862f053a5a83f1cb12c64edf1fc0a7dd58d7b4ec04eda8f222793bc821dc3a50ea09f5975c6ed37a336ed1370d9b9bc9af3" },
                { "pt-PT", "d5a4d3877326959e30d10603a28368a7651979b38eed3e883073f56cfdc8ea2e10712d6ea599a84519a6d78a98dd949311a6cdeb6b4c59c8d351104394ca65fd" },
                { "rm", "5c6ebde0eec70fe0d340977e82e04bd2109f456a1e5a6d0963e930843172f72466f84de1aff42f9ffe810e335772134e19fc1ee3418f73375535b1c29555ded3" },
                { "ro", "e57f7b9c0d2ff5b244cc6060cfdb1fd4cc9310113dad2e69cd085b9a5a0006ed55128830f7efea79e1823a6f414f6d69654db6d1d316a24e883628649f5c7a98" },
                { "ru", "a03ace3df2e773159d59adb6bacd1590e02e95f4c11525bb8d4d6ffaf2394594a0ba6ed8033677a5e9ad21f5048736eb8df656dd08ce7f934e9ba51452840a17" },
                { "sco", "38087ceb28bf746063f061faa1d2b1e07c840a178607e421f91673a7bffd66e060874ca7a4e1bd63e4304df60bf7467a98d4a9ffb605451345a359581863cbe6" },
                { "si", "5befb060f4d94fc308885a5676879c8392f876ca36197e63d2d030c735cdbc033b1149c5bcf73553c1f9044a85d5d490fde8b78ec3409047d00b6b93d849f0b8" },
                { "sk", "c042fd97d67fdf477be8f21f3a1e4a7a8f43fd9413e18386015b9998ffc8d32a7d78feae95ef1b78f2408d43feb10ca94b06de9081c80d7e65fa2385ee0c1911" },
                { "sl", "c4884ba2d0a00e0b88b1b60cf2b3b5c304210ddc40f759c96eb9751575f3208e5c7324c1d1fb35f319de871b594bb5571e4667aeb0f23c396131fde24974eec1" },
                { "son", "cfe093f8a2d26e597eba8c291ba91590371014a562c733d4b684614afb615e53e3ae2023d1773647800cbf992aa9d05c66fe72e54d8806e43d76d7792da380ba" },
                { "sq", "6f0f047a7c22c5ee96b31d70f88bae61d8d5fedaf5208c3ca52375a0fc2aa8c346f66854861c338b755831879375b90c27fd500d824e0a224eeb64ff7393fdab" },
                { "sr", "72cbcb3acbc444657892af5f11ab3acd16ec7c79069d8f53b73f928fb29ba899b48ce682771850c9c8344b2a72443c83723dc86c6ae493296e6925ceeea669f8" },
                { "sv-SE", "18bca3b4184d43eb2b7a97472ae38730a221b917ca096c7f7131bcafe69b04f83d47f840b8fc066cab25b8caa9efca83b0fae327c07a07c5c84a0024c04f1144" },
                { "szl", "e3f48aa4c0526350b8375a5519b6022a11680b24828687e19b502c037069ddcd3dcc25ababba63ac512f0d91cc984de2c78b814da95ec1edc3993ba63c027f07" },
                { "ta", "2e37be8fca9a3f2bbd27b9ef3ac74da034867557b90bf844d3e661618af0604165d523f42b77b1a24700c3bbcecb9a10575e8f688bb77621a56e8ccb7c47211c" },
                { "te", "b6d42614159b6767862566b562aa8430a6c8d6438713c6017a2191afb94b832d0e246c2bcdfa78e11a0a23a68059e5e1278fdffddcd29cc52ae460207291f47a" },
                { "th", "45f37828b1dec3ddc975f1d7cd6919c71831a95d2f689e870760e2ddcebbb1346374b3ca1c874b9af47bb43ef5bb68bbbfe3ea9b532bdf2f72b5d251b07c27d3" },
                { "tl", "1adbb1dba61a3f48ce7a712ea03c574bd5bcc03544e6e1491818987c2ed5f706947d8d9b06bb4cb4c8520e6f770e0a5df24881f5765f014bbfeb08250f1dc3e1" },
                { "tr", "526f8174aad9a2342697173ad663c05e10744ecf61c1a29063b8c97cd41635689b6b8dfd6d06ed96d06dd4ccf85cfa2390502cdbc1cedaa07d06384c349e1904" },
                { "trs", "e63ca9fece8f7a8ef5793e4c18d9c31bf8e4b50acfb0589435265bb6248ce16cb1195c1d1f3691d250be0e5a081161f00189e66240fabff3aa3ec9988716177f" },
                { "uk", "09a7ecceba1e3e59fad1bc04eae6704e44c44b46e0ebce3ac9aec6cbd8a4ad8de8dcad1e11cb7e3274fe6f7a7145353129e610293192a89b3810d7d0b9007b6a" },
                { "ur", "53eaa34dbf642a4c76101050531619da85dde44a101baa909b4f1d3b5ad5a19616ea07354bd4477261d653cbe8ee5aa503bfe12cb67b34e001774dca67c6bd62" },
                { "uz", "d417f7245e4df275c8ce287f9310259fa9c556c9133e2451aba78b52b4cf556cb7f02e77f58edc83fd1f82ca4fe809b5aad65dfa4b66c2597f68cfd41d503f04" },
                { "vi", "ce8fc46ea59281bba19e4bab2a0dd8ebc79ee6118dc8022ea2c2e03575f8b31a8551f6e6729ab3b7ced675bbe96e23eb5f6ba6b7c331caddf3c5e30869597f38" },
                { "xh", "a13ede9a78e35354287b5169a71c2e9de3228dc70e5edc5fc41f97caa6669fc2291f20a3b4be68f05a54faeeaf78769387eda908445484e7d85144cacd9acef2" },
                { "zh-CN", "87a7a789c915554ea21b5381cd80d1e32396e0b2102c254aeae279e8e0389ac304a0276a8cd74bafe23e1a27aabe74d2a750068fa6fb2936857db2f940115866" },
                { "zh-TW", "2fb15e3c8d8523f068b7af58b741315ab59705a26765e677812d70a2a12ba4d576f128bd9f7a229d15ece218793f4673e03b17b52961e5e9b8d3ce3643ae8ed9" }
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
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
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
