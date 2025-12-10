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
        private const string knownVersion = "140.6.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "b913c4e4cb31fe79670f5bedd1ec8081f151d3ed29faad2c5d4edbcb2df781d28854be4f4f46e587b22d1a55a0882c6ff7c2b2ad64f9c08c31e281c5b1fd7dba" },
                { "ar", "688f6e16aaa0e91b1479bd43c774a0a89145165465b40175a98681612fac21edb00fd1ae20acc7a884e7b59139aaae2ac868773e8bd70aa0f14fb50435b85d11" },
                { "ast", "829eac3cbb5d7d4cc827ecfdb49cc5e0921bfcaaca8b3932cb421d0cc16a85b59c102eb89010f3337db2ffd3c05d5060c3173373bfe72d92e7e569835f786ab9" },
                { "be", "aab1a295c6525f7f3fa538c999fa8e581caed64004091d3522934da11ffe2966fa8039e363b5b75f20df849fff2b9f4f145b63c561c32790a0e7436c8f912061" },
                { "bg", "1f40b7511ccce5fdaea031459da79fd96c9284dd8836456cd3157a80a1812f0b08e39b638bbcf00f21012f601c9cfcededb0c4e5005dca744388b1dad97b105b" },
                { "br", "6a3a7530f6d7e973e49760e0670a4b7afbb45f53f6ab9f133b444440ea3c8ad30303261ca255a904a11d42a201c96baaf63a89e0c06080b70b9aff9a812a02d7" },
                { "ca", "5c3e57f0399d103cba17cae05c6673a58a2bfe9b2a791d46c2c664df61a188c2df298cd08db27d952e8d6e516c251fcb2672c20cf99070619ef14333da6d9ce2" },
                { "cak", "1d67efb0804236515bd4ac4023efa27ae19ea7076047854c6465c7a22bf6e2012d722ad1080913e07d7697fcc39f125311a52b0278c50f24dc99458c3994375d" },
                { "cs", "14e75bcbf81842db2618d6a2bf0258cfcbd23943428e5a51db7dafe4d2e5249f30c4522c15b4a56ae7451fbd35ec2c66a10a3dd1d224f39225af7a8cc940ed6a" },
                { "cy", "57009c53f0022e8bb5ca67246841dfe358cf79a16757d8fa6c421344ee720fa30a852511f3a86065345c4c7e31c35c116eb618fe5c744ef0d63bb819b6859c0e" },
                { "da", "424725c6b9d2f331fd5cf3332a5bc369293fcd5a6da279c1bf6af79c4d25bc52b8b1b46175e785bd780a27c98687f820af7a01de73d5ed118ca7e67c1748e4e3" },
                { "de", "d4e533d5c60e9f7fe1c5d3e2c3cbd9bc15a96d0feb6126518a242dd8722c7b7fc4472501984907e4425383e93ccd58f90c8672c6ded64e39d3a4b2976c4f5970" },
                { "dsb", "fdc867acaa783558081e12bc02e3c18899bb52d45bdf8bf3981bd3bf925eef8e7afff2b4656eac0f26294f7b18c61b1540f806c5cceef2dc184c3fa96fcc2320" },
                { "el", "dd225e0c9d8027100844cdeb0d789cac13ee2efac68f1270cb9010609b086f1e61b38b3163b569cb56baecb17d6ca9f7f145b0e83a7dc04248c3680aaf2418d9" },
                { "en-CA", "73ac4f2132646dd2a20fc7dc15c219bd5957f4d93d5331139c410fe8c20b2200b65324408bfe43884266b526cd5533440c7a39fa2b4dbfbb954d2fb9ea902f2b" },
                { "en-GB", "4331d9290decbbf23bfd8a210a7f8f578b11122925cc998ab12751fbc6ca0ea498098389e9203a2ef286b42109ef1938476fa60ae6b31ecea9a5f125f51f04e5" },
                { "en-US", "260ce249e642a7145abd62bfb5b1c1f846dfa0d3ed8dc004d27a4e25c0edeccacb5b172d7585dc316037929730c9b5d7fb32363407f9c60efa91e32f356a41a3" },
                { "es-AR", "2c5e5a8b09ce247a1a34c907d01127f521afa4c13c1ee72fa2f31f7f48406b1d0ef37398aa0a38e23b0e2fc0949da2b1136efe9126bf4984f697693e025cab83" },
                { "es-ES", "67a9d6af5790d0fa55995d065b4d873a1c4b2dea6c3eccc094c076652242637d0fe0ce74ed70f516b87d1ba32e5aeb66281b7b8ae5da88130da0af2d9bc4e907" },
                { "es-MX", "21c3aed9c93121ca2ce80e5b4335c49ed33f461f3309e633c0e5b0c365f800df470bbc6715bcfdcc37f21c98b6c4c1521210bc92e3dbaaaf0c0fd40e1c92717d" },
                { "et", "e183fa747b7da54f89ecee14918e2daaa588adba2b237e32d2500e24ebdb6b291c93122b1f32d15151d306b039adba9368ae64fdbb4a46a6e5563fb8ba439cc5" },
                { "eu", "64b2831af8a19a16a5c7b6ff22c615ff335d60ef27ef26376181f396dac6737f8cbd3f66c9f6254fee2c65ef62110f7b088594b5c2d0468b9992d015fcdd14e0" },
                { "fi", "9f7f010aac7e1d5c8e953fc8ce4d192d9524936eb12272ebd7a35e21d6c5425752982024289eed0c5cffae610f1b223d54d975bbba072d7fb7b209ccb9b877c7" },
                { "fr", "26e2cdfe29cec5086ba8e7211827944a070d8a938744caa510c7b909c12bbbfb99cb458408b63c9c57d48e047f3a32e1d83a5c23cd67fdd3884e3ba1a9974c57" },
                { "fy-NL", "6b985c9cda97e00044b12cb928b29d469764db5a437c32ac2c30585f5351c108a627a0dda3c56e5e3e4db9b264fe5792d34a062960806b9bc1615213c016a91e" },
                { "ga-IE", "c271315ff1427eb63c232354b8c92d282e77c2fe6cba9ee3f1462d8aba3b0e6bc985a9e1fa3489ad35c544ef9bae9d9238b16ada97f94aa361a8c818caabb0e5" },
                { "gd", "a76bd9d4c2529e07e8dc34425001598dcf0581594b67c4134adf25ea0418f91f0c8d8bc63feb8ab4885ba6f6424c0b4107d63432df1524c0be056d23c3e13f1f" },
                { "gl", "2f6a67853e77e5c71856e92352ac1db00eefada473215a559b4319157cd7fc588758026a5495ce09f76b2a1a31286b34bff251ae905475f440d96de9041e5105" },
                { "he", "cbbf63e4f11633d6a2da4dbae5b33dafdd53cc788f10938107ad07dee59a60d2212fc0238f8285d0d928f21439dfde9f9fc98133de0b502bd5d7f5c2246e0c1e" },
                { "hr", "46923fd1cb1d838704dd474df63d7a7d049c7c05ee3ee9901b604fe44af66306ca21ae9d1884aff30f4145b78a9e4e81292e7a000110e5199ae0544ff82f1ea7" },
                { "hsb", "70ac3ca7662ec3955b956c059cb8ccc52fb252901739cfb4caa2bca9eead685b4c6b189d0e8bca7af958093f98e7bf1aeaf47c67c2a2306b80a4f543d5a1fc6a" },
                { "hu", "09646c753b1d4e6530e443f73f7872c1a82ccb89e60e7fee2cce69fe8a203f95abce2dc25f4986ae58d90cffa07389ced40a416ba90e0c509fa26351cae571b6" },
                { "hy-AM", "8718fe94d449dc48985bd06335dc28fbd2d85f8a75f84d467d7b1761d04e4f79f5433b39e88d9aa4ae96e2cda2e44892fd650b890ac470eaa6b3dd6a1ba4036f" },
                { "id", "a89efef993ae478990ee5fc6805d04ddbbb8af6758448ca1ae41ba39c6e436f6fd76afc3ae13308cd171615d54906389c846b77ca59cc64577c19bac8d7d8d37" },
                { "is", "2eede58f7aebf90a3167bfbd3f79e5fed410550a1f352f04d2e54037966e81ebce4a6d565cd9e1cfb3994286a02845e03d5d544e7397869aa7fa9799ec24552c" },
                { "it", "6cd11e439718718aa46bcd3e16f2415e1c4a175fb91c917fa937de9835c6ca6c9923bc69c2dcb0752d9ce37cad7f914bd0a32ecbe418afc6f63ad96e65df2ba7" },
                { "ja", "6065c7d8a283f47cf8865b528d280c55d25d9f8e2690757638ce07f8f9a9f2c302d6111a72ed51afbda47e14bb8b8ff49fa2f7de2c6e47157ce4d523ab232003" },
                { "ka", "03ffdf740e09d3f135fbcff80d1c5c422f59aa1c062c3865a9a9823b5ce2c129c350c96fc526e27246b49d058b4ee2403588d4b3dcf5f77c3e3060cba3c8930f" },
                { "kab", "059f014fb66569b377d39e4f34be26eed28ea7f77f103dbd39fb1fc5174c65f65f78094b7ecfd0c01fdd8cd9985a8faae2b67a6c7b710bb4f7f20baa3213e817" },
                { "kk", "f2429eaaecb559677c71b68045ffe7844282254aabdbbc9f5463678af48b4cafe44be1d432c00380116d5854b98d1f6e96cfcb4b1d93a5cb1419adccb5480a74" },
                { "ko", "a5cdc21855c691f19e28011c15671b386cd10dfa51c379d6b023ff215c6edfc380640455b7f3b48632c6bb20e9a02e3cbd26af3758c4f02a1827c9e2289c86cd" },
                { "lt", "812f1656fc4f3247cd15c422a9e98600fa498a7bdb16f781ebfaf473f79b47361db5de45d8d7e636fc55fb9fe027473095236b1baaff90ef6115bc1e22052bfb" },
                { "lv", "03c23a79025001c9c74fe06c50d2a9062b8a095b7880b2f1b88ef5f5ca5c04a1f061cf79e59528bd866e2fb1bdbc731e495a7085575bf9be01871df94f12a050" },
                { "ms", "40086b1a0b65cb2bd04b1e676886299ad82871312c8227c34694b7f005f2a0e359160f9b4a5f656ef4e64b9dfbda2565ac48eaadb7d2e687fa1259172a318b68" },
                { "nb-NO", "29199b97a96aacc1773776a02413072e2565320186c24b4313a836bcfa39c9e3af173201f6105fda517169eb6023db4cafe64f489b41995e08d0f872b0fa5663" },
                { "nl", "11966f43402aed213a6bc7efb3905f678d0646dbaa32ba5c81ea0d9ed256bcc3177c487ef60447f6a3ed627414a7769d1e58f3d0badaa458e61ad0524b05696b" },
                { "nn-NO", "179d7dada62467e9637b626e55cfb46cca5832c9fdb26f5d2aec0485bede040eee39fd48b8a9a47516bba8010530bcad4034b58e7f9a1cccaf9d7f41d830da63" },
                { "pa-IN", "c891a8a21f323f709def97ee4535b5c88eccd28cf2ddf3ef71f5825bffb77592d9a19269ff3c3084beb928b5d5ac8ddb49fee289e6d2427a49b32905fd649eee" },
                { "pl", "ad4bdb0927ae12b991078b570ed5f4b0b267ed8d1c6fd822f052ff88622a95056bfd072ea90c55fe329f3c62fb4c585b69f1bc9d5d1d667de1c76f7df0914007" },
                { "pt-BR", "b8fe9ad2fb11387a0be7c96341a1365e6dc57325a17d62935de0fd5d3e21d635d7887f749cbc770a9654b44eb61a77fbb5a188a72ae469da2cc6aaefb398392a" },
                { "pt-PT", "c85321fbc803eed4bca756a40a703d933b9f23fde056166137a51a9917dcbe73b2e7ba4e2f771c3acf2747f6116b572bb94672414237afad2e897ef5dd2ec4c4" },
                { "rm", "b31f204e58f55ebafd88001de25f28866b9436464b6d9aea498a5259af0600f671ee1458f937b0bd54dfcb055a8a9bd344d51cfd6677f581bf9a04ea2d0929de" },
                { "ro", "1b89f7a8ce83e4e43a1191701ee0ebcfdc0f2b9f4e6e29c97179e083e706af8bcf2d5566c5f64d1e0447243418f2598c33a807606e10733932aae3b4277d5126" },
                { "ru", "fb11433dd88827b4580878b68b01075f2f2b803f1678ba1d2ae5cc0b52d963dd983fc5913c075b2e31cef6b05196c491d63742c7c807f1b312dfa08177c44f14" },
                { "sk", "2b12b2f50d827852800ff4cb1ae972deb6fc3e9a745e911e886cf6432042f72cabb9de19a37d6c93ceb3354f65377b34225dc46f370ed865dbcc0e9f82554428" },
                { "sl", "674c610b3efc773a20bb7b68216e80fd7b2604c4195b6cd1c5eaec6fa5e40316f1f812a26ada356fbbb66c16a1195628572a17537ccb080e88362b698520e713" },
                { "sq", "e535ca45ea025894da360ec467162a9786178144344ae439bfaacf420ac2bcf13ad193096b3b37599205693e4abb49e0e5b1b7728a3eaa5cc2d57b16de6641a9" },
                { "sr", "b819338cf370dc18b1dbb9ff592a4e96a8433821934b7f304c4c3d7c7b99e5bf7a19022ba873e5887911cb6953660a8f115009b5626239bbb760311f530ddbb6" },
                { "sv-SE", "fe37fc2b3597ba0940699375b6a2ed3b5df73cfc9021b316001dc5d628cde83ffa05bb8f40bf968a9886ae5206f2b9b2ee2a8784e3239c552b25616c44673125" },
                { "th", "f72c944a31c7426d4d4274ecb326e0e20f2df102444da946be581d2858393a2145ab7ed5e42ad91b37fa2cd5dbd536483b04e3f5f2ef9ecbf79e31eb902cd4d1" },
                { "tr", "4a9d6a84f2a6b6718ebb519578a93419fcfc39d6604e42a34a501973c87caf1e9b4a9d596371a2f83554f967e6d474897ba506c92fe3aa36e685eb549e337733" },
                { "uk", "05b7bf90bd04e523b3d676f704769b4e777a7912a2d6af4476534ba8468f0764678604ac4c815adae294628685c1250af4c79e11c1d34336c0332c1a676f705b" },
                { "uz", "ee1ba144570bb3de49f2c4a884e7ce2b2a5d66479eb8aeb8f16c2d92fe5c5e905ebaee32fc75adc9cbb615bc8af06ff8772103078e6ce5489a843de72da8a7b9" },
                { "vi", "74927936a8aeb784659d5656ac1b03f507e7f2c5a766ffe3cd76df2d2a7517c3740417e9931e4a867b332489e93d3eae9bf54307dd7a4bb4cd9f05255dba271a" },
                { "zh-CN", "aed581cbd3d08b18c13fac3c824db34bbb61e80baa8b9ff47369b06287e58f4d91311a055d41a4d2649786aac77303772a0c3b6c4125894c8c5b5c60cf50cc47" },
                { "zh-TW", "d612f963fda5d7552f98706e5c7be5a8ab706fc9560757d1011e779f807875a8eaa0da9db4bf72eb619c03a810f450b0411e63b3138bd1a4466b2a97819e65df" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.6.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "ea3e50579ebb73b8507cab4c838916066512fd9a76e884d21493eb8e38fd4a0962f4e214ceadf68a69aa1bb0938c8f984bf1f901a75ec8bf71a4de819f77537c" },
                { "ar", "5f03b2f5cc62b26fea07133daf6f9bed43fea4a4fcc24e8b2fb2e17fd54c69c5002489e9aa5a206ad5a267301fcbae630af3242fa6b0704835fdcb01817f99ec" },
                { "ast", "c8b90d632acc69eea3d970aa8a62093f981acf07cbef701d4637c8b5efbc6cc340e059679a22bd8861a9138f619a697207b9f79356c9b0bd92f0eeb57138a43b" },
                { "be", "3435b501b8d46e67815cb3d74efc9a6d837d568a0c2d74fc70740db525d1aa01d59a9b8498a26da3fb921fd2a296dd3bfdb5045d24b2c60173588f4ac4d21041" },
                { "bg", "3f9190026a417f6bea1e6d94e9eb11cd627265d04fd8b102d8c22a612fce3312efb6e80cce40fa49223aa325ec3ed75e354f92699fc1c69025bebd1001c1eb3e" },
                { "br", "35e4da9c40ef156add105016a9794b9e56d0c852289bd9bc6f020a67a5d51634fde2a6b0b5019c923145b4e94a9d2b6fe40426ce4e9493b4b0e8521d0c10b66f" },
                { "ca", "f0efce3ed062fc49482d69013ee5771c898087492e4c67db4600d78a4d30df1701ebb0c5c5a469c88d780835f1dfdd4ccedc8d6add5e380ae1a490e77f26fa11" },
                { "cak", "98c60a9500727c3e1e73b57add1585ee688046ef4699ee87cd972873d8729171e87226c3c904882b97d1aba1894eba4727611af5e174b610af0415a922a9bd82" },
                { "cs", "416b47ada5b426e6e0413c9bc7ed0dcc1911cba1a74987e037191db13086e61c184f2e6de21309e7c06dc124adaa708442ba710d665dd91705e42b594c532b05" },
                { "cy", "7b16ed8646b69ce6873a71bf670bc85a2a4cc23c2767e3937e9d16e944f8cf1849675a2b3edfc1a4a28fe1f9218d3961cfb481ef84c95178737d78b7afa2dbdc" },
                { "da", "c223b7cc163c976cd8d87e8e76204b710f2a2241f970bebd31edb91c55d47716f439115b2e9ba49242a386b16671f7bc39c47bacb6362aec098cc9e5e123310b" },
                { "de", "6c28b7e2cfa1e37c009555d17584958dfe073e7bab3595e7e4b3298604880899a539237ebf5fa47bdfe6b1aea1bb3e91701f97cec97bda3f02e785c7c6689385" },
                { "dsb", "7f0bd067729945eaa674b47ddaeba9ca35830040c0d5d050413b2aa205c9d696965e1d08fb6fc4a70e9efe1351d0872bebaa646a3de9a6b49f24d49bf48f061b" },
                { "el", "8d48e05fe6f39bb6d789ad39416d4bd77f32c576bbac97d452bf3b59b72d53ab2719e6acee1ab51ac300fc7343fd8564531e5445da791bea4844ef939bafad58" },
                { "en-CA", "f535a387c0a9cb5c12dd9e15a41df2a07897b0e1fdcf1b7b35c8485e8fca11e932cdf5b9855fa13f22224c8fe2541def1c9b42234a43500eb961c15cd3aadd40" },
                { "en-GB", "4b879767fee3b768aa70a55b3f0bd1838d634de8b4a3a1adf3d7301f88ebe38b152db72ebb67e1c789b7a069e7551b19a67b2dc4cb27d121843ee46fd8e5a65f" },
                { "en-US", "3fed9a2a62956450c798af95455bed97368870809a4d7f480a3628842f82f37adb38b5d7e66d2d94993316a9bef856ad66f9137e0141acb2faa4672055da0862" },
                { "es-AR", "e0af55f3debdc6ae54d4f0fa5afca078c1c2ba86db440c16bfd24b59ff423e28052b94e25ece4d9a7d0edf0a64f1de25d1b0d17db347f33fc71a02ffc3fb23a4" },
                { "es-ES", "8de26d1a78435eb8a23a213650cbefee1184bace3b27997994fbbf909fed1223b9cccd61e5c89d3a881ad845ad8800a9f8434448a34c3d0cbc55836b002f3640" },
                { "es-MX", "f9ac692fcb15d42751bdd8637d5945f6914275fa5bd409f078c523fa6387ad9455c6f68b41c9ecb1d474232c0b602db5a98ef4d79c06a9e23db0727bfb43f3a7" },
                { "et", "d4aa175852b9f499344a0c9afea77442b32cabc69f29d387692585f8bbe486431ee1bffc699e8631d7dbee6ca4e470a2cf3d6df0427ebbd177cbbb5bc1170e53" },
                { "eu", "9b970fea2b73918af56f7314d746d7e50aab8896ad83b0580e0ad7ef21463801aac0a341cfefd776922e7d1b13499575d67efc24e423c60c60c372eb978c63cf" },
                { "fi", "24c393e09ba943bb549b8cad35f6e296b2779ba18412af43b011b05c7466e5d7421df46ce8a85086be5cdc3937153fca5e36ffe762ad8f2ca85f519e0706d0fa" },
                { "fr", "d9d3959c60feb165c25aeac4cf5e15eb55d62c92bce1d1f1354f4df80bce4e13c5bc6d52b72b275b198838348c1ec8f363bb67cc926fbcd9e1de92e6e924e2bf" },
                { "fy-NL", "f05332f8f9ecfe7f6a6c70a695e6cbcd127ba63c58159f625732af71cb39b06ad5d0f122f98fb933ab57029458386b0b7b8f6bab556f26ede4e863865c647b7e" },
                { "ga-IE", "5afa594a3abf3c7ddc2e6c3111781fb9c86fa49b97c96d324564007f5ec8e6f262a1845a709a6814687dce852bc056ad4f9fa17410ebaece5c8c172b97f15d46" },
                { "gd", "4d6d5182a8de7ef3e65ccc4ffd246121a44ad953b495c347d5d4cccb97c66dbab2840fc612a1f82cd43b47f69cde0a749966ef7e45a33514936439af6108c503" },
                { "gl", "510cfc54ac8d39e3434b9845c246b99f8366d4458dbb658205e1bcdd20424443e024dce6328b81e6947854257282584814dcea544fd52dac369cb7491720a7f1" },
                { "he", "39ec6896665ac0abb2f6828423d46cdd0f240bc6a3f952179e02e41951572b3fd8bdfaaf7d375c0c6fc27eefdaa9e59a73d7f2a56663ef7689044952b343ac09" },
                { "hr", "57ecc2009a71b3b92db19794cee12586f9570b050fd75cd2bb4bc07b1160fdd7dd54974c2837631dae2c8b11f7e1c89c899b577b645a911d6bd0c4c9f017c605" },
                { "hsb", "dcd18d09c6be2ecc91bebd43417f5be87dcdff9f5ac58e93ce6818c880d89f0396451124ac1baf15b5db46d5929a1020c26c73521ae0d9827048559b6bb5ea85" },
                { "hu", "ae7f3125ed9b3d4b4863e7655054c08304e99dba94a9f4cae5239b666ce7a00ace584aa94be83b25b0e1378f217023833ad4749689b8febeec433713b51e6031" },
                { "hy-AM", "241d01db5255d2afbb18ba5716bb5777545f3d43c51de09341c1a910cd336672536522b1c30880f3a0c2265f17d77ef05fa1292c9eea9e3f14fde96c08657b7d" },
                { "id", "0dd263002378a6a6feaf13482a492978c23a7918b5f9a28e8342b3c568f5c6a1a0f4c237af8a34270fe4ebc3218d7c384b8098a834e2b777b462b32156184e7d" },
                { "is", "de1fc76d6c8070649866968ed4a644c556a4d15d1dc0ef43b70cae750b0744283e6b3279db3f6c6ae0005079efa50ae5f66c181a8cdfd025eea045b6510a9201" },
                { "it", "b39f9976d9e2f8c35a073ec7533b4b5905e6252aa51bb6b01f676a33dcaacb30a026077ffc1aa2a93808b6e0dd6fbd3d5778b7f381e4c61903da2f45d1a59fae" },
                { "ja", "f24da564b687a80376f97e96697e99016b7a8770e3b49649dc678bd299ff5db8f30c3ad5674d8ee59b3f70128cd16824cd69e0e77fa76d7df6b3e6784073b8bf" },
                { "ka", "c8427137e5b97c3a2afd86945431d4ee4273692522bd339d226d851efd700a3d83eb487c9bee7408267d531a2cf285ab3ba28311c584f008b40b55d629a1bb38" },
                { "kab", "3aa571a2eb6ba51fef3fbfe9e1153509f64984545f9de1dc44130901576de819e23384bb1930b11985aafcb4906f16ee223a99913b8854a6ec84defda86dae4d" },
                { "kk", "ccce63408b14e4c9dbb76b1fa716ff2f113f5d4b7f02caa13b4ad4539ed65623fcd93af0deaf9fd60419afceeba41470a9f69ed489e6812e5d3a9f96751eba27" },
                { "ko", "2d91fce6430eff3d816920b7fc197d33630b2cb3b2f7247a8d0fee2eaf20872561db031f52936fdf8d7b2536647bd791e772fb15c9a08a67a1286815bf7796b2" },
                { "lt", "055d78135dfe3ab75f07a824b95a4989e6205024c79adff86306854f50623e3f88a30382d349fa1e32712da3e6c81511de8e56fa7c6173f78357461931a6de08" },
                { "lv", "9e865403e6f18cadeb3f91ec80c892aaeef19a37ba9fc9a00b138e10b1de6fb0ee6d754d7836768502164349f4f28378931bbd4f078762f34ba04894a9026d4a" },
                { "ms", "3074af12ad2431045d783b0852cbcc629e3b8809ed6ae1683153a2bd4ff42fcc24c92a41a474f42637f5e39e50e909f7286979fa878348cbf5c246db37905232" },
                { "nb-NO", "d37d66ad4f57b3bcf4ddb6a307fbd9fa8097afbf0375b3fe0a554d00539c6235ce2536a4009ad15537dc11d6ce76b8446c52b3e5aa5e5ee80858137cf9d35fea" },
                { "nl", "6bd73e8d39ec79098343f66eaa487c786234fa0fca31bd47898a8b8698a9263b0819f1cb27a5260b24a682d29c7e8463a7f3e9c2983599ce186dcb75e63d4d77" },
                { "nn-NO", "6577a3a7eb765711f3394daaf494b5e46fb46cf6cc62cba6fa0ff8d24c0e009b0a6107591d98097154ffb47839ca1ee52def232cef38f3b9a27a6aa223a03e21" },
                { "pa-IN", "a6ce7ad129922c32dd85fd7d881b2c414df638bbd0bd458471fc2733e6d7627f0ca50d8b588eb72b4e674b38828982b198d594b25aa13c63199b998c660a67a0" },
                { "pl", "244b3f1bf8761978230e681d828a09dadef8f01454f09426cc5513a5f86c6bb5d7261e73331e809bfc965babd4388cfd3244628e310bee679d2216d27ede4a35" },
                { "pt-BR", "af365ada5acdb6dfe353049c68deaad0357c3ba299baee5a72de3f556d77f4732be197cc1b5add7bf3c57b6f8a094bd9ca2c0ce0edd67e0e2b041c26aec3488c" },
                { "pt-PT", "eadf53327de9d9435f8ef10faec220a6f9d04d1ac6a6f5163bb71e1ae1a09fd45e762028de8b1f399d842639ee1e43a1aee0d887ed9a5becf7e21a1cb5319582" },
                { "rm", "d579b83f53663f63aaff2a3658abdc7aa0b3cc151e9a3e719fe708631c5b7b8161a2236cbab393ab38a5b8855ae1fa972e6666331da1eb9ca4c8d3994782c07f" },
                { "ro", "e722c530b92208c888428604bb282990a450203574a09c3ce0495b7504c162fc2fad36dfb683cd53a00f4771a7708943afeaeb48b0764e8eeaf1b7c8516dbca0" },
                { "ru", "b89d7c90a7f4de83e337be60645a69a537c3aa4385c13f17794bbfeeeed6e13e96f274bffa594d2fa98adfb5a444ed7516fa404a522b041d3ecb562307fc6744" },
                { "sk", "f242232b265b131cb25ef29b3a118f34a5d65866ff1c8beed17318e514a315f614afe5fa573a3b4526b6002d0aa6ee3180bc10e9f12445c3783a38cc84353e5a" },
                { "sl", "cd92262bf458417bb04a8c486a34bab151a360f740c2fb42a254705ee4a7064f68b597521e2260a0d5219df27b63f1e178024805320842123ec34c5d08359d41" },
                { "sq", "cdbdc02e6dc555ce121fad428c9f2e44fedfe71c789b1b3afaafebaae8be4f051f8734c1a0e7aba943c3386d0122c886ae7731939810d7f8cce562311f6bd763" },
                { "sr", "a2d6d9be47db94c55756db18efda7e2546d8fb1923e1ab18bc84ce762f4c2e548ac9d8ded1b94b5b4e960007ecc2cc5162ff5225ae66d00e115bb68ed6eaec6d" },
                { "sv-SE", "d02b707a20ebbd193956ee6ea2af0a9aefa7a559f4fb58d65ee5305ce40444923d4ea7f002fe58b0de9c900e4b44da1a4063770923376e2eef250a8b512ca05d" },
                { "th", "9b552b13cd27bda407c36d2603b72ae44b4b1cca7b9870e9b607e82b661994ae3131883e75a4e793ecbf517c6bfe95a53080af5aee88dacbcfb89d3b86b8fe72" },
                { "tr", "98a7b5df49a1aa5f5b03dad13f4a724e6affa1cef937d2837ef0c951e65d9e1344baa0f06691db2aafabfb410f459940396490531837e65858412d531f92a23b" },
                { "uk", "052009a30c9a6ec356ec113a6ebc5a9e62948c7d042649a31a3b6341162f0a0a467ffa1c7ab203ca4b254f3e60b9cd400511aae3a6cee9924cc6a91f8ecb7d9b" },
                { "uz", "019b4e7fc59c17a4953f506684fdb738d089f7c91bdc400b4b8a2af3edcafe691c334720764a852e5d6828a6c4f0aa25580ef221d618fb60a31ea327803b8193" },
                { "vi", "c6fd1b3f53f347564f365bf6c0acdd567a31d39c56e9013e51aa5994ed8794bf595b19565379d7f1b6f8e7fc22de4360a44f5b00ebdddc523675c7089203576c" },
                { "zh-CN", "a7c358bc8aab72f8b3eb9cd28735b17ba03b6922200245624bfdf31352275a0afeeb4215777324818de4a4ecbe8e7582d6e612df7c1d5e012660ef65baed0865" },
                { "zh-TW", "4d113f4a3c8c13be1e5c0c19946bdbc8ec1cafb8dc9fb8bfb922e087da3942c8e7f68c6eb4c241e92b1b9f6c5f80b67f6f4612154e141d8c77a9ba8fcc2ba6f4" }
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
