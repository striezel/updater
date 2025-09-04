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
        private const string currentVersion = "143.0b8";


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
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "62fd00bffa8d68264e2623ef0759a9ad7c314dc982766837e4d7fe4a7dd4d795c72e46aec0c73c2ebedbb34324f986fda561e6cd6a8422bd7405f83d8be29335" },
                { "af", "60b2fb992a07bc1f2059a1992cfdd9e126a001b9d2efbfaac73daff14b5aa19cf81102947d3adb8920b8edde9db2203d06512ba03ab1d07e4a9087331f304589" },
                { "an", "c012430cd7ed919e48a8bd5a6d3f1e8d8884c944525feb70982961a627b7f69964bf0e72550fbde02585b9c120ddb993c4a30024b604031b998d90aee2c6e8b1" },
                { "ar", "487485eed4778c03e8ed739376a4286c5cdb84e2ea3cd010081ba58402ca37c777b30afdb74e606f77f70c2dd9cbfa88e79d0661981332eb3c48b3cad46880c9" },
                { "ast", "b3d27b0aaf007909fb7936995de3e179d39cb77973199e38cdd30c843b23cced1c3c923308ac938419928deff765e2cda1562d242e18592f775889c68a91915e" },
                { "az", "65d46a2103956d34f74fd619157f4fff826286536d80ac138be65413cc7c13f15a71767b3e1ece4ad3ade829a8c2a8cd74a6ea45449ce08aa0beddefe65d4d55" },
                { "be", "b6f7ef7e7ce7f93177896d0b783febeeeb48b65fd086ef61ef132a0749cd62fcdb4d2f0edef72e7b1c6baf95a2ea39e2e4159b6dbd22f531c41bc58e36a6d587" },
                { "bg", "cacd2f37fed06f9ae26fdf10e0d6c72e2cdf939c64822718e5c9f634222adca4e3fe8d59deb21f7d1b0d9c6a80a689ca77cc9119beb8986e97eb318d385654a2" },
                { "bn", "223016d6adbed32828560602c86ea656fde27656e1b59fdf03e6ca96c3f4a6b5bade229bfa334ccb00f0c0ae5b5222f256f7a12b3c2cbedf4ac34dd81a50650e" },
                { "br", "9f23b5705d7ad30e3a26417653b7f0f8e95c2edf580466a3803be6417715185626a1695ced80da02d8c957625510eb6982d59b5008dd25875dead3e93b1a3516" },
                { "bs", "7078e41eac0a0322de126f8991550bd458517a53f70e3ab08c312f0b7633dbac4f237f15788a892771c92452c18afe86f099486a0889e9bfc48ed2bb7f8fb624" },
                { "ca", "f6a8f2ace183a720d7f06e97b2634396c3afbd8663397daea95132da1aea6fc78d826e989eca182bca38bc357fd8502d3270eb287262daa0818fc72e1838deed" },
                { "cak", "0217416b50b9d74867056c2940b8cfca85282f80998e75b22171574b0b8eed5d9f3c39196fbbd7750553d62374c73ff20d609a9bf437b11e9e1e26770d6b3538" },
                { "cs", "90a3c7f6b82b0c03d175e6ab400ab8501e144a8eb02a1f6e35e494299871eec3d6514ef19707f11bae1d7a3897a4fa3b18ae266f9d2dc24761e45ef1c35e14ac" },
                { "cy", "8c54dd1e433db9ed736f4bf0f1cc363365181be99b4f6b540721ffc835656dc9eedaeafb071edc22ea558fe3b68eadb87fee69cdd8bd7bbdf53d48be31e5d5d8" },
                { "da", "fbb0ba4c3b205f668e9b2c12cf3055570c6e0ff60de94eb2f4a7d68c278c1ccb8508f496f85f77fb8e1e61a2d79b8b36bc0fc72f83b8094c09db3ff2d4ec0d49" },
                { "de", "d45770daef967fc34f8414ed0cf7d7d7eb63df97d75afe98083081e2e67405f8cdc673e92b40218fdbceeaf5ba8099906ddd8849ba7e718d02c71a4b81f13c74" },
                { "dsb", "5e6f2616cf1250140c674e39d6a2e93d964a124be7c2bbbfd5d1c29b202b33ca67fe48a8dcfa6f537b6d1f2f79a93bf942b9b5d6be8f04bb289cf9afb71978cc" },
                { "el", "f43c1a5bad7bb32cab4c6d8f960dfba0984642a25f45defd7b81a3e1064824e4ee9e739dfa22ffdc2aac753aa6d8bfdba7942a53cabb2c9c557f655e31588eea" },
                { "en-CA", "8234b9f7eaefc4bfde49dc07b231f8c7fbbef674cdde7b7685f06987434e263738ebae8cfbecfbe438dba398120f3278367a206589ad409da75b5a2edef2d749" },
                { "en-GB", "b33e03a6f215fd4e53611bafa2f7f3b28aa7ec973f7876a84e26bf8defb6c2adda295f0290d6cb947e6a9525b0df18cbd3f77ecd32601fc7cabfc98e21ea6195" },
                { "en-US", "1e7a92644e813db37d056948bfec00accdbe18168d3740a4bb7c0ced7ef13f43319c35428b15eb2971c408e1e3080cd58e1b296048ce3aadeef442731554e601" },
                { "eo", "f1ccd573e54b602311a574cbb264c70e94366ee2628f0cd1942d9a3bf76a8a0e4f7c95e004086138c5fa07f850f39cf2f7852395245ad2358dca99ed65b8adc1" },
                { "es-AR", "4cc403ecc0bf81716cc56af01c49ce15ef7128d92106bf37e9aea3d9fd9ab915b8860803b318b8d2e4a72dcd4addb7d8b609264e09d1c763585e08584753601d" },
                { "es-CL", "71bbc77372279788a8901031dd9fd8b3ac4d8d4a36f9ff8b1ed6c7ae72ad7dc2c4e0d523d03c85732deeb32e15fcaca750c2955a38efe5fbb6bd7b1b85fd3277" },
                { "es-ES", "064d085b8a939d2fba6e509b2dba799b9031ddfd4786b35fa1e2ab5f17619ac5ff2bba94f1413aa3b9db806bc7c58a5534ecd37ef80fcab718a263f6c3caef2c" },
                { "es-MX", "520b5fd38ad9678480884f45c9270fb4c72083ef7c12bed88fd1985437e5a249440010667098bcd7d19b8712a0d76125ec104f3cd7f1f2fe4642693ef474be1b" },
                { "et", "5f597aaafb62342401da29bbdaee44251cd39316a9737eb6d8846a189184014405b9c525adb3ba812376fe150029eb0d70daa0e1e4014cddbe93fe140a89ac62" },
                { "eu", "c1b6224434f9834941958cdd0d8c7b3e12901adb71df354f31542d0e20997cb6419b4097e6564939b68f1acdbfafae094c3afa44d323a782b3fe72521ea425b9" },
                { "fa", "e4b6fdc83380f9e050fc90c6d52154a58c154c7b96fef987e9be7606b4035cd4ee540211b1ec5172462e45445e8994e0671ecc8540aed21b1a5e973b10fdfd40" },
                { "ff", "5ddb0f57bf3a8edf254253630bd976f4e2929328a4567211bd2a48e126fc561186fd6cbba2304e036afcffc97b88c5a0115b170519918ff6165ebb071b34bfb4" },
                { "fi", "a895977055e30100d7a2038ea81711baad83ecfc509b6451787524ca87b03d3eaf11fbc58ac8526686ed3bd141b0a58ef961d9454dbf893bb1bc31d3882b1a48" },
                { "fr", "c239a7bff99e1c4101ac86704efa845683c7ad23fd5ab7c0c99950bc38edb9e0efc1115a1824f57040fa8e60cdc3a113a38a08472cf71a45c60e3ed6e2ac7ac5" },
                { "fur", "8fb418077b1248a417c77c891d6878f0eb8fa31b84bc5a9ce70a15a51ac866a01df5d45b29ac71df0ddf74897b4bbde639e590ec595ae77ce17154287125014b" },
                { "fy-NL", "baa2804022c224e2e5eabf72515ec2a7b53f57dc3aec5ebc3045fcc44a90c29bc2998a370d9df407cee228d792312ffe5cfcc2f1bf3307ef74d4850605629d50" },
                { "ga-IE", "737beeedb1524cca14cb0640b0a6970908f781a547008213fd139329ca7bb30cdea39f4ab2bf6155218138a48b1fd907c65b90b4f6439cde25776d606c8dfd52" },
                { "gd", "3425804a12e7b0197b3ca7b6fcfa34abf848eadd4d4170428203a6b6ea0e4ec09c898967ed1afce7d45e1c3d3c24eb28ddabe882511d71b31ab946c0b749e522" },
                { "gl", "fbaa52a220dc38915dbc1428bb3f15863e2dff44f3a9424cfca498130c433b0d5cb927f0ba2c11027329f86292216cc8beae1428b56ca9eefc5fd1ce0a618d4c" },
                { "gn", "69e0e883879e262cffc255e23615e0c1c484bceee1bd818815f8ac59f0e3a675c810764f681b7b56fb6f4113fb1140626b6df7bc618a821164e91aaf3b9c0136" },
                { "gu-IN", "6161bcdd4d6b076b08225776787c2d0f30db33b4b1c3de8fb28ab7fa4f8f689995cba33cd0789e89c21d16094ca9823f632eb9286671a62e3b689c1a328f0274" },
                { "he", "e0b33964f1b684f4ee351b5a83f6aa15bc4af5367fdff0bf1c85f3fa0102b5d36c76f3e9caf1909e93415e46d1c40222bf82b5580c4e26cf081782c00e5a6d4a" },
                { "hi-IN", "843932bbf0b2933c2d5eae722a1d275b41bf6c425c2b08c2844e5f6e4f63d5ff47a89314bd5e252820a2298a07ec3db1be145b3af4ac1815581f95a8609bf98a" },
                { "hr", "ed75ddf9278bd16dbd27193167a0297b0344fa6218e0ae55ca220de868e5264b51882e9d8c87e1cb54ca52b32360c2796059ea91bd8eb7eb350510d29d59f9cf" },
                { "hsb", "364ac8852bd1ba88629d87d7197a4e05153f4e9899cb96043314c2aadf0f6228fafe2e4a46048248e97b5fc078b6c0be46b0b0387dcffa41dc95a70b03663582" },
                { "hu", "791fc40c66e0ee0bfe0a1d0f37505d593b00def63db2c53365cb5d27653ca07729dbc4280f7e7517a0e23bf8de1791c64f61ffdaba0a8aea407991d4ac412958" },
                { "hy-AM", "f5cb913857dc29a4e55e4ac9e60af589c374a9bd3e61b938f54a5d20df3340a1360f0691c3f3c415f3250a66274ab293fbbf59bc492cc5b258eb60c2606a195c" },
                { "ia", "c8d2aaab2acd9f8957b8473ee3278ea0093f2f48aa113ef7179809719d838463a027e57eda85846eb01ffed77be29547b3d0c9e10076a50934c1c96d6b8d1807" },
                { "id", "01834398ae9837084530fd7604624ff25dbab1a674f2de5e300c46b703cb0af6240fb4de227b2ef491136dfbcbcd5e917a711b3457540f986434a49561d9b5f3" },
                { "is", "e852cc5f5a5cfb5aa39d2d938b61309ce8da0cc8ef596e0c420a2e559accf62996e8499b2d90f4a8905eff1a4d7472c09ac879950b508843a05949ce4131ffe7" },
                { "it", "74852453153dc1076f5792beb80222c96b9d3f381b2e382d3bb7e6550e5fb5fbc76de1ce6483e2c74be65bc42ff001913b765e738406a56caea95cc78e6d0065" },
                { "ja", "4a7f756c198836162a8413274f6a435588723d4bb84b66ad0f572cffb0c4f6ccb2c522c7ce1f829d13beb01f189a49f1aec0ccaf6fea087f4e11c4edd47cae1d" },
                { "ka", "a54e22a3ead1241506424ac7e6ccdc904cc0e194dc6fb2e2803a6c7f1cd890e080167a2786d35730e33c2ef73a48dedaf9375c94fb045ef9df1057a502cfd5a0" },
                { "kab", "c80f077f34ba453d6cf9867666f0c3c0a7bfb8527b85f560dbff41d9120c8260b81b2c6b11e5fd8ffe680bd54386d0454945ed9f89c1564b6d47bb8c26275ec1" },
                { "kk", "0914ce9516f5a9cd8959b5caa189fbf716f8e3f6727930488fb4fdc3fb9801a2fd42bb06c04c766e81de57b5f2141869ed9a5c577dbcabbc44ea07c3d9905064" },
                { "km", "320bdc2d7e2ee1302324204b6d00be567cb38f03b1cc1a7ac9bb210572dc2930099ca554c9b407becde407554d6abf497008b2e9cbb7ae9c1a3b09668317f06e" },
                { "kn", "088ea65e4078d897a2d37dd4a01d78b627acffe940567ed2254eaf4688a285a0155029504df00b9e74d9317afadbdedf00bcf0c0dd1705521bf8071766adca74" },
                { "ko", "9fe1890c94bc074c0001aedb8afef847d7af9a0440da0720aecd7096557192425172fe4e962472d7fb2480f3e69465d330e53c33a86e9b859155739a855a0f36" },
                { "lij", "7df23141cffa6e6dd439a5933c3fe50104dda6c43c1065297c40e271fc7defa5a1507143a87177af56163a480900df8d9582052fedf93118013dccb7f58fd9a2" },
                { "lt", "026669bf102e4862af889ad223bbf9406eee64fcfccd0b517e9244eff66661db2b2d2102b2a01d010cf1cea4aeefec73a702e3de8d23e7700e2458848639e3e5" },
                { "lv", "dfc0d8f26f2a32b5118a3172b92fcb474dbf8923b0ccef562791ce220ac0aade40c4b2a8a335c73342d0ba380fe3547ade0e6bebcd3ee889ea7f65a662a35066" },
                { "mk", "72c8656ca97b95eb9f33263cbf9d8e8e21459459e06145729d5744ac3b20ab9490b885a76304e2fc6a0f7dbb2761cff7045f380df6efc592974f6d43e4974409" },
                { "mr", "c5a667872d1d60dec6c87b27ba13af2e710f0ee2bf76bf09eb018948e65b2af7b66ebc332d6167b9239886b06fceb309b5df0c0433957498362a13e123d0abe2" },
                { "ms", "2ab51fd362cd9ce4ebb676b2cbf381d64a15a1b8568d0f11f32348fe4c5ab908af6d8ed9b889d951b02074e1b7be30117fc4daafdabc95ee91205d191dbfcb0c" },
                { "my", "40ce8a06bf3f3b8d424ef3e83041a4e81ea8a2ef0ec36835eddbb9e3af2e45e871ea7f5be56ad26f71b7e8b75c1d083c3939199475dad790d14547b3025246aa" },
                { "nb-NO", "79b9267a8487fbd0938785d2df40344340ef0a650b7ec1f8b934f4e5a4a46c16678865bd51bd24c91220b772d3c713bceea6b4fec36bda943cb27949930503e8" },
                { "ne-NP", "20cf33623fb638b489ac797546f3c198ff25daeae5ed591e8f076c690d58079986c18e5527b8bf591529f20d366a9b118d1a80fb9cdcfa3cd6526832de1f81d6" },
                { "nl", "a6b7ae09bd456040b99c9ebb6d8934c16b57d1bcd3ae05bae7fd28bd7f44a44b911ef8bb1ced2f633436edbbe865646ddbadfb5704f0906d23130e14d4d42a8b" },
                { "nn-NO", "5f6677d5d8f5c2e8e6fc84ac2efba20694051cc67cb802c9856268be913b4d822092fcbc1a17d11a0f17c2cfeabca70e8de80c4d1f911ad8c98d33e3ab5db20b" },
                { "oc", "39f6b2454dcd742e9f3fc41017440b5cab255d4612604d496110cce78c50c6eb0d6ea172405608aea6a4d99d6a2a30a9e078bc4c025e57bc29d019c89a1a9925" },
                { "pa-IN", "d1e9692ac69b9a1c8359e05c90cd5179c72adde3a4d1ab4774b6a66665e68df4753bffffe3b44eac2992e9f1c5554005ee4d7bbf847ca8a26d9c4804a69d2462" },
                { "pl", "46a30cdc82dcbafa0334e87ce7dd2bbca698b4dcd31671c8a9afa8b27cfbd2e309f63e41a4d0cc3ef756c3c6419ca94fa787f0f3fa0911c531c2638ee7cea641" },
                { "pt-BR", "d99ebb43a7f52cfe8ddfd65b9a095e7bc9859246e89a0778af9e470854ec3f5d61d570b0acb44bddd02c7713f90d7d72b4f4c95c59595bdc9e26cb700c78c87e" },
                { "pt-PT", "fbf6c76d2526b6adeb872de60b3664d6693510d8c7ed6aacc19b28fb395636fb4776341e257f76a0e8bfbaa52c7f98182b11cfba033c3abbce5dddf81a4fdf91" },
                { "rm", "783332b853f8a509d82bd0f095220d3e513b72b83987d6df4abcec213d4dc8c8d9de96808bc0066bbd6d368990fffbc7b64c3266f16f34838531ac1a7583df7a" },
                { "ro", "085c8f409bbbb5c2bdfd28d138d302864b3b7413dbaa302fa9741569ece4382ee606ab8321cb985556640432dafb9768c456809d38ba06d0fbce93442af7583a" },
                { "ru", "45ba16a48d4bf389202f50e34a85bc1dad308552b8d1a5c55e94e84206d9f6a6a588fdaf620da1fcd33b28782bdec635e6ee32f9191340067cc4607861a77606" },
                { "sat", "d2ff555eaf4771a53f1f8e7a03918b5be5d508eca3b1c05505fafeb31f4e800722d12c2332056650e9ec488ea2c8e8c58a15be62d4a8bd77e3fcb87f2941b0a4" },
                { "sc", "5c3f0b4ee9bfa18828be5000fefcf0f8b9dce9b212b7ec6c372a60b5028dfa2fd7299212a9f508125ad2bc1875dab5bddb4ef0c8123b19492fcd2710f023367a" },
                { "sco", "13971bc80ecf408c5466609bc9afc994aaa68b202ba7b2e7d4543634fa747d0416d55917c2d71ceb6f6e40b8c397b3095e52efd5cfe369f8e6017ad5bff6ae31" },
                { "si", "255158fea95c0b5e90927c65cfbe8b93258ed72894325549b270861b69b4db40022197fea3f7a88151162fa8ce89cae720ea381bd44e5aec975b277fd4298a5a" },
                { "sk", "f29c20674eaad4588188893229691801071c3eaf4cab41e83e7166d46a8b96c18603a8ffd31d9c0542c169dc581825878b1f9b49b2290734bd0789dff9e69a52" },
                { "skr", "404f7bc71936e40d6ec8a72c584428fde38a9b24a263b52768bd0c4db0ed231655c16cb36be07748de244161d1710132d3c4c72ddff16e5a192135671100123d" },
                { "sl", "af41bb5529b065937d6c54fa26b35b1abbbd5855b1a832f1bae8fdccd76e8726d8c447c0e77374f5b04e9e70424e415179b989a0f56a7bf50908b0edd51bf4c7" },
                { "son", "a541972b38ba857ee3f62901d46c319cd56446092b2002848862e013f0e575f5b5963ce67f62254ec61d0c8fa3ffe81bdaf505a9761940b690eb0550fa8bb68e" },
                { "sq", "8fbb1202ec67f638fe835d3b9f5a35bab29ca5f3ecc40baf3032b38e2118e43d436a113ca768e7798b83b7b8e1e4aebc2af7ca35220eaa804470bfb89938f958" },
                { "sr", "9e0380a16764d92fc8989bdc203cc3db64389a33f11e400f66add3525d511bdf00f159d0cb1cec68b58a7d40eb68ab0e1e5302dc3a564ea66d558408fb3d2353" },
                { "sv-SE", "ee84b8ac1720377fe971ff1ae59b7483900084bb817dd4a7e77fdada1dae09d783e2051ad5b5fed38c3b1917f1bbcd870445c5260468711d07aca2006c36fde6" },
                { "szl", "ae4ea9c59c3de7d3cb2e93fc5ab1e153a1d4e8b9697dcbe972b44c805a9e25358b6af3fd046f57ae022b7dbe57cc948a6e403d20a8405098ab67b2a3deec620d" },
                { "ta", "5d7ae4ee56ea1255ee1e60ac5c1736593557330e512d3fc121493ebe3fa9480078311cc1d8a0221391a87295826190bbd7d0494c2bb6387ad7a634f5ea186aa4" },
                { "te", "7836f06cb078d0d4e0316e4acde56fdee2dda6412290e7e2126dfc880ec116b3085b3553a6c43a5667be1e39c44ba50016e5e7baff1088f5251833cca0cd70da" },
                { "tg", "3a79d642456cf4debcbe782f0b79bee9720b54dff5f637c60d4b520b64f6a5a5bb96861698e3a93666d81080fa8901e1565b29f711a6dfd1335f8de44c6d71c4" },
                { "th", "cd918225295889eda84175e9c2fb63370167d042472194184a28f2ff32cd0ca115db5d30b802637b073d072a8a3117ce881403818b4b3adb8673a9f27fe4575e" },
                { "tl", "2efc4f3553264854d8319d7206ce58bdc30db9aa87e74eb2fd96e56f90208950829b80d64d450e9b87d415beeab168cbfa0a74cc722561e1ab54ace1dd14f5c6" },
                { "tr", "54166e25ea7e6c2ae2ec2f543c53bf5be1e39ab12246985252399c528cd38c690d4e81d13597ed846aa1154b9226591e568e5626bb9c464199e9a5cb3ac00e41" },
                { "trs", "3d44f0928c03bfd89a3f8b0db1f5a1cc391865fb3e1f6fc7597668f0e222deae4289731e13a035542d8319e6496780973642511463c0330164d9d0a3e665268a" },
                { "uk", "e1a0b5be462036812fc023ab5f90e4aeec201268e5d5b99bd4fdd47b6f2f3cc913f007b3f1fc90ccb35f3977033d70e015be93e774d3df9bb889eef5173ed130" },
                { "ur", "fdc0b295bd8414e8737cf189e026d026161b440f1002ee211469c39d414a456e866e20e856bbcc41de67618dac2e0ff1d39026a40e30ba6cdec1e39e017f7412" },
                { "uz", "fb8d936afe1d6454c76e31ceef90517d41319c293c8450468695cafa8bbea01bc10a8e2007109cbc7871a9582b039e03aed09fa738239af6b585aad601a8c154" },
                { "vi", "b14a752e1922271b59be3ff7165cd88c3af64479a190d75ead227dee18e244975e11fa1f56f0ba4d772505f3a35dc19a44a98a9bf1ad1496633f8436099f5f04" },
                { "xh", "ef9d8ea1aae2a8e02cf091cade8f7055240d4b6dc9423969c70357008bf53b845ef17b2574e79969f01e1e9ca86dd7b39785e04ae2ead27859b27edb927ff684" },
                { "zh-CN", "1cd64ef853a1bf61976b0f5b5154587f5ee0af95bed9dfa1da1c5b88cb52b2c1d2a177c67921656a33e47ab379bad298a0b30dd02f0ecc5cc4b8b41a4f163d94" },
                { "zh-TW", "fa0bb041011a5068c23a5b5c60382b531fa72fc9caa98635dd8658a2aaeffd9545c1da56a0fe7af5e1ea63ee7efa8ea7b103e4d79addc1c7aac23a70fab9e129" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f834368dac5642b987ecc72cf75ca0c7f4dead9ab2ca19283280cbf3fc7df6c09d03d7db82881b722b9ad0d552c39f2f4304eadd593771b6f883bcdb7a729aff" },
                { "af", "93fa7bb9136006a666accc295d4f3f79bebfc4492bd777bbfc12e4ea5843cbae77108a80338f46248e3ecb53eb8521516f5a919852a7c25d10e322bfae292ee2" },
                { "an", "9100de373fa061d6c817216a59e9ab3a07c2e32cbd5cff93fc4371cf5f9f457b582bd3be2208e14dd02da9ac6859006f0f294b881265dff9627bea35b9d22e62" },
                { "ar", "0395cf299ae5a6e487b60f10036b0a91eb205dba05e7a23b6e282c41784875e221c56f2b46e4eedfe64a8d9e48ca769780130d24f696a3b78a2e561f780e631a" },
                { "ast", "286d86cddc90660cb1df28d59577e23a354783c0fb6111e67aa63d8b5e6194ebd29e6b1db417fa19cf930ea22ac42e0c12227d98342d507f73451b5b54e0a9fb" },
                { "az", "15e438ec8f31632a95fa6dcd17f711e6368a0e73d18402062d63a3556d139b66c5a6c50992ab7d84617d9c48dcba5c251275269b25b0d443ea8217ece4da4dbd" },
                { "be", "7047a4622df24fff8a1ccf5a28c78edcdbdc759a290d0108f1366628b3508f1ad439b4afab490b025b91bc059db14971800c2011920871c2f2eaa1c8c115c075" },
                { "bg", "c43804128f57fb6d2e4870ee7326909cd49493ce249b6f851390a9fa87b320bb0d594fe651081381566c4771efef84551a51e07fead0dd4acbf9097d9cad5994" },
                { "bn", "4e9ae4e522feb68ae9eeb5383274e9c8371b8444a6306137e6081a70c2b2a01ae3f3e260b04b2c4932b778c0aa8a3b392ee271cfd54f10e2ae5044143e37bb2c" },
                { "br", "e29b0245819148ea13b635a029181db6f9e6fba25536dd96915d8f14234acc1396314f6022a7783046dd9dcc5cfc0fe4d417cafddf063e37eac7e1a9b05d1811" },
                { "bs", "82b66d239b6a3733043e34b924b8ad2f9e07a744ab30ae38ca1f554c2e96772a56f710195ec7a23bff76134bf2ace067558c9f5db02346b75d37e092bf6bba53" },
                { "ca", "e5e6677b339ac4a6942b09c1ee18806bf2a724b3cb317fec835db7b55604b6fbeb414b8fe490d4250a5baad277c8cda9082cb30f9965c43e2a34a17a6577deef" },
                { "cak", "9288ae2e1af571ee57789f82086a22c2c0e4876b27f12235a626410f9ea0abc6a1ff65f704fd20bd45d93c8cbc18989001e10fb40e5b827cbc9987388ae62eb2" },
                { "cs", "dffb6ed88d9ae22e6f1cb7a952508d8c60223bcdd84b2fdf58906631c4aee3915ef835c89d54ba442e16bfcecfb4f17d4b02db89f257ad5ac88a4674deb8ea47" },
                { "cy", "fa11d857bab79f2badd8ca9187706949e7ffaf4d5f2365380c6f93faeae8e4f840bcc999cd8ddcf08b911b2d042f2da13a4fb24845e3b0ce6affba4028c4dab5" },
                { "da", "1a048638cac92834206186e7c2bed20b369d5a0972d0225ef485a1b57ca92e8ed467e79cf3f0019264080992f6b08f3f4f48bc964f88f16770be263223707d53" },
                { "de", "578dc90390a293d15a526a7523d7da3c1977f2fd5ecff1284541e3ce3eddbd133a3ce8bc628c43f96e0bb2fe281ed8008e39b6559a779a47dbe628bf38879def" },
                { "dsb", "3fd933e055941a339dd9a2afcaff2c31fe1ccecb16cbab1d887c2c4e876509d97e992c4c6a985b9311765981a2e9cfc5a3640ee0154e7a96e37ffef5eb046bd2" },
                { "el", "6676c124677c2a0af50df5a271028aab68f2ee22e233c522ddef155aa495611dc7aa7a00756f89c476073c4ee1685c8146a48b347eff2a30be82ff8c5323b209" },
                { "en-CA", "8785601187017ae33e19a55bb0a8abfa4f1235dac243ef2a450447a2e5e0c6daa0353e42b62815c4d13dd560e0c13bb06e5ef292d4d711cf4da9bfdfaac7c627" },
                { "en-GB", "3102f89f8159ae54e3c78470c9058bb41c460f1d0754e386cf010d535e659514c86babf8942bc9bb268a85f191ad071ecf9117a84c4dba419c1fd2a0f8f9c481" },
                { "en-US", "e1ccea3f6c94be7087ad1b245442a9345f6edf8326a205eff3829a9f813cfc413c4f0719131f1e0873498ba61825b005907f1a420c457caeae4ae653f28ab15a" },
                { "eo", "c20962c784614a6ba72bb94151ac6579cb5ba8644db3d270f93a31ecd84d46e9c7b4d1f543872654682cf65755df25a53664c4e19bf75939449f305d665efdcc" },
                { "es-AR", "9b12bbc2b24777842311c2e841e001cf2bc8f7194f6bdde2712a7cf5410de8aefbc0e11858b6e106b817ecaf8e302961b9ef433d081e714c8118a7ebed1b3554" },
                { "es-CL", "dd64d8fc919339227e717762f03cc22ddfdfbc588d0ce64cfc8e136219fcdcfd173bcda013806c8e519d06096c04451cfc7c8ab3b19cad31832add598efd280d" },
                { "es-ES", "78a3cc755056a141d8d21ab61f7b209bd86f26f08b8e29e14cabe469e1b5d04304450e48fb78426342daabe2f1cfb0cd92486e00a2d134a51ad5f6d976d2a23a" },
                { "es-MX", "070aa536ac2c0dd3926eda4902185293002231d01ec33ac7f6fd0ba5e37fc7a9dfc5b9cb556b0b010db4ea4d768c70393743494eecc3c0614fd39a8c1e5b9456" },
                { "et", "de4ba72b8ad6cbd30fe83596a48d1857cda58e17ffe56dad401268b7b63f76e0d0adc9306c507a96322967f774601fb86d7efe15389627354d82b5478e43eb92" },
                { "eu", "75d4bffd4b120ee2e4a54e78da9261e524a856ae22cea5af6651ad57689262d762d77e450a9028ac9c0afa7b157a125290345cc681cab30a9cf2bf8dd51c6c9a" },
                { "fa", "5cddc61094dc95ada1aa6cd4447a27d7a4e2e1180e155c8bb64ce8ee995b4210d63860d9dac3651fdd29e0fc329a1331e19a151f391c543ae0023fc8590a8bdd" },
                { "ff", "e4a31ba1fec71e53e5a364b3d2c0582d97d29dbfe7ff85f24e74aaff8ce4442d6232a39b9e0c35748ccca6e1b7d6ba4d9d80a7efcd316601565ea628f29d7b6f" },
                { "fi", "5a87c1dacd35e28be4f479d9d7d062f49dc72fde88899d3e8562a3d21909074b21d02298b3725017b4bdd990ce0b4571cef57f4fc1be8b0d79f1d0aa35d5b4b5" },
                { "fr", "0efad5493017bb1e681b34b70a0780795f5cfd51b3fe01015565da0948ef16364c5d5c3f985e199c6ce331c005c1df41f9737a1bf2cbdeadb93b47d6f2df2ccf" },
                { "fur", "a02db26ee9ececc6b3514f7cca64d5a92e8590d554317a534b04fd419790af1a71831b752402e381040a6d2f42dd579bbe17e773009f1ae03d27038554c3108b" },
                { "fy-NL", "a8033bc1e43f7c2d535478a0a5f532ad38ea034a824087729d6d11ccfcccaae50d62f3ca874bf1c624c03e5e2f7c331ace9d826967e09633a00a02f636207489" },
                { "ga-IE", "d15798eedbf9736fb404849e50c11a9423be8f0ed0a31b984913a8872c459589635a564de26462492abfbd25275fd41903772e32852d31509b8e2d9a323b19e4" },
                { "gd", "dbe7c99496fa8d39ddc71ea4b59eefe6f322388bb371930c10a64d92ecbcec71013fd5a266c0056e71eb33b2e774937faa3cad2deeca7313cd8e8869d9632576" },
                { "gl", "e452e386590bee31338a174692b36480eb255e1bfae6b1e0c58dd63d16835f46838fe0ab613c43b5b82785ee686d4eb68e492a8d818bc56d4932450dc6bd79ef" },
                { "gn", "6e0657aa84f8a6265bcc01aaaa5fa8e748a9199fe6cc4e0c3b53ce0fea93fced1577f9f0a0d4276d3928315bffc3aa4503f3764a5e229a0a5798263f0b332a12" },
                { "gu-IN", "8eb9e47fb353a78bab00c2a8fa57512f3c73f13e10da3cc97ce45fd14c26b5aaed34a5a575fd4bceecb350b856b82d176919dc5be27e0fab47d55339c224bd14" },
                { "he", "776aab4155f8b29516d3fc6e9d200daabd77928d7c90e5c167ff295cd2ab6e331c5b871aba9415f715202f7613512e16922286221740500f9d6ba8987daf42f8" },
                { "hi-IN", "e358ac34327c3461099478e16aedc4b43b0d94f51b9f57e0122153d2713210274f435e6b2d58cdee1654dfac54b6578cbfee32e3d9d2f0f96a364614f7fda556" },
                { "hr", "01867ab2b89845a35502373ae9be9f9a86643cec9eaf59b3bd7112587139d2a4deb4e0a988483d1c741cccf7b407a92954bb75178ac04e60bbcc4d10d68e4e62" },
                { "hsb", "e1211de48e5381620f47ffacbf449601cfb04e291930e948864885f7054aceb0e4df458a6ca5fa08aa95afbda337d7173d3882962c826bf30e062b562194d820" },
                { "hu", "8417552ab8ceacb75a6acc25ace4bfdf4aebdfe43b1d212bdee922346dcdc2b7111701906d179cf1ec5d22e9fea66613362784b584af5bdf702093a889f4406f" },
                { "hy-AM", "477e92eefb391b8741a19bfeaa989a9b731683d53471c160f5c95f93a8dc36bdcca57bc291df540096a5eb9ae0c239b054d53b08f0166a30530b2484a722fd36" },
                { "ia", "903fc06f01c566eb5a7cf581e5c02f106c80ae5176d252e80252e2577c517a168a0677f73d766a029fa782a23d7c468e2290088533bd44ac82a17c28a90f42f5" },
                { "id", "2ebacafcb9f656b51953edef0148efe3e32df2979f9b077823a448cc462bf5d690a80008aa4d57a1d352f9a58950c624b44a6c7153208647f081c19c271155c2" },
                { "is", "79dda6848532289d3f865740f9f3026d5ebe96fa2979ff2a46fb338faad7b88b5616e73172f4c7bf566c9974b3b30c7eeb0523de7c108af4c61661f4082f6b48" },
                { "it", "5b034a9175c153c98aa4d3c0c551a04d82f468d7f968926fa1eb9845daaa8d0e5bd30f2606fb697e04598df45ecd5c8478f008ca2c6ace959c0dfa8a890b7e3b" },
                { "ja", "5e0570d7800dd2eb606064e76fc4d9c8820f79531b573367ca85afc1e67a1ea977b0ccdf4ae578237055f9767b2b50f5e4047533e72f22e550de8be33b17cf01" },
                { "ka", "15669c77d505c5b44bc430c63c78caa58f917ae8a78dda3552bda67f2caa8faa891190bf0e0e6bdb16a1e49d2fdbe4e2b3054cecc7ad1b6e29e27bf6cc255a27" },
                { "kab", "29ca8fd0c1a49ac3794e73fd78ef21fd2355a46c29eb08e85236c4997a9fcd8a5e8fa74a69520b3a8c513d3460c1c90d8cf3a115ee5cdf845894eff5f7d150d1" },
                { "kk", "56cb98feae3794c4043f7c60e85c088609cf2fc575ff8a006eaee48c64a3a277a46bf2d399846c433edc79113ceeddc4d710cb5586651a7c0197eef945b691f3" },
                { "km", "1b1bff24e03dd5fd8212fa2d8f4923173458a14b67229bd7e6d03d9c6610b22ee8f5e8c617fe544ef9177dca6d5070f0fb1664876ee4345f142c98d5249776cd" },
                { "kn", "f0450d92a2bd80a47a8ce9bcfe76e0c7841d8008e58ff62893ffe2137778902822edeabcb37c5c00b23434cbf30b1a1e1126c191b28964690c0748819fd247e5" },
                { "ko", "7b1115f8b2afecceb31be27e599fbcc6f4f2d048fab31bb7e96b09bdef2da343897f99f06e68fff4ba9c6a584073d0715947201551918b6ba2c81b20a3a2806b" },
                { "lij", "0c0d21cbba396827fde5a7841ae9488c8bda288def6af19689dba89fa3f97d6cffe5e61298dec8c64a99d170f86c19c3486d30d86c3cdb30db0ee1e450668787" },
                { "lt", "3437496d3cf6b555b78e8a725858a9ddcd1b38985ce92ecf0c1c667cd1ee909d3e66c3df23f1bf11f41e50692936867c1fe5a1ff73a516208114aa2d6ed3b614" },
                { "lv", "b59ab57cb7e5477509108b17bc06e12418dcb1034ff550f3a16fefcdacfa64a59fb0a25fb1f9f88342cf104220897ec3a8d078b70c3cd9ac8d1db37fb8196159" },
                { "mk", "8409bea2b29e216c5213b004ef4e31fb11d52b3b7e1360d4e61f018e76a072f303c92542d32d8b2dd28f9f98326cb31390c2cfe04185f8a83897d79d5980aa2b" },
                { "mr", "d4dbaa030c03044fb476e2d29253639b1184b12e1fb1e96a5f71f1cc4b9ab13642544cf1267c77cdb3cdf6dc1eaa04a264b7b15b9b4c834a7eb1d00814d6be87" },
                { "ms", "2210512f7c4361b00b22add1a38ef15b8a2f44bf8b2551219e78bba3601fb0fe7ad98a8ed4c4a8cf0d51654ca3ef41b72fb414089ea581a46f2fd0569e63902d" },
                { "my", "48003124cf13c4f0455b3523c50313096dedfe3480c329df35db7af91009262b67178f9cb9fcccad3f6b743f81cfbac440692990b377df40ed75b25e42546934" },
                { "nb-NO", "0230be557589d19d7a568db49e321eb26b7ff27c416317da39b28190173e77bb2e4db3c6ba3d7ce4c6990658c5ec1c1c4c62fbcbd4172ceb624db4a5653d30ec" },
                { "ne-NP", "7e2f2d36d71ea4e4fa3249c7ae1f3a5f40d9ce0468e4a3de1a763e658c76414e36910e297b74b50a25591bc0acd0743c959b0906dac4ecbc6dd1cb81734b640c" },
                { "nl", "b2014567a8b71095176a4d79c40ee92c9e89830226dc7b33768fd5fc8ff596a21d7ad41a587d42dee5a0ef81b482bd970e618ba0f77aad1f0d5242022965ee85" },
                { "nn-NO", "055ddcc0a58c8296a827c6e53b3ff4c17b63c658543fcca3a1d1e4b57554a67086afb14127e01daa5d17f808fbd64c22e29942534c4c6440b7344088adc385dc" },
                { "oc", "ec1a5e2101ef47e7030b4cc1c3ce2ccb82be569143ba6bc685bc39ab419f18db89940b0c7a5de8408107a615c1a45c129eab68ea0e6f7e15dbba448353adbe1c" },
                { "pa-IN", "bef5fbd8a84d52e7e13d5639fb055cb1063d30d9dce7cb94807c8e292fb6e971eb39152db7a8b052052531b19bd0ae7f28738dd73fdf4f0a6dee92a78142f5cb" },
                { "pl", "c283683992fdad819b4d3852c3a0b63e1668156fc1003db1a7da60aefaeb33e588c171d9226dc0542a3398da190c777bfe0bb410a9b8204509f327879ab50c57" },
                { "pt-BR", "f3cca97ba78fd18ecad4137c1c94f93b988c78b868c8f7a41fa83945bd2e9cff91013c3e05cfc04a6d1b58f9f2d498a23927aeec8781b2928d977603ca048f2d" },
                { "pt-PT", "fb3ebae95c0ff0ee6e818f62b93ca8750784790f7cf9a73c64b8ba7584d2bb077ad0d4554f426d5572d7e742b4ab42e39f79f1be4a826c26f1c6b458405cc1b7" },
                { "rm", "fb6acc44b19b5b13fd2e2bf1a336e20e82734811d8d5d0f3bb505dc7974ba5ffb44cfd15a07aaebd3b8b542d50d8689eafb11e64fcb8892853529c163785def1" },
                { "ro", "588415cde8458ab5987e7d2ea652d2651fa5670b8f43e4d35abf1b7da7f563884f5c5f5efe98dceadb4c622025d9c927e887cb196807504fa1da0f9af6e22b80" },
                { "ru", "6c7214a963a74bc7842e5b07d1b781c7c24e0fe4376dbdccef7321f60acba0ca6fddbabdcb49abb0533b49b6f81fb2a0bbc4df2a5a440e28d930f00bd5b97300" },
                { "sat", "19978ebcb16f6b544c2a30095bf7ce47297a17347955b3e86f417d8635dfa72192f3370547e8e70a2ce8e6afbf6c6b44378fbfd589fb07ea17a8da16e5e2682b" },
                { "sc", "9c93faa24614517f41263d4fe504a7293cdfb5a0af721e9d9339f20b20781db7db21bd54b08dc8d6ad0b8da9c681b94ebdb19f239bd3562522df3c1e00691f4a" },
                { "sco", "5a9d4006fa7910d84f818e809a724a8cb08e6f2b51d2b8e24a218d147dfa4f3b4bdb62dfac8b8210a1a52bd409f9fe1b6e3a6275ba0de36160e45265df45c788" },
                { "si", "5b962ac785cd4bc814be065984c25ad352c2a7d3caeec81bd39d84a704f7703b51f3a3e72f5787d81e21e0d7d45724aedd073b7ef86ab1b06bc01852d58e2559" },
                { "sk", "d5f4120de95fb337c7b87bd6332d5513defde010fccbf2c3b02fa260fadfa8b8c1b9718a381e484337571a2853ab82bd000385060cb42aa07b21106b5c08ec1b" },
                { "skr", "636fcb91c4f2ae366d4658eb8f8f49d3fe4987dc71c80d6ebde0c58e83dd3986a3cbf118ed48448fab0fa005655e18360bedaabf0ab8b645409bea5d2305071f" },
                { "sl", "0b4b52c2ee67a1ca02829e63554ea1030f1366ffc78f23508654fd48907ea8ea3666c19e854009a7571d658e7679af5cdd0ebf7a2dd1d3cf389a8ebc983a1dc2" },
                { "son", "374d16d5270557724d0434c9d810f522a812f382d206fe31eb968c16e701c67370b9289322246287a9d4c16f4ef398f1e2ad9e5496e7fa34a58100830189f65a" },
                { "sq", "3ceea33d4e95f488bda19e61306775d3ab17fa9edfeb9004c30d4c416f705695d4c0ff7707db7c3fae02656b4feba44aa0893ed7a3d3ee0a401a69342898b362" },
                { "sr", "fdc455de6faa70f77c4c3e3c37baaa6a5c2cdcf91d927d9f54d0d16e6af8ce6aecb67b48307bab6b173f209cf70e9a208374715516e3727e303b0b0d68a29acf" },
                { "sv-SE", "8cfa56474bec8c5c06cd59b8aae0dfe270fd5347b060812b8378ded3b29f88ec8bf28d09431fc9ffecdd06fe8c1ea923586cba81e5110183795ec795cdf933c8" },
                { "szl", "4df69fad0cd2a93e8489e40d6968d79104966e780f8b8e9d620f9ae658e40c52f42d4261bc5615e215979d36d06be529a823a9a0026ef8a9d6e7efaec2c68831" },
                { "ta", "47a4f022fd14d306feef11cc7e5a7f85dc25f62952b42abc63e808b200dab28006814461d560187048715ce7a018f5416cdc181dbcdb537bd28bfd08ffb68440" },
                { "te", "bc7ad58ea379257675050e66716a5c193fcea9589da417ddebbe2c51dffea3f7ab367a4c802000c8f40be0d89a59c0c1866d4436f6913793c3fa5e3d7d74f2d6" },
                { "tg", "66c23efc2b6b477279a4fb0376dff743d7c89d60bff23e5649f8c67ffbecd0958827ac4fcbf2c5a354b62071ce376812c131d283f9f4f6b9fdd2797a1099331f" },
                { "th", "54e39c415f13ea6ff328f2cf81880d0339b41b214930443d5e52dd9f57e007ba9366dfde77084e9910161ffd1f758421c988b0ac45429828912d158ef0ec06c5" },
                { "tl", "aeaae01a41383c332d3f84d4cfde9d1c93cf4fa3eed239953e328a607d1ceda3a4cf9f132a153eb1e4bfed5d84c415d7e71df56fe5e6fb022f01c74079e59f41" },
                { "tr", "a639f5b7a98035f7f0ffcc4f54fd3064d16f247505c4ba9b3716b1bbb96a59c258efa09e9bb9eec4e2286377888a16ee6471683608251b69a476fa1631ee7802" },
                { "trs", "a76fb6ed3ae5218bafcbe0a5d43115226742077153e556ecf6a7b7d7f97a698e949cb0e77257ae97e1882456ccf976f9aec9a376bed17395e86bdbb652d85502" },
                { "uk", "a410da3af6e3500d4cd96d11101f94f1b39d617c7c50185b05b6a699a6b9015905a67d037ddac7db36ff5d14b63dc412407aff817569169526b94b30664e2c73" },
                { "ur", "fd7acc56731c291b7ad572436e309cbf00b400c70cf975f9469aaa2bd69c4dc3cb947b9fbf127d5644bbcb578ac7a9100354618828c57f17e6b9d59407344e95" },
                { "uz", "7838ffce3580a4935e763800b5beabf23765f007bf5ec308ea8fdf6e31cacf349f6289a4542e7e2b0fc9c87d9c5ce910aca6c3f37281ce53916a70395bbd5178" },
                { "vi", "1871bb734b1c52da55736ff4228d0312f164ec1e2a3c6357772290e8e67c1135144c2a2c5b2ca0695194f7dc870a9c37f8171bd25f43471563829d74e9b18f86" },
                { "xh", "3a7d9d5a31ae721c0e04f704617fde1bacbc8d41ea6de915fa5b4253636642371f59eca207dc2595ec5e25b9a38a564a238e772e77f90de06c0962a9e5cf04b1" },
                { "zh-CN", "8deb21941af8150d58e567e402ac22a55ae1b62dbfa1b5be541eb69324cc02889f6dbbd1266cfab586f064e3bfa667f1257aaa8221ae56c5da5fc54017effb5b" },
                { "zh-TW", "13a1bb0168f75000cdf2ed0efb8b28c3726b1029006204a24d8d6a67802e60882d902aa70c9c097dfb309566415baab7f421b082a4e13a93d075587c41c92792" }
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
