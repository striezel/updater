/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019  Dirk Stolle

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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "70.0b3";

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
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
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
            // https://ftp.mozilla.org/pub/devedition/releases/70.0b3/SHA512SUMS
            var result = new Dictionary<string, string>();

            result.Add("ach", "f5bfd93920686c1ed30122716ed96d387943b44c6e555f42c7520187997b42f0f68dc7dc9d08896129bae9033e6ef58adf9af6da6836a6dbd8aba1b481611934");
            result.Add("af", "876bd2df5dfb33e39c6677b8a3cebb84abd2f881f83eefe943da483b26f37980cc588441a6a1377f30443a313e766a895d49fb345eedc4e1929b86f72d60824b");
            result.Add("an", "b6d776e027538c325b6a8d2145b718c424390b5d0ee189efc1d3a998e1e8fbd651dc32193af85d1ecc38e4a635717198124a657492618ff08a629c39510a98ac");
            result.Add("ar", "349245fa15e4e96b985232892cf7c3dfc90e1a3598fe1e14ffacadae4ce2bd89eaf19063a00722e876b2053a28030a642439d32324d18c9e855ad5e079e4f2e3");
            result.Add("ast", "0e9aa34a9e26285f686ed9b486233338831058d0c1fd550f982784af747ba4b4d503d0ad0fdcab3f77ca5a9eea96ff38360fb533ad2d13874be678146d462948");
            result.Add("az", "a032889ccdc17bf1dafe628b00f8d667a59551417f71359cb6eff368b61348ba7887de7b3967c4862872a920b798dad44f6750620f6f5c6e1048241b39d671f6");
            result.Add("be", "164f0622591f889b4a1a6f1f8350a87c1c10434015fd9f09034b7a3a1940cdce2dbd7db225c48025f36c7b078d90547ae8f2e1579935085e710a16866ae90c2c");
            result.Add("bg", "8f220cb0c915c0e6114deab0bc06f23d66aa6bd2a7282ae8ec8215de35acda3e9c3aae5e74c634ef6d525368ab42bc848a9519ebd8ef61749142026d9264983c");
            result.Add("bn", "9d5d836de7ebb16c26b182429150f326ea28f7ddcd06a91e9f819a24276fc7ba17be6f9b3ca1451b9ba54bc9d8eb3f342c8fc0638aadb632f8e4c2868c8e5165");
            result.Add("br", "7e5b73878e7435212228e74c60b0f521faf4b0606113f330352a21dfcb049badbae1da1c42c8be606e163f7bb6fefc2095f21eaf63409389cbf7f59e887ff4ee");
            result.Add("bs", "b27156d0a81c03286be86e78f916faae73b278f2f96406b22a1004eb3bb0384df6958a08428a445865df41367ac02bbfb6d4d86b0888b7d50a2b5cab892f0405");
            result.Add("ca", "8c02668aee0b0bcb482714ee61945488f582c99b2223fff7bd87a406b9cccd5c09618fee753a2258cd08690e62ea5928220cf79686b483326a1c1f6f40e9ca66");
            result.Add("cak", "c1698ad5ce05ce7107f711cdd1de365729cb967e3a945ea7a5b08f54c8bb80a2f881414e65e8859d222ead4529ad9beca00364c07b16e19612fe29f1f8fbf780");
            result.Add("cs", "f971d144c815f899db1f5356de2deb870aa3b5b0f0cba748ef6bcb43eb14f860c04e5cdc43b9cf93267bb8ce91a5a9808b617d755df9fb9a76de111d5cf9b26f");
            result.Add("cy", "c547d321ef23bde0798e4d3ac22bace148b3cd618149385405015476b2de84f83da1ba39e1454b612f11eb5e2f4e73e8fc591486c278388f5e753789cb4e277d");
            result.Add("da", "7f40fae3f0b226fe14351ec6dfc24858d71dce43e4f7fc188576d4e639a47fd1de7a87334a9b4f234eeecbf1073311a508ca8e1249dc5b9784dc429f380fe99a");
            result.Add("de", "8a0fd5ba3ddc8d51d075ef9b337022130807a3e96ff5ed737cfcd264e713d6cd919ed5c031f408ed707ad8e96dff134f66d5bf0e334759f636bd7a21c8780a34");
            result.Add("dsb", "45c846ae58fc1b6eeaedbe19d0828fd82834c098f9984f7186be8ab1e2dfcd9c07520d2d36189389b1a9a1d0a0aab495740e28861da9c520d2a177d1faa065a9");
            result.Add("el", "80def74145e8dd44c62b13ef251e660b760018f22af5a944ab3406fc244a9612cd8408d0315a42e09a3ad1d43cf897f2e8c5f1a36dd189def5550fbdeeebc78f");
            result.Add("en-CA", "61775b36045f1ba1f4f120ec9e770503813e3bcce41fb03adfbbf87f3eac36607b5141cc8c1d3db39df9b5361d4e3d53ca457543f182c1d6e16057e9bf90ab4d");
            result.Add("en-GB", "62bdcd8bcaa7ade2924a0fc5ff24b04dfbf85a9151f9736a5987b1a4475e37644378564a92733cb8b6ae946ca7d8c1372cdf270dc06c2d6762798e6354358d38");
            result.Add("en-US", "a6e7c7a291daffaaacad73773ae485b5e554a3edc6e7e96f75c03a824cc47afc5d49a83f65aa553cd94ce80aeff4e70cde1dc2ee10a0298269e542db485bcdde");
            result.Add("eo", "3f4db9d153715ed45f9ed6140b46f5c65c49ff48e76c12289d18bba43b5c76ce34642f2ea39cd9c3dd28a1abc38bb72603577d7e54cd04d2b04b2dcd93aeea7c");
            result.Add("es-AR", "cd8e24490543786b9de81360ec3a91e7857fce895a367629db9049e3f6106ee771a30025c87219d64c803256f53f837c3f9c30a175ce9d9de111dd21e651c3e5");
            result.Add("es-CL", "e9e9d56780dd66a1677b06e9d0e1e001cdf3f40b28c1b7e20b591fbdedf60624380b3e8853b969d8865bad05567e2c604d4d5577a87c10f28501ecda825fae75");
            result.Add("es-ES", "94458dc1294357623a1757e0cda0886f19ad14587d3265f51a575415dc88c81dc82821191759bfa9e461881482a74f17afda2ea6ce9ec629cef28c8a7fc30c60");
            result.Add("es-MX", "f1dfd58ec856316f3c5a9209e9f69c84b670cdb0df4fb8591034560ef5ee11aa57ceab9dada53cd0a0a07abe9574c032d709c1075bd324a41d7722eb153ba393");
            result.Add("et", "3570a0bb828c4c9d08bee9970a97467826dbf84f55a112cd56d98d38a823a670111ebfd2e38d05ce980bb03c7deabc24ab7d298418608787ac4045559df51971");
            result.Add("eu", "92e5d8af360f8391c7c5602671f92bbea2caa6944fa67788ebfac6c73fcd3aa88bde99a7c244e7fb9b9d888ef6ed90401576d493e777d7950b50fa934dd033f5");
            result.Add("fa", "3fbc1f1124649eedf1b90f9fa68da5e5b94b31a92ff1882e53f1ed0e08609c94e9a76cc867ba05ae5a552fe46cfc9bff226a989dc515837df11ed9c89e91cbad");
            result.Add("ff", "6868550b796d440dc1e0babdfc38b2685b9526cd8e401f212219955a8567667f62f3f7a66ba9aa677b5b1a7bc3de2fd750af01f138b6c835d2f91f8ad2084699");
            result.Add("fi", "6c462fd679a7a4a5192e897d87ad0cf71207778b78462b3e1dee303de1a3a7d1de5f31876c0e62f9c3b9bdfad06115710dc3fa21e66a98778c0d6b59e9a41d07");
            result.Add("fr", "9019ba2549b65ceb677c176ee964d4d83a1b0fa3eecacf15f5c82b0c073fc785de92bc29cab0a394ec6f23d69ee6994ddbc1fb22713daedae20c51042c5b288d");
            result.Add("fy-NL", "c9bef967e5f947ebb20dfb691b81aa708b7e389aa29fe321bf0a75dd5fba20db7acd0e7c3df1f6de5827a9436325e8c15e38c1f6efcc148f8d241114eaa5c7b0");
            result.Add("ga-IE", "80dd00053d97507999ce72428396ff0a81188cd8ca835c941cb1b29b887ec6539fbe00aebaec4cb52c6d303d67c7410f2d6aed85e3731248c54c5cac7bf9c8c7");
            result.Add("gd", "bfe149aedd07828debb64ca34a379d1547bd5740e76c23d34d328c898c648246552d59211d47452ddbcf69706ec0aad2120a745e50bf4815ff1293fbde56316c");
            result.Add("gl", "b3d687a3bda0624e0b65452270cd2a8bf9f3db348ff269901b69e37a0e098d32631707de024686f28d4d3ce930018b01fa0aad4a30c3e5c92eb43fde55c11f19");
            result.Add("gn", "e2407a12878b2fd15d8dde2bc51c4e0674793c33a8041848092934e99fe05a5ad194e187470a896a74787d56167e58798756463bae434b4d697cb110014ee742");
            result.Add("gu-IN", "827cf521559c6705e63cf1b1a06d03f192deee225f603200301273a05f2eedb541e50277e104c3929a1b7e957df9ffb0f2fb6054fac7741b9839c86b6fc1db95");
            result.Add("he", "470360ead4298c5eea9ce608604f5fad1e36f498569556050d9990fde3e8abe6715f771dab7a20f0c6c497fcbcbca542a4b01f4e99612649b6312e754fa33ce0");
            result.Add("hi-IN", "2d6449f80e0b3acb9ab28ffd817177e50a77835c6e76a8740b71f80b36524641e8ecbcf07e905f61ab74828ec5bceb46f91fbff86bf84329858cd58ef27c2ca5");
            result.Add("hr", "b3350a76f54b386ba6f41b0e5a94cad24127bcd4bcf5965aa956d6536d9eb59acd4e486863b5506a21c6f6d3353c3d8dd29a95d471697da005422e086bb41df2");
            result.Add("hsb", "8fc76612fe2bb638109f0d089c6f73507189ee4341695a5d111c8278caf3fd44aee278c3be29053d98d858985bd748473870a78c036bb615df48b831120e2b67");
            result.Add("hu", "42fe21118774729de028f18ef34fa752f706b99a3770c63f75f55e3bc9fe679cd2f25ed6f87f498e01faef3b97809cab9563088d7d3acb7441c896cd3e4f45f5");
            result.Add("hy-AM", "7aef29a9796baa8a852984c300dd8371cbda113ce2d29951d821e82f2927c4e00cfd6b4aba93f56a32f15ff3cb3a3bd055eaeb79e35e33e4a492dd0ad5f5c743");
            result.Add("ia", "2fad9a03b4aa2797001860e6258c044f64e2863269aeb57af0e303337d4cfa602d0ddb42bfc812d3901bf8a86de43da6d474fd206bb8eb5347a36fc3f7cb6630");
            result.Add("id", "9e550386cdf365bc1b4989019a49f917d5b71601a47fad9f2650b5d124915a9a34161015eba725aa8849fb33bde09a1a42514de94352937adeac483935291cab");
            result.Add("is", "9b3d51fd51dce23ce6be60e4b0726a556501f1ec8c4f1a2b1d6f9c0f6b6ac599e6bb694ad2d1bae2358bebb034fca57f3037aca8991ae46f6c342901828dbc67");
            result.Add("it", "35d32dceef30f72eaa519165b4db58ab2a8b4741cc5a8a757af92e3a352a3c84241e5c0fab471b0b565dd0319d2c5adaa4c2746c189dc270b9f781a48d58ff02");
            result.Add("ja", "b6dc9d215a979d59287f20d9d7b0d3a31ec2dbccfd513415412b520c9d486d18d4fa5063f625e4a800bcd9215f4f64af44a8771d9b311f1d09eb7c7627f98e9f");
            result.Add("ka", "fe6f8300886b28bed7952d8e4f61e9f757d1974c7925901a20b1e591e017557ed7884c6d0ffe8366ad10fadab403389db181474a7e091d5f7dbfa057e0e905d7");
            result.Add("kab", "c650bab1ef21490bc7cdfef099c42622c8dc9ca79ceb5adfaa7a43c4fe4d5376abf40ba2967b8bd9f9822e45fa770d0372e059705943b99dc0be243ed642ccdb");
            result.Add("kk", "9735bb7bcc6356de524018e2d3ebdbae49def7ed0100dc7ae3ccbd19daf5fec53e51f390d72e5c81638a11a0710176c28030fb73216afb8f3f45fdf0b602bd2c");
            result.Add("km", "03a306540ad5d4b71f4247679b7cf874e87b6691f01e2031346fdb79e557b3c60ddabf162df91380bce13ffca038e69fac5c9962f94f3bc30ca61bb7a59e2a4a");
            result.Add("kn", "c19709bba04069200173a483ea6c5710552710cb6e82ddc03f987a61da2585487aa751aa4d6481192e297018ef70955f11a60c908ce0402e07b74cf4f9a9d3f0");
            result.Add("ko", "d4ac4a30d1b215da1b88afb3aaf56e16fabfe47b4461323a046a01339e402b1a62c946acf79d4103e1ccb4d824f8da88c4f97e564c9571a2d197753e7ca53d1b");
            result.Add("lij", "b84abc54f2be750c39ea6a0256cb4d2f73de41b93880106b6a10c9539b3dec73bc3d827458889d6f7747f940b4bd52749c893b56877e3e90298d0784e20d8c04");
            result.Add("lt", "3e339e76c05e54c9fbafb93b38d7f461992a74d68aaccf5e2fe51f6efa2129ff8c3b48c9866fa20c74bf84b7643f4227077bd7132f2f7ea4ac60532da29eb6e4");
            result.Add("lv", "618b4a9db4283b242f6209907273937cd07463e103b6e29ee6edad735dcc77fdb5a279135df8781647c41cbca363db695e01f225e7d11e75d5c834017592c2fe");
            result.Add("mk", "0f856593093fc79be20ed9b4dc443fde592eae57cc61f2dd639308de9f2e40fd0307297e202260fbc49830e0aa023a084126fc9ddda24ff2dc6ccef92c547ed7");
            result.Add("mr", "615384563206ffb5355ac0950145f39ff4200663c11ecb7fc96ad4e2362299ed77a838f25582959a7ab1031857fa6fd1c9f33c7c04100f54bb699403dfe421b1");
            result.Add("ms", "8e627156f1c147b0626c185ce06974e7967a069c9169c36d8853494dc5ee0e9d6239875d00e35f72f99c700cb96cf3337b1a8be8d7e9f14001d47b82ec3176ed");
            result.Add("my", "0206863676fcdce39fd1ca8ec49581ba51475a6ab031c1c58ad41a9ec3acc453e37ce73b79804691b04f9db45da301a59efc882a0470bdf5d0da0393d29597ae");
            result.Add("nb-NO", "57aeeafd646dd3ff5139ace665978f6998bc946e609f506b55e37c6a3dd0a7dee4cd84529ba20c956d132172de4b63c3ef5f2d90bb9a9e1234b83a2519120c0d");
            result.Add("ne-NP", "5e0716f98f80ad5a2d2fcaa22e93f0364cf8ddef94078850c1f2cfb5f2dec428db811ed7335b4e32d403eeee1a22b7b1be9d590c0ab45586c7cf896473445172");
            result.Add("nl", "e52981a14bdc33c8efa491254ae47ffe24c04e5f139fb1f73afa4b37c3afba1ae3bdc45ad576d1b72db3aabd5c5be16dc3cc50d3ac748aab22a72d2a0d8e1103");
            result.Add("nn-NO", "85294341825566b6b1f633fc4f4c6b46fcf068a4f4eed1a13fcd31a65e93bd2e11168311741029ba8ada31ae61b2c53e7fbb98353458c2d14adf88d0f61b3e9c");
            result.Add("oc", "c07364093b755a342df92c19d1072d068eaf25c22c59625b8906d8886b36b03a1b357c6ce2f45fe850ea396bcaab085d2ca27279a373e6ddbc38a581ad43222e");
            result.Add("pa-IN", "05ff0951db030896bef7cab82ff7ef30ef1c54d7dabe971b5fcaadf405b7f07dffb321f669dcac35ea4fea779d7981751850e67db876996e94b3b3aa09c01222");
            result.Add("pl", "1a2835e89d6847c0558874d2669ccd1a7c47d195fae011f0f3cf4588a80c1d511461d3114a525b75d0c4b745a3d1a71cd5b1557548001e7fe412c38153861b56");
            result.Add("pt-BR", "9446973dc07778b84661aaa281914e7196730e687c7a7f08f9e020f44932da716fcf796aba88748df5c447097680752ed16d129fde4ff2f0a11881007bad6133");
            result.Add("pt-PT", "b132c78159985328a2fc7010c55de692e093eedb9da5968571f6c6e557fbde38e32217e3eb53e18773f3f7ed00b4f285935bf2037839ed843eeaf0369dc504ba");
            result.Add("rm", "7fdc1524793e339b7e6a522d7b165e0d1a1c57be513dbe720918f0941f63a2c6a08cff2d0b8801a9e2ef1def9357dc5cbd6b344214092f89f9e196f0d819b858");
            result.Add("ro", "04412b901b2c74c805683f0360fdf6bd6a8fa5aab288947c694741d7c4c84a9197a278360d22a9ae31f9481f11be2cb6ce0fb1bd0918aac82470ccd694fc8486");
            result.Add("ru", "84a5747922a2916eeab6f2e905407e24290a8b91bbc3ab83440815308a0d77f93ed3a583b497de48a0c902741806f3bd7d823a0bfa470e1d55b2db8e5af187cd");
            result.Add("si", "fc45dbcc1dcbb70234c7ac1eddba07d0705d123e192ce6130b067ac84a8cb296adfd57d49be7da82f9af1fdb31182cd27c99ff9c31ab3471c82f6fa64a8c5cd4");
            result.Add("sk", "3d1906429c35e068f3619894071a2f754c1d7e8cfbd466753d26142b45ab3030140c4d0e782cefe7fe4bf4d1b4a5b82046fb44d4349cb10d974274ed7c4aa20b");
            result.Add("sl", "212411c8b83ed48530b3e44d128edf019ac1f166a884f320892f5652ba6d60e41f58b2f59ca91ef19e5a4f26b6ccb237a48200d01d7131a3a49d0e4b849f2e52");
            result.Add("son", "dbe64f613d3f43d1b61f17c310a681130790604ac7edfdaa45417c797a3b32cbac3b73bbb0687f8c52a6202c1442f03dc98805f85a004ea0007a88ff4df4b30b");
            result.Add("sq", "b8ac0c26e2a6c3b5c17cdf5e7e03723e0ca7bc2ac5240d7b2ee2ec3b8b00351468f5558d62e2b0ae6e2ff88462ce9ccfb074ed10db411993289047e974d7287c");
            result.Add("sr", "d06b1d511680fff530adcea68184305300b16ec65d77c42c0cd36bd8e2ba584d6d060afc295b36bd6a0f5513f212b3d2095ae9d371844abb58f9b512b2f25e69");
            result.Add("sv-SE", "c6436a426f2798f6cf5fc7c959363d9f6810a06084fcf47cbdce3c1e3e1a7dd442fcff57156af53a488213e3fb9202d3c0bc34f1791c11fea74fca5b1e6c3857");
            result.Add("ta", "82d5ed70ea346422c4f63a2d2cee3f3b4ab2f1bbda2b44a08264ad0a9e02412f63b4c755d36b61d200813e1b8671a7c0657b3ded65ff5703d29ed9b913c6d6ca");
            result.Add("te", "d781f2650a2d4a1b8c1138c9faafc0caeade0304f24bc6b1e95dc4af8afc25ce6dd623a7d70d5aad7a68f29500fccc420187282a850cd84cfd8f5a27464b4102");
            result.Add("th", "187aede5888426a6624821d0216870b8cf8a5c87984d25f32954280bb9bb0658cd407c2ff06448e5bf123bd118f218cd23efe73cdae1247ec562f1065d7b28a5");
            result.Add("tr", "4546a81f195df5b8cbe66b4bd9ba4233fd5bc999f974addc0dc6dc8b3086e2a54298c7dc0f03cb3b6f6f2fa60daefa3b0aad7e0df0f3f6ea0c532102fc104aed");
            result.Add("uk", "7b721817e5500d7b60b9a10ab185c7a0d776749c9f838ce4ecdf4bd7682da83495c8c6e394879d029da56dd9492d63d74cf88caeb14568f3d47733f2fd131154");
            result.Add("ur", "e9940c24764660188a7a1a1f71dc917cea521fbce23f06fd5213ae9669a6abbd5d91a32cfea2eb11c1714c0da4f22d262b8d092223165d3cdbb96fde69e85ab5");
            result.Add("uz", "035fb413d51fe91f173f51d7a1fae002562e7027678a01254a871192b06537791a4527a7dcf5702e15acc14a9edd130007043f1ce209969223b008a73b6b67b4");
            result.Add("vi", "570ddc07b501b0a1c18980568fadad844622fce9378d874b6fbd385931a424da66ea8a73e78bfc835641d39a720e4838d2a9a0f08a9756fec67686c485fc460a");
            result.Add("xh", "b5476263bd0f598dca0dca8468947efdfac2cf5a3c5110d055234b533fd2581e1de5576a0b1a12c22082423b56136715d80409ad205266b653ea5050c4357abb");
            result.Add("zh-CN", "d801d4cc31b172dca03ee79cded2208e8ed7d1a4f6d58e1ff26c706aede67a22b564644d4b5c419cf8d7958dc860b636688ca5ab89c8712c52468552ca5f004c");
            result.Add("zh-TW", "183f1548cb7a1334abc2288cd1bbb45f094c593981b7bafb313ed260ad4079812b6ab128c6122fdea91acbec04474ae4ff382585c4fd1dff8dcf005f9095a283");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/70.0b3/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "99e0e11b8ba798e8b26ff1a128a57944dbc9182ed989415dbbc74bc7c8a172094f6152382fe2039e26b793b3297d90895aec62f25eaa3005fcc604c84c1817fe");
            result.Add("af", "e6f81e6b050ecaa9ddca007d8741898960d8672832aeba6eccfb4c218a45b65e9d8016bdabd9aab647704d952ea9af7928d0b13eb70598ef731407f6093c111f");
            result.Add("an", "7e5274093e613a96518675c870409b8297e68e8476575147cdad21e2ed32b0aafd495c63dae918a4030011332cb9d2c323208d774e3d4a17187ba768a230ef5d");
            result.Add("ar", "6bdf44731d5b7be0e7a2e6ad85d3cf7b6860568fec43cdf1f71d02170b0987c4bfc6ded7304d4da9d1e99c4aa2a4a3b7ede0445d4e14a597a52b3fb99f985c4c");
            result.Add("ast", "1460f68bc49a74be1eb726c6ea142b0b9bdb030ea1263a34f2a939fb03054dccd7e3909c267f9eb63241fed7a9678fa8ae6e9ce6b558ec929799ded23d55c13a");
            result.Add("az", "c831cbc6520a7af8b53848cf5132fdb8fac127d961d8d7d7beccea5cd573974f2fb2a767c53a10524c9df1e9f520bf35999776746b260c1943bc9c85ec17760f");
            result.Add("be", "f8b2afb50df5142ad3f9e9a4c76dc684432e83fbfcce98b603691ddc77cf2941e0b14a70102c1917e751c0545d857ec995974d64f788fa6dab23a4a723242bf4");
            result.Add("bg", "695fd5bf34cd8b79704a4f04fb627b52502fdd12e7678230d86601ed52e07928c85e850d0f9f0b5b8dc1b3cc066eb93740c6982146211f3ec7c90d6447c01c08");
            result.Add("bn", "e0a7175f19eb8a0ce09465863835514f3357276ae5db490e022d8449e932585c4d448546fc11618da404703037d7d31c2cd466cc995b1349a78549785bcfed15");
            result.Add("br", "10bd5402a00ffe7afa69f73d137a9ff0b3972c8cc96203f601600c34ce5684a275ed64066a2908fd44d546585aca7e13b7650da2b42c57c2a8339ea7dc36df87");
            result.Add("bs", "1db9600e1437ea5d3f8aefcf0b5577b10e03120f0978222e5762f1bace0043c73601ff8e08e34cfd77966b3292e2d381d26131a423fbec8867557c580f0ad734");
            result.Add("ca", "9ed76893eef371e6ba013e11b41e5c202cc5dc66b0a3a6f7cc01853fa723fb0f44df297cb2403386443aec314cf22f1f16685003eaa2031ab3b2a40b5872f137");
            result.Add("cak", "89a2ee01fa3287d48a7d63349715dcba037245e2af8b96254794e388f58c0b83ca13eae40b9621513741fcac43bc58761a5af8e0490dc8cec3474a78001ed5d7");
            result.Add("cs", "3fb95f56c683726e051efd7fc455441c58988abf4100626c6b6e225c936af6b5a2c9b80f8b1165dd40e4558eea74ceaea6607cb4150f78d1d1ef26ef60dfd6fc");
            result.Add("cy", "eeadb3e806fcd231374246878b0b441bbb8fc8c563cfdb05080154d9d147dc86fce4226b8c36457fe65c93b3ef956faf9a3532563b8b83e84e1cb770f5e7ad63");
            result.Add("da", "b07232b0cf3f42f1bc52147e8a47be2f90643bccac902efd8752617946cca3c5892f79b4632efd03e0a4bcf23dd4bae48e70c1b2403e57efb54016c13c4c791e");
            result.Add("de", "167e4148467f25f7a7242f638f1404fbb1925784fe751564d1913f02567b5e08ad077c9efe163edf17f721fb1bba6b0f9f5f3274b69d03c00e9756582ca63bae");
            result.Add("dsb", "ad720902f19f69ae8809264ecfe3827e0620f583511f4a7b49d8ce92643a282b368034f7f0a561e94af88dddbdcaaeb4adb8a1d5e3a930c2ed68187d616f2cf7");
            result.Add("el", "efe39bdc8d7b50331f2987eeab3de0d93e77fea2567ce355217fd81a1b2d58bfae362d1dc9b7a05791e80d205257a22e1952308f4f6c7314cd9db8f1f0ee9f8f");
            result.Add("en-CA", "4e3b21f2c768351c9d7143062bc311a069691eed85a9641cc21d56d8d99bfdcb946cb58dae58a9406f2fffc5b31316b48d7d117a5e2264f7611596c0ec550b76");
            result.Add("en-GB", "a5b4eea659059935164b9586df0ef9ff833cebf86979323c3fa159a88d1cff2867ea2cd652ada3aae6cd94350b4c7ff54043cfe59649edcad5472f2de3f5d870");
            result.Add("en-US", "4a331a5905ac0cf47684d592df80bacb7ecedba76994f308ed0f1e1d94a822017e819656aa32deda4614fcaad46330ef31e36a7c201d9fdbe0d4f186decb1c24");
            result.Add("eo", "b8399a5dfa7cb1a8ddccd3be61701d4a1b9146ce56b9d6f6f8205e910bd9934c56e4a47d943dcda21ba6f6b055ec092cea2af21beef4f7cfe7db2b064615d0e0");
            result.Add("es-AR", "44db2b150207433e155875c549933d8e6a8115bae8433c116171632c9bf1fd337f74b243498d09278348ab6c3146a993cae954a2741ad60f9dab5aef4bf2cf97");
            result.Add("es-CL", "5c01c9b8d5c01cf7a754ce900f49d7eb53865f383f4a2a1ddba883acd8b7d81f6b7ddffc2c729e2b3f8c1acdc7ba47d2b0c4bb4c30f5aca7913d75155d98fbe8");
            result.Add("es-ES", "37bcaa4136c18dbd00166a9b1e102ea9382afa2ec581e17ee5d63f83bfac9a3ac885a60c72ebe6060445ab0ee6801ab1f3fd40b306f74dbbb89097c84e327588");
            result.Add("es-MX", "9bc1cae28be395ce649173ee97ccfe8409dab04ff14e2336aa38b4e07dad53dc2aa1dcb07f62a19c09ad7b83bded5c7a5e97a3413fbee81d195b5654ade05e5b");
            result.Add("et", "8b3e79aa7451a9deb7d195752593abe9144de23b6403ff20d9b2c1580b68e086f541e9e4f94fef621b3d4bb8c0d34a3beb28471d09bf1574cc677c24a9512cf1");
            result.Add("eu", "b5021f02a7521dbfc6bd38998d67eee1809d4db7d971578fb3e38216268be02755e5c29b51582f5e24353155443509eca24de3aa40be54286797836a2b0760b3");
            result.Add("fa", "4ee65b42f4d74b61f6aece5efb26f633bd3366dfdde76647bd8990832c845b4da433b2d06ce9cbb1faf49df4828e07a1a81a44c3f54df9132159b6832c8d8fa2");
            result.Add("ff", "21c9eac71ac13073fa9cd6942ddb2729a0b31c3c466e68f655e94bd8fa12dfd4e0f1ec98aa0149ddd04174e4bb844ae59bd13e8f0249a9387b7987628a4543b0");
            result.Add("fi", "71af018ea11c22f6755d3f613c4c80db6d5f684eb7bd0c08055c87cd5850a6622c94cb3a826d3f3c677b4d923c231a30f862d4e7e19b86d4f3bd336a759c70dd");
            result.Add("fr", "bc8d8bae37a2c8651aae8fec50b0eb304b09d9593ab24b8772311ce5bb1d2a0012f45b7745ad3e2e0f3bc2b6be318a7c929bf44ecce65e6d972ee702e12c3897");
            result.Add("fy-NL", "cb9286063a8f939815cbd72f0cf012f413e2d9f43da9645451434d29fa8f0b09c107d02ebade11a20c2e7e81eaa9109548adce1e672785a262d10dd54f766819");
            result.Add("ga-IE", "b0687a6904484701caee34818d7a625ae63fd353162cf96ae574d898db69d095d089cc9d67c489487d817e53ba757488c7964d80f98a53ea18e9b875525c271a");
            result.Add("gd", "a21d2a5788515c5bbdf691bb2ace12d330f24ed4b6f327e285edb192525b1ac589685a9e0b5efb5da97a5c15f28233736f0c84c61fb6cfa8d18a3ec30252f4ed");
            result.Add("gl", "f96f8d2e2d5d07cba7519ad91ab79ef6508d8a280c3ea229d0ad7f7153f4ef9053bfc44a6f1a6e07fed08631689daf3ad7db58ae26b207a67f32a5ddb8ba21de");
            result.Add("gn", "2dabadc68c4bc119e2f57bb33be479330d16eb832d7a404631b7839a67e328bf015bab3a9c109debca89bb4113c3b1ec62760aeb3d334dae610dec18c9ab36f2");
            result.Add("gu-IN", "c838f5509c904ad61fb9d1722ff9a6132f4e9d3ed005d965baa3dcd85b6ad2e7ddc9442327be0271ebb93864f1757bc1481d5651985ece7eb296dc811f1288c5");
            result.Add("he", "aa35e40935ddf357e2cb9f9492820b69cb7fe30722e2cc7c7b4d2d8b89d795131a272e88eb7efe3fdfedcd6dbdff0bded98b89c59bfce0c62b50b84fd6191000");
            result.Add("hi-IN", "791ac630551ee64ad9226c0438ade60b6b12d99d1bf5b07bf707db9847e2f2115d356dc0ff525426c9900af7e851f5fb1e58a485dd8d9664f20de6d895332dfe");
            result.Add("hr", "9677dd8731dcbe0b614699e1bc5e23ef013b767d33388e44fbbe57dc3da5ce82b22c94483a992e35ce07b428a6e8fa0448f41a4b6d8a3d8a19db7b9d57c3befe");
            result.Add("hsb", "99c3f0c53c44e76342540f33e7e76205cc6e6f64fb1b275f9663331ff62f8893537d08dfb052500be09bb1bdccb5a4d215efe071a32aceb13385740052828dff");
            result.Add("hu", "77b9c50aa30733106b352f282755f9c46c6750a19f6cd1cfe44cb4067f3e57d979fb79821533f3770cc719ed804a3c6f49552eb33b1549c9fdedbc5994a23093");
            result.Add("hy-AM", "f1c0dcb334785544b7d6a0afcac4ea6370dd5bd63416bb987c8b22fe644673316251504b0a112e0c86575b94b420e1ea1363b125ff3c9a566a82100732b8a018");
            result.Add("ia", "7e39e2b58f04ee7c6318e6646735d71d3c617d5fecef8bae71451b95461007db206a3d2edcf689f988d2ac20f46c0c7400668fa2a572e03497ae5184543b29ce");
            result.Add("id", "8b8945c67be84a767e9d658a2b2474cc7cb2f12b28bbf076dc69adda6d57066fcb0fd04e86f948d501256266fda0da0c968f1e79098d2339aef689a9e15c86a3");
            result.Add("is", "eb7490da741a90d7addd0930e6cffaf9f2412d25149d5220b671e9e55d321c58bb0ff7059e79ebc10866a238c35f478ae85ae2813447287da24a5e0a40f3d457");
            result.Add("it", "bd86de7872216e657da838ee422a98fa25160501805fe1c1faf09acd2e70b3b4815b8f48b877376cb5b2df9457822a99982210f8ffe2196821b432a22d0e8fb7");
            result.Add("ja", "72427654845b4d2fac029c13f32d256835147d09c5ae36fffe09337054cdb07f7a926ddac7b9ff0dccc56f99fe912ba95e9c28b7b4bef00e29322512484761fc");
            result.Add("ka", "c344a53518faa20f8bb06db28e1a96d229c17b8e4322c65abed14439c1bc303da75a7b99466f9a8f00ddddfa062eef5e6e0661db5695d6500b8a595f83ebe469");
            result.Add("kab", "64a403a8a86e3810bb58dcba407ad807152f7d1c9b59591e5a4b5889b6e99b3acfbbf7d1ec7db623095550f387deb9bf20c4e9c01c0ee41da012273433190531");
            result.Add("kk", "d407e9213b3f03dfbcaae54ec0b3de3ecce22b634ffd6f2ce8157fd0eb9d870b1d124d5a9438a52dddef145cc1829afdce586dbab1489e0095938ee62af1e4a8");
            result.Add("km", "f3ac077280a235989396a68b51e9ebfccb6c4b18b0628340abc264067a755cdf2102ee803c90c18f96751eaaf5e40273180af63720c28098d13844877d51acb9");
            result.Add("kn", "7d976a42dc10c46656eb7d2114b2fb0f5fcbb3c74001983616f6db82edfcd07687f1b8533221bf0823289d5e75a70ad6c47c1b24b148707ea85b1321bbd932c8");
            result.Add("ko", "6b9d87a65256485a2bd3d1c7e580c0ce848b175083a9b2302d1190a195aab76b365d9f867457b90dc42a7c8f94c623343089e218dffe83a01ec4323869657df1");
            result.Add("lij", "42e9d11e6464977032e3b5a036f7704e9452157f95c95b92283da6459602e30bca093bd0983eef6ab5a1336a67f1f232715dfcaeb09dddd7db3a2830482c71a6");
            result.Add("lt", "484c7f488edf01c430172ad9dd4952ebfff26b1259eb0d0bd444675a49a600263d0f9b3b2a876b488a0731ba2962506515a258b103b5021d331ab330038b7dfa");
            result.Add("lv", "a4123fb0b1248ac9d294ca12155c3144dd16d0896e42b3eb54a868677f9b65cf2e421dc46a7c17a97fe80272f07da78099b7a50dea6fde0e8ff44cc04d3ad595");
            result.Add("mk", "f30608bf773063bbf10f1a62f1ae87e67e26b557dea2df56b7553318a79c38786d765ff1b2845b1f934e0bc279e378711d0c6c3576d1eee3e04ff5df3806be84");
            result.Add("mr", "22023b6edda16219aa536dfcb98b1628d94c3c30473bb336b08b9900d92c5612d62a382e6956006f67bbf4f8f3420a946ad578cd18b58552088540ffc473693f");
            result.Add("ms", "cbbb4174ddac8a0f5152cbad3fb69ca745da4450e1d567a241a9a22e987df8db57853df6f1b8442401d0a0c9046af44799ef3f69f5f8802045c5d6ecc130ef6d");
            result.Add("my", "84ee05b5e43ebd73b361215ee93a423fb68caa64c661fe9549467133eca013cc2758551c0fc3cf1770332b2565f28af0790c9b46e7a2188a1e62e1357bb8c75b");
            result.Add("nb-NO", "76a7c45d46d7591306890f08f6450fe2c2a7234d46e999bf78e9c22a8ea4558c29b5701f1e8f414496835aa93a4b8a23aff5c8e4a409d72c8520187c6f95a98e");
            result.Add("ne-NP", "603561ff13fd579d984a293e4996f9ccec91cd657588b22d3f154df1700866e10a0a4d869cbfaf2472842c40fa1e1a31add33be954a9a337d2fd97d9e12bd48c");
            result.Add("nl", "2a6ec1695028995d5214b0f75d4052e1a96356d33183bc58f6c0873b8149068135587683527ade6fcc9e7b04ed5ad35f28ec568257a634adfadb31ab9125122e");
            result.Add("nn-NO", "c6574329e1047f0358f456cf9d94a53de161f1b28185ee1c2bf4d18f4564c6514c5a40360c94ec23341c76e4ca0c46111012ff44454d6a0aa10c880e7bc95bbe");
            result.Add("oc", "bcf0d654b44fc7ddea875dddf17b4b74d8e62f51697242c310d3d7c4cc4dc210709dd95b1aaebbb6cc65f774ac328cf747deef949f054b4c2ce08eaaaca0e9b1");
            result.Add("pa-IN", "1886e68343e6def55e67188587e4b3e89e85c927edc89978d68db65a360031d4de38bc0177da5ec0c9192465a2cf93273140f6ce00ef05705548a7caa3e8b693");
            result.Add("pl", "7b78ec48de1cbab59bd67e4a2da87704e57a8fb018fd62b2dd87091694d2aa6b08e8f73b9acab470e65d827a978be1217d4d6889267b4267af81fc8e7a34980e");
            result.Add("pt-BR", "8f7f2078627961cb99717a7ffd95fed168acf809c425ee1a5c6194e8c12029e10395b1a059e4553d117d6fcf33d105b3cd0720166ea61e08082f95ffd223dbf8");
            result.Add("pt-PT", "15114862381dbebc9b3793db2c67761f952055d5b4e65f104ae915ee7a6061d31c413ff110699679734b98640bea84942c4cb401e76181aa15a6fd552efeb889");
            result.Add("rm", "7f0a22a8a5dc6eed8ea3e4818f943c51287740be4f0ad33a2b4c7b4f82a7111b58e1ddb83d1eac43935adf163db606962bc196daabf3595dbc2b8df2ff60b914");
            result.Add("ro", "d3e753d7c01c9e04d777f099b35b6968f56cbdfe213342c2519e10a0a5fbe876c35b4bd618b9c76ddf0116282688e322f0e78115df95a126bfd6919246556b31");
            result.Add("ru", "7f584198dba19a9277f0eb8ba028397645d84d931abde2d002dc6637eb94fd3ada1c70fc27eb245fe4f4fd60df67b9cc763d15325d71cc3c5c7d5484fa80275b");
            result.Add("si", "3ad89ac2d4358d30130ca4b1ae741dc5f5199e59b91ad5e3c28fb4df433429015339df33f6a6c5cbc48500858fc18e18b1755f97f03e80261e520e4acaed936e");
            result.Add("sk", "919a64ac3b6f661bee55f6bd9074c8ce5a78f7bf1e95585a27e21312415649fa91b5da25f7c328ab2e3a191f8042a8cfe3d4fb89e02c39ac97ed0e8ae1b43336");
            result.Add("sl", "65c9532b811c261d97c7a224cbc35fd4d8421b7c127a3472c35446c904c49d690d4f2536d79ff4a70f4a240d377e1a7a73aaf031a5aac4ef73cc4ef7d473fd7d");
            result.Add("son", "f8b589a7655ea39f2bf97e9652460581b04a8c49dcf6846da856a8e2a6e6e9332a80fd765c51386bd1cf526ddcb478531b5a415621e2ae70bb04a5a47e68b371");
            result.Add("sq", "f2496ea2d29a3fedb6829ef90222c4014e1d8ce84756c38a557da4795b7706f3cdec96a4b2009da910e21eb6c52ca23ee221630b76aa3004108e6c51d0997663");
            result.Add("sr", "62be0116241024765777a5c3ab69747d996f0412daddc4586032ea4407d79f78512426fb830c9594a11eaebdffe6c8741955fee09fa2491125559bee58fc7471");
            result.Add("sv-SE", "8f65d8a151e37a9cd0413d2ef7267b2712dac085f7fcd905ceec54a5238f3a084e94b3d8db0bf36d6c226aabca677a24d7fb2271d9ed5744d1e8cab4c40b5d72");
            result.Add("ta", "14a35452f7ad33872ca7fdb214856e72560792ef53e6bd6f2800d6240825661bbf427e4ee3ac076817d09388872a657ca7d0beb32f3dc81f6cb1f3d2338e6110");
            result.Add("te", "fc3d251a140c57a6e2dd713686bc808939e3cc414ca53b91704f387dd4b3e9e73b3e2323fcb95ed62b7661f367d7d28833c7d0690030191052cc922f1c7e2c38");
            result.Add("th", "94243df8c34f272af6a1194cb7c8b7cbe929a5d69e675db7dbdcd088b2e1444c797a0fa079eab31f1d884d6d8668b8577698f97a0504428cae4ad4701cee2973");
            result.Add("tr", "93a383a2f32654fecf2d0ef3673c5cfa49b893354ac87bef83aae2b1c47c397b34efb83dc910b6fbb79f44dd5025a1fb9b087870d5480bd23f6aa2f304fcf911");
            result.Add("uk", "a380063fb331411f09998fec6a24ec4ff528dde0c08e136ed9915aac2009fa7507201d700bba994070a6ec30d011a6aafaeb22d6e526258902f27145f8e4aeb7");
            result.Add("ur", "d311d08d4d9660b0ecc8d7ccf48df0fb1ae034c7e7a8dee66ecde4649d61885bc046b4d70288f5dbe48b0a57223cce30b2a86287005bf98b44477a9a5455eebc");
            result.Add("uz", "7c1e4146931372ba2265732873a34abbb52a52cd5915f4f7c59929c2a437a099e30d123a18f8543e39e1b18dd75c8dce649324a9a1c19685a9b7a9bd7eb6e1e1");
            result.Add("vi", "dc1829abe62a0e0a4a69c242d27ac0971cc02d5adfa98ca0284fb457766e89dcbd4699c018bd33cff0188c398c625c9922bd2f3f26845d7bdb2ddb5f1fad0dbb");
            result.Add("xh", "987a30724f77a162677a9ef06e9117712c708d6a3292c632448be83387df2d2fe9d7b5a0e005e951582ba08b392057969604cd7b700ca4d82893878cdf57da1e");
            result.Add("zh-CN", "96910358c99a9425ea329a8f878f40fd092e2c271edb259b5a002e3b07af28eeb0e3832956819ab01bb8c4fec5085562c6a688ee808cd14dde6194db3d04baf0");
            result.Add("zh-TW", "bfa8fed5add0e337bdf8f4812fc4bd8cb04fe40a740f46ba64d25ccf5f0382b0a10f13b0bab5579039a4eaa3cca7938693268a017ce3e4640cbe44f491325cfb");

            return result;
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// the application cannot be update while it is running.
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
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;


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
