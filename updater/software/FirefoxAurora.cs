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
        private const string currentVersion = "152.0b10";


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
            // https://ftp.mozilla.org/pub/devedition/releases/152.0b10/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a6567c73d38251541f076d484ae28d732943006df6515e59077206b44934887a41f7e7d1c86bd7f530ed10a710559056beb1d1de695a0480cce9655d50d188e9" },
                { "af", "ab9f6556e8e01442045a241c671715904ec406f890fa01e2431f9a7621d632f66822f0427718df28eeb621aada3dadfd0e916efb44dde7a4f10371f6cc3f7a8f" },
                { "an", "60b8610794a45133c8317b42d2c9ce71166a8401ee23aa1fdf90003aa1afbff10dd16890828b9f8987864033b12ecf207c3f57a7c6d3dddbf93a356d08379af4" },
                { "ar", "02782858ff3c3b19f02a07f2d235860de54bacbb8ac31b641433c008b8b2e56ba9f0b73f1445e0b85fa6806a66334fdab9ec7b0261cdbcb99e2bd95ae972acd1" },
                { "ast", "3a38e59f05e6894dc79338b43c8cbd8b758d68ced800827e30dcdcc497b9bb048fa071ac8d6984fe02f668b54d8cb88a5e693a66aa4cd6fbfbbf5db98e60165d" },
                { "az", "ee9d0673cd712018d7dea8dfb5edfa30e371ca344e0592450c41494d7f1fd0951a2c5ac5aed0c220ce9b118900240c413f5c93757b0be5df399017b89bf40638" },
                { "be", "00b28b00e6cb8e66d113971355fd61468c2351de2df9b51fea707940046b1c2dcd76bab796a861424f359bfb0a04e3af8bfd4eb05f815f8acc2fe01b83503fe3" },
                { "bg", "33d9db324e1ae1730fd5384ddcf2716a4d328852526eadf3c3515e8baaab535c8a73464bb700673c26790c804565790fc5b401c851071f637cf83a93d3c7397c" },
                { "bn", "2f716df3802a7366a39763f88a3ba60f0b591d518d29c46f48d0a6662676cd86197daf55e7c45d16352797d94a9287840953771285c3042bb62bd6097d2e12b8" },
                { "br", "75356e51d2a1162bed102d0ba965249cf30653e04e936fcd6b3f09ea55ab40d4e30afaf4110e313d82558d4da375355c9cc5c47b28bac6b2846d0d0b75357200" },
                { "bs", "1e5c52bb50ea0ce5064aed271cc7cddfd6fb5ac00520d339c719e2269f6fdc0dfb2d8feddceea5a6d7ef91b0a31ee03af71b6c3cac3a72746ae198b7b332c8af" },
                { "ca", "7554199f98252b16372dce66171e41b76015eb1f3861209cc0e374a2e23bad3f755401e204f6d2497c3f7c170e10ef7c6292d645505a520a8fc444caf6b7c3f7" },
                { "cak", "1137e3d81ef7bb395d7cbaa0fbe971fd8961a7dc4bac8b2767548d2af914b1cd14a1a6708daeb356a5d60a39279480b771ee84dd419cd3695879635abc832952" },
                { "cs", "1f40c3eeb426a044bb1e93422233558ddf286f4f3f827be2f44d592303c099a576a0f29f59fd089ef93b5dee7acee45eb4e0b5d46d01f09ad7007bdd6896ff59" },
                { "cy", "a6cafa1de0b1dff957c82df42fecda6bc94064d7b51fbef5233ff89845d9bd51f4c23f176092e176540c377b98de195fb015fc1562340675428b184f59fd20c8" },
                { "da", "252f92e36e628129010457d3d983bd12d74f324ea8b2e77536b4068ab426e6397a2212862a18daeae33ba0256347cabb350fd75e7e592ced2944b325c5f43244" },
                { "de", "7b7dd0ccc82575a93296286beaf2a60ab2ddd5c97efc48a9d360e65db0b17aae0a5f181d52ca05337cd01c02e2e6cbe6b2bbb47a8569f7080127caedf3007244" },
                { "dsb", "1e0c6a6691c66c3c4f2fa5426bee1517ded4f17b2d80c52d7fa8634c34e6a23ccbdc59ff62634871acd07a577a73b729f684e5c38bab957a206dc0396b3b322d" },
                { "el", "36fbe3394a9190998fcc591fc68d10a7a0ddb6595e05f168f448bbb678960f53510970283d15374a6d3eca6f85e953042d4d9250b5702403506badd5f83e24c4" },
                { "en-CA", "b75ea1d5b90b63a90b46d927d038b81b9bd04afc018e9fa93d683fdccb94102408fbd00adede724549761e5820ca8b51cb1fbb1908cc0b7ca24202aceca38870" },
                { "en-GB", "5e1bf1b11b7f2ccb8d28abbd2f99b48837009fd42b37e62289f5b10122d6e5cc185cd4f6e8b4f772df7bc3a4bb40058b2812cb91b0bbd4387c6278551accf70a" },
                { "en-US", "6665029a9176cfe5b54352e57977f0310a4a1da0431f77c97b6133a0099e1dce79566e442f1c472b813f83ed914143ca25a1ff1796ba7b4e654d986de685d997" },
                { "eo", "680801dd019c48432a8476ab110d0382ebb436b4fca1d5cf9f9e0d04446b2ab828a708409bccb7babcf786e0e912d68f46b002af1f89add4309c4f82c2e9ca82" },
                { "es-AR", "710a78719de2cf05e4108926b1867d55beaca2ca6ace442eeeaa12b90f6deb49a64336ae5feada2e7b4bfc09edd6a3adeea97f6520354813078f6053bf29d703" },
                { "es-CL", "868bdc7c53fa258878ac81e576b7a1c05f7a929a214f1f296afe5572ac58a604f8c7badf824f9928c99a19fc4418cbb72244adaaa8772616ae825aa6c10ccdb6" },
                { "es-ES", "70bd2f023bc311b69f492eccbdfeecce0a58fa046f73c76f87b3f17cf7ad1bf280f71f876c06c642584319ed3a588d3aa4e34fecd3d2780d74d0b8452c68ecdb" },
                { "es-MX", "95148c36824674f33c676acf89aca428ca18c4649e1391eb7350799319b9077d3e7c8771cc95ce01f99df867c30aa23657a268601427189e49ab01115b99a26f" },
                { "et", "c93383b48fd07d13f9d1f467d37fd28f221257519ee8ba5f1af552758aad1013706623fce0c05f6478bc34276718b41ab627193439abc637c23891ba5c1c9f4e" },
                { "eu", "6b9bcb36df0c091714e87dc48ddac31e8f3ee5e18ed166967f34d778d847c3674eb1a4d7367c2d229ca9c114a44a382856615172db59c0326d2f647d4ec1d00c" },
                { "fa", "27b54377b85957db9e28be734c52b8c960a664cbe1e52578445cb493d2b0745962abb2a138d8f15e7d975cfee10b1bfe95581118580ddbd55405a8af010d3dee" },
                { "ff", "13e8a654c4ec4dcb39ca8842ccdf1162c36ed24ced123cf1d1ab6d4b8d58b6faa06da86baf77f7c0c5d109682c4532eae285e6a194a3f7ce35ddee48c1864c12" },
                { "fi", "756527a23ba8468b7e6cdd45a915ce598d52b630dc61281fc1c35fb07b03cbdccb683e32eddf014d3b3700662e33d505207530deb8266c96b725bdf606f12429" },
                { "fr", "03a5324411af48ca75a1652754275ac1322a2219cf51b3d00dfd2268d9e4069ee824ae2c1cc2c5a9591ee3d2adbcbba288dc93715869d11ffea54315d2c6e2ab" },
                { "fur", "eec4af0958fa8f571b440a5fa73ca8d18737fb06b731258b756868b63b1f3976a96000d46ccb10337a4ea5e0a0c586f9259a959957f20dd32d4ac90b8dde3835" },
                { "fy-NL", "b5dd7f747a2ae88959f8fe07de7e225ad8f5537b48edbfdc04d33ac4938595f913cbafd73635f3a06f8bbefed4420dab07c42ed9987f61bda65a4c8310bef989" },
                { "ga-IE", "c270651e74c308df3b26a51a2afbfe6fc3565b83aa3e22c13da738ed1b6b590883b185c360a3677c1c568b7741f084f4902358421669cda824f93cdce32782dd" },
                { "gd", "6b78b4c52d6ea4366c5b6d775ecc49c35b351b686c40fb9b4ca1ea608a07061c5048fac0fe541ba52e6fe8c70403710fff8909adc16f21f5c9093af3baf13f02" },
                { "gl", "5ef92225f24c6051a740be36635ab58223aae6f0f7f7a1d743457a05ae3534f67a97b1881cf2ff2d03ec29a6b6bc97d93f213f59ca6b8b1bb8fe95cdadda411c" },
                { "gn", "258386744083eea8771708e6d1ae23fabe1fb7ff57e3c95e9404f8e7840ef8832dc3afe9e35ba306023009a481e6f5b10d84dc85b7482358c765ca1cc553207b" },
                { "gu-IN", "8796e54190e2bae87191de7d39c3b2c5312cadb51365f40367bcbf0ee91434763a42618c4f9b216f063c1b4edcf79a56235e0b01ed8cac5832cad10558f1c28e" },
                { "he", "bc5f204d10887e08dcb12d9a9ca4f5a95d010939abc466f1dc87e956c517e79a99128571425cc32b474eeecac6a45426337a3e27bf6e1a6cf7a31eef8a2b4fdf" },
                { "hi-IN", "b1f617da0893eff2e107347a3552d20f181d7dcde206f1731d57dc2b41ec162b5aeabd9833d136b66296479e7e4f553a3584aa2ab1bb775ddda30d7239a8f6d7" },
                { "hr", "e995f6b02f44dfe3bb36c1e28bf3f3207f673eed6e4141a78879084e26463a809b19db74ef7841350c3d84b938e8229a2b3b83f55d1d787eed8724b72dc2657c" },
                { "hsb", "d379be8b2021f21dd886e9350d5c15254f88040579d0624a2c1d8f0fc7320a0bc65c29c908940331d4e77cc6954cd0cd34f629ac7827cb15c6a7fdbd514bbd76" },
                { "hu", "c593d67e6a5290ebd52024c2378fb2b2ffb55cb4142e92daa9cb0a10b8258d797dac3da38d752466ab09e4669938066243a46a5a7596b699624631f1e014b796" },
                { "hy-AM", "cfc9a0ced479bf24b65d9689a0de14715d3fa905000b654f75b863c81b541008c9a2a86e87bd2c8e150fb7040c2cd6a1e051f1a90177a570875a7e74817ec9a8" },
                { "ia", "9be9ac3ce4cad89ff9c5ca5ed61a7fec1bd466723f53cf6965fc2aee3867e05db6252d54eb192a25e66229b54946c7096c3c3669b4fc1b28afbe6f66842c5715" },
                { "id", "d15f6eadcadf54fc45f6d6e4dda2b225b12f9bf2434fd2590b2f4f5c8b9c7307dcd590193eece0f6f06cab511171a1a3769baa2ece0b57dfb853526847703202" },
                { "is", "50474910c8b6f80ab1739b327a9601352abe578b33684b3752b8980d6259434f56b6d22605f739ae6f7ce235d0dede5b2b421821d95f39218281ab8261245065" },
                { "it", "b2b3d20c661d67dd946d0e08557af3bf17088c2b3b6316466483cc546350df3988ad3f26970576a9a81a28a2bf72bbea4856f0991d0b14caaabeffe0230154a4" },
                { "ja", "2f3cee88b743f23c572cc2c0de23f4cec33121e9ec82c48ea69ccd18d215b6d6ee568d47d88dd3058b511a60abc2beaffb782d06db5f7358bdaa3e80ef54f4ee" },
                { "ka", "a0f4a03cd9455be988a6adb156e8b311732d07930f070e024dd5aa048f8e24c112c43fac3976aece7de42c0f2c31a1c30267798f90e63488f7018049bdbd3fa5" },
                { "kab", "dbe399830ccb957b989a4fd47286c5b195d79d46b94fa8cab823b46ff220b6186002923ff6364458563bc819c2485b343ecc357d4cdaa940f9576fa0ab4c4df4" },
                { "kk", "aa7343fb39a6eaae366a062a71dc3cbd01bcb77b0e86574d46426bbafd1fb47cd9291503012d6552e9946b7f5b9faa8ea4614ca4dd75ecfe1b33e115d0de93a5" },
                { "km", "412063acc6dda6db216cb437028f3898825d118eb675ae69e3171ff680faad6df771bd76cade815b53dc8cd56415b979a9aea6b10f132fad5851c40760f12df7" },
                { "kn", "d1af3f809345b1b11a35983f549a9de9b275daae6c853bb7cb3511a52a26f4d7c55d9cb127a4cf25725c3b4f50ed11d9f990265e2252dd58f238ab1cc2928f40" },
                { "ko", "cdf0f8abdcef74b53c547187c9dc20aa73e3876743342277a2a7a7a3c3790ae7f33ea91b1e2cb0d820609dc9e6044fe583c76554fd9bc326c6e7a2cd5d2f5a1c" },
                { "lij", "bbfd003f62d499a23cfd0100ba1ae3d6fa840ec4f692aa63d1293d50f2a926d496439ba3296846ca206be354a66e5c8c5e7efffc631153723eea7ed290b72e91" },
                { "lt", "a247a65f5a5a712c5bf0644658a8ad15e7971eeba464a6df671a73ec8ddac8bc78701e0efe25e9b74cc5889c36830391d69a3089a4fdbde8a0d79674d4201b95" },
                { "lv", "fc0e93b4b1530aee3c192b2c7f3424fe0c4db0700bcb6d5e9f81cf72f833288ff247ad1779aa0f3aa600d29a0e6b7eec3dedad42dc2499f159151d3f938a642a" },
                { "mk", "85f9e837a511b3c5b517405d41f126b3de0f68a61dc1abc62c9790f76a83df120adf86f3eb00ecd07b55ca66522df2e7ca3deba9959ce08c791f677c0528f799" },
                { "mr", "57e170dfeac26904269058301bd9d415abe834984a1b2341207e1b04bbc1a64e3d9be096b1f255826df5cc4df41e93eeb8376548a9544dd17917540d2e5246dd" },
                { "ms", "8f8183dc5ba340099abb32386d83645cceab25bc11253deb434c49b6571d442f3141ce2a52a7cb893c47cc47f105aee93548e5b1b933ed4224121c2284d5e1e5" },
                { "my", "8578d85506ff8e07fbd44c35f2aa1bd172dad15275c31de30c121c1bdae817b9e849d20c668f14ebf3730b51e96057c894d2ca7c13aa58fad88e05338b486d67" },
                { "nb-NO", "79f5a6297f4d77b89a4ba78b22d0b668c54b9d8a8b0f172ec90709b489c825ad349979bf7dbfa713781584cbf10b7349e511f1bf0bb44c07e3e251dad727a17e" },
                { "ne-NP", "ec074605b8c450b4e4cb4c2e4bca2303ea28bdda1194b2347ca60cb5b1c99ff00fa08e3def4b86f7e2c8f49a5cc485c8e72107d86e1a4ef143bd577718d0da93" },
                { "nl", "42f0f28f13f0dfabd4bb886f3a5ce599fc0bd695a8b7a56579fd7b4f90f14b4ba4e8e9165f393a44000ffcd62e33fa229faadb87a8d72c9e5fb5b8d07db95114" },
                { "nn-NO", "6cfcadf07f024347aa0a499f13b337972f815d39040edaefc54182cac5d04bb2ec23fc62bedfde48000702456f2f9716264388e48e2745d3c8603ccbc4467cc0" },
                { "oc", "80bc3bf3c611d396de8ddc64f4cbed408a96cacd592c2a5a63ea4df01f28977fed89e4dfb9567db595076dc87c619de7d51a9cbe567df26cf0be62e9b87a5454" },
                { "pa-IN", "8588a2f245e89cc3046b67b0ab454d9e52d4cd31b0899ab338cb6cebfcf868dc0fe32c9b27687d276f77b1df45866b5b82c99ccf8849417ca4147b5af0a27a96" },
                { "pl", "5208f589ecd906d3e0f30217aea7389a571f81149938c3fd62f4254039a05b25eea9399c573fc2d66ba0c97d1c829c6bf31233f820a32b8b67edfb8bc5b172bc" },
                { "pt-BR", "63e7bc52e8c198177ece0065ecc52d669c5dd37e0ba0ede99e5db5e25240a8548e675403a5cb6e09ac2cb667c71a5c6caeafde0a82165b083a04dd5b5d0c27b2" },
                { "pt-PT", "e762ed081557f66eca6858012be3f41a1fbc06b61af32674f6a6cee9532db3f5db7b274951c0b96883403415851a93c9eff2fb68f1a40c693b2f69a94cd98aff" },
                { "rm", "cbd8a21626ed08dda0e1dac39e5554cbc43086dea8d8ee1179c2974ead977b4ecda484e4a99064c184a43321b34c8ef566e216e5b09ac2c7196a3086c9915a7a" },
                { "ro", "129af2ed5cdd829226316fa89f0670a7bd7bb934cfceaed7322dff822f666132af6fceb57357c30b6b32b132e54cfdda1481717c2eea1fbb61fe716eb99b8c3c" },
                { "ru", "b8d167a06e361e03ffa5457ad92d6593d202db9a1038d0953a64af39b93819efc58601923dfa1abf04cc461c138ff830f807be378155e9979fca8a6317ed2131" },
                { "sat", "98f89a3600305c70ff2875ebd54f9fad35c6aa8a7874e9a504f04c4441414a7d08feb0581e82201440a8567ca54faa299b6fa48a2d57341f201d5d33adf88085" },
                { "sc", "fce738ab4d07438c9d1d1c987c61a172aa333261919b944923c111c6771d97418ff89a912e71d6ae31e5da7fe8988737354416cb482248e8ee3382a74bd4faeb" },
                { "sco", "7c438e521a698370e78c0a4d682e848f89dd9c150c378b90956ec0aa24459cadbbda0c759fabce5134f1dcd417bab9ca587043ee0d9c8867c2721ca9066df3b8" },
                { "si", "47da3eba6b4171d1358ebd7af569dbf98db103d891032767f62528f169fea7a6ea453f3a70cd7fe585fc9e4d2976543ab247bdd1203a7611ae2c4c2cc85ef165" },
                { "sk", "45b9571204e7348478abb0dc5788d1c01476d5af845799b804921f880aba851f2384014c525b4bddd2f87eda02c67f35f665120d3abfbb82346b8f8fdc87662f" },
                { "skr", "be931e8b831ef8cd5c5be3a041d0e34cedf25f3d2a5d1747047c64f1298dfad4b753c0f7cd96c1c12e362afed84de494f7fabc98ce7168468d6af1de93e68c7d" },
                { "sl", "afa82017f071d043fc409f6725a648fd4015bbabd64c4bf35518da3b48528d7fd271a61acd8e02a3f2633556bc664d674dbf9770a87f3f2971705c4f21e09f5e" },
                { "son", "8093dbb2b1d7b46ab9cdd83be96eda2c0671c1b76c518d0a3d59fe78a4257d4ea9fa4863806f8e77e467f4c4a7ae56dcda8b237135ccbd6a47b9756e326d13d4" },
                { "sq", "917db529a3946057e7a9107e86beaf5c0ea1690ec59e0b933388095b0722ad31b5e65ee3978a5e9ee00157b288dc59ae7e565fba245ea4a1e8231304a2e26bd3" },
                { "sr", "0bbfc6b36a1edd265233d83c7813f18a17d23c60a18dfd0795f188c73ba313ba66ee9e8478ea5faff5f5562f9c3356243ab34a3a10e1cfee53a3ce1e9ed42557" },
                { "sv-SE", "675e811012ed81abbce4a245f5e6d66d8e3588faaa43229d582a2e9e56c8ae23e08847c1dbb404aff94bbdc37c99c9a306e7cf9d965586b72e4ab5bad3880df4" },
                { "szl", "ffab8f08c563deb5ef192c8f2aff1510a9117032cab2b61793827dd4e958e7e417d984f8318da2aec1cd0117961379f1132797b4810cbaacf6b6a3ab242c5cfc" },
                { "ta", "91e357b58af650f05704bb94c34eecc125118f604e1acb658bc6486c87794459982b86d767e3c07dc2b7019e017d24b4c61e68f50798b260f9079f9277952ec2" },
                { "te", "8a52ebc7cb6bba2dedaf52184d818639932824446a849319cf7952770fc839ed9c2e82aaf86e88a78749a07ece70e8be6dbbd69cbc67185f393b4a32a5d5a08f" },
                { "tg", "b3079e17136592a2441dd733c39699367d587a9eae22ba0f470561fb149d1b5f29d578fd5a47b33e278e170acaeb8131b4d89b7f09f4d9180eb56032132b5682" },
                { "th", "fcf29684a3579c3dff7bea9e57b9b50ab49bcfdba2c1a6b619f50e09eebd975943c6c9cd239de892bd96e7caabfbd0d7980211456bc28c6a17c94a2bb0442d83" },
                { "tl", "51614dff03bd6e3f295abe791503e61e3b6cbb3edbd40755e147c4e5cf631461caba2774da13453165f9e60b42cd006c08c0d751911d2de7226a450f8b221376" },
                { "tr", "546b9d91b0532493fc7a904c186926cab06540efb5722a3b2df761e8fe36880cde8497c5365d7b16cdf86a9fe78b3afa94475fbdba7bd78b5aaa27ff74873935" },
                { "trs", "7350092ee4b7392844bfe5f08875b2947cd179eba40b5b2b8ce5e620392d11c61d18c4d95c96f9ad705a6c3db46977e0bc55c78e5a12759e7e22c2789106a242" },
                { "uk", "1580cd2dfe2fa44d5b1e7e1aea2666fd9374f564d44f25754970aa9c207ea7dd2261ce9a8f610c7484ff2bb5f019a77b0950dba571575c87012079d537095038" },
                { "ur", "35b2a37b544b229bac1363bb9d3e42ebbc777218533bb051359d3954e41ec0ee6c6cfea28b46ad6739f5507657bf8ced9959971aa7e1b5b033df447778ba5591" },
                { "uz", "e6b79442a494ab116f1a196174f8ab8638d69f24d1cd6c5e194579cec0a1508a729779173732198c74a94107d89e8808738724afecb6b149aed9c95f44e66251" },
                { "vi", "3cdb02f7cd0ea4e09a098e5e245d4fca71594bd59a8477482c9f0a75f6240901f6afbe2649a6603e0e8b36d0d3a124ff1d7a5a29f792e1161afee56f994cf32f" },
                { "xh", "1dfe1ca7b7e4eac0129c302f24fe3fe43c6917efc246698b3bf11506d8677d554439ddd14d5ffb8b6a398bb7e7bdc6a285e8907f98c837c8aca44c1405170392" },
                { "zh-CN", "c72b092a6c4e9edffc3a6d704ce5be2d7acbaae6eaa31f4734c5cf677d57560c01769803d159540a31a9250ee291c988f79fdca1dfb6a43c8ba531ea5bfc201b" },
                { "zh-TW", "ee6017b3b38511f54024978b1771c5125615e2c4409abe056fbbe358ab04c877c30fc9627006b4883794c55cf454b5c9d09dbada2eecdf2ce818ce678b9af82e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/152.0b10/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "29ed1f3d32d089af0005effb68b39591fcc77a6a70dc8acf1534770cb335ea1c8f304bcd8fdb7fb2345e6a7588a8aba8802cf80f18e9defe66bf898305163f2d" },
                { "af", "8bb731e1dbe915dda13d77cb3e8ae886c5cba6cab996892c689b5994d16f034bc5a77c4d5e16fdd88efc7ef3b0db6e1ce115469fae81c29487663917e01fe4d2" },
                { "an", "e5a6429bd42d7e19d88e8cf03797dda55908330f3ca26556742f890b08271b1a57c14a76e748827cd87034559940af6c76bf7c0f6a42c867f52d62b03b2523ed" },
                { "ar", "ac3c5c6f584485b8c85b88db5624c5e145250f0bc27c6ca9df6f3f613adc8b08c21da3793b5e0dc84a13528b16fe0e84dbac8d8ac2f3701e1c5ac452cfd33c9d" },
                { "ast", "697a6381043f92ffccc3c8896cc026270e0d1b61af10809869356da2014fe1fb3a70e46d80e0e56ba2a894196e725e6f5373511f05b84607013a51415b294e8b" },
                { "az", "c8121ea92c47a821995274466b1554e2705fa1b9e17380b4831c7996915d8f8e96314d241de85f8eea7dded21508acc08e9a225dc51063bb565e7043009509ea" },
                { "be", "32170f69cefb11795b97106c36f07fdc18c8cf4b5905b5760f17e13c6e6f8b0600c5cfb5f6f445b880ab5ecce10c6fa63fae8983f245eafe8eff737fabec6a19" },
                { "bg", "3b0253cc4405fe4877e6b996cf118e7808de897e3919399da754aefe69184edf1a5ea72534dd7ecff4a453c412493bcbd91a5601fb27f0951beaf9e84b664742" },
                { "bn", "9d5ddb86b6c2a9acff85172b7c930361e3d0853ac41051e035410f8b56bb5b52ea3a780bc9f303b939dabc139dd34ce3e37312a711a9dac94b0e72eea9c61280" },
                { "br", "dbcb963119d3e969184515384b58f34cb3911717a9b9bf754c0c9e3ad5f60b833feb5e88ce721902623f1af3ec1d1f77dc2da779274a22e3834081cb31792f3d" },
                { "bs", "3fc4d80a013f2353e2d9ae7b414ce3b0368e68da6b11d471787050679350d58a60eadf87a3df361bbd9f85fa1d6a96e23326dc6e129a417206298d568e32a44d" },
                { "ca", "24b930cf48f7cc6bea6d4aee8feb0f62ea7dfab391f65ea10d9509868af84432e3bf276e70cf97fe71776b516243404d65cc17273167a846cc8a78f8045c249a" },
                { "cak", "2109a93d357c105ae704ad19bec7449f56ad3f2d5108622dabd156ec78b8edf072788e60d5459301ee72174f15c51949bbce96c1011ac17f547c2dfd7bc4fa1d" },
                { "cs", "e5937374143b804b6592decbf0b3622580d8490e245f41612e6134ef454f83a5e9a118a93b3523e4a2d0e41af8305c7327a93066f02c31b6a7de620a999e7155" },
                { "cy", "373a91edc65537d4adb57996da09a089fc1a5dfe22efeef63d7a3e76b1bbbfb29256568bc7d24c690ea93da924bf4713a2317aec5cbf00d81b780f04c609f422" },
                { "da", "83406e95985bebfaecb7cfa227c56cf67577181db521f7832681518491afdf7d241f6bbdefa5d43b5fb9d7eb1781985743520ba6a3bc6bd5445ecca063904dc8" },
                { "de", "ea6cc80eabcad2fe1cdc76c643b92c0f5e7065256e06c174af9bd009ac88a33364252b071ea3ac88576cf95a2c0d879c587169cc1aa3feb81e450076ec0b66e9" },
                { "dsb", "b9930bd97da68b9ba36e05408748bb89501006fa4a19711b196bdc26dc25520db437751e204a3bb0b1aedb3c1518362210cf27757ca1d2fc4520a23c95c5a411" },
                { "el", "cefa169d6db8b2fd1f6b82af31b779498fa5413bf4e5061865dee7e14895814993cb388c1fc0990b7cf3f735713bb579edfb3af4802c5539fcb98a279f40f1f2" },
                { "en-CA", "9c8101507c075b7757a3bede63a70169c74894f561405916853ddcce10f48ff5b00e129fe068afd4373b2ea43cd79bf35330d67883f77f27ca15595002b80917" },
                { "en-GB", "51b8d5251419cc11e435b4114e67931fc3560956d1ff9a6c11daeac59159b9893116d12bdf9f78b5be71a6a8d8ba9e53f6938fad36a20d61850aae1ae5135802" },
                { "en-US", "42e80607782fb5855b96f422ac5b953c6244a6430a38353aa6946172f113306f170774b9d9805715e1a670ac34eb1d1f4a638ddc75fd0178e2772232f5b16e69" },
                { "eo", "3920af2ff99fb7682e36876c944017867277d67186e589baf1c9085405231688c5f96258484377078abb8e3b08cddd0d6001a95de53f1b843f7797f1b476a49f" },
                { "es-AR", "0ff3ef0652f309e64f0a73512fb9a32320c7426657556a3ecdf51e8bf15be8496227fb53fef6e80be77e5850c756e5ed2abb912fc3e3220f4681b914ab3d113d" },
                { "es-CL", "1d7b1d85c84efeffd622e2d69cbee046a429a3144dfcfa0822f64ad12f692b0baaad6e0165cb13ac7ef8c5f0843b4ac2b0e34038fc6d886de434262ce7473115" },
                { "es-ES", "c41b5b2fe7765e75984326262bb944526a45da45375e5c018f57048913412497434585c9ce9016f80a52b56a6d88b39ebcbbe7d14a30f9f5aca6e1ba3b53ba28" },
                { "es-MX", "f9e524a7fcbe9b652e646c204fcd79ab6259cf9ba2d70398eec7aff0eea78db76628c05fc38e6703048db10e207790335fbb2267439096c8cf0949e5370e717c" },
                { "et", "c16ba95b9600dbc6ec4d4677acd953361f4f223ef4f051d69d1ff874761b43c35133e0446864f66ee9b997f7f41cd08139b1740069e46327a9c899d0ae79df18" },
                { "eu", "08b987c71600f51d1f159bb643ba96feea7527fd209db0a94a46ce08e948b3ec2574afdd22440d7c9eef5d312647921629310f8d30b70ce7349f043c0b2883f5" },
                { "fa", "725035f50ce8f0fa573222a6626f4b20b3f2166f6dec99d63716a62ea772f8e24d300d9b452739960004fd989731e3f148b37f1b33fb028d1d083ea021746cb5" },
                { "ff", "1a0ab6aed08bccea7647ea80e05d1403cd0e3b21a1d184d95fe1284eab021a53c373e7db45b7da6758b924be9689cb4199d4900444737d75a765626efada9fa8" },
                { "fi", "8a3db1b3e22cc9b83820f31341a3145a1e645bb1ecb4c4a4c4640355d6018f5685fb8a2f2c0d1d8a03db025432c90f170da46983814c87ace0ea8884c93f8f2a" },
                { "fr", "916999632b3c2aa5d7039ba8f0adc2532e72096eda18bf3d9da0adc4b59e9a943a8f481a45ab3c5a7038e2530f7bdcc884644c78b0a44328cbff189062b464a3" },
                { "fur", "cf96884314a633134b6a6f9b6d3100ce9bcf3a8cf6f62fa133986411fb07de71156b784f881651d6abd88193d7dec9273c42ec41fe5d2f3e9ce4d2ac5f25d9b7" },
                { "fy-NL", "287df5c487dd9d5af9e9a29c0668fec57581e130e5b2de4289552cb3c6254d1710f41235a5b8902f0177a2871e0205d21fc64672cfa23911befcee7a545fd9c6" },
                { "ga-IE", "3a460d892d641be3668c4046c677a60a759fa74127a885505f8c1abdf977f05eb2cb0e919b4bb5463c61042930ba56601bcdc503804c84c2e199a36b6f5e4ce9" },
                { "gd", "cf137a3d44facecff08fd0640c918f5b43c656edcf2839f060823a208d2788d574784a3b5c243da2885e6eeec6b143e1329b1dee573c3b55eeebfe5b67001b74" },
                { "gl", "318a22f72ff3911d8505a5f5710613b210b53108b3e0187b755a1ebd39502a609dcafcd9339d5bb76f8d55ec5b16462d7bfee0379d98fa6b4a2c7687b0af611f" },
                { "gn", "e90ab6da1ca9b51ea7d11fe34d68d676897a02db7ade6a67a60c9e5370aaed767097565d46c02804b1aee379d9c5fff3fabf375dab778ea0d707d18f0affbf24" },
                { "gu-IN", "6281346b2079407073dcc8f7ffaa92c560fc2a0e70f5b0093093079a4607da5c6fcd32c0a916ac978448e61ae3413bcb7f093d5b87f6342c18d7115ef616bc7a" },
                { "he", "3d3ca77cd43ae5feb718153d367a1f1039c1c15f1e70ce5d6f4e99793767788cc86571a43c4b37156ae83dba075f98e108d14f502260aaa52f3a043eb936dd6b" },
                { "hi-IN", "d29d55eb38eef6abf995a1acbc2f236cb0e752ffe06809588e55d019b8d6e7acdc35b7531430d175afd957099de6e9ea36a8d3ad0f0a40ec1caf6dc705328f01" },
                { "hr", "05432a8476c8b1f08ec0fe251dd8f04acf717e3122a2112bec9b6b1d134ea66a8693af98b83b8054fcc2da6c744558b42c5a67f9d394732a41e949285596f62c" },
                { "hsb", "a685e3d37c64c3c19c29f92dbef6f508925d346d0d1e1e279783fd8cf91368e033c644131708464fec6caded94e34ea12ce2bba21a74b282f056ddcdb18bef0c" },
                { "hu", "a28314d649377cd93e8ef410f41277eb298c1b9db9888856e466b32e59f2290df7730d8a2064be052fef56bea9339e1927df91d65f3b265f36b6cdcec1ae5572" },
                { "hy-AM", "67cc696a500e59f38b788ffd59ac97dec21b6a0ceb164c9d31bf7d88d989a16a0afc4e2d30faa9f2897c5f2984f2715cd42815e231491fd46df504b74d30828c" },
                { "ia", "f151c5afe8f93067e05ad1f083541f86c5dfee7e2d5038adee811e75d910dc65adc24f70cfec7b3859214bd24b69fa9e2b05617256ef016d8716d426ac90f296" },
                { "id", "9bfeefa3f84ea8b8390db7f58d8911a904816609f6bf32b470464cdc138cb88f6ae0563d698f7d3b469be72d9780b4b11a305b6561fc6adf3a5ce798cd59d52d" },
                { "is", "c235c3eca4841dfe9ae712bc7e28205738804854af3326b9216ac04cad1968154599e783a73d690b4b9c8779a29ee75f87062f27e75f5907c5436b7f2e47e842" },
                { "it", "76a883866071ecabde4d70a0bc9ea84171830d8cca7f034260fcb25abc40d9409955124178d60aed3094b7e175ad41cdaf3f28a43f6ab389effcc44ac8070d5b" },
                { "ja", "c515b50c516d17b6bac3b5ef627d4d837e1068edc54a2838059c715c07485967817d34329117d0c44fcd1664c9a45c0f8acec428e6cb4f4965294f502eb4f20d" },
                { "ka", "4667893b957940bd16e2aa1fbb4aef264a0dd6d38b42c8c3da3d51cfe7033f23a0fd4d25f1799cbedbad9732f234e8c16a8c707d61781f7e19f5b2836cb1111b" },
                { "kab", "5c4f6e009f837cf9fed5b98daf40a3a3ade165b13bc7bd0631ad1cfcd954d667638a849abc126dddb81816cd4adb71eb1927b1a75f80f5d08b6f64571a26aaa2" },
                { "kk", "053ae79fba0ae945e96bf4e6d9c0bd1d817c08581bd6ddaaa6885f890f402c01a4dcb665b445a8fa1eee9dc07622c47dbd5c56f73785d44cd9ad0e52d665b8d7" },
                { "km", "1c3bcc75ebfdf562b6dc70983a5f81b30ec49de419c317d70210c1e16a09e2e9c5ab405d44fd9b6b16a5f53db9978b53aaf01e65c716ac25dbb545058cc631bf" },
                { "kn", "8142ea59829f05de483e110c8f628df7a7422c06e7045df94e0cb2a14cc4dd2e894a5ad0484aaadd80936dbf0c129bc3deea2f370561a9846ea547b53b1cf472" },
                { "ko", "80675f817dfec8f204de58176e1269615bb2d2af80f41af43ec3326708cd02eea52e0d73c62e19c601e36c93437503953394ffc186935ba977d2cd58814595fa" },
                { "lij", "91f2d2df63ed9f329c3b7bbeeb689ffad6308644656b997670d39b00dd06a493c29b5b6246821c5196b66a38a099af62a973001f87f87aec7c4ef64d7063dcc8" },
                { "lt", "3d4379975f83ba2f9806c9fa4fd314888282f41df066aad5d54d6e1e737b6a1b6ab9b397016c0aad5cc82e8ecb0356514a3d97404dcf69c491a375d5dcd21e06" },
                { "lv", "4f3cb14e41fde2891bfda09559638515baf476f87654b13d7d3f078759d353dcd8f4bc503e41b2018029506c4c8ea58facbc822e27280d2cfc935b32f0e706f0" },
                { "mk", "90eed79124118a8f3d4ef892b1de6d1fb7e33c8bd87535ff190a21bad17dd3626a7bb1081f27916ca6edec05b98c32a2016825313528f90ebf97dd3f4c10b8f8" },
                { "mr", "1729262c94f7d83ab1000543df35e6eeb051ee7fcb9fb831b2c579c01f55261b53561bc52f48e1b64048858fac6c48ac557870de253c4874707671ab891bba7e" },
                { "ms", "1f1c587f7453db55f5906d1992d2fbc857d346ba249428fa768ae8d1982c877b6415093e94c55e599c37b68f0ffee8b6438d38bca31ba9cf95c38db0deb91245" },
                { "my", "1488204899c31e7190cd1739b89b72965dd438912d3759a538a698774458026c6abfe9d39966c26cd9a7206bf5f30cc512cb82491da2efaa858c13771d8ba76d" },
                { "nb-NO", "6f1bbfdcf061f3f133428e78fa84513db9f27032909fd7cbf9e162bbab66193b3a2762d6204de4b41ebf2c6a4191a0c8e05717f94f2c3d343787c8f28b1127b3" },
                { "ne-NP", "3c3d53ae1bef84e20a8d53615519d8a1216a994776605b0f7609928e06fbc13d5164d17766f361b7df0e06887b6a0ce6fd81d91117449ee11748039211408bbe" },
                { "nl", "82645241166bdbda7c9c69da35048854954a57fcc74f8f931a0253b560f2f8984a7ce3f0285fe56af8572ba1b05d9e222f01d7ab202390cae1aab320e11bca65" },
                { "nn-NO", "3c8f9c554d9c724374779c242eba5404acee922e12ca9a3ddbcdf97a0e23ff53df97fecd416f434efc8c9b5dce0d6715beecd14317cfe7ec65e22bd7bab1abd8" },
                { "oc", "1975419b2d660e449e6232b389cbd085bc3198f8147604a01c9c8e22c5f3525581583247ee5988b0f7d408c3157a50e36c3e97e3f96906e5699593e0880facd6" },
                { "pa-IN", "625e51fb4915d8f46abd28530bc98b4f78c3c4008fd4261f962daf7f8ebd8aab6f970711b363a8f4589f83df6a8da5130f548335e799cbe12badb42ec01cd568" },
                { "pl", "bf54bbd9ab134f746f9546a183484cb68e7a473926902b9c3f2db68f1ec4d21f15dcb5a5a83546586ce3bfcf9eeaf3edfe1bad458b341a5932d6ae5b0edd3481" },
                { "pt-BR", "65a0b7b9f045480a4162d79edca93cf956e03b5785e30c1332a5914e2e50cfbdbc427d457b5762338927f781f6ccc898660e1ba47db5939263f26635f5b1bded" },
                { "pt-PT", "cf9098d208163db17ac8ba7c48f26d7550d61927a4d00f42869832bf516d9e2f7752f285ef0e58f20d79fd1b2eca0446fd06d119befdf3c4b9bf6cde08aa9560" },
                { "rm", "684592ea9dfeebabe49e8817930d023e5327c35b0dea216a87837df959e76a3b1edd7160e505f143883365685f535ab06b6247784699f8847de3bed21729006d" },
                { "ro", "9fc84a3771752603248f50bf667446d798d8833d0993ce23c3421765c8979423d70b3ea04f8190bb9405fdcb1847746146b86ba4546a3f31e30198d9d4267a36" },
                { "ru", "20144b43e3d662b1ae464b69ef4ca4110d812f5d480894909345158b776bcfe6ff152499fb302f5b0f596de8711f2d4eff25cc72acdb7a87c3c42da8c7addd9b" },
                { "sat", "4ca99d1c4f90f3933cb1e3eb758db9ce451194c18f813308afda0b4b5f14b31e49c3071a6d8bf0b37bc4d675db5a68ae855e81dcea23a4d665108d346be475c0" },
                { "sc", "33c12d0a1b04957fc2f64dbfd35f28ddf9d54cf3d4a76f8815bd8b47dc1115ed165081e76d4339a62957f5b704e09d1f180f6743798e1893268c046996909610" },
                { "sco", "1c670a2b7774e91427575f32f05a2e04bb093d36dbb4c73ccece8db17b4a9b810d21f633e6b515b1b5f10efdc3df7ead07e1e52d625e7bd2b0996aa2708eb967" },
                { "si", "f1be0e69f917530a3073d5bc3918d479f57df358ad1a4b9fc5b6e6233dd2542f6059dfa44a63f07ad2ad17ec4eb0d43f06d8e38334f27294fef4f0dccd936501" },
                { "sk", "3310a62df6323663915ee438fd5497a2cbd9cbdf6cff7be66e64853c88bdd470a27bf1ff513807bb8e9d5ab6d30ed9e0d71ea31e9d9ededd0315dfa5064613e8" },
                { "skr", "027d7cfcdf76a863c31baf2db939840193a3f00e9705c8b9b3fc13d490420568d499be0dc63497d93cd419f598e21bff9ce4a95b695e694da286f9d6ec318b87" },
                { "sl", "27491597120a950ded5498bfe701fbef6a31c9f27ae543e0c68ebbabe32f4ba1a4cc8f54e37e574c79589ad262ad363bfd87734cb53fd8457b3706ee0df975e9" },
                { "son", "218c34de0013615b42380462acfcac1d49dd9882a937f5fce01846671c9928c084f82b489a8abc78b68d07772fe0048d4c4efe61a63eb16f35595ce78fb75250" },
                { "sq", "b3f1e7d7c28471ac15ce3329596ad2436cc0282d508f2fdf900084392ec71d0f2bf55887be6717a65f26ee63ba684d864d919320123811b6d5dc885960b22e9a" },
                { "sr", "d26ca63d31081c927bc54d14d59f3633ee023524b085cd7fa30bc2f32dded4c0258045d2ca3e1fc2779059d782052f6ffd2372a28646202771d61c365c9416ca" },
                { "sv-SE", "e6a6ecc459ee7012be624b29027adbd027cde832af77246ab5972227ebd2ad733da47a41de3f5789568772cb0e7f8dbf6d4970d2d7a4411f1a40ef1ef86df10f" },
                { "szl", "0df6b7c361344b25b252d2c9ba0d2513ddbdb78991a3f15c9f489124e4ef6608606c9f81cb6937abc5cdacfbd9c3b1599b4429ed9fd5993bb5a571eba8107ca5" },
                { "ta", "f782b6788e4460979b639c8feb630e0d415e4eb05ab6122656590e39ec4e12f027802c2d4f668d5bfda509501af80e493350f2ffd446192aeb3e5d5ea425a7d6" },
                { "te", "bb29ed90bb85dd003977c3fe4a0009eb46f29af2402d5e68d66243c41a761f713f585edeb8d50c157a93df08c0fd1e5cabf2b992dd81535ee7d56762e1c675c3" },
                { "tg", "cd2689f645463176571c0d9e369aef62a8e5411cd5860f5a9f186e22599cc2ac5ccd0f44565f9444f3f4bbfa9cb14ca2fe61ef0fe208231ccdc9f126d199b3f7" },
                { "th", "16a0e34cca3975b42719285322c1dc6ac288976df51d862609da3665e1e14d8baa03afb13928314c25f1887c9aa5ac9c9231fb19754e5149d13109a98fe4ecda" },
                { "tl", "2d52d02d31f5894318a5f928def5e85e805c982d5eebf2b629672cbdf9917dc721cc9da95f51e88d93cd5038145353221e989c8a8bcf448de2e09e22976f1981" },
                { "tr", "f5c2d416ea5600886a4d0ea64f7ec1417f874ffd3899c76ead8d82c1a64e77cc7abf9eb2bc651dbbfa0ce00c6b3381c68b668435972f098e7e19037d4358f695" },
                { "trs", "845be1858e5c78f63827c1d88ed91cdce8f4dc2c7d10c5ede2c673ba9981910dd20b9c4022ded7ed81564930104aa40099df5aa8a5cd43a40cf8bdc28d30a9b0" },
                { "uk", "cdf7da94d1b344972bc0e5dafbe7838584c29031bf84d3ce9905765d857adbd885735c1497a74035e01b371d1fb3e33b5570c1142d188304b94a9cf3d3d14a1a" },
                { "ur", "c3bccb397c633bcee757e5d30f4eb5a79c014962bc0eb7cb73c36a0b148a4ef17370253c8b0f8c1c97d6a7bcee1cbe2de2d3ee8ae74a2078e03d7c89f04533c2" },
                { "uz", "9cad7343442333936cfb8e9296c8a23e73b3aec7cedbad19ea018eb4b0ba3fee7c184d944bb51d367a3dee4a01fb4f844bbab2bc5455d82f62a2694f17ae6a72" },
                { "vi", "0db20fd28cbb7cd39dcab2369258f16d059114f468d27ab49fbb779f6b486407bd92d063e3a38f5d1367b20b2bd7fa28c14a9ed1184d95344b7f29ae75bec93b" },
                { "xh", "49d83f2eeba12a837e428ce00a77cf5e13a47c2ba149a1f9185ba02619e7e876bf6c72b3bf483ea497b6dd1d47c44608a630a8ecd2a3a4752f214468afafd369" },
                { "zh-CN", "c909a2eb60d98fcd19e24254cbcefb8af78774259127b6f4ee192915375a0b1f3638f149435c60634477203cdb09b3fdcb118e3c4f00a497dfb071eb822b2037" },
                { "zh-TW", "dcd58fc0f2b951ab2cb0b71f62d04934304622db766861aa41c10bf3085715e0f06863ccbc5a90d186205b5a4ade8aea97cea76fa37274d478a27129fbcd771e" }
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
