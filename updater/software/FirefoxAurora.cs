/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        private const string currentVersion = "131.0b2";

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
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "82ff57f969f7bfa5864b16f308dbfb8485edc198742260339bcd310832a0d1c0b62b92714df7152a2c7e17fa30b4c0dd5e1f13831cb7aad7a65f89e961bbe26f" },
                { "af", "619c3247c1cadfccac700509f239fd15d4e16d03809ef78c1576970675029c360fefa427aea26478edbd71b5a5950f10a138ca48642c7581033ec72e3a1fe9f4" },
                { "an", "48085076e73d22a92a0cb4072406acaafb981cd2b0574889fd971f77ffe74ff0c4eddf57037652e14b8c2db3b0f7fc78112e84465a7cc95ce921d67284f32532" },
                { "ar", "a635ad9dc7c454793b3748bb9355857748719f4c55b477c38d2d5a4c96ee22511a3e2ad59c62e49ffd206b4cbd2ba28a00938989df7a5cd618f2bb62919da357" },
                { "ast", "fc9e6e3ad436e40da840668e5ec20d31f996bb777236c652202e0dad6cd31d2a992c60d0e2f76a813e885d70c8b61d48911bb9ee05a2ac4971555617f921e8d1" },
                { "az", "d04cc618de800b14a606bb4460880a8a04fed8c5e9b3aa4803001ee02572bd6572fd628221b6b09e9ef91808820136b7ba82e4a77e5792637de89277ebf34ece" },
                { "be", "db36fd729df448b2fa79ecb694395dd46a6535a9300ef30c24d2cc87f4d6fd7be3d295e240efeacc8a9a178997aacab86583d6e803df9aa1281f792ccbc4a4bb" },
                { "bg", "9256330fafe6115b6176ecbd847d3468b1f4d46d9b72e346323a973ec47a2e533cb5ec00961c2943a850231686d355a9db32f41de9feaadc0d2e66a6330e5593" },
                { "bn", "fbfa9fb1d0b51ec994ba1332b10b0f1671ed1062d14451dbc432cafb46fa4de63f29160e0882337236e6b2e5d1a8ec3fdcf08eb5c9ca92fdb956d858d5fc870c" },
                { "br", "85b69cb8b92b035c2257d113c786af64536a16376cf21c3f2b0a8179be3b3d902fd10bf2d91d9f37b2a4871966e3804021f64539f4db2d615ebfe8f3ef774d25" },
                { "bs", "bdd2be799b46178a7edb83d5f95e12c8cfeeac5d1cc42ebe16b3dceb26e73a88491b17a37a3e681a1b79e287622758c2b3a28008e3a7137c95b7716d70844e85" },
                { "ca", "f5b50acee207a37041d4e99690dab75cc4423f8ce626c9d56cf1ddec19fdb54bdc84888585ca21d7a48e1677683dd4cfce4b959156a6d278a113f2d170fd61de" },
                { "cak", "f95ad4869ecd0a99a36c3b7e8a18e68b2afe641149b51e7cb9a30a1a91da917fb0f68127ec156fa1ff0c670529e12e56b8b96f221868da9082994fdd6c10f6fe" },
                { "cs", "ec7bc532130394d74437d363f2806914866f0122fffce572f0c79796e1126c33f63bc9989607b5a92f37ed269e643d35c8be2de53e7dfea4618a8f903b9f5160" },
                { "cy", "53b511c74137ed347770a61a13aa4e079065ee4307e5fad12d81d3e259ece1b74b819d965ed8229cd3e5a6f7ccc137e075b8a2a0d8dd0bd2a46e3c2ba3860a21" },
                { "da", "5ab9badee5bd4c98f570d7198a5b024992b0521bb58906db429201949dce6c78e9d3c96a5e3dbd0230f77ad4cb228e03d9072dc9bcd04f1519662a6d26e49169" },
                { "de", "0ac7d8445d0b44168c2cb9d2a7512da2e2225fb2564b7dc6de016f9df4c527aca29ebd120b818961222f729a9ed4e4f67df0136c804e82b2216d0e580c86ad3f" },
                { "dsb", "6ad9eaefd831fa618ea4bbbc456ff2b0ee353d2b66631f013dd11f2d37d85efb75cdb3efd954cb7e9b3fb91481c8e8dcaa1614a860229f4ed3f8f74745f15eb6" },
                { "el", "8943562a7de3d2383cfb6a461df8cf52e21b983132881f069c15d8bbd30bdfe03cfef5e07e59145b002e08f8c6d9a81cec1473d8283ab4ad829e65a51adb0dbf" },
                { "en-CA", "ee4d925b44d69f304c510dfc0ae53b046eb6c7a8d2abc531ffbe4b34cda16634aee396bc1a2b02ef716444a337fec4a029b8274c781c738c71ae133ca6767f47" },
                { "en-GB", "dce6267a0464f1c9b42bbb75c92bf1ee8708fa370ab47363bfc98e473fbce2769ed8b2b6fbf99b10694d4b915a0bfef7dfafe6ede615634e0f9a8e4dc5d805c0" },
                { "en-US", "2850f0c6c67be98691ba8cd91f96bffdd50a2a4087e8dc6ac2b956629e74b917a0db2937049214496670f146b5ac8db341c756ff75721c00ed562004d04dd560" },
                { "eo", "2f8c2c2b331921605e83d90fc613735eaf7befba6aeb199a28baced5c84ddb8e7463ffcdc12b6e3a38f00b2aba3fe5eb21fa5103fc3b05a6cceebba6ad72701f" },
                { "es-AR", "230ec26a12190260d63110ea649aa49cce0066abf6cf1c1a5e61b5f2be14db8600b6345e546999719902fe04515719a7341451d0edf3beb9150c73372c59ac34" },
                { "es-CL", "15c9099de08dca17e3c9e5642f79ad537fa2281efd4b6eb223f404353c0bd113e5b7502c88b24edf9af444db0ed15e8589a562c33c2d8b388a1de51b7b74d799" },
                { "es-ES", "313fb3d7a3be7fc56f53043049446e4572845206cf8e4663101164053883b94ccfdedda2cce86a95afff10400d1c48a22b83228ac37fef17aa5b0e251410ef7b" },
                { "es-MX", "2e50665d9d076eb92ebf379209e243b5d14c21590bf24c4a626a7ac57b75995f671db3683081156fbecc85475d00bdefbfaf5c870f6ccf8778b42be040ca4e7b" },
                { "et", "24a1761bfd04457519c93514b74a4b4652ea9ee1836ab70027628f07d01d90e0ba07c40b756ddbf8ba4f13facbf0491f3ba124c5ead35a50777f9fff42aaf6f2" },
                { "eu", "2101a35b04c57389846a2a87cb34734815baf5475cdedb3daaa87c222be32de381c076cac3822976dec5c17eac6935649c8d448e7bea3a3d8a65c2dcc973e8f8" },
                { "fa", "a12baa3def6864e25316515ee070a4baa904f54d9e7ff3b121139c31126809e5a6710a49e282b5476e9609666d27b56e6aafc88a11b34d8b5fed904e39272b03" },
                { "ff", "3e3cc1a64d7806f8b8aef958b80b51a1b40f0ec01febd2f38d84e44d77c7e2feb35c0e82bdebd6bf6562faa4f2dbcb8866fe33b3b705f4fe69018f819c2f1599" },
                { "fi", "e020057ab1dffb0af46a86ac2ad655a7c33f063ae823c353889307ddc28773f77596a639069c240f8d219496a55c10fcc3c91ed7ad47be6d8fc13f13b3fa6406" },
                { "fr", "2a5b9a96765eedd8863562322d83ad2d76137ce81dcda654ebcd156ff04cc2387081735da7d5e4fd3b1b3b29b53a3e25d83e364c08c46147d97fb14f3606354e" },
                { "fur", "c27eeee8bf5f2907f6f5c8db6c502e3464159001caf373539c0067245456baf4826ed769d86085e38d77b0f95965aa6c4aec71218003b316801f34c8908bb6cc" },
                { "fy-NL", "fd162bc0515a9dd76a6406de103fed775cf4a7ab268ad2a19a47b976df3b65eae35df6ef19a84359ad1f2bb1b66183ba6ca484165efac851f6bcd90026e352c0" },
                { "ga-IE", "8162444cd9d47e305fefdd7de6c2cab3bafe7134e91e7030f2cb44a1dbb054607e8a96c4b5138b2dcc3c92da59c1f342ce425f0ffe637c10dc37d37f0f51780d" },
                { "gd", "850b7b4d890af15a4ae73df5720384adcbc2dedcc400f76806a5cbc2315f32e835f046babe43235975d965ebcbdf0d304e9a540511f6b01244bbe49817aae867" },
                { "gl", "4f5b0d025e9c35a64c47680b1277f9397fed721e9c2eaab1be615591f0c5b89922796d12063bbbae7d15e2ffc0ead3c40a085a1bf43ff3994248b4a314d41875" },
                { "gn", "3435d9f5733d3bbeb98b32155df9cabb3323372b97d08ddf35a40cf0af11e00a4ea3066b85bb7f779d5c0dd715ae2793e4be42545c4b0fd90a1dd799ed76b86b" },
                { "gu-IN", "7cf1fecf569476f686b8d83ef7ba40868b6a6a6134ac16429e31a5b1fef40c66033ffd6d7ffa00c1ec36bc6c76eeddc38ea90895c54ee14c143650dd18f562cc" },
                { "he", "1e3e13be706bbc0853eb30a6760a5dc4cccfdbf41eeb47a9b868004b576f786db3c45fe2da1243a0a26246d9c0b9b33b31d089def847cd1f1f25e16341b010d4" },
                { "hi-IN", "cb17882ddf5f89362e2346418a2d0a7400bab10dde2b44e2e03c01032ce461ae649ed17a231588d6dddf816544933817726e1ccbf63523e3ca8dd92dd442d02e" },
                { "hr", "7e35f696dcd6bc21f1671d04c0eebede9c1cd6520b12560b92e26d119206bc1ae53b0f67930a8443edfd4929c9cba56ab1654eabf2f40f109c7f5badb2f6ac9e" },
                { "hsb", "3f5dbd664a43bfc109d533819f4c2cd6d9096b2a0c110917fbe35ca88911fe1e2f5bccdfb2d713d16efe18f3e24fef3a895d626ab8b7bc2c0ed0d3baf7c84c17" },
                { "hu", "25809b907dca55baa487c503d5cd9f323eba3b9cefa423f12bd6bfc728345ee24cde33b7750e5fc23b8d7354d1376c550734868602b4da5f2af646465fd11fa1" },
                { "hy-AM", "45bcccc200f1b8cf27ce20a44cec2b89d272dea1cf4dc22be2798d8c28ca3d768045e079bb1f08962988b62f4a1d8a4b7657e4ad4d937ac563c7cc2e041ab795" },
                { "ia", "58a68a3db46177f34c54c925ecafbe7d668a271290b674b2cb9a592f27736f8542ce94fa191718aae589bc89074e97a1662e439a3ec7efc62dc59a746627a022" },
                { "id", "99df8da39cdb8a8d5ca0c989862b7c5e692cf520d2e6f0122fef7288889cec233230d687f0342787fe165316f790bbdfd2b76f0225435eb4530a315f36170913" },
                { "is", "af38dbeab9fd768b867e4d352f7c12a4f05e0ed80bf8d9521f915ecaf2775468c8d6a67f06d76d56d039b4400c13678b865dec24d930dae0753fcf32e0f853bf" },
                { "it", "0e2b203724835358d3db1cf582da5e0b02c3fa6a7890fc5b40bb19578b8af529e5033f6a83135d3ac9257e0bf20624d2ac7cedcad0ac2d55834df2253196fafc" },
                { "ja", "1587433f70ab116eec40755e03f66ec8300e14fc5c13c0cd410f6fb363537ab37585a2a0b7bfa4bb225291e923e5b18a5b99f7fad0f87784029636db2535f0e7" },
                { "ka", "55c30f6a4d21cd1c95853ca9913fd1d5ef5945c2508c7aad5a310b7e59bf79f57dd78f74835267fd25d73a953478622c06ba3708224dd7331e2cdc52b44a49e5" },
                { "kab", "29b4066db2f77ad892b3d1a464e7f0168f218f1ea4d1962dc377fcb2d66f5334894159960d508e587528fe2a49609c800368035d43eedbf99096b402566ef54c" },
                { "kk", "77d7bbe654e78844b9a958a9e9517827b27d56cb0e1f386c635fa5af1334806dc2baecd44be9a201bc06668d6dea8bc560c246714feb4d870b22e0e9b04d534c" },
                { "km", "331eb9e9a0055376fc504b9b29f9ea3da40a6e33a56123e7a56ca69de3810b617c26d9fe450da8024e8121aff1ac7a8a65604454829fd6a64a3d6c9f5fec83eb" },
                { "kn", "7105a1518a074aaefd8be3e5179166b1e26595ff7ce0a1d32ae2f32dcf2e9179c806e60341304fdef937e06156aa07bfdf4ff17a7d6c794c2638fa26dbbcefd4" },
                { "ko", "28fb85e2bb7804118f0df9da6839d2f6beb6756759b4d004dce3f37f71b3acba5745090441e447af151a9304b22e47463522ec36586a4e59018c66b77b54fb60" },
                { "lij", "917258eb034614618515268aa0587c2c9cef4ef18e4dc905981274c8dd73c730f137c39012f138622b12094c90eaeb5e1ebe79514f7d64151f7a7985c466c336" },
                { "lt", "c1387b06cf24fc0505fcace17953f767014ef445856a0c5c383b0a7385f9077f8108261aaf7d4dd87096dc51723934cbc518220b846394a0a246537c00239990" },
                { "lv", "77b92a5e5df5f3239a2e64cab4255f5471bd7c1d80ab342940f05e52e3d5b38d3b3b2f82df860015308c368936a5cde92cbba987ffb764d52bf29b92c4463a01" },
                { "mk", "c4079fca35c5f03bec1a907143eb9a98f27103456462a5575de5333b3d82ad788fa74c10b77db3d298fba718605a662f1f7655faeb8db6964465c139d95222b6" },
                { "mr", "b9eda21b45d55a660d216fdcf62017c1a71388b28921b9a62cd01468d6f35062f951cbacf6b1a43bd52e657073a7669efabc28048a5f539b327c1e7616a8601d" },
                { "ms", "10676966afa818d55547f0f1cd0055872f03a60a637fdda4a20b9093d8ac81e654a92e32b0e8226b6b1ed2f5d2cabd9f663cd8b267ee76480a97d7720571e140" },
                { "my", "102b8b8ff6bc7f13e0fa27c0bd991fbd439c7e079a55fc418aff746d1368b4d0f2744db829d1648eb9cbf344f24b84d0d2e3cf3e9ad97908d1b9ec38f24bb64d" },
                { "nb-NO", "baf770e4c640c8bbf2e0510e3356027ed25a2ac02b244b859e227525998b81687245dd4a30c080af59fd2964a2c8253a36421ec3ede00ca5b0612a0852d9a47e" },
                { "ne-NP", "a9c0d6b897eb0210f4a46d1d0c2e29a4a105d3f333e5208918620da555449b6f21077a72756958d0673a8348ee0d30723153a0ea35cc55015d4bab1022f672d2" },
                { "nl", "acfb4dcc6889f7ee997dae3baef875b3c204bdac0f0539702b2790afb7a80dc8abc258ef98ac3703739621db0388bae5557303ebd48cba42bbf06915e55c8113" },
                { "nn-NO", "505ae6022f13dc009e0611626aebe7ab7be1f5b210fb44aa0ce331103a8b74bf8e177f77f8dbf6b2ed5a6531df191bc678a563a4fc60c540fb5df4ee7570b799" },
                { "oc", "200e3bdb7868e83064022e4c98e32c24cd44d8991d206a48b47910d4d861b6269fbf61800f81583a4587dfa55c0728bb300809c5953e712f2398335f259f5140" },
                { "pa-IN", "874479666daf668ae0b32a73319767a5ba0fbd59952d4e03e36836ef517fa8dac6d5fae42d85427f4bdfc566f4abbe0765bc3cbfbab14d094fcc9212bbf27c27" },
                { "pl", "9c8412b310edbd99f5141a0947895389e37cb2f6ffe2b71ab6d4d100af6618d89eb637aab877c78ad68ff2d61ff5abce8cfeb5226f49a93fc3d2b60df3bc90f9" },
                { "pt-BR", "05376f095d5fd6c66ee274ad8f6d0b97d634619d70ae66ba88cab65c598984e57bd713fe5be9fbb64cb6394cc8617852140071127c14d6d8cccceb39d6e9c020" },
                { "pt-PT", "42145916a8b04ae3eb988869c3a8fbf199337dc80235015d05ccd90f4f73c63bbe663f8b345914cafb1919273a927da9ffeb207f0edbab49df8bc6b447f85f8d" },
                { "rm", "21d49b92aa9d5ee38b1a1144027deff2da13f768325630e86fbfeb53249ac1ae26ae386657fdbbd2354a8caea946c5a38843fce3c9f40e9a3ed713ec9398b92b" },
                { "ro", "592de327032969fe6215d9591db243dbc55aee8667a3ebbe940eef67bec1573d8c287ef3f1124a1b9e65d27d744db763d7d130fd1aa739ddb8033dc3c54b6797" },
                { "ru", "41cd05a3e670b62c748fadd8e9153b35c67f1e6601a8385d576d3ce4f166fded6a9d94fe8392cea75f6647ea45893d5f683b5bd2bc5aea19902d4bf1e0270bbc" },
                { "sat", "cf0f2338e5be1cd0b75540629bb0431fd35d3d5e86a4a39624cd631d4d44dc8c612cf53ea480c6de12597288c80b99d908aa7264f2b7f68f874cbc49a94d3a33" },
                { "sc", "50e16626fc73c8364f92735d76cc38bdc340d033e00aff5feb86157c015d409b24b5a4a0013670f5579188b32144a66abaf7d37913369e1f578b8d1528e9e236" },
                { "sco", "7e8a16a01b1f48c310ac9aca3cdbc82b6d282eb488816936c891286bc9351f608a52a87bc3fb2e9b3cd44844992daffb3e59d8ba9eed50b15d50c452fcbb46a3" },
                { "si", "70ee62d6fd1da804db5fa33495c0cfa5f147fea5a83a9e72ee67048202a86dc32a9b1527454eab14936487eeffe4d557c995ec4c33c3be6cddb23d9b69fbc928" },
                { "sk", "c0cdf3b2a0f88907b7869f697d2e74a1bd59cc71c67007940b14f63c13226be3fad99f03b83e7350e2945910f3b001475d5a8f46ab19b49053302582f3de9df7" },
                { "skr", "ab87cb367ecbc807b616dc78f0f5d94a396486a48544378bf1d279d7967c10a7de72a1f5e11230c7675f26197f264a8d041e6490d89ade352916743883a127e6" },
                { "sl", "abf4f188e9b76c8ecbfa82f4f8d42deee62bf464b7e89870857ea4787aa56ed68adc5dd0e4752d455ff2c73216e8f2f7dbea84d14fbe49d3458112b0d76687ba" },
                { "son", "8e99bb23f82b10c3ae1d6d1d69e828d32fbd046c5e4a5e1ee04e29051a86188a5e1801a65a8758d921f697bcd4335fccb9e6f785878ef2fb228a54c1b763d210" },
                { "sq", "19a3b45b79be7a38a529f44e2b97ee225fab490306aaec57f8b53b02bd68dc504f6f8195be2227da9961dbcbdd04799947eb1c59792ce8f0573466c710cd502f" },
                { "sr", "4f950749e382b87e29c1878ba57d08ae6194dc381bf3c07c46c9ff5f4492493d6d975b54f3692c0c60c3f93a645ada32d74bd4554ecd4e3b4baed5e10e523566" },
                { "sv-SE", "870a80c2b261508f784812916333a60bd07a9b16537c7f2bbb4c521741be1fdbbf74917eaf34dbf57d2f8313eb6304f9329a8c6789042574e5569a60bfd43208" },
                { "szl", "f7fb5f6334c3f3b38f65e844137b08c0b597b5123f827efbec463189704ee239ddbeff5b46e40da61a736294f62b09f9f2921823ab1e45c9e414c21a1d0538ee" },
                { "ta", "bb5298a3be45ca5e79dead1c5a53f3a55d43169ec1854605dd224910d9e5655e5ffb068ce44499c09d8c71c11ba3c7cac26926060ccc5a7887de4b67bceeb925" },
                { "te", "e773f6311a67133bb575e0b6980bc8ba76baa73aa5df3c71d9895f5f5a38009073fe90cd5dd2a1e67b72a03d32f83fe6f45b4db910600297a8c5727acecadd37" },
                { "tg", "7c2d65733e86663907b302f50b9a9a4df7e8de06ae5916e4dfa23aa3846ee4cba62332549de3c46fcc2ea145f35205e47594ea0b17565158f96a75afbdf52174" },
                { "th", "72196b90bfdbbd521f399b374a071d1a0f13ea2279d4092a8cc78f4512cd66829e0efbf0fde19d8e3762e167296be6757a12c9988855543cbeefb87efe16c930" },
                { "tl", "18b3c43688b4b9b47e930b8a037ec332160bd7762aefea2f07c547e1616e8c343695e09ab2f1d380ba94b162a6b89966392efa9bac72f93025e64f04c0ae2571" },
                { "tr", "abbfeb143a335e8276e8ff5b51b9118fd0ae5c0fa7328d6c323f7d578b583d2dce9b13850bc5ce093e4b33fd338c1ab88a90e3f69ecb72cdc3744bac6d7f54e5" },
                { "trs", "a7fd40bb01acd45472886120ff7cfb9f5d8e6bfcef6e9da84e54d98bb34620074f1d440d42757c1266103ec63b7dbd284e0e2aab5e5a1be3fac60fd946c894d7" },
                { "uk", "4554736c0ac8a1bfb6e7b725c62ac62285432dc3812f289a860248da2b3345c3a67e76a0201bfbf98120fb79bc38ec97e75b53d8c55179879d93a174d9f1854d" },
                { "ur", "dd756a6eac20ec1dff2b76baad39344ae5cea0fd1804724134306c2d0b164e9dcc4b2d16ec863fd1f21e20a9bf3fac3095c7e5cdfb6f085fcfa4f3e49f319dcf" },
                { "uz", "eab3e203cf8b5ec366022532e43ad5255970b96a813073c445f1f84bd855c0a5eb4e7d6c12866707ae86e070deb25cd4fbfe658882e7edfcb801c54ec14122a6" },
                { "vi", "e1484eff2880d110087a01b6bce6086d0c21ff7d92d1cf0c8e6dcc49ba5e5f33fbe9665d0f11456db5ea3f35ec71de0a6353d99704b70cfb5d61d645155fcef9" },
                { "xh", "9256b5382277c301486fec3c1c859c1114da779cd3470d05457e14e1e1f7f3cde112b73be776c7df50ca41043cecfaa6967426cd5266ccc1636cb87012b1d11d" },
                { "zh-CN", "50e0277066da163605087c82f109e3cc5f199e12d36b219c2a34ffd2102de1170cd64900525e4c542bb5583d0355b435ca04f52df305c5f13f15ce4b53fdba5b" },
                { "zh-TW", "5b3b9dba246985b0622f612eb14a69326758566896d2018b9922432ebc98b6c973e9891a538ea9c24f6f8dc9afe19e39e277ee236692c34579dc4cc60af269e6" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "380c71ebeb059b02dea1d1ad931de07eda995251481b18ae516eb3618be137d2e064e40e24135cfc13c9bde28454400e2c524a15319c4e8ab97d280e4f64763a" },
                { "af", "9304a73d50ef73a891c403b4e4b05f233267f0bd705eed9b7e0c251fa120710949102dbd8fd918964b49ecffe3ee5c2f8fb48e205674d0748d64e16763526772" },
                { "an", "ca3f62f0288fa0990a95a2d06240c4507895476605acafc4c7501d8918672344b274d63dfdacf628292cdec4ed13a514cc7bd27b875eff7876aa38bc04076f85" },
                { "ar", "6af129f807109cf68b4d20ae2d8a8bcf3696f968f65c7173d8770122a10661ee1346cde6c3ae570c65343cfac106a1a1d9d84806a782c6f3cf9e718276866cf8" },
                { "ast", "1a51360fefc0a8443f45cb6d1ea69e6f09cae06d46c8540b3f5a7d400bba7f09ea8395ec633421c0ffd00778a53053edbd5f599b53f1fceced0973ea331e04d0" },
                { "az", "509085ee483d2dfd561585cbcaed34e194ab3572d344cad9360bbc3cc74065184fb1c47aae21e0fbeb15a56274d19378aa6463bb4a76190b323970327e8be868" },
                { "be", "2222c5a69b753da2f4fb896f9e066201976cc720b48d908d000a9625738700d9805d78a4e69c82041e4f4d9cb2ee8ad6c47ed171caaf32980045c0eb093c9c3e" },
                { "bg", "1c7c01bfd2bcc340d2c1ef0b145f1e9704cbfbe68068e117fc7f090578700fcf1d6858838948e2c0326ba6d03d7f93afbb12ac6399e17de2cfc4b62a8e0a5cf0" },
                { "bn", "fdc48bc762cc77644acaf841ee9f097f9649d0423938614d3e8e60289c5975ac26f1495c0db6e28556a5e485afee72742bad02a8079da903bfc4e378d9fac7a3" },
                { "br", "594376dbc550f15d6892d5ea6e5d89a21f54818fbb00cd073822ddc85f670819bbf9b0fd801dd0313c2094024f0a87669b8b19d3aa346f6919db7bb522563279" },
                { "bs", "4abc755ea185d3e66bf7e6bc7730dfffc196fe68bd9c12204c6cc8c2db6598ccc5801af0a2c9ec86a2cb410b42d7d7734f2b56d51855940ff4648e900481eb1e" },
                { "ca", "13ef3e0815f6d6cf1b58d7c597341629ac1ab36bee90cc755514757ee3fc65ed7eb697169e8c69c091744af8d5ecb13fb78e96b8d9109f7b0be3781b51149710" },
                { "cak", "6879db87666e5bb789d44cb12c444d23b5b7a4d9e758adddd782e0f5385706f703893dde37ad2e71c06858b7868236285720103093e74832ff2ad8abd448d530" },
                { "cs", "f9f1349fdaaa75858b35e1a4f94d66880884156523315bed4ea808a5224211255f47edf60e6730ddc5d6a03f713f297bce6f256c1b838eaf1b50e020e5431c13" },
                { "cy", "845e771f1673545dd3f64a0c9927baa3111c3e8853740cbcd693297fead4d0cadf77417d054dde760d1c2412668836aed6aa85ca9685a66595252dcfd9d05cfd" },
                { "da", "8b8820b637cd19db138a5e70cbaae8ac56aa92d7eb5b4ef9d702cea6e929f97168768d90f876625066f03ae9aae3f77e538d7a67c8cb1e663991d8c2759db975" },
                { "de", "7f395109eb0187d54c4d0ada31e39d3f56f9cc605a178a25c924156886877b16689063bd190ca45aba1936eb60c1a7e872e8f4375bf10aff5a1618deb766c923" },
                { "dsb", "02a306ad03480e93e7955b7d5e796c81db6148e0e81ade8544c3b36707d5499daf3b338abf253ef4494f6d2490afbdbdd90f5d6c3efdb7d907e08c4b5dedd17c" },
                { "el", "a113db681abb4a1d0803a32e599ab0c16b1e8d6dc485b98fa084b8492f3918dbf2ccefbb9556f0c9f3d725d90ecc83866519a2aca2e8d059881d245982f9ade7" },
                { "en-CA", "97323f82e3614ef0e7130af0f85acc0d2c6ede2a6acd78ee5a239fe568b3137491919faab2ec043281aa28fa5eb35d3fa2393698b1a635bfb8c49a3d48e75c99" },
                { "en-GB", "98af31f2caf3878cd621993954be35bbebaf9a6d5605e0df4e894d46c778e319b46dd6b9340d758f9f1e588caa2ee18bc9499bf6d565274b4342928c1526b21a" },
                { "en-US", "d1df6eaee2f7932cac39e3d915d28f4be8455bed7f900d963f578f59f448e94bba658ddc7378baa8063ce6b0ecbb4979d788ab523b3811fadd6fba8db394d5bf" },
                { "eo", "d604390d12d32ed899730b24e7dd3bc3dbfcb777078f1fadc20b49e2444ff835b47d52152a6f8aa8f2d8d60f50a7b5d5e1eeaf401606560adbde423392e1b10e" },
                { "es-AR", "bad0e3cc557aef495dd0c17efbffd0a001decc445b260b9e0dbd0e3bfb33b3ae96d6f99cf8978c7ef875fa291b7c588646bd09183f204f48dde39205989c2544" },
                { "es-CL", "2cbd5661faf8246f725c6030931dc11d1373b28b6eb84ac7f33ab955b846429f908eb6dc1e9875856da7ee8dcd6fad92b2228e6fe17aa7ec29daf7d1c0d7b6e2" },
                { "es-ES", "fb962b10ff04bdb6e512641c94df8d62bdbcd8357999d2fe6275835f4d406c7ded0d6de2040ebe39f749b8915858dccf6b308b69627623abd72f1bed7d15f45c" },
                { "es-MX", "d8dcff3248e53ccc3c38d40a77184dc89556890e6ecff346e4cb071f9dbd76d5ef57f44facfd488769b1d68a27f29815235253688c0f50a90ad33c4d6a232a97" },
                { "et", "09bc31a3f885da4987e0938de8f1db5411b36af16489110686b0ca9ab80d97ae8d24d807ca49348214a7e59ac318ce85c59b26fdefc1d22f12c0d21b9d5b5a12" },
                { "eu", "cadcd7cdbc26730d276d6d410b9ea71b1890366614b438bbb9d595862e4815ae43fd91c7233608cd4b422a98d0a920a3d8fcc536fe2e16bf0c169239b8dc31e8" },
                { "fa", "b67c6d7c1d02346aff6275d105d896f8873670171717bc6ba6ca371a96d19c484ce7815466155e83b56eeabb0e680a8f85a5fa01b3be41bc90b3a7e92bee23cc" },
                { "ff", "e0176c0da8521f10adcdfc03e269c2a225c7214a659bd10e064614f099994e0c1e1b65114dd04b8119d30de9c4aa43879dce2d36bfdc207ba92fa64b78a67d32" },
                { "fi", "406583bd7fcba8b9f65c7352bfaf2b85421c67bb905792c7bfea66982e3d6c3dcbadba3d830a0b4f16226d34f9cd9c31e7461594dc07f6dfcd15058df76c966c" },
                { "fr", "b9ada26df537da0c8b418e0bda76e69e6cd066ece5908496b386f83bbf1754e643a01d9f448abaa6370a0db7b07f07cd352ef834a22509b4efcd0da37850f096" },
                { "fur", "aee3d1d5f94d03da555526e50aa69b68b057413f5898d2ec42db5cd3bce0e5567e0323dc190cbfdf0b111ca91ceb2d1e6a9e952575e7edea6d1ce5343de3a4d3" },
                { "fy-NL", "5498dc51f1511c5e6bd5640cf4865c5cb10160ca2a8bfeb7ba0b6b560c72caad4c00850ce3952abf48329989a1eb3d3adc654c7f55bf58ddda04a9c007c78ffd" },
                { "ga-IE", "af01b7b2e890c9b67532bea4bd179dff95597938f3cf1b9b025775e8d19817b6e33626915849f6d72ab5b64236a3addf7b08bfae6cd853a44cd20ccf1afb8aae" },
                { "gd", "8ce157266fe9aa6a0d3b969369a3b9b17a938c6cc3652e197dd523ea83417a0940281851eed22aa0d24c083131cce5052e2b888dc4858a1d037268f56d104ff6" },
                { "gl", "29b6389f9f8a5e50375ce571e0693b172698dab0b8ddb351cb05d435107e28de8d361fb1f0e07d40d58b7b73df683d3d1ddeb9174ede4a5e2f69815b219db61b" },
                { "gn", "735ef24dfa0974ba6867a2305f9f6c5266b39c0a34174dbf2cc06de36d393b00a3afcaafafb022278bd56db1961526b1e41429ee9525e58c2c140c42422313c5" },
                { "gu-IN", "24c93100e2392ffb9b5b1d7c0f99d2ae106336296063315818e6b66a35abc5485e82c944b7579bcfcf7e5ae912caf8fd39af32f8abe6016aa22837281efe5ee6" },
                { "he", "c6387174a30d00e6b98dfd8c08195189dff37a80ca061d5146cb2da79d7ce7e2a4ec72ecf140260bdd3fac1dd848b971637ffac7d0ee46c99ec93d451a6b467b" },
                { "hi-IN", "a67179803ecec33d2d902f9d8bee91c287c64d0b8b9e409ed8403132c044218e233c975cca2bac78e12d5909130b8a6b8a005d42156809c8533e4bc1253f317a" },
                { "hr", "cf7aa544a2b9287326e7274ce7c62ee75ffef904f48022d15016e6187f481211859007c2babc5771bfbe2d65c34f3a023cdf18e34ca6bab4c02ea71d975ce578" },
                { "hsb", "fcc1818cd87bedbcc9d49fd0c37ee687d3419ef28471b350ce19dee30c43508a29d6cafd5bcb2d75369eab4fafb17008477ab297c428e20cc7d016fe58ac41c4" },
                { "hu", "a9bd1377685bce69b1753a196e59dbb89622c6e2090c56a08e48ebd5de3e724cc319632a7e64df5328d928f8aabda756434ea3a82cb5251bfd923ff7c3614a7d" },
                { "hy-AM", "2d6ae4459f7d368d856de125f7918ee97475ad13993a1335766b9a322d62f152a4f0f559d2545f8cdc1be64a23188a2e353fa536e82b148a2b1b857803875ec8" },
                { "ia", "a90a34964a78969ef586739a21b76ca64bee57a56953093b7d5f0b29c7ac7854e8bb693ccec63fd97b8021586cf4ada8e9dfc07da38c6aed1e72fbd7602ae3bf" },
                { "id", "a751dae7532c7271d7a6d2b5da951cf0f268089f33a0fc238cc5cae0d14217daa94bb5de3ffe7037e2ddba041fc12e48f8b2958d88de2306b0e51f23cb9b00a6" },
                { "is", "75ece0274e3207e5ed5c45f227d6da50b9010e09bc19317faf535f8df466a3f818b187fddc78f2c96b845906e3128fd1d26268acbbecd30d9dbce9886047e57f" },
                { "it", "45718eb26d4804705308a7bce15d13fce4d8c01482db49098d5890cc941250315f052f0d33a22ee4950cf773eb3758b913020b89b080dfde26c0d9319ce2ff13" },
                { "ja", "8a8f68d6c7828e91b5f2b10e31538a4ad95e3cdeff97fc16cbcf04eba1a2b1ede9f1dd9f50bb5cb9f8fb358807b57351d59cd57ad9f0e1b89091826ed3c6413e" },
                { "ka", "18a2a26ae96a6702487805fbc9b789d0ef6ba70f2861f330e0c5840b0d87dfcb0ba116be89cd36f3f2d5f9dd6228a701a0303e89cd3193d5ff72e0ea8621c806" },
                { "kab", "566bb504cce84a68cc2f8ed6616ec132e6d61030d639c9774974d287fdf28ea3119718f737145f1b9a737486b7e19d0b01b24270171f3234cb86c641e45e3b3d" },
                { "kk", "217d474b53ae5e2f2115b8d118c166f974dfa5ac0afe7a1cfb1c7198cd8485f233a057675748e1e6a348323805a3491a63134431608f66596bae2dbc302a1f6b" },
                { "km", "2cc9b1c1f3415da128cf0101d3608aede0caf3728781d8bc93db13700f93f7432453fda501ed35d599274a1342b9d5ad5b24cd3f8d9ff69dfaa8e2191b7dc0c4" },
                { "kn", "1f6feaf71549db22dc25eb72e3910b24e3ddb1e59ac932c4073b39c07da9574b0ddbfe0fee78ce9ba7063ee9f40a55d4efc96251daf6cbaf198229a84d06ba3c" },
                { "ko", "96d020edc85e8c57fa94c48e6c98ccef25b05c72ac1d83edc9fc543dd7241e737cdab5cf739acfc83d4b68ccfdc8e853b22e3651843dabf770d7c13974c2c418" },
                { "lij", "f658d57d81a8c8d4050a276551fccea62b0b7f9aa9b5c678fa73d682c3060c559921e4a47e300d24af82524d22fabab9b2a45dd19b662399cf671c99550dbe09" },
                { "lt", "ee6e3349c9ff872553e0e7f8d596d45d699e92c634e1874b90b40622ca572507956e35bf18483e5e3ff5db5eacaf260851f6ca7a3b8d77e8e2d484bc6414a873" },
                { "lv", "5dedfb17684da3193a680ae0c44f18cb48727f5032df1dd1e3d643615d6bf68fae19dc44808754f5b856df37be1c753aa7190a9f6873ec9abdd38a2e447959cf" },
                { "mk", "02f9b9624b04c653b710c76166a24db6a7bc95282a9d471b7614006a7476437465a4194efae739a8d69be68948c8a3beb6020d4b70af130649c0571df7ded1fe" },
                { "mr", "a577ffcc90cf936905581ce1c076a2e5d2df0ac7124db496dd0131886401b050b96f825aa1abab730825aedd85ee9465f93b85ee38e55523bef54818c1f96cde" },
                { "ms", "5634211184f665c5e7ce38dc1592fa91ab8fb65517c49ffe2e76937373476067bbcf32a11399fae555506ef2bd4d33feae8d8238568d53c0b75d702b7591ee56" },
                { "my", "0b79c4f0b43a7aa6371407094d720161312980a9c6ba0161f300689632e5fd96d24cf8f9df4cbb1d8fd7bd69ae8bd9b6fbf3d6dd6eceb9b17301de2bb4204077" },
                { "nb-NO", "6a91a442ecadb0a805f683d96675b6b0bcaa9c4ef83e6db13835393a9aacb86877a29145faec45ab7521a6d051d1fa2ff7456b4003c77a7ab09cc1ac571a86b6" },
                { "ne-NP", "3143185d3dc7cfa8288e8a245e207fdff504c33814d04dae3c6426c9760b22f411303f3e684984dbe99cda9cf50db2c35e404b73808e7492e0a08af87d73625b" },
                { "nl", "3540421bb35f0c9c745cc2c66e39e6f2c2719e32a9fb373ede08711a36a5c529ce43ba4cffa1bb8501a4ef6e4fc0bdc05bf6b8b5a5dee1c56ae0ccda0da34d67" },
                { "nn-NO", "55837a3e0b2a6a9d6a54c17aefb4555856815895b86302145875961ed23686ea520bc17f1096b5a1ef3a9f63d9b294589e6555371f3196184b754f66ff30e53d" },
                { "oc", "82367206dc840bc5d2564ad46afcf8e9d0bae42b220df887758a8fa4f68e0326e6b6573918eaec48f15b305aba3c5d7f34994c2527aa40efb6215ee7f0c71a36" },
                { "pa-IN", "3f26b90ff6d2f381a560bc68dba7240fdc5c3be60d4d9ea7ffb65c7cc4503fe66f053c8e66f970db7cc0ead664265a2a99b799c9cbb66d2b5bfde2b87b203f40" },
                { "pl", "80025449fd1f30d860e4417962b7b2adabb77de58a1391d753dc460c08fd7ec9ae52f4301d2e4b5c292ba6f97d285d6d6ce556f6ea653b3784af0dc4ff43a4fd" },
                { "pt-BR", "49352b39f04f9af8b0e8d30e0f9f788409bed692320f1268a070b79d3c56ed21f73ebec415366b2d558ca4ad423deeb96c77ce4233cd83df3ba9283ce9c23385" },
                { "pt-PT", "856176ee2477cf7a5b637926060e2d8b603688187c3dab25e2bc00a59e272070d083bec7b13a73f80370f1043024f8df059a47179dc2dcb6715c6c9afa24878d" },
                { "rm", "9194c7f5d2328348f22305e9f27fa8be8565fae4c2947a9c52a34eb8c0a5f80c5afd10981f74d8bb60bcdaac17636825d58ce10b7a6242952b9f7dadd61eb484" },
                { "ro", "d0b9cd7928f844852e1bf11df93fde9d68050361048b5d137fe68e0a26d0a38d2c282258c096b9546970ae83aa860d14a4ca58adf66c2f9ad05bfd50651fde7d" },
                { "ru", "713baa282cf012cb3455d23dea99913bf6cfde07926b162d1fb62de7ed92febaf9d2334e54880ba811cf479d367f00ccaebb892f7c8b0ada02f0d23b7331675c" },
                { "sat", "0e473a9f19d99d9b112a27ad85978811683fd102177617c7bdad02a53e5ac3dada4e5e56024ac4df93ab07918d1ed9f9bc42cf58e2f75e607d18cf187bede1e8" },
                { "sc", "9e3f445d654aedd3aaec6ba4448df9947d8d4dc77de7adc08dd50d4759ab02e5a4f04ca8cf37895f09612a9d3988c0cbf3997e8311c75fa5e895b93d296270a1" },
                { "sco", "bd9f3dd3d102b7760b38a3f1cf121023662b8cfb3d9e31c96ba164faa4a57a78365861a28df66ae64f852ca5d9d77d0a78b5b4cae8bb0c58ddd108431a7e51e9" },
                { "si", "ae9ad4ad72573bf6df86be8a695c540cf0139d2962a947f8ad857c0c67fd8fdd2af3627bb3c1138afa74b8333a4a3c555b04801a710a24874f024ab394f28622" },
                { "sk", "5618ae58955818e0a08e439cb06a1e7e906480bdbe100b18ec1aff29aa6ec3c9190f492065203468971acfe728027a6faf9ef924c11e727c19d4603ed6986c3a" },
                { "skr", "115602c2b3a0b759bf2d88202b884a596c67d3cb44b7d21cc05a6daa733d99652530fd86a3c8fa80c7ef0e23b13e2882471a8d4eef8e15ae1a2d5428807bcc27" },
                { "sl", "d51284a5e0c6554ba1a7fa7128f0521bc5616be959d2122a07a11d8d874961e0875da9b85e4e2204f914065b7810f625fa7bd027c2b18e0d2da589293e7594aa" },
                { "son", "8ec7fe0003eb01cf874f3ed1462197d9902a46edb9a7cbed8cd99c145f735aa0fbf2ae10ca7d18aee67d88f9c29264d5a4629cdf9804aa7ded4c00be4e12fa62" },
                { "sq", "3518fbb3dfc05c957a12e1be4cbc92a3b3d1fd6d8e1baef784a4a18e7fab1044746e9c4813314743c8cd50c05e43b5c8960853ac9d9b7a6e79b93ad8048e018e" },
                { "sr", "5d066f0684bf7894c27193bbcd61b438152d74695de7cfce0fad4af43c06f261e30f881b966d1aea7f42e8c7cae19e47d8aff2d735b395b3bf8dfd96c2fe7047" },
                { "sv-SE", "d6954324f7717ff71ea0d936a985752f207457cf73334ea90f3959f9e856fabb324961fa4bfacf446d5890870dcf24473bb207a86181c6591d1ebb95bef4cb49" },
                { "szl", "b4a4f3c4991a4b2c6adc313faa392ee90744ff0b23e706d7dc36af0a7abfb36a879716f9cd5d26793af66d9cc1ac705ab9fcb3fb97eb1affa4e5af23308902b2" },
                { "ta", "5f0476ed017d4c5d339a2dec866e5f23dc0f69dab3e35cb7ddcba26db5151605436d99357121d6ff16362162a3f68743ff95ba7a6f1041c5f364e62a3ef3fc8a" },
                { "te", "5caf445d326af262ee537075cdeca159efb04791dd81068ea320557c0e496cc15144ce7fdc822947f8aec1f14af15edf4423244c74e044963ca556a6d9635987" },
                { "tg", "3a0fb03f80f50511f4ae5bba6298517942817891f6622947bafd8fb631e1e67ac00631cab55687535597816021064731124807c6bfa4e733a025929684121ce4" },
                { "th", "4e502e58e2c6741bdf9d113b30d2c5154b583a649d68363c663519d0ccb23020d637a117aa1ad16e14f37be3b6b9acbab5035e4bb13aa1f56bd617a85d824f35" },
                { "tl", "6c3cc4f87952d45ef2c04bfeb38b411ba40ea9d2b254fc4dd3f73b96942add02d8b41f26612c34da3616413cfbc55086c7e7ce54c7426fa4fe4bc66c24787115" },
                { "tr", "ea71c2aa04c357d1a29da4225015a6e61736382ad0b3a8580472131a5cbc2222fc96f27c93d57899e4d790b39ca74a5b63f517ab23560d0738a22a95ebd4a0e7" },
                { "trs", "ab45dee137bd09805259ec8b2c9aac0bfce7b04e1d0cd6d2322d9147e0643625dc1827e494699dff761336f9495793ee3c03b98975bd194c98826a082e64888a" },
                { "uk", "23852b6fbad2e861c961f71a29f928077bc232eb7621d7dc507ed824b5e8bc6c5d2534ea1a07ede307be86d58bc6f1770fc165836dc49f36107b12dc9d1ef59b" },
                { "ur", "7dfe088dd1d7af74305e200cfabb1887d9a3a2bdc5b133b6e3d0f34b924cf24b455774c3f76d3141b23c37bbca44839af37ec3b1a43d28d10ec3366711f14c07" },
                { "uz", "23617c25982250e683954a53cc95b6c66545a3444052bfbf72ac6369c71782db5b0518d551062974ae68c581c36f23403d997dbb59add58ac50937364583498a" },
                { "vi", "82bab8ded6a1d43ff56856000893181a8bb521e4a465024f30396e4886f2e8358f4d694b16839379abbe6d1fd426417a67d5cbd8148d517dda0069ccd3331b4a" },
                { "xh", "a02dfc89cc4dbe81ce26a21af43cf216d5821fdfe8bf2a0ddfba4f4756117a26566b755c1dbf5d3591f72fe82438339eb27c66b82b55217c3d0b0ed5597cfa19" },
                { "zh-CN", "8f1a5a0256640530b15d729e49249f9f92c6351fce00270b816861b4dadffeb507b7ff658963613d321265956904a094a5beaa40995789b1a3486493747ad3cf" },
                { "zh-TW", "8c40bdeab33b97e471f98fabf6c51d1649865f78cd05d9786f22cb4168cb4d5fed310cb11db3926aed54483a707ba960eb1df51f3d916079a8fc095ac2a65ade" }
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                return versions[versions.Count - 1].full();
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    cs32 = new SortedDictionary<string, string>();
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
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
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
