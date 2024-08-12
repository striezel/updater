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
        private const string currentVersion = "130.0b4";

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
            // https://ftp.mozilla.org/pub/devedition/releases/130.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "51f837984ecff017241916f1fa7e4f250b49590977a6dc0211037769ccbaaae685afc4d4739bd9af68c1c5ea15b92fe5285be52dd1b653b504291f701a535c8d" },
                { "af", "82fa871532b1592a7ef45d90f4ed86ab0b0466137e1dc71a321129b60a56dd561d6550773e977f9114e1e58f50932080f433788e7c274331db56da2bfa95392b" },
                { "an", "871a655a8518ac2b209b07fc583609027a5871b0a20d784fbda2ac73eaa62c83f5ef5b50c058e505e51cd0ba505e64f02b9ee839e5ad99b302deae33f588c59e" },
                { "ar", "4125d6e56024c8880c0046de2fd57e7fdfe328dffa5835305c397653feb8b1161c0f3c3e7be385c549b99527871395f7b7e57111b09a8f02b856efe6200688df" },
                { "ast", "726b8be36f697299c6a4d0a096a1bc3e000b9021ad65d2194010b8050d0094e9f67e184af248c3ee4b175370f062bd8bfa377a961b91e4b795a7b02a72681067" },
                { "az", "a1393105fa995c42e9d7e4181777fb563b6a411da96343e5118bbd9d702054ce098f49846f814395f239a8d2b6b6a6774cf7a078dede4810a160d3e5ea838ca9" },
                { "be", "6a1292aa5a13744b23a83a870f2249ff24e58dd9c3891c4a531615f8a676b23eceb9a605e83c45744be3931788488a9f4fd80539151c0c45063816a171a16f7d" },
                { "bg", "965750692c7835496334a0f975d8e8ba6a1a7f889bc1ef4546a5750e43240f2ba51285d8e38ed62b367320ba960f71b88d9fc165929946db8b08f8d4881e5889" },
                { "bn", "592ea97dc4c96b28f210f61ceed4a0604365dccac0078cd979306a9ee0954184f9324a75a38de2a4df9cef8d473fdd423b6fc61c6488d22e757ae699d27c3a9f" },
                { "br", "dcdb1fbc4641e9bd8bac52278df1d93d39a59c06b1425edede5953bfcb2b31b38ce3b78afd25c57cbe04dcf33096073620c0cbd755051751af072711998c46e1" },
                { "bs", "45c73d2d26900936dce1a98295457761b59b2ef177c2ceedaa3a1dd8c3f8022e2ab0de66ef5b64c0f59d3c2b10376029126664a21ac26d9289ffa65084757fb1" },
                { "ca", "43728f128466d2179483827a414857b20a91ff4226e96851909404c1d949d6559c1fd4ee70511f5114444ef4afa02dc32d4c04e9361e2bb742f952286e6b8ec3" },
                { "cak", "4bf653922830af65257da153d5cf2edc039f2c12ffd34f6eaf89d205c767c281ecfc1d26dedebdf2665e51f48cd855264ce6c95a5da61d5a4b3047d46bb722fa" },
                { "cs", "244acce8ae77a84c4a414e834e1f3a23e690467d98eb48653ddec32b39b3c9c005afa071af8b4fdd78f334a286987624b74413e0897a934e0d4820edce6d2265" },
                { "cy", "3c93773ad17b2e45e4fcac5066acaff5037f5e8d647bce9dd094c38252b43a3470d51153c5aab0b69c96f2cc2a4ab926f7f11f781af152e2e193198c40339ab5" },
                { "da", "77af3b3543e24d4e39e4e84149d68605ffd28fbf137c0137bd2dcc758b28eede0e725e5e23c02257f65f4b1cea7034793fa03b95a211f6248a177f551d1bf5a7" },
                { "de", "279ae46e32aeccaf9b732e2b3475a11518aac7159446517dc16a1918c17f3d30200c33ce6e02e7fcda0216f7223bbf5a44b2edeea3df35102a5102b9ffa5ca25" },
                { "dsb", "2f56587489dd276cd65ec3669b27c8cf144d098c6a9cacf6c1cfe15750919bdde8477ca3f8de9c4713e58aa603d4db0d51f8b1e522b09073c1fee60749540fe6" },
                { "el", "d31679687cfe78ec585a1210c951ac00a515f4a4109222b5baeef73b098ed8f64b23c4bf3269e2d8d34c54e9ad86a27412af2349b5fa006a7664c8ac5cde8495" },
                { "en-CA", "a0869361d3f260963bd3481f78b4dcb841c64ed223e1641a6eff0a7d8d476dd881b27fe2847b2f1bd8f65fbc5f3bfe9860bd10dde9495144918bef5dc928f27d" },
                { "en-GB", "8f781fbbb3b55d78d3592c3117203ad1308183a75ef2e4fc858aa7aa69055cf02f6d01a4e9af26aa4f887b3b06af16b1e104a622c460f44ca8d81c016b77fa02" },
                { "en-US", "dbad80263db94782adfc91d6abddb19e04303e18622e7bb623788ebca48dd15e6f01e56c065346082d1e258d2d1228543d9eaea91c6e81a90846a668e7e724cf" },
                { "eo", "4d62975f3f71a27e771d94c20b1ed4e09c19a6ad3def688220efe533996a7dc838b01b17832ec2fc2b5b59229a2eac71cf809522038686047ee70de48820fe14" },
                { "es-AR", "d1699c74a350bcfd8d2ad1ed8be956a6868a6f54c0d912ecb42193faabd45b2c7b936741d16000665a2dd7942263cab30445de7ccedc5a54d8a5d5bab8be33fb" },
                { "es-CL", "fd7f206e46f9cd1283252315d9f666a03123c144a44ae345c60a0d7193ba1c3d596324c3494743ab7e912364e5c592fbc4d047a963b83e5813582abe1f15a17a" },
                { "es-ES", "e12ab90a05273272c8e1353dbe6c6bddf4770c1f6f51c4ac5b3b4017036d1ecc6dea906b8b8b491c43f93bb342a8de3051ae2606e9f89cb0eac83ff43ee8b44b" },
                { "es-MX", "a5aa732305980eed5ce5f93fcbde3181ea35f7695795976727434c30262777323f21e42d986e7dff503f9d46402c09c6e1d889022ae91971249c3e51365ebe7c" },
                { "et", "ffb44e5bf0f6b31d2ea01d54a2c89e3effe284d8204b07e4d646724b7cc31d55620a5cfc7fe7ded90c1b54eaf9c18e8e413f74640483629a4217c4121d326884" },
                { "eu", "508e264d8e0adf21537ac1d17cbaa7736b119b16ce713ab67b34cfa27320248e9e7eaa2e2c765b1a6ef177235232ba1121d699c30332881cc45386b302595574" },
                { "fa", "824dfe388af2b3a4de1eee081daf397b8c139158c5317f4602ecc79253ce2166f66a4244eaac55973e1a5df706b3dbd00a649e9445fa810c8802eb00e0b57569" },
                { "ff", "42741e4cf124c195a4de2e5a52e59c28bfe85d6f86afd1caf0bef341589baaac9dd3908ca137a8503e3ea390bbb1c6c5901eb558146f5f7cf97a666517c18023" },
                { "fi", "68751b56aeae3ed19abccb71e14ebfb12ed185d53fc221e02ad39c372be91c41182ca5ec41a94be271f2adfc740dfab961e0746fe85893cf5669960f254c55a9" },
                { "fr", "45f50827d20b7252473ac078f146a3d467672e24d0b9438c2ff72ad1cdce51c8068d7c8e2d239335288b476b80cac34cb67c155c2f3a5f469d475ee01717c207" },
                { "fur", "41eb7e30ba89b3189d891baa19c8d017509633f14e1d333aee3da52fc4fd12e0d5d98f0d40002afe3d3d7c5e1b3e8cf49e224e3859630c38948729a1ae4b26c3" },
                { "fy-NL", "aaf372f66a5975a0a2e6fbceea81d96debab0bd153200eab4bfbb48f3da8305cd8a53afac631427eaf9cc098fba2eb01e68f58ee354a380c9198d6a33d88d048" },
                { "ga-IE", "fb9fcfc8e8ff2a58298d549ca8a0a19247e046c4ca09d2a9553fa2b6a607f420af4cc58d9701228df97b72da4f11029b062ecebc8ada747df2ca2dc38dc723a0" },
                { "gd", "4411b6e86560cc03e883f78e74267572a23d540185208ee9dfc7c0df9d2344192af199059e16c947644911fadc7e6ec1536714ef7e792b1ee29ca372a05cec72" },
                { "gl", "8e91d518ae49f205aff85ed93f0e64f51eede64b9bf4fd2ff9e3f3c8c993520d361a2d5db83ae4e854739f44287e434173ad60ef16ba6ec8f84da0e716c5056e" },
                { "gn", "f20e32e297ab24408ab61c82570fe58f11e6f0a9268395cfd878e4e8621b9f43e311da843b1a7390d78c8580ac63f6c45ca17b0e0e1baa351be49f4be3a6dc49" },
                { "gu-IN", "0834b37660e5df2634da846ebd0b7e78debd5c446abc4464d819d5f17da406bd23a0d8838de59baf2afb045a28b3eab8d6d3a276c2683c7902165b6d8c05c66c" },
                { "he", "9af877ecbe8a34dd27d47f43771bb9209135637522637d39268a4083a6e0be47415c473792535fdf6c6434165e770eff7b2053df342ba049606391400766577d" },
                { "hi-IN", "e6a80541588f6dd6bd8474006076148f362a19fdbded9dbfc48049cd1a517e92dc64572f2ebf3c2e321129f6db86fc04e1e20279380136a9561a78b88cf855fc" },
                { "hr", "a88dceea1b5e5c52913bc434095a0c546c285e142fcc2a7b7a6390ef5afb82219c9980b8c906b6667c2650fe062a6acb157a1b9bdd6113fa30c84a9f9aece355" },
                { "hsb", "143ba0e6720a0e79a989cd9b55abce57516b8681b63ecfa61b705a94e6778a4cc2c6106a7c1e7bd0af39580cf89c6964b33a0842679a228f08dbf00d050947fe" },
                { "hu", "93f38a92a41ed5d18fc3eb09186f257c93bed81f979ef7c92c3efe453e3c947a86930646c52bb5973b6254017dfc264c172f9195172059dc464b230ef357103c" },
                { "hy-AM", "9f2910e17e9c61600073e3c6c471c077fe3ca1bf7aeeebd8ea0ea8340de0896556f3fe1b1fae1aac0d4593f0e9e22001170cf3c2bedbc0254d84a817df98822f" },
                { "ia", "c85100b8a1f9b417114b9b3debcb15f09f22769c0fc56b2854eab664cb86f457b3c382a598fdf87f1ab6ecde0e690bb1500733e77fb62a2005eafc7e6e361fba" },
                { "id", "a6fa7d857f3fdd2ca97914e470484cfb7391cc5398a63c1fe12ca93e62063d84be32ffd25b81596ad3c0be98e24be9ad25abeb69f311f1c2566665e0486c2b1f" },
                { "is", "751517d1f6021ad190fee9f82c2f2f25b24494940885fc8ef89b845fc93d4054b6c9bb60dcf485d99b1e29256bf8616966b8d2562637b4052b533e4f3bd2cd6f" },
                { "it", "9d36113e2ed5d4f97b20931b9ae6e64e2e4d27f807bb0f4328174b8efaaba3ccff5998bf223593056d6fe5ce66812a5fd862af9ae6b21d77a8fa0e03b07b37c7" },
                { "ja", "984bf4ebb5b61d4f529035fa24f760ee53d21ef8e51dad73ede1acb2daf9f7160dc561ec1b1557a9da5e1eefe2fd46296c6575f586bf638343751d218a22ba7c" },
                { "ka", "464aa1992c276cab3fdcc9aa70766c0f82afcb30d5b20e15963136cd61ed4fa569670f09705f0a33fe447543634540ed67cb68e04f42c2105982278c383eaff5" },
                { "kab", "fb963be444114e0885b1e909e0190ff7788ce50e3e76ec1343fbced9e2c792eab5360e476be1dab4d8c35446dc0b3af68f2c153ba8b7b56257944fe265ff702e" },
                { "kk", "fe7ffc645f7a8ace62ac77352b343dbcdc3a47565ed5b758a417f69909b3da5f6dac63fd3c83b08e13840b42c62944a73fc0678b4b01dbdd9f3f9a47199b7517" },
                { "km", "590b7f1844b2846d716290bbd8945c75c69be5dee74e936a78d6741d3756603ade91dd38a20b8bfddc18e02c2d9c9c1aca732e04cffb6dbb9fc10521a666504f" },
                { "kn", "3b623b1243ee9e7307cddf96eea16675d34aba761cc23ff250b6605f3458fc016a565411db7a5622ed2c912681adb2fefc761c68706113e67bd1da7831bdbce2" },
                { "ko", "c26f471d3a84d858aff737965d691104080c05de3bbddeec7ad3cfe4af7063f8bd727f9f3ae06910c15632811bcecd612cb23f6d2966f66328ccca41bb38af77" },
                { "lij", "9f5f2b6db50cd010f95cc5f51626bb3de3d1eaf788d82359f879ee98d92f4df2470ecede92e3091fc6d792509abf682a54b615e595db500389512c8868cdeac0" },
                { "lt", "8d2d25b0ac09274bb945684d07a4dae0007b3d06c4e05f2dafdd46af3fa77077bf010497796d6d2a25ddb7028d6fb12301251d18e18a3a7d3606f6011413b22c" },
                { "lv", "53f22725120ebd2234bbe3f310ee47845dad03bb211debaafc1224773a081a7a152ef1bebf7ee048e757ea955c59b388cd0630c9e8b90c944b1cd9032eb0021e" },
                { "mk", "55529ee8a28613885d0e146753758b04ad6d5e2b451899e677667be026c3b740e90dd2f6a8af480adc6d22e069aedd9343d37092c898aa69491be9e6f4f1b729" },
                { "mr", "3de9ca6f1264ff8c683d6f671763f5c3df05850ffbda707cf07ca9b79f22d5cd4e401c2cd25e8b55d740be1a73b6f5da4fdcaa9ed99df0cd2fce2cc530d5a2f2" },
                { "ms", "2422fef802f9d0ee74ab24cb66b42bd7ee587d7a67ed34fac2faafc83c66fe0081d8e752cbc823df94009482961937414d9ce7b59b083e85bd267a5e9415bbd0" },
                { "my", "a52741ff335e67a6124e716562935a7d880f34ba6e76e9d22a46ee83dff558024881173911d93b49617db8484e1ac65b680252f226f38fb31c4f5b671c1b774a" },
                { "nb-NO", "110a8f58f80ad49f891529fa5a54593170d5a398508967c883c3c87c70fec6d7c1733a3b54955f92e4f59e65fd87151a8f39bd7328b67e7ee551a4a80f812afd" },
                { "ne-NP", "c1706c6263d50a9022972d5e3cb489437337a0589370ba96538db6ba44237dbd79375f9a0accf6c38c061b4a19430d5d76b19802c5b1214209f3f94b67d04acc" },
                { "nl", "3a151319979db2fb19b7981e11b62b467f5ab2f0788eb3e51addfadf2117984855383872211d3bfa0eb7a27d45f563813656302dcc5a02d1b23073e00c50fd18" },
                { "nn-NO", "b07329193120e82f46be7870c0fef2d6d6e42636332e28e16b0a2289e8141c147e1ba97f36a96c48beffd94878d103c014c51e34cdd3229fcc4b852e868a71fd" },
                { "oc", "3a15f36a8249956102019b8bb6aafeb3afe2a3d0982c550b4ff161c48ea6a28759609523c656296bbf7627279002fb17cb61a94c86cf4bd64a7c139fb76e0f7c" },
                { "pa-IN", "3258be642a1854bf09c97dcf6f8187d24561fe975599d7bc5ab788b5eee30136eb51ce810e31f3094f7ae8d5a243b9bbda7d61a92a8a7f30219e84f987763d61" },
                { "pl", "8bc3092d82b3b2893dcbc862bdd151bfc4eb79648b75a893cce3545f33f40946c47cc676b9f891c652c3d83132020a480114524ccfba618f94aeb42622ea6dcf" },
                { "pt-BR", "d008fe7988385ad891948feef7b84df79f155e6b0760dc6575c1603bb50ada48fc0ece74802822bf53d2759dc8b07df7fa4a34493552a86bbc2ae874731e4dca" },
                { "pt-PT", "9b4dcbb2e707bb1d3882192751900cc15addd8f8120e431185d8ab3268799231910c1fd7fd5b15ea2f215efe8a7f8e8b390e6b9225dcd87d106cd51b447eb0e6" },
                { "rm", "d9f8f5368ae766074937281ce3fc2ad91f059cf76b8ea3e8cec82d71f8224d50b5afea0a9765878a00e1695b5e8479bbc753b18d14aa6ef9ab2c3a6cf4e2005b" },
                { "ro", "f041184518fe4f4e896d7caafa13ab228b338b84e8b5809d692570343899c3c16962ecd04e0a749bf3281680dadc454dc9d8d41ad2899098561a6167b029fa4e" },
                { "ru", "728cafe9b41b605cb88ccd37afffd39fc04942a5f0e8ad36d39b281eb1cf63fccca157db1e126ac0633687d324a7dbc5a3ba6e2b5db49c535dbe4f333b025693" },
                { "sat", "d1de31c3e3a276c8b0f48440806a86ed8e65ea0cb459068b4e5364267be0cf277a1b29dfb61f50661f49e304c4e27a2a2f6fe60fddb2485278b8c059db421328" },
                { "sc", "3d40c80e57f1c4fda42831e35bfe82cb27e7baba1b97d46e9ef193eaeda44766ccb36525db93202017139f64f43004dfec944073076895b89a9e1217082893ac" },
                { "sco", "63ecbea88ad0ea66198a488787edab7ec35bda3fad2091d80aff48047200e467993ae2ac3ab3e5d5b515fdb07cd64e5979faa277d73bd10217e4ceb63b90b010" },
                { "si", "302b3af8bfc814cb63c1b33a1694f8e01992b18a69beff56a5cf91e3503aad19d819a74f20fd9d18ed21baa1f8096b58c0910c5d303a295532d6766a1efe087c" },
                { "sk", "b7bb7700b26d33861c6e6cc43c947f4f489934989ba5c83ee102ceaffe24b7296483766b3863a7e2a8f80030bde3e258ef0a08520fa98210ae992519e73edede" },
                { "skr", "ccf0ae5d766acac05bb7b1e391bfb2719505f766d70284b81855ba67213c31ac5a35424f8c03be75fc46bdcc34bb6d8a70f63b5aef430281be10ac49fc1258ce" },
                { "sl", "f162217c9dadb5db71dc2eea6314732da9d3bcb8d4c43b35354543cb6e19d31765d7d9cf7ed58887d7ad766103c64c747b7636b569e854442947f7835239b9b7" },
                { "son", "aeaa3967a077872bf3808e6dadb145822ad641346ac68aca0d2699b0f0c9e14c88e1adf25c76a71ded66fad97d5f872be19fb3372b3dcf8304f2c0efb2cafd82" },
                { "sq", "6fe621be2dbc49cf7612f62829f5cacc4237af42b0f0efe902d304af6a0f66f2572c05c061be0c9796bd75206c98821ea3b5af097afed832dc4b2a64972abdf9" },
                { "sr", "16ce4d4ed4e94101442928c99a2c96b6b65e8e8e86cf551f9cd8f4472749d5e9d2c1852aa34fcb6323f710a535dc616fd660d7667f574c660137a60f4e73a00d" },
                { "sv-SE", "d97c40dd8a91938ef70cca16503d1a01f0a852287cad133eb275802cbd221fb79d9c8a25564cc85022a88192163126239fd4a2c858be3b3ba985ae35f1799bc5" },
                { "szl", "9bc338c160bd9f5535dacf12d0fce532f227f0d5f8983266ac9547150ea2dd557cdb40c1a0881a588fa3cfb917c236bf2f2108b3b6d15cc6402837280cfc0894" },
                { "ta", "f1af48973aba522ab435293c5c7adb20cbe55492c89c4249a9e2f72c075ca623082ddbad326216e1fc6ee96a85395bed755b100eea1437839a6779aa9fce26f6" },
                { "te", "fff30b32ca604a174e8a320788333ac64455c9df5135698ae9c19389887527c4d0c14affb36db4e7c1f8951f5f66a3e2f46e33bae96f1b87e28b1ae84901bef1" },
                { "tg", "74a16fe2059db5de30e769d497716afea312aafeac51c60fb0caafafbbfc78135519acb3da4f7fd0ee24afdd727daf06d530af6e691c2feaf34390321648a9cc" },
                { "th", "86b5eb3bb67f6b79be8ec9e92c0de4a8690472e54c9fc87fb0866ae79d4e176d11d6e473574785398c2926ab0de998a02a9bc7b2ff61230f00657496046fbf63" },
                { "tl", "0205c5f8645c5dd5d5de0b8d18e492de48ddaeffe55581447bdab8e7bf30cf1421f2d464781d79c5764d06286a93a03f6db091619ed08b77bd42476ef3f0266c" },
                { "tr", "ac7ab3d657527ed11e7debe666dabf1a99a83778170f2c9c0503b66676140e785464647a180309b7453be8f78a6d3c375a6261e7a60ef11a745b71c793d22182" },
                { "trs", "6f1b711301e722f45b0cc87f28a58dd5266e64068403ff57cb1201cc710d81c7710b96a8d181d2df194e03d688822519dedf9c16b76f9da14b934230418c0d28" },
                { "uk", "b66a9f93b35fba1712ca6cefd7036849d56570534e61d8ed52c051496c8d199c90afddc78c25a486fc1cf70def3ec50142a12a7b745ddfef4b8bccc7d63d16e5" },
                { "ur", "f0b38cda75a71a3b8ca0ed7057c104e718cf41786c265cb6d1ef80d5d5720957a07d65f028c7e46de1bae302d7ef0b69f8e4d16fed475a721eca93da9966c4b2" },
                { "uz", "cf51cb6b174f4fb2ea950ee02e278470d218e0bb7d771beec422d97ae58c65399d28f262089d41094befcc8a737a0376b907ee86a17917d3e87998a4a14b07bd" },
                { "vi", "2cdb2d0374f72329cf0a0c716019632f422bde993a695e356e24e17e9fb94ae5b0b94cf68177c5cf32ce3b8673bc64bb4ebf32abf504200c612f4dbddc1f4498" },
                { "xh", "105e1deb57c34317ce9f3f62881b4173c9c16e11798e779d18ac5a1471504271b5e63ded00d3e734e15184751d6f79ebe7b0661079ee73737a1a58b8ea29a49e" },
                { "zh-CN", "72ecba470e2d7641fa666966eaa050c11a583d7e68cdf898806c88006e101db562d01c7181df4d627f2b939d7420027726f57c60aaa4f4c7e28e0cf849b5a1f5" },
                { "zh-TW", "303b744fb589d7604b59dbfcc62e4d0be87331834181bf94a5469e099142cf06bbc58266ba04314e981cd9fc8a22b08f6163b422ba2733eb905606ec4ae2f8f3" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/130.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c6dc5540624ea77c11c98c5181ea0f3fb6642d1e63d8a7f93dc0cbe202d44b5ca5972a6cd5d156adae39e652aba635547452eb9990d528e48007841b472a9a91" },
                { "af", "c4671d2046c5b402611c804fa70cfae575f1ed71a3cee693d5ad4d83ad58efb05ea646e6be1271df23274ec579799ff324305309c8c16f138979ce0efabe9ef6" },
                { "an", "50c47464124068dbaa6dc08e7cfc948ae8d2e46845c4a41d0bad4f6e23b0ca6d3380d15685762a6a55ab108508601610c801668f7758125119e96f6d746c1f41" },
                { "ar", "d86b56e67ecccb61f2cdfcf480647e1cd2337e35d5592c1e1c4012ebc6c862ab977373daa186166ff8060b990720a180bc803274d41738d35c64d6615007f659" },
                { "ast", "78dcf4c64e8c126d284f26af07d3dfc21ed57cd39dee2cd6c65efb4624136715f73c90abf4bfe994456bac244ef36b4b2631bce541fe2d4b311416c44a26c1b9" },
                { "az", "db4d30485f4b0c4dc17bb49d35ffc8fa053ecfa7f67b2f3441b5cdb7938b9f788f02a59f32e1c5c6078631606d257abc4dd44c99799e6c4cb655f749eee56408" },
                { "be", "fa920c0c796d2a6b002e605cf1f87af66bb3a0e38726a71fa6853f863ca7d4532d98924e04723aaaaeea53050f962d8b15ff950c5ab380f7390b47a3057548a7" },
                { "bg", "894674f88abde8e96b08bd2e56a30bbcae82e3fe3f32ff5fa07d927033e1a985adb3ffd44593db604c42863bd37f729dc8667cc5337916f77583b2badcd98052" },
                { "bn", "fb69ab352dcc7ecdc1fa7d2325e3182a5856ba0d08d3f9c4270d68e1ab77c75ddd388fff3198b861323ccb7f6af9be55a96ad552d0193e459a1ff194173d2d07" },
                { "br", "2487d83f4ab713cb75fe1fe7422607dd06b39f9dfb9488976fa304b04819ab3aca06b213425107eb8f1691807ad1a950bbb65be4d26f7aa209497e0e8250d803" },
                { "bs", "a0a0d4cfc2f38ddfd3f6906da9e1d31da705bef0b2c05d5b99d0f617a26487579ec75ac899edf8b06cf90c9f1d5ba73c38913656cc620c0d5e6e1711fe147d37" },
                { "ca", "88ea24522cfda2a1948a41eb13b3834f87fe85f144850c23755bc2d1411a71ce834226cbe233962d722e763428c0db3ff41cadce988b00ad66c0172b5ff98636" },
                { "cak", "026c50ab421d49b431bc754e073273fb70a6977396b87ba00e3b057add3917c1410ae0eba4ebb55bdba4162cc3a3ce318bca458f1aaeb4d56dccefcf35920c1f" },
                { "cs", "c8fa6549bbd76746da5e6693b14a2c2170f56d3a69d65cd50c3e519c590fe8e9358ff0c9cd2cc5908fe4d9e5a6443657c47ab81cf5016d080bc39fa0dcd14f1d" },
                { "cy", "f50a36a10bf3c5800fd83fffe29c232eb9f5c1680aef63bdc8d10a7ad3309f7b5c8b39c719951f9af2620599e84d008e85f6d694f814173d5ccbc8c6137ab18c" },
                { "da", "0386d2882ffd8a82524a4b4d05c768a0b0fff4fd53f5acda296b95c5f7276ca6c1168849bf3acedf16f823374f0dffe00803afe7aad7f0a9fca532224c455912" },
                { "de", "da9d22d88bc2da36e32f0146e95df6995cc80e33bdf8f487ecf27732cc435e442f9b858409db79f4ccc3ba8d3498cf369910c8dd709eeff4b9d860a095e88c43" },
                { "dsb", "fbf4dc370780bd6b1914fb4aee6ee567d534dc1d9eef6f57a43c8ab93be8aa9450c1042e82a9793113fbbfd3d49854d88c55d475f39df721b314ab61932ceeb1" },
                { "el", "75820f955eee005a340911cb4df68d26a35a94cabe2f972acfacfdcecc2b9f48ab1eb8be4a55a853a255d8c67d58f951353a21364ff77e9cc94b0b6cd7f1c595" },
                { "en-CA", "69bf01ad6d2fcab350adb05695d235ec22ceb7cdcfecff1b7be028ed69d9d3fd0231590f50e978c750eeec620958dfa73e19fa9b0b52cfe589c522d1669b9106" },
                { "en-GB", "e95ecc513ba36ee45eb09fbb7f1b574e09746a20f821f85b309786b706169253dd6fd0aafa8046a86019eb0fe75d0d07b26eb86e0cb80c170c0ace391025db82" },
                { "en-US", "114b4c1407fb03803c1b098196a445958131ffa2747a34f4fd1e450ed87d35abbecce160876a20e3c2f1432ba8539226c14750f6f2e31baf9ce9473be8729ca4" },
                { "eo", "148d8f03b0a0d73b238d87f6ea7a90b32ed99365c59e70a0a2457be1efa1936bc7c9c693ac1382471a94b94ac4997566f500bf94123712f396b761a8508035e1" },
                { "es-AR", "f5e3e3de738db23d0c5d177bb946c68ba262c1365634d0655132767bfe6a8023cb7a73d09835b717abdfbe90b71165be32ace3fc866da59cc4b7d2c396c2fdb6" },
                { "es-CL", "54b9f7985b435088d7a148581abf1640da4421eb4628b6008bbb24e3e63fe173d16f3eb786ee25535fda89ad7e578980db0c951c382b30fa07597a991f49b03d" },
                { "es-ES", "670569a8e824039f2fcaf25eacd30ff0cea25eaeae86d65200dd416242a94a028e68d3db1a6071d7dd6b546ad60c738ca576391c577dcec71f067313ebbb444d" },
                { "es-MX", "9cd9358bac093b293b9b4dfba541a1437e70078d51e19b3751b88b0fad779157858afd829f098852bc6f88a31a23053c70bcf5eb075d37632257dde02e93ed25" },
                { "et", "2bfe3f2a35bda977d70b65350ff922583549970558ea13ef7baf9a521ec936554bb9103b6a9fb94d05b1ba746ed2a890fa341f1266c44315b26160e382df5dd2" },
                { "eu", "fc3f077e03e048066b65aef8a86da3508a6e29f708119d8aa42ec71c2ec30eeefc81379394567c10af5cdc693c2dde7791a84164d1d5af6ba83123c3eeb2d51d" },
                { "fa", "5e7063af6a1c5772e3a4c21a6454a1a42cfd627627200ae47efff6a74d9f61aaef49ae6a70e7002d1f144b4eacffead88356215605fbb557fbb464e8207310df" },
                { "ff", "d930efb9421a73bc61536cd8b5d6ea9ddc4b35acb928a089c0c87952d92fcb2d1dbb0140d77355ea3dec99a1edcec0a5b35acf48eea756717e2805449e91c412" },
                { "fi", "4e65618760ea66428f32128394a9fadea0a1f655ebd98f28ad977cbe198f6dbe9e976a015bd4299130d96501e6f3b271f3c61d361d6dcf4d07bef25d912df1c3" },
                { "fr", "1995f8192ac72168f69e40f88f5b5be68cbc4068c423bcb8e0902f8357b769f86165a816b7b193daefb7febbfbfa6acaf296048523b6cfd8d6595dfd2edadd4d" },
                { "fur", "2b44f213e80a83858791eb0a66976ba1bf3e1d03355f5b4f0613fa1edd7f5766f265b519a20def1140b22c9930d0b45d48b35a353a785ee6ee6bfbcb5cea1e95" },
                { "fy-NL", "38ecbe118018b2700187295ac588218cc3002f87c6b1e2d80ffddf283764d72c35d04cb9a2b9d0a255e0abf63df7a0dc41fe2e34895a662b83a58fc146a99993" },
                { "ga-IE", "59faaeb05d3939cfb2e9a9908fdb4e9d9a5e5d153a9cd85ce47afcfb1c3e404b66e53795de2ba84dae3f60629f0ba7d6226137e9c78f559422c6689be67ddac6" },
                { "gd", "6a17127727bde9279915b907285df165a090fb3328090a0860f2ba003ac391dce663ca2588d0dac2dff237a22d23e78f8376b9fb0c08390cc33b7b1c1302aac5" },
                { "gl", "f7a7e080b21b3f2daf7af1b39a64534d93888cb39182d719e8237818998813152b53d0c0ec04c7fd9d84c5996a56f5cdc1ce8f72cbfb0fd06cac333a58061e87" },
                { "gn", "f2f329606f166493b6cf6842ba54aa656c65afd270f59a33d0ea009877d302c7aa6e7f88d4c9c10fd3b0092fd101e6c788dab408d5e8bd6549f65458b3fe5fa5" },
                { "gu-IN", "5f7ecf5ecda16fff6867924a9fc5b80f7082983dab5fc6afaa8d14b9ebb0153b12d25f546095ace70bdab0a247c6d06852595513cd3326f68e680e6672ba309c" },
                { "he", "3442a806b95aaae24f155c83820e1bbed0e634dd67112bd2cc3f7575dce1663d2ebdcbe5e0593832bd64c60eb365f4dc99e449cd7060cb86869fb964bb481ed4" },
                { "hi-IN", "0bb0861b80e8feb63dcaa9503660db27ae9309f92e9824cc0d72d0da97c093640277ce898bfd90a173a460657314c40b2bcbb3c9a63c4f3afd14abe97c86220d" },
                { "hr", "609a98f4bb721c8f83003dff9fb5c508f1653102213fc063287198b4d25ecfa8e947a50f9da31b289941f157c7bf4ec1cc6c6df47c19996dc1fe464da48f1665" },
                { "hsb", "c559d9d60d617b32321efebd3990322f67d3aad95256f14e20b53f6adfcd35ab89b874281ad1554dd38fdb3e141096f2bcf229bdb1d37432b08ffede502ddc2c" },
                { "hu", "668e1ad9f77f81f55bec5a6426957fff441d91e2743e095da1522fc7cb275f104f05de5e5d2f41814fa597e0dc658e272a2b70caa2f6dd170b72966e5f0d3892" },
                { "hy-AM", "bf74c9605778a31f66280de6040c32bb1abf1a218dc0f8a1b60018b00c88e61000884aaa6bebf388d6afe78086a508ed74fc583302a8ada4b9854239895f2a01" },
                { "ia", "5aa84d9eb44bc9ecd1787c1f182c503b518d148cc2978dec53a04a965b416ecfcae4325b484b3aba9179010518174194d8d753b8b63889f09903d5da68dac611" },
                { "id", "124b73ab832a3de937c57097fbd5287fa4236fbfada4c568c602e027f351fb8ab15c040c5c5265172a9556ef6a210185d1e8d2d245f00c1212253df52a281726" },
                { "is", "3e0cc9f86cbdf6abfcda6eea2fd424607fe7a5cf581fe26489db3bf255676acc72da19b9f2469e0af69b7fc1487acda6b9536b6b30a67e32789598a107a171ac" },
                { "it", "cb33f321e89190c0b2b53c5c6439781b133ec578c93dbd97aebe2fca713970e01ffb699b1f55419968871584aec2d4a7ffb48eb8b85acd5f2acf876dfe60b9df" },
                { "ja", "c7a676c6639884c9c7c8dcf7143ba87f2b1aba0d3059be926150f5dc26ccc01afe75fc52c715efb4ee5aac8678d75ff38e0428d08790d7c694a18127122bd105" },
                { "ka", "05b7b8e9c024cc64546178509ba8e6758ece6c4a69ab61fc91327099909645bc18a99c701c32d9a7df8be196969fc5ad83c04264ccf4477d713685505eb7780c" },
                { "kab", "1731da50cf26f088a69e52e1ed46c393925e3dbd34f50fb766734cc6e34709719c621e44f414c0f19e3cd72046724051aecb35581e07fe160f45b51c58da703a" },
                { "kk", "875f67a05e582ba09a7e7a7edaadc58010899e90d2823082134c4f2b465505c13a2d6de4d8e8e353d3e92097147e62adda9dd3c637e6cd5d07404aa4c700711e" },
                { "km", "05804be476a4661ce1212f2aa3af188820245e18c515b56632197bc39b7b396a664208b65472b144d95be65e3a2dd6fe098cc18681dd711706cb2a77ed50b69c" },
                { "kn", "fdca9d9ff0115f898cc502ef0c747d2b035da25e7f6476b24c2c5176477964fbfa4209e1c1ca0294394ab22c4a7b247fa73c6e2b2e10efc8e7ab484a072423c7" },
                { "ko", "6e7f9bd969ff3b69a7b6e32f3ff82cc9303b633be393bf219de5bbcb6d62027d6b8f5d34b6e7b98955a47a191a1742f516e86d0e2dc39ec2c7823fa40c0691d3" },
                { "lij", "f924462ed2f50759b6ccb373c6874ad464442117f371856fb1733c79d65b8ec8619e9c2dce4a14a902a5420d81ab8b61ecae3e72171a778a2580052a8f025832" },
                { "lt", "d570b50e95b01b333c1ee6a0b15859f65724ad39831b8fe7870bd3ec6f72b622fa3d778743e45619b6fcd9cc7a8717d7648c344822a24a48214c07b94c55d83d" },
                { "lv", "3b035dd811983ff125b3002aed8c27cfccf929eabc21bd534377465cd19fa7814b31a062990b228d4aa508f5dc787312e27b63b6c51d2ec584a57717e2333257" },
                { "mk", "30457e805c323c70230b39f9152c1e1ca808f5cab994bb45fad1d73794e65e844ad5ad4fda5084af79b688e7a8ae8c2184a505500530636b7aba11857cb2e2dc" },
                { "mr", "1bb2fb5e9dfce4673daafbd124f3c2f5a065e785317aad4221b7b3ce319165ce31b34972944248d4b08ac4c4039b78f2f6eea564f92c2c0b713a0317602ae4fd" },
                { "ms", "e3a471d93373b228d5dda2c1a09ff35ef88d3005770fceb8432dc65887143759cf3c59d26fa14ac37774526add55ff23189b405f83dd3438b81a8d06800fc63f" },
                { "my", "fd325b4b7c67c8bbd38062f778d70a80068ac1b6cc3b1d6858baf4b20e9edcc466f9aecfbf89cc106edea5c48142634935dc04a9c7a77b0e5d921ab62ed89077" },
                { "nb-NO", "f82bfc4e1dc6df589c4b575f3b6a3b1136906639d3ea094944fb62010fe72ee530d9e48ab006e685defed894eeb1dcf8af98a0fc4714b279ce360006233e2265" },
                { "ne-NP", "1b400eb4a5fc7bf6752745b470ec4b48684f8b440ffadd2d9984e1414b6d2738eb2d98ba29e15e07ea3a5b14df99f907c1adefca3f62f5bc09cdf8d7be635ba7" },
                { "nl", "ebf4a0b602bf34e883f1b64ad3142f756017bf5572a1d28b78912f57d65195ace085467219253131799445d2a89d5f837b7cc190d7470e6d93d562561a931e6c" },
                { "nn-NO", "9c1830dd3171df6b0d7c0373bfd81143be64f9cc601e3af381d15928a51d0c2799d48a16213fe61091cf8d5d211fcaa9b572a718bb8cb5a97529bfcc5b56324d" },
                { "oc", "2cc95f756ddd37194d2e8ffc5c62ece19fb6b1369250370a09e3e68a19f0fc52f0819f3ac647eff4181688704d2001ba10c3242ec9bdddf71e4e7656e768eaa8" },
                { "pa-IN", "ade493025752b81d9cd57550c4e624c0787a841f16c45ffc31e6c3d00b834ccaae2210779b4ffcdb6b7c844201ef35c9cb5ac600c9b092e2aec52e89ea23dbc6" },
                { "pl", "4e7e91e3a9de04ca31fa3cd14ff8a646ee8b8d81886d2927fe1dd8b23965d235ef59a9be4f2cd72516cb67aafcc183836a6c7d63ccb52291e31e53c10c07d629" },
                { "pt-BR", "dcb92b41efabf0ab2defb3126e917dc85733c991a3cc7a13f67a27581ad7078718fca9fed9f950cc60f167209818f8ec1f6ff17d54ad558597e0e51b1dfc054d" },
                { "pt-PT", "4fa0b48ea28b7d442b3a6bb08cca811fbdade8a91b42008c9d55ae40f139204f73bb4f25edfd6ea8822405bbc642083910cb28d63415e07f865faf9b4daf6390" },
                { "rm", "53482fff0d7d7e81f2e5b3af92add71b29b14c3804628f8d8079c7dc4dc6090f56fe459dc26aec304de964da0c59f22b73b5d9dcde990186289c73b64a1b6815" },
                { "ro", "1d06f1c3ea2cfe80e39ee423a77fe1917b3f8be20358a1cc3c8c4ebc17f803db21e2f1ad5b3741979ad15d20f3c82c366a7962381aa5792e31051c2078024c24" },
                { "ru", "87045ba9057ba37493fce12f5baf319cb003acc177d796a7ae7faa31d39341e5b8f5cdeefb288f969bd99b1c8b90e801edd168cbcbe48634eba591afa6848397" },
                { "sat", "52314f9be70c25ee57f9f429f930e74a4fa91b6a0b6a11389d60b9c47a5b6ef9988b345c233e66439a99cbcf408121d2365b29aafd5adc94012adda97f18e7c9" },
                { "sc", "acd6f8ba60ab2a7e6178b44f8e394f4abb062f88ad26e5ab8a88787bbc02f0b3214c30f9744dc65adb0b6ec19a1dbff450ebf28d7c8afc930487accb75958bac" },
                { "sco", "5fc9bc2e7807fc937c7bcb8d6ce8818ac413ddb9aeea5e2da3c39bc462f36f826632df111aa557c8db25c57773937b9ce0beae9286f58c3670a4e18b6b605715" },
                { "si", "a8da7f00eca8b12cd272b3150271c570c457f11b9aff0513f17538109de8f5a299362e6d1cba894bc1e50ac02464c851f1858ccb1a29b3597d8c18f5a6e25289" },
                { "sk", "48804137b60881af4a193243833cb6d7a2026363bce07699976d237618fd0b5ca444eaae388a52a4ccd06f43153095451c0d149f7453abe70bd5d05629a61bcb" },
                { "skr", "86424e6f0e54b354d7996f840bcc1ca66e4c1e8fa4a225853bda3ba9ef8408da79db5c125ec54954c89669316648b40ab3a362cea88f65712394ab4a5e7b94d4" },
                { "sl", "80a983aec6b47356de315a7e05980b9e1f5a4106755b5ff227c22c6e6f3a0654c8e6c6e1c7225d47787bccb52c93786349449496bf7adf77a748e8389de8a8c0" },
                { "son", "0a6e3a30b77121dc769396fca39a4ba9e40bd6fa6e14cfd0992853213f52e2f9d18848ebd99f4c28a6d0e8e2443d8495088d6e2b0f90d51e10927e922e8a39a0" },
                { "sq", "f3bf535f8717e7beb65bf24f2fc033566d8aa4b44814f3c9760ca27f92e9f93ac1bd7fdac717fd1b9b63f75c1613c1a78f6a9299d9c5143eb2d0949f01cbe6d7" },
                { "sr", "8b44b0a1f0af2078d4eef784faacec52d7877ee4e459a38a4191946e705c6f6b00a6a3bdf987af55f2b05f3ac163cbc97e0edc6874d91afbd484d05588dc6afc" },
                { "sv-SE", "52194c6a4019b4938cbebaaf17c32641bd49bd39dc1b60e5238c363d2653b35a5c0adbf6733c64f498d5b4b16d0a509cf510ad47e1f22d84d72f13789d205e3b" },
                { "szl", "3196f30a7d33f34335e6ef23b5461a25046014103bbaf8acc8e90615811a7fcc1e23c7805c7ca742be31332c89a06c1968010648c72ffbcfe9b89b9c111a8905" },
                { "ta", "d5708cde9df833cbdbe59e4c3a1ee3fd768adfbfdab80725013ceedbb37dd90e5522c5268acef613ad944b00a1768b385bd45bb0d9a5d630c77139599f576e7c" },
                { "te", "c9b433aed0cd6609242852ca8d921566b4b381334602ac87b0300c5d961284c0d8409d62bf1c0bc7973d41cbfd855d901fe07c0979f85048d94b83231f12704d" },
                { "tg", "4f8fceafff7f56fb7199c7c8c3ea67682a86155940188fecf2098582e4e8abcc2bf259e14e2c1a8aa4842a8c452b3636147380ec9312752b7e4fb82e31e79e05" },
                { "th", "844336def2e18fb9c40f9c8785eba9b443b97c6e168415ad11151f0354dcd3251832676986bdd2053d201d3ab04a6a110cee13aeaf1e1ae77021b9c88e3062fc" },
                { "tl", "d162fa2412cc57a7a90e7ff707f702385080ed9f377ef5af91812894611af4c9d4a680b5ac8c1ddf43e91a23833e349ddfcd9e72f3aea43328eceb88cc2a8799" },
                { "tr", "ef5f6f0230d7320b2984600bd69a8036837ea1e452ddcc6cf512649d034809067ec8577e83bb2b1edaa5ef73306cd106f572760f1f177066531f7f73a6e9f4f4" },
                { "trs", "5fde79e5e9d841978e50c1ccadac7aa9b2cebd8018bcec744f61766f37c1eee72cad340e056289081b08f8e80954d9f770555d7be6cdce90e7150dae705be076" },
                { "uk", "080e1cd2a28015f7643d2b2152954d1604e60ed207cb3430d8f3b85aefca09f651902f05fe5bbdb2daf49fb420fe6f0fd827e8205d56364412a430b21df0d8c7" },
                { "ur", "a9a90d88b12bd2d05dfde661a0fe34f9725f5ce4faf80284dde1c0195d4accc02d35bf6684c91c8a15e5447223752c277058357689664b1451ea2ff4ebfc9586" },
                { "uz", "c7afafe6c7aa7bbca01bcb6d14e202f1ee9987bad777a5e4f8668e30cf2c8ed74bbf825b3108291908ef487adcdd64f54090614f5684fb4f1ccc3830f0951436" },
                { "vi", "cc1450288c84721d48db9cded3016507f14ad014da72585706f0f5a71df260bdd571b69ff1d4f86d061c6d28220bb2142eeae48616b3d7edc09a76df78070aa3" },
                { "xh", "fe77633650db83120bb073290625755a1a9bacd63de83beae86e674323404ff6b05016fa80df86e6176c72fda1f68c51883e6f770e26d81ed2a2f194b208fa47" },
                { "zh-CN", "580ec9ef47721dd78c30bd0b035b6825ebd647e8c1c9fb678bc09f5be41cdcbdaf79d5f490717dff510d8b3cf7cfb6b6da2b2f5afd0a9275f8bcb037bcd888fe" },
                { "zh-TW", "381735cbb9ce66bb9e8d9830f27bf3bdcd9253ed5d02c1a6a15618e16a3306855c299261d8948014d53f3ea1a29fb5c2759f6a22856c582bd725e0f1d58b5bc1" }
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
