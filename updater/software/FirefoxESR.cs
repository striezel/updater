/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "7e3f15f8309007337283046566d2b1e4a49b5ad54cf68405438bf14dfb641960522ecab66672bec11855c705d9d7b7d024222e88b7acf218f264cfa5113d254d" },
                { "af", "b9c9a0dc0296218e89c5a71f960671fee4cbeee46288ce3b6e7f228b8f9db03edd74c26d15b606b6d86806b0571ae711200851762aafbcb4a3d38202aa6a78c5" },
                { "an", "3630083f6c786a668266fd70c1f5bad506d59477f54cf47c7bd37cbdb3c868e35772f0da76f540c42ef4ab98e9ed3c704eb8300ab1648d370c068641aa8e9d02" },
                { "ar", "b58bdc8ded6f0aabab16496db06a5c18ed35466ce7439dbe0a9b128ba24bf331b1ede5a4911a8c3f35140f9f7e35596f06dca8568c3c9c6fe1d9b10e26ea1083" },
                { "ast", "6dbc476f110e72b89caf5498fa6f964905ab585316321c4938490f9c99ea2e7899bc406f129d3feae713fbed47f383cf88015efb9c15f9b539fd1db78e4c9f65" },
                { "az", "93f69d32f603e36b2ca5449bdb541cc8663c3862d207c530446918fc8bb5ccb10f784973957ca2fcda58d47470af920d5b54d2a02fab3f496a6388c089ad9cc5" },
                { "be", "c7d8550581bc6b56d363879871fdec64cea2aa8d82c27b202352d9940c3852172d2c3dfde1fdfe7db584c4d00e0170fc86a06b56bbe3cf04047dae7cdc4d2933" },
                { "bg", "c9a02d9c2d6fb5ffa44298fb990a6c2062ec8c528aee823f2a559cb3bc6b975dc95993f4f6d91493557bac123248369fb4b5bfed309c8585d17bebb4ab870c08" },
                { "bn", "7ac99a24fb20d5b5dba4fc80e319715121d2093218edeba4c9e15cb18e61d7f7dce253695979f92285001105af34d881039654629b12d2c354f8d414a08e216a" },
                { "br", "8942c95c04d5e2dfaec8a7c69ec6f2bb625d754b6bb9757fb7f7c47545977fe381165a4dd2b932dc5d3f36314fd1811975e95a1abbec431bda01094aff7bb125" },
                { "bs", "4a637b1f10e22e18337a5048a39993205d817464ed21d4721dbd6071985f45d58d2895bea73991ab34fc3915d0aa1a56f62bed227a62a71b3da54a047ae64982" },
                { "ca", "754e5d5b63b05244d348942b55fda5d37e87022a6f935ef8a754ca2808351e8ac1960892b9076de5a72cd4850a255b2d0887d7ba7bbba5ddd18ac5e977ea3df3" },
                { "cak", "1ea0618844c765918b4ea0285f639526295271f86670259f51532203d36c77d989c3210b623cb54d0c48c303ffd1b66de43acd8b876d58e813b5ec695aa6defc" },
                { "cs", "ced5f21d2f9b2c2edcb8ce61df979ea28832df7630bb83be481c762f6cbb96b4e179b5dd05e75614dac665e3023504580d7cd1d9672bd5ca0738431095dcfbd9" },
                { "cy", "b869d4f5aef3c569b5179acb8d68371a2ed7096a7b7a8fe07591ec7030cb3f7acab73f2d999c06f2512a34496d0df33e8c2545c9955499614705c7c1c289f49a" },
                { "da", "aa253eda47243615cae71ceba2e27169b849437a6d4c4743df6bb3f25aa685c7eae345135bcf9ca409e684d590921e55f9a8058070020ae0d0db09b7b55ee261" },
                { "de", "2518201ad57d7af1dbf36f88bdacd12a0f8c052c7636c55056ee86086fb0db5ad61bffc79199ea392209e407023a72bccb6e1c7162b600e05f881a20f87220e7" },
                { "dsb", "00856b0086a8b2ffed54cc6de6ab13fb8f05f35a9c83e7aa7daa063e7262b3e5d202374ef97dcd2cd9ed1ffb788d66d6352e8bf6274e1c242feabd3bd6a2588a" },
                { "el", "8d02e43077ca2526dad639ea2b5dd32f6e7147cdddd2fda82b877f07456d3e54f2f5bbc7ae2b1c4dcd1971d5558eb21dbc9e3392c07656d5d52b1f43ca366188" },
                { "en-CA", "c45ea0ad4db32d4f80f70aed40c4f07d96ce33a794daeda78dc1bb3f8b0748bfc263d5cdcae5a166f9a479d19495e8a14a53ca8a636395e8fdda4aebc15ebf2e" },
                { "en-GB", "379e45e8cc766df524a942002c0299ade24a71eba90d3a2a3a74db734f93bf8c968fcd18febc9d61fb784837b9967fae3bd76f7c79795001c242d5d70567a94b" },
                { "en-US", "7f946bea49198996ee34f49a6b2b6bc49a14564b5c58d4a6b9d4571476308481f1ab4fa6a6ca74ffdb1ad1423676775c162ec2f856dd517a518c67799a2491a6" },
                { "eo", "e1aca71598fb678cefba971e564951a0e2641b296ee64df5149c7b6ffeb5615888a81619fdafc934fe45aa88fa8d02f163fbcf771a47d83cef5282889be5dec9" },
                { "es-AR", "25a256d5137c94f467902e025c0a123adbd563312b7c9d3c760b699bcf2e9dfbd6f09fdcc58e2679e982e2e954af36cfb32a3db701a43b8eb1e38d345269ff16" },
                { "es-CL", "47e38aac8cc3e2fb16ebf74f3bc18b224b2dfe04259374b39e0e4d79d27b9fc25b259ab47f10f802e9dc823aa4d32f86c165af6b261618b6203022a3fccd3f02" },
                { "es-ES", "a5faabc6b11970715112d4c84927a857adf95247433b4d1fe4e1b1fede3d1c128374ce66d760821eb6c53f8260af92fbcc7aec7be97be9c7406050a68049b739" },
                { "es-MX", "018e8ef65c920a4c6c85565dad5efb97a9e6e80ced30b30d266b9ed17a8a621ce606339763a94fb0f5d0919342377878c5ae2be3a9127b9ac86afbe7c8767d70" },
                { "et", "21a1f282ade1ac95d82de639e4ad3cfcf6d83cd38dc70e448e2836b8674b29478abb2384c5711c8c551f7df9758b66dff775b369b02252f9f24fa6e382397728" },
                { "eu", "4afc12fd744fe9cd1d33a79b1afa480eadd30c72bdd122edf4539e792ca4af2d0331722999adb922712e907e85c9f560a31db4d57dbdc21907dcb2ff048c753e" },
                { "fa", "d8223a7d91d0465dba11238a3a5e7d3f4455eb5c7e7a7c06a940c65d454e07985f037c654b296935c494234bb8ced85cba34a0a4920bc46fa187baf94c479f6f" },
                { "ff", "fe0b2b41c0a318a4c8675f88c172db411c3f82a631973939ccccc6d9f4163cc76de696cf53640ba0e6a3520720f7c487cb01d681589720060d674b830ce7a056" },
                { "fi", "1afdf499f19f45de62748bcee099c79503e91b9dea36ca4225fa5556e619d293c612353985fbd051c0c82fbee2031426c993c7e7fb65ff03247ce834b4fc722c" },
                { "fr", "aba8ed276df23e5915db037a2126c4aab9fbc14ad16b708f2517416d8bea99c5ceab98499805188e1af92cb94f9dc22c0c8797984fb0990cc75f7dcb1589cdf8" },
                { "fur", "5a670050d68456db13088af951a751a1047663dfa95e7b4fa63e19e8ec0fb31ab16a2df813e00cc8c7e9c1c9cfa0077bc0e877746c7c9609d5a1ed18b741ddc0" },
                { "fy-NL", "62248f61802a8eb7334d2ded26eb1de77be446257cef801cf3526334a866764dce1c238fff2df034989adaaffea020ff06c7114f48553a73d3ac000c8ccdaf28" },
                { "ga-IE", "dc1567a33970943742c3a8002d4030ba3fa50ff1fea1e5587d398f7fec64415a2728233372631e3bb1ba0746c32ee94f91cb199a3d0fb5df349d417849afcf25" },
                { "gd", "3438018fca06293455c1a4f480ea8699a41efcd524122d35a825112dff8d173c7ac4b40759679d728573e16d088d11640c96c505a3c02d483452efcfa755762e" },
                { "gl", "b967ad46c3cdc866f275dd4bbcc23022cfc993a82833f9a79b17c23afa22dfe14f191293112d07d432c372b71dd0841a39f35e2dbcb5659f0f0977dc5d881e7c" },
                { "gn", "664731c8fe20fca42f0748bcc73f0d98c9a266fb24e55d5a6b2f603ffec9c595dfbb398a74226b226661af7c563e6fd2eec7ea0a737f7b60711fd73d959d763d" },
                { "gu-IN", "3a0a14f8686ad7a496fe657df8af4b9ca0084923a70a9396ad76fd5a67920166d566597be256e1ca03415f31b78c616662749588ca8cc9bf151879c6996096d5" },
                { "he", "e506bcba987bcb0776327549bd2cf6a833b023ccf378abc10b654490ba8ee17f32ae2026d05dddfec24363f3d8bd0aece6371ae21592bce7137e5f738f559c6c" },
                { "hi-IN", "f399ee521692e61176c918d182d03304e99fc3a752e0ac031cd90ccddd9ea8168acc3cf30a118184ca5d7da08b35be853772081f61400a0e1800fc70fd34ab18" },
                { "hr", "b3d0ff6d28c11a90d301a8b14688825834f2f0b24e62015323fa8e029dbeab1590ae346014a1f94d888cd5e14462e8a232fe03251d0210eddf2075e19feecce1" },
                { "hsb", "84da2c1992db01b78da392c5e18bd7de5edf21cd6ed53609741b33bf3393a7545b5da831b40359cdb4d8da33afdb3695577d887540efd79ef616bedb4a347c0f" },
                { "hu", "7fb86c27dcdcf7db5289ca22f35fcbb1ac33014339f5bce8d35b149fedbda07d2d81203d406e7f8f382b06e43699c451cdd2ef0d21a4560713d5e3c0d844bf53" },
                { "hy-AM", "2d1518e503e955e0652e0b4d49e6e31be016a601efc0e6df7f4554b538926d26971eec73823981664673db0d8665956d2741343441fd72a83ad9878dde119634" },
                { "ia", "870bbd0898057386504a9a3ecc68c91543e310d44a2d6917dfb04e95fed81624ca93f33cc0a1769844c7abcc23dbe20e83b5c1cfff7620caade2b67dd136aa1b" },
                { "id", "7249de761344fc625ed044af688a88de94f5a0db5a5afab84d23b81c5bf873f27b189c2aa38d6676fbaa975d3f3d36d801b4b5dd98005a0dd953b1dfc50be62e" },
                { "is", "42db4835cce613b4db3f89ee04990a2659bf716b7ec9ced9d5e8375d77552d4a3cb9a485e209767b4a6b9e08193ee98ed9197232005a692bb3701162e3fe7542" },
                { "it", "e2faab1d0c52cadb88310a3d0a0a775497fdd871cf19f28fd510c24b178abfcb65cbdce0cd14b257bc1b6b42fcd13ed719b2b80d2af195ed25e70e37439a6e24" },
                { "ja", "ea860d4c8992b75aa101d70a39e7d3693491ea4987c49944f5d74580fe1674dfff47612454a9ac51877e97e6b15c90741a0037d9d97f089d62a9822adcaa17d8" },
                { "ka", "d25a866bb6280aa9f0953699e62b191fc800a9c758629df332bb18e2acf7622d2f368ce81feddfa979a2af532b39e49a9453e04b5418a4b6ed6bf5b3d8d5905c" },
                { "kab", "5212eeb3cf1d7fcdd97fdd901d709f7ec8354ea8cd6418b204ba61e04f2db7ccbc8bbdb3af61dd8fd9f4a11dc168dde3f30b3f57d2cb51fc5951aa34777c5a57" },
                { "kk", "8d6cc504b0d69a66f0c852f765971ffed41cf7da4d5ad82fedabfc902b153c1bfcbb3088f55ba9a14afa17728643fa14bbc2b06d60ab1b4ba147b3215a92e43b" },
                { "km", "fa3a5fd723891a26775198fd04aede8e27dedc65e3d9c1fb40ce71aa02be17c121cfe7bf3a3fe4269ffb3323d04df9d6dda9a157f39ea29ce892645d94460803" },
                { "kn", "92fc6a3537a4689a46fd04bb0731652d7c2ec9d2a7a5a2c5c86de0160b52c02cafad24ffb98bba1e9cc6790e2f4d09193850c5ef4cc3f97d68f018d494df32ab" },
                { "ko", "ed5ce9776b3c52b51515200f28b9a83d2d12f3d24574e5c19b1b9c1301b08d392293b831e5cf3200347e4bd69585519653b0d7ed0ecba2fa7891723c17b578b5" },
                { "lij", "dcc1bb1e19a98107595fe5b4fbd5cf92e6288392e20c8744a5f0c4f963cc9408e45beb72134dcfe79abfa7f68139bd432f929b391b1c64b316323e000e9a0b2a" },
                { "lt", "56f38e8d90eff37ed63dd7a75006bda216b8afb80c8ddfc47020574d842b320c28eddf8d8480ec2222d1dbc9e168cba2d20ced79a7e5a1e3d2f4ad15fb37461b" },
                { "lv", "8fa23ec1f800a14966c4614a0669094847e007fc06c1caab8712e09d090f4eeeb797c8905c61e90ad29650c10b0320857f3918876ce2773a2b57ca5b386db863" },
                { "mk", "f7b002b935db4652245cba98d7b82c2229a386b6f8998a6f6dd74ba3f8e2710069698db0c7777951e4abc17ed6f95e01b7bfbce0ae40114d3dec32d883d96669" },
                { "mr", "703300e98c90cea9650a01cf9e0001b25a27e1f262cf3af0406a67473df83ae2eff27dc20189868dbe7b0d491e514372ccf087c6245c122b9b80ffbd78d76aef" },
                { "ms", "0eec9e48229d9d8f8450aedda3290d1ac36f3f81ea006f33178d06aa3e5d0a17e67e769f651d8ac0d6e67b8bc47d3933d6753e8a30837c6fbb03e2295cff08e9" },
                { "my", "a1d832277ec33bcc284b72cb44863f4d60bce87996f75f3f003417bc0da3c8d03ec07a8e07ddbfc5d2ab6feb0a45aef13ddda6c8f29aa8bae929abba7f5df54b" },
                { "nb-NO", "62b6d549dc05ef6d5e35687ee747df94b6d8669c1f1d54123db9c1c9747b923f58ff58ea6aa30bce7cdf9e5f2bf438c114709d675de5536ba14d659df64fdc3e" },
                { "ne-NP", "ea8131ef2df7dd7b5a2f34bfaa721b357767cd5caa680fe028c19e9de4158206345eea4fd7f1884a1f61708e124fa918eb8f990e616d59f322e751e0d57260cf" },
                { "nl", "cebe9a77f0d4167b1761375742e2dc3853fdd29cb035e2ee07fa256f5e1c43897c37e3f21b9526d9c30011ae4eb9bf7ea41b582508fcf74937629d4baf96a46f" },
                { "nn-NO", "3e89f55bec9913399346aafb1f168cd951189d75dfdc2accd6cdbaff6680138df3025fa85004337c34253f28640c4b1186c639e956542ad84d092b864e3698e1" },
                { "oc", "77f34265eb2781b1eaaf3d773251897f8b7adbaf9ee4744dcd7e9bd9886abd1ee37b529fe2d21198ce491f43039c30b8e1628dfb2f211a4b18d2b0526de5fd3e" },
                { "pa-IN", "c0bd2f7c644967e16efe0e3629c3706dcd4650ad1d3d500f93d021acd64147826600061babe8f81c99fe89c9584b4a020195f297594d836e6b16981c55cf513f" },
                { "pl", "21591e5bf2235c2ec7685165f87482413b72b5e596ac303a4dc63bc9c2ad1d99a9a931448056305135efb36e50e3e95c7664dc487f05a49329274cb459c5a764" },
                { "pt-BR", "02d61fb9785ee3e69d7c29cb094baecafce2ae8229f2be54336a9eab6a628944e4565943f62963b031eed0e56a828af9942a6c5e405ef1ab8273ebbf2ce27a18" },
                { "pt-PT", "7a251261bef93eebeb252a45e1565f426e3d9cd5e3e746318df71cd036a70217eb055cee28b65234a981895d3d089cb6a2bd3f6827d402266c77ff8b0eeda074" },
                { "rm", "3def4a711aef4a543348a7a19b5f252aeb70a5172501455112977947f28dac18a226970fd804eb79e9da95b2d87c0f4b0465d8bc65336e0f1a80087dffb244ea" },
                { "ro", "a7e62f5402b04d892fa5ab7e81e6993a4d39428f00983000a87c11bf40ae9a71af04a79a323a7047deb0c10acf97b65441acb9abd8e53dda0d627fa4fd5737c9" },
                { "ru", "85f8ee9ebc62bbcd78ab111ca3a021f4a45f8611859726da13d0e6c87d236cab1cfe009f6dca5b6766bd82f76463531d0664fefe6d1e0c3f27396d86f40b5e12" },
                { "sc", "665c837a01089f183d879e6af7e8b9952388ac370878bb6861882ae7cbd3d533745f6f9cd1272dc44c564912d1444d585993184444c949723d185eefb0a9d067" },
                { "sco", "30448b19168f98c7fe65064bd80de33e680f58c392b8b99d00b673042ee5e8ebe94edadce5505e530acac4fb79dabf4d9bf59a199c70e43ead6684317ee01b18" },
                { "si", "c64a726353bc05ee83c0f2e6db5f9912e919e4356318a800540bce511ab6b7497b09bcaa8a37ac19826f233cfb7d59b813d5d8e21c53408b3d8c99ae63153b36" },
                { "sk", "2228bc17c3f68f240b7c1b34fc5d69fca1bd9dee5cf38bc214cb7200833b9e2a28664b762e0c4c1c1ae36a9ed0c0e6bfb4f0c47feea2186b2d4e587256089891" },
                { "sl", "b85743d1ce70ce77a96c15796285a009221a7f93866890a6155819073b2cb3ef1c54c5fbbed5e787ee2c799db60e865a56071f1136edfaeac6db30476e69d83b" },
                { "son", "f6f21e44c0d2999af94cd09995f2209d5d103860e523fc144e9682c0dbca4c479092ec0e977c3c4b4ed089d58f845752488664bebba4fbbd06f7935fff8c0477" },
                { "sq", "30c395c0b38f97dc94280dc9554f422c1773485d9204fd4abc387dcc038d36451e306d0424c67631bf5b751b6e5915fe16f4afba9da19b782a00b4114b1e75e2" },
                { "sr", "69e940735663fd53de1441839b14836cc4bf7ea6421103126134d5883c3b618e1071a256a4c4e5de3d813cb015f5b4541440735a4b8646c14057f3b683146bfa" },
                { "sv-SE", "327d6716b5851800df82b06b85e130cb90bec677391b2958478aae388578992f3c43ff8201abd130b48632a7463c58279b788926540e06765699cc8d223eebb0" },
                { "szl", "0a96b015db3eeca120d5fe646b756482404147f28508fec859e54d45d9d6f58b8e13aaa6dbd536e81c0ad5a1d505bc7add0ed635201d8bb60a3b9326747d9e42" },
                { "ta", "74a58b8765a93bff6a8fea1973e1b60b22c22d4abb06b693a83fa0b612c23821e2bc47279cbc6baa0954350aec1c2f8d93914d9c85f542ed4b21f319b8f3ae76" },
                { "te", "c6aad30738fda7594b7084eeffdc0641a9d25be5f08a3f3261cdffbf21a4f919df8b75a76f771a417cd935650ad26021d29b65767d7392c071ffad520f7974cc" },
                { "tg", "0b81f6c3d41de06f0b28847a681ee0e6a8a23516d01d30a9a187a3cc36189e6e299c62c5ecd1d703d883b7f52d663e6888eec1b252c04bb3a4cc2455806fd212" },
                { "th", "ad5f97c2a0e8f94bc0f85d15fc966c6b7b6a21ba6d163dc3afd09a1fadf9fa7497d55adcff825308919e05b71cc6605920e3082223c7aafe2a219bea460b04be" },
                { "tl", "940d00a80217cb52369a43f024a9736283a5fabdd6c789f8d68dc71e08a407af0ca2e45c37422796b3c10239ba05306d24cb36869743177710a1130cc59c317a" },
                { "tr", "f7d1682751fa5ee2001b4cb4e786d35bc1bd5441fde94cc4e1712052bcdc1c3cbf645ac677c6594c17993a80a79e42f9a611d01b4c4b153600bca2ab4480bd81" },
                { "trs", "db39ee952425b9dbef14190906c6e0997ff23a388866e72e6c7856ec71a47c00f0b82d986abf964ca83baf3878c3f99db174ac7133cf58becb80cb9c4233bcbc" },
                { "uk", "33c35bfad1ca3dad50931ef2562f9cbf7617e0beb0da74d48e47447538cb4c0d258e7c447fb3791bebbc3090e9d62264c240b0acb3e7488c6346ea1b487feeea" },
                { "ur", "f571929e2aeec43ab508bfc1193c4f46051268c3c3d534cba3c0d9a5524c19b0d159aec58ec6dd8310fd3bace3acc9135029c83c654a84a4c17471d8f7e4d2b8" },
                { "uz", "ca086f5a65734cf4dc8a7ea5959571dac92bfe41d328f5aa47a8393d7ccfefe375c75c876e272b1cf86f09d0e669668a1ba4964c4ffe77c138084c3ebb769646" },
                { "vi", "080cccbc5b3ae034deca7fb1ee6694f41f86be8c8dbdb42ffcac2e1ca46b904d74a76148518cd914ecd67e4d00a32c6270a18ef199065524ee1b1cba0448dac8" },
                { "xh", "dbf0f942d41888bf11f5621cff28c6501ae7f23bb0df6b5b26e1f0572edb91eeb802541e2298c61f7f7a12bad625737d336c40d45cf122df24638555c6357523" },
                { "zh-CN", "e1449941e6a9a470b8066d9bd94d067a96878fec611663defa5b27ec13b7939f67a5864459e28c56b63fb7e7c30bc50d76ed95388eb1c234badda6a62877d4f4" },
                { "zh-TW", "c10eabee68049f29f253da7e852db72f6abe3728b2d9184d0b6e1ec3726bfdeda318a23c497d2a10f1c10ccb0d917e5ef463f7004009bdb3f49e1f0d7c18144f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "d1dc91026a2bf15831547ec2abcc0f6826aba158a8cfa77abe9b1f2af736ba36eb67fc512beb50dfef1ae0cb6b18b887617a08002f285470b083319b7d0dfa52" },
                { "af", "1dcddb6b418612384799eb552e33bd3808cf24c87c5a8d7d4680ee80e91ae0349c4ee6da3a9f1460ce25bb087b99c63f7f51921563d6420b95ffc2233489da6b" },
                { "an", "b2a363a82a2284f9e2d355dd410971e7cb9d55406929d3e9706a64dc39457f2b772bcba1a5431b4a3c944c6797e15d8e7f756e160742c6dcd8428b7d0081ad98" },
                { "ar", "4acfcdf9fb1e5f24ad59905192e88d54fa07a030af28cd6a4884a41f346c03dcea867ebdd5fbd808a04fde9169e44934fe75afbde640af56e5820d5b997e788d" },
                { "ast", "2ea3e3a3aa78835b60c44bd720ebf0dd946818b2c7a22683d309c1a4f50ab5c07fabd89d07a47742cf68280968595c572801c7c49500ea10348506d94b9d259a" },
                { "az", "44d886928c603d6addf5730e0ec3451c13199c73c3d6397119aba3981b9e71bb3c71d9fafb4db7d066b64808552bca92ef61af981a55b2bb083ba667d7c03980" },
                { "be", "4f133aafb1fd4eb762814d68ad0b353fd2473c30976eb2dccb833a2b8163058e6881569972d8272a4b6384761c3ea0807459bb286f7b43ed8399c7b902826348" },
                { "bg", "85cd8a49c0dcdf82fcde464d55acec73c41f14b50a3eda03a40b4256e392e46bc2a31fd94f663f9885acda933a54c99f1459de9b6a11e7863a88f4b6773f7352" },
                { "bn", "82fb1e72e3c9279200bcb55ac65f38c81b9caf3bfddc5c1974707fac7e19a920d0dab708d002e9e2a97303cfcd9d786b84f7094aa202c398a3689160b81ecbef" },
                { "br", "1bb7d0842308ecd1df6795daca9a9d5771c67e6a3d3a46651757b3ddd787dac779e93b05793fc1d3eb136a4a549bd27305137def7c74a5bb06105fd8bca75395" },
                { "bs", "ce5c47ae5dc2f9580f0d7186cff41c821184204187deeb8de7f309dc28725b12c072ae32fa859db0aa2533ac7ede1b6614a96e379997bb7e251f20b1068227c6" },
                { "ca", "c3c52b858b66d75306976d0ab19fdf244d0ebc4def201a96b36826b9b750c92b387740b6aac02f476785663a03e077ee738c39c1439bebe7fede32e288b318a2" },
                { "cak", "3daa4567756f8954efe1aafd10e36d0113cd2cb64f3de3088c09419817e8a679ac9dbbc91dad57ca7aba0fb96cefcb4761c6fa6d2a20334f981610ef57f5e656" },
                { "cs", "420a42dbba145ce31fe374aad6b48813a43f94eb9f5a756a3b418cac372bbf17f5a924be9920dd6e99d042e0bfda9231c2b76ccf88fb3855338d7d67f5ae4780" },
                { "cy", "b4fb9a1fb8db6074f34f9441260da427f56fedc54c1411c7990f02dc9bc4344511b35f27d287ee407f96c61bd97a67d95bbfd3d051ddf678717870f2495d280f" },
                { "da", "60928c55570d977989bf2cb0e390eb2f58e7ac5945b2ca22e7faad1e7bc9bf5e94035beea08f62752a427b3b8a62b2726836b11da4e90d7bd1ed7cb4439c48b9" },
                { "de", "f08a8e50bb2b86739cd0e31f3a4897b2f2b65d65bce79c000fc57b5724cf934a75bb76f501d1ab3c5a384d485c1fffca855fae088f87c6a8203bdb98ad67e646" },
                { "dsb", "0cd8a5024b835c00505f4422cdd9738d8ab2d9821e383cbbb9a96668dc2925cad51940375c1110dada6bc31ee8efc3ff5198ec170c568f3b3a3015fbb0d5f55e" },
                { "el", "7140900d339ebb8f60e8af588e46b318535e32e0c8e95e650bff8dd7bf7f6389532ed389c81c91877c2234bf024171499efed68b80c56f344f8e015a47717072" },
                { "en-CA", "141c6ecc12e51612a6c0371de515a29eb763f977cb279d610fd1408cbabc71115133e55370e035c15165e843d4de349325e9254bc226a7c8e32aca6ff420a5f8" },
                { "en-GB", "e46bbc406a7310014f4211669c44dfe202fce4bb3d415466ff28bcc654b06ca35f15de90f8fc13d579e9bc29c4b7c2e9685db4a1b503f0f6e105bf7fcc899b9c" },
                { "en-US", "2f9b8c138d676d740c8a586d48aeb1c5ab8eeb35a5d5a35d72db8d501059b1d6130f3a113b13c051acbd58867a7daa5f2679fd298d8e99ad674086cf0b825bbb" },
                { "eo", "2e6d14f8ee039d82e70eaaa869c427582094a7901d7123d3b4cb6de37fab747718b4e906afd600d6d7d883041dd16421827527ba5956000afb6645da061d35ae" },
                { "es-AR", "e2ecb93d257466c8b66b6a229591d2be717a47931e00fe18f099092ab07d0267125f22d82dd8bfe3f3b1f9a4cbf1c11efeffe4e38f57b64d4e85248a97ead482" },
                { "es-CL", "090406516a9f43b1ed61feddca4bd4864e177d4b242226698c6dcb90e640834eae5c1b8c100b1b87de7e93bad1307dc3b22b957fd58ef7bc4811b8200b9b3d96" },
                { "es-ES", "8a1dd3c4eff2d5f041b3d9eab0cc7ac00f9c57ec03009b521960dd595d4bb972bbc21ebcdf6384444962f80cc808b68a3ae4f2e75a658c6de4e09fd654dac32e" },
                { "es-MX", "6e3e25cbaaf085d6f9e9ce15187088bfcb7599261237763e25f4256156c5ac90bef3040a77ddc7389b52091ccd21eeb195258ece9090a940d163476979ab5ab0" },
                { "et", "f252f01487831459aa054260d5628b57700c68cd59c477d27b4528d459e22971c7200a43d8df5fbfd1f0b7d3467fa8a08c8a63f9ef26f1c933bb0ca341a8f781" },
                { "eu", "3866249a1812c099fbad38c108a6a248192b23160f0ff020b7deea07548e556c02093209fa5dbc6eb2df07e4c3ad35d310760821dbfc1a80ebf1cd7f680dba46" },
                { "fa", "79198b3751c9c1cdd2c9b5171f226ca03edf9f8b250c98f3e6bec151a154d1e07ec13b81e9025e4da82d37dce24d6c9d8bf200ea5d1c0b5d47ce35646a5e1a73" },
                { "ff", "09f2394bd64a82c3caf906dc970d468cdd7126390d7f38e90bf59820e04ed9e10c3c0e78ef026a6131146583beac53947832b499016e23e4a5a08fc755b7171e" },
                { "fi", "1c035da58302271567158f0256f5a7ecb7282f2f5415484e8b2d6fd3db4ae68a35651f16df42bec02a7dd78e9b0ed6065bb7b989a92322e930ce89f13dcd6958" },
                { "fr", "6c2a4208c22841b7af2487e14feaa0988b7ffb2c42aa5c9af5894028bce91b87957d1e8a79ea2e3dd695d6a19467f3a6419c7d9e276e2d85c9a46c30d8f4facd" },
                { "fur", "65ee156db88cbdc88f274a74c4b3e579b905c3e0800f9157c283fe432915ca26446c2d7d5e94f201eb8dbbb11ce027141572dad9c9cfaad7d7ac7d3acbe94d86" },
                { "fy-NL", "e666b0f2d35a22dc1cad488f2ed46edeab31313c11da089be9e491804e352fe215abd152cda4d3427ebc5999d6c11c48650314fdc5278f8b96233403ce13aa97" },
                { "ga-IE", "c7a42ef4dd644db4a3904921cd3c213b071ca27380a3b7ac31ee31ae2373fd94e8c1c2546a1c042d870cf104615a1129c531d6d3f918c84aa655571e2a888bac" },
                { "gd", "677ca8fa5729a811a2683db544b88770d67b5d7bf3ee4f6898e511cba696d63d536977996cec8193931e0b0147e8bd7ef8cb9f6f5265ba1b0cbd905591695c74" },
                { "gl", "1a2201b46db52a9052b466791b44679165e2b481c71859741a644511a66b07b3f3753adc6ae1828a4f54508ddbfd4678ed174bc5c619d8557f48e76c78874a07" },
                { "gn", "364c6628197ee29c03a07c0ab287746cc2db7b59744cbbe76276649f7d2b0a5aa1139dda4384cd060337a345b6b932ca763b4baba58471a19033e0ae27d03fed" },
                { "gu-IN", "eb571752e325fd1b6c4aaffafb1fc4c339d589d4013c3ac9d8ba12c90ba7adc0cd1f620f71178b0d60463a6313ef9702b7049e444612c41c84da1eebfb481328" },
                { "he", "45a2326138331a2f52aabc8d42d6f687fa68cc0e77c9907c35304b796f9ec2d3cfd0a113eed48e79dc99509618fc539533a40b4443c845c22f741b361ccc49fd" },
                { "hi-IN", "44ad79f449fe8c6152206aee1775f5eb8a1ea2c32cf30fb8cde8f27351655e653928701f5ed1499cb71f686f37e61c066e04b2ea3f7fc4908bdd60246e585a70" },
                { "hr", "67478c7eb68ca9d9feafac6fc4ce388cc9831c33ad2272753e3a718e0a47757b10580ff9f9ae1096c0ac7e26bc5a440949d25ee91836ce69fc04afcb745392b6" },
                { "hsb", "91de5916891e436b9076034494331c288f907159073ef2782668b9feb6cf1dc6475a24a889363424f2e289862f57561ac45c95cd070c8e23b5d24615616110ab" },
                { "hu", "226762d16e7962e5023df2e8cd6e19076a5eaa9301bb80ecc1d9004f10a6735c6490bc098d00265cbfee941b187c8ae7fc1e68a6f5bf3484566b29cde87f9a05" },
                { "hy-AM", "88357842534d782f66f586bb3a94e7ee60e96952ff9a55b4d3d6513e75b27ebad8dfb923d3d811e12f80cba62346a6053b13d8f9b00a5b13a8cf6f9299c82257" },
                { "ia", "ad88effbf4d8a6cb777b1d97a67da93c80d0dcc9858b708da7a84701c2138d8bd56e1750c6979f88a65b97f0d0665a6a7040caa395a54af1a4692c2a3b3971ad" },
                { "id", "63f920ce0b9a89d8547c4d6aece69822d7824a227db1f910b33ec6b9a95a9c9783c770a6a37827904f4af83e29d3d9377f4b2d614686169c9d0dcb7c8ee8bef9" },
                { "is", "7ef151951ef565e6e31c5d0d52c113d5fcaa34ad65faeccc7ba36726989cece48a710bb65dae531492036c93d7640dab7e2dfb3dad25ede0efc9db3503d88869" },
                { "it", "b42162aadfa81f207687c4008bcbaa2d4965799aa7386f0203df3d524cd33d0f1a6f16e04f21fe36ef65ab8f81619969919879c5598f10dbb26e7e872b2f9417" },
                { "ja", "65ab6e13ba40b723770dc37de064717f180cfc3b37ee7c7a51d7a77417a09dc96b28b3eaf04b5dc2e11ca6729b78359eebe7dcf68fa91b0361170c5babe1f90b" },
                { "ka", "e0b9b24de1b658533022a5429016dbb0efe98cd848fbddb1cb8a2f2dd54472700a7a5c96437db87d9bc9c2840a56f80c7732d9e8c63ee6303c260d6286f55d14" },
                { "kab", "547ed8d2b9aa95f33afa7b095c49676c1774a4510cb65d5bea23629a6524169ed6cd94d6cddae9c156916d1603df13c62ccb3cc5fbbc8efe625bf15aa0322d5b" },
                { "kk", "ea5eaf6e143b086ea05b20d8228d65eca6855150c802645419846964b82ac05424edc95040e37c8a1461e6af1dd5a47a2d56d3ca8457cbeb03834bccee63a4d0" },
                { "km", "3ccb9c729299a24855c3967ec9a452787a51cfbc62304b993d7a6e5543e3254116158c52b6b07c5ef7c93f916c621ed1b197574ad0b3cadfe1352d3ed6752f8c" },
                { "kn", "0783a49999a8f4c3f6f67e6aca34b07d8d1e51f32f95f834f272218845f88591dd85225f11a1a96e9cf32de3c0c90425daa5fdfe11f0791c14ecd24227961e8e" },
                { "ko", "97d89280580575f7368bf1cd64ad9029537da8f90b40379800a478aa78b608c66ac0e62eeac3375d6dec6711a0b869f7943340bcebf7bb5d89f9c71d62aaa4e1" },
                { "lij", "bc8fb23ddb5bae94087f12c701ef08ea43a9c611f0208511c834d7e196a76c2b5ba5f5d69e335b25f198163c209c0fed82aa3205f69036490d09b767d7bb7c50" },
                { "lt", "8447c4dec37519143ea111cf4dd594f4efb0d50df524fc9663d9f0132f6feb376f92d92891645432d1931fdd0170f462930b46374a8f7a1862ce5e4d01534e49" },
                { "lv", "aeb0217befee489e17ad7c1ce14c78da44b4c47517e78f79d4972fdf4e4cae3b0d47b258ee6dd0ef3bd18baab43f5bbd7ab06384e0e4253453fc6670aca62f99" },
                { "mk", "a1c0203e2c3da993028347a58bb7c1cdf55d071a12c814badc03892e7fc126505dc6e569ebb9de0d0cdee308a08b38a9cdf92efe5c75411d4d22aeb82b046ad1" },
                { "mr", "d9b3857d9914e18d6dee4986a6df681803caf9e506eeb2ec5f22382a20dcd5d6bb2990db9a6ced903dd63db6e21848871afe994d849c449c06a37e30794d0a99" },
                { "ms", "88ee68a53b716aa32357fbd03f4b1a5b05740f501fad11a299fbed10d337834b14becdd14ffa157d1053f2c49dd774fbeab7b0cb1d397d732cca8d1352e84207" },
                { "my", "da3fd94aba39feb9b8e9e8639f44712ede2eabd36357dc4c79367439104631d1e4562b600bcd53774597806d425682167930e36dad2517a1cda7ce477b1bc0ef" },
                { "nb-NO", "c1c12cf503338850652e61d4700d5810f07753defa14b4f90bcc2abdc9c543bd9ff73e9c658f00c806eab0e07f53ddd6a601d8ec8e6afe750c35d3908491ef09" },
                { "ne-NP", "88292766581b2e6dd492fd5f03a7848901e3905e93941240a9ccce21611b7388499e4565f7615ca4b832c53dca05f87ba0dc65a8ff25d9251e2e41b17ae724f1" },
                { "nl", "9d3cc5e270909375e6f7e4c605cce4f37df93733e835b36e96d6a0c9ff93cd086c773ef375d02fc72b3f33f1744c0d2849d2094a1673cae6b68fd80a9d0e657f" },
                { "nn-NO", "885eb4ee4fc298879f1453ca8a83f07e5d210bb9699c72ab04630b8d10ac61ea218d19220d9f611462c7049a8bbc8ab627a695e24ddd5720f8fcf1fe420ea11a" },
                { "oc", "4edea25768ae7af8f660e6780b2b4a2b1d9d258d4e8a4a72932e43ecd041a2245897651ca48059f52b0b8f09fc7332f042c7803797ae39ab4d4a50ca307d0ba1" },
                { "pa-IN", "06851d995a1ba6ce87a68e0b834b1703c403d922da9077bce6d2cb3242759f3c1b40d1a9cabdc069ad4ff25c05c9f2982dfba813383fd3b3085949521f8487b7" },
                { "pl", "fe00411e78969d7d8aec48ce4c0270dd9a64265e21baa2f771eef163d30d2d4c6012c64ef43fb3a3cb225ba01355a378fc2077313b5bfafa6b4a3db211ef9f95" },
                { "pt-BR", "bda3acca0234cba80043393ab27005e8cb270e22f01ad7d8db8f4554b3e5b25c6528e351f03cf4e7988a40fddf850c2d4b5aa471371826104d2f28d60bb232c1" },
                { "pt-PT", "cfd1c68cd753a5ee65ffb2d9f3b7b6dc932c51e82b5e8ca88968b8a3bf7c105a1407f187989ce56f28603993c8819c735b69f227d17d57629e223eb78a5b0a67" },
                { "rm", "be84ff78123b263a80cb10c23fa516bc6d0f9991d0c7f682e56c60e2219fad97606f2e254c1b5fc06096d7a87fc599fd3161839c9837b60c448618bf53ff904e" },
                { "ro", "819a673cef45997fea822fcca4d4bad119a4c48e6a5b5934a3d2f745bd400cf3a14bdb5cb661b7a723f1f21e665da65dea573078a5162605e63779322ce746a3" },
                { "ru", "acbbb9621c243d0a270d6e6520f301bb6c4ef20e8e17e084e848c63b04861ac0da43d9eea1348b46c84bc22daeeacf799186a2d78bb735b1f508b0d4d19281e4" },
                { "sc", "bcceeae7f0fe7bd119eb6ebfac5c83c71b4da2f99c722fad9fa035a618a7eb8d0b0a16dd2339dc7710eab8d8d20a63f52410911410b989cab67906e0c075b8a8" },
                { "sco", "b9700ef63635ae9948664c024bcd92220be37d91a7330117b65915bddb0980d671ea0065587fe715327aa87ef6eec2d9cd1075f0d8d253341ab1002ed7650ffa" },
                { "si", "fb6aaf80bf80114cc81976851b3994585855606983174bfcc2f08a68caad3472e0c6a5155f48acdd4a05bafeac5a70182219b42f6730edddd5f743dccf28b2ba" },
                { "sk", "4d5c1dd87c97b8099e10f99fabf636fe3fcc4145042150712beaf9c28c82038913dfc09c5de5cf4534d4d2ecb4f78b8780ef5429b64472753d36161f5578eaef" },
                { "sl", "04f62cc83a54a93947a6fc3932846a86230098169a1422eaea3b712b1a75a9597d9870719e28eb97de67191fee89700d0b8379adca27c4bb4f8b30752402196d" },
                { "son", "11426b1c1ea6374a7cbb72b251dc676421cf69b396641c33da977b23c121525c53c18fd5e5d2b16d367c893039e83651157e3f64633d14160e1e41106282964c" },
                { "sq", "d3e354b3c91433b36c4854a2949e906f19cc4b72958d6a3c2dbe139db2f32a54024d31db742b6d8179c3cf350055374736415dae0942c97125d257a6cbb23470" },
                { "sr", "1b61ae9fb7d10685b10ce269afcce82047574a55301e461f916561e030dbdbe5a591f0a42325a7b291215855d5849000331507aa0db6350906200f6e74798a06" },
                { "sv-SE", "0530b0bdca52f44d1279df59e1d3c7d12194bec1069d442a8d71c2c4b8d612f1f4db2b4e3ab2c167e3e6d5b7f842f8d869496bbff95e45d475a49a4886d7153d" },
                { "szl", "856d711b608fcf53bd7f8dfd283a12e5aa68b4fd289de5fd92ca1586944ede8ff186c263f39398d1f3b2d74737504390a5638387a4ed3cbc11269634a790f4de" },
                { "ta", "001e351e5145fa2d471ef9128b40860310ea54a09373d4983313c03f97381d29496c094412c970c14998f6cd3e992ae28c62a39d9a4dc9e739442cb395a42b4b" },
                { "te", "ffa458eee9b271bbc0add06278b7acf6c231d1cbacbf102b32e1f9a1e2bed8f93fffa8a4b41e33271cd8f78f9fdc7111542c49082ec39d3bea43b154a9c88d84" },
                { "tg", "15fabd0bafb44bf6deabe042fa1d3ca177b4ba4a3b9430ed9f047aa6f3c36c69571a3ae13656c56c5f684d31a287c0487c23b17097d9843e16f7d2e01b46cf1a" },
                { "th", "011c6f2a2b949554c67cd18015b575d3e871dec53c5209e67a1f4d91ae37561150328b2c40ae2fe6b68ffecdbe60c319a9a2dbc3733777ec1988acf493f24041" },
                { "tl", "0d7b9cdd5ac00dc244b5c522f43c6a20ebabb2ccc04e995fc3e3ae446840fd85a1a40edb7f10eff2231ac97d06e6bbf5041f267cec28b4d98035a5c354811971" },
                { "tr", "bbf64ea3bd26bd4e6e0124ad78ba7a9bea1e1bf2d0cdd3e7ef9d6aac5713a9911fa2b5e1e08ab1b7cd81bf6eb251751b0750fe39d739180a76ee5ba8db2b0a41" },
                { "trs", "97e4a1beb26e299298eafdd83789f48fb27e253b72bc3e504aa6fe0e900c0b9b2f0e8d453894289befedb390da0269aa928a934fc0b4860050269fb4baebd8a8" },
                { "uk", "deea41cf8a29a7b750664d81b1d78dd32145cd6614040ca573e606a9c5599762fd54f447dfcd88bc75bbe9deb45346b53b16b6c334e9e865577fb736736b6652" },
                { "ur", "3fdf92483944a90c1ccc9fcf4224fc7144f9df70eac0c5324e7f6c8c2ec120ca6c70918deaa7c6463a2f05383f7529c3baae08a1121e72f286ba69b7461227fa" },
                { "uz", "23c8d282a7615e0db702d11283edd6f49c24dee18c5b6f33131b0f5f66f43ec366e58afafc4d6789afd50773f478d2a342b768fb87b3110d78a3fe75225f2b5f" },
                { "vi", "1eb0a8ebe325122ef3f4f07a2820246b8dacd9f037d3616dbe383ec4776340481b6d6f84735ab026f5629b7d8fcfadde8028048f7f3f75ca64c2a7ba70506b0c" },
                { "xh", "bdd9756327c41bfd99fbd6940131501c7654ec1c92edbf005677222d0c909812496ded227704074fa3cd634162cf59d1a887665d7bff0eba01798a3949feb44a" },
                { "zh-CN", "1f9e8b388b24112d8a9e1b7bc838c71519b19eae651f25dbb56b7c7d284bd2beb7b3395be4c1d0c50138231899f74d6ea681ea193036514aa4453a67acab2b22" },
                { "zh-TW", "367c92db1c0e04c8eacadf09c27717d2cc7240a0d2e89f456a2dacdae8ee6684d94b479421970f411290b15cd05eb11cef9e12fa4114406d2ad00345ea1b4be9" }
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
            const string knownVersion = "115.5.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
            return new List<string>();
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
