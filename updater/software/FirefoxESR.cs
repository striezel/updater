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
            // https://ftp.mozilla.org/pub/firefox/releases/102.15.1esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "b72c7d2c692e56b3b4cc7fb916e43d62fc2f0eb3b71b70ff6b700a6b4771ed884e0a7ccb0e6b16f793bcf33126ae3da7d50e47d2cbf256a4c52167490433a285" },
                { "af", "3f36a0eef2c373a839bd161adb7fa6361280bc71f975829f454031ef42a0768fbb946a71dda40d2fed9ce256ba8be385c4da765d7f46f23d96b9de55046fc060" },
                { "an", "f1ed5e930fe9c65eefe872a5fbb7f452cd47c30fe101a17cc0203099151e6758491bac2b6098ec8c0e557d9c5c51acd9d75ebad88a1426fdafb643c5d1c5996b" },
                { "ar", "216133e3c2605a433e478583ca4d4462daf2eb2d449f2c0fb76fb2e8fdefb4d9ac8ff5978605ea30b29c916932e41cde2e957f61e4bb904f3bfdb472fdab8fa2" },
                { "ast", "db254cf642c6b99d7547f9593232c3d2fc7f7240abef7715719e18220df8e50255c45a93871a56bf62a12762a206dc40098eaf844e59380805708705f981ce4b" },
                { "az", "b7e579d17375cebfdbcb933bce7177bd27fd4355720134941b1d9e67b36af4accbd0e1e77e9f7c372452e0796394f0919f011630cdb78ec7d51a35a57edd3020" },
                { "be", "e35bbdc6ec49b40598c81db910a69eebe18e7714a7cb6314abfffcb06e48f334bf2d59efee0542520ab45399b05ead0e394e78737b5312de4248c0d0c3693c6d" },
                { "bg", "4798004a7e392bebdfa7acad836a926a462b46b5d181fbd1bdf5d0cac7c6fbcd58c4eeaaea1d1159bfbab1aeacef61a9f19863c213a76925ae5724fa19d6714e" },
                { "bn", "52ab3173e8bba3134cfb7c72d4fc2eaf8fc654b2cf2b0e7355339cb13f84bd686de83585f2b5880d8c1cf00875259b2a6cf89036afa00022e44c90588801a31d" },
                { "br", "b6ce372a8c7ea6e865c9700ae99e8ec0cab6789f3974835da0dd0427de476c1095028f6f29163b8a977579f2c28f146f29d639921c92d7105c8cd6a798bf8061" },
                { "bs", "ba556db56ad9b52f04afd2fe22937a0767d23853f82f2a3f8f5ac926f491f0e2fbf8c7b5a802848da0a9732d02967d7750b9d129424d2179eb4821c47a8932e6" },
                { "ca", "310dbfd5ef7b9918fb75274b5de972d0d146e84c9fa6eada58d8bd2d47f6e787382a09d599e3d6928dc8c4f4a72dd58de5b039212cee31d2d2d22e5c7a9307ed" },
                { "cak", "1e38368d9ac3b7d4123ad95f192033da307a5556b6b2abf5c305d7ca56bf9187ac7f86e6f7d44fe8d56122b9bf355c8f086de979eed2e91bed0d1217140400f7" },
                { "cs", "0fb35a7a6d7a5f77cd2d674ba699af615460c51c38a7129bbc9827349c8be1be0bbea1337a029bf34f4d3d016ad524e949bd189cd3d0b12398333edcf98cc975" },
                { "cy", "33ffc8c503b763eeb805334bf084d3ce46e351ffca39ec6c2f6a49ad4b6612cd21c6d2c26fd68ea23e1fe789adb333301bad93e4e3d77a44d772980b00c24ee2" },
                { "da", "3d9d6fd1707bd5873d00992dd11378d47b469ba6cd5ac18974ae85b2a16bc3b3d5df131cd68ac28bf08f65b469643e4c1797d5675ff92d85f596613264ee79a3" },
                { "de", "fef70edf7ccc81544e7c66e4b340767698474b9f5b555fe7ec85d0fd194bff314753128d00f5d63cac0a655c7554bc5b53201c87ca760575bac20d5f8434fcaa" },
                { "dsb", "3ba70295593d77afa357014584462eee6ee64a874768f16415d0d7f173ac631c038318ce652c4b800f934fa53ee6f89c577cc62808ebbf1298fa190d310191c6" },
                { "el", "270e0dc6432beada9be85da0b90ffe8353af5bf9a6fcd40e01df7432297736839a58f478590cdf943cc735b0a68a6fe849a548611b5dad864ad4f4ca4d562a29" },
                { "en-CA", "09e67291b943714496336bc3c6292c17d7bf1d249f50d5ee0b774335e7dd6ed7111c32a347544c728951b29cd93b4c487d1b1d020d0574aff2504c55f0162cbf" },
                { "en-GB", "43ccb95979388c471dda6230247a8a649c7df8c0c39d1117650018c8d271a9616b149705dd4cec3af36407939667ff1648b7d033d2f5c477952f28a0e1e33586" },
                { "en-US", "f5496544d857fccecb219ae7da5958974b8ebafcf812a78d1aac0adf73bd6db00deeb3b3574e068b865323d18bdc2e5885e9254e2bc618d529bf7729b6ba755f" },
                { "eo", "58b4f19ca3b31e95fcc9a6b5d438e1eed91e99f803f31eedb1b6c542ca8a7a21a1b8124899a89e2438cf0fe53b4492f709153d4e2c88e5fe39704ccab19e744e" },
                { "es-AR", "aa5114f48ca88dcda242c596d712a28709ce08e866372dfa689343cabacda64b5fc4662d011dcb48c6c7ee5e3db511dc26804b45889ccc7cce5975ff00c2e022" },
                { "es-CL", "bfd90e6059e3b102cd90ace816cb7f30a3668dd5397ff6574ada5719a17e10b81a0738e2af6704a91b66134e80d45429c35fd84820cac86c3092aca778ebd074" },
                { "es-ES", "36151059291ad4a8275b52dfdba0c333f46d2f10ebb6cc51a03e3712d434cfca8b2ddb845877857958a1c3a2f15185216928a72146a7efdb0f1d65191ca126ce" },
                { "es-MX", "1ed946d5b3ea546e0c79c9b50b146234f312268d57d3c1e85f1ae05bf7fe462db5b726d3c0e6412c949a3523f47218cbd96eed0a98d708c120b1c0fd62980904" },
                { "et", "d482a08b758a2ecdad8c5ffd1919cf0de7fea5a71919c2347b7a8b009eeffa7400f2e63fc1f8e46bbef2cdd83122adfad40844006e54c96fc148c009608f12d2" },
                { "eu", "f2b35ca47e2cf04079c7afe90543a72fda2dd941e09f64e19eebdef74c6dcd69e7e019d370724db9fad250ea9fc870bb4b7b06fcfa7f6d0484972e1a24b3c015" },
                { "fa", "397ae451cc9b1c8d8ffc176c3139495c874c68c82ef7c10174cc609734aaac4eac810e3a3660770ffac048ce0b444d9fde7a0601e5fcf242394d8ec7dcde9c0d" },
                { "ff", "d25297cf1664d716b4996a30748656b64ba6cc460fb948c87925e5f9222f4aa7cbd001d9c33d178e4578d6de507a32e878260fe78016a9078106ce7d91c75c3b" },
                { "fi", "9125a04b7a399613a7133e30a761442f449e827ca7507aaecc544b487be3271dd0c23417421333e5cf6b6a84ade4abac2cdedc9c1d4760da6fbcf7b0d174f221" },
                { "fr", "34ac85529ba19667e3e46498d10a9c8fa4e878a41669bdeb3f37172b2b4d2be0a57ae59152ca86c0d75c0a9800abd343a5ed04f8d1552bea7a95beeb6de00f3f" },
                { "fy-NL", "44399f77d7b62b3e0996a03148416060845ad43dab737cd89f2239643927e3fcc34249bd34c78edb96c41d070d4dc03509717f6afe9448318ea7bd56941ab78c" },
                { "ga-IE", "6fba74173a31f6e010232ff16f4cb6df146de7085749fbc2225c9643182ede241b7b2c4a2451e6f9da2864d8c924b15e144751c2f7aa219bd630a84c6a6eeb6c" },
                { "gd", "764eef6f2448db8ead2b48084c0158d24e96c2e93ad73d3efc019c34e0d5f1d0c02235d353c76e2f686834fb396db99e7140f3cd8a5bf81adf5b3160a03ea930" },
                { "gl", "6ed74f7db07f4da44472732ae02c10b256337ddfb4f69deb114396fb38fc016858ef01fe4f0974cd0cb2adc834162112632090bb2cb9f7880c832640a1a7e462" },
                { "gn", "44c9ce6bcef3591b5ccd9d2ecd7ab08bb215e3ff358f6d54c4ae7c3abd400117045cef0f39217bb971142edd33ccbbdd8f96747abaa84c3fde8ac51b92aa0d6c" },
                { "gu-IN", "bd26e02ec2b27cc04ffed4f1012d72107c2622d4c013d57c942ef69ad514ef690364b9575b9710f59c0baa7efda6a90b50e2d14ba33998e599a121731d49be50" },
                { "he", "433e5c0e1cdafad13825ffbc4c93826e9a016ca498f143e14b04c4b7983047a67ded46764825214837105aabdf4dfd2a190c6e843e109db1067785444a9f5f7f" },
                { "hi-IN", "50a39034a7d228517c8f77a3d036c7ef71fcc01f046489863d1e26b506c7e52cd0f69d8a06f41fc899d7ba1d154f5df10b31d2748b62cb18ec22c48821c99485" },
                { "hr", "2be2c2773f6929c0efafc5100ea90b148c2b6079bbd880e609eb57e050d3ae25d758f936fb64e53960553ef952f409d07df536083659b2f9935e07b0f47ebb20" },
                { "hsb", "8b151fd12cbdf15adbea592868149ebc0e73847e9e3eb30a25469671c7d6c76d01fb3c807201eb88120329745fbac3ec52f6309c3342e3a1e0698a9dad4ec821" },
                { "hu", "62a11526e26823437daf9f9781b3ac157bda526573db1d22648f1dc93b81c9434150c23eb7fa77ce70ef8aaccb3f01fdad7a25e2564b377a26815d3b460b727f" },
                { "hy-AM", "7ec43a2c4d3ccfda04db96f5a85c64d1603c20e9fba9610a2214894f88bb1d9984fda24dd698164a33d6cd6d77d9690b635bf5832f6ef3fd06712b9a527e8bc4" },
                { "ia", "9a7714368ff10e74e48e96c4d2ebe1e62156fe3dbf4fb55bcf2d0d5126660ae76cc6b4ac7d5bf3cb71d716fd22f545b333d5b8c675fcb116b57ccd1c4d14425e" },
                { "id", "64859ce8eedcad89f8235b69b8459b7a4d0bde0e5272c6511513f254b9a38cf8ba179c81266f6d8866fca215ab9003f6dae7a04fcfdcdcb72f38ebfd7b38c618" },
                { "is", "56804121f66650450b1936e6dae1ea241ef93334a0accc728ced405ddb21ea205d77c7ef0707d4ec64bddee5897a22f6b75fa2426823676288ea9cd1282c14c6" },
                { "it", "04cadeef7db215a83e2b2cb20f8cfd123f7291975fead236392c162e1672a50da1d829cb21e6809960f1190d2e02db53f62f66ce9dffa8794fc5f0a67b04f682" },
                { "ja", "3f7699204d51539aeafdef68520634b81cd9104c504dff7be4a10ae56266c4a2d7967780abc71d815e463467c8ef7930f1bceef50ed8998e3540e2ee000dd43a" },
                { "ka", "61b8e3c2f705f3719379b1a001666061e480dfadb75a1613d03f06eb6105b82a43c29f995235347d55976c7924586b72193e40d9c0469914df3c73d638c1fc3a" },
                { "kab", "e11730f5fbf5f397f4b1a5783cb0105097a581ca1a3eef07edc751674c1dee6ceadc7b21a447c2e8516cfd2ccaeb260e9af51405438fcdfcddf51f46d1617ec5" },
                { "kk", "8967c9e8c994511372e1aacc0c13c869de251779c1a202ca92847ba992c622f6670b9462c28ded530b00362a1925bc70267dd9f0348cc614f906ddcc48758a31" },
                { "km", "a02e3477e6693e7b151b07d6cc2532cae46cf912ce29756eca4c241dfd2c57989626776da6dfe018dd1e096f6f6dce51c3b69e2324372da47d57e8ec0bfb4d61" },
                { "kn", "04e3c764cb2c9b9d62da84bf42bebbd15495596465da97094ce50e14e1a9bfde414d56630d671028e6e3a24d4ff034eb6b70dafd36cdd89a04782d18391c7944" },
                { "ko", "e235e5ffd4d89e6fa5acc9dda799149967f18e59375bb77be10fab5bcec9acee110c5df0c589754bbed3de58499ed90212ba73cbd335e9b18c3afc80bbcbb383" },
                { "lij", "01fdf409c9592106b1e3f3a38c69907733316a9a1d9ff6b8c3f8fdfd5dee312ba96bbee9d4bafbad20f9559e4c676f5059485a016fa71492354000989144a846" },
                { "lt", "c8e4ef003ffdeca6dfdf629b72d6bc8e116a5ab80abd841e7658385d268d32e7a2d2d6e751e99d6ae2d7ba4c49c7f4c7474e2fc8fdc4b252e6e15a0849d49660" },
                { "lv", "2fd9169ad427a5735da2093cb3c84236a30d8eaee3b604538d978f7b65e5839217acc7534fd1a142cefcad9edcdd9bbfcd3423910bb38897016b4af8bf1933f4" },
                { "mk", "4af15fdb0097e99cac20c796895773256f80ea9aa82a196e63475a4ac05d029cdb06d9a3d85ea8d12a835833cc8a0eec80d4245ae05351d7aa764e137e816e00" },
                { "mr", "ecae53f72c539ef3af52f9e23c35679c9082dda984eae375eae0f6c0d8ae8968f6c160fe7ef1b59b25bbfdc5abc5715be71375d1fce0091f64cd2286209fb37a" },
                { "ms", "2a5165fa24c596da9d5583d6b8e166e8bea816bfa958cb688498bbb74f7072e41ab6f62018a2f9a0a1f5e3383925e8dd637d8abe114d79bf46d150a6837192a6" },
                { "my", "3317692373693341e30f34b9f210182f053feec0bf7b78acdb5bb87f126117b11d72b91a99816fffb88ddd977635b4719e2224dd98c7610e6118441f443373d1" },
                { "nb-NO", "06db42096293bea95c826bf53ea72333b0c3d3cd7ecbcd3c10cd24c0efde45fd545b8ac2bee361ddcf609230f7ed9493a58b1596413e114e35c1891375d3ab70" },
                { "ne-NP", "4242ae6eb12a08c787f738b6c45fe6ca2b3c578c13db80e2bec7452690000c6213dbeab7addab1047ce5692f66041153a6742a6a690d4d73c9b56fd8734d2c9e" },
                { "nl", "8eb15ae8adbf51b11b6a83ef7822f4bc6482d7e39f757d11371ae642d5198c9df8f7b8dfbb691072a50295b0a3fcbbee53e203e0223cefca1ef8d31d142142cc" },
                { "nn-NO", "e06e17bf57d7b718c23bfa7a1ff8dfcf14085bddc94e4eb7a1d929054ecb499e47c3a71d68e07aebac222c2cec337170c700a30e29509f96c88345863e29b46d" },
                { "oc", "5b138da6a041aa754718f35cf5e7840bd40ba57361a8ac7a261759675a12e1db711dbfc5d2ced7c2bf052870a8d1a458770e400be79ffa51181a33a0e07e94a3" },
                { "pa-IN", "8ead596051b08cb3bc1c2dc9e3ab2c1f8178db824e130895401858477d8aa162adba587077aefc05da58c97d9f41f539bb7a67d434d5a1bb961cf5cb85b65dde" },
                { "pl", "dbb13547de11f114260d06b216cd9c3b088ba610a5896497589ec17e98343e88c95b0d6ed700bd0679f9fe7331f89b6de83c8262aae3d2991f49dc3ab8097e72" },
                { "pt-BR", "fb59a46d9bbd5af141fb6c85b8076fa28760180a23e5c7f157ccbefb74b5ae6aaee7daa561858802e0aa0280b843ec70bf7f7f9f5321c7dd2803daec065d5a6d" },
                { "pt-PT", "bde00bd1d996777fbc8fb8a1749dddee60a299f660c71d24695f1cb98afae8ae23595028b19090c6c13cfe9e9b157a01b3aaee61e944852b5e7921dec23f6856" },
                { "rm", "958693a148a82cdeddffcfa16d90964c1ff4bc9638e7cdf9f64bc6a98b6b675f553d56688702f7902a33e3406866ad7d7b6cc8c6c67df462856a377ffd274520" },
                { "ro", "5563eca83828eb8b5aac7e16b357690f6697ec963f6296ebaef3a59105024031b2b7e01b67502843e66287b60bf375b9191941d7fb0e300ac3798c111fb34f9f" },
                { "ru", "a7140263670ca1c2c4f2bcbb2a39ebbae36f55a6e274a0253185ee77060044e1d3cf5cc56628604dd3ea8c153f1d09ca7ebcc7a390553acef307078310a8967f" },
                { "sco", "6c30a7da615fe164ef624cf47675dc33bf812b8c64681f12872da6aa00716f4da4f4ca71c61f5954d9812bc96fb67279527b2092b93695ccdca9eadaaf2472f6" },
                { "si", "6f614f4999d75681729a13f3455afca7739e6980fb35aad3dfedf3dcf53496710103d6e0f4562f42607583755b7934750fbd846ed02fdf9061fd5bdfc74048d5" },
                { "sk", "1e121dedfd3c756c8a233ecf7af3c25c357f5b4d2f19c96bb64ad69237e4c8b9dd3f1e753e34cc3e5db30ae1f2fd792c31f0bca485873e3a07a9b168cc0d3b6e" },
                { "sl", "c4ee247a66715beeebef04ec79ddf8ae8b5d388696111b9b40a04fbd8e8db306eb36e0d3f2c48a826070052ae596e506f032c9d14ac347809da35a178a08ab6a" },
                { "son", "8b1991b2ca3b9697ee8fd389229789d89b25521d27c4ca6d0d22b14e7b1753e08448c004db8a4bcd830fb1c73915ca33876a15b63256ce23a6d8845922034676" },
                { "sq", "84485a7b6e53aa35205b9789e0fa0e9fbcb8bceceef89b542ae989621423edb7aa86bc96f3ffe0fc27a1e0901af46e856d9db28afbb462cc7d5694ef0caed35e" },
                { "sr", "a2c1d62e2de6c302ee85de692d89259cbcc79b89b0905c0565c121b73214895ef33714d5303db29c5a52eb92d735d0d2774387a8f154784dcc101bbb84f8193e" },
                { "sv-SE", "9dc3581ea8fe6ff5c4dc8946619e888c98b288d82c5945d1619527335d011fef0498c46d772695f6c565061e545e8fe002cf55cb0a57baf3f96f63854efe453f" },
                { "szl", "db553c84fb862b527a4f357857494d82f6076685510555dda85a1242cc5aa0071d42f8e1868e38dee82a4f52d3a35fed957ee60b94f8cf20f3996a23203eac27" },
                { "ta", "5d39719acbb71a7c866d1981bd918fdd9e411168c157909af8c337b959c538636e628f97de9e0e85f5166cff8dcbbf52c85164d7d746e4502db2705550380499" },
                { "te", "0e543e7b6b80a19fa326b84b0ecef477f05f08c5729687d692efba508d070f9f2906ca4547ca7b7a5e7e8b8d95b6b9f3ae19de2bb70bf9d8497b3f3801a7e0a8" },
                { "th", "838236b4f047984688a0449dc55c71c5cf559bfeafa1f998d56d2fb0d03d5707464e13485b01eb0b5599ff209d8c9b9c9ef9ceb85403fef7116af8db338903b7" },
                { "tl", "1b6dd12912d125e20e8b4265f1ba6771d53afdb1d18f0485e2995595099677daac97ec7968eb55710a0e243f464de5caaf95271791da3d4b1b7c9373b86b7e66" },
                { "tr", "ef146f25f8e206f2bd8175a72ab3d4708bfb61974c8c2366a9713bef2ae3f5cc1855b36aed15dacf1bc6eee9b5a05b6ab192d9066bc285a0addcc81c9e472dcc" },
                { "trs", "b02e352950b15a0a6ae6c21df1f5cfd23491acd0cd59b9802bac6b2908ad05ec9db4c61cda75f33aeb6989112aa9b277199158f38bf480203fb3e94d11371d36" },
                { "uk", "86fad36ddc48b8a387be3fada0bac15b18bb786865ee63813f0b930a3b165ec5e744040feabd7b7901ac078ccf3137b67fdcf26ead6031efeed3306b14ece32d" },
                { "ur", "5c286976b0ee6b1342120eed7d59da77cc9061128a9d6b768275e42fef8a29ae14748b9ff7abc1fe3c4c72b0f0e64cffe3b390162dcb80958c3c9513d5c4ae45" },
                { "uz", "142ab10b5bf7d1672bb8acb656f7b0020e1999225843ca3f649512e0bb8d6469495ac93a5947d47c3ace7761539d36f0ff4d9124c03d3de4bc2c992fcf084304" },
                { "vi", "818a0fddbb51c8762c1e53604d69ab842a7a59c65082b10ec810d1f560f8c406ca12c9cfe94781e9754f99d03dda2b29d33a0fc6c3c73cf9a61da70359b81b06" },
                { "xh", "2c2292dbb40a95543219b02bf6810746832d10cd6b4fc22635ad69bff70c2d069b262da22078e8f65ad89d0885e4ad53f75a436e72761e14ceb8bb3125d85f69" },
                { "zh-CN", "3baabea7661d3b0153dcce759d55a4b72c54b87d4bbf52dd24421d82eac928d775caedeb316ca85d58761569685b8b2d26fb42a6f9bbe2672fe5a9a1de45874d" },
                { "zh-TW", "4307bd4ee7b063446d6f811094db3cd73cb95f826b4d16292b297e817be5e0c61d295d0937d4d0af2da1544259ae861f1b94ebf005ceb7ad08cd344d6e0bc5dd" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.15.1esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "2f68bea6d4f75116f1f583002b814893eaeee2797a119fa0feba91bb3cec4ab9ae565ef7d1496ceac236d3d19350165cf7ecc7c87ecd18a4d909b858fc189db1" },
                { "af", "35435f61bd568c92d48318405b92eb85ebfe88bffde7f485a0de2e211700112b0723a60c62a389b886b96925cf2207177cd441e659e5ca8a122928523c085a1d" },
                { "an", "c9ba612c0202274d18b7d8ff65a65501c3ade42c98ec16b067be2cfd76dc780cf7daac05bd312329e5bae9b986c58de419ae26da35d20d581ecf3d08ee57ea8f" },
                { "ar", "444d6c0b43c0919b778b2fe2a9869f02cd05718ea091433cf50fb81b1849dcf3377cd509def8539010e72c060eb32f9f3ebee816e7b42cee65eae3058735d4fd" },
                { "ast", "2a4125d5e86d7fc5b031a4ce57393370a13daccd570e05639b69d61633e4dfd78ad4a1c938ef6d17afdac5e35c494221a79c71bca9fbaf997739ec021999c3be" },
                { "az", "099fcbf0ac41500d25f5dee6d4e22454ebd507b7b29c2303043daf4aa4552a4b87edc4de6f98bf4b6e306c92aa5ed5f8c4c43ba2853437cc2835780ebc58c05f" },
                { "be", "ee1b4815ae1aec379e0906b89705959d5b0ef129a52b1a052111ff2877c1637e2ffec361fb5a9e0209fd269d6db94122df3c6444a07a67673694374a6d42d9b5" },
                { "bg", "7d9c249c0cc3b3320b17cb3ab93b6c5e2b7b09b0460167cbb75c0289cb33dbefa960056ef1a5629fb3098a24e8841844c60fe0317a68aa5df6777f6eb0aa0ddf" },
                { "bn", "d8829e485ff802fa50cb542fca6c90b986f11b6cb19566ff8d5bf9ec0df707641019faf8de27a004d0f095fa739320747601074b2b4c523b03706ff5610c312e" },
                { "br", "202215f536774a5d1a1d3f3352effbca0312ba1e9df28fb36d9012379d2f26e7cb247661a7de16d3c51604cd2973971fccc7801dc4f4bdc1d462eb15cedfb5d8" },
                { "bs", "3054eae2ce79a3af63ac1de17d54bb8f0cc3a0a1a930d20089d5ece88910e84fa4b773b40d1312a3f9ba4200d01643760d1ae80f4a25ee3e99a8f75df62449cf" },
                { "ca", "6f26f84c76ca2330f1921d2bf10c511779d578b259db8908fb14a2d77d751ecf6ce34dbadbb9643f71bf0cc1ca05d0a69aebe9943aabc1c49a1def36188e6483" },
                { "cak", "e00edb4d8172298d7a02674a7884fb77236a30c7e3f3e11e01ecbf87c8dd4992588eb3948fada350ad8421d51be69542dc2c7ed97f9eeeb3c0ac4c8eb3c43712" },
                { "cs", "c66470d41a9b644ade64c96bf98a2119ea931344f69e30bd40c121e5f760d9cabae48994a39c9851545b5de3fd5724bcf01e95ba5c40a306e2d14660a90390a3" },
                { "cy", "e2b7b802ab37a0b697eacdb7ea22ddb0b04e704bdcb5915f37f50289c0ea7c692ae7052cfe90215ccd2b4fd05a4fd080529780bedba51e376e88cab78c56dfcf" },
                { "da", "c243c4fbcddd367f4665fb951c8a803991aa472dae81526138f658d5625ce076c9e71c5cff48ae56edf14dfb790d63ae3f6fe58f133d586beaf97d34700d6bdf" },
                { "de", "8f217e2fb3aae568e1a87e279e92a69d8a57310b07969b4a64f49ed5ed8fd20a244e9f02159f69f73995880ce6ab3c70530e83e3ceec3a23f8f77ae147425034" },
                { "dsb", "6eeca7106caf53cede8b70439957be3aa56ab40fc6ffd3d8f334ed575fa9787fdd63d0b926a08c34c88fc77f242e67ae6299f099c4c00d26a0a82f431ec50131" },
                { "el", "92f4ff29e22637658497686e893e710c13487e2112224ba6d474b43c00d484bc63bd6794a3182b6f01affc8f621fbe2c1d5f64249533f6f32624109f36976bbb" },
                { "en-CA", "e459a833a3faebd30c0b783c6cf1cdf72ab6e9a668db4a86df9adc2a9169ab7e99c0c3f58c52d7e7bba57f63e33e316d353d8576fadb72fcef1da4c9e2d691ab" },
                { "en-GB", "5405dbc212ffa78476affb31676dd81281002ddd97e54c2a63c535e80c8f6b98725b590954e4cb10f3db0e38d7679c0c08832b73554eee8e06ff633206c645be" },
                { "en-US", "2bd86bcb61c47a38e9a5eb2e1ee43ff88a41fc8ecee8a74f66f9884438b6f40e6d75ec66a2dfb4970bb94deb890dddac19708bd94811c502b2425d8e3fb9bcf5" },
                { "eo", "e2ab601d30cf6a2c158c510e60979ba8790a223e7b3cde85da9cd607a805aa90cee2a44ea21b23b43a3494e3b9322a683e6f732f462afaa740cb988de11f89d8" },
                { "es-AR", "da16f22e4d4d2ca4d8144cc1d692c8d2f4889dab170fa4b8a9929454bcca613ff6c5f5ac5fc9c21a31a32cb69c82df634ca25511ae465975b7e564ceae33cc91" },
                { "es-CL", "35b565e4471b029107707384f53776a86f6e0ef50b5d057e5925219c483dcc26bb11545cfdc5af112a43e25aa6a53864deeefec586c60794f8f84fb6877dd18a" },
                { "es-ES", "437707a8f64bc15366deb8250af1745b645e9c336528e914c7ba26ec50f5e8432f9f6a98df4d0f07f0dd4b53c9bb1b2c49cfaf0642b99aa85eef459da2046d61" },
                { "es-MX", "94e08eb99eb2e713a7b5682d5d0032ddc55a2a44e9864ba5eb4acd8880197ddfae0eab13aaf1c187a54fc4de82b3500668a9e62f8b83aa60dca98284a60fc458" },
                { "et", "a62d08720e290d63d8b412fd09467df786cc428cb288c05ccd392b4dc52c9b4b7a116bf3ba4c79839e85601a5ab64403c39817c595e866e143fa1132bcfcc1d5" },
                { "eu", "11a1fe0b90a3944f362a7458a05165cbb4b3d67a2c452930d9b37a0caff6a440f0954a12582f58a53982cdb2a17f632ae1f9ab9a409fb8a344da3e70e202e18e" },
                { "fa", "8a347bdff7ef5b99e4c5db8615e4718f6358aee5a7be2d9f436938a26262fe8901fc3863eb55625b6d3067567e4d3deaebbb178ed0f62a27bbdaea6155abf97d" },
                { "ff", "0ece7d0967cbf79eccc257949ca8e250afb35b96cc232b62e7b1d533d1e98406052b23ce351acee4f263518930bc2722b34c9a8bc491a41a41c0d430b5870c32" },
                { "fi", "6e40f8355b35b20106b0b00c8b3a4f26cf823be23c87c02389b22ef98ffe8169fa200de95f631b7343c1e963d3cc70fdfa95fb42ef772b6116162aaf2c6dcf84" },
                { "fr", "9364beebcdc8a0bda824c7862f50ec0d5fd3d19f0a69ce162973de5350a9ab510bfc9060675fb8e680e2536a073b76d70c50abc2e7cdf3116848785756b84860" },
                { "fy-NL", "0780236c8fffb605708bb60315fe7c2208a7a15bc2df3893c0fec270de4783dc8a6356bf312aa7b8376c42318cfa7ae7f4af32bd4f181a136fa4da2428a7b43c" },
                { "ga-IE", "066541c1895a6dd44df911d33b808531efdb60a7062f65310e038d6d4b053baa1d35317210af613600c3458cce632d0fd9fbb8182d492ebd3cf3cc5b0a70a129" },
                { "gd", "6eea5f0afd6bbe024c4659410bd8567b6e76bc822060748daa7f07494a246ce80eb24c2c9a00756f3b5fd572377a0eb9a0b1726cb1ef041de4a1e01c2aee76df" },
                { "gl", "7339e635e3e33fe7a569772e3f39166ebb3b6218a8a9e46857138912c2f9d74c5c6100c66e238ebe47452c74473622e9dfdb92ee191358547cab32d23e36c47f" },
                { "gn", "3c9b84876e87e48a02099a34547f05a8cecb08e2768a1a261ef2a51d4ce40dcfd9ff208287b99a3596dc1f3ae021016a2ddded432e800c8e863540773f60e279" },
                { "gu-IN", "b86f0d285ed3ae7258985fdf46d356ecfce4b3d9197556b901e8f964dd466ce2a9a82136e60eac62ce5288ffd26a40bc95168cb7e27b71e11b7b421cc3c3734a" },
                { "he", "b80f51a8bc5017d824cc720be73228a9cf5fef3ac9a7e6efcb86c84397ee5e9525b473bb312460ea66c0116c557ce0b738004a50c8093baa2d3d85f7f6f26b62" },
                { "hi-IN", "0447ae9ab94fa890f1372b9c6039f8d1972ad328578b57db4e036e6795012985b7ada18f5814af4aa9094829338224dfb1c965288893eac7e9c68a7f601c4b79" },
                { "hr", "2fb6f0d820083b7e4544094950125e8f99a95526f33992791cbab10de3682b4f1c378083dabd94f0947036ffd6cb769a7eb8f7ac3fe6a775ba39cc0d2c5e5646" },
                { "hsb", "a9aebd8f41915bb077ced1bacc7592e52c272edc951222adb922d2456a7e0f0d6cd9034e68404e59cbb69b28b88f729559d50980ae907c68ba97b23601a988e9" },
                { "hu", "a92981fdca38f2ad37a21a241dd24da923d67b20f0f5144b950de36a63415195995548d7dd28fa2e1004d9e4735eb09e2cd5c45384b89ced4a5f540657227b16" },
                { "hy-AM", "7ac375451747ad1fff9da8261be3fe47607bb62ed4d437cd673212db5a757fc1fc4d99079647745d67cda63f52d510171eea0e753c8098c2aaccbbcaa5e0ba34" },
                { "ia", "28bf42fd19875fdc2ad66812b829f14a2e6c2420820f160c656bd9f48896c4453c4fa2c44bb6890a2098636c57950bd0d943421dd94d44c617bc0cc818e70f6e" },
                { "id", "9454766aa81e8b019266351d52707d25fb140356b33b5d7337953f81336a65027679193aa93d7a98c604eb668f55eb588c7c175bac4987caed64bf30d98253fc" },
                { "is", "9ff3993a4a17e470d076dbf04b3c1f169f9bea58bc7233cbcd173a876c9203aae55111c96b798fc6f9b52429d4daa3c02cbab40e43720b5ea509f0390a914f0d" },
                { "it", "1291a6f4a7b4a266cc805cd91c6e1e1e6ab6833fe69f6d607dbc2dbf957ffead1897410ecdf2b1bde0208ce6c96e52ced5dda66e25e11f5ad5adbc325b6c19b8" },
                { "ja", "0c68033cc05517fbc67d3dbf7d1af20d6f60633207731c9b20f66e257d877971934ded4a244418355b4adc9009f513efef2873c5d806e809fb98838ccfecfd59" },
                { "ka", "ff78b2813ba333d676b18db09838c4a80a36bf258979575750bf66c23c2208cab33384108f2eb83a034905838737d560e8e7cf738ce42c4ac06b5ee3cfcfa7fc" },
                { "kab", "ee6347667cf1f10a7002258c95aedfaadb7786b3f6db63404143b1933ed185e7a7a7f6e1c539e66c3f888e8cea9850d2544a4bc6870357e240a6caaf20dbd14f" },
                { "kk", "4a5401e4be72822f746e6b61dfea107fbe6d30024ccfa288237b1f9124829ca88aa32e0948de372ae028bb8374b716b524ada8e2857f5edef2e88889ea179db7" },
                { "km", "747c0037f7738010fbad1dd4b8070c11b48f9922b674218748a857910a2e83c939fd112d9756c685aaa8bf809acb3fe4d41b38059e931de66a90f2b0b36819bd" },
                { "kn", "049662b1665a80c1125ed0ab2a0c9b87f6829a104cfac41c5b3329009487cc0cee5d243f7f3f6790717eec47596abc39540f535bae59a3858d0fbe5a80bcc64a" },
                { "ko", "b5a9bf249ed8a2a295c57a610dc2567f482819517d483c7f2899e7a7cba89a4173397c0cda14b9f476ea024bbd5c11879b1b08925f90f88b9e8784e76fe20e87" },
                { "lij", "b5a6f426a68ad9bc069c4c9c91b43db8d28e7893e621d9ef535c424817dabd8c5356c46a80a65f47f0fb581fa159e056cf77b9553327c8b0700b1e7eec09370e" },
                { "lt", "fa04f8e3255e5bbd083f393d3942c2fb40c886d72f4dea534116a67c615679016701bd583e3b19ad2b4f6ce96eee4a835c028e69a2973f1878f157a0fcc281d5" },
                { "lv", "da5888f77cf670a3c43521b6e851b2c8e75fb1703d543303969a7ca246ebe24600da2b621791f121120ff55b309585944eac1f793745e8dbc76748971a666772" },
                { "mk", "6f5b414ccf075636134e909577fadb44ec1f2e1e37422101fc10336db8dac89a945d100cfbf5ee5fcc5ad9c6716cebf334c9d58330189d63ec13a42df65fd725" },
                { "mr", "b59f7590c14a9649ffb4b786bde9d08cf16773565f606d016ef6a108b76415558c44b9abdf04576cbd4635d8b9df79df86cf4e262a1b69c08cc17662b896195a" },
                { "ms", "29aebb832b1e7073d99293ffe8d738a165e865033f929fc292dd6060f7770622e82957dbe3126e888d134083abd4aef0cf69c086616901d9811f74a884667f1c" },
                { "my", "b1cf5a1490a22e690755e008dbcfd1eba36a511d2166a086087a728e90633125aec8f2191950e1c7966c6947a9dbda6eb79334a4d08f5795b33328aca6e9cb9d" },
                { "nb-NO", "2ead209b2ef4fe5a0ce1e1be1f08b21fd2c82c81d57670986beaa6e14e615920a0e0312eb403ffc2cca6190c9cbfe08520de778070664f65fa6467ed1df7670e" },
                { "ne-NP", "05e5e4f9661ac267e4698be92ea7a24e686601b53b048d83f0fd3d7c8e338242ed8cd704d30b044e4c59a54151fcd12d3a9a8ef28e440e8d71954804255d7f9b" },
                { "nl", "513b4ee03a8bd62f10d23ef5e084cb2cacee2a43909cd6d147b47be96367360c02b81615c60b6d901f0c25dba4e0839c8b7dcc4922fdb8dce2f3302d69334efc" },
                { "nn-NO", "ec79255e8593bc703ba7edb99952ec770a231b8c70993a6369c3c4383403ca7f76b40126be720e6f1161b22c40e2d75e6939ba3abdc2a4c62ef9b91cd712f27d" },
                { "oc", "9e3bf8ef5faffea10bf1e4c596fd5c06dca7ed4b904dea23777ecedd5d72ad2a72cfc17c298b6b12886f3ac32d822c50e517603cfc2012a410a6d2c90b278c9d" },
                { "pa-IN", "ab081299316fead7f27fa4faf66756aa788d2ff321ffc9468c215f9d8deedd37e1af0dc65070f62e016156332fd25806d3c56383609d9494c7cd1e3b634f1599" },
                { "pl", "40fadb752fe125567a8bf42862c79a8339af03fd57cd533a5b201059ed28ed16f0eed8e62e68bb052c40f2f25ae65eb2a91d143b781cf45c20e524645c7df161" },
                { "pt-BR", "87df6c60dc5739f58cfc6a221c9cceff54d43478661580b2fc5cd3a80d8389a710621d96099c8328b37e09f841b0537e819c0d82594dad7ec1f493df2e291817" },
                { "pt-PT", "49ac0911b632ee689e49e71893d14b0bc3cd634c8efd17f68b19d5f595ffd7db896a0cc2d65cbe57df0b14124822c38c96daae717c96564e4a8f4f343972e80b" },
                { "rm", "e971adf4abcc16ded6f95036a91f728058d9d467281b0ba62df5e3ee9e3617c6c2085ef60a629ab3017649b81350da29ad90f932b466de4db1e3f9db1f7427ce" },
                { "ro", "e4f212c37b86382761ebe1349b31b8bd8c74a23a9f585db253b24de55acbefbf1a5ddf86915d7edf0a4090823ba2780599060f310ab60243073d8a87a377c66f" },
                { "ru", "e68c3e404647d28424f96943b83bb6bf00de39c853c88938842e4d1ceadccc5a5f5dbaede45c4cbe448a4c8c3a28ac0ec23af302930ae83f788025f31390a9cf" },
                { "sco", "539b110677a6f1689e5ff049061d90d6fa334e043fa34d98ad3232f5723d12f6175c89c9215382dfd8f3fa429bcba31cb87022c34ea2abf75aada1e7f5c87459" },
                { "si", "383d5072b79636cbb813392ad6f894ad0903be394ccddb9f2b30de7376feef23fda9471605bd77ed7f5db63abd5c713ca61724bba1a7577e7c6582a736326457" },
                { "sk", "bcca5a54ab5fbe678bb0477aa2bde36b6e0aafed8d442041639bfdcfcbf6e0b4628cae58b39d7bd8a20ad7576e187eefe7925749b2f4be638792e26731f8fc4d" },
                { "sl", "51c0c561e5972d7614ad38b5c70c267b2d42c172cfa11316351a5d43de62f09962d5d4c9c27c08f6f597b716ed9f1f29de7a4cc4734164f5e8bce90863886e73" },
                { "son", "786917531783b51c2fdb1eed261c667eda146685b6879f554d372290b6796ac4328217c54670388a0868440225e36902a41bb45c88e324391fea396b789bdc55" },
                { "sq", "4677aa358bc0602ceca47a84b68e91d9bf5779cc42a3006570eae52198b8d6729c9d248d77da46c987a5d9de6a9a003cd1df2de6c22e3cd4c000f4872074871f" },
                { "sr", "bdf6c5e034cc67ca57a978ab7b9e8bd53ea45f4023c896fef92a9f0be4089b14a10174779138e3808a0a575bbb8c3202d9f930fc89df1ef0ce98479a5d298088" },
                { "sv-SE", "0b4742a067932b5ff1f3d9fb336ea2563af9fececd9c9693523546521a755100ec2a3c20d3a2552e008cb9b94b8638ec0bda2bc1c364888b1003efc81a5daeea" },
                { "szl", "05bb66d442d426ae49721d365cd2172674419ed8801d350857f5b948d74040612177ea176e7b0aae082f69c87c03a65021efc208b0e18dc146ba8e4a9d25b7a9" },
                { "ta", "2aa95b92662a35088fb8c5755e13c5258604925090386ab65a42b327bf3b8e14b65aaa2f22fd86fad6b7c839a4bdddad24c534959b7dd7b2be4a729044d90c8d" },
                { "te", "0458ec5a5e4cf3bae088c6ed4f1210d3d9e1396d2d95bb6b37ff2478763eaceabeb06e2d04256d538eb578c3d5a3e2317353394867e5d519c2e516a4647718fe" },
                { "th", "04eb1f8307f60d85ea9acfbb62a959f76d697a3f6133a347bc9f21c8d69e0ea9c5c8d2b0621abd6ccaab2f4dcd138ccfa65c6d420a09e12a5add5c7caf96b851" },
                { "tl", "f84b692ee71413b2a20eed6affae73870feacb33b162b6ffc4049cbf628dc705b2bc7aad3cfb800217beb8782666b53abc85e61882496a685485c2a927cb636d" },
                { "tr", "09424da7010321d92600e9788bd406644ae331e28973a6eab51d2e805a5a44f754ebda57a9f1b21d5390c7977121f46d7e2e4a39479801d96d07ae1cdc69c84c" },
                { "trs", "4d7dae51cec921491a291d1e8a1ace02a2a64e9a249ad61041527ea74d738a0974c9735a025245650d16157426841f1189db24ac39b195db20a6c63a7523a02b" },
                { "uk", "6b59a24b4afdbb7253c4715659fb440a873f16f44ccbef616b585264f98d1e7a15c61d08807d6154bf146e517555f079863ae5dccc287b211685296a046a1c9f" },
                { "ur", "d793cedd4721fab612c624212a41b4778954d446fd863a64f5fe594b5d6d3fed6fa8a0af3d70f23f36b51d84d1589ced96adfbec4826c906e9be019c74e2bc8c" },
                { "uz", "84a7e3b7881a9a0e6e3c5f104cfe39ad88c95354eb14c3044b3a71139c7a2e90f3263695537d535b2bd3fa8c5abc2c518896dd13c05107faee5af4fe343876a3" },
                { "vi", "de3059daaae7e411a838c04eda1c4761fc17e5517297be54199b13aca39067011f990eac8ce6a3501ebf0a8a421c67dfbb64796af6eada2e2d1641fae3e1ef80" },
                { "xh", "c20366a5c8aa1427ad60765242ec5e7bf6ae3ccf94ebf314f6dea67ed12e5ddaacf1852f2292bdfe5b00e898ff7b678ebeb01ab6a2db840085e978d14f6a58e4" },
                { "zh-CN", "833f3c681b2a97322358ef2c4e9620e7cb98b1857d4f0392cb70fe361736ee2a4aa3949d27d7dcb63b73095d30a4efcd9ff8a24d2da2055c40e89f6ea1f2a4db" },
                { "zh-TW", "5fac28741862d752af87c7b609bdc221ee4301273e3308ba38f57d4eff99f0c811ee9695c1c66f1a54313f0640047b1922daa0bd9cde891882ac2e977f1e2172" }
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
            const string knownVersion = "102.15.1";
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
