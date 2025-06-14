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
        private const string currentVersion = "140.0b9";


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
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8ebd35ef93727ca188233d369e9c51ce852d86188ea2cb5d81b8233f9edb7fba99837717de3a910ce4631ddbc645e86652ac30f3515a669f1d15daf3b2e998d3" },
                { "af", "d0c8182d74b6db381ec8ca434a9952af890b016264e890393ce748ebc5ec1af0e0dce10e884742b392302e36e33bd0c43cb5e34a41d42a1331cefa6d0a5598f8" },
                { "an", "f5bc33059359aac989a6ef18366c849ce825d521d02724fcd331e9c9f4b3ed4b767f5d2aa32ffa1f917c22c27d427a51ca9715a3bfd2cc8fde8edd1e020fac8d" },
                { "ar", "5f2cd8cc4df12b73de2f270f6252f60d9ef7dd554d06705e25ddee4038bd78189284caf4d8a1f4f6597431882215eb1a93adc21acb2836d6d56da5a65cc7bb19" },
                { "ast", "9df559d8b534815e27bb45c9a43b34f8232ef203aa00ee40cde55902bbb9e6c2d7478e513ddf9c658b4ba4b383d51fb4224795d0c889f4287ae85ced7586b512" },
                { "az", "bfe0349bb783e6103ea81553deab52b009d5b7025fc0efdd09c70b065d3633a70cc289bf5daecfbeb03f69303e006dcb9ec10f2a58fcfeb29269afd152d93262" },
                { "be", "1fc6e137f451140190229042388e29c51bb6dedfa2e39aa2fb38395e971b1881ce261f65f8b929432765f4d65615da4beef2ab31c029d28c51041ceba8fee023" },
                { "bg", "caa519e04c33ce6f46f5e737b1618cfbea176e0e4623f8148ce243484b7c87484957a364168f3dfa869ee77f6505c31d4a9ed75213b991b07fe45ef5c36edb24" },
                { "bn", "8d28310f74dda83780f133ee2c91cecf2e4eb646114cba9ee827add4e63b34a87fcbd15e2179078d083bfe2279d6cd3827dd75e499131809847a9e00c1f4088b" },
                { "br", "7843088d05483807eba1ab6b7d6ebcd9886801ff35d3531ac6c1db013f5c4975f8cc324f64287524f9b9dc88eb2777d8b85d08fd2225b62423368ec72ff426f4" },
                { "bs", "514f9aac9e2732b8049c68c42bd8c71fff8b4384d5860ba96b9bcf41e867806aaa768cb8e7beb6bf32a199d9d9aa5684c3361b954521b39ae541262bd42e8819" },
                { "ca", "2dbdf2c2ebd7f281c1264f0271201969ec2150dfb57b7e29c3abef9761c5a5cd73a6a6e67f018aeb7a0c9288e783c81fbdb46cc9b271ab60bc8071e197d760c0" },
                { "cak", "55c941c6af37ac01a133a9e76e97e977dbdbe8b82afcc6f69f7acb084ec53304f8d6f90e6ebf6e383091165fb6490fd385272fba175b1a644b7fe5a438e0aa3c" },
                { "cs", "02500fc251268cd0a15311a41eaaf3ceda420a484ae857666a42cab09a6aca3636e79de2b17703482cdaf33aa0ccdb2d1be1c12c524bac518d042308c45c86bd" },
                { "cy", "7eb38114b4d6bbed5aa7162096c7ccafa263493d2698357116f4e0ecac90239ecb39d5128d3d863ed3aa2cda4e298b598d490c87349d056da44e7a08667a6fb0" },
                { "da", "70830c066a2bb672db1cee669f86773590dc67d8823ace2b3d64796534d529e6c3ad137def64940b750ac2931a07d6408bc6f506ebe800ecbf4a21a16c5ff8e4" },
                { "de", "b753e27ed9905abacd202543ef9141d35ae1b060815506af7627036884697f52e749e7214577eee42d9f9a11819d7f3abe7c5eb6e3cbb1aa1d86a769d59b74d2" },
                { "dsb", "3d0bd4b3c0538e12f8a9efb9e06b602d5bfb0de114b59f24b3658183564061df03ec77bde5d66ac5c55bcf847ccddfd0985d7b18430c103f33feaabfebc77a08" },
                { "el", "9cb5d32da31154261aed0262394ec6852b284bf3243ba0da16a160ce330520c2471cdff40bcbc28ce6870ecfa1a7e7999f9ad32c2f136e31366ead41c0609107" },
                { "en-CA", "40d432b94fdb240c168b33bd0ec124b403245d51642bfe19965466a3b8a4048d52318dcb83689eda934f51ef8dfd711b35621b61e507d11e9cfb1d5fa1abfbe3" },
                { "en-GB", "31146eb8bfec1039abf65aa7ffb0c5426615d9575d051cdf22568d331dc8e3bda6f24dd3df02ddfbc2d55a92b2b23e16b9478f99ec21f842e73544175e926172" },
                { "en-US", "6189af082a2689b103c09e6e91b18de6b4d7751114165f4052459adc0ce0142a8d0213a177ff922ab42e2dc0da61529da08d4b4630aff05bc30a5203393df743" },
                { "eo", "7251e96c5297a3821c486cc0ce0f81d7b18241e2857b1673408afe4f3cd658972735275e3deb7330a8013b01ad893eb3e18f6b2d75b43f50ad19767ba51a7933" },
                { "es-AR", "427e5b861f8bb24252f9d05b53c9bf5a918f2e73dcd6c3fc34d8718e3b0b381caec193d22425a8d80e5c0b103d5e611ec1031801a604d1bb00d2aeab1e2d0075" },
                { "es-CL", "508a248f2a3588e7a930a3c803a3a1fea90513d65e4dd3fcf72fa377552ddb5db35731bc37574b6c83782adb54a37a8fac0800a9eeacc5b584aa8a6e765185a4" },
                { "es-ES", "d42bd612cd4f8d814bba1fe3a16c6d939f96ee289e55892b25139f9f21aa476dc727e4216cc7ecbf6fda43225493195ca483b7346e48bead1dc5a339b7a21267" },
                { "es-MX", "c2efcf437087669a466ac424cefd1f0c36b94c58e0ffbe8dacd105f3c10ea9990493941b775f2b3cd16943e92a019aa5392e22a2b72981d66dd2a805b7e7028a" },
                { "et", "ffc359104706d815d52efd71e2a7409367ff0c3546d7c95ca34455b0a50eae17059da310de2f270c9befc174dc86cf3c88e6698c5d1d51dd4ec92149f351a5dc" },
                { "eu", "cb029fa46c8950962da3ce8297d22495fa1a0627af6dce1ed92091d79a7fbd387e03986f3db645b11a626abfeadfd766618b407c0fcfb0d4502aa8e1507c1fde" },
                { "fa", "49d14ea42edc2b940db24c6c41cb435a71284e03d1eed2486c717f71c5356a389de7fac03c1dbb7a959eb90eba278593ffacecd02d2e0a932c24ff07c6e46ff6" },
                { "ff", "55ef63b23aeab38898efc7cdc5018460a3356271c977296119761d2770132e968797aaefeb36dddb4602957f8bec2f62e33684a08569440f6920cf9804181269" },
                { "fi", "fbebe3a83eac30bcbe4baf9b6caaf4df0850c59a5a2b74c12b02e1231723c8f837d0626787878a2844a61fd9609eac4050c3527688456bfdf2ec944c8b43f7f9" },
                { "fr", "f2ccd0de05a61d5eba609af3cf3db2b605e8d87037492276f8e0a92d7839ee691c0b4a61cc48830213a1d7b238129d17138f3b41a90c27228247721c2428b2ea" },
                { "fur", "0a35be39609a135551b7d3314cfffdf4abd0cd3f4b3383eb8c6f077d86681818ce35fb74e2f0be0b227033144f592e41d07df4f3b8a0d67a9500b9b684d11c63" },
                { "fy-NL", "2fa7b3063fc19b7ea9cb9928ca54235c291e3da807a1593a04208f45e34de5519b0e6e685c7fbd98912d738aa2390baf82a303cbfce0e4ae31f3e6e390b1aa6d" },
                { "ga-IE", "8d68727d7d5f7bd50163fe8efa691fd22870958b47ada1ed9e6e69c9ed0923077944ade8206406f0ae582fe135befc5d65c164d8d7f99fd1e5b3b95e21c86409" },
                { "gd", "48e88b273b7a969a3876f6c0a80393897d2ba1b3bb5da5aa43e516ff4daf7e4e78c135d90da740fba1600eb744a46ddd28770414ab2a3632095542ca08cf3d34" },
                { "gl", "9e46a6f0e3285334b2e2939bc389286da70a0de6ab76a2478813a5aa9d2ddbcaaa82d6a623f3a881656b2eaf080a1115e0889e7035cd0578bc59c51ad5f6be3c" },
                { "gn", "6c20b0542cb923919917bb1dbe57dea1ca00eb48fc7553e9e85e08d86396989a9a6f61f56bcb30d9cc5a1a221356db9e63dbca50fa79d1b978f88389df64c2cc" },
                { "gu-IN", "c7839244c07474095c6915f59292e984dc875919e445aa7ec87f0b5b7e5ff01586fa0d543222e56e2d1f7df7ebf395e3a62d955117bffd1fbd5d45098cb772df" },
                { "he", "f364b22437925238d497155460bc7ef54069d69daa0a0c9f00b8aa976e0e72f147b69d59697094545eaa09a89aaa813c90e1717fb540910ee3bb464bef24856c" },
                { "hi-IN", "bfefe6e677dd69cf3bc3455db9b532f22e514c33b0f589bf0f67348d3e913b66ec9c646e313ed12f6bdd16de7b0e6aa91c046602f1ef93c6e1574f25111a3d61" },
                { "hr", "3d1324f2ca1339860f155395da40a3c6e391719450580aa9ea1ba2ee4c12ffedad7ff69a88ebd32583cefc024cca9d436e41f16a19bdd27d14ba1cc7fa599051" },
                { "hsb", "6998c7f2aefb8111f7fb2292a55bc56007ea7d168e50c1960643fe86c13358ce9f1c4f80d7cf9c877dd52cc13b0d84633023fdb0ce7f6402ac72bf2e84c2fa0d" },
                { "hu", "3844525b273120af7af7d429347d9550fff662d4f4560e400bd6a76fb7fdacf6aadadc7fe5a560302dcce61a2a925f6db8a086e84d8edfc7f40f1aa3390adbcf" },
                { "hy-AM", "cfd1f56e747923e536dc5207f931840a6523de199cea0e5ee3aa212e3d2aa6778bbe1da6963f5b6bb726a2c43aaba4873514fa909c7ee08caee5c21fb4e50693" },
                { "ia", "9f1fc9d030f5a19d3376000be09aee92e9e5f7fc7b7ba65a6e5ddf73d842df07698e29c3620eb27fe22ff0a51cdd0bd99bdc1b023deb0bbb1eeee4650e2279b0" },
                { "id", "c273bbb05dec915e54d7e3d399e7d37cedf5c4fa89ac8e47722732b6e415b010b5bfb4e56cd351c7997df060de7ccc1e024d2dff8371409157a23990ff4ac545" },
                { "is", "49223695af1ad46dbe8745dc263e24746c5f84e64617909579b3df8c0ae0b9ee5bf970f38e6a51f45fc497d9f1d89e2d26e2490a09487bd1805844c496a933a4" },
                { "it", "95af0d2bf7aefe29814f32f5094f614259bcf50a42c4d2447060733b296a1544f9cd5e4fe66def9f03f277c6dd5756719880f9ad37e0d8091ef640f359b25e5f" },
                { "ja", "5b6470f7d088783c4d77d861e663795425b91b99e7bac001e15df1a84d05f918cafd1251e538530b43a087284a82f5caad53c3e10127fc2287cbb056177c78a6" },
                { "ka", "ddaafd8392597bd6bcf43fa17e0ac356265afc678bd7d1c06d65645411b08b03e0d37ff04c4f14366299ecc2daa7ceac1331c970a1d128889123a56ac93def62" },
                { "kab", "a07b776a353af3fa994a5e32658af52b2abfd6161b09f87f7205bcb4a06b155906fa81c1c98e33b9b8aafc91336766f1054212672eac76872a5146b34a8e38cc" },
                { "kk", "e5101a330e13c0f29fcdcb21b4538baf8f37561da765d66e7d90cbc69f13ad1a779541f0107875e14f0c4fd81e1db5b39be50f77f8984627c8b03f8cb46eb0eb" },
                { "km", "77cc144a2e71af0cb66071bb55e6d5f640868e931338b2ef789623f8f75cbc160a090d78a1ea795977cf060b232d31f6c6dc26a137acbac86f1e5cca978be473" },
                { "kn", "50b2648a5f0ba75541b9199358f2b053112b32aafa2505bd6cbbfd296398f75848674a958e70a455d15fcc9c85773f3b32e8ff618550a150fb090101af69f7bd" },
                { "ko", "824613bb46a4bcb970756cc3ec44f2ec62a6cb1511a091546004eb025d087ea34dbba7e4a672cdbb6027d2fc455489907662bcb2eaaa9c82d9f02d9719d61ad1" },
                { "lij", "a72c612d797c9adf29de18fad8618116b18f798f9a25c9d5ec4c91ad1d023a200d4d5915fae89b5570f89244b5e7d4997efe16789e8fa28b89b270eeaa3c5333" },
                { "lt", "dbd8f2e7291881e994ec711d1b31c9d7531c1d52cefb3deb31bcec409fa9e26e973e602b3b740d14d15a9e6b211fc818c0f30cd026fd78e9aa9840a209179e3e" },
                { "lv", "276a8b146912a846d7aac7eace18c6c09b81b0649d81fee2fc89e62d6e142f354f3fc6d3bbe2f4962eadb1fea11c97c99f4516bdf5298f901809fbf2ddf68ca5" },
                { "mk", "19e44de2ece03be32cb14c31f4499c0a634888b6174686cdd6f58e25647fd0b1d0d26526b81874bf26b95add11971e0f7477176aa22d42a3c29a81f5e51d2d12" },
                { "mr", "92994a86373dec2fc2b6dee971eae0fcdca8a085c23dac7f6bd97d890f40b42cf5f5312a36ad356db4fca27e829d6a7c96907668cf1938c9f99163090d3774e2" },
                { "ms", "b37178e440e6f97ff461c6764f724bd0fd2a87fe1e86faeb45e17b7837fca8b5db09d85314be4e7f26e5c80c5b005a7c90e2684706d30669362d4fd8278b4732" },
                { "my", "411a5cf382946b122d185fbbe8bcb109b256e5b24e0f3baf5b6e49f388d3889d8aeedb405580a9497dc91c4be8f77c98e603e0e2af2780a6bcca7482cf38a7a0" },
                { "nb-NO", "e61df1690c27b971f3485eed92c8e29e7fdfb555657661ba79c63ca2b2eb70f71704b056ef22e951bbf3073e5f28d7547f4c2b204137edb828be7a29d5013f13" },
                { "ne-NP", "bb72c36367c096ad0f22f15dd3165646632bbca637fa32ebab938f3834eb24c34f6f0da722e0fcc42203e3c6f96dde7f780f2118a05103600358aa4f70e4cf72" },
                { "nl", "a1a8d2d6fa6460b40435c74d43a33d3509b508c09e236d02e62a5b46ab072027c1513315cb9e86a8fc5337539b6ce3a6e970ce819863ab1957de64d0e08f186e" },
                { "nn-NO", "97d4db168dc2c6b73fabd98fd360009d9de1859225d07ed61a51f2d78f571996fc167a701a31848e3c518127b63da7b97869bd9743678f5db25edb2c7ee195d3" },
                { "oc", "f47de6e9f3dbf45542ac74062f1b88de1b9a2ff4d3a83314d5f6dc1dfbda6f1c289189c91cead81987cf9beed945a77e93829bb2322485719e1bc76b36f5b00f" },
                { "pa-IN", "419bb057e3235e142f3fe0dc8c800e3358ae14ae2a690db5c7fd9796928c52a2124a1ccc41e4a06b513b991c4d178e9eaf5bd3a44049ea6b1a3ff6382dd86e63" },
                { "pl", "d1ab856f51c2210ee491ece983b6c64255eeddd1f006e1e0140aa46d31ac0a8c1e22ae8548749ef003f3561c9dde17a7bff844758ba3ab3337a6bb95c9dd06dd" },
                { "pt-BR", "28319e14b20e80a895edb4fb88a724944ee69ea3da148bce70a0064478b2e6893a44501866b442df4b2f2e09c77593c8de7adbe8f25901cb489b3993c77b4c8b" },
                { "pt-PT", "3c0a9866bb2479d2f3e077ca309434336c86d0003ab794cca15747bc815aaab3d725acf65987f72e8da629f6a8d9b74ce8308165b30441d8b7bae902e0fae4f4" },
                { "rm", "87b793e455eb886b37fa647fd792a9e88c4ac884a65e9aa9c1cb3276aa903ac999fe8d9da0037d856816db09483a67c16b1587323e23584c4f49130b9b65ca7c" },
                { "ro", "4f08fc41ec17452c0f29a54928aa4dfca346263fef495fcb7c327ae1d8cdb5debc0a45fc27bdfb41f2d8d6aba7529612a4882a6e917dd8c54a04cb6cbac2ec5a" },
                { "ru", "0cb32c72e2eb3c238e406dafbecba568e3427eafac64e6a474f938a60159dd03b033e12cf6e920726b89ba01c235257f6ffa96e29cad454ee4008b171693524d" },
                { "sat", "72da4b8333aeae2e8555f7bcabf9dffdb5b5fc20332bcdf0400bbe487cf12275e25f655b7d3f67ed172651cc54e4fb21859fe3b5b3dbaba3c8599a70c6e41e9c" },
                { "sc", "29168265cdca78a7587311dd50dfcbbaa8c65b65d079aac5256d707ebef51300016fe46d4fc49e2ee3844b1836b820110f1971c2c784555977dcad55803f0fdd" },
                { "sco", "6beca261d37315eba62c1c7cf5c29df33ea33984bf9238976436c001d8a78c9626e4e9d2a4af5fc402a45fe20b10773b6764403e95acab2649cfd2960d6347e4" },
                { "si", "fb2e5d82b007ee29bda3dd6e459c8a45e0f69870ce77839c4535c0ebd6b64f3975f8bbada52bcfab0bb6b26ddf9ada6f5a64d6ad94b3ab1520009d3774e4c45c" },
                { "sk", "593162bc8e8a07e2486aa93bd9e8686472e181bfd0a19fdf1d4ef1f7f41a1e9061e81a670a08835ff4d06ebe2e592d6ef9a53487701834794e6c3b8dd4cf11f8" },
                { "skr", "e03616b643cfcd2c0210b33933de5ab17c104b2d6cbc7249b2debd521e4fd241698f5ea8b9776372fa3d923f00d19db3972fb32b04a3167caa000550865679f1" },
                { "sl", "f6593c4c027a2da933cc2582f31a8247aed47318499682f39bb17a2828c431f2e74e1aba57c7bed599c6654c67bf330fba5572192e4576cc139c4778e45104f2" },
                { "son", "430feba42aed09a98a10253dc0bc2af5d7c31901e82381adc3d39d7d16709de5ac92a1e2750b237918467e43a20bd3f50fa9077d2af744eecaa7198484e4cf24" },
                { "sq", "4fb655e48bb92c62edabc9a1e907e617138b60bdbd4cdbee63ec9207578e7c4fdb8d9bf002c6611d4f7dc31d727418af3214dd2e172cb073a5b2c7e0a8ccf6df" },
                { "sr", "cf2775fc82be57befe3ecba6a29641f8240c4998dc9b5cab9fa3180682227c944b436c5f34b4c12162e562bdae22fd08b0bfb6d653cf2a43b797a1aeb6679f06" },
                { "sv-SE", "b66ff313893e0be6b83e9c1ce0b44b017ea03a861565e3f980543ac704635c01420be1ff1ced889d2f06394d4b31edc5adce1b9624670ed2dd41bc7a06c03a85" },
                { "szl", "6b27b2abca54a01165bf575ae2cfec6e0b596c5a3cf8afab5381a76fbf3c71d942cd5dfd53e6544bf983ce7e730e3c32778ffdc93bab63ef1a7e6f030e182d20" },
                { "ta", "a707863f4281c25fb0c9d160dbcb675aa5571e57a56bafc28d23a3feeaa83b8e6d03c7ab0d73e90a742424210b62d7947e6c345b634dfcce22a6322ca371cf72" },
                { "te", "7bd668ba629d727129d41631300f1887ac8ade432eec77b364f2562b635437c007461cc40f43794a1c4db546240ef0eab8bc5b1833fd67650164a71ebfd87f83" },
                { "tg", "d92db992aee18d834ac64b5aed02cf7add1e617ccd3a56bac5769511f27ccd355c84e4d558f9140916c43da3ab45952661cf6619cf37ffc3fe33d5eaf95e8760" },
                { "th", "da887d1cb4a6cd14c5a650a0a618a244f4a1bf7d75e2925ec69c6a6ffdca8bb9d50f7ae7eef5f99a66d66d186a729ede33b2d6861793994d1d9a2e3d7d143e31" },
                { "tl", "fcb539241700dc2740358aad935e07a3cd4d68f2538dc74bdf057153c8771790d658625fd95db6ed74ece4972d68100232327e080b497d5e3a2c936ee9dfbb8f" },
                { "tr", "82353b009f2359fdd1c44ad319ff7ac409ce67379b242afa7765c71be5c387757f8fe0c586cd82b58d5bcfeb4437f451a0085fed6403590b35495ad5f8751585" },
                { "trs", "2deb80189e7634a347cc2fbee800d444e8dcc47e1d7a319e27320c6335fb6fa4221e26efe4db4c1853e7d91cc7af6879c4e86f2e3fc297eb5319d56eb1db4885" },
                { "uk", "4542e986503fcddea14fb81795568b4f6a01f006d0bfb43044b67ab6ccf1e64436c4b3612b7e5a85c1052a95e2bc1df2eae9200076f106b982fb17d4f54129b5" },
                { "ur", "716e0c38c27091254bb99f9ca457a6ee1a0dace1ce8fb36b82cc0d6e8a44490fa13639900c126f19adb587f25c6d995a3e08bcaf14885d6814141f79b9a51a32" },
                { "uz", "f7e4013dd64674de9c2f3dcc4010fba31221aaf32ee5e73ae0a27f41bbdca9b19fd7a543047305ba93caa1212fde275bec505926ecdec064c2a7769031d54ae2" },
                { "vi", "f4a152fe69d37d4e7f78df43b3416bfe7b52cd003c15230799317354a3a1d3b19bf44f48e6079d6512334ee5a2c5135c9306c1b113a747b85f4be49b4bb91274" },
                { "xh", "d883fc42481a4e6522b7a69bb0393d5d02606af540ec3efb58a9347b0a40d641e7a00e91bebe571ac052831523b9f60ba96b30564556d46efb40aa4a98773e04" },
                { "zh-CN", "a283c83123bc6b48b1ad4f9d9f8013859c3a6a0b239d1cf657e3303e77fee1c1f89cb16ca7847dcb332f507fa0e7bf9a4efc0467b294de91fc6b943ca7c78371" },
                { "zh-TW", "a6ef8d35c3a3b3681059537bd932f9b9af27cde89f9c0f8dd7c02c01df998656bb64c1a3ec9c2498df08238a5e6962324385bae5eb3faabc41257713a14c9f75" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "bb7d9a9740b83517f4876dc79fd9f99c35312638f4993f7136aa7ed7fe1069e31c02552e36e3737db57568713d5aa436a341e34ec83459e4f41303410fca86ae" },
                { "af", "01007192adc8af79453be28bf9352d58a2f0a8c45c35214a6073a5d9094479b24ac0acee30bd43cff80d3d816561ae2a9bd3265222ab2e64177c1392dd43175d" },
                { "an", "17e408adeff62af63e7e8caa6d27c4fdfc675409a8ce4b055d121335a2b527e592037f1afdc965b73cd5a4a84d1f18acc25fa2f53728372f7283560ac3d99330" },
                { "ar", "75786f479eaa200836c4f4b1bfd2a06e230e6263ee314358a28767c341fa4df8751b860aac5728d8307146da695bf84dfd4b79cc7c52052b208c6539feda7637" },
                { "ast", "12c44fe2d888b33af54cfac68db5a9d9d8783a0ede365ba6c5037a535a6c3e9b5c5a5dc7c47b363a5409c7c8b2c54a37552d708557282537f231a57e1d49f8ba" },
                { "az", "c689410ab5318cfa82ee2eb52ee35333cf13239595312af69a50e288b9ea7e1a90f465f02f36ee70fac451655650651e5415fbb1529859d69dc81625750cd737" },
                { "be", "f5ee06ed03470ab79ca1d3df89f45e26a9810762c197ca132b785b7a83ccdc711f8770c7848e5e331d7a7e60c5062374ea3a3dc157eca6672d8a9f07d19b5baa" },
                { "bg", "f227c15d84fc708dd81f238f4027744a3b5f60c28b0ef5f6eb0125ed805ddb3660334f115770a079b637171c697d715c94e6e1e12b55fdb212ea60bffc57c1f8" },
                { "bn", "005eacdc16ae70dda725ffa566ca9658d6c1d3421fd166cadac6902cc92795dd0c86a34976aa3bf825e26f7356b63c24d0df2db78364cea6ef1fdd1d93cf3559" },
                { "br", "5e1e94319de9c4482bcee2020185d174e7d027901612a1204d46316218cf14fba7da10bd1d0aef5606a9bf98eb5ae9762262c85332f5e2a1a895a18512080b18" },
                { "bs", "f91ac7d9cc2279856293abd02432a70da719039f876cf40143241e0888df2503726ba98115c41b65b11c0b31c008838f39ec7777e5a261fd7133535690c63498" },
                { "ca", "fe9a28b064d97a96164c97561e175562c27fa11af82cec27b211fb57e0eb43a96f6588731f7224a5325ac183116370d104b1e6a01c550a0a7f65818649709ba4" },
                { "cak", "3c15818f74b1125a37a97956e8c6e1a601331bc66c8de10b91021bb8617ea9f089857864a16af778cf238f26665d7e4f92507394324abfbed2bd5dbbec8bc4f0" },
                { "cs", "c12e157d19603aff00898d8c468b512d1bf7300936b2546124b0cbcd18d4ff1eddd3e19424c2415780b25f444a7d2b850f7f05565c013dde286430d0750bcbb9" },
                { "cy", "6458745c07e6b192167a1adf3f4883a5de1a641eb9d98de8063d6669b4b8ac86314371ee72350aa5646368ae5671e61b903c8a966a46547a850eec37e5d836e8" },
                { "da", "cc819b38445106e3fcc45835d048caff249bd576acce3713fcd7df5b501356893c950d75f5827959be27555b451907cf69630651d3dc1c811add3b8a8a0c8b0c" },
                { "de", "a1acf3a403ed955368cb12c1341db7f00be507558e67e88e6cd60bccef69f935ffb5dadb3b863344be95cc95e779d6e56712acd56f60c8a7535da03a35824227" },
                { "dsb", "10e638646c8791f0b67e0eab459a894e980e8e333e239142d87b79a3c197477f99b6f9a14c9310429e6f8ad0ee5a593c7db9dac435914d91fac39f995f72e8d4" },
                { "el", "4accde881af241fe4d0f553c8b253cf6b5ea0dc74a2426e0ac1e79dc3ee8338da3b5edc87302048b0e21f94a0f0938c8321f9d14d7b7036ce4dc8abc9e1d3c16" },
                { "en-CA", "d1126a34899a37ce29b0ba644f9d103fb78cbf3e9282ef375b771bfbb078c0f8919ed3fff91319cfbe23853091d4ca2245d4a855a45debc9dfa28bec1082d09d" },
                { "en-GB", "15d7a3f8ce85aa6211062fa38314eff0d85a10662da349449c7cfd74aee1a05be4673f88a5e5a3047d1e7c2df07a761b862892de5ec3fca4474bafd185391c89" },
                { "en-US", "a81050d6053db1e37490eaa9189f5f846dc78420085e6a2ad522c235aa029ced67e67e240807d93ef3ba4eb423242b2db48f97db07320cb4f58bc554cf2790af" },
                { "eo", "2a6081a374c4f231ff3627de7b3ca6759c6a7e32737f4d95c2c341d2009d02baded3f251425b327cff08cf51643b67b203b7ebbe8aabfffc4ac2a7440a49ff03" },
                { "es-AR", "09a504cca258bfe4f9b3ab202efa0ebb9424d8ffb80d33f331ac26242603b5bdc3c03f58ba8f55d43792eacf7160978ed230447ce5af89e8fe741575297f6bf4" },
                { "es-CL", "54509430b89b88380c198b1ded69e9dbbd3869c4a5af7dcb93d565938951d003a6e9b97379b41659214cc187ef1839d9c221b46cf341f4b8c2fd980a1f8887af" },
                { "es-ES", "6e83a2d65a8f9e5cf8fba64955ef1d0fe16312b0ca24ad78e64961e145e5c7e12b05f0c7f3a54a0194e60341d723a968fb7af464b684aaacfda5ed18051f5de2" },
                { "es-MX", "8fbffd171da7edbceb817ac9cc6dd7212032a886660bb31b39a385810301578c75a1349538f512447ecadbebfb326a3b5f426c0a99a941a07ca1c0cbfcc1328a" },
                { "et", "5c4bd702c22b23862aca783e370f0e972bff2628c3a8ac714da8d6e58c7ea22166303f727cf34514d504694f78da78e779a1d10bb60f60a31f81313281d8d6e0" },
                { "eu", "22ecff530007ecb7846db3185ee0422cddcf350aa2f7115990063af0585168c69ff0dde38a3671f02040d388cdb9b6ca367f3eec85979ad75e3b79db62d20c68" },
                { "fa", "ccbbc7bca77bc5ddae8efd2d479f5c3bb5221526ab98d430a28897e68a28d112bdaf0264cfca156907cdc2b61500c1345d9f498333e4c6dfc02d6f38b17d3fc7" },
                { "ff", "23789b54e057402d73a55bfc7bf91a1c21cee51de488111d7f9e97c4ab2b326657b2a8c4dd7a511ea997fa25db6be04b2ed111f0b02f8b8ae0097313212bb0ce" },
                { "fi", "9d6390e213fd03c17db075c33a50d55b4949bed11b8576cf78a18ee4e77a6cf8969ab9d68682d9ea37ab8e903c50d3fdf309c683a5cb9192cd7de47c28e52d9f" },
                { "fr", "5242f6180842e3318fbf3e11993537ea0476e05f8a36110f14ec2b75902c832bbe42a5b869f15b75c259b949bd94d36341b0cfa47c23e9d307c8fc2696c1cf83" },
                { "fur", "1b7ed3cdd62640788613378c7ce3619deed9faad078f7807647c6859f994517e0a51fc57b7513ee020b85d82030a9bc5fd0030f8c7bc23d71c93041f3efea805" },
                { "fy-NL", "200928a838d4e03ccdea617386ab0a47ce94e21f66983c240548b70150837cf062bc123438cc29f6592dc6dd70fcc98845e697715930ffcde8870ccc706faf70" },
                { "ga-IE", "b4e4d6fa61a89e057762ac13a4c6603870c259e1186e35ed14a6e36a4fb35dbdf656b78284c1c623bbd8ce3ec2a7468db2df5c1d1c1cc0ccd191d68d659b523b" },
                { "gd", "0be24cd7c5c6484eaeb255293dc5b263db717719285bf36a9568053142761339afe22576c9b3b3761aac0dbd9c4cc7a16ace30d91b9803b4c80f59b96434fe4e" },
                { "gl", "e48860d247a00ecf895af72e603e89c4a6498381540728a941799bf968c52eac73a21c95ca4890bd081e24f82c0be7fbb95b5b21c7f3b907443760dbfa31d728" },
                { "gn", "4e03bc8fdafcbc980646ae4925b670a58f076e48cb357b1c68034fc11d74809805ff3eb811867c0edb5854c8685d8d2fa8c76542ed99c450ad69feb5c15a83ed" },
                { "gu-IN", "bb61e49c51dec1e08e93cfbd5008f4ddd2659f28dc46ef6671a34098b1ac8388647a40365e30316ce0a46e178bf19bc6fe04e35b46aa264812a3361cdaacd069" },
                { "he", "6a240681da3d2e236012b5b2bd24e3aa558029ff47b4e1df5035f666feade59a57462ea72bbd52623da97a91d0e5c9b48cec712d379394793bf93c9b17b51226" },
                { "hi-IN", "ce1a5c02cd60c72e54421061d899b0dc5bb3e9167d79147c9c615d32e0c63e1dc0568c10048fdec50d8a090abae28617e2e55010a64bd44e7b003cf5d6d5079b" },
                { "hr", "c00c6cc10466f7597cdbb09198dbd6826547f02532be4229673a4be2cce91f8e715467832b7e2f317407dc0346cdf37944d1d50b0aea7eeeed9c91bc6592136a" },
                { "hsb", "8187daf5fb410034553c6c20f4a3e011d33b73d36d1777c38b4c3f32334fcb8be7a2b80e551b8def5aaf18d31b54d436ce568ee98aeb68cf8cc31e912898781f" },
                { "hu", "42ea3d121e30613d6b79705d549fc966d84443df10b45d188ca603833242423246c65f9b1841b11fea3f3c5deca86583cb16911d235e93204b7c1865de0fc4e3" },
                { "hy-AM", "d4453c16c411bb9c51ff0e0ea2dac425ad0962eeb25ab77f20406cce113264c138acac7fe0495aa210f4d89ef3ab67f36e6c4a0e10c3780dc0cacc0deba2d636" },
                { "ia", "a7f32d1d9cdb30f78e00648413930524f3b47a4abca1a02652b9ab3a85e08665e1df5957da463e713e9d24dcee3295ad25f31513942b36009dcfb59f89d9c1b1" },
                { "id", "32c029839beb094dcf0471d18ecf2a96f736ba5e9150b47cd8e524832058189f479083712ffaa41871ac2d1cf9920ec1638567e971923807be6545fdce34b15d" },
                { "is", "03b50f816fcf4162e482c475c4dc4138bbd1ebf734d395ffd362ae5910ce9194b53da8a65b76377ddbc560b93928473d0d301e6a8f9057c2123ebf67071e253d" },
                { "it", "22e26bfa7df21e2325d1a2bd56f089ca90dd83ac2134a3f36541688a17b6455adcbd24d8650445e71cf41ffe67e62444fd53deefd9db8ef9b95c2b4c13081604" },
                { "ja", "8108c31c268fdade578f94c36e9ce42bc7738afc5db7b3bc326b10922178b718e53bb6199a51b611dbcee47a569e9e0f3c727786275b1fc16ec7c12943ab593f" },
                { "ka", "d22ff8533ce71883566a2d4372f626b83a8c358a82472405975d52a151ca3103f3e2b032b883dde47cab1c39ef98750071d8bfda94f0caf78f19fa81646846c0" },
                { "kab", "f1801dee7e7ce44632c922f5c795976fb0b5d1c27f249cc29be3af991cfd4ab9c13177c7963aa0dddac34b42587a6f29a62ff1010f3a9648bab938e1032c03e3" },
                { "kk", "1a424570a03a533ab3f480a407e4bf218228eee915d3c361cffe34978c81b390f7e6172fdcb7b92bae059ce60dd0b5f5d748f4ae74497ef6223e6200d1ebbd90" },
                { "km", "d522fd37c7be9a1b85b719f3e58c193f2d0352a610303d778636d967a18e416150800e7e37bd6adc6daeb0fcaa2d45e225d5920df392b43c69bb55e3af05d1d3" },
                { "kn", "3f78bb275a3284c33514bd56f342f924da4ad33516f7cbb36ede6fb5c85f95d2fa493578e4b822af7f23e98f1f5e93490ab7f1b5b7a447dd336a2780529cd02a" },
                { "ko", "dffc33ee58af3f7351d1de742d031efdd9d513f9641c6472180bd4a92fc4021765ba3630eb5d7cb3806cb8affef81d023025dbde8860331bd26d7f2b6dce5d77" },
                { "lij", "cf44bde5b6f47887572b250f4ba42d4dd85cb082a966380738654235659f8a83458c00be2871e1e802e7e99f6cec25ca51683ead79eb8f41f1c02ed09e994ba6" },
                { "lt", "a3855b7db511d80adf83c62e6bc23a3062112da0df3b28e90967bd0118f7182db6af1e76bcc5e13739d909fe50f0859f17cfea26cc4a638856d51cdd9fad8b49" },
                { "lv", "972124750c81fb5c78c41b6036d5237b2c030d590ef1d9923542392e092081e65264e5b1c2acd56fcd98df7d350c1ebcf4581c367a96c82f01f1347f9f112c27" },
                { "mk", "2f7ee9b010a40a0c857df7e3921a4fa8248fff4ec7b04b37350b00c845f21b935f98de0dd65cf41d41482a5a8a3a7e4fd731f6b38074aa3156c914326d0cbbfa" },
                { "mr", "95658362f1662f49dd84df7e082109a671098198b8730b1c270800860351b263dbe3645f9ee3bfb911e1e2ea33d13ae9efe35d43d714062828a7d1403efef700" },
                { "ms", "5857d030dd75540ca934c2ef42c300dae6432ae1b088df35fb178f1a5261ed6ef52ac5045573cc5d2b09dcfed37827318241e64970a003f30c5535e3eac04dc4" },
                { "my", "3bbed84a177a0cc9302428018177ab2c19257acfb0e99d047d12d3125ef731e025085d70fbf3f0fc5aed708a09c206cfd4fb211c085fb7d4c39aac81d2f9ab65" },
                { "nb-NO", "55a2e0db6ee3edc9e7ed33098db2db19b78c72baa1417df5a6724cb1acfa888bc2b791f51516acc9538030a3ac0d43a9ebf9eff8f2ffe1093c788b6129668381" },
                { "ne-NP", "fe05effa4ab2ffef6ea0e066d2fc8d5e05d2f400659c44394bb8ba94308be5cb7e2c4d35c4a5df1e4222ed0de17ace8efbcc71d2d4d55fabcde3812e5d1cc143" },
                { "nl", "bc055a20c341a2eba4667358b64beec57c6316691d903f6fcc4dbdb4e5b558d38e0acdadc958863ac143854f3bb0f18fe8cd937eb66608c11127bcab5e6cb0bb" },
                { "nn-NO", "a0e7ef90977eed33a8384d56aeb057b091520039285c45d02a758cce209a7ae74249b57cf50cdd324ecb8a4b4be94646b7f9ea6605264c1dea584c0fd75cc323" },
                { "oc", "5e655258baecf7a24d629a142567ad54fef6664b0969f55112ca79e2e25b3a4b4a59e40c77a93bfdf0d1a29e9e1da8009dd59fb811b8a87d428ee5e4151676b6" },
                { "pa-IN", "ee39cba21f8405b30127d7605b55a78f4b4192a2d39eb3b5e9cc35675e41a4e53dbbea2c028cf277853223d088394c9141b46bc8c8c508957e73561a6c819c6d" },
                { "pl", "3df3e308f5f60ef2f680126c21cb5445087f3865d9e9dda84c55d7a75594469efabfdad41fd14823db37e4b8c18b9c1665532ddf06c6d20cb1a2332b14cee147" },
                { "pt-BR", "7f9cc5203a3fcb1ee341699c286f0b72639b188ebc64eb9576e6e38f0cb2fc6eac09f751ff9bca6218cebc5b157b215290332a7a1344f0d218d89f8e0450a3d3" },
                { "pt-PT", "440f9aafcc408e3b2bd3306da2c54b219c6aa90b599993bb6dd929c5da97e5bdd819cf5a2d3fd5829cd4078a9326e3129d65b383b2688569dda37b075a829c56" },
                { "rm", "d015b1797fed272f09f820a964ac90bebe7fc3a79df91e18c5323a5849003f1154d0a05faed0c723a0989633b0671230a6f5059eff25d779a1e2d427996f56c1" },
                { "ro", "430f97290437144b3de55ab98c53995a0e69eb7b5a9a3afcf98160cabcc3954111ed31cef0d2344ab02dd13c457b1fe60a5fcd4e320539628755801dc531988d" },
                { "ru", "588e2f351799d1efc95c3cc2854ab464ae16fc2016185082d58795412efc526a63180aff6070f4dcda804c40eea12defae3944073195751525fdb4f8335f9ea5" },
                { "sat", "398a3870d9e20c4224af84d6a751d3967bc95e0a5cb946b94b6c46f6c973a058118f2250366cf0982e8c68c105f0743fc074f2f1b4724d89b45e3eeae8a94109" },
                { "sc", "6eb46a47f56d7c9781accd469129ab78e0bd3e79ced8897d203b2a36292bebcf0087e026bfc2b656b3e0d860bd178bde8590850c2ebe07f4680d14cefb175f77" },
                { "sco", "301a617155822e2b0bbb3713cd5de53f5c374be206f4b8b937e55633e5b9a509792e4844cb321e1d0c6bbb08f5ca084cf2e3d0beea10e407cd7b29da6ef35e45" },
                { "si", "0145bd12df64ded9cafb054ed4b84070fb3af627706239bb7059d334857c4240be494e0a756dbd09cfdcb640c9ff335d49ba5cf926892a08865c0efc9a9d86db" },
                { "sk", "c317e630c91081d136bbadb279f0ec2ab02d7b9617a2655e093f3fea677853fc761bb3a2d2e9146438e2f7f5103c378ba8643dfc8c2e8c485094f46a3814fb10" },
                { "skr", "a7428e56586f16e675556ba91cf700650e41e6e0e64808872f82081c6e2378e4db6bf5e14e2892e81412d12dc21920ed5935d1dd52b882c5c1b7c86548029210" },
                { "sl", "cead84498e1520273a0a4419b9b376d3ceeb1d2c420757b9fb7a6915c4610c67b3df7efff52a1382f78a4cc53e36a3fe0b6ac8b40b25a97ac47e7f5503a1597d" },
                { "son", "80cf425c8ee55c53280b92ec1a54879627d9549f5e8fc3e8cf5e0fde998d1046c71e256dfdc6d0448715bbbeec9911dc4a30802a7f4a1d0950c0024f330994bd" },
                { "sq", "d36fb06b31d2744e6aa135bfb80637ffd4833e005f171070c44e2fd6061b8ea7d03d99782f3e800401acc7708c7d8682a4bab872bae337aa196ca7081e4a4cc0" },
                { "sr", "71b7db6c4d260865883981ec7340e1f021e1b5c95c0fee841aeb44bb33cee18796947d328f69d84d53ed4ab95e8a691b5bf847fbb952fa09db1fffd85b4f1204" },
                { "sv-SE", "aaa63496794b73704ede70c43b452f6e74f093da3e1c09aebb5f461b0617ffad1e79d8fddcbd1503f65fddb979c27ab6b9a25eb3587d102699b35b52f82eef95" },
                { "szl", "b89f921630eb03fb3580587b9196e97f0ad7dbcf65f00404d2d263c7aea31ea61b33f4b2fcedb2e12c924cfb8b874f022b6d918091d60f20bd3b9beb1950abe8" },
                { "ta", "16a7141a627efeef82987750795be4c2599434689d21df57a279e07f84c07aef5ca12ce8bfe4d2afb3f58e433c63babba6a19fc113bcb7972504f6d8b5ec8c39" },
                { "te", "80c50490bec9bfe05a2c0bc4c70d94234c555bb6d8b3729c09fb66f2ed3ce4b4664de8fd4b4ec9b8166304520e12db694768cb5be0469b2bc5630f8e9b09d0ec" },
                { "tg", "98949059b11df4c814ef4819efca68e63b16d63324181a1c495b16cfa95a53510c855f3a4106dabfb27603bdb58fc700fcbc1618bb614bd52e8b68950f3d87db" },
                { "th", "1722105bae9259d5443ba393c9994d9a3e41b0c0b6cac50cdf0ff0e63a301c5d84042b5b61b64e6861d2dcf2d31259d015676e599cadde531e51b814c31729d4" },
                { "tl", "4b08f9be1e7c67e5777e6231e665462e82539b1c8da7f50b56c89fb071b4e59c88c3f57cf20be3f2e8c90850d9fbf35400029e38cc3644baada7f138ccb0b9a0" },
                { "tr", "c9f85edec242eedd667466cd58b7fd75f76025fc4c00a40855194fd6438dce4e492ada8c44d12226930ed41d66ffdb113b85f32236da83a552f0beceb40e1ed5" },
                { "trs", "7ca5c77a6a50650df81236f59339a4521209481ac9f0ded9fb160bc00e0af22c19f5c18f42c44c572c6b039cd1265f8e03c98aa87c3a023c3f8c0111b535ed22" },
                { "uk", "5dd1979a65bad342caeedae0260611b9e38f8195fd663104b36de64d8f2894f4a6a7d2ef480c91967a43d95b8b67a4c71b3c47bbf77da1cf9abb61ae7921a19e" },
                { "ur", "a265e43547daeec7db0698eb9fc3e02c36d0af38f7e1aac55f6421ae1e2d6896d4a222e45ecca2bb75fbe70815909fb29f6914f04fa71b9e2137f9c411f1cbad" },
                { "uz", "acb543cb0eeab1166a89aa51e5a1d6d7b805a7a3dfbb05b34264cd54f4b6eab1772297232a4c911e6b2d6c5dce76e5c2455ea3b7893f232e03c8abc55d522ac2" },
                { "vi", "1107f1e3ef0f10a4e50ce6169e35dc17d3da80e8c2aef8e2480fc26dc41408d7ec94d3a4a5977a3db40d14f3837042e701066a9e58db6a0747b8f05a87201e17" },
                { "xh", "5eb409f7b3b24dfa65e7587b161ae9ac4ade94b26d57ab6069e63170fb9a72ce6d6cf0d7de17f91d4519280a0c8f764fed1307eaac702a3df6be7e7363ccf53a" },
                { "zh-CN", "5f983298dbc000c92346408b60c112b95726b642c89b8785e0baa83706f4646282a6483686665be26487f9630fce0fb70e1cc348615cd62efd661a3919c2a15a" },
                { "zh-TW", "014fb2472b95942e41f5f363847e6a0586b107703f73c7940e5ddf9c7c482305e6b57fefb507b10ffbb796c60df7bd30765cca8bf24d5d91c44c911d050161e3" }
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
