﻿/*
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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "124.0b9";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/124.0b9/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "6cbf8f081a5745d04283d7f679d1ead1fdbff91f95f37d0b190bdad006bfa62375438020f63830631ec29f41fbaf27ff96bff0e708123a1ccfd6e2117b19d1f9" },
                { "af", "ea79998a3d38a52f144ed37c9debbebfc6806ca861df4f4178f97ee7fd811a1a62988d8c5f4e9406b9adbfe6ffee1f8d2cedd74710440efa2d2c6424959bafa6" },
                { "an", "f10a4e9e95d8bcd3155e294bda89cf74011a844de9252a38f6acee48c0e4c5151c75ff3403784e018b8f0f77248d9632bc4653252f375269dddce7e413a29947" },
                { "ar", "570e8bddaebed38211a7aaab6171d26dd2794ee2cc31913191ebf96f6f30e87e02a484eaf48501298c3649ae235ea1e3f4448b3c39f4fbd9f1c389c322d415ee" },
                { "ast", "4390cfe2214156a73531f79a7c85351527102002501c1e92b45112b40a0dc8f1257373d24f396cc5f383edce5021933601346f66f8c4d3ff15387dee7e8ebd29" },
                { "az", "6b88022dbf4f6f2409dade5e10f818f4704d1dc35213fa1ad7a6c2d4fac0cec438a7d846755ae3f5a18aaee919d3c07f9968eaa593f4cc0f00fec662e4841687" },
                { "be", "aa3b76af98ac1cd876b3651237d271535b10fe8a5002b631b0025914133e13c3284962437723593b78e4790154b3324862a5902ef8021ee4d6f8982e6d9cc1b5" },
                { "bg", "52020c96a191b6264ec1ce956eafb0d7233e2bb4cfc0dbe12326cc7c86d6db47e1ec4b3e4108fcc47067ec5f6a9953ac36ad2a594598da2ef75c3981036887e6" },
                { "bn", "c3eab8421c8ba0730e66ca03b741bbf84fbc14fb970f2ea00d784f4b9c6e33fc72477419838605e9897e8025e88f489f231a43a7f03ba55b2710cecdd29132ff" },
                { "br", "6f5cb24bdc406686da98bd2ad56182c61b1dc7c929c5c02627e716bf34d2c4a5816d0d89623f9069dd072199ec54bd7fa2574dba19e449275881ee6ad76726c2" },
                { "bs", "d797f8e0b98521d57280e9679f0cfda69ba5d3977405b825051c32d9adf8bfdcf1402015f13e9ade532feb47e4bfee1ebb5a2ad8bb0b1501597682ec930ccba2" },
                { "ca", "dd8eeb2fe109acb3e56e53fc168e237a6f614ce80abf61a20f7c09da3691ae2cd09d9d0fd3f13501edae1ff976cc0e886b611d06a96d44f6c7c374bd9f704bda" },
                { "cak", "067424c7de658d3eac621c96db1f88a82a0b5743272911fda74a64015eae0228be395e8b5aee88a3918fa72272489dd4be6cac3f9c391a48d6b2d80dff8bbce9" },
                { "cs", "21b072c05051832361b485b010798dbf04d8c5d24ea22240f008e17dbc899e450c6b1665c97f98708b4ecad4bf2f62d80051ad3e69e2ef7c3dc155cfaadb509a" },
                { "cy", "9991a5e04ba22e41dfb2c2262aadfb10d3ea909f1cae2af7c022c4af045932a2fb59dd26cf28e7ce9f174a93c88fdbe350b79227c2f7e414779784cb6ccbef37" },
                { "da", "68959bc04fd7b9b3a9d4b0cbf075c32f47df17498d3f76f22905b9cb215ce15805648f80b76dd6c347d996c86eefd0dcc7893f605cd2e5f58aa7356089243024" },
                { "de", "1787e54d6ac53693d2738006ca5dfe212c486136a926035407df733ab5ba15f77e4a2c2e918b5351de7ca271af02080f65a4dfafd478970588ebdf3a03ddf123" },
                { "dsb", "5b835040da1deaf0f5dca142661874177f0a2387340c3a407847ec0fd6cd8e44d7c12d2355c1a4af37c794024f448087417b5e9888726f53f43c00f07149977d" },
                { "el", "f426bc9020616ef5d28aab55009c9f9bdcd8c1ea1d1a90e706b46a878eafb34e5b89d41d307b378a769246b1cf3b3c5862520861da355f930e23b1e225882504" },
                { "en-CA", "09fee1251a5b2dba345cc3d26885a941011a40bc71cc65c79dd5afbda0b225c95dffcc1b75935d7fde97b5543f3b1c24174759cb5b990a9e7328faa5d84421fc" },
                { "en-GB", "cfe33871f59dafb32c12384226a2a6a61470d08b0478aa37146d0f2518254a2588e3da2823eaa81a7f54c0a0e3620c352de811ea6b3ac5478a012014c834e556" },
                { "en-US", "5a30bf408548df324dfcaf7ad2678d498323161b676bb9c32ee33acfb6a2028fd5b503506ba09a2b886dce4309d58894e2def1917b75cae4943b4c24948f5676" },
                { "eo", "62885bc75a1d0b3383793c90e25bff0e270a1d9acc4539a0c2c6194a1671451188670518ec70bdf5f540e333a06200ead5f0a3c5673c0f951ee85a3faa598ed9" },
                { "es-AR", "0f4746be1db7207e505ff996f0d6eae1000f28a4786099e700b0e7976ff64314d236b9aa03a747fbc0e84ed72d0ed6cc999f59d3f48951ded50ca1557f3634c7" },
                { "es-CL", "ee8213354ba4818d17768cb310c6819ca2a43019037f9cc494ac6d1f62e9cefe53b3765ee411ef6bb8204fe4de751218fcc5f67c423e53b4e2102cc7b487da04" },
                { "es-ES", "b518cc10806fa39c62d6eeb03080467741138efe333b0b02af0af94e81d165e7ea81a35153fbd5fa837b29a409645a4a5d5f986b6ae6864ec9e9d8b5f4efca1f" },
                { "es-MX", "b15df9ed44cd43b7186d86b5642f0b96f06873aa2b73a5f73b98964ad9c3528849ef7e83c394f772a4d6767c598917bce79549210841dee7d3a0f10c3a9ce2f9" },
                { "et", "060d15f7d41e751af4d590a075772f7148fee215a8ef65399642104080a30453a334e599a5083486068f50b8e899a85885487d29277cd41a499ed263e4ab9070" },
                { "eu", "1a1a3b8e73294dc7cc883e607e6c7934e9dc4617c899b8f6cb216f7905f3d8f7253745aa104005cd3f8a91c0b1d9f2d44d52626eeba9aaf9b7eab7bcd2dd42a0" },
                { "fa", "ee25a86b0e9a711916488c5ff956ebb17e85a78f9f09a8249c617593c2f041b55b7b0f4bd8ec710835fb5301b1d5e70bca15f61257135be94beca338776abbc7" },
                { "ff", "49d3b534458a00f8fe235b2dc61b3302d0dabf99bd628f7973fc494981433dcb903d9a416fa977c1e35f02e170c87751ec66fc3a819c5e6ed0d7884328b7c38e" },
                { "fi", "5ceb729196b3a0057c328be27122a98b67595d79b44aa9993bfe93b15fbaf7fc8adaef9c99d147ce2b5dcd1321ad92cf00687a252d2c341f29e03359dc425ec9" },
                { "fr", "c2541bfaefe2ac39b914918fa047a7e36664b99c1debe153ef683962968769b3bec75e608a9a19c659f927ea06ed2fa429d2c748a7b17c168245919b7abbc336" },
                { "fur", "9c4c3a0e32b7e39ed46a0177ad937b4459e72fc4a19a9981d2b847af369cac29bf13c2ed62bb0b01edfcb1568d062b9c971c15d19efaf27aaacf6030fd2e4942" },
                { "fy-NL", "12b3960695887cd69f9c82ac1318e85a7159e8ac84b5b694ccc5111f3f540ecf8f4f074ace1b8376ac0f9732b5eccdb4e600f16238f00bd2ef91c7e13726e9b6" },
                { "ga-IE", "244f6caa5b415f913278201497c49b6898b60fff55cdfb6db268d85763c59993612537f3708e6d8bf8ebc19c214f8f2cde10ea7e1be6e89f90f6cd4ca0e3ce3c" },
                { "gd", "d1d259c149395c4f8afb9ba87da5103f29a0b3239825b85a47662de87c8f063f87b2d11b45bdfbd6d8efd9c5fc40a2e853557f617a85b94b5a618d2d5222d391" },
                { "gl", "9f63517f0fb91ef54997a935a644d6c10c6a6b6a7835a9683dd1a98e4fb6074280f63c2ae04e79f3ecaf619275b6c0270df7478cfb032290d1e3bcd57640c0ee" },
                { "gn", "172e835074c22b324ab1612796ee2ba13c6d2e9abfef6bcaf9c5ecfe8e77eadb4a9ebee9f8ff37bda7fe0a78d8af4a2f1e98f4eb5f25dd4b195e529315e1baeb" },
                { "gu-IN", "92be7fb510aeda39e5f31fb205608bc879a989f60485cf98c2d1ce78ee4566e3df1225dd22c0e8f3c833300fff0b1d4315de3652868141aa0482144af2646315" },
                { "he", "c28678eea27038a63ca3d36902d764521e4d28bd62d32c7e54d9ae524828ed656bc81730d8461f85ac81cfa30de3c738740a9dfa3ce7bee4834791ea46901c8e" },
                { "hi-IN", "33b80e031f343b155ceb7b04b9697a85364c4771426f74911c9c807ddfec691e9b3f58127df8d3b8f337dd088b2d581f42292ce44f35211c0708859e959f8f72" },
                { "hr", "255aef2b02fd1c4fa273ac5c469206c783a0c2a4652bcf6519448e740fd033f353c05d1557c8996d424c6e6e1deebcd9831c6171f645c0953628bb1b8e1acfee" },
                { "hsb", "7b65249beada0f257d6bf84fbe4c3dfc19a6c2c2c8c77af8d3d6022637d2870ecbcb957763eaa3b7954965e6b00e4452f88123452c073613bd0061a05d497e6c" },
                { "hu", "6028ce793db03a4d0718a36271d47781cf7da562559448b06fbce1d40c6ebe04610c45fbc19c546e5b4491d87a43077c9a6fa6c88d8ad1c89f7cdcbc5c9c4f1c" },
                { "hy-AM", "38f0006f78e7a913f03e71e798c25c9abdb1ddbcc8cd1479993d2f6ed32ce4a9a15efcf3ba3d23a21db4eaba0d473be59c579a7f28e1d57217d442506a688cf9" },
                { "ia", "a77f77d81d7e0490808601ce99f977638eb07e6583850139efe4de49a16a4bf05c7a42c32bd217eb7011c278d8dfe71ee2affbafde165281025f4f29d89e9fe6" },
                { "id", "ef2f558b1ad588937466302efae277b90809c4894aef279b2e9cb787ddd7c6cf91780fe92f683e91a642a1efc9f87f75870210826d37bf2e80f8e3f62e3cfe75" },
                { "is", "9a8c39f99ccee7164d7268865fd9854df7f02d4950bb27662df616667cf9de19e0baefa168769c0d57c5ab680b4c4f5ad6d921c396c2d2e5ec4f69a14fa795b6" },
                { "it", "8948e030a5e2a7b49c79085328bf0987364fcb80431beb92e0b24af0f2d8b861a93aeab98615aa45b12a594de041d6b13ddea30ba99aae604dfa2c0f5afd0f0d" },
                { "ja", "9e65bacf51e93a53d41827da0777dd8cb9e89834e05e43269dd84de9997da3a3e3332b5e5d90aeb715871ce64ad72e2eaf42bf5612d15a3e6a842def9aadbe8d" },
                { "ka", "c5d38cb7da0a51dac5a59ec229cdf46c07872fa9520f83c8deaacdeae71ee90ecc79844b798b0d6897fd50c90ef0baf5f326627a344c357ad9aaed3885068d3f" },
                { "kab", "bba723cb766ff09f7aa1c497eddc7c612e2349b44c54d1d7c4a66bb528f5a17ecd7cb026caca795c374bb05bfea258e72f3090275db96348fae8df9dcd0f610d" },
                { "kk", "dbed463e70d68a56c5b690d64da27fbbc8fe28969d07e6328687ae265146ce31a01b56889ad5bf251c69502a6db15270719d158edba86c0e2430677684fd6fd4" },
                { "km", "9ca549e9c4b690c6adbfb58f94e1fe28f66702c8744b8d9d0907fc14b77c1ddd09acb9c8e123cbce3e63a7a48877e2c5ca0d92e0690bbf47adb846a6549e6bb9" },
                { "kn", "e6dd88972509f13913b27b0ad052245e2126e102cd84e5129fe0b1ee39a70c79df785adaad8494095ebe3e1c670a09e6805210fb2f53c26f83392fe8ad70d164" },
                { "ko", "51cbf904c259e0b9478501f86001ddf28859cb96aa0ca3990c7a93720c4c22f2735e73653b1b9b9967b2f56db27dfbbdec3a41af34d4b2ad9e656e8965efe36c" },
                { "lij", "18e432242242532151a1103c0dc7960e2081d953b81a2d66289855b82a309bcec0c89c9fd5cade478347deaf66189f7feb477ef10646622ea4f82fef5378a78e" },
                { "lt", "580d98fb5543485ec0ab682754a32e20415575ee2e99681170e56645a8917c695c8cf29e15b6fab776f8360e7f3a9f4fc1ca900c060a88de1b633ccff3d325fa" },
                { "lv", "54a25a9e22580caacbc10f59aab300a1169a5e702bc9e0b315136e69c50f0dce6152f9df2b62acfeccbdffaabca56a82253f1e77e6edca38b4aa519d28791fe7" },
                { "mk", "c7308752dc379c88b0103213e5a0e32eee68ca2212515359cefc8f64f2ddb757178d2473b99baf9f55edfac5af84a3f57841a82431885c3e8565928ce66c932b" },
                { "mr", "b53783efed79f77d45e348babf198d0d35e596bee13a2ab941a52e58b7bfd0d8e3dc86acac58f545ac71dc5be239088290f564d717fbcfa335707a271f63eb79" },
                { "ms", "7d05a0f029579fba6c61bb021f9bbbb56a4ad669e9d536f7fd46177d3266d6df3e2db0c2de921f9e22117085d01d6fc612b592c2378474dbe7e1e23ba85c10fd" },
                { "my", "224ac2a1a6c6fd7c8c1aaed5af9ba7b86a833a8cae79605568e5747b40cd3e80087932b13ebe3f5aa51a20d7cda426a9233d66bcec7de408e4ed7da471274e70" },
                { "nb-NO", "173d4458c1c142c36de0a331b0645f3560bd06a2536efdb81db303bbd602382f3136b127a955b62c98b59c80034b797d58e62d09a416590584f99438612aecff" },
                { "ne-NP", "caac9860f03e938b4a1c342757a888b9e59b8e9d1424d90014a8b90c25a85cdce6fae07c69e9f68223e4f24d8fadc1207dc36b0290edb5ccb6e9d24999c279e0" },
                { "nl", "87f5fd702ab8b00a1a9806cfa543950efdc9833a4137527a2f7af16858dacd45d2e5b03e9c49ffa38f9711e6454e6cfda2aaab09c7df2ae8c3077419a66f18d4" },
                { "nn-NO", "bb62a483f8b48ffa67feae4632c1f262f96616ba4e639db90af95031ba0879fd802ae360bfcf8a0482f9132e80504becb2b647f4ae2f60c75ab79d8a87e2e258" },
                { "oc", "0b11894eaa78d4d0f3a0026dda8a50295459797d18959055fbb9358e3f81dc80b911cdf6c44556052257881fb37a741b25254335bbd2eb5ddbe7bb97a164b72a" },
                { "pa-IN", "c078cfe7dbc384e1bb00b7c2808cfa9b7916a60ee77869d4c7bd336b21d9aa20bd7ce6e022f3ff25144a4e693ab71ff4a590394688f7ac88db4bbeb14873dd87" },
                { "pl", "667e0635f895139ab9ee54b5663dd301e2ac6dfbaeed3fb9e2e4dd87cf8291b7e91d052a56ef269c4cf8caacb06466bf251ac60c3218f81561e1082dda2767fe" },
                { "pt-BR", "de7434ddd90b41e332961ee4e50e0d7c06420d603cc6fea291562f316f17e0ba4b79a19d3c83d4bfeec1e66efc1fb5ba8a87444a589100a543c16746857183bb" },
                { "pt-PT", "f831c31e4b8966372f9d14ca2b90913ed35a1eecab1e6436ba901975254bc95d820d35ad1a952ebcbc8bd8d52fd003d59c00161bb947ec56453fd8bd5f92e0b0" },
                { "rm", "2229b0a1c91f4e1ea5351834e45406c8bf8be962775f8d35abc49c3b459e8027524c13ef570a37b8bbb2d77e4775ccd76caad74735ddc0f4369b659921e6d71c" },
                { "ro", "4f342fb22c8f179b415c95775e0fc756e8e488661064b6780105671e9af6ab61da3e60ddf3e8c2d747f9cdbb61ed2b6311df68e874d5ee3bd6a80c536c6261dc" },
                { "ru", "061d14e99801de96edccc8aa494deccb60ec1338ebb910280ca392182cab4addeca1f1204f75cec4bb70794d2ebbab558ab6cff7a3fce42ced8656f5cdcbcce3" },
                { "sat", "935e9d83fc6ff9f1336f8137a207d3bbc3aba6a9b936598e2f5eaaf673bb4188336bdf1bfd851ccf3b87010784d1a5af6c167e8eb3294d7f9a98e5f55173a71e" },
                { "sc", "c22e58bdc444b3878e615b3ce84f7d78ed556da73e22ce440358adccaeb89c052828fcd4f6f0b0a09f4582d1d1bfaa2252fc5821b54f5e201cd186d172668ed3" },
                { "sco", "2d2ffbfcc719ef1b17cb405e3cfde75eaeb348e53674c584df7e9490351b54b8b57398adfaa71f4f9bf6d9090424bbe8137ba9a6df84c47046f063c2e67b8404" },
                { "si", "7803ddb78387c7be0d1974db9d252c0799beb7fdec8cec35cc3823bfa67ab42b1bedca774ab16ef315521a0edad5dab20b3504ec67e8e5968025f56962a5cb05" },
                { "sk", "6b0484942c66e9d7f885ef37a7654aeb6392c58f147f8bd3a28c80d1b95e6f9ff3925154a5b98a74fabd12e0a03aab7455e59789f45fab39087f95cfbf63b3df" },
                { "sl", "ec842af578b74efcfb850d274af53b122fbc7601b409d5495276bf0805d12e9df463d7e9d05fe73de9ba6754743619c0e58250da005ce87bcbe4c3b6277449fb" },
                { "son", "cda55ba6661a47ede283669572af00cf0944bc446647ad745babf1fe394b76cb56e2a38d9e02b94dfc11e949496444a1acaa92d8a7c68d09c504a6fb5324a8af" },
                { "sq", "50af21927525d5c8e1ee765f348df66dcb2e2bdc9262e0294d325e181e32fbf60d341c7af3430d29d8f55b7d06633a0d718d95498471c7d355a5318934fd7a08" },
                { "sr", "cc873641a756e8ce0eff174784a2bfae9044c24b5a3d6fb2f39f5826bc635dc1d2089c52c6362316d9feeab4aa7d993ae12bde45fc9e2994e4f63b5cc5fa7486" },
                { "sv-SE", "46aae8af21b3f7dc889aab7d7fc6ecad8dd6ffae13a325da379c41be53c237cd8c7def963f2694720f38d2fdeacc6e66a7a4c69237f0851e2e3ed8a012140c4b" },
                { "szl", "1584e14b1fac81ae821267726a3f1b393b3e4dd809a0fea8db2e04be0e5d40faeb85b15c4ea27be747c1d56ed45eb21858a236b3ee971de1a9ca181bbab924ea" },
                { "ta", "06f3f3b567ad69d5131d65fd8f1fa9a8886f89484253d4494709e04654c200663482f91134f808acd77c6939e9e76790957d8aeed27de8dbea7b83b415992af1" },
                { "te", "9c158f732e557f2b8874dfed0f3ee2ecdb69874ccfc20ec985618b5084ff3e59da53f86ce3e898ca121de89cf4448190e6e01c815ce4e665281ecda56faee185" },
                { "tg", "b77a5114499f6d4bef0e5c420cc06e5ca94ba9bec55f66ac12a26a3aa8a1f981ba544fabe4df2db026e251a96e129fb95e3ad4d0e6b71e39d1b10e440891063b" },
                { "th", "6c0e52cf4b74fc86fa0e8249e7c7223ac0dc0e8461772f5a5e2ae94f5f78ac7559cf1822dbc3642a54aa066f56d7bb1890bdfd8b201943fae28a9a8be633db03" },
                { "tl", "15e0133add13f91b72e47b0dab65c30f4529a86b1f46780e25dbfcc2b07a36228c0dc71e8be55baff993632fd7b8d44efedf51f1783f0e539078e572ff1db96d" },
                { "tr", "c842a3b13359e200bbbec88bfc4c87c8b9ae29ff778096ccbda718f809d6b70d48491ebd7091be9c4f14b409dea42b56821658c82ad588f8e3466e753061a773" },
                { "trs", "6299e6db033fed5e9ea0231fe8b35ccdbccad900dad45209dd707ff70f02272322874ac05d14a464b9404e926a62987d513636add2ef9ba48a4c7c8eecaa56d6" },
                { "uk", "6668f1ee02ebb814a778b67f2fdba3e99b54d02e29c1828eff912215095e304963460951c953d24a41f931d11171983cbb99a9b1a261785e967dc50ae7199263" },
                { "ur", "5f9aeaaaaafc8ee3f0f7a34851b34bdff96875760abc66b9f898f8c0ac2d4bea6b962f5c221286d2e82e2a10cd54bb163835202e9a5bd0800b8db9a8a0ac375c" },
                { "uz", "0d0676afcb7bf4a3baaa21688af9c8d9ba5b2b8711ced24558aba5f070ab478f1876e74a72ef002aa8baae530dfe22312691377f41f574547c2a775efdc9609e" },
                { "vi", "22486f21d59f5160228f3f248205e79c474dae693e547e2a4e8e9cc0eb171e72812d0ac8f4e85933680bbc90f04bcc7924b6145019cadabab657fe460cc0eb0e" },
                { "xh", "80c32b2f9aeadea905171cd83db5ea9cd93078cf9b1935f57d5f1df23f004ef2a9dcc968f6fd93826faa33a29f75fe9e385ed8bdbcba150cacade736ce87e25f" },
                { "zh-CN", "e263cd44a8ffb64f10a6b14e20727bf97d1fceebc0dcf224d669c2f9404517c2eb82b66181f232fe458b03ae9d689316c2c430695ea879a5c8df88e84b1a5611" },
                { "zh-TW", "5c6445747dd116c248333da41d53b2d099caad11c157c433c395ce93ea31caecc529ddad3781679cd20f7683944475b9bd58a483c39bbbdd705875716d7534c7" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/124.0b9/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "fcd1827822ccb152ffb87f0281b4f9b82e46017500ac24559e3ca8cb31625afd08ca0da7f1188c645e559396ac630354b9325b739ff0561ae4090d330e4465ce" },
                { "af", "8b20e275a9ca73ebbc9fe145da130073845fe6dc6896463a42c650f08a0e22be97e00e39f4dd3d3c2910f3b19fb1338f76e2725237b0ece70e8cc228f023a30e" },
                { "an", "66724520d4c512a61f614cc51ceb1cc55f96fc751f5e47886ba0d85bbb6ba92e12d5cfcf7f1eee1a9461c45375aad7285849ec9e0953b1878726514a17b63a70" },
                { "ar", "b50fba6e06b2c1b6b231b1731cb817a9d0ab4ba7abb8dfec11a454de40dd0f5512ae731358db6d60aea52fb8597a301f2c507814ea619f5c07155490e53190dd" },
                { "ast", "0bd7ddc55670199a8b09ab5c1bd5ec00355f41dc006ddcd9792caba2ae756fe45466f87550d99d675558afe9a9e010c7ba0a8c0e1a63a861d23c44f7a771ff49" },
                { "az", "413f92fc51d7d7be7988b70268bde69ca38c9614dec16972c3ba133092ed2d00ce27817e2e10bcdada9f2aa60d9159ab83e4d5d3952b9ab69c96c9f5c1d56ab8" },
                { "be", "3fd84657378f0b96e23f6f6f9a0d64be9746fbbd91a812445c8a594823f62627ce6c9b5cc29b9facb26694f07fbe64c5abf3b0836c8d93179f8345199f9c846c" },
                { "bg", "0002e89bb5ac2d262b41e9633433b0231b9e0fc0cad34bf40fab3c58809b6d89b2c2bde1cc0e93f1a98cb92312d8146bef4852e54ad86ff6dcf0cffd62a07970" },
                { "bn", "9122a97ebbff3f787178c9b585b4d43a3d7aee5605865d39bce00be64c134cc0cc61d94e0768def980bfdbaa1b244594713e6912c26ecb04fe413e914014baf8" },
                { "br", "26bcb0312a95f80cc2e75663d6488e7a1c19a3cdb0563b4e304ca9083def2ea245e9455142a3f50ce15aeb08cf8b91ba477580fa496b3a556237654a3f8c98b2" },
                { "bs", "4e5bfdb486c69e2d15a8d991324522ae233ea641177f0ab9337a80ebeda03f1046d59f64fd804969f6be26ba32367e2437990dfe6eaf3dc6c8f77c55508347e4" },
                { "ca", "d3f08cc50bb4be14800130ceedec8a4329df72bade208cc90f3ff0d1e6d88ca71cc226a358734bb10035cc040f56a80db1d6183dc2d90e31b4fbc8c35010697b" },
                { "cak", "9cf0837359594b694ea4ec71600f0ba008cd2bd7603343eca53537b2a244091f76eb7506981349cf92c22aed7fdd7ad2afe6895adaeda2844b9adc46897a6265" },
                { "cs", "9ce9fc6a48e29c4805b931b28b9344d3269bf4dac6550a878098176f734666b0597c630fd25da7abfcc87a74fc59c6f14a136bedf2ddce12ac063c26e08e5a30" },
                { "cy", "01d3b000de088dfbccd6a317fc023eaef3e00e9e078b3ab785fccd58f7558cd3897de7a8c585ac6b09582ee3712d3dcfe6c8bfde8536e76e22ea0a8f35248cac" },
                { "da", "3c44de183c1d1c822199feed3f2a3e597593e80be7ae4d1e51469592577492d1efca9f819a97949c6797baf14c208a006af04c337685976ca9d1f3a2609b63ed" },
                { "de", "6b30736a47c7ca79f3e8f90dbae9ac876fbbb6b2167c8c28354cc3d54a2c34b82e6949899fcbc0fc0fc7612bcc0cacd09f94acc71de8b0d797ef27869804632b" },
                { "dsb", "d28673748403464132e685308574185d90bdb18fce908e5327c03d0f725ae2ea0cf107914cc088a4f9d3220fe8705be7903f434e5a10a8ae63779458e6a53edd" },
                { "el", "2e878883749eb4db76bac29b2397d584726785126061b9c15052a29216a1a1cd80482bbd09897503f7668fad15c4f3f902b2d0b99efbf5df7be44ae1c25ea287" },
                { "en-CA", "ec3f02ce07037e4756e4398ad7f612330fa9419d901bbaa2f0690c2ddb3f8115b3a4dcb5ea3e8e5ad665868712d56ee36bef54f4f4e50cdb83680a779ccb5149" },
                { "en-GB", "56393f5aaf175d067bfb304cd5b5862a14bb8487ce9b921b2ffe8adb9672af8060a9ce1c0bea2dc27746960f6e43ba72405ea42de8703fbd99f6e7c158b07826" },
                { "en-US", "5a01b560c735c8c2c64f67ed1aed249f4bdbf7fc226a14832f041f474446e48eed457c0377b99f2ca128294e8400239f94874d8e986cda019472cb3b7642fe1c" },
                { "eo", "6ddb89b2275f5d6958a6e2167d6e593e784855ee06d980159dc707b329701275afff36a50c1df0d5decebbd05152e2de65e96787d01040565b8b33114ae41cf7" },
                { "es-AR", "6863b1b3c876727a1b8310dbc5bf96057fa17e81045e8338618bb7b70c7873ee8f24c2b495ee7839112431fa701d4469860a9ad1522af9808d3d93881eab62ab" },
                { "es-CL", "9e6ec94f35741cc84b4bdeed61f0132cfcd0dab3ffed8d123a90b81ae15cf72dd33028458e6eb06e892f3a215f714e3595b7a0c7a52574dc69c9dcd48d3a4379" },
                { "es-ES", "9720d5deeac7d4262886eb4ba386e3595b2dcaa2dff0dcf7a5d9900234ce333dbd6af87715955facd2196ca829466fa8495292dd7e695a8cb7a4d8d2d62b8283" },
                { "es-MX", "d8c0d15de6047af6e5e8726a6b03fb26a345eb3a0f7669be746eeed268831d71e300214b6c1b0b536e568c8edf09693ba2748d158bc610af75af8d852f3003ed" },
                { "et", "ea241b787f48ada42c85c067af6cf3b75936e92c3b085aaf90d0bbdb2c659b2c3a5c13da8d664c6119e22b21ac9dee2b9cb9353c30340ef8438c80d6f5b0c55b" },
                { "eu", "e6bb59a48deae9522a832d916a2b32ffc1d3c4577f5cfb9213805a55686087e86edf8a9d06903371f343b95ebf65f6fc0aa786fa433a14b133c73f14ce4a4b34" },
                { "fa", "4c58c699bf8167081a0201b712e9aae24b780596836f56f8e11da5f5126bc4a427296e926d2214499360819b1d0b54792c09e83108b090a3e7a4008bfce517ba" },
                { "ff", "d532fa72c8f65db9eb409a002548c90e81dfe262c6a3725c4fdb9ab94626b853ecfe224d4721caefb5dee96b6654ba7f46e2f25f8bd7021ba0d6d7f68a171981" },
                { "fi", "265055406bbf5b0141ca8c9cf5fa06b68dfcc93ddb179341e7a69c864a504d478af40b4d745013ef92eaa0ac2d40ea05235a85cbbd42ace9040946e38e619680" },
                { "fr", "51811d2390dbc4d240590d75651a9fd91080dc7f59b0df2cb1e66d65b22ba6ec116e8a1794b0c243663e29f7d540ec9187ad118cb3601740fae7f7282ac8058f" },
                { "fur", "d2537d5bcf1c23369ae63138be4b27782409ad3c95676a011b4a396825f897cc98e56932d242092dc65fdba324ff4dec55cfe5f7db9ee16bef382fad1c6341f3" },
                { "fy-NL", "3a944335a9ed772a1c2c5d2168fb24c3c0508198feabc25df054546bfa86138d5d634080427958562eec853b02f24d3801aba3db171d36edebcb899a2fa9cafd" },
                { "ga-IE", "607aa87242834527f54035e74a0ad1df75995b6b7d3cefff3f557d50d0e065b74f02651f78c51649e6977b55fc21cb87b4135dba06967a0ae576c34f5b194585" },
                { "gd", "e6f1e9c49d767a4a2fb85cfda1aad5b754211e4be271bdbf057c6321130950b639da24f547576425ee2df21ab5e611e258b4278f9fff0523d2f3e4853f1c5a38" },
                { "gl", "b26dc5ad22fea4a1912aeb21024131147c53d87c3f80df3f7f55773647414489bcf25c0cf87e3c2bcc6698992b75bc0d947f9e2002c54d5c86eeed41cc4c2cea" },
                { "gn", "91aa994e47b403d7bae35261878da9304867fb78021ad8351fcab9d6a2ccb854a69fd5a99706ab821ac86c5b7402a27d6d64f515955ceef4b99fdfa4233c6cc4" },
                { "gu-IN", "a218fd7714b3ef684ce34a43e231127c07146c11a2c7188a3230dc6a7f1bff3b46d65d66cc37df2cfd9cc7e0224ebcae27d77a8667633e79ed7db69d5dafa8eb" },
                { "he", "8e77492768b9124aa8aed362d514eb05c06a55ad3b7b302bdecbeabb43d05a26baeef0a4a1340c00aedfaa172bc948224e437f4c43fc3e7fc860d02a0df949d0" },
                { "hi-IN", "714c28a4ac11e7be029762785009d9b585859bbf5ba186637c5ee6b2ddb789e717be8190b2c0eb349ee1fc8336dd25956c5c8f5af6057f88ab2d6942a995bd02" },
                { "hr", "3f0a741d58324fda374f9852d99beef5b0a2c1ce3f38d856dd85ef607b4535632a3e25c9244ffde2ec189e999911d90c89f163cd93f663c6fd4f65e55a5e3816" },
                { "hsb", "6c90ede7e5c7f22cc553f71c07342fa1e4e03d952a5585913e75bef78ab181c5bdfe2354c2ef4128d16517f2d7449c1ab3aabe5fcc49933b35cb72a69bf7121a" },
                { "hu", "11561131ebce2a5906c3f3c04a437163a5900f5fb2d4119442337b2361f273fdef4fea662d117ae7e5a3bf0bcbe9916434f1c3742b760437d8c1406eb7428540" },
                { "hy-AM", "4968e6fa09fbd62957ab10e0f25a443172ab3ecab8628b3c3311afa798f4e2e2e80d1eff72700f51780762fb158dcc0b0f6d01654428494dddc730cd32dc59b2" },
                { "ia", "8126d4636e297430edbe89559a8f1127356d762298067b3d248a417e23a78b0d49adc274c0ef0e974bfb5f1c0b8e76c3ec321671f7a64e5e4fc34c702ed31e5c" },
                { "id", "77945a66b2ee20a70d5a53b123a05e84e6082d7715a80b3beb6d697d1710ff875ec8ee2d61777934fb67f00c7cbb95077a4045e12c3fee89af66ce072f7e687c" },
                { "is", "53a15c2e727477dcca364a64a619f45412062ac7c941ad11877f5206f00c26819b1124c9012893a892457887781c12ef43d95a2f0b81601727248e3cdc8aab79" },
                { "it", "46374c0cca4b0e4faa583407fbbdc1a7b01b17b1df8b6f5be56659efe93ae93ad0d24655cfe2075438f1d84c6c3b791181a23a90246d1b069a282ceabfb15fa8" },
                { "ja", "8d5afbe9bb947a07f713d94efc0fb9a4597707c263f58e9b9880cc956d959d40682acb361d7defe1741ebfd5d50dd3e834a3ba73f58091298e32ec1b43caa7d9" },
                { "ka", "0bb481c52048441c71b5d19edfec8cb0506de6e726d02ef7f9351352583ec44d818b588e1ffbee3316ea427c60b412c4b5912c32a3bcb9e152c18fa5bce40187" },
                { "kab", "62e1afc5a2fc676fff6ce03da07e825417c6f8eb36127e780cdbab3d6270b10806c6e3e737dd16b1181b240aaedde4482bac2a7b0fafba33bc9ecd81af514198" },
                { "kk", "8ff8538e5c95982b5d99ba30e5c1a501548ba943a2040a2e47ade3b5f2186479b6ed683e15d88c50a4de4023911e83d24ef30ce10b4719c2f9b2c211bcfe1b26" },
                { "km", "8cf36307dde8a5c95ced2052132c72a3fffa3362d194767dfb81c83804716f4b401502481348de31d633c9d427c3da472bb18d2552c1fef6cbf5f541927c2a90" },
                { "kn", "28b1bfa453340d0d40ad0245fc9cf5c7865c8b13b42b9c898fe940fad56e71cfc10a12bb56127ab14a13eab5632968925053000231554e20a213ecd2ce314ffb" },
                { "ko", "7de913e061dbb5ab65982a195a609b422e6e2b30abe9ea3fb5f3155e8aef8aa443f1b91665602e9855143025fd6e40589ddb62ccb64869b0ef0f32633038f393" },
                { "lij", "e3dded61c336189a10b3816caf1d393dfe3f2a23576db96abd0cbf0d7629a6a2cf0f2c48b5a1c66a6b51ce6f317a7afe1a6aa9a0b1cc86d455e0ed4b375ffd78" },
                { "lt", "e63254ea6fb64673a293a32743973813a01de07756dbb75eb08dcc69558c749dfd0736f39e5d4b420b969f21cfbd12a08cfc622cb2869c1dd1c4420fb409e0d4" },
                { "lv", "4abb4d00184efdbfaa2c5f86fd815d88a1f299768ef3fadbfed9dc0d3f2a124c0d6d5c15d61609479435ae81dbc7cc1d5abe96513885af946dbbdeeae94b7409" },
                { "mk", "ebcfa59ab9a2d9582b6b36961238bb09b716763b0f20a596052f1937668a38adee2a4fb38677e2df61135b1e93ab73ce2b33c881c8540963e05fd9be96596bcc" },
                { "mr", "6ec1ca25b0f4e32f8a61f7a5770e4083cf9cad2b23c2d29601628645bad7dd05dd3b685355cb9a0fc23b47636dc8401fe6e96feff5f4713932cb34310b2c2ee6" },
                { "ms", "5f18f795c4e7a04df43eed5211baddde1738543a167300d0de114c2fc3e8c62a36e15f49a59d2379d477bf58809b8e4c23b1cc6529ece635939ffba29e138219" },
                { "my", "7b8a91da9bad150c13389ccd005051029efffaca29814258f9342a43cbbf174182c0ededc05bc25cd79251549f5c498f585e5214a44ef4573a23bbed8f15c6aa" },
                { "nb-NO", "6a82363fff3523259235870d0c045216b545bf69e0b398d794d33faccff1d925c818493f67d4c0da90e9b24703fc18b9ba6f76b5393db2942371657fc9d3f52f" },
                { "ne-NP", "a4ee76cd6a53b9d869ddc076f70c2ca822d9b27df6309220cd89c55e4dc6d0bf06200daf38caf9df35e9fb92e8e7f41decf0bf3fc7275516c0c35911c0362bbe" },
                { "nl", "7b84b3538e982347dc23b9ac82c0241bcaf751924f5b2ee790e6174e16bbb59c78af6e255f08b3ee92f8ce22489d31dcb922dc9d7bde111448a9f7c0fa88c8c5" },
                { "nn-NO", "6323217894f8743b33588d7bb2bf7eddfcc549e29ba1376058c7845a86b1f682f9041f94d3e23b1ed78e34ded275961f8a6a31f9f89e2207c9b033a9ecd6ccb7" },
                { "oc", "c74883c1126ad8fd680f84b1524deea67dc7cb3a872bc74c6ee65b6c7484d87cb700e357495098331621ec67b5cff065155c04e3281c9d032ffe996a493d977e" },
                { "pa-IN", "ef34bc8c132a1b997bfc6240feacff535be08637e5f5ccaf40e79e6b3d4c6b581f95f5ba5a2cd73ca6a33c42f39704c4f9c412d112d2143baa0de8741b0d7596" },
                { "pl", "a16aeb88a7af91a408d0e036168555c12ac518ff56699f08a8cac67dd859793166c352b12509fbf74946fb29f93a26c54e46c8d1439f4477c05f4ad0223c2f9c" },
                { "pt-BR", "7f9f5647122865f6637fe3da3fb6aeea89bafc50deef655eccc9a6d30fb3a89787bfddc146eb773e0076edb722cecb0f70664b80cfa240d932de58637d660e71" },
                { "pt-PT", "14068d1af425d6fcfbcc36e0a277b16c5f98aa1dde184632b8046f68a03ddb21ad9416d87bf9e93326563e2b85a30c8eeaeb7c35ccc4509fa1e9dbe3cc133ad6" },
                { "rm", "12a22cc7aaaa4860a839b0296aec7d50818b675fcb1d4c752000b09939cb01c02632329025b7f74bb9d04d3959bf8346db985edcf66d4c833d54f7d938580497" },
                { "ro", "cdef2b50cc95dc31706b8fbd9807dee2bdde630ee281dbd77168c15088dfe9143b18b305e730baab9f94186a4cf9b9ecb65e5f00f9bd7579b91a270fa3e3930f" },
                { "ru", "a4322a142d6c3b34da437a51371518da414e8e74f56e39490e7187f9c7339ed9be80bfce044f80942738385ad3d70a245b085e9ec75a0f712b2db0db41e9ec0a" },
                { "sat", "c0a5d8b0e4f7243c1f27d70ace9f2bbdede9851fe837986fd8cfde6ca4b7dca22549e9f39b2fd297cb71a5382ca0a7d90058b9eee6952a2f2fd2d7738e678c9d" },
                { "sc", "bd53feb04cba06d9d1d3671feeccd4c9a7688f947ee400ae3d99b2f01b528085594f4c12c0380b2af764ae06407b520b5e9ef5fab2fbe9d3f5374cfb00730c97" },
                { "sco", "c43cfc1bc866c29a599d64fcde2a8c8e62fb03c8d9859ca3734ad029c68e911ba950c7d2f724b0bc5856f61c47f30d89e8d197e330862a7cc53f15f93d0b312c" },
                { "si", "a7e74cce04391a5fcee759e61492fc66247ef99fa4dbabdd8cba583214bf59bad602408ecfd9ea14b0bba1361d56ad63394b3a420b609315425fe7f0e0489410" },
                { "sk", "63c85f25115c3e20406e46ce59cf943de76d59dc3515f55463f87ec9b2b3614fa44f6f9da5092fd5c5956fc6199368c52ca2dbe53d41436bf68b8d325774d86e" },
                { "sl", "5856f0af384bde4ff4f943de4176dd617fef87f9bb5c8397f4614dfbafc5fc5884dc41b19e805e33e1aee5e6040d7a7c92952610f97504fffa5a912e8817d175" },
                { "son", "4cb1be76c33ab2c9d3477d83b7efef7cc3993cbb9cb413e3e3c3a02776f597209e5fef40a5cd1786359195a8c05ef52439193e07c28591d842c38991c2d18b14" },
                { "sq", "6192adaca624d702e85e9e998ff732936ef620db37a3f546d750f4673b3faeb5f281d85cd8863f2e9fe8a0105328ae5de949fa9dd6ad535e90c99750823259c5" },
                { "sr", "6bda75e0c1fdfc08afcfd0fbd1bd165ffa8fe5ab15ba07777a2f6c2024a73d84aac13220c9862a79332c54b56fb894f5e00647d2e0329c5d8dfef50af34e603c" },
                { "sv-SE", "17bbae6b362e9d481644676a5fb00337063260fa3891205da95487d0a3385c255454b6bedc97d4875a03376c3cbe909538288d0c92184104a6c0e33353102393" },
                { "szl", "11c0036924cdcab6d23f52a819f879c3b09626c7ea79843998af5a6ea5b7c2e1b9e1798bf24952e363230ca1f33be97f5463bd992f0662e49d34e8112d526b61" },
                { "ta", "d52db35b3c690f1c0a2c31a94fb0535177a6828b7d4cc38c046776bb1952da6913d439c1dd38ce5ec8ceb39a05e917c0161cddbc3ef3f90db9f2e3d7accd2811" },
                { "te", "de65e24ab685ae200d97ee11ad5b71d39b1689fb3550545295fc2b0cabab47cf9f6c146f34f0b3f9578c2b3aa6a6946a2c3794464300ba6345cd79f4d8756658" },
                { "tg", "8e9b22dbcfb9fef2141ad8ba1807a6d8c5445031b8a6d96b2eb07aaf1fbb27a09b2b2689d9ba83b9838d0b6d111769f9dccd96c548b936dcb711eb0b1c85873a" },
                { "th", "dd8d82e0fc093ea4896bc6ec9f39235a0baefabd8b9d313632cdd8cb05b16d902d94b67e47203701358d1b182455c66fcb669be924683ceb428bbc613f954297" },
                { "tl", "9aae60b29fb620af5f3fba09cb54027968c504612412a7df4a618b572f6ca3b31938a243c43c27f8a1dfd5c7736baee42cfdfe9d2eb1501572a68b3e63721bc5" },
                { "tr", "a8292a1c474122095a4dd0f02e5bc3b9da0e85411f4515b2045b181049d8bed8001b3b915ce43cffafcf37ab0e45b936bd1d0f27ac9a1c032e266459960f112e" },
                { "trs", "e2d7b05335948dd4e26719cca757a317a0f08de7125d7b709f645727b5fe49c1bebe8c51d9d585138b05079830fc7c139af11426e6ad3843a2f864fa14e3aa60" },
                { "uk", "40442eb1be33c30b605879850b6433c4d41c58136159dc0b9a8c8c64604891227ac7d063e83a80f04eba84f8da45ab7b61b832841e1182b1d92bc734171a7b44" },
                { "ur", "1adfd157b55328d729589b2893b8e4b25581ee4e5717585aab46e165007b7c3f202080caa9534b747a084d13d5f7a56beb74419210ab0a25674ace5770ceb1e4" },
                { "uz", "59bce71a48977dbf3236e87a4bee638f0171540361fb90087a1b49b730a809b9dffcc01ad40d23c1d1288e94356516942ebd25d6942a6f1c145a455ecb94d48b" },
                { "vi", "481f90f076949593042453f46c7805621a4b6d7b23f9e71305384e40f80533d8ea3e8ed2973f616b2c7f75c3b341e9e3dd418bcf39feccaf0afcb9f951ade72e" },
                { "xh", "a9e5c8d272f498c971c83a127c815fc6de2d8d9f5a7738606f5c488cd879fd3dac3a2398133bef58ddfad89bced3686f6b3bf1386edc89fd0406c1d5bb817278" },
                { "zh-CN", "988614cf14146db0fbac207364ff0689e9ef2bb78907721ccc448ba9d86189dbf242077e3ab69b7c71567fd120c94e18aff14ab553d872a6e8edc15ee1a62bad" },
                { "zh-TW", "d1b18c149f8be1b5c4cf7bb7609af0f78ecf9abbfaf478019f2ffcb52e3dd8b0f11b3870284631aaedec212b3b98f9f80a636e6e949ca7f1475d0451d38e0376" }
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
                    // look for lines with language code and version for 32 bit
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
                    // look for line with the correct language code and version for 64 bit
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
