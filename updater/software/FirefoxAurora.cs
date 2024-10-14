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
        private const string currentVersion = "132.0b7";

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
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "76ccfef31006fea8d3ca79212f5140171d1a8f5217f47d7f8c95da55eb2323c5f592c1abdc301619f3659dd9fbee5be70f5bf70e9f3047675ad35b5187195b26" },
                { "af", "80e58e855abc5c89215b102cad21517a83898534da8441190aaf5b24552ceeddcb1559f5602157954fa2fb9b5b814d44ae8c0f50627dc7e8d389c8a62958e756" },
                { "an", "4e4de04427c2cb60996891fd46771bfd512abe6f3469e11f45fd1a9fa79a97729272bfbc0ddfae20fba210e4be24365812a6620649c3f82467c084e068fe02ad" },
                { "ar", "4aa532ac7208708c99affdc258b8c0667f6ac57fc270f88958a4fa2413aa9ae7f455a82054a20815e831b605257537e6e7b30951bf4c2ec921c88488dd72a95b" },
                { "ast", "0eb299d5b652f312a04c6f8bb873c8053d5d510175ea82b7665474607629ae5eb915db524c306c141d6f1c61702dfd61f45926b0e4f96e8c8ba758e174c4eb09" },
                { "az", "dfab4c7d4e691cbd89c602f7d0100e863a0ca74f611c0f2c5bf7d865df7fc4fede64066da95551f2440a1a6d40865213cc21a5922db263d978281bd0914486a2" },
                { "be", "270ab70a485c753152c68ccc2db8b88f432c4e4c6436dfd516738af3ca9dbd9ca3d38b21532f5f7d2b3b1ce5d9b0e5b3c6ee6ee9db5502a234dbb49146547f2f" },
                { "bg", "96824ed1463b812271cbf910e1245fda621d755a1052a15ea95289583c26a77ab7750c2c398b85417149ec0efe637ef0618360e6163999e210c6417dff39b4cb" },
                { "bn", "bb7737f26fa799dbd5be41faae4c9c57af5c6a102a892e29cc8924375ea660a40ca8dbe9d5fbb240b5955ed6566b44f55af71e6cbc7fe8fc2bb5bee6f3c204e3" },
                { "br", "fc007bb6be056241fef3d1707903626eca166d0419043a1c40f2b88d5ec0ffa86e2c26bc97f14bc749d64637dceba302c7854dbdbdd0ab4f915962a300d1c2d0" },
                { "bs", "fa704181de684606e2593061968dba9f303cd769301501b9c512b8b01fd00a2ffd4ae3720e301905f244f605f60e0d55654a7f605ab59346687a5fde84b80aaa" },
                { "ca", "74929d782546b54f55556714e5a6c1d00bd11dc8a7e710139a9ed4c94ee750037600fe26e3a588a98e8277d738140934122cdf693a9a362a45568642fb7b26cb" },
                { "cak", "7763974a3a4b8bc4adbbdffcce80c69cba4cc3e9398e2bc1dcef0d83b908cfabcb9ad0c9be0823d3431695e418ecc6da3cad098857a7c28559261cd217cf8b3e" },
                { "cs", "29d9053ecdf95e561abbf6c451a0b8eb03e46ce82d144e1585ff790eafb44a697cef1bd9a69b7594b73d43328a4921ba0704f594bbddf3a6d4ae1bed80d64004" },
                { "cy", "2576e8dbf22dea9cc130e787c26d6c0a0522c0dd76f7bff9919ffc817b8517be210e15a6183060627e06f550ad0826e0ffe9909bd12c568b5fd3e2778290f378" },
                { "da", "60883da7aed9d19ec7ef431842bf60dffdcc563bfecc6cd8d5f608c203d309e0600bfee2d22106eebe79f7a274acbeed097af1ee5f1fcbaa37181440756dd796" },
                { "de", "eb2045e863bf162f86074e2e3deb1039b695c0dab0b34985cd7ce0c8efb5350ba225fb38454de61f94f14e1fd10845fa120231b2b6e9108670b7100d3a030167" },
                { "dsb", "049aa0f208563936c0a67909ad64619c5bac1ab19590333a33589b4e0d8ad45700e104243cea352d7186e1905d1e55733834195376eeba2dcb770739fbae4df5" },
                { "el", "b1eafa6286e35e1ec5fc25946efb2ac36ddbd2235e5e72ea149eed1f62cd86778380a770854b30818702d112b2990fd98e93cd53d2970d4c83bfd32f148eeb08" },
                { "en-CA", "32b015cb7f012c713a4e0097699105d28bf89dccdceccd97cea3cd112eda90b47d706b3ebdebfee932b6d5cf6a791b55537ba48c32005ea7ddf5b51fde165ad7" },
                { "en-GB", "581d255811fae8bb841b9679c51c2dfa175480bb5c1d83d8587b9603ebbb236fc480fbd1bca1b349ff409ab46737d56519dd786d57e1bfb49cb950a864d5a84c" },
                { "en-US", "417df17855cc0773d87f1802d1d0d3e90b685b80a3add09c88003b2d5bd6a7ede6a8b080d862ef1e4345583dc2e81c02b3c2b1cb71ffb13acc87cfd0426c5637" },
                { "eo", "5406fccbdb49212da8dccf73dd7874b8aea13211f6e6b1f093bb9110e7840ea83e0e0c1d7d218b478745106912a796bf664d0f0a683767fbb650f6f6f445b605" },
                { "es-AR", "62d0fc09b966a1e638664498fca9f20616f263c4a41d744cba4f450ceaabe0222fcc8690f6dbf824d34fc39f07182c565953776ba38527ec2c203b5ca1a7b481" },
                { "es-CL", "b59263c1cc9c316297088b050ea192c1470e1366098ecc8064e34e1bf94434497fdfddcea8cbd5bf511091e61b39a7dec99fba74ed43e5700adddefa848cedbc" },
                { "es-ES", "c9274416322fbe74410ddb5ce14c9311a7efa5ad2fca229c2278292591d73bda7fd52c546c54fbfb6a24125579cd8fb6362cf20dc78411954740e26328b800b9" },
                { "es-MX", "4d4f17dfe1a6e91c9b5a0854ac2dff25a4edab36780ea090b8f80909ca4e30ef7c81ec9047fcaccb5644ccb657deabd6f7f076401713bcfa17243bbc8b5e597c" },
                { "et", "a3a686af3894f06c2c08fa0177a2f76a0da917a8a460d71845ccf03ea2651c82ba2df42ff5cc4c9f038b4f6bb1cb65f165a2208d3b8ac8f5b778404e88a059f4" },
                { "eu", "6a4698ca636adbd6f0556cf612bcd78fadb0872dd0f6b5d40abeb40b615bcf61b17c0542b0f7359b3eb47f1ead1e4853a9ab9f7f5397f0d8da28566ae9cd8a2e" },
                { "fa", "96bee62d5287695ce4c8d53cca8f8a3be2e944687fe398d4c58f0a98615b72a087234ce6f4367ffe22be3322de8eddf4376742fe963fec00844025892d7229fd" },
                { "ff", "c37cd2c5a345425370386a2c19ef50eee77bc44e82127e0fb224afd3226d529dc0a21a0192ee88bcf3c08cc6109770b701a167a2bff93e50a315861b93f26f75" },
                { "fi", "c502b0c4875128cfb636b40f5ca19ea8640b2890e74ac523084ce6c5ddc3f9825cf4d70bd5cde1290079d2e57525a9d49267a1828c9fd61b5c2089b89b9b783c" },
                { "fr", "1fbf77dbcfbc97cc218e2d26d7da0964ccfe6231da1fd07be61f6455999d8367c5ee4aa690af5e4073aad5bf6e3a42ca3de14a557c07db36189b5c3c706d9afb" },
                { "fur", "27859ca31d2154d43f11f1014adddb653283d91d87c37501f24430249cba9117e264e46651a415698b62313ba7a187e885a04390ea82360055ba0e93f4cd9d33" },
                { "fy-NL", "ab2773a2894c19664f7ac4fa38178c5c09e1961c8210ce36eb98f6c95b21c6fe2074bf68d81560f2e612d1415575c27463aaf9183d022e1d64c723cfa6cd37b4" },
                { "ga-IE", "42c5cd22c32d973fec64ee3cfe77b43d7ee52990f90c6c3d3d18feb1c5af2f399ff4555d34c38fd8bdbf529d4f443bc041c2c3348ac18d0a6badc212812517b0" },
                { "gd", "0376bd12aab57820a7255833aafe1bcd9696f06cc79ff4d4ebddcb56fcacad54a60d4a0667e9ab33da903749805de3d2c66bce9c8ee4b5052e566359985dbe98" },
                { "gl", "37659b9516ef62e120fa83f3f0e8019a8bf8bb0760ba19dd608447ab5cdba20e113b64efd2b992ca971e45c22aa5d005ebe0c9f3af503e72759bfa320a1d9e63" },
                { "gn", "2b4dd98a4fbbcb6978608c277e3d3eae5c66130f86c03736ba23f0434e56c7a0092db84a6af70045a41b766895f1bde06a98cb8cbc47c9470a2b1074b038f2d3" },
                { "gu-IN", "f3687c18a843436c40756dfb607bf43579ea519e685510c0d6b70ea5dc5dffb38c63280bb31caf8c9de55ede93ad3898f5fdbaa9a4ec098d7305d24fb2a0c508" },
                { "he", "96ae117c317c689237e3460cc8762b57f2a6755e4d77af4e17e02a41398b6cd0294845b4009c9c915b8964ae3d7f18543092d39c8f49cffc88357d860e51bb78" },
                { "hi-IN", "7f9cfb049a8353d772575dd36e0b40cedbb7f73399edc833714fce40974bcee557797e8758b579072d44d11b87cc9b4052a8f2be6c9a003fb9ce51286017c9c2" },
                { "hr", "aee5882205c5e571e49ba1f6530eff452fe28269de4719f53252167c01041957f6600cf51f6a52f30c93509a476bb8a3f65494ce8977dac6985af6ba59ff1999" },
                { "hsb", "dcd35a712bd52b1c3f9b57c30d53194c034e3f88d8e404e17a506d1587ba8134be0371ff47de969384a68137904817d5ae1701b9044cdb6f3e9ac17780da789c" },
                { "hu", "10dc7792826d1c7ee9a5b5b25b34363ca4281ac93376fd50a72da8851bf7882114ce3eeeca746fe16f0f755d49bc233443d7fb41835ee93be6f39ce67561465d" },
                { "hy-AM", "b667656c4bb66ec513e6f00794a278d43eab94be01fb3a80413303e3a223445f3474279b340381d7d24139d5c21831c434f701372182cdcbd78394e3d0dba596" },
                { "ia", "7fb5072ec53e22127eb364b3eabb6ce807a38a105bb1108db3b79b860b1b78a6a1444e35f52f48de969f25667fa27ad494c9579e6a17ea75a5739efe4b048a9d" },
                { "id", "0e87fdb043966a864a02e47bf24660ea38a85eb8cabb930c153cba812baa218087278826fc988e90e1b46995c948019525c2f06d01ef665ded25ebdf82da3432" },
                { "is", "fe037cb4b73faa71d4cd5e1e98445e93db8dee24cc92bd76ded7e5f506cd13dc7b36fe17ef5efa55d562e4b91dd296a4939ac9483f48d612404dee1338e655e3" },
                { "it", "807db8dfba37fc061f049c9a501c72fbd82c0e73f26a0f87129c17dc76349b550a956b1fb69a5e4555993104f25214dc6e01a182b8b1c138c8dc6c7efdc5b81a" },
                { "ja", "36c9db85b3b781cbbaa7b2ba7181df64e889aea88a9e49759fa1843bdcbb86e6c8b5d620acbc5bbf7a7036afb6858ad7a6d1f89acd27649b465ceb4dca6f14b9" },
                { "ka", "9431f0c371e89b4cf6c7e039a18d742ce4b0e0f786dcfd31435b494e1b39610c548504e0cb5c33fbf0d732d24636b70b4f726d1532a08a7c014e5d21a996f3d0" },
                { "kab", "0ce0f8ed1e5a35e91de1374ab46cfa55fe5c59736d68a5dc078c44cd6ec815088ed6c4e5b10f4ae27791fe09c3a2ddf08b6bec65695e54e64f6e98ca734435a8" },
                { "kk", "cbc5c3bd94ee26e608c4d92d1d093c8e8acfed55cc0a11c40f7bf5e7e9408d432f69b02814fd5708a6892fba1357d80e805e29b5d2b27e26cad8c214f494fb53" },
                { "km", "6f7149516046c37a56fdd7f6db53c74cbcf32cd7b6c9c6ebb06dc9cc508764277dcb46e5ed5457f0ecfe79bec80dc0d478545f1548fe992df18d9fa970b10fcb" },
                { "kn", "2971ba0c073f8eaaea683e7e52e93898e3b7fb89cb76880b0624bb6bfa853974dbe874e7165776f32d81fc08eb161926e107041dc5dac055cba14b7ca342be3e" },
                { "ko", "a4c659d7ba309b75971d2b51691d39314deb2ee73c4aa1b1a63ef945a3b450e250baacbed57ce20cfcd940011864718aeddeba2dc6002e3f1ddacb06d72f3cc8" },
                { "lij", "1a86e55e31a14af320fc4a9f817965001c154fce68362d4bd90ba1f9765c4b9409353e15c514daafced493b885ba10bb5ee5d70e45e28db76687512ab6b7c613" },
                { "lt", "94a203062bbad657e7ceb84ec707133dd12a492ebfd7a19b5d4c4c2ecb2fb089a4b18a3b239e2ef649c56bad68b8745a5ea7764e283eba6049d1e93beab48f49" },
                { "lv", "69ce3076a2b26704cbd16c0eaba01aa8f37ab86ce33b2a990795e261a49930bf4d2fe89618efb10becb57e977a452d6dde6186e12691e981f51405c862380765" },
                { "mk", "ef931cae2b054c59bd9ed120a52d1f2c2e83bc65ee719673fc23b90750892a7e61aa4055c357eddb5b6d4c818574685134696ccf5f4991770a7af8d9342478a6" },
                { "mr", "23bcb5c88189170065fe0cfb9efb984d905fec73fc1b77be827427ef832fa944328d22818576af0c283dc9b403d0a41fc35cf4b9cf8d2c7916ffe7a594c7b640" },
                { "ms", "1da59e959a8ad3967ee3bd595dc63630035783bfa96f2e493c8072386b789ef2becb52ea2934c8b395087953f605a82a4af89335e37cbb54577e8750e77aa1b5" },
                { "my", "a3139e6a495d4830a81c584a244d4781d3ee813d71e8de0e3a488731032001e2722bfb80733bd82123e81b48ee466c9acb01a4266620ddcb58290dfeb18b424f" },
                { "nb-NO", "46bfad8252b3b479d75d601207652400db8ec53960ddd005044c4f9d471d7d451dd2c42578012db11919f73de7d06e0f5b38f6a756cf4a27573a1b8a589d2db5" },
                { "ne-NP", "240b24597a63ad35fcc2192818aab221db23b4617aec91cebf71f9b72dcf77133b5ba99cbeae930e25c1b622686f64c701f83fb737dd3faaf7c2cc19ae31af5e" },
                { "nl", "322306531b99588bfac7bcc8de367e52986a4632c76af4aeb091da99563aed6d65087778f403502f3c4e28cd5839ad99dd83dea2045854c021239de4925e9a4d" },
                { "nn-NO", "041b37ba86690885d12fd90aa39b5a92ba280f0247a6f27c0394a005cb8d16aef7636f9a65e57adba3bd740c4ec87fd40c2718ca5681bd016de229de4584c0d4" },
                { "oc", "eb4e676df2f81a66de75e5d9974e6ba7d49bce14b6d22cc4647dcc8fd455f548b443b99998174754b2c1b42307be1dcb003e3dbde2cb7d1a60f7f5e595002693" },
                { "pa-IN", "66bbac61ec940a86d40aa92a0dbe227da676b00c6929bc9e3f4203014eab2d40b0bec90518099ab7a3849b38ef00a2513357b7d74932d0e5f026f25a3a50c937" },
                { "pl", "5c8b1712f995e4dae120360039aaaabd3f93766f03c922e6ffbf56f88d880cd4d74f874f290f637cff4761384042c6e88b6db88a209c016a366748c528bca6ac" },
                { "pt-BR", "1951b515d066f93262a9647d20988c88c6ab508c351bc01291fdce4c3610ae64f131f9d8f6f8eb882c2482da96afa5e8df989c29a6ec7dfe370f324650ec5032" },
                { "pt-PT", "8915600554191c9953504a34e33949d0807bb2d4168f9e796aabb16d8436491397fda43a26485f5a77351ceb262c50141487b1703d7b119b78706c18404b9e6f" },
                { "rm", "1bc13316034fa1e1b8f697dfa8187055072fbb49372a2c90a1b4caf792079f524b6aa13b2c762803c3cd84981424335435217f7556b227568cb69528df4aae10" },
                { "ro", "579f273a8fe72a82b7badad828f9c21c911f604394bcbf042ceea77d30102958dad182680776a520d8f04852bb2eed353705fee20a75f30c0415d9fc8c94a299" },
                { "ru", "105e346fcd0acae972545b7d1637f7ca1b8ea4a71aa90d183cfe22228e8c81665826d9b43a490b765f28d943deee1816edee9ff05c0e0ca1482619e79ca752e2" },
                { "sat", "2f8de9a3d0c737663e46dc6c64ef9507db4352cbf3d2a9f95d555cc64b0aaaeb3b267fb5e5b477b71d50eff4e6512d137f763182640487507ed9d70132ae8919" },
                { "sc", "6ad351ed55ee00462c68abe70e9de24d44611e5ba44d1cd6f06396ecb3f23f24ae747adfce7f2d0dc4146ed69d0537a8ba103964515c95a6f362ed3c0a7520b3" },
                { "sco", "d1bc757c5823e7cdc365ff63803e8889dfbba08dcae4ae00c2a02a21abecffb8c0e462942259c34b79075bdd88268c9e2d93b9b4d4815a2a90f6bc8085b3d1ea" },
                { "si", "93ec5395562a6038cf9c471110f3ec09a645a3eeac206f1e8b0598f42a8e4f3fe9e1a8aa5c36942e0bfcbdee93e125d567bd9016cc621704ad19875c5a5fa000" },
                { "sk", "a8955e30fcece9c775b226e2e0858fc9772c9d12bc43a0599d319a97f491bfd38321fc571eda80f67d06a243c9a56f264810a776dc1fcedc574278b9a5521aa4" },
                { "skr", "bef86998ca70bb983727247e34aab46b50933ad1e04f3352fa1148007481051deaa2e8e68215a8bde1460c6345b82d65ddadddb4f2908b8449a6f61f17e3dcff" },
                { "sl", "f37aace267031a8b7232e54796f28e10275262b1d390a920f99ddcb49432ea0d77b998c7e01a02646973cd7aa182de843c4682845711ae6a7180b2b124d1bd80" },
                { "son", "5d4aa2bb938d94716facad7713e7529f92cc9fc54c5867edde2f962d8d5f0c1f85dbd7d6374492c33c4debd9f7fa501e7afee42b4f4653395a50cd8223461e7c" },
                { "sq", "4b6b00c7600a8fe359da395c0b1a9e1cd40791f4369f070c5579b838126a9ba15af87f5294964c931a0f1e3ac08a322bf483175027e02b337f309fbdf883329b" },
                { "sr", "836e36a7ad1b309d0158aeebc2cc2db27bbf40554b9c8b0e6fe6b9b6c369c5bf3e9f173669641e931df758dae497fddb9e8894527c8239ae8960cec842f67283" },
                { "sv-SE", "0ece813412ba8ad0aece432343e774a5fe09230ed48c8d5659dd459ae594e96c48608b56c27ce8320d596d81a9bad351afbf2360b5722b2a5e4ebe20dce0738d" },
                { "szl", "cb80abfed7e14617ada32ba2a4652330db12a8606f32bdf9f8f0e1fb0a9df1f5995def14d1d62640d648d0d00ef9c3fc8f76af4ec6875db67482f70a1133b69e" },
                { "ta", "ca12191ed4608ff918bc8828d618ac27ee34feefb54f66e5b6bed65986e1c532e76fac2fc5e4e3dd8c69e67ada1d849d8c532b6b8bfc294b1f9b27da75b46934" },
                { "te", "2df776d9489c95499ea3b176b816c0ddfbc172934470e8fbc9cd6d171bfac3e768fd48a0d2476fce7eea826439167f332ddb5bd200dfb63c35dc98e5960d0c6e" },
                { "tg", "f1e125166a5398b882f92c1d22de791b6d3cc81d382441e9b8edd0636c980b7f30d5b48313c7f50d6b40316b1e457553ae55dd75ede56bb424e20a7f4ea43339" },
                { "th", "265e4325b9ada1c874c359dd6dc282e56e6958096e0700a230c5816a1dcca355cc89340bc3273a529c3865321529d1113d80a5fef83a9f7e2b9b303ce514d441" },
                { "tl", "d2b9a202505d173aebe6a7c52f4aa91dbea043077e7c220cbaa343010b83127fb1d0eebeda6843fe16b2fe94dc5ca4b637757dfccfe6f6a6cf9283950473a94e" },
                { "tr", "fa1ebc0736d0376f3d87ec1172cd7a2934f8b85ae89317d765bf53cfb42d81ab4e251c0bc439479590cae4bb07c2cfe204975e049dd222af7fee8d77b33a2ceb" },
                { "trs", "d95896c0f1601959954edc8746d25887bc2aff08a49ff51e55f0eb9d9bf25372deff587ba76db28a19fe2f6b32eb196d98f4c40118cc07ea24a5825d6af2fb0d" },
                { "uk", "dbc6c26e790811439866905f6536e7e9e1c31a9c4f821ed0c016fbf72a81e6556dbbb57e11d2f8890c32951a958587a1e2f9b9e3436539fb50c0fa16e2071cd6" },
                { "ur", "19418837a888da8cd4040b798028d970658eba7e0b628f98857d8b709feb6eee2bbdfe3812c809e261c68c9c3dfc34944665a1f81681127526d45b793a183cb0" },
                { "uz", "ad25fcadf58761bfd4080d6a30586f2cb90b654f1f2e8f656d8e40c63c26fcd2d20609f2a845319609950ba8017ae7fabb231611072426091549b65bb4a4179c" },
                { "vi", "0f11f785a206f4b0760428fdeec64d056d2a5ddc23982aff4bb1bb03b4f4dd1b7a8da4247377c6d77a31444f9dcd47f144a4104d48067aa524ba4d621f5604f0" },
                { "xh", "1b4bba6f24444deb11e9fda69ba6afc0212bc8d34cd4259f82ff1ede7a14a08a73c2a09cebec3822add66a7426bf3d4d200aa4b741949231fcb781d8873a91fb" },
                { "zh-CN", "76327fdcfb831c80fc22e203ac1fc1035da5b9e58e1bd505d619e22570bfaedbd8b95db13e806edc69d7215c353bda9d1f70c51e986e877b650c0aadbff8ab7d" },
                { "zh-TW", "622e621c15223589e0f3d4bf832bd99cd9eebd1925f09b3c865d026a9bd05e961ef8694ecf0a7e04ac104dfb648420457c3f30a42b2d633416a6566b6d4b3e5c" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9402b7505e36f36656a04b2ac9eaa8238cbd48c7858de5655e64b702a4cec7f2878b2ee4c07effa10309dd11163bb2030ea8ce4f1a515577d7dad8654326bfb5" },
                { "af", "96637bc40077a2f08314dbce44c137df8d5600ecb7c45a9453a0f6f8dfd19503ad7cb2c69f79b87beca3e8bbaae5c2a2c195c4b87857ed20408586dfdac2c9b0" },
                { "an", "3e8737f3883d2a46cc112519c1d1778ed1d6da6784c91555da31fa82fb4b273ca88d7657b6b0295f75e09e36c8bd59b77269e8e1322213dcd6a789dc6725a570" },
                { "ar", "c7dca696f8a45418fe14eaa9bb13286f311869121abddaac7765e0f3e92b9fdae666c97464062ab8522f8f7345a920abdb33c62a28d4cb5ac1b20f1afc204463" },
                { "ast", "0723871df9a76b0274b6cfafde221ee1576c709878571ee194391db805e0cc709742a6dc00c8133e884e4ba55a99a8ded57d191711250428322cd37f49feb8f0" },
                { "az", "3a09e09e31422aeb60073a4a82d3d8974a6b05c05674f484800d2b0719be404b12beac2712df3e75d1ae07b1dbb41ad29031156b3f61a605d7d05ca3b19b5d61" },
                { "be", "165bbb931faf241b57a129f5e81491986e377a31591371141fa32c74a9dad3995d275e08fe76fea43cc53fad5e7cba3d14ead44c73b6cce1ab5a8c7ceeb82dde" },
                { "bg", "b18aafe273927e34f153467e6b06643e90413adf68b0cc5fd76eb14e42ecf9d49ef015af110c9dfe19fef4e6caf924aaa19a313283329baa42cbb7a6a751c453" },
                { "bn", "684dfa327bd10a884eb40cc42b754b7daf5e5a797d146746d2a0d1f2ad7877b9c3916b9c5dcf0e75b8af1976464f0c52438a538f2648a4e4f7157dafa8906b51" },
                { "br", "577cf315550dbb376cad41cdde9130fb8c338029c8cbe9b723b77961567acdc0064144d51620c0338758f62ab3c68a3a1640d65907d288e1d97b80b5418e7977" },
                { "bs", "1bbaea5deaeda163836d42c7a62bd1953b7d7e34a127761f75be7118291c7e853814a5721920d2dba169dd4663204e776da2706c3fa0cf5d5a4e0e882f30bc02" },
                { "ca", "c61e66052dd7941637e514971714faf66733909f4f504b403822bc17e7f9f090d216a19cd17a402ac491f5dfc4255109b11083fb7a973a69639b99dca3386a11" },
                { "cak", "4269a04f1bb0c60637eae9ec21a71dae7247deeff7fd53d3f32b8b135d5b07e281dc5c91bef418a28e17c91a9503d254756ae8f65853265c299ce2b60ba03f6d" },
                { "cs", "3db59e3cc97470f9c50ccda531d72b513d68346844cf6ac54e9918f3e24d1e16db01841bd91c3a6582a3f5e0fc921e52a0c955eb9c8cb694f9da90443e74643b" },
                { "cy", "d90e6f978ee1299479b9710c28c1160a0e24ba437effd61c09977c5652f25f887bbd31c79a8e8c99a43d730a600e54cb20a4fc4a073b28e3735e80a3a7c5d00f" },
                { "da", "4a90738168281694bf76fa5f51b909c363de8151f5182c53fb20505e6d0efee4710797f50c6cd67cfbfc19c4fc3632b57f91f6f30e699725468a62cdd6ffe915" },
                { "de", "00dd454da83a265c4e4a84001079f832dbd3ab7cffb110d87906b6889836d22c9e774e3a3cda67dfadb797e1716339b3dc15d1ce84c0c139b6fa85da7f78f6db" },
                { "dsb", "66e698e170b4d30d207647af0299510b2a8603e215ccc9b8ebd603d0d5f2662b183e685cd97ea7b581593e40588aa5f909fd4670c25423dbc5ae397c181cf38f" },
                { "el", "c5b9a8b1571b4d5bb21795aafb1f607918b6d6b5d420d3cab22d47e26346ecc6c21a3066fe88635350d60329f0f18f1e3677a1fd26db81137f2c2b567cd8c4be" },
                { "en-CA", "2a584eab735801a7cd060bfd01ce259165f21f26143eea536395f4219eb3853511e53f0194e2e798efd06e5d546b1960b91be9b5964decec3fecd11bb26faeb3" },
                { "en-GB", "065d2e3d703a3d51d807899afcb75e16085825d0e5cc8e83f4f7bd9576f4c596d07ffb4fd47f7c829d83c722761aebd3a456a869c80cfba96bacf36ee5bfd018" },
                { "en-US", "475f8c02145e979eeff45f80d6e859d59c9f6fd5868413af1703c02e5edad62df59b8ff7f8af68aa49b99f4dab5cb70c41c668ffe291ae4f828c3eacba16ec04" },
                { "eo", "24ad07f975f5386bb9e547808e8f749452fb68176409337078c11c9e8a144adcbaa1563e671cde880ca271bdeea1c61e1f961112e67fa444b1c612f53a4cfa79" },
                { "es-AR", "c365faacac45e999a12d5a989c9b041458f59e1a618c7cfd135f703df56e4e1892ab11cb885b8dffea7e3997a208aa652c6d91616fc5bea3a8714c965afb0491" },
                { "es-CL", "57e99b53715263bd9a2521013c500ba037c2679bedc39b41b0e3538e03613464db5b2ec16e4d6ae5a5743e2afad2be64a6f98373bcc6cab7b6ed6c0489b8f40a" },
                { "es-ES", "35ce14b4d3acb0c712f4c0e2592347c0b76ea7886c01c38a97d8ff261330f3098f773dfba061becd3e2dac694c040cc9381aa018bd25c2d12e06d004eacd0e3b" },
                { "es-MX", "7975d2601d094b1917866e30912eaa164fff92a168c2127b688f1bec919d4d9adb7d34e7bdb7d917f638e78c0c154bead6a301027d69006b6450cdfe771b8511" },
                { "et", "8ddd3c0a5357f060a974634efaea2aa310bfe63b79e8e02e1d5c0d9d2113acf913ee97817e27c1f088873963015a9e57be71d01c0779573c164ad1651dbb7e8f" },
                { "eu", "c9c8a1219b8de82dde6fb18aee98426f6dcf14742dad84830af582caea480118b98454ca92207ff6a450aabd7c2aaf5bd0d2aad1ea89c5f05a9540c1d39d48ba" },
                { "fa", "24aa64ec97a9e804936092ac938d9443b873597cd744321f4ba9492a486638f573e6661da96c085b22a05d496b9e2f977f6a9a3836ab3753021ec59a87afc8c9" },
                { "ff", "f8b4efa5afd606dd2c87ac73cb69c1ad679bba8b32d33d919f98845a2b9fc648dac58291a708278e8c65fc745f5b832d4db22e83f9fa74ecde665abe24aea270" },
                { "fi", "0aacc25603fb07f2b0b1b4d135bb9488a53e2a406584fa3d5f3d7f3ad685cff9f7057cb4a9a3e9725d98df67f5720f693b0c00de1ca4cdd5e5e1b7c6e979e5db" },
                { "fr", "d5276d3f465c360411ebf34019915941887e573429173ce108a0f5c91801dd53eff327995da46fc481c064742e4e5f9d6f12467971b305f8f556330e9a04a048" },
                { "fur", "bf559e15793cfc037f5193b0384ba86c287ca86a47fbed0fbdddaf9105d6b87274260d595fbf93a71a9364a81b6ae82dcd097e9aa89b51b1333701672896e0ba" },
                { "fy-NL", "d325af924ac08f0b11393a0fdcf208c0bd9fc09eda08201232c638564e601aec69690bf99bb5158ceb16ea29120b32c240558530af6aa610730b12ebf00bb10b" },
                { "ga-IE", "0549800cd8dae815bd289715d3af58778394eb864775f28f55c02d80bb079accfc033b543b854989014bc11f66d8d560a3bfbe626b89e5b8419c0278ffcdb2be" },
                { "gd", "73cd21f68cc4effea6270edb88f74e48b11e45501d9752c3033a8d5bbff01ce5dd9caca93f5360e55b8309bdb79c00905eb3fbefe840bbbfd0afa91c5965d194" },
                { "gl", "0127253d35481d6c49f4f83e2cb05051ec6a44f081a6e2b41908aa9bda83ec979377134e875f9b7525a50fb340be8d22b20968198d66ed6d6afc69b8a05dd8fd" },
                { "gn", "64033bf3bbed9e7ed8d798cae7ac855d89e895c4708a28e6de0e4f9839efb3a28c84927142dd04f112333a1703d73a949f440bfb780a0ef1fd7cf52617e42590" },
                { "gu-IN", "46205843b8c2b356bb5e8c4b5509a1ce26227842384ae1f8e3bc7bbaf0d1d055d10cb2910a330545c2411fe15796b3802a97dd9c31488d456ced17ee287c0a78" },
                { "he", "c84445e10dcad6c24d18acb85c68b9c80fb5fb15078e9126432a12810428dd673501f537578de3fd0a84f1cce4b9b9592a41ed522b44f5be263457dae2b824cb" },
                { "hi-IN", "aa66a20fe27e0d3f8adff1ea81b20f1b1b59078d97392fb3ee1da4420307fc572841342cd80071fa4375d3b7f39cc77e64b44fbaa696837f1f9e87e17984e77b" },
                { "hr", "cf75421d389ab4bc04581caff2d8095ecc1eabaa49acc9766f7f35f55293cbfda742eefa7170919e6d0d13bbaac8a0babe9497d40e608f55194717f840caa2e2" },
                { "hsb", "d52df1fccff32aed3f29e71652bae1b882ecdf638e221d05d7d221aba1eb73e6453727c44a310b5f5230130d70323b836f584676e83bcd2ae235f07c4b578515" },
                { "hu", "dad27645b1ced7c20dee342a97723818933a7f2d1f89e1766ac7e71ed1d2e0130fe4c655797f8cb30e928d6a694ba0690adcd954b3632ee03c4674705c819386" },
                { "hy-AM", "9d27dcf0339e0d0b0b51ee3b0871389f7e4810de00b9b8a5bd11389060a0b675d841a7e15b08524b70b69617d9a019f35db16af0e3fe631969d3079895ce65a5" },
                { "ia", "b997cf1da84a2cc32e3b2bee61366342d1971d49c60e2aac60c0958249674285a84ed820856f13197eb7c953b70f67da4be7ed2e8a18dcd343a32a137f898c85" },
                { "id", "ebb9852112a1405630bca4bc83a0642d677b00348e77077cec563fd68504c8b8a4907b9eded4dc217b73ebb765f2ca676168914db426a463c9fc9e77d20244a8" },
                { "is", "8d598c8f6847a166780f7cddaf7903ded756c90ebbf04aa6d6ce7784f723f56b4b7da1ed595a28aa75a00ca8aea898f6abda39ae01db4ca26eefec1b9624484f" },
                { "it", "3c4f2b8203c20775c1bb7e5e159d66a3208c32eba4aabcbe29300201ef780e27842d5a82788664713e76e20cda3dc5b77e3af5e26a410b2c7ab94897ab0150ed" },
                { "ja", "1785d117fb8a431c8733d688c915fbc22d9b2c11ad594cd8ae8fd8beda5615c35147aeb22c3543f024159d46ba93d4aca9eb65a0330578b3438cccbb005ddf21" },
                { "ka", "20b8ce47df5d63ceffa1d8240f1a06b1dcb0d5e193a212880dbd1695a2b8235b09b2f4fe1385079c28d2962286294dbf5e4233d4feee703d99b1104a37836b6a" },
                { "kab", "622265a5612e288884477b14e86416cc7c7bd51615f0688956f5594314609e302f51cc1cae2834a1b21e28598dadd31b3115202ed5ce11222b3ea1be2b1e60ef" },
                { "kk", "bcafbbebeec9526e41c608b7c082a11ac17861f3e92c97ff4a2f2cac3655e53bb9a53d41bf708cae7ede6b62c1ef20bab1fb80b862ac2469dc9a724db7df1938" },
                { "km", "803a18a4c717cf5af235534117aac1a140080cd0422f2867ced1b4ab0c404b5a10266529682eaf288101ce39c7f70cb8e7c89af36949f0eb3cdfac625aec5465" },
                { "kn", "623860c9a1d187d933fc351036b9de743c8f845f4b062d10ad64ecaca6fa6567f012c6bb45b8af4370e151e8a06786028c17e130ea4238c16d3abaa234308180" },
                { "ko", "25585dc41940e10fa4cd5bf3b3c9932872df45213f5c07554f8bdee4167ff925dbcee98db56a4c60bf61cbd7e1981f5331f2c55cc45d959aee62be178dbb331f" },
                { "lij", "cca40fc4f906833a1a979ee6104cd3daa1f26d3e1575b17dbddac8fa2bd6437959afe7fe21b7d974594710b3b84836fe3293908e91692c9b6ff077569b387b26" },
                { "lt", "8113123268fb19c519021f5c06b93b4141943f5f08c98d6eb623b68b223c56e7687c57ae739c988298bef7a7cdf605c0b206f13bc3bfff4237c6df8aeb0c4911" },
                { "lv", "a77d6a15d87c011a923ee9e17beb104b06d18a7be4596ee16d6e3ebc0ffe14466e242160055972652f016f4351e92d8b23b34b241678f4aea135f258ffcb57a4" },
                { "mk", "e4014fc2b16186175a3cc970fb9727a409fa7bba7cfb42dd5720b80204ee12e26469568060a29d000520b86a905b2ee5e4bb6af52136c007cc42426dd197f571" },
                { "mr", "27f271da1c92182d4ddfe77a68980ac675a0ad543726918db148cfca7e06e05d57b1980c24e55e194d81c027e6c62dbdbe27c9884b10e27332b6fd29cd3b93db" },
                { "ms", "8858d7bce9ed06e48cf129f1d4a95627623edbb5f4e7b9aef6a5ba1ebb708da751e7e0373eb46a013f237f5d3d66615812d9ffc6897f9186dceccecee03b6d76" },
                { "my", "268c37575073549dcf5b7ba28381ac012683efc412f1d38945e6daf08b2badb0f3b2c0a6b0adf1ac3c643765fa7cd73035742c052df9301638edb94ca5a09e40" },
                { "nb-NO", "8c6c250b4e5f71dd3fa0984a7a4e41fa13bd41d938da9d5aa050c5c788e393e934eea0ce291fcd4945355b21ef4833813252a7e22e40605461f23a7e63432265" },
                { "ne-NP", "15673edd1f35d6cbf1fea288b21dee525a2b77ebd57c79232b1583adbd4fc045db95cf3562c90effb3d3d36e259192b951f62119256e59c0f016abb764f0095b" },
                { "nl", "372e7a4b1dfd1a750dac143da97eefd0e8cf096515e184262d58536963206c24154d356ff918399f4347d2c506a4e9618a4136b512ab9a2282878c22a0da37fa" },
                { "nn-NO", "68aa5eac5edb03fe2aa5d3e502fcc3e9ec07b3508c8d74f31b2dde3e8806464e2945b3946cd56b84c2331fba7e31fca026ab51008a59836b02123680cbd6e485" },
                { "oc", "c48f94c0da51122dc116403a93900e7113c0e58e8f40332eea21ea35db438ca1369b1a0f5512723b1f28514d5b3c63a032cc5b5ce247b4a28e8f79d57808ccdd" },
                { "pa-IN", "af1bd02acdbbbac50409de5d8c98314824b9c213defa6930e7dd4dface0244f2c45ccf1a6beed05a63e84b68e0a18d63837a844e30ca7dfeaff52e133b153bd4" },
                { "pl", "2096a809c6417d2147856eda6fbe5adc15dde5cc5d5a2f88249a919b5faa74ef616ac644e1e76fe47a9d5f80709407547890f8a1adc917cfbe57fc8d1774a2b2" },
                { "pt-BR", "273f9f861a5589cbe54428a7218ae13aeea7717b9fc63d3523ccdccee16ec683acfe1ff93ec631284e35daae65aef7db34faf389e13c11d16bb06b0d2cbb6324" },
                { "pt-PT", "5c6cc0623e769fc57851f616166884f46316913ed40db1d61d1eb991f2346ea4d3931a7260d554601d3936a7d5551042998e6617006cf809171056b202406a36" },
                { "rm", "0e0a9ef843b060447315cbdf9ae9df3af97e62674c5ba1f8d999637788a94559da59c9e852e5b378e99b1af27099748b85ece1aabc9a87a06b47111623737aa4" },
                { "ro", "5db390034641dd45054a1adfdf059b12887235f2456b1557e980f1901c8f549103a75f41809d8f1a1ca44ca776525ea15ab4ef3802e9d8ae3760d770eede79c0" },
                { "ru", "25b02b4ad545857c161d989489fec05f1052d421ed17b3147ea13a27a51d9085f91249855438d363766fb29079d845dfb9f0f59801c230e1eeb583ce0f76f9be" },
                { "sat", "8576e385327dd4f72a40be4191ec56035fe23b6aa0c1514d6a06d9636d9fda890f1d273db42dc87652e62cd0a9238c965e4f49e508abe50dd1235f42ae549f14" },
                { "sc", "05c7be888c4250eae822f141c4ae544c55a44e6b3da8bd158c332b25741b63c3722e839c39fce91ca198b535b0ce13c52713027a51fa6128c2c5d05123597659" },
                { "sco", "393464cb265a4ca56d260396eed8382977c92326a4960977a21863f5a7c8c81a9216a6685037eb343ac3c7c411481c21d378f37c93e29655c7d026547f3fd63f" },
                { "si", "8155ce97071dc01ec2c8875d083fff8fa779055f0cd8b61644d7ab933a72295ab1d1c71a39cfc183bb813ce4ba56942911955b57843bb7b415f9fe456981b037" },
                { "sk", "39f9946c98127b7c1fb13e29536e9af46fc9a0521b2127f7a4a54c721874218dee821d6077aa07b8752da285e09cab5dc9658f2e8995f5578cb6aa3bf0e953d3" },
                { "skr", "3196913162c7a59b5d4bd6f449c6585d0d0f45403488f38f0db5f36778c4a0690e4f7cc2a6c7343b7f463c29712cea81acf9b2fd28f841758e733aae02daaff2" },
                { "sl", "fc954df40f9e7f5e46cd8fc7b40be369fad44b65bdf7d75086dd60f0590401b596cd80298e77dac05628a10ce29d1dc9e3b2b379a75149a219d0fad46a326cb6" },
                { "son", "a6ba85c30f0ce352c300049fa1e589e4979cd89ce81119bd2b1e037549243f3b1af3f2bdf487175b0523a0c57d15777a9f04a0618eb949508265aa158cd2195f" },
                { "sq", "e689337329225efbc75f360d26fa6a7b17fc6aa5ecc8e822100c3c75d557def43b5c243feb90e8ba6a49e99cbe9a01e7ca4fa018face3112c93a9dc5bd58b873" },
                { "sr", "3ee546e172adf820f783da20a95aeb1718afe11f9dafbf94fb648a1f50d2847373cbc4581f93de4d08a1b897dbf36ced76e37e5c97a318e38d89584e8c628cf6" },
                { "sv-SE", "41a13ec9c59513cdaad6984cf9dd2a4c5e7dcb5aa3eaf01d9e77ea501afa0683b8498807dcba13d0c2d7eb52ebc1deb5c2cf1d50224caff81a68818241017569" },
                { "szl", "6beead4dac0c35f36e373da6c30c817ba256132d4e9abe0ecdd5619c334c943492e2691df94c39f2511149719020e61830ed65710e540a1137380b17c64b371b" },
                { "ta", "99215e852166005310a5f440c6bc16baa97b231f49dff433f1637c00521cccdf0b1a26d7e9318e888714f5ae33bc6913618b7d267af6f651206697567ad2dbe1" },
                { "te", "be3c5ae741005738c9098e585011bda91404b6016281b0a85e862fd9c254cdf8e30a0d3a3514cd22ed20e2264016ab3923b54a24e4964dab298e81c3ff28da50" },
                { "tg", "37edc91d5173cfea02adfdf00fbd0a6f479de5d9664e98ec90ccb1a09655a3407def3bb32e60b68fa9f37dded9e005873bac1f7c2ea22ee26ddafee6b7129df6" },
                { "th", "8e5f81f34ec464ec7c1357b8c9594083695c9e01aed04cc78b2a97bb676876fb965a855e5e4c89b7cf07faeefa603bf6435828d04a1c0a184c1100c8bad112de" },
                { "tl", "3b4570c149414c085b7a778d54c30093dd734ddb63e16683641a4c627c4f9df496c5ab832337b741796de35a4e7072929e9a39c121807203040ab7ae01c77f36" },
                { "tr", "4e10307b4975877c6e7609509d0f4721878404071f900d8ea190e47557cb4683cefcfa11be53599436b41356db560d9a19afce228ddc0d11effbf1dd206b59ad" },
                { "trs", "e353180e433010674c9508ae20add986bc7f90c0bf871ea9740fdf7ff552385ce5eef46c2624139034b654c7c6c722863aada206fe6def4d710ab9e79bf50907" },
                { "uk", "bd93402fb12b43d613f59f81fcebd0cfbacb7ac02fe80c3bc40e409802b614d3956122926ce2534ab2d1bb95af4fa3e0ba8157411f1c4b5fd364e1b4470ac9fa" },
                { "ur", "b2a8a64ed427df136dc1a3ae16eb0378ee901381671bb7d5b4cdaed740c1c8c52f56bde93def85556828e203c7ccd681238b72798a06299f71b4e09d9d0a80f9" },
                { "uz", "18817d24dd2a9f2127c404c5e792f067abe0d5e4ae912ce7b9af1b7615827675e20a7c4035e5e8aa8b3b4203b15a1dfc9cf0c43a0d3cb9552be7f76149ff1534" },
                { "vi", "756710371a43974fe1fa3748d312a17a6433ceadb38cd30ccf5286c6109c2f68e430f0320588c1b641e690948f6b0514608b248f4b34e129eb6ff45b0b34546b" },
                { "xh", "31f22f44e4a94c6eee5512b83c24009be051afd25f86c9952aa6d73c0ff21e0031a868ea91b8476a8e9690a7ab43d1b60d6d36782478f42192ea06b470978379" },
                { "zh-CN", "e47e63119367da7dc59fd68df33f2c5b7c1ba6e7aca2b2688562f1906afa0a0fa8e730302302d689eca3b0a2be61527c15e6d337d3621312d3c0eedf29d04127" },
                { "zh-TW", "1fba9c036b178f133c798b9e51b9f626910644e53fe53535b70e843e5b0e48c9fb01e3f3e240734502a4e933da226b45ca160472ce2b438aa0bf34651d6753e3" }
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
