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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "125.0b4";

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
            // https://ftp.mozilla.org/pub/devedition/releases/125.0b4/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "0b2d5344a7bf1126409b1866a1821ad593653da7784157675a298ed6a61edee29385bdaaf81a28cbd709f984f1754516b36289d98aa13586cccc04499cf61ee8" },
                { "af", "bb77d0e8713b2109f22195f72a0c9d5946cb317640d010b59ff5e5c17aae760973e62014b612cb7074349b066722fe7bb03918347706514f6e738dc543233f49" },
                { "an", "d852b79834fd2cb09f8202c372e76ac452c70421e7b05039779f8f8434e13167f9bb58e1b1dbdee08e29e34f0001f92adc9d3780251f87a753e5d2e7926a68f1" },
                { "ar", "6b0a1add7708bf613458de839264d4946e8cd1f5f19fb0213db54c7b9b90a4af339e8015ea10f8b298034111423aebe1d24eee60bab511ef05af5a007dc25bc3" },
                { "ast", "7c1cf5b3dfe744f40c4c515082c885216cd3499b476bc53dd4ad833ddb48d65c9a8a10e7bc66efd0a9c292184e5c4fb5b215a15dbdfbe92998568f86ade3797d" },
                { "az", "2ad91534711d76ed6db33caefe3d2e1b650728657d7985f24bd3284bcc708f830f97b8b683781dce763421a760d65e3ab70b510618a9c79cced7348b60f0c50b" },
                { "be", "1495af8b42626941809d18c18b5127399b1bd3ad72b6fc53d5a589689ba309116ffe0f0ae69cfb99fc59ccbc904cab6f72f7fa5cc2fd8beff10c28e608f17e70" },
                { "bg", "383753e2a97f857af159a0be2831eea72ba1d405746d2f499d8879c66e3f15a49b1e05f19989bb7c8261c0c3427de2087cd3206d9cc080d8f240463ea46a483c" },
                { "bn", "47af19b76414a38943e7707f74241a4ccb71bd1293c149f03a27def2d6f37f7aabe379d048a68b5cd415adadfd21c927d06597886423db504a5b39633920f26f" },
                { "br", "f84c31cbf47dd24133fecc122486790d9c3a0c72103ca884e71436035de61ec65e969fe312a4b54125f0863c46d41bc23e7a0c702709eda24e8460a78eb2d987" },
                { "bs", "5b34ec5a0214d22b297dd5366ed54f43928626b639ec727b5d099b21c939198c3f30c4c4ffbe3d65b2c7342ac31bb1285a3dc3916a4cd5de694e86af76d892be" },
                { "ca", "6fa704dbef157950629daec0fa40133da342a5387ca655c2d2e15ae464a4b1d08c7e8eea297ea3e0ebbe648e96f834630fced43439fbec53aa7ce7ec098eedbf" },
                { "cak", "1a47cb89c7b5ef6ba800da20a7aac2623de1bdcb6bb8cf1459e54c1872b07cf2444254d41754518006c3dbddc970ae16135acfd935b859494ae63ae8bcbb1f22" },
                { "cs", "ff804409a633c1373299e4dfa42817eb606a0e522e0c1b56a85752fa9c014edd06138a31b79c27b40f4f8d020e2de7345a098b9ce458c0f2ca4e0c4281efd653" },
                { "cy", "8abd33a91fe92c06332148409537e292d82370661ca4959ee6650e4ff00de2acf5f0a5bda420598744b55e9f77fc479320851aa215a57402229b15897d260ca7" },
                { "da", "8aaa826c803b963cc864d4b2ba3f8e7cde8140ffed36d3c92a13773dd443752bc1103a31266a64187d168c5251969b51c6377baf6cdf65479dac77d17976b4e1" },
                { "de", "7c23a417f7ff2994c187ec92738f1d6cc8495b8781ac64568da44c36a2709738814d1b79f8f9ac6924576600a12b7904eafb575faa3a4c0815559e3949b29ab9" },
                { "dsb", "d27da058763410a58f0f6ba0bd19ce2339220a5dd72065e1552ab0a840aa488a5779102c83ff3edfea3fe8063335bad32c966dbe8de3ff4ecaadda716f75601d" },
                { "el", "6dfbdaf6f9174fbe8891e521ae8d7cb34218e9573bf5f509e19fe5d0c33cd6a4503c51ecf1f862745c1adefeca05a6a30ef450475c0ffbdfd75a5d6b84ecb537" },
                { "en-CA", "b6466b732347ff6da4296f9f3b89a7e227872aa5521a9e49f5869d9e6ba225918d8ab8d7ec844709a6c8fc54c3bb225e66ca11c4a91e1b0e7107ffd6c72b431e" },
                { "en-GB", "c5561b56d469f72c2750e575f0b7123a02d55d38228e9da4c9b16f0de2528a24b1e32b06a479a24c14500e1df4e6362917951ccfc8d3b703deb68cfccbebf0f0" },
                { "en-US", "68a60c705957acad939db280bc5d917c28c0d0687fce804dfbcb1e8dbeabfd495f032f261ce22edbf3176634bf712814565f1c9b3fd36b190fbfdce34396deef" },
                { "eo", "9efc44c5378369d60d66fad8822f4ce1b69c062d44fc95970b8de0d14f4a50eedccd529fa67ebf92eaaf664965aafafb95fdfae3b7de16040e370d5ac12310a7" },
                { "es-AR", "942f9a4615cc66b06ce4eee6f0de74a5bc598dab6445402ab804d1e9c4b7b5f57c27627fc06c71d6bdaa800911098471f29aefa2d705c81faa9475f8abb2699f" },
                { "es-CL", "31e0ed8470fdaa01aff1410dad6954c40ef4b409bdc4ea53cc30e57a55645863b86373563727ea0285d35c29fa11b75657817913bbdcb43a4c2a657849c63b4e" },
                { "es-ES", "1364fabadef969eaa2da75f3104923007696e37b10873f0eaead0aef16ef8773a3341bbc5b204e90af11f19767426d26b0956ef458cb1e2dbf1069f7e99a221f" },
                { "es-MX", "968498a1590bdeefc7966352e93b2d2b11616baf5001a442829aba5114ec92d6e197461edde6e00499cf0f2947cfed8caaf5d3fe75105a7bc090a40d3628b9ab" },
                { "et", "0b2c3f8b12b05cb76be5e4cd65be81df45c7f95fb8227fdc12d2e08df9cb0bb2698f49bb0bb44813bbe853ae6ab8958c8f3f8afad3981a28c2fcb11ade7523cf" },
                { "eu", "969f850d65df068e1308d719375fabc20b5d9f6db716178d2462b4e13389d69bb6122762ca0ac40e4d49846815cfb08dc040a00dcfe8b0a94c5bc65a6fa1d6cb" },
                { "fa", "54aa482ff285c2275d83f9a844cf3f8b22001545398b09bf6caffd46c1406d5827135af05d02eb98f4a1931d62fa3262e27cdab7151ea27f2128e7bcb244c296" },
                { "ff", "e256edcdd392ebff0a7a54a5d0bebda18620256c237c5b7bf61968d3111f24ccdc44ca312b4bdd856a05a1bd7ebe04bbb72d7ebc1437bd430b0e0ae2e28b0973" },
                { "fi", "833ab65cebcf7e8d493c35c57504dd951e652079e9fa711e43fb3916126533ffc3da493928af89206d0ae132f18e779e5582e3feb0e7699d053bd35dc08b4820" },
                { "fr", "93aea116327f2cb02c8675a3ad3529e2ae3c2c2dfdc4d2467a6b6fea39c2c488c593b3b737318f9869def85d16d368d5d132ff4b5b002e91a1630d65763eaae6" },
                { "fur", "f38dd986b64f09ba47d3374856b4613a3d89c30d56a4d137d09d9adffaeb4b54dd04fc309f74283603afff11c333674c24782df555c3cb051f7f33b65497bd4b" },
                { "fy-NL", "ff7aacdf64b847ba48890897b7bd775e6d4170e3dfd67ea9fd157259c8e64d9fc772532a469b6fbfe9d4d6e682813e7856f5409f20bc07e4cb84dc9b634c4c03" },
                { "ga-IE", "1dcdc2e75a3cf53dd5179850133223c6a87adfbfd8d2c2740d7d28057e58a63df083253fc2b0cf08beb956638ae887993d3303b6f1bf43485e64e406c2001987" },
                { "gd", "3f9d478490a15539a4cc5a5db7872938e96d5c8f1ed6f5d357eb6dadfdda445426952c871f52730342e9f5a30202529165c889ae3f972ebbe6481eedba35c45a" },
                { "gl", "b8191d2464f400991b6a4512cd1eaee8eeef4ba5b5c1bbb81c7a684e12d710670762e966bed89eaca62d47325b56c02dd6c05db7735a47b58342e15eedec4444" },
                { "gn", "12fb83d48811eea4740a949a4b88529d3f1fccd23f2df93a0943ad416eff844b85944a6c3b3626f7da64a92e4324c212845ba1daad22325f1f7a38c3310015da" },
                { "gu-IN", "5931b425312c0c98a6951aa755d91bae0f08029c4088b2d66905b1284f6f408bed6b7ae584fe749e45aa868ea3dc1109176b1a5de4826ef623589594a40c253f" },
                { "he", "e6e6e57e27ae7e868e38a846b78319b3ce627593b409f8dca14e38599ed7e257bcbb0bf6669e351ebc654eec6f3b3dad49f9a2fd084c4dd9ef13118016eafe88" },
                { "hi-IN", "6a408de5fcfb58f4bd0da84583d3cd7c38653f7619b61c9cbe7cd1774d853ded9d7808443876d4442a33e166cd1d029b85095fa20d46f28b67e5cdfb2f85f8b9" },
                { "hr", "7c7aff79c1bd34a1b11b92a45bf5473d626c7f10ae2e7bfda669300ff42a5776289a37123aff31436b21d7c0c186a77c0f2763c3d606d2727f12ee6f0abafefb" },
                { "hsb", "c7d1bf4bac0f7e86dc53e6ee945632e5b69c25a3556c6b18d0d34358a0838bde0a69c227b3fe8f7480e4b3fa5331f295532ac7df7b6ad0d11f5de6e8c1789531" },
                { "hu", "5f79a2fbe0fdfa3dd7a2144ed9b496e47eb9782ae0e34c6dc0a448397fe165dbc7ace2884fbdb8cbbb5b3a451711f424135e51456b065ddc9b81f0191be9728c" },
                { "hy-AM", "e6204adc6d7e227bad3913d0e1dc70653e17b9d0393e973eb9910027cb676b544738ff775372f57e1ceb4e1c896338f1b90391447936075d05017eaf09c50c57" },
                { "ia", "0659d9c4a00dd5b16629d4a5043f287ea5aa83680bc00df6c5a3c1d709545fddc90d5fa2c683c667debbff6f0e9292466a17892d14671bbde99521e1a68b2354" },
                { "id", "8a0cf6475d3482c9e1563d64003f15eb71cf24364df22270bc62290ab106511fa66b506f4a2294964ea4b8cc81d92ea596eeab2e65c01c1458e8db08515f2ad1" },
                { "is", "ace8e8fe654e3087b2c9d1b977f9c4d826690fc06981015db2dc78da7f4fff00a601a015f8ede6928fb1b7ce4b48ead1a387389bd5237a8726cf4d908d030d4b" },
                { "it", "b79e0e698ae3c381951521d38cc098f2adb9e97154a25a83a62d1fecc83042e75f0d6a8ab385367ed9c48ed4b9e9959b09f76788f2596348d5455d9460e6a077" },
                { "ja", "b870a29a6374d296bd05078e12cb73cdda338d6f06b8c0fb90429d34c781ecbc2855470965c01997f461acff59bf735e45c92c26d6b7f7d9698e703b7ccd0e63" },
                { "ka", "2ce80548b3716445b56a0f397854553b1e51d4b4178c048d9b72955bf7c143c0a82480013a5905f6bebe5aec94c11b296bde3f3cd8c8fa208b9863051c358d5e" },
                { "kab", "5488697587e7371c343ae4b4a211cf2e8b73c5c17d020f1b0f2e8e40d0a053f3fabffd5d07a1c9c927a6bdaf77f1c85246b0638a18bccba6035aa77fbb141837" },
                { "kk", "549bd13471c8c5fb775c7b2ca6cd8afa5705013bb0955f881273a0c6becccc62a6c43c55697dee9c8d269c55d1bb71e74b5a9c06b19ec68ca5a98bbf2bce00c9" },
                { "km", "c6c538cca1f558fc429e9b47138a92c49b96c21decbd73d90edd6337938de34c2c5961d3b4f90a40e54e8859097804732549fc12d766cd47c33b5415aaccf218" },
                { "kn", "759321fb430e0e43df311dcfa32759196c4d7e74ab4acabe0075a099a71d26e8dcc0d1740169316c690f879a74d5addb80e1cae18476939cc105965831e7f9ac" },
                { "ko", "29e33810a2391d27a07fb464a76755ef872df131cc021a051c45b3212505a04b4175ff97f4f9e835694cadd2df034b53ca25b042efde8b2457ba5d1712b1c35f" },
                { "lij", "024af4e0ce8a4c1744e87ed7f9b8b0d42b0d852e31ea26b84dd8b1e74c1a536fbfd5a540aeb17f812e266ee29885e60cf3921fd5a129c8a2d5cf27279b7018c0" },
                { "lt", "4bbbeefe3c7cf6046958f9ae0e2a5a1b377d1095ca17546abf915c966aeb97ee2d81a4591214afd2f958f2dfa88cbce2ecc8f2aaf4fd0ac213b52f230d264b5f" },
                { "lv", "10bc6bff32671952b7f702b30dfa77a0e5c05d58b04c4c81a0c79efa36903e84ef8fd45c763032ef6f55a492af7b9ec3946c23737fb93ecd9080c387c9e97907" },
                { "mk", "380db2a6ce18a0128ab55084e2c9f01f7a3f09e95275f76a912f041a16dc398f40a6d138d2270e9bf97d470facd70c42c46fb365172d091b033a4914f60735d8" },
                { "mr", "0b85f4fc67ed7ca39fa2a58be23fce61c6cf9d3506e2aac952deebd2442dc822a4c5013a1a6c8c3636b45c8c4f83b712885314640667ba5594f838b0ecd638b4" },
                { "ms", "92a2fd300ed7d7115387967dc2af4d0ce93b45cbe78c627be9a64dd2fd43df9d346806e5ca8818a1be2bf1de44b57efb61f40d166c475ca30ea87900db75b16e" },
                { "my", "155480080bf76ebd8283b4c216b512a7ca91b85aaf903d6d37b3f71bf72ab306519a9feb3e9492ce0855780016532c4430e7a24b6e424cb53afd6266a6ebd50a" },
                { "nb-NO", "f32cefa731e02c090d4ba3b37d79e3b4d954da2c90253ef4948eb44c06b3c92df0f8117e95c800e19bc4b17037140e4b78f3a7a761ce83d60b0107e3b9f2239f" },
                { "ne-NP", "6928d8253abb3d37d30e164ff35548ad594a8425dfaba7fd489147a2bda33477c56105d018d0ba121b3e0824b703e4c5e9a9330cad6c25effc94ad924869d195" },
                { "nl", "634f214d23a3e0448918f9fe564339f8ea805da585dcb048200a389ab2eae7c815dc5fce6b933458e916ba01c7fb84e52c3531662c090759390b352a87ad5a0f" },
                { "nn-NO", "3ce70186ad97a6bae653cad537732368ec80943d87ce292659cffbc2c4532ac64e9a927bc464f2e7b380f3405efb612041434275354980992e8570f81848b0f7" },
                { "oc", "d15d2c528cb7f982b040c277c0f9f38abe4587c53ea1986abe091c71486eef8099fda41fbe6c9fe86a9a2a662f1091eca651f955e2cbb814ff9d4e034df94e7a" },
                { "pa-IN", "395692498b2cce7da7e079df3826499bb6145a146b14525ca95a2869bd4e57085299b79df6800258ba0b50d9cbe11c4660fc3de23b72ad43b7e37c29dd23777a" },
                { "pl", "06a1f3b783ba6f1f776b4f3a3aed73544ccb338c4172d98d23721195c65b0dc76f65f0e2fca7ff3f13bc30bdb3b7ddde5c2439e3401b41785ab61a8c932d3bd8" },
                { "pt-BR", "9e31abaa7204e7a00f88024a9cff5207c957cafb495e1c6027803e9eeb157287339ebc8549414fa2589f0f19f93f692ae2133fc1227fc1901d8b0d2c72342d6e" },
                { "pt-PT", "5e57cd15ad7c486a36845ebea1f3243f92ee701cb71576ab3000c2d3ab3416adeb774dc18acef1d79f88746db47c5f759f49253f00a18f154d51aba011da8a72" },
                { "rm", "fa5526ed7781c5bf7e0252f00e83d87622def3c44a93f7bce7dbc9855a51d59408373876f5136fad5906a2608518b4d4ea2cc689effe062ed56a1af6d7502b79" },
                { "ro", "0980d06c1bc0a79ccf5c88eba752d9149213cf409c4c8d1926622c4cb555e00d2754e49c7e5e07499fd1c1f08319103c5514a4f8a2947714e2fdb8302904b848" },
                { "ru", "0b289d6945efe1121dbe826abaf9147a69fbe6f75a7bd0c5bacf65c7e3132b55eb7d70f172d6c67446526ff10b9f43d7060122f20b5937269fa9616b3d118b7c" },
                { "sat", "8fe39819289cd9dbcd25461886d5e4339ce8990887f661398680f2d16187cd6d6ecc250b841473c8d27bf41f2f6efeb17cce3e57cd0e718c9f8892f37a21745a" },
                { "sc", "597704440a6e38c7ed15b43c1c31f4f49411cd4ef190b8f66c3f1efd93b0ea3adf89b859b9aa29bb7a0e10d4509ba51845751e461f251e86c935bd70e117fde7" },
                { "sco", "3d83dc2a29ef1342a58c5c68b97375137c081822119f5cf79fca66bad9154441acec6eae47ccc8900be5638452d4b44bc6c96cb45f379ca714e89a773e2f067e" },
                { "si", "ce4bd5cf0b5687cc2be713bddf146b5c23f9a081ff3ab1e83779c9a1b86506ed0602271bd1c66a757eac08d76970fcab0e59211d72604dfdfd3e38d855e422b0" },
                { "sk", "95b3bc3d11fa61fcdaea0199ab5f2346fa1d542934651fd39179238c26a854bafefcd2357bc48f3696352ec20b429e6832f289958286c992f51a140fd3474ef5" },
                { "sl", "94bcedbb6c2cc022769525f4caaa7bcd624e551bc4495bf4bab960f2414f32e25930d69cf3db02f4873cfcb0658505ed81cb24c3ff937e7c1eca73f7e08c473c" },
                { "son", "469c9a02d5cefa80a6bd38e944e71fab6dfa3c0d99bf88229a250c182990b7d6a3069efc8ee16e8e0b06b9e85c865b6790fab23a1834e07cd7ca9d2ab0356a77" },
                { "sq", "874346e7da86d724075dd1915b467526817e9fbe9f0104decf135c94b5da30f1aa1a13366e169b5f8d4f1c096986d4155595a0367dfac4929ed673c8d7b92322" },
                { "sr", "c2c976b8e4c9ea385b13c146c530a1d2b5841bd19659d55c4dadac7158337f5ad57dc6bfbeac2915c242a8e5dcc893d0f70f520162a3c706e622e48000d81434" },
                { "sv-SE", "811d0ac6400fccfd67b872c7e3e0813c58e262ce56cab6197b768b786f536e7f6bada02807bd0cb51f254048b064eaecbc68715796a92047d53878ee857465bb" },
                { "szl", "8d897328c095fd83120c31ae8b7e2e77167c600ffdf4131bc78f4b8f70938f3d3ab9cd7764c70f74d99c73d4a4f607988b5d7d82e1cc3f7f28e45614ebfbf155" },
                { "ta", "b7d88af80856bbdb61ba3aeae9149ee18e841257b2e84eddca5e0fe3afc8a43b08720f620f23d06fda2532eaffb4c8d071deb0239cec3c94de2b7d1d180a7515" },
                { "te", "da0162f71662aa7c92a94e55a9bc0c089a434ffc5e5d751cfdb8e89feddfd23a60d29539ac87a6134e0f2647defeb417f78aff1bfbcd7e4c776dbab510cbc055" },
                { "tg", "9a45511e3dbe70932a1d485cddea70e9f90ce482e73bcaf6800d76446b1cd9804a59c31985b3850aac3160f65e5a3f763acd23342f36497e761e12d390c0fca9" },
                { "th", "fac650b860263542ce3a64101eb26775943ca1d6fe26a212bfdc29962bcdca24315e0e88da442419c080cee01d2c36c84d22a1e908b46b45a802aca3faf64560" },
                { "tl", "26bef3029d03df9b8dcce5b5fe656ec420a56b35bbf2015f2d651ab069434ecc6797ff6c8ca4d8eb75cc4f55293083266e224e49262a8dacd9bd624306e3cf62" },
                { "tr", "081aa49ad4a772edbf2c3ddc3885c2dbd380805fa1bcc4f229b909774cda9be639551a1933d1d448f92117b44644347fc31239b6c7e3809252521474e3ffefec" },
                { "trs", "0f42d594b8492937c729f14d6802d6cd822b32eaf3784b254c8bd689862826bdc5351d2de5550d906bb1b59248b6700aec212f8830e0d122421060bf864eedde" },
                { "uk", "3756e5229f448618428bcb16415b8dbf09e54870be03cc92ebdcef623cea8cc0eace2c4465a8ad3bf05464aaf99f30491051809ae3d28951cef04769c3770e8e" },
                { "ur", "6dbbe1e4697c1fe34a6022fcdc53b28aa04aba18e553abbfea6b717ef946b22051b09f5f47ff093553ef54f9750201995489f5fa5eb2f4674d7f643c09b721ff" },
                { "uz", "b5c205a7b237a7945685e3cb494b80f05172cf36445aafc48e9720e03e7ded2eea360eafb4cc768457fbd13686558cb29e1acae98c40c0d9e1aff0f618e9c94b" },
                { "vi", "a0520689cba697dfd4b5a4ff5bbc0bb37a22dfc2ca33e4e4befe9913568e50cdc6d658ae93ce96488090683af60c7ccd9c656f855405395788a1c13b1565d62c" },
                { "xh", "5752ca0385b2f7500b9e61fcea0f7e17920e8ebdb7ed835f9089e38a73b11d01953e1160a2610e315d229dc1d9eb6c4b949b6c9db20e7361e0d1708010982df0" },
                { "zh-CN", "dd8406869880f5765d1ba894dc5f22db057e0507b24e59d590c351c7de6c524623f74189a6e6c00209265cd9305e9c8c6d50b4ca143cab50b40b4fbeb1554405" },
                { "zh-TW", "e92b448c4fc699ddebfbbe681a6012d3a7b78a3715d4c2a0420d4123a0fec4767cf0afad80408a8f88e02a9f47c44d2a69c0bbe1e51800710a237d3b849e5090" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/125.0b4/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "11cf6b855533cae7968f90ad546fe645502cfaa89a0fc10f29fe3a768c336017748693bb81991a5a524434758395325fa64d3f0a5fae7527743e79dc685a765d" },
                { "af", "27f2bcdda36b9477716ab7cfba03c8fc12aa8a5e58a957a2df55e22e43b935bfdad7f0de492c3cde38944a96fa58ba9227d7632ec83bcc685a49f5694bc0bef2" },
                { "an", "7393148b999e02ef825de6dae100252d0e4249a819fc61b9061914faa5b61830f17123375552ea37da8ac9165276b94c6cebad5747b76b935bd1a1cb551ad466" },
                { "ar", "40c948bf58c1e3e3a87382781f3ef13e83f2efa19124084120227f33d057e7798724a027e08d87f8bb77440b64f3439773d37ac9d6fd48612a7e2ee842db47f9" },
                { "ast", "29ce888d22fda108458799f4f3ff2fcf0dd73d138de00e854f46a3808f8a56a11e43923fa8b52b49abc301a75189d8ad5307f154ba0bcc792d56bab6ca0d4e0e" },
                { "az", "86f5cd21eaa9164bc4adb01d060330a5bcb27d9a4a7540e0d8721bb8c0336c1340ccc41260b149ce7141f3f5004278d3413ecc476d51c7e06f3e0213c1a14abb" },
                { "be", "6ef96fa9f2822a71a37bebdb520b1a5c118df9318d5045ce62015240ddf5171835071e8d292663e98fde541c9465c53edc0670ef137a46617b8179ae05c67141" },
                { "bg", "f69502bad6a37f2b1c7666559beee5b6574626d844e35d8eccd7d491ece7805bdfd54f122d1848bea2235a7c0eb068fef98aced2d1df9ea368b080b6985f0521" },
                { "bn", "829fb1f7dd8ddf9e52cbea9193b5236b95dcab2e54b3ece116d0c1df7293ac23829c296675d7ef4476c0ca9869b4e3f03a2631529831499c9beee81e5d461ae6" },
                { "br", "759df7dcce6d1e8c715661de6ef33f9bcc6c166e9f40f3c669084359991703e8978e64d32f427b8caf25dbe0a7e0c1504d338e48449f57043c911c7722c11517" },
                { "bs", "5caf4b2068f38c237a6e794093e3dd46a3485d2393d1a46d0e12fbf118e7857e05313ad7d16fd8c410f7d34b86413b9f71998c0d9cffc03526bcafa7c0ea79cf" },
                { "ca", "c9aab7e68bb90187a35f613ff6b545e71346b62be6197f8518bdd4020b21d5a654ab68c96401612553eebc8bcfdbf70785784b9fea1fd32928524605b2aa8daf" },
                { "cak", "e00bc195f2660d6c36fd87c236a75e95e00f7c72a4fb585078addfc8738ad4302836394cb2f9979eacb2e8d93cf9502f47a74a0d9a2287396468829c72139344" },
                { "cs", "20753cd5fa13b0cc1c05ab9734a28b572aeb2a14a8e65faa3ea79fba48550e3696737f04c8ac04ac3ca204d29f0e4aa71edc482680dacd16e3d4d69231c6e462" },
                { "cy", "ffbbeed80a458979c82a576c6c9f9304a7f2aefe11d9f5f111b7d1115a6e68654325d1516cd23c512223c6ffd0d2b71407a8a7fc8875f688a67455645daf5060" },
                { "da", "7fa035ad8633974b4fa231f4cbf6728798390fe7284c65241d7a761eaf4bc25622ce86ea7bec65881818ded780594a0d7d4f9fb450de74c218e6da5288195412" },
                { "de", "23b8a08875fe4c7955a17e25088ee0e948624c22a645d1fcb4079a8807c85225e517fea36c9fae92a00518346ff44ebbf8dd955abdaa4043450148296725d8b5" },
                { "dsb", "d9fbd6ac64707e1ea0eadd2e9654e71ae8beebe57cc4de5e875919477ef9a63bc648d39711952761fad7bc4732fd6fdb67a4c1a13f735e6c1bb5c781ea7cd2ca" },
                { "el", "e2a9cd8c638e83be3dce1d3e15d3c57cc5361204eb12450730c966392ec2061830ef280d3c48c948aecf115f09979c9ebe7a955e1a8523be33b05da82cbe57e2" },
                { "en-CA", "657f0a6f113dc4952a76d7754328e7cae308ce5a49dd2066f893d5fd20831b3fdd58ee002da893000356950b6fa8bd0255c7d4502ce17bab252ba8bad84c3091" },
                { "en-GB", "78aff38620cc293e446ddaaa083cfe98b64fc91b698694e6db75738baf0e353fb12df979c951b8fbe3042ebdf659e167e1f6bc417dff199b982298b3feff99c1" },
                { "en-US", "2cca0581c07ae4d99efddfcd3f99a2444b0bd13ae6e7c61510fc40221a2ecbec9e3defa47c16fe8a715cde57b1885425a07501909ac8bcb7ed1edeb5b58e6aaf" },
                { "eo", "7de9fe43a98982cf00e5ef81ce685a1f841f42a2d0da7ed18df8a70790b2336a5116570a764e3c0a99ecf6e3ff528ca1e0714b36a06d9bb4715ec37a3261ed82" },
                { "es-AR", "cd8d6b5e283384ceaccb1cde6ebc568b7b8c4a4186fd4442a32491f66704466a2b7e1b9a5beb2fb97cbc23c855708b043665f33c99b55f302b2406550fafcfc8" },
                { "es-CL", "e1201a3c28c070ebd7fc97800b98781f4ef0566b2b3c00e645ff7a0a77ceba39128bb760d122040a86835261a9ab7be221b65c06f638dbc65c11d2bb80bb1d9f" },
                { "es-ES", "d85f072514860084b7bba886b7ec4bf5eaa1dbf2f9bdd3d11e511aa6a54832686451206afa2f7ec52df500659715cfd4d81a019834674d438647b10655b8f869" },
                { "es-MX", "9417e471bb89535831ba8d100bf1b5c4a0deab456babf64074dcb89b92eb165157c4f21e1ccfd5d936d31db8212bf50ed4cf9516874b32aeac383bf4ebca03c6" },
                { "et", "b11e439a3e677434a9b7263bd95b0b089ca35948a4636f3b688853df09047fe1c5b81e7a0b8a12809bc0cb9937d48a038f01f4c3aa81788452009953ca540bc0" },
                { "eu", "1aabb87fa11d820b845d88af8cc5d43aa9d29b455e3d88ffe99ee314c70610174ba4e82abf95593b43de13a76d7ddbc1fddb725c8dbc1fb72b301ecd99f889c3" },
                { "fa", "ada2b10ffb25d3763422893180161370c74293e8528b5dfb315c21260ea54c5b309e926d39d5e7104fb1a5edb3b70d0d645e7a0608091c7293918ee15e7427b5" },
                { "ff", "49d1ec1507a8e6a3aff521fcdbd8cdfb0b7bfc487c8f4e240909aef1552efdd789427786789b0042af11fb47007963e3e798aaf704610210c9087150588ec49a" },
                { "fi", "b793cb97725974264c19e8bf3686e3e2f1ece667e8d1fea2234ad809cb1a19f4f705d746bbf1de35a68a7c7f326a35dd088d26cb1c7dee5a008e6d38623eaecc" },
                { "fr", "b5382d4e175949756cd77a827c4c0a574ac2de020b1fb6a50572098ba9c4f2a65bd8755137e2347d2b2b15c4ac88f6fc690d0413f43260222fae2f9b822bc6a1" },
                { "fur", "c820324111054379a6055594eb48b1574a4ea8d61ccb4fe2e169b6bdc75fef7203146856a468679da3442d8530f102495bbfa9aeba0efc909b3d655b1fb2b124" },
                { "fy-NL", "97e59cab4dc81f84529aa6a143a948400eed08d624be6abeb4b088d0db855da5e11d7d2bf72d3f49041f48a2c27cc4ad9b252b5c6c94197898abae4438d43766" },
                { "ga-IE", "018cba22a75b357a30945e6186c3eaf773d110c1b5236b7e54b42fcd952d277523e75ccc96ae21ed1c96c0aeeb6656569f53332503a2a1e56282e4afca6f0290" },
                { "gd", "a52e28a2265c3fd3593a6f5b8467e2721fe46e97cf4a216b2eaea455a29b774c2d50b5d7b6eb4bf54cbf4261cb4a9031f947d96eda216950792be9c7649dbfaf" },
                { "gl", "7e9ee2b7d245a9cb986d41408b01ca4513a338c50f51c6df895e8f50c01dfe34ef1c3f7108f741f88655702ec81c40700329e9e0b4cf0ab53eb09b1115394185" },
                { "gn", "d9666fd949cc4526af5ab5ae753cf0c17406c99e04f44686bc904e943c7cec1f0f5143a332e735a36cd81087c5a4d2ad8f74f6bf1fa55519e09cbe9cc25b2f29" },
                { "gu-IN", "b03ceef47e403b60b1281859fc7c2a499fa3db840a1316aa7514d3b771c5201433a3522b068953f3cb1d07fbaeb01658c327218561c1f735655643e74012d0c4" },
                { "he", "d456fc409fa161d27ca44046879f001caca51ea261859020d4999be080ae17d118bbba9b54e13adaf174026e89bf48d0007544215ef3be8f38d99c0cf33e48e9" },
                { "hi-IN", "b4ac3c67028e726fd596aa4abc1c594c3c9daf43e8b21a96cae78e02e1d87e36453d2e6e21cbe60f38cf86c6627cf19bccfc3ff4013275539d6a483bb77e90a4" },
                { "hr", "8fde9ec3e8fa1bc3c0098c97d863987f420456326bb94a7e19901dc5eaa54f1248aa0a0074b33884b01ebefbd8cf9ac8fcf84fb835a6f1816dc5ee1b4a78031f" },
                { "hsb", "eed767ee5ac6f7ecc726d7f7f83e29b0131314a6d65bf914c57c2d31065d11f128965bbabed1524a5bd46f9ca5eb9db7eccddb62ce1c520d471b1249dc189123" },
                { "hu", "adde0535761410ab67e9d7fb07e3f6a44ceb985303218e4b9d2b60bb9339ac217e0c5af3efa659a2c716901a7709e8725def7694c33733f38e950973d82d5a91" },
                { "hy-AM", "3f1e344b1264dda39ec1278220764ee097f0c71477b85fe7e196e62891bced6fcefc73fff91604fbb544653d9072b17b08e8dd7099150850ef2e6c9dcab44e52" },
                { "ia", "b18515362c5d690230007c4aa2be67ac857481d3f4c7816bf52f86eb1a1ed2669ddb98f6c4ad1b15d3c9e963bb18f14a1169ccd8d3dff2838edfc57d2dbec67b" },
                { "id", "c032f60d742123b2ff38319c9fdd55a237ba8da4304d44626aff3073d17e8faf424929e2fd721e4b77277ec96a879f5522669588d630d1d13793125448f63d40" },
                { "is", "041d15eeb6d503af4cb7193bad23a3bd6aff68c56e8aa1875c197d63a15c34c6095a11033d08e33fe50bdf9652ebaf4a43e414f26395964517db3c1ab7bda5f2" },
                { "it", "7995f674acb31b66d62729ecb37e07b031800da62179bb6635621eb4eaed2529f65d0efef92e0f5ed0bf803c614d1bfabd0008b6b4dcd95ed9ecef237d20ae57" },
                { "ja", "7635179608586b19f53323f14d52c55a6b435e46ee9c1b2a576f084fcbff279f6a6416b3d2bb288b8c00dbca185a94e692d3eb82aaf00063fa963c8628d8d19e" },
                { "ka", "c1a5ecf425a3460cf8be05680d452fb20fb60822745d5201c4617a3e5d435f62dbad00b2a94990686bbfd81154024cd37e74768ff608a1815fc6d35abd3ecfb5" },
                { "kab", "7992174df2578e522d233ff6afea22a1ea92c7fddd7554e80deb2f644e149db2e2bffcbaec92e6c7717c30ca3f366df95dc514014997757993c8f7ad8ce5ed76" },
                { "kk", "72f0d726189c95fd85a1edb8eea4b7f63a0589835d6516d93734df2b7e4362f512b43fcbbb9f2c75ce2be10918357fc00539bf2e022442101289762cbadf26ff" },
                { "km", "c07ac0862ab9a15ba48a8e05ed9c9dd4437258cddbb23bbd717e004475707f9b141f3d75a13b748efc04c216f4bedbc5d20d8a933bdc2b15fba5d3d0f0e14d4c" },
                { "kn", "b3fffbbdde30c7e1180a57de3533f40b55867a569e82e6185249ca931a45c792e496618ef4eeb394d6761ae1d2274d4c34b0af20c0ad5ff379575786d1fc01db" },
                { "ko", "878524f27fa626a2ecb6be9e7cb3054b731606205fce08c7eec9e5058fe8ac5fbd97fd856a520fd23259d8f67b5f5ba5d6c4d85363c6cbd4d93ca7b87d4641b5" },
                { "lij", "663fdfb35531b456c7bba65a6e68cac3ab9d05ec05e58c2c8708ae0a0341f236033a21095b0a7f3f95d63fa917e1300eb414ccf29ad413fd55e6eaa0b5a82916" },
                { "lt", "61bc451c834c108e1df82d20d247309137b7c112029e315df9a51e53ca0c309eae8be5777e83acc76dbe425b8c5c24f6052d08afd9487a827e8dbd8f9c321316" },
                { "lv", "7f7e882b45442fbf88364bbc333ae85e79d224d25504687c96c0431898bc95c1e02781d0fc11b372f0afa5769064edb250908b5040f2637fa43c946fb351000d" },
                { "mk", "fafa285b52e91e8ae30afa1a0d65801f0e9cb61feed140282e022ae1bf9451f7fd5aacf1d86fb2be5faaa8f010e75bf6242e6f5c2bb16afdde225c63d110fb40" },
                { "mr", "bed0a7da8cbcf254f7d45607bf19e9be12bd34bbfff05df54cf43821bb0a0d9de4dfee70d9e97476e81f421aed785968132dbb5580e21c0c6a9a4975dd54ec09" },
                { "ms", "7b097048d721d58692a11619c01b23ae42a1115a3e593137d035883a8c2f98f3f1e8bc4fb5fe943b7eec9ee2dd0757a4f8715e9b789651a286c973d578b02df7" },
                { "my", "011fba6c9a71b33807eab53ba7c981d7bb7feaa8849864ee8eb850d834d0f5ca287fe2febaea26d2e1553550b12448e9eb56cb3b716ab425bc8c3097134cf68d" },
                { "nb-NO", "27370d64cf89e9ad42066c9ec5a5d39d68ca29f1f761714beb796b3511ff08324899c107855113bcdf631f3ba0becc79d665ee0a278f3fd1171914838d6396e9" },
                { "ne-NP", "1646d9efb46d2f2a395ba31e6bf8b9d2ec1184bedb4d56df28b1f421f1e6c9612750455326400097cfe8d11083b78b4027eb31b7197dceaa08a395e1ff9263fb" },
                { "nl", "01b64c9afde31d986c576590bc3d1f8e1e990f3782cb13c99ff74f69247bbeded9acb102336f7cfcd75f31de218f83a4cb5f5edb46727752be99f8c3bbb720f1" },
                { "nn-NO", "71acd02cff526fa7a346dfd468606c940de5ea4363a0a017bc7987d15d86d1ee4ef194769e4600d61531b3498340996efc2ebd9bae2a70619091ce56b27c86e4" },
                { "oc", "510b5161cc677bb35ec34f4be8206b5eaaf71e756d4079a937d2c8f3d6ef57b28d165715338da8fb304637ee9ab3073bee16aaf744f47967bdc0d9cf10b2b779" },
                { "pa-IN", "47f1c3167da92e91f616c46216ff076cad5b3cb1194660a83c2fe9633398c9bbbd28435caa4764dc1526e698369fde93c273cfb62ac88de8989670bba9b0881a" },
                { "pl", "67f473d3d322320632220097573e428eb1fb0962edccc1ff1477d8fa0401c11cb784a3a78893ae21b086967010dfc89fe7e81a6d6d7ed7779f37c54e1d9bb875" },
                { "pt-BR", "0abc0a2b672a072c38b6d749a37f4aaff8761eb116d9373b7784a7e13663e56b5bc075927cb0ac3f10f756894d50ea379386e4ba4ab55e00df53253fa14d3510" },
                { "pt-PT", "ebc7cdca8eaa62a40f42e7a001a2b76fd9a965242732009e3aa8b87c6c340a8a55e2dd7ba071044430a5fbea79442e4d72ac7214b399a38671d0e0bea1085815" },
                { "rm", "f06cd55374d14cf8775403f805446123f65ab169d35ec20cbf42c0cb584cc49cca3b95293769053886db943f2f8674a8411a7822c5e9b6c15883bf9a65566c61" },
                { "ro", "97e7eadbe7ac1981403a62c30a3b819e874e935b01499c40602ad824acd1de81cb1c90dcaf9eaf1e7c6a3c3066337157999ef6a3bbc62fef06bdd8db0f463f8b" },
                { "ru", "b9f1a6f9dd959e935e1fcfd904bf4dd5292d87c618132d7429a4cb4a58334bbb0daf65927a98267ce702e419c4ceabb678ac72a0cfbd1e06cadbf513743b5ce3" },
                { "sat", "93bc0e5f81cdf211107b262008dd857ecef50ab4ff472b055562eb665126f77bd0f26201f9ce46ac7a2b6dab7d360366f726b34318edced7a244badfc36d7d45" },
                { "sc", "89ab4239f6c6c090c36dbcb213951fe25b618ae715ca09e4393daf43622c53bbf759c365bbf4002c15818d12657c4da0c238fe8e5c8f1bc8e68c39c25a11c757" },
                { "sco", "b09d0d2e1624ce760b4add4b293b142c95639ec6fd0c69ad0f13689d93e75135146651f1e10905c7fd83af061b1cd3b10a35b5fc8bc6b321cf6810e873b6382f" },
                { "si", "5531034425e985c73f9894cefad5558d0b1c91cb82f3a63911bdd08568cd28b90e08f18283116c069127454d1c8cdbf644244a4f0526e137ab9886f222de0f01" },
                { "sk", "11b0c4fdc6e4125c79316db04108ebaa267f78b5bdfb6291f26c07d4e8eb1becacb9fac4e46e3ac60a92a20e2aaf018f68ecde9dafde384f2ca178b81465cb85" },
                { "sl", "96ef08a12253d057192d56348ba98f96fe692eb274b02e910ad6b7196c9c72fe8cddd7c321c4a32b5d7294683322b5ba96aea8436e0f50bfcd39c88dc0649173" },
                { "son", "58a0b19b9cb4f75d1a38775ba7a73052117a1539e4b86799d56c881d9e82e2757d26ae4c1a26c2ea0c9ea022a7e6b0ee38be9bb68d9cc2d470728ff8c7320f06" },
                { "sq", "f03ea48e55d18ae8ba4adf60d158109f367702f67b14c6c6c9ab44b4101da28aacb6b35a14a84cea8d006b8e019aaa4f7b216b0a4f49661ee65aff1fb2923a65" },
                { "sr", "144e500b9d6096501f10b9e30eeb078d112a814244f7be10a2ce5cf0cdeeaecc350b1c6a97b0d00554177b8bfaacd1f741344af78bff6e6bc0eda803a70fb8b3" },
                { "sv-SE", "ebf2b7af75a13d77ccfe3094794363bf6ce10854f0eab235a3861b44807e85555a69594ab0f0d075ebaaf07eb6685d878b4c448146ffd6896bbb0478ed329d66" },
                { "szl", "547870357662c8b8cf5248ce9d70806f84eeb5a2fc0d4486c6cc0040b47ec371164d8258de1e438b5ca6b46266bdd8dfce29ae00912a0adceb76af2d093a193f" },
                { "ta", "0652855db24f64b35ef6d4cdceff529d2c09765f3daa4d5e4f9472a745fa3dcb9a8f14db25c91b8f34cc72c8912a2301fa87ab85342d96b8da27d5003e42243f" },
                { "te", "1fb295b9546678032969cf875fbe8b91ed505d82a07ea877ab3ddd737cdc337d9b46a5bb10640b9774c7c311e5da64c17f1baa679e7d5237827c2fd400ec8d3e" },
                { "tg", "647b1ebe87d57c2c75267172dd17fb351b9cf46ab7b5a1b4939042ff4f2181e89d70398869a1b3380def5569b3776dc61e41e52311a526a8283710f666bc8a41" },
                { "th", "b7c2234f4427f3b534db779fe29ad8c63631d4bf3d87a79251705d80a496b6ab0f22776b8424f70a32cef7936815ed7b0e7939445fbba1ff03c3bd38f49e085e" },
                { "tl", "5d58ecc7bbc62e58cdd19f4e9f3d2d588b5be1ca77c5f41a736d3f444140dc5cb828f77431e9ec61aad737490e4b746cb1c67bbf21763b1f70bdbfd513b8ced5" },
                { "tr", "792db52f4af02f123d85c14d7b14d67fd8f38beeb070158f062381ff8f94e0fcb702f09879850ee013077c07b91ee203cdedf7f4c1ce9b5efc82893f480fe218" },
                { "trs", "e3705ed0f2fca4cf9663e82f317f55312e80c4f1e8a4fb9c40821d353444bb31103aba114a55105a13542eda6621eb9fd71b17ce8e211f619ec9079d0b26d269" },
                { "uk", "69051acb5b7f96cb8ce7864dacbead0a2f309f30914ff64f474601b6f05a4d1f07107d6017ff13b7e95a079624e25addcbe261f681a95c3ae9f20b25be8b1fe9" },
                { "ur", "179752ce7329a3f7bc1074086d6327eb7a2940c8f349dc2897da77017e6ea0d26dda07aaeb28b7ee27b4b6eaf59a07847614c2dc709fa5acd6bde3d343226fe1" },
                { "uz", "afcda2de28308c5c7b39afaea5db8f9d63228958b7751a60c8470c28615b61b89b8301af1800cc77bfae1a525fb8ad5ea7a1e6a2bc7884b32fef12b2d4cb062b" },
                { "vi", "0b460c89290a0fea07849e35e63739daa0f830e3d5509c9716f7fa34a4f17cd568fecacd694e79a674f694bcc6abfcd17b4c804c308bca010e6e83b580dc6866" },
                { "xh", "0aa8f8e86a7fbc03c025e65d6252918353948a10351b1db81d322950486b07eae62086ecce6f18c743d072bb41e18226a03c1ae4f4efcac8c60f5966f6b5178d" },
                { "zh-CN", "bd4695c0aaf8961833a7ab601cdf5c5dd70e4206ca50cd4ad6a7185b84dff61727a08ac447dffd6d292e780be38563436d1500b50e1797b135268c32d5053994" },
                { "zh-TW", "b9d00fafa83db454cdeda6dde3eae99d4591b26359372119391d149c36859306331c159ca718f555188958a4b399dc4244bba3eb06be63bfaef808dfc07619e5" }
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
