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
        private const string currentVersion = "150.0b9";


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
            // https://ftp.mozilla.org/pub/devedition/releases/150.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0f57deb522025c7a70125a32686fc6d5d67c69b569f1273ebeefebc9a58030b30ffa4307e186cd50a8cc21eb988c02b122f382a32fca944642a6bac28f71d60f" },
                { "af", "3a69d38a608732b69a61aa55d9f231e3955c8b454bbf639d68b8a1dec34442c1b5adb2ac9807ce4d74c9fa1c60f2c82511477c1d468ff9d8e50eae7c3347a883" },
                { "an", "fcd167427954c381cae903c858f3a0260fc995a8ec90088b97e4e5ba0b78b724f837cef7e16d14f346601ed1b83ae4b5cd69c68a1452b96b2bc8849b132e42f1" },
                { "ar", "2ec5c4186c184d25ebdbcd242f7317145f2a8ff6994c532028d1e71ce90cbeb262eb8141a1e274c9343c05f6a0a5ad73fc88878ed0e07b8636207bac6e983d7b" },
                { "ast", "9471201ed50ab028da03b32ae6443fb5e951495f3cbec1d6b4c4210bcadcbf51385a9e8063de8cbda9ac085b39e93186ca7dfb28d21244f36aa74e043a5f4f3e" },
                { "az", "1274890b1c49e6430babf1f16e14f3121066e33c9a4db8dc05993884bd1f0ddba13438ab63a780bbdfedf0c419c7329b3e3fb0a936e71161e56f4293f3930506" },
                { "be", "fc2520d8771d7bb63942f88d8e950d903f0d2fbff8726b32114400a20dbaef1032131f1fad6032164f02852bade326f5e551138c7fcf214a1d07e3d33258a5f9" },
                { "bg", "b884c67a07881ccd8e6cd41d455dec8be81b0bddbed4b28db43398f0c761d984865a6a3f16fc921e0510c2b8b2a58f1e70ffa53de8d458eea1735df614c73f2e" },
                { "bn", "099080daa6ce43f13668a3130da5fd49fa51ec379b0409d45a32cc40bff82997550126e056941398bcbbbeefcfb3647898cd4bb8b03ff72739f3653b6ff18bc0" },
                { "br", "f06133236b9862c895d78f85358025a05cd47df2742fbac5212897c1ff31f1cb3c54c7252c33f4ba2a8cb2595a4e66e737ab5afce787b70ecc43f965707b5dff" },
                { "bs", "31fd6dfd0d35f85ada4ce04d9de8938ba4ef32fc414984bf28f09549a1f88eb0dc6ab69f5825f96d21f7e3c545e685fb88f169bac2feade0b4cf7a05968611e4" },
                { "ca", "cd91280dff8500802753d8540fb5fcc95cc417c0ff28ae409cb518c54f8506f6b7caf0b26de9b6ff160435c5c0b0896d400c2971fc413d8bd950c7097c496d3a" },
                { "cak", "97e44d0e41a03e03400e1378290085fc4b9b22ebae2fad1b4c57bd91d2b1eaaac0362e928df8fde5b068603b0e6a90f2511c08cfcf9b20800bd349a533e58e9b" },
                { "cs", "493406fb4ee1df2f2000b742ab52a44f7e76a3c20eed959d30e7abea2b06422298d7945aef602a7218f2ff20334030eed0172ec4d363e2d71d5419362af93f77" },
                { "cy", "6f159b9595ff797b6d39e19a23ff8d4a420001fe05494adef28b4ff8cedefc46e596f3ec9cbb52ab7787932caa4feec15bba8c63ca0a7d083d2bd46c649870dc" },
                { "da", "d9354b4a9a8bc39bd7a16a6b12ba2041be971beaa630aa0e908c2112eec9b2b14c086aac3de713a1df7ed5516e98ac57e962665d7403f20ccb78a32958ad293d" },
                { "de", "5a6d2441b8291dc2a4913e35f8f76576e16cb38c507fbf36bc8e52499e326bde45a9f0a7a5818e5f4409a8457006a95b2bc4550049b9778a734ab7f30f97fcf2" },
                { "dsb", "ba1145b3669354195b2cff3e428741f78faf6ea3d2cbe8bba5054723a0081daeb60c875de6aca12ec3c99a89105cb635c333270c512de629fc4f644c98297121" },
                { "el", "41bde5844525db037f978a0228374fd46c6bbab6ac9840c572f68e529f0c97ba87b9e0a9b2cf3afda8fefe28d5db46528391d9c3c216b72e4745c75dcf3d42ec" },
                { "en-CA", "255014ccf18fe7c25ed7034cd364ce2d143cf55ceeaefd7175c865b2a3edb9ece0a66e13520876525f1287a9720d21b651d06ea8270ab5386bad32ddcbd68010" },
                { "en-GB", "9105d90d4c5c2c884ebe13d3ff25785f11afc91d120abddb12566d19a409b8cc9acf1d6c95d0f509bf8001261da284fea7c9443db9d1604ec92a9b7c36c0805b" },
                { "en-US", "0b795f106896a6222c553a432c5747181d411aff163c603e9a359234fd0c479345097bd5a129a13a31e8af0366cf700195c8e5142864e4ac960bed909129a005" },
                { "eo", "69d6a5e7e571d68a783d33a07ba7f7a548e0068d66f2ce048e34fa1f049cbbf2ad848b0f6fb9fdf828c90b7bd1bfb1b45311858c3666e0ccf690adf30cd63a4a" },
                { "es-AR", "d1ea466451d86836011fad9c8a39ecbdb1ed683ca5f4f71511f32d4311267f70eec6e2831f585a920e4448c2171ddc65c98737dbc78c9f1cc73948154328deef" },
                { "es-CL", "3b505cda136f6b94b34c54a0b5a009e1d72491f163ee62e213ed6e24be74c0f6a7bc570f16c4f98fca0a7924a07534c0098b286afe38da02902adc7a68b8ccd8" },
                { "es-ES", "3b404524289f7190ca0ad41963bd118b6fbd7fb2ef2dfebf3ced27b92ef42c5a72983936ee42c88dca1567f1ed6314c59a99562baa6a59abab4ece757178f7d5" },
                { "es-MX", "cc9049e7222337d9db3abe5e5d057829a2e8d4330a3c9d02a849e149952b1e1c2fb8efac4e2d8f9fc58bbf0f85d2d618cddd079cf516030e212f718460c7a39a" },
                { "et", "18852205022860031119bfc0b8a1caa8a812229d5fa63ef1e01f7047c21d8f22d815fa2b197b239714c19e58b11c09c8b9065084959dc026bc4a89b03a7d6803" },
                { "eu", "7e6ac0cad22bd03377d97034b9965d077e3dd91d5bb89a1c79a917d26a7f4ff04d7d713d540c882442a2f59b839f7faa3e111362c0ace105c873533a6aaac6f3" },
                { "fa", "38be8a707b7ada03846bcb2626e77d2540a1c942e00353985f0bbf727efa5dbc9242d9054bc265e29a23346fcdeeb6e7dfc7a6876b5fc2fac5883328f5316aa3" },
                { "ff", "35b0240830d5dd9c2c1ed6e25219de836a449a3ec94a40e4cdf4a3a7d6cf321a534bd0f1ab9d57728723d574318200ff71b514e2d6bc286489b3a6c3773476c6" },
                { "fi", "fb9f1922e4f90160eb1450e2e4e8049cd3799e72089b1b277646bbe5d56f849c466f3f1801dccf4e36bff6a686f36d16bb77430dcf237dfca1bd2a468699b841" },
                { "fr", "b86dfbec4bdc2178df3300ba2db1a43e580aed7aa26c1a5d6bdc355270f903d73eb5efa5d8f2c92ed5316f404fc79c77e88a3e2ecb9c1a9034314c8397ecefb5" },
                { "fur", "44fca47e25edda57bd9f2e5598a9127af2ee5ce500b2224e32053e3bb0db0eaf11d74a64aa16961c80ef41247f26eb54bc99647ce9bf795b85183deacd0aa583" },
                { "fy-NL", "1643e1d1215d94d480100c01f12db1a1bf58592e20a9929e8814042b9c5b1dd0c14dd975d9f582a17a1729f9d3e9301df33f3211fdfb49c340938ad22cf16d8d" },
                { "ga-IE", "b47ed4c797c105644dd0c70d0c84b76f0b64393dda1f69ee3b8d324c78424e24d74d2c164df5e9cff103aed79b2e33de344d85db56628ef4f4656196deebbef6" },
                { "gd", "6bc0667ea458bec91e024d6c8d583c62f244fb2f56c18181eee6d15ecfcff3bae3f3a8377ed0460a6c3e5618a3187e270d96d0fc45937223b48b7cbab11b2eac" },
                { "gl", "bbd71d8602a4f019aa83696f97362cabcf308ca1abe1485d95fa5943576c3b2066576eebeb984b0a9d382972331bd30d010788d85ae1817158e9637d559d865e" },
                { "gn", "e5cd9e9485ce031ff684d4010dd8a8d87129d1a310f210bded608fcddf052360d0e046ee120fcba045c8082069bf8c4807fc9c65c81a33a9b0c392a0a56ae90d" },
                { "gu-IN", "cf62ce030fdab8de951ae7064a3da92f038561cb6031dc9f5a0fd178e5869bc5833610f2bab9ad5f68c981acebbdc57bdb1736a6cc6fe26b87b7cbe8c665fc43" },
                { "he", "9183457dc8064e1dd897b3fbbcd7ed219741c34829353c3c847c9473caef097a8bd107634aac9445e374ebd9d3ee5eb1c821a6772b9d78948e5b14aff98d1968" },
                { "hi-IN", "bed4b6b14c2261c89597a36afdd5d4621d125f0bc72f0872d398dbbd8b7673ba90d71f079079125fa2991cad2b0ad3e4820dda3cb243010978c421cd2ea03378" },
                { "hr", "10c5ba577b9c7408be5a05dc1ee86f340aabfa9d2f1c4bf297c6c530131d0bea4231e3190285e69d92cb978d3e473d5e48a308b1df3ed9223daa703465c521f6" },
                { "hsb", "3aaee5c16702d6b102e9ae7ea9b3ea95e12cd55e50d0b6cc21670537249090c611f98e39cd1b91b2b99ef89700898bd1fd410d573b6acf55928b31196610fe8b" },
                { "hu", "5b30f6c0440559ee706f27805dee08db097e2f3dd70053a4da44e6439c8356a468098a31c940c4909158376dc5b7c21786b8d305b09c34ff6e2246877d37d0d8" },
                { "hy-AM", "620263d765bdf7e7b99dce89fa906b9428be6ae0caa9f5e68fd0cfb871aa7ec3a9719e21481d20ee2e6290ffe1532caeb93904bec88a74ee21557fe3590c4224" },
                { "ia", "083bd4b08090e57b89f8cadc483f92380ec6741c43d258e54e5d1732860be6833c39f3caec0b5f9a23a2be5ec4ea7e404479f4769c2d54ee0440de727470c0a5" },
                { "id", "f2c3d29deaabb5d58dc4ff693680b5e4d09180b47899bbf2576c94ec7b0d71990d1d0b92c7a1073ed81b4a2e623b374820f2199661f4a9c0e42f4a6f40d37bc4" },
                { "is", "e79ce041ccf3b3d3daad4b8adb0361bd813867347c373b29dd6149ec837c204cedd076ef02e722d1f59989a27535853438a9c17f0ec879cc601846fb86bea1b3" },
                { "it", "6544de6bd45081c377c27dd81f2db2fd2904c9d977d53d3e6e506af0520b1b311485371eb8a01e5d22f63b0b165201c06107decdc14be9ed20b9e89f1338d405" },
                { "ja", "14634922d3966c43e1d00ddb075f49f874f1ecc51abe03c304900a946c695839ca20ba7b99011211174ee9a38ba24f87804ab272a29bdf5cf70f667ff3d26bb9" },
                { "ka", "3442f547061976d634062226ceaec28104b3fb43fd70ee9a4f4f503fec0b0dc12bef149d24e5c19fcab38737c793788e32658e3692fb5e8e364625a3797d2cac" },
                { "kab", "38a182564e1c592c82dbb588af9105084a38dc9f7d1542df906b9196034b5583bf9a3915ec23f2832c4c27c964ba35e4538a97b020df41cb86acac01a2e2d306" },
                { "kk", "61d2a01ee23d127023480ea413e55426a2499daffe797a884342a6f9281c2ac3a3a86c0c007476033b27c3f0cc5e773ad490246d2eacd48f83cd27b6f1d95cc7" },
                { "km", "5265e7a4d940ad8432eafdfd491815d5c8feb2414f8d8c38118d6e1b31af7b315edb37809a6e5011488054b7c11caf2d086ba7e6cc255d4ab0bcfced2e3a3b77" },
                { "kn", "7bbe820dafdf0eb52c22f304c036161660219a12ec2b01f783881e839575cecb8a1f22f93d5f9e363ba2455ead1dc7adeb30c790a6dea3fdcc96a09b30ed7d8a" },
                { "ko", "2eb06369f5517416dc9a5df9412983a3f2fbe8054b38a5a10d87703ca6884676a5b57e096de55088cc528ca01bb0c276613b334dc7e4d644ad94a50a5339d148" },
                { "lij", "b984dcd3b1766d94706d547684522ce2424f2cfc1c2573238ddff2a4af60dce35911b6f0243e894070f1fec449f264916e20af8820e06ac58820f34889fa46c6" },
                { "lt", "b0dfbbf084671dc052385e6fbdff9f1b3494b11f23ddc2f1fc8e5e917420cac0b8a029855d0c9a5f192814ddc434938e4acd05f51b0cbbd6538f9a40307b482e" },
                { "lv", "ed7f6e3d6070bf2555c53c573cd090a5497e6f15d53736bf4e58a1bcb70a308670a92c3e6784de7d77cfa77f8a57dce0bc8e62224703fbe9456e5c17645bbab9" },
                { "mk", "c3e10d8bd8ebfe05b5f80257517b7719a0f077ec0545acfcb98abdc8e82df084bf879ea6e233b130b26854afa80cd00595c796d2dd74697b2fc71b56f6971b3b" },
                { "mr", "f372f760fb614c1c2fc20a3481a219003092212c42e0820fa5a144ccbc60d64fd5ebf98ae227695635003cfbc502ee41bca3af101a2b0d75baba8ded481b7156" },
                { "ms", "17cbc4f521f5d937c41507b4263e21635ca2c8fd142739e7c6960d4238177eeab611f4bc3f3a5854c1cd26caadfb5abe342096e968f8644adbbbf827340f1734" },
                { "my", "9edaf7b13a752f1f93d6aaa8b88f69074e1ada58ac2d47accd7677b6f18b73b0762a4f2b5c2ad882e4b27cf556ce15280e29a97657181f6d12d4ca820e7af167" },
                { "nb-NO", "4fd656935489d932d8ffb4b0c456e99878ef0f838902df1eaffa22d420a0bce353590a500b41dda183ff94fbabeecb42c95dbc5cb04508b0cbfbeadfa1a75c6a" },
                { "ne-NP", "b09655b9071e5d1471aa6a924ab544b718f42fa453a355257c92a6a88fd39c81a6f24bcb9175fdfbfb4f9fe50749843c23150ff063fca541d59e11bd9dcdb7b4" },
                { "nl", "a7d487f9afd4f1dd648a8e6c32987f520fd82235246c4b8fe01b066d1c41426248c510c6d85fbc9098cbba53a081281237bd28e77e7a2623c6f6eed059418a88" },
                { "nn-NO", "94c4591982773b2ffbac4110dda8e5c6187e3a0c21b8f114090722fd7dbd808510434960be88dbff86715b5ab79d8a820fac98c42cd16de22885373bd8d30dd8" },
                { "oc", "e26dae6328e2d5ad5065fea44e2c2bcc5c82c125f0ce6acff020e136169f96f227a240d0a4c5d8e4666024c5fd8043ba57ff4d1b21f8780dcb2f29d5f6882ddc" },
                { "pa-IN", "34f8094273ed32c67fe4890f09b4d3b170f40b28450cac7a3ce266075249c3093d84550a1c2bb53f67abca900d571a57c1b8acd44d9584bce8845d97119017c1" },
                { "pl", "e865298b3bda8b0d8c4eaeda1151ab60ba6a87aa1158246205f2800d9689544263fd6d97bb97d6ad29e5e4fa43a63a329e6ef45bcdab588708f90d042fdd39b8" },
                { "pt-BR", "443321b1c068a0716d905031fa43905c6c1afde5090e4a0bf7c0ef04fd890915b81a4b62d30511814a3c95416353404f6553c8c293ecee66764fc9545c975186" },
                { "pt-PT", "567ca43d86f7f20dccd40a17605e6e62efc1086c743c398433eec4fe4a77437a6e15d333339cbe69c8835ac5d70ad3a241ba68d4e348b75cbfca4f5d1f64ed44" },
                { "rm", "0377697f7d56b0b05b2b525e4535fa03c6d7fa7a1367183b0e0961e062077e1e419bd4cd39a56c25ffe666b16628e10b096b823933023fa16d6d9e4be99dfced" },
                { "ro", "f41b7ef9161785a64da0f90b4137e35c9f19dc29fe8b4da00b08a73e674987801cdf433aff0cda6027a508e0f860becfe9a36eb71ace5f18415510a90b6acabd" },
                { "ru", "20b491545a3cbbc6f28bb0c0eaa153f1e334b290d2e98ea6d44c3045fb6f45e218c1915cb85366d758e1186b0a5641607824085f140388f4fdefb87830f8f025" },
                { "sat", "54e26be61f8f9f9b81649972d8aa9383ad060a46704ec98f2c858a25b1678c568517016d7150fbb68e00aa6cb5a6c92fdbda3fd8e9cf626093611cbeb05d078a" },
                { "sc", "66b323a1aba9af911798ed949f25bb063449233503ae9e365a874fe052d2a953030292cfbddb5f45e14e98b5d53cdb0f1b1ceeea557927c353a83bb691685ec0" },
                { "sco", "3d62a819b6f6bfe41d3e25e412c8be7410c7acc730c74930ebd91a2ffd4a32b0b94a9460c73fb51f52cea341d1c07ad801030de4a67a25c7b8eb8fc25b989ea1" },
                { "si", "85cf8d03dcc53021481d643fdf7bf12db3cf7c8b06707606fede4ddba23ace9fb302c77a78bb57c36727f49d9153d95222f16bfd551fdfa9d2489d63fddc7185" },
                { "sk", "e160d0397e0ddfe1c0dbbe64bb6e8f449ad9a20f0728589633bb19b4bd2c543e6fe6e971ba148b769ee27af1597cbc477f25d12720cb06ca4d0225ebbb9d9d98" },
                { "skr", "f6b947ff35253035dff8eab3c4c2c9d7fd002dc80977e25779dbb90fbb2f9a019e2888ea3694a8ef5ff5a4f0d1c0d4edbce2e1f735e49eba157ea45a092016c8" },
                { "sl", "8222a12046822e97a4efef06c1d3b1783c6af933fc83479ac8a1c149ae44c03ef0c14a924ab87fe735ce1a316af7a1f352c2073f9ebccdfdcbfe811e445748c2" },
                { "son", "40d486b9bf84bb3727ed803504509b7bca2269cd928e8c3d52b7c0785ab71be38e0fd53aba72f44b6ef7e48c16884c04550546846050cf7f02dcbc42bcd6ee08" },
                { "sq", "eaf06e5becf5fec5f36f49db5a12cbedd2881119d456b8ff6a97fee599e7efb1a074fdc8dbdb43ce4ee716f9e765279892b6c23a1184fb82515481b53cd3d9b2" },
                { "sr", "c669f34f76397d4cb023a244ca87734784829056d08c746a11dc5d2f7b95be2b1a09c77100d7fb2060b5f97f1be999ccf4e67e9869006f67c67d75868d46f29e" },
                { "sv-SE", "c9e14a48ac281e74b71a29e5c712f7d232f4575b4f9163551cf86027c0107738efc6bab648433013c89b86d603770f80ce745225cb1beaa2497612f43ab5c499" },
                { "szl", "94287648060f2c4094e573142723c67bdc9b69c30325ac4cfe46af62e6ee38ec8fbe6d19f2d19d09c2017618a2c057db49fd236f463fde4cf55426b18e26e4b6" },
                { "ta", "bf5d69ef01b6558fe3d4f366f395f9616a3a7d42550cd7888eb650762cd2360b301c16068faf91e345d88a2365ccb1a000d6f80cf5ffaf19a4020f3a569ca13f" },
                { "te", "34d7fc2311903f235536cb652533903c70f0a0ddcefbc4620e6beba31c5ca6a0ea736c7c376e8eb7ef9699b90d9cbceeeda8a2473412379daab3cbe1c61cb1d1" },
                { "tg", "b63fc7e9634ffc67716577a5420c4d829936808c0fab41d5e0d0da39612a7d0b6c66cf898014c64ee0e48b68b4c4624df2734ee8cf0848e0c6018a7b18d1c665" },
                { "th", "49a224d73d6531185238d8ab36e0f9812600f3db23cfa7501477c664aa89b8443fb6a2efbe8b9a22a48414448d3bc6ef7c8360581587e66e59e9b066d76f8c9b" },
                { "tl", "1dd2a07a7b78b0e9f979bfd04a05837dec66647422542f806ac0c8d8133f4a25054d5a18af6196f22cc3af5674f5edc763aa1de762a04b8c42e6b931966cc6e9" },
                { "tr", "8ceb47908079570b3b5511ba2e9ecc0709cc8bc7c233cb3a7c7d0acd888ff3273974e56856bc295e0183af6f5b374ccaa26ef229e8ee6c1ab8147dc517ebb6c8" },
                { "trs", "b15d9dde9c79446a1b65f9632b567bb1773d8aa09c4e6449e039d07ed37a6aded2afbc4d7d9b8903c88c7e02c5af872793471c1b6843f75a78187aec3d97ecb0" },
                { "uk", "50529d1898302515354ed73dd31a255af92861dc9be6517de0f1cbd189d9523ead7b0a0e26e9ec789371c7a8f1fd82e1c6c3ee1537d6713efca5981b16e48a13" },
                { "ur", "a53d1633a66819181e0a27d45333a3a1ad0b70508d7cd07edb9f197ba14c9f421357f934cc6065697505d07092886f7e8ba2ca211b824524545acf117b6ff553" },
                { "uz", "90cf1b250ad06465466977c660701dae717f80fabcb6b3e1928a8b861a948ca40042b84ab18c7ea949fc4497002343147d52f0602ae2cd146b97d9c5e10b2b4d" },
                { "vi", "87e400fca734a8754480432d34f6c6cc80a38af4b1b33bcc1a9a64b2f4fb44133b0111a23796c925c326bac89ad7e100bd3586a3d14a91e27d66b223359e3608" },
                { "xh", "2fd4219401ac0a6d9ff0d3fd172df16713b6fd9a79a6d733d5576f0e5c269731b6ad7ab7d26650c73e9995bcee2dd4d817524b3b4947a5a724b6516974d07d0b" },
                { "zh-CN", "c15b770d856a73eabebaa61854f666c0861be85746d016590d34ccd92c3d02836d23d6e516debe603acd8bb298fc0e2da61832b26580b1794a8418a2638a57e4" },
                { "zh-TW", "022eb804a5c9275eae91ad60942047dfe4adde869efc0605abc268f0b84bcf0b8ecd7bc4642f33b204515156839c490c74d2aa011211afb86645e18cd72fd43c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/150.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "bacd8d67c242b60375ffb1967361a586f4e544727b20c0e509df0086e96670f880cf022563bb096824b3a8d6c0c852a3e845cc011c74824137d82ea0202714b4" },
                { "af", "f69f1ed2eb9a85d0ab5ed54cec4eb367182e3070a7381a1ee1d36e31db5e732953d5d3a2c28de0acac669a7f1bf5296943428b8d2d2e852e5949058768b68165" },
                { "an", "40ee4c519f783bca1fe2851dd8675426eed68bc0bd06c7fcba5745125bdf8eb5529c303e19edeaa1f116bec4ffa49730401283a14ebd4ff5321752c3ce778b88" },
                { "ar", "dfb80138b55c842fcb37202196a6be3e860259ebc7775f7c62abeccb54d90b4e9b06d4693cdcab6ff1b9504ea8bf4d900807569a335dd162d9e21cc0409a4103" },
                { "ast", "342e2d66c5dd251512737fad0036cb6b40e976de25361fc1d5ab852ff2a52340e17fcb97686a4d29b5aecdbc2f6738d8a482dcedb33b7b18826070eec634d442" },
                { "az", "4a599989432e2c4fdfe0c01207f3f66b440ad7009a60cdb56846467cb0ec4129b41f44e02a12fd73bf02cbe0fa8249fc6295c8a63c29605d78e2dee58a96a098" },
                { "be", "038e6653814dc8e4647ecb5a785f62d40d2480ff368613861735f3e41e4fbb1d183d30008c28086866b5409a905f53714e6890c0478335c4c6a99f09c93cde25" },
                { "bg", "03ce7abfe92e8b37dea98dacf7613e65fbe4195c21b596b84b74586d0ec6087e99fd192bc7f82a569f0bb663f198eaf6b18e8dbfb6e413237ee6622e1eb12f40" },
                { "bn", "53a6d20c16b15f6402bdc892494760f9d85a6f599d37428de747f5287b93efca4293db076d836442c85d04cb2106725ad06b08500e33ac0697f60163061d8a4d" },
                { "br", "946b01659c58ef94f5c581aa9733db800bca977adcc0ea54ea2b35892e97f4d90ce12494d740a21cd050a3e63cd6550507998afbd5672f9a8bd8f05321a39be9" },
                { "bs", "24b1b213654c7f6b273d37aefb716dd01160091b9b7bb0957faa6fe5d25e81f4bfba394175ff44905dc7509339bc194eb9cfd815b0594c1446f85127fee99706" },
                { "ca", "18031073ae67388276d79cff2d7ad553489e13611b970ad28c94be41aa18d21a66ab033ee5510b384c8ea56057dff53f1f08cac2ac0edd4e7259640deff71ef8" },
                { "cak", "a1be458c68f48b7f35a0eb64f93b56345d91eb541add72df269d477960e3627167977c6d773ac74f57aead782cd012f720beb4de2ce8d7c27782f2430aa97db8" },
                { "cs", "4c1940cbdf7c0018ab5d2e788bf3bd2036b6ac67c3d300a772a2a0721c49da62985bff1acb5c9983a8cff26dd478a55ce2d1321f16dbc2ac31292611ecb5b7ee" },
                { "cy", "be75bc60fdc67fee69ee3a0983292896a68cebb10f66ecaff5349041057577e638ae10ce28c658e1325d2d43964256d8ed7344de81e5c421345d4a06e4bf3e93" },
                { "da", "062b006e19aa43ae37002b5fadcb71700e6ec548dd2adda1c5f04eec70d21fd72339a8c7017892ae49e19d2bfb0fd3f09fac2f258a04b914feb0e20953144133" },
                { "de", "27ea9557d415dafeb02242cfe67ad480877c1e87f4c94150779af727dc241bb85fe4a9b6de1674903622bba32a91d55b03279c4f3dc3f4596b6ff1877000b348" },
                { "dsb", "5ab760bebd7f95c28b3a60e2b6b68f7d9a228b9ea45fc39251d3569f02f67b2c2b8651ce6eb6e46185f8d38f206c89b47c3afe009424b463f815934bd964150b" },
                { "el", "7d22156c5a3d8700ad94e09809054c723518ee253498332428182a775f3c42590f6d3da6ddb7aeab56f00ac979e95058075c68f7c35ac761b72ccdbe689b808d" },
                { "en-CA", "95f6b37f18cfab779dec8b236890924a59e7eca63b85cc7f06608f5bedc060a08c5f102f29d7e52b43a640db5df60333c84a5fc92acf931437baf3d9b9cbd326" },
                { "en-GB", "e7563924babf1063dd5d3ab86d16be54b66e203a65b502e93fb3ff61f637249d6b5702d604924c5cb3eaab7f41870d50e0c2bf35d3ed583c0f2955221755ea59" },
                { "en-US", "efe2f68701ff3ce86faede3dd56501ce88178a5e88114b92ef9191ee6cbaaaf63ec49dbd789dd997fa3fb208d351096aba7ce01c989b919bcc69086bc950c3ac" },
                { "eo", "2a35cd89eb27876033ef6fd546343e73a36d0460371690c79005c5f8530f4f61f6a208eedcef09fe82efa9a7a53c7436f795ec9bca77d6a6cecd0826270d162f" },
                { "es-AR", "ed6054167675c3c41f862f4e7a12c84baf80ff1eb0366f3f8d7c4245f56d6e65c2940b01be11139b91db8a1dd4272800e90e51191674cd84149851643bc0ca86" },
                { "es-CL", "b5da0066968de3088ac39f04a080711198cf7254de45e8fab29b2e0ee0ad7abba2b2a08b9fdfe1f5a86a669c049ee7a1259795487fed060a174d7b197c895ae6" },
                { "es-ES", "c5215ad84e4c72dceeecf9fd8a0b33041509844128bb315df28455d87b1459696e49e06424ea3033e252e06a1151b1a1c1b8224f09e124c06c318a036619a120" },
                { "es-MX", "86f4846972dde71f09cf996d2ca632752731aa7d2c5c832309849b51274c3120dec3bc00db4648afe8bf3e51ed0bfe09dfbddc4296f2475d0c9430733c0d86b2" },
                { "et", "cc6d43191055e858d74cda74a92eef84b1ad0504e0ab186fa7ed9bc2a4d592698b3e9e27f46ad0bcd9d5fcc51f2f15f19bd281025e86c656e22deff15b0f9758" },
                { "eu", "b890bc74b3b36856b9759890f8bdf8d00b16a69a6ac91b9a1765c9e520e7a5e89e5a4fbd68007685c158950961436ed82dd5a8d71251ac5b20930300d77e17a1" },
                { "fa", "b30ff8aca5f2c2d13c65242b12084948c2d43801dacf41357eea9e390552f66d1d410d4772d724eb8e6ec7a9bda8b14b617871a04080716587c8f885e2f486b5" },
                { "ff", "201d114b40f727035769e7380ae6418e7019d7a7363aacae224f3be7dc16ed2a14e801208b3367029073d77dab0e92f1ddb56e16845e52802429cf4990138615" },
                { "fi", "2d35d174b4c751850ad538e9a22e85a9d9d0e8d0bc9ab9949805327a781e097cb6b2c751edf417e653318d19a12da4508a910ce97861b316bf9b06091448ebbe" },
                { "fr", "876e7de9760513000e4f7b2b8d22cb4be336b4e6628054731bef25ef4a5a3a3cc4d66ad68fc59a70936c35c6932543c9edc6ae4ea32ce038dd4516b15eedfcd8" },
                { "fur", "f8f4eeed0404d0cb7fbd8b578ead6a107dc4f78b7e192e47f3f492ff9e97727f3ae946f209899c2488173db0aae861bd9df5495176ad54d362239cc08114cb0b" },
                { "fy-NL", "6fa8f965e6208ead66ed78998af84710ec76d3968740984a6ec80e63ac049d44d88961d5644381ad9ac380aac6a2a0e69d67d884b28888c4e913a6e878cb10a0" },
                { "ga-IE", "45e70c26fd93ae4070dd1770c8a749b0fd0db4633da3caf927dd8ac6487846b9c3e15569847265d0e19590c60b69e450dae0dd8e16311277272539d83e7cec8e" },
                { "gd", "197741feea1134acaf1db7d6eecab0136b8233eff89e463ead31487d002ea971441ea282fc711d57c004ac52138bbb4ec60c3d1395b0ee58fc3f16c5770e2788" },
                { "gl", "affaa0cf8d8212726433c4ee0920685bf6ce9b6a7d31fbc9ad54fd749344b27dc9eb4e70355973988bc735875066d5fa8403a97da96ebb3a3f2de884c4a9ba95" },
                { "gn", "e4d4687b10ced2810c9da60be5dd739d93c9dfa605a61584bcbf5d63dda1178ff7741675a58878eaed9baf2284254f5be56a01041ee1b81b3b829ccb23629fd3" },
                { "gu-IN", "ccdb0c9d431a777a6f587b08c20c4c74a34b2482e75371c2293b4764525b9a65c4612b6e2c059cdc4424b73ae188b3bf60764a5f7d687683005a729df3a9cb7e" },
                { "he", "6694d9adcd27515aec70b55702edb0815e86487fad08a9c9f9a1600e874f54396e322c32460293e4049ff8d3a4d863c5aeabf64f1665fe5f100da793908ad348" },
                { "hi-IN", "da194f85e5fe60323fdbffd7f95d7665711f13a7d708191355253807ec9d1a2de608aafbce50f54e47d28ad4ba3adfb9101cff79962e9f0807855168dbd0e112" },
                { "hr", "048ffbd0c77cfca92a041a71c42ba62330ada72b729aae56ee847694d4b74fbafb5261a1664b2415cc8c0d0c13b267559126460fae251b7cbc5a2ba3ba9bb85b" },
                { "hsb", "86a3d19b602b087ba3b41055f3b35a6bc86bb13f8083b65db70d56a1d8e4e92a96aa1f789c197f02a6b2506cb016b1b659ae0b519594d327e5d0946363e50bfb" },
                { "hu", "6529c4c8eec911c8b5f30a4e2acd300c9b8af8bfff68125b669fcab859e9ae3b21b4ac62fb5da0ad247e6f547adf6968e69f7f921a9e62d02e68ff19733539b6" },
                { "hy-AM", "e59a4d25c8d61b4f80d32ea63f97c5f2586385b11dbc41d02854cdcca77f0fcff1b2205c2248a3511f3e9df5dd2a06b880845c7cee8ce1f445331f2cc88b9461" },
                { "ia", "f954c1a90b5ae8b860230c4f6dc7a70c1982ba5cc20d44caeec045a12ddde9ab0739aecb5a63d8ba98d2b6036962cd982fd6cea0b80904bed417abc2c133bed6" },
                { "id", "1d506e75bc67691e928fe62fdb56efb3356f15f56df0939aada843e1ea88856746349245dfedfc17a57143600c8196f3b72f56b963aa1d1d6c19ff256533b1a1" },
                { "is", "d82c5a0b2786b23adabeb0c134034a9c3cf985bb0e0b11ca3d80cfed79394501aed99cf5750d6ea2469516bcf987ea55233ba80edd6aafb7edbb8351037917a7" },
                { "it", "3b9340ba683b7a0f399b020fda7435c172b8b54e11e9ea73789caff6192f482a91a5db8d429cd7ad8ab82542fbbab0a91d22a01e67c057e34a93fc2c9e6e0d0d" },
                { "ja", "6d7b1b4c0b617966834d6f37234f4da13eb41d9c1db1d821acb795adeefae2704fefa90d2278eae1162693ad560c195d61bf6ece15ba336777efa387feb2c967" },
                { "ka", "24a08453093fa4af95d6e213ed032729528ddd384d9b2d10736e6434ddc6718c4c9a7bc340ecb05cd01a31b50fb7e8b35e222642c075d03f7d10e13b9996cd5d" },
                { "kab", "bbdcb22639d6de3f050a9ad346c3fbb9285af8ad91581841be6c23328e6461456de6193066a5c357ee7c8fcdfd864ac5bbd3db0bd48c2660602824800fdebfa2" },
                { "kk", "a8a401dee0a3f9bc0b1ae58bcf5a860cece877654cac89ea1193a8ad23aa27e185bf59dda39eaf63446d0b4069c05499cc6ff7acab6c7f73ded1cc39bd245280" },
                { "km", "eae47696539e16bcfbb79e86f961164ba5f269ad590902e0f019f8d8259ccb6c7003b561ad5d593120cc502f899b377e58da1d6a534fd9ba2643e7d811018c7e" },
                { "kn", "b75f7416a67cce62c50a42e28bd2d302f5e295df0d37bdf60bb9f19e55b290d33df9b035f4a58d12960e5b074c2ac0d6e29f6ae79af587588d803f9923046dc6" },
                { "ko", "54508e4e6a75aa3b6600c01f6beb49b5d396643defbd0764462bb633d251e6ca3b43b8925504d58bde106bf831bb4182068ed04fbcb0ad38199bff093981874f" },
                { "lij", "7a59578a0f853a1803cf215c8fd678369d2fa7d5ff8c4a492360e23ea87395f1ae4119bdf6d17be39d3b100bfa8b16d78b6f205e5c6c6f0540169642ee4ff492" },
                { "lt", "66e6b577fb658b24929fcfb52f8df517fbee6f07eca8468d6ce0199d2ff8f97880587e72e38e4bc25de72e48f09f069aa945b927f8a2418d6f9818978c966990" },
                { "lv", "d1b05b405aacf6d4193c33f773197e656d1538ea6ef6a00e618866f32d2e4bcd179964fb33a8986f30ae2d75547c0e035fa7f640ff7c0a30708e7e88baa2c63e" },
                { "mk", "19650cdfd21958af13acdad33cb765fac3a12632863e206de1b641542a1168bed54fe2fe19f5fa352bd39c8659038829a63fb58de031e44223f801c284b06167" },
                { "mr", "c172b19adf0bc8f7e6a729de6680b764392dddae6fb95e525e300ce4cdbcbc47c78df7525f82fd8490f182ec6cb9e00cf1e8102c124f5e63ce091009d830f429" },
                { "ms", "9b1ee21ee81c0566a76be0a347d0a054c0b5914ed8bee7b257a42f510fac2a0a6496438ed3241184b94c353cc5963951bf7f31a00630bb980cd3392e207f7065" },
                { "my", "d4f2d6e49b7f88c0e7c57365df29cf8c205eb9bffe811c121cba6bd4653ccf27dce9f4b19aaeabfa6f8e0662d513028e0fa06ad337f0e276aae67ebc1ab7371f" },
                { "nb-NO", "eceaccdd9b28098939a6cc46fe460fa0e50faa3da30e6b4e76c26b60563ab7482c83523c3a9e3db0af0b81e8e6f9f25020952bf4d9a92605716c0f8ab73f2bff" },
                { "ne-NP", "8ec2b9e2ef5df960b2becab9bd148a966bbc67a014cedaf54fa16659a5bbda84216c061307257279f8b0e5313382e405f1d56c0f50d015da080f079297408792" },
                { "nl", "bebbe92a942f190f7f9c1af3f7d3006d46bd573ed59cd1e7d5c9864aaf0d5a2792d27cf314d1c357dca9bfd0ddf8c1212b8a08fb8ceec258acd7f5c5e99876cf" },
                { "nn-NO", "0d3832465afad9b6cd77d84e5ecc47692ea93914bf2216b53bba58b411eee8324d0ee819c7d5b04b33b4b5306ead09a9650a5e03a2ddbbb3c3832b721ac175d5" },
                { "oc", "00c4a3f30a52688fdee8d9196cac385ad7e6d31e42fb42bcf2241f60b9594bed566439999190bb17a99697afcb2057e727f8a30ce3deb4633e5e8c3475b298d5" },
                { "pa-IN", "45ef0e96996abe06a9398b05aa6312b45ec4770db8872447d0cd595e7f4af4f33b980ab03ca9f01450c4103d767af7d32d6bf6fbc2d25aa0ac8ef975a6e1a2c9" },
                { "pl", "57f36f4b1eff9b60272c09983f25b7c881060d4f871a05cb9c7be78a3ed085ceb600826231055357b57395df299b7a39074a75b49331f394dfc0322b25798fdc" },
                { "pt-BR", "5dcdf119b2accddbd0eaaffaa966e1a66ca6ded6a3ee906f33076bc6ed613a9dc1f0a6830519f344fd33d65ab61c177e3d8c32d9cc02f559ead0f02171225953" },
                { "pt-PT", "c1037c82c78d871c4c2ef1a68d7bbfc022b8890f2152891962685fad7ab171f6ad03846ff23091b3267020bc37392543a0009c480038189a72d6ca0339f764d8" },
                { "rm", "e06d2673dd2d223d25d6e3bb5690cd40887c007d3896e75d63e847a157f0d69217541d38e25defef0eec441f53678642229e021a7c24bd0b457ba536e98a0a92" },
                { "ro", "99b7a6038577030bf558a8b119c6d14e095d6247736573f10d1eb2e8cf1afde3d9af9716e89dd91b52a62af80fd09923740c05f8999c73924fe46b66163c46f4" },
                { "ru", "824601177968b96c6bcf73a9327c5d627810dbb082c81dc23e7c8ca7891ec511e95ffe8223a6d50ff227876d8208ebc7c18abab8f55f75a5ccd3e9be97a54720" },
                { "sat", "f2b6eba9cce32ae9bbd0abac6bb4bd88b4f963b2ce8c09874985aa98e269d6624d177dc09509c4d8aa42a871c733e1b50c8d7120c5b851515dda459c625ca4f4" },
                { "sc", "bc9f8c56db964247dccc042582fe91738b6cbfcaa9ce8ab538372095a6480e913797df501a38b22e2443831d70db5c7d8450ddeb58e69a36dde2f72f9b1e570a" },
                { "sco", "5912d69a243e08788c6837849b95f060a52492bcdba12ba07151019b594fa41f5472c4af6b51bc01285b92aaa4345c973f912b601619506c08544afc008c7064" },
                { "si", "9a7184071f96aeb4b72f0165361d2fdb964733c549bd919c40e2168e5ad73bd326f2d5b72cc9a58ea2b0cee0f868996a7e4e2ab5580bbc52dcbcb1efe2de96b5" },
                { "sk", "bbca00cb0d01c96d082995c6b5e594984c4f401404f06953d148f4a745edfd6dc337588436496a5725f69c32710e3b3e23f569f5f33f131a1e6750b7ca05766c" },
                { "skr", "1d26c01da72a94f08b834eb2eade0527c2104537829b0bf060cb8ea8b1d9e52548937cc563177d95b7c49aeb6ce17afc6f1dfb7e683a93a7336f7468842d0230" },
                { "sl", "95623e58fd07f7a9b2c1d10bea1b5a4c207ab18e310e183356b13bda526486d9eef08f6147c44ab4667899a2c7c445d0d8ea92aa95b8473e98c4fc8b0176f0c1" },
                { "son", "ac7a43351944e54b97592a28cfced115dd03dae1513268c93b195867fce6ad1a6d4272a561f5b4a2d3747148a0dd18f3f3406dba56b8c8031b8d7bec1adb3814" },
                { "sq", "761f5aebdd435c106613d2924704acb884ae8b24fc507176cab3e443c40d29db6d1346197e338ef12bdb93299bbdbec003b2322c4b9f81920470c11b05c7fa45" },
                { "sr", "08452acd06f973043499ad256df9356a99bfb5542f60e710f94bbc441a793b6ef8b0c03467a9b8c0d41b787032692914a4dbae62d6e611b5377f1af8d9a69bd3" },
                { "sv-SE", "708dd8678c728fcf3e8d84bebf8d307d3947cff21a46eed5d95cc4b395bfdc2650c6726aee47e3e9c50673086054e91c8dfd839b563e47d863e3bfbaa19c0d31" },
                { "szl", "b477a99b00590107e2cdf222394eed0afa34672a411e446c53f0941262b50c173b258fe3ee9285eb291232fc6c021085e97d094035c01789571410ffd6c321e6" },
                { "ta", "a663b66d8143393ada7d375726ae5c1efb44ed210eb93cd73684c3153e7410cccdda228fa1206f6434915a073eb5e9f502634971af7aaea3b5b3b31b951ea6a2" },
                { "te", "8488ead58b1cc6cb0bef73caaaf712c676891dc12e0a5d558d54b4c56d1d6486cf58b96df587beff6a3269c461751599caf6357df2191b1b26c023f4722269c1" },
                { "tg", "a3acc3d9fad9130c383f69f18228b6b5bf5e2557b1b697d214137ab8534d2d05c84fc4dfad02f731fbb913218e811046259a8db946cb452e6f3efd62e86e31c0" },
                { "th", "d21adc6ec02c1672e928059ace18b983f5908b2dea315a2f4c49e3a577fa6091fb1761d4cee45a70d9c58291231472c217d609636464edb0fdc76f2d9140cf3d" },
                { "tl", "453f6ebc11fc47f756a0ad4f609d5e4d1a1f2681460ac84ec8e399de60cd45ccb4ceb67ab9a4b42540342facfe0d9a40682fb53464791b5cc3fd5cd39f714824" },
                { "tr", "1a1579a5b962c126711e645a7adc44368e66ea9675a06447f821f2afcbc6632fab49270a2bd2bb88aad537e26ca8526a05d1096bba96f2e3f01bdae87010d3af" },
                { "trs", "318738f8fbb8bbbb08214deb55f8fe97ae4fa46084aff583078b4e0f06912a36be57f14f3fc2b954de158a8356e5a5b3f51a9095e9cb52d4f6660aefcc23c62f" },
                { "uk", "542fca9ef6f302ceb8694418d0fa926820c8787ae724206153ebfeb2cc3e424ddf85d6551bb79c0a404598a85f024d9215d8b2f2db9324ea4009542f65bb5c55" },
                { "ur", "6c10e5dc1dbe17242189d5d7723bd634bfaba4024b5cdb952ca4c954fc244e8439b7e708956e9abfba1c11e3a385c675866e551e644f5334d86f92bc357deedc" },
                { "uz", "9b430bde041851e85560001fb22844f4e0c9a65d247396fa760fd23d73a74d72c672b3afedcccbcffccad3fa02d7359f2abfcea0ab78c937205b94f68432bf92" },
                { "vi", "74c1b1937f5d8cdd0bce57987f7f2add1b400f1ba82362d0342e6b041956123c7f00675986aec4c648f8ebe6c58889ecc4673552d528d74fa67c35d76b88acb8" },
                { "xh", "b3562b3db63089c4ef14daeaa342f7c511d2e95a94a3686bd50f2eeb2c79b1164b8bf9ec63dd75adc9001502583edd321a443aad409595f7e226d4bed0333c55" },
                { "zh-CN", "a789ac1cf9f2e3495ff5501a109a3b08fc037d60d9e2719ba16d16c1ee426c9d051d95f3da5da9764f8b84a524b3bf16e801140873ed0635c948f4827f10bba2" },
                { "zh-TW", "583fc4ffeae85f131178465df56dd4621e1a52188a057914d8a5c20710c15846925f5ce766f5eda4a055980e4600d4c4e76c7900ddee7475a790411fb15d919c" }
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
