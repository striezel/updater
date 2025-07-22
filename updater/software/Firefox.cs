﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/141.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f9d3a028cc7b807969e8e3724ee664a093cd3f4496e0fc776891234079708756ac896ac2eba36ce37661bfa06d723dadd662a25bb330e9263ccab01a83861547" },
                { "af", "b8efa8a897e2246581040561c8e242854ff9bcb1cc358105358f19127a9e364c6f867bb9047e9b9b03f5aefd87aea9b38e0f68991633709fce1c73c3d5335bcb" },
                { "an", "409856a65cc9dd4da57cf35b2a47e05bdff06c3de436cf8395beba4a394fbf8641a6ea43a84492fdddc4370c58feb442e87ba65b818fbdf955c2c12ddb065e83" },
                { "ar", "68fd8bf529550670e9fd8d5b0b62d3e91793b480621ee5d206bae757aaeba3b5094da9275f4e5f70ef68ee482d830b380b426a6a22dfdc7440e7bfd303981b15" },
                { "ast", "f6a1750f3aa4be987835424fd2500a86dfb39ea6944f9e5faaf2ca9649f35171bf6ebebc5e7e9b19d0a3ccb638291b0491fe196e0abb0f3fd4e7a84db1280603" },
                { "az", "cfe93f595615e9773b6ca374fe176e291a89a59ef601b46d125373343a65e1433a34a0252c95178df7e7cf59e1a840af93a09c32f05a44411e7b085dd54e8e8d" },
                { "be", "9c90f0db432be73418b0591d10d0e6e9660d97031910428b1e55ab11bd985b8f519ba249feb3f721f53c1b6c7e873a1528cd7872990574c020ac08e928c8654d" },
                { "bg", "b0b7c7407178c8635e08e2a56ea78427966f943ccaa7b02ccd617d8f90e05613942f6b6b5a096309faf8bea732afe076489f2c9d65deca63698f4278df62b0cf" },
                { "bn", "29ba673cd498e46910f96af510bb4e239b7432832f2a9a5073206a81fef0bcd086ad5db2a1788153a145959e366ab45325e22c5b444d8bbacb82afa95f81eb56" },
                { "br", "79ae70149cbac8e5275946b690ca54a628a02d88a052a32163f381773c3800c0d8b74c8175b24d1eb3aa9d29d38bc88953e816ee3ed4ed2459e622770ff8f019" },
                { "bs", "c6cdf800495f0f5d8c2288b698d9b1599daa25c357b0df5a6739fd120fb8fbc19cdd9d3e82c58487b65e795389ac0c21600814e2843996622236f6a6386bd9c5" },
                { "ca", "69067af777de68f7d06dbd7da0486d06d8f4f8639da69b2dc96e5bec150425d31f19e907e736b55acc1ebb99ca1ad68b40ba4080708efdcc1baa7dafa49d3668" },
                { "cak", "3c1ed42e34142989be5001b91e82821a796bbdec3b490e7631f20233b6521b1a12959c7896ba75a00e5b6442b68bfb944bfca7f3b7b1dcbf9c04404b8bb0c76c" },
                { "cs", "40e7cf2af77fdde05ad0bc2f51c795a712882d1c19a2e736e7a58c0a00ed81227bcea6e8dc9dc102d2c48af7dc334e4cb505ff57b7aa2ec6de2ef93f0942ea13" },
                { "cy", "4a3a2586bf1bbaa99a72542d3a257cfaa7eab110256cec431052ef048fbcfaa980a897cb9226401771b9bbc019d9cd9214c5e3334c58b8746ab34639bc989cf7" },
                { "da", "bd11b9c04ffe2b5c10846ec78f6cd3ac50521238f4a72b2be74869d57a5964e3a13c84ceec40bad6d56e33985edb219a1b0dca09798d11981b11e01020dd8bd6" },
                { "de", "6775406a64e111e950cc48ca32e0c023d68fa45c64a72ef3338c312d5cfbc68dc9b6a2a93c37f5ac25042417b79efe9d1ee2db367acdba3644549acc48a00432" },
                { "dsb", "559d97ceda940d4a99d6a95c351fb29951cce60b2428dd6614cba4c609dcb83ebc38ff5bdc467feb7f3c673ede590f64989a93ff24cd9e4c0307a5a7df7b633e" },
                { "el", "3b278983835e51131697b493ebd96a837aad8d1380c7d18abda0d68764456e837578366d8b86245cd5c5f5ebc1eb8984561854b84728e8aaf8c6dd581e1f177c" },
                { "en-CA", "f71025ccfbd0b04f7a6e78d8cb4b24aec59cefbc3df993b3b8a91df49395ea3c713e72152a0680d02a6dc0a25e16c23ec5c8ae8b623f9e6413e4ba40ef2ed85e" },
                { "en-GB", "093432e0b4e80162a91a76faff47b79771a90f880e99597f87a1606457128bdb55009a920dc291e1a94e5898073f68ad40177139175493b8ba527f1514fc532d" },
                { "en-US", "e38dcb7ebca1c825a7e47c79d2adea1eca0f2b8b289fb5c0c8acd5510046209474b6bbb104849b6a4e26f962153636c3b0f181185350caa643b8d7e1bc8854cf" },
                { "eo", "cdf2ad8eb83d6368251bf22bdcad015c2bb2619fac9eda5d83a5acb5fb205471c51f6d0004af86a9029c35757c2e93a0e35343faf3cc2cca3cd23e8f6ac4fdf2" },
                { "es-AR", "066b99a3760eb01bfbba4792a7470130908963bbc10d8a1ac53c5f04cb8cd530569f67c80500724e73adc7abd4cc4fdacf76a962c248e5f18047a28a4563f952" },
                { "es-CL", "213e8a2a51b5ddca918315e26bdb66fc0a38b06ec14ab4127503ed49f6c80daf2fa6ded09a22136fb598179d860945690e0441c99c8d1fb0617230fde3f327b2" },
                { "es-ES", "97a32e506c63ef3eb4271b20cb66498516cd17a2cdc0158e1f356df4515683fe8241e73a2cf99c318aab4b06439db5055bd5dde5b9f8af8233556cdb38a4ee4e" },
                { "es-MX", "1fcb68d3da5d2723b80a5dffb57951272171c5d7782c755a3a82e0d16fdbbb099a5fda640910af21263451495655fd0fb1b0f61068576bf37f9a66d186b59aa4" },
                { "et", "b0693ad71db62a1315ad309b08c986425c9fb2412f48cdcb6d6faedd9c939af00bd55ce19f19fcdf54aa723e920b39457a21fc463501099bf6ffe34fdf919dda" },
                { "eu", "bab9bcad410ea7f9a4c3a035051ba931af22efd7e66e392c0d75b7b7d92405c659d43cfabf6d61561a1142cd147347e41da5231cf24c6105f669950ea35b7155" },
                { "fa", "e67d07923a2b81f9cf171a07eeca4cfb9862c04dc5e9b731c7b38072743bd0653da62c6ec4ff752eca06a3b14de58b1a283b9253a72394bb893827afb5bec5ce" },
                { "ff", "a6aeb5dbe677c9964780960ac5776f544fa1d3ac169c7f10591542bb155f7d9e80d46b50ed65af126309a2573335243b4b6bbe45296132fd3c56c3655dcafb78" },
                { "fi", "ddba3fcbe72b1fe552d8c01f1a09da55079f9cc61716868be0233d0df8b35cac179bd0e476e43312f56708928012b695e2d20bf99a56b99dba7065c0d66dbed6" },
                { "fr", "4ee01a58e7a6ebbe528e05da94a17548c4d8bb4a418a18b7f88100f96864ee6eb1ef255691c135eb1e32550d03c074c6a36166e863bac95293ce3070ab845608" },
                { "fur", "9335f9115c41b40f22369d3f1d0f59fd8d7f25400cd5554cf169319c94067f6492a7df9c2d0b521be2d884db3b4f38c2b7f10009c871ce3f22b70db989b10436" },
                { "fy-NL", "6f8ecaf3640f0abcd8c7f4299d4a53f89e29b236da0122e1889610c8d8c9455fcb56626a91837d544ef86e1665b3e7635cfc917c4f105a6bb7c70a08fc2a8c60" },
                { "ga-IE", "37511af481d0f73dc53aa6a2d1586b72c27b2c2d61d0359863a706773dae2c919c50a4f29b1eb8c9e7f5f74279901b173a5d493b8f932924067a3bdb864a311a" },
                { "gd", "700290ab634756a798dda515e5ed8090e213fcaa3e77e1c029a601595b0c0cf3b96b9d7ea78bbcfb2bce355ee9b16e9a260329f9fc31a3546e735e1713737499" },
                { "gl", "66f92f07f3cd7f23d8492a4634528c642076a6dcb0ba3c3167ca6843518eafb8559f68e6196de4f2424a7ff193ba1c6bcfd800274309e06fa628ca82533b9fd5" },
                { "gn", "bfea6a02d0e66b873d395df1a4cee1be37ad338ef558c5e7305af74a91c898b091d40c855a9443bf68c13d6ef0b685f7d0555c133d2477e98107b600dd2543c3" },
                { "gu-IN", "c7a2ee7fc5c12f108955565d472679ee4effac1987c316ed8744b4597f25eeff3027be38e2ec7a21ddb67dfa325125c027655e09e16bf01ceee4f7040cbcd821" },
                { "he", "910a8004dd3543b941c82417869473d7d01aa3427f417e2f340e89128a4afeea6f3783c718639221ada4bd912986ddc3e63b8ca67d8ca4cd75509639b987dd06" },
                { "hi-IN", "ff3e45531cc562bacff7e5c81eca1b42a8d75bda9a4c6ff00850700645ae0fcad12b8da6fa538a5ed73018272e18b03ea745db8e9b1d79b62784a3a09c4c1436" },
                { "hr", "c72cf8f37cc7f0fd55511f1aaf19b0dd7c9d08b1c38a23e96f1087df52b141722524e3127a708865a2a4327a3a1aa33e1c872e3abe67fc4a7a2e30dad8c8cd52" },
                { "hsb", "b6cb4e4bdc0fda23d1e761ca7a379edf1c382bffc8659f941cbbeb43a05d460d651b062085acd7438293b4ee753e6894059959c4824e6cd831a72537f15b421b" },
                { "hu", "6bbfad8aa45bf46fd1bd8759fcced1dec6e3933162a5b6d34fe87a37d8058d660c64072f8dbf97f31fba425e4ae7f977a07d87784ffc48bc44793d14f6cf29cf" },
                { "hy-AM", "6bbda8857b487b7444e5f128c2f03bf54b494969aaa8274744dbae5d7c96ff47741126e5fe8f9587854394e11e76e8d7ad86b1d1b6ecdcf9f226f1309483f1c0" },
                { "ia", "24738ee796202f1d04b6fbef163c5722af05fd0efd4f9fb2d6233a04f469eb554a86b1454357e91c774d105c440d8e91afbcfb2878e9041d7c1cff67a3b725bd" },
                { "id", "a6327f3fcd4cff1193ae45b21eed753f41148b803480f7dce2a968a64c5432bcbe818cd0c54b665fff3772fb496d7c869055dfe589882eff7ba5e2c823e0c229" },
                { "is", "0043f8fb42ccf06d73c57909d052631c63c33771cce0783ac021d1f31688b5112d23536cf13c29a8c5922eaa6b7c396e94aa5b36be56f91d920e1a2c96f62808" },
                { "it", "310bfeca02c663d5cb8a5ec89878efcf834e1099c950538153f5793f010217e5649b5f0888cebfffbc2c5055238068eb002615b74e7a71f2cd69d45f251b4357" },
                { "ja", "d577f17633634fece89bd880cc5e5d6c1f3de9ab062e8e61c45471c06b654cffe3e06df5c02e98fc596bc25150abe55669cca7759d525a8f59e0e1ef568d5160" },
                { "ka", "3007d6ba286975c75ccb2bd7eb7da80915ddbdcdd78084ac090479bdf05264d40cef2c6145ffc677ccc2c608ff03e117da5d7b8734e89c395aece0d8844870e3" },
                { "kab", "732ec28bb2c7da4aa43a57467719599a6117c57acbc6f824dc1ca932fb8dcdbe8f986b3b5df30f5f0ae04d610254606811da126544a76dfaaf7591c478359905" },
                { "kk", "c7f811f36b55a4e685c8a6ddc2d173c6e790e451a10259f21691f2af3b48b83ef117f7461196e8728b2d24f91e940bb78cd5bfd3c1929e9f43fa417e9a4e63ba" },
                { "km", "36fb886b1957e3fb9fa33215cd3a526019aa18b514b82c0a51bfc55dd429d46fd8fcaa415a174c9154da2ba1427547203080e7da853fa0d9491e8d44b8351c8f" },
                { "kn", "9d46048934ed84970525df5ba9a44b053d6f713975fdd2d96171c7183a3717fe4362eae07a83e5dd68e9b61d9fc1ad92a890cf3bad9b777fb42fb75eac6790cf" },
                { "ko", "4aa1885b6b3bb074072ab373e50c234d3afe6b6710bfb3baea80808aeeaff174d511ca9e5106eb8bfe5d86d0a7bd989e2fda89b3087dfd0bcbecb0b43aec69b7" },
                { "lij", "ceaab3683b8b9fa4b53c14b3b43df8715bc18b502b250c478bac15d374bf5d30eb7531bf9d5130ad0b2db85b00748a46cdfd0d844a56a058332f2ac6b26c49a3" },
                { "lt", "ef6d8b82cf6899d23b4a042cba8dd0ba27b09118ea2d182a9ed56757f57029a0395ed92c9b439bc321ab70cfaf8544ab685044788b3036ed29ca44c106bf7875" },
                { "lv", "537d7f5ddaf7f1c88a75c67dd57dce07996b624fbf66675e7bb30d1174621b286433bbced91107f8f6de9fd5f19052a08fa9242ec56b8a0f2983cb514a65e1dd" },
                { "mk", "92e0ace2b91c26c1871d52211bc4b43f7fce1a5c9ef9ff777d1b0731aaa1a341be72e33bd4e45f642db524d455d08367c3b38c0d1770a49904cb6128199ae092" },
                { "mr", "09a1513ba6f2c1a0d024bbf4162a25ed806e65eb778a4817bf07b2fb92b40dcfba06e11c564e93121c7e423f86db7d57162b062ddb8e61a2a54e29346fe781e5" },
                { "ms", "2a85e45c1d2f95b528f6f9fc010c61a45c4b5a8230be224b9ca24c25658ac7336092ec20df4efe407b114476e80c902fdcc9cc6cba1a9f67db4919fe20dc8838" },
                { "my", "567ee388e111bb82bdd48585a7bf033b9233b7adcfbb6cb54748f1a27b3123643c565904ef46e267dbce84a39c1c7f649aa2934255762a20aa531c3758e2a03b" },
                { "nb-NO", "b54cd393f45abc12ab0613a46fe9bf26cc4137afb869bee1d1daf199a940945b03d00f688fc514a335890428e48f7f750bda82f6dc0159197b147b3a5d3ee5ee" },
                { "ne-NP", "ab9a08e7ef30cc011c5c6877f976294e1a76948d57ee0f1c9fa128e81205579209b939cc9f62fb01e3839954429e714fc13be2f046b1f9bc6e36790b08badcda" },
                { "nl", "9a1a4a690f469b61c570f09bfd585d3d738f55401778b002fa541b094da2f06904ee76f45ca3b68bd4d5875b17f59445a45593fb5de11baf5a685f7e1299b1af" },
                { "nn-NO", "89a644326754ea14f42ac4ab08297a035b8fad70da0a9fab032bcb33fe9be777c017c7af87c429fca74a0bd68639d156c739697f957ef59eb756136c7d46546e" },
                { "oc", "ca38706dddc8613daab3ce7687c2da667315925745f8ac5451598a284e038ecdde7d2b5830a8e413b6d0130baf4b1a050e63a9af3c6bd31a0244da75cef1915b" },
                { "pa-IN", "c2798ea45a4e07c84d98670441e5fa518a0cae1eabe57859974453fad9465f06e9ca76505c90e2592282be30a6b200a30d30eedf7c8d2059d7e902bfa99321a5" },
                { "pl", "9c2dc354e53675fb5f88e879c3237f38c32e5e7185c47c7675edd4538a3ab8fe5f4f1b64a8d00e6b6b7a7681ced8c8c8183faf84df0e685d76df2087e6a9857f" },
                { "pt-BR", "ba9e1dc2800eb58bfb4fbce4a4a76f2959ec929fd04f9949fd1211e9b4060bb984ee3953f40062cca0a479c2ea88d117a9889d071987666f329caab8d79f8915" },
                { "pt-PT", "29cd744ab8a9a3f95905e43eb6e37deb56088389250ba67dc252f8f40c8a67490da9ed6a9fa63dcf0d19e8de78f818fe08e2cc449f3c62729ce26ddc2e07490f" },
                { "rm", "afe98d685664e4e9dfb041ee3c0c04d0474fa5fc4193e30b82ebafcdcb645236a3e0cc2112ea44acc3f989949f8467bbe59abd0ab6be63cbf2d08fdc0d4163ad" },
                { "ro", "1017a546f6ca53ba7c9cd4ef69f93d4dea064500dd56c2b6d0d9d5f6543140fe3b19651330eaff86df934202d7b87adfbac3c06830872e646058f7ceeb38f927" },
                { "ru", "72b899c595101c2052b25355f49c6e27434413806cc4f771795cc5305216cfd286872a31e3f926a2c269629020e95b35679c0eca5867580d0358808ef82a2f45" },
                { "sat", "d25ec53e9a9b8a61b5ec50288a5fae87da2c91b5c629b0801e9d123f3f80e98299d6659b40c5efc4d5cc8b359c683f6e4b36df3c3ae1fe8169d448bfc877878d" },
                { "sc", "76cc446d3f8950c31a71b1c1200839784e5a2ee7a62b467d4b580135cfa405890ad42a2b6e62538bb379b7fc4527a07e882b543f01ad974a5b35c27f59ff69f0" },
                { "sco", "b55c1bab3ef7fba1c504d81725921072c7ea1b030d6746d10ec6f3b3dd8aa15f5ab56dcd6129f64a4b20f6a0ab6e684c7143ec762802958f55fb24f5336139ff" },
                { "si", "52c5980870e69a4f8068e8c18d6f20e6827006b5d42ec103d23543863adf75124f79a0f419059b9c4282bd67e4afabb728cbd3070fa3e0864a6a3add6898ce14" },
                { "sk", "0ea43b8d88b767f89c7c9ae29460c1038cdda6a8c337a17984d00ceb72f39256ab6766ddeda32545f9faf2e7488fb5b2635f2d3697ad396fddd3f4131dc24ad0" },
                { "skr", "391d1969bf095c79faa4e78bfcca037b2b2da80c2d0deb78074903f6267cbd91a4ee110dc456347164dad47afc89876e8ab7a4ff345b82b0a92041ecda509a6a" },
                { "sl", "652fa7410f349dbdad2eb95d33754c2aacf9154cba678951780d135370fa1ab0095845d509098c3cf495849ac6067288d40f3ee8d23320b9a91dd6165aa50d7a" },
                { "son", "fae6abbf5f8edca7d663dde2b1d409320d115979d4425f05a852a3bba77e8661c8d2adf04f0d1f39d240b3d1365064ed4ceb48655a6b017787f852024e3c56e1" },
                { "sq", "800154177a3569cb9504d1d6ccbb14f8202bc3408f2d77edb0165b0368b8cb6553f210033a2a588706d43fa8df66f402aead408569d32f80c9cbcd185b9222b3" },
                { "sr", "98c08ce64851e9584edc84811de18c3370e9b5dac11241ea67c2ff68f2267e773a38fefc97ab3481a6b5fce80c408279e5dfe511d7ced1893e939097eba103df" },
                { "sv-SE", "f628a896e6634fb6310c9b835813249701705f4c0a46a1001a4ac7567911cae4be84ca1eea838971233c0cd45647ca9d7f2f3a26aea0f76d97d08828ccd8b2f0" },
                { "szl", "072af780d36d5e03e674b27a41987ef8fae7c1f74a51a1390b0aba79202d58b4b22635a17f4e4f9de9e82a3dd79a3f32094a814f03f36e82f80a5c8b563a957b" },
                { "ta", "6f83b0770ecb44cb265fb4cd6ee7b29ada774b6e6ffe0bbfb95a75fd31fc054be5c486edfc48ac82d72102cde696a2d4ddefdb0bb045f424268bcedcaae8dcc2" },
                { "te", "869a193d36de1de33a7bb367f388da84eeea6e6cb786b6e627b0e61829d40609d41bfd8fc39aca88d474f3cf65e1e7f929b4fb11ddc237b8aee4419655ab721e" },
                { "tg", "7f7f3bc04964c89d97ee314d3935110c1b86ccd1ed809dd9046823919126b3980a87403813a8847637ab9a7eac9d98524f0843fe0cb156a8dd9d2ac3802480f1" },
                { "th", "7fcecdb2667b290839132d369f4fbced0a027ef3a2952880687a7f65ddd8cf63da8852f46e2b2e0aade23a2a85767c1d38501edce454c83891103d5da1d89207" },
                { "tl", "a720a1ccb766fdd61bd9f0adaf6f0cf5ee0e2458f96b244ce69d96b62f190912fd3d4adb26255921deef127154765cea7449baf189d661f0dbf7c0401396e876" },
                { "tr", "b8697e0c8796b6780003b1a99fa68320ab2d60572eae8fb52f9dc6990bfca19f0a68ae18a49df1c73d6b04249c2a01dc53fd28326c6a3538b8d11cd7d3cc850d" },
                { "trs", "b9cc6e08a9bf9d6c954f8f967eb801d922abe97b0cf9b72d8b62f3b097649faf661f96909fdba874d3ad6a44425ab041cb28c96d688d4531b2af2ceb7d26e11d" },
                { "uk", "b8bf2ab759ca5a0d6d78103e9cdb8c9ae392beca8e3e21f079f103374706613ac0b2eaef0b67372cc130bc329da82c85a0e617ab0ac319a770fef0825198e980" },
                { "ur", "7bc30ba79d0c7c7ea383cdbd4e7658e9378e62281c6981dfb7b34b58cf8d2cff5499f6fdb84710faabb8ef89faa74f2441f9c27f92fe43d54f86681e2fdcbcac" },
                { "uz", "2252f55ffe698e56a8a5a9a6c1e4ecaee2710386ba2615e325311c07e7a08e8a6c1f886b9917d6714164b6125f3e335481d39c0528d0c240af2caec09613765a" },
                { "vi", "494063bcbae40fe1bb89af1838cd54852aae01a3cfffd045460f5f8c809cfd1c62b98fda41ff6638bc254640e07970fadd5aae75528234be47d4b8e64c7007fe" },
                { "xh", "87a9a9d7422b9ede5457e603f4e565ba3f262ca224a3a94b13c40f511bb18e6e0b1a8b60f87e5e3ad8508c42ba41ad8a4019042c2e50af724f0599a3d04d1863" },
                { "zh-CN", "b08ef1530968cc464cf846a7e7711f35def75157eb0bece02d1fde8a821bad3537b1b3b8aebf42673f68db72f336a898152faa4168e798cc76cc26eb579acfee" },
                { "zh-TW", "02b7c81e9e462b5d3bc0ed960a2df111759c30f60480c1a2c5ae19fcecb6dcc6bc87cf78b747fb131bff62a37a0c515e3d2d2ced46444d51c55cdd238ca84fef" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/141.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6e18b565d5f2d205029520f11fe46da6b85260cf7d6862240df23f3f5d5a6763bd0bce01087e40c2f9a88514350da83d979f7180db339eeba8cb276fa53716ec" },
                { "af", "0e273f965b0fb925e41808fd8a67e8128e85f4b2481f00ed23ab50a5b085685d13e448b580a8ec4ce9cee65949f4da203f2bd8d23be82bac372cd63f11545759" },
                { "an", "0572e2b9e8ef7b883333655938ae49fd2d4b1893c00f1bea7571545f398b6cee381a2a6e0b68aab80812e3dc9fb28fff366bcfc95b53a8b30da828857c4fd46d" },
                { "ar", "e19a0f163760bd32707044a0e6ffa81667e36916776165cd6f7eaaf5a5c2105aadb872d8b167f36b0d16c9f5fb768a1025b3fba877ce5c78ef37fcd1a436300a" },
                { "ast", "732c02c33ff900a2e5ea3682cf8ab9b08991e98c5d98c25a4e70a27df2194b039db501810fbaf99490563526f683897f3ce01e8b4c16f71ca4bf33a635254f9c" },
                { "az", "3448ca0269448851c31697f2519b7f2b72c31ec43dbc4d2803cc9c62eed5b4b4733fdd4de21b79dc338502abddc824b327fa827ff62b5c2f50394596810deec1" },
                { "be", "66ebc360fcb772b95f0dfc0a22a386c0a0443bbd15a462a99f4dab2a4b94a90f78241a02509b2094557a6f8000de64e7e8cf5f9d43d7a7748e09c8733719bb26" },
                { "bg", "7afa41ea11503fab88f016480bf8a7398b940359a7c87a723bc98c63b8ea86d9d393b47d2160d18cf6c378dc721a4645afb7ac6b3fbb825acc08cba90b7e28ad" },
                { "bn", "158d254c4ab4f24ba1653669ed23a6e24c8c2a05aaa2b1de1cfe12ff21a0a33aa44a267ad4f8199c3292d77c2e93914893f68011a042a708d659d94dda0eee2d" },
                { "br", "405c279a1686bdbd3cbd23445cf0c97b3dca32235318981047c2b17703d65ca5c0c5d82b3f467ff6e899a6995d5ad3a64035d4f1b89d9f0ba06aa868ddec69e5" },
                { "bs", "e4bf571ccbb978aa30ad371dedb9d9ec255265a2bca5752dc04bec786e121ed41128c0b9fab2afa707dbbd035808a91fe359e638d1f0c2bd039fe903da1fd3ea" },
                { "ca", "171213ed7389410281b42917702d637c3915a6418730a88987460feacab7cafb66cdd3b0b2768d1a6cfbcdd695d3d9a5d35a30197285fb750b77a50dd6898c4f" },
                { "cak", "6fb383bed9728859948227dc93d808d41fdc95236333711c9a34908ccb803ec78792610828546f053ea6ba97cccdcd772ac299be3adb8f7013519397af457476" },
                { "cs", "3c9112d474080aa906ac245e8d0f90c866c4d12134e3602a4ab411fc6ac9c27c2352525e909508436c5317b7e80e2894bdb6770457fa0517d907e4caf2036e50" },
                { "cy", "eb7a7ae8364792300a3f1500433094526f4ccffcb61f09e5550a8d75d9ab70d05af2763e1f2f37377effa46782aa646565400f8d9f56c0183d5c739a4c12d4de" },
                { "da", "389bc781318e1da3fe4c45689b67129c09081db8327d6ce723f283173f88080d0a43c5d85965926f9d7ee1c20636daa40bd253d3ba52ad7ec735e9a445f32a8a" },
                { "de", "8e0cd5720b3881be9bfb19f7aecffa0d048379882251cde8adae7b654857022641ed42bf448d6e36ea4ae13b34701e1580e0746157f0581a61b583a4a805004e" },
                { "dsb", "296fa75c29530f6048adff4288b2f4201c22c10810650b10d80890816fb23e5208d49e7ca899acaf67f4e40418fdf2a3116cf4a7e169c8dfa2988065ee7ee357" },
                { "el", "84abc1dd14a4907d22396bc42f40a779f9b104bf7d879e808764560437af501a0c97415c810ab0bc81b509c35f1979f92c23876782b2f36187debe2e53d564be" },
                { "en-CA", "bc66c9c16defe765da0e9ceaa125c781704efc23a2cb76e20d2585743ef7a3bc1b1f2b71aa55f6eaa07eb174464e37ff8601159922340896de45ce98f1ec3d4e" },
                { "en-GB", "0449230598d11c793a242bfc159254353f352a8398af99d7eacbbae255e0cf59c1be057a6f890e710d7960ed961b40b3b22f933af49d20ef5635e0acc3f59016" },
                { "en-US", "d0bea6a4b6c29b14b1b4ef345944bcd7df968dacd839445433b195e1dd99723bb9cdfb198db97f164cca0a2971419655a855d951fb1a51e93e621277823ce2ea" },
                { "eo", "41de5c55992e67003aadd47e167a03d443ff588b2853858215966168e08fb6a1e40386376fb6ec149785c020edcb8f293c4f902fec7351c8ffc3e39f287d87db" },
                { "es-AR", "5f6d7586272d5b35e7ad55f0873aab532d371fb12a447500e87c920beb28e13ca30c743b2eddbfbb5e74f8aa52f9a2461f8f0a33f7e80652d3ef8bf9ab0df53a" },
                { "es-CL", "6e8741a0d4eab12857bca06acc212bbe7323bcdd9fb4a0bfbc48f7f504532436cbd9dcc19018a7df5b703da6b872391c30557ec666fad4fb21dc84e2899705ab" },
                { "es-ES", "721743aa65df1e3c33c83e973951d53ea13a8cc9090fa3088dbc961fa9839a5506da254de885a8c4eb9b30e32b1a6bd779c0fa07d12cd3a98501ad7086cc4bf1" },
                { "es-MX", "130e0239042e4ddf4bf4077fb103ddf2419b44a3eb3b24b4f9cb6d73f16129f2a63eb841cda5a0b21910ed0bf15369d0b716edd4c34a0d6afc1ad5f8f60cfec6" },
                { "et", "4451f54a8bd3f9d252a86fb0122e2e10b21f5207ad68c127aa8a0e47d42e5ba713eec931b6b04adde04c63c96b02fab725c2c7ad438e432e642f685af3008df1" },
                { "eu", "de77e17f88cf7219f533d4ef2e51effef27c3fd52040c57ded945da0d6543891aec048731b87589f1b524494b13c1ca5a87820e11b80a554f878c80daeb55845" },
                { "fa", "46e08e58fe2b2d3b8910e41a0c4212b16a51c58e40143e68c8fa7aca00d6b04991baff79cb66b00ab59f04c865c7ac0a3a233833c035008628c6d82fb196a095" },
                { "ff", "4861e9f87fd0982a5f7ba587308eecf9ab390a6e843b8433d9f98ba0e9dbcdb17718747d4451245196b805e991f3550d75e1cca24157effe3cc5d522c080f8e2" },
                { "fi", "0ed80a31a26dfff32f1351920062711500ec3f9658588d4c05d29fbc665d98fcbaf9142e5b77887f8aeddd0801837a2634bf1acb83dffa74c06390eb06ea5a8b" },
                { "fr", "2d28011bb4ee496374f2ac057684c62f80539988dccef4d61f2a28e86ed59eebfcbf0a8aa17a9a46770fd4bd997931ebceab9f7095ee34c29e59d38457a9b25e" },
                { "fur", "979f2d330ffff6aa65fd174433b760ebfbcf19c59a58db8c5e4f61398d968d68bc6d5fe4f77c30c0a8716d5e46d97972d4c31707a1a1ab621714c428ad7c4fe6" },
                { "fy-NL", "d53d5ab90e64d67519452d0c3c9d1de30fc2f1996e7af5496a36a13bbdd81a4a565826f8cb967641f3ad24590c1e8e62e0835f2ee104639cef98303ceda8ef42" },
                { "ga-IE", "645426bd9dec3122b5f31bf325f6267e092f0eae3926367c6f3f59c683c3538ecd069f3b87180cdab86a686e540fbec992f9d9e76b59e2bc47da894c0a63a61e" },
                { "gd", "71e81d6e0e6481c76c26280bc16b0f57c383c2c55976b0be18a6b353fcc189828d4f359f9f34bf2d3e06efad3659d36009fb44a3ff7e229a78594222024bfdad" },
                { "gl", "c97d6634c81fb09cf11dd88fb33d30bf20c58189d361bed321b06a73b6514bdaf4d50014cf8cf26133d5461f038f96b24c4aa7715c7c75a20bd9752c964282e8" },
                { "gn", "2a5c25d185f1beaa595e576fc0238f09ecda378a03d031e7de0ee19b9aed21e9b3da9e192f228f9f2e537328903f0ed572b4136020d0f02943a2f5a6680d8334" },
                { "gu-IN", "d436ca173446812ad15ce7c7ee305f4da853cfb47cd5b7f3cf977d03e6218a2992e67134a048d9f0ef4c5789d1b7307f8c7f1eb314425fb41df679c23c35df5f" },
                { "he", "af624879339ae3cd817e9166cefb77866e13fb9fa227a01309970a326a9752910294f60fea0e0753967e9259806d04779baef446a79a5348ba09258188ffee87" },
                { "hi-IN", "9bdd15d084c6163336c8ada959586f2d92e1c9b9e7887093daed61a0a8ad6aecf6943dc1ef39b3cc9fa9915e33d3f7008b55a142d9bf51e6bb056cb72ef766b3" },
                { "hr", "908e994f2bf5038444682082ff592bde051fa189ac95756267cd0bcbf802c0f512bcb0f5ecac47c961da34bf9369059637040424d148aad7701d788c1bb78691" },
                { "hsb", "86abc9fa8e2cd4e8f10aad1bb3092f1693112205179f18912df8028681042059304cf475ecb3b672509053a5df7387cfaa9c0e2530319b5241a114554a58a0ea" },
                { "hu", "57f856e6e227593b5a6c120c26ae0d9620ecaa9502651d9332320e59b885deb9b02942548aecbb14016190ec78b67ccbda2500d81aa88bb46a38fb57f44e8a38" },
                { "hy-AM", "fcca0ba4552759e02c3e7fe08bbe23e7fef8e355225c31be193d9bae3b1f91fe64838efe97fce0518077673c2b7a93d7e76aed34a1a32b151837064238c066f1" },
                { "ia", "12cd25c265bd1e413f118d9afb5067573d864ced7ff0f914959aec3c1a8d549234874c8d5edda4aac7b210bed44bd6d6ae44949665b2a36c25c65db7531c6946" },
                { "id", "3d528a7c1f87976bce3ef67228acf9a943d8a35ef120678d9d9425a50a9500ef6f6fd47f62901d47629585483388b749c96404410019dab09454e1f13b94f077" },
                { "is", "2cfa28b6b07cd9f8549454488a70298f1c16f6c41ffd046363191280b5fde70a6361cc8849678fbc2180f63e82cd6dbfa4a818a9b41e17dec65a16dba55e78e7" },
                { "it", "3cdef474ad146488a1303c7c5ec2d052cf0c1a90f68a1f8090230b4a05e4fb3788fee0798fd4a23db2a0db97a6554c27e89a0ed16af8a9b93611cf6f17017ae0" },
                { "ja", "6574faed9b2a26ea8463d282d218d0094e34b4ffd2d9e9c453d7fa40999d4ebcdd04af84b692ebca851c17e51b05d905c3c8dd7021142840cfee6c5c8ed046b5" },
                { "ka", "3886f6b4b6ff4a429bb401ae9e07516314e94bbfda4035854423ed7fa54584f9e03c6060ef39337fb52d58b8fe483ede2933c5f99f89b801df9b3f9d08fcfe5e" },
                { "kab", "acaad9cc7d54b11e473ed6f337588ac2118a8d614537ce6c78ac620260f6c5f6aa1461f413091e4743efa2138403b945cbed622e44b603d9675718d600724c3a" },
                { "kk", "e427cb3ac1d2edf1a01a2fdc41b16ce85d999b9a17eab704a43fc40e53036cfd7bcd2061c922b40be7ab865d9e9980c0cc88d760b8f459ec479617e1a1459654" },
                { "km", "2fc01d2d74a2d2b3dbc528f3107b74ad99a0777cd2f13df27ae8eb9d38d340f25aeefab913d4707cb563b8e2b3c2a4611a80cc48217fb38f80e07174635888fb" },
                { "kn", "368f9f5e3a166ae09f78de457ba9f3fb700c73fd4912477bfabd3a1cd06f8155e43880a5d51a2febbb15e669d8a996e1adfd5d87d2da4b9d6875e7574638d057" },
                { "ko", "484489667819a01d20cacc46eaa5dec9f3dacb834cb7a04a2f83b29689c6497d479112e64552dd0c498b095251146d3dc6e91d88da2306c38549bebe9cf18c06" },
                { "lij", "073b3d3788bf11273ef1fd8f5929daf5975bae1813b9f86f511b859642f48545ae60270fe8b7a7c3f8093079869df627977019234d3854204475ed94b8fa8646" },
                { "lt", "47b47113beb6b300608ab6999a6c27d439397dc539bfc90007acf863a4bace70e4a408e60e24cae7256c8acae9515963ca2a2bf6203afa175056c71772b81ce1" },
                { "lv", "24a637b74985a0855370e117edc8e53fbd82f982782df7a5a38b40444dcdd6d2bbfaada64f91bce05f5a5fb88cca8762f9740ccca589a21a3272cf99003ec0b7" },
                { "mk", "3aeacc04179dc74adb96bf6558240e979bc5c947de0afb109005df6bad343d342769a7be119cb6550d2d0939af805e0d0d4762c95d3f4cc62fa3699ae32276d1" },
                { "mr", "97c489dfec1d9fd93f04bb3a3558c6eba5e74c90a6d508a6e4f08682a81528bc9bcbd63d52e9bfc1923fd08aff885ad55e351365b5492c3223bc622d1de9924b" },
                { "ms", "7f32ecd511653d3cc1228491a41dff5aadbbff475def4b5ececad6d82522dece5d74036dfc8d7b56dee5684d1d21b8b5c1b860b585fd52815b72c62f49e197be" },
                { "my", "8befc1662bf96b821b3eba9288b93125bfbe793ae9b003df2aadcc939ee9e01fe95a0f61d757db9fe2b7863c3af84040839cce20cc102d61a78826e3775038a9" },
                { "nb-NO", "4bc2cc30f2d47325121dfa114110e9d0ee882e15bbe4f74f5659f1d3b41c3f62558f39d081ccaa8eb232916f62b17428b26def833e45538a1a7bac3ecfb369b0" },
                { "ne-NP", "6b10f8bb68b601965231fbaf19efcf84d7f3618210cba9d1f99a1b076b22368ff8a1118edb0e63faf380beddb35918f8c855b5920e7d53b01b317b313386d3b2" },
                { "nl", "d3d6c685c1453ecd25bb44435669c04ab8e8bfec41be51cab2da156e0ecd75642f4672b4c39b9dd8ebf54aa310831072bc5eb24f1787335c106874d37d8d632d" },
                { "nn-NO", "ea1e65b61f6204475a2284252ea46780894fb34d887638de107a7818ae20f5949d652644f82f3130f4ce659d0a5ce4b5b858134036aea4fdc7e831c2b0e76dd2" },
                { "oc", "a4314c27c4fbdee4fb8f10dc141ad8345c7ae28147f0696ac80c275715d4710fffd12242ca5eb33aaa7fe599339f56868414e9b81e9e4f420a37db4acb566af6" },
                { "pa-IN", "07f5ba553debda26eced21c9bf1dad798f6fb17bd2a9ed41f731f80441b8583fa8ffa4f882f50376103cabbfdccee091e795ad2450bc089500ee976c83a1cb7c" },
                { "pl", "7840afb5ab065643b1c44a064d402005622d5410a8db79d64879b8aa09bf229420f2075305f3b148b6fbc4bdd3dabe8ed88e05f239be4933cb0a0d88c4ac9610" },
                { "pt-BR", "5aa4a806cf951b501829c7b4f9e1a76bc095d8f596c913b4a2496d42ba80fbb884e8b06fc22ff31bfe7f633d91feec42720b6f66ee94ac211642d375c66c5ecb" },
                { "pt-PT", "f64efb57c1595924fd8ad03073ec42a3a920ceab181b1f5c72eca33aa2e4a2cdd914364fc8274e8b08b9a5c18e7a21bd2d69a2f2d22c1b5d524383186192f8fe" },
                { "rm", "2b647545ba1a3e486d0186e37081983bcdf510b7be48a9ef035122f18de63d576b931338b302b625c15265ea5ba71a10d29c5763ca08b424188096caa14ceda2" },
                { "ro", "dd1d019c123dca511b46e15ef7e866f97a9d78b85cbfec5b2026918e94f992bfd8213977e96568d172baa833073614300a2a1b4e8b345098bf0445d2b4e1d8e4" },
                { "ru", "f02163f7679f67c9ff2a838b8ac1e7999ce8ff290309375f17ed3dbf5c2ab1dd58e88eb672cc662283a575c264841a245c0fc0b933ca0a4f58c9dd77c2da0a25" },
                { "sat", "f75e0cf3cd4462044c600892507fe78f2c47cd48ffd80aeb625a5397960fc94288dcf1f5c53c58470df4c1c0cd88f25dd05545784562c0b3e341cd90827570a4" },
                { "sc", "b479808bbcd908b3febd2cd3a0fcc6fd53bf2660cf99e780f132da818f737d537a546339f1a71ddb1acc239be5bc0a7bf6b806fef55d17cc51432837e3613151" },
                { "sco", "f0021a56e2d05184ce854eb0fa9f32d1426bf0b967e756cc5725994b919b37ee998141fdc6790752b4a76bfcde0014c975ada093adfa101469075e19f2cc3de2" },
                { "si", "4adcf9485ddf8fc69c5b7df36124959db28437d5a53f87b0cf602cbb3d111eb4ebd2cf7a795fc9e4720c9b20460304520a085e570d6bdf521c7332da14c875a5" },
                { "sk", "cc253c0cd0be43a0ed26a3937630d50f73567eb15f4100ab682bcb35036cbf5e993ab2b7818f282e93d1fe33be605975bee468ea0844a63c0e67a9c4aaff922d" },
                { "skr", "55f3647e1ccdb87cb11724d48f7cceafeedcde1627de39953922beb5790751ed59d3a4aaaa4ad5e5315b53426c83228bf2a88c1160938c023d34bee494fb8ef8" },
                { "sl", "f71d089b93db74d599e959ea7747706d03b631a7a1f7498a164e5b19bbda2d72c86ccbc7cabe52f7fc091ce05bf785cab85c9c86aa5e9152d4d596e54c4a29f3" },
                { "son", "21abf352ebeb3fd78b328c1b12581c7cd5a64f1d5a68a238a153a38ea4adddc064d3be5955862501f3bc37cc3c171f1c90a04d096d4c85c441d93c477760f067" },
                { "sq", "df9b91fad4710d55cf58562830eade0cd499737d9ccdffe0d92524eae670bcde097caab84bb3fce3cac3987c0b7dafbe832f198540ea8d85a7edcf5f3349d3da" },
                { "sr", "3a77f797145f5fa26f1b9c89782c86465909bf3e710345c1fd0719142dac7610da397f6f0be78100bd7b8b1824f2a610e76c3a61c1caad4576758b4f0ffd6c85" },
                { "sv-SE", "0aa2fb0e89e29e796ef67ae3e41051de336c615baf14c3a642c5755778cd0843a995323eb601b2b746a8b5c1d6cd60aa06b1380568ea956276bdfbac93b035b2" },
                { "szl", "cd1b909f73479e4c9ff39f0afadec91d8713f60de05f556d30861b6904b3a98dd24182ffae398606363df9479a8af49e1fa9b8fdca41fb6059930dfdfe1dd01f" },
                { "ta", "e65b61e37ef3862885b8d25447db14384710b0dc6ec22a45b14dd357253137f0f9febc5a970201420a7fb06758f76f1fc1e5b920185941d8d0662fc83686686a" },
                { "te", "df71f0bfa342648ee1a307e551c27200c86a34475262ac3e324b4440eb07ba9cc82959f093e64a2ae63a32548556010525848b13891dad9c95cfb3ea4eb1abe5" },
                { "tg", "b42e2b2f7a2bd4be6c0e875a7f245e9b70dd5928fc4152129fca89f9965ecfaf2782f4e43df0cbde3d014ac43c06b179047a36eb127a36aa4cf1ba6a9f6007fc" },
                { "th", "0f6d076fa912cbc8ea95eae386f1796356fb2f8ca1a366f01c050bb5df4c6808ff4c14a55ad013c3eaca8fe3d8bf47986d523c36063adc0940267d534f8f35bd" },
                { "tl", "37cac3164013a80c23b35ce837381b1569de048f11bd7b6d8d9e739eef3419bec32ff068f2d22e9a59ecc9d9f58482d9cadf0f527a5f28696bcffadf5a3cf3fc" },
                { "tr", "800a593fc5f830b3dcad72bf1feb00b7d2e278d7707ed98bd10059d03a281f0611397c245f85085ae905275e25294862de257145ee2be98847f5ba0e6602bf68" },
                { "trs", "c395242ece45446b4d96321aa4a792b25826970c5740b6c0992c4238cecc202c77e3f970ebb2cd6304a75b8f201fa246412c6c8521f33db820e4e365e73388f2" },
                { "uk", "cf1c22bb2ac36911d8ecbf51b56d6fab656476f9f0ba9c37864d996bb3b6e861196e2d235f536e73b1f782c1485edb8ba56bbaef13030a4036a29e1ffcf7389b" },
                { "ur", "cba0bb93e6146f48408bc2a7e9412e08ca098780e59e9e7b7c626730f5d6eac1b805348d963f58172d1591010d41b8703479ee67dd3ef4a2567c328d26af9ce9" },
                { "uz", "9c41a33d7a533da142bed0d5bc0d83560c95b73cf0caf8d938ed424cd96759338a4849039d9ac59ae41a304f630d8e206856ae543db9c0708fbc896667983b6b" },
                { "vi", "be1701f17b01e3142d6877d379c41d93380a20320d65106b0fb87b5a1a132bcb913fe849333dd195f793af03cd288658dc756a6947e551282474a6c13f32f495" },
                { "xh", "680a7eeb7e28765cf53fee1f4ab89a79768d246fc747e04695a46b096f28d418251603fe7737631fcd6407d96cd591816f2228ac3123d06d6f67d36677df089f" },
                { "zh-CN", "fbfde88eb813e807860d49aa09cb4d617b2ba5c68a00132a20c711f192f4fbc8052a80af8c73eb466fc32d2831785c159cdf6a8a54ebd895fa3e724a8fde2fdc" },
                { "zh-TW", "c0050771b74c1b2e8202a0d7da78c30993c4e05d9a7ffa373c24e72e7d51d7a128bae60a59e1dbb812193c25de6cd7b545346b7b79cdda86077cc5c6e5af8964" }
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
            const string knownVersion = "141.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
        /// language code for the Firefox ESR version
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
    } // class
} // namespace
