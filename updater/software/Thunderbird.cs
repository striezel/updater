/*
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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.12.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "19cc4f534b86397b5610e2b631872565ca1b0c443729f13fcfde61a4a89e830a48bff20ee099304e48d730ef7131f9e67d427d6519604389ff6438e0189115fa" },
                { "ar", "8ff730f983a664e0816a4e399d89655272fe93750612eae28568b0ed0419cc9e8834f1a32b0505e0f40f6ae4f56c3fe91079e4733a993aa39281396b232ac86e" },
                { "ast", "8364e35ab809515719b47ddd98a2d0beec891ba10016ccb699be843517d813062037bb89cf1cd2b8dc782601ee556f562dd0f3a9eeb604fad7a1cdeb09127c86" },
                { "be", "cc79307ac7deeb0e4d013365e17f638ccf4d9a0ee016ff55a409de9b97f40eb5dcfb8ca88b8c3a29d62ad63793da54cfe7bbca55a3c7c7919fa9232b77c0a4be" },
                { "bg", "9548dde6b4b27e53c5f364c3a6b86a5bda608e35f1fda578729207f08f941b5c229b6f82cc168cdbb0f56b2bf13ff4a16c8c3b1d347602bf8fe83db75efac187" },
                { "br", "f0d772d45c800d1c3d786315996f0bb935113812ccc265eb0f4e54a19646806dd2e3fcc8b6bb69c9a6bbe91c5b408e849422899532af10371a800f38b4ff48f2" },
                { "ca", "8ce64b1d3be011e0139c666df80a5c3803178dfbbd43d512e968c2a7c8744dbf5f788849972954ce4624cd48e6f636527690ba4ed3d84e46715e5b594f97184b" },
                { "cak", "27f4e67a6822c3d783244488aaa6404e124d3d10d20bb563cfae74e76bd7a1c9afc505847e98a1744a40bb4e263c32d64b3412c18d00545482545e733a6fdb88" },
                { "cs", "1955d377c6f85a80c86f609dbdec57e210e5c89cec0cff55e0f13afb760cb03493e9220334ffe6222b2109381546986d07d1774a249381c7b2e3353a7f7f6b33" },
                { "cy", "2894ce79681d8cb6f2a9d864aeeede5a30cbfae0e73a1509197ff1a6fa73852ce36f6859ce1da10432f2fc53d140015809eafc56e61871f6d2e57316d94c2c66" },
                { "da", "f9738316326f85a435fd76d0e94ed11c4fe105225224808507eea53f84ba1005287e0a1b19a5d9a46570610426a2005abc20d9e0669dd6161c6d54966c283278" },
                { "de", "f518cbc13d8f28ce32cb2535948dd304c87e5f245717477656eafde4ff47681f5a941612a6a99e8ae5bcb521ea9758bd4b6b039c01b656afc567d5799e147cfa" },
                { "dsb", "ce1a70bc506efd58c212b88efda4b81beb3adcb1c3bed10d3b9750df2218b475f0e6a53d1bb009f2d2a666af2f17cf7d2532ae426ba6a4dd9d26c8858be8757b" },
                { "el", "3903dd33864bd014e432207c6e8feea6e55d3aadcd263c2f4f5f70fd80d510a84ed72ce37de9b3081a7457c097a96fcf70076072f64c908f5e11a4fabebb0af1" },
                { "en-CA", "31b883d637c749c83860c610faa70ca91f4a4090229cf5d51bd343a2164fd79aca5d52707ef3381a6863bde37a2b109d01831951110ba1ed33196ef042ca31ff" },
                { "en-GB", "b7b280263c23eb66b46f0f8f54751771c4e874e7c30c7041c51de5f950ca183e8b8275b23fd7087e42037814ffecc2073bdcbb6d730664330dababc886bc3526" },
                { "en-US", "e85a462622c5b98b5ecc3608c780f53fb53e34aaa773cd002b353d8ecfa79ce921de976cf4f04759be7a63c815fd7216707a3b37caa5e193ed3bde09ebeed064" },
                { "es-AR", "eb326df1d6a9a9f6a5d0dd224270a9905626a5f575579780bccdca92ba3f19b9a9d1d1664e6809f089b45f5777d634bed4742d5fc59278fd4a0f31b5df447139" },
                { "es-ES", "6581a32ee0df02935a4dcfdb2bfdcd48c59ade39f21cc9447cca7d84f937a24bf46f18f34a09450fc408aae11047e98043012d6bcf626675f3248f07f86493ae" },
                { "es-MX", "9e64b868197d1d9b0092a746d983bb8751af5f8ca528510874439454839aca0ed1243277cf2d2b9b23b3949778c5168da6d6fa03ca497051a0dd7bcf70f5a71e" },
                { "et", "478d3e03a7ec71ba2ba5ce97740af6f41005cecb959b9fb056e49b77688b673111a9d87340d31e94840177d76a1798fd02fb5466d9d7338cef958e356dc451d9" },
                { "eu", "4dacd020b04b3e1c5cf4a554be7999c822a461c0025c5af4f8161bfd6df3df2b0b83c7a5fcb8f9db0033c7e8d2efdf2f01777099f81bfcc536ec53e2db790d99" },
                { "fi", "e18f4cc6c71f153ad281974178b6dfab8cc9ebafe37407c8d1115c3bea004ec2b3ca947b5c0f7a1a5d3298c6a34b3ccc408fd67c3e92ccf8dce9d6da8c853869" },
                { "fr", "289150a254b431f606268042faad2441ea7ad349b37183d4c76da863ff57ec5cd0c8fbb0f759085f7e748e61ee06007dfe06d69493883c506b98e1325d4c991c" },
                { "fy-NL", "a422c3819cdeb6435a3de1a0d848b879282c0af578d423abd574d0187a1bde94ff2a946439367ec91a6bb94ba1c3055ab4d901bb2e55dc1afd9489eb1528e8c2" },
                { "ga-IE", "60ea9d03ca0778c5be9279dab156e063eb18b82c51e9045e76545788f2b58cde3675da998818ec2284fbe2ddb91602e0538728417a1af9d146cfab2f1fdd10fe" },
                { "gd", "69b7c66ce0b98dda09543eca273c543e8906df1c4057acfd45623dff80b85e92fb3f071559f06cc0ef7d9bcab7ec40c4868df3c5fcc8f38f4857c015886f7f9b" },
                { "gl", "1b5d287f0b9d0396e073a583651aead06da400dea761a2bec22cb325af4dd681819534b9a2652ec378357554ac8096e442e4b41aa3ba27041ac80f6797f4fc1b" },
                { "he", "b0022fcb8d98fa124c461df04fdeb632522f61141cdde3f679f515ad0a3f69699612b8d2ac6ce245d2f190f2d9a21411986b95a49cf8fa0be7ac44e2d414293f" },
                { "hr", "9dd54269ff07249089162bc0bc0c809fd24092b4d38ace43359fc7f0267e3bce3d33b216df90cd08c842628c814a97e37ff5492613fec9a848f17106d1179e69" },
                { "hsb", "c9515c63cc1512aff6dc70ba0859fe47ba9101054af0850a03a49c472b153fb9cdaac3bae946eb663e273a5689a189ac3cd4123472b7e2c28ac41db24bac47d5" },
                { "hu", "73a5dfb0b244b95dc42899da364d8a9775401a3bcd8af355c6fa7c084d0ab23981580357d25743e7e85c6ee930398f18e10c7411b47cfbe68d630bf60fcf966c" },
                { "hy-AM", "6ae8bcd1826716dcd8c289a3cafe23d774393bcb79d0a1ed2f3ef3a71fc24586a797a55d0f5176ca3a8befea20ceb10bfbf31d385a70bd8183eaa9f6434c8f0c" },
                { "id", "dbfd6bfc27e4992f20113d4d0d854c719e06de36dea660935d49f183cc32891ff89808529c1b20da00a464c9374d93c5b883c98bc0272476df6d2d8a5eea0006" },
                { "is", "ab27199adba7d8d0e04a4bd6494725606a1a2fa787c66ed6c700d54dcca815f338161d683566fa4aae77b2d125150d309b9d0fc03235e913ccf452adc2de8156" },
                { "it", "f57f27361633ad2775692ba000d0d93deacacba359747c4ca0b364111ae3fbc9891105739324fd28d4b0ed0ee1aa561493d6eee74fe22c8e12b0bbd7293c34b8" },
                { "ja", "ca4a6d9da71ce46d422cfba87186576de907114cd7b50c410148e40f5e3074195d27c37356dff5230abf1bf121a5c942c2c848bbb48996c3052f6560bd9323e2" },
                { "ka", "bc0bef7aad0ff5f310fc0dd84cfddc890eaff2827f6e4ea0dfac9a4c832db9df5bd672de92c41b520ccbd22ef3caeba5281ae7877928992e85cdae2959620f85" },
                { "kab", "31c129d1d3323dbcc1c04e8b31041d7165518d1c777da430d46a64871beba903ff2994721b5ec689e17aee9dc2f4b27a6c99ebc19a6f3ed731f506a4ee6647a0" },
                { "kk", "225601fc2fc5d9a1a26f277ab7d235fec59637d3a38bb239bca4c59b3dba3e188ed0e43c1afa150453f9f995e22accb3959033464e70d6f3261f5e624d9c36c8" },
                { "ko", "050ed1ea706114242cee0e320b28a460b7f7db2e01af89159d2fca40a7a446c1849f2a923365660838cb1ac1fc6e80e158b51e7df5b42151b24653af29e906b0" },
                { "lt", "93a96ff0cbe0bc819cf230bbff54e1b8785d46d0f2a22c2a1d020f853a07d63ddca1e8cc42e526b3cbfddb508d910003f3d151bf1bd7db0fea514598036686b0" },
                { "lv", "5abdb7d65a5b28380a6792039fcd957638cb847c8e9c3cb8211f341a7431ac3fb1730ffab6482155cb15e447fcb19a941c0c5669148d3149d1e1ce0000f2ef7c" },
                { "ms", "aa3989fb29bd1faf4dc68af082c14b37d58a45854e316653307bb02700c07d85a78cb74926b70e088657da835ecdf5e1e0af7ee066c8a6e90f1969ce1d80c631" },
                { "nb-NO", "d970981dc0cdf43101ffa16b4baa628f6461d6473bf35d8aad5eab212f5a0d2445fd323e100c961b3ade335c536c22d5a04bb02d7681cab22c29ecab0b5ad6ef" },
                { "nl", "ed7594cf97a9f296515ae08cd3efb92169418c0ecfa35c630fa6559bfc99fc81f5bd540d3965b79f329e5a2eb8ad65c909ef73bdf48fb2d181a194fd9bb0eddd" },
                { "nn-NO", "5a72ad0efd2e3f553aa8f18292c31734317486fbd948d6cb21e8a0f8c9bcf2e253a96417da4b7f24360531b5cad2a066c1d7435df22141576750eecb77b94ddc" },
                { "pa-IN", "5d0ab4080fb0c94d5d4056d7e4ea5d8f063b91acd0f26fc0a3e7410b42f91081681670f71c4757b133ff12efa8972b93b230897aaf72ac50727fa65001157ccc" },
                { "pl", "76a32279bd70dd88440de06b3e674c505ea93aef7617db5848beca642d79781cae9d73654b82ddc3dcea368c659ce052a7778341d275cbe60b942cce44a5e664" },
                { "pt-BR", "2d308a7aaf3a943fc5d5e621e5c6d3f1e8702672ea7402749e809eeb5b5a94736b872fcd2f8b6ffcd2f2ea1c70bdf7e2430a8d3a882699e892c33a08a5d8a94d" },
                { "pt-PT", "b5b81104532efd39bbe14bd3943be8b33ac1dbe7a1c3c7842378983e24cb4d34771006ab82c44d0e1eaa7475a44f4214d7a570da1b9ca4dc445edc28113e99c9" },
                { "rm", "5cf8b6f19ad62c6e99d744e45001f07b3095958bcede7cc12d276f8129338385cba9a919a0244b0f707f59fe676cd66bdef8c2369abbb0f979e3db55ec15e609" },
                { "ro", "3eba731f63bee35dc1f9ed96f9a40d308b75f91ddadffac824cad7178879ec59a14c0db2463fae7cca925613622fefa645c3d5554ee81c7652a561d51b89aa68" },
                { "ru", "be8d5529198069f1373e2186b4a2baf0474c939ab6d625fba263d99dc1773d77ebf232b3a39fb499e474f13f9fe298a499f0ddc800450c3b8bf37d273a7006af" },
                { "sk", "85128fc4f232c5aad8294a314c2fce02c75f07bd39fa37c7826dfcadb4e9c91e550027ca3042a002185cfcfb03a212be73a3cb18ca6fcc9d6228b6ab59a693ee" },
                { "sl", "4568595969f9686ea2fa73f684a59926d7f6650360ae3e00a90ae4be8eb44c703ab4cd2eaf9844acffd36d9fe6ba186cb47ffc8ba3accff89d5c58743e68b796" },
                { "sq", "47117a58a6dfc200f87519130fc371cdecdab829e6a5d7cb2d3eb4dab4a81fce108968c4a3ea235fa87cc30c62f885fc0341660afab141e34673b6fd0dd366f8" },
                { "sr", "30053cb1bebf6918023330faf4f54ac076f11c9baff8ccbc5f4499c6b2a80ca400131a4b062430b685bb4ed22d7baabfb2d454b91df5e7de44a84c7613731d76" },
                { "sv-SE", "30523415752b6edbad59f6fcd926e2dbb2ef0ad020a335abd038b56e843fe05cbefbb7661e4aeea6ed7696ed3ec7d1efd1c57a1c274df6cfeaac7be76dcb59b1" },
                { "th", "8eae55d1f11e409b194971dd2e2ef2f091c2ef36e21474ba1e1965787cf83048da64daefa3dcdab6fa7344f645e1fe250966f9f2ec0ac86c3cae3be8bdf69c14" },
                { "tr", "e5ed4a637502e730276bc59f46be35da81e09544a8d57d206d1d8f9a5a0358581a68206f00ea8893b54a82c8b8210d4c98c26ba92f43e6383426ad84004bdaf7" },
                { "uk", "5749b916fb1823124a11d5858129d7ccf5063c426d570fbfa9e358f1a6caf3c1c9005eac71133b7f8e1655c832e9a7748a6f96bad29d43815de66898f986712a" },
                { "uz", "e0a0a99b696b81f8915bbbfe4874c4540bd112d06550e976ff5d0e251d1ef839fb701930031cf03c88ac2c4ac5fc3d0faac0f0d87bb7acac3674ac78f50733fc" },
                { "vi", "257e33b49de353f3771cc5e56e9fd082e072a06a05eb872f075f8eba871d2e766dae70e075d3536360f04ea95062fbcee5b97e51ef0fd47ec5b34ff3780a8532" },
                { "zh-CN", "7078a77f2d9d3d52a419ae9f556bc0543725c52e50e8ff6493a27b4af499bb5fb4a32b3b48d6892cf3520151321c69faeed04b37d0654f831cb3a28ccc06c427" },
                { "zh-TW", "0edb1743a46aeb9dc5facc943a9856313f93a114518b9cf9cf3d22fa4636aeb638d313a3637ee16f0a9ea203685c85c720f9792f8749b505c0eaa0ab7049f990" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.12.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "8850e43636b38799b66afcc70ad748c4fa6a07923f705bdd04f60f0e8c13514ed7fcc9c463d390cfc91baa72b6e1d68187cd6fdfefb1c7eb3dc217f22818d7f8" },
                { "ar", "67e3577bd650618cea4b12bbb237ae5704ade55d638e94dbe74c0f97be1dfb9ef22f1e710e0a29a325942b1f402880b4b05c51208c070b09f79d34b6738ea6a3" },
                { "ast", "1c643c071eadb6ea101af55b827b8b88f9212d39b81ec2e6835dab934dc8d24fd3c595702df9a89b47d572b588a42518160bf402dd4d1169fbb16b0d8a57a26e" },
                { "be", "75ec69b9563558c92f72f4a36232e62ae0472d78184227f77dc7ce965c3406a16e6fb8cebc24a09b9ab8676f20a05c5d48ef4e32d564ba10e3a50170e9fa9255" },
                { "bg", "5849f08b08023d07a2527de48567cb9632168742f07d59a2d37ec0af277e2e292763573220ac0419544b670adfb732a0021e9061238e7eb5b25583dd81f87bd2" },
                { "br", "d9d500686ba25499ea8f6df10860008ce38759747bad44281a7616606957161000a2a1c0a1ec4559b323292c41f53bb94c0ba4d81115a67641a68c0a6c8ae5cd" },
                { "ca", "c6e44aa2431c0bcaf259e86fea51e9c2380b0bc38772bd9fdcfead845fc42bd24ce6028979aad780a87df8c28e6443bbaa696db7bcba8ca95ee2ce213c7da83a" },
                { "cak", "474758704611333973be3f57ca49c49b5c1eccaf4f4f8631b78ce7b5c55599338e5ddf18d8ee2a16a8721dbf95cdbff2bf31217091eaa3deba8bc5ae96be8159" },
                { "cs", "1b163ba50df80369de5ab47a1ead997a3c078001e64d060f8e79da8ffdfd0d5d639dd02b6f0102115ee94b6a69724ff121e3a2ecb18bf4f69ea873b6147817cd" },
                { "cy", "e0790e9d464921031d0a348a6c146091f87726f9c6b2a6cabf8bede881e95474d4df05e01b3e85a89b7105e007e3af1f204aa6bd9646e1fce4e2bfb9d5d2c750" },
                { "da", "c902366f577cd1d4bfcb073d3fe4c64e899027c098cd3d1a372d4fdd2dcbc44f466fea5dfda6e99319e4180d7feecca7a35f11019fe4d6bf43816ec4fd05557e" },
                { "de", "f07d924fdb2038d636e0f331e01c188523a593e92688d68480bfbe548ddb7b3def3d83369ada72bc28ce8c52ac3494dde0339a3ab6be5706559b62ecb4d6b679" },
                { "dsb", "66f1e64f70ef78cce193831032b8a05573494337adec72d693aa70fab2b61e95dd623db42604e32979be15108c07f7fe26d5f814313239eef98844a7c9e9bbb8" },
                { "el", "b0b6a6a449cbc8ac0fe6b36e8b189249020adf2da49cf5eb6c8a5bde83922cf668ba66589d5d67a1134e8b24f379631559baf842c68d333bf28e8ab4296ae83c" },
                { "en-CA", "670c4624e166e9939701f4761e3a5f33c878ba9bc5d0cad1514d37805abd8ded43b34834674ffad90f2f37e8e984a3df79776dc527461c11ef9d228ffbc8e7e8" },
                { "en-GB", "70a93e2436db3a179f10c8a6654ee445bfa5e22776cb4ece6a44cd86a510f7e39089260452b4e62c7ef825e221a92b3c5f3a74b3726fccc0bcad753d06ea64da" },
                { "en-US", "43092df40d326594546b676ab89a850176743ae8db15d6e977e7e4b3cade14c3fe674511b642bf9b9434f93a6bf9b50128ee7340554d934d1a7705335fabee53" },
                { "es-AR", "39154521e9cd903df6e77c72c27c206da3401c6ae9376a23a4c38c580ec56ae4450985ed7a3d912ec16757216bb139a22f7eb2def84cd0ca531ba08e3bed24dc" },
                { "es-ES", "3da4dbb26b3e7254b8e7a8397f5a6f2556f8ba00763dca4e9c2f6844e75490811f04e13f45f41f41025438074dd6f3f398a6add3ab84dc7b9751d0c38e7e71ed" },
                { "es-MX", "d4936e6fcd928fc4dc3c3bb9f8cac990939efda59d91fb7294aeeaad4d65d0efd2a0fb9c5bef3c592a26012a90c3e34c517763ebac85697b748f3e0ad3f75467" },
                { "et", "ace81fd298be352caadd88e9330bb983142286da31157dafa7a0aad243b1faf5b07834d728c3a6141e221fed2cccc9b92095a1fa30835a082af7d9ea0ab8a4bf" },
                { "eu", "2a3e2c9fd58d7633d24cd16d8d1032a6af498ec218c6d7b777e5cdd1686a700ea256f53e0723e3142959d37efbab529677c7d793875fa125a34dece318d91e95" },
                { "fi", "45cc04944d95503abf1e31d999185b521e07f69a91d3fa1f1cc1ca87cc987d85d9beaf078a61913e6ecf0a73a0e15071b12f4210a63658b88ec13fec8392954f" },
                { "fr", "ae4b4703e7d9717f80aa3ebad8dba97d8e085faa9427c557610f7b9cc9515f43e1f00cb1e041006f6305cf5b6e3eeacec9d36ff2805aa3ae839e9b5dd4a8123f" },
                { "fy-NL", "4624a28a0a7ffb8f3f83e10657adcf5d2b1367fa497c79ab0cd0c3d4374b4d30c85d3060106a61275ca9ac659bc6158a630670d044710a0bc9f3696c87c6cf3f" },
                { "ga-IE", "e3b575c00ac8fcfc21050c475d6c9e8a850d96d3642cd6debe30c997ba1a2f96fe6437a07a68e6194bd0eda8c436359c0513849def9d1d5bfcd3863d2aa4d0a1" },
                { "gd", "761a103db0b3609dd1ecd6da858ca0265dccfdb82de577793deddd76af5438afaedc2b0e44544fc3e210e10b358130f6f68c275aa604406e7b49626029464db0" },
                { "gl", "dd442e601ff108f349a9f1d8c986a03b5189693dd92c0832a4746f299a8119eb9bb1ee7aa05c9145590b39de7ababa41622b2b659be4b8913a3dca34866c9bfa" },
                { "he", "c3ed3ea8a9ce6adb87209520cfd49dc76fdef8c693abfcf2debc9851e1a3f55601e83e7fde20ddd58d46c440d2af2350a3353844145cd354771cce75eaf15632" },
                { "hr", "dc7073b10f3c5225b55ca386907f263df5cc5e2769bc0b9600c5046e994a66cf9b45a34e9a0268d76975d76b4520b80068b31a4063a68811cf1cece53e573a33" },
                { "hsb", "e367160404510849fb5b461ac07c53f80b3e2f1f9b0653258a68074db5f81b87d5f4839bdb3a864e1a55f2e91f34c4fb0760764901b29e86c9d122b83fe2f07a" },
                { "hu", "db92af47ed53d49d4abeefd158b06c2c8fc0fdcdee23b4f6f74e34f8c9aeeccae9a2e5a82e9d26a12069409041e9416c3cc50be15d88c9deb32c9b916fc348f3" },
                { "hy-AM", "1dcac5c8a67e1a6abb2aba181f1c8729091bf5272a83dd457d017c14ca2f0a7281f7f9fc28cf5ee90a610f6b0af2791aa542035f747fed59ca2ebf98b48ae6ae" },
                { "id", "2cb7093bc321aa8f856c43b5ea4bbaa21ed062e1c3f74dd51b5eb0afdc06a198f16a1a290c7e658f533acfb3a48454e849e1431b7b7d700f5255b108aa7b587a" },
                { "is", "49a484558730ad83421245bf68cced3a9fc6effd0058b82dbc62024314f3977c2b04da098ace71b0982e15bbd68aa26aea9d5d1f85b8e3c1f25d516a5d60a435" },
                { "it", "48cf16927665f3b2852e7cc02600440285d42784511db078b3c26943e1565c42b29fab5098f15242d31b91af0a3f0bb592faedd52873d06bb879ffe141cd1cd4" },
                { "ja", "d0ef6024b258a0a3111f9b16bed1a916a5b46b1f4c1dc4fd06ac92b5532e40963030eea626407c5ce262d87dfdcc7f77e964146ca975b228a84e74ac32c1099c" },
                { "ka", "ba395c35d9a66ddc8c4879f4ed0658bfe3e7822d3f9e82bbaf1c9420d3e4701b6e90928e891105dbcf266d0ddd2987d279ffd9c02a4b560596ca7f1ff00ff614" },
                { "kab", "921c22d8ce196ec7847c544d58020e6a5a475a3460f913dc59f985191227169f3b725ed9ac51b14402f2334f5e5c715b28314a5471f64fe5a09969171957f0f7" },
                { "kk", "1b988b456085ce434f0b1429627c12dac26327d3f1e9f7a9d3e8d86332baeba68f5c0c39ec520c05e8925b870db8317deffb38e96859382903f75559edc84fb6" },
                { "ko", "f34aa7946c6c7680448f42ed9919a6016a752dd0538c49c3d9ebfb20ed0d55e3f2543f4175b8e5ea9b65827efe9199e41d5ecc8e2af5a4fdbddb3834123b4190" },
                { "lt", "a6af53619b7de34c03d442c495a86307ae3c309a23bda516ac8d8c0f820bc92d330f789ed02d4d49ed308048fd0f78171a81ebd7c48339a6457e2fb12e9fb752" },
                { "lv", "99bb65783fb4c2218abf3f1c85013191aebe7e53b7f2f7da038a1284b2156f521c36808b9c34d1f25308515f025b6363d9ce0e6eea8476f6e8157e27b1c283c2" },
                { "ms", "fa9201dfb0f7f47f40d9166440704aadd7f225272a90abadec8ed540026bb67fa6f69ef711f010b3fc11a7fddd884ffa957359f5719d039058217650aabac6e0" },
                { "nb-NO", "6313a20ecce7b63b6090bddbcd9abf42de2233f04c3639922d7df691e272e038f53a7fe6768c1c527b4df26bdf4b89335d8ba94132e2f8334520870e66423a7a" },
                { "nl", "6e3279c362c02141c56522f9deced3b53ac69e90215ff2d6afa218fd7a19bfddf56d4364600e0ae19c120773342d88da26cf81d5d9fac136927505a29a0995e9" },
                { "nn-NO", "751cc458ed3212560f4d2e77ed33661d59a57fc8b820b030ca51e3c0e60d3cfbe677e3a0299d2d99159b4069fabfee861c0315410f672d3968526c37b8486d35" },
                { "pa-IN", "cc7f07436dbfa165dd63435b488351da36eee84acba05d027fee191e858b7f9d117d75219310a7edad7941775d5692462e551a8c894217a17f276994c831f697" },
                { "pl", "ad10852d5d5c3524da40ac9c297dc94a6e60e72a9fe97b333103997561c78d1ac291b1ce1844c1a4f3bf597ad5552b83748315e9915a8174df4b031dcaff93c1" },
                { "pt-BR", "5872e716f8eb492334aa9d704c7df3ad57e8e6950c28c1f64a8ff89e28fdc7fc518cfb1d3128e556258642b567f3f9a18f7c5dc65ae549aef6256b22adbd97e0" },
                { "pt-PT", "defd3c1161cef2d2262624c0386fe2797160fb1696d7d85a8fb210dca6e6f71f66688bf8320e334429bc027b2d9c23ce9ca468f09342d5fcb34197c8b11ccadf" },
                { "rm", "32a5e8a17cf915f5adf20b9995038731bcbc9053b35654a3b52fe01aa589e416ee6e35dfcbfb78af661331664f6899ddc70907a38c178c0bbb12ea37493144dd" },
                { "ro", "1fc1dfdbc5c90d5e27b84da0b5de96b747682490a21336ecde42ef567ee716219abf785d2818e102b2576873ab7ce7b24c61cb44248d7470b49172a117d825f2" },
                { "ru", "576e97631d41384d6046b855d4ed66bde9f69c9c0c5ed76496a6d0d9aee1c882dcf0e3a2b19542a0777731a315152fbbe6dbbbcdced0fd87e84a45d6b6076066" },
                { "sk", "14fa4f6a735715aab94e801e4576be001b94668f71e6c487e6289b77a3b0f2e3e18146de4ec5b7be95f14eb776182ab37ab649e123d9fccf9417444d94b96101" },
                { "sl", "65aa667aa3186f2ffce8de181c20ad91d861e1be7711e44e08b0e63de956a4c0f1a99a4d6acdcc546bd08361eba5b5f35c65ce54d16c64dd765c9917ebc248c3" },
                { "sq", "a4149c0be4eb62c89ba8d7e186538807d8ba7eea3717966065adf92a5205e0edff8639fb4ab120f3ba920486140efef3052d62c14cc8d86efabfd9317e346fa4" },
                { "sr", "15f9e029318df6384e4d120aa9850cb395f79de7d476bb596d1531f6895c5532cb30a74f059c56ceb6f51e771bec1e4eda031a0e76070c1a803bd589be98fc62" },
                { "sv-SE", "681c5fa6ede6dcca716f108bf55d4f22429c78543915c6cb185f2dc4cc959719fe1a9010385e5b4885bd68aacbedc4d0df9fb651c3cb445f2123639b422843f0" },
                { "th", "b4a204232b4677dfa738b45cc5299dbfe8b2519fe937e87430d669ca72b1c56df60fc8ba97864e79d23b60b5d72ca1e1541f74cc9b9dbdf280ef690ae35ddb47" },
                { "tr", "4827b06fedaea4ea2787b1b46e197a4d72cec6b1330a203a04d744ed0fd89965fc89e057b84c2803607ed85840fa53a44665730212e2295b335b3f2e22ee8a97" },
                { "uk", "31f61d1ec4a923645b8934ae88602b6a0a3fce16eac46b4efbab54ce3065584cdea993c543d46b6140f932088fea82de0d4c3e664798577a990557867f162f46" },
                { "uz", "06b6a6dddce464df4a8228e56d6138e6a41523f7ab51a6740502018332567f2f7307cc38edfa81be49c2aac2e486716646011836a4f2e3ea94dd724feb4b153e" },
                { "vi", "a86498ca833e22e61cb0ac5ff1959009320508f9294a0629f72b776dc6429b87f51d2e749dc4f8ae511b342ecd3b8ac45940fd7cea08c90eac6b39098604dc96" },
                { "zh-CN", "b923be2a1268ff0560be5099fe6c2db472d2f0c2ef550000c4dbee7acf058c987b93bd4d2d030e43aaadb8de424e766c3bd48a67fc4514c2d0f3dddcf72cbd2b" },
                { "zh-TW", "73c9181827ff944b1f3f8f1166cad00e1946e3c8521232ab4a397a0870ab292acc8f8a422fad2f9fe58fca31c8f6d37f38e582f3d51dae0a19c4638c0e4f0b3a" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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
