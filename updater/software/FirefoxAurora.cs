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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "123.0b9";

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
            // https://ftp.mozilla.org/pub/devedition/releases/123.0b9/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "1589a674639973fe496e1df4f6a63b2f1cd7b06ce0b76aa9ab23b820b971de4dea03a6f2730b2e6ccdf9f4b0a0edc70f68d20964f3a39cb843264aa68a7b12e2" },
                { "af", "6febbdec4acb451c2837220a725460668567f25c3cdd877e4eea09952cb99f43041eb488bbbe282a48607bb273aaff62d5177e6367d708e29e82c30fa049cdb4" },
                { "an", "5cfde58e03916633f3fa7b2056b7b4804515d711180d26c0c1389ce74860244e073c9d5916606c375f0cf8042e3a141bf9be4779ce5bf1ca19ec75c910481100" },
                { "ar", "8fb8c335910987c721b4cd17df50aebe11636cee90d6c49df171fce1b200d9c4ee46754753e3f10a388a6340bc0dc213267459d10b7497f6e5bf93f88ff8684e" },
                { "ast", "a698b67fc02e98a1b258a8b905643747e47cd8de9667635795ecd361c076024c272559094b3f594393224509c0e1cbeb783f8797c19f4f1d2d5a0fd0bd09c761" },
                { "az", "b1f1d1110551bfaf348f3b7e62fa8d523da092f4da053383a7c53a0cf234699e8ce7fee362236ce923ef92eda400062296aa7f520652e0da5cf6dd9a99cb259e" },
                { "be", "891bdb37bbf6532304cba014b208485675fdf1b6404f8e7673dc7adaa60eb8e8923b0ef39faef0ebacfddb4a4545bf26f738cc51cb34b5112734c9ba9b833b29" },
                { "bg", "6e49bf03da9add852827979f76aa8d45223e4ba042278225a43cb950fc541eb61e2618e46974b91148d266d1107d3b515b7e7d99b782e4990a9a752a89720faa" },
                { "bn", "664d7ea1f49e85a78c9547e7b569f59d715b52f3c81631e5b1c77d9ed6e9c39052d036e3086a9e9bc677b6ce7ec3d154f2fce4f0b5f5f00c6a4b4fa2a19eeb39" },
                { "br", "b99a96dcfac3c1501e33fa63b35f24b313d814d35d1f56a24cfd97e69428344bbd8e8987151fbc642726498bd251cccfd503f04abdb73eace63eed80a729ce4b" },
                { "bs", "f62ba463c807a68f1762446253e30103097f312ba70e41e28898c6a12c630dbc9085c1e20a21728c07d0795e24f01eb1e28889437dc504254d777f748c368560" },
                { "ca", "00560730e543faf5a436eb9327d1319910a554b9853feafd6e3250ed9b6de88b4c7f0993e30385e220f79d3bb0bb0b03c8f4780d11fce244e29cb356578219c7" },
                { "cak", "6f64fd59e2eeefb653ce2cba3a611a536de665d9e88f21807c962620cf33c4941ec7c6f1e3b9ca23c19cbd8d2e19939522e71237bbce1164e7f47b5ea958ae6f" },
                { "cs", "75eeaf3034b5de7888e228a64afe4c4ba014f5ed9a30bd95f43b4b171871223d9aaa0c172407506ccc32bb4f92a73142847a732d17622c6aa878054faf166d2d" },
                { "cy", "48d929288d6ed996be601a1e4b13c4e98b921cfd7bd66586ba567498d9eead2b0e463f753c28a55adc7c97cda1239984ec2303b4679b6e7551d63eb4f15f5bf3" },
                { "da", "69ff908dcc07409989ce3931d0e119870949382c6f27d0097fe126dd6da01bf73a3a5aac4d9e6298b99424b1a2e351bbf207b664a8215e42766e4b617cb53443" },
                { "de", "c1ab47472bcb78aa92bca27ad667bd778acfd28f4976890aab78881c32c36e7ac35635017573257cfbfb95220e74f7f7a3ab85460b737827a4f3c6256c42e856" },
                { "dsb", "05efbcdee371bf20e847f9f7e579046095e0ad3255c424b445701f67bcf53d8e8f21f8ba39a16f7af1ba69ab6355db6121c0ddfa88f5637c64af8db8881591b7" },
                { "el", "ece42e5b4dc8e6e6adf7e926fcd0267f82a3209e27efb83cfab8f7a68c007b3454c6e716d8cde72eb0a189de3bc2787db4042650772a213ff0e3f0217672e69e" },
                { "en-CA", "bf9d9002400a8eb2bf727655c8bd209ce4b85e18f6487bee812c92ccbc0dd3d32af5a7222f4c4b774d8b26e40d0836af29bfd0fe7e68feababf3eb5bf0c57a58" },
                { "en-GB", "f1d8e3b8a69637c6e13b4ff8733fd3beb1bd7ebc4371d34a80d2d664d3fb5f412e7726fa48bcafbe91af0bc4321b03b211efec2e065f0c28a891e0b0d1ec1cd4" },
                { "en-US", "33f4a2e55c038a72fb0154de4843f09a876a3b32e7ae1ebd4e3053be00e26740756bba34141c2b2029d19afe432b85d1f8d2fc366c1f7a7fcbac6b4a067ff263" },
                { "eo", "b9e92a9089dc2cafedf1951b739042345b6a08ce3dab4ff4e4b2a715a2fb5798bb19ab7e10ef60ef51d4d94b1f28882ff0365f6644e38f056b957c78ffeffcc0" },
                { "es-AR", "81860b552debae19d87b709dab626174332d7c05be7285b249ebf11d03a72c760c620fc4f3f81f8c8e20757f9ec2e8b5bdd3b65cc72d82a5f171742aadac5371" },
                { "es-CL", "7ca1e68741e8284cdcc469ad52e2809c742a3a3b273b48280a521aeac2b7e5ea1b4f4b32745a2ea33df73e658f8064b111ca368d198ff397c5169850d56a0427" },
                { "es-ES", "8fbf8cfcea28c6ad90e7b58bca28c58c798db2eaf5ae001ede81297cee94d58775780c0a3b08958919feafa8bc9bee19e61c69bff7d30ef8392f468a1221ae61" },
                { "es-MX", "1d09e598af8436af9a2473749769d2feb41161a18370fca3026e4dba636568a352d440323aa3662b4615aa8887e6270e5bbc1845d92e140471536a8121e2679d" },
                { "et", "99ec55d8012f1beb96a3a192be3ad599fbad98f53ddbad4ae52dbde80053c8a7d90a42c2834da09960abd8b60b734752291d8143479c28c36d616f28daec5c53" },
                { "eu", "240ca918186a9f62217d2f41556e9a8fc5cc82c938d00aaca98aab50849c00c0deb0198a70c83e0804f4b40ca4d35d2f7654a37935cd234f132e5355611145ca" },
                { "fa", "83ff49f2735eca2c577e9d55105ccb994b5e029c4a581daf7fc4d20bd176fb1c979523857b984453cd028236527bcf3d63399c66b393e012147a7cf9a721709e" },
                { "ff", "4b20de7b4c9952fbe70f9dbb6dccde7d4f674285788fff8eb02267de859c3ab0b1a808c562d8ff01faffed417f538e8db9f648bd22beab9b3ed8653095fa25e5" },
                { "fi", "f62acbfc9e50a1857eec6641c9827702812aa299a299db8513e084ef82ddaccb14741c4982fe04cc742ee7a5f184ac445dcff0ebe00b1ed2effc07800e8fb1ff" },
                { "fr", "bcd2bf60cd668d8e2c7a66c13c5be5dacba38d973113c8e30bfecb9e9b98839d87049681684ea16830c14df2ace84fd46a54d206cbea5c411b3ea52537126a41" },
                { "fur", "fed14c76ad681634c0a5977e88c164f66e99a4fade9ffdcfacf9bcfa4af911d548f713723dcb873f89e5feca4018917eceb88189a3a3f22d6b90a3c1fbf55645" },
                { "fy-NL", "a7f19faadae05454e8ea4c25381221299e8abe900a9cfe5251ae517e43c30f88e362541eb6c95d4ddf769eb308016d57c1afe1e410695bdd0c8b89c240dce563" },
                { "ga-IE", "63afd02d064283e205b6a5981a050eff6ed4730f74da924d4109f06438dc8893728fa26ae293606c5cfabe94d0fae395c963b644dfca9e75cee613999265e37f" },
                { "gd", "b7d4e7cf23aa6b7e542f4e68ca27799b8d7948bf931bd37c8e80b5f878979e3d0208d3858aba4e2a91e210d190511f6bff4901a3fbf291f1259ad127976560ae" },
                { "gl", "621b4df550a0b955a8edbdd7865b4064b726763e50ff4438a9d45182a72bffc5da39fe63b16bf45f6da559b42f3e07ffd52ec7187a3092ca8483ebed90e3e9d2" },
                { "gn", "7535ad0a611e4413db78dde98384d4ee372962136fda651e4fe350c7b046b8d8b22b3f37342be55cf66781afc61aa85ed548061393e08097a5642d0538e55bbf" },
                { "gu-IN", "1334e7ed0e2b0fdc0d1d3188f82466cc8f0a745c7cb987ce3ca7978d9a097cac1f658422eed71441a717bf16d361bf23ab68f471cd401e2719d9a72de0e93eab" },
                { "he", "e8a8454284a792b68ea1729154bc53a55f58cb963c56eafcec804bd7e2be49ea01fb1c98ea06c1a3c618dbacbe8b2dd30ba8bcbd539baf848e155bcd9daccccf" },
                { "hi-IN", "1737dd94e918b3a96a1f6a7e6e12909a92411987f9a16084d42378d458728bb24a1c2b01f4d3a7aae7e1e64425a6e4f1363aef49d088dec066e12542d15d8b23" },
                { "hr", "451c45b137f3689e3008de590e78e98f33cbe04c2d7cff911dc48791bb34c879332954c8a554f8bb537c0d2b25356bbbe8fdad2ec30e04ebd9774d95570354ed" },
                { "hsb", "68581b8e63baf53d80f1aa8ed0bdbd92ee6c8fa332b06d16948865770430bb8b667eef1e7b0b20ba933906600d1bbc4110bf976e067be52108b2e0cc81c8bf21" },
                { "hu", "cb6ac7d69a33e2a4c441f4dbc6bca8f5063754969e03a9cd88ed579a7f01b261e6f077fedef0c14f15328c4da384b1dd70b8806e70e87113b9129f524a98745b" },
                { "hy-AM", "ddeeca6bf00d56b87ebe684a6ee48d788d3934ac055fafefed47b6d92a0c183625837761cabb56e5f5ad93594179d1487c52555107aaaf6ddad259f67ba76b4f" },
                { "ia", "b1ddebd3a977054de093bf510900ba062d3aee0ae0ba5afb01cab53ba218dfa78fe9bb101b6d426c457517fdfaf82ad3a3819a0244a233bdd54da2b7a7bb4fdc" },
                { "id", "d03784a6723ac78440843b095fd63da7983ad11dd19a8fb53a4ec536ab6e08e5937e710c24735f605513c7df5d6cadb77467ee3aa57c776f091acfea4a1d0ae5" },
                { "is", "72bbcb6e09c45129eea4735c72e9bfc29b8ff757112e8a5e33ba829c0cb515b22f1ab0d75af07be8cd17e301b92d14e8d58bff36c6e31ea1b005cf04419083d3" },
                { "it", "49baa33016c4a8be8bd09139560777eca4a0ba865851cf8ef0a387af26dc83c15890df5fcc212657c7d4ee83c127340cbb71e39e78693dbff1d2e3158990eea1" },
                { "ja", "3f5e6d12b59726b946b0ce4c1e41ca91e306ab351aecb3d83f9f709139d31ab47ba73c4dee258df16b10b4d49aa8302cbb7148a9dc05f3e6b26110371457ac6d" },
                { "ka", "4de135cbaf736189815c3d81323275c24f0b7e0df68f392f0bf98f9304542d069b5561cf9bfbf2e6effab482d4a7e263db5ccaf2e79801e52f0da3d6376711ae" },
                { "kab", "5d679dd30da62b1a0c483bf52b58fb5debdaa0d357061c47689901b6ca3b199378617e2b1fdf0f3081a1c505c7a83a14f643659121b13676eda6baf3bf2736a5" },
                { "kk", "5f453884b1683bb97dd33fcd27beb0cfa8025b6bf0f755391259057a0ff4054defce8e7a3888c7c9d4e02442e7eb38282e5a459b9aefa44dc42e5e8b8b36e529" },
                { "km", "2632c796bbb307ef8ca99d06bf71d21b3dd8ec34a2bb95207c165729cc88b79d2976b91b8f7f9ba6beb2f2d566bc8e47fe30203dd70cda577a8ece975fb1ac1b" },
                { "kn", "47d92da17dff12a282e170866c748a28d2417837165971db2634aabb309eb3b2dd208915ff69d7bf50e23c4d6135b518e08544ca42354467e56f467c18f3a7b9" },
                { "ko", "90fc014bda5291458a11346f755afe1bb83e838041c79bb365111c18bf76d6f6bebe164d575bbfaf3960c618051ee33363d715b11cf041f4b4df64ed15f2cacd" },
                { "lij", "f15377dec5e2a79916f56909eda96448b393559c8156ea1036186f1207647555746f82c68ee3bb53db3ab707e722963a12aa339489aebc18c8a644c7e3722d22" },
                { "lt", "fe6f4fdf3865146e80abc07d7cd37ae52795e13b60c0009d6d5d537ae9b08b6b8ddf1f8daa8e0c23b17ebb8f127b72c53bcdd716241338be399ccab74c2f1347" },
                { "lv", "12232925c687997457dbde70853c01c57db8ae8471cc8488bc33dc5d57d9bdc1e7b9d46251d2ca219c13df87472ed22a9a13cd96e2f2c395c6ea33da7cbc2782" },
                { "mk", "18c42f5c3164e98dbe227d8ac246837374c61e3f88980bfc9e873fe09f590d0667acbfec538f213436bd9066dc9c89f9c11ec7e886999565afd23f149bcf32b1" },
                { "mr", "bdf7b423ae625a193933a1a120edef014d609ce1c8e724161f24725c40b35a70844e54b5094e5a1f7699e781953dfffd9f7e77f21348d769eb562de232245949" },
                { "ms", "4139f1ae3d5256c678cbfdd98470f8063c4b6a15c51fc3a6fc6e72c6f5f0cb33d31022a65ac8715fdb0628b8330ed5e08f728f0d180e33df38481fe081693be1" },
                { "my", "b02ea907819fd1f1b1b92124edc532f0d8ce0c5880e304f601309bc0926333de60c3c83df3bbce3931f6f69d8a5d2aa0595772c7f2f3401e27e0213f1931b890" },
                { "nb-NO", "52ab9d27ab0003d8fe3683f2b9d48e51285722816f688b8a11a11bbdf44f92af354a2bfe27a3d4251c8457b9e1b20fae0cecf46a2945026ab18661bee37e4420" },
                { "ne-NP", "debbcf07d97d3f49cf235a2c12ad0ba480902539a701c4d8feb02d94e09b69be06c193c0dd944d290ffb2e6b4c4a220a20ddc46cacbd9ad3a2dc0ecb75fbacdd" },
                { "nl", "f519819edd343f823cfe469b0da0ae1a1399ef52935b307de524d56730f1f5718a7f811cc24e0bfac2f857d4fd60ff2081eb61870bcc596f1dea6899690d4296" },
                { "nn-NO", "150d9a7a021ebfbc64b4421425eb528aa77f16b4770930f9a0abed3d7dd0c39123e88968ae7fef1cc50a6051582dfedf0cd340d7ede1df0b356d83b1f689614b" },
                { "oc", "f03f5973a18232d4da7bc7f76fd9271ac0039e1cd5fb654547c5f00b6931f131f9dd1b3aa10a279abd2892ec95dc65faee23c1cc8b4a7312f3087ee43d312ce2" },
                { "pa-IN", "3526a3d13a219ff8e2dbf9dc29a4acb248001fb4881997ed497660387a0f11657f41ccd105298d69f7aca55b4145ae99562403ced808d866c28c9a3316fc9aa3" },
                { "pl", "1325cf3d141edb8cab4a1863a1680cd4d028c131559f876fa5ef7f2306fa002662ee460b601ba49faf91b89956130e55134746bf95387df948c84cad3457a6a6" },
                { "pt-BR", "6e1f4ea92bcb33414d808efca3629e47d02c97e0c7a8181ab950a4434022202ea600fb2e6bbf196c77c92775c75c65ebd11d92df763fdf0ba0f7da2db49c1c9d" },
                { "pt-PT", "d692ce5c431ad9ecdd1ffd855fc56de066a6ca9e1d4cd79a6c5d51c93d4d2091a3fab41e0815822081fb1ca38c77df3e95779de6fb564467eeb807e8175c164b" },
                { "rm", "7037301e0a0f9ec753bd4bee87bd0ec82417ce1986c6463c4e533714981d27f7717f998ac422f90bda28157f5caf134b45c617a019460155aa03457e284aad62" },
                { "ro", "ecb7028631aa96356153f10093729dcb95c5e3da22e2034ab929ab814dda4fb239136f4cc89d4eae1dbb63fde60022701558694f2546dc927fbdb6197a63712f" },
                { "ru", "c3376326386e029319c850c6b3d8ee53f411b84efc910a48676a276d54a3886c3a0c523d2e0c5a9af6ff66518b049e57792a205fa66beac2fb5e3c9241fb20cb" },
                { "sat", "504a1acf703537ad6d18d477ddc7fb9c57e18586067cf1992af63315445904912f947958c72a8067a564af4684519c9b774cb2a6982fd2cce04f72dcf606121a" },
                { "sc", "081fed9c0cfcdef6f4f256d76231d16e7cbd380ef497a8c918d17ff143499e62868bea8784bab7e6c17d843d21022bfd64605cd100ef7c780eda7fec7b163a46" },
                { "sco", "7cc1128d7495616557ff633ce9d1d7584a4ef336cfe83a6a06d242be622728b357e188119d9582e329a73fd87d99aedf8e3d2bd510afb3e19e2af7e162d02b40" },
                { "si", "6f6a376053de054894d63e9de9d683bc814db2dea28b1723e6cab055df2283e119227e076257648f312ba69b12acbe1ceed543249f54fb36f9285e0fcdb667d7" },
                { "sk", "09901c4d92016330e148a5e85abf503b38b7e453e47c7ecad2618b0dd5cf6c6b2b7de6eb42c27655393df3cfddc248b1dd002f42e01b3b1c566bf6b2522fa371" },
                { "sl", "a070bc495931d969b750a0ec0d941f93f73442fd139687a849caca73fc4802fbeb7318267201b4efc60c9df8758ed124755c4e958f14f13711452129a9d498f3" },
                { "son", "3ffafd13ab168e62b3e146069bd8f420404ef8fe4f9d748d10839bb7f94af1ca7acf790bf6bc1e6376391dc8c8dca882fe79def8f8d5e022c1beba2f14909d3c" },
                { "sq", "470eb4914bfbfe8490cee458ee4a7ed7c1021b59500ab2446330b5b97fa1e25fb1704ca3660038d638c0ba6b7baa6130195c70dacb401af6c1c9d5e10702f2d5" },
                { "sr", "3a8c135c8d1e4de4d3c41612519f725c1dd24102ef0f20a37fe38aa5706525eba6b422d2383af51dd0b15494accc189e8471c71405e4e666b9a251bb11972aac" },
                { "sv-SE", "88c2cd79b96fcb45c3b3325fd8da870ba09fa815ceadee159985d14caa895658937592a3392984a586ccb51675a57e5d24b53a94f94ae8ee7ac29594134fa136" },
                { "szl", "1d5270d0ffd2e820800d748c57a12d8079dc817da1551461f4fef10ee8751ed7707cabf38e1283330dd02157fb58017a13ef86e15377b979b9f4f0d28097cfad" },
                { "ta", "a0f05b452ecb2dafa71231fbe181e1dc1ae73f06fe2279c8cf77ed11a5c0c42385610a718a63ff9a2d1d1b86ca7db6362f1940e271945170825498ac051d7d89" },
                { "te", "233f7a14285555c83fa416ff7590846a582b6ae7525e1ceb76bdcbbd64c580874b7b7a87ecda567f6faeb5f974cad3a062ceb538b1cd35ab319d1a7cf71a6bd4" },
                { "tg", "950497fa57e0a643af9ff936c4059be0f39d447ab2adbf64c477332d54f85de072a1439111ccc7523e9d81937959eb0397fb50774443179fbfa44bb2d25f8b83" },
                { "th", "957992faa3fd90334add5c308185287d49588f104cc258637e6c4e35ba299ee6b04e6e11a34c94093fbdecf9559543fc5ea5aa020ff8c4de29cb655992d55111" },
                { "tl", "1c4d63279cd5938afd0265457737892534b37caa47f0658df95eb1f982eaac1a910a4ee65b9130e4b7b8264b43a117980c4b91911582fec81f7188bf3c5a00c4" },
                { "tr", "a4f0017f93484e794e18e2ca9699d1df0a70f573e544a00a58ab1907980d49cac68e52b53d449ba98486b6f772380a06abddfbdef4eca6f1b5fb47782d339a63" },
                { "trs", "54746a24e9a5832817b4ca8404325a5a00775b36cebf77450c52ffc788987e55182f182d65565b170cd7706c6efe3560e0d6a1cd6cb00355e0742b779812848e" },
                { "uk", "4dda4c57a8750a792fa1fcbb95b360acb882f9bc87e1bce3f1a7dee77283e9c6cb2329e7676ef2744cd549a5e846f28c0e85a45e1b0336c011f54d44e5d4bd04" },
                { "ur", "e1221e5b5266b180076451db486a063b28c2da4db4bee9857d495c1f74d560b8fc1283c313aba03adc645c7732660e65b87d57ced7c99b7ed4704fa16cb8b51b" },
                { "uz", "73c5ce9c7c7d5f417b6b384060945e47352bd6a85a97c09ce92eda4396959522ac8bdfc275adc839b5fa5d6bc8d4e823bd629942223f4d000aacfd2f57373197" },
                { "vi", "d5b4011a887fa53ab8fe747b52ee0754bace307d768c3f526fc654b847060bc337f2ec784597aae3775ef5113d15743d82e7e714a5951df289d2ad920a377bca" },
                { "xh", "d340c566fa0d4d6c1ba33f17719b5a8d81159a3bfb4504ff322fbe4b05dbcf155c764bb46ce35978e91213ee32210e2a9af62f2a51d54b912702b4fa703dd43f" },
                { "zh-CN", "0fa885bc3854234dddb02dd291b41a6a80f499ab8fd210cb3320f1bb08cd7deb7b1bb9e536eabd95785cc1144f06db05cb13ff196b200539ce50c9fcad86ebff" },
                { "zh-TW", "81215b1be489dfc1fcb46e405ea7306ecf655e59b52b7aa7595f85ad70f55ac508b751ffab5a07712a9188c1964b2ff4dca073b7e80e047023e0b4d23ad23bc1" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/123.0b9/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "2e0d948c5ff4df245dce540aa0c0f93f1c8e85d9a5be2b03a923555b68f9c648bae3b3ebfcbf5eb93e0c0554b073d708e5e02db2189fe3b1a26b24f0d536ff90" },
                { "af", "65d82e02e5a27c9aff158a6ae848ff0a2de18b5b2a62d078b1872044156284856c24c59cb189ee5382d164bc0b166251efcfcfda0b36cc18215166e8b6585d80" },
                { "an", "b8c4d7e09e27861869d2b68859772da91796f01873dbcabfdd03eb6be58a315eafd70d861d166ae73943aa7377f9f895379d5676e6d2763ab463c5ebdad935f3" },
                { "ar", "40b3ceb59562c7a82e7cb762ae27fcf9143050eb11dca3ec45c5f25c9bad4a690f66c4d53581ef931b56c510a2028ebc056eff37a7ff290ff1db370b9eab8386" },
                { "ast", "f66ddb7375415fde7900fbe02a90260c4586dbdcf5206dfb5f5b57651693be7ca3559aa61e558fcffeb83161ea873f840e75d6f1cc4bb6e10e775fa58da0b009" },
                { "az", "aec1ccf4895d5f8ca41d48966ccfbb7e3911ba3ae69e96ae9981c9577279c6560d943456720a82cea5bc5b21e9c4168a65058678d1f6cdf99f052c69eb69731c" },
                { "be", "dd490f56b749fa50f57603cf03a50f6e776eec46c65bc2d1c00670cbcdc9ae55b7cc4fb12985709728c996b89f24d6b4eb54aa0b7399c298ddecfde540f7370b" },
                { "bg", "1630039592bdc7937b744bbbbd9e078bdb02602a9c31edb52e2fef8a00707d9270a43a90a0db57fa78547dd34276d8f15b312f44f1c30a5ea431581b39119826" },
                { "bn", "4b4ac616b457b52c95f7d293e1eff9f49c9db069a991bc41cafa29facdf1ca7a602859c49d447636625f44dc9bdc64c3aec848d1523bdc0a5fb666a314a301b8" },
                { "br", "60449f74ebf105e51672dcca8db62c2da9a9caf7ec90f9a3c65372b12e913a0bcc3aaeae719f877f8e3deb5e13cf14cc1d5e1b04da81c86c0298574df054be78" },
                { "bs", "5104b63b238c8c9e3df5171a4fd51a3b3a354df9879ac2addd559bc6234492a2fbb3ae1c3649c0cd00ca52f78fb6de9ac63f06425e976918b90a7e249edf4494" },
                { "ca", "ba977085360a50e4adfbc9ae6e71e939b52bdd3c856389fa5fe613336def2fe2106793fcc7b804fe96e7f4ed8dcc2cdcf4621c10e88e367932799220596fb3a3" },
                { "cak", "9f5f4047f3a5c6bef2682267c5bd95cb2ed3cfc18435151535cd49cdcac153d5b290215648edff71464f06cbff477cc86642bddafdfab01ad6017a544bea41c9" },
                { "cs", "19dc6ab49b176ecd1e1887a494a6b79127836bdcf3c39e8631f43dd8394dd214973331d83213c5f1646c2da7582098bede55029c3927a3982bcc2539ab93fcbd" },
                { "cy", "ea307b00c62bbb7b8f97353c82292fc3f2f3fae991e90f55e400fe0e8da41d3d3e575c1e05fa7c13fa52fab4c0c6a4e4aa9b27756aab9b67ac2db359369c68d8" },
                { "da", "808b13404916087c615303227acc00a809fc67c6ac971c7ff6325cb5f41ffb781d6e19f5b275d9e1c907b67b5c4fbdc88bfc2f1538011f19b8e8e29913cc2fed" },
                { "de", "7007bcee6dc1fa163bfc0e596fa5524bbd36ed221e233c8783a892c1bcde9b56bd4dd79fda778ea5b0f202a3b4add561d120249353f785da17881f471f64e16d" },
                { "dsb", "97aebe6a977776ce95c7db09f765b582bcec8f10d7e7366d9fb13b35faa28c5a50f19fa505e6237ee81d79f237ba8aad81f916ac4e8ac82ef7f0cb15ef90736b" },
                { "el", "b881ce3e095b92ec7b9340f2535e0269f6cb65a02392e2a56566c144e55fb930561d7b537d9a1e866daf53f34a759ed42505e8aaa02837e2c9267d6607aeacfc" },
                { "en-CA", "8fd7443ed75ca63cc22eee48340f14ec60281489fb9d2f0be61359fe67350e2ca4b1a605f24a6e06b3ce3af3e12a214e4d36da3a86032a7829a9f9ad14c5cfce" },
                { "en-GB", "2f7eab9635fc0edcefa1fa5479f118be242e3353ad16a9b342e482065b4f0e532a1e0593f4e37032d94b260722f5d8d3422a4209d385ee90bbda78d68b907e1e" },
                { "en-US", "f7aea67d8e6147b57ca6817b65ff9055c893d15b856f7d529cd26343383a62353ce5d9b8c96960067e58ca8742f3ed2b01d3218b50f2a3e33869793b05687bdb" },
                { "eo", "79477de8c638919e8d720b4f98fcf68676d0d004df6748f75cd499117ee17f4c85fdb682e9730ac19ab18b16e7434220b6d04175f55fbe27b4c866ec2ff3b25d" },
                { "es-AR", "6ac40e0cbf100df9a08ff545bab351ec2411a8efdc36c3f92fed85002f6f400513e05d6de3b86bdf9c873fdb36d426da6faa0060294efbf0f5fd41781be38ac9" },
                { "es-CL", "e84927c473c5dfa3af4b14b507338ddfbb5cfd2d1c6731b299d851647eff6c8b3120313317e13388f7780ff5b0570296b49a766c0642a04a6549f2684f513a4a" },
                { "es-ES", "e51e3f7047bbbd22e51adc7bc0cff265f4ba38a34a24347449c28eba7a7749404f2729e7ce8d7ae8fd8e7ef55e8aa7ec6917a015d61e994363cf2bed2707baeb" },
                { "es-MX", "635cda4b231f355dfe3fe8aaf841e9f959d9f50d592a17f2bf120a0ae7f5a9e8076b4c3e376b1ce09eb190e93afd36bfacd3c9aec960536c2e8989604b8c0929" },
                { "et", "88ef233ef37206e6ef8ee443ad042215774a1175ce51ba10e49bcf1357eec992b00707ffcf767eb692ce6b4ba0b3297b246fd883173fbbe88edeeebe05cc4d71" },
                { "eu", "0c68d3d700ddc4f05895c8df92eb607857d14eb670e06b06edc6799556fc2ccb9077b01d723d5377459485dc05d3208b5a9245ea16c2eba8f929806e1fb14e64" },
                { "fa", "1c73fdc17ebeb632f06e7d8ee800c100ff8e12910e8a8f7cdf517a5744b44254671be64e9e303067d0f3272afccadb0db59444d1b2808a37d55900d6cd42083a" },
                { "ff", "c8c8fad6af326d270f41ba6efbbbdd66047154319ee75c5219ce52d9938a48770949fabff34bc92260e156d95fa834f893909b62ff6429badbdd593a683ce6c1" },
                { "fi", "d2b11ae9b26def527afbd43ea5b97686aa6317be436a9137a5166fd913765281aef972290eee8b698eadf76273a590053baa064f1252f62bea7e378a41c40a3a" },
                { "fr", "c27238f2dd32b259d8039862e2ceeff69df0f429ba1b1249eb282146f9d32f78fca5d4bbc9e1cbdbd2234ef49d1ae189c72c44c0710dda0b6e9684c09ccc9832" },
                { "fur", "625586c51b0ff2bed2665f994d7c7bad7c9761f0419e74ad6f758d1e1a96e50e4dccc3cc0df517b87249803f416e231216c1265552403b2ff296f2ca187162ae" },
                { "fy-NL", "8c794375c894112d167f81cc046b8d463a389ecd9381b58d617ebc272dd866013bb20ac7aaee39f5957a15aab0fa26e13ead3752400045be48f5289100d42677" },
                { "ga-IE", "2ef3c2b003cfa65e322567a1273b43fe2c935c62f2adbb5a6226a5959f6f6ec58200389f0f4cf6bc8a284ebd94755ac74120e12a44798be09fc957cce027eca2" },
                { "gd", "9bc97ca36a6ac1a312ef796642728a94544f1f4c18a2c8289bac5e581840693b7aa17c12ea6fc9c9fcc3c2f208b38dc88c140a4e60333bfb0501eeacfd70d9f3" },
                { "gl", "a58574a64af83976dc291dab517c96ce353695aef229b7510b842ce820bf60aeccd83f1a609704e103bad4814787e330fc820291f3341a30f8d1b559b5bada92" },
                { "gn", "c8f1b1d933d108392ffc9c9e1d2429a2961561c187af6c41bd4294f53698bb89119a49c754edee2db75cf91f9ea130bfc5ba4d745e16903220276a46b616403f" },
                { "gu-IN", "d2e50defad0e7f4d6183b1cd4c577d6db728018ae287dba0bc0b44056215892c3eba5b89b969dc89c16bc8b0272031a5c9532e53199af234d1600ac0a757c64e" },
                { "he", "8335bad70776770c847586d6a0ba6bb88a208780b7ad118aed50c753b47cdba289a0f7d764e5920674c030c36c626ed1c9573e8255598c4d10f1d3bb3b6076e9" },
                { "hi-IN", "764c7b1ef04644897ad7a96a18656a5507a6e9ca30c62b725ba66f4b30b1d9e7300c9b84e31d462c17659f9dad409a0165bf34d837618ff0f0297a90035ddc5f" },
                { "hr", "3504ff62942e59cd05fd2224a2f797d322a0539e6d2683fa7cd99d10ff21f65e8f9803f1e29aad3a476d3ad4391aa05ffedc375913e5337c3c62ba09e5d53b5d" },
                { "hsb", "9a39946dde58a2a6eda47d3b678cea3e043ed879b136ca89b588435123b8ae92556e36ad62dc4c353230ed83ea1bc6e9d8f1c3ecdf35a08fb4adb6b73ed77d08" },
                { "hu", "7b08986d285f95527ca659ee29208375058ffe3b2b450b1457e5c3e40fd9a832a7a33c8c6e41e64cd47531ea1b7cd3ea98a76bff2cd33cacc144578938f5c6c8" },
                { "hy-AM", "dd06a04abdb3e3e3466d51ce8b5080e0c2d50ed40c0bf1770a8a48691f8bd5b232697ec5d51972488be618651bbc1abb4168efe2cc02c8cbe1ad4405918a23c9" },
                { "ia", "d4aff2a389adb9ef849acfb62a214c761adda522468c1ea2237be6d8bd2cf4784296327afcd58b7fa15e94010fc011d24723adb081df1eb5d66295f06faf9389" },
                { "id", "1453ffa41eb4732c090b9eb1cfc6ceaaf8d79376f42a963e40b1bdc141e565002e8d79242ec4e723844f2c3d2b3454cab6952b2c0ed33af6e7997a677ce35582" },
                { "is", "30cb1260cc9645ad8e4abc033acda6643b363842ed76124e2b74e139f75ee1129f4b395903ea6d1c45b78e80a22480d72a5fb730383047b1f9b39d98beeb378c" },
                { "it", "0549a5840a82cc8f2c097ab3e2ba859317fc26ca56faabbe6bb8360dec44344705a2dd4bb4004c05ba737d7872f81646ac425e731da6235eb33cfdc416be61f2" },
                { "ja", "76151ff52099d4c36953bbc2aedea8b5ebfa184cf67df83bcaaa33cdf30955715b2746d885c2539b963de9dc7e22a1c8bf98ff75d977015abaa874f5e2287629" },
                { "ka", "40791eb5d4a4400c47dc67af2e97434922d9e89c3f12dd3517b49e39886d5ef2207e98c1025f0090ec8a198f7d1f6456af1ed03cda6468494797cd99219c8159" },
                { "kab", "0c5fc4fec0b91fa298c79ed2b8597e7bf853287142bd0782a0e7741f36a4546525d94b479ef09c00ca979da3f470a73d70438a2fefe2fe7cb3cbf6e34b5445d3" },
                { "kk", "8a4de210fc70b28bf361836f32192b957958de649f6a53af32b54ed0ebe93c2566db88b0ff22b125ef5af6ec95cc48ece6109bd590961a9ca6cc381e3a8de020" },
                { "km", "d25050e318f6c5822c6270c876ed1eef078c6946bf5f2a282a4114f768d6f6b5ec49df3fe831f00cd5ceb3c93d6959eb2be619945fb1b4dcadb670dc1536c8bd" },
                { "kn", "d5a69ce3d48184152ba85730ac4ef2cce10f4613fa822fd10476a65c901a57d0945e54fda70f1d93bf5e7a4b1ac5271f974211448b6b853716c9405b07f423b3" },
                { "ko", "e44e7b99d7b0e481a7d76a0809be2e61306170a0cd996e4da6e799517600832529eedf7b878252bf3a686089999f81e682b3391e20521bca8be5841c6ad5bcce" },
                { "lij", "9164187c033f7570951ff64ee78b8e4d662ccaf7e41db8093b18971e48d7f9973967dbf201078b31ab7e3b1565dd24a2d63bae0e2ec623c22f166da9840a01a9" },
                { "lt", "459e1f5b3534c6671ffae6d39d85f04d45d9f84f1093aa640e6fef437bb15dcadf6b99cc5c8f9dff0a58d8130577034c29d408ae6808e330229091a65cf97d44" },
                { "lv", "5a4d0415e8dff2d1a8d475765b61f140152ea7606ca376d91e52c9d7333a686d480ab80aa16a2cd03c77d6a7d9268ed7feb045d516211cbeeb92be85cbbca84d" },
                { "mk", "647fa255ecc2430eea3ef542ecbd3d2beb12f823553fc40da0b2446234950b93d2077725241225e5a083ed4c8c843fe9ef3cfca25656e79b99a58259bfa74ff8" },
                { "mr", "3f11c8f8e1ba36e5bc87ba7359a831cc8ac9fa77f035104259fd35441d034301beb063e56adc1b36b54ff7a48df557db26b9875c871be0c6883e8ba2f349dce0" },
                { "ms", "006c5662cd2f05a0ff47a609635a0b5aa44767a648360876ca827abce9be37d88e7f0e069156a13c986d27ca0960d6f6cf2641f809d377b897f2d339167cf1e2" },
                { "my", "cdc17b71ff5c26894e48379f9528c505888b2107105f9b71f1544b60a976ee7ee791c74dfcdecd5acf3b68e6c88e42c818a37d009326249b3c7d3338ce38c010" },
                { "nb-NO", "cc14f85295bcd4360c6cc567a48751a9a3fd8e0fd216d9605ea7aceb85e05db7f69b6d19c0238ff1df1911cc85e1cdb435c2e7823154ce75d1aa7c0a11a71149" },
                { "ne-NP", "084495c1b195246da450afa4e1cfc1ff67808a3d210a5c72a6f0cf2b9574ec153633f06502a22abcd6d9dea02140dbe7fde12c43ddbfa232833a298b6687dc46" },
                { "nl", "58cb33491285ccce3b13489d3d4a395487dc14a0fbc59a7f917538ef745e210a0d305c492092ac9a512972e66c09b6f12b8b0ddc04df5e286834c2530bf486a0" },
                { "nn-NO", "d49598c8069bf2fa4702660056c43e118b658d48a0cea7b5c41a2f2eebeaa0f31e5a177e548e0d3e210c8df31c0437871e795e7142a100ee87be9d29d53a9085" },
                { "oc", "2d6c91c7412ecbb01e3bc37c2bab3dda1ade0a5e7ba29a9b42c8a272e03e142275c89c14e54948da6cf316300dde7b1858dc2086e580b5a1477c9fbba17dc8ed" },
                { "pa-IN", "97a386ded382211ef3fa537b02f9aabd356090f42f0a3d8c8545bacb75980a5d0ba2685ca84ad92a2d333935ce507bce3155a69eb76c93ba5ddbbbf40ee140d6" },
                { "pl", "79a6dd4b1e9112109e2d98a42fbdc4a7dd667778b51e3b4544226ee8b262533f0419df014d5ca6bef031d76a677474c62ba003ebfc3d09f71d0fddf122acb858" },
                { "pt-BR", "9bebbf3c296454ccf4d02c3f5744d80515fefdfd5a92e2d2cd87ceb541be2f47899eb11bee8ebb83c37638dcf5f8e5b185415e341631e1225484c8d06a165d1b" },
                { "pt-PT", "ea755ed61806bf89f181d856c09bf91f2623e2c51cee69107fe4541e36511af051cf0327a43c2c9282623689405803f24d378c31f019400f0c2eed6d1fbe6358" },
                { "rm", "6165cd6a707c317640a56b8be285eaddc74f5f90f7a21848c648fefdbf3c083f33235e519471e07081ab42656db85edc224b7b869fada3c4a0fdd97edca8a5a5" },
                { "ro", "fba73088308a7296056e153e887775106abeb7420b46addf6854e10a886f5e8f5cf430b93bf17466ad9365e1550501655776c1970110b6beb4cdbb2248e0c0b6" },
                { "ru", "277fb729a53257da26234b69732ae667739bfab090f5fefd617a19a3aea1865b9125c166960a0f56fe640df311b9c392c889be1a4f6b05aff36c518aa7b08370" },
                { "sat", "8c7e925819c40360b64d86daeed935dc50f03d024633bd00af76ebab2917b0ca112c9d20ab45240b88d76a783d501f01880233317d7a01ae26524cf660ddc151" },
                { "sc", "08fbdf8d34c727a0b6d1f3fda5dd72c7d9df82658043e899d538ddaeef4b77b93d4179c15901cc90d8abfced4b46e8bebb9598d0b7a0efbbbf5b7dfcc546a197" },
                { "sco", "63a648b30caaf6a579926eabafe199d402ed1cad55ea10cbe1c62a89497aaa035c72acc64ee64332e5390cc3c89778a95287bd2ac866a094c87a6c50ec4c08d8" },
                { "si", "d20e1a9835b722b6a791750d9d29481f5d85efc9eaaf21d9a9c0fc6b9c90c61d8f13ede217e7d348bb4b3d14f8a01659308ef842a4a593d53caf4d29caf30439" },
                { "sk", "3e8f112914b7172f6a9fb261e911fbdfd34857fe795c803ef61cb94b8788bf634db56f88754afb67336456e15f583f7b90ea67b961e68af8f8053f85260acc28" },
                { "sl", "16a656eb607a378103007c90b946ef5929005a681c26ea2d750361baa7739757fba9e1ebdd5de9fb46a56ba0f69b10784c6284436770131feaaa830645db4531" },
                { "son", "a893da22b1624c7afe150e5a75ef6d483e8dd8e3716b9d859198aec33605c55611c18ddac67699a91f8d9c42d5a2f12f45f67f2bbf994bd659e2313ab7c2fcc2" },
                { "sq", "ec38791fdcdb3f9d104cb0728c121787f388c628b91b03d1845e211450d1b41cf29a95f409c18543819ef7b101a29c6a730be8310addc7edd50bf9870e0a8adc" },
                { "sr", "29fc687b94b9f18f2de819803cbee57d9bce382c78bf314ed40dbe5e9dbdfba5b7fdbef4b2abea5ff9c5a28a6909b625b6b8d93886890c4a2dc0650c4c487432" },
                { "sv-SE", "66bcf2616241311f57b64c383823956957e5951efe82513110a33cf9d4497f58b94c5ebafd73eec285fffdd927733d333da7e8012246f59b6fdc5214b77f26c6" },
                { "szl", "6f5e0782d9de0561d3da21ed91a35fc5da4151213cb8ea746e524e7e0ebf8b7540f13621fd491db079381ddd66859e8f2e516da58516a95e6df84e0043218919" },
                { "ta", "607885b24652bf99831f65e56927739b5d4362e431dc4ccfb29efa91a8f1da7a7819b86d17e5ec5f73819d5f26f24e7c6dcf69540f3e3cab3dc99d1b5be43f95" },
                { "te", "660d5ac4b5d92f2f3c810703e26fc340077a6018016ee7f2b2085b513ffbaf8014e270baed342a541310083b293627ec0012e77381e211e4396b23da4b8cd58b" },
                { "tg", "686a14747a098cc6ec646b9f3a19ead5a8b818393d469b67b399e0e40351a87b761824b2551395bfbe60069cd457826b68edbfda1c3a8d58b12477d4a3a1c531" },
                { "th", "9990d5b6066bc4eb00a1dd7a961b64fce4c431fb0ed93359f4ed85400846e4c4f41573c9068b2832371c9c7984def89faa7fd4e49d734db41489372523de1993" },
                { "tl", "48438489a4f579320908067ddd2bc518c26749726387e7cb1e01ded33a737ca5cd7020225793df89952c1e686df51f0ed2cc0f5d3d6b01b6fcd3ad6a2193331e" },
                { "tr", "bcedacf689c94410c3121325780b6468986642441e6c7283d9ac1d1f72de8651bce1a0f078cfa642e30f71cf79db8ab37e4ca076891e38f7106345e45ab1b640" },
                { "trs", "6d33d54cc13e290e9f083a3de7607425049f91739007616ea0bda2b6e7e180f5d4a534a882baa6b952c597cd451a53cb69db82dc79a7a99d25c34d24c914c0bc" },
                { "uk", "342088cc4950cc8c19f041f72d5eda1f2cc5d8e5443788f6f6bc6d7aa4094343a807a262d887fe773e548866c769a67e5339ac9cb89b84dde0da5e6d61164716" },
                { "ur", "ff75680335ed1f14a6b0f641ef730c0b8d7381fa248e14743f940702b4ff5f5ada7fe42c93c074eb199d24d5ccb51b899694be6a8538baffd1076e18115f827c" },
                { "uz", "312727b0df28dcab4ec277d4f9f69d21a90e804a1647806a6b3db77520c65101f0c3c1b7a3862a8f59aa15cb89f2b5812e124318f3aa970989315820d7865406" },
                { "vi", "e5fc4a4a7d9f623aa484cf958a6d27257fa3765e60ce9fd259265969e8b41545b03bfd8a62ee516f41c293bc57267955a5f6803b48bb7e56d661efdea357827c" },
                { "xh", "2d27ca955c816fc4c19a892cf51cb7c708d759ace42d3c244e7a91c0f64727c671fceacb27bfefec8b4694487040f55a5053d92b9ea97f065cddc124a14ce739" },
                { "zh-CN", "248b8e9c91137abcb8dfd6bd3734839a8a47a3d8d7e8f219fcbfce1c3c923c265b18a24aba81dfb561ec0061acaf04e95fb96621398f7c5420784bf0030ed09d" },
                { "zh-TW", "4f640f417c5262b7148aabde9fe05eeff50ca607fb11539af3fbfd0a4ca22d31c07199e47ac2f693ffd51899a1f72213acf3b1b1a51bf37ed55e958dc845003f" }
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
