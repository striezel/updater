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
        private const string currentVersion = "131.0b9";

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
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "13347e6ffbc0a9bc4e798ed4749839ad82f77ec35684d962e6c4447b720d4099558b4c8db24e0777641702160a256190cc62eee764957879451d3d24d73ce66f" },
                { "af", "0cc5bef30e517cd9a82dee470afc056e2a88304de1d2a75953774a3167986b71be4f485957f876a19fd958ea5faf3d1180c0c5d74b56743ca81ce89ec9bbc33f" },
                { "an", "56fcf011273821f5e729a9ba610dec4c369a530951dcaa01a651336caaac6c7e7115c3f103d411466735f5c923222b1c984a9d42e5cf3427841141cc36d9ecd0" },
                { "ar", "206d7754d1fda58da674676e657c388f5cab9519dcc1179823ede40c9941c1220e715ce282fd14ba6c3ae036c0813bae3197783fb94a8296c8c8134109414a4c" },
                { "ast", "0fc0c7fdea792b7686fb12b1cc5ca67dbaa74eb6a1f2bb3f90836b0878cca353d27fefe47b47d5abcacdded61dfde85077b31b66fcf6356705cb2c8d2719636f" },
                { "az", "97c5b85b0af86bc8e4733ea4ac8d4b38e91f1cee32fbff894c1c92bfec8e11b3608ae0b747c06da67b7119aa2a8da1b7592dd00e46d5b70d55de097d1cef7956" },
                { "be", "524433792bb6ad346a3467f3edf2ed45840817c219e50c9912c883fed08cef12f990d4760f166b87729d846d925b7bd242a35cdc1c3fe8db157bbac8d1aa022e" },
                { "bg", "b02c217b0b4af132af9a2f2f0f76f925fd9a0f1a6d71503662e5e48900f22a0952da4e68b0f9ef5909eaed18e95e6746b837b575518e5534e629d983bc6a7961" },
                { "bn", "6663c0626e1498fb42fd8237e2b62ecaaefc794ab0f01feba4a4e544af6b536b1b75baf14d0f834ea72757efd0523b6d3fad61628cae237c8446538ab6c9436c" },
                { "br", "f347e93f03d7b31ceca4b949657dfc762eadf77374f3aaf935ca133a5f435678d21c134069777f5502baa9303da1975a5b4b44c8312da8b983440c00ec66c186" },
                { "bs", "bca208c2f6e40c1221ba5d8d9eba08d91b24d23042e60ddfac500515db69659a0f5e0cc71785ee14362635e18d012181e8ae3b5fa2a24a27d8c500ea124a2266" },
                { "ca", "9e46a481a2fd44848c82f9ff33c24b7b6e26233c0dc453fe8f72227ee7bb197350acc46f7d2b19fb90a88abe79b80ff9afb7cb1230159b3f704fabc5a2913fc5" },
                { "cak", "8bcaecfd239d106a05447cc1cc3f9ba4c38be8c1ebfbeaf4642f520da616172024da812fdf557c46e320ca727398c13185335784e5b279538f78da8bac465a43" },
                { "cs", "3e009a7e0b5a0e7bb2dfae742dbc3506e8d01eaf002a911d0d3dfce36004860cf65623f5a644be2cbd0e78982050e042ebbf90efdb511ff3a856d36113f9493a" },
                { "cy", "d981755105e38fc6db2be40cecb9864e8876b0483f17654b4bda6ea2b6f0d7f74a9f435b04b37e06a4d117713e420c6d42e714c85bc140739d255706d0bbbbb6" },
                { "da", "dcc1cb6c07d0a1918ea8439b9cdb516bfe2923cc901a0af95dbc4bbe6ca75e6d960bbfcdf8f68ff5860a699f3ad08a26d13a9a43ca01cd92e757ca1ff0116036" },
                { "de", "86cd95754c42f0d04d8e9b8886c96ff020914c72bd4f079b8c30f62bfd028fca03133d91fe23926f37fe2f1aea3d65095f5702b7be5d9c3938257af87c8775a9" },
                { "dsb", "4eed1901b35e473465df8ded2dc0fc0700c3f5c979d47e5ab104f372822c5247282f529b89afa7440f29d4c0e8f3a00f35392ec7d1f4e4299034d5cdabc2c990" },
                { "el", "b438cf98beb07e58fcf502d2bb9d1507649f5934e670fe3615f0c31ad67e3f2ebd65476e920b8f70046121ad7d6c92767900c3ae59512dde4f8325ef289fc4ba" },
                { "en-CA", "43914c3a030a6874807f528d8eda2b2ad3d83f7aa14fee773d480ae5dc640509405033d34a40289e3426e6fbdd8ea1a8c8d1d2c56c510c8208c17ff339790ca8" },
                { "en-GB", "bf803de5fdcdf3f79ccb18202512a115fbf78b136210a9863a0635506227280661e9af4ab4f536581ceb6d43ccaac596abab54c0574a2af25a7ec769c0c2ce9b" },
                { "en-US", "c2e8e789f9f73fdab05d6632aa52e338285a40893d57ef7133288b604fbe6d8f2e49207027cb53763117386307b56374b871afb9be8bec565dc354d0c2717fa4" },
                { "eo", "d5478de7f6f94102cd855ed1d7374dc24f8802061af9efa74ff9b2fd9ab36b21062490a2cf54ef9148a82f5305095420ed5e29618a7170c787cec4740ae57036" },
                { "es-AR", "b97dfc6bd7555741c855cde85bcf4d7adc6db79870edca66fe3e2393a4f160361e88ec62dde713a3cae1c9e22dde0451309e5167681a39d9b23b2035bc01bf7f" },
                { "es-CL", "0319542d80cddaf5ab29304c0fdb745840512f11fd1fabe675db8a42c4048bca67850bb81464a3c5b9ca8e4b8c63e15a90e8a033847c6c285ff98c2a45355cf1" },
                { "es-ES", "9e750be5f82c695b233bc8300eb31255547e2f7d76f743df6cb8822cc963415963af708a3b7dce051c084885e8d74b6438cb4a802c4aaacac913df9622eab799" },
                { "es-MX", "b7547e639581ded98c09c34f2cdfdc01b0816e271cd0aafaf00a743601d4d728dc400ffefae5f6cb2a2a1589c872a4456192faedc28ddbcae3844f33bc075aba" },
                { "et", "1ad0e0f5df8333697bce0b932a66549ecc98ac71422537e80160dbd867eb995296eb5ed749a949445750ca87291d6e8ae41c47d99bf0abbf8f54bc4a8bfb2656" },
                { "eu", "b8cfd615e183a43f39104a661d5da3023f2c808ab71e4e5857e70a255fa277309f5cb75907cbb89e66728fea8cfffcea39b7d7b50a8012e3b392ced2a06a3ef4" },
                { "fa", "b990c8b682e89542b4c91e8c9b06c1826cd19b86802505d417c320a935ab3ef6124b62901edaf2620f9f5f3bc90c2ef8264caff879d6c21806e815c7a991a75a" },
                { "ff", "cc4adaf2ade23aa80b86b8c5f008ff8b8895e903e193cd4b7dcee042b0f41cac7ba8eb8a5de04d35541efa39c3493b1fa2895b3e391003498d7f76c43b3e6468" },
                { "fi", "8c95cca8d9bd1085dbc4e82d13be8cc6d115fa2d6361ffe20ebdc04d949b476983890209514198addaa384bc192e3c49b4b41139640154bfbc66e802f43bc7c6" },
                { "fr", "e30ba61676047a39e8b8a8d6ed687ef9e812ea6363387e0ba99c3ec598e12c2af3ade243f3ff12ecd2fc63c33d27c0b60422fa599bf36fb9a2db8823e4876a70" },
                { "fur", "7933209940706871d990ac747ee2afce098a8e22466fc2afd1d87b050664a1f4303db2689a3ec735f2e1c977e859af3e63e47321a8566a24251ebb58cde4e6d5" },
                { "fy-NL", "d1c6f6861f98a04054166e4b6b112867584ae06a376ad35371151880f0f02debdfa1dd943365b4db40f21d9086e9930b192e4f57543a4735b01732c304acaf72" },
                { "ga-IE", "92fb5005dc2174e4e9faa533b27711c2bcddea13c600f11d3b41e635a9ca26017e7c39d32f99ea6438f73ce16f42af877615a57c65eb32b2d6178be207676eee" },
                { "gd", "6e4fe5f8e59ef07830433e6a29deea20927b994173ea8e8643c916889197dbc10ea4d9739b4482cfd77b24509f369d942f65c54ee36540efaf7877b5ca6f3cc1" },
                { "gl", "211a2b83e5b2af2f4ea5e22103e2a3b068ab4449c6887d8c86b0f4f69ecc80add39c96594725675fce4e7537cd5f50db696808646c5026f7e9fc7ef6e40f40b3" },
                { "gn", "9bd6166dc7e2722a97c838bee2a03df0adc7c293650a6cd231dcef010a6c02f691fe505b51237d145e4933a74b20f85b7eb628d65dba2103608bec58417b0793" },
                { "gu-IN", "269f4e26593b60dfa1a0abdaa78bbd42cea15ca7e5c74341c620941d065d4de4769fc6c24a9bb01e39c15bf45b75afe98d669fbb83acc64dca6709bf196fcf68" },
                { "he", "f682f3e1b4e3badda893eebd30549acb96c6c2daea0b9d83a14ded5a9121d9476bb1f24d9c3524b62145c22aad1d510783698090ed094b5144d7606010213db8" },
                { "hi-IN", "1a7ea7da87187ea48299f5b60e8c15455222529d7fc69388c0fedfebbfd427b93e24cb79ae95acc633ba7db1015f5c10cc393b41f86f1a0fbb8b79f46909ca6a" },
                { "hr", "c254642a6f47c51b44e90bf3e1020c98df890dc0b5b339e93358f86fc2ec96afadea0027d0c4d1708345160d2f7e0bf6532361871b5a8099e300663f835f792d" },
                { "hsb", "921661e9b6198f9e741e94d5c6f9c6164b487b2340066e707cb4f8f1422da723308616eedcc135db838cc8a7e0ea82dc3aa479f655a1bd1eb0f93f053e217bf1" },
                { "hu", "b6345e17c54027704b3a54270b561f74db8acb3725978a07ffb742902bca3873afc0146971757efbd9c82e8d5cdab9f09e62c327abc44b9f9daa092e87ead2e1" },
                { "hy-AM", "3b743ac95134c63c94a563d08a834c0290eb57fe2eea1664552303ba184d3742d711960b9a310d1769a85251179bde34fb10dd86658832984dc00c00eaa226f5" },
                { "ia", "ab28b5bdb4e623a42299ed3bce41b868655591738b7737ef1a5ebbb9229fd49aea6d31565e9ddbac86f7a1ef148f62cf8a71724c8bfa97ed93f73b69d3cbea6f" },
                { "id", "bb297a390a0ac9be7a942403f236c8a6537ccfecd126f701c046bc0bf5ed16321f07e5caa3fe55826503a2a5f73c42fafb74bb83c837d6c801373a3859748af9" },
                { "is", "d9530ddd180dbdcdf0880be50184f13c9efdd7bd12843998f011c17ad49c75098965b8c7cbf4bd1251eb658dcba8b65ed02bfc71cad5a86aa470e039595c25dd" },
                { "it", "ef0955fc863e1064fae5929c06b30373b730dae3a942d1119eaac93820743c7b014d9876a17e75efa87b05709a61e304d9c6e040065b813b6fe599cc12f56afe" },
                { "ja", "7975ff1dec4dea3f6f1ba927e4047ff99a3fc5b1449959b07e115bad7d5121b273a86ee4dd0a22401034ca9ba11d9380a714ba6f7bb32bf579f77613369bf4e9" },
                { "ka", "e52daf0b57d9cfdcc63484c96b8ea40a37032d629d7185244da101a1ab919eabdfadfdcc5b8275ae518ea35325c779ba61b4b1a4ae1b7a5cc92d5b99df04c32c" },
                { "kab", "a455e6f4b0c0762b38b5e00bf3e2127b8ca84511c5197533f28273716397b8c26c0c8b132bef98918b107cb385d37ae3f61667118b4d750ef1ad6260a4e4841c" },
                { "kk", "3c3e803575cedcefa0fb4c15bc00eb5b812f61cbbe77dcc128556688a86d54efca4d5f84aa5b9450842c9d9c5938add5304f728a6176e3a7674728ce46c463de" },
                { "km", "cb40b9f9c7856cd337a6ef582ef19c544e5fc9a6e80f326d61f2f0b7a7648414811a2cf198e0e4b83fb4c81df9c360b7cbdb5789d9613ce10655272b9c70debc" },
                { "kn", "af40cb4aa2fc75d8b065b7bfbf0d4842d4f78848981a88d14a0d8f9a9fe922da2b506c946cff78db84aa520d5832c41f8c44b8c96e8ac7799e252fb06c43340b" },
                { "ko", "d13d2ebf53b52a0697030dda7db5a919606eda672cdf20553a345023b9ca6ee8e986877d7c149b63c4fc0f07e68b8eaf037c11d443e67d6215a8dbcd43840c17" },
                { "lij", "81767f50f14aa1d3602e82d0352913352d1e814f9b92ce8dcc679b4709901fbbd37f03e90db3c97b35f8f05529b579f548a9cb3b62e1749ecd2eda3eab784dec" },
                { "lt", "3692d9614017f52281552a06e2d12f29082288e7d323990696b7139addb4fa8fd9859bbd8d81a63672c199748076bfd0fae46d75401d255e1e2753cf3e8bea7c" },
                { "lv", "4a313ecdf0dd365316b1723f93fca9251a7bc764190bc7ab7157f287e4530dc1de3d4b3eda5ef6250373f63c957e74ff955d3677a4e7b3791c651b85d8694d34" },
                { "mk", "9f004c9c88a019a2cd6846359d4ce40870c58fe30b321080da0bc53fa48e77a0c5e80f08bfbc98ed694fcc1c9f5d1957cb7bb01425643e3c8b08724818f5a206" },
                { "mr", "1ead6afaf59a08355531f4a1d00a6e3fcef15bc6b0a3017a07c9e6e9870f15c6c93369c9dc8706d7feb0e8d22d7cdbf44a96896613798d9a2b620728f99f1773" },
                { "ms", "6c233f952b13a225cc50ca65ec83e0e995c948c0597ecbec101a736cd14d445052104e0eae9ca24313ab9f853d2f57cd69d0c4cff97e6839830324ce65356ee1" },
                { "my", "20acafdf7a92ee2463cd4dffed2f1e853c423773ced5da9c81e81510bfdac4f38674ecc3889a08fdcf046a56292f39ad6fdb6bb10dbac0398ae52c0c7fd6ff51" },
                { "nb-NO", "901c5864b05377e622b90117c3bdc59b11ea475d686ca68193696691bbf9f27313fe07d928ccfcbb85c3df5f30693cc142b5cf89043a30270f9176ed8666c7ba" },
                { "ne-NP", "a14e6dee9a9501d528d090b5422fdbc488173a5314eac4d78a828b26be04f3dbea713e69f34134d9d81abe01ae575285fcfdeb5a46f0d24f382f28a42b45397d" },
                { "nl", "f3a55adf5da3317c237dff3ee6b1790aaed42f4b5e260dad0abc4bfb6a5dc6b7bf0040875a183f10db92852e2cbd9e28716a3f44f7d70baf21fa2b0336046fc5" },
                { "nn-NO", "2ab31923b0c59087ecf8435c2beab3d0ccfc5c7af43a6fcc402424f3ad4a0dae3f0e002b42bb00e49e88ac84d83642606a411f3b6f2fb58b5a306ba0b80854a9" },
                { "oc", "5b332b8acf1c3e849d4894c36b3bd1ad0b79dad982bf2ccde2ad8cfae3cc316e56248a3f0db2d7959eaa2ce77a743a5965b76d071112bcd9389f4ddb0da4ca1b" },
                { "pa-IN", "19ee0d59c0f3b764b1a9981f75d77b53845c0aa91734c68af0b49544b2e78c1cdc2a78152af468f0236b7c931841b0babb693c1683f32b26bc905d69992942ad" },
                { "pl", "562e1ac2b4842c2673045a44a71d53a007926fbe17a77db32d4f70940a9c5f8c3ce893a24b09a3015d407492cb75870360e75fda4d4bbedf6b27ba469a7ee1b9" },
                { "pt-BR", "8af38c796ef53d0d5986912826d34382b00abc5e577f5e7b10823462a0ad8ad50209ef2d874351747adfc84f4d67e86527c72e61b08fab9d6ff3d8600446004d" },
                { "pt-PT", "be12f08bf9c889a455d4430322434f2717a828e1b7842d4189303dfc172de19262ee0089233c40c4805069ed92c70227a28a9ba9d8f43dbf385c2d645e9a898e" },
                { "rm", "27ef041791a50938f8578ed0ccd5323c40a194c19ff990616fed1cd6a05fc4fe7cd107d1bd4db7b742aee385a1cc5e041e92342eee0256ada24a0f8b9f0bcb41" },
                { "ro", "f88f484b3014e593d2786023a440bad7a2c4155e4abccb6b04907a0ba75b83f569bec2a99462ecc121389d42baeae2f44c4a417f5f3992b52b47d637668001b1" },
                { "ru", "4d5618319e0f933c70979896aee4c04f0bdba7258f91be9287d093d79d96abe0ab60a202b4cb721a1ccd3e15ae543abf8742ee11df28c4bd092feec77c3329f5" },
                { "sat", "6dc1a7c0e105a93fb0303bbef4dd3726a51dad8b9232e0d7df6a81ed23baeff16d194e7d202d762b0f136e96da30f2267260afa02201c0620fdfaca54be63196" },
                { "sc", "361217ce77377e7f720f148481599004c72de3015fcae0d15c78c0db5eef38cb0e29f8034ebdd71aaba9c13b90623bc0d21de706b26ccadc96b324994be43411" },
                { "sco", "58936d0d1bad2586e0869f7038619b47210ed83841eb6731d9d76ddf25fe91eef8f1356d925b91321fee956a6aa29799301ad85983b97737e023f5b1afe7fc03" },
                { "si", "477f7eb5566734155ec7da7454f907ce38efad9c1fec2cba4418bd245111f480ac8c8c53a00e444e51954d06cb566a98f0a9c1264901f699b2754d8e6fb37de0" },
                { "sk", "7e09af15ca81862006328b0ae12ecca3221aa9084f616a9a7127dd41705d79330190f781d9e3ad376f55240ae8203870818d91d93e379c826af8d609973c9f39" },
                { "skr", "d4f1bebc6a934f1e73bdb3d39d032997513579512015c32159cf8eb2a8507cdc57d02c173814c9ad7da7b47c10cf37f9da12e93e42c505d8b44f3889d6a7363a" },
                { "sl", "db84854fcf1dc821f9a0a0c23f01a61041f5a99f6791399f0ed31c2badebe0d2a0cb859edb84f0616ec2acd621308ba7d8f5009016a5046198c7d10717d126ed" },
                { "son", "4f3a92c9a4d6f8d50ef21483d46baa82b902386417ea200df71966e994e60a8e9e0ceb0c26f85e648ef75f60735d6b3838892499af8bbf1126bd019892ed237f" },
                { "sq", "a38f2971c179b5f1d410c5270a188c539ee0f6f0054495fe88cca5c14aed644da6ef0cc67421183f892beeb06beccb054b1a79e33b2b8d717190671246eacd4a" },
                { "sr", "1d66cde730ed2d2f7a9864961b02cda1cd8885d70f56fd9104b18414e7e57285179f0c126e474ef571ced4b5eb8fea67de7e585f3700814e9432d1690d1c59f6" },
                { "sv-SE", "3722e618d1780a7c40c18d6a571f05b9580595ef4b396be8c9daaa65a6b2a03d0d5c77ade880b499035f0bea0be3891fd555b61c327278077ec35e8cacf58f5a" },
                { "szl", "d198f22e77b72493c94e01214fae604c61bc9ac53ed7fea9fdab5844415bb75e7686bdb58790360e6d527ca928a621518630c6c9c7440652b250b892bf264629" },
                { "ta", "7b1a18542fc76b85bb5d237a33a3f1c5ed4cb828245b36c48be1b0f5e07a85d0a893d19f4a08be6586e35d5aef333ed1f257519d6a3af648dd6be313eb95eb50" },
                { "te", "87aa8f60057bf3eb525cee850db709aeb736a0b0fb5e211a489475220910bf5d008b651b1e678ffd3d7da96b95d32d55e60aae0c9ccf9b2cdb3bc4536c4de198" },
                { "tg", "550c7b8c3092824febd04efd58898c4afab1495d5a847afd04f0dcee72f08da26945852d806f72e649238eb9b3ae5da6962da2a0a49eb942a732512ae9300948" },
                { "th", "1902ca6887e5fb7a612b303810e29030716cec8641a6d96e1470a8ecb3e540f0aad89aad0642b4aa2c7db5506d9c4042450768add8afa94f1aa8c6345c7bf79d" },
                { "tl", "15d2636752248b65e7f3e27935b4d2a4a8ad0f55fed8c0be8c8712c1d797ed4f7dc6bf876046a9980898b443da4bc552d4e83e3aaf5891eecacf15f7d66c9c35" },
                { "tr", "f8602df6ff4cad7cd2ab7a2bf1a58a4356cb0bbf41e766be975c7bd2189d51beb74ed09041039c376b3d575fc32eb2ba4c7943be34360a6c6f97650f25e8aab0" },
                { "trs", "80ef45394d4bf25c52ba0570353e4ed0c8e06b4360d3c513a4b46b9df6d1ee814a758be5d63e6b1616bc84e7cde312550817e2c17a72fb84a86e13c4d2e98df2" },
                { "uk", "08af5b3cc69b1d8ed45ab26d3e194b58b1daae97fe8a2957898d5f0f27dcdd29d6151ee08f8571605a3d5c222e0cd0bb772b85c279228da0b1b4bd191910e7d7" },
                { "ur", "664a1a00bda9febc5a2c9961a45eae4fa2bb9fb6a3cc205ceead22428dfd8833f1aa7fc23fb8471174c6958081d043692d6ae348dc641e2572eeb4f7aaeb13a1" },
                { "uz", "e4cc9ab7157484c8ed16d64cbd535f2ec0d37e8fe30eb42499c26f81d1a79931b4c08040b214974c2f47fc84aac7824ffb290d38efdcd2adf1061ac1c00c0a1f" },
                { "vi", "5f5905aa569cd9270bbdcd467eb0fb4c7c16b9f9375e8f71d58ee000792b3dd0c7c3edf38e181edea72869610e51b76ca7b79ab78d6d8082c7135ac63d159c45" },
                { "xh", "47fe9816c14e987af10541598fd997c97f663f5f860d6b7ccd01a15a8bb4a97437ea8bd10b92bc360e85a8a006c97d957fd574fec61f498ab0f91fe30af2c12e" },
                { "zh-CN", "31c207b9728ac16043fa21552fe2a45947d89b0342fe849fef38bfd8aeef5155e56b2682f9438e5dd633c0c669f0540219b7dcbdc36a500e35c40de03d6c5fbe" },
                { "zh-TW", "5ea418dfe3684826291084936dee61a00fc1571cd4451ed11e866d504ed8c8320aebd36ab09290e0711f344682af01c9b48ff3e497b27fbbe208d4b133bcb2d3" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "553a004802fc0ed3934dc073fdefb881d2534b991459b0a5853b2419be10e56a0724aa55aa78c09559c6be93073227a890644e90977916a93f08bea7ac24cb55" },
                { "af", "0139ecd9a5d22e7e1aba9df39c8a6cc2408c9778dd3f9c51ed12563e0b67b3b86df4124aec040095ccefd99df0a96f6f37457ab3e64c93327821a90aeebded37" },
                { "an", "c1e17064f1d382080aa14241c424be1f7a179d59850d3d3b77daf593aef0dc4101516e984513eaac13703fb921c6d9c1258bb743e676c6a64fdba8e2c224071f" },
                { "ar", "846c3555a03f11cc11b25b7755f83e18023bda33f7eb117a204e799dbfc0107c4b3bc2b41ebf76f468b39cf95ef160729ed9a1d4285909b734d083836d34a55c" },
                { "ast", "8ace59b0bf3ff83ad40afbe1204e376bc5c29a22fc8f9110f6bf68b3e6b2e0d565a610f06cfc3f648a6fdbc756da270af661d7d0470e8764ffc9ae7f94333918" },
                { "az", "c23033a8f051750fd9aa91e3d03caaf3322178c738e5cbfcd1ac392ffcfa72cb2e9e692c30be0ee9e9a2251b4c555cecb701d95eb0229990d38b0295927afa72" },
                { "be", "05d4f68e697545062519a841907f19d522061f7f7195918142f6ef9f684a734544dd97480e101db70b919025d9f51e042fa82d6cdac7e7db794230a10dcb4769" },
                { "bg", "52e433855f00b507a350b8dd069804ec010e9b44932fbe05c8feff576c031728f20d0e21c49a8202cd79a961fd89e60bce4f8f1e02e9bae970ef991d687d1e7f" },
                { "bn", "0c504c0f913464c4211896695c277c84679451c63933933b5b6a18490f0c466fd50e00ed7aeb32a4464179facc481c07fbcb439de4addeef6cb2d8a07293c43b" },
                { "br", "5afd1cde4dacebeaf3a9000b0f4c553735700406e8aeffa6c05b6550d1b542dbd07689152935a63949964ebf2dbe985d0ca52393d4ee3fa6c4980010a2cd0351" },
                { "bs", "ff7a1938163ccaca654a42ec43af6e6932a190a7bb5851e04db4619e7470998a88f6f12158c5eb103fae8bb190054520642a5afaca2f0e869fb6480b26d2328b" },
                { "ca", "e7f4123ae0d5fa12b4d9afa4ba82af8fbf231e4b419a79c2fa0342332861720c42b698ff687974f86ab9cd06630f0b9aab934d59a241e5b57004c0b4ef073d7a" },
                { "cak", "5241b8ddbcef2e5edb37ee502217351fe57b5710d61d79f7794f580e1c0ed297d0a8e0eda71da24375d726133c7ad092b77e5eb5de91601a4f437cd9877f8f20" },
                { "cs", "bce4c49733b1480be4039e83dd97ba59e49f472cf6ba6a83d55a00262943c8b5221ce388de03ec356928d769f4840c77d1652f7fe004fbec1ca4b060ebc9a301" },
                { "cy", "b46e61435d88de3509d051ce7fb8244453ff8b6b799373efb1bdc2a3483c74b9ee25f0f89cf5dffea8dae0ad73ec8c1f0a6d14d1108f893fb31f28b70e68ccb9" },
                { "da", "5f86c6758d2c4e47cbb51000fb5b1e2166c12a1a6b5cc7d97362da103ae3b6ca3210d96976d28efd317b8f5652419e9a28c1e5e9cb15dab7e331b295b1aef61e" },
                { "de", "af4019d5354434d7ba1cb6429c262d187e5c7f1eceb482194ba01ffa69874b161bdb9424ab2d314fa8985fd9da1901021824eb96a6fa3cd4e38e1315ff560b1a" },
                { "dsb", "4e34d347d37847ed86e0e5549039a5bf16fd80c6bb58fadac089c86b0b4206bcf8dd938e597a01ceb21331eb9d2d86c31d8b39800a0961a79fe207ae3fd4152d" },
                { "el", "ebd965b355761c84e97652f0e3a8897b1f05b0b6e5f10f985c5a13f8dfed0f0ece44f6a70ff749a5151abfa620eee79ae852c5e9aafffd88e2f4120d644d5c1a" },
                { "en-CA", "d547afe2afa6a4b64e43a9b3f3c04b687c94356b29f5464339c23d447d5045e2dfdb2229159722610b6d1c0694720829fc76328cb926fc93d0ba45fa52575664" },
                { "en-GB", "2e056be463e47c538b79923e8118340c5f03475a78ab5036ef5cc0585539269c45854ed0404f3e5798d5182b496bd062b20d20fbe458210b054ae4431de22bc6" },
                { "en-US", "88abf19f02500fb89599a2ee6eb63b0a2c849ebfb2c4178f4f27e192a9db394df29d3878926bef96834e8c5be0ff0e4677142e8f1353dd6565ffc4c276d122e4" },
                { "eo", "36b2bff6cf2ab0be47ac8a24e182c5a2708b0ef0658119e3f2462fe8ea968ad4083de66de0908e0dcf09c22c257e9da46109a101777a4a542b3efdd23f3dc1c8" },
                { "es-AR", "4f69a5db2044c20ad9a5415cceee3a6f6b86de4695848225ce25c2b70300e7e328462da06a6d4a1f050724f3a0ed25d1d9044f5bc53840b33613404b836ec7ab" },
                { "es-CL", "7d4d19959201c2b685b1c2067650a69d47b10865d789c6cacbc6672b3ca237acf8bff1506dc9eb773781c71de43290e454f61650b0c41e18a1c95e573ac043ab" },
                { "es-ES", "39896f839c41679e823569f621b4fcb837b7271402fff12b2205914ac7b351970aadf61328f26d08234f5ac5b1b19198c370364e1610ee014c6d50e890efae56" },
                { "es-MX", "dd1fa3f6084f6181f49cc62a9075d3f190597b8c1ef7eb5612e263885b3107dc53a328a50fee980ef478a344d0a7bec8a661bd74119841996dce14dc54ebf4c9" },
                { "et", "384ea2ef51ecd1c71bcb21f24c3da7bdedf5a9cf1a215c16d8e1e8d0b365638123c98b361604b8ba89b0bc3abb6e7bbe9c5533ccddb0586eafef60acec8a5747" },
                { "eu", "acf718a85ddc329bf018794fe8b964e05c2e01438de131c8661bf700ce8bb30b28b0c92ff91a50eef3d8ca28e4b46e87ca8fbf4f249a09fd4f6b0e570530745a" },
                { "fa", "d2850b35a06093afc75bed25726a6f6abd24440a4bd4eb5fa694eb58b2235558c5c4a96435ae1d053b0ff1620c4fa212155bc3a6ef4f600e2a43e3ef435bcd79" },
                { "ff", "211ac8ab20514e6cb4cb573620026c39a28682d398b48aa318c7e2aa086838d7af09094b2e3e672820775a83c7d8598bf1716d50f5ccd63d7ba43c202fea76f1" },
                { "fi", "0d57003c64d6cb4e9518aa8319d3039f61f43b60572ad18c2b38547f088839f1fcfd8d315d82a4b7eee54ab4ffecf198daea826fc52f680c9a343149d03a0925" },
                { "fr", "81a16ce5f92924f81e2e42f6d316b05db250eeacd96e15688bf269bc69366f0ef615d6f7e163105ea59a052ef402f01b02c725597fb296929e0081ce1cf6562d" },
                { "fur", "6a609427b576312a8749e69b98040f92d6733a1b30c45566362b6074032edb73094d5acd7b3dd95eb849eb9968aec2aef4eba045e6eef05487dc28d06db81d6f" },
                { "fy-NL", "970e4a966bdff78b11caf805819bdaa36003e941ab65727ee328c9f35d0e5589fe5788b3012b98a1789db5b5d7b82414b40e75cf02a1496b8d5a877e57858b09" },
                { "ga-IE", "ad0bcc6145e4c5058c71a4ed42c13131554f0ce3e13d17421442acd2ece37d30b2e09428c6dd6dfb30543ff291846967271daa15cbca660bd7545edd9ed0afbd" },
                { "gd", "f0d1d6d141a6ebf7f622369c892907d75a792125e1e6d810e0e0d4a64446dd021788ccdba61338a6a82d299d4edc671feb3a95ae0a9b0ce19d83e539c44fdcc6" },
                { "gl", "e3a5051cf2a7fd231fa644c4dfb186d9563271437f1e7a1f7ffce30e2185eaa11965fa65240ea0ec062f3fa074706802ca95816dac5fdc084bd89f3e4612641a" },
                { "gn", "9f0d4e5f100dc76606083725de5d04a928579426043e6619ff5c89a1397c0ff91251cf22e6761ba248ef1338b1697ac41ad1600d191999d5971428af7550d6c5" },
                { "gu-IN", "2299dc2262d8c8ed90a7371b8474c645a99f5506f8c097c415ec75766a31a81da52758f99259b992c4c1902bbdb10f4a776671878094e77103216ce13117fdd1" },
                { "he", "9773e055b7c517cfa0bb02ba7fafb7e0cfa8d070718eb7b4c8a6af804bc82810d3a098f04091f2cd5ac59946dd7e096fac646ff7b32723cfc22edfe4664c2637" },
                { "hi-IN", "a894898942e2a998de2879d3d832e5861275cd99cff92565dee2bfb9fbcf1b5de4bfb5b8d5d0b8096edaa9843e8d0bfd378f901441f9af160b3b7439fb343574" },
                { "hr", "7e808c5836c3165fdd2a588b17dda18fdb93cac6078a0397ae6a8ba5e48deed4235a5b17fb6ddd5f694020047bc01dde7334de41633779163a3d189ed930be84" },
                { "hsb", "81237b074b895e8476a4900e119dd64384f6fe729668dfc2a823e1a1656777ef49b51136f0f1ec774d299f66508e9c3c04008acd494a26c318c32fbaa64fe69b" },
                { "hu", "7b9319bf7d52625b8b70bf527749c0d8687bac08625d497773fcf855e04e5699186bdfaf93019224437295652217e9ad11d5d3010b96f80f266d8b57edd4d2ff" },
                { "hy-AM", "ffbc7559bd2cc5b01aa2e3107ce33c1ec79027ccfb6cadc05ff940d7713e9b4bfe60cb8b766f1aa30983f651bc07caa5a443dc9cd3e731bf9e1b65de730067d7" },
                { "ia", "b3639807495658749e6bcbaff6fe2e50cf77a58629785e0977eea3d4ab8b3e4ebaecedca833d814f59c0e88c5ba00c52b95bd25cd3f85bfa7e87f9db3ec33891" },
                { "id", "ff839accc3ce4f4e93d2c130e80c42b3a924a24b0fd0e0b4d488c379bae5e53ef580ee38c65132536ec3324d465d0cde202752fa8f6a6316e291f81cd469ba05" },
                { "is", "e586386ccf7330ce7cdb22265a49a8c570396dbf5f81a162fe44ea5eb414bfe5d957805d9f3d556fdbe9fd57902004ee6bb36d3da662285979112cf3ea61dee8" },
                { "it", "a519c74937318d4fb7aa046b7f0ef4cbe0fd35b14bfa0b87aebfda6d4493ffc7aa383a86fbe488a369199866d90951f62d74e4ce0ab492717c91c9f1a632711d" },
                { "ja", "df6bbc797d83add7bed71b73f017a7cd4887a9a1fd239c7fcb1011f388e94b144d92e4770ca8442a8ac37f00744113aa90a4b6b584673b149d21bec5b9778101" },
                { "ka", "1b25707f26b7b0b3ebc6e5c315b7e9543a9dea97d1e3974e3d180ae6d95a749d22d625484c35ff13532d9aa70fe283749ac52b84bd794faa993247ffce237c08" },
                { "kab", "e736e0a4cd0ad7b51d3d98d6e2cb3210e54cb84717fbd3b1819106759aefbca6fb9daa45400570a5eeb4c0e0a05cc1f4c952c1e8ab4331fe9308876b2eaefedf" },
                { "kk", "d0398539ad1458933bf2b9c33eb9c20876e5dfb3803515add44b8ce030b02b47d26a2a2614ba63160a67012eda5a983a415d65ccbc925c3656fdade24b132213" },
                { "km", "388bf1c08ca0ad15ca7800d0d86d98182009e561a91387cbdecf9d527e1235cee031b7ec7ddeb7684fc76a568d1f8b9b353976c9726a49c1c308e8b3a40b2007" },
                { "kn", "055216bb989ca81ce85c73864cabb2e9f54086975041d0c4bdb375574fd89017e905a1ee787d083ed412b4fd52dc93a21c83f991372e92eaf2c29dae612fad65" },
                { "ko", "83078da0a4bf790101c68a277043e17b8d2db6c958c1ec043ab1f334fff194c65975f68c7324e835794343ee5ee379219d006637143a0fcdc28c962b90495234" },
                { "lij", "dbfe06419b92318274cc38516b55c4c89ee7debeb5fb1755eeabdf782320a80f323e2da8f93ab4b161da2927b8741af7d68622eafc24f2b57991c7219c543112" },
                { "lt", "d8b46b86d9ce1ec20d4daf446f4d3a8e8f587ec45b69f3dcdc434ea61aca8ed704f61ca7c48dc89ade73143b880299ccb25a82b6265d590d33497b794dfcafc9" },
                { "lv", "86233beb57a42e2fcee26bfcf10deefd48c879c8a729a5b8158f9c3d08111289d9f0ae0e72db46cec977a8637b8fc6d4a35b29607651da55cd9d6f76ee9e5926" },
                { "mk", "c85bfe9d68c2c59d647ad4c84b642d5e38e91fda449aa5d4c95e702236d6e0afdeeff1cf9d96c9978453b0c03f1941b17d04b775d9827ad2d4dc8402002c6ca3" },
                { "mr", "c0760d2d02a6586a22eeb91723feb5016c8bb3160b5f82ad0e4eaa13c5d164becf0ca8ee9867cbbd5d637a0e7a0726d2d9c11298970b0cee02f784cd6f2f1dc6" },
                { "ms", "5857a480d0244b3140ac54ee06a9f6e36580681e87711236084219eba79853bd4d6c6253b538d2ba8ef7b7f0249d5c0651cf20421df3ed83d1bda007298f7ea7" },
                { "my", "3e04eed9267ae6be2acb6f3882258399ae92641afa3200820fb9dbcf01472119552b026f429725026f79650f99bf85bafcbaa585e1f8a24bc502ff049fd49935" },
                { "nb-NO", "71a833cfa52497cced51835bd19601b62221406c79ec8a4bcf87e473f0e071ad49381372463819cd47f5d13d54b6acb4a434671830b4c60ab0e7f910b112574a" },
                { "ne-NP", "369e999f0283a7eda1816859f158355c69d9b34a59520344ecebed455e8fa5899f5bc728496e0eeb6d862d40bfea68fb30af93354990ae92d7ddeb2bc46a6d76" },
                { "nl", "fa2dd9667f3e439e9b1db14f4acdf7d63365bdfdc98e48841e2428ad1e9ce2097336c133c6a9234c5c9db143d45e63dab6b6d7efcd06e70c42e1103653abe684" },
                { "nn-NO", "733b4925825747c172ddd41fb044d2f4640146af30176509f10a5d8c08508f56c54212dda1ba7b914c6cdcb7f9d9c2e34553a8db78f052833c036ef18cb41a01" },
                { "oc", "1759feaf3f68efce96df6cee90de53e9fbceed8dae3787a8ca5739366563ca6a103ef3be63951ea716e1cf2aa326655f8e3749bfa8835f3353cac0b42403a057" },
                { "pa-IN", "e6b70cf634e1cd7663e2c58c5540b87fb1be08b81398c9b286123c1d168c13e2a62bac1239bb5d5b0a72168fa8ff3ff1674791ebb2fce76a938d2c5a234c4085" },
                { "pl", "ba1281cdd707420ebe8c7370e9d18dde6332ded10d10a0ec20f54e75a098d8e80042b4bc74e59bbf854fe99b24497c855dcbf15d7bcee339a9785a47a3ed6e9c" },
                { "pt-BR", "ea7e29350a39c8131c9a10c72c8b9c54ccb21f1f20c2ee0ced28defb66ff640376d7fb8d8d114fa23cc6b2bcfe1a3583fde1a3ee07196a26172adaa77b1a60d5" },
                { "pt-PT", "3983ec030a40bfd1a1bb1f483b3bdaf12572a67a1733d0c9b87a3fae4c12c197b484f59c1ab91c010ac720df572e0612e50f6493245c09c80e8555f2e325d368" },
                { "rm", "0fff3892c77aa516c7fcb1b06def9538f5ae6e9dd7c04c4bfb148b29920652da8f7e18a03fb839e69dd4f921c23796440b688dbac71e88846197bedba41c6eb3" },
                { "ro", "e346ea019cfabd94cae7497dba4640e47609d84e7146eff947c791ac0f0ecf7a4f768b78f71a687447aafafc1007e9537a33f7ea2946d7c12b1de22457d0ad2f" },
                { "ru", "1431bd67c79d24520857061b108913d661d73e1a08fc4038b495c8a59dfc48cbd1543c6ccec3f39f55b00b161f439c3d1771e450e7da8d915dd8864d0d9a3992" },
                { "sat", "597387bb0c8604b59d918d9a848aa33e2f2af0738a68d8e3d7d0a1a65f737f1d7163bc46cc566fddfd7a1ab858a971034652685851abb14504d26853a20b8ff8" },
                { "sc", "62f828fa1c2ff404d876d9794399e7251a39a96bc8743cd0e0226c0490300ab102fd103efddb3204523572d2c36e101f8133e38fc97a275a36669bb675f42af1" },
                { "sco", "7aeb0fdf3beef4c9445cbc4764b4235871bd4395cef231bf82818f0400afe010856ec96a8ea2cc8ba93ae32986428c08a93878c9ce751603f9a1d049398da994" },
                { "si", "fe36949841083ee859f4b81f7d4c09eb310f268965b0c89b56d3c6e481779f2de1b409e71f9f1288445732e5ad75cf4c64cd98c282b49a41af40713657cd5e37" },
                { "sk", "9bd084d16be6ee0f4f73f59ebf617bb7330076435289a0d3eebe72757a062a198649d431ec42b2afece05fda3b8f3415fd1faa3071280a57bb6557a5be97aaaa" },
                { "skr", "fee54bd32b165fb5ff1f31e22ae58a7288d998218e163758cde5593587602fa1993094b93d2030221af2887f8d4a82052143e7cd6c39304bf7d0abb9edcf7ff5" },
                { "sl", "17f8c80a39a434c82f08c1fb3c60ed377a05f9d9c89d64bf3fef080fb475412503da0ca54eb243167dfec71b9d556f2b9609a600260a2d88ff6a536c3df0cc7a" },
                { "son", "a5ebfd8a12d5c710f0bc63c3555a7c8916fe87c91ae3fd5e352e65cec5bc5009584b710dddd9fe1b0f989ea42c3fdc91e8dd8c9f3a310dfee111e6a47fdf78ac" },
                { "sq", "2dd7ff335d6d16b7fca36467c1838ab5b90a23ece37e84ed146396c54962e0b08b7bac994cc564a737334e6b2be7b7e70ab87cf66a739257834be7d4dab64c73" },
                { "sr", "8ecb8904915fc9c4ca328fbceeb4043332cfb44fd745514d73bca0631f089e0f8e6135ee21a86c7bedbe9faa8706ba9807c9bb72ea0fe9b012f0d3090f1980a7" },
                { "sv-SE", "7186ca528fd2154a8e075e97a167c626131c9663f5ff74212394f11e0ec40e6277b85f5d41aa36871be514509426feeef9c6ebd61e1165acf9c527589536ffd9" },
                { "szl", "41990d231a2153f410abea473229514db847f350dc26efe335f921fc61a0939bb49f924c8b0c4d8a9a3af447f8873db18710c2498831debf3eb31beebeeb9a60" },
                { "ta", "a89da7fdbd6f465a1f3c181bde402eb57e7b30a8f865245f0e56e7b874f4b6a4377905f39189e22e420805d2383e7feaa8a472b4d7ab7854490742d22a796073" },
                { "te", "3e7555759d2e12a67e591471159941f6d2344b90c672535e957c213e5760668da3047c39c96a90fae3270810706e93894d9a9c9c469f33732ddd51b84b964735" },
                { "tg", "ca1be9616ca80cbd55dea705f9acff77556f6a9c6a6a7a5decc962dec559c3a8de5151d2d1c11070c9bcefd4ce065544cac8ae09b03027da03985b9d0aea1223" },
                { "th", "e2986c8ab6a9fe2a2458b2b77217423ffdba53e5dbef2efbc17d353a20f7454c2c11cae9f518d6c7bf6a0d7a6311744f99c2ab1a56d789e12942a5844cb14c39" },
                { "tl", "f29dec103267a0db810849f7036bb1e6911bdb4330db03a66fdf9a85e4fb05d5c4674459820eac5501c3bd867984d95a2f3eb79b2d2b310a78c3c18b066fd9f3" },
                { "tr", "bc09c33941b56e6fdbf57ed5da139279b7a7ad6f04f4c37a7e34b3f0deae0c11ae63c437716ede68ee85f8c143d549e7124b874103494f4d9eb8a42eba355bf3" },
                { "trs", "ed656a00b1df2b6d3fdbdb859a0e7954fd88a52847e95bc30c4e765b3dd63ed8c0df2d797cda52b11a3f14089bd8e51847c05ecf7d9132f2bc04de76142bffed" },
                { "uk", "5818819ffba0726a63f4dfca871dd8b4a7dcb067a91c8da8642d76ffa2c46a120a1ec747bce65d164e80e129aac71c4a4408c09f5fb0f59b7a865005c29d8519" },
                { "ur", "fa2cbe894a7cf849228ea8ab47bb92abf2728828fc8a1bcde5a22070a3dd2a053ae0d02c22836e9e57b8e07396e81c22ab2de7482f8d51e7a94ffbd80e23f5ae" },
                { "uz", "0128f2db0521b7acbf39d89ea424158769f23143b6f0cc3d5dfc9af43f07060328c39e40a77eaff4f06f18c6ec15866b15933c3e6731e172a1af78b6b10da2e4" },
                { "vi", "e0f12fcd8b9fcf566c9151cfbfb539a3a1890b9ab2bbd3b556c07ee586802751a03ff7e8e7b7ea2ceabc0fb0461c4b3538084a5c941a308b64243e5bc4166f47" },
                { "xh", "5d294596f3f01a358524659450799402fa5e1f442579833977c499b5022e56b63d9f7cc0f13dbee63066141106c69c380549344ebdc6e4f671ade1f4c5872ccc" },
                { "zh-CN", "d0e11a827e2231666e89698ed9f0cb0603cbebaefc70c054ca5df0220644a3f1c98513004e0f233744c660f652c298735dda1789878989de74f30e258f13c030" },
                { "zh-TW", "8d3ae5762549c9c96b4dce8b43c52a62e249f82ce1d1c46b9b4b1ebd80daa6c61a0517d1a6aac8ece11ed29f5085182c93dd659a31155d10f6e7835790275497" }
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
                return versions[versions.Count - 1].full();
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
