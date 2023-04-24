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
        private const string currentVersion = "113.0b7";

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
            // https://ftp.mozilla.org/pub/devedition/releases/113.0b7/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "3f572b49a204f277ac25d8bf3152d2caea381637b2f834f050da44ba553d989a6c57e811f26e57fdd81668d869f22567b664481e154e21633719a65976f6d355" },
                { "af", "1196226a2887f85ef8b9f7012f29178d82a0c143697c0e631fa5ca9aeee1fdbeb369bb64a6bae3615dcb79a82882bbe254509c0a0ee5bf62db051536c716c224" },
                { "an", "93b87b0c861a0edcc930037c442d1d8f9b5db715a2f9d89a6c8a11e3b9a98842032fdcd30b7b2d6a30616adc15a0d5e2b70b48415b1065970b9b715e0be67aae" },
                { "ar", "73f7b04bb1f9f6093aa0e9233c6151de9b2819275130bd3d056b8e6f7d94e3575114e008ae04cd0c88f720946a9c9882f69cf75ae4f2377630f7e2f37469dea1" },
                { "ast", "c321ccc68fb5167251a3ef1ad64daca593c476ccc840a2ee792e7ae0a3aaab76bf3d96ed8075e0b5ba4b0987a176ace34acb5434c0be5681072f86c72709f753" },
                { "az", "30861b903bafed513ff722355850265ea4c0f02ca2cb90244c2ff57120e15f1d9de0cb3dfd7187be552c8a577cbff880c9263073a1a3c5c3133dc7c3197eb2f9" },
                { "be", "8bdf54cc03652c613f0675b1a236ae265c04148b0b2af4615cce9bf4f719047660e4e66ef230494e394d0fd9a74e2f6b4ae6d865555f8167976eac984228e6aa" },
                { "bg", "68240ba45ff410e43a10af14e826e4c4cb9e45c3ff7fc78ec625323975d5d1ee377e10b2bcf821afbd1a7b242cb9cd6954e10969cec203ddecb133c30d491e05" },
                { "bn", "1769b811c9ce03894c2f0023b81880aba102dcf85b65f489c71cafc1ffad31a7ac54b7898aca3d720d7ca5a4a3a99b68f8e70a5de12737a50829ba83e12f9ab4" },
                { "br", "1b47b4c17dfdad5f5a5796d0dbc17ec3d27dd16dadb46d0712f20aec5abb5922c874b3c4603be005fc02399394da6107939e07c9e2158736982d4e5b0b1d8e10" },
                { "bs", "31dd912af17d6f76a232c91366ed978b6e2a9d795f826b110431ec17b3220933be5184a330701cc5a3c8bfa526d6d7f98af1273ed15c95054b342caf0264734f" },
                { "ca", "b6b42594a2e753e8424027a6cf43ef7e23d24d19d769c721e3bef9468b72f0c1827c8bd922f475eba9e842b1f699547c7187313c2f12da71a650c94bf322387f" },
                { "cak", "90eb549965204380ca38395420eb91d11dd4790fbde8d1a376fec33294ffb3a57cd676d5190ca805a6a6519369298abe7da9e405ad2f8e71aaf56161883f2ca5" },
                { "cs", "0d1c0d73b05d907b0246220f718c8b5c43aaa478037357df8b1b8488c36950e6041e935c7a31f9381c29fa38aac912106c8d7d4e48d002ca9e192482bcc85427" },
                { "cy", "e9a97c6f9afdf5d4394b858177a7052c3256dc598c2dd7dd35092b1888f6165bf21438f5160f7e8d35a9a497c0bf39a2278a42e807714df8fbb204f86a44d30d" },
                { "da", "2ba601a595bddb0f2b0d5f695ac9b6ef7f4b0cc3bb300d997a707b0eb3db3de01bda4c8128b651ed691c13e8e45ba5fee9143ee6bb461a0284ece722486d2b02" },
                { "de", "4c30461833079108c4c7655d38459bb457c4acda74c2e66ae425ef4d96423914a3d9324491f31ae497cfefff433e4b3d1c9ec902462b4d3b92012f7c89abf204" },
                { "dsb", "c26e8cc5b2eb0433735ce80939814835e4cf523fa1e53c258bc1b8c9f5141b3a6ac3d5c92801263474baaa8a4b14ff7e367604be999e757ab26da68a0523bdb8" },
                { "el", "48a35e4e0c7e82fff0547525cccec5528bead7cceb1e4defed7558c1f7145834da1d59d9910f864f39b79d2bd7f429c6b93d634803a2e932e43e2d486b273712" },
                { "en-CA", "63d892cc84cf3f23946ba327126d8f26329419ff9dd3a38560ce507994a1fdba489784572bc3626c0817dce5052b46f379d1e52c2e14b61e9c99573e73ba62f6" },
                { "en-GB", "730796fee4bb6ddd417bc8617a97b70a5aee26308acf899707c955efde77cee3124191d1c2220027e25a2cdba642fa05572226c35ebddca9972556e6920fa551" },
                { "en-US", "f30fd9d5b3a2bd02ab19c1c8e975a2862b94b4098e7df1a9ada0cd926c902bb860a37fc553099875f0d68c0860253fa988f338fe52a6e2f4e5b80fa880eeae06" },
                { "eo", "7cf3460f389450957dd2c1d1170dabafd9a20caac4e54e0ae4bafcc34f2c4228c50fc3806f3a7bb241976e90f72ca3a25358ca6649e6d6902774c6e2260ef559" },
                { "es-AR", "91543656c89b5d59d705d6ed90cb5363eae71cbc45e0fe5010b1bac144b936a8d05cfbd3cd73d2b06a637d105ff6ea4379af61a6db61cb2db9e01675fb77f6fe" },
                { "es-CL", "ce726479588f182ff801881c70cced2c1fc562d93e51c295f07a4162fa486e35943402244d5b991e12aff928a69142a1413c9b095a8342bb965b267c3050af08" },
                { "es-ES", "b692ce73db1b15c99b1d0e3511f7dd58b0c814cb3cbe932a777433e8da54828226abcccbbdcc8c5cf07a4c279603d2ffbaa40728fd39dd5395d40f2413486623" },
                { "es-MX", "52068dfd97fb493b347d217b6dfb6b822fa5af7040fd1031d17ce12dff12979da3424c8a9e6d99dae52e1020f8cce784462efa25fe01aedea1f44a157dfd0924" },
                { "et", "27f47113d8bc50c6e87e4664f0860382466f1f6eb55fbdcb2a8d278b6922cb8c1ddda6219dbd3b243e562cc26d69bb37e00b65106b45432592b40b6b0ca6a51a" },
                { "eu", "d0b7914d3274f6f394b640619d660c68ad4af21c55f9c2cdbda1f783d3e6cdcb43f7671aec5a580adb824b0d6ce7686da001078765d5ba5206be831d700fa78c" },
                { "fa", "f9a6b8bbffbdbe94bdb821f311ce8f620e56e1b3cfbcbb844a497a668a8927f3dc210ab36adcd82d8f53c8b0ae5876f0a62b0143ae6ddfc634c3c20c8d26059c" },
                { "ff", "4857d9696b464a5221b717b8a2782c03018f9cd5474732ab22d454f88387b1dd0d35c1a3837c718fa25d428b541b2f76a2752cd3adc3aaffdb25023f5b136a66" },
                { "fi", "7c2f77cf48b728fc22ab5a606bd20893a12e3f7e4c49fbecbe2c32d15e8e65e92c34f3c7e40d33b1224d64557ccdb8fd4e38d668410b7f4b7568e0d8bbd8553a" },
                { "fr", "6a3667855fbbd4827b816f90a09fb3b918310a4558345cfece95520bf6d72ef244c07df351b323f96ba9b34bfdc077473dfaa67ddc01fe288757f115d9c1b670" },
                { "fur", "c1f694e1a0b4d591d1d82cb5c55b4e73619647e716a1f5517e35b871eb46ef418d5c0dbf65c6646fe5e73340902cbc5e2adc18d5822fbb0e3af758131205c0d2" },
                { "fy-NL", "b6037c59ce9b4401d9724cd5feacc505852ba5407b1f5471168f868c21a5c2e3cf332e13fdc33cb52427887c258b269f53bfedb03847a89aaca7efdc79b1ecac" },
                { "ga-IE", "71f5305188041c345143a88d1f2df96b71720893c24f090307044fd759ac89db69123452482db738e41c3f1fb20d40cfd97aa612651f6f036930bf7df5fbd44b" },
                { "gd", "9f90ec7d905bf8d442d3d552f8e0866e9602b72c6e7e59c363f040dc88bc6c2fbb5e5cde70c0ed5ac0adb15533d4a1672806ef2eb0bdcbafb2fbc7e2ae0fe1bc" },
                { "gl", "b4cf802362a89f5dea6407d0138f2fd25692b4bb42a97453677c6cdcf0c530892b476fdf6f6e30a74fa95e2c5edc6527d058281c090ed3b4044f2f95e5ceeaf6" },
                { "gn", "cf20b2448822758ed0b5f18661c68fdf7cf526b2c9d33ba1387d5230c6d3f0f31b612e8b82d55fa011cc9f7946cf4cd976379d1d65f7a74553876133841e4a23" },
                { "gu-IN", "fc5aa19c578a693ee72b604a60a357681225f99ed29637160cbc795b73bf6b1c1889823a0de814cb705244891a5429e036bbe735967c4c4654502136b50a0c4f" },
                { "he", "75654879be0c97c85801772321c280f567bf58eda6bd94b51355525ca6f0d332479d89fd3484dbffd88cd256c6b692f711d27d6bc73bff28fb62542333c11f3c" },
                { "hi-IN", "159f12e5ffa662555905ad2ede3cffe17e1c4211152a2beb26618c9fa9a2faa00fed340e2d0017bc2aeaa23937ebb13bfc307a4fd0078e8f9ba1caa481a9dd48" },
                { "hr", "96e3ec7f7f4f7454c752b7029e01608790c71d3538b4151e6690b649632d9f0b10f49d0b67b522bfac33fd1fb282d5ce3fa02ca4ef512e2655e8de8cc1e96706" },
                { "hsb", "7be639e2bc17e9815df5da7e9b1f097eee54d18cddf72761c6377b018ec5322888c19c24fe244a562e35163800afbe5bcc1e5a674f7936ee789e55c7416557e6" },
                { "hu", "c166ba458e75ad007179d5256906bcdf4f379b747c5c5048d4c76c0522bbbba36b1f84d6a9b376ba0d76c0c4d642dbdc6a3c8b1c9080d6794323c469c5679a8d" },
                { "hy-AM", "b81cc530fc90d46ddbb3a2f87e3d0976c9dbd84ad269c1cb1271e69e9aa5a1ce6ccecaf60bce5912ad14710b6ba53c42ed56cd94972ce91cd718f57cfac1c4e7" },
                { "ia", "5adcb2ce7df3c576479ad452c5d45ad5bd269fab7a64758f8eaf1388e0b2e087ff5f826253a31f8a09c430fc2046153c3200d0f843853e5a3b1cc3ba96d2fa8c" },
                { "id", "44eef29fd43b27a50db985e9d243f2be1439af89e8c31cb345ea5c3d3cf6c3713e496e58179c319ef77d1f499888b52bfcc3b865671d1b4a793affe94c6f5fb1" },
                { "is", "8c217ae0a03bca98a6b390ef38faa5a0781ffd069d76a3da0ce6e36c695c922dfcc9b36d21624dc847d8e7b8129c2a40c8f7b716b734971b0c6adb7d665f1944" },
                { "it", "665b001d3cde1e22e33cff7dd370848a35237074c6cb478c57e913058f2d866a136c534c247bbbcf7d33f41a65dd5a76e8d8aa650f4330e0199162625070d219" },
                { "ja", "e1930db511ccc79dd566dc7a39b3e02874108ca05410d77a40ada38c870c8337b1100fe92557d425d3e61464093dc3f904cae89d81b99a14a7fae8ff730c6e5c" },
                { "ka", "f2ad84bc9bd503b07c73abbe3f8eb7abff28732af7e1ff228f9653a5d064331cfa7dcac86210536d8416b0624e688385c1054bba96ce1cf1047ae34929cbdf42" },
                { "kab", "8e5736d5a58fe5a451dd31fd74381ffe6601ae2290c6a56d5c2af0f591234f1aae77e160142a77a5dd6e967f9426df846b68495cb64716a0e9d1c9160bef9238" },
                { "kk", "32b2dc38743eeb303bd5c24ab2b6b01cc25ba54fc5074bcd695db1db846e220559fbc868954cd5c57c28542146ae22eeb73ce2987171f7d8fcfae8369a3905b9" },
                { "km", "620f8ea45ba3d5baf0968ff8b895b03c0c17de134a282c740b2e247bc5fa0968cb1147cbee470b15e10b43911d06798a4e5b903c1c1df07dd3305660f24e56ed" },
                { "kn", "3ae5d4567a9774fa96319c193db564fd3d6ec27c4e0e350588b6a939d07e586fa24f39cb92ed4dfd6ca9e899d97e19322950af760c54151973239541f14bb9ce" },
                { "ko", "32367fee6e9a72fa565ea304e9e7bfbb506cde851bb848a99fb5c27589a021bc4932fd403816180d545c7c4f064cd345c14149f7daa494c47b982a3f849a2bb6" },
                { "lij", "145d84838fcd6db6580dde491b0db4f8f756c56e6e6164538f270f29cce04c8ed9d19c290d6251848d8da5d4eea7b4d63929315ad34586e938c1d72880e3bad7" },
                { "lt", "482838bbbdd16722141b2720dffa3ccb025b0223ba11f29d7ddcfae19e0c5ca868b55292a3e80db2e37d90919b0947c2f3abb430ca1fa813d83bee0eca9b3ae3" },
                { "lv", "52e661fcf831659186e1f184d856d3ab4dfc44bed9e6c0ca0ffe3825afec22af23a1173ff16c679f03c2f3ec148f72d836f874a1c3f8d561546ce7fe5c54a251" },
                { "mk", "42469bf9d3a2b5b228b0364eaa6bcd2283c1125b0fb652ac8259eee1d6dc45314a870245d0cbf4938a6960ce88635c5792e0ea3c4349e3ee013a939ae2a6fbcb" },
                { "mr", "99c319bf40186c6fd1600e1c53109390bbc75c08ca8357f66ace4f23d876e2eb065f814eb651a6577a1264672f926224f0c7a23d3fe4faaf5f771c4322b7bcb2" },
                { "ms", "7c9dc007ffa42855cf30bb6e2bd73b9795095595ad10922f09a0f56502acfd1fd6a1c624a455db83f88204c5e695ba6e38950d0cddd09b5e0f56f5163469fbad" },
                { "my", "6190090dd7a42e9ce7ab217549be5380d9ceec5ac6a7d9a16c357796487e8dd07156032eecff71b1fa7c7877d1a7c02bee8ec5e3cee7d7c60903e1daa224ee83" },
                { "nb-NO", "6ef31397d5bbeb0d53248119e0c3ead25fdad488cfa1c605d79a441b29981ba8cf221fba3073ad379b7112cb8a97eae542c57b8740c9d94528825a6438ab8623" },
                { "ne-NP", "98bef424b3d77ba983c9e3335a242220ab0903f18064058ce46c9aa0520fdc8e1c5ba9066231c5ff2904f992f82e33d91600cca3b9740601b90c7f6145b1894d" },
                { "nl", "2b565a9c6e2659cb22cb3e6f9dc17df3bf565ebae5aeb5c32966f53fac3d6edfe6b8c2c327804bbbc0f6623da06e8b40dd11646b91d03cc7721de26cce2fb561" },
                { "nn-NO", "d5c26ee7e9a43fbcd7bdeb1f5a197c0d294a85adfce0ee18408069f07b166b4140ce9aa4f5369b19f613d449106107264640b8019bf7b23076173d34ea141d7a" },
                { "oc", "fa231fd612b4f98505a4c555cde7693bfc7cb77a75e5a89accfab1036720dec36df28036e6018fad8c17f53241ef3fe8039d69017bdf9510f157382fd3d29f34" },
                { "pa-IN", "cb17bf1ab29abd5d5184aac23e7994699df9471c6a8d16a50e5a177b76be37e2d3e949627e6f63ae584a813353b706cb7264146d9b0577cdb7d467559d34c12b" },
                { "pl", "dafb0d48e6cea15582fd7250ca8afb287b76fd94b4e7465ca7df9cefcfa7b2b5bd593cfaa55fb71f4e9c6b57e21a182f0f4b86633bb1dc5e17dae55b14ce9bf9" },
                { "pt-BR", "9635ea6819383c4668ed313899eb8e76d18b494dab42b0e2dbf6ccf399594e15e00bdad83d1b3d6abbe8c792c1a8b201c45e0fdf04a251344f5d0ba33f3a9659" },
                { "pt-PT", "fd7730f879cb3ce2d81431eb2ac988950bb6dc5a713a2216ceaafa476a0212edd72811951d0bb92978341a53cc50c1e81f5c607d67cae56016e5749b61eb1105" },
                { "rm", "ba52fcb550c5fa41ca3e2a2b52be39e63c241390336b933c9e6d9bf8f208c2ecb0082d85b73c48ac9e51c56185a9bd1e887f73be07f729d32806929b51ba00f6" },
                { "ro", "1cb3a50bf492032d42bab162714a891cfdf1b96ddabdb775897385f73277fa7e59009801a914cadca8ea5af0b0f08fe49e226cf0980cfb18bf2b5c9b9ed3c935" },
                { "ru", "442ae0bbac17e4f3c1d949286797f231f8be6c765baafd7571ae049b9dd114e4e9cf83f962c8eafd2bdbe7b8cf5f816ffaa9d2c26ea697adfea1d61e49ee50c0" },
                { "sc", "8c7cf186dc0f81a3db20ac1c675385eed7133a562ccf6ef84baaedea744d18b5ea3f846712ad7c8721435e9b15efd5aafc111aec21e917f414be0343965b2d0f" },
                { "sco", "00f5a0b4d0dc239165dcdccf4f2d3a9d521f5fea8e71adc1576a4b1f6f51af047e5e9dfb363048bd218dd5987dbd34935733bb93e61a04ea892379cea2f89e10" },
                { "si", "fff616f07d58fc81bc780d7dc5438dd9351061a487a80eee8ca6e27860caec587e1ab79fde009dbc645e1231edbd2fa5c622d810d6da512c1e541a7ca19be42d" },
                { "sk", "91d444c269294d89a1794e8e8e55ca3d454f26dda4d399831fa4bef54e4969cda060f9aca250bf4ececc8d3390423ea275a785e9f89f25a108977a61fb4f0f24" },
                { "sl", "a6d43db4e16def088728fbc97cbf31adf1506ab718206064dd3046798283a5b08240a5ec107fe253f9a59c08396a14355fcfa4e77a12ca008c82b563ea26d263" },
                { "son", "2bfda4738822316d9d452c1a0afaf045e2e9fe8a996e6c4b20fe816a68536349f4e096e21e8208bea6643d8292db26f7cb80c4643e354191c43b346d28db7b9b" },
                { "sq", "6cfcdbbac22dbffd5dc48ad4bd29aa8ac10ea4260eefe4c653f4a7098e6a8367a208197468797558e6331d77d8302ecfdc7c213d8ba115f390f57f69432f5314" },
                { "sr", "1a1d94363c1ca67d6c478e40d83b5ab4a485312d5348c8899f6f1e7f37a06c539a0d691c13b655dfb3de1488396fc9fe8fc6f0e6b4b48558c0f6bd328f88c77d" },
                { "sv-SE", "e4e27917c2aadaf6ade78dfafec75b3c45c90f5eddf2a2e7723e95e175a092cad20e426ef2abbf075c015c905fc0f524ba8c26d9de60aa9fd3d1129773b1f3b6" },
                { "szl", "c27118bb7bbfb73d75c346ed9ea8a89a83eac7a8a9dbcfbd3856594858a38baa13963864a218e7196dbb6dd2c6fe805657090993ade348df0f2268fedad75023" },
                { "ta", "ad08647d9a5da999ac153b88cc6efaa98739757e8032f58198eab0664e91af44011625ce620eaab42167678bc9f49a8a7cb21764643aa2d7487f27a7057229d5" },
                { "te", "9d55db6c9cd74185c527ee54d454df6b99a7fe241b0620d28214bed2a51763fc9059b951d12e8e113484ae908bc1c0cbd1e165fe83dfaa56d26612ef87b3fb46" },
                { "tg", "e7c51411220ad7d2caa3638a904e39fe83c2d79e59d331d61f97291a194ed7fef0bd12aa4d024441dd44b611718e9d5abecd44618f0ab88f5d190ff356f4f60c" },
                { "th", "9dc54790834218a30406b1a4df92998e2af12bfd1d6f522cacc44a88c9e5767b1152927590793273a85500ebd1baca8c52da349a24888020959cb99cabba0ebe" },
                { "tl", "f06d251a077fce6c9f124f11912aa5798e80ad224ac1e761a3478c802fda6400d3fefd163791c9deeb47ff8cc7bcec3c64551c4fee01cf09315c57b659fb626c" },
                { "tr", "4ecb73de131c4f0f30283af70ce59ad306826c8e5266e7f2c5cb0b08d84110bd764d658995756dc6f106f1161373930bd6fe6a3ab287c1b0a0cebd4c29058f10" },
                { "trs", "ea350eb19f832c81c6d382c023294a69f87ea3fb7cfd6dd18f09e7eb35141209c47e29dfd500e586dc31a29cd855e6c27067d1e9f0e7ec57e1c6ebdd2e728e50" },
                { "uk", "6d44e6f156d4cd40fca41ee09ffe084a119a664c95ce593b6590b30947396ad91e22c30dc9328d5893debb3a565bf17727d9944d5bdafdd500b8e53cd7153db0" },
                { "ur", "79a66637c657fe2929225a143068aa82b26a2ceadaa04437f37cf2aba3a609c929cc874305ef86605709a1a513382dedf6077368dec5c421bbdc2afecdc8a308" },
                { "uz", "d8c355a54042180e00a4e2838ed57acd0cbfb50d6284b1d5fb26badc517d639ce94703961a34c406311bd114d30cc128ade9708e3c989e7cfd686094a61ec2d6" },
                { "vi", "b74c23daee8d770bc1cd36b4d0f350609132d3166f3fc91f838163baca4f5f3081d2551d954da3987430a8c3071f7189148dd42967ee8fd068812c04ab1cf949" },
                { "xh", "861808966dcf98253dfb3504a80e7c6b1e6e62903cb2b46c60a5aec282c74fc262fd3830a2428d86c56c173530a07dfd84ba8170f161a81b7808117436712fb7" },
                { "zh-CN", "89fd83108354537b17e0173fb2900075b064534efdcbed2a9d3e0052f9a7d2b678dfe05c53fd6a57562fe71fa05b8958963f11bcd51cca525f2285c69cf9d1fe" },
                { "zh-TW", "da1d165982646b9e2959fbb919cbc1903b5c457c12a8f0fb3e1a4bf64fb72769a1815f407742519527385fe65f36ae757c07736e5137e3e58dcc53cc563254f9" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/113.0b7/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "32c86e7b9854a5dcb1c850443b422e116ba83486570a3371b34223a7a96c3fe74b8b58857270305feec6fa799e86d0f1238921ae7ff9c58092aa256135ff6234" },
                { "af", "62899b9b4995d948f20eb550e55103487b054b3c3044f55df0b0a670597e2284966004330219810702b1b3860dc1269261317829f20c2d207ad079903dfdcd46" },
                { "an", "24530bbcf97686f144b3ca20c7026230564a7e34d1b6e6ad886cef28d7b47c128734f8a44504fc3aca3eea3ed4aeca65af136ae78d82db7e51d27d2ff1b303b4" },
                { "ar", "671d52ebff6556a1e7157f4c6d14f9cf15ae9c47b9054e52da1ee481b6e5fa1da7b3f7955c870a48962e47ab9430449a65c9dde819ff484f7cd296f17d7d022d" },
                { "ast", "f9fa94d66ff5e3a3228e46120a560427e0becc3bb9d5c1a61987d8fcc37ec3b24af53274bff337f922a86c4576f20e8f453f293da4b77e07a0e273cca76e357c" },
                { "az", "4f8b24e23681c22084fb438e8a81a3904ad633b641e21d1241832ed8c3900cabb99c76d37a91d15870a6bd4e04df415b1b4fc50aef44aa58eba0d093053e19ef" },
                { "be", "9d629ef1bfba484f3ea0aac1f7bb77eb6f3d0c6a4eac464d5aa8126f2e4829d22a84dd72276347d615a0fcd8920a18d4d0dbfb06deff9c1069b98bf920ae6ec8" },
                { "bg", "1a8e645bec967bd9026012df64e890ba8662f4473352905a180d10e630e39a930258966b56af28c709aa5c70103754c3e919218516d5fc073a6188805e78a844" },
                { "bn", "efe988c04884b7d631886ac3783d4941ab1a898de088f9e09c3d3ecb581c4bdd79a3bc8371a863d26b7b8573e0ebdf117bb79cf975de0d75972d1bb630955adf" },
                { "br", "429ae19bcd3249555f1a8f64c92ac196ea81938816c34927a1edc458bb4818d5e1efc76189b9c148f10ce0c88a49f73464f7f5e2b136df73ef860d43c440aa97" },
                { "bs", "9e2a305a63b6865d70cd9ec13c5c5dd0d93f5ab2065397f4baedd8130b5678b4b68572629463164ada74980bb9e52ff00f01dc77f85727a536d7d0c876516a79" },
                { "ca", "32fbd664861b6964311bac845e3f193c8f065a4d21c1c2da62415059c3d2335ba283e6d3689ef28c186d35807c8c3973483da5a67e7503a7fd65d81c033b9ec8" },
                { "cak", "6e7fb79eb45e35a388649f5183b9a2845c830470243da520a25857ae8cb666c045120e4cc1eca34f0bbadd30e1fb7b2943a3602b36e2545ddcdf15e39d75173e" },
                { "cs", "4a0bdc3bb344b19380fa2c319d052250ff92bc0839cbf29be5b940a64b21f59e976a6d63cbaf4c6c781dd18283dab5823fca0d68a131a0209430d55b01b5ccc5" },
                { "cy", "7e1853945ed7f015518f17d31a2300fd464deedac89dca6d4409823ece34b060af4b17c4f541656eb80b1c084d1077de761067d1d68d2f9465686b4a3c30362c" },
                { "da", "ec271542eee014a66058d0d2dc509bd19b016d7f291854c30107bf110d97ad470753ee6d6efd4b7cd135220f061a8be0476e12f8b5e896761b256e4b884a069e" },
                { "de", "75ba0d08a427bc18046aa0929238928da727dadbac9b4d78089a52a8e316deaa3416ddb29204f1150fb18c4f2da08bddd9c80b0ea943de13ba76369d80340d50" },
                { "dsb", "6ef1e5ef6050e9a736db2504891b50feeb0d931b6f03c20c2f28d1b4c4ee41d5bf25a47d0c45a04e6a2f3fdb81e7089e1b16b9877518d2f9747809c84a981714" },
                { "el", "1a4dbf48c709386298a9fe920a46450a443998e80c5bf56fab9756a742dc1541996b663e8a01ff2100280219e13fe5c69e38d42706a0156ff6888f10b9770c89" },
                { "en-CA", "6b1e858b6dac67307da8cdc5047da888888a534a7df5ad6509d77fa04ff78e09cf4d98c4eb21c7e5a9d1da9f0f98fb134187d1a9f3fc5c68e832da37729dd93c" },
                { "en-GB", "0928245e3285616380963383526f6af13f07f8b160cc576c53de44b7bade2b417ee4493dc85929f37dfcbc0db4402dc137a02c054226f4af2a3d7aa93833d8ae" },
                { "en-US", "fce854f6f25ca5a79cc789dc0bdbef27dc21074e5b058a576435b4978cf7d1316042345d4f4fbe4c868e336088094d94ca404553fbb5d4fcfacd857b19c93bcb" },
                { "eo", "125743e666a57970c0f7604bd372c850f5ff4bd701a7b9e229b8ce4d3191581ff073dbecf01b7ce21b808faf3572189a6f6d144776d6892cd41f22f0f9184034" },
                { "es-AR", "25305705f581f09d8f375451b82120ee3f6835bbe9dcee98e246863bb17a1d08878d906620e1dc565cdd6111962b5d2d1ca8954a41d6f70be76c9e8bfb44a37a" },
                { "es-CL", "29fc2a891d01b73b0fb56f039600f5f36e9b142e51dfc5acb0a7117f1315dafff7f2a20607069712a14e0b6ad45f3983e6936389bcf36e435e9c2cb71d424f21" },
                { "es-ES", "462512162532f5499410f99ce0e6ca887d483034c9548d8664c2a3609e90948d5f4414c88295b0840a0b0b2c224e139da198fd1d66f32a340b2730cf50c90696" },
                { "es-MX", "bca120818cdd79d2bf59d2d5dc69008b74be345a36e287e1087232992b9b95e083b60e7918ac9cdf95cfb9c128f691d18efa84ac226016e2c3ee396728520c5d" },
                { "et", "4add9aab611faaae8b45255be42eef83cecdfc7ca291edb38ce96b846262b18865d966423c6a159efec48af382f39565aa3e5656967d68e3209bf7472dbad691" },
                { "eu", "0a64e09f12385501bf1ae3128c01c3400f8b03d679e3da205ecc60b63c8df5afc35bb109999bf4413330ecc3fd4f21633599e6f50b16570d254c86f3bf01c3f4" },
                { "fa", "1d4b8c14bc7d58772d19fde790ac41aa19a4410c51e2ff2dea0351f4f19ae169099e8e5d29bef25c4eb78fa50330c0ad238a7e8e77f909755efbead580901e58" },
                { "ff", "8aa90e663359bd26ad65ca8ee19f8d21434c5496c2bb7f06d9f3a7d49f027dbe139c53f7c9b211254593d82fe057a61379f83d2ac17ab1a01f2483df1478757f" },
                { "fi", "e7029ec9cfb18e5090cd4293359b09713aa4bed7115a0f342b997136e36255d0266c77ed69d79b4d75cce28fb8ca41d546e361d2ec533fda6c68e8d140fc9eb1" },
                { "fr", "b3ddaa5f81e2a15e46cd12b96cd1f31931bdaca7de86ea1b3d5b4257cf5603450aebaa2a6851c840665dd332f5938cea3bbbdff5b1f967caff4c2984ca4b897e" },
                { "fur", "fd1a144ea21991f42ed9aa6f481ea44149004032fa23199ca2e25fa9bf85c238a54fb91e3586cc0e8af64de43c0893a62882a7ef78821258f5a994c019690853" },
                { "fy-NL", "4f50fab40711c9fb570b002e7c5c86ea742e345b36d435284456c6aaa1d5296860ef207b6e6f3ae23974dda48f6973b75af2e88ed4304acd76c00e3dda418d45" },
                { "ga-IE", "2cabdf82c0f88f933ac61c310e5ab7c30ee1aeb0c5ef9a637c54640ed039dd911ec0f63e3dbb611aad8a820d42a40fe041d16b78c4b72b92839b32e04623e640" },
                { "gd", "635e9d30e03d32dc99641af255c45a68d69e5ced3fe70d4c3b75f4d39617807d219bc2af4badfe5828d4ce1cbbcddd5f150f9531fbfd992681bd942ff8330996" },
                { "gl", "343a8d8da72d5137453aeaade40fada58210bfdce116bad9916398c524b7ac618072cfe6b16cfa65abed008df18c82233b042cfa40f4688d0e30526ba3e5484f" },
                { "gn", "b98cf2fcfb99f7b2cd631c56c09c4fdb030b3cf7441228be9da3227cc1f0234beacea75c0a62f63755c5a197c38c921a6b5de59082bbe86d84a3cf1b5f6c8c67" },
                { "gu-IN", "d258c86a3f6665ff03d0babf136c2b5b5d22fc7baab19c7329840a0d955bd81b20a111e502d0a3e5ba5d3e9d1d8e1406d8ce16a90c97404fa559d70a29bee2ec" },
                { "he", "0b5f8344994d948bcc9bf54b19676a164b3af3592174ece2cbfe6521076e5d7b37cf566f915d10827114175835db24c21313524b2d5b6491b91e7402e3346f68" },
                { "hi-IN", "79c68e9feab19afe3a5ba903db13a88d331db80631f215d2c589a0fc957ae809362e0c888019f9b588f84c32abd56cbd39a9ebebaa2c68c9c2f8712fd7dcf1b5" },
                { "hr", "7e92cbf1094e86925d03ab4cea18b2e351e3a8488d7694b4012f5983351eb85871ac8cca1a2979d04f3cf00cf9fb53daf01947e70e58f44b62f97f5fc25499e7" },
                { "hsb", "8d03e6364cd03905c5fe50fee383db8851fd71a45a7f3760430b6207c219e3bccc9d016ece16f54326805a25f6b8d5df88a74a4c9630744544fa73e408beba05" },
                { "hu", "ba60ec73b0434d9387b9d137560e766129acd500db21424a123815074c84972e310a77db03f9aa18a836ea86b2ca3eadcd3a0310a16a695b41245e846724ce86" },
                { "hy-AM", "7a877da7ae5f488470e464c4f97c1b6c6852dffa835cb4f1c1a772c128c935ab8bb7c91c4924310c99a58a1bda16255afbb8b9d5343949b53a3be984f533dea4" },
                { "ia", "3d151d8f74e6b58be617f30520c1b362feb4c24fc6dc1cc7cf142395c67eadcd53281f6893f69fa1da8d2b7a42a981471f11d60ff9f6c146e3a5657623f39aa3" },
                { "id", "148416df3f2827df0a92ca6894b09594ce04a97a6284e47573562350645bacedbc337a407d14318e91de5a01efa8753703e5fa051abe65c6bdf1738e6f9ac78d" },
                { "is", "b597f82bb1305e93dbb17e3335f3f4227d0d5a02418b3d269937ce4a9ad4a78d05221040aeb2427f2770f74103369f4b8fcbbcd93b57749337eecbf150036980" },
                { "it", "d09c1284ad7b03e79972467802c175cbd3654ac19eba2c0dee7d722d7795678ee95c2c339ad56ae74c513efc8546a7add849e001ffd47b03c4b35ecf0583b7ac" },
                { "ja", "9bccb3bdf0229abb64b4d6b1136aa41b64f154adb6ec58d46cbe6122fc83d6d52fb2d75ba18ce8cddd5ae3e7d29927f0938028ceb42b50b54eddc23e068fe22f" },
                { "ka", "1f10b7c4143b52d835b167cf10c67c3c9d7c9a3758f17fa1c7add293e4b3845d2fc256e91263d412a7b6c3d7cbb0c9f956a4d497e002550bf36c069dc089692b" },
                { "kab", "29e3b1f1597bcd25aca364c7d15f5abf5a266c98798c230a3cfdfa2e233d484cc80735f00459de4cb40ea44040a1d98510ff14465b2f7db1e932d3cb173edb85" },
                { "kk", "4106c984524c85005a5b9492b67d24d19942f7c11e0355d906a9e3e6c0c679808b675a55441024952adebe1731132ea28b6b35e03f11f856907e4c77770db6c7" },
                { "km", "0ab08c9ad96339d0d4be54701a32653ddd13c245223ce5fa99d0403ecb3f91fa2824c07cdaafbf7a7f12f6d29ab0de4a69eaa7c1ae55bb9302069867c97239ea" },
                { "kn", "b175f62a1cce3f4435a6a5d27ef30e9c6ff3e2859fdf400c8ecdfed9c99e34ac05eb0b67a1f95a401ba326d7b303d2a1ba8258c6ccc872afa21b26b0833fbddd" },
                { "ko", "923a1a666e52b5d7d57916a137382a72f91c039d5a3ab7d50bbed776a8c973744819eb56d5bf78ebdf7929398e84e3b211e9865be4d6ad064dea433dde91d05b" },
                { "lij", "1a006ab0d3953bbb4e98b202ecbd06192e7387152b2508f94b7bb02ae868ca9c15e8f652b3a2e9a7d694e3b164f5b5310404d3e663946d82581eab689f07e375" },
                { "lt", "ac0014d431ecb12b5bd5aab5da466c165bc3d2bedae1f371f6d0a8bb9e90ebe1c452df02f3ddad8402cbc22dec789e3ba8455ac106d669e22269cee0f07ba21e" },
                { "lv", "da6c2d88430895a28d4cd512f6960813658696a3427f71072de6bb2ca74ab4a2157b706c13f24a2497262824ad2932afd1ad1e47ad2ae785463e076a43dab627" },
                { "mk", "cd08d1f9b7a1783eddcf9fa36479ae5a2ef4cd8ca30a977a80f932998ca7cdcf06194979da09fe1c3d074ed143d5eb96f51c91cd559e737ff497bb2ad1429366" },
                { "mr", "a98cd16487997a0c3a08541f01528467e5c21f1d969fd1b1ca46f31a43b7290c60787740b9f9752376f81186523a766057db80ce7971ef925cea3a05246760b0" },
                { "ms", "a919e9daabdafe7daf4baabb31910bb9bb3705790b0e01fc5f80bdf58dc32710f363b6d53321ca59cbbc30c76129354f4f903dd0ad58d9f6cd8456831624a9da" },
                { "my", "9de8c2d3e4055ca8a92ce99bc38406e8545838427249cf44842eac549c00c596a1ccc3d76f8c60d66d269b77095be7a2716f11a039e854979ad58f211105394d" },
                { "nb-NO", "e84ca325e09f92cb68bb4724506ee5c4c296dbfa794659bc68cbb866e963308442e700234c3df0094f16c13415add1debb09edcaf45cc2c4838930f5522d1108" },
                { "ne-NP", "ab5b4155009ed71a9a7045f73deabf4d13cebf69ce1a99ddc51c1f7fd123aa16d8807b2e91f824d1933bfcb02d1890508a9818f36c140439a263e5eb87d05c35" },
                { "nl", "697a2ea2749097dedd3f3afa716454ed719b9bc80e5a28121263a90e5d99c452c04ad02bcd26195e0696fb102918a6fee6dae31a2bada1c2cde0d213961ee470" },
                { "nn-NO", "cfce39994e0bc08ec4ddc9f82ff4c34ec003ff8b512b4f0425b73aa6f49b43a4f3fcbf9e6c20137c890b6b133485e3bc8c86fe70e595427dcb4e5d57a39f45fd" },
                { "oc", "6ac7f63b184bde7b5a96c95c55c46f0a9bad95dcc44ea3e6f2dd7c6bdfaed39068f4258585198e3716cf870e855f6e8151f2f45c767b9b14426269c97e5f16c6" },
                { "pa-IN", "5b70dc13ac0d585ee0df363b284f816ae12eac95fa2fa6848cc63bc5c82c120b718bc6f4ac70866cd2f6b26440545a31a6f3e361e79af32942baf736bf773a01" },
                { "pl", "dd75ed005b8e402b8817c3c1a35d172a92eaaf8fb0e15e557e8dd0d8dc3b28d57ad34c17db4cc32198975f8d15092afca32380337e78d8d3f0a7ab10bab0ef3e" },
                { "pt-BR", "3a9bb7ee4cecd3396b819e2f1cb838d0e0bcda55c41ac8c48b28493d0371c6427eb465c2dbfe713f514462f87e71d5b646e2c26e94c1181d5e67c3b3c92413ed" },
                { "pt-PT", "950b76f7479b0d70475d4035467e6fa299a029642aae84affd35014b12afc0f17c4b2cd153154c3ffe61f8e66fecbd9283bc0528bfd716966c2ef0ca62c942a1" },
                { "rm", "24cb75856b76e63f1a0784ae0521ce55125e0800e5bb08780dee08b43479fdf9756cee090fc3b74ee3ccc806f9c43a91a0e98253266b04d0d85f49e02da29a2c" },
                { "ro", "2fbe5fc219cb88002bbcd727a12749c1ba274d6418220b4ccc04f5d145d4bdc0025d53088de2eba1cf7e3daa737e03aed83bcbcfc0513004ea5c14c48ae8073e" },
                { "ru", "5a7f39702b351caf4398dfcdb76ce6ee5ca46af077dc3401b9c37f81f2f125195108988c28283e9c8c2688315fc9008350075c291be22904d7e78eda3591b157" },
                { "sc", "4e79e887da23ab1c3246ffcca5ea70b248cf9e4b64bbc5b58e655c8c1827b51be2f6263c1cc25750ba338c7ca8b68043bb4e172959bd6272bfbd0d71232af61e" },
                { "sco", "f525f42d35c521fe735bcd944b2f8e2fe92a20babac1bea7ca72c58097b63723c30ec2348093f2be29a912ab85957490924e20167ea148ee1e4087a6f6d638b0" },
                { "si", "fe2338df49c441d86e20501fce4da9168918f29273b08be4e28d874123c2e705d815c9a83052e338b67d2763ddf950b3e20939751c6e42566f288969e3234910" },
                { "sk", "1c84c638f7f50142ac739549b5a9354b7cc2c45dddf3e35f2ede0bcebe85af9b1d75ecd8c227ac158228062c60f1b9a7413891bd3f72634bb4475dcfc6a5f3cb" },
                { "sl", "afe98e6c6cd1f794b76b09c9406967809b04182c177bf9cba2d2a01ab95d7229b1b87e9405387e73046ce09bd3fb88eba0bb0ce0caca60b911c6471ab39b3493" },
                { "son", "b593ea73b13a539024d871dba28141df033930d61e2ea582f4b231007b548ea8a6432195e05af19b3082542d0ed1c86e5b3eddcf88677e63727ac96491839203" },
                { "sq", "c3b65c660b71f219a87689d94f14982ae6abbeb6aaa2b4f0b745d32e30b8d8825c46e8256acce11b3238e8db01d2b8dec5414731a56d14cf6f661fd0ff01f006" },
                { "sr", "3a3edd880cdcc580a2e8f5e104b843f73f1369c483dd09dedd664c110a296b3e35b9a5fff23d13afa987be0ff2cf940a532f1f48ee3b70b03a73bab669973797" },
                { "sv-SE", "29651ebc19e6180079d932b112cb92863470ee1c04eba45fc323a490ee3bb5482841997b9002512dbe61c9e642f71152d41926fea6224e17b70ecc9347cea71c" },
                { "szl", "ca0d3160af2d0ebc97c51369c86228d701f401337273a2e1103e9bed145bb790024e7d64ed8cb2cdf7e71acf05a1c0e572e48f608d093dfbcf7c15817f7225a8" },
                { "ta", "c3be56897ee354585767b66fa8ba8f18a562b55e1dd79dbb8ed92af01c895147dfc62d6b470cebdc703759269b368ef9cc14a80d3b9b020587faa57f20d7c2c0" },
                { "te", "02b6ab1ae2448997f6717bdc66cad5aba9163dc9c09fc8bf455691976b13550d3c6eab02e224eb9be447359e02fe8c1991d69cc2cc6497b8d62f44c03667cb8e" },
                { "tg", "8e0a53fb3399b39edbb84d7e643776201bd551f11328bd2ae4e91051905a1e5ce9ffee5250bd862bad540844fdbc2684dfb66106edd5cd278e19bf5edf703f47" },
                { "th", "58015565865abd3d0f2147cd4f72f0244f015d6a90451359bf294a03416a85f5f0b1c18a08d987ef3e49e1c8efd25de81e163fed39c4d04bc1d0c8f7ea9defac" },
                { "tl", "3fa3d6923b52944150a7b25ae3afa84b76e50ee1303ac84baad3e373c072098bf901e93330d6d1c5ba9cd265d11002380085e2793b57b191ccdb33a57ce90f11" },
                { "tr", "b77bdd265df689039efc136545424d704b7724d456e0c245b417e0d364b26ffd25464107c053ec61cc61dd2b3d9d174e1befdeb638d46c3f0717da6886a08d53" },
                { "trs", "27c3c78f055f0f4d2fe3b347ae8ba9fad485bad9c1af05aa2b8ae02bba42a7692839e181882a0c68461bf3f24fc1aa9fe6ba7ddef5064e0abe0a717fdb3d4dc1" },
                { "uk", "ea4201cdcec0970b1ceddc514447f4320b1da8b2f5bce2ec2d45f8d1118114100c10a8573af4228e6f84ba8ddd27b188f78cdb56b7ad864dcb6e3512f1c8a6f2" },
                { "ur", "af6e8cd2a1092414165f11d71149c26e65273c8da7a25cf4e94153e5d3d26cfacd9a72c194dfd39d7f5a226513996e8a6e40b1e895ead0c384ef0a44475a706c" },
                { "uz", "2d4bb929a5b662672fd4cf8d90acb472139f7978515f06da18326f78a9fd87084fa4796bd3548bacd88d881c2e60107f7f1b2cccd7f02c930a94aa995d1ef0f6" },
                { "vi", "9163de6a2a7e994fa28101c6f8cbdc34f81f39163339c43281e70047a2aca7483aee8bffd57ade00cdfd4bb9112881ba932a0fcbf642f77686177eb4bfbc75e0" },
                { "xh", "21265915e608b677f55ef2d3dfde2d1e3cc2259ba993a537bcaf760cdd9f763a7c0bbc29d5ff7ba17a8a45869f87eaccb8f25f9e1b79d5182f9a16b3314e7275" },
                { "zh-CN", "2af31459dd59a6177b14c06b72fcc4fc13de49df11d583aae626e1a1c33c1e1ee15480966eb7a5c0142bf64e1ccf3703462265c9177d096180615e5df9568ee6" },
                { "zh-TW", "7af75a257a2030fb799f1b246473e36459c99e4c92abc7a2d4e8bf119fa7caeee08c69469be9e3a35375685545885a45ec24c48a265aa6c069f64df2a4cee9b9" }
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
        public string determineNewestVersion()
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
