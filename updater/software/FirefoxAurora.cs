/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
using System.Net;
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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "61.0b3";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
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
            // https://ftp.mozilla.org/pub/devedition/releases/61.0b3/SHA512SUMS
            var result = new Dictionary<string, string>();

            result.Add("ach", "5e4e47e296040760ef7885c8be9b8b4067c5340ff3e12ae73b3b4a9a7c88c396e98a3d0006695f5771af68328b54de11e27eb01c251237d71ceb9c25dec5b704");
            result.Add("af", "31141979b2b4f7338a155ae27c313652a1a3cffb4d08eac2e998b0acb56a1d560bc600c73f98f6e6ef5e98726e417d9cf5946fcf0c720161b43b4411177cb2a8");
            result.Add("an", "68435f5310478db21ab937a314f28a9f1e702953ac80c7acbbebe5996aa51fb02139e8fbe15133a2db7d88d0fbee9425c8a509aa8cfe008cb61595f2375c5c31");
            result.Add("ar", "806b506b2364ffaaa893c9ce5e90da954533ee6a1ec1c17bd052d703050ed05cc2732d78c26ec6199b8961963d72c24b4531ce39e615861421a0f04c570a066e");
            result.Add("as", "bad65e3b463fdafa61ee58faa36f12bcef00265068d84544893e49ead21c370f55ec262ca7ce918007e486309fa00fef33b7af8e231f3f1a0998f7813ab91210");
            result.Add("ast", "4cdb37ccc3017339d5ffbab1f1e4adefd9e72f7e9c42fdec27b5faebbc15aada0c89ae06762257fdf58accd1adcb80543c23b5231d91f56254c2cdae3630698e");
            result.Add("az", "77da100620627ddd0dfe92f57e3a05dd414487d538a67b9fa8b60d949545b1344914bf3f1110f990089611b98932de85a5626fe267fff7c7247566ddb695eed8");
            result.Add("be", "70531292851fa4ce472d5d488e20138c450c81b9ade48673497c5b31c9fd98e2372318bded753cc812bc4b34b129fc2e9d4c50f13830f2dbc40cdfdf4eb82d51");
            result.Add("bg", "8241cf00a8ed249fb9d4e059ade7b741d4bb07c1465b7ce28373536f3e8fd048b99b965d639ecebceb768061196c3026af216638d2f4a64350a145288aa27983");
            result.Add("bn-BD", "7495e779ead3815e5ce1382e8568931feaf689513064b85448cd6c28c7f2dce645ef021da87f1d92026cd4f95f15884cf350b4bc1b82a7daa295d52125f8c48d");
            result.Add("bn-IN", "70d4d2c61ca9cabae6fb2e46f7d938e71f1bcd7604690da48f405ec7da84ce058a92b5349ad1ded5e35a2514a5432ceaa3617e9637845e7cf2409376a4d32ce1");
            result.Add("br", "f09ad80381aa0acf4e57198d11efe8ab8c5bbd175ad90a51bc2b1afd8bce569e6b3533274c2c44e65b206a788512b83b28209a855a97f6154f168134c66047b9");
            result.Add("bs", "1a31c2556572f6e328a8ce54ef6b394261538d422072feac50e85e9f298f086c56c3262f306a293bbb2a3253a0ded8e4e060b0b7a3b12d24c47e6e5ecccfe2fa");
            result.Add("ca", "9eefd1001163309497a66173e377e6e89e4f5353ee733fd6ffd86b3e1d8bdc7c26a59c0c3108ba5c11027165b2837206f6bc9ff14b854a9101157151cc77f7a9");
            result.Add("cak", "379f6997e997f2d048b7495d05ae5c19d345fdc7e1e46dd6add94236dc4112fc786d2415006cb36ce8889d95e143fd2733683aace1341207a7a7329a10a378bc");
            result.Add("cs", "d2104ff86b27bb5b59149354c9e9a8e3ed49453345d58322cf11a3574ca4008279d71b56019d58dee4f96a1bc20c386a7baa850c71d92da1ebab4c36c7cfe6ec");
            result.Add("cy", "576b114544ca24e582b6655c102d9d5b7bd3b6cde7516334cb01bac81ef48fd20972b2a765dd1d14cdba5381656d031521a15897e9e67c0c4362385c7d5091cd");
            result.Add("da", "13cbb760868ce9f379bcdffcf155e63c90b44ece648f5f450863cbcdc9313bb71103e84fbd88702125ebd37a365901a00f952be8227c39b2a09a29c4dba2cbca");
            result.Add("de", "82524a2a5f8cfb5e5b14d11884eb46073232de662e221c41d9798295c6249546ed5d1c202567db88f0fbd5538ff0039b5759943f3cadbab1d615ef09fea90890");
            result.Add("dsb", "80468d941aa341f54f8b9f55f1a11e4bb5ba38e801c0a8be14c54a0d907b4e538e3fa6be46768e45619a392734595a07223690c7ff6e2f2e1b19465d0707338e");
            result.Add("el", "367c2b6205b4515f88fe4e546690ee0b9a10bda49a2c5518601e9bf275d1ee9a9ebdaf2763b25159920e506612df9a557053079c45c208633a4d940723854f4b");
            result.Add("en-GB", "92a876caec9d5c6401188d5f9338e1bda9dd3c5bd9f19a5ec2c0174d19b4643de463693b80f0d679f2fb7ad908c00c6a797277f07331d97aff896a9284d782b3");
            result.Add("en-US", "63f5040900b931640aea02a1e9cad2bf9e0b2cb62776dd60e45590b51d89d212ec33f70e3862b3ba3c3c78a702a771e509bf4a06e3ca601b717075405f2e9400");
            result.Add("en-ZA", "81f07fece42863f76e6f35ec4a52f467900ac245ad202ba12b8be4edd1256a8c5a9439bfee7229fd67305ba4b6914ffd711eed0366f6db6cf38f764bdc39d561");
            result.Add("eo", "e76541365ea966c263f990a57488c7d3f363c0b24be70a366e02c31458f49026e54f616c2f325ef6d373eb9171dd0d0558439c99960adf72a60fb76056fcd842");
            result.Add("es-AR", "bf1cbae105a851bce0c48c12e9979e3465be5515b98820dafd9e7ff050a42c77b6e7ef2da12866735981e3357db51bb81a8da28f8185658fd1408f4948c37bb0");
            result.Add("es-CL", "2d502c52de343667f9efec8a3949296869343e7570772d19dfb6518cd2f77b507017cd595ff217367b2919816f283161d460aceab0bcb57ce6a5fba4f6b2c8c2");
            result.Add("es-ES", "c6a3196a4623824a0d62770a4825e068878894f6f0798761af8a6e2d364344c18240296728ef739a782b1e550ac0e97b762910e0fc2bd975a2f82079b5b3b315");
            result.Add("es-MX", "c2c326565f626a0e8bf54c2a3f170ea473718bd2e7ce64f83be30182ee558fd743afb331824c9a82dc77909583ab53c3d7bca9a5a5d9892ad41ed9355857e880");
            result.Add("et", "4226ef0b9f237bfde05e491bb0080f0975aafb412c5fb5b42b49e065c1f928647f2abbc6e14b0ec85cfc2dc70c2bd7d7830ca0f91ea8c033c570414f1a5afec5");
            result.Add("eu", "c58b37d900fe6f75ce7fcfdf0ac1d2b783fdb47b11af75fc5893c624c7c798ad54f24ba6a47276c8a989372808c3bc4d6aba7ad65e3e3cce2a4d32f6dad2e68b");
            result.Add("fa", "e488d922cc0a272c0a5c578dfb86448c457e2d7e168bebb55c21721f1d07e4679d8e9e63987885691684e144d4e4469579ae5ba53962e6085bf9dddf870a5e9b");
            result.Add("ff", "a3ecdd4264c55590a5ee758bc2ad7ed85b0a9caf399a8feef1d55532a4024e7bb61292e39026ca671d0f9ada73450d30b390b558067ac6cd2cfd3fc580d09217");
            result.Add("fi", "369c313e1239d8b7493d606d1046a375cdceb7ec6c47a88e3ebe590fb6f9fd95f00dfb046b9bda67c8af3a263116d9869f9aa96681898124ceb58cebfddb3db3");
            result.Add("fr", "60f32a820c8b4b57adfd939708d82e930842a82504717df2533d974dbe383c6e711015f32ce3e8ace8805ed46e105daa75ff9550ce03f4d3a7b3e0682dbc555f");
            result.Add("fy-NL", "90d0ba19a10d5e7bfca51ac3682bea7ddb6b5c9de5d37d77b91451a8a16a46fc60cd014cd3a26f02b10475002c1310a4e82009af4e0d25042c6a61ccd53c1343");
            result.Add("ga-IE", "568aaa31c8c8b628cb0aca9a91fa701c67252a8e8d7f529e4cb9425ae453ab789da098729a8e08ede2763c9f1e65c517d4d127d7cbf314ac6ea2f6068f907042");
            result.Add("gd", "2c03b6865154f6359f7aef1792dd3270ebc0e37fa77199df8d2943aaf81976558a7647cece56f7a094e9a8605a34f15eb539ebe1f69e008c26b6f7f7da7c4572");
            result.Add("gl", "d4afcdced8f60c06a7aee9a1f989405b55df0893d2d29b7d5654771b36b6738958421829d3e1937940a69393c79e8f33b99983df103e618062bef2cb317a5f0b");
            result.Add("gn", "cff8b8332d18e0e8e9325d9f4515a3c418653457dd50f1efeaa0ac4c4e058f4a62f709cd9e6dc431217b1c4f4efb43897b7ab11efa806c9988770732795692a4");
            result.Add("gu-IN", "f7a8b82e37678775b7a95e87e28a1bedf7affc06114140a9544c532ceb0fee90149e95cda51194a24050cd73adacbe27ffb32e388ee000fa881117278b70aea2");
            result.Add("he", "f9bee3c9cd7aaf1fb24c3c269ff54bbbd52459bed7eb01a01e1bf02ea5e71fcd38816626decc03d4d3c36f247587bf8e20a48067a7b1822d97ab43bd273311e3");
            result.Add("hi-IN", "50946d946ba55b09d779ba400e75d9942a3d5f5342361dee342be5533d8005543c30cd252e1c74d67f095dc41ae63ad036223a53372ea547923c5196ddd95bd9");
            result.Add("hr", "f8eac3144b9e24993b0a949c5a0748720b97e62d22752945d57debc55354d648761a9c2c5e693dec162ff03ae2fec857c93412f9067b7887c3725152ae3577ac");
            result.Add("hsb", "21a9991c2a74256d460c622a6316318e51bfe780e0ef1aa09a1ffe7d8747dc2e2c19108deca9d58d6f46ac10de76dd4860e982ba33feed3488b32855ee18b08b");
            result.Add("hu", "42feb0f413f74b8f978e26b21fab94ec81e0e836da1a6d9fe1f2c545db84926e35bb855400a46c74a43e0696f76154a233589a511791bc6b850c058b7fd9a558");
            result.Add("hy-AM", "69b06c5715f66834b79c5c1530f53999c42444207307812f8e1dd2ff34ea18cc2a5ee1d26f991c1b0915fbf920563884126101e13e551a4c465322a4f23a55b8");
            result.Add("ia", "6454f77fc70cad68f8461e670bf73dbda60bf56a60389dbf871ad350399bc26a250da0e99f7175946d39b810c175f80fd2b9eb273f752a1d79d1388683effbeb");
            result.Add("id", "dc7f6b064f9f93e391a9deb9e42cce4f543d9d618fbcb2571d156b7d9a88c76923531adb620f3f03dee8e7a4a5e077fbe0639399b44a00243023d45b9ed2fc7b");
            result.Add("is", "8db487d7f81a451b8e0839c5b79e393c94b371522e5dc915e49116d1805d6f4d0147e54563dfd6586eb5dcb57f3af57a6480ea39a3da55759cf98284e6c02102");
            result.Add("it", "0b225cece7c2545885c88d64685491c86ea30abc26a378baa9b69a64402ed15759b56164b234498391ad0abe47304fe7ef4ff3bf352fa2af97de017f4be8213c");
            result.Add("ja", "b0ea655c02d614f368a5fb72ba8080b4f3defb37ebb4dc990e8e8988e4304b952f63fd812cbe3a45dc7da06e84e7586669ad5f779ffaed926c4658f0e378844f");
            result.Add("ka", "04a2dafabde4c629d1e276e966beb3345ea3d8e66e9a24349d0104fd9fbc4be9f34a31c62f2352e745d853619b75597b7dc7104593beb9073595a5563b03e8c1");
            result.Add("kab", "43a246ab6f6e0b1e933f9bdd5013f6337173f69f85cdee6c446fc26df621b1ac9f5b39ad58ba8bcf8b926ecb6253b864b4df29aeba66bd1d4f4439ceea39de78");
            result.Add("kk", "a6857e27be7b9295532dea8922043681fc60215e0c4319e838d20057bbe1657aae6720eeb711dbcbd86b3d0546bbf1a4d23c1fc8862fcf986af99bee428b92fd");
            result.Add("km", "8909db8da01ea90b32578b3ac628d46658eda1ae82bcc6969ecc6c5371ce1ec5354cd67f1e64332f6a709e048c53516a0195c8e38fa6e96fe7f300d48c4d1850");
            result.Add("kn", "a55aa56c103913deb569116256a7f2d553710208bd1eaa8f20b32c2654e606bd44b05cc3eb87a208ba21dd2ef1e99aa0a8bede8921bbbac339b1f50ff25e5de0");
            result.Add("ko", "852c909f076cf6cf2f5d8a52b7e0d32f4daf0f0e1d226ec6a4e93910054bfbb084e4fde9780d6238e08d985c85b1a97269622ce069e6f3137f5b1edb11998aef");
            result.Add("lij", "b369d9abff53b9e4b322df1b86055a703f4c6be474a5df18693f7f282207e9d1a94256272d4c636e8005536d2cd2efc0307ccea6b2277c62afee9f3a6d3fcb17");
            result.Add("lt", "a256bcb219977837daf13b638bb902244f4a54c5267948ec93851bc09b6180592b0f9c02dcf4328e2464b014912d6b8c7cb7c90ef12b56555713daaf0f3974d1");
            result.Add("lv", "d35512761ff4c81d2152a380efe0c14a4924caa0888a15b136f6c464b2f3257d0a4bbc25940a3e39e9ca9ca8a379028aa077e739b4a08c587d84dc28af2ad01e");
            result.Add("mai", "2f192973013a286f5baf1df4ce5a3b8200211e1b5c03996c5894c746bfd760fb3d34873112009a159d1dee1f9f154ed69d45a0aaabaf45073005443a0e19d97e");
            result.Add("mk", "e6288e5a45c4fe00715503f3b1d3a7481d187cad2a83e25878621504e9685ca97b38669e1391564e863f6ee73845d4b6746912384a49e8e3e6b86445cfae3c21");
            result.Add("ml", "e1cd1b96bda9399e50849b4f742e84aaf428b3efe8ce406db11ede98ebda10c15b5aa921e8398b3a2d299ef6d2a6b08822ee5ee19a6996ee476f3e62b34cd275");
            result.Add("mr", "81117e2150eec772e01e71ea9d82788e41da5fe00add92cf3c7a69a5688797aafd9ffc7a56d2f64e750513ee3a231f8ea5957cf696f0faf3c1f42d970c664b35");
            result.Add("ms", "596220549d49f59a36963046de31122d10716830a727149e6175dee542d4ae689f9b0f327074cfffd09d4d9e639bcfcdbf75e0295195c80641adba947038c10a");
            result.Add("my", "e0bb88d93250b0552eaa45f7a58ad26f53cd3ecb2ffb9374e26d306f06234ac30d0fba367c3efc19b3df5db8ad0c7823c591c20ca2732557d05c2ff07248f9c8");
            result.Add("nb-NO", "a33926fb417bbd90d4ce5decdd0b1347c350b336c1b825efcce231cf6d875387efbc1ec6d7d290e64b02e985bc7e4710dbf093338c4e76e0d99dbd0155069a76");
            result.Add("ne-NP", "0366b9fad5bd1b500f559eb6bf7adc6eed42ef0274eb6f1c2fe24898d06c90e16353db1378b6c16efa4d1a11522e83a5e7c5b637b916ae1ac07a4bf8cd617574");
            result.Add("nl", "aa641d25ad89f40e044b3d8b2e9e9752d23973b6e5f7ddc9813bb318e8940d7d312ff13fd33364ce9eac9e21629ddbb7536d51c8d13321957913867291a8f970");
            result.Add("nn-NO", "934d4ab6f4281922905da301e2e6196faee63143e74e059f27dcffe845787c73821dbd95646374a5619a53a33f3b3dc9cf6fa6d42c44a20cff3a2527d4e157fb");
            result.Add("oc", "614a65ac734bc5d42316f7a7a2d737d7ee6695a205ebfa26f12716be6ee381704b71d551d3a797cd66a378d74c6bd3aa7db00667755267f0295fc6b826f270f4");
            result.Add("or", "f00430cd480c64635469157d13325dc5311cd84b164fc9075b12d8e608cc887dbdec4be87f3871cf99fd51a30b0fb6905eb526f28fe0bc8087e11db911fda81f");
            result.Add("pa-IN", "c62e39ffbf1e197d65a50473930ae792cf157c6aa53de6a873869154a409d3e7b54a611655d7f65a13d069a6ce48c90cc5da465d439d1042497a3461f45aab0a");
            result.Add("pl", "3afb28a8140b2d0b2acca28c62e8faa7ed4cd9ac8144676295742fccc1399ec69bb749a38dfa0e8db54b5c75be77647537b299074cc831083a5786fb013d3dd1");
            result.Add("pt-BR", "44d045005c35f56e4871e288432dc99a23c6f53f4a1d5f9f49ccabf408dbd2fde146d9a450e77d9b07839004588dd4d6e60534d1c6d40fce4d0a3f18d3388897");
            result.Add("pt-PT", "64b83c5e8bfb95c38b40c83d5173c8df366d01e6c99cebd23f34325c085549f1ab959b86e62b89e2abe14189ba374b68aa2255ed7b70dbcef5e671228e07740e");
            result.Add("rm", "91e08b9c6171ffe9aad1337a3e4df45cd64f620ae97ac5a68968a3779f60a641adf3ba280a605a1cb37a7290b8a290a5798bd8851afbfb00be4dc001c7afa025");
            result.Add("ro", "63f3859daa1c6fd86305be4745592f81f2499112482dc1526be38010c185adbc3ff2c2c3cb43f93a06461333e499be2e204026ea12e569c0e943662165167138");
            result.Add("ru", "61522744e51d5c60081d019b9fbb55feb106e61ec859559cfa57c1c918ca971eeb7f7515911462579840656523813899badc1a62ce6c814c68a01fe2ed74720c");
            result.Add("si", "af7789ebf318788e81299a959e1b6e0a59a80a87a4df397b8dc102a9a2a122bda3bdcbd6c3bdb184b5bbf7b85ee999d8845928f58cfd706da67c2aa8a382174f");
            result.Add("sk", "bdea72b95d80c37c3bdb5d2c26d5a56b3e4862b086bee3e54cb4e6ed2144061f983e967281a3a3179dff35d2220e168376c2d6a73c9c0e8e1b07ac4c189821d9");
            result.Add("sl", "2854a681d48e60664e1e0e9da5d4059321d8646e6f40928c0a27695a8871c844de1c2e04dd06080e3040ba8ad67ced117c7da9099852994c16d3a5eeeb42bcef");
            result.Add("son", "a42a88c34a70de1633e5cd47e2c82ae8c73c14935fec599bc7023c10f6fa8846e0b8c0d4a70222c67e4f7acbb35ab662111bb367d180a8f16900a974781c3286");
            result.Add("sq", "bf3616ca6ec0933eb35bac52c7817ff75a200a9242e1403a0725a31ea0be7056e533a9b01a88805dcf4f56c841bc2af3cfe06b9098ba4aa7a488a941f5450572");
            result.Add("sr", "6054f8aa8712439a4e4e8478160bfe51ef25d2c5c2d343bfbb1a9bd75add63f644048feeb59876685208b772fe996b126d958c3b9c74f7e68ad9e7f38f21440b");
            result.Add("sv-SE", "53fbd5c8743a3cf3ac6f8a0223dbff58be942ed0d9e3a9f164d9b0ca6aad0e75161fdddbbc21c4b4da19ed2db00c3096b99c50f63283cbe3e43584dc24b2421e");
            result.Add("ta", "1d1ce66c121a0bab6f368f064e02dea9c2efbdb7c829700391069f80d8f9cf30ed6c82f253c01cd5386b0520fe5a5925c4ce8cb49dda1318364620fce16f2dc0");
            result.Add("te", "4dd19c7bf115363aef13006809082733b23b16318521762e7abdda7ced6673a6c1bb20a6e2d9aa4d444307699b59785b1f57b5b699e539d7275d4299f99886f7");
            result.Add("th", "9b4d7e6b439b1917a878f27eb11617314710760c911474d66f89047edc4ce2f9d70cf75bf2d00dc53e6f84eaa4a7931c7fe8bc5ad09a406d146a9ff0b0201a5d");
            result.Add("tr", "7158d1db4b88c8665893e2fb0fc3f89ca7fb304f54ad869ca43e4e386b8c4e278d85602c1f775227e71aa75b1993b4749696c924af9b4e9659d997150ac83acb");
            result.Add("uk", "1957846292607c318ec12aa33a092eae26be30adfb7c9fcfe2da87ee52b4b53fa4daead463176bb183086864b906f7cbb5b5f71a662fd45477c7740a1678fd46");
            result.Add("ur", "61232d91c43ccf495417aa33ab4950b521a854b764d5c7610e3d49dc46a90b3f9befc82b4b3d7365fa31e30bbb3452411c1e5cc7fca9b84a7cf9c797091d6745");
            result.Add("uz", "5ae77b17b927ed7bfa68bf93862f3f918970b41a70af0d3615ba16607615d2cb25743162c093f84a17493ae0caf4a37111c341e29523e6e161e26f46aeae606e");
            result.Add("vi", "cfc4699d34c03ebd8d4bb7e29ba3f92b4d25dc220334a9827b2f5ac931e728f01cae8947bbcc9d93fdcc98461dd1c7724ab18f24e1593a7f40aa21fbe611af79");
            result.Add("xh", "71982e33dabd59a2e451058f4e0ed1b9815cd32a59d3ccab2a8403e962e88ddd1a324bb617bcbc49be8752b28b7e240bb4add376102b02c56ad9eca22b4d7762");
            result.Add("zh-CN", "f2d56b3a90e5f4b72ecf8da787adb29f15c562204506e429910036c4cb0c3cf6bdfb99f789e4409b31898d40c335f464d8c887614e93cdd72f4ba004bb963d95");
            result.Add("zh-TW", "6d348f66819dbd223c87830b3b22f0449b8d31932c9bdf78ac94034fbe0af028a86f5db3ea586cb492c08cb345896333e0f914e726fc171aaca2973b2c99e526");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/61.0b3/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "bc4c54aeaf132d240105d7d5b03c62fa511fd9224fb3dec96352f0bfa6caa041c151aa6e43739a72b45227f1a56ca2119c143832b92365d3266530d2829b6155");
            result.Add("af", "3107fea9737b4f459aca970b2a12615c482960bf11ba4db2b659f78a83aad146f15826db02924768453a3aff179673292e04346647e58e59cfa3a419c3f4e30e");
            result.Add("an", "f38f37bcf8694a0684133d5dbc9863822febc08ab02f0fcf6eb3661b0cfc47603b98ddc69578edabb78e73aa3ebee2f2a3a832745c11cc8b54f6424a511c5343");
            result.Add("ar", "adcd5b4b566c58465b09e64ee03e4ddb49a6d7e96f2c4d5d2d48f60eee2ee78dc390173cafb6daceb56a91738f1c7dc9d75f280be8c491e4a32b8e31bfe40488");
            result.Add("as", "ade04e307b363291b12584b2b3bc1d78aad7dd57e4ed66b86be70abe81ec6e5821b6a6c3f051dd8c594cd148e797862fa328533ee8924475ab106b8f2dfc46f5");
            result.Add("ast", "20417e0465db4903b03263eba73af2e482d1e26df58074596a91f52d94e915bb176abe1d8dcb29c356feebb2349a3c9d44a255354d8c388987b80ee0effec0ae");
            result.Add("az", "b86ccac6e9b397122be3e741183d1f9b6465c8792dccecf392cabe85230a9f8764874cd42054ec302291ef87fdb25cb2cd350461bd3cc067233978a62b2e8ab5");
            result.Add("be", "c97ebe9b6b65bc0d74445cf66ac82deffdc90b4e7feceab2a8dae970dea1897e135c7ce5fceae194011152bdf3ebb1dc91b438107d63bf6096fdcc9327e1cebd");
            result.Add("bg", "263358fc9b991afb5412c1d1752dc7964881c15188f437ad825de0bf24456b2f0ca9be8bc7a5d5d6a6d5b4b70dcd0755aefe3269fb20cf43ea866e5a3da0c98a");
            result.Add("bn-BD", "782e8626d8d28d88cb5408e7b587354c752b5ffa61be57486594767f971e29ed36c38b956ead705667da72287b45bbc5d226ad996843c3905a7758cccab8dc2c");
            result.Add("bn-IN", "42cc9432ed72cb336bec007a504525aa7b1f139647601197454a9ead4bfaf7311ea4a7be0bb67e9037e4f3f599568f0d5551ec819e05801b991e337bbcaa5ae6");
            result.Add("br", "ae3ceb3a720de23ac2dcdfcc50752cc62b89313769f9a453d50987412510b33ccab99939419dbce3ff4204e754cf839a1d245720a582427133a88033aa4792b0");
            result.Add("bs", "eb93693861fe510eea12fb2dbeaf5919606a58ec5115ee3bc720d8b83f1c2555daedbadd62390be1dc0cfa761e999b4856103338331d0b33abed839b9584e3ee");
            result.Add("ca", "c8913872afb02cf9d812cec0d5c46682175efa9e86fd330aa9a25e744f6179653a5af6c86edd20a6f802dabb640f7e8fca3686fc0168f2d58538387a74bb84cc");
            result.Add("cak", "43ec74405bf36c59a991b42d004926f8ded96da00a81dd6aa4a9b1cf1a9a41557d07606e3d3e058b01fa6666fbc0e93ef1a139917fd25da9eece9cd8c6d13793");
            result.Add("cs", "1c555574d29406192333b8599f1f69bbcfee0f6c0ea30ca9bd3196a6a78f0fec904f0d03ec1314fdc677fb0cf51e97fa3f2afb8c1a8b7147737e5acc94cac6de");
            result.Add("cy", "d837d77db6f53834797eadc533682f163504c563d1afc1881cc117d9f8339620e301aa48d35075203c2a6a844eef04b6efe82526f0d03d3dbe490bc1f3b71926");
            result.Add("da", "507d38302e643990167f2d02ebc658707ae6ec0c070ac243ea2ee95a2b4657d015cd3f602e93444236aaa01ea81199dc211f8f753666b6f4110d8c1e4d959e85");
            result.Add("de", "79b22caef4d62a3836b9f7aeeced0300ea2fe0cf95eaf1c105203b7c37e3ea5985927cc1e7847a7f2b85d0582aba8f8a678311ebbec9b6072238da161e84de62");
            result.Add("dsb", "dd5ff4b68e10b285bc1a7ade1255cfab4a480e39dd9013783dfb518235d1ce824b490c585b516faa58123af24a28915e824fa17806013ca33ecd46331b5a5313");
            result.Add("el", "12ada5b2725408125ef0013602d8980f4ab543967d225b7e454bd0a5e975f43c1415a55de85c95e040bb5da2201aa7b2d1679bcab66249445404d18ca1d2a06c");
            result.Add("en-GB", "9be66541837c4c1412243653fd6186a42ff65c7897197468e900e3f88d049521e15f7707c3a90e1394f4e0a8d54e0afe13259e939e588fa599e11f96776809fc");
            result.Add("en-US", "0b2ca6c9717f77eebfed40fd268774c103c24d7a361378017327338e7a4b8800460b18c046d472df3250107134097cf73837fb7c49da901d4390b489c35e2693");
            result.Add("en-ZA", "30732f0a42dc963b450fba81d6dd8d2a488e662d2e57c88b1559abb3521ab51bef85b2296de1adac20df7898676b4622a604f4d4a42072b8b542fa628ee9a7e8");
            result.Add("eo", "5b5bffcbc5ea866648a0988ba60e2bf3c3f734e7ee67979169cd22e5c6f818341fb2a5f890a3ad50dc89ad3ecada8e15cba462538bcc0b9ea1f37d6b4417872f");
            result.Add("es-AR", "70b2d518f7ca332657b5c1784992e4bdd5a27e9a0f5d52e323f0e3d340b282cdb9e33a5ceb76f3112a398190da5d5fa67a1bce1e4d96fca97fbd58d7547eda80");
            result.Add("es-CL", "4a28c8fa1bc35fd2c932225109a12f6b3082e5fa116a4f161ac2e04c1289ed38273056c28a8f753183e5b57047fdce65fe1799939b39ca2f5c500e106ba02202");
            result.Add("es-ES", "71d6911c3ebda05b391c0492983811115f9b7a437d09db675650ee51955c8612eca47445426a9b1586483d000568b8b00fafb83dc28507c549319cf3ebbca9a4");
            result.Add("es-MX", "a649fbaaf3536319ca3b4322e422eb313b9f077f1e652c83825c61416db681afad919b94c40a986018c95c9d194023c96690c0224d57a448ceb9798e950ffdc8");
            result.Add("et", "5f5f873f3ab2a5efb560d368911afe70093e1b38156c4aafe135d97fd588d59abd442d5f0be6974e084ef77bf83072d49cf561a16d1220a050c7a73503b79f0c");
            result.Add("eu", "befdcc8df4b901b902444becac80773a81c2562f11fe963fb7936308bfed351c3d1724311bf8af4f10cb1518df18dc199388872d2d827da470e9fd7a30672594");
            result.Add("fa", "77587eaaa02b7b9e9960ddbb4e86073c5d45c92f6a81daec77c55632eeb711dfe7b707a404ca11e5132f6100933775af11f69976dabfc1d0656f80fef5d69ab2");
            result.Add("ff", "b83a9371dd4e86383d4bfdccb868c24764616d543e26b8dc897d784d89701b7edf13c499dd482f773af65f080af04078416da7bd55c71cb2a9f56b4feace8138");
            result.Add("fi", "deb977dba2a668cd4436acf8445931c12f60f8556873c74696489c0e3b3570f799a3cd911bc9730ce69eb6e48e6101fe78eb5510a4b4491bbbc59372995b8711");
            result.Add("fr", "4f0e8a341fb52ec90a2fe663e1bb5e2e01a802be88b1e31cc8fb37af35f262e5163dd7739fd509d5351ebacafa2a2b39739444a56c426a3415363edd57b7255f");
            result.Add("fy-NL", "d410e36a39278c5595e72ac7d87edcd364d3b85a81f7c6c548840275eea2b88ce9413b330d6ae9af1f5bfe665249aa5a71287828284da4b513cc830d09330d82");
            result.Add("ga-IE", "9528cc2a89aa2c5baff83d79d4a5d6d911591b60fd0270b7169a544429d249772776dcad33b16cd658c6bea9d5cd73a0361da493ca22e29525c46620be010b7a");
            result.Add("gd", "f462821fc6bdb7a4fbdc064aae01cd70ea8a141bbc1577b512d866051bb157f46aad04dbb9133cd24adbc65327151134dbf32a63f15d494bedc8d9756d450456");
            result.Add("gl", "5a90e7070ed8f1dd825ffc8ba5a1c9db5e9f74b8af4d4e4bded7367eb3d069d9d8b9d54ef830b51549dabf6d0c76dfdefb36d547f84ffc151734cdf2662db0ae");
            result.Add("gn", "fda3f3c2cbca53b9b5acd4ef9ca27eeae72a954eec515fed8254fbc4dd3c050ead1b093ac17a862fd27d877dbd0ad47186d1499d9ea2a6f34cca59d296c3bb2b");
            result.Add("gu-IN", "b6f357d13ed5595ad563c5f3215ad7b40619bbc168575506d568228c4d04f92ee226492e68db4dd804297b7c00282cc4f8c70a8467104a53e3846ab23d3396f0");
            result.Add("he", "740deeac3c7c1f7e4d4fc84ef441f059bd52ff411aaf25a971d86ed304b11e1607dfd3444da67352dae392e05ec1d855eb76f24db861d850dcfe6f10451f0bd0");
            result.Add("hi-IN", "201a43cd9ad075e33571e682da67c29fd53ee70be6248eeba20020c75d8c5eaa45d258ab9a6ef836129b609a8a8a774e3617cdb67b62dfbaf5aaf636e9085f3d");
            result.Add("hr", "e4bc5e4bf91a1b149d2236cc347383a1fd46d50b0bdf27124c88a8608feba323f68d9bc3495316331dc84f7b59d83b8a1209818c5e7f6210febabc53d84e1a0f");
            result.Add("hsb", "59d6a342a90976f768e865d15f65bbf1971d53c0926a40001b6778e5dfe76b3481d73eb7af7e3f61380fb664eaea792be5592df2c4df38dbdcc06bf89c7307c2");
            result.Add("hu", "6259988b3acc1696c4f47a2169abe6b38a5956bdc70a82f4aee58a27deafe0917acdf02dddb9d3b4d03825fd7be0e1ec450fdbd20240571928631f75532d83b7");
            result.Add("hy-AM", "89e69a766c8cab56850631b0e4553f21cd73844638a635b45a775b13f7e544f1660e4ab7375616c742cb7bf5bd7b7f527f0e1d96f6d4602907142ec285c7cea8");
            result.Add("ia", "9157d7e8c3a9fc612df9f93ff71423bd3e9675f695d27d8c5342f478b69e7e0062af187e2193de8aab41e5c10b4d2fe4b8c40bd81b19eb004d2dc50757373e27");
            result.Add("id", "77c052830b73370db1d861967e27740011eaded974f7be06447161bb9d6a3cf3440512d06187a1e18af0cf18ab645fd43a154edddd9bab005dee6ab02722df2d");
            result.Add("is", "16309a92c8197f5c4a36b6ce05705c7d854013f0c833eb78f216ee9a08858170f01b04eca37d0391c22622bdae5a35a5513bbf7f16b729436066f087e5485e76");
            result.Add("it", "79e9a272554a2ba49c1dec561b105b1af624a28d0ab48eac2b54bf34d178fb921301bd1b41c9101e6406c36f7f94511868726d6bbfe04dfa3fe4b80c0ae3f526");
            result.Add("ja", "f7ce14b2c94d9afb81b02b14b05b241fbd501bca33ccb26b8e718cc337dcc6172c60ce8dde8befd3dd58ba7beaab3cf949830c4c5b54de0cfcebf64df6fe967b");
            result.Add("ka", "a399c03e97c7cf02c270f724a92af94fa849854aeb2d87bc62c7468981edda7b96c04f96f600c711dbbe2b4acffebd23dfe82b3f6e94fecabbc8479851b44299");
            result.Add("kab", "d2b2c0cb074b69fea9dccec659ef07cc7ba085bece22f8be629d79a9ca138021ddfc7612fe4f30cf50e58854421c4aa77411419dd0c946686a79a59774f19eed");
            result.Add("kk", "ab122498673faf48e188f399ac6ae7bfaa2f6f5958c96eb75986e9d0167540c751b65e4b27f83c7faa24ae054966279297bc1882931b1aeb13061bd5d0e3b653");
            result.Add("km", "106015bb5bed5ea94719592cc9c0df1a84d812e5da5b400af8a48d844d1301fa8d1a0407beb51f6f149b41f47aa02377220d13db6f96a95100660dad341907bf");
            result.Add("kn", "f54ccd12d8f11aab9e20be6830227f4f4e1b76d3cb957a5ffaf699536c9156744a987d7792b6e5b28bdd14c140f05cbcc13f7bba0b06811e9f2001c814db25f6");
            result.Add("ko", "12f22037f335bb0255c41682ea5c5cb5ec9b92123639e4e73a419611f829efbe17805d60ed36ce76b0a61dd4ef842ef1f3ca13040fef0cc9463e50e28f22edb4");
            result.Add("lij", "5a6979fa6f8a1c9f2c9e2321f317832f18b1a504f3f0557b7172594c5bf3e79722988187c999211f3f54eede52129629b282fad7009c431b9bb9407d583d382f");
            result.Add("lt", "6e0d8bf24bd29376cda02763df3bab855baa5c48b5c43abd8c9efa2f23817c0fb16b9af2f072352d6b3e25814048ef0120c174d5e3d46e67657cdbcb631aa8a2");
            result.Add("lv", "70074234bb5b3101d9da916e9142d7fecce3a0ba31c69d93ba98c4b6f0183dcaf7ed7ef8ef3b315883aa9d5fabe795da9878b4f06cdbfe326e79bc4028f61bfd");
            result.Add("mai", "a573fa439616626994ad773a60f9ab5048fe2b6734d3bfd4d4e8f204203f509bcd70678a395a526f5c1ff85e09fa4c624e5e604a79f11a5517634fc27e00805d");
            result.Add("mk", "789c337194947f25801dbd23916c91969c5e82dc6dda3bc57075b85198e1e8b9ad54b7d3401c719939cf1e9821f4f3d9eef76bdaede60299b59878113d85072d");
            result.Add("ml", "48df846c1b383efdd4af5d4c9322d5de66ec49c643a17bf47939f3a6e920adc6c909615fd118a188420b6609cf0a6fdda1756c79e71f5e448ada8d37373296c8");
            result.Add("mr", "ab71f7922942ec260850b8357a99ec558c41b7cb5314b8c67240b421c0fe4b4cbdbd0b62fff18b715a7bda380ba615bdd5af64d5c0a927c020c8032757aab287");
            result.Add("ms", "f42e7fd0a7ae9d0c4ae85631319ab276f734716a677100f1581d997e92a9babed7f4175d27dd9fee33d9d81e0076d824c78621e8123423729e950c493c248129");
            result.Add("my", "90f314cf8d9d08df7bc1b6e25eb893af3bd86e7fe9f21c03fce25d86f5ebdc5f012bec5074d62cf61d29712544052325b67d9fb41fccc8b283f86e9a82e4e992");
            result.Add("nb-NO", "28ad7c26e03273d3bf99e1eaefdc32570704706380a006670f9734211a5188796e1d12ad2500299950e8f69573004e1493d30fb3db46431056d060503149c5f7");
            result.Add("ne-NP", "1a7576136a72eb7f30fbb2b937b5c49a841cb6f724332e43d80b3e6991c0738a97bfa5ded7a96c8e1e45c322e3a0af3421a10e1427047527d06885855eef89cf");
            result.Add("nl", "21bf21cdd09a69869bebdcceef014760e6dcebe2de7590467d300ac6af08e9ae2032d7a77f5b7dce2352d6f2ea7f2abe767f0d3c6b438f29e9502d235bc64d83");
            result.Add("nn-NO", "1841b802df3111943e1b0034e2c5f52406bb86742bb86ff36be96ec94c8a5ec67e97a783a22040d20bd2203a4fc0361423c09d64fb162c48b866e791e03b751c");
            result.Add("oc", "c48af0288a5162c918905b898038f768fd43ffa7af31da75d7042ee85c9b089cef85054322261afe09efeec1ddc368bd2ccd46a9c3cfcb15f307898426012597");
            result.Add("or", "3512b1b647481ad8d14f2f54e27ae641ee7f11c0d776104b66cfeb7cb7359b029be28eb15672877c6b34b31e2a3f810fc450326d80b646021457ed036b2108e6");
            result.Add("pa-IN", "021c1fdd644356d3ba2d8132e8a024e2e3a7d40e8ba83e4b98de837240b9459645c5dbdb798d73c1a276259657a87bd70810b9ac7053cb74c4e61cb9a0e669e3");
            result.Add("pl", "98321ed1fc9c871fd0d5353bc8de03c22cd35c01b62f8eaf4d5bb12f5042a1a0d89964aa2b29a5ddd487f4fdc888030dc78bd171d5dad759bab23bdf225e0ad2");
            result.Add("pt-BR", "214da9e220b36b8f6ea485b8e39e5a5730bcf395d59a0685dfebf251ed289b5f9add68eb0003f0b140856b4283bc125da35f353ea4f24ba76264bc5b16fa6ee5");
            result.Add("pt-PT", "e3ef14b77370b2a5f8f99639bb66768bb123b3d30088ee38bccf9eaedc05b75744b3092b778c3d6bfa10a0ab31d52114f62f950bcccfd5367e124b30adc61632");
            result.Add("rm", "be1fd4df5934b8732b5e098df8539fdf789600c153c9088b250598d3d21ec9221284df94b2a9703e8473a07d5be3a3c25e316830f655bbe591ea9bf94207fdf4");
            result.Add("ro", "5c94960fe62e2daef937ca51c78c3c6e5bb5e448da1a20eae50d90a4cf75a8f121c65787187ef5a18bd6dd2225d2344687602acbceec4fdcb8fcab3925fba171");
            result.Add("ru", "32b65b93d1f2652b0b81dcb633f45b9de7b3541166d1be73d7375e2102cb9729ff0cfc3cdf1c2c3e3ceed5416d51ddb7c25d437a1ef667bc1d27e9e7f6519106");
            result.Add("si", "3510d87c579bf9ab2ebb49098358175563650a91b4aab91e363bb9f85c8d4f2e897a43cb85580e12c553b76ed6a7cdea32820ddc0941c8f79d8d6417e8318d39");
            result.Add("sk", "50c6f4bcf01ca9e4e3a21ca5face1aed7c7db4806ff4509ab87a40aa6ddfd83175280dae2cfc527bccfbf9657a1dc2226575bd9b597ea8b38bdf4801b14bbfbe");
            result.Add("sl", "edeaff3e5a6a090b126541e8cb54e562bdd8a5f1f24e391bebccf83f472052525f7e00e90f5572bff84311cd02a72b7a0887decf9ce2a3b93a9410848836a796");
            result.Add("son", "ae64fb594346db4ef44b77d4732c482f5f7c0233b7d372f51ff313e6f5840f4192d4bd1043a3af231051e14f4cc3fc739ff205ab7a23f091841a8c441213cf70");
            result.Add("sq", "07946bb19ee3769abe0219ec661d7107d19ff712910f4aeb5340c46c92b62bbb383a8c0217026b7a37a4f39c10be160eac73d20c4bcb30a5d527ef3c08121ce9");
            result.Add("sr", "b2b379d15888f110c5d43e1b5bec5711ed41d49fa27d1a9724e080e8004922f66caf68c987e96e26bc0bfd04697ae41cd3672efcc046b1486fbc346a79cfd273");
            result.Add("sv-SE", "b4517c63b851f759e3cb07995253be8c58dbae9b87497fe9efb050dc37d9f4757cf95044aca252c5aa9c1712076af31aa1c93a6a3edf65bc4f43976ba7655a87");
            result.Add("ta", "dc423e3f68adc4dbff58fa9998a94c14fb20fe355b3fee7c455ddf47f7ce541c35fe6ee10b6bf861ea4ac89ef188a580eef8f5fcef65cf754462de0c0f78afe3");
            result.Add("te", "be39bc0f378e88f9acf6cb808f41eaf5b6da60ee2d0f00ae65e0d189330992dd504d4a62730848596860edd133701478531fab64616b33f3c26149b6053d4088");
            result.Add("th", "9c2a286edd4a52fdd47c2928d5a9575eb8eb7485d0c04961d593b649c4e933f207c33850f112186d19791e5d5a1aeda88adad280510778317fbb0704d1ac96ff");
            result.Add("tr", "ef29ef4c48efb22ac9246fafcd40825100587991b874d06045afcd583e58a4687446db43d26c23c55259974af1874f5208d4f56543de6a30b5758d1ca86ee3e9");
            result.Add("uk", "06fd1daccfcebf3f2fac105af3f10a7bfbc26a0ce1557d6659270b9c9b4575555e4d57542cdc0d8b0a70d9c7c42c11bedf7706fa39de2df61670f61a2478bd56");
            result.Add("ur", "17e6878fa56fa422ad20829c5879e5650068f1061dfebd16353f5a1d6b3b0a71bf7ec130fa45b623a2f879a03734fbb8b915aac434a4c67f29ef2ddf77c3ea04");
            result.Add("uz", "8ee6b55ff9ab7079b37533ef18462a7c241c314c9a23da01a56f333a74f64fdc5993295e9a8f2f66ee806742472f04ea291f7e18c76f7cc7f2f3bc5b108846eb");
            result.Add("vi", "808663b6f48201900f42d5dc9db1572b6cc4c6df5f32c0d163efc33ed3ef2a61508d70d5f20af078caba0c45a309bc1276143444754dcb025326c3adfe977e4a");
            result.Add("xh", "3a84b2d3ce4f12b7e7cfa925ac68e77c67d637470e10ed77b37183d07fdb6607fdd3d1ed9826adb9f3f0862253ef2e808959a4c34f36113c3b7e5386b4e5a91f");
            result.Add("zh-CN", "461e0cda84b53cd94c3779118714b165963fe0b64eb072eabcb4ec6b37796d8cd54b367312c1457c778a4748942e7230194115eeec45d9173ed058dfb88d4be3");
            result.Add("zh-TW", "fe7c1e76aad881ed289fa3357be466e4a5c0e3ae942dfb64571ea88f44b529310af00fc4a010f8f059d651fa1a2de42f53f4bb511124a28cb333c26b7304dd46");

            return result;
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/"+ languageCode+"/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion==currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64==null || cs32==null)
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// the application cannot be update while it is running.
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
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;


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
