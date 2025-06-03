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
        private const string currentVersion = "140.0b4";


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
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6c3928dc3b94918ee6943d709196788c85e078326bb4c6e906951263a3342876a23199f5dad2304672cbc721dbd6f9c832109d074a5a5ff4d5ca60cc53cdae1f" },
                { "af", "15e7c80c02e62ae56d53beb9ff934eaa9b5a960c95cc2766ec6938c14a39c0312a29d6129b83b333ce49c03006a0e882e194aab72e4b6016f2964f21de06abbd" },
                { "an", "6a2efa8b4c1335dbc1d4a0825c572d93c76c9ea2c9a56a4551735d19405d8493ad6035b1ebcefe5ad6f94df6bd434f751ef22fcc03e683f505ff28af5a796e45" },
                { "ar", "ccb8829bbed6017a4c286fb694165e085af0cbdb657acbbe3baf64669a9c55f65c99744d72d600bd7a86a724a30623d045c07d4d4bce0504b2d89ae9579ed35f" },
                { "ast", "ee0067a120cd4f4e5bc8511055df3865b038d300985a32fdcb05cc934e03259b4244cee97efcbd0c47c972d42cd950e36bb119c835cfba7848b128175e9947c3" },
                { "az", "89c54849430f5f4fac445ae4b0f43f4f89d2d476e6ff3bec324d451d592eade7c73f8a4faf5c2db5d3bb891b653f46d89715b504b4e3df0fd78b4f4d6c05c34b" },
                { "be", "90e4b5bd841aa9405ca324ae6d41b243579e7a9827d8801fff01fb37e3a0a4724a2c6f9b8a2516b9597dbe5ca02bbcb0d312e0f958774f2a76f1e39731f92315" },
                { "bg", "274c5e2e827fd1054c8fc24da102609aebc7982bd36d4ae8b10005c617c348a1ff0a39cb9e310eb80b29698e38a63fce9408a06b97f313f291ce067ba57b6891" },
                { "bn", "6e98d1b9f0ee0fa0e3d0e8f67726e1dccded69fd8d95f8afc3ab98b6dbf2a8b9c0cb913c2648de4ab0e48399b84cff62d6d23019cdec608598f57eb5bf716614" },
                { "br", "17138f46d4bf64d26d8e3f4e802b665b166fb4c1f1666a337360518aec117d349b5ce2a17c27c5598f51d8e98f73d532da79fc18f518b748d1fd671d8956280e" },
                { "bs", "b915050b33f9bdd7de1fa9e0258f1ee0a0ad78061098ff81f7ae5cfc35179479c6be967d526552a51d51766e9eab8bddd06aa61cc2a6c4f534a3ca49c14c3479" },
                { "ca", "e997f0895c100386ab9e6c8e5281e05dd7d1139485c9ccfe6d9f8d8abf7a487138a2e66f1b59b145701573338409bb44db42670ef416c9f46e2695434f647061" },
                { "cak", "2ab3f0a588d67ba644e730e65e029745df0af53629c831599522a0dfa4ac50faf00b54c8c5383be4ebb4b950e86dd31fcf2a483005ca4ee74eafa8e02578a240" },
                { "cs", "b1aaf1a9bf26316fe0fecf73d2f1237b4f41df1407e80642e70c18073af9f3498c9314f3cbdb65593ac3763fc07b66b4900cc59d8779d8b13e440eb66b6c29fc" },
                { "cy", "e0634933690855ed6c333fb64c97eb5674d70ee5a98485bbe896213210eec00c56ba2496b7dd21859d59ef953fe218df022a0972f1efa148e21725fda054c687" },
                { "da", "d07010acc3979a56a16ced4e5532a1a05a1d0912764ca718eac07a7e219e166a62306783bc0d7bd016b0c37b02b08bb1082f6f0bc1431f955a8b836338b91e10" },
                { "de", "14b002761b7ed73d715086c93907f0184cd6d4b223c64ef745cfae0268e09088126edd1eaac4f46ef690da180aac6d9e07ea073c58c29fe2f0d404f6bff4ce99" },
                { "dsb", "c881df9cfbf9cd3d097c16d5216544d320995c0bba3a041acc6faf569b92c2d9f49f94c2dcfa65f03abcdb14ec4a718b57eff9e08e7c31c0a5e4130f892a5487" },
                { "el", "578f2d8a60c6ef6d4200338129a31f6c7e319ab630514fd44e4da66c4f9a216a989f7654287d5a85b7a2a87437512b705113ad6d564f2359b81aad2c4769be1d" },
                { "en-CA", "959d8ac690257f364c2a810334ce153379c7db1e980eb6a959ce6beb1c47acb823f32a661f546de82902d5e3e08f90e565fcc8ede6c49195ff17cfa9b5373923" },
                { "en-GB", "c36dcb5fa08e138bcdb0697085e7ce212c5b8f7780fb482ab31d758dcc50ce1248120a95128e84b9199cac683f20a3a3d453d9ab970987f81594894e2d4a143b" },
                { "en-US", "9cf16a0ea9ec9a5ff87decd70f4bfecfc187d425a29d3e8c1d4f51bab43759d1f7cd2ff6f71c91646e2fc6de4d36b45f70439b7e634fdcd6be2c0da88947481b" },
                { "eo", "ac851c09d412d05c973c70a93dfc427ac423f9e3a9df38461328ee18ed7ff9f8d1a1dd1bae621b5c728799a38f710ca7009231f3c4168ba061ae1591450965f6" },
                { "es-AR", "ecb992918f269f15b748569caf0e7272b80c2b9e8b69f369176f2ed5cdd716da1ee9dc5abae30be4cbbf79ae500b5bfcc61a00f9bd87c7c406183e3a9ff11e0d" },
                { "es-CL", "267e3e52425f6cc7a35d19207647b6c9ddf4d03f13444912febc5bd3c1a974e6f256959e31cb33f1a65d5956685408772c296a915c1dcab8b1f60106cbd93362" },
                { "es-ES", "f85ad9fa34a0ffa9dfea9ab2e28b83289c686694e852d033f4181a390fb2d481496d4f88ffeb8df725389d19623159692b3dc6792d6ce9c5503c55d4c52787f8" },
                { "es-MX", "3d9eac5d0ba5a41d4ad8dcc229274713d15729e00d6325c1353d31c9ca0910636a4ffa7109b03f73b4900abe0394b705f53f9ada930632e64c30b138683bfed4" },
                { "et", "a8d08b356ded3ae98066aa7e4209d34b2276d840b7c6c2e0e15218de37a458dc715119629cd344b90d19d8ff9a42de918ec2b569b94ab571b653708a1894d970" },
                { "eu", "5400487e64bbfcd15c26a4694b43060f1179385500336dc55b20dde7d51fdb65e9905e05351be191e5f04cb949912836f7a413db6e17add07f3e6bc0f74cfa60" },
                { "fa", "f03ca1abb75152356b9b78f3478cb4dc78f8e49122982b8bd8fc05340e5f2aa2e029d398c5c41cbe06f880d5e6cf527746e5cbadbaf2acdc35bad939efb7f58f" },
                { "ff", "9624369c9bcc05ce78281a0c512df985b0dd8e287d32283cef88000682e8cbb23a5abb47f08696e524dcae575c4a6345bf9d422022388ebb8597d14fc64f0697" },
                { "fi", "9d30f02e22a6c0c1861304bdef228ad15105ba62a5eb4d16b0a3f8fda825a70468586404aee2fb6c85c4b89824780d7cbffa3533f5a6d93e20d9bea0ad98b6ec" },
                { "fr", "5c3c43b8dd3e24b4765f13c6a5f365a220b4b3c0f6636576922861c4206be104716a1defa8f8c166bd28f8b57fdfba4f4100700223fbb633e171e4ffb864e006" },
                { "fur", "29ebcc32efeb9d58c0d8b65db87ae42d8661ab3c397c328514753061c98f41e25b1a1496995ddb619bbfd0d8a1c5668c228b187c7ecb72ccdcfabcc8f708cac8" },
                { "fy-NL", "58561dec40c317d8a0c677b3ce933db71e8b399fa15678251c503c9971145935e241dc732a2c35fbc02c916fcb947f8331646b320e3d489394cef4fa09ffc280" },
                { "ga-IE", "d8ef5948a80c4238d62dfe5f303a0a31d86b7e4c642c07ca299101851981405150aed44d405f9ed164bbef2778973c5e0153b8feea55a06f75d838a3b80f31e1" },
                { "gd", "e4ce6819da99915ce95524f680e08fd7176c482f545433245ffc0548396b22a3c62f370eb0baf45d2f92f49569aa814d1616a58e23ffdbb19fcbfeaa979920e9" },
                { "gl", "ce57da026d0adabfa441972bab684acc6c750197391f4dde58003679996adf832600989955476c4f9fc16c52439fe4ee1880a53638a0892d5c661351fbb73322" },
                { "gn", "0985144ecaf93253dfa97d04c36ff5b9124b38754eb15a9544370c7077d32ed0c9e4154c850e7beeb4e6b72519c3d73ec80d4124d189b3fcad139682d101206e" },
                { "gu-IN", "127de206998c3510786723f73d84f1ac4554cd0dbb5b9c7433851f8797b0503b162c76bfb19f7e16a26dd517299c8103406e6394a485aae9b61ff0c8ce8c72dc" },
                { "he", "be14aea1e1d2d76497b50007d7ac88ff0381bf4620712577e701954b633ef0e31d0ba8850832cabae74d6285377507777ec6ce0b6b416f64e71e9d4f0872a026" },
                { "hi-IN", "81e8ceda7b6545ad5de37ed8176f6dd7efb46d4c8652a732579ba5f749af6b89457e10373e27c6fb19195a4e958f75e5ad79492244d814929589c9ad343d2a29" },
                { "hr", "77fdfe5f71b0d106e15257b450ff16e70519171096245124223d1dc524c1f94684ee52d9261c33cb6bb2ce494dee529e16b441b4e38289898467fad0e3ccdfcd" },
                { "hsb", "3ff8cd4fc0bd74259ef749d38d964c79fb2e555212fb2b329b72a98427d7dba93a6ce996e44f1d847a33118e9badc0c04fd67645438c4cb2d74cf66772a25ce0" },
                { "hu", "ae97db803066a4a30a205e518b90bb829386fcf0d61b8349c04894f086156dc03e6a50d5023418970e42212c3534ed274ba647818320a18fdf92e597eaf26818" },
                { "hy-AM", "f5dcc2f278aa389f672108b33a73414fe84d9a2634858418fcd00994172c7415d3346775da4876935833f77fdd596ca1c4932f0a9537ddb8b7d205426702110a" },
                { "ia", "804a842286bd72b914b0aecac83c5cf433325e1520a420fd65a5ea7ff7035df5d3d77224e38edbe042883b9c9cd0e15489ded719b5eac3ec7aacf098b21c906f" },
                { "id", "4c0989c7b6ca85c814064ee51ea612b9f3cdf5e8d937218cb8fedc80bd5654bcdf7f3950d24ceeeba0a34fc5ca0ee270e17152ab34be88519a9c7a9814400382" },
                { "is", "c1385e490a4c1abfbb4acafd99032e5bec140a456cd5ba1fd5c6dc315d963cba36a390d95ff9f613b012a77a54e6122f9e14b02895e4a6c660679488610206fc" },
                { "it", "5e8f8ae9e47e76ed09dd0966447d6a84ed5637602638bb0d374fa6398cc7490e2a21873c0bb88a5111dba37225583bc9c6d0b9645a5afa0796bde0bccf525269" },
                { "ja", "f91a1cac41a4add54d024213c3b18c775747eecff2d88a6e693e8d6b3c7060135691c1cd8514b294b3e0026ff877cea6214075c29cd7a29c8e81094467d814b4" },
                { "ka", "18fce53c4027b5e1624d66a0bdbef0d2b39d2fd790af4197095a62a3e36d665f8f950eb34b8a0d03500ca40d8fa1ea7edf8f1e55a46e9dccea59720c035f0220" },
                { "kab", "c556565bfa285dc304d3b7526dd0bff78d0e29f6f628f2470a42906efa58270417248ccb8a6f3ed409413dfb64fdb46ee064abcfe2d4b0542d9c00d0cc31d774" },
                { "kk", "a0556d48651faa9f9bdd5f860e3211a0a9a6971e98202cb58afcd6eba0cd71c691a5d8f8a222b8cd0a47b3369163d58cfad3fdd705d062cce6dcd9f7d4c498c0" },
                { "km", "19629fd6c929c543fa8e856696f85bc5f25936072678c73fbee640da971e0ed2af21ee4fde09abe49d41e1302827961a47feb12e9504145b25216ed11b22f32c" },
                { "kn", "9d82679289e06e91c772332eff8971105512d6256bbe8cdc9f94fa08ad016bf2cc975763d82d26c24420ccb0647d46a7cc0af72c6cf49a12150fc4ed4ff19160" },
                { "ko", "b62f06a08242051d3fe7f0cbb9628c75188271992e9d99d6fb3dc6a01dd0d83597fdda793855ff0e54124b7c9bd409744df445d8e684219cde431b9fae11ec47" },
                { "lij", "b7a7ed872f49a2b3db58c380dcaecb8cf209c91bc648b0b6fb6d525b6dcc8049f0eaa0c84678e727e69560f9e2688be9ec26ac4e8dfc70016e970e5873a06d3f" },
                { "lt", "c1ee123eccea6dcfdcb394d888bcd34a3b4cbc19cce58ae09848abf20b0629bce39f3b9785ba25b3d14f3371626ad12b97c1c96f0f72579467c023f2f1152207" },
                { "lv", "0e899d63e7fdf7d7e693d73ab726a1a52fab1857dd6cebbbbbf5d019558cf3911c779628a7a91db8504eb5c2f067cf418c35afeb9507864c23ace057ac9ef067" },
                { "mk", "749d22dc3091b1b649843193c96fc2a93ab90ee90e7f5de2d317a7b9f17eb7ca16d2fcbe3fca0b1421b9e10fbb2ee70b149186785e4043dbf98644fa4f43d45d" },
                { "mr", "97c46b00a3637ac678db11e4caf8efcc892092adf6c88bf03a69d087364fe77c43f65b986def32a31b9af466d4ea3e369e92043774b946052aa4b83c7d1caaf1" },
                { "ms", "f653d3ddf95775dcd9d42ea73dc9f2a553f4f3160ed49a9ca4e91eb6a47dbcfc676e009a2f5d7767172e5921a73158b738afdf6a8919fabe59c40bc93fada98e" },
                { "my", "20704c19384b04b1484566aee707426e3c79a53ebcc7541cac165ecaf4222559233a75483b139b5609b9b98a57e4b10da586ce0e416f5523b5af5ce25d5653c2" },
                { "nb-NO", "a598a1247f99782b987a05375434c833ca1b063ee9a1358e6187953164596a26c00a420e2e37ab6d8ab5d035cec7587bedcf1bc9b3d3b1a74cbb645e7a47e0c7" },
                { "ne-NP", "a1a46311eba509c7957190126b08bda1477bc2a57b34fab569c374806140dd3c1b250ad74f1c795808240be20611bcbdeb0331d7953db9e8de6610c10a909e08" },
                { "nl", "2a12283e12284724b7db167a3b7a0482c1a1fd338ad9dba643f4706db883bab2a593f8d39d417cc374947291333947014ebed2c625dd4f7fc9032e8c01e36f29" },
                { "nn-NO", "62459ce320e1c1d4813e37c629e3d96a6e2bce150505bcdc12ae7bf89085004ea6aee097b57ec144e4820a2dfe7d0b6a0b30908bf29267af8ecca1e2197fdc84" },
                { "oc", "980404646fdbe7560bd7197cb2041b6289adb727da9de6031de683fc72f9b5534e0b74988cbcaf91f9049e67b297d5f617625c6e12140ebcfe307a2ab495499c" },
                { "pa-IN", "10b7c1095a6a81476cba5d011956d5da385dfa8dad39066258c2807d85ddfb6c7b7473f14807740939ee172cffc20b27d7be708c8896a9e96b2ce6d5c7935b87" },
                { "pl", "02b4834a8ccdffada64127b92d3833815042b58756c1e812e7504b2021600be34d7ac3ea94319140f900da3bafcce34b9d6933510a091cd5745134862ef9de96" },
                { "pt-BR", "4d5e4a0302e0833f71c6a5a2596529cc60d225c79a4306f374c677a439592a048ab552085fe7e72bceacda6feffaaea06de62640acd2a0a6ffad94afc67a428f" },
                { "pt-PT", "2678e1083f0d6bf516b6898bd3abe94f1b74cbe6ea5c4f9f770858541cf821757cc0a2c57f172da64854a5c2dccfd8ddf11786c43be9d2a35fc0c682437eaf61" },
                { "rm", "7c43fe0f8ed70e05dcba902359e700431be21fd78d00174b43237e1c4737574126c0761ca843513be99843939791779f9f54aab3ec7fcadb73a4b5228444d06d" },
                { "ro", "f80564c8dcf98b42f1813ab8a7f54d5be7463b459ffd54d1657d4fef905d254607fb34fd8f1a25511f2e74429d8f5c274d25e4d6f4eddae6257efd3fe8c2e212" },
                { "ru", "81db1225de35e0e91be6ff8fd43f801c31985caecf36936f70b1ec461ce9eeddd8d8c08f035d21a58922e8691631c1471e0e07c384c4f6c6db25e9fa2c2fd93f" },
                { "sat", "5931243f973fb013977383a84c46b554f0e96c3788c7d8037b4edb26b08c64caa1ac770f2b6650f2071422fd295c9c824b9f51ce2b18bdf66d0800f3d03c816a" },
                { "sc", "1e648890dd9e578640bff54bb496437b6895f71e22e197b183c029bb65a87920059a10072294ae7926f2305125a24653e4205a6e711769610c48039e63165fa3" },
                { "sco", "bd89b30029f73e45b83d1d2cbb3b26487f788ed6d2b81187f3181b0b198ea8b1771184833b24197d992d5efd4629a853a368ca6db11a7278f7126229465ba4a5" },
                { "si", "0d13ef62c7f43b230df6f9b817aadb44f6789be5f6fa92ab4c578abf7b905bcfea132dbb26b971dc8d5569f95c9e44caad91d5602bf4d900f7e30165204bb45c" },
                { "sk", "7071e19cc560e77a414abd24a36cc86d639e67d2b9eeea6e2d583d6b1a0b72b29a78961c0a9090dab0b7e24a5667f62a3b62d9ced389707832b9f3d68f31f15a" },
                { "skr", "1a54ce4539a7ee5706195d1503bc98c5499470172fe69750ea584bc0962af16f5d1bdd4108bdf5a2ac162c31876aaee04f673390933e87a89cf807131df2e3ea" },
                { "sl", "66dcfed5c276cd88a4f848a98991e875c8fb03804f1feb213b7d6342ea85eb4d8d375373c76f69a3a260db27be6891279e68a30f84fdc6c8299c6c255f03fe98" },
                { "son", "b4ddf2f49162d9b2e015f15e3707f317860a2653809bd15b436675de7ee469c911a7ce53cc64d76714189f718c88aefb685fc6ff54b0b6c40e957791247847ab" },
                { "sq", "83b6fcc049e04cd0903a3f05c0f9399fc44a57b89abdc0154b83ca2599e9c4a6ff7c4f8b0682c22dfb1e6e83cb177ca22a712da7c7066eae74fbbc1135bc061c" },
                { "sr", "e65f2e36cbd9d2be1d34a21c5ffb4ae502ab4e4c74a94e5f145052f4eb2647d131966a3c10f6be9ad2d5ab2cffb34d573c2193b811e5631b9be034f25252b742" },
                { "sv-SE", "78ebb3bc3d8d602a1a3b92ee6e17b0afe2e2c789c143f1251e41bda2329dc336ec7dc65348bbf8e741f5cb2859e40aa924763725258ddb148ee00d9b189c24c0" },
                { "szl", "07fa7872665c10685774f0a78cb648e6fce89fb0ac98615ffbc6bc15387eb813fca7b0765bcd908d84a97e3c076c72c2057581725c5b2b0ef4b09e3c37878abb" },
                { "ta", "e7943c1ca238a471b5bba5533adcdb32fdc62b6fb3bd6648a8d7ffab9d4641e1880acf09ab180659d5a566f6fca699fe9312f68ec44c3a3ddebd25baa2fde0ca" },
                { "te", "7b694220ab5fbf83c72935562b44ec9a4bb94ef5b872d33b67cb4a859ec31fe69389530d1f21a71ba4ffc9bf9ed4983ec433668aa5a2acc7cde6c85571a7544d" },
                { "tg", "c634915d49328415da7fc320cc9c6dc5aa904696097140196c37375a20b5500f9612ef4b1fbd13cc3aaf271d5dc2f1679e15422552a92cb81ef29624d7805192" },
                { "th", "3987cffd1ffa5936eced625232275d389b39827e32de079a246e737e62b583d0321a8271b306022bbe33917eae990b2a188f52a59ab7c7635e75fc81ad052d5b" },
                { "tl", "7ff37e91a2216ff177d85f36cf2208eb3a33bea310970bf7d0964ca2a252e6587cbe3eaafb0ca1e2cf57e72c0f8dc12f25c82036f480f600e832027f23fdccc0" },
                { "tr", "cabdd16fbcf83102734f336b6911c33e98c42947b2d7689980d36c56681f3f9d158a34501d50ebe6633d3fe533abfb5c2a0b57889f5be4dfbac8ba3ce39a8cd6" },
                { "trs", "5d663bc5b73c87768a4b861381d5f8ccf8c654fc2f44c7789690c480bfdc09758a1a0d5e8deeee00c146e885e141bb345780a93628f37dcb29d89dedd228b3e4" },
                { "uk", "a572b5d8f17ad4651dc8791f6096518061fb2b1ca3620b12fdbc1072b06a096e207937e855515a0b49eaa3d6a2e4e644ede4a4845b6082dc39b533b0225fe4fc" },
                { "ur", "7ac4823710831dd72ece80e53e057561f41daf98f06029cbf3e0620c7f485449846decd1efa95f8c0cc3d92ccaf0b0c856b993bc121d8c5233bef16b808c6a20" },
                { "uz", "b5ba00c81afcb5be3ebe90535b9543eb57041524c94e39a6faf9fa53e67cd9b401cfed7a32fe1ecd3cb8b1572c6dc6a1f7868318057cba02fc872b972735485a" },
                { "vi", "51b1d1b52e98f2038d5892a15ce32378bcc8556b7583856f0f541f2b603649f6244b68ba15721da02759c33f2fe702be9e44589bd0746819b3b36a05b5043515" },
                { "xh", "87eb8c0f4544050b5fee192057a30f42d82857d8dbfb129ad7b56e1cc401e684ca6dfacafaf510fd874074bef795bece4ad985a882b693e3a8c2704d1e2a757e" },
                { "zh-CN", "415619e81b5275ba7a443c2bc113443eacb2241dcb6c98a75f44efd63c52cd43309c46146b8298715501ce8f7b3b2199eda80d6361a933d1836f2bd47ae7f5f1" },
                { "zh-TW", "ffb7eb1572b19b11249d1d867271a3aa0f6bf815f4e7b11d6017d3fe0ee415bb99c9ac45a2e045b0db66f4c974158a098e3ce261b0a128d363c63c82165590b8" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4e40e72607f0bd540cd36d87c31c0afa7402f03f7898b59c5bf7690cbbf2f01820b32e2077383a23e8dda8166b743d2fc95511027c798d887f3d4c0acf95f4c0" },
                { "af", "9aa24f983ad92c51f7e4f21fe7e2d1f932d3e0413d876a7d64c1b495ea7769a9317c53736f308be23f2072fee3d16f5e3729af28fd662ab7763ff40644a6805a" },
                { "an", "ad953c02bdfff2c45559d8c75775cdc4c8f98492d8ec50f33e5cce966bc7e667085b3f79f09eb6b006314bcec1c3c254229ba449ffec2b8a2afc035d17da2401" },
                { "ar", "8e79bba7416f14a7d18d300aa59d19f486bb01ef83a3438065067204b43f87bf889b24c0b20e29884390dc55c6d7d2188331b36d56a9b9d4304fcc8b6fd5e3b9" },
                { "ast", "0f027ac0176d080a0ab25cdc3a9d8d186a61fba8f927d061588b47f52169db04fd69ab2925130a3b168812c0f0fde7408496e6f36ee4e405c9ca1af13306ad76" },
                { "az", "61132973a69a9cfdf348114c30830220b99f12c4c64348861f75706507797544f348da47ef44209b1ab7771d9d685dfbcf7039ac05039a884cb8ce8667961310" },
                { "be", "94a213c8c70bdfbe3267fa8922273ccc4af53748765fe903ef16dd2a9740e99479dd7e58eb7616fae7c638480d2cc473e4a3e99ab9c73012f4bbbc3a3542c9cb" },
                { "bg", "5c0fa0cfb6361af33c231ffa1378534b6ecdf2599d09b1d7e08f87d136f4106426ef66bf8910a6715b98602a201aad197f6ade9fdf3edf826a6917c0d33d0221" },
                { "bn", "de509f51ec959006fa1c3f573d906f6db286c64fb413868ed40fcbe8c462f2683b0e04bca5c09fb0d667e8665794ecf25624799499910feb7e2bd46060aa2340" },
                { "br", "05cf0014f5f0fa7e76eaf35a9684604429cda3008d33a1993ecb75cbac8046fb031f8fcf4e99a28698694bd99c637f4700bc8cedb38d795f647d7837820e2d4b" },
                { "bs", "dfc5e48a3d881896d97aa2f4b6719f9bdcd99cbab02d5ac8b902196d27c660d9af3697bb353073c845a850def54ce31601788c5ca5238707438407cc76248b56" },
                { "ca", "cfe896cd5b594301bdaf9bfe9bba5854881f50b9cf944e1019423c73eeb048132208471902cfaa0ca71c9f337836258ebba0fb430ed9c8d45039fadd2c7f5850" },
                { "cak", "bed3d46bf88803c00a175c271f953d65983a097f5773d91a7e17aa8eaa7eacef5bfd7bc82be8d5d6630bba37ffc453ed5c6335a10d06bff1a2f0fd97d3573204" },
                { "cs", "dd61646434e509f8b68a3983c984c9cc6461df818b4c9b0042f06f0e1a3a3ebf540c3fe3076ea5cbd8aab2fdcd86a4a1e497d36719501cd300e217543b46c534" },
                { "cy", "437e8f3b0e2ac2f9faf1426b00f6d1a7e1fbd3b78c054ec4ebd2a35d9d733a7e11acb6b454797628e028f179aa70ba8891260c00da1ebaa911ab7cc8c9d37f57" },
                { "da", "0097a236e5258d19680e94cbd79ceb0787aac38bfdc125363b5aaa64b8eefa7b54a9bee4381c96030e5abf0cbbb4ed8151e3f1148523036eaf4003b94d0dc249" },
                { "de", "9122f693fc3e1ab1a5eb6c98f6fa67068336a198643a7d21bbea7b9f60704c6d5e644abea3da0be03293e6b4cf6f96a927ac86a011a6c67f32ad042d5907903d" },
                { "dsb", "04b95054325d9a005739e77329825c60e9cc3ac94a31a95d9094bf57239c6e3a9a3224931d468227acc1c0bcb9ad565f77e4fb6047f7351a31c78e7326517393" },
                { "el", "5cfbf8eef6759031dd713f27167d617ffdb1ebb3872ab87e5b4681822297a11e01fb83eb0feed7340a2574d6d8801379464bed0830d269534d800a6dcb81518e" },
                { "en-CA", "f1512c77d44d6c33dca0382473483b8ff5d6399b2865beea72409886f688279cf9a01ddd7a187fa4d3b8d127d4d88225564eabe12415c02032082b7b591ae46f" },
                { "en-GB", "8a72754a4897bfe9e8f842b50c06841359eb716ff8cf83f5832194d082b1c5cee9640ffd10970998a1631a3e71c2bdfc0e5c8d71aae8e6bcd3efeedfb4a84895" },
                { "en-US", "17b79739d067ac5a02c4d261d6aba01646de23fc032c25e74a333201f54b2fdd66e3e561bb630701c4df55b42f016823daddc98557d7bdc9ab575c77e3167a6f" },
                { "eo", "230d155425f791051087ee22da9376e380e5d5d93ec094445faea6816e041ef3be0e7c7edd7e080ba8e928c7ff2e99501a48a49bc637ea03c88634ba2ee43d0b" },
                { "es-AR", "9b121fe77b7b5c2d61d10f82d0aa0d1da19f424fadeead380d93bdebe9a492297a6917bf3868d6d33863a58251808d724e00f00d6c5eca32bad87a32d09d3c83" },
                { "es-CL", "d0a2a0da5f9ad6d4e1d365f5acacf5e1a1fe5508841302f08b71993659145e2a74fcb2105502b8f7603e09d336f22c6c8a7a651e234d2705fa96b11a0b170902" },
                { "es-ES", "da4186728725dc3f57ed30b0e6859606a538b74ab8fa254594e4d285dbe5aa6890ea95df8a16c19b4536c1f98bcd81659a30fed0227f9face16224131934b657" },
                { "es-MX", "2b7abe831fdb4e3cf1cf43be77352174a9f830b0bae499164ee68ed2149d3c3f8a4ec3626cde23e847cf19a6309ea31a0d018d9e60747a4f5d43976bc90d9e15" },
                { "et", "81c8664eb499dce663b2b08740b84cac2f8e3a9a11f12d5b8f7e08c48de023cce60986cadf8e82d9be3c3435ec4829d2ec8b8a36b3b7781ef2ed86e9106455ed" },
                { "eu", "7ac92e4c968b7cf8ab55d9f840c4d4c39c640d1dee540f054ef5d660d4cdc3e4770851c78d4cee6744b4f128d0f0b274cc47c2ba03f0452b818aff7e13644662" },
                { "fa", "b4762e714e004bb93145c91b8431d7aa11d6b9353a48f92fbb3b4118c2b38e777785a1755a0c328c0794275acca268970227e0b63b49f497c1fcec921e8be4e0" },
                { "ff", "bab685e9460129ed05d7ef4dc194ea086d4e56f80202626fbe8395f2a878fc338c1f2e2f6b9bb22f4d285ed378162867715a5290e36783a67439215069f92497" },
                { "fi", "4ca21d4d36df7222bda84b97068de11da37aeaa3955f94b87e785602788d5ce5d3722a0970afc12a46bcb35675b21e42c065898a595e8cdaee2b02d5c0be7cee" },
                { "fr", "b8031715db367f970fb34aa918b9997a0e06549b442339806ef77712e75c6501607d2bb38c0525bdc36c4f6f16188f4c8b4844a4b8168433a5a346ca42e7c7b8" },
                { "fur", "6f4eee039e85d0c90556ea2c314113d0de5ccf9e4eeb0a929435e58ab61a2279006afe2d85a8bba50d06b580481ec76bcb5c01824643a547997f9c2dd20f01f1" },
                { "fy-NL", "b7125fbd1bc7527b19c38b2d85342dbf31fb6093642214b28bca78bfebd28d7280c50c2114a26fbfc16da0b03c774f99ea22f6d2709b6f49b457f619cfccfeaa" },
                { "ga-IE", "2c98559b9a121ee2363383483dd103c9bbb382070720c569545633907dd23194fbdb61b79d0c658c211e693c57a4dbe4236cac4cd184b937d7cbf5a57974196c" },
                { "gd", "cf097f757d0432db615b756fc8f3ac79e59e17b5204c984def10916b40dda14290a01ec90b47cdf678a4f88bc72ffcf811d1029fcf71643f1a6746571da8107c" },
                { "gl", "6083f1ed347b48e055779e8f023b9696004a9b3c8306befc3f612c8594ffe3497e821659a4f5568fb82b598513401c02d92c132118a1328f39fc8040e8de53a4" },
                { "gn", "d987da493b76553d5e73baf0a05a4f5f5def57be10febc4d4e524846fc256e72f0a5435342be81b2bb49930705569be2d8bb55fdac4d640923ae9d14aecac415" },
                { "gu-IN", "346f8f22735e89659ba8cca87e421d085f5116d1cea8484477c1989cbd553403f7f2ab87a5052d13dd091502d9d4643c1c2557f5693aec938beb8395c70ee278" },
                { "he", "d4bffaf2db9df3d32b8bb2ffc716f25e627cab99758efbd7aa52597e771451a78217ac22f8ed14c225a14eb5615e220d0f4059356cabd47bb99b2937dd9ec5e5" },
                { "hi-IN", "9e6a4bdf8128f380ab1e7a2d6f03492f2142285b8e3b4ec2ff73cf05ee5cbf05573ff67bf2cbf2b6d143a6c34ed82b64bb53de627c15f5439c9e4819bf328414" },
                { "hr", "95096ecfad8bc48d5fb6c34d57bb4d4a923103deaac784f55c1840d1b0f19d93e1aa7ac6bec9015805b0d9ad57d45347ba055248d8581059a6e7d0671e28f329" },
                { "hsb", "18951eda4dd543098628a7da46526a81f2a720992d446acec74c9fa682307de5f9ed099b4c0fbec3a61913f40113655768accb33fe406b2fe72c1df401a03ed9" },
                { "hu", "eeeed644eb82445fb5272fba912b1fa4d766e3ae3ac8e16077f1ddb977c7ca9ffec779bacf307739600c550c988bb2c1cff5b5c2366ebcd9ade4333002019543" },
                { "hy-AM", "be110bafd3102d0a52ac77a0dea4259bf81da4153e3443182fdcdb728cab747359f7394e3c07a5d220bac9c9a49b26bec6c5930a81ebce9bcb423d68154b8806" },
                { "ia", "825d17b701fa02e819a8333114dd95300685947cee60eae8954555743ad3d3ae6899edd0e0ad27153916d95c48ef4c0b18bc9beea3cc1c2f657ff63431d4e9fe" },
                { "id", "4974f5a45fa22f049945664f13db90ae359719c77d8c92c1624cf3ee484b36f175b76d01b8b608f8dea91b65f90de1b97d1dac0dda3df2a912162b3ef067c2b0" },
                { "is", "165d5362fd402410003926f6cce0675eb73fa9200289b5b025d1ea9ab64a4914bae722bd2ce87b0ac561f05ee641da785341b0fd3b17db06996142ce6b291e69" },
                { "it", "e5efb76a7fab8f19dcff411c3708b3398ef00fbf131a780e58788d4f8954ddef7cd62cc373651c15d85c9e8cb06329cb07b07bb1d47ab9876921b1bb6d12569c" },
                { "ja", "5c21db838790e5f47d871666f18ae4bce1db5c6a3b08b2e76a22091af268e5096845ece033743be6596c1ece2e73f1ca92f15628c5e971f94c1fd33a27a9db8b" },
                { "ka", "cdcb84e829bde2e08385f1ddd84618d69884bf4c083fff8fc90cf87dbf90d42b3f92e9c1177e77c7ba9d33eff638c239e3d0bc6f13a3a3c6aec68a4e24c61290" },
                { "kab", "d29ef03f0762ce6cb8c94552ed9756e052be3b13cb557d35dbd1535b5206ca833bfbfd7abe2ad1aea2586d0898b56663e65429ed048d967f9bb8aa41208343e2" },
                { "kk", "468ba6528e6434e4036851866c068639a1b7a173ceeebc7ba8c1eeff17ff64d7597b40d1460abdf9b8de72b636c6ff85bcfd7476cb742768f0a79efc465ffa05" },
                { "km", "fc7e0366f21c64ac9feab3851588279604e49366408076e2908b9d75e069dd0dc98a3593e4b753023fa098fae02c2e9d930ab871430f1fa8fda1c8dbd9a895b6" },
                { "kn", "939bc92edf5e054948e51718b6692cb4cce4852d323b457752f4e5ec24ce42bb00288fecde032dadf3e506d14cec55a761574e60a23ded96938fff0d1e2a3d17" },
                { "ko", "0f14db88d3f9bd5915d04c4ec514f77b43b00de714672d01d145fc3c7f29908292d0b84a644fb68e766fa735c2dfd6ce9d9b204aea6dedab33bd637b82191ca2" },
                { "lij", "58679236ca105cc77baf4e4df09b312a7d51f042efa2bf29341ec492401fdb560eca25a693dacf8587ca04d0787ba8b81cdaaa000ab5f4486f8928aca1c259a5" },
                { "lt", "8959aaa39dc41bb984f44958a8af9ad24e70843a669034a99153e096057ab8d4ea47f6d5c470f00570c1546f5f8d8f3a8c72c529a819989fd900014c861a24b7" },
                { "lv", "df83b5afb660d2c774af1419632392d96cd14a473a6d0aed2e47dab5c40fbae9e15d4c1aa0f95a3e54483407c3226a1f2094a8a8439b098778635eddd7368d2d" },
                { "mk", "79a54736a169c906eb0ccb974d7e347e544f90b46793978b910211ec1cadee86240c370438f3d5626befaa5de3ebff7c1f8fcf77011558382ac409a353fcaa14" },
                { "mr", "97121407bce16769ba01ff074fd7f62ad3899007c858d0fd2245c0d2ba83238c967b012b8e3f992e81ca3993de63b082d3ff4538c213e24ad21d1cc723accee6" },
                { "ms", "a65da9dba7232600cb5fbcf6c4e409e5b3ef4f229054cd2fa416f468a9da5b46f81d5785c87180780ce2802ca7c89854c5bdc86f850ede2adb4baf06a0e837d5" },
                { "my", "c9f7cfa178ec8de2f5d4690faeb4e7dbafc77197285118ef7c3186048754ec14e38b14385b9d6336c1bc8db1c78d0ffe40d38d7226e79e6983b310a0a163636f" },
                { "nb-NO", "bcf9d366c87005bb0012cab965d923b65d10018c853188d787289a5111f530a36eea6ea27a4e0e3573b98bae834705d8d59098fcc8b599ab399b843def4990ca" },
                { "ne-NP", "0df1f74fbe41a40189fe355aee7879f37b451e26545fe6f733b01fbfdcd5f81de35468cc8d65ca4b50d9d57a7e6072ca43d29214718dee99abb16a93511f07c9" },
                { "nl", "ae9e7226461f73ee12d53c106085fd9ce94badceb89e0b7d9ed0b25a5043893c8985817f075d9a0750117de9b045c1656c097bf514ac2e42ab8b2dbb6690ff56" },
                { "nn-NO", "c397dd48b8874beda97811992842afa68d4e05d03008dc9f054c031c0fbe53d5ba75c1e80a81a2a19db7fc2deb04008ffa03122e4a5ca753a14793a584c4859f" },
                { "oc", "97eb49f21be62e16256bd3a6a5cf816f0e9ff3bd15e8cf07b5a0cf4d3bb670be378ec8449db1ad2e22a5609d259e5b6e96798425569adeb3691d9293c8e9915b" },
                { "pa-IN", "9aef692c812992ac55b149c3ede726592a721fb473736b3001832d68d2cb117e2dd4aabd2d13b70d59dfd6171c631452bc67a11fd54a718b0db06d276db3f079" },
                { "pl", "bd18ce421875e82c90ee3c20bf12c98a331cb53891ac66fb36da18e9faca1f8da1dd4f97635ff15bd1900bd4e29f1ce3e201368f2ed37153b638384f0360d533" },
                { "pt-BR", "796951bb3d5944453d7da24df2f484eb9a6c698d5972cc08c33f81faf930160018e51df0047917e20c8d7109f1ed32001600e229ef043c184df348450d9019e9" },
                { "pt-PT", "556017b52df790b5dcf10cd053cb8d90a034480403b9e3d752cc61177c312d0e9f9f03ba603cd1bde1b9a82783c0f7be957e4eb5bf1964a847b7c2f12a0f1bc3" },
                { "rm", "73753f1150ca19a2c986a7eb21ceb0a0401e3cb296c69159c8307f7984793cc436ea6fa5c28ea22f3384f2526392ff0413f0d17170635a21057427c937a42c38" },
                { "ro", "543283bc404270196c91e877414c5c2869be0502e8497754a4f9775999f87997ed57712df8f9cc1a0e27d63485cb180d065dce137e25a325ba725496c3d3bb31" },
                { "ru", "2ac4cefbd5896cd8d6e98771c9ca8d854d9b4f490c7dfc5d9bbf7c6104eca8a1cd3519430a3f7bcc9b2b06b0d5b5964d4b66f7c1062b597a7f233a2c441469b6" },
                { "sat", "43e0acfbf0067c8595be0b32d638a56154bef0bdf1f3129e51b23357a6848e923b68204f753bffb34734755c7d0a4557c769b7d45f80a45056346668376e49b8" },
                { "sc", "533b64e3c51ce42a18fee322e8164f25d3dc7a1975d6273f67258544d76b121aff28bc9e76012a687d6ed1ef6442cd567452ad59b8430723e1622a6b7de9bd4e" },
                { "sco", "66e98b4da00254d827c8700b8c4c89709e59e3ca5020ca2529fd07b6bfd19327990db265238135f95fcac18f677c32c615b0217a9573ec8b50cf6a43e1d91fbd" },
                { "si", "781fdcad2fb7a69773632f253e9d5e26bfc3cf5aad310fecdd249eec7111176da3e5b7b30e45bd6ca07ad55412729007df22c7085624c8b310bd922d128e9328" },
                { "sk", "fff64d77a16d72425ccd16061234395d16238edf35565d91ee63fbf660dd62eef78bf17d0e557ad0c6eb6e614420dc9e5f3b28168e9e87d23831835cf3ddeb4e" },
                { "skr", "d3924ef7c213fd9fa080d1e1013fb447564dc6ac7ab299aee4504c21df70b4d78f26e6396229b853bef4c9480e7df92a6a630e3a2e117112e0da59049f61b131" },
                { "sl", "3cbc81a9e96300876d7c799a85c16b5f002c2ff379074eceb9caf09226529f93f88be14432b611f28372a1fd75145edf8a8e8b5092749228c82c1db851674087" },
                { "son", "d1aacc5f8f4359ee86fcefbe8c6add683222c515acf4581a81d026cd71289cadb8b03113c963ab5edf8ab94305ed0a3a088b9d8d367d34d2e5cef04bdc2d53be" },
                { "sq", "da33dca56f8c068b28a3df3203af80a887e47906136b92f141b8d8ccc9115bbad9d007b3c329cef656c5868edb4fdd1b9b7c8dd1e6ee1eda8db77f74a33aaa42" },
                { "sr", "1ee338a97fa41798e42b14da4651fa985693b65bef588b3b95cc83457443b5137f8fb6b755cbecf184822738a77d333752c63953c9b3797ebac20fd89a05a7ce" },
                { "sv-SE", "1c5d7c57c842ecdb8dfc7058c5c03498f6a18c2e5a23e18555cd9b3b6c5ccf5a34574c6560be314af0a50bf09b91d664e0e8d637f3d8a73a82323c5e86310380" },
                { "szl", "fa6bea48cc422424c708382b348a02eb7308eed1c91c65c05ccac47ef8e64566f29dd6f2fdc900485439a92723761bdd274de4553acb54c50b1995f2bf77bea0" },
                { "ta", "960d4b6901ab679eb377b1a40dc07d265db4e088eeb683ac2a5086400695df31509eac5066b935a87f639c5605ac5a57557de3b13f8a3b1b87098c7067f44945" },
                { "te", "50c931bb17adf492b6778ff94a995f73b0e1e134b8b725ca6e6eb2150ed8535b1694061d14e36c24ced29665a52b10067fe231388dd22c0c775eb953b4fe1218" },
                { "tg", "6ae9baf38f506b36b93da32c2fa1a6145367ae0c48c5b7ebecb6e125dceb69d56b8f6fa0b044d41f4f85cf1c8569e5be793452aa9e9319a5bf63285cdecdc64a" },
                { "th", "50068fd194027251fdfadda3e4ff5229db73e414b776ff8e93cd3d2b250f1369a3c351052ac4ed68fd112596b0f3e512da168db1a3da0598bb2d3fb89f7fab62" },
                { "tl", "29cbcba6ff8dda5c5daf9bea8cd71f405dcca567eb58c70f9cc7ac7947fc5f01ffab230e9dec52102ca1bfcfbce73dfe46960e287d479788e260d47c836dfa3e" },
                { "tr", "b7ccc04d3a224330e1a056090b035bfbbff7507b55fd3855aba15a88586005ec2f0c1e73bc2a7d5dac0d08e829588021f0b10730e776474c5980768649340393" },
                { "trs", "0f103aea8f4b25c7608b387ab04470da9ac5ea9aa195c43c3ace432dcfcee6295097021221c6c312c79180380dcc853204906c90353e1c2234dce8fc2d73de2b" },
                { "uk", "f760e4c8572a3d9d57c0aa7e98e83c553a1ee80d29ca91c90894e805777a7ab12f71af7ab2f9a972d4e054f315195d4b17ac9fd71daa7c049b19fa0974bb57de" },
                { "ur", "52f44791c5898eb7f6f36e0febd09132b366b5e060f792e35398b572b4dd0be379a87b5c0800aa2a45c1b612725fab520afc36b48add8e178952c48fa51e322f" },
                { "uz", "8112809e754f7f00a56228b82b8bd3876517207c6584b20486ef8c652df5ff17dc49e9b985e9a625f3ad0e920cc78dbeaf9dc9c19162aed2af93994962bdc15d" },
                { "vi", "5047234a693b75d499a012f3ae2e0179488ee6471e79a1e183b4e208ab0e8c1a45d47cc0e390f872b765a22d8d3bb8373cc3665cb11d20406befe2b9ed5a5be0" },
                { "xh", "de2ee83d57478285ded86dc21a289190cf677c84c64d2b8be1a34fb6a460e8d7fca6fb2af1f255bb90f07cc59d7ea0240dd869a04706aa8b763c3129662b2620" },
                { "zh-CN", "347c4013cd620d7edae5830e55de837c47e6c829fe27bf62857198de9c81f0f99acc07518b7903339f57a9d5b9d9a8f5e2264e2320cdad806baf080f6e16f18e" },
                { "zh-TW", "32f2ac32bffeb943129eb10f82bb376f4093426a95e99aaa2194cb560640b61d507218d62db5a3654cd855e4e391c4ef9f7550c45e34ce6781e743689bcba1d2" }
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
