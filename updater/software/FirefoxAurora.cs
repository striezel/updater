/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "99.0b7";

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
            // https://ftp.mozilla.org/pub/devedition/releases/99.0b7/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "793b96ad25d6e09a6e19f6eabecf1a53bfb848d1cfac0973d06f27929c881549fcd5b75f40908afd8bf15d8334b0fe606597f33db7326cae86157ebe050e5390" },
                { "af", "1ea730b96cfa564d89c3a3137814a7072175c9c84da0a04a4b65ef2b662233c5e8445bd1145c67abdc05f65ac080b6e6a84b92d52791b544db20921eac9df07f" },
                { "an", "b044af17dc31b126dc1a04ce558350ba7546a0c2a1b0327af288ad8abecbb67912bab7db2aa14ab2199966595ca384fb0b7452e276fcf90d5fc9501c2c835aaf" },
                { "ar", "1691853ffc4b4a9e1ad1b83cbef210859357e15937898152062cfbb082d22a9b1b396ca5b3ca59d57a97dc452a52904e61013aabefb9f03e4397876672bf1298" },
                { "ast", "ebeb961fd46102014e9f1d0f6eb592331a7cf493b629e30315235a0288fa011b4fcc6b3aa8b4cf4e7aff2858392e64d34047b2d8f42bb13142d89b6318ba7da0" },
                { "az", "2b9ff897f191a37c8b4d241aec8419b222f60f2a3a93a187b5ee64cd8aaa412b999dd66702a0a31ec6fc0154fc2f0091d201c184475d7a79eda77d57d6008c48" },
                { "be", "5c5464d14a63a421c38cc8ec3b56f94141dc3b70dc485ad6205c897561db44cb4d634319dc683e15126fbf1a69c8f59fbece94026cdb07732fedb232a92022d7" },
                { "bg", "2ee570ea89d7fb68c73231c718756557f5233fd81d05afab9b741bf834157631fb570b25a98f7d46562723052189f239847eaa7bedadf66b83fa1cd317e439fd" },
                { "bn", "ce63664ac4924ddbc26f213cf4f5dda181983853176e0253add8a9ee4622c6047fcc07fa457bbf900ad9e802678a9077ec20f3c407b7b1dd0eba34d76188c261" },
                { "br", "37a4c232a3ffd680eb15b162960d9b060bcf6ba4667b3caa57dd2b2dfc5b37d03006c51ea51d3788bf7583bb37f6df8c9e540b4c5b56b88b509d25bd563b4ce3" },
                { "bs", "be06bd8bad913c411f249314fb4ccf1f6a090432a0e963cb5b23639ed77887f974af1a580f6253d7eec452e8e21e9795b0fd98dfdfc3e05dc6f7ad9bf2be3f36" },
                { "ca", "3eddd2a9b15b4fc489bff872cecb1adca6cf796e649df0cd036c2a4ffb27cb14fa53a46cc69be8d291ae5b81df64225cdba4015a8f06e515af97d917430dd0a4" },
                { "cak", "1b7011ced40a078b28e071679b492b116cecd9b151c97029c2f58b82964aa1989e9cf8f43dff26448bdff16ed7bf8f901f2d5eaeab0bd66bbd5958e58843d9d3" },
                { "cs", "44fe9d84d0933c28f7fe4ad56b47861c272c9fc56f2451cf30b3c31beae9d569f2b5cdde638cfea412e17c918af9c9741ec2c1fef615da3adc00a0d0668a963d" },
                { "cy", "9f03cdd7a422f7d7074758a4190b4aab46842d91b7bf0b20397f4225648276c047d86584f75edb8c1e645e4ac6d6c3ecdca69c703e84b48504e29f2d111fca22" },
                { "da", "15ce6ef2ff738c37c4406432fddf3201c9c046a6ab597ccf990e325c5b199e3cb3796c1ba81d20b10b7d77c288b72d8599b0bab3a50537edbd46246abd50f978" },
                { "de", "e9a3cea9cc12690d166fe35bb1814b7e2c50e992bc2f42aedfeb678edbb8fb127833bf3c1f55a1ced00ed3c4b8570912f7044c67c4256466018e98893da27578" },
                { "dsb", "d9d3140eedb10bca2e406dcc23b43334661908e873ed9b8f47ae4abf5fdde362b9e17244bbe1d73aa0b05aa1cc37baab0a3744d2a7a679d94dcc999f1d2f6671" },
                { "el", "e8f4ef63d90db3c9062e5e21668312b21dce0e7a91dbec13f324083adb9b4b290cdf2e3d2d8d240b21dade73d70ab382adc0b68626b195ce8ba2dbd3a87c6d2a" },
                { "en-CA", "2a6195db6a83ded77787364cfe467fe537418bbc875624e3ba63ad3658e08b2e2bb693eaf6e02b853f994081eee262ff7f289d05f3a4cea21900b50cd70e5055" },
                { "en-GB", "b47f88fb212e644da57b9ed9c583fc295d75bc0600d7e3cdb232d4bada3b20d6b83b9d934d79925864c0d1dcba6f1825bff7d5a49efea0e33755bdbcc86e8262" },
                { "en-US", "0fd7d6818e7e4ea41e90033f9f572dd94aacb426254f7e6d5acffdf44dcf1fa37fbba0ff07ea1eb436690d2cba95f5bf717d05bc60e01032cc3e74d26fa1686e" },
                { "eo", "b46516a8b7aa42c669a540168fc60708094c51798d48f9857cee1a424fa80fc5cfe71a6613b8c2c8d9e9f0931fcabd0015e3554cc207dcce523d241b30e5c2cf" },
                { "es-AR", "925ec9152ea1be4e6ef99cb0bd7456d835ffeb80a46c664093b6b64415e564994e1e479c212de3cd66cf7cee42c6100be7c84fd73401ebccd3a5772a339bcc64" },
                { "es-CL", "d6b5fb8ffecddaac2485a5e0e8dc86a89c8aa8d4068a299d353c072c1b7b4f0c3217a28079263b1db5ecf149c2a7d7d24f58b7852c5ac3fc0e73efcc0d3d1812" },
                { "es-ES", "e07c4afbf96cf69b9aba0f03135c77c34b1ba6f79aa80abd4145c4f69389ed98cb4d5386c1d1e1e07a22951467b1da1bceb89ea07f5f5cd15df0be7f201b4129" },
                { "es-MX", "8a11d0027a30f157c68551fe700443c30bc1206c28b4c493cd4fffc02f8c48dd4fff89545e071b240870671e5f220539488d8518c768925d9ecce579ed805b70" },
                { "et", "ebbff9e5f1d617fed2445f35b7ab691b8a4313c675039d94c9046da680895078c2c80ba596a8c829e7cf1160e6280886033846e7f85cb7183631bb361cf5f33f" },
                { "eu", "d4c02222435e108b00589b1dadbdfbd43af8d0381f06974144484a5b0fdd1e4504ffaf6aeacd11397611f6156cf5d82495caac4d7b94fa7202e56311c085b56e" },
                { "fa", "d130153d3d1ad62d33f5f51a2089878c7735aea7b8c210b205240c626e5ceaa4aab84bdb74562ad01a3384f898145ea420d2c2bbf22183806e03c16c66414988" },
                { "ff", "e13b01bf7e7447f791b0002b78a39006e43230e603f7ebe38723699f54e7b1d8d3f912f18bd7c0601a80078e6a7199833811385913e76c0e98dd915345611477" },
                { "fi", "931ec13d755fbb3c7503b203ed830536f4aa055e551a177a760070f869fac61186089e08a9bf5326934a5ba464e98c4cc8971f0d859ab1ee4106d5d1fed40208" },
                { "fr", "fda6d73d1595ab089a4a60619079e1b28306503c2616ba2647c8a99535bd006458757f01f1233b73e89f8fae00e2325045612f86550e4940437b5d93cefb8784" },
                { "fy-NL", "5df5188ec77efee6fe9eb6a44999b443123dce7003b4f3c9b03b4d061aec2a59bd105ad41393f41d03e8fac65f7bd2d753de648e825199bde3b72c38156cb0e3" },
                { "ga-IE", "f734de4d6e891831e864f0a56d378717c020c42affd492518f366e6af5eb308abf6a58d15c1496ba26cc76d3e0e74323afeaaf22b7f17b335ae8dcbc40e60e0f" },
                { "gd", "9195879dc6403f06928d95b35a4ee43c6e819780fe3b843439960c99739ea3a2272e271c0c94c948f81b7e9c5214846d7f72ef635fb24367c2ecf85ef8d4a60a" },
                { "gl", "249cf6694d4ec6f419ced566e432042f6b0effc649cd769c6c5ce331064c07857f30706fe12fcee8e5e3fe5242c1c59141186e2799dd2f7a09d2ee9606a95d50" },
                { "gn", "cdb30cae5cb3e5c55a958910c8e712ab027aa9e040d50c18fcda523ad60aea9fca063c5f84205163f263aafafbcd12a87b9ea8ae0c6ab92e651f34119d39672b" },
                { "gu-IN", "23754cd8e8e484e4f4dd7dad3065b4e8f825c2df4815d014d88e55169b0c7710454cad1958f95eea8357bf949aa4dde99cfbd5b2ed5e0ab09a5dc66d85d73de1" },
                { "he", "2b4c51ce7f6733777cb9ae7cfcf1f58c68b2ab8f922e3a1e7abb196a078ec5229aa096e99ce04b92b201702d440a23bcd538f67a2aea7d85310ff94099bb1e03" },
                { "hi-IN", "cadfd45e99518efdc8bbf4303281de4c31a6bea27acd152037d6ded358fa052c144aba7cf36098d5bf905545d233bd72fd8395f26425431877a89e76bcab3777" },
                { "hr", "2277367d0f7c45819727f9902a67c4ffbf63ba8fa1139372cfd84d6dd39882573933373972f16f639fe08cdd1b0488c3c510c7d66bbbc8923faf8bdb5c067bad" },
                { "hsb", "e6b8946ff24c9ca4768f4b3c4b1f9a54e99ef65c45f54fedfb248236fb19527dffbfb79ed341777c44cf0ed9a0c1bffa9f1af682be1acbbaf3dc32e871c7111d" },
                { "hu", "6d9aee0170b5f2cf99514ff92822f8fbd3d63e4e5747b71f08e2c1fee56c8e704859d3bb929ead93fb05c6fecb3962ce86e18cfe7522d9bffd7574263170082b" },
                { "hy-AM", "7a3ea05f153db17bd93f5991f52867b497a4c38ea2906687f797948db3293758b0fcd2beff0ff0302b11c7ceb2763d93ebeae9dffe34da64e824a947947a9985" },
                { "ia", "6860ab25e9005228dd1b82b1a73943ec7684cf8e91c973201ab6b6c57f4cd57f77cbff572d4f312238d4c0504ff8ea0641b94ce68245c0b47c140f7e95e9323b" },
                { "id", "50b4f71814de0c906bc7e1e1cc4aefd42933da619db6ab89f859df5d787c39e6be8b8c608fe6502d8156f3a6f026e9787dc84e39a791f21333562ccd1d53fda3" },
                { "is", "5304dbb4dcd330561b12592dbb8b2b4fa64249dee1fc348848ecb7748d9c9a1451703f688426903d90cdd564bf9bc4c69f62e70501355758719f9446cedd86b5" },
                { "it", "3d04006c793cdcc4ae4cb9678fd5cd5e86d8fe2343df8beca64a5c9a145bf27bb33a0507c1322033c38e300d157d20a379528232ced8ec9b8f016ec4d6961e64" },
                { "ja", "63a032c8cb3efe046de5e17e5eed350ee2b50deeef2edfa0acee22a08a251d0bba0745f401ecfa118b6a20014f6e952fde6eb9c779a2f6522afaa52789ee4987" },
                { "ka", "08877b0812686a6bb58fb29543a1c31580287900a03bc0dab9148c44596a18711f3b22d53c616e7970a90566bd7e2ce2b4b333d136d267de92d5b8c9006ba45a" },
                { "kab", "16e8d1ac863e83a7c27948aeb63e537dd898198aef639c64ef7a8b4d6bf59f79b11900a556d1b31a5a12e4d69aaa844e6ae4b8cc10b7af07eddd17923bdf8bbb" },
                { "kk", "a630eafd6ac20b4bb843759db874e9531f4310ebbd4e16e8547b22c95a96a44e051845c1cb52b1d3c4347e6740234a05d099fbbaa006bf83319f3a5586c5a46b" },
                { "km", "e3e68b60b9e69838dd6c0f451c191599b540c6ae428b557e576c489285fc393dce687cd0e04ce3008df0e82ef6e03ae305e4274bbb29c30be8aed7fcb84c4f7a" },
                { "kn", "3ff88ed4c272279628b692aad09b519016537d332417a501542a6a7fd2915bc05d85a081c6b506f9f50c2239d5f684bcac54e11f2a2724df9d752891530997c2" },
                { "ko", "a8e6e96031891ee9b92d8497f9355a58c3e845cc817af56d01465b8f2228766be0dd2c1d5b40dfd3f52ac9ecbbecac92feadfc1378232a2bd6c5967cd9fd23f3" },
                { "lij", "79fcf376c8608e2c4096f223727b55d35029d713b629a9a999ec14170400eb23a4faa96f672773469b072e890e3be12cf979f28389b20832ac450ff08cc8f25d" },
                { "lt", "c0d5828078a360e5a6558ada1bb67f1e27c5f37f40bd04af9662e86e28c79d1c9955b99f375af0f0f1b405a6a4515e730e71ebc2f41f449d8a87f0f0e9e1de27" },
                { "lv", "895570a4bde9059679a82e6f90832c2eed61c86a40c3704eb604664ac26c3ca349ab252fdcab8a847b766509ef4432936c0c0b7bdab02a561565231f74ebb30b" },
                { "mk", "30c8d8f6fe27c58710513d186aa0af3fed5e284669db4f82c59b8877fe2610516635ce0153e68af623510dcb34b8fe5d7a54d2dbdda15b3062b1b39e3c4b713e" },
                { "mr", "dc8aa473bd0565662020432fadbf05853c48d4f26782ce2e5d512337a6c0b2080ab616eb549637a30dceeb72d8f0b314cde00702bbe48b9f0a533eb007032413" },
                { "ms", "d70800cce1357b1567e1a7d6d8e8d96764a6ef14135b040a0c65fd5d1afc310df8f1ef187f318b83f0841a30755b859312bac34b63eed03625db45a46dbd0112" },
                { "my", "01e871917e5e51198101a9bbb6d374e6eef424bedd44dd3e77822e7160c9e1e47378f3b3f7421c85030e82aeedbc82265e2dbeed1e0436cbb0d4b57e8f899b58" },
                { "nb-NO", "a91ac74dbefd4a4521bb03eeb0cd51cf66726901db08856a5240d4a6faa1cc8a5aaae1a05a4141b5853bb517f5b6a343d07c3805541096e69373b1717e5490aa" },
                { "ne-NP", "f15c016569d5e947ed39ad2632866738ae0feeda46af2818ef07e9b24bf4fa666004e86d28e3a920d4ed4eb9d843abeb55818904cb8a6d257df1e204693154fc" },
                { "nl", "807bd3b052baf189b91b4e0906d97680b63a90365b27ecf8a50f7daaeecce0ea2832f7bc73bd2e5ffed58262a8592b9135282471f4b883d4d0391f99cee50445" },
                { "nn-NO", "78b9c24b6f68b8ae80dc47a7e44e60c6b73198418d141ae69acc8c46a0fbf730d10c0ddaa7284ac890b6764b659fadc4dc249b13f5ebbb34299f831d77257273" },
                { "oc", "4b162653cbcf2a8621cb43f4270f4c08e0ca47d0057fc7042c3d430d68196e7715d5637aea51d33365df892af5d3ab1600a9e42c1b4b58a598267471966d210d" },
                { "pa-IN", "856cf54a054d68fc7e35b12e2975d594ea7aa790ae5c3b76d02207113d49073fff70a71206df8c785c7b6ea194058ab6913fe4b6fa463839fdc71e72efe2223d" },
                { "pl", "dbfcbe4c7be0cb0f0ab38303f698f9677d0f6b9c4e7b3ce67694099b6720291f8414f2c59abc456cf96a8dafb1f3e215467c26f842cb49514f2655a65d8556ef" },
                { "pt-BR", "1507a7c8b3020586448ae4bcfb614271834ef4e064b14762308faad7224a50017f9c38e2a784a24284f4ae724a241afe2db23b0e2cc38481d1f680a633483dc6" },
                { "pt-PT", "bdeeb61e7c3c9517574a0455e80ccae4b201c038b4d8601a24096a0f4b3ce112476996134eb43e08859ee917c31ed408d1a526240e1cae35925c1bf7b677c55e" },
                { "rm", "b67dc54971539f658cc157ce22b624ab58ea36c0a3e62573d1179f37ca9e7524b9e6a2fccddf5625935f51c7fa3f98790c0e90ab70084c8ff9d2f94be96a3cdd" },
                { "ro", "acead1586b5c9b9590580007fd2acbeaa15860a17d472b5c11468a4745bf39a2c5c019a39156ee9a07fd958af316098fb415fe794ff716c3d2e67610f8eea82d" },
                { "ru", "0234347f1e602ef962705d054931d542bc6a281bd1476e585c48779b71da82126c5b2462e3156b3244c6680146871a2d316de6a19dcf350761235f7ffaa12eba" },
                { "sco", "9c7557366e1de78671ef667bd3c5e3b2d706f36f114a4eec9ef5d90478b2f02e5226f1a84c9763e9f27bf719b2412b936d8c737cdd5c8323d865fe829e9c5390" },
                { "si", "7994931cbcdff385b3a58e944e9cad172af297554b01010a196567f3219ff3dbd385d1f9de5e279e86715be1f8218f274a8a3a329eb87b34c48f476360ab9e83" },
                { "sk", "0fbb3346251c00a40de96d9b97ab4c696f6ddd96d93ac47a123f99705b4b56af1e0b91fdfeea9039ccd14dfcb2349b04311d1ab41ea52d1bf4b77405897f67c9" },
                { "sl", "c2433999a04e4dcae3ebec9f3f33306a3454299ffc67c6982f732c5a9b04188f97986de353024211f8f3622bd6dd14dc505136d4014c9525c0c14ba91f4359cf" },
                { "son", "269566c6bf5ce4eb466f482f2a6c137652948a440982588d65e7743241334265c49ccabe7073d9a600ed5a3f070280ad8086d139f87a5172e94b6093312abd5a" },
                { "sq", "895fdc59e1f015c25eb66b1c4838dd0510cbf5654c567f78a2efde6dc53e6f3a21b9928e0e65162f2861884f4e179c4c2649c097f469e4b90acba5e813609702" },
                { "sr", "946dc04c76c26f8e7466bb3847e84013b05cafc08db41d0c2784077774ba90cebc408cd2afb29b578523f1751dc23b454764427297e8cc3fb63d322c507fa667" },
                { "sv-SE", "466992af9134e93bf0bf84458e26f40b0ff622b030c69d25d594b4cdfaa9a6a5abdf399b91ca43443a30dda383c1ab83eab0c323ff148b2180e94bc5e1f2e909" },
                { "szl", "505335ef5b0bb46fd34ee3b7c0ff7d9622cb586c2bde7f471c3b2ac3f0362909297800ff02e4f03bc7e17b82c682e88934802c261ff36df6b5354a98782c6898" },
                { "ta", "d8c7b87eb7227dc7a23579451cfacdc166e5c364c26b2add6b6c9eb0ae7f0e34099bf1d4b4ab24973672fc0cf15e487af6accd8105940f618c31c9ac565ebb3f" },
                { "te", "295f9d4345c0bcfc3e61b41f6c10bfa9c7d441ee3df9923dd0f4f6d8f3aec2a001fabef5541d6b1638efe6f82fc8a04e5fc0a04ddd672fc33c60bc31af94db1e" },
                { "th", "87e31803e078734d570c398da34455d332f6802774df33d0974969c65a8ca09f5e44d4d4ffb350f146269ed87f2aa8f02a1104d6deb56bc95385525f99845801" },
                { "tl", "1a69f374540bc3c7f150461396a8e3460ee3152e469ce40d37119ed7cc067a443b50bc14b0d6abbaaa7b58f1bc6cc07b2f99d1709cb1aa947eacdec74ad879d4" },
                { "tr", "3468757cdc438d59ec8cb96639c95b29f22bbd272759251cc4791fb36e1615bf99bb90d644daf5c16399e5d41bcf0c51b52a87dae3a40f519cdee3bc4f444780" },
                { "trs", "bb63c1fb0aa6a57e44d579b34fbba140812fafd7bf7be4607be40ef5411291e1b6df06ea61aee2d83ec99325322905d373d5529dd11f054522bd7cd8a425726f" },
                { "uk", "5ab5e516b736b033d4d60bc3208e9c332275c4ff2a4563854b533b5e362d2362c2a4500b095aaca06565ebe8a96e28f69bce867cd65813aa111aac156c770325" },
                { "ur", "722ae8cd01d231d34491f61a03ba5035437734fc6c4cee6800150545b7b9c4aea51c6007b13ea6c04f8ad52c9236e1b03446390db674ad4cf22ae75b14daaa3e" },
                { "uz", "63f610c86f226a5a56c07bd9e8a9739c71631e9bbe98568d933a86da3fb48fd46d51b9ed8dbf1ac48ba4be7d5287695f7250340bfd9af7a581072d4032126136" },
                { "vi", "d6177efe8599db4374428a704181b12f9b9de546a51479506593658a99fa66ad6e53607bbc92292a9e6f7c09d24f46f8be8582095a06526b01173e280857eb8a" },
                { "xh", "64a6f64ecad8976ee8fd79a37b1f4ef7ae11474da97d220fa693f12a9518a99db1159fd413911e470390acbc5cfc6c6934e18ec55197adae06e2dde55b542a2a" },
                { "zh-CN", "4b93e96ae972095d2bfcf91e60307711ff7f0c2eab84959f50bf3176bf9cb560a793defea7c06d339fc63acdba84da60a392a55911c02fb0065a62e80020b324" },
                { "zh-TW", "ea9737feebed5e8a4c95d68d43a9d689c14336dc1996508e247822d10f708cc877755eec0975cd760d0261a13a4320b693ee18c5b7cba89a81b3f6964ca95b85" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/99.0b7/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "f93fc50062d4f7ce20413753f284db13d2af17d300eb67d72575ac4a8f0478a7913503f767862ce019cdc6b749bc4cb7ea00b9edbc8174d08a9946b43bc0ccc7" },
                { "af", "c8f66ba104aa55c12544e00de8c70f915623b41bd58ad901e1a98f46deb84de1428e7513b6fd0c7126eab58247ac02da40965f7b10504ab01c6e796fdead7877" },
                { "an", "6e3b3578bcefde00d526f8c85de5a6fc5e4407c333acc0448015037400e40d3f2dd8a0edf036535e52c7f83fc5aaea09923f93303227028f8273edfc5ce3a9f7" },
                { "ar", "e7358160076bb925c4af6565d86ac2d6e3d5f99784118435a2039c0013fb4c9269b36afe75d593dbfe810559e27bb6ab015b10b319ddb5e266cd18922883ac76" },
                { "ast", "03faf848915c7a6d538a43ccc1491242aabcbfaeec7ea44739b29ff9a142155975d7c0059a4c8eff94e29946b85316188447125da8067385941a96f7d2294257" },
                { "az", "14d2bbc49183e4cc85eeda26f9cb7aafb50dee70a4636d52f8352de43db7f426f265e83323bbb716c0c1802f279eb5b2c393dd9725ff5456637e8e8b4513e3c7" },
                { "be", "114382fa923a347eed5ecec8ce070c20e7323ec4df4a5a2cc69e760683cf18d4b89c6bb2c8f8cdc8cb52e7ff65c4bab26323a9b6c7b514d71659dc96ca37e97d" },
                { "bg", "7a0f9fafebeb543231875adac76dd6f64a70c8bde0be304aa8673b1c4a00914a08620cb54abd31e777294f1e83ca180e1da349c7f9da7946d3c2f0b2c1140a95" },
                { "bn", "c2555c29830556766cc612c0dba2e93cf277dc4bb7577e39a02b928fbb5e489c71baf320d36a9905938ff53b83fa76141c174ba0d878f2c6f91f3331a264d56a" },
                { "br", "e2306d4e5842c1f4ccb84ac3337984419eda3ac62e2f4a62ee06cf3f26495e4baa06b2847ec53fa5caa87f5d7d0001d7721ca4f4d4306e9ed6f2276c558d0c9f" },
                { "bs", "c3232a0ea1fdd3747b3b346512a82421d7249ae8212a6c5701bb104445cbe048e1cdc3ebba63044a4580b08203d6add7f334b9e34a8d238d739bc0a67299fc07" },
                { "ca", "109da4955c80b244828ac72077187225f8aaa52af9131aeb8ffbd89da95a633e513b15fd1145df7ec52a21b4486b30366d5fe4513edd131275e38f67bde178f3" },
                { "cak", "d04d887e5e2ee325d939e6a660c027916ed5eac8400bb499f1c03a2e661c71f39fcfa4c6ea31791dd3d3a90247e4b20c0a17b13b19e8354f1fbda074432d6508" },
                { "cs", "2de16205249c7c86208b32f712526214a1fe9a482f59ea7c49c727475fe6b17321f817466d29a0ad096f04d56b164dd604137c4b876161edc08301aacaf7d908" },
                { "cy", "beda0637f8339371e778363ab744d6a3d3736b436a1686e9c632d01af3609a0281ea2eaec9775fb8a8e7b65e3e566cea6d9b7da0bf68910515750b0b8369565b" },
                { "da", "194ed77d11e437de5ef9e59b4104911eebec426caaf44b744fb2ffc8eab2f571fab6de4cfb819b5ab07d74349aff011fbf178a91c7af756f032ee0ef473cb707" },
                { "de", "7fd2e1c1d2378b9b47ca7eec017ece90e519b9ab721d3987a8108339c49ec599717c02b7963dbf950ae143b3ba34346c6b9bbc90214fd813ec403c8ed2365278" },
                { "dsb", "8c376834cd1e525dada39152328c2b751801835609db263948582426410108bc52c6cf72645d40fdfcb387b499b1b27e56a8bd68eecc72f70c48dce79dae7b93" },
                { "el", "c08c15da8765d31e99c0b2e6ec2ef2f50bd990be1edc3e2ef5ff62f59eef0db2edc66724efbea5576fe5c0219deecdb531ff93f1e8bbf5585ef17376f2638496" },
                { "en-CA", "060c18bf278bfbcda905d9db5684b20f72ab1c5c5c8cef6063a8e9b3928df26e763663ea5791af81a3dda304b06d7b05eb16e5aa601a720173223c1d9fd51332" },
                { "en-GB", "55ef2a301d37e5ba3d32de6ec87f6bbfbce40b08625bc055e529210aac8db25b6d7be61dd93e7aa921a605f42825661a6ad4e120475cbc6bbeca431bb033980f" },
                { "en-US", "cf95b3aab4d8284ecea09f2fad6f2e0c9a8974020f9976cae37ed0b73632d97e491c6e0cb3d9588d484c9bb302bff0347585badf5d4ed9b4106136e1833b9e3b" },
                { "eo", "944c8fd362e6dc7d2e9417fd5720a77145a643017a153303cbe06cfd590006dc4c8a1c03ddd0ffe78420bdb1ff83510745b7f93b26f427d1a68b3d63caa23c76" },
                { "es-AR", "21e57d0e76cbc58b6271c7facea8423a3f5c8e62b4398572a7105a10d3ba436e14bb673b6b220cd83ad4dc798b62c3bc89560455bfabf8a187fd6fd49311352b" },
                { "es-CL", "1aec6c6a187dc790f23ddf8ded14d3c7de48c7e6c2da76556b7773e0180a8939b8c9afef32d6874f8395ce1530b2acf33ab2806c525b98deda8ab76bbd3523b5" },
                { "es-ES", "5b2c627e06d8799609bbee97f605cb63bbce19d47d4da26e643ac4c5a0db0d9c1df2feba8ea00b4d559b05fd6223f88cceb97e62bd8053655d89fa4939328591" },
                { "es-MX", "26bb025b4d0edcbb06b150398c7f85d1d0469e239d96debad0012cb205af860032fb97dbb71a7ce94b6437420d4c97476fe16a94cc2359c743879db347b65135" },
                { "et", "f151506c1ceb94f91091ba67a1749aa84131e083f8f711f5716cf30c7a991841d8988fdbb3ffe078c4ec1b8e99b9b64e63d602131a6cb3b1c7c5934d892fef34" },
                { "eu", "c8ec7887932cc0ce99884fe66fa7baa5bccbe8b515b639f64d9630c414ab903945413bee7c990dab085cdf5bdd73e953fbee2b041f38ce9107956fe5a046555a" },
                { "fa", "6927b43f91246791e088cd9d10641b6cb5527406785197d56e8158999e01ad4ff459d58fec2c380411253af2e5d8336239bd27b50051681f20fbe33f8864166d" },
                { "ff", "385a3dc5ad9b453b379d58b7d37930c1626d8c58dfcb11cf44fdf10c6d6111efa86da7aaac6f8c243551115ee785d484228785c7e5d7f214af25934cf3dab882" },
                { "fi", "b9c55734e2ebc84a80ef98df002b1d285ccacd16b43e45c94bd9c4592b6ecead9df329c3bdae51fdabf481f28c877f8b01b33a1afff6b0684bdcd68b9356fbce" },
                { "fr", "5ef413274460f44a1efc6d7ad12a9fefe88437ccaf546fc5cb777229b71503de669c5d742147ffd550c6cc2334e8fc10a9a0561a75761f7965438e1815dedbe2" },
                { "fy-NL", "4214136d4b0aac08cca41e2a92e089696345dc29ba08058a03c35262a1eaa89201c5661d246867bf898e21f7e5d058a939c4bb1fcaaf5df5906e28e500c5d880" },
                { "ga-IE", "05e9afd35d1e9325e0d3e2a1f60e00833b39b0b5fa5a1a045a3916c31838034024882b69974a6398a4245df489f54888fc8344c9363ee34a620d8b06f7b83e0e" },
                { "gd", "f1f915a0b1b91df7e93b94697ee74df306d08e896197d0dd097861931f54ce46c5535ab57edd40d60de3fca8fe96f844a1890bab3f755a235b0cdd05112d2964" },
                { "gl", "b3eb2cf7a15dc60b92321974d0c4186917be97a474d4f2ce6debdcaceb0bd124d876d4a642483c7dd81118956500640a47e3a0c76fa6ece6569113f9769fda59" },
                { "gn", "fc0e8d0bd4c5a92477e9646ea3a4a24d82d6420ea5aaf94dd384f6db44b3c977c8d59195ebc98755b1842e3b36e77df7a6334c917102ace6da7acb8c828af72b" },
                { "gu-IN", "4c324f0f7dbd336696a7f7026e0abf8c10c06e8f2f3fb89997f0c58e10503330012013d6e3e11cd4c9792536d836028474bf8e742a070ae099d676dec218b1fd" },
                { "he", "ab332ac633be5d0e32bef83cc55c950a7bb37832d8523dd7638a90760b20f7ccc5ed815430e61d76db1b13d030c8dd21f18d90f311cfae60d70e33aae50c6627" },
                { "hi-IN", "a498c157438798ac34c2ace90f4ea2a0d0d53c64959df6104997214a5b1b18d74bbc6671634a4cd45b50a9e40c50838eefa1210ead7a079892c3fed7c476e505" },
                { "hr", "d80e2852d57178e002e78104a90539f7805ffccfe227fc45cb115dc9829520630ba2b3bb37b0006863093666d697c8f64fb8af13be04fc57b7914af1de49a927" },
                { "hsb", "e4f9eed319bf62b816199bf4a32cd23b6f66b25635fa308b494c7039c606ae79fb8e8bc34173794be6c07c74ec311f53ff32675ba2f3ef19600255d1ea47ae65" },
                { "hu", "5999c72de2f8d379d52695cc427c370aec231f59eda4cfff81386a35e6d526eb148cf8fe035234f63d2d71416922e6480a5a3cae9135a8ca84a3c4b12ebd4c60" },
                { "hy-AM", "4e77cfdac19c13a9f5ff61ded0dddffbbcce52981cbf4a0e084871b6d7768c126ade8e351bf0548c7f1ea93f068016c0b045ace89dda71e3988d8d5489236bec" },
                { "ia", "3f6a7c444e63642dc0cbc48b518d0c3c729cec1ad438ad1ce63f84cff4b79819a43c0f1f3d9b13f215b706b2ba4690b2201f39776c193719943744962b3eaec6" },
                { "id", "7c74b9f4971b6b7dd04dc3dbd9433863c3e9c10a8917eb5e95bcf95d3835fdd3b51d895a7db49de177cef4cd0976e88da5895a1607dc29c2a7e101027ca9445c" },
                { "is", "f06a276ca6f221a9db52a63d5cc903fbe5c117275537a60e038a82b3c8ed7fd53d56168f5664458aeb6e5aecee2c0e425fb1100c1be91de12386fd1ba62f8626" },
                { "it", "89fad0d574d6f0904fa2e8936fbf92fcad1808a8179cb6e593fb78d2c1f49a89e9ebd7dcf83598f65a67c7b39620d85b1848ffbc8f9e07ebfe3f64af290344fd" },
                { "ja", "a04c5d25f8ebcd1fb033055aeb4984af26edbccb830d5d619872a4bbf29110f8b8ae9b7fe60448048f5d9a1e07cf350d8667b2ac5b5b011e19c50eaaa957ebca" },
                { "ka", "5c0ab0c37c166a24dc29f0d02e236bca2352b48d73dff1c1a8328d6531a9e4538943a2334492061e4f0d2d8297273598c2875da3b04a4ffac429f6b4560d52d8" },
                { "kab", "91ca44cfa16cbbbf068afb8e1e42a0cd5f4f8112a004acb044e6f37ee8b47b594c55bf01b869d8e149ea77d711361db47bec386e1fd6c43a5a88e028c0684ff4" },
                { "kk", "3fe979746303ad8f9c9ebbb1a8a71579e06912fb99314c118cc735dbb6fa893c0b4c009738b1867d2a2489dbd78f6f2453c82e9e4b632c7e4d30fb9b174ea0f2" },
                { "km", "6bc665f87c1406c3e9562d20c4af81df2af1277111c44749fc251985a5f57403f7cb10ffa3a96528a314fd75613459ef07f0d7d8165df980649d213b38d7cb27" },
                { "kn", "3a0f83cfa112c497d3337e6ccf001b53681aa176d956d0fad0ac61b86a2a3519b7fa6d6b8a78d3299e14b912ace941c61a208900288b280023a36d5556284c8c" },
                { "ko", "c44afb6bf1cf28be85812190c2a9967ccbc33dbaa395682bc516a538fb5c0da9a87ad08fc9558b3d7b024a67b414f501e970aed592abf905294be9f5a5c59fa6" },
                { "lij", "6e255964698964128935228dbfc34eeb6e19a567b66b76f5b44d1efeea761641fad0a344b3502e050f58cf5bafb4d4b8c255cf581287bcec9c6c5060479efb85" },
                { "lt", "42cba7401f33a31c5b85046e9657cf0824b313116daed4041918421757ded00c2ac51da0f850c4f96d432402f00141fff57b2ce42a3f49078dca0ee94170480b" },
                { "lv", "d81e34f5a6af4def886da129d45a8daf2c64155f708080e8c577bcb5897261b5ab53b68363b088403c4fb3b7f038f4f5496652011d3833e7a85182bed0be80ae" },
                { "mk", "7c8a727cf828a1663cafee812a0d049bae3061100bf2fed53a1f2283adaff24ab497dc499067dfe728944f885b5a7111b2ca5a6041b04fb6d510f6ed8fb3ca71" },
                { "mr", "f0e966cb0648a529467fde2a1148d0573d3b7670c35acec99f79f842872061675490d6fa499ce98a176cb31ee050a15c5df6a8af250363e01570163b2fc6f820" },
                { "ms", "37267fac25e660e5af425c124cc91850c96aeb9ffb06965e81a8826a72c9c548c03b325681bf6b566fc89803f16d64ef35a7013eb80725735fe46e16aeec15a2" },
                { "my", "4aaf5aa280bbeb6126bf84f2965ebf0ceb2663f81886cb406553076ee14e676007481604ff7cddd3be9375222e1729fe139924f2a81f18d9d332d7cd565207a9" },
                { "nb-NO", "a4868aca07e3c0f96acbf0f7c50e12d51a9bcce2b7ad2829d9a248d4050cb550fac39d8364df44cf06da1144b3fa0214c59b055089b4ee90892c30947a06a93e" },
                { "ne-NP", "872fbb270d87ffc487d95902dd1c948ba08000f2358100c85473f6e087e15d0f8f0bff69a2c3f288ffa06e472feaef26043790fb80f09eb92f5b6d514aa2ca56" },
                { "nl", "4ce68b254d7857656c54d52ebbed744ea72fa025f8a4d521c38e61b1b3ee777ad0fac1e92cf6fea672818b541ac956a47a3c2bc7bf23247d321c27c8239cf484" },
                { "nn-NO", "eb457aab746b7f109898db0740cd9ba1b725edbbb1cd25d3130b4dcd1b85eee2c9537e40a647cd2a83c55a715e7fd99bf99fe919c9db231a498d3d6cc72aab26" },
                { "oc", "79f0198e4b48604e6676c2d689e4f0b17302ceef693429f41dc0275ce9477cc6321a36135034054880b48068c86b8fb2c69f804eb627e1ce895f9a912929072f" },
                { "pa-IN", "711a7559ca556815319539d943b76cf98fc0f797b090efef348dbd13262b31467040b4c8c27a70b3a66baa2e17a20d3b670081a4068f11d9356ecd1a95bfc7b6" },
                { "pl", "1d4f175baebb5b10bdeb5ecf5562d188e79d94bdf3a2b7d539e54cd5045bca3bc1c1c35129898d21d83afde3d1c3647c8e26465902fd3ac55a002eea4e366069" },
                { "pt-BR", "4405804f371dc58487cb63b12215ff3e0df63d7984fe737e6111c781144e103bad4edddcf5cd2b166a6cb74dd022ca20400cfb287f20d65b138fcdb340193fb5" },
                { "pt-PT", "fa16b4ce16560821b828c6c43db69931683a18b78f909a5f99bcc3244df4cb7e6c2ac975f61201d56d545e9c8c9303325623343482b50aec262ed8db2e08eaaf" },
                { "rm", "4005816ef316f7e430b4e206d13ad964ed4ec51689c7d5962f806a3f3954343b0dd1cbd1b3832cbd2b747ab5abd4b30e055b57351fa3774744389b04884c7259" },
                { "ro", "af97d14f3f9d344bba6ac1710bef17ea54f32b5a4ab5102a43ac710b5bace3d93061e32afa12e0e473d3313192ae9c7848972fc7c8f4eb867b8d064541d01f49" },
                { "ru", "52efc0f96640659837a817234f39375413c5467b57a9f74a013ae36d871778389822ed6d612d18f5c7be700a3bcf08755e902a252e7b3f195c5e298b7fc52ff1" },
                { "sco", "d211c0b5f4ed5837458b6e48979d0126ea3147ec7024984bc2c2ecc622eaf4b0a7b4c08c29b6673cd60e1af19c8d84a4ba6414dfa5cae189571f37e2536b1ee6" },
                { "si", "b9d0762ddcbc727c593f418017cb396b621b818c73443ba4f583498d163bbfefdb5526184da010ba36dad658a4eb43bffc6b08ca2f2d5edb5f4e73c604c2eb79" },
                { "sk", "7eb8e46be63c87d6c519fd338325f64e90ceb83f90c76c4c74d7df16f2d06f5bb0710306d3b40b62a3c1b61571b9fafed9ef479717c3c3b7494c7b09036b4295" },
                { "sl", "04c005a4b6264edb0218e614e199015221bc9d6f451b75dcb00bf91acfebd32a722e5fd3598e475f46fd693f4fbabff06f5748c3334800dd44bf75cce9bce965" },
                { "son", "77e4c76e46bdaf4810c9e563a0dde0c5e0349f8100cfe47e531abc5b057840c37552c67dd72ef4b2ff1d52894ac94b9550f534e42d959ebbfabfbba16919b783" },
                { "sq", "c4ad85e5f457e08c143b4b7433d0ffe84fc901742203645691c84ae11fe9ea4fdf84e82cf8f93e01af093d454c7f36b66ca28b6a1bc0b42bdb6ba5c1aee9afc5" },
                { "sr", "9514dec710cae3b7fed18633108aed7fe81be197baf0d338544131c2a815e75d72e04269a3dc4ca3009782a3b44f795ecd05a4a6cd7ecdcbdfb1788338a3b829" },
                { "sv-SE", "738292dfb12eaf8c9c0eb4b1f04af6d2fd1258594df8cd9d2a0d39c4f583c7425ea7089a3ed4cb48a18f25eba025e64380e7ae0bc2040218f6eae104ae530554" },
                { "szl", "ce02623168e928a4b7c612b161fb2dfa86c30abe779789e1d379398b0aebd0b2dc57f1b7ecab9d9943947b5f6f6e7a8032549bdd63327f0cb93da48d8131cd4a" },
                { "ta", "791a543848c4a3eaa6a63776d43c37e3a5f862af10b7797bffe0d4f109eed7298a3187df76fd898b00936acabe1572e11701b9194556da8bd5b6f3d66dfe0860" },
                { "te", "402b3f9164b32fbfb735b8d2c149302d64a85747d5d66ede2a9400b7219dfe0f3e141731f55d0a4779414be28246794bf424f0f4e6fe6215e786c7da27b7cbfe" },
                { "th", "a612efa9f652eb3b1138490c6049f3e6f9dbfca4bbe3d8d84ce6cf39d98a0ce4b7b29c1452bc278aa22dd61fe7e34f229febb9b112ff899acb4e0558dc1a0c8a" },
                { "tl", "f883900f8adbfea49ca73eb46389fd5451e2a52b067ee53bae6563778a143fc0e544a43e731be1b39de809b2607d0a2d22d5c0870d256db72336589ef71c2a81" },
                { "tr", "716d7032267e39afe9200694276e0732084d5dc677996c46171bd9b632dbf253be8d6de8c387c9c1184bafbecff1b7a5a47d2ebce78e5d08954c856b90fec2f2" },
                { "trs", "7d9cd3f13eb68d29b4b51dccd1ce451175e9c58ca72eb3ec6727b53435bd594685b571926df3a251cb70dbfe0cce3968a16852d71035fa99f82fe7998fe856e9" },
                { "uk", "e754af467b2981ebd5a8b3e45f7256a90d59c91b1b430e1a4a7001d6f07e6522cea1ab990d0f83d7d14b348c87d3bd41aa9e6188f610885713f69afdc94feca0" },
                { "ur", "4bf388f07f1be8989457e97d6fbcc579878790b9336faca44ce81b913ff56ec8c6f8d3bdfc7ebcfb86a4a944d173ebd44170e1de29d2940893670cf76df4fc62" },
                { "uz", "59845640518386488c683c3b1542785b559e5cf5c82990d889499dbef868bb34c6b53d30706a0c9096780a0285432af1fac9abf729965c5ff284a28171cf532c" },
                { "vi", "e7b1579584c1801a81d4dd7b36ae59de1497430a1bf71b3f62d316a828c0b4a42fc0c6e47a4ac3f505b90cdf958f596d0d2db104e735c0cf5891162903683ebf" },
                { "xh", "46b91fb85e2a0039226e7e34d8e6e6e5d19df669471e01c8b548f3ba4fac68b1858af14f721a4af29ae73fcf1aa11715d66f0c7a7012b113adb9f16bb3da50ed" },
                { "zh-CN", "7eb5b1a781bb6f5e80692036d0998ed1a49793f31f5711ff2591a00102889b9a270f483f66672d149a788b0911ee7bda2a4577fa474fcd2d7532c435e780d39c" },
                { "zh-TW", "21a6df1f0edf15e4fc4e79944a53772483fb828ed957c926462c3cdfcf4939f1262de04d2b2c168526fb3826a8223432378afd1a2b56038b7f0bf18d3305246c" }
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
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
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
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
