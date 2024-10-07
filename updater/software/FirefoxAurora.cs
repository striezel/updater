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
        private const string currentVersion = "132.0b4";

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
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ce71bb2ca2c2b94c4314a5b244b83d68f86d7439d16b1662573585f41b5cf0ae61c4d6847d58d7070bab24957d98677f7867ac7372daec4ef0db3dbee223147b" },
                { "af", "e69d933b5b72ada2ab313efea6f80447fa517bbabd614595dd330c312c225ea17d6a04da3ccacb0ce5229172af2d793825f7327aa00e85e2ee6da78c9aaae415" },
                { "an", "df818ac5d86cf47dabe85515bc99b5c3f6683be6f17858ed3aaac1a94b77c3443384b1cf4ce8e843b6f141685241de7dec2a979cad146618e5d19fc4e559175b" },
                { "ar", "38bf12c6970924aa5c89b5a0f149503be730481a9d8e5cee9368d9af3d74d20266b21be1b5ec587882217c5662a08303c34b616b281d6b70305c1768f8012ce6" },
                { "ast", "4265d83db87b960677ab4ddce42e68dc2568dd94436fd5e7bb197a873d1aacc51f362d3cee9349e4d767c44b9ec29e0d6a7ba1ebe906558bebc0984653ad22b2" },
                { "az", "796a4c0c08cd4d29192f6e176c145bfb9d3767b3fac8ff718bd32b7e16a61416a129b222e137b1f9447ef8210b389e6359f0b173aa287552d40426928a2d6aa9" },
                { "be", "31e9fd14d66d53815e94166ea5868ff3a47bb6df974d6196068da3e0fcae395c1dfe6b6bf24707e1074d1ba4cacbd4c56dec60bfca28743753e665c3e5623765" },
                { "bg", "05032df7afffac7c707073bfc9648a89a3e1435d3e179a6dacecf93c8dfb7af876efc071779507928ac9ff414090004f145b57a7aa59bdbf50e5acadbac2b1bc" },
                { "bn", "d64fd6e4e6b6c63fd00195ef013b124487b374bc26ff1173106e5fab2136d559415481a74065f394bf545605c0f3399358fe8f0f743a3c16916f8f19d30e1af5" },
                { "br", "62b8b8b525c42549bc613a94934c1620000706d2abb51a36cdd4aebb5c179962d1e792e8406aeddb3ac7b8794837f114fe0d0d4c814a7ccc3269dda7dd413490" },
                { "bs", "4abf16f72ff0570b3e4d365be0163d8d91670e118734a3d583f12d6b7af03cc237e9b4720810171f80362aa27f647a2adbc23fc6a351e5ce8bce6af327c370f7" },
                { "ca", "49ccf3dbc877725b8c5504ef4850b77331f8cb315fd01b4e95b3ca8f3957dba60e11f935e64c5d6348966d72433b3cc4db1330d2838ac5bd50902ab45484e065" },
                { "cak", "995ac2888e390170d8c80a77d4db7c314650f94711b836b102bc9ad5c179d83e74759ea3fc58a0707ccca45c68326919210be6cca03a25cace4f7603d76c8a59" },
                { "cs", "524b888b1d092ae6e7e8f607423c10f35209b987be55b683234c4d14b4e85c7ef08e166dfe440e665effefbb82c9e82c5c909dc4337a9a191b0a4229d167e57e" },
                { "cy", "3e9bb78f98ae72fd8a0705c76796d4c03349e180287855f7ed567d4d2dde03e1d3bdfecfca7b73327920e676bf0ee7a98a048e134c00ff2148580a294d7a121e" },
                { "da", "d95cb8d1f78236ddae209385d42aa7f5d951377e155fae5cec04e5be67c964408c5e72475417fe9d193a37b343a89e3d050016aeaa4539e7623e4bec2159fc1b" },
                { "de", "f4f50a27a1ae02f4b3527bacd43628dfc81ee7cb425e71454d714ef90df8604317c5801c6c7d01d0242946a6354ee0e6e214350dee0ff6aa145a5c60b0dd084f" },
                { "dsb", "a7ba3dafad4d453d75a7c6d1566069300b85c222c1d04ef71f346f360ee55276329ace162f1ba72ad718fb2e846c07bb604761dc457a86b88867006009b35895" },
                { "el", "2f4b921ee6f822595e61e188512510a8df0f53aad7d3c9a82751d2a58c39211b2d8b4f393338788bd74afef1d2f0f57a454e8cb1d3e0f809bfc6c6f1a33d2533" },
                { "en-CA", "5be004a6dff3e11fc2fdaae02cf5fcb1e39237deb69c702259dcfa570ef77c01b351afe0b0da77cc7c986e90e9e40c6941340b29f6a4a5240185fcca5082d857" },
                { "en-GB", "eb30f2e5e12b412e9d57bd7c762332016b0340fd8197ff75c7a681b7e22b01ecc33b3c7ac44a438d390184dde79701801aaa226cb7fa5e7994e28bb676b9635e" },
                { "en-US", "d0b80aa4074be7d405d62bba3d3f5d12ecb52bebdec28fdc37c36a4d6ca5b6725fe6c97dd00efa3b46a5478c22532bcc499c1fbb9d1a47b6039372d7e717b94e" },
                { "eo", "264d8d32e01dcd74df4deb7fe72d6bed594c4335cf05ebb35956ae962a5bb5d281ebb1ffcd103edf87d0128b995e1d93d3783c6387e15ec102af026e3d96e902" },
                { "es-AR", "75723651426fa60ffe81a4214f053d916be24628601c318faf3a2bc9b5dcf7da4e743e89f397fdf3293e347d0bc306532b5b68e0c02fa2e321400f3656296848" },
                { "es-CL", "6ea284ed5296bd3ba639f75dd070b254c277c6267eebdc7b61a64178fd3e68f288efb638e1dee01c1ef2513a27d068e42fa38b484f2d9d8b793cf9b9ee73d852" },
                { "es-ES", "6c326e5a1bd6cfe97b0983b6c15cc2e4e1ffe42444237ed6920de8c9adcd3bf8ee38eb2e717e08201d383e38c9dc23a6442e8729cd8a0a35fdfba1db6ee6b1bc" },
                { "es-MX", "67d80268742bd415f327ab0d622114af02930a6a4508edd9501bb50c6f59e25d2a9c207ddb6c103580a4efe325e9b4c12fc1e9879d595e4ef58db3ff4df8cd41" },
                { "et", "bfa8304d361f803fbe101731f64b7e1a30cbf4240a9c196273fbdc406f00155980a3685ed70426a0c31b615595916e6f684ad8d38fe926aa7dd8f923bbdd24b9" },
                { "eu", "cb88d68f7cd942fb122b2a6e604b63aeaf9e0eb7027ea0a5484728f2189218a98e249015a7946e6295f5fe6bd9e7385e3218bb5c2eb4768f9c1e1fdfe45a7ddc" },
                { "fa", "9d6978979b7c5d8b233406cb7701101a65ba372b217085735fe1ae983902453561e335570e0fd70671b87afef3d52e78eea19d0dc6940c3c222910258f62875a" },
                { "ff", "80aa1c727e3927979e9d0b4286e2f8a61cde2b95f3e3a53acd45179504e56de068cc9e39488fe9c9280f745c5650b183e972e149792fad072b9a68ae62a362d3" },
                { "fi", "c828e1f06295b5df0bd08383c3fbc67547216e97bbf9d13fc3e728699125d1101674e305bb9206c5e38d672de364fba9236278e94d3d7cd28d6a55e8b4b03759" },
                { "fr", "b57a2018a77a1d75f5adb28580b3722cb3d924e5a21a98bda900fcc798bc3d7b27b23d1ea75694ce06813f1a5638553e5ce3fe460712c837fc1a5ed22f782f88" },
                { "fur", "5565f299610bfd91a88ce200aba803e7e312335ac4d85c138f8bef880ea37995049993f38783766f802e2b34f91ceaa09476f8389a729d2faddec3f7e9238215" },
                { "fy-NL", "d4675781430f0c852fd4241eed93c8e9555697e6e3af75f9ff75e46cf2b1cec1c3ffc7671dc641ad97cd3e797be3e8d8eeaf5c23dc9ab07c512d2042a2959be3" },
                { "ga-IE", "6e38ceaa91d40a21f1401e668a3beb438889561cd973e8889d9b5d3f190a14493b255070e59a31c2696051b1e3eba5a53a11f9d0cf99c14dbfcfe6e64995e7a7" },
                { "gd", "cdb661b820699e636495dcebba5e45a2d1e4624b102febaf3dd0af15502c04b9f896c724fcd5d54512641a337bdec37543d01e726616398dcabf453f33b482ad" },
                { "gl", "359cf794534bea5262c581a89d13f4daad3f1b3bc28b48cdf510525291060ebb17dbdffa86e8b8efb2745953af8f7d104aea58346e290dc9bb1b0e59b77d6523" },
                { "gn", "9754f5677d55425895515f6f2a5b37aaf185c8dff307b5a4e1bbbeadc04b0e0d6e8779c936cacce8b409014089b2955afc712c433559c98eeeb38aa355f48414" },
                { "gu-IN", "144916192c3b4846c891258802a5a4989820394ff285275722d84ba22016ac576938a20a1eb39093147a85a17dc35b67e8d7bfd8aa1b80ded06e4c75a7f7c30e" },
                { "he", "5c3e1690ffc3e94a86e6b33f6a21afc93384fc878b87d7bd94a2224004e412318d96dd7110a4bf51c84e6741d6482ff14c7e562974ff105347a74850c6911c0d" },
                { "hi-IN", "e3fb5fa670bfa6f2f2c52816288c781d08e0d52ac9fee034fda831b74b6294b03e0864c4b76ed24d73b427b115a96c46ebc08d04a654a4e0174c66442206418d" },
                { "hr", "b75cd05d4be36017329d883465c8d16183c7fac002169f6fc58c2472bdc103545ea964372722b59e733e006665cd7379c4ad3ca5186da0325dcf0f98b52409bb" },
                { "hsb", "d7449063c74ca70a03a417391ffb9e2cf86d5002f0e98f61ff4a2a156c638a347e7d10b9a0f6321d94ca0f4936fa7636b82700cbfd790cf0a96b4dc37ab4f95c" },
                { "hu", "f8fceb6a577475e321b745a07a89a490c4f2283cc7c0dc38fbe7ed41f1e7a4eeae784dab28b61c37ef6b81db8d601e60df46363aaae0ad456a8f4e663ebffae1" },
                { "hy-AM", "3095f81aee1df987abb3f703fa11bb5c04d580dcab80f45edcf01f78ebc7fba0b79d3aaefb0dc5158b7b15eced8255f24be045352f3cf27b1f1f553dfe273789" },
                { "ia", "1eb8b756da51d7153fc409f12704fa10debaa54b83346f50e0b83f118fba7abcb9415b98479baaa3f93aa9df757d1b927793c11309b076564df63cd0a163f694" },
                { "id", "cad72978de5b3a20d51232c09ae3f9853cc0a6a77ff227c2e8230b59e6029cad21cb7cf228ba5a097392d2fd68c5e75f33a28539ca8a96be18aa40bc217fe55a" },
                { "is", "6ed6cbec49caff3b35f635cc79039867546f9fe56be89cafd4abe0256816c9d178aa4485f2be3fac51bb2bbb70cb83f0b288a1d7cca2a88b0d99eac6e39ce519" },
                { "it", "03ade1aa98360a64e98cff4fd899474794aa1792658b67d146ca6819583ca78be1090564e030f5001a7eb019ee89d82552f3e48d810f80a7a3e516119dedc28d" },
                { "ja", "1148624a1a0a8e7f3e9bc2bf244282be62ab4eb52fdfbe162f96348bb7abc450c2ddad991db234aec58e064cc158461f6718974092bff057d54d15a5301561d3" },
                { "ka", "3c2edf6b07586115281823b97fbd2bec31d443ede49332851f461d1f597a1e3e75dcaa67fe861766632f80f330a487229ec0e9e8517b86286792d803552cbc27" },
                { "kab", "b3085461f572dc96283c644179ecb7a76a63edb75560aeff7f73aa35c7ccdf673b4c8c680b780c79526f139a61335e87a31ffc68c68ad2f553de5206734eec92" },
                { "kk", "e6ce09e543beb19bafd0646d0d3c1b23069c8b893cd46a1d5b1b48e6b8906d96a8361a0dde3734559af2f8976420fc223fcf55060fe477742e341a32995facb5" },
                { "km", "90c75152cf6b59eca176eb05baa616583746e36a5c47bf3108289364b034cdff03b14470e6d41295ab8fb8e41e02a40f7a43c0f71d80979964976ae234a59b9f" },
                { "kn", "1227f60ede0d44f2554a06ed58132b5edaa2e925dfed9518c6ea9c2eb3f2480cd21e96682ca6402f5460248c1aa955e3936539b383a591dfde1badee29c3f2c6" },
                { "ko", "eef65d4b2eecf4c420bdcc2e79624758e928fbe0257e244651d4f896ae5769e0e722903a66b7c3a3e0dd1cfb9719bc94be636e65e24efabf752b2a602a88dcb9" },
                { "lij", "8f5384216b33a7e9414ea6b4aa60cee48de733bce1b5814cdaeb28f9e2780e788d76c4ce5efc15838f49e783a79613a54387e973929cff2c8597562ea13a316d" },
                { "lt", "8f7e3ab6811b899a42b05aa6847021ac5f68e4e8847921d044ce8415e826c12fefa74e3c026bc2a24cbad640718ab2063493d8cfc565928a20cf70d969991d56" },
                { "lv", "7b78066a4323645f432c874a2057cb079321152d39648a5f5a30709af614176cde8690ba41a373c24626e57acdf2fefe5830d111bb7371ff822354e10fda8503" },
                { "mk", "ed53a6830c76f3a15656c5723c8a84f315cef5407673b4f48870f388a29f612d97bb62efc21f84a5b8cf0cff9b460084ad2d708d8d84b8c36f1ca197e5c4df76" },
                { "mr", "d8fd52dbee4df7eeda297d259fd8c0e2423ecaceba5e56359f1da7cf90344e6fc9437ba635429c9fddbb512e1aa636dc49f48136ece74d48dc7e71219801c08b" },
                { "ms", "ea96436036b4868b273fbbebf5dfcf92f54fed3c6b3bf5f6b172006cc6345db6524bd0aacb4e405fba3b9c8d8506aeb2681a99a66020166ff22af0e76261c4a6" },
                { "my", "2f59b3af9fceeec2ca219808896c2ded8b548062fd3af1d15499a0cc12323b1372e4c0549c588df07794f3a9b34371adc4a77221b685d8b0f48caeb9dd00ed16" },
                { "nb-NO", "94b3d09f856a4b4ca58768136a51ef452b5be545cf15d100528d36116f96a05e838543fa31b8f0744946e95ddaa0e4d06492a35c49f314922dcc7b4ff1de912b" },
                { "ne-NP", "da7c96f54ddac7d3679b9c453c9dd904d156b92e1a1637b6d8ee5e187a23f96b3f02dce9bb709572b5b2bca869b430d26dd1bd80e92bfa475ea1087dec3667aa" },
                { "nl", "e02d1fa84eb329103e6c0eaff7d855b6adbc0a571e4d20c145eedef76ce5ff92825366d3c5a18ddc9e28c0d24e0dd944995e9cc66b4948c78280e1dd16daa41a" },
                { "nn-NO", "035fa0eb4d9d63c7f49e80986793c0ca53b95362ddee14d72d07140e6aea02a89d7d4ecade7970adf9bc2ade525e8f51d41814fe65e0874954e9cd50a3a6db96" },
                { "oc", "78cd457602e98661a3b54768d7d0c591f2ce342f667118f89a6cee0f9ed5a18b1d528ad918d842e35955286618691687ffd4ad2ee24ba47b93e9bf912646ea2c" },
                { "pa-IN", "6a597a5be0654ae19400eddd8e9264caeb74c2c10140c982b5d91f7d91764c08a6f7a580ed92a3c8d8b742a6b43d877a9eb3537fbc2de2e165eab0754ffbbd05" },
                { "pl", "4703a5140ff37dced2299af740b76432b12903ab3b305a50ea3da79510992491c7a3c9ac3754c5aa67a95a35e18965a9aaf6949ca8525635ed4578f144f1deba" },
                { "pt-BR", "ba50fc754da30e62db2f0373735757822ef54976e8ab3472cab32cf791e2c9867151801e730fc66a79b68bcbf1453280773e792dd042c70a21cb9e56dcb67d5d" },
                { "pt-PT", "220f4cfc56cc86f6c35c495e12f0d45a2f66a603a538801b5bb41fbed3c145df7785a28a4c68f245121aaee986bdf11bb7b0e6008b92f93065a88046269133c3" },
                { "rm", "91abd0cee354e591cb9fa76616fff5635b0c92f0d4cbe4c7cf9ecddc00e9c9006ec9bf3bf841b25618f27302d0dc4ad086281e4512da334f6ee2caad8942ead3" },
                { "ro", "d0d5f3c044a5a855f33868582069c1a3feea5d5e4b5b12519111511cb694686f827ffe325ec42a078cde007fdeb0dbcb2e1ea7f37356231a376f15a5b61d5240" },
                { "ru", "24e89980fb6111776d6c8d43fb5d6c738379b42224d102bef33fada8f439984f04be58ea194a229228f85be633c8f3799c2771b1cde8f9710b33eb11fd0315ff" },
                { "sat", "d0a2672d6388a3f241367fc2a4fe70193f192995dae89fa5c8651a73c64a9933d75df1477bdb743fee63a8979c2c967caa88a0d017a6655c2f3de9ae73fa35f4" },
                { "sc", "f95a97eb1a00bfb324b25945ab7cbe557132f9d8824f4d34ec194d33b28ff870c3bbe7cdf42647e768a2802709cab7c48416bc38de7f9ad760c36ef66fdc3525" },
                { "sco", "97114a35d6b674bde0f063531263a80ed11dd40520552aadab3810256df794f2deda655f76007a8370743ee78fca960a0301133cf1418ed1865b3829bcae3718" },
                { "si", "2eb65157237e66e63ae153ec5ee9214d46cb638b27d0349e21ef0d007d225e54b0c51294e419f16cccaa1db53cae186e045ecca42d759f69e4be732ff76d6e9d" },
                { "sk", "721b3b1cf8d4ed9754adf580692787ba41e0b377d8b2de3f8f737f8717b6d2525070e72333dbe1cf140dc31450054180a2cb6f0a7fd544d122c4d5c4d0337eab" },
                { "skr", "085463dfbd93bbfe5496e96859c23f82ed477afdd0c889b18130ca039c1467f825d8b193771fea67c7e99a8e5b37396e46fd36023a2bc00c550435483599c5b4" },
                { "sl", "7a1d46897a928ee7e739b8442a64d3b36a14637618d1949b6ab840465c343172a0893cffcce2359e18cd1825eb6fc5b4bff1da7e3ffb40a25add22aa9b60ccc9" },
                { "son", "13446f1c1b61a7cb9a482819dd140789136e43ab4bc1984e01533b62d5b9490e74ba6a69a4299ee8ba9eaba266a4821a1923bdb8963ce572439748d415e7792b" },
                { "sq", "fb87b38ec679af2e3ae95265859c170b3a1aa4cf74a3da4ccfd5ae05c51715e313a75eab2412a1eb5c2d1ce0a255b0e695c4e45a084ff806a337724ccbe5a732" },
                { "sr", "7848a5cda89966a5b7b3b31cd04a1c825f5e865746dd9357c9af59b02f639edb7ff0e4db4aa872c650a30c038bc365c5d38f8422fda2a281f8b6e077355ef23c" },
                { "sv-SE", "353653072235e7fd002b1ec0f7fe3de95f66bd14b8fabcbd3feb6c5aa2fbbb7981fb7b09487a73c961d26cadb38845b46207eab47e595479622cf6270a05fc66" },
                { "szl", "ac77a06dbe9f5c5310cb6646d6f0ce29090174092bf75068df3082cd56ea45208b6fc1955132732588326feeab399eae6eb8f0957f6a172df01ceb6e6ed85ffb" },
                { "ta", "229a3de656a79e584c0ff33de5023b08319365cd26b51b3d9896fd7e60c472b5f7b2a6e7c2ab034fc3d0971533b608f29b0e5ab593193ce55f0d8685223b4e20" },
                { "te", "19fbd68f6a6aef09e00eca6af260704eb673d9a4133aafc6528428df11852790dbc6e6f1f46afbb6467847ca56996f4f8be4ab7c9a3dfd7536e16bf9c42c99cd" },
                { "tg", "791a5504382b6233c430d2b5b45438057b9631db4e56917dd017ccb0ebb13cf57c784fe09a64ea7c46170c562d7a0a955c0141cd6137499162f880ec16d61950" },
                { "th", "aec5fc4341f7a89408bc0e172c814c0a6f8e6e60751d98ed193adf4b0299dcb7cad5fd45d52276f74496a3efb67aadb0c15069adb9d868f20db06da135bc53fd" },
                { "tl", "9170c6fd5da595ebfefa1b296461659f7f598c66df275df17f50dd7308d312aed1144d24698f8b2015d44710bbae668581369af9bd29545883ef051cd90c332c" },
                { "tr", "98dfdedfc3267e488e7cd2d7f84dc19e5256c18122271ae10c7fc817db0a55a7156681b1710df26bb0618c5bdcc840029a099fe64f0a3ff002ef957e5cb1b59a" },
                { "trs", "fba4c5150555ec257b2654fcf18c9e496123f4847da3f0689fd437d4a9c640edb8f01c2540059c92d225164befd3071dca00dbfbd55c1aec6a7ee9031769b470" },
                { "uk", "b90aca81070ddbc4444805bb854e86e9efee5f00b9a60cc7c811efdbf954e7d2461f02c825f982ff558d945881c6498fddd5c5b5a58e69d885ae466f444c8bdf" },
                { "ur", "78bc357c83941a305c8f40fc9133e7a70e6963d5b7703709d3eb20deae67ef7493c5130e25b23adc503a36a21605a2064c05a5d43b5cd0c4e03134cc9f546e74" },
                { "uz", "21fd01cbfe382f805800192a246056480eeb61246e1bde8631a3d65c1f4d6e878071ca4dd37d6295e831e3608590dd6f5d02dac4ba08543a7b2263f564617c3c" },
                { "vi", "96836f37f58f42b4474a63f763c7bca495d641b09453f88b1d45b300670c6a9cda6690e0f5cb48a794c88859d112c8f6c537e36a5667a15e5115ce78997a8e1c" },
                { "xh", "d9c05e0f85ee3e4cd70079b7101508fb8bbe2d9c20b801155b23464c60ee5e28c2aa675fb25acf585c09464f3e4538e693fbd70923f68501b202435e6e8aaf42" },
                { "zh-CN", "98d3f788f200cc232eee2d2c50957f42f901f0dfedaf387c7662befc24cf3b46bba9b9eb8a6716f92108b1acb798d1b2daa0fb62d24fbd50acfa42062210cb7a" },
                { "zh-TW", "3a4d47c99b6069cdffbf9baef800e34a616582b298622a8b0efa04ad8e63d57e30703730e9194034458c93ae20f19afc9b4563fc4ae9a25fcce8401c6fdd42d9" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/132.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d43d41a6aa968ffc5d890f3786846a89b379439707feabc0b23b66f0f21e4710bba709c8a0f305f44670a66111f5f7229d917d36f326bdc59bef35a920ccbe96" },
                { "af", "abda5c9181e37ee24d0186ac6706f4c31e952c5430fdab49fbf400c3a2b542e222f0afb3958567dd6c54802a39aede98d40c6aa073d4c52fed0c2e08dcfff87d" },
                { "an", "55acd9eeab676ddb392e4f2055abe985c159676bd338986a4bb660a44f823b05625563a595cbc01f1761da449cc4f88ef2124bbf9e2d3eeaee790a92af082256" },
                { "ar", "b26c5081296392cb43e331847d9b1aac526534db799c8c379a8f49f74a79096fed99005c450da5d90ba519e156058a4330e2ebae61af7226c8ac06684cb60e06" },
                { "ast", "606a027cbf1e2674eac7d23ecabc61a4414e31817917d1c030af11909b3db1ec6a697231105e8ddb2b52c4039c64b63ff80ff6070cac42cb2fb48bf04922f2d3" },
                { "az", "c7c6d02874a041ad4a679a8d05a0dc49e1f93c966c7ff872f2b852c857c2cde302c83165db7beec51cc935718c4c2d7b4c747b2f0c374f202d6042c0ae1d6a3c" },
                { "be", "6ad2d76657afaef02638c5ee8451c99a3b7713ec70df250b7d7239eaef844a54c0c6fdcff38c98e7d904d1cda15ed4e7746cf2a7dc4d20b9f45b3fb03f8cc6f1" },
                { "bg", "962a877c68beea3388fb25ceca095ad6ef7a122dcd191656bb35a8bc19f52625f5e1a7ff612111e3c6656505ee1208fe4dab3d1d9da75302f46425f266d59c63" },
                { "bn", "1e7b89e581a57da2cde47d42e51c499fb3c6cc039f08dc5e0f3002b761042d463aff1653be89b315f9a4b7f7d24b85d6fb80e9f04c0dceb79a6a396cce364ae6" },
                { "br", "aa5520c8179267a69677db06b1ad15f173a828122949ce5befa575ca1515ee72efa7d6e2fd719344cc44e8d6e3dc261e7090680a9960d5a4a75f0500d50f441d" },
                { "bs", "782b70c9e008af0c3ddbd0995ff5cd0fed6622322fd47fe425192f8bf9b02f946797af6cb0e19c27ff4068d39709e971a96491dc6efc3e16aa6fc5b55e799e0f" },
                { "ca", "8c868cb26d59b68d22f776ef53f4ab53caff6c3d643b4e8811404697d73fb3581c811523b5b928681a8d48e7588f6f20dff92200758b79b129dd2d6e4cd5055a" },
                { "cak", "2e428573a337633e919218901b46573b57aa453be4ddaf027356683e3436251ee1680cbce0ff15b9c8a62e9d3d3a067b1ce9737e037f5f31b4cc28567bb7f72b" },
                { "cs", "901e5741f669332863e4e0a9821ae11717dadbee28d242b4c33097dba2eb30865b2097bdbc27aea24a566469e0c0b5102f7e41e4b723438d08edea4f27ce6bdb" },
                { "cy", "9025012b409607dc3c9b639aae460bef19f4aecb16be14f6a9b9c76ce678a3078fc850a767094806166bfe447f5b0253b7acd7673a33471dad68ba6133d53624" },
                { "da", "3978cd35398ddf6ec7152fc26d129a6bc89c9b5389f5c4ae7aa088e1b453f65c17297950f3dc2787434069876ce4cb52863cff7239ed6fb27768594399e20bfd" },
                { "de", "064c7dbfbf85bac428ebaf10cb39cfedece34ce6f066384a80d6d7431358a89b2ded5f92b8cd4a2d4793115b28ea30804bf6a96ebd9828e397f07b7323d1aaf3" },
                { "dsb", "009a59fe73baf13118c4981e7dc97a1edcd099bc8041b8c71f770c362b03f9d01eaeaf2b82160686d1d7a9c4c437dc1f0ec22ab3d83cd15a86038fafdec61708" },
                { "el", "744d5db4defa14ae0bc159bc07a97b2f35655b5d83313af27a77171a27a3088217dde573bbf462946ae3b7a6e6497a3086c7fd3defbcd8b18d7a904c9c75cd57" },
                { "en-CA", "fefad8bd76fbc50bdf2e5803c219f6044e1c81e3c43b76a182d3ec7986f3d2fa52032966390d9e0cb6b85a0fb73240eea53ee683a52ad1c294c46e34e8b94e7d" },
                { "en-GB", "91b15cb31efb9f17fb9d15c3d968c0d69437317ef5b401b4352f3378b2b055c19d1ba32d857ec7bc87aa3d0de267823f8079b9d68db6c3e0414b1d847cec1dc5" },
                { "en-US", "488a35ae88cd417ccba90a244e984cd31c511491a4cfc8348a559c38449ea8d699982c994c81741fc02f55506d8c95562cd1aaeb9f5e91634fed3432ea3991af" },
                { "eo", "cc938999a1cc9023abcec60003fb56228e35c12aadd817eaac7291f791fb264b2bbaca7cc2ddcbfa39d399f2528ab8417dcbeeb48050e81037508b7ba4ab5e4c" },
                { "es-AR", "3b65055157245ff122a5b86c383bfaf09e76f12963e017051133a2b233e1fb54e205bceb0fcbe6f745779511de5446f93bf83aae1070cba33f45d666a50b8b35" },
                { "es-CL", "8eac14f3e3f4fe15d9f2339906848d9a0ee4cce9429fdb38f66976112f0db72fc207c90b8259b583d4bfc642464c03ee17e2846f8f3cb7907f18613c84968948" },
                { "es-ES", "0a4030650c2a8381a045ff8e24c5a85ebedd98328c63e47eb498e1f86533741f9e298b78b8c5e6d004fccc71018bf07596914a0ef113f3eb28b037823c376779" },
                { "es-MX", "a109a94a5c997bb89ffccf5734915927e0046c0cb50326b80785170f71b42d6498138a9970e068ce51ef91a7f02445d26b832822b1d6b147d96572a94e67d9f6" },
                { "et", "7c186c195546089954837791e736938b04261e3c56b9fc9bb611bcd023ebbc929ce0a0730135587232bc7885dcf6386f4c88f0aaf1b0ad53b029928c89e98600" },
                { "eu", "bbdc4f5be4de52dce3c191c560f08538f8636f12c67ecb00d0fe3e66674b4d33deff71dca19db1219050b18c542a655c50655d82336024f1d27e2e79afb0fdf6" },
                { "fa", "caf7a3794703b02debd4566f39d9cbde423e26fa6557554b4bfc28c0be602b06673f22c92b1efdd35d8ce25f52accfe2a51ff4e30e954ab91b9b2a3a023423c3" },
                { "ff", "12c60fa90125ddbab3036cfdc02a824b9c624652d8c4b64ca6b2bbb1998423cfbf40123662c6daf0a745705497716d8efba1e26819276c6ba7d207c30291251f" },
                { "fi", "5a684a4352b6a22fea3d2d5591e1e544c122dcf7a11828b432fce83db12b698a4f82c2dcd3d3b87a47f52f033caf952f671db2a87d30fd9d501c864748205b59" },
                { "fr", "094c0848b32d0943eedc7f6fd0152e9c8eb9763cabe87a68c6c4d3335f07994d25e51c0f1a29f7f525f4b72f41e4f1c7d61f7488b080f91762fa4d9797895b86" },
                { "fur", "c2dc42cdd73208da9702d0d877db2b73a93f0ee689a356b4929464b192151d7251b553e1b90643632ff213d2fd91d193eb2aaffddcc950fdf23712f499dec630" },
                { "fy-NL", "96bf59d5e7768d6cec4501bbba47326a4d7f443d3a5e56139486603c6ac1bb6686ed12fafd12f7357040cf296b4f9a6801c5313fdda95db4913bb5571383e614" },
                { "ga-IE", "efaea39c4ce061ab7a59a2e002c6c0a3d1d48cf9e06cdc512111bcd854cbaa0bec7620d770b48ae2ae00037ed257c34b0a3dfb7043b6f02d981a44a9880a958f" },
                { "gd", "ce88aeff17a18bd023ca813597064dd81f8c38e58a9b59664af673186327646fe088fffc7e01748dcf5ea4ed5c8d162886f3822ebcde1a8e0a1f27ae709bdbd9" },
                { "gl", "5600a1f010bc3bee926e224b7b283809ae83b5b663b4acb42fab70249c34e8b6316740b3e447537fb1e16f39563ddeb771e7bcb05a3abbacf2e7cd5106583d54" },
                { "gn", "ba53ceaa230fd71b0d475e59143e33bf9ba30517c7839f22ccb4af5b40f5a68fb77528e289bd1b34f39495f942a64fe80982434a373fc4698f81bb3ee8c31e99" },
                { "gu-IN", "36de02a9078a0e7d2608d9a94ac604d3d249f020b6dc22135a457994db1eacf7ce56890ee4189f84d3e02ae0b59e17b1567460df37539cd3eeb63c9f4aa59a6b" },
                { "he", "953b1ec61e341c64fc531d6a2c7e733b36ec10383f3f7ed4a9e308125cab232eef0e9bfe4ee0abad4268da1d520f2b77658ac2096b03b3781f31b9d550b6a80e" },
                { "hi-IN", "5f388cc9a1abdf940d38a2da3f6543dba582cfbac52b8ef3804f80a1dc7f0d46133599019516f3b96483cb93b5fa79d2f12d0dd8fd3bda5a0ef5fc636d1133e0" },
                { "hr", "f1acef35ac8662387b82ddc028c4ae906bdd50718ee7f43e332f560dc951f803f6f0dc15bdb42bd88c1c8044a791e2d426afdfa1712fe9abe0b1fe12f3aa32c2" },
                { "hsb", "faacce36800c963dc8725fe201118528f598588cc4bdc284f6dac9884796d481ce105d26c28ee60e04212c041f1a45d18ab3f4800df970452d477208eb5434a3" },
                { "hu", "23931aeb6b3cf46a4aab588f153a27452f2a37c59217c688ee567011d7e56be0f555249fe3be181d36daa1153fc51cf075b904f571e1fe8329cc864a889d0929" },
                { "hy-AM", "6ec82307c642345dd530ffb5be26132c21667f1d2422fee5f0852f5032f9ad7dbb6a2230dcfb6b75061d2e43ff98a50d3378a54860d2ef3437f425f14d74e2e5" },
                { "ia", "9bdd3c81202d9b99fa8c72a203df1a24b128d500ffc7b0a8fae136e602ce66c00a8a88932dacc88e7619d0fc668ff8fcaa05a59574bb8a736f0012b136ebe2df" },
                { "id", "c42773edd1ec7479352df21a05b74f18298df2008a9430811d2d04b60875807ce42fe20237b69b228e01ba58e2dff19d87d47151e2295242b43cd33801ba43cc" },
                { "is", "661338179fcc90f2b1eabe9a9cd7d4403b277d706b37bc8dfaf8d10aa4463ceb6c8d8c0f403e1dad413598d6e429a4b0e511e43ff4f7f60b2663d2405d9cd960" },
                { "it", "e2f11e352726a245b3a5ed6aa5259126de103f21d7ea05a01688b10792212bcdb4e3b9f2abe3ab4fbe808506ee3930a14d192515c8355a64fdcd06f7fbd0131a" },
                { "ja", "046030fa3807ea21217f7d03c71c900ca6982af40ee99b2fbbc8b7cb31e0bfd4dd71436577a15050b0b111a6791d21be2e2c271857ffba1578fe43842611697b" },
                { "ka", "7e7a06a3650e2577b6484741373a8bdf46c42d4da527893e16dc44417f11b9ad34b72d2374b88325ee6acd96ce9cccdee08f98608500226fe573ad6ce2952dd7" },
                { "kab", "6af29a17ffce200fbc1cf68aa70b3beb47c69321a4a8b71d0fd903711cd308d9d5b4832ae115248a362ac0d4d4d8c2c51b7f36f0fb7151cf9f8b0b94a0361e79" },
                { "kk", "be677c356386cc145fc8df3119167d209ec27e2eb9a4f78e69adb7abf721f7399245b39e4302b2c6f33ec535c7b70f001535a8f5609fb07cfa304b56d4e8ce2a" },
                { "km", "27e16e4e81814c829470d33822f72d7948db6d23596d950cd13a004bebd89b2e9031c6527a24bf5772825560705481a60b17a067fac1405981f8e745cd6db82f" },
                { "kn", "b3dc1c8c11a3520d60184f6f69da2576b8d7d77b76aeda553de27660699ddd70b1e9c55a35657cbec33d208a208704deb8b15d5866f14bae7f9c70a7fbd01e10" },
                { "ko", "079fae68e5e76dce863d0edb69e191f25eae10f5826550ab5305530274b321958cef8a77b92d69f813c303b13f81881d61207421893db1bb52de990a1842aec2" },
                { "lij", "cc407a08f193ca08d21996754db6e7a0178f35f440eb6979196cd031503736bdc2d10c90fe4d20daf814d10c786065c1d38e705cb60684b407e0af19d8582f2a" },
                { "lt", "dd1a7f5fd8de53ccb92c067eba40569a740afd5d198c6c4e3650eeb042ffc25be97843496627496e1b46a7bfa53bbe1f70f448130c006a856e6c6e530d6b3641" },
                { "lv", "a6807001e7b86eb3f6bde2dd74c3fca36b248e060ef2135039cca266f2b977e8133011367385a85b64742c06ab23ee103cde36d8b758062aef8b6f36f01c3538" },
                { "mk", "096175c82763a2abd91cd5342df3ff6f6a3f04c7157eee051bd074db07e0be91b78b5a926596d6bbeed50f9a7b358fefc788877065b428b581e184c01332bb41" },
                { "mr", "7d142e2a86f5cb487bf52bd8e680cbf88f58d3914c776a0c6c26e452bcc5ce0b748b88a5fbbcfd8541d2d4eb2fd8501dbdb7626ae097f47df6e42f18b11859a2" },
                { "ms", "c548f90333f48efa3daff4a2c967981e8ee860c35b605b784ed17dbbc9a7782d5615fa098e528603c0ad886800b351df304f7cb1fb182fb9c883a1a70adf285e" },
                { "my", "8c8a5bed6594dbae22f27bc66ac45a22087112066cde32b541270fcf4194e3232fd6921f1612e489f65d572e40b232f4039a6711eb6e89bffc65d66b1fe23f75" },
                { "nb-NO", "5b4892311255983322e791b3834d668e82907841ee493a09551e5689ef46af2fa035f11a8ced655c4d86a1c51066f8c8757fd23834c5fdca3545e0f642284b50" },
                { "ne-NP", "bc358e326d97ed6e911b2aafffe6142788f8c5cf4d1796c679a4bf6042ae0359e90ed0e8d63010321f06635fa13c18da9d85c95e0b81c177402e39a93f476417" },
                { "nl", "7eae15aa571d4782e182fcaf1c09bfcbc979479410f1742eadf16eac2f660c31fc47d22364befb7f4eaac61db710571e7ff0361d91132dcc8dd0684c4684c033" },
                { "nn-NO", "fe5323a658cd703cdd36cac4911949bf08482d179a45d642b9fdf4f9c356b43c06eb9cc8a1cc143685c42063f7c850fc3be4f534c246e1c579ad5cb9622763fc" },
                { "oc", "5fcdcdd66b32bd2006754a9d70939e61d684c78dd963c3d8b97d4e285c5d7d88c0ecd56f5dd1f07909c8a6b15a014c4b7ff8ea9f6687dfb4e55f8848b09208f5" },
                { "pa-IN", "d9c7266ea5079e65f723d5f168cc4ef6f38cdec57adfa25efc9b069705d00cfde80acaad8edb575f3d7032e32cc22bbe2d99356bcdff7f8e073f38cc8429d8be" },
                { "pl", "e2b6fa66f4b159e2f3dfefa85bb420e4b9307857c1a26f207a7fa4e9217c34da9f7aca2933123813eaf1d90639c0aeca2343449a9a0952dba89b84a91061d663" },
                { "pt-BR", "52b90f730508cd7cee1730540d6608e3029c051f5395965a77531feffe94793bc2dd444339597552916b489e4e13d30360dc13bfd51dcd23238ae74cc48b3e7b" },
                { "pt-PT", "ab73312cb027ec55a4aa327e6985e0d8f75e58f530b7bcab58ce90881d86274975a2ebc2e5919a1975d80f6a6ef72b26f7528109805c1bedf1525462283e8953" },
                { "rm", "09e0ec491d485f10c98e10ce30a762b8b1ee0119c88bf1551d89684cb056f5379838ba4346d667a9c3329f5524e45dd8716acf1fd27e514e64e6facc2973abf5" },
                { "ro", "307e261f529ce4c771dcef6e0243e039383d6f90f83dabaa02684d3ada706db0848a7fa36cbfdae7e282219619604171cdfeb31a6087004a9e8978be232bd5bd" },
                { "ru", "37554d3d60e4477f92bba41f50520cf56e407ab31973f30480b1df589954b301b690e7005a0fb28496d3a642f3f07b21cb4148a37389679661306a66055badc7" },
                { "sat", "d182906a3637762f8c7899d7b2db16193c72d8d4d1eeb31c431dbe6175e62c256354920eecb325cf77513d1d5df1ef01e31fcab6baf2b699ad4ac436cedddd28" },
                { "sc", "fc204286b133cb1426db3dff77d7ab60b2ff52114bc7d3f554bc38e262f069025128fe85f02b5f7df92de579e6ff7045c069a2e3a872ca6c1c304dce946eef8a" },
                { "sco", "608a33fb9a9c70a1cc1ce296c76feda7359753fd0cbaa1794f58a81310fda03ee416d6556067c0d5b1a074c2e82722b2471d9bd68196fda935d7027293a77211" },
                { "si", "daba59805eb8cc0a72e5dc0a65daf8d7bd1442d4643af4eccfb27adef6a9bec241819b673e6d3232b264e86b4eac1257ff44416e7cbaafd01a50857adb3eacf7" },
                { "sk", "8f520cd35e8cf6ecf2920b6e6762f647f8cccf035eda348c5047010c7ebdff36024532f610a73c7809785eae18bddda9b8cb8571cecebef6cbc8eafbf35ed3fb" },
                { "skr", "d7d8696e45f5c29121d266529fb1fdfa8b603c7f23ea66dc5161f57901152c2337e67e969c1bea97515511c09ccc84f9fd46a9007be5b2dda0e97724582ea1bb" },
                { "sl", "65e74eaf741cb7739a756bcf377b44194e6d6c27e45393086ca9343fe04849b5c975d0c2fa61bd5137c314044fa4701da08b33b688241796d0a36cd91581f8e9" },
                { "son", "4ba6fbda578cd5fb67af9d484c4b386824675f7d8c6ef13476ba6c765171fa6e4a961b32eea346ceb68fb1dcc7f10fd97b3679cf82218fba0e0a8263d4b5e18b" },
                { "sq", "f8147d86bb5def9c105008b97c8856b1c8b10daddde1dcc58de1600be19c06758d3cbaf2d519f37bd2d362a62d34ae127cf22a54b312e6934d0104f383a88e4f" },
                { "sr", "e02c23629f58ca4927131b9fdd2ce385ab7194c9330a39e817e3c6110bc59f592a0a2c54512c3676fc63dff9822a128198eba2ef2268931c06ff50627693b3f3" },
                { "sv-SE", "d780f99f79ad6a18ad65a435ef1638742a4048760152090090e79a4e88b19c6d5de4e4e3249c877382b92fb6bc749a7a95e4b4c11744a5d8c218855d2968cc9e" },
                { "szl", "34d70190b52e5b043abe0ba0f6ac045287054b9b41064c6cf070abd4fe791f67fe64c382d675cc1398b479dd4f834dc106ac1562184572bac4a4684d3b7a1ae6" },
                { "ta", "4afba97b1aac1440b956194b5f5109100146c9f8087c5b4d901b036d2b1982d5dede5446a6fa993a36c97ee9e36d9e7a5db7898c2002e60865a4a710fc1b21ff" },
                { "te", "f8f147d9fa1397a9d39635096a36e734f9452821b8fc8047efa0ef6fe56db1c3b92b08fa072f41ff79235190c031e1f2787fb2b602e610f97eb43d2acd8174a8" },
                { "tg", "794923546064e3631fcaa4ec99922f651c192e7472200c2281d710b28241621dcbf35d05b3d6d4294162c36202b3429d614a03987885459ccf7945017ecd278a" },
                { "th", "6b154e1e1eb9e40bb905466dc920d451e963ebd7d27cfee2ae450ad40cd4cfc242abb41f39747763159d871dcbe8349326706bcae272da03f899709ab2072c5f" },
                { "tl", "465ad612d1eb663c6687dd97c1689ed106ffa60384a723a94cbe205683e4055441feb5b4b407859957b55daa4958511c9846ecf9b8f2c7b73b49f2871cb71d5a" },
                { "tr", "20ed1a2e2b1220d2a127dc816697610fa15da6683f4641fecf9c5e8d061cd121526957a57fea14f80b659bb3a2770f8d6ea8948a33df32a66ad43da761db07dd" },
                { "trs", "c423aca769cb6c5d4ea41d7bd10c24f38f7f9c551b954a933f94ebb7c4926e8c512abfec35d62949997dd6d754b7ba561594b46aee6e46800626009ff594e182" },
                { "uk", "550842ee632c60586408db0f3fd603c57730cc6366fe0a2ecc9547f62c7c9ef75a3840ebca960a2d40e438bbb20a7d98d2ee6b4528af6e5de8b68ad148f56995" },
                { "ur", "526e054c34a2ec91b464325149ac3a075e1d4fceaef89bcf79ce9ba5e90ddea0becf01d9653d005919846043391ec34271cf3def8ae0a0762d5a80667afa776a" },
                { "uz", "39221df0bac69e525243c16fabcb37f0cef45a74a2027e01ad9f3e45de0fc571367a172bd75930bbe09e5c0068f96bb708b6e666a7759d54f5b020ac09e6cc56" },
                { "vi", "16b3cf098bf7317f2a4f045657bf52bee6ef99565d16ca61d5fe3c53f3d7791abbbb95250afd1c1eca9fa18a8fbadd5004b373186989a6bcdc0aec24d0e0ce73" },
                { "xh", "2f2e1990bc3d893f7d33c537eebb8944cb83afcd0bb6e06f89df632f239b8328260a1c1d481d3dacee6db0251e2d1311d17563f236ece35e8e58f8f8812614b2" },
                { "zh-CN", "b0f18f225a335c06750ad191db864b9c019da2383202a81c47e7cbbea4ce50c1bbe9a6c10366a68ac2191020459015dbfee33d9ba230b2d553144fa3b8dda09c" },
                { "zh-TW", "2dd6d5f8d528e359a998d916d958b9ae58f9e755e4aff56319a09331c7d3d04565aaeaa58dcf454b853274af1e8715a51c7d33ec20df8faf30f6eabbc9bd1a7d" }
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
