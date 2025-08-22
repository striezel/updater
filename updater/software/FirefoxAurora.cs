﻿/*
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
        private const string currentVersion = "143.0b3";


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
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2749055add8ef9234933cd9291035300275511df145aa165c1e72b408958e5aa3d6680a9587fa42f501944f1118d8c8ff19d5f56ff03a1115e7f567c2c171bf1" },
                { "af", "34ae86464a16a3c2a70a9dfa27c07062040082d17ed9593a672b4c0507611deb357041b4bda0884ea0c87478fcfade4a6257ccf8782bb1ce5b00f8df99dd82eb" },
                { "an", "60ab102599473f24eb944703e8384341b605506b766208e9aee9a8d43485451e214673e62a771143ca9c9fc4a22a0fd75715593085eba5026f7cbda3b9103a93" },
                { "ar", "4c4bb8fffc3c9df6c8d81ef514a5b64b86070c390ac483a75ea715490a575917789a4ab506afaac1391ba20160c357d6d4a9a91338a6716e1b3e3bb881dbc88a" },
                { "ast", "119950a8dfb3147b0a5bf700523865f8d2dcd7fef043bace6e8191bfe34801a37c925ffaaff91da01904aa2eb713a756a025ca1075b00e9c083afba5e19b0995" },
                { "az", "48280e88e4b7324392b9e12ec65c74f1b212572b316e88aa3ac483eb35151ef6e5ff31220939ac3cb3df56f09dce1ebc9c0ba479c61528071f54e3357e4f4498" },
                { "be", "1da242796f02b691c99247bfd1073197a57c8dffb0fe71aa6bea404c2c5cc3485dd830abff293cc25155a4c37f89d90868cab40bb61af7d0a52bd3826a84f5a5" },
                { "bg", "f9f49bbac653e658bd5cce5764a8932389ec19e22d59efb1ac2f31a232912b860b3833eae357750c42db7d2f26bbd899b4fa4cff8e1178bdfad88f9da32d8cd5" },
                { "bn", "49959456482148496ba9837e0e01b40372e522ebbab2abaf8774c3bca7396a729a48f70ccf9cfdc7b2e7ca37884c4ea43ddb59c30c7e93449a209c19c87b31f6" },
                { "br", "7e1c72a57e618787571cbd0a16823d9047d4c7e69912a5cbe683f7c6623523202250090e753d5a49c2c0bc3a418073189a534ce1dcf4cc4a3a57c80624ce8b9e" },
                { "bs", "60e653295f019ae454552c633c8517de11a202e2b816f86fbf7134cfb6d202021dcae66b6028c1f3431b5421df58997a8659ccc2e728998f7093d7b5d6dd9bca" },
                { "ca", "c830c1bdc0b0b86388eff2a3267fb6a1de5fe8b3b66f37f31650216b9145863387d5870d45842d54ba458990217b96f692f7b2de23ceefbcad1cdd04916fe563" },
                { "cak", "cc146a0c56d9a5f067bd47c4dd3a375c73b693b84680cff9857b95e78222480a7b07684e30503d7eb4f79edd35f555340d8833338c789c9792955637cf0a540e" },
                { "cs", "3da25cc0f4d6d3ee20997b18c088d81f0ccb8361d241a7a57f99c58f397ec7a155e6b22b1dece798f796da8c345c2ff8057d470eb83917b54a9c4a1504951416" },
                { "cy", "5eb74db60af2dc90b4857df7000703f707de6577105d5c0d860ef0728bc29e044e944b091e56ddfb122849e5156ec793343c87bd70faf6b9907222cd8aa37224" },
                { "da", "d399ecd0067f772b5308c3a45c4ba6a1906c2a66246c95c3d3615dc524d639534280501da55704fa6342727a7f42dca1b47aa0149c1237b75326ca6fee205050" },
                { "de", "cdee56223709772df4b3d1cebc15dbd1986bb736f977a2aa0c49de33ad5fdb2436ac04a0747b0a29e354d9640314347747962a0e3fa62758f9c2b59c9aa8b915" },
                { "dsb", "b7746e8c393bdb541a3658d77b93a4d80e57959a6de601b526c77c9ba628954746211c438743afd001e7c008637b99e332dd1e55da1b6dc807ee90061945f166" },
                { "el", "44a9de5cf302e981a80e0fb15ac16ba5340ab6a3009fc0a6bc6b4aea7317477623adce05b17828d00fe1e6ca1fa0d873335fa6ef02ed2642e24154b2a5f31042" },
                { "en-CA", "2e38ce95d077b989d68e3a8d530eef659188bf4e9a5244ce7699af09b05f9f8f5cb2d02f3db3633ebb2dbc101cb898c0ed474aacce07fbb5a98ebd824dde3e78" },
                { "en-GB", "2829d9773df32dc31c2719627e0c81ec099b1b2125fedc98523337171280c88d701ffdd23fe0763a669f59ea503dbd8c33361077db04960abe4d402bc1a5a916" },
                { "en-US", "c4cf7f1cac8ed837169a087785b39b26d5bef309bc4c7604fe83cd0efe0134daccb4c0806fb366217628cf93a373775e1f70264a87e54f367bb57810dd9b42ad" },
                { "eo", "fd79d0603d4585836d725bae4851f4900725059a8726effe76f4b6d88a4dfa5462d0644c9ef54342aefcf322f9c6801ed457fc0ad85f2e25a1c3c6a80b35cdea" },
                { "es-AR", "ea154bb6db03ada4298866876081c35720204b0c26934921e11ce3167015861fe6c87449614b2811e38c8bbef1e4f9ad675dd08191b5e250ed4598c987090e69" },
                { "es-CL", "b0ba75c82c4b602737f662ec75ce18192ed23f70389b0a0d4732ad9de726789d15a18205a5741b37c206679952f5bdd1ab575a4dbe54ecfbed0e961e14d14a1c" },
                { "es-ES", "4b3c906c33a0f4e060cd80355aa98a38ba9cee45ba952e947fc034f62b97ae7cacf3cccae352b7ecebb743359161a04cb907144a01aac56ccb32bfb32f360f10" },
                { "es-MX", "d7f87f854c1da849039cc0616e557d9139532f07411b7b02cdeffc3df18af889ec99cd9d51864ccfd6e96b33a6d8cdd3846d4e80bd0d266518363d8dca68e45a" },
                { "et", "d51686ca7e802a2669e86e33de3ec8a2b736685389f4d0cd1307ed77d3ead0efca32039ec0248d80370a030d98950817f92ea0e4aa04e42bc24fb380c14e0813" },
                { "eu", "3a07d1fed5956cfcd4e302f84e8b490163e1251d53b7a076280f035429fdd69f01e35b291d3f971038d74b53d7b1024e6d4e75089d74ee4a3c56a626f19251b6" },
                { "fa", "e74b27c54876ce051c9f271328542ffa2c2aadfc163cd60fef7db251a448b4ea8284a176e0c531314e64ba511d92f9e863b474b3149361630053d892009c1271" },
                { "ff", "9bf5aee53c569b3e26dc4d407a56bd52748d08399b2ffc113da786fde4426f637c39ff1e6692626038846b48989137f8f43eafc293d1813be4d016322e6601bb" },
                { "fi", "da389e6e7d38f45ff383657e66cedef9d4b8bb5c21ae09d6368e534bfaab117312618ee492053b7685178a67b31122447f29387d72b5062fa4d042698c9aa43b" },
                { "fr", "8e63a9f6a3f3ae4528bdc83f4bc6557a5cb9b9bcddb6d1fc5c72af34d89255b1f0ac748bbf0e8b5bd1b7c621857c82c599611a08f2cc7a1f40ddbb5ab3551c9e" },
                { "fur", "232c01b023a9debec0e5e4fa98ded88ce7931abee341e58e2362e298937bb6e025d8c49690fe0d165e47cfa3080079f5ede7f5ec3e4868cdddaa1c077a9b1006" },
                { "fy-NL", "8789c51ec947d2401351960296c4b8b3d85dad0519e3e9f9426a56e6c94e6036cf23664d8e8ef62ff6d0c1fe9f6448873c58d18df561cec54c6f68cfc93d9530" },
                { "ga-IE", "84e182397a1b7f357076f6db6dd9f1b34ae1a024ece4ff22b2ee8ac1d9e68873d7fe06427628b42373acfa991f2c4fe784c7426c138a47bea0bcf7913f57292e" },
                { "gd", "2037b9c45fdbc8cfcbd485566e045ec315651992bdf98f78bf5306bc386fe9b4b874bb21064452a1dae1b490d245e67b46f0420bfbe583acf0061349ad130660" },
                { "gl", "438dcf6607c209bd2ca7ee406c3b5eb289f35b5dd01d6997b95fdb221317a1563e146aa0ce8cdebe9da8aa796cd8a534b85246ef9c71d83e84e04033fd72d030" },
                { "gn", "5953eb841f041d71a0acaf94322584f33850d043b9dd97878a07b1313e5e9e0f790de56f9453bfae9497f47e322794818caab6f0d4cb2a98d1a9e647bcab0397" },
                { "gu-IN", "b04c2296b42acc00d0ccf3883f1d6a920f7bb2f201eda61d36c8c9e6670da9bf42a8f51b378381d821bb74ec3d8d85a78bc62438c7bf11cea3be4ac140c1f8f7" },
                { "he", "1c30c560a93f4ee593f3fafee65d259587d4eb6959ad228b8cfc770e11a72fca35dadac838e24b7f04656f1dcb276555a10b973976d63755ad8b723bb88dc8ac" },
                { "hi-IN", "20b7851283e96c09addeefa3340927d216432957ff437bf8033d62e41f5c160a1b58b3cf801feebc41f890cb9fa457645a5a0c54f4783eecf9bb44a356e57c74" },
                { "hr", "7ee6b805d30e00a75b62c0acfdaa5cb028247c6db9a49d7b8ad14a9d9dc9a3b8e7b428ee7ff8d0107ae62f509ed03a3afb4f034eabc7b4c7b6693684e502d347" },
                { "hsb", "e31307877e4398f6b2a805177b64367b076935cee56486965a548a38fec77039232176d5f332d8e7d41d5960f52ddb1b292714d2b0c3e07c8b0971f865af3bbc" },
                { "hu", "3e643d0e85eaff27af8ff2c85a158ff096bbb605d7f8a615be9965635e8a06d3ad13cc2536a947e70763c0349f748218d010c34154796cc34ab47c8af20af776" },
                { "hy-AM", "345c170fc9c5445ec07af9d2c36561b9622173a6ce3a6d1879e0469322527cddc661b55a9e63cfc8b593b8b5caa9dfa458d615a89a97ccec69c34f6bd9f853c5" },
                { "ia", "c90bb96b398c13465d8c3e7e8e85be449eaf06c5c9e7d48d62c893f74ae8a7905f0549560e0ad42291d67ee58131c1a45cb93aaaba349b41cd017cb8d346a327" },
                { "id", "49ec07540f709f574c6f80abf8d907f319834d4d388d78f16a0dfed1e40fdef39c4f3f2e0e5c604653c94f717b1f48925a831b7c100e8ef19a6d7f19e7d5fcff" },
                { "is", "71dd49055d34fcc65d6ec751076872343dba6c7533f8a32d9b3caf0e4f8143c738e0dd93ded9cde3648af3a7435abab51139fdc7f3c6bf9b2789dc561af5ccaa" },
                { "it", "78a9fc8faca8d4e1b9fd0038ad9d55d1cb0268be4670fe247f2dd9dcc1765349b53c2330a686707416abc1097800d32888a030c17f0cb1e6a63a69aa65d4a293" },
                { "ja", "b4de6f7444714e2f8fc1d0571876a17d8270e02757d8968648b7391fa4c8c99814c79878468cb4501ee4ae46c6853de9acad6abe1029260defdb7aafb8ed4af9" },
                { "ka", "cf89606714def582ae581ac6fc9af816d7652e070360174a2472fb64448aa67ac5d51567d685219883e23145dddb1ec7980d783f5de25211f900744ae9787365" },
                { "kab", "82127284df8dc798b7064a834198bcc389577effc0ca7ae5f169d6668c1890eb4f9092948be87c73df962e3a033aaf9e5dab7b1555a66e0c986f83b981626cf4" },
                { "kk", "ac54879099a55f89ecb07214710780bd00c45cb9f0c2c3c34ac0726e7235c572c6d52783ad152d47dc753be77b77074b563b1b64eb7617e336d3ae409bd7b5cd" },
                { "km", "a6ae0cd4c3c93fe9a6c4c6fb8e205f972f2d2d6302bf3f004c3839c785175280b71c9269fd057da6f09926e6dcb9664ae79019e02b8265203e23b2d9d2204fb4" },
                { "kn", "781a9a6825201fb2fb75f809aa60d1889c1d47192fd5f8094ebe14bfc958d40e01fa9190b6c69b748eb3b3a8168202d7934cc8e06077ec16dc940358a90abafd" },
                { "ko", "122f94ac0d1ad9a63f1e3416ae7246f509bc339b90943b566eda295666fd1b707e2668320afc4b8267bee9877db79bf4b81e2f78c281c03df30f9906ea31fa42" },
                { "lij", "de23b89875125f07047cb380c32fc259da7c232b79ea9fc5c767240289fd443d522f746df3476ebe136cc9618cbfd69b733621194aba86b0ed9258b64ae6e4b4" },
                { "lt", "962dd52fbe3473af5305c963305e2cd1745f83a1043751b782be139d466d0f758d42ffd6bfb6be1b51afc81a74b1617b5d0f56adf1d851fcb52661a23a97ea53" },
                { "lv", "88099a89a4fd456d84a23718e3012977dfb88e8cffff79e5d8342050f4faa2059a32ec57a7aff81b6c43f692ca4eb367020372a6eff2f1db7e1bac0d931bb57a" },
                { "mk", "b35dc643bb81af6dded006456d1ab24263aa8e295ff0659b54ece6eae7643c3f04e5ced1d47810d30959bed2195ea5ad959a83965768c327a4603bdb838f19e6" },
                { "mr", "5bf24934bd5ee6827031dcccede61606471ff93ca49920d90f6a17c2cc30fff3ea2fa7f608a750be645d826c24d0c2b8488bc5dd65b5679412c7b704f526a4ed" },
                { "ms", "41d98131bbf5601e831dd14a5f3a8d499ca9407d704e29ddfa27aad70248ea3cbc9ca5822d3546b6078ec04eb199696b0f776ca10bac4ab84bfa99c3baa38a99" },
                { "my", "76eba5e4f305657d4cca4c7d6c41b9573b733c58f6db12368069c431873873368f2eb4c7def292952d37122af3fb31351b7cbaae268992e08c18f6616fa3c452" },
                { "nb-NO", "2c11bc83b8dff190275c98eae9333cf01e576da84bb92d17da725ed18f550f382f0269fea5309779e5155a18369d45e633738edfe381423018c66283f3e0f74e" },
                { "ne-NP", "16107b094481e16536d0ccce70c04ebd38aff8e6c8e34b3ff7102cae5704ed7b681660457a8067adf406495d02fd7915e53e2d4635af95de2ce604c77fef119e" },
                { "nl", "037e106377d17ee9d733cd1a07e0e1fe53e42b86b1bf0bccd1596ab30b04cb08508da2709382d53c8244b02474ce70d72739ab1b4b5dc2cd6da6be5fe22ef4e7" },
                { "nn-NO", "4276d7e2e51ad4845dd8c54d04d66aa1e8f69b6f9c4b34389fb4d7ef753630a5e6053b73768a03371a961633eea201d6d7c9f45c62cb404c35b39c58f4526fc4" },
                { "oc", "aa5d51b6ce8c5bc5b8d8c66bc29315d755fb83b907334f131f51049e2e83324069c7ba80dcfbd0728189986ea07081040858f1cb300ce43f1f6e2741beb50454" },
                { "pa-IN", "5163560b457a6b446dea276a1d5eda5675325da096d35d986e860a16b1c6bb6cfc3c5419dc984a886e1ebc3632e4f3c572e7921b12da7cb89857b94ea6af8893" },
                { "pl", "936f263af60ccbbef660b458189937b9d50c72f3ede63e79c1134c0c5037e3849f35908de3e5c30142de88b77d6615d1c17c146b7d8daf32b477d085f9f67927" },
                { "pt-BR", "25d51e9f5dd17daaf816ffde1bf53022f67320c48066c9a4a1843894cc0e7f2986458902eca0899d9c7e7d1735b369c72e564424061587a9cfce7e5fd30a668d" },
                { "pt-PT", "a0470fb16a29a60dc9c13bf5bfb454cd367439f8dad493cee666d7d37af797bfd19176016db888d90f51bbfa3aa2e7b635759b06a6107fad57857ee5ce8766c1" },
                { "rm", "2302edf79fc47db9a56f8c27165260e2ce6d97905dd0c6c6c277692b7027d6cb4d83e1bb1bce8260816acd69a39751145adef4b7d4d7b3c0516a52692d76c0cc" },
                { "ro", "784ae1d37e8b1021caf28d37a0c1e604fc2d6d12ada0922221e7c22999a737fe20c4e4bdb27b10ca1b55a6c28a2ef1e4e7ec101855ef75159b9a7fa7a24372f2" },
                { "ru", "fb98725e577c247607a18b4f77e301f06cd9435c1c48edfa943fdf078cff88c972c3485d3db902487f15cc474089a75bad5b774c8d02a7dc85db5bb0990ecc69" },
                { "sat", "49ec04a01e967d701d36a5785f6ffe5c8b057413ecab85b97613e429451bb1707024b5464eda870f3b7f392f516ff042d63159108362e3f4a3ca66903ec184e4" },
                { "sc", "6f856f06491e633e9e5c9c7d26ae27f77d1dd3fc2b78150f6d6e6545969f72c4cdf90c8e40a7ae6a2b4810278b1612bcb2c49c5ec568f4bbd1ac6d20bebf40a2" },
                { "sco", "f11749bb3f4c667ebaf5a3b34b77cf797d66a15fea6ac526c9fd5fb13b23fc4025dc17a22f029c23411c3d83c1780526429e1b490471810eb416140cc00d4c8c" },
                { "si", "e917a6753663e6ba97acd1970a1fbcf7fea859886fbbf58db8679ae9ed94ca8a5e75af48e48828be337b7b46d07750ed366c8c5a13e965975337e6b0a4194ae0" },
                { "sk", "1ebefe88359f4e706b2b9ea628eb1bb64c6b177a901a2c50bf68d777575f4f83bc5b93e08408156452b24453c7f59a892047f127390cd6f9f0e1cc3c32b04b1d" },
                { "skr", "3fe6b37b72c33f6aae92b7d8829202ebc572d5e53a19215aa574583a7a519c70189ec08bde68802bd14d0071f180e688169fefe3cc6aadb17c6c48d19b015315" },
                { "sl", "cafc25de46f572d1fb93662eaafefbfb65ebbf0f3588478401702ffba760101a3b186fa2100b9bfc4e5b9497a0139c9d47c5453c469827ef9f5b1ec44c4c57d6" },
                { "son", "ff7332f7136e0bb1782d9e9879d17abae74767afd46a0b4c8b79a9b361eb07dbb7cf12e5bb21b123b731c1ed4a6605d141a1a6a15f9d8211e5e4c7358774b3d7" },
                { "sq", "7d12afb1bf9e66aa5bf95830dc057b8d17126d3b2dabe3fea56802df093c86311997d54480a869dd1caa9578781b106d4f3b8215d7e40b9d47e6044eda5f8c02" },
                { "sr", "c814dc91a9f049f5fb995f45c2f05f1cf82102ffc19086b49066a72f7a637d7e4dc14c3e2d15a658d5380e394044736b7d5556bbefa236314ad00665c2830717" },
                { "sv-SE", "96c2bce6086d0a900256444401913953340a4f4ddf33816437897578b39a43e1471880f5d2bccfe4d36c7e1e245bc333d9cce1d36a86d8ec50f226ccc1a040e4" },
                { "szl", "7269f84a8c66a4fa27aac96ea6f371e9ee2ba01a95bbc21e2ce95b5a7fe199ce456395bd655439501eb45f4bcc3bf1d292dc0ab614f347c2e42fa584e153c1f8" },
                { "ta", "d65cefb6be88e4c2a16e107c7f4596f00e19ed767e98993e63fde20e06dd7621d1bb991918a3e6c8273bbf1060ad261887a638639dd141b5c39639424bfc5883" },
                { "te", "3a1b5582c16a6c9f650ac47a4d0e530eb013982ca06882f198b4c34cb520f54d1cd8142e8922ec04686c3bedbf41be8b84813dd2bb27c9fab662b9b2c261b4fc" },
                { "tg", "08b48c037a556cf3ff8a0c5008e21711f475bcaa02b6b9626bfd8c130e8b2f1995ec53a20c203f1e2d2e4f7084b8c37985674a981885d8e95f946a211ab1e11c" },
                { "th", "b9f0b6fce94692ddc97fe795b2bfc5d3164d70269bdb10532192b09ceda6e3920a5d493690c69f926b70bd7b934ae9f53d9fd3d2f41f7681995e9a10f9c9ce06" },
                { "tl", "45a1b87a93919374fbaf55c9f64824ecd6fa4007eeddc7b76a2696c7e201a88e663d8520a1a871db8069161f10f3aa9115b7667b6824a04f5670d5cae89d6adc" },
                { "tr", "2562c6fe139112898cb2f65177c1936b6a2a7598264e68f1f7803b3c54cbcadb651b0d649602ed7d0bb93e8791296f8a99ff9a77d38d1530b70d9d5c3db35fb4" },
                { "trs", "4d09c495c451d329afbe96e7e1dcb9166af7531834d3b060fccb9784e81994b4fdd57c615870568c4f7fdbbd0b428da84c55a7d3edb8e652f9356979a28b8b78" },
                { "uk", "21142a6e56c396ca5662337252dc6405e31be1293ccf60fe8abae0ed76414e6bdbe7d06d8695eb3317088b601bd9e29c60bf8b246ab8d741b6c961abbbb6867d" },
                { "ur", "a5f6c8b8b1008dca9316fac436fb6b84670a15e5669f62cf3c6427067e78ee1d5c1157bdf28f5d2607a610539db1351b6d9e1ab03fc3a9cec1d1e7b6d5d766a7" },
                { "uz", "0e66b16e327c6869822f3fee0f47452f3f2d955fbcea0a0c1b794ea65c574bdc4f98bfcf71fc7c0779046a2309318165400a2dab2f511b58a37eee16494540e0" },
                { "vi", "5c33832143dfc9af3bc6716b3fbb8fc47ef6c70ba9e1d797f8aa46bb490fc60ee9dd22eaf7d2be04995b1cb389d46d9fc796c3b92b3fd75984d2a252a5177884" },
                { "xh", "82785ac7aede0fc372eb4ad41b56f8a0a546bd73efc6e3e6a88abe8e82574fb354687b0c9a1b3dcbd83a17b57f2b068ae028cf1caede0947bbee104e9feeac4e" },
                { "zh-CN", "4fc3c5364310cf68d166e7fcbf41d5362b6497980785e339d508296883e4f12e3a4a7974445b5e3ca7cb7a2d86b8448fad3a08574048b213a650b4521c82e7cb" },
                { "zh-TW", "c6aee01a218512a600eeb973405b48b40bfcb232126bdf4c284e55a8d9c5c92ee42dd28e663ea3586176f69a0a0ded1125929e1c7ec221ac2e9faad995e80319" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b1d12f464ad38f9b0afb59a523a466ee813eb296836dcf309a9903c6ce2735ba54d3131703c5d7d237b3d112a8166cef7e11c12ab56f7f16d773dcd77800b808" },
                { "af", "aa55e3eb9e3899ca8568abee17dd9628e4dd3e05c2e322e041b1d07e780e92d041c449e32ccb73a5fb75fdcf07320973527f25028d3e19d95e3a83069776f72e" },
                { "an", "c3b86690d26f4db7084917d5bb8d8cf7cfad412d1b7be9622b8b87cc27148af533392263f736b66c94472b0c4d6cdf224e37cb19001dd2f713e91ff65ec6e962" },
                { "ar", "6c9443bb229f70debfb9c1b22d99fbd6a5ecb5e37720fc0c6bb017ab028c1f045c93c393ecc6d6c6f6133d5f87a678089a9e8bf2eb3d7a1d8a250cfb6337dc7c" },
                { "ast", "7bb5fcb3b3f743d441e8e906ee20bef4d1b043f6019a47f824c1cad7924db66c3799da8ecf558bb4fc3550bcecad9aadd48d68775213990502c119482871eada" },
                { "az", "b796ee3dd71e3b9e263ae5c35456ecc97767cd091ab33059b86d6901df91ccc8a64cc7f8e2ac9a6fb43fb1eccbf2f4e03ab1465f31ff11412d3fc7f80273b985" },
                { "be", "cb45b95bc7a4e4dfbb6e31be2da830fc23202d1ca94d1db02bc67385bc3b36b6cb1e43015b77f74b0642e25fadbeaeb6d92da073bd9c023dd7f54e5983139d11" },
                { "bg", "bc8ee039c9b971ce9a47b9ec3155be6ca302bf6c1fb3095ca0c6226f77372748641582956b73affd5542d5d9dfabae4a7de710f7e8814f7492558a92945c9283" },
                { "bn", "bff8b006e3eecc55b1560cf619e5ddd1247a3aaa8d7a82ae5b1a480ded3e7bafedb2c51744d173c325d24ee2000019b3a7df0a67f4ed490283d2438f37f5d80b" },
                { "br", "009723db1ddd9c0e811178e7db9c4a3baef0624726b49b2a259f589de91db2a76ef89e06cfd4cc9cdf79434ab175b65ebdc0c8a6d400f532e859f7bab48c09e7" },
                { "bs", "9273ddad91989eeb40c7be09fb8a3722eb0306931103099a8a910d9f31dcf474305d62df31fb2de94a334cc7371b95a52e6b0724841f3314d69da1172886608d" },
                { "ca", "5ab3b23bcf0ad5818e1cd1fed42ab51c4c09496fbc39a816c21db1fe83deb51598f8931c0fc0aabe1677ac95d34424ab418b67595c8cc8d4bb402aec7d065327" },
                { "cak", "ff921c8a31fc6a33b042b473a4b2a4fa2db0413c570b3e8d9eca585271b0a018f14c04e86db14ff5cc7c5a73d086f7d9f17272900ec251cc273043865c2a28f8" },
                { "cs", "4de864fe320cd5560177cf3cc4f1642de2a03e7933bd7c4e863e9a00901ca919c810c23d5a35e26aa32e1c1adb68990e8dfa60152e742984b9d8f16fddb2afe4" },
                { "cy", "a677b2a3a64e605c744534c67f63859ddd31c104df5e976969c17ddfbcd5573f96c5a1895214adaa6c1f72a45551ace559790c1e2642300d92e562fe34a65990" },
                { "da", "67717aaf8899d696a91aa374effd09494b18e64b9a8a19faf7da1a7f4f40d51b811661f9b840cf9863763e7a4025957018319b4c54a901e520c35eabc9a8ebe9" },
                { "de", "fa255d8288a495fbca711f6b4e3c0f4e796ef6633302d13b284011371c7e328067bb88a6ff24d3fdef37f49ac6409b7b30c523c6c3122f7460d348821875bb31" },
                { "dsb", "9d3ef280cbc15c5e31261af3e87e2842fe36c4ccd94d2875a849f36e0f51c6102a94e39a013fbf796850390196ee85063923ccc12f3231c47945465c8a2d2ec7" },
                { "el", "301170bdb67c0a1882ba8115058d8c8005b7564ab9bcfef55d980a2bb26cf4952147d08cccdbed21d6689773ea5f7875bda1a626497366a2b45cc7e7309f9f25" },
                { "en-CA", "70bc1925808c97c6967dcdca1cfad5ab48890f87c87d7909cf60ce7119a7484b52e768f896c6ecf1b61f76385d1a8f7af05fd22d029b69fee3632115feccd682" },
                { "en-GB", "71a52d5e0c813bb2c5d56054fefacc3c4dac1c496ef53ebf9796d31931e64af6a567f16dba33d5311ee7f1ab73b4faa4e6976ca8a82c3fffd83229642f88e4ca" },
                { "en-US", "db52f1d6bdc62051c82316d85836dab7074e331418933ed48c8a3a3e66994977edb27965be2683079778ed7d36b7338e46f604fe7afa2ec8ddf96e5deed7c6e7" },
                { "eo", "ce0b1cb670a32352d20fb52180415a559220bdc6b64584bcc3c7f7cd2f148eb61a42ef57436592b0f2b25ae40ffa781ca65a08382de9357bd7e52bd63419d57a" },
                { "es-AR", "8df76ed8bcdc6e176eb5c16e8b8828336a7bb590f6460c1b17c1cc918ad0d4d795c29d044a3033b1226b733f6e30f8c29b0cfde2b44f4100a786d0f24c7a7754" },
                { "es-CL", "df1747037d83d5d01ecb5db33f6a2a738c258e11f1194e69c1031f652efabe9646c2d6bc0eab44b23c1f334450bada6d2970c638efbe448e54665522b4d366d1" },
                { "es-ES", "4ba9e4356e133919d2d2636f164167946117ed92b72cd162a80e87621fb3d1917b997d2e1274c17113cdf379b55e9b7700a524e08d23cf4cf75494bf22e5c489" },
                { "es-MX", "a91db5ebb292049a24c0313ba7e63733c472199f3af4f7d9a59b1039007ec769e7ecb2f2351d7f3122d732d3b5859c1a3d6936fe2ce47c6e7adcc4240c69ad7d" },
                { "et", "b1f99d63a8b45de73e89c3621e0a0093a6b35b0d6e354e7198ddaad610746420d26a99bb4b0f8ca942824fda584279ec6af34cbbf22bb5eee9c129a08374cb02" },
                { "eu", "156ddd84582dac8268fd0f4997d3481ac93b115507eb16831aac07d112144beaa8be7cc74f62c2b3f1140e9009b45c6e36f6174bbdb648dd3b1d8d7b8d96f6ff" },
                { "fa", "351b388ecda5f1f17a2ac18ebbb11804a3fa88468f3625c0422898383ccf80d98d8aaacdcc218b2e4e165b2c6b62f2b4432747b63251960484c590a95cb2a066" },
                { "ff", "31eddb58445cca30b0317e7c7bf017ac077e745e1b9937f541b95a6cd75e2b50f5c417906368ecd9ef207a4c7d9d46e7b28d00bf6842b58c6116cef41a3b53d0" },
                { "fi", "97a79ed74666780f4e75202a170da806ce723c600ee4c6034043eb20cd496cf2b2061a66b2db610d60af5249c8015d41f140176dd3a78e570503f157998da58f" },
                { "fr", "827e44bc18f749247094692fb77c5bd71cc878233a9cc281e55151f1e0cd6cee7148ea64d79ef4ed8f2863fc7605f85732438e3f227874fa8f249c5821811465" },
                { "fur", "cd5b75f678819cf0b3317b5381a930a6d2f3f32bb7a331022e408fdd0b1dc1f0891506a2032b0737860a1768d52a74a9dfed338af6802caa6160b5e0ef32d474" },
                { "fy-NL", "cbf269eea60ec931d0adf4c66cdceb829e628194aad28c26e015ff8e4fd09aafcc3e844e8214c7fd982e5945f71d08d3159eeff5f4985760f4b47c34dbb371d8" },
                { "ga-IE", "612faf6ac0aa83fd647405486b0f3aa6ff202425fb9896a0a585f6bc083473907884d647f8c13f817242ed06c032de28b0fac178afa93b15ca9281b7e2a315ae" },
                { "gd", "baf312e6df818fc25f3db032cf4342a66454dc2f08c6317ab4d022cd1c1467e5c2020e0a2eedeef99897c76843377fd634f69ca13c346bc80879bd410d0fbda3" },
                { "gl", "723338dd0826f48f689c7e7a63dcd9e904b7db99fa7b78c9eecafa2be94986d59e1a954967010a8f61034eb75df1a7115a6efa55aef910ebd9eb4e1e92d7a80a" },
                { "gn", "64af6d0e3113feb4cc05050e1b891b862ef20a562115a250bcd6bc8821979c8a6b1498cf2a17a0e34023f9ee4c27109d63db9c89c7e7d6d8a959ec0243506e2a" },
                { "gu-IN", "8006b6eaec49fb8f52880d50f4b5eaf002579c824079cb8516a10fa2aacdc76d41d9377f96d54302592a20f01fe1bffb0dc026ff5c6ad0164afbf2b94c40a8b1" },
                { "he", "bc4c367a98998ad4c0f250583f01b790bab82d349494cda382c1b8762da9af24bc94718b81e815ef9524ad18aaff239611167c4f7c0e532930209633dfd4cc06" },
                { "hi-IN", "2865f505758f699aa6462ebd98b02e2f21fa541ad8844e5b365c5dc27e081d963a13da12a2393cde88d4d29a7a9266be2bb2f010269a0fb0252fd700b3900959" },
                { "hr", "7fcac8d3aac37d7b4482bc20ec6f3c02b5d0ac4ceb9c1b7610cb7b6aa882b7c69a0534531e983470e126ffa6486d8ffbf7f70ad87820a444cef2ebf498bbdced" },
                { "hsb", "6910e5ed285f76d9058107c54d9927bda2a8af66c73c653ae2b435dc136545f68f1fd88d117dff6adcefdca81f9f7cd152d4efea71c670992f8d385392bcf37a" },
                { "hu", "478d81d490aec83cb3f13e04a51217b7d7c3d83a082c5888f9bda401115ca9449802413766ee23c95b3e79435eca435d3038a243bdcc555bf6cf183e3739cb44" },
                { "hy-AM", "1d8780b545cbbd718cc9581c0b5559ded77b5f11e72395d811517c907392eb90f11dfc79f3fba289e04a54b161dc1c64c85b36f02b5da06a861ca516ce309078" },
                { "ia", "42357858ca37c275edd0f4d5d58441088dd709b38e26ab3b8eaae5e42d66971a981c7d080d511dea1a01dd43f328f3358ed09b030757f285c8d79c2cd651fadd" },
                { "id", "3e54257674c1793c0a47a4529df9acc49c0c109825c1cd34c131ac6ac2aca48be454781f440641fb7b020d104a7a1c76d2d1b1a31632b284ea6d0fbf5c1f50df" },
                { "is", "3dac89b2b2058a505ef515f5d7d4cc4e256bc3bdc592d8adc502bc005354e8ab4d118ed055ca51fa9513d651f60ddcf2dec5a73ad3f2144e27c0303d2b8aec24" },
                { "it", "da03ca455b3e11382dce90ecca820d872460ebb9193d06fc2ce850b67671286ad9c6b827303ed695973c8bae8f11cc4beecdd4924c9270689a80188bd1cb270b" },
                { "ja", "57979f5822a97d7ae22573d72aa848e14a497d9b9d3cbaf9fcf4c4a1eae7f3bc08aa5caf4210493549da1512a2faf138b856d5860e9c53d01fd0ba925c6afdf6" },
                { "ka", "d2d166f3cb1e0f89b572d61b9abeebf06b7b3856c78a840cf85f2776c4a0de5c9876e2b3e5b5a14611f0f30ad4cbbc4b2f3014686e5622115a9b52025b1f59e0" },
                { "kab", "dca4316199a55faffff5aac2951a3847f39a36ae7be616a5665d86622634ab750ab892658ec4f8c8edef73e3c6ad8aeda75c159c258d2e9371c1c145a2966347" },
                { "kk", "1a9b7ca4a60d11dfa8abcb761fcbd096ec83ff1610e9f8f9dce2a7257460bb874fee3f8b9d178036c97e370325d0e31a9b349009d07cb0a4a35d00b7faa45072" },
                { "km", "e84f425879843921a44d26cc0426993dea51b836bf738084191477574d79cece3bc87a1892030d445c5c599290aecfca257b1b972caea8f002645285bf45809a" },
                { "kn", "8bcf5c224660d7a0af7da9c7e337cd680b88ff534a5d1dda933262e9fc28e74b21809bf543faa4f14546bc8f395a8d0cdc74d4fa996045b96ce1cb31eba8777e" },
                { "ko", "f3432134e8dffc37032ebbe0a017c283e0b30339672211cd9f0abcc7294cac055a7863cc48e9417d44f591c7dc9359611237a3935546ceb7fbfb5efb12f52c14" },
                { "lij", "9a2f1fc6264ddaf1c3a016b6f9cedcc90d0e82dbc1efc598864861a55e03615a5f3269b018189457e69183feaa7a82e715a74ec53db76f93f3b419227b37480e" },
                { "lt", "f7afc29f48aa118ad535786de2c539bc87255400921b873f68b92fa0834a88b077ef110468d6b47a8c71d0c4f5e480f0e88dbd8de2598ad1e251763804947800" },
                { "lv", "786367466b02a21568106001e0af3a0282e7837fec2ccc28e13d0af468d00050f609d4e1a5bbab22e7150e7f9bb05babe75382857b71da56abbae6049450b42f" },
                { "mk", "70f05f6787047d6be207ccac23d356cd3241b268fe19558aa4035b2006f8344365dfa4a1fa6503bcdd2aa0c3fef44956e5aabd2c7e882453bea190969eb8c72f" },
                { "mr", "cbc8147e81c3905e94b09e6a267f571f6215d48d169a21e88d808b810037237e174e83aca8b9ee4df9acb6724922c4f286f55b42ef91d2b4144e72b692102484" },
                { "ms", "e45b3f4ba909558ebb2e85d12a72a4792dc0631eda69864f150a8a8e0a9dafb0ae06dcd9af5cde131f19b30105bbe801876e103e68afab8d099dc593bf07d00d" },
                { "my", "7402ea53257864762638125168a1d110ed77f29cd992db9b4a67973afcc07d399fbb7ca337dc7a6899260dfd26bd0f067fd5e2accd30d3084a1073fc7d2d5502" },
                { "nb-NO", "a8f06eb13819afbb8d0314ef90e4e7045017989c5d52f6d618d2383d3806da0d5cc4fe27e072aecaffee14033450cfec5a0bf9bee3950e83fe2ba73572f11edf" },
                { "ne-NP", "c70e15e243c94b3446eb637b0c39934ff24c2cddd44bddb05e8332e4fe7963ef8f9add444a1a9ffa3b808065d5273458f0c46ed5c049c81f44c91892d68f551f" },
                { "nl", "791dcff0158bbe7ea764b285cec95afbb6a98ba30b2a092e1698cc301205934080799ec223a7b6cf3d7c538473c543d678aec4606102f46c3d4d569960f590c9" },
                { "nn-NO", "7a53a72b2cb82f77d47fc3542bbc1f72ff280f1ee31bcdf05c7ae62bdd8354270b3700d4b6cfaac474c531cf8beac83502611fd4aa65aef97731c43eadb63611" },
                { "oc", "90ef4bcc44386ce60dde0c6b5cae63e312de50de6804e0fa11c2ed45b32ad91a2965e753b085815db2219dd1da09e9dbbdd9c24366c93ed63d58385971178769" },
                { "pa-IN", "7a0d0310ea3c5cd853b7acb89a86d38a4b02ef239dcf9d7cbca28db756931c41a81581ad67f2f11754ddf9ddaf6ca10428496809cc583b71ec7ee65e573a474a" },
                { "pl", "6fd5def45c6f1fb7fe6fc22908471021146c014fa5f5e10648c56dba8435d31f0220e1edc0107e7a22526064001ee04c85ff1d7961dccfc9c4ddbbdc7aff93ea" },
                { "pt-BR", "0fae971c5e24fd5019098abd95f717bf3dbfa77547f7e0183d48684e57711668422bafadd5b1695784e3058e4246f2a66696a322d33c6f62a2dbca9fdece2855" },
                { "pt-PT", "34587b06d3fdd53bb7781e2a9e3151c7995ab73849df170b6e34b2aeae34742e5a1ced303e3bd57bda660dd703b5fd1bb0fde2253c481aa161957aca5b9e6c86" },
                { "rm", "f30fb1c26a4c2794e5485e68c21ec09271836ade7574b758ff151f6b487f867ae1fbec9a5b6524417588f739c370f934c4ae84a75bb607f9f7536b95129f9ee9" },
                { "ro", "225a3f49a0ede448ed63a403afaa74d5b62728fc2251a80d78aa3c1b1127941c14077b72490cd50c7333ea570edc0dd5694ac32debae768c40046927c7d960ff" },
                { "ru", "41323e66c34f6b8cd88007c22631e01a14b65a6ff55358082b91eca72b61a7981a067ba262f63e5b484b4fa894c7df3592993cb6a43b7d697ddd32480d32250b" },
                { "sat", "33e689aeb20050d312d6d60b560702f2fdb004a447b3987da2547c0cd11b5ea25a41ba2039286e4ce8a00ef3131ab14b0d74fd075746e52f133c3c70be9e8691" },
                { "sc", "5799a4ff422c112f32ffc73bca5ecd7d37240cbde055f24ad824a21915497fed09504d71cbaa4a1ec1518fb5b4af42e139ad43ed4800ded09642cf5e8a72c5ff" },
                { "sco", "2924821ac082066cfd803880fd47e24f47b5a7174757d04eac52752344b534f4f841b7586a2fa69285b0bf28e358ed6cad287938b4450c1fb162c9607ddcbb82" },
                { "si", "91f094e7a88ac6c386a7672c62ab5ae9c67ab5e66900e7256d54a9cf765743d9dfdf8f42823b810f29282e2307abe86211ea41d204505c79bcbe91abd19a90a9" },
                { "sk", "6565c78fcd02407079d407ca2308cf5943c73cbf203a88b32f9c391aa31d5050bd2983a8c006d25b88ace023e3c1abed726b6ec0efc8f461f568124e41d37e6a" },
                { "skr", "23c9f0861cf2211a5d8845366c76f53d3cb8cffd6f0180334918b5f40698ff06e0b9311b7a9b529b657f74748d1ad4aeb7a22cc54db3764abfb9b0bbe8cf0ac2" },
                { "sl", "40bed2f4b28b26c1752cb43bb84384d9ae15c851bfe35a1052c34cce3cccbff0b2bf8b8682518fb3323a45d96c6091593621d6751ec6e9d0252cbd15aae3ba81" },
                { "son", "f98d9bb46b70e50174b13d98fd9fb2cbc28eaf8e058c110cb4fd71055aa265342876cc5eccc6e417cabc6d491dd1f2eab959df193294deb157bb91791e3e05ea" },
                { "sq", "238254ddcb14959d7529a0ec0b9ce67770891ebe7d2dea9ac763a9162a9ed6872e680ae339d99c27022ae950f7638b25246beb27a28c396da761419ece821c5f" },
                { "sr", "5d4cb93faf18adbc459f03243b491f011655dc86e9a2900c6bb4efdbaba1afd4183306330bc9e6b5f62d56fe2a688ba458caf141e48b16334eb7bd3b67d13c0e" },
                { "sv-SE", "48d09172ec87db14db8b20fb74d7cf8a725402c6a040b4c3f43d05b6b5e2121daf53232cb4ea0254421dd4f7325c15d3c0b4339cd83f222aa138d74c1c350d9d" },
                { "szl", "02fef2341a3189399ba4bed79f4bf848d7f3af80dd2a8e5d3c5a13e0649afdcb06b9fc2d8bf1c2eba70865ef31f705ed9f988765971294c3e1ba7956c8227984" },
                { "ta", "38eccba6e5b75d65e4632a6a377de0f9bba27b0187e57f57b515e2c254e22c259efc43b7012b09ec8ab0fec3dca8fc620159b4947121a60f4f45330fafef3c93" },
                { "te", "3ad087c0b281c4a6f662e4fa4da13dd903fa4e61562d645ea7970fed272c9822c2651ec8bd7b392496f38db6a0bc343dcec9f2f5ce89d006e7bb7db004d8ffd4" },
                { "tg", "7353449550f7922f6f623ca6ae86da6549662a3fe708ef0e85a8f7005cc60b7be884a6cd2d9c3411785d897a408f6c28157e7caaa330e56a3c27ca5c33a55e9b" },
                { "th", "950b8dca37d1a3411b87d320ffcc4dce222926a2a1a2b01266c97916020f8e1240663a673826eb393c2429c41a20a85fe4feac7363a5db2e983c538a2ba573c2" },
                { "tl", "a37d77ebfe5a371836aa9519a0e3b118fca55d448b799da8d224c845f20260946fe3eae2896ef0f8f35afae55196f9ff8ace898b77c25897372dda452d84b800" },
                { "tr", "97bfbf5b5e86aed7e477a4ae97c307d5dd7ae550a5262596a0f9dab7ddd1a3d481164c003b483874e70de658e71e74ef5d391448fb1f611e641d96aa44dae1d9" },
                { "trs", "80354cce8ea221c3c8770df1755de070077204925476eefce7c82093b422bdd33845317b244ca93bc2b8151fc02867acbb9d68c83ed4d383f23a3de9fa4a0826" },
                { "uk", "2e4f92512c35a543726754bf905986cc71801176ffda0c1285d8382290893646598428002c8f7b4c477d168700529a0f1d3addb8b9384bfef331af6f0adff963" },
                { "ur", "c781fd6ff53bf653ed911127e3185447452c97fd49c3c61ec4a2a0ed2055faa9b3a4ec40577c34245fcc61e0a547b2773ef6f834546f397666a14d0c28312a4e" },
                { "uz", "4acca9c86cdea2231b5b1c022c41dd113d2b4ed8d62ff3c969292ff9a5527ca19c56ada5baba71a93cb16c8a42fdc801ef5cc1e00bf9ff29b781978a47ad3b43" },
                { "vi", "f74a7e3bc77c28380ad33e28168042164aac472185a0a9c47ae445180e55c18b88b844f6538dd58cfeda05106dee4a34746de460676b997f717e2b16df3a3b9f" },
                { "xh", "b6e1dfc46a2d55bc0f2e5a0ae4239835d148f94356c7cffe03d4a36ff8ac3d9008fe3c7015612bcdb15e105f18d03a943d863f17b7183a78931bd764fd5a731d" },
                { "zh-CN", "3903539e8e54715646514c88bddec29cd06e3db217502afa982aca4c755de329deeebe34a05d2a02dd6e55f67f858162e4d4df9aa5a452ca0d6aa960997a00a7" },
                { "zh-TW", "d3c76c6aaaab12100bfa705700f8a93367a692972e35035173fd1cd509e4e7e2232747d84bf5da54d587aee18ceadb67db32e89f59f515f47c8bffa4e4f60197" }
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
