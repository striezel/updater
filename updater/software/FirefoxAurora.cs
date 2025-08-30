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
        private const string currentVersion = "143.0b6";


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
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "80295cc937fc22b9e828567f46f1c159d04937a8d3fa06b435fd091376592bab47518d283f648254a52eed3b6db51283795f06072ba2501c2f8a62b9a430e643" },
                { "af", "210fa4f9e0907f7f3da9c316d618ef67e773a699f7666595600d7f17f970d767fc6cc2193c5b9e3c865c9305335f39c8de21e0e17976fb9ef5668005367f79c4" },
                { "an", "cefa58224d326baac12d384a16f47f7d20a717e27d5a38b5e57b036324a1c9f3faa92e6d9dfb53fb68096cd7ef4365ae376f9943e87c51521342fc9e1f8f084f" },
                { "ar", "7ee681a492672af5ac153059dc83d4a1ce24e02eb64b4c78c011d98594c019f5d8a4e53aa3974c6d8f38319a7bce73cf2af912004028f9259c3528e67b38784e" },
                { "ast", "51b07e1f3ae3fc3068a2341af9e980383bad6e2e88defa444c677f3e34b35eff6d060413afcab418abefa534983644de101a4dc05da80cae145b303f880f9862" },
                { "az", "6e7a3b6f7c92d4694d21d6761e833a85feb9853cc088f7073e5710ec742b3b435df1a93238262fd61cff6e8b9fe428cfceef6a2818f923c869b137cd6e237174" },
                { "be", "28bf16503d4699b465be0111127a97efdd794d646539d643524504b70d63b0cf4788015edbc9da1e1ee6246546530f5ba60e7a4a9b8152e0bf09331e3246a56d" },
                { "bg", "142b474b319b37bd60dab82f344ab422fa5c08d33c5e0a515597730e31c4a5dc0d9f9798484262f9d62172f4bc290659677bd328b9d1ec2986268b41c58e5e08" },
                { "bn", "16bdb07a639cbf9cbb219c4e507a1abec1af0c61601597e1a3272ad68b1b8ad5cc1c317bb2cdde271ff628f7049c3d80e19a4179af293dc8ec600b6de317d8ea" },
                { "br", "c9236c1b23260c4904e1c0374712121be559aa7c294f5556d2247508ff7827e7a90b5ad1a5fc2c7f8995a62b9c3daf44c8b919ab70840b1733a4d2dde8fd1691" },
                { "bs", "695d2788de07a5e89d68b408dc1a9229fc7cc578f2df4011358e8c0e0a3c7dc8b896bc41fede516857b4eafe59a123da81ca366dee37f4f1dec10ac66d9ab1e9" },
                { "ca", "210a20552eb37bcb6b506b59d2c900438288d7e8b28143a08f05ae3a4f85bf6de0c05c5fc184e15234e0a1ea34501ffdd004744065b62149bf44b2323b7f0568" },
                { "cak", "6662f6f1423ee0a4670dd4c2142195e3fea3425b292df9052e64134b52fbc9141225a697e852597e2917c57f002eed2672a4f09b0df9e8b6e1823aa4c488a544" },
                { "cs", "5953b0a6aadde8089709181989910528107a212cec7059d6fbcb9ddce1afab7ba82a8d72b2aae7f41b16ecd923eb82954994d0fd99ff54ff4426486752669833" },
                { "cy", "593071a34b9e8c71a1f33401d68d154f091e5f456f07e98653e9808f3c63b9e48ce24f152766f9115921695308bde9a7e8fdf5c0a2da859ff3aa19001c0f5237" },
                { "da", "4fdcaa0f05ab0ce3651227890eeb6a849ec7c0c941a0e4db838a43de5f65b75374bbdb95b09a71498fffa9452957e587213ac72b2aef61a741d6cb7ef364b5f2" },
                { "de", "bf12f689e1ada7feee2d914fb22d67bf69e75f6fa8e128e18e4de0f672d4985d5530666185ff733c5d232511bff89a48873d43fb9704f1fcf48190214d45ae70" },
                { "dsb", "15e3a82ec4ed1142733fdde4ae4b535bfec2091df0aba91a872926474703604d79cd8dd472457049d140e542951d7781d1f2b663b5b04254cb93cc024e43ca27" },
                { "el", "c04fd4002e3472fac7f2729c43ce9a97d1d473c317cf8c6d3e906e50493df00805b68edcad7467fc4215fc9e4650e8afebd9935c219a4d19d063db066ebf01e3" },
                { "en-CA", "f6f2a43e032cedebc1878dce9253ec65ee321cd5482284ceab2941a0107e83e73fb677cc5a8eba13a7cf714a74633ebc3c880072dfa914a1e5e7d378bed7dbbe" },
                { "en-GB", "826ac71194a5ed3331814b6f5e1d53baad16db89d2d154dd696e1739356588bec1843ab5255a1d7aa1cf49d2a3f5237fb900a6b74b9577f53163418befbc47da" },
                { "en-US", "a078dd6388e3c6b01bac6983dacede39deb5feba6a53ca73840086f95449696ed922a3b33a5dcb6ab775f7d760ea80c332a6542a52821cb0b01ea16ab4eef849" },
                { "eo", "af1c4a3fb14cf6a3899948d47b0b942e11f9ec4058bfee32774c27b0f859a43a8004db5f4a3ffd34d563442ac587c3752e7484e958348f5fa339e83f01d6feb5" },
                { "es-AR", "0d228c4ba11c0cfadf6ee9ee1137d065b87c89a1b1c961fe643282b68b32e8d6a6c997bd06db6ea1ba42d3a15dff452762c55811ac9e33e634f8363766609ce9" },
                { "es-CL", "2ecfa21bfbd901fc8ac69fc63acda2e03f87515feb0d9a5a824a0a579211784505b85f08aae3aeb1ce955aa32b1d591f4bb8211658394f8f0643794de802672d" },
                { "es-ES", "36d22f6c151cb73da3ff9f81eff36405499e351d6831d095817824eb3a9b28ef7973ad64c2ee66a2c81dcb3cf0b5357319d260552bffca4ddc0f0838d5cfa6a3" },
                { "es-MX", "050b9e3a43f9a61fb5bf3a4284c4d75cd0c2d6404c0aa8b4c4625f0fa6f58284cbb210b18e0cac23b3964f33ada6fc6fc5716955738645fd0e4a0fe77f9548ac" },
                { "et", "fb0057861237ed85ec11ff3bd8b96c1a12f8b3be45ee1df1c8ca11808ba26610ea8fcc63810896bea9e146a0a195459003c4dd740c4e4fbe58bba5a31b665feb" },
                { "eu", "40fa10dbc960f6aec273612435a66f4c1830e75f40dc054411a45d025d1d8c8b273a174c180f9267da363fb2cbbd19f059d3a38b9e71cd2fc6c070d493df3852" },
                { "fa", "2fde1ef83e758f0772de16e2fab37a5fab0a1bb20eaa9b98dcaa45714ef2054be0b3b9ac834b82dcef52c757c5d10b5aacf589a2af412afc78f2369b1866d2d1" },
                { "ff", "aab254eedc9415463f48f3ec0d14d0b23da6653086b2011505b8c2297624d66bd9af5446e0930cea7016a45c8a23a0f6271a7b5d781aaeaa508a0f3488f5d257" },
                { "fi", "e749c19e2d001cea3a69e370b2563ca9fe0ab141f52f73fa2a8fbf4346ff0276592700d47a1a45b6d31fed84fff8d241e2f5ab4c200339db957cafd7d69220f7" },
                { "fr", "c0ec6086607d75f87796ec06a494fcca02205f2562866a47f1c624bb0406b4af07eec815e683b08d050d580712d743c4b14b80b30a2c1032350a69b62b890daf" },
                { "fur", "cedc21fce7f8cccce2063114550a84de2661314b18cc58372a509047895bab5a1dd8cf8e2882a3bbd85b319022dbac91a2e5d6b426b738f6e7ff6c40e0953a7b" },
                { "fy-NL", "8357c9d5ec52278732565b26c1992b44f4411e5af3ca73342e60a02d3160111c139e64225152ea7533c810e8e13fedf938f357b95c82ebb7a3bb3a03b3dfb227" },
                { "ga-IE", "952b84bbc463796b6764b285e7099e22e7df557187e1aecc9b672ef0e3753ae173523121ece096175a3a281a08b21a25ee4e0943da06a3db56e7834b8e4461d6" },
                { "gd", "edf04f5e706bef7dee3692c028db50a7f73b9abd3e628977cc553c627c84fb22a14dbf75566a7586682e4898185a0510ce0383831e843bd1ca5728c58143ad1d" },
                { "gl", "cf9bff1cd3c33bfb5307c78635b8e4ca8ebe07062e811cbb636030d18770fda446c17f5bfcce4c1513a97bfe0bcea665acfadef6f59615bae9fe08ee4070c6f5" },
                { "gn", "b3e2f1aa997200a5834535a9dc85366ba7ceb907812a6abd8d0eeb767542f9436bcc678ccbf035bba138dcb00bca4a9101c8421a9ae24e1b0275f92cb9736051" },
                { "gu-IN", "e9e031d047b5072f4a56cae0e18ced563a544528f0a48c878f158f123c6d796498308539a2b6cccb45eb5dc342b24ce6e1069483f919503d35f0348357cfa601" },
                { "he", "096caefcbe82c8c2786b5dae5223880964945ce511fb1de75203b4dd5034a742fe5e229941e400ca92a558795ad23fcc16dd853a1555d4bbd4b7953bfc34e673" },
                { "hi-IN", "841e271e0839d40be44c741302ef17770f03739d4176d7177f554c5030aebae2496e9fe05334bb77be8bbd3c8ddf7afd004ce658f7cf8bac45b9777029133603" },
                { "hr", "3ad0ff19f6150619b0ad08d1eb1523e490eb7ece3038854846c036587569705d858b1a3ed8133dd4c57fdcd2d200af7a7af3304608717fb419667c0ff9399efc" },
                { "hsb", "170f6f9a213c1b104d0abdb18162854705fa225fa4ecbeee4bf168c9f0e7865cc7d10d7dd7bae21bd481ab07cbde87e0da7c16c4f8dc9adf9eed15fa2d45479d" },
                { "hu", "e97131b8bfad62d0937c78ef4cd7a15a53748e261b5f00173ad22c78bead1fdfc4bf5976b88e2e4dd8a9cdc167b00062365ac8ccb8a08919d709aeb376b67ad0" },
                { "hy-AM", "8870437b7c324e48f1d2f62a46279dd80321e9538316fd9f746d4503d21d316cbd27655e4964b050b72b70bbf5647d7111768c74834822e90e4e6d38c64f14e7" },
                { "ia", "cb643d49eea42e4d027ecf8ca9c2c10f2f9356760f12987855fcb378ff54fb7e7499e7e6a3ad80c491971c64d64ad280d308d8e767b7e73504cb94a72a90ae94" },
                { "id", "bc5dc6ac58ec844ade44060b330212628642f22899907db6f1888093f14db1770a8893c31d528e5f789954ceea1f5059f049877b5a7301b4d308aab2c78f00ef" },
                { "is", "f5c28310cbcd4d181a2da1258dc5ff07d06c0c161daf3c19e08c8ad9028a518a1255fcbfe51b3772581e96b8df24cf1ba3085bce9c6623023c51593fbd9dc2f4" },
                { "it", "924abcb848b22df78a487608c1162d300e1e4cc925a7f597cdc2b41cdfdbd0d9d05b00802407b8d428958b3b6e4411825d2cbb59a2a8def75b84d1e98064b9c2" },
                { "ja", "5f12742c57ac4db25211d5b74d522a3b252a40e872443c0650128124eb85f2f7074f1b9b38e78dc1010a141f7d5928b9e521b0727d5d96f30f949c96f99e8b2a" },
                { "ka", "d329ccafd193448a57f67c1d663aaacc3f4adcdf843cbe8ab5a1c39c4cf9839a0881d268277eb88f4e350529b9c89af7801a0d86768031f2200b51ce5e237e9f" },
                { "kab", "1aab1af5b3e42266cc305363bca03e64591bcaa1719a2bcadafe79ef96dca17696b4ad0afd77a3d831a67598783372d1575a4e2de0dd9a6959e40a0669004ca5" },
                { "kk", "74613e73ddc7c19e2b0155b7c47c16029edbc767eeef470f322763ab38ceb75568bddae0298502ef4f716afcebcc40cc737f4b4c4db6bfe6a6a660e1ae2208f6" },
                { "km", "12264b5fc239e1f473697d1524e15ab686cec8bac3c2720b4ceef313ca04ae86f5c6dede4ef1917aa8e2a8cbe9aea1bfffbf55752cf9bf8743c45edd2fdbcf4c" },
                { "kn", "d1f23cb22e6719d11f2aa66fdc078cb145c88f68feaf4633a369fc291c2e6f146c731829bdc1f5ffd60157a379498eab33bfe28b04122007dfbaf650bc9f9bd5" },
                { "ko", "d8f03e7ef1405b911c7457a73dafa2ea77daefe55749fb1c9f43d03cf7dbf25e1557cb4c1907d283fa76578208b833318fcfb2b38cacee66133b55b62b4e35db" },
                { "lij", "52915bb3025bb759ada723f4f1e63c211414d03f2b85ae8f47e217f1e402f8c9eb2839f443d403f64f935d011da246b7011ed6492077add2e0a0d39010785a74" },
                { "lt", "0678d0472cbbf52e863d20a7df770217159fedbfad961cc5efdb6bfc97dd8b931169f0d80c697bd7de33ccd551d6ba8b0ad714cdaaedc14de7f791cbbc0c9d2a" },
                { "lv", "1db84c20322f6d71838c55c7efa24d8d8ea883b41417da681fb504e13cfa39b4f708905d768d360b344bbc44a4eefc717c40fbcfd4a6b81d584f6fb241d1e246" },
                { "mk", "4eff40399a0723c64274b6719492d88c6d942da6b204bc8c28705297845544eb0673727effa7e8f21b326e1d43918c90f20c8d67e0631052ac2c523ad32277b7" },
                { "mr", "92746f3331b8e6480253e356152ae4c271437b53147ab51efab74a7b881ca572dd2cc23d5b4d5cd766b14cb8e80dd087a600b7b75b06b89d7ac50503ef31ff19" },
                { "ms", "6ed7e9c08d7f5a129626ef185feec5424342e06db37eff1778df415337ba64e2e017936bd7f7ccc192bdcffe7ca3d1a10414e15f5a5a9dfafc6c81fe9816973f" },
                { "my", "77c55590e2c21ae011982a3700ead5d980991e5d7b6caedd32226286abf98b36714a3301e112ddd5fa0b9c708e1aa7d6834ca52d6d57fa63f1f0b2c56694546d" },
                { "nb-NO", "5eb57389d9a5dac602d5c62dede7016f873ec0f90bf3a1bb35f6ff585b4e58cdba59cac1a26d42ab5b13e7fcfacde563f7f190a55ec3228dacfc706576948e19" },
                { "ne-NP", "4540454efb7dbe76bbad9df664da09064fdd5b24864b31e0935ef48f20d51d5024cf3de028c2d29dcaf59115dad23cf1f306dc0108b9929eea2152886646a3b3" },
                { "nl", "231e0291e140c5377f24c23b67f2e4f03ef9ef8d060a4d681e4101b2b7b895cd2f4f812753d2f17e9c70fd5cc39718aef1448c6dbadefcc33070ab2a8d05a97f" },
                { "nn-NO", "06902cd7f26267a661057e1fa18952197bbb774fc88fab21de88931270c63e0b230961f3a5c0d8b15c351e9bc80d652d04e6320e1287367603405f26f3afa39a" },
                { "oc", "bbe784f82cd1980d613006c1c53a0cf006e7ebe8e86f369e6cc2dad45496a543a8805aac5c5e22793402267aae973cce682efee18efc0cc5d8f77c5838f85110" },
                { "pa-IN", "801edf637c3338e319af3cc6e93b275e1d642a0f0519195228a8ce20d45f39f48941718388a4cb8861a0bd6f05f323151d098a57f9f4b0d457ebe788635f276b" },
                { "pl", "c0f75e933cd2398c53a8f7f456340d598d38b2980b9191388f95686c5b95a36f4d9b329644ec58ae547fa5a85bbf62f8735462f77fc5d2d6e525bfa2d24f8a7f" },
                { "pt-BR", "c5324e123a32fa3c4521cf86edd4c0413fd4bf619aff93ef97c92283ef28f31ba0ba9cec926d8ef0d5c0ae28c0d6ddbcbd38bd510cac521d70128164e408ad30" },
                { "pt-PT", "c595aa610492443d9f8bf0d5e45aac75421dc8068ab2dd52227299e02b80d01050c6cd84c484ad5a965c2ed51b97d3fc58becb101ad3becc4ea9018c4c0e62f4" },
                { "rm", "8d898310f9f4523b98a62df672201142cd2e64a782a90363c525ea37711981ad053a7553cefa75f82aa7dcf69da1038424dfee934bec8cc502893364e84277eb" },
                { "ro", "5918212b94fe740820ca419a8fc41ec8e56567fb031f69798f7017fd8c32e52de3f498fefaa24211711665799ddb0648c3bb2f2a42ac911b3487272e8f33ec72" },
                { "ru", "26375c547d4f3f741782a720d6ff969d4821a5c8b721e52dcfc7d7e7003a3f891ccb2f0eeda00d69f23e833bae3114f1494cd9d1843963a08e675d2858ce8c27" },
                { "sat", "b4723c58216ca19a5c34d6cf7853756725ec69f2d2fb67b317db00ceb45c1018903d77afecdae0c6b3c04b544359b2d72e302226b562d354e9f2caefab4f734c" },
                { "sc", "ad12243fe5d41dc4504e9b0fea157abce5e533af24477bff94631cbc0dad10f606b0b6b05bd22b81ee344c2c6571a08445e149bf630c5f4ee64fc13cc4ff7534" },
                { "sco", "e9e2c0be1c2ce517f6dbd2ddfa2a80ec5edee3b75cc43a3e45ff8068fd1638f59226e768061992a2eb404a59d75fc0d07f52edb002d403fb8212872f70e11fd1" },
                { "si", "4dbf9b87fbe78b55b6dde365ce12b86e8a84412f2983d7dcb82069b682c6249c522e457b3ecb2ba03e9d0054c425778e44fdb8ee2c95b0b47dc8dce4928e6f80" },
                { "sk", "e703695d38b117e74cc2729d3902697611ebdafe19e7ab0689cbbedc1ae761eb62e8d73616d48cd0fe431edef74f6c37342bc86016ce63a52fc935f05c33738a" },
                { "skr", "4c8fa27a0f4a38d7afa02a5bef607166b509914508b0debd04cf84270c1c6b5efc834cbe2d2e4c94bf9b7db520f329d863c57bef74e0c8900e4256d0b4cd0774" },
                { "sl", "88f03f7260d902156a2c218bea37d0a8e2567d30be1506039148604d53f60cb5f91eb431d2148df6b65286d85fa895d9a6be27d080f4214afdedc7d640768fd9" },
                { "son", "191cf3f64a9819671b60e8d958c06ee7190f1efd439650ab000837b958263f323448c089eee9aa476a54f7176a2dd96619e8a454e1ca74d2a5b112cbfb45cd97" },
                { "sq", "2ee203dc0f0fd5a5a49d32934f311ee3ccfb2f46abf06fe5205deb8f9c9ee95a648c3ada4bd506dff279064b6389ece7296755bb187df75d50f0585b76f052e5" },
                { "sr", "d386099af82460d17ae213bbe1d521488ce84dbdfc26542b930875ed835b909525af30a86740859d9f2384f76c2255011db8d02b00697a769f67333ed941d30f" },
                { "sv-SE", "a0f9e3e653994476143284927cc95415ce9f0527a52cf8e70416a7bb3b6b16e3ecad3b2c7dd6962bb16eed94ecb93f473bc8fa225c9b081715744a0d97f419e9" },
                { "szl", "b612ad88ae1b5a4c8501dca379c7ad851940d61a866b9e6bd9d5b77f1fa29c44aa545c348450d1ba99acf10075f8912c778772ea631e6fee6be30ed5903a7e68" },
                { "ta", "921bd80d3e042a3f57598924d215a9c81e13d99ad5eb35e899c9588c7aa8eca42af945c5f9ab3dbd96b187e3964acd667f3899afe46ae7edb65c6d71bba6db5c" },
                { "te", "f3209ccf72ae976eec6916097bf7dd3a92ad354fb7d614a23b554e159fc2c5055769f22ba80b1cedf6811b2ec35f4e59d19162f457e2cd10b6846255390faadc" },
                { "tg", "9ca8957b8e819d2749a69cc5c7b720869f91e373e1eee9fcb506056c068d0e30023c6cd4040afef68799f201b985b06af3dcba37b3b265603ca2cf00780f3ebb" },
                { "th", "4b240a8914c695a4f0295c8556160ad53788b947dd391210a72d3da3b54b29aa9e6f29e340524fd6e1acd32254246ecd0ba5ee31c319092645fba89fd6a66fc3" },
                { "tl", "67042a846b3419986566a7dae243cf585880ad4e5540e752e4168e080ee30fc185c09353ea2ab94b42c2dfb5be5841c63bf34bd0569c72f73d70c15aa78db665" },
                { "tr", "66950ae907792e7366ac3667cb6928879750ad618634751691d650b1d443a953fb161d63bdf5078d531d71c3c4ec565c79fc8aba2eb5001226b7cc17153a6301" },
                { "trs", "16ff03bcd4326414246045eff16449722ef42e294b680f9f74ddc3af9a0322a1d78e65d2a54d9a4ca52f135817a2c80057bebba4de3a068e01716fe8ceaa058a" },
                { "uk", "fdd4174952acade5461ffcfb122986ae0c7a482097a5d7af04af7f68b28ec72569349c5963065a5f0f2b4ce24a25da2721d9850f83689d1e8817ef8e041483f5" },
                { "ur", "671716b104809d8dc76c681ebef922744b801522b840cfb1e0edeb8f815c47c883b9cca3b7ac72622bf7f9d04cbbbe12ce9e58285113bd4e7afb3969e5f69c55" },
                { "uz", "507eccdf933d0db8dbdbf403a61499ee0ee3ac78400ef613c8bc1bd64ffff773d8c6a2a5b401cf4fa142c0fdd5fcc4d0fe0a5e344f3844f664ef509876b47223" },
                { "vi", "81c8ed5befabdefb276fbbc2f2dc9cab5e6a57f1572804f368757eddcdf0ff82c72903f726513a9f3beef62a74c85561d0322031def9c2fe0e0f6a85e033601f" },
                { "xh", "8c46e5110c943334065fa5d0eb307e45f0384ebd453b090b13b2d9f11a607ba324563f99acb8238b379b23b808fafb0df37491184ebb9dbf9020030aaa60b9f0" },
                { "zh-CN", "6c037f8ac06f8545316b3850b2bf3cc408d183e5edee23c6aea8d6927d260846537743b3366cbcfd383d9b4d1ef42d400624d48c4528a08251e778a70b70d904" },
                { "zh-TW", "01f9466f162c70a886e97db75fac1d4c2e9537fdd0fe1028b8d4ba2f1385cedfc0e83765e465bbfd745cc44762e327e9da12848cf777f9ddf0d61e261b9985cf" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ceb8ea30dcfcc29d0bf09323a42b0263c1cb605e4c27306012149a81e66546f2bb197d654925631d63792efcdf2ace5d02beb769a26ba3f68a73d3ae20c03632" },
                { "af", "8b0b68bc6bb4b63fdc00646d3a1ed11d6f699422e4dff8a8b307e8cfe98837b228c36c4b8165436e2dff73a0aeaaf7300f36088bb93598ff22b33deee34e1f47" },
                { "an", "0f105b1a89db5456ee47d02b7bf4d30ff801d82a36af68ba532db3a77a7b9abb99d7b9b6c2c52e4ea3697f1a72acd45fa480baf4561aaae6efb8e0197258fa22" },
                { "ar", "4cf8423a51f5fa3e9967e06a27cb9059f919b47f716d7c8f124d803257686d699ec9b328991fa188a26ceb779c15ecc6ab7742517ba99234f73f229d743ca1c1" },
                { "ast", "7affa3fee0e6a317ee7bd5bf4dab69d9c712219cf4254554763443d0365044146e0f281160d01c79ff10fbf6ebe969587c00fb45fe1cd05f53d9e18a9cd7e99c" },
                { "az", "0ebe47e974a2288e6ec657dd12f903b252965707c44075b0d8946a71a83762819601ab26623d1dc0f747069cf46b114c6d99b113baf063cbcdbfb36917f58b55" },
                { "be", "ae6332e2e39db6dd228f8ca6f6813b73d0984c61bf7c801c88a466ead6eda7cedccb8400c5dc35347eb1539e2369bfe5cfdde638230c38cfc548110cfc8996c3" },
                { "bg", "907138ba7d07c0d0269459f019e41e236a2cde5e7c86dc36cf1e70dd7b6a0537b543f74c1f3970efd246a40814a031d92701faab2f91243d4467a7005a0ca4fc" },
                { "bn", "8ff0053bfb211e993239678b11558f4f30ff9cdd3d8727502700db6e89bae5db6d829165fee225280ecd23c41ba5db095fbacc7e8f9e8e994b141e8215d92ea9" },
                { "br", "3bd9edf1bd44d5e6c4e9de4fa49d662bb3109a7dd562344f6bc9f75751e70e96a4bb5702353dd301d460c49ddeb90e5a5e3bd6be015edaf86752180038614bea" },
                { "bs", "e633713aa430b89f38f6f3d5ba028cc3a58f842c32ca8dbff1ad6363bed3ecae53362af0048a5c16159b439c9b07215af8a4f3df186f6222a72cc915d7e7ddcc" },
                { "ca", "b0c70ea94f4ee8904ce9829f60c7495d7534e29077b0b4d009e31a65d86a579e3c08e16770bbcdea3ee5f1350bb3520a399a61301cd65be68cda1d0a0acabcaa" },
                { "cak", "8d4167f946e3f215c0901186fbebf9a3c047e5e05f01d9d0c2fd65ccfd671b1f1c493f569e87c3d48126870e162efd64179e835c22a9b2f61770f240854d3138" },
                { "cs", "4a043171eb4c7cefc6dcc568b50fe936605eea634f3c1b7f940e41b462194881162afcee841f3af07271c2ec576089645f800c5cc5c7ee4268272f5912c6a52d" },
                { "cy", "e2259b1ba71635fd4543eda41b90e09c096e82c8cba5aa10bee87da4bc74f9490f6f23bccd4287a6c995b702a2c691718e0f7fda3b71a00016b4b456c4e14ac6" },
                { "da", "61eef752033d7af70ce3e3286842d23b00ae419fedbc02e4fafcdca162902509435d4dc5a61f45277e3564a8896a5d34e51bb81dd6c7c92eb5983ca2b6a2cf6b" },
                { "de", "47ed51a47c342e2f463eeeff05bd434f1b62826d9bb7da65116838f6e6ee3c2ef094bb619619062e59f9cb348dcd50409fe26900abda3458bfa6dd5b494e537d" },
                { "dsb", "d7cde3cf3e12afe56427c5a9f261586deb265eb3a35562537aea80d438fb6fe49622eca6c6674eab9b93569f19ad651f5e342616651e5affc620e32ba25d07e5" },
                { "el", "35e666238c2c3ce967e4d852975747be24d4816c62add16d793c05212b3d70a803e2d94011671f3ad1e5f3a51ef57a8a7d8f733b08981384486dc068ec3067e3" },
                { "en-CA", "05c40e429d0dea6ccc843729d4702206c9ddc9e568471caa6ed8e4a0ac1ec49963ef004d8dd6b65c8fa859f59650993a011723e0d9ac41c72e1ced6a9b7bedfc" },
                { "en-GB", "094d336501ec3961e65fe6eeccb375a8286d19a27b46ac2d1902074cd0f958d58ce5554f245144fa5a42bbb7194b861b3384f1ea01a1f17b165efef80abece03" },
                { "en-US", "f3735205e123c10747ba43eb84abeb245b06da0f3eee1bd1e0836ebacebd1d272b6249b7ff18e04d7f08f1d50c0afe76a906a24aeb90acf3e5ab6a4615f0846e" },
                { "eo", "974b4d9e015d5f53fe1feb3bced4b0b7dcdd7b51b063433a83351988c0a01236cc76ba883a5e2429427e8873224bc2aa241e276d0d9260edb21f68806c613073" },
                { "es-AR", "59010e9eb8e69966a193b7670fc6d42fe179f6458148e99b86c10890753ea1afc9d71323d795fcc5d8375542df3372e812fdbed960849c8f4146478bf506d9bc" },
                { "es-CL", "e6a51219c5aabe492e303c25f063cab6dba896ec1fcfcc0a316b1911c9290239a4a2593ddf75ffd5339a770e0ba45f003a3db67acd7d2cbdc06a051a326f1be8" },
                { "es-ES", "7ca7903930341abf35fc9bb380e7b39912bd008cefb3445f48633da62a530ec15728ac30b23e852ddaa0a751264a993e0562685ea46e4aad17bc41b3cb980efe" },
                { "es-MX", "2ea6db288e9232d10a253935e5ed939b5d7caea1735e17fd1c5e945c471481b0d28623fda7f4c7017d56371137381742bb9f80e1609f3d354fe8009ed1c4820a" },
                { "et", "3f52ce8ac25d5582009f7a2c3db27f21f572790cbef498b795ff15b76b4b59706d6d3f1a7b1a7bcce3c2f54897f9da0bc49fd928c630600a01e143543013b9df" },
                { "eu", "9752a9424ff8836281426569491ccb65cc230c24b27f7386befcb97b672d814dd6055944c55cad0b3650329f16dbcaa065af7be0545670cbf0b147b52bef7ff9" },
                { "fa", "cf2edb3663f67afc6ffea142b3be5b1d3adf2b72eb00867fcb27b18e166355924dbb8e0f217c3078c0d8b84dfa6d0d765ec1e27518a10a9fd01cf6e95da318a4" },
                { "ff", "43f19799ad411d941e6e3f618e782e57fdf8c9b5b4ec1198e137c12bbd4e7d0e5eee40a9ae87b775bead4d61c2fb12c4fe4dc42f79c0982a2313c6dd344b6304" },
                { "fi", "7ac94466a7e3b0e8d5bef017b9de969c44e231e1c370ce397b2c1aa5962b360162c25c93f096d8b8b52418ac9d67fa951167a390de9542761db9b8582fdc7fff" },
                { "fr", "32335242f8a5aead0bcdee7bd01ab368760a994a685a308dda9268a874a5d4f8da311df47dcf4a04bcdb74411743685c039c51f1e9be36ae8a6c22edf4662975" },
                { "fur", "b957296f296ee9d65d181e4d2511c9be1ed027af1778099c37bc32fe3c9d0673ced147a89cf0d496d2340daee8736c08a596fe15a969932387b9b4ea02d40000" },
                { "fy-NL", "84bfa59e420737191a8efac834db2f3d79f434acb328bd6970e6648a90a9e0f8c51b2f88ae22b777acdb1eddfdfc5eaf355ac737c84f75c7031377cabd4c2dda" },
                { "ga-IE", "8c235c363799f2a7218dc8b6695e97d5764efc8c539d9699b41295c68963af01be3af727f15f425f920d6ba51552c667015cf43d8b52f8bbf8043dbfff948171" },
                { "gd", "098e641f02696c2bc993d1ee059fe4b69b386fb0e3597fe426f3d85e051d077d8c186eb59784f2c96ffcc9c9a764562a4daafff6cdc0a42321086e8fc8a88b3b" },
                { "gl", "af75726039807efc48c4e0f83b461b93a26d91152fbf144197fed865c813cbb956c3f2c8c80ae19c1185bf4d68d6135566c77307e2c0ef6b3315f6d25d3bc269" },
                { "gn", "bfefccae6c61e6cf3f3453fa78e67ee6c0e6f3df6847b7b797f4529ea085e2803aa597634f5c29a5a0490bc1358f59f11a944fdb555648fcafe3900c72155b07" },
                { "gu-IN", "4b8b4979f39e2ff9daeacc0007c1b3191d2a9b4c0af8f6bf0dfd944d8b1a93cc95e3fb4d1b101bdf824fff5f17fecbcbb38e772d47506ddce65b835b7546d173" },
                { "he", "4d1ccd0bb023852af06d73f4ed711e648e530dc2e249abbbafbc6281311e8160cd94990c48acfa3b40159ca6021bef2144864308bc261c8a4203e7491d08659e" },
                { "hi-IN", "48e449c85f806de2ce352312a2f79ace6cdb80f351e4b46d600b553e225cab6a01d9e6fcdb4dbdc4aeb5cf16e073bdbe2e1285bfdbac8cbb4d4bd33866bf947b" },
                { "hr", "ed418cf2dff8d7641877f07beeff1dd08e5813cd63fd1125497de02c7599701dc8a6acd4d768a1ce53572d25b636d8a9303fd918ca8d5128d99cb7a1af382cbc" },
                { "hsb", "7e2d3127b0786cc96c16612687027b895f14bccf3c370bdac58ad57c27fde5402afae92dd95832705ce1942cbd9a629e17703321522c036ff31c9136216a3deb" },
                { "hu", "38eeceaed9562f99d5a64edaf1b84cc2fcd87d687334953d6e1cd8078da257a50eb88c75874e1ad90b27a620708d24fea59eaae31ebcf0075daf392fa5cfc7ec" },
                { "hy-AM", "1e20cac2d9c243f0387aa67e2d1639ac126c1bcecd84d00718809f9038182543d893f7a9a353f3e7253392cc821cb837075a3985b1b643c8ff4cefdae497ecc7" },
                { "ia", "559d6a2a54a858344eddccb7fd860effd44e7a5d9f699ca388500a29a0404f574dd077217dda33a54dcee6ce2252dc5bf04a5d18d561a3cb2df57d009748f805" },
                { "id", "4c815271f6de2849655fe3ed03d46d74b7355286950f538dd92fb03b7a9760e060b5a8625c8c40238616b8c25c0cb4e0b5fd7b2d8b1abe06fb7cf3220b58c34e" },
                { "is", "f5fe021f101391649d776ace44ad5a27b1b03630718b354a1634fa46ca746c2111946c7b40153ddef9c14723753d567fcf4a7d513d580f9040d7b5440a60e7f4" },
                { "it", "c5e53685491f4672c2b148420f7733879b1ce3634f912b2c67d8663b72a5c735a4c62fa5e21d9aaadc237b7c3da816bf1d69a955f9b95a1b32bbe28b1b026773" },
                { "ja", "04dd6281d81e74c49d75268902ad5d22aa065e5dad347b26a4554d4a14c89cc0c5ce5cd474ce09bcfbbf3dd0c74a52bd4743117854af6c6d03e22957a0dcdaaa" },
                { "ka", "83401a74fc259722c87dcf84cd6773a93bfc97c099616316e9417e170542eab38e88bfb095e230330e101d0767cf2b971e78fd5d2667f934c276249eddfb607a" },
                { "kab", "3280ee5b6c83fda2c4be577108b70a7c428d87aa75afd33dd59b4e144c6f275b7d7dba40a92d10786b328266b88700e4740ce1fc9efda00dbb4c95d7dde2b62c" },
                { "kk", "83825b0117038aefd8f1972798af56719c7a73b0fde637d4b4bccba6c3902362b4b58b687bb54b1e575f383a9c3a8eb87dd56c67a43cefee9f8f059b29cc9929" },
                { "km", "54b7429381625820271630576319e31b1592893fb583c6e4e10defe3df939d27a83db8430b69490178393bb60414c01fc80b73e4484d5f016321c59fbea824f1" },
                { "kn", "2857cfb5ca3140536f1881c667b5eb0254ca7cdc3ffd155905f918f4ffb17c79ef25f35d2e247cf9af609a12042d444518f5c1e214d6d9a32032d26e5f3ab993" },
                { "ko", "f0dbb439ac043b1cb82c1bd5542951bba7d737552b367621ca22246dba3c4de994710c49e09d5ea0a77a12e57438f3547c819dd5b040a8fa8de94190b600909e" },
                { "lij", "cdbe20f1a6fdf9edaea8374cb080681744dc47e87737f0039297a2105bb2ba38d97f26a4cd2091c76b9cfd458e0d2f5a5cf109be3095c41efd5283aa1d0147c7" },
                { "lt", "b492e5b960bbcad9feefc137649939eb2b981b8bf58f56091e6d56e2f991277ac31bcc7ab7081a0b6bb91040265a9dd1a59abc03d78b625efa6e30d384ab15d0" },
                { "lv", "eaf91df36525be34d157f01d4d8f87b0037df4fafe0ecd81f24cf629078eb3f646c30fa6cf8c6556715434b6f082d3e39e4333760d07c1578539b99b60df9742" },
                { "mk", "b0021e91dd327322163c8c443087e6964c6dc3af285a67cfd0a426462e876b26e9beaf0d1de7dad1b11e1a87e309e3d3fba55fad8685cf61bb1e5ccb617dbbce" },
                { "mr", "26166aa03e0d0adfd2019acb6aa99741d825f31cb388d44ba228a8b65792d16e5efc49ad099b66dbb72bda8ee5461d4e4c15c887277b587536820ca1fcfe841e" },
                { "ms", "f9274b2a3b753ee7c21f899558703faf6e8e817cd64fabd7385d02d59fefcea891ff9c1da93aba345ea92e9a2c874a1bf8731bd44caf7b57f70dc50ebaff576c" },
                { "my", "f5f4a54479eb1dce9340839e25f46553e43f93aa6c2f437d3a5803d4538a55d360742b544e1ef49bda6dd381c8323d4830401b0d6346c0bcb55b680086024ccc" },
                { "nb-NO", "f11f8cfb217c2e815bfd5072f9b9bd701629fee54f35c14d16d6c93ef8119283066bc3fbf59e8075c491a22226832a53cf429bb8d2203f80b8322c2d612652ab" },
                { "ne-NP", "7cf090d72b1e89d8e16788c800174a765c755253a0d8d7d10ef830a749f7150ba13fb04f8f8a6eca279fb91bd275ac609df9397b8d0b9077291173c03688554b" },
                { "nl", "bcee9f2b3aea99db2d14c78d7a70e1f5035488203f7b82104a6f2bb86e5b4908feea405e16522cd28340b502fe3997ae4ee0cd2c3f69a92ae26df663e327954f" },
                { "nn-NO", "c642532c32c99ceefd2958accd177a0caa253e6a62feec64c02b35303eae9209478f5f7323038fde23a02b94eba18cbf4508925cbf34080ad0dea8aad2969c0f" },
                { "oc", "1594518f9705fd1528400a2b4712540d51b32eb3648f5b6524ac09def0108025536b6971b3b44e17381d4df8508da55da09d655c8ba63cb8aa9dd14a8912ab01" },
                { "pa-IN", "d1f1907b99143e0e2f81ab53fd4250fd7c3d662f4db2c96337b07878d8082f32d9735986df4acee085532600fc451cee5d23c455037e1c0d090ddd9781703c76" },
                { "pl", "48721d03696098b0a8483adb7b25fd87f86926b38b04e29d9448b1cb5907d2514c461d1835d9ce0f9762513b9517bf3446c8888ceeb8f0599bc4368a10e7192b" },
                { "pt-BR", "e4ccb5522c912fa44484ca8cb41b813a0951f79e7b4351d6781244459027768e643b7dcaa379443d420568c70de184b50075cb6611b751d5809af462b0d71e39" },
                { "pt-PT", "1452d2b90191776439bd629011f5068d41aa7551b973bbf9022331512a8f87a69ac4e28d7af56ce933541614018264973709fddfa68bfad202eaf555bad96735" },
                { "rm", "b37626c1fcb7a01711757a5be4966efc6c0908ff2dd6bddf5f1b07948734f450be6c0366a7c57112cc7bddcbfa43646177e4d828db95e909a97147ab2582ff7b" },
                { "ro", "477a7e77876bd4ccf47a11c362b4c7cc467dc949aacbb59ea24fe403c824d346499ed3f9c8abebfacf898db353b4a2435231c84ff95cbb4ee2339d278c2b969a" },
                { "ru", "ac77dd4379ccb47e50f207331eff2e6b096cc86677c8da2bc9cb6babbc176856e730fbf5b6d39f94939b77b162de048829b83fdf6224c767c3b9c5846c3b0abd" },
                { "sat", "be14fe82b4ca9ba62b503ff4b86a824b08838a7687864801f60f27c75532cefb1bb08a1ec180fac62b4ccab8365728578ea514fff5d5db80563fdbc75eba43b5" },
                { "sc", "874fb292389da51b03f706ac52382d1bf4c49ad02cbd4d1395a83c0f86017884e10947fd2f40b661056b5d07e26dd7b9b44e0277ed78452b42478ef6fdd59cf2" },
                { "sco", "5f21a56772a4a5083c4f0dff70f89669373d5271fe0d43bb8af420194976f9df997a301e7be6f2a6e210d3d0e91f1f31ab4aca278101f442a7fffb7a51be090c" },
                { "si", "317d166d4bb21909dbe1cd366bd271189df231acecd45ce199fd0137d06394ba0de6dd6e0ea150706a6b8a730c17e43c5abba73ec01473711f9c35e102c656e7" },
                { "sk", "cfdad538214f2027694487573ea33086a20e053e6723b1b7b4cbd3224d048d73caa9adf3791a03f275f6077279cbcc551ab7fe9384467175644dbb30e1383045" },
                { "skr", "38510459ff89a00ee5a249764faefb3c82c1426d585530ae2cd4016aa6fe72d406b8d5109fe41d8b7cf9c3e5eb5b98e79c22a8d032a6b5cd19d2194cda7c36cc" },
                { "sl", "ea400ed9904b2d6b91dc8e55ab9fd340a74f87a0c1fea17212a426704c3764d2ba54f561a177de522b656724b17d1af013957aa0a61ae95db8bf351b647c9977" },
                { "son", "4fc252525a7982363759fdf56ba75206ba462b036f1c0a4f25d12833f3e4034ed9898ea8b60200aa46a9f754f6c38426312c8584566b02b292b96ce0a8f5bab3" },
                { "sq", "2285678aff87f020e72e7f16bd30d6adb78fbd6a1f9fe9eec46b7ac39eca0915088569eb19c90d1eb912f6d2efa1bad048544b19bcefd5b93f3b5fa3efe22cd4" },
                { "sr", "014a485244d8151f06510124c98694d6ee3c51b5a41faa3d3aad9670913407d35e24cc29a064e7923b4298f4bdf5f383f57b992c3b32b755c43446da910c57ec" },
                { "sv-SE", "875903dab29ffe5bab8e0d59dcf4dfaf1806735db365ae0c9f81e90712e68c27836f673cf1162713c890d2afb2ab597ae909eb3ebeba75ef221e3a05fae05bad" },
                { "szl", "e50c05f8d325933e4f395f639538f875dcc62322a6557dec417b88423ebaf5f9489703329e9736764fb3de0a80734d1b74d1914fca4374ec37095fd30d0eff16" },
                { "ta", "26fbd91894ef44de03d4fd1babdce2952c6c78a77f2c518f67a2d57061581fac400970182b401d44965060d4d18c46f1da0e7ca15a4a051e0551a5d35441ead3" },
                { "te", "0d2449bb39d7f63854159b4c0e2beefcdc1fdc144ff1982f8a2eecaba4f5bb1c6980dc113140089977c68f3f77c614e814230636e2f3425a0739299c9ee176f1" },
                { "tg", "afc0ae0ef66833581f3e05013949d1c95371c2db5d1478b4034369469acf5676c4d1a9cbae8f7f5a58aee4c361c07ea03a8b4cbc77d5c194c648c39f953f1abb" },
                { "th", "8642e694a0f50c2449af1c092943b36e2050206acdaaee4d5eaa746dce1dc337c96df37bf415e1ca07c6d7c35bf88dfa73fa8a9237f21d571ebf764f72196285" },
                { "tl", "b952357b5923d6dd55fc7459c5bc3860470a7a6d7a9b4762bfe639593b397db82d99f61e0d5123f3841fb2b4e9dd67373c6e483dbd30603e2c5a5f2c3e89d08f" },
                { "tr", "5c68b82a7e6821cf3494cf378989c00941811573f7da83534154b6798310f3a52476a8bfbe2e9eccce27000e1cd52c29799215b7826f85b86f42ea6da17ec204" },
                { "trs", "07a36e2570ede3c7766a654fcfa774bea372201eedf5effa46b11acefb1490ca470f02067cdf20b0b42c75e2b1ea9eeadaabf3a45b35132b227fdb45236b5a25" },
                { "uk", "ee765628d8a0dd6c296f8a5649b597a2cd31f94be8f5f6f2df292ace35962d6048f643943f62e8be67e7ce7519c36b08898a62e12509dbe094241e35aa4a5cd0" },
                { "ur", "4d1db94f3e6c9b8aaaf25bfffc14d509074365d3274b13c852eae3b9768aa017827ae85d05e817008fbcb32d74e54857805137d5010b295af6aceb72d3e45664" },
                { "uz", "4f15baabc31cded1ba83d65c1b6184027d08ca99c4f35ba48c83768d5b27efcd0dfb072b80b4b7a6c77d990df07a9ac5a0a7fe045268a5aa7f641b1d88565617" },
                { "vi", "0416cf88f97926557126441fca013046538272c678ac7e363101e81a16db033fe4ce8b36d022d1c46c03458f732de260a6f1ea7e7cd3c8dbfa12d52a554d5c72" },
                { "xh", "17c0383819f967dc571f6711552fdeb1d00e70d3f5e29c1f3c751a6ffd5cac668aae7bc68cf70db4be901fce53d94d81c61e92708a257d06983a4c850ab58b9a" },
                { "zh-CN", "fcb48d765150eaf6a3b453f338af45b394c923a7a03577e0313c3f8692f2fd2e91acac8b8f92956df7184dbb8ba956907db2bd07f94591186462bacfbedff88d" },
                { "zh-TW", "7496a06e76b76478465dc938f2b8ccb6dd2719f686ad17d471ef6d6647dc2eaf78a7775da0241a8aa7148796c29fc9e0cb354e8dbd4139399ca43d406fdae1a8" }
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
