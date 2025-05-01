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
        private const string currentVersion = "139.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "25d26f3d20d72a3ae71a77ca05a96d67c44217765f2e0f0fb2230320576ee5e63cf215affccf10867baee0641b6da634119a3a6da1ff0935eb047e6a5cea4f59" },
                { "af", "7a6fc7e6c704347c95dbbd37205dd319022a3f5610f6fb729fdb16fdcc29f7e30c19a296aa7dfac5f24a25b93fa0772db894c976ad95936f11ba8e1331d42026" },
                { "an", "fc7931e277455c60a0d12602bbefe4c1138f78f46beb958d7f7d1e0860bd743b991ea9fc3e0b9980af6b826ac178dd5d8a21f4081a9a774d10668b22feabbb6b" },
                { "ar", "8547baf2a54cbf5b1b954ae4079ec75f0d84352f80227b98e814d8f9b0ed2a216e2706e0270b9e7d52805ec0822e65876b03738b8762050acb9d930cf7836aaf" },
                { "ast", "eaf404c312aeefa61547e0442a44a6180b04584c0462725fe15d9d07020aa7d07394af2fb0c5a96b7637979f2c192dd5dbd0bc320013ac8102d84014a4b30ecd" },
                { "az", "d31dccae54d82b54d3f247fb0062364118bfa8d8f3d22285cd4ff6f8aaae2bba7531b2e6825b36c29c156ad471f0c89447a1ef27848f4faa6771b28e8da5105e" },
                { "be", "e4b519f50cbb99620b3395e414d4f42d06f4d4b78e0f1189cc6ccbf9fcc66691213e29648ca746b5eb5d3c1675484c3b978924b19a408fb29cf61b7ca03c3e8c" },
                { "bg", "f786305bcd9f6c7ff5370abdd21ea7c010ccdd65a81b2f2c7aa607b613c8d838047c2aee496b5953741d9b8fbac6eeb5bacad4eec3d35d23fc16e24e1457e24b" },
                { "bn", "862286a8a5c60f0cb415c23f5b5b598ef97f522b5b170b55ddb76d845700a514d6c9acc41a47d22766fbca05958cde447805182df33151a5ec6b66110c092d55" },
                { "br", "bc293ae21ab4a9ba6f0e3b1842c23a28b4fbc62f1d28a65385c39a3e3a0804590a59a79550d014f8d2b5d1a1326d894ed790e6f660f5440c391c7a0f302c60f4" },
                { "bs", "0622536a5fd4a589019a8fb311d5dfd5b9e63e088b74333fea5417ad7cc39ab83349d2370a631ed224f8d6f5ab10f7e0bfd5108b035c96425f630fdb62227736" },
                { "ca", "baca27ab19fd8987b27ebc8d2bcafdeb68be89d0f0ab1b6f09aaf296a41dc3e34df10a6c29859fa948898be7b22e75c25bd98262014cf4fcb18a5cab7812d228" },
                { "cak", "37d7545bf0eaf8bb7c588c7bba0525f79629573efb358731fa39e4c582a0f518dff9e3f7432b280e13dcf95511fcf83ebaa4576fc057e4f64c9ae0cc8958c684" },
                { "cs", "656dd6ad9144daeef1b640fc865d164d4dd4b0ea99a5843c93297526b26195fd53e94d2806822d0e8da280e5c4d18ac8e816bf6933481d5a9fbc9c9ff5464016" },
                { "cy", "36a5452f25ad9e591948c47323e44eb599fc69a93e1046c461f15880cd4645424a4344f2afe4008c568b532f0481706d9c308f5c32884874995e33ba2d3441ad" },
                { "da", "160920cee87ffd1514a42a147cd3353fc179ff0bcb6b038a9962062bfa6651532bc253fa76b865454bea20d14c6ce1f4f06d5437a6c489762dcfce57423c1ebb" },
                { "de", "db877d48d1e9b181b3bd804139afe83ffbe7a1233a46a640e582ba28d197e06a561d5d0ac69d351a7c1b3136ebe878c8dc8344721fa17d5323d742ef6efe5a9d" },
                { "dsb", "b2663afc262c9016e18fc582e9fc938ddd012c5383eb901d19b73589555d4de271feeac769fa4b6e936fa9f2e46ef1448b59bedfca9c36a6453589738bdbb95f" },
                { "el", "31b1ba676b4a2551bb8795193a3aaa4ebd454f037bd12d3378548781fef3eb0df45cdf8284409128b53a72109a16c52392b0164e7040c056fa9f69cd41fd922a" },
                { "en-CA", "0fa857385866b1839284acba086e268d7ff002d5416057558cb1595887e378dc340bc84e1e8b4b9ab42d36048b452bf6ba4138fdf13c293ac1d9c264fbd6f13b" },
                { "en-GB", "2b6eaa62af7f3a7061d4a1cefefb467646f91e0b9315fce70870c6430338bfaec98599494257dcc0e3ea024db53953e0fc68654b49cbf4ab858a20826e8c9af1" },
                { "en-US", "78900fc98e00f9f767707a19768e52dc1b74ada81fe12efc3bbd6970e94522608ce1aeb550962a516ff844d6eb6a394c726281911535657e7c472f65f54f9a62" },
                { "eo", "43f542728ea06f615cecf3e91ff8ad496ff1001410d7343914fc09c55a4b4e13b94c57d5528d4eb62974ffad218becadaa3a152e136c97f54dcecc42e38a9519" },
                { "es-AR", "17a80493ad6573fc8252421f0f1e1e15800e932d96f3ac2bb14bc391dfca4403b92d89b81fb0a6ec47fc1d0f8e4f5fa08e32ad6ac235dce793acbc356dc2f84b" },
                { "es-CL", "427aa06ad4dd7edc77d25102ba3b241fefa98dd61d941f4e2af9de9df8dd38cfa32a3c7f88772c658982c1f04d460cc9938a4c3f3a44048e88cd37b6af0f40a6" },
                { "es-ES", "838193c314217a9f1f2da9e0775c9d74d5e3b28238af4e1c3ae2ea781add8a9bf643322cc194ee74505a41f7621468aa2db46aa5c0a61b7960b66954c65c9a77" },
                { "es-MX", "5569c1491c29e8891d9ad4c402aaca4ccd4302db8c52c5e2f8449ae066373bf48da5b4ffe77158f93090319339744a70ae6f6b9166d77db8995488ca14f1bb41" },
                { "et", "cf76add6425412ff5fed799feabef5fbc8e6cb65d8a6542c929a710c0fc142da83c6dc69509e4ed2a223dd1849c826723599a530677402fbda84a4f4a6d68973" },
                { "eu", "a630ca75662caf2973ff481732a8e0cf72c30c8695c0fd0631e2340b9bfeb79e313d4cc57188cc218140ec0549c384746fa7f4c6b9ffba3c1368b225f799e9f4" },
                { "fa", "24272d389e5593c1071c72cf0433ef5f13d458d519742ffa661251f56bea5e731050ec25797d220d8a99df7fb11178e441b90903d447af6b92e925a61d895f87" },
                { "ff", "ebd8a4128df479d72060ca58227b3ef0ea41a6b0a1e9edacac20c4e4cdbab161f83d6f6ba218df305d445b9a9b404fdd4f2cfc3791658fa0534801bc9de5e636" },
                { "fi", "53071ba5bd184c00b72db3478fa382e00d63e524c918a1426223f9efca65ea3dbbd48aef825d0ca5c43b1a9db7d040807c92ee18b52ad239b8d11ed01774368e" },
                { "fr", "62dbc4b9932846b59436f76b3607082e9af585f8a1cea95e78d0b0c497586f729f1abe5dbd89e3e16499ad4be6c421c16e04f456b6a05545371973389175c62c" },
                { "fur", "03a4ea4aa28ac31d9a811be10e07b144e34de59fd3fea530fae1a85fa97bbe72de20766acf9dddd212dc843c33255b1e71364ca47b7bddd9422399a22cda5baa" },
                { "fy-NL", "ce56365485fb82d246fb3deba592ad4781fd7e8ce034ed8e84e1fa5e5de6eadcd67dca79385286d322ef687a4259a320fc5fd2e3217ccd32acaf40cde8dd104c" },
                { "ga-IE", "ce62f082eb497b240ff6cc6dc0f25cf273e83bf87fd6a15a56331b8bd3cc384a223879b3a1dda507cef6d52e137f0b6c08aed924daec432c89055c040b026769" },
                { "gd", "4d2ed5e0ca088f34376f4ddeb8bbbfed3a9a657ec196df58227e0ae1d589e00bdb0a15e59c7e742178782ff7d48957a4b2df4a9e254d872603bca94e329c63e9" },
                { "gl", "edf5c6a64474c1e3c937f0523ab01e61da10ff6b5ef59d1a65d5f7cb767a5a7b490c39794fcc8982c069b49b8952760beb11e15f35dcf62d778e201ce2946a9c" },
                { "gn", "b7f40eef6357bf67bcf080e9215ac073a4b0b693fa8d6f25ee39c64a940b763cd6ab49a41d799dbb964545c615bad6fc2c07daa0420331ca1f19fda5b1bb9806" },
                { "gu-IN", "466582e004745806f7963441f7fea2644d6e8284f140e189fe60b386f603b9ab8b695896b257a3d39a0bba487ddfd383ab8fc48c77265f105d273135e798db32" },
                { "he", "8a98bce6b8fdae0966de7934916fa3180f233f9135d279608b57c874f553c90361468fbf488dba9712be75947ff285141fba592ae1a16b721fdcdcb294045d42" },
                { "hi-IN", "1d01543e2104cb36f2cee2c09fc19bcea7e2da4dd8225f37d2794d02475356b6f3eb0a4e25760e81e48b26ce7cafa421e4d5ec9e1b4311cbc116c7ba973784bd" },
                { "hr", "b3221dc102145fb4f4a2ffde1a9d86591351ab1ce810b851f650a07341a16ac1d79000d5c91fdc0778f47a983cd8dcfd612c6f292f0aac92cc98e3178ae81f57" },
                { "hsb", "bd1de0f6d121681be691a41f858572740d2fc9659a24d52c57ddb85c3ce1e2e6f197438be445a2f15e633413ef938321160a31ca2d4fa76dd65b445dd916000d" },
                { "hu", "028c95b6c38b25bee4c94da01fdc8351a237edc7abf1e18335afff70b1a1412983c6c5670f4b1f3bdc5f42d5d6db6399e5a39d71b01c0d8b2c7a2275add3d4b0" },
                { "hy-AM", "838ed689219f9795df4250c2e110ff1bb08319715f4fca94a091801244636b4054382487cf2c9c74035d3118705f8a66089134eeced19da2fe62c59c6c74232d" },
                { "ia", "e2692aa57da393de2897d231432957727b1cae4e72306061992d60dbaee6b379392614fed16de5bcd9824f2b6319d4251adb3e17a03edb7654f4e0de2e033995" },
                { "id", "f2004ba745a0511d0d40bb32f9962802ccc3235e2ab55e264e0900c286c684b28495a5f6516ad4a19b1ec008e842473ed2ea396a02b26df97c221fa421c39aaf" },
                { "is", "61add984a7db43e41d0790c9e04820c1deb5f79fab20537d9aa774bc9b06f274f543878380e7551df55a9a453d82e50ab28146ca0581b2500a916211d128f588" },
                { "it", "18fa81b5239f51273c9371b480a6b648541caa5b7fba3b54c3bd08594342a39dfb8572be90ae0d30e6822435c2762f74d263cefbefe0aed61a0c2b42af6e31c1" },
                { "ja", "90a918bb94a87fc0cf7b2f6473c85d4b0f0dd116157411667e469f8724ed852cea5e5bc45745fbff8ac7c69ef39de014a17efc61a0cdcdd2e5d303657afa19fa" },
                { "ka", "db5c594841260ad7d6f528959145bedc67caeccbec01aadb2f9419ec6e758c663cfa4c7403b52c0db2e9320067c02fe290ea7fcf1bcf9b4968ac926ce420b123" },
                { "kab", "05a07a1c0498fd7fe376898bbdb1a0f78d77677813306025b077800260bdac9550908a93e13750822992e41174d91cd21f8971c1aba706e22b00be5e5f2c7a6c" },
                { "kk", "0a750b99a4293902fbb2664d1e196cdfc5edfe038dca0d8ea8564d92ff2bcff4f0034ff66b78325c1345827411a20c320d9b6d9d752a54de67729eb7558d214a" },
                { "km", "a9d0519cbe04278d4e08bdcbc78c6c71939b7c96e9a69a2f627d230c84a3c29d8e8cee18d761d3a615c14d2c6527e46071f21e89f87f259ff6dc453a93c7f2bb" },
                { "kn", "74064f6e5994465954c567514e260390854922190a57a99631b9b6b2e19b49c3cc1fd8223c58e828ababf8674e4b711ac7e248d8c5b78c5a9011d0ca2d561385" },
                { "ko", "d08d4a21c6c579ba3660e56169007f701359a9d689e9eb86c3ff8324f15b80a0e58508f9b8647d8c7e431a0aadfbfbee04681e00b1eab573b28dbb909d4438c8" },
                { "lij", "58618c8d617be3c635c2f8f5307d24b164c08ef33e69ccac752fbaca8cae402d56d2dfbf3af4bb2b1ea9b1904064ba25e9db874a3b19625d0e8abbf9026ca1b0" },
                { "lt", "72c832fe56ca05c1014f57d44c4c4d52b2d86c4b260fe799a1cee51ffa1c1e2fade9ecb28143d9b0ccb3f1470cfdbfab5431893a142c977e3c78a94fd484ca42" },
                { "lv", "e5486c78ea1bfbd633a561b80876f76f0bb1cbc7bb97484c507b8a30f4ad18d327207a35b9fc9a61fba37164f182526d56a86ab5f56a9825f3b7dbda8f0fb9d6" },
                { "mk", "1f3236a12dd0fa4042280c3dc4f56e7c654842324fba76b59ac921ce731a93e967b768280c54e41a417db3fd023e6005fda24cf9ed1ee6694db92091bc1be1ce" },
                { "mr", "bf3b2da8cb97069e647aa8919e6eeec1b2e216d810b1ac6a52dda2a2ac305ef0e3d72072dff67a4b8a330b0c78a551c5c680a1a123ae978b236144d6167bdfbe" },
                { "ms", "4ebb73ee7463f699ea56bec7548ad5b7a16341135039357af794e9f5cd820fc71a0e754dbb4ecea8112b43ba4a44d31569f557b7e3d6a3ebdfc3eb6cd533dbd6" },
                { "my", "c0a9e8ffa5cfd35313adfd3f13b1b2d011b7dc7fc8f644ceaa0108858ed359a97a767d7ee13c7284a33283f3e7203c424d5013a8e75baf2e0b4c71331b126b5b" },
                { "nb-NO", "d1ed98b7b79068b710f7a2fe61016d82c77d56b6e0ccb2dde9864c71ae85d5e28e30f2b0b09c4de872f559c1b50c7c79e003b85899544281ff8e4dbb98e6f4e0" },
                { "ne-NP", "06f3adf19d53826d7ac8acf8677c9487ed5d6b596148b76f5ae86bbc3218617d221bd91af66ef659b5f2bda736c02481db7a63b40ee683f5ccc6d501ec07163e" },
                { "nl", "2bc38e5a9a9863daf175a7068adb2ba36a02b1b808d511e92023fbc77053918121b22cc09982985b296b36998e171c9cc109ee38be16ef5bcb25e0bae117e549" },
                { "nn-NO", "66946cbc33032104e67a77cd904c0a3d65cd1721efcdc7388ba437dd102ae7f34ea5add73abaa32348b64de27dd839e44b503821ca47fe44b569b2c6a3ce477d" },
                { "oc", "8b98599ebaecd1087e86682ebebc81831fc1a286e4f07b2de41b33a1245202d057be666edb01fb50c7bbbb65dc0f970d69d60b576966c12899b7643d453ab4e3" },
                { "pa-IN", "634f5f0a0dfaf9cc2dec5b7b7f92a90db0fe149576c6dc3c7ba90b3cd43e0c6faaeec7b70e97fd33c5af745aa19c8755ce922ffd4759bd91cf9db5c17e72dd7e" },
                { "pl", "a353602f995094efae3ccfa7984465dd8d503fb3376a3b8691e788baad334e2546047bc7526226309a7687a8d53f182e9e17a14b20770f174df0aae836da3615" },
                { "pt-BR", "f63e748cbdce9a5c51e483d05dd9509a012a2c274a09793b4fea110146316552e39d478e7b6d303dccebaf6c544a921f574545d80fce8a49f1b27968b957a545" },
                { "pt-PT", "72982fde22008fc69b979a3962cbc6ce2fe94cda2624f959aac88d234eb8b0130b3460d0f345cd496035e265775936ca88126b6ece404bf1c1b9e435fc850ddd" },
                { "rm", "b069c9ee19827602a8585a4fa7fb0b82d29e4062e423b60c70c5521c6bed64106238a6a2788df3f86d327c3160eef4910b4cad03ff3add9469d4b9ad232db9a2" },
                { "ro", "02de4f4887c28ccd4f777d4dbb11aeef3ff20ad68c0fbbdd58a669c72b8a73ebb672b60bdf0798cd232e58bc9f08efeb00acc9072027929cf5de65a569dc719f" },
                { "ru", "4cb4b5022b47b0b67973ef2007afbb9877b5f5bd3bc38c4f86fd3e040e1169d108ce438a431e09c4761bf41350760dd4b6588e6bcd2123659856a155e79c73f1" },
                { "sat", "9acf5855db05dbdcf3cb0524ab4a43d0e3dbfeac5b259c0ddc2c3f083ead5c22c0c8e4ac78f8f11f63bc92167ca2d5c239edb7576a22f67a6b04b305d5381310" },
                { "sc", "660e5492db16d1013644df85629197dc97561ea07d29f652ce43fa7d11b8950124b0c2b177ca91bc5ed561c9a6c0fdcbc96c6a6f28bf47839bb0decb9fc75334" },
                { "sco", "75845527b8a0a0b55b5afa24ffab53d7c3e849443d33c4426699dbfd8b3960348e1a43f858c49c7cc21211524cc154913bb7edf48a16f4418a5b3ef5a2e13899" },
                { "si", "3029873f212a082f1c6b10828219c135f7e2ed95166318c342ddba3f709df64ad41223112dbbe0c54f54dcea00d68c346cbc2ad3323913ff1caa6b3b4b765d80" },
                { "sk", "46c067af410a5653d8bea0f9a978dfac7533ebb82af24f71182df8e250c378c0f68dd5982a7127e0d8b80582aceac98f24c9b6fd99f556cfaa548270dc1b55a7" },
                { "skr", "940355e9a7a37692f8a34139b838f3ef682d421b699d799d08acfff9e9a12da1d7fb792c861af5c46f1f182129ffcd8605815fecf547c32ce0ef6a54f6b2a0b7" },
                { "sl", "3386fae83f8bd5a3f533402cb48a4925b26c8cc638bf33cab54e0123ba6f8579b8f3ddd688ab7ff5e50b57ea1345b348334ad28ebf7e902f3a273828510eb79d" },
                { "son", "71ea1bef533ac241962428c210f28bc36494db4f8624c9ac7b3d48162af7c456014e9902d711be0a49a8a9199197f66a8a7920af8caf0725c3f88d937a40adad" },
                { "sq", "df1b78902d53338d7fa837478615662033f4fa62bb82dc39a1d06f828d8cb66e8c4ec084509f459c0295c37faefd95ad0ca0fc03ed8fc3b2ef22d65938036684" },
                { "sr", "a8d165898b2a5ef4f66a16232233a378576ef080ff109e04bfcb1dd7d00e1127640aa7155f5678cd00d1a349c400e86df227fa0dac0af1b9d8cdff51a65652d4" },
                { "sv-SE", "907b0ab52b96a6334e18f7c87368b6d67af1faf3f3cfb233da01c22903de6d4911949a031c7591f21133317e8eba176aa6dcb880e5b8207aa211d59d83d82ffe" },
                { "szl", "d9e62d8d25d92868141d673677414438978f9cc350cb22661fa8d80de25ae4603aebb327149c91905e913474c57142499f6c2713ccf4cbb7d44a17bf42c3d6fe" },
                { "ta", "f7a50535715aedf688909cea0bba65feb4fd43fd870f303f562a1e1423de42f7227c009fa2cc53012d6d2a24a0095dbdec5be79e79349d5ed72cb0b311fb409f" },
                { "te", "f0acc9f9000b2b5eb82bbb7ba63f243469b2df02fa8c7e776f84c74ca04017a22add133cbb2b721863f21043576142383e8ac029b6d3ef302b5454481805aafd" },
                { "tg", "7958fdefc2c60ca41d9dc076d6d681fe8ea4ec09634353edbd4d224ac77799f9c6fe8f629ebe69d76379e36362f4ffe096a510628efa68071e2e83e5a3aff3b1" },
                { "th", "9d2392602dc6d9b4390dceae0123a2789d2c9db075725d119e03801f72d23aa211ec280a6a94b6a6ad13393891d19a328680e3bd19cc10cf5030e8ff81d9449b" },
                { "tl", "5b22821bdf518095f55ffd54dcd59f34612a37f3c74a0053940684bce50763f60f03f094e30774b3ff9f477ec2d2b8fbd00e34818016132da6bee1e2c49dda9d" },
                { "tr", "84c610470a21a6d129dd16ede3a2f7a12598fc6b25d39bcf8d7272669644a1cf9ae61abfdcaa6d38e569211812052b7ddef60145bf42adbe972238b798904208" },
                { "trs", "94bee66617d1533d26b725374d8735e741ebd304d5d7224f9cc633d552040e0820e98e07b01893efb9d98a629d6cee395b93fabbd84030a6b6c796ae4dafb36f" },
                { "uk", "b36f37fe466a2cc0223d930132b722f3668c9a4761a29d27d60d7c5a354b1293ebabbe4592c1d6231c53affc5ccd88160c4e60c26dbf9d25793e7dd261e0a559" },
                { "ur", "76f40aab34e5ae4cf97c1d6e7348b76b9dd37dcc7deedc61ba32fe89935802ca506c84b21ed5c3729e2d6d53bae6cd55f07d1b0dfc329cb9018a55059be6e9c5" },
                { "uz", "55c100a638a891ce069267c124f15b10110b47ddeeb513dc166c8a4277a38cfaae522968ca5b9ca7514a884764d837690e1c8cc5719e21cc8789a6213740e215" },
                { "vi", "484a3cd9d11fd995377d2d4b8531d4efd66151568aa411deeca6fbba9de4729ec3a7edc03e42313595d9a842727e4c8e1ea0a23015fe55b192478ced8f6d23b2" },
                { "xh", "1116d2a754731281ec838faa1ed3ce6cc9e8560b00b08391e578b4a0fc73dc98db27d6f0d23b6f20795c802b731f8ae73bc3d2856c056b4713ae0ce1f35c6083" },
                { "zh-CN", "9e112fda01e7b0bf8b39a1a03e080242a2d6f10f72cd234fbeb6e1486c628d3a2cdaec8a67ae998cb4cad2207171b14c7ce65757433705cfecbc04d0e3be561a" },
                { "zh-TW", "51af802e0275b048b866a34df21d7d1e83d492f2ff6fb2db7f0af8f38ca4673a582e439cac37355927d665a6bcd96f1ca87598b89b5b2fdd10f0662dbf791686" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "944ad41abda275a4f277c46d5f10473ab7ce6d3f26e07e3f459b8f5c014e4350abe74df6a3e321df3285d88d87e070866c3cc3fa78e63c68e18e89d4a99824aa" },
                { "af", "1d673596182516d3322b66dfd22ae1910dbd5e8428123af7ebbfb2df24059897bf0833c94625bd3ce70434b5866c3275a6be49db0f5167b2876566ff3df6dea0" },
                { "an", "e0cbc53be78706894888dec23bd5d0cba6a0100bfd49a2cfc0cdeeb13e7cc9a999d808d90933a4c6da7c359162a890ce4c9bb31bfbb469a46a1acaf26838165d" },
                { "ar", "ee7dd55b0d1f8016cd8e76de6b713d29444b4b7a01f29cd0bf9f8cf3b861f7cb9426f3e29aa998d10dd93b625396122992e495ec7aa211735cc9dcc29af0b256" },
                { "ast", "a3e60ba23f27d08c640baa64c72898016afd637df86597dde065d5c874581599eefe3761fa55291c1eb18ddbb48e2b26b7c3b05321ade687baf56a337eb0712a" },
                { "az", "0f7dc84b7c30229e717ebb7488c85f71c4cd010cd10492809e2cfac59f5af57ff9bce30fa6bb583c4024fcdc33c74f5e5a48e051bf904fc3b9bddea1117328fb" },
                { "be", "686562d92216def1b1aa5f579ce4eae227c7179e4abfc568a20526018f7cc5dbce84d4fd91928c48286acd3c421aaf7e5b914f8a0de7df6d7aec8cbed3a81f3d" },
                { "bg", "c1debbd5210a23a31280e7c484cffe8b59675fb22a11465a74e972f6f62bb717da0a087cc01658bc3c95c4b32741ab84cea7d710ddf01eacfaa9d13014b59ad5" },
                { "bn", "f76264ce08fba1de4cb5cf6e90c5e951a8604306c1e47316eb1e9e81f395f433c8b93e06c719bd37dd30e0ce1bfb438be3fe9db29b7937b099030b85dcdf511f" },
                { "br", "31b2ad7ed4a67a737cf6e12208c2062eb2d8f968b3784971c5cb98a4c11d8155a5ce89a064c1ac4ebb9fd6d36881f809ef2494ed2d6af3af9700361d2c5c101b" },
                { "bs", "d26b306e022f0cf1ce4e8657483a4a25f76a64a39b92190d99e944e8b86ee6820050a0418a644a420a6403727034ac54ba2c906e299b90f0821ed994a672d5cd" },
                { "ca", "18ebba12402e574bd8c8977f98dc40118c90341d476e77245ca79ee339a2a25002b7fed8ce5128da7979d5f5970a4d01525968059edcc5fd936ae619c8f159a4" },
                { "cak", "6101c513f1274822d39792f7b75a15f8c07682002ee7477ee56bc91521dd5e493f75f94001b80ed8d95a2ec5b7a5129094e6fe9a03b685a9fe549205681d98bc" },
                { "cs", "8965593baae4c6ea15aad5d1d5dbcca2d5014de542f33061abbdf383ef75ffbdbb57b5880a42cef109564428414039081ff4dfdbf726bc04d3681d085e3a62c4" },
                { "cy", "739b164d37feb9da11296e932137ceaca92944d8b527372e82ae8254537d6570d7259d06c6a5ef262ca3cc7be674b85dadd8e9c6d0455a48c6e2cb3617c89a30" },
                { "da", "55270694e4f201cf3f2421e3bf7233c2f27f5a34c84c2eca8b629454a02ec15b96954c4c80561e3f97d95b7adfee4693fb1ae2051623ddbc2b7ed77d7b689a23" },
                { "de", "33b370fad92349739a9df4372be26a65541160c0f14aa9298cd05b66629dbd5dd5c35e8edd5b49805732442c4b5fedbc93165c680e4229b0abeb9a3cfc2ba4c3" },
                { "dsb", "3db9f53b5f0498f08eb5f53943295bdc97b58c86a9242c145d409f1dbc93e9becbdd49e74d4a63ceca5a3781d54a9054e22b454e8661886d046ba64c1e7b3179" },
                { "el", "9c9910e5b2ba7347aa763382bebbe43bcb36ed7ba52bc4ad688d5086349546abb282a77f897cdd8f9714dc5ad0b2dfc24a2e0fa05097ef94da62a747d6d82f29" },
                { "en-CA", "b23240b389b0e9ecc5b694f7b6c88c84d71a0ea6e38244320043910e970935b67ba64d90f304c5cff4f3c3c51681961a7a4c155ded6dce75b624d4a4d9bfbed7" },
                { "en-GB", "4bf7a981b894305a83b3ec275d9b16fbbbafda066faf90091c227a5923d45ac8ce5f3b8a07b7a0309cf4187a972f5443c35af4966a00f2efd2e5d41fa9cae941" },
                { "en-US", "3e849111f448528a596e510417cb7bffa8f84d43a6fbbc4a772cbb75da3c1767aba5771d649752edf4c595c7a09790b4ed808defbfbef77bd632b8b7cd6a8252" },
                { "eo", "95c71dbc3f376a2fbdedd0e44477760f34c0ba7fb4e1ab4a344cbbfd8c8bac8be68050e75f555ce40722d23fa2088cd6155917fb82728e2d92400d764e68d735" },
                { "es-AR", "cb0821f7bb9ee8249e6c89dfba557f4bb08189b5d31ab3f6990f6ce00ee83c6e84f491ed6a93bb9f297c41113222bb7ffdc7419d86047ae343be83451b0f0ca7" },
                { "es-CL", "e01a071bfed0fbf99fbdc65235275fca355b8058efb786225a923e9d9054b1defb06ccdc642f3175328825b5d53c971c4e56bd4d4a89bec52ef430549fec1129" },
                { "es-ES", "b63a855dfd8fa5fbe39fe504da769c575f9535156c9b8406a11633cf9eb83150fd756558a09265855b30708f8986ddf14746cb9fb2c19e604819bc079ded3e61" },
                { "es-MX", "a522b7134d709354d63a3e6c2bc4def0cdc22841ea6b7d94280d9a265a2bde8c76f6f1775e87021b1f89f8ad91c10174ba6761382f3fb2dd0a5dc59bb412729d" },
                { "et", "1a45e252be57b40df129c9fee162d41c89bf24de1c7c10c3f0dbdb4719bc9e243199a573ed9aad423c6dd1297c810ac0818feda80d8060937c96dffc099d64d9" },
                { "eu", "5f936d6f8047e9f07371a651497073a95f22859422c1dc52068a0a7bb2be74f319d1c7c637e2fae9c23ad1c910c6e440bb13c91563bb15b508055a4e55d5a633" },
                { "fa", "1d9f639d81dcdb495b89aba691ce3369b3b04f0d9dfb479d038b84d53807b0176db1127982d7119d155efecc78c7b5614fc7f008ffb89858544d6818c0e6d2a8" },
                { "ff", "88d1fc18254b094a0ec581ec4dcfd741ee4121f6e85ee7635579c6fe376d980dd60e594592f2ea4ae33e4b7aad7da19f5719d6bd1ac8adbee660dfe62f544d8f" },
                { "fi", "69d25b2f382b075a75bfa611f5e2748316069c6935f2ef5fe4cbe55a2755dfc5db98ff8929dda3fbcecc2648002fdea7bf547c087a5b45973beb1171ac73381a" },
                { "fr", "a042351819f437c65b81a99658fc46fdb25d46ecf2cfd938438289cdeef027dff601bdd9ae3708878c940be0289980ffe95cfb2d96ec7dbcc7a711093cc67ae4" },
                { "fur", "f80bb7403f31005fdab42945027d3a5bd49d9a4709fa0b51fbf8db6185ad5f8cac0495c7fe977f8278a4f0e0e07174dd44e299b2b23c5ecc62b66a5ef168ff30" },
                { "fy-NL", "1e9d000628243a6602eb3896365bb5b43a038735d2685931ced9def7ca160920e01606c3759e0283b0836e2526054cc00d69e1cc9979442ce4ddbc08c06b1fa9" },
                { "ga-IE", "929a73442cae6465bc445be185a857353e255b41b85b5448d5f166f24f8e16bb7573092a03194b1bf28bbefac2fca8ceae6322434a486408aa4127c4123c3a18" },
                { "gd", "0c3b1b194614dea4d149f616ee1da513547265a59f21360a9eac6675a10483d6c270fe36ff7bffda6279c1811bebcab7c6ed13f617dfddd5467d34863915df39" },
                { "gl", "800a64e1fcdc9b877d3b7e37109ff4536ae1d6dea8100ef043358f567419620ab284ee2854741c06842be54e8752f4520450f44cb065e8806bc5aba0bdf2a298" },
                { "gn", "8fedac2c4a10ff5873d4bd7f9cd38b9a90b11f22e9a9b327ef583f951bc97c4d95d77d8db52b9598bbe80fd00450430637696f7b6fe6bb2a66cd423fa27d2f01" },
                { "gu-IN", "b2b16a8de0894bc4fbe3465431f05f5aa1970829e53475d503d6880da9bbd5d7e19545118e07613005726fd515f86a7690dac8e0f424d36ccdaa736ab19c46a1" },
                { "he", "9ce363c4ace88d78a6e6ce6f7a7d31b6a4e1ef0b82186c637378ae7ab31b5f453245b1bf54c4fdf1f5724cf7671cc47dbe9798936ac93c7958f05356776fea70" },
                { "hi-IN", "f72f3b4ac2582b7016c609bf93cf580fc68e79d40b84c4637129e6bb533c9a2f4ade312f34ff17530ea871d148732e8403ae5a53f59ceba299d0a705fed3090b" },
                { "hr", "ad5df991e0984ab360e2aa3af950c0202c97ef78e9b063d800f8bb0dcf756686102c7e9e3e4730547b4f2e746022451743a9e262cff11531f2f6ceda83f7eab8" },
                { "hsb", "b69e14f5ec9cad1693693d42d7b7c209160c0a195214c882086e52bd6ba80e77f2f873df8bf8ce9e178ed99543768e1c9dc14c97b89d04087ede5c8bfb5ae5b7" },
                { "hu", "8536b7065062c17761ce5ba50105657f0d8b83a23a81beeefbc7ba2bbfb62132ea80fc27234d200511e8b6b836d5f6ef61c814028eb3306291dfcafbdd124861" },
                { "hy-AM", "3075d6c775bc6fa0c7afacadb3f1513558d681c48e7dc71221c803b9f57529cd5b4f1c93c224894a0bba42257dc0f2259a93775c2a9e059b740f87b858c50df7" },
                { "ia", "a3aec3a22ce2552e21fe7c210a41cf5041689392cb3c74eff4ab46bbdb025d62f13810d293294dc1031f50fc5087dfc9c95fa59be2151a309e371768fbce8e51" },
                { "id", "4d1de59da79e7952bda37b3597f96159430288f1095e5b6727e57063a1b124f80d61561e22dfe4bcd748af0b04600cf5c600d1f32f20c132dd03ec9aefa246bf" },
                { "is", "12b2df0cc37d0fbee9e9a74103e955a0e2e2bc8a255d5492635cc4dc0ec1640e836a7cdfdb72cc2ae14a9ef80cb7561ff1d9cd275a9361a8ded10b648db3e0e6" },
                { "it", "e8073419ce3af35e69c62696a303b9269496924b3dd68a03879e8f175f1e76e3d903fe703ba56ab0c6ae250151e25a4b33c1f4ca8b9a27b3e115945b437a0344" },
                { "ja", "56c5d9d550349bb15ebf111e04b55a7361549beb83bd497b084996214168699e60b7241b458ecde649bb8a115afae0552e63d1eec0539f6c44a187601cd75b85" },
                { "ka", "ea23b2309e8994bac70a1038bf7dce1ea10389e05586a05c3ad141e2e1367569b3055ed8bb7de6fb1295b2aa11830e100f30066fa81cda7cd0a3cf40bb22991e" },
                { "kab", "92b88f223c21602be7b5107c525740c8a0973d88eba776227574528984abee416ef0cd662453c0427613921ebd57eec06db2d9c3cf21f06e75e5c0e3cbbee19e" },
                { "kk", "ddeddc41f41da81f79038133af438789ce32d9ac50e716c83319b70012b487ff88feb5720bacfb50eaf4d7c9c307355fddc2154a87db156ca6bc7c504c5c53e7" },
                { "km", "591e4365285472dd4c827ccbee667c1c5ba225ab22290706baac271db0d98377600a73f00ab2424266d4a9cba7b797b9e3e9c7895d3d4058bbaa57d387bf0a96" },
                { "kn", "5167be1ea05dfea9425a7bb4d164c48bf2d4d6cfe73bc1305771fb8b35f607619876a4610379323d86f1fe244957e11b60d558407f0f8e9b870bf95058845e59" },
                { "ko", "cabb0f55519d3f229eca469deabe8fe69f87ef8b53e75ff54768d75eab303b811156a34b7d893e97fdf60714403baa2cf3e97055206b1ef17e203c80c7fefe64" },
                { "lij", "2a62ee9a1b96f9951ae4662c9e775f47db9fff42fa47d55f2e2e31dd02e05ff7a56902050fff07137d584293f004ac143066284c80d46992743f45c5113cb37f" },
                { "lt", "2b042f3188aa33e8c34038d8e816ceb8644e462943528906db0af396a951b935a72e084b1dc70e85ee8ffc8c8ce8974d4952ded7df8af576b8b651dd53bad44b" },
                { "lv", "f2098f4e823dc40c6ab103deee0bf25a8fdff4baa78e94fdba98f96cb7456d993f6d3457bb18feb71fbee9eeb75ea7135bb399c8dd81f3d25484b1831172b0d8" },
                { "mk", "4a859b94628676c0f801833b55c20788e5e8ecf0073a3123451806b2a86f5b56d83ca684faf7388de5b819b0b952aacf5e833d5da46c75db1a8c6f90de07fb61" },
                { "mr", "3d25fd3c9742f73cab892818ea668d1e4eadd919e69cace9776eee0a6ed256c4b1cd9ae3774c9d7f83f7207e1b4cd4af93d2576609d64c68013ceabe43241985" },
                { "ms", "cc1b32f590a80e3738370a3a04cc2c48f100a72bcd1bf664dd3fb5e9e6b27c41ed852b0e76f9bb611fc3412608dc1a1da997190e04670a52f76edf511d59f7a9" },
                { "my", "a954dbd0a5dcc8a043ad53caca909df2df27ae978a5bbdd1651db6af56921431266dbfd551125d4ad1016b0a10c136572d39f926a3cdc827d3aa734d1e609378" },
                { "nb-NO", "82ed2514d4ca4bf671cfca397fe39c12064fb4937c584f588a4fe4e93aa7d0fba74c72058a32ed958803ac287313fad32defefb07bf6494dd041a4289bd84b25" },
                { "ne-NP", "6f6e0492194eb27a117804dde1125a195b56d945f0363180c4600099319740c8384840efe2cf1309d4c6783d502318ae61e1d2d70cbdb802ba559b3bd9b0ae36" },
                { "nl", "76efd20dd13056626d1979f2802dbe4cf0ded1cfc857a7b1ca4c8be760a9a3c55e9f6a0282b7d8e0e0687644188ef2b81e00073ebfe54e0f89f26aa6790a63d6" },
                { "nn-NO", "bd575b76d41f5feb5a2d9ca5494885f6911c6fcf7eaf4d834d28b7f2bb3022d89cad70af9a3c0651dd4281214ba1938c0ca76a4c78bc3e87409fcaa7bbfd62f7" },
                { "oc", "51a6ccd3843f883931a4ea8f12dd3b3cc20e73f8163c350f09a0e1e4c26d4670ffb18a2f2765169e1fa123dc22c4321660b5bc78c5a89d65246bb34b15236ebc" },
                { "pa-IN", "f5891824fafc941d3799f191f5ca816bdc89b55748f105d2e40a436ec6f292da2f04f2aadce172a858982debc55b100d2db4cf9a9ec90af28543a4f75ba6f396" },
                { "pl", "a64630d8738c57f53727dc82bd5b072ba0eaa8b6b717b701e8bab7e53c5d415eedc61c427e30f32c24a235a2d4f55f235bea1286965136bc7767964bb3221172" },
                { "pt-BR", "a53edaf1352cae32350507d73b2e2069f4b36e99cede00c96af2ce1114cd36795f5bc116dd50b8b18948a4cf21cf6ef96a18bd30c4e9e38df11ba1c72e44fe01" },
                { "pt-PT", "d7a134ce656323115010be315d7a57cdac9619415f09afe547e3e5508e649b1c23236d2f20438a1415a43e72a7a479333435f2bffe688bca5bd7b1f8880cb6ea" },
                { "rm", "06d7343daaa73036c76c348cf9545147511491ec6d6d12973df0c0e917c6594a4350a88e1944d8c35892c1c6de6b6bee4e6836a2ad6d8b2c13f441d1a9e1388f" },
                { "ro", "5b6a84a87e60347929608c91c6ee34ac639b72ecc57c358c4a988e7d44d1bbbed8f1614882413d96a4f4dd92e7bcede71063de0ba875d302895de42698c7940c" },
                { "ru", "0e1a361d1b620ae58fcbf9ac470f9c538bb255bdca38b4587cf057d1136e61a49483d12155837deaadfc549ce47dd2dd907532bd81c9ca9beaf1452fe2089851" },
                { "sat", "618e6fe3f49493cd6d987d11ebe6244ec813c16c088f0ddf52418fc0ad63518689319fb061f1fb225fe41ee826d7402829dea89ab606ba3d585919237eff5a74" },
                { "sc", "6c694a4289514fec15a1c98fc14ce0cbbe2be8d62ce7023354e90f88d425776f06a047aae42bd983d487d03e368a82460c9d1085a0281c86d02266961a970e37" },
                { "sco", "e7cf13db06a948aea217ae413ce1fbcfe324a0e5b9239ecd5255177ebd1270281c62a7325f9b87ac2153c44d659d6f0d59f3a19c0dbe35b93e4042cc9d785e4e" },
                { "si", "ade3570e58f4ea473257de7ae8a80af63c5dd74bc46971e7a571408516914997ce3c85557f5635380ee90b98e782d2d6fb5be0629a31a7b50c52a1bef1f41fee" },
                { "sk", "40822601a2cccb5412f183c7049c718cb424e1222f381f9640b57e5d3ab0991a354e2793a916a14d3d1a9e83246ee169783ba85b5c9cff8cc96556c77a634820" },
                { "skr", "ef7be3f7b85733b9ed3d6154f4531053782f72e44795946e24cfd95605c846f8d73075d837c0c2976d02b0992d4b673ef6325e5a32a4dad2ab78da04656962d6" },
                { "sl", "97b0f4cb6c3162146d3e7f66a2afe9216c6f9a89737818598d510aac2e7723126af10161ffcb627848f4b0f910a4188b52d475f3b27859d33db406fbf3a1e6ff" },
                { "son", "992ee62dcb347804dcc41a19eda6d40aae894fa087137d242dd0f3795e3dfcfae576762379f77e5c42d26cc467cf19909fb928c5e4bf0191cc2bb5156728c546" },
                { "sq", "3be7a87874ffe92adfe2ca0147757f18dc9bec28bc2956a68cd9920a77df4efa97bfe6f9f13f415a008f9d9f33b7f50635254dcd2f4eeec7fa4f38331b2a7d55" },
                { "sr", "39dd950cb5af6dadb06fdae04e3372b2297a072d2d84b947bebfb55549df5604c8d0a92947aebe51e1120daad15d9ec6109499398ce317a7f143f1304f333891" },
                { "sv-SE", "fcb649c4287eb3563df22baf0892a786ed07d1c30942c69078f2e2a5ac2aac4eda97b5bc9efa9f845ddebba67e37e3d7891240cdd67bb0c81bee1a53a7d8f2d7" },
                { "szl", "2c6686eb4354eaf40572327a0e6d0e410b8e293d942b34f4dff93f7660d72a8b1e6a1413bc6a5d35cc23e7771d9fd4b4d402dcf1ac3b334e6a411e78a1e8e20a" },
                { "ta", "eac89f1635146fa5ba19b4cc552deb097b520d4605c9e18fb284d1b510597030a4794c622537a262be74c182e74bf0dd4c05947d30d193654decee711af404df" },
                { "te", "3aa90ccfd451da9f1a829eb36195ccc460a8ac9dc161e6146454101cf966fa23322ea77fe45679265af4618c188b303505c6ad8a015c575cc1af64ca90b4f562" },
                { "tg", "cc72c9327fbb4fe62ee4979741e01879e3325da85eee2e0f79a1d0e53a75d0b186515a01de755736e3a56a0e10787f3c11686105de7540a02468f8f4e81fba1d" },
                { "th", "2af69cb4022b72be48f8693f13400275fc96c2405ca606aa066f29e9b2650f8489eb10585d69736a9e6d3e31cab664ad975c4b024a8f590108c83c7f184c309d" },
                { "tl", "a8e4f44f38701fe4fc425c38420c81258f2a9d973e4a047fb65e521d24173d5a0cd3e9cbd5e33924b81a73eadb70175eec7ef12d718063c4e74fad0a16da902f" },
                { "tr", "485d212ef06d6e0dd5fefa714d9fe5a9a58017d98854787f7b568300ec1d00fe650628e796ff5572c36ebd92b9def991a7c526d073699f7300ae2b42174b4ab1" },
                { "trs", "80e814b032fe7fe4a0df4089f594abbccc9498c8267dcc82c9d04874ec5d3939d06b3c4d5816941c49b234852bf77ca21ce4b184cf69428402e4c9c50f44f334" },
                { "uk", "681624a070659da6b99167e4239d9f0fa83232f0d5a1330dce069f3ef027338bf04bb8c95390878d98a43be0e2093dc590e54c3bf830a101af489d80f89924a6" },
                { "ur", "de94b33f49fb1a2c9987d8dcc819a74ee431776305b95f5e2579cc871a5582dfac3a2fd3d6f1fa1860dd45a43b2f1c316f0ff95d456dfe7c021ca0fe2ea46d05" },
                { "uz", "fb80ca0deed3d5795bc0f40d11e9abd8e34e09cddc1ae3b3b38f7cda6c12ade38dd6f33b6dee2ba8c2c335f74f688e2b76b138c3a4815da7d195981a97ab1220" },
                { "vi", "69e0599ed5c9221bfba25768695a61e9d7f3ee72eec0e034410a99587c04c222a7c0599ffab17ccf0ce114094c16c85a8e238182f76fefa93f71f4bc26fcc0d2" },
                { "xh", "7b501c11507cbb3250f4f75c471f756a45c56a1f2e13928af71c7ea4aab951eeebdba5bee1703ec4ecd434bb8d34352ad8cc58afea76389913267cea4e58926e" },
                { "zh-CN", "7d77dba3eb58fce8afed97599ff9c674f542c477fe9e41db85448c860d6a87680e7ceeb2d8109e38928a4cc1a7129c9225acaa73864694fc407237eaf171cded" },
                { "zh-TW", "1d5a4a7f078dac516fcb08b3bf8e33fd3f79c3ed7e9ea2919aa82926ade09b7c03fa54022e39c5369a9a89df0758e2f2adf32e8ffeca2b3c4d000d2f0141f0ae" }
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
