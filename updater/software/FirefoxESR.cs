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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.3.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f19823cfc2931c4c048e5a0af47dcf7d9a2b6804b89f2dd943f639a9b634b94d11520496479e3340a115b6cbfe9d19c0ed662c46b05aa4c31cc2d016d40591a8" },
                { "af", "608f7aee5043264ef9ca0fcc95ec212906d59ac865b1b2c3f5667885ce086be6afb24c056d0d8d84aff2e18c15b5743a8a2e9d69ba1c0c23ed31aa8bdf762348" },
                { "an", "13efa99cd5808402ea38c858399855b80ddf61a32b1020f2dc89f7a76dc0fb92676fa0239b9f249883a1db579bbe1fa6b71d04fd5ec3eb652fe43879f6c99f56" },
                { "ar", "2752ffe68df759807ffb2545186871f4259859a65f61734801928220364818b5836a018ac8216cdfc40f22279e775c493a101887fc8f494262b8fb35c2dc74aa" },
                { "ast", "66253bd333615e18c0e9c212b60f38c9cc630c349372c0b9297c476207794fd2518447fb5c589caa1da76ba736a32a2ac8c62a4121480c3cf779b7bd72e034cb" },
                { "az", "77dc597aebb88edea2e3187888ef3b14ea6803da62622e2a2befccaca32895ba66a3ea73758a0a9245840eb354f490e4589dc7fe202c467b0806be7a467fc1b6" },
                { "be", "4850eee0c7bb0a1e4b0ff6fd79f7623cfc04c9af467eb1a897f4e605b38d1dc2bc7b0e6ba658803dfcb95b326649d4cee7257dbb07428ae021d0e6290b757ac9" },
                { "bg", "516fa7ffc08a6906118315f77d3250475d5e14220185511aeb4ad95489e0a245a2857eb9ee24ebcfa6b9c36dc7694c5871679cfca7942b459bd9869e7e113087" },
                { "bn", "afbf124ada3143a8bf9c010c8035eb6dc838c7d683d0aba7447e24da1b8353dc108097b6b0e8238c6f6e5cc943cf6e4b8a55de9371fa8e595c55e1bc1325d238" },
                { "br", "097d342d046fa37f38cf2de62ceeeb6afea400a6b8ab6d9989d48a1bfd8141e48e71d04a97c98b4364ffa6280df54e8e4f0ef362214aebebbf51a8446d961f48" },
                { "bs", "282b06b06203dae3d8dc2ff15acdb67ed01b586ce74698600ada69e245b8b3a747c501b994818cf26d24d03e7db7e9bbdb8e44ee1aab035c9a93e0c18afe8b32" },
                { "ca", "d52da77c33774d3fbda421a417acebbe6c9257fa16a9b9bd8b45d6465df9f0a531ae41549665e88ed2936a2dbbefae5a9d6bf02c6f1a693d715bee3a5c1a478f" },
                { "cak", "14049506e75d4b35a5d7a91d8f63d68dada7e18f2d9d4d9aa39e3fd7dd46bbf48217bb3a0bff5d5af5dcfebe1f7cb97459893be617bf221ebc34e4e81acd2136" },
                { "cs", "c77254b94d429eb86d0f0218c17d78a76c949530daae3fbdd1b809bf3ed3f1b4b8f6436ecd18d31017644b3e6fdae9de15f06ce1a7ff1424a899aea99d23718a" },
                { "cy", "d7c606f31aedc3aa7695e251ec25c2efea88fc8a4a15b786d729a37095fa210e709c4480bd01f673d186e2d2661005472e647afebb73466e399b5f7783def908" },
                { "da", "5ba1e408a67ec6a4682576d0dd82278432919ea8def2ec6db14fd13b00fcf4049ac63de649a8cd24552e3674ff864353f90d945804ace08df0b0c2875e0bbe3c" },
                { "de", "2e0732e5a7e1ccc750d157794fb3507a6d9189e320744ade06d93b4c2e82c8d31eb0cfe32a2f86710e332b467caaeb6a5128625aa256104899e5f9effc0f7f40" },
                { "dsb", "5e4b8df9cd55cea47e1c7c5c31a91d4e0e486c4060543e0baf5f45038f1152624914e81ace8f184dd4ea505e8a89622d330c2c5cb03d8fb9a4c055ceebd58c49" },
                { "el", "f501afc118dfe8a9917541efb1b9b69cae72482b50c62345092eb5d6ee97641970644558a623d57f939562b9ceed181a5b28999384e1132644efc5c8208fc1b0" },
                { "en-CA", "9ba9de66975df938bb8d0cb459335639ce96f1c041659affacf5dd110542ef122192bdaf6e7ef9d8b5e8114e5927a64ae304fb3b39aad4df82d65ffebd58a5cd" },
                { "en-GB", "3ef69e8133e2d37d9d4f2603084fa4d92fa64e6b74afe475d6074aa30603b4d5f0c77abb68d26f097c63bf324d9f5e7c910f5c14fda59fddb5ca0503691242e8" },
                { "en-US", "ee5115e22bf93c7c953ed082e65c665d8b65c3726567c368c2c5499f58d7d46bd8eb9c588c4ac96eb5e2637439982aa37d554ae36a93c9a12c88b3b90bc70982" },
                { "eo", "031d4f73f7a01296713bc4a9e2156676f94ebe103179d531e673918a90fe474b1238e33fced24ed6cfb2372ab24824b13a6d05c64ada470f221feeff3ea86f63" },
                { "es-AR", "04fd60ba42c2fe5cebcc8ec9979f010a1ac9ffc39213fb0e49f55f316a9076ae12fc5bcd2d468e8212ff30d787660b6767763aa7e70a2a3540663b1455b6ea1c" },
                { "es-CL", "208b3c411496f3fc3c876600e60e44535b688212d2d7a364aeb454e76e46aee4c2370be7764817b69ec972b73c3d9224e2a7fedae499c4f051ec6f3f81e4c22a" },
                { "es-ES", "5e5383d8b1ba65b9f8a389050e8c9a56056a07c65c4b3718190fda5f2e1bca3fd12ce3b9a8a623ec068dcf7439864a2ca73d90b798d0864800fde277c36ac005" },
                { "es-MX", "fe55cae3c719dbcc678a1a186e64de19d4f20739681bb53ad8becd438125e790cbea783fe98788b21028ded1ff612192c45111022c504c2f6d9c93fdfc808e6a" },
                { "et", "555214385c0acbff36e111e10f186dc94c5fc845f6f777def398e1f62a3a24bf9a164d7074a3e0a8b407d9bedd8976c2ec5fe2e4f3999a8e9e1369e5f600291f" },
                { "eu", "2f449b37b0a33307dc8d59b448bff8748ae04cabc8310b3be006282ba17a84a7460385d11e2e9e10a4f0ef88177785c0b37a8409a81d673416b7a5308e2819ea" },
                { "fa", "6b313f4369f2da8622ef7b3313fdc30b259fcb87fb5d0de82aed2e2cabfd2ef2a37e237005b2eb846d521e1d74d93d97cd4cdb3e9e7e9d402a636698a0bb1473" },
                { "ff", "594fc6204652bb8dc3a2170408eb35b12660064b13eea4946237e9f4fe9fba131d2f1956d5a36374099792af77d2fe655e3c8fce1fc967a5998e213144cb7259" },
                { "fi", "0bddd0bb594958018b17a28cb3f20db047a9914f2c37b6d579054d024b7bb23f9524ec66a7b57581e36c58d52a48d510010b3f9333de466b4b6b80fd57ec9aac" },
                { "fr", "4f03ffffc00714c5d27de6b53505e4f4670f440f4014eeb3862d5ac67154e37f31c50648a41cc202373c841c19cfb25dbb898484789354dbb8b4f22cece60d98" },
                { "fur", "2a3e41310bb7ad0d539da0c7dda04cfe1cb3c1284858aa0bc24f6b94f29d085053440b18fb8572a449856f83f0434e080855515137954f91c0bf4ffcab38770b" },
                { "fy-NL", "23ace42849f1f18ca73a07d7e47521249bb6ebe97da16010afbc521077654e9c2fbc20d0c7521af022e2b8c92f320841c4ad0e3cb574fd21472bf282b63ca0cd" },
                { "ga-IE", "2b0508588161ff5fabfe76f67b57147f19be8c1e2a5900138847aca3a83a27702c6a76ee3323e195ab29ccef638704fb9e25c7e5ed93392df0e1ed7d52db2c38" },
                { "gd", "84dc36476e5b9bb428b2879c11e2dd524c77557712659a5c5298c2d043381aca71ef477a354f552c7a143a2ae2d0b5f286c001affee322ab55d531f3cb740d68" },
                { "gl", "4a2676bf88f405fe8ea82fcf84e898ef5d227fd50bc5f1579a1e07141c2ab1868d7f7dbd32732056139a1e1f74461ea021207d1a55032a0cce073d9e23d5650a" },
                { "gn", "3e4e9ae2307dfdd70fa845a95b8c6e633154886f32de08ee62e57920fb7dcd482378cbd3f791d6c12b446ea160135bb727ad30b9b6c48c43a5c3b9099ecea82b" },
                { "gu-IN", "aba311ed3bbc41b653ab3abc84eed9c7e22d61f37593e357cf1b5a4ad6b03cc2585b8592195ca0e9e7518fbf00ec463c24783b78ec5d6c34394040acc00670bc" },
                { "he", "7a1578309fa30d073495ddc71c35ce078b57c22865ddfc54293bb6bf6baedd20b957a85a9ee0cedefd5cdb911fdf2200fc799386b4ca996d5f2d0501aa32a9c4" },
                { "hi-IN", "0b9fc33d5f485b78e356bb375214257850c38b11c44de6297a5a11e4219eea14c1e0686301b60994d315afc69641266ac062d715a323f7002d8c8c5901c6bf38" },
                { "hr", "cf743c83a8dd9397404de266b4a5d5cd69d176c6c43500755a531405c763b9b1477922f274deb6ed7fa2aa3003563984d192d8e8f8d70e7416f19f210e21cea9" },
                { "hsb", "fdb6ea145fec20666b4a608fc0cf1c1b9a4beff7d94d9ddc1f60f66bd50b20ee5316c5bd56c310fd1c3baef044fbd7bcc9994954cca6f2c643467ea0945c1b8d" },
                { "hu", "06a577deb388d41beae0d5275368513b4fe6f5f38e9166d330d6f3b18098340e93723b812d04b2dca29ae0f00769e5829fe66ca32c66dd4e865ab994f09f2167" },
                { "hy-AM", "b3885416e8fc6e0e6746e76f2f6135ca0efb851b2186b116a5380094ce01b13243a282f07f54126c8b286dd018e120c75e76c6467983fc7007936329755ac3e5" },
                { "ia", "621afcf06ab129654fd699cede11e05baa02c352a19fbc9216f9b4a9354ba5c7597f50879b2b9a3c9281107bbfcce94573fc988f4f3a745af219f9f06f743333" },
                { "id", "a2b84c921d2f0cdd87a759152084f9530b553e1632ec921155ee32e2688bbf24cc2a8721846d5eb79576e140175b88154f80f8b3c55dd90b10123b5413136eee" },
                { "is", "676b53bfbd8bb345b06b948ceabbc7a28455644c7c9423bb5f32fdc52501f1eb43e7d07947a09f8a5bada6f8964b83c41ea55ba064877360ea901e81baf87044" },
                { "it", "91207b284d68093293874d810730f48c697f30c10c636d7fc94485eefb8cb52c6add4fc37b96501e6c7892294789cc0139c978c0393bdb1cfc2cddc1ce5137b6" },
                { "ja", "98d62429918fb0c8603d3d89148543d50bb7c0a26fb026e8a596f39eb4be1bb76dd5d0b79e0cfd11a15a6bc5e23eb006e0806aab6f837123facd9c159d210960" },
                { "ka", "acf58f8684a7ec998402a68ad4a5ae9dd4071eacc2bf371652c17194e490f6f291e02a2c8c9f4b99fb4c59a3a7f0c638bac6c2f935dd337b125733868bbad0a7" },
                { "kab", "72f1663a8a04122f26d5b94724b1f4322a0c01b95c154c41acb6fe495373cfda74112e318ee6ac632cf1e1d6b1795809dd712542e934980f5a27a5ffdc7edb0e" },
                { "kk", "bc68d13755692f6f303c09c2f1afc29762377df894fd94809fc12646b7689b3fc830a2a7a2795a56e5d0ab46ebda77a8736a38ace4d6d1f0c0173a4e386332fe" },
                { "km", "05902e3feec5857ee9811b53dd5b5756e2c47ac9467794d3ec98b94e7f33feb11a38249951c1c52660cf4931efd557fb8a5fe0e9baac1669890ae9ffaa552079" },
                { "kn", "e1e6973010dc8297d8eed49edafac0c29ce5817a2d734716447ca76cc43a5d8abd88adc9f6632e72c55b460da33826fc43387cf79f90f1031cdafaf248670c1d" },
                { "ko", "5ebdd257b5bcbf5a56bf62df6d5a64208cd1d2fdfcbf08b6fade62658462a5a82da255c0c05c6587a31723731397be8fde043bf53ecdeae3b517333c8d089d0c" },
                { "lij", "9796110093dd1f4196ea5720ea53783b7105e73c7a1aa8ea0ea73d4ec37a2af2d548122e21814a487487186a6985ca7bafa4459ae0ef9f2fdb3cbe13b3c90da9" },
                { "lt", "717689a8ae3be7d28f58151aff77b0d9ee577a8083c194dbf5a7281d1664579c388d69ffaa57ac275605e4147f0559f12b568d57f8e144c03f6d89125815b148" },
                { "lv", "165e2145fef02f39897e39453ec2151afb806dd0066172ec50b28da78b3089c9c38390030a90dafb23d9737cbea51a90a505d6aee7ed28c89abc00110341209b" },
                { "mk", "0b8390e0ee807ff7284be4c5e2a1aa001d845919c6ee1abf7b2f8d29d7c5a82a67c47b0752c79f1ec4570bcfd06dbee805f5268b3c3a6e1c8e2bb2c14e47b8ba" },
                { "mr", "b76db1db14786c375272449f3da7dc8d7d3de417d3bd91c399715139d25a3aa86f48efabd6b7757a5366a542a77813284b79bfbe6569d15c9df27e01ef5dffad" },
                { "ms", "2c0e1f17235698195ae42e87174d0c79967ccc18aa9dc363b1c7f7a34f3737e0f8fe9df92944896acbc365ecef4f8562a16f54e857a8e18d6a433af00b15822a" },
                { "my", "78608232eb8d371128709e9ad4a051d181e3ecb73e235786175f88467414bc3dd7fc98c596b8463321729f0c2dcb16fa41dd4f77da3167a888a9d08e0d7ddc07" },
                { "nb-NO", "3e001555b1a20a9d6df37eff287dcfa26802f524f06418f4fca5120808a78233e1c50bf4ff39041fd820a236a8aa76a6505c06892bc49f138b47e8729235acfa" },
                { "ne-NP", "8d5aa0d469602cc74c11888bcdbbe1997fac4d3550d5181462c65bb4a4e4552d9a327145215941ea3a582d0297b2b85aa94ec832bc596b7e50eadafa676c0408" },
                { "nl", "db697d26718d118a17059659cb167a63742e901edc4ab3372e8291d587554687f6a528c6780ca37a7c0a77a4d8ca9324880a79a9c1400ab800421731cc89c7c2" },
                { "nn-NO", "07a3db6673da1deadae1fc44f515fb11a50225e9ff1c3e46d4d2515b479cb6a09aef40ff136fae2bf905c255f696d750319be83bd35910e36ae00e3a7de736cc" },
                { "oc", "07eaeac2c9ea2c75376b33bc6d2dcd7b8ff0d7b9cee62023821ad7db87f08addd2cd8694564c5fd04d6df4b8b5f7f6b5782ac7b52a5b07615fbdf19fb8d34262" },
                { "pa-IN", "9d4361971fefa9fa31edddfa4d93d74eb60f1ab0268d865d8a828f86a7ec773daf0d0b4e7a506a1226160741a06ebfdc9d64ef85afc60f1e593921c97415cb08" },
                { "pl", "c574b7dd1522f2e91a698c4e616b17447809e0af85e8b8504f6dec5e91696da31536c3105aef7b5263708fed8c9af4c0c12d13da0c382e371f4e5a6fdae50aa6" },
                { "pt-BR", "e8dd302b6df1213ce3b061084dea2965deec01d823cd1d812079e95d5b8425df07c510d50d58fdb57fa978d6c169297fa4bbe04dfa8bbc2d55e07c326cceadaa" },
                { "pt-PT", "ae5cea431d4e12fca87bc6cc6ae8ce627e98b823fab9a5496d2e70532e180a380148db63c430d19ff2df8220f0c5ba728a170f2ff3ff4aae663df32e1050514e" },
                { "rm", "511c07cd4943fc49ad1413ee76158d04c07cbda7e7ed976e70a4c4e694845e8bd5a85b78453aebab665f8e1912463fe9ea2b7155367f27333c209dedefd4a3cd" },
                { "ro", "ba10b3b94e0bed9e7d136cb2651a88cda73e3dcb16b50ea1ede127ca89c01405d165d0f0fbb7461bda0d92a34e77a72ce5e4739173a1a6415135a17f684400c3" },
                { "ru", "c2caaa35115c0e44f0d9034d31d85b05c18d7ced150e7a24a868930d73506eda94a92e505871117792b7013ab773b7a0556a855eda7fb7f9766633c312c7c6db" },
                { "sat", "b6648ac7a5bc9bc5a0fc5ad563c10efa2b2316117d0cf497af1d4136b1eb36e5f5fafa488211a72c7b8067936a322321dd89f4f281b19a5d2893151f845cb4b8" },
                { "sc", "817ad0543384efdc6cdc7b956fefd54f44e7711d631aaa6d22d60c8b47b73788ea3fd50e2092c765818613bfc2ffeaa71b3fbb6fbfc3f33a9e737a15a4a86636" },
                { "sco", "aac0f7f7fe4d6c610966e5ffe3b2403ea3536b34b8a0ea5ba087558c40a7aec3bb844ea949e1df2b433afa94b1661ae4ba069c9bdfd25f7cadac0918b008eb4c" },
                { "si", "23a440afb56b7cfdc852b483058c77537f8f3a0b8d65224755f3bd26376365dae81dc96579c404b2d7e1f65909c633c6a56e0e0a2c74d5d90d0736a4c6abf9e5" },
                { "sk", "5dcd2118805f95aaba01eddd5a31baeb2f3a51d36aea87e54b4d0b7e6c13cc9297a153ab1312733cf01f1a837f6a661ede5a032cb692fe3cf36f1113fc7c0a64" },
                { "skr", "5fdb4841462bb91fbe23f82af8bcd75a88ae4249a1da22a4531d1486c157da0054f29fa752582b161e37769929f2b30bb2a26c4290e004e8d6a1138596fb5795" },
                { "sl", "cd44eac838adee6a992d08a48911fe9d7d331e0fa1a8b1d7129a84830f94af226a7c290c67151cba30de103b5ab9db3218f14444e13e0a3fa6016e5f946509d4" },
                { "son", "ab74f6d62d68e2d14f5146275f370eac0035a8a59d5ccecbed6f771e1a727a899a50fb7b9efc85fedef6ccab4e0588ade4b9afee8b794a1c96d4b9e0aa3adb97" },
                { "sq", "0e9069d64e1966415781b8046981ecddee62a56529e0c6683b183ba7df9d0c0eff0627e05fa72611d13c97f937411bb2ef699f98935087ca9f752917fc228eae" },
                { "sr", "b7fa20470c2affda428db486fbab6af71dc7710432861ba9c3cb9b1bc88501f2e40108edb1bf757bc4c803829d0578dd0f36f4926038d7733d8c651cf6520eec" },
                { "sv-SE", "d8235557de710cc61952d79660a555ca09812f37b1ddd585d8b1ff96ca43bd9dd15fba15ca156c8af0598bb2f5df90b6438f725ef1100b573bc68af2fa8d3461" },
                { "szl", "30188043f11a1840cbe66e82bd2c4558b821c6a6b7ea83ea0b7eb15c10a42cc3ea640f134bb389743491a1075321f7194a8b71b08d2b5b7bb71370142d8b1204" },
                { "ta", "ebeab233ed59999b39494ab9ec2b87851549bf1db04a9d26696c3e64eb463db8edd0f138a1b1edff67a4ea2013944db2d050acab095569a6f080a71d090b4bc0" },
                { "te", "8b45315ab176f674156b064a0c56a32bd38c9c4a13d13f3663156d8d0cd4c1462023e67cad65d21030c0cb07f974c111b7c3d3b9e98ffa54394024dff4181eca" },
                { "tg", "f8f255c92636673a1eae97b019048c91658778262a9d547f2d349795936cc629118514711a871c1a86c5c0e071c066d31f5f19b48d308f64231fc3f4d234290c" },
                { "th", "741f20b884b223c00168e92a8a6230b290c46614e8cd2bb7a46ad3c2ade84b688244ee9b7119af803f8545ad26073a2337fa302c62797b4da87f42c1f5168bd4" },
                { "tl", "897ed2c2420adef5352ffc5c726903776bb4de90290faa938dc77225f5532529211590803ef5d079063c1f66367537da8d1500d5f1fa872af7ea9f1649381809" },
                { "tr", "e921220d89d2e3a637d26c90fa5a31dffc76e7807d03968af12925d05a2c8d9dbabdfd0c5811091320ce42cd0a2436568b5eed662bee2e651bfd81de150744ea" },
                { "trs", "19e1dd5f841357764d7768d00813ba877c917582f50853979dfbb2d950cdc10743fdc26dc9622a148b61e4fc1272d1b8c44a98d6dedb865673acbb228e63b311" },
                { "uk", "9dd04297dc62fe6d9cbf25413652a63d9a267c464892c787de649e050995d5fe14bf3d076dd019cbfa7a6f66e506273961f7eec4cb2932a4ca1a3281891cb599" },
                { "ur", "c6e5dadc6d5d3b661232691921ced9268cced683ca2a13037a9f41a1bb58fc703fa84ac7edf078ed02de59856ee48cd20f0b90299b198ee20e8d8e44c3822a71" },
                { "uz", "d36eb0645669bbb412e1cef267848dd6f9a721691f16368cc46f2bc04bdf46024cf91ad9480d65df0f6df85b75fcc4ca99f8544301ba43a5534aeddb67f4621c" },
                { "vi", "dad15dc9149ed7b46dfb5733d9e1ebd80c3809e1880779adb6487bdfb8531de99c528b68e098774aefe7f76f785337814ee71e655825fda00d68fd36ec9722ac" },
                { "xh", "8240c15956c364442cf8f3439b4a66529182267c016a15ebc970d421446731d016128d7ebe0dbd6f30013956dce00635861e83bc6285da418c33cd8a5a46847f" },
                { "zh-CN", "74f91a7d9bdac68a9e5109304f9d51e696a7cad0db8eaf92bd93657c899a6b1c83516d3cd6c51f1b0646d4e1b8503c69fd04f3ff1371d57ee7085d462479248c" },
                { "zh-TW", "f65593f7e92cca700085893e5c5e350a405ba4429dba7273b3cb63111201a8a50f0eea7e04f92b34f706a09d1c375e4a13778bb4909aa2559d45c6c51b140ac4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "26c72c0a350421cbbd5e6c9ad85398a2a39331994eb2a82bb9167cf7e9c37b14a2e224415d2b243801228ba95b163add291f1e438fe04d4c798aa0fcb12d91c4" },
                { "af", "f240d36d03bd6c9bc169f372ad2d4a02291a6105d087a8edb72f52019a696904e96c3a6e768816a2bab7a68b8d285159d889330ed814be277a1709b9c91c3468" },
                { "an", "95a29bb5e23e61b161be3090611565f4151e8c8d949608eace5e64812e91a292863bd67a3660794e37e734915df3f069dc9a464e5e19ac113fbbb3d3f04ecbd1" },
                { "ar", "d3568800f9c8df83d4dbb46ea8bf765750986c2250b293750b64a08be4b6c5098b0fd5dea59ce6cc7c072a7d4b8da2e0cc0da847bdcd6547a1e656d51dc8cda5" },
                { "ast", "3ee816c5216c65ac24c40be677937718190f0defc50bafc130a43d312b158706d5ae32a6127447bf0443d8c80bcf31e87552341768e220f6a7856f4f1aa6e49d" },
                { "az", "e9065a0a7d39b8dccd661999d8e5d8fce992955941244c7c3dcf45132d0e861b3a7f162aa14f6200bf9d34880e15046f5294df202e400f49e24a1e4ed8aca44c" },
                { "be", "0b60a112cfcafb860cc1f2085e6deb48c38fa92d7d4f07f3c842102cd36e827a78bd86ae7477900cd8db89a559cc39b9ebf4ed7a8608e35a2502be47853117c7" },
                { "bg", "3393202352c75e358ddec4d8d428124daf06c9ae80e378b4f74cd2fe097fa41751db7d56740010765bc70732d7aa15057bb882eb82f6231f173ad2e0e06fcef6" },
                { "bn", "8c47c32e98f3b3830849932e92d6df6aa8327b9d1edffba1c72b4ffc286d44b9fc2ad9d214d968acff3b2c1b08511b83395ee5d5a756d6535f512d9832c88811" },
                { "br", "a4209cd394ad3bccc3404ce4fa382145e7f165185a30028a52edeff0b10ab0c814afc0425e190047d26b39f5cebac2650665c8e414b0d03e0eaa778e8463bc10" },
                { "bs", "f959cc77749ad123f285f19f330b9d8315956d6d1def464e117224f2398adf3ea44b168c2f804b419020393949fbc55e550194d3078d5af4f1d17c79133e4506" },
                { "ca", "a03d623ddcac331a0f7a19cf0eacb51102f83e4e1b7e4c40336115c3de4afc2dc38751be981a89fc16327decbc06953bb413e795fd8215101dc14e8623fec097" },
                { "cak", "cdc86a062ebd83e56db96472784fbe0ac1d83e696363d19ed2e5b8d492944bebbca2984b08611ab1630fba189d5ab2ccfde517a105f6530a2c55487cdc36160a" },
                { "cs", "76ed8d61aa470b02f414e1a85d6f1bbcde7b2e3c986011072ac2557bc4e3b626c6763fd0597c33eca2a963a35ae01f253982b9e6bee491a0e99863136c2bfd68" },
                { "cy", "5a216c7c9a403ba3ba6a8cd669720a650b0e384b12c019f4398fcf966a7096caeb9d46660fa02e9d84324d063a11e131c60236061a86a943b0f4fb0f36f81b27" },
                { "da", "44624ecd0a7c941c92fa6b00d07aeb7ebd014c10d133dcc840c970ccd9a93fcad1d69d68a373610cfa0615948b8fb18e3a973fffc9642d825ca961c000a1beb5" },
                { "de", "c7ce6b34532db169b7a3f5741282c3ef12bc9ad1aa4c9d36719b19428d64ec9891157820c3881fa8d14c973cfe5cb02ff7a28009a83ffaf1bf29cb6f8f7dbe34" },
                { "dsb", "a37f0cf193ab8e1298a557b2a9b8907f02b6b534a5a5bbfe6d9a358708733b633999c2f6a6f1168517296884ca70443876cdda7d4ed8650dc4be78b09aba3e32" },
                { "el", "4d0617b664ad90cc14caf42ec3d2f2bf07ab8ce22ce7d9f7add6f89c6665204615f6c5687acd467087cdd614e0485bfba78d982ed15e7f8f50bd67868eedf91d" },
                { "en-CA", "33d37cc259233ba0e2290012443ae323dfdbc05c596e05a6f3e0b62edfc3a9ce1863b583f8849e65b7cce678b6fd875a67829bca73fcd86ed01179dc5162f514" },
                { "en-GB", "2db7b38b56ba1bda7c6a6a3d6bbc29288c3d4a1ce5a8cfc80896dba5fcdbd57f7b221f8e667ce39001ea8d6c287cc6570e4e3258b8cc948e94a77218ba61b192" },
                { "en-US", "c287fc56ce57f3ce925d5449eedbec36c1b9fc97f8c0cb775cfeefc9511bb0ca64c9328d8ad83b356bab5517569b4adf15b77eb0b3b02573a3d1a6a940f858c5" },
                { "eo", "3d8a4d674160df235458a193549fe139b2568284416fc271a7c806ebc6ea65b1195a8ea33b650a66c189f023ec0096251631753d00c54c015a88693916fa3997" },
                { "es-AR", "c95652c901524b6fb305197c0c2fb46fa6378cd301294d567553bbf5760ba07cfc1e30c0be70d73dcdfeb4dfa8eaab5f326ed49f935e66b585c6ff50d9b67e42" },
                { "es-CL", "f3f7ce9a01cf7f22aa2d21978c8c7f1e303880406dc3aebaffa8124d69f406ac0e51536cf9a00dc3fe411944852db9b8c88b111ce5e40a08e42d95c26413a906" },
                { "es-ES", "210deebf6db05d5475cbc05d11dc81ad0aac8f29869d9c9243ea94325e49304fb6f7ee9a11f141543fa15f730256019b0638479d9488c8082f13a7896445264c" },
                { "es-MX", "e55efeab451cf2a88258e7f309a5bcf575020ee4630e3c05a3aa949bd370d17b7ab19f596885d7b44c13e5e527113b181abd2db4273ff89515c6c480e8e8c69c" },
                { "et", "9feb60f67491b6db0d9f2130d7358e2a8724f8bb5ae16ad6b4b17caf5c1e617f119dfb8ca2f65ef27d3cea5d4e0fe8191f8a1da50a0a1b2bf18f198c795ba8b9" },
                { "eu", "64ad008430e485ba8a9a02a018d5f846df655063c5dc3b46f80568aec02f02eaa5fcc2c4b323df4b95308bb8f6f4b2f01fa51866aa00a3efc8da3120ecf0f77b" },
                { "fa", "137aa17d2c41f0ac14dffcddd5655fa2f22b4e7b553e215d358eee83c772b6a5343342dc9bde2f0dd25717e833e4857b1134683c5648b271c6562d7ea4e1fe9e" },
                { "ff", "1f53acb60f20df3910a3edad1c5324d73208a96f5af4ae2caebe71ef6de339f982005a51c9a14f62cff9fc6c54879aeb57a775525f1ec69d88a3db9ba67f0410" },
                { "fi", "532b6722cf2d677c69398325557d26b6da286e83d902660aa6497049b5ddcef7afba6a519c8a06a97b5745fbd16edce6c183f3a6c828e19a9aa94cc5615344e5" },
                { "fr", "332a4f45ab9e993edf51053ef881692615699f4d90c47d31e75b99d4269c45b5de56ca7ad9c6d5bc0f4c1643fb5fc262d008c980db21d4c4eca0700f36a3404d" },
                { "fur", "a1f54668ff3babca7ec1a1791935e8c44e3a5e438b998522d237ad4d8df90d11da3b969fb07aa8a9db70f80fd9d06eaaef75baf0146bfcb314d8efa469105b2a" },
                { "fy-NL", "3b7b614850463a33882fe2064c3ee6a97517c6e6aab7e5b71cf82adcb664ccba93932053654d9fb4fed4dba6ed2cfc9a0e9f0db9042a3f3c2ba43d5203ea14be" },
                { "ga-IE", "c8655e62583b8d6dcf8ad115108e736c1eb8ebe8494b3cdef9ff7125f0b0c72c003d68ed308905b4c98bfa50eae7626c3135eafb1605f9ad098440de19e34a40" },
                { "gd", "019ef5c6ca9178a4d3a02216e24530e87ee478f3ed3d61baabd4f329c5b416e427d8c554992369dba57fcebe1b2009ee7b075c514cd98a4ea1ade908a393a1ad" },
                { "gl", "e800fe36bdcd9958a92b43124100fc31c335c75bc97737f9748522cb72c14547662ce91d1ae8e0cfc5ffe34e3d463e3663f081f21a950d6054ee6a2d461c9464" },
                { "gn", "5b2ed206e9b50c9fe62334bb6cb779e68efc2fc19d97f0b7d7c9d8b85079fc3ecf42e515f9bdb4b34d74fabb82d86f468b33133ef1588f60279061f561cc2dbe" },
                { "gu-IN", "4dfea1a69e564191309ceed2e95ad39e1ba97a07479df0351507429d2c9f79b304c2f4283f06184dfb84a65e6fdf0401eb2a16959a61dedc4fca656ffc7f4607" },
                { "he", "69a2aeeeef9892d341ad969497dfb966ecdde580ca41335151e3b0932cd8aeb4b9c1f9fbe5d7e77e94da374b2c28cb24fb162e5731332cd2fb2b7fcf00be0f26" },
                { "hi-IN", "71c68863a6ead077ccc1ca02fedca0da386cbc56593c32571264f3cc54f112f7f0e9191e779908cdc6fc6a33cf11f9e7ae6400c468a3f0c056d8169f612f9af3" },
                { "hr", "7409694f93877f240d516dd031befd8db756cf9429a09cb4c59c3d749573f9322a60010bcad236dd361b9f2eb0e979cd0e40d5d2a898582b6003050145916e19" },
                { "hsb", "062cc053bbdcba96fdcd9bdc2f27ef00c23f1728843e74b8f7a25f2220dd9ebb1cd775e0cd73be7af9616cfa73921f7aa44c51991879fa5eaf42e0c2685cf432" },
                { "hu", "c8ffe36823d951e499c6cb6d2bea0d2b86be0fffb9c1457875cefbfa3e8774617379f7307e06c89f19c4fe0949459c8cc6a83cdaec004a83beb8a0b9d8ed5f03" },
                { "hy-AM", "7f24702693b1190b490d4c44c02c903293c635b50bac34ac44c67fbd094280341e85ce76774f29eae6578a8feb2097818e3b314ad304c9953c50c0b09454f184" },
                { "ia", "8950dbb2149f72e7830858cb91672a25273ae1bb0b2ddaa8efe609ffe2962eb1e353ce0fb05e9d052e562b25371bd2a3cb97c65dfc3d15452df62aba11a9c598" },
                { "id", "fefa50e8c55d947b3c0613c3a6a752224c68056fa13ab9e6345c12ede3f2852fee5a059ccf93fb08c6f6489542a0e02d72e992cb6434f32fa24708d9a2ad5f8b" },
                { "is", "c12ddd826672119c9f6f5702852ea61a4cf0daa4f3b0c0be2b23adffcae7f916608d2cdc6fcca3a3225aea662ab4bee4ded7109f19fd43c0ffb74f28ad24bda1" },
                { "it", "c6ca67ba71d5e1da17da7b0f130749fb051d443f3d0185e3501cba7436b31577a76134cdee5dbf7736bac82d7b76ca1026a505b9ca566ccdb069a44a5a1528e6" },
                { "ja", "7e901063f367a1564e682de8ebe7ee6240385481690d746c57c1778a4e16b83de1daaf3eba9738304d64cb3a7d88879e571519fb1d4797ba5fd55a685f0407a8" },
                { "ka", "bee339652b5ae8b0b0fcda2c401c7c7658c3b25d14869d1e9f596c3698947e87d353da60093713f0d0ed8e1cf594abc9939408fab868b88af624f79c61f23761" },
                { "kab", "3c7ef464ebbc7231c9fa2ca41b14d645bc69df44914a2ed44d8f892ac5bffebf19fe391ae3c40a2437cd0659ee45a7114c1d96ea23a5af66076d56d6d5b9f183" },
                { "kk", "3ca603b75abd5d999aeaf633b4495bc4ecabc25cfe4989ac17a33c35095979b4d51c4d0b67fd56d188f3583aa30ef5c0c02a53b14c924905b96f08d8b4c32d24" },
                { "km", "b0296f3d20e79b7e0252dcfab404ac38a80cb6d9f0ca62d0680dfff16f2330a4db55f1e5fca0698418e3f8f29d8026092b4dbb9509c30820740bde730a9f9da9" },
                { "kn", "64d87c88d6c8c10394671a1d13332789b830864641e49db8ceb79c8fcdd264984f81deb72cdbe0364a2302955b6212c827f7e21e9469c9ce53c5b0fb49d68701" },
                { "ko", "c96534f7022e98beddcc2748085c66f957634ff6711df0c7b111df953d713304fd44d635139a358e1e2beacb74bfca0d7c49112a8b9ccc3510a7577f0847b00b" },
                { "lij", "26fd82027efe0be39665916f887f40269e513f142387a0d5ed279391a381a76893f393976c16b608bd0355ff8553a717a97183ecf42f353bfb526ddb84dbeace" },
                { "lt", "2359cf401dbb6ffb8bcbbb8dfd2057a9ced9faf09df19131de2fc5793d241070dfde48e817f403166ed37f7747c9871c35ce1bc009d8b600334d30e8f65f31d0" },
                { "lv", "84a38a4fa56883acd1a03b2051224ad2e655b64c06e709c60844e3195af5684df70278a834bbdd00c77d3829a0a16292b5afde748b722a89a6f1529ff39faac6" },
                { "mk", "b00805605f323021abae5269f20e9fb2bf4c6fd494552aaa538dec8bd5b917ff3f4d67639d77b37fb7dbd9a4779a6cf4cf0572d4f7b2963ef54b68dbeb4e270f" },
                { "mr", "6ae688c80a2b923b62b172085fb77570c2364f9f77aec29f11af251a90167aadb2afe59ab1d1bd5b13d8002cff7830e2622e1df025962fef73798c551897bbf7" },
                { "ms", "6a78b23b85827389d920bd1dda93c89a2de78dca47719298cbaf3063abe5cab704431b570563bda049f448c4ef29d2f07158d9d79218876d6998c0c4ba917819" },
                { "my", "067600b4b3006539ac202995f9027b6a943787cabe41172da00ac0345ef28966c1aeed18baa16793963b130609141d9ab8783eb93d1a35e3c966e482fb185f71" },
                { "nb-NO", "dc228ae7277eb6a1b73b1f709cf2a8d590c9e251c1a3bcac82239db928af3ce9c0ce5161893bac1e209cdb35b761f02be78d22040d2e3ba16bb47dc518415fdf" },
                { "ne-NP", "2f28bbf00ddefdc05ee7c6e3b7de76e82f1ba543be793f52fdf97b8f63168630b2c915b2e66ef29eef73545a93169f0dfdf8f64ba1169fbc99f6a3b328981434" },
                { "nl", "45f6085baf319d62c9724f660c3be209a75662a24660e251a143b0a14b348b178df08b72c0b6fe442a43bdfee95ebe236519a43a8faafc6617ad998759cc32b0" },
                { "nn-NO", "9fae2b526d7277c1619fc2ee89564eddb665f0e953ed0f2fbc99c62518622c5b8ca81990d7b767b03c59ceb86c3c721ca7394c2b34a9aacf69f3600caf97fd58" },
                { "oc", "fe825ae3073d2aa5f8d5ba2aac810d643da29025fa46ad9d7d472f834a2622deecb400da1531aad241d8b8b069462962a0636d8a3e6a0b6173f11e068d8079c3" },
                { "pa-IN", "e66e7328fba6c748581f9a5fd87d2f7aeab9bbc7e2e5162dce377ca2e7668f6cdc2824403a584e736867dd0290078be6a8d0cd92e9c38c4e0c8e738dbd4c310a" },
                { "pl", "e21199b974bc945de9ce8c06c99f91648a663206d07419a9ecb52bbd16623db66cf209e6bc4639841eb983f4125adb6a5eb38b50d79e6f4221fb8962540f0995" },
                { "pt-BR", "5862b616cb55e004c852bcfe51bacce496624117ac05b92358736fdb66716bbf4127aec7df1004676df9f2e24286639579dba03b1236c22caf2ae0b0c6669afd" },
                { "pt-PT", "a20a1d7eccc65d134fcccbeeb0f9c7dd09f7e7793f6028ecc4429e40864a5e7044aae606c6c0f9f940cd264bd238842ebff928c55114f5672b0d238cf1473c41" },
                { "rm", "f51a30d1adee9121c2e43aa60a4efe6ad889baa699e6a10eb94052382906ce4733f589c024cb8e533957c2979a7cd2b5465cc2556c920c30ff6da39564bcc2bf" },
                { "ro", "7cd2b6ae8f178994df5f890deaf0717823246be4a80169a9b383e2908bb998c2f9a847b340f2b5ff27a2a1d5d88e87e6b7a63bcbb6eec1b9f2bc2eac7ca9a458" },
                { "ru", "bfa3afe73caf2a150a5e47ddcadcb270970f8ea74e43c4e464604f307ab38777fb7edad70cdceef9671b187f5820c51bb74fceb8b5d40f046ba0953160444731" },
                { "sat", "4e00c6c03bb7ea8042dcb6f795f16eba7323e573216ecc940c677af58f8c07581c250cd61e90586b2441238519e114c606dee770b02788784c493bbe5a9997db" },
                { "sc", "0d5aff6c2601bb3c9f08c985a5459b77e2f2c2f0849323502a936fcaf4b95a1d4285b35ccbe9dfd4dd51f132b1e19998084b5b184b310adccc1c2770e9e605a7" },
                { "sco", "ab0eb155cc19e19d7cb4a098a6de97e0920d38c3a9c3f89b0f5e596acaac3ae5cf00d795793918ff56323bad6710e01daedc2a47602a423681b2685ab66e3dd2" },
                { "si", "aa7c5dbbff9c7e9bda9039ebd4d3fcd28b6f00cb7dd81bad9f5727343c9e75dcd63492658ecc6f46d35f4ef139d780879013028cf0c0b5924ab90f1a36d6b308" },
                { "sk", "63bab9eec274b04ca54bd76a44ce5ef14b48636f674ba84ac32874cd38af9dc40985f1f32145e730a9ebd429b346cca34c51fd387d6e7ffe6535918f80793be8" },
                { "skr", "addba7d535c3e33f8eb6e94410fb4a2d93c25db8600492b9f4ca4ccc3a1caf2edb30f8f5046f99f6bc47cdb0c1e3b5412133fab8fc2184ea5e776bbf2dfecbf7" },
                { "sl", "3b123c889a8d9fd9734926e03c823273182898f29d089fa174d0dc58686bc2b93fa8cbafedb6023317683a6754d2a400cfd95b6c6ff9296ab91f8716e4fcd9be" },
                { "son", "3fa8ca44c2ab6d8e572c583454155726809a698a79a34d38059624890a51ee3ffe61c933740ff1ec3fa6ec7f62cd8a4ce4b5ff2f8f491248f6c9aabe94d3a3fc" },
                { "sq", "e637c679ab7a523ae124cb5c93979d21645e984f7eae41323ad86a954d65b21e76aabcf51d1ae0028fb4cba001431aac55f9a533ab42e6e9986dc8074016c9ea" },
                { "sr", "6a40276476a34e3360fd931691fe9094a0ade5ff08c973435a1bd89acec0b43677bf27b872932498b7f3857e313f8d22190bef55f6a8ebeff88734f445f248c1" },
                { "sv-SE", "cf16437323e580ccbcb6b9a17230d929500422ff5948f9f8d49b5f940009d27ca748595ad887d5fa3f4016acc3199379e61b5dec61f3abd8045507f5bd6f05b9" },
                { "szl", "017b32e52de3702875c0cfd78b203092919f966b83480e72769cbaf36378442f655952ce713b818a4f54721920176eb8aee323844f752a40f9f60fcac24a7400" },
                { "ta", "ad16d3498ef77d3c0c3b601db0c264d5616f64d4f294ef81f513136fb93c64efa43a86cdbe9c86e05f78a7f7b336b239d789ab521e160434e2957257f67dfa78" },
                { "te", "039fd36041bd8a26b19012d4edba615e1b264a11316de7b2285447efe1c613fe674aeedb94e26f7c96bc62c18604678fbda25a0ea7274f936edca630a47da8f8" },
                { "tg", "b044a240360eed201cb678f12ead3f448850efd7f68b5dafdb1e4694b05f6b153d009856450c9baacf2cc65981325083bc8d6b011815bc4b00f67834ebe932bd" },
                { "th", "e8bd268ff3df96baf7e28cb0bbe01dc6d343d075c6ad0061349dec39f9da34fcc430943182e5e9be2e20af69c29e6bd7e25735b7a3bf5e09ecd2d89a7f100c83" },
                { "tl", "8c6b684ce1b8b4410eca96ae07d72242be693122ab758235d628af0f88d42c7694dad26b23dc1968fdef4f447aae3effcc51f19f0a68006b0b478fa0e98cc61e" },
                { "tr", "c94383bdc58c16bda58c1375c1a03492861447bc7618cc97199046f6a21c35ee2e50e2e91fbd19b5b73d25d0cc767144a52a9b3cdc8db8110ca1595661a39791" },
                { "trs", "9bdae72d4c47dae9399b62497d71629d27e5771eea344f7088fdef5ede251e0deda9737e74f6dd9d4854a83c7d48351526f4f69ae4f88f99cc69d3a60b737860" },
                { "uk", "91caf85d3c0843104acefc0d9541290cf0b2da43154ef1c964ebe15d1efcaac652be5884f03bb67579508267e2fa8f459b1c55aa5700d92759e17af4fb550f38" },
                { "ur", "2f8f997e034aa6a272908b0f0442805383868945307e1f59f7e3cafe993ecdd943e7df3687ad737116341f8be7862f2278f4c4a8071579409c4e729c9b4c6065" },
                { "uz", "43ba264752c6ff5ccccfd04a48237832976319dabc00fbc29d83f8f182344568f12246e317e6f32689e22d8d5bbcc4583d9853c7194c4448d9927f4b45ab5ed3" },
                { "vi", "2ec695ae79ae92e5528013f50765315c0070d7f86ff2e4c03eec33024e661479bd1d3be998798476d66048d4834a00760a1b3669891a2856ad75f03335936391" },
                { "xh", "51d7befec0ddefcd444daaf18a6277e8f0d0741529a01ccd92f4847b5fe0e0ca7720bda923f8a69070f4b0de17fd037db91e7a12992d09dea119b68cda221293" },
                { "zh-CN", "dff5b79435577830af957c156fead57333f9da31f711cbeec0d816a3d2ea48f34bca77eaa37620d454abaee36f73a213656ec8c41936744aefca8169e977202c" },
                { "zh-TW", "419a37b7a585b41aa68b654c8b25367e39b772d41d3181525009f6af139eb98651bf76985f1c34a9cba02871cd5015c78adef4d707166e55beb384ed6d4cbe1c" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
    } // class
} // namespace
