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
        private const string currentVersion = "141.0b3";


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
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9ebb5866b4dfa121d30b98c3380a64961feba2105297d8280c665af1a0a135845e20f2882825a88255435b3a648ccbd2cd958296efb64b6ed69d1c51106fad35" },
                { "af", "2b9ec382077b380f59bdb462e63eb653a7171b170b0121b5dfe99d94cde099c5683d28e51889847661787bffd19220f571b40454a7706b48b77886fdfb1a5b25" },
                { "an", "e771473c893af228d06554fabad6caea3be5432e10cc816d2bb101f1a39b17ce0b87e119402515df8065f0185d4c12b94922ea1af5a0237280849c0830eff6de" },
                { "ar", "4d8127d942cce8bd833c645b07f4a7c42aebc91e0db8f7e9911dc70db391798a959fe8b6142a2310c3414436094703a1ae0b3b4ac4ba208147e4b97732a24bbe" },
                { "ast", "4fd67b34f626da07a6344177779784dfbbd8a9749cc9fd0c25b34125843292c7302f8731d5cb868963472198fd94ea19a55b35d234bf91aa148c11610e260a7e" },
                { "az", "3c485aa42b5fdf8337a26c3481e8388f37dc29e6d92a3044cc799142034c698d6765b09905aac4e16214a26a00d6c67581637f160d44d663ba5a31cdabfc1a75" },
                { "be", "00023259bfa9edc30edae65fb121615f9cbc4e7edfce00c6fdf70fca306eec871a1aebbe172a01d7f4e31fe9af9697e80463fd1855a3513367176360aa53014c" },
                { "bg", "c91e6a02543aaa11252ed09c3bf4708e95fbc3cda079028f54275d57927861a491502ab33601f9db2cf335edbb07c269d15d417690f5bc19bf7c9963283fc27f" },
                { "bn", "0b2af7e6221f0ce0882b480684e457f11586c24960f0ce8f6864e05c1ba25b7bd354abfbdcf1aeff51ce3a3158a7a283eeafb48d8fd07e007d24c01df1489b00" },
                { "br", "9e0103b73f976d53b74045fff234d4e923303efd0d12caf73f1577e4a30fca3f43c36d428dfb9d17c5c7e776ca89ce35dd15a98d77b8709263f5f0dc56658daf" },
                { "bs", "004fc08576bc69ffef84b4559e017e2852bffb3204c49eb295779950e52e1aecd58cc9dc5fceb0b1924996251b0731ef63d995de6ee05f02cf765be670462a5d" },
                { "ca", "88b6e35eae8721e6d9dfcc3867db27f5d4dbcf84de6289fdf5f23e35710a1fb14d8e07ba1ed64971f50592e5271e12fe971922efbf571d767cf47c1264a5b88e" },
                { "cak", "c62ea9b92286a027bc00f7b83940e20b788428f301eee3a3cf601478ceccfde42488dc63c6a1e67eca4a6f6cc129b108ef2f7b4183c26ed5436e943f5e216a35" },
                { "cs", "36a8baecaa4181c7b2bc3ebe8bf6a18fd84eb29ad4aece631660d4457c5adbacbd9fc6ec00670d4522dd7a05ecc9d838bf34ccefc407f6a235aa66afd3e68da4" },
                { "cy", "baad5d7438b6d9447591ddb93fdb05a394149876e11a9c77c34c6a1d23ced37ca2885c7874fb88feefcdf22723dff39fe1267b69fbbf8191cb301bc5a503550d" },
                { "da", "1dff18b89d40fc211d608fbb616a2956d6bc8d77529e3e2779cfd18bc2759aec5c140137467814092ad9b9b74794fe1af6013b5771d7c2c52e37a4bfbf42b8ea" },
                { "de", "e4fd2ab8b7f3449ae108a330592d52fa73b5166542044e06ad7ee428608b4ae7221eca61110a9016b6240dcaef8330120d00e0562d28edb31913a58f27a846ab" },
                { "dsb", "f39c2ccabd3946813af400bb6490a199dc28dfdba0684f397c9110890a99be744d2891b1f41ba86bb8e7bef7df9ee9a11c55ca3547163f395b013c30fd04cdec" },
                { "el", "9697a80a977a2b82d20327f3d4943bec0e488ff0999dedb3410f858db4f80a1d5010848c8284fcfef9e0799947d20ce2a4ef5e6238e587f66d103c637ea3c790" },
                { "en-CA", "a0c630880768e25acf8684928769c13c8ab168e621b59496521ad5e29116aea98c3d77d69905e03027ad545dbf8ae1dea1479ea727a1a93aa96cf3d5f2250697" },
                { "en-GB", "26c5fc578f75275484ccb98f6a9599815aa150896a27e54c7e5231e1ae295a180815110cd11e002fc703c562cb2495a37b7301a6bbfc894ef5a711b0f60c2441" },
                { "en-US", "116d420b95421a03e4eb27c87e73fd2963368c0e58f7323ceea8dbe867043983ca8518977917cda0825fa7c8a7b63e59b7af79c33a31dbbf9f37946fffb70046" },
                { "eo", "21ce6cb17144374fa8504b73379f1a5298db2f105189bb8492a1ae20a924e47359c4b0ca0597fca2507e5659dc48fcc1d9d764ca12bee6f8d4f35757f363c9e0" },
                { "es-AR", "684e17c068c0aac5c22ee008fb4d0ff661ca3ac701d8da25d206dc013150e5d89bf0e8569a6407e867065d8ebad63a1fe022923cb3bf68a3e0ebed6b53b87d47" },
                { "es-CL", "0b4cb9db4da9b2bafc1a7cc34f6b0336553ac0d8d8aedbf58c9d3612365bffc6d7ba24908239629f58059c0d3e17028c7ed3aa775624d233f845ea80dc4c33e5" },
                { "es-ES", "ae501d0ac3209238f268f32e0034c2b6810484ad5cb21b80d0b759169d9198c55ca5401a128717c2c173acdb9a8f2c026e32b643903394b359e58dd2a5fbc739" },
                { "es-MX", "ca729ea4ef7315520f1fc68c55ba16a6857dfcc0a0044bcbdeb61dd9d313727bbae587f407253fffb176352ead0ba0e1c98ba76874af983b2163369e99c6dabf" },
                { "et", "99c0d789c8a92c01c23d29806528b389885f06a975e2f8f370dcd86ea277e872ef70c2b252a4c0031b509bda21866fe55e144784ce384d3ba9be81c76cf3029c" },
                { "eu", "7574a0d0958c3ca7610312cbcccd2fea10e59c33a06894619eb06845025fd88bd79b817a32aeba49057a2496ee605b87c8e15e060af8e11910781e30f1bdfadf" },
                { "fa", "cf1ae067833dfc9f24b2ab10fe852706d82fc48104e4f0e414f879053e606f85bd002bec18dde38e1d6c88130f80b3ab98306cc6f3db32c418add56b02ed6102" },
                { "ff", "1d98343ec0c5cd60f0c3cc9647698ae77fd896eaed69414b78e239604c878c61dd860e88119d759589def55d8012a223b91f2422aa0b9600a88ca23f8cc83065" },
                { "fi", "f452783f5a784047d0baedb839931bf0d5a71fad456b9db7871c7fc1cdbc0c8b8a25726183495518eb59b8575365e065c613ea494571c6999fb73d6972562bf9" },
                { "fr", "bddc006c40417345d7c64e6749790892e7fb46d797669d5076a444bf1dd750f8c1ba85a68582cd8dc49ccc31d45070bad6b9a5f76b7eb3fae1463c63c76f7913" },
                { "fur", "97ef593a47c49d1b489fd142ad2d467fa8f1d6cccfc092d26565b2eac9fa2721559e3daa4c52b460989fb6f7dd0565673b1691f07d1656fd51c1cd05b54d824c" },
                { "fy-NL", "39763fb0b0bfbe4527cead6ab81b29c47d0a66defe4cc02891586b5d9e8154e6209b54609ecf910dafdabbee56cc12ebfb47dff14176d813a81957f0b417e85d" },
                { "ga-IE", "63caa557d43793ae92002fe4e7de487601dcbbc507adcb7707b5bcdf38395ced93cbc2340bb3622b45ef1a58787d84ffd9161db87758db2405565bbacc0b476c" },
                { "gd", "70470286294e6ddb00110216533a2cf46f902d9fc5489082afc606402a777801d74e407a994c2a750bc3f3bae05dd9fe3ba3be490df943ad327894335c0ded39" },
                { "gl", "d20f15bdc37e630bccf61bccd28faf36b728f6e60b7feafa39f8bec112aaa31d21286fc26fc6b8be8f34c11e7a7f42adeed8a748168f4200ddc9ef4c6a202520" },
                { "gn", "cfd8d70d273635a931a2190c94f8a39e43d9b0b201c60a237911f6eedeb536263759737a9200467021665b6b7e50d3293bef6a6d3cae130a0a4e74a52d5a6eca" },
                { "gu-IN", "49312861f07b94f07a8e3ff5b6cfedac590b3518e8c1e1abbb17fe8737a3d9b6ad2e53defeb625928c30de6a79caac0a4f28c1ab3bf0a60f63c920113febd100" },
                { "he", "a19d522e94570f771af88458f0e07df424ed03589bb520d5685895a50e6a0f0c2fb530a614c71d2517e78f1f6295f24701d535112a6b94010781178a64bd1759" },
                { "hi-IN", "d31fc71e755bfb3a8f8938bce6942ab3d7cd70f621b6ac8ed9bce8f1740faa7f6163e4ac026a1eb627f3bb3a7fd6e914e376fdea7cccac2491260ed61ce0abc9" },
                { "hr", "3241a8fbed987ca740743fbda13b7b8af35d2d4be19453c1e17840fcb01dea24091fe62bd21b67c5984d94f155281d87a9f7cafd2902cb25b6f8f16b1cdb324e" },
                { "hsb", "4af9915f64acc841c81c4a9d745a7f06c8db401939518903de5262c4c01b53dc8026055cc64b2fdfabc6ae06e34efffd750a8a8dd0f0b431b9a3c632088b6906" },
                { "hu", "9b2d3db7ee1a29dc94fde0680e8dbb04429cb1e56d9c108cad63608c603dedb6d22cfd55bd48eb178c285563af1189925972f355427294a767791491fcb43620" },
                { "hy-AM", "fc9e7b30d7960f4c5653494124b185676914944d985e5ac35cc093739a62465d0dcca62785473860b551193ac7f078893e02d30af982daf480534fa345b2501c" },
                { "ia", "43894af228e4c4f5b76417e5ced5d900e475ed8bbd3299986bbf35f7d8c36e7ac034842a30a4b90fb300749c2867d86056e989d779724cfae0b5e58c047c44aa" },
                { "id", "4aaa5d92cd8488301ac6526de8d90f6f128643e10ce55f0352de88a712b8bfb8c1e045ae574199d3859068534684c93b62cc878c6dc2f586a30699141388c6df" },
                { "is", "8be1198cb2fac60e0d994d085f7eab19b00ded6122842d56543772402d97ca388ba8ae8ed6913971e42256e19462e45147f8c6d46f10c3e933d59f0e4df52f2e" },
                { "it", "2da44e60d6124a356c0dfefb7b10364b8b187e3a1a8dabc038743971cd003d5ac0934020b1b8f4b6fc42f7432cb4aaa16ac5c1bb19f02604ad2650248d6f737e" },
                { "ja", "6b26b6571bcb93422430ea5a9a8afd57e44348dfef854e6e72375cd5b839ee277696c4e9694d6621c834a7f42e2dae8937aabf6bf23e66c82d632648fbf1c274" },
                { "ka", "fd36c467d2fe692977a31b21a3553732b9965f29a82c8c948e5db61caad610894145159754907fbac5ce62509877a5cc4b325ba36a01de5b9acdd52bad2720aa" },
                { "kab", "b12839764d0429fce0fd09c04d1f78aa3502ea8386d3af5a69ed19b1599640234f4a4db37fc7c19e201f6b47c483d46fe610be51486a2e276f22d6481b51653d" },
                { "kk", "521651ac3fbce2df7b4a3e0917964e5f81d09d6c95052c64616d58edcc08dd436bcf2b174e45d4cc406a36d5e752fef26bf616fe82cc06853ab6b9f74e556181" },
                { "km", "6839bad37f8d2203680e81ad187d77a9c5565dfecdacc45d2ec9133ccf63aacb82a774fee5594d58a0e7e13844e8bdd8f5c4c873c9fe94cfea3a41ddc44edefc" },
                { "kn", "09b09b978bf538a08312789504cc0d118ef1b7e11cd254dae5f1b99b083e72ca8e369d2eb2932ce6b32374ce41a9fd7ca092e2af8f34d2256fc9fd68c876f71b" },
                { "ko", "d80fbabc2262a4bb3f31cce41d904488297594b72115f829373e2d4e16362ee9b76f731181762ae8b00e56da964e8feaa43b0af382cab5d4af3b5bf0c757e464" },
                { "lij", "ed8ca927bbf155eaac06979ab86de00a90005cf76983800da7a2a30dd7cf6c957833302e62388d699919cc8c7b19610029a68b9a9b8abbb10e93b1b587344e1d" },
                { "lt", "7af07054c6b4c6084b21f3623861775c46c5f1a2475d43ac8849da592a4996327134df7b25cfab56860d34bda48468861659ea80ffa2f7a09d74ed6b47c76fc8" },
                { "lv", "8eac2f625a02be01fd88658b7f3023c86e50101e08fbf4ebd17af5aeb5f236c36453194342fd2f25020fab6cdb0c168ea55c285ad693b42defb4eca07bebf9c0" },
                { "mk", "bf3808c871916355a2035df545374aea1dec2fd09f546b5f1d583d4c535c6f60471da387d45c6c02ffbdd6392e02a653ee0cef65557bc19bd34683bc7b86b471" },
                { "mr", "e76c1253a796f3d8ce1f1723eea4f4c39a1bdc9786f0040754b61fa2863f522c78d4d3a7db27571b095d4cba707fe07fe13f2b46257f934a314524f992107d04" },
                { "ms", "181b3692e355306800ecb0856d4ff2bcbbe16c47c1e69811c2dbf849a38d3aab97a66456627975f089942e348fa3109fb1289251e22e3ca9f1193fc16c99ea8e" },
                { "my", "2e75455ff433e82988d2acc871095bedc06b03a232410e5f154398b322986189ccf8ffba97d0e51753e1e65cdb902a1358c2e758ecc59534e4706311dbf04c50" },
                { "nb-NO", "e8a30f8e84ff984c3569b6c1662fb6b0bb49b85227c0a9a268e062fe510d7ff11380f0a27016f497f920f23f2cf544ae1cd0b48c682a5908f0bf046dae9853e3" },
                { "ne-NP", "8160f3698daa41e8070c618c34c21275b0f80b20e595087a073888f48b206331df217f06495a3c0bfccd11743515815d1bec3821b4cbcecb72515b1e304fe6df" },
                { "nl", "0e531d3383a09d8536aa6f079acf4e1bc8a92e358473f7c2518f03529a7b2e615413212673ed49c23bebb962aaa606b4f1794574195372d28d976900a3e33145" },
                { "nn-NO", "ef836a572f18b75f865cc8de7d60eb2330df5eb638a7d73d3d7224c0e3cee49a14fd419644893d8724c800765c0984856764478d37a25e10d4c107bd37216092" },
                { "oc", "8279afa924885a4af60545a72f1b313125271274cd6520016b3c1c04ca3df38233c5d7dde79d9013df2e8874cb78d3ba68f0e9d079e83d4a8da09607388e18c6" },
                { "pa-IN", "d4a04938bc3607ffcb0bac736f883c22d239b249b5085efdeb5e872712422869666ceb8635e76f841cf6ed58b4dc1f5d889cdf512da4111b74c192749cb404ac" },
                { "pl", "f26291c51714fddabe9e658e6d0d9e9b617f1727571ed503327f7d3132b19155e345c8c7caaf6779f23e482408bf326d1b1ce49b34bc0bdbbf47392a9a2446db" },
                { "pt-BR", "62d3df12cdfc70185a48cf94540973d3eb4deac4b9570d016bf54ea10dc84e6c39769211ada2206058edf5bffa328ad9d5653dcc1ebcf965ce5879a12647fe97" },
                { "pt-PT", "a46ef8181d3b9c4dae2583b97c82db8cc3da3448e0a811c98ebbf6881e24fe83c8b59fca78f0af795e66dd017a70d5f8c0d4503caa8f00f51d4baddb9000fd23" },
                { "rm", "12f9d3ee41ca6c6710fe6b948585c2d41dd1e5e8ea8f0ad6d1baf1235418bfc6f01320d66f634603b57a0896c4349b3849c851c4313adce7b7ef641da2e232b7" },
                { "ro", "b31410f8e59d6e9bbf67a72013f56662e59563e6d9c3ba3f1084a16ef4acdb679e1b4d24158f1798c63ae6b3b70632cf4d9a43646be2c403f4ab62fb1a929309" },
                { "ru", "00d0e3867b3b5d84bc5b39a64421f057c28064a923db8ea079679d2a9af9999d0cd538b59438d87753df0d78b5550b77b56199b2d7a36250d5c67d10a07688bb" },
                { "sat", "9dcfb90c5a14f4c996ba7c51b794d03d311752d65a66e29818a0a34981f05b7b7e38aaaa7b2ee82e1af35aedd0301819c277670cc1e8565e489140a0c5bef64e" },
                { "sc", "3490cf5c190a7396dceea0ab375a961d7f8d34fae156d57e64f2226c18565a2bfa8793a899525a169994f74dd6df252327d8e5e96e25dcaf3bf30caf77576c26" },
                { "sco", "83d8f6f0211579e535f1c29256f74769d9073d4c0135c22a439e4e125aee724641ce7f0f5cc0809574ee1cfec3b15f4d524bb10858ba945ab84c712ba6c86544" },
                { "si", "2a5b9a3253e130010c936c6326d881438ffe57844a1340cfc452ddbe0a20821a5c3b59de5f2bb492611549b81463b5df593817456d7069538b9ef6e641574680" },
                { "sk", "149d3da5f8aa7b1ea316ae651285c6524ef8cdcdf456150d82055f37143f41f22685f0923a3bb4638c5926acba0f8d8d4af6756947933f4a424dea019e755125" },
                { "skr", "0a2a921c1776566e93c25c091a58ae1ad569cc019726b95a4caefdd25c2d3b6a63741434a594652f735b46449c1e5a3c05efe04fc39e584aba854a9ec9e25423" },
                { "sl", "b162204d64f5094692b7f46a0abe8571ee0b69173ce2f434a211e534ea35ef78f9d848d815920168373f1c1c8a3e5e829c78116be91afa580647ade4e0248efb" },
                { "son", "db38b6f1be752e959183b8a7d9554a4b283b966aa664f5407a3c874d0589e6d1cc17bc09f2c1bd38ab6513001b0c8f7638b11999ba975d1c8deed24a3ee55205" },
                { "sq", "8dbbac649b89a5e60a9888b9ce8e7491ecea802b2e7b3ed5e8283a4352754db76d958a8b64d2100619a8248bb5f5d1609c867d5a1f023646250963e3bf69469b" },
                { "sr", "5f1ef18377e1a0aa2f8e1f5d9dc8c6ee1884b6fafcc88804724659e718ab094321b1ffa17d0085600f02d72e892b2f7d3fd5ad97a3f928ba3da3675a7657e688" },
                { "sv-SE", "04fd20d0af94f1cce4a699162275866a6e6f7465ee2aadac8fa9cd49e7119121e8ad56d56e7651ab42d8f5aae1b457bf5221391a8108ec9f882d3d3b7017f997" },
                { "szl", "3cab7e8d5f10779dfeeda7b69f9ef1e79d17e81942d74fab91e27b3772a55d5a39b455a80055599978e2f536bd2c90d2a8c8e36f9398f5887a871713e1c58042" },
                { "ta", "37bff268b16739017cb088ecdb3bdee1fde139dfed99bc3f9b14e7c9583c7957b27450e325ae625740c84bb6f0b8a0faee5e9b0d41a1b4d42d0c950cfdd13df8" },
                { "te", "c0c5088926f036ffa4fc517df0e2a40b6c61e0accc4733626dafabc9371a1e72f380850dcb89c1bd6b11b792dce1a72a3171c75f8967cf69e7023c10988e54f6" },
                { "tg", "bdeea1412011389a859f5594659150958e53411e9015f0b9db945c1827bd59961458eb1a1fcd260de317472d54fc12a08dd7d207098b52102985bebfce09494c" },
                { "th", "3c5c9bfcb2de8c5c47d9aa57b4079847e37d0731dbe6cb6561f3116860518f62db23da2d97807fdedcaf5cf30b4e664123b9869a181d07d1b64108a592d83f9b" },
                { "tl", "cf06e15fbd8ea49e93b3eff2d9ff862620df39c1c599e576c3f82ad26ad081c18568182ad82dc809725201dcad4e51b10cc5311aac2bc4e1abf9afef5b9ec36e" },
                { "tr", "5a95224c45fc51652cd66822a709e47fbc523e62ea642b08222cc2d8b81582b6ee5bd1c8149e35cc2c0c75631fe43750fe34dfb0493e7968f848e84ff9d37538" },
                { "trs", "1eff34d57138c1d5e4f73a5c89591d19b1f2f1fefdc6f66e1a65afd00424817d023e9d96b4e6186fc348ccec9f416637a47d193e2fd974f61dc491aac3c94852" },
                { "uk", "6439272b889b1431c5f0d93f206dc5fc80ced59e4236285a496363681fb53c9a74273b05d858eb8da055d0e52c5358dcf2cb7ed35c0a039cbdf13b73d136ec3d" },
                { "ur", "4b9b52796da29bc4f1a3f2b5a1454462344b65e0a925053ab13e4678c6734f96096e7d3c896f16ee6b130149e335f6957c58c94c6dd03447192fc2e278d42cac" },
                { "uz", "3270f33e1d211e1e78c62374b888088c11987be943020339b0d58b5f5641137207345099a05bbd4b4ebc725e828b55406ac2366e7045d33e22513517615783ad" },
                { "vi", "89ff2f2e3b244347258489c85f43574b060fe550a76ac75d12cbf406ac9b48e8b82552995b2418520347355b68f1074bc50d6c68b7033365c3fce4730d329bac" },
                { "xh", "42808874d568ad3318bd55ab817d9c9bb7ad7fc6bf31c98892f7ea7739dbfbde84c080b394dde19debdbae9a0e753247aa7831cc9d5abdbffd2dc76c9327727f" },
                { "zh-CN", "4c02420e793f0d0eae677126002b93ce94201fcf6e8d95c92294db522b2725054411b5570e9d624cd9a280f3733e6568615a348035856f75db88a8dbd560ac2c" },
                { "zh-TW", "25bdf61e30e354c48dc6e35ac266c721787e9a5e1b9771697a87ce8efd6ed062da50996ef1eea04856916e617a330dff626e082a07c86fefb4c19a42588a0fa4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4b8793e3add8f5f1616a481fc435dd869654fbdc96a2c2c590853853dada7fb15c11775eeefb33886e70a88cd94f3e5ff6cf81f27647534e15ce770b1db5934b" },
                { "af", "65e1706769891f8d31ef4c2ac2934177f82fc6da127aa45c8d4eca3e64bfeeb81898c56c53a0282a13f6a52fd15b3900f636a67bc4a32eb39e1eb34809cfc58c" },
                { "an", "35796d7b05d7304f234a125cc3453973e4c358188f366405f09ae29bbde1e4581704a53fc15163dc6f6ad927cd722b8a660dc22d29d279b47f787e06825bef92" },
                { "ar", "c141d7e013ea8471643b55527555d453efab343fcfb64ca2cdbb5ccbc0b71314fb7c689a6f5a7938821d90f6cc6a368d31e8ebbac906dd49a7d338a4747e0518" },
                { "ast", "e6b3727da32834788c88bb64821bd5bf67de65ddf0e0eeb16d5cc6b001a68fc4438defacd630fa03222bfba581951f9e84472d6943917d427b8f5d150c9cd010" },
                { "az", "a17074e2af074e3bf2c4d6de5da3910f7fec43291316811982537119a842a31abf457bd446d171d2608d6260df1e5a6b454c7d6d5704e045739773497cd0c906" },
                { "be", "b3a06f89208032f33bdf479c8ac7695a3b156ea13b5970190b0c1db552798803487f2c091b6de1cd9e606a7bcb5b6117ce8acf485d0388d6a5eea0aace1fdfd4" },
                { "bg", "ac3e709b8b1ffab465ed7dbe02a37913274fc0d12179dea73b277840c5f8a8ddbd0825fd3420a52efdb8b65f215c1d5a3c1b40ddfb2a41dd02b86288f2efcaa4" },
                { "bn", "7e5c856ab7b25545d07cb638ee2d1d13e0528b5449c97daca9f260aa691fb52a188a41882055029ef3de4bd201475a7c578031081bbf134fef8a491df3b4257a" },
                { "br", "31ea121549e1f587a584a7f34723c94e6e037c6a278b7272db1af10f7e3ec007f18eb8208756bd81072f933a75d956e8b6cbb10ca64baedc01903504c39e1919" },
                { "bs", "4040ed71ec45c7bcaf6824f4ed467208d8b289b069c5c1369b0ac167335b898fbca5c2cae9727f6d4403c3cc92fd960b0d196e594b169515cee4bdd283972a8d" },
                { "ca", "05e3ea9d8102373ca861964c1a549d1c48e3dc6c26fde4e9494307afd9f3aaac9239279d9f3b2c4e31a24a7f8670fdfbb9261a3f72eef398aeb925d417973d79" },
                { "cak", "b12687478d6bd73d220c44057dc5692f2b406ab7beb16882aa6804d96ec6cdf670264320a1962230ec1d2701cd43736d165879fd9de64bd512e1dc866f69fe95" },
                { "cs", "085d755f86a9b3bce787b29eb6a1759b6afdcb8aaf9edcc90a78bca6a18391cbd12d3c005f95109f903c0e2ef7d282e1b7f9573ffd0c985691f8fc895867a2d9" },
                { "cy", "b9fed52835b7265dc870117f29992fd28865fb9dcfc80d0161885e03477494f62f50977da4269f0d89e9cbc3a9789506c0b44ffb41df4f3a1d6281d31a8d1471" },
                { "da", "978218cb654c3e490207c3c8a2a2f70a1f18d75fc09f06fa1b0043a4c746cdd36efcb38348149e952ea8997cb66f191406699cd03f8bbff7466f867d4e3a0e7b" },
                { "de", "4a3de16372d049d548429d2c8ea73de56eee795976432fce2e07cd2f602697e9da07c279fb85bf64a028b7400e172830b1ce6495615324daeb4b4970b2b107ec" },
                { "dsb", "6f21d0c24d1344f6b178db26e6d052afc825b2eb63b7b9aa003d75e9611015d560eb33435897f4295b7e178ee9d2a7fbf55e66dbaf07ba345079e9115af0f0c3" },
                { "el", "d923a52bbfd6b98549470a61363570ec301d438d499dcbd1d3859ee943abfe2f270b893369811c4b944fd1803dab17f3cd83512d7a22dc4c8188a7a8e1dd69eb" },
                { "en-CA", "f60364808703f21429ce286c69df61187a7cfa9793d7e9ed35919b7416467e936f07cf45b192824697da38016fb193ab665ece9439d2f8fc953df7dd3283d401" },
                { "en-GB", "9a42d1f09a3757d9d26b7a42e4227825f9eb0dc66109ada02c54cfb92be097ca5884c35fa37e6969c67e2cf2be5f4b22edbcde96bf95a4b38d56ad29426fab6c" },
                { "en-US", "1f49f2614159d26b4901c82e5e2cabf3653943e598a6c52c6a6ada3f206e1d0753f581a14d4b9c00f9e36280f6a41da27745177b7845afc36a36866cb12c0a99" },
                { "eo", "bcfa1f0d01334e85d9bff7d02791ca778e2e9211e650a9481179d30edad496400204b770bc8953e40ac5f9bf8c96708a81f8ac0f351e15915b9a78a85345e475" },
                { "es-AR", "6bb68d228755bad26120c521113a8e2e33fa873d3a7d24894f40a27a2b33f6e6f1ebc31fd204109f0f8668ffca2aa76ed667713e6f6d1e1e85920135f3e3081b" },
                { "es-CL", "8297d16de405e9a1d87a3c67a49837edd2b167fdf41cd43a5de8682e98b0ac089c8efa103b19e3fcd07e743a2e2d6a4b3c935a895a32a1527e1ff1dfaefd937d" },
                { "es-ES", "8097484e022336c0a8932f6b57ebfe22c473dc6b69281612c490b74c86074b7886dfaadd178d189d04a0ae26330d6219b1fe4be20e39cef85858e8b875160b87" },
                { "es-MX", "0a650607bd2570435f41fbeae1e8775721dba986df0443040f3e2ef8627c22cf26ba80bc97f7d890475974f087634faf8e226df02e841c939feeba36698a1be4" },
                { "et", "46e6b3c55e479a22116b827370b12e4939da02bd2425b4d1e9e2c8f4f5b8940658bfc72f5232f7e34bdb80dddd8f6ce902798d91865154a94ad53d73d438eb1e" },
                { "eu", "ad2fcc0b7ffcea9bf88fa0b10313862fb57c8598c6400c8fe96fe1fe15763007c58076f0f95399ff28a7bdd3efc05fc0188281c14991263e61b4fea54d7c68fc" },
                { "fa", "32aa6f482f0c7342b423a0c59408c02dc42c4535c977afaba87f40d3680a7e8333252f6f487c37e6fe17ded380c8f2d11c19987148e09572331b7be5956a3865" },
                { "ff", "652c9f26cbce5b3f31cc4016e838dd6d1e38cbf3836a4c1abd28ef882c9916581c627ebe507a009ef102f6c7194a13c05abe9595aa159437ac929c8c30c0cc25" },
                { "fi", "6a7ab14d1ce4f2cf9cf76975f3ef651b53262e9e5468a7b18a72fc5d9721fc4df99d637185445f398539d86a5c172cc6340801e0793a6cd1816997b16bae995d" },
                { "fr", "790d1241d9f5b8ecf965f309ae07027f172b9917ad68fe8441c29b3f99ea053c7a087498272c04611fd26b1fcad76ac284eeb953fe8db80a56473ac4ccf40ed2" },
                { "fur", "4911f325554d775e4e0b148464625e19877c6bee75041987d1a172d20a04b7b8e40cabe04432ad74fd5bcd3d45a52cd0e1007dc9992626c75c4710094d591d17" },
                { "fy-NL", "52519af96933355565e8f87e7e60cfffe61ddeb547d099c8fba9efc1f14f35370b2cfdab62eb82e3d311b9cb71d9500da16f56cda71a6483d76c0b3bddc28145" },
                { "ga-IE", "8d2cf63a13bd420c01ad431897456f0ea397f3835a360bebb5cb40a094a8b5a2092666d7620c38e5a91fa27698cdae56a52b718a782ce18de29330c5127227c5" },
                { "gd", "78267698c6635d0714a8961c90cd7d56b1bfd91276dc437caa78d3b19cbf6989dd005a5035c3288db2cd21052be4b4cd4eab0c7e75ca9b3bbafd2eceaecba60c" },
                { "gl", "f4ea33b1928b07f408756263e37ee77cb800ca1549035b332c5e70539f769cdfc7cc299e8dc924eb8f58fbd94868f188c1a12fc3157b07b441da769023fd9e47" },
                { "gn", "8a57d129c45e553a9f361c361e929aa1390a64320b3241a6b600a5679d6ba922f7de061a03d325463360e9fd6de67837aaef68c8ed10a67ac36fb6e315812233" },
                { "gu-IN", "7c0b7aaee5a88465c1d56e47160087a86a1d7ee6334701f47501b529de38d209a3a4a360f91c124e4c30bfeee4048bd3fb582a283da67824d0b530761ccf3af6" },
                { "he", "6d23eb485045fe084e12fc8d9cbcb8c63f48d50ea0aab723689b91529340d00fbd3d7ac5d0da8e5b79203cf06ecb1d345b1f1768de64523bcbb6531ff68fca9e" },
                { "hi-IN", "00c13788b15323db21c3c504523bda6f0084897f29743e23d8766e10befac7a0d446f79689dda1e9e54df4f6164627016b930b19c3796b0ce1447289f4ae3553" },
                { "hr", "b14b799632427173f32e188432fb41ecf2973cdd7f23b3f980ce5d933f298b69a75db54871404d206efdf6b237bb356b2e16023a4748519611672160ba19e73b" },
                { "hsb", "7abcc84283f51b699ccc020b884616c909d41b90f1fa4fd6297627a548fd31d01f38328f7fbe6424a3f7456e222bda193012409b65f0ef9943774bbc81b7f96c" },
                { "hu", "87792dd2dca95a9c6dfd0f363f2674fcd9414d61adc565709533c1fef26d1f65ad48099e4ba10bec98a07f79aa47ba53b5be8a94342f1a9b3454e7747c67e4a0" },
                { "hy-AM", "50bbb020c739d710ad8c24fcb11262d47ebf614cc6f4d31a25b896672abf513832acc7c72bafb2df13407dcd530e87ecd17a6dc2975183b02cdc6f8d89416a11" },
                { "ia", "a07f6747b5b147d78b481e7561d8a3a90f17549b15c689790cf19d8096a8ad38d7e16a24319d08fba9e55e12519d6277f69f0e8a6cc8736ff186a747f39e3bf8" },
                { "id", "953d0bf63cbbc811b19777303b61aa100e123038be76edccefe28c2f9abcadcda1fe4772556fdddd92b526d2af1e1d52c7e72fcf050592c115081cb14ede9162" },
                { "is", "1470794d406a49b3ff095fe8950c78b40aec1b7e942fffa21f2e975642e48acc40166c06b303f672e23cc060392ba7b03119348135265da6adb3cff2478d07d7" },
                { "it", "77ba86eec30d07a8ee5b115294a1c4b38f68c28d34f1c375129ccfabb4e52df8a32b69a79d0734e9044d7e43395f1a0a6c1f6d945f3a5ef2ab3314547fcd3ef8" },
                { "ja", "eba60b50db46558c820a8e39eb1d5f4f2cb2d2b0915e317a22873986b98b38343a4306df7fc7d5943c19008d4d2663be8afd1849e74bbcc916fe66cb8e535501" },
                { "ka", "4d1a48061dc05b80b5c3c03cf0140335f7c293c7b699037505977217c0198e114bd95f222c6ce641dafb3ad9ed08a6dc43f3d2f5cc8467531de13abceaa473ec" },
                { "kab", "b93b6a4dcfffde9e6b222ef500b4612666d5de0d405d598a5d620171a6a438b18d25eee4da1208e1ee3a0eaa544388ba8237776e0bfd6905113d2b39a898cd41" },
                { "kk", "14b5fdff6b3be66a16e0e019fc4dcbf30f1c3dd53a2b6e6a6b8aaae7bbedcd4b604bdbcc483a06ccd7d11f783c768fced2ddf65ef150d8666407fda7735dacc1" },
                { "km", "2e7c5083245328e09f3415da7a4f98fc2891c864dfa9a3bacf819761a02891043a783b5be6f02b63923f1c046028c02c809e946733849ac4d17205fd5a2656f9" },
                { "kn", "abfe4dcede4c9a24f31da812bd71f040fb73611c8234dead3fc48b1e4900655e6424517dbe834690b8c4cb29eee48443879c188c6e064eb5611c1eedd5670f9f" },
                { "ko", "d035594e620cf6e1a801701db9788480a769e0f185086cab64963e2477b84cf37494dfac4706a791ceeef945a627b636b53861e919bcd1ac5304ee1f2f402c30" },
                { "lij", "17b61adcc2d2f9f33c2f45bc1406788db65b7d3b59f86fd531102e19c6f70430cc50bb6464ac3af4bdbb20bf6c07ef91a54798455794a286b2c6abc9ec925196" },
                { "lt", "c8c188c9fe70f0d4170782c38c175616fe2b39e4b05c1b7e5b1c61661ff3fcf900dc4e15f8c94dc5563a6de77c7c46cb5c0884206f0cd1485659d4b0eb64352c" },
                { "lv", "a281027256f0f1063d4464770fe291cb28734e18393dea28690582eae35b48267f9a957dd8fd3b7ad7dd38c52ed6babe44129cd288e3966ac6e24394ff7b0e22" },
                { "mk", "097de29d75e3a0437e77a3d999ad6e72e7e8ee42d124aa4d4bf051c48430682f33d665d4960665a6d31e54a0ca8f5e99eef4c33db3a686b6c12a44124a5f5081" },
                { "mr", "e50ac9ab242dad4deeaec1d4a148ac5eb5fd683388c5f15bac3fd99a2e8168218745bd6e5836e9cb2d0b040acc1340ac2482a2c8ab11fa27d6fee0ac33b9191f" },
                { "ms", "6ee9b27190f59a93c2fc9df878fad918f72d0a68d72787a6d6c5a14a812eede92b7026ddcca383f1696249f6555c12696b709f3e4a4d95f03af5c8c82a503158" },
                { "my", "d88e071d1fcf4fd841307862aeae93125a35be3c54711466bc23c80f5c5dd06d3cc1ad2976e5a5a12ec95802831b01e86e31c514447b27d238b28e9ddcbb4100" },
                { "nb-NO", "a43856e48618ab6554247a917d3df81b674ad6094a8fe0d5072be0abac4124016d6a46d61870ec338c6bd6eda85028c206d4c083c602d43e1b938d97e1415891" },
                { "ne-NP", "87fbedd3cb4a30716cdb57b5704eddda666b519b6b3c778a87dc3d9609a8ad0947927384625bb8520d3e32b0d48b131fb94b706166f761f2a4b4e0638258fe42" },
                { "nl", "d7ae02941242d16676aae4c239c7f321448fdf0f6a3c9b691352f1fdc9c4d3571f95668ee68d0053c9361065adb604535d6a99ac4ebd0acbd849b7d93ff033e9" },
                { "nn-NO", "1bc4f42cbf6e43591a027355473abc53af8248531d49f7245bf5cbff396e6c1ab8422fc8bae226dc99d6d494b7067a73d8e1302abb7fa07028bca35dd04b9b5d" },
                { "oc", "74d1f7151c55b2c945fcbcc7544b72cc028af4739950e49fad7009fe2abac12d749282351eb224baa1519da984163609e8fca16cca608252a1d8a117e8affa7a" },
                { "pa-IN", "257883f20ad332ac03c2cb260ff314b6494689a0c416963e6cbc4098838c08285548cfeb7f4660bd901b1159c48538ccaf5ea5e823c7239fd7a0c555d29f51f8" },
                { "pl", "53b33934f191e296b5c4ead74aa69e01c72e0e053fabc143f4185e9796819b226028c018ad901f9a6d7ec16ee9bbb1b7caf8aa8e0b47fb394c8c4a13f244e90e" },
                { "pt-BR", "d3c2db8fa7493345ba074ee2c86fb4d209c378073ec13ba9a940aac11ac42a315805afcf14a232768c24b3a030efdf9b9ebd18fe0d3aa009e92a148ff655bebf" },
                { "pt-PT", "d574e14ea4dad1a6aa7d6054250f2b52533855c6c0853a8afaad717444c307c89066d5c6d8c2c3461ebcb1a226902e5edcb9a8c4a521f5477acf0fd8d0fb2336" },
                { "rm", "1f145b369c5edcd7e6059089cf6f2f0b7044d51193facddbcf5ee230f0274f041520b9bd309fc472665d624c9df4dfc57231d3f40bb8010c4e26500193bd499f" },
                { "ro", "a40a7c0f699ba889e04b5ca95241275d29809edcd8ca6816c768b9f0a7b6f463446aac942b0a30de617547fc2565791b9a428afbbb033b313d22f8f4980a3dc8" },
                { "ru", "edb4bdf0538a9dae95e8bde20c4f796cd71a897cd6edea273bd34d0fa2978d6b759a414ad8098d289f1cea6d79a1d8d68158fa7b4897a455a56269fb0a188a6f" },
                { "sat", "2a1b048e04e9d8c3f93f88c3ececd2a61a41671543b40278ba534ab9c3f4d2592ac0d497e373801fb30a4b6218e037f28345b85074df0e87f80fe8c2463eed04" },
                { "sc", "a8b7aef9368c862819f8ee8583984e9429980c8bb88899f67a471768a79a9f22d6fc3bcc483d376cabaa2f3bb2b9d5419203aa7a0eec427ce2165f8fd2959566" },
                { "sco", "98d65ff71985e430efa4192548646875cb6e088df755aa6816af2ee2913d250951c46f472c9c9f00f70aa47e084e06faa9454f3e2c183425f55afe17e35a4ccf" },
                { "si", "493f27ea4c047ed84eceefb0a02b31743c4a361b37dd228136de98e882bbd37efedcbdb08a686fa80880d2c967bfcfe13af525e7a633872722c80639040661d2" },
                { "sk", "0b2cfa6509f4780c6070aa94e52319b7facc8efc1f02b6cdde9c279b25e3ea9ac57bb8add00d34b8376b155035c6888e84fa865ae775b533c73455953268c5d8" },
                { "skr", "45afe5f5fa750244faa6c8c051a2a13ffb41023df310d1f39dce479e5a0422d7aa77aa7572b4c1c49e524d84a920b61568cb99aa7af7a1e3f33d04e05d975274" },
                { "sl", "e40e2c87f1a3b88f5d4fa64e282fc897f36ce3beb92bbfce18ec22aed8bd7a0cac4f7688fb1a2a5be7fa0f6e1d4a5ccc7891cce8d2f372538b4741e588c5e5b1" },
                { "son", "1e7897709d56df09a1b5ac8dcd338778b84da6ef29d8bd7c60e61ca11fe080c5cc88e3f051d6bd2b4aaa80422b7310b9e8fd1790252a3763b7c607468fc7253a" },
                { "sq", "3ed23c01e13169931ea60a1b8adb795cfe7f344048977dd899676402f84247ee43e9bcaba28681a1690dbcc173876f9550fdeb406443350c5ecab03a2283fdd2" },
                { "sr", "a960a58f16f8e6a932d369f771c1071cd366be9540aebc1c1414509c47a37d378963cf361fa817147531fd5739402f2005a53ebaba7a5658eb627e2c12049ad2" },
                { "sv-SE", "d7515f4d87d8609e464d7de2a8756ad9b936f68fac1c2aca3c01db33daddb30d6219cc84b4587f93ab68d54965eb853e7ade7dc63bfd4a09011f2d8d272f52fd" },
                { "szl", "8f46225a1e9207c8a2b49f70318f73c1792482e0f10968c98cc09d389b55b972817a583812fda2f754f24132b42fe898746bd09ae1c316e77a38860ad33cc802" },
                { "ta", "7e129d9ca16d667debc04e40942ccbae374c72a0fdfa8196b6c9dc8da09d5918f9b95977505abb055f04f27458be887ada0db0cd9a8ecb0356a71d214d4725df" },
                { "te", "d9a0a524058b3b7c0965dfb19535debd2b2c039a023b59f22f47c846d117a98655b5086a2ebca7cd0d9db797f8103631b3641a0bdff98db403eff61cf2f909cb" },
                { "tg", "15c6f02969fcf54103a539423b6b7f52c59735cb817617824d9a64edd8979d26c87c2800e2f65b841e692ea2dff0abac7c392eeeca09af90497e0fea021c9a79" },
                { "th", "9b5fd1e989469ef91de135f058a838560d35a869412f766208c9ad382259cbb67f5a2d5112717a1c104530d2c9622e4076e740a6d8ac9879aa5cb84805f4b09d" },
                { "tl", "1e14bd39055ef36fc8f13c841513b3747fcde1633f2c9005f273bd6cd89b7f8a32f4cffa20bb29ca486566b19899bbdcfedb6da6366ab319c3587adb6f47e26f" },
                { "tr", "0b5fdbe23965da56666c41142b03ccc1aed26e6ad1b970938edc16841d7fb9ffb9e20fceec38947027b279e35708e0d4116f79bce436e7c4e4853d2fdf444a84" },
                { "trs", "e1e6f33b9f7ed9829ba3e70ae789e1a3462f84cfda111e6ef639abbbffae8ccaf613e17c6529e25af5252e2b6733748192af2a68c7cd5e6f2c26eea779c99e83" },
                { "uk", "a4aadaf6f11e50599bc1b9ca8579b3c93057d10cbb206bf9335a0642b7056550489878e5418fa393bb2f5908335c623bda63bba873faa8d67c638e0a2ca1dc6b" },
                { "ur", "99662a934bfcbd390e7dc6d2fdeaa8253c7bf115383d043133d73782463653ddc8eda9d5b096ea82726bb29c680b723cc8551de0cb0f81b1dae28352e32480a2" },
                { "uz", "462838ba2b448b13f333894f1e31442b2b28133ff9471f3ee805eda68f69f1c987c6c5971fc38e46d90a103abfee600c6e0eb1007a39c0197ba36787444b0a4b" },
                { "vi", "03a2ba7b77094560fcd3f9d55f149cfab74b282ceb5301a88744e0ee8dc3327f86238ec4a469dfda0fdbc5435d1f0381c8fb7975fc5f53848cb44dd48f587e7d" },
                { "xh", "d1d2158b108fec76f1bd15bfecf9dd906a0149ca8bf32837481036b37f1bc1f284f8ae934f0c251e15525e18a82e75d8ae731eeb4fc671805d548c78969fd27b" },
                { "zh-CN", "af35920172cb3fbd1f8cfe654e2bc6ac9970eeeecaff6e705cbce5893b62b1d7f0883e45bf067d8220aeff6a4fa7f606bab01e2edd8d9e50f9298ba9ab4cbf0b" },
                { "zh-TW", "a620fc4065ed7d9b731094d27cebb2e9ee06cfc2f0fbd8c430ed580987470e13e5c258d36add4eed2eb16bc760e21068d570e8e3649f4dd40935cbb307d0512e" }
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
