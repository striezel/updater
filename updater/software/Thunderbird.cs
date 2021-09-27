/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.1.2/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "9b5bf2be44cc623c4ce3bc34e889b450e207b2b6c3f6da3b5c222a47eff14adcbfe92dd3cc00398ba271a457604bdc2d3f6ee0b2816632fc6caea9a247d85daf" },
                { "ar", "51692ea633353689911f41d97a75850e72b3cd7849816bb0ddbd5fe5f1177d513e777b8ab25a89f7bf82099a57fbeb600f8b3431f39f9bcd55b2b08d835947f8" },
                { "ast", "cba4a23aed78dfe7db6377f22b4576aba20589b8336818535838200732c183482b66e4f04553b6d2097bf3a909f21e204ed5f984fbcd822110a98e289b7bfcf2" },
                { "be", "4a0dce70d98cb6e37ce9600d5c0b84a625ac5c8595d165e91ea50c9d0256d469f42c3c6b64c46c8744e32f67e40237021366822b67b651ab1dbcc48beec200ab" },
                { "bg", "0f30da6e8b49240029432b3f00282d3dd2058ae4ea4ed6a0fd151e6c044adedfbcdb9cd52a2f43562132411743d9e05e3a8bf19d767be35b39fbebf38bfcbdd4" },
                { "br", "bccb3b6a4e0d91e09b82789e60de67ae93a3c2b8f0687476d5e2d771f24ac773101ae98e6e307ef3a2198646214524aa779b75190c3caa6ff6a648efac09a1cf" },
                { "ca", "0666946a0d7e34cb8195ea5746ad16647d41e0040ff0a89df875a6feef7c8a6f677994fc459f802868a572d0367914b5fbe83a6b10943cc2ac817a1473826b3f" },
                { "cak", "b02ee8bcd37dbefece2ae3715625315868fc229b2f9fcb304de2db393c3d2bd869b07835dfaf0923ac5bc7a2dbc1c4ed42b6455ead4ec9a63825e7971703ce28" },
                { "cs", "1f0f8f80264e3fb2dfa5e784349339ab80ec3d67333266f0177fd4bb13f0e8258453125c8b503788533aeb774647dcad7e94ffe23595ff9b0c5f234cf87f45a3" },
                { "cy", "162c3188130563dcc922f9ba54d28950b4fb30a75f482601b7699c39c85277f39de6aa05d2b6b7efce0dc4562d4930e2a71ccc60ea0e182d41488295a5686172" },
                { "da", "10e829fa839b4a1f495f55fdd5b1b9c76d742b0a3c13c8aaca337ce2a0236e00dc9899b81367d3e3482ef4921d53db0a2b0696ca8d768b019dafee4299cecb1a" },
                { "de", "ac4b3b56b9fef5dc1cd8dc70393cb2f2fb97405f8674937a9970e9afedac7f1d812448c40413dc9d16b4fa5bdb14be6e1b20fbe7b5b150a07e6d03013bf030a8" },
                { "dsb", "1252acc7eb1b18ee8c8d4d501242cbeda540e93b8a719401358bfa88bc844e3cca9285a414288764f3fdc6d7fb08a683ff9e920c88c3bab4f1cb0b90cc45bf94" },
                { "el", "7eb01d48009e4526d0411c3b38b820666b52c607307282079b416af6296fbd297b5794134342c110d80130a9753f801f94b38d8f03a1f9f6646a6596e54b96de" },
                { "en-CA", "7ee92cedcf8263bf2f47acf8f8fd3ec8d41b95ad4b983d7d05228e8d5019a4d0b4179164dcc418798898746ba3204e103383523a3f1e75071aff3d0085437803" },
                { "en-GB", "e005a225bb2cc3d471a5a70340390939b43754a6bc46552e96eb51d7515065f4e76a46d974055d6ccdda6449f8e1807d1fdf0c8ceaf58cf5a4b9e123e57f8ba9" },
                { "en-US", "bfdfa936895cf19fa42bf2d0e6abf96963ecf6e0890a9b623047554dcfeb8f518f748335fbad78e6adc02e602f8f9100110d652eb8b32cb6596d8a4204fd02e5" },
                { "es-AR", "10aa6a250e66e4f17d33bf00afcd3e74f82164488af9ebb50725b458e39af29d1a13d8147ddb2d37a0d7e189590b27daa0024975fb8eef8f4ee3f774aaccdc91" },
                { "es-ES", "a2481c2b653116d5ba0f4e6f28c259ea4201d9759acb243fcf34ba5dcbbf934ac659dc6b3ea28b7180ea758fcfdf55b4e30935efeec798c46416224f3ad4607a" },
                { "et", "6533fd8ce4ac4e6785138240f51299d22289c1ec08414d91f9fd27651306ce20cf4afc83e46d5a6e9ba9cc2630302a6372314a72a8216eba8d5744d690dc594a" },
                { "eu", "732b40e22e5c8721618606b901d1b733d285f071fba1909e63b44d0209e7bccb580f0ae46551b1cb4b6314cff24949ff66f5b4953ac395d403b3e6200c91d381" },
                { "fi", "ad65b60cfc6b8a521233dffff99d661d24e776d0f712ebc837ccc9038b8cf9b105aa9c30cd97ed8aab5fba296353839d324b3bae5b4c662508de94a66bc513ee" },
                { "fr", "bf095aed51fa9960ac1e253b95504773add57d42b351646ecf0cc892b9d2f42c32d973733b188163ce4429649703278868cde89c1cb4a0be21f2157615e94cce" },
                { "fy-NL", "0da6e25e1b0824c436f3e49dba7e2177ebaa268db12f8d5319ad366eee7c47528e27e5ab14cac12cc23a1203689674d76c9b4a8d1dcbb660b71a1ee8686afeca" },
                { "ga-IE", "2b9570d861ece0d6da993e11726f5135b30c3017f86a7266491e2ccbece29f6d213406f9a400bb791438c69a70dcf32b024803a70703b47a9bdbb243417d7bfe" },
                { "gd", "26dea9118e5b6a109ea36f242a15d124bc72b952049d987594a19a68b55694074cfaaac3048fa861bce85ccc8044d632f87192b27a1d486ed1d568e31f63949e" },
                { "gl", "c0d9d7390294089f1c5a9f748bdbdaf825010d24d3df0cd79d6ddf25a22771f621834f0172ba0200e8f11c564ca4e05f849de80a5a0e56b2f642da1fe9cc4188" },
                { "he", "2e0ed17afba0b69f16b97be20e030d65ef2b4ad89debc97f7d1ecdd00889090d1c855f4c2a77a809b5720a0aa5f3eef099a9428470d5f6e587ddef1718b00026" },
                { "hr", "a929c6b3abbd366f3006a1890da9655a6a5326d87c574725cf6a4a00d1c0ba6fffe440517d3875fe4e7746d9276fde5da0683b83ef5ed78cefa1a62e24f7080e" },
                { "hsb", "bc5d977c2a2894e60cebdf7a3ba0c8ceb4ce5db598a47d533ffc36be41bd6fc0269fbda5b8c107b27bbae074bd683f121c96e4616834637777120304bd08e8fb" },
                { "hu", "4828f57392046165bfcadbdf81dd9c16ae75b8bdfbfb8f7850331273ed9eb123259714a76d75b2f56354e9e87073a5e4a218977da060c78d8f34000bd6206a18" },
                { "hy-AM", "2b240b200689c1acc7914a867a4afc0e3ff6498c16fcf4bd831ce53a18573260e6ca6e2df415ea128f59b89129f2d7564f00f9ca6d7d4d5f7cf80777f10a5f68" },
                { "id", "8d44de926f0f69bd34e3a977a8715a45bfa0d95adae8bb4fcbe9c0722275574b64a71373117276b8838fd116fd1f839d6ab76d50874bd17c43b7ed85d59458e8" },
                { "is", "3b4232188ccd853f596cdb5f9ecc851e2d7b4b694159868627ce4866c75f5cd1b6f130c666d8436bc82d516d9757e2cc163c76c3d9a81b3a2e18f4234a9e4ada" },
                { "it", "c9de7aa1d0db17c2abdc8638263be9a99de00af2c6aba598589a0180e8bceb1f493235204751c92eb8af3ce676e95c5ffbd0ed19d8acb2e9c96d841015cf4be4" },
                { "ja", "0063c36ddf751f1c759917ce49e491da26bd4796f0e0d3f5ec18a753fb6632b033769054e6e3487da04cb39bf43dcd23afdd511e76f1201c4578e9192b8ad7a9" },
                { "ka", "cd2603ab889c79ebfe6a1a15cae7e0e4baa6df67406dfa0c6322034d0b22a1c2834c779f6ccd2a71c3bcc2d94913c11046374ace225c29839610fbedd57dcf95" },
                { "kab", "3949aaabdd8b3725d1af029182599877f6baf2a075669409a5d036493f5c1e0679bbfc85569567ab2286776300d058350dca83798dafc42afb2b53dbcc3bf4fa" },
                { "kk", "02344d18f6a15a24cacd42bdb434645316363ff8700c7e5715104257d787884bfb780058909264145ede05da35df57d23cd0fa8796f49c572e76d4902ff8c85c" },
                { "ko", "03a112c981128397d0119ef14f811316bfc20c688a1366c75dad13ef4fd9420414c54a9e0b689c721e25a99286e91980cde61873b7538325f51c13edeb5861e2" },
                { "lt", "93b1a5ba392deb6e29114c5573fde618d805ee23d6d0b50815ed23913c13793ee1ea5a4be728299e2c0d45c70a2fa46ee42864120b7e72478928e582f44a9466" },
                { "lv", "d433fd8d458f2f436fb8b298363f083e2ffd764bf027568affb25c25390354cd20c10e7717d6e387e7316ec0a3817a586fe600453188275eab24ea11b268b514" },
                { "ms", "77de9c28616e9b31014fce4a25c405576f53734a2cad29e3ac74164d597de6d0afdc907312bd45eed37557914b773e1d59fadf32bb8292bffa3db147679c5bf6" },
                { "nb-NO", "28766fcdacadcbe15c806b1cd92d5ce74f429961b8c12794b1beb83f234c839d3ace2031d23da580acd7315f0e0f9282fa6593235242c93416f7d518dd819eb5" },
                { "nl", "b95c8b2345d75767c983f2adddc276eae4ec00a5c9c46b726a46c7d0d8ede3b4d4bbaa3d5501b9b580a94e0f7240c1e59709cd91d61d98e1d41dd76552e9fd14" },
                { "nn-NO", "de03911545526adcabbb189a6409fcaff2b01580cbe5aa698f40fcb867d388f06c52af2673dd8f9b9f9d5bdac5c1aa4bb9fede2a731eb33ea191b43527e335ee" },
                { "pa-IN", "88d581ba391f5a5cadaea1bb1e405404a0e0125c6eaeee41ae97487e0e28a3b8161f9c1ddcd0c19fb7329574056c84e1158ef4b4ca811760578ce54e36357aeb" },
                { "pl", "fb1dc4badf92ee1a59dfbdf5b9f44b05edd36d5473630843b9b8716a635f851384e9bd87b39b968941671db3ec3d709607d63a0f1bd067108df0ed790811047c" },
                { "pt-BR", "68ce517b939b25fd6c25c2c13894990a6cc1d625a42f50867b1c9bf614fce27a0d9e56bc272f43ac72b11ba2080b1667e23292686602c16bd970049430fb502b" },
                { "pt-PT", "b46a8ff376b5ad6c6d8d33630907fa8d89d9743d1b7df8dec9e4daee69f639433702c9003e30ad0e47bc1707572bd8b8061f251da95c5f8165a0723417e4da8f" },
                { "rm", "e1de19e4779498a953e711d630d58c571e990f4d53cd9aff9b08f05ff01b3e41d6f033f1c08f62f48d49f1f73f44ebe981557875e532fe986f17f3da42bac7ed" },
                { "ro", "98eaabbf94a152f2eded646fea2030936ba71b439ee21b827815c02fb05a3aa39f21892ca1fbe7919a0725095c7f844bf71867a27205a3e3654b19a522cd39bd" },
                { "ru", "bdeb9381cb83d44333d166416a568f849e67ec46cac6fe03be0796be467299cce2308c501629645d0ff3e2c45159323b6bd772db75dcf0507485aafe69920497" },
                { "sk", "a5a15b6cd9e506306ed148dc38f7e596172d08b9f7ed2c7228305a3e1baaac0f8310f690104e35df715d97d8a4cdc921cd8a259f77748470beb68735328930a4" },
                { "sl", "bfda084088317e5c71fa1230af466c8b1a34c997738358cbd566baeade9445f1a02c8a82099448ad0dc6fdd9e02661ca585f6a8d36be5c887f9fd1af7944184e" },
                { "sq", "e1e022db611b7a875bde61997194236d5f097061567cf5e3c1be2c729627cfefd4c5f5e8c9c6fb2f6201501f73f1fd3e7f8ba1e3d68daf2f4aa4f94612bfa19d" },
                { "sr", "81e49fc77da0f0c0c1dc29573cd4cce3ae2a806e9420a853ded8e658e385da9440fd671205fb2d68f02aaea2f573e34f1c82aac00e54f4fb58be06a8017c98fa" },
                { "sv-SE", "7c0f2b8528acc496b0f1991ddeabb688b2141a56fd379b968510e48bba3e7b1ceac857f56ec313221fe6189b22615f769a2427891555340d458b5499633c0106" },
                { "th", "a640dbd4ca51268a065d55bdc1211781ca818008f5bb4358b3034e467446310de468956ba95462bbf1698b072a7ab62f971f0e1a83a38e49cbe1d5bba2e008c3" },
                { "tr", "7dce24b3317758989beaad5ae61b37f4a54cc2116cd34a57b82b351156eca08993b762045205eee8d988ab5c46558dbe04b8c6211961d594b8fe90a6a6bcb9a5" },
                { "uk", "211fd9ccc04610f33e2d49e6d5e68a6a306dffb4d040f1d7ff36875b4236480d467a3f1898e4d90200e1a1a8364738cbd22b3d5560284a7ac665b039378a2a66" },
                { "uz", "6816a6591fbd185717a930883cd43c4de83655f3c15ccdbc048815041e00edd5112795683288f57e1624476cb21a1657d34c7edb6d6fc9b47700ea93acc77869" },
                { "vi", "8b93920e6ded1cb7d66ea9880965228080107027aa1208558d2fa91275a2df6871d21dafc1a0fb58c56e8683927654df2948ec6362462647cb3d006f1ccd492f" },
                { "zh-CN", "626520d63141beab49471b9c72d0d5dd1558e6269f0398a624fae57921b518c2c3e5f784167a14fb188372be350fa968d303b2b4f8bdab549cba35dedaec5cd8" },
                { "zh-TW", "d587e0a0655fcd7ba198d8f41aaa560d9349ff36f65911ff7a384918f6465b9bd6de8bc259ea3dc41dce656ceadd3eb492dfc7322a0f726276e69c4b32c0a229" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.1.2/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "a2e8e5cab2ef16c8ebacafcd3b16388439926d992947747c9f3830e79838fcd2414d8153e4a3eed6691b955fbb4f89f3ce1bfe56ff475924dfa25767f9ab5b12" },
                { "ar", "46a3be621e84e7b4eeb5733303fdc341c336f29108655ce06ad0d9e658d100a02a731f5f9b50d6f79311dcbf90b91de3e34523c982e891bf63d23d6245803cdd" },
                { "ast", "ec0b6233be96ca85eef748d6d083850bec9e4888fd50164e4f2984136cf65726588ee0daa4bb8c39f41d84f28dd894feb0319d8c1ab81a9af914f889e0b62194" },
                { "be", "5687a0ddb754062da4045134edd8cbb9eb985fb5f74931239b461970565b3960c5bdd53f91cb1b1a960fcf1a37ff67bd6d9d10fda87723e8dd48ad3eed981b88" },
                { "bg", "a063157e067e09984879c932646865fec84b0c1c42f250d84715487fe13c10b45e6a83c52d67a449672d12c5561f199b7b0c5f133836fa9ec58f38b0baa5a798" },
                { "br", "07ce34939be112e17bb2e8ef69a8f51e4894f3dee2b207cbab956a16a4fdff9b731d7e565599e5b10b7a37561a019692d980008ff751b8204624044791b373f5" },
                { "ca", "ce05df3e54670282140582d8c721c228283b33c1f2121f4c8bf4f7fb3b96c064162327ddd92178a8124ae1fb356f3b0b4f6fe2f8a8c0662bf9e18dbf05370b31" },
                { "cak", "8a495836b5d7e9f72abe4b03d08f08e835ce8223cf603869f8f87f4ab7684f431523b9f624f0186dbe616c4fae36b9ae0d917c70182fda281ad7a4a560f7f16c" },
                { "cs", "656de793273fb112557d0e68346aac7bd35158a6d40cd4f2250390f9befb6568851ca65350302f8cca72f945b8957e33b5ba63b650fb36854f91c9df8dd83932" },
                { "cy", "c9364b337ef0018d058f2038eb18ac5a7dcfebf8f89218a9aed7e7b2c99386f3a9e7fa742c189d9f3aaaf7045fda8800e8bf65292b9c902a61bcea440d3474b5" },
                { "da", "14961d854c23ed38ef57c2f80141884e31d45a7a9acf40a091a69c4c9217a8ccc68e8dc82c41d21f5b1ea990a0cc51c010cbc53475c3e968406e4405db28eb43" },
                { "de", "8dcf3db39566731a75556ca158f0def9dbf112d51bc6b461a69bf4e5e324f5b01ad3b27e1eaa6653411e3bd99ea3480ad2cdfe071c72c817e76a3bc2aba33b30" },
                { "dsb", "d8cfe5ace0844017da1a984c583d33ab8ea5c854bd7022c918e93c73160d4a4f5165b07c69257375b62c457bda86e39ff4f6ef87d3fa2d15362fb394f4099ce4" },
                { "el", "6e21f64b6a575737743d44f606cf6812bc881bc37d2437e2fa47756c0885584755358eb6aaf119f820d192df44ea5e5f071fd1646f64ae81065b64d13f9446a3" },
                { "en-CA", "c3fbc159e11b96593882106f28acd390dc5d7ddf5a8087410dbe895de194598a6cccd953bbf0ed065242ce80de48ccf32092fb328e4ad15192c69ae7dae8245c" },
                { "en-GB", "32e88d78eb8b30b9dee82632efd52d014b8243a15b0d69f4fddc55c38a47c8af3df7c80df2a55743d16e9362dfa20d31eee28166cafd58fdcfcc946bf13a0fb9" },
                { "en-US", "15ba3be640ef5507e4cefa588d17f9fbdd5e328261dd8bf71146b0ab17146a95caa89f0489185256903dd28c73edea51ea52ee861296a95c000b9f807df71247" },
                { "es-AR", "510a4473ae11b981970e00a2f29ffc5a395ad484facdd89e6884eaa00efdba784854f85fa70add7598f97a49d5553ee06e4b12b2d9cbd8460a0225599be3eacc" },
                { "es-ES", "cefbddc175773673505a5aae476e23eacc37f4effe1200526b514e79c1591077066df782663b9bd848514e8b68b80d467e00ddfb139d13ac3fbd1ede5f668dfc" },
                { "et", "797614f2bbebb281e3dea1c58b7d54b0aebb80709dfcdd5b12273bf382e63d63db5b7b91ebea42c459f3bcdae158e23d11db53e384751d094b6883eca9c4a62a" },
                { "eu", "def7c009cc5305422ac6e5d1bf98090f75c6c55becb2af214ddc14d9349e43ab872576e906014d32874f6323b3d600b03a785d3223ecf5f34832f954f7bf4e82" },
                { "fi", "a78eda33eefe9b3abb31981eb344e3a02da516f7d5a79ae119202a8c60e31772d395f69f3fc5c1cf9d6c4119bdaa3fcfec1cc2ca247c8ac55f5330da88eadd84" },
                { "fr", "1dfa818def4eeee6f0e4bfea1428348363c210b9abe28394e081588fe7e385f409f4aa088e3e8ca5ed57a3f7b26903eb6d18cd1f2858cf0de205d512666c0123" },
                { "fy-NL", "50b317dfdecdd6535cce8081b21f9fe20996e771e262b2e00de879219af77f7e33807ca33809e2332a398aa8bd490e58b5ee0358518432e56a8c12c86f10599e" },
                { "ga-IE", "368ea46802ef9a2f66d9313c655c8a40ea2c730c4e56dd72937203e4d47acda0e2a07db809639e3c0cfeb01c05ae2a55e7c2ac27c83185fbb94cebc94eed5f4f" },
                { "gd", "200733c6b61ff7e75dae938b847658aed617d7257c741795384e43bf6f7f82ae57c49a3323d1127b7ed718c07935e0470ebeb05e03f24eafa247cb217b9d495c" },
                { "gl", "edb1934fa3bc5470b72b7570ee9d22a4bb8b48ff8cfc80bdcab85813778d24ac918b783487af7bbbceb24ed28bfd31d21ce8abe9a764e9e4103fdae4d7b6a9f9" },
                { "he", "dd81462bcdbd98eedaa9cd4c4fe9bbf245fafa91674fb1f724e16cf508c1ede9147aae5b8b5fe0c3d6cad6eeea860ef9c30c9f1f9d15b3fc850fe02a19f6f5ec" },
                { "hr", "e1cf6609423a38b3c69a1dbc1c8c4d49cb4de6b46945e432b527690d36607967abdbd5cd7f081e15fc9b6b5ec76f08c3985aa03aa413ac9b5b2a6a679e57ae93" },
                { "hsb", "1adb8350b16ca005f9f0be0e40c1de211fe9d817bd778f0b4a81d0dbcaeb640553d2a2200207bbe71a4650aa51dd4d5fb407db45fba93fdbe8144328670a5816" },
                { "hu", "93d21d81998c9c28f29aeaaaf05512c20ec6c1809c950f9594fff192515b4b4671fdd16664e627e49e11e2c1231f39d02be5fa2f98a2506f065e6acb9473be99" },
                { "hy-AM", "afe1f70abc43cad2314c237abe0447e1b9b249f5829f7246e403786b63f2b50daefb35bae02db45ed6e604a82b023cf2ff48b9a3f5cac1f3d810521211f542ac" },
                { "id", "d7b75c5b9f3891bc44ec45a5c14d4b6336324c7cf193d6a91703ab10932ff71b14f2a500ee383923521f346b12004360ef164c6d353a2bb85dca55d7a48b10fc" },
                { "is", "8245e9f2090f787fe9f7d51f090cbaa3ed817ce919d273b790a34ff1af7dde66ba60418722f8d9923cf0858c3a2c924a31d039d369b3af4a926e67329bb6c4f3" },
                { "it", "8cba2030a5f54cbde40ce2a76d673d6f5c2b61faf2cdae94bd2b23265a39adf3a0d1452bfd829cdd5fdd8a2217987d8b2e86e13b6d3177eceeb829cd6b6adcd7" },
                { "ja", "76e91733cd69bbf31f4833cdb0f74cd58001efb3bf794bbd27eebdb753549ee84a6d966d23f719b687cfbb2f162f69f8032a6e68570a1cb704db9027c0508ee6" },
                { "ka", "dd48e30ea1fd3eb736e082293f2b13e6e5b529fcd845a0bc30d7b4871f8f9c037bcd9cc8747b43ebfad4bb00100b5091865c262fc9189790022d89c8c3c9dcd7" },
                { "kab", "192bf7d3c8ca1e8e3423efbbd1ab9d364c4b0e69e4bc12154231d332b8efb322469ad15f46c76e32fabac094f4642ee7a74f6103ce056a96e660945fdddc4c7d" },
                { "kk", "639ac4ac2cd39520ed29592ed39a9139ffe36c93b9e925159db8247ce464091a297f471fc12b412b27fb83cc8412becc888c01124eeea00da83b6023ec0d1e0e" },
                { "ko", "1638f17695ef6f58c96ebce7b9eae879cd694207dbdfddabe928e93dbc5a213acfab9484f630d5fef4754d6bcd5774ab07e6b1a37d73952cebd43ae0869ad13c" },
                { "lt", "05054eb0be879dd02d1a32473d9ed3347655b922101a4ad35455189de5b8f91ac726a6ddc3f0c8ee0b48ff496bb5def06a49e7974abadf640fd6f09ad51e0b8c" },
                { "lv", "e080e87da453f0711bdcce2dfe2f111d02a7e5e1b48dc0375919fc109382e316767af4dc19904d9829f0ee31a878a4c0b92f703ac32d280a2ff0d15b622b4968" },
                { "ms", "9feddac27c445283886dcddc4da83d97e0a095250c273084dd67ce148a02ec411d717e5eb9b6b4c3f89cf45ddcf777d56666c046e41a337056450f21677ae9aa" },
                { "nb-NO", "1df3e869f5cab4ccfc479978b33a8758cb5f6748336417f25874cce2b54cbb3bab8f62df30d51ab5456c8cab7ee6f3b9cdb797445f3ddad335d85b20fbd6741e" },
                { "nl", "afe95305c401aa01d05cc9613d99c2f288176ec9f9d87632f18a967d6381c3eb2f2f2ad40f759c381d6a26dcd0bb303be502299414f20aaf5d54f0c99af2db8e" },
                { "nn-NO", "bbd36d697d824f5f8b9b00630867ab0e3f6fb840fefcfa496de607a09ee1391e7587bf5ae00123bc6c663550a5f867446ba49baab86b2b1e9217dff368142e09" },
                { "pa-IN", "44bce631c655adc3ae7d0fb68b5202f1a8ec6cd4b133fb910413bb269725712baf40d8cf4c96a1ab6bae31146bfc8491c8d40ea39f60aaa352c34190e1c3da4b" },
                { "pl", "bb13bda8a0569533dc9f5912ec8f9c37056a69683915522a084b1f30dedd670324477c7ebe8d96cec616016f2e182a0f29dce7cba1e3bb0af448fe06fdf20495" },
                { "pt-BR", "035d722da1d93b8056ab8df7d99459b9068ef14594ef92bc8592173875535f97338a80da39c79409db2f3868eee761eb920874cb3ec1b1b9a89b430763f19bda" },
                { "pt-PT", "03047e974fcaa07bbf2d3e73109378b8e2ebed4464128c42adb9c8891c269e3cc272b6b97d4a71799bf9d5c3beebe9c76559815e4df0f36d26acbb8ac8d59067" },
                { "rm", "5d31b234cc41225d65621d61ae16125ca3743929ef165233028d772248caa89e94c24012c0e25f356b7fd458df108ce3043cfd1df04ebd8c745410c05a94bb1d" },
                { "ro", "fabb129c88ae4294a3fe9f86684b37f9fdb759e693d8ad3a42150a446bc6887b29d893895ce34f9ac9ec05c156f19e334174a256701b1660a40b05b992626d3b" },
                { "ru", "42edfecefdf93a8ba0ff1c6bc79d2fd42f0aecb8329ac3213291e8e666e621be60f7dbfc7cfe7bd9db9f9943405219ced629794f5397ed283f89eaf867e9d8b4" },
                { "sk", "70489a0da56bf9736683a21eb5d665ef0f47fd276b836e15176ac6c41dda4d92e68cbf4169668d74fa33daa2779b90b087c6778cfc81e518773a37fdd931fd74" },
                { "sl", "65ee9e1650617d1510f8ab3b36c4e7e44a6ac9e1c52aa03015a4b3e4e012600c8ed0e445f228f888b657e018b4c552b070ccbc5e45fc42899bd81266279a9935" },
                { "sq", "5a30f98fceb828fc0cfe01c05d4a3166bf9957c086b0603b134adbe0ac2f8631f15ff1eee9876d30c753a611b6a90eef5ac0929786b48e7fcda72c773e47ad2a" },
                { "sr", "9584e843a41e0f9a0234587fdc146b121f4f5f06585f7a3052128b825feae4cecfa4bc21cb7b8410ef4c310dfa0028f5671860bdf8dabc537444930d85e4afb8" },
                { "sv-SE", "7472112e7b9301c3c576686c26123146aba06368d90f4a301ce62ef265eff7dabd83da0238bbf95dd8e10c1f02502ffadd1d89fcb7d3a2c9e5e51f2244f352df" },
                { "th", "feb2f96b6b505571dc1df123f96496282ef874a9deacb3576bce976d2e5e78421772709df58b7d7669b6b36c4fab3bc9c36b8cbf42be4dc7f53f75038e32a654" },
                { "tr", "3626284ef54dfd91dd93735456f9852d22b84a1fcde86b2ac4cef43aa2e5f129b7163802d708c408ea90085ea56ea4d2705d9e693f49877cc875cb120a2fd727" },
                { "uk", "b129a10fb5df528239424fd670aea0f0f256e550a3d75ea301eeb432556a6577b7de52dcab593a34731d8f054d36020f7e2331dc3308bde98eeb3e0665a999c2" },
                { "uz", "49ae28e2e79480dcd3f3de94cf46c5c670fd34b8b5c2f1cbe8f9d6ab0b218c69446a813a903113bc20b44764a5822ac46c364e9c26da08fa7fc39a30048c494a" },
                { "vi", "219196f47f7370f6e3c1d8f34eba4e5c95d38ce3bbf7fdcdc20e6147e6255bcf9d6626d415ceeb6f7d06321a99f307dcf05925822d5b4b87235e332035947657" },
                { "zh-CN", "3d95741d568370e943666ca87578560245a63351be483791727d4cb5858d4bb76b97bd1bea76be84a997dbd429fed549a84ee94cd050e00b0fd6ab766c57fcb3" },
                { "zh-TW", "13740d8d5f6f39fbb5c594b00308b2c48d8ec21aa7a4413be20158260a975e44e9f4e2328b15dea7c4d65e0c4501d04fdefe6502415fb3549ba4db265d040898" }
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
            const string version = "91.1.2";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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

    } // class
} // namespace
