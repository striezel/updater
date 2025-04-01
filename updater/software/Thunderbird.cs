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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.9.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.9.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "38adaedce413f26d62c944aca92e1281f194a812949e380c941ea119f767ec7857eadac36333432d733a772ed5dd546d094cbe674745be255256c5402e49a865" },
                { "ar", "9b886143b72228bca4147c2796cc3cb760387aa36c54cece8edfa3d2767886672a421ae9cc66cfc6cdd0803556cb63298d7d5c3f69d4d97f773488febaec48f7" },
                { "ast", "fe4040dd705908f62b40ab5fdf39a8dcfb700e79344196c636cf9a72c776b4507436aca29c1df180e0839158aa7c62e4bcd588aa1e758df018137c2d0a93620b" },
                { "be", "bc1654a28ee31f2897a3be6a999ff18c05f47afa37c24df81418e3fca2be89bb8c7ef84dba2ae8baf45f4e16a6b17d685f6739bd405df70686f18216e0d6940b" },
                { "bg", "e8807eeac45c8b3a30d6a3149e705c02079b7fb6bbf76f160c5c672601df6b712ce458109ee1e2fce65228937ff98ee96432fea7bc603e2baee64f01ddc08eef" },
                { "br", "8dde996a7cb2aa5f8f5f62608112cdae3d35ebe20c6151dbea5fc36a6dae638138bb15f7a7f8bef415a9dc964205dd7237f242476d3600858c6976271dd6ccaf" },
                { "ca", "e86a03c3839be89047732ff7f657af9afbac5ff3fca86e441e7bbcd43d6a9df83adefce7089db2d6f7f3b52a893a940537c9cf996a8a90454a9a95cc27524f3b" },
                { "cak", "aa637b848cc0387ef25a156f3c11da901e696945db922cfe6266d9188050ccef0ba9f909fe43cc616ac92a4f0dfb405719c5b53a912d453d6d09894f92805867" },
                { "cs", "7f6abbbd70c1cfaffe90fb7d61c5acd692b5f10ec4da3810d2412f0d28367ebf81cc24a6da78594769831e082af8a8fc663f2b66234c60bf0dea6a0271fd2b6d" },
                { "cy", "f3e7bbed4224ebc49c5b6e5c82147ba476d2706604ffa4181d1a8a56da600a312d69ea28975e3721ec9111991ec48ef2495ea67e1e53952c5ceda35a3c8656c0" },
                { "da", "20f6d930fe5626dddd71ef994aee6277f963d1b8001baa14de39203138959e2a39361dd0dc1918f25b783ffa3cc92bb4f1298220d2098c9a7af856f35d94619c" },
                { "de", "cfc5a208f6c63ee673beab0108e80e961c275be8ae8382af8c4ae8521b534b7ec94cb78b85a6f687dd835d936102bc24efedea417d8fbc77969015ec533f04fa" },
                { "dsb", "476189e2701e988f2867198b0349b82aa5ce35e8bd09e2dd4a7f85a030578a0eabd579740c2f7ef28bae79811f870834c17001633332d71aa5ba3d10c72a3b8b" },
                { "el", "e5891812876efc716110ecfb8231f81bd553c9ac286651401ac3a2b24f569272b8e3b0bb6db1703584daabacda205f19c6c33fde5d9922a2894734efbc742b78" },
                { "en-CA", "883fabd945008206ac8cb90e1034b3960d6aa862b29247a16448f573e53a7fcd145d3e4a74759085df9223081c65301af0736eed9487759a8c9fa45c390959fa" },
                { "en-GB", "305e46f4e8d2fb2914b8a8ff9af7dd480901c115089e0bd01893a948f33d249d848d43356f7d73cbddfd64bfb1e5cbfd5b16955af92f693965830ff5e3632b80" },
                { "en-US", "f7f070fe4319de166610687c715d39cb45ac9082edfff99fdb87a724fdb508e12a1263473b88add2b4997b7ef1460a3036551c0d459c12d17d7ae127e707caa7" },
                { "es-AR", "946e90b1368a695d65192254ee8d334b28c350e9b71ede1560858136dd7bf84af29435d155c3c98501b599cf412eee8788bbae747f1477b6b563820a669735d2" },
                { "es-ES", "805861d499ba10abc1f862827843314d2e3af87a6127c42307f7ed1d97150ff2f3b9befc84bce97cee157498c65a5cc4a2b66410476b30e486d78ddc10a619f6" },
                { "es-MX", "c317b157e6158f58ca23219b3063f1f0a47bce9f2dafe9433b35d2f0f2e2c8af93aaaf85e5ded65da219abe416d3bd90bd285fd4fba5ab050f17d8dec340815d" },
                { "et", "b551bd11501d967e349ea11e8002233f275109bb75338a3b176f3a2441873bab835587b4dbaa59444e36a67331fd18e43cc7f4448ab40f0d66d2b9809683d7a0" },
                { "eu", "023a4d24e69787948fef886124d84e8a0a33f3eb276ad61cee1ec53efa137ca72863cc404b87a0117bd35ea0898a917083d6c14bd5c55624c9207a1e26832a1b" },
                { "fi", "c31f13ce1d767d2e4609827f2bd512b497785a0744ac8261d749b93ca8e9b926e0ca02989cb05e51cc0650574745fb5a2a85f7cf4ecdfe3d6bb47165313a86e7" },
                { "fr", "fa5f6522b61dcdf5eb8159a68e98e3848b9274139876b2358abe279daa0e7d8326509b2bd345babe1a5fcd42a801d71a316c85dc4a977e6f7d08b7bb4d506ad8" },
                { "fy-NL", "e2f01d96f565e61b9c37e6a106e1c1315cf61e791a398794598e3f14c5cb572c866b568dd00491347365e19b0e748c008f0edd94043571d7f37644ddf7999f67" },
                { "ga-IE", "62e1eceb5bd7c44ad7ba5d7745e779765a7c9f62d65f1c1bd784eb8f9953f27c9f9a7da19415a8b6aaeafd5945fee4aab2cab902e22aba586deeb19430f5b741" },
                { "gd", "b6a92a6a67f92e2e05b13c542c8ae5997b0e2c1e1c5b34926dd3350f19653aa1c7b2d1c62fe70ff5ff306b5f7b6fa13881d13847c68efe76a5db280f302d73d0" },
                { "gl", "7155d9e3babacb3c325490015fe986b5380ed46167c14a4a57a5d051783fc9f64ca71d9ef8538ddc35e51a17d625b41ae16ff41807da68c301511730c6699524" },
                { "he", "2629a111d180fffd3f73397c52c239e700369d2f9088099945b34a3c3a934ed55d2ecfda790191ce75e632a28da6487ccb393f64b9eedafbad9f1c89c4b4ba20" },
                { "hr", "c7520aee7974c9445df513877c8cd2e294323ca319d888b5365c5ce39d09dcf1d1eab0e44a1f81c0b9ee4e8444080f9671ca426fe83df25676df7184f4f85320" },
                { "hsb", "6a1390525f3c4c5ddc103152da7211d2aeeeb9d928221eb836a2954e0fbecc58fe19c5a5100d147559b03e66ac4437c25247875c4b664adf82a217f1a8953353" },
                { "hu", "62f32ac4924dde167e209438b35b561d2d0fc41d2837df6a8d9c9fdb9439d30466f507772b9f18ff5b5f43d85639f92799d803662087e9d5e923945445703db6" },
                { "hy-AM", "43df6b3d39861c749aa26f542620ab21c69e5dead05871de70b0030c7b909a20586a369094426de6df50ea8a9c6ecbefcd2dae4c6584ad63db3369c19e7fb6fc" },
                { "id", "b406d775c6abe3cdca084fa6bf9ea17e9bf0cb33ee8fd7d26ca898c64bf28afe4ff50cb58003170c65f1e4c71255d04378b44445e590f58e630edf28e338ac12" },
                { "is", "fe4ccdde43d4bc5986f933c867ae2f9a045f551d80c61ab7232ad2f2c5d19e0fd7d1eeb9794e26dc4a6fd8dcd48a248bebc170ed86853a309e91e7749096cc7f" },
                { "it", "1b55e205e895ef11f863a86e0e657aee33b8c73bcf711f20e980864d726d0f847bd74cc7b67b180eb740796190988d702bcd8d211ab9b330f79268553db73421" },
                { "ja", "16d448c20c51ec4c04209568082915ee21f5053c606117e655b8df2959e72dee95fdef45658376d3c90a975aea3eaef8d20a26fde318813eea08e0b99bbe80c1" },
                { "ka", "681248c517d38a8b3872dcf8161328240beb91cb364f8416a1e3c60d6d042feb30582213819a972165d4520d0388413334a0fcc66fbc5f8f7611c7561b1a44e6" },
                { "kab", "1135e12640f6e42fd787a7dd772d4465b75925343cd27ac1e8a65d4173ef642b2290a5193275b51fe84df09649c4ad9c80018306ad080931004984c69376c421" },
                { "kk", "167a01aa0d689cb864c0258369811036929b56cf9a7db9459743a4339c71920aba792e0104a27e67a257e7e520282ffe79175cf1bbe69ec84f3dc7e325754040" },
                { "ko", "1481ea267ccc690d1b1d5d3edbf521ae037ec1b9713564b560e3a86b82ddce1df065da23993d89900cf84eb4ce7bb4651d3df879eec6f9d5f847972e0f7e024d" },
                { "lt", "d9a07bd1ffc8c0dd53b0c9178838f1737aa47a5dc43143cfcb9ae54b1f2a96ca9ddf40d1b94a4b02918256c8b83dbead5121fb884f6d8983daf6f708510f1ee0" },
                { "lv", "cb903671113d554787dc872ecd2b7ba132c83b8aa275c034191ab3dc24197c23c799e7012fec13a2264613dd395334c55a4c310a4470fbd84d5fa8a2f8d443a5" },
                { "ms", "dae0625a4619d4182eb1bebf7022a476326f88d8985d16d7d52ec61c348d3553e2e977abb489f09d0d22131391178862ce71c6157e4a459475480185bc6da169" },
                { "nb-NO", "bb36c428307f8114caf6732711856cf9a251dae47a448d3fec20faf84515302ba167c58b70fd1e5234f09b22a74578b3609c93990b7117dca1498a33f729163c" },
                { "nl", "5ac9f6706c7d93e9ca0d5b10fd1949cafec38446182163a9b15e30ec2c8516f4e2b3deb85bea973910db724cb9033526c3edcb726b0f080a6c5c83d7fd8da8f9" },
                { "nn-NO", "408346f603f7cf578526ea78ab6ad8b13b097b77f67c8334bdf3712d82e4bac125040c69cc3d9c7fccc00484f5487ca541d413a6050e7cea4fa8508de4170d49" },
                { "pa-IN", "7f92df4c292bd8d803633c335182b636f69a865d6e8e517053b7b5a3fda516bb23765022f08ccdfb1cc2ab1a9634e21ec5cd50d6059bcc8d600d2b64d9c20246" },
                { "pl", "eee517adfd4d4a513c0fd61cd912889ebe63d8898599e173a5ad730e7cfa070fa179b8935488f5149df8f55be215be007c2e74bca5b67eff00c58f5988d16d09" },
                { "pt-BR", "49dd641fc051abba3da86390b90a604ad4cdb5d20b2a8dc18d291bdad58de08b3ac7466756a4e6de70aceb7c123e180e361d6af6be8f47218a795a624749a3b8" },
                { "pt-PT", "a931909325742b537497201e8a7d6997e8ec44f746581a48ece6265a23095465f95a2637b663458101a48e240c34b2760854a90c99106ad02b28c55d59a0c355" },
                { "rm", "5e4dac9b5147d48473983b89a3da9e0c3ce85f1dccf7993520c87ef0d4573c642dc76afe79eb38a8630fadf737a99b471ce76ea33a2ddd295334727d184dc8d7" },
                { "ro", "b26cb3af49900b1375f11838a906e6f0a65b90d16ea381c2ad7f54f41eb6cc1a0c836960d5e1b5e50001d3a0da164566e37101ee2d972c746aac464804f61bf0" },
                { "ru", "fb85146da8d28f062f4ab08a465a100c55cb731a39d819ab342b717a7b92da5bbc1c701dfa9744189487cb9fcba1666d98b412cc2eeedd5824d09790860c0d8e" },
                { "sk", "cf95ca7ee2eedf638fb5d9dc097c8465f4f8fbe17b6284f7b2e9c42c798b2d8ab67df06ab78f59c0ab456441c28bfe95c59b5473eb96a5855a9ba51029610ab3" },
                { "sl", "9d1cd0d27d4d1f0cd5477cae11f5e9f7ea574f1995d0c16207c40faeefd5af1de4e60ee0cc20adaa62c8535af8357660b04e6fe61d4b12988a7408bcb7bff054" },
                { "sq", "76c241cc81de870c79f741cde5f13ac4b408914664f39138ea68f66c4cd779d110822880b0ec70c452bf69f280d5dc80d61caed624c0992f72e22a4d81cf8b50" },
                { "sr", "a0a0119ac21ab4c72d88843708e9610e81f9f3d8c74e5bb0097d3314443fc677dd1688d7a71791eb44848bb86bea265e9d6d6449948a2127eef1dc2207fc2b48" },
                { "sv-SE", "ba660480ef53c048eca568f10cf16220c141a5507508f1d41ed94db6cdc6a5ff3005265531ef7b51d7623f0cba1e649f24bf18d09aa658f1b336b6275d981192" },
                { "th", "fc6733a7be5888048dc3c21df058a482444e699d341cb7547deb21b27fcbf0eda7477b7df97cebba6d806db616cb99ab66223eb9f004e32c5bbdba028bced9c9" },
                { "tr", "9d2636f1306ab69c16e26138ab9b575f84af6ceb2d910a1d1dd8fde9684e1e56d2178ea3d3c6d0e41b2af764344f99adbd3ff5769208d3498f517795a5aa1662" },
                { "uk", "f7f549c96eefe0efca56e73655ebbb0774db34f327599570f2f2dc168807af314e2915f558559cd17655dc904971272b3adc212deb53490950954c03f76fe426" },
                { "uz", "62570afffc026ddf5ab2d8fa247e054c085feac1e9346a9e36b2dd77d8563bc3f5c8205a320839e37e3c4cc33109dc8355f8404da818bb63cc920e129ecf0dfc" },
                { "vi", "f6986a1618b06075f22b5e7048023fb5a86859182c944b9d8d0a06a34160fc5377a49c6c593d4f99d520fb32ae00aa960bfc520ef663c6770ebb7c45fb0fe52b" },
                { "zh-CN", "cd580dcde580b9812e45e91e01d2f175ae4ed44bbaf93d793e22ec99763363c326b3ec03535d8f580db26c41253d7ee7f5790302e55cf3e8d926a302c4e53099" },
                { "zh-TW", "f616341d6e7579648b665017bc127cbf3c8f10ff50bf00c9e5a34c826f3b3ed0ef5b6039c66742c172192716fbe9705490a0ff1d623d9d2b45b4a673fad4c893" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.9.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "0c124e5e86a1fdcf58be29e14b98b65f01ed6ad67ed3791a27386079589d7d5502d26d2f84cd1aa2281c3890b7f94702197db3111e7086de8a0c103fba538a16" },
                { "ar", "595eeb2f9cb7ba77adf0a927c427cec3990b0fc4774e742c3cc22233dba3edd9744aa2e144a583df60c924e56d606b725d96b70307d8d1b36c07cdf754a0f689" },
                { "ast", "e2d678f77f0d1d216b51ae8d2b6f891dbc5e9bff3e93c1710c6ee585883308f3dfff093489bedd4e6f5df4611d839eda249dbc3a65d1623b6d0dc63a169c3eec" },
                { "be", "7001d5796374d486f1cc967ee7cc33995668af248f61f08005babd251e0038231922b08e87ed2974c254f7a7fe516c5f51bb6049a7f0ab3d890cfab056c0bbc4" },
                { "bg", "20db89d4ffba6c9b5a7a1e6e64e908ade380a4f01f49ab5e8032de8f5b20de8c9e8447252d7166f61bd8c44387574973f32c5ca8ae40a955592f2fdfc4a21188" },
                { "br", "8e5ecbd0a623f79ee9b1f515e9bc665d3430d63160a4ab94720f28d3cef1af2c1687611484a73ab394a93c38b0e9140427be3b5a10d3e89359f4756711657d19" },
                { "ca", "98272af640827c9130d52664cfa55ece42e366119d4a1c14fef26c405ff9b2668531bb6cdd6ddbf9259b286a656519a759ef526e5399b68d035662c9c04645a3" },
                { "cak", "f22db9c66057335ea8b137565b18f9effaf1cdcd8b5e9205b9cc1edacfb22140b46cc9d14e6b73af900c854deeebd62dd8793cae7ff76a7d330c32449dc68562" },
                { "cs", "297982b6c6f1c54a48afd2c3882dafb722faa0db3f3c868d013c69add344c356a69c344057f6c29746c961ad17e455e1d869d120b6ab5c70280c31622e78c785" },
                { "cy", "86961f267b3f36b46b2c7073a353a1b06c53f1dc3573102e8b8e98b2e85b90346bd1e8d2e80c6f28c8b8536766772475323d5fb61278ba3a2ec066e3badd5fe5" },
                { "da", "1398c36bfbd0f45b6ea93fa2a1c0a66c666fb4e1ce159fa8bea388e21a8eb93eddc126a702652b16834ee6a02d2c934a15bedb8e8ff29110d5a82c7eaae517b4" },
                { "de", "8f913e6abbd450725aee87c0b50e8dfa420816a542d1b36e14e6a7225d4937a1bed82bdd808779f3b03a8b3d6ae044b1255148d8414e563cbd1a619a0d3cf27e" },
                { "dsb", "7e63426e7719e05d8dc03f90c18f9ad8ffb040e33fddaeebcbcd2ab5be9db51e5a03826a322a832e6c17d11f9a03af77d800c436f8b9f9aa94814eb3d1d4857c" },
                { "el", "42753ca9cd949302b99af2cd03a388b1fbaf36afce0f084a0833fb7af63a13de3ee0cf18a1061b4e21fb24e133d0438ff0ac99c0dcd745fb6d9c36fb533ebb39" },
                { "en-CA", "6df9118834813571092d653444260ad5bd4e3c26066bd3120dc916a4b72c769620cafff13ea391915a5be201380e156538f3a645612398093f5072c9cac9c6f2" },
                { "en-GB", "97084fd0286057d4c801825ee8c74739f5b35d63d8b80eb26cc2782acf77200b117c424c6fee687594bde8ac19329529e5559f0c2ea0773da30878fb016eaa67" },
                { "en-US", "49ba3db62c7f27f0071143be0751f40d4edb1e96e225baa32cfd112b3f322e15631cc3263416679b8c5b896f918f37b9239fb21f04ffd0b7c2a5e071b1e90eb9" },
                { "es-AR", "c300ce2f4c2c156d747a4aac05c869692aa39628c051540922db90ea83a7dd239c11013f07f7ba1256cf9d84e263810c82dcdbd3cb4f9ff81960631f0d139d66" },
                { "es-ES", "c1422bc0373ec776e50fd0a922a8077c76a13d0ea5dd77c89d8eb5384a286eea1b1265949340c824ebf58452b5d02212578c902340aa8d5d4cd8fac18ccac9e1" },
                { "es-MX", "322049517b25879e0760399bd0a9fb80ba18b994d80ba9b31b029f3709c8ea9d2d3cd0f4c89059ac2f59885d9d6dbcbfdbf7b03c372e110445c27cd6e178d36f" },
                { "et", "ad7154aad6f18e34dbff397bbd88278f7b04bd66df93739eff7b1174f65447ee76ff6c12bf00bd544ee076523be73e46028192a486e2c58eb084bff61a3d170f" },
                { "eu", "4299c0f2ee2c7e3632c6c4fa25c02f372e262ac432b10df90648ba38725281dfb36f788f7b08923bcf4b6dcdae36e2ed3d99bd277e386cae0bb152bb96f02a3c" },
                { "fi", "832c1799004397326d03b2226817a57351767a125f1c44c6d738053ca7fa96ffc1d6bc3800c4911a74f510c0ba52e66b56ab9ee216393bf6e17cc9b7369f5257" },
                { "fr", "4e86490dde2d2694dc34a81400938a9419f796b6c283e6c1171541841ce1cfc47b483cb2ab461c827bf299526bcd290bd6bd1aacf6d4432a121c39ca47662412" },
                { "fy-NL", "27ab672fee026571390f3010c1004c3bba3561d4c74dc9da207018ed49b2d77f7a2dba18c86eaf70c04cf9863b1338456230b8253dda120d7ac3ca26ef4f6747" },
                { "ga-IE", "0ba0c0744fd77e377fef118c0b7f3eda4e1f56483f57773e8f4c13ef656708f86785ff8f8d71988987174c0512b5afd50e4931d6be517687050e99358211a119" },
                { "gd", "351ec548aae391e513e4b6e39cbcda21db861f9e7b3392f2641f6b0edf7c9db6f7630cc3a07672b919c34fba9c8ea5a05a1c886d349846f22f2e470eedf3d342" },
                { "gl", "95fec7bc26f64a516bf05df544a7872d58bd334a58de2b2fef1eb069174989946b76a9b9853434bac3f34573f19a4eed675d0de9abe3985a780b8f94219577f0" },
                { "he", "f02b3cd95843dca875b357d7d88872daac2aae1c8e0908f1f8e41c8a27ac83fdad8e8f202cefe4e5806950d94c5ec819e7a04271266059b5ca9736787aab6995" },
                { "hr", "19717302eaa6a1a1f1795f643c1b8aed8234812315432a7b6aff3313d7a3894d016c566e65a924cb12bebe132109a513a932cab61c3f8c7ca0f72c11c0234f5c" },
                { "hsb", "83e349fc55cf71c2cfdb45c4fcc176a07f5a60f841c081f3e6a997b9f4fd1f73cdbbc7052c5bb662fd777b7649397df2cbd55fa23613dcbe1421668817f1360a" },
                { "hu", "7ee8707a8047b7781b858a5c7df633b562939584cb57db69c2a8e9f14cab700e88a60bdcf5613bfcd9555c499523df6d8371a8c72064639d344c3d1bfa83802e" },
                { "hy-AM", "153d2ab51a283d500b178cbc22cd6263086684517b25a507724f9b64584f0c3e5ced1f6364447f98c5b18aaed586dc620da2da16800d7521d4fd8099d1627ce1" },
                { "id", "5f4df6c7a82f1b13074d991bc4adea9e02399576c8ddb0a974975184475732cc34cae3df75da1a8987c8121fbfac21d716e7bfd9e4b75fd3f8b652f9506b2705" },
                { "is", "52855c7493c22d9ba913ca65d8e38f99741c0e808ed23f26752ffcf171a99d6c0472c69816ec445cffef89a873b5ed39045cff59c83ce8663b10acf6f815e58d" },
                { "it", "668c0d15605e8406a738bbfff54771d80e7db35e85abfde5efff5e24dbf6a2f4cfec467e694e3595d4acf9dab8240f1bfaf4b235418395360fa42463980b5db6" },
                { "ja", "059fa148fb62f653cae72310e720afdd7fb984d24f3a541dad3d9abac27e1aed156deaa0475d708581132404d286a20ee583590743171bf74228c92de693ba02" },
                { "ka", "847ed5d7f1ac6db7b080bd60814ccffd930e8893245e2d7b0dcb5110d02d01a11057d02d6e6a9f89c007b547c99fc20738a298c22310b1c39b1bb6075219b05d" },
                { "kab", "630ecf558fa91eb340ae7e8afa2bfe8bebbdbf355a82064fad3448133351f576f8e8f1bea36c7b76eb4694d9248c180404fa7461d09d70add53b0681c4d52bc8" },
                { "kk", "a185110a0e319d4594eca8962be8f6dd68ef035bc7ab8cd45767755005e63f96e1cc061e65ec1dd3de86dac4ef508ad4dedeb7e1221e23b13a952e8959139622" },
                { "ko", "e4e9f498bed9ecbb0adb0d0c608f612ac191834c1906e2395f9d33f17f4ef6611ced070fd46d1befffd191d6923fb6cedfcee62e8e56c21546825da4efedc5c5" },
                { "lt", "acce97e67183b9a94a10c59b6cb5e81d14f68c7ebb87854ef3a5902364615ab8d3106edcc05869c7ef7f159d70d008d0b9cc2a048f3c8972e4789a19f3ae2263" },
                { "lv", "d17e9ccfd814b6beb652ccc583d65662ee9c37acf19c24e5f3fb3b113f52a70a030966d7e8eab25dd38932f788ff7290be2c0b8ae3cc2bab1b84e8c7d0bb9cbd" },
                { "ms", "66c44aa19f1a85f800938c846037eb8a4c521b5699a9db76de923790d36ad163852559078ed593ea523149ffb158ba98d47f45459e176667402f7d4f01c883bc" },
                { "nb-NO", "30650ee7da58a380635601bbb53fc3856952410d3e4cfc66fd7cbe401e4ea9f4f921a1bb3af1592a218d7cc6ae0874e1a2732f56c1c37100b071d922378ab886" },
                { "nl", "fc517ace66fc8769f265e75dd5721aa43de97e16178167ff340d11fbc98436f8fcd6dfaed4d625f15cc15631574cd3bf1c5dad9d3376007f317219be9e5988ae" },
                { "nn-NO", "830edbea50bb260207dac64e2c30577e29565ef07faf64745192f185cadeb4e1a07eee3e1d3b99ab8ad9b386e5892305975aedc5f541a84af801d60ca2bac2bb" },
                { "pa-IN", "e352b68a0c93f9fb2dd84f9de04cc0b0880cec3743fbc7700732560f71eb52dd0d6516974f70055876e375d25e7ca74bdd1378e3a5a987d3a2d0dabc1637eb74" },
                { "pl", "64e246f8baf4d1579139ef4ba881ddea1386e1894a1be6eee7f111f5de630ecad1675d43041c211ea483e79b62e2589334081676d95dec13364e80d0eba2b669" },
                { "pt-BR", "af720431068551f1383586e27d63d0a4ada9c849f8c663be0b0b622b8d2603fdd8fa88bc6ce77833c8d554356b2ca0ddbcbf8e7ba8cc015d13cc6ca73121243f" },
                { "pt-PT", "9e6d2ec1e408c8a1ee23705db3e758cb3d697612d4babcae173904184ff2409109ddd3f957b837a50f2b2369bcca0cc0886e3a9f5c014f134efcd26559daa8ce" },
                { "rm", "a11d75288151d5a0fc56fa6c200e5562010cf061553fcdb7610e470caaa4043d0468c1cf8e9ce97b02f085b2fef2a9e7ff475d49431815c7d1417c47d331b987" },
                { "ro", "81da8b1657f0f73f501367a8dc640242e93ee467f7442183ddac21d011c37ed3417d247188a293f7a5de4efa386d0a6b55f0b220b0d32830503091f25ce17082" },
                { "ru", "508b04e7f3d0beb871723e6bc21f2e0ec7c7269031ab060cbd8b012909f17be207f80d508ef27b0f1faa626ba1fa5323e1bb04c8529f264d62f22223539d4833" },
                { "sk", "297f09bca35f7c21f3a4d77b6a876ab0fc19bef9c0f27684787131ae580b1b280d21d34e68988a07315998a138e11e20623274db6a2d5221cae02c4b125b2956" },
                { "sl", "27ae35161ad6c46b24c00d1116c63bad337f5f7d2fc5ca671c5e58cbf186346334edfa6ac7ce6b60d83092d0dc97e892883e7af34eff4365c7d2f33021130b89" },
                { "sq", "86578632e7c0068ceb624e7606f99ede9f8a1c5c36971524422d9f1134c95ac424885c4b256186a3abde0fdbbde1f1bbbf77b224d3c3a894562ad88f26e52485" },
                { "sr", "c3cc9b1ef214a62709c28c1477655acdcad6f788e1d947dbefc2d709c421b1ee9d1d26fd370b3a779bf214a9f03f65d2cb996e41caa042c30ec35779f86df468" },
                { "sv-SE", "e6fe3d14f6d8a167a40c60ec0d5d0fb3e4d07f89f3a57a7e8cd2d8bf716f88d29697a62c52d867cb980f5619caed7ff0cd33ff9f3a75b82eecd2d605129f916f" },
                { "th", "8e9568c27695345706cbc769a1c1de01621ebef88b20cbfa14aeb27b6a8cb31cdbc97d2ae8e3db1a70400888f49f89c71ceece6aff2846882816e58bc7cd3d6d" },
                { "tr", "c63f99ecb6822034c78bc19ad315303a648f2192fb76dbd692c2e74290009f14c876f1563522e273cb1fb225c46b6a510f20e61aea50f6d06770670cbc6f53d9" },
                { "uk", "8505b4053b95da415820c3065f80d4f35896a906d05e030d6b056843088def83d5129f30a7baca5439b39930a553f5df6400a6fe30ce79cbb93b755d38b9eaa1" },
                { "uz", "38ac3df8f52692df85e795b9a25398ef25656007c50c57355986540999fc974bd5f576b8fcb670d5c5e71b355d658a9dfd5fb0ac979d0b36614f1cbf3fca5c3e" },
                { "vi", "d04426c14be928ed3247ff9d3cbe315764aa877acd1832986aa99016a7ea93f89a2252a954ef2890904e9ca23bc754e7c1a0994eb3d740cba35a4602d1dcf915" },
                { "zh-CN", "f0dc426b45a2ed90efb5ef7a87a5be4108f32ccc46c741cbdd4edf4f79ed5d5a6286222c28ba2e7995ee84094587c466ac279864163f55bf6040ad01d8f900a0" },
                { "zh-TW", "2462e86d53140ef0e57a50f4bd3aa00c20698e310a057cc29651cc2cee89b089942334bb9091f6bdefa01e0e77953a21ec4a75c0b3db2572c88b4c41ece6f322" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
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
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

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
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
