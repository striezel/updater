/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.6.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "105708b178db94ac59178f2545aba6d10b9ba6652ac56bebcf2f77033658d10eb70e9b936b5a89e870da01e3d747b4f3230d919bc1e8f81bc76fa4dba3e1c864");
            result.Add("af", "ae4ec8c22ffc9cc709458b5ef2c16bd27eab521019a6d24f713f4117a12654439d775f0fa82c474e6062b15db7488a10730abce0e8d315e2efc3662353119fc7");
            result.Add("an", "22ed9161766d09cadc5e0e572ee2f6f06b117e5c012e6c16a03be237efd5d9674695aa257a9f37052e7f0924589387ed7a731f8546626bff70c5dfab6c738ac8");
            result.Add("ar", "47aaa8911a5769ed8509048d6cb7a1eecdd2687a18d108c0976c3d02f01ff08bfe5eed194231b3e7e60d91449d7ecc6a3ba56593b182705929c483135221ad64");
            result.Add("as", "320801832e3bc1370c6d0fa68a6d5c4c37c097d1b53771995a57b399ccc3b81837979823933f02244729cc278b1844f35956812f3f16a0c054a77d259aab828f");
            result.Add("ast", "b1f37b2fb0b58787ce5c1313d9f41ebd664cc8c0ab223ec593a7380ef75ff116ec6880007fa12e8cf8e1e3139ff75a6192aa928a3bc76b48a5abc4e458d84c2b");
            result.Add("az", "45bdde9f645bd2764e401e409e434d0cd0f2c7e2d7824e22a04bfcceb27c2d88ead1c18906a46bc6ef3e1770a228107bfc973a093fecdcf2cc7dd8f76f9c245d");
            result.Add("bg", "52f43499c6c3b9394faa49382faf31f641391872d4bb98b8b62cbe0531b27efe959635ac039ebbeeb54b8c900fcbe9b9316e5a417023d5c3e8120e8139e48a3a");
            result.Add("bn-BD", "3ed448c6a09d1fb9b857e92f11c045fc37b457433bf955fdd93a1b1e78c2bae9964a274977d31dc0fc347cc2407481eaa855599e30faa7d75a0e1cc6850aa7aa");
            result.Add("bn-IN", "6b792f14f687e444ffdedccafd96f5ef5b28fe73da034e1aed758c76a3b50923225b1ae170ff898ae1409d0313ee3788bc580dd181ea8bac5fb706d2522eff01");
            result.Add("br", "94952840a57aa4f565c2a0795fe8724ce73016e744745706ea3cdf0cc06e66481b11ad2a8b625c7c0e09a8770f5f0cf99aadcd15490a19253994632474392cf5");
            result.Add("bs", "a86d72b75fbb5ebddba3b897d206daf6fb01e9d858aa61881e827850edc35ee27ad948b1100619e546766f40625de0d500cd8e56ba48fa8ba984a72d4864f654");
            result.Add("ca", "9f3764788ede5d4f3e081115edb7b140984f3777755d0b5b7a4ea4326c5537f8d47b43a2484f95a32c1c66715010cc2c86764823cb26f50e5e468d94d1a3203d");
            result.Add("cak", "bf63a82b5c75d7476c35cdf99a00f96f4d70da622d343521f2e29a34ad6df7985dbe5bb1ffa04049ea49cba93877e0d17fda4f206a4d4430f1c9fad1813ddefc");
            result.Add("cs", "2eb78b53b53960dc66c28ac50d165d861dc3c67e2c81975a0747ed05bb274c614f163cd950dcefa6ee9b3a4efab36f890e72a98a8e3e6e9fee66bd26281c0fe8");
            result.Add("cy", "2efc20abf196b2e664f37c323e53f484a6e0ff64a7b7d2aa1cd88375bcc86209773bf5150a2a6b979dcad5be5fbd4d50c345f1f2614f71682cb042b021241fc6");
            result.Add("da", "74b4c22f9a9d070840ac4b7df2c0a07cb151de1e9c06cf01cfaa195ae16c968580f48af8cdc59e757d29499ad1916cf9685ee20dcee1b31d1c4d621a3a6ad86f");
            result.Add("de", "eccf03b1c2d14aca070b6794c0ee892dac170f5c214bad305ab116592d0aabde8681d1701099944ea0b6e38bbcbc05e8bbb10600094c174b3c2df23ea8e16eb3");
            result.Add("dsb", "a0caccacaac6158191f1dbc482412c2a51a4d1a6fee4b4f3e8248a38901309ab25e62012f4bf189b9e38bf63dc928a74bd9696c0e67275fff17c976ebf3b6112");
            result.Add("el", "c0082f750856f7f0df62b8683b413850aa720204bb9a9b4d3107d1042e472c3455a804de8aaea3646e829925c2f3671627ac61bf4ad74f573eddf79c085271bf");
            result.Add("en-GB", "54de0c532712dd219dd8bd345efba5523bec3a15c62ff4e6589fd929c70293be39bccf556db8930dbf2f37ae83cfb405fc3bede15e1dfff70ed99e7ef03e2aa5");
            result.Add("en-US", "64ba6ccc316a8f0d8ee48728cd18ecbc3873a9b862c03cdf28f8483e541487fb46ad3c5dcca507aa27cac4765194d7e018926706cdfef8a6d3a7c27398f5aee0");
            result.Add("en-ZA", "42cc981421880ab83ae184de6bbea1ed101999d81159820e95dac7d45ebce1ed7ac598da38da2473236d9c5d4fdbe6bb7e51cfdcb03fa48cbc0819286139e287");
            result.Add("eo", "3713c2f8f5cc1a0f31055cec8ebabf1890b227b8b6d9c8bb5f95becc4e8dbc1e2f48998adf56db0d62aa38d78280eccd3b5758df6f743336b74a671d845f5380");
            result.Add("es-AR", "dcad3b883a44f1ca87e820bdd2e7b4935b1a2bdacb3e91faaf917f21240049b03bbfe913af1f0901db19b3ad7144f3f5a2729ba772e74a40f796da4b978f6a21");
            result.Add("es-CL", "27de4b691af4294a452aaa5161ed49abb2fada34e4bd11892c20e0cb34e341aae29b475f831b487d8525f4703f1a233632c5908904017912bea57a06e5c83928");
            result.Add("es-ES", "5fc4f288ca9a971fb5410597b06a22c3d982c5094adcc623cceb1d7afb51024aa7d2a046025059166d7bd9e414e37cdacb23fb27f07e68ed513e736f8635e3ae");
            result.Add("es-MX", "e653b92f6188d1f5cff22834a50c90afa11030d97d1362e9534b432cab17be2f23e5bebba48e636f581c5b009d263e65c222e51acecae5da1e65b44286a8bed0");
            result.Add("et", "205a4fb69b9bf42e18df0b427008c9d5bbb7785a2bce097e9342e2640db4d31c420219461fb866909930816aa80307ab20d39aef98662d8d027b81e09876c05d");
            result.Add("eu", "e700ae181ff2789def8234ca8be84138f698c31e3eb0410e5d49717216084d18ff964870f76f28f86bc0332ff79223287186f95489bdb64aa9636adf77c103c5");
            result.Add("fa", "2a19fdfd99b02c48f21ca5bb425730b2bd31b49d0f0dec3c9869acc9e780efd4d6048fe2c5ad42226b17b90fe0bf80dd28e696330f70c1230b5c4cf55c5f58d4");
            result.Add("ff", "fa1793ffc600e4d0e79b243219551442a55b6d6eedf65ed92d7eeee25a31105f0c8494279fc92ff83dd2e1c61ba6a751edb4ad5e01f733ba1e05ec89137eeda7");
            result.Add("fi", "bc58231fe784277e0aa1f12255df1e1b844d7ccd004c5c017d3215b74417b2de102db8a3250fb2f7c056c763cabbe289cf0653c81f3ca9766597c4a761320bfe");
            result.Add("fr", "709449698100073d56f54d96a4d7f5d4a5a226f16946b8036de5a8dbad0235cc124f59ba7b5c9d92883bbd62505b191741a2c715bdb771977d72349b23deef9b");
            result.Add("fy-NL", "eb2aa614e335a8ef117dad40af3755ae087a60aa02f0e1b471aed8ae94e0f82472eadc9f88884b2ba6e263a396bd04e2a56f91a804aaec4ed3d581deacc31571");
            result.Add("ga-IE", "3539b557f8e1b4240941f3685dcb5d6e2b87ae9d88d46556149cdcdac5427ff9540f5fab9b0325db67e2ed55cad0ed61bcd283ad54ec043248131058e5764201");
            result.Add("gd", "7908b1d3308853e6b9c01a60224a88581076ae05486bd68d06c5ac68231f72bfec37c6ffa9a4c7c61bb3ee7ebeb1975ea6933acadf4de76e05964fe89f31de0c");
            result.Add("gl", "5b3d3dc62355742aff61a5cca144d4bee2ec83f1d5fdaa846bdcc24d435e8c57e9347b2351d4071738d040af86c1291049115121f488b6e4ec29f9456ff1d9e6");
            result.Add("gn", "59c9c8c3b5bfff5fe1660bb04dce547eb7bcd92f9d4d7e0af2c4da792a2cc867fbae2a12bd86c5e30625c6c2305ace4e30b090225e12b764df7f79412f220dcc");
            result.Add("gu-IN", "38b83a45fb1c664c8600679304d9617184223c7ec6fd2e6364932c14239a63edb59ccae2bb3d77b3bd1e2ee3c5e8fd93b3d02031549c588c57c5605047a70f01");
            result.Add("he", "059acdf26ef77ead50018af7d308bf90b55350d2c9be8351f733d2859bef79fd11338720046f09b0cb01add5e51b2e4c44b5c48ef0c408566e59c784ef428548");
            result.Add("hi-IN", "ebfc44b745e513d1d59e06ad1d29371016891cad604a085573b095833d6e22a92758b1c815d343a7baa339b135280fd6d6701298d02c1bf3b8ad22d34eaeec55");
            result.Add("hr", "a1ce20c6a627c963976f7d132281ef6f6e6e152b1bb5d1c0df3334b1a97c3c1730a367ec86d802d26629220fd3efb6a9238d044bb16e4452176ceeaef82b304f");
            result.Add("hsb", "f005211a49270917364b6d755941fc3a0e5769cd5322f6529624979e34ba4e7b16d4d9cb160ed73d6d1edf9dad5c87f77eb5f0088a4e7c83fbbb5669256efdf1");
            result.Add("hu", "2ff1d27e85f54b1bd57f31cabbcbee8afb472c80c2ec983bfa645ae7792dfd5cb83911f862226f671fda51af4f72fedd340eff95b793e37c3c36f534051a4d7c");
            result.Add("hy-AM", "1335bef5dc0b76026bbe70d25ca933de27cac652581b0f2fe01ea75435bfd26ecb75e6f46a11046c6326bbf72d7ded9674bfe36688ae9e621cf63a391ad1e693");
            result.Add("id", "93c7cd4e7e0fc5294e6f79a3f6c0214de52108f158f7e5ee0234c874482c096b0ccea99396cae56e145e488157794a252fedbb143392cc80f7096b91a2ce8926");
            result.Add("is", "53f563bd6812d5c1311f937c41ac591d0f4c19fb55a93c26006605dc419421aac73ffec6ec99a689c0212cd66ba682a7e0cefbd2992f1d60db45015636f389ff");
            result.Add("it", "f9b0b9226e4b467de20ddf5caffd1158020a441d7a5f7e1494d3ca9255fbf921d87e4ae803b7405921d953a8a7d6acaf823b8149c98ee69dda6b0f73639b4e14");
            result.Add("ja", "87246c85bb7167e81ac97bd8b1f09358dc2fc3ea6ad0a84c8278827b3d4378baf35fcf53592fbafb8baeda6ffa81ebac15d83bd1a30ff750529a05ca9980a577");
            result.Add("ka", "8aa9278559f1ce73ba9c9493dafc94aa11eeed3ef162a74c8e89a3461ef2933765eadb955fef80a3220b1e7648af0c62b642c9ca3288c611312b1fe4ca68ef4b");
            result.Add("kab", "182ecfc7300d1e25cae89c0695e9d014622d59f106acdcc0b0f314acb92d2bc8f7fd973c80a45e81191f4869eb2a6a499bcd52eeece2ea8ec120fc04ee9704ec");
            result.Add("kk", "a744033606370311393f779799fe6d3d154b989364096b49e27a4858d0e148f85a0486a3e7132bb65776c43ef7aad7eb0474ba9a1ea2ee59f529b049fc10aafc");
            result.Add("km", "3a87c9a0acc6e57fc551cf1c6a0e410b75568dea119faa65d0f439e74a57a053f75ebc222b56182f2a854d2aeac1f776cf5201bf1cfc6760ede2c132c4131920");
            result.Add("kn", "0ee960e88b537b7b0d244ba9cdc43b97bda88e5860c9b8938a0a6e7ac7b73a4cafb7de97982a24cf33c8f60ea9919a81118364c1f875a5f1437a00544f858db0");
            result.Add("ko", "5ad0ad5f7e8773b1eafd2e0c2b730f3ca3c53e3a1d3103271e676c8307f8903be02b60304c1025c0578e975197f815afb5c05d0d8a32c3289bcf72dbba494331");
            result.Add("lij", "c2350194d3f99c52bc60f94e30c86ac1389df0e8bad78066ed7aa00efec24b29395c4c8faca384cc25a0af8f4421ea4ceefaca5f649a14ae8ee6fd8bddbeec62");
            result.Add("lt", "8d0e2123d7dbdbfac4dc00231dc11f1e3832020a7660b9021426902204275d46795a416c0c5d6162e1168a5d0ed6d8055d6fc651fc1878bd33bb9046a3e6a112");
            result.Add("lv", "878c83238b4d7600ce794ebce4ed928bc2a5b4fb5d456c2d39d5e93ee6fa03d1b48d3a9c2c05e1daa11b5d52515df572d8ebf18154df062e9f3620ce875c2abc");
            result.Add("mai", "2313b1f7f65b8ac5815af3897d34a76a6b397140ff13934973c6afa1249c0ab894dea8f35bddafafc28e1061b8edab60d08255fdd4bc8149657e4250884a3bab");
            result.Add("mk", "d00451a7e54ca565fdb5c8773bb2cc71472aa7ced9d86aca7d0abc818bcb63871813935bf55513df41c959a3d3d8a49f63c94c2f7ff8dc723c70191e99712126");
            result.Add("ml", "a3f8bd178119efa51cf4fae1bcf6552c57a88153ec4b87207c6ff17e646c0e488ac37dd5f244d4ecc667ff72b66dd2d94753ede20613f43d42d1b935b2588557");
            result.Add("mr", "e285f8809522fba558928debfd029c4a0ed490f05109e4c9073f9ddebc04c9be9cbcff1ee32537bdcc798ec2da04f92fe333d480fe760ac6438a4c4ac1d6a86e");
            result.Add("ms", "e829999caffa503f131a180e096ed05c644c0fe31741fa93ad8a16884053450420b1ad4158b2125e8b32a4e66ad5858ba0d54470ef25385db58e330eb8dc4c36");
            result.Add("nb-NO", "e341f4f797b5fc7f0ed1fc7300979459e718d2b55f9ab1ec0913f5c199d5e793b18fa83b90820463ce861cc9fb96f744afb84c7d92e8163009065e9663323dc8");
            result.Add("nl", "9aecd6bac7077d46de8528d410cff3c19bdc94f6cbd5c7a55339cef3ad469032aab10b740c523a0cce8f867e400fde98a542ae82a36f5cff354ead5c4ed13bba");
            result.Add("nn-NO", "5b3f6570560296868891fe2785e446129b7012835fc131da6c15d59b571b827720e49588b8ec4366bbd2bd13e4e9bbd040ef9dd91ba0ef82e3b7cbea0c10b483");
            result.Add("or", "0ff9ff1859eb0cd7ece85a35c6f357d9bee585d0e86857fdc012021ad005e9eecc277a5f8024dc5514bb49e1fa40240ef20e45b0215dca0be77633ca59f9d7d2");
            result.Add("pa-IN", "3720ae9dbf84fe185796488d4d8b7e8dacd10f362d08edcf53102a0cbfce5932a4054052c1025650fd5373d39f883f8fd922131f993b3aa4cffdcf4f25598ab6");
            result.Add("pl", "7cb69b897c9782dcb8d970d620b1ee565562917a2377d8172a9c2391e7bb22a82a870cdf413ce44113c1aa5deef1038cb2bf9c446030c8e484f5905d56fec013");
            result.Add("pt-BR", "2937d05c407f434d895fda209934d0b560351e96aed3fc09f95a4a57ec101d1f28130ca82156fecc240a3b23c25768569fe2fbcfb828eb8e6a94dea0ac5ed7f7");
            result.Add("pt-PT", "b87911d34dbd97a9ecb718cb694570b30d24cf5af42ccf3cce2702f18a3667ee83691e109eeeea33db5a14c0b3ae7574566c5985f3c2ac991f50595061eae6a8");
            result.Add("rm", "8df8662029e954cac7cce849a1ecff1c6f0b2f52975af059fe4d770997160f134cb7b56ad74ad7fe2b96ab1a1edb75a2cdf8f16ad95e8cdab15552c0de5069b2");
            result.Add("ro", "a695988036b0c8a208b18348c16c32c2767556dab950729126c02396888b6cd6b1c2abaf52347fc245874cb33edf53094b2c0e2cf840290146207f0eaf9ded7f");
            result.Add("ru", "ee75c76486e1f70dcc77fb920d2ab8c7a0ff1ba6761201dd7789a4291ae89adb37da8b82489a4603bd1a042f62ce3c616e61b31d1da8be6ef66ad5b77fa987c4");
            result.Add("si", "081dd121e1199a617517db8559e8e53d9faa592ad5ad763dddab6860b033566909ee2badb9da1b1269febdb70902f34aa5a7cf592bb2e9c6b60994565cca25d5");
            result.Add("sk", "16a47bd513e3f76af048e57c4c15b51b42be3460c81ff06f567ab8943c828be192177b1bf12f6360301ff4bf1758a84fd131d6d8339c7caa82044e46c9ab7da8");
            result.Add("sl", "760af6160d9f0fa325b98cb6708de70a205c0cc956779a610b9816b2f31e396254ca5e6fac1f0486354d8a099e1a961e6735d1542b9d054c42069f2847b28178");
            result.Add("son", "d1a923dfa122509b077e7a0e5ffbc49141359aeb0b97daebb2edff9413a746fe381945d46a62fa763560527abfcbc3d558a3bfd331345e61b58eb3b577c92c5d");
            result.Add("sq", "4d5b4d6dde487e0a2f0cb66968054c2280122a5bc80e62e877bb8cf1bb347ee82142db0b64d7b4087a40bfac0368dd563f295e1c561c47b2d769548ccc34427c");
            result.Add("sr", "decdc7e93319e54f23ad4a037e189301fcaac10a95735c6b9d2c553a3e1882681f749860f14e85ecabca6ef26d10c572c44427ca58c5026eea75de54446ce5db");
            result.Add("sv-SE", "4c22f1d9d3dff93cbe5def77e9d8f7693375c08ceb9148f596e07ec9e4691affa498e36c6bcd59818fba2e1c69a81f195362cf20aab2014769fb5f755a1262c1");
            result.Add("ta", "024e7cdd3c3bb068a283cea0981bebe7fc7812c90525d77b1eb24d55c12f5237623a11739c1d75b417e5d6b757afa79a996411c3ad515f0c2f49c6b294a16823");
            result.Add("te", "469d571053d038fde10a72091590e31ae389cfeecee566c1c9648d87a33253e37c4a15452d50b0277a61f7411c2ddb0ee642503d662f9b831020a371b8052b3b");
            result.Add("th", "2d6e19dac965c2628b2932f52d57e9a7eb753a47017d34e5ba3765d7966e7c5b73b550ae1f9abe4bccde31c7145bc2636fa303419dbfbe7f8186e25e7263c779");
            result.Add("tr", "ee092a698379e6efd883a3606f7f894a7ae261bb346632d7d3e39792179948116158115c06674ef976533275a939e8f4946d3b7190faf90aac99c078fbb93a41");
            result.Add("uk", "3ffb426c9f131243d557a4bf21ae5a792107c836fe7454b2255b962019f9ee58c468f63be394afdda1ddc63ee59f3e5d4801a70b3539c104cf11a16b773262ef");
            result.Add("uz", "3be93a75b028441056a429a660b80986a72a13b0c11dac03b1758ea2064b60edfebfb21a1969c1f6b6d8f9059cbb1c61bd20dda1ac2ed04f39556c77fd61f4a8");
            result.Add("vi", "9cbf16b4c18bf421fc6c5d3d88434548da5852540bd602935091db72e049fbada3bcf67fde5a5e377a3f69727f5e6309dc6301d838a61d27ac46541e259a99af");
            result.Add("xh", "7045bb9a9a90cb4d56ae998783f31d87c0982918e6ff08bc9a113c2847872a0be00d804a815274bd317dd7c090f6b91d9b59778dc52fd5bbeb274ed0e6dba7e4");
            result.Add("zh-CN", "d0373fe95f4a3c9d54c29d48a4e855200169e6e6a06ff3f0d9a559e7d31f15194e151e78a2fd2cb3a71c3f1d2ce6eafebc77fc740f43cff68882ad424d3b8c37");
            result.Add("zh-TW", "5c86022ffd666d8829ae95081779b33d414d533ce1788e18833e672defab696e8859abd086639dba985df872c1bc217e369acb90475e8d528c0e2b5c449f694d");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.6.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "960674c661e1633d6a78a7b608109f9022d0f1760b368f7c540836f6abcb9e52f5253add816ceccb03b489b46974e78a81738473b966a287ff204891c60911c3");
            result.Add("af", "acbb35c9a4e195cf31f3cc9c6822e8fff792b6d27e5ad59f2d4b1626af2d7224e501c8f3e230608d7664f19291abb54f3f5873fc9868876fbfb424ff8f677017");
            result.Add("an", "cc94ed3d2e8e6ae973af21a34815ce528ef23b56af26fae26e6a7356be145d0fd739bfb36602f8a833c47e93aa657eea30f794f9784213a8d8eae807f2f86778");
            result.Add("ar", "69f9350c4a720e0c611e09efc32e06f948b66f56e37228422f2cdd0802f35f338678dac22582cb85bae2f3433814cfafd7f3900428c69512f9d96e8c3879e588");
            result.Add("as", "3f07cd50924b12b369327ce21ce501f8f5aa36fcd6622668b0edf87a45e83fd353b292e3f1dbb7ba0158d7ca8d5baa8905028d698cc82972f77b575202048764");
            result.Add("ast", "f54df55d5ffda1a95cf532ff8031a2dc65d0d20c63907cc371d5b2665d0316868250cf790aef6ef3eaf9b6defcdd46e9db073f5f66570c34ddaa0b6373073e90");
            result.Add("az", "d9d3d58bdf859ece12a06bd27704c35b45ff17e484ae8967d89a36971de2185a079114128d5d44d45e9681e155d63a32fedd9c240f174aa466bb0f55ff3adc29");
            result.Add("bg", "8a95d78232c64f7c7a42656b2ecc92d0d7a3051ce3bb50cb27709056f41d0ebac2bbe3d53638af035c80a0f2a319b0b8b646b02e71ccdc1232291b4815e1de63");
            result.Add("bn-BD", "db28aebed11f4f1b901480377feff8d40968aad1cf7cc051546eab3f519d73bf1bf3cf29ad7bf0b6680f935d9e6e9f6c30768cbf99c99ab9efbc321765813641");
            result.Add("bn-IN", "c1b1b039a66a9fd07af9d07233b0957d88debbaccaf8803dd26916630c5d57590d65469bea5da69cd90206a6847e5e740d88ede3d2d56a19c2e4137fafc58edb");
            result.Add("br", "ce5134b38ec286600352e4e0cb07e4df1266a7064014c12264610a766133ae6bc02707882b41ca50e0ede4267043c9e79312c872fd7d0db4dcd12ff540385db9");
            result.Add("bs", "86217ccea3598f549d8e27bd2eba9b99584e84add77b4117d325d505c53a09e0b2f9dbed9f463b89b114355f84b78a10fe43b41468cf00cdb1b56cc5d6018645");
            result.Add("ca", "33cc44f8092f0ced2118340d2e01df516de2d2f64da76aae260bd4983a5c74193613d315591e7b632e6d9cb3d340af34bec0bfca99361583b71b55dde6bc58dc");
            result.Add("cak", "be2c5121f19af5c27bdec661e49772967ff89d7404c4943a3c8e56bfc58d4ab207b7fd727a2f6596705e413d63750f7c3df1376b00d9e137b2ee292373e59433");
            result.Add("cs", "c5734c8abcacc3a23a6db2e1ff8c31db2aee82419e5d5eed2cc2f2590580ef468ecad71d96274120816eaaa9b5b3310eeb57180598839bd58558336c3b16a5eb");
            result.Add("cy", "534d6cdfc1095711f788ac755589d8dd4b215b61f74f02bdc6c7e52dff6e63a50729adaeb311ad647c2352cfa6c38b02f8bb190f3afbd26edad07e2415978214");
            result.Add("da", "1c02d0f5cb94c4afb68dd3b5dc842dc9c43e11b901e973be5562742c78220da399a0b81ee332bfdcc38a5d6ba164db620362d40164936bc467312f14b500f6f8");
            result.Add("de", "31b5ee2c9393194e749dbe465351cab88e3c9baab1e506c197474500b4a042e350a318c56aaecc5624b34b3477a8b22f76683084b0551f4174c6ab82f3ed71c5");
            result.Add("dsb", "b2979d71483f23fc33a81ef1198bbe70134db95ed1d2cf114a9dbf060b8c4ee0174bd6bf7d5d77fd829c21cd3eea514818a8b29b4631f180d5544603cd7f95b4");
            result.Add("el", "cce26cb8d29fa5bf000709f893557fda2eab43853ce15401eda285a06c0ca66b17351e3a299079a3f5ba7475701787af01abf425d0a6e83253817df981392f11");
            result.Add("en-GB", "8223b74d748e48abb651a7ab8fce3fc810e9f14467d8907bc3a500300420a27f84384424e011a2546154e1afc8d5ad729f626e11b20fd42027683d7ed680a803");
            result.Add("en-US", "6bf3e0900b019f7969a09dac8a170519c3539d5179ded922ba320ecacc48eded7b32a84dc92cfd0b2ff006b14c5f9c54c1e8456f34f2f68544fd0658c6f5215b");
            result.Add("en-ZA", "5ae5f96d13a09603df66e892789fe611d5b98712fec1100a82351b7d5b39c54e99ec800b6edb8be026dab9bbe7c1a53ecfcaaa47fb5e209bdbf706f40b944aeb");
            result.Add("eo", "7e7ff5d89008cfac8cc460fd346520f2b5e2ed9646b6b3d014ade45e24b6570a7180f52916e91ee769fe362a7f6ad6679d2e848f156f1b2ac59750e5695b7e3e");
            result.Add("es-AR", "3345add2891d7c6dbafad011c0f63662f6dd80adbe37feaca4d518964e3404f1743ba55ffbf45f1c1670abfb9fb82b81b9bb84cf2cd56d300e1518c1982be41e");
            result.Add("es-CL", "77617b4be58ef5b2557f1b02c39831d62649d621be500a31f31e9269d6bac93fbb23e655a24ea90d682cbf183e40632bdd6809579faa33476d453c9d65ad9ff3");
            result.Add("es-ES", "6e1980ec3a30954aaba722d74637f642a5b8ff11ed81ca6ee1ace99410b4f77a2046388c134da77ad0d877f40a80a1ec07aaec685f0da444103886733edb36ba");
            result.Add("es-MX", "524592c127d3b26025e9b8962eb2fc028302e1ec4dcaffe30c181c5c1a94639d6bb9bdce9f220f5506d7e1929730d72008fbc3d8ddaa71af4ab2a7c3c87ead61");
            result.Add("et", "1d1bd52ce1af2b1e9bb529bcb9218b937dcf0cf29decc090db10d23d3e5c08265d02c46a052d6d4cb4d2bffbe810ad85611cef96877e02581efdbeb1a4ff8288");
            result.Add("eu", "a75681d7b1f0ebf9a4559836c214be21703d1113028f8fd27212b69c30a1c77ee8eaf82c8d023b5f78a5dc2fd07e8fb345f251baad98d79953a6ec4958bb18be");
            result.Add("fa", "1ad8d2d6b148223f7da9b280a732e89d6481a1e5cba57666dc6bfdf5716433daec3b131e255f4d798d83601972fa39773da72ef9979cf6c5458c279a3d29c7eb");
            result.Add("ff", "545d8ca4201847673540f54555bec9a2a74804397886949853f1df2a3986d5c450867bf9be946a7533695f1d8e402fe58e5e9a00b6243cdbd24596e6ea6b4487");
            result.Add("fi", "dd1fc744d284b7f911680f33e638b2dbffcf9a96513b76e23e50ec7a63034fd03df5509bd5ad213653d8c1b5e9056983cf9be9b9c927f0c5b28a3314e4011216");
            result.Add("fr", "99d582508c9aa3b1cb1cdad78a778b040c089f2aecaee4a55b42a7ce88e574a623c12c8426162b38f14d8b2bce9ebb3efd2b9530c4f61c94f171ef9c692dae7f");
            result.Add("fy-NL", "a8ebab7fcbe01ceceb7f0cdf1371cc7ee2969bc902c7a7a5e8e5ad1003aff4ab6a7fcf96ae94be81073292da8fa74bf6356defb7bb39082646dfd7a3b901aaa5");
            result.Add("ga-IE", "baa944fbeff4e534f9b5834c183f6ad9c4af8f6b704f35823d4ebb2299b9677b27dea64fcb95c09c72065f3810c672f0ba31fdf3f542a654c920816a5d70664d");
            result.Add("gd", "f8684c9ff54f27392d7c6e4ae1c4e9376c175c5d323d7d6b124d7e425c344ddf9057f11bb1beb805412f4690fdc1259d90f07d299632b4c47ba9db96cb379563");
            result.Add("gl", "949403c963042725e574819cdf15e139b20d491d3ce120d060a183bb54043a4ad97b6e9658c693460ec28381e3870756104c57532e9608152ea3dac424287189");
            result.Add("gn", "f044cd2d6aed8ba67a80b55f6ea5d1f5602d94ee6add2b2075a8bad1ffdb33dd2cfc1e996b20a52be2f34eb2a4ff803dd46bccc3333b5241a7dccd7970aa4a9d");
            result.Add("gu-IN", "f9275e19b6420da504e69ae7d9c3b3d1d5b0ce6fe2188757c82eb3efcce50b395616c06da16b50e21d3c4c6a94442181fc29be4ad061c9da0646e6f75c3ba64a");
            result.Add("he", "b348038df76a71d2c4a1dbaa1fac0e319b090e8ad3b4ae86b7717f1890c73ba8be7c0a70d3e2160471e68b4f5a0ca6521d802c3ff8431ac4c54a33448c2841f7");
            result.Add("hi-IN", "64c621bbecfe86fdccee1fa65e99aae9c1007cde12acce17f2634f925247eebde87cf8d7c2a12dad53abe42c89d89d1c5aab287a5be0f9b4fd0f40139fcbb7ed");
            result.Add("hr", "08af28ed4acc02250227bd703a9a90bb4c8544d565f2a1c8f245f39835743709fc93d8ff747c452e57e14878693806b82128f7f33344ce851027b6dea66fd772");
            result.Add("hsb", "1d6f918eabfcfa6df4b81a316e40fd104ede437d2334061b97eee34d10592039efd083c4479fad0c313a08c64c88cbb82b5e67e2aca49ac53d4ad995d9a3ae10");
            result.Add("hu", "2c5e5ca35d13671d5ec39597c5774d3bcca5c0a63b95c08766bff05976d0f58608fe82d7d9e53a7e7ec225d27ed45e511bec1619080a719d27602c1986acc0f2");
            result.Add("hy-AM", "f6e3b5f9be32369d1be88e82cbf6a193dc08ffbe121ce11dbeeb2fabc68e2c16dab36e16534e74521df192a5fd10c6342da806897bf0996c0ae936db13c1f7c3");
            result.Add("id", "4d49896ff0e3285472d898d10cf13eb4f5cc382acbda761ec37ced59078f1bb312f0357929775f8791a2f003b0ede4d5e5ad968d1f6a03814ef094c42ba687ae");
            result.Add("is", "088bf8e769776d29994feadce061771b50c8da3fedf3450b79c6c501bacd1ebf7841faef128c9b775327fc02fd87b98510720a57688f72572cc65e15e26edaaf");
            result.Add("it", "1ec5a831e120548137c86b11e6466b38c2da5f88dbc26ced70698840edb5b145fabee7166b2e17f608ae646685bf79485a33b1270abe1efa91fc7c3157f68368");
            result.Add("ja", "6bc589aeb4a5c157be756eba458a36f50ef1e2be63672ec9027e7ea14d5eadc6ffd6c57973542461d200de5999e73717099625f8312b98b15ce110f8b601b4db");
            result.Add("ka", "9362e2470bf5f05afe4acb0ebcd1a42cf2f88e253fc3ace29d177e0e39fb7a6204e8190ab978503cf2ee3093793ba2e6222bea141c6dc49021eaf473915a59d0");
            result.Add("kab", "f2054b54f6e9f444d55d5ef209e77f8fdb9d8535e45e9d9d5c9028e64787a89a3fa01b821f8f03c16a83767197f5e4fb324d8e780d9f4928b4f9a03631977128");
            result.Add("kk", "0a1bdbb5f4b724bbcea82e34645b117b50bc64ed49f87fb80f9db4d154475fdc7a7d9dd8b2bbd7fc70e792ab67697f950843629164c233abe2e4469c6fdb83fa");
            result.Add("km", "653a70232cc343fd8d212d94ea94e4c1f2ab2824047318498ceb26ebec7bfe101c6257420fcdba8ca8c6ebeb52b56d31b45d9dcdc3d107437a0f9e3427daa086");
            result.Add("kn", "99e0391ffa6038ad663f36b0cf5100ee33fc5ed30be409098ee4aaab4193b57e82498bf7e06077349581e1fd268e9eb7238f002b1280244cc3c00d8cca9798bc");
            result.Add("ko", "4e4072c8d1818eaea90920267d7914dd7089d4424d234b5bbed0f13537b56964dbcd7ff7304040966d5623d250bf478cd6ae73884cf92850a6c45e6c5ac2403b");
            result.Add("lij", "1664573269e7fd009682012adff1adb2b07bd5c91842b8788a1d1436b7ae3701088dae838efbc3eb445a345a70eb87445a86dd73ba7a31db1a3be64e5652b2fc");
            result.Add("lt", "596cd4a6bb23b3cb5d8d9f8384c42d40f3cf356099cc9dcf966c82ac9c1d7693a4f310dcb1b4d8adf6efdaffe8ed7355599e5206af6060aba61fcb7fbb55aa34");
            result.Add("lv", "ef939ad05f9cc3ad322adad31beff383db59924bb8fa1965c93a6d2db7b668b7e6263a9bfc630d90a4d4db36a582750c8fdbf42358c19560ab6b6d6436b9f36a");
            result.Add("mai", "4ca14816436edcb01fcf2687569a3dade1ba4204673b70df50cda35fdfdd681ee6f68e2d52a4e625fed5df89c29e0d3976b076c47f43f39ede7c34da2a41e7a0");
            result.Add("mk", "95c69173934d51700e3f0593a586fd53322db40a4d6ab9739c28b718359cb94a6a896818b5c4039766b28498e222ca68cc5f9da4c247e238600e6fd683dbc405");
            result.Add("ml", "9c90d9b515f0433a804d6aaa7d2fb70a085abf3eb8aae4525c7b13e4d0572fc06cbf6320ed601ecb14fd1d3de07910aa68e958ecb1cdfdba0807e7d47ccab23d");
            result.Add("mr", "560debf6b2a4a2a6f07a3767ee9e0f04b422849111bcbb817365f6c911f28d1f8a327ddeef2ca292446d66cdb305c3779388c2111018950cfdfd3ad7baccd027");
            result.Add("ms", "4f678a1f12dfee73eca503813a1f315b7d97c4e0532e854944d5a9c0449474d7fe2baf8cbd5139bedc6a37499ec3481d75b42e297025e19eeade6d8d99697e8e");
            result.Add("nb-NO", "8fd3350e72dd4535656e15f962b3a680c7cf05b251c1b72453d373ed7f61866e081ac713915b95ead541f57e35d0f1e7bf67a63af16a516aadbc41187115fe67");
            result.Add("nl", "ed9b10c2a33e01b093314f4ead8f8ede7fe0e9319dd6317e53cc762ce447c491615aa778c298d78707f9a2b34a9573fe449014cc438c5c371a4b4fb7d8cf12ef");
            result.Add("nn-NO", "a3eeb77399fbc6786427677d6f1becaeb666018eb1fa9f20a3f1733e13ceeb678d5d480dfe793adead43d154ceb5287aa9eaf6ddc00db4b2e1665cb42f98111a");
            result.Add("or", "e19962b7abaf16ea26afe9beab07a1ce1dc80d39ce549b36d60d0b64a149deddcd5bd4b109ad9428d5500395619c4a8fc12228adfcce33821f1f5027acb7e4d5");
            result.Add("pa-IN", "b5f1f5bd3bfef89dd6190ce10b633e1d5254b04a310b91948f1b3a3bc0c82b75d95ce68c6b1383bf6798b71d70be37b6cd017347d253119846796d22c391f77a");
            result.Add("pl", "36de4b1d9c0e9cf2ab3e14b7289f7bc04ea1dd948afaddda3269198825b794af4fd32a6805b318d61696d1dbaaed457068d47ab3f1d494d62f1cd6e7046f65e7");
            result.Add("pt-BR", "97b21e8984ac0c4d0d7200d38adb25ddadca2d2e68b153fe230529642dc17686e0ef77453fc995c43cf1519862b72edb033eff918b6a89dfa7d8a46593e393bf");
            result.Add("pt-PT", "57900de67cdafe5774ce6a39d56a562db1ee41109975ff6b53e7df4c1f3600d0bf590d97bb7cd09d669a44fad5419459bd140133dce0d230854699c1266e8861");
            result.Add("rm", "d03f51a9aaba3dde0473763ece5a326d7d4ebe0a5cff4b957a317d503c36985ad24b6658e3c04c7a25a652489db9d37a134a3f4872e617f3525a1ecc141f0253");
            result.Add("ro", "0e4936b4c84acc2712f099f14079445257dbd11c60307145d5f7ce1dd77ac5f29f8c5d56debe5c65e9ca525362165259e21030b008d0db7a3d1943987af9bdae");
            result.Add("ru", "694c481d6be3cf38afc48d7ce22bdb48f61bc1a2a78d2ecb5e2f1a486b201478eca7f16366c07f2a4f6e639a149f15177f65cd9cc7c1fc8e943d7b54e529fddf");
            result.Add("si", "1f732c12bd7cbfd69a9785bb46c05d26c1f41bfd81a42e61d3eb157ffc44cab7e3e019b89bef1bdbb9ea081c34914a8dde3a269db8a7b85201457e86be782dc2");
            result.Add("sk", "3536515a23937cc94e6969fb8646b5d90303d6c76f942b7ef09a1f9c1d361947b6235e75e146d7598028dc5fcb1b014a03769f08bdecb3c6636e9031921c9706");
            result.Add("sl", "5af25cd7ae555d4d61c723fe813945ddc591d809a8ea2d1744e84775be1bc3791c5fcb530ade4d4271239f1de956cb32ac80f1512a3e61cdf23d1038b439ebd5");
            result.Add("son", "384d81c36abc92582185757c8706b23bbd5a0a29c1fee2398d0f33fdaf4f6a36ad98867fc068abad60773c509c1b3adb8a21d63561d3a40f2907168fe061b8b2");
            result.Add("sq", "8322a0e415f2955bffeb089e84e6de09e248d5a0a709ca9516f741c374f96538659ccb45c3a3f2e6cbd75688fd320d0d5a51b0cf1ecd63070a5c334840117757");
            result.Add("sr", "7da95bcb723bd47e7032c4aa3651ca7fd9101623cc0533cff623d92b24434773e7185c2a5d7a8fc3a4a6440ef7e0cd1d1b0304f81d7d3bc9febfc1f11505c927");
            result.Add("sv-SE", "966bc0df0fda8eee81ed23ed66e367367cdc65aa3c6cf7ada0c84d947eb1b5804c1f2d5d8dcd0e7414d5b93fbdfc1ceede22b82b6f36c2f58cfbfb99fdbab7f8");
            result.Add("ta", "053fd7fefeadc3f33ffc802d037009f8a6a686ef1e51c7b41c6cd6c038d74d05a91dc86c5820d250f90e28aa761dd2f5b450e2b9b6ebb919aacc4a0b0128ab7f");
            result.Add("te", "fe31c7e6bcacb2039034e76f4b2f3f1671e26b6bfd00cbb6adbe25829673003ca23f6cdfda5519d10af77072e4248dfe1d1d36b7c210617d53fd4d37b85b4d37");
            result.Add("th", "a8c5099581b13040d760e12fdb77483a1842bedbd4447a0bc9745a41d80c5659a8340faf37845bbfcbdd9bc1045a284018f9aa8a2b4c5d7cea9b6201f8bc4887");
            result.Add("tr", "cc5c119d910eb6e2195f948e81e0d78a87a309759e109b8cf02eea15e10c3b8af9ea3a1d2b2968dd1651d08980f5cc07be0d6480a09831a36b22550f8053e5f6");
            result.Add("uk", "4de30483abc2a64a8c3daa278b527d990828f3cc77a7f639618675591d07580897a1076ada8b966f976f4b8edce1adcc0e286a28f1749cae05216d7c5fe5870b");
            result.Add("uz", "13d6c8b3cd96d76448cfce1893da46a6e480e7ae1bb41b0014b70ed7193f7619b79b64b40f60a66156a35519ee07c2a53204821234657f02ce73f74dcad21de5");
            result.Add("vi", "792455383773bc6de5b7efed2da5158d601475e23c8ea1d92ee0e9c18a21e960d911d89b3021db3c9c6ecbc983625defe712c323a0752d82c36159096e4ec934");
            result.Add("xh", "52dd990a5cf50da3fbaa38b1e4c85fad7a4466a3b8b37e79bfdec9ee559517807dec36a1504f1add79cc0063d8739bf80e61baac5c96da97f0d2a69f79132031");
            result.Add("zh-CN", "e53d7f6c46cb4c8fdb6a8699f12111119484b41a73938b761a4ddc3d85a9cec9596561e43e83bf4b39fd38582c95f534df7ee67fb863f860a9e9d74f728d6fa7");
            result.Add("zh-TW", "196841f286529c1487c29664be3024ae78221399eaa5db6f5fae7072cf65764c48f9c874415ea6d8d895e05766329947785a925d1a395c88294bbcb08aa2cf87");

            return result;
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
            const string knownVersion = "52.6.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox")
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
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be update while it is running.
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
        /// language code for the Firefox ESR version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } // class
} // namespace
