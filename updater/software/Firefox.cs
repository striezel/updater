/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/152.0.5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dc070976af43cbd11b776cd3128c94359f57a35519fc1a4185e58b491a1a7e7f2b583c187ddc5cd710426a6702d42e169c258e40033f900a49d2954ab4f87568" },
                { "af", "ca564c0bb4d17eba9ff53f499d26b4b21ff73fa95be62225ab18d5098fa25e0f22dc0e4e5208c2b3303577a3f1da5cf9c046ba77a6e31fdbb4fcfc72c0915d33" },
                { "an", "4eef4c5755aec85a2a686930359ba6394e7cb025a684bab29c20805a7a5a94963c9d915eef949bcd33c2ad9c9aaf8186394c91739e4efd478a1f6961a225ff7d" },
                { "ar", "43a19ab7ec708f1cda2211e125cdbe6ffcb3fdb2ad19ff487f52cdde83edd8873a00e90b8fd4738c336ea7012e51a5525a0bd3372057c7f22283074c09b4b922" },
                { "ast", "2ab91f786062b729bae6cec14f41ee6e2938c6a85c0004c4ec6f98241fa20b3ad27a1b356bfae3a8812b7358e18169d5faf6454a7c2d18bbe936a8e41353d2f2" },
                { "az", "d811d1f7ea7f6d82e650e86f0b0de840e24793eb5cdb8165b3993ddee3d98616ca9d4fc7aef4ea027ad153b22fbc8da026ccb30732ff91cd938a36b53d2e430d" },
                { "be", "f6fe0d4577c65948f6ff76be314319e1ffcadc4073772b4272e0d8b3621bdf1c8e984d518eca9f2540a21d98a5b432ccdc3254e819a17cee3d7e884ecc95d2ca" },
                { "bg", "3515ea748d3bdc67a75ae717f9b804f1a9efb6d58f430cce7803703e817b8f0b174806a7b4d0515dc83b4216a7376f424f9330b4fbb96d0928599d019ba1d4db" },
                { "bn", "229bf07d8739cd9de985ed1d677747284306cfcbae39732fc9f22822d2c2480c392f23fefc0701dbfd89d24263d66b762332f698dcbd1a6f9fbedbff245daa47" },
                { "br", "eb3af8cb8c355f00825e268dd1505281e133d5bbeb0a169946b511cc99c4a5d2b8ddd30285182aa24bcd324c5d06bb76c28f311e259b0a887245c195cccdbaab" },
                { "bs", "e3146204d13639148759e8e1434e5c7bd7dd1abe4abac7ffc8a1c887781ae315b6f247e5458e555546079a17c92cb167ffebca5897a9e249fd6baa7d4750cd47" },
                { "ca", "3bbaeaec314ba07db846bd2633fb5eda94c3d118f89824b4a385731e10ef46ed41c2f7f23be2bea944808fa50d0cf9adc505f5fc33f10c8e5012df28f335152a" },
                { "cak", "097715a8c2c29395803b35cb02c3e06a2a77db557f01c41ad4754fca2c6ea403e38d0c72f984f1a56719f8e9d23a7a2b57ec39743a75ccf764ba50012f77bfa3" },
                { "cs", "8b13dd67b6ba8322eeecc6336f35c728100397104a615c1487c5d5dbd94b8667e4441f83b11f001b41d2a3c0dd36b73c825752ac0c6d0e2aa2356343fab99a44" },
                { "cy", "b8acdbcdd593f8ab1970b42e8138275aeeda37b306483645e807501068fa375e6d84b7fda5c0af7c41c093d7d8109df0e25b03569d818eefdf970b512cbe89d7" },
                { "da", "826fa17cb57692db3a303369c56baf9f5d6c4f5b093c38996c33ad29cc918dbd89c6046bd1cc63eab83b0973800a8e8a026ad38d579f3263e14f897abb1e25f5" },
                { "de", "f53254665887c5106263a02704bbb34bf27ace68e78b8cf33bdc9ce8ffe1830558c5f408fd08ec712dd94aa92643b0983599dd848d92fd77c8704bf49e02189f" },
                { "dsb", "f516928b99ff33539ca5c6b277194d329e9943cc30f03c40809b29a3a6443b40d7cf57bc083000c4fe996f443700a90d7b7f130d1301c4ac24b6372845f0adaa" },
                { "el", "ca70f49fc527b1f1feb8f5195a77f0256f9c4336c223d68a8ed295a96c799b4493dd7ee50dfe3442ef50eea91182efcf9a6427442bd2781947ff6c476a300273" },
                { "en-CA", "0cc931d430186934d46c141c4245bf911c45fe040d32726d01aedd498e5ee158d6029d23c1e902aa301caaf139dd400aa3e7e77d2f89564a329a42d066151bca" },
                { "en-GB", "d99b4f6f7742bde5bafa13aa5a47080f7c919969ae1b9e3036b0059e3cdd7fd03bddefc9fda5e3135327be95ef36e7d66351eed111ac8473f720848efa5a225f" },
                { "en-US", "0115f59cc7e7cece566a9247cf896f767fefcfaa7d83452ddab6593167b1dab68d01f4b945887e97a6b3aa28e8ce8b6868ac8c70197472dd7fdbb84603cc9065" },
                { "eo", "e08996544e060350519a09d2ddb75e298be95c76601e78b5ddba5f70df88c90d523bb853ca657cb195b11a1a75322247954cb66373c18f4802d7259e8fab69ac" },
                { "es-AR", "828adbd188f523a8145fd211e7f6a99edb5e7193a1a918b904471b1783ef51717444eeae85d699845770633a0954b2a3528fbcb9b99d550c3024bd019a9f9302" },
                { "es-CL", "cbbba3e00b8ae55606a12625a63e026bd624e2db2e59743b813eab60633f57baffb029a18fb3685073d8313a0205568ff060cd75563346931bc2773831952025" },
                { "es-ES", "e7c596f7a8007042a9fd3bbcee9a80c6ab9e8cc0d96fb080dd81c31ef26a44b0c8e262c569d6a4823a4ffe3f4b5c16845f248285cb02ae96bf76692b355b4789" },
                { "es-MX", "3be09d0aa9289e0f65d3ccad451a8844ba6292afcd27d9624fa8ef9bdd977fd706b6a2e24a6b45746fae1e174db21c8b5bab9532f978d18d6d7c87e40ca8f2ac" },
                { "et", "91cea4c7f9537179ddafe18284a4904269faa0d1a2c3aa4721398285c35ad764e0425b0fbd89cd5bc09d81e0b11053a36ddaf80803fe4c4b4b037d6f05d49edb" },
                { "eu", "e7d5e3ef5d1a2008ea008bdc7d9f9713114dbdc50582e692c1a5c2bab35548b776783af4d3f3ddf8d44af8b62611f8e1f6b6cc200275c2f692b739b9a90608c9" },
                { "fa", "8ccd75f55d3b9ed8e9b2387280e23e1fe1877c8602fb58442360ea0b56aaf0189d8c8a5b5391ca7ff7421c11c583406f8176e758733c286ce7ee43166696012c" },
                { "ff", "0103c4fc3b62061d616654ea99b74fb6f973d7da655d24e1dd43012c554bf6e0b5f552c24fe9c990f8b25e77b784e4c769269c530430f21cd68e00cbd145fc0c" },
                { "fi", "4062a6ca90007fcc51f608448ccdfb3683efd7bd31601ede8562aa108875e500108d173b7ff97b73814d70c597c2ee87b6233094932380ed1921c9e27ab39991" },
                { "fr", "53a97a95228cbe39e28d4c95bcfdc0889a65a7b43c3e253026ad0ea875b0071e533c9958f28ae5a474bb25280b798abc2a9e643a1e319b6e1c64e7768ad1e361" },
                { "fur", "d2cebe25c714d57a250bb7da67ea731fd1edea8be9a2ee52a9c9fe1cf6371f72d789c7a183160f62c9613cfe30300a7086e6e1fc6aa79cd7be3dccc387b14dda" },
                { "fy-NL", "11ae8947046c8a02c5cf28fe6e8c50a16f42310dc955f100f0f2b2610c63eee7535ce77294a85ba85f9e145286147596be73b4335c015a6fa6b8b5549eeb4754" },
                { "ga-IE", "e2aca9e746b3cd348a60e8a829fabdb65009fc7663bf5b2dc6905ecc22e0777b899eb2d2f4d6d9417336a1284fff40b885c086fb0a628cfe70fb8b9e42b66021" },
                { "gd", "46ed41714234835a680b1706f740cac918a17d894deb8b0cb82e8b9563d213dc2705ed8740977bead888bcfc3070d457876c0d3ba3a7d613460c27d254605168" },
                { "gl", "753e20aa636a10535fb869da97367171a9da4c00dc915f1d4a244c615e3f722facab1be475bf6c9f54e77ca3a1d51b2641d42afe9ae9123978eb4d55104a43a6" },
                { "gn", "08a90f99ee2800d0abf94472dcea9ae83507762230fbc6563bf59e83f01608efaf87b42cb42c448529414cb117f70e52405ced247cee73153ea77fa953af4fc8" },
                { "gu-IN", "f096b8000c679e7288f1f0a4b068872f963cbf2a2b6d0742288bc76a374dd35001a23a054b186ed560259d4db116d1ab2a40fea82ef9bb07ae1e59486213c2d1" },
                { "he", "e6f998afdc99295b07e880b17e0400f6a0118d59469bc7539bcab8772ada06db52925df9acfff456df349e7760ff7b32aba534b0bf230d84a11787ceb2e6e361" },
                { "hi-IN", "c596299dbf462f471f51a24c403bf144d19866c96c9fa70831885b51de32a0543164bf53b4343b990f48f23756976d0e65579c1b6ea146ee4ce573135096e199" },
                { "hr", "4bb09e3be94319854ad77e95b725f74ad49288baa5d38ff70ea7b374e412646f70eb4d50c9121903cfd8af262d0f041bd7e8e194f275d7f87e7f2ce701d81cf7" },
                { "hsb", "89b29352fa7befeea655f6ab3bdf5b74b583f77509a01bf4f495582bfff2f45d80bc287ff8e736ffb877b190267bf4ae583a06ff4b367655bc651ed8237e5856" },
                { "hu", "a24f45cf4e7127b436ff8089e246b006c2b244e44a64619133827bfafab0da01dd4d74e73ef885371fefb1edfb55f3addcf9adec8b117289b714081c74efe369" },
                { "hy-AM", "add636be48111350b463c184b6bc974f909211731ac07fe0a35035b81aca5bd758f12258426b6552f9fde6bdcfc2b430815c700642d6a503ba9092f996a5d2d5" },
                { "ia", "a0e4f5c89c5bee084cc9dd72fc3c10d15639b70c84f93e23265ac0121fadbb820f5b37326db9a7b1ef03088622938a03e904f0933f1c37198b03b563337d253f" },
                { "id", "360a40ba9412f81024793eff952c0fc438f4190ace60c3487d22b0a5393b42ee65345663c4ea22067157fda065544e33b338ec94b4650f046e6fe2a30fa010aa" },
                { "is", "25e0ff1ac2107db3c07f60f2475adbcd93f2452d1934a649b5f257d08485d347ea4c9aeb41d0e21f337fea71fa83b7a223463fe21e84aa39dacdf62e0e04e7b6" },
                { "it", "04db7883d7bb3a238afde13fb9f7be5efb0353522967c26ccbefbd6961f90ab4a38914feb2e017b9d376e04c88ec89f2009ef5f0885bbde09d6b3e4035dd801a" },
                { "ja", "e7f1898e5279ddf64990ba8ea885d82bbc5828756c3a18cc99f1720a4ad3c02901d83572f21a114241cb5b6030af9132bccc6449e5b06dd601ed4dc848ba2e3d" },
                { "ka", "5485b4760c38a4fa78abbdbb3a9e77d2e231f9b0ed4c54158900a3fea0a9d0f53561c4a8688a83a7cacf2f63b7f0d23781b11c3680d5750db7ff77309a425cbc" },
                { "kab", "2d22702849b50bf543796ea35bc938c3991878368925a6be724049a123235f368dbe51bc203db1203c5d29207ca3118fc29471d4a8f71443da2ed9c6aca8272f" },
                { "kk", "ed9db5190ebf1f951190027d809606d736d32574aa3a70e651589283ee8cd3682ad6b460f2ccb6231225179702ef2b80b118166a65270836a1fd53dcb5a9d665" },
                { "km", "1e58f1801e997f282161358af03a3c0523e39750e84b897dff508aeb44034502ff7fc43a1cc8435ae89038789bb28adc29672feba73e3d2ea69c04e1b03183e6" },
                { "kn", "a76339fe97c98a7ac97338d9e50a097e9f0fe94f3396e4cddbc547d5f74ab9f70f35de9b18dadae61a3a732d62066039c522a71d00aa550e660ed3c8964ddc5e" },
                { "ko", "3ac0e87a535b8f10fec1ab441e994cc6c6c09c4c92e06455884c48df8fe5c7b30e40a59c9dfc5dbcb00baa148c94348d031a9689d1b44072944cefcfb996d456" },
                { "lij", "93022e368da2a3102f87823ef49423f8b1aff35990210eca31febd0565c094c6ecc062091bb0c213ddd60371348d660309bae507d19e8e5c78adfb63d80cf9e0" },
                { "lt", "b4cb10ce9730fbb4224c69d8bfe4f69efddc673d2edc34745854cf15a2b29dbcf8dc76d26a123738e6eb27a431d3debcb6e088620b91768bf9eeb3ec2013f008" },
                { "lv", "19250614ca164d5fc98bbfe97d21b88eb5f2ffad6de07d263929a647db5af77c122a2e5ba3d48a513a0c96b0a3b8ecc8444e48522fed8c4c9f03791d705e84e7" },
                { "mk", "fc2efe864e3917229df6fd826817c881f11381ab9ec3e684f961dde827819ab1ba31efeab951da2ca864fb79d212e4cfde41bcb78da99bb1134cd5838fbb1931" },
                { "mr", "9e3c4f5bad6c842ca772895bc73f4ac927c41e1343b6747f84bbe4a81636c2ce105ea95244bffd5dd54b53c6d8529f022b36d8ecf525708cb9aec8d6b01b7d70" },
                { "ms", "af3d00f14db75d8abac19ab9f8448654c79270ed99139fc9f968eae70ef3f02d82cc83a4f485a04ebc9dd2a0c093a55d2d7804c042b94f950086d4daa60399f2" },
                { "my", "2e423411cc7561c41084dedf3feaace5f357ed60e0c7c20d5382c41b969cb368943bf62c7b07baeefb20bbfaa0e13e98767a5587b88f6df33a5a390ba1152154" },
                { "nb-NO", "617810bd8126f53c869785401e359f77bd9938f3c4df8dc0dbf81b42a1279bdd65167c19f56ed81e6ea4d0d789041e1b755c64b891dca56c13837327069bb6d8" },
                { "ne-NP", "9ba07b15c31eb941271283063f21ef694e80ea994e73b69fec8fb22261cb481011a9170aab9853c37c12e181ce6bf483ee0c2839ea0d71b9208bfa2aa951d06c" },
                { "nl", "f40830a6242e6a40ef8d97e3147005ff41a1b47be59bb4968c436fe303005202a3ef327b6142d53d23819a5bf46a4dc673b9c4d4490004e32c2648e9c1e66a9b" },
                { "nn-NO", "e5a34a5c396eaf7f47a703c4747b7fa2ce9616bb4f14907e9bd5b88ba37486ec0baafb2119c4d2646c6af24509882c69cbf4e568407b99b998782bdfc9ea3d89" },
                { "oc", "009848499554badf8ddf5f08aa9f5ec96622940edf59801ff7edf2b9e53553da67c9d504548afbcd025e32ea87b8326d73730472ee29fe6235569b4ffcacceb2" },
                { "pa-IN", "a35e2d2dfdfcaaedd5695ebcb9b336b2f1c7ac90e6a519254104359ca42e11e78e4829ba1e7c00c6dffd4943f7121654011ccd1f83df36e7095813f18fb6b26d" },
                { "pl", "42c325a9b459f95007c9ade4f05ca20e0a7c9b4e7413cc167ea4e1e6c1311373b86ee15cbbab8b4b6b601fab06af1419526dee1cd796683ee0cc1ec55d4dee06" },
                { "pt-BR", "417b1b1c64681bde520f3fcbd8e79b7197465d6e1d93ec34472eb16afba1cbd0df1b80f2e2156b15e51d13b5142bef57659a1af05378ecaab5cb1eb70dadc184" },
                { "pt-PT", "08b64e03088837856b00123785926a8ac606554af37554e8e414793c4feaaf03bba5c80556cbe34cf6c74ccb728ffabfd417650a08bbc842f8e10ac585f8e19a" },
                { "rm", "ed5875cc66649aea77e71d624264979f2e0b6e2b92308cc34e7801eea6061646cf6748feee3d82214a732114391567ad74ce6966d0f2c361cdbbd0c66fbf6849" },
                { "ro", "e969a13540550b16a12a6a11f9d5e8a0d3255118ed22baa5363118b42630521ee2683448044f3a1ace496111e9cba987efd4d5d76d682dab13626d4d1f20571e" },
                { "ru", "786ed1c3f04eb34e64be57c39bfc09f2bb4de1874c0db4908c385de0de62061c9a54c2eb1d0058d2993efe62b715bed3bd225cafc62606c8ad5cd742cb22b252" },
                { "sat", "330fd2cc1290451e5baadaa560d3f5d2a1051289ff6e7d7d8fc6e56ebbadc1d4d1a89387b47c643b46c234bf442edf1b45914df1d0a639a5e5399bdfb87e058a" },
                { "sc", "c7cc40aaa24c828c13ddedb9b209196242f61903171d99a1d8f422997b2d7a1fab2759688c9f7b4080ca7619a86d8cc9a4ecbd85771664150454611f797218dc" },
                { "sco", "78f1608e315e2bac0f0266bd33b6175c8f796dc8abadc8b0f1d7fc905c7b5e7f65f2ade67f45aa06fe7a01479611eee5a03b67313afc4aec7b752cb5647ec255" },
                { "si", "c0b63b6b1f724c24cdfa68b66f56a5ee7cfbb0e68036eecab310d383e97b806fbd8089faeedd7e45876e593f36bb6c9fa70762e4a772b6d9a0c23bf09ce7bf35" },
                { "sk", "e67ccd9a48f9b07155258ad2d0a2d09e1b6a81159424fc5c9a2af056acfdc1dc7920ef9c6331fa47ac9315aa59e485e1957cf8c1ceb27977cac3c4e47e64557e" },
                { "skr", "5686046a5e61ce1848d9050261a3554da79a354f96b381982a0eaf67ac190bb64122f85cc207015c46e8d8e874a7b6ac6545922f7693d0205781b36577db66be" },
                { "sl", "1484d826475adc51a0112328e1129a0ed13eb774098d95769eb745467b81dccf6ebafdfd39699a2f5fa27c85de9219c0d37ec67545643805d41cd9531fa7c903" },
                { "son", "c0779cb0c357878bfda88063e652d5f8698f60964ebc53b509db30f4d2fb93443dd626f8de4f7d9496043f3f963ce4a716b4ce10826b77f0806a9e51762947d2" },
                { "sq", "9d20501b4cac8e2faf17c0f872611531572e5dc47120288cddff119cd3cae3a045d8f49dd1cf96ef909cbbac536e42d05b39d1438d3b504ad470b4aeb16f339e" },
                { "sr", "ecc2dcb54013517f511a2ec035ec717954bdf1f8deb9239fc503d1770217ddabc98ea376cbca16bfd6afd8526a68a2aa5d94e3a3b4329bf00439400fa3cf9bf4" },
                { "sv-SE", "b3b7aa86f12322fb8d010b19ef2429a162716875648c0bdf188f1c274e6b2de3c732393f2e6c764c3041fb76ea3f0905e2c587f4be5b7e445dc4d468aa7d1e10" },
                { "szl", "c7ebcea8e97107bc3c3bad7c7cf5294fd3bbe85c11838b61a88febbc3c789f8fa8157188dff627e07c5b6d1e28189e449d4649bbae17b06f63380a28280e3ef5" },
                { "ta", "2c65e4bc914fc77695807ffee0c6f54eeb47849c83c091aa3b7e60060b3d7e1f6edf8e5e4fdec1040f092ac76c2f3a56c3ff21e2bbc10e717d881ba56067df7d" },
                { "te", "e5949bde3a3a11e7314ba695a16884fc77d366f2ae823d83c70b0ab34ff5af00296cabc6ac79628dd270609ed574e940d22da6e59e5dbbcda4df52ccbe7b444a" },
                { "tg", "1cc38f734e8f01c2a79faf17e6deb5b35749c4bbe1c6debb3480a31ab34d3f2a7ecae0576f25bf26abcbafa0bad753da9704a163670505f4ba8b1c37b462cee1" },
                { "th", "f9b84c5da627d3d54b1e73fa428b7caac054393d297d56f346ca27e467fe6967a8d18515498ba9c4facdb75eeca5a4cd18bf7acabade97118945dc9ea350a30b" },
                { "tl", "006a3bae98582decdc3f9f08a3a1a427835db5905d4d24f67bb805cb090d0dc2fa7cfca23711265766fdc5053a1d21a031278a0b1012207a4fb9e576197af76b" },
                { "tr", "76b201df86fd4be1fb4343de23cd176d446eb0fad35badd95a31052fd4893f717b67d8b9de6128ec897c113fe53bc93bab0910b181c31c8b3e6518b9eb034b79" },
                { "trs", "8d1dd8391578c11735929c1f18dbd1f5a3c23c00caa0ea627f46b63905e1787d98a9f7cec1c0d2d45ced46923c44513b2f154209b7d38154d95ceb1da7e0658a" },
                { "uk", "c1c3b4ad838bbd066eb9124423c176143776cde5723d4597e06adfb96ba6b986b5b4c9a8837605dc7da70aca5b94e0d77aaf4b43f37c6a187d67ca92c54ffd3f" },
                { "ur", "11d6f0caf343fc341a8676be4aacc4ba1796570bfa0f921182e70504920061479d9ebb7f682c3d10d420b74eab13499414080958abd08d9286966d8de9c1b1a7" },
                { "uz", "1c79ca30a5060c59f228adda20c3b519ac0ee6e1a76d8455c7c447fb54100d66dc4cb94a5d1f35bd625468dd876a67db0335155ecb179ce7a3b800e18e24aa17" },
                { "vi", "712b057ad1570666f31bfd644b1b3c1304dfe1df02088903532cbdb50781b11a1c97fa4724ae669100656761b6847cd37a21bf3a920b7028f7d92a6a59f5ad03" },
                { "xh", "2a0e501fdb7dcee1b9bf1f4bb388afe3675dfb20ded7476dd6793b9c84604048eedc3efc21c12752e28855314ed92e432e5678b094ac2f4279ddec12a2835eb8" },
                { "zh-CN", "b8ed8c4b5865f9ec212e54a513de5b811171352f5978c247db5561285b7a56a631ab7d6087eb4019aebcc5d4a1d7f81080734da6877dba0359741b9cc37e9e87" },
                { "zh-TW", "8a4b2d93c8d0840ef0cfe270094eedf5311529037b8f9ccbc80bd236f4f37fc5d51a1a1045a53f099c64da6cd5e929602a19f08f8bdf228c69531fef374ac0f4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/152.0.5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7326650c2bb19dfda6e43e05d70fabde472a6724f6ac21d210672f67a5fd286bc20fee6d100ad87eab8e5c0543441d895c433c4bb5c530e32074e0d7c656b9f9" },
                { "af", "0a4a39bf4e695501f9ad7dc4d87ee89aaa76cb8e5612e4f875775871d4c3a7eb5271697d213b7d501208a910c846729633106cff0bb3bc5634cc301168a73055" },
                { "an", "63fcf7d434866d7369f4ee401c448698915b11f4a43e4e8d57ceba799a351cd2123a0a6b65cc0c804fe234f78d8f0b29ebdc14b1ce3ca5fe85e7faad03cf5214" },
                { "ar", "0f85b4f033993d5e7ab440753776e715c9621c38e9384364e217281809a05b47e00cd33c17d30173dafb635c17a3831f1a89a86274ead7dba335b0dd46d420d3" },
                { "ast", "c0ae92f8ad1a2d67bdd01ff680deb196c8f88e7cd8aedc1b73fd3176ffdc59502faf43c6aa6250fd89fac4011be8c2150ff129c3f52fcaa4d7a772e644d245f6" },
                { "az", "b2aa312056c35c4d0ddfd42be82944156fad65c3d8e4bfc999622a955ada641885ee033ca2aa7d5d3e623323a124f674922fddb682a75160b5784b54f1a61743" },
                { "be", "9165dabcf7d1b84d3e3bf33ea823b89126d09b9bf80f26b0e753e2d3eda9f2a976ef2bad8af2445e3e01a12422973ac07484aa046cc9385b2c69d5dd323168c1" },
                { "bg", "d66959cdc7dd3302cc50e34f636f83cd6e240af2199d15f731a6a90aacb94a5b322e30fd87027d036d690fdd9c56843b46dd0e6dfe32783b04e16bac69b65309" },
                { "bn", "ef5244ff791bc176b5ff66f6150df0919114a7077b0b0c8356ceb34213b5488b29bb40c758c09052b6e20889f9a970b520b60115e481ae0495d3e3e8a560c04b" },
                { "br", "ba2520293690e72c0993707c67986463d44b9d995c196bf612ab7a4435c1c8f4e3a826045b6cd304c6878664ccbed381beb930807d348b687bcdd45dd116bbd2" },
                { "bs", "e5c4a0bd4b8952fb881b4a8c40d17717d7b3dfd4372792361b40552567181fb118bfe2e09f745e2a66723ce441d536213b9db55fbeea359048c9c2916ef70642" },
                { "ca", "c544628be35cd2562f79e203c914a5634e05961eb0237d7e7a4ae9ccda6bac1bc1bbaaf381ff8ad93d7535797925ec10febf8f8c9b967629149055cacef17a47" },
                { "cak", "8c6c32b62c5dde2cdf6af86c7d13b75ad12c2a9ab9d7714c0a305f79f2cd73f7302a82f4a30bde0066c1b85fe2059a42c42e7f454c352e773cb67c4a34041aa1" },
                { "cs", "18f57a59894e0ed5a3ec640b5ff3bfed073da5b32c700fa894f37998f5f884b35d7add8363058e0278d32cdd4fa379b53af158c8e2c0f9957992145da7a3ba5c" },
                { "cy", "9bb249e86ebca3a7a0db7f11fb9bbd529d159bb91191805c2bf52312905f19028fdcb8e44833a982ea4028a2b05220ed732d504da482d4498d0ac7ff512df729" },
                { "da", "38911b0c7eaaa269039d4f23149025e95ad44b8467efefff94be157c1123872e27bde0a977739af9b323d009e9b15c5f2cb2ee307df1ea8985a7feb5b438e5f1" },
                { "de", "9aec731ef3cd06e393aef01a990fa4d8697e8ba4f45f4f644b3ac16c9810c62ed3bc122bb06c5e2609d2ca4243c61150b8b444524d0ca2863ea1ec19c665460d" },
                { "dsb", "848343e8cda617dd9fb018bca9cd0521773eeecdb35af16c60cab9b2b3b59b8d19899b642e4ea9e7fea0f8082a1ac37d0870873242d5f724d353e64f87a89483" },
                { "el", "be2fba08898c8da6634b32320c90ae2c48799bfd61cac75e070ade18e13b1651f950fa1e30237cc5448c79febe9b5daab755115fd5c8b985f6f1b92064d8b7ab" },
                { "en-CA", "d02238eb09cc2c29ea46188ce0c9cfceb408941cd6c6d24c4e373b882c48e9c01d78a666db0c1d3e7e27045f1aca5ab949c74a1b4b86a1e4ff868cde881a90c6" },
                { "en-GB", "16fbb03eda9679bd7e1c270c2c921931f63bb0c34c77878d53a49582f26d819791e7a448c82852b560a2573ed33096315ef9b85ace35a28df085057c03b049a4" },
                { "en-US", "aa3a99577c2509761ce7aba71ac433c7f280de6687456f96619687ea9546f511be42b63cd1944c4037b0e9d38cc4f6fa7a008632cdcb247b59ad2769fbf4107d" },
                { "eo", "b7135d19ce40a90cd03dab7c8cb13f7f6cb2c2e1c9ca5e197d66ed206d6f4efbf6095f60088e6f67ceabc9612f3bcdf3e9e237a3f8368575d37237db56426c36" },
                { "es-AR", "94488ad2f1c40da12e3fe152a9a6841fc49d9b47cd0fb6427d5a31df9fd47e1dd425977916ad7b5a94e21be01ab4dae542410c02aa1139bd16018d885bab32a1" },
                { "es-CL", "85fc4119f4cd76b8bfaec750d5f993149d32e1ff07af8ed5577fe031f75a23472c7469e5925d1f517e3c4c2452482f8d2075c6ec8e73ac6e54fdc998bc605df0" },
                { "es-ES", "f30f7c544b33f0910727f626d4f7441229bd583bd897cbd714f101fe7e2b896c4f969c824b6518b9d44bce517125aa37b2942f97b42aa7d58841b35ff474bbd7" },
                { "es-MX", "c8265f9db082c98a3ec0822a6ebbcd01bd916edc108cc0deb08d2863a2a6d03707d16c107984d5b1d9987123e6815443e54a45ee42796e0079028749d68330bc" },
                { "et", "ba543ed2f28c1dc1e90599d920678139e8027ec325f496a477d66e4f56eda4c05de6b9e72c5dc1c31386cab656115624175d11fd4c0dc20dffccdb05a3cad64c" },
                { "eu", "771ef79998295d05cf20ea200fdcf633845d398369bb02ba5458a5398b78e893376905a9e348a23c66ac09da6c961a17556951ccb5f6a264abecce31e682a996" },
                { "fa", "e01c1c602f7682b4cbc85e6e9da80cece841aa2bb5fa7aeb1feaf377597cae180e6fe8f648a4fbda9e069d6e10a85e5ae3c2f20465702536728bf041983f331b" },
                { "ff", "ad1b347c1a02e39f86a6b0d9a5c5b5e95be6c2019c2ff921482d74d24673dee08ccb36a914f62b230cb8990da2c639787ee26c648caf44a3967f3b00b553f4e9" },
                { "fi", "e9e4e947d57ae2b33c6ed5efe492c1e44b3ff1339707169fd3ecf51dcefa2b85c06b37d3a12dd0be52626de6c95b90721f5ff2b665c0008603b58cb030ffb65e" },
                { "fr", "fade58d072199d297acec5497f3cfa84de4ebab84db7e5dfff9bb5344443760e451a60a9c85b3ac0f34d21fb1c1b3beccde639c69a8c68703757166312a3a214" },
                { "fur", "a5582dcf246dabd81d4e9c505968abcb52d4ab1427ce9cb7750fcb1890e2328d448c255b66d3431f1f62b1375e071bd309dc4a123dab5ff5fe2733676cf556e0" },
                { "fy-NL", "5f63621f93da2d16c55395289326b518780df02e3c7943719568d5c5838870a467a4c73bf359dc925a83e1826a0db3b431803973f6e7c26936c957b4f66a89c4" },
                { "ga-IE", "02e75bda8c302686162d7d8dba2429f6c79cbb9dd83f333c06fe8b1aebfb71b4cbfdca3d46f0e2a94a397eba968e78181ca423d0ccc9e9ed3753ed5d91fd3a38" },
                { "gd", "37989f4659d7a4f1139383f275ceae7befc29e0b7bcba9a53af6340016743f034e69e6af3c5959a627cd832d9ecd29b5e75192ac383f987937f82c757fc97394" },
                { "gl", "57e35ec0d2d51f3fe8cef3eb9709b85d15dfb91331657eb19b158c7977ee8dcd25122f57aac537a53ae6d2cff1ef6c8c457188a5427e97f6f52b9c53856fa8aa" },
                { "gn", "9a8ddd604d3edfe46188b450d5ad81b12f2830ff76b9df426702b355e4bb045341bb86d0cb4ce9696711e72b407604103930b6a3549804e4ad3adc7031795348" },
                { "gu-IN", "138df894359864dd6f3003db802474be01ae864ac6d9957ec6df45ca5400ed1f8370bdef049ae3e05efd6e9031930dc2a0afa57ca7f9780f5fa197bf495a6875" },
                { "he", "708ca1a55517e7288f3f2a18c42d0fd630483fe0679c66314c8d40cbbdda323a6702cef3b9a1fd9610c1a0a9c9c65d4db6b3a3b0c7320d70f9659421c8e4878b" },
                { "hi-IN", "927fc35605b8bb331372f872d51482fae3530081476b865d4358ed239f7e42bdc4ac5a362670356a9d87f0f00b5ca83dfa12f8c3761cd740f5a6330e3ef1fdc3" },
                { "hr", "2e96e1d81fe2b9e9c1f2439f770f241cf5e0fcbb757e126b64a9c6f363c184c73ddd6c0611b92f0967c2837e58281d70907002a85b041151da889911a26cb5cc" },
                { "hsb", "d74163d712314d3d363f39d4ecabda085b5b4384d60f5452482abbd51927bca31372babad339252357d56a8e2cc6de678f3481efb963d78b883e5b23892c7887" },
                { "hu", "4bc764f2175c0df07c452215be201d078ce8827bed9bbc7d953e7316f80550dfcdea8c6c9145bbef149de292753f2ebb6a58206087dd4db4ebd2d3323e381a0b" },
                { "hy-AM", "2e2768c57429347fc2e6f6139b928e43549bbb4a05917207164762fc96d5d7e5ab6955ee15a2eea2d5a86d2a7829246d9f6987bdba0d4db0141284e49012d513" },
                { "ia", "75ea056c3a933a477b5baa93ad66a7e7db9699c6feaeef15cd703b1cd725b38bebf90929f82cad7d8794e8f75e6627645de1c9262d71121770b738fe0fa275fb" },
                { "id", "1b8a4159529ff8b1a4257f0fa786431c745056f5a6652e8b4d29da61f407e856a198e260a1e9d94ee8d779ecf48d6f670782300e9fc741a1af55a3c02cb0ba16" },
                { "is", "6be20264c115b91b6312116b734ff287961caf385118fd8e2f2fe58ba8d9028f7ddf7fd4fd68c072f372ee93f40611d84aeb31efac96acac26759b5643f7c095" },
                { "it", "1c1746765834576d1777593095810820a8731b9252d0ff09212b474cedd1019e5b78dbd1525c729bf46387ccc88496f5054ed80d955e0af9ca3b32a36b957763" },
                { "ja", "f32c5b91795e513c9e07872cc494fcb8915c3d97bcdfcebba5b7e2bfb30da722e55aa08e787c958113e66b4f42a163fb4a220a848f7b97f8ee3230d95d55096d" },
                { "ka", "fc0492241831c5253dfb64d0470ba218bf74e936f0a247e6c830fd1c0271c63fc69345c0189c6e16052c0d662aa41f405ad84f74bbf58e3f34d3c6429cb437ce" },
                { "kab", "fa140055ba858ceabf029c5f5458897ccdd8460f013f402856af7da992163be06db0a3bd43a7b7f65f193687de985a203eca4dc9e7b0b273b4a7b1af0e0d9ce1" },
                { "kk", "7e3754e2156fd80d11dc713ea9ba1ad25d2f886a0211a28f65a6d4b96bcaa5a728556fde3c4ab86b3ef4c92b28eae970b45c8ce95516bbef5dc70007c140e64e" },
                { "km", "958b88c881cb46c2b19e42057b4f4167be46ecde8cbcce2357e9bf3e955c9b58c1a1ccf0342b64db164683ca761fcfb22d828451788571f2e7af2b1e94d618ed" },
                { "kn", "ddc4c3501de0b80d107ecc0c17b1e450f63b19a23d14cd6224049f54dd01d194a9648daa558e9e0d0b3eea19506813bc3730c867421a725e920a5adfe419c7ea" },
                { "ko", "59e04b0729d0f8041010a38792aa6e81725c600f2d92d7ccc19f01979b1e50ddd6dcbc2c4cf21cd809a5b8aaac74b60177b656c0fb2b6bf254b70cb00a9281ae" },
                { "lij", "56f0249882b9a69ae5361f82e3645c3afd9b8b7bbc26092f1cbe1e62390b368141206e480a621d528f9c646420b1df85da56aad246c2dc6ec2ce4b79d2b2181e" },
                { "lt", "f7168bd7116b9df70576384607dea1834642a3ea81f519d0a72239f6effb0727c0dc40ea3e9829d30ec9a6b8cffef20372ae1456344e70f381603cc14edf5117" },
                { "lv", "0607fbf417830f08178f501bb156d58d1fad7b8c982f69b11adc193c3dfef0e66c37d03c08fb23250c954b1a6cd018d5d02ef88f5a0b1295c62a60832fc8f860" },
                { "mk", "5cfd9087fe32efc7ee54a38c6f15eaf244f34a9d007b11e5e71d436db7ec66e9796503b60d6f6347b65b4d9b686836d5d6db1133ba99c6c8e1b33d1b4c49e96b" },
                { "mr", "4598eb38691686ec4873341262e3b75c7012d3591e4c448bfc2d362136130ee7adc65f9b985c2d071d247d8bbde7eda22e1bb6c63b2bfbf47235b86fd46d43ae" },
                { "ms", "69ce6211a9e480e67fa0444a549878ec0d47c3d389b87adb512cd4b73d70955887a2590b99c518cc7c16a6c9235e793c8cc37f4f1fc46c8e3ebbcca290cafd55" },
                { "my", "1ac51c977264ff4afc28d3eff30d3772ad5ab2aa449dd250be098ae06339821ae7945254382654ceb9b930932c821e8c4fdd5b445d5bf6a9ad8a215f3d945ab7" },
                { "nb-NO", "83f5c180b2096a1497c83dae67fda844d728a1ffd64d827afde0fc195693a78758d53c4a27e3e77ef0051c64a9bf4c192ffab79dde69e371a66ab525250c6554" },
                { "ne-NP", "a65bfe6359e5bbb5f83037de84a394cd2d6462da5c3d1bf39419b6758fee1d927d0f59f0649817bf9dc7d2455f0565dd1480749b15e1e034d70b1a917b4835a3" },
                { "nl", "81ef0118fa153850f472c0c9f4dbb7779344d6b32773e3b8089b24c99b18a4321f806813ce6953f9003287cfb2166904311bbef5b612d8549627a7f8fd364dbd" },
                { "nn-NO", "f21c819cdd3ee1fe9ac6a4b3a049a447f93131e3bbe9d4b2ed0f26a9a893c6669125d9d9cbba56993f0778414ce5936b969beff327a4a447c497ba8050479e66" },
                { "oc", "598656a3c6d8e2649962606151080eb94a075e977a7592410e7c04d69d41aef24f0f203412ce5386939b6238bfb624e364813f3020a7acca5e9f97e58fe50cd7" },
                { "pa-IN", "c8db5d74f4d47e0b3043a79edee0d5cc2e23815deb8a85e3904bd1f6943456abe9b14142ccb1350135ee36a38c44848a9ac9d6d479ff7f9a255dba0caaa9c05e" },
                { "pl", "6b7411f5503b659417d3975d810300f550d48511c419594244afcaaca2505962189d25abfacdc72cd9f2b8aa0b9c02581e27c809e3d53bdf53b6512c844433d0" },
                { "pt-BR", "865bc60dcd124aa48bf6fba267a4e650c4457fe7a0c657178157750f0be7e82531563380f10a7d55879da995e1b99ab909cafd33c2f18386d7dbd48d9199d321" },
                { "pt-PT", "69d9134fc662ec3f959f5bc60d2b33e9a0c34eababda6fbe6bc20f16ddbd4a497937bca4daaebc70235c38238630cdefc7bfd917487ce6a3e86631a4077851ae" },
                { "rm", "6693fe01cdc6ed29a8ad5652d31324a4984ec0f6e3f2e6255381db359172db21cfc477e432eeae0fe2417a5e8bafb6a5a27ca953020ba5a77cf147be68865f39" },
                { "ro", "cac96237b04d693d4bf4dbfffed9cbe221564db015dd081eef504798c52c5577ffd179218a116f81a4353ba82a627d78436e6d8de2c3c5d84cf933d28e8c2149" },
                { "ru", "ff1b051b8963da48a7ecd69290885fb2c5493cb3e32f52f0496d10b997ed3092623f6ea5794327a4ef1db2faa44b9551a8b25fbaa0fe2fe69e5d150773fd3339" },
                { "sat", "8806bf81abb80c9290c341737117b9ca8ae43b973a70db4d39ee955b41b9c789846c69b29240682d9557b414d502d87973aaaf58e0727501812b780f1a504e8d" },
                { "sc", "d839fbbd8757d20d22a42618ed4b955eb82e3b783aad639dcfdd5245134d807f07535d7ed8bf439b5563c8ef942b647a7bd3022f5a82e6132dcd58fed7e69010" },
                { "sco", "2ed7fc6a773a4d8e81d2f403d0e168fd23c30c275223a498855cbfd430902d41bec3dcd29ccf3ec5dc9cca5e1eb7df724cf683c7641421eb110f875643338606" },
                { "si", "19eb70cff074468c1e567f8ddd22bcf6a2df8e13c77a46af45cbfe0ef631d0f19c180971607d74f929fb53df17593d8b3dc24b57f0de1ecf0d12bf5b1a7c29fe" },
                { "sk", "0ab81838d25ae657eaad682fe72ae77b80e797617457b3dc6b713407b8e90e2dbb86163817712d6a3200b74ca14d3f18bdb398057c21cb7f96600be870c0a03c" },
                { "skr", "71d3e88eec4e401d798259ebd4e068ad905cf81f74d4a9bd7df87d25d4ff7aa016554b90ca9323a224fc3fdb34d758fb4aacedfe496edf21cb49449dacc47b38" },
                { "sl", "40282752273b2591c32d00fbbe30447d1f9f257856a1b4ab816a7b447a3b38212f6749e8a0ec09a87799ab9e66182d118308fc4c4fa3be542833f588df50591c" },
                { "son", "fa168034d750135a5b70e68085529d4bb770d0179536613eb2e0ea134562714cdf4401f50a6dddf0d15b762cb775853cda476251abe5258a2d34821bc997fd49" },
                { "sq", "47826de6bf295638d8acbb1bba5a3b7d9355e90a77b27bff23b5f337462e288c27968f7f52785f66b8f5b5defd38542555b5c9634330d392fb2596e6042a2f7a" },
                { "sr", "80ce66bb4ee1e379ff5b7266488847071ba7699ceb8582df4159d5410426b058e80ceb848911240a7054010a6090c6de236a265abcf2bd76f1573d45ea656867" },
                { "sv-SE", "5242c1673b23067397b54497b859a4b103dce390866c7b480870ce9e4ee57091e9bb8865605351b3622192fd3d91459f15952baf2f45cf9ecdfa9132fe98ec65" },
                { "szl", "dead3a247bb7404def1e7985e104230e967ddb430009f9920af1aff541d710c17cb12e79e239b7a5aad37d3b258ebbea6baba9360f30f9edcd35babebd75ee49" },
                { "ta", "26f64344b985768ea66709b2c79a1f5de140dc8f3d4ae9ad30dc1ba9c19351b386b038795993cce0a556ea72f69ff778d386a5fff9f952f086b0027117944106" },
                { "te", "6190651a2f4b52c3c3e7198fdcc7f574206598fa1f704fa940a44b737954663fdbda6811dda556c836d3d1944b7d8af3939f3fe4222c8aadbed43eb388263521" },
                { "tg", "f838a6315a6c3ef2676ddc4fdc1f98bb2d6292e50cd4e10b9a2b503c1a3c4b3be619889391a43393a2dad9bad3ff24e8530fe113692eaf3c300ac5d32851c15e" },
                { "th", "414746a65fc0fb56b78a0a3df042f0e779dc18e4d02686538890a4b995dce064ba30748773d813437ebdc2750eb1990340cf26c8c335ef16bfd8e606bf54a9e8" },
                { "tl", "fb8e37fb81066339f8422947b1866e7c56ab42e10813580e28957f214b6219f7d948642d41bb9f48a92070fea79ca0bd2d06fe4c29c951a3524833e004d0b195" },
                { "tr", "b496e07e79e143bc60b80f2cfa6cb43fcbbe802a838030d3fc024cc34f277d3f8e1ac95242cadbe92512ec11d2496fa3c5c4ceecc7955bece5ea4dce6fd6a67b" },
                { "trs", "9fb012a83fc8bbbbb3626df52332aac9e33b7c0883882aa43f7979eeebac45bce69185dff415beb0a60000d5e4ce5f5565dcd5a4262f612dd15977615a8b7905" },
                { "uk", "55628a23013acd63626aef4322b02c13c5566e9c7faee227b72006539c5b230965562ab89af6bd691bf69e20edd977c4abc1118f0584a8c5e85940dcc7aa01de" },
                { "ur", "d6605174ab5105e80eb6b4464ff922984d635f4c31bfb0ad3d57d3b25a45051a2016b1cd6c93f0762deca69ce7a0be29d2772e4c9539a673b573591db222c1dd" },
                { "uz", "4db14c624f738d95d9d38e878eb8b49d6f9706cf600d02d4376f3bab5c6df90b20ccb5e4e45f9d40fe56b05e03f3ece9cf1d7f69061aeeea32c25297d4536b1f" },
                { "vi", "ea78e5a7dba59f7d0cbc0a59c0df6c88cc0470543b2cda04083e7d822f19d450504ac8147dd5f0b49fa910a6782d885ca8578c3022f9630d7dc5fcea0caf6381" },
                { "xh", "5a53c9666f9d2259721c566ac9885becaa3941d41e25dbe7c327522b445d8760d49003c64c2179be85f3c88efffbe38548fc31604feb9841a3bbc25f68cbd7b5" },
                { "zh-CN", "f232f5031b7c89b4e817f7bf0e66b107691e383add379729660caf33c08ae5f261d91951f2ff43c5ee59f7f916813f6477112f57a0a7fc77fc0bbe5494988128" },
                { "zh-TW", "708e4e8d6669915773ee3363bba25bb1e5a61d83cc97281d390cafb1245fd4cd54757b80794425ae3683866cc7036ff3534ba4734d3cd9a0f5013e7bd3304f9d" }
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
            const string knownVersion = "152.0.5";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
