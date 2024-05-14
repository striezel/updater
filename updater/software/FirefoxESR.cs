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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "8ac9ab92e2ad4a9de1d58fb953d03e035f8db678c3840beee541b289e7d6a82ef3e79925ad2488bb854b56e80c72996b8d72c184ebbc6d14c5c68a26172ae72f" },
                { "af", "44b1ce50e4bc585854ee46c5ddfad4b07d863b36556d93eb9d53a6e226940b9db3b79dce6e12140d596bb286855fb58f0f0dd3f59c59efc4080fb72fd065020f" },
                { "an", "243be49fdab49eac17d01aefbddcc63b09f88ead470cd66c8802a327849d7c7d46f7f1f6f1cad9bc28244301e520443d965e01ef6c41ffee59271448cc5e61bf" },
                { "ar", "aa3fa10904eeb506f4b8e41e600bea6e380bd1b82036f7ea1b9cd7d245b7031ba00a820e7fa26e9e7832d65d6d9c691fefbcc3a253baccc4ec0a731cf2f9438e" },
                { "ast", "2edb48ae453f2fadeafe26d0eede9c100dbfcfe1317717c8a20664a92a9880d8fcb1b68fb99689f8e9a0940c2a80d90d3e64c801234fee3ea1d4347aeba15045" },
                { "az", "b4c983013af1578c75b00c247198676c4e44b0703a9c0c1f73b1e1e7816be14bd0741ea0452e05cd368cb6c4868ba42f3b8c96b9370b8350bd14fc94dc517f4f" },
                { "be", "cd0e7cb33e778110a8fdce94f296bdbe4cf4d9c7f1ee93d5cc4a0647120dafb1aded218b35a8f3c976f180267a90fc67516de781812b74e79ceeb53ca72d67ef" },
                { "bg", "8500696b65ef3a23c095bbfb74290e26867bb1c1ed427495c4a313def054cd830cb4c34344b374d6d771eac20587b41b2c025372014be04cdef32901f2c08123" },
                { "bn", "f90e53f39f02ce9c5a9d1e8a39f821cbf92d0ba9fd85b0b6170641a73a303041cbcc14332f3c4c2beb4503f9c46642b33c24b6f4635ee6cfe91029d16896747e" },
                { "br", "348221f38371b34271c3b7951e556d00729976cd66d68219d86117816e83cebf731dbb8dc35bead63556202175c7939d6e439c64a9ab2e41f5cc8eb680034bc0" },
                { "bs", "f2e7e103f74af3e76ac497aa3289d25024a818250fd2af8cf071e8956a71e20bcecd156e122d4ef9b0138ce4e039c3ae33a76b44390bf113a283f6cbb30c0d92" },
                { "ca", "3ca349eff285aed1e38cc8a469449140762554ab75fd620ac95c877139fe1854a48ddcf7f949c75c42510c26d50a4cbfbe6c3b1caf6064ba9c9a0c8248520ae6" },
                { "cak", "821edc43fab5bf7f221b646733d3868858ab4157831d5996cc76a92edde012c54664ff2180120f798628046e81bc6bb23f630a94b60e1ff51541af463726ccd1" },
                { "cs", "caefd8466b2e7bae4cdffed7fd1f896f04af8388f3f4486f5a93f69f01c4ff8e124a96d34c2ba77c7639ccc71a2e0d245786c0d9e887be7b79f54e98b0a3ec0e" },
                { "cy", "9838befdc22fa099388e2a8869973747f7963b4748559fa29d5d236266be70607e59d409df537f0273c99705798cfee8cc0bc6fd4f8c1ba562610f53a1eaa612" },
                { "da", "b8adcce984913366f13cb26e033d634cc54b012c11140bfe0ce315eb424f4ddb70ea72443b8ff4e1b59914c252569645f9d1fbb60c6103640d56ccf88f3974f4" },
                { "de", "51d6d7e3dfacd4c1ad4149a502d4771c4331e58c9c18b3eb1243d3099ad23fe83ec4011f8949e4a3ce7ea571f6023e14cd2ed9a7e2041a73f4615468525c63e4" },
                { "dsb", "7fd55add64906ef27b58d90704723dc6f1040c8148c98171e9f56422245940c3c5e3f18e580333bfe8d6944b7ea23bffb176adeaf5add1d6148c9a31d4e1a4e0" },
                { "el", "f803b17b94e11ea26df5ad32c59aa84280c744b157aca92700e7681a2dd93c3e366e0c60440ec52d1dc1e864e0242d2adf7d008795d3ae28617a68cfd878036e" },
                { "en-CA", "76756c0d4646b907635503e34e9f021721320517af949faf9c0630384d7693eb47e012cf6ec4674b6f77b8b3111592b8b84814144e04d214a2124801e20ed2f8" },
                { "en-GB", "7add9cb2e3a5f440d2960c7d4deb0e5f1b852473ac0d84192bd189a464b9c559754ca2dd693fa103868dcd39adbaa755d3e3bfb323dddfacdf3a1230a9b8dda3" },
                { "en-US", "a8dee29f21b67c5f03205e50d8373da22db6cecc66547ba0e8f771416f6c198975f1172a1880fa15b0f257f6fa5f252b765781e97f8e13c0f3efde9e71131559" },
                { "eo", "fd6ead4ff974cc1caaab87402f9dc0fc8795103f043e563721f72283dbd871b7a68df9d2492f961a7ef2448167a32bdd9add096c159450d69a690e7fb3e59a9b" },
                { "es-AR", "d6b3005e0fa15342a1cebedc4874f4f0c86b9af833c53dc17e5aec39939ac6c68c8596974c938085ce79807ce6d8e844c661c5b7eeffb3a8846649f873391e62" },
                { "es-CL", "11d5cb452d40f546c23b8daa10e83413b08f4572a21425d717453646c00412219b71ea4a8c9f0ae94323d5fe23e0cbf3c7e2e72993e9111b26f765bf042b5405" },
                { "es-ES", "41a0aca9a0815503756ed8a83545ed2b6e520a2ac9f61e0370ef54c4e15758ad6b50a239952451a3af32dc5d7358f1523a5885403d69fc1a664e460a925d8840" },
                { "es-MX", "cdf2bda6e54cc8690e87f83c14f6b647c74e708cbb8a0a1620cd4b13413f105107081dad04790cd6397c785205677b81c7721a8a2c4d8e674df78228e4e1ec08" },
                { "et", "5f7203be36f0cb5376e1be4f30ccd6febe3bf53d7c29e8a07d4b037637d35ce1454176f16ca9a210bd4b89032e5a167cf330ae0fbe8261e4b0f0d5e8c2cb3631" },
                { "eu", "595f117929261f0663050d063cc7f937f48a643e7c1f13f64ad386aaa8e7643526cdf282298e0c147358691b8a741e6cdacaceaa2a7ee8a11f63ca936d3cfdd5" },
                { "fa", "8bda55596feae6a168ad6daa180512a498a0d2d0167f350ce0ef05ea1301940dc26967ce5a9d0f647c93ae4a12dc6efa2e32364528c286754f6e1e16d559104e" },
                { "ff", "5b97b6859fedfea3e4f3c6e2065c79069fead366e88a991b4804811d28e9bf02d1e94637855939ca689f389b7ed37c2d05d24bf847357d0fe4f7b66d7f3ba748" },
                { "fi", "8d57907934c6f16ee50a4f6328af460f42060421085467573464c66536631ac5cf3b113fa2fb3a5c98455b7b7b013d909229ecc75ff827bd8b66844489504387" },
                { "fr", "7d4f017cccac710d1de82e024e1d9e3c425ee9a8ab5ad9f81904c60dfef5f925a43fd86312a2a5e1dfddbaba1d5301083f467cfa8a2a99906cd883ea7bccd61b" },
                { "fur", "00618aa09e6a63c620d59617ef30977d921b7e8e864a53e4bc3f4efb8d49a713e63474935e638fab373d8a788336c3daf685d451e3aa92dbabeddc6fc5f33c33" },
                { "fy-NL", "29d011c16ec47032ab7def2435896b70a07c1d091ffbfd26f61aa5b07c14249b2fb962698d065762b4330ef2ffd7939f178a011a1a53b87ec09dde4afe530cd2" },
                { "ga-IE", "10b9f6897dbf1dd8093f73cbe59ba02ee6e55f85103f32f2812e1d1f1517d8cd299b6fdbf0df4ad6becbc2adf0af6b34767c08fb0b383ea2f7fe9daa794dd9a8" },
                { "gd", "a3265d18fdc59e1fbfc798cd56f069c3d81235f5be84b98a8f5fdc0e018425cf2c1f9126938226c8c257f59c720e49064999eb52dc5f8abc87a37403a7a0a6d2" },
                { "gl", "068955a17437684d148812fb790eb0057e1a4deb8506669e1a8f5a5e3504604f8e2583bb1fb822e6b4db6cb1ff9aedb43a1e069ad8eac9d53a163156d9e635a7" },
                { "gn", "d93d36c79854a5d3066879ee1bd950c5e9ff55e86774e78a5ec025d5d7819783c5aae7d00171f464ab3be3ab5ca9d8e0d4a08757a85eb92501ec73de749cb5b6" },
                { "gu-IN", "1b0eb2c7c71b83c884c089d67fec0fb264438a7e0074d7c0d5b0816a6985310a634ac347c754f3a695967d0a1d9b70760639d1cedbf9dc2b36dc5ab034b11ecb" },
                { "he", "1611ae6a47f4fa54ac1fe6d803fd4e4bf7b5cde557c7bc472737af533a55e43b51e6f9074ed9de6b92b904caed9f836adcf2cfb959953728b05ac095bfbebe4d" },
                { "hi-IN", "9b6b1ca1dbc4508cf0976d80c3e7710cda7c0422b2b67d1f3b3f264115d25fb3dacd670857bf23f7497f6a3f446e03abc1e2f2df593dcf68676a42e326018f3f" },
                { "hr", "afe0cd0c9f7702254ee234a4ff167c8bb9753046613432d6aded43a01230a97d26fef64844a8ba68038aedd9cdfb48f973c037be1ff4e7235e1fb1c6e3908fb7" },
                { "hsb", "16e25caa4df81bb7f4217f130e210b2043d86b08264a27873d6de323526650888af467777f8f9bea13e7715da18622332fdd52f68a35f40d86b9ae8a37fc9e9f" },
                { "hu", "369e77abb4cc3dca40db162946a7aee3558935ac4d3ba7ec6ed8cda5c04b3116b667aae50c0d43dda944ee6acf732c55d8502af3831dbafad5d4f8635dd41637" },
                { "hy-AM", "f1aadf26888a1c30af1d102ca15686d43316d80623526a11903534dd7bcdf3ce6acca6a14168e09306697184af33417861bb359fdb7e00f9a21750f6d1e166f5" },
                { "ia", "56247c56d0acf31c103d19685425b17ec2deea5a06da966f98c1f1eda793216af53d21509c98648ba5361408e36d369c79d4dbf9e11e64b4ed559c013b37cf46" },
                { "id", "bff4ab469d70b9038257136214d6fee8c9a600f0ac0dac5161323cb079dba662f4cff708914b12d2e0f157918b2807af53c737d6dfb95fe461b99cecfd1db6b0" },
                { "is", "87822987e544e8e81dfcbb2a54326ab6bfe738c5cc35051e8990bd489a6303ef852379d5ee3d9fe29a5c3bf2ce2fece22f2aedb6ce46203ee8f19351aeb22be5" },
                { "it", "0c3ecf2c5a19f09295c9708c288572365710214e477fbaea560fca29d9ec65646fe5cb278bd7dffe8f175c4565a26cdc08fdc36706c8d00478cafceaedd50f7c" },
                { "ja", "edc28507edff6db8be2a35d43ebdc9f13b5f5bcb5db96e2570c3e6c80a243436328bab21eddb16529912463b0170a9b4087435785b3f47aad349ccd5e7dcbb35" },
                { "ka", "46fcdd3bd51c27fdb6dfc6779967d68982b07807b8bf234a37740353d957745f5391301d784cda01273ae77a5dd968f6ffa48607f62073e9e77123626b07d09a" },
                { "kab", "a7fca7dc1ab38b490d9a01bf310237dc34ef5faf34f132f72db6a7cbc8df1764bbcef1fdfaf7bbe15293577cfcfedf54754096735c07302f2b5c7c030690c8e5" },
                { "kk", "71bd02c746ccc73e22b0ad39e7852a7efad216c1d019997fab181d21713a4c8b0cd19909df93cf41a2db32d5f77bb31a627e4a6834e07e7e2572f9559472a550" },
                { "km", "58f63a59047f1d7522d58ef0988ecc9b8cf5e37f3ed0387f785d09382e08e676e7808651639b6d54bd1bc2322daa0dccb95dea7f04f8c6881bb8c84bf5c69288" },
                { "kn", "e1cd5d343932cd2ddfefee6a876191afe03a5a1c848a1fe091d1463bc1802267697219f97fe667ec78e096fe8779a71c94c7cb34b1a965589e283cc623780a39" },
                { "ko", "ccaca5c1c308b93e1123ae5878add8664440d1e1425b7445671d1d153cb7546b6a911f622c9d22d63a5161bad82dfbd9fbbf0e96e602c5792f4571f5be675ac7" },
                { "lij", "5bc578e6dbe6e895a5da21f124fe489cb66327153ae3fa69a4afe70b05a770b97295334101a3b44586bf88097e3f3a167880f3e185587d4784585661534b32a3" },
                { "lt", "d538a50a78118d4f7529cf302d895931d34875bec74a8e84e996051740e6e99f35b832603247384b92420275e3704e49825dc6915c24a8e1aa213d4eb5db50a3" },
                { "lv", "f4ad16d76327f03fc7ff69c5e79a6d395ae049a4622cf4b0e1f12c92f697baac57288eb93d7ba1edf0417ebf5b0de027c97e336dafbc7bd94552e68f8d393376" },
                { "mk", "6f95c92e985aab22243e512f2e9649bd36fe035b1d0692eb532feff86278c4d6a4f870676e7f6c55100d3024e57c856af2ba14bdc205ba50e7710b9b0ef7160e" },
                { "mr", "2ce5045f0f38714a386561ba38c9077ba92fbcf539455a7d548b6ee2ae3e9d2940b797814a2e4d8dcb2f7ce390a2d3a4b6744fa4534e8d0bfb739e90d4d32888" },
                { "ms", "772cfbbd9e566a2f14b49e5841528e1a9e891bc08d152b0473dbb98f7a99c6f5962e5a6a4fc5c95092080cfcd7f9693bce9b7423fa58dcd746ba4c77d64c1223" },
                { "my", "c33ee9ab395af36e5417fe7409ed03d228df4e83f0bf4e650b422fbaa1cb9126eb14836a7692a8daa166e96d518d021fbf1d783159bb14435104b491525ad0ae" },
                { "nb-NO", "2437caaa98ba4f9c4826303fe93d77add700c6eab0b7a0696e2d2989eb8723983cc53bf6781d7cb64f886efc3c4a0646a896d48afaffc463fb80df618efd2e84" },
                { "ne-NP", "28820d08b5b1221d357ca53f5b08db64a8c184f971466025caf5e4c49168d071b9819cb051950ee8fc427255dde132b684cb06d02dc29cb18166e79d9c321ce2" },
                { "nl", "3586d411ca11b99dfb314f18b010106b928d78d46fb16b5158b13357b3ee4ea87b0b9acb64c043febbd9f90295e31933a98eb1cef9b6dcd677821f1d9f4df820" },
                { "nn-NO", "f8f496750293be3321c992d10168b2bb13f5457b149371e7394d3fa3490f2c698bd5756d885cab405447fd4ec06223dbdaf88474e89d125d9dea03203d553e5f" },
                { "oc", "5c7f21d4d18dcb66a4e8dd9a4afce8874ec9388b54c1060a4cebd81ff3a3a3bdc8424cc93808fe40943271ad0835e6b4ddbdead836b7e57335c7df9d0769bd2a" },
                { "pa-IN", "4a958588fe29956247158fda097b3c0cfa2a0adf22f81302113b919a46f27dc6809233a9fb88449ac08210f42d1bf1a1f4c5cc0de289ebb1eb4cff7a1db5dfe9" },
                { "pl", "6ec580255bd51f640a23b5696995a19202014092a3881a618f5cfb7880b41491a12d93a38e39bb305843f1c49f65400a785178568cfa7a4b85dfa01c87730ef6" },
                { "pt-BR", "f4a38d8ca67218388123b9ab1496cfab061ffb2f7691666e151a83a630b85528dfa92dd6225bb4e2816ec3afa5700742b424ae943f63713a94d1f25ea50b422f" },
                { "pt-PT", "44c59983ec9fce5da455b965c2decb4719d5a0da2c35ddf5983cca71a3f1d9942fd299eeeccf0343e9afc2168792deebe352bd3fea513aec5bf9162d828359fe" },
                { "rm", "65ec9994609b19eaa3909e96f106239e710177f27761542440e6edb8d6a062a2f3adb673f1b1ced393c4263a84ea57269447e80dfa0774e53dfcae95b6054e43" },
                { "ro", "76aadc780a32c72715950fb3f818c8be8fe5bca37320a97172bf7b325d38cb66c21879fd70e7acb69fb08054ef3bd4d0a5ecf4d0a7ec02ed67c34c299487c6ae" },
                { "ru", "1d608cff3a6ad8ac378121fbe3ccdccd28403a083f2e8e81faaa3443a9907362a07de3cb6b43897aa03615a4109a99aa5f2dc50b599f8a1b95ca7083311c38ed" },
                { "sc", "87424092c56cf81311e258c129574e74d1f519f76874912644e10021fe143318d10c9a05ec33e22b45702ea8360fd616e9a5a96e52be3762116272cedceb921d" },
                { "sco", "8034a6a7f3260e1b025c42d3cb12f205fe602681219d11ba94141c79b7cc14e816a9b8172e7728c5fd56db24109f22697d6deb22f552de4b4218243afefd4369" },
                { "si", "0339f27e1a777583195462f30b32505a0f0ad27627b323becafcad28bc5eb7336058bfa847b481ca884acb0bbd167bb71d6c85a80e5c628ec3261d7ff692c006" },
                { "sk", "05a3f3e056ad43abfe2c823e96dbf0bce152ffbabe5a04e21121ee43498834d88a068b5dd7d3a5a52db65703a1d669b7bfddbfef45a1c72f2f34a5ccc83b0d9d" },
                { "sl", "2d9467c4bd1995c3d65b824929e6f3876adfaa42803b46e41317fed8df35d50066fb3fecaf8b67d799c8e2f421b53f88b21901434d062ef6daaf43cbcae454ce" },
                { "son", "276fc9ac60da2896b79e502fc90fe3e2fefaed5fd8ccd218a4f45cc60d5c4be72e0498ab878e3f0c0dae6555670b4be2439f80d6a7e6022e8fa8852764932278" },
                { "sq", "82b22c5783315c1b50ef70eb1522ecb186ce2a95a8cd28b6e44e6560f33baa22cc1edd896d15841474d08428621192b5f080be25644214f823de073cb3c39c5a" },
                { "sr", "637741725ebba61ce882595bae73f01af490afdd2e5a60a0b65ed715ea2f9c4b229e11ecebc51d10a4ec860fd413d974641c03cc94defddcb5cbf8ff5f146947" },
                { "sv-SE", "1030d96d55d500949235a1ee664097f52caf1a59b292e85e6785337583d7b7133c2884eadc158981935b70d97d9c514120b30c37c71557529dc5c3859b7699ec" },
                { "szl", "7c0b1a8c26f00c9a712386420e98cfd40352c503141878c21efd3e2637993eba8fda5d0156d99a9946e9ac74693da49dd89aba8525dadb52fc3eaccf797bae93" },
                { "ta", "b40a8d33de4f6d12a2ce66863d415146625ad954d9a530a8de3fd66699c5dd28f936fc04aa70e8bc482daa8a158c0f7d7fa7411a64f4379a07c7bc7e454d6a8e" },
                { "te", "54b007e3c669377894add9f0e5705f04bb766e12a9a866c70468eb3397fdaaea675d256c8e9178d090cd8d51f96c2b0e581643c7299c64d029f80e540058f335" },
                { "tg", "503ecf951c3ce991c6b25e5297a1e593aaf543a90b13fbc673660b0cfdfedcaed6e14efc414ebd4da230483bc4f48af74c6b1d2b3157b9240786a196d5579f24" },
                { "th", "0335be8c00b6b9f482430e5d20905922a109a430a247129094d1b93275d7b868248ca944cf5dfd2fdb082206397ca054fbc95745af31f27c677c3f6899eee624" },
                { "tl", "f3b8b42b08e137a27624e496d5ef3b860ee32159d3ad369c8ea86342f41b9ab9a0a4abc79ed1cf392741f7979314dd5e977d1f5ab3167cfb2ee1ec530a285ca7" },
                { "tr", "fb254d44437e9dfcef02918226da4d72f516af9f4f050ac67f585b443863320642d61cc25c542dac1a4783c66a8485900bbf6e5622587cbbd2a35e1acc7c821c" },
                { "trs", "e8618f9731b290e75f76b080a202e81a14207813c536718b2c362d9a9b7bc305bb3296eeb9f4b0b3b5fb1fb9d0c3459849ea3ad84842c00f46b8872924b4d591" },
                { "uk", "211b9a1621610bfb871155f77daf498760c9259c38e0a12bff5ccd9f0c5ae1eab0aa04c1e7dce7ee928b9b987b529f713d492259b70a56bdae42834b35d7ddeb" },
                { "ur", "6d6b1fcbba946c86ed760a6f2b7e5398475c68538a261a99a243f9780084f5cfdbe87105adbe091710fcdbcdf204292f3ade76f38e43dd2fc5c7c77a97f2bee3" },
                { "uz", "e2bb60c923a43f3937c7fe3ffc00af0e79ce71b32f4e5665e33125a4b781af65bd7bc6babe5778add35b5059022a10e001b33086d738d829b75b44cbff01ac8c" },
                { "vi", "7533af040e14c9bb7c35d45a053c196ccc64e3bb68a37a34a5c6a597956c9fe199c9a48a377ff4da97b4a3b5e906098d85dcb355f3933c4a1c0eaaeadbfda223" },
                { "xh", "d5f6f3c55b2f5ede14073a5ed92ab867fd53fc991df20479879d8af1ff690140d6004c87a8aa22aecadaaa8367136e50d1e6eb0a93924f943e613ae491d63075" },
                { "zh-CN", "7605974ec136a1c45fd23aa91a489ac75008ced52c318bc0ec470f09567192fc851731fe8d456f0deb8f033bb153aec04a64ca8e3e3b24a648391e6aeda3713f" },
                { "zh-TW", "f5551ce7db7d46bf36714fb7843d06274b34c2457bc9ef43f6d7e7905812f016aa91bef6dd21d22efba8cc0f5eaf03b0ba7a1b657c6dc9ba57d3087f02aefb84" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "025829ce7075de8705c9efb733602745fc713755906b2940a1209594b3dbf4a763f29f6ce527da4367751edce908bf1fc894a62d9e41ffee87f3ed51b20abf7a" },
                { "af", "6d898f70afa5347ae80e220536cad66436c8efdfee9cafecc75510bf037bc0ea93a1b9e703529f655cf7257209d10c35ec605ba1ef22cedac01952b995f4dd08" },
                { "an", "fd01ceb2dcd654147e63c79ca64abc9196e9fc1f19449b9fe8372d721e1c852be4f1bdfd68939e34023653073219079b87f1d776a93a284cf624e2c37f955cd5" },
                { "ar", "eea3c58f68d21c84271df33d64db991482cb09b280de035de9ec5b0263684275725415a9f05b17f129b661a2c566cbacb0e701b954f0c11c2bb4f7e71a0e69e7" },
                { "ast", "739105fdeb705c600201f35b99e57382de41def5b58a2fc7373e46776e12d6423aca8f24806612b54e6f9b22062db9d18d4e7e110e67cacc32f276e6bc35547b" },
                { "az", "69d1d7a9761a228d625270b2e269c02f6d8259f5004e495a83368e9db5704910e1c98f46808bf86711049e5ea6787961759124bb9d90c56a7f686ea3b10f30a3" },
                { "be", "e403296ba7aa9bbf1d762c8be007ae764d6224a943b6cf7aba0e206b24a7e8277df4e8c579d520415f7b1fea391cb3ab3bda4b68f33a7c38185a00791235eb75" },
                { "bg", "2243694e7e68bac0933c021fe77a6ec2ccd4091260487a49c64cd45a3f482c35478955fd0583eb28e51b678c28a2a68c4edc6d1afeb13eafe0ee3fb79dccfed1" },
                { "bn", "01dc621766221da26cfa994b6a5102e6b187973f51e2ca77c89ed5ecde0f8fdb172e9a53c48a66722ca0e91abecd48ddd65a21d4290fcdceaddf65e72a049270" },
                { "br", "1988bf191389c86e8d5de7ab798429a8157bcdddc8bdc29e0484a5ea900eb416c41408c3fd1ce48dbd37f78bb12fe729b2737f3fefc4ad2f3ea1215d45094e1f" },
                { "bs", "085200ea6f1926560ba7ff1cf8dd1776e6a936d3442582a6a05888b56db8472ee4183bf4f6f630ab6daecf56f3b538e4f41e6d01420dfb2df59eddaf7a0a950e" },
                { "ca", "9a2557acbee368b72372a4bcedc0d17225f98a6482b70b5e44e0cfba96f38e69355ef15f7cccf8c20a6d3f409888576d00f551993f63c91222243d306e5260f6" },
                { "cak", "ce3e63540550150a101e2fa6f9f45499708bf968c88884b69eb8cd8307f464bc27f06a1f286621ab30933930b99d3fe2dff5a3cad82c0547e865cd7777f1cb34" },
                { "cs", "0bfc9f3fbcd8949124373d4c5cf6478739044c19f6086a7fe4a4aca29dde3a104db41a875ff24644dec171470dadc4ff13b00c0d3258df9bee600f19ce69962d" },
                { "cy", "97bd6af465a26cf63e0ebc3848eefbc80a57ebaa928699fceafcb69aca6f5a2d1773d5c1f467911246863f61378b4f53bca8f3e53d731544b7ff8b40d96f9641" },
                { "da", "442db78900818c5a87e8cd9d25ff75876205c0903c20f63045369dff46465a0ce0db74b8fb2291e673b96bcc8332981221f1b95e836d532059ba7240e9f2c1f4" },
                { "de", "3039548440af2dc6a6faae9486d14c6afa607cc596a383305bc90eba2c9fc4ddfc63a5d17aee5fe21f427e00eefeaef413fb076f9ae996998edc5e52737a4ebf" },
                { "dsb", "19b153ac69fe22dfb49d26a3265b00430680662ea8ddf418fe431faff04ddad3bbf839a78afe00f64e560a38fde61ac5e7722404ec89dcd50c91f3af40509127" },
                { "el", "01cb1e9e5adc93702f05c49c64de7df65a2b4ce15243b0acbf8c7ad222223233fea825751b9a3e0963525a19d5485cf13bbec14858e51e1ac4eba7210ef6c026" },
                { "en-CA", "8543436c21735eade5b46c7fb442953ce3ce0d6b1cb829337ef14c1f8dd1cd8f047ed6211da6a65ca68da1587dfe3d7cefe22f70bd99db6ae1c42740d917fc12" },
                { "en-GB", "c414d99bb93e26dacf906dda2850cd8b9605ae200158fe7a6a0414ddf07a771b53db282cc6f4d653991264ebb6621fa83690bf43216acf7d9185dc5a1a343c2b" },
                { "en-US", "c4334903d3139ee4216bee257664e6add4673a575224f0e1b6508b7685df46d1fafe91796b3fa0322e5ffa96a90f1ce891f49289b571a4ae7f2e06f8c5cb734b" },
                { "eo", "5d9c93fa58ab743330bcb0635349b8033655712c16dcfaf6b389bbb6675304ca1739ab4a968ce039dc315659473fcb7f861d84f26d8e3884d3124a5d811c25cc" },
                { "es-AR", "501bc88aa672286634ff0cac14fe3536ae643a1c4c96ae618208e272660cfc1b174a49418c7d489025f897f2302990ddd899f4c2f3c0eb45f9699a5641142a9d" },
                { "es-CL", "66f24e309638b32312e1b083ef3f5ff165bdd4c0eccdbdeccea986888af6be2f97a18ae1ad9fe5416d9b125421b1599c18c958a7f54e0f6b32ce659f231499af" },
                { "es-ES", "26abd75ffc625a45444180a0315e34d7ab2571f1d1f4d8baf9e1ebeee52fedf7c47a2acabeb4bea2d835dde26ae7f8e4fc541ea2eeabdc1af3cd122f50e4fb56" },
                { "es-MX", "f0b709b91f5d69dd13add640118a14984e271973ca12625597d084b8ea4395acfa53de4e0fd9a93bf5f9400a20836d3bdb232ddaed6079804dfc3856123e5eb5" },
                { "et", "897cb232ee28a477ff8b1b3dcd100e4f17702dcfc3eabd8c9e44048bf632cec6f82c366e0caf3c4f3468224d31f2ad570106b6c58183c34400c107aedcf7c8f4" },
                { "eu", "df4cabe4097f349ef6cd8015414664b7c0c0d48072d71f20e8e4bd834949f9b05d29acab1513a5ccef76776ef0934b902d570f8c014afaebde0f76690501dfc8" },
                { "fa", "c5fe1f3bc64105e23419516aa127e858a36cb3f0e20006957c381ec7dde80283f24418cdba3e8055f0aaf27c1457ad388f6bdb29dd259165e44316e85bd3d463" },
                { "ff", "e90f215025ebf0ddef53d7d7972eff7c703bb295af708c2bc3609ea49aca770dff7031f3e4c8975294f4c2f805eea2b201093ce0c22c40b8e780f8475aafa9d5" },
                { "fi", "0e7eccd6059c7922b4b487ded63c92ade35096b51170adf3adf9a73c997338c6032dc00099ffc8bcae5e350e84d392aae638604fe87412a628e8b893f2ca6ffc" },
                { "fr", "aa2ce406b94bcc0e70e707475033b3b85d03d517c79f2050edc10230f41b6d71400ec3be2e960edcba3ed8bf8f910ca2d85dc3485360245a0b26345c098d5fea" },
                { "fur", "d14a0dbe67da7afca7d051b4b747d3332989b8ce7ff578034ebb52f16db83e9751b68b7a440da35300ab914d55e442c3f820b521f504445fa4f8c0b4803309bf" },
                { "fy-NL", "732881cd7803c0bcb48d97ee3caf164cf421728cb710fb2bf6a4766a22f0f3b126d2f0751168ec3ab9b098207018a580347eda90c3de4d442ca13e7784f23f06" },
                { "ga-IE", "b6eb5814ca8a3e53a86b0746792e4c5c979d70c5dcc1efe09e9171a2760f77c5e2c014c3e23771214696b3f0334ad0e31650e3b024f51c6c4b63227b056a3c99" },
                { "gd", "84fc68d1788e036ea9ba9dda36f28ee8604bc36662dea6ab1d81d491242704ed0339f27b7103bed5ddb6aa2ff145f2c9aafeddfa299ce509c08349d1f579103f" },
                { "gl", "114774a0464c120852f1c666aa960e5b76ae7dbff96c8e6e0bec0b7e6663cf6826ada349510a00e6b242d7b09942d2a9390118a86123bbd6862afc97258a302c" },
                { "gn", "587207a8f3793012c8313b611c94602e6bd18bf1bb4b23c0651bb52738d745d89b7a83ce6996d447724ae32f84a78e73cacd01589669cf14809cbe81d5c08520" },
                { "gu-IN", "7f5dfd139997d24b4898b93161785be2b67f8b0c5ded6c63f72298be909c0af1a3574261ed8ad1256a8c7c83153a0345da11e3104f9180244c81c6112adbf7ad" },
                { "he", "f186fbf8138e574b834801162f1c3ff2aaddfade04f6abb8c1578c62923a1c06040917eba600c7886dc04584247ddc14c550032ebf44238a4709974f6ab5267c" },
                { "hi-IN", "4008b9239e2ddce21759c44b2e228768a63e2ddce69f33c76950351a799fc92449e0e94d89ecfbb4b50af615d549ada02d8443f5070a12b418029a68bc31d0f8" },
                { "hr", "7eba1f8c3f68924753e0877b81869bf406365ae34e22ff0cb456c498b18e75db3801666b44939908bb67a5f7796ddce0f4ef7fe2a9e19e2cadde4b62f810ad61" },
                { "hsb", "3acd38a2f24ff1dbbc7a060af50fbff644db322dcdfce981c5eb631d21639d85743868afc405f5edec5b65f584af91a220c8cb607f42555f9d6e24bc5448e9c3" },
                { "hu", "6d810e0bad40da38b57c811d8038a1b5866bc803b6aa0b4b3a5f3305b64011968b56a0834e1441614cd7a3ce377eda866bce70e5ba60ae6d69bfa837383d3c6f" },
                { "hy-AM", "21085d010c98a0c701a479a79d6fd93fb824be1bab8f32dbfceac7da031ae315df72198ebc51d6943463abedc630c659468728b73e6c0ea6786aa64fe7666857" },
                { "ia", "3b5b30526defee3fad30d781648515e41ab99095b6b7265eb8a9a3609a4156e001ac98b0419e7ff53d2c1da089e41d0bc2ea6c73c3735a56279982a4a6d706ea" },
                { "id", "ed3c85e2a53e529c77ec318eb520ef312cf3452c55e3b5b0ae89cba8c5d0cb7b17c3b249e067539e63b34a8b2cc87e714c5959a17d14cedc09d6826edcaefb6f" },
                { "is", "582598ad5ec2bfd31d62dce7f11a1894d14e7fc1cee0e2b8df7bb80077806f39a651f455a35f84c9d4271c46d486c19a106b1000785e823a9107a1cef1e3c626" },
                { "it", "17dc211d21ce89e372dfd82ed6906588e241f6aa0f1a919383d0081bd55e292c445b68f37721a52aac7c973ebe65a3c91927f88138a0b99aef84bbc66d17cbe2" },
                { "ja", "b9c6f0cc198ac72edd062a07a399ae9f44d4338107a4b19dc1bb57465ad857234b648b33b361ad35f65411e39cc972fc28d6ee5fefd05a9fcf46099603c8bab8" },
                { "ka", "71ed32b116e80b1e65042d9bc222281f2dc3f06862ffafe2333c1daadb011e8250872bf685d74e7cbc49fa7f3c93d3939d278856aab621c7a03c9506b87294b7" },
                { "kab", "dfca2df76821ef8d591537d5c454a478dae0322d5c17132096738c072158ac2b474d85281fd63a444f6a0c4b1cd3eb63e6ba3d23bdb103a119cf0cd65269bc8f" },
                { "kk", "b7119f585b82391986db1927ba6dadf9529edd491e426646821d1c5de373767f889ebce162bf4fd65ae443e2204a8b2bc3df8485a264f88d41669a303b62e5da" },
                { "km", "feb2f24000679aa44c1d8e59566271630fbde60d88ac3cbec7dc22b6954f399af766f5433c5f13aa5eaac9a4aa42125f51ea74f8b243c73bc5e6668419c00ebd" },
                { "kn", "81713bb7752431a421ebf5d6a638daf26a0fe123b1a4136cae35fba285fad9503f29f3e0ecde7c215790783d7d392052e3f4bf670bdfa871f7a59059302dfa17" },
                { "ko", "61d5a36bef68ac793512190cfaa945d24c2fa4372373a34bee8629a3277c2e3df4ec4d15654af8a03c71e7f2e82fe7f23332a1fa27f540fac79ec8368023d188" },
                { "lij", "0ea99dfc9332cc7a90990c0012a28f3df542ff8020186919c083a0cc6cf73107f118a58a3e0d722cb8d1660441858fc8626cba78012864023142e8c7cf861675" },
                { "lt", "68cb0816beb0b2d1236c3574ce4508e3b1115af8583de9e5a5dfa8873a83db9fef20840694406f890009b71dd053688d3d3ec807877cee3167a81174f0a5dc20" },
                { "lv", "59b9d316b7a74b12185a99f2b12bdfb52c35bcf34bfa12d5d74281614d83e9bdabd7cd89bc0f0c15bd8e77445148527dbb787b048aac8b8fa9c74a4cb56e4bc2" },
                { "mk", "f50d27a18140ab7d6de4cceda4793da7d7e77ca84e6a8e797c63c0d5eb60731d42bce583c3da4ad8afd5e729ba516983fcf5e6defba4d596ee1b4055087a024a" },
                { "mr", "9005f454c45319e2184dca51f87694ede6e161ffeece2a077ad79bd2f275bdf0b038b7a2045703f9a02b41017c30f298079b70e8524fa58d5133ab8bcd56186e" },
                { "ms", "1df00d7bbe4bec397c6901177e9226426053b1451e99d1e0bf395f3300806e68cc950caefc6d7aaf91f7f9be66f0108b19e06bcde420f1f12da0ef426a08c9fc" },
                { "my", "419c5d9d9aca96664607704c12442c716fd3c2395eff12d9073981fc608a787857ffa2eaf032385f3836ac3e2913eef02319eb561992bb469b3bbb37ae000cc2" },
                { "nb-NO", "9e3333d2f25e5d0f49393ba11ad15ce1cddb151a52d6c148b17e2c0d43f95ff0beeb15458b5911fae0e0fc2bfc93f2247fc8d0f4a3a3d62d68ca3fcd8e75e217" },
                { "ne-NP", "1b1551bd738358f9d9bb61bacd536529b152e7d29e06f7def8f9724601e9b0ca57becf1d8dc6bba714ca63d75cc38186cedfdd12cd2867e6d3adc0d083a5a2c3" },
                { "nl", "be8dc7fa511d1589fe93ba8731102a99566b8b18597cb1d75e2b8f5fed587e8a1c55f34d893d293127ab5fdf32d3de68def4ec47263dd81b3850b2f6fada4a1f" },
                { "nn-NO", "6c396a8a12b7be30d882c860fda5ec639111a31fb6b60be8679f2653d0c591a60ea6409842fd7153a4efab8d1478a7826f036af9b97199326177700cf0c3692b" },
                { "oc", "bbdaf6e070cc50c4a2a5609384d9a447e54708c00bc59f2079f3cca67ad11a29632699c3f36d3ad26199b4e0c02fd758667748a3f8878cd1312d2288021dd5e2" },
                { "pa-IN", "9d1c96c2f5a7c0dddacaa4dec03227b5e758b95ff53d274ba25e24a3ade82fc19cf0272a0a90f83f663154a76ec5c340a5c174d649c675012fee8e9d67bd9461" },
                { "pl", "560fb684cf21895e6cb02a2e2bcd81a4a729d007350a67617611bcd199f666644370db3e71710958bad3ecbc7ed0e2b8cfa5c3f73a53d53f47f23fb0b0b38181" },
                { "pt-BR", "f1396752f2567e90c9bbc64fbf5f368bbe47fade72f3606e6651c2d49ed400d03d7592cc43a6927e8d87991e69ef456849a1af1e546660d070666d356d775f57" },
                { "pt-PT", "f4b7547a4b7a030e7b853473acd4cf2b06f1ef14085b9d4e8914a2070a7bef28567c68013ca490a3bed9c426454d70ed2b22f21cdfaedcdd397028c1527ccf09" },
                { "rm", "402815eb731465d41ce0477fd25c264c3a532f424648f231817eb2b5e343323a9e327cf7310db878270aa111f5c577a463910580f932a90ac689e1f9bf2bef37" },
                { "ro", "08517a2b7227a1211387dfc1ed9d045c7d82ece41cbed98675d426b9711b5916c4272520ee107eb668e41db5ca36ebb2bbe7ef5e170f3f9a478027bce06e1a9f" },
                { "ru", "086861343e8371e3a826586400438b31ef7ef7bab9df8ab556a35f4ffae0a8763b5eb2e8f28dbdc007b664c482067a9c202c22d3485ae23b7f9389f706cab16c" },
                { "sc", "06ce4cbd956dea554bc81a67d3a2e722293098aaa3e380b285ab5f7a3fa58da0765821d4558c9e555f7bf7ab0f7cab6f3c9308271167eab01bd17403c6872801" },
                { "sco", "45e1d7a90adef74d303e5f4e031416d7f8a2a6a634d99520c8b7d0cb6f59d7d27d9210137a02e50d0e40813a9011abc0131c0e014eb79e424fd1f4e7ded0fb1b" },
                { "si", "cb69770a06d55bc2d80d2a1b0bd097aeb708615cab7357382390985093c1dcb73321e7ec9f00d248952986a91347af992fd4a8189767160f2f29f2d76cbef605" },
                { "sk", "566edc89550c1cc52db06f4b351d397066fcedde94d8ea79d3838e0b856259c795aee07400368268d5128cf4b7f1e2358a56db4319f2fea711e676018a51d659" },
                { "sl", "9429e9522221739ca5271a80f894d4601485875ac00149efc158e302c65ba8403239d32628a08455f24f7d438da9a70c3076d7e01d3e89e25d627c13c8e631a1" },
                { "son", "3bdd91298f6defbf13413d5c21ac9ee761f9b1a924b78e0d430b636ccc4901c7326eb1b5180bba8610c68b652b6a2cb0785c56b1c5fb40e1dedd943306b5d20e" },
                { "sq", "24912c138d4ef2daed828dbb42189f3b79159e53547e9fcc133be3ab74eb0515503ef540fc03d393f02cb0b25f132d7bb48b5a9557aa04b72f5c5d39410978df" },
                { "sr", "ab190fe1da2ec410e1a6042fb727a341e3a4deda0688864de0ff6ccf0ccab856097e84effd9722fcdf16cb9b4bd67cda07814a4cb145d23c3d53ce63671af90c" },
                { "sv-SE", "5a691b38ed0bd226b0bda1d000ddf982c9b0233631b93fc219f497f3b42c9fd1fd26848ed21a6ecc8457280d1d89324cd4c554855986daafbb6aef5aeaa32b2e" },
                { "szl", "93a545219cc59a4fe554100d0fbb5a90831eb8c33d4204e498373a20b1f6dc53db14716f0d7a453db2301b732c6c0548f599639b123ee0a036f3042561de3515" },
                { "ta", "8b03bd6f79ee73bd9ccb64d3d26bd471159fa0cfd63ec8eb804f748763f0c47b26fe4e077fae1aae9da6a50334a2177f54559161367f113a3635fb401567bf81" },
                { "te", "faae53e0cee49a2eb4492bd5010a37cf879d1ec5092c9879ad60104a505e36a4bd26b3afbe800695039033ae39e92c13b586a5657d9f46bd134591e7779e4790" },
                { "tg", "cc93ee3595e338fc19ce908594d3b8c11be9b6b462130b5adad4139abef53275a8749dbce1ddc935c6058e6fb22ac95677f9b10fc2fefb7da4d6545f1513cf2b" },
                { "th", "7935751d41511d909ac8a907847f8419be5caebcecf17027ac3c45d18fc33fda0d6f6d7773d31da7ef1a1e1b4e396732690e91602dca87e051f58b492e7f9cd1" },
                { "tl", "d4eea3676b2b77ca22ad75b3df2a75e680e7cc1ba65be694fcb56ea680204e485c7459cd7fe73b2d05342cf68ae679d2f4ee1654a6a0dffee244e9a0d879f35f" },
                { "tr", "b08a92b28a92672389a90eae6857dca1ac3471fb68ca2dae9e5360f76f48a8a0de8f1335c714017f2284aea7c3ffc3040b21f037544ef0a9de8f81ba21178992" },
                { "trs", "85ac855f5db168f261c845b3f1e6a34fa5694bc6b7a0c47d7cf0e196d27193a5c3c9f2f6ce7897051bc67827dab6858b17414510b18360c1c35d036e632e4d77" },
                { "uk", "dbdca3569736af2b70e837840e9784a2bddce80eb77c198128d7894937599b34736a3b0e3ac7cb2b67b11ba3249b76021dffe0f27dad0b61d8313e2d8e051061" },
                { "ur", "8ecbe584a57614948a0cd3a681699069577650b6015494169109fede72dc101ad3d458def9804f4efafbbadb2e5adedce3bfead3865d2f0801384e7986299dfe" },
                { "uz", "0f4087fc796924c2fff9c31716cb631b217a6b82caf2fc85d10c59176d142f8600b75b34a0a8d187d662bd4644481f25269bafe58a3ae37a63f3b22af7681a89" },
                { "vi", "669ce2906667b8ee793d269721ff1b35ce940f990e47df1ecf6191ac5d93b14a7bf01114f59807a510b809c6ed0cc92c02d42019debc29f42e2455592e189c4a" },
                { "xh", "cfcc27f0c2f65f59a40d14e40622eda5ad25ed600bcf3cc9b1099e99b4b92897013130f29c28d1fb0a7c74fbe6f2cce3d2f4d982bb15f4a8a5c8c773d5430067" },
                { "zh-CN", "e197cccf31b32c71fb28f1e029c0f7fc2e65a2f28aa83ccbf22c9dcd2f02aba832de9633e88b8f62c4af627130b4649dd9825053d41b766a991e627c25bd7f96" },
                { "zh-TW", "fd34b3540d0951a461e9002f164c9ed2e1edb6ccd9b543e59e98bcd6633aba640f9cbbbbac5abfd735c078807a78c15eefa77b9f43433555848e3f5e00b5f277" }
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
            const string knownVersion = "115.11.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
