/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "110.0b8";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/110.0b8/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "72260dcb94fd9df7106417f486ea1b9740dfa0b7f9789f062405f645f5c7cdf967c7b45cdc5dd986c626c113e1f0c9af0a84a79edd0faf20f3091b363a4866f9" },
                { "af", "c302ffaf8a426ecec92a903e3d52ad9e6842e727e2ef9fdc9fc650f7846af04900e929be9e0b1a7d8c997522669b587254a20e9dfcc9af33a4d68ffcb5370507" },
                { "an", "90a3e1ceae17b1b554c706afe5ac4480c0f7461c65aa42255f0f72738e1d7f0014bb9bde43799e3e5b01ed9c229fd78fbdbb902ddd186c940e89365f05af407e" },
                { "ar", "f68745f3c07a1854b4e7d77b06c5702401798cae85f21b7723b82c4ff5590646996fed3bc9d106f349b40399dca48869466be1bd85f01e847647c547c72607cb" },
                { "ast", "786dcd351ac11c0667c0a6a6aba6a363a842d6fc210fd0adee9e59448cebe240a4bebd310fa569ba1f20e268944057ec97edfffe719d96c7bb63feeb8f7d496e" },
                { "az", "f599c88efb9f2029b47c4b8293f5f880a34ed6837211f630684f25a0f2512dd049296045bbb6caf73b684ece49d1ebcd0cb588b1918e4cb55d254c6b59f0fa22" },
                { "be", "5fc8159953ddf546ee55a96797fd02ccb0a42a1b79ddf7e5cb51f52e003f005ab6c589efc94bc27501859e81b8602e3bd625343b247ba34af0a69e385356fd20" },
                { "bg", "99d139ee0daa9e215b096b63be0a510a1d99bdfbd12fe90454c3caa361282e15f68c564068de7537c6648fed51914fb4d9c65d01905ea695b887a432e9c5646b" },
                { "bn", "066021fbc270161aca144d26215aa13ce67aee32430b4cf3001a3bd2bb5590c153936a80e78663961addcfdb418601e1718b1637fcc27599c8c51214982c1ba3" },
                { "br", "d27f179791dbef6867e4c02e559f4442bf831065144651146eb380934fba1e999a678fa06a16e97e9cbe03c59fbcbab9e797d687989ec4dbeea24cd209ca3318" },
                { "bs", "89c1c68dc45ff8aefd1b1443daf084205bb9367f9f1e20889cbbd79b2a6f43d883329254ce1426a7b260b9c73de8f92f243c85176b67e1acc2d7fb8e44b18134" },
                { "ca", "562c18c8a3246f863f322271dfe9afb822e0beec03496ff218b63dde2af91d13ca210b7387770e6cd633a65a9fe5786df7dda44eb0be1d824bec6a61de462355" },
                { "cak", "1f0ed8bb8e965bfbfbc9261b9a05f58d698391f5e33061b4c1d8478a0a2c2e7b0fa3b3ba691c78a1e93ab9857d5b63a28efbdfc54d08a0a1f7c485c7e6981e24" },
                { "cs", "aa74735f0cfdc910e5bdb4602a7138a9f68706a36c6179bed96cb38e331a83d6cc622c7427cb61f623dad3f083266bda05e7b2c9770d5ff0c5a8021919a6a68e" },
                { "cy", "e84120080fa299040bc9b331740f7c3fe727e7b69f2d95c221456500769bb2de532504062657423bc89198109b661d522854dbd0feca6c186bf00a3662c92232" },
                { "da", "7f03bb2615efe6865e034b3aa2deeab801429e25dd958874f3094047d7fd62f69a5bda7d92f2397025764a92264febc13ae9c69f3ecb3592ff7147393ddb115f" },
                { "de", "3d3f660d40da9abb51b50eba0de12b149857cd8d9e092b2bcd7a60fbcf348e0ff9e8701cb055a8c979ff2d7f1cf9dd0e80f976b873f7be7e6e749e53fc875ba6" },
                { "dsb", "5de534728d6e6adf76e56412e9b275dc88ba9ffce9eab40efa5d6e52b6336cad14d53e9cf0d63cdddc8d5996e1f3a5377bb2f498c283aae103d0df9d9fed3251" },
                { "el", "f4e369476d6af2e511b888a849dbda1e3d7b910db12cce8c196ce3c79d134d68db876c34b310d1eb2c16f82b4d4edd5b417e558e8d05a6f64596f6f7fddd6581" },
                { "en-CA", "912a21ad43a82c09ca8b112dc9aa6dfdb81c3fc4d8fced828161a4eaa23133d253213aaa0211b74a68d319d9637bb59a4e2d0d26531009c9b870141783fc8d04" },
                { "en-GB", "d066af3f9bd0f785495c37c75bd481a579fffc484df40010de17e45f0eec31c0e5eaad9072d26c39f11a669e8437c599c15a61aadb4bdbe0e1696d20e22fd7b4" },
                { "en-US", "ce0439c3f010dc8d62501158e23be23627e019675c9ec8c9cedeec197c35f13163c094527edba907a03f6f25f43a12ffc759c4aba5024e8a9406eec26b3cb6f9" },
                { "eo", "260ff2508b6b5bb69d73781956e826197761c76110e0ac6eb1933b037556aa41d90c37936990130034fe18377a65cff4ecf8c19dd42f57c8c5ce6983e8c58805" },
                { "es-AR", "422d5f11b77e1cba6ae7ffa99896fbb6314ce53d875d982238794dde8f86c25118c190089fe33b242c24cf8a1aa72e39bb8f3c77200dabd23d8211761e5b82a3" },
                { "es-CL", "cbbeeed1397ee21559fcab0aec9b81895040c7d51c481a9cc8917e9e999c0da44e99c0367c3fe7d78faf17a3b56561f704989aa7b87b2594ace11334d54f6c79" },
                { "es-ES", "30e40a08960d39443384092bd3c8d160af9842e8a7df14e4f765eef0922069b8c22760fc5a3304c2692df203f8b6fbdce47015e210ef4cd94c86775b29de2524" },
                { "es-MX", "f1402fcf6953f258835f59e1dd1e85e04e1cd0c314f4ca2d145ab1c97747311cd56ee8c79035a4ff26679e34dcbd70e7fd9046eb53d8cf0e7acc2c8c89985b76" },
                { "et", "869eeec84b46f488df07765919967d19397a2db2078e0394fd9ccab0f532f123fa9dabf9c7da8a4b60818a564b8b9cb097b1a16a3af4f71381c30c1a21e01292" },
                { "eu", "329cbf625565427aac50a39d2d5e19c9a3f7852bf9d34befff9727279f4a51680ae7cee89d38ad4f8bee37db3530f70cdc6c79181e9298afd8257c78e9787bd0" },
                { "fa", "5c5913785f8197a12e669f613fb7b7eb35f52f65714a882816cf3aeebad3fa68bae9b9e549964e41ebf1d7425b917f1796ed2c35943dc591dfca927b9ce95f12" },
                { "ff", "786d51229ff83be5d0140a366404a76b7a319540fbb89a1de688af82dd570f191b1580815aff728b6b66955055df4db9dcc8e4257a10b14888d379e3a287c736" },
                { "fi", "7401a68adb260b185ea9222450d96184b411502a6bff6d73f50ccbb1ab346b6f61bac03eb0d3d651f96a1d690a428693a76da1be562171672efbc472bf71cec1" },
                { "fr", "8b4f0e3289d34c59eaaaff86478bdc80ba4c69d44401310c01a26faa8e59cc6b5060c5ea625804ab30b5fb9ca5a8a319f0bcbc5cdad9007036814a7d6545cddd" },
                { "fy-NL", "7c6ae21bf7ab6dab43529e7bb3f5043300f3318fcd2fb18b608e8dba56668a3449f95801d13edd823052f9a1aed2fb8e3234c86bf08466f380f7e40a972adf28" },
                { "ga-IE", "b1a9a8da6a39e9b51f310529257f0b49e4f444679e10b1da958fca6bf039a51856ce064eb5839bd6a189f38f868d1ec23edd1d506a86e3858f7b1558aea5b11e" },
                { "gd", "322e70b107fdc475901c80a28c460d6916716daa80c81593c976142d301c8543228126c22ce1c554b09f0000c44b3f179732043408ac98d406b370673ef3e992" },
                { "gl", "312d1362ac53e08af078621b46faf555fa4f30a55dde41c512d2738933c1b92273bb6c0dc8301c174abbe68bcada2cffcf656a0c40694964970073c0a5fe78bf" },
                { "gn", "d671fbe5f0fd45c2ad2ccfad02f3e8d30f6e53e33324008ab36651580ab543d6001221cc8b77dd330814d91586a2238e092d5aa6d817cc4e7c793045a681d594" },
                { "gu-IN", "aa286232ac262042f4a66e2f346d8e88e25f976709c3f8ff00938f7878d97888fc0340efe843f96000a1d90f45c62ed161028b1ff9a50b85299a15f3021e27f8" },
                { "he", "ec304959625a7ebb845a0dfbb064f9ee7f2b9a0af8fd1948808d2235ef372a33e7f060b76680f74d748f60cd05c9090d852069cf06bdcc90af87ce0b462b479a" },
                { "hi-IN", "bd2120434f8e2451be6746b4d3cc45ce80cc4670c76f2d0c77d2b3fa04e44cabf92f44f9154ecb4f7fa40227bec01a207bd1ec4f7a80e811cba2ba8b384b6125" },
                { "hr", "b445a5d87039bba427329495f398ac3cb76dc365c20297c092f52c664bab45c7be2d6667b05bb45c8c9196981d03265b6f91ee48c76c800eecf6fd38526911dd" },
                { "hsb", "dc1cfe6cf771cae947d935e4e53205944a85b1f695a10efda9429238efd96e35e0b95e388621fb671dd90181cebc204945651a848fdee6889ac77bd900f41d6d" },
                { "hu", "c1ba830f49487a5fa3bff19ed28e4e9fe359896348d7f9a22a1305e4fa8dcbfba89e01707a674e9624443c94adc7de25353f3cd227dcc2c803bece02538f3026" },
                { "hy-AM", "06d99802182f77098cb95c15f0f11da2b834953e30922a330f8b9c51c035076a3ce72899d807841b91b879bab369463873e06f38f5ff552fdeeefbfa2939ab58" },
                { "ia", "49c96dcbc0490d9b4ea6cd567a99ad62d5e7ebe4ab666ba3a2df800b8d68e5ae65f93c42de6dbbff7367df04cbc7ce428d07b48d4be0a1917501df90a2d1e7d4" },
                { "id", "a74954fd28ab8f0b4dc4f81e36ea95371612bec0c3262f7f8dba23788789b56e9cd81b20f03b866d72e486b643d5cbcc706b5de20190ca11c5ec31dd9a0d2a0f" },
                { "is", "8b43cade22f826f097d048746de22c4fd49017a0e75347ae2e309eff93435de766374971d84f00dd83ff1fdaa0f922116a53f6e4eef304f1c0d145593d97d61b" },
                { "it", "eace1f124ec1c5f5259687206f2b62507797f8100e6773ff8ca443b84a614940056289e28bd6238656493c22df7b7fb80bf5bfc4fa8cd3c8b557473914a2eaeb" },
                { "ja", "fefc22ef32775389c545df2d1074ef0f37a2dea2489073615bd5d7327fd59e9a8b2be425ef32fe86e6184239d02f0840b3506928798fca91294cc09a504ec5ff" },
                { "ka", "11e65435b3f2f264d6e539c38fffca64614dc2ed31c8086e153b5d874cd82a66f4a2fea793bacae3465ec16c4a821a20f38147d49f62bef7a5587791264a1a0c" },
                { "kab", "ee55bbee350e3adc5f8c3bc2a88697c5cb3f98f78f951636d45062949cc5c6cd35dd04ac6829cd87a778660afe66344717a25d880a74fde812b055102dd09933" },
                { "kk", "60309baa3271c58591955e9268e1eb205afb9adc85fd0aa61fb05f0da87f2902681c4c4089c4680e1c5ef08fb990866c42a99f89e4b1775dd20818f11c525d80" },
                { "km", "8133ea2f8da6d69f9d4334478cd0e96dc65a0634fc40d7271ad133059babf796e064e76448f2fe98e1b449e0b0a8184f785c5c61321a52f67b904420768a6ec2" },
                { "kn", "696d8040eefd728152394f055ca60f038ab42f5f7425a2d6b0ccdb8e9d978fa3738d8fe33d945d398812cc828db1f94037b501dabf55d90d94891d55045a23a9" },
                { "ko", "f2fb837984f53aa9a7ce7747d41d249bc4ee44c286ec63a391103537088b96670c89b97027d13ff03f63c811f6a02bc79d37696acb2c87c25d6abcfe6292ded8" },
                { "lij", "9e64ec530e405300a46bf3a3b3e6540ce3f656449004069671c5d64ae259c7a4a0548ecf6e3b5d8b10f7984214e5977819e3291469244be957cc693e544687e8" },
                { "lt", "0bbce8a4cd48833a76d3c7cb09759e22b150a296967f8a65eff91b666823b9979631d5d16e851469ab2e45a407eedf4a31eee4bb40f7d9c13781d289475bdde6" },
                { "lv", "8fd44f2759e915c94b39062a39cd539d51b3d9576d20012ed75130dd1194d694db233bd08658d873f7f8ad642be529ee0b01892b0650142d69354abef409259d" },
                { "mk", "0f1d63470bef6d27fb98e08e3bc20eaf3d7765be49ee33a97443b316e903dd6f79201e1413d854b2c9d14ebe53137ce26437aa0eac8929ca226d642978f844af" },
                { "mr", "e0627f5c433f77f51229d7bb3f36af9fb8c8e8b2e9cc474b69a086dcd4bd303997dd1c32f73d6964b9b1c8c5231a49a8240e9333663965496bf903ec38838797" },
                { "ms", "42dac8912fc7735b1740a477054f66ea2aed04cc309bb31cb40e01ab775e0707510ab5d0c716e7b318d70e006916b4f4d0e49abbc25fb9db6e971d11cb7e3ef0" },
                { "my", "d56e1fbe77c3274582741f7c9e2db9ba8ac1299de0e3f90abf15fdf37782d7bac5f4321627db42294ed79867e8e23d8e3dab2b2d463315d4e05a90439e94f3ce" },
                { "nb-NO", "c78531940b194378624c1852f6f765fd012f9fc73b001d8b472b6a55823b9c88262654ded1728c122c4a4ff704e2e8f6e0c920ee8df28a73037d2b51e633d977" },
                { "ne-NP", "1c443ed12267744b29f055f24f09f9aa892eea3856fd57200bd62d6c975b958302c96cf42dc4d5e508dde6cd5dabbec98d04f0da157cc7eacf14b33152997eb0" },
                { "nl", "a70e5e004b1fc25b50715f7f1681307fea9c1debfbf3c5be2d5ad2c0bd87e0ee08e067803b95ce484c510b115e759e11ff6ff093642071cba8e8dbeb7eb594f1" },
                { "nn-NO", "5ef68f7a45a305e73d2b6cb380018c38d56ad22772a299885fe71df0c88c97f7227cab378405f17fd023d4a81e116cb0f5776c8cb36b678eb91b972a2b2f2c2e" },
                { "oc", "065a441612124e6c2515087c53702d42bdec863f16764a02949c5dfe87311366164a1ec92af65b69f6a9042b324dad823d1e9b9fa160201f95e0a1324ef9af26" },
                { "pa-IN", "ad30ca1eb4973d63c06cf77345b92358d906c1ec96432a12a8d92fbcbcedbd8f557f87e81f2253fabefc943ad34403f80e8147f4a13a940a74613c86c5bb796c" },
                { "pl", "974e2bccf4974b1f1c7521aec2ef77273dd94f5a14c9c4c215b38e17ac9f19c8de857666dd610fc38e05c12372409856e7377105a31fc99e38a3f4e1b239106c" },
                { "pt-BR", "f431c1d592f0b28e065314f9a4ee9d2fd7388af7b047440802b3afcd750d2dd7186b01d462d55c698ca7dac07ea4573feaef94c9c2bd00d8a08bc45e29cf1573" },
                { "pt-PT", "9c402b39d920a7df1bbf85fa4ae14a86ab6493fb27e358fe06087df419f9387cd86815e57683525af62e78f8ac2553e16133dbbcb8bf950acfa5147a7ba28d94" },
                { "rm", "970632e7f709da3bc5f14f84eda556f653c5ec72a3a771b209469a6ac3ee184d8267734c982f3a4899ee4f23ab7d5524d0a77bc70f7a89717fd1b0a3b0941833" },
                { "ro", "1e2504191ae447bede6b4b517d31be310b3b851c8af2f309c80aa410bef7da904314328cb74f7b94450066acda7d576c057fa734202ad91872b50a53a0c73f67" },
                { "ru", "02a6b489a200323f638b28bb78ec5b3d29c9ec5885ac2dcae3c0ea9cca7a1d9de715f906c4b441bc3346b41d40e6cb11d6b7b92257a2cc92a50e6d696ee464ad" },
                { "sco", "52306e80b18715cfb410eef2d873f7484e63d93307f665d7b2dd527331d015601250f60a08c4ac8db6b7348e19f0810e403320b1c0cda16f825cb8845d5c3510" },
                { "si", "570694b9e074740cf62fa0d2c606c7ec8852649f13d8bc45168b8b10b19e9e3e48fe01fce2f4ca0944a6247536e8f6e12c0e83b2e95d04514db778743770b30c" },
                { "sk", "3048e8812b1fa20ec607eef5e9b0c9aff90f0e684403e250660ad649fdc53f46a3491967abcc132eb3a15c7d53f12835621b5ff1e4d3daf8714e0cb954165b37" },
                { "sl", "20ab192e64333e454d2151ab909d8b352fcd56ba49095eb1718dfef049d12089e53870d83f710f5f89e9f2eac77203c75de7eea020cd7feb266dcc49fdcfd7bb" },
                { "son", "f0600cbb75e51c2cb68aadfead559c2084cd21d06fc09345d84380e6a04b4cb42845c885c58a3f05f701dab2d05704053a078eb0cfd6e509e1dea080782d9de5" },
                { "sq", "ccaf23a2237c572f1c16afa17e55ec33717cc6eb2444ba8783e96bbf0fa9044ab51949ded2ff29e5d07c0d7d62e6ffdd1d1d16955e6f51335cf1022fe47f421b" },
                { "sr", "556abf493b66ef319cf737eb270c0f619ad17e0c5aa52fb14ab10c6282ead61222d17ef824030280245f71d8736a816ca4cb96272da613dfe842bbf8085d8274" },
                { "sv-SE", "b94bbaf22c8a0770815340b820787581712f920f65a930a0fa4913337860de190052607fe3a1fc0919263ee84138d82ede1be7f3a2fe4b01c5c5d6e9a85e0447" },
                { "szl", "a8fe88ea052b005371baa9a5f08aa20b60e0c4238a0aa605a352e4a25ef6e3471ee66021e9c7e64439d647f3e6e4203c655939ab78279522b3682ffa1e7e5682" },
                { "ta", "2cf342ad2805a2b69ff9e23b925b93e22dcd669462a7f251609bdb739737a67176e97a61be800758f21a05040cab6dbe4d019019c43271f5ceed7e4e80b684a8" },
                { "te", "5e45233f6419ba084c8fa1a8896e9461fdbe80d235da66ab732d62963f53af93f4d4ba5fb176d65ff798837912f46854b5ce6f02f911edb80db3ccf29b800b9a" },
                { "th", "cb653a7bd149f158f93fac2a516d18f6e765aa8e77e9d6604d3d7f09d85e5b456ac833e1fae4d55fbfd656ca3a810b65cd5fdd18a63d53af2d635bf82f586476" },
                { "tl", "f13bb21c8ef5fdc9d806af6c1bfd37dc9708a5ba5da2102922aa19b55cae26dffb39e319562738daabc88dfea51f97179db2637b454a4e089aab9e96465c175a" },
                { "tr", "40baff4c8819d3fa1d59cdf09f83356cd815ff348048e9b27f3bbe72a386f3c2b8348740418355e1e6cb587dad107d10837067c580e395c1df03e8adb4ad76fe" },
                { "trs", "8e388619f7d3d89682dad81475c398679a323d0c5c797f948451593a2246717d35694d1436147d2488437b95c2b3a31b55847c6060c00ee83ae9b87298d0c418" },
                { "uk", "121cddf2a26b6729abe4d9f19b0a215f963e6e5609ba1b70f7abf211fb5f3b337a2f35108dae756cc1a3f6f85435e6767ba194b343c675ed9d5bce6277baae78" },
                { "ur", "30469879e8684738a4adbb97ed28cfe2091f049995766838063e73379de669656b8020c3ff03013a4187b8365790f54ff41579cf6d825adbd030524e2aab01b8" },
                { "uz", "dbe6db45cf6108a638023452fc6c26a464e463e8eba75c8bff1fddd194d5e78e7834f1a3982d0f955a03fc78c5ef7d05a3dc7d1ffbf2569ecf0328b5f548a178" },
                { "vi", "cbcf5d218e6d5ac93ec650464731ca7a7948df753f449da16a2b86d089fdf6e7a4ce2c914ea931f29b6db1ddbcb04de7b091761ca99967ebee1fcf71e76a31cf" },
                { "xh", "d24251932855c3f92ea7802cd87eb0b69a3f548ac947fcfbee58533bafe3b8ae8312fe7eb7fa765d43dc124b7a6a3c28472f87cd3df2ca581053c85b75d75f79" },
                { "zh-CN", "3c365d0bd65babbebd98639e56d0ac2b7f09843410f7a49652c36ae94d036fa086bc8c53ddf4642ba7e33f5252a1220cb2094a607a279af7b2a7b0ddc7b2dcb6" },
                { "zh-TW", "72acc7c6930249eae137cab4816cdcbee710d1fa5277780add55776fe0a8bde756c4c935f47fceb64bf89e23892d1edc0b3b34edf6859c3bd9fb83d81139db49" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/110.0b8/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "d08f55be05d741f2c32ee6eb1b5f70e2ef2e3f7d165b4288aa5deab193f3bac91e282e5331d1715e3cd79c356894391492ce02eb82d9457ba3c3cd45d71715a2" },
                { "af", "8d15517b606a388e786bb10b719ef223709bb4d3e7222bf9eac1ce50697b9c36ed7ff4e816396d411c3a33e04267a716bfc4eb0823b9014e76361867e5540c10" },
                { "an", "5feff84a7772e93db8f1f01cfe05b59fc6675021cb4afcf01e6ccb20abaf41ea573d407db790b6128043f77cda24ded79c65d518a20d3bf52d688e9f6507d7b9" },
                { "ar", "07e820861f1f3438541c3eed9ff58ce32f58cc3656474a69dca027f086069ad12b2540107f3babeb6daddde51a5b92e48e6794a315ec4d006690014ac7fb3db4" },
                { "ast", "429fed5d641a9b5cf3c6550e4249212c4f0a6e59dab30140b88206fbe7fb12a4d8a94098fd67af3fecbfa67be370c503ec2d6eb3bdd16e902b040ebe31e5cac3" },
                { "az", "72d172359850182a2df8af386f1385a41f343da1b19d4b414ee19593e3732b0d94e5d7d94cc4fc8c6318d83b712efa15fe4159d6fa735f7d4034595a1c8c9c8a" },
                { "be", "7752ff0e384329b279f2b1a9a6b2e72b95d48b0193be474989ea5536de2eb22300d9e3a812d24ee881eb1f9d15f891fbce2eea101340c6e958ab1662c2d6fd0d" },
                { "bg", "2c06c7452541be1908e1c273acb13dee8f7a5cf3205ce3138021f126fcf10a7d6d7fc35979f9fa80a41bf51b2880d77a350b7d2ccd020e2e15fc2d3ca51cb972" },
                { "bn", "b1a150a7c43fde9a35c52d2b51dad61cf75ae93efa8610864b41d543fe35a98ecf19d2dc99915e7507bb353d10ce789ac9728765d95f1ca5f1aa27349753c839" },
                { "br", "ce83df1542eb7e94542a597d46aa23e964128404cdf8c0476c38a3b97e3732c90441a257db307eafeddd19ab84ac63f710c310eb9b7a761b6e48570023d18aea" },
                { "bs", "33b95ea3e98b909a9e70eb58913cf8756aa5241e639fa372e64740bffecec43372868247b3a99e44aa538efafbbf7542f96c2c8cdfb4bdedf8aa7ad112e311d5" },
                { "ca", "a787e414dd3207ce4fbd12b87d590179e5b85572e596eaa13ca22bd358dca4a1d9749e769181a1709b0279ded125b3dcbb180073d19e89e0e4a811f40a2ef293" },
                { "cak", "65051eb08293b0de6626d457ac93a5649bbf3ed1145e837f82522b90d2582651355382531d5087e6a88a9b487062498f15973d57ff0f37f93e38ba116ddfdd51" },
                { "cs", "2cb5d9eacc4780663e4382cc31c51ca06673e5f17ae96c253433d737228d1b2abff28106395f4b9f030c085093c971818312ff3a446b56fffd50b23113a08745" },
                { "cy", "e2d80bfbaf5a707c431f55554e20c0427c288e817e3a519468bc1c3bf51a6b33f423e7a0e3cb114ef3d5cba1932e201cd4ac04cae9f6b04c07780044713eba71" },
                { "da", "0c4ab07b3210d449e8075cc10dd955b7433ae2740fcf1693d1b68947f81751c1602bce06d15d8f84a4371494282ffc033a8952bcd40cad5dfd8d6e399b2d1721" },
                { "de", "8131bb7ca122e149de305f6a75f5f2e6fe05f69b6d4c8b1a6a0f22aa857359ecf681ec3d28f1b10981e545b8f55de8caac9617bb909b865ed3601654a8fba81b" },
                { "dsb", "5199b7290fc0b02547762325f004b32cbe1f0422510bee43276b980a75882368772d03007e60f9021a630e61de649adcc8a132a1ceb3d5d929b7ec30ce1036cc" },
                { "el", "62511ed43fd636306b913263bd1aeee993b5db63aaf8890aab5265ee19aab417db0d9d01c2dc5d8d7aba46ead650b802026f8fb7361bf5cb05f79187dfd14a5a" },
                { "en-CA", "d8deb3ca780d85d4e8a5ca1f1534f5d7f4892e0c69827a37ded93acdde9da4995223add510085441a21edc146e8a63641672cbe3a0ae9a2668050927a1e9e504" },
                { "en-GB", "7e33d32c8626e41213e9e51dae65f195bbd0092ee891dbb8e489e204a85665d165713547075efd10e08abdf5ae82fc41cf9582de6a6e9a2f50becc1a622ac140" },
                { "en-US", "abedfba3e33d667345b65911fc3ff10dd71ebb640982d5837c1978603efa64ceb3596b4ddcd68e6dd4cd6d566bb535e4f687e06a4130ab1d198e75748205409a" },
                { "eo", "33cdd5298400b5c52f6d1aad372c300b003b3946169bffdb5943f100de3822dbd76e7d100f4f44b58bd7c8421e7284e6372b30a08d4520882ce48de26c9b240c" },
                { "es-AR", "a31aaf977048d1d1b2966365a11f7520c8a6e805a194f09da5d58ee9c57a09eaa2c92387c3a6f82ccaafd2e7aa0e05ce3bb398e3ce75a8c508684865dbc1d69a" },
                { "es-CL", "f65253af535f892f0b4975895e9706e9f7a3747ed9b187f8bd8de02bf3c485a9eb1ec6708ea9fb1c5398dc95b85e8c0db9c35437f79b4d2273d3914645e0cfa0" },
                { "es-ES", "f026137d0c5082f023c7ba6a5a1669c370a417037574557fbe842c78be497f36da947d14b07f42258c142f3794f109f6505b250cd4dd2ca5f112561939c472df" },
                { "es-MX", "0f5a4eab8a36770c9e34f06d50865c0bfc316c58eb61931a8c1e98d4bdb0f32db1ad283c5c4721cfb63f8c0bf8cac9cd33c252ea4374a378f447ab2960f751f0" },
                { "et", "12375cb57aa351b734c2314d583e70813c4eeec5b1dc361b7a9cd0d5c74adb44826eccf77efcb095f069f0579336502e7dd18e8b5cfd988e6cd3988f05753a23" },
                { "eu", "8e91191e8d61cb4affac78d90d60d48986098720d4db22433fde92671c138276335251c22b290cbe3017299a60a439868ed7668051e0c8103944898ff398f47b" },
                { "fa", "474ccdf64b6d575d57c19d79eea016694e195c99904cea11106b338638f0183402763ff3ffddf00f98506545b409404f357fe04b30236fbd46498ab5e0f6de53" },
                { "ff", "470fea54c020890f1932c0f911590121b502bbc9650fe42af285bb442e7d45d8a9dec335c510479daf72ec75d62b1cd87799f6ddb356ee54885c134edb15eaea" },
                { "fi", "2be6ddcbabce4df99d167f04cec5ccf767a486986255477c953b7fc63e550361e0ff0c43949477cecfbead5486a10377e9801eefae79b05ec6293daff3ad79bc" },
                { "fr", "99549fa20a6fd9947f5dc3b6303eb7275421bfe49a7756454a265c77574ddb775283f1925835e011a148621d0ebc96453944a3d3c949dcd37b7254d64f8ace5f" },
                { "fy-NL", "53d2bc307d54a2653ad4203bfa6e5797eaf379ed0061288f3cba96c8da802bec0140e65ab1b8661b4f270bd828b324895edfe4fd095f965c4b14ed48e55153d1" },
                { "ga-IE", "9f6c4b4060027b984f86d5a10ad1d3b96913e517adb2a5237c9f91cab5b0a5305f028ddd6b3398ee2c381ebb246760d6caa50b060229ad65e843ec7e22ab3670" },
                { "gd", "36d74d9cf7f3b566a4cb61fdeb2214b5314e787ee48d7b09ef997d04adeaec1e31475809c6d8490c7dc760015b6a77ff43796c92351952a64957f569ab894ac3" },
                { "gl", "309a980b821cc2b0b21238e142a81cdfb657dd3e7be80bae18be1fe99a2cef3ef051ff1259adcf5af52752af426700b52b5c81e63aaa1afe4bef442c2484d5c7" },
                { "gn", "636fcd39dc8b3acec080b3e5e43de8888bb1b01757eaf88d766b78b18726e493e5659e3766b03ee7ca6a4662abce7ff001438d1a5475a936240adb71751c03e6" },
                { "gu-IN", "1998700723212e271b52a92fbe5e9c01ef740d22e17b9a064a63ff4761ec88adde3f92df6d124784a152824f6c7129d244d3956ef4c52bd59c73b414c2864560" },
                { "he", "5795a2594502df82227f4b171602a3beb79c457611b7061f393ea22e6e366a8614804b218e042194a76315e77d63a4494ba6f75e6e4aadeb85151ca52d8c0e4b" },
                { "hi-IN", "987e10f49dfa653cc6776bd01ad71f01f80e9bf9f96c2a24a0dd780171848f65052e5cf9dd679e84edea09105615a571de5bb28f9dad40db4594be9f597f7f4c" },
                { "hr", "dcc9216dd0a0bd7f8064f7d0697511ca7869a84815c19aa74557bcff4ab46dea3bc2781618f6653145ea033e0f45b3b6e28d795476b4268c9b1b8594e6e1aeab" },
                { "hsb", "a9acb186735e15adc94af72999626aa18fea0306246dbfca273c78717181de322621649231636080f5b8f462281c2ccd2a6fe22afdb64ac3edea7c840c9c2d10" },
                { "hu", "61d447857cc80f2161e8cb340fe79b3fe99a8b6af4a4d6918b6e15661b10efd2e5885bffd2a5e4f594ce117ecad80a84c5b825d95b57d820f228474ae608ec02" },
                { "hy-AM", "b4642414140ddcb04171a91c7be7aec180df376122039e077c1aa9c533ff8d74ca5a444057dd5ddbe93ba105f5bf49a6e58b397bc3b9a8f4942456e7996d81e4" },
                { "ia", "782bf96d6ecba3a3a5cbe41030abb769d0ee27b9ba0637bf12ae3b503a2e4fc898e34d76b9792ef98bd4f16c2dfaab3d6860de0922dcac9b84bf34253741ae77" },
                { "id", "7b52448ad405aaafeb18b58d906b8f4209ae35a0d766c705710d0c1923eb9d59d4c18afd4d7b6514e9b278e17c67e5a3aff67154560d1270a60ea4a490232814" },
                { "is", "e2dc7016cadf12c792909e2555bec7f3d9ed2f94a4a00dcafbf08836fec56d346db5ef77d5d4bcafe527766d740841332d093e96d41a7ed706a1acddccc612b7" },
                { "it", "c1cefb351d051e86e6074a96486a11bbb997b29c290a92ac1a8b0e55ee5cab3c0d49ff904ccd76f095375546df8103a29e984bc4bdf01e5a5306ad74b12b2cbf" },
                { "ja", "f33beb0b578f89607ca1744c3d00d061026f4ffadd47697971b426398288635869c133495321007ad9d0e3b07d08ac8580d0dc9fb875e63ffedb3a734aad01b8" },
                { "ka", "d1718af397d3e79935b7e4b46e7c08eb6621bfb73608138303ddf72446a02ebeff4f0fed580c2162f47f94f48ccc97e015ae41634431a18e21135edf1ca01481" },
                { "kab", "d53bd1b5ff282eef2c339001faaba3e59b7a14fbc23645a2142a25712da3ee016cb7ad364c459b5807d2079ec80ec9222466503ba5a19f53d5336df06410bbc0" },
                { "kk", "df1bb2380d0360745e4a401b9b4d6e611f11ded5409295d57dea3bb1dd3fbb74407cf1651aa08f44166a3339ffd69c8ea32822e8d5cab74e6dbacc6f94ac0ce6" },
                { "km", "d6f6575be6b5f2fc512f4414db0fc3c5a8ec42e07522e98d35c03419a6786dcfcdeb090b1678f21b32acfd6fb1695ac4868f279da3934efb716eb7abfa0764a4" },
                { "kn", "7960c0d1ec340de5a31b992a5aba86cf66ea9ef42609817f12a3e2306847de6ceeac43142e8aca10a288b7e11f5fa809eb350b6386a40f62779157a4400cf96d" },
                { "ko", "7cac01f33680860a7fa3b2c74d83e4b1d6f5f09b73c71720416d323ce6340583fdfeea137049fd81700c2721b309db4e206fb1d2ba2edbfc3637e0b98d39d73a" },
                { "lij", "84f029b7dae72a89d829914b8973b306ccdb3e9c2a2ca8db2dd1ea527affce539f0cf6ad815d584b93744f9eeff3898a9b596605af470747e4be9a00c2c93e05" },
                { "lt", "fa11b6b4af9e64f071071243007af5fefcaefbd5d5b9e8a3d9aa802b8b52f1d78a6c6f0ba949b2361d062a6b14717a8e79232bacdc5e8c4ba03a8fd7d5fb03a3" },
                { "lv", "c0f26b364e4a6d6b07ab7be804e73fb785b982aed4928ee22a04fe72e4b47279b5206b1c04dbe0e3cd13b63960a94f123389d15e0b3bef9c210926ade6c6e0c7" },
                { "mk", "85e69361e471206fe68b2165925885b00ce1e98b57682fc9923f9c298b01afebfa474e9e968ec9e3517cde7ed622e824811a35b15e69c1640533239a12128645" },
                { "mr", "0c94836b39b52b347443c12fa1c7877afb09d3cd33dbe5a74c28657166176844b0f4331787e894afab2d087828bd458c43d59ab1ee099e501ba1708df3e5d506" },
                { "ms", "033b5db7771567714531755080e86b2164b2031725fac2ca6398c626f2db2037ffbf5764680c19f3a3018ddadcdc4c8cf2c199da0ceaa31f7015b71a62933007" },
                { "my", "575d0de5dacd23bb1f61408facc96392c624245f907c8054425efec36d06fb1005eddc0ef1ba6c3201e3b0ce020330ec32a5450e8c959b5f6ed625057a1402d9" },
                { "nb-NO", "5669a23b32a40a0ab2499bda664c57a8ea1b09dc6982409073bda10e86af995c14f49384ea955e23e5f4863a9b04521561e34a342c360c396175aaa3ef8ac0e4" },
                { "ne-NP", "691110d943e26387fb5214bdc58406bc00cdf6ecb79dc263a74fb7de419f144e2c980174b14d5d13ff8490b6fbe85680f46fad554efa525b166245e21c1a4239" },
                { "nl", "b0e151bac0cc1a8683432755e9fa444606842dd376ff98f10fc302bece8e686b6c296a7fa9805b4cfeb083cdbb51e391dc2e3c6acd78f2724fc339e3c038db29" },
                { "nn-NO", "d9f561e95990bddf9411f347d33a6c77e9d2e7a6d3aa90691937af1805ef6fdad45e5576fde3d492e855808440164c2c45f1da68aa1d5eeaee2e56cdfc48f3f8" },
                { "oc", "1da2a38433a27319aa0c222a9905c557600b80c2a3aa67f6146fcc4c126a618bbc574b7c4122e3d76a507e4afa32fd228626ccf7d5251b7c23de961d9a0ec6be" },
                { "pa-IN", "04b412cd17f778e3c958bcaf8351ac28d16a9d6bf7993bd0ef9731a818719a6e67fece98cfecfc69654c2a1aa32e1ad4373028c9dad769a82016f8dda963a03c" },
                { "pl", "6b88306c5e697dcd774bf747f16f5ceb91f1dff29ecc3aad2d3974d918d5804b86f61be9788d2e9d044135f79d1cf0659fc9b052f7116a82f814d27f956a17b5" },
                { "pt-BR", "3ac6e741211ae473ab8d50be08bf96af9e8a0820132f4f8427fe7aedf2468209050f49e0982f8db51a0c8cee9500f6d2b93c6bc07e043c0a72d939b879b834fe" },
                { "pt-PT", "e3e1c0a7f7e2d9ae25f318b08c024f346458e0169109e9f6cf4f0eb82c7b944f2942ef676ae8bec3087e76f26155a4c214ee7a971a3ca33625390065d5bbf15e" },
                { "rm", "d87891766a1501ca06e8acb65d9f53b59dcf68e6b356467bfa280aa6fde1b2c7fdaa7be8327bffc133c10b26ee4f1c8b0fd68b37488d0232599e62066c880d4a" },
                { "ro", "84dca6508ffb029a4da722e2e2c4a8f47a779d5b59fe5dcc43368accc89f41496ea87274cb2b90db63863a63af1e1b4089f2a6c992e4b0c7a648d41e32024978" },
                { "ru", "27d3d5cdac82b6e90dbc6f4acf4907e3ea25f7c1f355970450f9680f5610a03cd12ebbb3c0406827eeb59a6fc09b8adc63a2d50968bae709bef3fa20d4a53d17" },
                { "sco", "448276be80a61a14aabe3eca37f848745881f5d0dff8170842885f34aacac4ba1a4e87d8bfff390983ba23f168d011fe590011e8b0c6de57eb3961d2f1908358" },
                { "si", "ad07538a0c27502a63854274a7ecfcbd836ed16c647c0b48bc0bee03c4850d3ca8883ce051d783df9f6c9f0df5f796dd0d1212712b69a38f93a77667c66424e7" },
                { "sk", "6a531c3d2373ca1eeeb1180e7096b462467a128b8425eb68c4777ef2b72e896d27289a90dd6d1632807c50f424dd537fed278a8c204d7c494c124f1b2e63f856" },
                { "sl", "f17c5aabc8eeecff419b99322e7b0c1d603412fa982b6f8e7a6dab1ae18058e28ea5622cfb192a21ffb034d8621d34019c10312c3af1924aa34dce4b6978cf99" },
                { "son", "21c36d1b384e4788ee2c54924c6fe6f9404e16ea4589a364bdb974f1e6bc7ae2c7407c07c35173afd07962d85e6a0acd6d7d2b5b3ccdaeb82c9b90325c7852bc" },
                { "sq", "1e2ab84a40894fa91b7b8b4f4c69c86fd70b840afcaa1e42eeac217363f312451169229fcd99372e30064bc78ff5ca4a622674957c56dd6e466cb02f616e4a31" },
                { "sr", "024a5ef38f06fb936583743d07db1a17581c4673f87389486baba4306b7570c9a166331b90d81b7687563ffcb53a367acb7aef237ab7291b5d4ad78fa93684b0" },
                { "sv-SE", "450953ef7769739ef1550db47aee5a70c5ac6c2bf173a63d7660cd265132f4ede04b4a5da704c3f49814c4b56d691d25b1eece576a3cd91c68e328c98ca3a0ed" },
                { "szl", "015a783e7ed05d517a4f2086f4a94cdde01515a1577e64db0f0706b1a4b615d9868b9ff82efa4447b0885d73d1b0e8af53e38cc1cbf933e9d9780c28409ba53d" },
                { "ta", "19078304f6f6e1ba0fc3d3181f3658f7d70db13772e7a471a146cacfacb5426b82b3d1396a16d52f6d07cab62b7200a13abfa6e42464c20069d24fcd4b8d74ff" },
                { "te", "1dfff2603cbb43de2f289130c41609beba29e63318c1bb2362dce60f7e37903497c6d463c6634905fb6942c42cc9d439ecb601219afecb953f3c0b2863099551" },
                { "th", "6401ce6defcbb35b86d30bb36dc70ae4f69810318961ffa61db8f57adf2c5af1a1d2a7f45156feb5c976a46c9ff9dc71c0ac41206c56d0a304f3cfd3e3e24d4d" },
                { "tl", "0a90f17825d45c8f2a504aa6e1e4e413a98f89ae544a9d244b32421dcbb20858972ee4612d619e9cad82512749fd02b156eccdea5a6f43827ec1c89cc71858c0" },
                { "tr", "76cd8045dab41b1492a4200a262765ccd1f438c06d3f4a03d7bf10bd788467c393daf0c6d5d87d3e15d87ab6283f2e4a90b7f8c79dc80b42fafb0d3683b84fe4" },
                { "trs", "6cfa973e1ad5f2b68177c2fa164e62654e4465c6d497181b08036d020ab26a93b708af0947437c12fb67b998bcaa5a9ccd4b4f9d35c4e4d6dab756500e64e518" },
                { "uk", "0102c23a86ee9ae9087757aeb3d7758860c96691f6e96378901ca842eb48a019ac7080ebb9bc636eb348ab3d069568b10b2b47bf85b015667f33c2a4a20759fa" },
                { "ur", "df93b384c31a5e1d9cbef530d9accba5129747c0b9e16adfda2174fd644078fa28ef706a97d1e0db9c65752a05877ab075b5995d2aa6e040ad853efcf7c1b060" },
                { "uz", "0986993c5c19ec2875406c8748dc63efaf984f2b6727d81bc73d8f6b7de1cbd18ab0d7cb490d9550855a623af6a1c4c9daa1d55a7a9c8cea643b0f7e982b2aa9" },
                { "vi", "549b0053468692837c9dd7b1adf508493f2c9d42706bc7eedd342bddd99b6fbad8981d1ef97fff9d115c06b3b1f5be74f4b9e88dc4f77e722613e334ab9c797d" },
                { "xh", "d3b7e827a877e1bade50b6c29bbe97b9c8dc485cbd8457b2a4c664d28902ffb027955e479184a52e4cbb7c7f50a27bd6714381230cd156d87b99a312d4e7abd1" },
                { "zh-CN", "bfbf9894e584ee1ab28d87ce09cab9e322f9fb25bf1a33686d0fc6dd4b9643f5869373299d123759c85e75a79550cd8292fcb6588a72694bf52a70e53349e104" },
                { "zh-TW", "f29cd5a010a9368be65f792639849c930b5a273cdecb283e3a6552bd58ebcdd063331ffc4d0cee31e2afa557f392eea20bef89c81630e66ec72e6c4e91d2ba67" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
