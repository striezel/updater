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
        private const string knownVersion = "128.1.0";


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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "db76ea5a4af1364d896c935a9395c651f6803cf70aeeaa465f37dcf1545d5d8388bf8dd26e65b23ef081269fcb94b5cd3142311a6307acee65de1ba6cd83bf15" },
                { "ar", "69bdbe19699961a08c76eaa4d9bc8278d74d9171de857b6b933918547d19611b0e2296a0b7477dc6ff6bf09139bd9b676207908abb42fd0aa6a8578af1921b88" },
                { "ast", "8e56b7c2fa0f4afb6798cf5cf3612b9f8263afc8d5b655c13174047709da02b313cfec4889d805eb6403ee8a075140cc8c85588320e7df1d73208ee91a8e54fe" },
                { "be", "4849047639d727256e9891cbc76c10054f7b4fb34482957cfbbe90acba483d6afa832bb064cca298f7e843583540667b24701783408c6d028151077bf90982cb" },
                { "bg", "d1561584c8241c0253432988fbec32612fe90b746654b56eabbd612cdc3b4e72843d81f77c388c73cb36ba0548205069edf468f6fc305e6858b2bf196eea4c8f" },
                { "br", "f033a684d5039bc4bbbf8e2e52f4f29e1ac4aeab97e9d7ef01a60388f4973ce16877a8c5a1c0581ef1cca5abfca7f1f06c669ec770d23f1ee67a66cd0b126fe0" },
                { "ca", "dd34274d515a29b28e49a5f29807adfff18eaa2f48b87b2ddcd8fb0cf87b5c65d9a88149b26b6d1c73769839379c50ed6b191a2d263a99f9cf3e40c1b1c5e0f5" },
                { "cak", "30cabac0b8051f49ad7f44f578c2f013a627b91bcd76eedce1d01abd4c838723b08065b4b1c9debf2c28ecf0e4114b02887cf218fd667b46ed607681b364b837" },
                { "cs", "0017a990f37a808ff3e0dd516ade90f9f168c1f549d7d87bbe98e1912f8bb2330279d05ce6ac5052859621e4940615c773758985506cb06d3555b64d2c0839aa" },
                { "cy", "b3153add3a94173c2b962c50f2ee34724877e603fc5e69ae431fce634db0640d191a8e7e5cbf22e167198802aae082abb8b2ff76ddd2c3a0f245201974542e25" },
                { "da", "f18fabecb919ced932c941bd64ea016950099e2db66f01ab42edd8af87ec6bfc8fc8d7513ebfdb96dce5ea86f06722533fa4238cfd275c6ca5be601ceb93b94f" },
                { "de", "b05dc0302b37c8ff83dd1db3b605374af6a550e0e8540f9464d3ef797646ceadac5b253011078cdcdea62fb811cee51a1e6d63825ad167d45bc87585fee3fed4" },
                { "dsb", "1893227d33b5621c5eb32eb84f6abc876e5fb018fe281ece97f8b421847eef1d1a50c4d2729fbe667ac087f49ba71e5b305ab47c48cec509767c03cec877d35e" },
                { "el", "8e8e5580978a9bb3338e6b5f5a8e626f097aca2f338fcae48128340183fee3f09fcd741b298d52acbd06fec00b6e7dde168662e1a6b68b2396a7c212db7af4c0" },
                { "en-CA", "e798afd7d02838885369efa50148f0d77608f3b48fdc0f394af9d294ec8da665c9b570a6e054981a9c284d104f566193ac6ff9c214fb613d59f83e1e586ea195" },
                { "en-GB", "3881bf2878b9186913c0bb84a5a299da0ae55ed2d8f254df4378a72ddaa3635ab00d43943e18b0cf47e3cb345d281093724e547565aeed672fb0a4d403a5e2ab" },
                { "en-US", "5252bda5a53dec08ffd761a683dfa42db749d2494aa6d7eb3910cc12056a9b69f813d5a14c48f44c26ce6800a5a48289115a7dfd3fc161b8eb87f8efa0bf66b4" },
                { "es-AR", "37070399ee8efc76f6903d4cf2451f64bd38d1bbfe1e08846f82d8eb8122c08acbfffc7de96be6ab8b10f4ca5a717265061c65331565ae51f1285dfb8accc108" },
                { "es-ES", "f553c17348381028f51d635650649050ab06482792b3151a6952ff106f659a8de9a1f942abd3b4af57e7120e50e54688cd47eabb7a00a8237de3605e08fd5cae" },
                { "es-MX", "08ad01627e0b2a832347ac09108d785086cde8e5ac711994672eef251482041622a32d99d63f7a1306e2a81fcddb0dfe9f07ae413f4ec7385dc2221e5ad0ee84" },
                { "et", "28378310e25d74d5fc4ff58b9a902ccb4eaf35901d04f2bb4692a621cca8a934f4b91570f97f9e3f20c15a6a5a8bf82e85cc090a02af3801975f43f4279d2817" },
                { "eu", "357859f9eebe4954a87056516417d3b67123a112bbe81a0d397dc41fa88b709ba42e4e81e77189550ffbe685fbb5759c43ed8fe67a26c1cd216f339fc7e9b38f" },
                { "fi", "950c714dc6bd2acd5bf7b4a6b9441eb0d7a7d159b798cfbf777e759631a3713231da370026fe14d3ffac612406d6ae8534ae1eb3ef21a071ec96a88110adc0ef" },
                { "fr", "d0c2edd1877f3e7d7255379f13ddec7dd1152cb4de8e701fc70ab4ecd609e3961b221219ebae91f290300da92b05f65b73afa4d85d135e929c4c0a6199fc5f1b" },
                { "fy-NL", "92a92c0628a716dbc42df05911b38f9bf332a8521c96a105670f641dc180df2850c557f384e937114dc8d754518691995d6d7eccd43e6a59152bdb6b51e51432" },
                { "ga-IE", "299143b6b9d856117d7d71a9f82c2f763741828b27a5f8e647da63e76ee6e07f3ea3df8958771e29ebb16c111714a3cb3c4085cc72bc7fd07642845aca37a3ba" },
                { "gd", "035010e57e3f354fd1359458a3cc8b6af7ffcca252bce2a8ebe1979b7b85c658d7efc0d6bb88a31821087fa12b71dc40cc9a0fc1841cbd5a744e682c4794321b" },
                { "gl", "570c88ba553a688dd1bc421a6506f0dd51a79c8906b0982cb1f305a3e15c2a471d9d9a49df5d1a5922a157e12f2881ceaeed2d408c8576f690a031e7bdd38a45" },
                { "he", "532b5814b388c2df4130dbb03a60e27a027a67084f76dad794f1ff5ff7a6c7922c6b966dc7e9e0e0a33309ae5391e31f886ae52f049133e7d2d92a933f0896bd" },
                { "hr", "d0302ddd677374293ef1a25cf239319cbc8f2013272e772b715d5bf478347f1cfadd1f350d284055b5a23f16a9e741f5c118f6a6c44d470855c3e81ae7be035c" },
                { "hsb", "20ca8bb6ea84995266d30b9b129032ce0ad604e7bc3e06ea241487d04abe6968fae3393b08dc3bfd865611155ee95f9db9b562940262315246f0876368008e47" },
                { "hu", "eef6983b1518fea1339bb2b315128ef55b9907aeece768684c18033093bb2c6306416e5099256827ab30b7f41eb2bd3f8aae925711a6a4f6c547b742d1d8da37" },
                { "hy-AM", "b21602d9994fa9bfadb8c6322514c5dac8d0b9470310ecae13966455fa108d34c2cb17aa70d6f2edfeb21edffd751a5863a636963415b6bda8d239f5bf54c60a" },
                { "id", "18557100176ab6d15588577af123756b86cef78c6df85fb1a1b50994ed1b24192b789e4e0da77df687188e25ba28cd9fb775dba0c2e1197ee1e1d0cf3c74b87d" },
                { "is", "612dd703e90993d8db1877ed09ba3af5a377160d68ac23f39a300829e8c2f046ea72820e4f8bf7c10043034d4442dd598912132986b7e2beb9a51a7217949eca" },
                { "it", "def742f00beda07db2dfb8e02028338c4d57b62aaa9a06c427e98ea620017bace6582f73574c5793e6e1bff0b08f6cf7a3dac207e586ce3f86ee223fe429ec95" },
                { "ja", "df3042b8368d3a33dabc10d03207d95d0e675f22e9a2ee8bfdc6f23ab8cb957271a17792cd3e5c22ceb57399b8b3ca0d509120f8fff7e8d42ac2c02529e7ff2b" },
                { "ka", "c1725dd1c88cb8bf5dc96c4cb48194c0a019b3b80f62d4f2911e77ed74657b116994b34e109381319846b1f204406863ebee4555a47235cb1543dc1071025943" },
                { "kab", "9097cae00992e94fcd2a53acd9912d72fd33526568f9ed7947138fdd69eb28821431f2efd954e1b99b8520461ade09125ec34c3c28d7f7b42bad54c0a070a11c" },
                { "kk", "8637c6457764d7cf86e8da3a9a264fe7f51c0753ae5369bafbcf37ab44ab755e01e585cafd30480ae1ce6970d313861de51b9264887c781132916ee18f52166e" },
                { "ko", "55a918227be0f6336de2d370e1c1579c0c29df15b54f3a1d0450472e0abf16378604198777ba9c414db6a6aae4b206da7bf9e6c5a9407c18a47953ca91424596" },
                { "lt", "2cf2af325857909aff601b28079bd04fb20dc8ed2aee97d6540b4ed68eda95d1b337008035d39813490fa051520b21237540168dfabaa4c40699bcf1c0b0c548" },
                { "lv", "ae293e6ac98bf98942c9a26dcd6aeeb82b0a2950522e2551bff6036b59dc4852459bcdf9a9a423af79151b5e6e285961e5606d50f4af6de055510953d09b5e4e" },
                { "ms", "d057e53f1756d9df8edd52a61c8818565a9bf7928903dfd1306fe8a7584c02baec05ea61ccd3839c819766b4864c488fc117de8c9da324663d339cc2a398be65" },
                { "nb-NO", "ae5f319d1ba86c325c8c3ce2a03da49f325f44c93fa6c1430e381405b819588ba54156492bf703c91a0ca86fc393100fc2d25e1f886c62ef2da5c4932a062f2f" },
                { "nl", "4f3fe5c9f94d0cb3ed403d0ebcfc18b66d307bc9bbd94896cafb094b74845330d3f572627b6a13c0a17ce04fc8af4d34ef7d8f08ffb45d72021826e165056a3a" },
                { "nn-NO", "7410f0fd65e6d691d31b1ea564dffdfc65f55fccde44505c7185ec24b0d9ff08d404d187c388cc6d1889865d44ea4b78013889e28149ace21134f194c8232e33" },
                { "pa-IN", "308fc327c7db81e4f1470117a86f66de31a6d044878e8f3787b5d0f37a7c75e32bce92fffab1b2990708b6f2706cb35c069115878caab40d59bc19e7bff60388" },
                { "pl", "523fdfa8d9b3707080725c4ba6fefa18ddf7198e28089e4f6c0ed3d52d47b4c74a5a9303b50aae90eb83342d2ffc19ae5e7c9ffd866cbbd7ff50b2fc55926d1a" },
                { "pt-BR", "96427c7fd73d4ff64b68184691369f130143265a064f7c3ee4a1d355f240fec527e58c48ab8bfc67f94f9aa32aae3b117601f41060e13f354a170919313bbd0d" },
                { "pt-PT", "e63c5aa836a5b401b183c00d3ca04c6b2188510487b367dba0cbeb184258dbe0489b356045fbccc6c1dc82089a94673b2d7bc53c11583b01917cb58560f3e7e9" },
                { "rm", "a0ae59614056eba51299a82b1ee761d559e2241e9be0474678394c3d1e46c8fd781790462f45c699f07cccf1efb43e481021f83dfe27a98d68085f7ff25bcba1" },
                { "ro", "470ada0d5b60db6657a9cccd2df6bf5bb5c572e74b5a913196b5105b2cbb9e309ed41cb7a679992dcf7afdc2e285dfa93a9ee54b53cb6b34393b507f00050ea8" },
                { "ru", "f802e4e886319a4650d890282e9f0932805a17e3402e51867a564f8f44b5f9af558bd78d9676b2731a019c44db1d3a3b5cf7a5ea638a8f0f25c0b273cfe87602" },
                { "sk", "f5bacf6dbc1100b6833bf8337974dfaa1fbdfbbf24a57d4fc9c1c8535ffe5315df28a6bc24eab1b1af803a1148721f3c1952c2d52dfd4378394989d0960bb649" },
                { "sl", "23ba7c2336309cbc84b0f481f68e4c161ef23bdc4ecec2b93b8493d4ca4d182487edc5473da3dcb6883b8fb9375d7a863859fb3775e85fe63145076b1c7a1e97" },
                { "sq", "533fc5803ec5e967bddeb4b11ac902f34b3da1fedcf1f939afe3a637de91fea42fe414f1bb883e73967c6bf1910291bfe40473811c1499c9004ecb612a79890a" },
                { "sr", "f39d953b20fe452898db5a86ea00caa6b62231315316fdc6e4f1b056adbcdbfdc943d3dbbdf50b4856f5f75308306dcd0ed9ff2a2bd224f2c1a2564340c0abf4" },
                { "sv-SE", "315a563ae1c8c956591601ee9e83cff17c683757b59a4a043e8cb06687d72f032a0b081835a4fb3025d0a12e2639289a3e702bb0bcf498814545f67715f33b44" },
                { "th", "c80e53a42798276ed12e04ef41a5fa738a29f3e844816eb385b16af83f1ebc3196e0d179b59da807f98b456e37954f410dc09457906c3db94943eb5846cc6f5b" },
                { "tr", "bce0ee954e7c457fcf6bc5de00b5005bdf72758a7712ebf47248204e77edea0732318a935778f8b144d305a9c68f648104d7358aa0d801567c7347d61ac53730" },
                { "uk", "e0ae48177aa99bd42c790d5df44eed432df823bdee6981f247e3135ebcd6391ca288b9fc0a6460c6167c6ef7be919138fe0317c74191ce9f8a73c596c5b932b1" },
                { "uz", "2b6c0c3030a60821bfa21983109b30eeac8b7e156d53f2c8be3c1afe95460ce13115f9b2c9b2f0764bc55b2950962a7adba2127e37ab5c532f8846a629dc998c" },
                { "vi", "2be5169396faf543160b833b422963b6420aa9e044662aad198fe737446cb72da470bdbfc54f21b0bc189175d250133067114d3e5cd093091f34c5a2cbe7df2b" },
                { "zh-CN", "0a10beb3cb9b32a42f9234855b130041a26b83bf456dc8c8398325f2bed0ab98732609c819e3b343b697711140287fc980baccbd72aa28ae6384a9636dbce54f" },
                { "zh-TW", "1e3263de601773cd21386740e696182e93789ecebcb6ab29c7320ace375740a42a2bd2002d7faf5a4f9a2225f459c0ca040dfcfab56550a431aed118eb81c807" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "b0089357a95b83e54203b279193ec4d397499acda4f571349c772b25e1b599c31193c6cfa09dec2597f558ed19ed1d21dfe265ec38751f6dc7581bea99f2c37e" },
                { "ar", "551c530373600e0db33c7988f7d0046bf489c611841b1e621cfec7d132bcc756c1301c481300a459f983f4797312c61761b25c764ac7ebae2d07b543b1be2b9c" },
                { "ast", "b8e86d7926b6f74519c0b17517385a64fe780729652f8fe70d1c26d0a1d735c794c14cc905b1e109a60c34cce665348d4411103df374109caa8eaabc21679685" },
                { "be", "c330fa8b7bb96ea5c88f432925d1054e92ad5303debbb18aa98b239471d8a9daa44ee40775a1462180a3b04296a9ed39f288249e3cc5fcd461663a72e45f8256" },
                { "bg", "7a8167e0d8984b8d1baa4f259d79aacc574f09297a861e072353a932ee6c4fe622d2822eae275388d13f63d3c8f8c309d72ed01eb52d6f91486d21d511cb1636" },
                { "br", "b7a9c02eca3e5ed383108dbae7d1a0a03f7c3432854a9b215d2663729a7d5904c77d1a616fc309117f1edb7346339fd1bd8011060fcc0f8564b69e98f4ee5fef" },
                { "ca", "670cc4120e115f2a8b747881caef2e0902939c609c7b09916087788e6df7529101f1314e8d941fc2e0054d3527f6bcbb59c92dd0787ea863f7ed01041cdbdb58" },
                { "cak", "37dabfa3bab63a7e9873e7776669f996433e81f4bcc277619aa1b629b1e9187829ad3b8f592614dd7a0d8d9ab7d868366b2b6a066c09e547b6f025da9fd87818" },
                { "cs", "16bfb0e5f13ca46ff09dad0b70eca5e0d9edff43271749fbd5288b0b78a1b6c41f87bae51c0aee4c4959ee9ff4ccf0406196e0b822177bcc3157b85691e2bd3d" },
                { "cy", "89b084132109d6ca3768215c913c52ab7c2c63bf5c2e2f04939b3695f34da8d3ac0816086e332e29d5b82b12dd3fe66aaa74489c1a88af769db6a65eaa3afba4" },
                { "da", "b9427b7c16a3c5927fd78b59fdbbae52ca70284112edbc09ae1821767f4836ba2b570fd7142ce9e83f9b7bf7d3fbef754e8bdbefc6a85c0cd122fa26f811a4a9" },
                { "de", "7ea5e2bb58d3180e69fc42cca9ad088dba4bb247cf1c1a1557e2b87f1ab2cd81a05e32f1a8bd77355fea05bfd306a4e9e54640d331797cbfaf8674b0aff2b726" },
                { "dsb", "d1fce5c47ffb1a594d19f15c2e66b2facb6ff2cc0c153b96673908d99b14e37804619a78104fa3276cab991d3ce8dc8ddc54f2dcc6083947220e2bcb88d940ab" },
                { "el", "c8555cce3f5cba7776665a8c491b6d29dc0be583dfd2ff91ec04cba0afb694b4b282d1c9557157cc45c8642c1f92b0197125a7219dd6457884c93ef97348cb23" },
                { "en-CA", "53bbea5c64df25e1bca434f0719ef9b46a23df02d0a82352153167200a0241eb8ad565802170e8cf4ca5a496a78a99ca12f3ccf1a48fbc977cebf4ed057cd471" },
                { "en-GB", "20fd118b363199ea630b2e7e1fbb0cf855036a4c2efbc13f6921e0677b46a9bb054d7d8d85a7bf56ff7b858ad0ca6a32d6cc2fe613f04e3ea6a48457aafbf4a2" },
                { "en-US", "151dfb3180ea90c6d1de9c0267a63c9de95b846752e89b702f96db88ebfb64cc0917915012d96a2f96b000a08b4df9ceb25d8c26c4e638077502e36e0aef3a81" },
                { "es-AR", "eef487385c325ba6f8290f36455d72b125e612db028adccde90862860107e1e9e48bc1a06006ea3a81ec49e5a556ed1aa5014b6e9780ebb7608feeb30164b11e" },
                { "es-ES", "25136bb6832a689b9cf7610537541ea7ac3ebd81658a468ba3a8f7569ec7f17465b38012eae863fe2434d0a694492342f06c4576fc60d6bc89b54498ddd1adc3" },
                { "es-MX", "9ca1c2858cd5ada4b83496f3383eba27165f6d5aa3aa7dec7504a922297938cbf1472da8d73d55554832ef43bf72104a8b451085fdc7a500cb670b11abc2de9c" },
                { "et", "9697d2708d3c19332909f84c43dea46cb0b44d27a64fecb026966dc9ddc1827c4dc498601ed546419983f6e5e0a56538f45eb23a6cfed932049201719253b914" },
                { "eu", "b648e6f961c50da69e55f2a5627709b02d5c82f694fc5ed0778594dbb09f167bcfda870f02f88f85fa6ead894fc69a99cb3de6fd38a4a41ba0418f93487d7dd3" },
                { "fi", "c483a73a40a4423f8f9597407dc1f84b9b98ffc7582e83c437d4aa3639a97caa241782a19aadd4735e4d9da74c35d4600410d21635dc5cf238e93ef54fde3feb" },
                { "fr", "1da7b4e595efa063319e3111389a17029a4443cd4952f76c450c83def82efed5a82af1f420b6f23086db4d8a2f6b342ba1e78dcb89874a0b7236f82825bfc2d3" },
                { "fy-NL", "9dbab68576068044337911bbe6d93615071900419d76ec19f656a189637a7cf9b6028a5aae019e18816132c40dd9bbe12fa6de02a9bbd1dbc7eb3645bbdc45ee" },
                { "ga-IE", "26f4c9f2f784e92248aa50b8a89f53fc47c6f589f5729d07eff706a2053d7072ff5dcbb22cd7ae8de58e97b291b69fa25e9cebd32d87dc6897b848850d16b380" },
                { "gd", "6f1de2beaa1693c800de1b72b9b43367052e28055bfe60798db21aa8b266503e8e4191aaaa9f37f4d86527d7131ea569725389cdc72c29ff1de7890f8b97a378" },
                { "gl", "3b924fb8dd2ee3e4ea6a4f2812c5a3cf4c1b8c4e3ffae35988358aac6e5010edb3f952e2dcebd90f432690d01e86a497646a0bd2c8a62f710afd478a0c999335" },
                { "he", "4d0fd3c4f0d7595b6c983d180c1f6014b8e6d9e594b05115430ee07f7b09e4b590835f5ac420e4d57b425d77ad37c6786456704c18659d3d7ba147779a45a026" },
                { "hr", "8a50a062372fe44615422d06de82e46d930dd98a3a7eb68d4e03584bc869c85e138487b549c4e35d63fd0c516fcff5fc533da8cfa42f1cb866fe3046d91759dd" },
                { "hsb", "1a8962baa0fb4f8990442e5a6432525fdb9875d555f4f32cf865f0fb283fa33b52b4d4059585d14222929500f9748f69a9c8c049861cdd5863184104e79b13a4" },
                { "hu", "608ab5c9d7ce9237fd416996d5bc5425c265fbecc06b0d82d918354caddadd29a152a58e9815925fe14b6df5a183c78ff7543e296fc4f79c13221626bab18262" },
                { "hy-AM", "173c6c76290d874f2c7103049e97a03e1d32ae98a01c2e38e142a8bf36057290886ff0581453878893497c3199a415cd7eafcfe90903395ed365799b37ff008d" },
                { "id", "e2c0e921d5983e7ba77fe5b441ec6452e8400481a24afc42ccbae4a1e1f74afc06b9ee859bffa9400a05911af3051956446d127bcf1516cd1cf77d05a07404d7" },
                { "is", "68123fb2989807592851f9daf593115b91a8a6738d725e37eff39942741d13b31042f07fb5203fb62bec87b436d67c253ba7107a7ba104affc365afc9266320a" },
                { "it", "a1a7f1d4fda934fed39fe471abdc909c1e7d34a58155e6fcc861f267fc1048414190c40a1ee3e17713a211094c0379de92581beaf631e9ee51b75f9a0529d33e" },
                { "ja", "4946220b5d08768f41560accbb212c1ae7cdaaad515c8d55a5ee1965a6c7e20f79b1a82f3bce683eb13c352e10f6f9c88a8875395879c55f75d90eda8ea1e8d8" },
                { "ka", "7d8baaa5d8f5d302494217779a1c031e22e3c500d66343084f0f0e048e53b02de0aa05fd06d1a821c9106a6b6f587266b7eb1b819e317225d403f893f0e2bcd4" },
                { "kab", "0f475558a16912bdab99840e0fefd382c6f21c863041d29c13b7ffd2be288531440cad34a1dbc4cab7235b375c629424b6bd8dcb2cfc4ab2de76de4098a59777" },
                { "kk", "e70fad3bb202744fd0dfb947d3a8a416b708409f976866a0fdff669086560bba32d0616f360ce6df035f495dad25b241cd726bb4457e5621aa6fc27cbbf0708c" },
                { "ko", "15dfee63a9459a1c9228e20aec784efff87966dea10d9bd53f443066c9308331dcade072ec0760a740aa3714dd2c83f0e7b483e5c53c67db38d945d9609cc9cb" },
                { "lt", "26832a35cbef9df9f9d3d91526ee32c19211751e525bbc16f894d33b342fa8cef14a028a586d66f709de8e17cd143ddb6acb670addcf89c49cf9d13504a305a1" },
                { "lv", "444bc999bec1f73b1e8933ad5c1850b1b1c67652d5ecbc71086b6a41f3cc48097c3503f265f72157a20cc070977d4023bfbb4bcf7d514f2b1da1f2388e2b9b3a" },
                { "ms", "a3e70f6698bf4dfeb7b032403c64da6895f992189ae11f93c63253f1d9f9c7a8a64e3fe15926600efeed11f0b138ef16acb1b537221e2fad280cec705aa83270" },
                { "nb-NO", "4ed1f5f52bb1f9501e89451a3ffb43256ed55be0e17be7d218891ee571841a96179343d21f598b47ff5570523f19be11a83126b8deaa07e4d3be3e1cdca8fd8c" },
                { "nl", "d79f5e7f98c16d199d14ddfb2c07e301670beec2a88d21ec7b6a6938cf7cb68a89eac8f706cab8b5c8fb4fbf8379745ffa52957efb3ca8f95690c7238de4d27d" },
                { "nn-NO", "2764454ca01d76b15fc0cbad440889529577091bd395bdcd533389cefdfcc0acb0f091ceaabea18e947c778ee103178f25ad3f440ee895e6804a9e507763f667" },
                { "pa-IN", "62bc5ed70426056d7c80f9cde70fb96cb7fa0553baadd8eed7737734fe5725d1e6c0c7701554787757586dd8485581942752492cc029dedb3413f1fb3dba8880" },
                { "pl", "e361a25c05c58839252b18eb25a12c57d96c08884bc201fabb25a9d62ffe5aebb4dfdcbcccf171b4098379cf1a130a7a226c930eac2320a92aa86c2838eb2c9a" },
                { "pt-BR", "7f7d6441f13e5b80d473b46bf8d5ed7e65140f9150d4b6dbede00780b9dd86f1ea6fadc21a9b06d2576b3c9955510078f8fe5072b2464b6acf4f3327d08b165f" },
                { "pt-PT", "060182bea31c2d6b475a3caa7bcc56c11348e8310cfba6ed3f12c48c492587b55ab557423933f29cc67410f0c85a291b267c74fef86016da0c7eba588a37e2a7" },
                { "rm", "c3b7da0f27c6964d4d117279a825e9a00eab5d7a2286fe5a6186bad2755f67e1a4fce40bb24c7ace0847a3409ad26b7c22e3890bfb169a3431c45fe034dfe59d" },
                { "ro", "88a4e5f3a7f11eac89b34b6ddcec7031935398057899e4980f6c365e9f7fb9d679b49ad74526dc104c9502d86d90e677475862f45e6e0110777c34ee550b36ee" },
                { "ru", "c19bb7aec1678f84b81c643c075017663b2967e58317b683ea076101d2ef329768f794eae0f25a216a0d5a8875c213a56f0b83d05658f34099a11d1bf764eb94" },
                { "sk", "dde9d1afdbaf8e27bd3d4c60f8eafe2a2917bfac82d387f74be88c2e5c8faa374da7188608936a8cd16d572a730189b4394cdfd6eecb123247a472bdc0c3cfd0" },
                { "sl", "e6d395d16e021ff034add227a573b3f82a180df2b936f2aa996dbc65c2f0ea7af57402c24a81e82784248dededd1b079dcaf3ad786212633ee708c6caf2f6572" },
                { "sq", "759b14ca6d40d523c1ec89bd1c4fc5fef9053dee0051c0a888398130b5d0e863e69310271e0d88fdb32947d17393b3d8e307d5e5be42b866f2944903f083adbb" },
                { "sr", "e53db97888e808d6827c6bac82450b3dad828712558cb1998aaa337962c351680cf66cc29dd0b676a3b4d20f6f57a5a0ea0faf3703bffcc377970a25885a196f" },
                { "sv-SE", "113a2e3f6dcb32af50966252ddff6cb8f0f37db6b0b8fdce26db5c3bcf54aa5c1f59d56869f0fc8aae9c41b548303833f4da264fabc22a16a125b9151da69ae1" },
                { "th", "f25d6065f6c1bb5effa7f505a2d6321882f439cbaa1a67e4fd2b6fc46b8036f5f175b7546e7b9be39afb33a8f830859766f86aa089a563e68a5dd26b06c68aa4" },
                { "tr", "054f3ce91b5ba973f5ceed14bb0be21ce2956911941ddf1871aac1393238585f1586688190c8613353bd18314d6a9f6530a03aab8f5dd71f38fe8f57f8c830b9" },
                { "uk", "6cc67abd811e41404b6b79200d064cd219d9c65349c98aedd612b087fda2a10914ab8e74e4afab81ef503eca550f673dfc5dd7d891a631f415353e9ca756b1e6" },
                { "uz", "276941603c014570f8a3aaf816f2584c54ce453debfd41e7684bd33a7ff17e7a76dbab3a6a23a56544b482c8f3af56d7ad7c9a11cefa0cb0d86bfd534aa9d704" },
                { "vi", "143c97003958d6f4d543cf198a11a44b0e96f6e5f20e7bf920f7a81f46a4929fbd88ad97e76c86eb27c279939af2c0e6218497d44955c0a682258e1104922cca" },
                { "zh-CN", "90a09ef7ab6e8f18c5094b5d3df0d83cddddf6ad2126b43ca22a4cade9ba43f6bd19a7015e4153fcb2131d0d38a8bb1cb2386f02f82772e1ea2ce443e391ce8a" },
                { "zh-TW", "b53a246784fd161c6d205089be7b17f66ebaf8dd48c32b6f6ff2537f16d6a61926b6a4aba12f3f6e58a3604cd4a7d25b75522a02514f49a6944ee470a98351e3" }
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
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
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
            return new List<string>(1)
            {
                "thunderbird"
            };
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
