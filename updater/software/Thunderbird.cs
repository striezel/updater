/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string knownVersion = "153.5.1";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.5.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "768fe902b020d6161ca6320fab883545759b9a91b2bd6e52d1b6efb7f28901138ac3ad6936fc3aab7caf4aa457102d383a970227846381e127a79c73111633b7" },
                { "ar", "2f539efeb5d54d0254e6ea58985280c0c57150b27b01828c021329bb53ffcad78a87965c25d134ec6d5d2e6361597b2306d05f6a1a038d16d7228d811aa025de" },
                { "ast", "4082e26d136673a81f282d3f6570799e1fbdf3e7b4020097b4bb14858591205f1ad3081e5a9be6d07f7670a43216bcc6acf33bdc4e94468272837fb7a7c0685c" },
                { "be", "74d82f17b98d64b002e7a22ccce99b2b6e6a259bebaebc86a5d57e7f82baf8453e5e020687b213ab9f4fe6c9e068e692e223947ca4feb339428ed0e298a708b5" },
                { "bg", "001106159fb73fb3ded51b1f996b974977f779a37d0cd41bc3c55486b3fc06e020b81734f00c623240b2e907a3f02468fb33aaf7d55c30e52d5c0aa22b424a81" },
                { "br", "f6c073f92b8dcd941be68f9e807e51df7b97df67da01e2a8dd5eeae698ad36e4509045c317576cd7818e4ea3d602985f76fdc2b7191c2b892b34b9d87e5fe6eb" },
                { "ca", "578fb3add2b24fb3346f9f7a9f97cf9a572ce15e62521379309959ca96f2dfb8ad9a686af9940ed8e6527784568562776d55597150dbc359c6a4466251a0061d" },
                { "cak", "7eea3f2bf48d47b7f329e2fcfb07a898652b22d8a34d259162dfa8d8669558836895194b162112e450284e2bb1186a1187cf2aa62ddd660be8b7bf9c4aac7a16" },
                { "cs", "1473fe30debafeb707c014163a65757c765b3f45fd6020192da02c99c98ff66656592650c98e8fa360d11c14eaec90767ad343b0d01fd101dad1c4509722366c" },
                { "cy", "9bed84d74c7a153b9b8aeb3600e0bf753bc5e304fda0c8eb262051812ebcdeab5cc95e5458085acf5ff864ebb02ef816ff5e05692acdf059c280f9eb2e13d872" },
                { "da", "ed42761f7eb8cc467f77699e53d7ce19ffae2c2c034aa3ddb5d7e26296ccc578b3e322f2aeb3351145c7893fe7d41a504790d65fc430f9ab603ee99ba3a59a06" },
                { "de", "d35bc2b6cb527a61f11afc2bafa3eaaf0c2c102078efab7d26ccb8df45f00f477e85b9ff3a62ec99a6fd635ed2c37ed9af0749352a241179d2a5aecfab270f9c" },
                { "dsb", "149c16ef288b5e3fd7689b43b2404a6e37a81a46978dc4584a909d8490d883f35f000827c367a3df237aa7475a281ca6343632102c060e6982cb025c3f5dbfb9" },
                { "el", "992520de406c5b2a3ccc62a090cb31e6adca243d3dd5805ebdd526d3d964415dc70c90d570f3be0ba3aabb4d4a91158923c91d4632da66f181a7bdc71ab1b7b9" },
                { "en-CA", "278a06d43445949fec78b0a7554895f6604268136a742c42284c90fa9c683c10f46f0d441f70412ef404c8a97df9902343170ea6db9450687bee985059305cfc" },
                { "en-GB", "2e32e3a82819db6547db80f45c4115070b17bfd55efbfe37dc1e0844b729e0f659037f3296722dc28f1d7336b8b840bde6b0f4dc3fe555cce0bce06a536ee879" },
                { "en-US", "239cf7429a8d754633ed673eb9154500298db9dcf0c4efb9fa12fd358061d447be2142120e00c54bb8f866f8304f2d7087fb71de1325eb54fc32d754862c9d15" },
                { "es-AR", "759427d4440a94e277094a625a20e9df6f03fcf34bb0bc7e022d33fca0282a8045eee67784b3be4316f72939fffbf0ca6a674154953873328bf6f214aff21058" },
                { "es-ES", "ec85e0066ccf897c1219d3199305171e09e6aee2800f9e5d594061bccaf8de407f016120397401812675614db82ac9a4f76e647a44964fa22c47867df58da9b2" },
                { "es-MX", "eee009a2e1051ba885e149dabbe40e2a4a0af794fd7eccfc91d353f23a9765884d94d55fcfd6c125e8e3869e20f3d14d0d9880a3204a49ba5a8f7b1f0e6b40fb" },
                { "et", "71b4384b8249d3334b650549edb97f0e10ad4ae57c4453c52f47c38fed0da327a0f7a653ce4f9cb7422979a8d83844856bfc56bf2b0b494603c82129f3ab5598" },
                { "eu", "0d77c8cb15f90ce23a5755dc7aee84eacaa7e384012b6357e248a765364fc225965c51cc44d270b9f07c8e33c73ad98fb80be069a524f183b24ff3bf99945652" },
                { "fi", "e58bbc07804ad4bc02e1c050c1c4ec72c3f538024da3b35655c0c2c9515f8f625a45be7cfce6f91c05fc79bd38e0dab474f3dc54bf1f7ce53f2f65cbad62faae" },
                { "fr", "2c946b21d811009fbeed5bdd83208c8cab1df8820b6e860ef06e5598a68f5fa31ff10e529a7e2cb64dfd8278582ec88e852a8b6905b5975e29f803259f885fcb" },
                { "fy-NL", "64fc0b251b75701faec6ff1749d4aee33b56c6ea36bb1ac5298d229a8b0b0329a84db9e2d72ce3346f021af468e79c0989d569b7a347de094afdf9db8aeb4b0c" },
                { "ga-IE", "35562618205bcc4728131b78964adf4ef89ec198279fee0d5e6f56759fc41eea6b91ea2046d1221365640b21f350c4fb3b0880bf35aab89292cbe0899f32d21e" },
                { "gd", "adcbfa832e34d983d0cef4e0b195fb707ffafeac7655216397c1f617f5c76ab57e7d70902f137cdd69902d7ddfe52a87842464f263771652ce5727d1452d2011" },
                { "gl", "8141256d3b9b0f5ac507fe7c7b7f6ed611058446aba81b41f523e863e0c14f07d7d37e252ae77fb24dc12dffb7261b88058758ac062fa8db572a23eca874a2f1" },
                { "he", "2ee3772ffd9855bc51270a5fc643b0a3bd30619bbd2f305e713dc69d972ab34fcdc3d85e905304644d43ae2ae265b9fcde6c365b6c72a70c317c5171ec9f9067" },
                { "hr", "3fb6ef429aeff282b42f4493693ba72fdb9052ab64dfcad6bbacbe1fa036c82583a354a3c0e51cb9d5ebee6615a4abc0535638fb98a655421c87b613a421bb90" },
                { "hsb", "01879ee88e980f342fb52d2eb162e31436b4987d25678dea4982ab507a58bc8eea85e5b42d3d9218155677d73a3cb62aad94db3e23496cf4ffc361aede17db3d" },
                { "hu", "4f71c73b53e571e692c534475d4867de815f8ba6f9d36f6f3e67aaeaedfd0efcf1e874680bdd8ec1ddcbc7f92d295741e35fc593877861061bac36478a245320" },
                { "hy-AM", "fb29bbaa006420d51d913f7e4be79a3904852257c5427ae48487ba6c4e3f4a0a3a4963419ab3e6373ac978e0a88fd079343b23a3e6bc21d4e2ee45ac6faa4242" },
                { "id", "15659729fdfbb6182f1aa09a312845a5925344ef27f0b0809e9921d95b9cb64969104a904fd77cc97e25f1f769071a57c92fb68df895d09783c404d93ff829b2" },
                { "is", "9320cd46347c5de3c4bfbefc0bab7c189116e782c9a4e2c94ccd1705f2957b74d031ce45ef2b00a09ab4552e2f45721d01d3d06c079f55eb3a0f09891e6b9882" },
                { "it", "fed95697435a3030d13627dfe9be88582e7fea21c71aa8562f966ff2f1872e6197abffeb704be34bad324d41044c2c4215c3920de2dff6a6aeca6bbcfd402936" },
                { "ja", "4f8d4a44a723581c2c06c6193255362f8db58992c950729e706e5d2307a0accc05bd8c58ab173478b42b8eab77bf2c7fd03365881313733ba7a97de1845f08e3" },
                { "ka", "67279c36528e12cc25f926360512448b0bc9424eec7bfb904e6b184562e2e3c52ddca779cecdafbdb71e07bb74dec15ab03e8c7295f6a74679c81f6748a84484" },
                { "kab", "45dc8d41a002b21541217741676b6e5cbfe373da4172da56d32e5f72cdca0aeccc711eda11b45baf7c5e33308d259886f741d07e0a8e7ee989f667ad14e7164b" },
                { "kk", "cbcc9204e1d319f32fbc0c220699fbe9235a1f8b0f3257701b482e028409fdf7352ebe547ae5aec5cf426ee2ab81f822d8d4418f65f3bdd03c4ddf1c5dbb8d2b" },
                { "ko", "9e6c6059ca32fb8ee7578da6996cb6cbff885d8559d8458b9d9e65d53122209ef2a0d05542ef298695257c816894d286698a00e6c1812b26118607ea05d07b6d" },
                { "lt", "489c37c96ce6cee256c0268db4f2126d04944a24a79129ffdd5ea9ffdd33bfc5e4f2dfd1e2ce0071aa20159505781aa599721b6e14b55ed35015067657db1fab" },
                { "lv", "f0ae925d59b3d156221068863d941d03b18f663967e5a972eb6c76508033b30fbcda0a69cff2b6321bb4fd16e8721469d56bbaa7ec5743066426e320c5c2f04d" },
                { "ms", "a8f8444e00acaa0ddde5f6fc014db0f2cec0fbf4b0810f8e73cc4f8565a0facdfcb90593c8cd70c55d2ae0492c99d9d94d6717a12acc654955df886f5bbfae1c" },
                { "nb-NO", "fe22ec7b23bb4fd1b44a63de71c5cb8bc663541b7ac0b1d3d967a15e16a517c41752a214fed320ebc04733b2e924b782553b038cfeacbd2344fe1477c3d7dfe3" },
                { "nl", "abedc785a5a2ebe6de97a7d0358a98044caff84e16d8716257d3ac1ad4dc5e9dd4e082ca7b1bb90aa6a221d696eddc6a0430e51173e0133f8645929b9972fef1" },
                { "nn-NO", "b10ca5cdb7d3ce7b71866f532f40e0a8e72baed0ed6c032edbae4c3d9831ea5d376fe48ed199937d91807c8836eb722ea85ea8c6f80683bbb4f0164942bf215d" },
                { "pa-IN", "2207e0ca2111f487a952f77a686f347fa8716fa2d19c4a29eb95ea07d16ab2e27b8fc58abaf85110cfd71e8c2c6721fed428183eaa771c3fc2a1b95730342089" },
                { "pl", "072114019001ae6c9182c1c74f4cf2daff4e724c69b7d9587c63189547049da2df8f17b9d770f08b6fa91c8455f7074ffa028d4d436acf324dd1c2592f56f730" },
                { "pt-BR", "95b770d395b14da99088f5d33af3cfb43a46f0277775f9771fcc26667ee5bb51f224a1c00c6741d25cc58ea61f902dad779c74cb3e6701625aec38a1d402c863" },
                { "pt-PT", "aa2c0d86cd1b05ec7a6d25122b306ffe5d31267f41d51f5afe79b2818afff7094f438b66d3bd10fafcd08ed8ad39b19c00046b793604eb75839c73e6f96bbc61" },
                { "rm", "b923180064444b4c1ca4a36d4dba096634570baaa97b3a697c721f8d17a94a648eb5aca590e8ed5c3f5a3bf75a1754a13807db3a5d4e801958671b322eaa5282" },
                { "ro", "b0b595580872ea40428d1dbb424b69d4e6489931367a831651181ab99de27f1edca0bdd763b5f473a4e6acdcc2b0c5e16c73b80ad1aec21740d9b295a09558cb" },
                { "ru", "04e30c70ddb30063a7aa051496374cf301772f3a468ac0d871b88a3c74c462b304a561476ad0b6a9365c6fc340f7ca6db20991d600bceaa14e4843a76abb39e2" },
                { "sk", "fc166be4fe42a87744011d876eec9616fe24f5cf4011592c47dbc9ada66c8c8bbcf06ec9669ae2cd40862640fdfe56fcc4358511eeb6970e6038e3c77f1b087c" },
                { "sl", "60a2f8e2f7afbb48c9683fabbc2b00fff016f1fa31a8cb3d0f463b2ba2f423d0eb05976c19d8cefa7589e2b0be8deb368565b22c33d27c2625e9530cfffe9484" },
                { "sq", "088dc9e3191b33921bd90398c450db998bcd5bb401088eaf7a7659840cdd083d2d8f88e74e247cdd313d087d99ddfb672f3fe5589dc3f8f01368e6860ed4cf56" },
                { "sr", "0bd68b85a2e9c2492399a14d1decfa62997a687a41a2a0ebdafcae0c61bdb811f682b1560ee06b466c03d28c0984678c7fb01a856b81ed388b233cbef24633bb" },
                { "sv-SE", "71637bea0c79692a15e54a68128e61cc1291393506876f7744a8913f37982c09acd7aebc1a9be878c785cc1f9c79879a0ef08cc84cd1e52bd87c31533b3dc8fc" },
                { "th", "cb57361745dc5c4a6c6df2d7ed736aea34e46affb11437db5528a18d43f3358239aa168f21db24e1111dc81a78c689005447aede7002c15f807010fcdb9cc329" },
                { "tr", "723cc6ca624625c250bc41854b88b46f493293d4f9bce2577fd83163a42bbb15ce9f86d024d797f4ad21378cd2eb21b2fe25db33f237fc16580ff57185edb0a6" },
                { "uk", "e6b7d7032ba5d4b5f460cda8f64787b9f52969c1a50fdbaa08072227632d2f46d2ccd24ad5195a94818796ce50127acc59168aaa7147dfb1b4a0dfb3fb91b429" },
                { "uz", "5884818557ddae73c3da058f60b66a52db20470058e3985877254e581e367037f3baadec6e80fb1d4914940eade475bd9b3875ea9470d1d136dd94180c6e47c4" },
                { "vi", "94e24b22504d7a22bb0ce6e8ab02e1f624f8b374db01f5631bfad7cf40fbdf323c581f0975b58084d65f6b5361b5ecaa2de69b32e871ac9d07b38dc043a4004b" },
                { "zh-CN", "c7c78944bcc2d404656e990d804f6a3fe7693ed5734fd511c264f97590f5fd00cca35f9c316c4c55a9fe49759acd29d517c963cf2498d56872778bc7a8089120" },
                { "zh-TW", "36c5b3ee7a970a4d1124fab7441a0866579bf6d409a81428e1551bb8ef3cf8b1152cf57f4679dd2e94bb1278dd75199fcc0702d6f6e83cb905cf4eee95548a21" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.5.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "315b77289d57510ec1b13f977a9ea66abaeb58bf4cf497fe4e230cca6b794cc415591d54b8f7c3e043ff1b5fc168a032784999b95d608355e24bd34b4a140a34" },
                { "ar", "e6997ebfddff3ff82e7d83c195875f853a4f7ae53921b4560d8e074d81a5c040d9154fdcb4aa5d3ac2b37711cfb2e06db0cd82e1f94520144cc4f5f32e7e4869" },
                { "ast", "f1feddd8817337476fe87e53c9bce53107465f1451237cf851da7152b348bae1e597b952a55bcb655a001f2856261d7b65a50f47ef6f568ff539d00d151e383f" },
                { "be", "f73726fe2006e100fe2442fb0a557b7c473b6d72b09cf3a6505b210557cb1ca4ccc9393c3e499841947d54a47d8baaa442c1f3f9d58d6292fe3337b4d1face41" },
                { "bg", "0908974e94ba0a151a671b4a23c780b9f73e59eaac20fe36e8fe60ea1ccbbe2f5b7c42d5a9b41f12a6375cb700edbc0bdc5eba64988e0bc2e0327da6ac67d722" },
                { "br", "7e02fd437fdf07652a0c9a2eb18f914422d6fa5f263f01678684a8b1112da885881c27f5d79ac3217d8b3de5a27c731e4abf130ed5a53b69e01a60cb96518db6" },
                { "ca", "56e9ffa87f169729302154838cf2347408ed6404682c52256079fbdb5f6944cb6e21c05c0cc5e523c726dfb79f5a8d341792997fca96ebbabcbfb14f9ae4ceac" },
                { "cak", "ebfcb216a8bbb581e0bb80c8f65d46662025e0d00507727107fbaf0f0fe89e9e3c7d864b0470abd6dec0081db35fafb1f6e74cab1fbef39d21cffd440404516f" },
                { "cs", "ff45387cfbfed02482e814a634db53702f32e17c0478cc8dfa480afc113c5c8bbab3d1f5a4e6a2615733b772b5d0e1ee666b9c0b0c3e3665c0426a33fc9bd7c9" },
                { "cy", "e6621513f4791798fe2b29aecd74f85c9a9b6d4e4f338d9efec5a91a4338e2d6eaeebce1097fec0064bd9584c3b8fe8f219184e1f9ef92aba8f11109ca5c4b84" },
                { "da", "7f8eacf3f59a0af3043650e8c019b06d47f7246b1043b3dc38a752b206bc658b3543d6a2f107c9a44a54455bedab7a2b90840a4c5d966809b736c29e1401754a" },
                { "de", "5dea45b88f671efece12ab70abbe599544bcb3206fcb496c068a6fea36ca11b904900bbb9b877d73eda018acae876a18b0b4f9f6403052f4773d2fb8a2f31c03" },
                { "dsb", "3bcf3e4dffd5382f8355dff4cbc332de292e39dd9fc8f5f59359e96dc04a9905865a32007bcbfc809976521792021c4bd82bea4172ef53ec3494bdab317981fd" },
                { "el", "abda923da6605852050cb1ab2b4d617d2bd281539851be60373779a08e84d99e8db23398dd612b2e1df38f91295414ede88a509d07d4114c94fb1861176f913c" },
                { "en-CA", "fe41384c926b6463e80f527c09bc97391be26bfee0c9208036b0ae7507568ba76dfde22037a77d56ab46d62e86c874253bde072f0769b3de5a56f2dce48f1034" },
                { "en-GB", "44a481c2d38cf44c91718543ffaebc13d2c9f75327e7cc32cd3f39b98436d7bcc037a43126e3e8b1f3cd6d6ebda20304dbba7f4f319c4cca08a0c8feb900ba3d" },
                { "en-US", "603bc90be09271a90c337547a79f3ce019b27278cd02704a88fe40c60074786596566d53c170ce1ff1c90b100ea740a86e48382cfe7ec7f8b77d603a0b582228" },
                { "es-AR", "e0d06107c57770e29c88fbb8bbb6c85ed65ec705b8b544f0103d3a4191ffc292ac1c9395488de2e08af0078460e52a246057723322b716aeebb4278b06f25340" },
                { "es-ES", "43eb129355c0c141f4d454ff6a6b0416c4207f4e891e6f9a75543c6c1cba64a2c800fa73bb7c669060f2d4bf43bb02c136f995a080ef8e33a3b92007caa8f17d" },
                { "es-MX", "c0573837b6b3755ef35cd967ed5449e5aee853596f4a078c383ceabae91d8c0f2fc373191e651a5170a302f8bb7cc32907b65b3c6217b359b9ef84acb1b7a8d0" },
                { "et", "6078f4e619c20f05770aeb71c9c20477b024cb78800ae9fcc6997df2c63472566eeb271beec69cba91ad33edc86cf372aaad53ff0b95cc1cf5d878c3d53bb357" },
                { "eu", "3b5f941dd1a75336deb307e6311ed9b5852d358de14aa49061b568017008f774b84416f1364307fdc6a25b69ba9aefc079c23fb7176fa101be6788dac0ebbb8f" },
                { "fi", "318593138ea65667a44fc6bf073b2cb90da572e07c3135d0675ff7a243ddfa1ddbd8c49cbadfd5c7fa19933c8bcd88762b1ffde2792b57c3470946572f6a260f" },
                { "fr", "d52871f047a88ff0147e1e2f281a0b6af53a6103e4aaeadf209ca5afbe2043180e211bbc265628121dbfc04199f115d6341262595bcdb2dece8fc750c0cf2dd6" },
                { "fy-NL", "08aa860748c501fd7e8188099e15d699b330a6fffc152c48772f27bb1d38ea81da4f4765c32824856c3bda6e1ca322fa37ae3485ee5a16e7f53611f9ac88a49c" },
                { "ga-IE", "3c1ab2c722725a57fbc637e6dc67964489c8168512f0285b06c545af401e053628cad3a564a18a1562cae21ed932057f5a519368c5c442b5bde1c69e567153ed" },
                { "gd", "a8a1d74e66da410703ba64e959350460c703a9fdbef1d709af7e992f8780dbd45b5bf5668503cdd34497c95af30756e13e9528ac5bf91f6e5471aabfc2ca6ece" },
                { "gl", "977e94d8b2a2955dd1b763832395cdb27b2826f9017cc3dc36b87a35f5a2e39b0630623a540a6976592a705609a35d82225c96ee3b4dcb8d5ba850d705c14d7a" },
                { "he", "a44c89fcdbe2360ec06d8d0723f5fe9898b49ccfd384c33dd109f22a57d65a0cff420309f38e5d6746d6d2b22f0b93f320d16c62f9b708bbd1c206b898d40999" },
                { "hr", "04164ee4323c619ed4e08ef065d3ffa6e4c1634415adc585cead6ad28072a297b4f3c8da7f412adf5bdf307c749d3e2726a6b2315bce069fef1995dd5da39fcf" },
                { "hsb", "e08430ea2bfd6e89a70c01e71c21ea568617cb1bd950bd04204468a7d634b1270964f1d8a00ddcbf82d5ae8976558e76e80c65ad8b1799c493c8c8dcb88b47d0" },
                { "hu", "21e8c8f4426077d4d73dd6a1dfa5c0e3cba60642ef7d5dba846e2b36abb0b1a1e04156216e23717cd50a76293f7e3ad17511257a23bd89ed62d0b38c367bded5" },
                { "hy-AM", "eb3ec500d2b751c4f87314f1ec86fab3acb58809a3109255cad23d25ca3e027c8aaaa1131401be9a0d2bd67dc6e13d044c6c28f842b2b46bda3e326bae571bf2" },
                { "id", "a59985ef984b438b2d8be259570aafe0e73d22dcdb4511893bbadf7e296d3f3c032d5c9e87f5dda0cb34b2251212cda80dbf7d0c6d1a6313edb44cad968183d3" },
                { "is", "9955a69badc85d209d26c2357ad07fc86f897578ac9b2737f5ca10fba0676481a00bf63668e4ac46d2622ce74f2c153a983a203f9205cf3b3a85eaccaaff83e8" },
                { "it", "3ee26f93c3d85bebc7d3547970210c3ff3bcbf9f86e13abd9ef84f165c67a29d815564e6412780577770fe0a8b5ff8092d47398a0ed19b71ceffb0d9ebe668eb" },
                { "ja", "d96dc2d1e552d92a254ec01dc34927e14f851558bb313441f875b2f2fc781c8cd11e7bb608e24983e4ea68033771a4157dec1a165d4d2ba460be758edffa3c30" },
                { "ka", "cfbfe0c683323d40891c46514b66f84e35c5a569de8663067d2509fdffd12568a789a7c54f7e209570df9c1270cad1d4b45db6948d1db721bbead93c9bf252a7" },
                { "kab", "a06ce97915cf59027ff1f37583400549e08889e8449bc520019577525d6d6d0492d5ba8b15f776401095733ff33cca832522bb1157962f31a7c5563ac3fef019" },
                { "kk", "ece89573e28343c1e2726e41ba59a3ede0a997db72e33725ea4b055b80b530076a8563d161a8c0e3c3370a250de4203cfbc70a3e4e9f3677164ef94f37e56e8e" },
                { "ko", "ec7a677be36d16fce66fcbc5c1231b4b3fe675e0a8a581a62c1ccf9a979c156e1ba98cca7d6bd85f8119e574d67bfc953a3cf97a277d0d037c6ac48a322c2da2" },
                { "lt", "03cc1ef1931fb1d30d20af73a22c568eea2beeabf03b980f5af112e6e3e7a9e7f2adcf029ff307e0c4d4ea46b1a979218897c78f8fb6a60c5d71d91cbe0992a8" },
                { "lv", "f16e9a2a794dfbd03e7dbdb9374ec98327dbc031edc7f62e31853697c2f32944742ea79dc253155a98e7d58c2b68931f40140c3568549f835beb81aa84f0064c" },
                { "ms", "a9e54055c759f0e5fa5448e78aae063398c9988a4b41c06909b7a710e4060c2687c3bbdd230ef1da81f76fbbc8e1714ec53aababc067c25059410d58f632528d" },
                { "nb-NO", "ba4509460a8f772343244ee70c293e3c17ec067a214e59699d6431dec1b5f0a974d15fdef3fe9d7dc3a915d75603e12be6a8a9210de592bc3c481e138d88e7a5" },
                { "nl", "8f64c8ea829c1d8b3298c134e561147f3d241e34a0917701524e8fa06477d0bb5b1942908680d071f37bd04f672ccc26b34e39e16af723b7238810d40613a3bf" },
                { "nn-NO", "7185f4f8202604661616b6319059116dc5138b0af091f857ce2c3c4be331fae4bcd64dcaa58f8747b055bff013722145fa9d59ebccf325a6436d2d003304b5a3" },
                { "pa-IN", "42b80deafe9f2f9a45b94fa47414505ad9c4dad3a7bd41169ef8f90d4977db53e83bccbb9426866cf1ba1ff9ce77410e197eb80074b45fa927b06cc37795f6ff" },
                { "pl", "fb2596ee7d08cbac5c68c22b4789088d2310103ad6ecb71af9fd2b7c9a6a4eeebe9907bec5299e0772a5f2191a58332d4e2e0efad1af548af12a7039a692e9a7" },
                { "pt-BR", "9a4c506425ad6ca6aadce53d24a7565213f4b80446085c6467613b4458be455df9cd4538810a7268e9e01acd58b9f508400727c6e1af95fbb0b2b197c989230d" },
                { "pt-PT", "4e0d0dee33b457b4e83101815ce227cbd53721b5f42bc6937c1e4acc29f8871159f0de0ec18abd81ec0d49be9d0d5a13fbedf4b0958d56e2cc404bc667ab8a99" },
                { "rm", "0672607703ede73b618e67663689b1a97deca4120ed1f6c4f01ef5b250c5acb193a82912ce4f8db93d386b5d118f4987aed807d5e3b7633079a1c19b857915e7" },
                { "ro", "623e6a0f85fac1c17f173dbff60aa2219609fd9e016411bce17edceea7552bda55a3d0a47fab44cc06f8bcbfe860f409a0bbb7eb13d5e2b4dc3cfb94f9df98cd" },
                { "ru", "2bd5935fa32415976ce52a61e257e4cff9c6844af9ce0679281d87b2b047b982e42aea6c375894bdfcfde393d607743a7d47647dd665856c3f491fb1da962684" },
                { "sk", "3a34bd4cd6b6207ceaf6478854b09f44bf9dd0be70758d9e58e695818dfc2fba95b5a6776e0f22e8da3872a00cb2cfcd4d63bccd4c30cc74c13a9ab661ec17d1" },
                { "sl", "2489cca36d9ba23581743ebf8c4f0a5497e139ea9313d97a477cc07c8681745614794db6887601bd5cfb8b76be3c11089c048c23623641eb8a58bc62a7852760" },
                { "sq", "57ce45ba87e6dcb6f3809cf4047d028c09d90f64199e3d10c9aa8d6c87071ecf63431ced362a73a4a10bc7de11c815dc77c43396bef979d16f474dc8efa81800" },
                { "sr", "3d7b5564baad22f5ac3843d16ff18a65503cf628f4dd9b6d88f25b7503283597b7cfbf979b8a16d8524ec24acca60357c3f68c7a4feb1ec689216fcdcb6f5354" },
                { "sv-SE", "e0eea528ea25d8e589964e0f5f52d96df539dc1d7d51943f3e3fb4adaa18074ced937db2b61c5195a38649506b1c5a4a2afade485ede8c7a6e9779a32ac2c612" },
                { "th", "6f49204218de7fe701a449abd08c232cf3e7b81f525e01f14c3dd101d3e986206d59c18c38c711ce65c822ff35bdcc0c0286daf598c9e2790381a8f50e73e9a3" },
                { "tr", "a50eae56668b9159f46450639ef414ff99ed3479c3dabbbd8997c2149628d38321086ca47c22e549b286a133f2a92a7cdf6d4f7f69a0c031c58b69568f67621e" },
                { "uk", "041d709959dafc1dbe087211758bf3a55944c7366be471dec850b09b30b229e3f3f45a469e8cd86968b6aa8efb3fb456866f8a97c0c73c038d130c558d415be8" },
                { "uz", "bab7823ae1d121430eadc96ffe56cb0daaf4c84154698436601b92cc44099de47040910835fce263453d69e3d1374075c29ba5e50b5b4603e4dfcf9ed3dbabfa" },
                { "vi", "d7cd3700a4aab741f9ddf67c439c0428ac8bc27594002bdf8cc737a3f1dcba58df9dacd719122e34d7e1846bc5b09e657aa1fb5aecee4d1ab72fe0dda1c4fa9d" },
                { "zh-CN", "79b97b4d5309ee5fa93e9825e8e6efb229bff6e7a008eb1a150c290f88ed34d3717db8025346d2387c5b3d5d1d505f51037d4a07b453567887dc75a400e2a902" },
                { "zh-TW", "655e2ed7f100d20ad4e44110886ef0e50af1331801c5018e684f5e0192c74cfb50cb7b307b91021204b19d503ce9e77203cf4a0507a0406948abb4742a7ff53b" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                string newLocation = (response.Headers.Location?.ToString()) ?? "";
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
