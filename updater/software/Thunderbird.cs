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
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.3.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "19dd4c3320d2c9815b6e38e370d3afc30e2b0be9a900771d3415963d8a30740dd51850e2b4c5e6129ee3a2138baa4a0bf4ae309f0d09258a126a45e05c4584b6" },
                { "ar", "19ece1faa58e67e54a75235b0d0f0ef6dae797a595e342a7374b01016a4b1e7293b2fec250e8aa02e61ee5e7a5690ccf74336677766c953259ba0da6cd0807a8" },
                { "ast", "5431a09037e27c2047cd91f8466b75f6495c867f3cb153387cef6ba67e81e3e134cedf52e094ad0912ca2c23e198d8dc662b7625843fb7c5f003a4970c4b0de0" },
                { "be", "e1eca95e02ad79dbb76e45245c8d5fbd9131f0255936980e8f32ac5bac4a378d688271a4a5c7f81837ae14722b5548404455271fb2c7f811a3ec2388520897c7" },
                { "bg", "3120b3bdf151a48d177d24303679df1f5e61d5657c4501b0ead3e8418006b29119c1c8dc897c8a922c8d1e8c59c0d302e241f00e5a78436a2693e62f2f485a40" },
                { "br", "d8c6123d3f2969a4ed2fe7777470a47a5d2f3d522e110b65da0c395ce55c7cb6508ca4c122fa76953550c87e7635244eee0c5953feafc5fff900465ff5fa07a7" },
                { "ca", "ad5acba43ed0c7a8254a168dc277d387798e14e5884cf2398e2798e3172e8833560f3b3a5f34069140218ce3fc31fcecb6b771399f1e813f22eed4994353889c" },
                { "cak", "8f13963da17215bc1288207d151bcdeb8e24f73ede4fcf98514fe6cb008e2e0081bd4e4a4e64cae849e1d12a93867ae2e36f9929c4329bb2570cd4e63125fffc" },
                { "cs", "02f146ab9164a10146d1c38452831c55503d76fbced09760c29b25c65b411d61ba1cd9531a96c2be763192d589d97150bc5caf80289c33c3a3b23db86201b637" },
                { "cy", "a699f68fbe6e77531c353dcbcd29895c58108b64c7cba6b8a890e4eb1d0a5e753d9b2b363f9c5ccb031ab18ffe5067a56dacf05341fedeb9c21878be99b5f506" },
                { "da", "ab8070d01e4f9cc07d25712a742455ddb0ff446b71535b6be246bb2b65ccd76f99a708708774e7b8fece46dc9fa4a249dcbde6e565f8bbfc02535a656c0f904f" },
                { "de", "981b88e93118c02d0e24422682df29d85821138c3f63e73d588c547653dc02c9ddfc522057269fc41f4e57d2e38d28dc2407621bdc1e8e8c990bdd16ec539719" },
                { "dsb", "67979be0604cd5780c8f078486842aae6a5cdacc9c5578502fa52ecd720be790e6a13b0c8ff40b67e6a575dc835a4e36f89a0b775814b273f0b6b834c5bc8886" },
                { "el", "916228555fbe34d1e7bfd7e9d591569329fb3687c510df43008d13a8d905422cd7b8b04aee498d4808c12e41531d89a9070dda82c5ac7efd97aaa6d69de50ebf" },
                { "en-CA", "be9b247af798b537c2aed7b25f8387c99d3b05acab95961b58a1a6ec6eaf2c2dd881966a05cf75df84012a065fdb5a2eeef562c955f8a950a2dc39a5c6445248" },
                { "en-GB", "9b117d367b4afa7197c0330911e27c2b2821b20088e120b03b7ecf9c705b9c8ad53185538f4e174fce7cb163f262878ef4e71b9ba6f31b49ebc69145cf69be06" },
                { "en-US", "f0668b124b3373fa9b428b492f8094d933814a21b8eb27b436c93d5d36d4167ecc4df8f5358734eda55d9833f9f3a433909c5a2f0aeb2e4fdf2925e7f0ccc013" },
                { "es-AR", "9350750a992bcc8d16372c7c35effe49ab68bbd8f2fb5bb2681d099d9c5ef888f3a84673f25f9ee218e9f1747e8292abce78230ba7d80bf06f96be72e7a55c55" },
                { "es-ES", "926599e7677bdb45712610a6c917f517ac28bae0f650879e26301349b0c156b5376257c2b4d44febebf9d206f1c918b3ba302a5d21eebdb3356b4c3d0f6758d0" },
                { "et", "6bc03987658aef045ca6a033631e0ad75ebf4dda7835f2eeef03f2e87995407a9c84309b5c9dc771a980faf8cb14ac41ad2e9c04755a9e7b307bdac20d360dfc" },
                { "eu", "94fc02730c703885b141f5b66a1a0cba094aff70a35da0b7fdce2dd800e9a1c0a986a69b7fffa8e68db20991daa69f8605c48d2b5809e7115ca8b757be0e3c00" },
                { "fi", "db6033c5b52db67cd6565b335d54d8ccd427e94ea523ffdb897a8168c979543412a03c45c36ea8deaef7077d4d6ec122e3d62e3f74b01b42e68d25a9b7cad3b9" },
                { "fr", "8b8843c8b7991be35016b13929d26d9b63a6d604a7cebf0029471939cd39e1867a173416b5bbb226415c37d8364393eb8741be2853bc08b37a3521aea72fcea9" },
                { "fy-NL", "f67b1400a796aff56fd3afd6ec24ff6a6ba25624aed4883df7578808f62e252b6b670a2ffdc058f407260f921f0118b16b2a2e385e46de8617be48821d8051df" },
                { "ga-IE", "69d8b67305818ca9d344f6c68beecbfd7f2b3e8b3e4541d3290e0fada5b60f9a519fdfe6f605696ee6aa2fbbc49219c1bda138ce3564b2db35644f54bf2ce81d" },
                { "gd", "e7dc13b28915064756ba187b98c46514af31211a43c7d5097fdf74781e1c2ac98d3c38e5986a691825c9d5c0aa480761a7fb2fe21f84c85835d1a173b62a3ffe" },
                { "gl", "2eb1bbbeca54a54cbaad4c1e0439ebccb4771ec94335b0b41c7e1d422675807e854cced0148248c3d7a8ae451188f33a9808459165c934e3d4f4789c9afe3996" },
                { "he", "dddd69f2d39aa2b0a9844f1cd9c9fe8efeecd3eb683c22d104e750d6f86131724b76f3330da36fe924893566629042ae8bee1ec130e702291674843b3f414ed5" },
                { "hr", "d64985b852a4e46521605c33ae234a62bcae4b44f630b88ef90bb89648c745071d9466e5fbe88156d36f26d3116cfb5334780761c0dbe3ebf8591dc2c86dbc50" },
                { "hsb", "453a1c638e62a65bdafce42d97fd2b9e44b27065dedb71632212cd01fbb015e0e43c76b31d741a7d778fb27bc9f4ab0a3c3b6a5e1eeef89e9b0982c04bb76491" },
                { "hu", "c59edcc85d10bb467d00f932ff84e662d90834def8565f87d18a410de7bc6ae696df973cd8a8116a768d429a1387b5c4c2519b887cf777c1fe9d2401b6470928" },
                { "hy-AM", "006875e2e051ca0c6fc7ad0efc00ac8d7cec7dea06414a397de5949f1b4f4068f558d78de6cd69835f0c0a101f49b17a3eb098f773242fe38c583672999e4cc8" },
                { "id", "c85f009740c6fbe8f675554c7ea11b084da0291b903958de50a45ea8d52263181e4f4caa79f4e3e98418b598d9eeb8e22be5f853b125c2bd2caf93c333a19670" },
                { "is", "3f5da8304d2c76d27bc41c4f2f7111fb16f3b3b46708a9869da7a2c89dfe8eb5d707f4a55e66c8999fbb7ec2c3e5d10e049b0a42234ab8084c0f0bb7d0b0f15d" },
                { "it", "d00f30b550321b9319dd7f9d460342a3c580eb915ef889e6da8c9080f2799626fcdf9e6a3e36cf4d6391850c5c78e99d351d1b7c21cdef3bf8df16bd41185deb" },
                { "ja", "b6a7c0fb0515438a1ad4ec2fefdaf454b5e813588e475386e1b6911cfb2d61380e0105a6ab952cc33f1509d3ea3c2125d82add36a244ec1ccd0da332901a83c5" },
                { "ka", "d4c7a49fbf3875c56fccb7a1f5233198393eeaaa3dd6348b3ef118da5a5fbf44c23da5e939b4a8a67bf6846b8814487389d61ec7675afac7a32e7927a1cfb299" },
                { "kab", "54622e99897f2fd71e31570e2a95cd5919edd026926832e0a930be787a4df2057ce8f232f5a6bfce58270e540ed657dfa9d81c18b041b5bb67cb8c98cfff591e" },
                { "kk", "030d12d880e52472b1268ce86aff304ca1f10f02883874b4e82878dc18cc16f7788ef682bb8c22531581a847a5a44df4ca5c306801fa176ff53ff2858f560fca" },
                { "ko", "92a5e2ba5153843b7ff70476f8964154751bb2d8774e26814735c16a3993482d921003d723394312c0491e038c75b5ab68a66decd4322f075ee2be6fb8200f21" },
                { "lt", "1abccd0570c472a0ee8561ebdaef0c7989f3e9b47cb58d94acff4faa75b3185550434063d61a0ad0892ad3f6b2510172204cce6938c30394b736a1618af83c31" },
                { "lv", "64c9faf84ef0ec423baf22f260795477a070efe3e80b945678695b30122f8f07f7ef4c161e7816fa8b0032fd1fc7b39f5b4c647669e10d43c2156ef93512f799" },
                { "ms", "2d90d1ab6c31a67fcaffe33a8d7bf155305d776078e47f62f78c94ed8580a11e785ba6b30a43b7dd7c6ea20eb21967323178a5eeb730f2177dbc6900daf84e2a" },
                { "nb-NO", "b8e042c34fc1bd8c09673cf8b8fc704a16512d41331b4e629f24ed336081dc96fce31ac7858c721b60bb6a1f742c6ace35866c1716e9aa39d715543a31178917" },
                { "nl", "f75c6d4e464cdf24904ece13c11764b4998c6aebf4ae1d503cd259a98d03ad0f2ca858a0a6300a3d2787325d9e9510e125fd5ed6d403962d158001df065afeb5" },
                { "nn-NO", "5b579facf9f46432e8858ce929e1093007a90bcde77aee2dc131a59f1f3c4a996830cbaef7d18ccc3058d021b223959363eba8f1d0a6dc522cf93bd312adea67" },
                { "pa-IN", "fe5e7f1246d814d48a7181e0334eeb27b187f1839bf155a8711fdd890b3130c4777551b743efec5d26eff3590b1805e3f54694a071db13a012281ee3eb582e02" },
                { "pl", "172df8ab86bda06f6961960221c57634718461f73bebd7f46e27647e83fdfb77b46075fabaf5ec3c455be061ae2fb4e45ea86289d5d90799fb584e69256f0acb" },
                { "pt-BR", "ea42407baad4ccbc7d6e1a488d41e4a732a7f2a2eb12c66428a54b1ed44b7aab205ee5c87b586c650278c3617d8553e202caad37c885b9fb63b6602536739ee4" },
                { "pt-PT", "d9dc8ba31c896dc75162310cdebdffe61011a850ba1f77cb045787c3a8908e33d8df98671c312bea627108af564a38711b3488183f16e53af11aed5fb4706c09" },
                { "rm", "331bf407fbeadfac53a252723d5a433fbe417194ef0bfbcdf999b53be1bee861b8db5bdf817b1c4eaa3ee197c7b2294e7569d32b51dfd932877396bcb470ee49" },
                { "ro", "a86158d6ab389ffb5c92f3e7fddd1fbddd60795f100c9b13df9a86c024b72bc862b9216bcb3b3907ccd13c816777fe1edca09d0d97bcbacd7335081ffb008377" },
                { "ru", "188fd7c5172dbe2f3cb8984c7aa499efd076469835c694b3bf206d76c49d72c1cd30ad7eb58dbc1fda01411fc7906bd054ed6312fb0449475d446b28b019f488" },
                { "sk", "dd6941b76c70264ef801466ac02453d82d67dd5d30bfad334db3faa4c0a1b604d478b59484c4021c24fd672a885f0a0dfa016930a9d71c44c8e782f362ee82b3" },
                { "sl", "2265bc6e5df22bc2dca141bece1bce66643431885b49743514ffd0bb1f435cc5ee76b2cbbf232a02afa32f96cd920df017acdbad41506f753a95b9a22e6cc3d2" },
                { "sq", "d7add3cdf201430cb0c76b5c599fd61dfbd746216890634dd362f101b12af50444d09d8cdb850125578fb550d35d7aae38b29d307f3fa67d7a2acfb47bfaf375" },
                { "sr", "2462d6dc3b6a47170c57d5aadfe0f054596869896509e310828e3fe2919c693273d0f0bde759b442305194fa2fd90bf1d3850ee9cbbeff5feea365524925dbcc" },
                { "sv-SE", "531ead2ff68b6c7d19fa5ef20d38da9f152392c0b0493947b40b1595411ca0fa0d6976c24bce760aa2a9866fa22435899d6df34df681e5f48adaa53d9f09565c" },
                { "th", "6936a5fe3b8b7e233a03e6d29443c0b33d57f83f9a7a90151a618930103b4ca3a6a1c64702693acfc354a2a9aebf1d0a1c1e7748f00ec7ae64fe6fe30a7788f0" },
                { "tr", "37ebf4d5b50c2642044cb3975df188dcb6d2c4ed753aef83ddb68e134f613a189f5c9ef6b9139613406331567b9be13c46abd2e354717511f6f623a07f9f1278" },
                { "uk", "fcb4865f44a2b8a4ba323c893b7eced20d4ece2f8382a985ff1026caad6300b7e1052f9d8f0dc23f993c5c8cc1b1b8105a8858ec8533bd3f84b3e4c35f364dbf" },
                { "uz", "a512c7d2ee4858b22bd78e070be0d05b2e3e6541ba7fcf8023f5bfc45059d1c6259d4226a29a811f0bf8389b00e33b542b862a6312c79c6c8fc1526feffa28a1" },
                { "vi", "d0517c5f79e4d9a05951a8d0d19fc0c8f5086f6d58b3d05ec6d98be99cba428f056450d7037a118d3f9fe79ba7e816fb9b09265c04e981ed0d4f5e8c344049d2" },
                { "zh-CN", "fae2c21acb38dbcaa05f994d5581ad7a5760da861a15a44cf6478955dd65ce7a95e8f69861e136d05de195cd9ccd7badcb517d7b7dee19865a300d380f097f54" },
                { "zh-TW", "b73e316c2ad646b88b048e3c5056a9443a035d918db2bb7095baf88fbf5c9fbac4088376c9b19b175fcac5224f958f9817ecf380b2903d67e81701fc3e076739" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.3.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "f335c7b33cfeadf6f2082a1800ce8119cb6b8f07cca365670f84a53493f998e360091d3713a898025b6795b4584e7d52f512de62c60530fb0df6f7389584dc85" },
                { "ar", "c5d48eb52e5b74fd681070bb75766c7747be3ab56da8a161cd2734c1ccd93cadcbc7b4955206d4772d502da1bb317a4ce55293a1d58d714c5715dd0eeeb07085" },
                { "ast", "5c5359275e0c405e535df4582500af4298fa25c4b897b19fd8f5bce502e961b13a6a21b96c0507e9172bfb09621254abd1d90000d3091b4df28ed331e3c2dbfe" },
                { "be", "5a621ea8de93c1dfa21609dcd4abd4bad93a52331373c9bc0b75a2e160b8f3f23bc968908b9c575ce49df31fa2a9cf44683fbea58b5bd18176d764aa026862f5" },
                { "bg", "4930b2a8ed65c998e3f80e77d3fccc03e5d17d74b70975566e7d1bfa9c08862a09a9f6fbbc309006db1cb14a272a8472a1871f81d37e1665868c847bcb7bdc2c" },
                { "br", "f7e0c8087cb70eb7ab735aae19da591147c90d0c10ae5b13120eba2618e1688699ba29b77db882244c9c9f2202b25f2a6a9becaf60e8febc52805e07089d661b" },
                { "ca", "c8883adc81d89581db9af543dfc46fd04e6f4a5458d01d17054ba09a05301d19c13fcb853f18c3d5f9c6000194a159a7266365e7c7f3fee8b6b46a612aa0946f" },
                { "cak", "f897e34810c281a5591e0f8286bda23fae8e74a95fff20cfb9bab4d499bc056b2f2de4bf7e65b2ebc7121e3defe21203261a476048cc65cc6f0fbd41d6c6ec8f" },
                { "cs", "cb51cc0e70aef5d95826b1ff3e0eddfd8de1a6441a567c3ca32935ce31bc548210416b1d36fb1faa042cff9db88fd2a76def8eb959460fd5c49a7a8a39610adf" },
                { "cy", "301663ebdbe98314b847357940e48385c5b91dd262408aface043eccb1b654b4fb80210433851adf515e35e5ce69057821c754c62379266df7b35f816e35ab3d" },
                { "da", "425c46e51f65f399ea674136fcb597a036e130d90cc77e87307bee20fa0f670536e29ecc2cd26edd659121c800bbff6dc542c3e498aebc7694e2016cb75a2d8d" },
                { "de", "bf73f7d695fb1c8a71de3938731a04d6036287f91178a0d0823e13af8f29b0fc5dd8d533e99b814259284dca4e4bab7a823ca4a40f52fba8852416a4876948e1" },
                { "dsb", "c965e348cfbe60b280f7e754f097c7d4042c3e18c90b571c5d05a159b487ff7a5c9700c71f498e8f528dec42fe33944e50c2d18c2bdce17f1553dc6c127dbc85" },
                { "el", "b95e5302f49b0a45ae07d4d6a9b54f3c2f2828d0a7b24e23fa5bb49f75e3dd451780463c901b6a2636526b452be1d4878b18af729eeb5059412dcbdaae486c74" },
                { "en-CA", "2286e083ec9a47ba9c5a7c36bb6a47c7f0be1bec74c51fed117f22c25faa554e4821e01fe60273b8a5660f22b2efc296289a5b42be08b53f6726a90020fa8214" },
                { "en-GB", "368d61b7b9443a5d635ad88c0c4f473876b08b4b2e2833c5914ab07d169a35991c394fa52687806930a0ae30cb313bd9c8dacbfa18e0481909af737be1d4aeb6" },
                { "en-US", "e0ebce9e8734d9953d0ffa86c61bb57190bd5eaecb59fc7212304fa8056b3a87db8da6890fcd04554034994cf4f45c645efc14f492833d3d9428ab22f0bc6773" },
                { "es-AR", "b55582b06223e374060bf1177c2e840110b286d8000028d0640b04eebe52cc84d0d68453570406c9f274bbaceb7e9785650d564358a99900d77d5102a6feea16" },
                { "es-ES", "0b8a6f98d445e9cfcc61004d7b7732196880c96efd8ca03e6783671c23432bb485132319779620410d47782468a9d6f4252f14da26287bbadf92c5e797a9a2f0" },
                { "et", "5027d49c3999757c263a0cef7fb69b6b6ab36531934587ab67621b8f83f7fb840f0abd810f8fc11c3df01f56603aa6d8fbd90b5792fe1d0a9b3eaa1e3c28217c" },
                { "eu", "c8f48070afd461e33a56a980e4bd280b2cced96d5e998d347a829e514bf9f0c88a7081620ba08a16000dc252b4c914d79b4e5ce7b3d902354172df510c362f5d" },
                { "fi", "f45e9df1be239375fc54004a8de93ade5b52322cc9324ae6597d7fc2b1b75f6657c2c2ac25877762f7e1aa7dd67dcbfca41b613534f68e89f913f995919ec4e3" },
                { "fr", "af130f397455fc444cc8879add0273d6a13c7d15ce8693df24e0b69f4f1100e8a3287513ed9c7878b9c86ed595ba1b4f14161fea4b5041b7fe74cc8eb5b2dd18" },
                { "fy-NL", "b6c364f8012e735f6a55799e1abf78d4bf9bf545e55f4b3332e8a895455200bec988474f108aad7dd3f22f79c0414ffc10411cb08e8c4d54a573aa7c2043119f" },
                { "ga-IE", "0c8bcb418474d7860d266f236d7d3af7a67c9454217d0f75a56710af5cf4a8e87f6d3284a3c3c6b4f2a352494037d98fccc2e7c1df04b31cbffbb24c4edeb389" },
                { "gd", "f0acda56311d922f80d40dbdc13b938cf692e4cac077825f627a15e15758a1f66529c6fa9fbd649f1aaa8fe0f1e3e316f876e3734bb28cc005def4ddcec275ef" },
                { "gl", "e4f323d7035b25ae8ab11de2427abd71ff14faf4ec8c6ee0cba8f00abfe872d01d9b1e0f19bc77fd72d17671ff767e45a1633d34fa767e7a0127fc4718cf31f4" },
                { "he", "1fb70eee48f376438304ee8814531ab91e2284fd2ce42ca0481cdbd5cbfa9caec719ba14d38f6d6dbfe970fd770e449fc888b661586902232049a432d4f4f01e" },
                { "hr", "fbbd7111805e6930e1a98d354b8c9171c3355ef5b07f6e074962c0f18b1969716f4528e3e38d48c4017587a08503389011772e8848abf4a26ed91947c3e90f8d" },
                { "hsb", "a690363b83ac81aa444f400b7fb758e62e28118a1b6ec755097a1943dda72a0f8a8ade6c789c1ec875ef0b759bcfb69ae66d2674d154001f4c003097268fb8fb" },
                { "hu", "b52f429a22be3b30f7bf5c3ff4a57fc341dac8570546d623fe7e18f71f50acc1691270c4a89ff5d3a586c80b8ef8b55fdd2f7be9975fa4c322210bd449e34311" },
                { "hy-AM", "18729f6fb8a36e69df30207d86c8a3b05d64fa9eef9ae9d42e100bbceb5e9c6dd27d216e570c8735523af554e250964d32f20491342c61ea26441c8b27e3b82e" },
                { "id", "179032f6e689b5d2bf1d5f2c5ace1eb45e211bf9dbcc6d6b819d2aef24b47fdf455bfb21c67cc57aa11656535147e8bbacf4ccfaf9e507239f694faf3def414e" },
                { "is", "596c08f433504f1bf028f383c5c37684d209dc3f382e5364de62844dd98584460fcfd1e3440e72d663879f03091ec5c180292186057dd6d5000b48661d397c77" },
                { "it", "375c2fd3b13da8cdb5c40c21e7b08f7e013e8ab4fabe5bcac36fa3816bafc810a6197f98fc1f675f0923f28fa298d5d2e1575389532611d000bff50fb0b0d020" },
                { "ja", "654501e716d5a356bc7529c15c56918f78fd157887ea8c783702674191a43e3724d0de5de431d1d445b8634e6dcbfcc29fdfd1c73f4d0272a8fb3c6de4d43763" },
                { "ka", "842a9bae9b2f1b97d8256b59feda2ce0667207f2765b755758e7a935a1fe6a7f810d770cdc4549b2792a862345513fe99a0fa42d82e3b93a961794ec7ae241fc" },
                { "kab", "07e889287aee661855e6b1ef3f760891de6aa703143ef480af0eba3229a0099d16a3ac3c5616a2f998bce1b599aeb8857217d308c96a421ec703ae3700391ac3" },
                { "kk", "0fc36cee83f5fae41906c5fedd1104fcaf7efef7382c8cdcdd88ecfece39275c273ff2869019412d5601f2e34bb6cd129a21d0dfaf25f7ec27c9ed40cde489ee" },
                { "ko", "96f0052b694fe2b0c414df4ae62dd2f4de6baf6fc6e694378af314275350a6910ebe8bd79d7976520beb20e679dcea07a95e10bf7a3bd79a9fb033b48c7c6a93" },
                { "lt", "e7a4fa73ee82c3f0f88d1aad052b853b59fbfb80d9d92edc3c6cd3c01bbb591bc371576be6540d0c2e10c33e9accd8367daa335382927eb8c18eb4446aa674a6" },
                { "lv", "0b1d3bc58c0017b78c7758e631ca72e379098859e7ebd92a2010c2207c83bcb8c5561587c4862bbc8056619eae87ddcd2c2cda866fdb7a92c83ae12396cd315b" },
                { "ms", "e174f62df656f24416982fd64c73f90b3ae251d57a845350227f1639387e4737f919e8c9f975df84b7332c8c4eaedcc6ee3cf2e45f860eed1056c96a2178024b" },
                { "nb-NO", "e401dfaf471da4235f9b780ae80480c381aa3aa98532aec3f579d1652cfadb3cd3a7d77d3a819a5b76ce03ea753a56f79c352dea6140193ff74f1cf21a543a6e" },
                { "nl", "0000833e0bd8276891123061dea15956d7e04e8a120599ef6a7165a9f94567dc4776733a2290812af662930cfcce74159f7ff3cf0a8387c7dc027694d3ebeb4e" },
                { "nn-NO", "d0018f2d9fe8fb48785c4918757b4e0785369d4f44f047fa56abb4dc8f2e016b92fb218f7733b2d4ecfc99da7eebe09b4d578808d071c6ad8a5509853c62e3a6" },
                { "pa-IN", "2bd0f11cb5b3732013bf771ce5a737882a261eb451609a8054e49dd01ef129bbfd7850da4261914721210409b9e4fa409001f85a9083091bff773f193e2c21c3" },
                { "pl", "3affabdb6c974c5ecd91f3965dd84c14787020f0718ef71c44aee17ad095f3350b3c579ffeb85da6bbdfaca1de1f7cc920e2f22f165efda8f36d510b3e491527" },
                { "pt-BR", "2913dba2196846e4bd3d74e0b9ae35428204853eef7e615f4cad7d655aa3b97ac93c4847ee3e12d33e1a27385a6b1d251367cb2aedc7d80d76222198030e3cbc" },
                { "pt-PT", "a4c68e300545c4e65784ceeb4a475b56be7ae49e3187963a9358820674440d815d3fc65e28767f921566d6bbbeb95a3d5d43fbf4552250454ab5f9fbc47fd585" },
                { "rm", "b11e5dd6cde0081e72fb42bacad1595df7d90f68b2f16d1dc7746be23a31dae23969c8a17110a91bca9cc5f67e983c5ad85368c4ff5d0f3f5932dc55de3f7c4c" },
                { "ro", "f2ecd6f845dac7a5bc21323329f1beb9607ae9b14edff946103f5d81316201fce41bbca405f8a34943072dda2f54dbf8a967727859d3b3c66782b5724d641704" },
                { "ru", "4db1f199a77c15e6ab2fa926560270a5b2c18559d4e1f111717c5ca05b08a2170a625b31971830cd2c2ba60658fa04347d869c2387a79d66f2cd3c7086c507a5" },
                { "sk", "61823ee43fe809f51e9210d5a4b6bd9029e360bae288ac8315cdaff123872e0a8dd38f9e646efdac620ddb6285dfcf52d0b953d0dadeca425f5705c297fcd2b7" },
                { "sl", "fc92f8687fe5eb142b6037290cf53be8f2b13b53df0190c740644952cd2e71ac7c68c4a776d51b82477714556505621c60ba29b5686804ae8d5d5a1d3600e092" },
                { "sq", "fd6f172ca0a539cd2a8dae4239a188eac75c969de42b4afaa2542521f324a31f0ec0bf813ec3401a099fe56450156cb67585e9c60772812867b26c48af18d787" },
                { "sr", "50cdc8230bcc47214e70a372f08f0624a9ad227dc3e9cbdf86fb0c5d07cdb23a6989003bf69b9ea04eb66e0fba593fa084a0a6ef4fd71fa5d3e167be781f58e9" },
                { "sv-SE", "1992e11b24e1f47ea5aca1411e0969428e3f62248570084330f3473a3231d172370f33c9542d22fa726451debbdb4a57253c2968bc1f30486501ac823c73c218" },
                { "th", "b0d0d48f4fd4b5e2ea1570c34a5fcd0dba87298a2be689b19593e5d881fce1456c91da46ac4334badc17806988f7ca5d15a80582dc3fbd9cb59db7a3944fc141" },
                { "tr", "085adf1966010d557aaa1976c000db5d68b4121b46834821b3934faf3d35eeb5bf37381cc063fe05fe95adbc9876ebaac0bca6c83e2801cb605a4380e79c2f14" },
                { "uk", "c8242da5bbcec7d298be226c8bcd9862bbb00003eb60b7f34f3a8175447b05d7ab36657ff4444ed644524a0db26d107fe64f8f2574191db280dd8c59ad46a009" },
                { "uz", "be7b5f20210d48f3e9988ad60ec64786ca3fd10c806eccf781f952ccdab523fc3a01d3a03489fffcea9862c89c5f6e99743dda8b220e62821ff22e86bdadc9d2" },
                { "vi", "bf78f1fa8aadb28895cf7a86bf71ca161d94199ba3ae8317dd4d3f9dda0a7125569dfd15d17a8d75805802cca3001535c958395fba0868f0212f0c78c49d322f" },
                { "zh-CN", "b873699e5c93d4fed6573f5b16db943bea1524d53beb721dafcc37a0f1bf0f53adb374807bfd46a47e27f46220efce5826d1783f0a462302c762b8febe9dea43" },
                { "zh-TW", "901573daf98cc643b9d50a0a35a8e87c97343db09599145ede57bd17f6c49cee1874cf40a2e648b4c1e4bf3176e628add4f9baacca75cd547d74ab6526ad55d2" }
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
            const string version = "91.3.0";
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
