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
        private const string currentVersion = "154.0b1";


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
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4dd0afc16b31f24103c91cc721604188bcbb85192cb3b5a897f6884cd3734b471a19ccbe0e1bf90de72464e2cf3af4818530b72f48bda12cc15ddd8e33e8527b" },
                { "af", "0273e0a89806cfb65472db6514002a896cd032d626b40a493e29b0f2440e493879614ba80ddecbe6be0533b37e797a83a44c9fc3cf5a3dd51f83fc687a74ce8d" },
                { "an", "49f5dceaf8d88013aef48fecb90b183bac6ab8ec7e25661123a12d30184397ad38c6e23fa901875bfb21f7c7c17d0ca4d595408cf5a9f1dc5c3d600c03900f34" },
                { "ar", "54c1a42c614ab62d07d23df994c1a4d9f6cd6cf8f9d72583aa1945504cbec87c40f8065f90a75d81af375daa12c9e673f239244912e5ba85425a87000aa12177" },
                { "ast", "bb7ee65df2a5f10d7ce113d2346ddf81cb5d171fb8176d0f34441762dbe433e1993c43f220cbbd365774ac6e914a9f47fe2451998268ebdd8bd3beab02c329e6" },
                { "az", "2344a7b510b3202b44e8f92f05179f8d09063b3f4814775ee679b4e1e23f150097144b488d0618a59f1161a3588f5450a3cf87b03edc03a33d2903bca99c5d63" },
                { "be", "c6ad30c1840fd5efd26e715ab2e87373176ed9351ce0ec6059fc7d1d37134ffb01b610b9d6f07113a24be2b9b8d5ddfc3f223905fc7da3dcca771a3814160f61" },
                { "bg", "034f2a00416adebf0e8039879594eb749a4a267b6da48740d787023215993d611965229479d7c684709ea0ae3ba8d1bc3403b1025094a97a8442e38c85380b4a" },
                { "bn", "5055115b0337cb5d39d477077bad50d8c68c39a19a140e9c0a4ee190832936cca6d201d64176fe9d6979b01f90fe6ba70a6cba1f10c2abc46f88a3e84364b258" },
                { "br", "24d6c9346f2c3da23e35fdf0c44739d79dd3279a0f328240b49a246a4bd403241e03e4f27997b37605904d779efc61284c9ae7458a86a0215c37931264dba1af" },
                { "bs", "816f7cccbbde32439162431ed4a0480ab3fc697d1ff579559bfb90e1d3a9de34357d9dd2dd11ebaf9ebce102e2dc3e32a3a43b5647dbabe64804c03db71b4b23" },
                { "ca", "9fd130071ec4d047c1c7d8988f67e844db8d0204b84830a3d9afdac4b6f8395236724cb4c50cc8af057dba3ec868c5fbc2732f1a4afdb504f2f7edf3f72f15cf" },
                { "cak", "76adc292fbf594e2024081998cc50abb7574cd37d1696841ec96c8a9d29a7e024d3c1e907c244bbc0b9c5a7765462f8236d0b72b1fe1d99652b4d964e8c09587" },
                { "cs", "5114d1dce6ba217bc9cfbe940b8965058a7cada73c81fbf24bed8f2e352d5342918e4f401ce356649cee88b8eeb04a0ce3bc2685542ac2aaf7dfa5b2c20898df" },
                { "cy", "522fd482745a5181a81fdcaebf1ee232a04a8980f329b2ebda6728736dbf486bd438ea26056eb686a60b37f10818b7de783b31d6bbd0490c99e06646fb5b6d57" },
                { "da", "15d9f4665743b3c14d19a66ab6342383ba2a3d7dfc630788ebd0b21c6849bac5ec1f1de2dc519dd847f58bf63e44f838ace36be375b5f4bf1cff8c88da5349ae" },
                { "de", "ab2a070d2364dece6e06a8cee5e01cc551fafc8ee092d4646408e06ca00bd7dfa7c6cfe0875487257127e831b253a5550a58063b7cad1cb91a30868d6f25652e" },
                { "dsb", "963f1d9ac3fb52e3c97ef9ec89bc4ffde01322a23545b1d2f7a08361d2ce5099f05089b617885f3199ce43698f42bf8cf0b2cdf9c1a474365cf3810bc298ed98" },
                { "el", "649bd0c296d6939dfc5fcc2c87353ed21fdefb23d382267b1e07c14cff37e21654f12bee294e620ed13eb8946f1ca29c71bb4f1d2594ce4f6356c23e0ebda6ca" },
                { "en-CA", "5ed57f26b5541ac9ae45679856be3dbf65a315e13ea75945d7460da39558e064dce4cdbdfdcc02c19cd51d01bd6ef3e231ebf2a29d2de2c2d67c00d958ba5bb6" },
                { "en-GB", "4ac4e4af91829e0390e583fb83a724163d49417a769147ae9c167961a5af08c1e8c8517a79efa5145be93f44413b064279792ce0947215221c77f0f1cc2ace67" },
                { "en-US", "e247cd15f3383177a1ed774e9a18e525906d95cff5f800f0919d6afbcecb25db78b0b7ff8f388d291aa8618c2bc5a81df1f8f3c485982a4c6b0b150558ae81aa" },
                { "eo", "d760ab8be479226de78b77d01730243272af81fa3886bdc9937c183d91054449bf8724a6672d3c58d59db51643e8af38f32509e22b2c6b4184253044952d5a2c" },
                { "es-AR", "a20693cb01e422e567f2dcf16d8489bd56e7ef634e597f4b5afa25734013d7c636294f79fd135406575c4cf59cba76ba0d05af7cb1b7d56c9bd287ad53ce28c5" },
                { "es-CL", "41db23066c5277a77e7ba7c0a5391706f232e26f9b740d421d408750aea9b27b0ef7b02b6d7d1c721c6aaf50953e60bbbad646f6cf5e9ea0984e8a15ef3dfff8" },
                { "es-ES", "8f01e5bf367c6c82704022d2079758630495f1cd1f4b01c84c506b8a1a4d3ddeb9d7fa83b7f51cf3e7531dd24008c6ced653b3f93e16d4b155e2955de788eae4" },
                { "es-MX", "2b5e7f84af36b206bb39fd99fa20294c7bc61e70209090905c4b9dbcd75973e7e910e44233e8b9522608747e8f356f50b01fea0b93212e655254d4eae054a8bb" },
                { "et", "5221cc999b5d859bb7744f1b8f5750cb83e93492888e620ad80d14564eb9870a995506d3337b092c0fe476011d2e731683db2213488e9d69b8bded14b95eb205" },
                { "eu", "95c1df80da2bf2a2ac17e0265d81f4e5f272ca4cee1673f2df5f72e2e3bf3cc25e9cf83461cefee93c704a0708885d4a20c0f11609af060ef0a503266b276090" },
                { "fa", "873431dde8560f5c143248c4181cbcc44561268cd2b08cf921cb3596f4b2e87160b3e5db126678b2793fc3994f2c9a536b69b92b7922575946e3760f6db8d387" },
                { "ff", "6be88cb371550153f324f7e83422b98379506ec27d765034bb4ac81a7a5e14aefe1885ec78458a3e4377b03f2d157f05474155df37742742095769d90f089c3f" },
                { "fi", "06a435c31d6fb65125a192d641b7e4d0c34e740f8babaf4a1023d313681e17660ad0d8e9c0a0108c8e64b54f66e7ab65b40ded861f3307fe8d600c8580b93d71" },
                { "fr", "b40e1ae58f891311df3ce5831e6995ba49b93ccc5a857c12d6da1033a896eadcea1bf9b0549e2103ad77797ebb325d87a375880c5d53c82bde3251ddabf4a435" },
                { "fur", "42ccd97f6a7af8870a6b10fec1443c22e864a9669a360c8e23dbbac70f287644e02024385939ef06a32b6d260827871b1061b8884af3259bcb7711308550229c" },
                { "fy-NL", "2503973bdc8117b14ede9f0b3888b2494099cb8c7869267038b5320be58080a7a88ca0cd3774580904d81f888dd2a017fe303d5bdbab135f25706ab86f013dab" },
                { "ga-IE", "b8b9a9073349d3a4b1a2fec5d25a44b0eb9e3e0142a0fbe6f59e95e51cefab3c93802b424c2047ef3b8879108dbe1743e02f4418c3da8f47b28ef86e6a9e64cf" },
                { "gd", "f124e1ab7d7110ef0ec4383be1f24fdf63d55d37e4c219502069e28544b6360192d46e8b0e59cac044cfa5560af9af2aed938d4431841b6fa5625219428127f2" },
                { "gl", "dd4697a051518c13168adf9e64f21106dd9ed8b8fe25be2e10ad6bee020d21b21556653d205456123440ffc2e2aee651330ec0b6407a672155696370cb01cfd5" },
                { "gn", "63c5bc02d323292f01c178fbdaa66becb6467c11258e62672588e8129a9c3d652dc82ee85f8fe7b71bd7eba80dbbfdf97b8e70c956bc24a0ebca18dd89605a79" },
                { "gu-IN", "6d679c0d9624aa8c962342d678fc5d66365cafe197de15c9f5ad62d181326ed9b4ee1805da4c16ed7ee9525b1f50da9863fe0e7e6bbbe5942a11a4dee56feab8" },
                { "he", "879c0d28f67d8a5ed4ed025223e1c8584e59188dfa8e43cfd188b59e916a20f56c00558fbef06752c6e4c973165dd4039fc73533eb88fe05517eb981dcc3ab9f" },
                { "hi-IN", "c2e5a9de0fdbe358d3206dd002f1920d561e1e6d25870bc03be0701acc7cf270a31518526c16d197d533bb9da97f2c63d5b6bb20bd37dd91f54a745f0beab416" },
                { "hr", "d53c216754f4c2112915422f87dc339054848947dc5ae8554d31fd894ea83bb5f03a2a804dcdb9f1b5e488847834715714aa6d5325a69bccd03867b6a5608d1d" },
                { "hsb", "e925bda779f5771e6c5cdfa67124755e84a33b2f05afdde85530cd3f48eead9a8298c21d36b6927d6330e41aa834651d248dfa01ba7b783ef93001c4389f6f43" },
                { "hu", "e03c55595f6d40409cca2866644aa88bdc88186942b41bee8dc63fbf1ce998f291bb9e35bed7f8354c067c2469b05e31ec8867b2f36b420476bd451cf39873a7" },
                { "hy-AM", "be019f1c4ff5470c66199c8fc6bd9ec68a3d4d14228bcca32f867a089eb6deaf633d91a37405c1e1ca20f37d9ceffa19c0029a30d863bcb42caf6eb420b8cc7e" },
                { "ia", "8907425d78a62a3fd9dd52eade5521d3a217d9bd2e9f353c7624348f772acb1cf215a37ee778bae1488e6ac6601e011fa8a76adf1a93e32efc0ec2d9a921e969" },
                { "id", "3c9ad4fdd8306c3e258a9c5f6fd53fdc907157c13f99933a0756f4046720966177425ad8169c53d00e55efb84b50a391fd88a3fb1d5c936d6a71cd25caaf8cee" },
                { "is", "c8fe56ef40c5756f16b0e475ead7be4a2210934275339e968eefd0adb032350385420664f4102067cc46947d4dbd3a8b24fa23e506ec42306fdd2903dc6da01f" },
                { "it", "becbd06f53128612d9f544aac8238f7542165754672320a19d9b25eb90b03a54e1afba24dd17dfcc9eeb4141c485879a77c05935be6ff6c370884f7b74b1f8c7" },
                { "ja", "d9e0047aad70daaaebd7d01aa65e52d7e43008c41f4143a837320ec47e240010bf546e91cb403b06ae2aba8e5cbaaea92adc50e363941bc0c8a5b50b0e8a1dd5" },
                { "ka", "ca476c4b40293de69dc7323ebef3dae171793defde0d385b67ee33e56c89f57a37d0b02357c948af378b2d59098b64cfa26009cdb74e7c6d40b44f7240ec42e7" },
                { "kab", "2984dcb4dfafc59ea98c2677151a2350dc6638a4b2855dc2f54113e076a5c44a30a80828383c701610f256cf286ce2ff98f261dda7cf3318f19744d1d503a7c2" },
                { "kk", "5f2fba007ac1efc2872faf5a0f09771eb39be60ee43d06003cad0f8438316ae937f8f9de12bfcd3af5d230114e6406b3740dba5a34ec4b6a44254453861708cd" },
                { "km", "8350fc1364dfcd142a98f545b97e43bcc08850d739d3d50b796b254056aca9d41585961f0f6ddc49c3b5de4a38dcbdefc09c6d9bb8dea3d5d4463e6886283065" },
                { "kn", "f338704a7b83dd7db35c78f440f42aa6397a5b33118737fb405c43b81df1b8d79cac7d3c57482106a46ec7294295e90898f711e6d5e9572094ed2216990eba40" },
                { "ko", "3a5f04b3fbeeeb7e4f0b32c6eabcb30878cf02e4ed58bb7ad2f9fa40725378daae057c3fc2ea0f6d2aa1396aa97715e08281278951f577654d7719f42734f793" },
                { "lij", "2f5c850fb61b421043606fa558a5746b8bd5c2011fbb05cca088631e9717b7e217c02fec585a4ce4ae3fa13c72dfe3fe0556824a1eebe15c8aa73b84632fec94" },
                { "lt", "b9ca780d6dcded4cf02680e3a564e510864866606e447add6bb9deadc8850dc9c2396053b2fd57a9527a11fe19bf7c4bb48f8f2052d9ba695476a7ecbf0c436b" },
                { "lv", "60b5c8f0de5b398fc32ebbf60c5269b9818f8b104d4f986347251105ca4fe8e25e022dd4432c98e6207d9e0ada07b92ea95a258c42f72d0ed19b3d324c9cb96e" },
                { "mk", "5c7be97d91014d250e8a7258728887c0cd5ba1f9ec40b84c731e8fb24c7a8aafeb73f1de7d2b0f4263e7be2c72f66b8496f08ab88b78d842e7234fb84fa143d4" },
                { "mr", "3e763ad46367c21261b5706ba04c3d71652deaa1b013ded0ede7829703cf6d7af49f1bb6f0004ed8ba75992f3608f12ae48c85e95acf1a4286e0b80e36bcd674" },
                { "ms", "0069b8600f4175793250a57186e2ec3433362f25101b31df6781847896ee8450a2a5c5dcaf35a567dada0a5ea23ebe0a080de4207c2fa387ed59bad735b1cd84" },
                { "my", "39787f8972edab19fac45f280bcf34631215369330fc20399c9249f2055770cb6e0be3ae756b116f3b8373ad1ca8e41a73daf572c8ce21ebd5ce4f63674d16e0" },
                { "nb-NO", "c8874ca6eb2286cbe6767983d7f3a1f582dd772b2a7c84627e3313b75bc385c0b9940aa690d44091bc9ef42f9ce759f878b015836bbde8e4738e5b5a4f5c93ef" },
                { "ne-NP", "1a624830041b7b1def96c767380bdd9eef59eb83a20686a14ec190c172b0b62a08979d376f21db75888cb5956f2c545b2b83925919355e63ac13d22d7fb6ddbc" },
                { "nl", "930220fdee72e02abc74d2f8b8657aa6b6c59fb2b5a8f00b09544175652b697ec5226e036071e754264b847e71d194e7c74e23ce84d552277ea4a248105e2918" },
                { "nn-NO", "f0ac674d3669fc11a96987d326103595f120691ceff0a3535e30ca7a89ca541ca76168693b41d420054b777f604ae1447177132a890b1f3257d57dbd28a82b71" },
                { "oc", "0076255f0eb39ea191795d198e5f15d49e8ea7c8bd96d099a9eeacc5fe35ef9b97cd09ef8a6e1cb98734d1472ce7d31c5063b69d8a2a2fb705ac36db821d4923" },
                { "pa-IN", "469db36e7fb532925866e2f5386268273db8f20c4aa0edbe62841373d6d49810eec9ac35eb8c1cfd5743ff14d1493436ac98d50370dd32a73b0745281ac0dd56" },
                { "pl", "8cb69c0e89861e84be125b3cf971d5fd2c006d5979796bc594d377259b060d53e0dce1444cd7f0280839271cfffca4e18c773fd0221f683fa51869f2af31a718" },
                { "pt-BR", "0c8284b78480590f94431c6760aac8cc03ff8e8e07136620ff7ad7aa030781e8039d3400c6444465d705f399dd8e8b712344583e03336abfe44f7feb3628bf74" },
                { "pt-PT", "7b486ba496b9122394314545083dca0799c733ccdb27637850e05ab787eccc115afac3f095dd876c8a6b621b3d4b6051985d86b4ef5a619a2cb63bd698a88461" },
                { "rm", "e10caf4f2fffa9a4827b84b9bbaefb758adcb210c8b684359e0b48f3a1f5f56465555fc459bc872ed4cea093aa65765caa9f45c0443705f94d96925f9da7f221" },
                { "ro", "feb64278b728022c4a9f23e5aa18cc67facee0ec27b592b8e400d21eb2061d0cc63b8b81404ceac4c4b427230f21600a853d5ba3056f71f69ababb1b53dbcc14" },
                { "ru", "8e49a03f7e965521243dbbb676617eb599794fc77da95cbfc48d0c49af1c2f354f13a1f5b3b70a9edbed5c1b20a997ddf02fe2aedb0bbd92f5f91ef084501361" },
                { "sat", "2dc9fe6df3d9c46c314d37de481258bc298ada77da5e6680a9d3135db7be965908589b81f0651489725305b1cd56c2693c5a96d3097a5a5c392074b7f3854d47" },
                { "sc", "2e06b8e4adf7c0a5c45994f372abcd7d177ee55a847c06af851531b7ec8029d1c8f26b9144d8b41896667c80d6503cc06057b6d4172ff9b1ea46af7089a2fedf" },
                { "sco", "aef54fa1cfdc618b418922df4b00c0ceb7392f26f3cd99e5337e22f84eb0585f40c06e92f5da7ece3afff22033871c01214a4bd3a5efde3cbe1d1b88cc74ecd7" },
                { "si", "db653f7870f72a0aa469f707911bb45770632454530db5c5faffb645d03512026ba8388603eeb9782f6f28f83e1dc59162e8bed92c3a61af8c2ecc9a97656f28" },
                { "sk", "2df5b4395d4972232cd0598b474644055fb7c9ca2a939c2af1403fa6f9e597fe11f24164ddc45d70adc8be22bc55045c5cf8baf1e74874dd55f20eb33a3dfd6b" },
                { "skr", "cfbad78e3f01c812a9a3360838a538ff841992a23ff64127d8ced569ae5f6376910d9fbbc64655f2c3ee7b2d9d72c65bf7d302f95fefe65d2b0d40375b525016" },
                { "sl", "524b414ccab0aac77e25813e555fc98fb52087f54a849e9503e5739bc29106a21bcfe126033d323ffa32d7b2612506017e9e36e8a205942e6206058b46d1b4a7" },
                { "son", "60fa4e16c70b249977b0f570c375249da80235b38c3b4cf48b8f07e9904d1997f33c8ff3af3e51faa59e291a82650dfaaa893b79ec0a5b447aa3d45da340a097" },
                { "sq", "84c1cb5abef8f29929c7055828a409626178f3a856a60d2d819e454bb41ec38b39c82d7c02f032ca621dc48417bee34265e6ee8cb452a5059d26c335fb15a0aa" },
                { "sr", "f189a72dab9088c12f9f7a30e5c86fb315fc90a187cdf3cc04b4470f01f125492e69188086de35d993ed25e0160e4c90c17b15659752a54c0142f9d23d2664e9" },
                { "sv-SE", "396696b14cad067712eff5ed32f1ad01e10659fbd2252ea045a4beea7a8b907d4e6469c715f3ce7756b3e5c8709e00cc8390f58b62510dc088c33f5721e350ed" },
                { "szl", "e9c59e21482dc5c5a0a4fd17867fb9b80332d17767a94fe2cf7add816d524280840944edaff66995c2b6899a439a846630b59f6a16a2ac26bf8591f1765eea19" },
                { "ta", "e70d9f2bf0628393a38f35b54e218c3ce9562728881b7c110ee5ccebde3df9802729d89e020aa1ff3cdc8180b10b0a14d1aeabe48acbd75e9610f77efa02a42f" },
                { "te", "64043d9c2f80376ee994b3f721da9ac1086d380ff2338f3b447fafc99ab1e988facc7593f5994ebfb9420a204a5bb4af6ca10bc0258d90f1ce4e201aa59a1604" },
                { "tg", "2ee4307b9f61b0e9c0ed062b9b1b5cebd27168e5c9991fa3f8bd5dca001b8d13adb508d9564c48789e32b0cbdd1770cf79d94077f57865196615345aa9fe3929" },
                { "th", "2f73babbe46b7e2c03b88bbee0a2666d4de81df7a86c21a55fede56207251a5cbced053d28c67f0a62a8480dc4db2e882c35ae1b841e7513d21a9831165c8325" },
                { "tl", "957c30401be5f94e95b7828b8b7979f59ce7d061bd16c7f1e764bd8d1ed59d4bd130efc1cacd3749cbdf71343b2e653ebf7d1a808364afb6b40eb7fcad004edb" },
                { "tr", "203958965a50516c7362a4d5a9911693b7586595d4e1d854b6f73dfd980697f7db608d8abecabaabe23b6721d8ffe9b0c980d16337d498f33e3775d9086e3654" },
                { "trs", "fe0649596fe29161a79b7539a87731c79412e830b7f50fa45f4aff563abe9f42706ce4ead4ceecc3f827f9d8389519a49204a8509ff64c366956ded045c4558d" },
                { "uk", "9b60bfc6db98db4617b125e92e015ed122269a0689e56f171e66f98272ee6ec3f126f5a0a386beec2b5ebc37dd78c0fa5f298a897d0767fa1f1b5dfc02574ef2" },
                { "ur", "f340ae8fb61fed5df3166470c56ebcc79f8f696a7b27043bad5fad1e51fbcdae18d5cec30539c375d396c5d268bb6d94e1aea64a1bc427935b909d7f0b27179f" },
                { "uz", "27d3203ce42beb0e88d361e2f17258c0bd8573bbdf4e2c40226ea8217a281ff88f3b15c01e27a55b30f0d889ac23d135e29f8f96d404c7c43942a1463020f442" },
                { "vi", "3e272028670f4c4a7b767d8619b7af29ee2c73424805efc11c9f50078ee34aa4b9e7344f293575c9950fe564596e2c5c1202b0c7c9f6fe65373b57db1a4ee58b" },
                { "xh", "ad0bd700946b51d00f307c3a79bca31da35919470fc69604898cafd0e6ece7fb028bec12f88b815443fbca726c5385b57bc70b591bf1306551bc5c023bcd49cf" },
                { "zh-CN", "a6741ec4c845a5094e2f82b2438a1a6bfcd21c9fd489fa0f9ab027ae99939e2c54ceb22b5cdcabd70ac238d9c2fcea4206539c7c3e8bc5c188b6c27c01b5b84c" },
                { "zh-TW", "dc0eee3ccaf149f9066c47e9879c59ec4c42ec21b683b8e60e174123e92005b075a5ef5b6349b23a5ec427df1ccafa4e470560063a974510fd3bb65b76af5253" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "461cf403f3e4f6f7335ef477ab5d72eb40e6a3f13c705e9599ea0850ddaf9572944427794c839877b18a602d5c995409d3061c8f3f636dac5367732aa04c0fca" },
                { "af", "c41c81faad0559f09b5bedfd64f3fdc9f7f423b01b1349ae3132d11d1b9609acaf6330a4f3adc19218499ea85a6e581da000cfb2755cfc0b1c75011b171d67aa" },
                { "an", "314fdcc78b1bb229df016af2bd8c73c59387ae6a2df81093dcbc4263fd8f1ec8243c0f394764b5a5079427bc8c43ab965eebce8b57c2b595c21043d50560e7e1" },
                { "ar", "33367e1bd2f686ec06684a9aab12a6b05c676b7455c39f44be4e4016b25399e6aa91472e17916662359ed511c7206f11e2e5a3c1c389f3b960a6b334d25f6b16" },
                { "ast", "3552a6027fa90520d730bd439a435cf5457ded7b6d2ede16b4bc31caa510ce9d4c18e1108b4950f57c3a37795565170486ed7319a63bce9af95f7863d87ef286" },
                { "az", "bb36ea64c1d198ae041bfce4bd378cca84d8547b0ad425d30a4cc76de1177868bef683974f3dfe9ee1145dcc552cdd7a6873f6214dd8a0be5988ba9921b6e8f8" },
                { "be", "f979dc1869025545b5988c63973e651953f5c9fe179c59eeccb64572776afa4323cfff69f1b18e714d28d5839165f0c865149bc199237de957091f41ded96150" },
                { "bg", "bb8c7af3b969e399d127009b856e489c889adac70ce880c6a98767dcac5d707243d602cab2161736a70f5d73952d6edbfa556437fc10f2aa5696deec08b6f35d" },
                { "bn", "3e54454a95949a61630392c6c452af1f7703a1dea06196a700c1d279fffcb22f99333d8e27781848f4ce71cb1029ac489914aa866b279bbd03740daa28df19f5" },
                { "br", "ce8431e9ce00dd8ca7bf48f70148d23394b84f4004f5cd1ea5e1c7499b83ea39c87b30595479f053174b8b4a79f09ee2d004e9d4545974b65a68263825c4f977" },
                { "bs", "1f012155cd7110760031b66b5a0798273868efd5f28471bc8206e22c1bdf0faa170c4d88317cf22f61dbfa8562dae05f590db9a041e3661263f0b3217984ccca" },
                { "ca", "fb8d18eaea935aa242354cdd2a22ae9066e7cdd5e714de4275a134c6f56f78209f9768865a932b2ddae8d85cc8698b638896122a5ff0738e2d260776648e68a5" },
                { "cak", "0b590e806372b2ba65554b5bd153283e4879f6542c1c9e8e5f0ab0f269a6b326b1f8e9fd27d3d2c474a2ec36e041e57b4cf0f24500bfa4792f04c757a7305937" },
                { "cs", "35659c1d3578e3d7d61dac10870ac759cda4ffa22c1af17cc3bddeb03204fba60b260890fa0ffb2c67ad3e2ff70bb4f76b20b2128bf732ce87a7d90428dee5ec" },
                { "cy", "d46cab17094ee30e1065d6fe7e279f0f7b15bbf7b6432ba103355ab99e1d982366e1dbb7c5f478149b0feba46f6c42bdf3e7aee5409723f3142a78192a8f55d0" },
                { "da", "034bd4e9bc54297ff2e3da0f3025cda0636b411d60459ff47a3599f2d30a7e59163b916e9c20c4bf462bf75b30f6e69b961213efe61bcb822e748f9dd7c5b646" },
                { "de", "7a683fc9c42ddec1d8c18a5012284b1c9adc9bcb1eba212f045ae0dd66f4af2e83a55af186101109c9f558760294a24e784526842de26edbe0b5f1e7d8303c04" },
                { "dsb", "18c934f259e2b0d678c6d0e7d6857424ebd8e6810dc6acac47916b9ad269ddaf687102203575ff7384cd64d4cede76a7b1a6191abc8b3b26a93919e54a9b32e7" },
                { "el", "be004f8bf5513b606460cdaba2adc727531853002955e97379f20153a281e62c7c7d3cfa14e29ab85c3a21e861bbd35226f862ff4f459b91563fcb965a371611" },
                { "en-CA", "ec61b7e90d327450bd9e9303bfa6b8de77036537915663961682bf7e828db722652cf30f0445f6f1067a9f6d6b415b6bbc5178af1da2b4a794a1a6291a23d915" },
                { "en-GB", "fe3cab0835d61d87805b5ca2d33c66834a4a5d082758ec899fe14f143ce2e312d5519f9ecfb2b8114dc43d169aaa2e353d5393fffa9f06126af8138d3d5cf0fe" },
                { "en-US", "88e79a4e8ecb0ce96a905c5d9d064b89ef90aab642a22527adf2df740e349b49cf431ae63cf4914fb45c609c52ee7ccd12499958ce34d98afaecf5e5f4c7311e" },
                { "eo", "30d3652b34883c7279b1164377e84be6d9de1e4f90bffd32150afcb6ceff4bdf1f26441d69fb437c27e8e3c5ea082913f6d97d1b07fd0310fdc80a1510f01b3a" },
                { "es-AR", "50f734b73589f744c6fd3ad1fe90befdba20c91b96231c572db1ddba75693b9525e56334c3df3c15ec52cf8b955773683e22b03ae6f6fa77d1ac8907a03d600b" },
                { "es-CL", "bbea2fede686461ca71afbdd895cd8284e5594498f20113efe6b3d98ba243123d7cdc330e7b90336a6d3bee7294ddc3e0fbd2a70726ec0ec495222ec74c4eaff" },
                { "es-ES", "33a18f5412a2bb3579ea29cd3d097ea2b8b42d80106d4641feb751788a36262a8594ba7ed4539c7bfcb1a776119af33e9064c7b0c0590b6eb82b671289650223" },
                { "es-MX", "262375edb163c775bbdfba3a4b331967dff54e4125768d18df0b37171d82b1494ebeaf3c2cd9fb5b1209ac01c7197c29457a3c5eefccedf582cb00490e8025e2" },
                { "et", "deb91f4ddb26f90a9ef00dcecd26597cc9a8cf89ffbf10e043fa9d1749bff36f52c42c23a99d15103a10ee84b6ee4bb25867c68e678b7a76bf7bfea4c710a584" },
                { "eu", "f420aa78355c088e703941ae3eaac626201f31de853c8b1ec58c7e500dffb22a84780643140e38cb038016f46e50f4d1b3b5de4c46186f4af05c284ed1b22b34" },
                { "fa", "1277853662635f5f4834d32c8833c2fa69c71217ebca68cb8f475a5782ce45d53f36de5627586df41a1057b386532fb4f5275ea64fd94838f6f6002f2cad0324" },
                { "ff", "f3fa8757730dafd575f09edc04c47e2d720af51bac38f84b487b24ddcdaf578e41158c0ba5e58f33046e5fb8297beefa74a5c79d809a6893eeb56ee226bef230" },
                { "fi", "3b148aabb2cec71bd9727eb5f31a626b3b178c771da067d87671a26a1a2829a8076b0a903dca902853778768246da95117550681ecb3ca355a900692986e5ac3" },
                { "fr", "c68caff4916a850645ede77f6cf4b8314fb00e8d3ffb81cec6d6dfc7161046a14f8d803fe9dc73207a8ee3e183387a6045b8a724e91afb7fbca15d895a2d76e0" },
                { "fur", "a8a41985ad9b1c5d24856cc5379f37e4ef434efb2a012589c154d011da2b91ec526a12490c91944068f8e1fde5d4d05954e9780e94a1d3c99da185c3c5c7185b" },
                { "fy-NL", "01d3ceb77ef79d4a843c0116f3c1efafb6ffc1f24551b61733fa78fd8798f2f6caf965f1e085d6f1278460ad21d375d94a5eae5b1a1ea459a65efd5d6ad459d6" },
                { "ga-IE", "a43606064d9e823f596b4f2c90cc5de27899cdb72fd03df3972d8475281a966bfa889de4d82807ec6b09cdd5f130803002b431a0fdb09696f5d3737d92a22279" },
                { "gd", "b41981ce75ffa40cf82ee258c11ef9ce70ec44d4bed11f0e24c7761976858dcb90d2363d86864e70a2be21e9fdbc4d6a878a17beaa328996a5ed77e5f0dd8029" },
                { "gl", "bcf7febec516cdb3300a030f0aa76a10403da1c2844edce94173a5f43b0944af8d54124f7df23f5ca7bd83624d1d9cd8806f08e5cafab6ee718fb2f57db49133" },
                { "gn", "e5b6c21ec62afda2bde359ff7eb0f51878ce5c4454f5de27d52ebc1930e4ec010345eb5268c95218667e5be2fb116fc02db5d09ca063d96b174b0a1d67afbea0" },
                { "gu-IN", "fa405bc7b0415f502216246d72a97f4ab9b1d655bf5cf71a02fc0f54a675df40def778177b3695cec7ba7135740d6eeeca15fdc75435bed86d91d8e6c34814e7" },
                { "he", "9df2f1e6af764fb1f38131dcc70d2e8c8fa93913aa1b2f8b73516bd68ec5b9c7e49cea33b7ab22811a3048f34941e8b6bcb515658bed1062a4b002aef9044527" },
                { "hi-IN", "598ef84eded5647a2fed312ef3da4794824b57872b0e13c50f2702ac86583f5e2f59167c244e100f2bdc03338bcb50e576c4ed8bc430a7a53ee4e5fec66198b5" },
                { "hr", "d53dc4256f491825a5ae1a92d806f0366d4d4cb4d75fdd4faef416fbda9b83bad519e9f572dd94a36bc064355a2e400fba64adc905024c52854d5a363f0f132a" },
                { "hsb", "289669cf67a0d3a4e73925b49b3129334d140901b8084b5a2c0e6a486d605cc32dbb282781f480e13371ef90fdf8f996582037eb4e1ff2156b9fa94039537a0f" },
                { "hu", "09126d1653c4e996b5eb9618a087536d08f00c9d1370198e442e62cf7076626eaf81855b7679e9749a2a1a5417c5c6afd357076005bf9564838c713ad2ce8b6f" },
                { "hy-AM", "18b56cf37089ca5d9d09fd117348b5ae8b693be96307d11fe29076ab999537bb86e0588a3ff25c2024fe81f3433b8198640f027c9133b7321204471f03ddb053" },
                { "ia", "5f2888f34fc65663fde14e47d9e55942fc7e0315fc387864c5d919c903645f726ebf33000e360f8f65fc29a71eed0111d7bc082117a5d5130acbfcd5a2121ac8" },
                { "id", "4c101ce985cb66bea34101cc20ae6bbd3f07b18537150bf424236653c81c985c0f2e69a6b743af2c844cf9e26523c8eb8767c009f8909052a66055e1622792da" },
                { "is", "bd6d0c0ebf8d936a9aff65b4614afb65a35921c98887db99bcf2fd236e48a4dc2b9d81a2980ff709696f8ceeb8b4d09db02539bb95b00ca733a88bcffd4c69f9" },
                { "it", "35fad644dad4a5b960e5d7a0de05c0b3264c02f4a715b408180fbe96bee010ec54372705ebbdec0243a56db0042637bb0cf53541b1df416742321f5c75863cd0" },
                { "ja", "679a70604fac200acd70712a63aadd765e8d9bd849bfff7e8c0350a945436b8ac3d012ce1fd778eea251cb78e3ecef7c4b90fabf325e494a189b16703738e0bc" },
                { "ka", "e1ec982b8aa5bc8d2aade7262a8799754364398a4eddab77e9d46308c4ec642608105c6405d4f40a76fec4a7938f78e167cb1655e9bdcdb18cd11c51190d92aa" },
                { "kab", "3ea05315bb40e7396291df39115e92384fab30ed567a5614049cadaddb78609b9dd682894497c8d3cc99857638bbdca8cf7edb42c810f6dbfc9f42f0253d0105" },
                { "kk", "ea434474e568586c0bfd42c64547832d57665277b8b8786a8105d0db7de6723890d1beb58098f2a720da77efe41c1fd49045e01f7919c2e7dccdf2396b4fbfe6" },
                { "km", "32328f3984765425394bfda7cf06e653e5418d2884a07f1e2e86a7a5eb81dd9d86aae03641cfe5d8ee656b6278a3fcf6f0ba5a1ae918c32a02b6122b70dce38e" },
                { "kn", "f836e2581f85a68cba0464bdffc3518d1f94f75bd18001664c38086cb121968cd97f625a350286a56893bbe03120016c6d9830227796eb95073c8efd6541dd13" },
                { "ko", "d1d990aee252bd21a7cf3480231ce08f46ee6558c6a7bc4f94833e3ec26c86640f58475a3b6eb99d0825a4c461ecf851ad7693ebd7d8e80dff3a7de39ea61da3" },
                { "lij", "57e68330594c1014c83329f553acb5380de9744f0a1aec1def3789ec293ae389db59000bedc35be6b314a04bfa4f464f35c2985b7f95ec076b0bbb0e50c0d5b8" },
                { "lt", "2fb678e15ab33931ced46c02b0be451da8af99ce67a844ad6f7708df040587c9f9ea963560196b7157fc3ad9934e69952e64ab7a72d9994f222d204f696d39f6" },
                { "lv", "41b4f332fff185e3a768ddf83984ef774050b2f19af00cc1767fdc4f44b1872d91c5fa81c901ba3557162a5fa2e5dfd680bb4d53c8e004cd12887659a5a1e689" },
                { "mk", "0183bedeeaa0861e2bae56e32e468bb77ab6aeed248a424af99a9c067228b180a37b35437927aabbfd2a05ef6b537ee6bd0e7dd4b305083c9e7f12f5e42564f8" },
                { "mr", "bebdf6bce285f2c552b042b790bb142fb31eb24fef01ae42c9e7b5991e6ca7f2122ead8f4af054aa6c3efa6fc71476c46aafd45457c59b7cff60da509062c933" },
                { "ms", "26f7652f5e5f418d9bb8c70153a805abe940753c733833a46a8c10bd6c57be4b1a1e98418e63bddf341ba08ba0c8629118c38acc38b60f675feb817f9e6282cb" },
                { "my", "275428ca5549cc2d0f26e0c467843c59e71762b9a62548bb4ff751e20804fa4b426bf8ef8500cbbfd1c8688bb73eeb7505dfdf3529b0b1300759276663d6b5c0" },
                { "nb-NO", "8dee483d630192d0171f3c84f638949ea271ed98a80ac2dfa7a8484c0852e9afafbad1e6655971934de2d2d80d1c7a35361bd49de367cfee1b623f75de10b8de" },
                { "ne-NP", "cd36790774df6e41e83cad30f9b65a4b5b4f4b8bf0bb3ac86277fa56069334d5e41a377be07f494dc0d32109581f347765c81238ba6cadab328f7d5daaa93528" },
                { "nl", "ff22df55928153efa100166415e103f51f74c01f561b456180051a0596d5349e684aef45fb99d0a67e0225a17967ae4dd2a5de6dcecfb9b8b5564ffb179f0349" },
                { "nn-NO", "873511f889694e6936d39f4f2fa54125bd9f783c64737413cd06b567ade6b74bb32c6a802e10a737e9b3fe788530ab4affa2020b3a0e5bcc8fc0baf5a9f197d4" },
                { "oc", "482051d6392db2e8ffe08ae5ddb65291af5496050434934044aa916aa4b3a1e478dd8e33e17a5f02cb221fba6ada8c9f8e6f3d836444ee1508014d918adbecc3" },
                { "pa-IN", "41b0733bebf7e07b95dc722560807d653b6634779d9083bc0ccd95074d43fced96d30bcc8cbb1ea68bc2b6148b7992f47596a04500312901b800b3da3067b7f7" },
                { "pl", "f0babd819a7148b38e0a6821d0128db3157af6764cbaf0dbb23f96e94e993191fe89f98b7c902049a3c874d649ef4f15baf62f1300b38440bbbd6a5a1d56bc6e" },
                { "pt-BR", "2f0372613ca8d98e01c5b77be11576118ec64cf98367875c3aaa9cb09f3ac1b44e391f1bf1ddaa452557adc253699526d27fad7ab6acfbc3b0e81a869198caf2" },
                { "pt-PT", "16d75027e6c08481e3940d3fc442cb03357aef78ce5865b4c93ece96601d99db812a79a7d025a4f7d66980900cc650d4aa227ba9608561ef988e5250f70dbd3a" },
                { "rm", "451dcec7c4e010ff1541fc06e726d10bdb1a1dc61a540a25b75f4a654e1704e7e2e0b884b844a56fdc7f7d8d5d21dec99961857ca3638dce8199dfe1198ae1b6" },
                { "ro", "a9e8a1a2aaa5365c528b91700c2c08f8e043660551c69581e88e1834146acb7da968b71418b977e930f3464d95a87a936008d46820bd7b96020d4a9d035c04bd" },
                { "ru", "8e2691f8b751e082123243ef7c2ac52c3944eb7d5681b37f75e6fd1043c8dd7cd117b3f69d939519f7c18df5b11e7350bb4bc8a3356ba60fa5f74912e519954f" },
                { "sat", "866acf998d941a1fcec03015f2f4883a596e625892b16d9443af8843c4fa40356b7bf5010cfb4dca6b627c600ad90784b869f9f183e99c87db60989e9c2c29a2" },
                { "sc", "f51a0bcbf221a28524ef274ceb0c253363532ed1ae924db27a86d3ed17de931e3de4f105827449d0d6730623e78bb71bf310636d3431247b45f8aab654420245" },
                { "sco", "e1912e3dbd32ee20cbe04c4c1353122c4b39a33f2b57f7f2b669f62c06e8f381e12b8cef8f3d235cd4d02471e2b0f3c783c63819f318735bbfe6f9be748d081f" },
                { "si", "04fec949692ce5c43593c01a249ad90f541052268df8c002fc98d8116292be47521e276822ef9903eafa958d74bc07159cba1bb655120337a728eb7bafa9eee1" },
                { "sk", "02219dd03db633ba70bf26306536e65aabddcb2bc58e71a9263728730c65f177738ec416b32d5198c6bd4d6cf9c51563b649ab5bceff38a11f0608523d4c5689" },
                { "skr", "9b71b103e1a91a15ac7f7dbf11fa8db8a1c6ca135e5022810923b10971b2e93ecafea983937bca14a4ba54494aeb50cd9ab486c336b4767860f115d0da0defa6" },
                { "sl", "60b552f0eb113490477fcb17e4411832811f2a87c1daa85172f8aa14e1c73c357b6d2ecd6195b13cd2417fe3d40c31b36150793e4f005db5cf17bfc0ec28db60" },
                { "son", "f3e9660aee6c55c33d52e9c7ba3f18b2271ce30093df5c77427ab50896109532bac5a1ca69843ebf2a06ffcd537095260dc9fce79bbe928b768af2ec95cee57c" },
                { "sq", "ae9987c15fe00a97df74b768368d4413ed665f215f99db988c8a3e58367093c873dffe6af7ce78dcd224c0c17e6d86ba1068c6dae1847a10aafe0b844de48a1e" },
                { "sr", "45ffbb6048df6f02de47e5bd8d7440ff32514a333b1df13223f85f6fe7690275a04cd4918d7a75c9b1a9bd79916479537a2d6c77027eaa2510dcb52eb7db764c" },
                { "sv-SE", "c447ba375fa8155d12b629d808954df6573fc36ff272f54634e9126eca6b393ad18205b38d08a5e125d6a60e94a5e2bd705c2058fa13d477e4489406537f5f86" },
                { "szl", "19697076e75141e1f1056ee62a091520339ee669b0e0ef755eb5a6a02f11c303ab4394f96046febabbb4353b97be00c2d95bff4c5566013909cfb76b4c09eada" },
                { "ta", "4bcd83a2ccd6679e16c4a1da8380cefb50c4fc4aa0d656a2c53064ce4c1ec1ed500723e38203125ab3cd7d04e1433985b8ce140b020bb81a0dad21ef46f0df92" },
                { "te", "492ca3d4e994bb500e4383abaf69ce9bbdb07ca87783c44f09756b11f36e228f5022e7c0be3ab992f9111f2ff037e2cbadf164d7ad2856b0afdd42f77be5bd57" },
                { "tg", "ad743c964f65a37c62061d2243d6670f04636f22934f42e3d489657315f0a5a92f055d4fddb8220d1e991c2e3d71a036592e427d65c00e5efe819c93c799cca1" },
                { "th", "430262a98e85dd1e1a52b87989b3dd9086d66e871c0e21dfa954565c54b2778b780f7e23ed8d451cc17b3c62331db09f51e20a091e426189c9de9dbb78c94156" },
                { "tl", "39ea7ea956db16238e4044b8596cc58bc236c59a6ec394b8dadae192c1d33ee4898f10d8ff0beb53b9de856d5e060634a4ac80c3a1894a80ea1b72e1ed5dda92" },
                { "tr", "57b0a46293fa66e85be44e473d290225e0d81cbb25b87dda75f040f5a0d027a7e5e62b88d31edf2bf01b47eb45ec772d4bc9fd430e2e0bf9dfb6327c866b68f1" },
                { "trs", "57f94f08f426a426c7c9180cc9bc638b641a75b89abbd37f33a06f2ca4799eb2715d65a1c7a6a66770780aaf857c28b2e771421a4a10715aff3acaf1a23d5da1" },
                { "uk", "97537f857cb93fcc6ce8c22998032a6ad7106d4a8c5891586ba4f130917a8b5f5a054ea914a95810be63d0dbd07de578b9f35dd424a78a2ddf2d46b877ab0e48" },
                { "ur", "d79650932b108aa0cbd94bf36bf2857e8df7d4d840d831a02b46ff148cd67becde963d45cb4cde69754f1c57452877e8c1b304aa73bc02b352adae714ddf557b" },
                { "uz", "7422b175e648983ae41c67e27f974ff3dfdd853480188af9ae2b6f1247305765c54d01b88fdb6733661f2279cb5ecb456af2a3ec8f9a81602d8c019cc0824b20" },
                { "vi", "db5d5ddedd91b4672c6a27f99fdfc93121aba8fdfc0eb93cb0363f70fd30505b0cc864eabe0589c761be3565eb2a258b2885c0c52e372ea844285185d0144791" },
                { "xh", "f316c63f447a590a8c4b8cdef7dd36b4d4eb3e69cfb01cf47b47c9c2218e4a4830b1089800aac89331556f156b7170521798be135a99112cc08ee3318363f21a" },
                { "zh-CN", "ee9cf77307ca635a30a2c765e7a2cc5f980cd5005f89fcfdf8406d17e320ee6df3786006d00b3869b569e0cc8f3a0c2bef8fe3401b358e78a552b1d8ffe59f49" },
                { "zh-TW", "62b587166270dee7d3a0152e874b2d43c2289f9b1ab300dac25d3a078cf0f10e8976bd5874208c2c9dcfc6a3b2b89097d7cc3c82068cfa728a9aa1b1e223ada3" }
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
