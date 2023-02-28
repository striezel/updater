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
        private const string currentVersion = "111.0b6";

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
            // https://ftp.mozilla.org/pub/devedition/releases/111.0b6/SHA512SUMS
            return new Dictionary<string, string>(99)
            {
                { "ach", "49847ca1bd4e5ca20e0b669d105a04777773e25c37441cb93194749ed8d3f2c2b4e3a7420922ccae18f65f5e39aabb4984b68b46576f66a877bfd8799b76bd11" },
                { "af", "2aaac76d3d386aa2041de03328ee7537e0787012e7d379615fa27d1c3ff254a7d1955e3b763179ba595412c4105cb64092f6080e49caa8cd8333282db547eb1b" },
                { "an", "7c9d4a0cfdbc8092e054e5b224d23ac09170dddc8204ef417157312cd86ba599636eeb857ed80db80023935abb69a2ea46703289b9d5318859c5a010cd29e252" },
                { "ar", "1a0bf7bc6521fb420d02dc27aaa3c3bb5b4be86a4a91dd76574c4ba6787f3c7087efa60d90a0ddf375cf9ecfccd790a08afd258ddcab5a389c21e5ce3124b482" },
                { "ast", "135da37778189c7b0af5459c693adabb0224430e9a6c81f795914e7e982579e593f7bdcbb9dbd62497811ca8d5384f00218322c287e90f02a741263492f67268" },
                { "az", "c442aa2cbee765ebcabacd369f383e21d3f2a17a530fc53bd7210845a018dcfa87c0cf4a781b40440da01c3ed8d80678d832cf18b872613eb31b5c2ed4740152" },
                { "be", "3c5c2ad0ddc25808ba7b9997eecc312fb076489e6299b9ef0b3346fecb6676b368e23d6e893c23e8b708c1754a0ce4ee8e8ce248d80a64bb2340f304231d280c" },
                { "bg", "054571737ae7e93978da028beb2f6feeb340bd9de594c12d3af3a0dbb93e5d196f890670c9a89dc30b0c1d75255316103cee4a51ec083fb66c21aeeca3318df3" },
                { "bn", "c1962c01b89012d216a73a1d936af0a872c3eafb55113384fd3e86b1c553bf006f05c3bb50de38cb8e1155c89893cdf038f30420fe5fbe4bd6881f83038f7865" },
                { "br", "72c42b21c2caadf12e54f4bc6cb1417731dae830a919677321370996999c891e3afedbebe1dc40b92bf18a889684174cc6ba2f2cac64085603a23d5960186eaf" },
                { "bs", "79f0fa027941bcb881ce212fe2a8b75abc518c2b9e96b370c8664ae5026020a31b65c0636a9ff57b2198754b605f169cfe94b753871acdc7f24708e440acf90f" },
                { "ca", "b80db1cc3d62bf70ab387f16cf64d16c7f8a05216d6ea324df4651f92a6a38feece1fa7212a0b7cdad210012d2e337eee95ffda13294e172466cd9d512e5662a" },
                { "cak", "3938fd533c9c9cf1914813f9280db122bebde1f3cb23f25b12c43b3739d7bff85601e655a3289d53fee838de246dfcecc2cbcd45b560a84d94f264b3c05607df" },
                { "cs", "eda00b21e455faab381439a0afcf1ddb23311170929e084470609cc8d0ff6b12f3fdc5a20a0d0925bd4b8a3c391090e6fae86ade065100b793d9d4cfc1430a6d" },
                { "cy", "f73e817e8c553b62906f59c88a291f7ea2de248423ed33b5e120b389832c2df7d1e4413ebf937d47fdf33afe469261eb53ce09c163b3f702330218b456fc8bfb" },
                { "da", "dcdee69e8e2f07ff62ef599a6dd0a8242a4afe625390e22426c0cadef0b46bf0253f446a1dbe674247f1e2d7ca720da2596160ae42a96c8d6e1f201b1f10c016" },
                { "de", "79473ed86bdf9d3eadab6386f044271d979ea9caca0c750db0cf649277946b5adbdf6618d993b9ffbf3b5cb9e69d585b51b3a176d862c80f7fc27654066a5adc" },
                { "dsb", "a859a1652bd07a7439705d75e7e54c2c2c7a8856243ee7ec9985a1747f6513392254853a256c6729d78819e09f8557cc96a537294bf13d0dd073d6b1f08d0fa7" },
                { "el", "dc808cca6168e861686df16cc72591801914663eb0e65905391cd34617d051b3d0fb2073f53711f17c0db033b30440d2e38a9fb5af199385ea5bbac6c887520e" },
                { "en-CA", "80ef61f55c3f6c50d12cddb8c1ccec932618f9f688214a81ba1851e8a6995319da2688565b824b0050c397131a8bfe4af7863c2249d972e40cfd9946ca39c785" },
                { "en-GB", "fdd47a4fb37ab9325f976a86d8c11232bfd052042c35d4f25a70fb7470e74cc5068cf08cfa3ca858ca4b5f3ac95f1553792419873a6129c1d4e65c582f6bea6e" },
                { "en-US", "fe1905cb3bdbcbd2d3151b510401d090fd88f8bace7eab29b87318f0d5d54f6153732edb0b56e33e8f56772042ef8bc0ff81dba828da2ac1d0cc691c113d2d79" },
                { "eo", "1681b0c83a1d6e44cc8a13dc527fc1f1b70898c428ed8ab1c2f9546b0097cdda0fccf68d4c897c910a3b8352fae52a3afa0d86fb4815da9c0312c0e4427ce8be" },
                { "es-AR", "d605fb6e414604f5505fe2b7bec8502b0c3ef0a14facd141a9a3149245d53b754799fe3f4d1d42fdae5ff2758c67b646dbf47abeea4b0d51aba4bb66a0a6fc21" },
                { "es-CL", "1d5b23767f4d83c4c4d1becc050a936c0e9301ffee4c78b2e733990ee7a8b82fc60e2c1c3ccc67bdc24e1a35919bb462d5be9efe6a74ce8a94c498a0adb85fd4" },
                { "es-ES", "fae69aa8cd4c38096a4ca9d3578a6373106628c6286009f68c91cc0985d6fda610a5520d832364a7e341468664c401c07ff14bf9b08d1777e2930d2ea18b2853" },
                { "es-MX", "356d1954482ceb6c8c625a81a691e281d634bcbd11038ed6e96af5734f712b9eb07ce08ee6b21920d20642b7d15c67e4cce1d2336b9a12cc93ed7dd94913ad76" },
                { "et", "69513e9911bf2cbc92e91d626556f76fac3120da48e0cab89b7c74bfa4b3cb2094404d01697cfcaf31b4e7b901aa7ca9a4aa511060f2bd9f127d86f7fa699fdd" },
                { "eu", "bb8e0d7cb24f3a6cce9938a15c913630f3d955bb6c2deb2a02368ad9192c008f0c7b2a5be0ab2b0201583df2f0672994c5bacb32c38a2d9b4fab80c153ee13d2" },
                { "fa", "9fd4c3881e5baf3d0ada58aa7e73d6ca5609b2f04eee98fb3fca77e88f8e13e4c44ed5304eaed96b1f72bda45ba3806a78657045c5fe5d3ef64d5c80b78573b0" },
                { "ff", "5bb3cb61df4edb8cf9918cb2ddf83cb7673012927d165d3ef05332d41c948708564664d65efc5c6a41c4bb15f9cebe8a86c5cd7faa9036fb67fdd252bc4cb434" },
                { "fi", "22158a68b66555f3dc9435fa8e0bb377a24869e808743d4941aa9e92e36893bffae39c92223c18718096792dc1f41219bbef0bdcbb54e8212d84b0fe3f42a25d" },
                { "fr", "d54e88b094a1bbbb8c7c1c23dbcb4c7445aa1cdec0a9738abf5114eaebdcde7ba007f76f46220482cdea5ded3a0b4d0ff135131ace415de5398c588e76d4a34e" },
                { "fur", "1d3d55ca04ede66246347df7d95e5531bd2b048e5b556a82fea6e8eec0a3dca515a511ef4be518938fb1caed0c2bf5e3ab3f7b337762a591a6312f2361c78242" },
                { "fy-NL", "da6be6634bf13060f4a805454ea00c3defd002a4dcf97bb607a9d4b1b7a53efd9152d99c6ac463a4cefffad7176a8f2cba28b4fe0c05ea07cf9921b2376321d1" },
                { "ga-IE", "5499cb09555c7b731129c250278af393966533fc25fc25bcad1a5c4c9cffcd84900247e029ec3faa0893c03e9f74c6c0d2508cbcb2b3692ae22bfe2930b8cdae" },
                { "gd", "4ea640af1e01b6d5007bef7c433fc4aeafa71005539ad1c3f46e7613c4c3cdb36e6a72b84964873924293a81e22b3f928b24b66adff4fb93cd844e616ddd55b7" },
                { "gl", "66873b6096ad4a3cbc05855b537bbee5f34c7c9454ba6334f69e0d361f341abdc4355245c830a79892dda961083a7a35b3b5b5289b58178f04b4e4c6048be72c" },
                { "gn", "e0dc3d3d2cb8d8c59263e022d4a1c9b875cf9effbba2e5898d20c4c2222c421d07ffb7dd94ac85df93e81d6255768a8059d559ec5c882ca1bb295346e6e186f9" },
                { "gu-IN", "8a31f5c5c2f2d41b4e082af5335b58e4aebaf7592a66d116f1ea730e0ab6c560a46dd37e6b4e425c7062f6a2d37e882ba774bd62b5e1ef30660e68f0600d5988" },
                { "he", "4f90ed7f75227252804bab643b39ce5fafbef1f512fbcb834112e023550f65f5c7ad5f2e1a302e623c5b83b8360fd4719f5efc81761929452fd56cfeb2b56095" },
                { "hi-IN", "b2de50a3a43ee65ec9d2ad4aac5dcf8fc8abc27cf1f766ae530f0f64b86a92f432e6549c0d9092fb0b769854f6182a359cb5d33c4d7b0d0e0f68f64d18b3b7c0" },
                { "hr", "0effd9d5e26c783576f01b4478035e6f559a29b4f596a60ec898f3e50a5ff5e5c88e15f2342855e9ede84711ebab3bdef1805495eee52e8cc2e508a705fb6acb" },
                { "hsb", "0e20bb09aacacba3ab3bcc561c540fac33394c8526078cfdc45318194db5221aeeb815f57cb26471bebd6ad83413dbc80411f2be8cd3a76b44a64fbba553dc9b" },
                { "hu", "33687036e533d1c9b14d0a5dce6dacac76a6fa776a158b464bb05bf4ed4c9ac9f402b3c5b03b87e846c457ff4a1f7d0e1a84520737a99dde31a892aaa1d9ad35" },
                { "hy-AM", "31cb0584f9142a1570e6c6b3a740f179d869fe9b5ddba669f7d0fae67ff23b96b8998c6753546281311599c40f2c894fa7b504d24af4df4510fd77343236d977" },
                { "ia", "2f875199e7de235d1243f02dfbf8b7d1462c5bbc2774bcdbbb4386d7950b7ab4032ddbc22bba357ca4ad2a0432bef4e641346fb3826616381ec7f0086f031db1" },
                { "id", "6e7ec875576c1193b5594bfc046601d1b69fad59fd25bc384426ec444ccc0b313a2b45adc571635ac2c435788f343cefd75e299ab3b8a164a6f7623337dcda03" },
                { "is", "b8e253fe8a5bc33a7e945f5d8a5c24411a58b3200c3b7bf997c46b08fed7751d5be556b3e1893dfe604c238acac49244782287cfa4a12b6bf6fc3f629cce69a3" },
                { "it", "48d45d5d26e800c9fba4281dc0c9ebf151a5c805fc383a40f067c4b676e8ef431093bd55265c068f2684e59e7c4c644dc41bfe0bd05d9347151fb1309f390343" },
                { "ja", "208339d5f479393ecc390061f9a02ac26608eac0aea871461c2f61f237dd7b74ddbcdedfd074012b63dfdf25a942be33e760e297d605ad042cc3ab970a32cdc6" },
                { "ka", "1cf416ee35bfb3ee0ff11c870203d6a5e68cffd7f518ce9b653a96c6201e8bc87f1ef96e21ecf24719c50a596276545d749d3ff831be73a6388806bd93c42d3e" },
                { "kab", "73bfc7438ff2a77663415a80d2c9dee4ca609c6d4b9c7a4c024707c454e8c822dbf89ac81ef337413e0c20b6890911fa6d2e43725ec1e6ef4dd142be890b165b" },
                { "kk", "b4c04f12a58ae1f665c44aa93ed1e7c99f8f064e241af143bb60a6814659396bf22f72d0dff569cd85d2bbbcc6be1fb80799a9b8b615838da48def2dc3948082" },
                { "km", "c746b7a7044d79c574b542ec264a9ad1a922e2378bd2bf2fbb3aba348e9f7bbdff49b1b847767f1e3bb32437644806897dc767dbf1197a97bab0fc8727e9f374" },
                { "kn", "3c5a366dbd2601a0d3cf1db27dcee4037e49c3d32ecbfec8b6e51202649a3f48c4abe7c9b54c85694fc040b50d4d4b818f67dccdd0d5517458916d6bd7404695" },
                { "ko", "cc2e596c65d62fe76b1423b8ff37190a38e8340a0e83db3bdd85dc953b87e4d8741c674cb4e6663fc5a4ac1244db2cfd1c0bbe68d733b8fdf5c23e2f38bf8a07" },
                { "lij", "31750a0412b85a50e38761a27497d0141468abde35ce7823d01dd8da626c00075a759971381a67f36afcee6b6e528a33ebd22071391d9c0cb7856b857d713221" },
                { "lt", "644c488575d41a0e439f793d4a0a8b1aa7365f74151002730d26a2ea0e994b349cf848a11169ef1f42b9c2a9236bcf762eeb06ebc75e675b9bdf5df7dc58add2" },
                { "lv", "bfb29bf11aaf301e597ca5d114245bf983188af3cf349f9884cffe1cd9da835b2748a87617b5afe5de65f14849e9cd56caab1b53e5bbb0c36aad93b715ce38fb" },
                { "mk", "31384e87d74b47c60b9099526d2cc15e7264cf222f0424d5156165100489bedd87bb02fc310902cd0ee574a7bfb16f4b55ecc2a7936aad308731c6ece0264e27" },
                { "mr", "dc8f5b666c7b72ad841be7202d65a12f07362b0ad4f02cf512aa0e63e724032741f829a7304ff06f969d72203266c52ded999c78dec44079f9629998f671f8cf" },
                { "ms", "c95b8eca2ccc7a4df426eb3764380da9d31ea2431c8943215d8fb7c6c80c8ace813167479b9d658b7bbe1531bf5bbdb1dd5b58721313a84fa789036194d2b5ed" },
                { "my", "4807d8c1f80f34951f5888c5328ca300f1ca8b904d9584a877ff9b9a5a38a1a0b8f5dfdaf010401e3d2c642dc10c070b312e52c2d79b4f8edccb8bfe3b08372c" },
                { "nb-NO", "ab011137bbb8fed6f9fcd16f81c689ee316551d69e7f66530fbf548ae38019f4333a948f2a715b98e907a64ba7368bee275afb6e13ed23ca335408c412528228" },
                { "ne-NP", "ffa3ccf38019a82e6816c90190cd8f67d05f07daaaf2f96572125d4b43c3dc7a24dbbfb72b923fec89248ccad8cf8783dfd5a3eff8a2db396a6e8540ac8e5871" },
                { "nl", "46b0a7d84552fa3b3f7c308835b104eeb189bee2e8ddcb69f70e9566f7d6636a4433c314343190adcbe5f167ad05368e6b2b96d9b5157409a91d0337bf0bf289" },
                { "nn-NO", "fe47a87ee6f124f0e1c096dca10db7e7235d8df710dd1a23636538134f8086594566f1483d1bd311f631023e3e5853378b5dbfd1311808367ce90db002f3b2d5" },
                { "oc", "d13e1d821abe97957d70955b7b5008214ab9d9943850b93c65697bef02ac42cfcf896fb5045b558f10d833ba994272e7409d819d858b5a9c45b1f0efed3bfd46" },
                { "pa-IN", "630656a6ebfd0e2258a0f5c18e12d58351698504645a02814f0c8b89db54817349074003c5d7228c0ebdaf6911da4f5cbe86f0c750a050be6a63f209761aedfd" },
                { "pl", "d6a4a015fe2e66d100c5f4e9076927369bda5f649a565f716e2907cb94506153e862cc18c21a66e440bca499769235263ff4d3284ae1d7d549de517484cfc435" },
                { "pt-BR", "c02a61ce72ef380c2c9878b0c9638df845d437624bd06bb3e45818910e7576da76f5a6f78e891e506cf4f3e9d088fc31da342c9bbba85fb1e574221b57d42e33" },
                { "pt-PT", "2fa119eab7f5da2dc3fd13b5f3e5de01bd862f64ffd0a0bcb41b6bbece22ad7944018d7f72adc12a44f5e0238fefa75bc714ee484c5923a1a893dd8b821f5892" },
                { "rm", "0280e47fa329a66abc12cbe9a3c03c2bf676ed920f1b432f09dcfa668f63d70187607696c027988ed40a2e0a30a31483d6920a5d32cafba6e2bbeabd305b6cf9" },
                { "ro", "45d927d118778346d44e588009c1a4310a39f46eb26608a7b7ae7f02600d94074ba84c1d4e8c79d946f8f0259d071349b39747b6fe700769cb81d2a33a07e8cf" },
                { "ru", "b805ca9c6236510654923548338dd5e137b0f6b308d97df0d0a271abfb1a18ddddb9c2f2f5a513695865a11ba9be5d1368b366c5423c277ec722f177e2d9f34e" },
                { "sc", "c38d3b9eefe89432c3293df6aab10cf8024f0583e8147f18b3b72fc73b436a5a2780b04e5290705bb18b7ad3a9e60c5b453982cc04b9115fb3f81f7181a847b2" },
                { "sco", "93b78cd0beb071b67375d20e666c71c667aea5cd155335f2755bb414fd5c59dfe59e25514c91fe5670706cbb62549722bfc0524bfee3f84a7d7d39f49c756415" },
                { "si", "f75f23775c2cb13c65ea967def57465abb510c98e3041eaf9a0db667479f58b1cfb2e018d74d8ad394797414054d032ca391454a0bf74c0c688e5ade25f07b63" },
                { "sk", "63dd4966d97d17362854e2df5b5cb48e50d53928e08a4df2b8ce0bc25c3bddb4cfcd2831820a01b604605869328c83b5d83d51baed9557de8b97962fcb502197" },
                { "sl", "450041d05656037f17b3b7ee65db629ff7f729a4b1cd1a0c7eaf3fc0684cfcce255832df45ca69c4692539692cc83e1bacee8b9c400e09de213119ee84a88acd" },
                { "son", "383b2919db5f32c4bdd182edddaca9dcff6532e97b81bc2184c39eabd441e58dde5cffcfe795eb03dd9b65e4e8d4e776f9d6d7a4394689137a8bda2a5ef5d225" },
                { "sq", "0423e8cb8e5d8dbd7d62a54a9a802df72ddbaef383b9329863c55a56be06c03c3a71bcefaae9002a74f57819fd83510f8d2b10c910f815a398005d0747b01f99" },
                { "sr", "6e14fd3eeb2a181324b0ee1aad93008d14de627e415f7890b015cb759e8ef303f31ae7ce970edcae5cd1f8b994ce915514454648aa81024f39153b56a4d523e9" },
                { "sv-SE", "a7f4475137e14407f9b9c0ce1821a2da07c0bfd1c7dd48b2efc2e8317bd348f208a407fdc8c7c8eeb8e93015702f8ac8380c160e7a8853b6e14abddd38563c35" },
                { "szl", "9b1e895842124e5a7937d9dd9ac73b1c2119e4ad7a6dd76ad903390d039de145a5f04e75e83c2a65bbbc8f39924761c1ac9f844468f3eac809191844a8be5edc" },
                { "ta", "679dec77367466bbb6078fa52246e8f0a5dd9b81c2415bbefc0ce84109b1568d35d320a84f3bbad1c15776bfc40d64a5dfec2561a460a8efc0f64e0e4912cb29" },
                { "te", "4147d876b727e33647d091d9f3c8c11f45c15e572688e3e51cd3f9e5e987bc46d658532aaa03fdbbc2ad9573d0f0b5a280bf3be861f7fd96f5379006c0f2ecf2" },
                { "th", "d6a738645926b3e0b2c263e005da09ff4ead7e5686464e2eae3cc1d0b159b9de8eef452e8335de3e6d13d8099634af2edadb37917db753f8ddc7b3384ef469d9" },
                { "tl", "d0507c9f7ab8040074637441a984e04375cf30375082032da200cf5deb6b34394766a19f33afa9837f00011b4c84fd0cfa9fa1fe26a861196f95b7249ac49f39" },
                { "tr", "ba1238cb38941267ad2fe2a28286b43282147b3b6ba9d51bb0263f23c110f3141d56cf73827edd4e286840ecf8442e94325616131ac730306280fa6c4686ea56" },
                { "trs", "e8a844064384289084fcfe3da4a940bc57e848cfdb94724f533d0320d983b533f77da384d91f1933851b9b6d9559268ff5c8f78f72b7868f711d700a7b5144f7" },
                { "uk", "e90abd7ab831ef2fe24179714fa24d963ba23167f953bf8ef5ee53b22f8194df0ed88336ff5aa30c0f17ebf85bf209a6d25e7d9bf74618b496b243bd0f4eee0f" },
                { "ur", "5f171b3b832f9ba9e98bee6180586bad9165ab0d07bf9701a74a283501a1629be8f0236752e0404fa37358c6c7e398b057edbff8df8d44facb7aa8889a2111b5" },
                { "uz", "93673d1f41fbc23862045c3b5a0666fbc49263e84bcd3cd70ab44ec985ead92e7928aba14058de447322652100bd1849a5128c24c3f2e28e3f32dd96fd9d3dce" },
                { "vi", "783ce0682c53b158fa6a3a9d6cc0e89fd9d1e344c30ae26caf21c7a760406ad4a788e83d5f350ab5edefceaac553a3af24c485222b08aabb79da98a7bd6902ae" },
                { "xh", "93e958490435f03a4ea6b13d05b477a3befb93ac6f66bbbbbfcc11f5ac8caff37e43dccc3365656b03b27ba317f029648cc4da60abd143e927875f8236f814fd" },
                { "zh-CN", "cc577679a7917a7b7e677aaacc28d8ca8124a0adbccca44b610a0aa873b190fcec67adf85076b23586bea677c452ffd4332db881b6eba55b15d70624db977774" },
                { "zh-TW", "4b87f47139b8cfa5f0bf75002bc70fc0368dc8ce63cc27bb842ec085dbc0a816106340ecb744cc02aaa26ace43370a0205ce13c060a6bd398a4dfef59597b9dd" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/111.0b6/SHA512SUMS
            return new Dictionary<string, string>(99)
            {
                { "ach", "ca9bfda0707be5c062c4c94c660e0421867069c7c893963fc66ace8a73b42c750dfabdf3d103d323544858bb3937bffe2b7836e91655859d60f51f924ce3eab7" },
                { "af", "e7f23dc128d8cef714d5cdf81fee7f602e7c8f91bdd1eebbe57d762e53819f1125fa6df694a0a270ff9b9825e6ecd448879bea644170dca262b3d682e96802b0" },
                { "an", "2a5e086deceac906876d381b64615d99a60dc577cac1eff7c4d67e59854420168528f4a7915171739b52edd112f432202bdd7db735bec2dd86307c0e940162f1" },
                { "ar", "fda1cfbd2e6a37703e3ee5a6c6c19f228d29c4519d1be9b2f8b843043d005c365eb95f342501c955ba9a0652ebdd6c0936140e6064035832e1589f0661438bf0" },
                { "ast", "143a4485030d976ba0e70dea21181ae87c7edda862a36e57e205788b0bd572b2cd8e45378e4e1d213fa7ea274c8f492068ed2708ea049fc8b4cd4f3a76d93291" },
                { "az", "351c891e6bcd60c5b9bed7d05a9a13e25b18f1c31c6a5228facd83b1947a94a0bba2270fb5d31eea954323225436d0bafd9e7a7626d7abda8966ad0b1c5ec4bf" },
                { "be", "f1d5b68ac1fa3cc8832363506047db1883cee9c91b77cdbf4ed31cad338fe52316310cadbfba8f24f6daaf45be110907a55ee6f532d2a10d3f97a0b3284507c7" },
                { "bg", "c5c405c6339f8341b8b5f524d5c60f2c37ea71a55ff8fae96bbdb6f41adc71ad99af2d0b079b2f7f54fd05af75c11f9f3afa11ccce9fb2180847886f991791fe" },
                { "bn", "c4cb77d46b4c4e22b618ebfa92609cf4c4209e48671338689e439793d8bbaac14153fcbe471c94e9e2127330fedfc17c8e1db89dc1989dba798669dd3b1b58a2" },
                { "br", "6eadd886e27336de0db4d1dedbe08a6f53fa4e02b1afd046b09b22a9a99786e337825f95180100f75920e3a0ff50843b8cfe8838cb5e1d460aa841aed7651ac9" },
                { "bs", "f3ac5e43a0472a6861de2bf56ad3b3754b1ead2860298e0360a3e8b51d4e59d07376aaf4499b8aa6d696b9265ab12b023fad7119737dfa0c8fe2fd133f4ed393" },
                { "ca", "6e50779a9bacff2fdf288261fdf716b8e50a23cc1f3f324ed21d1d3f8f6ffeaba2b76bb9a6991afddcce81663e96dc5569120ce5da43dcb0d60220d2303114af" },
                { "cak", "ca2f0ad52ad095511498a3689bd71eebeaf7fcfeb68cf022388f853dbda5e02faab254b135142f25f2d971ca513739f9342208271a586c8119656024f3171a16" },
                { "cs", "45f3a4c9b9e5f8b5d4b1a359826e1ca29c6bf6c0f7099d1e178dc14f22b3d6aa8d6be21a8ec50342562d145ce2a8af3d3ccd41e2ac9affb7dbc70919d178003f" },
                { "cy", "104c4c24a23876e3a4a163f10c1ba76116a6f00bac002270e15d43bede55df52543998f1575ec06da01c1f1fe9ac8b8fb574c0595c089574379aaebb8ec213b9" },
                { "da", "1c6b45adbaa3299637869e0b979bd3fd9d8b91e4671368d22ca29fa45a148d4aa3a1515a821433af4d27c090f268d78778390ef1bb90b8f09faf41efa34c538d" },
                { "de", "b1307f00e7aa42739f5731d8ff55987f727eb522a58113d4daa727d0680204beafbdcb716c5245d3e9f41a9bc54488fb984f37404cea1703f094c62a7c2d67eb" },
                { "dsb", "1e5daab457418ea11f7be53fa058aa5df74a65c9e6313f641ccbee9d322e2c8c0cae2f390310750d6daf9c01821dd3c5060e9a74a9ae7cd262191044ebc7c3fd" },
                { "el", "685bdb72cc85e7451bab1da1234fd32afca266ac80204f93807868d5be9a787892f2487aead6e4af4aa81252481ba48ea4548f5bcf4897e07edb75e415608ec1" },
                { "en-CA", "0f304f143dca7bfe01adc98cc30aa1bb67ab56c7e3d127af15034b1032db390329ee42473624beda90ccc15852279ed1a8060452e25391b380ac53a3924f63f1" },
                { "en-GB", "1470e93bf0b29bf81c20d4ab4037f3aaadc1a1528800c2bb6d015b107de58f1e80d85a65dc6e4f876b9c3339f4aae30b3b00696c870bab9852bba52c7fa7f410" },
                { "en-US", "ce76f6b1eaad0c73d94c8d00b21efa3cf151533f3476c5f6bd558bdeaf5ef1f60c38a03c811956c303628fe765bdc76c0a54d7fa85c476a9a870922d8b981927" },
                { "eo", "1faae2746c72fa08040200fd00aa7d001de63be43b246c8055f1ca8c94d435c8e0c8fafde40874c9dc3ca3d7649b8026c029e475a6fc4a296918e3d1eb669477" },
                { "es-AR", "dc0eb9d12d0ce9b729d6f12c5b8a67934d325a3fcdabc43883207d7b4c8a60445a2ff171ab90f15d33ec896846348c96624362c3a4630a2b81497aaa8bb4e648" },
                { "es-CL", "3f5cbe3cf20b3330c1c441b00e73cacfb2d5d5453750a06ab51e131f97ff4f6816a75d44f4907a558a0298ef285c54be5e5e419b53362aea77d6b7fd408bc712" },
                { "es-ES", "8965f2353622e958659f3d8e6dca7e2eef6e957283eb2eeff14a00a2d89247f43808eafe3567a7ed42cce4e5c234eb9e4dbc143a499d674aec3b7d6b6aeafc7e" },
                { "es-MX", "dcd020ff1dea8f3888ab45fdfee985156fb18feb49ba6504ae92092c3fcda974633449c3cb4aed5d4fe2a9fe1bb2e488869d95b4d833a2691efad1293ea48325" },
                { "et", "11865b55ee781accbf8f6d4556392a299041e4a9ec1c83693799607066ab99c99ec175fddcd0577ded1d1b647acf46060531c7962f6f9de15ddaaa0d74aa359e" },
                { "eu", "0fba4c7b51c48f23bacb06abed3bb3c30cb965e7c250350954d9c382ece85759727be477d787c92f55e22cb994f4f36d012cad6deecefd438d1f35fc6be0bc8f" },
                { "fa", "407f5ecc607e7dd51f7576301c983c67dd5bc46b92d9487b5a96d557e47845d336b8ec37c74d1ff44ca2e049f365362dacd769fa6509f1f9fe0eb498cf317c6a" },
                { "ff", "48edbefac74565cdd18000f28a61f5759c548f313632ae6ff405bb44281fdce3002240db495f3acf632379cafe7a94c4016e83a090c36256263e1e77c40fa75c" },
                { "fi", "4e529bf9c6888fde1e21b91223398ad60e68fd08b882b63b65ab8a2adef35e977fea2fd63d25fbb1d733c5bf90c572726fcc0ca40c1570c00c089c0c6e1686e2" },
                { "fr", "4716c073a7242cb360148c381b09e5628ea4b9b4a17c30a0e4b12c150f74db0ad77dc1723fe583e4c4a07586bd9f17cf133c8eb02b1687db15a096441397a0d3" },
                { "fur", "e7ac2cc395cb704606b4d9898810aab18ec14df36e8e85f70d381f4c7c29687cf9f002b8efe72b35c351fde507f1e7bd5fae3d397a725bc5c945331acf60d328" },
                { "fy-NL", "95244dcd14f2feaa86829b8d3dce9f7d879ef2a1796c8ac5a90a4c770ae6bee96a06895025ef7427154da5f17b37a5e3cd0d72f2fd2c55b53bde07225dfeec00" },
                { "ga-IE", "d1e8353cd3a69a558c452f9ae54892b7ee2c0307cb3183fb0deb889a256f01e90a617cefd9cc81531a908098456887054a024ae90307d1f2f0034cb140e40123" },
                { "gd", "85b98db07aec958f20345df3f3c8c66d767601fd04e50fb7162f2c33042773fd9be6c0d58525bc5670ea893b8563a880f34db4dc2175a97c1b66506161370532" },
                { "gl", "3c5aa237fc86c31cb9f7c0f47ed654c0806b6db1c2604e6927d5e31a734a8c9667dce903064003b46eba82749630403a50d20b7703502bf303244f2768df4c3d" },
                { "gn", "a1acc321672d79272d04f4d8152c4cf12d0cf17191b2b6212440c65340728f0fec4c81b7e641588587b865d2eb6d511a9794d5ee34ec2b1266037d037605b9cf" },
                { "gu-IN", "35c93f67cae955f69fcd0dd399fed42f4d22c8b667257933b807f03e46ea575a2ca0f26f93dec30fe43ba1499d3b1a67ae503d0fabd9c431d49bbe30aa4e7c83" },
                { "he", "10eaec5c0c1b72aab91cefe00b85b72a770ed52890ba9f83f622cec552a5a36b6073be85d4931cac163178a5c9840de85e3b77177a5edcd8b7ed1d64e30d2c43" },
                { "hi-IN", "26a7f9d209b9c5d4c0e4b750b798edf8cbdbf87c58cfd6674aa2868c423f42945e98caaa2d58a1ac506e3bbcb3fefd603c3ed612921834f7c4d49b87cb0d2507" },
                { "hr", "f672249a6f31d0e3bcbe1915d8da739368967073b16e689419967740462a91bc66ac7f2c6be2700b890372246a0fcaba8344603471b5d0e01afc5d13e766cd42" },
                { "hsb", "43f87cbe535bb3572786a9441b2ce66ad08941e9456e238e05df25ba44b73639f4bb46ffe4059a3ba024e448d175e86f5eeaca79ba74a392f0dc29c69488c22b" },
                { "hu", "08c69574507651dfc93d6cbd2dba610ede6821d3de7a5970dcd2af0ae44b0370b415966ea56e44a99eb71f2573a4194fd2cd1b5de7209fa309c5e7aa736a15d0" },
                { "hy-AM", "09240ad4badb37daa8b796f4d8f4ec70b51b731c51033d694b0d54991803e63edb4838ee5285621b69cc7e39836966a9c54da25cb67ae7731546be8e00572bc4" },
                { "ia", "7894bf679dd70d383d117515600ac95a59ea040a9aec74e8c0604a9e3f057ae0eafdaee0a011846f5d1ef827c295fbd1c3d8d14ac016c0acdce23c188e7b9d4b" },
                { "id", "801832482a00de9d37cf635b8fb5d26164a3092f7f1f6fb6084da090a447b1c754e8f6fc86635c8ffbcb229055afa71c7bd3c571cf420f5907cfe5768ff24229" },
                { "is", "9666ccdcfe967e4e8a1ea68ff719ad5b90af6315ef5a132eda9b79b86d3ed96d18a1769480eddce22f7ed055d29f64ef00d6f09d671f21bfdeab794bde2bc2f1" },
                { "it", "b97483d945996a86651b11e9add30e7786b6ef3aa2ec5c2c0135c57add0e7c7ad1ed073643c45ffd0a9543f65eef379d3b4911112068b19cdab7fcc6ea0a665f" },
                { "ja", "51eed0e869c2f49565ab50696dc06bdf322d9bb2a6dd3d1b02e0fb7645c020043b57b6df6c9154d1e6db54885f56d0842fea03f5d0b1290994e811df04f99366" },
                { "ka", "98f5d8d2d452fcbb3b51b3193770d48d4bc58da98f87f26f95a5a2b5144027aa1da3d142f4d4c4d3b1812159a4c42ea4d5eea7e153f69f30ef1570fa171a6ea6" },
                { "kab", "16fa08eda5c6f0f6285dd2e1bd5284b4c5fe26b4e468261cc97c12e08589ca8166b5eb0e231b953dc18e7c87fe9ae78190da331f82d0ca85c7154b8632d720cb" },
                { "kk", "05bb6cf77786e458f34e93738ba3073abe432ce1fb97a45dfa6562f6f3a2e28922f298e8b39a843be3f0a7ad6069922238e52885f818af4840b9cfa6dc103a0f" },
                { "km", "1b800c90145a36240e60625e66555776c4e5aee3a2216604800fb76a42a0238a58dd1da150b010a16264bc68c4cf7f9a7c5e4c64fe5dcb9bf5ed9308b5cff520" },
                { "kn", "09e1df294547cf34b8d7f2098563230628e80d660ed8eab28ea8f197e0c9a45c54a87ced356ea488b4cd8220697cfb012f7300f2e83652d4f896fe8920bbaede" },
                { "ko", "1e2fa54903f584d984c6978d0b3fe797b1733824eaa0b433b3761b69fc02938d555af79f588e09b439e430423cf271291d15517960c45651aaa71929311e643e" },
                { "lij", "82a16ac2cdf9cff7316cc2de7f6479934d7694feca3e1b187d3bc35423a596ec375373e514dd7913e249b395d0ad43bd8e2a7740a104d56bf166e814d9a75acf" },
                { "lt", "c917c2aaa6cb69f078066b948fc75450ac2014d14fad3a64bb9264a703dbb9b889869442dddd03d12d3494fe0b693955e2d961dd6dc738ae58aa06c79aefa2e5" },
                { "lv", "312da8a0b9ba3cae2df012ca618f9b68a9c10845e35b5aa0540ce20a171b3de156b2d62bd019edc94209c0cfd84fb1a4a6b3176c94cf06d082b57be0b4663980" },
                { "mk", "ea8e5a75609212d26b3c1e1025f02c0b48eb6085fbd4d9f78c3c24612006455030b895e48fb6bf58779cfc98da5cd1d2b716d78d015cd73dcdf3ff6f768f872e" },
                { "mr", "a331fcef4c9b23afa093e6d1f4b86ede14c8fb8384d1f28189eb1fb94632e53a4c449aaefcedbf2075cb9b72becf9f8eff5d63134214467f216f17a55f3d38fd" },
                { "ms", "2a15cadd944a4c9fc5f2088da0bd1b5ae80f74b7e3cb38eb1c53129a67cd181637d5127edba64ed20db355358ae34c8d1a4bdc734cb36f95a90f91b47036b513" },
                { "my", "6bbb4ea203a8f73dd9dfdd708e3fd7621252e516f1a326855687118f9dcbee38382a6e758e2a9a47f693211adb29813333ee48eb33c1296d6f4e853c50bba74a" },
                { "nb-NO", "c8baa73d99ec78924ef994068fdb30a67e0c7ee068fb4e15fd9248bffdad6b06c2915a7b483ca5a2f449a0e20a1fa2957bec7c27d6f8f86421e8f2676d498501" },
                { "ne-NP", "38dce0a95ea3f23badbe4dca99f6d0d99fb5d2d5b20db50a36e4a6b0eae020b838a9705f7e8fda004b66308b99c1409b286eea4b8b06a1451944bd99c619d5a1" },
                { "nl", "b5bcc24a663a90bb69ea27dd86b6142e7189c5a48149470872ed6b4ca7a6e8ab34a90815fb23536b6d0dd8fb25c2b85804349573062dd30b5fecac6bd5380f49" },
                { "nn-NO", "7344f70ada7ebafa5ccf7e30c38af4a7767844d858e6346e875e4dec5b2b7801e283a6a0206ab419209e6786061933cda41d428183ecdce58cced7892a0ff747" },
                { "oc", "f8012f1e8454e88ff3b0412abed191ef6be561fe981318cb27e053ac5b008718a13bbd7c9b7bff42ee51197e1d48723f2efd8a171866a038e267e501a3c6e992" },
                { "pa-IN", "b9280228c1865bebc2509c5ef105ff12de81d9d35c930c57451d1e8942942824abf18c6294ffa494262870e1e723c485c1a55dbc17ed2c58b21d56071e5d1432" },
                { "pl", "a4bdc87396092fc7fe11116bf8e2c993c23bf41e358885605f6d04a0455f9d5f6d7f1e35ede7500e30226fa5b84c87146540803be959718acef2151b541174a7" },
                { "pt-BR", "f53d0c377bed63b3d97d27fc28e06d4480eb92f3db4e1ac94e7132199094b51c3f666cf500d1ccf722700e61e3a2149efb30a9509f70d89e6ff2f6e363f92bd0" },
                { "pt-PT", "0788d03c11a1febfe6a5be8d3b2adcfc1e4e0928c4b5a42b0960c524cf937be3b7cd72bee7bc2000bb9f5808994e6bd0bc9efbb7a3a11e38508d0361c8292aab" },
                { "rm", "7bcc5a7137e4c44d3a96f651f9bd390ee480fc6269310791f0971f27cf3389fad0ce5faa37805d235302dac77de5855367f5d0d85ae6b161caef5c1749e8af17" },
                { "ro", "8174efa03b2afb293c2b6e1180c8144d508e77ac86e775ab4774cbade9064524430f9f67eb81ba82862d2f34e92fa2cf89dff9581190c701348a3f95c0b0650e" },
                { "ru", "149e06ed414e3c1f33fa2e5a408b0317bf3eb8e3b9c8760f695c326b70722a0515e70e8658ff0d5ec656affdc520de219d0e8ac6424a42874b4ea46f60ef6b95" },
                { "sc", "c254409087a0d58394b00ec670b303d9704c27048a8dd496cfa3ce516d0e179e861241a3c7786054f7eb1813723d0b281a1c08690a5b1d36e773b74d6f450532" },
                { "sco", "384609878c6fe8fb384026b336333d008ca00eb95043982f8d6a466d6e9209036ebaea7dbd8d94e870bc3681e4154f00278d1658fe7ce25cbd2d4db90959d174" },
                { "si", "6aa9ca0252d21b3797acd171acfcaf90731c0f7b173235a9614406e01ebeb22969695ee645872db1e8ad9c46d1aebfda53bba64a61bc12becc7ff3dcdbe5c81b" },
                { "sk", "4c39e9d104c6206ce0820b10800eaa7da87c2f0e70078dda5dce6b5f73f3cba7d044232d7ef6a4139d812d51450888e5131d8ac1f25bc6462d13c1667b45b1ce" },
                { "sl", "2694384dd9bc3e46b5ba3bf920fa2e7914ab89cdb7f903944b85610b24b0bd3c33875fadb5a5bd9cdd981329d0453db0639685504f8a63fb1013033d315e2924" },
                { "son", "53e23281a285a05b9a71c61acedcde90a9d4e36aa709ae21a135b1f6f4000783fba4bddfbedcf339066e81201835ab9edc1973da722ab98d39b907f2ec19d720" },
                { "sq", "4eb1f35dbe62e4293da1194abc5b8972ae3b4f61a0983d9973a87196aab325a81fc13f82311b6adf11326735320b01cc38474ba609596aefe90d28a71f78b268" },
                { "sr", "c72fa190754aa07c42ab57c7e78bd47cd2bfa1509081d6481ce5d7796bf1a92bfbfec3b34974217ebefc846ea161623fcf2ea635e70f5d34fcbaa337d83b23d6" },
                { "sv-SE", "39de7a078668ea27c3fdf82edfa5a4c7359ae1230aadb64aca2448bdac84db86dbf1755d04810f3fa5e062f37d99d7d9c4c4affa2af300e38e130b7ece231204" },
                { "szl", "2053a754397f7895ffb04e0a437b757131e498a95a293f3a344ae5d0c23ac70d9d35c3a8635ae7ee651b1ec1c000f769ceab115cf5ad7e16452b6f9144b28b6b" },
                { "ta", "2755139a62a1105a8fa2fbbdb1998a9ae66cddcaca0d165d9cea0b6710bc9a9ab237fca18365da30600cb3aa6de6456f85c3b7d63d5d4ca61e0a78f45230234b" },
                { "te", "6491fb77a8c181b29a48f3d37c3c25620fae54878bf308fa7a1e2a02b69a02e41fb3d2fb332b03da1e3c1238040491b2207941e826e48621ffc1983fa626c6a2" },
                { "th", "6db2be143e79f8030f6bd13846fe60e6cb2f1aa7a23c483f3a8378a139e62b749f6fbce96184943d3671d63ee105ba427a0de6fa383e8c9ec009cbbe6f81e3e6" },
                { "tl", "246f4f005758d184ab135f684776ef08efa73d227478560dea6a1c6ccf516b13266841cd7ac6eb3d22b8e7176d607a027e4a193c15326f2897e926596b1021c7" },
                { "tr", "d34fc31511d7e66501e798039de061c21bdb3c262853d5a935fdb13cfebed4ea7582de107f5a37e9f39c4d1fe805d2b90003f178b02d108b4ef7b6f89e378dd1" },
                { "trs", "17b92cc8205b0d563391fdc6190acd564ec4eee4266480aa8bf9e03d105afe87e36b4eaf43e463135a8b955bf016e1e3e38d18319ccdf51e6a51892b776fb77e" },
                { "uk", "7fb493d7bc593de136ccb9562aaf8f71ad4aaad7de07e469b976081e198d90ebaaeeb61aa249d54f41b79fe74703beff38953592bca0818f78f408d2c130e2d7" },
                { "ur", "2eb69c6b81c4c2090dbaadee1d46fc98d4a4dd0723f4a7667336ae5e0f169a4f36e36b055f052cea1478a4388b0fd58d6dbb9dfef20d61bc44804b3ca21f123d" },
                { "uz", "dec7a389da5f7d232fe5ac13865b3b0f6c50a53a9d10474ee3bd78d808ffb855cb481dfc06eb960ad451eaafcbfbbf8ab6723c101de90b49ec315b258b04417a" },
                { "vi", "d282bb8821c618308211240788c6eb024cd3a0c781e82b4a33449cc2f0f7987bea5b525ad069a88b36e13fffef9bbb5cb8bf627f5cc80d7a1ed91fb8feb3bcda" },
                { "xh", "cc03faef0e47b8ca300665bc4760562df40e0a4a86a85e6fe7edec4d2257ce7ed338235da1b21fe1b6282e3cd862b1e12ac46f2366ed965298545dbbe863d4b7" },
                { "zh-CN", "a52b0a00e8083d7ffc86e85498583726d4f14c34eedcb021bb7b9adda380c39bce6e4f68e77ec0bade7c928c25e3285f173c92b3cee083432cc06877eb8e7c60" },
                { "zh-TW", "a08c61b180117a1ed47f7057f419a57264bb6609718851e64d03bc6afba2a302aab1da5a7b977e4aeb195f63a6e42a856e38427becc395a5afb070593e434d43" }
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
