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
        private const string knownVersion = "140.13.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "b73d6d821fda250c278764d530ab06b657677d0ec3b6670de43cc1b615dcdb5cb1ac4aa520885a90f73c2e50e34aae06cf293a44d90f89891c7bdfc43110816a" },
                { "ar", "5b0366d2ff2a7b9171f70393d8a1d8d453ed89154d8b596dbe9479a0414d9f4487ad351a3d7916b6a9f528862dbd8ed1bd150b8408a9c7f9b4a14346f02f0c56" },
                { "ast", "1b0105ab89f564078ea67c82e792f94c337ad16fdf9d53e500ad07d05fe094b28d81aa4b68f29c9ab030e9f508566701855b16344eb8451a4359e4e5c65cf114" },
                { "be", "ccaf50526a58161cf2de8209c41ad08c6ac5d4b8482568138a095ac58d18a744e2022b90c909b407d12b02521a2274197b78f35ab691cd14aa336f0b9cf17790" },
                { "bg", "55edf1636e6a21af986bad8de6c6f7352f6649b674d4653a648b622a27b2b49344efd7a084653f91422d678fba9a5f1959f9c5c07e51d1597404c03d68d18de6" },
                { "br", "252df184c5999d4ac98eff06f6594861a5cbb1b0094a6e49cf010af6dd1e3fa53ef3cf9a214ea78c52bd29d8f2bf05f7ee6b55eee10f14fa3c98beaceed0127c" },
                { "ca", "f847b54588beb862677d1fe3f257d60c0559a0d5d73f2a2e2f7b219c0a42efc9bf6eb9cc6659a58d9133aa6b9cc866099154b9e855d51fb9fa7be06454a0c71b" },
                { "cak", "3b4cb1c6e8060736297c9b3d344cc616a46b354e66a911de15720bd13641f60f39a24babfba9ac1365d9ccff27b8f2489f525911ed41641ab229f9f0a9ced946" },
                { "cs", "f59eb56532f76f0c1c2f2d02048e933cc27d9cd3fe06896271908d8a1006ab02e0b3395062dc14bf7d275716747358ed1139fd1e5cb2e5cb27666ced30b1aaaf" },
                { "cy", "86a8e33aaa3de26aa94734d9be0871bfefa8667357cef3a8bc180d3b0a842232f4d03f160f5403bc7ab8e87417c86a1863a46c60fdb1be29296c875e06b5921e" },
                { "da", "f975551a7872fbcf2e12ca9728339b01aaf534d32984554883e51bc28f115d1b6a4761a529c680907041c663c54bb1d3101a93ae5bb0f54a1d6ea8aae9ef96e0" },
                { "de", "9e02718a4fcef543f9e4f9f511043f6836aebade0296d03210db43517d1d8c7039c20ad06a2c02398740b092b7f148b6b0743c013cae0d298852bef7a267292b" },
                { "dsb", "d7654584efa13ea4635b4b140d1c0e33195d6dabf4e975873ef4e8e371e77eee6b074982e887dc1162660691d96fd14b4f2051e9212b7a26233e5bda3d067afc" },
                { "el", "ec3e3f6d4da9305f52101ffabe422037afe653f50a6ba157b4d045ebf39c5d077367646c01ca121ba0da4609c0d53584297fa460456a82919efcaaacd07293a5" },
                { "en-CA", "067fef4164ac218c74703b83996ef60b9c93c60494e090ae526be76b87a1a6b696279fd2dbfce3275a7f0fef4bd3865ffd362ec5c23eda4d8c23e9a4cfe6abdd" },
                { "en-GB", "74e81346d21dae42f3252ff9d4d8cdc2fe127308aade9612f6e3f6dbd8efcd892b82fb27298d225c8feeda28b274b5cf2f5dd8503535a06fda51f6403587333c" },
                { "en-US", "085efd88a50a69e77e7cbcb70c2557af720b4afc82a5b87390e8c4710abcd98b35576baa9f680de2518792d84ea2e8f33ab223b5097c06b09333a4a2bd215879" },
                { "es-AR", "41c1c2209c66fb700120c4c30396b0eda163b75ffca3d2a46627730a1c125e1e9e48539ffbad1a6b87577cbdf904fc07d7221e1ae6ceb23d9a6134f6ec8cdfc7" },
                { "es-ES", "34cf8f0afd1ebbbc0d88ec3fdcae72f47d0a89f7baf6a5093d93ef50fd94d780f334a1b88cdd75e8589c49a1fd6691a8098d80f7d963eb2230daadc1da8c8178" },
                { "es-MX", "6695ffe3b2d9de43ccd3a5774f3e2eb79bd39713ec7263b5a93a51de4dd0cb5ec018d216ba965a3441f55818a5ab0f4e9d413aec0fb602425e3a19a53ac74e45" },
                { "et", "11106ef6a9db468840e150de9fed17a9746354bbf4f4a0ca73621435c091ae9ed5b92f8b7dd0e81e4b097ae7b7f99072edf96b3d206c2134fe1917ba4464f5ff" },
                { "eu", "ef63ed8507b87f340de19b844b3d9ffb3a72e98a248b042f5b15342ff211780337563219ee9165c67953f6df0e44cde81f758e6a0e11ef11719606bed4191a88" },
                { "fi", "c6b87926b1aba0063c4e2dbceacf257e8998c33d1cfafc7b5a7325550ad5e66b3b6a9f0938439959bc80824eea090158827f22b8ab7969d4710cd434e44f8cb7" },
                { "fr", "c87de09d7b809b703d4eae9e9638d488cc9cd03076f3004656e76032c68650cdb0e241adff8a164b4e72d18bbb0198792f46cbc8b003e12600eebbc624d86a73" },
                { "fy-NL", "448e96bbec4f85e6000f4798b9b550d4193f97816f682a70f1aa55d8ea9d0a78ae2eeec69a2d01c3871d2d292959735a48fdcd0cbdaab34324d06fe7aa7986a7" },
                { "ga-IE", "42de71daa8c8e3182b34f54cd6c0b70dbe861e7576c9a2dfdf39a66ed38f3139b99506d692ae5c2ad0fc454139626a6dcdec07bbca851c5e5c59479831ecb7c4" },
                { "gd", "364ea660153a47e55117ac0c6d27d169bf47b372a36a4ad9f7dfaa3daaa8da7bf8b42e5de5703391c08c0b03f12b96935bfa0b6f8502fb87de8a5c78ac207708" },
                { "gl", "38941b9d23ff7c842545069a1ca0172ae23bc2c62bad660cf04d6314da1b3a1e85396f41d5e608c298f768bf7a7bd1f6f60982a8389166c2b9e9825b937631d3" },
                { "he", "96cbb4df1b63d63770422b0ee66cfefb6bb1ff0ad98bf2f822b84fc533c8b79fc8c483d86a42e94811086edfaa56d39de18cf917db471c245db37268b857cd25" },
                { "hr", "905e98fecf7c654c72aa97bb35e5bb3a148ac13f6e45bf766a522f1c5d2a2454561427ce4a63f87d63816c31328b2ecc41daff48dde736c26aeff45f475e2d7d" },
                { "hsb", "387b167556541dcc76e3aca4c29590d52cca969e994e01deff36fbf049812b3aa286f34a0d31f37b5c684091f10bc9756e608ea2eb39e4b20cbc8a78285698aa" },
                { "hu", "8b0c9266e9709c196da3bbbc8e18482fad19073db6f627541e14d2e6b2289fba17ba9c4ddd18bb83ddf61f18d632f04e0a517a43fd07d4633528508925664dd6" },
                { "hy-AM", "ba22ba86ee284fe7917bb19b53b8e283228e8dfd2bd2ca4a40b74c0b9dfbb75a4335cd1cfb679367428483c5c890438427017c3b7af8161743b9d5c7026f7d34" },
                { "id", "4c364aa687b835493a3e08b28b023468a9b4ed83297f5807851cb604e35f9d000835b190b4cdc89bac1522c80f05a09cebfe566e30df7b51a2afb0540af28cfc" },
                { "is", "60b7dab3cc16bc34c05af2c6ab8d5f39e241290c4483307f56997963bb6ef5c8f0889282e504ac9a96f4b51934044f1c3369c4628917dc3ef51a956424b80613" },
                { "it", "2b1770ed49d92e34e95e71aa2c5a7f7b918ead43812c6c79cca49918aa64299914a5769650d7a55792166985808229ccac3d7152d7d5dcc302b3d024ae1b1428" },
                { "ja", "de538ea691bd7d0e5f40dcb280d9ddfbb1d2e8bd2e213e024322b6d9cc3fcc4be8f8af66932e4e4ec2adf3a101d31d68f49a1e250717a7fc15a155989e93e251" },
                { "ka", "a1cb57e2cf9488c3fd0c97eff5fd171b6d9a0143a3ee087f8f6ee06d2d96ae2cba429fed3da5ecfa9aa6e31bbd40266fbe06853f25a2c8825a260b755815eff8" },
                { "kab", "f07b72339777dbda31feeb4c36516489c2a8a80fa62a210be791fb2de86373e9ccb4663165f946d46164374bed7717a5c144a332c75eec5b44a2cf83ed7ad0ca" },
                { "kk", "997ced2a8f57907881a9cdbdf948a475e31122518c5da709b7069a9a37f2bf11ed1fca15041c892cdeb46ac3ce0019ae81011e1a719034a2d68a00e536a11209" },
                { "ko", "79d55d03e58b8018a4180ac9a6d6a95eb99ffabbde671c8d35c1d2df4a8e920f6f8a4e9df33d990679d8f71749fd0613be38fbd546cc3f0df96b2940f8cbc173" },
                { "lt", "70d2706a107fbfb95558377ae9cea51dac7e445073569ed295511ed378364575b5e4c09e5c597affc5e91aafb2f88ecec010566adecf5574fbd15ed8dca7bb9e" },
                { "lv", "3b32a1e1f85988774cd5711ed3f7cac08a0a4575fa480ade28dc3fac50529f85259f68c0a4ec3f95b0c620e3e52f2174213e2ad4c224345c80a073379f842911" },
                { "ms", "0d7082af51fdab7e53aef39206fe79814abae9e68eac05fa3f9e8118fba390af1dc341dfedff4929087e88ec90357009b5226c55eace9cf1e5d4003698a82954" },
                { "nb-NO", "b95749c5a44e591aeeb0900d47d53644a6a2ed30acf10c509e4a11058833a4d344278b59878c0b738b717848adb25d0c3192707cc2f96a2cfdae47d837ad5c89" },
                { "nl", "1e27553562d85e654acddfd4b4768201fa232ec3657e3a10eda09eeef5fda517b093e01d2fb5f28ad7e90be8f87e4e5cb3285f1e1fbb2707bcdd5d65c9d5247f" },
                { "nn-NO", "9ed55c17fdaf7dca3dda4e063d6582f7abee59717bde8f42b0b0ac51ac032c63b1e25247094ef87b6ab54fc2ffd540778d69121104ebad690919599b6335a560" },
                { "pa-IN", "d4116713f1e2636d204bd74d0916b2235bf11a932e581733b42ee9b7c070c30527a65f803c701608a8a9dc768a40d25cfec51af82408e56306f973c6480c37f2" },
                { "pl", "7de0b603b3fbe5979787d4919aea76e68be504a59463207828ae3c2e8f92831a58edf6832859a5cfc669988cafa7e479b91ed95518d48eff6e2403951be6b93e" },
                { "pt-BR", "1dd3f0707a9cb8603bd70f65939574a8c299640f7a494b379fe18ce7cfd6620870900268826575fca28d9941db750fe4aa04bae56ea6b35b089d98eeffd6466d" },
                { "pt-PT", "342fa26e11c1205995e68e9088d6d6ba6cef7a3790434481594a3651d1932b5cc5af1f6c056e97d01bcb55f82035ca6c1e44349ff931fd7086a1ae27c49ab73c" },
                { "rm", "e466b47a8da69dcd94e4c9d5fa0982b06621ab60f6e1a121c702cb469e9b66103d4e95c8b7d0535a5008def928f858caad913250efbdd914a6581bf8ebf23c75" },
                { "ro", "21e810cc075259fe33467d80124901237bd945dbc43c65b4e3c04d25f6c0ad99f8f08df0685ba5255b75a639baf3ec469b942e7751199f574fa89456b3608544" },
                { "ru", "b6648943fa643b785006d9b166bd0086244707e7ecba5c3509ac07cb5193e028d518ad971eba440e927750e7f9f72a5ae54c55d6d15bc4127f2d09d128b6471a" },
                { "sk", "e585e58d90c2185a7e09507572fe9cefaa5a07169914a13aaa7705cbf644ec23861d9cb508ee13f7de4b8537f091e1f5772e1a9d76ee7bad14aadaf70b96991a" },
                { "sl", "d89a76db02f41f8949748f878a904526fb1b07657ab9008c4d20e0d57f7bbf99def3f9dc5433db5e8b913f3ea0bf5946b284e8e5445046c2c4c8394338b83e97" },
                { "sq", "d08c0e26dc6e3a30e14829cf6d80da4dff25f04d192262690bf253458611467d3d256d666e423187dded44b0096e3465b1054bea8ad4f7caccc091b3dc8a0068" },
                { "sr", "5861e67d289928b3cabc1d78c363c5f9a61da6767cb149bcd5da2f78779b9ec6a8db7ee2b7f7adf78f006c472f6a200e7cb924562f6c54f5b80cebd972181eef" },
                { "sv-SE", "8f1b660296e3c6ae0625698903da0f6163bcac6b7f75681042467b545d05ca0b59c405f7f0a5e813244f473e541fcbc806c18f5c8708ef5339f4ff0ebc16ed5b" },
                { "th", "b2229f528615517f2e89b2658f847970bdb6535220a27682e6c681fd43248d899f458702ee3c8e9a76f99741031ef01da7672b16cb4fafc296296f1d65927f89" },
                { "tr", "7a99b527b027845c31bb1a4018c54aad51b5493f3c4d49d5a165637c1c1e0a0c1d6f306831eaa8d0cf199a97b3733b207754e5e0fe99d556e61a4e34bb24d868" },
                { "uk", "c7a204448018a7ea4eaf220b44ed34c7e5e3e33df8324b1279f6fc879d6a6d9c0c8e3cee40aba3192a449ad0581ff69d7cbf1f38c234604dee6e029d4ff8dfbe" },
                { "uz", "cb70a2129f77abbaca02921eb0bd42d77cd906c0c78de72f16d88eebfbc8d8d30b7271d3f0c7ed96d3c1cc5b15c5ee95b09341bca4ea6055e675f7725e4c5fea" },
                { "vi", "5a83aedce1a2d97b42b545c303322a2ba65c437f6ce3cc693c4a103096292719248da254e57b102c510a0cd3582579b32925c7ffeccb8b96b9004ae4391550ae" },
                { "zh-CN", "82a20e8f4f03881c7864c882859fb4e804f0e2864d290362fc51f1afe6f93d7a608d1132509ab9b5bc0ed9890f79b6fb4691f759f14b2be4b86a94d6bd7e04b2" },
                { "zh-TW", "1eae86a0d9288e09839b88e927546735bbcfca363fbe4e007b0468ac7716a37a62bab42bf3de9205971c121fcbe4f28add61aabff381834f751a050453ae77c4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.13.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "5ee469812db557579793195b21ac05cdebf56b42ef5711342b11a5bb2abffd9dc57310c2625c748327ff74ca3c587f79543e2017b52bd5bfd376f65304426e02" },
                { "ar", "2e6628f2d57103d8fc5d51290586d2e76657ec4de060649ef33dec7e44e379f1d42b836b03f1313f315d69a8352970944eaae43c8bf68bc6db6ff35bb91e2499" },
                { "ast", "cd67468a74c4b20f6ae3fb7b5bd5615508efac4cfa3bfcb52ff5b4387bc3e8fb74374fba4507211d7c265cbfc8ec0a5b745c621b93960fa2f6cd5a8532693966" },
                { "be", "2687867c1e18d3c83841407314efcfb04f1422bafc24e63f946f3891e84fa8d7f794e53d762680c895e268758982ac033e8323cc5f8e79567f9521e4daef8270" },
                { "bg", "fa5270fd4cf48d57072556292f306aa9992de8c4c796427f70ec84b06544b19f4b0b6cb596d90cad6a3da89c9053ab36046987ccd5bb77a303d31fd5638a7c6a" },
                { "br", "d74aff724ba2b69852afdd44c2955285739bfe952e68f25b100ad2e53a9075107a0eafd919289c470251cb65b7bfe78c7d26c794326fdfff93cbf6b0310af1ce" },
                { "ca", "9b236520c226c1b902cc9cca74e7581d1765937a94ee64c770dd2b10a7035c670a0bcf71fa1a52c4c18d230fb6f3b441eaf7dc4cb9706ef7828996393fd00fe8" },
                { "cak", "e48c8ced30b31c37fa6c7e48bd5c397f6e99c24030d8421f5bd31283e765b6b33da823dc2f900d80617852b4ffff6af40ede8a7f75d7ba7504a74ffcfcba83cf" },
                { "cs", "1a2923fe2d725b302794512f2224125eb5560f7303bda64791202b4295562b8ec6a071c145b9eb43bee4dc81ceb47efa9ec7554362aaf1c262f4f50218b3ae29" },
                { "cy", "f15af0e5cba5b52fe71603952c1363b3ff21727107693270f89674df4bc518dec31abc88144cddc5c5a772c4caf6a553a4da1489f0347192afbcf27ec141c7b7" },
                { "da", "4c366c2acb35b90a3c0389a09e40d83d62aedf137a9cecbc617045c431fadf32a49750fcd6e64cf0d675ac5cc0572241cbd6a67311bbf945dae81b6e3df35c4a" },
                { "de", "62ef938e5184704d05d794a73c3d5a7348c01ed816a704c9226e473e5dbed104afa1fbd32562de3b25aceb9ff1cd01d7e834c2ad40ec7fb046f5bddad5f81b0e" },
                { "dsb", "f0c29d8c32bbad52c5b5fda637b09b33e8aec6b087f857bb52a6b62ffcb3050e09f8c1b117dfbfa5be9d6045fa150aa8ec2ae22fb9b378c3ca6189b638ed23aa" },
                { "el", "b8b1d71f1a332256c5fb96664271dcdf199377855a3e6d663e9b018aa0c5b32d166cda4109de4ff8702901f57bc4635c20931cca684dc2294b322be9792ccc72" },
                { "en-CA", "3d3c058dec38f5f90aee9dcbe38deffe6646568cf5c262291f121d48d8c95b6c9d4f5c24615c9c2d155fd62c480935b4ba7693ebb8101162f3004ccbdfa8f354" },
                { "en-GB", "1f1b67fc180fb52ba1757db50af4e5fdf6eeed99b644935647cbbcb271c9081b5306fab17832d4cc656065d446000a029605094be0d7298792745372b549f392" },
                { "en-US", "6d553ee75293f2a2fc8576c3244e5d041c171c6e32c2997e429444f59925e502f697966cc8646154fad26881a62b3172c88b415dac9ff79e1fd91a414e8071cb" },
                { "es-AR", "a772d2a8bd478e08095597b615d53dc0990dc27d7db4de2c0fcb48e3ce0b5bcb2a8647ce381cd9525dc825c0d7812f1dd10b9c1a949a5d16e144406e98a62482" },
                { "es-ES", "0c44e49368af43438c155e2d42cda1a4a7e028bdd048bd2db86d14b7c670316b903008e9a5e011fa7e357e33bfc18ccc6ead5d180a0885029cd941463266205b" },
                { "es-MX", "9e7a4b4e2dd8e7347cfddfffa716dbb12a137af381b63ee104fcb63b33c1c67b34cdf21e9b336bfe6cbba2cb650a42f93a4c63c385635a764f7b1d63a994da78" },
                { "et", "64aaa608db729c9dc99fbc6b6180508b4ca365f162b6cd9cfdc657bc6012d23af25481648e49f0bd67eb761431d9e7e879f975689c410240c81d5613d24fd2ed" },
                { "eu", "f382fda06a67b43e77a059c0abb51e135bc684337ba7351a2eda2aab71a51ab575b554df3c98e129e0c53da8a1e40f8bc611588a3adccf1c7628251fe79cffe4" },
                { "fi", "a3ba3608262ee8c84226b25bb474fe9654b2a1f10d36342908a3858b684560ddcc22871a2b76ca38e02a449dca75658a75e741b40bb2fccd6014e4d9ad44b0fb" },
                { "fr", "f0fb2aa90b06b8d22cb377504b50e0564fa884e0d449d3dd11c8e337dfac74b24755c08cace416a74f1138a580bb1776e78a2c1ea722709b5b3f513e5af5cee4" },
                { "fy-NL", "59a212ba3be0cd9a680cdd67755fab1ab12375f0251f7d0df19a35435a863966ced49965e3e900c4811d72473bb6292d52c65aa3466c97523fb71445e1cc17b1" },
                { "ga-IE", "74c554415d8a633c081a8642bf5762f12f83860f26886b8496304a65d7148e27b96439f6b9a0279e84c249dd84336c135efd01698682a0f679967a36f50b947f" },
                { "gd", "17016125165a1406f75bb06587bdf42de72d0247bfc6aa2967b7dd32277ea10a39eb8dc12cb0de3f9c04867dd4359d0d457e4ddfbc287ca400b6f30050c3e2d8" },
                { "gl", "f32b1a764a2793078aee8e50acaf58fd437c4798fb70969b393741ba4ab5f14e465a8d748cb0645bf54c28cfd6df676f63cd0391b2d954761b281aea0e345428" },
                { "he", "144be27484e722e1d44ce765364c934230a74abaad019eb52b67a59b3d918470302b9c97e264a47598389c91e5eecfdc58272dcbccf1e0108ff4730596c2734a" },
                { "hr", "b46568bd45dcd833331feb389bb0ecebc673cf15925c48bd48f342788f8225e533747b843d5f6c86aa14e369b52e9134edfbc3c3943c25f32f83c0adcd193e1b" },
                { "hsb", "41859a557a66ed9a7407238b3786aea147e8732a8cf235f1755efe346abaee4f07b7b943dd0ca2a4a79cfa0f782c7ee15d3e8e373ba8298050802e1edcd475ea" },
                { "hu", "e0dbab91d883dfbc9090c1e1ce5eb780c24bdd8e837a6a4f29e055623a30b0e6d0be19d3b4a96a2bd7770e16c500770e7d339281284ae0a29a048a5d4a77f7d1" },
                { "hy-AM", "ace08fbd6a3d3af9deff8f771b79dc024125395568fffd62526e37aa85f333a5b31f1fee6a8e7710fbc35c0d2ec9c0fe276aa8d46499ab18be64034bffda75f3" },
                { "id", "e754dc1d4581d9fd7608abc907e1732ef949e6e1b8883b1df95a2a76a2a91cf9771235d0cb2388c689f1091192f8ed42d9a09245c5ab7c298c0001f97388efb7" },
                { "is", "ea4a560af023dd781837d69d0df7a310cbdb8ad87a29008a712bf63b92740078d5f4a7ad415411bf732cd97cee0cbbaad6d2c80219fa71828cdf6cd0c58b389f" },
                { "it", "5d96632047fc4930d38db3d27a0c05f7219e2fee84225329423f43e6340c99ec9db879cb9accf4917970b42739c0f26f9131b76c89e6620f431983b9ca1b0c92" },
                { "ja", "b4f4cd1f4abb62fd38761b99fb6c12860850c470618dc0a388fbc349607660c8012ed4c652d61bc22a41e5291d4e47bda5b26416e3e98a4c7bd868621cc3e376" },
                { "ka", "b96c352e244571e88fe1a624e9ac82fb0ec860bab4b39c135c12b26d234c856d5789031567f5c97087ee2ca663e68f1ff4d1abc2a4d71744d4ca4b3d83081dc6" },
                { "kab", "2ce615a1b133e35fa290bedddc4b009fc7c1227714b5cfab51cc481022461a053fcbbf9ede715bb6444b27455616b0cd8f34a32c4c4d8cf5286a32d7e4d38877" },
                { "kk", "b45a33ea015141d5d52bf71bbcf356d9e57b018ae46b9d3cde2ca644ad13df912fb4bd740af8e3e5d2f5369c6768eb59bcd707b559051b3178eb19b5e88b30ca" },
                { "ko", "ac1c4182ec796ba8a5212c2068bc2dbae57efccd115a6e168f1ac17dceb1d0b74fa32e2f335076513a92a8a4e942a92a4f995796ab3a35568636f274056442e4" },
                { "lt", "2b4ddb1e8f10742c67607ca6e13eee1d79cc2818909d76ac67690362828459fe7e732a3bdf8a12f493b22c5eec0ceb82551f28e1b4dbf9c2f535a6d5c32d74fb" },
                { "lv", "ea322d00dab1a8a0428f7c9bdc7cc1c6082fd99fd82a62f817f869884e5adb7c77e58cd567ce458168ddc761abccc8dffe46dbfdbac1994797de716a95148a61" },
                { "ms", "c6ff670f31d87b86fdf3404bbeecb9eedb5e5249ef97a0a36838c2a9b344d0e98cbe7debacd4fb0ca15e23bf4db4fe4c9fa8143f420ee2cb237a69aa7f251eb5" },
                { "nb-NO", "71385bb24801d85449946879c33719429d01ce0feace0998f656d06e042a7fde2ab4e3cbcb33651540db2a67e6e9ad16ec92d058707799ca02651da4b930a2b2" },
                { "nl", "f866eff17a5ef13929fecff54c5eed1167b875e90afdcd2d4f1311101e24b937878e08eaf2561fc33e1c78cf41a65e4235feb8145c8eeadcce5579a2ac0fffdf" },
                { "nn-NO", "4cb2ca51f1fa72b60c5972ff30df3d4f1c2737ed8e84d7785d5810ad8db047c4ed9e5ae59bb1a8660f4c04437d23806b266c90997a84f933333e094cdbf88a92" },
                { "pa-IN", "4e77a3f76b47efc7dd874fe36eaef41d87b613ff3b95a707415e14aca230e4004b03d2c2c61c18c86945df80b93aec1d1b7e455fcfd34ad7e08465f25931db95" },
                { "pl", "15e2c600e44b4698b5ce8cfbf1e686e0e685c6bf60125f4f2b9d1f56c693b7275331f45e5f9a7f83583e5f3031e153e07808cc4a2c736df2e2cc0b0bf1e4fcef" },
                { "pt-BR", "6a85f6827660cc53e7b30d15b390e23a9892d31307ac1c6d1a75b1443f4730e0d299b00fe21fb2bb038ef71c6f81ae1f8c353a11bdaa6ce398bcc25796adde47" },
                { "pt-PT", "fcba308f7bb18aa0cf33c9fbcaff493f33af0abccef99c8c968509589d13b5acfb5794e795fb1fde948c9efab5828df7a9bc8b1ff222ab87924685adb1db6db4" },
                { "rm", "9749e29ad4db9ab9f1b77280726883945d397e4937325721670e85ec5397b756bc760fa46b8bbfbfaedd0a8399ef6eda407838d4e695efd9e2f90aac41364416" },
                { "ro", "51e89d2d5e629ffb5bb944b41028c860ce3d0c43bfcef369efb6c24b9cc26fb80caee9b79cc79b1927affb60a602e69f6e9b47aa43ad6667323a8a9514520ead" },
                { "ru", "487fb00c2a0326d7682954d6192a5cef0a24a5d00960e30d1c32a041692aa5cca591aab0fd27f82153c6445332f23585db5ae0eeb93ce7b86994c13093beeb71" },
                { "sk", "52a56eafae522ca341a1fba8191f9ad07206495c2e30f8f5ece612a9a00bb49c071c9110d0958e8319548d2949758c8d93a006f3a6c7bd4123af8229a6ed3225" },
                { "sl", "a809fba046552880d51bc321cafa5eb46c6dad491db194653fac326ea91e98ecec9f58c5a116a2bd9d6a5e005ec064cfa0c4a6de41f1680e314d7ec1017bd458" },
                { "sq", "c5673a39b0d5c261acc3220593c53da0c1016b3c532e462cb7b4f109660ad3a331c59ec2d6da00374e13e847816b0553b7632d7510b3424244e503d794a787fb" },
                { "sr", "af9c69e4c47a7fc463d63fc33efb05d03c07158c67ed742a709116318eab919d6d22ec282b6b21351ea4d0cee2b66ad3e53543fc677dac7f511f7fc485ea50ca" },
                { "sv-SE", "13c08c4619f9e5766646bf47f630ed172124727e5c2ab524a09948d484bba8165ed956ca89afa8f64ce56ffd99af4ca71a7dd585b166ecfe256e813cfa65ee72" },
                { "th", "1413247f27c3d09a826aac41d1a4068a2de98fb242d35e9c2d82d0250be897ceaaf930150f939b9af7d7080d7689d4b14c8b8b43c6c0adc8ee7260b06cfc12f4" },
                { "tr", "97a79a26559564110f76fc46a87a31a90037d4168e8a041917bf2a9e7b1ba8b37a17877618da00f4d2be2315dd088a8fd32a15c6d597125717befcaca1db39c9" },
                { "uk", "bf38fe840ac2911cb56e55ef0663651fcad0e47770ed3bcfc3d7dccbeaed568fab49ce0c6e48585fbd57f806391d84a4d94a2f1a052cf47df1a0ab6d48cf4d5d" },
                { "uz", "761bc10702d4428521854a53873c00acf5316d3a1cbc32bd25d414d371ee4c35798de7304825b2126c215524830f81103baeeddba4909fe05768b199030aeb64" },
                { "vi", "6248503b0a59d3d028312331f3039e9b427293debe2261c73707a5ddd0663f0da17046981d5cb43cfbfd15ef6724181a0e33d7b40ecd72c36cadc3b72e5a06b5" },
                { "zh-CN", "8d4e2641564cf17a677a9de4671f873bff71ed513cbabcf6710aa43fff8b496dff51185fab807f4f1946b8585e3482dd3b9a69f80394117fa15c377950d03b86" },
                { "zh-TW", "dccf7f3fe948fc2ad2a5ce5e34e465966021b042e294811d59e6634ddd98aae93bad18c48efcd8b310aa3ef3f65f30fb4bdabe58368dacb20b08d07145eaa5bb" }
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
