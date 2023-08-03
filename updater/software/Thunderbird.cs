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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
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
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.1.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "12d70278bbcaaa41d0c27bac438fc29a394fb84d8b0de15e8d5b377bc137cc74e40cdf88577a98ec5b7b4809dd687afefd51cb417eaf629512b7f5552e926aee" },
                { "ar", "711c672e8fa2a178b238d333f55541e094b9b9d7b451d15e9221433b1783a89eb67301b024237784bd656a5412f1f4dd26eb1cc07fc1e73f88434c72277ad510" },
                { "ast", "ce0bed80fd871c580d55d4c3a4da0b302ec4cc81062b776cdfc52329864ca9ad55605cc8d87ccd10efccbb59646cc899a84ae917abf24f35a13396423f1cd528" },
                { "be", "8f185f51ab80b24e0b37e0e9a135810ba14aba924280f520ecdd22eece38b042f310200c4237c47d2ae7b762ab2bc94cd7b8313728c2f57ca2fc763d789cc649" },
                { "bg", "005ebc2be2ac9bd0dc2859e12a4f9b3dfca2feaa980ec2e55cdf2d2231730dbb229a1b1cfda62742727659ef9da4e4c83f4252d44e512e15ec5b936cf0fa6ce2" },
                { "br", "e141bc61cfa99632c330f58a798c115a6860ebdd8b0f3d0d8e90d2d962b93facb111183e2dd1ef6a134bd767d9a50f4127e84c7f750d16cef7060ae2ba2104ab" },
                { "ca", "ba14ea50e62cdec0ae6a9219875f3e111e860c031c8c10237cdbcdf38764e4e2468de69262b754e41ea78cc83368ff85232acf0bcd90c424420a860f75788f33" },
                { "cak", "b18a5bba18657ac5b4858a77a6a35208f3db67e78ff520a5b5e02ec7fe2913f30dbd8f8be4ff5a47e0165dbd0c55ad65294ea6df6481e29f066b40921e4c7598" },
                { "cs", "bae433c42e2a832baa3f77e3f4c0a64f54e0bb695adb5d8d483a3bb73f0f0cd8b16b9b6766d6ec30729b9273775e97cfa7c6b44e2b96da743b290e1efa4a640a" },
                { "cy", "7ffac8f039cdd84888614d40af71903a90bcef5d0cc1b515fcdf9077e2e852f96829901465f9e676aa500c50a26fd4953d9511e51d8a2cae9f97b17bcde7176d" },
                { "da", "7d1e1f11a9e4063b897d91f5081811724da8f507e7d6b53ee02db0995791e6e5544af248429073f4395932e4292a1eb8620b5701f14e05339150b7c0f8e8149a" },
                { "de", "c4f8f3facc553b9da0f1368ff619ad4dfb2559e3b7a976f10e8e9bd071cf02ec3543efcbeaac1aa5d3ea339f10c1ecea8e555bd118e0c5f95aaa84498aba2686" },
                { "dsb", "49bf87a3807532921cbc801660471ef53a0e883b295d5049ee050c75921e034ff709dbfda49d8d9cf6a629869536d75fa91e8b44c302744cf40bb8a8431c57d3" },
                { "el", "c7515f5411c60063f9b0e8554c13674959895db080ede1b2706459f21ba75adb7a6d5a21d736c5ca43925867326aab3b0168af943cd468ffb2871a4bf2419348" },
                { "en-CA", "676de64cce2c4455a691e222101f527045a5a7fd9100586d34d6b1307dd261a1b48b88fa468d394f2a1885e176673c34fe0bc15339af0942d087a5fd7adf5b7e" },
                { "en-GB", "b8cd9b87b38941e375ddbf09f8c89d84e8f5eaedc5028d8706dc224c8c387524bac16d20122d9c11e788263378f332da80dde999dfcf10faee090b2eb88017df" },
                { "en-US", "1905354d4258184cd2ccfd8f30bb8f2afa47b8afff6d6d988d8c24513b35eb577dae989d44fcc1f3c135f87fc3e70459904ed2d62289c3fc1d48659896125679" },
                { "es-AR", "2c382abcb7b6e397be8fbd091bb315b194a07b391af0b10753206ddeaa4339439cbd54c52568b3054445fd09c5a24d5373a4dde064c7b298823efbaac75dee29" },
                { "es-ES", "01d13b1514f9783ced94957948fcf93532a1dfcf10447aa8012b8e335ca4ce95bec1a75667e1e073e21b05e6242cc08532cd70559a426d7573169c3b85073bc8" },
                { "es-MX", "e0c8c16a8f743b6f37f9a20a33ff4001a128d0400cd6b9d9a7cfe67ed854011a2086ebbb6ce3280a41adb4badad2a96fdc49b0066ee1fe1d477de37e4b32ad44" },
                { "et", "dd5940afdf19ee57eaa842ce64b61a18e812fe8e47b7085ed036da6aae29b79f3ee20ee25d1a8e5cec3ce54664a2e54b5ef2d2a22ad1a70d38753b0f87446104" },
                { "eu", "5d8fb400b977fc05d2732571e59c77f09747eefe0c3e436b03bb051c0c27d98db6f358f5233c2de9e491b040f616669efef4c68df7e1b643f4e69ca129065736" },
                { "fi", "9f566b6b9ea95297be4d548a03ae5e5c3ea83c1d994d6d7691aa9b4c1a54978d96d6caf52f8eade6d5b500b9bd809b464a28d4d748807ccba6ffb7a879d8d167" },
                { "fr", "ecf2e096b71ec81c89f9de571e64d2cb0176046b4cb52992a8e306cbc829b30794bf5293df7d34b2add179a572393048ad50767b8e2344d8213ec642631b8107" },
                { "fy-NL", "ff4589592298ed2bea47abccb84bf352360a4d2fff924f29a60f8874d304fab26c4f2cb15c9eab5d09a22cc6ce7109dd2966e70dbc03c19d0f05bc6af292e108" },
                { "ga-IE", "7500f770835b764d2f4d0deb174b9be0e2d3e00a7c46d2a8bd0c9b6c5aec13348d79b1b58960aa28ebfd8f65f7071ec0fb36b6ff20c0e5a2009541c4d5bd9981" },
                { "gd", "24d2e7df92fe9de21276745f6a7a3e92fbe167747cfe27d25d863cd14151514ba93d013b3087bab6aba43c7b1339a5dd3c60954c6ae9610d0fb0a49b9b4226dc" },
                { "gl", "ae1724d5b697144f6aff9733e9bbde26a78b43e46f14bd4f752f2851791feaae7697b7009819818e19a5e10118c082811e83f33115257b9731249b1da1b6665d" },
                { "he", "1c4f4601bd7c7acde5f6804d642388a073fbf9543e5e0e26782ae4302e32c4ad7b95d335395adb6844546df8fb466758cb3e46df479c9a3b99f4f8f5a090e555" },
                { "hr", "0345f4149445ec69cdf5aaa0c85b5d3c32c7daa247b916be1b5692279a7934e80d5cf945e8d7a474029ff5dc2997032360dd52b8b33e6fe42a46e9b250da5fd7" },
                { "hsb", "1d1f9c01af08a96a2674f25772cccd5042b31e321620a21a690ee6f308ee258eb295210e1a16b4bd076610cf3c929c47ec02a5b05db9c44273f196480ef720e6" },
                { "hu", "1e772f4998ef571dedb44c2adcbc09999fdb2444a719b5e0a0406ff81bc93a7ec998b180828cd65bf3e266be20deb43e0e59723150a14c9f9280ef44f85252d2" },
                { "hy-AM", "d9b6cce01726e2dde6fb7b3d3a84c77bbde11cbc7eadf812171a29b3b571f394a5e315cc935f0d0bacc85e2c096d4f04e10ffe583697e5fba62264009ef4ff86" },
                { "id", "6cac7f22d47f035bd037d4e8a628939eb751f8f5353832ba2ccee989d13dc0fd3dc547b585132d3b3d045ee98c7140e9a0297ecb0aed87856532a7aecb4aac39" },
                { "is", "5d6a7a9462f7d1b211874c11cef171321bbb86a6266c7861abba8926b35523087a98250734e041a3caf443c0642dcf3c1e0302f261ff62842a43cfbc751d20fc" },
                { "it", "8fc5aeb612861ce3ec05bad79be4839ee839e50af39b88bfa3036fc46561792031eddc9712d5e56b5ea2af62072ff607d289b6bcb9d31dbbfb94896719b3becc" },
                { "ja", "adc50ad60508a1d4e3d087f928ce61540598c0f2d9a4d970362b92905f83067ae3ad06a32e854a459b84dae1aa0a4c71ed6dc94b8b9c5f76ed7316af7a1dc6b7" },
                { "ka", "762c4a8746207ddce47598c408806413018ff4dbb74aa1cb7fff640f36719209f8efe9cd55e69489179fbcc9af304c71920b9ca74affff2fbe3b15e844a7998c" },
                { "kab", "1462e77dddc3686996f65a1665048c933f5e0d53fe2167b16f0e2060ec920b14c297800ead1dd01d4f7000bacb535b15ff20a34f06429c1172ecf506df9a258f" },
                { "kk", "9e1239ef349f6566624c1a30dd2182cccaf4bd02de302d8c1ed1513b2a1b78631ce66246f7abc32ef43a6d0414491af82d25f57aa28c82dc0089c1ed460ee592" },
                { "ko", "9613166091f6bbfed34a8f5861c8d148866f09cc4789b6ac3d53822270de194e11ef9f452093b98b516b0da66b71bd779051466bdd74b6e41b2c30da9f533fb8" },
                { "lt", "23169c3ea4e2a2778e940cc56c32f5746d6f23661117113b1ddfec47928bb3e7beb385f42ea33403ca0163f09003e3ec8964a246d6682a1fc01631d3f0ab41d9" },
                { "lv", "84fae8951b0a01a0a83016ee8cd012ff48daf7bf3c41b18f583ce80b30e6d2050521f8180fe76410cb99372c2c49380586ee56e78e74e95370dea4ae06f0d42d" },
                { "ms", "ad0632a5925acd123d6e7cb58a14a6ce8ee02826dbc64d2a6a60ac83b27c6d9539435581b151db9a85d391703381b5d7bb834c459e3d445ff7bbb0ae0560ba98" },
                { "nb-NO", "b22790630c5318e5594564bbb68f7fdce39d9eab7174c37bfbd6da0fc855c37acf6f44f298db75810cdb903ce408ebdf8c22d33601134a692f13e629f72abca4" },
                { "nl", "85bac79b6b06698e2209063f70e9ad55e5a4f5250cbb1e7657d7b6afc639563c42797925ba9e5896122b22f2d39eb9fac6d3821f5631a105a47a90e39393e1d1" },
                { "nn-NO", "152bc850d33aa5bc340f772d8f00d40f0b8e6be1457070a140587ff4c1430858ea8833d50c09ee6a6b3109ed329d0dc73153d093bc9b1d53eccd63b61976f551" },
                { "pa-IN", "54a993d14142fb7baa8700137728276e832e011b667fd2ee42a77c8ab83e37e457ddadd9e16ba47994cbe79f4918090b7b49192d94d852fccbca985b94860400" },
                { "pl", "b3af2a23960b19ce53fb7383b8835182ebf65a0cda7ff8848c0336d3dbb3ee810ccb21d1f2a11d9ef71af767d75d449fbb5a1355f657e7493c11b705084f81ac" },
                { "pt-BR", "4c1c409cca3afd2fccb2d76f9ecbf58de64e3c62a02fcce7264c2a0fac5cef77759306f2a7389b934053bc9a04569402c28a755dfb4dd865a400ed4511fa0b49" },
                { "pt-PT", "d625f7a743b55e2f1370e54b76f42356ca9d321d92583550a5fcbda3831297c24d48063c154679c5d3824d1352bbc1c2ed4e0ffbcad78d00d30322503d31143b" },
                { "rm", "e2c471f900c6976135688fbb962c5a50bd3461b35aec46894be9a6ad666edc4321c13e2cac3fbea5bb6c11f16577bb448de257128ed78d018888d2a68f48d120" },
                { "ro", "0611d321eeb9dbc8891c715f4e276304ad6a70abe9abb54615c03d52f885fcf2cf57fa937b7b598e68d580c1ed80cc9af050dee06e3536252b576721054a66e1" },
                { "ru", "e50f4ce481a8c6fc7dd8889eaeaf21256454fe7898c689128a5b2fbce0e143d214169fe180be7c9fe54c2211a9e42e7083d31f5c7bcee0f64de58cf8971e4bba" },
                { "sk", "0d8c36bf730fed9a7e53f9892554a432aad773f033f8abd19263d1029f68d3ed2500ad7553fe9da13988fc8d00e0be76a492c0dc901e7363c221ef23e91fbad5" },
                { "sl", "1e8f7c76c76a0635ca1f59cd26c324308b33f1a45f1557d6986dd7263aaec0a02da9992607e9b48e19fa2ac7baba639da2b607131394cc0f60a120bdc0e7902f" },
                { "sq", "fb6cf37b56df2b03cd64e50179c7504ddcf74f2b2e11514114a32862508f7ddaa6ab9f1dad39e825b9f1ca6056a08d934597a884bf46ca12191af0975730f9d6" },
                { "sr", "19f29fd0797c1f93a1a6968c3fe4c4205e951b490ff897702284a8704997ae0c239dc2f545ab1ac73ced4f50657f29cbe6f69418d8f84981494ddb1f8ca3760a" },
                { "sv-SE", "3a956551778e6f038a331306ff40c16c8f1a48e0df00e28e29d7f00bcdca44fad38592125a7682782f6fbc1b3d230c7755f94cca1a7d2a28906c7cbf21abb626" },
                { "th", "aee83e437540b795b41d55d404231096895f0f3b3bf96e88109266d455259d7367c60fb234922df130fd236ada88198fa398d6fa12cf12925294ebf408bb6227" },
                { "tr", "b8abcf1fdd8f865d95f76b93982de7ab8aaae92a8d7865cf9b822e54d782f66aa386056e0e0d272d0d4ed711ecc2df3a55cbdeae226caf0f4b09431a9bfae29c" },
                { "uk", "86c6b867d6ceb0103a4363a247c1094e3da08052265e8c20735c49a40f428aac961bea20bf74d0cad911e59ec4ffd8e542029e43becb6e98d92626b527bcd295" },
                { "uz", "cae4f72373cb278ae51ec286d3cd7a0be6c123ba89b8752f55b94d3b0e16fd7ddfc608484b5645c32d65c8e8dbe24ebb91ea2ba953b8f0f87e6f47505b1fd57e" },
                { "vi", "b7360e575168e1b310b492c49f39774089f8e108df8a891d582aee053528eec3e8b223e318ee77cd4fa0cbf52d47b32266b96237455179fc243427473047954d" },
                { "zh-CN", "ad0ab09ea64f1d60b4e7cb15b7b8387345a61d0de2f27759feb9b5a985cffe6a13688212ba66518e74a39e46ea4abaf3e69e62067526b5af803fd01ec1447a74" },
                { "zh-TW", "a5a3c5d82b500552c8bb30efe681cf9ece054431ede5d60db0bec412110e8d71251109851cf686fd7e77773f5b2d86684abc70eec341885fd978e0beaf5ce4ed" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.1.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "3dc7789dedf74ccf682a3a009b1076765c95ed8275315b5f638b4c8604ce3d2897b446ddcb260723151a3147eddd10f3f5c383705e412ec867fe05875203ce40" },
                { "ar", "2ce960c21366344430f30c8d1022db8026dad91c8e7d6e968dbac1b2c43e5c5cc01b8bae3ba6e5fd538dc28ff35312b4e6d0e39e05fb8f0f2004c53271be6737" },
                { "ast", "97bd9eebbf2353e41ab41272592406936bda97abc46ef47f2817f4a7261933e7f2b5404ea3989b3dee7cef72a8dffbd241ec7d1c2442fcc45f2b2a7a4fee5fdc" },
                { "be", "70fd12e544e27dc8501e02b1d39f786622604f3ddd4cc6d77b6a20bc749d24dd97ed4106f26a838ac0d8295a8b7e93aed73d2c5a9aab25372dc3568d969d85f3" },
                { "bg", "097ca011a81e6ca50e54ff6515781c8de14c5f2b6dab79f306c623906ff3f2dc15998af3e0c7bc62877b9bd4a9e89a859e6f4b4cb5438934e3e66257c496a3d7" },
                { "br", "d538c4329d1b873ba0fdd953bc80b1a14ace75942cf23cbb94a83bc8eb43f0d732e86d6411259dc90c4c0f8abf8dac3c2c07260afb3d61204f7a4a32e20f657f" },
                { "ca", "938e876b9b9b14bc2eca5389e20d2286d3bc5a0ae87868828401e5840cedb732f6e2895145e6f89eb8a4b0d196a339f1cb832b610e69e6a2dcdcecbabfd7e85c" },
                { "cak", "f319dd10959aee817ac7e1cbb35a76447051543cf82ac20b528fd2635a7662c1dac4fbdb1efd9f1741e4457c79a0216e53767cb3d96bd9712da4642eb8c1fbd0" },
                { "cs", "676fc1f4f185b461dd0b3db09e8e6eba85e0c355ef62f838bd0de2b0ee245854c6d73a39b84faf13a23f54251dedb66b72b2a7728a64708cece4094fd9b88ac3" },
                { "cy", "e25e5a44623c5a9b0ec7c3927fcd21b4b7b94887e086ca8d8b82bf6181c2a898d0c7a683162d20c47929c424c65f4e8c1e26e523cb7ed736bb372c007f0c029a" },
                { "da", "51c616fb434d5fff40696e95361bda2d98da1bcf4e6ea7c6e5d914975a56941da3380907efe2961534f29b59fa4a9773aec1c0a57875678226379d4455452811" },
                { "de", "23f2d8e9e6f8adcc8439f22821cd3ab76429a874bc672c885a88c4ec77ae3652673f70926b195e3f8a09f08700bf248eb3b8c8cd228ffd4bbb9cf05847ce8c77" },
                { "dsb", "c39bdd63985da32c53660dd125fba089d5f164e5406bdb7ad8195e5b194e3742989cb754a4747748a5166c9a3800cb8118afa8c550d25c4837571ed3d0e730c4" },
                { "el", "ad2b9b2146960a1adfee30f910e348a5086b1ad1f78a2e90b34b7698ab21742d56831789e48e28c136dc7fc0150bcd830e0e0bb3751d3d03f3f84e7e4617b639" },
                { "en-CA", "8969934ec818a93211dee6c3d9ffa495f84e5249fe715000167dd6a67374f1f15b6bc2ddf9fedd20de56360a6b2da40603e6ba1e415c44190266965e5e38a379" },
                { "en-GB", "9f899ed18d59b85e914f662af2818bd93c3c65d5be6d675c6a3047b39039316c4a07843efd246b0cede33eb879ea333743800a33a91d978874d9ced0a93a7c59" },
                { "en-US", "65bcbb90b4ff7fc84d4f696b2bf864d8f19cbd447f40e600aa1d84bcff2347e94ea5bf16fd8d39ff72d44b2aafb90e2e7385addfbe035c72113b0f2c8be55b7a" },
                { "es-AR", "a390266af0b71819995ea8f130fc53adb3ff5ee972c2a439be505e9e06fac8b1d9d19e1976f69a7850acd35e17117b16800d0653375687378e580629675b6b74" },
                { "es-ES", "1928dddff908356911136c4fd1dc0dcd363fc62c0eaefe79c3057ac78ebc1d748e33f9f8943bf071a05b84ab60aebcd8ca4cadc829b4ded5753ebd10cb8559cb" },
                { "es-MX", "cae176bba1941209fc20e4632d2ab1d462b0caaa03d62f9559732b2547e785f299754ff24ef2ae3056dea6a33627148bd957c79dad5f35ee0457ef9d280c91a4" },
                { "et", "ccff3bf3d63da92578c82c928991c85aafa8f6e1029008829daa994aa79892f6cd50d22f06bd021ee31de8e3e67e88598a62284e05ec57b4b9cce50aff129010" },
                { "eu", "1851e8b68ce5f7b863d126019e3ae95d80086c2ffc46a757ce60206b15d13488b9b29b77637aefca7452dc41f488759f885538310c3bc431d99d336e51c2bed2" },
                { "fi", "1d63c2218a65b9bbf6d13c848b7591899e3cf55c4dfdf7adfc85f9274bb7d9349c6d237f192f52f6ed24253d9e3c35c9fdea08037d577d4ae8bfe8c08ce9a7db" },
                { "fr", "3773dde11e186fb8c94b4233b176478464124164b38a71067207d77f2b9a33428c21f8321982dbfc7cc64a7ca89b892864079269589c639ab0033b35c90c2549" },
                { "fy-NL", "d29373c2c9256b731be2ea1cecb0ef5aebcdcd1fd0cc3ae3c73d2f876ff059c0c65d34f70d7187a66e360c43dc190ba7c546a55292ce617708aa17fa5f1bd15e" },
                { "ga-IE", "1262e04a308c7c3f865b62ea4bd7e041ecd0b213bc55b3a1045c317ab1a02f5973a3e52a55c0512cb0138421ed27f4f1d3413c9b73b4040229ca5c9406dbc35f" },
                { "gd", "2bc51dc74dcdd2a4da549627cd1f6e170fd80b97fa666ad232e2c94161e5b89319cd6cb0283839178301c928e98c207c4672558e59efae6e6e6d493af91e4fa7" },
                { "gl", "27cb05d5063525f63d9d41017c2113cdd4c964caef526e60d42802d766f122017391aeee42daa3bde270781e8b6243dc41e06a6c8c04ba63db9c1d535a14a9c3" },
                { "he", "ed7d34e63d77d5407af929e886bc039ed343ea5a566064f76ec63f88b6aa3c43648a119740d7c49c9f28476ed04b8169443513d84398f24417c00acbd6661383" },
                { "hr", "614c03e648bc11f6bc120015364ab5d50ba74a5efac34ec4b249d0d1a7ebac243999e948f59ecceb0d068955e054e2e7c924573dc72965f4c629449f9959af98" },
                { "hsb", "b4f1a1828fcfa0aae09a9cc2c75f991fc933d99b9e6e120bed5e37e2a9687546959ef851dfaf455f237b83ae7ba75988183d0403ec281fff13784e8f782bfeba" },
                { "hu", "d5a6fc7def6772c23313c23f1356243db8add3aa73755c7a7882b9f6725ab31bd1dee6e5c1aadefaa44c2787b0b63cfe33af9eba62aaf6bc8a7a6aaf54f3719a" },
                { "hy-AM", "8a3dcad2c4ec8aa2a3279c2b213d7584b60fb0cad22f0cb18f6ae8b0b742ce3c8e7e76f55391db7ab8b1c063c6d4ca38ace3f3b419a7f77653adceaed6feacd3" },
                { "id", "7046f78475607bc1221e1f27847d71f3db2713a0fadc3be09feccc6a346d52af78c2aa08a5fdd49b1822ef2fafb2dd07cbc4e2c93f833cb70123b0835c7d2ec9" },
                { "is", "41b4b810b116e3f529d0562b27d834a73991c135ad72c4eb835ac95fb0929a9c17d1ffec25124788231dce9ba4d48fe8a5bc9e71852a8bb03f191deb99235bde" },
                { "it", "7b48330dadecc62130993436416609a56b2815614dcfcab1d33e4cdde3d2a6a6329d06a8a8e97576da12da45c53c5966cae26ec27d3c11d708cfa06d5891d180" },
                { "ja", "938aefc41bd832cd22af1becbdd7b529949be41a1f334eedb5b528560b2d6e35ab305ba60e1e0ab322a81997091e6676ae91203b7ddf0f559e21c9bb558355fa" },
                { "ka", "58dd1f96d116285ea3af36a9f7325e4cc7963d94695e883b4cb7c96acc392f13d3ac56467fa3b60b5c077b18528d57cdcca8b0715a83eb803ac23a3a7446fa7f" },
                { "kab", "52ed97c0e850dbced2578be2c16137c5e4ea2b2cc9ad73f8cb1d909439e8d34b92c17e901b5487259d302687426eab32751ff3b8a36433815bfe4ed4f5e86762" },
                { "kk", "d66357d45c1b9fa75457599fb47dbbe80c392056046283137c78d3820844479afb889d269e15a46b30fe55a34efc310273b8427760bb35e25d904835d0752b31" },
                { "ko", "987d3d4ad99820c7b8be56eb3c1915dc095f23c5472e3247ef58921dfb22b579d6596e38abea9b611b9e6e86f73d5936f2289d7d28d54621e63f2dd7bb45d0ba" },
                { "lt", "d17d9c030e31986676fa83472d78d848e552db9775ef17986901adfa5cea46e3a345f3e9ab1854104e31b5ab7c992c13fe673f9dc2fba651b97e5e08c46050c0" },
                { "lv", "a730dc488d7bf3ec24700e581e356c8a125830d0f41ee6581d22a67c70c8ac717e9bc9787a242f33e6703aafe68dc09c98d85d9f5482222b19e65723cf40245f" },
                { "ms", "2771ecd5e47375b667aeac91bf957c45d910998d4ebada941b6f6c1ab8e56e47ed8191e7cfdb38237db4e7ceeabce6875f4a00cd2a956c66a5fa9cf8ad25f0e6" },
                { "nb-NO", "0f929432ef6e85f6c6605b30f429c57a55098e07cc81ad577b61cd54afd6ef1cb1fd5600d61405906c640f3ebe881fe523907a69aeacc52c1269162f22ee160e" },
                { "nl", "e5f95184b0352a50c7643aa309688e66cb5804b2bf1622609845fe4dfb26a0d1a499488215c76607328242c8c481472127d3564ab277abcbb8bf5e0c0d94038d" },
                { "nn-NO", "ff2bcb165c945f8d39c79ae0ee64a604cb41e665771c47573862a1ed9a64c590a0f170633397e7410b7bbaf04277b1aba97c1bd5948298cb08f4ed52b7e6a629" },
                { "pa-IN", "348e5256c27645a12f3bc75bfcc9b9c1c74839cf0636d9c00a01e13cad425c752e85aaa9f701e1f1a94b7fe67bc50c3ceabfbba055503438710261cc1d8ff223" },
                { "pl", "52de25b095b26fc30c95cacbef6b827212617c43f1597e46a1853e7045248e4c9cb3d68c0375ed849bfa4e2429371089d6811167fd64e8bb79ca3c167cac657d" },
                { "pt-BR", "928233dea64159ba4b0b80e0289c1dc64846c84e223c2959deb34739be8b878dac79985253d581ce20ffbffb171182ed170a76159b7b98aa3e52c7c43f12f26d" },
                { "pt-PT", "258eb059f03e2d6ab6fe497a2d8bd607b8cbdb2f98c340ff33bf7a74026a0ff3a1e231226a131b8d4f1c4161327b40e0d65e111a11b860cb15a4acf095b14ed1" },
                { "rm", "4cb49297084e8732233cc01825e741976a2e09ae3aeeea1dd2fae007b790565f2c8dba086746aa0afbea9774ea36fae8f3a5fd1fdcde0758985c4b068bb8a92c" },
                { "ro", "167adcc00a53c74d728751d87b1b892d2e1ce774d92fbf0d0cc681367a4be9c53d8646a70c9edc4e2e333f8f077e11ba1c6e9e3ad71abd06d4b99cf6b14b531a" },
                { "ru", "b6e23c33fb3b2bb02b7777b3386090db266a4c3e77357315564a8c8a48839c8819909fb1874b915fa5446cf96d25a7b198e100a75452cab7b698226a31cbc7eb" },
                { "sk", "27edc12d15559f66191f3eeba82bbe100feb3f75ac0b152fe24adaa2ff4e262506bd3c828b938029694e497848e2b70478f129937c368fabb7001dbab0c0b64c" },
                { "sl", "0787dd23e5472e29f87bf56ee8a168a25cfefa10d112a30a04e461bc2d20d89665e9a87eed542eeab7a89122808c724191fdf182cffb189e1875d83af072d945" },
                { "sq", "05ef5b66d19e7a3d353fe32bd7534b59ab57d6b000176190b7cdd1021cc5102457c1578def0c140c12944d07c24a4a39124dd29262ba757c1299047839cb40df" },
                { "sr", "6bba9824e74187059152ddf5513686cd69357f1fa74e9866c0e293e1968d562d00568a706afb7116d609c2fa41bbeb7563d61c0bbf7b67e76b7cb66e86fa3a2b" },
                { "sv-SE", "cf13bbb4c49032f04e345027fd1193abdd7036ec8386fb2684b6be1b7b194b18fdbb160a7b196e7b3c6b041aea70b995aea755fc82e67d67fc74e3f3e51d8fc5" },
                { "th", "1c847590cbc865159f636637c5c6217c2fdb13fbbd1356f89355e0a6cec83973b53a40d204421153c14127006de29a1c35bbe9a9e4e5f8c155f0d2c11d186ab4" },
                { "tr", "1ac1a6f4213fd2b24d3fb9e984d0dae152b52146dcdf0b7481a12c04b8953deef68658683ca6ff9e361ecc406e9dd03712353e897fa888d682274a285f55fbe3" },
                { "uk", "4c716d92fd5991a99a32887cb7c3d69a9891bcc8203ca0f0217dfe845bce7cad9b094bb74b8630ace9811c49db40eea9d8b4c7e9023e0aeda52d4775ea19f526" },
                { "uz", "f8135b9c7ffcc6412cf9020d0415bc78d2bd614a1b9b539604c44b978c9e1a45d93ede83360e8454d8ad1e890a23d3300834b995c7ae58767c4c1778ecb74196" },
                { "vi", "f5b3a01992817a7bd2f5289d4b16091bf7cedbb4273d2928baebbe1297b54b527ce7ef5cca15b51cad089330dce4f6356e8c549a68b2cdada2b713b92f2623b1" },
                { "zh-CN", "45a253156e017ca8f7971b4e70569d07ef842105850269d385b0933c2ba40044e3f44cf9a435f489d1b59b1f67878416e1bbdd4e72f37e5b98a05932c640f873" },
                { "zh-TW", "da67ddf6d0836c640adb03eef90baac2aaf02bbb26a7e1eb80e9af20e56a23c5b6c6ad6236348a6b19310a0c26fd4220aae846923ddf431b1c87532d5adcae02" }
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
            const string version = "115.1.0";
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
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
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
