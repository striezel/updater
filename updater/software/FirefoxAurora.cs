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
        private const string currentVersion = "110.0b6";

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
            // https://ftp.mozilla.org/pub/devedition/releases/110.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "511a0cbe0c90563f10a3916f34952f87dae6c7d073bb29e2845d3ff5ee84b00e4d0ecd61d1462158a0ffaddb7cb9618f98eefc729d7f354ab12c06b5bf990546" },
                { "af", "5d568d017d464881ea8b2e603f67296b2f42953bbe39c403b7a39cc5df6172ef3e10f1efd30106b42ec86124fa6c62278ebe15b6afe7bd45ff44d21f3bbab101" },
                { "an", "9c403460676cbc47ddc285f3917121b8894191a492c1edf801578bf0d3ddb95acc905541afc51ce89ff826789e0508e12c6f97c9bcf7ad8f159f5bfa27dddeca" },
                { "ar", "18fa866f465333a38c07616fd9b0def71f5e6a2e3f62265157a35d7d32a0b7f65692fcfbb7dbe4086983dc59c1084b5a2abc137ba6fda4b4b5ff5a99e9ec0f2e" },
                { "ast", "98c94d12bc86bc043dd473f53fb2435efe22eefe5d9e200265db1dad7255ba6cdea3196d6d7ee91b3549c5dd26154b5573b332d53922e80fe915a017685d9133" },
                { "az", "08f06f91126b8b1c2d0ab6b6753e2674d574c19732dedde841cddbb9cc9eaf543eb1358c82febf36158e8b0e4dbf84faa04c74fb6b090c8a44c4ec3d03ea8b45" },
                { "be", "203b6f47ab2f4270460da82d9b3af0921cc209676570c6aefe858a27100f014b2017e24a09a790d81d4f06b6379b715e8033fa74926b8763105a0008a7d17974" },
                { "bg", "1ec8f6dbb2c50e9fe2e6a9b26c5ebcdf91753593115e160b6d2e36ea25d20f50a489213679add057ccdce20ef4824ecf199f51f1c9771afc4af6f7ed222146b7" },
                { "bn", "20fb564f887c644b4ad8c83427bf685ce7fd303f80e6fdf1e38c625add5bce3cb8b414d875810d2e207a814a9ce12d8d17e9993740eebe67e15ae49b93911761" },
                { "br", "61371cf1f53ac61b20c0f06fee60d39689e41e77dafa5ca003fda57abe7fef0e23920740681566f219d429764bf7f81c0ba512db856a3d3c372e0c906c873391" },
                { "bs", "b9f66f7d135f357191a2e566fa7bdbe087ae5595b5ac71f4f0414bde8db624e008e326dea8cd1263f7e1d2832c44082ec2bb3b09a216c25fd86cd5dcc1833bdd" },
                { "ca", "b44f288b662a93fda27a9653dc5844ba87ae69f2efee048ca5fad636b7d5e340bdb7e1abb969532b1b91b95d19f0139d0bcbb43c939b40c61235e53b5c0ebaa8" },
                { "cak", "a4572400a2648bfb2c0924f8d077f1a145e7b3bd0f7dc9b3881e87f071c55e88a8b449aff8171a19e5df0d50f8049f887d135cfbfb3dbf93f7d2dd22f42db6a6" },
                { "cs", "01cb86ed7c5ff5eb36b0818e093c247b125055209ec73f993bbd2221efdee88f7024750310ae376fd04938f19bc395a14c27d97933944556935b97b0a5ed2843" },
                { "cy", "ee2e1c3924a15b9f7f1a2400bea9ca1aed11f58d13e1fae5b9fd1737579536d26e940ec07109a773a3939853df12c05d9bc935abffb9f3294ae547a8aadebc46" },
                { "da", "5253a777dcfad64115655f6b1570b8fef15951476f5adee770eafd98910c39fb4058ea8d2f01636eb566dd0d4f2f5a5972aa64070b36ad7e05210af9f2d6d80e" },
                { "de", "e791a0a79c13ec04b86c7700d8b3430c650b3146664baf6baa209ffb3d38cc2320fdbdb2f88adc8d3b1246a5b05e9cc1d07155a428895fd39e34c7ad87641146" },
                { "dsb", "47769d3530366a00e8af046435606a5666448e049225f0b32a03fafed31c90679beeb87d4073e45b773ec4fabdcef6cb9f317476353ba9805419d212073d754d" },
                { "el", "37df006364b45d28f59266d2502749fcf5ab5513a0f5f265fcbf63e5ddb4a447fbc817f52d20dc4ac50f04759013d63f42ab5138aa41a1dcf0b9863cbf12927d" },
                { "en-CA", "2fd02e5dd241f159dee588005c35ff701828a46261ad8ebdcb2336526ccde75cc4118c4ef43c0ec76d2e0ad57a6ab2b53be650cc11abe10da333492dcfea2bef" },
                { "en-GB", "fa0178d7ef7d31f448140186337861a07bffc8774a6b33361ab7f83350eeb85dae33a237ec5cc162ad13962f1cd6e243bd4f3cfce6a66f1f85c32a08aef3d618" },
                { "en-US", "2c7cd04ecf12dcf725a83a6d929b04e67b84112e39780eff937979e2e9163160a1f30e0dffb745165236ee6f4454ae5be8203ccc7d8280a58ee9d41745fd9a42" },
                { "eo", "8d7d67e7af8646632984f563ec6c595ef85e8cd5f81de5f59f1f46f4b4e36bfa91429b81510ac5eecf813a20faf4999d1bcc7359365103cbb2f97ec67325a62e" },
                { "es-AR", "a283fc7362e0db20a2eac52de27653decd69379b2c0869b2a0b694a598c02b2a0c691c15247c07c9d2ec48ddc5aede0045a151f698a4957384d8ea8a1a6c6d05" },
                { "es-CL", "2449b4a65adc622d0e2428c0fc08bb72f7c724c0d3145cba941369abb2dd1d0fc70b196caab8b72bf91076015e2a055d78d49a6b1a7c7d9c669da5232c02a2c6" },
                { "es-ES", "e3bd0b784e263d99312100ffd34d3d038ad7256fa4bb3de3aa9873228c6e7d22e63770c82d787dd6c59bbc77691c5f692a33ecb701994c2ec1da3501122e2c95" },
                { "es-MX", "58f2c0233cf2a25233d2db886d9f25f30c6e60a7f85062a969a3e3d18af38df885a75f4e91f9c5cae669a5b5d2e5dcc95681041cc32500642bd7d50c0af23ce0" },
                { "et", "b19700e4ecada1474dbbe1a87fa79c9448a7dd580e4f2306649bf47c98df707fc67a1f14138e00e398320ec6cdb7b427044ed72cd95693c2b66c729dec272ec5" },
                { "eu", "8a2549369aabd64a8a9a7adaf369afae4ef96998e306e015b5ddaedbd15267a7d7983cb3d569ec48ef989759ddb6a284bc57412d29318fc35b2105394e293913" },
                { "fa", "d0758cdfbec10f94f8dd05e3ec910086042e4d8311ef233dea00ced2fe4400889cb93ee7220eab08cc3577e313bac06e9e857f64ed77e9a1d871cf707c8f13f4" },
                { "ff", "3a136dc6b4b01db7b420ff4822aa2830546ad3ace8d9aeb991ad6d030b19a6c2dd4cc394c81e6ebbbe783ea06db1c2634120a5df5e43c30d5065ffd093be9ce8" },
                { "fi", "c36947658afc965ab68a3d98e10d2c97cd802f136da6da2ab95d446bfb734ae9d4f3acec294c317625d6a69e4329e591b30f1d4bfa0995a4966f78852ecf2837" },
                { "fr", "326ba74e4e71fe9e40cdd9d5a70bc846673f3aa17b0916a91091e53073cc0c5f6beeb0e74cc933d4df2f479a8ec3903695f6a8f4620167b39a6ef52eabff9848" },
                { "fy-NL", "60fb324f81e0656e37eeaa4aa0147adeeea1b42295ef048acab8840f6702cd47ac3f3ea7943273aa394281da033a878f31e4378883170ab66f4f6789a9dad648" },
                { "ga-IE", "71fb830e92b13f4306eb77973c2f664e48d506c58b2e20e8603375a37d1e2e6a63e850340fcc34906d6bf556633b6c5839cc5c5fafbd8f4104200fe3f7e2129f" },
                { "gd", "12d9df2c2817b3be1962b44921e3f789e6389abf6b0edec08e816ffb54a206d7af250f66859eb378d3736868620a29bd1162eea1d26852c274c621e26730fb91" },
                { "gl", "af4ee3285b4392d13d08c5c3d62d30d7e7a1ea0d3c5b51d5527a76f9aebaab93f08a9e4f5cf94168a11a36e18c700ac3cd8b10f0b3c4ae9dcd98fda55b63cba1" },
                { "gn", "21cfa06e9191a63037c5650edd080588732107ed08b1008a6f585d3c041842cee8e297209e77778209cce1c862cd638505d2dc644f1496284ea5bfb639e38eaa" },
                { "gu-IN", "0b991bbf39ddb3fd12e66bcb05a43af6a496916284eb5cc5690835a391c8b380f6cef1dafd8bb34454f1a65d9bb1eefe13c75f8ee45a81737b66fb0c5404ef27" },
                { "he", "4f7d4e19212051783e2b350718c56c4686c1d2226c7cfff568b25d8d82acd6783e0fb0bf97d4996dc5372b022a928f88bd67f49f6e978cec9def0b5486fa6684" },
                { "hi-IN", "f84d4d78ea7d20e73cc7247ee359d2fa86be97e37f0c39e78798164edd6abaca03fe8d095599bd85e95bf2fef78e480d901358c4824209b1c317df1b947dd34c" },
                { "hr", "84aa1b00f717b61441141db09aabca9dd619196ef5e3147e0f1224bcdb7f9d7d0256450665ae6b6629810e42c468c6da8dae497e5a1f716124d00a2e532dbee2" },
                { "hsb", "310e395689b5c4f90df46b2042d86648b6efb112d57d879977a312152963c743d14115f3b3bda9e71f514ea514625e5edb6d9484ada1ab7dd31b628cd2151375" },
                { "hu", "c238d191f98f6a7245c73d9dc1024d50cb18ac11d0cc8d972eac506bcf5709029822a0c03ceab4c608996a36d4de28d9e06011dd431d3bd08d57a8e14f85bd1e" },
                { "hy-AM", "ffa89bd5465180772886d0a4e9ea719051c27e57da8f7fbec6c7facddff517d9dc272a6d1ccfaa58322d0bce3f3e14d674bf87fa90b7e9adbde2e37e9f1dbe0e" },
                { "ia", "b92eb38e235e81ce79f9dd6c3b065c38ab4365cf3ccb49f7d981ed07259c2c79b496103f3807fe42b3431c62ee1c12b0f7d25f53cbc07efea464fb5f50a72b53" },
                { "id", "077e6b9daa35dc4679a294fb8a5865d1909613629a41951d91817634d86b91b9612cd90f3540d689b2ce3d0825d43ad401c2255eaff717780149cde3e6918cef" },
                { "is", "f4854cef0f193ff96a6ae041972a56baa584f9d9e840b4995e7b31011982e221af84d2621eb8fad4ff11a259875debc760e9796f0288aa2913aeb4b0e9560ed5" },
                { "it", "10f69bb3eb3f80c02a67e34a578bb8572013e7abf60bff259525661da0beff034993ac6de6f713648b0895667a755dad1e98ab452e1312c1e1d40552bb99ea33" },
                { "ja", "ffc7fe7f234ae9f4fa2a3cc41b7a3923f4740763275f17830dc5051e73cb5f847813bfbf5c4de6cd2c050daeb4928d09d151ddcd55f11c612abe09da022dd23d" },
                { "ka", "6b2c875d575f7f1009a55ae4c6771cea6843dd49bb1f6383edb17af87cb436a9c02aebe843ca887dd9106340cefa8e5a658d478d197470a91acbb314d8f58acc" },
                { "kab", "b92f82f2c35e9281621de6c45a0008c425ebcf647338f415bd9a9b7d6146b5cdfe65312d77cfca893a455218191f6e5646d17c44ff0fa1b3092498b828a347ec" },
                { "kk", "ad30bd65b693133ba115616ca5d1cc9c10695a7de9581dfe0451e04a0b1833f0f9117cda3cacd700c6fdb8145bbe8543082671b99695045d0ebf934fe8f0c13c" },
                { "km", "2bd2aa65d356fcda657aaf63d24786ae6776cd0834676b1a756b8308fbb7cac3b6abfa5d5e286765531c084688ea62c98388a608092e6d0da835ff5f79ccb641" },
                { "kn", "68a1de239b3b7a083b31743f5d2025d5400dd0f9afaa28bba18f4dac9d2bf0b4f247fa20e563b07a2c2622842cc90792424a4b9a0d6d8b327c12e577be6204ef" },
                { "ko", "899c44595c63a56180e4b380427d53744028070929266907f6ab996bf4ba671e6f8603e4419f771d2dbd9fd6b66916dbe2594154cb9effd6aa2c2a742e0419db" },
                { "lij", "c3a1b6360e0da075cc48a61f0b84b1677212262ed48d05f5312c2e62d62ff0426b30ed4d81d8c006e9eb92e6c8f138bc3184107d4a384e68f69e9be1b1918422" },
                { "lt", "f834de22183109dd77a6d91848feb9b7625d389a370fc106ac8567b04f96350fcb88c693ab57bf350bb3ed58820f9f6bee6a039d7290a19c29e170d14db05bbf" },
                { "lv", "bae9a22bca62721bb1de357aed26e0d0fc2c4d840a05f572fa4c7c8d2cc7395aab10847e6fe0241b9bc8c57e7b0bbca2fba2deced42274a00ffcfb1a3a546445" },
                { "mk", "6d7b6083a96edc9fb2453334a9074e5ec3a769f0b3c27f9344d65cc65bc9b15cb7911cdc99c63ecaf7ab061c7c05b2a9544609f2083532f0422fcdf13d37d66e" },
                { "mr", "880a8e7bce241237acb683a24545f241eec4154656f86dd6708b492f591582aaf00a6caf6544ec5051dc9873276e027c263c0a7543cbad75715ba59af7519d22" },
                { "ms", "2a72324beae7c3ef3b0d007e10dc3d35764900cb255961de2e415122bd8cdfce2e7127d809e964a07a9a4261af4e6462e6e169a19ee04e714990933842c5e321" },
                { "my", "2fdd8206a891b9b9736ec9bb8e780a8c3ca8d2adab66c427b28f259cb05615e773595015486b579eb711bafb294a99ca7aa6e812018ee5c0cad75949b0e32b61" },
                { "nb-NO", "af2a064b6422db7908abeeffe78aad173cc4151fa43f62b303e45acc4b4fb67292b4ca50584ac8a5aa1a3a897ed402afe6d883db0a3f0e591c8aa2049776c0aa" },
                { "ne-NP", "3c1f463ad89c778c5a1becba43a077091e90b95d32e3fe9ba8581d5800ac6ad8dfff61d51a7ffa2efa4b67342036fa3645093449d55fdd26eef2a08de86f8865" },
                { "nl", "186131dca0ecfead7bbcb7f168e01da68ae8cf2a8f054e92851a6624baa88ab301df7eb62289a73fb59ec1da38f3412f6d4dfbef085566442109afd9c7d3dced" },
                { "nn-NO", "7ee14403fd24c2849e1967cfa5cc11d281f3724b8a7db33de6d943da26dfddbe980de9000e5565db1ffe038ad52ddad52fb74eb5ee063b54ba8a1f9f1103ea53" },
                { "oc", "c11364bf90dc93f7b3200a19460e2fa111083675baed7102a1a8665149ebcbf3b1856faacffc7b2bb59648c0c85cd118587a4472618dcd51459d7bdbea697ff2" },
                { "pa-IN", "558b9d53a853a349adae35cfec1e6abbe6324519f8a4d154cc8289d1dabfafd44e2ff0b404f3ee357d88e91e34d0649db7ecb325c14b8968da91e7428611282c" },
                { "pl", "98dd666c60ed958f34a9ce77296cf81d77358926daf33159d72df5b0175a4d8cc72c3ca26b12f353646d7c6c515a996ef25eb4d94ba570cdfe0346d7b5b425ab" },
                { "pt-BR", "d96ff5f48153940e09e0dcc35b10867f1335c83fe060f461a4cc179b03f6e2276f1c9859bdf660c890c609af5272794016d857226fccb8e27f2080060267029e" },
                { "pt-PT", "9960a8bbabde5ccc023f0715c8562d3f1d871505011da17a771c218b2cc4e27e16e9762e4d74a8a16ab0e9bc1c42f763ec02f7479835c494b3b76b971526ba4d" },
                { "rm", "d75f81420fb3a237931c9c7720ff277c30a2bb9cdf7c4bbd16b8122f5b4fdd40641fb50112e51f5a087c6f17460d4ae3f5ab215c28b4533f2cc55a4adc3df2c7" },
                { "ro", "11bb1acab3d945ca3ff7cb31d7ef158e6b83dc039d73694be28d17597d10e7147856bd60f789a85d21f411da9b8f720de732e927fc6565aa387815e32c619395" },
                { "ru", "3546c02d4a7323c0604f990b425d7bf39e91b1f14ea1a13db0265899786b78220a4b2e7e68cf6f544b73e96e93c92247e321cf70111b196522fce701d56f7005" },
                { "sco", "66d48bd2d8c1edfeb85866d272183c146c5a00bbcd320fca101c42df5f1395d0270c86b0fadc860db64064f7979f289dbbb1ae424aee63e90460ad6745b513f0" },
                { "si", "ffe098edec7fc21665c03d2246515e3e54c756f6cb26583386d758fb52f2b798dfd75cf64c4927e7ae570ee4f6f435d2c2cab29e7ff754c7b6be8670b18121cf" },
                { "sk", "44e6986004db8449a19c98176e0c22b05da0dabd8050e966ce72e7d78d6f74c360ef8d2e13202acea6c67da7df028dce707bb976159c8a88313e5dc9d1b63633" },
                { "sl", "20d8b128d8a779d46955fc9d0336a7c401fbf5f83784f8d45d8db2df70299f67adfbb4ab23c7de3bfe215913f4f3fc8fc2edb3466d4fe05e01325aee0be6c961" },
                { "son", "44d641e03b5733a4538292dfc79fea0dd2e87621c489b017bd2b5b2286e19918a172a148edd3a5786ab6f7e375bcc3ea691095c138c5e471f8d91836426b0775" },
                { "sq", "c24b133fca57a9623cca47d9290443cdd8eeccb658f6abaa7a940155c4031929bbc45e50c712f0ab037de81281eb27674b9d92b090be1ecd802259b6083cc85e" },
                { "sr", "6cfe23f05956b47c954708d30e412cae10e3a905b4defae6590a377329c47c38c7ee22d5627b2d0639e86538065a044e1e633baea1df8b8b8c2fc747772af684" },
                { "sv-SE", "415a29bbda0ca9bacec2ae5baa5e1f42d06e440d2deab621b7614120157b12f9bab8a738ed5b7de573f4fae45cdf4271360178bfb0a256ec81dbde0a68e5e7cc" },
                { "szl", "64f83ffefa3346a957bb04def599d61c916ffe8ab472b0ecb09cf58100098d9dd6cc8f9648f84c4ca18e04fb62609cf3fbb2e7b13110acecf5e7a2569b7bd6d6" },
                { "ta", "3b08a450c93f3fbc76dca5e5db1c24f10241ed0bb6fc5b1425c8b3adc7f5d115503ad5455160f9b8e91f4258d96dd50c7e07e77f0cdd68746c1acda13f7e98fa" },
                { "te", "bae04691a7f9b5aa25bd77f3b66d978e9a8411ef4dea176ce78871be3b9e2a36c2aa0f69e7abfde8092a5206653399425a43455a7b21d7412bc149204f24655b" },
                { "th", "78200d61e96188f9ac4bddc39c72a36cf3b08be43cc69f202b51178ea49935fd7070aac151f53f9ec8b960d9246828516635ccf56ee57e93d7025f475d0479b8" },
                { "tl", "c71a618b9620c1a6a806fa5b8ec5f4fd0dcf634456704b9e2e67840f73f5aac19b897951c7b890b73368a008e00433deb7ade747fa5e281e63b4d61050de02bc" },
                { "tr", "7201878e44b63d9b2ad0620ec70213ecb5a33431dfd3c129377b1f0659576677668f6923c64b8a0304e819595daaab70ca3751ef24662c4d67d73ad65338ce03" },
                { "trs", "31e8435a3637bcd7771caad1b98d3765cbc10fe2c04fe9183e4bb52e11ed462d278df75107626adeb28aec0bbf5f657a508ce3a370f80bd2bead67765a30c622" },
                { "uk", "bb07ff7b1439a7bcc90286b820beb08dd918f39a391854bf4579fc552e5c050e8f308a85bd9499aa023a1401e169d8a468a3c7380f8744e9fc0b4cfbb4663b4d" },
                { "ur", "e9ae558971f50c2bdd51e96edf815428faa0107c40f568ca939764a1f9d53c5e8c230958cc6da3b5efc4652c54958864000571dc8b5dc7f29dac9459655ae27c" },
                { "uz", "bc2c72d1a868a7e4785c00978dea6078f79355a9b83fbe26ed527bde284f3affa1dcfaf2b02cd248ab6cc6db89498bfb1adb7fe395595e1c290bfa6d4081ae56" },
                { "vi", "9d777a444702436cc0cccc7c967b8e1d845a859b84a0b5d98ce9b84c0951d4cd9167df742b21aea8c86492c7bb88e7ce548a733790f816f4e391cb2570563c33" },
                { "xh", "23f06e9e1ec2b1e84858a68a92148931c5981b9c7b5a2c110abba71162ffa5c46ebbb1b7a9673b6fe4309ddcbc4e563902d2c57c505958083d69f0512daf1d5d" },
                { "zh-CN", "b74da727f03c3d9df2a31d3d84657ee9017ead3ed45e846d95738045e15c3fe3166f2411ef100d203a12660dbda18573f31b1af0e3bc69523e12c8f71d45d47a" },
                { "zh-TW", "f3f0abc03fee175ba3ac458ff3ef0cb10fca510a8d3181e19e6f8778546f237370eb1e9fd06990dc9eeccbe0867182fa063efb435e5e49f4bfc741e9c297839d" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/110.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "f4b6ab0e02f1938cfc685fca1ff3653a5f759366611ef743aee42e86c88757e5d1e12648b7939b6ea24400d1bd760464bb36db77929ef344ba279051f481f06d" },
                { "af", "ba6b5d2d87acc104eb60cf27b58b56f7d9945b0c48222a242648c4c5d2c05bfd0e25741517bade1b7044c45a60a3fc1a232b86fda0409f6add46e909377e8378" },
                { "an", "0de0622263a9cf95cf8c7e808fb324ee7a4a42197931651f8f8044d08dd94114311f006404b408d219c4e91bd89c432af3fe7b561aac6ce262c20a488a3488c6" },
                { "ar", "04d7c1b20560fa03c97d6edf4eb237cadb033c099c1f6b9449615f2d18f05d4aea1561438656e2e962bbeec23dd961a9417779fa5462a05f010d75f87b0ccabb" },
                { "ast", "9c54cd96383a14b602c6577c23ef3e97bd38c40e92b5d499888eb4d8fc635e37b00cc9fa5a92f6f2b3d5b386f3739f8fe469d0f2fcc1b41de659c16735e05938" },
                { "az", "9fe185e32175cc2736657e5e2e17481871d3ea1232ce4b8112517a4c351fc779ce9978d601c4990e1a5be103cc330db4b8218d06e14fd0a181e910f3e5b1f868" },
                { "be", "355e24c5b5f2d5eaf691803ba9dc6247f81b55b3d3a9a115de48da20b71c6b0c209ab4f22f551affb0e762393d94e3589171dc54fab4005963a4b7a46f3355ad" },
                { "bg", "135f8756a69fe4cd2edb27370bad80a6a014725e34edfdf17577bd33cf32b9922fb457372d845ad7014f3dedf7c9c766214692eb74e18c45956a7fb9b9be23ad" },
                { "bn", "aa8589e75527fbb772582af96004be4ca08988941246d88f15b33ed12b6c6cc7e5cf100f56af7925103b25509f4daaea9ad14a8a48f79da2c7519aafcc8b6db3" },
                { "br", "2697bcd59b9234ecc63020929f7851d603af4b9e1c84e9a964c474f45227992ae8843a037abbfc37320d373eaa49db08f15e12c4efd683af1e4313c55b56e684" },
                { "bs", "52894de21977561ac56f6aa0b5379e700251f5e54560aa8c02764e25ffd794ca2c62338997312686675c29ae0588b3967b756cc95c9a0ed91557a24cf5351560" },
                { "ca", "80de7b2835de838efef7c86a65ff35f5e5d15012c61134416d46b03e821da7fd9b94430784246ed4613fa65354d4ff3a4151f9896e6a1b3e43f8a3a045808f67" },
                { "cak", "456471ead6909a036b9d2e298615b8c40fcf56a25d3b0beed54f3c5a7ac0a88ca48ef585c50241c1d71a5a3b3dabb2d79181b4883bcec63265aa74bd7972064d" },
                { "cs", "4e6c7db8216085057858b91a583edc4176ba3af6f1637a9d57df087c7a7fc789c3375d221491f51f9a3a1e5bfb85779099fa4139ab71239e030f7a657f8545f7" },
                { "cy", "03a4da9681dbc1ca1ccf0ff60bd89fea6c1fc795673cba4c7f247f18b0c26f32060657a9ebaf3f8328ecbf7137bb2249e7d7892b2fa2744eec7eaefd6b899251" },
                { "da", "598fab773d23c7ec0b3e4e308ccf319a420cc6310f0ca35961ce32e0017c2e316d39c2181f7345cd8780fb7e81806a05669f38a94f3af523393e0eef0a5ffb5a" },
                { "de", "3be959368c58160f28ab7171c4746c1f100ea1b798da7474ef06c2fa2c862409d1ab0450099c102d2ded9130a9199cc6b34bcae9aa207cbf518b41fedba6c772" },
                { "dsb", "8167d3daadd0c2b1f0cb2c43bcb28e1bfd84a58a5b376b84f573abaf4af164725a18a4d0278db8ee4cfbc1cd65459c276b765300c261440ddbad2fa4323e8e6a" },
                { "el", "e22d4c507ac2c458dcb71272ee1a5d46e1d5584441ab991f8416e0df2d496aad4c0b2bed73aa77af9f4ba203619108d901a753602f0fd6e88ca01308cfc7cb23" },
                { "en-CA", "92ba07c47c8e99d0f5b16171828dc859106f729063dab987220fec8eb2ba172df5014a3f6a0411e7083513adf2c97816b70190463958e31de6c7c616c9fcef6b" },
                { "en-GB", "4e2fb573ce51f16feb855686ebdc8400f7bee8eaab2742b0ef163bffe8a10f5c45c7f8bef4ffc4e2d26625d3578065938b53eb8789bccebcda1f2412090d19f6" },
                { "en-US", "1cae173095be1b2c77b459c7fd170cfef53853699a109f7ac2d107d1b4a6eb17ef8b5ad76ac6f6fd4909c2fd7296c0e170fe4b249b2abc2fa15e75e5ee3c04b9" },
                { "eo", "da93f1d990d08aa0ce3d97ea3659e5090bbf91f0f62008ec2ed859fc498659ce3eef96508f039700d55daa6c7d6dd7807525c85a84b3e998506fd29424f187a8" },
                { "es-AR", "43f7973f293728ec114ad6ec0456e2a0ee0473bf8202bf52170e2db9677fb23b9b68bae13c2c92b09a8a22877a526ef924de53ccc40c96b1f83848bda75ff8a4" },
                { "es-CL", "2a2ba31a3e4268c5abd64103f83ccbb01b7edaf61f07fc56c84c3b3598496f6c40668cf5962d8a82d57de0b0ec7b6abaaaa605682ee91f776ff203c1a618a994" },
                { "es-ES", "396d0750f1360a78124f7698c1ac10389608e8a1cdc1c8f7b12ff66d431ddec74b1521dc263a5b38daadee99cd901ff6cb88a6e8de2ed19d4671a59a4191a932" },
                { "es-MX", "2b2d3ed83cd729af3cacbb31389471ba9ab6563e33790bcf9b04c715d5316f3718dbe91485f562bc972d827df1969676cb9194cc9919ab97f263883806697004" },
                { "et", "c451021a536c76d5062445f5d9bda102a073b76c72e49d43bcbeee011c3cd4ea721cf5c5853f8cd14774245d3bdcf423c76c6e94818931f991e5d88d201d9407" },
                { "eu", "0d55f72a6fa1490ba6e4db3efde871df013c027c9e4be3a919c5d315ec89845dadbb1bb29f71523f704be97fe27e7069fe2955238b4ddd0ce1c5ddb7b6aa14f9" },
                { "fa", "2cced6698116de514c7caa18082b9bf0cf9ee816b64150af3fe14deb512a14560861bcde5e2fb28a5b6180a0a3e91e5e2462b3c0b6364964a84a573be03e2279" },
                { "ff", "df7725380c3e9ac1ffa5ed4f4de9e495af3566a9127817c8bf28777e651d3d16bde1631977efac0ccb15e4662637f6501f3388857d5d84c508470e1d81145431" },
                { "fi", "a4776c779135d0bddadf4642542d06073ba6b09c3409ad10a7dbb18f6f1a0f06e97f97826d8652142cf328668c86aa67c8fe9f548427e1a2e76cc4e55ba6be7c" },
                { "fr", "4a28b82984675177b8ccc40d4c98946c860da4c954100c0be979610f8e62d6710369ff4565b1646836defe0fb8303410ab3d439f185b397692dd10ca5fcc69c5" },
                { "fy-NL", "79e8bc7a5645e68e7de9cbeb6ad92829ee805d0e290a937f306e75485c1c3dde6d0cb79a1e87e0cbe26f955547d2d3cbaccd94c961153b326738a0a67917822d" },
                { "ga-IE", "f3d044022a4f2bbccd25c1f350319f6bee03b23971f28888b36aeae4cd5b4f4e06f445073f292173d9e81ae8488b7029357db72b2349b842a9fc32ab39f74ee7" },
                { "gd", "127171ddfc25e781f549e3955d47f258196d7c614647beebed996aeadb19ff89d097c29cde03dd5f6c34b407d59ea910ba161fe4625a67236b3d7935e1fae03a" },
                { "gl", "49b4ad7c6be1082c030eb3e7fda39d178e1ce6478bd2c0d43be6715093cdb87a6155ae1fa8630c37319b6d4aa1830206c6073e333e7b05b83fea93851c406030" },
                { "gn", "11e5d8bfb99a31287f892e3aad830cd3fd5d8443582f36378b971df12d66fbd916dcfada3655fa049242a54b66cac5165fc38ee56a9147fdf26379d3a9862a75" },
                { "gu-IN", "d3485afc47b6cab165f9a53d71e00896b2f68f0f80bf3cd03f1be0d9f1a1c33038e9c305f4d5a2f4c39a612c1d1f7f8dd3bda6f84c76a550e3ffec0b334d7220" },
                { "he", "746739e4f4a8589e65490ef55a613bd6776726f0d96a7ce51b676972bc3651cc69329d89a3002732e5bd410ef3f8d8fc41d8fa903161c35de5b5ca3e47c343e0" },
                { "hi-IN", "bd5a1815aee8302ac8c2f563e80ab0d68b369c5a6031eb90ba2f3cdeba33544c5fc3ff738aa0e8aba8ad70d5550bc9077f374db40106c40e549b4fc0895379b6" },
                { "hr", "d78132efd515eb0023813c7bb2fac016fe5930a7227d5b86e6a3780c261ead54751d57ad1ae576b56028f4f37e8a2487b921a472cd7af251a1d4e59ce3e8dc77" },
                { "hsb", "297f23f0d803d7bd8f5badac105e4ec24e3b790efa0c30bb38ca4e198aa5c4ba4759e0aa5222086a14d0bb341716fa420fc9da374e67a4bf8242364286bdfb0f" },
                { "hu", "e9bcaca1d30be895f08f7a174d919941872af30ab125a0833dfa4125815c4670aa8f95c94cb6599e45b88aed6ac7c501802317be607c0c25fa124f87d601fbd5" },
                { "hy-AM", "8b283bee24644cfd6cd39b36fd4a98033e1fc794d380bb430acb6aed409359d5cb62db763ae238f7f333aa5e7da18b6c7b1183eb96759db50361786b7c637276" },
                { "ia", "a5859086bc55d5b7f7da05c31ef4fe6b90f90a4054bf909eed6ce866f22a4244135d7de996245c5a69100674668f6ff8953f8821e01d1ec352ed176fa3e7132f" },
                { "id", "c2e4c628e55f4463d9d27ed53836bf375bb2ada61f5f5d479e38aee8576518cb22033236b321f16f8aec97a3036c2f7ad83c8e73b57cd83401e4a4cff1ea91cc" },
                { "is", "3598a7823f9ac58a48b04af4ebc1a34fb7398c4a8e73519d1d761a78022e488fbb137520c2f087dd75f8b1504a197a01f59bdbc14363444013175ee30c7dd561" },
                { "it", "f1d4359014a35e23217bbccaf72b296381b8c0f86205672916af814a6727fcd4d7fa7875b41a6b4ae3d2d84d7cb488dc96a4ff62c794fd1d7c6fe62a37aa9bf2" },
                { "ja", "6677dcd5a5b24bf3abdc5c2615b7f98b35890f1b35b687e84e4cf6eb04e95397f343de6db7042dc061786df292fb384101c8ae50bc89fcf3baa23bfef1880cc3" },
                { "ka", "7cb0523a7314e620e8990bfb0729ea7c0a8a97efd07eef71ba3b30e0fb10a73e517de15d6aeca722f26028a0708d9fdc4566e6d5af799c395232651007ee04dd" },
                { "kab", "c967477e7cb6a1017a3c4086d04e5e6773245735ade4d958124529974dcec64c07ca26589266929cfa1eea47b1ef4a485f8c9e19aebcdf44ab959ab50fd303f2" },
                { "kk", "57da528c56a8c11457c0e92d6f2538cf4f6e6da3766dded05185d828629d621aa1f501d416939685f05e098a81f6a818f7c2598575c2bd5da024def20290bf57" },
                { "km", "afe88a496dc7391e47316c70b2e744f10ed206320a9e4207bbcb258814278c9c2f4a0affe8cecf5887117a0b7ae5340eaa5d62e95e3aecbe287e90551e3fe899" },
                { "kn", "1e378e2bdeec102ab2bd914beb8632330ddb03f7d05b3e555cb7361236f1122324cecca76acccbae91bd56dafc23219e0b6f1ede103322db496a89d22353ef96" },
                { "ko", "6c8ba768dfd96b903a85ef5179505b9aedfffb1d3a5115e3aec65bb8b2aafdc99660cf4050f1e75afdd30611516cc4a7137c559c9147e2aed0ab829f3ff0f157" },
                { "lij", "b875ee899fac04649c347a2a84c370cd12d5737fef1462b1ba16c4aae9bc663b1a9ed416042127c1d63f261f0e6d09c688cdaef0b598bac763e5f3110669d5d9" },
                { "lt", "cbc3165b3271b0675852fe549bf245ec14c0309c3d8ba3f6f9312b587a476dc3896745a13b206b5ab788d184f577742779e0952471cbcb8c4e2d13fb0bde4578" },
                { "lv", "be78a124f296924318a437b6fb28c96159c22f195fae6ee0fc2aa7635eacc35b7ab64754e60a60a66a14b706f7f2ca4ee6f4fdda837ac8b44174f556aea5b21e" },
                { "mk", "cf0bb3d5b8165655d1d218d669391e81d343c63899593cb5ae628b9010aedf1a55525a45f79c4c462420a8bcbe41abf664752fed7624c4f2c375a8820a0c9096" },
                { "mr", "d0832b754693a2af55627a19336ca3a43aa2b6bab5fbdfd8c892364856156dea1c17d3410bf73b2341ce38e1a3ee3e3b63e3e82055ebc23e1f88a91cbe12d164" },
                { "ms", "3cfbafeec8ffd0b142c7231707e16046db7f060a3e83914631154412ed19d9a19e9239dfc999e2cbf65126682ba48e8f8d3d0e44c00f2456983a04c54aef3065" },
                { "my", "bfb25740f4db7fa588e1b90576358345b4813e5302eccc6c82168cb07b639507fee1d5353fee34658854dd3a91cef9f87bc9c46526ce9f6cecd45f4d8d20f012" },
                { "nb-NO", "feabc7d78fb8e262c962ef4281d900a28a3728e07408ccbc15562a44e57c0f446ad98f349bae2e14355d75d1070ab7d662a4f3ae24dd73aa8049f0e4cebdefe0" },
                { "ne-NP", "38f338c760dcd59ace2950f97e282c18d177f484771bdae86f37ee846d0d6dcee63ca8b3c94d780ca20a67784ba07574443164b76aef3b51d83596d09314a3c6" },
                { "nl", "ffa363a6470757869e52a95a2153cdf6bdf6b4b77d631d69560724015ceab4652b5f2b77ab99e6f2f88fbfe7d13657d2f315e7d2daef20ce4a40aab4f15fc949" },
                { "nn-NO", "29aeb069377f3e2a9b0877d4338c7eb0f1faca9e6d3a9958bd4a8063285cb7d24e8ded3f46942a621213f6052cbc22202b43c4e1b390342c2d6c72bd060a4eea" },
                { "oc", "6b43fe9897c900594558cfbb3b36a179c5a5740bdcef14bd40318d3b843737448f5f8d99945972f63691ecd83ce7624841cdab97c571cf2194a1ba95acf1ee6e" },
                { "pa-IN", "c6a4ab98f86ace23ae00f75d866f85516d6fef7d16ddb045fce4b27d28e822f3745f2ddbc3c874dd82df0edf906e62d634b10b7b909fab2603bbc3a66e2cfd29" },
                { "pl", "b0008d2c07d6f06d1884a4cd27fe14a04c760b5b1be937bf91eeb7be709e455340b7683e61b945f7019f65251aa2e290476691c9c9889f469c14f075bd6ae5b3" },
                { "pt-BR", "0e3b64642e4f9a2ba6b0575a9d99e00ee95a7a0eab2162b2ee8579e7552151fbcc77016f3092a2b39d00e96fef418fc320e5ee9764ea352404e1fa9e61dadbbf" },
                { "pt-PT", "07876316319e8515010d97c5a5ad150ac888aea1ff47f3c7c11db334a4c3c9f1bd9878aa768259efee54a19fb46a614b895436312567ec53f5ec7b28a210f00a" },
                { "rm", "d28d1013a4df3e94fce2a0b28def2c2450174e70b10fd53b3b3251ba37e983468d284970af7e9a6d2db489a82f208fb35f26c1611a9fe16e7607dfed0f36fbea" },
                { "ro", "03e7ac7acc1320ab05b7e9694988ee3b723dd03f287353a5d1b1295938d9dbcd15351d39cb58230346daed4460988e86fa28488593ccfcf9023ddd2854410566" },
                { "ru", "627a722a10a60f0a90ffe85f3e880a9efcd745d19ea56396c0d8e61c01a164fe772c863eea6258313c939993832a35c590228b685914bb40d1f3c9c1c86cbad1" },
                { "sco", "8c4ee1866d884d96138d822f28a1e14871d57e0d17f4802b56267ee7018b5617607bb720013ce847bf43ca328f8857b8d3979944f0416c434fdc5c93faff16ac" },
                { "si", "68f5ee4c2502f321e49882f784c4dcdf0236c1ed5e83645b7ee5033c536a1714f6587eb2a75ced70b08fb694e21089f6df8d6bffe5815933d1962eae23adf096" },
                { "sk", "7334551e1c961aa58daef1f8973a00b87d24b1b1ca007c17922ab5ae3249559cbb5baa03d473bbeb1adb84af70e58cafaf8068464cc12ebc21aa20dd1f12187c" },
                { "sl", "6de7ab17df985fc0555a8bea0a8909094b58a3e619faa0c103a28b054b01db98c09bbec4d429e771b5a0f4cf5ce25aae64502db86782d9d268299340a8d85eb0" },
                { "son", "34b15f0acc57e5597845b746db796a198180c07a8d8e67556d892756d6f1dbfac2c8e172227d0e7b135feb9deccc9e1499965e12ae70856f04a668183c322bf4" },
                { "sq", "b68292bac445aba5a4dae479c0462b5adf4fde6adf532c19b3fba7f5e00c8530b7e8686192ec6089898858d1ed8f8ae7d8f075c146ff0e33c57e73f3162333ce" },
                { "sr", "eebc367cb200a618da9bc6a3484b88481d48c21ac8282549944e5424018d11fc50ab7d5a92e73fc53bde2d5e3340de35b2bbb6df3c451b9767b01ad52084b23c" },
                { "sv-SE", "406cc88fb0660a98ff3c9892efa3bd20f060da3c404e51225813d2a645ee2cf5a4dd177315c66899ed812d6f93b1614d6f10ff6b8840e1dd7f8c807258fb344f" },
                { "szl", "7fac8e305caba5ee08018cfee0b6627cabb9152576f2c8d06263d0efa0432de7318992c163d03abca19ddb09b7ee9b8308763a1af003d8ae2fcc52dc2c990454" },
                { "ta", "9ca975203919bdefca2777e1dd783e8ad0bfae0372e5c8247a91f2d90b5a1092bea9db75db09fc5d6ef241d8cffbe04986305ca7e4df950287dd23aaa62025ee" },
                { "te", "c3dbf77e876c0a75a482a260b3f1e47941e660f3b89c4a17fb6e74e282055f0d370c2ecbc5a864c08ed7747114b849bbd535cc64ac28a61e022217c76fc4dca3" },
                { "th", "bcf3166eb95fcc59f46ca9f646947e4be7bc0f4de8d13559e4874c1c1c17fabbfef2e892cea84c17e51886d758f7ad1076f3590166ad2bdb9e8475cfea98667c" },
                { "tl", "f5d9ec8da71a6c6012b85ff8be4427dd7532a0488c362d002bf9a7c61fd447f1e95f5ae4c3456574e0c549f14a9eb8921a789281acedcdde0a6f40cdba1e1fb1" },
                { "tr", "c6fae3957f080f4f530e28ceca8cda207b50cfea2f2d139e1809af5d12ee31cf8d5e7b9604016e971eebc351d5e6fa8bce743d82fb4ac225b7e187ccf3453e4a" },
                { "trs", "ae0367c3c0398e3ca8eaba96bf373580b4483bc13bb4a86c9ebc59e1b982022eab82db0d2770019cdf9f6f7108abe92f6a70bcb1fc62e5cea467ea07ce3ad3df" },
                { "uk", "9bed5c4b4432dce1130750a6fb8676eea8e351b2119d9c36a1db96fb9b7145065bdae8d7b277bbc296614dbf41517a035e49aad297e437872dfd2d16d5cbd695" },
                { "ur", "fca741a7d7defc6f0578cf5bad5e6e1a5d2d4bed60ae0a5ef588907f595aecfa1e60cfd64d082f4af2257d73e6564b656084e4e924ccad844ff07d89ee62132c" },
                { "uz", "90e891effd9da94d070f8db8760c83ef9bd32560ad69758c13b5bf9bd6dd556a39d3d7934e52317b8d5fad2489d80b7aaea3b8e07b63a63d296a338e2121dc5e" },
                { "vi", "5162a1513cc44f4446ea9857b3319e67cffd4159b87ba60db730878f57857713ab74640dba505121df9bb70e5b85ec916e7fddaaf4e6e5981b634ea3b72d2f63" },
                { "xh", "d04aa30a0e438473b6010983791d1579077b9d5f9213340cd77f886f4fbf7c21718902a46dd61daf49dc60a961147e4ed2e9d8221bb5119d21edbafcc7a13d1d" },
                { "zh-CN", "cfb7818c42122403e50cb90bf106f7cecf9013c6d82d3a8d4bb5ae339ce4acefeef32592035a7fd58338222cec81effe5661f0af03a80d53e201c977dca82fe5" },
                { "zh-TW", "a412ca42a213424549dc9c5aebfd2f63628eb7cb079b9b582cc3670e078cf864d167c92d3afa0808d7ed82b61baa11b800563d7bd1d5bd1ca7c11b0be0b79ba0" }
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
