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
using System.Net;
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
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2021, 5, 12, 12, 0, 0, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "6fd3de2aa1fb4063e66151c661e207ec6d2f7cab7bc94310783442ecbcbe143a3040bb5caa517def8141667a2f4e2df8cb413d44a583ea524cdc8299fcc27bf4" },
                { "af", "f6d97f3b13f6e4557bcb210bd7a351eb6007c2fa4ee732c991d6f9ba46726deb733a37ff54b30414dbf393f32f483d12be45eecc1f7c4dd00736b4fe941a2797" },
                { "an", "858aad5ef5987ad7bc7c6baca5ff70904fc406cf5249005411a03c6f67a85fa44398409405088cb006f2caebb7e1711c6ff2853367d6693213d39e2b82a1989f" },
                { "ar", "9072f0e0ba5d08212367a63cddc2f4dbe0ed688c78aaa625877cea39fcb8dfa7aec50c71de02409e29e39de6e43bd70729f590df73075176edf2fe1ff47d7a8d" },
                { "ast", "c2381c88bd4103286d2872188d0bed0a7151c6f0895aa4f8134d05406ee4ef26b3e52d5656a6679ee459321d21e54d6b0f22e06ff59dfee1fec0ab57036e4e8f" },
                { "az", "2f3b6db5c2025ac1c46de5e8cb86d1622965a1b5f01759c1d3700a639802b2675d4080e84c2c706629b4cce10a60e0bb9a8f64b7098e2f2040f42c15f6ea2279" },
                { "be", "0b718548bae0196c9c8278f7a9dc20afe9c794434b76bafbd8d5d5b3a531e7c538bd0324379303bcc2ece2aabd3c16fc4f7a0fe1567acdebbab8295f39502a92" },
                { "bg", "e03ed3cd21f91a567cdc8b3bb316cb9177f24618f183caf2f164dbffaac886992aa69c0f047fbce6f45f7861fd85eda279c763972b5412214dc06444029e453c" },
                { "bn", "42dd20fcd40ebc65934dd7985501fb95a13487246a7e84331c7d5bc47f6c7b63947daf40ac880baa3909b909a62102094bf225a9f75637dd1b64206aee2831cc" },
                { "br", "a38a213871f36f5620a0563fcb4f6279b207e90bc5798fe8521575d33994e5ab683e39562af8b81f2290f37707bdf16f99034aa5d077a59bba167004847fe53b" },
                { "bs", "8064b234cdb3232b06300a1c6223dd5d0c1391cda68659956e05d9672d9da68359bc8e1a6a5a71be391732247621faa0c6bb80b7f9ecd6902e1d2d6791f48e09" },
                { "ca", "be2fef0103348f13a39c5d0a1b802f8e36ef902b98fb050e841e4a1c8b28fe61773b5ddd72824505f6353faa9f956a15d98306bc0a66aedfc76ba87dc1f7c8e3" },
                { "cak", "ab44e8f736fa75b180b114ad199e005e0b7f93517f3681a923f5663168c4061d83e503e82b64be2919c1c1fb4452bd0712148b34850164dd2678432ef4e41d41" },
                { "cs", "0aad938edc6837d10740a0f442332e1f41df4c24f7250ef0b34e7137f4c468f1c5a466562f514fc32a53b39f6a055235e90bd877efaea0a2dd70cd5fd0b3bbb5" },
                { "cy", "ffcbeb6a70bf1c018ce28e8c7d19fee182d0f6bf09b3e09253d0af74fe2d163634f89f53414f97cc5f9b88d25b6848d67f3619ec101dc91c5aa97298f693a74a" },
                { "da", "d5d855478455e6c74bfd5467a62ac0a35b0c3be17e3ccddbb488278e19881ca05ba46709662902608af72b1817c47b89bc7eb620db72d7db0cdfa910ab946af9" },
                { "de", "03c55f4a1625c563513563a0385048064c87405579c2a795e50d791761f2ed2ad2994fefe7d75f6494da34729d374aaa455922b5e8b3a7f9f4994a2861625a9e" },
                { "dsb", "5c499370abcf849e6fa0d21e33e2ecf8e2b7a60304b90bd659cb5567d4662ca6e1a54e62d65072e4a927869542d2a5d8d00376b11b0b0147d571af80ae7a95fc" },
                { "el", "489b1c7d4109ae1524f71dea6b8da81cdd3c01f3eda043183f814274465f056dcf15279c73d3c76cf3ee89ec115dfd5eb53fc872689dec9dfc52104830c984da" },
                { "en-CA", "4938ed455416d87082bd8889a8d8c7d0dabee0a4e4ec02141de643171aff0716d5b0b273fbe94dc972da76c75c3f3328612af11a94946298304a883b69a54e13" },
                { "en-GB", "169a2ff612f9f3d0c75ce4a01b872076235c5a3a061df90b8a3e3d20bbd07b691381938bb00c57a9c452c085a0d56b0cbbef0b040bbef42fcfea6322d08d4c7f" },
                { "en-US", "5d17b99efb7da64d30481e0b80d49f75ddef8359176765a30bd8d4d6fd92516b131a857569470fe5ef374e9ff818af50ca88512f2c3aaaca18b7534cc70a7296" },
                { "eo", "e83333ecc51e45781858aa8c65469ba7f03f0558a0009237212befea4fcf02b635de207fb37c0163047b2f9d5aa78550d3cb0c272c4143976e400fec76029e6d" },
                { "es-AR", "6e4aa68c34ad97c6de4db27c7a8d9001d9afa452f9c228a301a7ad98d60f19684ffe6e2eb1ab88fdcc16a0162d38618547c01fc25d32be842f41727385ed0b8c" },
                { "es-CL", "fd17699e5772ae40d2fb1ac2ea18e4832d930a4fe7b79f931b0aff2ef40fd2e4f62971b69c6c50ed0e05085167946590648b469bb7890137368549603381a48c" },
                { "es-ES", "1a7b6e88964a9fea866877ef84207c7dbc63e30bbd8f925956539b3757c219ff991a1f82a7657ff3b9423ac223ddd68252b2230b23364f4a992e7d14458b14fb" },
                { "es-MX", "0563046740d41506754758454303f095adaaacc3b9e747b1cbd167186ab7ddc667614485e287cc5890b7da212681a262ab74579410825491c1dff37f946384af" },
                { "et", "96b110b58ab035207a8e66e4d0579613442ca7509d465821f05fc79852e8c6b713b24eed50354da48e4f0af2c534bd1ba0f9b50b32bce6b7f7b9e24b71d94f56" },
                { "eu", "0181ac6b30352dec6c90909f526cf8e717f7cc5b4e994c4dfd770796cc99b16e375b702f61db1d1ffbeec9069f6a90f131e402837ce7974b8da365498800d46f" },
                { "fa", "4cb9e6a288642e6e9d38df49e8e214f80ac1cd1f6b8158e9bbe6bd74211ef9b2cd0a81a7a18919b12478f6e3eabbd9863337114d1f901382ebb568abfb0a1a05" },
                { "ff", "540011c468dc6102df3035a2d2e37525c61a7d578f9e58d2a70c400501bbd4033af34485af90b916946bdec1ceadb31a536b3dacb81632e24a465d1cac905c61" },
                { "fi", "abb9709629e1ea47c4968fff092ec683a67c66d4502ec5676df60f6f738345e0334dac67c90340e0b0e9cc0db458f43ca94eb3d4a657e086444174d386ff84c8" },
                { "fr", "497b50688eb0ddc213110bc438419b998818889c75aee4fabaacc1f58867e4e683e92ac2b58e7183487b173b369d2e289c01bac49923ce810e9c6f7ae3f58d56" },
                { "fy-NL", "fdeec1c75186f8fe4ce43b48d3858df7313383bb02b26e989ad98b71081b3e3db5f6854626e64aa4fe9bd3b47df4a41f86b9bf5f58170c2030cc4d76e4729c99" },
                { "ga-IE", "5cf0ecfd32be7d60e5c634d5c49d01292ed3fe577893ba86e2abc7d5200c08cbdb045aa761b0703d85c4312b94880217f7588d73fc14c2ac1640961c655cd5da" },
                { "gd", "f15e6878435d221d500e950d61ab3340d465638b9bbc33bba7c55e44d5506ad7806c4114bc1ae1d6fceb6c70684221f9641f47ba5d1da5a50ef80cb9c765db9a" },
                { "gl", "6654b2915eb941f433b32cb85dc985fab7208a3ad89b90a11e5c797321358f26849920d3cd914829e3f98afa9c817d15094d09338d51915500daceefb48dcebd" },
                { "gn", "9ee85adf0140296be1de48200a6691bb58b27018ee5e3a8f1e37651f70cf86a93a75d66addb6dc8ace399a13835cabdb8a0916e284e456aacdba255416c15a48" },
                { "gu-IN", "ebe04dabba79cca4638dcec14f56554847c9f9e649e01602ca9db8cf60f2067a7658efc1a73d5d073bd1f3469bc8e948e1a9e79500bf3ffd2924aa83baf84d11" },
                { "he", "db61aa3d869d7d89e2b0fee048c200f600b95a9863528762caec3a652d016750f4218472d26d87b1830718831ab8774da8ef89c6b5a111b5e7df57d6e4888f2f" },
                { "hi-IN", "9509797cffaf35c088c71d6540f3fe8563350a38e30df5c5375b5e4ef0115a53e9cdf7683c09bb938c6d77f913097197ef565a1112531036bafcac73c067d5e9" },
                { "hr", "d2baf24155b13a63fa91a1e522197fcb44fd2f7de2b95f661a57322d10f34be37708f33805ba1046fac01dd329337eba66dcf82ec3b75966614235605908cf7d" },
                { "hsb", "fda453650f8124b37cf14538301fcef72a8e2b309cd9cbc63f7b41e74988d1d68cdeffecab5c06132e0a629418de041829491044984a20f103378a4179a81b22" },
                { "hu", "ec21fefa0151ebfafebffe41a6f71742bcc548a343623ccb4ad563ec4ec3c1b8bdab9ef715bd7a6edb3a5ebdbd60dbea347327f6cac7de662921ba959e02263c" },
                { "hy-AM", "1adfb597a3c525565a3dc901b9841f346eb2e63c8a2d327fb48aa42e7917aa01527c477a870d38596dd8577b24241366e03623f68509dba976a6d9735deecef2" },
                { "ia", "1845e430f8bcd66c0cc6b2d492f234a3ea50f795571dfb9cee34cdcd1ce2c3f8192437a63264734dbbd2eed0ef5146b68f56bbdd40f0d99291828d8e024f18ee" },
                { "id", "0b988083f192241960782ec499858a867e77636ce74441ecf5343f27333f17f6dfe80bde713fb5c834d7955fff4de44d208a8c4d069eb3db23c29563237d2ee8" },
                { "is", "4c052f281e950b9fe3ad03bf710b6f74aa7957486466f55171a379537a5f1b7ae85343931edf46043d06e8518d18cc6cdd080735945358214ce1bf04134074da" },
                { "it", "d93259e4d2e136bfd6d48086a21278ffece2e831d0f93c1ce9df74448ff738d9e67ed67e4365f67f56e50784f611a0b2dbfbe6229829e48a3a726dd4557ee544" },
                { "ja", "f8865ea3a23f2fd4435bfba2c87ce3c1a00dbab96f68ae57a26df4de0f428b8254656a88580a4bb6a54ad46d7a90bddc98144c156f57f4e286d87fed36dbc878" },
                { "ka", "717a26df5d226a52ca1af140195ff90e6d62378978bb2940ecaafe09bbcd301961cdc76c08533c38c5de9a5e44433d9878d2bd925e16c06c61902f209cdfd70c" },
                { "kab", "3de409f7ff17ff3d40562587f3d15537d3576baa7a16a980eb59a21911c7981041984eba754d63da13dec87ccc184f4984275c3cf98e44573340e7e7d6df58f1" },
                { "kk", "754dff977e40edc55586a4db2ecd0924134a2672b177213686de5ff48722d7303e296b9d2fd319d94af31171b9ee9a41786852a4a44e299e7b45673befeba1c9" },
                { "km", "db4dd031fee454f90ff195686ead8ddf7b22ebebc41d3c9950358098bd5308683fe73562dc666ebb1a622e53b264106897e157a42a4c986d9a01b2fe9719425f" },
                { "kn", "7f5e868ce51c926111281f4805af0642b833bcd14092c7ab1aae39b8d211c408c52f4499e379a44110a04ac9dc9d00ed892f89acca47876b12c4326dcf017ce7" },
                { "ko", "9609f64a779fe95976ea656024a53a17a9a4b87e5645fb48f3f0fe181dcdac343d9033a2f67f46605e33730d3b15a9f8fb0320a28678917ede3079f9c8e1902b" },
                { "lij", "47cd8f49382f9334aa089ee691f2297cdb3d38ff3ff5d5b973e41bc3f968d44e98ead60d5dc2c9522fdba4099b7175259001b163086855d37709ff60233c078c" },
                { "lt", "692e880098cbd181777adcdf43d6afc53abf6ec0363f251471833679599157559491dd2afbd95f7459156ef6a2dd4cf9bd8321d1e65931c363e550893ffd3fab" },
                { "lv", "293c17fa213c8dcbea3cd0a405ca1a1639e7332084b06d8121245adb6cc2076e7e6c77d9fea4b18ae39d8bd3f345a8fb875e52d662f138efeb7a19bc4b4b1616" },
                { "mk", "6988ff89436056c77c58c848270c702145592a3c3009a91fe9942e3dcee556a001fe16edbb6df46d1ffd3fe5d6226b9e9b73c227d0c939aa86e703e9a00fc95d" },
                { "mr", "14b88e92cf2660b3016577ef433932ca9e3169f603fa36c239e73fd5a771e7feb1eab32615cb6d6ae4d0ff6c2f423f90ef7810e109c12a7bca4413c1d2a3b075" },
                { "ms", "a7ceadf47dbc7bcec2b02e5556863310439282f167b0dc8d98e221a2d439082f61a166ae172e201e0558004bdd7738304e9a0cf2175d6c5ff405965d925cac91" },
                { "my", "8673d889880e5d893ac13e16ee27df48f72c54d5a724b31e113d2ac59a580e41be22c2bba85db472f02f8aace22feee360f11d7a8f93dea5ee982e20014411d1" },
                { "nb-NO", "701e5cf174c591316ca77b712c36a162de106b94ce1bbc3320ccfa017484b9bae7ce294ed3e73c363a49524be4791e2bf9637ee8586d2690aa591d25b6c50a82" },
                { "ne-NP", "00caabb4f1c528774a44f3a3f7e787785b0dcfe9f27574401e0a2126e5e72b4d3b871812b6d575f87e06178bd9a63e7890d0d59d16779b832ec5a5896374f5a7" },
                { "nl", "1ce00d8462e0caa712ff915ce9aefef830af1ae4565033dbc1b41ebbc630163f1b51f648ee3a70c97e01758e8cc9b0484cb29479612a54f53f760f1070d76e97" },
                { "nn-NO", "edf10b3ab326e4ac7409b4406213b89af2abebef7a8c0fc5e9ff00935a99e83139d48f7843a868ae9233ac290e4d413aad204b1d4b90dc3665c92c2d48c5dbef" },
                { "oc", "372dafaee8e0310b58e591935e5c4eef410fd6af5d44361391cf45eca2668ef5cc17af56e0fabfb2c23342cff645b07b4aba2455966ebc5e0889c22fa9086642" },
                { "pa-IN", "f436e253cd35f7837866ea4b54adfd7b44087c95625bcdcb2d6b02c72a03cf2e55ec442933ab0d05a2f6c09dbb025d170b5b68097c9fd8acec5547edff25cee3" },
                { "pl", "169ff8848565ab3b0ac2064b0583a7330c1fedb403c697f1c15fd3405bd40851bf406f4695fc3e27753c0827524ff075f46c0bb9b16cd99e2eeced702d847408" },
                { "pt-BR", "129bcd5d737949757c290348b24d3253cb5c7c77ca9b27141b5434254e5178982c2059473387e7361645d9c3d9566105e4cea30af7d3fd0a484b4a7be9d48cb8" },
                { "pt-PT", "ca34b87f5ee566c272cb108e703c5759756322fc8441231ec9bd79e1567f51fa60a542c62078fa1b2efbd23f6cbe8fb9151fe95c015240ce72dde4718497c50c" },
                { "rm", "21b6e61a9694697865963a866636224cb79d54bf7eb284beefdb93e5d6d31a5b30acc7b530b1c901fb1a3f2016a51aa9f5a0928e40cf5f33158562724c0bd399" },
                { "ro", "33a39b55c32258171da852c8322abeaa10c867cdf6e2adf660d2fccaf548a640f965680ffbd3b52d3d6a55c06a6406e7493d636ff503c119b6ac99f13e6d1a0d" },
                { "ru", "e0bbaacb7102f971c3132e6f14a71583e23251a761e1358bad90672746f1965d6387d45b93ec0f9661d166f6621d4f3ddf33230e3e4466f4742289679bfe0588" },
                { "si", "89d3301c055822d89d2d44a2a3787ebbfda40b32bebd786f0416af0da0e12db44bcf2bf967f798337535ac00f68ea979b34422ca1c38703eb002d6a14383cfca" },
                { "sk", "1651a2473d52b100a81118b5c05a4af72ca64eb68c0813ecea653a8520f1023daf55db41eccdaf6b350225222a3f66d77aebf9501222772a3c4ce63e89f0b1f2" },
                { "sl", "4e072863bc00a72e639f5584582b5a5071ab93936de6dbb3f24d2740718ea275bd20cf297a8fe3a9f38ce097a3d2608bd3da8086a3f8fa2de21a5889b6642e49" },
                { "son", "089162a262a5028582923f960d27add22e66ae0bad89e8c1e0c73afe57e7e5588148dd7de566aaa48f04cbb43c762d508ff821d56c925374f424b87413a35fcb" },
                { "sq", "f4a68bf470ab6ff8a17c0703988eaa75a033c7a35e4faf99a659881a1c452d3191fbbcd8b34576f638663d60d3bf92fe631cc8e4fa590c055dae5b6d26d35662" },
                { "sr", "5500b2dde56375ee06b4cc3e8db214e654af852260292c560781b2c4cfd49b9e2c176ec6f8cd384ed8a11a16461022c8fcad2b3c485dd0f9d533aa0147253462" },
                { "sv-SE", "ad79882928441c8cdb0254f2eb2b4c311b8c61ca77f437b3fafad559725a64f6385d148c0498daefcfe63bc6c638e992ae15bfa0841df7b5ff60a322cf90c887" },
                { "ta", "b8d677b2d08c7334db204b1032f6b74e20d8834f1eeb65c379233759c679b1a4ff20c9362dda7a0c0e3efa0b8a1a86b7cbcc70bc736d00d98d7dc848bc7792c4" },
                { "te", "dd0852f784416532f41fa84479d0a414754f48ffd5edc6336be7b8bde5a173d3a8eaca63cdaae53e7a24fa29ae2fc6fd84ce7541a799545b5acea4137d614083" },
                { "th", "44ae0d731c09aae89ff5ec74d04fbd19bdfb54023ad56a2acd7b15f7b461907ba1006d67f0fdac5222628755f0e02d3edfe948ed83abc0aae5a30fce733e0c73" },
                { "tl", "41c053c28c57010d51c4645f27f13df0a4d8bccd48603be39ff625067b0990ba65543ab1353dee49bed0e75e8da3d1361d87bdf8fe111fe438b9558a8738c9df" },
                { "tr", "b6e3fb6282bd7423b617d237817545b408eb303a780118ffa11fbe52becf863bfe8d4835f1622a1b35da53a466feaf18e14fb4b70140ec889b3b6e123dd46176" },
                { "trs", "8e990144ea24cb9a032f7565fff8a95ef7c7ce5467bb4776c85c964e55f26a77e8d93add3452eec262577a86809b24b6a4a3d1f7defef3c6ee96e235266717a7" },
                { "uk", "95d8711715466c080f0f4ae87d0b71097a9ad34904691c98427cec16b6031103263f5dc17f55200323a9e8fc928dfb250da8f131914ac315a9fe22ec8e254939" },
                { "ur", "8d194d7f4827cd45f07c0260c5b94cf39e633e73d9c7fbd25071de5b3a55b28d2f08888a3f8339b6cbafc96b61be74661c86858905a9318653755f9b76f6181f" },
                { "uz", "049e388397ccd432d39f7114490cc8f0bb575cbe3d81d4241c98b68cef0cfb58b7698984c5b5670830568a4a4f0b41514af5dead640db51106e92d1a72acb027" },
                { "vi", "dc65125f5d75bf394cc5c3b3ffbf798cc81b966ec8cf977a5c1cac8629e1756de7a231b8c1cb367a1aac8617e8804ec7f735f99a0edd8c66d0d60bf794f630be" },
                { "xh", "30e8612c872e0531d4458079cebf236125e5eb7084ff2476f70c49390d8fa543eb0894cb469ffb92170f55e0f464a5378ad808cf0b51c0c96d962b5fd6de52ea" },
                { "zh-CN", "b3948f80c7944262bcdfea7d2b8e402b91a5d300a611a32d62362a83d69dc614b4095e7828e89e6c02a6d7455bb2a7d302953aff142485f1a7bb0bff43075a37" },
                { "zh-TW", "1bbb0e8cef24f6794b32c74ef0e007e143bc4fbebff63d2b958b0d87dfe754c67202085d9347b02446992021008c1343f7b04f291fbf1a22ed84793e383dbf13" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "d8cda747523fa41b35c0d1606f66121f5f5e2de685f327828fff8940075062ed391fa7d4190c54a3df494d316db8321fde68145bbc2d33d418ade08352a4de81" },
                { "af", "467b8d46abb37a62f6028d01f87dfa5f968342bcd587dd9fc298b5d8ac85526fd21b7e40cc6b7d7083ce4ee3c8037a278ee3967951a76b137a95b4a4f3b4d7b9" },
                { "an", "ad348603e63c0ee9a0821d9e1c110068ecf4b4f8c50dd4630755f9a5cf5f96f6beccc77af70a054ddd5530021feb19d3172631313016a671d87255b3f6df3023" },
                { "ar", "697484a14f5606c77ae5e2be308dffa25b6cd81eea42051962dd8a6fbf929d8f0e3472c553eea41fbd515d412188bef59f22d819da4fb948c7f26e1c7eeaf91c" },
                { "ast", "a7a65f0d87c77db778d1fc7c5332802ad6a2a723c4ce634cee79bb6fb62f7cc9bf9fa710d4398a3b1f873c408246f0062d0a4d1de5ea5e428a282d948a4a84b4" },
                { "az", "eed8ba4ce6efa7eea1603555c51534963af89d8b932d8633b84d8a3e8568984e836859b877a5cb29b92a1400a8382c1821409e876b4ae68db0e3845f9536101b" },
                { "be", "94ee9b0f4596df0d62d983ec8c1f0b46ea4b2b79682f263214ebf016504f20361a05af8a8e125cbd642d449abe34512f2841b4a370ac999dfad3a39dfe88b690" },
                { "bg", "5be636c6ec1b84df703a118e4f797da465d514e5757e05d269ec130c94c537e2d4731ce03884f49c6c947f246a25dd14de3b235c7413e19da22e8782de03a05b" },
                { "bn", "1433dce523589283b62b1c670ecb75c5429be205cdb39d184f1c0ed8647a2f723003b0f0f397bb0cb1eec93e2e84b5af51021a3fd661da4dfab6c7642912d444" },
                { "br", "0828c68750a8d892ee33195cd223f4e1d9b0dcf8e207767d83f3203629a8caf2efeafc429e4e20f0595dda4f6465b00d2c578b6114e8d2e151718510934cab3f" },
                { "bs", "4c3726658652db02e40e9071aeb4d0045471570485468d472c8a80589886656cfbad01e2c277e09466196473938262f6facbeef337f1825bcdb9434e45688b14" },
                { "ca", "0411fe0df321d8ca43c5ca38fb85ecb369d1efa0441c2a7ffaaf1049c4b80d8083f27e2113c42e81546acdce69c1f65e891ba02afda2bc2f090b30a7357c5f63" },
                { "cak", "d2c369b0006d789330508519fd91d424b8bbeb02b94fbb5c1b7821ae361f1e020307001f9e3cb35d954bac8a840c7c03fb434dbb7c2ca2ba8a8ef6a29f6c2012" },
                { "cs", "62221f400bef5cc8d3d39293143c62305e5cd257c84faa6e9c8ebf7fc1192dcd7fd32ee4a55e033407d6db03c944e2d52a1727c333500cfe2d00f1632b45a299" },
                { "cy", "3ffa4af56a3ee9bd600bf1d2f57a9876a03b9a7fcac5c3b9ff632054212213e1eefca3661b163d073922ce70d8479567c7af46d87ca2051852de76c9f1970ba1" },
                { "da", "7eae5cc3e8d715ae7a10dae9ed0f1179d4f5d9943964f676beed640b52d4f161c375072563e43c19fc85d93b27dd607d856ba821efd06e530281b064c4f083ee" },
                { "de", "11351f903f09aabde5e8f66c22fc7e747f7c40af093ab99702aeb4fc3c836504a36d3b2c7cdeeff56ce3816d2a53d2803950fa6eb78ba30d86da01d0618a74c4" },
                { "dsb", "31d1c3844094b673766a7eb04a4c57d6a7c793b93dd228422fc657be6424098a5e514c99e4fc1550f79814d549bcb2f0b1aa8be11bfa594380d62e942d61d237" },
                { "el", "e4457a01f88944c0d8860b00d354a92c6413e7748b5a6c5daa30f485d6479a1a67f6fa920d320bf08380b07346671c3cedc65cac76d93b674d8a55087a5abd58" },
                { "en-CA", "ff1949dc4c6ce7f00e00aa0fec3ebe3ef0cc4a234066b34fb2e581b633f25cd2727939a5f47f652ff6978bc53d9e898e4200219c1a50fc33a3d64ea6dfeb1dd2" },
                { "en-GB", "056078b2664ba93f8ca3d34ee9926bb801169dd0ecdc531491a2b1d38f2cc676a764d3571ffa2cd05118c6c54bb7263910c41cd12bd1b96e9e525da4c6512db6" },
                { "en-US", "ee478a9e08436003f846e643f1682a0cd1633c2777194c24b55eeb58c6fe2104b628e74d1a3dcd9a59ffd921ca3fffbcdfbe8f2bbdacdf9a31d8ef36ac9a7f2a" },
                { "eo", "86b357e80db79a072a18562642d6e9bf14009f4153248f5cbe3fae2d0dd799cc51c8cb912d674f1c3fcc13883910315331d278b5439464ce2c879cdc5d99344b" },
                { "es-AR", "311945c4e1c3a6dc7a0eab43b5f630aab4f30e1c0d8906cd1b93ed0c1442aaad70e1647b1cc711fa2b834ae7bd6df18fa3667a1d043e10d67129b2fc731a2cb0" },
                { "es-CL", "467b39b775d612380ac2583428732357f556954c50ad1355e85f6d18654b84d234a5d9587321053486d4cc98fdb57527d815e7f80752c52e2286092c519edb71" },
                { "es-ES", "986447b147b6e01f417753369feadee78231db142a15c5c1d11e6624297714e43d3b0a05348dc19e78b13075b997cf41bc67b16711a2dc92690c4c6f75704ed3" },
                { "es-MX", "a06fe1851ee0671f23a80487b894c069c4f9f7d075377e2c5865517dac2c883dd73405647030357dbc35e2e78e6cd1430e7cc670258d641eb0ca404e55154712" },
                { "et", "b7b0ee93a2635127c9b1983c066539edc83eb0b8e3a0c65de6fced0e6415921f61598b362ced91ce9d6f98365d2e13ddea085ba4bdc61aab08f44f9465577d3c" },
                { "eu", "b3efc88c35755b7f94ed41d01487ec0ebd20cd6746b30014c7c6fbbc7d6ef66b80cfdbdf09153db2e7a0b882508613d55ebdd6156aa88c6363a32b2cb2bd8b6c" },
                { "fa", "78701b8480d2f683155d21f4528cf5c6e8ff842bd3ffb61e73f6c52723b9cd2b4acc5628595955393774af47ca5ae22ce28a94639b4372ec01414166a12153a2" },
                { "ff", "b9bca93fa66dc51f9829835609b520f6e2afc2ec57f7ddd5765c6a287d3f9251ee3ddefd4f74b241098ee25b2d113eafe19d65fb8ae56071d84328a8f8498cb1" },
                { "fi", "48b082d6119d47c71ce6784548ac902afbe263c379fd8c04abe533a4816ddd585d2414f539283b757ce3e40f4f351c896c1db8bbd54b2260720d703426586f09" },
                { "fr", "3061ec28b0e77bc68ba3cf010e6bd53457865144df93592d83df82a00e55ed5462f16739ea4e5f79fd075b1a673df3e4fc0529e2a89a70745af22384ff0ef275" },
                { "fy-NL", "11c850d799b61091bbb3d122feecbcecbe8937631e369f50724a3fb1a16d397d0bf547baaff64578b198ac8ff4d816ceb3914912c7e5558be99be8646db6d20c" },
                { "ga-IE", "57b1e33cddcd37b631cd67113afabdfdc85c02c692b6bd455ceefa4cb5a7fa3a7fd4067398369023f1330326cd97abf2fa819fecbc8c418da7110ac3898b4e98" },
                { "gd", "8e7730c3bbb3b829d05b4bfdb45b5165962dd6f4ace04cc767bd823f0479e316f1bcffe5b31e7d1bbf5c6b1650db1a12ca9cc6a28a83b1fb5bf58627750768ed" },
                { "gl", "82812dbb88c00a8c831c17f48ed2ea4120a236d467899d716efa7a840b077ae88991017168f3dd66eda6a366846b52f117e75d5960d7385ea05aaf2720e79015" },
                { "gn", "e245ea01a9cec87144f0406d0917a0ef970718f8948b0bc011daeb418642f36b08e218838eec47290b439644baf408ca070f833420b0827dfaa6740c6d84bca1" },
                { "gu-IN", "a00e4ae59969da65dce107cd70c3b972e1be23d0eacd34cb9e012f1a52cd43bfca8361af329037a261fc97c80066560c39fc9423b11c0ef81429fe7be8bab813" },
                { "he", "84c1aab61c7e38eab8b2c07d0c4c70689fc072676bba8c5ee54dbb141432f419c6477c540d956fc0566cddef1f0a3e98507698acfa6ec93910d307c811dd6df9" },
                { "hi-IN", "c244f6470d5bfa08a1b588259db67c81437bd03676dfd29171756846e3836846057797bd604ead4d4a815b0bf148e5b28c72f00a714175f997e12b2e58575ce3" },
                { "hr", "aef4bd921ae185b30e145934c855dede3116a32b9bd4932995a0be3e85f040e9952fde7601137649cea838fd39fe65ceecbc9b1b3535ae72784ddc07defc643f" },
                { "hsb", "1e81a7d53ff1a1af0a4aeb11bd1fe5c973ca4c91b5be9309c7b273e821ef964b33eb7a575ba8a926527a6c72813ec79f9e6ea167fde1d8ca3cf11649b590c548" },
                { "hu", "35f52b55ce3f510d3faa5a417231089b57c1aab87ee5920c580e64682bde461f4d0a7fb4d7e7c9158052d87a8f42e48ffd3206567099d0ad7cdc81d26fdbd9c2" },
                { "hy-AM", "eb9d390baa472e2e8494e52feb41537c41e1b55dedc6aee379785fcac4e0bc4285aa03c7d624dcc424feff04a884b3482f926e25a86ffda28cbcad99fad73be1" },
                { "ia", "2ab0290dc7f44699c53e26e55036293874fc7762f58a6b30316e9e805ee93720739158da185ee9b5f94fc01c5096f026e00307abb52b9812ee12f93ff55999e0" },
                { "id", "3d53f0968a9006fa9d86b12e286603f69d619d2338f36fd764ecd29abb0ac939fa41d7c5a11d7c016b00908009e1c409e5da1dab462ada60d55c932a089c6e7e" },
                { "is", "0bc9b59eaf73a00e7190b11a314072d7d440689bded2aef2e42e321a2048d52923abbdbe8e4ee89af628544711ef47941825e2a2b4155aa1e96a8a494dabaa72" },
                { "it", "e76bf0a95f9151763f8b499b77864c046a7cd0c605c653cf181f4709801f83689b38af3c8665cf0713d84581ff0881a3fa062ba890e0541510215fd59a97a63a" },
                { "ja", "7032323222b1aac6c1c05ac5f9a2e62953b2ddc4f4c83ced1067e65c51a21ad0bbbb8d455f498f15445039642bb8fe8ef18370e3555046fa1db211420d77f09c" },
                { "ka", "a32e849afd3cb6e968839d080a240b6f4dd96dee501afbd804066be7ef50c4388475289261c730c42204beca7deeb9bfcfbf39c2ab8688469bcdf41a874c7265" },
                { "kab", "a804baaf424a5a9408500f771ad84b70e3414a14dfb56f06ba20be1f52aaebe2e495218bb9eaf9043a8e1f5255d4306a699b82990187933193461f32ea62aa42" },
                { "kk", "cbee3787016c89ff238bca0d17f8a28f8fd8951d1fb8f81c6ac0c9e285df51a88233947bad09a4f77c242768ec2f3cd7c51fb5b952ab0544fed47849646c8483" },
                { "km", "89f8d28715b05dad950e2f30c53f36c34b3bb43b20e88698120e43c41f2d61b8385806fe119fc33fe9f74855625f4f468080269d80f37896a8a83a1c0de19611" },
                { "kn", "c2c8c4adfe0dfe68cf5969daaf736e7308c7051426fd008d0fe8ebbef763464ac9c29b630ead03d1f7a647cc31bb213d478d0f6a9ee57014fc8abf99761f9907" },
                { "ko", "171f03ee3d53c1d123683a1da15d30d791e1165275b615817cd68b8b1dbceb1e8f3423d3bbe517ca9c5551c12e759a4cb04a018253e0e29bdce22d9875019061" },
                { "lij", "e30e14c77a484a11b777bde7c8de961af9114f3a7ccbe97813eef41759483f09162de403e0191326e1d8e6f0579a650d0388dc755fa582787773df55ae6d9429" },
                { "lt", "b35b4790d5850fd2a82421b3bd59be7f1833768dee47afde6db93e635255a63aa69870f7aff57d227921b43cb8bd4ace9aba4d2530f068e06035e241c4c985cf" },
                { "lv", "e11b5878001d2906df745de9dfdbeddc7449caa01ab2b69631392774a0c263a429c9b0d01f860002215ea019c9e1b605a0ab8d3a38f84c2714f875bebe57482d" },
                { "mk", "cc8036fa47368d8f016d284bcbc85e9ca0f7c54df24db54b315554aa4f4a171810abab29f393fe67df479356be65860177b2d5f4d5737f83d889aabb7715bff4" },
                { "mr", "b3ed7d3f77b6b0b9af20e5810eef165238a3ed22c633ca9ae7de66ae576899e01b809973aa647f6aa7dd1f1193908716f837179b56d503cab60f8f797ee3281d" },
                { "ms", "e08cf7e2cb1c2085d4734e21367c854f4859c2b31b04fc56d76a4e395f074272272b978f9298b8f2a30a9ad4b42e7b590774119fb4763823b095d95b027c4393" },
                { "my", "88ef794ad0ab262715a6edf50a7bd05c1ebc41b4ea67709338574cb8e425bb6548fe5b9b0844c251c37913d16674519afcb5b0dae88139b1a9923064e4f89446" },
                { "nb-NO", "15ee709e72d66a9e72066d995a9d4407d2198b3f0d69f6981f5fe6786a142610cf1873c8b872bfd1658326b3a1464f2e984c8dd790ec8f9197adcba59bbc7b47" },
                { "ne-NP", "fd7cb7de20da769a41a3e0f175329b2946ea38356cafd098f9b19ae68906eefe2bb5eaa85835420a83fefa96267ef52e2ca98138baa771d187d194050f5b678d" },
                { "nl", "bf30d34213695d262bf4f903154adb16c6a9110efd51270ca0cf590ce62723c31a549bfea5b96225c8a0143de44c9f4f323cb1e58ff23a7145bd17bb8dc36b85" },
                { "nn-NO", "57a5aa1ad54011383fd47add409d203b59b786450daba7b63f826312e589e7ba0de9c07ff7ee56a47b66a6cece6ed0fdfc7ae89bcf7b9ce824e3a2bb12944b5a" },
                { "oc", "36a1c684fae8cba856aa7d341e5153e0f8711df90c0427c2317562b3f6422bf83d29a2fb1f0b96b31ea9ab11547cc725caccf8cf1e81aa3f8cfac56674cceb69" },
                { "pa-IN", "2010332d37dda16e8311537cde5f6151ddc5d3199a9def5636fc5bc518368ae6c23403227d5043624cd22210e58a503964a26d086a453401635211284644ae6f" },
                { "pl", "5a8992591fe1d14f4216ecba2d2b39f2f895ae463292694750186f0e1a94665fe3f7286036aeda503f796b84d5e4181020b0f830e5cb6e883f76c233ee17785c" },
                { "pt-BR", "61b840f856cd02017cffa138f7c9bcf9269fff270a1922091f26e5c318d0a305b9b4a3ab634c52b48865dc7b3ce2ac01d83d1764494efed46f0a634acc98fd55" },
                { "pt-PT", "f84c15a229d17ce3296138f0b5b3b4e4af2fd7c8b24f31d12392355facbb842b9e4d49268feb30284adc68832821d20b044d7c7ed4dd143fc9dd5e0913ff63f8" },
                { "rm", "98ba364d8875e3b57e9b65c6a15305b10221e6e3026fc938672e0da8b01f351c9a4c5585a5c05e0660f1dec4f69f237fd30436dfe0bd0cd3e269f9808fd4afb4" },
                { "ro", "2a1ab643f315f9df093ee64bbcb98783e0a27888d8e4844a745171e6e535b17fedd3a4cda8acf822e4afcad43d8a54ff7435be1dcdc1464515f681de89cb6dfb" },
                { "ru", "570892ee899b7b1b57b8f88da2aa5553199cd7a816220eab4273f4cda5760e5644c014d890bc8757793edc7e573476824e203ad044701004a0d6a3eadc389325" },
                { "si", "55858d1dcd4552ac43689a56bfafa72e1b989d17f6b9df350318dade4950d989141b0792a03e5b02e67f7e4b276ffd8e6dc40d72948efada2f5a201205282137" },
                { "sk", "5410775246c5bf4ab613b4390ce26179a8605b805ae373c1b18ecd70b001850b2207122770d4e8bde2c377c8c79dcd691edf269ef73b6f6b4a1f0357372b97fe" },
                { "sl", "8f6b8273e54dca1f4bcc292fbf9ceb821fc80d0e781e58ebd7f5a62f07cb1dfa4a942b73d6e53985f1adbaa89f2d18c1760b2be8628b63a5500f134f40c9b8e6" },
                { "son", "74f2dc0b6a498f492a436feebf6a7089bb9f86eb86035de04544fde803981eaedbb0a181d84014f75571ce67d39d85727417fc61e924a042c3e5bd2845ca8baa" },
                { "sq", "f5b6d9002e1e413503f29b6c9ea5417f35df6ec078203419c7e7b3a614d9601848664e799abd893ba2caae07a57992c60493ea7cb980589d70385587ef59bc27" },
                { "sr", "303e20dd785545524895a4541e8b3b3671a822146fb3c9ce6ba986f8b41693a26decf413cc68d8512832a01ad9290e4df53ab462370e3314add86fa64c8217c9" },
                { "sv-SE", "305bd43d09c58ef64add622ef2311060fc4fc0c893b0ffee751993095b5da971cb7770c24c9205224da1037bb71fe059ed242e8c80709b26da942459b358fc14" },
                { "ta", "1163b75431428ecd7e7c9760c97cb4e36ca8c3b12a6d4ae6d78e8fa2ad7899435eb568e52124e659dc1a6161c42f2875ddc4678279280c81b7259377dbc64ea0" },
                { "te", "6917948a65a2e87220e75df6e23ced0d5e063b9489d517e236e2a8be37b2392dca8272a7e18020c0f5cf9bf2913e39b8d60cf9612edb35128fc388596a4aa3e7" },
                { "th", "56d4c25a78a34fc3b642659573c0644f0bbd530990c00bece274a6ec22b600c9e85dce87678963a632dd6f30ed8dca05d05342548841106d191e74845e51d379" },
                { "tl", "4c6168b20af29d0dee607da922e31933ce8eeb3ed6595e4334006c1c4ea086ad33b9409f6ed4b987339acb3676944541ca030d013c398a5234ab2416f3e28b5d" },
                { "tr", "d2f42b7922e5a9c963e61a89a22fba70c556a42f243ba8970544ee25ffcd398a1094e6dab1d3a7b778254ad1be0de99d5c3069cf521d9c78fb6890f8a30f46ea" },
                { "trs", "42db7aa90d18a057c9b3e8d5e5aa0352f243ac190005de5d77ee85b27340726f222f4fc937979ed0e54675f44e1c1d3198696e43d043c29cd14b367c006821a0" },
                { "uk", "5fe83acd360c48d561b9acf9b072465abe90e766877495b0a624be14f3291f5c463b8662e9ba6c58b7b962d4e1c60981afb46a53099f831d4a914513c9a10029" },
                { "ur", "a19137911ea524e1e8c01388596ffcaf7729b848328d6cb235f933eb0fa4ac341ccbec848068a07b52a9ec21e3b80b3063cd1785f94a27ef8011097f483e1e01" },
                { "uz", "0472b3aeff9edb3392846d44e83c7e9f22544e7dcc60bdc2a19df213ee4c9a9df6d68610605e06273053da6cee37e77992a78d62f2c4dc38bdcde06ad9d5b6a6" },
                { "vi", "6a95c705031e8eb96c4dffda7f3da6db99df3fd5be75c6c94336fddfc6c7d8aba655782e7e24f495f6b1765566cfe1304687acf6b672f319b84f18bfb7ddffea" },
                { "xh", "2659c9ae40c82f56bd83173de8a50f0439d1698e864e61e1134fd55f693c2b48db7b15bb0b2a5dfaeb19615af65f5e410b015a3c51be0a731445b490e300c3a1" },
                { "zh-CN", "7be0ff5792f4cd2db1d7da54d6b1ee5c4802d6414a539ef0b5f794365b6b3b11aaf28028fcbfbd362a03e5ca8982496b7d9616e3c7e2203c777ce64421a4c53e" },
                { "zh-TW", "ab22b4161d6c11aeaabfb6126f943e13a3c228a876e0f17219c4a9e3ae2044a3be3db0112a96b0f2a9bb20251353dac053d57105ce48fa9cb7589da31d11079e" }
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
            const string knownVersion = "78.10.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
