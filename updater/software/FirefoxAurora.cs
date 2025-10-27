/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "145.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/145.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3987a20d4c91d452a4757a55b76767c60a2afddf7122a431ad6f57d86312f07dc7852a34612947808d061dd1aa2c63726c5fa09d8b584f618f4303b42411ef97" },
                { "af", "5cc95001fe9b4fab33c988839d89225a5c7c7d9c37e637186091531027a4a7b0e1f71e4c998e81375d62835711bd4eb73cc425b51ee3c692b9403f1ce7cfb1e0" },
                { "an", "7b254d8420630223b5627303b587bec495221229c456c95de0f53bb0dada5ab9935e410535ed1d9179bed684a2769aea0927716ddda74d870e23d07fba1a7d1f" },
                { "ar", "b9431607b2e3cd665252972e675060d96d5a24dcf772642f542e30d0485c89f74eb7686c3a47d77f214caf2c5f8947a05270f8fa51f17443574bc640706a6254" },
                { "ast", "e51a44b69df50446bb422731cd48be650ec7db520d559c84b4ac9b33c48de5a782b78c5c8c9ccdd40595f010c80e8699fc4672024880a47665f440c5bfffd3f8" },
                { "az", "7382b7d99bf620cdfac358ccef2e808f9e04ce8507d6b214bdbb8658bcf1a6a9239e14c03d95de9fc019e584e6c00e890722c0936f41150cd66db6e9a9885aa3" },
                { "be", "9d220983e9679e99493473db030fab9002d5279ddf8cc1994e66fc38683c46907df7d713a013d966ad5d706ad5e5512d6e59df40a7b7fb88b53c51da2d2d72f6" },
                { "bg", "218e7494b68b30ff9a0ff59d5af6cdf437173f5823d99397ef09e8d687622d2f13ed708a677ee696aa2b7044cd58f8094c18dae028ecdd97d36992ae2b331868" },
                { "bn", "8af68c3592960b286ffa496ef898a09dcffa38959de0a481286c34ca6a3912ac25a46be27e3362657b27167aaad9c6651f68515c93e0452ca24286fd54d9c972" },
                { "br", "8f04c2e45edd576b97db73e2df8aa7cfa6c8ccd7b04fa550355abb3cd29473aad10731fa4723d4bda72e31f292afd2c71d92544b9a055d44fd3056de4ee2bb5c" },
                { "bs", "1ef079b9d979d5081f8db53ace7e459ddc3088e6cd4beceea1bf6450793dc752b2f6eb3d78048d5a80ee74e295a18378503199711994a60462e527426fb7bd1b" },
                { "ca", "678ac53d89ba09fc3653c88ae433b8795feff95bac8b67f0f07c9e17f5723f99ea11ecc3e2c32899896aeeae7e2f5c22721b47c568625ed39569ea9c679dc303" },
                { "cak", "3e419b4bc32cf46c2f514b467c6fcf553065379060dbc321e869ea6a6ce3735ff5b190270d551022a7671dbccd4b0bd2c14d8ef043c01f1af9c6d8e40b6fa3a0" },
                { "cs", "35b4e73888020c4f5295f041939dc586c259f3669a9b955c417248be0fc05eca631891ad136ae0628115fffa540fba1f6677bcdae04852bd4fd4638f524f8d85" },
                { "cy", "45bc327853450344b0e07d59a93f004f8073cb4352a922de9fcb57e1d8a63414674579e93889c3f856240f9322cc8398b24569cd1e159ba018a30e0589f766f4" },
                { "da", "fd4d198b6992282a8fc4687d13a65270d02393ae362ee7a53a43ebdccc18ddafbeb1113e7d7499851961a1998dde6b1d24876de73eea9110d37de20138b50cf3" },
                { "de", "f037c553953b629c6580a563a110af06dcb0f8457791951be19e296410fa9c78f13bf77cf1469cb25771101d0e66742f8c832c1687c7b239368bcd8cab836300" },
                { "dsb", "64925f7e5552581642ea2b2b50755480f7f88fc049ba4d43411e1a6ca08f38577ae5b7168b9988e31c0d1ab5c71ec3a03b91a3d59e2238bfac8cdefeed4e4a01" },
                { "el", "1e78a5d559b1545cf3722192dfada477121a7c7ff79728eb82c87d74798ac996433728a8b27ffab87e937b5a01a2d4a5199b491575a91b6523242c6612a925e8" },
                { "en-CA", "2b8b1dc24ebf477bf5997e02e4d19fefedebbf4804672ba6d3426508f474b04b7d5270fc95584077faf45304daee4707ba6bfeb2750a4e5f9faa8dbdb40a6e48" },
                { "en-GB", "4654c94ad41b2cf280b6916e2b7c811ba43e0217f49ab991b53c9fd1efe4a02576207a30f646aac5be5e99e0dc8a04638b176b6a1c755eada77f0bfd1b30136d" },
                { "en-US", "7ff33b1ba9f4cc83c76075a91c36a7306bd81534d1dfc3d19f7f5d25d878524aa170f94ddafea5f58547cb481ff4b66c9c772f0f06087c59448c13c8fec2603e" },
                { "eo", "e41c5b1a247b8b45d1c4fe096b88a5b70a33b1dc114221fb390635900bec46160c72a51160bbb37826afe3e4264e773a807d6eb73f8000461ed93081fbb9faf1" },
                { "es-AR", "104f3623291d2b60538b1e500121007897b42f03db7d59c6358f7b611d2dad3a4ebad5dc53a6ed04c6ed6d73b32bbca94b5e4568af5dfba2b1c974e87d85ca53" },
                { "es-CL", "1abc14d2339c18d38f1df5b1f7c542e04fc411faea6f39775fc7da049e65babb40f19b5bfdcbf703649178f90e221b37b65f1d081b30c67af4625564ce1195cc" },
                { "es-ES", "caecb7b3888d1cd3998ce7ca1871a04708dae49869e31ed0c4f3350b21c38ccfd3f49e4bb4cf299e8a22155fdd3d9040d5fba083ba5763002949c3bdc6dbc8d2" },
                { "es-MX", "cd965b49a3722781f7f19f088de6b7792c56a69822e63ef6f8ed1a690c9f7beca1edc0888226f48fc0a37ae2f5a3352d8be7d3180c59bbf488ce7eb222f832be" },
                { "et", "9329af4a2e8cc0ce6f04773eeb147fcb1dda702c7d56455bde074e885e13b9511546a9f5eda9e51341673af8989c2bb9030fe1d281f52aebd4bdd263bfae3af7" },
                { "eu", "d9ca3f32f7c40c7f6032d1736154a3c218d981a4d7ea9d292773ce3bdc5cc21120cf05a6171aefc15cd39e77fe4c9a85f911066fb603156caa43d09f9cec82c4" },
                { "fa", "ff1905bea73a969051e83d1f08caea795a3ba840a26e2d568fb52177ce2a8257af78d0b6ce5fdaac87e77f4839249e46fe9a05a2d2ab5125f322856ed885ec91" },
                { "ff", "400b4efc09c88df2395a0e8098c346253920ebf86015e0742313bf64fd80c41e2d1ee95bb8801805ceca4c3cd031e26617af9c930a2a9cf04a64b5a617100442" },
                { "fi", "9f9d5604a9d9b9b54d23cf73bc73ebdd7b16285dfd2ece205fc9734e7afb90f6cb638ad6342145186740d9d520102dd0fc6df6ff6b6a65112793abc223231ff2" },
                { "fr", "020a04dde3de2d9bf7f0e08a74e8a770722b0afe98c6dd5a371c2e7364ed732043115e6b315f0cc3960a578299a347e7c0cc8f90ee47645b49a844fd06d0d05f" },
                { "fur", "3a372dc7210d4312654aacf8ff81a1b42883648bbf842583d88c3ba51c5bbff7d9f964464fca58a977141f9206f6d3bee850d517c22fd0eba662dbaea6d25f7e" },
                { "fy-NL", "8c3052e98da9b1629c3ed805aad0abad96be234439ba610d25651e07b0c7ae5e6f5aa32c1c9085c655bb02465edf0bbe7942b5f58ebec6a4f7a06e5b15dfab20" },
                { "ga-IE", "e8936cbb2e6b27ccaec9f12eb69583736add067403eec86b8ca9a31b6694e824293c65172e20443d16f43c7b75d2b71cfd56a544ac8cb7df747bf64363740029" },
                { "gd", "65c070cdb729725921bc59993d2f06518e524f0ca19c5412bfa340d2541ea7ce0728d6aeb13805cd41fe5159b232a06f6156213154e6405a962ac8707a39c384" },
                { "gl", "3a1c206022c768ee0f38be96ce3916443396fb812cc4a51da72b1dfc3f4600e38a2fc919e91bf2423a421ea28ae7c7884dc727afebd92741d800dc6d84645e39" },
                { "gn", "384f47789aafc9d2d6da137946f270fce71ed6bbe84b0a0a54ef116b8a7eb6294fcff29336a979fed413d549f85ff4c67949b5fce7071d8e3cf734473c78a982" },
                { "gu-IN", "2b82924db590423be3aa931a4daf423deb4f9a4cf6e887ef92fc7e0c36663f1f88c6b35e953fb6b2c2f7a706f719ce4e059699b8bb3a2ece51bc802d83f07da8" },
                { "he", "16906466f4f34490a2a250ed6d9924c75487d299e0e2e9ade023dca93e3bcfce37a400b0963689310c966e0a09a84737c3506b82cbc261756ab13cc75bd8dc22" },
                { "hi-IN", "85b523e92430802efeb6eebb8b37dd61db00512eec7bb59a7254a24b635b8b4baf0fddf88f314d2dbfa0a149a9f07a86b122eb78318cb150423ca1a65870c398" },
                { "hr", "e542a100291f2a6ae59e009e197b0bc439c8f8dcc8ae875458fee8edbd203d3c79893c6254d57227901579e244450d10dc1766186785e258c6fa25aa15ae974c" },
                { "hsb", "da006b26fb9a7cce11169f756444358c2c5cd49642c09fd345ddfbd393a1d6913103e8440a3715f25e59f9dffb493ba566bda348985258c68ea2f529bcee9805" },
                { "hu", "bd094ee32d924ad335268471a3b0eb751680e352c411a39a0f257ac755bf6a12cfbfddbcf9270842c8d9e35fcbbd9fe13c4b37acabfc769cc9a564d1c02cdbb3" },
                { "hy-AM", "f1777b7d9fd1d96fae69b7f1d046da371401fe565966fc8b79e7a39fb562d851d515281ad725444534e6316fa6af294e4278fa069a5419d1bb555d00d158f5c2" },
                { "ia", "f4376cd673e3d32013e069fe717ea6e63a695ea8e07fc69b630a92ade201eeccd56762706e63d63946edf35417e489138f82ad7c58abec1eb8f0d4fd78d5f6f9" },
                { "id", "e97dddd171fc20362539d90f36236a2d47fadee8a2481f322ca8bc42f6c14c4f2f8a74d8ae8ab89dce2d343b1cd55a67aa6273a652e1ea154c3ee34facdc35d9" },
                { "is", "503dba98e920000ffc8f0fb9777e8a0e20a31cffede1fae424341be34824b11239df4aa30b699f2e51bc20d7913257b8a9a7ac4d96a41953a17b978f74f85299" },
                { "it", "d5b985633ffc3c0c547255ca1137256a6084b77bd8be33eea508c45401c82f4fca42be8842687b422c040bfb8deb9445a678619136a10216d5f07c73490b5478" },
                { "ja", "b2ebdeff320268fa36633d5a7ccc8d084f0ad5a1e5e4a3bf0c9972bcaca53a73ec054776fb189b83c24c66a6dd018e85a1a34eb627b68f12cbd9f34f9f58e4d1" },
                { "ka", "c42bb8e03aa25093a26263193c8332915317ad44c273d341180c69220adac14cd401ad5195f36346d7ce36022535b2446ee7e94e40c3e188c417f942f5b96153" },
                { "kab", "d8a9c42f3124b10bdb2c3450bb84823e2847f94787f1595046f8f09a1aa6d002ea4a2c7091b95f4511bcb791e8e96b3cd22a91691d5a6ce48b242d85ca5511df" },
                { "kk", "1a1434674c4935a6fff0c541036c4b79e80183581acef2c4d096a23e8f3115c2a309bf9c0af0e51dba992836d810053d71809aad9dba1b338ff03c028875ec36" },
                { "km", "86116acbf8e5da77a9f16857cb98b33d8181e04cb49bdbbb25ef2acf54eeef17fcf5c06533ee34a1980c0c640b2916eb6c9baf466a85b79d2e76c1bed3601c3d" },
                { "kn", "34ca740442528ab4292b49bbb8a80b095c9900030fbb4dbe3756eebbb95adee56e8fe45c26b4b26b741444413e61739ccc89c503104c5331c35772c4210ee5cc" },
                { "ko", "f0011413160514ac10618f2422ee0b4d478c32325eef3f9b3af477fbf3d445605ac8b33ca2a1f5f68ffcff336b00d3ad1e7c18c15e57a39e8c0709a6bc5bee51" },
                { "lij", "ecc104a9b2300f0cd5ce1cc5acc419e109dee2b9a934ceee83165f1ce4f03640edb418cb7cd8f339c5b5778809db65029eaa167875f8484af7badd720f3d6c5a" },
                { "lt", "b71f3d666120f4d4c48dafff722fc3ec501bdbef03534cab8cbd6fc17c6d68a6df904dd130b53e2d2b8b5466270901ce0fafaf9d9f1b27f58abc6d367fd05c5a" },
                { "lv", "8124e63fba36060cf837c2dfe87889a23aa1df933bde41b78584bee15a7cfd8abc8bfa0680ffbeb68c7fa75852a905f68aabfe03bb49fdb3aa49e794e6e38cbc" },
                { "mk", "4c21b55abddb42b3cefc8b49dd2d471b950500b79c64d5ab443cb868bfb212d8cb747095eb02be4dddfccb451b730e30886dc3aa58dc217c51c59e19678e4cdc" },
                { "mr", "3b6b616dc4734a0c23278ced74c0206357b671d963b67b2c9cdf8c56f5d8a2a35e947f4656403198283b550cc0389413f22d467404b3fcb11885c248c8089c3e" },
                { "ms", "f091355e7b816fbdd46c522204a2dda641a228d3feb756c3b8bb679425bda40676e91ad9383bb3cb8345910a898129b5dbb53c64a8e346ea6facf38e22b0f128" },
                { "my", "eef382e05a14b42051605339f937f6f0ceeaac011907c428f6fd36984af77a8c9509c277e8fe2b7b0bdc8752a99da7ca5a4bd92953b76511b09fb427d73e870b" },
                { "nb-NO", "cef8e1afc073d5f7bb535acecc29fab15c1a781fca0e26aa369c8247522a6815b0db500a4b4380df2cd3b1895c75bf1b625a526c4363949f10b2f8770c0a7126" },
                { "ne-NP", "84a93788681f847c21e6633dded4f09b6b329589ac56ef51e8c77d19e15216795da7450ebd4f31510770b7ab7033fa77426665cd4e44541d9d6433d96cdcd7e1" },
                { "nl", "d887dfb3c947420e1fdf6e1033b8a38c8d6f4d232ccfc487f29392ba17581779ffeb608e2d1112ff0454dd6268afc5c76a4965075680a99019173cef48fe70c2" },
                { "nn-NO", "e2c921aba0790fa27bb4bed9b12f611295c61db2a5d6920cb65c46a994b8c9b54e3998bba0f2403fefc8478966de96e63700d82fcf2a30a0b7b98ef50c293da2" },
                { "oc", "3ae3602580ed189cadc0958a2448a84f4a24a1f1ff9a3838fb7d19971b533abbb8e0486271a5d60aaca6191a90a88e8cedf3efebe6379cc993e47cfe87875eb9" },
                { "pa-IN", "89e2973dc6088588832c9f0e3fd56979ef5b9e9b79dd9aa086e4924b4af6704653995d8c73750de13cda8799a9c1eea0c9f149cfacd6cb1825baef7b2fb37b2a" },
                { "pl", "6b553a3e0e0f1a13c5a5163210543e0ebfad1a284e71688e3c4564707cefaf132973801d584324211fc323780d55eb039c22585bf38c2110ee10ae477b080d35" },
                { "pt-BR", "fb03c31f59b901d6e424e9f0bb2ab9943d4ef9703b54906111f0f63fddc392e2c5904eaf180fbe2d6f635fed4fbe77dcae721d4271b964ecab2b55c4554da093" },
                { "pt-PT", "7fc911021e566b7089176a8bf82fc96d8ac510edbf281a8eb774ddf865c2f3af08a87cd1a6a0f86cbf71dddc72b2f2b659afc82e1f501d6eb41692d342cc6bb7" },
                { "rm", "441eda829ac13528c5016dfc19df71b97949ebab55f3fdacd42b536b8b02938cbde60cbfe30fafc5871aaa0087a4c53f3c9d1039c96160b67040d88e15e8b1f1" },
                { "ro", "27d0db2cf4291d78883364dbc80078fd438132a2809db819e79208266de8e5ce3d098289cf5dfa0931aab1313c481881c7c2d05f0537f172c41851d5aef0afea" },
                { "ru", "a1a91227b2175a93fa01715d10217a0322d775726f9f05ee7c8f98043048a7739480e7d7b67b8c5b919285c912542443907ef207c7fc247302c3bb653c837589" },
                { "sat", "a4c725e6fe2bee9f633da9ebba4523d07ecab25aa97ad9e1795adc11910cb3c232d500fca6864a3d34276d243b0563774c9dc8dd8decb61b87459f8eddd94023" },
                { "sc", "f595999a2b27717d0a6e9d53a4db1ff527f84795525d40233c01d62d6a8cdc4e81578c5b3e7d4dd5273039db3e911db808984bcd372f7e0b35eddafc72ba821e" },
                { "sco", "62b8cda4774c5359c01cec9a514f4f47d041d307da9b4cf20bf3b7e0f4f338041124d198af12e6a19e2e546cc49b7924ed2188c723db4450a2f9821f0caac7ec" },
                { "si", "fae45db4f74b4dc8ffc334a57110f0c93fec71f3e6f2c8d57266a944ca7fa5b046a886ff1d44c3b217e4269094128987dde69c324330d3dbb374a815771fc8ff" },
                { "sk", "11b088e04bc1d93b693f7d57c8daf93f2dfb009568d497d8cfa2d5e0d3eb7531984f87c3e6bbec0ad2a8c750be154f4ce48afa26c3c345577c394f07f9119241" },
                { "skr", "77fdd218ec48ef17e9a96aeec29bc4dbe4cf78dda35bce2b582cbefc93b066d6dd54a5aadfca21e215d2c402fb09621025c9bfe9b73dc1aba2587bc7b8c60992" },
                { "sl", "a2e104fc2d6d495555d5e8c43016bd20b0a957e79842233125adbf33e8d8a59af5c5351a1e9afc2b21ad565779babad311d6b5bc1065a97ab80ba275792b34e3" },
                { "son", "f015283832b8c9e9f45c99b90e64dfa8702ec7731f5545819f6a363b214dcd1966cba931dc5b8630a4a913e504a6e16d90362a284aea3a4895454fed5b9a983a" },
                { "sq", "a6df2fd1378cdfe0b89b25b05d08fb452f006a602eeb0ca38129bb40cb6323c19a980267dbec195238b72262452c3ada81d2e41d098d2db763c9be30f625bf13" },
                { "sr", "df0ea3acc467b67b5303037638979e7245f4016d26cf98aa7b8344913a346cddf80f60d02a34b92ff433a7b61ccf0593de0abf6f83fda8f60c783a354bcefe1e" },
                { "sv-SE", "ed6b81bea7cf38dd87e917a91c4d18dc21d403ef6565c541e62e318034fabcc234d4c879054b0346397a31c9b6cad522296eb1a4ba47793fcdc33ab49ea354be" },
                { "szl", "6c5aba93392fed91bf99179a8785c95f5eb1508ef8cea9d0e8565b8da9387ff3d1014891dbdaab63dab1a2a34d690f0e28ffd9c40e65f97c66306fe216afe29b" },
                { "ta", "7f5dd9034afd2c33d0501e614f7378f44890bf7b7ee454c087fdda896293438f3059274b22f756715270cc9d22c90a450e90f0f46b00941955715010c0a1e6e8" },
                { "te", "499afde83f6883f81a8e2725d13b3df3be9344416634f11a001a61599cd7b737c054c8c7af687d26e724eb355dd258db274c54ccf123f01b1579a4a173148f13" },
                { "tg", "35cd98b5f79aea1c150a499f939ed4c8053cecc74fb7ecbbd9233ee3c2f90f459845a8114f3f2de479aa9771c1ab6bad7d63d77841238552b591bba88d86d9d9" },
                { "th", "206f7b04209fddca954266e90a42a016d7ff15a9500c76f43b926ade8b4094c470859793b33a3f6083f14683ee2704f81a108a9ecc906e67e4352f775fc21cf0" },
                { "tl", "2518a5026e9f813d7eac716922978134b9e74e88f32b19828c96b1a8f20fb3a513b540c8025d338f36f56da4939ed66ac3f99201b9d9f7f19d95d0fea243654c" },
                { "tr", "a1f7a772f13e9b4a9b63eb1a35da0df91ddd0b59fdd8d3b96470a6fdf7d71b515de500d5a1987c3decbbe0f90684721db671654dd8fddb6b305668c0b9687e70" },
                { "trs", "a2b43baa864101172da30cab596a4253dec228075bbb9a716c58c58302d9f0f80fbf55b690e7c8a4721363b64ca82ac8c31ff3f1a95ba7158ffebde452fffd9c" },
                { "uk", "4f257bf32f2bea6dd65ff2a38ba6555098127ee773395eea8f887da21d1c39e7b94a1c651790e97c7a04b6e4d3922988ff2613a97f5e2948fc2c9f5f40784099" },
                { "ur", "420304ae6212313dc31c48b1352ee789847776936029d483dd6df3c435a8288d5638e178b838d9ed40ad1994cf5ff9f50a3bd4a2d62180ad25eab601f8f94b5f" },
                { "uz", "8f19763f2bccf847d9d60fec18c259f7892ee99f0a3cdb51a576493d43f03c775a93f690655a4f5738e5dbe025e076d682e861f325275e24cc45f1f152e79952" },
                { "vi", "1c600657707d420d0e16112198126e554f23deba5163a95a49383f9780b9596bd54f593320546051cfbce6f85fdb9218715f12edd3a20f918de5840f12d9cf7f" },
                { "xh", "99a80d2d55748f07e827588c422d080ae2705d15210e1a14932408a2dabc943a16f66a09c4ced4bf50c46cea7d2c525232f95a2cc1ad2771216f7d3b805eb0c7" },
                { "zh-CN", "d78cc6b99eaf5589861b33a3fd3956d36cc00eb165155a2ca72580478a8cf56f5d9aa8e92b410ec1ede83c579fe957c69f5e74ef89f38b40c27bda248e0452ef" },
                { "zh-TW", "a02f85df2fb673f01fe42e5d8468593753cc776f3114a06f7117e4daaaa35129da516ae9c9d72a4e52598ee1b8b988d7b498d5bcab426fc654fab801c634ef7c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/145.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9b145193f5a25234a463eff7b408a18c320ec34cd9a4b8f213cb0c674840ba0e83a6f4fad331a510dd04e09eb2ae749d1b3ff6dcf810aa7cc9b427834bec0c96" },
                { "af", "a7f38d751660ea1535b3f9c83074ba8ead2ff40700ce66120ec4b8a004328cb50e985d0da1454a10af8695ac3b9e4d3b6b18bfbd218970a57956e028e73cf7db" },
                { "an", "bda4a74ddd334d4a3de8bdf6193a00440177eb8ac53e4fb8180672c8da2ae0d1f686478108d286653e555e5c6dcb45a6408e0027ce0fd4f3cb076de6926b1e5a" },
                { "ar", "6bfa3bdf28d9ecd9931a1d95238d4f8bf258b394f1024e351b71da8030e3a84fff550276ac733af8eb395f2d5515b54497e8103688504a575aebb45b072ac2dd" },
                { "ast", "a91eea2158a13cc2f63c2aac5f2cd4ad1b77cdc37cc18a7f20409c77bc65534491151411619b93d61639f05afa991ac02b23bbbd21bbc7f4d7a6f15569ed792a" },
                { "az", "5af6d59e426c9691742d8c7a01d0542ce35ea103564e4ef97a64dffeb0648ddabe7289a9b19613e3d9a563d0f9fa6786229622539c56a540ee86d67048778968" },
                { "be", "052d3752cd2bba06ee4483a9cd1fe8436778794c78bdb0415ace50147a0c1da2bba06ec52e3106321c3dfb209c2cb31f3bdbd8580f69bf3a46cdb01cd89f77a7" },
                { "bg", "9e0b6e5dac77da32a9c25071bec068fcd4a84767d9974506d142e1b81fae0f579b67af661ac7ae190ac5c5661692d85676dcd3b5b98b5f6cae287df27130c534" },
                { "bn", "78a4b2e81950793e19bdcc087c2de6896ad4d07070e0bb7ffee6ac6de3698ea72eac8ed8fedff263fa657fa1884a3230f39ca04c0be465b77545a904a300789d" },
                { "br", "7b3c265a6b0e74c61d4355a9b2e554682e8356f8e16e25b9b996f5504d08c449c970fb6b8502e6f57ae31214c5fbec5e086e9773a89c823f680ac7e557297139" },
                { "bs", "7dacd788a016e854784552aab3efcf2841129a641b3c2b4f2aa11578feaf0a620a32eb407d8ac586993a618d1608febc360b10379191cc089ef78259f56b2e69" },
                { "ca", "9263b30f8b8026efc36a65f574398ae40dbba9344fff46de34af1aa8e2ba10601eb16e6f9b8253d147569d2b01426544e9d41d75b009231e9e19eeb03056393d" },
                { "cak", "f591175c87909589d2513e876d7d95d32db5d9d7f9643bcdc49680e6b515f348f4aa698f1a150cad3dcc9442614ab1067a4d772c6669859897c89d09e02f3656" },
                { "cs", "dc69f03bda225818f1be6e691c0ae2517c45a6467c332a712b77e6e8759189fab5c22a0ac67a215e16954da271c92678d12a2effdc739916a463e13747583381" },
                { "cy", "fa135a7c60d0b3471f19a0f422a1e146ec85728afae980f69e8a885a00cbf6edd6006b193913bad1c863b192737576f05821113389e9d58b4fa0c96480dad31e" },
                { "da", "f132c32e2fef8ed64c501d981e9670b8f77e2da889e53c02644c671dcf6a20706aef7549bc2828972c973eafd5261ddb48142993c861b370cbf35b5a951e2df0" },
                { "de", "d21db04becf584970186b1df6b7777aaf28c414ac58e12bb9aefccf59b4140c6223da113d6cccec9aeff42e947811502bd5190e2300760da16dec700396ba782" },
                { "dsb", "d2b3c3fcc905b97334bf3bc25a4b7f4828578104dbeb4ba0cede9f3b1f338c79b573a6f1fd6be72d4033e02bf50875688d2e61fb1d1a8a3016b07105d4306e15" },
                { "el", "6096a9d4e26e2713471cae00b9ddc0f94761a1054ef8d5443e0a04c743960c7e343e6e0d893986184d863c614cd0eed14c5fcd4580577bc7bdb21d6b613a265e" },
                { "en-CA", "87fce3a2c467393913b0b1587d903eddffdef402d4f102146dd00436aceab8d7a140f9202e6fbb29f973b79a89c89f1a835acb82e414dfe12c972d14eeac2f32" },
                { "en-GB", "508fdb9b1a85742682ffc8c3fd1677e7bcaee375148b601eb6b186b16c64e1f2a543e7bfd6e3ddacc4d9a72cb50d4178d59ed7eae816b4d1e261beaf170fa1ee" },
                { "en-US", "558689db31e272498beb3ac17f552d5a0ad684c12369a8f6af5c07472bb0234114f2d5beb5671245f81f7bb0810ea5400bdbb4698aa5819b835fbe11bf5e43fb" },
                { "eo", "1b7ac134cf9740f00b0ac33e3acbca95e8dcd99e875630ea4196ac2500e5ed5ec5015d3318d7be07123724c42e0b9d8d523a23ab7d9ca846f62b925a477f5d70" },
                { "es-AR", "1e0f12fa0facf24785e281c615f5e51b31fdb8976743cac7d345feac39d3b42f484badc931f5125696392f41d248c9985fe3e93bb7c6998befca848834b8f0ac" },
                { "es-CL", "51cf3f7c5351539fb3a429160f587938462787ab9f40ccde232568fdc599c598d1d8fc7edc857d4ab1b82f942e42644a5d068b58e45cc7a249536173b4ab452a" },
                { "es-ES", "013b4d220780ca72e64ef130e3465c53aa3e66377f7b15c33b22075b26673ed83d01a00a66aa26fcedfc616fe44efbf3272f9413aeaabe33d416541c06c616ca" },
                { "es-MX", "5dbf7516b1fc0a9da694743a099d8b34832e2fa931222b78eb124a3fae24fe328144e0ffba409fecf04b4947bab9000abfd8f960adffa7a75fbea405374881f4" },
                { "et", "c370548cdb586acccdc6e1440c1fb55012956eb53f853cd4815d1ae1acf52d5cc9b9eb644e079ef9e1417d92a379f7f35655407ede402b93915eb8412824389a" },
                { "eu", "01412abb9439290e42c9da45a09e528632b7ef50339ab9d814eebe7657eab81c091b809d2a0ab004e05ef12bad09dc8b4c17be8e6649edb6d07e2a30916f6d3f" },
                { "fa", "eed688e653366ad1abb16ee8c5c5627ea64c32f28ba135a35f86086ac7f58caec227e94a8ae24730822f2699c5794d2d2c210317495ea1a0ba1998525c8c1590" },
                { "ff", "fb8e68b133d678ccf489aed3cd5a127dfc7628a1ceee50a0410116e25eeb7cc5202c34449cee53d358e5d4853dce6cba9923d3e9ab6f56c11ca6e419527da648" },
                { "fi", "539c602a5f969aebfa2513189819901e90ba7191d8e0c59db693c6cca67d9c6b1d6e709af4fc0c9652474738a2918fd8747646a29f234345f8a1d096dbfa3857" },
                { "fr", "788ee9334512011c72b802729c431ab6bbf17849cbdda2cbc4789d61ff577512f0db86a671cbbb9185bb8b82458e078202b062a6ac5d4efc1036ab43bdcb5b2a" },
                { "fur", "d483afa655e9abac190505cd6a607da7ac7df1abc5af617667c7ebfdec253d6dfd512b4f65a8e61afee0ebf77737489352517a250f8f9675aceb9e3c9905c792" },
                { "fy-NL", "cdf2037397f2948573ef88c114727822a6e1c2e6a552e97d5d772897e6d4e99c73f9adcd756220eb0a294a7f799efa873d6cbcfc55dbaab6189a1b77768f0641" },
                { "ga-IE", "1097689544e99735f3ae37e594cb1b86901ebfbc1ce95c0e4932518c2f718e950eea9d6e8d51900a55e8cd3da5ae113b38eff51e4ea5b941d475a85bc1d793b1" },
                { "gd", "5896a0d00287e0b30363eefb89173398be92757a274ccd083aec3bbae5b63e683dfcf4734e336223d6cf729df59c4d2c6cba1c938cbb09a912b574548d1a8758" },
                { "gl", "6b1000b3f586c2e780fe958d9574e3647c900af759f7ae1a1fbc096906048546e138d0a3e706a33709d92f78abbda21b092bd8e3adbac5559bd8812499f88f21" },
                { "gn", "7ddbbf8c0880a0ca68da6f07c5e3e8270681af26615936eba02696b67803c56b64cc327e556a461ad615231bf24f950ca4b64401a7e2227542e7257520852556" },
                { "gu-IN", "243e5df00ced2c5194838819b8f61650797304b49b8d4c360d977af940722b1456e83ebd783e7346a935bc6cd2c1caa8336e86764d46f62332d8cb85a8ca1776" },
                { "he", "232a1e0aaf2c783487afc55bc951e8dca88b03bb366ddb8852b9e9f59fa2ec1dbece5d0206cb9f0d39da8e72cad05795f7afc7b2cdee58804056fea01998f753" },
                { "hi-IN", "6aafa4cb565506ff0fccc1ef8181c7d613691d36dadec48962bd17a1bf8dfc228da81c4bc6e16324bf68418d420dbe951354a7b4cbc4b2c29835d5cf1cc96628" },
                { "hr", "ac90bcd18813856b823ec3d88070cc370c573ab54f72504fba58fba61f9412029c01623f8e28009d4b363398e6af83cb2bbf41003136caf0c80911af01c96e3f" },
                { "hsb", "4cbd789faa83add33457685e50e2d6ddfecef9e499b87e90b3367203804ede424a7eda682cc30ec1a1de1f1f26c528cc70e5e8c802ca8dca24d5578e8563dfde" },
                { "hu", "73221342eac4a1d114472e52c967dcb45151eb2aac8c5976272029e86204588804ac12bba5a82bd64ce2ad38c7ca5475b8dcb5598ae2c318a433dacc18fede6c" },
                { "hy-AM", "cd437a8da09d0a76e9f65d5aede5dd9b2758d162dab62e5873bf96cd692b07f2875be0a17c0ee5a9a6c2e081b1cf5f1d4bc61cfee79ba0e9a0028bffea710074" },
                { "ia", "4ac81d2f1ecf7abecd3d617bb9211379d0f2db4230ae3b94dbe8067330817bd7fc471baec438585048479bf32c4357a267a1fbd4748d8f3b49f5e029febdcc51" },
                { "id", "e26cdb3e5a0e93b3828dedb36892fdf5619c71073a36d3745368a8e91ad1dcc6935f1f353ce46c7d67bef081bb5ca877e9817e0ab5b638960958c391c5f9c5d0" },
                { "is", "620ec3a8997f989016a9bd6f61c8374499afd4b94df56e7610f6c6a67e5d63ebb0aa8e2e76eab9846b940d6c90fd0ecaa6c0765c93ac899c997a3942542d6d8a" },
                { "it", "865567f1e428af05bb5858638d3b42d3ea8bedfd931713108755d9d544fc32945215582fdd94c612060c398a115df9d7ad48520dffdc63d3234982a35aa7cbfc" },
                { "ja", "d3b28ee39925a1004c31d2baea03fd6e3563512e7e04aa41ed930d1de3165146462e73dfa61433df6c66ed367e62b37dc4107b5cf23c9258e80bb7750c70cfab" },
                { "ka", "26d59e51e0dc4f6463027aadb91e5286a06b627087dbf26f0060f3826538a170ebd89b5b34e53e99ea12325dfda0edf3c49a3b7d6377af59573d23204cbc0b15" },
                { "kab", "bedf2f2e51c04b94c5d30b2a7e9c772dcf66c5000fe858faccf670346c5068c8a296d354b8a4a9e4092b6ae4420e31c24642c961dac23874e1b63948ed4b1e12" },
                { "kk", "870fb13beb37e1f6a5a21e94a8dece4db4cebc1dc28937a46b8715729cacffa5a07d3dee949954c3f7517e75e61d213cdce0c9b37d740319085a079faa173b25" },
                { "km", "c9bd371373f5da005e7b77099832a9473f3dd7346f27ed35608f546d63d34c6b40380338407d6ab51032bfc99986a4276481d7c53bd243f6f9320fa02e825f6e" },
                { "kn", "535164837a935a6f13445e171c3a5dd9971a2e90f330fbef0933475c7209dcca49b9b4ddea74dd03f7206e10249f201753757efa05eafdfc55bbc3e3e8676a1f" },
                { "ko", "0748621433ab1213e7677dac6e2fd6697cf666850459624189aa087dda0a0fd1cee3bc35d97161e2173166fb1c21f82a5108d74fb6ffb17faa2927dc7cc6cd35" },
                { "lij", "16030a729a88c46a54b073344f857fd9edf9f3870f47aa851b4fb5cce24381427a9335b50052844c4150a6c668fd2301703eb46c9c6b7abe927ba7b2993ef387" },
                { "lt", "ee3d6d63fbaf64007233006487adc76a9173a8c71c2e42fa699b9380331741c37fba60da2b9da30498435152d38021b36e4d626bf914b0d7c12ba1c0a9fbc8f4" },
                { "lv", "7b65bca38894feee9967611dbc10ae3bc39827577734c900b59d2db4c093b4757161ab2a8f9fdcbc1c3577d2135aaac45a26691af7d67ca101b6b8b19a71aba8" },
                { "mk", "9af6d53a9ab93d6c8d74d01cf3c6b23cb5c008fd93fd7c22aa4f82302cdd3b8b6ad62989e9e69025a7faecb21dd1051f1afee954a847169314d71c254753f767" },
                { "mr", "45e21715401fa238f057c2aa65805d93856b444e143dc0e63feb3fe501d7af93279937b58b8e27682b65f128824fafd41162db8a8126a3268ea5e5489e781ca3" },
                { "ms", "726eccfce7b2761d4da60f69a03f02a8b45a54f769a648dabd3485e167d40a583a647613ce82d7f4905b28a69dc7cdd3c0f77f1fd180f18f5d34974f3a8874ab" },
                { "my", "99b04548611020e5b47f4eda96ca1213485c29b49b8e9ba694997484e3aaef3a13ab1050e841d4f6a60511d22a57a7a3c1c6db7a79eddd9a195c01daaffdf9ae" },
                { "nb-NO", "2fdeccd24640eeca68fd260585b3b65e8450db1688df65bdeecccd8c90d5977034bddb988125cb02620e2f2b9a5a763343975d115b5b58b45023feaa0f5d3105" },
                { "ne-NP", "cb1ebd764c30f8694e79064303a959e118a6d9731e6ca2a0e70b018017b8818781102e22a017d0e3bc460caeed805fcde3ba17ed2699bbf6a7e263fc251ccb7a" },
                { "nl", "1fa5a501c562bc42fe60ea76564cf7413613ab57325c20dcecf839d35521afdbcb084795ea3f5c7379485f47ff3ca539b079050d0b8256d74e3142c745ab797f" },
                { "nn-NO", "dd70b82c82cd3baa62d4ec7b9e5d901cd12c8c277ee8fa6f0539b7ef69f877eac0a283d63c1031803d00e845d3e5e5a851cde170ad208755c9fe8045c2420504" },
                { "oc", "b0f593e2bcc84d8bfb84b0aae21ddc9e427591e5fc86d712c6da0cb3ca58ce908023c56b4f224fcb590bfb3dc4b0e393675106e7f59bb5852c9b36d2180a7e35" },
                { "pa-IN", "84e5302869e738a7fbcb725c51bbabbee0c9f3bf97d79c9d8e6b5d141782204c03688b8b258fdbf9c64a2483107b13091710a977a177ed126825ad3886047801" },
                { "pl", "c1db2556f53fec802645930ca2531d3a8548931866578f8f2acc8e8db7410169017f36692dabfaafae60f13b3b1372af4f490561fcaa75e5ec19314d8f7966e1" },
                { "pt-BR", "3bb16758637d8c21582dea92d41ceefc99485e99e7a7a45cdaa3c0961b8623dc8b9926d3bd004d7d6ab059122b61e5c4022f736aae4758d1597edb8fd70f9f77" },
                { "pt-PT", "0f3cddd9008c20d077a4061df39bcf587da6fced2e81a702726556ee1f1b22588df75911cd535e4450b7d82ddf461b2de0f83c44af207f96a3f3e9ba1e1e0873" },
                { "rm", "91b3ac46b93640e7a3817c3f4878d6a1345bd1854f356a1daad8e1b5804dd08c4cc34707fcb2cf5f573287ff8365c7dfa2dedfca6daf562b1c96787a9767a6d5" },
                { "ro", "de9af3c19dfa1325857b2e01a3111e4d08144f89ea10ded2b94352710fd1b735321f11807afbab850dcc1f9efe58f9ee02e6b00eb2b5fc4cf3130a3b7aac6266" },
                { "ru", "de0d81cf9a357b7922b46182c65971e2866369db2e119a01c6f9f7f852b5585a75fcec5a71b03a331ccc7eaaba03c9c7aae793b5241befeb8d7697604276e07e" },
                { "sat", "c433d6cc34721cc65f322520fe8b70fe68c043c9c801246ad4af94d2bbde71ef17ccae35a48f1a24596f928e9846119359f745e4e336ca1e11054fb111c91d9c" },
                { "sc", "3be9b74ffc5abe2bfd90dc4613ae8b027327388cd9d315e10c02142501899f6eca86c5e17279e2438ba6859f50dd005ab1f134b5bef18237c4889c31bea5c420" },
                { "sco", "4d9e1fbe130ddc6c2c3d68b84efe888adeacdf4fb981d302dc3896140c3cfc91afad284a75d8b05142cf35023b77528a5f86924a1c431eddecc82bacf9255b86" },
                { "si", "122ed707691b265e28995bca2388e51d36089c93218ea7ba9e0e3356342d1dc8e657e978af18dc8b1a748f3d1ec0c5b4bbc6cdbcd0387b98c60e9078f613f2ee" },
                { "sk", "2025c583bbb375af8906a784e33a2b5b0273f44c7607a62cbcbcef32fe9ca89c354f9ee00ba1060cbba36bb00ef5e5737099520c0d8c83fda438a2c29fc85745" },
                { "skr", "0711d27d1e10e6d2ef0e647539fd75212ef86a70cb528920d6d21b52abc6c8dc7e07867e1997f6ee7ef6f50192c053bbd5b1e2979cedc120421a3def9fe74ee0" },
                { "sl", "ad52c292cfee44c14cb875ccfc688d7abc9a013fe84a36715f368e87b155a53f505c55c49b44c76aeab6b09ffd7f79419ab1b198f9bf37677f304f12b84795d4" },
                { "son", "c1a0e386f3b8c75547a1a8009ba9cf927f1fe82d5c90b1f49c08dc58f270f10e6c50c5ab8213a98e9899d5382a7f2427152fcb7c9fb5e15ff611c37bd1137fa2" },
                { "sq", "a8762c9b70e5b82366e0b8e8a4fc3d452968bd77d79e7535134e0623d33a69da3741eb790ef2e838ce88289e4fe9acb5ac0ae1a57c7da69d50a171df2d959e69" },
                { "sr", "2291236aaf8c65d408b4171d18a292a89075dce9023a632d0281ff99523b33248c5553a44b05e05ae62dc610590d02208c55b5b733f7edf2be2ba870e26709b2" },
                { "sv-SE", "d241a986c0edd48a64583f8e4fd6688a4c61604214ae31507547b108b868c5abe0b0a2926f401d44a45f698edf662f15abfc252727f3f075983f73a92aa0a8db" },
                { "szl", "1f71acbe6eea6d9189e50609c93618b268cc4b8bd765160659438099cb051e800d16de46643a67e5dfbdf93414988d57bcc1fed9d6c4e40afeb5af872ad82057" },
                { "ta", "d614d58f205ef8c93b4993ae9f9c69d57f299fb47bfb1deb7150ba569396c4c0b2ffacf21879ec7b86452e921dc514d8948e20cff533b433e8fb38da1f800808" },
                { "te", "b9d311eb99460dd8e65a2852446ca33526b4eed7e6ac2cb1f483a4f7157ef33cea1869516b00b50c8a84b0d821da1049623de310937835eea79a75b35e7e41ea" },
                { "tg", "043c672ba281b0dfb96e89b6a8761b36b2c28eee49cd5ba3bb4707e5cdf7d0971e7f1d0ceee2a93790fdab81894111fdc3088b9a6cb67bd7cc5322f3ba643876" },
                { "th", "91d1bb9397635688cba40b1d68c549861151cc225bcb3f4cbde37404308902950d1509f97a70a023c6a1aa0e700eae6406714992ab2ad2d30ad2a7e6778736a1" },
                { "tl", "c4b2e7eae9ebd383ceeb4b481504b8db39e97c3212996c5da0dc59374ad4f7a3e90c52fcfb54fa4121e1f0f80e213a8b708e0415a8e22ecfc5853642ce8ed993" },
                { "tr", "5c91c4a3e6c637d60b3e8211a6f1f171686ae495290ea3dcfab67fc6661a499fc4333d8d7e2bf4730a3eae020509c7d44c6acd7324f2f4c6978513f743becbb3" },
                { "trs", "2b4715d10c2b678797ca1ad31f9ceea500c39f3730fa3181a8be14b1f42dba1044c646ecb79ffe5ae2ff4f0db75a0d7148925c7e5c010e669f117a17d529653d" },
                { "uk", "e94dff0d51389432a4066530b3438902cb4ea2c00ac8a4fa8c4cee8509bf159a2cff902e9db390bf72722d9c19c8408f3f459c588d47f6dae1d4c0b4a48bb26b" },
                { "ur", "57ee1799c66f905796a9f9106ce59fe3808d6557fca9effa3730931b49c375edf9c33a9084f3c759621b79ef88593fd9a61a87a018f858e7c95c07830b32b77b" },
                { "uz", "b27fc881b3bf1b57298268cd678c7ef8834ebbcc1cfa9ea5e21265694fe4799b3e39e814b91b0243a64b2255160cc550d6ad1a379763bef8e5387f4ce80a8f9b" },
                { "vi", "7dda3e947578530f97c3326affd843527895a46e5424b87f74f812eaf505191bac3ae69885827ffec8d5882690d87f719fc4e3723c8e90fca180e866a5ef1c03" },
                { "xh", "2ee80901955837ffdf546f498b12eb406c695caa7a2080a7d7a6c2729b921ee2bf74845113e07ccb6bd12a0c3792b3ffea4619e86f0811d069a9b70e7d1eecd3" },
                { "zh-CN", "92dad0307d467f65498a57b6072d1d88b9ebace6e08e5e41660d72233def4569cfe8e6de355c2f180229f4105519be8bd370dcca9c5a0d14c2d4ca2ac6df1737" },
                { "zh-TW", "39c9763fef15088b3f9f293fe10e85057ef89bcd7ff65541617986576125a57d95579052740a8739a2e53f497ea84f8d3ee3f1afa4ff5dfe66910f30363cdf0f" }
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
