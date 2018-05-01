/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
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
            // https://ftp.mozilla.org/pub/firefox/releases/52.7.4esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "5012bf8ac28a9e3e88fc83268cf57341ae744647cf3858a5324253a4870695670c13718e3efa8508f6fe1a992123a1e2667a83d91f230faee7f385b97065df8a");
            result.Add("af", "3277da38925e0a8edf319d9bc6aba04481f161c312f9bdcc6fac95fd35945530b7a586395c6c5219711f51b1d7fded755f897c0aca946a7abe174c60cf2482e6");
            result.Add("an", "3aa1101cf148a4ec3a29882660c99941213b5a6d2b54c785ba9f981ae5ae4e18a69d65487eb106658e1ab0fa7cbd170c15b017caedc714c2fceeb788ddeec691");
            result.Add("ar", "8aa4199aac288be5fb3fe5ad803e950fd6ffbc36fa701fb3f63cdc8cd3a0d03862d36e9d79e9fa7d85705de3f958dd2a11ffddba5a034af058dc333e22e6bba2");
            result.Add("as", "b107dcf60c26fabd64bb74b42e7c4683429af529a173179b27f033e2707cc8364e617c6acb063e5ca1a4ff117252cafe1fad7cc1222c41468723157f21d836d7");
            result.Add("ast", "56d9b9182fd6f94157d4622bb6eac04e205a03cfb37ec984fdf26d441535114a4f8b3f2d636c722f789735b7abc86928bdfa2f4e7bcaa602bb05911039de6828");
            result.Add("az", "0435f4c409fa056a606c840089071fed2402a5a076a5b892586b2b652bfb07a72f4579bfd88ccf063efe6cea6b652a96535697df556844351d7aa19853ff762a");
            result.Add("bg", "21dbd6513babec6955bf1581ea97daa0ef8149c42dc6825457070b45ec5b7d1ad92ecfdcaafa3d599587a8c3c236f7e1742031da5ae8f5604cb982966db2ffdd");
            result.Add("bn-BD", "de50c08f7154fda73628a64852943c45e170386d3d2c002a861393472ff0868a57c1b545d4fef3a4ef1c65634ab794cf2ae05e641786856cec7abda129612377");
            result.Add("bn-IN", "707c14fafbf980f1fffbe3e009665353ac283faa8819fc61553c37d33d88aaa5213ac718ccc3e902ce3edeb7e098437b1af04cfe9cc4ba6282b659088b48a98d");
            result.Add("br", "bfb52b43e8c2a305268e9819d9396f6f6d05a962cbd4d82f5209394f55e113b613e2ac1f92ed0e590cd069ebd54ad58188558d72cd5eb12026de0f5180535a6b");
            result.Add("bs", "a4384526dabd56562968e19e8bc34686e4286f0086e329e9f71310716eb9e96c5a286db47170c3d182a87c08693ea7c99682380e3910293aaaf32078cfdbeb07");
            result.Add("ca", "7ef31d456bb076f705a7d4593ee2481a0bf38d267876a3656a85fd05090b2f70572524b04b5d24b0777d67f6307bfb7569138d246b9805332ab2d1974074a646");
            result.Add("cak", "75cac60e3534f4d302eb332a736b9e01accc02bff547c94b481dfeddfb799e81c6f3d671149a6a620ea0483ba1e1f2f42f390891ae072ac601df8feb76a5b7f7");
            result.Add("cs", "3ae043437b1118a6b7509b6a767cccb17c6eef18606976c4c5bbd5f8522946f1f6e84f1913d8800a830826f9a47f7e152dbe37c6cfd50f94a0feaea516fb0aaf");
            result.Add("cy", "51baf6b5f43fb3101c836fc4a9da094ae34b0c4546ea47484e5cfcbe51b69fb3cd068f8ddd09b46400a89c8be0f880c7bd263a5c0c8f7d2fbe15ca06968b47c8");
            result.Add("da", "b64e70846b3da9ed6438f357c0bc92210190ebf04f3eb223d8ef1e297db972b0bb294a6483eb79402af5aa913573dc271a154fefe5ae90121792776acae47bd1");
            result.Add("de", "864e4079abed0c955243a866b9734fd96bf083568405482b54b73f8ddb71277595a8a461c4109ee64c245a6ca083370e3f6f3c8f155b8e2bdc7dc3f8d0cc7ef4");
            result.Add("dsb", "32738fdab9e6c01a1cc4b826152b6d581642664e2bf8f24bb7433b45dd9f93857adc9fb2099c253054bd075e858e9594a9d372bef67bd2e8f4c0efd474694277");
            result.Add("el", "701de65d5e2bfb9a4396de64213cba582e35875ac08ff83b7d3390268ed826bb8847e65a8d23fe04d51be97f1c9bec3f2fe9466fb8ef19f1a9da626b11c083aa");
            result.Add("en-GB", "20d6129f1356a40a901c6fd405b3a176b55a39983b4dbafaf58b68a83d085f208e9037d340d089ba395d8b2d0a0d7f72e2f823ff34fa36ed788bcfb5e34c0288");
            result.Add("en-US", "12a8cd934cab5337d2eac0c5d2c602d3968d337daf8c1bc19e1e66cc8c92fcb8046eb936373de4012dc6cdbe4dfd81619f9ce23a4a6f740a273c8b201a762131");
            result.Add("en-ZA", "42d751fc17998afbec61f11182a17394f1ded2ea0fa9ce93eb1ca6316569677c7e959d9bd93c6f5a266f492e5cd51637e29bfb87334fff340ddd243f7d0d9c34");
            result.Add("eo", "384f2ca998d6b4a2fcc3a97e6398e365a6f5ca88403c634c2dc21f66f3961037750013b998f38763200025eb74c9df99ba6893dcb1b71c33b3e75a2d85d31bbe");
            result.Add("es-AR", "c5edefc6301e20147bd9a3249abda186cd0b9d81b1150e5f60bdbc4755b26a3608b419ff18dc3f4f315aabe52d3c4d472fe14ce6b7577c33ab9f994d8c1a3a61");
            result.Add("es-CL", "d266e5e42e1f135ed0f3a0428e64ad66e59f314f26ac9a994c6be18340812df8eb931af49f92f09f62d8fe0737233e08dcb2ee6812d37bd433ae4db852d51b22");
            result.Add("es-ES", "f9418ae3df91b79047dff7efa96cc392988320c577aa395ff70c820113f8a9b5ae9d0c3ab6948c5700e150592dfde65dcde2e8bc11a1ebe805418852358ca00d");
            result.Add("es-MX", "18315fa88e889703f042859453344b3fe498a1184d8cf34941a9c8a4784cbab642dbb372644ab22c20956561a7c0b8a83aeef51c4df402094d2d56b4afe6f475");
            result.Add("et", "60d26ebc7ad1687e0f446d00614cadd463b6746918066744bc4193dcb8e8297c980ffe6f0ccf9ee3d2cc29e844af075419c0aae7ee2d49de3d721bbbe631f413");
            result.Add("eu", "43aa4bc851c238cc8aa0dd82d3089ee78386a5cf937bf31d95b2f9535acec513b260e8808751cab8333a0af3c5328cae15060cd91a9b6eaa30051970b4072fca");
            result.Add("fa", "5e3fe54d66e52cb33ca42f258ff5ce0ed4cbcd994f740bb995cef151838f8a64e7f761a084161588b51f53de6faebce690f925dbcba0c1d3874d4ac4babe56a5");
            result.Add("ff", "e4c2917875ec500b876e08ef655dc2a82b3aabdc65f87d78d30f71d3423c79854faa294b24fafc86765d13304d19e411e5eb8d4078f18a36a3cdc6bba92dd95b");
            result.Add("fi", "e6e15b910462f8e8b5c5f5a7ca6a56d4971f85981905ad9d3a7ef896a7aad3360984589c488ca8909d2033b3fb70b48f24673098684ad07fae5f9e3d3db54d39");
            result.Add("fr", "1485a2ac36be7c6c0eb109146e3e817bcd4550766dd59d5b60e5c4a7967e458118d156b951df7d58f19538a03de66afb62c2e6896b1dc400845d1ee9b96ff9c5");
            result.Add("fy-NL", "a95229257e3bd01866bbeeea5a8775fcc5bd24767ed25dff7002355bf6a9f8e2ae8458bad08e4d2480984b6f2e42c6674013afaa2d8b2a422fca63d937c5b6f7");
            result.Add("ga-IE", "b2a80a315880b50703ede8cac03ae2fa30921038601e3815038fed28d29e9a15fd26ecaedf64baefb85f11bf564e3ed46a8a45880ce2e8187140c47467cb062f");
            result.Add("gd", "7990488a9b22b1918d5e286d22ff5331ff3dc4d66b4ca2b0f992de4ab254ea3664dedb1f0475eb4d9c7a182edd6f1a584425a42786351d51ed55986793c8ab8a");
            result.Add("gl", "a80a4c8829d75ee060011703313273b275b3431ff5570e760b6db4964439b5b9b10d4f7b8b280315db9e8f389821bef25b32ff2e7f9222b178ed548d1f151c08");
            result.Add("gn", "d9e4a0c0de57673a34a761629e2677578374a515245d6ce815e9ed10599aa86900d6292acfdb4b797b83ca468c9fd1769f2ab737df56563bb6bb9ed4ef8cfe8e");
            result.Add("gu-IN", "0ec140ad03a5f2940ac7afd8e5a6e0f1940d5d3b65f9590957d5c543e9eeb76382d20d95b43c6a276d4a49577879de222a759263693683a9a1a4d9cd7d7a4005");
            result.Add("he", "426c031e7e2ee8668c04b0083039630c0b7e4d8de6471a3e1e1d5afc46a2c8a953334660404cbc2edd2b6b90beb04d37f520e0aa41cc4dcde21aace9e1c4743c");
            result.Add("hi-IN", "9475d6fe22c5cf7ec4698d0f1abf1395c31a29701a383ec5c19be7b33dc0a118fdf61bca1043f2446c014c784ee25e45e22619c396232e06d4eadbdd2c989cf6");
            result.Add("hr", "eaa55c365b4d3c3528bf5ac87ad75c3bc33b396debbd4df96abd68c9fc58eb7d91639ab1c4f8870d0464eeacdb032772fb11e3d1f19db061ee7245c6c53c70e9");
            result.Add("hsb", "dea5acbfee82498c5736f8f3149193f5e1fa4029ca6753d135785e3ce63d5af1f15a579bdaa11a0356839c07b45cb73955cd3d579a4f042bdada759f51ea7a5e");
            result.Add("hu", "1d88d86ae19ef8786664194c27a707b420c0cf9e2dd390708f8f2a9a11285fb8d32e33fe703f835cb87d3d00892ac74a98c594572460188de7840d482739b6f9");
            result.Add("hy-AM", "d4c0690c5a112bbe3eb1a6752c3beba3e7f513db4c43966286f9d517b0ddc20c93dc83ca85e426a18d4c9fdeeb41782239113e20274adf7a8a0e3f9a73d12378");
            result.Add("id", "2f85c96fc343d93798d0d6968c64c87d72907f2146764d60c325f6b65ca5e942152fc817633a1126fe301cc9e2e9b8ea2cff42042984c776af759e5b865db0dd");
            result.Add("is", "a127e61c665ddfd869cd047a329de1bd19502ad63fea56eb6b85245f28248414cdebb8801fce26145605c64c4346ccaebff12a10b7be2bb3cc37c1739e565da8");
            result.Add("it", "ea625098bf118801fe2746706a20cd6ab461768dd876261fca5d594476320e4dcf6f19c49985b3e07cd79865aca70e6a2d4b150e4cd4142547434969f76e78fa");
            result.Add("ja", "d05b31fb142f7d29a9ca68e6f62e0cfd38481395858bbff8fe13439962d100ae846d2017c31b9af3d825eea5d99850c074c7c14b3676c28a10d5de7ffbb7bda6");
            result.Add("ka", "6dff03d6a15efe2ba609531c31fdf082ab39c3eefcab58aa682f55de423501140e1964ff0eaaba19ecfa87ffb8f1c06d068383e4844afb5708ae9eccc126a934");
            result.Add("kab", "a79a6bb1959cff42dc9b12bd5aaa821aed8f2d956692923ddeb9e54f72134c297633ad53314a06b3083f0ff6a9f311d1c0b99f7dbcc0c25f89553cd73ceabf5c");
            result.Add("kk", "561965a50b98150cd66f5d910bffa54cfc64acf1fb3ad69d31f4a9b26172f0a237dab431f6688ad841d050ba7f03c3578126f8f6452edad1d9e94dacf88d071c");
            result.Add("km", "ea33c67a9d058e804c6cee8b57818595ac3507006bc6927c351d0553409389d3946795bd4fc569c696f334d1e570fcb0af839b750649663448964073c153df7e");
            result.Add("kn", "a894113c1a93f9660fd113b3967f637f1376616dc2403505971ed1b9276ae0823def6efcf5a6f5f3a95ba3ae90a41e4f5265279e1f9edc1b27fc20ac27d5941e");
            result.Add("ko", "1edfa511d630374635d26af9add2780256c989925402e01571531e338dc37f91bed6fb66b926716d996ffe031741a85eb93959deb49fb1909e45853fb777e0e4");
            result.Add("lij", "db1673f53eb1464fadfc0e835be816c220d5491c5caef8259baf8d1cc53d613d7b521fe4a359c02894c3bfe62d194ffd9929668c72b653a36f48cf8b4b51ee37");
            result.Add("lt", "293d797b7a213178cb382f5dc4769151dc2b4a26ec56bfeaba4649df407efba03595fe9eea9e36c866e18da996c2f953d1b0b3cf464d379bf5e129054c47b3c3");
            result.Add("lv", "c17cd794289d330a00b1dff2eb921e280561db56348e82395dd51c01861e63a8bc5249ae6872e2f9a07efbcaf59478c3c16ece0f3bdc83ac3db454c73b736d51");
            result.Add("mai", "fa289dfc93f8ae7b067bcdf339d1a954eb4620f3529a4f9318c69c983f7fc86a2918c0e7027daad7f9c7917b335136c3a3bf7dddf4858acfee8b7df405028fbd");
            result.Add("mk", "16c458fcd9f669534936f1ec5c0b2bb3120889c2720459dc7af39caff37cec0e78ea58bc74e4897692e5634fcb1d8037f835e08dacec77bf53773f838db6dcf8");
            result.Add("ml", "2c8055e5dc33e6fa92ced677eb2033470b7917fdce7227ce2d5ffc2f8506f2438940a41f4ca98a9c04f77fa67605ed344e5a496c9ba91b4aef1d845677f45fed");
            result.Add("mr", "b2030af2900ac5cf2d240c575a32ee06fd944acaa058ce71f05193097155fbd2fdfc5401de1b79ebed2ecc94e45a5ec8d177bcb5ad25b398fe8f06a1b85a05ac");
            result.Add("ms", "a7eb5a19270eb3d0cf2ce0b871d7286e716ac92de823d549d4efa26f2922cf8bcfed68086ee57d60a128ef8be21fe1118f03a56919f1bf8a3ef49c2f34f79c02");
            result.Add("nb-NO", "a93ab708450f3187b4c9713b1d9c1fdd161400ef1f3395b7d7a9c8acd1f7514dee53f8a4d0d31049cc4e9d2509dee944d746b7a5dd77afadb57617ca5a40b971");
            result.Add("nl", "92d085b709161b069704da8b524af1498687e67a12bbbd98710a9c91435767aef1f3e2f54572b2ef7cd7b0f210337ec80de4c49d33cd2a831b2bbf9331951ec4");
            result.Add("nn-NO", "c4076f52b9e8c496b1b5b22943529c2255978c35a9808e2dce66adb12678e4e1e235b77aa7bbca26c2d99e107b8f55aa969b2d647e2930528c59614df173b2da");
            result.Add("or", "c8a4448418eda9ae66000ff66d1587ca72ba37515a4a631c6d86633bad2cf21eb14f68a4fbbdd2f38f19973c0e5be54194be9ab4a50202653eac11213d7023a5");
            result.Add("pa-IN", "ab930f4b053afdfe69b59c80253a05ecd2fbf099a7761de4c1ea731423a9671006b948d2352daeaa5562a46502f483f12ca0bbee610c536bf821ee025317f24a");
            result.Add("pl", "860b19e426499832240ecd42bb541de87d6528781ce47a814036249e2f438b40879b67fe53b3be6fb22fd91a8f3d43edae52ec64116e5fdeaff4083a6c975351");
            result.Add("pt-BR", "a0c830ab1405fe56983322f1e0e55c61b133c48eadda0535c907c76845e9fdfd4592e00172ed43f03e76d463c16bbf591c91aef0324b80fed118d02e958f43b6");
            result.Add("pt-PT", "e9340678a3ce9d8ff306c6ae4ec6fb5d1f90d1a860105d19c9ec5535d3e31ffd16e9886e7319f8876eb622075ea0ce3546c2af21997efe20af4a2e1b7bd58c0f");
            result.Add("rm", "24360e2cb6aa04fe06bc65c5183b1d09d053d19300ae2ba324c05baafc63bff368011ea639a8882df58f3e3b1338435cd50861ccb35817d0b0b0579e0db56142");
            result.Add("ro", "c55c1a73047428c343c32eaf27c52c9b4e2066da8b327c146968791bdf46475e09cdb77b5b85ef4f5ac0eabf7e12b093291d54577453fc3a794781d9666b270f");
            result.Add("ru", "7acda8270a2e32f7e9bae761d925aee6bee50866ef75dad3c260f9c674df4af6918a1bd58f7c07db28f0c3e6c923d2b21f5cd27080634163281d0aa95ed05c94");
            result.Add("si", "b8e566ccbaadf65d7c84347a8ef92d25979011e6a151f3b17d70dc43accc93bf06bf1535f0b421ad01a1c8a6dfab3e88ccbe5d3851ee0955d74d79f6377f74fa");
            result.Add("sk", "30678acb67d3620ff34cfaafea13641d75c1c33ff70bdfb3f356d4767391fc70e40236eae6cdc51947b5f3222920ab9c7b02fbe78e6c6723045181e424480245");
            result.Add("sl", "b0f20c73831f56c88bc15ed67f23d888384a017e6925eb0784f36bea3d6141cfc80b336f6b6a87b41b75a10112c6f201d1723453719521e5833fe7e6a6a014ab");
            result.Add("son", "c38b89c845e19dbdf5f16a3f2bcf28c53124d2d74a4e1e5629a8bb640b8ea13ce8cb867d9af8dcced8abf135e53b701f1af125589fd808515a542713e8bc56cd");
            result.Add("sq", "4a830ad697659408ca8d202296a6f6673707764b61809d4b17da16eceb98ffaa40c5b74a9c19e71f469b7a3ec57c8468abe783785a63d4adca195caa416c31db");
            result.Add("sr", "a072d1dbfd85802cfc11e03c3d335a6b351517e78545d901a91c6f7ab32074a9057a25cf0b65cd80ba2ff60936fdb48b0a9c00df23280bc70bf5d2d76e7cdb75");
            result.Add("sv-SE", "a5c1ec4e9a495ad88402635b1c91dbdb2a54576035fae88cd565dac9238e5013cc45a197b54a4dc1975c32011a70b273c2d1b6d02f4eb8c3d01331e11ec211ca");
            result.Add("ta", "ecf95efad95fa6a4a5f7af72385749981d5c68acd141a064a4d2136793daa06bb84b0807e6276e856c33135b5556d22eea7353756b4bc77201daa240f41b6b6a");
            result.Add("te", "8f7aeb7af165f5f0b6ee79d8de37f65e3ccc5b439047400689dd71c5c5269fc8fbc73a7215b89cf0f55d6446ce9c2b29e6be65bd92cd6d7b4d42dc5641ef905f");
            result.Add("th", "86e7ffc52565e53901be568cf4b720e8efa7cdc1894c40f7b0e36d4b4bae74bf16750fbbd348acb396c333419d2a4c4185c48d143f06bbe6a615af4d8912c946");
            result.Add("tr", "596094df1a981603142f3a3952f8e0120d831a350e3ff353930fd6fb2142874f62b88695bb37b700595168f026c6ab4a9709294f8b752f9ab7dd85f3511b5921");
            result.Add("uk", "f6fc8dbc5285ef8ab05e661adeb05c9f66512b664094e6e6206fafa5980ba486021e5eed8c57a7e0806698c4deb93e8fdab21e5705a33c46381d0b5153e672fe");
            result.Add("uz", "6376960653ef89569e492cafb1f3b78a0af1be389abd5ba1591a4b1a2ce3a7277b2702c371f3588c4b987ef0b433d7f95464161e732ebdd4b8fe99632c6c57a8");
            result.Add("vi", "4060358721af217a69ba5a2fc24a98c9a9dab22a09e18be05cf206a82c62d8f3d2090c3eab6afead4fbb7e1443d661ea91c1be306f6f0361f2298d4096ebcfcd");
            result.Add("xh", "b37af1a0983637c77a44efeea41b0e2a997257d0efac3fd8cac4446faad8f63f678cc99ac93067812ee404bfb2900040599198017480b251c1229c2a408134d6");
            result.Add("zh-CN", "2dd41aa533fba5d94c16b341f7c3a90ac0f23cc05915871a936e9cbec7d5744c284a0c247a71ccba26138079b7d77b72af679e3a8d8c4b4a961eb559ff003ed5");
            result.Add("zh-TW", "b5d21a6f199ba400338290e1f3918799b0dda59896af2cc8b9280a87028435f182585fc81dd01b395f5f909efa7d04b1e6aa5566a9087eb54982415d5df8e867");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/52.7.4esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "5978c7caf0f480719c2acd327a620bbd69e5c3501bb1225e8c6c2f082fd36a3a68d4ecef474a36041f7c32402064ca46556932fe41041ba862f388caa2731b0e");
            result.Add("af", "5a339cd66046d9ff01b78a7865056d1a252f146d00908cf3ed24ce787448bf3b6c25bc92ff60b67949fa0fcb6b1253b7d6890e982398f2c3f7e9b8771056ec7a");
            result.Add("an", "21aeb7bb6f1c482a316bd2b0667542f7f6105bccc56b8caa53b4272ed7719d2a7dea8ad5b1d13c008fb8364eee7ded4cf623b90c84fd7a8e1d227b95095e2f95");
            result.Add("ar", "e26aba6bce45e331e2cad24a44292c7fab8f0e32bd701886d8668f9d388c57bca3773b9ef8995bad82ab77d312c544329deb871d437ab148145e6195761d2c56");
            result.Add("as", "dd2a52d6e57d2fe772a81593de8d9510b1f09e1bdc8bfe3e8c30a575ed1f48f5cb624d9fdc1e3225dcb83b9a7b3deb7dba2664ce3725e380f99b0662d642f150");
            result.Add("ast", "c1a1ba24daea88b36d5aa64be02656faa32dff7e41c66ef8a02071f054e1e06b9c6348def8fe473e52e241186bf356b6a0808ddcc65adcf9a7ee38fe1b44173c");
            result.Add("az", "0d61e1e97ffb739b22032686c10d2e4f236922642d4bdd6eba0075de02e8d18e7f2eefab5ad2af7e59d62fd871ee49259d0514e9bd95d2d483cf20ea0410ee79");
            result.Add("bg", "953b5e0c19cb4582fd187fcd494d7c17709d12cb055751c59b1fd9ba4b04fca949d9921703c6fe04513c419a518a7d9c52af89e2fc6b8ad6edacb2ab9d1ab0ad");
            result.Add("bn-BD", "9e5e80df8c3df35617e81bce9ae5e6bade3e06f73577a570a10461f8089584f6c94f1b4d9a22e1753c4122c014be3dab16abd76dbb4789342178d13f26de12ad");
            result.Add("bn-IN", "124f0a8de2fa285bf54f447bb05a8fc040c98c1eb8e522d78cdc4261f5eddec1592e810dd1286ce286adf6dd9583773be7707139a5e1f34078c03e136740f96b");
            result.Add("br", "78bc2d4069be1aea7fd2358eaa33107427a198256ef1193110d5eeb0b7646685ec9aea372fc4ac6c80a274798e30a82bf02f7e8db77546b23cb7c29813bf87a1");
            result.Add("bs", "4352ac996b63fbbc911dc0ff520c50df0b50951063779a0470255a6ca01c8b51a5b394cd1a125c3963b6e4a867d5bc7ddf3757979fdbdddbee94d9377fa29b92");
            result.Add("ca", "1608ea24b5b35469e9353466d6b450589d96ff0df545731cbdfc75cae69e6b33a5fb71c3fb4240133c719a40d137c47f25e331c168d01c3720b49eb5e8097335");
            result.Add("cak", "a5ef4fc84cdc33f65c1d574a071ddc99bdf53b046344d931763cfdbfb4515e08a37b880b444b9b9f31e2fbf53d8845c3fa5cf081b61997f133a249f73013699f");
            result.Add("cs", "9668ab35a8d05780ef44b9021482be964188c974b5f676c1dc216e5c3315f1ae8c0036c80bc5d3f5eb8a0caca4475b8b39dc4ebdaf7cefba57644ee125c4ba3a");
            result.Add("cy", "4c5dce5b1526b2cbacb4c5dfa4ad4399fd003864958f098182ab9264e7fdf32502f0d796ed700be818655eb441c4ba5b90bd104fc9561a7e65978bbc9a13f646");
            result.Add("da", "84f2668c867c7ea72d7d1e318d5d040bfbce2943a97b2d39990a22d713cd67b9a199450a49bfae45322a3b87b5ca2db0c3321efd2f5e78dd9cbfa0ba430032ce");
            result.Add("de", "e5b5714251cfeb0bbb3e270f60eb5a9dcb63c02d1360893e86bf02756dc37a9318543e0b39e95fae30860b8f069100d7325b92c59ab8940fd314362fabd600c7");
            result.Add("dsb", "ac3739924365e96e4e9072c515dc817e3c8451d061bab735ee4580dd3ad485069928c7fc57cfe5c0aed9e5d1397d1faf8ccce1158813ed4d830cba5a70d35d24");
            result.Add("el", "81054acba0ddc589b45f216a21cb765f1c7a0145837783f6f83477da5bc00160f41b0e5717487208cc502b38f1349230fba8baa9ccb691a161832c3bf5cc976d");
            result.Add("en-GB", "b54db133a1b0b859f868b201f47eec8b1fb1858806aacdea52d811138463a93cdbe276696cd502ae995dffad641148aed7f80df5f3e9b4b311f00ade18827085");
            result.Add("en-US", "755c37873ab420ac010444ed04b40fb2b0fc52d61137324a8cde4e17b8fdabed7a348e2e6f766209c40ae9243aa6f39bd141f6c36c89a8b1385b85db076c3e19");
            result.Add("en-ZA", "7093da31d915fea4a419975323f9ffaf5481a81256fe889c2eab57e2fed883e44f14aef27bc4be7bffbebc5b4e1a3f8382cd4f513ad562fcc0536b88c70c77c1");
            result.Add("eo", "ede977e7f531d26cddfc1d04192ec5d28252bbb6e1dfad160b62705207a5158c3c44c75476081e3f39ce17b72fa68177f61a0d41d2a0567135c78141610bd33e");
            result.Add("es-AR", "2f75ef7eb5d5cdb36f43a868a5775dfe574d621e8157dc35a8f8c692ebb8a0770efbdc1a1b0d5a57f95d65aba4965c08dcd049e0d4242246443ddd2332331e9a");
            result.Add("es-CL", "c305400336ade9d84d0eec4e728a2184bde10833bf5d69cae94d971ed393356e23a1e13cc133cae82b32aad4db778d6f6af3664637b7a914e3e4f640bfd9eaea");
            result.Add("es-ES", "41b765af68ac295490860ad7abdfba377b3fe27d8de107376ec5a55565dc458f3ce10fb04bbc3ff5e5c464b927f423289611d14e10b664c7876eff59d00a2bf5");
            result.Add("es-MX", "12253202075640915e2e0103733924389d4a2fc1ddf80511f72cff20daea7d027e7d3bbdb4aeb91c25a745619e45f5447df45ac242a724756b779648ebb2df82");
            result.Add("et", "2fa66cc72894ed7b20f23149bb6c52a19708aed07a513c77657157c967b8462eeaf9fc3dd260619c9263230464451cab39cb7dd5637589946c161dc2e0ea5406");
            result.Add("eu", "6e06c52f56e5fa5ef81c94636edbddf15d55f9f9b14f6a4002d32e61f8a48f9d1cb8a174d66bea30a16c297149c022b348c2e0751524e7900d95e02d793622cf");
            result.Add("fa", "3f3acac2b7fd42a2f24fc20a4b40be787eea85e0f5d26a797088c55e243c6a35c534e0eede4cd9a9c741c3841fdc0a72bf534754fb6cca05817d720141c92226");
            result.Add("ff", "19c9c3399ac4ba6e218177249ce0a9c1d3d86eae9e46a3969cf5479a3d7e814ae557e91c609eef2ec2b53b26234f7c194197be406b208eb870eb5620d636e24e");
            result.Add("fi", "a5d80895337dd8e3ac2b0fcec4a5a8d4812072cf18dd2200a0de28af81d4b12e5a7aa1fa4592a5e7a77a0d6b5da55070f68955b69bec90f9b171114c1e648200");
            result.Add("fr", "f51ac78f5c39c6525293f6d7a4103794d39730bef19b605be9f0ef01738e522f4b6a69e07661719112c3b9a70b8b9b708105e1745b1c7c75d4e2fad584b38ef4");
            result.Add("fy-NL", "e65e15c3bf49f8b7b9a27970af19e07c348ebe0b5db9a362eae9208a41dff8ef78b43ab58c9674f77447be9baee7ea0c420963f15e58e288775fabb8c947ddd0");
            result.Add("ga-IE", "512fe27903dbe319d3de41c1da514d8b7c06106d977fd88958f6f67b12c45d1da9aeb0b50c08324fdc10b23ee1199fc230377f77bb08420169f02faf1c6c88e4");
            result.Add("gd", "9450d89f6760c98c0cfbc50de4122119fdf75512b303ea94eb97aa1913df950de8ea049a2db9dde734eb56e2a5cbeea8447c2c2fc38107fd63532f77a324074d");
            result.Add("gl", "225de42fc747d472765bd15a3ba431467f593c955092dce038f37fdbf4d12affbb0bd286a3bf52775f5fa0d9adf77df7b6dbf99ac67596ff1f36c499fbc00681");
            result.Add("gn", "edee58add715cfafff0b5532d51b90e49694c28719953b3b9439192aca84c6bd14fa57f09a4cc18d6ddd40350d1f4aa6c71327ba81e6cb9d4ff67d347a73a9db");
            result.Add("gu-IN", "ebc3697c5b1c04807d91bbc75fd029d08672d897e1ec945dbaf24685834067f03a6aefb9f00e116e28c40a83a9fa62130b45013150b509f8225f70880f5d5654");
            result.Add("he", "c96ef432f5812d368a245daa0f1fa3da4f4d50477b34cc1cd0f05424245fc27f3ba578f7c809855f4625d448041191e6b18f7e7bf6458292957698bc12cc0688");
            result.Add("hi-IN", "67d809ba87984b6d1e693bc6c9f62d9470d0556a1162aa1ca301c23d714757611045636628fa7d2536d760074930c47232224361a3feeb939a4acd99fb01698f");
            result.Add("hr", "74f9245da41a4fcd43741829d8c480fb385183572b73d4099689eba1559f63d2d5ae7bd8f39f75644a5c00f6a14e376b34a9f8e5289d06ef20a8a8d9669d696e");
            result.Add("hsb", "26635a36871b06294c09914a0d4ef07649d653fdf07e8cde162e2fe00dc4992c56e3a3f3a034587e8bb17c021f3e37f7db5397980e0f479a3d3da23149f1f2d4");
            result.Add("hu", "e17d218ff74314dc73e3213e0651d8fcd9c879c54181fd581ee328f10e930244af98eac7edd46f3d67fce39704c3a71e9f7cacd9fbcc35ed3e6d672ad63bd93e");
            result.Add("hy-AM", "9d4077b4991d1f1965049590e789d9b1c725bf1ac1492e6e6210ad919400826ecf1cd6b0012e668c66fd724ac1ddbb75e607088e6e9f0969c40b7fc8288cb038");
            result.Add("id", "068eb68d5f5416c58e70004997456f1c99f4a7f499c5eed4e5470a3439389508f512d6fc34b49a945719ca9613ee5a6c8f82716e42f2d52d8268fd3f170cdc62");
            result.Add("is", "55d78e2a73261badaae156bfdc8003a10a7a25ecff3b5d67311661d0d63b9475faf1353141fa816171ebc1953dfad3f0e924e382ebdeb29457d5d4a7ddb1e452");
            result.Add("it", "3bfb9b9bed357f0f264c29b6b2c547d9e218c8c2340dd515a7b7597d820db638fa082773da8478e217be0a3ea4f97b228d01071b450fe6bcdce0c719b0ce1f1f");
            result.Add("ja", "230b3e440e759343e646382efade1d80ed3e6c21b9d122a01e04370c6350361ae5826e2bbe1cd311f5c1c65a9f6fd42d4cb344903adae6a267d5e8b84449cf0b");
            result.Add("ka", "511b6ecf559e90317a797eb1a100da3708484f289cb291b8c1c71f7a8c43dfc07f138aa223dbf72fddecb622a75d379b705bdf72f91e90dc32806cbc35518e5b");
            result.Add("kab", "1fbc1e2b45b97b2c899b3dfd5cf8cc82fff6c2da9a7cefae1a8d2876f7c12a153a0aabdeabcd09c6df871ff2875a587deb0fb160d471fa7c3db569fa798cd303");
            result.Add("kk", "6061331002285f8883e75f276dd06802c69d6bd82fe58a9360eb91c5fdd7f82b3d80434ba66895b4bdbfd95624ec61a3f0c9af25adf4dde53512095020c4c1dc");
            result.Add("km", "1ae75ed9cb41f1f6d6ab76b12cfe253f17bd686d973b80813fabe2db7248da4ce76d5020d9f9c47c3eb5b00e642235346ca6491ae8c18746993a61d656266d35");
            result.Add("kn", "dfd26a9f8dd95333495c213a6286dde125c46cb7897d05f767510d49c48bb58d58891665ea526d0600564e819294a02392879202e06cfcfb9a4e00bc7e70b78f");
            result.Add("ko", "185dcbdc21e6fedbc6973344b4c163201c7e50cd7f11fa319e44a6168bb93ab2b7212dda729e83ce485515f185327544dad268b9f7fc8b937a1b187928e5e741");
            result.Add("lij", "f9565498e7d51f430f164a7a79028da20d367ff205ced2a9a7dd646c8c4a2ab8fed3ea59057b2e6e1f6f757315fe17fb984daf2632978706f2308d26df153d94");
            result.Add("lt", "38d7bff822063f3a3a7f257169fdd52dfdd59456386b7f9fbe1fce5d85328ac6bf1a4b0491626100016dc0dcd665b56041d44bec6c478f0fbaa5691955012a23");
            result.Add("lv", "8e76ea1020cc9760fd97430d23224f68f5601bd796a4e8b05e343bf6095821f489a5ac2802093a6f0fc128b904d3388c83218d8e1b6d2babd61324b9c6d60717");
            result.Add("mai", "bfa8277c112cdf7f8fed855eecd1e262de8d4e4d5881d213b3f344585ac18193c9dd9b7c254393d87db9157ce5419083b89821b7869b151291905b2ba42129a8");
            result.Add("mk", "3ea51d7bf8f752ec0fd488f1cff5a39266357dd1d877f4bb88859447f55aac51f4e4eea57f186c972d299c066cc6a3e60ac95d72af52373453d38437081d293c");
            result.Add("ml", "942f6f90c0c644a5a32eb04ceee146affdb0605383b4c78d1edf086ef07d562a13cad37efe8f0ad559cac3b54efd40223745d3ec8084448eb908926ca0aecb86");
            result.Add("mr", "24a8047c14f839bc543426cce74c4a4d8e616e779ace8d7f93c72e50a3f6e63cae3b72d25e30b011a717398fc9998370edbff5cc01baea4e047e65e2d2710149");
            result.Add("ms", "4afcb68bb28b30aff648fe48277191cc19eb50a6b08b2f0966107577b978c8cff86c6fbd7c4416e36f937d28779347f909c76986eed67e72a87ca49f09b7a395");
            result.Add("nb-NO", "c5d706c10b992e2e30e1d0563cbab991067de35386ee83c5f167ecae5b6691fbbaa7038c7e5f38d5f083cdc9255fc4beb43f3a10130b47903266815607f88d1e");
            result.Add("nl", "75cb054b7567bd105706a3c27737df82865149bd8c4c1791cea3cdfd647374ad28a3a0d4ee4fbbc9e94bcddfa848614dd5f0a6c43acf21c539ef5e1fee993c9c");
            result.Add("nn-NO", "fd569103895925beaf734a9803f4128c8f3305d726f7d57161ed6321b8a291ff1c09795a4a301895bf5d025def0c6c768b1c36ada96bb33e4b47a40bece0db71");
            result.Add("or", "12196a2f780ea6af66d75720d06b485f79b9961f889bc05f609552f51c7a28dece0c2c54fea8660c75d6d8799b454943fbfcb7aa311b99933090d1e61f47b7f4");
            result.Add("pa-IN", "86c0ab129e6eb26c38da65af2e4652b12abb13b397bff25fe5022fc46b4cacd8a29d9891fb9118815035c3f223f0af7fea1a3a6444b652f3d9676e03a022ef85");
            result.Add("pl", "15b3893c7558a908c3ba40ec0e509e80545fdc0c3448e7338ed8eb84341c20df1d56ff860e7d317078d5d2f73792d0b4b4b1c8aad902c3c908df7cd1e0933ac0");
            result.Add("pt-BR", "21812b63de2f8dd3182eae3631a411e94e5e41395d84d1bdefff983035bafe8eddb0537331ee6ba433f1c4ad71667602c16101c332aaffb7bae5600fac830c39");
            result.Add("pt-PT", "28b05e9d49f540deb4d48da603436e2112953265292cba085a8d09f225b58b46bcec327a7557d206c5e9a713b3b6111775b10dbf927226da2ace25135d6771ab");
            result.Add("rm", "171faccf127e1d7ffd0bf391e254da61cfd3f89536446253c4d8f166756ce723dd5e13de641a2e3c6bab1474dec19f341e734c8ce677c4f2bf2eb8dd0ced172a");
            result.Add("ro", "7586b4e5dbc9a232d9d5927357c09e61ff160e0da10b3a60a7d2e821ae9c50b6994762b47eecd52edff314efd39f2bc0243804a6d7551433e5076c2a13d2bf7a");
            result.Add("ru", "76804c16f0347f2109dca26f6f0edc2c6d140d0fd585da40d471ebc05ee40faf144635be91e49f654511aee4974b8301ead844696924067dbf87e4feb954b264");
            result.Add("si", "fdb0db7f6d66e6763d045b60bbe2fe4ac4937f04334a1e4d15e52506d245ac4948458ac27530c8244a8b282fdc4ecbf9cd7978aa29fb247501dd89348cc2ff4e");
            result.Add("sk", "dd66c4d6ae251a4bf4ee6c1f6ce40fa4e95d38bf36a2a47efcaabdc66238c3dba8b143539cb7b9e962881213368536cd27114caf970aa61385c22c011bee05fe");
            result.Add("sl", "e7112f5908a7af6aad5b968dd9dbc352e4546aae5b2f01730aedae8b8b310b7ca976e532e4edccb295e0527a647c6d1ef4d3641126b97c578fe2fa76f948f5e8");
            result.Add("son", "1647dfb9be204d8369eb16bcd026ce5ac1966decf20b691d0da4d23487439c0ef728bbedcbc541d220a3bc37e15091918b135d907f7dc8149f1c0ab7f21f1d04");
            result.Add("sq", "2b3d92de0882f8a7a6af123622e1655690500b1f2749833aa7201cbbf9431193d63f9a182dedfe004f75f190845609828ce36e9c8c6b705441ef947111164235");
            result.Add("sr", "2db8e660efc5f51baf1967fb6203f170e636aa88381a5ab84eb6a32b65628f4bce42ee500d8c399c30046d0d76a046cc3ff83e2da012054a46e45d565e17511b");
            result.Add("sv-SE", "a57974b8dfcf80ba6b128fdbd802d88312a55d52951139626636eacb3db794b2241b871b96946ac092a8ccb3d82a6251d03972fa67057e2bcb6c133aeab46735");
            result.Add("ta", "05f588b5ab96786c0018e51603fec8f391cd104b1bcad633b02c1e2aee03d9ef3e3a43e7da921ee5ab9556ad9b1d761c3746646b04897ebbd980184b9ea07881");
            result.Add("te", "03ef7406705bb90668967739212cdf784024893b73653f294dbac24235b779eb128ef12692d19a0bb6ee97621dd57ea3a04400c5f138ee84b54383aba98241af");
            result.Add("th", "eeb2ef9ee9ebe91cb7ed0c577aef4aaded325fc9554eb5d421b9684980dfd7376ba3bcda174101c62a946dab3a7c1e3791fb54e64d6226f03678b16f733484aa");
            result.Add("tr", "33eacc59f6fe18a3f1c14939665b0ed6d296e6f0ffc1f18e2e7c53a386d3d11cfdfcec9c458268597bb52ce29fd55c5699c850e914544618bd36c7d2b97b31f7");
            result.Add("uk", "2f4b42b0c98252962c0fe3e10a08b55e1cd8de138165caecb923bad13aa4e92070c0db40da83583f270229a6eefc8b0e5a7c6bd009fdc0572b5b509a5023f304");
            result.Add("uz", "29e20ffb0cbdcbcc0e56169c1c4dae4a8befb6fe90a1ae97c3b105948d418a156f56f476dacd2c999285c41a89211d074a86b78ed2199af41b2d6f302402d4b6");
            result.Add("vi", "951823281c84057da8772e1367ca1c9b9e3d6155a5c92b31eb410162f66618ba049b7f6de04ebd0f1571d28dbf522a427106957f916526a5634e67db6e194845");
            result.Add("xh", "62eef14c739ea52b9dc6150ccb93f73f2cb904411d5cf05a7b170d1d0e248323b42de654b3053d3d00e6f1629f013f5f83e055c6bbd6688cb91d71903f9491d3");
            result.Add("zh-CN", "571f765986396af389b2f24d0e5844b3c933521add7ce02cdae2f08b5191d267cb90d39bd4a7584d17f8f399069dc8df145b6f488bc15a49d21a3d9a1fc94096");
            result.Add("zh-TW", "6b0ee554686175a8dfa0df6c5c94932a5071596ff7e148846e371840c50d1763a17fb096b7c054610365e7b8e16c538931612e68e365bc788cd2b1b51ae0759f");

            return result;
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
            const string knownVersion = "52.7.4";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
        /// the application cannot be update while it is running.
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
        /// language code for the Firefox ESR version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } // class
} // namespace
