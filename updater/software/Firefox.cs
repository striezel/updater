﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/142.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4ab2677692346891273a36a40f7088d875aee042aa6563c83b109d28b31630e3c7cc411653e86f42d65a521e6c50c7951c9be0c0fb2a5a5628ac3a62ebfd6774" },
                { "af", "23cb1d8d7df4e826a2e88d9d1f09fc29465e678fdf64f24c278bdffba8344d2fab0178889f7a769526342a05cd58c6df90a5127563f0f603d752ddb3c1f42ea8" },
                { "an", "fe79dfb42c45c72c585dbe448b221e7854a85eb665a1771a95dd9dd2aa8ebf71d1afbcd3c650a3acb5a79ca9d9cf345f816307109fcbf4f570ef4dfbd7aa869b" },
                { "ar", "2d3e7ddb4fa5b035c26dee78ddf934aa710c443701df8b8bc07a2b5839f2dbc36470bdab710d83b0ff455140e4cf9c42c54d6a2293d17470c77851cb354176d7" },
                { "ast", "e95bc76432251eb7f7bd44811bd27cde36f6999be512e0617858f10e3bf312738611e9096c894fa8793323218592f83b968c84a4218a83cff62885ba09a75de3" },
                { "az", "85693d7a1eda5e898b5a82d0d12a9f08d8db7fdb45927482dd40213a9007e7247b31ffa71311a5dc364e0f5ad46b4ab62bf4f18aea444d43b83b8c56829f08db" },
                { "be", "141f17d9e130f6c0e502bf0187f10b1b2afce87450121cf73a6382032136a4e78409e301b8a49aa46235a0f12f3a7775692485b326675173f6c2a76a29114f0a" },
                { "bg", "65c5eef81725412d2cf7ae93ca08457777cdc3ab5e5163f76ebc169a2dba26b47c310c3b5a96425f370b544519f9481127d8f840065d8f3da43f4931962328b3" },
                { "bn", "3c79d6ec850c32ebf825c9ca4437c5a88fc36888e6622c351222cf11d36851b087678d77fa4ed8b707419653dbf6f23f2588f8899cca00d2e3a0319e6081c3c5" },
                { "br", "c6db33519598ee197a6a2740544c9e3c4c435282d027a34b05a5da4832c6549dbff31484d421ba3379ec42acdea0a41f81c8c7af5b1e60e3e1aab116c6b48e2a" },
                { "bs", "a34081786ba4c77506b319225d00698b86383c9173a299d06090a8bcd5829a3497f9f5d2cb689a4088e2862143ef6acd6daac557eefc08d644ac0c51ee76cbc9" },
                { "ca", "39f773b5df2c5570f2bbbf1303cb688f297488781fc9ea1343e34f65e16452b1a03957533fb93a1ed8cfb9a1405d994c99f50df6bcf5af558efe04041837a967" },
                { "cak", "1e7ff92f1baff0d8580a66ea8658278a533c42e22f8fe02c6f5affbc78b58d5907c038a24beff4959cb6edc0666c32882ba62793ce68c6e3aecd9a61e638db46" },
                { "cs", "03cb26928452f393a2476cfd3ad138d86f9e2178f46322dec0286f93acfe9f9a5172672179f5735f33ae6081c211e4d92473570a44c0b8aa11893f9d3eeab930" },
                { "cy", "3e816613ae0383fd225d854afc188e9bcec6facd7b0e7155d2bfd869d5872cd51d82ffaee0580c99a0d7aa68d577c00d3919736699534f1653f7f1ddee9e7901" },
                { "da", "074b7c0e0267dcda3c330bea603a99658d678a966c194e5bac028cb90774577271a269159f1e0fb09823610b1ea807c4e21b202bebcdbd00149245bdaa45511e" },
                { "de", "2915e958784d0824470c1be89b6eae81235c54b9c4480bd115ca5e8bed637f40eef3b3890f731e93d6f0fa973c1443922d37d63fe8d0d44c85e11755fc7c44fe" },
                { "dsb", "5f77021cf7881b7ec3132f97138c159821f91cf322d2f68f079299da714a09ab7c000cad38e2af3454c138cc3c766171e092a1e3d424aec3b371d97f84adbd86" },
                { "el", "50d35bd686d31b29a21baa3492f57a9c8f458476611b1a8a5daac7b59ff07ecba5a4c8fdf888669d6da9190bdc2163aea0f016c8593289186751310f72ec47fa" },
                { "en-CA", "ce0bbfd6428898f307be21cad7d753db6d07ece6a68c3015333088b87999c3a077f14c243476d5c55e8dddc6b61b2b76cc6d4d07211f5a050b270d4f7300e543" },
                { "en-GB", "5a9399a75c7d4090aed94fba7c2331487a4d953057ce2e8a4b438df5fd8018d93ec6ea4c3b21edaf6f3c37ee26ffd9d157b3c147d3459360045cef341f348d21" },
                { "en-US", "e5dc475211201da87aef9e8da0f9d4fa838dbf3c7cf5a244bcb27aa2af6caf7abfe845de0ec3aa2b3fb5659a5945ff8cc989e40fe93e7c44503282e12e82d6a3" },
                { "eo", "3766f5811da8adfda6a393164497f7534076e803cd1996bbc88ecd9d8e2abae57f3a653ab647d9cb0c25766be75bfce3dd99d4c9b2065fe6780dde5706a3e45c" },
                { "es-AR", "a09101c9dd51167425e09596ea820d7e111044c1e4958ac7e2c01ab886977b4ee3785a724b6ea063a496fb4acc21f6552f897ab902d9604b605761c9ec1f49d4" },
                { "es-CL", "f370f837581b98ca4693bb6c866c6f0452b5a1ac267d50ce8dc06cccde761f6fad84f690e674cf036cf627e94f98dd114f1940b4902e8446df35a338d1b9db62" },
                { "es-ES", "090be90b87c7aee4232126c90c515dcdbb5a022c7c7f54120f8a397dd93742762f9a3e22359589a504751dc5fee222982ed6b642d9d6fb1766e8092e1514a9f5" },
                { "es-MX", "841c06092e4a6b42eefde0c7981fb286d350118af98bd8cf210981ac65ec8d95122ea2a49380edfe2db68a6a6c7390631ebf5de36d8d002ec81e63fce735ef46" },
                { "et", "06de3ecdb6b45a80674451acd794860e47d9505c228ec2c1e4f418000131a81704da7d0097d84d04ff1610a28aa2b5af23c10a66dfb2236eae56cb6cdbabf734" },
                { "eu", "bc52a17586dc1d2804d1ad9101f57d509eba03d1f532169d81c13d0875f83cbdcb8ddf448d1e97b4836a3524ffc43785fd1d249c3846722a679fc99f578faeba" },
                { "fa", "5ff1f69806e0412be02de8f624ad1d72b1f83bf054797038b98e91ca61e1422dc3ee254a3ffa2556c6e24b71509b4c16432543b35ba66b9284533ee4cd909928" },
                { "ff", "6584dd30e71ef23986029c2de1a1105df620569def9c891421eb3dda2dbd5191044a7b0f40b832d4315d02f8ce7b1cc5827ed66151482bcd2d02839e4d5a11a5" },
                { "fi", "3d9d2e5b95254f0f5e8b8cdb36d21ddb31f2b86ecfcb0d3709743642cc7ea97176ff14cdd9a1193162ea68e8268f178a7d7ebbcbf5802bc4a7c99293cf8fe119" },
                { "fr", "f57bad18c8ab124bd9c6bb117d604fd97014a9edda70c9c57a19ba44556dc8305f4da16dd0c1cdf0b55f64c9788679a27795d8c0dc08143ea41fe6678afee9fc" },
                { "fur", "9fca675a187a6433737e9d24a0f2a7fdc85bf3c201df1bd3b5b9df2cc9330e6d4ae9c27b859b1dbe0a04c6a72533f93f6cfbbf2c8bb530367551e017ffb4f395" },
                { "fy-NL", "e97f14b89a1d3c7c6157b647a783994afb7939f1bc4c7b0191171d9e2c442ccdf7bc997f8ce57865ee173fc96a6ff601bc551109245d622a959dc72ea807a789" },
                { "ga-IE", "e767259cb20c402d77a6eca8f883b1f0618290b9faac26aa307180365eabe363280d2085e93785d5d21ea45d4f55b913b631476dd826d63a95ab6b09491a2328" },
                { "gd", "b9709c18383b8561a4889f11c04dcceca88d7b52b776f37afe72c0691af8e87b3db40b1220a3050d65ac9d372b6c63486c4cb6cdf916767897b8dec680a8a6c9" },
                { "gl", "403743c6d34581b37570ff7c3cb4cf234f4f5f130c22683bfd8ea8ce8c2bc37409698c71ebf36742fd15d4d6a0cb8e82fca0d710afcd1a28a3469051689c0da3" },
                { "gn", "98711681531530519ed958342364ee8bcccd5ed2cf35ce8afcf691cf3825a9da67ecd0a31e30c436d5d31f5a756e5c019ed88ef840cc39deeafb71896f20db88" },
                { "gu-IN", "930ca1f75497dea6f3de05ff758badd9c8b038ea053cb597769d39225f6e8eda71f2c6874a5ac7b115b90fb5ba1792d9cce9aa9122666122e264459df4c444d7" },
                { "he", "b9b8e7c79194c05a0beb33d870b2a6a071567733ef3ad509c4bc40821c096973f27eb4919ad7bf47602a0dd06ee7349abe3047915980f6daac90982a0ecd0a85" },
                { "hi-IN", "6361c83e7a24eebbfaf92b5cce4ba882a0afce0677ab51584a051769ee180461e678eefd9a18f274c6110f668e1016dc5236dfe33c0e0e1836ed547f444dad47" },
                { "hr", "b8c49076da61adba238396c9fe6bdc7319a1534b89a63af320473c2dea4434d996dc56e9d38e8a77749992ced7f8c85c27a07d8563064d9cdbe26c3767640973" },
                { "hsb", "9e05e7b0ea91fb893890843550688177746d9aa650079b26a69f5194219239d91368e0b61a8f1c900be1b33948a2e5e498dafc4d56380cff3f193d65bb94b07e" },
                { "hu", "91d8f58999e253fad564035f3041c29bd48db924f7e4791ecbfb4bbd9a42f5ba37230a50bdec81447502cde9da1ad25c104da93523947fadcfac2bb102e60c6b" },
                { "hy-AM", "714f935ac1b550de75d48be8af91d65a1a780b66ea18f17c0ba9d423656861852754c9a19224a9d3e91d8fadaccd0a298daa00ce93cf254ca9f1f6e0223d56ba" },
                { "ia", "d4512ffe5a83031971ee12acabc1c27bb1275f0a36edcb06434e99777fca81592acfa528095b3f87c8794d69d7a06c9c12fc4a583a030daa1e4a978d4fd80da8" },
                { "id", "cec4fc3f1a3012f5bb5e38e93e3d7e23f56ce4579d6e0cb9ff4281c2c074ece64ec91d76fb264bfe635e9bc029f20ec37ce05b6aea7b85f56369f9fb2da70616" },
                { "is", "281238bc60491fd7f6cb1734f0bbe146df5f76327ed64046699e05a8b267af6f65022a92c839191351de415e1a2a6f247ce07a14e2b1552035b69c8213b83a56" },
                { "it", "88c9513e68fec4cb8f25d29a03815ad8612c00bc537c7e04155a8b9ceba638e5efcf391b94b1d7b37da46893a135a4c16623acffde27750ee05b5d2878f4e930" },
                { "ja", "e6125a2bd182c2e8a6ea5df8cf40a47fdd3fe6038335803d36891432cf8b5aa452d5220f0da4a18a6db73525d758eeb728d6d2bdd4597c82359fb734b6a630ea" },
                { "ka", "9aaa1a1d24104cabcb9bbe01901730cc0bcecf03d68599022f53eb546b8101639be3941340c318ffe6087b16c1f1b958b6f2527cf8455dc48aa59e5b155fb79b" },
                { "kab", "88fdf31ae3180300d3303d72314428db9624044baf9a6af1f664f47fc2bdd25b8e5092b62fc611fa4c7fc572d095f036faa31227bb8422e2a3d9c9cc306ac2b1" },
                { "kk", "2d7c7338b50c146e76ad8ec2f1993ff59201b57d0231f58437d4d931149de481df43ed28066fea99610d0f41bd19a404ab7c5466e31d202d88616561b9452924" },
                { "km", "42d3a0b7b2a5b1dd2126e2c26b3978b44d79c5059560bd6b575babc232b69018f0569bad9cbc2e3d2b052287da2192b453fa68549e8abe464320af99a636f117" },
                { "kn", "e7acd22054ad5a5fe75ff624e30c0cf60b05d5346d6d3229db3f37402ab8bcb11bd8a53e285bdc7301c1fce94d127f7aa61edcc8eb9ecd68100497ac511bdcb8" },
                { "ko", "9c726f17a9f281b48a0387f7b2f417fdb1e1ce4821a5a81f7b43edec992d00a26e9795e6db46b9bda1d941223ad0138176c6bdd81d8c8a1d10682dd60909e795" },
                { "lij", "cafb70a0e06ba0d06e22508c2287192d1a006f06b092269dd03fbfb0484d9493bea829d3963d140e41485732ba2dd8e5cb498529bb67aa78cc022e90e6497655" },
                { "lt", "4b92baa123027433b3ef963b8fb0d00ee4e55a804e55de7fb47267dffb36c76692b3b9e494eb90b16aacc12e576be60402dfc785110102092f638a738969bc0f" },
                { "lv", "92007a8de744af0affe3f9ad11104d38fbd3118092482242639090c98068553bddf4bf7e1df390989e9eb4c50057b9c5585fdb96f8d3119e8b869031f3e02ef3" },
                { "mk", "714aef976573378a571f233d294514ddf60d07f9a76d28700d2a75608526c95c7108a73e4545d2018181dfb7d77af21399090b3297b5315fc912c5109ee4b30d" },
                { "mr", "a0d9575ed9010610fba54395d00125c0fb3f6ff0015fd40b381d59882d15779e90b1be63df927700593011b0fafb79679eaf5ad85ac91fd85b96d4b8d1b76dda" },
                { "ms", "868cf46f170c6f3203193efd703e70895737d95507469363d3e0befc72ad47cc8dcb561931d1794a81498c65630b287113aa1444a1fdc0da9b11aaec6a521a8a" },
                { "my", "dc9b4d42eba95e9429077648d2c56dbd6f662fbe21b539b43acc7d0d6fef24a37b6595281388f382b9ec3dcbc4c9e16f251e94d08ce06b308441f3d34b0da56c" },
                { "nb-NO", "1b1a8c77b995ca3ae4f4a32b908be63b5d6ebb12291d2eecb78054ae7bc39570fa5989bde6de59384c59f8b519cdb36b1b7dc3cee5483e7d762a2ef9d670bd3a" },
                { "ne-NP", "4a26d9ff52d8a81839d8ecb39e4e31f094e3ddb65842216eb19d4b8a5421a4c8652761edf80e7cba1d8bf10f08fdff2701527c8bcf795e9de8971438b0a2f8a2" },
                { "nl", "bd33dc643fa5b1584da0108727db6c12231576b9595e166a6d4285657e1a73ee5fda9a8b603f7d1aacfad249ac2a8eed47dfeea31ac0b6c316b64f9ac24bb0d2" },
                { "nn-NO", "4e7ddfe9f45c4d45b30f96cc90e4f2d430cfbf26e665f10548e8923678c89a448227eb63ff751c56eeb45c66bd582361183d87095d55e984d2862a5950ef354e" },
                { "oc", "0eaba417b15b0fcec9df4b54c540fc506fcd7a372f6472c231f950b07062db7bfdb170b7a179ecbe8721fc48042d43e27fc60db696a8957fe845273ba567de57" },
                { "pa-IN", "9b492a07c8d0064c9768f959ad70cf7b1c7927606ae71130352f34b15f6d08854624ffecf3dfac42b924b6b2398f525c1390bbfff586b5e8c4b3b1cca7cd93dd" },
                { "pl", "3aa19e2abbc429cbc44196d307c8d79e50217f89661654bfd9e65225489f36e9cfcac9b23f0790899d9efe5e615da392bdc684bd7716aa19db1b9c8ff5911ddb" },
                { "pt-BR", "f107cad783f62153bf80cb14e4fa182cb5909ad96e0c34babc951fbbdd0f67952f9f8f523f4da2b38b715047910f1bd990d96bc2d6fccb5a8b71c22a8c21536e" },
                { "pt-PT", "8984db8b617f489476697a33b0a548ad6c443059d30499532a52707806f43b285efcabd771d5efc21e499a0b8b713592a9d116481e7ee1c2185d91be96f7238f" },
                { "rm", "82ae6e4746a683384d0ce1a3f987a99200dd2b0da68f9f3c2a43685d452b97d8594558362082723cc26150211e315521ea3a3ed141bfa146c8799af8884008db" },
                { "ro", "7bdb1b1992f8d9c5ec156b3119a0e28e70af8786111e3dcfbba0ce90ef1bde00f26d71552e266242da2cb7450187fe16bba65ff4a80949eb3b71417d149aeabd" },
                { "ru", "8aaa52cd683262022bc679c263e17ec2a8fbed17228d42bdeab3229680494b391e0c617cd85d71f3edaa3ca04002ed3d8564266b52af3ad5f96399b90ddb650b" },
                { "sat", "0b64d9a14f4b457471e9e319cc23445cbe6b1c6639198d384897360093ae966c8c8e1b18d305fac334b763ed3315b25aff724038ff4c1a20a54b233e4ff5de27" },
                { "sc", "70880a8da628f5ac3187a1e63ecfd5692df40ed7ec570b7e100bea5f78db48ebf0e2002055af0df51f1451e03e17620617e29fea6ee45d6b64032bc45fe6988c" },
                { "sco", "5b05c98a05e80672f85f6d6cead88a620c6bd061cc858d7e8b9b5d59dcaa840376ae92ee544b4badc77558c5f36bf8e8cb1e1fa5b006793a9f459a7d509218f2" },
                { "si", "9b71b3c4bb155d4c669bb9d7b9f6a1c51978bde3b27f66d936d79e32c3d53520843203422de13a02aea17f37632cbe48bc0ddcf6ca4e66ee53242b7cc5b05206" },
                { "sk", "84bf60b6eadacbe64a20f2c39dca7a5bbb1530d55cde6200dd10c39f9784ed7a7841e5a20f8d8aa4467b80412cd038f4b9c36ad302687c53e18f2eef35634f3d" },
                { "skr", "ccc9500cd598fafc5c93a4b7399432e26d946e85db264756cb4c9e34444e2e7c859a65e8a22352f25185d9fc399fa2c844dcf1af074d1dd2823d4a2e5ec5cdd1" },
                { "sl", "b1e48683aa55bab6b04ec82518bc03866e1be7d49abc21fe24f2f96ab7ef54ecd55c3e21dad9755a1e393c105f9dca51f118e77f77915bed2795ee49d1c68700" },
                { "son", "af0ddd6fb2f6174411c410bf798a5399f49e7eaa84e85aec3b9498b9a8bfa3f1f3f0b0aff896124d106c4cd95715a03922cc7c5497dd639915c51de51bc4e1ea" },
                { "sq", "152a4e1b879ac93d99dc183ace14dfbf810b01e91352d86d912381695190e1f648f5b13004528cbd9891813e6e827d1d4788025d6cd432a555110a9487aa8cc2" },
                { "sr", "005c4f1ca22eab34909dcd46d67ea1938459d55485ba4fd31fdae4cad1b5d8511b83e39e2e379f65bdc0398da9854d47e0f9071d259708abfbf1d317b7ffb2db" },
                { "sv-SE", "966bf8d681f5a6f161344ea1fa31a6eb816f9a2cf088a334f0048faff7fc38beca72475a1e7722819de519cc6856f97dd2cff5e19c3e46ab14f307d5e6ef91a8" },
                { "szl", "e5ccac61792c48d81d7b8a3832c613672567c04a4e50ccab1cd4e5d4d8dfe2436b9764f0c063c3754b633a96c8a793e603299fd457bf0689174f03a641ac02e2" },
                { "ta", "5e1c51ce0ad6c5cd30da8733446d843370b666d4a9c492a578226efd6fb9af2789e39998d3bcbfebefcaa169e0d59298ed7d3b2f4b0174d9452bdb87daeba44a" },
                { "te", "04c63235690c8b9f2b92c212c83b96bafc49b348276e4cbba9a291295d14291516687ddf7d75c0314dd99eede8b0a79c803b70c4dbd131ce4b8d88c277b2c2a4" },
                { "tg", "25a7d747a04929a6d95b42d598450a867bdba4779728e05397ca57eba8b2cbbc6d0a7d29bc12509b66f87ff5b2329e9a321b988b4b6a9554cf08731997693619" },
                { "th", "5dd0f8c5a1bd1722d9e15e748034f7900585e42a9631961251f9bd4ca7d10089d7e7ad7fca22211dbb1e8a48ae4e82dffd3129e611ae8b41dd07371dbc90d21d" },
                { "tl", "8d1e44e94798446c7f36c4ced6a8a6441bb0c294b082fe0177fcb4298d723405514748b43881d2bc685087b245d807dbeb7dc2b74c26361f24446875a028a5d9" },
                { "tr", "57f0e50b847e7e9d975c80d7704864df0cec3ac0270545496ab71dc792af8f5f0418c7a59b6a9f95719844e9b2475c3a29e575abcd5f5e9a3b6352572d343ad1" },
                { "trs", "edbdcb8c70af47298523abcc904b456da03717182922e0ca250b64867b528b5cb9c80ad9718d3ccda478fae27c4c561477e97f9e8569854fa1a12cb735baef88" },
                { "uk", "a676b5a2a7257d0ce2b8d1d81ac02629efeb62773d2d60db4f200aea0e68ae4e7eb47e917a03c6fafb0d0efdcfb53ef266c220fa663892b8b41c44fe05c1b307" },
                { "ur", "73f38c952d09b0c71a483397abdd3cb6459f8dd874e4f176e7b5b8933a3a448b627190fa8a949990807123109655d966475d26b1e33e069fcef4b3936ef19be4" },
                { "uz", "f8d228ec1bc893e065e1d1506b6a5a9aafdafad9721c1d512111651c329e0bbb6104439d7c8bfdc42196243acfbbce1ca27dc29c66acb0a4c6bae4494f673e15" },
                { "vi", "3cb3173dfd5129c03044b21564d224a0d80fd6b487b6dfca4ff295db1ab486c2751be614f78c1621b9f414dd0e9bc435e5544ce990baad21b0c390f49ff2d809" },
                { "xh", "d4d10c4f997f0e45b1cd0b51b3a38d5f5c05fb697dfbfd49efa195baeb4a4a2929ca2b9f2a3627b0c9a8722aa0528cc0453f8dcae66fb6085d05028a36610e00" },
                { "zh-CN", "b154ced257cc92b7cc0f6e2774f811f9a727ac7400091871e874ba7684eebb600236f851bf5890545ffbbbc8ca91f2d926f64133149373d48e4e09af29b3c922" },
                { "zh-TW", "9b3797f3147b8470528292a7141b0861a17f86d455a947906c32d1d5320c60a4497991aabc758f03c9f231363790bf96cd5fbb4a1778e2415e279588d5161426" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/142.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4b7e0a1c7537df9037eaf708224ad3e0b4f5e2a80b3e88082845c9c22a57fedd53fc7e1e724424ae34df4526a8ac4d9798690148b7cb3ec937af418b73faea29" },
                { "af", "a511ec43ad89f3b0a6c4a3181304238fdbec07e3016aee97ce064ee215e2f21134c7daa053c76a2234c3fee33255e66ce07f1a5a292189846c7941f124765eec" },
                { "an", "96a5f3e1817786a1c9823d8010937829fea039bf4b0d6dcc387edadabe6281ec2d3708cf9ec367ad8d879f25023adff2d00aeb63e8a280ffae63a8dd96743b78" },
                { "ar", "b3fcb6c026c41136f905a4c967acaa773e3da673246f303d52cdff3976e7b5944826f9942515def634f6f05f726fff7ad0358671f2fdb07b9629b8d5a46e92b6" },
                { "ast", "70d4a42e5963e61ac43551859d07958bda7184b7390e98a4f4d1d03583d3269cf2ddecb06b7ebac0dcaf1e503fac303275f3395dff43eccc462daa04107c3288" },
                { "az", "fa9e9f58d20438c7cbc1a2f0156f696e767810b577c87d70f1c7e927502be20c218b05355fcebf9b30a1720ec7ff09b3cca1df00fda376ce43f3afe035cb1e4a" },
                { "be", "3dd5e2495fa91d8685ff72d7c27f4932cf5bf61159771c3a30a3e2d7ad5fddbcab0110c418b5d00828d34f0569f9149c9b3f3e073ece0f1cb38b4a49215439ad" },
                { "bg", "95d882af57df814cf1c5dac610ae4ba610e1d0a48ead36e156169f63d040e90fcd22831efc7c180b3a14f9a6bb8decd9a4a7a990673899a35c04fb95fefe41c7" },
                { "bn", "74c3674adfbfc7554f83c7487003c44bf39b82360c85a160405dbb9f6eb2e3b3bdd08027318c1497d9688bcfcc73dfb871f9754af95ee7762500a1e40bc3d7be" },
                { "br", "f965ea5e6190a90d0ba554865fe995f6e3aea4e455c06b7905acebecc8a2777ad9cb0930d72fa49bf24d76d223a9668391b988fb02bd0db70735be22d6f964e1" },
                { "bs", "48b397fd057d6bbdbca50e20f965a881b08624f4aa3fb79c02b5053d8365941fb74c5381d1f9e564486588da93f348d95bda988eddfe0d3b4b2507b750e610f8" },
                { "ca", "a3a05f379d5c9095ed51b6b7c05716f85a3e1072784b5ddf6d5bad6ed023b6da03ffd718598449f7bf2ab55c882e467e4648dc0e782fded219e23cd42fbb85ba" },
                { "cak", "88f572b07e35a02b9d59bcdf61ea4a0228111288d2cb81ee428e865de84d173a0b2ab76834de5b5869bbb6bd56d300c90d208a449d0193121ac729a3d7188a3b" },
                { "cs", "ad2007ab5b6e06d215411502b9133dbd846dfc972b6a8d03636499e49f12fd04f94fb64d9896753e7d64a425642c5ce56011e61abad2b3bf542c79850ece2d6d" },
                { "cy", "d53de021362842e5b37fcda19bd5be3937668179d9c45b5670afbaf582049fc8e8d66a8e406f5bba7fa683ce6e3044647b6f52541f0aecbde57ad164a8cdd277" },
                { "da", "1c7a7cddab69bde375078335e9d40e27e03bc547b5c6d9e024a20fceff4d8eae4cfad918aebb25318b450f2cd26f723d48b7efd0558a63806b2704b173c575f9" },
                { "de", "bd24cfd8b2682842dbf21f39c4d72d85e75337a798450cd3a1ba2137ee261fe645b321a6c7cf133a5e77832672bdb9282afc411dc85a237619bde26cbce5acbe" },
                { "dsb", "e4f0ad052859f9af218a2aea9530470950af7d48d3f38ffc1252d5ba30ac8f41e868d297a97443a072514fc0213f99570a3c7c53474cd3fa34ab816200995619" },
                { "el", "10abbdc0bde6a33b176f81b126302bb2ff6ad986da41733f8e7a007a41828ac1e308235c899464957b34d89592003e142a5a939d61cd1b53870d8c25b3d06965" },
                { "en-CA", "1d37c68808aa15cfa9812fd52ea3c3bc7fd4e87ede7256874c474a985924b3e9ff7aad28c1f69ebed1fc7e77918289cdad893e514b32ef223bf44295a4e1584e" },
                { "en-GB", "ce49f2d4be0eb0cf864c74036057a2954be50827aafa8ebe53ddb911e2400627b969c82549fe742a355aed101eb305d28597301239c5b8e0129e8e4f63b22432" },
                { "en-US", "3dd31dd91d4ca91fc9ae61e444387d1ecb9ce557432a0fc296a9861f43c8193055b0ce10d49ad44fd28bf4df456104468d2ca41ace5435eddbd691a14fe8b68c" },
                { "eo", "e2149e772ce1d029afddd8d2cbd479e4ac0200797ba0637ca19d2841ceea3830fee49e884c08bf693818d592bad80481eed974c5d4c23d28eb1305b612e8d8fc" },
                { "es-AR", "d5fd7a8bfb869909e7869f65d6b104080c1e4beca2891210871f139261197e818a0f7c6dd0f42aec9690f5b48822a52a55ea2c269c4f623aa118a76ae44e1dcb" },
                { "es-CL", "b2409074cdace258b7a3b7107ef522da94d617fd372b947419e91cfa0f6ff921cd27462d6235d4c7e2b5451a7abc4f340758eaf5feb599fce5599a95c2b296e8" },
                { "es-ES", "707e84799facf1e734c12b6937f125d149161213c60f7cda50c263b440d2f23c2e0d532aeca5f2b4cc8412a4593069332e24829917154702fb0ba50511a3939c" },
                { "es-MX", "203dffba9a3c655dafcf82658704fb5ac31e1b223e0b8b699fcf45ea798e779a0b10c08d1d3c3762400cd7a5b5949fc195dd83316bde4fd9c1100467aff014e5" },
                { "et", "199728ea389f434304f395ac6e68b819236b5e7072c43c6ab7747366c8d6e9ed3d6b8b84ce582eb5bef0c23f143e1d5008bc7e4e0d06dc17460b8dcc239f2d39" },
                { "eu", "30dd73ea004c256a1267d67604a2f7761525027d3b194e51037e60d8e0b785a88d4543fa89341db25aaf07126a0556d65cfc01d8ad267e74c6b9feddb315fe39" },
                { "fa", "ca0c89a75f3265db117bcc84875c9ee2241106088efc59ef1e7693c76218898fcf094b4a272bd480d7fe277db8a1d94efa42aa3364fafb0b44c543490cef0eba" },
                { "ff", "b5f7290d16d1dd14fbb0a54b56c9c7b7fe0ad9890125efd06c5dae8350547f424c4f5b28da265a6ad7f922bce4ab5e0686267d333d376c50ae9f4d7d3a9f40cf" },
                { "fi", "5bbf6fb2148df2f2b96799f1112f46606abb6afe9b841a3b1b21e3aabd7b6a2338fdf16746fc8f8d021cd721a748504e54bbc2a5176e9fbc51bdf57bd27d4ceb" },
                { "fr", "0ad9f793f202cf4f2462902a29140fd56129a5e037b4c1edb8ebd35eabe1cc3af03e9312b9d9b614530788a9d2c1a17f7d4b153ead284b57ef5e547926772173" },
                { "fur", "884d436851623c7010a91f7763f4d02234e35482bf63d95b023f29a3893ab8617ab1efef25242ffd3c988c75e7730a56ddffe1a0eee447aa2d8b6b66a84b61fd" },
                { "fy-NL", "8e1d2075b30bd17ea25706584edaad8ff8c5f97cd2e17ac76b652de89637aaa926de40665d0c7e2dd65dca13feec3c0d10e72d9ed310c9d8125aa35d35582f4d" },
                { "ga-IE", "488a60e3428e9c26672157653b5ec1ba62bdee0e6242ab5c995694cb1ce3c3e36f82632ef48fb66cfab3c738a76c7bb12e6d3b1a55cc30756639d66f75e6f879" },
                { "gd", "1286cf0a223e5b26fdf398a7885fb60870be8585711b1a8fbf321af59c7eac9a1441a1a9b3fed69e68ebf3922b5b41cc0380fb89da1ce6c8215c4a7b9ba273e3" },
                { "gl", "0c20373e6202fd0f48bf7c6524d0b7920dcfc4e399b3c849fa272404a994bf0e9e491f645f87840b5dc4cf6bf5d449bc37626ac7294ae5e6c533736c90381ef4" },
                { "gn", "266e1eb0fcfce1b5eb45cfe277f59f4616ecd1d9722d36c4009e9a96d8890ca3c4c0454b682e44845e57d20bb9f07bfa2e53b8fee5b116ac864d93ac1ccd17e9" },
                { "gu-IN", "a544d87cc9cf46294709657f985a4d28d787ecdbc204dd260559a88df212cf106f44a15c30e289eb34a56b2c55edf3ff4814fbdfe92d6d96062691f6ec8902de" },
                { "he", "69df6f29eaccb5c8e2c61c7d6c2ef5f2d88be4580005d203587fdceadb0ec12a3943833f5c9125c2e9e0b5224f4fdd50e135b080ed5f428b37009fca55236623" },
                { "hi-IN", "f683fcbc894c5e7b79b95fb494ca2a76d9706c81eaf601590b12b73ada4d717c37e069a95587c87cb3aad32aa393c9178b579509c511184e0e105f27aa4c58cf" },
                { "hr", "9f6e2b09daa7cd8f7aabc5a5cebe9b34e886a1afaabf978470dadc4e0c01c2ffe1060a288a659379834b36a99ff827a04f0904d0d23b2d61fe2cf41944d8359c" },
                { "hsb", "8398666e019cf9c4040e92aea8f9a7316257d20311fc00a7e48d43c5eb1a49152a9bad9aa3b01822e812afef40ccd944118c529c68afba479fa9b5adca848cf0" },
                { "hu", "6cef7a31b55d6faa228b765d2b055ef9a47e48379fb81e90e568fac812a87390c7c620bd5fa675982e0eec2baf89593ef71ac5ac2f4a2294312dc83fa146e600" },
                { "hy-AM", "714cd0493966ff88ca11acfd1d2173b93d21cce98e264c1dd21b2932c5acfddc483227e0ab9852166d784554732fa4af0ac3efd6430bbb0ace22263ad814541c" },
                { "ia", "f2812435d3490deb072298c471fc44f10e60f9a997ad7a4ec6d2b1dad148bbdfefad62b1b86709e5a699500870c3d207f91e0d207404488a4b2b2d1e9324c411" },
                { "id", "7f2748e0bfd3ce2cf31a997ea76e101d75836544b651bdf65b4af68b0beaaf439fa5204b26ee78783cdf915f5246c924a2e419e7872f59f18df25f0a30a39e0e" },
                { "is", "eb53771b143e306f46221603182820e3b6417921a59d38b217a23c5d7da89f97280d943e4ca5d017c4b84020cc231e209312821979d49cff73289b1355027e34" },
                { "it", "d3c9b36ce67d460c1794a33aeb989222ce99165b4b3252a10826b2aea403dde85bf68323381cf4700b8fe751d5f21070a37215f80465379a78d50ad2873848f4" },
                { "ja", "26c89d9fa81b286aa58f88903aa42525b6eaf06d10b31dc254e136853c8a9e9a4a16608142b22413197fb360d585089b2459707cf92096b88179eed5129479bb" },
                { "ka", "61a43352a4ff25937329b60e8a163e68eb96410186e802e9fd29fec8a657feeb219c2bbc344d8f2329875076947750d76a9fe05544d07c0e5c7c4d900a355101" },
                { "kab", "d3394369c17ed5ee2e3826a571f118d4a26df8f0782704acd7544e9e3411de5eb2530b4804ee82c8a213baf084249086dba0812a463e1e16e75b12d0e3e276dd" },
                { "kk", "cbc917cfc4f6bfcdad0106ae997212b3785aab7a1791439323b781cd706deb47925ea9b825cccdd67b2bdc2ab6f5cfb9615ab55321048eddf69e9f9aa112cd28" },
                { "km", "805bc45a6f8025e50401e0d904e03b7ff4c5d63bde1ff2193add48a55ec2076ce1f42679a173496e368bfa4789d8b97c24769a0aee5e6881106827ad58209b75" },
                { "kn", "6ea03511892d7c93ff06fe042a15490c52bf3554f5eb6231a235d9f7eae855520f6d10a492f80882adbeb3e4ba102e6cfe2ea8b4ea2d01d6e3a2e3ff99b12878" },
                { "ko", "e95527948ebcf81c6b7168f6c4c014f5e5f66cc55c854b16df55fd21e0b8a420d49d5eb96d0532b3efc9b372d7ad81175e5a622e81152164297749b3270d7b64" },
                { "lij", "68b81db71b37e507c978f116044e3b08153a23246bb06c0298c712788a5b1b57f5bdc6cb91d7f929914f2fd3c9b633118c769c6c5a2474e8d1e832df8be2bf9f" },
                { "lt", "f85283781d42f29d4bcd13b54fc90e1dddff4861d91cb2095cbc9478c40f8f35818808def3dd24c98d78efaa543ebc26e66835b5f3059ca102f18627656d7399" },
                { "lv", "30c6d0f9924ce85ba243e930073ecd19d53cac021fc391def63c59af256b0784b3a020f43ad864ce50ab755ead9d887b09a3a04975d822582bd6e685e569dbbd" },
                { "mk", "4e10777a92f9c6d94f4367d1f361c82426d7f9e8b640088784c49ffce108254967ab9f8c4eceb3efb5fee37ad5f978faee9be69db372c7b7c5190ed4609594d7" },
                { "mr", "7ab2076a75a9f752226123a510abcab344f443ac23393a31105c85e9bc2eb138177b683a670e0218ce22c0ea0779ae9338b7632f4f1822a1dfec5fec57eddd12" },
                { "ms", "85ddf5cd912cfb1761a11443c43245d4c594ef4eea7a3755d33329a5821d049c477fbed5e6e5fa896b501dd4a0c7acf5a11c29271da655a9a52f3fab41e1b8be" },
                { "my", "e81edc13244ccaa7e40f178e711390114967a1ac8eebc2e8539f1ac1181086eec5714924a725bbb239bc9f41cc5e5e13f6b0399d92312c151a84c41dfa72b857" },
                { "nb-NO", "6c1b13824e17d8fa6c9b0407e1c02e9119dc7ada92720d8b306066383841e3d37656e88196bf5d822a4edaee40e7e35ec5929cb4815513f3c8966cdee23d131d" },
                { "ne-NP", "dbe87917cec3934139c8e1bf8aef0e8a60185c4a911a66c49720d8dd33453ea3a641cde464ae14033161bb67ad4e45a697c57266ade11786cd2ee0952ede45d2" },
                { "nl", "495741932298105e6d7e3ed631a466df0968cc3e883976280f69899eb07fbd009019a90ac0c246473a62d3cfcafbaa0aefe5f51788f77551619f23441d26fb44" },
                { "nn-NO", "0a6c797daab9ba52fe7b817249553274b164a673d045166c0bc24186e8d8830278a2884ae3b60c7082256b4bc45aced9962df565ecb3e18b76a427b4141fa26c" },
                { "oc", "3b1af001ba37ab3e5d14a52573ae844895e10faafa29a3632ad573b14dd9bb634285743aa4f4a725bfc11b52dcc5faa3fb68eec7dc3a5fc7580764f3e4e0006f" },
                { "pa-IN", "109370582ab829863343eeeb6fac116db74e29655797ad6633360d8e2954e848d1bec07e112e15a4ed1b925cf96c2799d7d262dda99e6de8b81942c57077cb98" },
                { "pl", "116dbc14cb2192bf58c0eed6fedc20110fe8ce18f98fa15dd397828b05dc1c2c0ae8b015241e5e4157de0924472d678722f7b21eb7907f615d1dda1643a019a1" },
                { "pt-BR", "70fe1f7c2b15afe810804152aba2565ec7c8e345390b64530f1145d9d04f64ee8e4b6350c32afc921182e8a42506a9e22cf49568d652319d366d37f684135403" },
                { "pt-PT", "1106038934d9a9555ddd2fcd80ccf8dd5f573968df914eedeef8e89a3a506259c1331d8ce0aab63f217effc87f2f79ad48b00f7c91aa14adf10ace0235c0746c" },
                { "rm", "ed550abc8cff55bb2e5b311c9d5fe1433c4f978196708ae147d3de2fdf1ab201eb084a08d8bef43149ed32c804157a706eafbdd6f26901f1545072181d9e86d1" },
                { "ro", "3c3713ab5b30d4b3a8202eb28417ac355c57884e1afa317c1741a0d6bbdbe5265a7bf1b770689c4a5940e5ad2c4079dacfc371801c0bcf0cc7d193592b0b2d7f" },
                { "ru", "6370f0f8182e10fcff2b4c8808a108e7e49d947d40f800baf73a2ea0420e66981175aa31102091fb30c1c3d319c592a3d53c5bf0cadca4e775c03d2506d5eed0" },
                { "sat", "011390b1a5422d32f485ec4a3bd8ea95f986a73c817d7737c8d6ad85cb9f8dc7e2f1ede752c50a9fda73b2153eb9ea2eedc089d8d683506fee6fd40f49919896" },
                { "sc", "df7b08818404777d98df1df9527b1389a264ec6a044cfb061c2d13d72c5d01428410c948cd2005667bfd950efaef84fe0022bd0e1dd8dbad387c09fb854af13f" },
                { "sco", "91b569ba16cd9311551df3e85291bf5ff8909e72a12447001587daaa961c1ea7d4d6c7dc6d15f7ad81e08506600b2f5557d558a66e1e6331d937baa774baf485" },
                { "si", "f9f78b00cb015ec050968be6670664a32a0159f1786cdc12a7f868861b8d952e33f9483399735e63a786db1bd6a38b5415034bc59cbc4bb4c3c817418e9ddf43" },
                { "sk", "ae99a2f2de22a6c4dc24d6b8317cc8682677ca612526667031275e48735f70548721b12bb7fb46fff8dc7815aed6103091d6219bfdd6a2520379903852633b87" },
                { "skr", "66562cceb573a4b843e8932b1f45b8d455e5d6c1fb1a3dc49d8f2f47f65f2799a1320f6ffa5c6e70a69d717346dc6188d57d6c673c7b88fec0010cfac3f4b4a5" },
                { "sl", "d84108482373d89b3ba46644e8dcd7372a34b301d4ac8b8f13d4307750acba73ac434635b36cb0ac2830db47239a139d6761718fd286b5382fe1f908430e2aab" },
                { "son", "deb2c3cdd387c708ec4c9948774917c85671e8ea9004e4391cb14fed0503b9c8d0af5efcab91b6e39ee54ff95df21148b432aef9527615529b74106e56bc08dd" },
                { "sq", "77f3287f728ee7196a2c55a008e98660f8e6e73996955aef120b754e20462c07215744c64bbabc2c7fc1ae5fd94441076f13293c7865ad6d2e29d2cb5cc068ee" },
                { "sr", "492919fc3c8a038da7966f4e5d52bc397cf59b07a8a66469a1732c57da454fa406644ffa5b25c2b8fb2244252c3c289326a5865716b2a48aac734bbd9ec00684" },
                { "sv-SE", "21e19bb17c6c2b9f891caf127c002836c6eaa3297d218a83b577e2c8090a3fb1e0c9d7f0d460aa221a27d1f8484c85078291c012a727348079e6f054aad9151f" },
                { "szl", "1fd159c5e9d9b5c4ffb41e9656fa7251b3e6190b729f5198d3ae1469bdd4e823e351ebbfa9f141ddabf621b8b8de36301107313d4f4d4a1b3368f27304ba1a18" },
                { "ta", "0093a27e89576cde6f26814e2514f9f5e9cbe5217158a6964b69de5c2c43c31c48babcf6f97e9969acf3321ef20dcad7095e89c8b509f0cd40426b7395006ab1" },
                { "te", "0ffb15172d96da90faf272e7df435fdf86b82bf1b12ca3248213ff0594238e9d811cd1b6f17e5a5e9a55942a9dfb233297b41625c73c295a1b6784953faf0093" },
                { "tg", "3f42b20a8a5c6a21157a69aa5c9a170b09005544387ca47f3f11b6939d61e734729dcf282b8927b466e3540bb4468b1df61ee89d20ee714f8af6a9e90fc1c6ce" },
                { "th", "e4affee056d38ac64d9ae66ee85af7551832951c37443cfe98e2411262b12c871cb1d245689a41fc64d82bde6a13fe9f480e207823eafbe1de0b611277029057" },
                { "tl", "aadcf4cc1d684b6ff38053b4a7d096aa0d5e5639606160de88bd3551014f10d274c1939a74f91250356851faae69a813925887b821b216d145facdfe30478057" },
                { "tr", "1785d6c68d5f59004360d804327bb0413484354230b3ed0d2d6445a7a3c2d679d3a6f1630a8198305397ba3c0734e191028b7e818c232e6b81f89b258207d14e" },
                { "trs", "fb691e139bec001e49cd4e066e98f6bdfd5fc7a34fb9e512b3e3fde705a539bc14ce6c0fc3287760ef0dfa6ead340459a84921131ce9a3a4334a023397e36d21" },
                { "uk", "3f4bc7c08daba543af240c553fee5ce8891e54bbaaf1bf271c204181bfc781259a9fdd741cfd67db460b9e08fe8b5ff372c200a411ce709f42325da5eed4491f" },
                { "ur", "ad6c731aeb0aefa642627789f5a5fe95fcbc4a677bc2f58f3a736197821d9d334ed48e6061bdefb4fbd7bad9135c912adf42ccf8b873e647b646f46b9ec9b9d9" },
                { "uz", "eaf511d1dc2b93b3615979e48fbaf028b81442148308c1a0d1fd26573a05c2675912494f0e9d94e1cbf530150515a38c9e11412eadd7154ef4a13ad04087e309" },
                { "vi", "4d39068194f8cd184263dddf315af7f65d882b43378fa72037a585531f47324c9fa1f856658b4804ddac929c91a1c4b6eb8ec715fbe09d2528885c5766acd927" },
                { "xh", "127cf626a20f5adfa15ec8ac17d1957d043f050e56745fde93e886545af833edf9ed3814c489d9acb3dc43ccd551a5b7cf6f3a14ffab0b614e6803af14ecb72f" },
                { "zh-CN", "74722166c93d40e2d67ab69bfaa2f7e82b15bd1a7225e555a044104e016989e98a113a7bee913ddfd2031e940704bf135933a7129a05ae40c3ab3f50f69e0c2c" },
                { "zh-TW", "5fc3f39bbf8f37f7367cb457110b7934b91ba887e9fc620caacc3d129a99966a5479222d48f320bdf1874d4472e45de886b2146da1b4ae047012852193ad579b" }
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
            const string knownVersion = "142.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
        /// language code for the Firefox ESR version
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
