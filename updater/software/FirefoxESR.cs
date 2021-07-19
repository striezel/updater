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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
            // https://ftp.mozilla.org/pub/firefox/releases/78.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "b58ef4e28176e91c88920a136072d84faa1c029b1ea2be6118278992f95590e7e9e3ccb384a2ca0b9399c93c8b2ad6afba9ea5bd7bf5ba55e93cbdba5e6a3549" },
                { "af", "cd2d17a24eaf5c42947244c3aceda6c774a93621d7fc65caa80e3f6ee8169f506655ed7f8ac662a132bfa80af34bafff93bdc9bbdb5eaa6c2292d58c6ca56b05" },
                { "an", "94e1cc36fa1f6745c56c46ea9f81b29c1672e7361a991fad359e897249671490b30146821f72e57ed2a06caa201aa3c107e45c21ad84e1c0a6c622b8127deae9" },
                { "ar", "6a252bb2252eaae52b69df680b3dfd9b7c8f1a6298fd5e37bd514b782fc22ba650156798a7b44e42eb70d9a1c29e14f2b00b0589e7cf6d67fc012bdadd7ca8f0" },
                { "ast", "4038dde17d777b7a0ff37569599a1516a9d274d796c3058745f3fd2f652ea3a3a93c0a20171e4b1df89db2c10429f3a625843fd983928e1b413828dafa849d38" },
                { "az", "dbef5674819cb5ef9f25e5f1d5d1b6f365cf7d60fce20dba6b31c80d3275f03a71e1407a0820a470f9f1a3a38cc30b8528c24017e21b85d9d64d85182dab06bf" },
                { "be", "0bf52e8d21ced37f01f495cc824fa60a521ddb101cec97cd9fab4166bd5729d9df191ad8e18b9c201fefad350edbbba9ddc78f214bfd40401fa572e157fbbf24" },
                { "bg", "e9997f9641ece17778632d5aac6cbf9d0055523a2f6cfe7a9dfe39e88078caaf6f8cec34de310939c106dd0bf7cd889c5e60c3d730b0d2fc273fe3d1cf1d2a0c" },
                { "bn", "3e0cfb94f69b599a509549b0533b6ab9c48da36e7aef936ac4566bcd07a5d9511645b795b1ca2894036deef61e5c4bfc6b008e99267c6246775bfa4e5f5f19c4" },
                { "br", "7368c0728bb70aa13d59082d6a4ab336c67d188ae7b18c7b9273fb6556dbc2d63b6ebe9fccc4200285ad5ed33dba3bbfb382fd5a893995759e4437f47c14c318" },
                { "bs", "bbbd1579b4b033146523d9ed1537dab35adfc00359cf8a2318bd8bfc98dafae276d0bc98913033ccf31c510ad23d19c536a0925a1216983205080964f945609a" },
                { "ca", "262af8dc2c2e4345c30c12b406cabaf32510e91395c00b8d897941d97e0413dedc1ae05880a9c169348b0a97199ca2c709dacc0d9ba6510edb82aa341f1a9930" },
                { "cak", "09f3baefc76231720ef725bacae9c3422b19bf97a7dcc08dbe0e7cfb10333c0965d9a6ac9e5efc1a6aa275367ba032d4523616f01c9ec0779565d58b80ff3de7" },
                { "cs", "0cb98733cf6221e3b64a8b296e49c04b983dea429e8fc4abea7ef5220a556731c8af5020b5b03de6486e162a9bad4e87e919fe6da2cda0be591320d7d6de40d0" },
                { "cy", "23e3e622c5e67f0496234f510ffc81dee825c0d528dbbc72b0f7e1dac583609b8430a9c2eaf00a8decdc9c095008584f50dbea4375039a0461254803f259af7e" },
                { "da", "4c9fed345048b1fd4cdadf176e685bdc58d36242fe721fe98ed82d9b8797176e8572bd3ebed03270937619c1725eef796fae964e8979ab41951b861ec5446382" },
                { "de", "14da31f2bab248ed9269834011f39248cb048360aa4759467972d97e85b79dd273a0470d2b6575c11a9b0538dc848f16bd1b5e6b198d278ff8d08df2942748a3" },
                { "dsb", "b1b61e035cdba64d9ac818b69d26941138634db37f2818ee26bfa72cefe7535b772bc62b3ef80a42e3ebcb54e9ae2b941f16b46b2ebf83ce615ae51b1210097e" },
                { "el", "4a90aaa58b2d437a0b386b93eb5e5e321fd0cbaac5727235bfb1259f756a148f1c5a33e428a9a5d1d2afcb6a66502281bf36659f2d71fa6de05eeac451ffafba" },
                { "en-CA", "124832fbb9943b94edd369cfb28c456928d30cfb6172651b3b01eb290d401b487a27e73d3a450f6d4f3fb7309f3127a7fe68008815b3303d614e68189568764b" },
                { "en-GB", "fdf752195adca283dd387b68cea40445cdce16b12e0d2d90f36b0cea3524f719e3c431a565b0c5ee923ed6ae49d7d277b9e54374fca2471c074506450190678a" },
                { "en-US", "3acdea8a7cff34fe6f3eae2d1949bfaf371682bcbef6f7632a70535bf5c54a029e1028f98394afef819966cf2e9c6d7c54d025eae1071d2f88b1e6668db47614" },
                { "eo", "db226c7c22cc53fd53fc44e8cda571dfedfddf23655374656e8d4604c2b6f3c88cd5ec8e3914c97a8b2204eaaaabc314a232ea51818d706c8b875ecf2dfa2eb4" },
                { "es-AR", "511daf2be536a47ae66b60c178439e1e4b8a10de5cd834363810f99ce4307d301d54314b5bef6de455ad984b8d4a31fc906c027db8ef44500e064d6b720a21cb" },
                { "es-CL", "363051c056ef0b81cf83e2a6101b8038d4e3dad3c218330c2e46402fa0973b2c5f95a2ce93700eee309bb916ace6cd510e139bf887309f2b04754b705c20bacc" },
                { "es-ES", "9f5d3c3e65ec17c4769e7e88e027833a0a89cd47065b6fc8569122b6f7aeccda6a4037f3ef194f6e1d0b4fd02fc4745fa48acbf568ae1b78e76d4338efeeb28c" },
                { "es-MX", "fe720392a52c99d6cad9aa2170fb7854e69e0bd5f942cd9b8e30f01be26dbc4ffe8236da67c74a8e00494c0b3f7b0c852a77e958f93df6ac849dd977538152e4" },
                { "et", "1a62556182e6944ff26cad71bff222511b7a161f0f218ef0069279cc0910142414979c875e8412cac484608b4d1417f7a374bfd18451a8feeb737c803d143938" },
                { "eu", "0e0cbaf06450c8a8506f0a8cfee554ff8819f314bf08c3ede5642b2d977f9ec79efe4b3aca399e146c647e1eecd9a8d8f5b4054865de1b91145a6d2e3babbe72" },
                { "fa", "d95471d5642e7a668382c576c1489dc114d1a7f79f2164429de2630bdeab3a8f2e4cd97c79d30ad60359aafbf546d43c16ad843142c9ea6f24f5d0321db023ce" },
                { "ff", "e62af848a502b7b0dfe43c32baa0be5516e50896895b546b86c2bbdf5e3aedc8bbf5c86328b14b5d7f35e0bd5beb6fd7e233a3eba8fdbb324d0e980a7ce005e9" },
                { "fi", "07bf141d7973bf81a50a8a8d7ad7c4919b6513f8550eb4a18c6cd61bfbeeecde0db24c664ade422ed260677d7d668b879e0240c997ed1b2a087870822b9d0054" },
                { "fr", "fb4f14f3708cb2f9def6765bb09a66d6f11ac4f012e613361b1596a958daa672c631425fcc2caeffda06d29542171576d93bddf1264cdeaa70ae6fe441be83d8" },
                { "fy-NL", "0d4fa1b75b9908fb689f897d94f78c04fad25f2fa1104748af20048bbfa5ed3eb536cf62d28be47a21a2a7cb3be91aa893f9f6a554f77db3d0103609e2596b53" },
                { "ga-IE", "c2958b1d0d33b7ab9a90bf547062ad3f220b4ae64fa6b1a4048d12cd69feea964fdaa273b4c9662eaf0f00f68c42670c1c6429f08ea471bc839a5d07a66af52e" },
                { "gd", "717dca6e3e7a73e5864cd8d5d3979b4756ee2d5a9edd6ddd7c2fa179a94000f868077ecda60c3b3d520a5c37130209ea5f4d4b131deb7980d3a43a7cc4589dc0" },
                { "gl", "42013fc05b0c2891e1dc95b54ebf1d328aeb7a8e0df22bb76182f53d61081044c1b373cf0f654415777392c1b0b650d65bcab68cacae2c0ee6a3478a144904d6" },
                { "gn", "38408b1d0dd64665f3d1e8d03a4bfb54c62f00879b05098506d20f8f584bf9b23ef1c8598c7b1465c139a92718c8d4f1e48fd1879a6beb290d7db7074d537b78" },
                { "gu-IN", "a07de900fb1129ff20c574c24b41b1b8c70f6b8eaca7b1033a05667c43ee11ca99b16be138504efd6d0b6c28af0e0c4e93fe83d25a2c83a6129c4070e4f2f0d2" },
                { "he", "82d50b81a4724801581346066bea07955b7daeb8b56c828f17c98c3b5584abc2db55557c3a1e577bbb608bfccf620954df5f2adb6f562a4530e7ab6f27cc03a6" },
                { "hi-IN", "080485e26d9fec70a42d2bbf0173065c43dde5bfe53d8e246413957c047a4449a2cc41730fdd38651323d82fdc0c06418fd050f6aa3c10d171642039fa169f0c" },
                { "hr", "7739f5db9f965da21aa72bcfd58a40bc74b0f06d9e2e6293d72e55a5e8914605d6611ee179c7f97a23d30d153a9d472b5125aa791679aefa476c583088b22fd8" },
                { "hsb", "b89d369393c467376b88343a9a376758a4c0d309ce57fc3e38d9e6f8b78388109bbd810d2dcdcddb9eb0da7364a1c26bafb92741beb79aa0a26efd9671ad7a8d" },
                { "hu", "c6af554dfdca0e2dd8cd1af0a9b6cc4b097fc9564f34adf05b9e58ea7a23f131bf17265f44da3cab11a0143637f9c95f70952d5e50a56c2c9fc9707c5275ed85" },
                { "hy-AM", "4d5954ae63c83a2041fa500e8c31c39c730c97306fac41f97fe4844af009cd41379b3ba2bab03834c41b51e115f7c2e4fc067eb2c7911cfff066cfbc662a3874" },
                { "ia", "046fe97f14df46e9628c05b3d805e9d221576de4c7126a9fc17caad575ce28f52c80b682cc181fdc13aebdfd484c290f7811cf8352e5fabffd3b0bd66662f106" },
                { "id", "53cb7925d3fb30071d19fb814c19ec6d31eb78737366d5d80d981974ff306a75caef52e0828904af27ed225ba1a8748a1c2b8611c521417be510110fc0343730" },
                { "is", "7f5a454115da8a62647127ddde8ea34dc4825740d47ed41fced729d088a9d43f5ac13b580676dfa5ad9e357ab5a9a94e3afcb7b4b06d8f540d4eb455a573da7c" },
                { "it", "7c5140892a66c228bd6d5c5a6b2ae97fad69930cfa1825206e50527478f9aac6aeef62ef476b19dc60a44622d88fbfd321182475aa9e9806d117443d6b03a968" },
                { "ja", "b252e3bafb2edc5c8206b6ad59cd55ee4f523e70bfe653e7b8ded58cae911b7fad3651a5cb314c52126d56fd7a3e878d7aa94bb19e95bff93592c0ebad0ba186" },
                { "ka", "1377639057fd2e6e72a587c8d63bc85149fd5a14dfbfd9558e46a3b8f474c7ad8938b2dfb5c7755f3c12c0a80223d5969406369243f3fc0380fb7d793b8b2b18" },
                { "kab", "c2fae7abe40c3f8a2ef7fe7cdbd0172d5f40bdf58ea94f477fad1a297b7040c8e77bc09cd8f9f907d66125b952b5fc5e0bfba447c0b18afe177385abb5b855cb" },
                { "kk", "41eb246bbc7ab780993ea09f06b11c387d10e34a89fd9e7e10dd937db460fde22ca2674f91e82d6710096e1c2b2bf4e279151fdc1f91e9ad313b28a23a22475b" },
                { "km", "2dc0bc9546f130fa27ccdfe7c955c002f80b9e76284aa406bc71a8838acd13f88b0a89e6bc36acafc60b408a35039e29e4b4adbd0aab346a1412e85174588529" },
                { "kn", "1c12b3bd056a09e920923b48b0c3a1bc3dd1276e00edf1302475b91f9cb39cac79c8b02a621ecf285ec0670c0281566d9b9afd681d2a12919411dc1e9744d5ae" },
                { "ko", "e35806617a0034b627a904eba80396d53637e3af25038d1a0416461c978a08fb7583cb7685804ecc6c46eec846f74b72a39d1806ef84d81ca2b9ef599f35b29f" },
                { "lij", "a3304e6002d11cd58c4ef78175661b82e0fabef95c009a868798a860288711654e8cd35076d5dbaca2063483440bd967b303d1b7e5219646a7636819651d07bb" },
                { "lt", "8069a0606991cf23fca762664a9ffb4b89e3e375ebc76271e62c9aeff9a68e5e62c6fe73a7f19be121e5ba35fcfa90fe59929b131fb35221a1634fe4472bc2c8" },
                { "lv", "82ea07436e546049f14e55a50a41847462d18fef0284f0c0786bbd8cf4bcc9b13fb4fcba4d0117540d655f79d779936ebf3c2053dfd6263d844d8ab0a243561d" },
                { "mk", "94811acef6f6bafb425478957d82719176a966eadbb6fdb031df37b06a5dc84255d6c3ab91e2d907b4e8de19e380e4ea50610f70f52306a886a80335d530c253" },
                { "mr", "76a5655bf7b1985c4e4b79a5e74c5bbc4b766124b19a13b39028b6c7ee2a5f23c4f88edbe0cca2c43c1693069ccd20fcb06a8c9781263befabbab081a42481ad" },
                { "ms", "f479f64b3cb79294bb2c0cf0c39f3a6093b72b0b877eb8440aca202ac9316b0a40161032b495749b4024f46b55181d499dfa735acb5eca7f7ef814f9b7f33d4f" },
                { "my", "7b09d13909cf0a47601a7f480431eb5767208ed8c4cb329ef4bcb4574c17491d75cf70798c7900f2efc8ebaf50c881ca6f95e985bbb3d3e5ba0bb1346a1877a7" },
                { "nb-NO", "c26b5963cc65915d069e985ad711b268c3d24978d6632a08f4000c9c31e03cb49920facce8f49bc407846bf689927a64d092351f5e0f50505566ce10781d96ef" },
                { "ne-NP", "54af99dde825476731cb507c77c44d1a69556f05445e9ad0a649cb338085f26af4df86904c3d1956d419b2ba1b9e1a4d7ae8f42ea2cd50d3943b8a58f58bd961" },
                { "nl", "11e350fd35f6e71b57fa457a67caf9b5418d678ddc5835a52f5b3871dadbf2f18c4680b4ea75f724912482d46dee58b86336cd6b7718d407ccc56d5ab694b7da" },
                { "nn-NO", "52b0f17358fe5c44c00e9c883d3d5e1ef8d0cd7e04d233b693d1a1aadbdecafdaa47140e88fc062cc4915e748e16d7b22732e6b8a0b177dc2989a36b165691ae" },
                { "oc", "53eeff3caee83e48572716ccca535e3a1934fb7ef5d0d4d4ed3ea8bcf1bcbc6ca37ce3b968568ff7c9f40898830ff12f60d6d0d14da38e95696197b1459473e9" },
                { "pa-IN", "4c4a6408b6232454081bd3bfa1e985b7994f51a776a6a7319745e1ca606864938f7855f6c25c28934120ab42076aece6ea3ae30eeecb3037ac0ca8fe73a885c3" },
                { "pl", "87d8ecfe8792bda3552e3164a1218a4eb7eed43d1db3496cfcdf15b846946e105b95ad35940a048ced1383dad0613fbb375e9d935b842d41423b1c50fd4673be" },
                { "pt-BR", "1e13df715e6bd2343943e2b490d56355a8e96f6f93783e8baf2e8a4d4678cd30d75e04a29d0ced79e7e5ab57521b35e47250965530ab8cf3d103669b9f0bc4a2" },
                { "pt-PT", "46b1aa726fa2f5e97531ae588ea1dd128753e9850924eeb98adea18b954704877548ca0c38abaa8dca2c35e04e7f30827595c26161147a99cf4c48b795703209" },
                { "rm", "dfd0743bec85ede27684a3e7ac77f555f276afa1ea614d5057f9de016c11d2cc9d7b9637fd14c45d1ad6f3f45ac67c30f8c650cc0319aa12733adcc09ef19e9c" },
                { "ro", "3839d20a87ade1772005dd8b246f3174d24417e583ce67a7455a8291e331bf51ac1f69a8d6292a00ed2e3e586498fa3871bd8f97703b532eeefc8a564b8b1302" },
                { "ru", "3b2cf0cca2c278825d8b230b7b7b5f997a1ea4a50eece5a13d1e227298a30bd86fcbcee428935c420ce4d48a8e1efd3bdc3e58d36bbdefbd14273880a155baaf" },
                { "si", "7036a7f8ec79b079cf149987321d6b11d947ad380d17358d924b1a374920d89ae9c7306b43f56e3676fdc0bc075ed3ec69d97de501d32ebbe878b079fa416048" },
                { "sk", "5ef7ef1cc9239f305e2e1beea7a3644f981c11d3d27cb679076ad419fe8c6c90ad322ed810e1b9eb890508f984a68ef17516bfe64eb79b374ce69fdd44e1525e" },
                { "sl", "b9a2d363d201c012e58db273155e0bfef2e51a4a4aaefd85f22b63de39bd0bda3a151d7c879d72078c5d986a0efb5d49e7fa762ff4ebf34b739508d079087417" },
                { "son", "7f6cf51f888d2d1c06f799e7e0c9887b3c5b6940ea52432bf6216c360c31e99e7c33f0785424b79c6c02b03e90303bb37ac8dddc99186c3299bb8ce4c1a96e09" },
                { "sq", "3d8817497769f4a36ad1d512a06e29bb48ee1071d1bad80db40c94d610dad5d266f24d2ebbc22b40f5a110fda037e7f39c460ed0e35ccf7a6ab42eeeed7b33ec" },
                { "sr", "87f700a8ee8dc49a2d71822b2569244a028f5599ea9e234e5d63d779bc42cc21c70ba0ad7bc11fda3cf02a8e13243962a3f03a12f7cf9be4c1164c2f22a391d8" },
                { "sv-SE", "9a8d1c852834930a860de30284ed98463a8008565df182650fc81c65ec97365e8790c0cab4ef6eb64337e45f5db5574dff15a8996b837690e0f8633d69535aa4" },
                { "ta", "c8638d5567c0a63b2051bf6ec147e4e3dee4883dacaa86cdeec09684fd264c23a3d1ee205c6fb84385621880ec9e420dd7fa3ac6abef554b6e623e966c56685a" },
                { "te", "28edf01323ae918985ca6d1fc9f0c3cd98c7d993bd14c49785e44424217cba9ed4a37ff21052a906139f64a846acceebe716014b09c5c0efd1cc4287eb965dde" },
                { "th", "dd83d439a81d196fdc5bd4c11e891c198fc03324421a1c51b5910ddbc8da0a639a8adb931dc7679fc43ebafd6247d583f0fc39c1fe865ec4a06c0ce93efeb12b" },
                { "tl", "6b35b3a9494dfe9e6683d56b6787a080c5acc134b8a515c1caebbc8f6df505e0b1ecf94e7e2f6b9a9dc10be2aff3a432d6689da251185f8221ca73fe613be34a" },
                { "tr", "5824f20d192cf8e590a412fcfddde2d27d33d82ed03f018f2e140ff80404cea7ecda112b8cb54275207df600eee45d0b02589b36e6d0db76298b5e8127c46e7e" },
                { "trs", "d1f18f795be929ba218b429e1fe92cc10867794192caef045c4d0a9a2cbdc707e5e8457bbd79541561121f91039fab396fa82a724e8999de9b85e5582037435d" },
                { "uk", "dbc727a1f1f3bfcd6f8efc7046312b9c2549a09316eb92bd97e72cf3159d4bc6f5f11dd0441716f07276c153ed68c954e9e17416b3981bcc80188f8618152fb5" },
                { "ur", "7294aefcf9dd523aeb92d2f8c5477e18258fcd955a7c60ca328872d0f0a1438cf1c5f7462b37326cd1b450bb3e1d12fff7dbd39d485bc7278fdfc3af999eff0b" },
                { "uz", "379e4cd266022b271fccb2e29aa45a6b1c7600ace4f3478d1c89021dceb382934c21d0944546392145a054bbc9b9a16f60e4d7b6700441c255db8307a55665f1" },
                { "vi", "485b8292ba46335875b1b6395bda6d6775b8185634449a3320bd36eeadb4fa928e8a0824798b35c849493d1bd3ffbc520b8a73c8af8064fba2c56b6c40dcb3c2" },
                { "xh", "a48b4eb56463cb366f56e54ba5e717267c77d7adaefa08fd8ac93bc6c355b2344e9557162dd42d360a449b2a6a851ebc87fe81f47ad584b073105df41455837b" },
                { "zh-CN", "76d8a95fbca189c63371526cc27679ded5a9168448c70acc3bc22d6b0f3058afedc223cfa46b5ac514b35b2c828de4d68287e258627e6d647429f27a26db53be" },
                { "zh-TW", "6eaf73768a98e11b98799e87a5d45e6c5fa7011e85d80f9872412d83df863a9dd94343778420783b0ad68da1d862e7f9968c385917e2b96550c1a4a454e7def7" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.12.0esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "e89a956a6c4204142ef5054966ae3548c2d71ffdf050e3ec53afbdee08451f7b50aea5837cccd43e36ec92f0fc22474ae0e9dd7235059decba418d797c9034f9" },
                { "af", "9fbdafa6f4b6adfb18121fa27be5de270f5df847329dc5f2f47ca0e49692605453f63d22eb4a2cae4a98bde7e87f0d28390b079abca4f0d5f2ebda4553ec9147" },
                { "an", "5cac6008c75dfbc9dddb2cd56b4e45897054d2e5aaadf2338e4d9750b7ee6eca02b092dea9216942f4fd1b8e4ed44d0cd4e784cadfb8c26f513672b4e7aebe15" },
                { "ar", "45545613999de5d967917660e1ac179e65e9ca2119236c0a2ff12c0dd099ecbab5450deafb3b83d79c756669d05e502df7195aed03b81530140801edd694eff2" },
                { "ast", "06462d0b858332d2c54b0b59f28c652369dc2e2bcc89e6e5e802e301d7d49161392e7ec7c7861e2ef9fbbf5429fa4dfbf9ab8d13cf9a0f01dcd95d3f01b0638f" },
                { "az", "d9eb85f60fdb4bc63f87f66bf1d574baa200c4f8506eea0767bac4e03efd97ffdebe9796b820ca0a591c4037d8f11eb828685c391de20071d77e96c1ee4fc63e" },
                { "be", "a557b3aface340942f2a50b7a855f22ac982f05ad7aafb7af9513c398343db4d631f51494bc5afea9f885c099448b7a0fd3fd88b8be4a017ce0fbae642e3d607" },
                { "bg", "30ca889b93426a960248356afa62a53aeeb726bf5c42ead95456ba9a624f189747de031ed8633126b654be7c2c6dd406a6377090cc382c29ca8e2fbbdb90bc35" },
                { "bn", "e09ceb01a553b9e2cbd2251e486dbb21d618bc6576d71d838d67aa4f1d797be4b056e0225062e14529a5f2a4c0b017552d9a912ece8a328a2f69fcf9e76fe456" },
                { "br", "d981510f14bc4d763b6c1692835951044c5e7dfa8293cf0e8e10674b9dc672e8b0d3896a012b6d315255b072b6754e4267ac4471a3334cfde26ed2aba03d2c28" },
                { "bs", "a9e7d8b34cfcbcbee7066ddb685303e022137ca5ed147bc3ed6b70ab39799e003e3457f179ed1e4e262add009d7082454233da2e99f0918ebc9d4ed1e7f95fec" },
                { "ca", "a45753ccb5f89f20994d4bd83308f467f15012d174465f82184dfab21a3bad6ea0a4024d6b6ad07ec25165b6e048202b46680e6f4148588e33d5201c101582a1" },
                { "cak", "6a972c6f77f2b6209fecb8aba5249ac8a1fe64c7934e8d8d390a205bf14f8e12a542935b99bf78526a3928606f969b613fc04c714b54901267a11b688e8d10fb" },
                { "cs", "60c1279f8e748058dcd10a3dbc679de7f4c4b9a230510ab751d359121d8adb02a8b4867198442e449ddd6ef47874ca9166d97816f3324715999e01fc158d9a79" },
                { "cy", "e5ce756a58d881728331f60d27f9a74420ea336feb454e031d2e4b38d7d38753d4a0b18133b8205fc7c9d74e8ebc917b3b3ce568a6c4c0ba45cdde541985a0f7" },
                { "da", "53a6a9eb59190f8795b70c5f463aac3b46774964eb16f7ed46b4a4ea3c92635f82b7f24a69695ccbfdf71ce824f84c374c620cb155f2247208c1aed8a9984db1" },
                { "de", "ff7e024192011f4e1e96e249d44e8b59afa0df5f19a65df1c9ad4411f725633377c4d3960208b939405638db355c23c5a45b84869132931eb06d716643e4edd7" },
                { "dsb", "4085a5ca1e9ad105a60c714c28aa1ed15b5f79954869ffb67cfaf99d2a34d947791436502a9229d80175b817c14e7b8d57637dc0ea6b511ec46cefc431c42f4a" },
                { "el", "4f6c1c2005800ef87e8cc3f73e69d696fa52ec75d77c8f4646a435ef7deb26fefb89d3838bbf895c03e82f89232c702b6edd758156574abe1342ea0bf6ab140e" },
                { "en-CA", "c24a71e7a353c2cbe40024879406b0ec6873fbe6715431dcccd012399880df42cd65c82403060a237354fdab8a70909b44bd2f1cb06c33e8981b3a15d7d41da3" },
                { "en-GB", "d5c0a9e505e19055bd0b70dcc6c44df4702734d5058b2fb761421dbbe186df106292d08fe082ddfd814c28000cbdae1b8abe23f5a7cd716bea99d665fb703207" },
                { "en-US", "8b3d545bed7815f0003e7331f92f850b167d4d891b0864c0f3db13aa41712613c2d3c1007d3ef4df4d205ecdcc7720f8e60ebf291424b39ff1d59d268f392512" },
                { "eo", "ce5aa6d05b3e0e08d47d0eaa70e1287f9d28354c63b3e2a6a0b94fe462c5e26094f657c4a3741a14cd96ca5d1eb477b885d0028da8bb7736e43e56aa7f1ba895" },
                { "es-AR", "fb771436248f05927298d839b6d24a37a15ea0bac3bb9f0b6a5d850956b0caf0fd8c469d44b7ad0c31bdf00a73ae6a2d7d4a56ee58a70e2e5811f6987bff6cef" },
                { "es-CL", "76f6ed19096f461bfa4a5a0032cafc1f918ee6fc6c4fc98e3acb56c7dba0b410670e08f46153ff9dd2aab7cad0da487c1f01c4443d0c545ca8ed5db060e9d87d" },
                { "es-ES", "5d330d2cfae0e68755a3220e7d2e9bf93d22e6c4ae1f5aecf6b2c0e49ebb74c3c87868e3bfbfcf13259230f8da0ea08271807c3658f81e037be286b2c5742051" },
                { "es-MX", "e570422e9581c28e7e88088110059b59ee16f9ee2ecdffa18cf2951ec8ffd9ac7cd94a0ac91d02e6274569f2c8887125cc88e4bcb288a5640c898c9bb4a7a8ac" },
                { "et", "6de36711386d87799bb9222ac9d8bcccae9961188f11ad4478d8ecd7d054c7a642ca7ffd2350fe4069c356c01ddbbf0238dc2a273cba94075246f4920f62e1e7" },
                { "eu", "587e5b479a4f3b18c55c0dea78c594c3f8cf83d7580bc816eb31508156122b3c26b8c8c8553e9e47c0548a59dbe51d988dcd41bc3ea7baef6666a7b0f10fd5b4" },
                { "fa", "c73bf8b522bda01a5ea64d60a838d3bb39b1c8eb90725eec7497527d1a91030005f85aa95559c61c87ddc9b52db8e5e8e46f48108db7c8a57d326b46ad4a9fc3" },
                { "ff", "d8ef63af28a5a965136119a38284df3495f10fad7e0873ba8b36c0ba8e4626e4409eac066b3596dc6d9f214c7b3040cc28f7632374dfbf3247595762b506fb25" },
                { "fi", "10bc4304ea8d6197159baaef6aac988c47366708eede6f60655e7ab1142da6af66a62b7fe5a0faf493878882b0e6d40e7e67618a01871fb2186e452b52c0ad8e" },
                { "fr", "89a8f1726e3302133b5a1a05b6365fe59e1a66a084cfaa588b35dbfef9ba2dac73c206513609ec8fbf45f6e47e876898717338d6c7319663376398aefe7922e8" },
                { "fy-NL", "51a926b15a0e35bc44b8399bc261ba8f3d2fb85ac6c482c840656929e97025234f74e3f7b8973025fb45ea27b4c9c6e6d8d8785e7264cf876fc78945366b25c8" },
                { "ga-IE", "1f9c78af465a54ec733f0a82ebd5ddedf24fedd2a3a97494adc43fdb6fc182bbac1bf804b07b0544bf7c5c449bcab98bf12fe68db689d06adae6c3b89928fdc7" },
                { "gd", "d6e9ca4c469f5712f4981792cb7ea5b2ea7d545cd87b4ec69c4fbc215e586d075f1a9e3adfacbb2124dc80b03c998eba01dff2253298936f8854cb09cfc87de7" },
                { "gl", "b5192a38bd937e12f5ccf74161c0b5e39e41d68f0a4f4fb748d85911a25310ca46ecf2a1ee7604b010ab6b366906c7c4ba47b8c1dfb1f07b151a25da92b88460" },
                { "gn", "d90f0d97830dfef25198e36ddf0b0a3a4993579df403acae771a22ef2b12ecd035beba23ec25959893c305e847712db5fd2f7f73ff770dabe2cfcc3f44e88665" },
                { "gu-IN", "35a2a23adf4f3687d525e4a9900478bc64a47ceca4bd75c3a69739a42f3c123c25db7e2ef140633c0133e1a796849a3eee99e676d3e29f17264106f2c640e410" },
                { "he", "4efa69404af294710c9c42e20ebfcdeff4135756933fb72104e074423cf31e62be14005ea34e606960bb4e4624fbccee445b4912d10e50ead19aaceb72f38788" },
                { "hi-IN", "07c0df95b53d0069097e4bf81c39354827724600ec70aff50ea69e5405d4a5a40724f853a321bb4d0768f166baa29b38af87554f8f763212e1b2a1abfc04c2fa" },
                { "hr", "0a7bd78b3e0eca7cd4ab4a689c29d2645b5fd428db971955cc58713781ec543d751cd5f61155993827e6c3e36aca7f6a28729cd17fdf3c451f02311441125b17" },
                { "hsb", "52e84dcb91d42c5c23605227531dd4a47ab12904f0523cded2573a5fe95306e9a51cb4a8c3a2e6558e62b0cf37617857e1ec243a569a535408dc9cb3135a114b" },
                { "hu", "11ce95a085fd951268f3c7f000cc9bcbfe92bfdd96c9b824aee413e56a20b27dd9e8ad3337a35daba238b124a773faab4d48648cb128cf826ae2a70131d36658" },
                { "hy-AM", "eea03059f5fd68d0392a3d5d355e44a8b4b1cf6a8532c48296716cb48500d4407a447acce51d32494757cad4daa32503b262a4c2b30d6bda4a4f03fdc3f5b9a5" },
                { "ia", "37487052c2a7d6914f90e8534c582a64ae40558ee8a39a8ffa2333f4be898c7ba237e46161c7b6287528cab6b1cb3d6ba6eb3d1890d0b77eb3f81c3b910524b8" },
                { "id", "73007fab6a0b7d3857028e65ab9bac7e47af582012327cfc6f59767e3184389a5515773068aa012e619a3dd82b2a7ca7ae191e1654c05ff7fad09b6bc7c8fdf5" },
                { "is", "1571ffdcf32e47fda908362d855d44a25ae9f27eb038b1aa7bec2a21d4d22e586fdd0df0d6f2cc80852cd9ec4bd102499ea8811af8faa18ed659ee8c4d0faa7a" },
                { "it", "9550c33575ccc4ee4e6fe2366614c89fdcff85ee77bc3c007d3ab732b48ae4a02687c632b12735ddba47de3c28acc945debe180511fd3638612949c4484a2147" },
                { "ja", "6a9b40abd9513909bd277d165e5d66fff9cd480c5162e0918385ea8adeef8625b7f118504f9d1fdb4d249b7dcfa682cb6e9823fdd6cb7ce1a07c8255a8f19cde" },
                { "ka", "76e0aa027bee41a60eebaac6207852df06dfecbafd89e1d20d5340c16532b1e9b2dd3bdf9ceed897090014464f58e2ab50fabe7da97b44e7743638a547cf46ec" },
                { "kab", "470db64b7a1ed51d5ae7536aa5b163f12e7ad98fcc24e5c1788a4b141d7d70b87342f774d932c557e2275254bdd668c3153f82e39bd54105d806e6d54824c8bb" },
                { "kk", "95a690552e22f8703f46119a3f2d8f110dfe34d1bc4e29c3716b8642f2d070adb07aeabb4f2ebf481f762d93fcea426a3b762cf01d03930382e2532b30b1d988" },
                { "km", "64737ee7ff93ce1a109d3c19a64293105c2f996cf97841feebeba4b7ec693d96a3c0c9126ea2cfc4a712249f0b4ce6e715db6778c012cbd2b7ad119735c177bb" },
                { "kn", "7ae286fc1c36db7a230350c840383c2815014edec461ba3052782d6d269d661699fcb5fba1d601abc04370da8496a82477b6fed32cacf25c1d2f5087007d66b8" },
                { "ko", "674c85be22468e9fbddac47f4e58663b03541933ca46b77bcf7781822989e498d3c567344da679aa3a28cfc2c94b94d7a28cc464039574e1f5e09dc8e23c53a7" },
                { "lij", "5a63ce74299b2f8414f1bb3acc3af95fef8e5273bed66179eda8c9dfae378459648c4c492f24dbece43c476f6e84a01885687950717e34fa469ac16c96e13006" },
                { "lt", "ceea5fcc41daa22cbe88182ccb02e8f0701f4bab16c520c03e95592b3c9198de2f5232a7664d40476463fb194b0524372dad727787310b4820e75dfc3bd148f8" },
                { "lv", "81beff152bc49c4bfc359950bc4a918d2e6b9655878981bd78255b7210a79469e64a9d4951955205df24357bd618b412eadd5263f3a9e858d888aae39cd486a3" },
                { "mk", "c85e9b888cbdfcf47593a1cdebefaf085e81f418edd06c62ca116c5f98bc15b31c124294da4f9861bd61197937d4186126ca510c85b3ecfce5a398a538a5cd68" },
                { "mr", "178d914997f400cc04ccbf8ac6311be0b61bf0b41354544f5056749c5172f54feeef2e3ff792e0d68cbdd7610c656d3575f1b2214879ab88bc7e3d9f6c112ae2" },
                { "ms", "02fe7365da6192b68d93515de254992aa70f3bbf687c42280349b8e8917ecd8aa725b879c49352cdd0ce5adb1c76f3e1ea500fc10968aa52764f913363e6bc56" },
                { "my", "b11917074f5ba1a08fcbe5ada04b69105601b879d317e91f02fe449610bb6fb1a8bc45b5eda415a11470994cc8f6dac8baace4f3d1d929043afde86f5c4d2bf6" },
                { "nb-NO", "47cf4efd5a3874021cd475ec67280a2d553f3eec931c3146eb7ab97f97f464b0109c8bf5ea5935e1671c3458963a466bed29b8fc416c633c3a8dbaf2f60d3a93" },
                { "ne-NP", "b5cf590046a3cff291e17de75edfabc401cdc38a3a8238dc58720f293205c3c70de3ca794cb42f892d8234e000e82ca0ad0292364184d70b8ba57c614cb9bc70" },
                { "nl", "c03fc82e0262a6b5dfff9ba85a61efa22d24646459c43bb4e662d2b7805ebeec011f3940aafccaba5f2a85e819ee3acdb0bed64f7b1a7a87707dde951796e7b0" },
                { "nn-NO", "f920d02b8d00447e81a6b1f0f30dc1840e48ee4ec198dd74b554bef65e4f4c2473b3e238a5657910654e91a73828cd53c182e69b87dc568e66476571be387ece" },
                { "oc", "8a8c46591f29a918572dda571a23aa5ce42b79fd41395a1925d8157d4712b152465f770e2600d0de2daa5827914bdcdf9e5f7e9c5f7116785d6cc5212ffb4b6d" },
                { "pa-IN", "c6c18deb0cda9046e6403524e562d8ff35bb0f00ac335d95a8b165de674ace9a1dde8b6495dc202c42409da630b8df03213ca75f237022b24701f38f775fff57" },
                { "pl", "d89730f8bc4b4c0ecb7ec069b95bcdf3d98ac29a868b1e9d9fcd39b1f6a57bb1d897dcc5ea3aeaa70ffc965df41d9ac280e7169cf5b5f0b541706e7d1c0c4ff7" },
                { "pt-BR", "e9e299e6349ce2283758242d61e2dd50d9b1a59bfecf606a7f76e762e2065c903b2c2f1cccd5babb44f3b2e8e39a275311812d16bd61f33c0cfe2c292b69a0e3" },
                { "pt-PT", "a39889c1600b1353a04d594c361e23e516145d84b6dcc7ea47e9cefd988a8442cf275b71e25ddbacaea30ef86bc5df46985c53b683dd340a801e83ad6dfcfd2b" },
                { "rm", "b1d9c1b65ddb29650e6cf5ed32e8340baca1e270c75f50d184d3a54c45f5a13cd1abfec57de80bccf6f06cacc56791cba292f58561b99a742ae1d4ca14186860" },
                { "ro", "2fcf3d71d6a9736cc7243b724750782271d63dce67ec50d0bba82e85cf792fa7eb008798bb0fbc708dcc371a49bb580e7ef897870f41c0d2bc37ac558553fb1e" },
                { "ru", "63765a23b58c40e65eeab2bfda14990b9b77fc91c6b906f5d06cba4aa2d1f5ac39f1cfd2f8ed2f96f3eec95b3807b0cb7aa36f98f252e69aa3c46034a13c6eda" },
                { "si", "e15b17ca6b00ed269515df5707399f4178f2465df69dd7321cd9935c5e001996599282f00d5fb3367f4f0fb0b811a3d5d476243c07c44722e52c34105922d5db" },
                { "sk", "1e3c47dea3f6dd8d88ca08f8bd9868105d655db23393af512f8a83304d3a627036e52d94295eea864b989fbd8facc3e40e401dbcce309d99a2f430e260f7a3ce" },
                { "sl", "c2c7b90369bb4894868baaa436031bf585546b6f997f474ce25c834f0785a73f9507b278b13e0a89856ed4ecf7825abfed3ee21d08d81e9b5f915c003322fd9d" },
                { "son", "5ac9f86c8758a510bef70864d04bd5ad2ee6681440bc3c00de55481d450376e7a84c7894e742aca86aad731b9600ff5fcb0713cda4c0622a7bc098b749c9badc" },
                { "sq", "c78d456a94bde4b30f11e211bdc702296a58456e2b6062814e82fc045b112f75f75432d43f7b7ba70406f1564bf94b41277fa0c125ed9643e1fb474226413cc6" },
                { "sr", "4842f0a80fa280f53d3fd50845ec7e40a3b7dc8bc51c8d41d603433146fd6105332c9d6f953737d50125a3d73a8b0b2e3a5aa051f877757fbe8170a232e592e3" },
                { "sv-SE", "5e87b7394f3f7877be68b3b85c2d9d9c154e3404f0e007ecaca8d9b56f0a9c07dc84e3484654d45166923911682ba43e7842dd88bc6b56169f22a97b8c33a991" },
                { "ta", "684931cb7a33cac2b0331d7535349e13a637bd23f77fc0331e4ce61379f4dc5d4189ebd22260f48a6784ff1ba9742f823928e98f88d66785da2236b7efc3be7d" },
                { "te", "cf1ebb928f1429cfa32fbb6c351dc857b1d3f0f861d8ebd274f1de7d36d4c6c0b784c355cf3996a14babcab6edbb333bc88d13105d7d6a88a083c46a97cd0845" },
                { "th", "7e11a4fece739f55420de5abdf778f0a5751f30b79374ea5837c7b3637b4008d0df64666455c7b791dfea2f3c1e96a6af45fc2e57155da2369e6b3c71af2c06e" },
                { "tl", "37477b285bb56851730b265d6e6dfc178dffd9bf17bee8047a4f2604ec9d7434b31f4b976f1306a1550ef3507b345b7082e3c66785eb9aa7caae99d4a0c614ba" },
                { "tr", "a5dd36af4f96e2e1d62b842e869ac14220aaeced95616f38e45fd8b07d1324a8c390a0e3efca7af935cf8ea24227003283958666d1459535789cc2ae363b9e0c" },
                { "trs", "22a16aaec59dceced2cc856396a647e77670038e7b1ac717e9aa3c217d1b1ab80ec737858ee72060734244414b44f48e8fcae0f974384f345211fdaa19e5b778" },
                { "uk", "9b3dc20fe598a13dd44734cb63158aff436711d8ae3d5e186498a870c0b85e4d9061b3e235fe45fa17696947f406e92890e737aed646e940e6a7d3d024418e4f" },
                { "ur", "437fb728b77177eec0097d52bb46675015057fc70a13d65fa3f7248b3e362d1ce53d5c134e7d6fc59025c73978e5696ceaf1b0754d7f39e6454e8bd8f96855fa" },
                { "uz", "c72a70a8db8940f6bd2763be5e17f4aa9859519c0529358cbb079d952b6d51414a31fe4ce53bec69f03a6a05ad58017ee9788094adb4dbc1291ea7844c377eaf" },
                { "vi", "0dd41c80ff83e88fcb787dd0ce1e516310d12f5baaee4a98a6d63b82aaeb63d09ddb373fc64128237180a44f51c9d2c85ac60ced18f2f1fd409bc7cfa2c6100b" },
                { "xh", "94fe08769356c8ff19bc8c0dc4aa09a07b97bb1fca09c7b984f4ba175a7c87224479397fab604f184273a86c13eae9764cd8f06f9fbf62c287fa036cd8477024" },
                { "zh-CN", "ce3c637e1c1fba3840bbff37f0285fe201d426685dcfef9ac5968aa0b2337e516fe6cf5634f45a30dcd53df4f6beba2058504149dbeb1523c1a7ffe3022541af" },
                { "zh-TW", "4ed125a25935dc81089f439da6cd8ccc732e54f162a9693bc29f8abb674ab5060d5525c547544ef12714d95aa40373d62599a54d22f22c983e3b48869aa1ec5b" }
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
            const string knownVersion = "78.12.0";
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
