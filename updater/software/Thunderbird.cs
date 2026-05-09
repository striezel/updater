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
        private const string knownVersion = "140.10.2";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.10.2esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "740b3a1a99ff9321a27da2c37ef927e90e606f3842c42a62841bf4f34c7f335db04b277f57248b1fda8d531de8f0d882265e5c712a36be8f1209af3a393c51a9" },
                { "ar", "db2f5a7fe6ae68ee855c146784c7e6a7570ff1877d234f6325dcba554af20a0a1fa0bf943b9665c4141f2b53e9ef21f5c435ec6073f1edd1860ffa6344b5c956" },
                { "ast", "c43571f172211c725c2da08d4dc1e5ff2eb459b7ac38dac1f641b346517bca8d300fd8a58db30b73a0d23437f445f7115737103468c7d4a60e7ea705aa7f1e82" },
                { "be", "e3518059e5d04fa51a29973dcbb63b8b8a2e758c4b7096434d0ac5972d5c4da24572e3bbe94ce74b5dc4a9961c963bab8d3dd630d3a97dc167c9b64990e3f4c0" },
                { "bg", "ff683c1b1630f8360261ad82424eebdd210c6234817d5586951fb61a504248d7620dc17ed9cc498690e5607dfc2eb3f9233d1dfbcbde68a3698f3fc8903639d7" },
                { "br", "0ef8af8b6a23fbb445e6d33acf9cfddefe30dda570ac5797f43f0295f82b921da7dff835a455b680a4af294eefe45482b9ff75943c2a0995bb5f7d31af33d7ab" },
                { "ca", "6d038f6fd2edc58081c073f41e4cf8273908ac86a12e365eac990e23d7f9c020104092a9f45e66e0f01fa05e1b69728f35af36a8babccb9631f40f86d22e298f" },
                { "cak", "7621fa7813990de41d161a5bbf72921576b84b0dc76cbc9ff42bcab0fc5f6b9bcc67862c119af3310e4e783c67cdd400eb4671e259f814ec9c2e0d6340c6dd74" },
                { "cs", "bbf39f2b9602b9a81d8139dce069326c38394b2bf180bfa766ce54c2e1a5a46893fc8300971fb79e0508cf65983e6f5fd6778e618c473dc97a7b66e757520d8e" },
                { "cy", "c13e25a6a1ccd92711892762a2f58ffd006a3c40130cb5c8b74325fb3d8c00c854484038737ce6bed4d62229b8ac9ec65ffe61ab888d7d56476677a2d25a49dd" },
                { "da", "9c5125de761dfa534b5dc18f7b2723da2d92d71f9e68db2c5763d6618fa7ff99f25f0a34a0d2f88c6aef8d4bcb346a3fe384cf3b797605df8e3ec4a9e0049436" },
                { "de", "38fbf89e6362d9c2c695c8ee407d5241a6fc4c7faca48cace3fa7d86e31ddb978fcaf215c3bb9e0ec6ffc2ee0e9911dc7b9e6a21551b63060bbf4f8988d69fe6" },
                { "dsb", "c2d5f13d6e7c58dacc7ddfb6cbaf1a94dc528aa908c2b8c41be16052162b6d876e8797f27cfc5902850dc56f3bff19fe547c99877ce11069b5b80baeeb516f02" },
                { "el", "47157e0b2a5d5c39856656a0e49e29970ad32ca817561f1119c7e393a0d89c80ff5ec1cbe944842b3a5924a0d69d4e9f9201c3d61cef2e55d6e722e793ce1e9e" },
                { "en-CA", "9d284e4eae1c11068ea444943713b87dfb4dd4568822367cd1bcc20b769b3f89d58c96fc19e1d1b4e8ced99da30cccecd0dd6d975c7c9510c7bdc3a05dd37640" },
                { "en-GB", "172e76b529b1b1e49a2e9f7db20260b56316c71701937616629fa572db04c91df13d1123762dbcf354d8f350e1b34d0a2091702d3658ba4d4bdbb4f0e999b4f9" },
                { "en-US", "5ee8b8b2bbe6e8cdacef7b65314c06b21c9491facfc010ad15573055f9bc146aeed742cb2d867ac16ca46f2f424b110ad49ee74cea7f22cb3e521ec868c3e0c8" },
                { "es-AR", "34fd2207d9ee336af35a66136deb534cde8b93a3fe61186aa99d10baa4b9ccf0ad42887444299ff9a4cda7787c97ae5de63506c27245cc779b76fcdb3053bc31" },
                { "es-ES", "c0d543d21e73a6325d4cd7bd4804bc1e3517389599090ae7e7a277c35766dc6b1641157762ee4e0f589fac7920fe85a43944f05bcbf80bb5a288cc0fc88fe67e" },
                { "es-MX", "af59ec8862f1f52c5a7bba3f6e2d42515b76334501a08a4cad6722f88493c7f31fdf463487207b90322cf91cb6b7d0fc37b9f8686933298c4be163a588a419b8" },
                { "et", "a033e8949d6b63b9043d07affe42d28ca83fdd1dd54522d128ef061fa464e84613433c913289760dd42aa9f86d9795707f5f0ed1ff8df00cc7fcd12f74d955f2" },
                { "eu", "9092c8a75305c47b4fc7daffa0a01cb20fb3c5446e2c336e54edbd7495bf3d49fc4c6736088b39745ee911c1ad3c829eb87db1e8abbcc0891bb41e747133acd6" },
                { "fi", "bfb86fa146e374d41aa7a6146d76d978c3c3972dfaf79973c9e46986f1224582076ec35a6a03db5c63e41049dda046bef53f250cd51bef3cf9f6077af0338d74" },
                { "fr", "636fd3bdd5a187cd948672781a139d7b740c0d57a8161b1bacba0adbf46c69b53617911949c07f7402455fd6ae6c6edb4805ab7096f8b15e70e7bd0a37cb123a" },
                { "fy-NL", "2f44799c89b95314fa834ec873b8aa3c8acfc2126c7742fea5acd2a71ed00eae7db365be7e3c574e6b7fa4b940fd3a537bab787cd497d165800ed024a7622b44" },
                { "ga-IE", "3addc0df5a449cbd1ba7b09e0915650396c2fe627dfade3032aa5592e38b2235d76a57df59a52888838b6d811d18497967eb3c3b23e76bf687caa7f82bdce922" },
                { "gd", "c071a0c6105ba2e666fd714ccaf1ab76daf5d9973317c16f0f88eedf462e828782f3c61132816b013785c687e252a27e42aa697128bed843b660d5ab4d046066" },
                { "gl", "848f158f4c091c71689bba3de83d1ae855ee12b3d68151793b06c9f108f619affe70e05b7b619f68b2ec01ba07a5e4ed67f3ec718c52f6937703a48d9323b367" },
                { "he", "7d190c55c5d92b9f026b2200bf29c8c5308a4499d6c64a3325261d8d02f44eb59ebd37ebc50637b041db21eb228b1c18a982595ae2cbe40a6ced3e7445a103af" },
                { "hr", "b9590de88014c0439a88cd7839c1802ab521bc929275505773c1666879a9cb528410ccff4a952315484c3239a4cc406522ac50075a0ec7905bdac31f9f6a4f96" },
                { "hsb", "cc1a68564cea2efa8c6d75b31c92859e2f4dedfed468f77d804eb14870978c4ad6a90a9446244da76a3f86cf4dd9567e238f7657d94398ad05c1549d8f0d8fd3" },
                { "hu", "aba8144c36e532fa2d59e92da01c3093abe8211067f51893b3592b4c2ba7c0e1cf21fd00f3e2a504606ed4d74f3dc985521eaada077a0b43afcdf367946bedf5" },
                { "hy-AM", "c3e2fb15931b8c2b85861b0e8134c5a98e6fdf8d4f6e3d5be09b66d08483728964da159f5574dd2116f79479e7179ca7612eb04747b0ad9aba6c3ebcba45d1cc" },
                { "id", "6184ff8fd720c3864115b2e2a17540510fdc1975c6c84a68bb2143ce8147213979fc80389682bf830aab967e2aa426ff828375e2c491615663fda53cec1e794a" },
                { "is", "b8c40c48653e86836bd5eb2a45bec841eecb2d8d145c24582f47f816405518f389736de2024fb6c5d7840757c36c6f0fe1bc9302bd883da075f37e94eb678b7d" },
                { "it", "58f5819b14662bb1a0a74b264476188147df722fd373918c529c69f63c0df9cda16d3c6a02af0667013e1bd608a6e306a19c57c22dc1a1bfd03041463bceb851" },
                { "ja", "f109529fdb3ccdabb0b3830678f3e06ae203983a67e5595c0e9ed1cb581c2e29c45229ede5bfcb401d10f09d8dd05c5a1cba3f2c040bd26e133955276ea6a24c" },
                { "ka", "3bc7d9131954186e421163e61c179c2a5b684db0c4c5309fa3cc03fe6f2e57f47f7ff87c1ca73c1f6331dab9b8fc7c5484feacc107bf50485ec88b721b0930fa" },
                { "kab", "12a8ea05429c0b4a1f521b239b7cfc668956dff788218689af6ba76799478713462782a58805d7bba06ecb488557cb4a3761e892e96dc5492a1eb69b37c1bebe" },
                { "kk", "a2556d8c160f8fe9c98d0590d59ace6a3848787af65e88cff9dbdd6810a912b9f8c2be3aa6dcf4384be53d011ff98c75290bd97d2b2f10e278fb956dc456ed6c" },
                { "ko", "ab0732f72463c92b6ebc4837f2748e508f0712ac254ce5368f3683cddd00fe1e0627eb2f575760acbcdaa2cb5054bb241485918921532097254a71c5e0651ea8" },
                { "lt", "a292c7a1ce362367f4d15d11e4da3f65cc272b1e09c655d7c98be832a1c9cd14f9741a728612e5b6a2388ce6cd7bc5a29d9c02a6cc99af7cc82df0c4558c0b2d" },
                { "lv", "1a95d418c6c5a464f1506e2b4c8ed56339e12abee895955b35e34b638141bcfd71f0aaec2d495317c8e7e1642933c5b0b773e16c07710beb702d795bf1aed1a2" },
                { "ms", "310cdddcbbca325de0358570fae1dfc0fa5af1b9531b63716cccd98351a84124ec54bd1e925423932913693d768ef66bfb0a9d46df5ca102e19924d0de609b46" },
                { "nb-NO", "86543bc38d2519b17a38e508048ca49a83d924398dcd64ec61b7d4b2b5aa0583e2e756c283178bd9c2a837e18ab1590e809bfa0dd5acc891f278d827c48cf5f4" },
                { "nl", "da005890f2bb9b8ba80b759d48a983342fccf232ecf5c5f5e9773f422bf3eb0a58b788944ccba58cbd9968947b661e0f59921d21a4aaa862e39850335336c84e" },
                { "nn-NO", "baf092c25bd9bc6201230c200af939ae1384afd22a157f5e629ddcaff0c83dc53781f6420d2fe08bc604ecaffd4efb98f92ea06c3ce2f54fd9141f68a38502a2" },
                { "pa-IN", "85cb8ec00aba4cabcfa5f271f29bd1a48a8193940997e883c916bef10cea9fcfd001338c7eedc355e9ff4bcdd5c3d451eb16d385fb45e2a112e33f75b009cfe9" },
                { "pl", "4328d9bbd928780fd693afe6d733c63fb569c127b951426022a82182ca03e7ef114d698adb91d6cd451e6b549b47eb0676f717c31d672931cedbfb3e65d382aa" },
                { "pt-BR", "fee407a0c1bd9127c2ed964f262f43b9bf1339707a5957d2a9fc3c38aed810c8f81eb66c20a72666e9c8ea3e8c0bc646332b1fde33ed7db60f745349c3cacfe0" },
                { "pt-PT", "abd7e29619896efdc18978c69bac449433840778a564eb79d90acff95fa4d7de1af62068ddfee0478551b59e0724eb3ff185041d96406f29332f1350962b7777" },
                { "rm", "e5ec42722407f68fb2cac2089c452b8ec35c929df46c5d6afe98c4efbe80a1070703655cd0d15b7a5d6aaa58b93340aef644c6d7fa9c326840e340d254ae274e" },
                { "ro", "79b84ae5cde8911120957154fe1487d49c78d1c21e4ca3d63f0fcf714b604f75a19cdb8adf12926ded05491a86516274e389e5739ae78af0e1b451923530eb76" },
                { "ru", "f0fc229d1abde0955f7d0898daac554516304d7288d251c048c8fa9655830fddae56a5406ee291eb6ab385b4d8c3de9b7646df96a15c276e3e008fc844697a07" },
                { "sk", "24e5cad7d9ace233c0b0157559026f7b503b2080cc4db284be4a99167ba2693d22555fc37b62ff4f86c61e9ad8e1c9ae92f96a603024e28732307d928cfdf744" },
                { "sl", "1b196f288721fa3a6323636752d2585f16089a37b598180b62c36e9fd7f7e4ef10e73daf97047e1829ff13e80db8d1121f3a4fb0e11e784836ed1bcd7d38bef4" },
                { "sq", "9dcb3bc5266ed18c333531e08b676f24bda8277ec0f5b6fd823d2114f34d6c8aaec448e1a88af040df8b480fd074497d98f2d683b2f48b220a740eb15bd07052" },
                { "sr", "00fb9798b37579a4f3d027a9761a9581a552ff6360bae885951e15eae36ad5809621b7416715b5b1f649353d4d166d94f50f3d38db267ad446ba8de221aafc69" },
                { "sv-SE", "5778327ffe837844f1553a4e7b447736079a4f10fde9918bf0ec5c7508b750d090e6c7f8319209dfec86e555a5b04656dbf0002820b2c94d548f3bf603fc9a45" },
                { "th", "43439932eaf9521e721602ace420211f0f9759c43beb5124af6cef3d98d95a727bfad539f0143affd19568157385e5292cbbbc1133cad58be2a24cd701db5417" },
                { "tr", "cbf1ab4f30e8a0182683062e62c82ebd923fef6888a251b50a82767683890a64feeb66133da820110faa1f90cba57db29e1d44eff4572de2f8bad6f850633a7b" },
                { "uk", "3f5bc77db80541bde38b7ce346f9d95fdb8df57203abad5e5077dd5cc76b3b1a64ff755654db298f4151c97658125ae9181b610570c5d9165c106c8df4a384e3" },
                { "uz", "efac1d43991cb3763b36a3980b5dc5790377860cfdee1bc6857e9d2c9fb600926b244b29148c8c740885b07ae216d4167322b70bb73b70acc12cd15648d12eed" },
                { "vi", "75e1c6d50f35b18978e4d0e50c80b430fef4039132e2955adb043ccf8c5569a86aaf184178425c382e6a42f46c69e494cb88edb58b7df6a39424b0607dc38cca" },
                { "zh-CN", "eccc766c1b284002f801b16457cd5d450a1350a5ad20438b63f49a47ee4c5ff6bb0ce3148c241c011173b66acb49689f0f14cd269cc597c147461c50bd880b3a" },
                { "zh-TW", "f1d0768d36f8014d60a3c5adb76091d0e6a032e23eefba134e592a8ab8bd4f0dec1545f4d6f71c1b742ade359852ec49f0415ae95fcf1bb7b9cf514be579fcab" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.10.2esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "e1754534ed15379e3b84b2f063cfaded2fb6474203eaa0a58fbcccdbccc1e45168da4ca11a33d650e9b7698b8a3fbd179b63b979b2ee57a5cc4361ee5041fe85" },
                { "ar", "dc3b85cb4f7336fa7d603db54f0c50c9effcce6074c6c27365c6c9eea045b7a59b0a9d95d126fb089475dc579dbe0f7cf3b6b7e33820b90d7429beb24a003709" },
                { "ast", "8fa762a11205864cd1c909cd48a135b6605b4f30b90907c4f38297e0359c0ca7da4ed48cba0ed0647f71b53ba436350ff60bc278c6507b3e67c1c03aabfbda6b" },
                { "be", "ae8e327d2a8ead1cffccb6f34b3a709d081c87ba0d547b8b90114e8b0bf4e4b6c3eb74e1a0df302febc674432e0bf1deb8a1f0e3ed0dbcd0eab5b8aa337bb030" },
                { "bg", "b3d8ea0c6bdc66d4216b36ccb3608c903c390ba0b9bb726f9f2ee42dd442e50c91ad141426abfbc4b464ee2789b43b6da3c288a8a88c7377feb3a89f675835c7" },
                { "br", "b7a732bf3046a44884abe41f42c9a3abbf5be855ea9214fcf2132bb6e6b6b7afc887baedc9b014ba36656c89d5b2436525c318af412563b68a557f2d8b5016d4" },
                { "ca", "7b6eaf4b9e55ab6688d98f61c10975421716e57b650277832542f0dc57d13a332c7ff6203abe99858f46aa93c7a0442ab7a83a034634437d77d221430de19bb3" },
                { "cak", "170d5ee05bcbec1906835e12f35216cfbbe7ce2b48ad078f826e2b8923779e931522b8a2d5f2e3d79563a08db083a4ebddbfdac6033da0eabed471329be7f912" },
                { "cs", "af25e64dad7399d31749dcd10b64a4bbc8c8aefdfede706879e9cade08c469cd01c94bb84e0e6378fa76f9d0ee450e1b4c34cd42fa7228de5bfb28bfa7e1ea6b" },
                { "cy", "8a502fa2b3874f1943d60d63ddea8a62b59cf67afc7ffbac96a9c5d88335f67742c5d341669653124f0f5800aa03534e80f54879399011f061ed03b7a0a6cf2b" },
                { "da", "7abd20e7590a7042c474407b8e0e6216ea28e81142ba9f9b529d901bcb23ea286510df5100cd8267d3fda9b09a7884dba4464140a700ce0aba723f1836a746a3" },
                { "de", "18b3998a52b964248b5d76278e3c4dcf795f6f3a9bad0994144e3123f517e5e2f39512dbe714f038dbab7465d6f6039a54e8d65b642d2fe15f3eb23e92eb3220" },
                { "dsb", "a87605ec07b9b449e74f1eb70899307687c630e3c613410a9371774a535c67622f6e53d6a71b35c281976ea9cb829c89ae30fcb98235793d244c7e471159e156" },
                { "el", "3c0572512182cab7b14dc4cb8323e420e8b45f9bce600c265c0892287181db7e0fcd28229a750ab51d74dd88c0e614cf3760c6d7a6a1bc5e2d8c2e6101727bb7" },
                { "en-CA", "7209a90d6229a27892161cbd7ab991be5c94d782e6a005e78c4bd7ff20f8b41c819be41330a5d882bced74ad751c4dd9cac35ea0fd0efe58071fd852a6d99e41" },
                { "en-GB", "6824462030e83b01aeb0ecd0301c36cdf546a1949ef0405441956eee3772d27d8cec245f1b04bd2a858ad3bc0a5c2aba0825a45443683e9fd6077402d3c27e8c" },
                { "en-US", "9a4412feaa241a6d6314b58a7e277d98cae2ceb6909d18bd7715134aff5a800ca9998c2dd053440e3e56191b1ebb62637dc9d2e1fb693e29d682d76215d26aa6" },
                { "es-AR", "2c88ae73c44e0ba4d80db633d4949557c013d62146ce7f3936b7e9bed0cf0816834bb6159abc82636b4de60e0aea337fcd996f6c882989adeedd90823c966303" },
                { "es-ES", "40b74f23fddaec2b532f6aa280569c4ee5075f722fa6b5ef394844612bb6082d50cb388303012f87eb0d765f94c936c4718241361f9dfd4637547c952c43a88d" },
                { "es-MX", "fb5e5d67211d7d5134490ca330696321f6496950055cdfffbd00fa39d2f424560544341208735d3415a10256e82f64ba9d675c33dba7a6836ef850a83b7add8f" },
                { "et", "3b19879e3bcd5097559fe5b55149e6baf5c3655038cd48ba499151a2d2f2904451f1e0367c3c1dad529f13b4d0cc8814615eecaef92d99f57df232a464d75f1f" },
                { "eu", "b8c43a0ca063323e464e71baf63b2fc339fbbc1ed6a0e1e2a56cd33a8640ef32d2e68d44e43dbc592a6e26b586e391dcb5ee89dff745bb811ed9f6767a0133fc" },
                { "fi", "6e8908c0a2736fa888e1648b7f733eca29fc902f09a66c0616a4e25ea38a2689b4ca27692053bb525440ac3c161fcfb528db5cf1db65918476782292b4a0ff00" },
                { "fr", "86a195bd4ba31b11c63de02fa5f9665f068380803a12a6b6879283284d15893912b16c5189282c718f5a7acaa98b3edec75e017b8764ae866337946441d56462" },
                { "fy-NL", "03691a01d20d0a71259bca191708da737eebe0041d62488e585a73fbab435935a9c4520f7854ada09b387963c2072b583d858c83e285e266f5914d6b7afc131d" },
                { "ga-IE", "7d01a4d345aed4ee8f17fbd31a0728f10d44b62a173a62f43e4c41d3181a8e55acce3d855b5570c642859de401be3bc1cf9f76ebe190ede7fba0a6627eaad7c8" },
                { "gd", "046268c307d0b8e28f4d87915dcd53eb8807f4992ffbe98146b8fb27af357356e9ecc67c5e5bb4fe3a6a27511ca3b662ce90c5f93efe5d06b6a8708243232530" },
                { "gl", "699edc93a464ac9bbd5d174cf99dc9cd961ceddb6547a18a9fdc6f6f5bd5e29211083631ead6f3b601060370fc90ec8112e78d7c4c81bc0a55982ad6ff10ce9c" },
                { "he", "8e86b084b673d98c0f9efca7c4d7f3b2aee36403ea2f94ccaa6e334f5d439001120019458260008da7ba9f5a6988e4a9b6b51b77d0edbcc3a421ff824404a702" },
                { "hr", "245dd3e8bbd092a1f0e0bbbd507a22e0ab81aeda8017bb176c32fd2640b511f35e90c8176525f08af33fee669e5b5feedb35c85e1b583b64a2a025a06219c1c3" },
                { "hsb", "d5567cc62684c757c0889f7ef2a19e60c8ac5e33fdbe1083021f05631ae93bf3ebd84a66af373e7a3fea3a50450018476da14cd1d2f021570ba40af090557bd5" },
                { "hu", "35dd047763f9d65711ba09dc9a53635a9ca8822258d2070e5da484f015c1e3b14ebc3e4f51a5f3a73252199c866b16983d43db5da6691c267b849345e5aa427d" },
                { "hy-AM", "3d2fa69d261159d103b6087e5aed8643d6b9976e30e70b71a986ef0961e04fa97bb990a904aa3aafaa1f5e3c96ac558f1cef69c05145651b0ef6d3a3b20e0034" },
                { "id", "b6d53feaa2b7dc1de21e5edb5cad07e85c8a3a9a4facce350475e2838ea9a8b8def69796f24c8bd9c2f3354b804654ad8290990faa349f2b54d04e0fe7369c43" },
                { "is", "a5542e406a8068c742ad14ea0c2c648573387f0bde17a87888f389d14cb69aeddf4e3f139625980605601a526b2038e87b12daf51223200ecd5f66109a5da68e" },
                { "it", "add17964f9b7c6827b22651c27282a297cc3933f0b0d9a8b9d99c4bb29ca9ed6ea9e7a9303e2b447d60c669e7d169d50f00a7a73532d9cae61b6814d22e1bda4" },
                { "ja", "eafe30665cb35fae215838d14f383b028e91330159fe0a4aacd5855ed026da8f6b4f09247118747c8bab396ee23adc0b869fc1510b766b8800878cea1901b7b4" },
                { "ka", "73c8184dcc5a25a0f75a86715186c12bbf89ed6259c63f73fed78634c821af97abea221cf578f955ba200f22db26c8c51c4eefd8622094598be12f0b93fde97a" },
                { "kab", "e0032fa87b7d08114ccee0127f957e34c6dd83547ffce886c69b39ccec75d40b6402c0eff1076959bf461ce36a99d4c70e1e46467d83ec08448ef4e3822c8bc1" },
                { "kk", "56682c58e94cc5901c30e1cc971648637895b3be85ecff0ad51dbc3e34e33a543a4027aacc422365a5a2a4478829c0fcc17babe69e4780810dfe58ee0efd6fe2" },
                { "ko", "c38c459b0f88b3ffcf8f4f39f67011ea9040bf6a8e32394270423e8bfecdc436de56491de0efb8c8a305a423ea4e46ae3b82c1b411467d0763511201eac5af81" },
                { "lt", "e956164fa63be77beccf0dd0b172c300f980679035afebc18bcdf27580e05e5eb0fd041f0261bdee305f8b65b8027647c35cbbe791e7bd941d8dd21d21b84c67" },
                { "lv", "6e9a266aeddf1619a814b8eeb57dad73e8a4b7ae82254bc6b5286fb7a3fe40c00af04702e3f562f92fecf6ae93d8bb3db0781c3eb66ad5d900648d702452bed0" },
                { "ms", "a7637cfd6901b7565ddad360187d0b8bd5e4515d1273484ba5142f7bb0d7de395c82260b912ea5b8911bb76da3890a0dd257ee93c0bd57452cf970a42cbba519" },
                { "nb-NO", "8ad3819b7d9a2301fb30519a2e200c34f955bf6dfcb50adfa0c7481be192fa3b6075541a54d63b7301c53a4f54d916bf3054e4ed146497653a289a94344b6803" },
                { "nl", "4d0638ae0c2ee1ce8e1f88e08726ba46f15c66157530940502db1942b969adc80f155776f1ce9705579fc0ad0aba1a13fa1d245df5d96015a81147ccc35748d4" },
                { "nn-NO", "73a0c405df20f4edb7dcfe8ca436cd2c203891b4e5a1d70b1fbbc81f6cebb9da94f99d5b5b0a050b1e5fc1a9c5feebf6478d1f1a3e866b302e6b31a84523a1da" },
                { "pa-IN", "66d9e715b81c477280a314014fb4eece3e070b82cfd30a66d64436fc0ce52b428363263b7168e512f9323ca82d56b4e53a063debbf1de67ce4ef69dcac48b714" },
                { "pl", "dd1751f0b0e3323b8b7fd22660844af02961951c8395f24f72c79b55c55b6adc7ace923ca74dc47ceab4731f28d67af63674fc1bb505d1fbd21c0f46eda7caac" },
                { "pt-BR", "770c2121954d1468af89a85d888dbea2cb6dae44995917989f1fd1330c24d4e14c9e33d12b92a0d42c03b0eaaf51acfb377943d396d5f286701d41f494834190" },
                { "pt-PT", "e67b191f04542bdb3a4559b995bd7ae8a046dd6f6ac4474a57c973c2597d1bcd0ad559318936871503c3e71f24671acef1b5c3e4dcefab0876b537804ab4a6ef" },
                { "rm", "7cfe22985ef7b9fd8e83688b8f02305c594035fd6bdda643e5762d7f50359330635c3fa1e1856bd3e14463f945efd16a8af91fdf06a5f5d993f066d3dac023b2" },
                { "ro", "324484393415a072710638f523b88bf488da96206e6c2bd92808ddee645e8e8aa25ce19813f040ecb69e4f34ea69b75032c35191c7cccfefc29d8e5337ccc196" },
                { "ru", "7b37f0aebcc27a31f9643954845d35251fc138faba9815ceb64fa795a8f24e3f50cfcbce495169634def2045898875b18895259d1bab8b0b306cf608035b782e" },
                { "sk", "423a3c4bbd79b112710777716c7dd9963db10de335fd9cf84044366e25585943d85b5675393078207041d50bdc9ea04374cbb7711c381b94c017a6c9b7d02369" },
                { "sl", "c6eba873f12fb99c58d685841ab323459ac492e513c21b93ecfc99b7eba56b11334ed3ac044d03c6265c40074245bb60f211b7838187e52ac8360f8457ae5bec" },
                { "sq", "9e51978af14d1611b3ca3e104227137666e3b2b5493938f6a38ce576f3fbbf770fc151b29143959bd7cb1941997b18ee2cda875fbfd05cc32867b4b0c586dfff" },
                { "sr", "f9054ff010689cbbcc4f510f9cb1f92cf302b8bced4af36a20e3ed26fcb54e4f315fea71d7e9cf175fb3c0a897e7e99bf865ceaf14835c23b3fe8bc593720ce7" },
                { "sv-SE", "66cfb35fb09684f6b9ae2234c2840d65b3eb62707140bfff95a7468c15ab659c9ded948fd3fd5ce972b8e797970cb1e3c2ecf9dd406a3a90bce0cff2b16e4d6a" },
                { "th", "d006d6bd4485e26c0c1b52128ea2cba2c514b43e886fa29029e751eec9307ecbb1e3b316dbfa38ba036b91c0c2d9c2ddd3c9fc147cc17736d53014ce67fc383a" },
                { "tr", "9ed1aa20e20206740e6473ea6af55778616e1390648201632f08dbe73e87c669cbcf5cfffe32e2992609e2db05354c6c249da8f033f076f3325c2bdad8518f0e" },
                { "uk", "ce950d2d30eea1055d62b6606e9e0ef8c6f816d1fed4db997e769bcc31abfafdf0b726458a0a5576043adfd67486c514d5068a9aeca16881d331b0820e3bdfb8" },
                { "uz", "7be911227e142be293c3f678cff1dd6f2fb55351fe648e023a139c3ada30960db260bbef02d41584574573ad02831fcbfaceff9ae74511aaab2533f34f8614f3" },
                { "vi", "d77b2a1f9f254a9ca8c6af140b22c9aa29d3c15a054c4e117875d51f38535d094fb2594dbcc79bd8d734103684052ca21ce051412f6eccfb1273197c254ea21e" },
                { "zh-CN", "b0c911c7d65c60f50fce20eec788779fd24fd70fd7305c9879f37a29d03f4c90f3eb7ce766ded4cd6c77b89c8dcc57245ca7df6eab2c058aad787483be4c1b8f" },
                { "zh-TW", "3d3ccf0741b9e64a096bfa6b0e2a16e8847aeb39afd5c20d0b53ead9d6eb55e85e10c2b3073b29069464357d22e4e9733f527630f6e600c4011e899c0092be5e" }
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
