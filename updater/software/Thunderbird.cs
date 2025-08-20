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
        private const string knownVersion = "128.14.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "480469688e89d9fe5442aa4a0d9d4b8f5b7926d594ff367652e9e332d282671cb54c53ad4694685a7642c0624576e97e364ee7c3117d146e138f8b9474ecdb45" },
                { "ar", "27d400e5a037c6a9031fc02be506e8af67d6704ce488ba7ffd38eee5776857ef826a9005a1eabe40a59f49c15ec2622d8d96e80293c0d94bb42750766fa3d437" },
                { "ast", "7b44d3507a67956b9faf06435503562ae8381117f003b831d0641edf3e5bd30a0c0f95113af35c7882cd770b7b2256e9842473570b9c60c1966ae670ea7c04f4" },
                { "be", "b4383a90459190dbd243f84bd6fa4ce825f095979c6f19cc479e2215a6c7db38b0a236b288e3d48cdfdd4fd1a7df80809b04397bcf88662c7080dcca7ef6327b" },
                { "bg", "fe81331695a9daabcea3ba9131cb281696947b2d2e5c76af55f6432c65db9a5e4ab82e83aba5296c1fc850e27619966260f595547e01de0556078600326ffb72" },
                { "br", "133b3654f443535bb468ba9fb7d63230206f412688b45eff5637568a31edd72b0576314cfef09c77c1839c83ef95a986ce837342165f44712f9d57d9c2e42c1a" },
                { "ca", "b2c73dcc5920ed8a8216891cefb95f59de61fbdd433e77a25515583439ea807f86f4c6c2bd899abe2067656efe9647eaff2585a4800099a174e9cb9b6d993e5e" },
                { "cak", "8c5689d793e5efc08887665cf8c9481e33fbe165dcd158caf95088bdc0d31672ec453bf8ddd51d68a24162fad33ccb6385fc1b5c18b83575626799191ddb2867" },
                { "cs", "e90b7949932917829f7d13c68150a2e49f9ed2fc62c32c2d8bf3724cb23caf64d78ef8450d4a0430820a2d90aacad252089c3cd10b9c03b73a1bc05fd3b856fd" },
                { "cy", "1190bbaee9258d11300d42b68d807a6564b37fedec2036945d83f90033706220dfadf4d5f03749026885c5cc2b39f3d75e5955cf60c0c57647b8e79de9c673f5" },
                { "da", "76f3ae5eb02f5d3d5538e493ed910b31be878fd60d16db1c10a61fb5fac5bf0e627d1ea41c7c5fdfdde2cbbde8b18eb0cff1a9fbff6e64bbb90e7bbed7837036" },
                { "de", "38a7bb4fb4221833515153baf2095c00b3e7e6131434758f61efd47f8061318d866c575b458411c0affc74338f7742b3a105be65aab05b3e3a1d31bbd4b73d83" },
                { "dsb", "2ad106a8b06fe0a57f9ed9c7cc0e50c63eb37c4650bdae31717d2dd853e7bc7db712d167fb18b0851673f9804352dc7d010da4761b0141ffd347e5bc9e7e2038" },
                { "el", "75ce5dce66a5ecc79d83b06cb8b42d93c9d2fed6c5d7ade4f32839de83323d4b4f23a34d83c10438ae508abd0cf44e5c9404d0299c6e04e05d2939619e83a627" },
                { "en-CA", "25e26e57e0bfd914ec27ff989d860a5997dc68cf2b10f76b7dbafaff5e201797c3dcf682eef3c567c38ea1263cd9cc035321835f57ff76fa3b55a71b724525e1" },
                { "en-GB", "b1aa4156283780b0c0428f56f77b542ce580a4185cb83d8eb6bd3b0fc97eac099480c4f7309297dbe8870fb3ccba164c590a0be05ac68c9818199d2c4dc09bc3" },
                { "en-US", "0053985204384fd5f8f12562ef36c94804273b6689ff0ec287a6a857d50ba64ba03e2c85e4a1109b05c7b31c97df63ea4f23e257606a192354357804c2c0adba" },
                { "es-AR", "7388ba5709f6c8d68e37b8b10457ea6d4bd1764492d8fdf1f579c55068611b8ff3c3cfe256ffae3be488d894fb2062159e5f480bf3ec301e840672ef594ce24f" },
                { "es-ES", "f8018e871eb12340e9d7b4feec998f9d03ed6ed9f88665bf64db16f9b153d19f496876eaa2a4bb7dd1a88b9b753e4b84dd0735f63cd54dde3b2c9072a4c9daa1" },
                { "es-MX", "632b2a4c4bf18761cff3be4b0538bd6128fef569bf5aeaccd54b07a5cb87e2cc37ed50415563a1c12c174097949e7e44a8d2174780da56fc37b2826b7cf53ab7" },
                { "et", "adbbeee18ff5180296c620fefe9810d1df8271f06c225af5a63178fbee35a5f0f41f53afbf5f03ad9f24ebd5c6f6a58648db2ccb0ef9afce7d687e49cbbdb3cc" },
                { "eu", "58fa3eaa70203b09867176be39ef1d2f0efc00bb12f3ba93840f45a9df8a5e5a5c2f1f6d4d9afda6c5311597f91293bf691877aca82f56f6675e2b7a407da69c" },
                { "fi", "1861db00a13c8a1674b528f58275edce65364fa1b2d33908f6172e30f80805ddf25086ddb339c8e6e1816bf0ba36f9b426554bca190fbcd21dda9e3f2e1acf98" },
                { "fr", "49782732e9c79d62a23c123fa12fe64427223b32f1c473860112f015910f012f10f5fc3cc0fd75098393a131e19cf9494546af60c02e786f70341ba513c18b9e" },
                { "fy-NL", "0a3a37a27b22d4eca34dd804c901166c65eb2104a7ad1b43b6f31a01d430294d8e942d26100db36236ec8a0e817c4b4809995fe7554552a9f8a1ce27e01198d3" },
                { "ga-IE", "4bd0e0e36d0cb2f04af7215d377853fcbec054330417ea15452ca0843d8129eeee985ae48e508bdf5efa505d0f0fcd01d4508a326158ec6163256567b486204a" },
                { "gd", "dbe1e646a06d8d7f89e455232dedaa299f49ee22a7aaaa37ecf2e5320580b0dbcd070cf61ea9be17b5e02585046fa9cc74de035cdc2cd6a27bcd2155df74a79e" },
                { "gl", "48799e96286be7f0f0d0ca878fb5920d09c85ade49d56876dbf44220dedf0c60348021d85dd8a4e08f659d2703cf862fea0bebb844ebbeae0b62ebe35207b1e0" },
                { "he", "8994ffc59683d82ab12afac647dae176284f66c3bc0ec5166ca7c638da4252d0b6759a97e87e356699931cffae8914226f344258d6bee237c62a9eb4dc51b5ca" },
                { "hr", "8563a3e8202fc37f5839cf6b7d34eebf3e2c750ca127ac72a6c2d9f1313c15a82f68c46d2284ffae851efcaa48b459fff19ed362882d5c68b8414de9da5a8ef3" },
                { "hsb", "57f363f6f9cf50a0e404020345d8f03b11cbacc8718b4cfb64be4be83ebbcf32ac04ce499df718def6b3c5ac11d37c9d990560bef16c8e4743e0604f05cfe96a" },
                { "hu", "b2582cc7171780cbfc1a13c8acd46e8f7fdd684f51fca7307559aec1f1088391a3090841a69e463ded1785d1202f01db9a5473f0673dd516c47ff8e54e40f113" },
                { "hy-AM", "fe71df44bb109804f95925bd85820a2222d083e4cfa0d44a0916068bd50260d325f5f7cee7edeb8fe2c4695eae0a25336e4b5552fc50a476a6ec48f0d76d114b" },
                { "id", "4d8579ca3587542c01a1bb0d9f201c965e18e8feee056afba7f84812433bf6ab60695e48df2fe3e7e18497970ff8ff2f304e0fe9f1ae96dc6b39ab7dcc90edec" },
                { "is", "e57f70e9e5bac4ff66cc2668d69766055669186d18b3c9d72d79a366f3f4134d8d63918919c778ceba2706240129b371dcded9af61a3ebdce7cb10251f010e4b" },
                { "it", "e662c5a6796fd3b18f24b4bd7baf19af4bfe279c797987627cac0638bbf1a094e57426f8b3f919cc80d792b4303d08143e03aca9f1d7215c5e4f4dc0acb85f59" },
                { "ja", "f876e60dd4d889b57aba646f103e60190767f438a8ba1f579ae865f59d7dc8504fae114f028cf5153fd0f57caf244732b269cebf3f8b4a95244e5f28fc44976e" },
                { "ka", "f11bc279cd654ade927b14a08fa38521b087e1700b700e29bad9ef72f01549b8a32ade1ec80d4fd81df325f57ab7b01ed55bdc5cde3e3dded79ce52dd941be29" },
                { "kab", "cd456927a317d3faca3c6f89b596cb86c39c46d567c701d1e44e6fac6e073ec76ff93d77087d58e6c038947f8ddee308c4d2f19b98458cf37a6534151a7a2473" },
                { "kk", "ced36e518a8a45bacf0d8da095c53ca698e9066f26363a86eed7194b14c25aea315ff6c5233508bda3e2839c7b9ea411b4119b9d2f4eba010b66fef773fe9bcb" },
                { "ko", "d8f4585f836df0b0990ee2d748f9a56d390c27b8368f15c7de8c808661eaa5952af2b6382e12276226656b6b56af3f576cddf821b8a2d886c2f588bb2085a80f" },
                { "lt", "29a8c864394f8b84b94126d2b01ad79b675592af379a42ff1d8a9b1ae85b1f0968193f75599a21c99ae61900353a95a7e9e16fa56f673b953b0b180891dd65b8" },
                { "lv", "3832af679306ebfd7c7db416c9776ffc9ec90f55a0bcd6145bfd6d2df0360d9597a40dd56482bb3419a724886ce30c369330227e366e9b5d97b842bb29977539" },
                { "ms", "6476b2bc4ae7ddddc3304f9d71793f6dcfd57a243c9c830bcf6e098738c4189dbecfb7f5346caaf25b012bda719ccb49405461cd91234d11bd4216276b91bd1b" },
                { "nb-NO", "b06c05e8c958ab3b90c36ee765574942fe71c97f892dcd79cc3f443856ac739209f864e1d8bf8c2b9094f083f8616a53cd30bbe8f7ac86fb00d407204739d552" },
                { "nl", "2e1f0f1f28ca90c52780dab5cd32a130e1d88f765e81828504f40e132c6a310e995caaf4665e04ddc44c348a1083434de519d8f08ee45c53db02e39d040a2a17" },
                { "nn-NO", "aba4fcfad9e38df006b2e975a14dffd9a3ad97d43c328469c79e6cd4e0d5cad5443ff04acc2b8f9cfd5ca42c8512b9a0f762a70ad788047e595417cbab5c0b10" },
                { "pa-IN", "eabafaaa40214df9fef180a8d4d986ad0b9abf97e6e4ec4b087d631bf9604c355e9352316c59e342d3214c333243af7693ba55fbe0d5a41c50baa4a784bb22f7" },
                { "pl", "80f49d48e4080123bcd98ca8612f7d0c45c1c829ecedd442442c715be129b1d55b168312726ceee71fd88b3f118629fde3a978a6ff665d9924adf8c92a31084f" },
                { "pt-BR", "e81e878c13dd5cf3d4d604c9cc94744f1620501774396f235304d456b37edb864a792dbdb6683ccc41bd5b8453e6b0cd045866066ee9a4d26da2483324597165" },
                { "pt-PT", "a599ea8494e3f62118a7028897cbe29a94f19e1ee872af4120508562099112e1593d00ad9e8177e97c1a88d0c818f64e13e8cd5e82d31493154562f481c862ee" },
                { "rm", "a15359f343f5f7c4b943482e60117def815abf0bc6b5772ca23c4a072f0d648efb978716e61fb431b7c3eb6bb661a37e9d615f4c0c8d49b5890fcb6fa163c933" },
                { "ro", "c0fe480fd0bb394ca666797d9327a7967e7f6c00e8cefbab6861fa8696ffe66f870f09a8011b755a427c041e10d25a1b4f88c80129c02f3511de55ed29f1a2ca" },
                { "ru", "f345c8c829b976761eb6044157be16e28feb72fa455abbdbde61bd8061224d695d8a877497847dcf0305bc03ca0c6af4738ce784493cc0bb8395eb4ea676fe0e" },
                { "sk", "04705941b55aefc5766cf8aa7edc7d0ff0add30a60eb5188bb824afe0c8a149f579b2c33d8bdc5c71d20abf085218db2abf5b8ef85c45de9e41ce7851dd6044e" },
                { "sl", "175ddc9176ad77e047aedbe0e73ccb852d03c405ffd3fd61fb0146ea8f72a80a3c40b73c66c1a1f6a3ebecda6404635fae1f5e6ac29dbc406d530f2fb3ed253b" },
                { "sq", "2b23e88b97ff79c8485016e14456ae391386b3692690f6a40fd225a42fa5e11be80df4da92b12ee1a3dfbe3119603923ed81f616b386573cc898c1115c658ac5" },
                { "sr", "5adde982c9ee0ab0fe79608754385493ee3fc4d51da4b6712ef78e8aa2ed8cb0ee406ae4e7f6f47d3ba569732133d8fce3e37464f20b7f2e8c7960560c2a446a" },
                { "sv-SE", "e6172dddb329299abab3711fb23a60edcad1b6fed4b5b2a9378bade238054fcb43dfd975a0599e0efd86e0c68e55756c2b1fed03c53c00324f19c9102467aafb" },
                { "th", "5fb305116405d116f32038426be41120855391954618c25e60a8efbbbd982d5f1e86fa5d8048c8847fd572b94f0941fd4c3055957721fdd8ba54f1415da54163" },
                { "tr", "ef93ee3f755593d88be6ef267c0f3283091b104859a6de3c3e16f39871a97e8dee4dc6518f023a2fc13aaaf55f26bcce4a701d282faeb811249e50a6f3594160" },
                { "uk", "0b894867d1a8d800fbebe60bf6f12f7ccec9b2e6df505d851f7b3fd310c9a2a00ffe5b3093890463720ebd08597e386d45ad3a6b7e8df60c53af6569e8037932" },
                { "uz", "f4d4b16f670b3753e65263cc4c0a2e994a08489c75f0c23af403969a00f7ac6d91239d78200f07b945d71895d054c5a892ec8025852ef66680985d2d100128dc" },
                { "vi", "9cf3bc75b3b2c559079d96d9b513f14e2498df85658b23260a62a662dad216bcfa860cc6cb5347cf1364c852712d7b67e5ab015d1e495ec07b4ef17bac8d0ccb" },
                { "zh-CN", "9dda7d077165edaecd5be6e06cfde9acddab6b48c07f076b2b630ff119384e193a97c811c7d106f91c420cdd50af932a73e1dc271c2a7222ed197c4d78d04bcc" },
                { "zh-TW", "7b87bdfcb2bc97f3509486b11eff1e9011d565bf9492dbbeda18da6d7686d7314aa00d36196a8c8aae6ae1198c8b548d952c940fbe315146fa4c5d5e6f245d89" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.14.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "f48bacd768ecf6a3fad02e557087a1077c91a7c3b15d4fbfe6201c0513e1cf0fb2f45f2894495458a156caaa02c31c079bf5f66915582fd2e90e546a24b3c241" },
                { "ar", "15f1b54c3820232456530a026bda3b4ecc606aca6b1ef0dafa6babd5ec8d01b894fec8631e14b7ddc5b695f5ea1b5ac947ee75879b28d374fee67d556b1549e9" },
                { "ast", "e99d39dfed8221b88e97a61ff93b3434116ed43b5d19c12c1363c80f0696fba3e641159ec3437ecc0b5d59607f311e3375308e50249d0e0ca2657f3efd46f1b1" },
                { "be", "1f8bef3737dd3d40f41ca1f69c313d3406b20521328debd16675f70ae1ef9157b57bfeaf1da591648b0bfdb9e7ae4b029d37926a4d6904aedb1a522288a7ad43" },
                { "bg", "ff1185e36efe72a6730e0f416b5e21299f15922d04fc31622d6a7c272fc5b7b2c30550cb8c2ea188de89f1a1e8460654eb6604080e7882d601a0a4a4c03931cf" },
                { "br", "7083973ba3cfb05b76760c834fe5b881938d51a917da65decb8e276cb28090fe1a23683cc49474a1ab0b5b40989bf4453dbf7e43bfe9601bf6182d67b4f63239" },
                { "ca", "784968396abd27c1a0d0e56473a1d74021fc6277328bc779e2106f94799d3d53dbc64975b27e320d16ae9e878add26e2b6c346479b719cdde817b00a0104b864" },
                { "cak", "f70cf076c957bba5ea6beebb158c293a8745587b936b68884e5f60ee8d774e5c3ade5d3b703c18779daf5d07f5c8b6593e7fc181c620713ba471acfcc950f3f5" },
                { "cs", "7715d17ba6e1abd2015661d7cb878f76e99eb3a4a7ec60240ad650aff73d69b507f6ec9ed85f24c25514ed390aa445340e76c6a0779546aabd1adec201bba4f7" },
                { "cy", "1090581ea2c52225eb5d874acb6b185a703c5439cade39a45a8bd422727d57a507d80b578b2c6bfb82587bf4cb13ac5c604681547384f4bc1cbe6f1b4ab5c164" },
                { "da", "a33fef576f98634f061e19ec7eab85af1208ff9094d5467bb2bcecaf8973f90699d349682738af3b0c802b3798ee322b301305d6c779ad791eaf704c65617d99" },
                { "de", "8076088ac54995a7a0e05ee07b9458d8411e8dd5aca72ba12fe7c410638b29a83891b9621d14dacf6d5204d5f7db0a5c4c9ce4ae8b6cef505c47d255259db98d" },
                { "dsb", "ac11456621a7123f4d243bb912a7beb2e559626490069b53d9c6ca2f4964092029faa21a427c5d831a5d370fbf2ce7dc13ca9ea42a22750e657ccdef8d91998b" },
                { "el", "65e9d06722df7c631bc2d7037b4e8b9ea0e2ee3f05dbcf64d573d2a6c80cdb40a487964986eb6f3ab8f486b8819f6dd054b71cdcc9f76badacd0a4e83d24832a" },
                { "en-CA", "3c2e0050f8c898e730e1235f38a3800f33ba9b36dcf6bdf80e699c397bf0379f7c3409d1e1937f913c3786086e6bace8b62887caafe71df1b634c3f67edfab14" },
                { "en-GB", "b7f3ae784152e83e87efc3b60738f6effe99fd14b1ae214843575b30f303638d480ad7e126f7259e3031a88bc452473be1c87a9beb92d069f7d2614283d2d4e6" },
                { "en-US", "a87f77fceee7c80735f3dfa5cfa920d5b4c8b094fd30275f8ed0c7adbbdeae73306b9aadf117e1d2b724248855cc273171d758f14abdf541b676b3b1b54dab58" },
                { "es-AR", "da5629b2a6b989f4d8216709e227c634079f25becbc2aee8d4bbec8387e1bb7bff3a96cc71064a8c06acb632183a358cbbc2b34f9c764f9930f4e62bb6058ac6" },
                { "es-ES", "e5ee1a72f280b34ed6df060c99ec287d112a8c815a6d651d0b1c327af0e8f2d77e40c4cb7c39d07cf66c6cf9d179c6be3d3e08d4b00bd356f62461d736d8510b" },
                { "es-MX", "ffd0599af89a3c294864e13f7a2cb9522ae505703dd77c54217c519f3232619048fe1172c80075b035100dfef8b1eeb4846729456334653fe4d4d0735b8e697c" },
                { "et", "0b904c128478e58e9edcf054805e1aede282485aabb213318491b337dcd44f83e7ee8ace02bcf35010a21743cdb01e913a64df8bb98130b566638cdeb5a860a3" },
                { "eu", "f221fd2977cb3b605901b2c5e51fda2617c26e9314fe4819d64e6bb989478d0a0c74408b3bdb820581a9340dc92d4bd379fa7c59358baf83090a4748d1514773" },
                { "fi", "ab137e0c96ebd1991e37bae2fa9ee1a24523d91e72d262d0ebd6cdce0f9f992c48b35ce13a0cd825cc71ab3e133ab7f0506e86956ba8dac53e800914f9b35bb7" },
                { "fr", "2cb8d27c2485cef787acac726b0cd115d661cf5720ee7fbc09ef34c5634cb576f58438ef0baf2538976b1d0efea9eb6bd4cda29313375a9c359e56ceae3db77f" },
                { "fy-NL", "0ae2594b0e2628b43f4f4c43e9c1914ae2bee16a6bbc941606d83fcfeb4ce60d74969d8f7191f30ca1abaf3ba7cd2e23ec83b3b2b7b27124d6858984fb2f5e26" },
                { "ga-IE", "a5abbef5b39df825a388b48de737b92f5e99a8906154abce44e7af23db6503c06417c103b9d47b241c9bfbe60819c30e01ec2bf412dbce0885121a2f6fe0ea45" },
                { "gd", "49bdeeea508c7ef3f6b5ce61740f96265d7e112a1c04b0670ab3918438719d5826848d64632330bd4dd97b907df77f50ae2e867b5e85b8a72e67e427f885f73f" },
                { "gl", "cce2c549939447200d608e7400f06f84c0181e08b17a9ca4011046c48dd4b82b73f553531653200c40a0b133097b5227bfac5456998ee919815cff8effc643e5" },
                { "he", "410425322b3422ba5525bc444c702cf4357576daa0466ca061a25e64c3a4ed0edf0a2deb74669bc60759d2107fdfed8860a565540d225b5f154fd4584663c31a" },
                { "hr", "c3ac37bac37a97b384199547d2fcfafe968c3c7745cc281e8da80e9dddd366c2b326b77356c9fa30d166e0e6ba490339739149fab69c26c57cef98c5e7dc9f10" },
                { "hsb", "8f21bea11ad0d85b9494e3efa845f94a5775c072f21e468f397ec12d7f20241a72f2778a65ffebcccb6b1f1c303d82aa65a713c9f477a116287de85b7e0663fe" },
                { "hu", "fc45bfca7b76d6b8b003dd5ead1db924f312d260cc6606159273fd3a8c93e3529de5610e469df015f478874ba21207d07aa1605486c570985a2f73c0fd84dc06" },
                { "hy-AM", "f9dcc3544cd37c6e8e434c9933ab1ab3f8dccf0c028e9147268c33d9a4219779f3e78d0e408d2e5e475b3078eb2fd030394780ffe20a68cdbbfc67ac24f4df41" },
                { "id", "e4c9e7c78a722a4ba9dcb5f4b0ee8da5f3474dcd4a4535383f3a81dd7256e18b8443ad4d809cab263f99c6b79198c411c88578b20413a8f3de973bb18d847834" },
                { "is", "0a2ac421d315746dd32be390e40e0d4f4bed709071f5bc3c5264f551112c81771429931f64649ab6a33c59e994d0fc30710212233f77610ec50cf04a6b62786a" },
                { "it", "2c0e5067019c56d027ffbfc8bda028150d16f403b9ed4d77fa265c3e5366cba030ea031be2da58b6202f8174d8dbbb5c1f5fc9c86ff30a90927a51a95d041d7b" },
                { "ja", "bc7a6571654000f0252cb7816eb2178d23e8512618519c200abcc0882be9c9f22c0e76af9e37611c8d21c307ebccb9ccb511efdc645956db314b7543dedef8e6" },
                { "ka", "a5cdabcca403b75835cfde28fc635bd88903e808255acec17cfbf143e9c18f28116aad8e8e3eda559745f4d317c05370ecd71d0a2968ebefa1e9b9b97c1d6cb0" },
                { "kab", "727db14b6b23f2365eaa623a460ad724236e4892cf4511ec7482bd8ad98e5ad65a36973d49a983974ffed73aeb3711a50ea97a0610beeead5ab7e1d5cb62e2cc" },
                { "kk", "6ecc55d6b22065ff598a478fdb702a24b976f84e155f857a58c012952e3c095f9d25c9e19b505a306cff30bc1da2d3afeb18b3015adad43a3895a45610014ad0" },
                { "ko", "9e433df46a972afb5629d44b80f4d2f76a5fda3d790bdb8e615185ee95aa0e70b2fa714787faf02d4b458a661cde2f0582060285449c15c9ac7dc4d60785919f" },
                { "lt", "84193fd7fd7e04fec367a32a83a9afa39a113ba857482bbf7d286761fc633f0a8a981dea4586a89bf3d23a57b0887e044ccc367addd2f23954fb2e23bf43a698" },
                { "lv", "8fd7a5f722312a828ee6f07b8d1743883e72043eec9cdd818f12089a265b38465181f69e74e1cebc3fcecd4e66d122c9c86c3c7d86f42c1ad45a12b89db19fa6" },
                { "ms", "76e14e0029fc1fdb570feb382ffc61b7d0401c47c6b1d57740646d74a7177d7a68d3c5dda47e88ca15fdab7d25a964729207a410bfdfbe34b2e33c6af7f0aec0" },
                { "nb-NO", "24f06ca65d9ead24904112797c89bf201c6e278bdc68b19c52e3ece8ed019bab037893a8df54b1b50378ffb50214b39a8d0e39e74b52be868f8973657321f3fb" },
                { "nl", "d333a2db90d3cc9d0f836eccd2e3b8a540270ccc787a73f76fba8bd0ae5ddfb84ec36ca724c9396c8db4726936596ebdbc7edfbc04e6c04af593145833961493" },
                { "nn-NO", "fdb678b216b83e9ccb00700f8531b7e93d08348d421774b39c644ad570feb825187e7cd30c5af6e01bd0055e3623ec1111a660a481cb09920fbb7e76312cfb32" },
                { "pa-IN", "af54ec5bb4e626105ce9078455ae0a14b1e0fe8aa16d3e1e68a00aafbc3781047d1210d1094bae6ce4ca9217e9b72bb6265dac8704c9403f68cf3c727a051618" },
                { "pl", "77aaf24ac75262d1aaaf104cb050a001273fb0027430bad4b7a693a5626bd36ce7985920c7a79b40de75f8116a010e4b314f8be56a74bb18cb16d781825383d5" },
                { "pt-BR", "da640f3917ae66c928a05797b5089324119a9d6ab437bc7f6ec88635e71140b97b80f476769d0dfe9bc33fdc6017268eb75674d234f0ed0c2fa0f1a3317c75a3" },
                { "pt-PT", "c38a56c61815320058f4c7d1754bb1ae6741596152343305681acd5518370ca455299edf0d3d8a49ddddc40a8fa10a1e7aab3b7fbdcca3eb8f2f4abde07b5a6b" },
                { "rm", "2500e7995f646c4b4501f72b292b744ab0bd985d28a63471c5c8474f7348a33db55a3ba736beb371fb415bf173ca0d9dad101d5ca792a3eb3ca367d4bf9fa00b" },
                { "ro", "653c7ce363d6da6d75f7cc7be0b196cb6cc070b23bbd2295225d04a83860f39a2f44568acddd42484b055a5f862106fb6cb67713a52e16c6b062ee178a9e351c" },
                { "ru", "f337e38aad8a6c5b8ae47e4612092e164b1df19d8aeea68d9b927ba03bf7269b5d8a2247a3e4e7c30eb1044bcc86cd3992b423b29ee8347a017e97570e7eda3e" },
                { "sk", "7e4a909d947b87e65cd1ca50287704533be2f908363f1f914d37f6ad0974e888e7e5f9c968bb78307494d610397288da7fc7051a2f284a36f339899c747f82ae" },
                { "sl", "5b6c178f6c803a072c95e41a2481c913bf22c6ec86f657009b1894e117d38211fb231917affa33cfc2481fdf46effed132659cf2885782d7c3399a32f2eb343e" },
                { "sq", "034a83e6e3776c5159024408a790afdbe8dd2b2c7dfb891a78232d4c5cbe3d209026df3dccfaecf787969eaf2e0d151da0071a22a9823e7001a3da2b6066c9e7" },
                { "sr", "8fa142acb88a91e3bffa246c36ade1ee821e81833219b3cef30dbea5c4d30dbbbc3d53c7a42eb40277a3a9b8df86bc5fc5dd18cade7f9f46fd3a25be4381869e" },
                { "sv-SE", "53a67cb31c19e3d466a3d333a19e6904f05bbfdbd44bbb49696d20abe3576a2a6b022859de57ea7192a84b948b696ad6cef90d583bb8a398e64726fc5b44aecb" },
                { "th", "a7b21480b6c486ab733c1efa538b3f0af51b6f66a0a60fa8aad81e28d0483c1e5e526ad7df5016ed11964a1cf8cddf3b909f54369059c8d3fb0f6b9a0fc47753" },
                { "tr", "eee99bf1659fcbbe7d3d1672af768e8eb59c87ce4570ae65b8b2cc332e5838a0f143899966ee6315b90890663d95b4e0f8b18d9f2485d368cb53a7d6418382ad" },
                { "uk", "6289179eeda8f9b2dd0aa823e5fed2ea9ae60d5587fd41d7b51f2b5aa94b474a7e3b1f329297e1808afc9ac94a4a6e6d2b720f252ac9e648389c6663a40a9f9c" },
                { "uz", "6dc1cb4d5801e9d7ad9b61b65f03367ec4e464b9e9b4f448385c28b61463102c94c17c71e2700f770ee0fd808a211546e5dea132fe88bdc6b5a1ed6bf3a5dbb8" },
                { "vi", "d56ba813c418b8913db368bd68b0417c26efbb826082ccf05a8f81e47dce1e2f4e3ecf064dd8ba83ba79aed795fe7ebedfbdd3a3c182bc417b44eb543e2a43c8" },
                { "zh-CN", "cf6032a77fa2db62cde7952eb8f9d4da55b86e0ded37bce8cf24e0783d8b669cd7a03c73850aed7ef15cf1ea3d9d50ba80088209c1367bbfb51e8cd2c8de437e" },
                { "zh-TW", "756e0e5b2bd99e4933d97bdf9116522a275d285ff0a7a3aec1f5453f2b864962d686765da358b876154261cc81fa5990db3ebdcf8c401c897cefe5bfa675c87f" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
