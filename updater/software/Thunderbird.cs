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
using System.Diagnostics;
using System.IO;
using System.Net;
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
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.2.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "0688a35c856bde7c4a0463740d619a0ca497e8e2db659153d9bc64d5e66e5a48fa05d67bb0c9e7a56a1c45c4db8ade2d1df020afb211e957ee8a4b219d9d0333" },
                { "ar", "d43c3de55a493f3fc962619f10d3383ed97719d5263f6e306c92c41f5b995b9dd13b39485130fdae701436088a45145b5c4dd9ac36d67b2c72fc405862422733" },
                { "ast", "c89e439d2ba92ecc986fc5d3017a5ba7ac6d9f24b4bdf7cfdb86f99a8d964f665ea912167b93b40068625fdd46b3221dfd8f2fb2c1174d5d75d3683867c05bff" },
                { "be", "4fadb11221ec42c077382bb507176ec9066b44ef2d2dfa3afa93b87250453b6e74307990f14195ebb0802e2c1ac3f4c4fda83de132f5421265e3819e2d4f6ae2" },
                { "bg", "dd52427f3fe4593cd8a813d040bee490926f7992a9411aca87be40649476f3abf21dfc41d564b64dcf7bca5f19921ad1e75aeb7938090fad5f83c2f31447e4fb" },
                { "br", "a87c121c34d750e2fb4b553b8fd0be4609ee4ca3467d1416163d2f90bfabb5fc6d5cc218b4da402d11d1f8f6a65571b9c886df6c8ebcad13d4db648d80e10118" },
                { "ca", "69a996488cee96a50fb6c48be15bde4590fe51187b6cf2a7006995eb73df83c8e182022edb29aabaa521c644b578c14cef569d3d59e195cca0df86bb536da5ec" },
                { "cak", "014a66fadc50afae705477353741cc961c4391dc697dbe825327feb37f54ff49b73d3ed252089446a8a0287a0250b2ec07f54af9d29888bf739f9e2ae8002a2c" },
                { "cs", "ae9551c16c202b41a1136fadf574cf6f5f3ecb3ab360f1c76cee1c3beed8bdf7969d59e0b50830c4fb2057ddf3a1d7f3dd792348d735b54efaf1e7225a869308" },
                { "cy", "81f7c8393cd94bf45ab7adbab75fa29a3b47088b3745bd1560679e81e3740e711081229bfad05b870963bf6fb00989693ed33d73ba2e7ef50cb3ae56a3f8aa05" },
                { "da", "ddb709dfd2fe7405647fa01923c72c5f43e7b7fccf0e6f93fa734cd55a5ef1f8fb4b8c595a192a32360a5a1e4b29934706673a1443702ad76794e52d96d1822a" },
                { "de", "f2ee0be170f16727c92bdc0e08aa7db3a826ad03211b97eab222a080ab1c25fec725b9bebb8af9a43b7b0e96001d4d8032e13c67696b4ae0976874a1579f18d9" },
                { "dsb", "33a6b31ed5f3c7bb1346778d4fc36c2a7582b2c83874a7cbcf80e8c6ae4cd235d34b5b696667a0a0e0bfad3f46ba03eb7357828a8a4f7b02f9707e046a4ddc3d" },
                { "el", "af82ba994ac240ff4484f430efbee2f666f827a7d13a7ded1cf0c7b7f3b9523c9ecfb9540985edf79a44bc7f579ba86b5f1248631d24064ca0ee49fb13cfafcd" },
                { "en-CA", "e622e8267d4abc3f85eb35ac7aaa9f5cf1dfa57a8f242e280baddba49f40c11e0b51e755cbd8d73ecab5e995600b4e6c854f5fa69c9ae0bebfd79731df5aae24" },
                { "en-GB", "39a23ae458e77340b30bd200a9ea13245f7c25767ae0039ecf66ff6a9adc3eafb23b9f400ac542cf10b2d2f7618e6b72534e1381870a80df7a720cfd58591718" },
                { "en-US", "8938eb90fbf8f5af81c6dee4c742f016a60ab014672b63fe4940f4a0dd1912c83d928adee5ef19221e73f3af4896719887048cec214b44e7c3ff673af5c30f2d" },
                { "es-AR", "926c47821db31cbed3f2f2e12a349eaa55f40ce22f2e482f1b5caf43592834a41ee7ccf441d2eccb4282988af2c83d23c8e05357910ee69884557f4eb7bd3970" },
                { "es-ES", "9caef9fbe1d87d2fed1bf233850ce3bdce1d7ed9153d5b1ed069127fa0d7986e360b1822727fda66248840c22bd0c05249aea40fb8385603a9103664e5de342d" },
                { "et", "8fe4dac6abe422da6f3286360af0d6c73a2580075f0e4739d75472e0d081f1ba0c36fdcb80b956484e53333b22c9741730a4285d1e867ba705b429c612ca3649" },
                { "eu", "43796abe2ca30cdee97fc96cc162275d590de4949e0c6e9eceb948170d195f343332f80cb57f7fb4c7e6e7e4167900015b7e16627e28b90859e13427f1668062" },
                { "fi", "2b3216dd6c649147667564c94d1f77de2d6072327a9fb49023f436046001308964605a7b501f61f13241c8643ba06c1b14cd4c30c5f06e24e8cf59373b0274f2" },
                { "fr", "4a7026aac52bfcce07176f50c29aa5337a5984f29a5cd2fc44f577484de4d7ba384116dadc4a445ee1b44876c774345fef8b76a2317fef10c484f57fda434594" },
                { "fy-NL", "f15ea23f0dfd28889f4bcd2fec149ea298ef0bb22fe25849f24b30f5c1c21000214057175cbc427ac19159503cc5e18b782c3272853d3fe0c4b83147528412c3" },
                { "ga-IE", "56b66c71dc7046c484c913bb7d4b8ae666522c8728b6155fc472d115ee1edd46908193e2f76d9ec3c0ccea5ee25258450e5fd0d4e4202739344cb55408cd3c37" },
                { "gd", "d5de026a104a8e8766cc673da37ec03b6d8be00009f80acea754078c5d3df8492d557a975dcf5ad01a0e83d6182761e0da1062f8930a7c3ddf249e0d72d06281" },
                { "gl", "9fcc661e375dd8636d75791fe3dcbb940b50a2e5123d91dc7a2963df390189772cbe221fe2ebeeee7d2c5824c500185470ae750a355637307f70dc1be9e2c1d9" },
                { "he", "f5d9036cf66ea728c9b17fcbb355f9242829b2fe1fa622754e960064342ef721873385b4d6e2723de693a478f374ff996ceee3c40809e856daad8bb8713bdf92" },
                { "hr", "8b4c1c5cffa61c41ddbc2c12bb7e1b4d3aff693deac287f03296761e0ed14eca91b07366173f5d1f169b7a719a0c756ba6b244f8f14d10b10370081c1ed301b5" },
                { "hsb", "3a8dd587106f070f68ccf4cc0dfbfecf28314a2ad2aaa2d381e31b0e5e89551929a35bdc952fe982242248d37d8111141d1b95c3e3f93b4d6194c520f6f58daa" },
                { "hu", "1fbd7b74a5a11620f0c1037ffd7848761ca9aa98cc12a01aa525bfdcc40357c10495dd179b4e4ee13c5cf4e45b5d8fe551814f58f6bb62c6105b4468bd7747ac" },
                { "hy-AM", "ca90ae4566fce31c4474304af58484ed84d3d1d39fe9d034f87cccee47cba4807d196dadf7477e7e01c2654e1ab3aa164897cb72f27a6ee79c02ce54573f4efd" },
                { "id", "ff9b6c5ea85c2347eab2ea845da75bb65f9ab814f4c521b06ad1a8e3f090118dd0cd124a25089dd6f13837d380293a58df6767188f3fda78f1e0d4a5f01e1739" },
                { "is", "ac2d6cad90e76caf6283cd5867faf430c6ef7312d0eeabf1831c5c3caee120b6edf54ed241850262f9e4628154054ee43af1eaf4362a8d64e1d37da92d19250d" },
                { "it", "a76a21455a200ec6eb855405facb267286cd9d905d39a465f6d848b96ea39ec32c83e01c731edb630f2a77b542e6bf04efae695dcfd8f89a957220732e54204a" },
                { "ja", "065b5cd2d65bf2677d8985f0ab63011f984cb745d8929f542a7973c33a22c81710f7cb8e402fca7a3e073d86acbe4fc0b0fe0fc63c44a0137a2d8a60cf7e26ec" },
                { "ka", "967b92263875d4111e122804c0cba33af675c39ba9e8246dceb58fe0153166ea8a34991792f812bebbd1f405d0e617cd73c08c98ab8d0e51c8ee7c43e356d37a" },
                { "kab", "b7d6b45b1d860d26d7b3dbeb3ed2e324c3a860c39ce831ec5a7ecc23c7473de3da45bb9b3c2bbf7a1cab1ad71a22c0c8512272fb6e889e1246df08f9bc3b85ee" },
                { "kk", "e6a7639641d378d5ecb5a9cd171dc46c61b19fa7426f3a8bf54ab6982426b0525b3cf73185a0afe6f0d2e074f15c5e69eb97a982ddeecd4d50e6b5d3552623d0" },
                { "ko", "ff37cdf5152957d69963a660a7fe0e03e37b6b5a31bf805cafc428446b33632913894967c36b7e2a5f5fe7324d9c366765e2a4cdb35947d9a51ad486723351f5" },
                { "lt", "212feff7ea130dc631b2568aef1a60f7c6916588ae3398fb26eb2b19e519abcacfa8144620c73da261a060f2c9fbb1edbe3b85001bb4a64b155ef9808eff1163" },
                { "lv", "2acd7565c4f26e459b296ea51b963f4850c8eb10646d17ea4053cbb89c4a4bcc228c8326906f8296f04fd1e2603952d0daa4fed9646fb5c8c7d47c9890d6d530" },
                { "ms", "bdf8c9f0d6c78915a37fd744ae0f45a848f234ed8c45cf027ab4efaf8e13a467d3268fc45b310405f1746467cad4ea41d98cbe3f8dd3d07390f1fc509e4e4636" },
                { "nb-NO", "9005bb7e400005b95923fc0d7e3ab921bfb015de75bb2fb13a94013496d9d4da473be6698a3eccca91d0c4a8434c54e877c4e66185b5dfa3edcb21c699f0fde4" },
                { "nl", "fda015e9c9873eb7f3cef89fd9848f8a24110a8d7132f64f7a50d8d1de6cd7cae2f501b9527dd141863b24065b2b95422d3862bd10a33125c075abea075b08ed" },
                { "nn-NO", "d3812c6a310bb8d0c482781088b518b8b8ca3b110d8d3e5573026e9cc2ad595ce03160c5a19b7bfb51518f3add5b3b7e2ea92d226c93269abe04ca2d2ef246d5" },
                { "pa-IN", "98ae3df09124339361823e1032b493d543cbc2870ee179f03a7885210234ec80001ce590b3656b1fe474ecb0bb41181fe0756b76484c32295604efab95ec7e39" },
                { "pl", "c9b27d4a78588dd3e8c8d0438826d7bf8803e0be6946e8950c443b80c5d92421429502e8c10a1e754505690b1e863f93e4955f62ccb9216e3374d4f95d486be9" },
                { "pt-BR", "05131dc84256c3911d2243c55eb0ec3769898db0057d7a08305bba491a2febb8f4e0a8b3d0b7438a10f8b6ea473d5f577b2798799c5c0c003f3475a5f81f3601" },
                { "pt-PT", "db72b45c07d4b53f2971bb70152e7046dd6a3491332b3137386daad8ac62ec17ff1a96c3485f86682b0ca245257be15f4e54abf0c0f485e45a03097172109844" },
                { "rm", "83f345e3d19c5c863f78089a1b157d5ca9f74d37588e43b3f6e1739e877b48f13b35dd165ceb4f62b984857dc07b45bfb2287d2f42eae14620b99b6f9905b720" },
                { "ro", "7a7089aae6c19747ba462938a3e55a0c76ea8d983f29b144564cb24268dbdce7d9931eefa97b403c38ddcdb1ec66a8cf428a29179a77c067b729d1b3029a9463" },
                { "ru", "ab3fe7e6c688cbcb6d2bf40d468fe27674ec5901887d2b330eea0452dc028970b08e84be943f903b6e9ce243e43622fee8a172becb6226b83af083fe675a1074" },
                { "sk", "7329acda9c4a297879376aafce8489379f8bbc5d9c48669f7f6f4d941db92c8021c10a3145d72ed1eb2543698ace4366c0f5c2731e97fa7a400c01d980da05d6" },
                { "sl", "c163584970a0f00a9f9e4028080ad80d998f84b9dbfa0833ce6a7e9fad4f427e002c0c4986a063e0f1dde7adda96e09b5ba8377852f45d5aa2f45859dd1f8d04" },
                { "sq", "2174a833c272bf1c388a0e3c65b86b2216ec9e883ef7c1d92e057e24326adb0d376d6a2cccbc7fed73202ec14108aca5f88bc9c46ec5b5e3ad2b5a3048d73b49" },
                { "sr", "39b33e80b128a2aa016c2a234272bd502bdc3826c9049750770fb1a193bfeabe8fa9d256d03dc117107ede27b8167f44286a2a6fc970071efc5b51851bc46896" },
                { "sv-SE", "92f2854615c3c3e1f70c76645c32e75911f2612fc60c8b9446c91f7c3676044c6d9432ac319f38feef1fe71241509ba319797a3160d72249c2519e70026d41a0" },
                { "th", "ae5c26ab614c64781dcad80c69fc9c18a8b45782297f485dd77cff80683b6d9c3a343649451e0374437383e1d8ec0b391cbf675d47a82932a8f308d81ed400f6" },
                { "tr", "47d81d279c8c3f3b0d229d185266407ffbe4922cb8d401c915caa632399ce41edc3ca8374ea7cba8e5a6eada77325210384e1e1bfcd05d120554e7e6f5a30f5b" },
                { "uk", "7e9758df60db72aff092cd68c26a721bb5a6ec67a935fc99603ee5d840c1de6f35efb575067d23a3f56b097c3a57e88594bf48acdf3711a4e5f381ed61472073" },
                { "uz", "d34400c0100adf41fbd1f7ebeccb44461127e5bc5c597f7ac4bc33335f57c2f613e82490df9c19ec8911a7d2ea31e4e0ae197d201e1ad5be029c90d8947197cb" },
                { "vi", "8ef6ac67077a7044461c40a0b92a573257de68cb4ca7728cba9d093bc3aac388c980aeecc952736b0121a9a74b785a3b281c0edffbef417d57b643357b4aaf0c" },
                { "zh-CN", "776dc2a983ad3ec1577f728c2e76eb46b240f805b6bb34f3e8684aaca3555d5384904815f19ce5295465c6dbbcd1fd745c0aa00e576ee5b3c49b4f49063c64bd" },
                { "zh-TW", "2e0dd0cc853a23f4f1425e4d2abcfd9ba150aa4db7217e59723b3fcdb4f4135f2cb5d90dafe5572b5955865ca9e0f9a10e119b77a3ded731fce5909a9cc83d78" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.2.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "0d103f45bfeb9e0f504bc6b9b74d97ee99738b3ffe22f3102dc34cbf472f2bf30293b582350a6d0eee9f32ff89d8eeaff2e4331743aeec19bbea1eb8465c9306" },
                { "ar", "8c4b340fe50fa1998ad0996967741e993e4072a4fa4e198c3c99084cab3df7b464bc1acbcf203b1a709c365d2ca43042e748c8b7bc15f2b07cb1de5f47454951" },
                { "ast", "e98be4a076dd46923b184a89e652fe5cc522b701f50eafdee31b77a2bc22dc19b4fb416f84d68d248790797347a66db16c350fc7551425bc37d5d0d2560d193f" },
                { "be", "3ac3b622b169ced17caea2ba752b288d0174a9be9799cb6012503c4178e28043a7cb4bca2dc39a3f3dd6bd850d7d5f02cd0563113435f4d487e624653b137188" },
                { "bg", "5052f0845212c36553d5895c0423a9f728669f9159b5fec451d82f1d908d3fd074332bd2e42041848b883c2632d601b4239db65bcff7ca8b123cebddc6cfced7" },
                { "br", "3737cab2837c9f7d83d7065d96bb14ed66c021bf6eb35569b17e4ffc71d538c269054a4667d0afc339dfab8af8ee0701601b57c7e1a6915879409e0129adb049" },
                { "ca", "811c91fc8903491650a1e6d0cf4be97a6ce17a35fb62e61d223fe56fe03aa61b94ce825af992e0c780fd6ef5dd290b23005ff2aa9ddf488d0e9d599a88addbf1" },
                { "cak", "a2d6e688af85ab1b8141f33a445ed9f5bd524402008d6375024642c9477ff78172bf33f3092d72642c981dacf540cb3298f0fdd578254d571ce4e7dd0eef3d22" },
                { "cs", "8b108ee2960efb275f16ab734379c4eb60ecbf335926deba89d2d6af77e0ecc1d9bdc020b7f87d9447d03a8caee2de351ceb30d70257f1e5832bd7b0d947b163" },
                { "cy", "d91688118044eebab9441dbd9b700f362945ac41c747b1de6dbe7620703affb327362d2c645d133d806bf542f39daceeb603e868477bcf8b6d0b236d908759f7" },
                { "da", "db38d290e730f9c8b656b6f2fe57c7a54961a44cccd42006ee6e27ecc4a6df6cf62521f6c8c636ea3745084f944d6f21b9eb13f65f5c58461e42891c1b272bd1" },
                { "de", "415e763f0591da06f61fe12932488ff039189e1f4813e1fa28b504cba2cf819639be77c4275f6b0e49eda6b40cf05e0afe647a422d087a1339f229e4051dfbad" },
                { "dsb", "dde15aafd37d9dfc1f66305f3f95fd2e698d4c6ffdcb7162668c6fe686bf079df149b0aaba11e14301c6b92dda216a57e78b914e9abf091c691a222328fbd894" },
                { "el", "afa559cc4fbd2dd669524b555e0df9dca803d8904d6a7484f4c1e66308b9f873c4b51c58167f8e2f4cd7267699a718f73cbbc05b9a395cfbc6317fade2040329" },
                { "en-CA", "7815d070ebcaa8cce62cff0b2325d5c93a031ba4aaeafb348baf6c3f12af681f48d4fccae5db19b1e810bd7cf12dc9c01ecd0dcce0b7aa100fe0ff58238cdfac" },
                { "en-GB", "87f9aa79279497dd1883834dd567c0b4125734c38bc89917364216bc67c5ad997b4a10e2a0279e9010e146d543221ee13ec9dddb3ade136a008c1aee615144c3" },
                { "en-US", "bc67e776dde72a530a60fbb7eb2efd5d420ec078847a579f4139391791bde5f3d052264e28d777dbe1e72def914429803393e0669c4ed291f264e785b34940c6" },
                { "es-AR", "3344c13fbae956be799199569518ce156c5924d4a52620a4026492897191b87cf3f56e9bcf6590272364dbcef2a0e4d14dc5329c545dd7bf385c980d269424f6" },
                { "es-ES", "a797c95a8e6531602540d191ab52803530f8fc8797a33e8e8be3db63c5d8f4a6f3464488478d5e59ae825c8fc154cc329d3b175d0454471bcaf8e4424825b254" },
                { "et", "9a3cbc5ede7e6764b2ff31e3a12eee4b45454fd10013dd35ec1e5cde8c0c8b093530084883d7a05b6d512e8275277da1a46e59279c652430a0bd4786d12e314b" },
                { "eu", "b0bae77299c84c932802f251973d5318697ca2817d88aa440610c351d6fb2ef76397fdabd3bb02f976284a6758d7648d05c6e870fbfe3f09cc74ec61b3533a30" },
                { "fi", "784553e193629381c86d65db1af696ed8aa0f98bd6828edb38d2c43d0a102896d7530b0dd484041deea283048b1e71f83d7b4f810267b5a6b9489e92862cc5e4" },
                { "fr", "7f7917e37eac1b17f6da2a5575e1a59f54fc36c4e794fcf967a3fb4d4ae257bd3d9f4ea714624d80099735948e65d47d0b54a5bf2d9090fcc363d7e28a03a1dd" },
                { "fy-NL", "941ca5f2a059a799b927f6a5fb1b121eb7a2f6822f7286d9e1c3ec18a27379d5bc6ef99d4f50ea898c1532ba08b94009737a725c995438de9a6e300d0bdd63c5" },
                { "ga-IE", "6400ceb0f7d8042a99205d3b36ca3a4c94166c2929eba997403029be732c151d383f2a75e660a0762128c26a635f24c40cb53259171ae9466f9979118c7fc9a8" },
                { "gd", "318ebf7c4ffbfcb634b3f8385fe443e58b9b07aab02b56757e0e2ab2eb7660d8ea3398b203f93091b796d9a873782f2c1c570dbf404707086998fe3abbdb5cc9" },
                { "gl", "75cfbb63ce31f2c14c70789c8529f9d4ca12c46efa6605cb3406df0d97a7a1cf7bdc637ab8d22ab9618adc9f860d399004b07c6dd811b7e2ec83a16cec198cd8" },
                { "he", "9bdfce8128689a8d319f3842ddfe581046e18153dd0006f2b5bcd87d82f7d451840fa6351faed97173aa5d8edf573009858d79f96cce7813178a9968e23791fd" },
                { "hr", "13c2489a678bb45a5c7265d6ee9881e10b3f5e4f2f6ae1c7fdbe7d08da8716269dcbc7037fedf9ea868e5f50c409c019eb10808dd1b2977cf0cd574eabe191f8" },
                { "hsb", "6fad7ff02a2588466ad7694e15c342a4651cda1a5f7f6dc88f78faa78a7d29e96d1a7435d87413caf51848760c1409bac31c96ffeffce778c935a6c662ce375b" },
                { "hu", "9d1b92eeb2b4e238c5a3762ca2f9b0dfc82e322f155ecd8fef7e46f4efecabbb0a4b4ae78df529c95c6ec14efc5fe161e9ec9e5673fd0ac8a60faf90f84e210d" },
                { "hy-AM", "02b30914229c474b93d088f95a3c78ebe10daa4f49335c6979480329b11a9d3a40dc462e77bed80622e8fa8fee1610eaa7efd9d387aa566a253b63dcf3dea931" },
                { "id", "b7b7e85aeb69a5acd35dd4e087ab356cd79bb6ada78d79822b61b9680cbaf8b895200bdab84666ec590ccfdc0ae03bc7608f3d65669f25f6489944e0d6c41a2f" },
                { "is", "04f80d1aae7fb559f8702e6fd2fc35aafbadf214838a90fb4c028a6b08268a066451e0520922aa94b4ddea081c6aa358782894344c076af02f44ffa5c89c0125" },
                { "it", "8b31556f17b8275b34b445da3c884164f5c1344d1bb56646450b3d7f4cd3bcd6786168c241efe17d1f739674f4020884319cca0f329603ffafc92d071da03784" },
                { "ja", "0ec2cc49bc855d77061a2bf7358e1f10f49ee72545a60e253b3a52f7301939d5448f3d4fb3913315cc076a25fa628e0b562d1a6b61d660cff950ce33075c8757" },
                { "ka", "86d9bdad9e5595d9d9cd107f310545e8e87c625691b2e30c5b39c66a0b534611bb763d2e2614d88be0161b389bfefe6298b75048c71b67355fce12167abaf114" },
                { "kab", "2b8e94c085e897d701d48271b2bd2531fe3f4011e54286d52e4b012bd535c6b675210556498b73d09f98b953e9e355df356116eed47c12d8c1741f70576d7aa6" },
                { "kk", "8917a0ab1f411f6fb73811092bcde2acafdcad00d7b6ee07bf8c5a8069116b8708ad9d768b55f5ed95578c0f8d96168b7c9b33a684c65c560f4cc4526fa3955b" },
                { "ko", "3fc73693a5c9294bc755d3904c514ee232c8229ce4191fdb361c40dd030c2276a74b42c26e2178abdf3ac15e8b37c5890560f74caf325fbde76328ebcc0b25a9" },
                { "lt", "4cce44cffd1d200168159a9ee298d4668c8eb019f3b2afa86dbde4ac62dde49b86933a695ceea4f52c6076bf3af8be2e2c53388bb8d13c98dbeb34617106d2f6" },
                { "lv", "8af5d39732774efd79e2e7f0bc5e712cf571d9b9e7939371ace0bf5d0d06312fa95797bbb77819a961e89c75234669915be177ff4240222e464bcb3d2ebfc297" },
                { "ms", "f97d319bb42fb7f4d19c054b055ae4d2dcca7c7d7ba1875d61c77f84b81e2268cc69b9ac02aa7435782ac6946e5a1f5e5450e906c8b4920263ce834bddda22e7" },
                { "nb-NO", "a3030e8aa4283543a676d457ba62eb061a8e24a1c432cb7d4308922182e9828d9f482a91dcd9b4abb0991002af831b7a91e0abbac6342ad9c7f8544363bdb5d0" },
                { "nl", "d7cf5cebd6d1f5b03f5ca0e0b4b6b8cebfe8cc592d25c28a33674030d1ce8c091053c65521b2cf55cb55d67408ba0c101c2d6987b0f73c0f384590c0e80680cf" },
                { "nn-NO", "597a888779663b279b560d44a30da14c0a7b33da9306920151ce3f668291e142f2a164ee70b6734a6ddb97c1d103ce22db5d75b46cd547d5f3c7ccd1108216b7" },
                { "pa-IN", "80eedf5f5ee67b8aa4903533d9eddf0bf4b4a2b407a12480ab13e97a51415f8ff94e51a253c2215a09bf2d142e1c0a851e6791ab374dffb3dcbb990dcd0b953d" },
                { "pl", "3896c22db3e57a2d2b37530832dd74287bf762d65bc30ce753d7d1d9d9dfaeb165b5ad8be3974968208518369f6f91ed0088f5efd7a09230e577cf9848d901e1" },
                { "pt-BR", "92fc53b0df5ac4fd978cea44e4110f2ed75a3963ebd5e43cb9257937540a2afd59f8d0fe388828b085ef95774fa4bd7ae9c3794ae0876ebf09edb064c3b76dd3" },
                { "pt-PT", "fa41241f045b04bf3cf807f5170b038fb50eacf3cd4931bee3d86dce1f5a827d8941158692b317e16d0c0c3ae330847d1b3cad42a7f83052c210e477055bf1c3" },
                { "rm", "10387bd708e811cb42fc316e83580d9c6956d26d9c4cfbf125ef6dcd5bbff0b470e8894908e867dfdd90102fb5bb1892131201af4b503e3536f9873ef4a13a6d" },
                { "ro", "6292b281d64953d089cc7e139bb4062999e0e7b14f2205e7f18be173f3a837ad997e79162fd592021246d683eaca6a348f868afc14b189829d6d225fe11036c4" },
                { "ru", "c08c2e0f499273633bb6c30ba2047b45901dccc017b579cd62598ae3d06b4e8f1cfc6d9123879a053cf2121a6e260749086f28672e45ed25a5fb842bec7635f8" },
                { "sk", "5c7926dd7cf8016ddde9ce3f8c2a45f7ea33e7ed2f1f10d05adfcdb2b329bb72b5b06b9a5a1f705dca582f5e0da6e5b5d698effb1bb0c74e53ccdcd5619d5177" },
                { "sl", "8749838401b5e5e3f7bffb60375dcf18a8194fe802b1d88fa1e8ff9fab68a80dcbe71c934b9c27dd0e134d26eb6f9f2823c90054f2de27eb2c33833ea63580b8" },
                { "sq", "2a912724ffbb39726654fdc276ccbc3843f5c7ec7c206750615555746ccc8a7214e50d3f1c2ed7a50eadd163a8d44575c332e66ad354f431e172c34633111eae" },
                { "sr", "0befd66814628c8a715225bfd11ed996c07aba6bd258bc578c5c9e4f8bf74b8f88540663d79bf62908172b36bd7d0acce8a8d926fc469b23b48c434cc74ba724" },
                { "sv-SE", "a43a9908cb9a7b365eaa0f16c854f5095ecd35863c4a1edb87cc79a65b08d82cef49d96c672576ad7a9d9536f61bf26adcd19f0c5204994084ee0e00efaaffbf" },
                { "th", "d797ebc52c03f564b9eac05cd8938dcccc95b7066ac2cb5801841ccdd84cd3f2ad14eac9be8a76139ec66ea5e2217e8e972d568748310669729c180972cb4b98" },
                { "tr", "29bdb2b988c791913b404bb1165c07759b1358402d0b6cbf87b2087fc6f767749417f6c115fe362ae5f9037b347b121b72f5cea72e3ed63eeebb0e0a4c028656" },
                { "uk", "e7e3eb521c74603ee3396ea9b1f26b4f96ff40d886700f411e4467e496ff0897383f721cc56aade2cf7c9b99408715da2f4d3e1be1c4e6869aa409ad4128e747" },
                { "uz", "819820e7e99f0ccb7d0d55413a225636c143cf9959aa59e8c4e8380b01ec0c44487ccdccf98a8a4fb5a025f0b626a9b31b45f741407f1298c970a7399f73fd2c" },
                { "vi", "1e2ea283b634727dc9cae72505f3ccf7e825dd509b441adf65de309431598524f0fff869ea75490c977da14a61ab945b70ec31293e145146ddf1d6691ace05ad" },
                { "zh-CN", "24db4a80895d4c5f68b0c9f88111d15396ff802ad14f6009b9d7dacd8f3612f8f2b1053d40a6de4f9786e4a91ec2c20b9b7899946ed28108d9efb89241d960e8" },
                { "zh-TW", "012445268f37dcc4086702c3f44384afc169e9c459727acbaa551794df844e9cd4be9d701f2582c6ac37da1ebf41a30ebd92afdcc16157c21d833d2abedb4276" }
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
            const string version = "91.2.0";
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
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
