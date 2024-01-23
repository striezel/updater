/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "94ed8e8407b3a5042f33b48d6fd0046ea4ab070d31e15eae8c17df689d30b509bb88d38337d557513c49d645f8f411e34a8423d4aae729bea33f670e8892e29e" },
                { "af", "13c6cf78b8ca62989b6cf678e65753d1907e712b4ad22c2a8b2cf54a3ae0c024d48532c8aeba9362bbe10ba0d0d9863caaadbec39ab45b6da665f73c350ade51" },
                { "an", "34ac92e4b47fe0391cca0d87378cab604fedabb1c66f8961062587a2141931f44d0d4a144fc4e8c7924774895f127fc3190dfe7e36a4dd559d3c0eac68d8b507" },
                { "ar", "ba334b776b50026f2374c7d8badb1f8a71c52bd15bd7d317fc3f2d1599d1a8b5497b33d3739c087ecd435af10df386b46c72ed6119954f34151ccee91c83b6a0" },
                { "ast", "bf077c89685f636d026d09c43be4ae267f727b655014eaf2f53211b07604457076fa585718c0902911d2c566920ef5c6413413e437f73e4573e6f5cfc56b5ac6" },
                { "az", "74ed5965d5852960a3d4128fa77d928a25343f0ac837474a2b7ed3f6cb01b136b4dfb95136763ac665c3c40e3d60a17dbe0aeb6071251bd6c6354a893362f51a" },
                { "be", "fa0269727f433c1ccb9f92d0657a7dd5164a8185eeb841da7104a5870a2fb4d5ccc3efdec52b37fb77bbf8867613fe3bc3b31936bd57819ce5a9aae0614f9bd7" },
                { "bg", "e2ba4271e1f4e4a6688b3a0cde526cb3436e1e98626e429b39a7fd4fb100cb26a6bca7cda8d689f59be18b3546b9f6705effe6528c7d05ad45189ca3dd20aeab" },
                { "bn", "08bd045d3910dad1dc98870a4b0bc72506387910a5c93ffed92a52404f89f6182db2f9f51c580f0186d4f0842339eff2ef4740cc6434c3d3b6ee025ac4f46933" },
                { "br", "16f22e3bda0d2b31f24577d71453d06e2de3af73637ecbf90de6e762cf0f9eea7b2e0d09efcd7c75658b6355f3437c844271cd274f9afa349bbeb2c1ccd7156e" },
                { "bs", "c6c0edbc69b4c454af009b8ad2c58600364cc7b0c2c8678e2984e0705bbeeddafecae2d7bd0e3ace6698c5bceeaa84a6909eb221b6d0887a94bbe4b8a54ccbb3" },
                { "ca", "bb8c59890f8263b264c6e55929df8b4cf073b61c94fbc0bda7303ee5efaed17f2e84de4db7f05954e614b3f27dbcfaa8289f213dc308de9a79f770a5894d273b" },
                { "cak", "d73a0a73b15bbeabb801233fe3206de7e717f51545341dc2f2303be05de34cff3326022e26d12a94cf589865e0f656f37c5a5d2cd3825d8fc6c3148963dc62a5" },
                { "cs", "53d60b9d3cdf81f4c2c820443ef5ae81e89c0e4b5e3d3011382f8eacb787be1d4f850c3a71fb5d1c109f17fefa1ec9873ed92deb0ae6073a40febd4f4b8d6018" },
                { "cy", "948a894f35a6483b149c3013f21e95794ff188ec750c3b96caac6233dcb2ff5064ef6b64405acddbf8a211c16aab11117474bb8675cd518eb3525152c192ade7" },
                { "da", "ac78fd584a6e0555332e962c8de0322d7616100807851419c5ceb464cd937b49aa11d7aeb810fb6c6c257fb00b3d1ed1531e8cd92e03450dc7295d58f062f0eb" },
                { "de", "e31395096670b91cfca8aa5cad466dbd9d9f72a505be61355596195c874e881025a3d08020c39fe5d886546a040643f3052317f664671f35d8aa2909ef11cf99" },
                { "dsb", "7dee783441075a45f2b73e6b9aef45a0aaeb3bf8ced9c4f2c640fe6b4328ff861310117d0232163562cd05ebd12cf698b5308c52e4d066548f9fdaff427faf4b" },
                { "el", "aa8ac432c118a1030d5aa63c03d0270ce8a25befafaa7f7320fadc033af2d6a58ec9368016781004541178e06d833193093b2f0d9d2b7827e46cd9957c904ad7" },
                { "en-CA", "d3fb6b04b749c23dfc6c858d9970e9c15dfd537542e0779ac35b1cb33f4109a70da88ad478dc8561f474b9715484a94b3abff2ea1b8ed27054eb36741b89aa00" },
                { "en-GB", "965f04989a728269f7e9ff31d31dda045f16340b4d95e9d38645a35b7bb370812f67576af95d17980370aac99b93187d5104d3b4c9f968dd9bede6a09e2aecde" },
                { "en-US", "a055ff4c39b01f85d1737323d3e6c6ad5031f3190c0188880b185de5ff84537bebca1231f1356f7959627d95412cda127f6b082e7fbfcf61263f0a0e553e2af2" },
                { "eo", "53940b771d05ae44849d3ba6547c3bae49961db3ae596eed7a7a56d2781d22c3822279511aacb10921f55b115ecf342d6530dd03108343d3ac210c2591db6793" },
                { "es-AR", "f7ef792880f6c48ac5c2fb06bf65ff6a97453098b4aff3c68f68c6431647da187bcbf144443d8e528995dc82606afdb1a32ba3e67e2c7001d1c223a85be1481d" },
                { "es-CL", "c12dcaea6751013dd40928fd638761b68837692277f127969c28719e791c2769ee3c4cc6e8d256a5b643288b38851d34b9d1cba41de9566cfe26f5681c2d17ac" },
                { "es-ES", "013d3c5d312a3c9620e52b335e16a32fbe6b98c2138bdc295d0190c1768195d9a162d8cfe76ada6c6be2012cbfa41adbb32f6a8650de56c909fbd33f05b7a9ef" },
                { "es-MX", "b2af92d7f6ef3a06eea681bf99d9dacd7c849950386b15489ec54fdd9bad4d13a22758c13c9bc36304b68aad8340a43bd5bd637275fcbf85f8eb7c8648112be7" },
                { "et", "ca1ed1385673408e92905593f09be9d15cc5afd15635c01a5b2b8adca1e7a826f4cf88d9a576b44f51e1f262438aa0772dd8e47ed8523c49d02406b2b58a1f2e" },
                { "eu", "bb209e853de3866514620b303098a44231b5e889447b5f6d96c0111382f2fdf9907df5fc2f98254e607e5bbc7bc2ca447b77b79829ba03af9194bbbf2ee7eea2" },
                { "fa", "2e5690309e10f29d91e825ff00c9ee5b7e70cff8a3892681393da6ac4e1668abe415afc23b750117e6c977c05752f0b7a4656870ffe9efd3e5294b2262c1a5f8" },
                { "ff", "ef14643c0cfed89fd089da876366a0ff87762141faa4bd4d1e0ebdf12becaabb872b36b326bab35dfb1fd22b08a79bd65d016375a673c1647b426d0daf473c90" },
                { "fi", "a1ca080b659a165f3dc9d5a257ce67e20d48716093929371c21bcf850a3ae26c6eb5442bdb07f638bf0c00c0998aa165c14b9fbfa6a9dba6ed5cba76a2239e52" },
                { "fr", "8d646fffc78bbcdf77bb737a33cfb9a13e0bc5cd25d098087c8f25f89ce100bec6cd9ddc1593439f109ef1ddb522ad3d3ef3c3e043a6ea2348dadda0aaf361d5" },
                { "fur", "6cdb00fe10c3a9cb59f809ace295d4fc4bde436b621356b7ba138f7eb9ccd08e03f4d7389053dcbb4c32701fb7883fca3c5866d772d2aad731af8807ec1432a2" },
                { "fy-NL", "a31e40cc8c1690299cc1a0f8bedfc819e7f198a3cf6ed0f9fa4a25aa2f84778b6f744e97bfe000000c2ad4fcf018384ec05bec3976fef4054b1613229ce70870" },
                { "ga-IE", "260c8f4f9961fc3664aaa451c3cd573e497bf38a7cf0d3c99232335c0cc75f49e3fbb8cb9cd960debbb616b19576b67315c8e889b1ad7de9ad1551cadd8c8857" },
                { "gd", "ab2db6f98a360a87afe74189dd624f12de814cbd67570e7e02d87bc19d8ed93e599fd13d0eaa4094d6d03d7c93d8d4799d36b45ac90801e7898d892c3faa00a3" },
                { "gl", "661c0bfa59d70c4c88ec410a4a34011027b0049a5e7448bdb35960603a2b112323cbf97083e714b5634dd92854b68163c6dc7fa705ed04aef2be1a7c2d215b22" },
                { "gn", "d7160f7867b24b9e8908dfe200cce357ee6392c2ba9c3b966f5bce7a2ec3b3df7fde961a5780b37465240379fbebb92a43e36dd61ed04b865f502d4261d115d7" },
                { "gu-IN", "d21de23f1a3c445cb0adc882ae99f271380f5734ef58612cd4a6986cffcc1adb476bb3be0b1844be48903e057cd94ec0e4c9ef17378af764bffbfac6d9654670" },
                { "he", "cd9e53f045d97a0ce150a09f5b5ed1633adc2934cbfc9c80f44853fcd9a0592b93afa049c8b2abcc93d3200621045a545a3a1d26b6086cd43a8df22905dc4f95" },
                { "hi-IN", "0ec80361f6881af27aa8b5ee26a778dc2c5d8e693d525a3559c6ecb7e41317660b8e9a530b48fb1fc5f2fab25ee3f7d819b9d8bb562803470932319f48a01253" },
                { "hr", "f74f0917772ec80f219945d750d4767d5e0142aea4342fd6dcbf5935e3ccad6a135faf03c67d0cae47a95c3cbcad9087f3aaa404e1799d1a51b647d24d1f583d" },
                { "hsb", "c71fd639937f4987e5d9faa9d38c2ea8e0b360319dc2df809090044f9f371aba94119929dbf126f76aa516e06f7675031aed828d413818c4e7065539322d0d47" },
                { "hu", "6b8f273a30e1ecfd76c4508d7dc98e1812aec11a4d55139d6355df5d16bdf1727899ff961fe4a1a4c012956be2ea8c3b83a9aae86e8b2e926c8dab14ec0d1a79" },
                { "hy-AM", "b02883d2d62c3d7751f6ed8f879039971521fb92b6f3910a33f7eb298dbb189f9944ae5efe0b5e31f47d02dc51a7cf2ef958de5eccbd32ad10fbe36274e44961" },
                { "ia", "1251354e6f7300d4238283f4fcac6c08d8fc468cf246cb924ccea9f13f8fa66e2076f24b210e84872bff07739e0ffc9a8f77ad475b65829533b6744b04bd7aed" },
                { "id", "7b38c3db05769364bf0bcfb6c60222ad587e01888d1bdb3d63d4799560d85bb2288a54b2d55efd766d38402c2e9976dd6e760ca3a5606ed648c513a490b03c68" },
                { "is", "86b72b4daa470e2e0c1a6f03cd7b68220f92c225e5cdaef63d190f347180b4c1bd5a06b7912caf93465c2ea77876e0805c256ba149b4c72c5f78b8d7ff809583" },
                { "it", "c429058f2dfb9a20999adc40c18e30adf99548adc7f09c1efbf2c81fc769270f485a55cb4dc04c8e3dc49d7b83cf3a2f68e867391e1836affbb74c06bc364ad8" },
                { "ja", "f8aff3c6142535f1ee98e21a417c64c9754e79883687729f1d3881f57c023afab4f2fe45b6645a9516edca4f73fa2f87d5f05b72134844fc82a99e8b8a0d2c9c" },
                { "ka", "27f610462fa49020dc08c952b9e7b92b0e04d3f5dc675d75dae3f79a931b3c9359648e3a810f06808907c6bed16c898c192ea3637fe6036360abef8b0a6c4f8b" },
                { "kab", "0f0c8a75cf443e2e756577638aa5c774b3d67610a7ba3b8b292a87c9dd10aa3d85bee74effa7de17f220816bb2cfe58f31c0c90e83f35918704f8c4166e71035" },
                { "kk", "4405ef81fc273c6197284171f235264f24ce1dcb621e0c8ef1f753c4c41f3a712a17766526a443d036f1a1bbecb9c1f2dcb6264cde1a956f7419f45d011fead3" },
                { "km", "33e461da58c32d48c9fd2a17ffaee4bb0a1b1ab81170a0137d0c97b465b0ea85147841787ff07a4e144dd51fa581de7001792ce42aeec3530e341a3d47b34291" },
                { "kn", "1735ff340534e1e6142bfa5b6097c6f7d320f57d519d4e929febbe430260cc80b3ac5fb4f25ea72aa10ab8ffb969561d429ea6700cd39bd13b63d288ff8ed92b" },
                { "ko", "0a4a403903eff86ec56874d1f1f509baede424f29992893935016993c83ab496acdcb56ea2bf1fa1a40d24a4cbdd506a5b9cd2378ec4dce92b51c8e94505d011" },
                { "lij", "2cc4f3defb4520f29d8872fb35dced210d1ce4c7fec66e2b31d72655da8dbff6a71933932ba8b5f07de913b9ab86f2b3379c1283739e6a40b46f0dcb43c581fb" },
                { "lt", "d939391376c9b2666be37440086b256623450a3528728d38e9d1293fecd6e59f5ca936d148f660529c3a458877baf3bce05f04f0d8c5375a6a93e9dda6d0415a" },
                { "lv", "6a74c17399222e46a01bbaf53fbf45c19a39d4247f18ae989bab7ddb448efeafc89410a369faa40683b41a8239b6016ca6eaecb83482686e3bcd6410195db59d" },
                { "mk", "9778a90f70802f7554e9a88ef65e4df8924d5672d18da5e1e36c5b055b5975300f2e1dcb8716982cf7e7b73c0d4204158242310f50a77bcd2a70bd8bd6deb01a" },
                { "mr", "87a0b808b6b8d50e922aeb2353ede5382114a2e1a1e21df996c6c9efc34633acc1438ab86afe5fca214afea71c463106c418c92182bdd88a31ba1250acdc8eea" },
                { "ms", "d4fde87b96c730fd1acd92b40cfaa719aca582c5949879927efa63f79a291f3c7e412c5384c9bedec821d5b8599fe9ff26b930b190e2f518cfaebc10e258b082" },
                { "my", "c5cf7d89288182cf10178313295f3ef92d748c3c4e8070bf53a3e94afef273b8ad10f4eb10826fe8452cb62d6fe7d056a28ccbc079d1aae2c225bf1a0c1018bf" },
                { "nb-NO", "c11784c663283566e7b91347d2b6bc10cfcdfd579bb685b33ad633575cbb2a343ab04938bde9444b480826b8a70e0862ec962c0014b3f086fb425367fc11fc8a" },
                { "ne-NP", "8d3bc6b7be376bc39384051fc72eabde3cf432638acf09a67d2857d730d80a2a535fe426bc27d7f1939e0345b54bd02fa1e9180b57719360904f645041831282" },
                { "nl", "5d1d2f29d6cfb16c63c1005f054871d6f899456830df4932d8c10c1b2bca12c47ba358fcfbd52f9b135a60fb8adb4fac2c5c617852ea2ab45698f52e726d914f" },
                { "nn-NO", "676f1be900557fc36b61abb34f3e7075ce6ba83259d6b86da6ed0031d6a0ac89cfb329e46bc61a6686622c33766d7fb34890da43326f8488003501ca91fc5630" },
                { "oc", "3a8c376353ceca33f17037084b2196deb28b8c9349f12edb81b38500056e7f65b6525ebf3fbe12e5fff60690793a374d42466c87da50e326e4a2a202e149a4e7" },
                { "pa-IN", "61f530c0a2050560c221c47f1ba741cdb938c9d77660111736807243946591645608a0d05cf8b2cb0ed1d0613799434a5549977a1fc3026da29a146190f22de2" },
                { "pl", "092979a4f39534ec331728e3f5449c4eff7e3ab239532409c8433b57c84a465b182d249c2b3d6b3a1396a73e25bae6b8062d9b7a62078f7eb796c1b2fbf7160b" },
                { "pt-BR", "f49eac6e712beb05628fe196ac7e9b6ad75a5b80a58d36c2247eb8da9692afc3f272bdb973bb4f629f1edb6865aaf20b8ee49e6fe49da6bdd70f26e35b96b6c7" },
                { "pt-PT", "ec2e39f1d40e3a9931820343947effc3f03cf3c3677b73197446c005f891dc6f13bd67a5646ca359b2b8d3d3a971c1d5dc8da669d4f4ef711e64b10aa19d7b5a" },
                { "rm", "5994d63f9cf5dec4cc3d47262c236d8463a074ec4ae0437b3e859ca79875b146a2d0000f74220720e208b187c531b7bd04d283f9069472296734d665be745008" },
                { "ro", "e0e8c23d2b029699dad4ddbdfa5a5db04c28e82af6d6eb8cf495db2727b48b22f87e0d3d55e2695c1b974335a67f9442ed3874ae8962331f0bb5151683ab22b1" },
                { "ru", "411b81872855d5a4eac1ec3a047bf62e8a46ed606d2935c6984265cca773c2cf6f1f0b488b2f9d83a3d0ef6ca42f40a3bcc8e77cd57b3bd5330f19460a6df319" },
                { "sc", "c7eaa998494d0ae854461f41da060e2545925180cea149103aee03a9d8b7abe683ae682e38af7aab9d2ecdeb4ad49095f4090f86e76b7507db71ebba6a284840" },
                { "sco", "357f046870fa3abd35a9cc8c6d765e665dde548b93daef49699346ac07ac395ddf2e4fd8d9458fbe101761e452fe733ebe57faedd04c94f5d6de5631a33de01a" },
                { "si", "7449125105c01fab27b139e470fa1c42ef4fc54a5ca49fee47da1943091048ffba9b7f62758248c6095da771b522fa8f6cb728946a512aa9e619a95472d6c68c" },
                { "sk", "20cc27fceac21f5a0b1fb0d950b57a436fbcb9bb3df94af83c4484a879183cce973016fd40582d23cab0db249262f9686e1783c50a850f4abe7275c28147b4a5" },
                { "sl", "880dcdacb62dabb681da05fb32dbfb917c78fb75a8b34d6e6ffe684a91f203ea8baa4bf5e8adf00329f9c41a97f8467630d65ab45176242e1cfcfbfbe048988a" },
                { "son", "6bb5b80c6405e9dd7f2da0e67dae6dddc51158f2d3f92c071dfd0861532bd4f5efa12f5bde769318f62cffa1300c1e3fd03452761c44b142b2e13da8b76d162a" },
                { "sq", "e123a42dc59fbb511284b0dd13c44d494e56c0b9542e1a699c4f1af5e0484a1dd1e2af2a43edde7e8635ef44e3431178dbc748f2978334237977dca8e8c3a487" },
                { "sr", "4c5df6b34c5ed2affdc9d28280176f23a9a1dcaa7d2c53902191c2648e6521e70d82a27364f9c5e6f8daf8813f39bfda5780050af0e0f100c9d57cb772145938" },
                { "sv-SE", "7052bfd0cd3b2d03b651fa59dc0cfd11dcb31428ae1d14d9263ba3eb0a48e83dff71933bf0ae4b65a4a293d1ae092f6358ed376444975e8207b741fd459cd814" },
                { "szl", "60b874a403e7cfa8d738f021f9ed92100830328ab6145966d2c258c53d53399d4a5ec94aab3fd9e2f8421cb4c8f9296f3d37bf64ac06e297619cc70abfec0876" },
                { "ta", "a48db989207ab73de0bc2174b516de8b289b6c67ae555d0b32d2fe24d4212d8361182f634553d1819880b70acd295bc3ad8ff1501acd8c6736fd0c9eb94ffbf6" },
                { "te", "ec66e8ba7d3a72ee85eee5b9266a5a5a8b342d87e2ed36afa18508d6adfd0b0da4f5cfbaa8a9e9d9049a2e95487a68346c7d98636328e054adfbeb1f81726c77" },
                { "tg", "cf2fc58b74a088f8f87c813c83547de55ece5590d1ac11a1a4ba50f57ff8309452acb4a897d6da9ab218c42674b4710887fe59a48afd356c7c32de0916e3c27a" },
                { "th", "447b8f94fd8315ddb1f1819d2ef6fc3cf5f3ee3ef5a8f081a4065dd30543c2e90faa4329d19b4ef53b1c8941b589211984238557f4f9a940718b32ffffdc2f6f" },
                { "tl", "f2a452ee174dc17084b608f56b2b47f294c32de6a0795860bf532b8438329940c25a6325dbc8100470131f5182df3de29065fcab0e7ff99b0a147aee788b28cf" },
                { "tr", "f29d1f2c14da07b177d16c3d5f284a896fa417b3391fd34bab4be675bc76a54536f60c36dd529b27da2d0fefa6ffe0e11a0aff404f519c3d866f38f04bf93a68" },
                { "trs", "bcca785d6d44ff8d2cfa64dfb05a7a192e086e46587e1af3d23f61c7b55ffb5785a9f217191690be1fd738495c19979bc4791d3509adef71c682e45a64407550" },
                { "uk", "aa79513681656944ecb40ff1170ab421101a927067db3e9f2ec17433c0bc5ca07052d5226901e9175cc8a2e6e66230f6fc3c5c5d812c14c2600fa3801f109e64" },
                { "ur", "71d57107bcf595ce19530dfdf1c0ae1495f216e97345f52adcd3c2615df0af7feff1385d3d1f436c3f13653896e9eee7b1303b29a4df2e98d627cceeb0d50678" },
                { "uz", "15f41a2e5f74c7caefabe27b28bcd95c3dbb3a890f04000c9c0208525e794c7777fa8b91de47b3575cb53f8cc4626fccd9fe277c50baf58ce37a6f4a08b41b38" },
                { "vi", "ddd9df4a09f0bcc3d7b8d112a6a193ce314225c3c90ac18b243582a6e0e96e4f494062029cc0205f6a5620a0474a5c80e7e6bd23058f523d9821acb2fe475505" },
                { "xh", "fe068d685acc84ab0758ef38494d5032bade332c0498ef61fe638f75e0163746b7553aaa92c73c28024ff84f634c308782538f40547a206a9f8bd95c03b20bf0" },
                { "zh-CN", "220a3fe28f1892883c8530881eec41552d055688631ea3f1ec483cb042ea9caaaa3b72e6be3025762138eda37123761605cc5ecac4c8ec29e1a35f1cfb7051cf" },
                { "zh-TW", "6cfa3bd7b572929b9c9411412b76768b1fef373fc72cc78fae79184e9b5500332e5835bc2523b037ac852217dbae15685faea9793fba05274a0b62a4334623b5" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "e3fb967d2536375f64e10a5d31fb5290738cf2acc2fcd066f4d73d105586812d078eb3f2fdcdb8cc44854866cd0e1b9f5ffd3ed4b6269ef6ecc8c9627e09386c" },
                { "af", "ada3c8f6a248c966a8b753d8d5c963f94e0c573005fc23f5713b7ac722583c6d152a623eab3385083c702ca6e2e68dd97a018e704b603fb759e668f19e66c46e" },
                { "an", "99e0ef9f198bd51d6afb9eda0dc6459d44e81b09244d22484e55615d2a654cad938c20a240989fef1071de3e73322c63c66637b97354d7cfd024fa823df05674" },
                { "ar", "f544116b45bfc5c85b878d8c25f1f1367a1ccda03c9c9ae01a818671d0f4a5668cabff7d892072fa8f35242fdd0d7b7179f10b478e61763946889dc8c154b742" },
                { "ast", "129a57e0325c6ac4e81ee00b88eefbee9feaddbe065dedfcfdd91f081d43be3c567383e0a5c0f00e2a8043966929f613aa6e2d4a97fa42e98583b2c24003c5b2" },
                { "az", "bc21834266ef6a65fe862474a78f4ce284511738dfca5d9c546270b99d9cb4a6d1200e154825cc1aa2093bf3abb31e04db1c129e95b944776f1d49d1c6174efd" },
                { "be", "b8a995b1dbcc0a467a03f5ea7791b80cf9730dc82e45175e6f8b5b529a58cd7636c550f1b3b4a51f8409b8251e9a9f986ccb8fb5d978c8e960a3b6c06e74b529" },
                { "bg", "52cb884e3d645ad3f291174fa62dc9f89181851df7bc9db3e38853fb1f6c040d994882e9255e09b0e037494620743706d7ff19a4dacf60f0d20ef4cdbb3e5286" },
                { "bn", "1fba8ac0cb851e25c51db30ee6b827a337a53665d53a255501924e4f1c6b9252801e231bf4fd1128d0d2c90ec70784aad5e90ef12735c55179c6ebfa9e168000" },
                { "br", "e10c83acab31a93cfb1dc5728221d6f2a8fc127d15498c9f8d138fd53afc23c8a082183388d7f4291df76c9faf656970da032b8a29c636023048f7786840b45e" },
                { "bs", "0df188d5011906675d9641f7b2f5ff6d71d327a0ae356bad6b1b6c72193d7f6ad0ff44d71971331da8dfcb4b24d00ea0da0befc1415e74b1dba68cb1d24ef49f" },
                { "ca", "0ff34a2991eccc951f9e0b5b2c6862d8088b074175ea26f76331ac347c5823f9b4ba442a75a3b9f4a09953a14d8eb08e07eb700d7a213ff31cd0482f03462fb1" },
                { "cak", "7943cad10de68c0441a49f9c2cc82f952ed0352a8ba08f4ccefc238c30d1e43fae1d5824b5a23afb23c2f3dbbd51ce0e0bef8b35ad19a89e2a5fb55f5458f83a" },
                { "cs", "9d3c671e22139a40cf9d020cf609f7ef07a8ac4512d95ad9926f7c6d3ac26ce476dcd3593e6236ab934bf532d8a975a9abaad8d95b59a1ac13c8b4ac61fd9a23" },
                { "cy", "8b125c19c91d9c646ef84421971c69fee43d2cd18825893daee923cbf626469f62efad794d94c0e82f1f67d5ef380944cce1a13e55ebf2c84cefdc938520e5ea" },
                { "da", "3111995b22ef7a28ab32f9ae84da7aad758bac6ce0aae4d60d4a810968a7e1f98fed5af8b0350b17a99ea5f991bd08c38b09ec2fb81bde8967ebd8fa9ec8b3d3" },
                { "de", "8196a5938dc8942c5c2d9b1d86d98eef8a89ca45b83266e10f6af3c14354a8098d4264f9c0f8e4a1d2fa980c4480dbb8513b3c749de3b2eb0b26fc7f49fd4ad6" },
                { "dsb", "2c9831c2b8c4a63fba59277ce7a2de0086d99448f9ca5f721966e0e5a40bd168c76261bfa596e00b845c70589afddbcf40becda2a419d465e273652039556a09" },
                { "el", "fb424154161460bb8fa4c44610faf963e33a37bbc7b13a9030ed465119c9e9a774429463fa9d68e292179538b087c97dd62fdfb1d6b730f93ba0796b140fa932" },
                { "en-CA", "605f80637261f6e56dda1287487427a7300dbb65e810a135072de156974e8f3cbfdb409ea545b48848e8505887c7294cb7bef832b9bd0716a9902a8cc46490dc" },
                { "en-GB", "b93d4dc942d3602fe9a8c685f9870214590735939aa50ea2e1349b7b914480ee9b6c64d6e6a351bfa6ab00cefbc31cc9233438da4cd75f74accad1b22dfb4aea" },
                { "en-US", "1dc44372f01eb0c8f9ecdd62c68de7e18d80febfe1e502e48dce7d9494b910c9796f52ab3f594da0ba791da2c922cebc13d10b83f8e7ce0ec329421dbb871978" },
                { "eo", "a06aea701a9d23d420d9741751682800006d784870f7a8103d1f290620c192632099d302a43f48785ad24ea76b854cee4d35dc2a1c45c7e2e0296cf26a763158" },
                { "es-AR", "712c8c3e6548f92ecbb5d1d6cec67247c42a071d04834371c44d709dd842356a8b9d22f6e3aec23ccfea8d05ec9c15cc70cd6c1d72de37ced48fb9230f8e6bf4" },
                { "es-CL", "bc6bb4f72213665f24608f382670896b38f44bb9b04a90f5c53f293b473469c8468e7475a5f6dfc818f11b302f36f38cb6d1396d26e34be18a7d4a1ed0f2f06d" },
                { "es-ES", "f15b318e5f7a8d37ab2fc3a991800118cc89dc803d4c19d88bc22ae0f1960db36a9e10c735a7a208c7efca4c7c786508222c30650b404efb722636f922d74a4d" },
                { "es-MX", "97ec586aa39f0a2ec6bd0a5034d2be13ede574c9194de3f71b3834c69bab367fa4353d2aa45da275c39f7da9cd29090cd2c91596fb11565071721008a0abcc90" },
                { "et", "70757d18685e491579b3519dac567fa18329e2f8198b2b4456f8edcd60c809ded50f5c2df45617afd925b33865b51e42a6ccb24b74601e4110c3db56900be29b" },
                { "eu", "45ac4203de03218b11a7aa75a95a5a88a2d67fa6d88c684229b0c4dfa11bd826945609a428134a553fbc58f18f3bc0fd27574300d27674ba981ab16c2114814b" },
                { "fa", "a49d4cc04630bce3614cbfa76e46383b83107ee5618cd438d7888bdfba2fc0c41af87e891c99af1a45f3208e7e34287321e1b9b8352b76eaf78806a59e3c7d63" },
                { "ff", "420b9c3c305f91897321aeaee48aa3d602d851d3aa65d56aadc066737ba2e1df84c312c90ce1810d5d3a5479fb14aa63398b1e0f6cbed0963f75f24faf0392d4" },
                { "fi", "3038d894fcff1c707c27074aed9a54630389824a707f317919879b0ac5eba334dec3c0089f3b2b2a95a9386eef6df0b9a74da16b5449478353d3d1ddac89f51a" },
                { "fr", "ae71e8036a6061a106cd9cd6963b728032908a15c6a7522580e3af43e6cfea4f640cdaab105db76d929c8746b0e9cfea33f850388558cf6ed7476d7dd73a8246" },
                { "fur", "e5286c02c2b8974be7ec496fb26f3c1ea4aff5344a0477a202efbc7aea3ce8d949ce32b67f87c079e2b5cb712469e0ad0f9321d5e3c1064537cea245796197c8" },
                { "fy-NL", "28179c310ed984af9c4cf583a7e0f9c7fb3e1360a29df27413745aad14c0fd228ed1b824fdad9f72ee099c18a7768e805445bfe8aae8de777ccc2bfb52fa6cbc" },
                { "ga-IE", "af479ae35356193334b569b2b94e1449730b4ec94486a5e62f251e9220618c585a2b28853bc6aede579527a1fef152754e4f1321bee5a8db2d970a6a4c4b7cab" },
                { "gd", "f0b3042685029fb34be3f663277eaf46bdb8425583649dc149a81d26f4c57be1ca60f65cf99b1703f80f6a012c14d86642c07d27be5c5f1ebfac86225b4f7f5c" },
                { "gl", "237ad0060e7e1894bade266fb15185a6685eb2152b62dbbcf0d91628465889ee6b1a6fc3c87f530234e6b5c979a936ae7ac2a8ecc60dbfa05cabb50f2963b692" },
                { "gn", "90e436c5a92a37200edcb9394e458a03877b8c6fc572a611d3faeb6301e46f1862169830653b756ca2ab7abbe740568652096cf8aac9f78eb64cac0b74e609d3" },
                { "gu-IN", "be688dfb9ce4cf0b87f419ce33ad77da4ee2798bd92c1aaa1022d22f8f9eadc556ae189ddc6f4f222bbad562a986d0347af1f4e51537f31e378bdb34634786cb" },
                { "he", "ad1042f32e57fab9158e2cf6bb5da4f36ffd367cedd8fea0351edfce167db659bd47f300f4c59d2050c5e00e65de59c3e0d86e80101cb280a64f1b364d5769d7" },
                { "hi-IN", "88f27402a4ccaea873e895821d62dd2f651dba0568a3b67a5c7918582efc0d0771e2f65fb1beecf027547228557e5f8692147e2b7db2f6b2e6956a89aae7e6f0" },
                { "hr", "883bdb34901da55033420ef67e6949f3730435aefed84566e257be055b4a2adce7075ead80c539df068af37ae45c351b5e64b9276b23c666e256bc9b4cffb345" },
                { "hsb", "8187469d7956bcbc263b88ea5bb891a7eb5436bc96bad3a97574f3679f632ce681d3a3d2d39b4a98c2a8e3264814b631ce9fe6ed38ba257ec6f5b5bd941bfdcb" },
                { "hu", "b3044889e446db23b9f7ac8b8e646b55344e4490921b354e5193a5c95fa48275f66a3a2306a3a5993d16b383cb79f3364c50d0bf083542501a248aa6adc09457" },
                { "hy-AM", "475a0f17d9d9db9a2fa5ee7827e47c8ad17ab2b50dfef3c39cec7d4f1457a24e02f9816d42db768df4ba57a36be7da82a2885d9dc94215ee91348db46ed82f91" },
                { "ia", "d5c058d89e22ad97788187ffd33a13124c6a9b9fcc0133030fb167a117115135c60798a03ef92b7495b9df79c11a6d70d78441624b9c59703f6583b02fbe23f5" },
                { "id", "e9dc48cecc373e3e2a38460a16154fa5a93f2c2be968d5996fa8b22d5c39c9558b7fba7cb05c9cdfc08101f954573ea70d704ca70aa0069d5726ccf845a86caa" },
                { "is", "4f35ffe375aff427c0cbfc77879758d5fb6011ad0ec05b5c7519976f0e39ff2f5d8db04bd771e12d545a56fa0c558223e133cc244579f31c02fde155aaaf18b9" },
                { "it", "97d75ad401bf39f970b94223489cbf2f0a7f16251646ff0f85d1438fb37d441a1a4fbf4e9541f033f3d9fc2f70718280868863ab974f1604d931a93f8e6ea5ae" },
                { "ja", "24eb68384cb4b4103cd1b19cc9192870e50fc207de8bdc0a42a1c5332a6c3d9e39a2cd66b95b8cb55ba4ec06dac1bee73a575edfa772011af5f2b629433c6354" },
                { "ka", "97b5a2212b5c3a38aa48fe809ecb43c19a6b62850220deea7660de2aed2739f1118f8285123541d2d6e3c47706b0070d95ad82c69e138beacb749252a300e789" },
                { "kab", "f7e01508affe188eda2e6fbd5099d26b13cc1041c3700d59b4be4e4b26a3931f868b54def7e697ae452e7bf8ed1c7bfb43e1b4c49111193dade8efef4168fd63" },
                { "kk", "e210bbd79e885465259e4cc77893627882701a0c8ffe3f9c19da4fd13444e0e20d949bdaa9d0fff0c3a6c2f3c208b7cb739730c86ac18d0b7bb9072362a9e404" },
                { "km", "58654c60350dda48925a831547607c336175e6b1426420fef05a724007a6788e478127142867cef0ec8e4979d357eb09d2a221fc1636a82cd0c4f5abbc56c4f3" },
                { "kn", "a829a6786fc91d1583324eca775e26b6c063cb249be97b6137e6668d2f3a239631573da00e03a1229cd86571540f62a650ed41dbf1e287713df55590b01c2ae1" },
                { "ko", "3f1d9d866a0da8e21e47dc8c1211416c6b214484a8524407a1a50ec428b30643cf7f9b17a356088ab64c8210f7d0a621e81b314077e768347b098b79f5eb5f52" },
                { "lij", "99b083423b7e574cf0bd4d00635768b23d2fdca43c42de75f531e6ba9f1bc33973f44cde9214b8db3402bd8108126e6bbf425564f444807afc8539b3af612453" },
                { "lt", "1a66d8e451fbf6136230a3707a67a6b7b54198858e1c20bb601699cce45da5c0ad523535518b0afa04d3523adcdbe91ec55ba5b8e8fcf3d77f6af88160217590" },
                { "lv", "884383824fd1b87b9d9de91da34008175a152295e5036053a12326a4ce43be448827edda76f42100191611305bcf3c656df4840e24eaedd3c3d7a1af3d70ce92" },
                { "mk", "b85a3d33c0b7d343b9c148ba6dad944d9aa3b9c31c251ada188fe7fc476ebd55e6dd0b3cdb7105dfd8c692afd000498a8e8199de0343f10340fe9d8867e079cd" },
                { "mr", "14518606e215930397dd9bcd8026e60b1fc7cfb1cd2e7dffc26ada0ee0e45fd895286b40d187cdbbda60f9e2d8f6e3c847145984a4c351197969479da8f04018" },
                { "ms", "11c451f25cc10deb55f3b8809fd3adc0bd7e2bf7ae5dc4c48c19f1ff6dc85f5148e3a8e483174ec0ec1e79b12b52b5f18a8c7eaf06ffff6bad62bab4b4b10497" },
                { "my", "699e981066e90b02ac95a1872edf8ec3d6d47f48a3cf0e35b44f28675bea419e0d0e3b81fd10ae1a9f4d81510a73d153288d2bafc38cf66014f7f4c3e2a1f67f" },
                { "nb-NO", "c37d95f727acbfd7d3e5ed63d530a6c236acb060c5e1c02bfd3480046ae410c897a35e113e747b60385d7cec7034883f9340ddee818d4c52173fd7daf262f518" },
                { "ne-NP", "09bce74961524a674b52e0b2a0a0c3f6e0b2d25d5753743d22938aa424932dbd01a146a4f336919655059838075fbd89399300210552883c5c8d355886a6a0aa" },
                { "nl", "1f3c7c021d1ea885144980155db50fc993389a2a8965d478cddaae221170b47aaa635cc8e63139b73e07a10744bbd25b1d563957a18dbafed3593e54dbaa5c67" },
                { "nn-NO", "b5728031035100cb2b1139e0d758087822b2547fb8ff2300ff5b7e405309c971dcc6a691e736ffa0b9222337054cadfa0c5f7ce90bb0124d170228d11a5f8c2d" },
                { "oc", "b94cc1d99c62fd3a1f93ec1c7bb2f457ca5e50043b950f1f9c51d79e4c5740dd494e90fd3331dc337058fcd8364308dcc31010717e8d107f387903aeb43f8564" },
                { "pa-IN", "20f4800dee295176b1cd424c3688828cac8ad69f24c53cf640403901a6ce0e22c0348986f11779527d32cbfea462c1ef2d7f1458ded88d68efda4056c7e7f816" },
                { "pl", "dcabd11aa0c19b8562f4516877f2d263690d9f333f4953e26ad4397fe0b2e8f6f5f4f38a247d919754e539bdd20a9ba30c6173629b5da3a926314c1fe30b8e3e" },
                { "pt-BR", "2cc4d9f2a9471be0900870629637e6705e9bf4d260170f0a63f4e6d2323a83e0c6c56b363f1a40db85be7b16fd1f8a061c4298802e2bbb6e3a9bd20f64f5f6e9" },
                { "pt-PT", "9ae3bd095a24cbc53857b8edee29c49a2f743ba67ef767b3617f262082cf4f830dadda307787f69822c2fae7af117800b0405985b0206192129745bcde7b7526" },
                { "rm", "10df93e54a8fa7bd08a21edac4a8ce60b6262161c6abbabbb979bec969da0b81fc4aa1333cb2ea3add6694ec5275823938b5306629dc86bc9cb0e2c515cda6e2" },
                { "ro", "c3b0a2c57fd56c5c8d55e9b4463415043050cc6a295e224eff8c405d48cd5b90328f12789de85d7da88c5f1ff39067ea263fd184b49a0cd94158cf693c0b6100" },
                { "ru", "e4d3baee0ef2243cbb56ff798d6fc18fef7c77b90e8266c594359689d5761789a506ed675eb2a9d121714079e3919604bc33ad8dadfad60dcc9929943d5f3666" },
                { "sc", "bfa58faa7d0b721095c43d2a9b9a2d1a205bef81bf7493d3bec085a5f625ddf9a287627c382540cf133b1b041d3d20730150a23810eecc28ee8df6cc637606a5" },
                { "sco", "4a506b47ec8fdd666da640c4f600b712b8e65969d84df5c18c1e33b5f5702ce13502b66b649521bddbb27c410e321f36f5f83d7fdd324e5e2646f8e5805a199e" },
                { "si", "1b87c81b8f629c4567f8c8698d22e7b6bfc49e7daf1e3ee73cc287c2a7244acccf370aa4cddf83eaf1bbfe9861f4f56f92d9843a6756d2286b473a3458f56118" },
                { "sk", "50fbe5318135d58c463171cc2b5d607ec283f8ec025cbfa09b8cced4017b1e31dd75b21537b79af575026e0693ae0c74732f50cb9c58a9ec2ad24360359c096c" },
                { "sl", "de1d1169102efc9757dd69de4fc8b32d6a0f1ba20692618f7105a054746b88a9f62aaedff7b815c0c6c3aa343883b4380f6086d9455b0c7663fd87c799c0be0a" },
                { "son", "9dc4b4dab712113261b16674bfda97492e7b29277d204e10330db0770ed5bd38e199edab3844b63b13f979186568aa8f3377d77af18434f06cb88bff9865044b" },
                { "sq", "41ced93e6d8fda851f4ac01d1dc1c4be7e724079edb298c220c30a1f1f05199e82a8aab13607b1d0a82def0624df5c99f1d381aeedac1785f96bf7a0873b1167" },
                { "sr", "beb4a0a120b183925cf0696b1299896647dc4b11c6303981d2b98b3acfc8ac5fb772ede92aceab15c7adcb2467c561db79d081b63f065a366774f2d413e550d4" },
                { "sv-SE", "0b8288afa6663a396e221b9b5c289d4c29a8e59ee5028d8af547f8d8eefe0fc2d88efa97bbe9d99c9e2e26243574c7df835c6679bac612055a20b6571380d13f" },
                { "szl", "5f90d656ae9d2377dc27c8f59331989f87b090763160835ab792c043877fba4a85c1c354c5807d24a39d8a868b524585b3475d2c971640090752fa05295914fb" },
                { "ta", "b90a220cb53289639e5f7aba55b7f226c6818c9a033c97762f6257c2f78c5f444661dbd691f69580f5f1763b718f337e6e3fda9f31bc6d5f30fe9e385d58c3d8" },
                { "te", "d30cb8baf6e46d259396c7796384c5989e7d97c8fbc651bc5d0f441fb5a668ba0b52c78b6f475ee21a20997bf77091078144cd7562f2983fef95ff6314ec79a3" },
                { "tg", "1a720494ec2796d20efea614b9f001bebe0250469b235f99fee7f55e4bbe305bff084eac9cb0d3974ab777b0c11195b0a80830a634da1e0d39862e6daa4cae17" },
                { "th", "f0b28512501f75da4d5e454480e120e5a7c8e59e0c4b75314652d5ecc051ae3c3bff844ad48f024ff4b23a0e2369d1c50e97b14d997a1bc53ccc1c2d5d5c13a0" },
                { "tl", "f580d87fcfac12fe5f0010103819823ff75562c9c096483ee4c817de8b01b4e7044624a3496a91afd212341d4e9006700da00d93108e3c9709ae38dca9372ff2" },
                { "tr", "5fed9773a0b572d97f646f598a5abae527ad37f64a9912d6f3f9084270e6359542c450d66d32d39c546826a2b97827f990f4ef1159f3290fc758af495d1c6fe1" },
                { "trs", "97e2be8abca0f404004a9d26dc7c701abbc79afb3ea21d0e327270a7a8b60cf8cd28b5fdb13541cb842c75a188f335d4bc4c193058d6eff6370ac50263dde82a" },
                { "uk", "8a3e7255d625d3b57e186b49ff5b1c31306b61af613fa24b2fbf20858a3fab757d1039f2a01392d546a98d75621366795f8af6909d1a5e17cd2017c1000ccebe" },
                { "ur", "b14c31646a0f2cc9ea0a507dd8fd0182285bf93510430c472459ddea886182ecd08757cba897d25f8c34e8c9561c503e3c9d6363fad68642a0641bf34f55b599" },
                { "uz", "9778f7b7dfed1ceed709fe16d436de377da80c1330dfe77c0536d9b56a5591b543e9382d91e6c0d598e06ed3d275a557517641c00fbdaa7de08b9be33224be43" },
                { "vi", "1b6f3c8bbfd97dc1bb3e1630170328c2204bcb15081622d44af2fc8e44bbfb085334dd2f8f36c3295d05f28fd930ead3926b2721d4efc53e9a5c98272f8d5373" },
                { "xh", "f39fd945d97f6356cec00edf4050cc7e7071a9e39be86e67d95c5766f84e0932580d8ffafa55da1b7ac0aa343cd409358698d2673c94321c71fa86d7f0ab95fa" },
                { "zh-CN", "907196b92c5cd6dd9d20befba8e9df8c7bf6e41451e12429dbe01a86d99fb21d0fd880f335b14d4a2b815e49d025340979df8daf39ab822237ac8b606357a804" },
                { "zh-TW", "76936db120c37dd6e0c144b04a35bbed7f51a0a603d70c81b0397e62b542731bb830fd9d98371d300a4228fb150885a68886568130fc66456f0a2f6f4683d36e" }
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
            const string knownVersion = "115.7.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
