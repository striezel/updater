/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/102.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "e8eccae9bb2c39df81a3458bb166d5147aca3707bb723873b75a1a9c2499e651368f5e74913cf5bd26fee37ce4dd1069ea5e57c5537aae339dfa96e45864f118" },
                { "af", "c4dfc369601ec740487f0d754a878942a9f0fb5a71a41be610c74eacbfe25d3ee512ce966299d1cd1648972d9d9e3d3ccdd094acc77e36fdf15d7dfaf43ff305" },
                { "an", "750088eb663a67c8e52e7d69ab354e3eea01ed91ec04479c4de2bd3127700b2416a05ea2a458a647f9f7c965ddfcbe2c54a209451d71507762e7a777089c3ead" },
                { "ar", "c2101553c93e533e7fa77994cb191ec3b4a6da5b6a8d709003fae39424e84286b503c66ae13de2a9d4c1c09e3f6dad18801eba39bec5d65e0687485018fb3607" },
                { "ast", "b6c1a2871cb5bd49eca876d956dc0a3e08188ed53fa1666851821d205928dc4fbf847e9ba332b47afa6094ee4eaf7d0aaa27f25c85255a864bf6fa27ff5b6c42" },
                { "az", "7ccce238579283cd443bb4ef8625bbba728c8abfd1559f2af56640d7ad5e34214f118be70d2753f2312e68dcf19deb83414a8ed2889d083d089325045ab09a9e" },
                { "be", "2d8f66a2a7ec130a982a81f714254c9d043493b0a72fc0c77f11f90314aa1a5924619109f655a9800aa6eaad111770a8715e5d0fbea39a6f7c9859fd716d558a" },
                { "bg", "5646cc34458dd8bc11657a97043a778e3c1de05606d07c68eb21d459b59e814b8abedff3f2a6773bc9d924eba616030fd22a1b60ad52a62549f5c7f17250f332" },
                { "bn", "13bef029c222e8f9a6ce77b095eee2ab1825f059a41de92ea766224c28289310ede36829dec99a71101dc0925121981acc208ad1c8494f7a807f04fe6478b058" },
                { "br", "6f617e635126340b715cb28694b357281f54de9bf3dcb9d898ba79e662449cd14aebbe38562f52b186d6c6e90c7164279307032ae722049904e65a0f981e6f48" },
                { "bs", "092dea89eb27f2b11b56cd4eba9234d76721f6e79289efb800012a3f966c3237275af4a9323d0598720c4e1b18fe9146dd86a910abdf163e4d3080d8dc04ee2c" },
                { "ca", "f4256f1dcc27dc84303fc12a42c2ca01eb43a7843e7635529d1d8dbf1de5c0b29a2b5aaa09c65bb85b72129c4945fc29a87129f0c2a403548ccde040cbded8d6" },
                { "cak", "ed23f56009ea55d8c73568cc0ab7baa21b10f5dd2836ac46a00d8ef92a124c0d60c387ade1317c538cf14221a94f198f9e634ccfd5757b54b710cc212eb76150" },
                { "cs", "4e32ccb08fe044db6cc1e033a899e5028b8d7c89d5f25f7cb60635749173b671faf662f8f232bb8b8a5430af137206299fbef3d3e40ba8aaf207ae0c597958a6" },
                { "cy", "3c9130818a63daca564f9687929038ee2aefbc4b08ecc5ec9ca04fb4607ddd54a490ca2344dfbfe20c2dba18d4f890680feba5990215d0e62e9f22df9c8dfe32" },
                { "da", "0c844c5c6dd896f85f871447af5941de16a5b534ebecb934d011339baadefaa71376ea5011ff5508d0b7cb342e0b7ea5a685e0338a32326563425309e22afc17" },
                { "de", "e6a97b93833ad60bb6eabf0e754196d70595246ff9f540a101b87983095ff879e64efb583a5d5b548060cf7a63f36dc80b6301a0b181f6e68e6cde66c5eae5b8" },
                { "dsb", "98c462c61e5bb9bc019f9338c111a1dec3aa0e2b272937e155d5cc01e684ac709b3b19483e65c6d297496f499100ed44a8bb15cc4dd41ef8d9a3c0bfd0f591a7" },
                { "el", "8c8db1543cbaee7f0ce774b75900efac0b2c891d3ab489f43304d98c74d3dc8c32ab3ff29f267069e3a13b92069f9c9b3874aef71dc4aa92ba7f867b62e5a71c" },
                { "en-CA", "0c6edeb69dbd7fb51ec1a4d93281c7c07e49b288a8830e4203198b8a7de02077a7b232eb0d19363caca6e549ecec5945073036ac78e109aaedb30f82d9128980" },
                { "en-GB", "433439e32ff9c12b154bcb01d74a0e4501adffca9fe8ba0a9a36ad9f46e82c8e0929c9137438a227c24323a184a5b512e112a431b96388e80798ddaaa4537ceb" },
                { "en-US", "01d0e1bc29d6e2fe5f5a732fcc6b031a5c47d168cc2546e1b90bf78b5ca14c5f4724485722e287634d185dc5cc109c19cd0dc234675eaede443915dca4edaa0a" },
                { "eo", "a70bf3e2d66fc32a4c2b61ebb39ae4671c4cdcdc0c540e28b676a4903f9b984da62ee0beb4e8d4380d8be8735f1e3451e6b56c54d44add5e225a14dd583a2d5a" },
                { "es-AR", "b10a7b1ea8a88f61a94966caae2d4b0baa8409d3ff2accc4f93875fe9075c75f581ce3532497d4149a28b772086ca11b0f6a1cdc8f8cf6e612be8af61fc4830d" },
                { "es-CL", "c7788069ac01afd0983da62bd875a520a3f70ec752200752176bf62a334ab4b9adfbe8658d50f13b78c3e939efb971c65b862082430747b3897bc2a7bed98ad0" },
                { "es-ES", "2114d0a7210a9e26dbb72c5967ad0535de5508a20a97c1d9185b952b08f74e69f1bc29792ff3ac62763e8909d1da5f2605434ad03c114f175fd5b03671a88dcc" },
                { "es-MX", "c98959d29699dbf01d1b492c69cdccd05d0377c1c366ef302c5a3556c837f6e0d661ba1b36623338d7cdcde55b06e370230ddfcc80d39f0fe8e583f721129593" },
                { "et", "c52c485d4a095c833397ba20749b7692730985afdcd9f16731dd34406b3f6c43ba013d34a7e74c611555a27f0996a2233407f271fbffc50c9ac90f9f07506bb6" },
                { "eu", "69604fedec63965490a82e868b3e7ce6e856a5f5d49f0d2822825c0c4f4eb7a006d616fa44d1f413df661ce942892dc2d6b8b0f80aad297a579679d7a1105826" },
                { "fa", "d5b70f77699d372d24d8fc2387c56810d2da75da205dfac7bada1f1947a16c65ec749362df88e3f73a9d93b52a6483131e029c58012abab0e25a5551fad9cc91" },
                { "ff", "a4cb1446e10db61e7e682b7650ddf8423e02a0cbef65a2b1e981a03e0cbb96d9e8228c384596caf2e72589e15a5a438ca97a9692c2497e477cc5ca0723ad5060" },
                { "fi", "54339ad88781290f37da9159d5ade864f7ef9cad140e3ec9e332c6af06712c4887e62d57e6bece57712fff6bf21d11ce6f1f87e7244e73b38fb47905004e3e7e" },
                { "fr", "0e31cade7197f3363ec2a90d2699ca442c3056593cdbbc388a02165cd313afffc3b31dfd5bce52ad633aec2cf0b5bc21ab95bc0587bf7e8c72fbe13f09c309c8" },
                { "fy-NL", "3951cc283f0092a6cdfcd0e33c6a9f5fa4fa5e7ee51f2cb09d66d88fbe70209d3c1c3d0da9c763ca5684e99ee15972bfe61e1f24da5b9c5ca1ae6b2031a28484" },
                { "ga-IE", "0ff162be81ea58dede1c431cc216d6f6e768ee02b2b9f5444ae481e6c931c883e6af8f358595f570f65c666f1be177e477dc071a14811da623298e81589019d2" },
                { "gd", "20adbe40b52d977eaacc69f1a20cd9c5495dd216462aac857d4975245394b8d9aaabcb48aa5710efb5269a5b9d538f2455a3d8e244d44c50a378ca0b42d5395d" },
                { "gl", "5d8a8fa693481467f276ebdaf0c624cf554bf1fcdde84f72738f8bbc41498ff3e30cb00d92dec77bb3983f2174b5e00898ca3862c5a57b4db12d824c3aff9678" },
                { "gn", "eb63f5af5b3c4521ad9304009410edff87fc0484e3c5f7467e0287d1fd4ea32f5a5b1117444deed39a4c99e4253b2ab3a687d8af2d6a57d309ade5aa11e632c0" },
                { "gu-IN", "293a322955014362dcf30edeea0d209e3b91cfdafb26d4fda12780586fb975015ef3909b50a802aa387c50c85c9bbc4ed7a5d2492fe2608d6a1ffdfb4032c641" },
                { "he", "b7023dd5ab0096e6c6768b0b2c891d88fc580eadee6b62ed5991025c93862bf9f9a69039dbf51c7bff3fc4d96e227054df17969c05ba9ee7f090f730a9f2e570" },
                { "hi-IN", "9e3f96d14d1557c968b9ccd6424b60e247317ea5c6b0d52aa0b3e7c755941f2d338c2a162203014ceff95267edeb5df27a66eeae9964ff0b8b93e13634d9bd38" },
                { "hr", "d4c802a7781fb4d67f64837b8f724ac735877d72e1679305f07d70e63dc0679065958a211401ab7df5cc7e501fafe70bcb00118f866f78ae61bfa87de9f6ecf8" },
                { "hsb", "eb4e19eef7a3e8c5678153ab5969351c1afda49736d87979ce6b365e9e9907de6666b4a91a55fb1a9c0a182ef27b67b7c3f4f8e0c15939472bd7f0f78e231767" },
                { "hu", "04284f620a0a947fa3f044649c9ebba076558bc55bebf56d8e61361f1814033a39885157aa1ead94339b824b1be12184344c0274210db3b9edbfe23689ad6014" },
                { "hy-AM", "a19c6e62a8b8078a43315f13443efc72c03ff078b70f1a44aadb45d08371733a98f866bc9d6cf0685fff62dae59494cc90c451346f7aeb4650483ef317f588ca" },
                { "ia", "0ade61e525d159f1b8f6fa8e5245063ec2ca3d86f887cf4a864b843f7d0b7d3dab3ce362bca2b74575e7587d12a74e2c4c29843bcb8d3ea4b86a1442c38c1c61" },
                { "id", "c85f9b079f551075468f185bd46ff1e2823c5500afcc5ccb83106c207911dc5c6cd1d7d591408a605df05094fe78a6c59eec294d3f702a2cc016dfd785c42f35" },
                { "is", "a8bf8a845c593c4482d0be41a2580929c0913eb909224122445ce5d344bc6b097b3b10b4be580d566cf57c282fa4458afdd1ffe96d02257b87aa0c1ee4e9c7dc" },
                { "it", "a17fa82937ef5612e7c077b7197d196bd5e49ef4970fc8f4ce343a3ae24a1a0970bc9647f937f5f544d25edfcf80f79d8e033926a34335bb37f2da59ea311896" },
                { "ja", "5e0473db3f9884743b074f3dde6c8915ee3ac5916b044940267f6de2cd7e96df239bed8e4bf407c04ed61f8b52d592b54a8e41b397c4819d275d101330274bca" },
                { "ka", "fe3de3fb54276c0189106958e98c69bd014b6dd5c7a2777e9e9cd843fdafc4a1d90552b4595b64a7132c8cc684b41c4b0c97c21c7a0d24903bf5c54b37bfbed3" },
                { "kab", "284feb494bc87a14171b10f28a4c9ec2e9b17a30966d57b2e712614a86a71c010a6e0cad8b5fd815ed34131c4df805851df96669494230c28e9a489ab507fd79" },
                { "kk", "ad0730d46beb79e6dd5c843cbe59ab03716af0dab1d1fff188e0e86a558a117f7b7a2fc7fe86af042ab3dab31048e8f9354252311479ac2b00b1dad425cd8351" },
                { "km", "e0ec4879087ab261dfb495760e27860a5d2eaae5d13acbb8d6ab623a49c6941de50d636da729106c439a44e354dceb6cb620822974912b1065ddf892c2cd0580" },
                { "kn", "5e29390b26d835e7e64a06bb3ee16863920a553d49dfbf713440258a76072fbc9c17c29edfbc32f42e64b0a4d06e17fdcac6c0c4281e204d77776bb5ed809285" },
                { "ko", "bb412e262bf6d1525d87b4b84fb5dec0a52bb2ff6bd9a713f00cf885f7aa83fd5888541fbbbfa1b3e624bfa3de7e594e87143fb8208073b2e48e6b5f5a4b23dd" },
                { "lij", "6e5cb2aae88bb2704eda423dbcbd59c600dfb06cb68978c8a9b11be8f50c0d240848f95c8bacbd7f61e02b8beb0dbe9fdac870ad78d31fab641134dec8425d12" },
                { "lt", "6face1745c2ccb7e89b69cf4efc9fdcc1dea94d989b8cc88c593ed953032cb207b900a467c79017e2e29e43ad98b376b4d9f909de74f3af698faffbae1c69c97" },
                { "lv", "09ef6ac34fbd46b7dcf234e435c1380551d29cd82da1e15a0ebfde119f890ca1978f3a04168baf38738c9d9eafc5ede3ea9ad859bafb06c059922c0205bb990a" },
                { "mk", "963944002e1af92bb88385c8f3541329c55a73ce7821bab66f5da4783fdb44680a82aa6eb1fe644aeac8b978465920480da8d5ab0fe17a27b6eedf3f937940b7" },
                { "mr", "e805a753b5b83aa383a740269eb55459614255d13fb753900f7c3332eebcc989ffd48b2ee0060fa243ba5e997f448390e63ea604f4a91cfd2e7eb43312f9d463" },
                { "ms", "57f633c767643c14ebd097fce3dd8ab41e2254786d51b52dca165cb27fbc0bd4e942e1d845d0a63902a889ecf30e87684cb273ad22bf5470f70516ac0572f5f0" },
                { "my", "9a7239f9c9c39ad84aae767a203eae6e7022fa8d6bb5aba0a7883af01b8bb876c0da5c0221a2d433b7f70f88c03ec8b2c2aa64d4c57bc41491fcfeeb60fa8d93" },
                { "nb-NO", "9ecb54148081172b876003a637c1bd18af5a586b8ed8e59add83e660922b07e05684d6087f42f25ddd069c4576c08239c39373c952f3d4f4025244b6b1a68382" },
                { "ne-NP", "e54a3edf1ce4d14b468946c5366e034f122c1fcaed5ddb1e63d06008a754a4e826a75c7f9ce99f5ec6b7b9af79a6261824a0f0208c4c30a9e24d6ff556cde7e3" },
                { "nl", "feaf1a265794b579cf8dd1a5e0be030722bd2abfac84655b4698f84cefa9c408b37220fdcd1d293cbfd60886765b39a9018e285c23967784ec087883890bc6d3" },
                { "nn-NO", "65a5330817b65e95a0b1e41bc265495d171432917cd5899c95ef96b03905c6bac7b194840a26adab6fafae3ad62dfdc1fe8fed80098b550c0c4d884d01f87a89" },
                { "oc", "d3297362e47107952dfbccdc81c5469f5fe63f2875820b0fe64be471a5bcff13b9cc04e9d31e6665f12a1e9dbc041214ed0e77f42106bed235486d2afc551713" },
                { "pa-IN", "bbb1c6099524d3f120089198b462928334a5e0025cf8f9cf2b2bc64d6696e9e9452aa6f4bd22c50fef32162002cfdd50694ca19ce3c561f131ac2337bed7d1da" },
                { "pl", "cb0a7e112d75a20c386e0e7c3bbe86f5aed35d30315db22bddf64f227dc3995880913f6ddc048a11c9c1ef43dc8444767687f105c03c50f7bec6b45065f70bed" },
                { "pt-BR", "eeda435e4ee9f6807307dacd73760fa10485750c2ccd22ced056ab50620a6553b1a8f131bdfc8c77b453969a10484c8ba48732835b01bed3e5ccabc71f43a529" },
                { "pt-PT", "83eed7cb311d5cdde13cb91f7036a9b48bbf842ff324b94f7f77b66f40f437790e0b16ab577e3e5da61a8f291da320603d2624cd68fd9ad226f7fab502989a36" },
                { "rm", "3e24cc1a598a2f66876874962172c8678cd8420f04063d741714d688469875e23204d0099ac4738fae746de7caa6bc9e2c659d6000ada1d7580463720bddfe94" },
                { "ro", "67e9de754f8bb238397dffe99bd7f21e304dedf124695d11f82f9fef4823b0ed40484951cf3f3a85e29c54e69167fc1de639485b309708ad02e5c6fc46ca245b" },
                { "ru", "89451317045e6610d866961a1ed959d17c3bf4ed9e3a788d6116e8e0d5013126a22cdf91f907577dbc23495e50a0db5040dbc2bdd64730e549da8a6a4a9fbe1c" },
                { "sco", "a52157f23e6e643bfd6615dc5e829d61766697f55032a5862bb818658f1669babd0bb53bccb76d12f26ef44edbffe4d7f2d86e819458bebe52e6df555d86d030" },
                { "si", "6c1e2f25dfc8ecd4d989aa64fae2a0eef780582a001102e6241d2fdcd8a520670e27e6f239fbd3ff6169ab9ccd43369541db5d82cd771bcef550cfc6a0bc5229" },
                { "sk", "ad4cd4d1ebbb26b0f6f939f55dbf0d2191d271d6cd33e475622512a37d343101993d4107fd77ed516a048e68a7b706ce33f917b257da076692f4433e49aa102f" },
                { "sl", "7a7fbb1316e320d9de59fdef7edd853e7f5a8adc10fd91a9502da1a83d51603596022596e2870b9d1f7e17be8b78a66e6b67a0e3704117b562d9a286632067be" },
                { "son", "541fcdecbbdd53dc301d61b2b23937fccc99197f4a9cf9746811d1a4b66af93d63d8a6eee6053d121a47d8c73a634940164add14f7bc91790fb5ad5b32282ba3" },
                { "sq", "91d2b480c21854ea3134998b6041eae8a58a1fcec8a1f8d6a8b6ba50ef53d81e2b73e22b8a8953f81731b1c38068d9a5810137b6db842694a800af6c7f29d616" },
                { "sr", "f766f38e56da1b3b984853cba8218cf79d8d8b2c0dce912fa34e6b9a825ac1a18ce4f1114198dc0d0426ec0a71a7f4c692f9b98609329525cb44c5d8636f0bd1" },
                { "sv-SE", "49d513170af91b3bd34016b34f2555ab0d9fc3fcced0677dd075085e6368a89c4a9cb77744b462e94a9a586ede3b2b592d712e3f929c5e73cdf26d122573a9b1" },
                { "szl", "24a35c2c37826c3cbf19724600a72c66fb4fa0ab5d7eb37c23e49ce26f2c035b9b198b158e01f138b26a003fc220e512a4c067e79430e5e993000d8778f62425" },
                { "ta", "d7c187f1e78a617d844bceb73d41c5fe3074749d2b7e84ef78ee2c0772b0ec23d245305da40a7082e9f11f9487f3cad70b8e92296be71d9673cbb9e9a45c2151" },
                { "te", "cea4a265b4fc8fe5893defa9c2d803a4844f5bb91f32a4196134c58869791af6a1d2bfbbd1e277a87f3cdb125422e4573990449e652fe08c52b2d60db0dbe360" },
                { "th", "f29f9d6b9cbff43b371ebda5638a026dee4eddf2c6f39918d97403d142382469e91deac8e05bf419efa002295850c04694b0900a1c7c119082d3d6d3b6301e7a" },
                { "tl", "2e859365657a4ae73d7f632f04053e011fd0532ec1441b6eca58b526e9537e29cb66dbdfa16e846ce9da9695f2c2dd390a3e250106cdda1c863dbb44f1087f4e" },
                { "tr", "3d96f5b7f783ad53d800d3754ae43059983729a607be752d1d4d97bb9b7c90fa932d916145ec4165359772280b9452fa4a3e7290c2cc7af6ec11714e61c3b57e" },
                { "trs", "07730eb9e91b024c02c4cd6038ec33fd833c66b7008d9c9597e770f504cdea6d56f93cc761870a7d31cde692697dd569ba3e915afafc723fd0a867a3312a280c" },
                { "uk", "368c5e339127cdad93859e3a22273a13e6655e765f46cb370d6a64d8eefd38c1a40b235604023b789510a79e8fdd4869546e8304b751c0403a32ca6469d26082" },
                { "ur", "6e7b3cc086f52c300409c7010329723d68d7f6432adca89012ba7c5a195242b8ee437508eb6e1bc3c84c01deaf0f48fc2b0176e0576a07ccd082b9ac81dea916" },
                { "uz", "6c555ca2160853d550179ccaecd87cb94733656edd1643b46ce446603db0378efba52c25ec260a9e01e3181b3c44611a2864f7063de1ebc5a9eb3250b3bdc777" },
                { "vi", "07c1589528c0bcfdf2c2f79568fc48f1e1860c2e6789ad9146091eaf7592dbcf5e044bf2611034d33c97d16a02db03dce17901224aa6b2dcb7593d6018f7d79a" },
                { "xh", "719f5c7899a24a5935c56ef0a9345c7104609ca6dddc342ea4c82c137f28b82564b100e4ec7dbc4a48685da689acfdf5bdc833e922a9ec20d3b46b235fed79bf" },
                { "zh-CN", "1691e39fa9888c816b4e924b3e978910a4681c5de931b8651f25a2525d787fbf755719ad516d80c4a926cf1d6eeae84bb9738da2f8c026992e4bfb804d307858" },
                { "zh-TW", "ad5a2cac3b689e1d56dbda5efd82ef30bf9171aaec1bbe3fde8e80a2671abba4dcf666c16e872f3ae668c590fa6bcd59179caea7121bd2cb1d9a532d961f97f2" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "b5040c78fb29aef1d8d18edcd56e1e49ea47ea1b9119d62d7abe804c2a0c8092f86ff6bcd9eebf65917226f02d07056dc07bc5984dc75917f439bcc8ea7a7110" },
                { "af", "c1b6b87983e3c06f77c25c12590bc0f9393ce7f861cedfb7850c1bf62b3a3ec0b16cebd4ccee3220c323bff7b967ec1ab3aad8606e4e9150ac95ba4ea336d6d1" },
                { "an", "928af34e89abb3b10db4cd1c74a58ad2a7c778ab65e14ecf59bf25e6494da321c9e112f94cbed6e95898f86165e2b657f145634db7f4fad8a1cdffe2108d3c56" },
                { "ar", "b22012e8fc1a38fd906a85e5258efe4b7ed82f6d318445f40170d51824cfad5eb086c3d8db23204e4bdafe0521eae41d732c043cbb9e699369d19623952a330f" },
                { "ast", "63c4d44424871d474c441c60d55be5e36982a56a7f266417793a181542538bc7d82cbafb051fd4c14a02e64c0718899fb446c276d2643748acb453498f3d1486" },
                { "az", "96871a38eb0e1da074d5506fb5686caa079c8f0a1c68033a38a52cbf115556a0cf57be1c00bcb927c66d4d2eb2039f5979241816bc2a1d547020a65fe7060d7f" },
                { "be", "76c449f8d5be96db39b03714d1ac30d2201084e5b6e88c912ee68ab6408cd87bf2d1e86462db67157a74487969831c3ae9386da3e01a7dac8258c7ec123ffc61" },
                { "bg", "101e23b6bb980d8f95ee95be16698f1f633d5c71086f50fccefb5b585f63dcb1e5546cfe3a4860cb6c572d73f370e265551c2cf6f00aeaf588e392290b011300" },
                { "bn", "9a0c90958612153e2ea806cc9a2560d0a013cc8ce0caa9815603fb8ab3bb9498ecd7568a3da8d8a160bd6a69bb9e8ead3af470eb8daa77e8b32110d5b8bc67bb" },
                { "br", "80f0217f9dab701a1886a96c14003fe606a7fb47d17df1d0e4a9b61876093c1970810457593819feb8a34e7bcc89e9d2556f695e9d0f7cf6cbea9966c54f043f" },
                { "bs", "07f247b8d9b2062509e12b0eabcc458607ae38e96ed9632458d8190c0b4e3eea10b608757378d7de7548bc15ff06233aeb8d2fab7afc75a3ab561bcc1a8e4d86" },
                { "ca", "c54fb9bb49e3016ba5e376569cf75d6db5ef9f437bde2730946e697b37bc2468ebf2e132c27a67ac4f2ed01e81e1fa13fc441bef02f3ff669752f2c27b57a73a" },
                { "cak", "39b8bc69ef71fbf8f53de23a1b081898a4ad08b2fc3c3984280068905b4fb0b0dcc48e4164d116ef9af57da978b8eab8cca9077d66852404dea6e976d257e914" },
                { "cs", "679288c5e92647d236bec12bd3cb9700b283b13771fdcb2c63b034c29e130c3bff332ea261de0429df5d7e630b5a8c410b650eee772feb3b79319a71fc2e35e2" },
                { "cy", "6868c86a63dbbe5cae8aa9bec2c1ff60174f539cfcf413c72ded51d749c38104da9f7beab6897cbda6430eece0650423b450b72437238997db80cd87862660d9" },
                { "da", "bc26ef97b1a33cda2833357cdf78252a167dcc189c0d943763d6454dd39561f94a2925c28bbec95678e25b4ae391accd83d149f19f5f999e4e5159183f677e25" },
                { "de", "e7907c0fbfd666a8992e1a83f63d0a6f0e5d5374586bd5aad886a0e189d29706147b9d43b50adf46b1ae3a33ecfc9fcea65a076909f16ef7d7cc42e6832ebc9d" },
                { "dsb", "3a729246f0f953c498536b49ffdba4a4488efacab0bbc1a21624a9185dd0ba69d538bb37ed33ae240bd3867adb6091e735eab87e5d3acf3746cec229a8407e98" },
                { "el", "436e0bc9dfcca0827ee15087cf12d12dc7923ad044c724d69e6b27c9710ba8ba67d3e91a413212cf61aebe63153548bb946565aeb2c818ddabeeb7b4658313c9" },
                { "en-CA", "fe68dee37930f27cddf7968086d625042bfb20fd2fdc3631c7e8079b3b6e49791834a2c2a05bf1df59d3a97f49f953dcb40dcdff1cfa9f70f983bf8189c55a3d" },
                { "en-GB", "8b2c3eeaff5af1185c4d6057b6b12b77bdc660e85633a93ec234663732ea966d28c8785e04ae840a7f234bebd284ad5d0bbdf3266bc7c91a553582c9f6acbe6e" },
                { "en-US", "bfbd987d3ccb302027e214b9e1e79c05fd2f0dc4f07cb6a21cbee01a2a0e0cac2e039a37dba5f8af3a5ecf6e825ed02b34b75113b764c94a8bec97260c1f0ad3" },
                { "eo", "ec62a70187a9bad6c680096b5ddc8709db2c0817a77017a29058e847590447261bae786dee8c6fe0a9e65fa7c02075d12bb02abb6d19536eba857b899997f41b" },
                { "es-AR", "afd346f55fcb760dc3cde171e00449514199cea7315ea2f5f541743e22d20370f060f190bcf73a1abd83b81553bcde57ce3b1af860d52007afd0a3ac30480224" },
                { "es-CL", "0c7f410e6c08d735eb77387f4e8cc1a33154c9605ab120562175c327e3254ae1428b8240495db4895f5d6566701b486b2d840a4d395725e5f36906512cbe6e03" },
                { "es-ES", "8e4dfcab7b3e2c294b61ecd1512b7670274a782e64ea06cbe2eb47461ecdff372e9cc142db55b77a8ea0737d4730f21129dd9e19daaba43afbdb279e98f1af5a" },
                { "es-MX", "b53eb711b3b71b840cc301c3250741829a1e4ef4becee8d8d4686d38f9d9fcf2d8e3e4a437edc1e50e03aa4249e1903cf1442f0d77f447f6b00e234e414bcf1a" },
                { "et", "c802c48d70d6c90703e9fa8c1693d89b825ac1c0e8cc313cdbc1ad0da1c816ec14e3797b2babe235cc70486662f035c64b7af26bdbb20779181b4d5538ffc821" },
                { "eu", "d70fa96d5e1cf0094505ac71735db6998783ad0b615e98eb63e36003dd410f375c2d97735ca9af1e04f079a0a2426d662cd233c3edec96409e2a12334af5a21b" },
                { "fa", "6383d46ea18a68b1585e2171529ebf28d90c8a6b0d7632700dd2b191aaa5bc0e2a8cfae3a72f1f1d38fbf20345d07705ca300047553195d754cc33b0d2c7a407" },
                { "ff", "01ecc47a0e1c2e7f2f7f28d54de66107d7aeca16a34bf01a782235dc3e87eed48dc1dbd7d2c23eb0e959ce9f05d11c2b831d1d80ef0016102bf945f7f170524a" },
                { "fi", "379b08ecf665f161f54bf72dfb542d412a97bf17e307f73702fb424a4881bd6c923a70960dd615f2112ed45a7b3f74136780b4c49d8338f8747f59f0ac0325ad" },
                { "fr", "ea37ad697f9daa19f409ea4389761f2ea468888676cf421d01e9a4d9b5a0d9a7af1553de5a58741452628e60b22d774d4abb56a571bc690a5138a6acc1336ea0" },
                { "fy-NL", "70f76c3e42aa8beeb184d555b0ad438defc83a5ff4f29f2aa574a0be2d830bd2ad84a59ff3d09df8ac37dcea18c6b7ff723dd787c0e3165fd3789a27c1805d42" },
                { "ga-IE", "b5345f5ac9c444f8b1f700da95811423fa76e71d949abd324c96037f3247e261affc18aaea8de5112f03dc7edc9d452f6634395e87b11cbccdb33e3e8d9da9be" },
                { "gd", "82bdc3f050cb56f9697a3e7f83c04ba48af62bdfed75abec60c4b2d649a421b1572fc1626a033c0bc5100a29afd67ea5789aafcd0de1b89972e1fc5e88eb265a" },
                { "gl", "72381f610cfb0cf0cff41359c3f4e0731fdf54d18fa82fae6397518995d340f61506ac007ef5c90b96a0edcd1fea5dcf0f0438e6e3f39f8f67660132f3d7655a" },
                { "gn", "33198a6dd0e4b675e6dd16de79dec1c17ddb3d9efe5166757b24b225199966e14a3d35cfd132ae85e12d4ba4e9897c6ea4d352bb54ec336ad8aa66d208155c1d" },
                { "gu-IN", "9914e097644f99432320d58a53b97f698f07d91cbe33520df10a8afdf79079845112e6e97ff6f1401776db5d751bc364ec10b93441f1d248076dc98b3e2e4bc8" },
                { "he", "d3ff859b6c6c4ec3db55d1d439f425645ed0908e32a68b8027ea32468db7844129f590234bb3cb0f41930338fa33d574c9ac59483c4a3e17a6dd7d30b06ec34c" },
                { "hi-IN", "473a4f235898bf4f8fab0f7b89750052789bf4f1b99db78aea1a89a4296c26abd61cf9acd0192cdded83eef6cbf61869f72aa1ef61e3e90f5f48168ef6134647" },
                { "hr", "faf886513716426f0525e2a6f0e9b026b77d31f3cbcfe85170bcc205033bf15b0e0a358e4b2fc8efa34580671ecff1f720839b63fb760b1dee08a01f2bb58f6d" },
                { "hsb", "d00745a669beb9ebad2a8ac0deb37f6a86a6c7d130c76dfc25a1aef30921b473b09d0daf2e67ac00f44aad47bece552aff9001e11ba4059b0de79c2c49bb5d87" },
                { "hu", "c47d1a65b65578cdf7085194e669433cb8417c2738c5dea1b949a7054a293e561eb00c5c41ecf62ce969d1c8b210fa970dbd5e3bdd453922a2514206b2086078" },
                { "hy-AM", "956b389de52fa89cf510121f8c180cbca22a76d0a554b2a09bf268ef0ff0926f0b3d95e09b81e99365f3a3c6360a2a254efa243e2483ac61a8dd77998a0c9c38" },
                { "ia", "24841242bd23381f876d6e7acf7887c09bab12450e2e4e9c0f777ca50a83bf0187add582556a7e1f7995c8bb458d190fc2776683c4860557767847398880a30e" },
                { "id", "4dba46e91818e229b852eafc402056ac7fa70f08b933f062093d8bb6b68a69990d6691b9a9acd8ce2b448ea68e580d01d735964fc8edd1397b017ee39db00f7c" },
                { "is", "0ef939fff11c035c248dbaf13eac9d85a5168c952bc0513a5cc0952d6529d6351627572e85468b17d5bc38417ce76152778341fdb8830b5d99f2f99edba5c8ab" },
                { "it", "515dac7dcfbe31056a75ea0e21aaef7bb7fb5942eec1c2d87aa410327e012cc611f2aba1c20d22075052117c66d87a518e6ec5d7f8f091dd5c5ea0d51f8d87af" },
                { "ja", "c44efbb54e9104a26441df6d2700436c4933087f5ab341685eb4730c28a267a70434bda9dfb38cd70ed08e5080e5acab5862c6f341f6dd64958804d7217262f7" },
                { "ka", "6de2455621407e19d33680033ccc78babf06b553f5ee04a013870379be0bf3f1cdacc1b95995cc0a7bc9f687a3541bdb5747a8eedb7af955970dfaf1dff37b74" },
                { "kab", "efe0c92a685570816657dce9408a22ac4a23edbbd09378a5eb46d44d76ddc8525827b80405a7be096c79603b0380faa509eb2821f79457c7a57ed2cb30388664" },
                { "kk", "32db0c780f7c051bf16c6d7be1699c898ec22c79dea8ccd8e64608ef5ff4cdfa61dd2b18e8b1a35a17760e7cac8787fbabc1b09c9cef6241667d9618ad944a43" },
                { "km", "89428007416b0f7e53dec158b712597dc6693cc4eb3ae69fc6b86b231453837f7521849064de277eb03d94b132785b7c178be75ce88b1569affa5e67c028aab6" },
                { "kn", "532d42c1020aef55860b25ec52940d52ad86c9142479e8b542d24a6a547779612ce877c19d5674dbff3791aa3e1bb3cb5a8ad90c0da2247f457f5191e709540d" },
                { "ko", "42e9bea0972dff5235c71bf9e7f30c8404000a9494cd06678f4ce554fab8694f86c4b64a25ca01c7a576e90ab6ff0dd2b220c5c379ac02516754b02fc471644c" },
                { "lij", "fa4d59afb3f8d0d8f8b688b69727152cc0aafed60bac0961fc3d7e9a5dbc0f7b204a19e536b6654bf17c1f71bd75e50f505e08c352b8d28e4372dc602c27f87f" },
                { "lt", "9590902e1a3e9207f002856b776a6244a0773bbe3ff61d224201735375399371fefa94b41523813a58dbfc7cfb869302f90e50a865b3103b93cddcaedd513621" },
                { "lv", "dd09a5b8843e82fdaba6b38cbc11554b3abf20c49a2cd040ed990165d62a8b8c65bb78c348ccb9461d66a45bfd0cb9c475fd4aa8232762bca776f7916b744e55" },
                { "mk", "b61ad7e50d261ca7d99db580edbc0940f1c88a0b65ccbc44d9bfc7818b80bb441c41604480d2a383731e6ebdcf2c57023491905aa2c95573b26883358abd444b" },
                { "mr", "0b7ccc1bfecaaebee8404228e7ba5058286b69d2b8cd3a404bae01f707dddbdbd4c768c7b200bdf511f5e7082bf883f2e78c91d9e30f774dbaad8e3b7048cb76" },
                { "ms", "18b7ef77daf989c2167f95df45409f0f6cd6290f8e688759baf48e7679eb0631ee0d54f0a817846f81fb68c3f63381b16a51c541ce15c6be351e58e4b7d2240c" },
                { "my", "77d990dc71c07b1764d52171503a6c59255cc61939ed99f04e1cd2bd37ea59e65bebf43f8b8b3c3930a6b5ce5b0bd3237866a19ac74503327d3fb47a0fb07500" },
                { "nb-NO", "e6de6b259365a0922bb02def3c052156f66f5b16ceb34eeafe862eff02bad85e6663f55179484c543b19917515ed3f299df7237fe9f1992e16b0ef4acea58459" },
                { "ne-NP", "86caa91203e0a1423da8a78a57cbb4e7426b6306de390b16ba44c0ef9a00884f6627f02d5940a933497014660cd370b773c96514e9350ee42458dd59ecfc3beb" },
                { "nl", "f9c6a35bcbee6e697b7a8edb19edab12d7e27f76f92a676ce7d5dd052febbc41b9d1e1b874ffc7790ad4f98fe0ff146c4ca119e24c6381e88a4228e8201b233d" },
                { "nn-NO", "64b763f4d307226492347492a0a6c862ef6c8ee3ae36a49f6831df6abd65ee19b1d625bd6f531fc9afbba310a93c96d55f5adcf2c33d74b0008e8f191203a080" },
                { "oc", "cdeb3a764efd8f7cd150ecab85033fbd8feaaae3389735d457ce71cd161eed67fa9660332327d6e7753bca906a4480c53a1aba988a7812ca7792b98ccb42c1ad" },
                { "pa-IN", "6403e3ffd2187617b90c1f9159bdb38322f5cbc2722c9362d257b716f78f2440a8f13bb5ec6c5cb4a34d76f769a9f5045c7ecdc4a191b31db52eae099b31e0d4" },
                { "pl", "6ad6a80f332e771c967a008896d11dfe350ab36c1c1c3bb8b7bcb538227b4f7ea3d54f57a850af192ef577727fa6aa5bd7a664e52bc2ba6487a36043084d3a37" },
                { "pt-BR", "3e8d5924a2441395922b5e022703833f6febff1d7925c80597ba4f977fd8012e011f99fe508b969b4c6c65defcbf7c4e1713287955a3e34220c469a13162dbac" },
                { "pt-PT", "65dd93466d01d4a6f0a56bb66856710d10fa307d9f664bcd57a527066da1acfb2b417ba0711e711eb6e55a0029081ce39d57e2c19bfa9a2c7988f2a6c6a35a8d" },
                { "rm", "1005ae2e1f353c8f0303d682509bbed637c708ab3a3a5a4ea490b98a317edcc57c03214249f83fe62b851b859c8825e4118c01195d6cfc622c0658081c51024f" },
                { "ro", "2785d3870dfbcf21ff9e65d8a4781cd2aaf8f691fefe99469017e8460676c733b4048e04c82377d8329fe8093fd6b538d109d53c86cc41b7c14ef87242b2467e" },
                { "ru", "57e3f336796eba375ec1bbbc5b5af6fb6d6f57cae392953643a9c2f07299dd97a695b11ddcf0fd6b2a016828569e900afdd2be7913163ab9c6ce8e8e241a0489" },
                { "sco", "56a69757e94c685eb1a75b41ef3aa8dc275356ef3088accd3f8a7bb89b0f87b93b139dbf186b13df1f49e265362d5d5a8aaaf0e86a14e0e508f0b94f786e18ec" },
                { "si", "56b4f4d83e960cc4c3951d6e935c57708f68161417a3cc31066a2d61c96e87f5bd892e847b8b587dc8222024ce7fbfce2376d13680ef76ac6028b4b53b08d3bc" },
                { "sk", "508236898cd6c3f166e81520c18dc0f3cd9a6eee5a27f05362671e2c48385f5ff0555effca4c7d0ad2b837c8c180c0c6c2924a77c8c536c57cf7de46af605987" },
                { "sl", "80f78e72aceba556826fa712e0b24b7d3de8211ce8f3a7d1c55277e47ee2ab41569bf60879023594f07368e4eebf8da191a00b7161c137d870fe2c7319af751e" },
                { "son", "d85a837232396465875cf4bf62b4b30cde8902e260a2b39a7f59e7c2e7fd88b5628683969704856c2bee32ab6516793bea6ad7b7a15613fff83e2c30716e5a11" },
                { "sq", "cf88118fda7cf01d34f7ca1c73a5a9c36031e6dd7cd784c67585ad9281f60f52d03dfca2830d3d581aa585476b553024c1db953e149c0d407a0988b70b767261" },
                { "sr", "6fb3f1d474fda0ae77b63fb5475c113e299ed5ba5d00052678bdd85559fd48c8b8f09e4ae91240e871331c12f184f1e6cba7caf3d1a19865603c48296d678152" },
                { "sv-SE", "4d902aaf146f6cd75678c6780e8f99d5273cd2b3af1ff5d5b7b9644519cfd4f32f67dd2f935aa46ac7b5cb90c4392191c4e70235a2735500044b5e0ff7c20288" },
                { "szl", "cd1741d3d7365ff4f1ccd122d0725242b6c79f433f0f16bf48a6438b93be989717f78075fe14c2f04e9b544f449181c94cf16ee49354fae63cb152c91d1acb0e" },
                { "ta", "9b5daf2656a5eaff3c6ac43dc45461fbff32491e7f0ad9c4b2c004e9a61faf63d0745fee5d42d49f9d6bd18e1917fdbc46f86e5f039344ff8a847617a52c1c8f" },
                { "te", "0619853a04d8428637e72856e45741b0d4c932481eb8a8d37b85e477f1a6f214a6f77e44729d2ea8a4e5e545e76c3f4c43b04471d58f46f8d98c1ac2beda804d" },
                { "th", "b39f992685b265f1c4c4aa50b18c2a69438d2b7ac57aebbec56652aa5e27acca8edae442f2aaec081e204fd6d308b1571d4d045ff563ab4c24a2a85236612487" },
                { "tl", "3fd40bc25e7c5066d2e22a09fabbefb21a52f5c2b9a02d0987b74cfb1127b4e7e10a90ed7b567dd276149e8ce46759a75db6eedce0713b612835650c01a5548e" },
                { "tr", "2c6faafe65fdba05a3579912a1e4925426fa872d8e8ac97e4d2d848187eecd9a9b8fb52e6255b1eb96605e1745a19e4ee4aa7672ceeb961149b48d6310f0fd55" },
                { "trs", "e1bb3faa5abc5496d1422c0b50441111db120b4b6b02fe29f9f7d263c1fba1444496ba5c58e8fdeb702a71ae2c79074f4d43584ede0ebd00327dad01bf0e0d16" },
                { "uk", "ee6c09170f8fd83d809951677d38c5b4ea7037ae0c15d3b65f6fe5715cb21840de209a1ae244d7d4a8f5affccfbfa14345ea872f0dd0ece8cf348716ac56c31a" },
                { "ur", "58382b593935a0d797745556d477d73c751d75b91c02ee49a73d7348b26f4aba41cc02a1a9dafa42b33acc077ff4a1a843962dc6e933570787b9d2ab352c8a9d" },
                { "uz", "2ecdd8ca79274d8b083e2984d88d75af6c325c40199dd7d9332c67c3ab8268d67ba3e33199db482e24b134768fff2d84a54f51457ae34ac2e9cba65e59ce6444" },
                { "vi", "48a73d953149bd465e32e0cffe8acb227c3654477e78786468626278f13632507b11b5644f6839f6372cf0f16edef4016e3ee69a4d0ad83f88dc206d015b4737" },
                { "xh", "696f02ee65dd8733e61a1cbc30ef7c7ff7cbe861cbae3da3de4fe8248ec58cc991e55f3ac470a40075ef4f835ef4769c0b2163a50abb07774e454e48c60baca6" },
                { "zh-CN", "e2ea0d44088e2af9f8089751641b8bbf255cbfdf9c146b6ffa7f2f66c87951c2d26e30f06e2f43fbeb9a8da53a59831a724c8816061eb7b34ae6568a48390350" },
                { "zh-TW", "c283d4a47148e6a6da3895ccde832e26b8e842a7fb3b9730f124e4e11acef168e748b772c19967d752f84cdd28b2b20a61e2820c883c0eca0986acf25ab9c2eb" }
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
            const string knownVersion = "102.6.0";
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
