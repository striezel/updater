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
        private const string currentVersion = "128.0b1";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/128.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "fc2ca0de225c103db4871bef5228b89481440cd8b4f1551d92c1f4676587f1fd7fcbb5e162924f996d97b1901ad487702cf1d8e851c11e53510e83a432f3f058" },
                { "af", "bbb5312ecc3fb4ab023a627db161a644ed21dd74ccc8791a9d4a8f36966e6a84b670df653c0b3cc42a9827c96f4ae462bc30b1886b548faa12da99326d684aa1" },
                { "an", "5337d10fc6bc949338a9d2cabcb61ced31b3550f4b1c7b84d2ebf75f3bcb35c92fbfbd90100fe0faaf410624a39333017ac06adfd65427fa1d80f108eb6c1af9" },
                { "ar", "994c7a0fdc1c4512320f07112e67b55fc3e2dd6b65f79d157fa1c24cf1cb8460812e2deada75271b9cb21f6c59774e121d930b1ae9a6fdc1510b952a03793605" },
                { "ast", "12681927c92b00f9628a9b51b6c3697caf5785648bdc4bd9bd0140b456a5aa0167ef240ef00e3b0dd892c9b1850e5f3e5b98c907089591e68d9d85405a81d7a0" },
                { "az", "1149b7eddc7e211b54ec5b58fa9cd146d589d8748da1d42d4e5ea788fe6edb7d315c5af7e1c25cfd8a11505715820e66d2e74cf737986334991d116c4383ccbe" },
                { "be", "d340a597e022c2fefd554f21bee75a9033d72d260aaf4477121b95594c02e38a660cf2689de8ab6505aa3d085f866fdc8e18330e0b15aa0f5da12bab54d9fcc3" },
                { "bg", "72c29fe29b2e9ef5d4b2220a1318116bbc084772c2a14efa16dbadeb902d14d36033292be4706441e97c9c87ad5e0ca13e22d916f3ce4264c15336eb659ab195" },
                { "bn", "a84dfa85c08dd86157b213b0446a06837e0bda11c53e9f12f4dd40b286c972145f0275e0265aa923bffedbd14be39da12f3954c3787a91d1186d589904659147" },
                { "br", "d590373eccc97b037b19fdfbb983fb93a19afa7461c691c03fe867832872c403141e992ca80d3b2ca37a7bbfd8ba23991e035061b33b0995db78017070c1f704" },
                { "bs", "ac575c82770fb3142a870fc101a374bb524b45d90df54bb123c08331d98f913161fff4af61599e6647b4c928d9a1c2308cdcf130824ef937bccc09ddeddce2ca" },
                { "ca", "a82803be76b2f5747f27c56c8a584399559368993e9c1fe3743524d4676f3e0fdbd3203a3c4b842775ab5eb3e4eccfc1918532b996897ecb2881e2c2c263e717" },
                { "cak", "e37fe01c6b6397527f7538190e0114ed908f8876087c48d8ca2364e256e8de2bed5fbd8e82f3dbefe838312d811aefa048eb3f80a7a8d7e04700f26358d6b484" },
                { "cs", "7b3d77c58f6b916def3ed5c8a90c47e036facd32e2eb51e2bfaad9d9b98d818347bc840da2073f248c3af231c402dd94303c53f407c90f6b4df318fad4a5e17b" },
                { "cy", "c46559ea9d0c0a610f14dd208588382f7ff8609e9d56da57cb38b0890459c136cc47d68429af7d17f526daeef93be4456e442bdc958c3a96eb00498963d522a3" },
                { "da", "aff4901f0d57427bc144ff5c943921d8a585ecc69dbc3e799855bfa6f79189987479e77fa3820188c5306cc61f5a7fba5966b7d58f56713338113e4f97b8cadc" },
                { "de", "c440e1a650ab1eee5b123293ee8d68dc9053bb2a7fbacc4ac9a38494a47060d1d41cf23e4fdfbdb558bf11fccb20d6aea19000b2d19687d68b7ee0b9369e1a9d" },
                { "dsb", "2eacad77f3733f9d7564863d9612b4dadbf7276f3f20559a805e2d77861a7ede080a1308e9ba38bfa625b18ed60406b9eeebfa146cc341d0d7bb8afe7f815c77" },
                { "el", "c548cb5b69383e049a2772e8a165b851cc6d8efb8c782570f2d11a58f563cafc47bad76152c884a56d4c7e261133cdbeb27b18f92be16114c0326c4f4ca1602c" },
                { "en-CA", "0ba61e13ed3c7d7c5e5af6b683924d9730ed2b0f4afc3330323635878b95ce731e0e8b1e2efd0ef59d5fd2b6c054bb33f9bce6a63fde879fcc2ec013ff0e4cfe" },
                { "en-GB", "4ea5e6cefc4397b891485db2f6c3edc0f257776621ee6f816a616409334a94dd0b19547715231c32e0a15ab7409346116f8e10af3eb5e42c12c8361f8843dfe5" },
                { "en-US", "2b16b1213998df7f1c197e0f85678e3173d3498376732ee7471482800eb284f946a3093e787822d2db835c6de2380411bafbc41efb7f341eae92a4f3b3b5b540" },
                { "eo", "65728ec24223dc2a090f99201bde5c5a3b46635d38fcafed961872c0624566eb50a8ba8c2db1268d4cf1e8807266dd8f20bae9bde624f693a92f932467dcb59e" },
                { "es-AR", "0b161467a7ab2bcb29104b642efa8f1a68fe774755a704e72e7b23ca2c8b503f406e8d8836bbc29b036948dbe03c8f5f48e1593c881e8667d89d578e860fbfb8" },
                { "es-CL", "a7deb3e40456f145645fe3585cd566e4dd5bb7b4d63fe982cffadcd83a438bcd6d5fa28efd42aa8815bef3b14f664efb91ef3dea66cbba0d9a1b7a4b5e4137a1" },
                { "es-ES", "76c06b644e09c0798d0a99e0eab5149e431a87bca0830f5fa9f3864e35c8c5d2b82236e964fb33c389bdc8a8844c7c023ebade47a4fdff47cea620ab961245f8" },
                { "es-MX", "1af46e8c28416e19a464cd7a6ac69748b6fdb13dc10ea0e81b89c74e77804feaedc3de5a0ea87c5c1219bdde996fcf255579f3e516c5bc931938b9a75d1f8ccb" },
                { "et", "111fae413594c3ec13df04b98cc9a3ebaa1b3c23245b66a4570a1297f090dfc45a12301eb51c972af1c312a521358fdd7615f3e531b4a97e49ec27f14024652a" },
                { "eu", "93237f3f249bfe68d205104dda29c3b1c40cac439ee4adb324ab1a806083b84b2ddea223309807c7dfb1889dd5e7cc7255ad2afa2ba3dab8d62b212ea503c3eb" },
                { "fa", "685b8f84aff810d1a4cadb16362897f8bc468c1ac117964317cb7674c17f126c4a07a28f0642c7457149df32e9c1ddccdb7aa0238ebaaeb8418d31c753698d37" },
                { "ff", "cf27c425bb15d7b45a32133ec92f7bea9f8ad04bf3fbc31faafa0394298b4f8718d22b20019dc1e45e13c543e32af1187d2320a19fd03547134f27aca9afd5f4" },
                { "fi", "710f45fcb382a0f75c095a2aeb2e4f6e9c95ce02e4c1d115d4f11db2774ddc87f3a2187d4722617f4464814f355ee22a74defe4d04c11320756b6df320a23ad4" },
                { "fr", "6df0f9acea09f14df0362b8633c471ef68a8817915745608b5efbfe5583e42eb40a8aef0a6893594f51cbfe5167273e207bd9806b2867d1e194541039642a9ab" },
                { "fur", "bfdf6645b4a3ea1cd0a063a84c4c30fe9963ee9a5248bbc244d293821adad05abda192fc552acd7335272318cf398e318076b2126420c8f368162d1219901adc" },
                { "fy-NL", "d3ba8298fa68fb86877ee44cea4c35c67e8c53408d25c4425c94246e7d9b14be9e64926f0fd55379fa75912f2cc7f47618b6648eb87d7a8005188599cd6286d1" },
                { "ga-IE", "2a6db02d1601ed65764ebe068f766e9ebea9798abc3bdbbbf49f5318e3dbe6e66a4aa7839551b502530cffbaf6800840f449c17c5a588d073f6dffb909be2424" },
                { "gd", "dd5925e4c3c46a21be10cf68c2a5c93542a1edc72cde89132ddc2f25ba3689e3e51aca12d3a8e0c7c8137ca35e71cf857d407c8660c5a30c452e980074b239e9" },
                { "gl", "34c5d567259084be671f4279ee0fabca04fa11543e1801c139557c08c64a7ea33094a6a7253c621159fb035ce49d44299395ea99539c85bc464c85e8f5a5e0f9" },
                { "gn", "ee4dc2b63e38a43f63309d11740b7b54e7abcf81aa1444946006b20945bf9020eaf8f6cc6487f4bb53aa7aff5de33c2b252958a2b4f5c2530be23ced7a913856" },
                { "gu-IN", "58439933552cc8e5b2f4a561b2d479cc5c9e454efe79e8eb52dab932109ddee6b7e7f750e874365cb078514991788f1b89fe391bdce1545f250f1573665f448e" },
                { "he", "0183bbec1f168c1e608ea898005bb014264a9987080e5e670031f51a550a2ba4f37c76043490776f8425f2e9be02d2a8b69610aab26af95cc5d138666a35ebce" },
                { "hi-IN", "794cf6a199a634158f2a8d4f67ecf63c2f9dc7f3593632844c524a551cbe9fba79eb1d8373811d44d3fe7a8eded3bddac97eb8c47c452bc543bc2ae226d6b289" },
                { "hr", "beaa57a67d62927a0fc693f14621e3230bf66cc358fd4f7691751c8d0f75d48cbd793a03836b5f9c0b6beb6acee3d0806dd8b57baf2944bafb5f55290f8e9330" },
                { "hsb", "0e40148f08d3bb7218f5b52411ec87dae5512745c987723f4d191a7a59193514556faad9d46bf018192ae761c482546ea95469a316b5c1fff13bc6615c10da18" },
                { "hu", "aa20099ffd39c70b045e2677a67d0a292d06ce722c819e2fda9be44ca8902b96de385c54161baf8994e59c74f78a171005a85d05238ec7692fa2fe8db9fc74fb" },
                { "hy-AM", "02a7908b53d7af9165e8d6b057e8ae5b51a9b83a501eafaa60627ece1a711e2d99ac9bb7c7aeb4007857d5ebfbc6aa06761e9703dea211157ab1dbe4cc5c08ed" },
                { "ia", "bcbb4c502201ff82c27e50242cd6e5aaf6c0e475678e6983cf8087e866b78c8e3f52bb8549a2fcd5129bbc2db43a7b103e0a01a83e898b0cfadc9f13b4a059eb" },
                { "id", "367b37f1b05bf7024aca193924ce40b5d914e1ee82c7d4adb8720f4f6b73a6d73afb7b5bf0d3a1f2eda2495693e90784bcf33f4bdf5228460ed9574ea77bac39" },
                { "is", "5e2f4cf13e45a02656f7f9bf647c463910ef8ffb1243d019ba7998d2802e92bf57d0cda87cc4916c1258698b5132698ddd3cb1dddc460893371d227872e775b2" },
                { "it", "2094781d70e139c77197f05c01505155db0c3d73508c42389e2b68b6d78c647327a510d8b1e78588779a2e89531d244c931e11d0fbdf5726cd1bd21ab85c9310" },
                { "ja", "8d08f7579f3dbb2c94a7e03da11cf597d39d10cd897353936774d2912319fa27116f066aafb6402e50a8068eddb09cb767a2ac8bc770703d198a1c63f43f87d7" },
                { "ka", "b1938a516da5c8ef89be3fe45e5a9bc1cc2fc030e9d166c7cf9398563434f1d3eaa41d90ef5cb049180691812808eb3987e3d4ad961f6e0bdfc31d72107c0478" },
                { "kab", "88fe40300b90cb79ed4f93b739ec7473aebb24141bf07ec6bba23e779aea1618e90cfc63352088f1cf369f0c946ccaae450187f088e0b0988262f82e18190e44" },
                { "kk", "e351ecdddfc886359782010122bddcb8c6e3517955548b9e76d44014e63e5d7bd27d53b5d0872a948fcdbccf35876ecdf3b9c293156d215914c38183808f7834" },
                { "km", "7e073d62a1cf48e9f42797070c284d79983600b19f61530dd2ee221908cd8bc2c943efcebfda70a0856383107e720026d94e9342672bc82597cc00314c8e59a6" },
                { "kn", "5f5ab77393f2af443ac07441bf2f423c16df0d9b33866d971eb384b186a681ebbe515a4ec5e32429c81172a06e5d937e62756f1c140841838689b53b9db8b71c" },
                { "ko", "db00a0785f8d449296d8336014912ddeb8d29c6d2347e9be3232efe931100d3a8fc691cf97925fab1b88151ec91ed370e8989d8f5d05979fac69503ba14cf1aa" },
                { "lij", "c0122ba2a3169d535e714fadb48c0f19b5f2df10c4ee221f00067ddedaaad4822194c49481f8f1d34c793f20d4f1f19a050ce58a780b27082d9493f4540af4e9" },
                { "lt", "260793886b96c3ffab040f407de74a037115c83601402ed4bf7ee8a5231657313f0fe2440115fc268812646238893845959114337caac7a28d7447cdf70a688d" },
                { "lv", "682885a7a003733e634aa7efc136c8de30be565f00db5397689bd040c92aea06b48a9a764c2853c520cc21016b089294255dd087a90e467147995f205fd4163a" },
                { "mk", "5631e1f2afd97eac880e9e849dfb876fd79e19d5b3e5af965a43ad8edda7a6580f11fb1cb1572ae59c958af08b89787a61bc490f42eb8348b620ab3e76b9ae0a" },
                { "mr", "d590994dd66a7d8f8fb785020160877f503f61c85c3df9795619d80ef770181c10c4ebbdf8100f817adf75b63b5573faeb0645733fc151eda3c5a47dcfbee361" },
                { "ms", "a52d4055c60bd3b003a801f905af56052addaa8fda9df311300e4932a6012791b33a344f1e5ca35665ae0c0a84fb095f622f09041b9151ece438cc4d23b2dace" },
                { "my", "52fd41e3f70bb71aae19d5733e0ead21465a6809fa455ab3b9ba8d9904e068e8aeda2413805f8289a6159722840bc9333d83cf4249bb5dde4113ff5b5f220204" },
                { "nb-NO", "6f1c139c5dc5815958260b5bc55571cb17fea3508bd011d81c8086c4549c211ae06439ea6b3356f952185ce996f5db51a3c63099e0f02d6bd31e75cc664d7d18" },
                { "ne-NP", "f62ed3b943eea3bf2ba5aafe6cc2048dcd4568f7b1e11c01bddfc243fc109611e1f06777838049fd2e5cb92e5f875ba898c84ed63ae3841bd8de5a3ba656eb24" },
                { "nl", "69a8ee142f0004042887644470913a6f05f8596d6864f540ad3dae677bd3e7aeae97db895d7ab1f87717e0c7ffb85323c6407acd10d4aff1b1b0f8d820f4fa21" },
                { "nn-NO", "c42b33a489373acceba0f750973122fe61a5dccb75bdd006da2ff8b41cce334a32f2388bb7116d9891dd9cfe7ffdb5aef1917375e3d2298cb0b7c2892a6c577a" },
                { "oc", "be633887ecceb50ec6ad420ac351e492918748fb03f590b63ebfbdc84423c5821959629b6b1e87d88622d0f3710f132bf1c7e90ef73cfcb9009d0a7feadb1b15" },
                { "pa-IN", "628396b037b2de4782ab4a6b499709f3651e7f163ab61d302df7d72642ec6c4bf8470509a875f076f1014f5489cb72db0fb9f8a35084c7548226b41317b38a18" },
                { "pl", "06e8e24ce7d281beca2089594325784bb26b96dd4e704f60d0827b02994fc78b4c4d7351118ea3f78861f546e50ee537b7e78a54a02ae4ac09e8570f110c4af1" },
                { "pt-BR", "fb60b9b0fda2bd411cbe3751e9e7b32ee2f604cb27376b2df3c51fd3fd4cac8265432ba5b7a50137a3ea0687b9d0e7d6c5b3033d9c69d865ad7d05cb8e17da7c" },
                { "pt-PT", "d4287d0dd9ba0b13153ba45f3e426682a4a075f463725715cecd176c35ad5d649aafeebdfbe409fa37b5f0e577342efa4e7f3c41668ea920e40cd02e6ef8a2b3" },
                { "rm", "a2d3e65f6052fc70486c904ad46acf7ae6d331a3d323f63c8274a638fd6006036a483d3c93c1f8c0c5723c1a15d95caade5f3b5b9af1538b4271d7d8624ccf91" },
                { "ro", "c81788137defd6792b13119eb8e879106d7249892b8104fb0f5e74259beacf3c8434a7b592a146cb76afb80cab1e61f5b282016642f029ab8c7b5aff6b9fd513" },
                { "ru", "9469a13812724163ac8f3c98a545b6eb564391bbd4b26ade74de616bed1b477bc8b776acdd7bb02fd2130d56edd9ecd85064c5c64d3e029a4bd9e8cd510086ed" },
                { "sat", "974286c5275b34569ecd9bdb4ad27def8f2ad80c514b582526d094e2048bdf2b4bfab8b80609ab5d18511a9f8aa231067afd28ae1ea5f6eebdaeb6e29c719673" },
                { "sc", "8dea67f5e406fac85a6d9b8f8d2e94a003647908678719a0b907b148fa787bb9cafe8554892f57eb7c5e18dd43184a378a3b49a37903d6d98666ff649dd22563" },
                { "sco", "a64c31a50a5c72a44452c419b7c3c4130ec3013139f1feb53775894c086e54947d21f441be6cb1c1ba6d4a8053ed77b99ecf60f84f32b1615bba6196bff85c74" },
                { "si", "213f63ea08c3831a38be4be23a4bcb8ea65e796a6ac3b080305ae74105b9e43dfc48eef7b804e4b017abc08855ae6e7b6533bc9a9d2e8dffbba9f4d02474df66" },
                { "sk", "9f03636b7145cb5fd671f22a473c584d1c2ba240015dd0c3b93eedfff3a25dc30b2a1ec7d4482fc31b47c6397c89190e6f88ecbaa0412aaed681ce8af18163f7" },
                { "skr", "696ceb4c0b7e22c0cebdadd68aec13ec4a9d7b73518f4ee48097018f17c4336227cf1df99f405f19257338244bf5f5dc20749f99a08315259d8a66086503b28f" },
                { "sl", "79bd592a4a59504766649bb41432b7ad3dc9874d2798054ea466d9b25e6a9095c79d7175fc6e20e7bcd0995ccf3803536260aead68a43f7e889d74d8fc49b643" },
                { "son", "6d8d1c0ead72e50f6735552b7c5ecd0745ef18c53fb463b0189c91345c117c1f8f4b34a5cef348403e13268263f3564a34cfa96494377c59d0f5ca727b4f7a2a" },
                { "sq", "fc47c45a7e88242bd715bfe811c51fbb77d85215b46d43035337f6a0c493ead8345ee2e17c04ea6758b89f836852b9d098816067f8158e5c1d0888c02cc5afc1" },
                { "sr", "eaa93a4093b7f5bbfef02124e3b94516037833bfe37d517cd1c7ed0f2d64f62998619cf42c8e9e2f0228c32d4b5405403b3f007c5e5f17f9b048a37ea7603534" },
                { "sv-SE", "cbb6565fd596b4b42753be6288889a3b2c69bc58ee9e4e3666c689ee12540ef9e3efe8e660c7386c5e186332b895c8e15b82a88c79c762d770889e20a737e5d3" },
                { "szl", "45bdde16c677f6c4bf45b865583ff8b40d5c39606940e7a9e1667cecb8ab0332fb6e2319e028f21749f3b56b0e55c35c0a0cf67d9e9a9e49777cf994edf561ad" },
                { "ta", "8460783a754488d5f0dc5f38816bbcc6a6b08805ffbb6d780ac5d79fac87780cc8cf3b5b15b61964a990deeb55ee8c54d8411db401115997ab4a6f040f4dcacc" },
                { "te", "48158515e196820be95f07054f2a46ff71f72cd14204bdb856dcaa89df95cc59549fcb21456d27f80d8b50432806ca943f37c3261d7462c9483e47b35862aeb4" },
                { "tg", "b32ff04fe54f16c92e29d4bef12a7767dfa69c89fc051a3b8c6888bac168b88f6c9181553fdfe154ebb06d866b0f356ed0405c5ff26431d6722e7b0e1975c660" },
                { "th", "b6f4c5969ecf59c65e000633d04bcf1dd3c30f02b68891cacf1e4e9e5de25d5bf6175b02f0f2b19c835e3bfff8b79c8fa100019b7fa8c765d2e24407f80715ec" },
                { "tl", "ac0cdf63e75759271d1ffa42000ea9aff23a842699366a4c3190134719da5f02ea51f9e2bef8261228a115bf4d3a029d1a45acc131228182f5b0211683799019" },
                { "tr", "755a7bed62ca1ea09aa35af311588ac65063009e912161bd82e4d1efc3531b57b7415e1a44a28d76529c9a8ea9dd04c6ae21e6b0f4270f9747749ab03106e11c" },
                { "trs", "d6456c17ddf2dc76203ab0e566e8054ea2a56b847e89cce20244e24611b7eb78044178c3f93688c798d8007efc6dadb5383ba9b67bfdd0938786af461dc18d9d" },
                { "uk", "e236c26e9d5b7d0b5dc0419f0e62c3e036931551b57fc7966730d8ceec661f5bfcb696f85d4dcddf0ec85ebac6fda12ea272e9dc15b45d1f51adc8a4ae982aff" },
                { "ur", "97407c25f95f731a5a78c1cfbf4dac779e951c76381b79ac845d251fb32fb6888f2d75585838531084bfef5751526ea1110c09dd44ef1766b1e60584ab6b7fd3" },
                { "uz", "462fcc67113f51146bac98c6378d6fb5cd39eb58d46c0d90292b8cdcb720ffdeb9c13ad1e25ea6c9406abba4707c0490411b4fa612381f81080ec974387e44d8" },
                { "vi", "4ea5a83aedeacaafc6a2a59671f73527b45cbd2b7bc7235f65dbece7e520f118a629b3eab3896713fa2e0adf08647725aaa9e8649bb768f3a927c2f8a7d15696" },
                { "xh", "39ad1e8e6ca6f1e63e446c2ebd055105290ab848c7be853db6f398c760787d6b6f8e8f3b98efb08d78038cd8578ba51bf418fc34e363336db89096fe7bec42e4" },
                { "zh-CN", "5f7a3ea8d5bdc2f73d08e9e58d141f0725ac345b3df446702b86d7abaad5aad9e352324d003a707e3272f2e9ba9d08bde107372e7d6bf647d8e365e864011a59" },
                { "zh-TW", "54988e9828692b098894681bbc7e7b912ea772d1971b39d673174abb97a4e797146ef6b3704c8791773ba827ffd2eaa6b0797caa2107f1a274b0f237602e2537" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/128.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6c0547d9e2288dc2bc2d314ecf82290bd209f1c6084fd081e3ba4a92be758e4bc1021039480930eb55f730e792b9d9c50094fbe1273a640803867ec30fc81f6a" },
                { "af", "8b448170d89e60fe71706939cf66c910b8d91cd91e525d7c0e1e9bd9a85f54e6d4ae707820098d958de97c2aaa981134884208c088e527de784ad9def56a41ba" },
                { "an", "f16505d83e893247489cd9477ed9f0881fc03b013fb64e955e3e86d22000a6d02b879dd747342c6896724732cb0be29dd24cba59f08d9deda9c06f29cd151cb1" },
                { "ar", "9358e346cec2c2dd54c8657de8f2cb52db6cc19195a3ab8d2e59d146173a0ec676842cdcb98e35c2512481feb072e43cfb4bb6590d75692f25e002e9dcc334e7" },
                { "ast", "e4da55b0118a661168681aff5f8c8b5e5b956bedae99a93aec96a3765c6273b4b36dca206545e3d7e97ee305bbcb274407b22e61c210e227156a65a8f77bd873" },
                { "az", "09fb3194fbcc617fc74a49b6b4dd7d0e43446fd15a60eb342562d0f4199236f997f55cf7a94f269b54c5431d7b49b5b97f79c56fa927a1ef0e7366e5ee34cb64" },
                { "be", "9fbe1874a78dec6004197323280ba9142261680045ce397c5a168a96efff6f0be25dc9bb2590c3059d5a841c0cf279438c2f33a7e3a64fb287e1ba8ecb7c66af" },
                { "bg", "2e9a5c9ac5bdc9f2e77217a53fc5b4d64359a4af463b1d2d3d7387575a5b0035bd55b48e0014f741398251dfb9179fe23211753e0a44e1fee9a654ebceda6e82" },
                { "bn", "4ffe4ca80a1785a492143b88e7122d00044db9d5287a4e397bed1b8894a17725009c3e045bb8ee7d0e88d1583706df4ac3f61a01a63907811ca3494561769b32" },
                { "br", "872f0f95378a94560a08463e5462c037aa54e901e8bd447eb7cf6750e932844f303bf369d23f649c90290a7d3e6a087a523763ed718298620a99456714af3740" },
                { "bs", "6b4f7ef36dcedcf48af0716e49692ed29921df973dbe369a8c49016e9ec1a2924f3f67acd6ac763d7f1c8f2bd968c19017968c05eaa6869ee1f3633171c7c86a" },
                { "ca", "f713ec1fa683ec82788f664fed167de8a3cf99ee0a4cba3ea92851e0f5d878f57797b78690930b98ffbccf6655627e24b59fbef58dfe25ca2e97216a93ff9464" },
                { "cak", "82efb41b8c36427c733fc5e1d46c379ea0e6734b890770fe2d1db03c39dd2943b7c71d2927def6a0f641bfc307c3d2549c92a2d2e52b03ba3f3bf4a775f7a180" },
                { "cs", "dc35c589a675072d47aba28183ffe6b20339e78e04f41de14b5ea9a68d0e20369935699a4d44705e984fe51915414dec253fd0ebecb8f68a6330d217b48ebf52" },
                { "cy", "27740f78ac49c464147b16b5ca4bb40e18ff9ceb2f7cc88444c576d5c3dab63670cb6227131f0234bbdf49e0d030234d0c1264e7510795c5ff12db65cd18dba4" },
                { "da", "59e7dbf8dc20651a101114ba77e176b89bffd45214c4a2ffc57f231a577cd8a72bfc03a518e20a535b06200ce3d01b152de48134121b06d370f247e06e206e33" },
                { "de", "b779785ce54eb73be6028de6bcf4d653498adf1bb40d4ad7996756be9ea62af0d230508625f7f24bd0af80dae29b36c362d7b3c4df254f9d03bee181ce75e4d7" },
                { "dsb", "790f2a9d3e93c54ca73db18c92e67b4114e3e92fcc02ff6e3e34936dcf03d8ff3833355c70528d55ca5fbe285ef0eb09f52e7fe92e8d892cebcb9c2de3ed9471" },
                { "el", "9ca1028e7d941c98148eb4f3609c5b010c181a6be193b15bf3adbfab1e1fa1722e46056bb987fefbca8a5026f53da572d00e502173a6bbd68ce3c76349182478" },
                { "en-CA", "5574e2744742e775543a086c43930512a1a23006ce9cd620bca97bcc65e5f8ec63daed7bcdc4ec1fcab5b159ac2a832ec72f935b88c0332c2241252130d0bb58" },
                { "en-GB", "adb0e046fc79a5b819226179e3b29bf15aeaecec36d66cadc0c4cf03d83938094cc3efd888a8f82dee10344d42daddd4ae710d5a0e5004dd2277b6b2e7011c8c" },
                { "en-US", "fd8e3594e82eee6ef9ad20f03f5a5fd17a40788b9ca337f4a0304ba402ce5ba3dc4d27d7134904e3740b484e835c377ea11918667a8852f0b1e8b2f4358b08af" },
                { "eo", "9f15b0b693e52364dcb68a1ff53f59385f34389b3930e096fe6c4f8e14cb17e1ee8197069e5231b5096e195d2af8957d0ae11c59fe258f58250cd22c37755768" },
                { "es-AR", "7b55d6997527fff23186341ebe28f59d4103dc4e082f844541efc4ddee257ab86aedb052ab43dbac25eb1b47c188b3b8d7299d62d66d20eb30c8096a13c63505" },
                { "es-CL", "6ed8e13407efd18eb97b16c62ed2c3691a42ae75e887456cc0a2870fa42106d50144e30c673494cde6f9cc840072def5dd6a6ab5334858507ceaea3821be3cb9" },
                { "es-ES", "ed929e3e9f503e63f7cbc8427d76c3a72b02f1728a0c64b274dddbc595550707f6f2303cd8ddaaed5ad38424e6415c370036ae3ca72c661aa30b3f9d93f3ecb0" },
                { "es-MX", "4a289782751dfa77e1ca3a3447036efd26e9372e9cde7f1b1ad6c2349df40a3439dbcb43f79f67d4e0e9ea31a316be68828e0239eca0d5345ff1862783daada5" },
                { "et", "4f3cfb70a54e49c4521fc56c776bde79bc42da42b9255dca9573dcd391329a205c176f65cab07b64acbd76ffba0b7c9fbcfb64bc4cb72b9a75290a4efeb9bc3c" },
                { "eu", "fba2b69889150b00de401f86ef3a5d8767c66b0637aa548802dd31b1b28505d48c4b0831af11e240fc52cc1dedb601385a401d8e4ddcbdc64df31948989db247" },
                { "fa", "b76d9af691f0153f82651a8310ba8f3825a31901c119f93eb4894be55d5ce816be2d6054aa458635ff23628b27a38b497775d0e866eeb733e5efe94c5219af99" },
                { "ff", "86b50b802494ef6f9bde1576c0b5df78fdc8fe906258e7430caeb98d64404695454f816cda0ddc29214be1cbc652e5acca4470f61568903cfd5ea8d61804ee15" },
                { "fi", "12475ed21b41e6a90b4dfd77de444420a744c733a603fe1a41daf4a03f47a126c7c0b2e94a04f1651d305f5492020dc0e0b6a4ef9a77b4fdfe79fd0215295b40" },
                { "fr", "48cbc2e3afcfb82ebc3c45f44897afae3ecaa88f3d90560d532fcfad476d8f6ecbf0c331d2578946c4bf1e179fad7806c7e4b6e855ff6a5aa653704a6731e2d7" },
                { "fur", "91a34741f47ccd3b5347d116534ca4dee48a8567261cc0334d81dfe760486aca0cdc8453963f3d5f00c4c8dae9cd78f486fbaa7580793a5c7258d7eeb4c469f6" },
                { "fy-NL", "cc37d86b48b482ed864f96e480a00a78466beba51958bca7b668ecaa11ad60c10a8b40076e9420f1352294fe54139e5f1fabeba05f3d90537a37e5f4d9e16cbc" },
                { "ga-IE", "8fe6866defb1ff969f5fcc3e564b489416054927ed8bc40ed93e100178985db36ce99f53a401d45ee57f65ef44fb63c28de232798675a422cbb6d101c40f958a" },
                { "gd", "6f124f57434ba4a6f1721e950a9aeabd91243f7d76a268e586b716681264fdf7937d037eeaef8965df582bd9fca155f9a751c2a851b35dd21845991777cf0cbc" },
                { "gl", "93dac777073c467efd3e2329f6168bed43f35a7d6b21e75c6bf04c6ef63038ffe8c1cb84a4c99bbdbcb70f253a5a11017bdb7ac60b88771441ce4d92b8bdca0c" },
                { "gn", "8cbc37cb7886a380b3d5cec58d3817e128b4171f62d29be00ec9abb58f37680143e972f711a74bb3dda245d45704ed991ff690d313ede7d7b3acf2a1837b5fbb" },
                { "gu-IN", "95bc359c9fea0a0ab1a900733e45b5a1fc384b2aa1a21fcb996bd0e7ab6a06960c590815a4ed6e09c3606a6fa3adba23e1fc9bb2b591aa240e7a787da2121277" },
                { "he", "2e179705b8d27079ee4196f75448cc4ab31ea0ab4516c601ea4318a2343ab726f9e24be22e371c70a94f3d2378396a2ad20031c3c799fbe45e43c8618e7f7ca1" },
                { "hi-IN", "f54b9cc2a7c7e482cdba91841b5b47d35b48a7f2be6fed3de8dbf11de3d3fe5ebf3fb39e523c01687b88c861e04f9954db80457326fa56f7c0fb53519bd96ff0" },
                { "hr", "791a0baef0172335d1484bec1bcf8ab82c1e6dafcfa537f5612500e6fda275f050de00f5c02a34ba6e29021745818316d4b17df1224206188c179fe7ad2bab78" },
                { "hsb", "3d270bb7015285db4a223776064a58c9aeedfb25cf41fcb8022d61f7d40b421a5ceb95462e8a7fc98c7b43d4a6b5c4805a216ff04ba024141ced277a1710e1ba" },
                { "hu", "93f217dc6cb02db08ae7cda06e56454b5b9805410a56b2f6d6b36a49b05f88845bd31e96f4640b0ce5b5079e41cc04a16974e18ed692af7d631e60539fb2a92e" },
                { "hy-AM", "ccb5731a2d9f7d6d20aa0c36a694567be255637f59ac464d34a2a1d27b8c6f03f5c0bd48a2d62f21a40802439f08416e060efb0b1ea67a9f41b5f98443b46a95" },
                { "ia", "d275977d62a66e7504d13d49a1c30b31cb2b12483ea76fe9b49398f1a9bdff9cbffe52130458b3fb9272b494412f69f050b6a36c43a49ee7d42fc5ccfb45059c" },
                { "id", "4155f4369006a58628d720c084b7ba4c3a295e059724e1f4214ff3850987e75a22485804a13d66672e8f7abcbf97281af8666b81fae064687903dfc018f4017a" },
                { "is", "3a645c28cfac3ac146ae669edbf3bf003c8d14fe235b7a56d878163b06cb4f020e2f26412897008ace673127b4ae6905f5d7f0182deef654eecb04e61406f81c" },
                { "it", "e115affa824c48c2bbaa7d17df81770778e9319022907ade6bbd711452a3560a194d4d7511ee9ffcc9cbbd3f2fab3607df591e7e148950700a63f6c67312fc55" },
                { "ja", "5bb10d3dd9e5fc9c588c9845e8d385eceb13bceac952f74c9310b7bd145e295c78c33224273f6849b8209508f912e1ce85de896610a7ff3ea30c134496739a4a" },
                { "ka", "6e432a19945bd1a1c264ca1c51570b2cc4c1932b5363404d7bacb4e864821fc40cfb55fa04f4a51fbe3ff54a3f02c7da350df6a78982a02bd2c622f2578a692e" },
                { "kab", "afa24336c02e2e56a5ec3941b2ed3d5c7af18d4fb9feee81646a19951e8fbf8e22917c5139efe345c81a0e21f63a742cef9bf1f550d977f194e2306060c08cbc" },
                { "kk", "b3f1b2d482787b634e1b1c1a30e9f8089787b1eed987ae56056d1b23b50967d5367d8bc88f473c6cb9d27b2ac83b8e186fa1906e5110f2aff07d0666978729b0" },
                { "km", "b7f777ed1b85e75ae4cae78183e971f48b5b407a307b09d099720f14bfbea8f55a6d49ae53674fbc0493eed4243f94f8e7f51691be7281fa3508ad67bc344146" },
                { "kn", "6a63310cb9b50bd97aca8c2378ae7c0ece9d350fd7e36fb330f578161da52db9259ebd9a9963e7a65f0e9815ad6ae2f350324f9983ac14879bde6b244dd20dcf" },
                { "ko", "eb7ee876f4380e0efe9106a166a4ceb6a9960bdc9aef2c267267956c9a928b963fa0cb1d8bec59b7cc9b6f70c1bfe5cd41aac5221bd8a89a4e9cda5a8d3a266e" },
                { "lij", "c6740695374f3fc01e48fd3eb22d7cfc33c8f6210333fb23318ab0e1593cca49b5538efa2a8edf95a45759385d5b1bfeb6b005166c217ac0e54a1c19cceb2d9f" },
                { "lt", "da2211eac30828917cff22ff032b0914a4a120fd55942957634ecd6124dc93e88f60e074c7f2e6341142515391f0c6c5814cca9fde3e90978645a8c90a6a9cf1" },
                { "lv", "148a60de7f024fa33d35cd6fa3ed3b5e8b33d372d2e6f6f969dc8f8aa3f3dd2269cb0d21df6662f5f66e8775bf2f5cba17627a5f5a42ef0eb8d87a83d51efcb8" },
                { "mk", "61e3c14b3993bfa8503674b5a844cf89ef1a595435a6acf3b8637f302d00159416b8382dc5d7a0228a2c9fda151aba199398cfb65f196fc3849954e5c99287ef" },
                { "mr", "b7f9e1101805e919238bf9588e50356abae6160c20eac5d3fa3a7fe77dd60db51776d85235aa77a4870d3fdca8576c12a550ebf686ebab4a0479ffbfdac77107" },
                { "ms", "fb5baff27fa8f3f84770c6da1bac7a4efb7954fd9338bdebf74d2434660d85290b4388b68af5c6cc412d45ed4709125ecbf094ad0e8c4ae262390fee022ea52e" },
                { "my", "31e5ddd88527efcef189c589c49d27b7a9ebe38d04744ba3d9840b7a70637a346d3e3e6926de12025b73d88232220cd114a8b3a949acefc9026a6a05e71aa8d0" },
                { "nb-NO", "fdf227455f80709f9a73f32d6a2f7ca0c7cd07ddc8e6bbfa3c0231b321ef641982ec82661cb7c13a63346578e906bd48f555d6bd1810fe1d026b3fdd54ef9418" },
                { "ne-NP", "49e33a3479c205e947118b088fb66436d49049723deffd5ab22614839b7a0157c62e1aa3d9944b6b860edb241922fff5ac9629bdf3d6f1cb7f307e3536573296" },
                { "nl", "5d300198d97de7485616324e802c56558e1cb3e1b6b1728dc27ddcdc9d216553530b3e8a5253fe4a7dadf102f608cc892522cab9afc9a61aa7812e449105509e" },
                { "nn-NO", "4a411a4d5f3a4ebfb0732bc9a3e0392f53ee38a8a426a06f7a867a321b4460f359301654d1ae3df8a2eb503165b010127f067b179bced30c75b0368c3e7308c6" },
                { "oc", "30fef511fde3b1d2346bef8c0acdcda8c24eb62af9dd5d606b8752bd006872bb081898f7bbcd4c423a90380ea747828b7dfac5e56f9f89475e12838048d780eb" },
                { "pa-IN", "0c1cba4d7049842f749d1c38138d8953a6d8321e7fc6b967dc9f0c9810d0673f029e9317b1bfac925619ce1fbb6dae4e0c1d924bd7c351dc8260d90b51eca690" },
                { "pl", "38c3e80380be621bbafdf59a36f0ad40c4a0aaf918fb75170edefdbd0b1bc0ebaf8ad49fc6966b97589925d31c9013e7dd6a454a0dcf19694f51084a57f13f38" },
                { "pt-BR", "3268e30844256cc0271d9b1b9328a09149af73b36818e2b1012e41a761ab2a556d71b2a0acea71e2e696ea1a7b75753a8c8af04d2cd63cdd0af851bb59b660dc" },
                { "pt-PT", "60d41d6a813cc895254b648f6a006525218baf674a6743868075460d574c3f507f5790c8db42bae4058251ebcad103946338997b769477e2f34fc49d5954ff8b" },
                { "rm", "32c18ea5c058000497aee5b2cc1c32d663f2e95b12229babcc4eb9f1289a284a29d5f8800a9100124da7772b451587de154aed19f9836fa4690298b9447fad52" },
                { "ro", "6ed2530e97581515bcdd06f9db90e121da4236a469dbbdf63dc77c7a6d12138d571cded8e381e6c9330044087ff1b70bbf5fc155621b082f178d8c73e3588020" },
                { "ru", "462db9bcf1d757616aad12aa72a0d2a28c7e69bbba1d2d92a8fc37796bc9285432fb63fe1f0ea9b131cd790ed1801eb904ae424b892f0c5deaace56f1dcdc053" },
                { "sat", "92fe2dcba4c3085ea4a8aef1c37f2a02413df32411515814fbd9faaf0b3f782c4c2fe410cb09abaaf383457355a21b2ea692ad4f28242d5d165c2070a93f6db1" },
                { "sc", "f5c3124e563515a6b61d86943659b260c9f32e3158db607414747508c08be26d727268f8ea2685e356c17e8ba08b9a7d3d7eb4c2031f2d5aee613880d6c2914f" },
                { "sco", "7ee3eebde56e8084fec18479d1c2d93e4ebefb3237fda138dab9dae8f8c78958abe1c6a4960ffcd270e0e1117388fb62e43e0d9561df447be8407e5e0b781334" },
                { "si", "5c4d980e3e400ff2d53b6d73de6fbfc2ea6954ffd0d8f89500f5f72c9351b30521d6d4667adccc188e81c968b27e0189ffca3e3da553ee8911993388211e33c6" },
                { "sk", "d05a39d419feff77eef974c650530c7536385774625d015f706efaee5f50fbbfe2bfb839f4132a6fe946624a1c6ac0e3b5c4bfc552bc3e2521285189b0ef79c9" },
                { "skr", "31461eb182534676c4f8d9b7387daf50c658f5d3aadc2b07ad52cb808dffb75a6c525b21fad794c2f0eb3f8b9e32cb6ffadc7fa25f021600b8241e93a5443eee" },
                { "sl", "963fbb0d4aad40cf5ae1057a195e72235936f1c698e6366aebab830c27ed7d03b8d612f58799e7aec0ec07d619bee89a1946e87851c7dcac745211c0a110a7a2" },
                { "son", "d0485eb81789a09ea0ef2948805d8eb62cdc298e9ee7e2ac64daff197d260ac5f5c20fa3df6a29bfb41a2cbf2d8ae63b946e1d8d9257bdb8de34ea6c37bed141" },
                { "sq", "f31a0d2eeb43a05d2470253cf90273370e0126b0b1e56098a442cf9aa5e684bd51750db04bcb16de531d92f98e58f3958ec7cbf82d15ca3683bb6ac44eb1a56d" },
                { "sr", "c62de08757609183f5ebe6368f245faf29e3274facc28d94789fdf85113a78fe1fea7f4787a6f35de949314fcdf9ee8e14fb59948d2df82e92852aee79903fc8" },
                { "sv-SE", "06bfb0156d46bd2eade407a552c43d0baafc6edde23b1b71202aadaee3a81abd3d935fa4db8cb7e23d5fb8e554d45edd15eb36c0eb9abdb68c019b68e07bb721" },
                { "szl", "13b10979e688cd527864908e991bd6f5541c3db645015ff046cb55f13efca3a6083647b384820609989718318e2351ded904c20bc0f11b86ddf26ea69c58e0d8" },
                { "ta", "ae2771c0e66d7302bcb9c030b6f8ed7b61a38b029d2e5da24028b28629a8331ccb4031775ef50038944f0a29226a2685b87ee4aa2af9c81e7f47dd2467eebcf9" },
                { "te", "1f70ee81ce5ba8bd4ca813e6c6b3c8a8ef602c323e5e7a5d7848b6fefc4bd07dcabf3a33e0f95c1c62586f4dfc978a02f1d642135097b64ae167c6c5f30a0f19" },
                { "tg", "9ccb607e8854bece351cab5754a9d01e63d6d1b1e5c8ce9a19ec9dae83918414922c5229b92211edc94c34a0583ef9da5f44fcdd8c73db6b83f27299241915fc" },
                { "th", "20d5d600f29ebc1f179beb68f75494a591100fb2c6f494251cfbe4bcfcb69a20c32ed4dff06634d6ad0eca4c40f9a7731b622f37fa717cdd47a9d7c38f771b80" },
                { "tl", "096874f61b3a58670ec87fb1113e7c8467b64fb903d1b9783b744eb8168f8561ec554a1d07c0630fe9471a162b96e5957649992e00da2f32b6e9ae8161c0588a" },
                { "tr", "a4419619a986ce36be6f18784ba94e32855d4d62895364538bd60dbf609cb18fb15e26a3277da1eaa4e2c7a6add9515ebe2a1f94d1faec25e473b9881f876896" },
                { "trs", "9c0c563bc0f0bff8b7b059a40483acf555625cec64fed53e5658006f4d0fcd27fac16bc47bba1be97664499e73fc542574c4d46d42611a1736ae3d27e9d25152" },
                { "uk", "f4f5a991e20865917955b8dee28d5960a28e3311e3d6797ba5425b8f34c58fb3e0aa1df3f9896b91f20ecb9b5194e4bec10f8555119d96a1a3c361413a1b9a16" },
                { "ur", "b186c10f8372de0385a12fb89cc8380845178dc19af9ee39eff5ac3d8c226d7fdf19ae45e45c7e02062c97bf60cec20283a6bd4ceff1616d4529609a866a4283" },
                { "uz", "a629b347ff79d52abbd5f2d64e88ad4a622d5bb2a5a4790dfaff027cdaf2c232931b4db127060e3f2c877880cc6ebd50a75819459c5ccd6952175877e0fbeb02" },
                { "vi", "2a6bd255dba80cf4f97741c444ff31739fec7a8eaff86c6938c0e3421466836760a74e01e71b2ef76d00e28c66218897a187f6da38fab77eaefaf62d0a271ed8" },
                { "xh", "c95c80a8d48f389a3fc532a35f6a619f9fba71573abb991ed9f4b3931581b2f2afc1b0495a9ecca9d58083d7f7f213a68a18ec6a00125518c70995428273c176" },
                { "zh-CN", "036c4a5b50dcb1ddf2481d1e8a248345cb9ec4b6e5bb7fc30c61c5186539a62f408284d3b468b45f5f9db2f15674855f409bbcb4957e724c5f10d5fa364fd958" },
                { "zh-TW", "bf02bb83acf6294de3c4c3b8acec85fcbf9b794220d8c4ca42202f7044500b67fc76b186526010838cf06a4d89176f5f06f1846f15c17dbf13ac9ebbc58937d7" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
