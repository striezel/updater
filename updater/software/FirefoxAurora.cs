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
        private const string currentVersion = "134.0b5";


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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "840917acb0640501619ffb5e8dd767da27101908c60567e956ef3b02a40a86e938b567a701029e65a9e209fcca0e6dabd01b80079823f031f8cfb08a7a5a349f" },
                { "af", "70bb2ba0da056f8ba555c98040a56f1662310ec8eab200525d397ba76a6677b562ea24d8418d7b8b3e5b6daa0be39a2830771bf3995f768c6eea0f8ed778e9cb" },
                { "an", "cc35f3ceb9c1df608841f7e7239defd120bdee8a3d058cb95def41517fab1fa0e36feb668d7957ed73c6700300cbe1d8f75af358aac2127055a4c0b34df026bc" },
                { "ar", "299048856640a337b7af856e3e6a47ab0d0948332ee0c73ee340cdff737b01cddd214a3a8ea27f270adda0670231b8a8182103d19b76218d9babcba3d2aa700d" },
                { "ast", "cb0fe37da10812e94077051abea5f41bdab65568607ea7e791096fff99f413a288d0b8073baac03714bed005021455d2744de28ed6b9d4f79751925d83f1122f" },
                { "az", "68f68b84832206bd5be4bf619dae62e0b33259de5c9b4bd8c15ef5385c34aa977cd04063c02c58fc84596c881c4e2a7941d01d02fe17216c65d9c55371673afb" },
                { "be", "15da366234868673f6879f40115573559e4f1952c68ac9e42e74b8de283310fbd1e8b1ecd5f04251d38771d3383e37b4d7e2071266c66803367339aa9e8aafbc" },
                { "bg", "1d2f6b88c1664d19a2814477b12b5e2685d0ff621aebdc2f591d88677df93444bc97c19f3a636b683413fdeea618963f6c7137ddc0100dc3e0149c070ff5f352" },
                { "bn", "75de7b73c7c360c3df0d74cddff21fb007e07e9834a70f3a2876934e42152ab68111118c0228db0db6f9be99a2f3300503653e8fc3de6b8f254114ff01d9ec0f" },
                { "br", "ef0076a87952d116cdea4c14e366ec9888b5dc3e4f24ef0691f72fe76f9f3aa38961d93577c57194e99a7716c482e6c5370e74615b04cb5e0be960de4c799f13" },
                { "bs", "6a9e6fb433cfed5d29f6e2856a38c8b39613c7a8c68e3953daf8e46e79d37cd51ddacffd64f5cb271e50dfd35fc5afc9650afc7555282c3de73097b3652ad20c" },
                { "ca", "fdf43682427f164cde38e8d0b7c0419d5b6dc579350a78b222f824c9ce510fe5407b3bf3806e5d7ea1a4c3894cfb5cb96ccbcfb6206e2a9fc0748f20f67731a4" },
                { "cak", "127f72a4de2389f5f67980b18fbfa2e0fdf3b9aa7624dc30a2fc8b939c4c38fd1fa14d501018dcd0b2acc7f7083446ae1490a97a3af9458c7ba63b8a8770e1ca" },
                { "cs", "50b86db9bc89a09923874e227780f588cddad4a80cfd9578b2be2b1b062cc15a1edaa2ac215d4ef06a52b5967710ae1ddb776f2f72f67635c5bb226754aa6278" },
                { "cy", "037b483bab0c53220ba265f310c55914272d1a67d6bf147ae145f3211a13273ca588b033ae4382efe8d7392a50778cc0c5c59a4fd9aa642f9aedc1ac6185fe36" },
                { "da", "2137d1b5e6f42de8a62ae1e1bade34a85d9ab9f695dcadcd4976b90eedc0fdb97d6123f43e592a4fac8819fbce25b103fd58828b23f1a6c218180d4c72209f34" },
                { "de", "e735cf9de06618b289643d6e7ce6fc2e7bc4ff9a519bc303e10c0d9fe581d9b0a1ec08d0aaf2cc723c2b9019031952e50a3cfc99a7a00a57704fcfa309cafedf" },
                { "dsb", "5631813f2923a1793358a402fd46f04553f6440e7f81e7d8ce28451d41ff7d264f2ecfc72d8b11a3d297841c7ff346d999035b4b507d470247e976aef557e0bb" },
                { "el", "bb15f4f7ef88bfd392f086a98121761c3db4b4defcc3352f399b6ddf87936e10043830f51f6f3de5066c1903a92e5c3456d58a9c79944d8b164326041f40a277" },
                { "en-CA", "da788746715aee316b4418cf9b8279817d89e53ce75ea8d3f64e77cdcd708dfabc445174849d268f311c99edb4e455c181f2ccddc4e7f0592251cbb2fcc35052" },
                { "en-GB", "e79a78f327edcc1c8fc1b28a90fd6d38260cd735a3760f97cd81a8304c957aca6a0e9072c0572af45f5691499417472f18c2dc75bb8c6690dc8b3d403ded6401" },
                { "en-US", "64c040dcaa1689f98a4dc5292a3cc2bf22e1ab5657659c4c13be2dadb56925fb0a48544c4751f364837f2e8ad74bd1a3b4beb1ccf5ac5eb3083f2efbeb03ab0b" },
                { "eo", "39ded9818752af3f707ac03272ef1976962259ca71715edf5f3fb80f081171312c8c5ac5775024a374a69bc27986ddfcb41b13f5a70191d5e194cfcf85825e9a" },
                { "es-AR", "1ea392816c8d2025295f0bd6183f195de2a32d1bba6156e296a9138cf51b1d63934d897244d1c26ac6b9affdb67b1b3ced8746289fd3ec12c5dcfd5c226d032b" },
                { "es-CL", "0fa536a7498ed944ec070403005cc57a4cf10ccd9a72fd62d82e4c0e738624d3a9850fb6a3943488381c145f44d6ba941bf88ffde1744a3091925092079cc9f2" },
                { "es-ES", "875f62431ec6caa2d226bd977acba43e4299d32727d7bcc0e3d14ea941819fb42afbabebbb154ebb46f1fa34a17cfb7a862fc67a504332174973db95e49fa49a" },
                { "es-MX", "5165eb26d0b1dbd649dad9f16f1df15a7c04c1df12fc4f50483a837a031c35faea33e4f1e7b9f926177fb93bafd7acba1df4d19c07aa2e386ce3d759bb2aa4c4" },
                { "et", "e613263d99d5a06fc73dcb9aef4186ee04d45c43a23a94ccb0db7294932326067afa3750555c0c44028fefd7fa9341a11f53a913def60f2ac012c6464f518b9f" },
                { "eu", "492bf65ad8b15b034936e1fa774bb5c54e0829592223664de93b37e1121a07d03da7f5c684a65f7a6b4b26f95baa1459219a8f05f6ff7dae0f5661916ef2d50c" },
                { "fa", "42f5262e36d23f6cf487d76319a69ed051f54caeda8be01eea3ad37742c895935fa184f8d57303ee07fd181c45214798573081379e806a7360639b66000dd031" },
                { "ff", "679c4ade0a8f0beed80523271a4be0f5015f45be7bb8c9cb09d2430e1fdaedad57d1a9c2ad5d82ec7aeba384191999bea3b8b16ea2caf1dbb99d23426674543a" },
                { "fi", "789a78be9a638ce7dd6081728f31ebae44810cffae4b78eb61b2c20200722a77af30668edb7d7f4896745eb919072b3f1d6d46c3634483e939295cae464f3aae" },
                { "fr", "41227f7427af478324f5141115c10b1aa329ffb7c395b9741ebe905f1c2b2130bdebde3d57db1799a3870030a9449dda30f1f63deb28a15d0ebc3de5ae6edeca" },
                { "fur", "bf9ad40e7aaeb548c3463e16959e238143ab4c820a3b4465943f2590ab0d0eb53d63c25e689dd56791bc253b743b9ed0f80c46022cbca4ff1393b274d7780786" },
                { "fy-NL", "bdb918d5f41a38692de14c3f1254e81fd6e87ab0c06a616e1244ca70c6b354ca020c0a64a96e6296f211618c21361d5e3c941f321599b67a66722f49079c4667" },
                { "ga-IE", "0cf9a607508d57390006bf91d246184d0cbd0ae6159762f5a94f827c3ab1673e01e223991bbfe52eb49d758bf44709fcb7be3457051475e385ae05b13bed047b" },
                { "gd", "125377e5cd318fa7ea272111f9d5499cf9b5bd050a8b551f3efdbfc4c874f069c158e0c255e7d2bc0a34560f220148bc86c97eb3b631235e182e8024a973402b" },
                { "gl", "f0b5a77a86103500b5c86c25e63d397d2e0f9a31c5a49ac08d493cc54e6bb420259b9ee42da9c483dbec6b49cec89045995938019ba67359bccd55660dfadfce" },
                { "gn", "b2af563b6c139d0cf601edcf9667f9f4b51b576ca7d2333fef77302c82203776eff01f570ed2940b31bb7aa5b6afeccbfd3217ba0ce4148f24793971db62f239" },
                { "gu-IN", "f6bfa4bbcee27e7afb1c458970cafdd248ef96d41945a8770e02df1a31b626d11b4cb617e8bdcf6cedd2fa09cc014fb3943816cefa49cf4d1d7b09e394173937" },
                { "he", "2fc8e2656d4877e6313b9910df22e6c33ba46977b14ab84011133e6b198d27c298f313e8259248a6cd0ef055241968f16ab81f7fa217e1007888488fa9df0796" },
                { "hi-IN", "ae6b0e1aba996b958acf92e8cc22a0eb08a420bd84fc5e3ff1705b9f9dc43ac145a1f52c4d24955a65a1008a7d1a0c077f2dd0ce021d23f83615bbd3e625326b" },
                { "hr", "16865a6d6147e4cce0daa519d7b6d7d1ae751227a74ac7ff47e1a62b6288cf95034fa472679a0f08739120e5f29154a574abd0bf71ab56bc2a34c5487257c3f2" },
                { "hsb", "02b4e095cb35bcb6b97b6ead1ae288457a7066a9977e18deb1db8de586cab1ffa43d3cbf3d8a68cd19b138a4aa788801807fb7a802e5d027460c7042522d64c6" },
                { "hu", "41ae4cc0f8ce0faa0a8df2005af5b4bb9e44e710854188df2e636754f7f3ec822e89ba1ad9b15df65dd5200ce4ab8c38190337e38e06a8792494bd4045146a83" },
                { "hy-AM", "14018ce4c21cce3924340037c006985098aed0b4c2b438ed6e42946471749dd067a7c35d6d96e7439dbb29fefbcdffb2a59e690fa370e8d1e2b4a0491df53596" },
                { "ia", "d186ef0a63bf888ced4239ad94058e1b0d15fca8ba70924dc1aacff45e450ca97242afde9c9d442fbeb86d9947a7c80615f9ebba5142ebc14350f28e1f0e2004" },
                { "id", "9c3893532c0887ce5ef91ead6ff6df4eb05f77cb22f8e5ff5ccf440a5696a0714421f6f88bdd0d7b2b0059fb62999ae9b4e415b7214ff8d20ed7bc67f3f0e6f5" },
                { "is", "802284dd5290366f31bb0ff31be4dee3ee965fe4250fcb4005cc06e29f3047be6bb85584325d8cbb1c6a0557757e7dbc6e4d76e9e3ec70b2dda6f9a3672ff9ed" },
                { "it", "f13c8c7addc71413af51cd01af1a43c6e7903f9c58798b83d2c8d6dbc6579c27d10493d19309dd48db4054860a7a34f5300e5b392392425f9e7fed242d3bf3e3" },
                { "ja", "62cf744bf221807248e4f4af85e03b48fa1bd218ba213b600824d17336f4e5f984551b463e25040482493e1d3ffc8bc500dc3fcd9eb324d7dc94b3ba758ecce3" },
                { "ka", "f3d9852ee56a66054338b3072d348e01fb5a31f4fe6703e0eb8f007f6884ce233e197b8b89e7a5d5f6d56b807f39ca7cc77bf5cc9fdda4840934d5e72b1fbc25" },
                { "kab", "cf9f1f1f510b5ae52aba89cfd54c7fe54bb51df6543c55c26139fcc22ab9d3ec796c480338fcc7d81f9cf4d32f2f06a9635a06782eee604bff616c42133493c9" },
                { "kk", "58399e6c127d372e7c85de97358bde9ad57c2d12ba15d8dba5ada7960014993f1ba717ad97e59786d67f56ba99d788437682712037c7c521d91c74860e95068b" },
                { "km", "ceba65239d5df0ffe4fd78f4488de8514ffddd342d45593ad0c1f94a5711ff79951c37888158cd39354889690cb6af7550f66c4beeb229c56355bd161cbd234d" },
                { "kn", "f543fa4c1a6e0cb3a5973816658e5d391e44883b91407d906e4efc5ec4e49f14793b2bfc8d486c3ec13155509fde90fd2710ae3ffe2b6440c28ed60ece58a6d9" },
                { "ko", "32b6e59d67690f83e32523a91bc097a8ed1d63ce6c9b96687eda71e066d208db4f5b891bbb5f8a630b3a4c82221c8710e286e0836b50dbba89e77f3b94953a8d" },
                { "lij", "36819db47b86768def471ed8a668c001fecfdc0ed1993aafac5868c9863835b79c5c33d5f6f8f5bf056cb168a86525cb8945b5fbb49a249adf0d1b94435ca9a8" },
                { "lt", "a53bd703b8ef7462258592b13d45af1ef785744d59f5b6c9218f224848b1f9e1da4a014cde69fed3b0de122a0d0f8d77d88b48b272c0d332b4302cbad9fa68b1" },
                { "lv", "fb53edac835a003910468d212e7de4d38f6c6b4cc3e96c0bbc940ab0e405e730575886bca7694e8b92b94d18baa8e39fba1d1a1ecb5ce0da1c2f022a3af2d5a9" },
                { "mk", "82d6999c61a47ab234112dedd93e83c137437bd4b16cbb3322be9141a3651ab4ba90b10a49a7e9083b08f94688a05fa8bdec410002b62b94b6456adcc3e2ad9d" },
                { "mr", "15b35e7f2fe756fc2501f8753672ee4416cfb3bad6708992ae5953bb3231bdf3d8d95410ee29e768be4579af903eb7664586543055b6a199651d8f258f3b6c80" },
                { "ms", "d095678b39f36256c2097199a5f2bb4c8debbffb666cf29d79c096b90c3c2a6ba087432572abb25229d7050a40635cf016c4ece92d442525a22d55271ab02681" },
                { "my", "66df84e949923913dd403ac645a46ef0321af12e216aa93ff5e50f5d4405c9fbe8bf94dfbf4a4bf417e0744b93faddd0f8cc9fffdab1d6f5752a8910a795f569" },
                { "nb-NO", "cd013780bddf8e3ce1c39e5848a70b471544dac52c1c0d6eab9fee4a9fa22ef69fd8bbd32c7dafbd20aab1768ae27d7dddd805a2ec61c91fa1d41d3e6453a527" },
                { "ne-NP", "d5011db5c0a1b000614193fae31021a01b3be62ca265a290513b1f8f3241dd6a9eb7a8117176ec796c15600e952527958fdd2b34ca3eea2164ff66d9360d221f" },
                { "nl", "6d76307fd04474eb1998a4f6b76d32e3efd9c477e412cfca10ffcdc06b806c954bd7ce73f235769e25651251c3977e142055b7c5957feb4928ae6e8eeea43b06" },
                { "nn-NO", "8eb94fcc1be3a543c980f314b9d7403ebd0946c100ad8972ecbf12b4ced37521d30a6707cbe1ac9749e3884b8052ccc0530bc8a1449d9433fe6d31572d454187" },
                { "oc", "44d1694c0ce53e59f20c17999cd6af1eaf99b38ac11dade287ad0f08f91f2611a210f428c72591d37b85eccd3f5e0c3ae829d340b629ec0043ca907a1a06d538" },
                { "pa-IN", "074369337601750345f73d9467080d2fae23a55634e46dc18d95b1ff09b142469faca9900f97e4c5e7bf02055c5b80f253307a88e2bdb32768cd4d96786ce70a" },
                { "pl", "38b9247b5f5c8a9240477b15ec747af6ab83594c8e95c6c26dd6c2e2aba1a9f5616ff8dfe1a679de592633b3b40ab3744613fa96223c9b3c22114b0bae141ecd" },
                { "pt-BR", "4f98fc5de926df7a0a046bfb27440eb776eea1b338453b6b133a583673001efca03b6cd65afc2db84dec046fb77f216428aac7dd203eeb1da16a2e7762fde702" },
                { "pt-PT", "78e75a36e7d7c3c7b551c38c9265b7650b8ea8abd4dae373af4022442602ab80a40e2da0645ea1d83ba33e2d63e3a23b47392418c41c550cc849ae17a4778efd" },
                { "rm", "fb559f25202b2b751b6f2ca8726e8f80ce85889a55b7645d68d6034bf902f324f39509e8c5471e3295096df76a382b42b4997d3953a2d01f524e62da29aa6979" },
                { "ro", "a640666aa9a0bc6bc88965429804fda2b2c251660b84bcbae480becde5b106b77c9baed1236e3f86884da0d794fefac7da68e8efc939e98ef05a90404b6dcb3f" },
                { "ru", "c304d67d9b19dd9cf86419181377d3701048727c0cdfa9c2c9d8e12c6f868c0f167e4465ca1c79bedcb23e389075c60cfd4ecd7228b3fbff0ab4df24f10e8c9f" },
                { "sat", "098e5407ab688108512e14b07c420adaacc146748663b4574a8989e832790ab45e2ec457a9ece30965e59d287b16b5e5d9e848e714f40e0ca13c7a993e42fff5" },
                { "sc", "5a99721d13a81c68326d5e7c03b0151994450dc2e5e2133978e834484bb3ef2018b9470e429bc73b36fbdf61a15babbf9050be13ccc2dfdaf41835af0c161404" },
                { "sco", "fdfba6644203c7e2314e23c9757af3322b97709081f51146ca22ed744d9cfa86d88826bd44632b67567fa7aae3286fde9720558ed61cc8451d995b9dddf341b0" },
                { "si", "d93f7f4f787dcc34cc0c2d904d276bd8b3e1d8bbae795b03885052ce5fa03a6858664298982c18f4205ecf8a6ec8a0c8c754801a5634d7657b2df270d7b2fc12" },
                { "sk", "dbb5535991ead6ed3ee826fd87bf117f90b1395b9129866d1d8314569b52575e64e3088c0bfd3913070559049fbbb9cf6b722660475292b541db265eb1655461" },
                { "skr", "1e33c2fef11980339a0e0de7de79f226ef3608f6dbf4474039fe6e17c152af89a2b92e14346be5df7e123c3e37da3f3886e79ef8c4c84174cb2f08f74d8b93eb" },
                { "sl", "7d1ea6a46a757a56577035176431230649697799c0ce6e58e9948b66467bebdf5d48d41bc363258dbb13cf030df070150c94eb13ee388c386797493840e20095" },
                { "son", "db10a7abdb772bad0450fa6f3809c1646b6d8bddc7a0cf609cb5282280b369a9c0907e28dfc91bf4bee623c92cdd10540c57afbd99cc54370926a78d72acadf3" },
                { "sq", "caa3ab9d93dce93da585681d0b1116fae3ae3beb2aeb9f5a3f85c919cc0725c51e36f556c2cb5405a92493204000103b24b7d87d2102a4a6cbcc8d1d99e11111" },
                { "sr", "26693af5faa8bf5e9486b86fd4df1fe3e5b852cdc52b4e6a0db74e6ef4b58367a530a3e68fce9edf36a1bffd667a9182d8353c9691f54d5d9d8132c060b6654b" },
                { "sv-SE", "689c01e584c15bb1364400e2dacb8cc01f2d10e75d810f321abcf00e1407acac929db836224641eadc9821f4bca753b0baaa8a785ed32ca50958412916094961" },
                { "szl", "eccf5131034c4a632f751fb8bfd01aa20df54e56fe6a8a36bcffa6a09f399af7d676f5346cea657cf20d1b1abd4af72953a681818d577c1ca24a3186eac0076b" },
                { "ta", "e051dc35bf80effb7ff5b4bc0e377109b843f2580db0d31c843adfaee0d22c47526c8fa07d7c16d2d770955457a3be4b480f90e97027f8535377ac94a0240362" },
                { "te", "a361c69dac22967ad7234a0ba95947adeeb8f864766495ede7d7a59569bc55ca7e418abe0f2b9a3bba0143b8adf3326d6c7d368a094292ee6c319f674f820c0c" },
                { "tg", "799ba9d32e7ab2195e8945bb53325e198fbf69be3a3bd9f24759b123b038f6f9a8a9725ce26fccfe06b1e8c41d8072c287e06aec468c29d799961ef2eb164d1a" },
                { "th", "eaa9a618f8673a329927f76c0ac8950e075d5fdf2239b9918e0573b9421f78baccd2694445e5d7d0c48ac28074421650a23c865661fe37b9521eebcffb769f92" },
                { "tl", "fa921b9df6e9062918475cd5e2a00b6e77ce401a0c47a413829114d68d6215ee20fc39e38c0d576684019c261efc4b3dc8b4b0bb56cf74d9b29e37d1947a302b" },
                { "tr", "5cd7319d6fd7cb9f0253eb0fc056a163f45b6352c96e265a5b92dbc2425ceb7a64d7cfbc3ca19e3f310a9ff70b6eb6d5bec2ee8bc73502d80bf2d9c6a778f6ff" },
                { "trs", "0afc41b38cf410028bbac435029ddbb70799d0275454b5a4807bf43e56d62d1becfffedac7bafc2227e43a6da2074ffa5aa99b709d86bf17d2afff1a8c26963b" },
                { "uk", "ae53979aae179f8f6e012d250e2aa5df7a4ee832c1a28b865c888952f812562327ccab400cc3255f8a71b9b7318100fd786509603283af1fd94aec1309726210" },
                { "ur", "c4091893d16333dab5638360b7f27134a9272cf0380f2208367a4b0cf2c2742f76eb84281c9cacde10a27c5268aa21c187b656a8284c10b22f291369dd6ebd87" },
                { "uz", "cd0b7a73f6d1f4bdeb5c5a490e3a3a3ee5ac541a4c973adb2ad8949811af2efdc902c991a5229a08a32d6354ca8d13de5358c457a9fb5094902518b9ceee1025" },
                { "vi", "be78f77298bbda5ae778dc856167ab4688e22d9dc0caa97cab34b0d420b25ebd0aa30ca1dc64f0a58a0a8fabec2a2f115b356d1127c266be31464da35dfcf4d3" },
                { "xh", "c2657d905d96ba2a0e4fce3ef37722852f28257abd56703eee039bea8673eae0dbe990520264b699bf7ee2d100f2d839d4173620d89e1780b0b84380157c4e20" },
                { "zh-CN", "efe8d59c455bbb10f3035614afc402c224a735cd57668c1a7aefbd639a1dc0d00baa1d6be0ecb881b74c07a1e4c69153ed49e27746effe4d6dad6a9eb0cd3c94" },
                { "zh-TW", "a14b7b1f74bcca5c18a675ef941bfe88aa1b6eb6235feca1dbbba4111e4f233f93a84263c9b57491bbcfcab883598edc3f9bdc6951865df5cb44dbc4b28eeb86" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "15e6a45bb53172ceb979df63c2d61997041a2a8af60b881c5df271d5b883968dd57c3d7c72adaa214c35ff7962c58f94e238c1a89966077c198d3baad3bd533e" },
                { "af", "940295afad5d706de6966ecba8b39b155e8b7836712ee17e608b505c3de7e12362870e7a14e5686e04f08ba0120693e64923a1f06f2777188cc40461074fe674" },
                { "an", "e39b223b9a5b6a817b08ee6c4a5526c81ce6b264e41e0a780702d436c4598d96d292cce65a75f1ed2ec139a7578aa5ee1311136f187191e249de7c2a5201e68f" },
                { "ar", "a994c752997886d52138b2054c60e4ebdf8dc9e444eb1634db009d160d0db45c3ad6f345b676d7d856e3972b0405c58814f862d03dd9c9148f677765fcafcf8d" },
                { "ast", "cb4197b3dfdb14d6341bf9a478807c7c704ab5904e22b69f1354cb30310627e617106eea4a5f0f4bada49f0466e05eebcbeae109311df3a4ceac0c3db8437c2c" },
                { "az", "dc8ed190bf66d355ad99ae41a323fc5079bc17de566c1a0dcff97a9128df28432a9c9c65e9984883d6c9c59a6be9f0c506bba7efa07e5a82cd69d1e478dfbda7" },
                { "be", "db577ccc7702a67a37983547247e91a073117ca6812d5df862caf3800fe36f660eae6769e6facb27e6403066aacd150044895d3a53d6db43ca5c4693ed5a88b9" },
                { "bg", "de32769863f67cbbd3ae0a400ee69e81505ef9c0822e89f0ae8435d1a810fd7230c434e59f31c706e347669d7abfcdf42e101274e183915c042e8c2386541265" },
                { "bn", "d7202c9b3a0bf33752312f713e0d57ef12ac0d8f6a1cccad3529b54fc56dd14d64cda5998435abd977bf064d1a93f9c7d655bcd219e40c1e1b30fc58e755fb43" },
                { "br", "02c033341bf235dac96036e11eb4effa561a25713320a4f5d3bfbe7b9109255e74ca96d91e948e84aff4373d321aad3687305a9b286938a86cc64ea0f3d02fd4" },
                { "bs", "1f775c5ede9820829bf747d7ade99c51ba901572052332417ee1ecbaf38e073167db36e1da293ca7bec1284965103e48805f7b1d627a2fedc3df58c9a1d2be5c" },
                { "ca", "489a6edda9775ffcfb02661d757119c41dbdbc8edf6371ec5981ea493adb1589ec037f711defaa3e100e1530cb051704ea8a5ae17d1b7ce65bc2cbf31ed018b5" },
                { "cak", "d9ec00895d7a6f9c1fd5d163446e9fa6c9709aa978a9bf97f4f463a6dd7a4123d8a7e2e446a3beddf3e3159f77f1371b3aa03b6e93baf60359f5dc86c5d151bf" },
                { "cs", "b46ce743e129cf0ee0a8cb62a51ad30ff87b56276a326920f685480e8d587d7a86824512cf01587b35d24ab69cf980ce50a11717b813dafeff1b48dfffe58255" },
                { "cy", "ae31dd591f573f1b957fe01cfd9940c1d2984ca662b3fbf7b109f3eb3dbfec1fb44ed9319c51d6a3f75e7892942a2883b7a5dbf8bfff426081391b5faaff9945" },
                { "da", "a78e8b6aa29e08666c176dd1e64fd30085e773e39fdbb7e76dd352293765bce76668574670a286f04f4aa7c213d0d57ec692c4ac5a94b6efbfffe4d2b238a366" },
                { "de", "e0fb15c34d54e97f00e2965673a740ecf56958e2ab22f09d388e45e2b49276e07deeb7651ae675b8e6a37b2164a6033ed46ae7c0a722aeeb0b2bd45fc64f3805" },
                { "dsb", "1bd863a8c40178d5f8709c7187490055a23c4487419b7b7ad28a59b739577566519e5e0cdd6b4def54d641f26fde23a5b1907dc5682468befe1a755dff4291e0" },
                { "el", "d6a86945e46b0ec4b35bb869ff6a67191d1fbea31c0e7aa891a9420300fd7ca15d72ba54f566ac75eb20d3ddd234b2c0b6788721e0a92a24ff3fc7f5cb1005e9" },
                { "en-CA", "153cf954f146ab7abe4e8106ff1001d9a683f54423a4087e52e670af901b8a34dfc04c216df1923ab35260be5a33038fb0e8daa16d11a9d7d801692d6a1b3d1f" },
                { "en-GB", "f717fd6c087b6b183e412bf1070337dfb9c6e1b9498dc424041d88fa73a12b24b742fe1290b6f1e9a79caf33cd601f527e305bdf754043b403fd71a55e01c2e1" },
                { "en-US", "6addf32e7f43be53e6a032d71f503e9c613b850470b8002381afdd393a69131a1eb95b1880fa76990cef62a0941dbae1f53094e774735f035de2098961549798" },
                { "eo", "738d10bda635b3aab94a5104228d2f5eea0fe6cd67bd1957958f460ad46ac0660ac700b3ca6622d2f69d5e26d9a86a08a51b9147bc7e0cda4171b10d1f44e96e" },
                { "es-AR", "9f7291ffd7bfdca9099dddc5e4b6d97341c1f70156a9b9a9079319c6dae19c9fcf91893f62f90909f0b4e0559acacc9c57eea2eb151a39ee60f2957214184134" },
                { "es-CL", "225ddc61509904e7c3871f2a0b9fa01b2e33f35f9a7f2e172977975400af9534d20815c924a2c4c5d08f9177dfeea5d307dc5f89e0f863aa651f0be65426f0b5" },
                { "es-ES", "0d43288c06f80f67a65585694594b967222779de5ed2ba94f61bccb006182cc1f465e04fa62773f0df295c2f2252b452befbe2aa3292ff269caa929b81898d7b" },
                { "es-MX", "c5e5d1fe0fe9ccfd5c2ccae968b677ef7874378fdff0ceae4636388223a0be6b9cf29e078320596afbd0bb4dfb7299508ae20d17d6349ed3c9780fdcc4fd06c3" },
                { "et", "5039acea0e7e627c31b1dc4f4e15814f085c845769ed83865661de84b3a28b0bd41fc550cbc0eb96e3c0623dd2719aa3324631da89988541907e3636b5ceb743" },
                { "eu", "7b4a6fde280eed0fca2b7cfec35ab5b0779682fb7ff66d53a2ce5790f01aaa5f1bb88e0f147854388691b53706fa63e054e7413fffc00f2123bd19e5418c7dbc" },
                { "fa", "523efb720f68695a9b285ac21607dc00809f9b5bacf9ad3d4bd04e29230a534aaf2b5b3c1abbd054681bcfea796d0b91e0e0119b5f194554ab435fa1d8fc053d" },
                { "ff", "f3acb8d43974e4c1cc316367e019484c5894e1e18ced07a62d733d6a5121e50a1391b1021db83d909d0bd711f60389d251223be10ae353f0f4111fc59c91e7b0" },
                { "fi", "acf899c7b9439e973d1624d6608c9c54d7a4a45b6dc419165773aaea96bc11c7305e36a5bb5a8c427e126e747c4caa7666742c3120a28e1dea7a6aba7780f94e" },
                { "fr", "75384f0298fbf3460cac0c19976fe9df79503d0890cf4c18cce4c2257ea951ef1c1c7e750790e96336bc8485436decee779690c2c4546df8a300badc041a986b" },
                { "fur", "56715d93acd88728592f4dbeb42b3b66ffe7f2883a7342700bf522b6261256209b09b2627640d446d82baf6f1d014040af5c236686b407f5cc4f37393f783a99" },
                { "fy-NL", "0a8e80dc8eb8ca66929e4bb222fcb2b81adb50a9840dcd6c189b4e15f11d5f1f12a435cf5d0a35755965c266a0206d48dea9b79acf3c79fef9bdaab6da022ffd" },
                { "ga-IE", "d3bb367d5cb3a35e505deca6a18b9b175c8765572a45b2e1b0d83457fc82dbf37ef70e3dccb603c9e3ba3f85e84e46828a7bfe5e9f01134d721695ae36a388f0" },
                { "gd", "cc9ab2f329e632f58cb3314a238f2d6c8ef7c03b5dc49e995bd91eb2d64c6164b315fee6cc97642d9ff377f3aadc6e490b60cdfdae4078d76162e7b6f65ba92c" },
                { "gl", "6085ac04ab9c7940de75d69a8623b6b436dab0ab88eefbb399986bc65c15c2e87a5f33e3cd8d434ed0e717e5820f4f2b86732b434f5320ea92c34acd174f379b" },
                { "gn", "85f8c9ce18ecf165f101478669410bf3b6bc3e30d3ed7abb9ea1afef469e5490243faa051dee84487fa1403adff5fc9bc17221b818f87539f525e27ed396d358" },
                { "gu-IN", "9367eb801aee46eb6e18b231bec7718a8bf3e67d9d7a45ad628a4941afae87949922825c0c7ca99d2477ea23dad26496dd087e0ca3c611644fc3903789454968" },
                { "he", "6b9d9b34f128002f79bffcdd4d70cf0b74ac3d6e4964ecab87e551f8ba838e6e5e5d70c65461a8aff12333e012038bc1099b5d144f82837bd3ad82344950106c" },
                { "hi-IN", "b1478eb042c4c298fb0fd5cb1f99249ad25cf5b65557b60262532c1b2940951984c133404847df2ebf1999001ead49cb91d38c6e5cdd309046c26f82b2dc6c95" },
                { "hr", "e448f11624a4b38935f0c3c500cb8ede107a9681c9bd9ce97713de40fdaad967fd135fba26ce3989fe4322c8b193d03a69e94a42da5ef31114a3b3e815aae879" },
                { "hsb", "275f8f7c5ec356a18a956f426ee244c1ef3c5b6bf4131f004ade35e9161889c03e985e05a719370a6c6655d26b86f0f747756a83080b724d581c3f5351ceae92" },
                { "hu", "8b196f09a04b1420efad7318213582f6e232998a090a68f56c799c2625fc20e916f2d3ad31935828c81e3ae1aeabca000cdb039a36eeb71d4ae143a03bc1a309" },
                { "hy-AM", "0e500c8fd6e727c9a93aee51b32d66fe5fc3fbafe9a8d432f1f26fde9708206340a7a5b4f71cd4a8f96c082bf5dd24e305d6f76deab7be4200f096f16237f426" },
                { "ia", "3bc3c5641123b2010d05de0cf36461ab43aa2fdd64d1049a6215643677967bf4be22163810b8b964ed9518be1040b6125ca21b6d0420a79fcf4aa53a5942586e" },
                { "id", "7da6051f4f04b44de4ea9caddb8f9af5252e7625806c6baa7f9a23aed7b9cf099e25b97711b80a32638bea337d0caeb3103173a8b03c9bbe996a98049128ceae" },
                { "is", "fed26ef56fcb7b8b73d4eaf28521906da0121d68cb28bccba711fe5208a8ceb47100e12034eaf0dd218ac5cc0df1dc8541c8bc9b63b7125fd56c30af35ff8e25" },
                { "it", "0dc1d8d4111bfda6b241b6490cc3456d71374216a40f5c98aa578ee76aa3fc5cb128e81588d909055f29a3e01a376d2c4bfff2418fe96958fa56ec3e7c2c1212" },
                { "ja", "8e93d05e4c49f6144c133d4a58ee504a7125d02d682b535c79d60dc4512140b33ff40fc5113dc99d43ffa0cc0519a63a35534d3b6827490d5956deca5c66eb67" },
                { "ka", "09317edf33db124d2bc8b9ea447731da5972e2c48ec45452a4d2f1845dd695edf5bb52e6fd3abe2c0492609b6ec027529c6bbf669dd84cdd24186cdbd2806a1f" },
                { "kab", "a46a5e590e2f8c4d68073fae6724cf6388206b7ea47476672529bbfe3745483047a5b55ac45f62426fc3f494df2b75e16e5584a42efa9ddf8f786108627daf48" },
                { "kk", "b5bd57f1e294612c74e43635f16ae3998d5fe3d2fba506d49c2e7110c08bbde43c23f95d15e7042e818d42ce741e3eb1f628eaea34220e385a1696ad3c4f40d9" },
                { "km", "83aace12bbe37b522158a997a838ef718409d1a6061c286df5875d8d53a1e61d0fde0b263b65b0f97e245fa6808311f1f2f58315c8273d163ceb537fd06394bd" },
                { "kn", "af015516ecdd7ef1e017bb5b16ced3002df961081cdb831dd87a4fcde2917266dbf5bda20bb78e0afeb94e9fc4430869de1cf27e696bfa4f98ae7e31bd3aa891" },
                { "ko", "b7a460dfebff5fab380925a2b6ae3dd5589a25f4522642960549046f90d93f4dcd6f246a0b575b3ca0acd35fb9fa9caed6971c72e3817fc535a1433cc12c400b" },
                { "lij", "44c8a355d6063ec4711268287636e1e7abc20c5da8e39fe8f18558da23ec1abffad4243d2dad47be31f4630aa150ea6e32deb4df2aec8565560a7fc603a550de" },
                { "lt", "10e34bc7a37157dbf1d330e719e82389559516bb03bc4853332c493b6d8c13bf14a03e3707898a3d8b1ff43e6b1420ec90901b0404ec48df25e3d86c9e8f6771" },
                { "lv", "6b78f3018387ba6192b080b78fcc817a099988db3e52777f73a16c668e92c0e3cd18551e5ae308f903ceb76cc9dea36e1a378872bccff6b518e0889fcf7d5b8d" },
                { "mk", "12266df5a3b9df4e8c92dab63caca722206a51d9afab7c240cf001a5b50236b23a2df02276066f68cba82dcb9a21c8804acbb652ece60ebf023b75da4a223fd0" },
                { "mr", "a2ce403eac400390e09b00a23a55ee415546283120e791c93b477a1f2820d454e4e6f0089c325a872509ef3f4aff425a70a4fb5791a01d5eae6e14bfc155019f" },
                { "ms", "f6d06e1896ae1b04db78968c27494adca14e0dc9d71d94d7495ac88615f6dfed5901d775131b756253e22a21e4c307ee1d40241b8f48b000b759f870ba19f3c6" },
                { "my", "17c152d361d15b815f934accb66d959b2a8a6df370ba6d5069fc1217da2b48f8e6de5f1696e2737383ebb0819cf82df61ff79cf01e1f1436cb593ac660275283" },
                { "nb-NO", "2e47b46914275263d38520196d4b5b2697acbf9b2239625b2dc9fc3c04936c99777695c4f7010adf0427a9a222709cf38b28f4f00d02b5fe8b153b4d3fc0371c" },
                { "ne-NP", "dab929388f6918788df4295ef344f6fb2b121cfa498219806567a587b581a6de589d49097baad38de54cb09447647e2a4e7fd13d55576cea1b3eeb3734ace223" },
                { "nl", "3bdd3f9755c0e3c9c99c2ee01fedb88e29b8abaf6e9eb67b227b28521b82361785d274ce310f6391f20cd3b6b296a78bf415bc4b520d2c526c783b73473a982e" },
                { "nn-NO", "c4966d865e1b7074c3d9a1f3e9528d359fd770dc6610c66bfb5857a09d38f94071f2656f1913ae629895caa87ac350fa529e30545d246436f318e390f2eb52e9" },
                { "oc", "559f0d3dc552f591d8b58d328c02e223d2db804b7e29ac908c8b0c069e8ea87df9ae852718b2c30453b6261ba9d88ca685bb03cacd60d8fe57af101a95126c4f" },
                { "pa-IN", "bbc5873e6b0a7f67c89d8fb79d17d4318649aa653e306c10ebd9ffdfc01632bd0c0e6c354427c338ad094832c194e284c157a1eef1c0aecc05f018f7bb1e6551" },
                { "pl", "00dfbd0c1cc654eccbf789469a1ca4bebdf9d15e4e5efe8a20edcfef4ecfc5ac7d055569e6cf9b929945c4a4384c8e5b70b184440c895532e815cba1f1aedc24" },
                { "pt-BR", "0eb3f709b2093b69150eb46d813e29cdb54cc5517aac88c436b39499c1a114fdafe2f544dcd6000891d4546f33ebc8de5778569ada0c806165574acfadabc612" },
                { "pt-PT", "ed8e7704fbf232e5e3df04226fe9d31f8580e505e858407f8611d5cf6a9347570a6adfc07357dd0b9e10c686daec245623736aed8c49b5e5b09238e6818a68cd" },
                { "rm", "2cd3d250e8167ad4195ece4fb4fbeb394dfb88a8aeb476cdc880548697ad69eed85ca1d3653f226e138ec533adbe3f8dbc8bcdfa549a58742d474c1b6a8bfab6" },
                { "ro", "e2169b1ab993c01bcc4ea7aa3509ede63027e856312a756dba105d38e23e1511be737580af64a502552e44342effde0343a54a2b7ac1590e2ace6422cc2d7c9e" },
                { "ru", "29b0c0a062d9e2fef3f4e8281764f3293a2db45396b8578fc7f73d97b7b264018d71a182798fbe8c2eca28651e1889b32520ce900b5f24dec1914587a3710efa" },
                { "sat", "90a89c69f4f00f47b4b5ff83eba32d3eb9343e4c9b201e6dbc69060216e8d20c5a8c63dfc9d2e14c733f0d20ae20a4b42f7f50b4c2311ae01b02dc27a93ef6df" },
                { "sc", "2b303d67a32191cad525e4c98e226f0443abdcfeb55e228c82c1e1f1be1d02dd814f1bbd965d7fa034ad098171052c4f30188bd4c9605ced7726427837d42c5c" },
                { "sco", "3797c9e468eed719145b142c5a124539f4eec57c101d221020cb3787134d51cc0e3e21ba361351bd666d8572760213acb46ea9e5d70c9faa5d0f56b1a27355d9" },
                { "si", "113db0b2db43dc0c74495f48e1296fefe6fe6b26b145e191f6e27eeabd2f90efbc3bd1620c8002213351f76d0ecf3308953a1022ae96e44d01bc40c0d387e063" },
                { "sk", "e6074a79e7a1af13453c2b0d129cd3bc8317e81646f1f5a31a703fe1a35e9ba399a36b1d88534f2361954d9917b83bc4bbb3056e27aca20abc8dd66285ff4af1" },
                { "skr", "4c53e56f8ab2f7a4aaa7af0a81aafae4d908618292f4fdaa53cb9f3809abb633e7ac24e543fd36602d8fd6f3f90c24c429c24614530fb3f2a50ae5c317b87599" },
                { "sl", "e63eb2817422ff412c0d7505b5613b5c306acf1eae053c6949a322472de04e16bd086cb6610fe0ad61d46a6c7b740c10550dfebcf05d1593097fce0795df3953" },
                { "son", "1a36657b48066f99273794b434a0b444959277c5c850b6cf494c7dce55f16dd774a6debf79228fe95b0adf44b4c288aaf0c24ac9f9b51061bea2b63e7d45637b" },
                { "sq", "507d7af4cc959f1377bb0c2a5a7107c933547e432b8c85fdf8ac6dee5893bf011c50e0751975975fa527d7b1e7be6438a6a57f4122d58fd3db832af78c454a47" },
                { "sr", "28b639f854c4eb2d27fd6ef06fcaf09594dd735cad37128304aeee89b52029b5a756449d07d7d6c4c438fff3386d349dfb42ee257f0e04ecb8628fdd62d378ae" },
                { "sv-SE", "b4a32939446268dd42f78ad4c703daaf163b28c0999e138db64572e75f149dbe4b7e99039f0405cf156bd9a6d2a9aa074698ce2c55705ba65f79389348e7e09f" },
                { "szl", "0b60ce16faffb53a7c39516467e7ae9208aa1899b3b2dda738de1841fa598ca753d65790b1234492b7eefbd1e6bb96ac8b802ef58d7aed3f434282de5a1ad711" },
                { "ta", "2168edb229012efa0085b8e5e20ff15133cc700886ac76e65c70736de79a960dc1b8254afe1e3280f9fbfb3547ed00c3a225fb3a5399b9b4c0544ba556bd96b9" },
                { "te", "eaee52be19ac95e40d9e175dade46b57a77eb0cd8ddc721ab83c2dc63b8f525dc21731c81de772b1fa5b4e1a1306137d00c4e2056932708fb60ad16c2d3bfd30" },
                { "tg", "b5e0ac17bef224e84d9d8c7a92ca869830cfd3178acfd3d6ae2c3c55438087205af751ce4fa0e678200b7353d31edd5375a95eff5d97b7f52ff64095d6ad1702" },
                { "th", "35337df2e7d29d69b49cec49ee2ee21c8d1176d6ee35349299ee84368111742f0fd2484a5be31af1a15ded117e7a3a6f4e399a875ccc4ccffc4c36f663ea80ac" },
                { "tl", "0de404a90a7d8e33181d468d5d51199eb9766301935e88d0efd5456bb55465d0322a867d854b2d83e607469ab1a6f9051bca3e26e89c7d07d3d1c5d8bcb75321" },
                { "tr", "022c68c166eeddf35d3a5e1e4827a9e3bcbd82651726566655ccf883e5941bc1b43ece41484f9ff4b8944d31e6b269d26c4eb2fc77a4d888a1918e0af152a086" },
                { "trs", "be537a2dc3f800ad86ecaf039ed493319636ba28e0554dc2e37e9f80d008317a3099477843e94ca32063be90a45179f8d3ae06b62419cd6a86415956ee0eb188" },
                { "uk", "2461fe7061dbcac1889e294fbf74330754ea4dfb59e7ff4ce70af53569eeef2f115549cd68b156b547a5e4e6c552a035c6c58aa8c1999810199c2c885f0b7606" },
                { "ur", "0e50b1d845675f8b59c399e262a985e28c7fe635de96d31566711aec3fd6a152cd47be332de48c4e8038a826c5dee8777a3c4916e84762e46ed7364935486294" },
                { "uz", "68dd9fe00975a50cebca7a743f94ff6ed818941f5e1645f1dca64e241ec8d9bcacf5547a8d85e5644bde385953b0cd622dcc1547a7cb12b6e01aa163ad2cbc5b" },
                { "vi", "60cf82ffde151805fa1262abac180c54c0562ccb59b1111cbb21a429ee206e231379184acec44ca4de30b2a3e9c023b302dd2d7e2a26039da67cdcfdf4e568ad" },
                { "xh", "a8e74cb8cd02fdec06a76a368b0e4d415ebc3e840b27960de7e94f8e30ea5b47a0f4a8093b42a90dfcddb3b95b8a545f108a56a294480dfa671933288df4d2b7" },
                { "zh-CN", "384a5e1d00ecec4a9607e8af470a1d7669cc9542cbcd3dd6beb618be68f82d1b06bf8e644b78b71c4b28bcbcb93d63997d9e86daa6636f4514e70e3f880c4b6b" },
                { "zh-TW", "d2274dea80341e1d856a835a24471fd5efa809947a4acab68a805cbc0db5bdda42ad4e0a824f9b1d5b07f9d9fee69d8abc4ae96f4f3c77c8cc2173006aa49b6e" }
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
