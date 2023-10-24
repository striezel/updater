/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/115.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "b2d418bf8ff04e722eeff0d3bf1cd1be694879370e22a2c93ef79fee2b19298d37888c3cbc78a5d6e55c9e3b4003bd3e9ff724dd04c8393a63d8baacac18c438" },
                { "af", "3a7f7a8c35d3fe98f55f1bd689080730c6255a3291af872cfb95a72aea02de53820295e0a6c1903040de3d3379b793dbb8ed5a52c5f2a939d43c3ffba26f759f" },
                { "an", "97d492924a48b8ec2ae522bc1caf43e88ed764095a10ac24b2b1829561aadb5f37e04f6fa004be5017ad1a7bf7023281fed752ba4c4b2a10b57959f7924f4933" },
                { "ar", "9c1093e70494b349c112576818b23bdea5f9e5792e81756c11a3dc29909f436a8b737977e901c6db7b5d09e3565fd2b3ca89f019f65179359f0391acd382421a" },
                { "ast", "0ac83dfdc5944cf82be5632f35defb9214639681e39951040a8264dbc04bb062c255ef053e1e90b208ea04733dac3f564a865738af6b5073981fbdd75746d09d" },
                { "az", "cf15784b9a797d796b5e5c24e215ea850464789084fa1818c4f2fc0c57fc1588016cef687a107ea52b43f62b97086e0cb3878b714ca56c9c265e842c5a89ed20" },
                { "be", "a59de4ca3b382683ddc8ecd568a9595b9db3868d9518cb1ce3834d4997fee8674c002fa2d5405627404cd8fb86ef00dc9eeafc15d31fa8101564b2db30697c1d" },
                { "bg", "f3bcbf59fef11da8e6ba1f2457f7c0f5add3b2f80d4b8c5073e02cc2ef03856d727dc644f8a538860e6a4d4077d21768e31c1fee91ad531586f2edb4cf6dfd74" },
                { "bn", "74a3445e7d16452da129572ba84d562fad51e80a701417bb98e529d9a9557d62972df320f3ad4d84992cf899b04edf94f69eb47d465126b1e5990886cf5c805f" },
                { "br", "035c78114329b3c059bf42d7ca5e6cc8fc389e22d06c4902129f7d10e3c73e39fd6e5ddd2dcba27cc944078922c7d64cef52e1196df0bf0e6ab87acb13c42e56" },
                { "bs", "d78ca40c9d941eff88c2d0aa7fdfc57ecfb2edd6fd8c9c12b57305cbf22f8fb1ce15869d12d9c4cfb6473553b1b3114733f67ec44dd052d8cdb553f7fdf4860e" },
                { "ca", "496eda756d11552453470ab0b57897ff15d9fe89a8241af09d23fbb62608bb8a4e545e2121a7771359abdfbaddd058b27ece96b2e524a1379dcbf02f54d59a03" },
                { "cak", "cdd419b24be9816770dab488cf0074d3a1f2e92fd419f53d61778f10f49b7cea22f825bfa23eb347e18e0a6886417865ce99c5627f36c4a31f02a072f15c1f45" },
                { "cs", "5dba5c8b7f0496c8ec5e84b20581b64506a8bd5e4ac1eb68b43588e51a8961fad8b00940881ab733dabf23e83949f63d5754a44b2f6a803281f3ee152e353716" },
                { "cy", "a73da02ce429c3c32b00de9b0b013b8415cdc3e8e49484480b863f6ca8db3cd768cceb13dd1c794da11d80b5216641d84459fd7067e2fdc4d7258983bd0d34e7" },
                { "da", "3b77b7232372d7b04f8dc40877fe06dd9e8e1c4e35f5b5a002fd46381c7ce9c69eff4f69a3754bb4c4d6e8059c308a781c3d020ba36731925390f8bb5945155d" },
                { "de", "cc376d67f3d24ba4452b8877cac65d99e3c9087ef722cb821c1c30e9255a78d2a3af35d12e3cfc3e7d68695146235b046e55a828bcc47963b385eb853c6a3bed" },
                { "dsb", "e104f83a09ce4a9f8a874ee6c1bbb20111f9ce9f0cb31d0539260fca81b120b638ca96847cad307c23781b96a899a719f6de6bb64d154c446760848bf608e846" },
                { "el", "f584c74353bd1ae6b3e67fbc6dec07a04627feefd8a77dd99cd87a2cc9a601a1d7d7dce83fab7079bbe1103f6c69c3cf1047f6b96c83c2369ab508b470650ba0" },
                { "en-CA", "81742b1fbb9f189519cc32cdcdd1cd0ed869bd50bedf2d8c8c22d5e534e195befe36e1e1f4a8120a2e07c62d3cab404296c58f6efa0dd34c5e02cb665422005c" },
                { "en-GB", "4be1f8679ae1329d830fac496b2893fba3dfa2cfc2131345a381d71b4a1858068ded6a5a17f468c2e12b24c0e223c04ee339b969baa03c9e958e737728a48e2b" },
                { "en-US", "d598830e1c52143fdc3617207372f4c19c4373d8438fb24f8b7e7d1f4a68934b8a56602cfceab9b4cfb75f2895cebf3115a1b922d5e39166c1a499153c6bccd2" },
                { "eo", "3fe486bc7cf0fb07a94f09730274deb0cf8f5fe7a2e4e03a476a6e0075d8805f58f5022c33b85a659560c44d5a67ea2921d3f0759db878afc10776915c369170" },
                { "es-AR", "cc08d9df9fc53bd8cdc12a8039753abc12d29a64dd417532f3f24f69612a5e5afb5db84de221e2330cd22701ce3a8d8cac92c5fabbafea95aa776a0a32fc90ca" },
                { "es-CL", "841861a75f537d73d4e0b02816abf8af21fa0dbf3f9d8515c1b872d3a1377b61aaaf3b4054e2a43226057d9f668180b371a3250a4a9c02993f580e8272870542" },
                { "es-ES", "9b430a161c1915c329416589d133e047605bdb12c34ba655d53690d523234fb18a45c4fb1fd7bafdaea20a4d45f0297395b5e4504dc1edf41d63a8b28e8a425a" },
                { "es-MX", "13525fb0193ab030bd536a1ba645fac201544244930d02185216472983c2e87cfb52663215f96619ed0049bd4aea2bbb5f4341890fc334147f08e8e473217d14" },
                { "et", "679f6ceaca1361df0e82446be647450d28bbb34462f16870ae7bda9adac9cc937a8f58fb4881ed6f754903db34b0d9d878912e97ad3d3cbc809c08c6546c0f74" },
                { "eu", "3fdcc98fd89c523385d035a26bd16bf5bfa310e296bc5c189bf979ece691a8813949b5739694f7a06ab509d4a2bf84e702baa885555ffe3ba11aa44359a255a5" },
                { "fa", "a13b219583fd1698e22103b8c4912f14db4a3c446eec1d7e3b028a926b0978a6cec35eeea5ddd1665a27921543e4663f088a9c40fa12c581933f6090f9beb875" },
                { "ff", "fd3ad63b1c41c9dae9788be9ee414fcaaf47bd74482dd68da90e029d0b7818e723137ca46668d7f8053bc8b084f1d79a81ff6cae93e0577d37ea2886f92db695" },
                { "fi", "2c9f220ff3f647ee6a7e76d61441d5c64cd76bbf8c0cca5943127cd45fcc6f318c0a42522c9bf8f2d55d87e119f473d3902bafe8c7669191fcdc3d18881bf01b" },
                { "fr", "82c583dfb250322f53557695e3628a7eec775cb0bed065e6b47102f09b4de65f4106a0429c879bf62bf0d65d82ebe8c1604fd53f3ec7fc1d61c90cad85138f73" },
                { "fur", "53406e25ff42c7922ca4fe8889299196149fb3e167d9b109a9ddd253e2160889aeeb773818e8fa51ee9a58772cdb1b2fff9ff8cd4c115dd17e3e94b513f20a75" },
                { "fy-NL", "cbc5ff1e3a45a7177ba428d842e49857537b1946f0b2a061bf719ca96ebe7103390ba0bc165796104c1eae328faaabaec588f4ba7fece2c87bbdeda990b7089d" },
                { "ga-IE", "ac0662910700e3b636cc4096e1b66a6f2eae4f7cad7acafd37f189b4d8a60eac9361d27c2ce91d5c472cc7cef48e5f6aae2e236340a8784de2b16429ba351292" },
                { "gd", "d7bf498a05c28ffee704058f57994c929e42645ec0159a6f46a21131421c57aa31005e6b66c52f007b73049cf39109879d6771cba525e1425238769b760c6d19" },
                { "gl", "4386465e991c215ab06c163ff03cead03a5315cd6561242f9f1308f355c8f681610dcc5ac4edb4ae40e0a7fb3a2dabbe3f84df63da1a82935b40f690730f54d0" },
                { "gn", "8454577a1e2a9f95356d49c9650686296958aa2db0090581c475dc710313b3d10d3705f7db1ae19e3e3b2dea36bda95a20875093d13bf06fe59ce99b9669cc56" },
                { "gu-IN", "127ce02438e467f5dbd15a671eed3951996188a9607eb44b3a37d2035962c970d9f0523b6ce9f326688bc190377457988312e41da87ed60f57b1b4527c5fb05e" },
                { "he", "2f6074618c9bd34b3738ac0ab97d23dae7ce19b242d815bedb31a85011ca47b1c6c09a92bc50723fc1c24e2d79612a792bfd4cb88dbb87d07dcabb350a6c608d" },
                { "hi-IN", "6915fd9f35cca10deac152cbd325f82204afa50bda1699de5854c35ac133290f42bfc25e0700fef86124660dead2e00ab7eddea197ecd03b4c4b1b489b4051d2" },
                { "hr", "1e395c09561bf762073c402d4ed43df692e5bdddaf51caf444f39be545ab0ec0ba223358be45eede1add6385dc44a3113db84fd85a561c9996b10f122331f30e" },
                { "hsb", "d9c303719feb7feef451609fe27332d1a5af08efb300a84fc99ce473ec3f7c3157c95425b69760a1096d265162d8e22a7d6e91ae7a889be5de6104623f8207fa" },
                { "hu", "7bf9358babdde2c2bd34e352194de99ad99106d9deb8cfaebfdc5c4488adf2d8858a1c3075aef9245879c5f6a4672a594800509d8bc5daaee0260c4d849346bf" },
                { "hy-AM", "8c846b06ffb194447258e1cd21add8d47a80dcf62acf6273b1ff6f29c57310f2acbe73b6ebdeae2fd324ab67f1d43c79418409ffbc5ec7431005092fe1bffd6c" },
                { "ia", "7c4ec57132379b1394a754962c52d548ccc035b10e87ba90ac61082e2159a15e207cd2064c7ca03450f33e1b162ab869ede275287f56fead36a7f13c33bb50e6" },
                { "id", "b83dacd46cce1ac0f11fb2e1f9c9e4d22864a0819f3549709121ed7fb3ccce3f102512a18f46d0de2feeed54c9defdb900ffe30b9922f0b2f80204dab6226dcb" },
                { "is", "df37abed00f4ada10dd580afc0d93393675df6935c2def17f69fe7033533a51d34204735d1e6d48eee4654a30b97f2ff4e7cbdd66e703d2013d24a26371c4b5d" },
                { "it", "97697e224eb7bc349714ac94cd0e76f82af544e2e9fddc6b2602eb29f8038b4b4428dc548d4af8899694f36c98fecae8a63097bc65417a1b86d17cb15fd50b20" },
                { "ja", "76f08b2690b5d76769afa8a8790a5044dde28d4dd3499b0ec547405ff4f2953814f5433c9d18f22be3d3b07ec7635722d87242551d5e919f6ec666d23085cf64" },
                { "ka", "169b53957316a3d7f0319e539e459e2a67334535fb15a448d01d5b3d654f1490ebee46036d86d58d7fb3e6014a998c96d0abd766b92c16cfa3a1c9c136471970" },
                { "kab", "e3fec906f6fa79a069cdbea172a99cd39c01e192d8884f6b280c8cffede03476184c98d632b9337481cf89c7967e9b5887579ed93f29524a88544f5239112270" },
                { "kk", "5a48b16677e175ab671f822b551b4485b67e863fa78e28ce7f95b029e869443ea72351ba1bb6baea5b2a8bc5ff233b924c386dde3d8d358e480173a66dabe147" },
                { "km", "5a1a56ccfc6372890643d7c14a7b67f5c76324ddb58c43c48a726a6a0a77f990445d908cfd7f64d7aa6d7dd24b98752c6639f73a15f472e062ac14a2beb04e4b" },
                { "kn", "20c8b03b0c94b9344af410b76795d72f3e2782fc3cc05b247c6eeeabb86c344f74d505aa5d2944e801cba7f02e41041695378f6b6cb6ecc12c8fe3f4bce3d55f" },
                { "ko", "a8f13caa70e8bc69020e675171ed926b787f8a072e5803c84e3d70f4a600a4ccb2fa359bb11945e762a57a2c34c2c132a0054c8a10c077300b6a73ae2fbb2c59" },
                { "lij", "28e8f8c24fe4cddc8ca4aaebf0a5f5fd836b23757056e735b88e903cd563b1e696060daac87a64a43be84c62b10319f308e406d61206dd6c348eb5a32e473c91" },
                { "lt", "171866bea9cf41d2d0433de546a40c1dd7d206f917bf3294e4fdedc417e45ce3fa250b0be843ab634631a07d7671b1229e38098e380bce39256976fb14c88dd6" },
                { "lv", "12b2ee96dafc3ba12cf1e9b2cdcc24b8198485b7b8f5b4f1c7d7e403de09ca1556e668b6a8045e3a042c567e1b83525ed55c0ca8f664a4b52e698f552228ea17" },
                { "mk", "9ae2d7468431d1c65fb35ce7e1b731d07dc53d18f769c92a55ea34a148623998cbffee14d74187d4e2de57f4f3d263c86480886ce0ff7921c717f1da3a2f3bf5" },
                { "mr", "7e51fd25fbb7f6285796c413395cb2ffe8af1b5102925fcb5db746ff2acc319a39083092d33f468a84097c0683d5deedec73ff66b4a0750b8c8f35d388eab860" },
                { "ms", "26c7ecff3f5df382935e63d4f61ffba4d84b7fd9bd5a1d82ea96b5003c1ec96a0834747294229845b8b15f8c48d0bc8cedc3f75fd7661bfa8c1b8fbfa02d0757" },
                { "my", "51e00628e020a929e40c9a26dba99f3ad337bb73cb42cd09f62aba677c2cf7ab97cac40c75ca1e61a99d8b8c764d743ba1a5bcec157be2d2a1af19e7d63969e0" },
                { "nb-NO", "e356a028be574ab58dc94fcf994387c9809af12008ceb9e91749458c9d443de65ef7882436656691171ca0a4fd3e9fb8e4fd37908b3136ef7ddf5c7c773d1034" },
                { "ne-NP", "c950b6ef0f11e78ebe72b1a9abde2ec4311aae815fd888de6b455a58e01f4acc89d77dfc22e8dca95dcfbda8f6f631dffb342fcf34916450d9849190ca17a615" },
                { "nl", "d8d7dd4ccede1f226af5f44db3de1b24b627af3854db3089b306cdaa2341d623f09bca4ce1c1873e9a4f8f00b549f686eff10d4f2d6281d598c94a7cd9df83f9" },
                { "nn-NO", "df104ca246121ebb834be04f700393d75ddc311bdec8f3594ded951d7126df7c471c64ae82c8e6a628036a77df4a4db026de0aac1f425feedadef0ba62dd14dc" },
                { "oc", "6403e6f69c304f38f7b48d31eb7988731070b99062271e689f532b3d194dcb81ea691588b76cbb46500d1e8e12762f5045dc957e1e2dda4d2cc873054edb2da2" },
                { "pa-IN", "32ede585113ec0582a56da395f5c2e11ce9e9f249efa11da4b0d24c9cdc69ad6f4b7411d8532d06edefd9e331acef543a96ed54057afc5066578a3972803b665" },
                { "pl", "6b255257bb1f1bd9b3ddfa5b09cac5a44b189247002e09ba7ebb492637bd3058de64f08b1e52b70fa22076390f598eb6e04e841091a433af6cff5d2daa235e31" },
                { "pt-BR", "55aa135bb8967b62a1fc4b9c221bb493c3d581612360bbd8cfff01517648d445cb72954d900532af59358fb7059fdb2dac5c82871c201be0d199335d2a273474" },
                { "pt-PT", "ccf9daff55bd13c4655f988bfc55746918569bf14f0d8a3a5d56b68c7fa6442b4d908776bc9f23c548e7bdfa060cddd6640c06fc8d95c3fa8d247135d62e9322" },
                { "rm", "8708a132f33f99ea5d1a6c88c30b181cf4d338b993e8413ef8fef47776ef8d8775744df1403bd7a2129c0e09547f882c8414c253c2780ef93eccc2164dad6bf9" },
                { "ro", "710490abed90d41200dd51d1410cfdc07ecf455fe1d43088d0742c15f14203f369c7c93cc4e07c6623fd21e76e188a1508c10d9aaa254609194be8adab34530d" },
                { "ru", "daad8dbdb251c01bc8a89c17a87a87f5a8e8e63542dc3483be2c5037e9d83535c2eeb15980a285248ea1dccf46508cd64d8925b2e97e70cea928c97eac9a8ee8" },
                { "sc", "a36a571904c95220a5fcdd7a2d376bf3404776a5281963d7f52bb8e9daf835e9411e58938e698d1bed9eac1c3dab45e61ca671de30d0022887deef1e8f258141" },
                { "sco", "e5d8e98070a6d1842fcadae9bb6288d921c576243697fe33e8963faa7252f183d873a1bc708c1d039d16e302153b1338dca5a78f047aac617250b5d87b5e242e" },
                { "si", "5ec272a77664137bf2054f967a5d6c4f3e1bc5a5a7f74fbedb7a38e282ccdb292965b1672752f11047c08cbc36197eea5c6382f922e17f742f38a13993eb336d" },
                { "sk", "fe1669c462f7d780b41d8a4c13ecc6afb6c6b8dafcdcccf2e8e0c2f73930bc46d6a24b40fe2facb77c2153486253ca2a8de424ca083412d9e57129b9a84ad061" },
                { "sl", "6b4b0b2fab42a44c77568c01b8d78c1e31aaac95aa14a1bc37d5b3eeae015e01ee5c8aa8f7ebb5930746ba0669db3e0e1da1bda73a6645878f247637441a50e1" },
                { "son", "ccc7060a95e9f5c721315119a010618f2b4288c409c9c5c8e869013a4fa110da54f56334cc578741b2e68978520a608333e4c5779aa87b73ee417d1b9865684b" },
                { "sq", "cbe6865d02ec46e7bdb76f8e8ca4f294d579d3d58d49d7e8459470b1735f984d2bc28a558ba3ba07720dd0b551a4ee3ba1ad1ab64947e2b1864bf15a96efaa77" },
                { "sr", "0a0e6ab91cbb56723390c1ee25b24527d1d75eb64e78ad1d1b78267d40025aac913a894cb759ab6e7f7f83c8608564237a923e36c6731ef837b4187ed0ac81b9" },
                { "sv-SE", "8fabaccad5de5c426c9d3eab6c8d5106e3382bb5162d80c1704ea20413eb8ca489c49d23ec1bc696036789315f4a9dd4ad99cb1a93bfb1194bdabc0ca161c01a" },
                { "szl", "0715b2600852e1373c89e5582c153dfe4877fffb3a63308562aa8ec7a181874bc8ffdf5b3e59ff5d94f0f794ba2b62c6f9f874a577d35d136aee12847df5545f" },
                { "ta", "b9e3ee29d0cda5d4424e6b1a15aaeed4d5589383e773a613585597fa2e6fa1fc800ba0e4e0a0f4992fee0ad06c032d1bc5cec02da1e2ba4f42c6afa4a75135cc" },
                { "te", "a55c35519137260087fbaf517bec22eeccc8a88a1f0909d01f0dd3248eebbceeaaf31b10a5f087720f2f66e44cd868f099d6299efe0d378119b32a6843e1219e" },
                { "tg", "502e7ec7f1422d6c5fad792a1b0547ebdf7ba02d0ed88a536e1aa9184450b47d4bbe6a633820e47a5237b560634e2b9c0b674ef621376cdc8a8adefd7d04dc41" },
                { "th", "638c1971685197e8c6cf679cba2289e34358b5fd71985ad8604e796e111184f80affd8fe33a3d546222b8d09e6c8824e358946ec21442a60455b34a56870feaa" },
                { "tl", "8897e2f544f2549aa5e290ade17372ac471ddd82a6ca2132c83ea31de97b049e16d4f2b9f794bce5902068e93e29f40b9426ba03a190286548a3a7d354f4bef8" },
                { "tr", "8a6946c861058246abf7183e904a623629f5b9082bc987c86fa6267a015557e85c049171639e2f76de111e8e4b0de088c131bb1bc01d56e7c3c5be5cacbf0292" },
                { "trs", "25473c84560eac4528f1850e35ae08a1d7a20d8a248f65d7042f870f25faa4d48a2f25c07569797dea1b3152f28bf9cf5ba6838aa9089562bc085db1596441b3" },
                { "uk", "c3f5d7508552d8f89bec3504becfcd338bb9145a64e63f4af43624222b78c8309f1ffce918dbebfe7202127a07281db167d1c3439b2443d546748c50bf200761" },
                { "ur", "2a3f43d7d76592fe99a360e67dd45284f3131162f3e0c32b903b22047f1680b501dbb3656f7aa56e963faa6acae63962f580605726fe81ca675e052da116c01f" },
                { "uz", "fd896b0c7841285bd5d806aab740c6a76f17142cd9f0d348444ec349f0bef2b4ab0cc1cef64e965120d240c0496d1d27784f00613227a9faf8801fe8dda45e38" },
                { "vi", "1f1bbc85b6911c796376a6f2a9fc4469b7d49aab90a98bdb4ba8f43e1585fb70b6d5988143e27981fbe1c3c4a8921879fae1cce904fbff306807619b8517951d" },
                { "xh", "0d38584d7f5ece69e2dc3e558c7f0096b322ce4845e11711736d38db5a7c139a420d4b9137f72b005c32c2b7c5a1db6bf5e661f3c68baef361946db0d002d7a3" },
                { "zh-CN", "d85b642d5326629cf7d248193f8cd91e370e2ee25acd821d01878328d4f63eb632a54aeb56577be9a8c1503b3a9bb99f3271b68c26660416a35b41aa0f344043" },
                { "zh-TW", "ce3c9a4fba475371abcc772db10c2468c8a9bf7a65ceb33a5325b9e6a996d6dab776f8085c85bb35a851235748ebd829689c643d5c31947a6d620599f4be24c7" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "11bc65c537400852bf9d80bec34bcb6f3a962ab19fa608d67a5bb8e7e81886001160ee6b50410a65ca631ae9d29e3993c06dc7f288f3db7e841d860d48430652" },
                { "af", "d25dc6d1565b5fd8889f8b10b78c70a969a6a8e2d3888662841a30cf9201ba044a73e9aa5e06bac257d2edfea6984e611ae3f2414b960a89d1682105340e8b28" },
                { "an", "e790ee6e6005c92480a089a6a080d769fe24bae13fac863c76d96408a751162b15921203879117727d3364417005fc75071d316c97ca079563b789b9e406b157" },
                { "ar", "addae21a975d45b2546651f5d8d926625b987122219409e2a3b02a390423174427671e98b8bc259cb0eb3dd52d18ecd735d70bdc0f9e5022282c84e77fd31c07" },
                { "ast", "c2bc1d1611bcbbe3a56b67d7fc1ba42952fd98a5935c9c5e5f6ee666dc0eb5d50873b3ac34168083382bc9d9b57e277570613cf2be36c3a1627e0597cdac5e19" },
                { "az", "c90931041e7a372d661f59a8107b59b56d6f43938cede2c504cb7b2240b5aa3b257723ad747bf774b37e49bdaf96dc8a46b6ab51f92072e336b37a1f7247b7ec" },
                { "be", "6b8b815cc89a60380a060c7b487b75c8fb87a4b314b12d419eb37b744e953a8000f4312df83e1bc0b562c4a843850ec67dd2126559cf90456be3f84c540ced48" },
                { "bg", "8c209aaeb506b922056a71586b45c868f5b3245129984d66b95430aef174abdf9f03aef5d9377a0cf679dce79c76a94541eb37dd6a24b73e62b2febf48ed8757" },
                { "bn", "d2b12fb7b90f6cafb8076c1d46fd613d170addcafcf904efa833ebb819b55b264bab4131523c42fadeae238b2bf7f25b8e9aed1f63386780877e2d3a8b3e2eaf" },
                { "br", "7e9a2917fb50b0ed84c5d1a4b3e9b731f8784d2ab6f1eb1e4af4116a2b442de2ab646355033ef783856d23420c0678814b2065f8d07cb68832185cd8a85f2f11" },
                { "bs", "0eb89ca8049cc8bec9bf7e703b97f64ccd80204dd8811c843adf2819f539896b98e44e9c7f1d376c99d5f83d476e194bc5c706eeeb88ede3d197ef98bea4175e" },
                { "ca", "9d4678129d61b5382a6c38846d0dba11dc0015ce77dee84b5d320399663417c58fe9a6728f746aef7519bf7ab648953d1e53878c92abb29ce389278aac1447ec" },
                { "cak", "10ed149d2624b3e373f2686f7071dbacc0bed78ce67cd99123873b7dd972bab0fbed41a4d41814d41e9f1906e15db178b054ee51033b87d359da91fb6b9838dc" },
                { "cs", "a15190f4742b7595a1dd3e997584c9977249a05f6a1995f06c5a09c716ff08290662146c1c16838f75dd5d141a1866680b10cc32248a6b17997b70ed0e43abaa" },
                { "cy", "f8bd98ef347a88e3efe10e2a75bf3ff098a78262f31002ddf75bb32802080151ebeb5f36c41973a0e9ce631e95ba2c009c14a5198bccf961f5d2278499689429" },
                { "da", "538adf48a15311c0cd59fc48794dc130a7fed416de3ae837b0c868f1bd8d499f395beb96eee2b6ec82c21021a639684c4e1d57954d1aec98c1abf1083a706e6c" },
                { "de", "af382d027f3e2b471b52ae2f511ef11feddaf60bfb670d978c076b33e27548531845d14fcd855df74338c78a8990236eac75bbb6f646b9048b1a72af63aad62e" },
                { "dsb", "32d036a2a8a3c53571b9d20103bc3b94e96395b8649a909f7f50f68080a818baad1a0810798c56fbf3f9fba7b5b00bdd5ba28d3a78061e4f7304f5b19e45e9ce" },
                { "el", "4436326a67d4e2dab43201bd7ea69226892129f486c462f667cfe3628a662802c558af7a13a59d1c4e81e0dca93e2e3dd9f6e8a9b5532b6b3cd8d0c575d8a45c" },
                { "en-CA", "e32c91ada1b303bd9f74db12ae7761df4d4a11f7c591a9d17d3ce43ff63aa5b7ce67f4b3e889fc8f26acdaf37c1a9105ef2327532219cf90c83244feb296219c" },
                { "en-GB", "6163efe67e15d76b9fdd69646045a7084183d8e8e067d4cc16e3826b7b86044c767a4dc9ebb246c83c45a0058b1f3c5ef87e9177e3ed1a5b24fb7474433b2b22" },
                { "en-US", "c9efe87f6c2118e92f9f4080c05c23741cd114a8ea841fdce469f515679ff5e7d8a05f607b011ae27db3e0cb830d3f655294a944cfd185fa71335cc8beb54e8a" },
                { "eo", "993fee103cf0865796b319e4ce2d67fa9c25a1ccdc37b66ac75ef731858e40359b6cca1ec7c55deac1b14c52bf795865cc6f457fd763c17ea15d050b3dd1721c" },
                { "es-AR", "6e566e304958a3e5acc651d0a6d10171f5aa8060f95219163ae1b8d7b4d1b59f7dcaa07e0278ed909b09bcf005a33f3f12af0fc96810c2fcc2f8fc6d203e036a" },
                { "es-CL", "3040ddba00f465faa8a48579ec8303786aaa6492c7c6eed29939f818ec662d21c38ef3f9e3bef235e0dccb5046cd022cd5fc63179d64c34aa8be75e9ac97a2f2" },
                { "es-ES", "09be6ad7168e31f327f31b166b0ee1d97a379495b2224e43bb0b959adec3b6c15a1d442cac8eeb442e18ff2e3bea12810c72d08b3100b16d9025cb345825b96f" },
                { "es-MX", "aec0df3153fdc3c3e76a6760bab9ab98a3ef80305258b363efa7a3f5756900a50e9d49d0134b655a21a4dcded21ed6b2fdc394fd37863273f4127d4016bf3e36" },
                { "et", "b39b11cd95b6d681aa5c24b653932f267e5332fef44f3cc1ffeb40ab3970840c7d2fa8f7b85eee706f15b5e0122c67f418dc0838353032e7018a6b7c1a1fc670" },
                { "eu", "5f98149f29d5b177b551cd91c6774e42c031422f8e220b1c703df8f0e0b7c3afafa9fa85391d72c46ad80c999a2f5f817ae71da1194832cc2d7dd96169eb36bf" },
                { "fa", "4ca0c3663d3ed251faebb49d364ec02eab44fcb6b12333ea55ef2ceb021f8dd15cc39e09e805b67d4357d2b3fe70d86e5901ad1677236112507c45a8e6339775" },
                { "ff", "46e1cac8f0f8cd55357fdbc0353d1917bad341a358a16a569244f71598fd00740dd6be56929cc77fe7763cd2cf5301e54110ea944698463e5f083ea22eb1002f" },
                { "fi", "a83f025742e40249f88f515023fd01a041edfabae0d5675845cb22c542d976eacee3affa71cc9f8e5be7e82d57679b3bc54aeb0ce29582dac349f0c55b25e27e" },
                { "fr", "9bdee16b3f0e1a040bdf22605755720c45e49a8c6f5f39869a594a0b1ca3e3d05211d061fedf0168c30dfef61324f0619e7810f0fd03e472d0b25cf7661954c0" },
                { "fur", "e6311c0d9e7d993149912f997e529e09cdcd0083c6cdfc4d8276f7e8dfca8be4476314d5264371b737f93ea85c33ce14be5f5d930efff02daae80f9f5250049d" },
                { "fy-NL", "e8d3af39d3e5bbada1922ac69eb62e8a655fa015044518f05674ef3fdead25622ba709779d0688919c4888288419ff88968b0aeeb7275027ab4961bde38313fa" },
                { "ga-IE", "3894d13f14606a422943930503a69ebefe206570784228aa042c3ef0939e2f2f1b6341b72bd4249a9a900552e207d4fbdd3e01a760eb874b34c21aa6479e3503" },
                { "gd", "fe7ebd676ca529f270a4b74417ac20e27788d4df14515af0150498343ba99bd0accfa3ba36516fcbde5304d85987f28d0eca35322af596b2479bbd171cf1d698" },
                { "gl", "3b70544ff87e6591e09dedf5776e731cfd5e455e62e4eb97e39d57e60d426640745c516978616d8067de61bde14ec7449a6deb879b835a5bcb05b66d665abb24" },
                { "gn", "592ac8877eb64720cbe988efb260992f7ab4082f7c79319d4f46153f74a3eb053a63e32d751bf846611304c5b18b246b9a343d948dd3e5bba38719b8fb71d821" },
                { "gu-IN", "ce25a84312f196edd1a24917a7b9138c8131920bc8516dcb01b589d29004f42cefb79ca79e596e75bbcc74d96731a1f62fa5b6363451d39bf825ee58b7c6a521" },
                { "he", "083c657042b815955a96b42a6003d96eefd71fbfbce274e30bcdc2d5703c8c264e32c480d1af3698ebb6ffe44f106607db70195767fd211bb4babbc0f4e0d2f9" },
                { "hi-IN", "e8305309f9b0f80a365d16fb6f7c4b8c764c493e90eacd8993f2aeb9d41c8827e9a218b295d7325f11ed096c4b9953f78dd4cadfd8dbf017af8619d13b419648" },
                { "hr", "30a4aedd294b934d50d292cc6e83d8e960d61927bffc84aeff0d86740cd98cbb5b96c015f4b9a80ea2d1aa6eb97aafe429deeb14a1eec9e8d94e315d3f1f5e7d" },
                { "hsb", "7b70cad4c4d3fb06a96ae7ff4c3673c39c3d620a5eb8232c2772af293c3b85ed1a5b4fa2866507ad251b04ead87b3f368ebe16f8c97b051d53231993aaf55730" },
                { "hu", "955697a6f170ff342549ea5280baf4d45f4bf9bc160d4d2497a6677c155e03af76b3c0462c9d60d564ef00dc8dd8d5895c2c28081301ee21360d8acc2627e341" },
                { "hy-AM", "8276d2db0bf7eabe4604b276e9467925f0db7fb340065509d36f2c83e087cbccced097022d224e694a9bee8f8cadfeba79edd4a906c55bf5536a8e493baff80e" },
                { "ia", "9d02f8b5cb99ce98e1c6b6538b4374497f689aeb5789d352b5eed63b80a6f25e93dd3930aee84b867fe2330c72e8fbdafd6a0224ec5a942102cc2471ba3aee1b" },
                { "id", "3b262e70cd67c3f534659214b2d39f945404c695dd61e9dde073aab37c079223f46df87e7bba1597fda7a143d9108b3865057693a58d9954afc1885c6b45bb38" },
                { "is", "73879e41a71b3184b2594e9d60cbc4dce34f8518d98065936e157189c813fcc8b8ba75718bd70637cb923d3680bb33a21eb4645983643cd07f24402d726e37a1" },
                { "it", "ca316f730835ccc36549e21732daaa6783a331a67b8a922700c8a21e32f647a2f5c0e96fa89ede1fcd0fdac0c0bc1087f4a7eebc6a66276a2eaf0278663246e0" },
                { "ja", "a71691bc7df36f7513f5a3a32268de12a7f56240ea68b3f24246559061830724c825c615063ee02d2e09bb2f718d949f3b8dd7dd6cdc06b8a2de181d338b398f" },
                { "ka", "fd0bcf13f4233a83963d531f3f6e02d21286ee4d7d74853140dcc03b3febf28c81c32a71cbc6246bf8e9f36c36421ea9e91bfc618d8e10818a18b590ef16255b" },
                { "kab", "509740855553266b18760df0fe563bacb433266e2054614919476157cc2cc642f7d865d21bd8f49a4371f716d81775991f178f0b91bb6c713035b60b744a0da5" },
                { "kk", "d100aaa2ecc0f9943d77024ca49d38db676f8e1d98f27b465b3658ec9ba78b1f31379ae4c88ee7ba823c2d829184c6b336a892542e0d42531bc19527d6c16d03" },
                { "km", "c5d4003ed5fad14d090fb217356430f4156867b5aacf0cfebe07b4a5fb311507dad5bd7587515abab1f70b85a49b7f594131b392ccd910570de85657f73322d1" },
                { "kn", "360d8d46b7d3b098ac5422fdedd859d4a542af6919398e945e77f5e82b5930c5f2f8e8a5b72cd815eec6a7756218fcb18f51a491669a9796b8806dd38ecbd95a" },
                { "ko", "5fd0fb5e08753785aaaecf7212b9cd4f24de1cfc74f284b703da5404e9994cd991004c803a7aeaaa99cfc45b0d9c99e278cbd133f855ddc114e7c6c0287dfcf3" },
                { "lij", "a187318695848ec2b04603b81e23bb9aada5fc8ef7c8c2dc64f3fbb221ce7dd0181518e02c5fa50deb0c9a4b0808eeb86d4ad4932e741db00e8257630ce600b7" },
                { "lt", "ea47a3eafcadaaa56e1d69cc4fb89b3cab5a67d766e92089285b967e890c448c3d2d4cf203bf408ea101d75a52c759110ba97eae88471872a8cd3339b613010c" },
                { "lv", "df857f01de103595b005a4b93a4eca042d23911017a7433fc6c09292897a5a26d5407181476e6ed3c6f5eb2d0bbb19e2ef7db97cc53a5a32fe58926fbdb12c1e" },
                { "mk", "a2d0b855a5306d76123730634ebfc4808635935ee493d691dcccd09d284dde2a30b4026c61edc84732a73f3cd916f97e83c0d0fa2cd1c8f80069d43cc0519ca6" },
                { "mr", "e5d826aa4bf3f8a4d4bde933ca95f992c81088c8e3cc27b2ef1a227ad2e8098e50442b82458264676fcfb543a5731ccc67cbc0e0dfbd825427ce92d853d5ee5e" },
                { "ms", "be55dedac76921458927cb94e5c9906fb71fc157c7b8c9972a47b18212eb0b8c7d3517210b57efb4ca8ea840e1040347a2f342719253967f82c797ec1c699f61" },
                { "my", "1eda0f795babaa241ea498de5f0079719006e4e893026353b22a860cbcd0c939a9c74835530abf058c3c2d2dd099a84a32a8fb026b6ebd26c75e9da28a70647c" },
                { "nb-NO", "6a90abbacc4dbf3cebc98c14678826a437a8e5d4671e2963f868b7f3f4d04533a972472f31f78423c3b971f28f6656045648f516799160eacd1651aa01100d78" },
                { "ne-NP", "92e8d55315677a9f202eb67c7ccb754162bbe2471d7eab48d1f59c2e0ef536a28d46c5bb1063d89497a83085aa4d3f27a8eca945abb4a679695d13e913e63259" },
                { "nl", "77305f847202ef6ff4956a148edb34b0b93d4ae96e5af70e516627f9b1bb9caaee3dafe08e9044791cbda85bb553ce9b909af43cd321339c9fc7ac0c521ebeb9" },
                { "nn-NO", "ebb1d338f67253ee660f000b82f8749af571b16571c0d0ac57e8ea98c2ea9ccc42aad08c9bb13f1c1e528285e226a61d5a1a49ed53d31d2b816740959c82c8d2" },
                { "oc", "8c1f6b5668a2cc217433213e6fff6afea999fd932cd99f97f0670ed77fd77a190fea694f6195f755409857717b7b6f69838be92e0257fe8225aa3c1ffa270b6e" },
                { "pa-IN", "d08778e09843f3071825f64ac51596c13fde9d39f47386ea4d68ea27744d8023a2d70c9f2d0757df9139297a2def010513a0219e0145e4c69a7a0dbcfa45c8f4" },
                { "pl", "30aec711f197d26673610b888ead51bf67c0195f9318396bb446dd0987cf97e005d77c617875b61f02f75f5c34b115ce737860fb6210a983c9119edb2fb75908" },
                { "pt-BR", "dd5413169b441d6302e61b3b3c1a171a10a6b1432cf237d2b59e7d178dc71ea554b76a5672e794b5132ea14041697659464f27fe9005ab5cd8b59df664e2d43a" },
                { "pt-PT", "9e6f5731610fca2bcc35ebd2a2cf69b37e49a9b627114109a570b6793c6d4c83b084d88b4bd863328904fd000378cbe20f091c67694cd37f2d4b4c78cb4aeac1" },
                { "rm", "6a0d464f169a3841107b3ba95f484c872d0a1a7f09eec93ba84fee86528c30bd9a80d7012775744dc21b4e3ca56cac96d609ae2fbab0efed4ad63ab8ac0ba459" },
                { "ro", "06bf32fc369451da8e86c218bf40123a74bae00f89ce4d07629d0c1b5789ecc2479c7df9e1513df36eea7a56dfc248cfcaa515e2ea3a592e079f86829986aea1" },
                { "ru", "dc8837051b38c16c84c6719ec911df9698167383769d0600c6fa03383d6fcb5698521a382a16ea382782c90b46def70077e1f4f915a221d48584e02f444ed0f2" },
                { "sc", "c378ca384207db605afd5bae3445a1252469a7645478b14251cc4da06a5b14e6982834d9e2a551afe7416649a91e4d2659e874673fe8a5516700afa47910a0aa" },
                { "sco", "6ef7406cf179be4a8312ffe23232893fa694657efe34527891fd9a934e9f059eb40cd341a3c80f8819af383ab83a316f55608818ad1c6d476968ea14546a7a7d" },
                { "si", "18babbc4152a0870fb3be028f6f6ffa5d3ec8432e9c8c6687c829926ef48d51708d61cf031775e405541c0428d868fdd321fcdcfd47abf15faaddfe9d0aabc85" },
                { "sk", "95b940ad7ba293e69c8751c5d20e1128635ac1f4582bd38ffd360e1bfe4e6484ff2c9ba10b7f06e89bbd36ade988d99ddf4d791945ca13ac771b9711a0f2d61b" },
                { "sl", "a36ed77fff098ce274ea206e62a3cd94613938354fe8fee9f60896697096415666f74f37bcdbc63ede6bc6cdd8706d05e305e56c8faa80f22a8d657333cbdd8b" },
                { "son", "220d2dcc3c205e3bb0d66ea47ce88f2161566baf099dd0757d788765f3153c7e955b14b7f67467c6ee59102555e2ef81fae555657572c7982c463b37c0ab77eb" },
                { "sq", "e77936fa85b5f3ce9994d964635cf043611712c1e09b9bfdf127e9127ea018e70ee5742ccbcc58aee88cff37be5169147109e8fba7d87920710e232bc82ff92a" },
                { "sr", "32613bd3c5bb01e476a545b07439725eccbbd66b3cbba83e770ae7dfac6a3b8d0fabafad192d8437c01382605edc6364d1c1b2991c1bb0467fc613eb0c7d6f2b" },
                { "sv-SE", "f678d421c1a255e9811b8da33b553726ad2451a94de24e25d139bbea96087efcad5cb1c1aa9c93bdcae6530a3c08fea483395511047e742c157822a06f3df4b4" },
                { "szl", "d29f320d6252ddd71aa09f7d0b93cd46561e63f4b3dbf8867a0f930cb206018090aa358da682d7a7f3898ea520b2ceaf083949e50de71e37d4a274f44c410c4d" },
                { "ta", "e73fdf3986d6f79a445e95a48e637cb9a9388afd9b928dd4802a8cbea51562a7364a67074c7005433c0f9dcff510481a17322e4d690efffc7eac26eee587a7f3" },
                { "te", "6afba8951b6da4fcd10502bcde661d4f914234b1bb02f11166e5d3c96a269d48b82fc509a8d8c4dbc743849da88622fe2e1331e4b4692316d6a0b00f60318bc7" },
                { "tg", "aed7ae55136e9bfcecdbbb5b321256796e14012f76a4de5e4cbe84591d12483cb92de2e8505e51dcd27b363440d0340384c1264ac542d4a8c78ebd60bcde79c6" },
                { "th", "a2f958b993e77dd5bfc18c83bcf4d052c5379468f82eff4eac67cce5b668a0d4147ef1bbce5ef7b89f9546ccbd7eaad69d9600402fd1b559216872627ccafc7d" },
                { "tl", "575c6cc849e01c1695979869d45980c5b1d02cc79a8ba15a3ab6d424e7d19f2d5bf8a27e5a68270bff2c8f7909fc8119dc9467a92f81d208cdc109d2567a2e5c" },
                { "tr", "4463d096fda7227f302c0b8f8ee0625d4c25412baed9a615f9b012027d5f36117fefb60ad55aeee738388d893f278051ba485e64ad59ad8da00fab0da9e96af6" },
                { "trs", "d270124ca21fb1e494448674628ac82c29441d34e61feb6409bb7122a256a8202362e7dbde9700d19859ac6d7f46fa3d8918b1946e817b70d3284f4d1fbba87e" },
                { "uk", "f081ea3c89e1be97d908735ed928a23aa694cfae175a80fcc7a0b2a069eadf173fbb8738285a0fe9cecb9e7425b6d9f41e811aad2e5da95dbfa860561200abf9" },
                { "ur", "466349cd7c46c8d56c40f94e24bab46a37efc64a5996d72cd30c413c143e2cadfbbab9af544a9057fe0f65c452050fc1cb6f698594feaa16cf01c3724aad3777" },
                { "uz", "5a8e1ae57da5334571783c269536edec767a026ad23db846fe2a4c8f3eeee45fad6ff313398276dfe1380bc8a1b72a16794deb7403345ac06e9b818fba875b82" },
                { "vi", "c3c4b73676ff92e83755eb1bfb4957cfb4cd1044a2e3cc4bf45f2dc38845940a6aea75d7fec6aa907fd26160aef9c516bde5d2e4e994a83b0a65be8b5ee9b5c7" },
                { "xh", "b56be5dfda2d7ee8e39f5e13ec06002dc941357e956feaac4baeb60bc57d6ba317785567c1a814b64c3d859a6013c131cc4816d9236552ec999610651c60a462" },
                { "zh-CN", "592ad93fb612d5bd41080eb51c24251faad76d980d19da3c6d242bb997de113dca1d582cb1041c48f94339c197d93978e9ccfddc331e137117f3210359f65780" },
                { "zh-TW", "e19b951db946d7a2014dab754d5e80507af3f766e6031445e57a2e8d16daee75e3a2a057d8cbd7a64047e4aa1d3c43eee8f540f341a5bc234b8dc1c1b029af8e" }
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
            const string knownVersion = "115.4.0";
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
