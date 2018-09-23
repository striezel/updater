/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
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
            // https://ftp.mozilla.org/pub/firefox/releases/60.2.1esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "76a727935e0903a196ee87b93808e9877527b2bc1a97b389d2984c2a539e756ac931a4c0570fb795b5d773e923d89ce8dfcb7d2153b99e99bd16bb361cda2602");
            result.Add("af", "b142d3692383960c80b7baa2ec7ee0a3e0e8de2952aac8b1283ef1fa1d0c61fe123fab71114824fbe66bc1e1befffc364f642e2be0909bbaabbf29d0dd08af98");
            result.Add("an", "6b4a244e22cacabfe8bcfe68faffe91175d319760cd5639ae353be4b8c6f7629838755987a5c4a7441cbacec8eec85b0da3f5cfe8c70726a81b1268a6d1d6c62");
            result.Add("ar", "9bf1e4f95af3904bb295a71cae62ab8e375a35cded7ef001562665500ef4cdf0062614ac75b99bdeeb3e84276f1ad61280f0e6fa73303ace8f7af48489bb1acf");
            result.Add("as", "868118aaf5d8d1c0a9915adbf343ed998edc03280f19487a38dcf51e378782fe1f125e53a0b8b60293616d8eb14747e5df28e679e6a724a2d9a6e77a9164d47b");
            result.Add("ast", "3bccbe488986c25ed08704026defadaab573decd8d6e48b7b9d1faf92af68ddd4c19377163c697741e79a2a409db31216c98848edfa359788265e0c3c053465c");
            result.Add("az", "8809bd2463334cbe15b8d284aaa5de1f6c37c4c38963215f328b2d6ae931972e49d3ded395436e4f85e29e2a482c2b6e879ddab3e5aa97c7ea6837a434f50e6c");
            result.Add("be", "390678f38be750dd220407330ea6859becd6694c026403554beb7356c6b0fd16c88ccc2f87c32058031021867b88f306f1fb061e2be3313a3e86a80983c0f9d1");
            result.Add("bg", "6ed077076ccfd7d7c74c2f7a9bbcaad5d5ce96dede59cef7f7c45a8f40eab560835c38490d6b945be5f3928f19bc7a7c699c53a5c4d5da8d7f44a512d51ebb49");
            result.Add("bn-BD", "5f4c60fd8bdda4d1ab8805bb75d599f8b74e7f76638743a20f1f86a136e9664d3451396517a1900e3579b00318694b5232bafee7546bebac8826b30582623464");
            result.Add("bn-IN", "0d7edc08b103477e3607b4aebc25108f98a4109a474338b015b99fba38dba808a42398e4cf6c99264f7a8a81f059f686e4b844b385137caaf7a24bc7155604a5");
            result.Add("br", "0bf27a9d74275719de6a380d17f823af5603e94f4af58635be7c31bc6b5aed268e066da077bbba5dd8a9e16c7df500310d939200e3c5e53cf1154ccf628c23b9");
            result.Add("bs", "971ceec974346ab2cd1b0a2e01b62d8e5c21d5d700a927dca157df296e7db42f9768bcf368d9addf344aa8424810acd2b2a7628f2f4ac3e1417c8674b07f0a84");
            result.Add("ca", "a4551a0d425d3f2874e959a05573c1293cc1ab826aad712b7af0bc29b2e5100eb23971b3715e4ba5e8aaf1fd4c70298b38fa852f532a32bc1819f915106682da");
            result.Add("cak", "e804fedceb4d194a226f3d8658dbd62989b92a3b72eac5ff0ea133b08b0c8813ce1a94a17d48015d817dc79341f66def16f61da73125e7f9f56f22d91a9a6dc1");
            result.Add("cs", "00b065851455d8d3a35759b216104a94489fa34cad9aba0731feffdd9c7c59e48c888aacc4f86a0f4765633bdd54d939cc3ab9bfb6c3bbfaaff3539d7738f894");
            result.Add("cy", "616b07590d56f33e9fb47dc456d48d82a5d495c855ad60116f2457a6c926edf47f09e6af72250163cce632fdebeb6bc4f3f293f44043075b9b0efc204584a848");
            result.Add("da", "9b2a87ab4efd8d9a4c4babcada2f0288088eb7cf2678dfa330ca2adf3b777708311d55a87755deca4eaf43863544e623a2916221bd664c22f28a8d5b0a2b000e");
            result.Add("de", "12b1ea4808d3b89a54c22c786116f51773eaf9ee154185e1c32cfd386f39e474eec17926c2ead8689398b3bf040445516e277f5e21d082b1b8318fd41df38cf7");
            result.Add("dsb", "0cce79df47d39fbfae65c162b71aa4cb4d0a6af4194525c7a45d7b4986455dfe88f086dd223fd8dd030ff9237b30adc333c397bd156c133b08f9800f20272d8d");
            result.Add("el", "cb3bfe01dfdcbcf829eb7ff52ff7d2b2cce06e0b45a949704283a8a5ff489457f6a9c1b63da5c243b4684b83202ef94a7fd8ff7bb83b196eeb5545b65c8edd55");
            result.Add("en-GB", "b6c03272d3385d6c6b4e78394e456416a1b336e0211640341cae97105561fb49003bccb6f07f64cfc02e8cef3821204c254ba0958285b18170babc6ff519325f");
            result.Add("en-US", "7508c37f23d910ac041c6e6251719ffa4ee49146d064158f923979a9bd38b7d18705b30fc4f3169fcfcf4ed4db70f0f71702fcdd99d1040e06582ec1b76345c1");
            result.Add("en-ZA", "e6180fe830bee329eff02b122e3652d0c619689e9793b26780beb3227d6b0b58267b80b4bf786696c2da5a58645510d5a9b396ef54c3f209fce3e568cc1ab545");
            result.Add("eo", "92520c5db200cce88bf23a37d4a62604453e10771cf6ff62d326254f270752b291a125d0be6534be2cebd0b32a81cf22aac4c73e34b7395d0c8a9281a58672f4");
            result.Add("es-AR", "4d82e5b47bde18fb780d3d6f2e933f8bc922cc1c9da358f8124e14d7be560e6e45c08a71d361f64adbdf9557c4678d2c942d8f926b57e6e4d7f1a15c6efbac01");
            result.Add("es-CL", "8ade31abb7216ec18bf8b0d6be3a74b0868c1b67f03e857d1d4dfd15d77e9df1f7769950685d2fb05905560fc4d8c9edb461aab59954c0b00e801feff8563b42");
            result.Add("es-ES", "9d8dbfc26939a9f0de360425f62268fad29f39eb00bed5ca40cbb1ee12d79a3dcefcd66ff9364ca7cef90faf1404faf8a0225b9d6f5db53699607bd6e85a4dfd");
            result.Add("es-MX", "b53d13270bc7d18ed43708d87d44bda6b8be1c293f011f5d177a6a76842f7b1b2c2a78f14091a7d9d68d7d048dca97f08ad45f59c8cb56acbd12c4679134db20");
            result.Add("et", "1a067322ab20f10dc5c08e4973f6ffaa0a402e2b61ae735bb093be4ed46e2685ce9de86ad0aca0a6b4eb979f6c27faf3c95a20a5c2d96e886be0cca5922e4c91");
            result.Add("eu", "524696dba11ea56ec3b7f48fd98e0c6f7876f61022c990c211d88de47b57ab76901332c3f4fd2b19441b9cf0b3146c07eaf164044d6058fe506e2f4764ed61dd");
            result.Add("fa", "abccd613455178e927157dcad4480b31c373d0126c2a888d4ebaec7b18f31c3b2eb54f91035c228f5ec1ab257197d6d43eee73531d27f66645b0c5ff90a1fb03");
            result.Add("ff", "d8037354cf4fff30c7bac158cbbf4b6b87ffb34cc4d6be4480ba339a6bb38a9f49cb3f45dbc7c17197865bd2c4861d0edbea971e5f79e89006db95a24e90cfa2");
            result.Add("fi", "d40d6d44c51e7ee5f48c9e453ef1b180654fbca6649498e9f1f0e069c485e0c2b538dbbbd19e08a05870b85c42a0be7371fa2e40739d83614089eedbc9a50c21");
            result.Add("fr", "2ed722045e60cd7ab696d77c7d2c0b211d3d2d005d3946183a0e0edfd0bd1c67d0ba5481f2915e74e66d03d25b134b08c308f541e53ee747139c08ff09537e19");
            result.Add("fy-NL", "5a73fde58550c4005cb8d7c016e2765974a09d41ce27b9a6876d7aa2e24c2bd9f76a37b8f090e33347ccfd61929caa7ab3fbc2f6196f718d75ef5a77760777f7");
            result.Add("ga-IE", "f3a6b151680c3d277a351918da8757b776b6f811038e551e8b20575a060f3f17d51fcc5cb51867cd159a19fa5db52e16ee72f98375dbca177051d3333bbafb51");
            result.Add("gd", "b162c7033a3e66b65d322e67c5e68f030696fcbe600bbefacbba0a58066d0839157780fe1c3e376805c792c9fab58f4a9944a8d1385eb701a9da93b38cc8546d");
            result.Add("gl", "ea1fa1ab84b3d425cd2f1ba528d45a6e6d2b003105cd090125af7074bfd7a82e220dcd553cfc8c9eabc91eb29ee6841cc57efd22ec141cf2398326ff60a76816");
            result.Add("gn", "dea7aaaa7bc2f87d95e9d06b050874683052f50953a5f99d181fd77cbba683cf78b8a61d1b41d72e3f3cec92202dd3119403eda1aa2d206c63a75de788ec9058");
            result.Add("gu-IN", "77a544ed793bd7c60a07e0651cdfbe322026ec8aa295fc4a8c83667002e13d6c41c4220a0050548cb49fa64f84c9795e857688728c1fa096b05ac4cf307aad22");
            result.Add("he", "279ab4b35f62ef20e4cdb3908821fe084fde50a9d148e1642ced57aa0527c813cfa19116286014596f5abd1bfef9f2f50b23022cbb1953e07ea4b8afef6ea434");
            result.Add("hi-IN", "68ea07d7d8dc97b68f4fb64d0d243dde372708b1455e96edb9129afc066cf757523f96fb7a18791ad32cf0e68afef0e371d139bf8e9b51d8ebca20fabeacb059");
            result.Add("hr", "22516f371581d22d867da5293c2f69bac9050b9c937cc0e239ae782c9cb5a53b9c6c1061b6704ff72c94aea5788f3dc4008cc5c2f703a3891af57748a8359048");
            result.Add("hsb", "4f43a30f235b55aa186b807058e70d5477cd9625e7352d21cd5b3c67b8afacebfbcf578e4abe33d923744458e08f049241e267513d449d82cfa77553e41f84e7");
            result.Add("hu", "d5942cb857c3f00886cd382a328aa3d0d3fdadab46250721560da1754c2273c2c43021e6989df577b8458805fc0d5df742cfe69aa29d2db93942fde3f738c89c");
            result.Add("hy-AM", "bc65891cc1a03b12cef184faa60b7eee19b9bb9603ef5d10c5558d8b9d99e9dd54fe740561f25054851edc9cb60cfbc2bf7e5ab6b098c6b61f9c10c966ae119e");
            result.Add("ia", "cb82c371aff7b035baa856786d46a9ede802b8add3ef0a910ac64659ac4d3b107ef877573d3609ac1f9c638099fb25b50e54981cf7676091a370f99ece9728eb");
            result.Add("id", "9b3497e583ebe722d63096d6d8a0c9fe20b340af6073f9fbee571bafd3e9fb9c519f6dad79b249316c8f7280117c1e4015933d6d4827216dfcdbe198b77793f1");
            result.Add("is", "08afc5445203b0f8e747311376f45af7eeecb4f7ca4782d2bbe6288e0f6cab707062b920dc33195bb65dcdfdbbe456507a8dddd3e0c6c957173c548e15e47752");
            result.Add("it", "418629ffb991bef1f70f2ab84b791c9a55be7cbd810bf3e1de6d0192d1b2e78eb94345ee93cd2a4cd4f3aa148d9f1b41fa5d12fbd7d1f762d54a874a892f16fd");
            result.Add("ja", "9432f442dc45df97290a612ef4671b3e7874aa8c6d8777200d9312cde62b371b6892af553de1728e057992301917f75eb82d135b301b999a823676734a3d2642");
            result.Add("ka", "f0fc9be2aa8f5fdb30143274f9bbdf00576a6a5931dfd91d3213a9300d525de42b97f72a95b94ea1ceaa0a6556c5f6bc255be65feb34a793305018006f1344bc");
            result.Add("kab", "7474571722a379a63468bf5729137e8e81ea5af4999a31b68b41049c9adfc35fc3a87f26b6a8bfea5109bafa2f095df22a83d052d252751b480616ae87180189");
            result.Add("kk", "a5b12da1a10a1eb1d989dc1e9f95f0864d2d67c6c751f241128cfa7cfcd3e07de30d5c88120aa4b0227a9c7db7bba6f5b81fa03d5d082b60f36d57dd164eedde");
            result.Add("km", "b6dc547614fdc954544ff8c314dfc57734472dfb60a57166b2bc08752b06ae176ee722dde92909cca086399f971d56969ee436786e8b917192416de36f535359");
            result.Add("kn", "20ed48cac69fec70623301451ae6008401e3604dc3e4a133a71bbf27f4db36c5ef21922e5df52ab8b05e0cc47f3561232b82cadb66a38d90f19ce05c83552555");
            result.Add("ko", "120dc53b166c0f7d6077e47e3cdd6794c45baceade8923835632081a5ad3cfa5e52e165aa7b005adcc2a3e92168549c420160f326587599f7d8121af1f060ab1");
            result.Add("lij", "0c6fc647e8dfe4fb4709317d70121fef73e78740f2ff77681b2c056a88337579c23fb1b18192fab1eb77f2445d07bc9cc34ca5f16ddd025f3572d418add821d8");
            result.Add("lt", "de4603536bc2fc0585da5dc435b1bd51a8a5367f09e9d90bf7fb76004f912c01090621e55ca8635f96b91d5cfa8be47d82101a840eae8cb2798bf8c60e92b626");
            result.Add("lv", "2d83189762d28c0637e1a0feea7ea8ed96149b3e82e4ecb84a154049d60b6a8f3d1d2931cc39a22c26369f8ef6dc83471695ab4d27eeebc15dd03559ffcb61fe");
            result.Add("mai", "be44b8e3ad6f9343e7ebbd8488a66d09c48e399572c115b738e3103c14871433886296ff5c58ed2931a545357945840c44c0cc873f1e1b682f2c26661a939013");
            result.Add("mk", "98c4bf719a943cdb496bfa39427bbb9b904a7c2946463f0f03ee215853025abfb70d87d125c2a15919ae0f49d6acfdae385579a2cadaabc05b999c5bb57d5b6a");
            result.Add("ml", "c932efb24b8803d9154ce4aa5d768c31541474ff58f6c3d37ad59eaad3a94d8a4d46c4d8cae2148105ef71769f3b3e64b294302d637aaac84e71f63dd628845b");
            result.Add("mr", "507fb01b49a3bd7f11438ab178b77e0e22fedd9b0edfdb19fbed8c2e1e0a9676d34c9928a3181f34177f457bbd93864e05ccfd33ed7d05c05e6f412c6abbf25e");
            result.Add("ms", "9341e65382716c3957189412f6b201b6582feed03f7f83f74cad971c0f390963fc2bd7d98e3b59d5ffa813f4f3c12bbc84a8809705ddbc611b2dcfa1634a01d4");
            result.Add("my", "8222d17467615b9514beb0b50419c63987f854c3973b0b05110c01d7ee97ac15984903989394697139fcb38ba1a4f9288621329c8b343530b5a3b0cf40cf6669");
            result.Add("nb-NO", "898d1b8875f5c26df2f71997388dd82a73f21af5a9421fd11de8c2e718ef2f719c35a7c9b4a38a415d5b5a2933606bf736bb8cfcfcd26051cfce65699423e0c2");
            result.Add("ne-NP", "135f2299d95d3bc7715c7c24b656cdf3b6c64c940709c9eb5dc8e80562cbe1a6be3c7802c09309e94dcb87b483da6c49b9c12acf2c9f875c1fd730854c740871");
            result.Add("nl", "2d4bdb4acfe2c825ebc44dbcd8623a2c2ac5d954b699d2a44785ece6757e91e2fcc622acb89c7ac8e4b8c729a67055f4c60cdc266aa8364b6a6aac1fdd92dc95");
            result.Add("nn-NO", "6f1844dee4fc79872b8e481d3f6092111c643c079452a807c3ef96398d4cf700bd8748b3d6df5f39fc7c2192e71e6621185e4db3ada170489a37e47b468f7da4");
            result.Add("oc", "f72dd35b1de0fefe31693c24789af6fa3fed49398fffcaf2674c523146cdaecd18d144a4b988dd17fac3678044fb744a87c31a612d8651e76f83ad946851156a");
            result.Add("or", "14151c85212059375a0a34d2bcf472d4fba34710eeaea134a248a169628aba4fa380f4ed3701285b30f5ce2c6ff33845608554052a289e0aa8718e0568e2758f");
            result.Add("pa-IN", "2ef7ab97aa1ee59463383ce7a0d7d1e1c0e80635d1532ea59cf6e27fcdcd006a99ab040378b10131b8e94caacfece6fdc55990e108898133f85d6e98872b7311");
            result.Add("pl", "6b6da45298a6c511d2cdcbff7f85ee9b5709b597162c8e60307af4c410a958591e165b2e8970ab6829def4472d5db990dfa2d478b57a90ab3c04361432658dc8");
            result.Add("pt-BR", "65e4d3db78f23a0b43d7b744672a295d7f1cca3c6d7f2033b58e95ba096421ced10e71ca0c6065e604a2ee7f9411d2480a06d142896459f7740654d436234497");
            result.Add("pt-PT", "ed32f0ed4adf6378f6a85172ca3836d6ded63997a57e82e37784d0234c660fb5043aaf50f32ab4d7d44dd5a55a7c13d46a67635450a4ecb7f171386ab0901b4c");
            result.Add("rm", "49333e4a99de2e73e1914cfb5169032b52b78058583319bfff30465afb30ee3b0b1e535e5184a6515d8993855e2a2718c4de8b2dfcfc9de40511943ad4e3d34d");
            result.Add("ro", "d5a99ce5f2e7da28205e30bd6b6f1f6f4e13aab6d01407b700ad136a6a545ce4e50ba2278b0e27fcb045c3f34f24def685a9003c5bedba6f3657e062ca73db15");
            result.Add("ru", "c0564ce03a561d13297c9658d04ae2940358d0136a0fcbf1f2523262c9a987ef6358efc7eb5bb6f0be3167566c00b66145992b485cea55143cc3838c87ae41ad");
            result.Add("si", "8c7737da78d1cfe50e8d9be504fb74699197f5388994f26387f03b25548cbcc169fda0a3664724712d84def6d32592e0bacbf13a3fda333d10a3b2ea2340a0d8");
            result.Add("sk", "1d7a911eb5786e211bb3128987f10aaaa5cd7ce67dfbba91a4833e18c34f5022bd095f7c604e1e96f6756e5c9dbf5ca84c895bc658fdf90f3e92dafeacee961a");
            result.Add("sl", "c91db3477777aa8926c547912540f8ac23633f4f838c245a96b2f7fdc274f587597dc9e1d85b5a6d11a55f688d02bae35e451114bd0cf9de9253f623ac76abf1");
            result.Add("son", "c552d3347733653650625ee775838763de53d15733da9dac2e61787f4aaf0b71e3bbec03426322d43ac66db3e7ed20d09d082f73bb58153b58ece1fcf43c2a3d");
            result.Add("sq", "f069d22cbc75726d0f068209185fb4289a6cb88f66b6119d59eaf5561f4bea63a98b7f187cc5be972070f01e2b1afb8ce5f10c07b309301837b8bcae03e7217b");
            result.Add("sr", "15e3b4a0dde42fd4afd75124bc8dd7cfa422588e0ede52f062be9cedaf3a74583c6a7e7389dfbbc4ae756a24e90084e84ddea31396207c5bcac3b5066c971634");
            result.Add("sv-SE", "d0b9f83bc644ce3df5530337ec4f60fea02520fcc54748dc473308bffdc58d4185616df8b1c64bb6dd4b38ebda10db75a5825b40b0192bc2cbba775a1a9f762c");
            result.Add("ta", "d1ee61790f6d664d8db82fca13b235f87ea34c6e747ea590365addfaa499238cb27125e5583f579b5b762a2c8e75c0e8dccd03d305b5b5d8dfa5ce3633918509");
            result.Add("te", "39c6ad866e5f35f0308fb9e30db51df6604359756808ad7986faa3ef1133aa9aa11b49b64fed2608c2cb0448a45c179423b2dfd0f92da7a7827349fae36519ef");
            result.Add("th", "1cf379f70ae90fe57dcc3ed538bb5302bf21d91eaa8a5eb0cb90b897a20283a75bccbb29b293426b9bc9189c289fb93520a4338d7629bed7cfd19af0ef85449c");
            result.Add("tr", "8c1b2cf98418b9ceb9d0af1244ad56ee261b7ca1396e9f0c641398c87ef0f8d34543795e41c3df398498b9371f13b03aa25ce37d16b9266d139712aa64a4bb59");
            result.Add("uk", "194ae5a5ba542aa77e379494a65f8feee593f81ab0a8d2aae2b2872d116dc762623e2f0464ee0edfc1bef83c5c9da446d8c7ab9e20bbccfb953003be0991be1b");
            result.Add("ur", "2c50aee718f105aa44644cf681bbc02d4cebcffb283bf1ff68d7ade5a8978492cdca8c9a1a1e8976760a1a099ad1f7855e129325e58a679f8a0dc1422bb93769");
            result.Add("uz", "0e4f0d48c9a48663dd02af773f02d843ef98e2d2c7999529e734d924288d9c2e906fc1372499bb6ff2d3614200c469bc08f6864c0022951c6aea4fc642f9c3bf");
            result.Add("vi", "498ad7ff04158389359272d79bf7e4cbec06ab37ad1bcd64c2bef760ecccc3c7799c41756a4cbbcbc5e824ad35c7023a9899754dcb868b85bb559ba8db20db59");
            result.Add("xh", "f0dc783913a55483a6adb4550444630cb97a7845cfd79940e885a2d5c350918b2019368430a9ac3c8d1b7b169caa1a4c07eb6677787260863de55ecc2a4bc372");
            result.Add("zh-CN", "3a5447671c842f441498435434c5ed7a4fead0fe48feb1bcbd9defa6592c1d5111aa4554762e086df1977dd74d12322bc9c605a0db5d2107b05cd3f5687635be");
            result.Add("zh-TW", "67f00f86614f4f13691e14befc033943949d4585367a5c6d3b8c84143b070423a5a0fef1764972e21eb72040d6870dd27c88c65b8cbcd0e93c2623d274780824");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/60.2.1esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "9ce9df1922a2868c541f5d41977935570a1f88a8b88fe6527955fe89036341ac320c376f9c2103abc4854f6e135ffa26a6c46a7331852cbd9fcaf72802069d06");
            result.Add("af", "10c7c80e85b9b1ffb32df00bf64aae0df337966dc97ae59ec6de58a2abeaf440ac1847f8a18e3215a7fec78876d4e61156c2b8cb47b6e02442ce3e18b5e6ed9d");
            result.Add("an", "43a5a90d11b331fcfbcf94883a5d4f2b68bcccba6f329abcff8ff9b3766ab3afdcd1f6a3fb9547f223ca801bb602769021eb09e2adca7e7b12d712ae3e67ed17");
            result.Add("ar", "13444e2c142b2e34282937709faf4354cfff9c709f9c1c51eed72fb4f665d6236466c51f1d0da1b76d9fe4d80f73f79d3011c510106caae9eec54b3178a7a771");
            result.Add("as", "f1a2ca76b5075c189ea5dc15340bb40962c593b688b35210e39116ec97dc1db50c78574521f4e10d478f6a61bbae543fae0bd900a8d46f5b6fa87b4cb7a0c878");
            result.Add("ast", "df1df685eb8edfe4e4889324f23aa0bf885d17718cce73d66029d2032350fcef6c1972de4e7ed7b8cfc186e2a4516912f476b79d78704100e1d82d160d8e50c5");
            result.Add("az", "088691cbbd4fd2f76576ae2b46a25108211dcbd9e63b772da7b2635cae819c11479ff5c1b4509c33ed0377c0c99b977e515eded07adca30b9f8aa203ade3ef56");
            result.Add("be", "d71d688f06b3e8dbdcc327c8323d9a35c865a6ca11043c90d451bf70b3b8b4f28607ad4e5d1df2684581226d92c409e72d299be4096f4a2201c2c215ab5df838");
            result.Add("bg", "40737b6cbe1a63c115e0535d9b4e502b2dc13661c2bda687b7f3f40792e0c834f89e67716f35f298338509319a745bf0da2dd3d197ef5b9da5060537d91c241d");
            result.Add("bn-BD", "fc37152eaf0f4234e536c94e081e5c7b28da77cedac81e32d5661e282908781a52648fa1303cc1186e44ba311dbf4bf7cc6fce6da6f765c5f0b383bba2a1fc82");
            result.Add("bn-IN", "648916c53cd3b5d90a31150fd44add84b4fce65255d4a0a3a2a2be8ef7044a4476d3a75a41e365f9ed541525f827eeb112765c791b0df74606c37351aa565fb5");
            result.Add("br", "dd9be9be98fe4e7284d3695e575c55f51a317752bff1d7b92e7babe6ce9c4ad0bdae4d8651476fd2c8ceac0cedc5f2cb15dc8f6a3464c1e8e805dfb4bd81b426");
            result.Add("bs", "580501a178ed76a7579259af8c047df07b53de1b3a67040fd8e957722f58f1e6aa4286be5cf4707267066b779427ec6a7c69b4394cfa36c75d5161d12374a0fc");
            result.Add("ca", "35bf2d6daeaf6217415554fa8c8028a3772cf0c7310c603d3a05ea7525e39f8eafbd27090492410a5df00e1c4ef2906acd2cf11029a20f05136156d45c20908c");
            result.Add("cak", "1463fe35794c3bc8c837d1522c45599925d2944e450e691039bd92f136986ed21b9eacfba043c9f149384445f2401e9fd36e67b0b33f3d551b4da1e000a91aac");
            result.Add("cs", "ab0e3cc602ed7ad10b166155a06d28a6a65b96208f9b379b19dc6e44edec01df6d9cf060c1379db05f85074074901fd423a8183449a241b300cc8da2f6279f44");
            result.Add("cy", "3480d4bbef506361b8f34623346c9ddedf2e3734ff4aa2bedbef49b99f92022f4b206194705e11a7c59d9e1129b3440688e8d34abe4e00817564cb3c61dd7127");
            result.Add("da", "6bb280cfab94a37adda460079a071abb28f6226f545ab19bc90bec99fcc9b3cee9da1af4fc1de299068dea19ba2dc5c894cce3ccd96553dfa743f6d48f35e075");
            result.Add("de", "7fd387fd948f5edc17519642417a57f72021577ecc847372fe2b4d4e49933762ec11cdb11d4ab00a6ced8ddded776f8ec0d49ddbeb0e85e54a92ed305d99998c");
            result.Add("dsb", "0240743c8ae0a5fb6c8337aa70d859b92d3b6cd03f3d60cdef6fb59ee2c6d064db8d4ae48e492209b7907e8cccc01f254176718fd202c99fb08502719dd03bf4");
            result.Add("el", "ffa2674c88b0af8bc1f6f358d727fb5be57fbc281d54a962492aa9082f56ccdde91d20b8db1466c9ce424814bf70291ee7556a04e7356a10e71fef5b3fddc2d5");
            result.Add("en-GB", "b00854808f5379defae21f6d2a205b41fb180d282fdd2671e02ab1de017c85efa9c6e8a036942bb9d48b539422e7d5e1c40faf19b374feca1c1f91cfbbd5b952");
            result.Add("en-US", "50e19d1e24009c9f789110ba42b98b34ad565257e8963eb1a04b5dc4653dab6774fb7faac0ae57e2e1dea08243db339123f682549119e67db00ea7655df3b2d3");
            result.Add("en-ZA", "bc7abbe813e5a80c98a449dd8f71cef92b2c05aaaec3fd9b851084e2a8d5fb35119ba19baf6602ba8f0c61049c046a955bdbc4d2a543351d01c7f61dfeadd2af");
            result.Add("eo", "19465c047ad56658d1f43a8772cf830f1ba55d9cb990d1f4a3353c68d8bff9dfcde9aaa2f7f39bfdc9ed6503d2fcfe4b4ff9d8dad32978cdaf3da2c8f570effa");
            result.Add("es-AR", "2e4aefc60ab9e255014d273586a741985593ee252403b05456e591776f0081f2ab56bf45d6a486281c7ebfd509cbc92b9c6d1469522e553be85847e4455876ff");
            result.Add("es-CL", "a6a82d946f1c9c949b3bfd6f222803ea9a1002a085e19acc2d12fc6f8190e42a78ca2338b0c1ac3591ddbf56a6d8ac92e837b2256fb40afb6cdc059a44b0dfb7");
            result.Add("es-ES", "18c38a6c250f2bb1c4d5d3a25a2f7a1ffe6fcc6322b3cf3815c90fd8196fe68e9ac9c9767d666d7da13c8948bcfbc37815856009acb6e46fa6290550293dbed1");
            result.Add("es-MX", "480e7ee986c33d3ecd5eec9c4175c13216f93cfe888fb5ddb9049ad7f564a8798e5e5c942f569ce368da8fcaed161a943e343984874981d736a0214665885d7b");
            result.Add("et", "ca0e271827339f220e7aeeacfa394e3e48250971cf2cc762873f5709bd3bda49bc9704044e547b0501a92f1c3e332cac4a769e91eadc95010385b79603630a25");
            result.Add("eu", "6b599dbb756ce54daa3d0d6bf7ccc47f851ff0ab68f9e9db3baad5421a7d756f0ef8ec0b9f2853cae60a1cdc6038654bb7f0026a5171033bb629ab26fbcab006");
            result.Add("fa", "21120a515cfb448416638930155c30fef03e0c61a592388932d0be372a686d1b9aeada71ec1e1b846297424a12b4ae708a490aea24029d620776d5acfb9b7a34");
            result.Add("ff", "bdfa548c2e217eb06bb9e213204d74f5d9e5e418c641753dc960910588b5963a15fb5d714532bc2bbfd489a06f2899ad87eb6d844cc163a93cb0bbfc4459d598");
            result.Add("fi", "f18650d7c22f7ee34c4997e247243766874423acf3e52a1daf08c2bd6440ab57386c475982946cae36a89ffc352f8faee1122be7e83cfffe29e68f21291514ec");
            result.Add("fr", "267f7674213b0550bed1a2caab7a29072c88c4e6693e877f9a532103042551661185a35c3f857ac168fd4ca8419ddbf3bbbacabd18f2ad96524105c4f6b06ee3");
            result.Add("fy-NL", "efe094fb3fa3dcda98297b4057a536ff3ec146e2a320647980c3a67e6d2278b41168d00d174b0c66b7618cdd29daa31a1b708a364ac48ba0de403ea4c742c062");
            result.Add("ga-IE", "3bccff4fc159a05f95bfc2d1278262f77c312b3e6f9600b3219fd5f563416c07199df9dbb13dc5ede9b96e593db140791f266da541322c9227058bcb0b66cc59");
            result.Add("gd", "5a1e581a9e70eeec3f73124514745aa3cc54917d6c9d701a9134fa48a08f1fa69cc25037072896efbf4d3f159c3b75c859c2462bd107b0fca55b115e7fc77500");
            result.Add("gl", "0d7474d4cd159949397324f1610c2896072f2f1a22dc931973ce39e1b0f660d6709f85af8af7b0701802346471873e1fc7c1d27789d25006e0a9edfed8ab59dd");
            result.Add("gn", "858d0f9e684d597693be1418187adaf70678005f94bb6be2bc13ca86653fb6463b21ce9987e4379173fa208f82a4341a1ac9b2188013c2dc1b748c14f71eed0e");
            result.Add("gu-IN", "a76b49b8e259b632da90d893de98aebbaeab1b41a52620a73e8ca8accb1e6c85a9460e42ecef624863872e418838c987469b2050c03d6272c278353bb89fba85");
            result.Add("he", "ddca850dea2f66e9df657c2342d126192e5d485c86774274481f42a0f4320205d062603d953736e10c505357e299d2635697e317b6b13906cb3fdb4c14ddd525");
            result.Add("hi-IN", "a43d2b3d32908dfc6355e0c6a165b75145146d0bb1f4ed35ed0941e80d95e490f881a3d1c87411f4fd023e723b62da9db00320d96b18d9898f3a18feef788863");
            result.Add("hr", "e1006c86e36758eab79195f8758c68d9412665b923890803ec4e7664ccf8ef35dcbcf390554eb79697de9a7786cd431f1f927f06757695cb48bca1e7a64b7a12");
            result.Add("hsb", "7f3d91eabc0e1f5735d0806540ff9758135946b3ff3fd3990c87baacfa6c9ff998b68d7d8ba257d31ad49a252d6c11930703182ae09903ee369061906d475732");
            result.Add("hu", "47fe2af54bf9d76cf7890f446c27324095537455909c6edd996333d49182b1072ead5613ccf37a70431089dd39ad969a581bf42a04b55a896ee5ebc3c1bd0151");
            result.Add("hy-AM", "493da85bf8534943ea08223105d348150d28909c7af0df6f5b1573e7ba7395db8f9bdf29a3b5249d4d64157f25e25a6d2a6f3f722a761822935f81167464d368");
            result.Add("ia", "92611c1c366a06bf1ffa4476eac478aac58c3875c39b10bb473c1e2ec9644c61a601c7ddd428487e5ab836b916f0a9993082c75ad032fe959e408b6231306766");
            result.Add("id", "d42e2929de2daa6bc71573423d6951a7f49a0bcfe0d958af7510e0b0267da62ce4e842b9ddc94cd2351ce133030a4b3776589fb126b933c0887ae91454cf2b9f");
            result.Add("is", "7a612e3a05c7c4f5808113c6a6976972932e5c404a7a56b8b03480d8255aa47aba41fc949c1a76e617a6fb7eef09ffbb4e2d99f9928bfd31dc1eed6e6875e0b7");
            result.Add("it", "cc9f30525cf05ed035965a085e56bc8d9a3801043cf7758caf7374353fcb74d9ba8e303f158ef810a0fadd6b39da0f3bbe9596634f984db1731c6c227b1f4d09");
            result.Add("ja", "ab7721a000c2f1b98b1e8c5c720f8eec685239f31805eb43481e3ab152efff3ed9cf38825950d69bcb294b85866684b138c34e2053f35897133788f63dee31b5");
            result.Add("ka", "9dd4e85bc65860e22822e18eb7b080a4f2e188a099e30957ce1077fd86283d283f86173d86ccb7eebc3cfa13a8dbcb8dcaeb1170a2056d701aa7a0371384f742");
            result.Add("kab", "b03756d0dfd3cc4f89f517bc71b99c80c711d95aa82b2b99224f4081a4bf0af2a136847b7d890d50f19ddf29cb09c89507a843c2f3df0d945d6791904a1e8158");
            result.Add("kk", "cd564a366a81eebf9a7756269305485470b6ca251260b6f37020a1e2a73a692516060df6cc516c53836e4e1a0bddf7594ca05f060d42394dc389b80b1fbd2ac3");
            result.Add("km", "2818350d4fb1c374ecd64fbc8e20dc38a5ba7759fba918d3faf0a3515d1381d3e6909a5d0fd6377679495fa18d3c09d4777f9c5d1cb06b4d13db138f51a95943");
            result.Add("kn", "2e26ff32ae592c00cab7ab625605bd28c3915caf113970a4376b62fd328a95d23055763f4890e56ded272152a72ccda15ee7d9a3c60b17dc3eb48c3b978b1c61");
            result.Add("ko", "b2dd2dafcc79a3fab6f07fb61aa1ad8966f0b4568c41d22f381d17850692cf662ba109f7f9dfaf1ee0e7fb0bd0c78b751ffcc136e93f172c26201bd523a760c3");
            result.Add("lij", "f15c4e85c4f234b0f53d8dfbd4a60241cdb1f3f85b11d5e927806b8a0eac0deb21eea01ccab0d5dc18371cda75d426845de1b5060a8b4f8fc76f963fc26e9897");
            result.Add("lt", "853887393a6d5645d4de5c24b83ee23e1421c8999a0d6cb8b8c155033f5e5a3a0814f42ca7b43d6bc99459c27c55d6123a4783eb2aaccdfa4f804ef3cdf85c2e");
            result.Add("lv", "0299526d27dc9d25a8a630c1e3ee853a2f30712df2708ef713e2ccf39907911545a422c1817707fb07cad4c7d52f06699361fae4e4f167cb7398e02d0583b4bd");
            result.Add("mai", "2d69b93cf36df315c7d224ea14c61ebe561f29b9eaf53abef0002d712d37e015be51db9a3e01ddcf9c4e380ba4a5b50a097595385b76e5791195226b9a082a63");
            result.Add("mk", "036d7b40c1941c82bb510badd79181d756c7920974dbe946d984c5e24ee889183898084917fa8d101c3fa7cc239a4c20bb786ea2fc2ddc8553c6dd49c96e9700");
            result.Add("ml", "0578b098ff6ff027dff47669d6986cdc604a2480dc39bbd29312301368c95e71778419e3dbe6e7245949ff28874b1bb4de1b0223151a2ffc3dc9b9236ccf56ac");
            result.Add("mr", "81004a750e23057160b2c86fbf86563b3a0424842dbb5e4d8626ca5278da49c45532f1cb43c17e93ab90cdeda0c95fa7e316f5e0fa9d29f6d57f72446622da16");
            result.Add("ms", "98ee5bcf64df51c2e42c4a8cf83d9e18c4d942ef9500a38bd2dfe8c3ce944a01ba671d8884af6e000408d0029f4ee328683e80badbab511c8612e9e51ba3f086");
            result.Add("my", "88ea7357fbc54524d47273bbc493b03ecc5f0010e51eb0a30454aab251a92d5e7bb771f906a46017ce6721d26589ac31bfd196519e50152982351788eb438b35");
            result.Add("nb-NO", "4c1882e687f87082bafe73e2b9ffd047ab559a4942b896b3e05a4de878be98c094a79b45946ec812c871ac23f2a27eb91f8cec730fb097cb1921fde37edc4670");
            result.Add("ne-NP", "69aea998bba40fbfd47317c50b7cfef03855b92695a523550fbd351531b2069e60d92429522962e50d6092d0bc2a959d77cbadcd53a8f6dee72d717a3541011b");
            result.Add("nl", "31e292e1e6a441187983b16a5c386e57bd471753cb4e951af0563eebaf9cf7a2feb9f70e7e6024d9f66f7737c9ec6aff0ce5b673a06998c83fdd4c3058bf782c");
            result.Add("nn-NO", "e147b7d703812f5420ad6a28bfee70dc3f72c19222ff6f6d3c451bc1ef6bc8b4236c5fd8bbbf47ae1fadb842f89d3683038fbf4e99f1bcacf2a527ffeed76ea0");
            result.Add("oc", "1ac7d1f0cab7d098a08678cb9c6464f3d0a01d2f4560e6d23154cc07f94961739976f74b0242cab7e79165aaa63d5319dff161713ba9e0309fece4e49e9494e8");
            result.Add("or", "31fbe16641979f2e256572a78a255d6ffbaf573fc95d3c0e615f3d98adbf895c0d1626f46ec1312aa5bfe07f648388c51a1e5f4b76f600fa46d6f0e00edd6ddb");
            result.Add("pa-IN", "6abe673ea9cc2927fa9ae5bd37128be0c463f0a0f43ea0570c376341bea4d63de29d550683b3e05d65cb9787f9e71bf83d3bdbd2aeb9013b283b37907554b53d");
            result.Add("pl", "61b67224d0bfe3580f2ea7dd37ad7b39988d8608e459edaed4f91306cbe5ba306a4f935c63fa82f01d6a2542f405495c8645695d5b20fe3962e9d02b7970785c");
            result.Add("pt-BR", "35768fbe86f115f9a8cab9f68727299c5390060c448e1d4ad5cd841a7a77e9511251a9fdb886171cda1f0745afeee021a43f611a94f154c653537998ab87d189");
            result.Add("pt-PT", "b53b36af02dcc4b1b2638299a40c8355c5620d715b0594d602917afffb20f6b995911955369ecb9457a08ce4c3f27f52583df4621052de19fa0c811fe35a91bc");
            result.Add("rm", "18bd596ecc9c8ebef81ed93681be2ab75d08e151a55d5d78ca38a9a7804607ca45f8a6d7cef7f33a29914cdb20973ae63124034984cceade87a400e3e1e024ef");
            result.Add("ro", "f4da92154d3b4763b01682644a5c9f3ee62442ce767f03b697977826f8df87045020536a9ae9b6ffda354643bf8cc19a0ab7d74cd9e968d817376635e75f9c47");
            result.Add("ru", "b2beff0aad3aa0a4ff4ca2d28ada8db448c8b24eca45dd9001abd6f2a7c45df1c11e49058a19ad7ebabdbfd1e95fdbaf701f39d572d50f57180d89d9f2e335ff");
            result.Add("si", "91b26f20b17564a9908347f44ec740162473f5b54a1fcc6441d7f548d1abcf9c83a2773236c6bd9b1d5b3f6068d8aaef227517959ee1296d4b8e21703445f919");
            result.Add("sk", "4cb0f8e6e63120229cfbf93a96f6041cc639d9887d9ab65542c37b07fa7aa967a5a17ab0650c709fe5f26dbbe4255b7faef5c2034919ffa658bf7f10475657db");
            result.Add("sl", "b8ae329e7abd4189a5cc659fc1601d88c5f9931bc53df5ce01c57e3ef683670b69db45b3e631e546e4ead929f48b56a3fcde28cabcdb8d64c5e913c75f2b361c");
            result.Add("son", "ecef9bbd040a875517b6c236c13beb1b9df7db67b9f5593643fe10b6a931f7cfcea0187a627fb36096389401b9acf2b3411ec6c7a0f43e500dfe351058c2dd4a");
            result.Add("sq", "f519ef3695c381c0b58b0bef446c6e9c1dc8d239f4c9baa60450578216937941eba080264400888c5634c61811c1a242d9706dbd2d1e276fccfb81b5edb57c90");
            result.Add("sr", "b71294d28214983c891bc7f3443f9f43f5fe10a33fd3e4459598b5686c4ffdfc24856781cfa615dcdf114247e61199674f7f000a8b60e8e140e6f5d40d8146c4");
            result.Add("sv-SE", "d970bdd2a39c439aae6f1acfa64aa049fce9a97e18782eb3022e75acd5af8f476446992995b8d1f97b88b87aa625e21eacc0c15795dbd48e0f5428a3c128c0b6");
            result.Add("ta", "4eebc8a572ffe30912e3d563167638979452fe8b3907324fe4013ca780c98374a5775f4359d82110cb38bf849a949cb6812edd0f07cca7dd845cd7b43966cbbd");
            result.Add("te", "96447f54d14e7999b8317dc9ce07f49f8c9d577dd89aa0ac3b66860415fe59cf553e3bf3e1141b65ffb482d2edd807d5b11c1e9536da7e697865a331a7f51b87");
            result.Add("th", "b609232ebd4371bae26c1862b87d204b521fa157711402d63e26805dcc7f4726829cf8fa500ec4c67d38132c9ebc249ea8962649502b738d111b85d555371075");
            result.Add("tr", "77a4193b50dfc70e737a638125028e015a6b97afa14a73d190e11ddd03e74754c73b0d2633e75b594cb6afd82e97de87ffa4798d89cf094bae6fe83e68632664");
            result.Add("uk", "deffc21280f75dbe199213924989414deb6692d9fd9f8954f9821827d2b26ba438e766ef4998db054c62a5e4243e33153842659780f2ee61f90099db6841b5ef");
            result.Add("ur", "7345e822ca3cb6b3680a677201001e62dafdfc787174a8034b1bedc1a4a464b95fae6b96bbdf2accfc07a154ee352d766c73b84233aacfc55f64e7a05dea90ea");
            result.Add("uz", "3e8b96d1dce5a4d4ce66e32c12b30ae761b963b2a5df058954e1326fcf315deeac4a5ff897d9266fd3936cb1f6e676176a9d2378cded6578d81ff3bc939f647c");
            result.Add("vi", "313cfcecb96cb195d89c734724cf88af0a651a62b740ce836745026399e4fd263ba63c45332f7c5ce422255989ade0f5150db097699010e2409249e7426361fc");
            result.Add("xh", "144588c929f265b10554d1bb2f341de3726b6b17b2ecf24e81cd1fb504e97648537cfb9760904686bac410c34954a44ad7a2b17454ad4398568539b818346efa");
            result.Add("zh-CN", "377d6269b4eef6fd2d5b94f29d9e21f985c83421d5385b44874b6d176629ec6236746b5c5f6e77c4168df9d0678981a08be654ba2c5e0db62ad45bae883fd2d6");
            result.Add("zh-TW", "decfd2f467db5b58a4c78f7631962e829f26f22c0dc8696f24ebc307399e384548b15f6d0f597218c63e9e8432c087855efbdb9ea75655a9bed1906302dd9fbf");

            return result;
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
            const string knownVersion = "60.2.1";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    publisherX509,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    publisherX509,
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
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
        /// the application cannot be update while it is running.
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
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
        /// language code for the Firefox ESR version
        /// </summary>
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } // class
} // namespace
