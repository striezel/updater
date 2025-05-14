﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/138.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c419e3f6efbbfd3d7da7c47de8e1510c5ff6dd98466be6697d5f8c637c43cae1952d13087541c35ef9b3f9c09bcc45543b7b2b47ab35a0de7baa77205eb1400c" },
                { "af", "dffeb7b12f0182ef88343921889e4a3fd89741bd6143acbfc3727f542bfcf8b3bb4e244df9585e6c0b7469b2fc4b557a314d2fe175756f932da762a74328d148" },
                { "an", "1e7da1966e932a0ecdf252a89fb31b804d941924ad057e054667eaf13508e0ee1e89d5a618861c99f5c9c0f5ec5c384c2671fdfc14b8c92645e598ee2dfd6271" },
                { "ar", "c7ef76a809e6bdc667767a5acf713ea13f22675ec89776d99a90a84361fde1aa20b8d8db6b60e3ce856e6e9774a6050e504eec49368e2bb6b9fb6ce644be613e" },
                { "ast", "2f7b2fb9edd2914ac8cc479b0efb0b84f94df8903a90dc99dc2ae0b7cd3310b9361d4cdfae2e5b8228f3ff62630ae7682c385536b79cf5e5183c3b6179f70de3" },
                { "az", "3ac54e85d737c3bb24bbfd51038b6a8295e1f39523d747e669b66897c1ef20c1464797f4da0a654e071f45c3d5577b095a1ed76d8ac70accf1c018d25a6ca3c8" },
                { "be", "5dcdb69a57e7c7fea9ad587212a9434e88a00b5abbf64a4573aaba77bd63558a5c12f3fa5acaaa3ff118e402df9386819a694c6ed58e4e4fb6a7f4eef1d4d6cb" },
                { "bg", "cdf04141ae885dffd9f6f531db4435020f57defb85c51e7ea07d6defcb9bc046525aff8e95043b4c321fdd8d62d3ffbca3ecb9bafa25b2f439166d28cc0dba19" },
                { "bn", "aefa1a2add6d8f30f5a6a799208fd4da328d27ea3209c05d9a315208e4ba5b481faa8ea0ea75fd753ab582d82157fd6e724a4e5ca35ebb4b433508dd4d11a381" },
                { "br", "118863793a99a474d1597bae01146c2edc82539a6b6871eda1204955391a8c075093fe3006b35423418dc4df76120370e5519d591f0185096e5a0fa6df13a72f" },
                { "bs", "c78670d9378d58cbbf4d52a634d37956231cf124de27edd40003a3f14ac0fb6eba1928fd01a52ee6bf05afdeb329fba9462355435eb5f6b1960f333658b53609" },
                { "ca", "59b8ec6c4792b56303e3bfc9547b2ba1ef31a76a70fed633873aeaa50fb526bec9e8d62a147ed7b696af234799ae6b8780ef98ecfa4e6f7b2c0830fed47a3eb5" },
                { "cak", "c458b735cac1b69bface120ca3046637080ec5e46b33ffb7c80983c70c5fc858bedeb7a8e03823973562e172ffd9737f70d2c70462bd0223d1e8c6fe9c1ac276" },
                { "cs", "f8d933038d4610fdde11b1f1deeaf2f4f6ad938154b9df14a88a5a44cf873ce1a08f2c02f64e99fe3a498d9361d2ffd090794adb42c6d5e279fb53b02fcb40ac" },
                { "cy", "d20f2fb709e3ab3e95b64001733bd51f2bfb034423be567a07c47418d2e73fbf3bac1e19a8e5bcd2cf4f2bfce6f4d5b2d4968a3d9f4259cef778fce642cad029" },
                { "da", "4ba92479080d5b396cdf48a99442d4b2097d6744b52e1b02bec96de6c94a02bf7345c77fe5810f1381de6cc335218f08b5355ab7e57477d4de00b7a877204164" },
                { "de", "6058254f15a9b85011f87f8ea9fb7f64b3d82b3af36bd0396b09eef01d610c65cc63df33d70ef8ad4cc4c6204d4a47de552f0f63b19e5f9405c8458cf154ccdb" },
                { "dsb", "5aa996e6a124cb248896980ed735b7db1ba57dfdd0988d4a6a76de1f79ff87414c34016c7cc91344ca4e03261d72c5e1e8d9474c5f01f44ab5e97fd4b6c20de3" },
                { "el", "5dec5ee7c618c9e239b810e2c39de82209e505c5f850f0db0767cb6bc964a39281397d70babe8cb697c0b1469cbc39e98121e608a6720982b962f946546ec3b1" },
                { "en-CA", "3cbd441c98f79ba14087f98ddc45b01fa50d89b88b47f7d825cd3399256d4d3eca662f1f13a78ab54c8407b1b4fec030d83032aed8a546210d866f4538a255d3" },
                { "en-GB", "86276781adc1c840ec0fbcd5147f46ef2960987086ea2d114b4b490c22e92994d8cada09763d5c21572bdc92f7dafd30775025a4f93f2d109bcc0de12c043078" },
                { "en-US", "9569d919e3014a1182e91c87b3ea713829e158010d8433782d0e9389e9b219334eeda5ec1917a7b2e8bc51fb7c8b8c3de00a65e6014343e5b81b984be8f6310c" },
                { "eo", "7fef05fccca24249e2a59a29ef4dc3d2fa3e7bc7960928d21e6a4021ad46a50a66ff5f00f5ee52fa217590a176bc1bffad29971b11fa0533fcdf281e9f890034" },
                { "es-AR", "afaadb561722ceb97dcf2f4af723c5d69755b53c5e5ba1be2a3c83a2489fae76847653c6e7a15fedc4c09670517c70f8837a6b0b8deb1275cfe3bb9e383fb26d" },
                { "es-CL", "40e582b138a36f2994dee167282ac17962e807554b9b64ac5c6224fcab11440b707dbe4fc3c913646ba132c4790c40bb14f22696a0431e459c5bc9ebfb423726" },
                { "es-ES", "a31b0c5b86b8d7d527032c0f0299c1928a759c9c1ea9d2ed8c4621a63875d5b3f95cc748a7ec4163432a57a01e34fed2ba38c424e7c39fec6bf45612f79ba87a" },
                { "es-MX", "20a655cea1a72582ff15aa9f80401bcaa98571e878421e33d4c624bd82ff911c5e7b730a799e28ed9c343a3a1b01816ee04c702e9fc1a6553ffd1a7e002620ee" },
                { "et", "cc61f8cbdce3d02cd386ec424a246050e610f68b0785e1a24d19abecc6a97ecbb9a19f188191a1d616d2b624fb80d7f780716c309ef54d24bf308e0d56004028" },
                { "eu", "157fd081ab4312e8efc5b3ac8218e8f7cd29761828e143bb8813a624519552973c85e1838011d1ecc65ea7d68861a346a7636fc00c3a3e7c3bf36ef7b4d1153a" },
                { "fa", "729ae8812cb4afdbb04c70407edf6fae4c2163290ddab1b07e1cd83b72c95310c8ba24d2c94dfdaa3d613268542e463a3271813c484dadc557eab7743f7739e5" },
                { "ff", "4f4c2bd13339a328cc61aad2b0c2fae610b6f0da5b7f39c20e2d065c4e1afd55460ad8cf2504f8a287d698320a425b252a25e75fd4f9542132ce51acdff3d76e" },
                { "fi", "6bac25f34227200688e165182a5bf104711cc21ac6f07a5638e73db817d189655f7b2f0933f85dd28c92f18396685d9a2f5b748e8790140fb9540c56bbf663f3" },
                { "fr", "84d0043dc2791bf50b0b847a6d5b4253a9cac9950054ae6e91cda3c71be799026aeec75515701e6b1b214b20604fa3a1240b55478409c7ba02723c31cb3e8c80" },
                { "fur", "002eed22788c57a6b10304410260c8d26e3d81aa6ed47bf5d0f35ee3b2cedbeccfbaf547352441473e83ff5c24d4ec38ccc3f5b97851551e92f09500563cfa39" },
                { "fy-NL", "ae2f4c997b5c3ff0db2f5a5a50d8079d3b45579fe41a11e6f9a1c797ea6cf7c5fd65b57325901a7b73303052432a1dc58be65e94eb23fd3e8d1b28edaf58d6cb" },
                { "ga-IE", "ff39af6c1a31c915c8c1e1b6154306b781b748d30ef52306d3bba51d51e5d7fe5b1a442acbedeaa5487dea74b16396927c29365735e5254027b9a020b3853dce" },
                { "gd", "20bd5fcd77b083012798b54be5394d2204c75f10ef66b8c08c54246fc401b29735ef4f46a545e8de7c5232beef849ec80d4bceb5748f085d02f6df30feba226b" },
                { "gl", "6956f80791dccfa4c43b40651747a69fdf031120596864876c1cdab252f3339e0c1811ba084bde7f4b0f30aeb6a165ee94c263eaf9888e3d54f3027a9b441f91" },
                { "gn", "70b32fc582b1303f4eb6ca55169af6d1059f63989e2171a1f9a362862e145e8b8b0a8968cc4152029856ca0b3b6a857868ff719170ea06152fccc03e24b69fbc" },
                { "gu-IN", "40b2176ef071b0010ccf9abae86af54adb4cad8184e80f97c0db5ac7fbc7c3671047edd7e9c93296ae9c8c0f0713e1f4967d5421b12e64fb4dff101935ecb67b" },
                { "he", "ffeef8f0c4a1fb2e54a289e721a420e68744d129108ea318a78fe352686d4dadf78c7e55adbd92a63332b15993fce754c70bfe8d43984f5e01fa2395df3e40f4" },
                { "hi-IN", "cd3f7d36beb5ac83a93844782021dbbc9028e29e0dfcdb112968f4dc8f49becf150c2171e7cc9adeacb7c38fd300da8c750f55d68d73ff804ca219460f3e27e0" },
                { "hr", "9382a8abf83201f8a565423301293216a8b688663f39f44b61a32fb3a56b6029478ff27c7495951f3452748bacac22899896023a3301ac1eebc43baba102efdb" },
                { "hsb", "b10145ef64a2a3266cc927a921c0d60c8ad269536fd10079c7a6be10e64d95d6f430d1c9647182527c29d4cc14c7650ba146505f9320681835ba200c9edeb08d" },
                { "hu", "7c582382fef7702dd69215153fc00f32fb00abd75231ff3dee3410110305db05237efc282184142bd179ea0be5881e527aeea04a26569024034bd61d9b975e7d" },
                { "hy-AM", "928b4fe9a034d0227bf4f15087ca009ccf0a2d48352733ef975b04fd47222835814eb6996fda71b843dadef3d88b740c1c82972943e8a7e7558afec57c279716" },
                { "ia", "1b0456e1585d262eb0cd85af2db21e697e0f850cd1daa6098e1a747a32e84c612804747c3cdf0f659b26213170f9ca4b1d87217e038663010bea4a688567eeac" },
                { "id", "4123d06ef08f9e3cbdba4b170b95d4c0277e9dc39415bcb2aa11a2b52061760caeea0b00a8a73d40f3aa43a77e5e1d2107451a00783042bdeda22ace75f7532c" },
                { "is", "ef743a99119aaf159936c08648c1a355fbd2cb61b97db966f1e252beb73bccc210d73df62e6f3ddd8194595ea9016e25a4619200ebd5eacca272dc7f685798ae" },
                { "it", "792d48175e7cb72b44976e3075a76a430f48ee39990ef79c6cf3729adc3db5f50666211723449452c5231c9692ebf4f48e3680dec03e9f46cf0f8da7324b9701" },
                { "ja", "b3144950f79091da40358885305a6862b5d692183a140e2d1635786b94244460eec78e4b3b96a0cf3f1fcd5304f9ff3ebdc70b4c5a203f625d50d5707f733f6b" },
                { "ka", "cb1c9db89597d9fc78d6a3d08997b67dbba066bc72a8d2921471ceb2b69e538e149521b6bd57ee95d346f8c11fd89f166885f1f7bfcf8069c21a36e7971eaed6" },
                { "kab", "788dfdfb7e408467eb42459eaf26463bb72ebeb69cf7e9b609fe842ddd7b776fe43959974d84fd5ca644c1a3c9f10de3775af7f8b618e2edd150020636704141" },
                { "kk", "a75e84aec15ae209458354a703a8e5a0309d7790076fc68d0d14fe4782fd34268d64ff709d6fc2805b1133a3189a521252f1ef33b014b2242b0069fd68bd5163" },
                { "km", "904854f3bc9de86d747a955aecd7cda70772eb74b4edf00e28e34d933ca285878e3783d99c83925392a9c7c80c8372c9700c65667a7c0ba278e83ff06d365ace" },
                { "kn", "bb32251200c6ff9d34660c4b89a5d1b5d886894a4ea97a23af4f120037430aa3035cd1ddb5d8666f0b887f8a7f9fcc39aa624d5f6a18c347bc961115504afbfc" },
                { "ko", "dca56d81b8df75871799122eda10ce53e1aacbe4067a837d6c6f6363ed7a6362a639967ca002613707a20f1eacd501bfa56dcc8ef7497fcf8ff257b0e8452e29" },
                { "lij", "4330113b7fd475512b42ef31e10e325e0d7e8a8efd3ee3b8315d0b720e99685113841636fffaaab2ea79c792dcc3fceceb3af6834f008b4c470112aaa63160ec" },
                { "lt", "12d7f5132511e58359647f2c6139fc56672e25bb98e1607079bef2fed2574a1f55e2ccf1af77b90b737547164b61f1dbc163933f50ebee69bba6832547702f9e" },
                { "lv", "400cc3eca356c99c5e91dfe352052a123c1f16745febea1f6f2ddaaed633504ad64c058123a47006e15644443993e372ad500e1962e03ab9120c3846afdfc142" },
                { "mk", "362ef4c0333a97d366ebcb195e8779473393f85828171245a292ac27f1a1cde80e2791622d61ebf9bf5f8d4d5c88f5bdefad4d7adea07c9fe97c351dd3699b74" },
                { "mr", "116aeb6741ca95ca2fe9b69b64f1204911434b65be74a61d453b2096265a9dfbfcfe764fe40bdbd2d603e6206a469d5ebc4a9ea65539afcf5d7c469ddee840f6" },
                { "ms", "eb4636daafa95bbd49db7835fcf056ded718125a2a1d47e4f9669945e4f51fd30df60f3825e6918dcc2bff471cee3bebaae5b38166e86d474f4f6fe6115a3070" },
                { "my", "7393e7f4ff5e002244612719de7c1fa2026377589dcfba11092b4fd89fd45dd3150bb857d17668ec5a67c7510e7fc018b47629fe382f5b2f68c82b7edfada044" },
                { "nb-NO", "a1742759a74fd2bf12b6772125c7ff1c8bb8fe3bddd0899482d78048387676ebe2f9dfdaf5bed898f187ab64b71698368566ddd78e611e19951a466c2ec3032c" },
                { "ne-NP", "b0aaf3a45ac29969c6e33ab0d330557400fc92c8ab5b561e2b1dd06f6d6c832c5f6a8618e93c7dd86d58495592e2ff8fda70bdc26f4b767ab4cbade7b82b2e08" },
                { "nl", "d8035621aa8c541b2c783eb7f343f284776d7ef37d59bfd09b5762e16d56ce0d92bf115b7cb92488a888abd074a402610028f981a18fa2538bfe4988146a72a4" },
                { "nn-NO", "11ae8abf8d82429cfbc6923f777b159b133f38d3a731153528003096cddccdfcb47200039d6c6553dbc4304d3ffa73fbbea32f210530b7b9c806fcddd25a8bd5" },
                { "oc", "a2ed94877741fb8dbeb9282b89fe1414e570634950a4b2b2aa78644911c13ec00f9846d7f20a1e18967d0e0065a055d2a84e97d7cf625e69b680e281e8ac8ff1" },
                { "pa-IN", "e0ad431011fd5ff0228a70aca16f11ca5bfb2112eab1a6b04e7f95c06d62a28b098432587a7973d2376a44df0e85be239d8388fde725bd7ddae646dc9cc509fe" },
                { "pl", "cda1bb65e98637980e30d34da731f9430568172299bf404e0af127bf78dcca82180c5e7eb406bffcf0f0eaad804cc9d9912279de3c42c47c128e3b690ce91471" },
                { "pt-BR", "679a5b542549289520c460fe9800fbc71cb1397f9f79d3fa9006004f7fca97a1f40e95e35ef919262456cfd0961bd99df492938e130ec169bf3bdbefdaed5da6" },
                { "pt-PT", "cc1a7682f4a90531d52a13678d2b90598d7b06411a6b439686fd2e8811befcdf91ba35b6af21f09ce4b11cc0adcac85413e3633062d607b2ae86a80c4d749ba7" },
                { "rm", "047e7d5db4c1b21143fca8060c1b7ccdf2afd821921ee39f9be72359e2705846345c773ecfeedeaef6dae6d02344afc6f113b1df6392ec1c3bbdac76afa67830" },
                { "ro", "12e2bfef0323bd942f721ea1899efbbf3f51a0b136aded988926d8d3418bd2868f524af73c230c74b9a1002e581f744d8f54c48b4805cbb17d0037669c6ae0a9" },
                { "ru", "5f113dbb09e7af1c184f3a99ca1316dbbe396d3645d83e94b6332ffb36fa63885cfa44ed93ece14a736c9892c552a5f7fd9110d7d012af366c815337e14a8cc0" },
                { "sat", "c2d92c1bae2122ea14b7ac0c4f6355608afac72d560d4e0d0ddd06e6a7bd96124a1b7fd5da666e1a9381db87e15fa0de1da0cd428b29770b06f1a8f07e79e0f9" },
                { "sc", "f870a1e35dc720b8f41ab785035d4accecc48f202265f10ca146febea800e5615c8be33001baf558e2dcd8439344a6e29c090020eacc33f75a9e4d5343b0625c" },
                { "sco", "7828d358237cf67585fda482be7fd8479d5f1cf5439286501837a900a0277ef392cb22641e28ce515381919d6043a1fa7e6073b7877a96e5ddff9129a78d2c82" },
                { "si", "490c519319d499acff78c5a40f28c358fef899bbfdaa070964050bcbfa641a36eec29bbe890d3c7eadada83758ac1530d65aeb7261d854195e254dae3c41f4f9" },
                { "sk", "a93b33844529d53e54b4b441a9d1dc6f84fe0e0a4d2017787a19329c49e7c801476c27b174e03b9b020e94de24ca8cfe67d8cfdf632d7bca7dd987fe1359bdd2" },
                { "skr", "1e3e6b8d1bee42b2182009cd52779bb686008a667def978b688282d28e5c1287bbc15a8550cf2eb3e293121cde24d2a80be42c4fc99cadda775f60748840ebb3" },
                { "sl", "de5c9cb4233548787bc109e094d3c5146fd9f71a39c0765ce10c9a3f7e3188f99a317c114129553bbe7504aac10d7e3ab882f72e309e028c2f712294bd343e31" },
                { "son", "f692f5b4f133aec0d1f6bdeb88646cb13f2acd8021cde1fb2a7452c05eaf346fa0f91d09c6bac95f2ce30d2f862a74db24f2785d434dc5da367b73686b2d0b92" },
                { "sq", "4bcf807ecd76deeefa8a3441569b058aba5044249ddd5cacecfca3b3b2efc4527a52e0d827bc531457a41b026c203b50ed6b967fd940456a88021b05d3e32ffb" },
                { "sr", "bc354642ba2857f871651ac425746c0ea7e4bdb7fc162d843be07a5c9f8da9787e9884c85bfc12210384a82be4783ed29020c0c6f36a4a61b255b1fbd18bf3c0" },
                { "sv-SE", "70390202e338f11ddf710aeb25b0780077afcdfaf1d65a9a1f14b734813a55176b3dc6d91038405ce7158bf5deb71f25b121131973f242b9b415b8cb6fdb017f" },
                { "szl", "c5a4da8286ecb7d2cf499c89be8369738280133db7e0c90ed4cb24669489ba48609ffc5603c8057479f421a262c7caa86e8a0e905ae3e310246803ab90d0906d" },
                { "ta", "2c4cbe71ec062638c15737264f7bffc6f1454bdafc3e38060052074ba35e431004eab16a358c2177fc34df57c2fdfa2dad0d3c38a5a2e230a93d2eb0af4d0608" },
                { "te", "b571cb39409a93885ac7a787cf134b6dd85d100f330a0b52baec1c1d31745c76c29b4771df00f9859c51e46509c2db3e1ba096653033835018fc641c9e8e8a0d" },
                { "tg", "44fdadc31e5987d16d11a73bfb6097f8a1c0cd877a743d170682367097e7bac846ba5dd87426229c91e4bf3cf047492e71cd0abe48c03fd9027e2582b7b3f43b" },
                { "th", "0b5a3ef46c93985f76ffe8a68b656971428eb6c09faa720e465483910a5a8709c5a270d86281a4ba62ff373e1c1d369bd5720f270b474582a4903d788f81930e" },
                { "tl", "bbf2bc4e156cdd0bac0fc658fed2da98b964f74087bd47561125e40760100d51d2d9288385c5b00ef2485f64c87ee58b286b8491b551a10ef3228a0e84c91d55" },
                { "tr", "aaef78805a0f9ee7475ca6ce341e7ce4a1c7b0a75c99a0a48ca816c54ba4ddc0a9c5f4e4aea1eb917d4f0c7ac3ad3e3173f982a7a85b6e0a53bdeeb414c011ba" },
                { "trs", "dbb327097e03328c072e6fcb9351c5d2268ac0d1a95e86797351497fad60e2bd083fe5b822ed43280229860f7d8c3091941235c7691e2c37ce17b528236d1a76" },
                { "uk", "39edf9495ea1d47228ed803b71cf1023267a54b266c2f0651ea55ef93b63a27fe39bbb121f76a74a4ca954e3bfcdbbec5a023d6619ef125e715f763ff4179d76" },
                { "ur", "1bdb01daddf9779a8edb321179b293a7359a231e4a8ab3e1cec42b6c4838a0b7c9a6040c81c4dec24c2b72d6cfe92ef25a81a33e25773b96e7ddd03142ffad9c" },
                { "uz", "5a53e599dc9ec7ee313353194db757a34f43ae43866aa96c2e1231f74eac5888d29526d440e500e69871737aef0dd5b685e98d9f5b449d61198bdf817039ff4d" },
                { "vi", "7c04c34b4f3f35385c941839d9989965a4203e94c0cd0b29c726f1f8bf691881b8d05fce80f4df319572ff9da8f5e431345ea8be81a2b89428de97fbacf553f9" },
                { "xh", "c0197ea917304580660b57f06efc9b8f7a5b9142f041d189b5ddfa26eeba395f7d0fdc67805dbfc59dfd23187e7bbabb4e4af6fd03865a72133204207aabd2ac" },
                { "zh-CN", "145cd677f46d7d911df12ed7ec9a9cd966940f1aba3c88fde2e6497cfd97988f00fa34b8eb82361166d3e8d418ce24a4afdc0b2ee7147589d4dc978f9e7aeacc" },
                { "zh-TW", "64da6fc27af934170a80bba23d3b2d5c39ae37c9d8df5fe9597cb585e0e4d99c50dc1bb93cf0397c130e9daef71a3c1f32992739329547fb0b28c134907d3763" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/138.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e4660d00225b04d1cc190a226c653a164e65b71549b0b2524d084eed74fe74ab5ad14850e367e4667acfa48f7b3f63573f317944224a2475665b91e1f4cfffdf" },
                { "af", "66f724fd005fde6f13a5ccbeb38e299b42965ab9fb5939809182d902eab2dc33be649d375d7a88e991b4d98d03eff4b7113b3c425db67e0f756fd2843f1eb2b6" },
                { "an", "dbaaafd644e891a55a6cf1db9e2e5728054b063414fcdf2d356fed42d4d72766e5edf0336db8d8ca9a80f10e1ec59de2f73d56f729094036c51c7e8a4deb1ea5" },
                { "ar", "c3beaf1ef83b571b1e6a83cd445865901e835afc89129eff1fae370654132dc03fef4c4ce4214d5538449407f0eaf43025c6bb51999830eed2d0b53764a3cf1c" },
                { "ast", "d31c100c86c0e42300f0b3207c21c036dcd0a32f44988ef7b197a68b92d99373ee24a448530101508d5eaecdfbbfc0034bc147fcb0e9fb30971416910839e4e9" },
                { "az", "5a94dfa1b45f63ab12ed1c42be61034afe87aec34271dd66f8744c66f2e99e56f0ecf9797aafeaef0ee4a78a29b79ea5d9fd945545348b5c2c540f5fbb4e38fa" },
                { "be", "8cfc36283235e4b1b6e1d636b3becd5103a3e92e061fc7ce6f324f2642854f9328fb1af2d42340c02b5a9259f57d30037a57a9af780d6591467c3bd12e4877f8" },
                { "bg", "853e42d94649bcd6455b6b22e77b27b9701a64e94f9f2a256ca6e6d20253f56a954081acda865cc8e0818e6a83d04399962115fca456ad3fe5fff61f413cfdfe" },
                { "bn", "193e6950d22877b6272c2611bd74f7684fc32e7a6ce171a9da29a669f54be6c2402b53912650e2d89fec9ed0551464bbea58ad017820f7a7e61545a6673df038" },
                { "br", "0d826c37dcdb50dc8b20043574f37ef4e27c0f9231732d498e7972d12536f68e46b3909c1fa7dd0a1eaa3333b025ad8f01fbf64e58079711b775f16fea334b48" },
                { "bs", "654030e5dfd3c863f2c15612641463229e555fa8bafcd1f32da2c5b8ef4b2e50bb47042fee0f8d5d34e4a040a6b97fa5981f3c8b54378aa2033e495fb7f3ac1d" },
                { "ca", "f3e6fb2584aa683ff71d7819b44caa656cb0ef72bfb9eb74ff5e90cdd646cf86ec517e1326b3d9bf6d8e7ba4ed6d3b8caa56d5e89512ebe2d4c6bc692243a839" },
                { "cak", "7b0208890d5977eca94fda5898bdd7f5b8a03674cf53b45a56d28d49de072e7923b24490463e162153c0a5cae48d7bd9180b97e0dc828414b9a86f317a175689" },
                { "cs", "df9b83f134ab5cf04d2518c8dafaeb033eb8136a8b55f780ab1bc17b8f210ac865e71c987831c78e8814315d3b4b6f3c192f5c2a8b1dc9963a72a92d25d14cb0" },
                { "cy", "016a0dddd26220481af5061e2915e4c606807d97cd8eae9c5e2c4c4efb304ce126084ec9c0662946d1237954a10d7675c2c1c655114b6d6cbbcfb175f1e6b682" },
                { "da", "221dd74b53b1bc642267463cce6cd1eafece2f6e702a7506b703bb44f08589b5a4af0b72d49c3b254400d000bb46a7f03941204c5adfc6b35f881c349d689db3" },
                { "de", "c37731b750f468a7d2598ba68bf6b8fe95d50a990b250dc69a0d9dc1576fbb8ed864fcbd9d58fc53e45430999bc7d3d97c5e63e1b0ecc4ebd57c67417dc24d22" },
                { "dsb", "3e67e0ff48895194c42dc0799c634e2f6d95c9b1b87fb330f5d6ecede32c19da50f0b5efb6eeb272a9774b92c41f5f17bdc2b1b3620f3b739d647d84d1211432" },
                { "el", "488ac8007bbc78d60af6f34d4ba8fb65a14f2610f9a06bb7cf0edc878126ee570fcf6e12ae7c2e96403020742cec154d3de7ef747a6c510bd562440ae23c0a99" },
                { "en-CA", "894be1fdfdf92d4869628555572f8d41da0a59cd19dc6b92407b4e73478e3ec69c3d8e09517e0d2366710031946e2c44939f6f5e6b38560ba352f109ddb4c662" },
                { "en-GB", "ce3c9fc9dbcf29f58c5d353d51f5a8774d995f6847f8179d2c0b68128f74829fb89dec85f464bb66dc653e113296ee4135fd99f0d4c9f56849aecdf8c57e8b75" },
                { "en-US", "f88160a72ea93849a91d57b051f12d8efb10574bf7caa9e0f64d70e5b1d728d83031feb07e0d1f2ac06aef09fa5835ee0446f2991eb5e9f65eba208e76736d0e" },
                { "eo", "5b2d3ee234bb2aa10cfa5e9ee26feed3f4c31cfbac54e568ceec1d6b52c21a342b579a5cd6b51adefd3bb925462fb1e02a0b3bd70c6f04401d52fb7a477ef95e" },
                { "es-AR", "522882a23535c496df5d81a54c328479e1b1b6b14a4c37acd19821ad556dea53673ab3f13be1a62e1e6bdf6886c1c86e2bb90119d2da55deb303176b68daf237" },
                { "es-CL", "0df734050613f6182ebc21882cac3560d171b2d79d5690e2ea86808300afcb0a2e295f10e41a23dc7406be0117fd2fbca27f8ecf8c423e82749d3ed0b7d385a3" },
                { "es-ES", "fe369be36bf2fcb034ded0374fdc6167b3838fd04666c67b2cab254a426b74c459f83a77df20b794eb650b5b3998cb5fa43af531bf9b1e0b7e994010b97f7c0f" },
                { "es-MX", "d7fd46ae36b8c5deb4bd4d143284b7b8b6d0bcc59d7042198fea722ee6cc8a0032febb44f26412d5c22fc52861798aae1680dd21fc7b29d02cb4f2b2ac259850" },
                { "et", "abdd06b788347654b777950581274923ff6e586fff63a441910902418857ca9ea868b6eec2cbf575b870bc7a12ad3bc3dad58ab50e2bdbaafaafe06d4c63f511" },
                { "eu", "fce6a4d66ae8a08e3ef244eb9a39d70902604553090b3ccc2cc695349b370d2f2d4a06d4715361ccc5fb526bf1c1e5fd20f2f0f05f9a27dcbcf61f8880816ef6" },
                { "fa", "0da71981c1a6ae8194daabe2f83859ff2f40300815ece917aa127d6a3bbc389f41ea7215563499a328ac2e79e7b825362824d8ebc63f8d8bb0bc99da5c96421f" },
                { "ff", "fd95e1a6263236dba932d0070343f9ed4cab3cbdb2f5217f082670f6f1ad6e9965cb4e55ac9726bbf176758b8088ccacec5e070e06419dab660d156d8cd7c875" },
                { "fi", "8b56033775e4290ea213f780c492268c6529068e0e1d80fca1f4caabe4e5cad2b15c1d6cdcd9408d0031677b4e26ed4e0f3fbd4a690fafe9458cd8797619893e" },
                { "fr", "1cad8dfd84051a372a6b85f963bb3858ed418c1504bdf5ee46ac0864830d88bea9d7e41eb2510d775d3dc827ef0196338464ac885856f99417b1c07b895d542b" },
                { "fur", "37aef596daf93730124601a0bc548ae4de2016d02b7447f8b301dd16d533e36e14ee95b551382142767d656a0f7f6e968468a7cf6858ab76dc0ed062b6ccbacd" },
                { "fy-NL", "b9d5fc6a67938636ecebad8b1e36c0329686974608b6f72c7228c451280f0008ecd03d5c554e2b411ad4dcd69915711b09df0e1ff29c0867edf6842964332984" },
                { "ga-IE", "368ef7647c7ecee91648eb1aef60c9b0bdcba9f27b95ec4f42266da49137f310d28895ed7c65f6ff48dcbf5a31273d736a9a7f47ae342cd5182b2f2c36b4f865" },
                { "gd", "5d8bb51cd167a45e7ed64f0143b838b28d27b96d0b3a17e43a17851ea464e8e4ceb64a2ae6b37977e71a4b2d02443b90c25e57c41ad58a28441978f62332b3ca" },
                { "gl", "2f7a1dac265b382c6798ef3b073c189416d9ca70daa02b0360da84d5473b9969add1eda5a44984b41efe9f95e5c67ed6a18825719eb38b49cd03c541ccea5dc2" },
                { "gn", "2c06be8f96a5637fbd3ed9da1d4f08dc62395a2a80c603d27940c329caf669fe9c35abad8889053d35e3eef80b0d8a726fb9e749d3803b6f12fe2357750082f0" },
                { "gu-IN", "e95ff38b8f12bf438cf5e6d882b624d8f83dc44e0029b8f554da6808a9643f272dde4c3a1bf6a8739c34b680f24059964ed3933eb4e49f5fcf80be2e1d0f77f2" },
                { "he", "3433dce0440e8316820e9e65702d352dfe0e83385bca85e58eca6fab9a50b53960e4d96c32a18c9cbd66e00fd8f4f92106c0cb259d1108d7158dada7e7046df7" },
                { "hi-IN", "e1d2770f5431d326376524f707605e1870879afad79cc9a9d67d54dad5e06c809dfafd5fb690dc6a1221511c3a33e7c47f9c3df2e521c757e7b4c6aff0c2c557" },
                { "hr", "39ba4a206c9a957332c4082aec6fd89fb615da9bee432e9c3ed7c7269ce3b708cdf83abc5449a2c45b2101edd1af75ccb0455f7b3a8a256c06040744a8937c3d" },
                { "hsb", "bdf9eb9ab59406e9b87e375363fe7665e194e9c476107f33a134094ce9da69f75f908e9ad7a4032c5a1721d6535255579497208a3039b9f82dc34c2ea2652836" },
                { "hu", "453dbe5faaf1fc72b7a5a51558cdceaef476c801008e1cdd4d6f2917afef5dbb1b79f881a2f4bcc96b940bf248fbfac802d5fee463a588230d89a409705b75a7" },
                { "hy-AM", "9a5166f461f83e990276b6bba68d3b4f8b182615f9f96c7f9a51c906e6363a7bab93c5e23b9a91a495a20426309b56ecf231ce871ff8138035b53d1fcb11b8b4" },
                { "ia", "8371e006355d934191afe3c64e642d0c7b3b038c791c75b806d8bdb723ad87833227cbbbc3dd2a7b73be4ccb10b427b4c950b736cc443c9e32c66a9a5bdf0359" },
                { "id", "666a6245bfde8a39db327fbf7654eb6e26a315cb086364e39dec0f3f3671a307275e2711bb03c6a5375418de6e0681a58fd69f1ed701e56de20769ccea8cb836" },
                { "is", "8f950aa7604d8150ac6d4a59ecf1b7439dea18055ff68023c3192282e95b5ccd77382a3ce343094f24ead0fa38bff87c2f1576d12b521fa3370298b33c45fb39" },
                { "it", "4dd79b9691336eab0a9ca108cd6338efbcab234b5b4da81d8a11e8088485db8a021433de528a34c2fa3fe1e6cd915462b099907acdd4004a04b0f812c25f8e73" },
                { "ja", "ef7b6a5cf74a87c34af033efae2270bde440e9690765e35c663bb8abc9fcbed0739f97838b8dc6a8df3a37640b09bf172f9a20bf265ff594cf957462febe85aa" },
                { "ka", "4c57f67128b5b34dc0935fd641c1c6fbb2e755533b5ce85ffeed82c4af97b4a4dca72ebbabdc51c8efda68a217d4719c12ad63b2e5087b58f265c2aa7dc413bb" },
                { "kab", "675990bc323678c09e4e1489b54fde49e2cfe517d17585705193f2f3a6b5aa02098898da78dad329914df822e4f8e72bd169a7e32d9204512ff6f4de0cd44aeb" },
                { "kk", "598acaba8353b89b0258dea8a5ff518904717f44d16011c05f93a4e577bfa0570e745ee065a15734dede7ef0cb024e57576b08249bafa9eb58ba0efcba3961ef" },
                { "km", "4a3fde4f201cc605f262b502aa07454115c5dda54fa5ae6fbaebdc09b4b436aaa236a26ab9142aa231f397dd4d802ad869396b17b8f7c364d138783688eaed8b" },
                { "kn", "7344c0e8bd735312e8e2d7ffafc556425c95b9ceed844fff170a0233dc77ace28c44e5523a37ab03d56dac7a6f6efb103b19d2eb5a514b6a568d604e427a6dc8" },
                { "ko", "e31c2a00dff46bf26ca2e46c9967251c474e83afaad1bc290d584efd6f8410bddd424318a1ecb8c69eefc6351259aa0fbec31421cb242219698bf0539c7b1a33" },
                { "lij", "642407d9239b459b79fad35b48e85a9eaba1d9aba97167075ece521022e3978cda474e17e0786cdb0576a60a9286ec96e71e6cd70b6bb6f64d708bbbbea1e3d2" },
                { "lt", "7092b2d1c208aa15cd14f17762444c9f2c4c005da4f84a08de59a27de04d6a00b4589c8703815d622e6d768470d18a574aa981e41e68870ebd35ed4266d48f11" },
                { "lv", "6a23129b9fddc056c5182155004647d80f88b4b02876881e03315612f63cea58786e8680c0ed7e229ec3abf0dd801f9c39768fd482f19046d31cd63b55fc5f4e" },
                { "mk", "375b7f97093d1168bab7fe4f94b0d3bb955720aa508b1f0db51c11eae40ce209c72bbd00a93ceccfc4db352c3513d1ff2b5bc6f91f4bcc497e902a1d39931663" },
                { "mr", "5e90c6fffb16577ff5abcb94ff1ee1c9ecb9ed6cebe1149ca7039705e948f553c945375d03021bc42e3b9b93b5d0f2f0fe1c02d0e0442f31b8f7f77697ef5164" },
                { "ms", "80a343089412910245f308f39a14d4d69583aa87af4c59d19fedfc8589cfc3d86094109083a0c99b650df6fea16ec89204d619a26d94bd33119092fff2ffd97a" },
                { "my", "e5f6efac13fb299818765781962674131f644d46d0598520a8c135aff1a7f1abeb49f2e5bb3d647f20eb76604536094e57969e66a5d8b18efa4e1560ba0131d4" },
                { "nb-NO", "abd4cef4b369d0e13b6389d6845caf814425d37971e32a144ec35e48b05d28b0845750ab54b40c630192e8902f22ccc5bbfe0a8adffadd0ce9a693b412145863" },
                { "ne-NP", "82e49f955954b74e4cd745e02a014140925d060793a458812cff4b7defc05991832452e0550bbe15782da7cd09d43a7f46a279903f4f605b79261fb0dcf6854f" },
                { "nl", "626fac4bace1da6860808d38955e9732dec7cbe5e337ebb313af174c3e4a9352b250345e7506f7f425ba17936daa897f2e31c4359d5feafc3278bb8224d7219c" },
                { "nn-NO", "6f03da05157e1c6b5c9fe41d5bec40dc6dd2396b00a07bcf7dab85f3f6df96c0a89e7f27e360b90485395d72fb644c5b5fb5ac8f4983633cab8154a6af571f3c" },
                { "oc", "53bbc1c05ea4a7a929146a19514c17e19d799f88e207a16cb8af0bb5e6f2e6c0fdc35c56467f13b2391b2b5e59f5e56b9922309321d84ef4948a5aaeaef433c3" },
                { "pa-IN", "ee415c47b82a2f3405bee2b7d95f689352bc3db2b1d49adb331c0a9ed93b68d8dd8cb9a05f503e0bb57aaf60b2c338d1907b751e7d00efe4f13f031221bb9529" },
                { "pl", "a7591779d4d3d59d205ffb16559cdb8fce7411fd3bf4210c76972044d6b8af9152896c7eb63f8895ba7613642f2bdc5a7cd33df545b68225b501dbfbde0845b4" },
                { "pt-BR", "4ddc2fc5650aa91b6bba815640557bfa9259cd32ab1380e6ac056d6151d75a809f25d8ff4fcd313732d4c8f9741ee9c790757842a12c63ae6819c4f1ab3b555b" },
                { "pt-PT", "c05cc2323ae3c3a6bb40cf3f300aea5244142b685ff96d5b8cc2f4eb2043d6a28fd5f2698f2c9c22d9a3393ec2d62278b8ebab7f40efecafba9547d276f2b117" },
                { "rm", "628c9748207dd596e601ddeb5d41ee44676ab2746300f98a5e20c67eeb391ddf22dc26de6481e17f4834604982129e9d0d550537ad6da4787dfb509b237da385" },
                { "ro", "6cc21a81f961431b183701507207c8df81ffbe6f92f6fe8f4994a2d17f69784468a117333e419a8bd0d50cc6ff28deb5aa01415d6ea9cf34a403986f9dbc4dce" },
                { "ru", "c9cb22ef74192a63607e06db0aa1aca45bcd2f1e56df382fc1dbf3bda84714e567280752bd9e6f7d2f88593516e3ae391893ccacc290a70f2e85455568653630" },
                { "sat", "69c826e00a1088fd27d485c1efb7e0e4201b770c5ee87747a19834db61769393d84ba0b303dbf81f0e8c55d7600c1e842079e81a0616b0f04e4b9f84b2cf7f9f" },
                { "sc", "8d8351161b6fcc376a005f852c57b730ae4477c37136015d039ac260de691345c723b502f018f959ed0cc50fc4a1333f3459a378063370660a00680fe870a779" },
                { "sco", "5165f6f16aff78a5d30cce9b9a2fcfb1d328b684b9191f91fed6cfb4e4902d627ec162310cbc5afaf0fe1e670a8bcfeb69a7b714c9c397d3e42ba2e41a27a9c4" },
                { "si", "9ea1ce8caffad7724e4cdb1c74c475c6127c024295713ddb37ac88c7a3c25b46aa09cbe152800e072e05ce89c6eb1ea797e1a6ac5730ad8d14e9d726bf3a7fed" },
                { "sk", "bd6031e3028c7936e693f23a2a4fbe8a5395a455ca7319c35bd1ccb8ab392591940748f9cba095e8e048f6d9100eff86b6d0e4648691371b34847b20b3cfbb6f" },
                { "skr", "9a89e76b782c8ed43d7f7cd8439783aa64d26b2bb49a391874a4863b2cbfb4d58b7f66ab1e8cc24103869d2a2d7f693b0062184e4e59691c6288c3a68bdfd3f2" },
                { "sl", "01459280de70e62582372ee7a010513bc8b36268c4cd75714f0c5c6858561b20252b08182741717a533842a81bde9d7fc14875f6f987ff550ae4810300c67520" },
                { "son", "25618615add1e8de5bf710a9756171bfea6b3d54a4d2b14d0954090f1cc9a40646245f9f54ef1530ef1a7550fc6a21402984819e8e401fd52fe9db0757b6cb21" },
                { "sq", "3eb2f4362c54e5bbbcfc2274e8bd690d851227964999485bd2789a33e707b8c809dad1f2726e999cf18e2d04fdf5d3328e89cfb6cbaa3fdea2d469e7f1975670" },
                { "sr", "14ede3e90080b9f1ad2250cea0663f64800db2aab22c0803a58050a6a758897cc7044d8d99039cba84f61fabab392efa165ad98c7be8e37c61059e6cb267e0b1" },
                { "sv-SE", "c494e80765e49abb77aba2da5c58a116a2cd3223a36abacc4133e1741acb9f426908c6bb37d7ecb90ef6f51e4e4c9f7b67fe668cf37827ec7be9846ded21cbe4" },
                { "szl", "73c174c086c54dd57420e8b0c396e565f6e25d5804af3dc8e7bac479791e6f5eb4968fdccd24d4f8ace6c854e7e2c432252ef492cc9194f44334a146c84b5158" },
                { "ta", "e9395d90642f491cab03e9855df81ff95a726178d0dc7cba7038f5cfbb19af8270bd17a304b117447182d4d6d138febc9aa730df507f8446a02c11818e08d091" },
                { "te", "06cd55d730ae85ce34f0aafe309adc01b49f6bc096ed12afc815b69f151266b888e1186f02e9a3db55d93d1ebcecc5ad25fae01063960159f9db5563f1627dac" },
                { "tg", "2e1d931a632683becb84d4d56d1500073231147bcfb70874c6d008e8282672988cc95dcfe5c82b7345088bb143dbaa8cdaf4bb854c709379f787d7f825fef286" },
                { "th", "02d5a7bb702236153990ff6566e869b6fb9af3ca31ef8db15612a500b106d65363f44b3f018f32d8e11a3dfcca3212067c0b9da94d9d37d2b4d6ffee86495965" },
                { "tl", "9edf958b306f4d33e785cf982d1d84fcb28b6ebe3e7c82dae1ac7f4df7a4ae27ee503e0b06e35868c076d804979136a0af4ba3f25fa6bc32b170ac782fc88b53" },
                { "tr", "b2fdc3ab1598e29c6eda130ce13ea1a07b3f9903dd04a3a848baf21caddf579dede21b90c5dcd0d38447b1800799cc7bb00d1b180b716344c43fa5a0118207ec" },
                { "trs", "3e819a1c9593c28c72b14d1d42cd77bb2d122ebc7d675037585d38eb1af397505a01fca7c218e52ed1c4749cc75c1db76efddbd4881099ca7760c4459982a9d9" },
                { "uk", "43cc5436ccfcb1dad5c8c2da16b7cbb6687d7ce92465253da952b5f51e9934a1ff264d1bd906e933f77c58d7b990efd1db11862664e350d8e9da03a3d6c39931" },
                { "ur", "2433649a47f4372feac953457fae22470ccb9b32e9310ac4c70c5ca04b053b0c7df6115cc291594b2d3864808f77c3ecc3b3d3a2aebe1de8d0c32ae416f33738" },
                { "uz", "cf9eb1ea588170822387b72b48178820eb289315dbbc3b277f415e3fd90f1e76ad93db8803bb7fe96e769fabd7894407484503d7e148c7b04533b315f20aa10f" },
                { "vi", "95ee32844f138293da7f52e202e6bc84bec407bd547278d88d449248e3f81a973ff472ed3ed8350e600fccdcc26cf024125c40e31db755e54a618c7ac805f9ae" },
                { "xh", "ab50437db7e14bf2540540f492a877cc06c2018cc8b1dcf49432f92c93b2d0dfb76d9f93ffd024247bb9537e719295c065295e5c82a3ce8239ac12a3c97749f3" },
                { "zh-CN", "d5d90d693b280e802409f840ec07402bd7cdae02d9bb30768015c0e204e4c61acecebef1ae92978159d55df4147149a7bff53dd3c730a08b8ca3aa9ae9b9fbec" },
                { "zh-TW", "848d78112f9305fdf6fc242cf03ed96f724891adf8a5741afad7e28921db4996bda0d7cbe2d85dfe2444e307a14cdd7cd42fd78e2dbeb54663a332a712c69c60" }
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
            const string knownVersion = "138.0.3";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
        /// language code for the Firefox ESR version
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
