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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "113.0b1";

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
            // https://ftp.mozilla.org/pub/devedition/releases/113.0b1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "e1268ea8015b9225156c9d91ae76638e24af73384338483af28257425c149082cc902541137ea2b84178599fcfb5c111a0c464f13a8dce65e36334e39bb872c2" },
                { "af", "70fd0a92c2978b1c65d1d257cb66f1457b1eba36e1f3a8378b1ef05900e03e52320f513ad22a2853eda090935fb9aaa31211ef2cd4b9c990bd7c5779a6cc28e2" },
                { "an", "44d5d70455adeeb28af31a3ceab9080a61548cddecbf51d8eacaaf98f6b36360e0537b4d282ca96a4f798215e3b43b87f3f1d5c0d2f57698c97f979278c56442" },
                { "ar", "d6091fec537661b9d271619c186b7cabf5dfa47e9d997dc855bfb72ec23f9f055e1e5b1e6c9e69b918381d6f6797450a90a1346ce04b6a3ea0cf507e89c6cef3" },
                { "ast", "5124be7f1de168d9a8c96f53cb36ecc7e56cfad80f68777d1fdb1023ae9219f26b70eb917476693cd0804e84f06e6900676f3586c8c0277465e9f868f1cbadda" },
                { "az", "c11054e5c4ac71fcc7bfd17629367966c4d32f4e432037d1cccd1b53f2142bf3e9ec650b59380f2b484e45a7ee92c91661f72039dba8eb6e837f509974063584" },
                { "be", "4e5b8ad6903e5f23dc8348887db4ad69a8c3f456bde5e7d25c2579b6d3fd4cef03bd34e4d5cdb55aaa484e31b3258458a06f5e3780f0935f9b146956ffc9f52b" },
                { "bg", "89284a51e4749441b931f3266bb83fb8e83e490fba8fb848688f14b8a00d3f93514ec113ebd871a1b209e928e3181f1ba13756614d1c4a24de465ade2cfc4364" },
                { "bn", "aac4bad01e5cb8a85269620b8eb86f6334da922d3880bb3c663cbce4d21505b92409ec986408ab4af8cefc991be73c955224d460adaae74c89734e5ee19567ba" },
                { "br", "7466c2a6b5751724c3d85d9cf4f8cce87711af8bdf816e4e8161cada26355a0ef558cf3360fdb14e9a3f177834eb328bd15debb910d48b21c5cff27a1a5c0516" },
                { "bs", "2f26c0dadc7ab4a8ed7bf3bbd137e7db162624b19cdb4c0c5a24f34ccb31da6a33657993ead18f46f0457da0c986d29f0f9cdbfff42201492f5b35c81b032a63" },
                { "ca", "e95cee05241236a6c8bcf0a1a16cd21d410187fa8e073452e58fe785b9eedc4073967e24851ab841dc5a9af65090dcc55f7097e862fa65dde403d78153b6b8f9" },
                { "cak", "cbb373bac52e218a76f3d7e750bc2e812159d1cdced2e18c949ad031cd50cca7e1840ad7b3846440a3ee8f7531173001e2c3423b6ad384ebbd153c5a6a69a93c" },
                { "cs", "cef438be3135bd7ad584424182800c65584ca3646fc0952e29a11a1aacab76debc4ae777ab5520f5688f0fb5eccc1a684457aeb6dd18b297c7dc50837d93d3ef" },
                { "cy", "6795776cffd1a227a037b6c03998d37ccffa4c15af25de38ef769e625f4e74dd259ecea5e08c5443218ad57c0227f9da97541487d969472b0226951fb2b64467" },
                { "da", "3dff01c6fe37cf6ceff9a2f820fac04a9a4c52ea0a6cf4d4b833696c06ccd5f130067ea2c8eb3ecabac5b5befc431eb09e504a858fc2305edc4edf844236858b" },
                { "de", "4afea080338736e9dc9f1c453a91b5848665c2e55a7ffe5689ec7055676c9f48f40cecfb71d1422da93715071813944acaee2065d3ad29af40c9562385241789" },
                { "dsb", "d876264939d238007b60f36057ebaf63a6122784f2bfcdce3555a0a0df7f37db96aaffdc64592631896a27052e2f7776d38a05d51c7639b9992feec019a3c4fb" },
                { "el", "30ac7f4644a4a29129fa610d3c857b119fc2a9efd2027f0b601acd801a00f9a15fec099a771be7621b644246d2fe93e023b1d158051a845c4002325a41264a80" },
                { "en-CA", "3ecfc1d76b4c3481c35228777ac7b56653809816f8db1cb16f2e0803c116298b35997f0a63f7c16e045d5cf893ed439c602a60f6a453e4b2d85c3d18bd7306ad" },
                { "en-GB", "037697da90287213621cce514604849b2d0ef82a4c5291544c13e52cbdc1fe0681b0f8c8699883a90a99ff1146df075b282e9762c0b40d29e31adc3e5d2ae1c6" },
                { "en-US", "7921aeb93da7a460635044a4545f34e5b2856955d6a6e2b0c188e48b7d0901d47775e5dd2215b4516fc9d12520b2f6236f70155620c614cac1bdad2effc12621" },
                { "eo", "498ab8331aa8d78835e92a126c721e95c8edb2aaff8ca74fc2f543382592699f3543d720ec3da3296f8656ec1bdd7d1c88199321a4b0cf03dbdb3054fcdc222b" },
                { "es-AR", "7a64529e29bc34ed4e5f31bac664d9e6a7f4520f4ab149d4dfd0a295f6f552a9f1a795e7c179a6bde910ceda8fe9ffe781d5bb921e46c45dfe95ddfad5b13e78" },
                { "es-CL", "14f7edab262530cb2115d118d7e1834eecebf6d546d90019eb4d6ef05a9a89a613e923468f4bdd0efe4a18599f7c050dd665a7f9f8965e8c5c748170bef7838a" },
                { "es-ES", "c3991d8f46297560d08712e20697d26b98c1d0dbca87bee9208ee60d8021ea5161eee73d12c77d6d38033f137b48875b6ca931f1b9e2ff7ed459a50635814670" },
                { "es-MX", "d45456ba68f1de36520a38d6e220605b1423f2c1ce3d53fe9315508f411bb21af4a4867d4b74b6f2a7c724904940fbea619f6394bdc28fc2c4bf71b660974c5b" },
                { "et", "06d3a6943669a1e81e1016ab884965df50b655b8f81aa5a4ce24f19f6c2da79d69756f33859470279ab62d501711711cfc0c01f6e7e936b4720d9f9a56ac074d" },
                { "eu", "49f9b4555d5333101e656453e05053882e51420bd9b44f3c6df99d57526d43e64d915f0d38ca21c0df3c4c2576da24f3009c41ee8fadd8fb5171e55408ff84f5" },
                { "fa", "9fae8135619a2ec2b7466ad9a01869b7888e3ad98120c0903955e81b505d1a2385b227c3335e7f659136b947c72a04a33eb7c0ffdf26a6ea24daa6cb52e5c112" },
                { "ff", "166413629f540ff04edd45de39c016e6d17f5e40577931d3b21f47fa5f5df49335f750fe2b1b92a529ad2397b3b77b99c130e14cadd417d11d84c0108346d7bb" },
                { "fi", "2578a347d0597d49f804694ebd2c471ba472535ab91d17477de87f5d21cd787a78ee43d710e8f216d33c9814b6fae63a861d508766c72221cc154c79dc39bfb7" },
                { "fr", "72b6956bc60e839d690d68df94f5ec874f28106100f6cfed54ec07067f69f3d059c50ce1b515b8d2e81d2246be1b66ef16057be72d95ea3880db9b8335e5d6b5" },
                { "fur", "1ba2ed978544a83f132fae26108aa09889c48f609aad0de1c84b6f184fe0887f89b95c43f7d3c89766b6939415b1021a890c96429c0bafcc0c328a8188a29ecd" },
                { "fy-NL", "7867cedf2df908d3adaab676786b0a81f484c5c8883d62c1fb7a13f729f51e3807fa730899e9be1a07958d0c7e7ec86d968dd9e3ab8e9d3c22184d6d8e9c6294" },
                { "ga-IE", "15940c21a2279009ce820b5b83ba3ba343636af938c03da2ae30a4284b67e0eed7c58d00503d303ca28d97cb176db3e1083ce7f06bffba3a9bdf5aa69c2ad68c" },
                { "gd", "c5e5656df8a443b00cb2aaf9ba13e1f1c23e77cd372909a7428024cf99701dea4d1220a3db35a10a2ffffe51461fd92bfb04a3c87774d534b1de96da0b79ab8d" },
                { "gl", "0011e59eb64c890818f1d9791b0fb7ded225e098c7cfef12bda769399b485269be54bddca428dea9ad9051ebf3bc21e13d105e91b174617617e3cf107d330394" },
                { "gn", "1faed25ae684ff62afb48014d95a6d371a68df3c710b97944ead862d0e773fb12ab23c4cf1a3c421e2c953d7311f9430fb6842bac996a5a9d943ebfef3cd192f" },
                { "gu-IN", "5b3c84246e6ca5c50d8b1cac5fdc3e91247d23d7deb25a386bc24a19cb0bd3f04ce9350a219b8aa8e65520cb2a5913d3935969af1eff9915fdf514509bc901c4" },
                { "he", "10c885eaa621804ee45293b658303baceb0698f2381050ebe876236b2c9aadd0aa98f61362ef4c720771b2b6fdcd952638c0b41ba13a7addac6fbd8ed449c9e8" },
                { "hi-IN", "228221881cbc1333f67c51fe0dbe3adf0539f9fc257fb47e0d85be65b0d9e2ba6d53c645c5ed025c77d19ab10de8960d3fc9dd9bcbd00244537012e0f6a0d71c" },
                { "hr", "da83c44b7483825bd41b85729e810ef08d17848586164b8569e5fd7949c43a340fab20bcbb499492f7f20a3394675cac4ab3f583539484d062fce097f0b39522" },
                { "hsb", "556bb8fe132b4279a1280a840705cf4e01ea64ecb07cd326636f5d36f63ec60c36f710a8647d40029716a30d87f53b47168469c78e6e17d92e113327c85773c1" },
                { "hu", "377445c4c64d47e145fbeb7b37df79627734fc8cd42621085cc3b3fdf9e271c486d92fd780f356cb5802334f8796d3cd0a87d9a0ed24eb306904493d709aadc5" },
                { "hy-AM", "4e28c39526c8ff452bf89a9439237c084fbae8740752ddc480b65f898897000b33e02879c23fed17de7c04a57ab3a777e9af9df80b072e18381e9c8262ae371e" },
                { "ia", "19daecb433366b5591c4c64bb3fcc91d91f974d07280777eecebf730862d5bb199a6ec049ad4b89fd34eccd4469280a1549a9fac2c0f038379cc149a40233dc4" },
                { "id", "fc475c08c04973640d2391e05b56d8db2a17d4b3cfbb1300a557cc8084261ab0628e48550ef860d87abcea1e255a0d87864b307ec1e34b6e9a5d211f9e36679f" },
                { "is", "6e388496276b53f55b1808d4ae5176fe96b61dafd3cb1813dca8a3365ab43a536be2c8f7cd5199605425ce2ad631e00bd7ca7707379caa246eb3f5ff16186714" },
                { "it", "cd2dbfe9fc708e6d6a6c32121530d001453bfb338d2c982dc98891dacec12f948369186eada24c1dc096d56bf8b6656bb26812c4549b076a32254dfd7ce2ff8f" },
                { "ja", "d69228db9678b56081ac197203b6c50def27f48d61da7841fe83eddc56ddec19395e60dccc3d789fd117e4b07edc86c8f99b7753ee1818e119fb86dc11380a2f" },
                { "ka", "d5777e298f9b04f03c2b201ce5328fef999a12d9555003ff1fe9ed55e68e94325bd1e30df23f9fb8edf8ce9bd56827a86315551c91ecbfe578e5b93c745bc41e" },
                { "kab", "fe20719b25341e99d008747ccf644210d56a04eb0f5c5799021831e358f815700dd3ee70d28dfea4f2dc26f2669aa2cfe900683590087377b3e31c3d243c2e3c" },
                { "kk", "e4b1e8a65f4002fbf3d627ef7695b70c0672330c483974007737cf4c4bbd6bb2f569b55b45098616c981539d957ddaa53dd45475ae87ca5e484da47f6fe9ed5a" },
                { "km", "76cc7b1704d70dd4c372cf4f2a193326e6bbb5d610ec9a5f302dff87bdcf3e95d0a5c7333411273c4f7d18b6ef2b81711ac3036d2373ee4f03723e7d35544f1d" },
                { "kn", "edc8db5577b26b02f02bc6d05e2d2e05fe6d25361103602152d7c88c9ef71553359213c4502c9848bad6093b70cce3c11cdca2cbc29e0a6d93f0ba714c039520" },
                { "ko", "1da9c6b425cb8d5528cce55b3e8e5ecabc993020bf729f6eb769e724968430890bf7f600cbd4f634ce21a26ec994c56f02acc4ef5570046f0987e4e6dd7eaa5c" },
                { "lij", "5242b2ce4baf3bb4eeddc3cd116e592524d68cdecece3875b8e78cc2abc4b957f5fccf10a77c99a51dc9c945e59d0c9cc8866b2b22bbb9b692a722c2bb99086f" },
                { "lt", "f75a309858adf88d521a9297980b61730820c6262a104bc651b3b334f3478ac962dc3c6b473eca006e039be2120aafd9f29ed6a1248b06d4f2a255491a4c73c8" },
                { "lv", "957a02b1ce9face8f60d988f52b37d88793ae0bff49717851915240a781bbd9e65adb5b79e831cdf2f6a57ffd971cd939ae53e9a2c77cc91b1ab841278a56729" },
                { "mk", "aae27cef21672bee437f22751f8c57cbba4730e05b63b716e278b770d4fb327985c47d20874d5d6558343d29cdfa4e127726d2a8a89241db555bde3c38bee04a" },
                { "mr", "d30f3d946a3eb985389ea56f43c2acf9fdbe25dc406c3b562716da59d2d5a85c95115003ea03b04a06bb476949534671d7c4084f5bb949959d33a85fb00f8f23" },
                { "ms", "25f14ea751104c96255186a16c800257477ed6d7cf979e2449f757d09215f4d000715aaf5aa701619b1e313d463d5378e311ad911b7e4332c38434418653850c" },
                { "my", "ff734a22ad6fdbc60ae3d78b271df05f0c53826e001793ce6efb37581497280b9973aa38d418380e9a2c8a4a483f41d4aa853c74529b9685325f07eaa2da11bd" },
                { "nb-NO", "df78fff9f0b45bb07d7ff4fef812ebdf6a54e9a11756049397e51cc041de98044ee6f709d98fd35268a4a38150e56dd9cd02fbbec9173809d8eba9e6f212b2f3" },
                { "ne-NP", "c56a26a736d3721bb55ac47bf2c1eaa7e835774e24fa09d7978bbe23eeb683d107db0b6122a00f9c97fa9e7543b764257acbf099d2bb89988c2b4ca3deeb532c" },
                { "nl", "4deeab45b8233f712cab3144f22afa4e1461df1e0b1ed59aa91c3fe13f8accf9dabbb69efb8d1150f4dff2974f9bc6f4fb19bc36b52704663dd7d72f6f6a7d75" },
                { "nn-NO", "4ad7178a2add302999be65cc2246d0b4b8bcc0220069f7d2f8f4561227bf51eb22188d85bef018a7f8feafd5d76f6bbf10f5e9ca50056552bd90c1ed9f201b32" },
                { "oc", "7861ac673343ed88b1b66909069d25f9142724268f0ed340f0ff6514fb94d3a9fea87048d5f88461031db7f229ae7c471a13ac77c6c23425fd2283a83c72b456" },
                { "pa-IN", "693f830f51365c9538280e62b95b1a13bde3da9e04a5343872b45aef81ef81d40e2544dda301a454d909bc1f2d4a9a6a39745d36b0f44d183b52eef9cae3013f" },
                { "pl", "5a8dae2ce62a02aaa3fedf3d69a948a65f28ff9d5a2f7038659ec89570c52ac20f7624a27ebc7320e4275e8503562ea213f8cdb82bc46eadab93293a52107f6a" },
                { "pt-BR", "9c67ecbf2904c9180b6abeb2b5ce092bf941ba9cef71b89950f285d768c01adda6666554b5cd5b2e9af3e4d662c80e3968235e90babcdf5e0fb78dfbf4e774d6" },
                { "pt-PT", "c399760bed5584706fb7487259499e46105323116e4c927e25c6418b6df43c0c932fc8be1613499e264a2d1534965bcb41da159479da7c4a597e92d196d00c07" },
                { "rm", "f6673c0d8fd5acfdc98b30054333c5cb8057b144c5be190210bb33869e6384cd77a3af165b1e1c8dc56dac6d8c2531c5cd6e15a43bca1696e3faf571e83c243e" },
                { "ro", "10d5cc76648dc833563ee84a559b4690e5249314928f68d12c9a8d37b569e0e0859dbd2ca1edc824da01a61d3eaf39e40f7becd5d533aa508a712ea06f63effb" },
                { "ru", "707aa3edbbf107dacd5330211773840560a6ae7097cb01cf6966f3136db611796f944c7712b1a6d4f9cce13668222391b19dd8026e2eee450b98da11bceba436" },
                { "sc", "606974aafbf750e5d594098e7e7662650d09bcc5ddd8348d188817d07c141523cb3fa3cfeb12cc65e104f40747943d9b568f923b22af487e23f1a4b8f702f817" },
                { "sco", "2660dd8d464cff797c38e61b48239d108f553cedc9724bc34ccfec827832c393f705f72219f4f9edfe18f06c10908b063337c2c4d156db899b993c8a44834949" },
                { "si", "7c75029f00a142ccebf72b9422892f6a3f88ef4c670d84e45d33092c8c9bc28067492e4c074bc56cb81636d147d752269098fc147489819f56383c2b0ba9a486" },
                { "sk", "1640933ab45c82e592ee6d2d3de94f507ca479bd4e4014ca17aac53313068521de0c22089148c436e90897c719d38c830ea59cda31e008f0b0ede4e0b75cd381" },
                { "sl", "e361cd299d0463f24a8f5c2645dd4298626ba21342ae3cc3e00d60bf543e1edcc0bc7e35300d194f3d503f219bbba0961ea724472e47d58e32e58d7e5efc395d" },
                { "son", "5746724c61ca849e3928adcb75fca2fd66bae2b41cb5311b81a7d8d9390374a01c03f3adf1c1187cf1a749fbc990f7b096b53f9affe71a17aafcc0e5e3d5f567" },
                { "sq", "0e29e05853be7674a8a7ad33ad7a53d8181cfc37c3bf4b7dd83801dd1ca6ccce32bd3636f35c6ee1a065e37d22f8fcf185773ae4eaa80d8b949f91ec74697178" },
                { "sr", "71304b7c24b5f36d7372723c8940818c0016b49d7d58ddbe91cb6687ba533538b486efdb9b5578209612e5eb4f6178d67f3e5d4abda44b2fe7b9131899cc1b38" },
                { "sv-SE", "a6c0b4a1379205cbdfb93a16ef07a0e0cdd4b581778d00059862e6297c49550c80ccbf5bc4afdd29c852e1604a7a35a059eb64625c394a1657270178cd1c41d9" },
                { "szl", "df46111cb03bf55e6eb6572d8846dda40cea13a8a67ec4289abfbe5852bf165cd6e8fefbd1a2678e7a0cd79103b7dfd79b3311f89b0fe0ca51f2881dce120054" },
                { "ta", "7741d932ab9f038b0605d7dfe38b6ac90ea58dfc12557405447620c2b1f97cb64bc98d7100d6eccd836a7a1a5887ed97ea5600c9e6a56e43ad060e059de986ea" },
                { "te", "f41a7b86641e19074433949f38e14c719e1ccd97415ac59cc3930faa0efc7f24a26c901c0aa66104c564bdfaf022d399e20338914b64ee1ff063f52d0f750a1e" },
                { "tg", "7091d71607ffe6a7dec258d2bcffe97acfebaec3cc02b5cd3ee2874f1b642505f5466183abddda85c617f0314c872c6dae2f97bf669e103b854fc55c147bbebe" },
                { "th", "e6dd43cc342288fddd054079986616032932bf50047901c43ffc50c7566520da3040aea766ba911d44565b72c14a4ec2d8379447de634f8953481b4f89b3f62f" },
                { "tl", "b00d2cf5f21cfd8cab5b2944c40a0bc0b586313b0a19a292122adc7d8c2a23ec44ccf7c58d87d1db2a980517a3021309e6b38908cf9253044c4c35a898c4ccfb" },
                { "tr", "805acb7d301922ce59b463e9cbd0056fbede191fa6d02066fc9e3f303c367b43828962ea012e76811325107507c2f3d35f07fa423ffe46a36ea9a66a0fd77c2e" },
                { "trs", "2a5bac0ddeafe36c8837ff3ba4f20dd6ded3450ddf43e2d23c6427b1cc7be4d45e28aa1846d9b957cabb9431858f44659c0c24a1962c4a22047712df894fbb3b" },
                { "uk", "afca4e501b91f4b09d8cd2066da921dd15fdd2515ed26ffd38915b3cbfbc0f4a7e45557acd6afd89b1121ef52a5df1ae9025f0026ca1c2c5b22031ca1e352c0e" },
                { "ur", "98ad3533efa9e2e0db2b1a990e519f110f794c1817fec3e917df9a3f7e31352e7c76f5e5841eb25d7117fe6ce71b544ce11fa46fe6a32f354ebcb620ca3b4b4a" },
                { "uz", "27c1f53dfbb95d634a7e7718576fe2491b0fe58a3f34c8ed9c709ab7e39c11742742d50f8bf244994c755fd3d5b1f57fb63ea7617d28fde754aeccf189e296f6" },
                { "vi", "0a91b57aba05e47f4bf66f4e7004518e28770aa10d4e5c87c36024fa37b6765260457c6a919ba3907fa973a39904a6192e05655b5615c0b36977e1c16120aacd" },
                { "xh", "87e627f1c64dc8ce492520321b34658fadeae4d2bbd24d664d647a9ae6b7f844594e6832a0138d5382276e13b6729933a8ecf19987479c472171be9253463f0c" },
                { "zh-CN", "43b227544e34932503870caf34a163c0795ee55928717e713564ed583de25806ecbf38b56e22eada15890b0114afa95a505533ca3d4c3e22befb2d8151197f73" },
                { "zh-TW", "ffc858e082ffd895005a24fb8fab9abfd0750cf212eeabf20ea3ae7d20c90cd995069a7e97c8c1d4985442f79f7ab1782157e0cf15e8ca5bbaacd51ea6dffaac" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/113.0b1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "d8b977f74ba1e381e32c437ab708666505a9bd4360cc607e8b4c552aa3c32f4fa6c979aaa6cfc32d10c0889b089bb6383c15302ec8a936bf2db93d04fb141a5c" },
                { "af", "f4aacc72bd55e3a13e1c58419554880296d7fd61836f80b5d17b4350da6aab2a824c9e1187a63673c80e5255eb5b3cdf1daa07bc2845b16b4281eb49d4b09df7" },
                { "an", "9c608124b2d30a7f64234025fbada5ae380343e17fdbe110b7d06f982f82cdbee8be8f10beccb8ec9be191ec00ab5c8fd9cb72c94a05c9f2bb41a6ca85ae3e4d" },
                { "ar", "fe6e14e277b5e10a79ce3fa9d8d427c90f63ad8b3a0995998dd24cca3aabc3bc27621f86b0e06a614d10a7aed43a922be87ef8de184698e8e22e00cab187d868" },
                { "ast", "288e937272f19f30245d5f9042eeaca8f68bc0c95593907f1444f823f522cbc79c124fef8ffcf4198328a5c08290864bd1b7adb164af49b729af0cab6dbdd987" },
                { "az", "f54c8e72db255315ce11e0f6d62f286cc0ba6139bc282d21f4c38491057d5f1d59628c77b0fad14d67cc77feef23c70f2e46bc81eeced6dfe7c74763ba2e9131" },
                { "be", "a4b6c483ee4eab24be0d46b79fd8bf482059761d7557b8de22a1a051f6f79cf995a9001d1158dd0792bd532d1c44bb7072eb87e114ec7f9893c47451f5831d32" },
                { "bg", "1b07d321a8b8bec2d1fb5b57d2831ea1d99c6267cf9940fab1c61f97b5c0af94838df8edaaa273709e1fe03201fde6bfea7cb09477cd17984153dd2acf83e491" },
                { "bn", "fc07eaa938bbc4df0ec8e9c2eb100707350211455fd5ed5fd25643e734edec6a5d6690ccac055508624dc769faad81beba2aae6e49262563d2deea2d2840812a" },
                { "br", "b2d3db50df5ed19acebf50e941894fede762b3238282baa2ef70e8248bff23308829eb875b77f136470c785492f1e1383297b0543b037853667a4256dd1aabd7" },
                { "bs", "eb689c82f4d5bbf32faf4ca71d72bf43ee449a89a706b41355caa9c769dd666d76457b14c1c5a6165a6b4a14138f46ae1f05dd172ee55f8d1c49ebf0014bb85e" },
                { "ca", "b66f2a6e61d4e53812397c41805675d42bd0f024ec9b795e055377a00df51356a92691c921ddcfc0573ae4de94788062b777fbcaaac544915bc1559a30efeec7" },
                { "cak", "910d4ffb53927d7914b2ac0082480f8645ad7bbf9befa82765658165772a58b5524fd0279b15d28a1a1081feaecde2e45d29e7eb6ce53a31519d56e751082366" },
                { "cs", "c08f2bf7e99d6c7a8153745505111be376c3bd76c202419ffbed905363324f4e5423323c7102ad1848441b1bfeffd5bd1a36ff1575c6ce9da0385c1274a0b09b" },
                { "cy", "ab896d454fdfe0a8bf3be29a0eb78e3131fe31c8c45505192b7e7e1738503b3bf916b0c5e010e22aa3c2d67bbdc27db57595062218129a874a9606c3202f2fb2" },
                { "da", "5191bfbb596f6ce95a42cf7ff5f59aedd6684d73ea71c40a17cb60ee161c1a7761ef2e1fdc2d4e75b9cc88b3a2985ddd272b08c6a3f619b345704110b9ccf552" },
                { "de", "67c2ffce41e2255454a8a5c7dc1d2e20c2905131a0267fc69f015e61cc22c93de6cfd86aafd1a6ed76dc0a6f9cef2ce84331b0b8dd671fdd1c539fa39ad80b99" },
                { "dsb", "6c7890454be044eeabf8144be642b20ed9323ab101462ddbd1720e248757bb5dd3b588a25d5d2ca8b5085c25505a97f6f2270e8903b30d24f95b1ca033e571fa" },
                { "el", "0168fe64f7c925193509ba7c99d681d046cd2e6bc46ba233cd91faab6cda8482d3b287fc24b70f220c9203503057a86fe7f61b7318f66d96afb7dc93ceaf53bb" },
                { "en-CA", "3525970c6d4f85cbd7087bae9c44ec2f35c483b93458013154a425508b611939c3239107326b7cc0dcf410a70dad3e33e4273173223c8e92be584e150074b19d" },
                { "en-GB", "9fc7bc7c720524bd06587787d60e4b33f76cc1d2fe445b5512f180d1a6c134cffa7cda9824606aa85a53e95ec0ee169888c8fa2aa30df858037ed4eb0c99c9a2" },
                { "en-US", "52859dcacfa92b213e8a8bb258ee01f492d9176e86a9dda95254f583e61b500e5b6ab912abf6d544d4d489786c6f21a399cc89765eb83eade2c7c71c0bf1561d" },
                { "eo", "fa8749b8fa412aaf35bbeb3ed9393b807a5d60e0dc57befddd25b1206cc979d9bbbb9b92de81f12e44e42f11a8189f757a8b3737e7c31cddfeba95b1f1b5346e" },
                { "es-AR", "854414e084d58a7c966a1c644c3c919353ce252983c40702dd550f923e40eb1bbd86b78bfaed03c475c97924df9c172e18a67f998fdd0ced996dac36d5d1480e" },
                { "es-CL", "eac5d6f3842c092c0f2891be0936a748fedec290b6d5e4de1b1eb1ed80f80342275664c7d5db5c92a96f7377a2d34814ac21f61cc312d370f0c6dcd7ccb3f477" },
                { "es-ES", "4a08e2251f190b05dedcea7e9a10593cf7fb3515a6da519afdaff4049ac75b79b3273bf113e7387e73b2514317bd7250495d4ee7a909b1c6bcd785d96c023cf1" },
                { "es-MX", "55c3ebaa0db00a3479a0eeea9b22cb4854b71695a0e3e50082127ddd237be1d4dce807ebafb3d9dd83a387a5a913cb69b1a85745808bab1a4ccad7e449526a8a" },
                { "et", "f807777379f4018d924cd212d480b6921f6677240166ba7054dfd52926ec0ac1d781ef5694dc84c9890498f1ff50d77b35126b7d4a45a009c9e7a450ed3c3b04" },
                { "eu", "bddb16eadc34bd5c169a1f5f418aaed9f637d6a996adf32ea979efcf40919147f79f45255ebcfa3a7a64ff2f81671bc8c937e6181a16c1c169f287caba0b1b1c" },
                { "fa", "3e11ae264df62ca0b79f53a48fbc588abfc5a9335af35cfd52c6b71d0202b44a4293cb38991e508cc614939bcdbe3089b32cc2545f2fed9cb20b9eea9d676e64" },
                { "ff", "1d170da9d6c0677dd99e82c3695a9f5f44e485fb8320c4e930916686d78b18790f2ef3510d7803316b8f0d24bcd39a3d34ecfcf538071fcb4ef21ba48296c212" },
                { "fi", "143d5f1862262971e6a46450cbdef8a1d2de6d8aa0a28d2b31269926df05a4fcf1560bf8a615d7dc393ed23febc44b3c827f7746fc53698f5ca1f8caf850a808" },
                { "fr", "bd7e5d5a1b9adce4f4ac95fcbd4490e6363648ebd16ab5c4a43a2c73a2ce794b2315fd1572760ced081a3a468f54e19a7091ff854c73bbe4ab8f30384120733a" },
                { "fur", "9c7dbe29bb7ab1b6f0dd3b2be6987cf26c3246e7ffc0c4cf7f26c41002703e6fad4f345c086c2acb469179da1b81b00f876903e38de8bbd496d5bb73989558a8" },
                { "fy-NL", "b6356a038a979ca974189af071c13a514e3d4482ca0f983aec509d889e56c9b72fb919390bc05a3813da2166b4cd87dcc5cf4de6ba8351a1c4978ec134f847ad" },
                { "ga-IE", "c2242f77acb68ee63fe199f01d396ce5fdcf1ccf3c87acdb1877bc5245d8c7203bfd2ade518db0702e6b70fc676a7966cdba7ab6ae4c6fbdc59252379e30a552" },
                { "gd", "4681d4a22610fe5aaf30fb59e82bcd212fca191fc824652f30306928c6bbb7aa85bd15cd7fc37baffd6a99dca40a19e73e555da67ba3ca7ceccfe2babb0f4f82" },
                { "gl", "e0dad916095522faecdc9ed305ef3125dca7019ca7cc9c38c0e8e1e64ba0b1eb7c0fb434a01520d36ea1393783d17ad68e355a264c8579a46124d48b4e15bd99" },
                { "gn", "655ebf57a154b6ee47cc411f43a116c42bf9aa53e5a57e9067abfc976a91585ee661598694279223b978966916308625aadc6039e258ea24b09694ae626fd34b" },
                { "gu-IN", "7550402ab80d3a96fd449b598a753eeaa3d05b35d05770ed5afcab08964607a5107f6f2c48e74fe03b9eecf99415fe191193d2f90fc6e4716e4d05cd6baf549d" },
                { "he", "51728ee7b2e929d38d0a859e2b54f768da42e973d1bfb98a78d723b29889cf7b49169c8022febbc8826badc1bf961f0fdd1e2fa0d88567badc1b48c82d11faf1" },
                { "hi-IN", "307fe7b8d4c956132b47ea18c247a6df6ed58bec5592be899645aa78791f565b51cb5f5cec0904dc7d6a79ec9fcf92da9ccfc489e0d07450fe446cd5a28d9bc0" },
                { "hr", "7966030aefb13992b066dbf4c95865fdf420d0db551656e4050fc1c8fb6bda89638c1b09ad45fb9465f38f7f0af084ca5e37e65ef8b533ff610a85dcfc22bf36" },
                { "hsb", "be78954143498f6ad01b098d57be649418bd45275ce2aa76428f191a34528e0531eb658cacbcb91326708dad3f1214cbf92b8da449deb7e554ca669e32b41996" },
                { "hu", "aa4561ca7cc6a75f83094a3a6a617935d94e70532baac1b6c2436ecb56fd7a3ff2930d6661e62788c65b341b5c8615fa04e1e6d3145652d1ca8c20ccad5e919d" },
                { "hy-AM", "5d5a45a49bd4d17c2aedd02d28ad851e3eebdc01d937272a58d2533a094565336c302b707c676d52cc1d470ff439aa3e888af11f4037d72520be657bd58e794c" },
                { "ia", "465df67f28f4c45875eaf0c705b8b6271e90587f5a2bf70d061d9031069b3249416a34ee37a0c9896e73bc9c4fbc84955dc48f45ab76eb50a0ce22da7c7a2efe" },
                { "id", "f2cd3d991d47bbe4ce78092c560950cd20b13c6673b9b9ddf194fd6b4513f0068c688e9c4b5b4b04f606c41c1b1d1e96d3b4fdd81ad957361b6893f2d86a041e" },
                { "is", "4b3fe0dfcabf96cdbbf9a76b0685b2033aa463f5814ee76ab7774df18a21cd2367e67e9fc48a645e6b7d1fefa5ba6f4ec7fa8730256c5b17ab558e3d8d89102a" },
                { "it", "49996b7a6a80153ed2d95242695afd10ffd0aedf38bb43648e74d001d9ec31b63692e99fefd383b9de16c00f37f935a8450c1383b66974c6c971763de00e0da0" },
                { "ja", "988d5230dea4192055accf970f1a05e34c04a08e10b25f96e5e0ea160ba919789faa2c51b71697a5c6b91034953c3c66c9309033ab95098ecfb97e1c5388e975" },
                { "ka", "eed1ad5c83d32107e7307dc0023f6193cd55ae15d5c76c0b16a8a3475c7d83aa9c181bc0cda7f8dccdb1af056147cd252af635cb7bcc1269a511b155253b8815" },
                { "kab", "03b6d8076d6ce24ebb4ab621b8e07f94cf55a533d0fda3d7d48afbcd38a2b906acfdba3a6d73c1cb47458abd07ecedefa9308a032f8258423e36016572ea6ef9" },
                { "kk", "a95619e0ac5fd159f182241889850d1d3674663dbf9a93c1dcb43b828a4db0c13e911e51dbcf59447e59d29678725e2d5acb6185d460eac8e39208b7536df44a" },
                { "km", "3c3cdb1c420fd9fbd89213faf22a17bf652e1acc0676b78a6996d128bb9b686bf3da6bf7e8b76b3ed76120795a284bda705ee319d3c74d333f673ef536f6603f" },
                { "kn", "b240fcb8708c3bd63f7d5e2c85f8dde9ce52fd284adf3518be7144416fd74e3cdf1c07a79426c42f6f8d25b63c848be38b20e38c51bc541f3be272e81cb3b60f" },
                { "ko", "a375bea3ba16c9124f32a06a3d4ac7208926d8ac2ac236e5207a2a4a5ecda7dad3cdde57106f1dc8a7a02a8778262be88b6934ec1947772c8d14814a3c0ba9a2" },
                { "lij", "8c2688678b55e0dfd71e9e5c55a5df651210d9b93700ae6433365cc479215c99ebb73c17212fdd376fb556418ef6771cdb91c72460760969ed8eeac99e11fecd" },
                { "lt", "39d50971fb97d1c80e9b31f5a5a562d3a2e5c44c3511be789e7d76303a871a9907aeaa6b2c10a4771439a351cede0f6fd15de0d6da1e5e08342f0ea318fbe1f9" },
                { "lv", "8845d26dff18c65881ef8676cf77204ddd16fcedf246a837b4a5f343c4305cd2757c82eacb87381e7b8d58d1d4facc399658a08359782dc50c0165cc9e0c2e8a" },
                { "mk", "dac8bc4ee73c4efd7efd93920c1d1693534e8f1a75a296000df9948d7aabd1ae0da42664bcfc95b51dfe07c73987ebdd9ae7deedb05b92d671761d7249f5a152" },
                { "mr", "cb9c79608ab4a943798734e8c0f362fcd319350f081f79094ea8024b605b851a7e2741b736822eed99e8730478bf2c2d9387f562d5aced9a1e97b5df6a0ee42c" },
                { "ms", "239d60be5cd23dc0c3fd992a6fdf3c53aaeb22980c5a3288e320a066acc9263e500af0275f5fb226f5425c95675a84e00d31631e034b5638274a3ef022c59a4c" },
                { "my", "7b0eb018f7ebbb63bc293beb533d0af832809e88ab833ea92784b38e4f0649cdcc3a5944dc95c3ecaaa081e6855eb498ad3a4d136716c249ebbf54b4169012e5" },
                { "nb-NO", "1586956819a0abf8c5bb9d036c9774ce8ef013f19d894a231497e146c575ed35e6eb0695f4a70a7521b0b901756b8a5c5c4812bbf60a8e2213c42b290c556199" },
                { "ne-NP", "186e99eabc59d1f309baccf104044d071ddcd09a22f36e8d959e5b753f6d859852b0bcb94d08108abafc1e706be03662ef559ac0d3824bbf2012f4d76f17f292" },
                { "nl", "4ea5e849f6b531222e9ffc2aba05fa6f8cd73b3398f2f8179f9ff9251640746134aec3ef90206ba3b921ccf3745e89aecc4fed7f42b99ae0fa72d1ac8c4c83c2" },
                { "nn-NO", "d0e0e3c4b80a7c853c5fa7c7a5c20730dd3b3e9fa711203b7831a447a702a7944d71d8a74fc6001dc3dbc26c0ea0f3d5d8c0008cf7bd2e7c2af413f3d23fc55c" },
                { "oc", "290cf004b84e59e88481765b5ea07e34bd136143e7cbb5da2f04d50af199983cf3c0c916c5e98486be077c14f2e0460e4bae09d265539ab9ddaba1a506a7cadd" },
                { "pa-IN", "8e4e988948198c8529049d672b78c5ffdd6811cf444c1e68edc01a3e0e73de07f2ca20f04fd3021c4c1ff7c4f61c1d15d33e73a84e6a11bbef685e35518bdee0" },
                { "pl", "cea7277331614526e8330e3fdd9b88e0bb26d89d24a6fed7db0aa0b10ecec0d9be124837243c10302efb8182ce5c40cbc26ebae69e711ddfdc2990a4cd0a5c48" },
                { "pt-BR", "8a841e8000dfd997d73091300a34d8eeb7e96403a63ff20b5c5e6bbd80850c10aa05de116511c89b3fb962623da664ffa9855d87e44f36c94883b4644e41df2d" },
                { "pt-PT", "1c2b62f8517721659f184d657ea60d677f85d7aacc099f26fe4c83636c17fa92300919d1773e11ae66ae9c36376a534f3a6fb909ffad8399c2b3ecd6ba61d16f" },
                { "rm", "f8aaa3010372bb879b05d5620e542a3d49ed5628578b4d5b54f75964e8491526c7f65ab8881fa7600acf23a09d8b7d1b7795de2652af784797b55deaa40cec3f" },
                { "ro", "bcbb194859417a476b373eee21463aa76949e65e55b0a6a648af17f5976bcf5fd4ee06d9d3fa8a77ef1bd31c2b8aef00a5eba5733454aa93e398cd7a3dd0bbdc" },
                { "ru", "9d0169f053afdb0210e8d85759d38989435f7f7a097ffac176a109454937f68f0ff87a5613677ea8d04ad683d8d627d91ebdbe7d6000d7c5a19595741117836b" },
                { "sc", "e7f8e9f7893a883e978f884019217ffa53c8feef0a04eb5b587a241a579c9c0d01c50e671d97cf00487cd17d8ea382561262d46d144a7b09c8c32c21ad86ab7a" },
                { "sco", "78b97cd4cb74386e0f029b1ce30475fd972b2de893a5702628a8af56a608da648e2c402e7ee9dbbdf5fce3268365a904e2265c8fb8364a74656a3cd72b81f63e" },
                { "si", "31d5890f7a2b4c95652eac5fe46a3123285bd192a276fd0787463d083d9bc1ad7b2a7378af0bd7252f2efed171e3bbe349e486a5f3e6752e5c10d755c231ab1b" },
                { "sk", "5100d281aee8523b592f59b5a27068c1f87ad656a7782373d7dfe90f98b674b21713da41755fff549ece0648af6ea32b315d2afab4ab6c50ee574bbf23b3e1e0" },
                { "sl", "125e64369c64e27c97e91307fcef79fe8bc409e3bff3d1eb39492e822509c5ad705e46adda578e2f2116b1d708b8067330b8b130779028d0279bf5701fa41d49" },
                { "son", "47b33e3ae7aa1510120584d0eff537e308c4e1ca5c084c6510ab46843661ef3ddd82ae5067510b8d9469dd2e162987a718a329a1ccdc1654f4c62662bd1ba81f" },
                { "sq", "38d21c58126f0bd67a3d489f4d2c62144b6fd041d53fd342a3eddb866efa285e9d7b906b05d71ce358276a88c5641313c03343029e723c9a03497019dba491c3" },
                { "sr", "dee20dcf716cf3f629e3affbc0d8fcbcae3450da5ab290f453e88e1c3b157bedf2e7aefdb43bb48b6fc1e1f3303ec270676f87fa24c6a4e5baf962d1dc80c476" },
                { "sv-SE", "329a8c00e1b0610405899ef1271fa67c4cdf13495300cfd659ce9ae69f3771d1b5a75818c28d86f8e1d700e7e84746627a44d79d16d9d000f92338a382b4b552" },
                { "szl", "a7386d7a3c1235da0201263eb43b275256039bbbfcf9a2e1103c08b68e162dc9f12121736ed30e70fdaede5fdc45e94ed5a2753a539269e144469939dfd20b89" },
                { "ta", "096e32f262b70325ed1b44ae8371929d404366d5393a727f066464479d540dc279949fd9caac7f1c8f20c5db2e22e7728a2b46be6a93db3a311f4e5f9663dca3" },
                { "te", "864d8bcf5101dea967d23f351f89cfe45272dd01326c7a8c95ef5f1b4a4be8a15b1de665dcbcb5f8130084d34467188a298739dbd9e278dfc9af091a0a5430e2" },
                { "tg", "d4a91b0ccf18b71cd945620ef77f3e0e8d3746d974dbf1bcadc06ebf29044bd3cef5a2f97538e5d39e9259e0cc6afd095a2b7ffc3aa5abb80526c93d85609e79" },
                { "th", "ba28224a776a593be6f6b8a3be46dca5d20fb414b25d4a1d42e6288fd58d3036391485d0ab44d04a0cf210a64222862e4fe08042f040cffa4d100dc1a299460c" },
                { "tl", "d2c6ff27844c999ebae6ebce92af9b4a923f70848b8d3c4a880e573cdf611343292db4b050bebe7572031bc2d4d8522c806f09bded3893b8978e5996f7410e00" },
                { "tr", "801ae9806e649f149efe301a9a62cdee8e07aa15c1196cd54c5fa9236756eccc029815b43f9d16e03ee016de9318e385df308787f60b91eb193e8cc03fbe4dd1" },
                { "trs", "2ffa384728a208df42ad90b11dd345b9f9d3e3c540fc1910dbcebf1a136596646d33f8051dcf5433790bf22e01ff7b077cc0fcad984f271cdae7a227fa311213" },
                { "uk", "45ebb2dc5aa63c6e8ebe78f993e7df377b754f4f9200ee199b1b4ca717d3008daca929d9eb79af17495dcbbb20ea6439b0018825876608ae2bdb3fa28b64b6e4" },
                { "ur", "bb7cd61245dba225d97b217c65912612a10bd6ffd62e9fea04456dbbe64c6c7609ea4f23d50a8f5f14263db8592685bb6784c1bb5214ac80e89a455875a3780d" },
                { "uz", "457ad4d702f2f4c60d14d0f2d820dcff61daf844832fb46ecc46ec7ae8c60e85f7407236a86fa8d2920b7f425c6758545a250611bf4a6648bef12a519b0ff4f7" },
                { "vi", "d896812d51d62fa288d8a0d5877115b24bf88411d78f6f3820c248ee952c3cbfbe87f92bc2ff2caaaff151d734ad8c29da174373ebabd77b121eaebdecab3ca4" },
                { "xh", "3a2175e592b1212d3abcdd3d77d1449608f036ac31bc627cda3eac6228ceaaf1ebb5ae0852933d0d02529ce0c5fe35d8b63ef7d454b82903e4a82867cd5fb0d8" },
                { "zh-CN", "efbf95c3927e6d2667c49a8cc268ba0d5b18c84bbc2bdb24b8b7b0130c0c4239190b268440237673596820ebfe53405979eff38c0ee428cfaa3d35b9511d1d3e" },
                { "zh-TW", "eb3eb61fa9fa7844cb19fb3cbed523ff70dd2c0286ce69dc69ecef6940286588f76e5895e1fdddab0d9afa3318c5e86f8915dfc66bb4a9471f652f0c625a8af1" }
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
        public string determineNewestVersion()
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
