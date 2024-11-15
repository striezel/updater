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
        private const string currentVersion = "133.0b9";


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
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "350f730775525b1b45f19a982607768fc5581c08240dd53d2801cf5801030fa3d0a7df013820f011fd5a0d2d8a96fd9d9bd9895230e735b83e061b2eea5da505" },
                { "af", "c447303af134e6ea922bb01a31aa4abdd027acdcbc5eb293bbe1b8149280e5b61e96a457c17166ad3014cfa9fbdba95f5507e0fc9ee5c457f5c358819e89707a" },
                { "an", "5c7d492027721be9a25eb174908d7c0b406330e1071cdea95550f25de9987dbdfbc4a10e3c41656da47efa7014f7abc40e9c5aaedfd0b847a8a002529d2722a9" },
                { "ar", "c8bf6a655f380c5da3c6b9c6df37a7c051f7edaf5992becea6e024602a7371c450c6c5d034ccfe6428e667ca9496807063b9a5b19f8583e502be56f55619bcf9" },
                { "ast", "aecdd836c2871954727d39880a49efd636a50f4b6492874ce66f7e2e8170fa855831be983a431ec3c46b1ea89bbbdac040e53f02399509d14d9842e8b584e226" },
                { "az", "27df149d1290f2e8231a1c3de6f15bcd3cd492d726deb8c6b09a6d9befa95e43ea12d54931e7500d60d5a0c1b65090640af38b91fb2c41b13df85852b7d32d59" },
                { "be", "a3eeb2f307bb56b087dd9e085706c49888a04e7439ff9fdae1777d74797d4db1c26915295132edcee668204a79042e9264a9ec506bc7a1943bd6f8265fc68134" },
                { "bg", "bfa678a3655d190b0c009dc0e6a018ab751b9b5cba1d74dfa8015f04a5d17a6ccdac2450f3f2cc70fd3a9ced9b20c1fbfd40953f821a0b770a0297cdfa6e1129" },
                { "bn", "9fce8dff42fb1d09d160987d4718fa801db657f38c535c6f2f7a75fd09bd92a71e1b8f721195a92166bc20baf5401eb168659bafe3ece2454965a85b0d094d14" },
                { "br", "cd402790fdcb8a501309b9db509343c8d7cc7eb41fd82eb9625e7d50f5d05137be78457a6538f33c8f362a7b0d249479259ded070c44898e6689e568146f4490" },
                { "bs", "1a76d77c0493d05f5ef13ef13d64e8f123700c172956fe17ffcfd6115827d8de3847a12a0506e3c5404c8dd12ae584d67d6b93c955e23496f630c64c438d2481" },
                { "ca", "654a8144d9df1e191aff466158fee586d391b9fdf76476c04d67ad9e0f1d2bdf13c6e26c2b6653058a1a6c910743dbec5dae350702ac92d8055563cfd9601aae" },
                { "cak", "eae6d4a68bb6e5a3bad20dc81396afd7959039f2d52c1e79d4e745ed2d5c56aba42bcf1bf89e4d793a613a0cec06a9359cd7508466cc44c268a65a957548d812" },
                { "cs", "bf0ba7ce029c8ba840641a815e7835c35373b4fe8483486706d93acfade6822344ec527bcfcd2edcb63f20521787f105a4c3fa41b23d1e79590e078239a6fd69" },
                { "cy", "c3029c9454f576b3e5417b3a77b3271f7ebb677f2159ad203b88dc0bb33b64a1c6146d55e5ef7d9634238d1116dfc2b567404a5b8fc88bc8253c65424e6f068b" },
                { "da", "ebf903b1ad62eb8294a7904b6ec2936c4386433b7e246a167977ec76bfc2bb433674a1169ae23aa83b713f168b36b66b4dfced2ef8c09b663de766f03d74cc33" },
                { "de", "1c1e34dc561e162f5a6b91c3153f69ee76e4e9372bd5a1a4039705d19f865ccfd3916898b0ad928cda33931af783db710386fdf9b1177a3d7d1958b5ed19b7cb" },
                { "dsb", "59ab5ea70bc773c588b2367669fc1abc4bcd83c0b779ec953570abd2e84d91a7776fc85aa4b106d0a02378dad09abaa1f5b7d4dd961fbb14592c98f0e800714d" },
                { "el", "66318b228895a04eaa07bd928988e8e7da2208eaa4f72a71f277e4c1825c62cbdf5c8f1f09cb22f9cb22347f25169adc8454cd3aca0177b7d818ea3dcd91deff" },
                { "en-CA", "9e61375a1b32d5faa8f15289a091f19416aaa9a6ee1d7b4d059ea8eb5440f0eaf309198a0718498eaf33d82b66062d1e4ceb927fa92368855028d25970786752" },
                { "en-GB", "dfd71a30057a61ee2ae4ac762c565e95688aa2fbf1b2130411134db7b0e392e2aac9f18ee9a867dbced402a90763e101b413adbd3805cf2d0ea16a7a26bb6e63" },
                { "en-US", "a1ad9755bc7bcac49d63ce141ead2a609f4f70d284a2bf8079f6d860122408222eeae7c13f5d57653814110fce191281fd146fa0b1e1ab0140e77040618f5f51" },
                { "eo", "1bff6dff59110db14eb6f71c258d3b3cfe077366bdf908b9023289808d3e41e1e9956ee184a8c9542684b67e2c146c7f98bd8ae8c23be9d7c921774d000c665a" },
                { "es-AR", "c39c3e6e84b784787de5636cbecb8a39df716330667b4b4ff0eea47e871f595afc8b72376f3b53beaa71ccda9b5585c7c4fc7497c42dee8bc98af4ff710c0027" },
                { "es-CL", "13b2c2124397186a663e61ac92e7e324853d2ee08c6231fe2282552d577ba53d9d6c0890e45922a05f4f469a119580d48eba44b70096a3e69528cc9123bb6f96" },
                { "es-ES", "4048a804eca5b9d72f3795d2822193c1907fbd314ee416221537f38530d3bb25d4f3a7ff2aad994d4b5d15556619c75dc73384a981016cc6a891cb5c7968b9f7" },
                { "es-MX", "7c2c7160b13e2168a1f934d392692df7faf32f40c08449a5340a4d61935306c036b4f5f63d7502e749c1bf6b2187cc15dba6c6a0f3a8dfb7aed49ec72527a7c1" },
                { "et", "f093f8ac9cba1c2838eb68b8af93827d4f6885806899026e522d7c343b6aecf7a2f8a8232fbf326ea151436aa2c11919598ba609b39c13d5cd1155b8d3f89ce0" },
                { "eu", "c4fdda53f9f976dbec8ee4646ddf93aa833114a9f3f3d63487e6b7bc849cbe2f98dc422f84ed74dcc0f8ddcaed7cd89951af28e249b43363298794dc82f15283" },
                { "fa", "7371e67bba2a5f787db2db84ab4a34eb4613426346f617285c33b2a716df0d5af827a831cfc2b07604d9152d5d731441cb01a51d36ff26bae9180fe308b845b6" },
                { "ff", "3f74014356455ea31641686ad1c6ac76827e557790ab716168b7fea5d17b03dfce07f663057d44081eb7fdddbcb26b797d42622c6dd02bffeb429d08315c46a9" },
                { "fi", "03e89d1a2402eff095000688a375cc76560c803a00b7d8ad2d96307f26ae7aed0d81a2f9f7cee6e8a8ed4a4cc3839e883a9d0f0e4b3885859c81da09c8f3774c" },
                { "fr", "b7a9a2dfa14be64ea0295c5668ff08f1383453dc6c057c3c5825d1cac8b3006e722a206c88b81cbb3980a5def7bd1c7e52badc0704fd50e9f24fd9e314004326" },
                { "fur", "8289a4c3697452a78620792352385fea1fca149aa67a898cb229520c45b2240ffb2667b7331dbaf879baffd932a9f8bba951d2efbd9352b8c147783c4534f46d" },
                { "fy-NL", "dc3029f33ce8b9dec125c91d1beed3a06664cef11ce8daf162d7b82854e73a3a9bc6ef5e966313c7b0d97418d269ad73739db45036d23f247ffc6cde0e316ba8" },
                { "ga-IE", "b75363e05f532e74ef5c9147a689ef0a6b3aa304da8d6c82e934a2a0633bd4b2335c9dbaaa9eeaf4993bef388b82f87da42c03c179c6b5a248e9e012c1d540d3" },
                { "gd", "b7e77992425da8d37df0f303783d7a4d05478383ed9e125b5d9c122d2f0d2390cc6719c0801971bbef498bfe77f94e12e71871aabb328e3375c66c98423bff01" },
                { "gl", "16688a05d58830be620cff265e3389b85e8b508016044a16afa924383ef43083a2be8f7411537abeb1e01dfc428bdc8eff4e796ead37facc60b74bba8048692b" },
                { "gn", "68f2a47f9b1ce28b038501972d1637b3e2d9ff13e2cf4123f552009ced7942013382be8f10d3ef71544915ffacd45923f39bf253c1d01d34a0128eb161dc793e" },
                { "gu-IN", "f5dde03ddf3af913117e4e6a9ed863d70c9c3c6ed2f8cbdbd7a49fb3a9d671b84d31aa14d183e23b917cd3b339459b8baa1ecd2ee12540f9b97923d7d1b48809" },
                { "he", "d34715ec0b07ea25ecdc4df2c5320ee0773e1ce124a5d2c55c3d52e3e6e4679d8d56dbb0a030c818112f889033ae2324613e6b96602cf601fb70672e96cb4751" },
                { "hi-IN", "47cef63d301682ab87a86c316038a7565317cfeadd630008436d87f7c6408a484ccd6dbc786adc802c7363b7777edb39c4b0abb89a1718d23f852e47cf27f230" },
                { "hr", "b480120e9d699ac4bd3df2b764313fc3850578596d9278982417370e3b3338e00de780b7db17c78412f7714f0e0de866ec3f321c74ee1399b829ed7f10326713" },
                { "hsb", "f28f5b29e6d3e14caea1fb80a98c17cb2a2ef01f030d1a06cb78d912b96065f2e2835b400bce399ba0fa028dcae6d18e4afaf2c100e03218d104a72cf10cf205" },
                { "hu", "b87513dbd04d83a39a11a54288825d3e0869f9e3e89b6232368d601f12157a537a2ca3c4730febe360f3d5803ca66680b370b65ad531c96725c714f902506ba7" },
                { "hy-AM", "1892868614868036f9a7efcc213919d210376d66690d803d6292db161a5a32fb029fa3ec6f98fcc31da970045ce6d5c12919861535cf49782f2cfe7eb392e005" },
                { "ia", "b3714372345586d2921e68251c368e041331b6df9f37139125c99d17818a7830bd8ae84c1ad9635b69e92396e5c976dbc9c99242f7ee0b35a67df8e68d94bf32" },
                { "id", "c33c52a7cc76ba7d84dcbf97b965ba7b7702cd311600b24b90b25795d8187e08b35d7b43b7b803928414264113f994bf7783a279da16da610537fa5cf38540d9" },
                { "is", "193d890a2c28eb528a61bd0dc4a62acc0f928ce99b0f3f077d8460fd9d348368a88b2cd0ea0c588f1f20a8b88af7efbc101402aef02f2f8e1c8becc349c3c5e6" },
                { "it", "32fb2277a7f61d293f32c19bd3ac708a14994ae736d6a42c45e557dc3f36f62394eac94b7dad86cb74833f93c5760f6e60911bc5468a5d5edc89154dc25eb1d1" },
                { "ja", "02b136fcdb509f5c8103a02b839f925014ee260890414523b4d3fd4f15816531540cd9a02761462872aac85b65a85284f288bd1c5907d204590301493e7ae34c" },
                { "ka", "b6d93c4ce4499c24dc31091e66cfe625111ccdf57958ac5baaed1784f0bf541ccbb58608c9812bfbbd3eb34b8993f4a9ca16f61c612fc8ef8768ec10f8e68548" },
                { "kab", "da1430311a965ced89c2c80d7b5bf56594280ff4c8783cfb2ba4d3eb115db829603ad9898561ccf9896aeb6da72f61c6d19a3ce5074c85eda693996b64f434f7" },
                { "kk", "297951d9e742a85e9738e08a5079ee629bd161c32e12e5144fb720068987fdb390eafacbea3edcfa451657ad656ea718d1d785710bc65e5d5588d661df782376" },
                { "km", "62ad27cf2b81622de07a55e5a5151d7cc4422386b6373edf03fdb3dd8336112773b59575cd1ab9f991a6dfefc98762a2f032b6ea9f2e65225bc3852a23ef9ffe" },
                { "kn", "46c62ccd98853592158abdd08c29e6612606da0e8b51e8647af0de649c5dba07f76729f1ae6db509103731529ec881eaff663b506f50a63e72f14e4b2852d367" },
                { "ko", "7cbe898760c0cee1ef37a4360d61081a9751c44130cb1d0f037460d7464701b0b874c41b088df50f6b2a654c8473f6fea36ef630e0cb865cc6c0c9e49da6b53e" },
                { "lij", "bdb5a2d3e147f989eba93f35ae3f0ab1be2ba1fa7e9a6f18a6ff79d4078027aa5288063c146ccc3aa1fae207523138f43eabc113b87276226a16530265a42ecd" },
                { "lt", "83652595a811f769005c51d4061463703a533af298ec5e6fd7516fd79b6168166f05dc5f03b451046288e3f92784845b83e6c6de91eefd0321acb3497aae7a62" },
                { "lv", "6f46e440511a4e20a0893b7cf73476404f0eccc45ba6ae7cbb7c083e79fbcba6322ef129796c547785370e9b142ce2377ddbab645496ed8743822c8279c84e34" },
                { "mk", "2b830f339371b7f002498968001118ebf7a01d0e056bd17e2eb5c3619f9990056e8885f7731858136c052a5e3a502ac525a473f1f5cbda1aae8d7bc1c6e044a9" },
                { "mr", "66048ba2ad7ae8ef303df11681e69a79dff913b0d8d20d5f80ad7b6c6182817b26312615b6d641c3279d48f487a87b2c3b26ff4dcb2e599c4b1157dc376e83c1" },
                { "ms", "a5daf341fb5df0c11d6a4fe27a6876f8ef5f8d0df4ec880589c99d815f3a543db3525a8e88a25f3c93f7743db2eaaf1259972d5b97b4ed09becfd97336ee3da2" },
                { "my", "f0ba0dbe56a97d8bd4103d0e7306e4438cacc8fc3ba5436997b49410ab3dd2e9592334bcbb1e92f79dbda7fa3827f669b944a8e788b92da111c9ad3f86125fd9" },
                { "nb-NO", "ab971334d39ff12bdb719c4b1e8b9902b811d5e98c65d75ecc399fd68dc869259d4b30f33575bf65f2f50e2ebffd57e2d1ba8343c9771dc6d3c4c40c910ccb3a" },
                { "ne-NP", "3ba7f1aa0ca838d4b028bc9290c50a65b98eaf816ac40c2d8d242d0bd668f5b6871bc88e128596992030054491e6971e78fce73a532f64b52f17097abde7a263" },
                { "nl", "da1051a597dd6778ff01c087fc1dae06ad36b57b58adb6e3b7f8ce92f29f9a642f53f8b3e17c01d679bc5d917ebb3a66d2bc32ddbc291b9d2ca12bfc3776d94b" },
                { "nn-NO", "5f9f235fc3900a1d02bda058c41e7c3d543e7e008ddc74a5143c846c2b385d293e7c3ef0cb1b22c9cab86dce0765ee4a2202421d084ee5bbc85d69cf9cf9237c" },
                { "oc", "16fc1ee5694889cd34d3610880efd0aa2e91485112939f5d416eea20edb48e353ab88384e36317988520bfa69206cd7cfd8b944788329b68fe788a0d22f4bc00" },
                { "pa-IN", "5352485b9ccd22a31afe1e0bc5a5b6ef8d0a973a29f04e6bbe4f8d3305ad7eddc8c6dcb7c02874e2223c6d29c159c27f1d59d73930253a301c4b320021d42556" },
                { "pl", "3185c4712d4efe20bcb7c35fb357b31e4b38d84b8ac49e34ca425656a9651dce3f382117729a5337f32bcb600794715a8d4cc531a595b02e05a0355e6bf91c13" },
                { "pt-BR", "562a2e78e49fdd5a62b741f01deec1b33c50b706ced044deca219eabde683c32c6d383c2268dd7b5da3fae0e61a3463615725fd747e1dc2f6c663f84164d9c72" },
                { "pt-PT", "6b234584813ab1b5724c2064d001a7ddf8644540a6cfb52c6927eb298cf149e1b35ec8ec572f3db04efc73d093334aa8592a091842913e7101fc796cd7ece9eb" },
                { "rm", "9a65438ccc56d6ba3b96072db9472d1bceb0652ec5db5844f4928a964ba3a4d18167e3091cc73a298b57e0c50d122d7a1168e68f2abc119fe20ddd074fab4817" },
                { "ro", "5cd5b2afce4ddb69429b9dcbd8d87050c81a36c253d44c3df4f8bdfed1c0a8bb6f1ac160848ae8b591891045f49dc62fbdbcb72160aea4c2270e26032668c01a" },
                { "ru", "5c6627772e1c19e47fddc3309ad4099a7ff9d1743de51d092cb7df512c1569659efa93abaf5d56194acea4b25b654d658f5058d5246e0da216bde1df760f769c" },
                { "sat", "ecf290d30202a11b4b62654dfc387df61f1b415977384d5ca3dd1c8219ed5243a75b159571f3668973da1750ce2334008e2025519af8f0c3965f46b41f019d32" },
                { "sc", "7555db59c9b7e175733104d0a54e482bdacf17fa76f867369e2e5e105b2725b398c9f7bcd5ecda31c55d4b31edbc8d146f24c7a87b03b8922d5745b5d8f63f7c" },
                { "sco", "1462675300ef95e55cad7ebbd5e90a231c6379ebbad8e0338ecb60729eca8d1c8b54fc7f208682e93e48d86c2d7c7eb64333d34c411372ad7d260bd8fed15513" },
                { "si", "3635541c47b3d4939950d417c2458d2ec6f1e922b780dd02b0ebb608dac58f0d6995cdaa779489c4b4d69d632bae9b1db1761961336ea57efb181378680437c1" },
                { "sk", "4d4f717245b128245a71583ea1ef4c2efef3c7b8ee386e87333d4e7f3fcc168e0237cd1c7802b515ea152b8280403d12fd4621810c5de044e55f325b8b355e58" },
                { "skr", "cbc4c474bce54e0f2a0e86ef1306fc85016e8acb885fac4949cd6472535e83b4c281207e8a050b40d99827000c5057d9b362c45c35aeb75d3353c9247e6e4b4f" },
                { "sl", "368468c776c2c36c51dee936680f6968d3bc02910bb280a5743de494d7c55e7f056d1ec14e75ed7cf807112cec675ea12c3d57aadfaf84d5ef2ebb35b6a5a531" },
                { "son", "35036ab6d51c5b34f346dfcda3270cb498012545a72abf8e5b6d290dbd62b9ba45f0e7e9ddb220e5fe003f0429a64b2cb84755eb6089539082035c48bde14751" },
                { "sq", "5018f695bdad482c15707f00ce179b1fa614d0c8c43fc43f508d6a1d65da0362f82cc9cdeb323708a020bdaa9fcd4f8cfcd2e47a7fb7506d4f0cc144882bd767" },
                { "sr", "544e4d5c41f3a11e010a8feb9a82399bb7f7aef58fb256c8ae82a2aad7e2eda73bbb7149913e28d844be6cbbde51f97d6aa745ad920c8a00680f5c0383cee84c" },
                { "sv-SE", "ff0f183ec600ec8a31a19b764c44534247cdaf223b6c414e7f6c305265b7e1adfe3af052825c024a40986ba8a9c7ad4fbc85e566c7e50ba47265c6d58de2fa57" },
                { "szl", "4aa920533d92caf01dfe148b8e3c8ce5734a9c7e0aba05d2c5041a73d202a7e08c45dae3de620a434fc303a7424c8bac179c85b47cedf51793d8ffb23fd30778" },
                { "ta", "32e10369456f4efb34518864a54821233bc55f623f2158bcd7cc0a58e5c06a7c947b56bf7e745ed0c1cc54ff3210058b032956148a6dd4e3bc99835646d38d99" },
                { "te", "793d8a4c1267f363fd732a3e8d5edc38d04233693de9d7881785e92c9d9d6c41ced2c30f44f3a6660bd00bcfb9cbf6aba541ce126c911f281ce3d3e0fcadd5d7" },
                { "tg", "36f85e561f540bafcfad2e1193d17436a2140d6739ae420ab7db925d46f960bd88c49b672a9cc7d887bd22edb0d74b9fc10e6e7e7b1b231aeb25fb464c853444" },
                { "th", "a3a272a81eac2b3fa8916f7bd2801c41453b7141910b5c0ffcdcc4f39966847ddc95e78c2a7c40b92f5c205a67cec6cab29ebb65473a6ce53427142c0413b851" },
                { "tl", "35b28c6fde6471edbd0d859d6f4710fe527fc611b30e19ff0b82b0c76987a6475085de2608f675a55103166176c62d27e98307a09220a3a276d23e69e796b4d4" },
                { "tr", "e5f7fff87dad11632faad3361f09daa281f592ef316783230639b4c487c2b599890ce09bc4c48abd8a39f46ec267e41c3a64c33f7bb6c9c7e67b203ee189b087" },
                { "trs", "3768e234e0443930b538ea5f5db93fe8a396944ddfdc976fd93576eeda4f812801df83507a2f516ea86ee58b0ed1de32e1b437df1e075daca27ba3da1ef835bf" },
                { "uk", "bcb04f8e0b3e20893cbc87af60b702921ca5b51b489fbed5f18b4f7af74eec11c80b026dd28932f6454c18489102530a81a72270d97ece231f3f85344b87dfdc" },
                { "ur", "657abc522dd3a53890d006263d291ef175792f574d5b24ce48306f1b49aeb1221e6eb6c5d01a9da7a7ebc36ce56315751ff3f0cc1c296fdf35f1f43a6ec1922a" },
                { "uz", "0c4bc4acb712740b25f4c56f948faddfc86ae0ee5c0abb92af4d17ba276e2543e2b6299912f783a89a5a01420e86fe0fb8e7e2307d9f1bf88f06b37e082d6f22" },
                { "vi", "0a202b9cdc4cbe470af87763c32c7efed91472439419978b3a8d9bd9bfa0735346ca7095e812390e64d94f88b1baaa502b4b8e2858859d4a46a3b988f685494a" },
                { "xh", "0fcfe45688511b0e68c9c551650f322e7ab019b4b16fc509da9f319e6a20c3c34d293e2da3dacb55f9958f33dff6a0749ee4b34de31bc284d0077c84573747b8" },
                { "zh-CN", "61efa469ef1468eacb17aa9ccc37dc6744fdcdac412dbf21b9bb9bc65999a557f044cfc533ebb56763deb611c65d27d1198331951e619b2ae8b4b23660c82088" },
                { "zh-TW", "f0c27e3d537831c296abfec9ae02a92d08b8ba9c95d35b41dc89da7e2f754710e05e079d40b3510028b84e57344c62e7adc41a24c244b4e2fe2321200cb34dbc" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "551ccd9d031a4cbe47d9371a5177dfd7665994cf340948aa5ceb697ae8f36b2418c0998a50e9ff2a21705d5c4678ef9b8d0a90929b074ab02f71921e54ded78f" },
                { "af", "c848141e1fe709ee1882558dfce5c6b145d2a56be13a2a0f153eb330d7482ada02aff1e1f6f04be39f40e8a2f50dbce2039cafb6adf46fd59e770b23cc45e281" },
                { "an", "aee6615f5bfea2d2d07bd6cd626aeb4812f7c767997c5df06113e3fac4b8890a63312ae7d3dfc83ca4a70d3f47e3e3a41534aabd947703fe5a8761e6b4c95158" },
                { "ar", "6021bd14b448381d1bca0e8b3077107b4568d42102e8287c419b357bda965bd1404430c942036b5cf0b1544cb465a7ff9cd237d42b919738096bf69e587aa4ba" },
                { "ast", "72b543c20de04c8fdb96f18a4c392c1cffb4b24641973f6cfd5b24d4587bbe731a657b6e911ff95154c0fb1db21b6199de4b08704e162eb3010f20eb171db438" },
                { "az", "acf3e4447005844f52eeffa40852b384d28daaea35f8cbe90895392a970c730ce4baaf7c5d61be49482b85b22b937d3e85bc1d6b6d833d57382bec950ad4eca2" },
                { "be", "b1d0da4cc887f1acf3c211202a31ceec7693e034eb64bf44d8f1edc0399d3308f172d0b70b109d68ceea52fdfa6b2f0d5722c02b7770a74336f3e74a69f2faf0" },
                { "bg", "93e3380b9a8a96c0582ec1a0b9d88eb8ae7e20fefa991047e7f508eabdd207ecec9fd853345f7444c6989bf086634b2ef2edd950fe0c2ac6ecf4b09e67327fc1" },
                { "bn", "a90127daa3819d5720de6b9ab8cf99bc998156a07314d87220e90f0f2be7700104c05ed974edbd227fee1716b2e95f15f2346b654547f351eecbef21dd2714a6" },
                { "br", "ec04d422982a974f4aa478d613887435ddbabc229b66abdd42b82350ac0bce3fa6dbb016ca50bc28c144afdb0c97eb4ee2fb0cfa448b2621523d9c2d02362d71" },
                { "bs", "c727b877b2f2abc2cef55e5e5b46d721628904324c9b1fd126a7133dfb912405a476ab1da510bff66fff03914bbd7f700cd54a142a8b9bc8b46f493418a97652" },
                { "ca", "a2283c4b295b3d66eb23b10047ed0b3ffccaed3c1005aec27709251579269872f5df27eb1e686ebeca057d76d3522d62ac8a3c62dab84d8244cb4bd37b551684" },
                { "cak", "1e30a80e820f58f498d24dcd7604bc7473feb47f55313e835d6f05645c544b4b086d2f65879fd762adee12f2101c44ef2f55aec2101172ec1c98df1288b102db" },
                { "cs", "0f7230cb1eb25d5f5ec47901c4dab14a4cec934bd46738f0eb6ca10eb5dd95e66eb56ab2ff6d329a7843cb87871242c6e025099aca4d56af87168c9987fde685" },
                { "cy", "11e0b61755d359e43f05a722890e85bcff147abc57c59b4df52b4f2b58486ccb25705a1b6146bf953a95dfcf48633d94d71ffccc0c5e2edae9bdc93cf1b3a652" },
                { "da", "175d9482f246bd4e585b7f9c8775eef5d540c1e68b7ae153c749bb67cffef75781cb8e03c869f6376da41000e939742cedb42fbd9fb74a8d8eb4ae7a259b78ef" },
                { "de", "739a5f4fb87ac3b462038dc59b55df11670115e63e9e87c944f4b72c54375f6dd3403822ef75b5082cc903be763e027b8ce31300953c4fd56c53bc76af7e6a7c" },
                { "dsb", "0d1066b6ec40c7011adc847f740ecedf386d8b12d9515dd0e75e18941b959c35e591616ab65bc30651e96446df487bdbef3cb26ec6afa5b976d458a3794816de" },
                { "el", "37056854e861f70186205c1384da90c5e9af3de00ab1a01edfcb84013c6bf03c1216daf40bf806d2b123c6b2aa582da496dbbb38cca6f48d4e61537062e4ca79" },
                { "en-CA", "274206b61a1f819e2bc2c9602caf3fed9dcbc396839ca937c187da22ecf945f2256a6fea9edfc1584b49ff942be667698ca286daf3ac3e0d63a5d4fb5942de94" },
                { "en-GB", "0765dce4a7b422830b6b5f705e8c9b26798f79a4b8573e2a646da0cca7b45de6efe61743183f0c248e52cff79458e5a343f8c652f2baf0d0d49e0a247c103bbc" },
                { "en-US", "ed81427cf78a1c5c97885d767c41d5bb9fbaba252a74fd7cade7d7c2adeb19707f2bbe2d177e3f8aeb3a5065eb4010d9031a28f7180aec1f42a74d97512e5f0f" },
                { "eo", "ec118a95746b2523bb36dbb0010889beedafa50b8af9510009316e9a0f2ebd840217c7a7d9a9ba069afddd50468d9a3561d188c3b90429ab0389ed5d625a692a" },
                { "es-AR", "5b6050791e8d4a55c4b3b149a447d89bc019e34700c713540d5d45db7a68aa4bd2b6b642b2c3f8f41a1837d9ec73e2ac5582f303c0e1bfd64b5a0657fbbda385" },
                { "es-CL", "fc42c342d19cba486cff5059c910dcf64a6a140672f523fc8c701d500fbc0850098c18eb9bae77359e05bc3dc5cf2f00b3c314f0e80d87c8c550267aefab4b3d" },
                { "es-ES", "62bfc594a65f7f097409873ba36a5afd78692bacfa1c02fb695c260d180c7560644965f4b3117a046ab375db3e9edbf3a846f2ac7c6f86c23cae8c9819365bc6" },
                { "es-MX", "0abadb2a68ee0ca8ecda5b145f0f44fc0f9f75fc1315329af30f08ac58902c66db5225b6ba963ccdf936f2d58c171f873a697e39f259f6786a974e9cb5d6db46" },
                { "et", "2d8af5000bc5ce8eca3d5849289d5b25da9d33b9d1f35fd7a1f0547d9f93b8d97d564486ce7bbd4eb1621be57650d06c670a6ccdc50af0173005c7d569f43346" },
                { "eu", "0267c06045498058b2ca3b9e15d3f278017b103050997bc96e37dba6fb638c6ae8b03ea79b404c076f77d3b6a8920f0457739e1c68a30359609dc81dbec74df8" },
                { "fa", "f1572a6dbe4148797bad0fc7e8eccbeb38913a632c387e70cb9ccd6b7f87412165929e7469cf3f1104cb319a27f31daab97d09ae8efc51acb40aefe4a15c9754" },
                { "ff", "6804794f084c49690666f4a05496516e7e8c95f39930c5fd45fcb877f7cc7074b9c7a0aaa00d93cfc10c409649c2d243788094a763488916544319ab09f0d890" },
                { "fi", "a8ed0e49558cb25e99ece53ee612d7d0d10e36aa92ee8d8453bcbc29aa41b0c2ddc09f00c7f282d908ef8d2462ced791b5cf83c1df605d175c1a4964f63706c2" },
                { "fr", "4793c8f14c7fe13a2e83da437c14e6b5e755fd9c668ed5c16defc069295dd17bdb598453033c2734a6dd621205666b3a7a812d15fbfb812f194af0028c6c2070" },
                { "fur", "9604b3173438629af4c1a5f07c4ae0feffad3f0129fdff803c2a99a2ac554bd28db214c08ed01a3ec5f9b3781466bcbdd4e2b5589c9818b226a65bf61bfd82bb" },
                { "fy-NL", "9c555d5930776f4995a625f88560515c6ca72b7c1a42d63976289ead98441eb4de1b8a18295baed1845e80a3e818f86a8b49cfefe4ea3316531ebf1ccd0bc544" },
                { "ga-IE", "18452e9353a52c3189d9155ccdaad6338cdac944d757eb236a63c06d04470937041fa785ffc0dfaf14ef582625cc6f23219f2fc353fff831373a07c535f47a6c" },
                { "gd", "2ef2d81eaa57b114937299a0f7ec8509f6c6d7b78f577afbe64b5f1c5ce94fb6afed9eb0c162a637858f51a9e68455ac08466cd1fcb682ea4f58fa854f63572a" },
                { "gl", "8129e245d89951212ce4fbf6e835a23218d23d7dd2db5dd098181f0846c8ac07896cfbae0fba1373c69b6be4844d1f214fa51ac52e28e940d0518649cba39a4b" },
                { "gn", "c9f018fe47a7585fade92a4f545f3c135ab3356775aff8dd62874dbdec5559ed935ecfaf972243d80a4bdb35c396736249d4d67b5682c13554c625aad1abad79" },
                { "gu-IN", "a2e62eedf241b9a4ac4fc6563077861b999ed2847da08d8b16b68ca64863bc85ebd995fccb110e664a2300e50937d41b3e6c5cf6b55bd8f06813f0d882538323" },
                { "he", "1deac6811b4ec0435697cdb5b5db2817444402b069b2eae6364554bf9d186e2ff28b146345b851ba829840b5a245114661433c1538bdd0f9a6342f353b915f5e" },
                { "hi-IN", "f8630a5a0a7b27c223eb6a436f20bf8e7a1f6838006eff6f1f16585e24ad4d47c7cf0f38818dc715edd73121c407859486eed89718348ac29d7a2ce03f75f856" },
                { "hr", "9cdaf87b8c51b947f09b1b92042b1c81a16876131556afbc860e113a3929d5521622c23de9cc1d50bfcc961b3f7f264a099ece24411cec3f20c8942a4f261325" },
                { "hsb", "1d1789e2edc337e03809ff083e530b24fe18c26118f2628bd1f5d4354f8cf287602d0b87e0cb12b485f073d780cfe36a8572f9a01882e8beab0b2d33362374c6" },
                { "hu", "d5f41a79198f6bf769067d41c649cc6ae5d1904fcb51c62ea7216dc64c9169ff255d78a72f405764ae0a2adccc243e23a926db5d416ab9b6473c6eec74690975" },
                { "hy-AM", "318a4c71e38f5744c0766942b8c469fe9505855b030a967da15629054c4521632b0251864ed4942670cf573678cbf1f8d3610bf270ddb28531f0b9ab9bc40801" },
                { "ia", "046eeb48d2f9a8ab3da67174c956cbc3f55451893250bb96abefabbdfdb0c34a3252821fdfc2eebaaea92b2aad105029bcd7c6a22fc9025c6f22d8e9b57b128c" },
                { "id", "a6f491175da32861e10cd7a8b6d703092607beec719d3800cad7fc140ecec86734ad693070656055a6fb81f445a0e70caab35e7823809d1e9980e5fecbbbc519" },
                { "is", "5021a193b84b53ff50dbfde4fa6d80de407c25c8afddfee1c3ec0620c79ab7e2e7d53b95b27d30402316fecc341884f296b8b0cd53d53ab5a12225e4287de6de" },
                { "it", "bb243fd7e614a53fecea48b419a3c744bb716393fec5ea32365fedb402be11cd147b1100616a6c3d6fb25fffd2cdb0390f034b9f25d23e5dcbd3c27fa0edd72c" },
                { "ja", "9387be6bfc1b96e2ab982edde133fdc7c4df64e52e102c9955b35aacc1a2df290a1cc223c607faad39ca9d22406f71d7609ffa19eb8826bc517bc0e322841ea8" },
                { "ka", "02f59d7aaeec70927d25c27b939ca374195d156b739f820f6417e09fb908c931eca16993d8877c2847429670c53518ad6beead794cf710b8c97a8024dfc9bb42" },
                { "kab", "7539ed7463c6920f4e006f8bf999bbd8f2b3aea864c8b5acf795567cefc7f628af6bcae74eca4c9cb4f8fc6894b9a789a74f1b63a68688a6af31b15d867c3986" },
                { "kk", "9103279ee587c43b94a89e2ec0e0162023a7df3ac1ac2d18f55b1092c2859cd3b430707e23c92a7d4a7caae4e9d3741078ea5e92992a3925d7ffab37b9c513a5" },
                { "km", "167070dd5b3e062646c1e9736eec68c8539e22fee486898b0f90f4ec40f6c4d882e9b1133827eb44af3cc3a3d4226e42d83f57f5465de0dcaa7fd4996629d4b3" },
                { "kn", "498b9a34621e040e4b5161ef7e93bf013b556fdac0e020d17aada12e5b8e2a33a33d6acf724895e0377429b170d0c1bf601d1d3e4011fedc5067af55d889492d" },
                { "ko", "9f379ed5ee1d3866f4218f4ae4580deebad46f5023f702818bf220319602088c7fa40deb94060b30c4cbe9e3aadf55ac2763e36910de80057be2883af8782565" },
                { "lij", "949c1597893d51b39add6efcf3a72907b67000a5e11449d033f36364aff23db78b5eab6baf66ee4c51a13dd564e5e36c38fbcaf167203252301b58dbdf987ad4" },
                { "lt", "9f5d02f514cf41625533af79e63d81304b2455e6fd7636a3a24ce7bc48944f67032be8d55f3e18a09cdbc1f5333999f0b1a470dd3e983f4eeed088b63b78c245" },
                { "lv", "65aec7946cae6582f5e8743e1ec97aa6c2dad3e0169a7e860339826cb08af17315b437ad97fddc7c9f36dadc61df470a7132b1d54803f3ffb9886b16d54ae4d3" },
                { "mk", "19d3f2ecd40c17b015fba72c5fc97dc33c463191aaf74d9b3b4e9d2804ee905ab02f7de54e1360671c6d105583431c24b1d3b9745171a71b7eac4c1c0cbc2c20" },
                { "mr", "fdb6736f0752cdb05b650524fad1663a9e11d03158ac2964be47c0d563d5d0c6757612651b9ea73ccf8a4e344012290f8e4b44449137d9d6846478d1c00386ff" },
                { "ms", "c2e972c8d7faf261db713b36855b136a3405520a8fa8a77a0bf8dfd3ae2171265ba84a4b34d5ba91b87dfa0dbbec29659864be108535a2312c4797e91b5e1bc5" },
                { "my", "2fdbf2ccb75c33dc5dc4eb3a977f30b56f2c57e09b0e0bc6e5be29d59e0e0a87a3601e2772846ea868805c8cf104ea051e443c7db32fd27f93cc2e74a8130700" },
                { "nb-NO", "1f72320b03466591f922cc7c8aa8a07eedd367f1e0ad770ff26f7e1c71eabb3bbac9b0520b82a3d81b2ff14de8bf74eaae7fd3cdd0030e691399d22bd1603c48" },
                { "ne-NP", "9d2397b801151208273ab346c990dfd1034a62ee46ad1f754c336edcf79b283f1b545d347e7755e0e997168cb7f7d4b3ea2dbb2a4a203f023c696c08f3ec851d" },
                { "nl", "1b3575f3eee7271ea10ad1736ae00d92da474f31032ef50b7fb6eb4048edb237174e75b6988e978a194834bc6c2bff3a0a4cbbaa882129f697be3140e293d584" },
                { "nn-NO", "3c0f98d9fc5d413a72d15c6c297b41f16ab0a40e74b146f53a1798304bfa8894d76f9e7182986ec133c86ebfaf793a5d7200341e7078a33e04f806e0bb75694b" },
                { "oc", "b35146e45ce51fddae9f124fc075a7c2ef4d9a6f0e6d694263f31dab5bfaa4c003fd62855005d8521180fbd9d6ddf34ddeeaf0dc3ad52713e39dd873e5d63089" },
                { "pa-IN", "bc2e4803e7793fa11ec4acae80565341b24c3e32844407dc0a0b9d9b81b150781ac9529482beffd12f9e9a9955990df943d8d3ce1c92740ceed6e967142afc90" },
                { "pl", "8681c6dc70fa1b190df431b6de1072c6a8b5b7436396300177ba3bc1c0190e0262fe0c76ad1f38540866aa79fe1cfddaf9a0abeddd0a3d0d91baaab23ad7f14e" },
                { "pt-BR", "40ad1d65efe945615d6b41fabafa1cc2b48cae4453cead7995a29736aaf397e057c02e43394cd8720bcd67b3bb12b3a2e5fd1ead563dc4549822da86c4af4d6d" },
                { "pt-PT", "8991961d88f3ee5a4bae228bdb826cc65a6ec9e590002bc24c88586d2d3400f6e21ed73e0f9ed87ce78f48fb30ea7f91fc11857fefaee65bfe2edd470a66c6f7" },
                { "rm", "db6f03f07ea4fd119009dd1ec4eb8fc88cf881fe824ef95f792a21bea7d526310b5a5a42545247a7e009d9701c2f8b2e899221530e8d8770e4313659d3d371a1" },
                { "ro", "cb18f29a838056d48219aef360f4d626533d15657dd87d034e16ad50d99842cedf131ff1010a92c0c39fb3c839e76b06d0c8d0eb3165a75895f5182cdf44a3cd" },
                { "ru", "4be346df56692d9d539b113f3884f47e99888f8846434a7ed837a62206dc45992a3600f3075ec58644cbfe36320957a9926b8db231c6a0edfff630bd0a8d298f" },
                { "sat", "df5aefeb12d51037cbab2a5af451d553f2cfc1162bc28d562b2b0029b65180d625b1432766ac87d5f423a3a1872945ae2a1af5fa3dc57a418d96d3387e255417" },
                { "sc", "aadc423d385c970aaf851b6a19a343fe1e3fc21474d43bf5b8896d7d68e2f7c689847725541da80d7be71718b7f2e49810a0c6b86a6468b0f88938bd30b53654" },
                { "sco", "3f1ce125ad5d6b40e6693d62cf270561a044d6ce859aff5c4c4f8526aaf8244fbf9f7387dad0d6d7dc8dafb1f8a5cabd7ad118c67fe2ee3bdd00946da9b00dd3" },
                { "si", "c66a9ea1e01bc3429874da2d4bdcad0398f13bc54d5af7f4b2e42abd9260e9b2c6ad0051cdc078468fd966e123e24e1b9fa5b12e26a9b513f395066adbd05372" },
                { "sk", "f98ab072e892551da2b65ed54db65e05c56d22192eadd929694ac23a3b40690c97b382effa819b0daafa425d56ae749fb8741f0c31f585c8c94bf934ac700c49" },
                { "skr", "7cb4497bc091f91ebec2b50e73a3627283b53ec4ae934209e677dd849d781334eb956fdd8a42171192f42c401649c8881c1d0cba4354950b996852f2130916e3" },
                { "sl", "af6951c326cf8ff47e12b86600b0d42f1aea1b56efa3ef3249d267d836b234493727e07b666f0bae7f31f304e911c64a7c29cac691c55ba50ffa1059dc4e9230" },
                { "son", "56e7cab55efc236356944e48cefa7af78a611d9016e426b1e5cd0f1783af0fa79a80ebc0535629dbd4a937a3d91a8ae8994125d6d44b09da206d2ddb1c488432" },
                { "sq", "a8092c6e4c8479cf2bb40c3b7984c1fa5d34fdcdf3865388e743e0c150c3b94b0f14b7e61f0e9ee2b06acc47c21259cf8d84416be46bb0e26a421ed0d9209d1f" },
                { "sr", "5eeb5ead595452aa053ccf182b32686f69e5afbc34dc13e87dd5daf2ea18c5a90489475b09ea9604758a58905481b2f5883c1483bc6a6db192bbde7bc19aa6c1" },
                { "sv-SE", "101c73342020e84093a2a83287c8792b404d08ad76ce0b3575962389f8c5d92ed4b6ecc0f436740fae727cc540e5cd1fda59b77de38c3e8b6c6c9e21f35b4774" },
                { "szl", "6a93ec7f74dad68f51fcf72e05bd8a900ecdefd17f3dceae3c4f3faf313ffee46382e4ed90536ce41380367d653e10b03b33234576853035acf6673fe4aa41ce" },
                { "ta", "0658a4399eb990f75be785e1657e68a7f02c0ebea885c1e99e19dec042c833d5ff0ae5b585e9b2c965d633003d8b2657a497bf7440437bbdb66a3fb5cab35ba6" },
                { "te", "d8470cd779a1368b7db5ca04fda0e01081537f95cd311ba340e5fda3f95e976f5490edecfe27b4f35a61a64305a375d5744caf6909ea98e206a8269673c15e35" },
                { "tg", "bbfdfe340406cd0879aaec7c61a1ffb47badd0f6aec8b4854a7ea4f690779468a57bf53fd0ed33f7ee46919d00f402fabb418495cf212081a5321bf5dc071787" },
                { "th", "26e998d817cc77c4808e61c52a9b8705a03f538f63da360112ebce0a6a688d7f8e0372f5d0342791ff8524edb6431f16446ebebc2927d27666fcd7652dd35996" },
                { "tl", "7019725c02a825f7c99dc419153b0a7436b870cba24ac2a77317b668fe9457078aa42c0cdf5f21306b69a50897441d75c1891452520dce48d9ecd021428da2e7" },
                { "tr", "70d6b016d79afba4edae2045c2bfa9fc4623b64af254d5d22bb893d71e65c2bbde5f8f2986d6569b9ba37f3c0712982b9760b1e32f23c5b64d2296305891ebe6" },
                { "trs", "5b694c7f5114dc72de721f1fc75dd089898bad096ac90737b123f3b754514369e3f9d02c150349fc7fcd7ecabf55fe1a4335064be18d9e10d9aedc87632d8a6c" },
                { "uk", "a19dc455d6bee274d63557588afbe6ffed4ee2a9985c874edb152d22729eb17464228f3124af288c5250a0f2e98106c431d1e7ec2f03ad67379b985f9274f260" },
                { "ur", "04435fa3c1ffa94d09a1c6a72b04617d053442ff52740ce2a91eab9b4c1bbf155b1ec94c48fa0594b424742c4e0e3e33d4f870e66b537a904a4b3e539570db13" },
                { "uz", "45767168d223e5eee4b675c03a5808647256c948e8a66e89663926895a13a784670ab7439dc176f313610ee727d18c6533317564c23cf396f93e5a6866758562" },
                { "vi", "1de282c47888a54a2895b4aae93937c59717cbfebe910bdd68d8b7981effae4175bf39e767930eb64aac962c4096fd22bf26ccda231dec7795de84b3c5a2c47d" },
                { "xh", "9d0d702cf3f47801a0d777f2d8ff5edda0a825e4ff7ebdc44ec449b05bc6cc93400d06fbd5c3390ef0b1ef8da868843a19cf8fef20b2b46115a5342efda6e0e1" },
                { "zh-CN", "9d3963285f29c5accc7016bf4463cfe07e3ee0e6f451e5bf737b4bc77201d92ec42986eb4f67633e861a286e88a218fbbd6294338d06cde95368a49691f90aae" },
                { "zh-TW", "5b6658196489faf841283dcb2f737a18fcf8f2eb925d2f7abccc4821670bf40a33db14255fe995f703891baf716b0b29a4c580dc0625f1336dcb3301a857f100" }
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
