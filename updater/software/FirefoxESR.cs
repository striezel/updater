/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Release Engineering, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


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
            // https://ftp.mozilla.org/pub/firefox/releases/68.7.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "f611c35d005980654d13b32c889b703d0ba3f59813b41c3cf9ae9d4710e036f6dacc29f911e56877e15086e29a0ee13628317533aa6aa260b42be164c5419fdd");
            result.Add("af", "76d20af70d105bb793d9fc393569dd645a096ec23a684e9d4aeb64ebe4b28cd18f35ef459bbb46ec7f8b54078237ce41d5def3b475bd632511dd58758602cb36");
            result.Add("an", "fe2ff2c534a1619cb408b0ed01344944a375ecd3d5e76340899d282cbcbe029e4d3878d5077c7aee31eaa98a53a5b885d70498ccf6f38c13aee89edb2dbc3775");
            result.Add("ar", "887d243f4926bf1c20c9d81966e12b9f7879469b0c3723c9c042717d03db33c77221e8cf1294a8a48ec5134ccad4e72cea1df2143b6f922f530b67df58534a2d");
            result.Add("ast", "5a8a6b8479b6e31c980b4ffcd056f26fd856411e432e203868f8147803808ba3595f261a7b71f6281d5176d8bf117b628f21bc86324a1fc9347fd40835caae31");
            result.Add("az", "9ac650e6612273233e30b342c3d06d971ceed021c20b54336ec223e0df5473825e0ce61563de944c58eefc1f6442a83c6126e024206059f832941dd92245e269");
            result.Add("be", "9cc88dd9d35806f82c93a6dc046a8a9645eb12c92b19f191aadf82101e720bf1f3f42ed7b0e8e9298d367f63d861194be37b92151a4d6f7f7253c2546e459db2");
            result.Add("bg", "1bd17d20ba989bf1b7fde6a19d3adc8fbe138317b81f709920fa18f37424cbecc25fb5f65af3b1186e15242a5952af46983214d2921b486d60dc99f3d4215459");
            result.Add("bn", "d82c9a9f30c992a11764bbb87c37e35218c3c06a40d3ef42fe670ca10c3b414104f41f88001b49d47d348bf24c9c5695ab6eb2a46c1d7478178d982523de255e");
            result.Add("br", "d93e9da73df50716cd8ec0a8d232ca85c4e8c2fbdb49b1018908648b8086f7229385eeade38bb9113604e423005c4df3ad44c8ebad4382f0d06467023f774208");
            result.Add("bs", "c89569b6234cd39eca72f564a1fa020866b1c2de68f6f121b9d11a8bba63394acafccf2c78a1a346391eed785455d9ae65625832df65e0ea3937ceb431825f81");
            result.Add("ca", "122f43ae96e26fe15dedd69e5c8d3ec96d343a482c5e51f095f7b61da9a40f512b68ae6845157320f7c90b7296fdad0b746f4071e208f991a8d7023f50348092");
            result.Add("cak", "782f3ba34ac665c9bddae29926d52eaacf3deb67a7c20a6c2bd2d4db850ecd2c42ed09d72da2902412ed92f002aaa4ad0bb25e64b657336d45895f875275695e");
            result.Add("cs", "f15cf6fe3b5a32a6e1e59ac23f00fe78423f660c554ad17120fa6d9c1bea674cd0c2ea89bd201a38247cf56c6b71b30915cd316aefa59887664c20b245b3ff3d");
            result.Add("cy", "de85d3d3ba034606701cbbc62351bb9215f4941c7c73f01758e51c4428b1ffa44f3fccc475c01f6e3dec939c6d199bf1bb980aeb312680c706052472689f8e57");
            result.Add("da", "961b80adcdffd071c7c22326d6fc61768dff1c619b72d52a808af2a473b07bc5c12fc44feca5a82fe0da557eda729f3061888da2dc33a0fe43aad72932ed29d1");
            result.Add("de", "3a3a186e80678b1211cbf10c914b1945b745b29d765388fec348317fec80f0033e9d734a4c0d9e86e319dd731cf221d135d418ca0459e86081f2bc09f579accb");
            result.Add("dsb", "8c48b620516c99d88df2050aa1eabfc6b0458ea7e0d537cb1d87e9bcc61df5fe42df68f24e31b5203c3de50ca8a4f52aaf12ea6dfea592eb43ecd019e5e9b8cc");
            result.Add("el", "662788e4b2d16d7b0e79d113fd18b34085a4ecb3c8b3078c2e2f7987d87a6f2134416bda34819359aa75b395ee1cc7370929110168b244affad709773cf4d606");
            result.Add("en-CA", "f646335cf2978113e56490c2ec56016b4b92910f35e4191eafb248633b54adcb00f82497e7961df9861ea2f6c3016a16d26c1b2269437af4c20d0368c4560aee");
            result.Add("en-GB", "76a3635b9bf09444e7da273b7b7d3b070ff663a193ee6a804d4ad0b7c923579cabad33a04067429cc029a4c792c724e4c93b6959d4f9df742b940a120db4c758");
            result.Add("en-US", "3b977c1338016d9788a76af41d6324e35440e19f00581985fc2e3ab73a06d8001659654652a29001fd58e13e65bbcb42a52e33784954c62402c8bcd9e846a35e");
            result.Add("eo", "3f188fa1815e933f2e3af63e1a2dfca1cc1bfc6d0ed204afacb443048ffc4de5e18f56880bacc81aff0d7370115d7a74fe4487ccddf82f8771b6d941d7c9327c");
            result.Add("es-AR", "7836dfa86f503d8861cf2eef8f176298439c63ac19f4d66a00a791ed99e5398cc8fad15dfa7ca0493b7fa01c3ab4d64b8ab1f1680ffa1fd4f880e7cee32b79d1");
            result.Add("es-CL", "8c9177c58342dbbf2fc18bad868d3fe6e21f04eb4172bc01e1738499bd10d5c365cce587d49ea13c9ce2cd97c35da5bfc3f5ea0b8c4d09a5974610d2ed5f3d52");
            result.Add("es-ES", "144c4f14908e7c495dadf3729b1891be56f072f3d80ec29e11c432170c93f4376edb8a697307d1ba058cc41be694358e47f3ba49f8dc37b6e3f82fbe69e8c197");
            result.Add("es-MX", "68d52136dcee41fa2b3dcc4116820c7edd2a787b925d9e01cc0a3bb1bf8123eda1ef1095e8e054440edd2dc4df9bb2fe1ed0ab5c8f23f48a53ff9cea57e35ede");
            result.Add("et", "85206ad836d824c12fcac5acb5ebaa07554eeb00cfda536b1b235a3cfbfa1321d487bac2ff89597dd52aa404a5ca3bbc317abdd9bdbeaa5925e74beb030d0f2f");
            result.Add("eu", "aaaa023f576d07def8932882215d2819c905cdc7f13730011cac435cd6c7d1ead9d23e41839f3376fdadb47d202d4e3e19fa2c00d924bc209120e024dc8a1a03");
            result.Add("fa", "f3c9bfccc6639782597ce26c31b15ed477584de65ac2233923107b06d8c43f702d56d027076b4ce1f7b24937db6bb21cf1f2116bc8340bf6ce7179f3bad38404");
            result.Add("ff", "a4c3c2c45dad95145baed62661bb03843d1f7e60c7aefe983d22aed903809f5fb15f28537c913e3bddcbf9ef89354490878492825ab8862a3b1ff13dcbfa3eea");
            result.Add("fi", "09f7e853cef05cf98d2e88db7e64e79bc2468941a41958a583eb8c0eb1624a39d1fb341f7c4aa5a27c5578dc61ca08adbcd8bf248a92bb8c080ecef3849eda50");
            result.Add("fr", "ddea879be727b02f8a5578cbf09ad0d82f6a81cced3f29482bd4df486f526a978fd947fe9dfcf06aeda39967ab03edfeb318ab0d9278db9a5804e35d3a1fd3f0");
            result.Add("fy-NL", "c23877d2c5c3a121ed664b522cc7318aa7d13265bf80389f013e32d806fc3749a034790e1894a8ef0e21f28c206f03edfbb35f00e909028f57ddff9accb3989c");
            result.Add("ga-IE", "a490a599c656cd00b4074fc3cf6afb51dd871284ae990409a12ab44654f875de5e01cb9e0868f45261d81a2d915e4da0c66d6ba9ff43771a630cdccf1c9f87b9");
            result.Add("gd", "3e506f2cc7bf6d1e6326aa4df98be91eccb288dd4d5d046e04356a3ad7498ed7016f13fc56f3cf19fd6e07c5ca60d5c6e8ebb95b4d1abc337405d0a0dfc04606");
            result.Add("gl", "33701c5c1d7f9a7c1388c4ed885193058b0cb375bd62d8682d25dbb1e784a35c69d725e694086951dc4b3f6db0b1c935bde1eddde1ca3a80423364e28ba95a29");
            result.Add("gn", "7d415855aaef38190fe3a9a97ad7f2d030a2cb5804ffdf07bc6a29ef1a6549675fd9531177e2aae854015e1bad33935352b9392a1b11a6f889498c02605c596b");
            result.Add("gu-IN", "150eb52f4ea8a1865ccfbc7fa92eb96883e1623a7bea2c35b4595ffe825beb47e1eadbaa5f8b8f38a64db24eab82819b1dcfb76ba8513a3dbcf9f633dec654e7");
            result.Add("he", "5d866bf8dc326697abaf5abd509a35b4b0c6f4230617e4ab65cc5b81542307a0b44bd5b6d87933d4ebae3efa5c20eeb93eab5706173214f1aa777dc83792c40d");
            result.Add("hi-IN", "4c5198e1a97342aaf315ca160792c69a52fa3b2c802869b18b3a0c3a8af5c3b9f9b737476a8f7ce548335b46af8ff0db8a940c2d92b412d71317642a0b81186a");
            result.Add("hr", "9d8d9e7069224694f124b0234499c77101c0f39487065e257f652f344c0da33bc15d002bb3943cc97ed751b955c8719ef9b0313f81c898a18096ed8eb104ce2e");
            result.Add("hsb", "e1860695e00fdd6b205c3f4bc835bb656b1e47fc9c555a5a0f0336af87c85acda257c30daf21a55162abcaafd1ca78d1af488426d483a97591e80eefee391893");
            result.Add("hu", "ba72b36e0baace84176d8ab4295a201a48a6c0c4594e17f90eea999103b9eef5713d6d689367ef24f2eae496e704ec824bd4cc93eb4b6dddf2b165bd495d6fbd");
            result.Add("hy-AM", "ccc296620e6cc77d424a20179972530b32245f1afc03946798280ca6ccad430c4c7ea3852b634ae7c4a71f1d33bff8565432ddeb7775f956b75cba890e4d5f40");
            result.Add("ia", "3f8fa139dec6e88f01b571233992c8f78c104d513e75feaae864100c19abad70452d88e5dc8cffdacf6da94096508886f1a57175bb749564fc899713f00a6ab3");
            result.Add("id", "4945f519fe753d95ccfeff80e003b6a5ff67d74edb5c9cdd3a569619d2fa219b420e41abcf2a13a20cf6da2286bf7b0e1cb1d44523e9320b76525f7a42d9c9a7");
            result.Add("is", "c9c9c1e7ca454740ca7615b79f7ddd09d2c1bf4c73ba436676ecb4eae92c45bd091e914f28c60a9d2978239e12833072cbb68952d1c1a69c4e7a6dc7799b1364");
            result.Add("it", "13820093eec0bb3cc2a5f215a68115975a4cb528a75e08a8d7b7f3f393363064fd80152de06d2b1ed151fd0a77f5d80c3c678bff52f9d0eb7894145f392bd25e");
            result.Add("ja", "328fddcd4d408c5c9c4cafc9978a746a14497e14480cd2f733ce07f3d8c3420b6ebedc18d2ec9b45382d8fe33c785bed58635f9d277d22d4283439ff59aab949");
            result.Add("ka", "4f4edea968aef1638692035b2bf817c4c0ca1f7390d7a2d2211dd2d5112d4699d3572d3f3973d88685eae1e97a406063801fcd4706900af717356574fed9c658");
            result.Add("kab", "c74dfb19e45c43831774f8c0ca3ad91c7e4101fb400b6383d1e5ee04ac8806affe0bbf1e888c43705d9a6ff9fe74df7e13c321c7bd51b9200b9bec66523301f1");
            result.Add("kk", "12b7daeb4b6312a78e9ef3346289e7e5a3620d3c5b95dbde0305b9eace954c99b0fdb9ae61a5b7b964baa72d4aa95eae7d42837eb66cdf5e934ebaff20bd5fbd");
            result.Add("km", "9ddfdf16eba24820ac71aba66a083e29a89078068d04d8d138b3a82b901a6e6acdb523a23a8453a110c4b6059ca25d131425ae172141793b7244c9e16e14c7f2");
            result.Add("kn", "d687e7756ccfd8076836dd859f00babbc31c407fe2f0ce1040450278b76574855f546e0735f8a6887c7fc34e43f5e101e233552f2fa941a79929e128f742cfd4");
            result.Add("ko", "8dc89de9d7637be7b136bcbec7e4709b26e1ff80bd0f93e1bd92e1933c63fed50c0805fdb9af96e5f822cf1c7728c6d50555db642b52d01fdef2c81c2cd29256");
            result.Add("lij", "90aa8f44fce3c718500b185032538d867d458f4014c507e2f35135dbcdf38a491370c92c4ef1694ae3b8d801f10b490fab3f5d958bb8997d9ce37c713f21f722");
            result.Add("lt", "2013aad5ba0f697d3c5ebf16b89e3db6119da0811c98137a12a603aeba0220f717a4bdd42dc3d3efef6cd49acd51a39d8ca74fa3641f1bbc25de5f9c7e4a9037");
            result.Add("lv", "52080869869a9c13351f596300e29ea4de605dea08a351a65bfa9163939a50b2e0a8360124cda0a77b2a6772c22d36293781e8b26d87abb989a8c808d0430574");
            result.Add("mk", "2e96f425eda31d6903bb2c22c8cffa67e815b9b0b74e6060bac569034ecdd4b9dd1672ddc4a8eed229f2d1c9475b6f674d49c6c123b0df32bbc7d1688731d764");
            result.Add("mr", "8877b7d319d9493144d6f7756d4040928af75f8be4c6aeeeb24fd0aa9195ff0ff520ae8538f558574a6d6c869495a02f8f4d50a17c122e1f0b56376c18c56d0a");
            result.Add("ms", "54f3cc0a36424ac8f51e558dfb81ba3feb040963c8e8886294a3476aca9c175a2e6fc6ded4f134b7846f12ddacc0cc630779580b4a8a645566597a38725e399f");
            result.Add("my", "391259c0aecaac1ce7ad8e9683a37c89363cf9a4265a91dd3a6e284860519420bd1a18158317125c2b6190f9367af30c5abb09ddf4b3affa3250f30a328a3357");
            result.Add("nb-NO", "522d1181b042bdc1f409ef37e769d164358737b8291167730e06433627e6b089a5265f114a5c553226aa5c7ad1ddaea4ffd5ca6cf81ee685999ea1ca62714a34");
            result.Add("ne-NP", "05f5e8cb7f7db81a3896caee4025e09b20b4836e0c2a13f92eebe135ea762e608fd88c07719493d530c2b588d5a36a4312e05c8b845e76834f4369118f6c75bd");
            result.Add("nl", "a2f48b72111e94c38b3bf04e271695d8cd0569d06b119fcc8fae2de3d517c74d09ea81e1d9b3c7047c0d7833371483a20063033e8985c7b9387880671577a9a4");
            result.Add("nn-NO", "6c5c218cc807df5ef72749bba0a3742d84065cd65462330c2d1964c8e646e0f08b41ee2ad7842b57bf68b47180e1d6a1c628c422ed00f933e81146b733eaeb32");
            result.Add("oc", "d045ac77dd0536cb7a187f45fadd4339664d1c6c01c7c9435186ba420d3338b644148d9551e369e5231ad8e574feef277ddcf212e035286d7d7202a1bfa6202b");
            result.Add("pa-IN", "11bc73f4261e06a8e6a3c25e7a84c2bfbf76b03112a4bc2ae279d87a6313048e837df7ec314d38ef1f9a87754ced077f0ea49ddea0c285e1b6b1fb3016f7313b");
            result.Add("pl", "6359dd6493326d10380448fc7d4d9c105e242e6eb4cb7d5baa1ee6004fe1d82e96aff705c18caa7f2e2b01750e5dd9c2bd04ebb7897520e569160fb28e60b14c");
            result.Add("pt-BR", "06f14424fd0c5ab96864e9d08aee9477c930d45a0270904d948d0030d62bda1d290ddae617d1da00af6bd2215cda6b9dacf28e7a45dd9eaedcc38269b7d94dd7");
            result.Add("pt-PT", "844001bf8e12bbd508ad86d5f06137ba4fee5d1d988329a2d6de50db0b1e11af9b57d781c99c9e511831206c07d041e69987215ec29d2d991eda6bf593bd0fdd");
            result.Add("rm", "10c92b4a32e9f1dbc64fbe9dcc84073556a167d3fb292868b5533418a3882e80e8592a256a014d59c270b82523091945511b3ea6c57337b63bbef3d65b2c7fce");
            result.Add("ro", "cdd35c6af772edbd5e1d48b4452f416c5bc8f3c90b9fb8ecb5d4ca9b39d479136f8061a584f2e3e2a6f4589212bba2006d9226067db5cdfa1251804c3620051f");
            result.Add("ru", "aa90c1e1ba8444c25e0cf51ab165d9949735bf6de6788846ac1cf414fa13e5fd0f90bf9740e97808585266e744815501ab1f8fe1ef5929c3afc21605a43dd302");
            result.Add("si", "7a11466a1da8fea09870be90f094393218c05ac8a9c4a547ac592f952aef6d78de413d41e6032d610af581e1af5ee7b176603d98e6688a2885bf3579a4a32ee7");
            result.Add("sk", "3ea25ac35921e59f7b557e4ad4f525106aa66ecebd4699bb63a6d7d896ead9753be09af6fc9e30ad14f41b059d243d597ba836c6e4c9e5607e684a4c70fa0683");
            result.Add("sl", "ad9bdc9df0a7ffb5ea34156a4206478d822919f288b82cf392614a493b5805af2928eaa1b6479734fc4c237e02423713f3c34815c7b38c77f4e5b759d64ee4fc");
            result.Add("son", "56bad8c169c5f0c4fefc44269657a29386ed95383e13e81608f3a825f7b501557fa4816238b5c50c3d109e27d1376a3d5cab88150602c0fa5b2316cfcacf3d02");
            result.Add("sq", "bc72402df356e1da9c001168a6e302fcecec12fa142e4fac4e88dc8830a559b0372b58b5b0aaec88e9c11668fc879f1904e66d6a0e1e5c06305f32ec1f00978e");
            result.Add("sr", "8d7dabd1bf2877260b3f2df5c9d4a2e3797ddbd1b4edcbf78a09312592b8623e17664da41f0a2576a0ab623238c522afac77ccd48be74603fb1b747599579e4e");
            result.Add("sv-SE", "96524fe0443f3dfb927641aa8e781ca4d9491a8678a43b6cbc5c34ca0a69b1a34ebfa781f93f5cd3f84e060723714e175119619306ecbc36da19c291dfa85544");
            result.Add("ta", "09e6a2a086bf1f6215240c02ff563d66350ef3148f9eff42beb4f2d3edcecd504797143b7975162b3afc8c83590d57ec0227841e04e5742eaf1b89b438468131");
            result.Add("te", "591b2e99d0d8d8fdab1a0a61b3988c448547d3d1c82993cb8c8efcff2299d661e2be958c22f8365618fc9f8ec3166c292e71703f91ba3860fb4aa00ab6b63cb8");
            result.Add("th", "01057b94684cc0207e357bd83754fecdc80f793f3994bc7059728991b38ce6a97e7c2561919da2d33bc2f2a63bc88fa474e9f382cbe2f47e7c1f5b6497007b11");
            result.Add("tr", "ce67c7e9e4727302a17213c8bb58f68756725e4be5b129cc3cf3672fd8be30b26745f323b16a54d9ebefd797ac17c0b6910a622fd1dfc71b9327212710d98342");
            result.Add("uk", "a81d8442543411ece89ddbcfc4e3aa6683486bb5e1ac3e28e2b491f6c24eefe6297199762082680645e4d9e22b33083767e452a46543814087ee5c07c8651f43");
            result.Add("ur", "96977fcab169b9477917ff5a8a964c2454eab504c95c07481b41b0d2e8568ad9b69a71284d03c9468fea7117156323e38c596b532157209b0cd094e60f92a4be");
            result.Add("uz", "4ccfdd5644e3434f233de25611b619ae9558008ef126cce0708ce04e31dbaac8662432eed47c6350563ee1df115a3ac3cc13f9a6f8b0ec7656223d43fca4b184");
            result.Add("vi", "be6dac62a2a3fd812b29d1dbeb752e950697c69ee8c32f295a6d2ba597af661e9c4c891fdbd4fa4cddb1d4009a7a59380a5b5cf27acddcc1fdfe961134f2cc47");
            result.Add("xh", "92981a66310c7be7890461a38212758d33111cbf0f1ef812a65c71c3286169d31952540a82c3db41c266ec5c8b9c5d63f38750a1af3e957b106a8a5798ae067d");
            result.Add("zh-CN", "66587d4c1642ff3ba6bfe80da82220027df7c5b6c780859260050efe637bf0c3b1289f0d1523d6d92ba58c60c2066be6e65dd3adceeb5435010742850543f9a4");
            result.Add("zh-TW", "382935221ac97097bbe5077aa8f0214a102db0f9374db27e22b7121d34d4ab20cd2d2ef386cb98c41f6df70bb884dd53f4f0dc669384b593aab8bcf9c0be40a7");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/68.7.0esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "9b8c7118d4f90c7778a1824360948fb9f390672f225a3da4557139f794ffa36ed0b93216f889289225f4dc6275c5f019b834a901a0d39a7f64f55ceeb2afbaf3");
            result.Add("af", "6fc753fa9423634995dbd78e0918625067cb92479d38952060922e3294481e202aab3e72be638b76f4c3cef1b80985239a5d517223e8b3789bdb916e0ac96d22");
            result.Add("an", "3237376039fc94d799cc5b0bc182de39fd07b0d9351ad9fdb3968126b8a76c916665a24ff16e2b568fc2153381b524e821237b1b8d4cae2db91aa86ac2c7fcb3");
            result.Add("ar", "2828bb27237336f410b90dc6e9b2ad88b23a4bde5c8f6958ac0e5a862c005bdcd2aa75f9045838e6abd1dfb17b0fbdf9bed48243764f717df366b098a179b8d2");
            result.Add("ast", "0815cbc814e809db2bc0544189963643f9d259aca96b628ba7807c1da4c3cdd79d3ef7e8707ec74272a7f268f196f23025547a8a66b10a7f29da6200f6a8c245");
            result.Add("az", "eb6a44f8e55e61ba419b7b86c7b27383ecdc0144ecdfbe203785bbe2847b21c64ce5f3435ca60889149779f875b017eaebf18cdfdb89f4b63380b5bd2aaa9f67");
            result.Add("be", "a990c4ab40f1a1554627d6e09a0cd744fe5ae3b78f0bc323cb1099fc70141a48e8cb7394c7ba1871497efe5321e9bf5e1e6767af7118073b4964d9357a1b7b15");
            result.Add("bg", "65eed1e2363b3b62b245e182b6acda4e2a84a6534d8759ed24af78ff9618d470a16a5f72199f22838848fd7e6d8eb1bb807e1fb3f49c4ab106322ea001b88c6e");
            result.Add("bn", "a5081073ce803ea261d327c731fc5f196b2461dd9214f298cde8a81773fb13a3621e274b5241270f04d00f3918fa266a35414c35e17fa1299ba61f7ae1decf1f");
            result.Add("br", "207e19b21dc451013b9c10a23b30aaa96de0613795cc178cead76b3db68cdcdf2116e7bf18c38b3646d7e29f3292c1a162d106e78e07313f1adaa2e782acc399");
            result.Add("bs", "ce246821613db6908bd31394ec3edabce5380c6478641f7e4275556cef8ab7c42bb7c444d3e011c78740a62ff6b6675eeab897c96d4baf8b289a7bce5d504a41");
            result.Add("ca", "8fd24c3607b75057520ceda687c8c58cf7a34b297f3644a3749ae09e78d1d4691b395615d5a7e042e0a270805e47630d9a763741d8853c8d027aedfe8318f632");
            result.Add("cak", "c62c79f5da7c1578f7d828c9a1d8269efb729d0910d686f9f199892ffd1e6085a794dd3a7538f068a60151e1ae9924af667891206153bea06f65b3601aa3ab2b");
            result.Add("cs", "7821a0713531924ac16227ed232f34dcefef91808322fb8a0e61b9b1faf149b3ccef8fba60d4a82b2be1cf6c26b219fb521ba57769f1bddb0d35f467ca28b8c4");
            result.Add("cy", "756ce0ed4c6fbd697f0614a304cf071ae604245244650b38be5c3c5d4aaa6e2bba1d7d89c7035d7a1f647b84c9a4ec87f57ab20b5a5691caa68b6b08b8731429");
            result.Add("da", "57d0a93847ec50d990c799e0be96be0115b80886573896a5fbee72d2992919bdfaa241254f390959c3d5731dfacb64c7a3e3aefa624b85077ac5c06b730bd905");
            result.Add("de", "3321e6ef147591a115386f84227a9d956f60cb66ccce3e97d8bedf2d4f120ad8fff52410c3fb5096cf68da59c5fb333403f21781d1390ece6351ffe284ef5a7b");
            result.Add("dsb", "b2db41950f2ad6171f42fbc97c9ba193bef5cf7ac5e41dc7b42befcc9f25ea8099368cac0c54aa8e1e662a91538bc192e2dcd208fd779acd75b84c16eb8d8628");
            result.Add("el", "84c118f1463d43ba1e762437f4e29201eea376b93e2b7bb636b784f35a78945602eea62795c4fedd38632a8ba38ba890a57c5d8d0830279e46d1100a706b834e");
            result.Add("en-CA", "99b0df259aaf66edd296dca4baa3cfa3087d9e6920304bd7bf730d8eb848e33d4351492c86de313d901292c3aef5b8db5615d052ef092be53809552705d82062");
            result.Add("en-GB", "b67cdf3ab0698e721809c1277d900a374ee59993ea7428d8824aaf2082bd74faafa39e85fd37a2b1ac72d02b1e8e9866c63ad0249deffed874e7c3f031430535");
            result.Add("en-US", "bdb83be9ccfa1a495957ab9e9ebe851099765779b16b12833d753795f42e82d1c2a9f74750b6afdc46f035c4d21244d74e86ee3c352db42e1905bd54c28f0eb3");
            result.Add("eo", "170936d670faa0ad8d79c479643cf19ed127f1dac855e184ed25bd10489fec664f2dcca26c404b3e2f7e37bfc8672d642e62c71f1cfeeb779fcecae733065432");
            result.Add("es-AR", "f6c7adfe6a74b6a669c15cb489fc199e1b606554d3c2b19c405daa3dac16747714252b02e8d67dea024d237c9d3b2dbcd05369a3bd9e32e2048f07662f929cfa");
            result.Add("es-CL", "43c2ed8e61b1356d924ac85c9eb9b669922171c7f7d403ca0f89407b8e480225fdf8dca96a85cdb96501d91a91fdb20f96dcab65cc6f0f1474eb1be79b95a051");
            result.Add("es-ES", "027cfafea86f421f647cf6aa7564d83485fa177c6bc21e8e31bed6d88700603e5af5a3e612f5509713cdb1b8a5b4104cd89103c96564181b137687242d561d9a");
            result.Add("es-MX", "bb87c3069233f26d2764b68b302abf7b7f465e8a38070e06d59977dd8e15d514c67647a650b87975bf1c0a4057d7660bb8336233a638605e378012f7e8965762");
            result.Add("et", "4485784c4b99894673cb8bc19f65a77590c839a05edfd7155713c96a7e1c85d1d0430002556fe1cdb421e18ca50970ca8dbec31931d98bd92b5c39a77598dfbc");
            result.Add("eu", "815e486ce66de33fe814d617aae9f6f450706e07009faa020adfc5c69c2e1c3bce7755c6801051194bfc4dbb6306e632c619fe5567818b3c93e6fc0573e8152b");
            result.Add("fa", "5c9440758b5a613d64dd22c802e16cd433761c9365f59a4baeef66d0dbb96a609e3821c7129c339abe8a1dd53cfb618dd262026699eafef5c018a55aa54317fb");
            result.Add("ff", "92e4c3e4199f4fe4650ff5dd9682e20ac5218fd2c3027940a0f54c14fc8de0759bec9b7a78d6351aaa5849d98dbed6b59b2bd8b9182c7a41dbc0e1df9fc574f0");
            result.Add("fi", "57047cd19c9116974ba7104d1da7c5c42ec0fb3daa8a01d60531326c92059ea57891c4e497476fc8b7a1a53ddeebb5d36e2798a65daa15c3132dcad7526cd1d0");
            result.Add("fr", "7ca9c444d81a4301167c2019f2ee147c0a283d64bb53507c076a29519a0a70ae616aaad80bd205afffd35ce3f754c52710fba2f1a461535acf2cf5f572b82c5b");
            result.Add("fy-NL", "70c36c94040d00354cebb890b59c2820c876c386400abbc331840cc778d7cac3bbc3e277875f77b1068aaf6ef7327aaf764506db90b5dcdb07b5e44e24e47b2b");
            result.Add("ga-IE", "e696c29a0c913a2d053f985834e64acf68b59c76c70c62e409d36a029c38feb8c31e7118423440601e9022967f9041604e300b39e725f896c4abe5a95cc46a85");
            result.Add("gd", "37cc857e591e8c7373e488613962f3c903d4b43e47c0c7a35be276cad2257fd83e99b8abd8bccaa1c1a395f7c92dd5ebd9725e05362849683162c14ade90cbd5");
            result.Add("gl", "743c29f7065fa14fe2841d140bd34484b16bad31c82827218f994566a07295951a0e20e920e0936adde389e3064afe374f210d3b946eabb5509fc5f3da97582f");
            result.Add("gn", "443347cd48c442a50288ee33243a4f13ae2cfe9aa244e28d081a7989b252620eed39f2d03b795afb66aa479c5f7daf067faf35646fa1b076f55d92b0d0db3db1");
            result.Add("gu-IN", "2ee03a4becb39a9ce3f9cfa1dd7067c260e87bc3ca34875b7c3a737117f613c1db604b44a509d09329bee4b85060110fbad428c29196db7204a00346697f027e");
            result.Add("he", "5ba6a2502594edaeb212644c2e626777de82cae3d356a72e5419dc09d3a8a9e8bdefa408b55690f8dab60aa62c8caa112ec2e1e9d05fdf8329d19623954ef163");
            result.Add("hi-IN", "52783b4fbef212999c15d569f718db2e5ef1780221b01220f4266916502cbe6d289fce4042bd2647de2df9a3fc23c912b0eb2416eee9e537af12a32a9720f44b");
            result.Add("hr", "584531594690a3f16f1f7a87a2df1f6d450e7fd6ef59b169677ad2d29d68f354b4e35c47457144bbc879466a809ed5a3022ab08c5dba1f70c414bc7d4e6b7a89");
            result.Add("hsb", "201e487d5d734ecdb7698e92999dc90da1f4595272a8e1a9961c9ee5eb741ef0fa75dba64e3ef6542166241d8b040df7d77fb8c14d0a963186ad3a0a9d61961f");
            result.Add("hu", "0842b56bedd7d44e3ef12899992cc43b89c0f245202c4cd23f74f1a29f791292aa66042d1c0c8e39fdc7e479d1cbc62341f349a80bc15954d5ccf08e3f4b0284");
            result.Add("hy-AM", "b468b7ff49b4324522502d145ffff2472a3d1b587d544930fa38f05883c5d9b0247a01ac28fb7224d0545c8a0aa6f692144e2332912415071ac727c3656441bd");
            result.Add("ia", "d694a5ad9b3bdc16924dc9c484f6398e5aecd94a8fc9507bbc439d91cdf0e3d10135ea0289afb21ed5eeb4c952ddbe907c894ecb6c54b2149098542e3532de1c");
            result.Add("id", "5c2627f66dd650c410e0119c4993856b9c56055e2a49d9702dd17bbccc66b9d0639e71782d4907bcdd831d9b87f9da94da35070167fee2778138df91bc10f8bd");
            result.Add("is", "5c050f5ded2ea629e5cbdc46f55d68f4482d43d08166ccaef5a0ca16b66ea8e2fafcb774f2c8d8265eb347d19a124a9304ac008ecb0352e1414732135f11c06b");
            result.Add("it", "e3ac1c5d9681e17c8fb75741080eaae2dfa0cd33991313a6cdb86f999815e6b6fcd59d42810add455a5fd9f9d1f330217b423d2fa597e60003e8fc02d1ac5edc");
            result.Add("ja", "3b9029ab7c70680c9a31af99f4fb67333defeab9d873c60b0915467347014ad7a67fd5572e55ce233223437a856d138245b201c0cee65d3bb6cd4f1025c8f1c2");
            result.Add("ka", "ad5858b5dbde17c064e3837c3d7e2e0ba7b685033ddc4add9003ec3282c087e9e3e962edb76ff64d8d0222be91d5ca4d4637111b190c2d7243dd767f937ab316");
            result.Add("kab", "004ab846d35daebf5e6b43cf38697eaee319fe4a9353820b0079f09d51eb29295e0539a4d88aa40c7a63868a3d90e145922db1ade1aabfe098b992abf6b2acfb");
            result.Add("kk", "85a21ab6a35de3ae29f3b535cf6c8b9456cac0aef238856ab19d60b9387bdc75e19ffb56b400b460155b0166f18c3646904f87719e7f70e7f2bb5b60f28224a8");
            result.Add("km", "93b7f09c4896c7d1b38ede0dd383d99e49f7e5bbadb4253edf03160d308336a853351fa3f77f0f13387800a6086d443dd85839f4b5c04dbfae690a9f62d2d267");
            result.Add("kn", "a193aaedcd64fb85cfe4959bc7c65daf20cfd12e0e2c38341fadb34cb490f159623d66fa9b00b4ae4afe925a285d550193a41e31d3be9342b5c76c36701302e2");
            result.Add("ko", "78aedf61f73d92af21c7c236ab09ae1e708c07d7edca9349542f513e32254013c8fb65e91287f1199df8b031c743452eeb8202191b8957cdf4082ed7af6c2a02");
            result.Add("lij", "9a7c6f0e5caa13efb95170bc688d693d47841625280315a7205bbcbda392a58d68df31a29bfa7403dba8c88a2fae5f4363d5fdb73549285644d7dd14467f033e");
            result.Add("lt", "7a024f19d2b0efdbacfba090665cee3e0cd357d962b55f529aaa53ac274913164a161df91e351cc622c5dcfb189482a5eda47d749aed3756d58f70a76cf0184d");
            result.Add("lv", "102f52c7624b6af07e01afa7abd7c0f471522c528fac235f40259d859aa91270491b9cb7388822fecc3075983e34d398b266cb3415ff6b7b7940983e695d1135");
            result.Add("mk", "4cc865fbc455ccdd846048280b76208ddfe4cab30ffab10a523c4486d0fba407cf646d6df32a2940037afb8d356a1af21f1a812db18d5cc8cd58588cb987cec7");
            result.Add("mr", "83699151b3a3efd5c6142cd7edb44a155ab55418f8cfc1c396070e0f0af3ce684726be4532d9bd95c660a1ae06cfdbabe028c565551f9d1f226016a4760d00eb");
            result.Add("ms", "44446f4f3f3e2178cbca0fd4c5e5365b364a434a82802bfc3396a5be9eccf2596409926055a252204e25996e4087f0b36d718f853a0e449b869b563b65d4cf05");
            result.Add("my", "a7dedf5855222d7186cee6a1b527616f739e595164355909568bf7f5cd77073012e8850e56b8f6664a56625c8eab34193c66d7474891ff81a38c6e9bb4b87b33");
            result.Add("nb-NO", "05a646d7dd92afe9b3044a79155416469b77cdee18322582e6bbd1df1380eece35e0f5cf4ef2def18a462b498a8de2e041bd82a8cc38935c785e255044c4369a");
            result.Add("ne-NP", "76fc2fcec6e3725dd5821e10d04700568e84d3a7b6f0e25b3721675e0ed1149dd9cdbf6b7b579b52474908d192d84ad1b288bed4a4999d2ec76a6f58fef9cb8c");
            result.Add("nl", "b27d88f543b0f34d5f10e6a75a10ee5206bf0ed1d8cf0509c8d272b3eb2fb935111ca10694770903683eae3757e0eddce25b73d7464c2e727bb2af4a6abf5d52");
            result.Add("nn-NO", "e9dcbecb56d7d633783fbbb627a655921fbdc76b4d774465c68ebdd2a95bd4321ba229a0b2b2a2d2c34c42477642c15275afed74d6718851823bc1cbfb6d3303");
            result.Add("oc", "ec217d1ed6a6bce68d4f5ec68c7b305c9a712a45b68b532b92e798923c3ba2ebaf9db4ba6b9b8f2f92f06f554858b5c0dcd14f4de7a48d38c22734a102cafe42");
            result.Add("pa-IN", "5a472ed90bf26254ab5b1130c4b1f719aeae6b2fa6a4a71b3398a463a7eaa71eca00271efb84c7625132e3408105ab6762e5feb319347d657dee147bd550a20a");
            result.Add("pl", "783abe2d81f8de3f5fd7db52aec398deae5adfc1652d4852b90397485601160f01746d276d5bbde38d00413c1283d2b64ccd5639b85c760616a5ec7a0b49df82");
            result.Add("pt-BR", "877ec0be9ba6e2eff0984a3938f5d2608c51cc9451cbd1e2f41991a7582ef81a12a2a5329ed5d7ba429acdbe8e96d26c159ea6d98c3d1755c4e81932a51ed9fa");
            result.Add("pt-PT", "29220daba225fda093e9c0e690ce914ad3a40eac1a2fee28beb45bb0db90fffdda95a1628d4f1eb03947fa7ec0bf86a942df5e4cadebe80be9b75692c8ecff10");
            result.Add("rm", "8cae55155403d4a19b04aa5569031ba3408725fec5b215c919235ce22029f329fdf66ebfba356b0708c41da10910cf352e8357f374d34d246d467c0e3442de49");
            result.Add("ro", "1e84688afc07f1369dfb3b3ec5d71a18939b61f6790d8beaa5047f5b3eb9f82a4fda7bfc58088b802543e83c2b2d677b7305dec21e05c4217f3709c4def73c34");
            result.Add("ru", "803c3a356e687f838b9701119427537047526c2af3a662b9635b7076a2789e1e5bf626cef061cce86e0adc4eecf5ca6e8710b79b57e7faffde233af35c679265");
            result.Add("si", "8b96eb8f237eefce49ad22adcbfbc2b60935fa42ade15b7325aa2bd1d54f69422080d0cd97f90d6f325e2d73488e462aee5d21ad0158c3aeb98a274af3382c7c");
            result.Add("sk", "5edd7616cafee66a2d25eb84eef7c61a5d4bea2bb22a9d2278bb66f9a6418395a0d39d52ae1c5187e7fead5055cfc5448399eb275ca6c014b866be0f4f1bfb69");
            result.Add("sl", "bc0a545e2fb3123f31df820f47978c6ee2b6e26fbdcc9d3bd42fdd6cfc66d4a3d79db10ad3cef909b0470946902e20d2fed902d0819c207e09a8aecb91693af6");
            result.Add("son", "2e66ea8eef0f84b1f75f13eeef04e3b1d65c5374d666df69ea3ebb5f09bf112ad4f1b82dad1e8484f82b4e9c16aef9dabcbeca683b262b48cd737aca86899c68");
            result.Add("sq", "5e6811abfb2f8a220673e5364cde01a71e8cbc5f4c9031aa265a9802763757780c3ba8c071014c521b46ad12928411931d384a80182b1d6d4d60e50a275bdab0");
            result.Add("sr", "91aadf184f3e188f0540601fc5f61ab8e796095ee55397bd4cb0dad55b06b56ab8b47cd817623c6723ee4fc80e9fcec5e6a35b41be1318e5422d90aea6df9fa2");
            result.Add("sv-SE", "bd6abaf96da32f6c789f277f888796e63b87263d76eb059f3473bb0dabe8bb4d143eb968c12f48d2d79c135423426f5ddfe501d036cefb031a37f6db938e8a52");
            result.Add("ta", "c24e1feb75c0386ec715191d62af655df541f9d72d34e29a4bc16a48ae8a9c8fb81c5767733f25670bf87779864726fd25bf638034d6a0cb07bb6ba213cb3109");
            result.Add("te", "fbebed2c1de28ff580e676b2ddb86252c1622648a3c57af1bfa6344583adeb48dcbddb5b8a1f566d23a38a93792e9fecd7ae9e64fdad47f84ff10f196e398adf");
            result.Add("th", "8eac2b7f6066fbbc02c5e51b163404a2bd5cb8cf3722e47201d9a1e26e2f241d41cf793f270273cd7f96ce4359a867139b4e3620ad106d1f5abb15ac550cd17d");
            result.Add("tr", "10e94b11f6d4849c6fbaa0ce7306982985e42430fe543aad7e204b6914ecdd9034b6bf80a3aa4b73b31765b6af3d7ab048335865ba67e3c6aa0f9960210114cc");
            result.Add("uk", "9d2285443d6a508189b8c4ff6c922d084dc78ce4e0cac054a89bf7490e335febbae15dd0d0829a2ba9d18e0ba72b5e9a7b88b684304ae82142856a07a4af6ebc");
            result.Add("ur", "1cea9e5bb78e64765ed43bb53ef2d7263cdb7ce60ebdaaeb56cb42b4822a576ba98bc2e3915d144de45b86adb93fe9cba2de083e4abf2119fe6ee46b90a61543");
            result.Add("uz", "2fcb9540cdb31e7a25a0b91b0a762c10e32afcdcbad4e64e519a8b3b4650b6f5b1d77f2f020c251e582d76c4adbcbfaa990c10c710c51cdaaa1a57cdd97812a5");
            result.Add("vi", "97b14e1bda7ab2983b5e970a1aca0ebe6e72750f4222f24002be9470d2c4fab6004a5574f8c7ff183981aeb40a55636da75a174e21683aeeba0b85c957b61ee8");
            result.Add("xh", "0cc6615657202735197e6619a1e6dc50bc3c28302a65175f1686279271cba128dcb9d23b8d827118870ceb9fb097f44ca8bb5d905cdbe8c6f1119bcbd6863f4c");
            result.Add("zh-CN", "0c009484217d7ea6fd7aa2fe19f54fe3efe33ca6216e13f51808f25e8297d2a684e29ece20488e6da8baf9449dbe046644259ac8e0800e805400c2aba59a0137");
            result.Add("zh-TW", "136919edcf4b942cd6388394e71f3d41146437e4a99b7d4dc32cab0066adc71775b8e780dba82381a9433a5bde03bb336d1beb4af2a645624bc4932b175990c6");

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
            const string knownVersion = "68.7.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9]+(\\.[0-9]+)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
