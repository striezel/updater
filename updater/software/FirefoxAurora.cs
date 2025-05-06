﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "139.0b4";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f15e27473daa172702198db66a7da1c47da2cec2afed02eb22ce4efb0442d3b9ea4ba2f786421da3a806d9306b0868feed4411b13cc1495aeada5ccb890af4c3" },
                { "af", "82c2946321c13a51f378fe774aee0455011cc6314a8881e46b26ea7a462004994f4852f55dba88d4764040c899ac2d67e9e63098717e9b86703fda42867d9c76" },
                { "an", "65d36fbd2aa9b0754c74b8188affe057cb3ffb18cf3b21f16ffaeb4601bf4d6cdf92cecbfc10045a20bc43cc742476b932518222ed771748396d31b2d582d51f" },
                { "ar", "fd69884dba1d389d366dfeb20c83773cc8ad3fff444c23c916fb24ccdf374abd6d938370fdcc64e01630cfbd34579bf029c949f66601c904b68cd8a2d72b98b2" },
                { "ast", "ddba7bf3b819db130f2344de44341b516a6f6f3a3cecc698776412f8b437d762f57ad68d0823466235bf8d0158bb6889f504d9ee3f9ad08e223a3ce5a039f6b8" },
                { "az", "3c34390478ce20d31dc45730af96f73bfaa1e719125ee62b83d087af293ca6346890a00fd1a0b6e39fcb2d48ddae527f2a0fc4132241a0a5e8704befc60ca5bf" },
                { "be", "9bb47e04cbf944a06f5407a031fa2666ff1f42bbe7f514a0e2811a24d71dcbe91cb425ce333a9fc65ca868c64ff5d62b5c3c7f2e0993618c7a9c39dd474f6560" },
                { "bg", "885caf827a9d6c24aa0aca684505010c9c56c4e54298f18c8326b798edfc46a5e00ee2b95289967e8be0566d9aa61e4c369870b7c053a0ffb184a1367374a3a3" },
                { "bn", "134b5a2898565533db0caacdbefa5688f3bea1313a46c68fa5b39c4d5782518b9ecf9cafcd8ff5d314ce8a62a06b573bf24e0fa49b47036b1c751e42fc773b8e" },
                { "br", "1e090dcd848d77f436a40c71e13dd1473f1254f29c61334f978abd95d90510d01aad7fbe9a8b489cf1e611420093ab8491b961e9ee09edf75446daa9ffb2e26b" },
                { "bs", "3240dfe12d60701e354c76c13c7d1c93234463e818057d9f86e45042205d970a388a73f95679ab74af12e0fdb62612a6d2edb769785d5e0e80567978de78fa58" },
                { "ca", "8f892299827df738f18b79b68a6ff7e3d147ae31eb34019679f002ceb7ff0720a87b96a1ca64ceb74cda2d1273f5374878559fe3a6bca8fcca627681b46f2fb6" },
                { "cak", "748f44b8ccf62a19b971b055de887e1e334acb6419ad8a867700e3c3dcdf6740bd6357144273faf0328c80121d9b2e3320e981a28ecc46973cf10e83b2510f1e" },
                { "cs", "49629e37d706a8c6834335f39aa1e500807c8ae5ec3d804c9145eb27e6d25e18616675e7f3102444626a71f74ae8a0f78f0160701cae6e17b3da9ea1c7e6f537" },
                { "cy", "9bcb0dae2e5a9c382698a37ce8c6015e2dae93d49f8dc4a777d7183096244e6d6592a6a820ca6787902248d0cff7f02d150e303b5a19712c8c2767e8341dcbe4" },
                { "da", "9294d89a736171c23a4daf7732525a8fad85d32304d1305302aed7322551b673b8898cc6d573a9aa35a974e921cc589c962ba9d5cb6eb3582fc7480788ba7d85" },
                { "de", "c45c33c8ad6cfd0240d6857202d1033dddbbecc1f5747179bc680aac425a49da8c2c29b8abc1c26aa503578ea55b79edec1059d134a52ab7c91da09b96618ae8" },
                { "dsb", "c2f1dc78edf50de01c04595a79eef02015db12124fa354d784fe81513a1454932beaf17abe4d9ff5331b63bc86e28ba2c2912fb1bc990d572ca67f0b961a90fc" },
                { "el", "fe39fa27f9a2e5a17375939ae08effa3ffd320abe6f8a50f07155e9fa88d87a850b7dd1629de59c4434d4adb0d884729c65ff18a176f45b880ebf83f3a40299e" },
                { "en-CA", "d9280a5ada7d3e24f3e9c82d263321bcf33398d50d3cfbc0087cb5c89a486482037c455d8c04966edd51efb5cd09b539a1c50fab6e9f114e5d63d7b2a9dde5ea" },
                { "en-GB", "08726c25d8879af713ca548c29c77dc81291d9cf0f3453bf62599d8d8bd3bba8c9045e0d03ac4cf5aafd6d554e37c2cd5e89c490be96adda2e09e91d877126b2" },
                { "en-US", "1f47db32d31ed389d0b536692c9bfec99b80d414fcaeb33a0b7168353e98726fadb96489c02cfbd23c76226b1238e1e1f77705267f046f1e86a8b8a73f228445" },
                { "eo", "d3d495e713d57e7f1511f9fea2fe812a39382952cb9f8bbca6317a842cf8ec3f818d26d0c184b8f2713d745ad5aa205556e1568b0f31426640489be54d1fc23e" },
                { "es-AR", "3ea67b518d20e1592a6513866266cc6939c21550083506d18124de00566e14274fd0a598dfa99f6ea70d8acdbf3aa57bc227b2f170ee43ab12c1c914e2e0efad" },
                { "es-CL", "ffb4f2636b3c658bed54a0e2cff73ac9e5a2441db12c309dadab82902db49cfcdacce623d1a4c62258753287e6f8818774d312045e91ead8b00bdeaff8d3258f" },
                { "es-ES", "e8867628d6530240291ba9126bfd42ab1030c35912f9b003c233d936ad3a419bbb4d28ef3c24fd4bb7c2001efe2236ff8b61478c2cd29987c2fdbb50b2a8f132" },
                { "es-MX", "1ae208cea8279767c49f0b0bae2415faa2094a17afa52f446c54f63fb3b30a6ca4397b77c724a9d022f13c1db564c0212719abd6331cd1e90c7bdda3de740708" },
                { "et", "0f09f778d76b8c953275934e64a07daa284950c7466f75dc2f6d3aa31276f7df7e77a59513412d135c3eca5d938ceaf5f98277e77c9920836044f068346baabc" },
                { "eu", "acb7dcebfe71c702e4b2eb56d3bd5ee4f4303ab1369feff1c49c8dae69eb8bb9171af8bf117e44511baaf2b8ea2521e839a709f35cf26cc779ca9934777b537e" },
                { "fa", "e22e9d24f8abc87ef5042c89b11b4e8b7ca73820839fe8714d7f1b63aeec349f81c6ddd08c36631d5d07a3f94ba7c766749a010efa63ae38d333b54192ff192d" },
                { "ff", "db048b2976d9302db49e3c7caec0ae9ef830e98bfd0cf2e6ac875fd610724dd00e8420bc2e27a439f378847ac4ad552325ef360c96a5029fe205bb2a70017f6c" },
                { "fi", "84791f7faacc601a37a29ef992cc1b6051414059196f2503d1bc902d996c9135bb7d23334eb2124a0de6a7d2073e0c9c7191d4465a2a9746b004aa831aef3e6c" },
                { "fr", "841efd04ee2c5e81ceaa43c3cd5f7af343918a653e8278f31eef741c9364377f3616ceb309e95a1fdfe37c8d65a2e6b36cc9dd00a96f1c92f132ac9fa350af52" },
                { "fur", "de721e0f19b9755377ebc0d1588d152a8ab27e59b6ded71370a164251dafc0cf61fad7af998f9ea3e1abb53f2f7c035654c22c279bec9f20a632755a2f3b53ba" },
                { "fy-NL", "ab1fdaddc8ba09806396b5cb0012fcd6cca455f7b63c6adc48e3326a33ba0a11c8fa6deb9a38baa2ae11b7366cf4f4eeea46061800089d1ac5003b5fc1ed4a78" },
                { "ga-IE", "6e0b455b9ef06b919eb613bdbcc25531ceee8f0de594ff9eaaf5a2c296c6952a2b0c7be306cb684d8962b642a2ae62df559083f2bbd26d6a507844f26dad08e9" },
                { "gd", "908d5a9a48822b7e02afa1f594d7c7124aa767324df01b7deb910e75f93d612a5734cbe7419aebf3558a81069c720abc11a815e5d2f6e66150d002444e9f3392" },
                { "gl", "561c379e0e03daf7c85bb9e22a061e9003cec4e7aed0ce2a22448b436644d3af4c42e8e62f15c99492e171e4e1497767d79ae395469ae566d59ac162bd8a8839" },
                { "gn", "9e1ba49085af1de6ec707e4ff4e79191d668a39d53513665153f07c123db65ad089d10df987af3defb72d3f0c02ada16b42993369bf15075cb3307b111ffd2ae" },
                { "gu-IN", "f09b3bd7cc27c906af1d82754bc9e82ba83d2e189fb9954bedfd0770c1eba348e1c7c5cf82ef221b148deab3ce54a4124a32f47cf3127c6664040e2334806eb6" },
                { "he", "ad3cae43c223496d06b48398ea51e79e4d59426d0887b961c859b5db83a3cdf3a629fca3c3a962eb1de0005c1100cf3c30ac2cce2ce4f7472746da62c48fb5b9" },
                { "hi-IN", "1b50d878bc2ae2b1abe0b7ad6932e777feee8b51d65607e4029cce5d641c873aeab4e2c98a15b269f8f3fb7940da6273b2e884d93672915be590516284c2271f" },
                { "hr", "cb226eac4415e4c9d6cff868903aeb1c35c0a20d46e2886ced56bd9353f762c9d230493f1e1ed41efa5d27d791160195a862f4a4bfb72136a2ade72ce9ec118e" },
                { "hsb", "a9ec565c20635a04d33e3b7d1cfdf48fed97138476298f9fae30480e9b7a4f11ded6a1d0c41255bc4ad1dd23cec765ad9c883ff1adf01f46c82b802f99adeb87" },
                { "hu", "714a32a25d4598196b4a35ea7e2fdfcc67e75ed05605ffa2c2e54e650d81c6fd99055722ef0537ec0e3be24e40c28c0c3ca4139fa2d653a95db464693d994cd4" },
                { "hy-AM", "6bc6fd90703e555d1a9d619b1d8f6ea88672fff7b0c10593be4f7fc28ed1e1b3cd36bb688d840ebd16a57b43dc0682c1ae856c6745e12098c64a313030b54e5e" },
                { "ia", "100272e29f00557f18e6d42ee5ec68dc9202ba22f1691b0191ddcc2d5d451b0032baaa8704fa42223a58aabada00f36afb406f1b0a1ff8a740d48f1365231887" },
                { "id", "f18df4dead063f9ced109d9aec81ebc6fb0e638eabd8638d0c1a9ea098635a816ce26243b2fb46f8e7f80cc788b11c9919c70480416487c21ff08cfd67e03d4d" },
                { "is", "332b5d1dde4901e34917bafef18a4086a8cf15b8a6aa7f337f93b48ef17a744a93d48f9e7d340198e631e1fd96cc2eead5f074634d1c2072dad6c549deb7654f" },
                { "it", "fbe2e6953c287f3b9e00c172f2183e50a48804537e1f38ef213bf697b1fcad022efdb999a6f76e6c3b9a8c9f29d58bd0b2c2f37d09a98db684c02bb0b71b6650" },
                { "ja", "712fcbdf62ca2f98019c6120845d1f5f4a8ea811599df3fed3ee4ba43f2a4fc4d1c7489dfae9525d28ca0e085b3cdbe8d823abfdf67679ba4d18a15fbc07a02e" },
                { "ka", "2bd0f170850a2cfe7e3706030b44c01715e3d53bb6b9c30459b26b8c32b1992303730db4945ba9fd3bbfcaca4bded8cbbb6d8afeccdac0ff2a10d24f69f3d165" },
                { "kab", "1b235a8226b5e23b75322f72fa6142ce436e13e70fde8ba58aaf0348a13ee8437a9cddfd3b68218e08c5c3d7b99ad310786f58bdd2c28cfdec91735b05477d84" },
                { "kk", "b45dcd5af0a02be4f12b809e8e0961f16b82a4d8aa0743295c6f252bbbfd32fdd257d4b66a4da51115e24078d3a4018cd4b946cd78f726076a9ecd8f97080363" },
                { "km", "931cdcf6677f97cbd8035401792b035ce8b2741908122a3532ab8c1734c5342a3d3f0ad454086e4e8c3b42822cae93caceb57b6c2776cda139937ed2770d2aa0" },
                { "kn", "d4bda5010ecff98b2fbeee173802b02d7d61c678498f65d815bff8c894a9a05a6022cade20a78ff913683051790352c9eb96ca78e7c06f3e4b7613e2e120a4f3" },
                { "ko", "41add2f8f723db04aa276b19f3dc5d524be35ce76554eeb24006e758649c68368109ba1e4ce7dfdf6bf57d576e366542af32682226cacb39cbd71b9ea12e02c9" },
                { "lij", "91ee71531556c3ded8636914c503fdc50b25458950ea195abee71d7412a9533e332a652c54e3ab8cefaab870acc3530ba21822e8208c4ca542de6cf3327ce854" },
                { "lt", "cb763746c45983a51d714fe74e3b6b492d167ec32fb8565cfe3e2a258fac660779ca51c2956d2fca5fe07add6d02f569fcc13e2c60dc9a9f3dadbda27cdce277" },
                { "lv", "ba9eacebc3152771df997be1f980d66377d325c0cc89f1b23d6db46c275a686e75653e69a07e924824d1ee95811a0639eb2fd053d85674e6ce4107b347d1f906" },
                { "mk", "779ef0791203f2e26ecef5dfc470a8d4335e5350187366314f949e89cdecb56ad1110a62d1bb339f6480f9e9a2b70d9598f4769c0c8656930f16d3d1e1c8319b" },
                { "mr", "27f25a4454cfbac5283f5c72789268403e64e8ecb66269da2c514fbdaf5f15d83c9cc2fc3376d8fd55f8e74ba0cfc019bd5be6a54923456a53a940f5372faf9f" },
                { "ms", "451e87e53459aec7d2fb7cd667f5d58472a524724a30521bd73698ec1a846a8ccfd9431d4d261293f15b08364e26d4ca8348d3c82434882ff292a8f964bc995c" },
                { "my", "de27a4a783ebb50a35f2b1ffb87daadbe3311fdcdf16e5e5ff0605e2fcd31bd833b9b738520297c3b965d00d3a7d9010a8b620944ab07c2eb9bf305aeb5cecd0" },
                { "nb-NO", "5eac7b7a3c788aaeda31c8a646c0a3846d7de0f542fc0eab3787d2584c21aab17b2cef59f9476aeb89a18270b946d10ef07425924d9ead1fdb8a6ef2925b9288" },
                { "ne-NP", "1510dbe33af675912055abd786ffe4812418d25a3b4f50b4d8a50444c7b397ace97c1ed642f3e9559e282c943760db774d309bafc5821d575ff54abb1f05d877" },
                { "nl", "ad43eaf4cf724d0b9b30eadc5c568ba1124872e30f13d98148038d3332fd761891ec91922d36e5f83642d38de6b6c4523dfc2ae6a1bbfd2516d7848dc6e98555" },
                { "nn-NO", "bf92631e4eb66bc076c49cb034110f5ca0c39dea5d10e568f5cb6c474df683566884a644a532cb557f323a2377629cd6b2cc28eb7e4033f209c8697f253ab28f" },
                { "oc", "d5d02d11905fc12b59aa3888badd0b6cf5402a0d1e75fe4164d0dee0a1186f1ab2c12bc917eb48fe92c58b6b6f721fb4a2b6b4782e4090bbbb4e85fd2c6b84bc" },
                { "pa-IN", "fa8b330f83ec305b6b9a885d59b92b183b010ced95268514994be23ea8fa9f1322dce6beb8ad27867a9dd4ba430cd4294a7e0792d84726f90712161c6f75c33c" },
                { "pl", "878c5a1bca9f8e6c142dae728b2f0d16ec3707416aae39212dbe2f13a156ae311e20a92fd325f2454cfc19db43b26e79133333724857fdb380ee57e574e119af" },
                { "pt-BR", "3ee91ad0482d0560d10947e5473f9011f0ab6e2eb1d4e43e9c0aec2cc59d6517badc6b0aa7ed0975d3d54d0856dcd4589fa9f7f6783ce55faddc900e2571ce94" },
                { "pt-PT", "c3176afa593a441f4325fcf28a5bfd253364f246206fc1f0e85719f7359385d5dc82b03d311bd5b7f7cc63bac46937a8c501c73f42711da551ac79de16a6cd03" },
                { "rm", "9bca59cd867360df3b78f0d48fe977cb33078da7ce7c553fb7d0fb260327f31994e957974043c2330e15a2fd378128215503e9670aa19c0c6d1562e345caf426" },
                { "ro", "9cce8fb16c999068850dd6da48766efbb1388ca5b4de4effa627623b0163503e5a59b927321511bd03a58fd1e61cb03cc6bd898137f87d641fd8a1dae7f4e767" },
                { "ru", "3f4fcb6fe4fb8ec1edec8dff95a23c4bc02eb6e6677bd296572eef711f11b4123cc7484704a7e82ad8841ee138e162cb16e0904d69f5445fdf6ee7bd1b76af8c" },
                { "sat", "837be11859474c8ba7236df395ac1d5c5b74a8350627a57d2175e58c95d00f7a946e44ad1a0e7a68ba149e03ce176b0a116fa526bf6a6e2b48b6f11c36429420" },
                { "sc", "e8519905f13dd5af13075f3847d5b1f90b5f793fc4b3556d98184ddc937951f45f23e954a45843fec243df7367a910ee4ad617c866db72f82940814e6dc758b7" },
                { "sco", "d26b4a43ce8b2c2515f2965b952f2461a69f2d178b8d863f0b7dc22077bda6ac7073e1b0c707479d38ff89dfcaf0e536736bfcc887fb7a118db6359882467659" },
                { "si", "cc490e6f3e7c89311cca150e6cbc8a32baa7806aa0f95450c9ddb03fb0d704b2cdeb7afb691bc3566cdd944500b94815fab9c34735e147ac955afabcd38ac983" },
                { "sk", "373897a934dde584037e8ca2d733f797706e14c3b4a8e3a9c91c47ddcf714e9fff5bb6bfc26eec02430ce958dc5c47659bc844f9f14e036db179b38065835e47" },
                { "skr", "f9835976c4c15a5bf4c9fada0a9d3a7f23c152e55e5746e931c2b58a94d16f1e69fc06a2cdb0a673bf3ff3da20a67e14d99de56c30aa8604a59b9d9781fa3f4a" },
                { "sl", "85b586046e967d6dd7812034c780138f6b515edba76c04cdee1123b42ebdc12e4c93f24aecaef421add9597eed56327dec32639d6494dfd079d65927eabfceb8" },
                { "son", "d081c5432f9d051de382bb579902bf27e3de70472cb562f4181ff615c8cb4ac8ab85352f5ae76dacc7a7afe303515c2fff4fce5a4389730b42e0fbd5341e8633" },
                { "sq", "71e3b7a6ece21bff55f7f10b0371e492d5a6869d671fa45540431b4610c1d9cccf928781fe7fcbd0df03be0815ed74215bc0afa13a67ea4708fdfc7340530441" },
                { "sr", "7977b216e96f6f79e6b97ec73179bbae5a77bb413a3d415bb563d2b30ace4781f1a0e84738bec867e894761332ef0f3d7bd4a7b7ad8936315d7055540f64b80f" },
                { "sv-SE", "5020721c79aad98791b08391c4aa198ced443fe25930a495f87699bd8e6db869e744820aa6c86fa03816aedccd20437ef570e41e4a99654608f1e40dcb328bd5" },
                { "szl", "dbfecfd944554820fa3b2522f282472ef56a0dbf367975e8bae2a2b8117bc4c3fcf569df2819f83fac2f053e6b3e65c915f41a697eac742f5a2fbe36eec7fb6d" },
                { "ta", "64e4c4e21eb40922ac685156bfd032ed61c53417e21c7fdbe6662c5cb666483c35be85b2b492ea3ddc00bfebb02c572d749899622ab46e0cccb03ba4710c7bd6" },
                { "te", "0eb6d995eedf7d22baec7cf5f40b6aa2dd37519fbc7a356d7ca891c8829dfbe60c5296feb81aa2e51c3781bb92582a968050e596889f8a865dc1583dad3dcb6e" },
                { "tg", "777831158feaba5ff861c9537984048e9e9d4bc6fb3866f0da0a17b0562be846f154194f6aded5c320f27e5c4be7d5e20fdb8f9abcf2664f144a57a7236baca1" },
                { "th", "f564e202a25f55c18450bad81c096e6e9a65d47f50c094b835e9316c7a6dd80a6218b617e1fa294f5ee1160bb69ff25434dc4331e4738d53ff6b889aac1b00bc" },
                { "tl", "5bc4acd395389bee00fb4f81a67fdd930ed025c708905a63c114454a79f2edc676336eedb58a9bb91024791acc4c061f6c06d27fbbeb729f813e194a08e759ce" },
                { "tr", "d849b15f27ea61213dbdff5ff319eff206c826a69919c41d93786ea52d2e9157025f132c83b0e8dcec024ca476e06a3ebd772762c37576d6d9eb4dbcdf765c8f" },
                { "trs", "a51aba5f1812dc7ba27c0d97e5a8222459c491a740d217268cf45ea90bcf010971d5dfba278e22d4cc0873ecc2abcec76e3c2d18dea2b0a2dd0ee00194525824" },
                { "uk", "788ced1a5187d0a6d81de98b910f145c21de6647bcc290cbda42044362dbcc1262e0ea5c705b48d8eecfb1b31b60a3755b8580edf52589f6f65789fa91aa4892" },
                { "ur", "a441f370f82641ea937148c693d756e8f0073a49e0895474264961e6f289309858d361d86c1136c7a58a39cf205b1cdcc55f4122dcdfc49b3f3fcee65359218f" },
                { "uz", "839661f1f8fd5deea5e377f5bf3408d7f738f41140180842ee5590060b5f846af2a5710f3dc1b7e7f7fbea08f98b37fbe95df12044fa6cc92dddcbdc77cf1dd4" },
                { "vi", "3069d3540719f881a7dcffbec86b430ce432831747f1a873f2b2c190456b08774986d4e42ea8b934c09c03aa53efa2c903ffe0b50a333516329d40cdeb0b9d2f" },
                { "xh", "10c2670e45cd96dab90ba661826d90bf1f090074cc4b2bf9f1ec3e5a09283bc9542f636b7aa56ee9c81c3acb7f9dd55bae3676ba3a01d0be66ac9b27ec54a15c" },
                { "zh-CN", "ccc1fd5c6b874c0cd5f8b6d248bf9c39ac0db789e2cf71c3a77128e121f1d3302d5516d1379e074127c8df76c3eedd72248600ebe30b55ea4c94336320461ff9" },
                { "zh-TW", "d008070b40de719effdd6ec5944c087333d37468a601c2ebbdacd169ed860d88fced36a5d251d886b92cbfe339093ffeab77f67e434e58000b1cc89fd1013f31" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "704d22ebdf12ad0c849711d37c0b6ff3e368b2a0eea3080137c9661031463ff314adcbd575233553ceb98285c76720bca8e9f53438ce719798cb65e3997a5a02" },
                { "af", "a975c9ce596de0ec983c9f622bbc4c7e700b5673766a2c06b0845d5f2373cbf4b4cfce350335fea8626c85afd254055e054878b5699fc0760f7e794512890868" },
                { "an", "05813fe4cd27569f30f661720df7fd3b4f00b22ee34d5949f48c3e7b3b491a7fd8711067f2dbbcfdfb9908645b75b55820d2287b7ff639b2d990cab8ff5d7809" },
                { "ar", "a42f13efb424d69f84e8985d479d670c72c745e7782a02984de43c16baebf6839678e0b13dd52e9aca1eaf12c223a948a9b0057d923e6da034f2960485289c1a" },
                { "ast", "b11dbb9a6b93f0883a7d297f3cb50a8859860f17d3914a09c9e387b1af771460ddb3aad529ca8e64b26f9bfeaf20f35360eb663c2dc4fc546dcb103c8c4ac9e9" },
                { "az", "0614d9068d6e5a93e258bcef1740257864f60c5cb89e07d9a3e3ea6347f29418bd93828a16304eee6fc718d98093eb8707b33c61b96da7bb989b724240c1630c" },
                { "be", "5079a0981b88af7bdb586c1db2886d07a3bac7f3dcbceae0e474866a8a268512b75f5ee8939f3f97a342fb0b72a3ba1d49083dea6981826b1ec09ed535401a7b" },
                { "bg", "a7d6b47a41cbf21405f07d187c68b9a1a54f2d69155615fb2b56d50a5d8b0e405cef9f7118d73178d4fdfb32f0410b073bd20e6daef0bc7a665d68d3aa7371e8" },
                { "bn", "0ae2829fbe4882aa309d9fe6b353550a9d537cc1138c5ddb15930bfdbb6f922b49369d791983b95fab074700d538d8f95129b80f29be5420d1fc2da520635eb3" },
                { "br", "1457a6bef9ad1e6dec6d6739e717dfc32f2cbc123c832714ba87da629bd4cfe1fe4f037c2e8d17dc7cfbac2fd4ef028f9d5c1ce65740616e014c9dc7c66043cf" },
                { "bs", "6f44af1f7efa1e0a1b404ee202045211efb0a2efacc4007c09c4c4f7798b23894eca0cbd858f1ed7b68059287f1873923ce6ef839568ce36a83400d11c435d38" },
                { "ca", "471cea05eba2eda4447529a5002cf64eb3a8f894db8ba85b4dd19e695f55f1ae457db6b5696a352596c901c0ce56a8cf61a1e0e7ce66b2f96a78068525ac3b4c" },
                { "cak", "7d713083a2517a687c0200091199b7410285a5001654eda597b44099177e1843908ff079fc7a6c50ebf61d56ebeeb11d713ad28142fb77fbb450f46aee6adaa3" },
                { "cs", "697538e77816d82bd0223c6dd5fc05fb755f98418e97c50e771c2652def950400d0e2f22a0f06ef205e009c5390f0cf92e3e4bd18a200f5f79c0d70f87b87a25" },
                { "cy", "8ac5078413c28016addf0eeb9dfbb85dd7f64fa32a081b0a3fb745cd70818c0590e385fdaf330b5374d43c7b1ce3efa6d221c2dbf671ba81a65c1c9e43226595" },
                { "da", "123fc2072a216422a0f1b911e11e722705e1e70fb8c2cf6bbf417675126b5836dd4ada59b1cb01cda8b515d891ccb0ec85def6e46a99d1775ff7d16edb4c3086" },
                { "de", "54cb682e31f4b08e02b8d7d7bd8335f5c1c11151e9db17119b1f072fcc3c7e045c76021d239ecba88d6bcfd340a4bfd117304094fb50299bfd1d435045030a9c" },
                { "dsb", "f31b5da48533ad31680dc2852e49d30599a749fdcad4a5abebf67be51068bc5e77895ffee5981a9e278c95f35ba153460d0bc333dfff2277181604776020d625" },
                { "el", "16b8a42344b268f283066120f3f5f93b1085402d56bbe21aa093c00284d45039484916085be3db24fee65f0cb732838cdcd02371540436ca32cee0a16d79a170" },
                { "en-CA", "633de8daef64586cfba043922a20eecb01a99aec4e8e5ae942cfea664c5e5ed9eb8252d45fdb74a71a46dc85db1925bb738466d6e8f67157ff11f5de7fbecf0c" },
                { "en-GB", "16f599cfc613fd8afca2fba744aff39b0b35589ca7c6ce0ac3c58dd5425ccf4439d186d03c7cc2715b3c5301f46650a86f087a11faf40c7208938dd4d839e1c2" },
                { "en-US", "ad58b52c4df88fa7a023d99a70a2172a7765332aa522d538aa975e7c69cb1d4b3f31c454cb169d4458ec9986bf9ed3bdd0c58223653928f936700fe116e59f7f" },
                { "eo", "0802770f4743661d3c391a65e0f41825c0301c087b600a3ae28b108c63082528d46cbececf17b8d6f5ea20e7ef499125437aeaa5530e8155f47504a58cc354de" },
                { "es-AR", "d33f49b0c4ec2c59adf86c2405fd85f82fc60dfeaddd61fcaa77d61fd1abf569272583bfbdc7ad3d2276d8886becf6a106a8428623f223555fbbd365add7d72b" },
                { "es-CL", "5f56dddcd80e0e0946ec6f51d9b18b87aa8dcf3e52cbed5a613505d89b0be6636e1a613cd56c47f01ce29b09a64001bc390b2ba1f7de470c54dc9117d654154c" },
                { "es-ES", "fc71523ffcb5b17c735e3437efdbc8b11cf25b43a55b10fd64fb5c508b9183d53173e789bbdfb6d6e8e142372588115164bfd1073d1629d6ec343bbf2299d7c6" },
                { "es-MX", "bd4cff6557222b56375c16ad51721d1b1495c1034d24ad1e82dcb25fb3b9db1594ce5d56c4d82da3d35dd617868f1f1dad508059376020b49b3b30aaed05d68e" },
                { "et", "ba81bdcf94ff69bac896fc65683b1b0c1634480b68c943ca54b5a59abfcc523ec635fb52153264076d4129f6b819f8cebfac6344587228a59603e7115a395bdb" },
                { "eu", "7f031970ec8c1f386af208544fe8d1bc6a102c1bb81ca49002f37923d922d7fe5cdd1bf1b8ada0d43ec735dce34e4c8e1378df7e3c18e947d4decfd82a3ba807" },
                { "fa", "98dcc8a75eae5d82c12fbc0a852e2e03e1896c70e8ae7ffe12c79003f1daeffc72e0388e60940475d768a54399305d3c67a9bd69df2d6b9ac961884b4c5f12cb" },
                { "ff", "80ee5be4264afef2f5d311a538999d05331fe513bf5ee3eb8f99f56d8e01e7bb95367b712f6afd57065c993e01a9f11dbea6a9fe20a0c41ba28a344cf6b7478a" },
                { "fi", "69e5483531ccbfe541c28717546d81343cb8ba5cd57223ed0b9551ba1b7df3062e8ca8e7dbec22f978db9591f6fdb2d55ee71b4954cd4716aa417e595b2746c5" },
                { "fr", "2b97b445fe7c69029a739bbe3ed7be57d4562e0fb3b1fba77e2315a536ed5a62947090c95414d99e297f48428bee94fd49c089fd319c8012788dfa33e7404543" },
                { "fur", "035db7085b6316745930e457f964b771a5326215e4798aa794d08a59e62368d737a9b5ebb7b375379562e3cfbb10bffa6944f8f119df76ee09077979864ace29" },
                { "fy-NL", "997959c2c5e6abcd52ed4b18e1fe46cc04945bc6da3e78d760982789d0541f14b05ff785a65c69a73026f01c8114dfded08d964e36b6e77a1ca73ce1aac12bd0" },
                { "ga-IE", "b34caa33ce93d3c53658a47e28ad5b3b85ea13bc0a57ac70c5d517a68ed9cccf98208e7db1d3770241ab3f0ef997848f56232366eb60f3ddb8ec4b9e63f883c5" },
                { "gd", "a9ec8d6a1163e561b91c80203199863e0c09c7fc7295e8fc54e62f801b859b5d561f122cac27d9a78aa8e6983504614f8a85088574af16cd6b3558475466dd8e" },
                { "gl", "455c10eb364d367a2a361738a7c82655f4f3737b1fa814e1506bff1200619c9900d0753864a1b584de505e04acf78d9adecdb43ec3ad5abb1df7b36ab026e86c" },
                { "gn", "acc5017ce51ec55b4c6e4f15d4e3d0796d7616135d12b1df9849c1a18de575652c43009c65a1a399a45070a0712b0d0feafb7c74930a0001b9fc416529ae2fba" },
                { "gu-IN", "b62a5a9c9a7ad3da19ed838a614d3074d67aeb393480dedd3f675857372c99b42ee9f6266d754665a33c610595329ac9f6b9de0fa3eab11ef59098f5507c2015" },
                { "he", "695a624cb0317699e646e6e72c49305add0246bc53cedfcd95d58a25adf17763db7217ad12755229d45c2da79bd70cfb8fd53f8637a286b347956549351ce3e1" },
                { "hi-IN", "563764307dd1f259cedadb03450cec4c9568f6b8bbf5344e6e733a5a3a82721e96acf41ab2e23204c712d698c62590a052590dc35c31618549e917e7d23243c1" },
                { "hr", "f82be068c160e594d47c46d1713cc0dcec298870705fda0367d23edbef44d214e470313968d8d9c7a481369c75857c9f05d159d8f694f99c7058fce891da549d" },
                { "hsb", "689c8326c8a6e383bcb9b6a37afddcfc635edc6ca8df302be798c780e493ca2384ad24f5e5f6bc4385da5d2502b202c19a1f0512e0db95796965a323b28c577b" },
                { "hu", "107f5232cedf14a83f16be99e718244063bff7e5c6a8f38147fe9944ba9824773be145eaa113dc46d0501c120d72e89aa9546950493c7609edfdec38458414b4" },
                { "hy-AM", "64a3f9e271908371a4c1f7d6c576ec15f624a416a55c960774e839d2b723835a9451fdd0cad8c5d47bcf81e94b8a1b4a2ad16e277f13edc07c447d8ea039b74f" },
                { "ia", "8a73783e04d58b351ad59738ad7a189df6bd463479bcb9b529833450750610d905da3140f9569ca29276d93797d99364f1d2e2cdb967d1feb357cbf50743a296" },
                { "id", "e58350ca787e8861654ed5cb09e7af9c5d9fff54c3cb48d04e17d459c5c73e3b5d0add0e4cd70b0e66159e78167bfde2f64b898c047756094934667eb531a1db" },
                { "is", "388cfd7c376decdfbe476c04cc7b5a540bb6d2f4788f45726ed27022e146fc11e55cbdf0d5db4116d748bc1a1024f5b200267e143af8ccbace5f03754203d156" },
                { "it", "a9d9390b58a06d68a26525a6c4d45c78867cbfe57ed42a9e0fb323823e8b4618756be75876320d585d05a5f05175e5300dc55bb1cb6cd687152c0ffc5d8dff51" },
                { "ja", "a8cf4338e6624e12e7bb39dc503f7ef063ae59bdc8bd2223169cb1e633d1722e74e60d081d67f27acc6c0547c14dd9826c5eaa32ed847e57fd914f0c3ce628eb" },
                { "ka", "b0e80e8bc8d59a7f6aa665656e8a1a15d6bd3e5be24496ace50c71792914e3202285e4069c92f3eeaea0068b5dfe810bb977b2a17db6d721074e00252fd35942" },
                { "kab", "224e2d10a1d0a65f03695ee36d93d0f6d73e2a658c9dd16e95ab83d9bd2c2fc56fcf395a20dd940b21a395a6f928e83eb63b41695d779482952702a65c270739" },
                { "kk", "241a417040267a32b225f8eeed2a6f2d3408a5b2568352fca5bd75f3cc865898c2271a3ebefc1ea5c6d771f9d3236147c46d6c9ea8c72139b9b5c7e143d57dd6" },
                { "km", "6d3e4d3c7aa83e038ad974ef2009cfbb6230870b49a7856f533ca3d3fd2b54433914b90097848379036d68166215deb5d40eee8434819798c1fb7109e46a8a20" },
                { "kn", "b315d114bff4fe022a45e0d7941331d49edf30c7d142832814c2f01988fbd1533d51b87c64b92e31f0487c8e2ac1132711bcf0b73dc6356ccf793d15fa69e4e2" },
                { "ko", "4c38b5ef7e4aa4df9360ae2ff363a7cd5d59dabca79d4cf07480d2c5b2e60403beb21bf849c8844750a36b6b1785bc0c1a9a97abcfda588609060aeff448ff66" },
                { "lij", "1633cf9d906c8a05069d1e914ec29dca83f9a9371153193c3879cd7b249c991d6859b07526e73edff63829171ca930d1fd0ce58a76d7e77638d049e74d3a88dd" },
                { "lt", "a720f88967ac5bcb64b8e5a670f650e6ae287afd19b9fc0b8deb5fa9e38cdd5e319a1d9bf51bd320ea9f29ac959954fbc59a4e3516ea7d31f566495bfa83677d" },
                { "lv", "bcb0beae7d2e0be192aaaa9f7c82fc23973b50ceb8a16c56121f103df3ac537eb298e9654eb4000e2a32256becba2d62396feff01e837ebcf87455f046f0d23c" },
                { "mk", "1934779e94434c6e92469f40cdd8658d92738b5a9983fef44979379b493b7e72f6b83b3c2efac8f5a04f45f5a38bab0fe0a52a6bd0f19c0db47add2586306e25" },
                { "mr", "2b842b18b2b74e44ac535603f6e71ac3fa55bc7b2fed03758ff7d195e1ec2175946f177aeb5b17a95b4295ab3eae4c92d52ef7bd334f42b111dd34fbd9811799" },
                { "ms", "d4876799ca4622ddaafacf00838437b2312bb6666f0779b2836296b93f91f10ef7b3070814efbab00cb620677b8fdd1e195d94afec4a84dfa816a8bfcf2ca9d1" },
                { "my", "7f31982b850828922c0c91c67deb55aa4d452c583f518f01beadd37799507b539db6d678aedabdb37c63fe12afcc44a264bf8f827f6d92e3c6a1a19474aad3c9" },
                { "nb-NO", "e76b691ff8e99d6424284ee82a0f1e597f333a794ef96b1b38b3d693ff80770fa7ac9dbfbad4e4797d447c9349080a2d20eae8d4109653a8945991f9270661c4" },
                { "ne-NP", "0aa3757bfd78ae89894fbe3c07cdf26fb7c41d65b5f2a7450d32b304d83fda9687b0ba7266cf930f586c3c3e9aa17652da47e6065d4d6981955ac82976f2a709" },
                { "nl", "4548aaab58e848ca75460efdcf73d818897075d9515acfc3fa907d15a1c4469b1a82caf4fc9a637f868c595903ba7163bce76924aae30fbc80dfc5007b795f5a" },
                { "nn-NO", "d0be16fa7b72c3581ff1f28c725dab554b2f6a0536e9792395341ed8b4e2e1ea78fbbce29c8305f3a9acb93f3498f499d76992efee779fc116289efe1b2f2bb8" },
                { "oc", "665288be7e9a33db434bf4a21dee293052235c8d2ef964da95a816cdcd083c84f8570e286cbf5f0a5593bcc1fe745747ab7778b6e4d607579642b6a475fc078e" },
                { "pa-IN", "82a3cf61f735ab3910eb331a6da1238faa815c668f93170b77ee557890525e28019b9a41abee1724e9511f356367066b391658ae1da1469de71c3739c9b5c8f4" },
                { "pl", "54ea1f7fef43b6d2dae1988389922372ded67f2f3771dbd3dcdca994278cdf3d7cb2fa4e3c3e747e70f98dddc222615d2960decb225d273b554fa6450e6cce61" },
                { "pt-BR", "4568ed23c3885b73126035ba06d489ab0a51a54d8e4f9ff72861a3d67388ac62eef4dfc338823bff060229b038e36a91d1dbe8af7a17f0738a979acc139f99a1" },
                { "pt-PT", "f8d5867419947536a3c05cb3b2d400161902363b5eaac2ee403f5f6515b8a15b1e91bf7bf40f3c08d92ed84eb0ee325c1a9dd62154bd2b5ab4897894018dcb56" },
                { "rm", "9d2bee9450bfe8404c235b586d12dfacaf983cbe5227e5f8207a7bd33ca4dd81d76964061d992c04fc5935c6470c7bbbd75c1d74351b2f21d41e7ebfda1aad5e" },
                { "ro", "57f7362c7bdfe8b5286ef2a4124132f1221cca004634e276b1a605c99d22b8ceccad40f0b052ecf23845bd6f446e895a5809d3cff4e89d382ccaba4bf263510e" },
                { "ru", "f3eb7c3b94f962152a77b2339e5cc5318391311a1265580a0e1f9bbb84d6fc68ff09a0e6d9c11bda75c8b63c8c70a4e4a5e26de654fb979111595e4c04b28560" },
                { "sat", "0acfc59875932e20f48a6554dafedeecd717d532b237c0d5e17a103e1b70f08c34d345bda0e14b14621aad6b6e0b8fd463be5c5d09d1fdbdeca0d8ab877b4384" },
                { "sc", "f0f512ed56034a57e5833ba5f578899a875edf97c739e20590cdd393e5d141ec74dc9ddb342f9a0e21f7ff57d36d3f947470e7abeb7a04ed2bb1286248715b44" },
                { "sco", "0e9024378ed1c150e8be7356735332d1ca4d2efe986b4daf9fc448551e9507469e6af3871fcf8fbd2c976eda1287954967d9d7e361499849b694ed2bd3f8c91d" },
                { "si", "e6bdbc2a109bbf46dfbef09172d7c7e07e94516c209cb5945f38c70602a653e435bf0163517f8b6ea04b7a814513f53a2a942b2c85b595de44b7c7dcf35ea315" },
                { "sk", "222ec2cb70e6a277d74f233e3874457794c9bf11e9f27d552ec6fd04af6fc5a79d4c37f8c50fed152d5eea018d33f4c82ebc084f1f49e9de02b973afa2fa71f8" },
                { "skr", "7602ee393d5ac86620ca25912d57a72351644f5c4a74d20b78e0bc1a3b93049c392b7b11ae6135f1fc6676771b95fee23e2cbea37524c1beb5bec43ae1d58704" },
                { "sl", "ba35642e936b625604ae304d3d68a969706519827a796e75bb74d0b3ba6217dfb7d75c65defdf1b8cc5eb28f11a891b26289c296cc372fbacda324385d416064" },
                { "son", "0ea598672ff687eaa3ffad7c14f9fd713f642c779f2d0f412b76d5bfc3929e966048dca9fe50622855555cd6b7e67bb0930c50c6b7b9cd1d1f77c794ab4314bd" },
                { "sq", "f3dd23cdaa2bb78f7b2c0312da84fd83b33c0266d847a9c5314b8c1f01dc402339c08d5e84c39a9782c20e01313bb6d2d28d6c6bef56e5c66fed2f30450d448c" },
                { "sr", "a7c56aa47620a16684cfdf650e3ea120d88b79b55050401e33b986ad8565db8cdeaf74894332adc410b2ee470f99ff5b6387eba9d173fc91546f9752e096d2a7" },
                { "sv-SE", "a339a1ad41b46137709280ed8da69a92ecaec86bb411feff26bf17ed636fcaef4f901dff5da4ac5c99acb8461710b0a97948b3675d6b344ee39c901537b3567f" },
                { "szl", "95d9f15ee3a0e1537f20a22d49faf4d7375c5adddd10ac5964403f4903f5bddd790385c6698dbc6de01c3b2a13a3ba2e5caf657beb64503e3786d1ab0a76a771" },
                { "ta", "973185247e2656f7654d6efce99ff9e770f5f78bb2cea534330d705220423fe5c13c1d7660eecd67bde26a2be59cb41d0aa650696c52eb58cef22480a3f67589" },
                { "te", "b1e6925e25e27e08d45e9b589a12357ad5d1bcd6568905aa799674edc44b59f373ae313db7e5b930ea2e1262ff77613d1b3a825c72805b512a3f137c67e09615" },
                { "tg", "7f6a3f5323b8bb811893ea9fb349f6781308d5f02a15895b83df9822adca9ce40ee8cc81fabe63d4635ffa4e3b12db93d23c154b5ff5d9817a6f2ab1d46da51b" },
                { "th", "a3792ab565e408f95bf1f9486a65fb14eecbc6cc1aac937efc1dce4b9e47dd711913a6ed4def35b2e219df18fa5a9b1ed2da6046cf30ceb39b40f5fbdd293ebb" },
                { "tl", "e400750a503211a49d6530e3d917ff6157a8a8f11cbc944520faa0c07c934b632b1781e20e77653fe88f0ce9a2b25b46627c682a63e730e7813cfa6f63bef49d" },
                { "tr", "4091003c962d21ef56ff17011c3d2f7fd03c45e025cf51e338d9ca8bcee8dd127f132064a8b4cbd84935c40b3a70ffb88a29c5fbc2cf8f9d97ba938eb706fe9f" },
                { "trs", "4f70c4a5bf86c73142f0349cea8dd3093de07ee7e36bbd004ea795d7da716e60c4b153048b6a252841390897c574f0b6a0647bb136ebd1bb388e266c536207d0" },
                { "uk", "64856cf39ee4aca80a376f004119c0f49576bf55fc5470213fa775d99f626c72199a24b1e922a8be1cd998118f9125ca226699ba0a1cee5d085a76569eebf025" },
                { "ur", "ebce8fdbd4e904c3b825c5dc70b1ad048f8c85468c720d9705bbc5ce60b3319b1ed89fa8543877612e45e0487d3581bad51103bdf207f6ffc4b5ee0bc41d9e6d" },
                { "uz", "ebbf542e5ba468cfa42d4983bab7867c568c3e81a5dd9c9d3a4a3e00aff8de6409bfa1923b073630324799ee0a23839da25700a64c67c50eac80ab2c5c590f84" },
                { "vi", "36a9bb84613e9b74a68396e46dff4ddc1a11c88b4205dfb082ee59e7c638e4216faad0ca059e60800a285820f35f7de933f51bd56fe666bf7ac8259d6ec87431" },
                { "xh", "695bf1c2a8aa2710a21e09a90941231885fd709da14ccf5de12699ce4f3a2195395f0417aa7d01fdae1cba934310102e907ec74e8f884eee7010d1203dca1797" },
                { "zh-CN", "00292c037bd08fb390cd2b5308172a6965400de7c7e40fa32c7e13e4f2b3dcb47f89f392aef24a146fa1fd3389b948ea0a7217bcd3e98bebf44edbd98ab2dcde" },
                { "zh-TW", "022700a82c620d2bd583f6274a48ea02a569e91cd1663f1acd91f421d9aff323f34402311e041d91028d5f16dfa63dc9fca3fefec3e52ac22d731b5e19bd1d84" }
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
