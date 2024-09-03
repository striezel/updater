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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.2.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.2.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f6c0679b4ce014124125a4a0713504a99ad9ffd22e0805e1825c9dc98fb5b2eddc5328e4e1d80322fbd56daffdee480ee6b986cab87e41f26f75ad58fece953f" },
                { "af", "03989beb9194b083276ab7720137f035a306b9d4925399fa9405edf77bb6b0a00b92083a261439ef34fa9d5c710dd36599249ac273d44342249e5514439a8a21" },
                { "an", "98b2fd25fa352ba0421e76e01a42d106999424bb08863c2ee35b447ad14f6c0db774ea3305689464438f40b80be476d0f19c46d81048e4b78959581b21126cc0" },
                { "ar", "be0e13ea2c63ed9efe4e5b2d2db4cf3425edbe4c115f91fe7bded99432124bb470248e5c77a1aa9d24ae781205647f74a8f8d51ba55bafe72b7fb3e2ef0973ef" },
                { "ast", "d63bfdfa1323e8fcf8e52bde830cf596d5f7158a80727eafa50f56dfdfcb67a74f4285ed2e5dcf5b6f1790dd44f48e1e07f3ae8b0b9be2591d71c5b7c6b4ee12" },
                { "az", "7c7332f632fc665b3979751c87e81af225fd4dc1992db070ac4dc4933923700fe1d7d4c3dfbb64a5f76daf022ee20872b16ae2c10e73a49f437e9c4cccd15b29" },
                { "be", "1ebf1bfac5b253c1d5ff559270404ebef6d825d15ee1f306b2d92f84672dc13b042c15fe211eece15b323b32d91cf1d4d71bcebab08646990c69bc423b384a4b" },
                { "bg", "c035539bbe467e47941a20e58683aadd366ffd2c055504cd1d97212f13f38d445d1008a922f0535cf96e9250dad04765e53b115447820e012c0711bcb317c04d" },
                { "bn", "92b3c4d1c554ca17bf25c5ca8063ed8bc4ef0040814d7e50293c50feec456bbf2d17dc702a468866bcc841c74ff1fca7c47114e78b9e9bb33d744495ab4d6366" },
                { "br", "59735a6cd58863d698075125bae628bff8a9faf7afb64b4d8ed2082c9805689275bcd2640bde3438ef8b2c01962df96d2c8225a19a4d2579978b83d3dc9e15f7" },
                { "bs", "09f31674a71d26da0abd42c2737fc54b79d0b2f7940a4fb6c7cd6f1d2858118554d76f0f7f415d077b7f65df381b9ad069c584d77ebc0011d47d75eaf5a6ac4a" },
                { "ca", "53eb93e30a052c6337b0c39e63b5de51a2667e2cf334d6be23c139ea8f9e7c2dfff15e85727649f92e40c444a89549ac098f19696877335653bd93fb57130b71" },
                { "cak", "a399a1a5caa2d9cd68d1807dcdc9d57f581d51b6e10cfaa58e83ec2037660bcc45ecd2e401e49dc93306b8195398f44390a577056ddd838aa0aa2b13918f4f30" },
                { "cs", "e90b180d62585ed43c30d24263c71a6d41579226195e10d273fbbe19a12ccf197d72b3cda47cec4be9318e82bd91834cb7730de20f8fd5d6b8496c51cd98ff0c" },
                { "cy", "27a37cbde8ffb04e46a6b777b142b0eff9e3c22cdf007c282da7017285bad612c14e3be8a0f142b7ea31e4abf9fde0fc73f8c56beff6c702b9bac1ae536ddb9d" },
                { "da", "c7f990d132a417fb942e3caca6da6a5c0f2643afabbcc2fa9a0f2328e43766170451237f92887113dec6f2025d179a8f08c5e864142dc4b3fbd88878e9d7c0a5" },
                { "de", "47163700a246626ee3ddf53b4059d160fb900805496c4a1fad65f197b2f6ff05101c83cf9f57eb22a74c14e7e13dc88894ce77a515852547d5003c196aac78d8" },
                { "dsb", "4fb66309af4943a8ed723e59a721d193a467ea8eb44df26fbebef0b212485510b8ccde2f1129f8d8b0c1e753beceeaab6e498c0815f1375e658798981e2336f2" },
                { "el", "c244aa9dbb891f0747bf7427bfd6848466240d4bfecfcb682934fd48467baad085d1093c7069ae49d4c69f54ce6f2f2e594911f4ddddde5170ff7c4fc4ae44b8" },
                { "en-CA", "08150d23e2e18d6d70392881040a6d94e204f41bba1f511a396e53d4f9ea1787ce1eaf2c6c1ccf8f0954e07c43d9e5667f17ef85b859658c4df5630fe7441e1c" },
                { "en-GB", "0f6d04a2aa971c5c60dbfe07feaa0861e371911884e5d8a911b4a51eb8007faa754ae194e535d01321a37418b36495ded50052610c4c23cc820ebbc6e3fda840" },
                { "en-US", "f7e10da20f9c3c4697a20658898534a513c703c8c74d26ec4d531a641810f1e7f68fd3cb1fd50860e16c2c863218b221fba31a8a5747774a8f54955e3d394dc0" },
                { "eo", "7560bc2a1037599c172e7c8776df3dcead73b46ace376ada62a482567709c9137bb22fce126aca39ed545106515eccd607c23b1aca1a06ae985ffa81ae796c54" },
                { "es-AR", "5a37d037d7b3ba85353e055fffe4f0a9a77a425546f1548d50cb99831a1a51735e7383c2d95d1c542aeffb951d8d452dd8f2aabef0914797ef9f2077b30c3451" },
                { "es-CL", "5c1dbcdd0ac7d8a9841c2ec8fa2fb71ad89f6607cd653d1010ed2d33b6c66051f99be322b4b8d077af8e52f39b7b92f9c136dbbf7c93a82caaa59b21b3273d69" },
                { "es-ES", "aa5fd23a3d337627079ff06ffee063b7637600c1bade8d8c6ecc3af9f879ea089ef892b1cec0927649f9c6413a1b5fcf2b5f4c224474aa288314df18be9c4006" },
                { "es-MX", "5b53ea4bddebe9b764d3602d3da6feb0e5b282c410c09b711303cb87b99d5aa39518a6a9e53e80c7bf272af6ed34bd728cd69d0ed1cd3ee9d120065ece52d8dc" },
                { "et", "d5d40cf3ec865549bd12794eb692456a53971dff67a6e50551e7b2ccc5a5e9b9899934d2296630fb2436b425afa7e9151ed30178b07d093e482e24f69b2b1821" },
                { "eu", "c5deb1267e538e53fa44ea47e538f7d63fb7353b97dd12324b0f195f2ad8ff720e26c7bd66442d7ed6b7fc39b23167fd3e45e08b425b1c12501ca3573fa974e6" },
                { "fa", "f6ce921a31f58c162e3bc0d70285bb347d22dd77cdbf1624e1064ed79b28e75587000e0ac9fd2f27b67c1622e66817e9f534d0a7007d88df6e8632d61cf4efe5" },
                { "ff", "21eca72149946d49ae1367d391bc85a2d5784adaafd33ecfde93dee2d1f16059aa4a6e5d9e40c7475a02815354d3760f246ecd2422837080aa772293b609bcb4" },
                { "fi", "cea17a96621ea41df8435c0ba861c418cd3dfe0d7ca91d46f25a2de23384a7a49f832b97394d53b896f64ac6e82605cad4c99bc65dcc0564578f7e55f0fd6956" },
                { "fr", "07c9cb9b1435dcf5cff2f83e172d45ec58bedb36e2c223f12b548917e2b1cb85a6077f9da86e40b28889615606ede7437034eb7050ba57f2a77d5e6931135537" },
                { "fur", "48ac6221a938a57f610d45b524f1abac2884dc90547592f164a3fb5f19b8059c5eb8aab332cd63cf3dc621a6e6342605823ff7cc23bfbd368f55277d4358c21c" },
                { "fy-NL", "b8044d3b9d798abd407f5f29fec3064c10ac7e66749bcef66f049c2e20a930a732ead1d9be74ffe425f3bfcda06af4a24ab19f0f5119840cc68bd2049269fd52" },
                { "ga-IE", "f6c4b8fc66507b6e963786052ff168531b9f557dd7a2c456493d6affc330c4f533b77e561079d35b18bc9ec31abb9961bf0731d45a651452c65287856382ab89" },
                { "gd", "c674b4f39df7c0bc4416b1e10dcd97a7ebb741398a9380bf019c8086bfb32f30f99cc3956142b33d699e8c96b831d83ad5925c6677ec06b06b06df8aac7631d5" },
                { "gl", "d54177502a356ba23d6f80d6280aa7dd4caf24b8032ecc704b675d0479c42bf01adaec00e2e1db8973ce04b707c48c4dd520b195729f590f5494aaed1aa93f56" },
                { "gn", "1659c1d08929dbd761e0c729d194438c9bd98465c5c9d02186d920b84cc921196cc727cc643b1a2beb02c1005fc5e193a0bff315a853edd33f3b6fc17c73bf8a" },
                { "gu-IN", "2e3a54af0dd8f5ccaebcfe6944c38803f58f1ea6e1d9ec063b9700b0e7a4a2f755465b6e2055c6d0c109f0bd3c10b284ab20cdfc8a98ed7ebffaf5b360cd7fdb" },
                { "he", "32603fbcf0aceab85465a1b81a7d2fc332e09c0d79252b277703fa8ecadcc98cf89f0d5203a02bb61d6f28a21e23dc1e0b5b3fdea4f3efa175a175b9ea06fa2e" },
                { "hi-IN", "8056843a603eb170c0af91727b1dd95a61a3cc8193f007b35e56c784b9f838b45557c97b9017210701f89b737fe7d04e7389fe858cb5e7a0c84a6cb1134b0677" },
                { "hr", "c4772cbfb99a84f1bfa31a0ab325b0d2dc6067b03319c6e95db333b4826009b9430bb9f7cea43735f793635ba19815c398725cd47f07535b9b77432eee9adc9f" },
                { "hsb", "a85b09c6f9cb9e98b2b814021bdb64ca4baae4ec51d5068b71767cf820e1f542f40310f769c5b7d4b0831eb27188d116176be396eb3af106b284e6ed3ec04d80" },
                { "hu", "982641cd376ed5f2cd9e092f71a0ddcfe2b108964c6e3d219dbd2f80849cf573fd254f12693cdfa9a4015979f9a5c22175e4eb06a390fbda756ac4e00895add3" },
                { "hy-AM", "7b7b2a9b10c0dedb4d1490de29708ca3f2d0922bead1fc3bb7fef087fadd549ec1518c167e4f5b23c24936d5272e35b111dd9f2c26a6c67bb6eee431b4b50813" },
                { "ia", "a49803a5da63971c84bd608aa41f62209e5cfad4d22d5d2893ed3142a94709dbaebfe34c1f8080d7e804aad289204402820773b0eb41779eb3747c7d336c5ee9" },
                { "id", "b2f7b81c28c72216de37b094f54c876669a657430d461e8147b6d84fee754e15874cb0a22642b8e83ee87e605a3b1f7522b101b1e14e3f5f22aeb4a2d7926c35" },
                { "is", "0cfa4b6a6960229be686d05439b993b98d8200698c4f892f34b8236e911f0b28238b0c59b29bdc2c86f333dbb0e10a24ec48f48a01c80adf03b6935de08daa4c" },
                { "it", "ac39ff0924a6085356cb381ac8330258e295f54e4568e50f3dbc209ab8f8705eb1b19e25d5d66d7160fb52874b126bf275f99079e2c0cd4452c1932002ce5496" },
                { "ja", "93970b9366d58cafedfcc361996875986e2a11a40f2fdfeaa407ee2fcbf36d04e1619b97ab86de102b745ba4360cfcc64e25b1b53118c39be871dd8ad1ceb683" },
                { "ka", "a4db3e16088837ead9b6dc9e4c39b59564cfcbc3f2ed744d7e1f906a46244bb38abb9e8bb5330cd65ddf0c08c433a81f1c0e40a954c8aeca755d4e002f545a51" },
                { "kab", "e86fb4a74344b3cb71f52b1670dcf914de35f15368443bea0870d86a665e4c30846a25037af6c37e1a28b9368ac6964f4b17bd3759a2706fa75514aa701f8152" },
                { "kk", "271e810cc19909ebd616016e576cf5ee87ed28c9bfc7abf34344ad336f3551b8a5263f837dac90de8356585e31754fa1175878bcb17d2a2f90070e25b79da4ed" },
                { "km", "46d273f7e4dc4e03ee6fea7edf455f3d4d7424a1dfa15901631b416a5e6b2b6306c2be36315eeb9bb26d251e84b6f0e618672e609b3057757933d8978ebf72ff" },
                { "kn", "98101dea0e1a2fc33698e6f1fd84cd99937951ef0107bdce79a909b2530695663813452edd32510892c88e8177d0c754d74502e0e7256f591ada251d8d3eb839" },
                { "ko", "9478bc45301e1333f65d9b3a92c5c7a9ad0b52bae0821701121d0210e6fd230840c6a4b89d91ec546d40dc690184d129dc39f27f9d90a41afbcfeb7558a84d88" },
                { "lij", "f0a6030beb0ba5c7e5ae20ca3b80e1b65c08183784ad76503592b4776a3b797d61264096a6c15d87f4044ae6edac9b805deaca9f8ccf146c340e574458a362cb" },
                { "lt", "d89357ad3ca5acc3f3c34157e9427daf18a92c9b4d16cc33d07db36e3d918126ef36a6ed8a73f20adf773756d89b67e2442dc671c8a66225d2479d42b5f7c2c2" },
                { "lv", "3aa0573d0d9112b075bb454d156be1a831d746f495183acb9fe3da37922a0fdc71decff295f4b196d24ddccfa52eb0c2f4f25abb4e696ab1103971e0d2e677d0" },
                { "mk", "f9354734af6967589235fd2558d6fb2ec4a53c23d206eb3f5bb9f6b49cb3ee97e27e04830f32dde6a551808dd04a2306bbe98bc83733b6a83af722f2049dd3ba" },
                { "mr", "b200977afbef67d5cfbf64369639a29d4f3a50ef71b3edcb410cbb925c2b4212eeebcb840f01604f1d8234c30481a659fc49df4c2155652baf4986f17bd3e789" },
                { "ms", "6835c67a5230e58f791bde54c578a1045ea6bf3b88525dba34af47ecf8a65a34bf5554adf85d419a2fca72468c9e8b0cf18c69816c24ecf8b2e1238b288268f7" },
                { "my", "3db28641f77360dfa6c4deddae4828546074b29eea4303028f1781e6dfe9312d8a87dd020fb6a7b7271ee63516e9dbdadb0efa3433bdfe2461b44a9b079a2366" },
                { "nb-NO", "18f36d037eb81981c603162699af8721c31c08b10e2925382abdc9f76bcf2b240f220fc9cc22c7ff073b018d1bbec0ee5400d33fb9b7c35d0ab23d6b905535c2" },
                { "ne-NP", "3bad038d7a2850edd4b837797a95fdc4c49b93cbf36cf7ee13d2bd6aeab321279837be109478e2a029e460f8a0e60080248063afadda3fcfaac84fbd75005772" },
                { "nl", "361456a1ea4bc7e17c94c451abbd9fb109c8bb3f133af4d2bc0221013c7a2b725fc3578a4061ed5e80f997a4a1a05edc1f08ff3d70f2546e5a7c04efb344f3b0" },
                { "nn-NO", "6afa33b2c40706ea965b2e4fc0ff1562fa1071224b35aa7ac0eb89824eb38ff445cb67e921fa3ca5b2ff15ba1c3b42bed7cd076550a5f3ed33601c4b15ed27cd" },
                { "oc", "8ddec902e28b400d916df3dfbf0bcad683cb32f116dfb7efd7530e7ab576ea1b9b891aa2edf39d9b48a3e60311e8d2a31d67d280e619e859bfb586fb4bb2e849" },
                { "pa-IN", "ac1c3a10522828d016ad4099775cd486fb28d9916b0338738e3e6c37f2d0e070b539aed88aa54d98b7dcce6b2e812b490646d169fc7e735abae1a72f649d522c" },
                { "pl", "03f7dc570cf42f1887a9349db2d326cf01e082b6eda17eabebc30f1c9817214b74818c600b58d931c431386cdffa56ad76c77d588d836acf7f53c5ae7e4d3f4d" },
                { "pt-BR", "abeea94967f11458614f9fef5ddef405b7000ecee254d1cfc6c6bb8edc644c4dc264a35c75480ec03b3ac4a0fc56c4bc1fb991cf0f44792a78a959e2d6d7568e" },
                { "pt-PT", "46ba22ff23bb77259f80515ede7ad7ddc05050b9428422c619f7acc88ab870b0846f0e455786cdbf4af764a4b2a82c9dc3de480046cb761bb7aa33379499efcf" },
                { "rm", "255faec6a9e638a50149b7069ac564cf6672e39399047b7cbd4c08f49f251ac99dffb341105ac53d874c4e50f52b49136f15fa3a81c0285761d96c7bf6b3b829" },
                { "ro", "8ae3ad144cecf8cf6ea01e991eb2d4af9fd64c6c64c9adbda975eddd2f1466a3ff912e4d32e6ce56a390eeb0df3ba9de9f6c48d3265c6f38f47cb6dce0b59611" },
                { "ru", "ce843183a7e2a35f64a913f964337f0e904f9cae4648170f7a7bb06f5b2a776bd89ea619711415fe64e10fce2ec37ed595b67c5a8629e13455d48a3c02e7e559" },
                { "sat", "d70cc82952f5b695a39aa071cadf53230e6e9a2e2e7c9dd9e75e0d1e2b68067b2d7e56793c88d92cdd5f973b9ad819779c906c06339ed0a7f1e590c5d007a8a3" },
                { "sc", "f3453a403b456ab3a2de3b8c837db5bb2fb90b84ebd837fda5ea0cfe52982aaec16fff2ebfcc0f5b740dc01a5f34cc00fc539b84b1fccc1a080cc4d59c02f810" },
                { "sco", "04f9ca80180a7500947b25d0a1c39ea17d39ef414c4afaa3d0ba3baf26ce47995335ff601fdbeb808d4fc809c8ac5427b6cbf8a7fceebcd099b9db8a960ed0c2" },
                { "si", "e224b268498b2344782482cb15bda77e7cc97ede9300fae1ee4c868371c34127f2b9e91258447fcdf127f811c53843b2c0abbd257ddb1a6053c6777cf226d472" },
                { "sk", "5a3267cb9974e6f58b6cfe1d2b9beac077961e9d8b4313b9ed5dc01434b7c187bad432b3179cf98928b85ba83d9e625da3cc22463c54044af9f2f586c90293f6" },
                { "skr", "7a3607376e3df8d31dd33144df39468929a62896f0bab34e931e99025d312685afafae94eae622f3e0373cbbe0f6e30a4e92a5d200366954d2bb84c620c6e396" },
                { "sl", "a814c18b98b0b4cbff28e88c91508b9254d8c057aa5e0ff0cb946897dd060acacca15b00fdeda8647ac8b75ab02aaf350fe7fe6e1aea5c773646042cf0cc7c33" },
                { "son", "643078510cb77c22af48ab3071a52feabd0127c43b938f922b8e02374ce9a3d7935570d4be77e0e3d697d2875823a6b5ca239dc577adc81854cea63479388324" },
                { "sq", "09a59b3510031b45774501f2bf5c12a0bfc1d929791ab18ad44705e9c38b6c2bd3c38883b17a7bbf554a1f6dcd04c2eda106a566f8d8dcf513a5a29e347282b9" },
                { "sr", "1d23feba96bed529afee2fc13abb79bfba05747ae60535809dce85ddaf7781efd230ffec260b1beae9ea7a48559a16bd894ef3b8dc0ad884766524d2fc9391c4" },
                { "sv-SE", "07c0b9d432cc421113684ab27ce831e98ed4bb134f546d52dc4e0b6fd4b52a09c51b07643246f7833e9afc57c6a4b19b240d7fd9c085d2ef79df17eed10f9926" },
                { "szl", "356331b2c7d2b917bdb1028a66f5fd0d17b2c04213120d298b149cf85eb054831e9042f8fedec1462beacb2a2928fc5a29d70fed3aa431df2af19bed356af0e0" },
                { "ta", "66dae1014ee5ea9df245ad9018287a2f7ad62ca060e43ec97a7a7e9845f4b16870276b568c94402cc39977da20562cd84e906f6bd18276ad01418c6241d6306c" },
                { "te", "22b83c630610dd58b20c814915a9a414d3aa4bf8a84e2cc1df179a80d211a6f09f535a07f40c8180429aac1cf94f9cd966f444c7154bd06c316f7b7965994c6a" },
                { "tg", "b1d854349270cb249995a5e98d151bf061283777a0cd435b0bbb29fd53a5a16167a3045c957c690686e7c2f9bd5ae5ea98907a09abd3520093192390f7932e08" },
                { "th", "e0bd9e263c86e8dce29eda26ea1c7b87567873e9201da766e391ad39b3585a13a351f8eabe241479ff57f017ca13a97f395cabaeba4fbcce8b237edb10de8e72" },
                { "tl", "0c4779b2dde67b784375e36c6ba9aafb40d65eab5687cfe93726e095c4b702e9d9517c4c6fde496d47651ff8dadb6afe88b1f53357675e772c255bcce9c6804c" },
                { "tr", "461272b9315a4c4f0083e3d568b93a151d999168d514e5c854413fa3bfd543dcef691bd2eec3e956534aa45a24e4dd83244438dcbac5b2ae58fab7ec80974147" },
                { "trs", "1405f8ea653e28590a2f8b88dcf3bc0aafebbcc2336353d7179c9302f20b0383c068d5700f3e43b222db91e1bd14337ec6852019a1176222a13f7899a4f66965" },
                { "uk", "6de321a394374a657da427fed5f363819255416ac9c817af629b56eac0a80498cd1d66cb7f03e9bfcaa80ba7a2088234a9d32349c52a025c0b6a9ae57631ed11" },
                { "ur", "988117fbbaf6d8bc09d600865551aca6987317c0fc6a0e5ebfa8180fd537154281f3837739b76aa0563dc9d4700335909c0bb2bbadda1f98328618f5a3d0287d" },
                { "uz", "8e3d5e8bd0f63dece83fffa124c3f07792f6de40b84467e955f255e36b870c2886d5eae2ca0c3a3c0610fd5e73bdef1acd9860b90b2f3e3ae892a50eb0a15382" },
                { "vi", "dd377d380d30dbf4b7b502e8c58aa82ca28fbe6b0dac0611ceaafef33ba012735edc8310eb10e06c390c0cd55c715c7f492e391710f5ac2adebd6decc7b4bdd0" },
                { "xh", "832a46b2115f4603a568b2ec406a23a7d9b020dc4f43b0868a173f79d29c8a4390c52882b2eea036460838e237a1c4c8881d8aaf2fb33d1fd7692be490a89f55" },
                { "zh-CN", "e34e9ed7a5d9e6b49033e035779f12da9b71409b6c5ac6df59624c8fdc6b141e2d24b37681df45ce2fba417098400650e4dfd87554dbc73f792572cb574d1d53" },
                { "zh-TW", "4b0c9300091fbbcd565d6096d76e3a67d627120864274e1d7e26eb57df1ed0d39006e919963886a075d675f8d17d44c670aa8f0c768b7896ee29147b5d794be8" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.2.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c10264e62898451c27ce7bb7944d1a83d5ed9ff77f307c306c2daed41ec7c24bd00804305dc3ab2e745acf483d8aa3606e25d03655854836828b001892f77664" },
                { "af", "298de458dcbce6742a5f2adc5acb38aef2c7218a47e2ae23b9ca48b3bcff9bf7800ab5a62ee959dee5d1851c92a75f1bcd0bd605948dd763157cf45e69450c33" },
                { "an", "0a301c694e4ccaedbf6102a90323c5684dd0dc79b89e771abeacbb5e6c4a7b903b2bd471ac6b41f07ab53e9455899c2114333a64b41c10cc63b0b3ca2062297a" },
                { "ar", "4eb9b84a96e9968fbaad8cbfbbf246ea5fa0adfdb2fe6afa19b7718b67b6c728fa3321b8fcd3427c414e6701eae3efe5199c69b7065a3aab69e2f3bbff2978ec" },
                { "ast", "326be8d010fe911fae68e609f55a769e965179b7c144138ddcf6c68901f344c143e2a3f5ecea467b7251d410d73407ff820a0dfa353cc77c86515dde86d62c6a" },
                { "az", "5cdc3ac729a3a7683fd4e189cd73cbc02e2f3e4ddaca4b69b140af9f00fc1de698549e22982b0ab013e7b3f98084f35a985c37d5f453a3a684d2d072b1c91f16" },
                { "be", "9182671050756f39102b70365727992c1fc46359e7900b25240d7eb5228d4159d1f3eaf7888f3a8bba4495b7e0af48c8d919dbbb39a9c623668eda89d6ae3598" },
                { "bg", "086fbf6220838f41cc7fa207a7bb177753ead2832618bba32ef59bb0db3e60d52eae1c8092954b196f3f2e84a76a863fefe83d98ec0627d64be2299381abccb8" },
                { "bn", "32bb31bd641fae7a5216be2d2fb4a75318236b99cef87f66fa2b45552c795952ab654cabb923f6c69e979af4caef21437d32134f5519668311d4c9c766369d95" },
                { "br", "866225d3e1bf7d3b7b8400326165a25680264d0dfb06c273e9bebca63c5f81378a33170267ca2db01228b5bd3851bbf7bded8d2d70ca4fe3ddfad1138616cb43" },
                { "bs", "6c6b8c1caaa44e655324be45bda9519e52224cc59cb116d8fc4895ed0127f7d675a6a7b5f119a38bb4c29bce990e53e7d100fd4c21dd89af631a29a3bc0667f3" },
                { "ca", "f4680638e1e994ec1c873b67bffe917d0a3e65d83d73740600ee01f824a4b861c4d6519a821df80a74108f90bd6a22b427139e7813785c11a73bac96881f1b47" },
                { "cak", "7b66b75f844d9078c8c0331ad0d577a7b6dfcc92d525f742111e65c6c53ab9687324e7995514a9c88f055cb8ab88a2d73e69ae9a047d4f70dbbe0fc5cd129300" },
                { "cs", "d4f7b84fce3415e45f25d259ba290fd606c9b1c75f87d220d2de312e31194b40bee3462fa193a6a9fd4b2f54ce6d1cade042e3ccb5a65bb28ccc4cfb9af8994c" },
                { "cy", "83a5cac428d2f72d015e6f566ad16d6e27fbf7e651875f75092273afd45c0b22af61257a05e6f078cbb2b13ede30b2980da5ca5091867aa099edbee8db6fb0a1" },
                { "da", "afea5cbfcf4c231b458406fbe0f9b558f0513908a2a9112073dbbec0de85004f81f283982dec489d3edf18b61af14a51e392d0bfad9c26a9046ba0c0dda9b444" },
                { "de", "35dd315796d40924c5d0dc4e626f4ce7fc780190d123fa4154ccef695c061995644797e6114d00b1e485250f53916f9c955611323346c63fb9775d74bec95e31" },
                { "dsb", "68dc551e3980d63a2904225f2ff079c356e5cf6f639561d1f34a639b22f048ecd4714df77bea3463fceed962535f9ea08fb46f92f9d90cd67ceaf89f88e474bc" },
                { "el", "1ddbbe4b4d48786ad6b33f18df1cfd4a3a09f2f06ed04629ad50ba010810b29e96b7e2e03dc871024e44e7ec6e7549423c84ffa98c99867a4c15b01ab2512de2" },
                { "en-CA", "20c8c27844ff67676cc3c75bad9f08536026da8239d8017d190d2b9457a151f2aaee8d38ff497f52f212b088470b1fc8c2109966a1ad897fd3685120071069db" },
                { "en-GB", "a4f2b6df533d868646e1d45db5728023efb416a401f94a12577f769a0702f49e81f92b75d6bc82ebc20c6021642e1eef0251cca77fab629cf10d348660688ac0" },
                { "en-US", "f8a733f236800f3fd7c9e95153a49a23e37bcc040b210ea3de5cd0b7c5039e40b0e03bedc6a6c993e1e8e1ee0a6d854a423980e17a44808d9770dd9f8ff323dd" },
                { "eo", "63b91b61a4d0578e08decba62879146422f6e40ecde2b28b813473e0c81170a02ab0b5a8a0f06de0192b8a7ab4d9558575c396825927ede0d55d144629361e81" },
                { "es-AR", "b7854a596f4898dec2e3445212fefedd26be8f08f0c22c21af6526cea2d56ba8ee68cda86b2b4c19fe99bbcad1f44fcb8d1e2408fc641d78cdab1013a13e2dce" },
                { "es-CL", "b0fc6a9370413b04bf42bc38af32de5722435ea86c9fde9039ec70d21a768b10bbe0cebac2ed272a291c0add05af703bcdb80e9a818c639696d476227c721668" },
                { "es-ES", "78123475da10aad20f56d954579c3951a39236ed0be8403fd65a13c8be33db4bd661b95dcf6959037b440520a90f474b0463a6ac38a10345c02fe47f1af52b76" },
                { "es-MX", "66523a8f1bf7ba2d6671ccb191413b126f9b77c953fae30da5ea90bb9cc1600ed4a48880b760b90af2b6f0d6ad9ba5ec0765ef6e922959e175b0cc2706e02d48" },
                { "et", "bad98bbb3fd5b6dbc6d07d9572af87918a345931eaa73a31c527e24997e39d87699516ab2f543072d3d87dc3df30a7665985de870790b40c5fa8a445bdedd0d1" },
                { "eu", "0be6ce5016f9003c2ca93eb1d3dd7e521a256b4e9623fd5f59f7b13ab5469b4b6c4e3087c3469fe10a871601f6a5b9af8c843d58df6c9af23b88c77d3b8587d8" },
                { "fa", "fc319fa13068f9fd564f3a355ed5e5f06025d0eca89cb20218e79aa2571e3e2f8bb35345bce2968d98a9498952184bbaac5034f437ef008284af169be37b394b" },
                { "ff", "a9421ea2f41ac4cf864979ec9292e18b5f4fef769b748e3e94951d4aeaa11faa13f3af2436c31646f718b7178d81b1da7666ecdd47707421693c214a5d1821f5" },
                { "fi", "2b040a1153607c0b6deec5433d4bd23396febb1894f537df1b55588f79d169175ead09d6b5842a71e5dd929cb2bba9f36437a7d69965bdea77766662d61835f4" },
                { "fr", "2187b89871227c246815063dc596d791192ce88b2f267dd0b1057e2e2fb3b08c15ec81e07a53ad6f2c6a4adc5b183b3170ea9f3a4e9f7c7c7854d67765038800" },
                { "fur", "92b2f0227e4987520e57df5034e6cb2b0a5caf05d8d711f805807e0538a7b1b014c04053fe53ed9637c88c1e7df4c5d41f7f9dda0406d9470d16769890a0303b" },
                { "fy-NL", "b5f96fb00b5010d1f739e824b588312cc2f4ee06fd7409fa9fe32832c4af23bd7e4f9cb4e8a40835396e18b8345b2d781ea0e712ce0e59fb5c54b337eb791fc3" },
                { "ga-IE", "e52377920c1b66c7bd112ddc0bff63db0dfaa0db62daf66391cad0dbd078b10370b59a38696f0120dab48f8ad264efca333757fda89319a4f4b9f9c223ceb746" },
                { "gd", "15c5abbc2f1edc85d4c51a75af5f1accc66e6af54e018073d28c1e4f7920fccf9e91f30e4cc863335fb759df50f145dabaa456dab94cdf2e1ea0afa5186e46f2" },
                { "gl", "c7b608eb147c5d5da92b0ed81b42fcec08451ff3ca8e393b733420823c6cadce850c34624092f61da2c9eba7a5c179bb56740689b67784208723d70d6f0078c6" },
                { "gn", "135cc422f8c4f2b956314d897864e22346437485fcbac977f9e1a3a1dc07e20c831eb2516f997346fdb8b6a44d6f687b5a7401d4944955101596ae61799bfdef" },
                { "gu-IN", "22a61a55a5a45e1014a5f9607b3ac6263c619bc6d8a8dbda363a7bff5873f195b9a97519f764fd06f50a2f7215508822a06f3bb00c70be7750038d99d053fedb" },
                { "he", "b38c0c23895d3248f1b8c9e2199ed02972598500bd3e45d99303acb256dec30f09bc1aec0bf386c49ead1ae72070f018fb80976b3a58cb0256665a4088e273de" },
                { "hi-IN", "2fb757717d38cd5aa00ca030f67ad89e15241fba7359d4f9f51b7a57a42940d19f135820ba194156058a371f18e00f59c4375d47361422e1a07d1064cfe96c40" },
                { "hr", "b805bd054aad2e9eda401ebdf5b00141f762cc9f441f84c3fd95dbb7d3c68e8bf07d48ff2e0abc7e4f5e88e766f754d443be4566bc39df7dd453224deb746116" },
                { "hsb", "bf0f4c3fb823972f5551793d18ac36ea98d425c8b6c61ac041d33b6ea4ff19b56644bbf8334de5c72cd4d556eeed619c3148b85343ef1347caa6a7eceeb35821" },
                { "hu", "20e38399a68776ed5d6ee8a12264018bb09702e727e99672e516982410955f19811565ae89c8549a6ebfa1cf638483f4fd453c7e9f236836f773f2e217d70ee2" },
                { "hy-AM", "52f804b0246938f5d5c6c4b740615d2dbcd879b686b6231b03925dfe55e1811b990981ea27091a0d970e6c736c746b629f92a5fb1868829be8e58c14078f5916" },
                { "ia", "a96731a6daf60f0d7ac853e62e3da33b21298119c543383f4367d95c2627758871cd72f27c1a1157596c9474c40c65b9face4409851cb26606c67912eebfa389" },
                { "id", "444301f796e0f5b8febcb1ba0f1c768cffe7436bda1cc3b887ff0401f5885e6c8e1720f2cc3d46050749df38f287cccbb93f3224eea5aa42d4489f5808ef2b1a" },
                { "is", "9d11e04bbe935bbb278669b1a735700e66a6f9450729401e5da81a72c5e05f7d07c5ed6031a616a0d6c757c7e94b6992e4a8e25bace3b7f485d1cc25827aa06e" },
                { "it", "b2879aaa1aeea7136697bf51e51c95272b6abf9ed4d6658e3e4da1488b010c6142e0646ffc85416781d7cd69682c2a2772dfcf7e11376aa2c054af4b3ce342d9" },
                { "ja", "367c4af5edfb6646fa96d43de20c425cf2c422befbcc821383e09763ab30b9d8671babd96eaae899ea8f5014ffe3e1893febfef8e0ba974fe20d06f56e6c97e9" },
                { "ka", "6c536c3365db921681c74ede8eb6683b5bbdcd52c4d65658e8a54f9e77a74df400336b517f9b53578066f583e62dee39e193a90f2f52e62bfe5c8ceaab132b21" },
                { "kab", "c149a728fbcb1b6b9815ea49a42edb2f153aa2ecd271c9042a89f141558d9a37befbc8ccb31a1384e94dcb5d0d3e1c1365419e8c6f8825c30eabad6c5522a2c2" },
                { "kk", "6bbf1516717c7be838386298596bbee21d74c6accb205eb45b4210388334c5d06c593b6170ba17eebd6964980c6da3b1cc2dec04254cfcf642fb41f23f1cd0f6" },
                { "km", "02ad23788ce653567a58b647a66a80ff9705c867171ea224cf1ab2eb13c86191cd9eb7f67495b6496af8809ed19b386f8c7f3224fc7c9e2b54039aa7fd26986e" },
                { "kn", "af87785f48a7b5a62b70b403e4e97405500cc7c6d0ef16f557bbf60883991fb43e2fb28701edcb42563e26f4d7b5b0c97cf2c26851653c7c9297e78d51056940" },
                { "ko", "2b290d19405d73485bcdb583f4e0adf3e52c2cf24751dac1cd466a19028ac6e78517ac10a67812b0b216daef5b6263f2913a9bd04e7378e7939daeaa442fcdde" },
                { "lij", "fa8bb9bf9c486d266a0a129623a5545bf8d1fa7bba6ef5aa79bae6efd2d99bb4bc0dd5e88e77f0740fc25a77c6a78e9fd1930630a0fe2536ef04e0b0b5d6d3d1" },
                { "lt", "995e875014057b990c73c64dba80a4012c20a68aea4fd87674acbcc9095046934e81e47233d223b86f4780651e008b7ffd9702dcd849d0dd48364cbf8a38e428" },
                { "lv", "c51e772c98ab1088f5e6f41cc7e75c4bbb63567f0c520ecce0186739136e221890c4b5e0f4e597d2ee6b42a4dab6b0dc9eb6b313a01211e7a68b6d2aee5c3d9a" },
                { "mk", "582c94d15cb01d7b2a5330721e89b22b2aac386128b0a1eb035392ab680e826ca455cb96ba77b4d3e72d9d3085c9f249759039132c9763052d6130090b64f786" },
                { "mr", "29c3050a1af44e4fc6745f957ae2e9c7c5c79e8d25bfba800bfa5cc98a1f037ac040d5eb7cfa64f4793bbd6f6c3044f4616521186ede70e94b9a940a3c7c5eb4" },
                { "ms", "e5ed89400d7d500eb7a87afe3c37057073b3c330495dd613dafc9c434059da1f7337b638d9bb32d91103efea8e87a2d36c7b47750df1cd261077b7af7fc4d476" },
                { "my", "a48864e6f2abab60715b444ad2dae84dbee91dca282d98b6e95e0a619ae55ac6712b8f367e54b1030a2bf9060e3a1a424ccd654b9a5b504540856b5a0dfef788" },
                { "nb-NO", "ba9d5fbab94f9d7303b9b6762ebf4dc0901528de34d099ed2ee08f14442c65fd1beaa8b400500f25633c5aa5f4922ed62b3d7f0c3d5b0612ac3d57f03dff6d40" },
                { "ne-NP", "9656f16d2a819d5204580dc919ed2f26e2bedcd9742e9714a0db44cbfbd7591367f2379a4b08158a4c80c2d4de40578f7afc055d41dc576fa80dfcc3fb200b3e" },
                { "nl", "a9cb941923420c956c68d1a923fd62ac4a18de19c84fa4d03b05efeb498f2ef9793915ab9babd996eaa2ebaa6addcc50b7125421a59368a406bacbc04f352798" },
                { "nn-NO", "97d1cc31e5dd2f251a6959378235b1fc833ce6b914b34a374cfc1f82bd514751b8f4988a2a1449ea4830bc5f0f4c7bf935008dd89d8d3e5110d8fc6f18e559d7" },
                { "oc", "386a036d841a89517691715e1ad64090bb613a5bcb825b01f8ecf72d52fec98ebbda7bebede7657546b7e18898a47fc7f6dbabd606ab593932f170a4bf469715" },
                { "pa-IN", "ea705dbc366000678a74e32f32b4c20dd5fdd50f09c8151324ffefeae5b57541ff4b9008ff98505050d0e52fec0e8b78a73c37e128d598bd2aec209df838024a" },
                { "pl", "fd893d8c335554f306228dbffe658e76e57ae638ecf4775305153c70a3ccf2e81e955895d2069fa5b80674f38e0becd83a833c75a0d87d4af55d1d8693c7dd67" },
                { "pt-BR", "0b5f46098a6f1262156f6845e4721a1ede94dbc9fe4332080b265ef06d40691068677623bb410836602673f512fe5b6dc44a4d7c8dc9dafd89c71e417b1ed4ff" },
                { "pt-PT", "18035c2c3958b977c44f2dcdebd60fee1257b090b3b7a619713ce8bbdb46ae8134c407e3e09b99617b2ad4f9daef64ecc65df48768252797c87eab0c19c32be6" },
                { "rm", "49d52be21039930b2c5d07f0985cf7450d30295fcd8b77dce7cb947b369f624dde3c32d02a484b095a08697f0d9556b7779e07b8f04545ddcf4b0e940ee30cd3" },
                { "ro", "8c409654455f648eb3a2bd4d2da6000a7881584c915340d157655b7715c1be88001fb007acf6b97f66de782689eca0a4c94d46777b93ed13f0ec1dc2cf2f2ce7" },
                { "ru", "d91b7751c2fe3c32a1538aa9069149768f94abaf745023d6ec8a35999c821a94e2d111a7b35ed2224e2d5eaeb5d9aa3306cb6eb8a872702d222ab6306b47e49f" },
                { "sat", "825c218ac687a33f01d2e820fe14c64f2b4ad8da7cefef9dda8c64f88087e7010f6fd8652805d76eba731c09b886bc713eb0645086772c4b38aa2525ce5b7d67" },
                { "sc", "6bf4ce1f486f271ef12efd8c6cbed18bcce0c127dfe2255ec5a63cbfbb283bce1263ee4144ca6cf4d8cdd541f3854d58c18f7191573c908861fe6b923ee5e49a" },
                { "sco", "b51fbd5231a7c97108b839e6caeecfc1a803fbe4c3bad36a8316f21d7efc40c4a7dca0fa12247b4c1bfd5c49c5fcb3c0d970395a19f362fcd0ca7de50074b5d9" },
                { "si", "19b15c7ad5afde9076b82cdfc8f8b7608bbd121889d0cc2a0a3bd2478d4b415720d66abbc78d3ba2cd42695b8a50da55bb3372d91e442b579b1bb967fccbd653" },
                { "sk", "b1f20b0ed8d788d56ebdb814916215bb4667d53c126ede9ac1bcaa3446dec8523b0cbe2993b5129a025d8e8ecc3886014ebbeac473bedf952d38f31cf2c1bc4f" },
                { "skr", "9e18f67caffd35f884e8fca516d4a06f8941435fcb11186807e06c3efb553983f8772a6e9127449879e2b723c87f5f90f5309cf5f41618187a1a6b5d7b586769" },
                { "sl", "c9552b71e30696585f8a3f29a79274b6b270765a0007d297128be56ef2a8ae739014253d0158c47b91ef6f2577ae81a3368bebd3d352061bf91dba09f53b1e7b" },
                { "son", "14ffb6609de376667ac79f7b8dbe26c5fb427bf98eae33aa4ed1d010bee522bd92dd3bd417a92c35e59d9735146d6f041a64c16abe4f68ce332a4b2c16cfdda5" },
                { "sq", "d1ec86e134023d5e8fffcb5ab37289bfb347c095773e015e619006edb392678c024d0ea0dd748db09989ed0616602a441d9ce537f62a3dbfe3965f5a33e0f7cd" },
                { "sr", "0846a3f7dae53f869ffb7b5612495678218ebb1fbc1c0a525fe396bdca98b7b3f4b2566a1eeb47cb2a8a875232f9a05f2e5e39f0fe9a4145b91528bc01f4f4f8" },
                { "sv-SE", "6c67694fbac0d5671d599d9c058ffc518ed196512e672a2c4383deca37d03b459b224fe8830637eab785cdba74702f112c6b5df8746797c4ccad6a30a89b70d5" },
                { "szl", "82d1a5335ad7d188786034ad37b955c55cf5b1eb86faf2aa4a70772d95e294bfe760a74b1fd25e369bc16a744bc4370bcd852cf67bb7dd0b844a100ff338fa63" },
                { "ta", "8d4ec21f159e65a73d428be1cad49dfc65531bf881d9db60ad7792d5cf4f66f72abf709e07438470bc172db6318f1231bae25801c2366eabae52fcc6c2985371" },
                { "te", "5358342919004fd4a73276293930e4d89b757b11a128da2831ca1094f0e94580b26aaaea268e34b9b5bcf694cb6c46796f8ea51c28ba81445657ade3c90f7ab3" },
                { "tg", "b07ca09ab854be97eaa6b84c4d1062bce611248f98c6cb56063f666ee14682a3f2a8ce89f8fd0c27a94154c23a3e61ed099ad82cddbca3545a0fece78d91dc6e" },
                { "th", "a0c94244e99c64819e201f7b9d35ae1fbe78119b2471b434db7585b244e94439cdfc24880deb1f8e676de7c7874cb7567562a9eee673d799a32d418793b652f9" },
                { "tl", "c8a5d5f9a19110bf983a331d838d008228dd103cdb72ddf09db9ea3f71e7f8181796a79dccc23e6cfa8a759ab2b9aec4492982484804a0c9cb8cde7e02e203f4" },
                { "tr", "e9dd641d5b30d3b9cb27e35d035f5fce9d1142a4f5805ef6ecf6ebe52fe529ee266a9ecc1c9a7703d203e1fa2e4e584a85ff7a84fb1c5b6d079c27f33eb5f1a5" },
                { "trs", "a9f8b3fb5056295bfbb74f06436cc3fe104144c2ab4440b77203b777fdef96c7f710b6a8231c4a145cc3b170eb49279d200842f760f7bbdf3abcc4038713d37f" },
                { "uk", "4095c00717d96c07116ad457e7ef3734c9cbdcb625bf6c04fd7048e0245d388f708085dc06c73c6cf8b343d5be11fecd0c791c840118b868398bc57d24a9142e" },
                { "ur", "844e6c215fee4f0b49a701881b5eb857ae4d95136f439cbf2d83ff64b3e79969db992fffec496fbeee9708508b7d5ed391d0045cc63b9280e8ce5c8ee67371da" },
                { "uz", "89ed15aeb249445aa058174748e73816a95cc584d4ab9c58dd5685c3e3eefdff1a3cc081b5c8689afe944abd2cc1957fc1c9483f0b88fbe6f0153ab1806a80c8" },
                { "vi", "6dddcffa102827303766b108aa1e044413a9d58dae7ac40ba0b25040afd5f543ddd6b03bc99701b6598d94d1f87ca1fe4ba06e5c9e38cca81c7231d14bd47f29" },
                { "xh", "89f48eda220f0816057a34a96cc2b2a1ab0562b56f0d9fb9c7de343054cd6e5954d0aedda1fc88e0a7418882f2af22bc8b5b04a99a0dd555ad48b6b5b6c8cede" },
                { "zh-CN", "b6ec1c22609c7a4769967c0dac2f1f96eb6839fcf602768b5036d77954e3a42bf10a2cf3e09ae2cd68ca03a6ce74d2d400a6ad4f1bd153838258a04f7df2c50c" },
                { "zh-TW", "7a78c43fe28e19f433993025363765b2b24fb70e081f7767d5fb4a2e8e1902dedd9271970956bf3d2b6db9320280f6048b02a382bdef7d25d5a03ad6bde0a48a" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
