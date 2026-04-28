/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string knownVersion = "140.10.1";


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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/140.10.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c3d2dd5b7da4f258b6258efba614dec60220132afceb3ebb5514038dae5e3c94ac1b8ff25174bba06bc1cd8210d4c5836bece013b700d96a434d0e873d662b97" },
                { "af", "f2f9c702518f80b95da5135019970446c76c017fa1081ca7cffd5fa854ef57ab1b4a989e54a909ea0abd50149374b6bd3cf6cfc8bcc5005848c513e1ba6c4ea6" },
                { "an", "dddbffe89359966d84add5683e907accf481ed94a9b49163b90cdc6d3a48f68087c965e67c577b7019c05e02197dcd5aa9331923c79befafbd427dbd55b89c84" },
                { "ar", "94931ae62f4adf6e3751c454d7734a6d97661908d00244373b5f4c4a1e010b3bba7552f22c9abdfedc700ac70f193fbb621bc74b1be0b2a0dd89d3ec7d261f41" },
                { "ast", "9e31641c7ea82bf69429897a35266c8482766d13f0805d8ee14f44ee71779904443b16a6fce320f84e3dc27879b6167aed459ba6f687d1429022f1aa24b86918" },
                { "az", "f6d8b998c80d67cba6a898713429fdd486715d50f8262d7e9c7bdc24bb01f56f82dc4937680cc346382509b895cbe239f935a6f9fbee835b15636bbc6c583149" },
                { "be", "80f1fb919835022d0b9f3dfee513d0261e247a0ff3ce137db67ba8279ea9383597a269f911bf204b7444c1bd1a957612381a34c76d82f47285e210a8a4bfdc6d" },
                { "bg", "164bc2ddfc386314bace99c48ee4683301f29a0adc3510c19ec1943cfc7e0e9cd7b3c50909801268969df53b7f1af1aa760a617b956714e6467981386bd81337" },
                { "bn", "cccc53c998d86a5f8f228c8737386cb12eea357ad401b0e3654010b8a2f9b4665f23204a8f6871b3ca2c4af1bab531c8a026f404b99733fd63209f1ba4f3ee8b" },
                { "br", "c711022057bddf82b4f6222e5e946ad2874ce21c82ca527fa9230c389fb413233ea4b62623a514ff29ab48fb787e817232e7c6c22fafb423a1e95c8b2f4fd7cc" },
                { "bs", "42716b00b63fd0d484cff28eff23c21494571406ccd6eeca3692255d48b8fa813e769150303686bdda07724b3385e0abcd518290336eab54f2738520df0b707d" },
                { "ca", "df60d76355f1d1483a885b85c45191dfe2ee154a9d56791602b2ebc5d4ff95be19ec60a7565eb9b073619b388441bc9ce9423b90e6dee9a078d66d38b82420bd" },
                { "cak", "5d134d3c71164b38103b3b9eb784e5f0733d7d9326cbc307df4e66eae14693922766f2ad73a9c3c017afdb60164ab3533d82df154ae628e642ed8fef82196fba" },
                { "cs", "3cac7d96eaaad6366c7ac0a549eb53b001d1add81be95c999b00d107c04d30fc9d3e58fc5af7a6f8b63902fe26b11c05f4417c60e8939a4c779aa81b3961e0cd" },
                { "cy", "315417b3c97d8dee31fc1e5cdb790e6d44330959ce0fdae04a1ec9a5c1f76d4a5db11ba7d20cb2baec6e027206c0fae4b1aea03a61ac6a2204b55456fa1a093c" },
                { "da", "e9c8d63c04d09e1a63ed19c6067b7bcd12e1b372f796a660bcd9b2ca21796721f77cad6e391ad548817a0cd7830c2cf0d8f810f431d4d31eebeb397384468923" },
                { "de", "3f30b49764fe20bdae596432fcbb37b1e81e5eb8a2d92480e17aede83eb34d3cb61c8b5afc2502771aea9bd19ac9d1b2cf285276983d7c8849a97f9c3e1a2554" },
                { "dsb", "6768752002e083f02df5871e3acacc4637b7a7e354edd98606caaf1416348b0a6708376f499a34b4825d9a4eeb597327c45d050a0dcbec66c7ea1bbcf695bd52" },
                { "el", "37ba87cae809cf3cc29b92d082ea8af3b36b89c700cf0c80b6b19b4262921cd40f105a811dfaaa8d651829d5fa60fc215f7838e5531e4aa983516d3d824f1dcb" },
                { "en-CA", "b4889782c5e5c2dbe56494a6536bb2732b72a6fd77e81e30b0b345d6ae92bb0b791b0e7562ad23608496db030b1493a0aa0d7b67a0bd309c293107a9d642b8a9" },
                { "en-GB", "b94fc381c1ce4bd752bfd97af1028398ff3924e48283ea98f03efbef7987662ad2103546d0f7dac4f6bb7f3afaffac78c5b7b915950055109fcb941f53f86891" },
                { "en-US", "083b9f7eb8589319076290fb2d88275f7a769e69713999ba2e23b295ba34519b75ade0f24c104a1fdc36d9921c7edccf596034c9c01328b538de7a6bd2b110bf" },
                { "eo", "29681a4b5619361a5f0fc68946a750e872801166d3f381ebcbaca2c672cf721645acfb410ed11328d055836355764947e9334e526c0a8ea64c32f43ff127a770" },
                { "es-AR", "4c49e2148416da590d7255a24cdc34c5a9cd0fe49cd3f7a7b8c3585ebc08a056cedae77f037d28464f3dd362a387e0c64ebed69f640669ca57c9c7ce98e5f4ea" },
                { "es-CL", "e83e33adfc9bb3aecfff1f47cf2be3370b80ca50f0ec116ccc133a06903b416e33b25e19f7cb2e9bd7bda18b288d1158eb72439faf648b0b5412d11a63e3dcdb" },
                { "es-ES", "7c52cc0bda2f3cb050ba872a58b0fda463ba7aba69c1ff524b29ee2660e6438198a69c96875cb331dd82300a48aefd4a54a8611afb4ffa088f39806a7266b8c0" },
                { "es-MX", "bc1f48962079cd1e2e60fc9fdf434680f1c542a340413cc0e709c494597914eccaa8d816090ef15816388c4e0181b5994c1df17f66dff2ff8a13d25bd65fe137" },
                { "et", "ada36505c514727969488c2358f609e7557e7402aa16494fb30beae617a35dde5e7c2980405987900e5e974fe5b5918ff78275e145ee14fbcdccdeb8ae5c3301" },
                { "eu", "9954bba496f426f42bf6c10b44a42cb3da94536a8a9837f6ec00f0b2b5d8ef93e5686122b9c1363272a8b39735fb5ebebbb4e660bc494630eaab6f88cd9b6aae" },
                { "fa", "1f6e130f3130b176c6c47c8c020c980d22ce7eae11865facd42e1e47f1d13665d5ed0f6cafe9c83372a88b5536937eb7ea0da8f7982b2eb539aaaab6007f2de8" },
                { "ff", "e014a249e2c2175b5a29682bcd1f0c246c63b9aa8ec1707091705f1a6f509248ce85a5354ef779c20af1219317eeb1d0ea7a1f1364e0c2884211965f41deeac5" },
                { "fi", "56d1ca9b2b8026e51140b9508fc86b246e01fe338c3ddbe31bda13953fffe941fe05769f14c15678c43a38954bb804d1fcbad4eade6b3aae470946d75ca6a6ad" },
                { "fr", "60c801d15ce5f4fd04b2c36869608a5627fbfb9de79f497df5635ae9e92d276364fdf22091d3c7349e91325d87ae1624075b4e3cabb3e006f50fd7b5d1f9bed8" },
                { "fur", "d9c7ff35fc4358aa15dd6208d8b5b662c412e8d08a66b5f829ced6629390c060161a3b3e2d72510c3b08e0aff41a3c8af2f8ce589f91c67119b6f8a62aff9c4e" },
                { "fy-NL", "252a5d3848389e5e2fd6a3e480a816893d119bf54bdffd24dc90fac5dc202ba6106af504978dfd9b19198349754d88593ff0ebe97f81089f2b8177a429d173a9" },
                { "ga-IE", "2adeb35e071ce905893bb6cdde03bde8ce403dc9f12a20713ad14eacfc65013152dbb960f30b4284d9877abbef897605a4a384f81035894d45292abd1a431cda" },
                { "gd", "5e021eb5d6d13bdaa772a55689a698dec3e31d703a6840d645b230944e1d5e957febece97cef88b31087b8ac6b8d6234ae0f9ad2586932309c20a05c578f7ec2" },
                { "gl", "5828c042c5546e9bcefe44aa0ff3a1cf170093e49ae3c95c6061c83507b40fdd0e81c9501771dfa39a5136faa2f77d94520feecabcc05f123d9d3f54eee9ee5d" },
                { "gn", "b8d264180e9138f3e173aaaadd8f3544b3c925239f4a7262e90efe3cb00f6fb15d9e55ce08449e5026aaadca4a52ab281c038639b1faccb93a5905664a9f3723" },
                { "gu-IN", "92013f0435cea6f1c6e753888490b8f00bae4a7ccef45716cd7c78c42f34c683fc18c73ef2fea679358560de678244399fbdefba95f46c4c8032b1588e2bdf8c" },
                { "he", "a5e822b412e557e642d050abe9df93b96ec470ceccf8d8b85c7fe14c1b8a7ae09253ede61014d22f00929fe205feb45c7c62c4e728493b45c3d4f1fb42fda5e1" },
                { "hi-IN", "c4882b04a093f87965128de948948846e98a3d9aea14065ef41ce6c2c3287e23511a4607a20805cf14d31a35439ff12ad005141b878c359ff62193f8383c4ebc" },
                { "hr", "f0c6adcb5dd959b32dfa1566ee39acbefb05ce67c0f1faeab88c56c74733ef131b8db914e98f25682a6180d85c0829135a08d9cef8fe59cf724d900eeebbe141" },
                { "hsb", "ea5bb1668274131735fc4b23796fb5248fa4b5307cfa59e071e174fa3350b4c5595228049b08ea7ba87a9d0a5698e50f7c2128d4044a5f2ee20ad3d6db0eb69e" },
                { "hu", "2b84e015a2f2e8a6d93aa3f8fa7190c82fda60c11c58ea4ce1b661b4ef095bb33a53a7e3d51aa600dd9f10805f6aaf6aa946e93ebcb26bf0ecc056cb31ceb45a" },
                { "hy-AM", "da31845d146ca6c6d11c97e28a7615a6d51ce7d97d09ff87a06ff148631b3ba04ec850cd4e1032c347dcadf9858eaadbe300e76f91cdb3f820031ee1065e35fc" },
                { "ia", "d3a76fa6979afeb8ca5c65a47019e016f6da5cf80754de41c422664c3d277459398aeb550ba9884e557e9a318186996be099ba172c48206f12d5d1d12704637f" },
                { "id", "30bae896aa3b067bf63eca481d3e89fe05d8dacbc1430bb853559324a78acd05e50beebf879184456409f3c6adf552cb2e1b3da9dc5ca775e66328fcd5e949ed" },
                { "is", "167b8ba53d0ff81a22edaec1d6f192823fb2fe7e878034ad4bc058ccd764b2a4131e25233d549aef2ba9c5419801bef31a26ed46818733fd277e8d7ad9825852" },
                { "it", "b799b03d3203d38228a3d262b948ea37e0dad7cb157882626004edf459a508153bbc4f77cf2f6a3dbf657c8c72fd2b91da914ce1e5a9b66e06cc2bc6e5663c05" },
                { "ja", "a8c628ea834a8351b71370ad351d467c6c67e41d8bfa675c4ec0d751532366a944327c70723eca4a0c491e316b2ec53800f6db4af34fa9ea7a446ea53bc249d1" },
                { "ka", "735b86daf29a33a3633d46d16b67b122fb75a3dd57ee07fe31f934b0e0c35444e27a1ef01eb9db4395bda37eab20e1a14b6d0eb5aa406e4e190046351e0c624c" },
                { "kab", "a28abde0e4b5cd66505defb858a0f8359eb63c266ce4ae69d1218292d5494d6a898f14e841fd44b529c379540515212740ca8ca6265839f9f9a1df4574241bb0" },
                { "kk", "16061157759dc74dcc6ea04d6c4823e34406db3c00754c9a1efd08d3a4331eb57804a0df57595a25a20437baa7119909cee826e7af893d1d55e06ddd1327c654" },
                { "km", "cac6c28e1b1c5551b7466a5b94074ecd20c61d5bced6a177d47860bd0079cac6337c8398611bba16cd6c072c2dabbacd07bf709ed627c3fcb8ee4f601621d324" },
                { "kn", "e4b01dfed5e81f4351dba09e40d6b8585a74cd035f5e766fbce26ce03e4cea5e855f138dfbacb0b8217f6b50a8bc3166a158dd04695069ee1d92ec8cb22a03c1" },
                { "ko", "777f5a43709916e45f161885f0fed3afd14142786ed4b4438337ac76d03aa4305915d3a6297d4a705a97ce5316b5aac26873df549649a846490cc9bed6bfedd3" },
                { "lij", "34ef31ff1dc6d1af177e83218459738e932da0bc21058db26dd50dc688db7756d5c6f1a6693fa2123428b833a521878788e0202904f5687f7d0bcd22e4717f72" },
                { "lt", "5b55dbbe30adb720068ecdc68452fddebeda20b6b335931aa2937e304ea9b7d41cacf4307e677d4a7ede37bbf6e98d8dc96155f90d523fab491998da1e51f9c9" },
                { "lv", "6dbdb9e72abbc6ff793fad1efec7c7d93efcf4eb624d28d2f0e278e963af4ee62b596b24f88997176b8db5d25bf2e18fd634e85e4907d8c43b79fb51221c0aee" },
                { "mk", "afa8d091521d2b889f0965ff1275602815d8cbdf70ce48c9df2e145c0fd0a03b05141691dd930d3233fcfde0d511b6a8e8a3816618fd436efc25da9f90cc4a20" },
                { "mr", "d851c357010c921e2e21c804385b5f47f1a7ec23ed170383413b5e462ea2b46b3985dda17fc0a202df057b17f600e959c0af39eb8a0df3ef84e975a12d459610" },
                { "ms", "984c2432c5323f2428e2ea82dc2bde78ff8400bc4b5ef221f92409b42125d461beefec357b8e79498e4e6531a5b1c4701921d9733289bc8b859a2bede1969802" },
                { "my", "783118e8b8e06dace0ccc6ebf83408e9ac67f71f6980f889e3d44d7c3fc9e8f96c19162eca61e92675340df154719f63ebb81c048209e9cd6fa9b0466c656a42" },
                { "nb-NO", "0e9013ac67b884fb5540f4f00f4094af10f059330743ab9639b07dcdffbe345af230d47703c328cf856fb0d2515566ad2e6cf09cb6414ecccdaa895becf9db7f" },
                { "ne-NP", "09afbb47e1454c9a45d8a3e04258d29454d48ddd84f96c34c570c1d6e6c3c30a85ceeccc7230fabae78383ab254166a7c81cf85e498c9e8bb25a87b096519098" },
                { "nl", "77e05adb3344e0109ed9ce280eec9ec9ae7009f49264d2d6097fc001744c09f8f397fe3f3e89e2aaef83bdeed9ce8e10c6ec361af5cde22fcf55838392848ed4" },
                { "nn-NO", "c44cc29b2ed619ceb09c0c0bd539ab273d37ad13deb4b3d23268f728d40d968329264c941fe1681587b4a8c0efd3e48cff596dc9cde7dd3dcbfad4dbbe6cc206" },
                { "oc", "ec2bfb524b3220fd39ee7805dbff61a356fec90712910bc1bad0ccd4c540fc7525881f2698d171e79b56a41a2411196f39a6e926aebb8fd977f733622be6439b" },
                { "pa-IN", "7654e7a2f12e57903644c3f5662366321034a769526b025733d78e956ef096e7eee2bb3ff433cb1c496daeb8156b6f094b8da4c84df1853e26a1f1b0b458b902" },
                { "pl", "1a59b0f692c5a422f533f41e2597817b5fdd07639873fe624c6f8bca1a0617c77c611fc4156a5e15fa8c4eb21a2c350dc7d3050b67043a09648deedf5e4fe9c4" },
                { "pt-BR", "038af21a0d345499557fd87fcc634a12c9ec6ae6653adfe7100da7ae202c38a36572bbb46bb5a783a5e45cd61a54fc1c7b88015e9f48a63d312f395738c92784" },
                { "pt-PT", "ff363a18657f4dcd0c06c503407dd8ad004f1fb06bdd68f7b6858a14befe989b743123e97c14580d8a1813ad14064e5ab734ea73a1e7078044f57271a62bd8a6" },
                { "rm", "87f6fd464383463693760c38112994529010881955f460e1e9ba780de88262ef7f929fb2801d93121f2aee72939c3dc20a4c76a6535628e3a8371535a4a9ac68" },
                { "ro", "1a18f7e37cad612733069e43170742d16faf163cbfbeb3eb9c15ed7e7f0536902efa4b4d834f1ecd63d45a8be262fb3d6e4d9ef7224c8ec404398253196195e5" },
                { "ru", "ab8cd8040329985a20fed54a08d9b210f88a2dc720430d36b74eadaecbfb0f81e7f8d4c204885b63ad905aa53f94c7591a08847fcbb68e0dbfd7dca1daf501ac" },
                { "sat", "646790800d847d6a9a881fa83b31200005d9c29d25a1db916c6026bcdfbcb01c32d19ea3c624984c9fd0d5691d0028fc4e1860a12ac850fce60e0a1c46e15d71" },
                { "sc", "d62b0df6950620ea0c7f1236878b3a2e278a0469dc1500e269a03aba8115023c3dc1921b482e0571c69351cdd4a9cf0d291ef8657c45f932054067a633c48249" },
                { "sco", "25d2f7ed0daa36fa4a5496bd71e165661b6689284b6720a2287494f06b818db9db95c9be6b4ac7ce4e60e25e76bbf5ff352033491bcbcec848fef87d1230cf5e" },
                { "si", "535c6a921619a9d667d35297c6a2064dff1ce074f2433396578895fe92199dddabe49b6ee044d40e06deda23195af8f6ccda1c5276e9c7c180a482847be512e7" },
                { "sk", "678d1dab52027aea60ce4d660ca042bfe79bdbc2c1376f98a473acc97821dfc99f9152c3e1eb1d7e423ef68093eab7aeeee6ebc96f15001543da8b4f65b62287" },
                { "skr", "32e52b9115db91eb53640fee574ca9c43e90e0198353a76da03ab4023ec1d25db649cc516977ccf660b91c8a62473f1937332d61715a3f5d131a7d612d07ae42" },
                { "sl", "ceba7ed69890515f0c14f7ef835273ea3e96257b956f3c223928c48707045d20c552085e1eda7b2bfbd511c128bde117c7aac61afb5f815fb28cecfd1bdd2217" },
                { "son", "9026927f261c985f2ea997d6697634075039d186b353069eeedece5578928a16fd5ddae2b9b78f49382feb5064f154c183abc7074cfbe61f5967e702e06df8e4" },
                { "sq", "e51c141b0262f27e6073fbb9be588643cca6268159e9061e9a89e9de9e90a99daf5adf783512d260dad816e8952f7b396134a1b7b1b91e144620fc402b2606bb" },
                { "sr", "d720c301f2601311f6e4d38e7f353e2a2aa8220eef0aa7947ca02762d9cc6afccbe0c26709c11df1bd88305809e3a5984a87c0948acc6dcd133a6d7b454b52c0" },
                { "sv-SE", "3833030cf88a4aa922aa92ceb0d9f7b254d735adc1f41c8841e906e2a49a9685d9ca92fb0014394d6c03e13fc04e359d2c405cc19819e58f5bae5944eae90183" },
                { "szl", "988877ebed2ac1882ea2bb26ed0bae085499ae1a817dcb817cf34282c3302ceec58d768e7e67e846573524a6f13c56ff8623aa1ddb1f2d75f2e8849001710df6" },
                { "ta", "55446b4e4667a5bb2a77c2f71b43fa66a2cef792165f205eceddcb9da3533b9ff17c7cea89c5a8957a1f39221ebdcae922ba6dc1a63f600b5b407418eeb82bce" },
                { "te", "bec5b6b4a1db1e3d3bb6266ee9b264726bde04d000ef9fcdc2a02ceaf38fe6273c22b100c9b1f5df1ca8b59b11e5e11a6c447b7a818473cc8210c25a24573397" },
                { "tg", "56621a8202f45284b0353f64fad44b395d94535fc9bc62c6e423de1dd45f6362e214ee5273be377491288c70ddc5bc79547fd7eaa7e9d67cd10b6e5752c34be4" },
                { "th", "70234d22eddfd4916692a4ddabc44b9d751a75d41b61147c600a1d646ce94f95e47dcf51e53ef1d039053bddf1bab7cc511b7e2a22618a3e41461e60487a82ce" },
                { "tl", "f1e31780e155806b6970c127f0bb33e78fce18d202f2f0f57c8a340f3c8563e870cc1a988cc9cc021a7271faccc4479f4fd7fde9d300619875a7453850cffab0" },
                { "tr", "bd330c079e9014abc6b6c6c10d7035ea7b88094bd0d3db6e65ef9e38ae438de5e2e0e77cab9b29fd2bdd177e783c65b36694c098fdfa5ff645ca8e51c10cdaed" },
                { "trs", "e9409fe78a658e62deb4f2e745281e37bea871977517d64692e59e5de9fecdac8b1655298a1a9965a6b47213f0fecaf7ac966b441c8d46ae2b6c982e8a51473d" },
                { "uk", "4f1121c795c16c8507bb68d8283e1a9e489d6d4ba7921d8aab12536e86f2defa460c2800472a21dd9ff624ac64e7cd033005f1975796f36b83373fdefe45df76" },
                { "ur", "9edce9c8bbc65c4ecc6811d7b509675db9f5ea4d503d2f7f9481a1412c9f0c79534fa7762051f831995eb387f4e6feccf048227f3280f4120892c4d4e6b26862" },
                { "uz", "ee04c8a1958319123ad9aa2c55c5b17e3b3b1217484e5c6bfa8fd38a3262ed17bb8faffa2af802ce1ea2f50ac065fe1c8d6e9c4d24d7feb8ce79e35bf0616571" },
                { "vi", "904050f0a44dc8c71dd463f96692564e4867f5b8d810cacd3b16a351c56e84b54670abad6c5c5ca78a3cdc779f05beeb7be95b586059c8e87c56e399c5715393" },
                { "xh", "93b57570a7cacdd9820542fa571550aea565f91e9067f28c90a9a60bbad5921eaf20af8ad38b38e9ebb00a72739561cd2b8aa661c681a133eab1aca0364c811c" },
                { "zh-CN", "98816b04d8abbabbd3a79199fd6eeec9e0c85905f7502a4463a0c8cff3f1aa303b63ef579dda9d8ef720d922e038add9ebd5653fccc5d214f3b6373743934024" },
                { "zh-TW", "de9cccc9f21a7ac1bcdcb0c5bcdaa319b0cab37722418b8f29937bdbc027c2b82a4d44fb91c1cd2f582bb59c95f7b6cb9ca92d565bdaa1706eece61ed20b0564" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.10.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dac1aed8cbf58b746fc3b6297059f88ab13b3e9bcc5c2d940ee9e9c51713a4a34a8e6ad59799b0ba4cadf610177c7e00f8448d0c64f243c2090e5c69affbb3d6" },
                { "af", "f962906cfa7da7c99eb56b196fdb136e55510b42002a0eb68118dc3c055f14b38869593eb364ac103a5141920bf132132dbfed1350c6ef6163663464d2615ded" },
                { "an", "de0cf4347d6c5c25c632d15ef6a7c8596a76c5056f4c652191f79236a6a2523e78a9e12940ece30f4d67a20232c934458b139f011296306230d0ffa205416b5c" },
                { "ar", "83efd28a72290e3df8882ee7426542c3a6b0db1cbacc6fd3f3a05586e082ec93967580b92be93d7b9ad4242038b91d7222ec2c34c9c67de5594d61cea0ef6db0" },
                { "ast", "a0160d614d2e1d41b63d324bafacdd44398cb9ce78c98cb85f8c701e988337e2b190d6b5fd315a4fb57a851a9aa66778de1e02f1afa15ad78a35f1d7a81fc440" },
                { "az", "6a0e87974c288ec26766717e5e8d50eb26297fd9ea03b0d948dab7a88b721d5ab1243081c91570652d90847d4eb165eced71aa075ff7bef770051840564b4094" },
                { "be", "bf113dac66903f915e3e42d37c271ca5ab999632efa1ec5b33bd8bdd4592c7991c1471f4d684715945b4bc794dc6f1db8e0d15d4b7012b9031d245a891fadb95" },
                { "bg", "ff8d61c51772f61d9411b7ca99c2b87e4c8476cb47ff3f9ff65b345b629292b9955b180bb2578a53e59c2afc0547b2c33ace500645ca8d00863bbb8c958c8ecc" },
                { "bn", "99fb0a8ef25336cc8d86b465ec8c26910fd5cb40fabb423d0d7a276e54436a9903de1ba1a5425ee5897ba413f9103c844060bcafdddd6c88737f1e3ca9614220" },
                { "br", "fe1a45e952de6d82ff33078b2ccda7fc575ffc8bccb66949b407afe8c47ebc0793459f3575369b94880005638f29af8ce98830f41fa19516430aaea1a49de351" },
                { "bs", "4a26616ab9e1d4190a8fe2f0777bfa97e5e4a3e037e474d8a13539166c33f48622fc4ca7b7fac0d18020b019ea12aab67e80c4bfc42163ede3c996bb73a6e3d9" },
                { "ca", "09ee60eccf69aaa06574b6eedfd624d55220d312e37c02873e1fc3113776932e0ae787a599d5348f50fc1445c604d0cc135147ef05c8aa084fd78ce2001833a8" },
                { "cak", "096068e1739d5619583a7245c17e47b47f23b415cb7535812d3229179124563f08db865b4ed61bddaae1ac2e7570456223d599fdfef530491d9ba8a76b64b88e" },
                { "cs", "75403f491944012536372eef2289a9864bf3972933162e38c20ff55f899db0f6b5b1660e98aff65d942a9ddb38ff23358b72e1311877d8ae18d4b1dc820d17b5" },
                { "cy", "76dc216979088e6b35ac4ce449ba0a62bebabac8d617aec9a082006c938318b5ce694019942d8dac2b2e2989e89d60c201b0dea3383088dd3e2214a4514b883e" },
                { "da", "724060877fb955dc1591bb8e9636eb430dae65573c078581a826ed74c9467ff460434c318db63cb25c069187fb48b9133160c0fad52066f2dd43219193194972" },
                { "de", "871a93817a007ebea9de8f89a996b8b8c32c20c3b1a0d144ef48f6eb00109be034e13c1efb1621e20e260f1f9e3b854dba5f654d99f70295ad90289329dbacc2" },
                { "dsb", "49bc6156ff32e626cf399310fbb9580a756aca871adc298dc1d43345574154b643eb5ed4cc0ca91a668a7427a099ad02321956443dfa4d36f2b3a2f08626dc95" },
                { "el", "c2a9ced6df8665f5c9292811fa84572c6c6394404528626782633710381eb375b02b77d17affe0c632bd20a4ed42debc451e4a860735f5bf4c87d0ce347d921f" },
                { "en-CA", "c3f424465f70762b1320537254b422a3965a711636ea7e7273ca79c6254918c04716fa93b4e2e382b04d0cc15c0de37b06e3b663cb89a8f413507bb8d3566ce6" },
                { "en-GB", "dfaa64971648539b5bbeb7ef9868b3dc81d1e0e318e92f0c6b29ed6e56e78a3f1dce177b1529b16585d822d8c261b9df3602639a666e286579dc4b60873a0def" },
                { "en-US", "bdb9636a579a9e475253a2e89f37aaca5339b3236dcd36752fcaf06518fcb0d9d688eaefbd405f25c55dbad510fadb33fbc8295cb466a5c0d70da4edbe0974ee" },
                { "eo", "ec48fea20a3bee54a107294974555907fd2b623bff9b628fb42d0b58e84b90b7c8b9ba2ee030701cb1d3a2bf62e5db3bc055e9b07ed431496e32e06de294beba" },
                { "es-AR", "fdf3ccc8cca4177d54b99b2954735a263019d731f7aed187feefd78e3106cec70da787fb70545a0f11f15afd26b6dd710dd541dd5ced35346f2965f911558244" },
                { "es-CL", "e62b37546d1e62f8d98326a0bcc0d5e1dd126db6e35ecea5cb48453cf5ea57557cfb136438d9e2312547e9866810668f98d0a1c0d36109d8aedd5401b3550af2" },
                { "es-ES", "c840037d2fac876ded376dd7d7608696d75bf6ccd246000312baec75f077eab635bfe3f62a293bf42b25278d3e75332d0379790a5a3f36e9cebfa3cfe03e3231" },
                { "es-MX", "0b253de1cdc2141edecc61ac30ac09b7abd022ff8dcb8660cb250ffe6fd8401a34ae4165cf07d09ca3df0815654e1b23c6a4755bb9093aa0f695f4542a813e59" },
                { "et", "b1c79b4add16c318155b63bf288953046fa81c0662952f55c15caad275057fafb2a55531005a348da8dfe5b4d214e9b6c426d0c36b8183f696af52eb379dc33f" },
                { "eu", "4c6a9503f4c0f8e0e6ed6dafcb3ef20bb19eed8ca04aa95f3be47aebc4dcc4cef9a85a5a164cc9bc101e7cd5b3847b332093f342c3974ec07dd8668ec44d2ace" },
                { "fa", "3169a377b7843d49fec2f115f6732541087c0a96a55e243308fc6f12490009e3018f6fdfb79d35fa1b13b84db7e684d1892eb3a4e47a76600af497a5af29be34" },
                { "ff", "bc29ac283685e78f80d3eb960fc11e3b6ee9cf66a979e4fe410bc4d17a494f6bd0eb968d10c8cd46ae697e3d861c9449d1d478cf91fe03e04fa97a1d2db27a3a" },
                { "fi", "15be7c826650a50defcbf65b0921fb224348bf4d0b61563596e9a99b8b4a253a871f614b38abd57a94404b9191e45f4a7651d93e38e82c8327b8a0d9ebbe757a" },
                { "fr", "2802326bf88859b5006380e170462c4c90f2d658a226cb746b869eddd0d2480b4dd5683ed3db851ad7d3883ec915fdcc18a9fcf6c002773015ac79b7e409eba3" },
                { "fur", "8480ef02cd72f4db78e755c0d0e4fe6a43d7d19b03f7cf6a9770b3edb6c0cbaf30c2ecbf41e0beb38a61c3cb85eca7aa52108e355fc5a9abb6e19521f04c9360" },
                { "fy-NL", "c8763de6acd05ace4eb4c3ea3434bddaab1660662186a63538f286df9cb11c40a654afa698bf3c556909b320b477001330666574688e0d7b79b7e8ebbc6623b1" },
                { "ga-IE", "db6c143eff7b07f2720d981e51048e93f5e8427c024e2b1d9d6a4428f8c5ea7670badc94328f893d822ec5be787cf89b626589576368965458449aa6e3a1fce8" },
                { "gd", "2cb1e79bee68fafb77deb8065dbf805bd39efaee1718d7e2915a8cd399cb714090d9ef43f9774b21855d55d4bc0cb41de69f9e63622d52fc34c2e713940301f4" },
                { "gl", "ce990ce940b1d59ce44968608bbf1dafd75ab457b09f6c4b0b6cb51f4ff6848d2e85a954a06fe8f96eef13bfbd57d56b0c80d8abc4c31679567470869f126763" },
                { "gn", "ee429de040e3023439e940ddb3a73378ec4e911c1e9b7dfac32a14693a3647c3ac67af26de6ea49e7a9aa6e33a9ceec233cf8b746c81ded6d2b64c1ab25c6985" },
                { "gu-IN", "302ca37c7767f85ba52a5fd6d00157748b90aaf19db879761b091c43d06d43c65089d123e75f35a659e118df0fc0ddf272e4a4a7a7f359610b3b670bc7da8f6c" },
                { "he", "6cf51514144699eb3ce314585a4a4099cee1937e32de280637e0927b9776b7df00b8ef92bba9bd7c3be540ee7d8d4583567f08c661e9500682c97c72a959b614" },
                { "hi-IN", "9d521d1cb1888cda41b7c8da15c2d0d291d3945c4f5fc4634d2125d11198d5729fe8274dacbe93ac434a6dd12fe71f80e4e5b8ad4fe2a00a9f32a423b9c05dae" },
                { "hr", "a0b170484d98cc83777205febe4e6d92b49d670aae671cdcdfbcc5e0906833e6a56dd1ca47e75d72392b2d4a529640dc32926861397447b44031e79eeff047d3" },
                { "hsb", "362c24891a883bf587c36dfac8f73feea1882dcc27836af36e734bfc5d9a29471ce1ca546fbe704cc3bc8d0f3050fe9b60f10bf34276c03c2d37e58929b5c9bd" },
                { "hu", "c523e041569f17d11f9dccff1d0d82f211382571ff598938953d8b80d8d8a716fba4a2cf07709fe4d0976e7c9594450ad9d1227e96f0523589368598c3f83ca9" },
                { "hy-AM", "631cc006b5dd1c8e8780ea0d2f3af6d200c4ca23b2bd9f73e738cdc4e5b150571dbd3dae32421865d7cb67b5eed3f6bb473679958eda349394aa92f025994164" },
                { "ia", "97cf552c39c77989514fe48c7c2569f47ba1be00ca29fb5e6713689748539857fc11cd7fa81325b8983c2bc66f74b438034964959727d5ea6375e6ab10789ba2" },
                { "id", "8142a01872c97e0148b52af2565f30d763e658f2a0ccbb1b9f827cb94601352f88bdd831ecf88da9578b85367b850151a1388f84d275e9e719d4e6ca287f7be0" },
                { "is", "2051e4ee7e2ea173397f2d04a8529e81dfd6077ac1d9df48d065b44c240b1a2c878d174642ff4f543ef0a092242f30c9bf9f8cb43605769e962991d45f069cfe" },
                { "it", "51a219e1a1bea0606ae67cc41869ac2a3dd38425920320489cb90e4db6f4d1ce6c1e385411312ac347e062beadb9137f5dcf71f1c35db43d1e46d563073eb52e" },
                { "ja", "d46ce794476fb4731f45aeffa6ae9b8e4180f989fe8ed469efa2a32ad002d6080503d641429f35897b92b82cf3796b0d94c8335d642170d44cd2eeaeb30bab7f" },
                { "ka", "d54a8522b550fa443feb032addb51ec36fdc442f5aed76ee057af545ca2fe87589f164cf316500bc3752702a97ca1d7b6c0ec49b898896182c90f8bb5e00f96b" },
                { "kab", "b1c9ff0bc9e69edd565af67a15f36b2a1a4b0d86c2acfcbf0b8b43c04eaa5ae015eddcaa71aafe12e9f78c6eab56bffcc22e7c8c2ac3a7bc398051ba636d22a2" },
                { "kk", "0982e8d9f67477d0697173da78b2e12936cabc22fe6f4ebc8920c03bb00e26ba58974330701e812a1a15418820dd0d2bf6944824b5f085a0941fe0d82d467cc6" },
                { "km", "d5df6fbe71cbfb378a54e8d731ce0cb8819d8c5c4c74ad5400c0178bd6a5d1f1b7a05779cb119c37353e2618a8b67e71e3d540b61bd8dda4f080b6157c20e666" },
                { "kn", "1355c866fe03dedb24e7ebd1da4d4238eee716faf6bccd6b71eea47604a18080e8ec55144bdacdedc909dfdb130dab3d11a8996edef7673440d315d96d3b7b06" },
                { "ko", "2db6f5d1ddb0b48d1a6fefbb7624dedd99652355a2a26f73e396f84ec7db1d83e24c225f66c85ebd36b29e7927a1e8b27e250aa4972f6aefe70e760f1c303d77" },
                { "lij", "f7884ac506c58bfa52a5bb062c82fb503e72e89d22b3309aea536a5db79b2e79ed594f6020f4918d70197bc79cfcf6b4b8faee4143adb0dff503b4298db72d39" },
                { "lt", "8b438aacf232b01b54810088c6cc1628feb98addba421644111d2d440f4fdc62ad0021c3093b0e0c1a56192cb8bc43bf31c2565fb90a271bfb858098f16633c1" },
                { "lv", "d498fc27443929e3f091fd9fbc2f6ce00ae373ef5a3b787e7fc803df1b0f4df8b2820d5b001fbbb0c20f7545024e3c9c077bd1207283167fe608b7063a2e1b48" },
                { "mk", "f3dedd6a47c505729c9cd673642cd81ef1445ccf07dffc1f2507137615dd4e9712439b41e89b5d5c92d8b83f3de221e0ccc4fcdf1e6aae84d3ffacb17a36efd7" },
                { "mr", "751ac448318d0f821e1bd2b647f8677cacc3b2c9835d77b5fd93267d2fef8397421b99b125bc811fd1eafdd5c9c1931b25b4e07aa22478d181e1412d68bd0512" },
                { "ms", "179b0eb568d2936f7b20c279ad93beeb3258c81a839d4be7a6dede32b6bcae53e1dee7ecf67e3698b8b0f2f104c597e7dcd52d13a9d817608fa8194accafeca4" },
                { "my", "1107656d2e161c79c1563e161af550003d6eb338b34d1f1f64a4b11e90e9441be5b313db37709adb3c7c0eb9902d0d4e1a72c19e3ce3a14709b2f6ab50dc8b30" },
                { "nb-NO", "60af90ecde8c099063667a88581143edc86360150847a0163b0ccb91bbf6909c88c13c4ec4decb526e8f4e8c4d5ea91faca3b077fe4c4d9de0febc4b5e12ca9c" },
                { "ne-NP", "077c8c49dfc1290bf4bd34ecff1b759ca288e9daad992241babd3e3bddc47e6e6c05438123c56d09bf08764d6c88f9e76dc235fd3161041a998d21aa548e3ee8" },
                { "nl", "ebac29bf4a57485258ff4fb56a82569ca8824cc2da62dbeebec45b38c5e1e362450f53ad097669f630ee9469900620d71307ab83919307bc6357bac69dd19df0" },
                { "nn-NO", "000a8bd86dd9f2e9774b090e76d6d675904699654120163ca5609cf6ce343496ce0b2bff754a4267f9512baef93c4a1822f798a456293c04e9e5200891c9cea4" },
                { "oc", "eddd932b5cfba659c055391ac3b1a5d1994830165e78436b3c9672ee2fb862c8b366a6add3b249e18f50b4afdaec599bb09203fa5bc50b75debe532d93890d2d" },
                { "pa-IN", "9d5e25da9f9399ccf5a9d19f3f687622bf78a838d5e84f47499c9b333bf50211da44d590a85ebb1a86995841f5f5fc1fda134e57ed10c71a36d4a859eece181f" },
                { "pl", "96ab829758c280539ed1f248f46beb1a9bd8f2d89885f547a88b51a8ab5f165146dbe843db284d24c9dd4c05eac1e588cc62c1238a6a4a5e2b69b9f69665643d" },
                { "pt-BR", "19afe41ec0464fbf9564b3e6ba43d29792fa2a59f2030da3bdc752b47e52e7e663aa401ff6c8fc84c27900e7cc2a7e3c490d9954c34dd511d1afbc5295e962a9" },
                { "pt-PT", "83cedf0c362b7ca42063126bdbd5f8571741274132274810679d5a6c052fc358d2b8dd77406c0e3b9d7f49644e2f3813499e20ed28ce80732c0d64c3cc8424de" },
                { "rm", "9cfed34999cdc16f2f7514ce80cc40242ee4e85ed06c6f9ce5e144107e2014ce21c14a63e28f7fc144e4bd672ce7fc8c872e480b735b76ac8dedd4f83c18384e" },
                { "ro", "ad24893ed002783be0e32163aa3821ef1abae1c47d5db0b6d1f76525bca687e6f32606a85dd1fe794df6c67e477ecc10d9891ae88eb6cbfce8f5fcc17d8fb0de" },
                { "ru", "a4425862284cc1d89e97834f1f61875eebd9b38ca98c27ef88744cba294c4fb68725cf5c2974458f507e03441bd6fb55243d33aba0bcfe425485953edc12fe7c" },
                { "sat", "30c309520c031b8b7c7df2f9b5885cf927eaf337883374d73e7b99ed80cf24007d5cc5a706345cc7cffe9c4b2539b613c64fe897dbebeb2715704ddad9732e40" },
                { "sc", "06dc077fb4acd83976c61d978099e5a86da58eeda274b0c53e7e01759b7ae88255b0b9c9a1f69b67128ecd8c8d352bb67bfdc3bf5f663f2502e464a0abd2396e" },
                { "sco", "e6699b0b2f8310eb82816c8180a9d796ab6baa596386c541ac473de2f1a7e51b3d54f86c3b59fbddf24315a91bba2c7bee98a7f95803ecc5e9f4b6869132449b" },
                { "si", "15c636ca248a9f61a49ef7441750a79375c3810644b5bd68bb854dcb5f72d2acc3650b90c00ea2a8200647b5be4c4860bbbf853ea5f1bb4c9f82b6cdb93cfff0" },
                { "sk", "dabd09b540c53022b29037d5801052cc5781898f63893adab9bc854a24ecfd6047c5fc274c22a842b845a32f986619f1d07ace3948d82c772266377f5860d443" },
                { "skr", "9e56fabb23bf6caeaa0afd4c5da92bdc98307276c2f3bc3bead13e6ab219c1410cb2077e4b6d22c69bd6286490cd986f451155bdc5534475b8f8824bfa9bb015" },
                { "sl", "12cafaa2a731d3921b06b76d2b0502acad210cdb20d9fd9aa976fc696a24f82bdcab11633d5d54d259b3549de87daf62e1034b86574b75994687db3d611ad857" },
                { "son", "6ef5bc9ff4efe8ddaba97c090900a6fb2048ba982daa0260fb27950cd1f220ca8acfee32829d0c52d59ce6c9dc11cfb5fea49ea78ee2c9d1dba7bec9dad14166" },
                { "sq", "f202ec8f0b2842b65d0f2a76e453a508908a627b7cb61ca9a0238b192499f1ff96844ab9c6838fd5a65f6f35185da8197479a6a8a5d621ff1caeffa6e65cfd26" },
                { "sr", "d0445364b00b38ea132c5eb6d1bbcc5a0bbdf2f8bfc0d1cdee2787858e07e512531b9229d2790ad0f7290ddc6fbb28ab2f17dc9919fdc4e16aa3c5278502dc3b" },
                { "sv-SE", "d0de15b8e6d961e5ccee410676af9741b4b655e528e3efb770cffab76b3935da56c910c5e9f54bd3ea5917b43d312eaead792cc7d43b582c7e94ff16cefdc2c4" },
                { "szl", "3d9cb4f9798d05f738b1a8fea49e4b9743c871b2c564d58af19ecd9d3860212666094666b8f492866800f15ae71d3ca562e1d1cf175f09f087a0a5cd1b3d75b2" },
                { "ta", "4834237bcc7f8d7aea67df150896b698794e8142dbee1b617fab760e09ca74fb75c707054bfd29406baa2922e2c87bced0780245e299701b7458cf2460f9e785" },
                { "te", "f18246b1fd9cb2c4bb7f2d924fb8c1a1bb992e5a9dfeec1639012eefca59505f574a95c10f976582b963571bb1562e6e6302357149a269ff96912f9e04fb2c73" },
                { "tg", "50cb6a64dbccf711738f7ce03b7d5e4ac9689356430b61a3ef63e76aacc66c84f46560ab3ba37817147b8f005eddd8a8999785b230271a8c958e94c3e12b8c15" },
                { "th", "826e955314aee210d1641f43aa87f95143c5294948ec9712e2804261dbb87cda2f9be8bb737027efaf55f72363ad9608b530dbaa640897ae191227293dd2a6c0" },
                { "tl", "18d2a1acb5bcf2a0d68b57e638c535817a3cc55f17cf29d1d6ee345d3210b3a2f9b6e636c2be2704aa069b23235393e55efb7d70d1709cc4c1a1bf54d230b60a" },
                { "tr", "21074ac407ec034f9a86037ad2d0bb88bc7a5efb3898ffeef74b78f2f00b91fd64bdedb9abcad34bbe74299ef6007cc029774ec5124b2585b0a0f0d28a1b9c32" },
                { "trs", "bf5ba616a4698d0d93d637e0a23cef91ffc8cc579e6cb30fdda770178a8db18cd4adda38e0ad9dd6f474a24cb38779f62bb6e9bb2e5aea39238765337493a5c3" },
                { "uk", "104bd79e94f61000fba3b6ed469889f7d6d565b2fa3d98120c88efebb320303260ebc0c245fc464205bcf38750be65dbd00f953c25816d5254def6fd343fddf0" },
                { "ur", "23aba897ac2efa04b0eb74359c15f725ac73f5b519864b8d03d7edea51653c2bf6e3830397ae1073a434e6ecf9125b26f7d9a0de939b2a75535dc74a512027fd" },
                { "uz", "ec13abfbf9f697125b585bb7c5b11bea12ba65782be19f7b84c19c05552d5fbd3623af5565e2c4fb9af6a9e8d16e45ce16608ee386d146081e6f7a1282fa0bc1" },
                { "vi", "5c08a1132e0b353bf12f49814f014ff85aa482c6cb370ab8ce348b881eba6fe9424fe36941097bf2a3401232e0f98060231509982c56b420c229e939b9a63f4a" },
                { "xh", "ee21dd1750f6a3deecafcf3e74dbb497849910415262db9f4aa7e56bff003fd08073d4370d7dcdb2fd53892f55b678444ab116372e5746478ac15fca299952b5" },
                { "zh-CN", "8090e842a662de465ebe1e8118eca6dce8bb411c1390ce0c503c2e6a94cb270f42eb09b3b9d53f397a659d97f40e22204641dff69387709d24b2aa609ee24ab6" },
                { "zh-TW", "e261258042a4aaff8778cc0405e6f779d7700723c758d162f2e7dfc26fccc059d06d0d85824a17e3f81f1ef5153749bed3772899c88e61f568337f76cb8e57b6" }
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
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
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
