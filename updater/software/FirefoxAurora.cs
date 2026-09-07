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
        private const string currentVersion = "156.0b4";


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
            // https://ftp.mozilla.org/pub/devedition/releases/156.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "07e1811c84be696b470e0cc02b56709a1e964972ab94e8fff87203a52f3341cf08eb88fc398f4ea57032ee7d2d123fb1f838c668f42d5567c07600b6975b8550" },
                { "af", "e1f2cc11023191efc6565ccd5c133c672831aa1a54b12626ca40a18f6bbf50b383db1adcb13a28307af0252d877f8842bb71180fbe4af60c0d21e7ec13c1555c" },
                { "an", "93d5be08ec37159a3abf0d2c0d35068fa91012b64b8704880bf886c7d35fb79484688d68a6440ea1c1ab5ab45c7aa8e5365f6cc38f80a674741091881891e8f7" },
                { "ar", "8d4243c5a13908cbfb44be62d9902dda19fef204e641580eb6f92af935d704cfae625208f164f6ab92225751e45890626bb9a7baa03a92ffc87b547c7dced548" },
                { "ast", "f755ed5a19c1be93aa32b521700be91a38004156a40e5168931a9caf81a6963ca7037d48a2fe4aac9e0f85b13b96704c3b9df3782851bfe512eb270c1cd86d54" },
                { "az", "156328a97136d1b8d6e44d7812fc1d899bee40bd68c163c3238a9ed6ff7163aa45a68074248a89f00ba5d736086105c1b50fa369ecfd1bd1b23360021fda35c0" },
                { "be", "944aab5060a9895e41dfd4288928374c8b6887ac6caca21a77f832b59380e1d5ba050f57758be9e56c2304c4e88e3a1b77483e2457a2492c32e64d677edb9891" },
                { "bg", "c9ab9a3446f2c4fd053bd6eac7c17c415ab0e2831c23d8c2a70ffe4b92428a853db9bbb4852fc4b3527301b80c105e1dd238f341edd501ffdd6ce6b12e3d4b58" },
                { "bn", "5064677c476e71a06f4ba45804e6edc52fc458e974f1e1cf8eada5219e1176dccfb31f5ac5cf9a0bf4bb543839f7e4c17e303e463c9ed2004164a4ab46a7b52d" },
                { "br", "ae63b8322f92aab661aea3997b81e57e24b7b23610a3a303be91f91aa9acae393777ecb2407fa1f3f37fba76161e1f2226c0615c2df1cbd8e5950a5fc2061f7e" },
                { "bs", "20bf56073815d2dd5c558d23c47d31ba043145892368c384f2ce9003c9f4c0462c6769234efe779728fc8f76959ed99b79b5eb3ef820ec588637b9d044976176" },
                { "ca", "c743567bff613b768ec57927cea89d618b8b8b4b835564e1b38050667c233b9d091949574547747676d544d4aa4e7001858515038caeab534a2c290a9a588ebd" },
                { "cak", "45495fb823cd0b0d9c88aa28a33eb5e4523b5a720cf78979d87d61cc1e557e1f2a7e7771e7985aa0147c70163b4eb8805f251a3ed505d1b4a9a48dd62756ae1f" },
                { "cs", "565a4b0cd2ceae391cf539e18764a514202ff1c8ee343885d285b871e9c983a08ffd147b197d53bf1e9558dfa7b9b285f7409c595fbff14b0db50c9cc5cf4a06" },
                { "cy", "be5fd2b7b3ae9a10db7ff1867ff9f40c75e5fa3f9fb0530aeb1972ede7d60ab407a69d9b1819d0a7c494415cdb1035a377094748e5adca566287fef5fcae685a" },
                { "da", "ec282e3287150efe4960ebbb230e14d2694c09e02a7be28eee7202bdd36371df20f1818d0931a9e26ed41879fd91663aaca9d540115e9708d63cdae811fdd4a9" },
                { "de", "231335cac8318192c78aad0fecf38dc9c76247209c658b1c0575c723368bf723fffa46b9497fbe3f7ea7b88eb79a1ad73b4b797047d716f1a92f5a31d2d8a088" },
                { "dsb", "f3e2af85df3f29227930b95730aad0a6ddf35c504b664b9300af6e59c49ed8a5f322b3ad54f43c1a1a6682ee3083f9d1a128df426d1b28e1b11d424a3552301d" },
                { "el", "f5ec26f704498d5982300930988a4b1598ebfc4b1c6411037473d1be1965e72c526e6fa550aa6769aef6225c2c6ef667bb483475cabcc4a9ca3a3562152f14ba" },
                { "en-CA", "d3815db0d13760be8ab41577ccefd21b34c4b23a882c881da4591287b97479aa206010ab6a6610c9041454cfeee7c6ca400ac35eea09cf51a8cdf4712454a83f" },
                { "en-GB", "599b684b2a537c8a2f61b929100ac2e7db3604e0536aca60660e8c4d753ce0f5d5cedaec6f7afc56354b7f922c334b69adbcc73df19b2370dea99402d0ac8903" },
                { "en-US", "8d17e8734cb4d7dd1253a77c91d7a0840337fca5f273d65905b7597077d7dac523595ba8e1534bf09eda50a8bf4baf8a1f3848918b878fd8d18a1a5fd25d5cf2" },
                { "eo", "4b7a032374f429cb876d41079f615b07bd57a918ce741ae9f639a949fb82fa9636824b7c36bd702a10797d760fe31df90791f7c9cb0cfb63736947e1b02e86fe" },
                { "es-AR", "4f735b05003f28b33a745d262c742797843d31e76a96f0e92b244a91c45ece3ef700e185ad65fb470379f61782069bbcee6dcde4b52f95335964c8bbb2ca65cf" },
                { "es-CL", "1c2daf9de46538f7499b3149059e8b8113e7c59813eb5998456671e1ef82d3e089fe2465c2096324ba07758aea1a2354621863df13231e23cbce43b7e437026b" },
                { "es-ES", "8ab3f7dd6f41568d09dd1620cbd62dc2f17984261433afaded7c5f4ef26fba674010691f4319485c1ae7e45ad3b08d92e25ce83fa0e9a820a51fa418faac0d0f" },
                { "es-MX", "7078020addee36a0b02944266a7c70aae55930655a068c8f1a1434c251e164785c0bc58912953b43f9f56225bfd523ed74236bfe491cafb5575ae3cd51055372" },
                { "et", "ff7900db6d02fb097f2dcf1c0d90cb1cf0fd2653a2c7f400f1b68d927b6c194b878e5f43edab4aa2126a6bb410354b49cfedc893f7900cd92b7d7778ef0b987e" },
                { "eu", "b9335c16346716fe4343ebd6ac8baf7eac8875cba9789998f1d2be5299ff38db56586e8cb527302db178b6b9d62dafff58cf7840f0d070b8f08b499bba9e83ca" },
                { "fa", "76436c68a6a504b9da3ada4068e1cb154d57baa7284ac807cbd8e050eabc17c29eedfc3532c92b0b94d34b40f8083c819dfbafcc7910f18198470a3ed401e2a9" },
                { "ff", "e78e48f6563d403d859a6f4b3090d371cdf9295c85bc412b6625d927d5be6f8102e323089842a9b84bbfe709805113f7200768b8b98e37bffe9536fb72c11b0b" },
                { "fi", "fc0c08348264a5b8234943d3fdf4d3d61ad4ad3548e55cc8888c84ead33b17900637e3e1f811898cedd840cfa61ca615b8a586aefb2888e800d2fdd0228949d7" },
                { "fr", "098c25edb8678aff71fd38f4e15275178455a58c19b8724754a6d63d9c1a58e1e89a1eae4afc3a7d5c4686c586a40a9d0b5cc4c28c82b5862faa1c9fb6b43eeb" },
                { "fur", "55cf3a27b4c5af2fd16aef2251c4f9394d29bcdcd2ebf4325ad7f59fbe5b52e382f9ee8d56d111c0bd40eaf14a1283151c9f671143ca64e43814cbd0942f2204" },
                { "fy-NL", "41a6da9d80e41c59c3168a425400830f5f0d35c76fd4538ae828ce9f2606f9f1dc50bea5c81c74e90cd32c3e2c6766fd439a2676da311f8b8c777d11cde513e6" },
                { "ga-IE", "93c972de703b123415b458d45377041747860296a9921b7bb5e83001045b067ba93385237ad1b3dfc9971c74f0aad2f7fa9b50de7538da9e3da4014dce4ec6d6" },
                { "gd", "53c5d53b1b83af4a6b378215f43bf75c9887534378d9f9acaffb774a60b187e5474cd47dab4e73398b14c4fc35de31a1d6e6d238d639b2bd4f5538d9ea43fccf" },
                { "gl", "561a778ca3acf064c7945702f280999485ad2725dd623dbbd4d2c034f7685948e56bed64aa0f7560ad917801630af8c9e48495cc947b723ed034fdbfb06984d1" },
                { "gn", "bb28fe0c545d6111292af86ed574c36046489b7621168948a397ccfa0dfc0d6486a696cb1078f461380eae7b361bbca883aa268f6d2c142810735a76f6f26f61" },
                { "gu-IN", "6b028e444bdeaf79cb178d7db2a0bfa7bd09d935d8611fe2a21099d205455b82e55facda5a500d14f2b2fe4af915ffea89bd94f05b4ca1981fb31f60ab173724" },
                { "he", "ad44ee47915c85dcb87341f779ec6ffec5a52382ba4b296a421b94a1672743a45b01a0eafdec2360bafdbf50a293f8d015f393ddf454073776e2b77568c370d4" },
                { "hi-IN", "d66e7ab1fc685c82944d8f7ce1557ad20301135ec7c09e9b027c721594dd420331544f60ad8f4b9e1f6efddee49632460cebfd46a9798eb6fb7e13608e25b76c" },
                { "hr", "6d5871d2bd06a7285253e2a660884e15c9dd511535011c96d76d2c29ee82d68f31da415fb18a3532a19aa6d02bf689ae7a2b214f0393f23655b99fb47ae2d13e" },
                { "hsb", "7cdc10649dcb40fe2d3c5260b4e5a79d8aca14a173c9ba161894322670036cc54460f27dfcb254c1ddc9beb612de89d3d9b1a2165104feec3c3bfbb412fc6a96" },
                { "hu", "34b95fe7cfa9a820d1e2a3784632ad6666a5f705e0f022d5b2e7415852b8731d9dd27bd1c6d32d37bc481d5eb421fd18a0ce75afec121adb8a5ef28dea898e07" },
                { "hy-AM", "c785f88a8bdf995c286ac907b8b7623eedd53ebe500710c59fb46353e763e835821d22b58db8e582afc509d44fb7256c5e9012c500101907ab84922a13a69bad" },
                { "ia", "5684393588e31f882dd127843290759b2d178af920e9113e8e43c386ff0fb4d50a5547ffc03e6c3974679c70162619a4a29c22f55033486cecb71402ea328fcb" },
                { "id", "27e4679113520c1fc2a505b860219a55d4b67259fc207d5f664517706f5978d8da03c9191e6b14de43a09f72f5f008e75634e7c550a9cf7d497bc78b3746fc11" },
                { "is", "5f21b182d8c7d4ed46857f168345119cadc1ce03abda1637a56843647ec1b9dff273d557d30850ac32ff8e95e4d0bdecba7644806f9d1258d92efa281d579e59" },
                { "it", "f4904013bf44d7ce68ea09e8abf98027868c2da4734797245090d2c0e6acb8b3bd0d426ff0a3d92b6d6cd09c86aff812eae98a61059913497bbd1a904fa977a5" },
                { "ja", "f1cb88a69e608bd7408377253a6e42fa73df70ebad5d733fffaa136f07c9556286a5a5bc9cf2354616735aa97a2d1f8c046654fafd4bc24350e040e23e31a2f1" },
                { "ka", "a1f99a01db2de45a5d3a1abcfc9f7e3acf5ae9c0656c207209e15a90f0adf6779ec99966c96e3357bee7de3f5d34eb516f51f5be9f2148f6b9710e32e8c8f639" },
                { "kab", "9da1753ca7ce1faff5969e93fd4c63afd59725a26db93507f521d41bd8f12531a871b88159ed135f351e077e5ab2b4e00684a75902cc46357a0ce88285bba1bb" },
                { "kk", "7938428e370bcc8617bb1a67275d132607d7116a4e2582c90c5228416a9181a9ac87c65d6d24cfd5d08029517cd7d44731bb14d10fedd15f6e3413f351f2930a" },
                { "km", "dbfa450b0093d74a9f4d189e73e452c874d786b7c04263b228f959f53795e3f6f54aa03467bb83a7eed679e81f0ddc9ec435d2b362a234329acb5234072346ce" },
                { "kn", "844fcec028a0d91b5e7a68aad166dc4d80d1e496d4ea60300f9b3d5a4635512604dbaf61e830e283051d5d2cb7cdafca1dec028136bef674c716b2dbfe9b2e3b" },
                { "ko", "6bbb79e772ee1778d4673f29516445103754e9250334f25884217c816c4741c879498b5fedaa0c6bb23ae5c33a14ab05a9c4c42d9a10369936b683f94c13040e" },
                { "lij", "3b49bc5afe998412804205914a0fc3312d991ef967ca6adb3f06889ddc19e6910a4285a9b138ed5868843c3e42ddfd7b430d59eea0b1ddaa6c97d27b973a5ae0" },
                { "lt", "e7a4269e11ff61d9e8aedac10683ef16c464943f6efa9921aaa160b517de59e1dedbcb4105604080d306044df5213f81eb51918f72fb856fa808216baea4e7c5" },
                { "lv", "14cc6583504ccf127f2318e4d33af8fb7fcfa15dbb15f5af1c641fe6af18241b7430267cf0c7603471940443c8b0287478571d201d6ec03870747da3acd2aa66" },
                { "mk", "e2740588df3d283eeddf46fa33cbd7d85533a6df8228b78a25abd487603212a428abe0dd2799ddf07e42fd575e78fcd84b6ab93d39e06845dbfd0b727d3b4538" },
                { "mr", "8b3120f5b4688838cee79c478630a616212353293bf3822aabeb54e9df01866285d9a031716e4dd03ad26b698296c41006726862a3ec5caef067cecae91953a1" },
                { "ms", "80b66cf76e5ffc62f3112e426cda120a37f53660416dd61f00ecb578a710bcd56ea17e6eb8203c79cb3451c2dc67bd0c0ca31f577d826c3a24334fc101f779f5" },
                { "my", "4dd25bc2e7e08fdd53d39d360b20dd5f5f3094d1fc2716408fa3080d90e17ae3e5153cac4179ae1520e7c2705eaaa17b87e39c8426bff3f8ef60734666793c71" },
                { "nb-NO", "a51896b34be5fdbe11de15d5c2880fb6f3ffa905079a0be52f8a54682ce9fe4f0a6fe78672daea81ebdab718da825fda3436938791104d6e130c919da6de1a64" },
                { "ne-NP", "3d393b4f221d04a4b161dbb40a4f1ffee034e6ec7ac81dc5dc6507c502eb087ec227342957f43cc0a57b64f678fbf1bb1fe59d22729a9ef05fdfc905adfd8ba0" },
                { "nl", "6e51f3933e69c8601575178d8c03c768a2975111817d3aa5e547ca87e409ddc22bc7aa63fa3df3477efd8a3ac540aa780b9f2fa1e7b2338bb0e7a06224b2ec66" },
                { "nn-NO", "32fdde3be4ff49de8908824307924ea223e881cde360c10aea630663b65280fb4ecb231046c5e4b2c9c15d6a3c041fa8865cd89a6e376b8d952566cff93f00da" },
                { "oc", "c398dce534e30bf0bb0175c9c90f4b323d3cd31bd286b4b65c77e52523e0f4dff5bc2c34a2c96c20779426f787629225b430746dec83495f445b9535c9003080" },
                { "pa-IN", "4033d192cddd0b37dace486fb7c5014e6aafdbd13fa55920dcd86c5a9c1923a9bbfc9ed3f7a40765243660a418c0cf393157df9aca540eac01dcadbd35bc3827" },
                { "pl", "cf4409ff68833155605b03f63d1672cb47e0dfd240fa8569070db26bdef15e2670367fcc941dc74250368e2173f52ef28ee8fe3fc5ff407d5f4186aa5d82b7ea" },
                { "pt-BR", "21ef211760675f760e10423487805f032f89343dd7dbd29acf6e54a674c10cb6763f39d3c74e50596e4bc59580617e37e45cbfe4d8e604a684372ea15b215037" },
                { "pt-PT", "c09939a1e4a5e627752ea0532eeaa1d53abb098c0c6737cfee8260b10ad19e8f6c6bd882f9f338807f79ce0bc928def9eb84ac91e68a3a35676540d87b25906d" },
                { "rm", "d01165452e1022c1e08672c2ff8a5d62bd5992922494b4a6a824e03c63817fe0e022160405fd9b50f27327dc4e553bcf77f26c890e4a9e5424b74143d6251d7e" },
                { "ro", "bcb19fc8d1103aec520f5fca5b48d758e378bfeef2ff63b53f5d1036c361a3810bee248694e5c062c9ab81d5159b55bf9d831ce53b5af0605f67c6d7af51442a" },
                { "ru", "73f7cd45d24d1d902844246e39da50e20722c3a1ddff19d2ec6ba3578cb899794e7b626b9eaf90356ed316440895d34be440af2df7332372ee34a061f7113ffa" },
                { "sat", "dd314b4d7623eb02517fd3cc15d000570ffa83093e8376915d740baada23dedc7e972358d5ccc18331e9d0fc21a4b4eecae0abfa4ff1a0027432c01df9f653af" },
                { "sc", "fbfeb506771730739661e34d7a7ee63cafa80daba5d9d960f9296fcfd6fcb791e4fb3ae4feab75f742b2821ac5400880194ac9e6f4d43b48a435113d989146d3" },
                { "sco", "c6a9216f8081af8a44364eb7c7729f004888c4b4d2ad1ee81acdb2dff1774fd9c05cc427cd575ae7799edc1644ce80486566646e9f897643544ad6c82b8a0902" },
                { "si", "4e571933999dea09adc57abed87ab6827fbbf63e9c664aa46745f0307417c44e32fb02e9d5a242df96b11087884b8cc0c0e465f6134ba922f7be903fa97d7563" },
                { "sk", "81f0f541ac5e5add01dbef1cd1d1e827c93b3064009d7597d8cedf1f7d2dbb62e9ba9b46d423f109caeaf2eab27349b5cda4a40e12179cd4b776711b4630c5a0" },
                { "skr", "0e4d2dc672187d4cc75574b60708a984b741da10646624ed7e34977f81cc6ef88a15a3ba114dbb7f71b9e51f643d9866f5ed1f2a299ea66a6dee7fe1f1a9af64" },
                { "sl", "cf0014726731ba91dd7f14487ad6d05fa60b271574ebaf6d05869a2a47c4ea2159b7b6aad4a3d6cc4ec65ab7ee2c71b72cdf90191327ac92dd316e80dce2d177" },
                { "son", "c932c72ba257b9dc0baaaef0baddf5cff05addb8e4ba3cedec66b5327c5a7e1b9791a1115795ba7f75905af47697cbb8342910fa9e7104d881b45dedbf53942b" },
                { "sq", "ca675843ecac3502de86fc55cfdec5ac87ed2593c17a125b701e7f58fbd0932fa87fd407ee880a2f0e01a762b046fce8eb7fc28ed68512dec4bc4b39c74ea13d" },
                { "sr", "62738766e38012bbe056f293e283aa3be01f9e481be7a99f6654b23aeaf868aaa82cb3d377ae050826151cffd9d971fbbaf410ec760fbadca571b191e8ea2032" },
                { "sv-SE", "041e7fcf12b23d5d02bd0ac24b6d3cb9466f7b9613e53cd9b98ec18330008b5b9f682aaead9fcfdf011380a801e0bc3a9d0827931deb9cc4e8e6267d5c0641e0" },
                { "szl", "3ea378e31f6d0c2f0cff0606ccda67af91dace4231f10ce72c54994e506e38bd4cbeeafb5d79770abc8e8ae54d1a295b0969ce886c040afe153a63584ef73a71" },
                { "ta", "7f034dce53c84da2a47d8790f0fd870371a437be9146ca3cf5167ca8a59356a06697a8c9bde345bcb36a2891ffc1fad613494095513e0939f641e7ce086d418c" },
                { "te", "23106bd43b04df5e527413723cb296e2fcb042dcc5ade373d9484021100575468a97c03c0461f17fa93bb1e682735aa1207cd7164c4f3af8c3c39db5c0a61521" },
                { "tg", "de3ca1414b3e69c0aaa258cbd7c563c191d9304aaa99ec33cdf60cb1ed3d691a4773fc03863ab347a894b06c58e50a6664df33d1a71f20aad442afdb2f76db96" },
                { "th", "c4f2fef1c822ef050c0c6e4f312968a65f984ba9008bf6f6ce5ff6c1adfc5007ba47019a5b8e20e0bd6bb056f124c618d2cd4ee054ec9e065e7754a07a7a923e" },
                { "tl", "52ec87e3fe8af8150e5a9e11a3c015758f39bb76df49f2bd5ef9e3fa722d51e656912259b8029992240add79a3b8f09bf7bdfa3f1d4c03480b204bd3cb3b47fa" },
                { "tr", "09fe007e183bbf64832b8f2fd985b59eb983bed897725e4f086890fe2d70c79574ba636b8123a461752070866782a6a0050271cd04827fa684d19a531db70570" },
                { "trs", "abe9069c74a6d7a20e48856e51ac728fc527acc646e28f967bd5e98d828a75747c136f3325a465c6dddff336427bc4efc1ddd8d5421411bd1007185195cd4457" },
                { "uk", "a96903f187c1ab9117899cc0c54d2b56126285b54d7635385f5ee4e30bd01145283703a3bbea74f56eeea96db83d6c5990e19d774bcd56fd8b232e11c66497b7" },
                { "ur", "9d17509bc644d9e0bf187973ed14730ddb47eacc1b7673ff7d006ab97fc11138473195a3d23730436dd0c37c8fe70e5425df59ccc500c37c87d382a927a30108" },
                { "uz", "b16a57bb537837c5187615bf71fe504c8aab3885c2c1fa9e6783c7e35024e4142c1df15cde7143e90d93fb3c92f6babfb1d7b14a49b600a7ca256a698a60b739" },
                { "vi", "c2b8d5a906819ca1a4bcbb9a4ae8411d5565300ac32bc2a38cf995c59f17c3258bbab3a91e532b9d24d6916446602538f094d4d260fe8e9754752270ef23e5c5" },
                { "xh", "523466a5630a30ff68ba1fa694ac61f17c97def49916be61602701c5eef4c4e3481c8be7396e8416d242712664925405ad1dc37c3bceba2a33679babb539c429" },
                { "zh-CN", "5bdd076d2b04e6637ca530e3eb23c19f6b2400ba60e9c5e994e21df1c0886a7496cabcf7a20019564547437a070e505cabe5794a6bd5abaf0698540ebce3cd0c" },
                { "zh-TW", "1231282b2dc394d9b7bea49a3e4eee80d1dc9e11649afd96732cbf37b1c240a378e870e585201df4011cb0884ef4eb907d09fb872257ab74ab37bc8bed13f3a0" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/156.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c01264fb3a74e904bfea536ff73d8128103e98c609d8c97a16efed3838be84dd8f8efcb937e3ff4c0d25c5f9283a0a5e655a326f8b315c3500b77edb5647ee11" },
                { "af", "cc4e3f217fc64a15d69b3b2d051bd2590b651925c530712aa097e09bb886f9f45b4e6a98e16f23ff66e8476805e413d78118e3fdbbc80e9546c6f19cc56c6b52" },
                { "an", "c036c06be8b6fb72e527c88948913bb44c6d88a2b3f39af48d77e7a2c9551b4e2e935ab9425ea95e61f2ed330066f1a062a06af34d89023096d1ee51304c668c" },
                { "ar", "84fa9743fbfeb618c9d7ab0bb11fb92859582f9d5770f902d6d44cccac906ecd082fd19bc4f62a85d716d2d68795f822a0181dc67b85cc5729aba5ebf2c8fadf" },
                { "ast", "db2455cf40b02e8c5e92df98b8645a8f5d1f554ed6614949ba796c1503974a51fd9c24c398a18991c5e9b44a8da446be225270413347dea403183b41705115be" },
                { "az", "1bf6732ffc0162b9d7238fd963901996790532d1c57098e2a38a06cce166acbceb460eb9cdeb10d7912227471375c2e76eceb1a9f1829a1f62e4c233c99239a6" },
                { "be", "33bba42d89eb17c0c0ab51884a75983f3270f9744015f81ea21b099c1403bbf4bc76ba14bae692c5e0186d3e0f2d066bdff03b3eb0c6f7e7a2190bf991984af3" },
                { "bg", "3664baf51cdda73427563045a909731e68fd887611de004008015a055ac5fed77d35284635e9ffdd295c4d42c9d592f1378ac373571fd8d6e91d42148eca7bdc" },
                { "bn", "473bc8abf562fc7ab45415da4043c6414928558903fc8951f9cf3e0b3ceb223cf66b9b503ff25122cac6bf0e8d999350574eece2a4c06fb96ba6e8005f94e8d6" },
                { "br", "2cafa88a5906d511db501257e92ee210683128d31c674fd39189af393989c234930dd99357823c8de83f59bd0f3cf8873a0fb6e4f1ff6f770951fd98b9a13858" },
                { "bs", "55826218f9cadc1b53f6a0cf5866056c8fa9b0b4909d6f512fa5838d6ff86e854d2ba2cbb05b0d29484bf535c89b6cab158b9db9bbbfc8c581fba9a4c3ed94a9" },
                { "ca", "4e047ff1bd802a5a82d0983ff2b6ebef3733cd6573125e8aa6b26ed61779ea74c7579a116e144494b5e4df1ea0f2e722374d55fb9e34f8488936c369fd93928d" },
                { "cak", "97e34a8d46190b6aa157996e8a86448a23eb1dd37882649cbfa739acea36f2f8dd12925a6fa900be35e75ea81285754ca113b530f3028be8898ccf7ff4612ee4" },
                { "cs", "ae49b97c9c9ca3988a89c70bef0f73e84f4fc5be49e2a1b39eaa6cbc7238fae946e0f31cc806b6bfd6f2a84ada1645ab486b67585162edb4b226b07c24003a96" },
                { "cy", "26f360cc6aba66d34730d663125396d0abb388d88fc75f901394b5a6abf7d623beaafaa77777c651c4dd0fda180c46c098c5e44620e3d3cea712b3409a4f3165" },
                { "da", "8c170db6be3eb852a8af2b2ad947070b568dd95d5338bacbdfb03d0d9f71c835ee462c2c3111d9db4ab99c3e27f64fcc984f6b30e097216d484179660a43fbad" },
                { "de", "42011929deb23aed2935bb386852ad65e9b565e96cdd183b8db40ad3f72ecc5137c8cd71ffeb24de417be6f123c6bb548b2b425f3f14b79a01490854284e5b8f" },
                { "dsb", "7d762ef3ee7d8776208b26c332bf1038d99b2c344b019093a411c6880e4d1442cdea9cee1f4d03178f6059626c739d566459200b5de6f70ff11f99e4f4b59405" },
                { "el", "bed4c2cec91ac7680d8c393f9cf04dd5dff6564a70d159c6a554a96b7c5d480706557d7360c2b9d4a50254dfc7525354ab882fc53bac23495fb40ea973a8f237" },
                { "en-CA", "ad899f5f503dfbeb2ee40cff403f784bd3d080f9cb9a8d6f3062edf410899ebcaca4e00c6c91d0e3f079026dc3707ef16d0bb8c1a65119d75eb3329e849aa2ed" },
                { "en-GB", "681865117d34014312ce09ad52fa0a9a7a078cafeae195f52c53e91bc661d0bd929d7c152ebcca30a196e6da977d4eb63225299de0d61925723b7d4d34ca7344" },
                { "en-US", "579c14bd7b7414155247c1e4bee2974a000bd2050f9eed8a315fcc415898656d04e7c039e15bbf18462ebc349d3660ae504bb27e4ed280ae318877860bd66510" },
                { "eo", "bd16f2b84f32744750a95aa899478ae9ea5a610f5984f251be9883907ab2417af5d1584644398625e62a91f1c029f70ed6bbf46b52b6713a0dc6b014d3b2c191" },
                { "es-AR", "ff73054fbbd019fdc0e2c83596b401e28feb47bb10d05ab2c37ced52c5d6d8f2037c84fa4aec81213520d431437a68a9b22c4093cd0c46ac3439810e28ace84e" },
                { "es-CL", "bd725b6faf338a8604ac8db25e7dcf16e287307de88d3e87a377cfb8e7d7244ceaa98fea6853197e461eeeb2c27197c62a6f9d99669a00a5dbfc75a39cf45158" },
                { "es-ES", "497395ed0e275ca9d8afa7c226b2bdf70776d79995f0223d013e9ee2407fa441deb1079a8187cfb8be1f4f68e98f944291ebe07694caf83f807af010662ad4d0" },
                { "es-MX", "811f4dca0bd6c5d039fe2f64d314f28c0cdea55d93b8c0f5e5008eefdd7103c96c0dd49933f1a4c1e7e91c4ee78ed63d3508fb07bf4ac3010433e18ac506b4a5" },
                { "et", "a2c70b82269a6d2f0fbb2c8dc9120c3db1c0ae90df0549697de4d61a507567b11d7e52fc91b496fe7600adfc0d497ebdb2ee460acc55194fc60199c3a9db61a0" },
                { "eu", "efa6cde80f6541637cc1dc6af39d34afb202a6c4177aa87af67299c1c1cab1a6d2ed957735c6aa6e01efcf3f6e305ef37db1747d1c1fd530243b8e58cc91a992" },
                { "fa", "be89b48606e477993b2efa9ba97e2f76eb92d39c847526ea1b79a57acd550c934c88033f0971c10eef04e3b2fd94ed981c26c1d9c80f1e9ea7fa982e0d873efd" },
                { "ff", "392d4fbafb2b725c9868e99af8cd5ef12d0011679aa73ab74d3abc57397f88c3301c128e591ca0035d9db9eba2add5ff3d87c41995232adcb329fb248ffbc194" },
                { "fi", "6c3ff6822668129afd21463d9091bee86ae2d321eed2b11800a750cc4030a54795b46c5b4165e178f2b84163196dd6220a44399a1a84675993e899c01530fa9e" },
                { "fr", "6bade9558b3ac22a03ec8d38864f1b5ca6233fcf98bb802598d127e49fcb4c1a2470e3eedae8bd36043b194353c79ede4ff22131cc31b4dc032ff16f8b4b2cbd" },
                { "fur", "f4558bffe4d4c7d30d08583c76c622a0a8a71185a5606b000ff7a55957e7997405242aa9bd24cffc2621dc835d23cf9d83453b88b6c98905544c8cef60664305" },
                { "fy-NL", "e167bcd6ecadf6a49dcb5f8212c22d7064687a5da69132e5f94569dd3d3a9117d311aca7431880af0a9852e2b4c7438cba252ed404220e6fc7b9370facd2ec8b" },
                { "ga-IE", "97bce6520eacaead613e90a3a89f1eafc534fed168d52a59d4b2f9f47845722eb4c6826e8c5c0a5ca3869324b10e6dd98f391b557294ae69d7dff2e2bfba0815" },
                { "gd", "56dfb030fa4efa02b550f2e01b619426e2f8494868933c2814ac94fa1617aa91e9a1f2109e11f5ce5690cf2ca91a1801c0e357494c89acf045920a36b52049fe" },
                { "gl", "3fcc271fcd494655c218a7d3966bf3ee7e52e5b9ff56b5d5072027ca05f23412298a32a9cff6cd92cda8b52d7f521bcd648c8a23832524963fc9399e02622801" },
                { "gn", "e2a692dec46bf06c598bff2ab174c858b5c594a4fdc2f84cbc1e0df8e7fb6f6672182780638fa6ea9a1e9d418cb4cca650b4374de7f1e5f1bda3396630e36a0c" },
                { "gu-IN", "de3821e8cdb7fc03182c6049b28d2b1fd273f417eab6e9f1daaece5f43eb7f2399efa7122b7b56911591cec59c00078a72abaa2c822d3a8b1eeab8600398a620" },
                { "he", "b1015c19501f65945e7e03a39d57130bcec138c44177b96021cefc1ded66b4a7fe244c5760c61bcffe474395a4068ccfc3fd84e49fd2ac8015673365bdcc9244" },
                { "hi-IN", "546780d75fc2b82568b8e7a05affd3ba6a92e46a5ae8019bdb156e9581a8c94f53a9bb21613fbdf95cd660a707cdb639b1db661bd55a7a2fe7b66e9469211da7" },
                { "hr", "5aca6db61f3c49ef598159d5f90fc0484f3bb2ce7485676eff2b6fd89f23e9f41a91f61aed6ab2d08078a715bcdd1b0da641ac79a8530266d9ffaab4668cb4f6" },
                { "hsb", "a1d6919eaf6a23a715c009fc1a58e2f36453cb29c59f35d882cbe0e1975fdeff709c4cf02a9ef408c96b88ce1b89f469278b7ecaa97ebdf8b0e7f4f577ae501e" },
                { "hu", "002ca04f4919199d6c43981e6a652d03053c2d25dc699cec9ceb545f6bbee633c4f2d575bb8e3c79286c37d7a8c158baa8c4dda6cb0783bd59e524a766b33ee2" },
                { "hy-AM", "683f8344570116b1b03d944c554ee0fa41aa7f390cd5f63e1978a3152c168c3fa110f4c7ae8becd05bc60bd7bedd7fe934354fc1cc7f6e08f0847fe5ba0340af" },
                { "ia", "5d99a7f53b74cb5813804364f8330adec210146a0ba0c1ab67fff0929773c2a135e9765bf28df896389c9819d0f8d059dffdcffa3b90029a0e4cbf9bc56c72f6" },
                { "id", "dcfe0626085a3e4fe0c229bed0723a7387bf50d87217a24e2195ada80087186aaf0e18f70fb73e514a8587aa136ec9eee2d38c4e8cd6ed961dcc03c723ed37e4" },
                { "is", "2abce89f1899fcccaa8adecf6982f808094658a2697c2bf53e07975a06c52d5305acb5cbfab38943a116c2fb847c5deb91fa939af3f4521b23d4a14d6a33d9e6" },
                { "it", "b5165e596aaef15f580445aadf72ced5ef214930ceeb3b58201287248ea23523f1c14f576eb235ceb3ab5f3b9afcfdd51e8faa771bcb8792c9638e44dc31fbe6" },
                { "ja", "724c7d32f292a5bbd606201ce0c55974b321b93dce24b654d4969f47ee345c41466e9217fed4add481ba119a5be05030f1ff52021491155f12e4eb742fe3ebb3" },
                { "ka", "f27812d9292682f28e211111945d9f3f1c41b990eadf9d49207806bce87093c6ad9ed21dea7665eb14d883edaf42fc16f506c1f57a55e930df34f6d52dcfd537" },
                { "kab", "c0419d35561da7f2fdadb58f5c563e6ea63b0e13c34e74f4f373f19146132326bbaf7176ec2803d2ffc4450c2ca31fe12cd155378a94d58cc9906ec6325c5ae3" },
                { "kk", "9a3269e255a389b27191e981255ee691467232ad4856fad5240d963511f600bc7376629e72bdbe32243d244081cfe70a6a8c1ea48c570521bae5fb7e7ca779a8" },
                { "km", "825ebe2be5087d6faf7c8d79a54032482f2f3f8761c1cfb62a0721a08ee485d5c308248ae52c6b5c66ae1d07ac8a2e45477028fdad66facb283e2928a46ef43f" },
                { "kn", "72ddbae26b002d917ad987c2bc92e791b628aa3c9ec41c22998ad66398742a4241a7e9a0c9c8d757dd2d5d5dfbb179391e9b99ada7956fb9d74b1c73c5a1949a" },
                { "ko", "d468b54beacede201e7249be39d83eacd712933ef18d956aaa26861b48daf6a3d81a0d4656e636b3e3b12f6d47c4c24e20d8a81295d61a6decca12cda81385b4" },
                { "lij", "d6378ddbc4dd4ae2faf8004382031afd3e3a0a70aa465523c0159b0febbd8aa70248c5899f78c985f6de5db17b4779b1a167e9da5e873fb7602bd24f0e718183" },
                { "lt", "6ffd0fb885a57e32fe348a013a16d944fdadbdf6b691699eeb300e4ef849715f88f7cc4e30aa1919528c42853a5a6d19f0ef23ffbb283e85be992dad253c3a93" },
                { "lv", "7cf4e395839776336af316e51b36d45762c702680345537c0b7b4e009473d9139331daeab88db6323386078f5c91df6461a8f189bd26e9bab0f76bf012649977" },
                { "mk", "92e28be71a6804ad98e6dbb7c8d4ff8b8b72367ed5a5de119e939cd633a00b60d3030596ee0cbb5591dbc4d4b2b99492a2912a6165c2ffad89bdfc303ab12f8c" },
                { "mr", "37f97f959946dfc2b9b245e300b23e26a9d4f648026fe522c21468f855696049d61af79d9856a3e23bc7fd5635b3b1dc3bee977b746a8a958039bfac3cd99aeb" },
                { "ms", "e775572b27b82c9b5e760ce99410213b497f43f74c9e69661cc73c6bf4c65b5d66de2b3e911b613d37dd56deace846cb7ffd50be77fd0b16641de6c64767204e" },
                { "my", "dd50f10122eedbf3bb6027b0049c8c5cf47c886cc971f1925572cfe565b27de391e7a143565fa5720e2dc76148520a8117baa30bdd47d12683e6cb6abaafe19b" },
                { "nb-NO", "5a65f4450d58e473786f17005954ba46fc7ab8eaad5ce302a58f637623d6bc1d48f33022c6ab2888d1464a291d4ba92cde184265a1a623b478712ec567ffad45" },
                { "ne-NP", "f9238aa8d8f7a335e73b2a9d4728b433b78172b043a7e2c925315711c2ca40cffdc5f6095703c6cffd76f3be3955f4e0ae4b02e5f39b5821836579dd8fa69fc9" },
                { "nl", "a3464401ec95a828d7d84991489d48517c67b3714592182373a51c5d3f12e4a9136b29624b0eb25174cbbdb78b53758d608b818cf28bb9ca7c578208bede3f7e" },
                { "nn-NO", "99bad05ecc305081f09d9f973e7df33d8cbbcdd7463ccb550c8311c0c1b7108bca807a8efd5e47193f794b4e8d79a82aae7232010662e28c9b9007c7c53470de" },
                { "oc", "9d2bdb9a9d8762a92eb7f6aa3b830020585dc840698aa3116084226351f9f9544088a323f21f865f5e984d99cc3154ef68bb28a1a22faf6ee342548880829ed7" },
                { "pa-IN", "d0fa85de1356a54b634dd976c0dc759b1b4a358ccf88055e5b00b2c4e385c8af62b06e9cb43a3ca5d164a36158feb76508154924258570444f9e1b06e9a6463c" },
                { "pl", "f2bf769b99056aab8f123f0c89d910a1a2c72b3840806b79ef095cf4ef4eabc4e8f924aa8c7f016d3fef3dcc0ee279a09dda733d0ee034f5e7f581db58bdb7ad" },
                { "pt-BR", "9e30fd3fb3529b55698c4748df70278978236568696338d2a88629cc31e65d2abb8253295b543815d3b0519b6f4053f843b2e8521cba56fed042c38be80092fe" },
                { "pt-PT", "3103dac9c6a9f793a0c5fd20ccd5abd5db267da04a70ac01acfbb0d82a1fd348f743cfc0d68f24ceb2020ed91a91c42006baf0f42882c4dc0aaf76c6d7e7e391" },
                { "rm", "88577ad14463db60daf68f2a47dffb65d7a5c8a4d46f97eb0efc3e78e8f54cf1b6ceb32149d2a106c35d5e3c64e7eacf95ab3887287f861dcd96000fbdce08f6" },
                { "ro", "62588b4a692bf2adead1f916534592cdc63bd7c9062f8b37982014d0a474bee31ed7e9947e53ef29749aa842aedfd984ddc05ab7ea6e1e7e742a286913668dad" },
                { "ru", "864caab12423faaea42f5c26ca3c8d746e1089e6ca294b1ac7289f0036c77be15582920ff327ac18b456c8e3839c98e305a7ba534f223af842f3b1aa9a4f95e9" },
                { "sat", "0baf0929977b9258bf2df583a8a6717d43e5d52c1f31beb6ed086948c15282a4dadb68d7eb4da78a83653a84a9ab5bae8ea789ddffc994115558ae1e8fab940e" },
                { "sc", "914a4b90d68e0d2b3bc988935c61ab89722a3f3210cefb24ae5e034827fcc096c34eac7449ff09b7ca484380a9a6b4f86ba2a269429a4eb3877ab022f02a22aa" },
                { "sco", "ef48008a17e77233b6a228252c3c4381afd34084b9e14e0281104c9878dcb6c52e293098bc5a8737950f2930393ee4f5bfbb513f1a9e9c1a1e93c8d5c7d8f55c" },
                { "si", "f413cca0fbc2dd79006ec081a97ef81a5fc8804c41dee498e52c126b64f521901977381209fa419d0d10bdae49cfb1e8be6f791989168b7cd64f96efae28096f" },
                { "sk", "2dd61e5810b1c178431c167fa544926dd8fccc2d0a2c945ad39c4e5c8c8b21300fc0b06d28c6e8b4e669216218e085d4d43ee1c2f413302aa0a3fc0340134f59" },
                { "skr", "8d8ccda8047ce1c79c67873a5a006cef43b94856f2f0f5047e7be1f66ee484d3071460545317068999d71583ba75f3eaec43ad1e006d3083deef5cf2e94763cc" },
                { "sl", "170f3c6b7327628c9f531ffd662a1c83b3dbde7b1f4ba8dacea006d2050408a6294a37bde52aec88dfa16189f557423262606211b8645352b24ed9998df0ef19" },
                { "son", "5597e6f9a49b107e00524c21eabebb43f8ff6da3dea77ceba91728a8ba8eddb4091143a1a0ad697a3876b38f4539b013aef9bf949554007c323390ad728e6b8d" },
                { "sq", "844cf1e29b277fee32e4f85e676f97ef6d1447be167e009b9a8ca75c06364e9a04e8286498ddae0ab55251c70d77b432a01b51315adc1cf452cb58776b4a4943" },
                { "sr", "551d524d45efad48304fab407a1b55fc9e45f43d39e69b63f9e6e09783724e4db7e43f1ef0f8060dfebeaa513e1cac426e83de7ecaf8537a65a9c68b52307498" },
                { "sv-SE", "adc7f490b1fb539560c3bcd7597ec88b7bd11d2db44d75cb43bd178a926405ea31b66213f85d7e347fb5bb1803e9e40c3292d3090ec4b145037573556ebaf094" },
                { "szl", "50d7b7c405f140517865cb713ea95334ed98bf3855195e7aa05903748a4e0cee8150ae0e14ea781093e79b2b9f2529c2e5cfd871befea699eb8f87c6412bf0cd" },
                { "ta", "8057feb67a075424281995c4f93fb07ad5b76fbc430ab9b93d2f364697dfcef77e7d876246860b66000c607fec8fbe9d0e5ed59571bc841090167b8fc80ab83b" },
                { "te", "7e4a6e9057f22e4ddda0fe950b206b91d3b71d4f67b31de88dda54f542be71180b3425b8de14e3e8f0a8f358711b1a3e09b0812c2ac3775eefece91b9bd5ebe5" },
                { "tg", "9a894108cc85eabe7c8f275a121d85d15c7d49b5367a86e8e308eac992fb1625a5cb543805f1153c6177eed2587170df046f4a1f03b9084c03326f0abb3ff37c" },
                { "th", "1990ed3ad4714a8e51908982bd8b0e479f6e147d4fb75b6e08a84f8d3a2e36f2abfef71d39f0f1ae3711cef7f44f527c1cbc457b73298852a771a36734a74283" },
                { "tl", "b55c2490e85d11d9e22919b8be32d3777f5de660ed39f5593fac4e9b1b461605761765dc39e52857a03e551baf27402269176afa02e31faaf1738f85ffb2e53e" },
                { "tr", "b9064650783b81270579298836baff51421277dd964f8546c6acade8c4aa89290f873be9ffbce8dacf5c24a605c78d805863acc7bc7437caa2ec1526a7818113" },
                { "trs", "6eeee0e0e42c30016eab0d42c3dd3c65f80bc81fe691c987b2cc3f140a01329e49f765384c047aa6e0eb6dc955fb0621e76d4db4e5f00f9da53c02d577b8d510" },
                { "uk", "54aa2e2fa6738668ed88c786fa7dbb97b4d0e058fa2967a3689838b1c6da17df3a9fcd32df75561ab82eb9f5b460c2f0e0f1e70f8122a96221c8098e59db1b23" },
                { "ur", "fd8b74c3be549856985f630afd13c700e06fd5243fe53b63b2c84d4999524d37e0c67c17fec05b68926886b6ac5eacd8f0211c8af217be4589be83567b42246c" },
                { "uz", "59378a8589aae576f13d78909fc5e74c3da94b44bb46187e7a0c4d1caa210d68af1084988ef55b3861cc9292c9a3aff085e17f417b7d19e47621395c68d2b842" },
                { "vi", "0cf5d7259fa28edbfc13a118d74eb896bdac6734bbc7a9df49f11f67f1168243eb8bef69bc1dc8054863105e2d9e94b3d911d29326fae229412397fa6843b398" },
                { "xh", "14184d7282f862c9bd985e320c000fde328c7280c6422d3e44274107e85138eeb4d7ac14f1c26b6ea76971a857e720bdffd44a580dc596bc196aba6b97d1335d" },
                { "zh-CN", "88ed2978b7c800ee5dd35cbfe72451b3ca21293a19bdf92dd6f498b477273b10e0f0f24108917d20324805397ea68516155dc094f922b505d13ee372a41cf9ad" },
                { "zh-TW", "e2bd3b52ca95431524df5d4effe6e9269bd85d1c068f1eea747fd2c0a6cf10c64b74d8abbf3daae790a38aa048e103c73a081639eee792497356ac30e4046dc6" }
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
