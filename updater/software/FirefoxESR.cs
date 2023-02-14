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
            // https://ftp.mozilla.org/pub/firefox/releases/102.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "979e8ef7ee3297ba9afcb2a43d32f17fa6c126e016c6f7190e48515a2a20222a50de4ad15d96c535cb0cf7fd77303b493420de96459de3704aeae3f49e03cd98" },
                { "af", "75fa1c39cad263e3b7c90eed96b659958efa72ba875abb39b6fe89a9b6ec52dcd42469096f5db746450e6e4dafc694d41cb19662cfac97863e88fee2a06ff42b" },
                { "an", "349384670c2489a88d31f21f1a6e621ebbc2d44428f199e5799a0ffe6d62eee0104381131e92b875e031b896dbc53b856e7c7e5f599b9f23643f6b4af6c6d727" },
                { "ar", "6c8a4c7f722081edfb2b99e6ada7c2686198d765b2531ec9bca478d9485c2b0404db49e84a11a4f544182f63f98a29e26441a7aaaaf6a3e7ca7b97ba0d7a0df7" },
                { "ast", "218540ffd122d85a0fc89eb482011ab49b6ebb2eb6b34e15723f13b93896fd47418653cd82713a6ea5cf3ada6ed17db04a6afe714a5776ff89321ae5fc638a5a" },
                { "az", "4153c4561bdc829b8725a9265cc89bcbf801b5a22982979450b3d533d63b556caf3698c41f473dde05b7d9bac56fe12b9ecb8dbacbaee478d78abf222715940e" },
                { "be", "1cfede912ab41ebcde94d4a8bda962cb8b4bc7fe4ca00a9d34e6c3bcb33dd68892dae40ba13eb0473756689da887066fff4a71e4cd397318c0c5130a3f94fc52" },
                { "bg", "28146f2f987a26766afb4656abfb1cd3551d50f3595077965494f76df9ccf23bd49793d0c3c4455915838c0f98b043a5f66554211975aca409be0c3ef0a41194" },
                { "bn", "4a85b5ae2b408c5ed6a104486d8a381b0cbfdf03652c09e3d25b481ac5b151568025c641fb20c451450dd8c8cf26972b8031661ce26a835c5fbb76abdc8ca728" },
                { "br", "0143ae5ede0cb02649aaa6ce21543da3d2e6143ded90ecd850f24cd3c3e06bd9d3a77df81d305068ba30cfaf44848d5caafc1c73065caaa1d82caeb540e25804" },
                { "bs", "9bebdfdc500f549e7d62f70197bbeb99b7f97ef38a2f76a136bc6948700dd5c917e5f6d1cd1a46ff51723d59aed317ebf4635e7e9040b48fc1ef03c14c2a9db5" },
                { "ca", "2314ccd72ed700c001889512f70ac9e33ef5a8e2c0643d439beaf05e2dfc65d33dbd20fc9d6895aefd052ce7e256d6097154a16d3e343daf0cceb9c92cc9f404" },
                { "cak", "3ff44f3df9447f90998d41ac49e2aff17c999b6e026f4fd649559c85c1ba6e84e14cf43063d9c02484ba81c0e532c7255b1d0eecc79f9a8e54ccb494d62761e4" },
                { "cs", "af7d7cd8de1b99451a7074e86fff9160016f3f1c6c0795152a13f6389bf306b98855069b6ba78d8ed5706b1eeaad5a52576e899ff3c56b0c7a2330f852a7ea56" },
                { "cy", "a4b34953b012616836b63c4828b3d3ad686684a6a91b383d6b55873bfc632c1d9b55a81abea07a98762900545444ee2d1fe7f4bff125b6e68d8904d8e3597a4b" },
                { "da", "0ded16039e0f6676fb177d36efed03791c81afac9dd216e9d80d2b4d92f10be01ca65c2b221714b9d00eb775984bcde5fdb91d0d61a0189f875aa2a177c01c98" },
                { "de", "35b4a059fe12571ee1ad1269b4dabe33aed5bcd7044bb434c7cd4127095af3dda4499078d8bff76d1ac6f98e6e2b7537d5115976f6b49c79ab94a4ffe99f0a7b" },
                { "dsb", "b2e446bd465904f9fc80381c22acb8cbc175343f40d3dd839bb640e5dee0e4df45fe19fae87b33c321c364918995b3790f4797891bf02b7bb73f7cb57d18df62" },
                { "el", "6b0cdbc6b54f82f550419f5839508592a83271525994161dc57b4c7ec2bbb830fa220f7f8b6d3498c44df36d6c7f9c2a8b984b47b75bcd4e2e5dd2320136c137" },
                { "en-CA", "c978d3252990aaa2cddc4249040548e44814b6755fd818126443fe2064ed42b4072abeb8c894714d771638ca535d9a1eef7a32485358e4d1b0864c95d4967151" },
                { "en-GB", "c8026faa483a24475efa29505d2aa926f80198d5e73550aa3a8b4a9f5e4c1115d42ba7ecb5cbb983c48b72afd7908af98c88b5f0c527f00571685d7de55c198f" },
                { "en-US", "62be6ad1e36320ca2d3c11c9f352a8d7b0c40b3296c84e6559f88391d86223c9e1041f3f46f2ff20a22aae4af7e3d3a5914307f6bbcee91f0b04a5000f1f6863" },
                { "eo", "38381caca32a92b4a78adc845af5ea60bff937cb6df0cdfdf29cfa5a3f57f47397619a70489d35966a7f53cc9db27956a93f7d77dc542cbb5163910e8a1de7ce" },
                { "es-AR", "dfc4a8a761dc1f18bce7d633d84c877c375bd71fe63bd244b1657dc5c18a744cfcb91e48af8fb325ca7c160a8afe298938ade603b3ecdd1b756ff83f0cb0711c" },
                { "es-CL", "81d9ec2e285f21cace04849ac1a76571569901877a9390a24b1239bcdcb4482668cadaf384b794b62ce07782b5740fff57c031742541d380f6360e0245f2b277" },
                { "es-ES", "2dac7581d8c99c6072ba6282b0c86ed428f84a89518702eb82c0ed86c2719beb0a043d97425593ef9e907540eed7834c00c6f9250bbb0a1db41aad704dfbafcc" },
                { "es-MX", "7706591d936bcbaf6e47cf3366df8fbe935bb0c084f49fd7688823853d4f30586dd235d0c3ab386c3167edf77a966f70b498e6f966c523406769330bc2aaadb2" },
                { "et", "d2162b1e20b900dd03969601dda63e97462ce3d23ca0cf6d736082d459e1310632cbedec2ab6be26fbd3ad0ee2851ccb018e6ab7f10e239edcfed12f372bc255" },
                { "eu", "986bcf2a8b8352af9efaa1fb36a76a2fb64c0cffb946e59f6a8be357e3c8f49870f5bbeb12778b08f1a3cdb65eec40f98d5f701f48ff4501f6b558dd6f23a8bc" },
                { "fa", "f0ccd11e363782b5adbdfc75685c03dccb9f941ac08a2eed0f1d6453a665e7e9adeeaacb1233566b23fcb5b1112b1f0eac356a547ac435258e9698d59d80d40c" },
                { "ff", "5042c3b7094294f6501b0777442b2b774c8aac2c0d1a1ab85a608f618906d9c631e63f2b7b2a5c18e73ea7a657327ed6be06821fffb274b14f9a1dff26b7aaba" },
                { "fi", "eb92dfe27dd350f71bb74e9b1cfe190a57f19983ebcb85def77bf902cbe4b6ca94ed66adb377ea63e8f72d5de1a290c5263f89d3fddb26568811825f08879afe" },
                { "fr", "749b907053c8c0151d3483d4745dde1070af9c41522d6895603b1fd6974599ff1632afc808de1f625328f79baae0283dd0956fa1bff1fd933f6f5159d31884b8" },
                { "fy-NL", "c36b3f54c0add9893883dc059c6e94a10d14246a30105ec66c10f8b1ed2c46a5b0ce478e30d05ae397c003b313ba3110aaaee4a4f567d33ba87957a840517fdd" },
                { "ga-IE", "792affc592e1b52ea377b6dc9a39958479ecaa6ce83fcef3d3957b2a26223dc8ecb1eb3dc01ec9c5d536bbd8f0a8212e376fbfe8a3bff96bde4b73e77f998a47" },
                { "gd", "c1c4934fd18602a11139636f250900f5ec24f901d5ddcfcae3be391a844ab79e8472197dcb8645a6a9c98161558fe3ee21e7230f81a6577fc431fc6a03692870" },
                { "gl", "1a667c100df55685742b61fc56f2ccc669f93f3c230043ce832c6f338d5b766a9d10e9aca9a2d8cfffdd19cf68ac15ca9b79f9a5eb582e5689dbd76e9edfd000" },
                { "gn", "b3b047e7a49d1d5822f06092d07d1aa33101897a7f4f79d579140ce1e724c6d5c15c65f8fde8d6a923f7a1ca285cb6ef913805972ef1ab02abbf6c54afa1296b" },
                { "gu-IN", "ddd3e124b4f077c6a618eafaea89e54f2c603cfa72be870f587089d7ce09a1f33c8be43efd100bfa0b43450307827ea5ec7f7a3208b7dca58b9bf3520a5d887c" },
                { "he", "8d25794b1e93ff764699b7470862c17e9edbb5ae7ef7e51155e8612ce86e330ae84550e07027da26d07c8f2dc19d85d64ee0bdf5b69296e4a37bf95705b4a410" },
                { "hi-IN", "241cf1fae09d9bc68a3026c43e5e534ea26f1e2caa41dfc3d2ff8184cb3268cf47fd20140cf598e47f6b3d59878bb4b8b3fcb855a2f2ad98666afbadaeca9d7a" },
                { "hr", "38770fec60096769e9608a86a0126ddaefff721bb2a876f7cd912a1a3f73fda76ce684123871facd1f1491cffa7074a2c29b108d1db46a972dac66a4d754fab5" },
                { "hsb", "453fbb625933e647597b518284e4d602d60ea4afbdadb0dea61a575742c10bdabfea1f4b571a5f332985df9ba108a19d8c09784333e5745a2f185a57b060e75a" },
                { "hu", "3289f98864b574ddbc322c9b9e4318480ac1ad937ede0dae578f32304c923bfdfc049d227dc9ad73da27e9a0004e59a67870bd93aab519da0cc1f9c0befbe491" },
                { "hy-AM", "f828790bd1e3ef4cc034238363d122641444b49df955c9ec4148b6c6cb3b1cfa37fa7e4e9257ce9ee9768778fa219c5059488fb261fd27eb7f8319cfb414c1a6" },
                { "ia", "b7c761d468b9b97689dcb6903cabb64df38f0b75f1663c6893c0aa0bd20c6efe9844c43f71425f34076763dafeeca58b24c92191076a3802b7dbeb691822837e" },
                { "id", "b5ece5f6a83dc0958aa9fc391c1c53e831155841d4b3e3963b5231f13651d6e598a634cd789b823201978fe63d4dfa1e77577f0610a326388dafcd6bc9b5801f" },
                { "is", "9560beb2c2d2b767e713394302b9d611539d04fb65c3b0255d561a65f6a7f94156dd4650e748e82d305c6d6e45a5d39e6079b50242a6736371f9a778367ea38a" },
                { "it", "520c31bdee9399e97f1e7a877ecd6b97d4cd2cc2c2afc29d7f1fca3340749349ff814e8bef0e15d703d660f5e6072d5597aa75d2184c8fab59050fd45fab0264" },
                { "ja", "c1170069373d9618b5ef8808e6b98661b65ac74ccf10c0bb2fac2d4c4cdf09415fffbd98e437a02965aeb1c53e5ae21f7e8b09af3d611400fff1c570cdb9b9ed" },
                { "ka", "591422dc150cc7d5370469973a38d1f6c007d0f198b5ead37a79bc9aa5a0e0e1338d5eba2301823aa611445fbdb73507a3f76cdd37d821bbfca17080338058e4" },
                { "kab", "4751b17fbe8be6580af39caccbf0c72c8226d8174fbc08e2794e1e008603bd57280cddf6063d4213d8862dba29039795da4e1ffe56cc2169610b9d101896d4f4" },
                { "kk", "6ae84cea818d380c0dfa24175fdc67b7db1564c54588b02976bda620e525c5b97b3e49c6d68a0e1af09cbdee8e4c3a787de478ed7f906b40efdbf2fcae1db13b" },
                { "km", "e2b4698ea1f2f06db9926e475b37b5519c28f29582e5b392cae7e46fd0ece986d798a407a6b868da36ae65d7a5986cb00a28b369456eed3281f1324ca07b6d40" },
                { "kn", "c3fa9d00fe4ddcb8d43d7ec73216862b5fec2bc5eca100d433c8282f479fcfba2944352caae79418acab7a2ad380faca59cd688763fcd7a48938cd30b1d1bc42" },
                { "ko", "02d2b1e46fc456844791ad59c3553ba87bce0142551f65c8142c102b9215e86905ab32d63b3fe551e8066fdbf5dd63fe47e2125f2960eaba4ec24ad777fe6c56" },
                { "lij", "a3803f7e391d6a9312119f2bb3b636d26795239d7ae1075901959b69d913bf005792da0a37cfcdc55a5ff65de3f8c6e8c63446cbe29a64a2c461afb84fa116bf" },
                { "lt", "3f19fbc1cea434c6d4b8ffd905cf6a42a1da23e66a713b74e32bc4cc818d049a1d2443f0847b629ea59407e1b1b4c18c0d6eb1b611467d484f9d0eecb00e20ad" },
                { "lv", "19153623012430a1ed7a772941fc5ad8903bdd070e6864dcb7c927459e8de3820569c55db4873e85c2076df44ed19729edba2483004351f50f035c91cfa0efcf" },
                { "mk", "101dd886d6bb2e374452f9dfa126ee2ee926637476a0da3c6f6549ad607e664bb0b454c7f0bd0a50840223359da8d255a8d410158b4a902c770813eb6911f65c" },
                { "mr", "199eccd218144865d0532ebab2e33206aa1451be3f15a15990bed21dfa65ff59b4d7fab227607577d26ffd79628ab991d2b32ab75aa0c5850b034e84e39e6c09" },
                { "ms", "36bc7a7f317dbbf9885f2eca2913ffdda8347dc4bafa2f2adde563e5f7f3c1f29e0cb84eedd226c1de0458ca70864043a7b10c4407c00bca16a1433b2fdb50fc" },
                { "my", "f651919638177e8e03fece0ae438ccf97456e6dde1f6e427fb06438a5a755313b0519a952d7f310d3074a9b09d6952255b09fb366a8017ef29b42879b351ae4b" },
                { "nb-NO", "e6eaf057d4713cec991045788b1b503ecde002b6a13cbcceeb0c9d9f6c0a95f0b508a3833ae9ada4322e5705fb6e084671d529d91aebc1bbdd1ddbfc27c45e69" },
                { "ne-NP", "edee8c28b5377d20ba5b1a06fe2336f7a4273b5b55d1a297395ce687b3823a293854acb5ad134a76b2e621d4b15825bf603a3cf8fd5caccb43b1fc6b38c19415" },
                { "nl", "a56d69d28cd0c124b72ee3b677b65cfb7fbbd613160e981ec30cb99095333c4e4237942200fe13a6f51d5db5a594de5d8e44a1b7674b6ed1355d9129b0330e61" },
                { "nn-NO", "2ea618033a76755d4b58490e453dae035f62fe2fd8b241eaced2ed21f7f404e884dd74140c677920f70e1183c6cec9d67c7ee388ec12555365038bb3638ac2eb" },
                { "oc", "16a44fa0d82ab1862a2f2b3d4629e2777a764b7192f7a69b3907685cc3825051072a939b0a889e963825d652bfe83f1dad7c040754b3f715593723127c52a0c9" },
                { "pa-IN", "f9acc0ca18f3a2c2b9cc2d7fe854f5ad7074357384d538de1a2416b85951f0d74480c54e7352f09fe7905f7489db6aea3e3ca104784c3a9d858b103ff69c0a8b" },
                { "pl", "1dc27e6da82ddc64a119535e4a21d9a90ef3add6344434c55f0f0a29dccc389b34d045638e9dd8929c4ebce07a442888851992831006d9d42b9a188ea4b93462" },
                { "pt-BR", "e1dca02278c087576d7816d7542f5deb6d3cc30b5ebdaf43a670c161e061067393b8eb4fe50a580ad34b5d01f514969e63f19e7bba62e450d49d74b894cc53b1" },
                { "pt-PT", "870805fead74a81c973c83ac2daf5ff45ded98781083dd1cb8d2604a902fb47bfad9e2ed653289d10dd4a41ec728221be3de1241ab4f564c4556a87318f1d162" },
                { "rm", "817350f60a36d04df27a453e60c5067739ddc01f6cf26d5825249a6307bdbb302974538b1cd4b3a757166d96eb1ef1465bea029e22e9924bd7a70001a0ba69b4" },
                { "ro", "080b6e6e68a3379270a1d5bf6756db7ae70090b09db60a2a6174941c8150a6d0e34ac3b309bdfbd172553bfddf2689c2ef7807028b90d52f3bf90ed2a51d7e8a" },
                { "ru", "e37b85e38b13ba5b589e1740797aa57c927dea01c413f3190da2f9f7ca03987f4b4f62a1d20df3118acd891c6976724c2d5f495f75fb4a95860d5aba99eeeb56" },
                { "sco", "de8b53a100ea5d0dfa9e0ff66df4a042d1e90eaa1aab995dc13868d34c33b010b8dadcb2f5074da2d58c7e658b6c244be2a2ccaf9387808ca39ea2f884fd98cc" },
                { "si", "d174528b45fe95b54ee5568a281dd65b8e1fc5208af2752b71ceecbc09df36c7eebfa421118a1f462e6e94c5af2704465c2743d9f0f637692907d68172f90d17" },
                { "sk", "80fefba4af3ce4232f41847c2f789bc3d6ba8afa9d3ad4c6efef00f0f79da489203721073654ca6aa7dfc05285b641b45883f31dfa50bfe058fd24badfada860" },
                { "sl", "11912a52dd75d950ff7323bd95bf475c2231a1c00b8d5df405f379cc991d1b36d824cfe8f793454f7c19d65a3583eb8ba80ce34e8d9556e047a00cfbe60b6243" },
                { "son", "fa5833e0a54a398632bb7334d6c2193b33ad526bd95741c7bc5fd316ded5d08c247b675a8875ef58551dbd9ccabb1715fdaa546c59c4a42d41cb1b827b0b90d3" },
                { "sq", "01e3ad34e41f7874ec555dd069acb94ef5ff0de5c1dbbeb7e7f33e891b1c2c9d82d3462ee8b301e630ad162b50885c03072bb55e52148a4e94e78b4bab32834f" },
                { "sr", "0db223f3d9d8f219bc3ab7df3ef3bb91f89a2f68165a69814af9bec08a1fb1782ca623a5561ad5888d58002f03ad42fcdcfb9acaf6840779ba9b9f6be3aca89d" },
                { "sv-SE", "51d6445810091aae12213409c49652c145293704949849719b212ef5e6c9e374e9bb52c7a16fcc3d8e889374cc4dfa007541b5e89332ebdfbb165c0a70409eba" },
                { "szl", "2e72b44ffe8581770cd92bba43c17344099811741677dfc7834b8dc4b242ebece238bc5b315ce3d50f4db1fee3ad96d2724f832b093f15d3d47f1606e7da945f" },
                { "ta", "093e282d0fc7c2cd3e20eb808990b27b568429c2e49f58130fb2f28afe95ea3a0cd20c52c02e6016c6b2175268eceacfc0b4385a16b5346fa7a6d5950c0b1f7b" },
                { "te", "21737630b4943f930c603dd03e797dcdd3ff53693d1b29ac0f1e17e1740aa8fec1ff0ba47bc9f1b3b0d1fb8a9c474c3d16d9deae2108ad97553e5fc918f3bafc" },
                { "th", "377ce0d2ed049b8dfd6ded5d6d15a42c2067700eca22e8775ac501acb047f344065658fb0a1655e75b00d14dfee9fe20b889fd8acdb97f270d02484e70b0021b" },
                { "tl", "ff6e9114852b80113cde811d1e9c760805dc11586bb605f98f7a50dcd5084625dfcaf5867288d8e55a315b89569bf93874b779bee2f7726f49d63bd83c1eadb4" },
                { "tr", "fa0b32b7879e2939b5cb9ff501330ef786db8cb644877b0cb283cfbae0e6c62470751c21560a2310fadd3d0a5a2d2297f94875163f2168bd59db4463fe52ec54" },
                { "trs", "eeddacf1483dbb1b6efb365365e1c6f8faf306a8bc3b96e18783049eb8ab0ac9c5be0b08d9c1a96752fd14e924adc56130a90a774e016a7ae1fc167c663ad9ea" },
                { "uk", "575c564831b29666a76d29e9d3607bbb09ad961bd05f6ac54ce361c478dbd271de971a65b81aeec778d08ff91fa7386f42f3ecbbd0d0c91c55e27cb306a59f33" },
                { "ur", "891b044d486a3cfc02d82fa40f4f83bdb2715143360cc85c6037aecfa821e2afa2aca5047ac7e863c3cad593b50245cdf9b0b7c1200ced0ce1b5396e8570e0cd" },
                { "uz", "a87f6f386dc45b85225321dde4776a2d5057020f9ed151ac096b87d5e34ab661a0ee0c6b5a01d7b67c01bfb947cfa1229ec03e766c17021366954103e07be93f" },
                { "vi", "7b45951b84e6f937c0eaea37e29f0a8c8945cc02132ca93d4a3580c2dfb8040543aded93b9573b5ee96e89eda4c860ed73e9ec1e54174c74451c88665251a6b8" },
                { "xh", "40f0a3d2aba30f20ae9fdd890cf3703c663f18e51da802d474341e69a612c29f71b4c70fcc3d9ba38569c344e6dc716b2ca11b09098059aaefa2e91679fa16e9" },
                { "zh-CN", "b863314b50bda7fc585c96354241f227ca3616d424ae6480d92d7da50820da513b6ba931cbb6f037c14b1fba88a406dc9675765e7c90b634dcaac9e4e176e584" },
                { "zh-TW", "4900119f70ba0789348ac8dd456a5ef61e1d626705f7ee1b4b0643409d2b28f86eddaabf9d445c315929df52c6459b896b53582e89998e92e654740b4a9e4650" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "757628c188eb878293f50b706a7384c800e6759ac31edcff76ba71b212d15d4545c41eacddfa893e156dde99b2236cff623eb7133c4d875a778c9254d17f3c27" },
                { "af", "2b13c30e004675894365f5e27426af591682b6e55cd4ab4ede9a1cd70e11d7aff3051202e1cad6f1eb4d81c1aa111218b94e2f3c50dd33f5c8880e7fd78c3a71" },
                { "an", "395b599323e2f41a94b531a2467ddd0d3a6a016335ad948910685dbc5723dd0d661a7b8024564085641262b53c0ee7ddae97501ef28f1038f14b5695602ea70e" },
                { "ar", "d532a5599d9c275382542d8849eb6f6e829a4c6d49ff46d135de15cac1cd0778f3b41047ae24feaa7be4f804fdfa12d83aeb4187f2498d061af3cf9559d03046" },
                { "ast", "ebfee3378323a98f46104b58bd70d5914972df225e6f88f10f7f192318605aac93ce81b0ed940a043a41d9b366a10fa068256eee7219109a1d7df03b94f776fd" },
                { "az", "5db9404c79b5bda1967ec335ca2f31e10604e03f042ffac4657e214594ab684ac0e52ca9a025a0d272833a3c987690d6162bc13d0a0cc27990e4375ae253f388" },
                { "be", "9e9451c55248bcdd893c6918588f883c6223a6f34e173914ca42347fbe5187a42bc061ab8f2dec995f2ed1cdaa79be3b4005d2b873b7f70592973ead3a34e1b8" },
                { "bg", "d02a9aed47699155b0ce4b76c32e8db4751201b72c38ab10262b22b0cc718a118e7c0d1a96b0f5d7cd96bd7d1ed749d2fe16eec0db3b1f811a479b0aa9f8ffe2" },
                { "bn", "aceabd47d8d33db795496545255dce155b6bff158e588595bffaffc21c4f2201f273404c3169be5974a1b857d4d511fc6835296469788c8b51b27a110daee8ce" },
                { "br", "f27e867af62b442b0e5d2215e213ad351a437d7d5d6e07e3d4c0f17b7cf21cfc335d6c28e8e53d3609f1e7fa86a1952cc8db2a102c8126cba94e9619e3d9e07b" },
                { "bs", "ed91ef25a7cb37520fec5a2464578da732744836953b239702877c344380fc1a47d43d25377d5be3bc4f96bbea4a7913ff2ee2579987e37399cd077cb6818f5e" },
                { "ca", "0b4f6fd9f8723747e9800e4ab44d1cf6d448d0e0f5756419513ce8b91c58036e02fe3ded3d2a6eff45cada2d6819b7a32b09bd40feca2f717123e6c10f42bcc2" },
                { "cak", "9e54261c906edec162275f887d93bae71fb77582d7d7eb4e4d23d7db5da57b4a2d31e433a5ccb76ff4e8e5ca258981db264dbe7a1af2372b32ce854415208cc4" },
                { "cs", "901faf2f49e5ebf70af2c4f758b30c839bdc6e7704aa51af3b0c9e2440911cd62650ff9c7d36205c081e08711e10871ca22918c08ee7f10bd867cfce5d96ff7f" },
                { "cy", "b0eafd02d44b81581ab8bc24bee24461d3a9a64be22180b0923585801a3d475948d494cbc1e4dab95620bb26798d2f5220b66607709c7e5e5958eac080c33360" },
                { "da", "a23ad63823c7ca2e67528d14619aac81cf7f0617bf4dad80749b066bb31fea943bc311d846d1837156d7b2673c163045f06bb6b7786be63b11d2acc4ae3d8eaf" },
                { "de", "024c823637d42488e4d613daea40a3edb066385b82ebd53c587036701e922bead6625685cfc43b8d51929e5473782bcdc0c23041f53835b46a70503ad332b76c" },
                { "dsb", "49de24db4e81445a312cdbe342b2b9ab7850ddf891063c8404c99f8712c27b6f1a17531eb7ae915e8be847168d5d2d1dbeedb9bf7b61fabf350e7018deb468f2" },
                { "el", "1edd3dfc42a482b829e376ccfdcd50043b5c3e3cc424b08a2bf89af923b1cf7df16e83fbd79c46cd26e319df652c729ed3c19c2472c7b41a4be1982cc4273a0b" },
                { "en-CA", "d83410074599afdbe75123f91a0caf72ad31ddd06098373c57197272c364bbe75a7b8ae95204d2fd4ece81c8ffb31cc8ecd70dbc701a8f2645850a3a9fe090bf" },
                { "en-GB", "4a544581132216609c86fbfb56684e1b20881f1fedf66906a1d0353a2e8bb68effc2caa26b1109dab3a212aa1dd400d3e456d1821e677d1367f6bbea9252a33a" },
                { "en-US", "79f3c78fae562ea77e718fb44557f8b9d8fea5c130fd5a3dd52e53f40fa78bde2cb96c3b119ea8c6dcefb53d6e46b7350010ba7b7de88bf9112be5a605d07761" },
                { "eo", "73c953714eb72105d952dcf64fbbaed7ee0db5ab3633f7789808a9081ce94c212d9cc64c0ef0a12c47362dd22d939eabcdea56bc8a38b836487ef54d68ee4992" },
                { "es-AR", "a63ed3bb0c5f0d8c5917e20af6811852b02bff047abd92f5878bc1facfc5e6b948bd26543ebfd372b12aed151f9830d1e1e4727f58ddf8e44e7b6ff2b0e84b99" },
                { "es-CL", "f2d2fbf76be0e834629d014521270c6709168ca02f21cbda51a415495b669575d772ae60b63832f7b70951477da0804287d9002b54f047d14587fca31517de30" },
                { "es-ES", "b0afe77342c1b824ca602a51dccc767297fbe161bd3b031645d757f431d32789a354fb41cf49cc2fdf4e75a75b93dd1deb545377550a04ec10ce895626e037f2" },
                { "es-MX", "4141222eab0209b5cce05be9b81f919feffc721880019dae52a7aa4327836285bd9ffb3fd90d5d78e922777e5889849a103c3f93e4ad41a26ec7c9ff31ca0d04" },
                { "et", "e0e1cd6a1df6d55e6b003973e6e737d6ccaceae8b89d352188128a031f838e8491f4ab4e250f375cc5d3135c3e65ed62f3402ba54c244ed86cea0b6aecbc9d11" },
                { "eu", "8b91ef2f1cb0ff146752aa25967585c916c4a04496f41f9715712dc1f4cc5ac3ad200637bca7495963817cec87d9cd2de2eeb971fc9502949a7a7c8c72295cb5" },
                { "fa", "13328f0b11f8eb9e53b6be0cc1f57acdf8dca8db96aa1ee1c11efcefadea12e03452c6ce71092989306ce4ae4e7b5e3d7709b6bac0e84ebbc77950b8e5f02a50" },
                { "ff", "57e96ec13d183aed01ef403ed7b1813eafcb300f8e5111beca72894600349ef8b25229d07f6b48033c94339a94a5bbf785e067cb55fb51e9e4a26fedf79752be" },
                { "fi", "489ac4ffa931700223c03e347fb824aa4eaee9246022c4ab5f41a890bfd1943ac88736b7444e7688033a93e7ae6335d0b89a482f959a5e2fd1a4aca2f5673875" },
                { "fr", "72406897d886880fabb20287e63b8de01998c8940b362c5ca4a99a936c56aafc7fcc489b19a5aabda26072bf55b645c4a39cf912142e8e781d2088ac91b81b2d" },
                { "fy-NL", "acfb9392df9bdc1b8bfc0221dea93de260d205d0a6290d41a3700a89afae5f31bb96a5ff27421d0eb752d040bdbdccf03117e664fddc7852a432fd621f658a09" },
                { "ga-IE", "126b8d81c0b27535b66928cb9db6839ce24556fa90c3349603974c754863496766c0eadce0a317e6f8b2938b3af90b2a9f8c0696e08f466830d8468e8caa141d" },
                { "gd", "c97baa33f5293aca4fecda0602103725260dd31586844d19e60f7878b80d5ddf95e4784ad475f0fab505690c11ec2ce9ef3a76854d396751fcaf50adadedc9ed" },
                { "gl", "54cb149505e0922043bb91358aba0edb2524d81fa5e9dfb451b0106c3ac6cf3f6d703911756dede0ac1d54c63b0f33ddf8e6b01cbb80aa8a87fdc7f4db67b7f8" },
                { "gn", "2607f3f8c880eb1166c9a527b40f0a210c3138ab0b824804c569f8b4ee1a91758e4cd7391f628b68373baf22315bade844689bdabbdfbec27b56758d6edc3ecc" },
                { "gu-IN", "6a03c7528e56270b7f02596b4feef7b0551a93955fd414a2d23c117fccc01bd91fabbc64419fa19d128231d74256dc54904c69ec9ae5b2f028f9b6553ed6c542" },
                { "he", "47a3b0a23750bb9cb5182656d80d2f8173d4444d0ce9e59ed8c417a2168206b54c9dcef7217d67842f002784b36b3be81bf2ec7fd1d355c9fa5d122dd303b72d" },
                { "hi-IN", "f99f6a3feeb2c1c14f2b31a8ecf8cb49db8c4b77c67f835266c0b0e69a58c9310098857a8fdd63ca83275c14ea1f6eacee023e430daf29780ef7df855680fba6" },
                { "hr", "01a71ac6ff536302f3c56056285d031f5f2f6530e9d8899f90f1b305d484cdb12a54b17a4442e670b91c969ae93f15cede5537d460471f7a389b043da62d711b" },
                { "hsb", "68c1a45211683850ec90abe4b612f142bf53bde46aba30e1eafc5475ffdf40893fb597175fae8876b24efdff592ac1105c9ac0bbd53ffbbe41f9f55643b70137" },
                { "hu", "e41966ee85607a15b501696ccb1756ee828b72d422d62d1e68d79b63774ca95709493505a4aeeac87ed4872ccf7dd0cec8617406ebaf43a643d96e4602610672" },
                { "hy-AM", "7f6677cc6f7c5be21a3e19d6d5ec3cab85c3edd1a982a29ba3ad762aed73568d12e1bc841de564c7ac59584c527538ffb78e566f902b7186b4186e57fef5983e" },
                { "ia", "b42978e9e291b188afb4c4c118af0a977c041b99096b0c1155bdad9de48660372a0b723b443bb26fb0d9cef3bca6996bfda4f0b381dc3e32fcdb220f290f00c5" },
                { "id", "fa55434858002acf5a28c69dacbd495cd84093925af5626f1de0b60f15b7906176df5f82ccd9b7fb85735044e786d11359a003cb03cdb87f043cc3a4bc7ebc58" },
                { "is", "72dc2a16a2b89f5f601efd3302303389aafd033aee6151f05d414c99b734772d7b6035095aa29bbfb24426f7b0b2e18fb37778879924c93e31811e22b0f75706" },
                { "it", "4d3c95818de73a6835bbbfeb971bd133d6c4fd113ab15a3853c995633484702e8a867f7734791b9f154d3d929179fc5724bc631cc6f29223560277c5422fdfb0" },
                { "ja", "67461f5ddd252772b4522d574781c47da19e883ddd3fbd1bdbabe353cc708e9fcea0d83b274b78fe221a28d3866327e2b30e35582b1005c481f8a5dbb51559b0" },
                { "ka", "726729db6fec34622bebd812b20638bdd1048060227b252b109c8ea6343ed3247ee11ab8ff23421f6193ddd97e86d074abae1dd5f6fa37286c6b99ed4dc69863" },
                { "kab", "cca624445226dd413eebbbe8139e94cc538fe7b28f890157e7eca9e1049ea83c8cbc9fa996fd39c7f4854216e1b135e492ebf1053b5e850e7e2085989e3537b7" },
                { "kk", "28f64d53abe49f1d8105dd3c964e38bad333bcb2d31e5386ee67457e16755ecc5b27dad95f7fbb7dbcb3fb8852cc7da9733c887dd0659414405c9d8caa7239a6" },
                { "km", "fcb8b4b38ff26d6be0e62a9743374228e635a62a0f4d0bedbeec73f54a7be3bc80830785ec050384680eff77b579adb24a71a61051ab485bf917f7da05b04ac1" },
                { "kn", "d7bd3ee1a5b9ae90c290f7328502d25592c0306a28fdda8fd9405b42125daffb413392ad4d3268eec813446896b7d4b15338681b3d1842a3b8169da9ccc5d86d" },
                { "ko", "cba7c0919c3878b0883f704082e181de2fa7274f3486d24ee985a70760d9d5843dbd500d85b4caae8e84c56fce1d68553014971ea6982000f6c2cfb61d218d65" },
                { "lij", "004a7bb4efc08b423504aacc3e0861acab47627461ff7eb17ab23882a132fef18e7a58b650a2d26188e368094d6c555407ed2add1235f477054378d55ddeb98b" },
                { "lt", "4dae657b40773ad5d2be66add1fd35eea3c8d2e710924ca9042bb4fa1a93367e73ba0de4d887d459ad30f6faf26fde963044c0593e01ae3679d0a8b2f1ebe960" },
                { "lv", "15724cb0f52fe848c927f6c6a3d86ecb64609f415aa5dffc3c6332eb9a512f7b1105c3d9f41a3380c399866d42819e53720ba5c8813d51defa535f52e005acc9" },
                { "mk", "f7b0c10ec3f91cd6e6bc633bbc337b31480fb08154516fba3541689306a094d985b6c2247c167e68e5195eae2c73db71c64ae499e136dfd67caa54a7e2bef38f" },
                { "mr", "398bcd8b7ee1e31f82ae46d954eee12fe2dea4efb86be4ef07420572a81d9ec8a37d1bc5b62c350cb599dc11aff3216cbb2e4a3640b91ced1c821b8a892f235b" },
                { "ms", "25005d4d4f229d25630c51bad5319a1c77d07ae6c6b4f2402d9328e1f73722d705d277f3fe60ff759ed6b4e107b2845f78971aec3a9e019bc5b33c6cf0f29695" },
                { "my", "5d173f8c12489e6f57875534ae696a7280bff7318c94e0799df9e027102954895b6da1029df9a435dc0f05bad9c167b4e2be6b92c5b76ab12ea315073f63abad" },
                { "nb-NO", "de95b7579cd073ca542395627ff2a4bbee4b77885163509b0fc4e7b7398f5a26a561763cf6ac1d76a576eb9b4ef9f18c1124078eea22b090b0455cc01b76821f" },
                { "ne-NP", "64e74c8822e28937cb4039764c5b4967fd74fa757db212eaf8449eece6a5707515a4d417dea9da4f6492a3f9c4ccb291940580b815e1fcb69e70836bfdd3e7d7" },
                { "nl", "ecccc67427c599315be5da71a2535a699bcc688b0637a22623aee5c6abbef81d6e6b5af4bf94e14b994ba9546aa857614d50e13bdc63761b52203c3e314f99b0" },
                { "nn-NO", "1a40c5d3160da0e7b28fd04cb4888029175de79e69b8bbaf6d0c310dba5ecaae4c5bda66ff10ade81cbb69e02bff8acb977d4ec9686cf9c43b9b9d839b34ec8b" },
                { "oc", "6534bce54ceb3ccf2c3482d95e8244de5c2c4e87ba48162a5433147071dfadf91ea5d73b4d7701cbe7e3098655d695431e8f14ba6838a12f378eced8e935dc91" },
                { "pa-IN", "80a34eb91b2c3719d9e29779b52a1a9802a149711917016ffbfa5570b1f04fc1bb5d60ed33d27eaafed585b40a308d118d25884b297e61c5c189b619f111225a" },
                { "pl", "66eed661ae1e1c9bccb3839a34621e47267f8efc9c8b4548bd5d1f632630b2e10edd179840d72bad0b488cf94f91e769d3613d623f44eebeb35b1041d748235b" },
                { "pt-BR", "e4374e6799497d011e82dbd2131ec3a578b725c7a47ff3a4e714e14030c0a00ae09dc327ca2167626caaea09c2289c1d908c86ebc1318c555df9f2f99ee96cfa" },
                { "pt-PT", "6ab06979b9928cfcb7006c103f2691fcc246a0c5f5574a2dc7bcd4ca38fd28873b8c33763e935769d99d683bd163cfa3086b6bc2cad90b264f3af56cf84aa989" },
                { "rm", "f66c1b28e2b93b2fe9e5abe7f4f06a538a4076b97cc24e6ea3fd4345a246b98525a71a175946d671fbb0465106913dce8a682c3d1761245825e2231363becbd8" },
                { "ro", "6fda9a85d2cd4c0af50c1ddadda1d394cd02fad8fc9aab3ff10603807b2cafc393e549961fa83b3ad570b83663f0ca3810b339ec78cd02437a6a8a35cbb54f9a" },
                { "ru", "a3eb825c3a14db210ce25fe1d5d410820775fb066a34f9ac031d2ccec5fd71348e0184e5c91e8b215c41f92b4fdd8f4cdbcfe46765cb93cf6101b5a44a6180be" },
                { "sco", "3bfbac3f3df5c9923efb956bd8b5c0ec4f6e521f84dd9ffdf8899054c480a40c5505646bb639f20722020b16d0999731dd1fa2f5e71165698f1e4aaf64833152" },
                { "si", "4c9514ab0fac8eb59af8ceb16d0b5764743260156a30e0127f180af5db4f5d8ff5665310788f94b16fac7ca2a703070f713b16a13145b108c6a57d3644ebc347" },
                { "sk", "3e6e72fa0153cd9b9c1d85fa1f6961bd53c0515ea6c0adbe1066d699b683a9084ae1b92292ea696cc56d59f7b3583cbe939140408ac21d00b1fecc3aed4d5d1d" },
                { "sl", "0718e333ee3c205e3940d0184f430486c80cd36c4f81526bd87912fb80c05843a07b8973fd538045fe2e5427efc2d4d8d163181a2aaa7f78b381e34377dc80e6" },
                { "son", "878535659a3aacc6ad8579938be9d664986f7d71fb7cc48c32d650a314e978dc40ff34a92999426ef5ee890b501f0f0e9e0d7d28f5bfa8948f6aa4f097a7cbbb" },
                { "sq", "3ce6efd1cb071ad9dbfa5d018ff582c47fb2b3d24bb9b0124f8ccb0c39c0e2d273ed7aac189ff8087716e1ab9acdfca6a09d1a0b7acfa650fed09bd2e30a36f0" },
                { "sr", "db63f35c7a508f9eb2a1be1dd7436eab25f08468535d5a370643d455909d08dc21ffe7981d0438a0533d0528c84909b631c6623cff5cdb97f9804f3c488b58bd" },
                { "sv-SE", "4825247a7ae0799e48a4406e061ef47ca653b6d6c0b88e670035c17a99b2eadeefc66131ec4bb2120d4f8d64254f95c0dd5f131d48f40d3b1f3b8796738684b5" },
                { "szl", "1b3ef8f9933fee4331915b2068f7d4a187fb9975286834729bfddea9a0e97099c6808651fe44c2cfc9c87dfdb142d57d50f406f5c9bc815c741af02a956682c8" },
                { "ta", "a83ee564d9f6eb6e28433f277bb8b54256d56c33ed4fdd691c6af924d9692af3335950fb8cccdf40b64e1a9434ce1c32cd6a39ece75005ef36cf26a3b1e353a9" },
                { "te", "615eb58739e082eaa5d6957f847d083f24f53ea072e99be91ed6cecc53ed3a4edb2e558eb6082f2a3efe8a530e6f1adf9bfed937927277cfa5de7f46ad56dc12" },
                { "th", "b4410a72e8fc18eedced8d3f1ac3b4d50666e1a54ccad7a82187a0c6040e663d92358e2d6c096b1126f313998c72cd0a8e4a06087e8e304cca547b49e1913bf6" },
                { "tl", "8b5b12696fda0e0df89c3b498ac5c9250a52dae7fa1a6c747d9620462751bdaf772fe635522856472c5a0c2f65422031261f236844bd453a3c3b13af8290f8f0" },
                { "tr", "9eae3fb5ec8c40262c0dbf72412fc4ab66b199840a48613b7a21c5448e6efdea8a98f993cef525f081328e61f578062eb074366b5b3b67e978b79945584e61a8" },
                { "trs", "3666f14f95e8adeff9caa8c70fa6b8613c96c80859eea413ae329aa4bbe7747e4c83a98ad7b6c2c380d9b3fa9d2ffbb639cadd4414a7d772ab79207a53410721" },
                { "uk", "43fd96b91337462bb136fd0cb4f24bf4f380409963d49be390f6ee6b4fca700f434306dfe4891a269b29a306fdbb28a53ea6f8c304df30a4ba8248bb7cf67c83" },
                { "ur", "23a2c06a881312abf18948378f3741a7649efd5fe71c6e8e02a26aa65b18c034675ab7c2f91b149496379bb87b791bdc79b35e33f10427ca6e63a35df3a21975" },
                { "uz", "a4798eea483406a0730165f1a1e7834fdc9dc6a894c814b9e23d2d0f716b3374d51ce0dd15228cf6472f080bc42d2df9e002639a3b06d8123967f5abec323c63" },
                { "vi", "187f0bb2941b302782486ede1c645d23ebbdde80c37376d5f947fafaf85cb5bed561cbd2ad14c5d2b52df646163af0509670576a55829a6edd36baab9ce27856" },
                { "xh", "d24b2121f80e60f98f3ea110050d1bee69285c7d7cf2c481c8bb7e40e1e1e220b2050bd396ca61c555980aebfab31b10e64594678856ea59fc4e465bdafd866b" },
                { "zh-CN", "9a834acac1042a8a4aa32d447df75ff7c08d0b1e1ebe6312682577cd119f57e5e5f909f9b199c5abba6ee8dd0d665f588684b5861e533194bdd6d4b37f23efc4" },
                { "zh-TW", "737bbe1ad5bb1f69ced10a51b54183ec0a45141066ac582e6ec0cfdf5585cf814334d11b87663d090e27f7ae3b5767eefa84dada31ad2a596775112fe78ebc1c" }
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
            const string knownVersion = "102.8.0";
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
