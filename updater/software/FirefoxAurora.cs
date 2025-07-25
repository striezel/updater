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
        private const string currentVersion = "142.0b3";


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
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "bd486327682e8bfbccbe560e8cf8859feb46cd777fbefbd74a55613d5aa04898f8c51d060f8dce0985d8eb308c60551f3510b8ec06677cbdcefda60352415556" },
                { "af", "88717d510b5b4cb815be33dd3e31133891d05e0fc670d7444fe4f1960d4b4a9954149015f76f959b73827ce9d819608e06e29b885e23cf7d9b8eeaf9ece630ef" },
                { "an", "c7940af936c33e35e8f598dccfc13fc9812f25efc0b2c2e7219c5bd30ffcaadcd7dff3ad275d4cdd2fcc0764a0c3707efd4da1eacf45216a4bad32b5cc04e0c7" },
                { "ar", "09d6b2b22b10e95b1237550fbacaa1982b6b31fb0f7393dcb0f4373d6bc4355723a9c8aa44a4618843a12be4c4c37c1d3c9d0a909e57c7e5e4be6e88febd522d" },
                { "ast", "5ef4d9decb24fbb3e8261cd31e262d518b7d98b205d4238b100fa042d925f7e1eff7d124332cf4f1e3fa7141d3e9e5f3dab330f33693474226b091ed41b88f15" },
                { "az", "d5749380a4b68c4c749ae744516ca2f2b83a4e4341a62022613d00f74b2c54e7e78484007dfd2481ce3bc4fe48481624eb9e8318feb38313b1545c2a997c8868" },
                { "be", "1c7d70f871877467a793cdd2571ff017295292e12b1f46576b4a05783c794c82326ec8b53b982eed7fd00ffc8612a06eef37c74141053f07e6bed667c739a704" },
                { "bg", "87624b4087091f10bdae542a3acf4a025af527f5b8f38dfa618d67cdb8a470ae988229fad1f89621fe3ef38c1e3977df9ba4a04aa8a9d2a8ab84371f2cbcc284" },
                { "bn", "97bb0dd07ee154e135e8414df2d50d74bb01e249db47f5d365b36e67193f570a261d30d3d744ba8feca60443c3b2f42f7ea2f736f5faaa7884572b19ac86fcec" },
                { "br", "48438788701cf2663b7f9264085c384fa590233eff7a95dce7f3e6fadc1031cb6667c6212cf051308d2381ff1ae2173eae8cfedce9aad580e11ac0cb798165c5" },
                { "bs", "d7ec5210ba2d62b90083dea82aa27c8cce87545fcb04c0eb8c72442fff4ba278b57636a0e79465ee4d339a4d6e94d2c8a142de933d5906feea32a9851f075378" },
                { "ca", "f60a19523dcfe55f3fd0e9b552a53d7259d55d8cb2fba1f5d8c039cc6ee398779c78655b85b00b6bc0f640456d95f2d4bf56752882baf9653d5ed59fbd535790" },
                { "cak", "ea32c55f30d7caaa43cbedd8bab9674202118c9b15a7fe568a2fa0a8847a198eae84998393324d3ba3ff6c254b6bce2a6aafff183f9a89f777a5ca84a859e2f9" },
                { "cs", "82546a63086477719d326f4af46cb101e8f0e3ba623ed767daaac89964a0b27675da2c9736d4efd7e35b1a140dbf4cd3480ec5ab6f4d834343d2e96bf9836a42" },
                { "cy", "6a234fa467de856fd4ded975b8d20e185b024094fe824e409f1186d5a0cf1bac89b2659bfe828896032157da58b67b640ff2e110f9a243c7910d1bec4968733d" },
                { "da", "c351cd5d60914050fadbdd853800d2ee13fc77d68c3ec35aaeb3000f2bcf406ea5a5d3097c8c27bf079949fb4a6edb513d570e071bcfd5eaff6922f9c8bf1b80" },
                { "de", "2fc6bde72cdac7e35b178a9f9687401232eeef535619ae7df9505e0ddc0ae4824cabfbe32e2311fda59353d8bd5fc22371618ec6e33dbc37e9afac92705e299b" },
                { "dsb", "a7105141c7f1262f4277ea2bf96239588209c8be0c9f3f2b675cd5ee5ce36f6754a0c98d289d6d1e4a228bca9d6f3922440eb1fdc78aa7163c72423563fe2ea6" },
                { "el", "c7f7d7662e447e09cdf66c8b5db71e8abcb1c3a2d562142dbd36882a7a0befe172f6027b36219cffea44dc8b3101cbdc0a1cbca5440351d66a1356e515aa7cd6" },
                { "en-CA", "363089b7de2a17ad23ea1cc279feac07d1adc6be6317a5cc5f38ce4db81c0ff9b55998b6e5d47fd844811eef7202b95c8987dbef02e45434a5a0a638458234f8" },
                { "en-GB", "ef12171f034981b80c2f162612f64414e353b49dba959978423a49321918ace5299ce03298c4a5f18ec4e5acc0a1eff6473db9d809b5b2a59dad14dd2db55be4" },
                { "en-US", "6435974ff8249446942ebf594dc77393aa413ab298c020cf2001b642154ef69316b0ba9bd559fa52d0ff5267c3c95678da253d5e65561e871792aaee69fb0b5f" },
                { "eo", "d3df612390320472a191e7c836da0a1380241ea743d43d76e8159257cd0b0aef8b79054f60c31273fb5c43ed036107439d8a5f931a123ab9e80fcd57b1b4cdc9" },
                { "es-AR", "b95c5bdcaaa8b3493f40836e1e28e6c210ea2a4efd1fa800f24632366f26760bdf785abaee82aa6c8872fdf9269842af692cf2145b3bcc5820474cea7f4652ec" },
                { "es-CL", "d9332ced6caf59216a1fec169ca6938af07f8e425192271b9fad38e05f73194da4c569ee30c8b72b3740e321c6e725b7113de59484bec2fda4a34c27da5ddd3d" },
                { "es-ES", "d713deeac61c0086cfbd654b7f67df9ba5e984764fe1f002636acd7e172520adb5b967236aa68264cd68bc4b564ac3b6bae4dda84ce4dc45c37371e42df6ba27" },
                { "es-MX", "20c10169edf7a9dc11f8b87602321e2a6b0155b494cd5dcfdd2430fb071f6d3ac3bd0732e384ae6783ad0bd2f76396f97d696e7b1302facc5c406106773621ec" },
                { "et", "e02bc9966ded7fbfe5a5c406fe66610601190c867cd10cd6c8f967a5b443b3ac6f4b03deca6daca1f4782e27949bbb30b1471f6d12e6fe72505a604de819d704" },
                { "eu", "ad0a4a51ca0425bcc75d4678064bb6140a293ee15019cd6ec060fce72f64878dba068cd2d7e50bf78ac93f3646bc8292b2f2047ece5a2b8b570f39afaee3f6f7" },
                { "fa", "4b9880e22fa9d2f24ca88cf74d1850cd02de81ae4c9ab8997ac5db487a8cc43c1a8504b578cc0597f7a798e8401ca7dad9eb1ed56df70f78c41ce6705b5c66a6" },
                { "ff", "e2813601a30f8f13a415126e7c4e1f789ff0feec795bc75b645ec706b44f2ba16e06bc5ad68eb89b1e061639d650ea932631389ce3a6deea516ceb2d0afef278" },
                { "fi", "928bfdb9fe2e2e7a845b48544c79411a682fec5e7eab0f1c482e9e1f1db70018a2621af8e6d27ff56f6172ef7e244b79f41677c6af43e97ef80fb2431e9b9a9b" },
                { "fr", "ee842d93e0e7fd0e48e229ed6ee86ae1e7c79e82990bfe6adfd5da6b9b37b6d8be45deb3746ac7969251a81d2bb89e28341f30b642e8045a0428bae6d4813196" },
                { "fur", "f00d14464c1a736e0c542f41d9df45af992d57f83249de70475cdff8f1ca7197d0b39e49a585428b838cf1ff37706b755e11076f54cf071b5de7cd9d886e64da" },
                { "fy-NL", "25cb2e101744b1b0914419e6559c208bc6c41ab7fe6864bdd48039bbdaa91737272cee3d1b098a5ed5e18029492a03638659e255dfcc40929f94758c04c83b3d" },
                { "ga-IE", "43e609390dc8ae80f49d9e3438199021bbbcd1cdeb653caf3aa77f432c57a54679a60b3b9d7e19771ad9bd9577eb3fdae69faa74d9b7bbd9145ff5dddcdb556c" },
                { "gd", "9143653c915a164787f6470146da31a0f8c7f7025ac7718a9891594f6584335fe51912aa8398031838887c9fee97bf7ca89699950622bb27f4c0ee921b210f00" },
                { "gl", "81ef5fe8427d7e6ff5425411690abf12fdebf7977294e72258f763bfd0a82ecefe114754ce91d143b59c652aa1f5c8ef2270bbb044d9f4cd4d039cd6bac8fa09" },
                { "gn", "8dbecccc1b19991844914fb1ab345d30de8c6790c09bc4607a69540b482ad5167f7a4ef7f73d2bcb1fdc1aa12b3e1eb5d5c56c7099ba59114ffa071b79579843" },
                { "gu-IN", "956c0a94a00d25ee56ee94794d883fe50075f82a2ed241d0a826b1e63305a64f50923ec20dd85459c0d637b51a63241bba5279e5a63b583ba1669d5f59ea8598" },
                { "he", "83823b4b757ce9db2d012bcfa8a3e12369195090d0fc2712a6a38f13a14a3c5e687ca411a36520ef91074ab1dd216fd29a7af22263d7d4b8f365d5c3ba116a7b" },
                { "hi-IN", "b02fcb64663b4d8633beadf19e0ddbd84781d12d74c125c00c23f8d57ba24e8103d4e6d36d06a7ccd55bb45f32832c40b55427a9b957a6cbbfea0eca56756241" },
                { "hr", "2b5cd0392e8aedaafe0d007fe629673c6f84b3a6f32bf76b37079f3c9dc606345012a9794cbb27b08e844061f7b65a37841e7f87ec04b3246319880c4928287a" },
                { "hsb", "c81e68004aae9fe9d4ccc7a48091819685f08becaaacdf3167b5772cb6a3f91621c886bba88c6c7d353ffbd6e4f657b5648b8f6f01dd0139c0238b4843c108fe" },
                { "hu", "5592f61d1f2446df59acfbc8f420d5233502844a4e9f675b95b3da5b61d3601a03306288d245c83bdaafa99de560cb2fae4f286de5d3489be1a4fd10a4d809cf" },
                { "hy-AM", "677dc0657a9da1e13c0ed731770a1e27f1d16093ec0f4b61a36eb9f0ed5d7edbdddf4296313646172ce5b6cad4f2129b180f4372601d0bd880b8948c509cb704" },
                { "ia", "d2790cb7b603220c78d02b63ff4e3754b9d2fab989283656d406e678e08e4584495141729c8656c0901f89987590b8cce5df5a9d482bd11e56da2c653d0148bc" },
                { "id", "85f1c7a12e7e8931c1efc383d82e3ea4a79827dfb12189286a64048bc48e414a4377724b789d29fbea8be81324ff4a9083ae278d83f29b8a5bdc43022e3002cf" },
                { "is", "3edb1f502fab7c37acbdc7ab7d2d640446f74634ddf34d0383f9521f931945d981428336f8bdb50bb9ed740b54596b2b44c7bc070035d804ddf97362f42c7e00" },
                { "it", "5f14673716a34c8b70c44874abd8cb3673864e3face68af711f84458128737c548a2286de319d3f7b1d139ce0873d39f499de195c64eb4417e6cffb398307b9e" },
                { "ja", "c89f59fd1481f8d198e6be166bfec0c3a9f49ebd82088de49926daa9663f68efd0e46ee518e249848060960c1308cb4e9cda5ee680e0b58e372c43a628070c31" },
                { "ka", "875c14e6a1cf1617e3c618fa38d54b7b16b5927ead3a383c97c4948bc6a71bd10479e01c84c5d10de363ef75f01050c6fac02824c3243d685880a326b969a6a4" },
                { "kab", "4d80c40bccfa98eff398953f3c678c5c5de21a57b59ee825db5721feebf8679beec3b0b0e9b894aa2a31829bc57bca0e41c80a2ce3fd00ac1410e6cc31b25338" },
                { "kk", "30fdf47826da7ab5d43c0b1610b217ab3b65742b2089aec0d7a1458a27d15c1f9d3fa572c087f7275c8643c855ed44acf69053d6293b28c4e54fc64383135871" },
                { "km", "10ff501ae7801742cf8ed904c52e01f51474b4082a8b78adc7e60cc3a5b6a48c0294f71c2b0e1cf8e2e406e2347e608dcd577836b8ffbe542fc4499f246f7be9" },
                { "kn", "fffbc98526288a3f46048c19abaa0b95c2228eee2b044bfba999278d9ad3ad2a6200e22f73ff5682e62448f07bb48122392d661fc1112f662d9f535f5d2efae0" },
                { "ko", "1abb9c896a9f466d6ad69bf4f24943b7b503fa40da77e20c0a605b988a7084cd1a89da1d14b0b4b2a6d25907eb9799ea0621425436b92496ae71f61c16a3b51f" },
                { "lij", "fa509f74797f61d50cd45ff6396b2d2a196113892f1039137689e4732c2c4c240a9bc3daa0d07adfff012d087a1b9a03b8bde125335edc93eb0153e6cec9b831" },
                { "lt", "d058aab93b60dad43a7f1fd573c5b8e312b9763ae07233cb551fd79a33d52f3b20dc034939cfd91fca0d44786d686bca56b02f0359e9deb25c87e95981e78c0f" },
                { "lv", "05c1b6bbc77d76f27a81ebee8b7893aee122f5e9d74c7ce9d2c2a8d4e8b6c5b481128aa89844431fca7384fbbf52f93c68bbd22a986297e721d0e7033c7be45a" },
                { "mk", "0c7d5270b32c79dc86cf96e6b1b43d8094ef12d599239483fc345211460fbc3cd42347f717ccb91ae706363efd736a3fd6d87994e3890e2d9dd7a80fa0a06d7f" },
                { "mr", "2c093ba3ba55b3d07bd6f377ce285641c09a63ac5853805d00afdb3f3a37e1582e3454837216f5e4e257cd8111ddc73dba08250c37cb59f4c23446aaf0026fc8" },
                { "ms", "5f288800a94a6b4eaf11a9fa7423145bf82272400307a58b211b90dfa56315bd5fea3ad7e437bc43dc61416c42b3b5f17436ac28a0ad4cb28a24282a98e6fc0d" },
                { "my", "4dca9fef61d79a71cd92f4fb7aa086f59b75078e4dad3b73a383b7f7f5d012d8bfa424f4d437f1717a9e53e8f19460c0946beaa996c819e6df2987a19caf05a3" },
                { "nb-NO", "d2b28222c937ecc2f42dc64bdc638814a162d9982aae3ddfedffc5d2c8d159629bf4f65ff35c7b005894cd1bf938f4e1da2cb56d04188272a6a0ff12f6d8c288" },
                { "ne-NP", "b92f5b1cec8ad1f675df2ba51392d65387002e7c4ceef8f43f46394edb2c88b630e37b2fcf86da5d9910d9fdd798d6022bc80c31ef02044cc39cff9ff096c72d" },
                { "nl", "46cba218f46d6da43379129c261e0142005abea743d1661558065b55ad99d27c575e705ad03d88a13a79a06a88bc8cdb8e2308586c4dc3ef9b1aeb467184978e" },
                { "nn-NO", "2c15be7030b8dc43b03ef06aadaa8dba09d00d94d30c55c06f8d0eb8a5a7dbb8dc3942c23cb5c03430041326f95a556e20330bb54529d4c4a1a0848bd06a835c" },
                { "oc", "732fe15543797dfd5bdee1514063d32d19962584c0bec10c63ac9562a8285ed0775e7a37faa29f58c3e3c94fe108be50cd60fb72eae05cfecc9a53a6cd46c465" },
                { "pa-IN", "d49455891c4f34d37ef1183ac6ca1763642fd70646c14f5184611679a74dc2a2aa2a056b3f2c2e28998396e3ed5c6d31679781f266c2c0f37f4f4b3fe8d02295" },
                { "pl", "f7ffeb2b497b23f6ec895b92e7ad70378e88d2ecd918ea3b9daee0355fd6e2cf7b4057f54cfcdf167c45360f1c2d003547848a7a64b8ea897616a70f404a6817" },
                { "pt-BR", "79e0cec05c8e6bc3d39fc5acf6874e34c7d8dcb03f19e48545489a636aad73c26eccff54624a8dc8a5eb52ff64338b90c91143f03bd6acee69f2940fa1be550c" },
                { "pt-PT", "64fa4704355d91687bf45a02b6df91b65f13776acd593e3b88af0d8f2db05ae8dbecf3e986192db7fac6607623336dbc1370fa3bea7753749067348e2728c721" },
                { "rm", "0b5e400428b09d329cbfedce9bf1abbf3ad35dd8ccb808cc62551990529e8c24f93d9ec11ef4ea1dd854765aa5887aa9dcf037dd1fe30310df8df67aec49bc06" },
                { "ro", "57f570c04fb68e22153510de258dd0762727f1eec3d2b25079d806de0e021e6ceb91b91630dfb57f63f5ab550c50a600e839d0d7ae797e79ca4b45262eef0563" },
                { "ru", "11c97584cddf2da34a1d4a0dfba53f4701d5e7baadd2a1dc91a75d3fb04f40d6dd04ba5c551ac16d7817fbc821f2a97d44fc7426f04600bd1c5ecb6c295cc388" },
                { "sat", "7d165bfa0d08c28461c2b352c6955a4e025d5fefdb20c3658ccefe796d818eedc84ab8fb9df3d2f7b5eb1cb58ad75b5367dd086701581069ded6bc8d59e74f6b" },
                { "sc", "5bb564efdf07774884d7f9d156d4aba0eb03c7d2014f9ae80ae26efbb0705ce87c7dfd227ccced010a7a6a2fb1566714ee409ab0f5188991d2da4361f28501cb" },
                { "sco", "f1540715924076abebf9aefe89fd6b1df89103deebb5277266544b4cb95dda6131aa3933e5739bbfffa5910d3d16995a6c07e8d7e0ad370e90d1913bacd69d70" },
                { "si", "39aff9aa55be2082328b2c078517bfff5a0c000eeddb457a5030bc3bb3a15f1d9673ffffb583b202020237c57f6e65a6cce75f97d1bc388a1e92328d59387b5a" },
                { "sk", "55ce6b3477ebab9384a793889f7d6e2851c350b501f83b3d029993a2269631a2907a79fb519a71e310162fdb6ed958d87b07128e7c355b2ab311e622e8857799" },
                { "skr", "c56346e816ada006a437286977be943c653b0ea14484f7e02d22c6ed29c6544f05a59ea17ad0b5e360da72d29c3ba1cc5f6a739b5f380a176e5df0ab6f38553b" },
                { "sl", "556fc47bef032a2148cb28f6f4a1317daa53112575258827156bd0635df84418c85eefff3a9baeae1fab19c5a4e3a1f580820b1613f90251916920323537298d" },
                { "son", "44979285a2f3e0749b296ab4cccb23bef40b8fb07be47ed1739701a64b5cf6104b872c970ff063b52859a761d067eb329f8ed86861517fce7b6002ce6378bdf2" },
                { "sq", "53a973f6f3d4a23ff9c639b4a3b797ad5fcbb05a2ce34512b0043b8517888298c1270156fd75642f7ede4eba974ce888fd03a4d122ce4820eb44f5d049bd535c" },
                { "sr", "981e9fdafbd8a54fb8e403a05131d49d416314feab0c095fe6fe01d477ca792f9a58cc0f8ba70442c0dacf5a23dc297b4b37b10f93af2f288f59da8e06f4836f" },
                { "sv-SE", "dbd3bcc0a311f5284f9c5e5d49a286601d2b3013e4c9fbdeec124e18ace479dbf03bcc1a72570b4d02ffef6278e35e080ebf88c9ce11faa345fd3a750c964924" },
                { "szl", "42a98830d795e9ec157fc5ed43b7e155b4bef27ad95802e4005659f2ccab2f1a6fe274a2e9e8abed2c36d018f5e8ce3ea65e63b1b318b4acbd5dd5a99dd0f5f3" },
                { "ta", "eccce2ec4642e87208a5984798913d902df33645108c9c690695926d8177e389e54e9f11c4b463ef56665962e12db68cb6c90d7c783d8d3fd429c706baab2fb3" },
                { "te", "8bcd5ea60f2976b0c9fc5b874cef4489d2c33f4c6e1892a87e8974859a074ff8d9606fc7758f999d326fe3a39a628112ac0f1c926f22bce6def5258f310dd57d" },
                { "tg", "e2c1787a3b1ccd93cb0dad23795ba457a1d6319ab574071b7ec2bdf94deb4052d889cf7497330b8ec95b156aa2a95228aa2619c55aac9b0123c88066ff895de4" },
                { "th", "ca763fded78ae1828d7fba3318102840dcfc93dcb99e622b9f55b3a934fbe68cf92b195155559d2eb124c1669a55230d7d7c0b7b7889ae64ecd23f0fa090d76d" },
                { "tl", "0b3da8cb5ffa77a632ea9a09af82446c0783ecb2251dd98cdceffcc77327eecc73701de13bfbf8b57e59765541f390f93695eb46c3054e037a497df764dcc9b8" },
                { "tr", "ab116ffc19406952af0f089d0a1205ca97192e3cb26e979d418173967b99ea785faace009ea76fc84b54fe07a70f81ac957309434cd4a65c04ec7b3f99938699" },
                { "trs", "e398434d11a2416418b1e05da122ee75e63571fcc342d101300d43ceb46aed83aede5d1b449bf32e3ae00e9343f67e275215b53de52ef849efcb42f2d3f7ff8c" },
                { "uk", "c81dab5894de28c21fe25ca34ffd7a5b5957e03ada091800e48a725710962eaf862bbc772d09cde9261a56d27607702234927e2d69df4afe88c8dc6c4410cc1a" },
                { "ur", "eae45b38e605ab8a874a99bdb1dcac4dac519e7614666625989d644b31fe30401e06eefb15b87e4921e3a8f2a27969a0c3939699ed4a7b3a03095bc113a74052" },
                { "uz", "5c71c9bce849e5a563eb1332fe85ac41a76603bb1a2a269d2b93905adb082a9f3e4cb79427e9d0967163d5ef4ed89f484c191712d34c388a16566b0d923ae556" },
                { "vi", "108f0f655bbe96f41f10f084cf1d00934d97fa567446a3a3a81c78ee1b5b7c7d8c85edd9144dbfe9887f59241257ef273f74d4b7ddd4633e0dd7d53e2c090937" },
                { "xh", "242f7f146dc790f3a613eace6c88e4ce91be303436d63a1b7393c235ef3f27e91cf3c8d6530634ad7b0d81c4b6e3f7677d453d01da4ea3aef28abe20cdd0b017" },
                { "zh-CN", "cd34b3ceddb8f08c84280ab37b3ecf6f17376b776f531588bc231b72dbe15310bef49a1ad8ff8150726361e083df889725f13da716043c1a6f9e61fde2fc784b" },
                { "zh-TW", "2fe93a449e7819a000e476936e1c9a037db4b19482ce0a43453a75fc2cdf1a0c19f4ba2dc024ec981f3cb082b80bc07274462268c1201d25a966896f3829c1cd" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9ff7665a36870d9035e4263d9220cc16f51ece8fdeab98782240a0bd512cd8f39e1fd93094dcbfab3dd4a886ef1fa871562d565b20ea69374754322a3227159e" },
                { "af", "ec81889364c2c1e4cf91ed380e8a9c594f39943d2daa02544fe395f83ce965ffe3f774ca95239db774fa44e36641685d7e181e2d59dccac996abb902be10f45f" },
                { "an", "19daa4dd5fe50d274e7a2906c2409c9ea5f4885735558190d35c40ee002c88974d876fcfd45e9a4b76efe9248a9518c24278da68d2437e026c225f3b1acc3d51" },
                { "ar", "27f40985e6dcf86e2c283c003699948a0f92fa4c113ef9a4015b509d3c70ae43d124814bb6877c8f9828be65a78f411e20e3bcbe3a5728330579d8fae4c92b10" },
                { "ast", "c0f1f5a1e2bc63fa1643092f60bf0e785ef31ec8545311e52b7d145d2ce8497bc9fa2cf5124dd1b63e4a23f06b12dfd1cd84685f5e876c44351bcff601200bab" },
                { "az", "76c691cce921256f46f80da3288459a70585d9416db08877b6f76b3918fdaceae7d031a5868ca9a86c26c9840f714a9835c6a78e6a2d8d83cc82770f39a53f32" },
                { "be", "9532888a3b28546044eecffa531017bd1bac38c778ef35e4a997c23587d8d8a6c73d748b751aebd60e62dc1a5d1f6db7e8853085b26683dace8a3065dc52401b" },
                { "bg", "24f9bc98a811322fa67dc079f9d9e308a347ad81123a8e3f9f88bfba2ca40db30ba6532823a570be02096625d1ad04ce8913ec82a8f252fc12cfece1c5ae806f" },
                { "bn", "c15578232e3ce1364c1c62970e5c22351088f401b33f4a17d8fa46ef803ec919e25a1c947e7ce5657cda493e2a2644d8c4aab33611eb1cf340ea712660313598" },
                { "br", "de7fca1b0ed32a76cadb670ec85bd5803ea0a19194366c69dd4cd04e158293e3223e93a4912f97b93a23e375f15a9f1445c7e312be8f5b21e3958c46005960bb" },
                { "bs", "a1ec0cc9018c85f34e80194a2eee3ab0b3b456cad74bfb71306b2a962e2a4c002e8db51ade26fb3b037dbac742be2c676cf8b598a36f3d109edd236283109f30" },
                { "ca", "f3630337e262b11169f99eb56bbe91fa587046faa8e250d1dad92508433edffb52ed90bd180c7f1e6d5ee855af9cd7448b1202f5c32b6dc8731a90a4c0830a2b" },
                { "cak", "e47d6c5d03a0862ca4e383239b71ee70cac50d63b318d8f849364fb5543a517bf9f1c155a50b4914911e1e6bdddfbdd355f07a3ed3b3b82a8b21a9f484c8f469" },
                { "cs", "54fddbc46f2e38d872f57894a2da3a5953c96ac0c02e5b97f78ca3369db62e64f8daa35880636801460fa805b5b79d435145f3e786ce812c14862fd85d06b791" },
                { "cy", "126878dcbe7eb0d67161babef11bb9dfd6eccb166fd47309aafe7037f40bb0e016b2a9bc66984d5d419785416f0ff0dfd512930b742af11d1fda71d5d0ed1edb" },
                { "da", "45d844be24c47a1c441c8109fbc45f6d8304f7867b7ca52b07627e4e527cff659b9a1d7167617c68b8ad32dcbc6545c7e730856452ebe0e85a924ee96cc9aab4" },
                { "de", "4942838095468b8898e713687354d54e1e81ac1507b99efa5d9cece16c5c2ddb191db71848a5b0c883b871303ce39b4eded4db84ff86de95f4dea5ea15412241" },
                { "dsb", "0adc81345be2732741996e9c463c0b40d6bfa716c97924576a0566091aaf7252417d309e6749b5ea3512a4e16027277b7497e8fac5de16ac8f284fe27e98c537" },
                { "el", "142b687c88113d5b20a0c130be665e0cbcf0ecc74085fba08205e8378b7f8d85188031115f6423345828f96f31e6b45fea0f89a2d73ec428d463271dd42ab009" },
                { "en-CA", "ec9730b59c2e1a9cd3ce03fc71b831ee6f37b89ad58449324bf97d02ce588efd8eecd2de7c6ceba05f3ce3b60080f9e138511f50718b3aee751499041d4c059f" },
                { "en-GB", "4ebce1b06daffb4a92a4d0acb63d465151340b67d6089c3d944ef8fcd7878c99ad9ee89a23b415c877a45523a03893ca31ec672540a9a1d04cc8213288c411ee" },
                { "en-US", "9cbaef92a6ebac9d4f84ddc083990668a2fed3c12b2e77c206beb765344fc5dbfa04f025352aa4e74d4a3fecbc033253d6d00ade51744a23066c367ad928b470" },
                { "eo", "e3cefb56e526232391334801cc69212f05ee6d7e4afbb0487c3ce80d665280837b1d0fd403a05e4a6e7f899c9403fd32f43d230936ac717e55c5767e70943c13" },
                { "es-AR", "ca0a58ab49116f0f983a8541570e3ad49782f655392da61a240a3a48207476884fb3a6a347713c08975160624612dc226dc9f3848637f988f37f6a00f75f6505" },
                { "es-CL", "4bbe989f9dbeb6ce0c65ba708749d3a74ecf88ec24e6cd905f30be5eafcd14dce43b9542125d0d1044d00f4a137d1c71dc504b043cf7d07d421c8591d06ea9b8" },
                { "es-ES", "08fd106fe63aa3421073834281bab594ab829a54d5793a30f2fb971396dfb84158946ec740e30da1ff331a2982e3a34317cea9e2dd5c9ad861d053976d56b405" },
                { "es-MX", "ee2ae7884d0f42bbd32ea76f31e0aca742af1b12008f58a9aec386ff2549a36a569402c7f7fafd345d6f78c6133aff77a517759d061d2d316073cfe116cbda14" },
                { "et", "c381537d6e60deab49ce40efb8d679bccf8cae6d68d3b02c0a59396acc7eddf74a8ce346f4edb0c25ab5734848ba77709f4dde5c6bab8923acdf524120cb526c" },
                { "eu", "5bcfdab8ce69504c23c484d837cfb9462c973a9344af1e49878f621687bbfbefd13944f95eb437e43f36724825358fe8c9d5ac868e26bd508e1a8768cc75a1b1" },
                { "fa", "5b268cad805921d0c795bddc537183d9653d7c2cd33f34e426ae622691dd7ae607c2c77c887dc35d25b23e1d71ad421d5de5293997287f988bca589f403bdec8" },
                { "ff", "763b9ca080338d55ddc581305b7617aea6e2b751940e7c407e6720fb4cd79b5dede065bf992805c487e20fbf8961a678713f93ce065f755fddf8a654c01c97a6" },
                { "fi", "af5acb83cb22a79f68c6ca4274edcdcd36eb8230df8f0bb3c6518c48c3f801fa412ed682bd35da1044f0e390fa613de032ae654343fce104fd5c140820e12506" },
                { "fr", "34817ea4e2ba7adbe80c791d7b3e2d3d677dde45ba96edf2253ca384272a79b9b8251b63692f5f875d61046e30d0fc027122f7147194944da51dd1e3b111c32e" },
                { "fur", "7a4e8ae4582044d2a117e9818e625215315e65d4950c037cf38ed2285a3eaee215bd4a80775edbe8377049e7433c123a8d4411ea7451bf85295022fabb20c1f7" },
                { "fy-NL", "4911251f3468d8125d9cf2e5230a05c3b38a44d91f1ae7dd67d0831f2c9e066a2c2aa183101318162df10319c75d04730b265e52a81aa24ab149725a5b9b040a" },
                { "ga-IE", "445abccdd5ec3c39727d6cbe5a91ed0b8f24c54f339c7e1c42d741816a1dc0c0b0bcd57d0b1af6b59bdfe884a53085392e78aae8c74a12e7e554db73da3bd8c9" },
                { "gd", "7799c14301263c6dba4ff59143d8343056cd01332bee244e75df837dfcbeb2c07c267e1022ae36f2cd02d312c711d7cc4e93e6768935e1ff10ba60b4831855b2" },
                { "gl", "772b6b097ad1363807b352bf6e9ae2951bd5def995128ae0140dfbb615c706f7d06003b5598ab9f03fe7685b5ec9c2b9a1a7c1850bdf4686956012452c471381" },
                { "gn", "a8bb9064b4812066cf33c1fe5453f8896b6945aa87fd924d24c020b4cb601c4ab3d4fbc68303a2a3a5ee99d059a6b7470a7b6b0b5b097387ff91e22339a55f21" },
                { "gu-IN", "d9845bfaf8888cfd89252980e84e0e3ea042b4aea98eea8178ff14ce93cccf8285e241749426e3e4a6102aaaa0ab44e95436792dccb008964e021e5a6491d060" },
                { "he", "ab8b35f96f6893b81edc97c8f260341671f36cf443df1416db8a580c7cf489189cd6b2d245fc89627390a7b55cc4193519b8947c070baeb96942108775d8ecb8" },
                { "hi-IN", "95fd19413aca8b025625925caebdcef1daef084c3e5365bd1f3d5fc1f6facdfac13cb1d96c3ae8bfffec9cf0e91dd217180f2699c72a2bae273c613d30192f07" },
                { "hr", "4f10fda970b6ea1b447f8557dfd17e981d38aad27b327d39ce7f195139ec58894a20447be198f485fe1e71e9dfe177c32358ff2697c810859acdbdad5003cebf" },
                { "hsb", "2dfb28a14f3aba17b7c840b733a8ba5551ff4d806e118e03b9970cc8941a2489720fe7cf0ceedd858bcbf4bf5e26d0926105dff2776d9aaf15c700c9851b3396" },
                { "hu", "87390859764373a4546e171336ace932687bea7a01d9fcf4f0d1d75455ac2c0476bce52bd880df6c01c107d0c43442aadf985c81eec86d0123bb97835aef33df" },
                { "hy-AM", "1673bfa538462950d9ce03b362cbaa6920caee620d1ab9e50667914298a37c90d3ed95fe0a2e9d598abf6f625f38033421d7d20dc7786995554019479f038798" },
                { "ia", "9de6cedd565d37fa7a2bb70c719ff0104ec9de43761a73df56b09512e9077b791b7d564596c572219702616e781fab669b279ef1d2f93e1b71f05bba05b7629e" },
                { "id", "2c8ad766e7579d78422b7f4ba8c0511f0f8f652c1b9ea3ecca58b27520ae23944aa06d8e478f78e3f7796e0027f0ea66fa3162c127c7b1bfa556c65c9b6ad079" },
                { "is", "7057365abd289d83da657af5370ba51c9a6522185bb84ab74bc314c32f412d3a91b0d95a8e72c2897ad58c0ff99149509f48dd626bc12f3a772a8a421b7584d6" },
                { "it", "bea4ca8230c99e9670a995c1ad59830c1325d28402f84cb77f2cd3c17e53ed0d38f4e90a3fb7dcb514bc7468be91572bb0d88a392f9d646c50c717bc86e6d29f" },
                { "ja", "e7209185fe2bd7134cc200f89a277385e3dcce24331df6e8560ab23f35ce10959a9f29f4419add403be1b7c569a23686b433178c8eba0a3479ffdd10b5d3b231" },
                { "ka", "fbd5f7904362670d317b6f1d3cc2fd80147bcd6c7269094ea9481ebae1dde50a19ccd0b3f5e1a4527fb46bc236e38902250b39e4a625c913c7d31d786c62876d" },
                { "kab", "45533ab9449be9ccbe56788d575648991b2721c1746c6aac1abf44c5db59fb223313ec56ed1fb354977e7100ab6ec0e6b710be574c5dec8d605165d1af243136" },
                { "kk", "b6e03a66a0b385fe6f236bb68ca4c265edfaeba893d3e84159fc052e8c5f7a5c53137956353b0bbf6761cbb226273007ec1993d0e21c546c053f8a1d3964d1f6" },
                { "km", "8555d58e49b53ee10b9eae379cdedac3cfe0426f31382659b18ac61b05337a72686a1e8d512aae2aeddde69f79a853384b35102edcdda0f611525aac3a4041a9" },
                { "kn", "b455012741b2f501fede9f29b85792facc6bcf79b7ac5e3716c2a47e7978a6b9f6ff9ca6b95c9f46913ebca910489533467b609efc8acdc70501cae90e7df5e8" },
                { "ko", "ebc8bcb1628aa2aba2d1a9cce7ce7627f1bbc3ea0a993e1a51e04bae9c7ce5998e0e4f66dc78118af767c1648baf89bcd0639b5379f0748431dbe6a308fc33b5" },
                { "lij", "3e186626d6d8e620f0d10e3bd02415533254b14903923fde8eac4f050e14a5f7602ed605f1f8d328976aae9576fa540d2bb93f3b4d106ca9c991fb0a2d7dab22" },
                { "lt", "c3cf5fe99e714f258fc1c04085c0531919af4d90f5bc86d8bb349aa7a4f2dcd15199e88b32f7349aea412a314df69264b7c82593d2678b6291b4ae6a9caa7855" },
                { "lv", "0d9c8b47589d5a85732e01633464a94e7f5310324d9b6a69cb5302bf6941ce7af841d7aff5e6624a25cde23821e6ec034a55d189dc1ddecca5709f58143e3538" },
                { "mk", "6151d08346d2202eaa4c5b2e5a879ce1c1339fc0a52713d01dd67668011a73e79690d10376e6364185312b09bebe8a3fb0f1f571b74f261d55145e22b23310dc" },
                { "mr", "96950a8c74ec6d426ed087f88c79a1e9f1e1f4ce7ce25a41f1ddcfc34d14b5e5c0fb1700d58c72e89c8a0e281f882215e77e33f2f1be96a950c731bf7998f8bb" },
                { "ms", "599bcfa0c20f49539b14f98dcdbf6f5957ef7a8ea189fe7742e04b2f8fbdd1b664ce60268f7e4f6af52c97154c6654a1d414ee4e58fc19f2096e4336376b3c4a" },
                { "my", "575d4e695067d10ad53144324fc5c548543f77d4cda9c46820ec742c0ed8d7f9f93334c329e5b075d62326a9429ede8999ec5c4141bdea754c5efe6824b20d9a" },
                { "nb-NO", "39bd922be8993a3c4f5b7a8cca43058d5a72e846a5cbcd2d14ffb49758f6d7befc82b5d914aaa45765bd0df25181607aded2c1dc3af5e2030090e34926a912ff" },
                { "ne-NP", "520b2b8fa951056d8f4bc6f6ff1d944a1c884e97973dd8a89a837bbede76eb330cb275a407f9bf3bc2fca96f62aad5fa4349feb5f22b36b9da748cd28237d5fb" },
                { "nl", "0d2af1c5d6d951a14fc2fc66049eea4e771aa70c8eb0e362e46df8034fd205cebd405fc0b2e7f397837ec0aaac79f4980f6ce1938c09db29eb9793c2d6f5a3dc" },
                { "nn-NO", "948209c495a5ac89e93044c7a1b8e7a8dd6bbf8076382d365a1b0e73405a8b5611ccc70b9135e6f43c523b4e414cafa0131f83d7c17c9188fb450b4aca51562a" },
                { "oc", "084249f0b626b7cad17b888b7152da8f0e32673fb47a5f31468211762ecfbc7a09246020b34e309b9cbe4769792522b6ae25178f2de3a3cb5fcb642ba8114189" },
                { "pa-IN", "7d6d5693d5428050922e61873154bce93a73a064519e31da97e172914978c874e2b1aa43d1e9b064af4e3199a82ac33205b19b2894822305578ee80055192906" },
                { "pl", "23288857bb993b9dc06521fb9fbc79fd7c3335882206f58adac2fcbfa82f4b850e4f666fd9542d93a4cd0623cf1dfc29124ac6a0b3a5e0327b5646448b66a82e" },
                { "pt-BR", "068c763cf9825ee5f0111cf6102c7b338f8d40a2b1a102fe35ffbee729770a445bb48599ba56b231569be5f04cc481e1b12797424b0f5441bdaccbc2987f1f70" },
                { "pt-PT", "0706e30c32338046ef20da39a48ac6f570af3afea411cbc324ba5be094294527c94406109550e35f6cdca3a946b8d20226287f28107d1e0e980af89d99aeb80e" },
                { "rm", "4587f790e9abe8127e0737d286de80acbd20d3b198888f50699eaeda0da9ca663b50e92eb7937889a59fed2d80611d191879371d4b06737e65707e58d98dce21" },
                { "ro", "86075d8218aa0079326c64d413524de041e5a570a96a6eec6d9f4749e6e2904d250bab78b80b9fd90c559e3d4e0d694bc6ade8844e3550de6b5fbc4369c2ef08" },
                { "ru", "2a82a05ef5303319557030ff8d164b50da497bf60077059850da9aaabcd836a38e8ae8052fcb22246266a11d572d0f65c3b6e0ce38fcc06b8bd88a6f709f06ed" },
                { "sat", "b00507b96b56c1363c6011a4d61d8cb90a8dd598c92244c1a76f068f7d864dda27ff5e92547047a7a2874e14e5763699c71816f0772eeb0617ce80dbcc0119ef" },
                { "sc", "40769bb99f39e7d8920bc46b8c107b00b5a2503f2ef95594fb2aab600d964ba1ecb59213e739eb2454a63e86743d2de645aae59377f7a326592de4c99ebb1bf2" },
                { "sco", "7cb4015d0edc5bcd4e9fa37264f6c262907c52e086bfde3e96e7b2aa6661f448c27c13087402d91a6f536e8b914265590fcc9f62c6f901f9daaace464b998aec" },
                { "si", "877a69d23222326e997087d2bcd29684a14af81dcb8fda828889281419c1efa35fa1256513f104035fb446941793b6b0425779ba4c12ed34678fc657c97c58db" },
                { "sk", "b22b9b2c84fd964e18934559fe482f19d4b0b397cc53cc858ee676131464a1404ddfd9b70cffcee9c751248c025887073dcea2349577762fba5be12de86830a3" },
                { "skr", "f66d735221d1331e05535d8aad00a87c9b5c4b0df86d9cd1d91d6a9519bdcd9d9976a7bb464e2a622d8bb3817acea22eb8545db716d8284c5c2ff3c34a311ed8" },
                { "sl", "47628d6706cdb00bc7e8213ca50b1d0b48865cfc12c72021c53cd16c7bdb94d1060c1a5a007af312d42fcbce9e900330dbe07bf3a0fdf0dfe7871d8aa50934c9" },
                { "son", "18ecb3ea0b311424e59d5a4e487ea6a6a58f0836bbc60df44f87c24336f747dac33477081986a4e57503741f6377bede303c4132293a8d22d727a24177f0a8e3" },
                { "sq", "931d7e4abd67605b1802b97c600d58c48867d52004c889335f28a6fc395e8a7cc88de3e81226f71989f23f255eb3b09e9ec394f5f643bff6fa69def6d945df56" },
                { "sr", "9247513c46d3f420f0cc97b68ec22271322e7bd78e24d226a6c82fe506c54fd578735a434c24a8403e6cf7a75bd30970c8d05d0a97f79a8a6641cb089e4e29c6" },
                { "sv-SE", "4b4276039591ebad18136b6d386d2b9bb51e7b2b12f4bba9162537aef07e85169851c1f123dfd814aa8277b29948e843d84620280f5bfa0cf924ecf96e5e68f4" },
                { "szl", "dc3c58454e4e5b95e34c33004c4defecaedc2baf71f4f8783febd2acb89ba9c78db731bb92048f846d9c5ed6ff6a0b3394b2369a777dd3056564b2eec0d8e9a0" },
                { "ta", "2e70f7df0486751aa49da3a40ea08b2a32255b2bcb42d44812b88e4de793b6c1b9967f36dc36e5d1f0f8cdeae29a0f0d6dc413a84254f57f860cc570d552e376" },
                { "te", "b518d469f7ff22d37766c5962b2f29a2dd5e38c85c3e8e8785dba506220b2a0e6fb475aa5fdc23e4d8ee8a99fe8044d32ea8403e5f535e8eb5ae633c4c601451" },
                { "tg", "d9774e88d9f21bea1b22a359fad09946b0889caa970d138bfe7aa9840e5fe71f32b6d27428ff8677812a2379f98f9332aa9870e543347756033a8c5749d9ab3e" },
                { "th", "1f0df3b7259b065dfa85fa1516ada7e1afaf92eff0ed4e6283039f9075a0ac1ff9f9f61fb085ab636e01d9fa2bb8c99ce9091ec09aac0e4bd10a15836406d5be" },
                { "tl", "dad5a225a31a6dc739fb110557f0a55876b4176047ea1649600e4e65bed8e3d55a60083fb10381a59b65e28cd966e099a829ad81511727095e5920f29d327ee0" },
                { "tr", "34f36ca655d1c756eec89e75a3d5a91f9ef70f534b3aad9e9861dfbd54b12be124ec9b9e6f2a22954d0a8a1fbfe2a0c044f54ffe390edad4f8764337eaed4cfc" },
                { "trs", "f6e114fab458cf01c0b74fe1c90439e052b26285734114eab3f9288339464d3fc95c37edf639a99e01e1cccd1485e85bac6ee7b321f8c0cac918729dd534e2f4" },
                { "uk", "3b2f80a65c3e27e1da186708d384fb9c3999c56cdc90162f3b4f165df97d15fe19a6ba98c0c9b2b8a469b8f06737825659d05c3547587dba3651f052436e1f17" },
                { "ur", "c2d52880a1000b23978d2cebf447ba4b36aa697556b2784dfcad14459de4759edb550ebde2eeff224c611902f7c38b942434dc09e11f5a77822ab544fd990a4d" },
                { "uz", "56c4f4d8af2d12bc168a1c8917c3fd1d0d4ff5b549fd9592fe2a31f1b0012ab151b96681b0935f2a47691cc5645285de29598718f5a7fa1ef88b7e7fc773e508" },
                { "vi", "142d39ad26a501379d6114b9b332152d84b52a7be02c3652ccdfde51394548bde25c5643c6d28d146c47198ec1161625b48ddb0330d4b9309c39c3da52f49337" },
                { "xh", "350dec57a746df4d8b7d051c4ba9d76f5b241ca8900b90bb0177810557183f3e4197fa0bc78e9de19c86a66b0fe753242f5d7ae7545b2769e56e329ce68f7b33" },
                { "zh-CN", "03529128bdb7f5de36989d2914ab68eb3ec0fcd36321bb995fffca9dc77066a366d7d9615d99f05ded7ce334b5947d9a7040ac41848c1b0b71434f18386c5356" },
                { "zh-TW", "079b53cfb96210c427596de39ef7554a5682cd623ddcfa3c5b05760ac66ff4fc0642b7b824034f2f754d438d69b186d21375feac8fe2ecc1ed0e4e2de9ebf78b" }
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
