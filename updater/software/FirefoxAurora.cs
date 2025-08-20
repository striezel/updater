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
        private const string currentVersion = "143.0b1";


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
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d9a482ad3cc9bba8d827d0fd3059df06752adf010597512cf398df3e99d353001ca4dbc62f1dd0fb6e8965608eed5137f7295a975b614d4600fcbfb1906e10b8" },
                { "af", "9db689b27e3089a0a0f94f6d03404018e80a68f8148373db3cce25b36cecd14d92901922c26fef980d2ba46f5ebb62b5d0ddb0ffb7a3da35b6f3ecc1e590b9d1" },
                { "an", "f68cb1777f4cea9b84f679393dfaafd2d3d5e42973067e8dc2983f722738b8ee87719fcb710a9222e47e6da5db588f66c603fa6a1a78c86b69d5e1903e71cc2a" },
                { "ar", "edc566afe8236e0a46b5eee0177998a1e8e7c1f6e17da90bf6a240e6f772c21191f5759f9eefa662c9b7919a8102ee645efcf670405cf657d01c39ad755d323b" },
                { "ast", "5b2ac2917ac72379344f07ccc89ebe6240bd96889f50acc4c2667f241a71ea0fc6b9277ee2ae161b01eac6ad7ded19782ce9183f8543883fd3746966e49b8391" },
                { "az", "f521e6b8e08fdf83d1950f85b533d5649893360ca67d3e6c4246b7c489e2993aa229eb16fea3a66e3e6b54a4784f78383280c09075ea2353927e3cfe51348289" },
                { "be", "13c039fa0ac79d5c1fb23475f665b50d54dfc872aeff9e34e26a66e67e34f8b808f4cd2e6232911a239e3dca67d1057e15c9f7249eb6b65f50eaa81425ce6f03" },
                { "bg", "00283a003b7551d5be8f69f384360e967463e11c44f29c67d9a04a26933f69d360e02c3024ec58bf8946aa73eda38712b386f7691a7a26222e64a78127db4088" },
                { "bn", "aeddc0f7d65548d57776fbe3aa4de204e3829cf92e2e5deb8199b3bf3d310411fcc7a62a3fb4ca75cd6cdd6b61fa1de6d80b16687019ac16cef5c90b58513411" },
                { "br", "4a18e2bdb02734b671482e64d062fb1518cf8d4a5f75c3596584f26b7a4eb5b498ae4c39e7bc6c9fab9c79b65e825e3e27d8853b5459167385b79efc2c1c8f1f" },
                { "bs", "1c3aaa577a0e8c9228555f597c3aefd4916e8f7279dd50845992443fd117ab1ccff5d3e78a926a3bdd0d7e5652530e73aba4b86b630db371298228b3c26afb5f" },
                { "ca", "3e74acddecc57a320206a355fd72b14ee03527a4a85e3ace7e086e9f28a2bfdbc09a68db007d34900c0b84165e5900c60c62eabd2eb823f5d48f6baa7f1bcf8c" },
                { "cak", "d6f67ac80c212c9db6300c35fa6199b279fd79e26e391a229d3062f0b7f79eff1c317037823e7003b63ad22dce72e76ef66759dc42520e77233996923ba5c4b3" },
                { "cs", "7e0c02967a290c6b4d3510ef019e9d4ff62573384c7cdac49b5dae06ff996e452f54fbefbaf3ae1247afe94883aa44d19731fbe6cb978a4326a4b320d59743e6" },
                { "cy", "a7d2f60e49d956906769c3a18ab798427e960b487611e6add903e63352c5eb01266814d2580dbec443efec2a37212329068a4e3f0949a78aede704e55ec7b48f" },
                { "da", "e9c8cda327f7a8352c86b85538bbc31fd34fc7b28b3bbe91852a24a02aa8a9a754eaf930487affeff3653a360ce06df7b5dbd9586e8343bd1d0c824917390172" },
                { "de", "1251fa6ee51877198f29416573ad30b75eec268cfb99dbc16766bbbc50223241c2b7953566f760d7c006b9e22df4ff2487912087bbf5286237891e01ec9e0e02" },
                { "dsb", "c65d54f15134a22bf69d407fff5ffc88d7bcf2630b4666d61885c604d95287d23109af0bce1690dbabb7fc35763807eceb2b6d6dc6ee0069c339efdfeadcf00c" },
                { "el", "391f07efa042b22bbc8d7c457d0263308bb40f0177417c24627f73b5338bb37117f5397ac0a8a968a4dda487017a108dc2a66b37bec6c1ddf577ee215a6be67c" },
                { "en-CA", "010e5ae2a6a859631ff963d292cd8a38b15ec46ac218f5e7a068e56f7b12bb4306fcf58627d7de737d0884cdcd694f2c4687960723d96abb6b4b8e939cee613c" },
                { "en-GB", "abc47f4a5c48c29144b947a80b558f8a3041f09991ab7a38414477273724893b13acd18989e3e5d9edd98b2470ce81d62f719dd2cc9bea80d5d2dd708130fb2f" },
                { "en-US", "333bd3d76a238b2ad0c99daef5473dd4202f53e33b4c7814ee2d3ae7483ec408bf0fe2fbcc7f06c2737f77a7fbf08b08cf6f06b1a48332529374d124a463c1f4" },
                { "eo", "5ec6b87a5f38669ebe7b38638866f9a734baa46e9ef1a06cdf9ca1438620d6ed2cba74ffc7c6522edfc9d5fd307c02d00c05c2c2892fbb69f2d3d157745b4e02" },
                { "es-AR", "3e2f9632a1b205d3ef3dded22fdeb435e353032acb091c961a36154d3bfd41a3aff639dbca9aaaa9296402e9d311ff9b39522d537bcf04bc05ebec86065c7c2a" },
                { "es-CL", "0d700567f0dc64872c53793a0030b344c0f945b25260f3c1dd6a3710fbf2835187df6997f5eff8737333404e23eda56d3ddb34d9e8e7a71b3030e7a97de1c3ed" },
                { "es-ES", "adc6ece9e99912ea236ae82979c0cc60e8b3cb9af29a4b4271fcd5c8725bc173d2b04a317e889c58b3da39c2d61a47b5c67947536a22fbfc0c27050387b543b2" },
                { "es-MX", "7ea9b72b819cf413b196a614af2f58887fc39d2b6663affcadbf0c8e08bd271301f10bb1034d458a22cf8997ddd573572442cdfb58834bf86e481cda5b09dfff" },
                { "et", "ad5b94fba9e42a25d73223947536dad183b91734779571d5d1961d3e9f7fe1efb24d7ed957fdedf474c7aba9f3e3b7d9b1121de470aa52d3f29043d845627393" },
                { "eu", "0c5e5038c5de17976e87da73999a5026bb428847f0ac65c91cb54307278bf3349db4e94255b779bf1ac488ba44063bf511fd675dfd630e840d61d6d4f48427fb" },
                { "fa", "7d51326d5656391e4c30382f52290ad8d9f63fbf372cb23f1257e9a785047a8c0b5137b66788fa9444ad14df76b5b73f0dacf089f7fd58ef12fd57de866375b8" },
                { "ff", "22a004384bb6079b4642a3ae7e88797fc2156c7f5c10e5463cf5510f9b3011afe21d80d03a923c0b79de6b56bae63a16d0984e88afe242369e4a83e423a6e7d8" },
                { "fi", "2af2a4d074a93906cde2b5e678947b59075cf9baa85811fa857f9d7cd6492d45a2bc7ed3c30f712c520e08ef115e8cdee131b49ac23e39d255f5afc420e5aeb6" },
                { "fr", "c8b4e754bee9ddfa75ccb9b229be9232455f8f56f01db15e3dd4eee397a0d0d3e698aec14e98848339d8a83d1886ed53216c509abccd75fd3f179d6bfceadae3" },
                { "fur", "8b5868bdda6b353b2d0b9f79a079bf3113ee7f1def30e5932ec2f77caa76fe25eb096ab9aac2b9bac6a97de722813a589c1782f08a97dc1f08fbd7e10d417376" },
                { "fy-NL", "c1f2278c10ca817df672ea313d2a66b49d75a4d38af82d5950b170afc106fa657463cbc709d6f3c3c79d9d5b9b9eb07fc1f4730fb9ff0f5aa24607069b643923" },
                { "ga-IE", "573f84e70ab6936f541fa8741a84ea2e610be48f4a031642c245ec90f3ecb993fee81b2269db21e7322cdbaadf4f3fe317ca7b522f584e0226da45757ca32714" },
                { "gd", "ad5c71584632ce93d4a50deac6b646ac6e0dffb7dc25cd787c24bdaebd9cec5790602760f876f144cb43d21d56750d25f737b64a749f52bf9d8057a9644463d0" },
                { "gl", "7565fc7407db59159a9a197c144a3501b3663a8858591f7bbdd113f7b12022a1b7fff3cf99692536ed4ff465038c6adc6b16406634d5af471964428414903782" },
                { "gn", "b4c9bca708f60b29e0f1a60999bf89a5556f8d798902534bac8cede6d1a9e4df6033a08b4a15b57cb1bd2feaf762c0d2c9bb116f76329a07f87175910cf97b70" },
                { "gu-IN", "169984df01b00cfeecd7da541bd3b613c14fabccf367b97720d435ef2c40ef4ea8800d5b1c8371a74472323d94f9d55cf6deca0d1b397ea381962c4bb07f1e35" },
                { "he", "dda727ec0808859493a13b69113ab622a0daf6a44697ee70956286e735b9596c61454df43b2dfb290b7dfb5e2bc6a658e58d43153b6cdf6a414c839b53ff7ebb" },
                { "hi-IN", "99a93a3a0601a12d5588c0a819d28206dc44d8e39a2e2750d03f23509f76a592c58193c0bbc40e722eddfc17b7118018c470eae011e499f5581c1bb867243af2" },
                { "hr", "38b4ab9dd6ca6fa5c6fd2e1f8a7402a8d845be719e730c54771fa261f23b49bac60de110776001157263efcd39c4e51db437f2400882d92cec575b87f664189b" },
                { "hsb", "c036b233ddac71c1495dd9fa04bfea3c0238e10b60e09c67b57e19ef8fe5f4d2af38860be13c80fd4deded6d9984ac278823194c85ddf08e44a3cc9d35bdc18a" },
                { "hu", "6ad16198ad4dd2ba1eb6892a55cf6936239a04040ddc114567a23e8c1c48f3dc6dc12bff80f31e4aded3e93695e4c73f7094d29511682e5a80b578803145f62e" },
                { "hy-AM", "103905c8ee10c520ef68f666c4ce4e0a8e912730635466069c0820cc34ab5b7367e1ef8a7e00801659f392b0497e045e43bf0bf9715505c1343ff6f4a42629b1" },
                { "ia", "ca075f1a57444dbdeabe9a89c6775167885fa240fcaeca22c0f9dc56b8ffd2af22e48c65fd2eb5d3bee28314ec00dee9d8abc09a74167c313b4a7a3e8ecb14ea" },
                { "id", "641bc5579a48f5d0582115d9b92d25ea6a2fec4e2b11b40f860d78471c8d56cbdcf9c9fe388faed9fa0b33fdaba5f071b91423a1421aec7211a3743c6097d0b8" },
                { "is", "c4bd6c498be92c4ebc78ce76bd5f34cee34193477e31d1e785a3c231c19e5bd544e2655796436e94f38161c4baec95e4015f8680f9cc3bc082cb59fb155bfb91" },
                { "it", "0a0710907d8869fc10271afb24027a225dcd11b5e9e2bab29285a8239f12763826b92ce02bf5a463b053b93ed837889ae308eac643fa6ee1e821d41764fe8157" },
                { "ja", "5dea866c07b21b6e5ac2a0e23a6b654e617a8fe692af9268859a7623f55dd4ac93973a1c67efe54e6e72a13fe7e67130cc9fae1a5b7a7449d6e8c124221b47fc" },
                { "ka", "9852dd7add422bbcc82c9e54a7750fdc60ac971fac82d893c8c22a609b7ecd4319a2d23ac22be8adfaaa9f33e501006d577a5d71005f96ea012d0e9097b5e935" },
                { "kab", "8e36a49f3eaa913e55df87f74d32ede4cfa433af031c2ee55c47e70fbee80f2fccf39c4a5ded937fa71481fac43806aad02a3f4ea3819c44b61153ddc05eae86" },
                { "kk", "d093a39d81b507336709d89a7c748ecc1902312597015c7fbf7226a6897461aabaf21e028cba4e505c6cf7059cb4a9f113a78233692261dba27f3f1d3488fa03" },
                { "km", "3564d9a43fe429d7a169f6a6264a138c6fc1ef17ed316443d34cb44e5964a7e0c13ee540774a5b776d3682f586c73a7b55314e7c9af66feb6a1cf54a8ee21ede" },
                { "kn", "90533485fdf01dcab783a2dbf30f66353659ac481820b37329999a7d80427428b3c2028ba37e743c22daa57bb4130f4ded7da0c1bb0a28053675c17bc5af076a" },
                { "ko", "acdf6442b872a8bc512a5b69a2da5fdebd3882eb3806a020aed82e019a2f2f8ec8d33b37d3d48dd6300594abd0c7308069455f79d0828b42fb1b7bb8d5f3574f" },
                { "lij", "9f828bd973f4e568061cff89cf037ad0d37d9f44dfc9c86b0ec7f4d293b711d03b65c164b337b11872a382702409a15c2fe0c0b948385b0e714eab47efc99112" },
                { "lt", "65cfd865c3f80a8979996257f9752abeb0390ff36e1e8d028fb492dcea9bc52d8f9adf6ab5ad326bdaa6a60f1b331c58929eb06eb6b99403e175c5435df9e5ca" },
                { "lv", "2f123814fcda42cc9ed94b8819843466b4df5ffbdeccc6ed0f9c67062f6ee9759a554e5f6115f31c1f0bcde70b5de8f5e33d07d2317461842f3c3ca1c232a6ff" },
                { "mk", "0a7a8107b5aeafff224c50570e1b82ad016c054808908a02924ac0343d335418ded331f8b1c3963e71583dfd1ef4311e260117bd92b5e8aedffff5604bb17723" },
                { "mr", "a94e12dad5388e0ac440d62410c269090d1cb74196d3e80742df92cfcfa8d63798eb86c95d6ba3b7c83a69c0d838c6d99fadafb4b15ccc14ff8ff889e16f0f29" },
                { "ms", "d1a71011f9062a6c03e888d31656e29b74b55eeb7996e66cbf8bc717ac5338908ee2fdf1a2febf3baf8c6584120546d0e8a6788db84163e34e2ff1ddec927b5d" },
                { "my", "14163417012a852a8efb568f4d4f7f0046d60c6f095d6a72d183495245905702d2c34cf174bf800760a3af83d803baa75fd675cb82d287d0087fbc0fad21fd9a" },
                { "nb-NO", "abb1f46821f85223298928c7b8399415306f2f07a04d0239711e2a4947dc6a7970e5c270bf05e4df0e011cc078e289c06826f7df0b57b7cb3b312ed84296d965" },
                { "ne-NP", "bedd86d88d840c5a0bdf7d59f52820fad8e0b7057f2509748acdeab8a3c4a93b95cd47f322f9eef4030b48e043335f263f2ac45033c2ac12461c1ec54f43e9bd" },
                { "nl", "e565f73cc252fc34461b7f5ade54ec6dee0fb780fe3f1ba138f392b004dce6e82a37123310d48fc099ab4f17c74c3dd353aeea84bf8eec21c22e70300813ce40" },
                { "nn-NO", "758af9cf06dbf0ccdbdd2c78f3de9beceb81715abee8782505f86e2422276e67f30f42b072770a22fa07cf2921776dce6d1dab2f3cb02839d8dfb1ae8601abbf" },
                { "oc", "14159bf77bb19430f5c1fa737deaa4dc2cd579586780dbe7aae1bdd959b0d8ce38542a7cf36cb1a1511e6012cb3897c87e4c585af0dcd544035168c6da4917df" },
                { "pa-IN", "bc6c6a4e925da3d24900131d104b09f0e0abae2b6dbb6011888da75299542cb9bca622be7d7684b12e7a2f3e52ef17f187af0d7b79df99e3c1159caaf800393c" },
                { "pl", "8d043c95febc248e130218498596799340c405ad53a0e4fd6b5fb81c64919b35d76cf03e384f4061b2889ea2f63cb1a53bedbaa734eb28d704d6489537f05ce6" },
                { "pt-BR", "92e73ccf820bb80b741d02c5103454c5fed25f92d91125ee7d8bf6f9f3c12a5ee9270b91cfca30d8244fdaa97b818708d6056b3b5d58cdb257b2e486b75aae71" },
                { "pt-PT", "a18544e9d4b3806fa7748e5b2f8fe4aea0d5dc4eed1eb7880796a58b4403c23b89d1a64d2e1d971ab18945fcdc8100678ac27267ea2efd117d8d596d0416903f" },
                { "rm", "97f1a109318049823ee6d52876877a325e5b0dda01ed342fdbcbc7f2eb91d16e5f0aad2bc0b7b30cec23b020034e6e9116c2dba05ca623f72f15675e654909e3" },
                { "ro", "643fd38b39a7a183b22a47114d497c6074263908c017b9b02c36434980af6707dbb7bcd2d5659bc5a6c48315e8d1ef665f29239256596f08a4527a612fbaf3f2" },
                { "ru", "fdaa229ed34da1fbd7548c9d7c61dfd8f1ac212db0a41af2eb2867a4f19a836d6959f506042644b62755cd4275241ca704cbef6af7613f4e3d6fc695c8ff14a9" },
                { "sat", "186f57598d2370991acd8d806b410f52aae0c05002309bdf41be7103427344e725b737eef6e7a6f8277266a95015ececc279811536f8757824c4e574b9574f1c" },
                { "sc", "df601e4bf66019f4e139adbe6a3615fa09caa89b69792d83beb40713acd13dbba9df69e1e44596d3ebb34a237d7c995c1c4491362b96b78fae076da020afd8e5" },
                { "sco", "a81ecff4c11ebd29867821dc3a97fb72953ff5a87be75e19d982edc6b89237216b6d8dff2fb49f158649f47ffdd02451aebff892dfc8b823277af8ba107c8cc2" },
                { "si", "4c18186716b109752dfcea99370198cffb5473aecc132f16440fa46f562fe260d3caa95b23c1832acdeacf6119132a4dda9ff8848cc0fdfb56959684b22aa57b" },
                { "sk", "bfa45a967c99a79e38f062752c64481b788b354b76666930dc6815b586f2a615ec1c317c0143003404a037a142e4927051bd192dfc8d1e93119c543e7efdafe1" },
                { "skr", "0341b21fd90835cead9adc56031e1db54249ac905200e59277253df139c95bf7e96cfd4c6d3e6742fcf7952246375f3c013c3714a2c6b224eca5a85d07b6da7b" },
                { "sl", "ec6d08c54f392812288873f8cfd736fa25e206bdf1abc9db478f4ba56fcfc688136b6c1dd620588ae4d6550036bd2587432bfa7885396a1ff28d6af25b18204c" },
                { "son", "f416313e80265213ad4ec2e1c080da53ae0a50dcbbf3a07ec46593fd6fa0ba581d6396655c4989bc0432427efdaa80217f4826919c4eb60fc0a008186372b332" },
                { "sq", "552c92b51c342b70e3570536bf0710b25dd9df76899d8611307ddaa1fee0d67fa738e34341aa6c83784835d2fe78c536786b4f04ce49b7d68c6d1456cc86e742" },
                { "sr", "d90aa93c1a1e76b9e79acbd6fa124622eef7074f4356c58995c7bac90f3eae92526c1bf14ef07703b5bbb0c05594a1f80fcea581feae534d82ff9a79a44013cb" },
                { "sv-SE", "5db1d0a28b1059131fc241499fe9c3fdf8d40c13d29326908918773c721f932cef9fadbcf47d1216c5576f28bba8578d39609c2e1f380112a3320fc1413f62a5" },
                { "szl", "8954ffcb97039daddd4d961feb7be0061cd639d7a43b5c8c966c3da469711bd46c07f20c0eb8f53872e565847b8f237f6d3329b28122b447f963a062aae4a19a" },
                { "ta", "3da141f519cf79b28a7cd3367335ce134b23b949e7647a40f8337fa1acdfe02e5b8a43dff022ae93c9ebfb5fc7bfcb36d15a673cdcfc8a8d7e97270f7624eade" },
                { "te", "2df1b3af9ee38cd573e760b88919885b14c25fa8107c965bb6af896315a8c9e1ac0c222e9b6b78524d338e525624bd7057e55ad872a57b0e51115f79dc73a677" },
                { "tg", "c79c460f69e66f355b21535cefea3ece418228cd9dd59fc741aa2776c5bbe6f08d047cef7250aad6f8d7bf8433e3d701f0079f771105b323934061b40d268bcb" },
                { "th", "8ae53fe646c743c76c91981f49df16ecf8727ae8fae67bb6de7d78fab55b65b17abe70473cc0142edacf36e9b7d62b05c26de4a95255e412bc278d77095b4b3f" },
                { "tl", "735cbd4e5fd2dd65b9c80e9eb40a8e2cf1c5a7d8f1424640b5f66d4058f7044d48880dc0d7cd99d38c0d41583e0cad55af0ce250cc5894e69f44d79f1c4f3f13" },
                { "tr", "8c412c9a49af703e72c6881a5852c25000ad8339f88c8928d204d165b0e582ffaf922e12cf3b745892138ee72185f4f9b2fdc8ef946c914f216dfc88d4e6fca5" },
                { "trs", "8a2183728f619444c7f3b427c9c6439e4cb0d8c3d5c55be96476ba6d51229180fc7ac215ef91bb2fc5b73e8e161db747ae4aaff3772d290bf306e9aaf0396eef" },
                { "uk", "7851e00b233eaeac6daa0a9ca24e9292aeacc92b440bcc070794f2e7b97968e8c9d502fe4c3f1d7ff43f94ae2eb4b33ce4f3a77c1d1067257d39671ac477608e" },
                { "ur", "2e2a20a5432936967d482379c4725cdce83058c8a87f8091f113c92850f5538226c4c4fb087e27c5419ce9d1418f68eb55ce216c623a472f526efd924ea9f030" },
                { "uz", "988accce6273bb89368524e5dcfd721681e081a84b63f7b5c1f00bb7754a945850655b5aa8c80de4d3e7f033a7ff261298bda5a32e18ca2c01c2875a62e64238" },
                { "vi", "8c634ab814fdee31eb01df578ffd106a3f617da7544fb9cf0a4705b2e4213335ef32d6da0073e74d26e123582593a2475dbcc1389aa6afc5b51de3f2260d0c9c" },
                { "xh", "ae08a1b60ed8a4c0e041c2b9161fa8e741b1a35fa6b38b4e7e59141780e2c71591a70475adb81e384b69bd8163ab8bd7107229247f5abbb7e309095ab0bdd0eb" },
                { "zh-CN", "7527321c46d0e7954bbcbb0208ce786af57c1fda6b26b1cc4c691e5484a344d3a212481c71675f21c3b0ecd1b48f6b0cfa87a75e588a4c8611154e2179ded45e" },
                { "zh-TW", "ae612c4eeff9bd4858177b4e2db76830234fb08f69670dd3100d22145e57408b06bae4985c4fd6e316b105a9686d78149de2fc2c56f2dd97ebcd313707aa5ed4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dccc9fa80a896f6f83a3123c68b6684cd773eb6cf8dca38abba05c760a408da4e853d9cad3449c4468a8f92ca51e9db1f664b627eb4129d49a917b96ac49b691" },
                { "af", "442bda19bd4000ae60391124ece06cee844ecfa67f7334e0ab097e8f0ac640309ec3ac53293b5a98a5f97e7177df21dc2d437f671301557df1ecbae18f93cdc9" },
                { "an", "1f973bc5ae48532f219a2eec8da4945100bbd6beb80d1609902e4a87176a4df4ed77acf13558f0d346bec363ee72c81aabb49ba2c72d9468584189cbf267cc97" },
                { "ar", "a90246ee218e53e42a2063de9d6541863f636eddb1e79697ff096d9cb3b12e90556a1357ca056cb3235b2e1de491073358d4385d770cf026e70ac4c08a74bb24" },
                { "ast", "09c45e1a5bf97d0ea52296f015d39f7d1b23f50e495d115b91bcf98128a24ff8a54b63dce80695a026b478434d875eb264965a77179ffd72a55bd40c9355b3d8" },
                { "az", "b9d138a6594fb1cbce737b55e23881bf538b3a303acf5210cb414998f6571fc45de6660c00af5930838ff6a2f6f426c6d64050b0f23651d7fad4acee9e92128a" },
                { "be", "e3cbf07c7e573c4fa4c074c3e34c5eeba6ad65a92fde7fed901080d1247de3eda2e082ce6657201eaa9731e31767290afb0995bc769cdac0f306695dbe1bdb85" },
                { "bg", "d1f8d255fa39af85800d9ab787824e75d33daab22181b6888808cbcc803eaa12665699db15d72b475238c36b5937d588d1ade555713a06a4a3ee937ca145550e" },
                { "bn", "aeaa2eda3c28930423c7c4ed6447cad92f1a1b0f2894ef730e1c17869b8e2368811450241c2b0558e748be3a55191acc800312d95939c3eb0f181d7b1fd2cfbc" },
                { "br", "2ee491971f922775cc2cdc91940a602641933b9df145d3a5cf487df21a30c72de3152b697bbccc0e8479cfc7be515799d9061dc628d812a9a2d6c1a346448382" },
                { "bs", "274fd3b7b492a085a9fdb934927307d8186ebf3a23ac458456e8d7c706f488d80ce277797a70ce81cf1c682b129c4432f36d3b6be9ec879e0f25c0c2a4a5eda7" },
                { "ca", "a39a1a4d077b5f6daea534ef77407f6d79287b96babf2e188670f30d859584f9c0b1fc682ff7c1a269eceebf864af560b8835984e3a163dfffe552839366bd2d" },
                { "cak", "ea9b96be903bb29bf5c4c95a0d2bb8716a7798486e11e3228ca17df118ee4b1e6ca0ff6a8ce64a81768866fdb979d9b1d763e4d977c048039b0434ac21c8fc10" },
                { "cs", "d236e7c6951822877664452e4ccc5bcbb626fa20daa8b9093dcd243ed6480a1dbc5d6dc5432fdf1b308b207b4aa05308737a11edaef430e55830a856027faf6c" },
                { "cy", "40d4ed4a7c8eb4c89931e1dbdafc7fe54cfc2455e3de2b0d7d5cbb7ae679f6cde137a2470bed9a2594f15e9f0fb7affa97d7ebddaa4cc6e0e8feb58937008f05" },
                { "da", "a1a48e5677c5dde891416c083ad38a01b375ad4911bab702a9937494eda693cfa021bfe9e5a597e7d261728d79e38ce51431a8a54787953b8d52b9f58fc5d217" },
                { "de", "cc9b329805018df9fe41a22cfb681a0a739c9202df8d7bf8f339c07d569110183227365ab24c34a4b9630a8e2ea6ff8684abdf702d10a45714440ce4a13346e1" },
                { "dsb", "31ede6f5b23f085c6713c4fb6ca12ac41cf4b7da8214e14f18b0e16a791255a4e430024addb9e2e888c61b9bf98fb6dbd87fb9233d89284fa1e183bd860ef31b" },
                { "el", "3b94c0e97dfaf862a0c5c3f929d8a6d40628e32929bcbd9691fc277f9c146163a80ccbd08dcb0d105ab3394cc0985c47eb73a5125e5af83aa36b7c9ab2a16b85" },
                { "en-CA", "7fc3d33d296ca7e4bfb718302237354fa19a0890d5e8133dadbce6ef11a241c939e0c3a8cec31b25507310e59767f993c23990ba4b4d8cf4c92849f37fabb0e6" },
                { "en-GB", "9390817a26abd30d7085b83fc735c71e33e2ca6f0a8a860a0b17bc4c13d5d0fdb1c2c42239ffb796a935605c07bf8cabde7da7e844f47a3d9f16cf8916c71390" },
                { "en-US", "b7801d2bf94735e8212e41ce7576d9fbbb8a1a585c2129d9bfc563e5c0ec849e01137db7ad2c1f889c1843fa433f74b962b10b46d2b76fa15203575d3548ffb0" },
                { "eo", "ea4c52570358403b910ca83228d4c10c137d185d7cbf98acff1a7f906694a26faa4275e2eae29100f9fc49b8d7d68a54f75c8dae052e27c85c61f3845c7bb18d" },
                { "es-AR", "43e4de0cb8e8d71a8582844fefee8050e1915c9a192070141c1f0799e94cfe14475325cff464101b4c9ed59579dbd547e3dbcc2f6fb0891d355b553573bd39af" },
                { "es-CL", "92465a6328ae4a78bbf4ef1eb451fcdab33ea512e6227fd9d4443a874e33d6a2d1ad1ab2b482ce267541f5dae99d53eced3fce73a4463d4a55eadb2a30e11560" },
                { "es-ES", "dc1bec3840d809bef84dd63dbecc991b8d0b277ee0efafccd8be709e20b343448eb1ba5026b47ac5485152d85e290de2eec83084fa4b0d58234f6dd933c80016" },
                { "es-MX", "9d7c59f99a8d5999c35ffae349fb59ac2d3d3901f3cd62be8efe0c9c8955358da994948e0971f56791e983a650653c8527e852e9d6edb285c4d5eaf27ee30db8" },
                { "et", "da0734e8890644faa367dc9e1c5cb8992c14984b43981d4906007afc3634101c38145f6a934c21ad1317e9a0f0e5894dc28b46b6d553fda37ca6d100b909d6b8" },
                { "eu", "1bfd3c63f1661943113a2888f78123b4c6c3cd0744953de28af846364fdac36049882dc157d8c8891796365d340db5d48205dac91c6f678b214ddae49a5d2e22" },
                { "fa", "bafdf2ce3ccdd135c4309b548587fe5b1fc40475f4f3622d985a369d5eb89bbeafceb7fc2d4a30671b9fe62ec0c491528e74bed2cb7a81c33f6279f14561d7ce" },
                { "ff", "66c30f90e98c2b37dba8ee3d2f8f2d5673c5eec4eb176e94d14003d0ffa3bbcb61765a0a17869c779d6caaf4cef7d5762bff3921c4d3c59eac84066df228b9bc" },
                { "fi", "e9100f61fc8fc722c4e3a1db1d3a61aa3815ad7b4ef9ce3496be7b93014c8ebfe1fe8769fba5a2084c56ef56eabc54ea03a634abdb8800faa2d234057849e808" },
                { "fr", "5163e8bfde3a2d6aa2c61ee462cc03042b7c10fb65f521f24136843469b74f40652641ea95f1573951cee9289a17099e640d36a401217d062022d34ba2f3eb2e" },
                { "fur", "2f5d84163b8b6e7eba2ecd9e7a234a0fc96842ee65565ad275f7545cd15af0af7d0396de5233b3a3f32236a2544491d0af80d695f55ef6589a50b8c93d9f0a8a" },
                { "fy-NL", "637646d32b0ba5776c59d3e3af8cba48e5340d7a7600104e78f73c1886cb51d61dd9b781ad294fe43a216864eb86794a0ca1046f94e34c67cd95f39d23c00426" },
                { "ga-IE", "231b2d14c782cfa736922d557ab9c71f77f0f6ab55b62d6bae539eef1c29e3c3f9a06e8b714cb204b7ec2617a004a4e06e04b72665b23ccbde554581d1350973" },
                { "gd", "220ca34719565102b181785a9694f0413f4d76fb4428c11ccd97dff751942e66e122171a4ddc2ac8673826a6d1be134d878556c3fa6d71b834714d39385a01a4" },
                { "gl", "eb0d88b8a832471d3a79f0acaa3643f41ae7f66458dc35cac9414bc754a4b71b217721c2726ce770ee1f286f03ee6d4697b3a963868ea692f3a3b45a94769d72" },
                { "gn", "d433fcbc4f9d47ebf76b6d468304b2b8842dcb32d63817eccec3b9470ac1f09138d6bb61706779396fff45436380671f72580ba21db58b84b8c4ed55f5a69288" },
                { "gu-IN", "e9bc7450dfc5f7f5878d5b7ad838eb595726defac39c0432825c3b52aa8112fc8cce9836903cad5a428fd7bc9aa82f9a903e16b82ee873114640126bcc136a05" },
                { "he", "9115209c04c1e7e2163d53b34705f069881a151a661073b91a7eeadeba949b206fffeecfaf3c8de8d7eac0c6df09d68e50f9acd0ca86f9a7b25e74752d33bac6" },
                { "hi-IN", "1bacf8f59474c1588f60710cefde4a9dd2656251a33573a49b49248b1973cab0b5a4b0cf5ca976d28753b85d322451370549a18ca53b3b4f937f603d17116b48" },
                { "hr", "df88b6911b43df6102156e4dd75d5b4e7cafd73a9ab724b3ad79a101e596f41b71ea9afa156b47405bd0c821ab22d3b13acedb6330bfc6c8f5cd8adfebc757b5" },
                { "hsb", "d4435a13c17ce4788c40dbf7e48cfc85060109b3f45fdea486796bbd5d9904dbccc4bec8e091511a7b2cfbbfcb14d829b62a1f66696b04635d695917479c7877" },
                { "hu", "6ad80fa2272c40fd5b82632c31756dbaed237d13a264cad769caced5a840f3d897ae344b029c79e09bca5c0716fd4d11a54afbe543fa6e54bd9c13991eb95574" },
                { "hy-AM", "0d01a3c533a820ed271f88ad59b2958da708e1fdbd1ab612cc6116c9d6fff156b5be0425f0091424e9f4c438d2a29672d050f85292f6b576146a8c68fec6fc3d" },
                { "ia", "e474dfee91701fe9ea1c278804e84836cadfb61e7f8f67e81de08c5e485ad00586474a1c6af3ce597e28058054373ca9b143fd3c5777df5f11a80174d285f83c" },
                { "id", "ac4d46082591477ecae118a316f87b558e9eed16db21bcf067199df617f84fc9c6b00cb9ea5b93212c5a61a06d56f1e3d216967b5048b8632c95211160cdb5d6" },
                { "is", "40dd4d595f1ccc5ef7aaac9795a77dd5d1925ce73ab3194c8cbe127c2bf8ff48b6f5ef38414cd0b150ee0d3bf3f996ceaa948eb0e3800c5c3d84d02bee855ecc" },
                { "it", "34e29e82a8e4223449235bc99c05e5235878945cef9c657b5215781270d13e435386b1493b39e1fa08a0036ee8dd3be1b8d168c9d13a50e36f1bbf1f17aff867" },
                { "ja", "294e1485e8cccff77aea0a92b042b94a07cab053399115577655176a6b02b1ff1afdbd55683b258dd7c2c6d4eab68b5cde4eb975d565570717cb70870a05d999" },
                { "ka", "632a8b4d6108452b96e1d777c6d34f0057c951b3faa1f6ae5ffc19fed7833dad48274628c88c48a6f7bb57ad89ff83ea4f7696201d0f738040d901131a85edb7" },
                { "kab", "186820b1bf3f8c536637e5b977e151310e95f78dcab8d39a796d11d2264c21e25f2fe0f6473174fa66743240529799e64f265d87d0cee1ce1d2731605eca3f91" },
                { "kk", "ad2c93d74bd445b8446aa4618e3a8d4d2972706436f2e7f06663ac1ba4ec99e345faf9448436f6cae1256a975ce323b780f3d6650946e9ef0c3949e255ae98c5" },
                { "km", "5db3648d910aabfdcd4dc67e14a0234d6e7a11eb60a896513529702c9d85669dbe7bea53c5bd1d380bcb9080d71721213a3eb6ccbb34d582de4d731e8241b5f9" },
                { "kn", "7a6d6595fe1a881c33e777a1b2097b52ac4851a01923f202d67296e8d5689aa664995c9fb24baf7883e9624d8c3771e9188d4252b623dea0b9fbe71d60a7a45f" },
                { "ko", "0bca84eb4618658a414d8400eeec17ddf7346fcfff68fce8687b0b2c026bb0659f94924bfceba34faa081c39c4917bd20e022e0655ef8e453640dbdbcefc4a2d" },
                { "lij", "b3a44e3996d86c8ae51b6caa3bb1cbd83c8d5fd063719584fa67deb644d91bcdd4d207f960441d4a19774a2fd2aad098b91ec96dd7e329c2888882a2ef761991" },
                { "lt", "a25389fac90bf6347c871f4b0f667ab19eb84ba73e0c3f7c1489862f8c78a0e29e418afca00a884c4f0a59f0b6c0f68bcbef8934410184f542bba65eebd2ec08" },
                { "lv", "23a4aea1c1e459b8e2b0eefc345400835641e7ea236744f7168d548857d96b1ff0ad2e787aafb942bbea466c9546edcc3f0d69675b8bc2101d26400580b29f1c" },
                { "mk", "0f43a3c23f14061f4fc5cfe7faa6da4e113b382c65b6243f46867e3d249c8de95cd863faf168ddfea8ee13526e1edb9ff870c18ee463c1e60c11130c3274cb31" },
                { "mr", "b8a070632b8b96a51d99d23e436a28f3f1150b01d5a69ce77a26fd6b5491af614c5894e57056cccdc30ec2315a0e0c30fe5b26f57c43a556d20a0bc7c07630be" },
                { "ms", "2285c9cfe479fe559a42b907489270a7cd8d6ba975654a710869cba991a423e554e1b2087f59389b4a4a60291016d886ca85e98ece3f5e6d5d7182c3b70c8aea" },
                { "my", "3e86b41763a9d9e2a8eb9b6ca42c05934fc6030afd1d151e5501efada20f0b0b793949e3eefbc6f9efb8d3c420195f6e2223947be2e53e7ecd15c6ea2f2cb782" },
                { "nb-NO", "cbaeeccf0993863f7e879416d3c4f507134b606d79abe292ea408e1312eee95d482dc98bdcc9bd607f4a32f1ac4d0e80b80be31ca397a52077144944c9662162" },
                { "ne-NP", "ec1d59e4590adb5c252e1f32d50fe0ce3e4be700c381377dd5c92bee0b3e882720f434d5d11bc796a85119506babca1ffab3ffac480f6ba5117caf5417608ff7" },
                { "nl", "aac7fa3c8e4a60a1e05614f6d7aa5a612a7bfba5baac7a5678808a510f1797f70184cadaea9775e79e0ae338d3731a65478bf94bf389f4b8136302590e0df655" },
                { "nn-NO", "ef0f6cadc826584ca2f83085bffa3d2c77ba57361d46baa28a402b72c856a64be71bbc7f8c650036004c0294ae5eb72e175bf55a0da286ffcb49285e8b793f32" },
                { "oc", "18d5e83d257f8ce5568d5d37f3068766ccea5d3faff44e67394487e1218839690822717d08304f8eff6c940e44fa52b4cf96dc718d1942e2bbbb515c846f824c" },
                { "pa-IN", "9483b05a8a754e9d44fdb0cf7aadbd43061ca38f26f5365ac8ae969bfc8c5fbe5361b4fc9975b2059e71abacbc9e2c62a7bfbacd17db9853208205d2e4ec7ee7" },
                { "pl", "652f7f97271ed64d9cd72c660aa629778369d318fc203c5c8d2392ec24e4983f4140c9d0193e144fe6f5299e290bde851c2883de18589225d60349cc3fd6ae6a" },
                { "pt-BR", "367b54cc75c09211452aa4de9785fc6c5bc5cee514fefb869ea0e879ccda7a4120e54381bd57523a9844f1ae3abd6cb0e28140ed670fee7f75d60382babb36e9" },
                { "pt-PT", "a22d7329c53c343703cae8fad88e1b0acda7a5180241b455111e149fadcd741dde78e2e00e068886848ac3b952b74464ca72c0752b3db61ac4e9a02e0e000b16" },
                { "rm", "8dd7462b9f5908bcb03a66f6d983cd94ee32f67b9769bf8b1b8ee7ac143c1bc5962b048ff9fc2c0103c15ff4bec75ae2b0c9da981af3894542b52a8651ffb605" },
                { "ro", "515f19c5f6c96fb4d06295ad94988214613757b472b7aad9847e9fda1f0125c49cd03377cc61c0da120dabfe0c3eb03e89551130827318ff9ead1c9d512ccb9c" },
                { "ru", "569741f81021548d8b24d3b3707e879821d6ed31fc89a70a013529615a4a3d0806ce62252693ca2ff861667eccf71fc6cfb536636b2a5d1247f350364787b800" },
                { "sat", "f2c72131762fe68ad5c414a91311723433fa3c5a9a86a33a45fc02da1746bb4ec29c7da9b18f7820ce2971279199ee02cc4ab8701319e54bf06d614b2e1580fb" },
                { "sc", "7e778840b525f8cc745d423a4d7f3e4eb5da1756c91c98ca76867103e2becd5df162c6af00ca63bd561419e2c474ead2d29d4d93d795a19282c70dbb295e79bd" },
                { "sco", "7c3e971b38b9a66fd9ac334e343dd29ab756c381e5d7fb6e871c230235d5139d9373978445374610d1f8e74219fe9959025a35de3a8969ee9908531b0b858e73" },
                { "si", "a943c1ee25ee6f067d5b602cd8db918dba203f6f8a02537d8863978540edd2ef97e18d16c81b83ab49742408baf948d8d85bef734918e6e3ce4458895f80e80b" },
                { "sk", "41643b2c70c364be42dcafcec2d0aa1c65f80f7bd9519b97825f950f36b05f3c9228ce6ebd6087968037835c83a3e321bc2c881a8312d00a4d56d29928a4a3af" },
                { "skr", "44c4f324edf2537184e9af43169b35ba6383fc9e59cec8432c1211a8c533bc678d27243e267f3ff8aefa0a08f4c989593d318060ba57d49c3d254660df13bee7" },
                { "sl", "dbc3dc06630abb13e889b501d0f6d01e4aa6eefad8d6a5da862b8bcb0cbef0105fc075b70d2665d58e720bbb601adf4a31123e5751b801e12c77a78f50011c03" },
                { "son", "cfdcc98f333d169bce0037a9c0857889ead42301df6e0bfe69f8d615a51aeb5b45305957b3f27343d2134c3ef83387bc3d8a9a6be8ac118a32e06cd056678e88" },
                { "sq", "5102f37b2079cda3ad114f8b32d810c902baa88da762f960835129d64d3ad3b918eab4087e06b328ae833e710c86de52d13bc793f1e88c4be7d55b44d69cf522" },
                { "sr", "85f7ff98e62f253dc0475ee0caa562d11d52a042f7c6b99221c5ac3ca0f0cbde2aa831a7abdd6d1bff4d6e64a33610d0da0297cddf29f8d31593e1cb5ac1d2a6" },
                { "sv-SE", "e3c3e33fa468d83be55f72a5785700c4ff1cf2dbea40501d3e8bce4085ad08f4a1473f34379660d7310e1a55d3e6bb1a15959951f05e678a0a13693d04b47d0d" },
                { "szl", "ad8b2a73e9d0f55e77067275729112d3b1f1ebaec078177aff52edb3adaf703e551aa1e5f9b5bda9b1792925d845bbd1f763a3d95e07b2a6c6f96cd9dbf029e8" },
                { "ta", "96a3508aa0b5a061304efbf90b3e2db08f395b2ee0e0717fa0c874eced204ba10d6bb9dcf915e6e81e850950105b8d902888ab67363df72d06383747b3d6aeec" },
                { "te", "3d4bfc16c7c19c8ae5892fb394208dd1ce0fbc07e2216a6ff9fd2ec5d5dc684d0bcf87c459baeaa069ee27c0b9bba30e1316fd6b41161d95779c4013a23dfaf7" },
                { "tg", "344206a0ad92970f94dd5af436fb8a7b97b6d0a44b620ecbf5d865f20a07b4da5401e8fc5da4b18bb91f5969d2ee0a5261744ed51b6fdffabb20089859dba493" },
                { "th", "3b4d6a31d0fa2d8241d6812558bac7459897d30c97cdc231138f2d08ed28b860a297a421cd6aa17a943dfc6617a583da7bdff581e4caef8e2f996a65fab13ef8" },
                { "tl", "2795c85936db08ee146024786427197ca14e9619d55fff19d112b45671c9c7b96b2834d4093ff4d8f0f977cd4cf6bdc7056ef623a7f5ea1a3aa95f31af16a33a" },
                { "tr", "3d8bd9519628726a43bf09c52f60fdb6c05818864359bba693e4684c1a0628b7b4baf595a427fdec36e0640e803c8bcfdf42d45cf1872b4ac72b9f20c6aea2af" },
                { "trs", "0f7ee2a860533df4e1eddaf54e88f16ec8948b51697d0a72661a39f962a492833a2df303389dc2d4e0cfeb663b7ef54b01d2ea0d50ca3cc67a5d129c225c75f9" },
                { "uk", "24717b3531be6978b59913e33996090a628e066373514716881ef853d6bd7c5de1d9039976b1abedcfbce0819b0df6020b84b536d80064d00803ff5faffb7c11" },
                { "ur", "ed5b5b869232aec0d889c2df22d1cb549328dd27b4c5eee5bbe88f21fa1c7b90a4390b1d25b3932e21d874f986b512a57b5695d6d4b708dacca858f3915ff1b3" },
                { "uz", "3c00be865c3d9a96ee67ae924356658797b3ea133c25c1e66adf6005f0c9f8a00cd5da35a02ec203400ff3de99b8ebc33e90a9f8a129d87b9552d1f9d842b7eb" },
                { "vi", "5d3682dbb774c5b9ebedc67aeeadb070d9e07feb1ca38a327c19512d34d0088c25776c3b98576e11f5e9aae031b9875bc7a5f9313c21e4bed6b424e5966b5399" },
                { "xh", "5dec3aacadcf71b83badef972e1b3f2f16a1588acf2a8aff0e3f631ca490ba0e444f56ef13a7e1548bc3a0c51f0f7b9c46a7e0e40743c2141f240aaa3f70eb8b" },
                { "zh-CN", "09aa2d9ad6236620f8d5e92f509527e9a8e2aea9144126b15c18221a8759f743b27f63b582cb9847f2d5efa21d5018b8166445c583332af4aef9edd950959282" },
                { "zh-TW", "fcfa4ab4c19c5d1835e4a4fc79fd19b6c3c086095bd91984af78beb35c5df8e35a7c9c41d2dff58ad47746d4e1935624ac8318416496411a761ff43fd3e56f0d" }
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
