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
        private const string currentVersion = "141.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "efaa7b245d388df91492b82ff0deaad2c14b3b2b6b6063020f677fc1bd56ea1d42be6c946dc8ebb6cfc16646dc7b4c2b1af82d13544f413e7f0ed1e803e8c90c" },
                { "af", "9a41ed0b750e40b2ad69a8f4f60b14749e5be5f79ea753daed37702e7c602c581df9279780235c8bebce753b4d16d4d7957048e42002595fe289f6534fd0cb60" },
                { "an", "b2cb334856f158548dcaafc96dfd4379c7e03d598855ce0d786663e9fc6dbfb7244d070d54142bc71bec0e7fab194a5b9a2609382a9018445fe88de6e9362eeb" },
                { "ar", "2f84df1027327cce7fcc09bf474fe1ec6fe2b124a08a9859821da5cf333fde2641db2e4c7309c22d733985c4764af381e8d450c199fcf65475878d5562ada2ac" },
                { "ast", "d1b772e43989954523fab6862f0b7391907902a77fc134bb6095d96311696575eff780cd792839867bdb6020994e732f65f9ce325321c225936ab6b6d9a07541" },
                { "az", "fc976491a4b397ed83d9516115049e70044fa631726303a85e478f4bfc1bac89f5f2b143ea7bf8e3a491601e38683159ccfa1917fed8534579aa0464a3c10dcf" },
                { "be", "6ff6d6a58ec1492f3b93560c90ea804cbf7b2610e0c13241da3969090830b965bbf1f9f38961b07e38a817247fffd9fd98bfdf6ec01ff4b1807c0ad186ce7c49" },
                { "bg", "061d53bc305b9dd640df2aae1d41e822c09aa6ca582919f493e039b6480ed183debcedc46754830419f800751f0f18ea6ea8e35b816f4571332651350b5aade1" },
                { "bn", "e398e8998d7eee4a2a359af7b8422cc9ce3990dbec2b89838bebbdd764deb2239434c430904199708794eaf91041efc5d2750ef09181ee62f5648212187da614" },
                { "br", "a41962dc5ecf93d8413f0b33c9dbb060e92105a525a76072e52f69f5b7abe629e57adcc78ffe1385927a2cb42555b95a4d9777b5c26e3cb7d79f0c3affab715e" },
                { "bs", "fda2c1721dfe744219a87816deb81566fcc6d47cd974caaacbe56a66f865a200af5503f8ec38717bb0cfaae4eaae112106ba078dd7d1936d63c1ac17561e6e96" },
                { "ca", "c297fa1875a8cf08e43231d626264918d61b422b3616a17476cfbbc81773cd90d9b90e5ad5ef91a48e91feddff95c1f5703728dc2b89d20d5df800d107600c5a" },
                { "cak", "a45d456a5ab73ae9f252c5716a1622aa916d6eacb33fcb3ce1c1b29e6ebf9a8b69ec9ff20210fb7df3f203a1129ddcb9ca29dd3a94c8d1f8f81f50c358adfad6" },
                { "cs", "3c0a61b924b1c2b798c4d12cb2fb8e5a34cfbc7cdb1d507f3901934483c96e8d8359d98f1ec0f4a6fcc4da6cdf10caf53a3074d7a0aa3533342fb0de4b53e975" },
                { "cy", "1611d4090c5b5ba512bf79739d4b1f3c2deb0d7e8e7e2a0e2bf88661c17553870cbb0df6f93d930f15e884b5a9bcee7e3203714484808e042be5a4f0dae01d6c" },
                { "da", "e73c7d19f88e6b78e87a2a63bbc46d3ec16150012b9bf7837f06c054bb4d26c4d31d389c32abb355196dac7f35f83ab210083a66d08161839039581d4a071a8b" },
                { "de", "53cb523982903ce08c2d58e3dd65e3f04e3c0bb6db929ece34d6cac7e5c2568d0acd1216c81ff975bb5cf8576f7228ca9f896ca6aa923e8a829372c103f73b4f" },
                { "dsb", "4310bec05068bbe9d5915f07417c7bc7391935893b62123898f0c0f42f2dfdea29670f7eb9f213d54a2aa967107141dcc7a375bd7b3ed4dcb046b30cbd16ad64" },
                { "el", "a94a02a407ea73d3cf4bc579f250d4c358379c4d5b65174e32587957ab6a8ffb35811fb8fdd7ac6d7a0f19ecac79af4c142ca5df100de315132be31d4df3ef0a" },
                { "en-CA", "ad9e769d527b0bed448f5b6cf9df8c7f4f48757dc1302b2dce92a611c3334546a96f914fdcc4c54c07de3c2b62292a66a8f4f994a1c38bc0166490b5e0910370" },
                { "en-GB", "c957bb67cf0f1409513af39bf3999801b8f3c9b4283747e5cabc70275bcd2babf0b325c03dc969e286c7194cb30079a9d4c228c9073fb97321a947fd53c4bc15" },
                { "en-US", "0e255d39bcf142236f1b089e6e6598e0e356282fedec12679152ef1516f6458a9cfaa2e3b2dd1769ea000c5c39500c05d69b75dcea2ed0a651ce225347515bbc" },
                { "eo", "d335a592f6739f21fb2a20e170d283beec4480ef2875deb800e57b83f34761b5952562ce2ac1a4b6983f730f4640df0dea69d666ad8da911fd380423cb34f0c7" },
                { "es-AR", "2fc364506814044da74bc52f2f9a61f6ffb85f129070b6958c4daab5e626b490cc7481cded72408ddae81cc7db5e0ef342e67dd8454f6e6d1fc09cc2a8d0a930" },
                { "es-CL", "8c76e855c5236364caed141dcc28b153ab35d82211936e1046c48731b0a70abddeea5f64e59e2e0a3526e12381d20083ee66ad796469671514eb9ea0f66dfa0d" },
                { "es-ES", "b40b9acfacafb43ef5bba8030871e4a2b8d1db6a30ca8c9d441fb796294482f6e41c7d846f12e7e56af45ed06f6b4c090152693bee28791e420a1daf1f7e4994" },
                { "es-MX", "7cbf0b1069f895a1a057e85f899914f88981ca4b25f8c9b07db57720b7008e76768477cbba28a45dcce4d59950127d0d4ff927dc980117efa0c3bff0e0040a09" },
                { "et", "09c6705a2ac63e6b1cb49446bb2681e3a73f6380746764b743f32d77f00f3d78db0598ef224fc2d9663adca3c88a0917f76bc9ae3ae530d8421acb3615b1126b" },
                { "eu", "45a5e7e019143baad2101d9171266dc39982736231a5aea57170d6f3e04b1ef76a9f75c5645f3221a62cf7c9a4e5a98af6982f9fa630da648d1d5b5815ebccf3" },
                { "fa", "4a2ecc445579164ad2882c4b6bc73202c9e8f0f75fb0c1e95974cb5f0f66139a2761e9c4ef6182d16f82a75586ce1284e409cd919f0c4be8ba044d4449666a28" },
                { "ff", "d7195906576df4badd2c2798c3c0aa21689502bd7cbfbc358f7db45a039068265d09cba57408eab7b2b3b35541fde980d076b894e54da1033caa2c8cf9f5180f" },
                { "fi", "9e50f671569840b41248c919920f015c110594b4711e7d68cbe7e370e4f28be8290327813eb57f2d65d0380d7ce2c468cf1058ab8a2a7d099eaf544b6483b4fb" },
                { "fr", "0ecdf364ccc4f406b476e0a2dd04a1ce339b9afbcdf72a49b1cceebe441c572d28b6f246b0ccb9f14af219cbeeefa0ab8773eb2325b5e9d170ddeb6584a4fddc" },
                { "fur", "c4afc1f156a9650a056d92b1f88134f3e30e24a41a0cabc47c9233cf2bb5835811f28c38b154a77ad88df06b19d8800db564e63c5e85f03c8bf1063c3e7d0cd9" },
                { "fy-NL", "be13347787da995b85cf58fbcc6d9d6e44ea95e22672ac74b37bb7b71bfd037459a187ca4ca0b7587a612a633fc02f09b90c3f5f5a9a2c77e8dc9bb288043e85" },
                { "ga-IE", "2a44b40c036532438dbfe14409d325f3a9197229f17ded1f51b3d610f8539d0e190e8ae022eae876fe092ade3c536475b87364ae0eed9554f46ac7ee5d666b62" },
                { "gd", "e0bbbc93cd115c0d747af199fa6e763d2732d33f68120a2cefa289f18d1668fe870c26a3085bf9c137a286cda5d97adf816766b5bd504ab2037d51e777730866" },
                { "gl", "09652e7950dcb317a105f605a76900dae25276fab2152894ecf47d71b7ac90ab86e5bf7c67bc4062d3584b26437b12c6d887ff86160ffd963c83178bb2a15125" },
                { "gn", "2864cf1ee488a8028dc3f3634a8f37fc144acd816688d094563717b66ac9593735b345e244d936dab495332054b67e8c199dcbc933d448c7f66b4efc118884f8" },
                { "gu-IN", "42f5336272feaf5ef1cf620f09bc3a8145d0c9da2d87a011a38064c1e421bc73a7599bab48e780cab6932147ea0cff2323c812c4ce44fb44bdcdbb2eb945c226" },
                { "he", "9ff53003dec87297a3fab8ff3bd0c0d706a03bb6afdff98a23b2edb5c02aee5140c02b8c8ff2ca1df9db6d6e999f215fb2a3912e3d30db7f4e38c41fd36e773e" },
                { "hi-IN", "818376d740c7a2f2dd27fb8f82535d1b5b0aaec790d4dbbe8c6dbae18ce49868b0c7449a23722db97a1a441e6621401810af5a4b7d4e37a554a8791985223715" },
                { "hr", "e3457e9c9cd07d22afed5e8fe32921939441d9ca3881789dada742beb65e6b7ceb49a93c10a8205945a10454c0bbfc96653d4af6ff9bd4103babe6f756944c7b" },
                { "hsb", "8782db42ee0b12dc00f2908cbc7bd1a615ef9c2519621927d97264c87e48afbd98409bad2072bed169b6ac40896259ff0c6e75030452b6763b0369cd783c2af7" },
                { "hu", "355bf0177e447ec2d423547e835cae3210a381561803ece5f046c8f66c09b9ab34bc64248c7f8cfe88925888e1c09703653c13ddd56ea3fdb5ea354e529eaef1" },
                { "hy-AM", "94fd0a4c088b36e0de1d28d37ef615f6f63b289835fc7c240b7c79de8f3aa113866098e2075db95acbb00ec927bc4539969c894084c347db10ec6a3995302bf7" },
                { "ia", "d56bec7a516967d72992478df082e3eb4426c735f50cd3d11ccfadb20921e0389ba09ca5aa37c2844ddcea5122a3b40c5c81b61f54128dfb21c736d62d10db76" },
                { "id", "51d6d3221ea19ba02828b4f42e0328e30aa100c5be0cf1803e80aba4ecf96cf91e85b04ae182e707aff13765fb2b32d521341e72bff4a0a147745899f92b3f76" },
                { "is", "356dd023fd533b281bdfaac7329890252c0187cbda75ecf51a5ccb77b6e3f96dc0c0fc1b0e97c3176a78476605348747ade3dcf8322e0198afcb33bbbbbb232f" },
                { "it", "acf32552af3c5b80991b3a70a59bb5d87c71687c32bcf8e077fa89c19760499c046ca210291e7f1250e77c6dad5f23102cce729e684502354213e4a484c9f2fb" },
                { "ja", "376ff1f084930e1d45b28ef088096a90c6560ad443bd1f36d73dc58735de68b853f49c8c3f3ebcd3610d63d03c42d26da6c6058ebaf043ef26bdda9d09bf8cb5" },
                { "ka", "bdc0082f4018b6b813f9147413bf4f7f49acd56e3fe3b5b56813650270368bc71235a85a14473280ae57ca070879b4cb1295e8d39e63c21a4c2cfb768d3ff344" },
                { "kab", "42a9ca46729ed76b72842224111ddf5f6ee84aa38bbac87ae12630749859d60aed5e3a0228fda631e80c20d1edc2ecf1685a83d43645dddb0976b615f296c0cd" },
                { "kk", "f399768929e212fe0ff2523071ea1b7218e6136bc93055aa47a5c91e57a0e1a074efe31544656d2ab04edf3471baf844f1fd5ff8363313436fbabdfc0096920b" },
                { "km", "64b97bf94509efe62b7a6067b1ff0bb5bdf8148c5e6c60bbf82716323f86f262265f05ff0a733e014a0bb2e992e0f7a8aa6c350cec0304ae3f58d0f8e24f6f4d" },
                { "kn", "cc8dfc44f8c521df16a6bca22a1b6efc16ea75db5d5a11d286fa6124b23fe8c03b805d3c16b33901496f51e0eb0cc934ae3ba9b91f312b6c03767dceaee7e821" },
                { "ko", "9dcc9ba3c67170aba29c5b8faed887ecc9ed9cfc95392bfe487554d0932543ef6c696dd36eb4bdccc992a6f5d49a4de4ed1ebc9b265dd7d139924644c900f199" },
                { "lij", "a8a071a64822e6266a764e04660dfa50db59d4a55f8751f5493fc887e39377fb9268df5afb0be284e432864b857beda7415d188bf812bc31dec4f7e2fffbf02d" },
                { "lt", "3dfe718ce1a1f13f656d6c1d337cc6388702941a45eb85f1d783dce99b8214b7f07547655b446d695edf9f8f41cfc71f43b282b6e113381829862b53f7661357" },
                { "lv", "549a9b41055c3ccd679381d91cf1d5c7194453e8ccdea1e03b8f598e618a29b193cfe341a6347d56e704096e9f9d475488bd9526fe768a185b4a01c7d6664303" },
                { "mk", "923f85e5e3e643159e331fc4d1535c721c51c4215dcfad390e6022ce1e339223e75e7430654304a68b9cd38ebaee6759687c29e810fa72494fb3cb40e1531095" },
                { "mr", "f409ab0ae10ec4cb6c36249f9bd3f41b6e3e84e9d1583668d645bfb4ef8189ed309f41cac9f344b0f2b75325bcb60958b7b2d9d8278d9f74d0f0af91282c5b67" },
                { "ms", "c538b0861cca745ff8084eb29e4113abd81c4c52aeb3d38b1fc7fe0f956ef84c7c48b38d47a9dd0bcfebd1a6bc73eaf58572c28d3eae744b7d26ffdd215bb6f1" },
                { "my", "13eb48bd74e71142757fb127ad278f8d71fda30e1bdbe3b69429a26b639d9e56c3dbc12722d58a1d56f542dc78fc751e6811d3f97e46f2edf9dacdf6fcb6bd4e" },
                { "nb-NO", "4d75f36e1c819716ab3751d4ae6a5e00caea7579c325d16bd9dbf8056da09791701197e199dced327df81e6cff397856c4e72fb859e7ba0be9270b24902e7b57" },
                { "ne-NP", "8dbd714def2437d68902ce0de523e95d33af651cbc60078116597d56fedc16cc4aad23533163ac8fac9919693da9333b442eb9174e2414734002f442bd731ad6" },
                { "nl", "45c7ffa9176c5296297dbe6feafbdca980c1bc935a587d8a7b549d6e2f306f09c8b6e863e117a2459c8abc4062a2ec54d0620c193d59f7d0d7ef5254f2ce80f8" },
                { "nn-NO", "212e3104eedba06e82836f14144922f8f7854e320984d4e5605752af282fa9ef8424391d8729fa098b49680b9d9a78724e5e8d05a04978b00dc5f1fc3dead37d" },
                { "oc", "26fbeb16619dace4b169f185f962a71a51722194ead16bb89bb7c268652dfd75ff044a0de850440864e33b726e03546456c3d7e52809ba419c1b5610a430db8d" },
                { "pa-IN", "edc10fd95b8723ffc7b086e1d93a0143579edd26154c8592cd13075ffc59468c38617e43dc4ae53fb729ca49bc0d9c6b9ba501f4d4b08d6e8a6512831d7012b1" },
                { "pl", "428fd6f3f2fe0f5eeb6fb3de76392b5dce806a1357c88c1a605d6b3b9646c55f7d6976ed0b924c7c52522aceadd69a5dd021d6bad730267f21dfe549173f8187" },
                { "pt-BR", "2242d31ea05b5d6839dc7b7996a826ac6f3b8077a660cc75310391da5c922f340d14a920d199f798b1b04c1e17e67c5425a42fd9bf89dae19146713c7b770cb5" },
                { "pt-PT", "2c82d307ca217f041b8db2edfb1440d02e89509c610e9b00b623bcf8befe3359c66d18cd1124c6161ebf942c600ea6f929cde0c12ac373008172c35cd13a371b" },
                { "rm", "9b096f6774b4af29c8b5ace9bee0816e7ff3b52c3d6cff52162fbafa74feaf51cac215e0c60dad1b20d42accebe180e02ef3a880689b063a07a7abdc07a23f5e" },
                { "ro", "31738653334de82f172c18129417a1d176634f4766042c37af318fa5812f9ba28f3110076ed06f253d18caac85b96b9ea8bd294f6952d905769ab4906be1e08f" },
                { "ru", "69a1acd9992557fe17583764e4c9342e8c1e16e9b811341610837c3466f5c3152a637075b5b8fce69f3c81bf0690f18de1b201f8898786e70c20e277a6b7021d" },
                { "sat", "57a026c094d4e93c6a72010d422b8f5b62a0cbfa20043ef88e5986953eb9f706267d1b13e4215ec7767789b5d0bc595cbd661efe43583587604d2088302bfd47" },
                { "sc", "17a3dc7af12441c39f603d68ed31f3345d9bc32f76b171196969715b09db79328438a0d6ebbdcab6937056f0a9f03d92bfae7d02d6af2d351e59b44eb647e620" },
                { "sco", "b9c14f22862a08536ec3660cf14d4702322d7197370624e61f3e7d6b1c3a709752a7e435d5ec00ed66e6fec9bbad1ed656b329356257f309ee006be01ef2260f" },
                { "si", "37ffc4d952408b7666ed50f882d969ca0666253a9cf7273a543bff60c737e6a3aa2e60ac291a0f407fd0f2390552b9450d62fcbeb9bbd062f530b0f1880c7139" },
                { "sk", "83118320d8fd95cf216ffb76358e33cd5af8da6bb6ec9671564d68d15ed57891877ae5449ca3226d6e87ed8f28f7332814ab730d0d311e12b7f871d8671e8b96" },
                { "skr", "6b62b1976f268a27e9b71cc4a00907ec66bf93de6c4667fa989d8e58fc00bca9295e3093e455b80c43268e08ab5ac1276d7be8be88e8b23aea64f9fc0ca770d7" },
                { "sl", "42deae69f5abcace52fbd6084d2366d0b53d557360a9f4cca721c2f29f9236c94964a40ac2fd9a90d9fff7ea7a830bded490d843ac67cfa71c26845be46157d9" },
                { "son", "5facaacd880d08444d5eb6bc476106a3a54462130c6e99cb656fcd0e663bf1cd1a323831ae16cc04fad54c7c001a4d58d8aef6f826630fbeb7a61030f9758533" },
                { "sq", "82d2bf4f34a5003e90ed04def155466fc2eeb1c01d1c6d60edf96ff44e42d5caf00501d0adf31ea282f0575e352341216550dd604936e4db771d80fd111d1fe2" },
                { "sr", "29a82e52e281d83efa1ae6e3d26d1630b2136d4fbb08b6a538adbf0c8e469bda69b86310957548f8640570086c5c76ece7ccf9d47c21e10e5647979f6ea81ae0" },
                { "sv-SE", "46d45a0bea3082373ecc50dea1293b81a271be9fcb526db7a9e911598464b2254ba75aa2116e5ab4b188924c94ac32b7cf6fe4b1a97da0bb58d7dca1ca35bd5c" },
                { "szl", "19ca0e54dcf2e0feb65b6c711cfd243a4a7742284c4dbe9ac6872c8d9dc85a4caed372a6b4f9da35ac451dd29032993e64e2345135fef5fb509b57710b68042d" },
                { "ta", "5b24eac69a2810be4e7b4e8a3088e5b1ea7aaae965d2c90f28c335ee97c5431d9fdf89e761e2608d62192a7bd4bee480da418d21c8a4bf2d1c915b026a224173" },
                { "te", "94ea567c4c6cd687f0136910d50667bf32465d10cad1e5f553451de7cf416424b193232c3a1509ab623f84b86f333c6ea462b3bc6b66905c03a3b073721d6a9a" },
                { "tg", "598a287b26a90db9986417aefbeb1994b36d47f31b119d852762352cbac12da8cf5d409e6fdb5b8efa366c73633f4e9cb61f8860ef3686d07913d8fdb79d44f2" },
                { "th", "3e5712196e12e1f55bad13b87ed8aa061e8d4739f2ca7965bf846832fb2b00456cb3600169af05421e5353ada7ccd66ceda509e5062eb899df840fb637c07609" },
                { "tl", "6ceacb42a5e5496b55b5611ff2b8504b552bdd117c61fc97dd14328e680efeacdb30f2bdcf94b1aaac4cc28d86a255ffa2a5ee6527c076a1b057b5a4bc6563ea" },
                { "tr", "6632ac7c298eb7c0bc43176a45e3960ec25819a8183e3337f44f597bb7ec13bf49b78ed8f8d47da8083c12f263725895d206f9c8a4b22c622db544574d86df41" },
                { "trs", "7d4ca119760e41ed926836b410eb71d4ba4f50c073d3c59b947c99026988b68481f176a903ce93a1c5be4f7f669a55b1b7626ce0d4840fa8bc8d959c1242523f" },
                { "uk", "291cc97658af8819e4364943d631646b049aed7f41580879cc650f8abca21afc379f5a33c25364937009e87b8314ba0fdff6f3b9de6f0ddcc08fe0e0ab322977" },
                { "ur", "7a2b70fc2150a863d1c15d74394f2dabcd703c843c98c86d5b3df756b94c84e7326431911b947cb7bb4cd335745533fbecbba7042e89f2882e3a54bdc874b998" },
                { "uz", "6b080fc51ca31b7824daecaf01dc372867fd52ce00e86d03da50df141810008b5a7d2ed79320860162216ab1dc685f66d6b4fd021c58d21a84503bfff5743963" },
                { "vi", "319861967cad838cb24cae3b8c075c82ea6cd1fb243257e5634d5caa4417e8538c46e0234f2e70c5e4e1099810c5a25fb6af55048d3949229619a39cd317c466" },
                { "xh", "022838b86582e42fb6d289c1236e123c66fc73876d3c85e346c26e64073a03a13ca4af282d1f94f35f94e23ab75545cb1a2e103e981c2d4f4ad68ebed754ac41" },
                { "zh-CN", "074568ae99c5413bdd46a369bc1c0a08b05b8a40af0be6f27d436eed35f31a5904ddcfd14f75db1d9b0583ec428fab9a246562027c2499e52e086dd15e476b4e" },
                { "zh-TW", "d950127e76fcb72fd5c6cfe74cd67e526e98822faa2177d6e2eaf0534eca45f9bb6e38d4a3730393cac2657cc8d2f48cbcce20ad8b49e8cedafc0c1c183e50cc" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "885fe5850d0c162aa8602d744dc0fdee33ec738b0eeb95067106d802041b5f52a801b470379132576232eac867e676ee7e7d2debac08682af587c5b17164b51f" },
                { "af", "5298e4e4cff62792039e2381601aa466040831521ec8dcb5a42e745c457743b46688ecf32403caf2ef17cd84b0543af22d79116b92b267002af1a4227058fd91" },
                { "an", "8a94561e7b9824acaae994dacbcd60b489ba14cd041347ed19b702f3ab49029ba6152c373597f6f8f5345553a5a1003351f9af61e9899fa0bf0a43545892dfcb" },
                { "ar", "151debc62000fa64fe3b0d50a19171d7ce83f264c60d93b1edef534064f19c982c3e165d3bd08777709a4d53703987749665ffc3ca98c271b7c9b1f3127bf0eb" },
                { "ast", "5b5c6e17f453bd7adb46156f9c4e84d996e23feab4fd10276c163c99a6e99f8bd5453e2c2cf70d1924cfb7dc478eef293932b96de24b4f8d4fbdf646a7c649e5" },
                { "az", "95cb5fbbf75ef1aa7e017844c255da7232a2a654161878ac710f7c9745aa15bd775e361ca37021b8179d00b179360f136106f447f30f3ce2f06540d45dfdb123" },
                { "be", "b9745fa783295bdd529b89b01d26e34dd179b7c4a76f48488ee5f36162f5ca293995d1bdd9cf020f163b90ed2affa4a13cb2b27128b1808da57317e552bbe73c" },
                { "bg", "c09e80f1f000a33774bbe44cec0fc10d4904406163896ac03113a166d27fd114262bc0f5218795c17ad0416e8ea76e6f3b9754aff3525a9e1ca1896a9021fc26" },
                { "bn", "69f2168363a94ae3cf6e88549c526e6979e0d7d4b77679de0daeb7fedd0013132e3af1731a5a5635bf0940a79b26aa3825633e72bdaa1700637d627c84d61a52" },
                { "br", "b5b92cd376ec9b950257ca1c5db04af58043f33c4fa6e18848664ff4acbaaf3984d5168963d3adf2377865236e81ecbf1bf431488c69a56412db156cba865aed" },
                { "bs", "0e6851c54d23890e2beacb9f727d15de01f7b2069069d07920dd68e7d0de3afa206bfc938c09734743722ef9454a45d94eb878f7067149513f3a3bdffd9ed026" },
                { "ca", "c37ab73757a199e85c90a4b63b10fd76390e91b18b7c9f7ff934306f432f4ea63d93fad38e0e8e12dc697a2328d95328409238b2ef6d839973ddaf837a9c30cf" },
                { "cak", "da119c2d919bfed191bac9a5941ada7b1940343e78f7c25be3b5cf936e9b06dc6105415e8d46ad3b192b66ea23f289b8a6597592a6efb214ef152b14e41f26dd" },
                { "cs", "fc5aeb218478986538116e49d51770a87f2577195783c4f48e5fead2c19c3ad6f0416b3a4c2f1b8bc03153e29ece0ab1cbcfed49679fe2ecbfb8bc1a137ec12d" },
                { "cy", "3e5baf2a204029c6d3223a45234577de256ac67a4669687ad39ce07ca929d881fd7ab6a64e25c94d3c0d6ae54945a7f8e20da3b159dd27bbdbd34df7efdc59d2" },
                { "da", "46f1ad107537f4fee595dfc8a21a2900071a9639a647f962b787a26fc1007cffbbf05d6ee9415f3294cbd2546565a27d9fd7481942312994d0a8d8d4a384da9b" },
                { "de", "1989156a94159682b20fd38b37d5d0d5dd97dd5cc2639317acc2852239abc5cfe020a9339cb83c7b8a098ad1812b72c992d98983a72ee44ae72247dea9fbcd0e" },
                { "dsb", "a5bc2a8adfa7ae6968bf5ebcf9011d8676d0ccb2707359afa3fcdfe9a07735eed7f9822ae55df485c36e12338e6b32aefffa8e1cc4af0d96bd9a389d3eb0d159" },
                { "el", "94f5fec0babf4880a0d1368386ab2697272336d159444c26fd07042265845f6c78773a5eea69530974458b4b1621030cd4716b26cc0cdf6701c56fbb63850984" },
                { "en-CA", "ff9c5a1655e4cb8e74e09c422b4b185974794aee205c909b8197e302b89b06d1f5b32bb36ce5ac04f3d4853112feea7deca9dbd66cda89f1d3bc1ee692e97326" },
                { "en-GB", "7ddad77794249e390b8eb183585457f1fab61a2bc645e56a4bfe7c5516bcb529b101b79e8884619fb573c5005975e0af3562384273386be4278463aebbefc293" },
                { "en-US", "5f9e5fb786b9613a5950af01b7c6241751624efd519b0540025c8a75bfe525e73fdcbe2e8489ad82e8702c772b3ae04c3954aae77fad43b6fb8e34f651053739" },
                { "eo", "e4a18fd99694026e90524844792b0b00c96aa3c9f97249b83f98db2ae25d44f4ebd014505d54336371863a6106b0ea27c785b9800d11620b75fef010b92cf51a" },
                { "es-AR", "da357dc6d2683d4b40359ca239a79f4fcb59cdd03ffc262a5ff40b068b5853be13db47e794fcd9d0463ecbaecf5be467a512724c766f52dd39d009025083d74d" },
                { "es-CL", "380d4315f5f25ac420170681ce75de780caf023c1c7847654e29fad9a81edd14c05aa5895eff27da88409e6d014033383bce1b57a90b0a11c5f9c785286f78e3" },
                { "es-ES", "35094510e67886c448238aac2a96ea18edc47e5cd746e043f342a02905354dda504189cd88e7a5c5ad04a85810efed0333c76926e1e28035a6d2820a98b57b60" },
                { "es-MX", "432ebcb9f384f0e300b345a5d0ee2471e7d762042bbfa574f1332e94b7053a32a5215e7d93c2726df8acc815037c5e50d22d7376a3aafe48ec48669f86029683" },
                { "et", "24ac6860fcb01ef84a8db3646c98db5efe33c85e140048190ee96e955cffaa4ecd8d3b5df4e35ab877cef9c0386eb36176a12205a4fd6f18b65e83cbc8f4a189" },
                { "eu", "e2bac431aad6252ed20fdb000c63afc08f5e5b00c855abfcdacc91df3417085e5884afb9c5dad1196b903a0acd831291d1292fd10c48babd6ecd63daa0af8fff" },
                { "fa", "0b199a03cdd0e87a2225d7d047fe62299b6a514b0e4fc5c5ff714314bb6abcd6f95b35896cfd78d37c8114995e9b50366013424e01b8079f3caed7c23d898cfd" },
                { "ff", "a77abda35157179b6448cc50d63d1735246a5f63819d5f753175ea5fca2ce605769aab88d47c1a3f02d6d9b0371d37bd4a9de3ceb3ee06d5ac2c37bda12ea5f6" },
                { "fi", "f50d2583e62b7491c54ad8c9ac1575220fe8d63a609a706b4728838c2f550bf56ad7b36a8aff5b99262fc661a4d3cf686dbe038b10e44a43cbb10676844dee62" },
                { "fr", "63f70d5e295e463ec8547d50227cde511cd1e8467c8b31f9dfcdd07971c8aec510756abd37e607dffc67ca37f68c821a2aebc024b1e1b56f7f097ccf5c90a85b" },
                { "fur", "7b6fed5198022a2910e360d87cc19837df7e94ac18bde47daa4fbff7d65b0eb4871a6f731cf3a16ddd9e234e493137c002bf7441a516597bf2c29aab4f9fccfc" },
                { "fy-NL", "ec0f0358e960cb72b6f04da0c029c3f92748b42764ba377d9103fde82d9ee9083ff10202c8ee550c12b2f86f44a6c4af5c10029b65742a1ff5dc229a7b634544" },
                { "ga-IE", "eb95cee14e50d4515e4b9a51ac0d879795456c10a6833877130f7647031d3634b79024a0a90f637a7f4ed6c5d01645a46637ab6bc32b2c95d760bef4337dc16e" },
                { "gd", "c81bd7b8b3ef42653ed775cf45efce54bc33ad15b75cacd3af9f3a2601533cbdb1a7ad95922d4eacf2348f76b5bdb367409b79ede32aca835f9098af4fe7f4c0" },
                { "gl", "df4b111497b38ec64e4457200b4242fa186590cdf67458d6931c0b3a7809757cfb22da8a99f7ad4d9c856d3d8f40c5bea75362acfa7d71514042401f3de4f833" },
                { "gn", "55d38a8044b6c10b1270bbb050dbe608b3c26805094cb8b83d9baefa17d2ccd4c5a5a079cb47c9b00f4cfb5a9ad9593630158ad2faab71d064ec8f04057e8f07" },
                { "gu-IN", "abb99a40b5e7b71073b463d551023e66a5f6219ce030766cbbaab24fc90022bba5ed859728ab7779d65bc8d01f66826d0c7ed222077fa2547658826c07b4bd5d" },
                { "he", "727cf7a9caac64b1d9197de4f646ad3de131e82d68f643a4c52a2a53554b3b5dac225199af429a3fb386ec27076764875b06bb3244e9018261e06a3e0cf2f8d6" },
                { "hi-IN", "3c194f252efd1ad8900548c746c184c483f48db21eaf4139ebec31f3813325a7dfe5947dfbd0a7a0708ed32b26e5066cbc366722bde695e295ee71f82feed9b7" },
                { "hr", "fe97f794318eb8f879dec18423b82c3a86f3a4658a5bb6596e652c30483e9ea85d0cd183a105bc3afa184ca1b992d4a3d0d87593a660130bd8f74d38bbc33a05" },
                { "hsb", "f9fbd4ca5e7edca4576a08be87ec639b512d6ddb5071894c569eae86dcac8ebd25b9265e05544e6a27b5d2ce1e2a4c9607df9102101e406004f8aaf0f7ef264e" },
                { "hu", "fbf0fe7b37b7a088df9e3e7587b7cd8c48955d0b84f00b6927c76b67ad1e5f42c9258ca77824e57967d05d42e1b8bb0d54b0c370cfd3627746c7f3ca43659061" },
                { "hy-AM", "9b8838bbb27979cdfc919b55bc56d4eb7cb9b63625774c29bcbade24f1d58db8f592c6a0b637b702afe93ed60a4810aeb904d6470b837d053317c87e7cffcde6" },
                { "ia", "4602eb9f2720d302565523d7beadacf240c5a6ab78f2978400ee3a5314144c31f7c5ffb19bcaabf19ec4261b99fce0058d89092365408547a418b9321fc4374c" },
                { "id", "61e3d6ae67fb9f23770d0bae1e04a04ed2d6844c04b482c17e2f3952a3ca537b2dad293be30e5b509913f8afd9ad2af35930fad810a6afb4ef9d4e9c611cea73" },
                { "is", "d9f406b968a3823a358c880e3b9744d058b55ce6a52258418ee90591a7541c6643c929c481ad3a079af69fc1e04fa31f1fd6448f6394a428c2e76d23852ae270" },
                { "it", "d71fa33b7f7a11593a4550f25535d6068c413f6de56167ed447edde0a57e7e60d973bfad45154876886c3dc27fd0bb207c0754f8766d74000a03783757785f3c" },
                { "ja", "7754c88431b23863fa222ce8937ca8f1ee165856693c211d0b274812183491430913b947fbef8f225b614a510c00085fc4ffd0b376703a867eaaf05709c4b86b" },
                { "ka", "a9e0407c1a434e3147011a42976235a708bbd6052c2b8551a460f27a25852d9e595960659f3ba65af414c8424ca246ea50a92263b11b380315913653b0578885" },
                { "kab", "87570cd6d48a6a9a0a8b664fc1892af21715b869993f3d970fb108fec77b01c68467c650185ffffc979ccdb3167439ee5acf9bba32ba4fd4faf98260f81e01c4" },
                { "kk", "c89258617fc74140867447be3f27edfe6320f8059bd0fc07aaaf1b78c1e5d931bf39bc679da6998fc4f703fef908693237b9fe66896d4639737291f79eb5287a" },
                { "km", "92160a99947b414a0db7090284545ff9f909e549319546c3537d4000c3a8d1d9216f86ce638d9201010392798612a14ee0ddf194b882bd201103f93325ef5fcd" },
                { "kn", "9524d8c9bad954dc2cf80e57bf9ed9edc37a89bafbc0619b00b1ac590da357761107d2aee86878b2203a94309bdaf3de37c7af7d315e7e9d5a3420676a549130" },
                { "ko", "fa34423bc52ccafe1937d34c0b0d5669662bb55dec86bd7098fb1ecdefc4afde4d3044fbd3821073062c40821af9fccd6a0b2172e4e0f1739f347f7055581838" },
                { "lij", "f600a050032a06ed112b526f68e374389c992ec718f8cf30d1bd1bdedec55133e95c5cf993acccb2f606d51ee33a13e0548d39145e94b4154522f667684add7e" },
                { "lt", "95072b34130ab59e77a4b583b3869cfee99dd523a19e2aeb80cddd869b170d261a765a1dd3ed0d39752ec41c8f47bd5f5fbbae97ddcf3bb309e3258fe643ee4d" },
                { "lv", "2bc22177d1893eac2e8d6a972a9ee6b97fdfa31db75a977799cc7ea88d31ce0037080a4bc9766777ca902178bd104047566801d6734a1fedf57949de4720ad46" },
                { "mk", "183280405b7e18a7306908819ad9f0bd8c6a5c9601ca739bb6c89578f567a75c54fc56a4b615e999db2a729478cc96802cd3be1c7ac74dff9e33207e5c2a9c70" },
                { "mr", "16a33534546340f671b1152b2b9fb9b8a081953f99da1cce8c5cc028ab2c0488f796cfaba874ec6e4d8d9c9f148fee81ed3e13f43673ac6f5a0c0aaae38c6cc8" },
                { "ms", "e3c57421545846fb3708f51a0c975a3f4ae6e211f0256d4c58a31974d49ccb59dea39f325f85bb65269eabcff4a03770f172740e57aa2ce8ea979c2e39dac6c6" },
                { "my", "de29f9be28750416ab5186253df5bc1c482e11e5bc96147a45b3459cd0e2dea8fbbb68baa6a5408d72d9a7b45ad79f9a60f489b338d0248e250d706b7455bae4" },
                { "nb-NO", "d64347d273f6b0578e2a4b081b2e37d7cae7c11ea154f9bac2f375a3db1269fd406eb1c62c19045c210cd0aaa367256c3ab98f7ef6bbda26cecfa2a380311245" },
                { "ne-NP", "329cf26e8de7d6fff89f27d31ad07191bab198c232571a711b0f22d8e78d51f35e9bfadd5bd2e05ed60cf82a1b34823e2b79277adb51be496332c15dd322484d" },
                { "nl", "2dc537e10eb124c66dc046adcfa4af306ef40207aaa342ec8835a695186681d7de174b11baadd1c277524181e80775e86fba8cf4c4bd57814f121fb4af8f0b40" },
                { "nn-NO", "41a008c9d5039df5e7ff6786c328a5f85ed12a02cf5fe44ca1548589003460dd8b94542e41f94ec977f85dfb43752b2dbc682c233aaa9e320813526457702690" },
                { "oc", "47f1f78f4babcd1c66398684830a131a770d48c6036016e7c5ec4114fd1f117cad8a9e9c63368d7b87f1681a21da3f1a964f912ea91e326ae75c7b579b16b8d6" },
                { "pa-IN", "3478bf4ee406cd025b78bc4ec766b77491ff9adf2e46cc9540ed05ad56bf4f5e15e0dde4fc67cbf3d57f97104e3d7ab5593b09276911dee3cc571862c08e1c70" },
                { "pl", "0fd2e8c32d7a5b26cea3799b70cccd7ea3ddbf9253bf69b00e633f337fed12e302a059af451d1e68c84d7df309860e971268282c21a294a130f2867c77b7c549" },
                { "pt-BR", "f2b28feb4d209a0bb5cc1358bfcf44391203028d780bf8f74ca0c9db3d13cd47e1f530e0275aaa15b96cac12f8f1637ff224b256aaa16750dda1677e02b29fe0" },
                { "pt-PT", "de833835a12cfd50f91ba3644556f33c0a4f008493313b2d937eda687c39a5134c98d09858b0eb0981b1c87d2676531ae2e0e56fb331e9b86482b0ddf31ef853" },
                { "rm", "493aeabeec7889d4a05b259e30421b44a2c26fab38ae42a23b25ed81cc9bf2fa3ea49f968c6c48814c7d109bfff3ea41daafd36436fdf58222179541c3f4783b" },
                { "ro", "f00dc15ed746f0c4fde13f4fa7fb432f360bb13d1d864a29d8770afc29df5982839a866b3d2ca6ce6e035fef0486b3bb0f65d27b57dfcc2b8c42bf2f47d8c965" },
                { "ru", "62176d08e6866c53da19bca98e821102ddd551ec45c14028ed5e18da7dc9c2fa7da736f3f07aed50c48521010370693f8e02a302ea2fba41773ae84427f9813f" },
                { "sat", "b3d570e282efd67b5ee6085cfd94a4c464d822ed1616bc0230a9a08ec213cfc2b259b97ab6e821d70797fcf822cd7c2c4ba4b48170b3f8bddfd381dfa647c15b" },
                { "sc", "5a55131c0ede466a5adea6bd6f3efa1d743221046d7e567cd261bd662306671b1753b7953e67167bf202133ef6849a9db6153219eb06c40f357e86c0d70ae792" },
                { "sco", "e8c03f19bdb61988a475d4e8484a5513f740f8fa2932e7b4b0309a7b67c337251870863bc06fe24a0b2e41438c072db9f4f528d42816ad862be9f579f4c90dda" },
                { "si", "611ca57960e59fc8281215cdb3441abc1d30cb4b7c4e17772d9a025a324728301c38d13491d8cdcfcf627dfd65ee4224c9ad6b5e639bcf210f70771880e1e72b" },
                { "sk", "6574461b4f09f46b09c1d00d83d5d9131d1750244a10a6ba74cf6e8413e3cb22394407c49035e80038b8332a6f7a288b0b992be54c86de76957ab3058de4676f" },
                { "skr", "7ba787699e5635097baf6c7a521cd6c00b8d47e352a92317ba333948ac7befa91ebe775ea5bb90bc1d5ead564e22d5b44a3b79f8eba87ef49a214be4d0880074" },
                { "sl", "6c5e034b5a222605d0470e46c09f26435f8653bdabea12909eb14696cce236b12c1ca48ba5edae206927df72e5a441407c1dd815cef16b0173a2c7e047d6c02d" },
                { "son", "69baba201f372d442ba07cd8565b70ece75aa347d86466614e8e885d695c67689cd3c265e87276383b9f5b25dc698916e8ef353c77d009fcc1667c12c3e27666" },
                { "sq", "1adb74bb6b862f9d119c17c18f84f00e2536d6445e32e62e3b0e4ac404834f884bfe39fa2551d88b81cf450d2135c472a18896c75b09ef0e9f48f04f0a733fd5" },
                { "sr", "bec9ab7eb5121d0eac61bc0e1e7be5991d280f1db6fba7c0796cfd83e288a04abc385f71b18e73d27561761c330c68a7e03aeaa04927ab8c63f2633e7326551a" },
                { "sv-SE", "8bb3fff94b4caeae2985f485a75444736a880708da53be8eb146d3e4f2f3c77802c606c67c26e2005c78479361392f3feb8e003d554a204cf078cae42b427e79" },
                { "szl", "742e47e58258621e3c6ca280ac019bb86b8dc900ca6870ffbb905da8ec033079f6e82155c3a00420f35b33a68cc0e9c88fa17e16bbee55a18663f265a0e44ef4" },
                { "ta", "37fec8cd3099068544d6ba7d767e3f35b60f0d1e233bdb7262bb3c2444a40b47a8f916aafedc4e276c2c74406dafdd062bc6e3ae2864873c2ecaccdfd21c6b44" },
                { "te", "e4049174acc994297bda9f52d256aea1aa8688f59fe3388a0466fdb26b25d51b7270c1cb241bb50f65bad1fb8170851f4570c4d1c9fa6b0a45be7a1ca898ed50" },
                { "tg", "4acdf46c05a73e016a297ee744e324784d07c7c543d25f48cb9952142d572c10e65975d56fdf53634ff1d2fadc2ce3bf49f4c907cf7b00fb96f93339dc4b58e8" },
                { "th", "2f85c245544efe3d45c7c52cb534240b0155e4c2fa0e764f4d3f8079954650211e24a7d842cf2406083c792d8b940feae1a19280339cff0e357aee775c43ab18" },
                { "tl", "41904a5fa6b5506789f567b0d0d8f6a47f1f1cf8fb47a0d77c18edddd83fd4baeff0dacff407fda3a27dae37aa526db74d3d08dfa4bbe58c462903d51fdb5234" },
                { "tr", "87f18ab3d8cd8cb001d8efd84255e2e1d6ec1fe4041c7532d63bc94ddbb2341e3a0358c55f30951933d9e505c10f6bcf7c6cc49f8906c2bec38cffd2552f01d8" },
                { "trs", "fe7b224ef4d780e8d8310983fceda3e020874375e7372e0e6b2c77795d53866e2d2878357bd9df25da446187e03b9f836bdd27ef9b39db06e2e7c50ffd46e41b" },
                { "uk", "9cc48b85bdab76cc364d44ae9e05fdd97df78104bdce3b407757fae3a825e7abd951bb9803d6d812ea7509c946cc08d067e47c01f6fff229eb6ef26165de7519" },
                { "ur", "30d4fdc1facc7b25403a1da6857c7bea10fde81e5c7d859a9a06deb65fe39656ca01dbd4d8dcc55bf1ac582d17249592e51cca5fc901efd8dc5e41715184a3c8" },
                { "uz", "0f78e489c1f063a077e44eb341301d34ed50997ec1ccc4b721b076e946c31719d55fe36d34be176b9c1b813d007a2c7754d046c1e55ea4ecdd75a1646075f6e9" },
                { "vi", "0d7d1f48efb587a7211cf5757f894677c18e4073925aec8751e31ea0c8844c6769d703d2de5cd143490d2719a72311383a25efbf2cadc5cf06bc67c71c00337f" },
                { "xh", "9a919430632a44209dfc8075ab9c9861232210a090dfb3f59cc147497f5fd35b18825477ac700098feec613a5c28ce46bde8adf996b0ec406df9cfc79d8d20c9" },
                { "zh-CN", "0c0c36237942b1891b4fcf5e82eb570280eb9a5ee1db4f0f2825787d3bcbbc51a83f021ed31f945921c520d2b2f8ed3af8853c108af970031260b2202f81ce72" },
                { "zh-TW", "e8e0f4108eb3779804e52e55ea04c70145ba4708a212742c5daf43a44488eedbb5b8ff8c68b887276e30c0b45d66fc97c8405ee6b04f7e48ef136283c700baf2" }
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
