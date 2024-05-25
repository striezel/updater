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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "127.0b6";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/127.0b6/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "32587e73769586b5e782719d6321752aa3e7908b94445a8279defcd946a0ccab289e2f5808ad8426d1a0cea80df732e063ae5d23c34e4612488f2500d2b2dae5" },
                { "af", "56fb2384c75f77b54112fc06ff5ea7b45ae7320fdf055caaa90a4768409cb145af00e89f2d4c4971d27734429dcbd847e7355a00e2b91fd16e55155a6c6fe603" },
                { "an", "c0db402df9aeecd161971fb0d54339705f2a642163f2447c65f54497d93961815653c824dfa0e4be77b72f78d2128fe52607035bcc3634bd6baa396e8dd36b4a" },
                { "ar", "64fb0816dc51661c39d0841fd7574c53e6ff3892c30a46be518d38e09b5a26454093a69bc8bf93cb7d9d53b5481da28fe1f424dcfd3b5b2b0eb63960eb2ea592" },
                { "ast", "462d90ddc4ee7ee12c41c28b54adfe4ca21c7b3573232e613566e26ae67092ba11a9ce78f93f205e214497fa1cea2b3c05dfc771688eac104b3c2438d3e5100b" },
                { "az", "3c153d0acc403385c41bf342d4756947f59688c7e081ecd8eacf24fe3e7a73e015dacca6a9a28fa7118ff1d5d4cf0c6528d434fc38f3a5b7cf8b6744e69e7488" },
                { "be", "4a6ee902f2d4319c898a604ccbfb595ff5d3e0a680b0f55b723db83a088923452e0db46dd950efafbd7dc1d5b7d46858f9b83c3a47081a712cab3a786d2c99e9" },
                { "bg", "d6731203593c3c8040ac9290cccf23cfc2f73011b000041f70d5d3395aedd0fabeb46c5d0323ced89ec5af821e4d9be1d98664d4450aad7692e679fedb801517" },
                { "bn", "08714108a2a4c6486c636b1b11db6e641b7b9cddbb89175e9c7eb51fd6524a4336390e7dca993b53ebeda20e5ca65f32897dc33cb13e32aef7793740a077cf51" },
                { "br", "c9a1b39af63124f3a07e7da936dde937d39fa271b75ed1cc06e16138a719645488b095058e11c2616a33f80f2470ad574915a16492d690b958d6da48ab300741" },
                { "bs", "bf1201bd75c56d4719473962a751d0ee2165479f09e3838f78160643558ab2bd69ed7b0d01739298cbacbe0f43e67817a347c2bf0b4ecb6310b56490f2ccc008" },
                { "ca", "d4464e8b773778784efdbc31689384ee06e58bdfcb1859e0e74de36a499a29bf72a068800b552950c46e22d2f6fd2675ce45f75829e991031b9f1299d5a8d9f5" },
                { "cak", "f07f4c2c11a85a44151e2c0381a8111b873ea302c7bcb6f7f8f5628a5c0c4f426aa9c45dab38c654fff8dc72910816a5e1f00ed4ec46f079e5db29032ced6350" },
                { "cs", "af45f0b40acc7e9526555d803490cd87ba2bd8b665d2c9fdad7bac47f035d9af558313446fdc7c7f4af24e9fa17ee205b589baac6dfdf4a3290377feb812d9f7" },
                { "cy", "61fa0f3c740868930f2375617fb3e8e874747290ffc5559c7c10ee4bfd17796f2b7618331c66366cc7369b5f73323e8c0f2f4fc686beb12bc8bd19b0d50f5629" },
                { "da", "b5a57d7cac9f301325c7c307f2e7dfc277e41b63b7053c427778c50e5634d8dc8a971f4f9c7008c1f1c1d65d79963c7215981d96c3365879e7ebadff18cdfaa1" },
                { "de", "81716435878e2c44be9dc2fa4db3512cbbfb078ab6783af7066b8767dbb182788bcc0e7edaebcc418e9daed82c7929dbac21ee37787de0d5d373d3373f8d4465" },
                { "dsb", "d9344e0dd5768a6c566474488c9ff1832f9deeef87c74c0e6728d95fb936a3cd5a495948dd491ee1c98bf39e030ec609c393cb4cb22f1f01fe2e85885e70bb4a" },
                { "el", "3b2e606435229e3bec55e746dbf467a33333f436836a8e7bb19149f6d97435fe8a6005de2758b4d6ca248494f48fce34b995aec8ee30a2695c745783c873c0da" },
                { "en-CA", "2dc4b9d6f3f59ac0b5fd802a6d5a2e4975c6a2e5795e2ff74c899775cf93b0f94d6fe7f060e0806f79a7f16f440c4d111d8d26995897c11c1c9662c5c3775b3a" },
                { "en-GB", "6e8858b37d855b152c45ad681b821a237f06147855f41c6d05b70c9b4df76b419beb72f52651931b00b3fe00135fb544304aab4898ac6389e019505b958ed99c" },
                { "en-US", "2714bd33bd717e4ea4e34e3eddb922970ffb1ab133d4a9f7c6b0a62bb0cb4fb2469e44aa19e4d6460750740f6e6820be75baea113a561e9165ed64f292363e98" },
                { "eo", "d09c2f878682a51451c2119d016bac6f41972753db75c3268e09028e3c6da609c28764141975c913382efa059fed13fc57a70db21954176ae7ae773d16776c96" },
                { "es-AR", "9a1744ae3561f40d69ac972ec95923c29dbe23bdc59998d8f41c29c96c185fb51326bd8eb5e2d35d229cc3d8d192b8d0580c93d8f168f478efc8d849d4425014" },
                { "es-CL", "ce3939bb7bac1a1de23ecf06d18d41adde6efa5d83b6b753e27086abb5604f59519b410a4a691e4d7a8724b06a5d274d034dc55ee9bd47db8ea99264b80b8492" },
                { "es-ES", "2d558e09f194588cc1d579ceebd8dff2fe707f070e3ea4735a8c5b6b4a19b23693b2bc45f6e22ef3a1b35dcc3b7a97783d23cf2232745d5832c52b794da722f5" },
                { "es-MX", "8acadc44b3403171a351e15bbb372909cdff4b36f20beb2e293b925d68020a004bab15f61ad2373d84e6e9f48dfefcf5a843de74d5060cdd835861a7e231f5ba" },
                { "et", "ae1a4629087ebf5b40a4c1513d71808baa99b607c134bbc85ac70d1becf5ef58ee82ecf95237b081f99954a7ec95bc0e0af4d07a6052cf368cfb12c282740ee4" },
                { "eu", "afdb62bffdb55cba9b6bb7e08a47a0bfbdc18ce68187a6949d23b828453e414fa155ccb30174d9480f72c076390ad941fe80c117e72e655186cd6141ce8b4b01" },
                { "fa", "3b09a0968fac86a1ea62aec830e8bbe515bc1537e8b074fcbe1ce5971652af000eb5de3faf369668d95142979b5d5cfcf175a26c54c955cc852a9f2840301d5b" },
                { "ff", "1ca03bdc61d9c70904dc7bacbab1b9df4df79eb125c570ebed73cb3fc763a0a3996f4503da9e4c573fa2752c17450a5e9f40c5f85aa5ec595295d14d8c09541b" },
                { "fi", "47addb9374a2542038d2b0c3531d8bad225a22b12096e0d559bcc04eefcd6d689c983c6702ce6beab4fe5b64f8f82b22b5646f93e0dbb7faed5409ca06ddafe0" },
                { "fr", "971070525b4444633e6da9d90dedf257e08c86a3b525598845feed1f1e748f7dda2bd636d646564f7655b200eadf6d6fd668324a38db570e29b788bdb8986519" },
                { "fur", "8794bd2bcdbc5fd2e4915f445bd689fc6cf6e2046c24698b15217891d5233c4ad34a54d3485627036cf892ca5423c11d984787c7846d3b45514c807c8ca92035" },
                { "fy-NL", "a619d8d00e596dee26aad591beb19737e538e8516ce608005ebe760fd75498c19307bf6672a16a5d6ade049608d30e08dd77fb635b42f7f5a4937a384c66da09" },
                { "ga-IE", "0b9c82624e6b4211f1c43add4d503da3392683e1f08ee9a72ee3811cb9551f00afad47434a2f0ec4c488c893e1afd0cfd2201274a0690918fc53e6e6efd4f0be" },
                { "gd", "be1cb4df2ab32d98aaae2fca891c39c8cef14892dfa0eb5b8f067b25036cea148da91eafd8a7c05152c3a981fe92b6bf6cab86decee3c053aa51e58412121baf" },
                { "gl", "f1615b7fb3430de5c4f7b4f56c5f672ce978aca23146bb781c3c3d831b140b67634ba58e41d38bd95053f20f281a13bcaeb58f277c33f4c84d74b5811bdc6d0f" },
                { "gn", "d0d5d7b20c3980c09ffd984b6dff7f17613847876df8bf5be45bfc64c477b15adb0de8c84ec89e78166da780f8a53e0d90f0818c9c6b74864e97a1b81ee8a055" },
                { "gu-IN", "94fcc4799bd38de50661f08f96f13ca44e821b42a2ec1e890a7bb3290fea30599996345cf8cdadf147560229323138053d8666c682bcbc95e0e6f5304858699e" },
                { "he", "1600064db1f649504d01a27d853befcce865bb4fee41c0f3171066274a8204b137449b4089c49069890992e1d0c453d30eee8fc3347fb64b391ba5f038796f6e" },
                { "hi-IN", "3df77d804866161ebc19373b84c1b32a7282822561211a22585ef2fc9818d58c1cda380e457d5182c6793a1606cebff0621c0bbf42f881c98ebf748b67ed64f2" },
                { "hr", "6680624354d6e6007481d458436318f1f94b3c3797d414e3851726adc44ad83e9ab02888d9029c2f72c30076bcae36f7bcbc980e510c31635c17a8077d655a54" },
                { "hsb", "fc4a79ef5f4f6402529d890545df883b1591b0fa4d603824440fe82fc5fd8f10f6fbea5399ecaf3a7b7719a9d80050b1bcece4309e4250f7b688c3cfe274972a" },
                { "hu", "a426779e43e16dab7ccb7422f356fce7a2e1a738a5751d8b8de5583d8bd712faeed2665aa36b8309aa9272e800c21d595325e0681b2beef728ae8aad82553c4c" },
                { "hy-AM", "4390d086cc89a1a37af86f66b6dbdc2edd3c05837a7dded02d72b1b382c9cb51b7bdf8272743571865457cf5c013bdef5b1ad3a84b35b5fca521ae9f7e223285" },
                { "ia", "2ceda7c1183866800d5d0bd1b009be3ebb50b97bd7085ac30683e1b01bb1edcb4d4c8fa4dea40ea24671331d99839a303476022cc10fbf926ead825a57f49b7a" },
                { "id", "31d2d4882742e63b8d1a02ba183486e1df64005b03f9985810d94cd70c74b18eb8b5e591b6cb94884296cbc5559641f1c31cdc763cf7042fa7e920990667fdb4" },
                { "is", "ccb1e32975586ed75aefea470bad280a75cf18ff16e6082b653abc23592d3e6a2a1a209721798f1cb1fca2fcf5d46f3f4151f990afbe4292e006c8b70cbb211c" },
                { "it", "a33e09b434805ea06595557ea6b859708d7ca612765396a362caca7be8b55d4c6e405e482dac5c9f516201b2f9d5a3b883b15571524b664e28139a20a5224dc0" },
                { "ja", "773cc6ae273b4616ba7be9c719018bb5c0465df53fdb1890999e93f24a10260ed983b63db35dfff60f1571cdeae4461c861992bea4de84fc9ce47a7c6b3a9dd0" },
                { "ka", "a195dea49b4e343960f7500e114a8ac2d1c708511f92987de34488c2c3b306aac14a01ef8a348108a74905e7bca1eedc6e7a03f8e7817d87bb7f5302cc064171" },
                { "kab", "d3813a6c20c2c080dd3c6b7f7cf0bdcb60d52126d3c5da313ad9da6d69d99cf767a92190ed5efda4f66e4af1a0387b7c76c8fa4022920cbc461dfc510c02f8e8" },
                { "kk", "26db358122105d571cf4077ef04f064a6966337b810375046c71b8ad06b9047e22306395b49fb4fd5e899d1b3257207c38f5e5036dfeabc34746c018a81ea988" },
                { "km", "395e00d15df6ca1e69b54b578c1c87cab90a829bd65d59db3957060139f956625f32bf7ac3b069ff0e6e346848499a7cced426920fa7116d10007ade975c22cd" },
                { "kn", "ba693b4c83ad447e5f09890718b478009837369747c4677bd31bcd512f05b8e2c3295a59f035d7e16024e1f0eb7514bffaaef77c77cff69a8da98c77a2238182" },
                { "ko", "12cb2e661a319a53ff601462b0ecc7d732406f813638268989ae2dc4ed8efd1c7780e9e9b1b7378e9a4e7507aad6260cdf251212108df504ae630833acfb1886" },
                { "lij", "eb6f53ec31d38d29987247f2b13675ec6d729794b9b92f584e7155c9af0c558eaa8a8c766596db1d6ba047e7e42ab3e0ab09bd527293599601a0488bb5cf81a4" },
                { "lt", "639265ffd98fecdbd0420a8212894f59df24427a9fa281b0eb98c2fc35d39bedbb9e2e011ba6bae66f169ade4fdbf64ae5daaa18a64b73b2de7101c85c825c0e" },
                { "lv", "149fcb2aa372b78618074a60615c4b51851b59cd9b4fab4c382f8ad06d0608197ab9eaabd5ad867445fa8e2a2f41d7a40fa66421192dbff15b92b263bc58c3ff" },
                { "mk", "4dd19c33c1acd3ceceba86f932b4c2a89b7aae2d927c5fb0832fd9c08bb8ab859248006d8462f11f8a68a8b071373a3257b38d6bcf03d62b17807284aee92aa8" },
                { "mr", "fc91e670d3a2d52f2f6d18a0bcadf9e366edaccc4714e5ce9f92a90fbd0f09fa5e5b12faf5630ddfe1b01677d9b4eb4515002b143b61133d8b846f47fe9d6f17" },
                { "ms", "a5606c91ce5e8e948d9fe7d182da7925e93e17ccbc10e7bd82b194ee434a425b68d2677ed5cfac4e72cfd3ab788d2c4a35a317b1e99d8b46f6481ce305278576" },
                { "my", "a6b954eab047a199079f2f07c899900dee9013241af5e0dfb9d9a7dfe15eae6a22e7b1e7b4d9c7f2aa96a707e4b0b89d82f6e275709ddd0d8ba38f0f25826175" },
                { "nb-NO", "f32fac7a64ce6f71ec89ceb2047c4e5dfa4b0e5b57a1e1ea7a7162c0b3ae1140db2537ca57c8ecb8148868aa96bea698993eef87088a2ebcc519db8b5579b3fc" },
                { "ne-NP", "4ba037888f7c1015fc579381f5b3b8fab4a6b9a1754dc9ff022d510e89aa1f0e4bfc4e38ef5f8df06925583ebea38288ff5ba63d82d496281e9fad3063484ef1" },
                { "nl", "036e3353772bad15a059623b57f71341d43d1cb6b5aefeda00993cc881ef211fa8088d0664e0116d6c877b24f4ce44e2cbcb4d0d80ccf18a87a1339c5aac5adf" },
                { "nn-NO", "88c25124081f13dbcff1c1f9b927cb1b8b5be4e40f75f669da681572bfc8370fa12701d32943ce5bab37068aeee9c58146316ee421a4b33fa7d2c1dba944b77f" },
                { "oc", "21543ebaccb4271692eeb7eb07ec8649254053e5d2a1dcabbe567fb087b0516c183a2db0d013a16a0124c5a4a2eb9c6bd8000147b4579726683fe64aaf9ace3d" },
                { "pa-IN", "89a5817a720b01334affa456db15d8cb719b578cd7d23f007932d154d674ce6c7b7845c8cd07af488eda95d30a7bb1a60339d5ef45b738ba6772d2e44e90e310" },
                { "pl", "fb4ec5aa2ad9ee03581826aac652a9effa890f7627cf90cd43dfb0f9b9de5846c4d186b29b30bbed80ea93d898a70da289bf71623a2738301c08cbe6e8e98bda" },
                { "pt-BR", "fceaae108080df9919e8f77b0d375970cc22d3b024b6f7e2d150c77e0a144ae0965d1380346eac7a84fda71f4f5ba77485928dde65f842ece05531de50e8e4b0" },
                { "pt-PT", "359bba472162df97cbcebcb2d04196fd0d3f0f81ac4f299950b31485fa30b7a3638de6de38d841f325710b874d1f8bbdddb9f58ea713a0f46d58a655f7e71d35" },
                { "rm", "cbbeee2e366db25656047d36a2c1bdecbfd8044bf0bd1653a247c1d1750d95b1ee55e417065549df5fe29c5902ac2d6639e9a07e5f5e141edc8dfdc7dfc7b862" },
                { "ro", "8b3a21410a35249c0d0e5e0f2bcc88b7604ae6ac2b6dc237c9bcec88137591bfd51c66c1ac518b74d0047548b7c5b43312959d93cd41f247567b057968e8460a" },
                { "ru", "d42440b26a8d0bcb42a40de9838f9765ad90be0abc1d94a2a97daba8e31b6a9d27383ee8a28574cbdf18b3a541928b3ec08270650a14adb556f2c9e427c8366b" },
                { "sat", "1b349b4baff8899b46636320de0eb99b4b8db9f9c523fbde0f37751b961aaf53e7a0b4f636f66fc084f0b1dc5e9fba5355b9acb523f933781be8758bb4e002a7" },
                { "sc", "3f90a1501bc048a0c04179b2d428cdc34d063aa1ac4f6800fa328d09546627b7d075225cd0ca0eb16499fb275adeeb788b2e0211a1a3438c08bd29958052a24a" },
                { "sco", "3803f4736a9dd4cd73554db43bea71e4a7a1fe24f96205b5a0c17c01397ffba35f52e839daa7c777707a6a9febce8e85ffc6fa75ee81656ed45dbe7f3a944a19" },
                { "si", "61a77d4e1b31e07108c99d93caf7bc7df947f9e6963b0700d13e55b394c682e5d15d84f558d7cf0d31e5cf7b3bfb09a2b327c4f41e9a92f808dec7a4eb907b58" },
                { "sk", "e7f6497d3c1ec910aa0467f46f48c7e4d7f8e0bce20eab8e870d7ec9f28362e7ceb68d0b96a235391eb95fc4cd4b551775fd3773c301929bb737dc9d2598b132" },
                { "sl", "e2a353b9ac98adab734962ca7d0bbd100960f607717f81ad2f7aa2c90f830c9556c5f5adcc54658dde2c5f6ffa825e5a43cbede026bfb7592285f4c975d3da76" },
                { "son", "b6e94c51f56b0b143cdec91540f791839fa628d8ea4fe03054a60312c2eb3c2a43763924deff4f97c0b9157f98c7481e8b05385a3d01830d13379a25265750a0" },
                { "sq", "0b9ff8497e901f1da5ef82c8b7922977de6a51de7c600d4b1a4ffae468eab5c3f7fb32a5074a82f687c0ba1dc79cc5819a344c7a9bc3d2dd818ba00fd42202e2" },
                { "sr", "308a3da9a70c405cde9b89d48f1aa81740fcd98c8b9e8e902a3b19647f4595b5d7391626f6d3030829e97e1732a5aec64e1d39798beac332067c34023f958227" },
                { "sv-SE", "e8af23e4efef52c8f80a432a625d9ac01011f3d57a9e25b51f9a7e52f4e23e168f4202940a010a3e93f18b8ee2a828a8186588821cbee0d91fd4019722cb705a" },
                { "szl", "05b77efc1f9151351ac01b0cdee021078032a63596d136d12b0f44afb3b3129bbcccd8d5bcb821c4a01a737208c2238a29a62c416fff37f2d0c7594a2dcb8a89" },
                { "ta", "cbcfb4bfecf5b8b920ea4bb8752967d33ed93f8ffb464280c35131b1cf31ef3444581b751715f13186065cff5c051e130254603532c3cb1ec8afc42821516876" },
                { "te", "35febc7c94e36e39f41ea65c0f5594b14ddc08820d50b096200f1b99471df2888d9e4885216dd97a228b92c3f7074881bfdbc4b430ca55d8692071397d844ec5" },
                { "tg", "4d5f596b6568a7ad9c2a8b59dfc0289dea4805612f614494dd035a6cd7658307074bb569edd2d8977a99672e039daf5531fe840826b94aab1a4b29f668c13ff7" },
                { "th", "ea124252c7b6b278e9ed07c5d009c8b053631190dc64203f46954a534e215df739946029613fbd512790f20b318c3a2a6aa03f5b53a3f2e30b32660717a1e418" },
                { "tl", "a3e039d54a26ab92e8c4986a22dfc8414755b3807ae8527b32031a64fd119d61eb7577219daf9b01202dcd6192b6440cbaa9d7b6f8fc63660d0b0d65394b0f2f" },
                { "tr", "a7c609632aed4d0f46ec48c38ae3408b1397c0f4d33fc2f6a863a5cd22517d11119d43fa9fe7e9bf2d2dddc1620a7ec5099051df008c06ae801259876ec34906" },
                { "trs", "a766baa200948b34a7a8d66632c5641d662e8bf44017a9965bf8d5c5b917d6676fd27676f7e87bfc556f55f625b51a8606d8a5bab978e6ad1a9530cc5ddd664d" },
                { "uk", "09fe6cc73d1c721705a8b8934876d2ef7760b244266c26367ea96ea4a2857239e61d48aae47bfe700b9d9d6420ca0531ba567e6787ef5cc604c2ef9d165246d8" },
                { "ur", "e6c5f0f3106e59eb257c782cb22d05cf4e37c94adc4fd1749da8aab202c4716f8f4fd295d4f7303f405762d48f9d3c051c8362a717d3bae18f339a29dd7ddbe5" },
                { "uz", "ecb11c64b1502c8546e6752eb3ac6ecf3bce0101d50a72949bad4b9edbc0ef5f5c49f18d0ce778010b0178f7640e31c03dc50feeb6e1157a3090a1143d35147d" },
                { "vi", "f71f5b18f825cc499261772e24e8e8d818d8b1a2501f9202b65dd8426f1fe97cb8137e7781ea035a47f05d32beb95f366165378af70580b5a87e0c8a7a493b5a" },
                { "xh", "d19e4b07046646079dc94ad4e1873442cdc052af6d9f56523ef181d078f89446e2f97dc6a3b67a9597669d949334a507764b46d2b4191abde939dd55cff6855a" },
                { "zh-CN", "f27d1af179371e693382684780086bb93bc4234cac180bd23726255032c011e5125476f8b59029772fad293f0cb24a9fa9eb738360cdf24ceb9016b0a0085518" },
                { "zh-TW", "92a8a361a262ca3f6602d3163ac94345957d08854ab708e4e353a6909c7ab587335b1ee146db28ecbbd073776ee6b8903097e210ef12057b25dc38ce7269d1ad" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/127.0b6/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "9b5d6d6bde9ad5484e2270728bff112f3b237a4703f35b0512ce16aaefb8deec6a66d1c6c3d0878c475199feb1485e0fbfd608a1a7dda7fed62e738204b8776e" },
                { "af", "f9680fe8104f3e1558513d40816a86f09c338b2931f609e3037d5d7fdd45e77bcd8b43844c3c8aa52be2582c6a1c5d11e806c53ddca45d13af192f025e9d1353" },
                { "an", "17c0abf8ab17075ace18adea0e322d10f77c2a3a87f1906a371f487c46b454d9c53868638d559f62f5c0c86b9c9af985a31500a010ca8bfc04c413ef00bdc308" },
                { "ar", "9849f9d54bb62490a984f0d2907b9f9441a3cbdb4109f86d6b85cadae242c2d3f9630c1129530029a57fdd451c7d3d1ceb5d155f46e000a016ec51bce9396976" },
                { "ast", "71e091bd276738483d329ebdd2a02f007e8eae6b9f3c38a1a70ebb15ed233002bce8f503f950f5d6639b4bd4c146b088f540a5dd4a2900605a47f2ae0b985073" },
                { "az", "5ba06191d3e5bdd843ff97de703898b845cb8c9324215e3b1edb6e3ede5bab675ea3c931fa238f18373521d840fda9829ef3b1c360f2e45e5548b464a2b10f15" },
                { "be", "5460a50cf837dfeff7a6631ee45206cefc48a223a5c8083b0daf921fdbd170e18661612a76a1168b3fa7e1717f22b1ad3cf6a018f6ce2596918432932c2be986" },
                { "bg", "9592fab9799296514d29a05ccc01fabf09cf431375895dc4df67b7393f947161106b01efd5067a6f9de502910a6a53d13f7b7e32936080dc8fe0078313014123" },
                { "bn", "34ed7f2782be1050fd217630726b1b553de5a48f13216283f2c9b0661360e1750d8e976b0d36e53cdb0823636c1aa44de1b183596774f9301357da8cee371ed1" },
                { "br", "0f54e71a7e060e7076268a28650340fef32d5c01cd271400843f8eb7bfdb5d24ce142f6e228ed5a094b0ed203f1834e7540383cdfd9c2d8861861ab6aa33fbf7" },
                { "bs", "234896882aca3c85414fe2979267cece8ca85456d918637db1a5cfbd6a9033dbb46d3efe3b86238929487600ed6eb9474a78f532b1d003740cfe4e586e833bfb" },
                { "ca", "8bd7a551b6078ca6defdc0602df6086c713e546fa5358e33a51ed96bda905c328c88d049239b4b2940548d3d3dc62900676fc7c27cbaf086a011702b88c7543d" },
                { "cak", "22e5e755f07b5f4b8b702e27f061788929799e22bc37e3c84870c5263c16cec8bd71e41b093fef0b298b2d7dcd882885ed883702b5ab691edc6674b22b8a0f34" },
                { "cs", "e6c3d81ea6a14bfd390dd9724f3dbd6981b95379483f027eec57160d9883e6d25a3c6cca382301abd7a37dd126a131e5a198a0c270a64fadcd49894ee343d1cd" },
                { "cy", "1e109db61f11dfad6e5eea6f8f70e492b5b41733f23e0860ba016b18753cf8e645bc2c6f09be53338c59986360eda07c92a7042968eeac30978c780da5607645" },
                { "da", "9db86b0384ecbdd6e5009f68d95a0a252dc34e59e29de293cb9705c1457cf3f531ba17c2f12d9f6fb06d593ab3bff262f242520aa1e2a727023f4c0c3b76fbfc" },
                { "de", "befa462794fd2b382fd83e96c0307fc359da5f0dd5fcb5edc41851722781b7f94fa72a9e755ca4f99a8683c0ef0512b08fee86f7feeed4140113fc41c33f958b" },
                { "dsb", "a5c800414e7951457ae422311643133f0868cab0a53276b3255f3a750f8876ba5814f316c651b14aaa1aa640f1eb6398a7fcc65cfe6db0e89b7d98dcb344a9ce" },
                { "el", "2186a1e52dbea7941717f478d0f0bbacb3bee29865574576e0db54353957786d38c8205b5d772c4d334679498b8edb2cda4f4d0482e2c8dc83642aaf9e4589ca" },
                { "en-CA", "d3a373967bb84cf01f81b03a4381a4b7e3eb85db9f9fb3f78d96003b4956201d687ccebe38706666f40da353a4884231cf199b1e9cab5ef8e09a6efb61d47c5c" },
                { "en-GB", "9c7577ce4991a004f0823635a9bb671418b1bbf4ec7e6cbe844117a2058b63af0e664db1b81fdb59deaca51b9ea7f9c07f841bd1b54f2b3efa53d435a57a40e7" },
                { "en-US", "8347bc7ad2c88f1621ae4527dfc50a3746c8b84904886eae59f5c39f56b6fcd12b146eb3fca5f81fdf6a6747faf54278fe19e80d4095727df9e1ade3e7d7c692" },
                { "eo", "bf0f24be928f0c7f1a26bc90dd00fe3b5b005dfb7d5c7739696d457f58ef5bdc730f200e250c83b998cfdad0cf04b96ebba3c3a43ff60305d929ebfea3bf7db2" },
                { "es-AR", "6242d55d4e51bddfe65bae31eb28226be6849e0f14da56a5cfb02018836e71d7eaa88c14b22b6dfcb336daca5c46bedd174fcc8f096ce06da34087c52346fb5b" },
                { "es-CL", "d83e21e8c5ab687084c254361a7d06c95ecb5a25582704b6fcbe2893bef6ffc0f843091badf08b82db8b64e3f2d65616c440e83a7b2f45c08f9a682c1e6f7efa" },
                { "es-ES", "156f6eb273c72a6981cdffc2c12612b2acb98d1a54f380d136d3da0af86fbc916b513e042c039f477d3b8127e281d7922828e55171f6b36a8b7ba8303ad8087b" },
                { "es-MX", "75f6425a4c0ea12b70bec678c1cb761d333f274b57ac05ab1528d1e7556b22f53b66c1bf83593a9acc0b943783442ac5826cd35f8d543c1c1e87c57cf7dd59a3" },
                { "et", "eebe96cb81c0f9e60a17e4cb8a81f132b06bbbe75e7ccbbfe67f05717ea152dce829a2991dceea28a85e848a98de52a36c48295fbace95045667df0a43fca6c3" },
                { "eu", "7f2362375d1a6897004774638093949164ef32dfa94e05130211f854bfeeae5464ee858403f2868e5f334e362f9bd22bc258b040ec23af42fcb5babc332e837f" },
                { "fa", "5b6d6783185bdb2c5c00d7024306c714eb08c60fdba13d6bd0d28c78ae3b01fd978032fbd4326e60d6ce362e95450c5517eef1568f96566c85c2a66a21402adc" },
                { "ff", "0690a711e0853059a06a811300d1f6f060495f2f539727499f212c1d56df063c7d6c862988992e349f275299105c7d1b2986be46b5b372534085c638be7c2c16" },
                { "fi", "8e837737eedaf736608010e8575f7a33e43a8a14de86da5d731d616f5819e73c12508029b4ccc5bcc558878fe373da686ce5354165668600dfeedff4ea48bcd6" },
                { "fr", "608f0f899240fd3b01b58ebf439481470d2f2c7a9f0c3b755f49872caef832f01feed17a6734c72808181454407b34ef2d9f89487b8fde8a77ca0bce26e89183" },
                { "fur", "934687d7ce88a8b2bc2c01a5ffd838b0580a46aa7a16603b59861808ec329836ae17c6fe637996f5d3bf0f74306cb9ac31c7d7b1fadcc2a2604d24aeccb049fe" },
                { "fy-NL", "a5627bf2dcfd438bdbbb2f4f47afd151760e14e7c2b7df3764ef665906b1c24843c69aca2a37aad18049e7c22115c1e9f24ed9862333228c764a7cb00771a88d" },
                { "ga-IE", "707378f74348f183c1c05ebe4d19e67e0a96e3319f4079c91bb97567395b8f257922dccc505c477d052d3cec71a9bba85aac229f6962b94b303cb46bf4d17601" },
                { "gd", "2259d30fa1cee6f0b0e11d825e377a9744d008ac0f3c56d0925775071ffc222356ae3677b861b1ddeabf2d0e1af8dea147acfd515559e631df18967d4efbca17" },
                { "gl", "74a1e17e51bb815115e265e153c471d9b4b29b1cd97c7dd223b8e15836b51cc41709c162eccca323e1b202aea2889758ec2b7d4c7bb54b4ef47c6a440ecaa156" },
                { "gn", "89fd597f447e55f47fa45c1644dc648b4ef51dc1bf7d246f692ed4e1c6466ccc24a3053e442d573d75ab0ea01e23b8e951b359f988e43466a1bdf6962baa7d12" },
                { "gu-IN", "03e17b9c67a1f11dc4f6834a23cf66fdde089f4f80bee454441ef9ac052c4c22f353085244b87cb5d510fd68f5deb0dbd7251db6f1ada68675404af7a0cbd016" },
                { "he", "d0f86dc2acd53838c2741733e10565c217afe89ab5e7cfa142a49951c74c91c3f37799893d13f2e7ce001738ad1ff6e5f1446371505373f3dddc47f24e76beeb" },
                { "hi-IN", "a3bb872d54c036eec3d3434f184ff9a047098737fcc3b62565ef7170b3780c1b16c97c82b51491919bdc342a65b1cbdf1829d1d209e4f7fdacdd825918f6c872" },
                { "hr", "87321da50139d7c304df018ff20b339e60effc387da395331d54bce840ae50eaffa94735a0b20f0f272e81c222b369a8287f6d22cb160ad02cdedd7a520e1207" },
                { "hsb", "933061d15feefc1c0b2eadb488e062fbfbca0f1739b43503ead10fb9d48db32969b38ec43ce1ded1f9669b4ef1babd4b61b30bfeb4c769209b23a430c5ec0bde" },
                { "hu", "766cda0a81a0759fdf01df91ae684af4d28650891243e3d52cea2344f10c345c5436635d17a67750cc58358076d236b96c7c29fbfbbc9d9657d9c94e26689be2" },
                { "hy-AM", "dc2a4018c16d67fbfbb58fe80dde8debb1f229dde83b665873be6bf500f4f82f1fd082edc34f18b1365a1a39b7fb7e999537ec234e21b458f24ff84a42e47380" },
                { "ia", "458f719d31cd9464ab45a3f2d08630750531eedb27a6895158db7f028119315c059dd0682007d3e15347e9c994521ce91810c1b28824fa59fa49bd202da1172f" },
                { "id", "f219522879f13601384f759ae7b8778aaac15cf2ac499ce5d8f95aca4b45366f250d91f8fea2b486b86aefe875492f0a82e17d984ad6c1d040110d1f2c64690c" },
                { "is", "329f204e4300bfd9a5f95d289936d5f1745fe4476c1ffb84a3b4ccee3cbc64376517b98e27ea29fb8c4412173dd70176806f944a2755b8b4e21e0b86c4538529" },
                { "it", "62285e3aca9bab53051ccc2aab359405c8ccd6ae2c48ef43563d22fbb9c6fc2f62229e8ef2f16db45c86120d9e9ee3a0696585ccee86b631d43bfc010d7cf3ec" },
                { "ja", "e7302278439d624a8b225eceb2532ce401efef8d8752c4fa01feb6183946a7b071a541f9d7d4d6e631eaafad21575f177ee662214a16334bc9a1fce384032c71" },
                { "ka", "839935bccea61be10598bddbd8d448a0717402013a87413aeb07c3f6aaad444d26bd7acc07554f8e2e0fcaf1d549e0b06e1a708838866a459b6f28fe32d81285" },
                { "kab", "cd088ac4d70411701c620affd4775f545e9bc0ed13c7560ab27102deb642dfc926523da2d31b31fbe5532d4249a3747b95a26290a93176b1a0bd0635e699aabe" },
                { "kk", "68ec0f47830f7b0bf4fa5506a160e8bb7068861fcdce4506d16081d318108e814f73687232d8bd29e414e9f2f6a16f96258ff77a763939f4d78518dbe55159c1" },
                { "km", "36479d671101cb3b90aa83a3d61953651dce075925401f7ddae75875ef8f3598a6c46b79a71c28efb71b420818275ffd55a99bf2debee14ea289db5452d067a1" },
                { "kn", "d92b4a50b20dc1aa19e26084c6275c206aa856fbbd270ca16ec593aa90b2e8b165a69e5c47c860ee0b2445d0cb59c124a6c583f3ad413b5d93923592fec208e6" },
                { "ko", "7a59a7194f146fb392256f9f4ef61187a65fd984915c4e73de4d9a027eea226e08a83cddc86dc06b56b83a9c62d7a16cf1b0ce9999966be6a0454af29ead158b" },
                { "lij", "afa3b8a444f61d06a93f22fb615743c3a5551ac8f2e0310d3d246f0b1f6aeaa7060f97c0a6f6b5dcdcfc09151b42f8c6106501b0fecc0a7bab0e25a188d14d17" },
                { "lt", "696e6f599c1341ec8e28b1a2c1b7e57ad2191a1cac4d2fac751f6d71676cd49a680731efa2d0c37096e6b54a3364b8ddeb8eb8a7dca34c51fe5b778b036919cd" },
                { "lv", "f33496ffee02daf832a615072a6434f3e1c3f138e929f84055aca3cfba5d4b7b713f2a9c5e2f01ee9efd04395e11d0b82030ddd27030d4baec5e135f8e14465c" },
                { "mk", "90bfc830912fbb3ba12e720b9254fd23ad859a8b801ca5a5cd36820c4fa4ddb74db475e7cd472b2ffcca516cf90c4362b4dfe628c809329fb04dbff1e42958f1" },
                { "mr", "343f1d9baa26b34f9e4bd48ed0d623cdfaa4050d9738da5f6a38d5b60cf9fb10f55ab84cf8a8d112c4aacc426129431fe2b1e3734b1c3e4ff5d9e0696863315f" },
                { "ms", "d83d3d4cf9d8933c43f2e3ff3500e203fb6b462f475d24f82ab552cbf489d4ed43aaeb886159c92dbb4bcfd64defcd0aae46c7221fc58ab733f6bb591b3dbf1c" },
                { "my", "22ff66d8c8ae49b2e27a95cc020411ef90154b94dcff157898c4863126ca84997cc7b94bc06c084e411bd4c423697373e316bacb72e7521aa168d20631651175" },
                { "nb-NO", "8f728a27b10ec155e67c866c257dd90f8d9ccd708d68616bc263b52fab378f577c551570e8e30a91af54f31f9a85385aaa678d3662c13fa7df78656177d2beec" },
                { "ne-NP", "073697ec475dbbc31a1afa1e670a5a53645f5aedb373b9a95d1e50ae373ad30ac9aa5ab3fd7cb4285ad54b8384398a62a7fe6ac0a8c4d5d7550bbe25ad3dbbdc" },
                { "nl", "6ec59a0d8e601dd169fa16ffc68805f415d566439eb234a955f725163d8cf1dfcf872f95f37dded467812740766713077779f269a46aa66b9d5a23fb92e3adc4" },
                { "nn-NO", "3d64667f1dad2316843f157d5e0702f28b1a9a7b57f250950853aa1851e6ec844cf590c80c6faaca59205f180f19ab6225b4584beb9ebf9bc11524b71c01906d" },
                { "oc", "fc62c2d05b82baf6c671bdb0551ed9460750d4097166ebdd47bd2eadff0cdda70468589669d96d205c63a240ff28935113e1b29d7e110b64e4a048316399012d" },
                { "pa-IN", "f2bd652ac198a2f6b7d2417f1ff2822f2ec438041857199ae6e8422934f2951f58a491f91ebd7ca440891ef630d3e30d12043c13771e0e86c739f274189e00e7" },
                { "pl", "bbe04d9f94b24df08075226d809675e53e511ace77497abe4c59081b52d2f4cbefc5dd6217a39695e0353cfe8bbd49f491f12c8835cbc9baaa3f525fd04ef354" },
                { "pt-BR", "61c8de67d091c5901fee781b7e8f99e0772c043e8693b4c6c56e98dfc58a859fba762f259e7977f312a05b85424e54e69e19217fd737de578215340aa72e1ceb" },
                { "pt-PT", "fefe59a13b83b2adb13a58fb0c2deea2c61a69475b93baec0466bd7d2fc5f7b004898ae9851f4f60a0322761d7ff58e583a71ee4de70eb7e404b0350f1c70dfe" },
                { "rm", "fa3ed24e2b43c803a82f49adbff37c97c6b4944864a82f5b9803ab1df9d6217e9ace7c81967fad22d0d85570d515aded2a1b6c5c4dc38134394d65e11b140d09" },
                { "ro", "23d36529682193cfdaea6c6f9d43fa778a197fa2252c4b5c3b51835748e23b3645a3a7a84d9f873be90838436308e78d7c3b004dc28de99ab9f727fe8dc08d28" },
                { "ru", "9d65b02686151666ff338c02aff2017736560e61602cc0d80d88935544ac2395162beafb0d76160579f59138330c5ca4d2490c2235e4aa892f2049e6c5d01d1b" },
                { "sat", "4195f853a199a45e77896b7cf53dfd6241e42d863df6400340aa495133f3d10720f47726ae21b75817ca534b6b686d02dd743753ec5e3e5d7e058bdf38e92de1" },
                { "sc", "0c05bdad698631b7e33396434dbd5f085dab696420b22e421988553de5fb24c656e1b2de0ea6fe0465f54a0ac255c158a22e1f3e74e326fe70bb89042ec924d3" },
                { "sco", "53e267b7c1b430ed3f736e33c67aeb2ebf7f06a1020b0f56c754f31299bf78cb0a20c82f645c940a08dcf40727eb1bbb75f00ac4a5923879b4f8eacff3882bde" },
                { "si", "782e63a0eaed461235a5d4e3153d97dc46ce8886e2cf5ed045b19b47ae9eb0038ab949400ccccd5fb62236587f9340bc5c4b5302b785b277fba96962d355c02e" },
                { "sk", "1ba5f87f84f909f2eb3a559e3e96fc14dfe197fe081db974b5529f38e389d355965db0016ba8e42dc11ad4cf49c8f7192c44eb189976c6cc93cf9341bce427d2" },
                { "sl", "4083db8381ee5b47d3dcede334b8b1a7f575c4c97c3a43ad5f6c4f79d93d25d9219f33e536c68320f51c0ecdaadeb328806179729607010541def1b4fa359405" },
                { "son", "f2f28f66e62683d379d9b8b130f651f78b78b4aa14779d9b8eb71d55a96b7c91c8ed21428c29d1d591ad254761f47caf1b6c5e029ea341465ec89c2ebfa9a212" },
                { "sq", "b6dedb9e68a91e57148dbb1712af2bbfecfd07db37b54e805487870178492b43cda8311495d59a7e7d13f1b0c4d995543a87f5ff5565b5e2d20c64bfe39f17ee" },
                { "sr", "016865ca8f19c477b5c5443a85a1b820c5564b5d9bc00cbda37ce89e11ce762b40b83ed1c6ce89910abd44cdbd0528a6c36138fa4ec23264448af07ef0fe6c03" },
                { "sv-SE", "871eb59f5eec09d02ba7e9b0a67c6fd981ec93cedf0994f19c81117908b117087ba2ba1e196fbc7351326c477d85db047655e16aba5c0161150347a460ffab42" },
                { "szl", "f6929232cb96d029c93713d77d312549efc0a97cf618c2180814fdf5d88f2a0154b6c1a9ccfed33e963313c7bb6519d61fdf1abea83148cf6ab27b50de48319c" },
                { "ta", "d5a0fab5f7b6befa26513baddf91234bdcc7c8914be8a897caa03f9dcfa3d6e154061c213203e3565d1fc59bf69de808a635e14d9686242047da3d38e72814e1" },
                { "te", "716713f4268672eff925e33b592aae916865142bac5c01724a6a9514c7b5df7f045215d307fe53462cf6ca2a8a237f00b3948661105cb8403e7f29077699f9f2" },
                { "tg", "daeee61b5952ecb2675f97aa3cca70714d5125f9120d50b38fc1de79d7de0a7f3951a78abedece705dbace2bac31f17cfaacb2e7f5734ac8339e5f1cc36250dd" },
                { "th", "b07bb41263297d64229c970262e4aa513e58d1321e06a80ff5a94bea4bdf353772d073585d9b0d90f5640655dcaaebbf1d5af4615991971c24fa75332d93fad6" },
                { "tl", "3289fc96ba8b78ac342df9e9a67a2a4830e26946fd22042a95bd8262c30a67c65f5be1dc406289f3e25f834b9ca9c84f6a23f83f4853ef56e662aac35e832106" },
                { "tr", "820d205d6df48728a29d9f992b28065254583db30c4d7382fbddadcdeb5e91c22e105affd3881035bc8c467b398fd827ff27b33e22a69b108dafb56c1078934f" },
                { "trs", "c8b12c1c393acc4a7fc245ed0126420a0fc1483636754fd4edc15748a6666fb65c8adf1e25240ac6df522ad1d9d1daa9e1df949db71d116338d094966dbdf976" },
                { "uk", "302a24619f222ec69e43e6ab1b24b384f1043af0ca5908ad450dcf15fcfc3e38f6f95ff7c5c63b81659e7d1d328fdf261536c9a4102fb5d342fe72ba3817b56f" },
                { "ur", "9a4ebbb21d29a7516fea023c515ede2181a693c89adfa3612a98c9c08b64fccf16562a44266c5f27794aa49c8fe7f60a2928cb5992ca5a00f4da39105bc16a3a" },
                { "uz", "8e09b41d24474070853a1665f74cc0d8834eb113005550eced3f4108a17466e136f5e1d032a7bba438cfc7bfc1ce35a08574596b2ace66d38087a509d4e48810" },
                { "vi", "bc18b30f7043c366d01c0baf4dc8fccb92183e6f27772ef047699fea68075994a9b19f3e83ccdacfae202aeb1a20ac63b5b1e8a55deca84cc100f9c749109226" },
                { "xh", "41bcde0efec789ac4323e3d2d1586565570a400f1d6afa87d6f36f52d263544361fef89cc34e0149fd0d42eecdad173de47d569a8701282418aa7b439d4f092a" },
                { "zh-CN", "eb65bed23c1c456601da1608cb7a9bf6217e11701479b344ed464e72e88715eea41e5bd04ba8b416e6f911f6fd2730cd6d4319cb215f244335857e42ece495ef" },
                { "zh-TW", "c158eba5f5f6bd708346288e87cb1ae57f9f59c8b66aaee335b3e4d862bdaed500d4cbee5bb09dab34db0d67678e06fbdda25ef25ea05adc655e30a68a813e86" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
