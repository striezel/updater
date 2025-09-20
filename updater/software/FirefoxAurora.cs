/*
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
        private const string currentVersion = "144.0b3";


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
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "15e54401a0e1443df95fc47cafff6ff9d7bcd6cdb75e0da2d56bad87cfe29afac6593e4087e05c23eca26859328e492ad1187867ffdab96d0d6afa9e3190c4b6" },
                { "af", "ee408d5aed734ec061a3273cbbd3878498a119198ccee79a929ac76167f525c1c9e740ba175d03d0711af2cf40d0ad1a2950ec16b558be786fc2756332896b88" },
                { "an", "67ff34fbf288bbb93cf2816fc628245f4cfe97a713ea09a4d4971bce772edd8bae6f8f247fd058218ec3e9699fd1bebc66b389c299150ce466ae2ad95744287b" },
                { "ar", "961abf7dc101bc17d74706a04847898df0bba104248fa32ee118ba5bdd6072c568a7dda07b905c24f88e4b687b6d17786e4383fb65d96f9e6b5dad710f81d47e" },
                { "ast", "642696d83722966d4188e342be66466277781706ec96ebbbc50574b9b039ef0e3e0316b2ec69a9f39c0b26dbd15b34d179c1a57b886719b0c685c979899f9661" },
                { "az", "22137034a98ffb0e636c2358704e194f8f207e43f3554d409fc8c0b211205974feb4e236e4e414f4f24ad1eb19c1d7ab6747a93d467424047d3c6246f2dffacc" },
                { "be", "e112fcddf8844653aca97259003254965e473215e3ddff1deb99d80fcef9259d22895ee7eeeb247683f83eb5c2c3c28e4701c4072ddcbc05f2140cdada1008c0" },
                { "bg", "e24ed163cd448a3d663d263bd4470348ab2fabbc2abb27e7787e4f4496579ae0c5e32f758338121493017e71893b2eb05cc18cd899269fb67714f70c91f01b97" },
                { "bn", "e55ae643ba69476746afe77860b7cc7c51cae841ef4421491c903e4fc7be7459e910de0ebb3f67ccd812277d74820e2cb87cc9cbd75b5e60e8a3d93586130424" },
                { "br", "ce1a8ff5944d6e5ae56d14fbfc9007ad0f159f384acaff4995734661aec1a3208a29df5148416115971bac5f8261b5d75861b403fbc05b2d052e26cb89f249de" },
                { "bs", "ba8c7fa9eb04da21a49c577cd8e9f343d419ba67ffb4abd3a4005b8ac1cabda23249f92be537494682e503ce00db16e08a4122345431252e454815f3e3f52735" },
                { "ca", "d0e0eeabcdcee4e1a48c9d42ed2147ff04917e5a4a44358b15999914ef02e1147b67bc4eefa164c20ba2080b3590eda2449dba23a63c5c9605590de7058ac2ee" },
                { "cak", "8e55308edbc5748f89ac1ce5b3521faf57aac92a90270bff546d027a5689f3b5a8a49a0a6ec475ab5da4afd2f1f1ecdee3e4493ffee04d819a9c28257d1ec57f" },
                { "cs", "47e6823894d270c73c60c6447a7ea5fc498fbad20251803e73bdff62ce75022d13b8683cd5461abeee427f04d69f6d55c4d908e188cd167e4dce5770758a78e9" },
                { "cy", "e568faf4a5360dee0609f0a03b718bfc737df8e9af8152f9292bc1544fe4789a16760da5956e7b722957402144d99838eae6f7f3917d56dd8c1f0db9b050dfc1" },
                { "da", "3fbf9e5c617e15892ceeaa6ff23d6cb23dcdaf31d0fb27d1dbd4abed3149dda826d1c679e296998a2d9256d3cb5065ba10834f45bf191e9f60c6654296b45e2e" },
                { "de", "b76fa57f68737b9454471713c37e9b29e57a038038ee077b21f331730e129f9be03566ebd7ce874acc7970522609f06cabb24697181a6488c8e49dd54e0d80d7" },
                { "dsb", "372c790127a5ae1a9c056a380ca13070e96016c04deb6da5f4115782ede8c7dbb442ac76fa0e81edd59c058273b90b2d6136ec240d0662181764f7271269e0e5" },
                { "el", "7159da441c47bc7588145b596b7ba496fb352f1a4ea34033ad580769850c21301d08d3b328cb37734168771fd8166cb3dfcd2299c0d7b150fd377e8d7b86cbe3" },
                { "en-CA", "04bedb6494f081d31e5279424bd2395c1f224730608eb6cee912d04578409b824bf9db50fc8fe806ddee8fdee5aae9fd9c329ede172e82c6ad2303ffa88b1bb3" },
                { "en-GB", "8caa17f5e51e6252996cd36c6a67f0ec937d2a4b6ad60983ac668814f1297329a8bc1d4b1d7489f72adaee0070d4f861d3e7a33a2a48272c17007b92f2fe406f" },
                { "en-US", "9e245b3299f2ef4a0916ad3bb736508c3198cbe528b296779a89d4609a84cfbd380d962281f64e2ab02991eae1129570d47576f6e7e8b1a5ca5c642f70fe3261" },
                { "eo", "6a1313e4ee1a8ce0cab1dd35207303311c53303a93c5e844bfef12e669417a5be0554c7828aa201d912752f692891d8ceeede7a3e71a9644fafcf12f50d1ccf7" },
                { "es-AR", "9b6f9ea1b653256c600848dc1a90957747f7ee88f08c90c49d7dbfa2f8e29311d9ce789012c27992a76b63a6de4bb62a5b91c29511e2902295cfc7470d500c2f" },
                { "es-CL", "fae0d8293f4a9ffcd4b37204bba72c22b252e55d67948297d17690b1f901107f825e8b971aff3bd28bfd0fc2d43a65c7d7aa6a20e852052961c7aa77bcf5c663" },
                { "es-ES", "3664efcc40697d260ff02ac9c8d3e3e0a06d2ac0a034f76ee5b4c3f946c4cac96df4a2f91a733c443ca6003d3c27a3adf43ff7db58bcde46f0e16ee735984280" },
                { "es-MX", "56718c8c7ea2a6b0f89f20e445da3c60c2336b3eb47d89819435b8b8cd806c0518444f9e6e80eacd2ce5ed4d9f36b84bef4ebe2a1da6b05b1f7bf5145446264f" },
                { "et", "c4209fbbbe203c3d2f8b59e72780e22de8d47c7d1fa33310eae0b93d2a67043e5aa5e8465350792f528728b78043c64aa4b6d3f901b0bc5a0e270f5e508e0021" },
                { "eu", "ffc07b93cf1b60f2bcf5911a6476ddc3879542d733defae0c9cf9daca691939fc7273a4e6e5fd8f98db2e54760db2a8b9d1a5412c080a489ac371398dc9fd3d2" },
                { "fa", "b75b00a141ddfc0d298024982aaa17684fde6993fb3bd5924c0f9665e335700daa6b1591533311cacaedde0100024c9087841602a9e797defb27790dcecd923e" },
                { "ff", "d1662f39b959401d0019980156ca56ab0afb36a9b40af006f1bc4018b7c36010c956a6872882484c6db8b6fe05c91f8b69f6ce0d52a4e88f20697e8e2288d303" },
                { "fi", "3639f9cfbcff3ba16372120917b7fb04e006e22af08e7c968e3d9641ad8b10e3dd3411b74fb901c94958c9f8d04eab4c8aeeb4fb55648605070ad3527decd947" },
                { "fr", "208f20cfe76f30c62f1b33831aef1f7b7417e0983d07a2240f0a5ec1a7d6941a10bf54411f066a9d5b0c57e1de256863e59212b783ad66fe57606ceaaca8ecd9" },
                { "fur", "0dbf8415b3b31978cd2715bd537840cade0e2378ee13ae2a4eb14c9f410e02278180481a82654f27a032f91501e308c8ba97fb92c7b1524ff32e0b77715ca20f" },
                { "fy-NL", "0ec18af7da5e583d4dcdb1ec65d52746a155f1f43ef99ed670c98389fc98b06b9ea6481ca5893b8971b2e6cd56628c5ddae7264435a76153c6aa85fcbe960619" },
                { "ga-IE", "6be2d0053894a0d83e7173ac22584bb053c5ac9e6e1d9bce15bded2939b8fcbc41403b5e3db3ce9674a5bb37dd6495866705e9d5c21f0f77a3985db090107f22" },
                { "gd", "685f7651b8d6a2d4ea485522c10d37d941c536dfa6aeb00dc4a5e0859c6ab91e46795b7e7ecf38508b62f2a7db8369871ab1f827af0256e35ab79f6f4b531fc1" },
                { "gl", "8a7d03256901fb139bf45344681ec546f92894f150c0ac0b7149dc1f73d71106a5a9bed8759edce122b34b69228a1641f13f82056eb543e5e1992ffa19decec6" },
                { "gn", "92ef1e74e146526258bfdc5f5b061a64bce950099a98f31825f9fd4e59dea91d18153e421ca5bd74d9a78b690f9127378e46b9639014f40a8f7e89f3f1cd835b" },
                { "gu-IN", "616f235453d9c2f6ab395f890aabf8b276c7a6cf4511da63e2d442dfa4c11b6798f0486f57f1b9003740a39c81f5c85c0d208ea9064a4d02ddc9fc059544f8fa" },
                { "he", "8b5d99533bfd53eaec649e6ceaa0a1569771ab77b292644f66f8624d981fbc519dc9a39917cc52204f6902b9569535bf37e7fa496e01e3f50ddf677cc173a809" },
                { "hi-IN", "d1fd4d506a7fb6732c521576bc6f340b25356568551a53e80eb3fa74f0422b3a902b6e1d157b0b3ae70415c9b2f451398d48866b0cc2256df13c9329c5966bc8" },
                { "hr", "4972aded8285ffcbae0b5804cc82d12c06671932f014df89f19215c34b524cf3b0e4d071d2f5306ec273a1e27f533c949cfa44633da75c92d5f13988ec4c9b20" },
                { "hsb", "86015dbf9a7e3ba4502896a60ee1de21b9d4359806108ec8acb0f05d766daa1a028b0ddaa014bad13be47dbb7f4b500f495a85c76f6c7d96652837bd7eba953b" },
                { "hu", "0584f36077d1be1d763e2c9af0819b7a200177cfe83a9549b8b3187b0372ff9312e96b537b786ebdab3775bb361b57ad93a466d28aea059a274d2c6b2ae5a7a3" },
                { "hy-AM", "e5d863f5a43333967d6a1d679fd2f15c47cff62f0eea0bc30ebbe2354af73501e7c91464b1f8ed17ec4f37964ffd2b5f9a4c96c5a6cadc6669944fe4b7cc574e" },
                { "ia", "7067a9c543e1ff5e3873cdf87f57f9f94f6928a45124e847600875e4f9d90917079b45ab5ed00c5e6ba105854dd7aa9eac03bb11813bdf03b08741c4d1f05abd" },
                { "id", "7e56ea3095dee7b8ad43760f86ad8edf8b1e6e65a02c9cb38c7713145228a00a03136b510fd7d9b80dd3160fb820994a44fe0ec2b76805a8140ec858813a77db" },
                { "is", "59f37884ae233ac789086bd37a4bde915e23cf5c616809475ba31d0ebed4fe117776ba8d433c358519ce2cda41f2ee92ab31b5de1957f720c17085abd54fbaae" },
                { "it", "6a9d22bc727b84254c4c1a3f207520bc30b6b0b021b0bb58a6424d904e5d7458dd473c5b9f549a6df01e80b21b34367adde7298b42ca69aaf6c47011a4a2c034" },
                { "ja", "be95f3bae8034f76fcddef533519c93e2dfe0a52af1d49f96f937fbfee7a402813afb863707207a6896b979d6a588becdde2a1bc845f52043af8c0a856defca4" },
                { "ka", "d7e86468cb9dd30262d7ab9fbf1732127e5bbce15f0507c44ff7a08b7f2be9abdedb90c92fbd25338a7bbbc5d839b881c6d217ddadd992df9a418730e4a59f12" },
                { "kab", "491d179c3989bc55c963918109a4fbb73eb6fa2efd6f5a8deb4249ac9da58ba92b5ea54b07e4e4a2fb82ff188a68da1090dd16795764fe3d06b7338408fb6681" },
                { "kk", "9c92afb7253a44121b7ad4c7c9bf714b64dddee805d13c1cfed81ed568824f8532f615013cab759649fe0ccede4b970b551310de0fe98a1fc9692e1cb024b4b7" },
                { "km", "35a33722f5ce1e639d93d72a7e090cf3132bf31ceb24b0a4cb59f68cdf424c256f015fdb95004ba2c254c1d41cfae0f2cd77bde789f1278f64c842a0f195bfb4" },
                { "kn", "56fd91238b0065e94ade067ad165831cd44f302773b9ae3b07491ae61cd049a8ee9fabdc1814888ef7fadbb7cc974f119ef2b2328c65e49b8f2bf6925b82a100" },
                { "ko", "64b7499d41acaf778c8abf2dd80c499c9f92d930136b19bf2e534107a88f426e04ba1b022d8865cf33c1ef1b7eda06e88ab094f895164e48b8b7751e226e6a9c" },
                { "lij", "29e8cbe8ac68f20a1919651882aa446ef3113580e459cbdd197318cc5a200378d5d0c78aea12104f147d92a7ec4f909a5b47fc4263fb711307551ad4be001d45" },
                { "lt", "aaafbe0721577d76f6bba82cf735db6f7c80ae7ccf282b52895b88bcaa3b9b6ecd1e02b70cb739ad5bd91a3ffd0e5524b7b8e303896d80db2ab9c25fe34bbd21" },
                { "lv", "dca347d93e29fb9d5a8b71bda97677af7ac74fd2bb1bb834dd836c35fba8e7bfc9aa31ff8f0df4d9a8bbae4c96f66900b03baa87235712068e50020c3029d5d1" },
                { "mk", "c21bb70084dd0f4d3f704de45447f49a4d6636683440c340e5124a547485f43434bb7bb316cd930719e1299f7ef1918ec82e99b7141387d18363d1683ecef0d0" },
                { "mr", "fe418a92c7149762503f335f48cb2b45420b048bddb0fcd51a37ca11dbe8c59f4bc8664ecf14451aed54014344f505034a41c9fe4cd72ee5e093484cd22e6e2f" },
                { "ms", "7e6ad7c6b82faf03659ff2adaaf53a68bd41a2c7d027da44b50ac86bfcd1a7d01919375455517613e6d6b90328fd507b26e897a0e5050ce2297af2563bd980ba" },
                { "my", "979cb36b1fb3ef6f42b8b2ded63776cb893c96ff84537c68c42ca4ab35e8c6632920748777a20114d0ba24d1a79274cdca8ce9a7af5924764d3eabc7176b3d39" },
                { "nb-NO", "a4339cb28adfd50c61291ede32f28c40db5b074644d80369e4b81c29fdb8a98c3d3dfd319db3e4ca7b29f455bf4de0b82b8c2b3d24b612ebec8ed5e83c4f2518" },
                { "ne-NP", "8b07471bdf78ac37a3f9b2cbf1462a360d3c95d529a263ff8c2a319b4431296975b0e45172039b2c5605bae074a2cab33130b51e483e5a5d8e515ff580a3a85c" },
                { "nl", "09b6d35665be051236028cc1d2f8b5aa87625e3e5fb00a660f0c97f5a2c54cf9c0c8ad90493976eecb00db9b92cf50387d9a2121098d4b14cc3f9dcd42bb3696" },
                { "nn-NO", "993009f0b5fb1fd506266b11a423524d694855d1e64d7a1789ae4d2d4750a1c4f8d0a780a31759213c00acc07c69f0d1a5efd6c4d91437d057c0e4fc5295724c" },
                { "oc", "426df329250bc4d5e79ee2b7e493a71d3c21d184cdefe58662fe8d5e0128eb298206f70a3df4f3ae35b06a49c9ffd1d0da229238509135123b56bb9c082afe16" },
                { "pa-IN", "7260f856d7ad197cc6260ef0fc48b5f314ddb3d01d00448b8a78ba866a051d44f680310f584846e236d485df5f627cd1b7a4d3dcb43195ec078b95b8f4e19f59" },
                { "pl", "0e5625325f963b7ac5aef9bd2640f5c8817e6c65400ad83924afc09f197de87c298d2970cebd719da789289647f4441b5a1bfbae67de7a9e856e0b1bf43ad367" },
                { "pt-BR", "3ee6c51dbee8f53eb0aa27e1d49ab1b8d3ffa166736f0047d4625414960b7d7dd8add32548252b685bdfdb9c877a429be3f8bfb76f8ba4f4c9ccd3be141a750c" },
                { "pt-PT", "de20446206272ced3b250e862fb1f5295e8f97e4cc14bfa4dbdf84b260ff4806cc72e132466c196822bee87c29302b4cc7ecad851f47ee017b593048429f510a" },
                { "rm", "598da7be57142faace9cc9b9e208d54a2cfaf23c29c96de4eb63d1d5f0454a808b70b416898682809e3a89a78b3dce1fb28f1a99aebdfbeeb8b95569b4831b60" },
                { "ro", "f3362dfa60cbdd1f55a9a56bfe3ce84213036503bae30135ca2ef6b019935b9f8a334539dc9c6758fc2879f118bfe5f1d36edbab7caf36c3590da9c763366a27" },
                { "ru", "fc4c2c99e426da57514b1adf89704858585f5462dab2b70aecaa67bf77fcf75fcb10cfc16cbbcb594eb230030bdb061421b8224970a5af75712716012c2aa62f" },
                { "sat", "f0c4c5a86331f7ec808f4b30192408a41bf7d7e00a3374cf8fdae796b1ad56a2ba8b7b4c7ca78a6bef6211dd8c2e1a83c2ce9901f69c225f1da462ed5163d87a" },
                { "sc", "7801c32b317af84f0103cf8db242623eaf865ac21c898b065a5f25d174035d3ab241274632344ac5264e9720972d3a783a96d94a69c6a6ff8f01d2be90b973cb" },
                { "sco", "31c85a79c1d421f0638697907a60a696040ed60ac25a5dccbf5ec71fde6825274574cac25522f3db4e26223db25d07d91e6153ff045b46ac8c3771ca053fb11d" },
                { "si", "838251e89bada5acfddab0c61f4d6bbf3a85676dd41173acccefcefc9746e3aaf985553beb5b991a91055e9c3e50d512dfbdd28b0cd72e4f620992fa4f0ab068" },
                { "sk", "d2155d869a6df5f124095f92e30493822bd7b1b5afca0b5e0da3bd3e5b5d2b8929d863e5d0ddca6b919a66c19aae24853d40b4dfc551040af405b6963fa76e52" },
                { "skr", "609db53a683a8d5f098bd22751f7cade95be28a9d0cf8c0421e57dc5b7c43204aafc97fc1c5c706cf884acb5c593d0db1eb3b63af41e82e4fb9f83af453638d0" },
                { "sl", "2f4b3f9f85d535e5b8e73ee01f3ddaa759ec9fd2aa90458c287a00869f9f75f7824c116eb81c592c0454ce10d75cde159cbfd7b82a8392f349662d03990c6f20" },
                { "son", "5371b5ad38667006341ca41eec03fa1d7521a87b86527bce60b15fa589a4ca1b94f90a4130c45b05439d0bc0bc75c3f8fce31c93b5e5eff52117a85119502384" },
                { "sq", "e4b49e6acfdd04c83c9201f3443d8ce6da82a579aaffc0cfb6d317e74ed0d2b68e554c5bf3897d4f3766f6cc526a90f0f9c15505a1371fa25c078f02d9fc0ac3" },
                { "sr", "034c275a4644c3e43eebb85140c0942a9004f2470b1d79f182efe3f6675b9c9799b73a3d22834720798977f764a500a7d82da7386b2327edf14759158d6b5a76" },
                { "sv-SE", "2030ddabae670dc603d9a4712c1d4b616c26aad75e87746b802976b17a81e25954ae9f8af6be95011ad1d6d32d91faa5b12f533aa4b3ba13899e4d4e84e2e2ae" },
                { "szl", "a08a0f68609388af2f305821938ba418f693ca203173a7d377e0a3c98dd72f75be59354413474b9519a45d95cf5d041e9df740102f32b3099620c7849922392a" },
                { "ta", "d8326032cca05f18a1bc8445b1d97080719da6f95c1caeaf9a8ab609931624642781dd4feeeba31bd7d42076a0da6bf57763ab8b40e3661dcd2fa456f0329454" },
                { "te", "c6e74a4dbcfafbde82fbcf26c061e5bb2bae04f3d5145f5f9ee21603c3f1d39bc972b458732faeb7e8298e10a6dc35ffa2815047181c89a6c75f66fea31d9738" },
                { "tg", "8a4508941579708ee88e52539d7e220668c93fe38b79a4ad0896705cc5c3e05cad86c2aae9a8765e1eabb76628929b59ed48276d2eb121d747c0e28986f930a1" },
                { "th", "8a11fcf7b8e6c61d66a280128c61bf297a0e80b62d5893ab6214573009bfd0dccd138e52bea723a8e57e52539b7079ec3e96ba7aa2043930857a735ce9294d41" },
                { "tl", "04bdca9dd039fc13e7d770535d684d4efe278687421a8e909ced4a043a78ce8469b04ca1fad5cc9f46365622a828c8bd11b8ac6e7c452838e7a18c6dd62ff341" },
                { "tr", "ac8a6e1422d1687c57e69e28aa9945947122f124f4c033587eeb567ce14bac6b31fb73735bc5ab1da31f49ef3622361b4ddbab47232f254f43eb9dfabbdf34a1" },
                { "trs", "ebb95d2c574b550987409c9a1e5f40093fb0f7f73bd0fdea33dee3fc1058aab6c1614f6a5c3180c86e465128def9d8ee48f6b38489cb7736b378fd5e4de50094" },
                { "uk", "bce1900392ab168b6cb0ddbc6bb1ce66cef8a4aa07eb069e33ded4c3994bb73fae85891317b5467736828ad3a0d3868d3e8e9cd8d4220ce58ece6823b8e334d5" },
                { "ur", "094f9581dc955bef5fd57c3715eef0aa97fee2c007c00222f51d7c8c448b047324304554b7813e0401fb55711b7ba07417d8e0b8051aefb48ba67db6fddac3ec" },
                { "uz", "2f61066d4b9728291519be8440755e1473fcd532b48eaa3a9dce619706c987c2f2864b143b72e1bf0d85e6847ef64acdbe753a75f10dda4e612112d3fe14bef9" },
                { "vi", "efa5f9016bdf71cb88c7357b356d58e8559cecfce6cf99e06b3a8b2d9728d95663032c3240033011f466dfbdfe18ded84f7125bd6b7fbcfb0a2b08e2bd720a80" },
                { "xh", "9646ce467c17ddd6227dac15bceb0196698d56ab6bd4f6c865e219e7c76def2cd25e0a3622333bcb279497c212e73ba2dd3b2ff5629ecda83ec881dd6e54f29e" },
                { "zh-CN", "78f09d516f61dd88a38f02fefe98658b843503d6635378418b1fc83c52cf4204fad011ffe39ec73312aeb6e84a53d13c46ed15c971b4bc487418fa8a807d44f0" },
                { "zh-TW", "111d01168ef316f0cf5cd9a2de57cfee4e39b513a30c505f2df7a84f4e18bead9917f98546f1ee98713243f87cc7fc310d955a646e2f42418afbe84485bfdc9c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "799e5e876db97098756e2a7ac226fced947b3ea6c191e157ec99b1f30ee69e3487b956b5723386e2eaf920a60e32bbbaef2c2d72556502d70d1314837912de99" },
                { "af", "b4126ff59848a1f29004b343c40f8df6c1bc282e4550e752a0b920d5a1338bcfe2de7479029e81d2a0d140dd95714ea7498e132bba9b99159aae01e2d1a45a60" },
                { "an", "c63853954061b30f650c32c0bb08178ba347048ea832d7eab704d48b923b56a4562248109e982bcacc0f74878c7d6c9404df1ffa2d5ced4f1f8ebde487c9f79a" },
                { "ar", "0a7c8ef660d80f5a18f96ba695363aded4f5f7ba48aa60f0c11eefc0d8993e8c0afad9ffa2c7b81f2688c9bf8f7b5aee4be09652c75b92adc4c0884dfbe9541e" },
                { "ast", "2d80903ae128a1cec8b0b53dbce3148fc773133e2b1bbc630b36d9a56c954c24c50e11db96feedbc38bbc336c3d069ff51864ab8d7c1415e080c78036a775e5c" },
                { "az", "5744cfb5156e01058857a2f9238754148894f5ebcb83de309055e668d6595dd45a8ff049f34cb9c57b9e84950ed4c36b7e69d62d09bbf47bea075c1ae7b64e15" },
                { "be", "225ce85555fc2b01dd77902ef7e59b1f5592a13a615e099debdc2e5d3506632cf786fb3f8fe2cec0108e8978621a6ffed8fefd34cf55ed540972a5fa74222b83" },
                { "bg", "93a77e2889417d8e0056d60074cc7e493d1b541520008f06bd9c14655a80128ecb617680cd6f26f7a45e143e04f426bf2073362eb87ada48315a44fc9e5513c7" },
                { "bn", "448f4f4068bccf4ebacc7af142ab606a176ea5940ad327640ff2837c46c11319f9927a5e4bfc44c1750b7694b26466f8ec50cd5fcd511f4a5c77d8eeb0ff1f42" },
                { "br", "cd36a3b0d818268d8d9b74b40ca7cb49f8a83a058ea123aae6391d1c81a28c1ad83c87465e7610b7891a4fc7d760927d04ef540f32e0d2d4b6db326328009ce3" },
                { "bs", "6790f62088bffa34641deda47ed485b9c7d0500f1378b285172799a0a587cb560897568095199a99d8eb92a10c600390543c024b725d74e154aa849890da49ea" },
                { "ca", "86bdca8e538e4221d1eee4d6bbf5fcf9c3fb70f28754fdf89b29bf4ec14b6aaf3915f96cf005b3f454050ab37c4d5990dc23823e663bb5677283863dc113762b" },
                { "cak", "0cbcc995f47a91d0720604a5b45066864cdaaff1fbee19cda6d97706ad54a5e0362e770719ad8b16859de8cbda6abfc101a0b33be2a306791b663b5bb6e6d158" },
                { "cs", "326ede26ddcecd1f0679b0c245dfa87a33e52bdd7411ce7b73e7317947d5fcb6028776e7557209043329c6cfd2086c9d3c700d56aa618ddfdd2e12d70268f899" },
                { "cy", "6f6562bccb25ef60a2efc04a2f16222bb093c7912c5810888d7d9a3ad31117191d8935026dcff2610107b87f1d6996dcd06d2c7102263badec9203b3c90522ff" },
                { "da", "9a32f1f40e900655492b753a7d3d21684868001d9e266481cffe6241890233df35cb9d6fdea239da94324b699cfa378b5db4aee3408c80d31497a95f322b6e46" },
                { "de", "0c988f14d0d684b123c5e56c15e78e7cb35b3d221992dd5ccb46f6a42a906d1147f80b7143fa9ef0cb49c8602ea7868b299619b77fcccda36f86a38fdd6b4b8d" },
                { "dsb", "6ae09e6db2f5232aed1cd53643b65f026fd6e1a4b1c54518792a3f5ca02ebbf22414ff842f85c4436f5e187fad33a8efab33ec476b12ec19c356c66f4f9f82b5" },
                { "el", "f1e0663443d8721ff02d25e02bd87172cb1f107abeea8e7739e9c20c66d68a078fb56985fdb56b864c667cb163929a74add9b0225c87c02c33003a60d51ac006" },
                { "en-CA", "e392b5cf9158ec467afff2ca8b7aeaa5938ceaae2daea4bff1b933d9e9946a5368dc0026a28bede3c8c8e41ccd29b6575c324c64d842f49570142c562e818fc5" },
                { "en-GB", "03f7d9ff121510a516bf54a4402c5e2e971cf5ba8d55cb0bdc39144d9a79e943abc11c0a74f1a6fb4eb07acb34fa182a9950db104f187b29fbaaf8413b56f4a6" },
                { "en-US", "17298e50607f92a6b9a2c0f024850bb614ff461a37f6956ba031c38633dcd212b4c373965fdcf68d5ec09832c638f0ed3129305a48fb5a97df6d01635c21f132" },
                { "eo", "e6810fa3bfe271dc223e9c3d32c1b66353ff42e41b1ec1077264a3054c10377d6330cd1871bbef533376d3bcaec82f782f9bf995fa9ea687dce829a0d952dfad" },
                { "es-AR", "301f9cc45dd2838fbd6c7d540b7363d51c24f1520c4d63601ef83b3625be609b114e5aac3f69f0ed74b50d8af59d1c1ca3cd6c0267beca3865ac2bf84aaba679" },
                { "es-CL", "65ffaaf930adf6aaab6a224a01fe95a37f65f7dc9ce85a81539c1525699331c8c98b16ab294e4d13c03b29d822f15832ec4793391b211445c0b344ec0b7b5c33" },
                { "es-ES", "b422d54266653c43c886d01d44de265e3670bb16ff672bd14b24d341146e0d3419869bbf3d66954fc24d8a26ff6aeec04c4606e752443a39cdb18f23d4c47fcd" },
                { "es-MX", "a830360677bbae411e827e626163ce7a0b59e58f728f32376ca857b67b5d4ad1d2bf021b16cdd5ab012a6f3ae42f5d49aaa6da76bfb4369fcfab1e893e0b56a6" },
                { "et", "6d8a6d91aa51025e58aebbb133086f5ab9f6949f2f7c64ecb4db0fe212dd7197a3c1053fc3046988887ee586e8c56d10cfc854e9a49037c4f5117bb78a8d7bc6" },
                { "eu", "2b29df6246badeec56f0a80158b5e3a0d583506722c96a560311aac5d1599958f7d80e14a98729f61a5f177b8e259068a1df699c89bcc3ab9376671339e1466e" },
                { "fa", "08a185322998fbffe4ef9c339f1e511e213cd38d48f2eaac4a0d4ca880464ddab05a346458ff106739f50a4ad3df07e469945ec645698291f14287272f1a1e22" },
                { "ff", "ba8feaf05ccbd9ea387f40c911357aee99a6f3de4f299b5393d2c9865a3f334a985ea7e5c8cf8a9985c3861948d3d8c94e241103dce7b1dc2420f7c1717b02b0" },
                { "fi", "e7dac32a02cab5b22ae3cdde33958fe011be847ae519122f8cbec9ba26b918d606d54efb5b66aac04e86292706b7853ba1ea864cdddaa591e5711f097dcaa89a" },
                { "fr", "9f1bf87aa9f98a96d1d8e0c7f7c91f5f7b56f6998bc66484b0aacc0a45173a74b93bd1c6988f3748e7868a16dc6fb6272e6d895682d8980d7fb620d10e246a0f" },
                { "fur", "e02f1935731fc45b41b477cbbf9b0631d2a42c006278544b17f07255b4c91d878fa74eab78700ad0434830603bf80e3253504c7ba9ab6a09b6b29cb3ebb6eda5" },
                { "fy-NL", "f1e43b82a8c4de0a2e1a2bf65534fac0a678ca110e355ff24739ddacd5b36b17e8c6f5e74e1fa830d9a499572640ac576402f736ebca696d77f61f38438afb73" },
                { "ga-IE", "eb243f91c9df519a60ee90e4368843542b7cb0ab55c376f09fe6b0dbb5441ddc03e2d5e2e6e410f1a2eff8943107f08630094eaaa7576665a6cbaf6b6c7c57b7" },
                { "gd", "62ab543151613f0a98eed9371b0a8d18a4cfee42e2232c5f85e3fa3efb26d07903ec5396f1892a3b5580e6510e7ce7b6ee39e0ae33d258a9630d36c7b4efba1b" },
                { "gl", "69f2157fd731c81cc48a4217422b004c1616e43f2fb66e717ba533043861e7fe0a3ffbe6775fd0de2b62ec1592d838dc9722e17a866a1584ce6a0545a169c311" },
                { "gn", "80475183dd78738b84b265732c567ac9c70273e4a480478ab348ba7a676544b15c00fe1551f9d258abb7d6e6c6218860726a6bd5b94c49117215aa8694281911" },
                { "gu-IN", "371ac0df6b2ee3658d8036c9973a71c69ebb58224e5195ced66ee5e3b0e710aee37c664d8f006b728f49b4642df1282eebc65d211e17ae8a68100c946edd96f7" },
                { "he", "60dd981a5dbaa9cd3c625b7b644291f1b07b365c59990253928826a21a6f464d28c5159ecb9bfd880ff875f34bd95c352d713e95e085677e8fd704827f191126" },
                { "hi-IN", "79c9b0f604edd98eca820f2734b23c638a301d150318613f41f194e3f10e63cfef74276af5437c743621298f410c154bee6266ea891f1e03b68afb100e4060a4" },
                { "hr", "b9d3eaf7aebdbe038c1b9e3d30522f71ce1dea1e8013c43d1914dcc1c45d42ccd0558faaab1f3e2c2dd115df140e8ebb5c34d474f79f1e5c121818f0b5c72992" },
                { "hsb", "a5a8337a15cf3e6f4c82f844516f04bb0dd895d31bc8c209408f1cf1972315fa2373db007030e8e227374e326500e4dfcd4caa922eb16e3b6de4d12ed90cd49b" },
                { "hu", "14a3defb98a617ab6dbd118d3e27961018ac7ce8ff5a1fe4fb38b5cc68b4cf927e8fa11a55d0fb4fe9988bd1d785210db534d04bfef324a6b6eabb235196d535" },
                { "hy-AM", "36f931ea0baebc17152d45fe61b7758dc3ad194c361aa5075a40c11f82df3aeaba78154abe7db6181ed733b5943137f768bbe28c9f15ea9d06ba7e89cc597718" },
                { "ia", "a7fdc76ec99daa9d9fa489c320e47bd1069c556bc3f9ce2d54a2d39cf040229138771812eb721aa8c6c806883be5422a48b5c4ecde9e1c200585330ac913c17d" },
                { "id", "f8e6c34cda6b46a9a38fc167e1a22fe7262500b72511f1862e56b766ca59e27059a5506161cc798eec71e2878e4f19f3b9b400ccfc3e269c1dceb4d9e07fcce7" },
                { "is", "4606e3b4ea86055ee93538c68007b980eb4624a3c13f16bbe0bf44e4160e8a68a7d17f6ec0ffebd6bfdaf5ad8025e17d243d2b271d25a229422d29b59275b576" },
                { "it", "a944d9053aeb0a4911b802be543e21c19e5faca156094ba2a149cbdcdf364ff555638874295a95b9c8f7ac1d0a0e7f13a4a253ea41326bc8b936ca9950e47d0c" },
                { "ja", "f77c130dbc2f18c5b9b88c35e7b9e3e3da5fceeac7c4b9c361492e57742f990ea627b253d52f0e67ad8188838f19ef88a95421ff001528db2270d45fbb02f019" },
                { "ka", "e16d408b5741fd748b55a36c9f43f4e36b9b7b4f03e74b5f6e82c4b93dcd2c77dd4eabdd047a079efdb3dd369e4fbbf4c5808c6243e1fb8d5432ee9463ead2aa" },
                { "kab", "bc290e2a6d846ef33b4cf4d1307d1c6ed2702fc46cedd9454bebfc9fccc5b97dbdabf031ddd3dc5269fe51eb58a7fb899c202a03f2c099f9f868750fd21b7979" },
                { "kk", "ac6e2473b6e4a5381eaff59ca11affd5c5bdbaf6d23178b6c2dd7971df0bede84ecac7e0aed17bee9cea0b0966580ba5b7dd58c4aef111ae9f8daf6b42aa2ec6" },
                { "km", "ca974a1e3081e3f9c181080780689fc33c6c730eb04989b811efe0c1a1051a2eb517313d352706bce9993aaf60e97e3a7cfb5472786f7eba81f086016ac9537e" },
                { "kn", "031b1f3a080d885d210740185f985e681570289919b1d923acaaf3cdd754789275264a369c4b95be59d4978a97968fd8065517f6673ba85fa952f109fa760ee1" },
                { "ko", "ea985a833c05bb16c50203065709b371fdee0acbb49f12d3e71403e9b8a38ec491863baff35e57ca1ec9f0677d1f80e3303d3709861128c8d08b8948efc4a13b" },
                { "lij", "304db1188201c0fdc5acba85b520cc7cce9efd2c515955c90d109fffd79c480174579575a0e0d5fb79013cd57774474c841745a0d85d15a1fa5e5690b9df154c" },
                { "lt", "b3c35e400cb4075887822b5ce64c0cf3ff7212924bc1e74f7d7c0bb5c6a6a02d0237610b5957da9cc876578642995f9ce81296dfc5594c1a39483c10cda488e0" },
                { "lv", "9d430e467159d6a8b7303d1072f2df9ce783a736cce2431a71b003af2bad406dd6ae5bbb8e4abea3d334fbe18a4fb1c32037022b0f645d9888ad501e5398e310" },
                { "mk", "d316f8fc9749262e3b2db792e8e5114f9307db5d8907743b026f1f63d5adddf52e7e6fcc35206cf31707cb089f25abe9bf3d2320cb069493d242f7515a9ea449" },
                { "mr", "8b673fc12068a5126fd04d4d236dfbf7cfebbbb1903f87dc3035030b5c226b90fb3d81eaf6500c25f56ea51c28aa0cbe730371bee8f78f8341e22cdd1bcbbe9a" },
                { "ms", "06559f7da697e700facc98d13ebbf6d71ebdaa0f41c3600feb07306cfad11c8d24f6018ab6db5814387a78bbb2fc345f8ca9dba4e5dc9fcad14ae5c568c04990" },
                { "my", "1b06f07aded792ca256cc3d2ed866b0fd5dbe21ade8da94f101d4e12761e6effe16ae916fab1855cd8a0ad90ac9fcffcd25f9305c1a22f3f5cf9e3e8b8ba627c" },
                { "nb-NO", "b45d4e9b30fe464756ae489a974b968c5b13599a5e95644f3ed1dbe716c8874d9d3884bb3007abbdf38290f191ce277e96020535c85ba87848f8c22d6b60a5af" },
                { "ne-NP", "efb1f7ebde6a0959ba15f2aca2c517b0d53fd0f0a7ac6f022958ec1e926da5d8f8154b4409c6e1e300f7a1c3d75aeb38057375a4621f23258892c12c84cf039c" },
                { "nl", "78218db253b01b093c9fc0798ee5dc05852c79e1ea5768834ded426178bbb91dd9e6f4d3cc336178fc72f7646b1973ff3690698415f9c0cd73be8f6ad20dce5d" },
                { "nn-NO", "fbbd01ab2d1f41876971aad135be73120e3614bd83a4f2717042ee83839a30bb8538d5554ebfa95f56d4bd7ae42d4ca1b2d04d81733f83db6919e8006295afd9" },
                { "oc", "dc32f0ea79e464fdfae6090de1227e730b1b565a9d45a25a79b19deca6908a742db45fe9c2d358b291159f6bca2a6f9a3924d74f8eebaf6ad0be0728df4790ff" },
                { "pa-IN", "350e0792a96d2f1bd7e552c0d33a6213e61230add9aa23390d0eab5034190b01c6728ffb8736edf6032ed816ef8846ffe63e3bdbf9c2a3704ad107a7b9c0c6d9" },
                { "pl", "3645a783b1da3dc96ce236a04c0165ea28e6621955ac925fc497b05ebd944b6a5fef7b315966f85c83ecad6bc3a6b41725262d1fd586c1c22a0d87ff592fe099" },
                { "pt-BR", "c0d74fe0bf4dcdacd432e9fe1d4846253fb6d2e051a5575c0c61d314a3211e5d7e0c29d022b47c27e87b825c17c413b5a75d8806b7e84c389862f9725bf1da56" },
                { "pt-PT", "01ac1e6d585207dc64e17d1f7520b0f9c4ab042c01a0727654488269d5935ea28dbcf255af53f3c75648180ad2e59a5aa786bb2b03be1eb2e4552dcbc81488e6" },
                { "rm", "78adcd19f6f2d4c54d8a78c7f085e2a2487a9cabc006315de981e3d26e4531cee864ef20228d8347686f4e21327a958c5e0fe031312c1a869d2aede84ea0d4f0" },
                { "ro", "2d75867cd48977b487c2497f9438b8e72338d3ef4d74f3b79993529a224b74c6097235a019bfddf17c6d02ece3d8142b58fb1e7a14ebe79139b8defe38415cbf" },
                { "ru", "8bf25e9e941da6554381f9259c22b566b9dc12d2f17213aa4cafbcf3c45decac7da226106d6a53e0fcb92847f89a899affe94a7992e611fe3e3e0a27c95190b1" },
                { "sat", "dd2e175fc559c025ff9f69f9facb5df0543f9d5106908561942335ee1e353adf953adb3b389a14fb53c1655ff93517c3919ce32d55f3a9d671df3bf7615cd35f" },
                { "sc", "369141815b7b71e197dbfe5bc5301688745c062f25456b38c59a28b4d4d33f917a93e62fcceb489e34771d4127dd3240faab180ac56a9ef2908acc24edf50c33" },
                { "sco", "cfcd8385c36430420cd8fa1a7fbb39e74c99665af6a14eb7e90036e39b0f4e808968bd095766242254a61b9518fef37f0059d6207fd25c29eab6ec05593976fa" },
                { "si", "529723573ceca3d8c9b0ae75b97f0251cdd4711e83cd64572846e1aed7677e1ba1972b78486a2f0e5ad1241ba000ac45550aceacc5545e3d0c5108313ff737ee" },
                { "sk", "7b006c2ef928e483fa4768992b551e95ed75e3c78b92a3f999c9a97119f08dd181260d437a74227944fe90d40030080a0f70dcfe52dec84cc6faccaaa549c9c7" },
                { "skr", "592f0071fe92c7272795668c3b9d8952b9bb8cc0db60d9f884970e77c6dfb83e3c00655399390fc9b94662b5f7dbe63b42c5bd24b59c1f643f135a7967388929" },
                { "sl", "59b0d80db2c647306df1a136707112710424d384e2f5d9b8b5a6cac000632eba859d6c9c2c43b962920cc888effd9f4a3e2b7940455e645fb2101247d1eb16ee" },
                { "son", "cfb95ead55acdc2eb75c16fff9b7f3c47a4610e96437e571fa1af7c0c85b0fa5330999c52083755508e8c0f3b7e7a5c1855c0e6045e9cff344bed703051d73ee" },
                { "sq", "3f0e480f246c8a12d8e5334498b2ffc1a7c4d9cadb27a28be150965aef8a1db74d83b47e1d24a4bce691530ff4ea38daac7c4d4460702868210645b61bc9edc6" },
                { "sr", "aa2a1d52e4ef2c5cb432f5942f2893b401396c5defd0520319758737d9507260cc08b8a809a9abb6da0296cb3e41d1405cdb58a5967c6a235e4254863cefee28" },
                { "sv-SE", "af77fc05ed6d2c68b8c85ca62b254ba325f04a90103780ecc76f273cffd8189bd0ef89d85dff3629f7f8f350142a38753fe19e9f2db13e5b653660987bb483cb" },
                { "szl", "2ef2d326d93a762b876270fd07310a651cda92fc5d1599a47ff84ba44b4764b1be73f6a725b3e0c2128ffe26e91a45341ceef064eff5e4b841c3d1baaf82821a" },
                { "ta", "af17f0eee1fe59c890b3291e8fe03a2ae1e9aa11dbc641a75d3af18ca4d90b8441562a06b4cb1034139dcb98c8efdb25e86d46875f1a3ff19e6278c6afbd3d1a" },
                { "te", "2d319d34b8b66a8feca85d61de33209045d684e443785a07fc23c4708b8ea06c2cbac636bcd1e5bb5a6ef1d6da390dbb47121c764fb4df4c0e6312a5963f9e0b" },
                { "tg", "f4ce51184ee1c9928aaaa114e8e3bc232e9aecb02566e07290aa2d43253787620edfa8a0f827839bdf57dd8cb333c423601ac1887dbfecdedd363a3bc4712036" },
                { "th", "6cb709511a4b15e675a5aa60b9a2f2aa3864f2d21efd6f2effcaf490ad598611854de078eb71a09e3ccc5b7ae6164b183439799236c34c78f0218ac008002acd" },
                { "tl", "67b1fb1ec36037252adb57eec092289255fc1802b900748a16cc93644cd94db33aac7c91c6926ae6d312018b45ffb2c69d6cb6e2a855294f631f649f14f1a946" },
                { "tr", "0661418f69cee22a80ea40a156ea8c9bfbbe9f152fc7707e245b47a102cfa373644603586d834ecefe4f7d59ede315b9d2d61fa872b879d38df0d0793902a913" },
                { "trs", "d5ce54f257093830dafa638c324fd2bde07950f14f19eecf3c43588e5fc10d296df03cbfb2ba0857a4227c5131d4acb41291ca5377f66cf27abef18012c7043e" },
                { "uk", "2259c1ed98654ad427243fea614cda72d3b58390a33e150c094c2ddbe2eecd332ccb8088a9352b053c1fb8b1c5e284de4de5c7e23d6155ee5eca79deec54e7d3" },
                { "ur", "91108e844682f2a444da4064a8bb6fea2f3c7bd026f23714316af259504b67c8e2c7ef4b4f848b05d87e972d86334eec308c647459cd5a02f1aa623f28d7beff" },
                { "uz", "c949d3c5392bfb416584dafd3fa829102d4cc05359a853d4f01ee06b9102360d665fa0694b74d97bd01d0a50680e19ca29ed77613c944ef2710ca11009b44ada" },
                { "vi", "d0ab4d6d2aa37839d0956ea2048417e1f6388188812e240d43101e9f68aa442fe68017930da49296837db259af63098b12ca226406553fb5767c63dd007b1c41" },
                { "xh", "f0aaecfcc8e3a60a59fb72d9ca4ad3906b9ad57d83c4030bf81a5cce58755a6ebb564845117164131c7262236688b82afd4bf2bf92e869c5ec926a9f6dbc6a65" },
                { "zh-CN", "05a7d33353592094cd14f0eff44173aa2cba8ef4d28063729c368a5ff0b18724fa814e9a8c543a9722715cf20cfc1ec1ee95917e8decfdcafe407321342855d8" },
                { "zh-TW", "2c55ecaae8907d7bb68ddffbf7129f38e653b3fde63e2b6f2761d0ac4ab74b86b2cf853b6d390b65d76d7ae474b8bc1e95535ac7a14b47d395333dde48627f7a" }
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
