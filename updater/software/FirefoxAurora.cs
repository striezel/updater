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
        private const string currentVersion = "141.0b4";


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
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "335650b1b2583613c3ae1feff4e97c5552c26db4ba47afca318c7f951f763da4419b717752360818eecf651a1af3ec67892d10f61b11cef705d4284b32b375d9" },
                { "af", "de8b8e7a40554b9d832411c4e33631256179bd12156a4c7a25ad5bb79f0f3242a373bd522124124971446998bcc3024cdda004d6e21ab297af3c1f8750dbb7ac" },
                { "an", "2c2521946c69e88ed27ebd1fa5f6a7aa5e8a011cca96640a2f04566fcc351038b7cde0b4cc7ded70a7ba84a0a4c17f069f2658a1afe61a85124381820856f96c" },
                { "ar", "881df0c88118327c19e98d0f92e47794559e704f67428f5a5b952aecbb307569c3b79001f0cb0e069b16c4fc80c7caa2aec66efbe133a0c313fb37a76c623d6f" },
                { "ast", "92877c60b3e3f5085d9acbc62e2c263234894418b74b1f9393e025daf4cc4afaf31275b297b58b1ba40918a2b835796b42c19dd56185fd549f799d9744fa3df1" },
                { "az", "1d087b88cd630fd456de60da7a3bfa795b7b63024b2ea179caec2c73be0ac3204d79f969b8a809b30b5a503718d9620bf56be41a593d458979b2710ac7c37d71" },
                { "be", "8af7662e17bf45bd4d4a24132b020046cf8d0b599e4867bf0a670f0b30b656f008184c7ecc0c4a471c864fd8c3a36f1170a7736ddf9d9397a66c51cfcb7e25ec" },
                { "bg", "11442d4ca4db9956467368c6009e4fb42706e0221b81e8131c51ae4d673bb5b06aa92cb46701e2d53984ffbe0cc0aa89daa0d3aecb97e8870c8c3be62207a6ff" },
                { "bn", "f39430f6c7f0e6cc06455b9035da0b39db526bc71e29db5995d25e46acacc2b38ce4b119e424911e3456dcd04b7980ca55d70f4c9517736839450c9f450a0a9b" },
                { "br", "5d61f24899822f9a0874e2a49db61941a17102cab1731acfd4e3616a9bf70b448769f2ef4b700d5d829227517bc89a09643e9a1fa5a3cd7533e4b71440e936ef" },
                { "bs", "02caff11279dbde217119e3bf9930bf84f7a4eaa45143ceffded95ffd07ec5bf59d701a3f761f9f8c1811a0700552c35ea606a33850ad200f3142a1276da6de7" },
                { "ca", "66dada769b90693d602de543ba2d5b1ff6b4e0b611dc25579724b3a2996abe7f187456b180457a7453408dfc1cf77a27befde4db7ca29c4856f1b0ed70c76cc5" },
                { "cak", "303c8cea51998ffa883ddfafea96197061762d8740166f6ffdbf1aeed7b8023424e4f4564d8d4f7abce1f0780de251d20285f2ea262b46b85c7552c09a070024" },
                { "cs", "827772246252cbf26caa1853fd806fa520e662a6ef75f2ab8da3fb10365891be43b4b0feecefd8a7e63b4af485e5c249c706cfb267b88dac8f7e824ca226f31d" },
                { "cy", "28198d46ed5bf43868128a26ee014ac8cd77630bce4c3d4d43eb21eb7fc5f09741e53bdc9247a2258c0df4ad16d4c27525099f29c00af28b2db5c2aa9c194efa" },
                { "da", "72509a4f566d3edf1cd34057b03e6da204009095c1d18e3303eb8aa21a0dfda1a1d5825c210f205f9204b489fe2352be0869cfaf80c4e587ecf208db1ed214a3" },
                { "de", "bdd48926231cc8eb9393ecc02393eb7b860df56c88977be197fea52a10482513c93c9d9a67b82de2ff7b7ffa4375478e232b297f8152d013b6edddc67f1d3b22" },
                { "dsb", "820e1eeea378c4da261984435f3b7f2a284a2710fd4933e04cb408482e10a21fd183a8dd481803e13cd5d9fa422859a6c011850de1b40239bee52f57945f690f" },
                { "el", "1c577fae84d92b3621776a0e5057a2b7aae1bfa8a5dac50d55c17f4fb754b27f778f1be223a4ec621e230ba2cba27f948833a24c4cf5af98d6cdaccd53a75ab5" },
                { "en-CA", "baec778a90645c28e30eedcd03681b8ba05e4b8a1291ab6de872220f590d28961883ec8e530b9ad09bf07dd76c59a5590cfe3893ef913b07ef04a9337e24ae3d" },
                { "en-GB", "3fda52dd17ed4649462b2ba5fae9e12f7a4afc234f0dd5997a2ad35b718b01aeaa85011426ccc65527b6db4974ba1b3d15eb415fff6647617c2c2faeea51ffb5" },
                { "en-US", "0ef0dc677c0c4fa668351a3f90894f6cd6fdda43f037e2b5540a40ed00b1fb1ec4fe0b9a5a509e075c49d0c15e8a9cabce498d111ef3ebc9bb8edb7ba52f8ec8" },
                { "eo", "d9007d951786b324ab51ff1d0848c7e160e96bf46a79a523722774ae35b5986aed176f6fec7455e61db876170beb3a7e0dc35ab260d440864170049cba26bcb3" },
                { "es-AR", "ff0927fbb4a915965752d03905b9ac0e30838f5a0a3a0d97a43b077d12cffa2a95598e6b65e886a70f720f79f64208ce10f92d7d55b8c2d14c60fb2950fe9bb6" },
                { "es-CL", "44b9598152ae309711fd47937ba735d5df1f8287622a2b1de5673a4084b8e2aabdd772eb46e613f9533939febbafcb1b717583b10d1e8176ae4bb44aea1f1867" },
                { "es-ES", "cb7ea23c471289dc6d3d5a0b8a14482d635c100971f7c00bdac0e2748974b3e335333acc4e558b07853f21d34c504a598f41fca414f2ea3126b72b10ec5f3245" },
                { "es-MX", "1809c4f0ae7729e8e439ecb8784185aa53ed237a3fab385f66bfba9c81a40e2233fedc3856660936581a81301e15a0dbb20fd818409ab6a933b23d2beb9e349d" },
                { "et", "76ea0de35386f4e2edf9a40faef505d0e3bb68e82bf9eac6a642f19acee0f1194232de0f771f162c99a0df8f05d1428d224a70f8a29aac61ee2991efe9908c91" },
                { "eu", "877cd1532e5e26a6d50ba8dbd79e4e1e590c6a71bee63e6bc81cf4f8264bd58332fb1c3e0a5b2638b212d491368f97e3ebd8644b57556a675c82cb93340fc222" },
                { "fa", "383681d47278f16baa0be224f35a439092a7a591f982c8147bbb6ff8c059567bd5eb71f6d4f446fdbcd49331f061899698dd0da923b3442ede860f20f736ac04" },
                { "ff", "b2cc5e3a2cfdaf5ac275c4817a074aa0b2807786b1465d3722f2a713bc9e83320b15298281960d523f5f2bd9181a26b727860757bcf7eee22cd1113962fb5ee7" },
                { "fi", "d8cf7f4c3aef46e7ac212c6180d9ddcd12ca1724f5924daf4e86ba811f182c746226d9499719c1a2ae9d0396217db0e55ffbfcaaf47fa3177ea6c4379edfc5d6" },
                { "fr", "aaafbd0e8b9b6144bce2bf8f384cdb5b41d0268dc18af1a32a2f3d89749d7f52d6e546ce0425011df2f3d66766f8554d279931e0fbf71a9b47c113cfbde031e9" },
                { "fur", "334c311c920cfcf7a307f49368cc697440f15ea44d1bc24859e02101a2d198b5ad8bb0a74f1db2a1a9ba677b78d149eda281975d027099efa3ebb515a1c007c8" },
                { "fy-NL", "189681b70f8a59b8c9bbf36a463235a574a0a878bf1b01fe513ac73fefb04dd25096d172b69b040d7a644d2dd84d30dbcf43af2e70a03e62ae1751bf6af629f0" },
                { "ga-IE", "4da7d8764651d25ce0a64408eacd80dea6d87b794d7adf5fe1a07cfc097f81b4dd1663ec53e5e557b26861ea2be54968f4ba1356c55694993e03e8807f646402" },
                { "gd", "02e74e070a130e040539f94c60fd458a897f91c388511b9759b9a7ed985cecce6e05038b72768d3d9a14edb5eb89d3b8c97bf0fd4299c8bd635372bb94010855" },
                { "gl", "61d637c64601829679b19a7560262f5946ff4e4a1ac9fed83fa78bd0d9b6e083845420fd9e19d94c0d4f1da232b7c19d30795df0477d5f05a19de94a03856483" },
                { "gn", "d73f47c3f13393ac5fe40969fe1356e6341c734bfaf7ed475a60e3a96c9be5df6da6d18862113d846c89d1c682fbbd6544235ebfd5369d4eee5bc0e83f271f91" },
                { "gu-IN", "42faf3eb1a1b628477c37e59fe241fb5b19b51edf6a60e4bfc04f76d9521e6f916ec40873f0285896d69dfffb6dcd401c0e1524bcf69318081f61a4ef44134cd" },
                { "he", "cbc3927207bbf490379b3d213ad443eeec2451ddb30ac44bd5bfb208a56aaca77c764e04624e68542028e0f60c146d861950dafaea637ada2ebd20d97f8db2f4" },
                { "hi-IN", "2f1ce97135e2116bbce5c742d6029c809a2c53ac096215fd675fbacf7dedf2c7027a16f4f60698d79642b1abd2c15d1e4581ab1119894feccd524363ec0a8062" },
                { "hr", "e32b1ca790dd6dfb22541a4ce6f61386703b0e1cf0a83fdf7983255bae47dfe6348773c6fd75524181e92ef68b066ab21c14458951112f3eabf348c0e1f297b0" },
                { "hsb", "3702258f512b87928b1178e9ba2e0655427601fe6188c8fd1ecdc9cc7d2b6b844ad4302357c58f89d3e3a2c58478fd9a6e92df2413fb748939a1d1353ae0624e" },
                { "hu", "7c6da3471f5d3c7b6e637437f077b0037630d6da01015495a838567ddb35943eecc752ffe3b4ecf2159a7deaa8702d5c068cc6bdc073d11ae8a9fb247640498c" },
                { "hy-AM", "0332c981bec3adc5b660dfa150578b8e4cc5018bb2c25bd0227ccfe96e1481a2a7eb333c3b8311b577a12e9c4c7637f50cf94213d22077da5f8ba10325fdf65b" },
                { "ia", "c6d125b6c697cdd5938bda90c2d63b875d4ce529cefd2f2fb36817eb98f396ae76d6b7484e3b08efdfa840e134a0fbaa4a92f95fa222c96efbac09afd2a00f98" },
                { "id", "55d097f1ba79a2acd92e07fa0dccfb5f774df7ee06e87bcd18acf331ed90a354a241dcd71947ac5da775d62d7321ef1f19e659514e8954dbb25081992189ee38" },
                { "is", "dd277a570407b944a4f1126254f855c32112d7fec74af5f6d33b07aedf197a7226341c320c74f03f109d80879781332761f622876a5f48c2b3bf923427e85671" },
                { "it", "ca3243218f5404254bf6d3f9d8aef392704930ba5ca0d098ca1cf7eb21ae4b4ca04864a318573f83315458a6930d236e35fbc2012d06ed21939ee924161f05e4" },
                { "ja", "ce84af00d7b600e4937a177db52c036c740627b7d6bdeaf8c307324eb114583a79a4edbfc25c3f5b4efd4e51f0c6266039a446eb4f80e3acc048daff711b29f3" },
                { "ka", "a97d7c54505f866e4555491823fd0df15e0c2d0bfa02458e3f0ec2986aae623d8917225d37ed5fd00ad71eb056069022b51b0cd53eff0b46e9478e46bbb18586" },
                { "kab", "aa13158b36b18d1b2b3a5343565dedffa0e84b90e81b058c5e3a2ff470e19c30d2093a010516afddd0fdabdb6e471208d31475300a572e220846ed68aa4cb538" },
                { "kk", "9f26ab1257ca926ca89b019f7cec0f91dde2e16c7f7d12ecb37b0e49fd97c4d68fe420738b86e25be269a6a0f0009aae7ac0f3ff026fd88532271df2c7fc9b23" },
                { "km", "31acd38e1e53b594cf087d61cf5013ea9ae61339a5a00feee09851077f8c44c736c63b44b681798904e46553aa2617b0badd765ccc7e20c513c28bbafa0a455a" },
                { "kn", "6aa8c2e1b629cc0caad025ec358cd57b5af90cbedff9d57258078780e2ddc81606edf3f409c2373b07ffa9e072bc64ba3aeff3fb5de7653576f4f6173a1609a8" },
                { "ko", "71258644c8a375b23cfaacd80658c80955ca8efce8210f43ba804de041bbc25537b1517762bcca65cf4bdd413893d28bdc9ab705bb32ec7760a61d95d9d6b9a1" },
                { "lij", "7ae45579b49119027ef52541d4a47d33c546648463821eede70feb675102b6d1283b0bc206b8c8a1baff9ae568958096de77f478c478231188266b55d9b0a97a" },
                { "lt", "36932d558bab5e5ba06525ce02736eabf1fd82c77e5c8ff51f8015051babd7850899b34023a8a4f764a1eb6280844d6e9a89647fef87429bf48451e9addcba54" },
                { "lv", "9505b7c29e5855adb14cfc375f13208b7bdd77fae5700825b54d6372f0923e2fb9080c84121dabbe55401b0ca963e5c89379546fcae574a444de2175ab999974" },
                { "mk", "1c0007547af02a0a3203bbda3d78d325f36699cbda7692fa650ab1b98c54633e656ddb031a381ef76b142a35b78a88316e610a17c159a926fc148811a9effb29" },
                { "mr", "6f3040493886e3737e2db56c6675d9113d88046f2eb9d8f44a99d65ca29492ff3f0b9886ab9bc9f0cc1eaff50745f77ada0063f78224b8ec1950fc6f53eec3d8" },
                { "ms", "d6076420fa54c1b033ebca1f68f971e6de8c2bdc987b790377b8b52586ab85d6b471af03fcf3e4fb50c4264e6075a163881dd5f56bee5f37bea5a7dfe8e95eed" },
                { "my", "ec8425aa7a6c5457a88c47f11a7d97f29090a7026e323050da445022f1739765afb6ecdf3ea5defe73f1148b1c12a68ae7cad727621ec3109916b3dd31a3afce" },
                { "nb-NO", "2cd7f2539bc695b0b69b1126323089163332921839690823cf4ce7dfce27b338d363aeabcf9e2ae0969526d4999fda0efeff09fd0e086ef897ce9924307eabd0" },
                { "ne-NP", "11a40816e668b37fbaebd604c5152a7e2466f9748d983eb4fc2fae07f5935c66885f53c3b60650f1c388229c2bd53d2f40c457b060eed158b3815ac27caf4a61" },
                { "nl", "ec4a6b4c59d7adfe8bd382700e893ee50d6a18006dfab8991114c7d6f25355f85f736ea8de2d0d72ec6afc65ef12014b28961d1b9a3c2ed7f72fe732621939c2" },
                { "nn-NO", "075fe0bf06300aa81789cc9aee3f6d335e047a920eaeaf9f0c47c16bde67c8f42645e021732cae17b5f38f6f33dddd8423fbb64f970993df07b446c61c68ae5f" },
                { "oc", "9140425f8b3fec59edb0c3f082d5792c62deb9194233504e08a3c036f4a616f5105ea0497cab51c4c470bd6bd559b4d029625bd5548b38d948145a05bafc0b80" },
                { "pa-IN", "49b0f49ef7041c0d2426ccabf8b16ac573bdf1a44a4c3ca195d832ce0e99d05ae95ca3f5157ae57e0411d83d143043eba8067149d516760d3debaf440c041a5b" },
                { "pl", "6763ca728d7b6143c54326a43188e343b4e9105aa03eec76575e1f41e4951cbf6858f9937d3bd2fe22ea38190d9fdaddf5ffafeeba3ce2803b30b49dacd6d6d1" },
                { "pt-BR", "166209a5ba92807c15b2386334a437f26c527a332ef21586fc2a6dd2ab079c1bca942dca0feba2d5f98c3e39514eba05ec915a5ff888904342c88fa673eb3b89" },
                { "pt-PT", "088e868eae8b61dc17190c3d2a0f70f397341ff928ef418532b1013f8993971bb5bfaccf65cb25e76694aac8cc3ff8396d09108649d8ba94d4bd4b4e211bda5f" },
                { "rm", "bf2a2f2526b67ad3acf5d416787609f8fe4dcedeb439e72d1b29d29fc4ac85971dda41626275b8cb8cdfa06a985dbe687abab5680774d04ebfa959f4fd5bc306" },
                { "ro", "04994f39cb4df4f6d7896f0b18f34c64f1dcd097461aee1c2b0ec0281d0dc1ad0a67499727b765cd9ec666d16f77285b3e90470ab1cb4aebfdc6b348e8597c0f" },
                { "ru", "4bea84841efc83ff10f6fc2305b4436d8422372010a5f9aa01d17b37145bb05a922fcf28801046beaf7afdfed1b74271245dc26903fb6c80c23bdff16df842d6" },
                { "sat", "9bda29bc1f923161646219e5bc6ffb7f8ff5cc6c1ec6e8986691fc3069a983d5c132402943294f161c09481041dca2c3d4d16a90f468d65145a0d708d02808ff" },
                { "sc", "0dbd32a9bff7a83646d716afbeba5ce64208a4498d906edbd310556d055e244193362ad763f1504db1cbec9d3ec3a5b34a28fa078e0a9698b93af62bcb67a907" },
                { "sco", "9b30a7a4c447a458ac980738f7fcc485f60ad46c134d7b49af33555c1acc7244d2d454e1d213fd6bc665e7e424216cbc269c887054f8f7e684a525bfe86ddd5b" },
                { "si", "a5977195cdb54bc1fce01e4588cbeae9d494d63e1159891043582021060daee2941353bada45e449de0a699ae2fb1be517e987901ec957f9ae09f1b61d40dfb8" },
                { "sk", "0178973cea12edcde5a7204f5100d592034d5d1d219edeb47c93b561ea6d63c8be933655cf4f520e869d09fae3d5bf0c6dba9a0fa6d9b2c04b676d8d1c1720f8" },
                { "skr", "701ab934d05d9102dd61926cdcda6e8707038880eabbfcf67a197b3aa760897315365d9c98059b338b205c030da5630eb661232d7aaebbf3c8a58c8b8f085efb" },
                { "sl", "d6d4e09bb9e140ed8efa8f16def69c55294b070103698857539d824c1b5c3ed3f2b71c930c8798e8caa36f1b37434572078c60e866a0fab3b54ad72b11921d46" },
                { "son", "5ff37ee4da3ac021185905b2d7471564f811a058dc90e35312414982dc76b7fdf57bd939dc750049e54955fcbcd6c7ea4e268b5e3e946f17bcc887cf176828c9" },
                { "sq", "1d1cebda3029af4c80a618611d1fb951d8f43954d66402bb50d8f967f4ce4b7411311a6ea265cce5a5d699e29c4e05a4a5b08063bdf4df960faf9ccb0697020a" },
                { "sr", "8bb474221d262bbf8b9867265964543f2de5efae2c163cc6b024ad86dfcf62b74bc5ba28f38d7d83cc42aa09aa6cd4ed83c3c4d68bcb755b3dd8a705a5d09e97" },
                { "sv-SE", "18a4dba0c816da6136a8167fc2d0432672f8ad3d73c44e63e244b47afe625a9e45643b13e5981393f8c77b170d4c6b13e71dcd6bc85956f9bc49e2f59d8f25e0" },
                { "szl", "0d3cdc4a482d9848fb130332237bb9f2ee2f5b2ec66faaef24da0df0279f42e337da32ed476144fe577aa9dc976ab4d6be85629309c57c53738413e7e41b798f" },
                { "ta", "e1a3f743a946ddb50142349abae7b1e45097bfe24e2deaa30c474d6d7d5b909e70c3a17c3062638deb85de210a74940ab462552fef958aba594e95c0ace1ad4b" },
                { "te", "24db12b9f106174db19dfa71459117a80b4b5ef551febeb322a5c125bb215fa5522b9b7f337563c4f2a607d2109fa024202264cae5d0fec46eba8aa136833650" },
                { "tg", "9fcccc11216d62a9090a77a8d18b086b6dd6aef5a0fdea65c8106bf45632ee12a27fd0fa97d73c1f8b991f10e12f100bbc282cf85aedc279cc20a3c29c47ca5e" },
                { "th", "c5688cc06c210ad9706e503556436fa2600aeff1bab5e1ae9cd9f0c9796ecbf4e4058f1ac900cc0e1e60c4a49709da86275b1926affcc9daa4472ca0f3d01a34" },
                { "tl", "82e233cb51ff41598615282678cd8a7dc87f7f38fc72516484637404e93479b6d9263b498b15f07259d2e1c54a7264578c87c853068915c3408d896b08c7e5e0" },
                { "tr", "b3b8edf0f9dc20d0b9c5d22c5a9f46a8b096a92bd2517cdb60b9c2f10f6a439e83203adce7b70579a9ceb032dc1979455c410aa26a82bb680c26e43b922e9438" },
                { "trs", "3114e6a18836b8eb2ff2feee5320c251371521bfb8181c80e40bf092e954a823f1a88c6190a7c1df290627874dbdcd1a6f3b261bc228450e263fe2dd55476ec9" },
                { "uk", "95ada7ff5c8f7183711248418720bcb4296b4b79728dc617678adb87bda248ef2abd6317be3e34fd76ee28fb9a4bc7846fdc7c2899650900d27e9a5413ca4c01" },
                { "ur", "79ab5d45db7a747fed41bd1f0eb439088659779c9d65160476529f7f7dcb82e9dc74e6cb294cfeb4413c6325806a094272ccb555781da5e254c01705f57bd124" },
                { "uz", "06bb3a5b643cdbf89d214ffa638945c137a5518561163f25ad365786dfeedf7132bf44b0c3789e20045faaff2f1bae85a59ccc5be35716cfee7e26f307f51758" },
                { "vi", "3d8770b67a8d6c24675f69d146dd7b62939b1c9b2ade1e99f9bb142dadc118b8788cdc94a6c53f76a0adfa86e7dd2c7646780fcf066461847cb27189dae3c815" },
                { "xh", "98449c01b338b9a498f3dfa26991f5e73882c3c3750f16fff789d878685e83db3d79f39e22b676ce6145b613b613baa47058b5b92597e9a0bc280b5afe97ff7d" },
                { "zh-CN", "4eab302bca6a2de7e4350cd160982080251341857fbe2c94ca2ba39d34c2e22262f1a56d23e7414f8d928a0c331d79f4a73c73344c6c26c04d55f090d7edf6ff" },
                { "zh-TW", "20f3727ffa2a52d719d0fd2aa79c6854943b0b82482e7efb7818394adf7486c6e047df3022a87d459bb931d3e6339d26ffda3d0b93174da86156de1e21e5939e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "855c7589dd3213fcd68abc71ae79d174b50ee7fa1ebbb54f25c5c53b0fd361aee000319940cd31e3b5f3c014269a695d3f264e7c92df92cd730bec513a9f5f9e" },
                { "af", "6b89d382bd2277fd70aa719ba42612de2b1f72daa795dd0e6e862121e003122d3cb0f02aec9ee220980c4151927ecc0acfb00439d5ede0e297d2f1818cc9f13d" },
                { "an", "6b57085870c5bfb3b10e14faf45ba8531057d9d8833e23563593e642a85ac46e683ddd4c5cc39f801ec491abf2141c633918ccfd24b11b123b6cda3b3bdbb804" },
                { "ar", "34764cdd5412430edf3b00973b6971cd57559bdf306e200230e10cb466065cb61358e505ce32e96e6177d9c5179de785aab38b458297d1193f4eca6ab06fb106" },
                { "ast", "dbf8850f997600a12681e5a9fe1d6f0a49ecee261c23403ac28ef2a96e6214c21bc8fefb9d0a768d1c072d311b51cdddb5f5473bfe72a647a5ad0459e39d0425" },
                { "az", "3c25a3305c0355ae6155dcab5c9c34b968c210127f116fee74ef8afddb068100fbb1ee7a71afda520d05dd3d1eb4135b98e4f7c66a1e02a90b877e8e553e2bd4" },
                { "be", "2e8234a48c8f082a987344a00b4be278ecadea73ec05ecc20d3f318072c1e6847ed15a71e9dc9b1c22990a33f5844dc13075e040f339a5ccfd3f5b6d703a1b28" },
                { "bg", "395cdc1b853cb8f5ba70382d4cfb563dd9e7b0f3b1bf788832d1a0a95b13077607d981e287db7ecfcf585bfe5de78d0c787082801a914a95f93cf0214da74d1f" },
                { "bn", "ffe27cace0ad8130d0922054c45ec74f64621ee2d93685ac0ec55c591fb2fb02a014927a40b6a4b5398c6da075a27d553ebd32d3035eafab1a8fbd84e84673e8" },
                { "br", "f85f9bcf82fa93094ad0955fc8fdbd2b086ff0727deec4218b2f0eb66ef5459ab461377cf1df23968c4400a053e556c444c54e753b0ac79f7fd29a7b66e72f3c" },
                { "bs", "513213b012e2845d8536304fda2b07773a20ff224f70708f7c545de6097ce1cb3e5769fc98cffac753754481e725208c3cb7709df509d7027219b3945178f692" },
                { "ca", "5652147f5f8c5c2d4a9c0f7818e67de42e6c3b3a1c5dd5c64241dbf104a3332697d227957814184ce0228ee485a05dd66cc516a0aa1a27680390da3cfee3e4fe" },
                { "cak", "e38a979b8100ad2021639e52e2fec4688d5ecc73b7d8694729599370d59715e71f2ec52e4a3c1a73ccdb466dd699239aca6990363fa673c31db90bb8eaf92cf8" },
                { "cs", "383d1cd447e1134e3b8e31dcdf02ee8d418ab0f99378a77cc21bbe414baea1b24045ffbb26063961d46e69e2edb23548fdb337f3433d41d8f536789d23804e0c" },
                { "cy", "ca472a3980b7b3d9ff916d6d9e6352e8f7bcfdd59bd865f09de9a17149eae2e47c5c332aab9d6b9b7948501c16a95363f3c38e0dbe7ec00191a8f9abac15a2b5" },
                { "da", "5f4f2d878c0701c86785f5bbc0287e1cb5c7e7128667221274607ae3b6d0441383a8eaf338394d1e7093c23f1418972884b6aa76fdc1b948b9fc67bd68b35269" },
                { "de", "c21fccfb4f7b22609afc5bbefd5ce8edabff3d74d3dd9af3faf9b759e249d6497692839f9f6aa082f889f3d53aea7d38d9abdb2fe7074cb62764bdc1e6d0a15b" },
                { "dsb", "dc748c08fb875491cb7478deddb1cafada1c29d6985e96fd6f6caa972139b5a1fdb8c9a8616bce7d1709dac456e1d8acd25ceb6143f2123158c937e947154187" },
                { "el", "c6b071018e0534cd13c2cfbe3aa221d605d51e3146d39b6db47dba54ceb71bb36e0f5236b296c3fe368d9b52e0d9592d90cdd47dd02b8cd8e73c1b238a978537" },
                { "en-CA", "6f3988f51bcb5f6d00536f06996a2e770223278c4aace98ffa357b50e8fd4de3d1df56d972c104db8d9d86e464c6b6f90edc6d33bb5a264cc7f4131457733363" },
                { "en-GB", "77990b5204679b0d84ee8d70a209b5e5a726ce379df31e62312e4cda8bf33582c7fa0fc2d38d22b2010b00997f1989480b908119f0ce94c1edd4ed8e703a4047" },
                { "en-US", "1214d2fe9a00cb40f6c22905eed374cb9fc0d4da542838c729c96c7cb3252491f9efd55782e3accd6b4a1187aece715b42f0569bd0dddf1c1c478c66e4e30292" },
                { "eo", "16ef09e000d4f48874c5f0d3e0e5eb7ab21f7c16f73616239f34bc96d1b4ec678650af799dfb73526017c24f1641a9f11af945736a354ec4d3086b6e8b27356a" },
                { "es-AR", "97b440f0911d7fe4e21226a49ffca75736c1d713fe8320ec03964c09b63b000faf2deeb9123fd82bdaa3833fa5922c2db64c68f48c24160c7204238d0064adaa" },
                { "es-CL", "dfe606c31d7a74f9fe243cc67e796437db4aae1149dab85bf6cd0d36a46819be6c26200f602d0e836761765c15bcffd01fd5cc7b27643597079a65881b104a37" },
                { "es-ES", "982b17db5b528e66847b2ca5c0ea2c4416fb97bbdba90c7f431cbd828149ed4d204fcfdb5b0c44d3a5fddffab15c8fc51356275a28fdecfbd9f914f1c325333e" },
                { "es-MX", "fd74083cd55e85112e217d9862bde35800f52219c0ee2398af25e5bc8e6d82960147a4dba29a8825231344b2b3fa70aae921473abd4bb16b2118e27f66899291" },
                { "et", "0c2e6a465bb847470bdfce39285e52ff38db126b2198b8e93a916c38890f425c49f20ebb2d74f5e27155584986652d9d807b349d20e33d287ac44981ed43bceb" },
                { "eu", "59a0bd822016cbb818019c7fafb0bb678fca80aadb33a8b66d23e5d8bb9c12de8ee3b1fe609891c5832eaa2290591c2b6c2bee31db9ca566fa11cb74c6f34bab" },
                { "fa", "11e7bb4e261fbf310ae7b772ab6d9ff71eefbdd33ac1ff529c3c6e86214d6189ee2376e85411414196f11157555a675fefd4c13ec417aad7b7983f6c5c9fe7f2" },
                { "ff", "c80b2a848c66197397821f508970c912d9a085d2de2171aba40d89ac07ab1837c22ad237939b9b26e8c92a2e14d6846ff6600c66da1ffc7af967e615c3d4d370" },
                { "fi", "b1b91098462679b3afadd8390a39070bbef92b6609bcc027f2c995daddccbe9b5701cc4f6a05fa001242accf96eaa34360822cfb53b151872efe2f303f44f922" },
                { "fr", "c7809594e9078aa2b6821f742d8eccd27d86d2c99c65e240a453e3375f4278c6dcab2834a122b5bde5b4088a71b1a013a8630e0e36f4b9d979e417e23bca0e74" },
                { "fur", "6f129ba8490c029a1c80c531b64ca8f1562839e7efa71736e20574e7812c6cfbe822eb37d447fa7482f4e26a348c60d36380cae07d3fe62178bccd2f8fc46042" },
                { "fy-NL", "fe6a24d8216a394cdf7cf5706678eb9567c8c26b7d1ccddd31d3fab6bb16e9027b30b35f1d5cfa1d6fbaddee5a34c249f111fee6c7f5bc438eca2a55474a5e9d" },
                { "ga-IE", "74f7ea3d069e5bfef05696db22ba245b730306e53c67673256650adcfde8df517112d0470455a389514bb74c8744c67479dda4ab14097ae7f3c9a0b84ca81939" },
                { "gd", "a6c8af240a84d44f626d8d0de1dbb020b6ad2b14bc0730eeaf812b6ffded9442bcdcf959e05e7bf7127e4174651747c81401bb7b5b1444afb5c68b0b5a54ead8" },
                { "gl", "22a38f0c773dd5c03e008cfbeb2f6a6c453032a6bfa97900fdc254dd8aebc98e05f04954094667cfe9033b00423d5b4386c13008d28a5f41a9c208da1ec1da21" },
                { "gn", "fc5c8c16de2cbe890ae81047e1d11e6f332f29c40f16dfdfa3ef4881533afbbe321af868f0cf0fd90cc930a3b22ea49b555c72df31fc6fb8d2e1567ddc85f24c" },
                { "gu-IN", "2215913b502b87f40d6a2628aa854d10ce2fc62d06f7a60e6d17157531cfe536d22be65390156d1fb7139f5de9a07ec7e98a73cd370ad85df1d4c606f09c5ff4" },
                { "he", "e358733f5812ca501fb2cc358b2ea911fcb3c185b684a17d46ec56b54ac186a46306d261920c95bf47e0100576ea27b3d03c284147deb85e64c2ec57564ee727" },
                { "hi-IN", "754c31ea3f60af07e7c96caafe60fed0bb4f42e1cabcaaca6ae9c2d34fd7399aa1bffdef9f4088a7a43f9419e8c3428c44a1e111057e58f158894382206180ea" },
                { "hr", "d37458be773be6fedd44632f29acccc09e767a7520c1a056c2a8a5f88deced87e1a0acc50e3a70664be89c7359979d5fb551ccfe4254260d4a2327611f88dbb5" },
                { "hsb", "25ff99282d51775e08673df4c4a27af7ed0794e0652bc8713ecef3fa96e3589b7d2d954429e59000c12f531e4e936a2aea05835c5aeba7043067d931ad7db5e1" },
                { "hu", "e19bf654bdf040934a3b450b9d8dcbd46278d0840e1c3fcd427ccc53e8679479655a46bb4b233d9d9457a4b5ee1a1858a4cdc73c3db44d6b8bc1a79865eabeae" },
                { "hy-AM", "66ed659591b6dfe41d47cc8031e1597713c30601b50deb03d6812b2957ef442060eea6bceafe91e5ebb6c7a2d246f65f795dd288557afd081e4dcc529dc423b9" },
                { "ia", "be8d39014fdf3d29261e2a5fd72216d48949a5f9e04c9d93dbf9a00e1684f99fc0701df0917669205fa282b6b70a0c498ff11ec66b8e1e62c895143b2b2d9abb" },
                { "id", "cd3a645de4898ab55f5b00dc663d2f1b6c299937306a69315e7b51251a7789a05b4581dfb4fb8e90f208d8620692032a64c8b562c66e21e36450be109f205e37" },
                { "is", "c69f6f5119f4f57cb9c48cd1149319dbb657231ba148ce830cf150ee9c1857b28c78a67786aa2c12cfece90788873a77854315eaa16142606bace607c55ffac2" },
                { "it", "0fce0697448cb273d6286c48cb38371fad21e035f12d6b6205cb7541f03c29d0eaf92794f7e76a66af1417334f16e8258d3fdcb641d755dadaf3f264f9f6d739" },
                { "ja", "debf33a99b65aa3465224f6ab8741d2a0e8b0f7bd9977156f32bf0b3c0f585433883d2f34af79dfaaa6ad4ca4f330acdaf600d95b4a47d8cf186b26a5bd15a60" },
                { "ka", "fc16ed3f8ae051b13fb626556e7672f3506f2e4251958092ac87bce59678a39e61da8cef45e12c3e9b254598a777774ae2bae81ccb51e6a222109266fd11209b" },
                { "kab", "2b166af7f3d89f4d48cb2c2a68d43aa0353117fedc5f90bba721c973ef6696dbbb0d53b719535f961acbb50fdc461a9cfe78eb561a08c25e829691e9bb63b941" },
                { "kk", "8ba22a243989a39abfe057b59f06e02d5f605415499bdde35119019adcdc5e47a9701c474390f83a0d53ac79bddfacf789e3a1af3b7ed6fbfe5f917c13527267" },
                { "km", "856653aeee5208fb94076fa91dd63465db847a3e03671327f7120a0470343a0cea4332352e4f3056efa40db070bc5c4231e2147adb4ed4b7ead7bf53925ee506" },
                { "kn", "63b32ae11b1d5245cf066e6b00dc3fc0cff203713fd2d5f304b6cd3f5efedd37a0d1e13f96aedf9ba5eabbbd0fb26bd603c377ab293d74a2b06e20b6351029c3" },
                { "ko", "8cb1eedd1ca3f09e67c71b7bdaa6b57c25dbe1d568a1cc45cb800fabf6560f5eb315735af95172d298ffa5f87a4fe433e7062310d88926cccbaaf6b8da409adf" },
                { "lij", "8e7feeee37c062f942a2de70791b90ca84827c7521d1fed6eb15d22d0e975ac034f7153c7f85c9dc28879f516e079d22d0597c1efe33a84148c65ab44cdddae8" },
                { "lt", "683c95f0326e375835e0dc2b9bed419341bd125efdcd523177e71fe3f4874b5dc0fa4bcd07b2848d5d543a25f77ad021908f5f76e8528fc68b4e8150392139b0" },
                { "lv", "2b1408c7f41004aeb9995173aaa904ecb50c298561e00b52d77dd97ba8ecde5c57d90766a12f46be1897f2a5d4d2f9d427b68da3b58ca55bbefb6812a00da028" },
                { "mk", "c7e594426ed6ac65b492d404e4df96f4a10618d9d8d6ae5fa2567439e8c8c831c6da775601024a193a3aac95b68af8ab6a20b591ab9ef90d8d78b21628fa1afc" },
                { "mr", "29674f9914cbba714d896c40168f69cab9494ee6f474f0c57a0c9b28b26480792a0be5f28cb6940fa2f1d69bf305b2d0e2efb0119a1a141ef932528d8ef5e418" },
                { "ms", "25ba51a7048ea5b81742d1cbee30ddd5154e44f36d46fb8399dc027cc986cca744713f6d24065c907e34faa85a8e399269aa8c63a57b4967f84199319e48cbe6" },
                { "my", "a8ee1b07f8240a643a0dbb32fbec36b8641f2452544a6cac6fa17570f7244ff0f58e4ef2632fcd9476e32c5446f6ff3c4b5c9cd77eb77165802116b80283da03" },
                { "nb-NO", "52f08b1da70faf67ef94c8f26de87b80dba4efe43adddf2b1df50fcd2427920be6b551eb83cbdf18e7c4e89be09f42d0f82fff927a8c02b0da69386d4358258a" },
                { "ne-NP", "c357207de51582f1d116e61797fb6edc212d7f20aba2d3b99f9cf9807d47900f1dc91af27702467cc1afc588e490b178be7f49446ab8d2423a130877853d89a3" },
                { "nl", "e04cdae950bf4f6271c6740756b9636be53a256ca99015b77d4aa2dbdefccc34a083c8dae96ed43fb2696db764499b996fbdf922d8d0c27a8635618ac6401d94" },
                { "nn-NO", "2b1bd89ddfd88cd2250bfe1ba0a4663a48b9447c834475dbca8420546644899c7f8c8ef0eb31fb28d51392a87e66f782ddefae6d21917f2b19cc85f3514e42bd" },
                { "oc", "376d45c557e3968a247ab59406fa2adcf059c7f3247e56e8cb88ac842ca02c3f2a189f9ede42a261616d5edf1fc9a5734e97783c9dc9e1502da0593839ded545" },
                { "pa-IN", "3bc66369b7d98f671eee4a146a09caba6e343557342bed794ec85cfe2172277b0d539ffce4985a42da3a04caa818b66d4a5040789fe201ef1f4cbe974f5c6a86" },
                { "pl", "aaff6a8dc8fabedb43425b6f18e103135036e100f135b3de549731400c344f98d0c8aca7aef8c783cf4d69fff3c1327a3b394debafb02750fe5b15eb03aa2265" },
                { "pt-BR", "7bd3b4df2b15cfe42b50aefed3d569bb74e9c090fc54d282218ab13d5720688dfe5260815a78e309c6e8fc4202e2e2ee2afb1ac1f75df461c237a4a8a318be0b" },
                { "pt-PT", "04eb1a87f56e7480de75aa08f1dcd2c1e2f48cd91c962cc27ce1056e3e4e13d04dce7e61aad0f38f20fd08bbc5c217a0361a7096456a903b858adf7d40f69433" },
                { "rm", "a29f176e6b51a318e05a1dec9246f77929e25519407530386237958a5ef6afd5b4331bbbfa864dfe5b9be5c13b2caed864f5b1554874f44407dedddb86edbc8b" },
                { "ro", "1e968b344463f01c78e0fadf617480cf8a98522c38af6216006f092e0bb880c30dfcda5fdf80e1fdee09e9c82180797eea71fa485a52d92b53285973cdbd91fa" },
                { "ru", "10cae46a081841e8bade478a4b695e1879ece89d2d103eb2308933ba02ed84a930644b1ab24f27eb76ed30717fc00494548182f47383eef1f46ee1a1c92d8b74" },
                { "sat", "10053946bf506009d93d4e17e96f5bdf53b37a863e23d6dab9e674131e8c796ece67718b2295d0e09e95a14a5ce79e8cdecd3cc044f6bcb8619250c42e1f5c13" },
                { "sc", "69110bd6e2f0fdb75ec255b75842dc5059b7b17064528c00e4aa3cd443b9f5d37fb5677d99e74d4231e754b8528f3df172876c306e66e96be03254745fdfe75e" },
                { "sco", "dc0c2d6986972e93a3f72973676d9b3603f2c7fcc1f33e84fd8b6e290c502b796e23d64578645997d4db819af29f2aaacb1087a53d5fb7db6ff95be7e6d02e3c" },
                { "si", "9c2ec86b6fc2deb53cf20c8df147b4788c8f265bfd261069c1aa23b15aa0dcc59a4d57f5f87cb885975c37579e6835df532e8eb297743be2becaaf4a7fcd3087" },
                { "sk", "bf64a3322f88d13afb69dc514420abfc6a9c5b3df686091caa383459a80926a1e85d905743f1ff654b3f8f56064c6f2ace1fdb346925d29064419606d073112a" },
                { "skr", "0f68b3963087734c707da2cd61e4cce79670c66506c6524fd2ef761925632ecb0532d9f1595b097a7d1bb5fab5a80b81b6de484386e3ed8b645b9b13033b1df4" },
                { "sl", "8a1fd55e1ee0daedd515b465b45794102e913aa82c15b46cf71920d8f3f8f7d3ee39cfd7e1a28d6ebccde5656cbfd5d4aa8bedeb90c615abf71c009be8c14f36" },
                { "son", "825f2ac8b0a386c544d6fe647051a320ff9cd857d72bf0a48c714a20605e837a067f40b65f02189bded9e24da851e0163b843b810ac1f38bf8ef75da3a122a2b" },
                { "sq", "cbc52fa925e742bf69e35426f830794e4b06193c4f0aec52ae947b36ab9bc513cc7b06dc1c44f535e39956cd4f60b2a25b8e917abeaa7f7ad13dec36b312bad5" },
                { "sr", "fd52b9e190afa79451205573e1a8a40713ef9e552774991592b8048da1d4dafd88b952d710d41c6a23605a903f5e3ae7acca609d52913e5c213cf1b1a67eefbe" },
                { "sv-SE", "2f3c17bd2c184772dce3ab2e419391dcbaa8b8fa888d6ee7ddfed7b95b8fe5c2b0958c709d079766a86ba614cb483fc4e6bdf0dad1485f84fc3edf858772f08d" },
                { "szl", "b10df77ad33ab74839b8b0543764f97ff6cad3a1e06b737262f656fd9c482559722ad71b944ec2cecce5e50cc84718a089a0030d017af9f9a59a91c7ebb8dc2b" },
                { "ta", "e45fb7ef688d1bcca3cb327a6cc0226a4d45cdb2950855ea8a876f2e43e4884e663303a8a2505205dd230007d2fda6c4a0311bcaf6623604cb73de2d6d28741c" },
                { "te", "d1447c754c7477cf953e61cab73ad1cc6488f90e07c61b82b495da48f227cc2c96d6c23af78c08d5e8c36f73e06b7c242f498ff97092a291e070cc63b948dea2" },
                { "tg", "bde97f8bd73600bfe5273411deedc6b7ea5c613a73c7248afbb47724c4fd6ed832b5600a8b5f12a236a538f68acd8cb24e719998abdd9e8b891f7c8c669c3221" },
                { "th", "0f2021777b33bc648af78466241052e66f7600b69f60f53c52f89ebea282e289d83ebce87055473994810d8298689946af086fd07056c41d9997f2e6e30f2d46" },
                { "tl", "c3d50f7a59e5af33b323bfe6e68e38699b31c8eac647d9476b5c629f2f8f8f50c93d01e70e204e379b7cb5b4928ba7ebaef990da721d6bfcd838fe031972cfc2" },
                { "tr", "1317fcc7ea45ba9af57418f96954b28d225ad3b700263c5c6a53c37e5ee09b3daed690fb22778ee9ed123bf0abfb5eb550a54b7bcc204768cb6e0d1f42728d10" },
                { "trs", "02921aa4bc8f03bb301a3cb72dabe607e990902e3f068b96c03cc8e9db2f59231c103a4b6c751891b7bff6ebbc195c7c106137667042aa82b6e9f12ce98680d0" },
                { "uk", "df2dc0c1921811ca2199ada9d5731fc2d305bd2b3d27be8a56fa1c06b328d00aa90c741417d54a7cf457c7b113e3a05ac7c20f6b14d41f8ef1f997e60e95ff1e" },
                { "ur", "8d663ada0acb3bb6efd890203ce9604d29d96fc7553f7eabc5d7c4926adf0faaa549b2855cf101358e4f7c12ecc4d0b1bc56d19a640946b2ca36f79eeca1ed9f" },
                { "uz", "52a397a278ef98e1a6202772cbc3d7e2e386695a3521d35f86502c64edf5efdb55b150222108601a9253b298178f16e8e4c3cfbdb5915cc7f6ef4bdc72d95d26" },
                { "vi", "40c8378c7ae559f3fd3b66d671bad1dae550761f2d89ca1ce48692bf81accc3642ebee4cf1f021eed7cce587cf28d0f3a140fd9a8b8b241104d5b95e470b126f" },
                { "xh", "767e42703feab842917f565ef81a63f7fb7a94b38b7af5a430370b239dd560700acf9347c956ec177b3511afb891d46344a10151bd54eadb7bd79742e8ee3c4d" },
                { "zh-CN", "d750082211381ab91a54cc5e41e50a1dac0ecd0945c70cdba1a28e55ae56223f9f772f808ab4b4e8d7d3f5656e6dff6517f253d03bc1015f053a76d32138049b" },
                { "zh-TW", "c0725c60838eec76a59bc1ba7199057b958f614bd685b53df95f827c5f3b036d6faa3feaeb90ab1ea7201b27f8217d6b48c5b41fc68ae7a6ee9a7b1a0b204c26" }
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
