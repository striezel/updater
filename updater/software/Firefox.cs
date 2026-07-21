/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/153.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8abe443ad68749aa18fdfe7edf2e008ee3ceb53f17110183cac1d20bba6c31ea12696bdef781b307890c7e6ad1e260e012256deef980153a1e665a5bbd580b81" },
                { "af", "394c227674c6907606ef51802136320fb732bf420763e5be3ddb37e6bf89e2ebbd68021e13895923f933b731443a8bc0fc71ce7837d58c23ca24659faaeea5d9" },
                { "an", "23f42172452a4de7c6f7cd71e20c746e2441519992263d00907e5d173ce5e08c90f282c14f94296c74432e2d1f5ef44ae030f91aacfc37a74c20b5c4d13a1bd6" },
                { "ar", "9904f2f05f9e6e7d0230ae0d7af55ca2a8e8f636bac58b4e21d1d4c1439a4dd23a353e0448e35c939a525525d739844a252c2a7f288558b183aa27e3fd427c21" },
                { "ast", "396b730b3d9cce062c570e81d57ad5deaa4151124c625706af1d9fd31d9ba6e00c217c138c2fca956213602ff895e4c7d6e71ec587a5d2c14fc93e6819a783b4" },
                { "az", "13dd602bd7243e7f93a22968e1bf1a120741209807134e7e982bc568a12e631a908926d1284ae400cc3675d2036e5b4e2043bf2bdaf165549cd8fff5e549f694" },
                { "be", "560ce34656d3aee634df672869f3202c073f732e04a041b66eae36cf50d65e4e2154adc81258c589cffffd935feee5465011e35d02956a4ae2c7c6947f0c85c3" },
                { "bg", "278278924fd4d390e7ae963e5a06df60c7d9cce3c90c497a575985a86d69143b73716f93b6ac7c9737e6be64e160f41fee14140b8d6bba9fccb8a98df16a5f64" },
                { "bn", "77cf99d063662b8871adf0c6a2a8ab52086f34b65865f3e336957b123fefc1976922ee44bd6c944526183704bdcdc26d8a008263254eb074d54810df62a551e0" },
                { "br", "606e57ca9d7966a50c5754d360220257fdc907282a6656cd7d57a6e3f69fded5d77ac424d4227cb395c9eab5a9a123586bb20a2da39ae7b7f9c737472fa531a4" },
                { "bs", "a23d8dcfd954cc45d093a4e728dc584a17d3bb3e47f3adc971211fbd61d910a097c635157e37bcb0ce42df88669cd99051e7ad3d4b3787ebecb2b130f7643b63" },
                { "ca", "16d92f5a7dbf0a16bcfd25151b2ca5741b86de94519c228f4378f645fa23174c1f4704028f626ba655299bef37ba5e7e4771e3b271c2c6d7bbfe5153665b3ebc" },
                { "cak", "a96e34db49249ec710b716c3fa437f9b2ed6ec5133b0cb509838b0cd44e8ef077261c250a70b58055128a3c72fbb4dd36c380bc4726c3e0eb7f255d99eadcacb" },
                { "cs", "37801507592469c95e6b6bc9c6e2b726cc1b76d2e644b0107dc87e71c87c11f140290a9b76e6892d18595d7dc0a028f0735a4c46952742249329a4a634fe74c4" },
                { "cy", "61417ff60bdde29fc59b4876d2cc29527ab3bc1f9d187e93ebc156f8d60472f3917fef7e730fa0b9f4ac99f6e7abc83332e23ca635aab3a5789dd6bc97d8f4f2" },
                { "da", "b52d7548026cf40c04fc84b2ee3669b3261fddf0928a75918be66391e58d32422fc48348e854c1c4582b8450d9b42e2f72e57ea01bc5c152d4ea69ac77aea310" },
                { "de", "cc9ce9d953fb60afc7cbcd73d358104b6a603a048df0eec364d2aae4aec488a0ba9ab3174fae8110202f2306ee7629a01bc0d457e6a0faaa1dedb0647a997d22" },
                { "dsb", "7dcea6868cf650d900890d1968160df0e13169ed197530fd830331a01facaa5a83e83051a44ea2c1ce1c4516407888653d4d7b0f5a7a1f9b1a5c406d39b10b76" },
                { "el", "ca263ac7c525762acf23003478ec15eebc3cfb8d2437c714a09c22df68f299de68d703b0d139c4fb34875d5e4614123846e1b23a11d46cda6e301a715c1f02ff" },
                { "en-CA", "a4da1b294377d34227696b012c8fd7c549067d2c7cb4bedb840903b21d9e225844a54f99746865683a8a7832edaf2a2f2beaee7fd48a05ed5a97b0a6cf062a21" },
                { "en-GB", "443a1253456da1f21e74bcbc8cf773767ef0b424e80cf2f734caac139d1d56593dd14ece581f64a9c6b81dd423684547c48580a63b33ccdfa5a957a8485e456e" },
                { "en-US", "f267b170a34420f288d1ae280614ba51f2527b8058edb57202db3ccdd617751ec6b68331303df172ed8b953d0c3a0c7bb02d87837dac2ef62bdbdaa862950ee4" },
                { "eo", "5ff7b4b4afc6ae3253bb3161683455325305c22ff5e81f0eaa614be764cdf19d1a6179aa1643c9aceda7e098614af6b9e1270936fe8a3dd263a4ae7a6c953725" },
                { "es-AR", "b35c59f0fccdc7ad8786922c3dcb8a1c827108315d7e487241cb9ab521f616f1aad7f3b88ecfb935881b2f77f70b983ec96784ac06b60fb95497eb0c81fba9b0" },
                { "es-CL", "00360ecc274e6fbcf47a39317ebc3b5edab0bd7e3bd27161062fa83d9c174e58f7d9c60eca546ff73dac8eea7c8659a3e6967d23929569792f9c99d06afb593b" },
                { "es-ES", "82a46116b973c9bda937d879652dad441e98f120f11a8693d7bf12babd41cf166fd38530a169c46ee1fb812778f2a6c02e90201d9513908c8c3d8980a9098447" },
                { "es-MX", "d36844cb9aedc0b2459d8beb84ad9cee31dec6a15c086f3d8b1c3389da241bca56f6228f2b7a91e78330d41f62c805156707d0c6aa21c85d4fafd0c413f4df38" },
                { "et", "ff2e6a15a6c62455ebbabc76d177bd5786f0bf5e4173b82cda8df351cad8e5b3b94b93a5b023a6adb4623d2600b26659b05b155a34370aa030b1875fb4627292" },
                { "eu", "42c576098b05d70d4a7e617901f8558d07b23f78b23e2fa04941de464ed19f93ec40d9168c92308d4ed177bb694378fdafeb4b7d46ea6c190a8e8c0704bbb9dc" },
                { "fa", "2a1ed7e4131cc98108b844c7396c12ee0fca6a7ba0b8f2177e2eeba79c5cfe3c7815545ca1898e324acaeac7e1119b10ba49ee57520e616ed5286732d37abd01" },
                { "ff", "857a6443b35e3d10aae7927feb3e6e152dc146cc4ed66431b45bd7b7346a99a503bef0fd16d8aee4fe53fcec1514a8b1fdbdea1ec50a2061a88038f0403e6be6" },
                { "fi", "a06728998cf6ebf9c99664811c85f8a73a46d704ef4c604e218a4b8f7491aff626db989271a035c4607d867bbf11d0fccf2c04a26c127167143ed73c00657d51" },
                { "fr", "1b0e7b416f28e3dda7e072a9a5668110e57fb82cd90271379def32b4122a4345ad8ffe11f923c1228135c3502284150605c1eeb32100c91ac9150fe356265132" },
                { "fur", "8050bb80cf0b3703e07508757d4edcde0a2de67f221439c29705d71ab67070954f7a32f60102f9811655d6a961301d72681b1f098faeecd450a5f0ad1da39e23" },
                { "fy-NL", "928918d688d2dd71f7846557b194f6571e26082e2076da2200ec84fac222acfec874a4afb81763aa3577ad6e16e2fe64cb1329372c3cfb24e82ee8ec3ba790a9" },
                { "ga-IE", "6cd023faee1ba0c0bd54522c40d7912df1d1585e2f6b48b9226b9efa3e6b8f9f7a9952cce87b15db057899093bbaeeb512be58e758b8d80b22fce51ed3affefb" },
                { "gd", "53068a5a9d3e886dffadd8683cbe9c0add5bc72018ac6f2edb78af57a2d6c3a05d5018745e5ca1ebc48f8358428fceb1ecce473b179415d5264fb3bdb7edc4d3" },
                { "gl", "5c91322e0549cd94ed0d70eab2f4cbcf63f6f9945e32d5f91952da7e63bc69e2e2d9d61975eee6246a7d3b413e12e01c3da311eccf7c2b5e41e7b055f474f3ae" },
                { "gn", "7f8ab36cef8971d86dd4dfe35a6219fa00b6f936960423b1eec0b9845595554ea8becd80b2b662783835a2adaa8de1c6e0a3378005733766f95abb1c85d90512" },
                { "gu-IN", "b75edd59969cbcf8465eb3a88621093bcb7c29eba19e9218481b751c3e956429a3e1a1b49f85fa542b033c7f51dfed8e4619c9db52173b6dab461e9fb64ff11f" },
                { "he", "d2ca62b1e8c4ea72f6d463a22d017cdeb8105413d405c04fa3b809d7f50aa02d54fdf5cd9d780f1ec5f570cff884ea877410c6a2fb36240be520c2d22f72cf55" },
                { "hi-IN", "dd74cbc426ed2c1dac160ef3b3c59737a410bd0891ea49fb0b7598477d39a2ac550dcc6e834d0ac790c1ec4c8215af784be7897fccf8ecc7aa4ca896bb6100ab" },
                { "hr", "4222277bb35b16838693465266119f2c38e486bd46091831a538c9490f13626ae668a5ec6d681c7b9507f375bb791110c344af8d072c545fd8da1f8b0d3adaaa" },
                { "hsb", "00d3460d62c0d2976f7dc3e7b975ff4f871a004cb1404131dc5d6fc978c967768a266d7778eacce92960abd47f22a24b0c720d69da09bd5dfcbfdab93303198b" },
                { "hu", "859b945114bbd6551ce0a92997735592829da74dd4538ab5ea0ee3983094a1e991a9adc95c5077b33f60385e2941a0c37028f75d1a7785514097b458407223a6" },
                { "hy-AM", "a6d1a01a07fa13080b0b88e80f5cb4f4d9ad80c2854a49ec04e1939ff345cd1d579047167cde848f814c66a65dd8e27d54cfc533cd0f068f9d027c68907ac709" },
                { "ia", "cb322a472e0e4c66145985ce51e39f426626ec05a1ae23f583a8f11391d476d9933de2e7527e0a43a69c61f8130b6a45fa73c8e38f1f944151ddb31d0c8fac1e" },
                { "id", "c54b6df696b73da6cdde38401cd7c871ed3ade12b6df810713c3172cfaa4bd8113b64f1befa65d3c96e3b17c4d5f725c34061e525d646cd7a131cc8a08229312" },
                { "is", "cec68a434dd3ae0a6a36b285b32493488717b66303abc1a7411b1ec6ce7dcaf00d46d70d8b3f3a626b5a4b13455d0094751c95fde05b911e2021f5b09c46ec21" },
                { "it", "246a6b986296f32e24cabc5e2b4d321858ea05ed01c297cf08ce135816ab26b09fc470fa834802459fc663fb965d856278a61da2663a6db9b074344b0a9503d4" },
                { "ja", "ce3a27df085abe2ba6e4d6cb91da9b79ed63985f187a8351e8aa7186831f777de661d876186e2c7f0dd14cb2bf4a6047ff9702a140e836d6f6733d3f60e3b98e" },
                { "ka", "8422b72fa443282f7e54945215cd68ab6b298f7d24f40854444a3b54d68d2602b24ab7ed0c3f86b11f174c3dc7ee837d145b5bd29ce64c5fcf75110a7ba7ec58" },
                { "kab", "13f52a7794adce72addf44ccbc20096f7967c65ec2f9930dfc21c6b04ac4e7077063f17c4d901f62190c9730ecf72eb3e41b0afcb17323c3553ee2fa18e125b7" },
                { "kk", "6d60e24e9a4804b74c5c4646f038ca44b737177265defba66bf0d189d7fb69f760b43f75145bdaef946eec64be3b41cbc92b9aa6b4e2eb3fb90ab2d126e4f67f" },
                { "km", "a3bff544549fd2e66979b4824d5749fc1d340d0d64b5dfad3f9a8e59af7ab2ce99b6ba1e2a285d798a4a64f5bd2893eeaf542261b5edc616eec98c89a44943e8" },
                { "kn", "07b873d466aceaae9a5dde846d12aa395400eb80fb44d4576ad91b24bab8b57169fa3d7013aa7af7679fb8d0e35c1137cdd5780c1b25368647c0c6d0d7607d93" },
                { "ko", "f7b148f6cddce0535ef09cd7c83a7083d807ad4eb65257bc2312ebb12c789c731e0dbeebb242a9401f4220f6f9bd0b04586f86c38742ac2e7e69da0a6da02b0c" },
                { "lij", "6778dccd53b242f9a286b7b95bcd49c59fb9d23ccf5aee8c40bfc0d97750d1eae75e7182320c961ee4486d55e4884f09e899811e7c8083406946e6a8ddc06170" },
                { "lt", "f063885706940ffc5957632785baab08917a737490698c1e4eb16680f919273b471cc934c3206970e1b7353f329d9f667db8a29d19105cbaa19de01ba1f93528" },
                { "lv", "f88e90963b006cca68bc722a3461fb2eb6e8eb0e823c0d729ef0bd1c20a316c7dfe711f17df188ee0ebda5f75cf1fef708d6e68305bc33f6fab7c776eb5675ba" },
                { "mk", "ef2ee5f0f53bb4d26683e6152ed93ec2467dbb08351d50be3e8362d7709f4472cbdbea20994d48682634654ec35b666d87ba5ef5c60314f2c8abf7736e2c9031" },
                { "mr", "b14871aba9ff592b68c52800470d03693780146b27896c3b82b37fbf5223dd68284d42566040b3f234ec93de8bef468b4d9da36910485b0103a660e1e8724265" },
                { "ms", "5314acc2d068d747962ab3901d5bdbbd7bfd7763ddeefc10094f82e6e82b84350ce6d2db7b3b7e627a668a82a35ded95dbfa8574f5a0a544834028c4ce153d1f" },
                { "my", "ecac0d65dc1cdf2c8cb14d92ab6b5ee90b4ddadc4b702f02bee24b31fed0a2349d90dfa2bfb3e782ed761af4d1f2a57747fc88fc18c0fb716e0f98ce008b950b" },
                { "nb-NO", "4abd5b490ead13f3f829c80ae4aa6a1fb9501f697823af51234a924a1a31a5509ad8f488ab5f7c79f42f3f42ec700a82a46626db2a6e2d784c0f84a65b93a084" },
                { "ne-NP", "f2a809886460094711a959e61244be1895d7aecedb6cc4c8009c5e81d8f335c509234b4a4f6b526e05f4ed6ee6fc73f1f8f4230c9639b38e82e0f620b81c3915" },
                { "nl", "a7b4bab617c1f1cd508d14be90a9e0f0bf60c678af5a6a14a096191471e9cf6ea711f7c5291ea1894cd541123f5186c436488a7f4c44eb5b79c8a574481d21dd" },
                { "nn-NO", "644b65b26c56dc10082c061748dca124fc7fc6c9ff1676f01fd35e961cea7d81b9f90becbec892a126fffde15c2546f9303f56e4390909f2c16ceb8b789942db" },
                { "oc", "aed73ef93c538af14c746371f051ec03c61b4d636f1083bb5b871d099e7a764fa892a6c0d4e02c1233351e9b82b36b05152b220de71d16d13cd3a13bb5fca22b" },
                { "pa-IN", "8fd560f4f9d3aac77574738d05bebe1e3c31c839b05262e1a9d1d0ab3517a10d52ffb063bd5e915f8e4f4294cf0ec5b483f0fdda8e5bb661db3ea71624bb4b76" },
                { "pl", "2853a1d88f4a36160bdee1061729dc731ce8ed8438bc10264082a43715cd83a2a521c7a1f8a15aa4df7ba8eff58b7e3a91d066b0c30e24219b64ad6e04069c64" },
                { "pt-BR", "3579f896377d4c314e66b0392c5f141408a9e86dae7af86b22a7d7ea4ae1baef96a6d7562edff8609e6eb96d002bb8a2aa886fbe7ea0491ac196d2ac67dacef7" },
                { "pt-PT", "8748fe09be32675e9c97dbd9f31d114d4604ce35c14fb045951f56937c0e8598d036d15a1def30d40f9fa85eadc93274c4f6cabd11a6ae1110f967a2beebe04d" },
                { "rm", "9dbb61303cefbfd8bae4bcbf8619330156f77bc6396800b7e11abae329e924e3394bc20664171c6453baf5aefe6dce5dfe402766c1d6af1eb602565889d680a6" },
                { "ro", "dc556eaeb58555310ef94226874cbef583a2133eb1e45d11dbd1b78f662d7658e1f458b257c7c7e678d94e26b19a2740ab18f63ee8e970bfdbe4d0643366c011" },
                { "ru", "80f18c2c9fa765a874aa534b4676cdf4022e68683dd422080dbfd8d9ff3d0db2bc5968bd25713be2867d4c12d1fa4bf3c5fb7ce556ee1b9acc70a6be20b21f3c" },
                { "sat", "7ac5e8530072f021e83f94c51701f293755e8096b4c0c7c8002278a1b29ec778eaeec5be5bda5e67d09c35f42df775fb49e514922acae8ace44b20cf78ec388b" },
                { "sc", "0e97bac4fc45a682ae3214dfda1fd7cafc00f3049957a388793b5c04c24254966a3730e1df2cdf802821bfe589f352355a7a5d47af715256c582268e76ee06a2" },
                { "sco", "7263f5a04260c08c9b2aee7962988888ae09454f0cb6eeaf98103d1393e4a97576779765ff051d49bbe144dc21a470cf15f63f68499b552706c680254fc81176" },
                { "si", "504e1031a826d990984d80c19b71633c4ea054dd4c09fb2d769457973109843c3278369c1c988ddf5eed92fa069a415903699cd9d18284e28426f766c8f8675b" },
                { "sk", "d386f7fd03fb6f3a9419e2873bbea1ff504dc84401900efb11663f289de7d39341aa45f0d4226c4ef92447a74c25678a874a9e0032bfec38e47efa9dba508bd0" },
                { "skr", "ec3e2c50318a4bb43e29bbf9358286148f7d2fe8a34c363646dbe8fdc40b1f889a438871f12c756e090242107aaf5793a765260ec954dae932bf4c474dc84a1c" },
                { "sl", "9bef6fe8605d5a02dd61cf6e0a82f1a245d740ef9a411b115674a6b0919735605bb33e6deb0fba441a6999bc1d8a537f8f99eafa1ac5135bafc54a1ff887bd11" },
                { "son", "743689e7303a1b8c98e12b1f7b3ea442cb28b9ce033acf0244adca614b93768f106742a2ef90a0ac71b246858179e02afcc63f072f0e24b956094b5c484aa0ce" },
                { "sq", "3bf0c3e3432cc761f7f5d5d574ddba5f09a7af8fd4c77e5b66a17787c024809401d88707cf665de15f55eb89927c93e0300dbbde781bf01879d300c09688b8b7" },
                { "sr", "194af8de0298cd2b2eafd0428ca6d119afa8d61ba7104eb6dd585adef2f00af96e765d24e0f6824e0ba190aedbaae8ddf396c33730a246e66e4a4a52123bbb23" },
                { "sv-SE", "e37f83e1a65e3ee75d13030322af79441e6e7d082d677ffc45902b76f8f0b0ed2062949b58971fd94ffbf1bcd3cf859335bc511c20a29af56e197c732ab12c2b" },
                { "szl", "f70ef578652b6ac73fc010f576ad5ed2b57aa12841c9b750e18615a1051680d6713b44c73342facefe15d225a27827cd2e3d4d90c705cff1ec23d6f76cacb2b9" },
                { "ta", "47406cbf3306f296b461759ced39ed4387468402c463f91faf6de361f613a89838f53c24bd4de045b2124eaa03e87f42d3b41be5fa0e45b44d99fa3a27e47ef5" },
                { "te", "96e9fd44653e1861e48460733429ea31b6bd71972c1b29b6d03bdbcec97edaefa95bf8d78dd55381f4395784bfdf304ecbfed0aa4ce18ff7d56a96b6a8ff09bf" },
                { "tg", "3a23d6171fe3c302d2d17aaf0aecb0cc3f5844e36ef1d6752fcdece0843713eaa19d4073a2da12a261d5c20d16950860cb094a76d9fb27c5805eeb4b2fa0c7af" },
                { "th", "469535c788d964616ce9f154955432e4377951c36ee744911b6a69967779bee4d2a5efd163b0cb745355e57593c1f8b57702f68a6959a98a93f6a9b5289d8b68" },
                { "tl", "4c8365e6d9fe12ad8f5f9f80af6f348378405fad2f889a62774335193070dab14503a0e6ed595a4541ff2d96a2a22da2d5c1335b836c0168224946f8a6d5f797" },
                { "tr", "203e35e03b86268c68c97dfe3d2f6c9508b202fba455bb3c72d23e1f620d75349b1a784f5e5e3dd7d915647e1f2742e9257f1fd62dee8011149f755217b0402b" },
                { "trs", "dba13d117cbee88203ea556decd048be4ecc87d7bde87e7226256b270261be533a4bd0fb6f410d544984a35d200483a4f43b0b1e551533d69b12b8730c1ab9c1" },
                { "uk", "53d79ea83c675219db6ff58b3b2671c31995ae702b57a141ffc4910fa3bfeb997968f22c9cb952b5a42e46bd9cff85d0bb4cf04ae48c9184da6e78b74f0d5005" },
                { "ur", "a6ff7a9cab279174a252e71cab700c582c4ede661dda6ec33df86ebdada28a490da60a45d7e9f0a61f5aa714f7904860b9b9ef003694211b558dde804fd8f144" },
                { "uz", "7792f5559e40a115301b03e962fdada6a590c365cdfa352cf8a0bb2aa73f13d10dbe24c2f3891b0b5ccbb736a4a39aa65e28aace1244b463598c8c3a686ed989" },
                { "vi", "7fb71a4c813705b82ec49f51dc5ff551a6a986245582bf25e1ee8f50fd15d053eb3e3acf5dd9ecb287914ba71f0b5163895045fa22f4423e7aa0bd7faa67e551" },
                { "xh", "4cc0de9beab1b1f793a5d91f65d807a4abded66c0967a7d37a970e936f064520fe75a891c0fe6d8575ecdeb975cc7ee73692978d01e7d25ddd2dc9484c060b92" },
                { "zh-CN", "c95fae92b338fb8ac1e400f0e80b3d1895c82fbeb891d365b6e74e7ae6300b347a503142d793e37e70bdb5d7bd7e2d207bb29759c5b06ba8dcdc6f12d6e96e91" },
                { "zh-TW", "ea1d3ecd0f9dc87e8ffb8db547d484b4770169ef4d68c16488bae037b619d4b7e5920592063f9d615aab106dce08d707ddca3f47b7524104f087eb8e5abcaf6e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "10b289618f0825735c63ab0c632203421291cf2ba4c76b6cfdc770bf0a9cf1ed2f3085db02a804cf91a131b0647fe3856039ea6979a2448a8762c93d1e8add60" },
                { "af", "798e46e2c0f3afb360913f9c355afc63e68dd3eddc0b5685b97356db4f3b81400866143facafcccce7bb28028f2e87742d2b010ed097ef269df5a1386b3a8fbe" },
                { "an", "7c9e77db1a0a7bd74cdbf852c37265d9bf64042491c7f8f3dd08ba6d360d9c40e36c559e685736bf2fae88b2f07df89bed4b3c39c070d64c3aaa66d046b366ea" },
                { "ar", "98a31abf862acbae85d97a530e5aa2fef3b90cae2149148589d41051c8c940974eb2fa6c36fecf2862e29d4578fcb0f1a353d44458e1f3103ba7c35ae6c5d8b9" },
                { "ast", "e88fb1650ebbc98c5e00839327136fa654666e1acca349971811517fa8f75db6d038738bd35579fee75c41e4bf3abf3b38dac0b7c1721c3d465fe10d66ab68aa" },
                { "az", "9c4978152483d3c9c5792a63b65bb6582debbdf4f5d573626fb85cfb05772dc67223af640032732225b085ffd26062c2c115031dc64bdf5576efe006a9189b52" },
                { "be", "9160f21b7acd7d55131920d845a08d7320b23ba08df9b708ae5cadf72ad466955180f10b2c054708d1b747c4d1c98ce53f9155e7c7c74e20fa226ee5af6082a4" },
                { "bg", "48dbccb29dd648fababc28c8c31119faf2e0676cd042161ac8dd614bf5ea04d77a43e304fcec4946397afd4d64d6bb74aaa38ef5de99bd8b35e5e8556a0c1c7a" },
                { "bn", "491e080b111a361eae4fda3175cc8eb3f46f9e56b1ff219413483b1e19a2837b7a892fc52b34adb8c362b19715b441341ac1f0610c5f829324d3477d5f51a298" },
                { "br", "e2509ea52c73f88bcb048b20891390a29aac2ae17247ae69225236fea5d99e491631d89e9b700d46145824545b42f6dac9adce942882ab0a4ac385416afa4fa4" },
                { "bs", "a1605d76d0bed706fb9c0c72669c0f23f553493ee5fc5a250c82ab2a770de7a2838dc1a260bab280dc943dc69355141dede6ec231a3aa8ae2f1a7bdf0ad6f385" },
                { "ca", "dd415e3342fe8698d13af5283302f035a09d06b7006c374c181f132c5cb367df61799c4ba50ce09d201af21ebdd250972ed41296f7ca042bd307faafe6f27da9" },
                { "cak", "0daa590a7cf7ad7d3e5c2505d3667b761e2367a13524e6b4d8b0b5bb469d2b9fedebc3ac25be8a86261c4bf3ef0a8e91bb61a6855e16750d05b5e742cbf13a3f" },
                { "cs", "9ce6adcd6096d4dadbb143a2dba3a46b13e4651f4d25efd9ac02cba3e0d0ac3fbec96d39fc25f64a1d6fd1e88028eadebf6785579ec691dbac32888ad77d2909" },
                { "cy", "a46f483b50142a9eda21431c4096c3ba051519a884c1654842718f9104e0f6d60540e51f64d281d1430ad8e40e3ab03426450d8a67943e9e5a72031ed5bd9e9f" },
                { "da", "95b6098c68cf12f31695f41df295ab09ab4598f791d62d3cca2cf1463bbd0d4edc09e5d80b7459ed3ee568f97a0dcc49e84c3e2a4ab50f19b5de91804a5c6f61" },
                { "de", "973350c7dc15bcf803a319636e160ea41f7b36ccb0bf90b664ff69d03fcb443ebab6a337d80e6493cf150b35a7a99ca43650dbb0f07acdb91dd84345fa0b697d" },
                { "dsb", "50e912e876dbf1ed05e962f2ea0ea75d099ae47bee0b291538f061b33120590a8298148c1763051e98d351aa26465d3883f7ae3513e5ed967541f812619013a8" },
                { "el", "517a119454087bd47005a4b3bf219792eb826edb0f00e14efd153743045131d4dccced048e42008e1d5a7c206ef14d9bb7a4fb7ca467fa2f64937f3fb999fee9" },
                { "en-CA", "6e304054741335039963a953bbfa1989066149f2dcae69303f16ba0a555d1e0ad0601c2174cd83e0f97aa2d4b130da699a2c6801bdec9ad6372f696599a38a51" },
                { "en-GB", "84b3f2caf4a6d317fcc3fe23845131eee7d4c314577b9874fe1d8aaf0eb658c65a616f464afea507e3ffc353e2603e19d5a91347e8c6f77236e00af3366d3429" },
                { "en-US", "2d7df639c637842f7d71d5f720e4d4ab80e0bed8a2f71820fff34b28d1c74e21245bbe7db33c1f13e26faebf1e7015680e6027d049a7c020dfdf003d24235043" },
                { "eo", "1c70bfec68b8313eeb12c4234dc05ebcb577adc355e8aadc234a2b723c82c530d9ea0a5d9c758c5734ad9a40835a74388cef1513e65931e432ee88ab55472270" },
                { "es-AR", "5ba4662e17c3fec0b950ecd13d0236819ae9960d1ddfa7751529cc5b7c1aef6d9f0ef9aa44895fffb154c631396c328d5a626dfe53341e0f8486f58ca5c4d725" },
                { "es-CL", "7dad45d97fc47a4a18e2b18f8f3b6496ae544d9a2126079934b1d5b4b70df950e9048b8a369ae113297744d205a277f4aaee131335af540a951ab2af4c26ce8c" },
                { "es-ES", "9ea0461bbb3749b27525fe6e143d22a742d118cd94e8a745c8a92e9b851f0c4675ed4da6c5d66c9df6f7cc40b27cff0fd10bcc22a5b252028fea647841a260d3" },
                { "es-MX", "7a9fb079d17aa0782806a318f08b76d46869226da4bdfe85c0c7e91361382da9b69fc1e80cf0e6a5abc775bc5eb2ab91c271087b8b1d4ef903b835ad09948a3c" },
                { "et", "57414d61b7ee580ef5e70e66445c6cccce725d0cb46f6055c1fc63180fff693d9bd9d02e551e4983705a47972a76c37b79b1f7b05c8304b7c2fcae32b1093901" },
                { "eu", "0c306d033eed7d2253ed23e7c6c29e2da96f8895db14cd3034a6df1eada19f27b3b38196af280c8b6f17a44544ab67f604c1e68a5ddd3f8e7be5b85ef9e232cf" },
                { "fa", "5902cfc3f25eb19763e9493615822bd19c9c925c9046f8d47b64604061b98f0f91cc47fbb9f4c098b2a647ef971066fc8db904736a5f6b3b0d5cfd292b0d5494" },
                { "ff", "33290cf7d528fcd95c6f6f24d1f82059f37e1b15f93ebc97b3861bacc53676a8e1e5bf433dbd519fbad7e866e8bd9c39a932bac1d0a943b708fa1eaa6c4b1f82" },
                { "fi", "568e88481086f930652aeb2b0ecd4cc7ad8aeaf441ff96e8ae916d7e63ee8237e39a2788d722ba6e1212dfc46e004cdc45e4f2e3706b37f69ebcca32d56e22d5" },
                { "fr", "24053bc569efb17948d33cbf54e7a5ba962d57ca3e2da78e3ccc5698cd296b101a8afc8fd4f98abad159159343c8085084ac7dd56b168b234bf449201c3ccfe9" },
                { "fur", "6ffc13671c5d1b1230050e2a20141f0420dedcf29aa82ee26cc401f202138028a481049a6e75cb5eb65ef74101c8a09666d0a501f7ba362994d105f1902cf0e2" },
                { "fy-NL", "fe0a2d37e023d536459066be325c9676e2d52e2fc0aeda940a5bb9c06fab73b4e4e1b5706ad03cbc468e8ada8bc80fc8d769e33e5aa7ba18201b058036a74824" },
                { "ga-IE", "5d5409efb6be35e6b4965d04857473e36eb91e29332c2286c2d723439c499ea88ecc08a21add0045f53a8a206b8dc10212cd80011923f52fee713b13ca92ee4c" },
                { "gd", "3c308fc15dad35768b299b59085928ca65d2f1d5292363323cf369e9734894a7ea37a2f8a07e3dbdb1ccaf479c1f1fb37a6580555018030af74334f13a096999" },
                { "gl", "176201c9b385ba15e630cbd60b00a42219e733e908cdef25027d3366940f8f7a1485c6dfbcb3f4ae33de64a77b457fef1532df97d20acda13648a18cc2957fab" },
                { "gn", "daf64171c366b1ccdf3837ae504d3b85ac6c4b94bb51ad4fdfaf3c3b10518936addebb161d4c93f41b0b1e43000a94f53b96f65451458449348c778fb0890d19" },
                { "gu-IN", "dc7c27203f8d0f4710939dae4f57d0b50fe361568d78d2c5c19d02ca9e8b8ef18335523bb8b5d8c9aa7f2630227925310f5134b4eb72ac43765a453b9ba201aa" },
                { "he", "f4fff411d23a17daef27859fbf50625b841614f6bdb3f4660e23be0d9238daedb4aaf6f16c938db7abd6f457ee27146ed945768cf01d637b6eb835cdc58f85a7" },
                { "hi-IN", "5ed20f9fdd26917f10939965578a078d66075a0dac533a3a21e5873599f172613b896f2b54acd4c73a52714989a1c4e38c48d526357bad1c4a52c7a53d247c96" },
                { "hr", "5e68093ae81616d6acb7a36904867d615fe0702ae1330b26d20406adaa3e89a74fafbf8c99d1569c7060c4cf3df7cb421fdedcca0969bf158d19f31cbc73c996" },
                { "hsb", "9d020d87754f16191c69f19d4645fd0d0a692e80069a9a223616f87bacb5306e4de08b8b46db6dde495078630315bc9e5093fc36cc04e54794d84bd27c53527c" },
                { "hu", "ee696dbc5d3103d716e85f63f6650658ab7c8cf0587d8d2ed8cdd73b6e1cbd4a86b6465bb4485cb911a02c42230c8255ebf843bfd5015ff5b26268ce63a684a1" },
                { "hy-AM", "192b9e326d9df298f6bf3247ec323a0eb55bdc52cd007792fe1b0cd1c6c839421a5e99854b049ad04021ed4c82e569914b7ed1338968da8d65fffbadbdc1f5d2" },
                { "ia", "db88d396232bcfbcb03d27e532b56733ba12929ecf1fb72407306f6a2039a58a67dcb34af47dab7fce1cd22868d4355d56a534beab227ec0699ca9861ebb9cb3" },
                { "id", "03a838458180737b4ff811ee85af70a43ef4d5069ad42b57119165fdfef8fac7b250862c049c770fd544af00953f0b11825535e638cd4890545f7728d7e4edd0" },
                { "is", "118d76756582d5a1ca49177ff2c92437e9591490b91fa988b0e7c4f6e6130f0ef1dcd28bf502a156c0bee5e7a33de2edded4c8041592cae508be87564c565dce" },
                { "it", "861f9d07280d70f3f13c461b14411979753a504ecb5576a4ec31cd5c4798e016eff904ea83a01682a37e7787894001cc742cbe5d02f8b262329775cf42d3d48e" },
                { "ja", "d657ae253f1a6a4d30656edbdaab2a17be360948b2ff6b8c3878f8cdedd42e520f502d75ebb1ae49169b108598155d732cf4dd953581aaf6812096165481b81e" },
                { "ka", "239773f039d725ae166024f8cb83ecdbb25bf7419aa5593e3bf39b91deb18b7a4e0810eafba189f1bb512144e7e6259dda273553630a4f2e88b49a941d2360b3" },
                { "kab", "92b6722f82a3c1867ba720d8ea9c5b6b0897d18b0faf8b9a41a927f69709254d7e7df2299dfd2b5b7ea6d02937cb5daf9251368cbffce6a7176f48164092458a" },
                { "kk", "1bb5e75a53d509214eff3e42c88b46d307d37d87eb673ad070fcccb0d391f7ca344a75e6962b8897bc7e1dc7b28c4848820082d7e6038b2f465c59662911dc6c" },
                { "km", "429a2b9cc2b808d415b0d8f7d10a230b925d88fd23b7fc5390c4417bdbb9d33075fa1ba736d1b0b2288b46160e46f9a0f05dfc4feca6139b3bf0676601bb88d8" },
                { "kn", "df2f62e6c26784b5457200b2c06a2ded690a2da13fde6c7564f10b6938de5cd55e7e395eb8044ec8fc34caea3bd0a639b1661932536cb51900f3484cb922731c" },
                { "ko", "0762f2ff392ef2d2b44ee4fdc9bf49bb3921c31fb1f08d39b99af8454fcef66ef2714bb0703d5569bbd433e5efd755546b8399bfd9a6df9fb319662d593a4c39" },
                { "lij", "da1038e5f81eb0a5e3376190ecb9e024b6682cd8f33b26b81b0696dac21f7eec4d87d02856e9c74355d63584b7a92b1b52909320f69ee41f0c1afbca6467e909" },
                { "lt", "868d8b81c12f91661b68bf8bf88c965aeac391c8a2fddf5d5b5221772b95f1df11947cefed32f57fdbd984b34279950bbefe63d3c1458f11e26c2079c25f2c43" },
                { "lv", "0461786c755dd928be29ebd4b10252f0db731dcbf4adcde3e4d0681b871199cef22cb413a246d751ece4f514e71a68c337ac7422d14e87a8407c3c5f98c68d51" },
                { "mk", "293194271e7e2134631751d4f5758af5368570bf9cd168359cd2d120b4f9fc3e229cab465dad58098bac387ecd6d9f18f091aedd8492a2efb43b30aff508505b" },
                { "mr", "e9a6d15ea228049f058d824223b126f7848eda8d4f55b0b41a0696817399c2ad38927c50a272fbe72f72be187ef9310392a9c72593859db496ed8d3074dcc706" },
                { "ms", "5b3ae0363db85e83d6a457643cb7235c5f015ef72a3717812f2320c84352eacdf4a1a9f3f2d38a43887dd8e35867dcc88a2b5bb4d24cb542610e69ca9f2b006e" },
                { "my", "474ca443849503884c5138a546a8489bbe8381f8e0eea22a629b13b338ae0182cd8540d1e5375f5ec5421626cb1e2734a4d373be1be2c3f9ad9af7efb67c2755" },
                { "nb-NO", "730d010ea7b4e7ef4c2a67f9b5d99f394b0213fe363599a6102a956901aa6a2036348758e36ef73c52b5964e5f939313d330fb1f195f8eee95b3d97902d69323" },
                { "ne-NP", "4a929f65f1df13fd1dc05ea29fe64ae30424e944f5fbb65c628a8349cd8eff535352748a8c5a5636405bd818bc1ac69308d5cbb3fac93889ca9ea697b4b3c55f" },
                { "nl", "03189a8e485c4ff8b9b3d9b3ab20d336749e09f305b33185e50623d02aab4496b3aa80915f0139648d70f4170bfec33e4f82daf1917c9ea87e2fb1dc76b06f09" },
                { "nn-NO", "0eca79a53b88021fd3e9f8471a61fe89af1bdaa94dab239331a7e002ed134d91ca713d57684d803e085b9c170b35367af7f56cbc6921486409de11ef242a2685" },
                { "oc", "c1de47791400361e3079da2b0cf44a3b6e5051d2ac6889bc074e11f489260a719b75e1ab744a57a54e7e27934f33adf11772f6f9786ca5dd32379ad6e46e0ebd" },
                { "pa-IN", "bec7e873d7ae9417f6e4265697a04cf056330e99474c18e34229a05ca6edb4589bbe7aee85c31868055ac6507ba63acfb5326ed041105edd905087aeae6f6f6d" },
                { "pl", "e7e54e47c450ebc2857f8124fd80e3cd29f058cfa00b999cc155c0413734d84e3dc6f9d94830b4c5e8abe30c8fdca0b310e23b198cfe612d66eefab96ddc5100" },
                { "pt-BR", "38de33b371c134d9890d3e33b0d67d789e860eef37dfd62e2d09e2cb3240d58531fe68d250c84c0597dafd3825f5c3f55a8e17ce4bb274a2c0777b08b697143d" },
                { "pt-PT", "614b2f4c11c6e656b23fa215937c765e45ad87963ea3aec258835db967523dbb9ce62164a269b72cd296c71fa368e04aef2bf96ad033e545c1f60a1b0a1f06b0" },
                { "rm", "280afbae15989f01a1716fa44492c1e77997dd32e7aad96c4bd67886bcb43ab8506f3427109735b3db041ea0ba92f56c96ca65c972e34fe62ecc7e17fbe3f76f" },
                { "ro", "83201ad135290b4a67c84c33ba5962e46cf375b231ebca83171d63b776d85eff69342ffb2b172e98f7a366669379e7c1582555a6d1abe85053140f25874cc77e" },
                { "ru", "fea922e3b7b09064d0a3ea6886c17623e0a142c27b1d6f6272717942bf15a0cbfc8a82232f5350527cefbeb9a7b6060ebd8ae3e04a07b927685000d4bd2913f9" },
                { "sat", "8dd4e5702001fb314b5ea7675069e63523f34f0d0290e8182ca04226a8cee4c446b2e82fe25355fdfe969577cd11d2d47c981c83305c3ba1f3961304e5d48779" },
                { "sc", "86eb2f377c082386ea9b4264888d8e6f4cdb6e461826e439751334356d37dc2a17e4f6897abe8513803514901c4ff32b1d6109b270c91fc57c96432484e89bb0" },
                { "sco", "0106d1164c933c5a3c617e859d24690424ea2d3c451a258e19dd189af65866d4e3cb30e86861b87f45936b39a2311caa9f5860c481957b5c33b3d224ef8ac8a5" },
                { "si", "ba8e9096f60c19935d9936da141cdb0e2dcb867b7c81703de100af44929d44288f83a46d9586aa84a1170d61f650e2f44b27174b06cb5f40ef3d9335264de161" },
                { "sk", "fbbc703cbac012403b2f91b7d67bd7eeeb3a1f974a703ecc4f71b15157ca0dc6f00197868857cb56cfb3ab324d9e4a5a0891c39bbfa2cccc555c66d2644d2022" },
                { "skr", "9d6f2cefdf7548e5fb46a75ae322871a60e9914020ce79b94c1148532542f07d79e1fa8f464f26640292bd507d19e22f16e2e143e3725a656d051bf7c30b1631" },
                { "sl", "dadecc74fb2411f6f838cf8715870d3bf97244c68ce4f5a16a017650e18a282207bdab1b729887c5481c4c75139fd8b0b29469f5662fc4c518902f016da736ed" },
                { "son", "a5a33dae0124527bde729550ba0d84182d7d5ddfdb95db011442785694a1421a66c9b84d0128c6a7a247872fa2646893cd4049bc95608b9ba5503cd74585d2d9" },
                { "sq", "f617607f0dafd690ae56c08b58d9c51f9b96adcf9ed52544e10704b1d2bd373f61310a0576aa96464e0fa3679943d3053521a5d0dd2dfa3251cdc85b4b0533e1" },
                { "sr", "21c2cf3a31c66f255e661bbecd6e81a166ff8cbdaa0d672ff1af02805cb3822066dce857c26e9997fe17958393d9ce4ee3d9172f2ab87da5e055c8576d613c49" },
                { "sv-SE", "0c8cf6d9e58b11e71c8e73f43537e676148cf5002b93b697c60d77e966c39ddecbf9557d7346a0a1120eee0b030824df7b6a85d8ba40df4e66a1acad306845bf" },
                { "szl", "7dbebd5c9db0aee5046ba488d3389f48500f589b702776a741dd231cb69012b233ec25212579c26d06f4409720377b5c8e4b0dd2a74ae9556b9445a34643f4fc" },
                { "ta", "8b4df0a4fceba049c63e7a0e135f3be0a0e4d2f30378ebcb860bc794acba89f20ac5850d3034b071a867b321a3b71c48dd79dd8fbec8d4071a75ee1b457b77e2" },
                { "te", "58c741c9523d7aa94ba7020742737c199bfeba9d3a5952d4a595ad48213132fcee1a5ad73a64e482f4954098711e3ad9663a6b7d606af01d97204845370568d7" },
                { "tg", "4bb23fe98be605be1d8eca836cd3285d26324ae22ab882d0347fa553f6efe307319993b9c40b92e613b7978570491fe045d697144d17ad31dc0b3fb454b2aaa8" },
                { "th", "eb03433d54db7c7bd73ad420cf9bd042b1cf71f9f40511d35c96a0b6a7d8326ec6c998c77d1b37797ea2fb9c8636ec5c21cce76cbc31830c56208ace2c70a761" },
                { "tl", "5ee1161b6c8a3cb1988ca6b8229c7dde93c60c34d9b9389fa457bfd366fb6e8371e3085701ac0c5b6d2add8cb5745534d9be21e23235c044d813f3cbac621d4c" },
                { "tr", "55d74469075ce54c0707bd04412fd60fe488478aada4ab96a2a04bdc858ef13ad4a71389d8ea62ca40df62e9e4da0c1db7d76516d532cc250998c5e71ebb7aea" },
                { "trs", "7c804e5ae15a2dd713f268845052384ea9ba1ee6a18123b233c4a11ffd90eefae9d0b2d63d86c3c2a3a82ee813b77aced8fb69bd25724ec5327a5d92e14be0ea" },
                { "uk", "f297e24b1f19917e27c345f8586901ffd02783d5dfe47f6c5b2836d4f47a40ab98b78502388771db6db0c45251efcd1476a229b5f9fff5c6449754c6aa29f01e" },
                { "ur", "a1d739eeac02a521f4524b8a149f7abb073badc3f8e164035a5df4172eb2f514d2863f13981c55da213a6df3223889ff5f58b3ca6e9651590b7300d9fb2f1144" },
                { "uz", "0cc7a588fe04375d74c369c31180af9855c9872cf244724aff86ddfc98dccac815abec3c88b173ed22c5af8db2edb3be122a5309b2e617a3b96ddf3e95d30d1e" },
                { "vi", "48475717ca0efdad9746db97b2a6b4f1b21aabdfdfe92ecd772d2a03cc36c1e20b1c15efc798e054e4646d7badf60adf3171358f06c551cc0ca846fb97f59d3f" },
                { "xh", "153d9d2ebe4878d2bfb4e6837b258a348577d05fde50ee65c923ba2239a157e3a54d85099014ee5c64537b384cb77340e3527671a91369433b2b2e87596d8a15" },
                { "zh-CN", "9e67e4eb8876a99d2bfc59c2a59a99d29b83c5fa25f5375e143736273789e8d064b74d017363108d6db235f86d3feb4882137a258b69be29038c6badfd2edcd0" },
                { "zh-TW", "65ee30616b1474371aeee5fff3846248bd780f93daa221791c39db75f1884b7cc7195c9bb8710867f3a8345bbe935086d0323bacc88653d5706bcfe177190355" }
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
            const string knownVersion = "153.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
