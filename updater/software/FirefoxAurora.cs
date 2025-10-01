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
        private const string currentVersion = "144.0b8";


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
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7bb7e3dc72357c0ca86b5d5cfc07ba122f69bfe443d599c892164a27c978ebabbb043350bb0d8c0b463be5e580dd508a9194a3d3b3af01814b6de85208e91830" },
                { "af", "1517092049d4b370d6334925658bbe4fb8966de67469387a4f97b34440fabd1c20fe87b7cad0664694ead9700f8887edb369858142990e16f008f32c8476a4df" },
                { "an", "59a8c67e9af19816d0ceb45e25ca900e8039a6ce07871d95a592fa41302204ee81ef53886db0e943ef6bd69a0b6bd1ffb000847a4f65b93fd92a025cadba8157" },
                { "ar", "30d410f9abf901ec82a806e90c32f122bcb909762c83c512198fc072efce4993a2faef1d9e368d7d3891df1964423bcf40d3742338000ae8db56719503105357" },
                { "ast", "040d6abab2b23432926e5861660154ee6b992929d223a82c36c27986598f8f149445108d98131a122d1d29aff328c36c87e6b1144fefb6654ee7712ec8cb5ac0" },
                { "az", "655eb2c024c08ddcfc1503f62c598426586392afc652722afe0da78ba03a50c2128b493f9927b370364f11e8323a8d87c8770591e3c44a92142b493858fe6ca7" },
                { "be", "7dc559253daafbdce43a612e704998c51f4cf73c5fb534b3fc257df6ca6d149e5d29b05cb6d427e12ae72b99a204866cd95870781a9bd5b793082d0ff23fecd4" },
                { "bg", "c6dafabdb9aa34d8e73e8c786b95158c62734d3bc3908a1fa2b414d6bbf0f64f28657de18ca97b5609f3d25850c93d8affaf88e6a8bf1bdc31c9e0a69f588e7c" },
                { "bn", "a039fff10d8df596d9b4111dbdd70fb7036f77344eca653d9444778e707ea012ac374fc0eb47dfd55e92f960c38065da4655e272c281fae98da2bb09f2d27420" },
                { "br", "b3c81cf85f934ea4e783d64e50b44cf8800d1ef4a0e67bbc6f2e1782bc3c68f2020358c3435ca9faa7f5bf75fc5cac8a378b2fbfc181fd8e220e6e6dda98d652" },
                { "bs", "4b184114091f623ccb8d064c04e06260bc5239527be22c114fa669745d37633b9440496ba502201229d9d8de98d73fb500b9a558a5d8046590eff747ae358a87" },
                { "ca", "b014ab46e768f5428cff2f289344842ecd3d773aad115ace9a6cbd212455d87406cfd260f50d6094d1969a5d788ff622e6355b2acd87de630936fe9866184391" },
                { "cak", "9a4fd470c5321a668bcbe5e153c0f159b239476ce3d2a4fba40b06fe1e7e1eb43c5c8545695f394fd233dd500e2074f20c470b76f3c92511d5e6f2d0703d9130" },
                { "cs", "c855f77e40c8c834b751b918e44ee8191552af37f80bf5893cee420c422f48596225e98ca6daefe81d6033bf09961509c8f00e809b58ef06950acb42ebba2f84" },
                { "cy", "0595eeebde306e5e2db19ea967e1be3ecaf46f50621fadddba45b9a8aabedc4643b293a513f33d7016c2573c4dafd0a06edc4a31001d276c5f93de065e22867c" },
                { "da", "e2af98e38e9a6ca62feb1fb8ea7ffbfa9d047b080b91db410d088bf8e76949da3e8b6a1aa94854d5a2a5bf1c7503878d5f1785b6e716da6857f086affb076b20" },
                { "de", "a01703d6a43bab2e703d6dd3ed3dca40acd7b8671917b43d2d405a57847c19041c3998a01af9aa3452151c703c95589a3a09f9b0e8639ee5eca5a58e5cd47764" },
                { "dsb", "a50b4868c851025644c0f69699e17c18b32f83309b21b4082f62b16170106dbac860ab6ad68def8b92e9a6f5f6564e99380a6d2d007700051508d84ac0a51676" },
                { "el", "4ad8de28de4c13b2eb47bcb0536e9cf960e6bd8e090d690f363903a78543188649784e5bf66b078cb5bb5070c67561be2f4f30621f04e544d477efdd0e3337be" },
                { "en-CA", "4065ee94bf29706e9d99ba60f4b931c059c94ca90d2377155423dd73d59de86db7fdb8ecd9e42a26db583dbdaf42b20b0f570997a52aca9a227f0afd4122a859" },
                { "en-GB", "e236dd89310068e43f831c2fd8f9c3629d479a3a0c199ebd9f007f03944f893a6acb83744d57440115b8050cffdee057409fff5524ab49045ed78765c3ba36ee" },
                { "en-US", "182c39d7a3fb625019a9e4578d8a450897341d557f89113a2ff5a9051108f8cd928d0917bc7817f50027476c057c8c81c48183a0a4fe94583d29b42f6c8d77f0" },
                { "eo", "9b2658034677cea1a0e25f1aa51e51d5586986893dcc07f9ed2480600df56c518cacbc862e6c227a97f36419c00a1b0837fe119e97f76f7f3a2ea0556d16b1a8" },
                { "es-AR", "c031b83d8057f6cc07588b9ef2737470b4a83ba911afc3fa5d3aba0945f295bb61b7d2a50d6fca82acee47a76816a2f9d8d42d66fbc77acd7f70d9ac35d81836" },
                { "es-CL", "b7143369ac5501e0b192b82a3b4d430fefcc724302269b03547d046e98d34d9adfebe2d3cd2edc6f4ac2b306c59e404924ce9e8fc5755078e167d8180aea177a" },
                { "es-ES", "5d449ffb0c2a811f71b4e08f583195f7441b90a54e0b642a9b397b3761d3046aca0b47c71b17bdf89f74da478d9010c198985250fe4d5cd9be170fdba072b553" },
                { "es-MX", "e28057dcd5e29211fd0df375829fcaa84f350d914ffd13088e313d9b22fad373ad47e25839e4d946cea464cfcbef3663d774ca2d1eb172a4229d3bd77dceb6b7" },
                { "et", "626034b33eac6940e26c3c90dfaed29b775bba7a7823fc90db6dff1526a8007f9ce3f578af2afd33f0635c53d291473260195e4db9d2db579b8eece9f747f25d" },
                { "eu", "b233bcdecf1147ce402a529cb4ec5b0f40c92a886150d2e41ecc86e39fe247d827719eff610254f4e37e96f39d7d7abc651a49e183966949ead6b3451e9fecbd" },
                { "fa", "ad997e9b31fb2a043489972f08b8dd83ecb128702349e0673d4d9f9f1e8daa7d70ff0d7fd0223b07402db3a2fd9201c568ab9f5f2efd326b615b1edfe7c09b9e" },
                { "ff", "f5373e390e0b3d2426987756db14726f65a9d90db0b66184bb44407d04813911afbb332b6ff56302db2694b8b2623c5453c2c25f8cf56ce0314b17a7ef6546ea" },
                { "fi", "d44e25c06e79e93dacd75bdfce5b73e55736e47211b19f8d1c17ec1ba98bca28a2451276b5bb0663e9ce24070a17e3db921c74254948ec2d741c593693201390" },
                { "fr", "eb39d472892e8f6ab7805123b411745f60a816db2ec96333a4f0ff5e405acc67627b6f0bdf52ffa7c75177476f1a43f05811af4b0ed0cde9b803725e301f102d" },
                { "fur", "b71d1341f73f9e125ed02c5e856f5495e7e387a60d7319f63c154897ce8160b5654e7388cf06975808a566f1327da1f342ff841b34e9f8ca376fdb13cbed1c09" },
                { "fy-NL", "57ff120a76037ac0407964da29b1390503d079bac26a11c0ce8efcc878bdcaef92836214f335f3d1babf2ca74310a2a90d3a8c1db8273cebba15088c07e6ef42" },
                { "ga-IE", "b6d17ae1b1ccf0177f82bea46a5b83b3deb751c868cd2c68a389806324ac7f89d6b626f3e0e11a399b35f00699af04d58725a478776ed7d3062a42d3cc1626f5" },
                { "gd", "7e63610c57d70e8f6ee9f6e185d55d72bfa99db61c8d75ec894f821ebedb62e8b6ed00d14fe8a480196bf02cb7a75edfed03b9b5ddf1e32fc58e7372e4268efd" },
                { "gl", "eaed72cf8d2a54bf539476b508e587cbb4a18cd0ca3b02367a498c04265215755091fbeb7b387dd0515319d0d482bf3b80522aa55fca65347468f15967a600b4" },
                { "gn", "bc8650b9451ebd5352cb92996afe451a60c288bb5b8415a3e38962df6e9e0098bfc4289cb2e40ff75486703d180cb6f50752c7d7dc630281ad7edb138527b169" },
                { "gu-IN", "4306ed9eccb882edbd3eeccc35864ac90cc4ab6c96eb3ea8af1b489bb663b7bb535fb933eb3135d21c089025f709e7824bb12b5d3d5a2346dace516cb8c970bf" },
                { "he", "e996c8b7ab8c4f84cfbeece72773484722ee9333bece14dafd7c3b9205214e02c0bddc92fd54bb8e647509f7ef2ef8667906b938b49c60204ee2f11d8b3f8cef" },
                { "hi-IN", "d1a981abd82596da2d1836f693dbd15e3b453c4ffd0587d5aba2e01ffedaea6cb4c9e45c257906d73f52c20e0b0f0a69a380da04fe7dee6591befa4801b19167" },
                { "hr", "fab24ea886366180c11aa6d855e63a6515df81362004ff4701fd5bb97054fa105cd4f6df3748226c5340ccfd34d33430a4911bcae2e8e30b21bf7ab930d43b4c" },
                { "hsb", "5f71017972036fa30e6c187a45d92a2b2923ad89d960b6fd002c120f7db09db4e2e06e24a344bc389c19476fb7b6fec5b06c3d2a4d407db03a7a964bd32815a6" },
                { "hu", "f0f5545cc33584a77f67ff8eef14929724a9f1fa7b6f677193271b3e0ddb2e09e549332c67df69030f115e746012bbaf1f6d3bec0526f52d2abf9a1780c3bedf" },
                { "hy-AM", "6d88697aed8b2aa7b0f3d84fd8d799a0866db000f729140460cef272b21240ab71b6375204f7643109e5906afb5eac3c3e30dc6ec2b8bd4bfe055af4aa9ef7cd" },
                { "ia", "82be0c7a0cc80b5ea8f3f75b067f9284b35232ab6c2cb633c0f0bfadac3c912c1b9c1d38497172bd9c9eabc6de561cd3f1d0fec4a1e0b5a2c630c4a544631475" },
                { "id", "9dad99b93add2e5198e6fe3f2d57413c92093291cecd7e3922057e85e50e6c654ed75699ef9d134c54fe03335a17af756b3375a9b5099f0d82334363336ef537" },
                { "is", "e6ac07bba3c37beba14137c359c2ebcb2a30b0193c166bc60e0e2f7c624ce34e3aced0da41dcdfbf2283b66a4cacb4f9df22b524f15b69f3d8e62976687607de" },
                { "it", "7c99d6d1470819c14cdecd0c2454f1b9b7810cd901f09ed5daea811111db1d249fee9b173e636fbf4b6d1529f756284d5aa9b0fbdced6b92c5e3d0ca207eb9c2" },
                { "ja", "fc4f92ad9da99fab7f62aa80e8ab923ea2bc06fb3f0fac2aa17702ebecbddb8c5c0ee16d060a2f3ea1b0a5ca2cb5fbb221c5fa67bc4b1f90396eda5aabb8e428" },
                { "ka", "22e337aa26e8490bbeb1407247093aeb3926cba2b31af8779af89d229d48338bac6fe40af2e1947e997ba8c248f13aa45ab9866d9ddde455f93d375fd2a1e602" },
                { "kab", "fddb546bec87132c4623dc143416319fc0ec569b12ad47b3957078679864f707010d57273db0aab8a6a19ff26124b4bd420ef6166d3207258567a4bc0fe621c7" },
                { "kk", "9833416a002917a824fea8eedb3af124630a4cbb9dabc5a4459896b0aaa003616cdb2acbe997c69a8e48cdc02f1785e6e94915b8ebd9454632f22cdc0dbc8ea8" },
                { "km", "0c92b4438117317869239707df9334bdb9d3a5433f68b72255b97f2c3d8dab4c31b8778c1d59cba78f92bb5fb2e96254960f98378bb2ce1c2af42af045ff3bd8" },
                { "kn", "fe708f0631aed6fb8007c19ac4662b6e99c4580089c45b98baf72df7ab5c62ed2afcba5bc8f7689232a341e50f8434d7c01ea86788f226fdb13a4833f8892eee" },
                { "ko", "b88be3de62687f1a527ff0051190fc84f736408a907c8c3ad078cd9381e7cda96738d30a0d8ddf5d5841754add2717c27cd23296997ac22b51bba43765469bc5" },
                { "lij", "ab77b09c462291333bd12b905ad3b2376f02aa86d7c18c1bf99b3cb971dc5fa8bf6b4ceba71faa9c2b59132eb6d57d7097648dec43e0d7adc76bec6fa2d4bebe" },
                { "lt", "bb14908f4472316b632dfd7cd435b23561375928f81d04e5c6dd2b45784050c5706ce6ea4837cfd8519f0e32a58b0ffc8f1077db69077f36aef94f764a891b46" },
                { "lv", "3bbc2eae1ac1b719f6df7ca567afb6bf63975736afdb73bf1f0261875689fbc50c8202bfb5d1d9cc1ec94b66922ef16cb9f17fa27e76bf1e7eb8622d3c58686d" },
                { "mk", "f4a00043cc82f2c5d63f6d08e4c72942833f903239de34147770d76615cc1551caf6604fdc1a41c9540c002dec10480989e184a017bfd9b2a7c804df7baf4b10" },
                { "mr", "1db25a3e9332d4b9eee9b21c40b5a043c71bd83cef3489c40f1b6cec879785f4946916a5d8f426e95f191913606f51c91466691c3c98ed79e65f39924442c94d" },
                { "ms", "df2d1c5b39a6b09ec5a30afe210187cb196d6307476c3128fe981550131a6d0d4f6b840bb43fffd2c02e20823d20d5b2654a5ae4d588dd1fa708a1452792c0e0" },
                { "my", "b32c928468ecf31c68590e30a4b5b140606954ae0837dec255c38bf53beb3834f6e18f84614216804dedfc0230581baa4109e8489722b5b50f4118f0f022780e" },
                { "nb-NO", "cf19ac8bf87091cd9710dac4878878a5aabf1f01dfb766f0d9117fecf32ec1c4a69e41f48749150819694ea8df1fe9491d3fea1d3a4bb04ff199abad2741b03a" },
                { "ne-NP", "7434d4fc0970ede55a3a358c013254a972d5c92bc66e1b765dbb4600211c7014fe8199572b4d01de0d730cceb28553e5b5882af31489650b598131db7c0e02e4" },
                { "nl", "3e010d5c17301b6c4ed3e5de4cf00cb61a69c303d5b331ae31a8f5047175458ff43494ce9a66e72706b81c3abd4b0f94234c042b76149612537d4995ecd60775" },
                { "nn-NO", "d09259541ada7dfc167156caa9fad7cd3c119fe7d2104dd6f186ecd6e574261db5ad24e084d2c2b10c5922201cef85178f4f713c63a66b671905d18e9cad2433" },
                { "oc", "d01f7ce49ec42d9fba7552a6a4bf436ba44b4b3147de3cf6c1901bac683508a9e8fbfb7112fffc40e4e2d98eef05c81ae35130e69849324727adc5fc1f68a7f9" },
                { "pa-IN", "6719d678e18a7120720d8a5270139e9ce5ae7c4510b970029a01ed604f73f88bd2dbf7e46adc3bf8a3cc06f954338ee9ca6fa623a50bbc57a404578aa7aa0b5f" },
                { "pl", "7f55ebd90aba7383b37cd0aeaa8ccb5a059ef296c64cd6a4e1dfed88ee2c41a9f56d16c783efac51a229f6462bfc1cdfe527efb1d4ffe602d9729826db75dfcc" },
                { "pt-BR", "a0ef8b6f47c5670ef8a76a1e00a1bc0fd6df2e653fb807fde53c8b68865e6517064ce3ed90a38b1c4c36c6775cf8132b9366e00e556dedd9a001a8d1f97834e5" },
                { "pt-PT", "3cb72fdc2eef8ec0d6b1aa3add64dae3df6797632f1dfedff59543a1e6f5e94c3b575e61cd708b11c9c0dda83bb405a87a78e634945a414565d01225389864ec" },
                { "rm", "8a01d416565a33e0445131b4f729412101765a4729113579f3ead94174ee3bb436101655f5951e157d1d30994690cc1c9583f9ebac2ba60edc572e4f66342c87" },
                { "ro", "687a8d0f4486a82a2fed239fbedd6564095980a87c1ac411967e4f776e8c0c4f9225e819005291031f4288fe43f00fbd2eed3f4cf5d3ecb6c214bd8c7c77de7e" },
                { "ru", "6648a72e943a15d1e30d58d18f922517c0de6e9a3af7d93ef547fccd59a06838511c4bba14f3b88178dbff84514401dea1585a7db06d00476bc6b18c4290bfad" },
                { "sat", "5d105a03ac4caba52f0c5337908fa096269de1c6343a673cd456a2d054116b22a401fd6e02c5ff264062a8fc85b1306c6c6594b449a8b17211cf68c377552984" },
                { "sc", "8919a9f6d51da2795a1a1b5d949457f84b3f7794a87f897e345cd722e95059f3f11dd7c58be8f7affe34e003177e8e1e85aae58929c08cc79616403c7907e8af" },
                { "sco", "e5cf99f902e3533c97c537145236e46982119c3a83ae481c692df9070965da1f50c8d37fab9898701620017ea4255170ad8346a047bfc7cfe232d75b0e01755f" },
                { "si", "cdc65c457db71f0e345371c6dd25eb390cbc0d77dd4f6e3fd6780da16829e9a1a118586ba8600a24b3497669a20ffcb1ea38efc5a9963f005c879c785e606950" },
                { "sk", "e481e23788c842b2c099bd1646994b418fdca01a08aaf59fce0ebcadb905f7acdc3ac867b21a7a221dc3bbba6291df31961c3c35a77b3609bada5fb62c6d9acd" },
                { "skr", "c1fa332bb5175db6279f0422d482535f9941b1c38cbc003d4a7edd2665a23da81f55c6674fdaea87b3681c3ccceb6c9a37e2a0527395e13a59dcc25c0dc50ac1" },
                { "sl", "497873da2555693e9114b82ce9d46231240c40f98c9b3effe091c1ba0335d8ef1c1e140161c23ef66357f95bd40aab9887bc05388c623a04eb04282d310e03d2" },
                { "son", "274f5ee08764217554156304535ad3cdacf759c3d02783f90167d57570b5c67067924b39215d810305b38d6dd9332895d9a4981f198964e01ea4c88b43bb5243" },
                { "sq", "3365e6ae944a52b0a8a75cf2588df266887718777444681bba8aaffd4ea42535149642a07b3e0a2e31a3c0af3d9f41d9cfbfdc1a5135a1e320694fd5bbbc8aaf" },
                { "sr", "330ee88649d8ed03bb748ae310020401b6af040ed344d55af9412dd5316dc4434bc1ac625de716b30725d7fa77fbf4678b7b3ca8c915ebd1ca2254ae1ae9647e" },
                { "sv-SE", "63ec8ee8079da19bf2e6a285964955d1fcb59dfb9c209e97d8317442b1703aadaa63f3be072a43264e81b0e3babb1dbc94086a2289b01668f561d4f071a0e977" },
                { "szl", "2ec2f15ca9bdd39e6eadf7d8d84fde3325659567af96da4dea919c1af248b67437a672f2e181498c0df0d4fceb969ee851d2c7af3a8f7f5f4ef8fa263a737bc4" },
                { "ta", "8a91e2e48f61d15815ffe647d9ea2d93faf35feb9e18fbb45c4c4296d6ed633c85dd5764039a224b8a292650c2a466b04995dc48dca0fd9c04c9b2c5a14831c8" },
                { "te", "53146cbc4ae49a4f580afd76bbd5c5a4cfb34b3ce90fcf7ca74d3b233bb0278f7ec6e607f9429c7390caa33d16b7eaa47eaf56d1e0c12e4496b647fff97a28f8" },
                { "tg", "f131f0ebd839b99dee1a3a7f8154b2e4d7bffe6a888ae7ca5db0901fa941682f447a98e666684d5b3d9236d8cda7441a433b18717c3f5692c037fb4173ce8786" },
                { "th", "f300abdec7f0f3691b67afe21f60b474ce3f1ac76390855a867919ef30b971c1857baf5e3ef304ca43f87995cdf6f00271a2f0a1e73273226599b86734e41328" },
                { "tl", "6346572c5b285c1a82402d595ec1a9b49165836fb6385426918c2780a8f6da3b921e6087c17f2fd3b987e214a14d4376227498c62abfa0fbec807072c8a3e168" },
                { "tr", "0a954d2b2ed8cbe91eef55bdf12e706d15e17bc537d03e6dbc7278997d98128bc8e8bb0a056e96f2d1069473be1fde60ed2cd7e3c4f368db6cd0004b44713fc5" },
                { "trs", "72932084338f151f04c46364cb24188904448d756ceec7562e3fff845f2707a30e0b94b57537b9aba0bb63d87e98e848d9ab9df7f1b50eeedf11db64f698b5eb" },
                { "uk", "fec16fee901d50749ead57acac977953531599f133c4f81567c45818a2c8f9e64cb63a942fa39f541883487147b8485a32a6fbfb4f3b53b635a3eb031b4e163c" },
                { "ur", "53922e362d679f76044886bcb769165c299457533ecc26c19c3f79d91e469dd92ac6a3aa4c1ff0f0c2b49cc00e25459f6ccf110afd3c25b71cc972548ac34fd5" },
                { "uz", "b9dfb27b9856795714c9c8c061b73d7dfdf35010e9a814ca0044b31c4de4cdccdfc7313f7513bf35c07d95b9985774227e1eb0dd75048f42c73f5da4af5b45c5" },
                { "vi", "eea20c87718c329bbf7a1ef9246559d3af4b78666fe52271971e3dde847f0dc4327a68818456f79b56b029dab9285ce28f7d652c6ef7bf2c0a68dfc3bc63ae58" },
                { "xh", "649871d2c830b76e8b01f89e0628e90a8f5840690d25195b5b2e7b75b020c42e3382e590fbd4ee045be196a06a92bef36978af17a38166e5ff6c6cdf112dbe24" },
                { "zh-CN", "6465720ccf899314e95d427d3918759113f2686784f83a20c5aa9754873e7cf0667a5191cfe4a56ecf85fd98d323e84a8ba57559383883b8fb90fcff76dece5a" },
                { "zh-TW", "c535793663c380af021d4603ec3f6eb186291153ee88d944ba1e8488cd550453806f4a31e789b3279cb3a352f46f77c810f73e651e3c3aab709c3db7fe7c1462" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ff7912f45790dbc00017c7ec7e2212ce4835caa427c1d7eb40892b732f390de9c8d79ce26f56b3e37e7b45438763ae34fe629d458ba749c8919201a8a3da3f9c" },
                { "af", "eba8a86e4edd85cd992a552151843b563d53901e40edbb877052c477c0145f07c125e4a189a157557ecf695df8d47a8f9aa8eaf47754a8087add9a4a763a10ce" },
                { "an", "c9471b4e73c26b660c5c1bfdf34ec8d1cd606ca44c9e09141ff17896713e25706eeba35e3c8a83f7d082daa3ca1ee0e0fd58906fc17a789cb070034cfbcae65e" },
                { "ar", "233675e81d103f1c545b1f3e7db012c948224be0e87e364a44584f1b2ca5dd43ccba4482e512623745ae7ba3a8481310c395abb325b87a37a27bccbeec8c4116" },
                { "ast", "a4720444b6ce1397a53da1ad02cf991548afbc8ad99102668ac4840fa26b2c68b347a70d31e7b8f8ef098163b940bf2642f7147010e512660f049087c1aac1bc" },
                { "az", "76b1040d22a06ffedd4a36202be3e670355d71980ad6188b5f31a7571dd24b64aa16528f4e45cfd083bb7fcb2b515a0e0b832d06499ca863ea94923552b39ee1" },
                { "be", "850ce1f034e3b2f808fdd3ec381668c8dfce16b6a0cb4a756e35b604548f4c57485cb0861c80ac191dc0d48a4ddd8065f98cc85c4cddab79f51d5fbb7581eb78" },
                { "bg", "e6e51c9291d105789aec49cffa135a93a3dc4cfbd94fdc53d284a988899b0da4fc23bcbd4c61a5480f8ef84448371149cae1e5cab5cdbc03f50b98b6e6604f1c" },
                { "bn", "5b8e66eff89ba3efad93bf4653b32c282cdccca72f496d56217f1684f92f4da4a860c454dbad3510a23473bb22863882f6ea7b93e64c53487f6ef3670f8d25b3" },
                { "br", "62226e39c8eaccd1f4c3b142ef0d69f8b559eadcd149202896afa988a5c0481deadf9ed1892c1a8639987457ffb2f16313144dc3634df60cc531c5901404f807" },
                { "bs", "118fd46a410589ec3ab85c1e5117123243965e0ee13e0d11410f9d99740620fa7bfbd596d9614ac7ce782996023a0d38450e743e5f47c9b124f9a2c47fbeba69" },
                { "ca", "a9c11e12f620a70e59eb0bc941e46644513f24b98c12668066408368533918d4ab7ac33cb1b739fc68c6354b894cced6d8a1587b894cf22ddfbb0260d1b9e100" },
                { "cak", "0212c2ab409579a0d4b268ff6459650e5abac6e22a2353b5e9fcfd9786a17967cb36ec99b2a447d57cab2cca93c2d0a2c6391014232740b17299b13fd348fb3f" },
                { "cs", "1c75e25aaa4d635c4b939eb60edb509626fd3e2eae6e93a5a1a58b3bcdadddae94b2009cc03a86bc88fb4cc936d1c71b4d35c498296b31c80a37832b71409137" },
                { "cy", "bbd0aca3c398aeadfce9cba4320e2d702dcdc0a5b0415ff73bc05e134ac071bab8b8db3d577743643406b1ebb257999762c2869d32bad09312eee98f750d08ee" },
                { "da", "6a6f3db175f1f7fe2184378b0e48025d7bc9caa87445aa0aefb35eef5c6749b427dde6926952dd3db9aa0294487953c8dd34650fa3f09fca1f71c8679328b7a2" },
                { "de", "c326001cf5fb8893218d17b9bad24072604d31954bf9dbe2b2681341ba9fc6479095a6bd916f6181553adce27b737014b5dd832459d520edf95bfbca802de8b0" },
                { "dsb", "8d186357b8ad2b7f36b37144ec08be5fa9b8657ab77390148fa0cd75ad07aba91655347a122832bc2c2eea2f9588457aa69e0af488be265e3e8672a1b8a96ecb" },
                { "el", "4af1d0b9040f17f14453406fec360e890da431fefb97a9da928c3445e3a53815f58b6e237d6662211cab727c8315614debfdf7e74d7337bbc305a2b82e830104" },
                { "en-CA", "ad983e8dfb2e872e0075bca5515da8ff1c07d6f6a6fcd7d3c38ecdad4772b30918557a78d8672f5f7b25b0ec8299046e1c06753ebbd4f7575392ea5fd40b1b16" },
                { "en-GB", "8fa187fbff8e0c3b7c3ac26f7694c811711cd3484f616618925d7b136cdc168708b9f0fed3b8624f3b2bb64f2bb29faabf7e688acf4c217f6d8730189e65a4ac" },
                { "en-US", "2bd12cfdebea5f51206ad2aeb06225ef3715512419d44688e207e152e4758f3a9b37614a20d1f3af62e7f25dabc1e5143652f20dd732cdb5170690bed19e3836" },
                { "eo", "7ffb4d4fdc1b8f1dd0cb41c31fc63c11dbd1ef0fb89e98977f2e5b102377f1b6f3b6a6ff0aaa9220285db2a8b5c8096f30576ce5e207c2ab8c10b95075bb1306" },
                { "es-AR", "c5d441d922a3e92f59f052d8355fb4c4238e5b0e627d0b420f33e03e5aad5a8915b5c12b73d2aeab0e1e6fc69f207318d5edc8b8564117869efcacee0009cfeb" },
                { "es-CL", "402801dbe8469de015a86a63e63031e8863061991358d9230e9e184543818087889132a891038da7924cdd735d0ab25d054396e5a5274be3d11de6fd3ec94f68" },
                { "es-ES", "1ba5ff21a9952e75dc00a93844f5cfd043300786b03f0d6affdc81236bbbbfbaeac99505a07c4963acdd1537340a78ed4c6dfabe18f1af3869b812cd9f58db8e" },
                { "es-MX", "6297aa55ab21c0aac5d1f8172ab634dd587c4f5c62e27cf58031ffc75ab82d040e08d141340cf8d7018b2a433958d94f3ff6c0628fd808420499b0cb01d431b2" },
                { "et", "8eaf1cb34632d55fc93e0c36773bfd9fd6adcc6b9b306e4c7c51878246ddfef59729402bd4e511c31c792b90cab87b0e3a48f266879dd657a61a5e57fa0b7806" },
                { "eu", "d03395b31dc2e79835ce1b728b9ae18b58b5ce4abc8fc32773b25432923623e8f6ccfdb1cd50708a41e519d7a68e045276431426287826152df4221172071afd" },
                { "fa", "0a165c155f05e29995b250930e218de0b602209f0258fe4dbf01f0f085dcdf67cc52348aa9568d817205f727ccd63b3ac9be57d1d9835621e1c33864908dd7bf" },
                { "ff", "53fdcb454684ecbc0f7181a15b61a7ca31282417acaf456e3ec4b2102d10d1c96506f531345152b5328da677528ce2e088ba89b01fcd97701d58067df350b741" },
                { "fi", "f81a71aab125c0851b2ffa798ebe0b77f616fa39707ce9603e8a34aee132f98fa672d2c47294413d017cafd1d008957aa4ff10989a54417005fc4655fb2ce19c" },
                { "fr", "3997f6eda3f5ea4274ab3078d3bcbc36fff89c4f0720ce5c119c406fbb8a00017c84f4e5a907fb64b4632797d3a64b1a9672eb97dd7fe180ba0f74aac7a3b84c" },
                { "fur", "f4decc31808d2c5c7e6f3104b56e211c5a002a11511dbfec8a82f218f9f5bbda1e5238a5c37f4534aaf8b431da1ab2a8b774599950e21fdfc0e7f2398b746c65" },
                { "fy-NL", "2d5e008eef1f342187c21d4ebf02ab8351defbe2149ca2e8f8a73f0f8f92411227fd7e3bf28c49d68ed49b37e4ea93e790fe81c0c1f27334bcf6031c33703b87" },
                { "ga-IE", "074e0edd88c80cf81517da44a04c99f1837a94f2aaf5d93774e93950976a88ebe7ed34e2c6d0e7b3ba5f0487bb5bf785b309319fe34882dfbc27d3ee961965da" },
                { "gd", "2b8f8b67b2151d30add10de8d6a1345da4f94d18c7efe9edded659a7ed3db641d39ceabe44616475cb66782ee9892a0d7f526f4d0c7f64dd069f5342abff8b5d" },
                { "gl", "128de7c8e55b43ebb8a11fe56e578ed90130eb00c1e9e2474c517621913e955cb7889f7f6cd0f15e1a7fe476320bbb86828f92ac5d166f567b02b8ff5f2cdf65" },
                { "gn", "9238bfdebec6cceb03ad6c8bf51f9fff102a27a18e74da641aa1752c523463ee14c0f6022e5b4246ac95eb7ba30f8f22fab69e9e57fbd010612a5f6d6309d65f" },
                { "gu-IN", "c757c81e096afa92f65f59255e43214eaf0693212b012e4041a9a0d2d18f01ffc84ea088a4f1ff52f1040bf48ee2daad875658ed62eec83670ea7dc6ab17c57d" },
                { "he", "a8167210c80fed2929e6cbc260b5f52d6f0efcee85bd03ebd45ded00f84a8378ce8911fc6cb60de8b81eb482414fcde97e40ef3450cc5151ee76e2cf8f14610b" },
                { "hi-IN", "38751c3a2c8099ce0524a5dcba2d3c519de8e6692362af3868941b08e20b33e5857c922df3b8f9c1642bdc3b90c5c7905e246542fa524258881de0388455091b" },
                { "hr", "41d66b3f251c8ae8f4038952df8c8b7c9c86afb824764b5b3eb3a2240105550099e7d46cfadabb68ec4d098efac06d8a9ac54c99cf4f0098eecddad7afd340a4" },
                { "hsb", "acd67643ada7883649b07fa1c30e4608ab15e88601e74515646e292af4f406ea4e9dfd64a20f545b92b86c3c146bc971ff40263867994755a96b0a50c50f3ef1" },
                { "hu", "44fe925d87807ed3c2387ade28907e6005db94fdfb0c7c6840a62bb0aa3036ef59175a1486991b6ac411442e4601e6ade8ff34ee92ff06ef22906a7d1fc1c4e6" },
                { "hy-AM", "ae2ad7276b4a80741d26d2d8fa4ea3d558ad0ffbb191e7e5f0481449cf88a2c3d497f61a2387f4775f5f4cc439d99dfe29ef0027574c44b490bdd2599edb9fb9" },
                { "ia", "fce5db57d18a013a0801c9b08e9993bf2499556b5587d3597f1110e9d99ce35d9299650c1861122eb34b3385a5faebaba26498cd45f7aabd8d6a7b5f241e6380" },
                { "id", "c47d5fe67bce4d6dfababffe94797feaec837953442503b8ef07cc3b4d367efb4f67088cb00c8cee22ab584961cb9702bb300fe1e2e1c1f9f6d4edd4849d3a22" },
                { "is", "8b5124c232a15af26154c9212d6dfb8068c3cc52db707dbbb71ac1098f155a6928bc5cf4ba6036325e642a1cf47a2302390b1bba85c8e386922eaca0736f0e62" },
                { "it", "75da9a0b8010b3cff0559799c15a22e7422c9d39549ca651d8cc301700771fd4598e0e9f2331bb839fa825aa04a888319b3f998c778752921489a73a18fd7802" },
                { "ja", "a91c7567b87fdac49b47a3221ff5e479688b22eee8cbe2943863488457be8b6eccb1658180a4619f2d5347680b184fc17aaf2ec3262395effee8054adfed9b3c" },
                { "ka", "f8aa854abe2bbfdf11e0fc135631c077da79882929b7edafa944feffa3fc158b12e6fcfeed1d5233ad3157b219dd3dd0f909159288cd9cfd69c47010ead3d0af" },
                { "kab", "d91c238db60aeb3d1378eb5741853359a93e3a3bb273027234d99a3993404a46b82b0ecc84b86a601f3b1fa6d2a99785f23c5274d896a083dedfa8a38dc18d34" },
                { "kk", "34261d4be7d827049d5809fdfefd53284d86d965d2c0d431d1a4641e48ace96a91a960ed6fab2128216f384bdf60ae629846a301ccf838c1ab7eae189a885aec" },
                { "km", "7debbee376ebe9cb8b92e2d922b1ae10209db634c42757ac61268ed367aae1cd38f0173ca3263afdfdf49834b144d5a2ac609fe915140f2f557b832d37feb84a" },
                { "kn", "6b6f28dec108be049449f53e353e24684598ada983f0fd0b6192cb06aad136afd74a6e98824a894b21ce8fff1874e065a494590d6204e84da732c34431be42e5" },
                { "ko", "1f3580102020f1f7656fc5682c61e328897b98f41aa4698ed4428fd8840f317917034666875ce8e2129708e9791529bf8d57c6871bac883415f823ba269796c7" },
                { "lij", "193c374b01ea8d99f35292dfc54595452f75bfe2f23dd8b7a0829f229f45e566c44c2f6609617c70d1b70768ae98214e8bc0cb89152341c93175b36c30404f96" },
                { "lt", "96d0ae50f86889e063fdf036a0a4843aca054c1f9cd9c4ad88af10abe0c50d08d6b9ffee6310ba70c0be2b53527b9988e028bd68c7ab419988c9d85a42baf46c" },
                { "lv", "b7656d3d9245f19c4d37401a55b4059ead49128a992113b7af85f1aa69ce050afd098fbcd17267e358f0c84028d35a476b004d160022626b1972975b822656a1" },
                { "mk", "a32da837a29974eba726da03cd07d426b9e241a2ffb84026534d6431ccfd3722b5ea9158ed339d37e5401a4d326a8d9fea0367ba3144de7fe830c80adc151d75" },
                { "mr", "f56b6e38ee5cc8f47c11d1f12aaae5f80ccf98f4477b273533d7152b40213123c032c094a84a1b8d9ea9116620ab31a251a1f4e2e8a308e132c9bf5de6f3f6d5" },
                { "ms", "1bf4ae66c322c880a78d29673ce1bdc2e42acccd8e5f0d59ce50c95d9ba18c4a21dbb4b5a64c08db9520203c6042684e26c35a1bd78727f014a2c9310893cbf2" },
                { "my", "552b4e3f15c10820d26f1cb18875df3f4cc4777f98a64ed587cdb3aacf9dac6da6f9a374b4fbed2182151bcd33d7653cc951e9bd63ea5440d5016b176154f0fd" },
                { "nb-NO", "84509d8e29e41a4afef433d5fbbb7b925eae288c1bf1f92db350a0cd8c697687deb30d2f8ad0e1a4c65595beea73f956a5d5d7b28072d25e0658e25405bbc6b6" },
                { "ne-NP", "5cdf6ecb3e8723e5af7a6c5e5b3e1b0b4a95f781d8f2336692ae1635075ac391113affe18808655d162c221d1556813d7de211ef5f82a5c496d4b9c49734e2ce" },
                { "nl", "09d44875a9b8487977ada81e247992ebfedba4105dd635b1d55abd295efcd91eed3093b3a57bf2595d0df060d9346445b9e50d7e4055f44a943299b4beaee775" },
                { "nn-NO", "4f034f1cfb48495cfcf3a74429b7f1d5b27ac968899dd0591c61e9bc7eae379b780ff6dcf2b106fa84283c9eb736bcea7790a6fbc4e0e8431347d742fe0e74cf" },
                { "oc", "2e9f5873289b319b92851bc0accf4b08a40f79201d7b65d2a6c5adc9c2ef59999d0df8a28ed53d1738f4647f4ae25002a8b3abbe7276a1337f5fd774f08d17fb" },
                { "pa-IN", "0294749e60458626d2e07f6b710e1293592bd372f8ae71bfe9c152af5f0662dd67cb1526fdd7068641d60ae58006a8d403861097f54df270d879aef4df538469" },
                { "pl", "c9426828c853fa441d892834f659a61a3d65847ad845bf255e5f9ef670f9e7fae904b922ebc46f7d8e6835c1dedacefa53e17cc0255d0eb37688cfbd0913016e" },
                { "pt-BR", "3d9f50027bf99e97a6db00b6e0d870069cbf8853bae4601916ad5b4b1aaa81967508e313edfe2965c11343801c5722d00b1b794d78f8d45708b33f898f63bce3" },
                { "pt-PT", "2f75cdcbc4d25e0294826434d88b081ed3047a51a15e6a8472dfe5a78f1de2fe89bdc2dcf5a64fd014d2cc7bcbcaa68dec9618d28d2341f3bfa9b9a2c9e92ecf" },
                { "rm", "3bb3ce1dd158129369a831f0dc6b71025a056e3d3ece833fd8c848a23a5cf93b99c4b06d4e1f37e61fdbe7e710f35134c6145ce0a9e87be1936b93cc0054558a" },
                { "ro", "f321bfa90ad6ddaa0fa6608455a0b39817fde2d732a344e9d652212cac39c845ce843e7d432ed58487731dbf709872c69d85d65bb3962ee4921d1d5422231262" },
                { "ru", "2d033ecea51ac75d37c83c1054b896b200054567433d5f5ac9bc09c1a0518e949d66afd20fab8967305e251e8b27db1fd02747aff8bc6e97d1f9f4f1459fd87f" },
                { "sat", "47e84e774e361718253ad343737883dbdbf0b05e25c3b26d3d092ae6038e7455e90512c5be1b6ab99c82160cfaf9258b59e5c8f57dad219e89ff57f8d8a777c7" },
                { "sc", "37837924a77bdd0f53a759d5d84f6d30ae614b9fb8d42a5e111fbb3e3ca83cea0d0d46ad142ec66acc30f733499222d0143cc0a2f5248106458554a6b1ed9892" },
                { "sco", "a867013d0c1837e0574874e13b44d1cc094fc48cbcafd42a411d63f62ae48c48445046d9822804418d925d23077714065579541ba552e8d16a9d509a24d13037" },
                { "si", "f00a2a3f76599959346ce5c97b6df81c1fabda789bb49cd14bcf59a38f98ddf310fdc4eb1f33bc92016a2685136e46737e9b3b9a41667bf9698534ed346648d0" },
                { "sk", "633b48d8ac1bde70714b08403819b51d56bee688ef3fffc65db1c8a7b1a4a778991708f84402cac11a16f558dee4c73254a589908a1934b292cb209a22321f0e" },
                { "skr", "866777f666d7dfc2fb0bfe391d01c6400b798e574bb4b7806f0efc9ddc59c9012ee4501038fbb481c8c7b9fdef5769e2aaf7b819ac8fe432883a25872dd24918" },
                { "sl", "14a5ec6ddea219fa0543dbd90a64e22ee6dbad2f3ece3112f8a8eaa942533cf51a6cd76d760ebfccdb93159a126c9160ce35fe27a414b9e1ee389be5ea7162b3" },
                { "son", "9bd65448c2257701de239567456e5ae8b4bb01c5f379132bbecdc0d32ea5b5bf8c1d7906fe350a0d86970b08629cc341a5746a0539ebe2539621e70d13e7bb3d" },
                { "sq", "0f01832ffeed082b1f3048163a29a1339518768ccbf7f06827aace58891d39939fc7b51b22e12b8b24754530ce31a0a1a256d183e63222bf034ef89df7aa6fc0" },
                { "sr", "37f28b5f2974995f2254ccf35ed05a50954f56c22d56f846bfbdc53b02e375b5cc37a7b0696e089e881d969033a8b8837e62d17a98e224b5d8c000a4ded30335" },
                { "sv-SE", "6dd2ec77de5c98910a91ca2682eb11031ffdd01683a87dfd298f4f7b8ec2f97bd574d321896795b2aec1e5419ce4e3fb909fa242353bd99c0d4ce7de797d2ab7" },
                { "szl", "eb677ad855bea2bf72e20ef9d930825e1e03f60f0dfb05e7c7dc3aa0301c1f9133ce6cbcebde21bfa00b2bfa1196e6e91d8cb94020df9c6ce69ce76a29e8038a" },
                { "ta", "49bf2806f26b90276e4b62fddaa8ae8e2bf6b5adc6a4d0546cd488151ed85ec067cd433d7ceaa619d6fff96f115691b0a6897acec982c5ec4cb410a73db92c91" },
                { "te", "01dd495f00ec440dfb72a2f533ac2ed8508f269e2db6ab7141c50334d6e8243ffb3825fec2db4b050e542714931e06769e911d3aa28e795ab5da7704b3b3c6f9" },
                { "tg", "1ee074e31c660d3e30db9e2434c47a06c8728360b165e5ec3b9545e706097d4da66c61d727869bfee43daa97bb224c20ab44aa3eff6d9aac06f2d4ebe660bbb1" },
                { "th", "7a48e3d0938eab3dba36f75904b013983cd78134168523c99ccabd4e75dcad9c95b1d6f09e11ef23802a032e7de4d0a703bb8ae1c309a2a586795ccf4d05d4eb" },
                { "tl", "ba0bc53ca321b55d0ae2ea595c0405e7a2c924b1da4a3fde7fb3c323184b9079f9a5f34e9fd7419cf6b854eb19d4561734f70cfc1a10d98a11252f64712f6508" },
                { "tr", "b355bc787f6c6e4547bfffdb0769f08e43c9f6ce14f830d36fa42d19dce3b7ca9f406cde5c755f48fc5421a856ac31b841012b108046b43b3b7d5723290ce0ec" },
                { "trs", "21fca3d3f553113cc064d9a6ca22aeee5eba6fc02db7b7608105101881894f0571ec2949f6bb8627251e624e4b1ead402c10698d4664a2b921dfa5b9c4087f01" },
                { "uk", "b2145c9c071f9adac46c007b5d3273323e2ac47c1b1229defc0cb4a5899fd9942d48e4a7a83e49b865cdfb261f9e6b459b8e984b7e1e68e272e631caa3c23b32" },
                { "ur", "5f669a2d9ef04adf688d8c8662564fec5bc57a412342efb05a6ad1b573b9ab951d7556324e22ab905561dbae6b611040d20dcd0f29b0d9bc36c98d0227ab121a" },
                { "uz", "a32ba8bfeed2cd3ba3a05515624e0a8baa7f7634400eae8f416acf56b3a493ba98bd79d63f7be9e12fb5a07a0216f894bb2c04e8f98adcd18419e7520d8a3f1f" },
                { "vi", "8db889082d74f8d23f6459aa10105cc88bb5d36a1ea03af2d03ec61be4d94073af1f9d2dda67050c22488e268f3f76be10112d1eaed9bf12f94eaf5bb249d9b8" },
                { "xh", "22920d931f06860685e794116d7ef1ea25b4da62855c887a71c6b2c43d30f18e43ac86190be33118ab3edb6376fa359d22c979ae41f8249d1a465170ea700324" },
                { "zh-CN", "3de5744f461d80a28cd496b063f11f2775cfc71f68dac07524e07ad5641ceb4063de389e2c2993fa6354b145f5de4ffaaeeb8382faa9fe6e5b58f49bea909f1e" },
                { "zh-TW", "79e508ef00523465e858e7fe0216bee4aa8a5a475f2c62e95fe9840ff6f61bc04e1117fe650e1a1ff4d569bfd181b6f37381ea381b8305a71aecf39930869d7e" }
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
