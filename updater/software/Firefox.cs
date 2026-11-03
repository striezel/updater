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
            // https://ftp.mozilla.org/pub/firefox/releases/159.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f0a58cc0b8d347b9a01394691c6f2269a4ffd5a45d98fa89b13d4e9bbce9d26119f1fc90555802bdd3f24ec59be8c9cbc63a4b34b102269accb255e4ffa7bf59" },
                { "af", "f6f48097a278eeb30425fa23a0fe340ca2ab7f7c9dfd7337e317bb3b569c754392f97deddd7d13623528ff8b614b0af0663574e82de0fa6d8396b29dac923faf" },
                { "an", "5cf2021b0a14fea2b130875712fca4f531e13957cb9bd6b888bf7bbcb8df264c49e5d7d25681b5c91e2896a09a8475c359059e3bd2f3198c11291a04a2709a2f" },
                { "ar", "04d29f15d2841c548536751c6a6a536b5dd144bc84f64bb0e8a25fae5249e4dfc232c6f1edaa5b447bc145d34f9e449f07780069953256bf00f548f4823cfdb1" },
                { "ast", "2ad37b3a081c102bbc65ee4cadda038fa2b1f0ed7cf27e0287e8c5e7f457fd40b97e52cc8ac7f711eaf06a47b935d50c09651bdbb4c6d5326b4e5a43964e6dfb" },
                { "az", "6ebd9fd037d5387041f452ef9f9deb9e21416ab3549769306e5d07cfc309ac052cbdc198c574d5fbc7fd0b500c66153285d7d1c28bea218b9fa6ecdaa630cbd4" },
                { "be", "8f564b6a8587598b7037317429bea5afae1fa6efdc257b2f215ae4f22d66a000f5c1bb7919ae5867c9dfadb5d3c49ba4959538f94417dd737b9f7eadab7e30be" },
                { "bg", "d9c7f7a6b162c1fe65172a28c175f2eece281bca3a9fbaa71f8f45542ace7b9fd7cd1c7d18a09aff1eedc9098c8d008f78eb8901bc416277bd72e680fffe693d" },
                { "bn", "83bdfda123f5af30595c49f58ce23e2097971c84bdc60a773332cfaf4473b67ed9bddfd2c0558d840ece2397348f81504a9dbbfe3414772dcc3d2c12a15081d4" },
                { "br", "c7811fd830966497074991c84667a0bcc0f03445bd23d20d57e76b344d0bf87d22e53dd1b9d22b34a340f77b9e0dd5e2173415fda0d1e4178e4a58965c88fcae" },
                { "bs", "f4387a878ac0c28425621186fbd27fcd28a602f51da71b84b45a17a01e0a84812fd796bf9626a6acf5782de898db509017d56595f2de5a8abdb4ede74834f626" },
                { "ca", "3ab7c6601d0baf0b5ec20c1f7fb5d49421203a1cb8338688db4eece67bfc557c4e7f7b31b8e8d2dc9f1a4b81d46953f17a2a9b4f5dab4fdde17775e5afdd18dc" },
                { "cak", "c3593b9be2417acb52cc80ecc233217fd6b0a9955f0cfd5fcd39f0b01edab781dac8508922c51c9a806c1dfbbef1c80da8b47fbd28514410c13c38841af03d69" },
                { "cs", "0339661050a659a64ec30f0bd0153a3ffbbae30b3fa994f523a433021222be224760f8c858e285f8b3877bebd21777f3f31701a3791c1f10c65e30273b377ef1" },
                { "cy", "218f260d8da617eaa3c426f854d68bdeea81051194464d9bada3b74d1bc662ef777e816ae8f28b75335320e5fd22904ffb4180ecb86e71581db60450dbd47932" },
                { "da", "957bcb01b13d02df90b696f50b649160dbaf3f1d8cc4edc2408f095727d751996cc2f3f3c2d6bc8dcfe632ef40aa7cb17cd7dd9c2974982aa68afb478e1ee97e" },
                { "de", "697b8dd8755d8229f894066f0455423dfeecd79664f90aca97a9426e7db58f5fadc279362ab54d0e1ab94f52d9bf7b90769f61000fa0e7ad5026e36a8dafa9be" },
                { "dsb", "d15d88436a2bf02e46ec029fea1a0bb63e16c0bb861507d5c66977b363a04d5979fe2fe52033532bee39459e2c5ccc78c0f41a053c620559a5e5913faf6a9d00" },
                { "el", "9b0563a82f93069bf4ffd25206902ef96e850bbe1fe9a37ee255406d3a58f8afba33c69ee4fb65cf9d18cb9696c85b4d3f08e0403d77279ae0119e4426f88750" },
                { "en-CA", "89fa9864cce5c9389c96637b01e189024d86fec9f6dc14453ccb6af989e465376a31c0ee0457824ff7ce1ede2ecb1cab141c9f9738fe4dcabc87b3a77400cd84" },
                { "en-GB", "7a529515f3f6ac1b1e3debb35ecbb3f666d53f7a66c4d68ca33a49985f51fd4f124e7ef11c5055736516120427273d44dcaf7125e55f2acd50be68a13977348f" },
                { "en-US", "22f3a6d71bf95890e8d52bca5253f336cd9b99ca1d1e73a9e490c470831d57dee1e70e4c71b0cd5028ef0877e85c18db6cafd903473b28e9bf732d0a4295a408" },
                { "eo", "00a6cdd3e3eb9e7aa1103d9baeab8eb24a366c809a6b229ae904e39cd1ca70dc1634657ce216770eca0cec95856575d5e5b99c80305ca7bb460414f1c74381ad" },
                { "es-AR", "947115b273465e665e5e2fa21671b6a22ae0c52833eb7946faa40dbf45d37c3062a2a979b97c04770ba76259d86d3f8a574afe0f455bd75de8af744f2d928dcd" },
                { "es-CL", "00792d645121cd77448e46bed4ab982f21179073d821bd022ff548a4973773607bda8fe63ab8729b2088b58cdbfb768c9beb96bc44ae1808029e1adeb4d1e415" },
                { "es-ES", "fbbf1c73bf0933fdddccb6d6bd10c7f3499cc17bebe6a34aa7f320d4d3ce6cb311d9dc0b0e8157c699d7ee58e4038f644a4a5118c9fde8793009715633596df8" },
                { "es-MX", "8861188917ee6d16e596c5b0e80604baac7f9262a689ecdf299ed647103d91ee785cedb366fb746eecc7b1ac08477bd4de5051d52c8b2ffa3ac8266ca0f281a2" },
                { "et", "296c009c452715a32feda0a772bc9ea3a34c6e16e86cda8b5293c96de8592aaa7fec3553656e72e070b5ba832075c40dfa4fb1e8da0c15fa31b6e2f9cd65a74c" },
                { "eu", "7be4262d3c79137a95e12d0fed8d9f3ba9e32f7dfaced318e4660d75d26d4db999080e0d337cc64e9ec6d8b1633442f2be95f827244f254f552d89e4759c0784" },
                { "fa", "ed7e485147af789ff9fd759845d990853b6318257be2f84f98bcc187e6738042bb7a571cda48e76e7537c8c59c397aa4a2c01b2fff4102e6047d12342eed6d7e" },
                { "ff", "6d475bcdc99bfe9b7d5a04387e7e68e96906f456b7353a99bd45feb2b880ad9efb965179ed7255f35d371c08a546a3b162d6a857d6c371f0afb6aa880ab104e1" },
                { "fi", "d37a0f129a7be2d505bea59f89c4a76c9364b3fcf798fdab2ef7914cecc3ab4003e61c28bec6644c2072caebcf3d7ba2482495690088e19eb5c1efe018a24040" },
                { "fr", "50ca7be4a84ff09c020036ddce899ccb703cef2330e6303efca401e995bf5f542d2f7096a10747cacfb117388e5bf3d9e73d6265c326b91feee2add188955c1a" },
                { "fur", "33534a63c63de93d444f5827ee5bb599fb039144f1feea37aef554bbe6fa31dd190d97ce342d6c4ef1b452849dfb0bec47c7c0fa0602ca9bc5f4e5201170ee7a" },
                { "fy-NL", "c7b50034a46b6fbcefc367c9441a4979679f41dd38de733a4aff5be101d7d2a538be2712d9a55d1cd1f95b356a90c84684cef29229edb63a606c02cd15562c39" },
                { "ga-IE", "bd5e4d3c433edbe790244ff9ee5c1ad8b525359be69430bd09f026ed841b3c3bf3dc65110f20858503e0255fc51f40065592430faaf1f2e220a6ddd925e46d1c" },
                { "gd", "7d0970a7caf9ea3b70d440ae494bd3f95abce0c0290bddacce1069d1dba683b6b34aa2934cbe0b67f36367026aece5c740419b032c8a426ba109e3f168af90b2" },
                { "gl", "ba3d6272e46f03fe374bcf6d37dbff4da1114f8b10b5350c7ef7ec4d1fd50ec6761d6a7a34025cb70c1cfb395deabc5864dd43e36f9a4db273d140c0026dfc67" },
                { "gn", "f07965d5ef1fa13ffc4f93d02e054fa5b2878fefe66712debe874fb58be59427da7fa8412a471d46548a9aa1623617abdce411b41da3b23583b1b1b2fa4f8c47" },
                { "gu-IN", "45b8e844f4f9bcfd830c91fd2a4c8225a1d75fe83ed40163adc96cc95dc38931479f45fe0e50b657962d8181151b36619612fec5c8e28552ae3a372818dbbebe" },
                { "he", "8af93b1e33fd3f72f6032bb4cbc261a42d66f311d643898a1074381899164f0853182e092e5cb46210ec40aeb2a3efc81f24809148dda7cf5a7b8ee5deebe54e" },
                { "hi-IN", "1f01245d51d40864d5faaea0053561084ac81b21a9c4a6f2fc7201f6ced440378b063b192dba5296276630fc9160c88e3e3174156febf081f952fb0eabca173d" },
                { "hr", "c7dadf62dbf4f32476af6870b9acf21b5cdb8c006ac174418da6c412c11a2279fa8693e1f2ba5e766e28b2b4af5937196c6a4f8ae310a7838feb0c02314d4496" },
                { "hsb", "f806da595f79db6d97a9e55e03d5d916768d2d367447fc760dac64fd361eb8a0d0c12fb465745bbde2bc1850173fb92f7813aeda0eefecdc1dcaeb8e1363e147" },
                { "hu", "f42b422c61ccf189367513384602944bcf57ecf3358cf723e1d476569db7ce4e3c1ab1516b8b766e89d43955670149ae9885cee09babf4d67b440f184958628b" },
                { "hy-AM", "d13de73ee1e6e7ffa401cab673755b3afd3160fa9aa4a0975f078ea81cbae35e6761cd0a3f2f2d40519e9ad9a755fea2ad92ec123debe44fc6e1b202191ef26a" },
                { "ia", "b655eacbafb739209def7f82b10d1ec280a0111797472361cac0c95293143f6c75fbe20daec7688c332035f102b8595590d9b726d71b937ea7358f2ee571eb44" },
                { "id", "5b981fee069d2b5f7a36db703cf61364f92ef669d1bdc43e24a455014ea9fbf7c0e2f54df9de71784d2a69e9090fcb5d4146b87ed0bd75dcf4f844f98e97a294" },
                { "is", "c5ac91dddd36b09b4206a3f8306ecc2a207f63e34b4128b47c9e374ac2c5cf63d55b876962a7385c88c926a45a09e0ac77da3f1b177f164276f4f10f418df4d3" },
                { "it", "580b7d4300553ee0f9d6c7913f794518a399e06d7cd2414d51cacad27baa10224c01eb6ec5f7b0230e0b9f91ec9de97fbd1fc30dd0cd75d2d3b198d350b9a9ea" },
                { "ja", "05e231e630ce16bdb03cf5feafcba828a11bd95c6c9ae699ad625a11061224048b7917610a352bf6ce0d5088fe9fa9ec259076a9b345d75270378ff8e831fe58" },
                { "ka", "348a187d13dd1b5e6c3bb80fb66732ef543d62dca1f7621ff357acb4151409a03bbdaa2681fab15872c6fa17091052defe194caadd9751480e17c9fcca393afa" },
                { "kab", "824cc0b37d9c831cc600de93dd4dd664f28a08d3f8f7d50b3283556cb2eb61c272ac8bc9ec853136da5d6869584f98f67d1911f39fa2bf3556eec2597afe6342" },
                { "kk", "9ccf54e9c01044c2da3a4238077099187bb136eacbbe3981537539d7f244c0a87bfe9a7e338cd58c20bc5890a7afb3d50c8cad1d45c512278f7ca9b473886e69" },
                { "km", "46f68cd1771dcbb473ae5cfb403bf33418c5e793f3bbebba5d4502dad98f45dedb00839b8e023b2c21abe026e91c6fcf23fd83c53eb2a35f52307af65b341cb1" },
                { "kn", "895661e3b9ad96972920714b06da188f5dd67f9d2e62458edd62244312a79833374557079c74191d440e50c5a2e56a0dcfe3ca4c66c5c10edb75ce7fbb8cf68a" },
                { "ko", "733a4824cd83ad92ff16ada59bfe6b84fc28fcbdf6873ddc1018207af0cd551f2b8d963c73ffad21f9a598ad45bb4068ebb3c81a7afd3e5d6252be1a029d1c40" },
                { "lij", "698a1781bb8f9820ab40201c5e27fc5881bdd6c11ae67cd3d0513c5dcc2c8f3b10f3b873279b5689f28621a53caa261bf41c3088f2a14165d2d8eeedffd96215" },
                { "lt", "1578eb55157670f05191d2c2070b8effa5aa112e1d63f38de574e500ab574e689704548c4ee2725bf2a5229513f1dc73b5d769232754ba1eb8215211af5895fd" },
                { "lv", "2bf394d342ebfc0a3d709bb4dd97a91759f4bada82a65a6b8ae639039f0860e1b2b24cd82c04ae0734ed36337109eff3c32bbae2af41d117dae2b1d7bc9097d4" },
                { "mk", "a23133f112794e1896681888ff5e60551645af4ca2307ddcde39964b335dcb2871be381aefb1c76256decec86ff16d830fe5147c20ebc55a8f32e2e2e9cb635b" },
                { "mr", "dfd97af125a2daa7ae223f87f6a3b2719fb549fc70e51c2fb6560b715c9802c19cfa6aa70de22e2019c97477052b3c99e8a78a187fab93cb423a4d533e26290c" },
                { "ms", "3edf21eba229f391db3644b4e78fdb1793f88abf3c622a5b44005bd5bf9ce44b5908f96a42f26418cb728f5c771e76189e37f886f30192916a60ede675916b0a" },
                { "my", "2d17364f46a60c649b4e6cb1e1e8d82e45889e22978914e6bf379e51e4fd05ba4556228cf75968e5b45bee6b4dd701cf5073598624f41b9c8371a08e897de582" },
                { "nb-NO", "298dcfbbe44a7e7211f16e68802e9fba3c3aef14387590e3272ef774a89a97c5c9904176aa6a74b77ca4b933eab434601c991a9ea9e5c9681f8e068544b01ed2" },
                { "ne-NP", "49b8a29b0636cfcd93451b3cabeda1319e93ee41a52ed3b194293a8f4ed8ed133301ad505de0b835980174de881ca317063d5c7691ce9de26f5d66fa0b8dea4f" },
                { "nl", "d9f482e22e9f06fa82ac74730c725b65f8f759c1b1b6d85f6d1fb82a7ffdcf81443be9f63adf259a53d16265f702b3fe5fbde5fc12f0155af1f2df6d9d015bc3" },
                { "nn-NO", "731c0b0f02ecee5df9d8445bbbeb8c128d5b1e5973171d219b256c45ec93f232bc1444fbc99fd1af339c92b4bb17de6888b059eb1b76cbe19ae196aef6b8fe39" },
                { "oc", "72b90b2c6ef973d2abf5351a592d074aa4e62ce75c2852b3bc8b70905080c9ef1da6dacf5f8a8bdb7d726e70ce9b9220d9a403ea3cda0443677338794c780a03" },
                { "pa-IN", "69551092934b5b819a7d45ecc49d907dfac9abd4afc7d8974393312ee195a61daf8a0e83e0e3b1d567b62eb961187b296b6419bfba0ed56da83208bcc22b0ae9" },
                { "pl", "2e135c91ded46aa99cf7160d539e3dcad815f06d437a191d33d890b1d9ac4f28fdbf0ec6baaa3a7c850d72bc8147cc0c72f646e7a91d771c3d0b4a2e96a0a7fa" },
                { "pt-BR", "284883351d0b0bb151c643724ba9088c2232110a601768f2ae97bab19dd0feb605f9931022298b46be736491957920b849993f786b011a6a348203e10f7da327" },
                { "pt-PT", "44e24855ac66dc40a5b7a3fc181854b5a903641fb2fa6b27e05fe86569200a1bc323ca0c05b5157b0f2f05a91fb1d7b0803802a3e6871dc19d6a4bd544d51d42" },
                { "rm", "9a0d5e7b1749fafecf255171482a8c869844e41da3dee3ae7be29bf28fdc9604e461d7ef3c9c4f8a6e262bea366af08e1ec60d60f2f5c567c9e4d2ad35822335" },
                { "ro", "dfd9fe55653196672e2121e4f423e407fde591a668c85872f40ce018c41920e1d98693fcb80838500b9ddea503e4a032390e4b3cc0940fb026ea4fb08862b956" },
                { "ru", "90e1b33c5dad32623f7fd5bdf862e9ca600738adad2da86a1ab6f1f3634977d9fc5f551901e61e9f8fed8b1d7431d9098cfe9356b7709073d6f8300cc70a2741" },
                { "sat", "132297e7624a806fb57e85c97eea83073c6fd9b27fb544e1f024c9c2f6103a9f4fdc5d6f617fc9db4353f66553837b9735fdb558434a3849d899474a2631b116" },
                { "sc", "4c02ba97ad62165546d6e96602c9a8a63c459438c5a447fd3ce37315c1334c294497a135e1b81f745fe6ff602a07b476ae18cffa616067acc63b2629aa769b0c" },
                { "sco", "ccf0b30eeff2e41aa6f2eb9d6d5338beefedabaee882447e41b2454f047f63114e5b6c343f0e7d5407f77df96403e2d4ac03815293e5abe1c719ba0742447638" },
                { "si", "d9b60459ebb0dc3646a6c7b06e764273de8dc00732d6e31b1d9f7d715a55e4c808396915de97ebe5fd7829215ee995c1eaefa533578d0f2b6f0a2f0fe8c87889" },
                { "sk", "58988d28f7f1cdc4558ae97497c7640a3bf5339aeb4f113769546320597734b8538a467dae5031f289e116c93a823c0c9f2dce073ffbb3216e548c1ba136ae51" },
                { "skr", "f9ac75dd90eeda804df37fc83275508492a3ebdd755f347e7f555c6422cd9d0df93febc07ab4d915d46d0b57fd2fe84fda00c3bf861b62baa4b93ebe4c656195" },
                { "sl", "b8b58eb9acb82993b432b1b6072f51ea143cd945c4e970090db1df37b35ea4b1be3b538148a7a40ecca939984ca3b9e8c13a2bda1a5a7ff6d9efa002cdf4d800" },
                { "son", "9ba5b31693ccb7881196e390a00d68cc54a40ad9b93a0805bd4c8feadc12902741c388ed0359efeffd08e821db56335af1a636b89375754f30f42d75d3a646ab" },
                { "sq", "026849f69f2e37ca3d2158a839359073c56f5bfbfbeb7124a3dd5d2ab757cd3361089d6ab607d669160bcf90adcfb274174a3f10af703c4ea0bf9a3a9e29eb67" },
                { "sr", "db641e0f0405cd79a302cc59cbc47008d1da9bfd1110f8362de51e63e1d63202afcfa176c7d6d061dcf03d5ee5d26b69896cc0c3d93c6f7e6bc38b670eff3b34" },
                { "sv-SE", "a1e9fd89219a94aa88acf939a3bba2618855e4dedb901ef4e314cf4c898597676931a8c75ec3492845fedbd1699af6b8459a38c0b8c30e981250ea3a260096bc" },
                { "szl", "2acb9d173f925280e260ca009d0eac24af6cde6ee9a4fced42db139990da482cfd0d5f3c07ace80ef4fe3a6eb07c059d3e5b6d9877278a7b8edcfed62db3f0e0" },
                { "ta", "53ce4e3780a9016b1d0928832001f52b4382bce6f88b218f86cf8a3a9695692e950f93244b9dfdfb375461f2dc9c868a596dba83589ba28c68d2431efcae81b7" },
                { "te", "cf3441234d016b8fc851a13f1661b4c0a308d157ab48955863f51dee6d78c3adfa10109e88b2c41227a3f07f4e9d7a6c89e991d055a3f6bf7ac46137c8ad0e9a" },
                { "tg", "cb85890499503626c9a63ecbf335e75dcf10de4e96d7730b6220119c2362d3d68be57f391d2054457a32bc4be270f8bec7dee0de2da02c05812cd7e625ade23c" },
                { "th", "7d240aaa2025c3759d97510f19eb97be7efcc4a2b156b4ea70fb8cf3adecf06e5118a5f4a0f2f8ee1b3b8d2a846a15e4bd858ec05cd10cec5256517b9a16fce9" },
                { "tl", "8778b500a4b45694b6ef0223eaaf2c51138d0b2b6ccd6e034c52f97a528f009b9e6b2310d176b0d26aa868a8e73e44a1938812fce346170b82ab2c3279feb087" },
                { "tr", "c2c2184dc2beacc7daaf7820919789b19f75610d9b6cc2024a56ad5523b8a1a0b0d86b509f411112d1dea4e9b7cfccefa43da6a593e12a3aad295db52208c6e8" },
                { "trs", "bad075bf945d7a01c19ec0a6c81b0fe70a5292c86340473e00fc19dcb3795d78c1d7a7450c2e3850f79fefbf41a567c59494e362133c4543dfaf8512857aa581" },
                { "uk", "2cc42c46628496363da96b0c3c8d6ac07f8f3eff4e4afb246d9c3cb2952e87a58d6d172e125986ec4c9019df922d1f8c60f9c2ba6f70ec00c2ad4d6030047758" },
                { "ur", "69a0625a3647f394b2fa01d162b5eb666d720bdf6a9179840381e2248c52696d7814a2b06601c2d6b98bcbe21ccf04c0ffba860d8ae927dd15967df44d812579" },
                { "uz", "c088e8d0dbdfe11715396aa137754eedc7d83cdffb059f61740f8dbb10ad40107e5a8658d5761b8561a04a2c54417e062deb08774a9666327b7ef08184e2b3d6" },
                { "vi", "54ead20c2f147aeb70ef65a6b12222e667e2b855eded33a7e3815f6f49d2e8fa7a7cd1d2c2c5b721fcc4889f01b02e8516ac4342289d8ae2afda3937220b25ac" },
                { "xh", "6396497368757884bc05e84cbf0ebdaeecd39e3ff6d993e9304180cb15133c507ebef39d1551debbf7e69df001e8e5bddea10f86043866f9ab534f91c80b0aa1" },
                { "zh-CN", "8e71d6a103460e752f115313f272809a05a236d2fe9987f70c425964622221ee748f93e82da081c6c2a29a2604fcf2dfcc92bc99866e81a7b107b1f24e935e68" },
                { "zh-TW", "62350078183d6b98c9a5e459d33956917d0bd92837ecfbc69dcea719f6f9d2cc982916f64033185a1b2ac1b2e3697930bae94718c0ee5f9ac213b25748014835" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/159.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "cebf81fb103afc441ed648b111370ae140f72ecc74b833d2884b06bb219aa01c338a71215df0132224233c290233ab1e13207059bb2acce5a989ec34ba25cf74" },
                { "af", "1ac824e6e9b6b3e76eb9e6e8b7127217676aa10a56a7570463480170ac5868a832396275e43908d0e4cf1f9dc2f5d7fe032b288d3888f6285a292baf61c2d4d8" },
                { "an", "ae3a8caabadb07ba61eeebe1b5f8d9fa1cac8b63f5ee2f1492f3e13b931b732ab92af8d9a9b5e8b665abef32ad09ff95ac0f6d97a3b9362021fa7a2fd1ff6364" },
                { "ar", "4682cd566c254b11d911ae1549684e6c28b8431b4ba81b0afbb8ffb00caaf61a2854aecc7da4011a7ff6c8b8e421974fe90756e99b4bf7d7b3d9e40bc04c16aa" },
                { "ast", "93ad75a565c3cae7a47a0515bfab64ff93e3a1fc0545635f8f5b60bd1bdbfedcc1b55ccd20aadeb09f1ec15dbb17c8e4748d72e7b0996def4c467e1f45a62fab" },
                { "az", "e163251dd9e41762bb09f228b35b800431ba59cab2c732ae66cf511ad33ccb21946929681e27b94e37689b1fd47541869dadf42ff9f82a343802fcac934dbe12" },
                { "be", "29c3d73bcf9aad5e7dae25fc76b78d24f99411d67e2fe6af918c251eac7e2f9d81d43fde32f83912e1cc8ea339f72d3fc0e7151c86e19500750af22b45550c69" },
                { "bg", "38245062b0919b90c9f482ab8c35f0bcfe7f0a12f8db591074078c0fe2d29461e710fed83f18364243cf3c3b7b7c7b19d81697db8c4b1167cb8cbfa31a93acf2" },
                { "bn", "dd43d45ee7ae90bb7bf6649ba35bc972811e3cf5625782d6c37e4a43ef4cc4afe512bcc739bc05955b1afe69824a64fcbe2588ac4c404c76245207f419d3f485" },
                { "br", "06a07ad3267b904fae3beeebe811cee093a68d1d981b3c592540d32d6160a3ac379ba8a07771b4059f7c74d92f9027cb1dfd4eec4fb718ac27fc13a64c47c85e" },
                { "bs", "54d44c9a87858298a680305cf7c41845dc2445a5b16819e04e1f3691dee3cb0f2d72a9b322b524cedd80237726a10baebbbeb9aee152a653a403728e254ebd1a" },
                { "ca", "78eeb3263f127b382c52c440e849823b1c762efce3225e2ee9f4966a623332056a0b345375a35912ba04f72e26c8856168f1213fcab5779c89ed482ab20d8e29" },
                { "cak", "26b15baeb97b3a6932aa657735af7133d2271808086c2693e0d49fe3ff8bec1af81c0e9ce1b907b6f8d5b2fc892c2a8b58e78750f2ddaa243ad41ee4ae0d902b" },
                { "cs", "4a5f69bc851ebcd0f8dcc79b6380964dd55eda21ab4bff561f0e42343ca76f775b57d3641f3ac4efafbfc098646c20b9968352dcd901f921fde1204c5d6ade18" },
                { "cy", "3a377c0ca29925c5daec416380b10c7cf35be6f349ed59b0135555ed1dab343e0ee6e652f4e2bbe5cb9cb7a99500ff20e28062001a401cd00636c18ed5a69773" },
                { "da", "59639c9e8c6b679355bbe2c33013ae88c1382a2af9b5fe19648dd3d00eed4b3e831e95dc79bbf650910a73f74cffc5ce69f9dcf5ceec842a2c511d243538d717" },
                { "de", "66666a62db88fd823bc80aeead85fa7bec0179c236baab2301b3dddab979d642bc5c3fee5dc0b2e829dd38c282736fb03f34464f72b781f60401be7d722bfdd6" },
                { "dsb", "f2df36931cf9cf794cb607bd9302297e29776ab5ea1432aa1c00300d54b138086b7e3a3b1328bd038a3f523027172a019acf2fd18d07e9b5e233190b5519558a" },
                { "el", "244e3acff2a21e69c85c1b79d3cdbeb0592bbcb86fa216dd22295407dc7dd291d5300f961e026f8eaf6a54c319d42232cbec6866d29568c9e275bf751802d0d5" },
                { "en-CA", "ecdc964fdaccdc8b50ea6fd0dcf297114911dc29cad76a4d0c7139a43cf5c65c1c9b61fc432ddb36f9cb95a0809a6ea1c0112ada805e769437ac010a5f28a3bb" },
                { "en-GB", "362dbb052cc5cfc4f81ea623f91ea5877bd751db0f576670b64fd6ad70263a216e20b3779772a690f8ba8559486cee4902d6a715afc647e8afd5c93803b1b95d" },
                { "en-US", "b309e1277a9e97caa0a1e650244020b7da6debc303b60b5ac990eda784347425ffbf2d3727ee6ae8eb0d7cd627f1e8a1e1501ead9ae8f169884d06f0196306f6" },
                { "eo", "33b158a43da58f8d045384358668c27e3ef370b4fb8380e852f9dff80b18c9d4efa37a501d7a4b04536adf76b7ab764976e5c596728b2b139a29812228f85c14" },
                { "es-AR", "bc5ec658ae9023537ba47f529288d141f5804e02d9371a5a32016b22c917a45b2e051cd59c653df97dd9d3a07622aa7514641e024c32cb2b64afca453069ce17" },
                { "es-CL", "61d2d99d29f0d0600e02c17cf0a2460abd3ac253f934553cfa680beadc1c92607ba99b9cf14202e1dcf4052bc5dce9aeebd3e702f67b0b355a03a22f1bdc2e5c" },
                { "es-ES", "cb54a6b7485f6df9e5df1d8f72506b6656abe0df4738235a5107798d16f627fe395a06d3ff3bdf191ac9f4fb0c4ccd409028ae04e44a32710eff8faab3ddb26d" },
                { "es-MX", "086a5ad271c1f1488193be4d813f50aa91f94111bff0e305bde67042cc838d3ce0547bb6e4e0bc0613c4358abbd1b378474aa4a9e2d762e0a03f922e046fb06f" },
                { "et", "ff7322930fe12663f58fd2f2c8617d02ab665393273a2733cd1df02ef9baab58e139a3ea342240725823964e5de382c1b69ed90d76e835fef9bc70de99d2c308" },
                { "eu", "6951c1a69e8399b9c0eda0d583ab0eb0b7f2f7fd684ecc71da9466d003348c5871b710c3a0ea5d52ce5eda708d75ec1a37a5dd22a0054e2c74527cdc5c6fae53" },
                { "fa", "d5e107cccce501662be0e17d7036d4ce6ae886eb3b1dd1830cf6d8ff440986aa11667308cae2c297ed2d5b8957a1477ab43d7b1006d1fa3fc0fd0530cd583066" },
                { "ff", "8cbfe25d01d91ea1becd44d35efcc2a6183e80b0bc7fef5d35fa297767db0d5fbc5d6498170ca1acd28d844a733b2b662a092d45ae785b858447fb242d124d32" },
                { "fi", "6ee3e4f7a46aef6f04be1588b297530f1ac321dfc32d312261eae8cc06540a922e3975acc23ade8e5f869b5bfef6e2e470f5ff5d36b308021c2dcf80f07af4ae" },
                { "fr", "3159eeb471102cbbb7c141296ce3b015cd7fb755e7a921e60a2c8007959028d20dd1283fe127c7ecdd6dbda13afd30c396806695d1be52d9f5809cbcf8b5c747" },
                { "fur", "78b36275ae9bb2071ce1f178b28cd3caa7e93ac8f096e29f243f92f063805596b8776cf07a75aa93a3cf026b8f45f7b42582a8b0170ab5e5e8e334f4367d36ae" },
                { "fy-NL", "7c00e1f3f56faecaa0b5352707beb426d507e6e5de42cb361e8335d4a84337fcb68d857e8968f47d7f7c38b08486571487d82307f911f4ae210d0f9c25c5c010" },
                { "ga-IE", "a50c5ddbc32b36e52023c30e03cdcfbbccbb45a66f3b5b8de1baa3999734fcd42cea3c3954dde4ceb42adfc42626a065ed7f2e8999914adb2041b7d7c91a43c3" },
                { "gd", "e385b004003ec5b08a9b5558af71e3d8a6da481aff8a8a8a809ce0aaa7f9da84e65ece46946c85eb2ffffb295f6ab8ec922cd8d0245144b6c6c1f4280b1b0e72" },
                { "gl", "ed64784a54d354680f75e7e52c4d4bd1b772e834d716806766022999bfc72244a433adc5db3fde456bd924e5e9aece57931f018eef5710185cbddbb5fbde3d43" },
                { "gn", "ed5cecdbd991607ddbe3869bb53d55cc8b94033eaccc944bd986d5541f8299c495db061a86c19386b02c7e5e106887d8a6f2d7964c9df6ca627184f5a84d3fa4" },
                { "gu-IN", "8f3790ea238542143225a8c8389c7f184a065315722e107fd09b102667bcf558e649897258d7d849ea92f35cb6c36f690c27e408179da5e13b70848f0c5d5039" },
                { "he", "ef9fe9981b2fa5721bda363eb0bca5ed247a9aedeac17d19877f7419b69264fdeea09c22e1810b3bdbf57d62a691cb3fcc6a3726379b091243b1c8566c8dede9" },
                { "hi-IN", "a44edcdbb0f0f750162afcd7c1bf70b4550cbaf6b26207360ee09cefbc2fe22e323422b8f8dae77f7df8baeb862d7a1eda9f2e5f6fbd72b4b1c0fabb411dd6e4" },
                { "hr", "9a4402bc2312f4f52bbbcc0a0e24bf9eea29a151146a1359cea21d73baee5e2ca6df9f132d91953ca12dfdd450eef63238f04b81898870eb9819518f3b41abb4" },
                { "hsb", "25088f30d4a907c5f863edb3b46248e2a90ce8c811cb7da7e9eb2645c2611be9e6887c4a343de901bc58c2c72bf278c580a8831ac911b3123d452ed3d6bc6341" },
                { "hu", "bb7e15ea409f31974afc16aa2c407c0db864abef454a44c3fb0ce7bfdaea8a7aa533eb8d28c57cf948ac373a811a2775c25b18affc3eb9b9807088121390c885" },
                { "hy-AM", "0beb97706cab446934a4cd9cec0c8cb8d0a61d9562a3e2b9f09f1f7b1a7337cdfb9b7ef458b600216549e930e22aaf44bc042fbc0c430d47e41ed3510d10fe5b" },
                { "ia", "7f06b92f91cb381752d43cd92b8bb14ca5d85cb51391d79305fcbdedc36270bd250190d9551545a6cbac14fa11da71c75e6994215f9037b1b5a7b630a5c11d5e" },
                { "id", "1f5e3d7805824a69433968bee7456b45fb64a2ec6231358b63f6a01d46e2133e2b79ebd1315338b359d3838e23ed8299d0c4b8880f7d29b5835f82e7d86f8ca3" },
                { "is", "ad1f4cb9291ced15736118f0824141e14dcf3c44c6b093f4aa13ae38899ff7ecb192cfae307f01cb3e4d57e999196c8ef5bb00bdb1598e9165f0ccc2f52149eb" },
                { "it", "a3fe0ce0284c78fdec2a68f16e7be49401cf38850c565c15e8c69bb1b05513b23e64b842c89d1873eee496650778e892df077006925439795364285f84d5c32c" },
                { "ja", "a215715efe3792ed7e4b3f3bbb3997cef2d1c68c681435d80feb38c34301bfb71af7d8f6b2c4af3a4c07c1b479f5f28d67ea69e081cfe40f524f1bbd3a9b41d0" },
                { "ka", "dded51a252d752f8a7e2c8961dae39f028c329673f5e7ace9b77abd562810100ec48b864a792fc63631d8e9c60be49ff4feaee52c63d9f46d09afe7268b2261c" },
                { "kab", "feba1dbe2c2c824c2387ae68257699d9baa78009c11c4e8744101295930cc1c86e727dc612419e201017bd86e9d4eec1828fb2c94cde141f8bb71f0212f64152" },
                { "kk", "2b91435c55b346daadeed701f3b4cf59b0ccb992e862a6c236007c5cea460ab3f1cba28839cb39a3f823f7ec02adc47dcd62f58980e660f18e06788f67cc3b54" },
                { "km", "c38f37045828f7ca571924a9db8c65490fce6b010ca27e419641e4480765782005b393556b0fa1619629e276020deb10e151d3ba36f49c5a915f2fd02faaba0e" },
                { "kn", "885e2e4bf8251445adbb86b607c913708f60caafbe279ece2e2d7b93f7b4fcbf45ac6a358189add4f0dc80d428805e9426c70918e28252915d7e6086fa82eab4" },
                { "ko", "677298ac1eabbcab7bff58295b17b2b1df865062f674510b7b68ac728f73138758b3989a5071ddf8a68a5bfff49f2528bcc8ae6928ec9e46a93552e703f85985" },
                { "lij", "de4741f4a7ac8253ee455490a2fc990258a8110ffc876205f28b38208535674905c95c9772b52dffad218b3d43f005ec1b9fd0c75776ef144ecc1761a7fc83c7" },
                { "lt", "22c2aa1a14707874c6d7606130e3c66829543b741727f1a7ae21ff4b054105602e06e34d41e6164c24f73192cdfb0983f6d0683a42c02478b26e4252c11fc5f7" },
                { "lv", "11f41ead39a4383a0a6b1de748ee397eccee439a06d8ff62b0c86cf0c275c592bf457c065feb549346c0090b732379d54c380d9caf5942a90b24296f523c1bd2" },
                { "mk", "9315e6c786204e076d14cd64b08afb729f4a7e22f1177194f3704f52d4ebe6c9057e3a0d02306377345eebf7d56ac9074cd6a8d49c3f9e0958269f0dea4ded32" },
                { "mr", "5666ea7de59dbd8883f70efc8bebdedae210b3411e7909046dabf287c8a4e7a6977b02db8b534c83c9ab2392fef68b9cafa0c21fc89c2fb1e0b96d2e7eacd25f" },
                { "ms", "be74a7b762cf79baf27648f62a7c83bf57505ecd7b1c59dbec16c16cf885fe41d001b91b739da122914ab56cd267fd0268790ff835239f8b7844f4176ad2c104" },
                { "my", "73c6509a4103608b691af5b82fe33078774d31e33e47944fcf5968002adc69eb8ad3f3fa2b64120bae79bf7a6f8bfc974587c9046f9c46703db692e6d79923b9" },
                { "nb-NO", "f279a1f5ff7cfe60f6ca6da91d097b6732f5f02534acb836ee4ebb2cea3a79570b889562ae9f48e098f10243f7a456873edc136d80ad0374ba6d06c05b5994cf" },
                { "ne-NP", "7ba910b54241e3a6b702fbdf7270683704990e7c6876e915bc1c11a71810355c8a02e3f1b3d12b0baa3e01760c9962fc24ba57e6a802c765b605c48b3005c3ab" },
                { "nl", "eeebe5f226872bc51fa0b1f37ff2560d0307524d4b9af4127b2e31e89fbd833d8251039d9683e99c5300cf31f2ef79591b5841dc69c20f258fd92dd58c041cc3" },
                { "nn-NO", "9c97877e93cc62e1cec1567057165a990cc7cd989c2899d5284c99afe16b667090dd8fbfb98bc55be38315c8057c012f86127c85ee0c837ac2d4c4b9bd00ba57" },
                { "oc", "c981cc76af704c97b9cd6caf7035a577899ad5aa5eb08b5ea28396cd353835018b7b88c353011b686c1ae735ca07961d34e17cd6de113064f4aea821d265e72d" },
                { "pa-IN", "5fa6b9b63c91df86e1f59ddb1f499071b4f3398ddd678cddf127bc20df16ac051555dc33c767ef32395144fa3393847891bfbfa873d00dd9a500f5503e6f8536" },
                { "pl", "d0cf545bb99dca684728ecd09cc0a12b19053df8aa96039b64621d27332e30740c3b2a5713d686a26e3f4e05624f13e56ff0ab557a79d96a5caf34694e994bab" },
                { "pt-BR", "ce3c84ff1c43c9e1657213437aa94154e8d79650b320bd73aa3ad64153e03763c3df7444257c68df54967f6b0d98ad4376d3fda56a7147d906d9900fe9f41fd8" },
                { "pt-PT", "9215428c527354a596c8acd1334b988c3704a1ec0fc015105e72bd711a0138a391750e49d95e6f6cd10740b4ad79aed04c46816ccbe69513ceceac2cef3250d9" },
                { "rm", "a7187ee465260b51debf992bbe471b25393145e840ab7b2f95f1f464d9843a5f673f6b0f820e1328e353132684e39705041e361216313abe36c012b62218890e" },
                { "ro", "1b8487f4268d3b94c75510b17e2ea7f387c8be8c59dcdbcc06cb08231c7796a4f674d3bdf51e6c9054c29eafe2ada6a68e71d891974f1b821c15bccc579c9f7a" },
                { "ru", "945b071843e449ee25f999e1367b1c06f1bede6c028d13f3c6f3296fc6dc976ddb54433b72033036de8dbbe016422febbd997bbd0b9798537e7066e5722e53a9" },
                { "sat", "8e1ec17c16be9b6b42e7b83708ee7cc15c82bc31f7b0aa95ddc84bbb8244cf71f2551c7b929e5a57e8530867f876eba955d6fedde84fe7fd7d2bba97f8f564eb" },
                { "sc", "99a73a11a670d37d6b62c89067edace115f556c0f2feb077d4f7ea6644e3d05de6be5e7332b90bd4ed22e411133753a6e288928c72aaf15d12516b6ffadafb91" },
                { "sco", "6c4bb41a8047dc4999f118c88ffc196bd09ac02c05e65bb1ab974d3f459af3881fa7b8d89d3ce2289409da4378defaf4a274a458352e5b89133ee7fc529cf7fa" },
                { "si", "4e7758a229e496d8bd14f83b8e9cd3d366a2acd0f59870f1a9b5ce4934312c162957ca5959b54d68b2a486b370c0bb4a6ca5df88f64fd9c1293a6994ca30b369" },
                { "sk", "8bec2a37c4fbfb328cfc000ad37550ea3b59a4f9f4e251e136e6a3bdb6d3d125a2b35b9ce0c6191dceeb34c4d256a79c9ec5970eb5c2bd001817301be5ed6a25" },
                { "skr", "485a064d2784bfb30cf835822ca2d05f9ccc50be555baf1ce591daa97369c98c2ba9534d9519249d0b6c1880f7f706204e6ee3bce8b2e209915d8c7fe9185a65" },
                { "sl", "867113b177d51220aea4228f41a0c4868bad135bd5d020859fac4f23cd2a1c20a6c6b729a96f5c658970641b13b5761243174caf4e3bcdb1d1ef3e9ee16a8a4a" },
                { "son", "6837b710a753c556104368d08fa13355278241d11ca0c0b62bcc28f97c2337ba9cc7f818a6ada2e73689d235c50f1c3c1f422f853ba2e5c4977771b1c5e5ee47" },
                { "sq", "9802e2bb17c082f676a2a1d544e79cdf4f722553d1a1be3708721f1411ca464222368260fc27c67f037ea159799ba1b66779e0c442fe34f4ed7909794fc81963" },
                { "sr", "d5ed9df444ae851c930a88c14ad86937dd3823dd762ec1e20f7b822768a36224e735382907623df54d88e5d5d7b451056836cdc082eac8bf40608d3d36eb183d" },
                { "sv-SE", "fcfa74e9e43f4964491ec65d5d631bdcb319adc27442d25a2d4d98dfa68a6d45e63ca548e935418ee88e9d7e0a6e43d4c8e0035d3bff0ed9a1f1b51983a8af4e" },
                { "szl", "4b4d1612b3a6a0a2b1d86fae1b771c7fd65f86a50d605eb9bbeffc79bc2b6e1b35d916445c5ff8471ae31abcad2d3cc06070a8eea027fdde63f6754bc0e9654a" },
                { "ta", "3b9fbaeb9605af26ba8b026002f76140842cf3233fa12b98772c9715ceb076ed0a31bb606fc57fc8c797cde6b404def108ec79602623c966d1f58da0a5deae72" },
                { "te", "50d31a4354e0be19c77cbfd08b8380b0203f802d8475468b42624ec3c3b8ebdeb490eeaf490e8915787222877088104015ea7af84397d65a08be1291de6b9d17" },
                { "tg", "d036ec069068f100eb2643c1c2e65dbe57f0f7b1d5abddc0740866f904634909434c3db17c591b254b158cb2f07cd76487f97c73dc466210ef6a52e682a2b5ab" },
                { "th", "cd9501ac3d823b8c32ba225c775c9488fc1fe5d09104e446e8d58216f0569832c2bd0ffd41fb97c0f4cdf995b8aff02d759e54e25284717ca28876038e33f320" },
                { "tl", "aec5a1c0712651be1f9403610007181e80d0c5c961c5c67405836a050fe1ce26ea831693dbda183a388df70be503f251ea5e5993ab8a8010f2056dad27e7eb72" },
                { "tr", "c9694d8ac36739d2e7846796a6cffd4084cd2ab4e9af53d938d2c072cef1447348c1288e5190bff5fafef5c3f6f1c9a87d42cb4c37017fc55e2e286732c04900" },
                { "trs", "d6c073f6c07135fa5877c008332779d30e7cdd7dc98703ea141ec5ba1f942d42ca2e9cb062a37f0d1e44fbc2bba9d2937d2168421b8bc1292d93b4181feba29e" },
                { "uk", "9beedfd55de6b4fbc9bbcf1ab6211ff6c4a37163557b7ff976b0edbbb4222bccc2031ca5d77e9f0e52de138bdf429709d8ea802ab9d34fe8dced769ba0d8ed83" },
                { "ur", "d00e1fc8d8073e3d1f3f2ea8e54684d69a3e30e6c3b2b67e6642f7b7a4192ddb2d2a24b4248ff28e371d0816674742fc3eb27a2365c143eb8d52f9c35611adea" },
                { "uz", "be364b767ec79f45ff239d6a47dcf268297f4618f3d08ef929a98014604a4f5afd99a7ff3c9b5f9e6a86a2e22726c1558288686050d71957f59f09a242fcbf2e" },
                { "vi", "92517b96cca40fdb5f71f5835341ca201adb671ff9fc5598915bb30a78acb2b684a5ef1ed151398fe2eea1bb4369ee5e77d5151b320395bd1fcf8f86972c578d" },
                { "xh", "d110ef2451a6007a3c012b4d079b5bf2f8cb5e8021dcde65120687114bde7cf4dbae30f9680bc20b9c5636610fe9d73892d1b2b7e68bc63fbd8f571e2dbc8f4f" },
                { "zh-CN", "6fd8668927242aa64418405eef7d6e73edd55f97d96dca1374589d2ae5afd61b6349426aaa70d31e6b9a9b533e5e2d917ea1a6c07b7e54b7ac9828ea883f6db4" },
                { "zh-TW", "468a75aeb38bc34353eab3e8828a95eb99b489a34cb672688ae0c94373ad1d555fd1d3f8413336b804652f1c07d926ea906a043d47ece85e2aece69655e3eedb" }
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
            const string knownVersion = "159.0.1";
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
