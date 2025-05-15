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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.10.1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.10.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "5590de37005394363c5035c83c9e74edc30712910834f7f2e45945bd65f2ade2ada57645308de0b195fb038ffd1e0ee8fafd67722fd1fea71961d78f094c43af" },
                { "ar", "5e0afd48b0c4ddcd325bf3086e7cfa5681ff9785c3bda0b7782e0cfea5009d23652b2f8313d014ecb94e811cfa20405b81cbed13e0980499865270fbf142e9ea" },
                { "ast", "53f869178c296dd0a1c065cecfaf02634cca05acc67ad96d1da77f323f08ee1143b0466fb3e34b0b65a239aa72550a57bb5ec230532045a49d7d30312c8e28cf" },
                { "be", "2023c72c8f80a5d914446f0b345c81b0d1d4ce0ae5d536160f39f78273c6cae7f7c21c12c9a6a54a6f09534b4b14f5bb514b00058d2c88593f75802373acf646" },
                { "bg", "d13882ede3d60fe4f3fd927f1a7d2db8272ea090dd09b198d68684fd720037ba342e3b93299d4df75a1d4a1f19ad81a7dc250afa979256b935f2aba4056cf262" },
                { "br", "01e36239b8f6b3134dc6a597e7bf640b2dd46efe26b02cca66148208bef19c9885414b39fc14bccacd7438ad5f38e00a7d8eac4895f85240bd563ba8c723df23" },
                { "ca", "708d4d41d0fb847025df1d6a48ab96166650a3b910058ebeaf2ccc868ba6c9f2878bd945c41f45e8c73882dca1c3de2b8bcedf052955757dfcdca81bc11b5291" },
                { "cak", "eab12eee60714c22fc78f5c900c2cd4a10ccf615432c0ab8c69d55169468eeea170b8f24f4ddb4797eb42e77a98c8c0d37d7383edf967c2ef95dad18cdba376c" },
                { "cs", "0807887499e4532adae44cbc570b02785aee4b468fac790f6cfbe5d1c8ce4c701c4c176a22ac13ab7344b4133b36cdb647a5cba96399fdf72ab7b4e8399a113b" },
                { "cy", "ef665a9a28f7a63f2e551d1d76ce7c4c24650b454b570ccb3565572c45f618c7d843aaab46515ac58d965b682d962fa7f805b87edbba6d6591e795be8ad9c393" },
                { "da", "b9b800cbf4f2349d0fee6e599b371dbcdaf610277c1e7621155cdee272c73c6c5066657882c706a65e2bc0432a9f2a29744e78c891841f3c60820f89a43be157" },
                { "de", "7d6d543d5715b9201659780554177df6c30cc45a766ddab7d611ff5b0851d09e05bf91a7cf5bb8d57df669d240beaae02083b1d142619463301c0392375a557f" },
                { "dsb", "048cf677b3981c68272de41c165ab0904e3357099ca59811d4689b9d71a324331a5e0255741ad2131598eb38b80fb9b0890a61457d336cb1680eef07fdcc48c5" },
                { "el", "75a68858f19ed6645ecac5b3b7b1c338c46a3961f24066b0dae3de36f2449af1a99e4fb9451c7a5a0d002faf9f26365123308c4e430291a26b74ce54822a1847" },
                { "en-CA", "ea807f62a348d2c6a2f4fb6bd0e844ea8ba30d77e7193fcd16ac5566d1e2c02d40f709a8335feb6ead133b6936d30ad4160fd34f1c282069694cbd175ab2adf3" },
                { "en-GB", "4cf5b1eae00baf5919f3610d2002d1315f7e3d8f2af13852e15f7f3805f0062d0bd3c7c898a9860804c95c586a8a88f7579f690be8c81762a1140b3d98620784" },
                { "en-US", "64ec3dee2f38bba0f41a955ad327c755e22c0480d427f60aa7ff7c00b6063e56699426f11283e77e9a6e1ed136e014d1ef4f0a6e50192f0bc4db4f81eced2bde" },
                { "es-AR", "914e8eec0695ad84c6c5995b56c515c6ceef17076de87c69d02a57ca1b46a62968bf55fad1ac3cd49d297de408e84614870d7676435bb7e20aa646ac473c60cd" },
                { "es-ES", "2d4ce5d152128fa8260dc9f511723fde1a155ecf5f735c4a08c064a12a92869c8799b209f08bc01f94d3355a371de26ddb395db968c750c9272e062eae070602" },
                { "es-MX", "af5ca5c999728801188b91ec6de902bccdc0e012bcd0d6c3bf58650083cb0e1226c9711933d5f09d88199592246cca2d3a655ccc36f37701138cc19f7688d03b" },
                { "et", "969e00b7dce584887082ec0dcb9fdca461419646293d3339123e91e408cfd10ad328243858ce91e9ebaf6ecda2240a3eec115999ebcabf6112ce11587b4beaae" },
                { "eu", "e82c4d988cd333e56050204abd368ba861fa2555ff00691dc26d7cd5b02c022572690e93803f5c61290123abba9a93debe537a43a726970fed180b09eec22d9f" },
                { "fi", "d5bfab16ec60bc56e5f8afcee7f2308dc7403edc174ee98bceaff95139d01a5eb94dd0fb0c1e3e935965b22370d4ce0152956d97ab08e6e49ac6b7294762a736" },
                { "fr", "95dc44f602ea8613fdacf53788f64576f3455b38eb527bd3a481a167d86f1c59c916a6695ef623811a02d264ce5656b1894d01dfa95b0bab42412aacf6b6ad42" },
                { "fy-NL", "aa884e7fc8f57bcb9b86584cf50350a8a04ea00739c7b63e585a71be8571f6232e23a53062e93479da6cf0c5ac65349fb57baccd6c16c2a782ea76800463e62f" },
                { "ga-IE", "470c3505e0a992e070841d278ee5fb4c767a7a8ceedc5960d691d0cb5d3f54bd684ff442da5ce6812e84be8736b9f20a020bf9a3bd6f467efae8ed53c22b3d21" },
                { "gd", "733051796a34e4f29671e8439b76c530dc55b06c2b9a1bdc28db6874196fb4efb8795871bfc9352ee4ec8e5e644d58ab642766fd9531cd86168b2834507d288a" },
                { "gl", "049018a1174af68a071755ba3115469e4a358f55273b47a410bf9e3643b889e9c5be4a4087f79d5f627fe4cc3bbc545e1d32ecb245513957819d325c0c2b5db9" },
                { "he", "024a3053a203f8cac9a055356f545dba6e976cdaba947cd3a31531ed13684314597a63ade8efbdbed47dfa43fbba8d276ce3524e05c3bb3023460b9a04046401" },
                { "hr", "a1efeb47d0a2c0a509bebb3dc77d209501a0bc00e1347af5d58221293ddc2bc7b520bba4cb43f6d1413e5339a90b5c9e2986fba486de8438c2f89e34bc8b590e" },
                { "hsb", "3c70a99653a9b80b5346979e05823e24b90765fbf38ae6dcce6f66fcb173bb077e7bf814f6cd351bde6f3bfce2810ebfd1b5dcfb134f39aac0de547e5854c733" },
                { "hu", "da0a9ec2aa58d90a20c91872031bee4c2a355ebf89efc7e694dbfe62f10b004e92027ae0a07052d5cb5beacf04b40f4f76b79650bdf70ab5ee9f888a539d74e4" },
                { "hy-AM", "5b13c6367702d5f660bec338bb5b8b5f1d0f3f1413db15ba5276ef01d334930a9cdf642eff649044546b907f2266184382d94f02c2b53095d3d4c328c0bd51b2" },
                { "id", "76c38c06cfe27141a64a6b811c8ba0e8598d42f9b7bb6b21c6e957e59d5a2f4e2bca80f8cd370a7f9426b57df563195c0b4749e76fc5997cc56d7e43fa2c2a33" },
                { "is", "dabc210e4f5e5b4b8045fcef7de19639c3f7cb1e97149fe847f46436873960c3c5f774f925d45e08f6d1dccbf171d420e2e3f121cf2f76f60c8b559edba5683b" },
                { "it", "27271c55f4302c01a1ef66d20032b19d3a0087689d1cf3d8cb9c98806ab8ba3d10fbdac4741b3e2f31440d7e015207eb2d31d02de600ced349aa381676b256e0" },
                { "ja", "6e79d5a6492a0d5a07be51b38b493bc654ca7457f7434e7f14ebfb33ce0b93955a646611adf3aaa1b86ea0a537e63a635b9cce7a88bbc9ce6a9170989df97b76" },
                { "ka", "85857d4ca1c8050a8f222266b34fc202a4f9ed95620129f15d43db9f50ead9024f56e8c55398c7130c180dafb2200174f0ea68b2f748ec4c3ce565fd1b845835" },
                { "kab", "8d29954ba30630c130862783a9ead01a1e9224266e4eca02b0d48b533cd7d98d013ad5a7cb213d45ca87f3c2a70a8d527410050963d40146465fc19a7893dcd3" },
                { "kk", "b1cdcdd92fb4ef470bf93686cc5aa468477c68c9a9f34e0181f41681d42699d94a3192d9be1d24eed791b491671ed178601d3c471adeaea6feef34c746ab1015" },
                { "ko", "8ae3b90c240a64c93afe37baf79b4d0715acfc28fcbf42cb1c53122ee71948253abeb6060720d8bc4a2248dbad0ada8335414efdf4cd0b248806f1cdb06eaef6" },
                { "lt", "ece1d4a1d4b6659a15449236e699b92ddaf58c918a1b7aa9ac25ae67365645bd773b9c362ac9f396254e761231d368895238944174bdd7628d4dd6667934fa5c" },
                { "lv", "1551589bee8a9f59316249be605cc5aa7365ade6972f84d75708a9a8165b83c912e939eb4af65f547e256c9b4689ef96a86bf65a42091c39f4dd49280b61ad5a" },
                { "ms", "ee5d311d671c91f1f3ad4184091cd884ed650f414a9ef06fdc11e8d5d2f0c9de9856d0d4f021e82fa4f1aa1de25ddd20f04e6a0201c7af0073b79d85ca110894" },
                { "nb-NO", "f088082779081c42cb1174247474a08a02b63a1b0bced99e5d7dec10273c5be0e0c962141b8f7fa52a13ae0ca680ed6229d5b9608d03bb35da413cce29497c67" },
                { "nl", "25746971e2a5fd8ae6a97eaf19760951310124b09f57485734c5041c5265eac01b121e3d86161e42fec4f3cfa515c45c0273cea9809f41c3d4e5b6ed7b233a34" },
                { "nn-NO", "53b6aa08eba6cdda750e72a5f5be08cd04cdd1465d8a63751528d3c25a92b7108ba5629fd8e01616010c3dfafc5ac2e08c21571bbdb7195230573317fc6028b3" },
                { "pa-IN", "1758b9b27b2ea765f2c7e1951e898143914aca926a24bc7a27a75d8bdf506ff1e86bfbc0a21817d6f86694484c0cb73a3188ed1ddadab23512df611fa60085c1" },
                { "pl", "9fd2901b8a136e018be783f98865a6f08fa0312d1287653f8c373649ba72a0937184953449ebb246e4f1b4d341b6bea883d09885d966d19a6b2a7825c9ef168f" },
                { "pt-BR", "9c20362ff5229c137c7baf092b109d834a76b3fe0b3dfb79799f037980088fb3b9ff9df2fe94398411e3c1a009b64bcf479add5fd9d99670d6f443fdf4eb89ac" },
                { "pt-PT", "89e5e69a32009fcc8f9c9e4339319fde3f40df5cf514a553736a70bd751a56c7047994d693dcc5b32920cd5a08860173660d5dd316c70f42e8e1b3ce501ff793" },
                { "rm", "edb193a6c7705ed192e904b9ff90c95e945ca6eaa952126198e5449c30ab8baff2350f7bc3acafd1dd1bcda8d85f76d9b8fe98580a15f88a5d0faee33df4c019" },
                { "ro", "5f3103818ffad3c23ab906b647e06019117c2511d0bb5aa969c52b5bf1ba0ba43ef081b5d91b3bff9d7c7a9e9d72ef89c716ba2bce78311b558fccc33a4c12f6" },
                { "ru", "ee0cdbc49b7ed0a8bda3aa2e815c14911c81d1f2afa311a9e7459f4bbf8d5b0b30cf02bffdeabb100b06a53d64dc533d523ca7cb1ef419b5b9952c71d5f61de5" },
                { "sk", "5cc164c34d660756ecbab2a43653262bfa0e10f859b4301950ef39abf4e7fb5e3cdeec6c62be00dce149ec2d8998140ae15319694b55c844111eae12bf7ae4e6" },
                { "sl", "64cc1bc56891ae4c48ff6fcb601d737c988a962717905559b1a4d85219ab41be636894c92047711101d25c26c6ac4fd7a9979b4b4f493dc347d8bc3908d8ea9a" },
                { "sq", "9386760e6ef2b5666babfeeafd2860dcabaa5d7aa728156d69f611edb02c58822471bf3f63a9ae681e2e2354db9d59fda7125e7cca18777a83b3fb69587ac11f" },
                { "sr", "cc5764a5b949b4de66fa9a31dcaebedab6824874dfe068bb9e37c23b7b5f310ac9ac7af85af512b16b683138614753ece1b5853c826d964b6fe958f88e510ba4" },
                { "sv-SE", "70d83767aa62ed796febaf38248cdfd7f3cf761b03851dc9fbe1039b61db70083ed7649e3dba45abc90d3344925a58c18aeb79b4406475b442db217055c9bfde" },
                { "th", "c7b79e5fbff88eb831790b4575f0c7e46c894e1166c2beb9e9a4295e9bdd7324e7622df5fb0f2623a9ec3bf68af096748c2e769b6535d5c4b158e8dbde2248f4" },
                { "tr", "27f6c0444f22ade80c797b152a05add7d838a5d2521c6725ef3e40015cc8523ab09271baf1f4ef010d3fc76268960a13e4bc178ffeae6cd0e439173df0ed3b6c" },
                { "uk", "31c452b54bf02559b633079a0c659e123e1546732a1f7097bae7e3d87df81f5392bee825dd01edab289b6f91ce3b12ee0cb8ea0c64e8181208a80564b07ea0fd" },
                { "uz", "9e1fafb1de03a09709f16deb0d18ce5684df7099bdd7ea10ff3247cdca582a99127a17411ecaac8e451cfd3f2de23a74928b25629f44d3234eaf237099c9afad" },
                { "vi", "5c4b27dee7cc343ffbb67f484a2584b6601c564b6437c75699c9167de6ce008bbc30b4027bf5f215488d469c0e4dc17dad7de75c7490b27a52507aec20136707" },
                { "zh-CN", "06114fd221cae30e84942414fd094662918eaf7629f17516dbfe674da7d724df84bf77c62ae0a6c768c2fda594e0d8ffbbbd20e3bee6d3a4004b6e893748f0a3" },
                { "zh-TW", "b3f4f81de8dde23fed41465ce1aaeed8edf6b3e11b2a034019967173cf6f107cc1b0cf1dbe57c8a0c4d38031f4b9db0c4d93f97c595de65ee49f687d05155726" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.10.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "b87568dc575fd390b8af96f572a0a498aa98eef56500f51487286fdebce9b2991f75df8de84429ac2d24070bced5b98f291b427db846c5495f18d1561768dd29" },
                { "ar", "a33b2e6145badd029f52f5f5c4f590827ac4c782ea4c101c4cce3d4914fd0d7dafbd7ee5ac7fa9b9be23cfe2a328d384976c5eaab2c5c8093d675f286a886cd2" },
                { "ast", "0f7a1f5d55e85f08c3d86fc0a5dc7e423fedcbe2d18720dc8669af6e4f9050f30aea161473615256ad7e7bc16913577b98596b9be6f468d813f23ade1e669c2e" },
                { "be", "914bc35685bbf81b2c43cb95d9063a3eda5f497162c68e7241fc898f8a81f33b2c020a0a177c0fe76842b6e3d8f7903bb7f8ccf793c0ce1336191b63f0ce0c9e" },
                { "bg", "5f291465fec8857bce63d567600ffb68dc384a77c2f823f739390db10ccb0f0c51e1b927a5dcf11a5dbb50e84e1cdfbee38208eb00c20e5da60b572daadff6e5" },
                { "br", "acf05dd03b103ec18c2eb76684c78f6037daac7e3fc7f2cf93572768899e27f9ec520f44799914fdc64e0e94496172df65634121b3d39d0085790012e441a135" },
                { "ca", "766f62ce5136d3f26e0aa63343eec10b72cdf337e502c3cbd601857583c04e0ccaf502d98a4e0c8768320c5bfdab512fb11d48b195a34c9fa2bb6b44845124a0" },
                { "cak", "e0e33627f972a96ccb06e6680572cdfc9b5f954dbcea66aa6b0321893472e78cb590f8edb7d2324c24c947a527ab62df86a33ba3acfe4c638d298e262e06ab46" },
                { "cs", "b555f8fe96d9a7246a834d5a2739858f6ce4b407935b56f5da1946b5479dd146e8b4b584b19331f140986f89d67c94988e2efabe44a20dba5aa8d711cc1b4e45" },
                { "cy", "4a8a1cb47d0154b37a59bf471d1780a5252b8aee4765314f105d93baf971e5863c8a00b03448376b8802926469b55282ddc4ec6214326125d285b0a22cbac51b" },
                { "da", "934164cb2b1f99749e3290b94ee0e79865e1081deba7189c160bf6c4bb8a25849bbf0ad0401652028a6ada9182e77b2c2473189932966656f81cbfd8d4443ba3" },
                { "de", "d6137b9e8c71935542c51273be8ab140bad0175fb961ad497d4ad8aa44b1dbf3ac05e97be18c0076889c5df5c2ec4fe5e4c0d34ea39a05290c5eca256e570cff" },
                { "dsb", "144008f9fbe545217ba50da1cff8b648a3ce4886f811017798a0ed7f85a7388ada67889696d22fdeda522ab0ade996a2a6aef47d86c2f48e2cf7481f6387b37b" },
                { "el", "b2fe99047e42fcda79fa9ba8a38d0b22a171f033849a3f677267b6f5bbb43c2164bade65de81527d1145eea56e0e7c70839165cd7088c92e8a8feb440c9a9d31" },
                { "en-CA", "8c01ded65c7dff8285ef6da77e28b1df83e2c121fa00aef13c5e5c60c0cc0e5f7df90c87cdbe61b31ddfea34f8264c31ebf6a22da8c001138b35118a4c23a525" },
                { "en-GB", "d2c68a36f0730f928da3a3e3b1b7527f580b54c81f4bcc247b81a7854949b02d2dd3e38a19d4f93f88e8417ac0ae87ea5e4d7842c0dd5f34a28249f8abdbfd5b" },
                { "en-US", "f292c675f11035f9950c0df2b46b3b99ff6fb28308448c87895456db5a5d7471a8d8d0e0cd712071bd6a31f3547bd2a57bbb1a4ff000f80b340f782c09f97169" },
                { "es-AR", "babb7c9e70c7493946b4d0c4b6fbc87e9268bc9e3aebcee556d992f933984ff0b5dbd9dd94e2bccf5166967abc88b2bf99e5802e9ec6b325ce61b6e6ef75a217" },
                { "es-ES", "a1ee94fb92e3686b680dc707ff18af83888479f503a4a202ddcbd4967742a4d21433222550e5e1c278102a3a27599697b0e35687b1d4c900a203b22a9c0cb20c" },
                { "es-MX", "3e1ead3450cff3367dcf3bf4a9355e2c5dbd865bec176e3086bd64509f57c0d1516e628a14b27850e79df764d7508fd585732db50a5c712b7aec7ff9dd6cb008" },
                { "et", "96e249478120d357d18c379f696c9553fbeb2e7af16a37b7822078e2dd4f2340233435a937149a33ec8f9b5cd65e985eae53c82b20014e9a55da98f79d009264" },
                { "eu", "4eabc79e0dd0ad53b3504ef6b47c250f9c05a71c301dfb66881c9f910d5ee2d90866fbea74e8cf1c67a5b9d4a4de8232731e15dac64a714c3a5702adc12e482d" },
                { "fi", "8848c5b6c499fe85eefca9b50b3ca88727af1c11779e452b77952a67d724f7fcf5d34125521805f2be1deb84c6f48afcdcacd68f67b3b86adcadc283249023d5" },
                { "fr", "f7fe25208e1dcede7c88a3ef0052a30ab161c75c88cbd7d44e52480fbd34945ce7e5f50f539c1881ba0a19e2d9a13cfd50642f36730eb0a8bb7d73c624247aa2" },
                { "fy-NL", "4afdc0c8825e9fe89874e70372088c4d996533cde7bbbee503c8532446cc1302c5d782e66dd0acb4cc024e71ac311ad6a0d4d8919283dfb4f1fe6c63e766345f" },
                { "ga-IE", "d566ae7eea070ed2f1b3d3d94299a886e7bd3a2b6a9622acd09ceabe93e972333d00495e8aa75d6335952a47926d47021640ca1c6eb878f7a7f2a391afe4b170" },
                { "gd", "bd23eab05c8da426eb77ed96568850ae113cc979da67716b7b473459d53af0a36ead65856aab0067d01053d40d3e7132e43d25d00f3b7568ab7d3b2c6a1d948d" },
                { "gl", "31a3964f988bf51d0026b82a3467276e68c5ffb11551436ee4d3ff2bda815846046f950837bc36adfcbe4f75d9907b57f45d1996a638c13db4d16fc2228ca48d" },
                { "he", "a064d53f2070dd8a4e7a43ec4182181ccbc574a970d5c3928b4ad8dca0940a0a71357d6da989c1f6a0799d6a7af86cdd9eeb51873e5d8fa3a42b332aeb0551fe" },
                { "hr", "6e4ff9ff77bafb6ecfafd1b0ceb343ea880cdca387f5cdda9b47b27e278c04cbe65ccc6457f8640531e285756025a72b2ba930488ac4badf77e8f1639bbb1ad1" },
                { "hsb", "04d266dc65dc75f0cfd55d2a92c95c7459525de95fe74fe4abdf6b780ecf745bbc13fa8ad04237391d330052ffeb1390665b356d09981f52f4a46f65a0c47355" },
                { "hu", "2b46c246b0aaff2bef27d2456a567069ce808d71667fc2e7b9b0536cb4da6d931c80e0c4e5b293675c394060ac6537b770ba3c268a74e1e004949c8840ba064c" },
                { "hy-AM", "a4ae94e681b247641b520eaa95126558c4d35808b83294c9a526d2ae5d96b31a3fd3464ca3741b3ac3f33f18118d6dd8b81b999648f5f41a8b687e3a93ad33dd" },
                { "id", "87cd15df82a579ed7eee5fb08c89508db2886757ec93895ab78c378807a48a0deb0f3c942578fa7311ebb26756b41771d54032004656153b6dfabb721f6115b6" },
                { "is", "9a5037df5cbf19338d85e9670853a4d9b7e5bb030cbc804f52117eff602efbc5c7fa0d0e41d134db1ee7f9619bce39ce97faace566e10d779705da9a2fe4d2bb" },
                { "it", "ea644fc926e9c912d8bfd1b9d814fbef1fa69f878da837aab566353fcfe26f4f51f197778075a47e24bf69d990a4b8fb6a819046e8253dd02ea17584a3b37a79" },
                { "ja", "dd38701bc0d3a004210f355cf383f564ba79d43cc6d458eff44a4750599e32e5aca5ef2b5daa7aa3b7cdf0cb975a59f8677d3214ddb659f2cb896e14bdb65db0" },
                { "ka", "da191e1c127a67df0ae338b5a3846a03de752cc057cb2f20cd1a0182f6e6476c5b6ca454118aea0cec830179d7b279703613a0f8cb8e82fc2fa524e82f8d1df6" },
                { "kab", "896c7ba94ee03a13468f0408d741a9dd77285e21c7c2f7013912d5092312fb6480952cfb1c738cb1ad54979969d37daebfbede802a9d456072b78404c412e6ae" },
                { "kk", "f8a33b1287c13cedf7b9b54879d825375d8389591a6b6fc3ae72570f1bc1f8c0674992e404c3227cb80b8ecef099a889cfb3ddb15a8671fd0c589897ae163369" },
                { "ko", "f6a1aba127beb93e327eef5e82c2b99f97a9bb6595f574e2d37784cdfb572620861a854b55e5a496ac9c3946636a06fa39b269cfe45bd882f75023d154f18465" },
                { "lt", "b37032e318033eeea45465af9be93cae11283db33c604a369f08a27e962866fb715d06bd3148b5ca75cad3b614ce58e484a705294234766a8de8a72fabc2a1e3" },
                { "lv", "d4b56a04d409e26685a7e67310cef4d4536326816b36ded6b553c55f2a3d7b0008bdecfe0bf9ea4a45d931fae0801f92861a16168aee2914c76122ae5b59b02b" },
                { "ms", "75d52e76088fd3ff1cf07fc3040398d787f54b851436695ed494b31f5c27903a94cb391e832d46ab8cabe94591b81df116645cdc160acff1dcb9da0506b9d9e2" },
                { "nb-NO", "06a141a2d46e8c83d251f3b1cb2d733f6c5b4e02f4c9a17da191266e4b73426f202cbaaf5adbca82bd74ce131aa8abdd14ba4d4db9ff039382b64fb4eb5d3efa" },
                { "nl", "9d8360cd27496e421f133bd47689d5f83dfd2a29bac8a949a6242b7e35793180698153455c5cf00bf7696271affa6fea5569d9130a572f2d1a04d5becf2176b4" },
                { "nn-NO", "73d140511b770ed59fa11de2eccc79f07b29851e1d548af094486537e824855b2d5c8841937952cc64738732539a79bb8097891312b44a6b67f711a4aec06f9e" },
                { "pa-IN", "8134cc23d9556486df52b651e09e29f2fe0081c4fbd7b22515a4275b57773e07361e1a319c11868f2d0f1eb46659ac3d70970a832cc51728baaba9be9354f11a" },
                { "pl", "0ef9dc44cd63dd976c22b2e6901f3cb8d3f2a86d369a9330591f7cf9b9a7b84f88a3871cb38ec21addb293d53a6befd581f5f05dd91c0a84e01ccef808f9b16d" },
                { "pt-BR", "80d9d6063aee242b259ebaca2877d14aaf801cb78f26281062651f1e7ee895cb91c32e978293ea7c6901b47370c14ca148ea1f41ed61d00defab21c164ddbb90" },
                { "pt-PT", "093886755539b9a1666cb0b4e166116c5367be6b9b5077984fc7f6bd17b0929948331a6bceb795e872f2339d601bd2b3ec5760c9696aafd0013b82d4f678f7eb" },
                { "rm", "ff7cfb59f8a42b28766f886157a3a1c73ce140425ee05709f710e32107f4db26506e9536adc3d2c4bbef61c841a2231bb594ffc520af8c911f91bc541dafa041" },
                { "ro", "c1ab3c3c4eba8529d595590c4f2123a75f1b24b0717725c91b60ac9db8ec22ae9c04ead4db1d4c168abae288600166826d3947f9788656c8f634578e23a0b705" },
                { "ru", "bc8a224b49656254f7448e73fe39524c24c6ab7bc81ef91d2b21f770d196c238d388be904075df21b8e7ec94e5d3d557d5640390aa0aa726f10b2dbb7a7f668d" },
                { "sk", "df16df28fd92983dbe21b58033ef1211390c56114bd44f6ef73d1a66480dc662db8bdb3c75b719e6d5464bf358176cca731d54f8bea8cd1affd3225e51d0be4f" },
                { "sl", "1e685210abc78ff4d1ec822608cf54af212170d869dfc1b02ee85f2d46aeacfba3cd25e33b188a823cf890328c3994df2088f2ba94cf769e6f5a5aa209efbf1c" },
                { "sq", "b1f4c93009b9f9dbbdb36670afd876a3274a698bd35fd1daef0ccf088a1118b78ff94ffeb65d62eaced9dff3e9ff4b8eada7a0c2161e2f4cc13caf862fb78998" },
                { "sr", "5487e052db9a3eecde29d0caed42f857bf95cb373751eaa0c14622359aff70ca4386f08e886e3141a1b7ee76506cb046b58a96775221c056dce03196f4a97bfa" },
                { "sv-SE", "2f7104fd77d6bac6d394d378233846db7ece2981a72f2ecad61ad4c55022af983c46a85bd561b8b38e9365131f9e866d1da6f672c462ed3d31095387b4ebf696" },
                { "th", "2d50ae47f888444e8446f226a7f20d3b49630c086047b9d6998576a81174d30d5078e4953cc206fb2efb5cd40731170fc47e68d7ce6f5f67595043660851fe28" },
                { "tr", "25b6b060a5038ea8ebc735d57f2a53f02fbfc10395ecb1c3b5e819df9230793f814ddea9b21d49d8ace1cd60546d2400f4bc41ca8cdbbb760ee049d02d91d4ac" },
                { "uk", "7a67b302229c7cee7da6359803839b38abde8677debd8521ac7ee6a0ab7206ef9d99201851c69b6ac4b22b29dcdf36e91aa27ccd8c4b1d621bf908e468e748a3" },
                { "uz", "fe644a5e9b5578f36ea87e383e504afda44c0ce519c51e953fd3604be69dc8a73a5c2396f429e36feffcef41d0c5add949598b4497804b35213b6cd9a984de6d" },
                { "vi", "1b6a09f812477cb495b363d6052b6aca96582c4bd4fcb398f4b09ae40210b208f0d481526d4ebf94895378af41959cb683e8155d3d30944d4b59192026d02109" },
                { "zh-CN", "2aed80a376e3e920e1992662b02a09e3986d705b3f019521cda941ba5f55eb9fd765e722c0bba01fb033c1c59ee85004717513abe3e721c1472acceaabe07814" },
                { "zh-TW", "f81376f15027eae681c68b7d950fefc51dd47ae6bca48966a6dfa0866b36eccbbbbdc2f7447a3527e3dcc0d0e6339a146234b40bb59ab8e3d795439174a8fb04" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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
