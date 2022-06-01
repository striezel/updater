/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "b8b6789c9b894933b6964d49819ea4df286ace2ea9a758bc448ef4a52c662b407e3d4dc3c3bfaa2701d85b306341a61da3dc242ea1cbfc535ddbc1bd154cd4b7" },
                { "af", "da3992dde4740b691db16372c411c5f4a4e48caa06fdda842dd1270b212ba02c5741a74d61389facf4c43c370a3ac020a9928958f2254a2f9eba5bbf7cc63bdd" },
                { "an", "2421a8330725ed7731f0ebf9174bc55de5f339187d2492a6cf621d3a24275df7ebb68fe330f6d20e3bf62e00fb71aa5e39d755c0f7ea85371d0afdc0a3db5335" },
                { "ar", "241d2d39234666b691243f286abeda280c041c2f46ab8adcb93d9c01485b3902ed74027b8ca31c568dca559d7402da53a3b1cd0d6e7db08d236e404b261ddf0f" },
                { "ast", "5e9fc054bf6317b8e124312569c586c13db570c1e4b1d91ba26c4d82efa77ba514e524ac7eb4a7d2bd85d0c491e311bfd2c1c9958b83bfcd6cb59ae446c9dd4f" },
                { "az", "1fd40b0da765de1a6f862fdbec200e643505614c60356489dad68a8d7cadd13eddf681e9b703145ac5318437c051d75051d5c3546987b75f5292fc4f038ea85b" },
                { "be", "9d71cd06d664630035aa5c9742c338f7bd80e6500a12b3db48f2f00c050c1126515392bc1e778dfe457e441fe43e51738436b9249d10dc2aad6c9bf25e43c320" },
                { "bg", "3765810403ea87de92dd82f17033f7d022033ac758e82df8d789ffde88231207510f9eea07b5a75c44840191b379b630b0976758abb9d6174519ed6d6e27428d" },
                { "bn", "62488b9100a9182745f344f720540a3a90888f1c8febcefec86b746969b74cd1010524c2a8a1039209786804904775e8084a9fb188b40be9cd8a2e02c5a3d36c" },
                { "br", "8d8a42957dbdb9d58c45b84364275b2ee258069ab22b02b13b54ffeb3444853b8b55ead3799c4a43431ecbe7480774f8ea8b17c2ed77cb4a6a7a28b4eb31dec7" },
                { "bs", "8199c62d00543694e76fa46271a8fa09167ed78739f51fccb668f94bf94435e206f6e65ca60b80cf8c678f628e2dbcf26fb5175f93c5cdddff0aee7791fd36d5" },
                { "ca", "d9db0735f2e0fb6c346a5b403658deea7bb0f0cb2bbf03aa4e8aec77f0482a24bc6b7c4576debbb2d1cbe16147166339d9722e330f7c5915fb4e7fc47929711f" },
                { "cak", "46d4a67812f46264704e17a29710376ce612db1be62ad782e958c6a67323f7dc925cefc88fa9badbc8392125ef98656cbd750e95b61b0841be9c02508b70522f" },
                { "cs", "221fb507a2174b9b3de46356a3f0610ec8672fbb6ec55a06878a038a693c323b6effa67eaa61c1effdde439fdc4ef4c07bf79864d08d1747651edd0fc1228fac" },
                { "cy", "02a0f7635b721572c23a4ca1e6af34f1897117dcab2a53c4c3ceb6f9a91638649463c12a50797ffad05fe80ea7f0ce3dcec3a43a871d64d3e27556c2ea408bc3" },
                { "da", "7e457cf2615b5d176ffed4780d421ad1d99d336ddb67432e9bd9501c6278c9f2cbbc0011b3e192c0d26b5837e0fa48433d220f93939a56cc702f6b3d195b2786" },
                { "de", "c01b7e8599ff0b5357b68f81635af370debc8c7af0ac097418b094289c37f3b6ce423a33c8aa7e22a2e6169ffb7b4153c0d576b598f5d0686df3fafcb21228c1" },
                { "dsb", "b19db05fd351faa4ba429254d6dcd901f3ceecf23929a36a10e1e3731b1b4a93b227686c1cc729082d6f8f58320811f4ea11c262a82f86588efb93a58c38533c" },
                { "el", "8c2d8a9d513393aea91b019bce76fb24e9519c60226077912e4a72bc96a0f1828b65437de8b9ffff49f52716da11625cca812d7ee2e787e45d3e2bbcd1d7372f" },
                { "en-CA", "f633f657c99ec40b97d57074813db6de0300511da4d77d1d01768fdbf46aaba26ecd878c0092e4c74e1d5444cae3dc937927ab01b6ecf65e24b1d1488e25c980" },
                { "en-GB", "3133d9098fe6cb0b55e1ddef94a0366788626d9d3e2610f2f3dd2422984c7ed6a6785ea9bc26e493bb516c80211e00224c9f150ea48a075282f9812172e97dc3" },
                { "en-US", "0a105c33b0f181a7e2900a593a0a9e98971a7498dcbd722011373ac3c173c56f286cf9a4b7158e0a427a51d3d66e3943734152b197e49283e3a53ee9072ca472" },
                { "eo", "aadcf55b00eac127fc715bdbc9440676908834964564147f1e355e8eda5e1e5888bffc52402f9c1fc34a4fd02f269c6cfc0503c7c0330c099a4a031e74d9d8d7" },
                { "es-AR", "f4ee8a58ee06268e1180bbcea3cfba919757926c5136cc57566db21eb519b142db6a699b038815ff915c14dce2d936bced30fcbe4b00e0980310550635d4a2f7" },
                { "es-CL", "d19d4d2bf56a6b100df3080edaea287c8be33431bb952d82765913371a9f551a11fd1b2c12945db140dc6cd49a27fa717b8558e73d542158a45c3d34ba29e4ae" },
                { "es-ES", "7d777978114f32869e8c3121bc5b491cb4b812ba33f60a6e0caf95a98c8bb028fb1a67af7e6acadbbd784e57e3a824437a26a3119f2170987a8913809348aba9" },
                { "es-MX", "0bb7619ba0b4201cd60049600cc12880722017eb44a98efba3f1b1d835285c86c91e5edbf6f1cf491ce91799f58ff8a665a19657b87e23d5658c258e4eea4aec" },
                { "et", "ae008a7c71fbf354511bc5a20d54d13fb46c76118355f85a63e800e1ae886bb24f854fcd92a68bd58ab17236b64a9ac8ca290096fcd337a6f1c3509af764ffc3" },
                { "eu", "8a1036317a5eac67b79ce310c4d57f35937eaab5554f055a2fb57ead9b27428863899dfb06ca1a430560a3097b917722d049fb4289f377efacfcb8634d495d17" },
                { "fa", "e08bfc8f218ca2e9b229fce6d302aa926f1e2c3133eb4582a08dc28aa249509ac5b144a2eb40643af5f88fc67d684fc75faa813c42f256ce696cf4b5ec4e7fbb" },
                { "ff", "f1e601f9f104a5201af17b78d840e37dad4d4f14c498f24a297b459aaaaba7f6ed47248bd119c04ef1d37528b8c422e62cd2d7f79bab145d819e4987f7d39d19" },
                { "fi", "b45e6e46769194e306414a607f02c5563403dc69d4ce835e14af0477932b64fd7bbecedcb90f29b4ed6493f56633af2c59718a505fc6004765784d59ab476b46" },
                { "fr", "96fe32fc1542d9c886f2d98c385616fe1218d57087c290a96467d102b27ed3c728cca8a30fa11615ddea668ef164e5b5fff7074a723179e4b154d1a2fadbd46f" },
                { "fy-NL", "df05fe59ce5071639af8b9fafa8280db2a757d265cf42298e9a7f17a6b0b49d21b57992365bf677f8a2c09b2faa505b539fe05820b93e7276dc90ffd0d99bfcc" },
                { "ga-IE", "eb6db42b5e8384f0aa2f5a7fcc6b08a33e64f1c69a4513fef835657fe80f6d36205eb68fcc6397b22ecbdbb2c5749a7319990acb2bd91c0373ffdf9c9450e798" },
                { "gd", "46e68f5022fbb242729ff46562e92dc9b3cc228d496286b5de08a4743df35e3c2c2577006f45368856b2692a948fe916ae38aa3c5f6fdcbdf7845be23f89e611" },
                { "gl", "bd6d69e4fd30894456bc21278f8b3a477f615e96657745872bcca27429dad2ed29120df0491f269d581680faeb76b78f066779289a1508b1caa86e71a436dcaf" },
                { "gn", "ce1380c438875ce0b642041986c6921e2759fc78bba9d06769605ea61e54ed05ccb1863e9170b1998cf2737e44ce0800eae3d8ab9713738169895b45ccb6931e" },
                { "gu-IN", "2678d4792b6671809ccda7b9e56f7f8da38a6e9f129ab4e26b15d7f5db03c0105d3f3e7609f4c69627965438e85453517412b8748b5d48acef536242eb3c1f74" },
                { "he", "d6c33b4f72ba7a83cc6410b9327031acce3dd7a53b179d82d66f87f683fe1f42a6a11a03ef8ca0919b57e5c7c4bebcd3736bea2ac7d81008d37ed9b7cf51b4df" },
                { "hi-IN", "a9c2e6ed19511077720583389115ffb4767a3c8627937bac5fe6d18d03ee46b8bd586e5b17536ee2ced90d74af17ca589cafd764d9691062e76827928cb717d1" },
                { "hr", "5c1dfcd043428cb83665b7fae2792039a965612473cb2153c37dbda56222362598f96a48a887c965763302a019be094d9d2d180d5067f3ee233d038b832c4aaa" },
                { "hsb", "15a78ada1d79c82e10d45d5638818a48b0eb113246f85f326717a1d05cdf0e1c340bd4c7027232dabb7080d6ad4b358cebafb9f0522a8de19fa89543a3eb4e13" },
                { "hu", "53058ebf2eec23c9cc15b962aefbadac837aead1d87e7000f5b59e24719ce237a8bd587f5e10d014427e0306aae293a637553087624f002becebbac667121ed0" },
                { "hy-AM", "d38e97f2bf6386fcb1384d4ce2463f778c24f8bb5bc005a4719a576d52ae6162627dec9da02466c0bdf5d0a9f6ee3d7e6be0757cbbb6f70752c4d4769bff0309" },
                { "ia", "4a282ad6807d7b744711734e2a3bf4ffdfd7f9e67476ab44eeea724d8937b78887ef278892523e608c9d2366a1dfabcf518e01e982a59ece797cd4b254e41e1a" },
                { "id", "a6286a125d270272c5a4e1f5994ad76deaacfd488b16a89f6061c818d4cf54eacb44267049d1fcdca56cdac0b3be2652b532fe2bbc5db4b3549f6e1939399908" },
                { "is", "d0500f2d2c3dd68a53744edd8e0d7ecc41944e1e882a5d72b88528c7e6f0775e237d7e66a2abf2328a2d8a235f45d75f3827ee610d2a7a48e744ffe8471b45b9" },
                { "it", "69fda381666946bc71aa3d0a021cf13409158f2b14cabf860b454a6ffbc9c2f2257d7c2b60072869e9e3aa1f4ac3bc2820337e8e690dff3f3310ad4b0ce3982b" },
                { "ja", "666c015bb57e2a1b5b6efb8dc4196c573d2626034dba039f68e25a68f0e8d90f384c875dd56c64511ba259b1ab09fa55194842a5c2e6b5eb6d14b1bd42bac579" },
                { "ka", "60433727388f7c24eff28859389eed2988841a01d82253e36fbf8b8d5753db4e1be3a996470fe5ce11126fc7d09c1c4b7c61839ab6a6c7e5e2b708687104c8a2" },
                { "kab", "51878fcf7bd32be1db205fa9b5b543e2ed840e70e1655ba24a760ae9514b9b1acfc3a32f6ac3f9c77723f17d80167ceaa8ad5a875335952fb0bca2bd0d6356f6" },
                { "kk", "1a6b2d20c4c7704904cfc84701437d0c90bdc4f7ce7cb12b6496499c29dc22633a09671285f93f696fdec1e457e56bc65c3ec4d63286a3969fa5d7086e46e1c2" },
                { "km", "13caabfc62d11f4fb49df84a183095f0795b2e156a3d5e50004e1e494ca205196d7bc8278e8c42d121d5651eddf65a8afa36af7f6f01c1dec6827c0efec92cea" },
                { "kn", "966666ecd68027f1463d3f642c64c88bf861cc2ff2d5bfb56926fd6f675db55b03af8a972caf25d680a60a7b1f2ae6075457fb51974885a478b8d9bfb153b927" },
                { "ko", "05f8349fad073604955d6b0f86fcedfa875558ae9b3dde5b341af1b7ef67bbfdd8f69f80fd9d6bd3f2388bafd93dbe1e878f1d4361274955dbc7f18491425980" },
                { "lij", "bc3925ed0f6f09a84abcc6013a6a7f7def04011f58d8c17431be9883c3a022a73e8cc4889fa367768c0007aa28a8c9294ba141589ac1ba009341e37fe0eea68e" },
                { "lt", "9f6b0d83127a04b46a741cfefb5cc93d45765e131151d16f2070df3be5f7e6bb8c847be946af8be168c33cbf937962f91a9fd70f09fb0dbda1f7d7dff21a1540" },
                { "lv", "293b59dd9868d57a76794f59d6a5a3b73ac14bcec9e5f63b619054d54fba366b65070268cd95f2b935302fc825dce1caf060f79c800f38acafd1c91d2cdcaf57" },
                { "mk", "a50836f753c5fedf2a6ce2527fe4b14ef88de2e901f584acb7b9bf0bf6e2508f7cebd285d06b736937f4ef32fb9f26b87c68cc94a25b37884d88f9cc3e042d29" },
                { "mr", "f265b79b024fbba7ea0f30511f5557210b293539ffb7ea4a62acdcab340c3d7724e97f2111e9ecc2ce5ed05befc61b2cbce2129768359e749a60d4c694e07a7c" },
                { "ms", "6a069a3b49d21e1edd834d12c61b7ceb3511ba5b339f6a1608d0026dc2087d0cc2bb4e14f6e3584f7293024aa870daeca2354fdcbdb24eb733aa4dda17b3ce02" },
                { "my", "c1799db0bd3ece40732f6cb1fad619333a2c3e721691d40fdb66dc85ffb97f81bf21c21828ffcc12be1b4215f7f0dbd665f69ff2b0bb44dec05632f6b4d336d8" },
                { "nb-NO", "ea4d7f0ff2703045bc5a085469376d0ad2a4e54e16890405bb85714e1ccf9994fa3fab424bdde565472ed80ecaaa53350ac02b6ba06bc7cd589b7e77088e1d3d" },
                { "ne-NP", "d5a808b7cf9ebcf03e007aff78b593998801f4489388656c5d3d8b1443ad57ca08bcc258d3ee45064274a04d81f2b4b466986f30b6a0fbde6d5c95ced97f5cbc" },
                { "nl", "abb41ea10d9855437409895db23d6f51f73b859ecefc9bb5c03e1b12ce436a44ea81769f5ad6736ac432fc42ca1c9144c15ce8e7db0910fd7750d075016fbc5a" },
                { "nn-NO", "8f7a4e50eb0192409cfbb842d7e64f39e9b9e4501e2439f90a612cd583bacc39556aefe60a61c1a140c6905f801e0fa7b05e05cbbbb10629e0aba7765535493f" },
                { "oc", "6be985eb4c3c213f27b98db587c4b9806a576c04c20304b36672e5f699c5fae3936e3568cb87765860df2c7b29c5707027cd24c58946438f5c03b8eab12d591c" },
                { "pa-IN", "3451bde19c94f9c3894ef24afc2a8ed7465b1dc7bc8aabea67849d5f0abf83a629848a6ba25ad8c295abbaa652120c58039f03cef129e2152411d421d8bc8763" },
                { "pl", "dc9afe0d22acb39d72cfce701e4426a91201f31ca2011fa59a005d3a73b4fd489a149cc9e75f2172ff7b611cd19fbc275ae70f99d764233ae2c8eca73a65dcf8" },
                { "pt-BR", "ab654e17ab3c4a4bf80c76a593234691dbe536fe2b58972a85f7b7bd7dcb3ea6d8243b49e0bce404e491a1a6d2ca877a47e90df02536378f8135d66f276432fd" },
                { "pt-PT", "266d1dae0c3f92e0c9e2c7f974fba7b715e9e5135416ce78971aae700609bd46d670983aa8c122a61be4515868ced66b1dbf566577c878127218521c8d5c2a91" },
                { "rm", "5dc7ad42ec33b6ffddf342549b8f36f09bc82eebc90b4ce26eb04cdb672ae50f20208eca49ff73e8d356ccb5e39e3deba55b039491a8d9abcff1087bcb72bd65" },
                { "ro", "3d7d52156078500840686514e6264e2097cfc77bdf36cfe338d440bfadf9af17d080305c0f4c11dcd6c28af075417c19dcfe098eacc669e1a2ebc0207cd0cbb5" },
                { "ru", "9587046e3984cd9c321ea8fd505080cd1188901b17180cc3d7a5d640f44aed284c54bf7c0523fcee429025b4c6f0fdbf2742744c75c1836a6927324e4efc29a9" },
                { "sco", "4d12f71114031bafe1e06b21e43884b300046e0683596864c20529407e93401cc1211c79b45379ee186cd55626f709c7ffbe10a045e137c8e80344e247cd8db8" },
                { "si", "dacbde44d1151371d635a7b59f3635138f996fde16e9361d2ec416e3d5be8e1953ba0226cacb3a80c35b03600fb876fd8266257e80dc5460f0791b70850e47ca" },
                { "sk", "bb7487172ab0946371162dd09bc0f68c492f94e344a08a149ef1fb35c3be5bfa571212640751fe740e78cc87ab8634f29c972e3f79eb8e4e2beba9ab66b5b923" },
                { "sl", "0c11394d26411df5b782a5278ebd7da59bdb4bfc67763d4be26e5f7265ad80dae14c8238444a4b0160dc45cd298a6b9622666e6bee91d3cefdb5018767e02c10" },
                { "son", "b57870ab4edd4eb646f99a3f15140a4fc138f655a0926ea498ac0efc6936a0bd68316153eece8386e2d39bac8cfa2197db721648f8a81c71f8aefcbb6b1c5171" },
                { "sq", "4e5c047f3d54bdc7ec8af6ec333bb8c8a3ad01ab61a0d26d83ed296aec51a86a14f14f885e68e4c0a5d0ce95a4f6107024b521974a9b0b950b122dfa43c93fa8" },
                { "sr", "8691dcd933abf46852c2f85715d6d4f0411d50796a5baee6659789ee81487d647e14d6057a1c3bbf05feb57f98f7e4358ff851ab7466913ca619f65494d4023c" },
                { "sv-SE", "bc6f915468f59f09a4f87d1302324bf9a595bf8b56582d9e2660f3258ebc27840e5d0c17b6bc3d4684cc9068d0df57f4c5b36ddccf7d19c59bfb6aff94664d1f" },
                { "szl", "0e6783df0d2405ec20b111bc6e173a1feca4fb3b2bfd7fef0539b0f9054568867037196609f15117a4a07431f0e2c1f59d0aaba2d215b555d016db9ce42a9385" },
                { "ta", "8e9d918ed533bb6d1fb206f70a42f92e9d1c19caf8afc68cb1daa6a9933788b58c8c21493fc60bf384a88700f93620a55c72269686ed969e570e0615ca24f18d" },
                { "te", "7377deb0dcb7126a1d40075f1a8a0bdc4c5a5b48c31e3ee8b99fd593f976e7774a84398a2189258f761be1f202cddef6dfc63d7c08ca6677b2cdddba1d613e44" },
                { "th", "81449d1e4c9de3b7b63376d21ede4e9897be65c1801831750653522ffed388139f4d600ef0e7665c5c7bd0496ed0a8a353070481d1125029ddd5bd9114fc20dd" },
                { "tl", "f7d78dc5b36bd05f30702dbae49985ef8599daf39666f6f258bfaa9e0aac04e2d40027f14ce117e352dfc7e1517c96623cc0644afd8095b55059dc4664afb700" },
                { "tr", "71183ecb96209852140705ecaa3d3f5f203baf9989e78083f77b6ed21ec77faf57a0680854a9c439bc59a4de87e9c4726b0e12ac64c310dc4c31ea8c3880b731" },
                { "trs", "283e5ccef53bd09938f6688c83d348e2350c377bc45be5e8063e5722cffed3abf6412e22a4a4d24d664ce48ff8ca45aed67ba48a3d3c6cbafa8627b16cf73d68" },
                { "uk", "f7f7cbc7a21fafbde16e8188dd7deb9fc4b93e58815abc90bb32f942fb133b190ad5a491bd8ea76527209b547ee70b85cad9b95d58a6e5f8cf4b20727215c9c4" },
                { "ur", "07d5b3ba08c8d980f74c3889a4487e34b34f077bb1a2fb2195658fa62b9933079811e345620326436ba4e3fe3981049e19fb8180ecf5d3e2b78a5c492546eb40" },
                { "uz", "5e3c6944e87d9fe4ff0e9b5225ca56e3635c8f753a05763fafbac23d05f85b8d62ef7f65629b0ac25ce3d56491a6521bf58200de682fd3f2e05b6a09fb859f60" },
                { "vi", "5c68247599bd7f5afc621fc096ccb2173ea516db1b062e4e36946f60e25b7723587b2e1fb267e2bc43678c5e4d6c73a4660a72fa27fd1fb7fda3dc7a6641d3a4" },
                { "xh", "c1b3fd853cab848652af77353fb06f2f67a3123a1ece64ae4cee9954a281087e5d6b5c5310cdd96ba05bd1994b92817cedc97a7ffb4513934076fe93a2f1055e" },
                { "zh-CN", "896ab57a316d0c841eb75cb46390aacbcffcf0d0f69a144158c22493e5a0d0d5c38e0766569a9a4d84b935bd16904ea839842619c0463691b2c13669dba7de12" },
                { "zh-TW", "9a9bc135a2187dcedde9d3decca10c2a64936f450bdf0a2d4e4f1850b01207663dee0775d55e286614fd18ef447f114aa2a14cefced139256507eca48cef0aa4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "f43f8def73e39b0e2a852370e3c1a36efa2c5bf0c6646a11379de4ffd02d5ba2d6b02c87482b11cfb74d11a31fc3eb982a031a049722db8b9c8c8463b0c6c269" },
                { "af", "f9bb1b7f9ced918710dabcead1416f0f52d056d67afcf6438ac79b2002d917017fce83c009c97bc06623b9824ee3500973f84386e2cc5f7309a9bc5efa50a025" },
                { "an", "bce9b174cfa2ccd5b4cc7922c2a0962561af8472fbfdc88f15b95d5a150ce53e81b65d38b4bb42e426fccf2025e4ac484954b72e338188a47635099b4834aec7" },
                { "ar", "6e80e1e858103f3238076c7f15ec8d5b2da145f874f7845c9a7df364c145d11c9a7609376e671b535df74c3f78ed515c9ad3b8640659df071fd7db35546849f2" },
                { "ast", "b27889a3b69dd4604c46fccde8f48c70741b6def8855f11136283a9007b3beb32cedd205129404b7d3c3aa9e522cbb199bce09d07240fdff6f2e0408bc602398" },
                { "az", "f701bf040c0f0cccdc8a81486a7d952210bf8c4939be606cf82f8cecde9e20e79daeb787db7b1a7017e9e2890deefd8fa8079429fe3cb3271304bfbd1544356b" },
                { "be", "e716e88c26d9f4240ea383fc4bb6b5ca10b7e90b88125ab0abd61629d14d7f24d451bfbcb7238d9cff84dcdd68a095d058dd40acab64e4b3c2c37374da9fc977" },
                { "bg", "eded120e7e7eb86ab3e5e8997e7057df9d2fb28e844349d7ca3222c66b2ec61e41217423f46d2db6bdc43ce582898fca289a65bdf7dafb77ede24856c61061ec" },
                { "bn", "bacc9bc6c8ab491720204866ddbf8cd95377a0e3bc748ec4b3d028a5e6e8e592c72e95cea448d953885bb5b353a2bce515451f7f9ff320b0b7dc8f0de17729fe" },
                { "br", "ef362ea615f683bd85e2767d782f2c8df11c918894af8d05961af950cf7b3a01a417d6cb8e7854e96f104b2c52b6bd75d810fd701c554e6271dedb1f5e833d13" },
                { "bs", "dab3d9b84db7961b0e14fd97400a0c8ec0faccf4658f31a477c8fb845cf6e8cd8ea3e5380d23e4de6c63fa5720702ae28653a45b34c3690ab705b88a9d30cd37" },
                { "ca", "8006d787c44d20c40f662723e900f1e8758e745fbbddb24dfc3b2d72cfa8b7d9084918cb9edc8cc35a8c064817ddbb44b2c1a749db576789b280fff8f6d4552c" },
                { "cak", "604dcd9111a297222e3b812e56a2e0e0da265152796a74809d448c66ad5976894d8dd326853d5bbd197581c75bf7ea594bfe87f5d079c80c388c4b92f7e3c01f" },
                { "cs", "ea228e44524dc8810d35e5e6641ddaff7e95d837ee9bb4425cf4565d65a1be8147d401e4609795652f3c7229cc55c4c35f47edeb3eeb1259b53315ec3f86cbea" },
                { "cy", "d98efafd7a026ee77b6f618ef434e7f1a34318d4229861ba761311b676396ff32f65cb7834d227267e8da5b097f4947ee739bb0e9eca01e37397e1a85b47e6b1" },
                { "da", "8162d01d2d39002926cfebce2e9b733f61b6de430e22f0f267d8a48368d2dbe47740c7ae9ffebec57d9b116d6567963d5350d02bac336d3aa650928478e880ef" },
                { "de", "81f363fb26997ba6f2de5915572b4ec3d92fb9572d2b016662ff755ddb9b01fecddf7a78a2d76801a52e5e059be489ababa5b527038aca0458dfb159d3caa594" },
                { "dsb", "c52051fba2145b829355aeed4d1aa7150df153cfd3b081cd384380878abe627a589b0fdf190f1830a980fa0d1122282a3de4131d608e5bc6455e42e7e8ffb64e" },
                { "el", "c3c4678a4560e8679b37d2a06f45f31e4bb30a19dff48585db89e7468ace107152d02f0c5904d2d584d6237b8c6fe8c10b273db708afc0f5c4536e3d546e015c" },
                { "en-CA", "c87ad4d9be163436a7ffcf310b10028a8ee9b26e73be07ec4941a66b3235f6f677c3609fe59cc155bf820a784486cfd87b9975aff0e0279c3ea25f022fb7425c" },
                { "en-GB", "f4f7c261ab648a0b839c679b881e0dfc2a7dabe43b2e71aaed04428c922937cf550bac1dea1a850795540ae2407af61abfd8e274eec1b1d25dadddc3b06be597" },
                { "en-US", "89493cd8ac34fbff09646b90b8a776f2c969c41cc4d9df1c625dbf2c376a548c234dead8e795e36a1c755bdc83cf4f7940732db843e4e167df5ecd09c9231846" },
                { "eo", "c5654fd52a609707ee5e0c91039d9ab6fb7b2d30bc4bc6470d120c1caa43677903675198cc87f41b8ff4a62b6d65dd8873538a8ce293a1c6cc740c7d6058da67" },
                { "es-AR", "0ff0b6905098f4e51ffe43bbb674ab66ee7696105ce108dfa8255fee61cc045e4a3027235e343ea537888bee902834779d3d9bae287c1e0d3241391fb366aaa0" },
                { "es-CL", "600db913efc189b6ab5109f109f11e9cdaff3678b5f5d265b9a80bed594ded058d4d003a48c18138b329a705a8ef88356c1d74e9bd86e249a5f2d2f954ec3971" },
                { "es-ES", "a46c55fdc00b7226cf81be59dea7c82be45e16866bc0bb97732c3b087187846b4ac626f4ea3e7fdab44ed081ca74cc28e7a162fe5f8a269695a8fb6ab3494822" },
                { "es-MX", "976335d595f6b7ec239b89f9f0bfb84a41ef5ba5c1775c79390a4d3d0945ab5ce4ed81fc7146de8b134c8ae7a0aeeb754b847ec6cb0e954a0e7d4fc7330175d8" },
                { "et", "d6075a63f867d16871bcf0c9d4d9e75cdd0a42016d9c5dba1c25244793a799491bdf04bb6b3f39de6b03a714ccedb7903da10d3eba3ccb4de828c63bb4d02ca5" },
                { "eu", "14d0364db51448f8cc8e3b0d445a0285887464a1ccb27a0262950b440d8cc02ae42d01a29f6d8ef1c33bf692540d7cc58f1e16d6a5157cc98ba436ab59782c5a" },
                { "fa", "08ea55b4218fab3e17b020e0bf6fd4dbdfc2378e5568f6b428459197bd6c3dba9a1528405bb15cd7b77bf18c58414378d20d8afdf7fe29daff6373206903b667" },
                { "ff", "8d9f00787e95580a6c13910374577f068137bafb0a136bcd347f11e9c7db915750f0701f76ff0a741790c905e7acb3eb33ba0062cfbb18149723c85240fbe6c8" },
                { "fi", "91624efa695ce05c7dcd6288f65dabb28b2cbfd80d7bf799516cfe548cb93413a7adee988e0439db7c0f24988dc4b95930ac8ad86cd5899c2289411af42b055a" },
                { "fr", "d8db2e5484823b4d3bd6240b003007c094b59f30e79daae7e6e604742e6f1aa53a07984f1fcc7f459576bad37069b30e164336bb259d71c21a62c859e72ad0a2" },
                { "fy-NL", "849c95462b482b26f096ed88fac6f2f00c8fd043c4c22088821520c8e970ebd49302ddc4ba21128df44fcdb194382896c81321a844b0b440626d53daf3f0fd8a" },
                { "ga-IE", "f11cd3b932f102a65eb32a350b836c17c482c2599ba1240346edec72f93369af5b3dfb612c04c21526b18d0363c7e10b4709ee348527b1df0e79f321cd51c907" },
                { "gd", "ca714f9c6a986b2bd5d9b8e4f881fd2c052dc562242641351a85d2a669aceed1519e3b61c213c9d8d6deb1fe7d0be27487afe430acfa894ca5d49d6ef0c4eea4" },
                { "gl", "debb18882843a6f049b03407dee087e39ef51e90692eef2f7be7ce2dafda9e9c1a5ad375a9cd65a3a4031361ee6e57c6e60a7572f39fbd71cd21dfd516f56260" },
                { "gn", "94d0b9a103db4bb58198b895424830607f14fcc3a260fdc191242e55c4efc092281fff26f9adce7cccdf24a5a1aa64bf141f7c9a1704bb0b7bf3386e9b082187" },
                { "gu-IN", "c0581a80e62d033cd16a0a6c96d0db5ccfedf970f9d004fe1a21724fffebeb43f56ee1e04aa0ad326134d63a2c1c1e180c960568d0f1c078ed425173ae1408c5" },
                { "he", "d92170c84924c80fbab41cbb927004b31aed074736aa28fa9ffe52eecb1beb30b8b393842bca8a40b3fd4a63dde7fe5d5b1014c676c334900e6beaff9010669d" },
                { "hi-IN", "ce0798eee443ade18de27900032eb6e5c667465f9082d64eab598aa6fa75a40cd2b7291e4232f1ccc0d0b1263845f2cacb6e35808933460867d8fbe09c3a0115" },
                { "hr", "005e0c23a7716a27f4828773336b4d1749293fdf6912b7ccd2892db731dd7e21de13735a8058686f211e36d4213cb8d4be0a96bc91d60d14276791f33d056afe" },
                { "hsb", "c1d9f23d28f13f92202cc785e2895cc1f44396b3bafde69489b632d62a7a841387f1fd5027c0d7b8f6c76572fd2b4d6c67aa1f07759fefa0a135c1e13d6f6f4b" },
                { "hu", "4f61f1140630e6149ac3f1de70ee2f96879de68a10802063dee88d8dcf7c3af5a4d287c25ca60988e4980836ab3b287125aae1d354ee6232c27ad5cae6798d6e" },
                { "hy-AM", "8bdc5868e758eb6fb5663f2063f293a00b145cf947ae236479e08f798dbb2725d2c6ab74c10dc9d5799b76484c9a7c8dfbe60069852f1a3e24f4362fdd08e880" },
                { "ia", "95e9f613ad85b3be0ff61205c1fbf2a8609feb8f5ddaaed433d942b470b705147437ca480c64756d6d4b03c80f35f8d0207264a49a85657d6a4c877c1fd00d64" },
                { "id", "cfe3fc986bdb536c523bb4fab0d17a2e55d45e7d4c91be1b6eaac290453cce82b4f96226ff4174d0e1c35e842942fe8ee8d6939e0c4df05ea626b1acb386e6ce" },
                { "is", "3da87bed11236edefdc813169760511c75892908c5bbb18917ce6a8d11a1470a93aeb3c20c196c39785a7d4ad5256c207eb2bd29f52f6a8c4ce86a7e1b1bdc1b" },
                { "it", "a89c5008dc4bdbccd323ff9f5e28bddf2c336018154c126476b74760b2140f69ef67e1092b11d1fe73e53731fb1c4bd3bab610e0f47a2a4a607237150c72063d" },
                { "ja", "5f086310e96d70cf4a3c75e3300c3e43c0922a5cef50183b04b8eb891479f22f23b3bf9960c89dd97b09b75fd24951e4a4397a48adb12e1ef27fed2f82e8bf7b" },
                { "ka", "4d2f397e1f69a303c449fb6ba0903f24aa02f812fbfaf357d43ba6bac0dc05ece6b520137f69a0c9b49d91563238c759c1504905a9dac5e26f2b616d0a2944bb" },
                { "kab", "abe67f921a1756b78135e15dbed9cf20213b6a03d38a735efa8277a931d49add1dee38d730c1e8bbbba3672d6237bb694f77226b9fb3437e9b83a608aae397fe" },
                { "kk", "ecf9152649b5f4bccd81dee5b7a63a29ace3bf577dbcedddca7d278165b4865596704f32454f56be1104d0f077eb62e1503eadaf85dadea985242105211f8353" },
                { "km", "ec8047a5a6f300c2c9f1e8d25892f1210e4624378614e1d224621d44d9f38e460a7497e05e957f5dd6dc78ae80fd55d48d5e84c0a4c37f5936978476d689678e" },
                { "kn", "5d9a34b26c735f4ece8fcb65d670c6b89bb5451b15ea800529c444d89994832b37d2d93480c3d2b9de0b6afa58c063d0f6de245add03b61cd23bd2de0f995f28" },
                { "ko", "7d4a6215384212501101284b64d728aac05239da49bb57b6be09c59c35eb38c3e4f079b7be2d3e3a40e55353a6287ab6022e9cb63c5878f87ee5c2821b606d41" },
                { "lij", "f45fdb545050f2b7b4538f6d2bae943bace12ca2ffbd64bcc83c9a16da1ce98ab2c1c8237ffbedbf1fde4618bb65401dac2a8c069e388c5060f82890b542fe08" },
                { "lt", "f26ba229fd0a1c7edf78af0f04657ffe1fe3217a88fedb7ef5e6120d14bd36ceae1048d2f661e3eefc982fd58bc4f2e2b6cb3277851e347053d4532e82d88cd6" },
                { "lv", "3be49cd67d2d95acff6a47d439b764375ecb91357edb9d77df212884d87d37968928c28a442b82b10868ab0e9a3d201e3f90052e753bbd59f28390b69733d139" },
                { "mk", "3c29e9ba076dd9b19684d504d503849baf57a63f4ad3c39ea81261c62f8cddc0969ad90ecd4640c4c4b0572e8320eae0e6a3d99047b1c0b7e188e405dbaa77d5" },
                { "mr", "215e5cb5834ee9baeb77dd29026b8fd39fb37f088906189b33fc7b7da1a409540d66d6ecc1dda6f72ceafceb3ecb3c57f8c15a50a5917d92edf8cc676510877f" },
                { "ms", "3dcd472df6b94f6221b2e36c33ad3532496d1f2325cb94cc1217167c751e26b174d44a00f098d68f9c43794c189cba6d014d339d327d33646659102c6ff11bfa" },
                { "my", "ac9aa0faaab362ad65e2ca2d61c308e829f60fa462d6b96f448fe234ceab7750dcb376e4b85f35bbe40c36a0065e359fc11874e8cf5434deb3f528542c9a6a53" },
                { "nb-NO", "0da9620907edbb0c3fbe6d3ff5e43879536632b483da117f5c99a62a045e2efde8e45fdaaf4b96ac15783b1010bbdffe921cc76b747c5d6888f7111621b096af" },
                { "ne-NP", "80ec659e76a047a50b4ad8db4ffa7f421ef67b1756ade5aa3e412fbe2947dd7e7bea1428bb8bca2c80afd8a961ad533878a1a0edf2809fb6caf501499bd75b1a" },
                { "nl", "57fb90de14f79ad8d9ba681786cb2b80b6da78e1acf04cdee5746a6751450d1eafcd0cc5a5042838daa2ca43528ae9bc9f1e4686bf07ba899c7dcfe1c1473cda" },
                { "nn-NO", "f69c8567402fc2f4047c06c85c2d9be38006fdae29ec8ef6e095300ef183300481e7c601d857fa48cb91b9143be1ae1d0404142227957e1e86064db8bc99d938" },
                { "oc", "c57716290460eebc7dbd9131395546f30def1fb13dcb37e0ab7adf0bf30a6a1dcf8147c7c9f198ee150ccb11ad945c3fa3e15d3321d443f2e039f3bb0625b116" },
                { "pa-IN", "21937de13bcc1f05240667099669e39dde2b348745987c52a94ca6eb726e2eeee921a7ccd09568f038b0002b0035ba9889f25d96ed8198eb0dfe5a27ae79cb95" },
                { "pl", "d25a9b94a72ec3300abe1498565e49a46245fd5020fc2ccdeebbf2b4305e06454b4449905abf668a478734b64e79a414af2ebfbdce5aa3da5d36fcacc16cd38f" },
                { "pt-BR", "c256b1684feb9f19e8999606893921bbef679553bdb4617049b74638ccd6b1bca8c8941b94b6b293d0b5e40148e35f2fce674a933586dece60c726135c327274" },
                { "pt-PT", "fd73d78a98b6e2bbaae91136c421eacac290d01cfb61b9050a0a6f22783a1ec447cd4b51e2922172d0a63add097734886efeee24e03750eea1148f155c5493a8" },
                { "rm", "5125347045a69931b0188791f77058ccd781cb25b25cfb85c26e05a37584a2e804e1670b91857cc4655cb644f7db1e2064e159ef427101f335d986042a1d29b9" },
                { "ro", "49b27788737dea95e598e2250ad83a0a61b6d45d9c918cce357e60189f4f139dbafab6c466db6be87487ad53ee181aa0b64deb7946ca69be5048a44b0853e2b3" },
                { "ru", "568b6af23d9e51074f578bfc8447f48de1988f9ea73d0fc6804ea61cf28e5f7cf21cf392732501e36c78bf9fb872e5044a4b3b5b12c94bba6effb18970f4e454" },
                { "sco", "e497c3b569a20b295f4cc83be2fde39672da0e0d4da77d45905a2db1264eb447af0433058a141458b4b6054e1aa769dcfb05cd0d95c93d4cb75092c209fa3396" },
                { "si", "4ee8d4589673207b4a274da5ff680801e00e92a74b1aa8ed01e1db462841ef18b0ed40b266b2d861ddd721b8411097185dc3c0141db22fdb966f3f5188b67265" },
                { "sk", "6e0327cff4017395356173ea044646afcfe3c64d984f8bc23d82764a91597a283bcb41ef8f816eef02002f29d9c6e7d8cd3b1e3f4164ff32d7ba5a26182b390f" },
                { "sl", "e0c87a49385657c9723c862c5ed3af2c5f38ee10dd3817d6df420a1a3b08633c89653dc96aa214426aaab248aeb9ce4e288995b38df6be9e0393659368afa1f6" },
                { "son", "77ff4e4b76f598dcc073d84b10ab21205b2c6af1aa7c3c61b1457e38a9eb559bd126691730f5d911a277dbb6a41e02878f7a9bb99a8ad4a935cdc6078fbae33c" },
                { "sq", "624834591c312134ad23b8977eede25b49610fcb1b50688d413128d014a65b0ed18962ab099f6cb9fbb52748767b58f7f470b7af87ef1a337a74d0f86f687a97" },
                { "sr", "7285aca6c75efcb27acaa1c6953933370049e5996e6b98c1181d406c2506c33420e6a0c41102505d52dc8191dcf1935892dd8adf90fb44de59573f0207ccb4e4" },
                { "sv-SE", "e071ee1044b038dfcbc297a91228d0a6d52197126270a271e15debcc8b4bbfd34efda9f3db1b40a4f93aa095aec9c91a223ed1aaf1cf3a79af411361cf642e31" },
                { "szl", "d074f52ab1ee66c2de53ecc12ccf1b93457f4171229ce560ab24b311afbb13e05061c8c635f67a41f3a9a8119cda4340757a7954befb133dda893def7e51a183" },
                { "ta", "ddcec7c0709cdb7dc58108e4862f930ef6e11cd5dc2a0641a688dff987177feb8ae7197cddea1f77778a6deab6074ea01b6b349fb066ff58295fc380b1b1f61a" },
                { "te", "c38b45cfff7c1eecdc54d1bbc3b634c7f642a08620c8e2499d55c2c3b914fc66015195ad9a9f2b29841c70ec33c0eb143deabddb95791249556bb91f693b40c1" },
                { "th", "c99b880a370ff8f4b1c9ee449869a791dd9260d93d7502337eeaa18bcd8fa32bc3a4e448df663f9c6ed002d50f5ae4a652665631fad0d8769e8f57e3cc0ec382" },
                { "tl", "7f460d451d40075030c2960d08fd0002aa07e0356c69780be94101259d27921392aaaf52bf374845116fa3326b061124cb794a2de178d89c391606ba6d2643e9" },
                { "tr", "7db63fb52a7fbe7f670e2f6c6279027907df19bf00a4f3f2145a7cb6897b7570aca066f70264efeb4d314a6cb634a0551139bf7e06cf1d63176ef9c18236a43d" },
                { "trs", "b31693e55e66ae9e7ffc349ed27a5505e3643bd00aa22ba1b8bbdeb8320d45e756bc4f1a18bd3c4a75ce1342c80b8ce8461fb4c0b9fda8adcbcbd590e53ff542" },
                { "uk", "640dce6694a67689afbd0a5c9cfe534b923b2d7cfc7f38a0c849d2396575cd8b2deeec769d09ec452c915dc65be508a0a0374b6b9aee4f6e925a62102cc6924d" },
                { "ur", "43dc65b2aa1f77fc38ee1577d9ca6fda0c65602381c4faefd2f17b7b839cf91aec96c6dbda0e3011c0bcfc246dd627b017200557271f1c2186dbbbd349498220" },
                { "uz", "8d3e775bdafa226eddcd0a997822173019418f7824004411b9369a2f77885d892989179729300d58a84d7fcd6c9f0bda31a36559f447c7694b67d24dd3159240" },
                { "vi", "db453c0f471c9857c30337794d7216d4cb0845b902e06dba4596d72203b1b193188b75e917633ab1e75f48526ccfd26c3ebb5e34dd5c5ed3b37fac512c25c7cc" },
                { "xh", "8546db87c7d0d7a6f806d58b80f78e8f1440f15e2ba6a1f3ee36196948042f4d146be053e5b7d35ce372f105d5c74410e6ef271f1df101bcfda73350d9cef118" },
                { "zh-CN", "0da3595a90830db404f5006653c8e0797b9bdef3e4fe3d60c9c68308b3024d53a5e03ae86c997f5314bf0d83f4e882ead3674bba0a52fe3439c9389e4881f5c0" },
                { "zh-TW", "952e783dad6d982ae58859935ceaa520ed861554b1e32acc8ba6977f145c17075b8adb1074711ff5bd29d2ccb6ddc47b3f43ca457a1c9f0c6499563dd445e164" }
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
            const string knownVersion = "91.10.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
    } // class
} // namespace
