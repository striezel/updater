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
        private const string currentVersion = "141.0b9";


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
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4101482744f8a39e1bd951f9f73650e61ea5efecf487afe39e48191239da5642ceb00993495c08142a31fc17c5137b3e6123090e62312e3beea62295953840b6" },
                { "af", "2bf4edb96415218a89e32beea554c3dbc12438b89b88209bab9338f3ed3cb969f6a688a9863e53f81ff4fb0a78e1350f47910cbed8ba5249c902ae907b5f2ca4" },
                { "an", "c23cf2c8fb7562b305433886fdbfd7dc25bf05c4a5529fccdc445b63e78d93d9acace091fa8e3eeff5a1fb4fc97f168e5ab1bf364ef2399f0f6fe5c50fd6d70d" },
                { "ar", "82840c97d1881091e6a146c51086fe3812022b93efcc594b59703242cb307618d2daa5c0b7aa9d1ec07feb791330a30578fc03e86d069cfcf9d483c05ae9e660" },
                { "ast", "2d38ac57edaac0ed678dbea6f31c0bd783c2fc22c703d225e9e1926c8be063cf2c47c31311fc858281d7bb317b1601baf868ed5fba796f8a804ed42912021a3c" },
                { "az", "5ede3a0904bc3818c0829c5bb7fe32e1bf2a60f6158f9c31de6ab7d6c7dee283b67c1331f3a23d466d4b08c11e57a7b0868a43612d7e3d8c15ccbcb42aeb18f8" },
                { "be", "502dd003935f470bb7e94a67252de3259cd397abdea1826fa6d2f454ac1d30a6e5919b2795b50c800b36d5d24bdc008c90a3d82e4741e3dcfd474efbfa72591f" },
                { "bg", "26a6868ad33faaee1a75dbcea31022e7d6384a10c4e2cf871589d61d6281825f319b82d4ea1452ecfc2b430f1cab8c2df945082a71bb00e7fe98e956d9f26ddd" },
                { "bn", "0dca5da0c78edf6f7787ba4493bf6a249aa8ebf36ae82d1e70a344e40d31759b0b02bcda33785a8579f2bf9eb185418ba931b09f42949ddfb93af63e8434147f" },
                { "br", "dad2562b1f2472603f43156d79ae5fcdfeab439842ac8aa261969dfad2178a5a9e024bac0887de06cc8c2ee157f9b3fbbb4aaba0723654161356e5d00c17a55e" },
                { "bs", "fe93ec75c7c0127cfb108b7a0409691ab7d64bcf4b51fb2d743fed822c86d4ca7547ff234215a6303c22f9f006489d3cc350329b25cea95b5bf8abb044c2d323" },
                { "ca", "f91503f8c1c57dfa4fe4a710301a52337f94e011f4973de99cbda41be8b167bb8fb3a313f2b8cac4dcfd5a4bf55794991fa1a8c9bfad05990fc5302a4f55d736" },
                { "cak", "0663abdc22405b7bd35b572d3d5c053af63bcd7f878dcd04dcda437b681af6b7b53d01e8f34107551b3e863af7d4e89d8177f827fdabdf1f4039e872ceb71c68" },
                { "cs", "6b6365ba814dd47abefd00ef648aef6975bd6a818f731374e50694d9b64d9a510405e6810c245224e318232aa9e6e2a0dd9b5a7cefb2acd4cb97023aabd5f771" },
                { "cy", "d1f124a841d9e2eb5b1e8ee9813e77d8877335b53cd8d495d03584593f4d2b4a7c6f97fe62466db48f804f58cc693622430ca95e76df3faf4eb014b2330ecd9e" },
                { "da", "fb0ddf43e9b5e102eca15a965dd22125f1b6c66f9b81a39eb7cda0898d54b3880edaf776d6c8e2c59b5319ec2f3eda3394644e7e0764f2cf4d2c01b07ec83772" },
                { "de", "4af67239438fedfb5e01c79f929a1482db8beb94557415179f94d1f24d1f020511fb0848054b303816c450394b4a52cffbad3185b306477196ff7d90fa255b9a" },
                { "dsb", "b0065235175b4c4c064bcb6ed8fa95f3a1656784d27e3ba00fb0488eefe63a5fac41d6ecb5b91020660d2d0792f50c0658e542d0e8da9b94622046a7494f9a17" },
                { "el", "cdf7f5ab82a6dfb24bdd1db24a84e59b35ee0757401349b4d8fa5283aedd897c367744614641181c9ac57289e5d40ff0c5a319579523682ebb9eaa62007612b4" },
                { "en-CA", "c75a7206db299f19a4cbcd0c67c03a762faa86d64ea4c90c84f65ade6465a36174303d066a49cc86c2ebd62139798993709181d9dba7666198a4f6532f33d1b3" },
                { "en-GB", "cfd56766510736d8df1691b12d95e21b1f679e01316e50a67cac5df1d438014b450c31e18f8030ad378f9622b4b6f730c2563260f882844cf8dff11c8b3a5c3b" },
                { "en-US", "8f332b089edda44404d994596007781ab9ca8541a3a54c17fc9b4c207c9b5382aa5841f152cc39be309a7762019c6217cba970ebcf57f89d3f38d8fba40e3dee" },
                { "eo", "fc28901f176770ad68ba74390d51d6300d955432055b8b32e19b0d75835663be92d0e0aa72e4b79a88618bda89f501ca90b09ce2736951eba9aca5524c9f6388" },
                { "es-AR", "86c69399e466f89bdf1f5cf3fef556d6dd8ed04e06a7cdf1938e15d6dff9551e0e1eb41f2004228e3a01b2fd16bc93a4a6e5998b5ff504db3288799c2d618f69" },
                { "es-CL", "70c2d351c473ebb0ad1df874a23e941278e83f59e2334d92c8f778aa49215c26d2ae0a0c84b6c1b14928356703d4b2277a19d5337ad0796b0bfd73a8f9072b26" },
                { "es-ES", "62a4e9aeb77522ae42c7706637b5f87159ccfc885aa4e0c55a590b2ab23cea792e8e1ea334abd473b84c580f898392e42277d7addb0c700deb1f75702eed7ef9" },
                { "es-MX", "4e0e1ea7f75952c753699de7f0c9a363d5e0b943a9ab943458cc60e96c21f60675231c5a81988886900cf110dda35619338ccf2f8b0782f2e295950a7eb454dc" },
                { "et", "2571d65a3ba06ebd53640fd9858c45916e2f03d27908227d02d2df4395a244b623210dca7698fa3e3440ec14f9fc306a3f790ef9d512e31ff12f2d90b0e5fa2b" },
                { "eu", "9cc5ee29b7136f5cc0b2b7519aa0b9524f9a12a8cdf9a691b80a936400b62392243d3cf29bf16b52fd2780ed338881e6ed3f1a3d12301f07c59590567c1eb30a" },
                { "fa", "7939ef887e7ebe9f46392a4846020f18ea288ca6338c8d84ba6bd017c119b057ddd107904681cf7403c5ce2a50d24df7aed82c20a2182086f3519c9f334d62ed" },
                { "ff", "89e09bd8cb4be8db14291121f5fd21ebc5eac65623a1b21ab83ac72faeffd820a35ee655b855d50bfc2f20178113049872896436656869ab1341af2a6dc77b08" },
                { "fi", "d2ad54eaebaf908964f743c96ffeb79da990ce7fdaf76ae716cc4aff87b548eba5865f0b7633b5ce2c77be8617acad87bf8a68994e964c98815cbc85f4deae88" },
                { "fr", "7f663cd85ab3d5b1844620b3158ea831f120b355892a4bc3be2eb5a51f4ce461c2c95a41334f23b8898a0da5e508d830a4c9a985a68d6545cecc76abb057d59d" },
                { "fur", "7c10ed961814fd38c518c849e54dc6d08a3e8ddf0b561208427a906ec8c434d94b3e0a5ed037bdf59c71595a2c12a3375769664545dceca7e2eed25a82b05f3c" },
                { "fy-NL", "190c147ddd0da8a14482b34ab960b66e81d9c531e367a276ccd81d9546c93937e24d908e916842548f4403c53155d58d16b43413a0613be040e4e9b378abc02c" },
                { "ga-IE", "99a8b75e8a7de763bb1c846a70a42d760d5cb8b5b091bf1ae41001fdb4450f3d06a4c97dfce101c74ffe8b461fba025d451e0f6aea3e1172d7f91afa98bf56cf" },
                { "gd", "cb51f91e74f718bfc3f14cabcd299dea94ecd708ac53a599f75f7135516bffd0265e51292fa2bce68becf6fb6d33a014d166fb0c7d94fa287c3ef0b020453dac" },
                { "gl", "7d4c529b15cacecec523c8080bd453edf2e7e58ba86a70b1020b1e377eaca8da789757ccf6c87ce076c6075b5ae7ed5c4296df9c17b33d33b22bd879d1df29bd" },
                { "gn", "530d709317315dcd6cfdbf65e89585eb2376022df8dee42c694f049bef95ab3f8ecd0030bd356b8e571f3964b1c1f6e5d94f110d34180c71433a211c6dee19d9" },
                { "gu-IN", "f368f96e06b1b32796a2d96d6344f7309892889ea6ddc077df75f2b98f69a2dfb4d03a0340cd67c4944d36901839af1c4e7d1b7bcefde9a45ce17780982fff35" },
                { "he", "d9dade34f01b2f67464d215daec3775b39cc9df88c72e3073ec4519c1fa7e6b0bed10b54bad78a5541e7becbafe1edaac772a77ae498ffb23e324092aad3e3ed" },
                { "hi-IN", "4946ff920af06565ecf8d347b0e898c377a72e953652c45f58d390f6feb9ee7dcaa2674066dbcc223ef03c6d772d5e95eb7b5caf948caf78259bc3600e278468" },
                { "hr", "3bf0b3d3fb65ca4f4054e1fde26e80bd5db67359e715544a1ed6cd52bcbeca7bf9f6205bca1de61a9d5d0dcec504f99e9b0ad336cd628e5cf2b76c4182b863c6" },
                { "hsb", "2a2a353fb2b9787e9fac11e468b38ca0a4f80fdaa6cab46814365ded442118c29205f31fc8e1e0a91426fe7c4953eb283ee1f7adb7587de8a021e74efc47b918" },
                { "hu", "dcfd2a16777999fb18588a371ef4caba00985121d92076888a75ebbc8aad6db8a12ad7481a2ae207363d0c55c2015c283e98a9693265cf058bce372572dfed0e" },
                { "hy-AM", "64268c607e602a167a3350afe55fc7618b17ba82199d2a14ed019671a8b03e905d2dfabb7cff192b89e527bcd489913c0e7aa828c1f4ed94e9644f4bd2c9feac" },
                { "ia", "f8b7ee9f4898fc42d4734728c0d11e2a33828b009a81d54885d36c731463433cf78a43c04aa2b07ba2547586bbce7d2bdf471dc3846416ba651d685417c822b2" },
                { "id", "82a5a02c73409ea96abffd04b91e3164ad29785efb42b4ea0f6c0d5d76df5dafc61532345a479d93701db9ed79e99565476726207c860c486f48a66eca6c5b6d" },
                { "is", "fa5e846ceff48a8b58b47760785aa67069d2e873bd6eb4e2d856abf4560eda7c346abf412aec9af51f2f90daf09d1a0cdfb0a03eb9dafdf60b7e6a43db486958" },
                { "it", "940adf37ef0f15d0e949a59a5f948477a9bbd9b8864408eabb95382c6fd71769d7d5fd2a3d708ebcdfc4bf9682035d9495e19a3df24ba9cd5ade1e9bde636909" },
                { "ja", "9c4ccf21ac2410cbf57b2dcff2df7f7f10b883cd0198f7830b2d610c3ba2ac3f54b5dd15bfc37d7e96b2a186f342319497ed087dae567e7585407f0e1330884d" },
                { "ka", "538a16dea9fc5e4ca73029a55b836cbd1b9a6ab1c05345365e2d61cef802fc9769c972e46a38130f3d48606e0b1f6885a32f609612de8f6c6fddf2c24d4e3246" },
                { "kab", "ba96d90ee879a18f997da6834dadd980355968247f6c3511f99c9dd5e6fabf3c3590fc94365ef4d608902fe1c83b00850d11e5f193d8ea7a5aca20c5d1f018b2" },
                { "kk", "550831d285cdd204205bb236c7f130ddd1819d96aa5da9dd8c52ecca4b398246468fa73b638e78cc56df14aea6ca545b10c35aebfe672f5e97e2937eca60035d" },
                { "km", "eab51b6c0d33c4b73ff1cbd9e9bebbde3c648680148218c282c0862b7c8ec5c3f58e67d6f4214d8d227b7011e3faf51f9c78b9cc4efadee5c28a76b07187d497" },
                { "kn", "5fad49610fa3b2feaa42211c75e1111e44f905095c0d6c41fbb4631d37847d2ffca2dde26b1f385977663f02873759f97f380b3257b6dec22b77ba31ad8e6ed1" },
                { "ko", "e1fa2362704012e6a655083aa8b9c81b40ea563c6dd2b4b97c4edd898b243ddbe6e1cadce5c0bcd8bffe5d191ff7a1391476529b98a1e70f384ec6652a8ba2d9" },
                { "lij", "c8be5c056e04376b17f28ff774be5ea6bea6fbbe4e031e34f93ca683fa1bea2c9cde02dbd96ca57468f990d73a68cd9106e010d9c653207d282d1d36b26d06a4" },
                { "lt", "ce1f058385f9657f477960ab9307f1ee20b52bdf234ee9af118006f9b74bf2a508519901b6f282f1dac521e23849294e1b6995d1a6f61eed14e60eea699f1c7d" },
                { "lv", "323cc631008a1fb5218279def258045c7933106867c58ad15af487f816837822c924aaf3a3939df50a928626dcfea4ea4c2d65055bbd52c7c9747a4d16060cbb" },
                { "mk", "79840438fa78d76889797a38ba427139b011f7b3b350c65702fefd269b7b3ec0d4441cbd0dc9e52f90fd8dd2efd64d3cbf0a9014b8c5aba39af337431060ac56" },
                { "mr", "ea8f20878cbd845e53b31e81d37ee77d3bdebe8562a5ea284618f429cd006080c1b1f1df1a3e8d812c848c806553a67efe9f80e9ed63387833c544722ab35130" },
                { "ms", "55a0ed65ff1238cad3af8fb52b9179d50621ef767dea6bb331b1abc87d5699741e715a1dd31be191284dc95d8af348c685c86f596a5477d2ba80069338d7247a" },
                { "my", "15cdff14f031bbe049f83c24077e22d0b51aedfd43f804a2e0a85fd0b6723eaa4b7d702261d165578c3169bd115367a276a72fc91eabbea50bce76b1a3eceb49" },
                { "nb-NO", "5a59bf9094e4d718e9012e47c5aebbd4e33d4faa2ddaef3029fc86b2e37b632aa823d4555fedb8245aee3acb716484ae416c36b55083371e736539670932a175" },
                { "ne-NP", "780bbbeff28bd4860dd26c76c89a4a2311c2bd6506d3c373e33947d0e859a09d6a42aeffc576ae390b36a6cd68a135d57b4f7e64dba4b99530c610fc1785ccda" },
                { "nl", "6c6140ed30976bfe159b4e443eb35f42f593d2dcb33acf8109db816042bd4f8a623b66fdb9c11c1b55c9343ba8ade837d9b8ac2cc46c2a983b6c3440ba68562e" },
                { "nn-NO", "b9f9260c32d35b5baeec3aaa1fd8f20c648bd60993ad37f080df3ee842af5f84f910243fe8e488bd12305871a42ac94a00061c4de6fe5cbfc2c6683a472a1410" },
                { "oc", "2b048b8485149885748c79a7497cc7dcd9c1d59f22d16cfe33fe8ef8e8e8dce6d84099cb8a61370a904d36e4a4b183256fd571f8f6b1f157c43bc635f2dc8ef2" },
                { "pa-IN", "b03e0c5095127598cb72e6bff496cbc4964572a7d2ba5b93c8a763772c027262f7123b292e359ef63650cdfd2bfbe41e4da6242bdd082a6be1c7dc07e4ca81bc" },
                { "pl", "ba5d88c374e50b36de936b4bd0e99660f7fbcf8320fd859fb1d89e65acfdba1f4cf4b558671c44ec1a6ff771bba4feda933b74db7bc6ade5a595a15756856764" },
                { "pt-BR", "a2dd66cbd0904eeb1d40c411612645573dbb2aef276b732bdae09d9f356bab85704f82e5c91b12e33227827d93d3728ddd9ea0f536439daad3f6cde915432d45" },
                { "pt-PT", "08a690e7cb143a3d429ac89c0f5d5f789fe4d84bc72ac1b33a87817094ca95744fe065db7bdbb0abdbaae37211285d4cb6aa23fc629cd6229341d493de5dd451" },
                { "rm", "092db2b675e0d2f31343dadb5654a0ead3f84636499f9d9ac30ebaeb134adbcbad87ed02104b2b57ee242dbaafd4f571fec2c65a2434b4f05abbb1048d6a9f8a" },
                { "ro", "a049f81b4b1b6b17d3a95da34a9dbff4b231c58ad135a3a88d095f1dc80797a81d011f6e7253cb009d8ae22fb3ca7821ff8979a574c1f43d3e6fd29cb1281f11" },
                { "ru", "ef74255f02bf3d28f7ed7f01134c7b2dee661f14149409bfcd943c7440d70c03168547b9233ef78b7a4369ebd9b8bfc6f38be4afb3aea1b80a3a3beb20c34406" },
                { "sat", "ba09861546006367e0d4f27c34021bbd0d27b1b92c33986e9075367cf35e036dedafce5a897a801a4faeb4569ff7b1218349528a97c333df49e5928b2c37cb0c" },
                { "sc", "177f42df9702cf0e41c639d0525462e0e1b718118573b4b2d25f1bccb7f537c7148eb13e21a744a0130d52cefbe2e1dec85e0d7a435f2f5d6b2b27cf85b31476" },
                { "sco", "8860d6669075889c9f99c907c71db5a266cfe715978c8717c0cd0c7c121f62160c161ed56e2ec1ac04542ee600354c6847a93c2664dcf97359a0e49450582d57" },
                { "si", "c96f13ced9bed69583a7fbb2ad97696860cc812a160afa128b794d8f2e975521f8f4862057feb790b50a592551806d94c39be04a9454266994917aa9f70e7eea" },
                { "sk", "9e4c82797f7e1b1a7933f2960a0ec43ab6bf64cbbaeb1c5255c5dc294878332aae5f6a1d1af6941efe3a7e92cbfbf63853d8c5a1172a07f06aaeaecc3def0d44" },
                { "skr", "b5577875733458187997f75660d494bd125cd510b9dfb62453aedf528786860d0fdfe27c9483d0817c4a49b7b2efa091c188a093c6af5bed6c37fd4c49426dee" },
                { "sl", "10f2eb21a8db3acab663613443d062d93fc859c804bd4e15fe43ccfae94f89fef6ee552c12243955f0581ecc5f877d616b77aab3e954bc681ec7a124965c5b8d" },
                { "son", "4de46055980def01f9578e2c66a666e7b0af726b9b06308cf87a512b3bee00a338d3ee9ff22b50bf2f159f110d48ac6c81ba2c3f3e023b725183d8a6a66106ed" },
                { "sq", "f47c9d4c15c6c45e4488b56ad8cf8edd8476d7bf3918fc76d8f61f884bc2d6b01125ee6db1cf65d6c9aa3d627a8fecd161218897d874e1a59dd1dbe88a3b3160" },
                { "sr", "ec2cc7bba92b484065ddcc2dad2e8daaed05a976ba2e4824eac14fee2bb9624efb584fe2cb3d0c0869468a700d5be34282b99e1b49cd6d8e17309da9bde26aef" },
                { "sv-SE", "3aceaa0551e126af17ea52bd5289144ac7752d5b174ce9453a159337a9977e8a1546554240e59641da70f4eddab0cd8b3c0e221ed9c2c8ec8fc5f4f74b6402a0" },
                { "szl", "3e9cf76cf768bdab883ee46c811dda1d36536778490c28d3375c464f7997521722809c1a6261bae6c7bad0ebb9d8effc981675d9fce97808b8dd1fa8d9d14377" },
                { "ta", "e056f9449e02f4efcc1e79f4a60c3e328dd47118034c1a84d16ded189edbc4594f67fefc7607c1622e0264629ba97fe00627bfbeb0b80cb2910541891c784842" },
                { "te", "0b3368c2706b37db739e65a22a2e83d05816aabaa55acff4f72ab064f35b594a1ba31a4eb2310d818d62512439f4bcc2f98155c9375ac33a58d4c55d24e6e5e2" },
                { "tg", "c32e4ea3659cfd6d3ac5baff1b7de9da64a05533ae200b0766f3fb04dc64a95c2cf82a0c98471ce350644ec8e88944ed33f7c2eccf87250dceb8e3f6ca2e39e9" },
                { "th", "0517684910dccfddcd0c5a161fe73e4eb99ac270f025b77998cd432a50ebd435f28ad78110f79698f15be27c9f6b68c98c4b74cc225d41785a4e6d30cd6210db" },
                { "tl", "fc8ba2810ffcaf0185431306f63ab7e1981f5ca2944653515833538750d24abc2131be47734088ee30fff1549a33f03e53b371c16dad4f46d6b6a386b5c45fd1" },
                { "tr", "8bee95531fe15378a4f5e9eb71e5f75d557d5f9c7b85234d51563ce67fd21b872fccc8e0a31325a2203532c9e788e71d0574e6ed4f1b913c279eba45dfec26a0" },
                { "trs", "350ed50d7ecf86b832195271dc7f546a887bea253d73f9cd7fafb99ef5c9fb8a7e1a8a95c5a4b39616c4b9694ff49b993dc86e456e688d5dd565c1b5a29ec171" },
                { "uk", "a87570fd57e2aeec4ea3e1f587a7864b7c2440f23e48fe77afd4b62aa30905d8f0ad90bd1966eb4d64300761d4922c053345c772dd56a7bab591816924f31dd7" },
                { "ur", "af7a2a60be3a7bde2662ba58e4b868c9111654bc7eea021d4348781a70e250ab89f969aaa3fc5fb8be39d905d44f80aded9f62f223389b666e3288b5f5063fa7" },
                { "uz", "eea150a5b6e568edc483b9279ffa24c2b542bc240777767cf9587cf29c89a7fe79ad183da0f2ff832d79da62546bbc2e9639b31aa939c20afefa9894235ea8d3" },
                { "vi", "ae4af07548cb4818d9f55a0688e3bd8a4f8b390bb34abb8731cc039d482d9a70a99d1b8ef7ba3927e6f69acad6454d0a96e4c0f963b8b38ad4f8de0e7d02dec3" },
                { "xh", "c98492cd4c456b7435f2c5241ad66a70af7a9988093e08a8834d21b49e5435bed4a37bc5feaa03a856d28e6245544a94cea849e064d5dc91f82a26f28db389a4" },
                { "zh-CN", "cf617b984321407303b602fb932a686080c1386ee74417417c7f3fda37e22bcfeba706c4881ee604ef2b8534ee81417d32aede91bba4018dc82937dc82507a14" },
                { "zh-TW", "a996e4020eab5d600beb533a97446b7e862ec24067517d0b3d5bb43a5986fcbffd8a9098d82e3bcffeda1be5646afdf239ab82a702105da06e73a4015d477a7a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/141.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "360712a1803a44130001bff2e8e74110f062aeeef3dd39fc1d809ab1a8057b1a6aea829316d7927ea87a4a7919e37ef4ceec4b486e6b855df120b6e94fcd3605" },
                { "af", "7ef3900f9db532931b0a8fa50190524409126697648eef0b12a50cb967b37bc0a2efb1df2b881406a837679607e2f0ba284ef011b8e970480ea1e0f645c85bbc" },
                { "an", "1c505e7a47b26a55401c8d9c3883f8a0663184ec7019d8c23b68469c479a8dbf3bc17b674e4a3cae60572458ddf0a42c8406c20b45710c801e12419a3ef01b31" },
                { "ar", "7d0d8f886de6a4a537ecbe8a8651930f01789b37f65f893c2dcb12ae5eb66ebb585464a5111437b4b9543718946759db11fdf68d9cea846f68de9580d3980d68" },
                { "ast", "50a2f2d0850f80e6f7cbc8947f2beb1782ad91d7716393f128c20a337a81e6551dc90d11fe2f466b9a96e25f9580b99ee1ae1cadd27948e4af7152d7a25e2a0b" },
                { "az", "3d20e31c4c1a771f07b9af0899a3f4753b08b227ef35349aa33e58ead6eb98caa00877cea0f8dae65c38785007446bf97c958bb1d25e7e6fb06aa42bc477ae99" },
                { "be", "b2fea56e3fa284e0cf3f8167636b7ffd570893a4d8361ef1407678b9f0db5f5b2ad8b4611e673c5d6e92a56a6db999286cb23b0083e6475c7a2bac3501ac4a94" },
                { "bg", "47f7d5d633b646fbe1e7a979d931ff73367dff6f70b066490fadd1869ab680ccd4a7d303c454f276427a6d67bdb023977d98cdd97c861b777fa87a73ededcf77" },
                { "bn", "065ec1f172754c9e92f5adbdafb4b6d56c310e9090928307d44fd335931bcffc1757773d87ce36a36cec04449f1b4baa21ac5afbef139992bbc6e30a7ad1c9d6" },
                { "br", "d69e4766693d26d99a94d998de91cb2401deffefcbfca27578812519dda92e27578f50f5c432abfa8732b25514bfffa878981bb73d307b4fe39d0dfb81ac2c84" },
                { "bs", "c3a93958860d915645e9a10848134bbde81089a0b94522d4a256a9fae33715bb3c811c51d814d4de25ecce7a79bec1abad85f07d7938dd9a8e826cc386c821fb" },
                { "ca", "4c60ad37f051f5a9bdffdcca179c5533aa2b4421b377e1862b7edf51b88b150023462936fcb640b7798ebdbe01f1dcdc8a9968b86305b26093078418ef1cf81f" },
                { "cak", "ec9fb9c7f6b638b1afb3f4b2b9886567b9b021a512d33c7356c4883d7bb2ec8fe12b2195569ab0b8d843021b892ce4ed07f12420a227ee93bef5ff0944ee0b0e" },
                { "cs", "452429a4b27158043fbf8d8bcb1a59bf46903552413852e748d688c8f579a1ec98a6d7fe1d4c9ff9479440d4d11d2b7e936b4b5898a99618869a0e939eda8f43" },
                { "cy", "2d120589c811caa0b9cc55b498d090b1a9ecfc51a7080191ea1148c41b57cbf4d4aac80a9ec04b799eb908074b9d79799de25c7156c06b25d272b1233bbb15df" },
                { "da", "7b141372d5417ec9e4ca890f017826a4c47813f9b4368165368cf74d44f43c22bd0e29b30d1a3b620c2271b599545067aa6d7cec9436f3582f95456a0fb34c82" },
                { "de", "bbc335eb9e8dde23bf1ee80b712b79a1f41df572d95d7931cb925f3de5b79218779fe6eaa87f75d99036e1dcc3de223328d99ee7cdde772529bb246abb332dfc" },
                { "dsb", "dd832419784c33e6d40c98344ef831c84a9612e5c1bb0ce7de4ca85497d4cc220f996b3f6d896555ad92e8b48b2909ca4b330768ded36a3b84550b770d1692b4" },
                { "el", "646f44bc9be4ba7eca04f8849f1cf97e866a0e00afecf609dbf622441562849b6881350c2eb287575e6bd3d0fd207d006881254e67fbb34a0c95ad29269ea7ef" },
                { "en-CA", "e09068c4228f657d4de0955038f66280f49cde51ffb11f7f86920bb6c3cd9fbca8610aa021969a3c0361487ec3c34d17678085244b9fa4231e97fcfe788965fc" },
                { "en-GB", "5524e746319cb104ca52351564ee859a01fdfc3ad482fdd80a33ce586bd7d27637f48c874d777fe63141945994aa342f668dbb0b5024dd0770ae117fa33a4c14" },
                { "en-US", "224da86ee99ad5bac84624ba0acadeb70f7e7faae2620a590319f58623fc7d35147de658b1520285a5cd1469c7fedd41478b48053e38ee857d12daed9d484cdd" },
                { "eo", "d1e484b6c734ab93f56c1cab8e7a5f27fccd815b50efee19177ab9fd4fdf99e4e579c18ec1284064246b91123265c979d696ebcfdbb37aaee6bd36b9975bb861" },
                { "es-AR", "71ebd2616c08567cc64e12189f00e92abafab2b5be7e1a724a04c8c06fc48e41feac134dc78bb5536b2e0026f03beda5566db8da4e79c9a32d31b670c153cce6" },
                { "es-CL", "d71de61cdec34851b45af27202137cf82bb6a047fb7fe7428a077413a3ffb471005e8d0cdcbd505d2844ade1850154a8e2300d953a03ff0eea79aaa0574f33f3" },
                { "es-ES", "86005a01c5a0d91a0c280601367222ad5642b88cd69aa1a3d570ffd5e166ab2f788fa7ef5ecf2e9a5d13c60d89df58a3966d39b8b0ff84e4c8c4bccf91a551ff" },
                { "es-MX", "3be97ac06b5566ea95ae77952690059191d38d31f7069bc5389c1b483304c24fdb5a676a5b58f7a476dc668f7eebed0cf8a4d88138b22cdc6cd0411c7d05b6f1" },
                { "et", "eb04f73d6e8a8b541ee9df6c1cdef8d762237986ee1b67d7e6b9650325105f96c309cabe558333bc3272b4e22b061befd5379afd532f6737896606a9cc02dcb7" },
                { "eu", "ca0be142137c0ac55f68dd7cd11dfac22d6998944e177ad439e49db9b8d10f3b3912b27bffc94112b7e360efc43173e29ccc68d4545d98b90f3d150ffaaecc60" },
                { "fa", "788698dbcb0c9b6ce39537daf23b0161214e272b6e3b6ea1c7dcbdf8f46ced4c6baecd27fa1349670a32064aa6f4712496fc19e9df4b7630973024b87c0b9e2c" },
                { "ff", "6ea84818e36e91d9ebd08eac596124aec9c1b2268ad026ed92533888f37288f7db5ecb75dc3db839eac1650bfde72d6f8c954107498f4a7994fbbe9171984f9f" },
                { "fi", "0ca657a4d873f9b62043b40c3b9a22bea5d05d49896e59d4540e05841e78363d126bc807ab5c9f28b889f43fdfb2c66d27bb7f9415635376cc58f2c10515ed07" },
                { "fr", "eb91b05ddba6a7baa1c4d8b21c047c32f4359b6cb73933ac7cc227267668dc8557aa4c9778c5bf18437548d08bebd8c83ad2481b237e31c0e954f79a12424fa3" },
                { "fur", "34fb164e54b9fd5412877a62c4580d257903925452feb47924e4431d7de20addca5c2a1869324df863da81c4716ddd515127f477aabe813df91e1d39a0a5a3d4" },
                { "fy-NL", "e79c8225af8c8861fa9afe4bfa06de1ee5e48210697a27aebd50d911ccb51d3fe0062c2c9efed861e713040bfe632fdbbaae2e7d4d9510bc38a75f583f17c9d8" },
                { "ga-IE", "12adafc5bcdd580b08238012670766e0640e2b029592e942c33b0e48ae8576276350c216736391c894c198ddd2f4c868238fb361be175f8f71761bb7a09e6213" },
                { "gd", "0db5bf25c0e43c654f182ce53c8491f6110b2ba94c488d5ee5ff55e1013fe833bbe9d704f5b4b95d2602f781acccb22e03252377298aca2f7fd60cde6d063ce0" },
                { "gl", "3a42c375bef696bd14ef506a66ae3e66466af4da14b50b86bfbc659b5656ef7fc3c7491e6631efabd8ea7eac39c7646ad9b4f20a981253b3c47ee81b88573a63" },
                { "gn", "69570bca3c9a5b9942be304d6be2983d83c8620d8a576cbdd12fc51eccea8012837be066650d35c1a9a1b17a3865937ecb1d7e97c42616dd70f27631fced5db6" },
                { "gu-IN", "dc14d39e7747436b897b6eca749f7c1da1d64600c9b1badc5e037e606947b262d45de04b0bcdf4b2c869ac1407a7b1b1a2cdaeebb3b09f4e212b48336fba05fe" },
                { "he", "1da0c3f954bafadf385d3e8f182df55f49bcbabef1ff5227af58fc43ee3e83592592741180fbc4a6b1bd15d160bba1f8a71ba96e6eb93313f38f9e1fde33a741" },
                { "hi-IN", "bbc1f15cb80149bfd4a34ee9931b664c2ba652dd869a1c8d568ca1fa2b1d738bd309487456d1c5ca9b9afed88ee72ac67a1aae387f151a5f690d698adf8949c6" },
                { "hr", "67b824ec43e0342524171fe1a37a043192009aee41709ffd6eb775a88c43a33d0b90e4fffa06bc84d6941b00e5ad4819138e4d321c47d2b5436ff96ff4b6c03c" },
                { "hsb", "c171711641f98737ba38d3deeb84b64a5481556ce1eb3e33e1e4dfd8682a7cc2994fe6014b6cd016310280c63e1dd08f80bb3ef242a2c654964f3c45bf0abe5d" },
                { "hu", "b2809a38472e494fde092a17d593e4492d4aece4f0365c01618f47ecc7fd98b68de8fc7d4b3781e3dc5c7f52ca0a877877465ecb9d6b7e1fd4f5bb7ad1b10c5c" },
                { "hy-AM", "b6b249d14867decb179764ab56737b0d89cbb890a8a3bf5d28d86d64f84e5d19ba73aa82cdcd5850a7dbac24f85ff70d5218ce37e00cf23858252f5b912f9290" },
                { "ia", "c9f502352d0deaeb5b7e190c1d1f9abc432fdb44995743c1eaf96f4917faa23e7259406af19684075a01aab7ee3f274a4e82eda89fe19bb991ccc7cea691eb99" },
                { "id", "e1390dbcaf7b11ee285d39bc81b7bee8618cbcd3cd2825be1515fba6d32e3000a58070ee9aabc447d7bcc3a41aac451ff07340c9bceb4152651ca3abe19ed76b" },
                { "is", "7024a1f9a92973134bb88881dbdd02fa889fb8917fc9c0337c051239881a2e142e2b81b983a4b14a0be05488da7db1869e58b29a1ba49718f19225800c2c1a84" },
                { "it", "7d843c890f7d6978929023be359d951bb8138ee43e3f16c153ed829b8dd8b0729bef7ea81b47c5667583f67f2e57b9e276532938b8b0add1b2acf6e726dea661" },
                { "ja", "e63d890964360f7fadd2452f76d439d660a44919dea8a38b6e5ce60e29e81c0fd3da8fa92608d7a7d9a0e37f2ffbcfbdbb94a074567b480faa9a444255129f89" },
                { "ka", "b9a2a8fdd424f1310967399eccaea84845c4e3766d5280cea1f7c5546e95b43e0b04d42c41a1f9b841f4aa0e20707cf0d5ed96177a81fd1337d67a88a25b2275" },
                { "kab", "ed3ccdf54b25aa2f9f42a39b143b04c612ce29e2e0e7f6e570db2a5f71c50a46ca872b74529b6f1e2e344bb6d506917fb3ae7e06eb334067a2b524981c339aea" },
                { "kk", "57ab2168247bd6c28c8b3bd22f54a2f4222de17c10295de043be74c54b9a5d13b568e39ce1db5e66601215496059ca7e19463fb8111482cb2b70368b3a62bec1" },
                { "km", "b759dc25b7fba9f0a94d656429b8555988b6fec1dc795fb56cd5a8b646c3a611489bf8f7db26a04b042aef4c4a539636de3c2d959b0af7a8876c06ee051a1f79" },
                { "kn", "fd6b76fcd3d676d39d4465c9a168d6756912ecc164c10fe147c82fc090d3b9f7e465898f77a7ca284a6ac6b6e2e73b7f8a669c5a132ab4ff0d816cd6b7ad9692" },
                { "ko", "c113f720077bcf6ec1667420aa498f477ed1cf4a3ef402e34201fddb2f91a2c93badd58d31d1daa2ea8a3bcbacae62bff40970f7a7c2940321f3b625fb62e421" },
                { "lij", "2447408e7887af40cc6c70cf477fa02ea51fd670f832a881c652597ecada0db824b862b7f7c4dcca5e698e4a4a288c67cffea582533e78ddfc0f9044cb0e1990" },
                { "lt", "db2d4936dbbd3ba4a706474de59a1e63acc0214c091307c6d043922db7083366b3824c75b55bf8f12917ea10dcf129140f86283efd90ad555873ef39dd1284c6" },
                { "lv", "8650f149080ae6c5a46cb18efd9d0104926717a7b8ce082329373ec87fb4638e823f3483a2c7a5ea766494bee0960a84b9b66b49b1ebb1282a408427aa2bfcc4" },
                { "mk", "bf2bb1a5edfd99e4235f33b5206d74f3458b54ee1d7e5720b01244dec4f600b4bab2115de7f8f6b87312a9dc2696ae4a3775b90db34bb5ba596792861c53f9a9" },
                { "mr", "5e0d85839ad80f80be14070ea8645e90b1a685b7501f6e169a059e5c97487c5b34cdfa3f996ad1338e2feecbe9fb254c247afc3da6378ca1e928f439b440944e" },
                { "ms", "25de24acd401bef5b85f4dd3116420b885ff9e481b780291b5b7851fa7777a9c0a06857f9ffbc089d0276327d3f458962a2faf3251a7baeb87a307b5a118455a" },
                { "my", "f8a56b5704b006364516477fb05f0216c7871100751bcfe0a15617d5bbf0190227180347f8b6bdad227fed6cef7934598b96e64c0c82e27a3591950a3d2fa3b7" },
                { "nb-NO", "c909712d961428c9a7a4d1aac1f63cde271c21bfe2a024d344145bb69b103d8ea23093ea63e8ae8444589e9e3d552c54cc928fd156c6e027cc57e35961e4172c" },
                { "ne-NP", "82638f82c90663dc1886a8edcb7d30e66fa7e03921509a6072c8b9d93a2ec4dd98b79ecc775037159dbc03bcfd656e9bab959b6b94b896e201cb21c8ebf086f7" },
                { "nl", "acbf210fa3c2d9d14db13f812deccd9b59087fdeaf5e0a2ae937857fae77402e03e291565839659720e89574be36376688c8efd3d9dd7a4819dae31298a67560" },
                { "nn-NO", "a3fe76fdaaf4ca0a35af0b6f58b57855847623665377ae4c6e576ae8753358a223cfa208a1458b0cdb5d617ad3417a6f5d66f3cb06edb395a4b9d60f33dfdd63" },
                { "oc", "1bd5f274a74fb685c044e7bf12e3019126e0d265753638690d679ab23b4c019a76a6dfe687a16744367acb0c5d2842d0ccd09bb9518d6845de12c3ee182d14fa" },
                { "pa-IN", "001241b749a7126f4d576ceac1f78223be4f2ebc3282f33749bbd9d2ab28a6e14467d65d822a2a54df2497f9913e4973faacf8dc71552fec10480771f83408a5" },
                { "pl", "923d654f4739ae13f83fab33beba8fe1585a9881191038c9a06e2f73d506bdb4ddf214cadd37b6b2cf255fc3cb2ead31f3372120a88a04ba809d50beb17d2d6d" },
                { "pt-BR", "53dd1d1dafc85da0cb3b9538d57fcfcfb3b139cd1abe97b82427d624685e551c0dabaecd73f68f12b8061c4471fa224f37bbb49a263ac579eaf63fee1ef12d91" },
                { "pt-PT", "e3667c80652de7021d8dd5fe407676ee40f05ee9de1b48f6dee8e8bc6970572a4e0419efaa2932ac42b35a1278c00c303df9eba2bf2e372aa06c7c94a2ebe2c3" },
                { "rm", "fb883172a4230f933e748ed303db3c8c5b6901950db305dc1cfc69deee5ee5433702c84beb4947ac85e174b9eac4660db2c8ba7e44a0b04b886fe34e038837e0" },
                { "ro", "c2217489884abcafa15c7a65680a6cac4d241cb5c9db495f13866dc79e521dea16ee3911c3e91dbf2bd9d7e62f669f16aeb80e9fdb9c603d61059131cbfd2a9f" },
                { "ru", "1d9c6f413e5674fa21179010f9adfd36ca0ee17223d78821f4fcc40edb5431954ebe3867916de6f061c9050cc4b67a03ee405029a6982976313c8da9bac6adac" },
                { "sat", "125bcd4639abab98dd3a688a13370f1555b6348ea0a349816e9101806d92c93945d395b2f23c48e586b61c4b765366dad0bb520cffa88fca64307ecac2de86db" },
                { "sc", "f9141f43f5c5b7d4bc32dec02ea9921991b642128932587032d8f4de31236cc7983a8102d5fb98dbf81f3407287672465e546a7ad7832349d7f4d8fc71f270a5" },
                { "sco", "78953a54d1d2c421ca3bcf1d71bdec7b1f5f94b4087e8131adf58c66b7e5be84b28bf85974dcf00b2f31b2cb25e0b88278ba285a75d64e1375a19d6104e38c50" },
                { "si", "c9459fade050970a7e500594e90ba0151db552418e2f2e5dd6979e4ee064485077f1a7334c2c018d293dd733f648bfd4b31588f4cc20de7a731007c0bfae9abb" },
                { "sk", "f08f7ac8a2df05b16278bf6f6c25cef3ba981b65bfe33c49a1dd42771f889eab02dcfae696ebfb9334bfc12b8cf03d6d02b65201b983639906c40796d970cd67" },
                { "skr", "611f40fabd0dcc5e51cb5b91d42ec503d867bec32d16043907bf0a3e35c28b50908e593e0af98e26920e7f9f80c37eaacbc6d7b9abd1e25affb677400df669bf" },
                { "sl", "1c0d06da39dda5c1617ef97e926ecc23ac2795c75e7960ce4906ddbdf4d5fc7f1a456e33c166013098558eede48db15559eec1ad67b02bf2c66542e5e50f57fb" },
                { "son", "57db544308c4e4d391b9e6c1eac7886dff619eed278bf47fe65903cb68f6dad1ad690ef8783b03a3c4023f01433cc71aa445568d2b1d55d03239c757a28604a7" },
                { "sq", "97579ae52225f06243b342bef005766c8894404e28901000fa4ccff4fd9ad051f5c04dc163816afa8de5d82935466f6068a12700ff916cfc624e9b5b542fe333" },
                { "sr", "2ce1fe8f4fc35260c3a961138a130ea85fadb8babcea20fdc5c9f91eaa90643f76980a271586c9e068bac221e0e079bd4644f6f838b4dd7eb46592b774ef73d2" },
                { "sv-SE", "066cc427e4a22dbf8a116f3d1f5f969b946eb76ecd9151068d994f020555137918599c84959da837c47125908bb509e3991fcedfa26bafdb071c41961cbe54b5" },
                { "szl", "b2afca81c6713feb491139c058ec122dc20b33065b4aa504ea7d1b115423dffa193f25a29fc66c4f9e0adc694e5158d6345269e2cc8cdeca3a3f53961cb141d8" },
                { "ta", "a10fb406bc92406b51bfa703e2c2df1c6d2e2ad48268aeb098468de7a812dd135b88dde51c55941e1846b27b72ecb3aaa10563e878790599b948d8c4803fe873" },
                { "te", "a4d3bde0f1b220d25be852b5e70d6a9811851fb1f92a72c27b58c44ee4abfb6995365d48f27bd8f012b0df9f898169e7b578348d4e66693476e40506c1cb6e4f" },
                { "tg", "f6b3a6242d55a67768e3c505f64505c501598b6642d05d142129ccccf5424ca44f115ea885d1be91a4a6f3250587e105d59c2ed3d4b83f0e57d87d88ce7b621a" },
                { "th", "c8a7f55e5f927fbb48a93c2c04ba4a1d3fc66164414be3b65ba56017e5697e8bb3f3e866d8d51088c48d48a90322709a8b72b76249509fda3237a4fe6fa88b0c" },
                { "tl", "18accf8d3cab37a22f2a90b3fcba78147b15b76983039b8935b578c144ec6a6c674d2fdbc6c382c557fb7d98879ad831d78d325ef57e59a78822dab9f0444f23" },
                { "tr", "1a2bec2ebfc83426c3b818d7e0c7abeaded70ac7e7fda8af94b5f25ae1e40a9a94dfc8db4cf35f7d7ea21b2204abb3efab8e5d61a2624f56feb5ea00c327ecea" },
                { "trs", "47656a9f7983902805731330d6a9b255cee5cb08c900ecf1a3259e0fffc36e03149734ec69c9ea1f83830881773f369d9f1ab0a1e2bea67fdd5393ff5ecd2e64" },
                { "uk", "24d3c8b46415e045b6da8cc33368d07e9261c891aeb833e90feddd729ba354e3f50da7e85d03932246fa0a90236d0f065d157a850e392c5cd618bdce73d6815d" },
                { "ur", "003db57ad990cd7f7ef4ce6e1560a47db409140794f1cf39161c8cde95eaca1b4c12e0fd347212869584f2d27a3fdbb95fc81d31faea338699935d969b514f3e" },
                { "uz", "c1a3772e6a34808e150580c9d200c246b35eeb1f9c1c9b7db701bd5041d7c554823d018256280f064ddf091f2bab1fdf40964999efc2d455b8f64c1a66af4415" },
                { "vi", "6aeb4ea4cfe784251037e327782204f664eb488c261fa838b7149452ad56eabf780e7f4040668bd0e26307a3ee14c9b2ef2e327779e2816f632cc278be52297a" },
                { "xh", "fcb97b03ec67a82ee266684600b2dc8bed249a578dac7d608cb5af580ca66c2271e56be99b719be6712a543531180899e2a6e13fd37dca196e6c10455500c7fb" },
                { "zh-CN", "d9ada5835c84a6ba063a2fafb57bc2e9d4165800bad219f36fcd699194c1ee6ff1ecc54052baa95e59c57e7d4f171a61bab45c68a23c1226a5fad47d5413c6d6" },
                { "zh-TW", "24a11e925f8aae76a27bd12d72dfacb0d1e755094c005421a08f93c6087def73b9a0914fe8afcad2fc3c45aa7995baa583c161b6a300e530827da10e81bb162f" }
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
