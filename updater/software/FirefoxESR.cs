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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.5.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d1fd90bd88f4e59549236185b0cb07fccce3b597759025fbbf0074da4d8cb0f5d106b66ec7bde8b7c723ec01881531c8f4501f6c722faeed42e8ab41e11a5993" },
                { "af", "b42c3a324174deb4ce5a6b7f03bb5a60854f87012fba3e39e021e43a5f4906e169b5370a5aa6ca62c919d7d0118cca32844edf7d0b3b04c17c30e4896739c451" },
                { "an", "ff2dc2af33a19905d84fd41dc9eff9e4cfcfa8de9cc6ba3634ec83e6cc4869da9509913dc35bc4d0edd6057668514b042fc01cf9163ff870480929762a3b62b3" },
                { "ar", "77a13d3d1ccbcea7b5265e085e586229cdddf68597f65591a5532f8c2eae1d322dfdf463dc7e38831e7f7ef300bc0edfa320bcdfa494c1a470af6fcae75f6983" },
                { "ast", "0bff0baab63b588406bdaef8f5514d008d666bf2ec8908b4fc105c0d351f65c714798973c390e88238475b89323ea23d86dfa9a5c803cb2f754990392d03c8b5" },
                { "az", "c03fc8b3c09ee10446083538b330edc6a57c13bf7526f0906f4ae65e4a63736a5b06108c8f1799ebdd9ab579ccca6c9e3e533c00c20cbafb14b075718b2827ef" },
                { "be", "de4b4f392ba25d59a2712d4e997de387750741235bde5975960477ba5378e34d594613efdfdd6fb321521c54c7fe4a7c94ff2cc9c60f38be5749588a6edcda27" },
                { "bg", "27a30cc8013c96f6efe44c8a837a4aa095b2dc6090bb1c6e2bd2149c1f5e685d85bc8ffb587bcab549fa37805937ab24ff082971874693842aeba4ed7438e75a" },
                { "bn", "72241698b08e874fbb5360ea557e6cc211cafd20b57c56fae7816461785c2d04bc793f4984534296e8fa2fa26cb0913b41b073a60fee72fd2bf15e8c9ff3190f" },
                { "br", "6158a01c4a2fc9c6194ff44a7f5e9b56e70dd00d0a01c8c5c436419035866362db2a42effceb7d2ca6586be1d4d6b38917a951978a1a14f94753ac149a2b428a" },
                { "bs", "3be3a0e5dfba5546e479b7fea5b1e829f247a0105e66f564b14b887bc19b8f90270317f373da2034fbcfd1bdb58d46d47d9d6aa4a78f8fa06ab8cab4c2eef673" },
                { "ca", "8f7452ce887c0b6f81a0173f71e5506e45639b9065188d63cd3fc1f5c37a5c502d04a4e8d40bc0677ca2f543374bcdb73775a671efb0928ab19508f012165805" },
                { "cak", "c82d5e16470833723ecccd79eabbd6de57144d90423c2203ff9692a4a63f50cc5d167bb8484738f4fd7cfdf41ab7e8e63e2e072801f27e002e11c36e3d89fb07" },
                { "cs", "11aded7259032482fb026b621fcd1223600e83e8ff9bd8a8455d443e8b957a31d5eb61922b5dc745d04c78676bd5931d9a4ce5bc0d150e4534251805bb53ca72" },
                { "cy", "e02f43bff4c7a69776096adea3b90927ae643ff3c043cf0bfda2b0dc437fb37b2c0f4c40e48828d8811fa5b77972de53e57742c99a19fd7ec4a53fd08753c113" },
                { "da", "026e71075b900d4ecc310994483d913af53d63ad07bf2afc88a813a05d41e5fe4fa47671b87505246a3574716cf984ef36ad2ba0e0755e1b20f7baa0b6771986" },
                { "de", "dea0608ee5d5a6d09b8ebe996f8fd9ccdead02dcf2d526be840a540c5b2408898083479e5591a899c1f911343bbb9837acd8895f4023ae22990465941b5953fe" },
                { "dsb", "4d0e557ac2b653551213f7aba33bf31d5f1678bc658a4ba1fc30e54b14a917471bc68d880e880f5213e67ea4d71e8b2cee770123d2f5ccc70b428c5c3aa610c2" },
                { "el", "2a67335e5c0e99e8bb8ab5873682e7a0a1d901e26839fc7990c9b6df50f0cf2337e6c3c79d32714eaab8e4ff5636490b82d7b8e4e20e081520c8b709e1f875fd" },
                { "en-CA", "ac1a84ca592f3cbde6e043e44cb0ea58f6e5e6957004318448bbaf1b5b3312e82956c04f57982cd10dd09551afbe6d37d2730a58d368b9b2560bba9ac7f02609" },
                { "en-GB", "0c6ecf1b1e6a4039e20e4b24f3183c990cd6142a87f085ffe175492394f797e982d14efa7bf96f07fa4e13b3ed1eb9c601b4a9f8954e6fe3f9fa0b86725bd593" },
                { "en-US", "710ad830e2cbb86f25f5737544ab52a4e926b3de10f1b37edbb10bd7e65719a015c02d768fb3abcf39c7efb9df1492e10e393002f4d3bb4dc9459a70fe033bbf" },
                { "eo", "5b97a1c54ef18ec6b1a2e3e98d80a3693fbe8f50622580887483debe18e010bf2b4e7a1facfed82950bfdc7f94b46844345910a5b00295061a5af58f13f18dce" },
                { "es-AR", "b400c5d0032ac294b7a98d25b7b17bb81ab5756b308d88caaa18f27bc872dbd7a1ece66178e34feabd35471bde432f33ec7833089c0ea33a69d808c1e07bf3cb" },
                { "es-CL", "a9021223d01dea28b10169f29041164fefd6d79da93dfbc0e791356833381e11c892ea8cdfddcde28c82f74719292ead6ddb01378527da81b5e576a8ecdd5a8a" },
                { "es-ES", "0ddd81e3a10c2805b724d7b6b500d68672999b28694a7fb0b89f90ef725cbe7cac2f20823b826292261b81edc7889e1b5e7d1ae803ae7abaf7d3e0aed04b6919" },
                { "es-MX", "9131045c4295238d9d461b3aa9c4e931cb7aa2cb9be25b7da09895a9c7a5d51c56942a41e9704dc5eda2cdb64f07753e93a7085b47ecac0dbae42553da25432d" },
                { "et", "8155525292131a5c7db62f8c8fd1196ecaa57763ff91e69ba34cc07631043cf7e16ac61b1d8f7b7128131e6dc4dce79b1a9bfae01eb1837e08c8f02fba3937d6" },
                { "eu", "be1f96e4365d437e62cd7fd62ac9d1cc092e2344208c62e0728dd4d3a3bea2c85b9b2bf4a8ced8d18f6593b68f337c039a7126b2a6a87b82c1e1612e4b7cbb9f" },
                { "fa", "d98ac67f4423d79e7bf9546c2af08ca484cfd6c91a043586b72cadbcc7da4b5ae7a8c1c102ffb944cafcde214ec789acba2cf77bb9ebd8f993479830fdf663e6" },
                { "ff", "7d5fc37065e45f8b2eb3860e4bf86d32a6043eace0689498004996855a90ee0a4eca4d38ac82a0d8faedfaaa18995bd1a394db021977146460c65193970be520" },
                { "fi", "3cfe4b723b9a60f7fa0fa7b4e98870c8133baf83c6da7c7a501e85f46259e1154d9376d226bf9bbe8214e9bbf7fa7b439820c678d97b861d5139e4884990bf85" },
                { "fr", "dbead8a2a596ef91b148fa8d8e3e8621c2de21723f9e79ec32c59c275672fd427c34b518be3bf4b1391eff43c715f8096439f987ddef621a95bf1cb70fe91ba6" },
                { "fur", "bbbdb62aea13ee257a04951a1235efbebe26cad2627fa45ade10d6d3a38531201c4771862d9d7705097d468b7b0f42e04be7fd1e06da38c1aaf91d3f90937598" },
                { "fy-NL", "f172aa0e59faf40faa43b828d73ee33560fad02f7cf47ba8b01abccdc67784f5449c89bbe276232d3d43c9cfdb0a4f01b132a97234e9a87450c8f706a6e00b51" },
                { "ga-IE", "c8d02046eb44d0f0d10cc8803f969a93178d80b7ba87220e7a499b4a824279103ffac4df45b31296d6623c8341449154b6cc67bc4fc6ab8d9147e73f1c20d3f6" },
                { "gd", "afea639cd93ad0852bf9e5505a9705927f951346a90eb004f9f873aac17b51ce332ae18110412c11a98edd1e1f74ea56b905b487f00670e920baaed9c33b4886" },
                { "gl", "e4f17318a0ac7a4df1e9716a15db0080aad00f448573865387a06403addf8162e024adc50f04e64ad79e9227444477f6f8502aaddea7aa6534fcc436787268b1" },
                { "gn", "0175edf4945033d683347716c6dd9ffcf3c25dbdcfed05dab2c5e187a6d6adb14bfbb211062bb10a98e0e24d34f28a0931a379d76970eb1b4553c2964c36041e" },
                { "gu-IN", "95988aa3f24668ebf49f505d643f52d3f1585fa8fafe8606ef165c82e7e5a0fbbdaa890bb1a104aed2b40eb42c70e533e7689f058c1fd1cecc029fc2a5a7e353" },
                { "he", "7e8c880ed2d647181c7af060d79cca567e6ee6953303377979855e8c48becbd16eaa8ec4d24efd71c3055c0092154554ccca03e1e942ec44c5019738546dafa6" },
                { "hi-IN", "ff024f9febf773fcbe1df36996a939a36887224e6cae8f6721f2b500fb29174091b74a10c5774a7110775e55b07a560a1c09e1a2f9db95a54fa9c408de7e45c8" },
                { "hr", "0d8efa5c3289e86c70479b4fb427e68daf20766731bc921fe74119a92d3a48c6befcaa7e14a893bfd81ca1c1a319192d1d053ba2b6d59f0bbfc7a6175d886b0b" },
                { "hsb", "fe3006f869776aaff8f83871ddb74ee1b74af94de9798030b3fb105733574fb30b8ad4a297099feb2abbca644a15ebdf0bba949c5773b5763496785486ef66bb" },
                { "hu", "c3d063f672724db658267a6e13c0eb3b91da464a6772760bcf7bf84374d543991a1259fd82c070d68b85ad617839582937c9aaedfb9c2e676aa8c58614866f5c" },
                { "hy-AM", "eb6a07671d7096aed0c2e8a7d3de8d9e109aca1e3b17d593c9b7e05ba118cc31b051e390f7ce192bc15469df2c458a2a7c32cc54bb00c46fc1f639864e96b44a" },
                { "ia", "3e63a8d2aff4fcc20def5ba61cd7e1276fab8b4070f889cd8f263c92ff359b42b07eda6860f367fd9dc1ee003bc697be5bdafbc6d485e101872989346f4e06d2" },
                { "id", "958091cafffe3e743ca55c5657b5495d46272e1a1fd4eaf14b2b2d019c33d800e31e1cf08e9b2dcad2336cdb46dab153ede405b6f37993c8f51fbf55857fcb37" },
                { "is", "591b5adeab2a043632413c646f2423b92d0b8c449838401c2c3447283e18514ca2a8d12cdc75114fcc429224d0975cbda89838ca0fe20d7823aa21f1924af971" },
                { "it", "9e3471c1c92fb18f2eb31b8573b9c7a6cf5b66e577b3ed827c42fed3ab8b90526d3d65275ccfc15663fa3afb57f038bb11316ecbae8c48aebb38354188b06678" },
                { "ja", "fc589a578625335f27cd44aad5721645eff4011bb2f1a2bf080a9bbe4def3546387ea7ca2ffadb604ab8709befd410c1a5729df28d507fa6d9b0d131201d42fb" },
                { "ka", "47fbfe6e0483d1d84931f08da529404531beb5a3be0548f7af2d7c3e81b99cd79034ca3d637f7941065a7a0d15f55f0cf57b0ec9e5b44baf37c9b5ea8aeba01f" },
                { "kab", "f3e15bd5c3b1a3e3eeb3826135fd83400729deabb6c4ca2a2e0296136e53235af7722769beb627a895a09674b4b657b76bbadbeb67858be6b141ccc2f37fa713" },
                { "kk", "3f8aeefd2f029826e0c331e4634a9489b5c5e7d0b83e928596d8be8af3f26194d3db1d3f007ab38d5728f563d0b1dec189bb8b9c7ae3d3bf945a73bd3345a5c7" },
                { "km", "4403b2bef97e5fd5bbddbd32798135a7dc66b65c7d680f0e1acc015b25719d4382c1f42aea7e248a7b8dbd13ff3fcf3e3b34cb498bdfbb0a2a8b440c74a27afe" },
                { "kn", "b3e38837aef55bb06d780c157a54126b4b494b1c0e521e87b75541e8840fd015e5a94d2b62577bb5b9dc55d37c0eeae3e7bf3665ea7ca6ce10310098937c953c" },
                { "ko", "5416922a57437e9223cac2b6f225750b11b3c540c78641f49dc8d1563295e61d94581879874e9c8a0c5346bdcad3c2140862d75e80a3406c783ef3c3389c886d" },
                { "lij", "f0e7ce750950babcd703d8fee20a9d4abc7419da560f81a14b0615441dbe98af9c115ee10c946641f8f85935ca608de7825f1695c4d17ea78977c0146e8799d5" },
                { "lt", "0acbde6eeada8cba79dcc31499795fd4cbf95e8aaaba4f50a816ddeb342034d2acca6ff56ea11acf3d1c973b2c221d58b060b716489cd92315df96d3561bce1b" },
                { "lv", "374091ec277b9ef8246bb543c06a4f7aded1dbfc77c99258ae6ff2dcc44c8e1d23d3dff3e8a14448567212b30aa149228318f4ac3a156ea7cae3e5b98dbf22b6" },
                { "mk", "44a9e70863680eb6b9c70e057ae678f8121982a9f5dfb99279c17b6f48e353479aaff229447d05bdafd31a602768605fac371cc1ada7e779944bb91afdeb9a37" },
                { "mr", "e6c840aefbb458312d1b1128da1303f54254c7b4f10d57e21c1f4d2238e8305bfa88fc4b6724cc45a0a7c7cb433779e7e9c7137a9683b16a33ee704a0035744a" },
                { "ms", "0c55550023a20b9611d79867e2453596009169f0fa1484b30ca17db0768d92f0354f56b15eae58477bb72b1b4dbf861aae1646144726dd352f53d54632612c46" },
                { "my", "b1d257b24827e772877fbb5ea0f438b505b9cd83491d9a07e41099e9f44355ae455f7d596efed820ff45c7ed166c071947c6f59c4f4eb2d7104b07e91d0113a2" },
                { "nb-NO", "4ab7c3b78ad28bbee31c9c28c02e5ddfe4a440907498b4ccf63092bb198e971a1cda21afcb529808e2ab7a23c884cf7f30c9d2a46320523f2ddb5652cb5d0a7e" },
                { "ne-NP", "8369ef4875d6ab1741b83b995995e06701891f363f374d5eb167f0340044b43bb1fdfb40e529c8d1bca8fa9e9ef6315982492a4c6a74e06aed4d000b29bb7a24" },
                { "nl", "c87fc9653e2675f2cef1dc0cbee308d55574bc7328c3f6594ab8eea84e42592a3cbef9cb0dda1568a18bf83b5d748ec845f2ef740d1200f3095d67bf6b63db76" },
                { "nn-NO", "f9c8f7330a9ec8184f0d9e57f32de62956331b5372063e727845d57f603fb1ab245bbd04ec1a24b08d180416144d8162a2477d034f8fce877524c90e7051f02d" },
                { "oc", "19fe138da56971b551e27d9c3ff5a64876a29d4e3c68b9147558671f6b2a5ad5363233c5107f5e132604b8f352fc3ef6747d109a7a160bbc7ad24e3a8866dcc1" },
                { "pa-IN", "5b02ed7cc3d098bc54a1799ea46d98261060e87b24c11d39e3ac5f83485a8e82ba5d7dd673de100d81111afd220c6847dd4ea694de0c097ce9ce7672e2e1d4ee" },
                { "pl", "16f7d38e762f72753e841c3b2831eb9afff185459838aa4199fa49bd9cba8703d35c2e993fb44e8389fc33982dda3a5b359fd1a4b0626b2887ccfe607b86d39c" },
                { "pt-BR", "4b8a6f5413a32c0b0841b87b19bfcc9f89932ecfb3308742eee3e2a26a5024364aa1758fb9c5443bbe3681cacfd70dc77ef648f92ff6f440be83c4de4e3b9d48" },
                { "pt-PT", "f42e9747c42f7a2b888407be7f14ffee578b1a7f5a4f6f1f199bff4ca378856aa8bc10af9aa625b95fafe95e29f39fc4b7831ef908e63c018c77f448c1049c68" },
                { "rm", "564087826e82063f7db6296017acd8cd008878a1e21530dcc1ae264b43d2dfe5591d1bb589c65a18158401c54601a0ccdc84adad5a9b4182ea53c36eb0bce61a" },
                { "ro", "16863a5024616df66a0ee40145b14e00b5307614d5c89e8e9132ff6c2fd873e6cad3df78e294339ca9666bcc2a9d32f8ab1abf77b0d579274596e9752300dbf4" },
                { "ru", "fa594092a284dc5393da14073b45069bc3016a08b8026cad3642dec24287ee2e277e360a8ba15edffd99fc08ad6f89eecd42e01803c64639fedc00e20e13c35f" },
                { "sat", "3cce13340b9696814f7e1b14c6d6d5bbdad6c49b1229a554659f05dbb18599781d1db5a11ac30c0940becd89cc9c8d9d597a6ddf362613f29aa556bdfa2f4b21" },
                { "sc", "9013168a1a9ab1bfbfef613ab0d661da423e60a276eb0034befde6845156e226840e6250c2931ece3d0ddd5bb2ba481ee475d5f64188718cb5b3979fc4e85542" },
                { "sco", "e4fcd31b897c7f616bbe22822f739b9c798d57654511eeb51a42511c21a6763766567df2ffca96917b8eb749afb82344af540fa84fcf442d95485fa4d7e8c34d" },
                { "si", "716c22c2a6e77d734550733358daed861e6b808554890599e303d7058abbf7a10207a877360af92e7b6781e49096797271c6843ee6e6fef8a10e1cace9917191" },
                { "sk", "813698f4a1a043defe01f6e380ee2b3b5a40dbdb7fa309bd07427288afbb2c3de54dc84cb614ad59abe8f921039b58faaed9285d7ba2d802758bb1f26572cd6b" },
                { "skr", "19e51b09a058df5e44753a1b354bc677324e0b4c00972d5015fe147226f80c9d507fe7817a4c8e76eadbba7720b7b0ee34799b6bbd9591127abe4afb25e6085a" },
                { "sl", "3c3e2c306b8959472a7eea8e639efb1076f8a2de7671223e4550aa0dd564ca2a0a9b8b215aca29e590a2bebc0cf9af3bbeb5d67d1fec8426280865f68aed5e8e" },
                { "son", "93c841e81ff7c08c375e32a949b3b3d0a653037074c77fd0f94e8d806101a691f2031e4702363d84b5128fa635102aab8b7b5de43c0d5623a6d50f709e32ec01" },
                { "sq", "a49cbc0ee5736c27707d4df3fecc8e5707ad2533da207b8fe35bcd57169457039843f86660e8706e304375de0b3ad0123f216fe7e555d929c1994d7c3657a95c" },
                { "sr", "cc41514f8cc8bd2eadd0a838036befc80b7da3c143dca3843ab41f8572f857445b646bcbeb1321115ce09e1578925cb4e4093653da2ac2b0e4c2c2e8d6d3ae63" },
                { "sv-SE", "fcf69f569be2fb6196320ccafa5fb2f7f668dd5db8f444d6b566c05a3c7df6913b60cdb77b8c06ec9af2abd6e433d36b0d42967545e63d31212eac0e0b805918" },
                { "szl", "47fc622131803f1e461284995756f7905a0e51d791acd0ea93057ec918fc711477284a85e51a55a806940e25e7cb8ab4254f7aee0ee243c632938865e5023cda" },
                { "ta", "d804a5df48b798f38a51677d20435a3e479551550016010031392234de4ba90c28b4e157ac6ba9cb425aaf49d40dc57d280253ca2da97b603584c9b8ed61cdaf" },
                { "te", "18917e988a42434bde5de15d827e627386a76e73e47063cb2fcbb42c81cf9d51fb2ead5f98ad544d42e89f28765fcbf21ebbcbe030688c65482192b7d8280a67" },
                { "tg", "757673cfe20ea4e5c1a01b3e37cb184bf14f16f6107fbb947512929c22a4349fb5f906eba7aa44e7f3b33f1ed0d9e17a7b0a7d8c482f8f0364d6476344806c5d" },
                { "th", "39d3881b91a9bc6cdd8a57a2442d7b16046d781a8721c8dd86c3c8deb828002d474193e09c26cdacb6d1304a27b9e494b2bc00a679bfb0e1c9fe02e6356073ad" },
                { "tl", "1c2a2d740c5274d79a6a5a2089eaa93feac0cb4dcdf9cf440c6e45540775046bb599ca831ed37ecf31f43896b12d8a0b680b57b6c3e1f90ee02e5c20ef3854bb" },
                { "tr", "0923d67fbad885e1fac4a3fc0714934f20bb57a72643c14769f393a582886a2443b73fa15b89d0400b9e879ecc5dbf444901a9ee97938b2e92c7f9eb111832dc" },
                { "trs", "2da54e0d4b62d78ecc81aafee1a61e5de5c74862ecc7eb80d21f241f92b9c2e450a3e6e1063935628f94a4b3f46564d3481f2a1575017725009c859e3b9fffff" },
                { "uk", "76647e707163ce6ac704b649ac312c649cd7f90693ec2122e303d1bf3288ee59cc7098404576762f2968415d0b3216981eb7d1c14187bc223fb040565c5e9da1" },
                { "ur", "337ce3f030a8c5e00a194218f47fb8265dd0e3a2cc39e0bff2488e0dd5f28e231578273957c902072cf1ef43b2b4b135d33b540d306605f16d677616da4d8c2e" },
                { "uz", "a20d80e35fbb43f9ff904e1b8426a7927c73073578a127ee1fa88c71b9aa1e0f8988f81364ee773bd095bfbd8c3162c24fe08ee1f93c5f4303144340e4002495" },
                { "vi", "eeb10a9b381a628d88765ca8ba5cb4f6af844cd1f27d5e5fda2013828d061efec7928cc58ada94996819626126175bdcff20f05df65d810e2191ff2b92d49ac6" },
                { "xh", "435d87bd75aad1887b30fc38e6b4677b85133101898e4e5368d6f8a772f3f8000f4b40100f2438e675332797fcd6d263e295629248ac07154665d5cd801abf5f" },
                { "zh-CN", "7c962e19842bb697e5a24c067f987d7ed1dbdfc38fb9d47a27bb1c4649b60ef68a14518781e780d22a81db7fe7e089490f63d1b8b5bca9b1ddd2479241f05e0e" },
                { "zh-TW", "061be2bbb5fce63b5d2577081dc202076fa3075dbe3233514b2f28ceeadd904d31c51e7ea6987a7bab7a4a35da60877f7b32fc075111fe352958a34643a8923d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "696a1ba6f7ecb8bb2c906760eb7c8a2499116fa590a93c1acfde59beafb2d14c6997f953dad8261ca1e5a75b121aac9377346b4955ae11ca0d6bd6c09eb9b838" },
                { "af", "27e4bd5e34cc0178a783ebc511af877a65895536e2880ce34d8027473a9a99e2f1bfb3815f9e78c44cb64ce05f034662ba7308f4a250af0dc38cd45a303d4ee1" },
                { "an", "044502a3df929581e4f05fcb4881dc30569366e7043db86af8fae44f6570a402b87cf326f17407a37b8ead7def346ba4c1d7d077a9dfb353e46b4452f31e6297" },
                { "ar", "272f34291fe2b9da0a1f443b9d9eb489a8eed4edf72c191975c789fc9d05fac4c5846c59d4a8297c88f02072f98505b82aa3f4ef30c7a0b468f9156a0aac8112" },
                { "ast", "c5f1f4f4cdee17fd0c6d20cc903ea26a78dd7d436f27cc72a993b3c4689cecf9136ae41cda88b3a547c9d9f19099ee27196ac7f6bb2be66aed40cbe05f54315f" },
                { "az", "8c57405bd37a8ecc5ca58a596a7bfb555628a9b426c2c9727b44cd526f4c9a3cd2b202a031583132bde94846851cecb857d5295c10aa514bc18b876624cff3dd" },
                { "be", "c9c0ad3b1f74495e30cbe810fdfe4e1f410a9b3d66928953fad08bcf7c314d2f14974dbf2e7aabacaab22e9ea2f44258cc5139ecb9b23aaf7dea7f2a483c9de0" },
                { "bg", "5473ad792318205ac405fa80301db669206f4afe27ab1689b455297c744d648f73be0c28d6db95ff6f182ad9ecc0bd8574ba54232e0ebcf4f7fc6f8f4838971a" },
                { "bn", "53646bb20874ac440de5a75f38d3faf76066c12b475364ec123805d053537c7f3c673ab39b85221488a43685cb1558a4e24903a8af697d2fe3b90ba253ec2189" },
                { "br", "e154ba9f544863d2d2427e477c9d9401fa6723a7fa6e8273638b40ecfd7d22bf63f88cdcfd051e996dce283946e334d4f6c03ec8bc09941588925bedd1e5f300" },
                { "bs", "9b46ee12b43a54b243d4877a3f92b47496ffb2a4b95daf8dc0c3b091d89457bb41b28e7e40a8a931f70df6e00e4ab1a430014e1b8997e21547e1e022743cc35e" },
                { "ca", "99363f9b92e25bd4ad21b7942e874d750a2d5425077ef32a66f9bb8b3f399f40f9accad0a41afa1a28758457926dafd44ab55c81b595bfc7289d3a393d039d89" },
                { "cak", "f0bc03389428705d30a45d05e47eed31716983c54991965c383547b221b1782ed7dfba1d058a221bd570555428a0dafef212a8f68d69618ad8e77fff5fcc8257" },
                { "cs", "846060711722d11c314a79c0cc4cff44c0b0ef0183635a71e286ecb5fc9fb9192462afaf9528161e98baa06b08f8bb98541998ed604912a4c0f204b107944b25" },
                { "cy", "2bb5c3336e91f24f297ea964a4c9e5fe71ebb9353a284d68015721cdf9a93d8e02fab2c197edf424db2afd64603ff0d4ef9f3b68d6323fd6107aa29f60083005" },
                { "da", "65a242ef8c3fd6fa083086f40b07554132d55332e2ce974995b9fb4f84782cb10db8b69ee8355407b8ab84595827676f37186cbdc0036da1f58010b727a4441c" },
                { "de", "fcafaf43bc9127ff7ec1af587a411c7cc5e0a5d655652c6717d3af58fb3891282be82632dc675d4e4238f8f6a6c7470451defcd2a1f0659341bc85d1c6931728" },
                { "dsb", "2da2dfd28d738b8e276462314142174e8142f26e7945ffcb0f8b871729419ee05260d25178aa67846756bb63ff926e8e8da3a8ad8974a87aba9ca78a2517e03a" },
                { "el", "bb55a799e7eab1de807a08dfa72f1b512bb97cfa8a47a124e5cfd58b55d3e0f066f4c6b6876a846cfe620973338c1cc55b8304d49eff487b1cdc4b939d1534f9" },
                { "en-CA", "87b25bcb9bba4b9c46e728d4cb29243171eb2c8c43a69a413a9e34908b86d3314485bc7a7304d312c94d1c115129e7514022e4cea4f08ce31758a329f5b86d63" },
                { "en-GB", "b5a938e7b69fec24fb5011b328c81aedb6f015e068690f948ec2661b8fcd55fbcbb3b62fa8af61cd459b1b2f5fcbdafefb20262357b4521fa513e8cf7c071500" },
                { "en-US", "bb5089470c1cc70ae2fa183c98a83b04d5396cca496a87d0f8d5ae70c3a7e48f5886a2982f4d39ca621476811b20c41016f4a5abe85e0ab1641de52383304e5e" },
                { "eo", "914ed3a659bed0b450c871a9a25d64a4a314260aa4c67c6988e1355b0e592cde203d736504c3e0c68425c164592a420697a266fe6acfb9565674222d71aebcd5" },
                { "es-AR", "2cad3ab6cac47a96acb2818026be118bbd33a3b25458a39db8237d5a35f83ae2d83270e4c1452c8ab1586a0178ddc4b64a0ed81b60f70504062638377fd4e3a1" },
                { "es-CL", "f5ba53f90ff9a1baa9b5918a46271497aa9473fb3cb522c3d2ee176208109fba56fb7d464a3f065bc2013d982f536f72834cfdfb367bc085df348c5ee3e50c9f" },
                { "es-ES", "0b1441b7c3b13dbdcc94aa43b1a32d8613d8870410003fc23672ebb1b01d14ae9de2ce25b6439c3bfba53066b59b4ca6a925f65b894678a1f4f98256ac6c0548" },
                { "es-MX", "137f7053a802cd72798e120610beccb85817fa260d8f2e34ee4478f1aa97097ae83044629267556af307b982ee8a9ee061b0a04a42e13ef971245fdb831f9950" },
                { "et", "6f86e8a1713350c48e1f9ad8f19bee8cfb9fffe72dcf59aa2da37853dc4697061dd4b32b3faa1e822c4bfc2f57ea5ebad587c863625b1b741668cf528800a3da" },
                { "eu", "7d8990fa5cf42dd4ce1d20013cbe7449cc1d201af5e7159ffed911ef669128481903888de5350badf89275c81527be5004755662bc9a001325a20a52568d92b8" },
                { "fa", "be1e51f59f08827f0e1e199131511b713d2c6cf9c315b4eb757ca76da7bed71f2b80194c148f15bed8693c576f7fdebfb8d63993541a0871d6e608cec8871549" },
                { "ff", "cc48a042a3a13163fab3aa171877bfadefe063b86bb81aea0f82453a567c8e56867218d438068aa67eaac28ba9e26ef573fe09cb48d3f6e1835b88efcc932106" },
                { "fi", "ab5c8d50a82a57e5fa53d22bd547b86029b25b231000d14e431bbea3a60d17e0ecbef87b35f0ee8e67b0b6c2d20dfcd03324a7360d6a64e00be37f2f55339442" },
                { "fr", "845254fa080586cf92ff56838e93c83597ac994fa9778626dd4c1d027ce74bbd4300e177f560ebe547fe4a2b8b282ac6a930414b236265af8986e412f19b95e5" },
                { "fur", "dc0498a495ebfb99a3d72436ba963316908471d28a88b9fb24a223400a952ca9f50dbd0d308e05aeef6c43c59957a6f2c58112b7c5ef555c185e4548f987157a" },
                { "fy-NL", "c2492fb76b7986119e289a74cf50b1d2f6f0e8a1a696651f81e4c9a82b6ef6960d31b13c71578fd343676d2d9208d92c3509cbcd463cba34f096be26961669c5" },
                { "ga-IE", "eb66c850130d25b8b227a8e3ce1fa3effc2c63146f76e38232ed0d458aa708e8599a815bbf0abb858cfd4b9ae6485311d197cedfd34205b7d3699a421b860554" },
                { "gd", "f524c88f6c1310421e5979fc71809dce611fd222dbc87ed778d92acdeafeee99dcda3aa1acff7ccb1b3a8849176752cdb0f03051e2d519704b2d068d486fe04d" },
                { "gl", "6834306ab6c100129212b19f7d0d6d8ec116e1c3a70b7185f23deaa38e4384d8053c7d8f80eb7a50edc8fb491c89bc35c53f3fcf52c0e5df39419b368dd872df" },
                { "gn", "0722410c2d66d0d7d6d6340eb20cbfb153507ae32d38eb8bcd011fd0e49d1158fe46a8629433e02de6f37971150f0a56fff401aa5f4e088515275dec75dca737" },
                { "gu-IN", "d21f7c0cb5be781e6d2e3c229ab635ccb46ed7222afdb8af9afa61cdcbe1cda65e4a01d499db38b1784ead12a3c283263067b71a219e678113986572064a8b12" },
                { "he", "4d1a52a9e7aed4da3dc5dcd7fe002fd321b6441df9e0119d015e570c00fb8f7db56b85fd7553c3db1f9df17f2326afb2d135c9a9717066dee9e06bc5d15d9002" },
                { "hi-IN", "ffd2fd0145edab26fd33e76e33bc26128540738ee62ddc58cbd25addc63f81125c1c9e06d8ccc5731c53ff93642bae15664ac98bb7f41d1a516ff4820871a66a" },
                { "hr", "d129fff030e282fc902743c0a86b09b5e87ca2ecc7c77a30e045eeef19ec86187961dad8d5e682a7b6d1149a5af59ddd387d29c6fbf5459a649b00b6c0fe79f4" },
                { "hsb", "5d83ef4d252ef1237eb043591f1a3f8bf471f132ef6c242e65f1dfc455e4d76520e6532ed3c4ddcc42039963f075edbaf1b59b32a1e5e77c80ab68ca3a384531" },
                { "hu", "4d6caff87e8052187d48b1afd1d10c4fc99cf574341adb0489f25b9cf1a56c28e3401c8f4b1bb5de72b8e0a9415e35d0b08d221c7c3b67be4c9223f3b2064776" },
                { "hy-AM", "4680e6340a20968838f78a07d4c9fc86cba55beba69f928056ed615aa9fe3c9ea7b8c569282807f986bbd4c01e4c3b4700b876aec6f5de46626202bf0b997fe4" },
                { "ia", "feefb2432f494b35ad6f46bc427ced1afc1db848d6bb5d889e2c732be44815902acbe9b3c8c93b634f83a572da2afa30ff0a3da1bef89d1d92edb7ebd7ba4edd" },
                { "id", "28052946585153c0794ee98330e40f710ad333f568c318a407c7abb2921a6a952d0b9f0e7e05ca260521169570ea42bafddf187d6534613be56bcbacb358c35a" },
                { "is", "974fdd2acf747234a0f083a12302f42178da944d05bf8da36b714a6f4a4b0ef4c8547890dbdde015c872a236a1b070cd1de916bfc2278e7aa9624b93e087aabb" },
                { "it", "22f3409d892f494cde77c8428eec4aac6264fbed06211b0a6e875e50a906bca620c54c46850e5f1ce2cead13b65f3ff43abd5436b674cb2c062b11e07e2e950a" },
                { "ja", "4265a761999d6770d30516d1b7b4b233e7390e6f4ad99b784c3e51188f0f5014fa5263c8aa94cd72923f5f2f0b1af9fc8b6b1b61236dcd833ef5e0aa57a9adee" },
                { "ka", "c88f470e2bfabc968f0ee19b296c03c048606ffc75b75f7d9749c2068d2b906731fd6a7103540dffc7312d13237b1c81cc5ca2706b76dc48e4465c5b21ca96a8" },
                { "kab", "35db8c7b18721be3f245f64f49c186851b5ae5cce9c61ee422137794f79cc22c222b33c8d9be50dacde23c5bae63518c5edf018fca752249d32924178b95efdc" },
                { "kk", "067144a8b1def271fa5b1eacdb3a341857b8287a3de88c1e3d752f97160fcfdf4a59e97ada33db1d86dd361507f0446aa5edbd72ba728966534cbacca45e6fea" },
                { "km", "f6d5461aef2fc07038ed689379341f9805789eba2dcb6f60e026887d20d153a96f6fadae463e94d1a515471a861a0ff7956c386897b1d464dd7e7fa126c0eded" },
                { "kn", "992dc103cc661e11d605c758a3ffa705ce7b98ce9b6f225897e62c491ccdfa221e11839ffe778836403ba4a58c4adf329c03f226e8f885a9ed32ab70678a33bb" },
                { "ko", "1c22f7a7d93bfec773d10526478caf186f433f0bb86704d53e5717df0672eae7143790731b23459d592ef4d9c81af47f9e0af03052422a05bdacb422f75374d3" },
                { "lij", "6ce6f5c2a6b8c81ea6f2896fb1aef187d8971722ef8c9101817620c2b3532492f4511bda3c4ad7cab86692697f61d53859c86a21f22e2f6bfcc8bd2d628d2cf8" },
                { "lt", "a25cb6c24cb78e4c21535182efc867182cb3dbe7779b9f4dce9bbc71636219c6b0d15b328235b60970af6fb2b775975d793e52c81373cc7ddede77f0ffb975e4" },
                { "lv", "a82c4692041aab9596145e5c9f71cd5874dcd5cc8b5e94938c02267ebda9cc001c3b33c5ec5fbd43a66209bbc68e51635c5dfdcf78363488a42b1ebd64e0b630" },
                { "mk", "317cc1cfffc9765212d41a130c8221d21813a0deb70f8a2b1e239f1c8e04fd6f5657229a46c0e5304785ba07c35af34303e3a4586f4411b8adbec45b6e50b6cb" },
                { "mr", "0ee2c550ab863f6f8a4577bbc49c080d4a487e56c7c0092013fb52745552aa0feb81b6eaf571bac4eff90a7f20d06605e20849e32b8bb13e158b89d2db50781d" },
                { "ms", "5abada18c8ddf27926ca6d191a4460f989e54b5a7de0b1d9f9493352ad0d6d563aff94f07169f8a7ba60f04e4b31d9d76a1e474b97e7120488e5fb3d1c7c403f" },
                { "my", "912402aeb4946b4dc1ad1f15c8fec8cdffffd2aa47c283f0019e7e4f676be464c85d4c0987f9a31f4d568a6373b7823d2614cbf528fd2ad8589d275f3fd019e0" },
                { "nb-NO", "2c51c9947a672295db484247a92900fdf589ccb71cf2ebf0e3da2f25687d22790e5fabedaa6a8ea7f7e6477346a2bf82e532240231c7bc44c53050a34b9000da" },
                { "ne-NP", "c5466d11fccc27405f50bcb687eefaf5a5bb7ee1f9cd94eb684e67c07546cc6cf84f49221ca4c21f580b72933a1f45d9a2fbba652fd2a789c5fd9729288246e8" },
                { "nl", "441b9da06945a47915155a755595eb7cf03a7639c75db04eb8f6f61c23ce5791e1e0af35c0930f5cf4b5fac40b01f0386279b78dac6d16eed1f0c13e11c61595" },
                { "nn-NO", "a81607866d3c40d3c1aa46077b544d2673554aa746ed015787b3e0415cb9f3c8859aa62dd4bc5deecf1998904ecc38ba766d7ec1e1666954ea7a4fe563410eca" },
                { "oc", "dc810c2062969ddaa23649181aa8fabe3d00db3b0a18f2d818d7a9b138a7aa41282ca8e92e886887648619deefcaa823c41e9fb4d2fa6c937e450230232323aa" },
                { "pa-IN", "35f27c6fafc2b2a53b75ab3f3f84df24e0983d042bdf63e326eae04f2a0017039406e0c3cffad6a91336355c58208f5034d7668b5d3d608d508a2c6373c075b1" },
                { "pl", "e88ccfd9801d7b411bdc68c21e2c6e6b4fbabb671774ed0ed718e204a9e58b57c98a01ea4f736d97527fe971e722e1dc58933b00c98f04b7f34f9fafa8f51337" },
                { "pt-BR", "56aebb58dad34d99ac826b882d81f79d8af34aaa04bdb8d7aab1d6ab7e5e8f5b63bdd4caa910f1157742acc3661043cd27934761ff52d7edd0678d33a109e1df" },
                { "pt-PT", "17cc85ca699e5c3a24829c2732ab9b7069f034f3508c8c063dd2f3cc3bb7daa784299db098c33cbe55abd11866e176f8ec7514c7c56f5c205d44a116cd88ba58" },
                { "rm", "59397fa7131ee4c56f255b4952a8c13082aeece2782de2fd9809ce4b816a2996d453ce29331d6f7ff6683799d4f37b5d65decaf01ce452fedea2cae8dbf4e304" },
                { "ro", "550bb9899a3952bd7962f120c3de092a6d4730e45a05bef3412058a4f2917f473b0c0099ad9f4011dcf56a37547bd523edf72fcd379aa51940b8e27a3b027414" },
                { "ru", "dbd46c84916dfec1f03859711acb91ec54218f45698bce02786fb0393510f0a3707a9bfc5aca6ab55d5f3194ae0d636bad0f48ecf4ee44a8e99de09deea5bc2c" },
                { "sat", "46ff051702894970e4833dc0f804bbd5d59b51e590e193502da7b9f2ad450dc01bdf448f47449c32bffa3b942b28a5a38d312b860cd0cada887c5df619b76d5b" },
                { "sc", "423157192c3a02fa987483368f8fe7c12388d73c5ce2253f955484dba33bfe2be43798461932e78d759150b3d0913306b51edbd2d936daa375a26b32fa78b0ba" },
                { "sco", "082815c891b1f8885f49a6e97f18fc3dbd6524153f3361de1d38899e002878bc0e42553c5aac6469683debadf69f6a9f399575e4134eada95d405513b7279469" },
                { "si", "a3e483e8cd747ac0559a7d871752a15fa8d6e8f5467d3e7168a8fd25c79751051792d5e629f70adb525b52cd47bf5c1334871f93030c2be0feb4e986b9d74dbb" },
                { "sk", "fc51d52298b2adac9afdf1dc54e79b43e7958297a0e5a1177cd1194c9bcc2389e8d2265ce3329f96a9fe18bc0dea5a69b8643adeb9cd2a642e8ce41fd23b34ad" },
                { "skr", "686a3c7b8623f2a78dd49f9d3d59641edcffebb4df24c5324131c2e261c51850f28a4e896e09e3815f07b3e0d18a6251906c4f20c4f900542cfa622335169fe7" },
                { "sl", "6e6c437ca9f3e76f064b2f435765860013f32d95a105e689b51f2b9bb3e1088345c171192b027ba88d489055e7847e2a848c67abf87964c7e1334fd184313071" },
                { "son", "89407d9cb9cc93b1c1ca7ad50cbc66f9b4aeebd128c722045ebba0270dda331c10b0b52e7e54622935ac695f957030dc7ca0f21d0721a84476b586d56097ea93" },
                { "sq", "d11d654679df1948fe7dc35ba21c2deb579dd4db755403bab21471dfb55859b41a76b76a04d7d3c6a20a1a34083d21e660de9592323affa532844740046084b5" },
                { "sr", "0716079de7849a108965413ac5dcde8bdc7c42e995940bbae2950faa06d3d713c35cb48623de65a5e01d27297b11c23d074384a68ef26e5b9cb45a7ceabdee2c" },
                { "sv-SE", "0606706a2832bca54c58c636df061cb23ae23cd7f957155384287aa035e44f776d90aaa222210f714d1ccfa365258665b6d35f7181f4b3d43f800ddf5c8aaf89" },
                { "szl", "e0a212ba75604ca4c73861bb6970341b6a95f01b56743504805cfa2b9b82b7d41bfe17765c976cf163efe21bd6b06a41be9afec66c4354b145fd6383441f14c7" },
                { "ta", "fed2e36b3c9627d75f8d540830e0e1a3b794929c79779dbd250708c542a5d1ec38d66f15196704d63475da0b075ff32034ba8e6c4c1301f7c2fb1ffc8ad99879" },
                { "te", "1f93219c4d1b2d72899f4e12a96b904eaa04d78c0b0cf4edf5e896b9974438e3d9f87cb4484986b2417a146390654ef28de6523082673ffe4f30da52523f6941" },
                { "tg", "013eae78a36941ac9285895d73c9c91de692a8720e1b4272b040b90f2d17bc0ce8a366b46f75cdd2e116d769729cf388cc1974cb2ea58066a15e0d9454b3768b" },
                { "th", "1ffdd0a4ee0a8b20fde49f1b2cd6cf4b11b288ac0ee8ad58c8188e89d0832a581e1264ec0575bb0a1fde3660d239da2097a3c2623dbefa5a8c94934b799bf3c3" },
                { "tl", "34143d65c363637f2f07650f12d12aaf6b740bc98c546c5f45c4d60b18fae91e2f8d53b1de26d9b7cd06d731c108497d4134598480bdc0649a1c38fdf7f894b5" },
                { "tr", "8e0cbc27197105bb4854445e1957295dfd3c5f07d113a5a75bc07dcd920997bc716bb806724a1daee0ef83afb39b6ab0b135c30b826444bb091a97cb374c62c7" },
                { "trs", "808189e011032c04d0eae62b27e52c62aba6b69b6c749b4ba2a7dbe0055425c4b695450b9ffa8a9301d75368203e448170fe18a424db4bf78e4db363049fe8e3" },
                { "uk", "1f083ae8fc6411726969d091a95b59d0949f16b9826944a4b3607751717b1c092a65b848c8b17f0ed71378998ec1f4d70e772eea5ed0d1aef825f2dd8a5eea2f" },
                { "ur", "350be2a584a7159558f36ad15c15433bc6662c3d829a914f60f0b6304e48de43c3766c7531ebdfcb9ac23c7d43f728c40a2ce1c62be3648b9b2c52b6333e34a9" },
                { "uz", "e83999909bb841991eed6f05caa10cb9ed454554eeb4c8afcd7cca84328527eb80b1cdbe3324e8a8383267bab8fec4192bab325a2f888c6bd85567677693e985" },
                { "vi", "3987ff8bdb540096d36fc0eb3574f2557996214d622dc9befd5712f01c522feb4647263752b362d98c7485c9259f6b2bfb0cfa64b82c171fb74f82067eed80ad" },
                { "xh", "42cf14551bc917d1459707fe40fe1a81d296291b2939b5d24dae00bb333e48efd7fc363fa1cfa90d1017bbdb284c40f51c5dfd763728144a0ff5e9882f9b57cd" },
                { "zh-CN", "bcbe7502c9bd12b830793c797af8e303e6074562e76eacd1de58e092ded9a4ed1b6528f51b4ddb0d48d5cfa7d7c2b707cdf7c4c17e1e6103ac404aa1c50f7da2" },
                { "zh-TW", "f98021762da1ef05bff0c442dfa74e77eb4f196547b46853806e5b0168d834dd6e1d40c74c7ad2be9a26f04ef752fd6065e40ddb5c155b1918a88e681a4d71ca" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
