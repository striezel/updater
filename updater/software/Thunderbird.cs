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
        private const string knownVersion = "128.10.2";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.10.2esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "a507d441a46b8406f35a6ed0c5e4a07d51819bfbfb39e0f9eb1099967f871c0981772734477c16f92e0baf4159bcd094ceec7b6f75e2eda754c729fd12393c39" },
                { "ar", "4499eaa95e1408dba527463b8dd35e49716fbe34327cdd4cbb1284a8db32a5da0a72946ea71270cb2115322ef788f22fbfc0984629806fe0d1d997fa92552422" },
                { "ast", "843290b98149da9c1d6428e7bdfe3266b8532f0e559435488587328f80e27172c6f9017a01eeaaf1142e9d12cc5a4b118c2e352d3c34f4d7f4ed891043b26de3" },
                { "be", "c06193c0a5940793490e136b26e54936d61c934e6eb3feff4ae2a2ded12f7bccbd5c4f39e28eb6ab6ae4e945318f0a89a89d230268275f3f3e6f584babcacd9c" },
                { "bg", "62f9a75dbd67fc2755cd29166f2d067a8239bb8d09047f426f5a508053dba28ef95386ab1883dd4417a2080ffeaaf345ce822a4c185a155ce16b8ccbab892765" },
                { "br", "f0d9fe0bd8986cdfaa0e66c3144d18f403885ae47428777b25038959491a68b2a389d1440eb749f5402609fffdbe0b395d65ee34eeaaca57fec7e770bf47242c" },
                { "ca", "8a3e1a2ecfe27ba265b55c4d5622c3c26f26684723913bac9de294cfca42945ad7a05e29ea3dff68dbb114e09d023843e68fa56f7e7d4eec84d42d6a64a0e46f" },
                { "cak", "b1624725d1c17b3204fcd05de0269206f54f31ba8751e43c303576754394dcf246355c91342fa3af4f1313edf4f8bdb3e4ae9f8bcfb903f28e96fa2213bb12c6" },
                { "cs", "f7d89b95f06e592663d9bbf7d3e7ffbbf52edb35f2c45253900c128370f78dbd5ad74fceb64453677ff933819b8f133258edf75897121ed1e90c75a2971c478d" },
                { "cy", "d6009d9362e290e669f0ae34e4172b35173bb1a043433e169452f37d6e96907653c4dbfae006a23c5acad7f5b195a00ed5d19f78fa99c35ebaf5938bc17f5455" },
                { "da", "b0c4648404bd11fc5d15ef33cec7b6638c774b455703ad1e5cc3c59fda0dbc86f5bb99d94dc86550874972951a59c6726d1f57e911e26366a5d02e719e0dd295" },
                { "de", "758a074979b5e63a02244302f8ce33521d0b11d419e79d2043c3bcfe09248c6eef8f53ec2c8887302028a1b19ae8d397915edc678da759fdd7edbf629a8976e7" },
                { "dsb", "771bc34ee6790f5c647986f29bd1db59a97357fcd3171b98662e92c7af2ededb83b5b30d3801b64c20b3bc08e2bc8861cbf9cc0388deecb7845a91580cb97278" },
                { "el", "85c7e0e83b011d8c6aa394530547769f8cfe258562de91526bf9d711ee4b355856f05679ffc6dc04f86859b6a6eb8cd6d5ffa919893cae4d672959e9241bca82" },
                { "en-CA", "94a644f1d43255ecf80985da3c5bc1d3cd35398e4917a7435ce26ee309c9eba3d3b272d38b598ac82be68caf7d7fe40308d50ee1a3c095f8b1fa32d41c478f57" },
                { "en-GB", "643bd0878495f6924b012cd6bfdcbcb62ccd7353de0f8c2b6dc365f33a7134dc4be388984770108f000ddba8e826ccda1bb8b73a9758361646163c048b551633" },
                { "en-US", "cb238d26871d20cc81d25c417a88bc1186024eb684a4e15028b200589d8dd3566efdce9131afe761616c4fd5c53d7b4b1ef5311d412030ce2443da5f70bbd9f0" },
                { "es-AR", "3259ce04c5be5330eea2658b570519803f6cd1e7c1d2c7fbee2114e5be014cc8e02649f76047546553a92e4a2315963feb343b6c7e996c8d9589e6be550e3bf5" },
                { "es-ES", "7464645f07823470724376afa8ca29fa44b5bb65ed8f8eb3c1b04f7c6f9751196188f0cbdc0373c151ae206f9a8c4db35237a795f18ab655e27ef1e3eb51bbe7" },
                { "es-MX", "1871788a7e16d1a1c3a84f877b06a3ac0cc5c40880270802a71c4ea8516c7992a91948162d7baab90d1008f773b595e1c8834dc671561a0e960424dd8470101f" },
                { "et", "0355e28ab4702921b8b3140935230bc3840c3a380decbc3fb00e7ae4c855e802595294493fad7fda17f3e112d05b88c33edbebbd058ed868f06f08357b58df42" },
                { "eu", "4699846819637bd7dc81fd2e8a911fccaa1cdd3e48e4846f70e6cb898c82b2b3a009348d88baa6fc179750ba2188b73b83c06c9ca5314cd420ebb6b344aff440" },
                { "fi", "3e3f12b4b8d9d26e0d98798148b82e026b48dbef80eb4659967c3f3e2648558dcca7acb3aa9e9c19c4c1026bb49c085a1d5114024f58dc1e346915cfa1373734" },
                { "fr", "a539a4b240697bbe57fbc3fa79963b652b2dfb0778f15c4888e148634771d328e00b1349822eabc02dff3068fde00cc1d132b3d6629a09ab93c3afa32bbd50d4" },
                { "fy-NL", "67ece31f3ef66f14cad0c55f2b0752670155d91457fe7e342d8a591f9a8b8c56687c7b04c0e94684adfe3f534287293f2f38712707848792645153c7b3e34d6e" },
                { "ga-IE", "5569383d667a3049d87edc54454fed970f90c82435efde39a696a7726fda684818838457a1c7a1fe4777af71a11f285ad0b9294ae58a9b09c41555d4d7a3b616" },
                { "gd", "4d0ec198f3affb62bf6c4d142425a6c1e2dabdc71f48bd0f1bc717142f559b9d5caaa6516884e473d24226c662eba53815e4ec50ccc2f1ac276a0963bb9a6eac" },
                { "gl", "a2b66a4f472a13f14fd712b4eee6339747ee4b9ce4c56056acf3c613c5e69b4f21ed5b377ff1ac3974f422e897e43335ebcca0c2fcd05ad776557be76109cd96" },
                { "he", "49e0ee76b3f1205c839aabb3261579bde5436a7e826429ebf0ae6563472ae990e3c76f31f14b59da6ff339e770bf9b8cf78c2015e1164a046a08ad3b82e74940" },
                { "hr", "1f3cf27f338d04fc1c783609977843e0689d7795a38abf1f138659d681b49b2e22b01445a937443dc57c30321a5bf63e6f6bce72f111b51bd27c6db761a5559b" },
                { "hsb", "8a5c9aca3c28b0c4f2f5d095d8f7d57d2d1a109b1f25317423386ebb0aad07b03b2a610f0d15a84d2c81d5df875ba87de5098f6f730df306158efed5cc1a9995" },
                { "hu", "3053e9b0e5804854884952cd5e6008e3124ad684193540aa10bc79189d66b02ad1cc4d59df948263eca228b62da8093627c421f2c71d12f9bcda9d05aa13b918" },
                { "hy-AM", "ac2e42953f0576083409cc691dd0a72cc11ac57a1dba04196bd6ed66998ab035c96f0f87252565ba08cabf9e99a84594c7b9174a313c0228e34143620920b039" },
                { "id", "86d3c3db999747703587b2f7a9a5a17a2a175896f8a78d141b8652338355e311601ad8302567d9271133e790bbb288be2b5179f864e0829773c2be78e7cfce26" },
                { "is", "92960451d8e9b05fd4a11624b0d0df0d3cdf04376f22f4e15908865fa898d5ad4418da17d29d4966f63724a090362e7ddb7671b33700be99ee13176e60683b13" },
                { "it", "d34c6aab2a99fe583bea8b6b44fa60d4777345ad0a8aab85472d8be11febaf7db53bdab5390a30302398a01fb056b852c2cf0402c1eb2c842804e6fd0d6708bf" },
                { "ja", "1cbd3c2557b5e4f6e0e9b19dd595cf6c796b5d20c07ca530a2458791cddd401fd4ffa645df56a18e38c8b5352e04840c4865d5167e2fd1e74ea45fa4352da726" },
                { "ka", "d6420c2d7b7a7178ea037dc9c06faaeeae4db027f976beb700a4c73341515870850bdf32fa374af147e08e7ebe3e59134675925ac4a7e45dec4c1fb22ce7fa1c" },
                { "kab", "8d4bbe00940edd12af09da730e574bf9c6d0ed34ea4206bcdec862a09cafe2967089aeaa6837171d4e4135c947a403663ce5bd71dbe87939aeb4d17e9efa8d25" },
                { "kk", "5168822b9aceae276aec5da34f35d5f120c560992882260eb52a52e6bd86427788cc3c842dfaefd28a2582822e72714aedf2c41d978d9f0bdc29b76ba4688cfe" },
                { "ko", "1027acd277a73c8c1c98f07b2e71f8916b6db9a5714a5829e366a7f2966217aa1e30b04971eb916614512291fc8175a07cf0befa87b17d5dd9697d747d4e16d7" },
                { "lt", "fa50b7e610355ad244b7009b2387cc423641e8f90d74202c1c7dddd30ed34c97240083e715527cab068f164c9dcf441c73e06fcbd11c8d2edd1abfcb21241f63" },
                { "lv", "9ab0df25aaf832249506f1781b9ffba9f7d194a28107772d598a2c9a399ff677127d7012aab9b5575677c49884a8fb80ba7ce122abe42d70c531c7ee0dd90e6f" },
                { "ms", "25b340b1c15b824cb4913509a3da7d9def29c4dd72f5fed39dc9e4985c77d34470c794398e7b60007e1e860e512d96b918f9774280d4e8b11a4675827a3c2046" },
                { "nb-NO", "952d5829f1901deba8d7e86e332a0efb17ecd4fe11428e1e88ff8817c29e20dbe00588fc4302bd73a05035cb1caa881dbc4f4ace9bf97b2d12b4ef53f85da73a" },
                { "nl", "1aa60817be27b9c2dbce013a7dbf057a64a2c62bdca98dc2589336e4528f312ce4cd2669a140c59ae119d4983c1ca9b9ad0953d90a8c94b936b41695235cd8a0" },
                { "nn-NO", "fd3c2391fed39c40586700439c236acbe40299740c15ccbec1070b9471c1be0ba7522ff566f9edab78a953c02a31ad1e25a29ad8ba02c7548cb9d9de86c87db3" },
                { "pa-IN", "b23305208223f5a4e2a4e3c34d322ede2a1cde6e816352bfc038cd1fea360db40971e83ef97f1ce71610014f55b2b5af71a552c2c664920fe16f7a3be93289b1" },
                { "pl", "421101632fa4b2cb2f82b7426917a0b6d0381922eda1ea61b7b1cdbd3a26ee4c767c8059ef2f15e6304df6f7e053069038d6c453b28aaf040f8860f8bf8bb930" },
                { "pt-BR", "7e6d7dc34675205360bfc9f5dd7b6dce5339d21d47e1a3bf38e835966680ff70c99989932fd3a564d0f438e446f6d2792f9d2c8caf444486b09d09ffb4c3dd30" },
                { "pt-PT", "c1fb3d74bb72fb36765cbe3e61d461815177155fe57600e64aec01b413daf7fe33711a0e06b2901c6f8332ee37477d7745b534d97c9bf6e67d11390294537c35" },
                { "rm", "2c956bff27e32babfb2849c33919ae0612cfa0fc95c4e2bc3b4e2881b4eebadcc828c31baf86ae7543a9b636a7cd6fc89dfe621791c3559f99c56053b9c8a94d" },
                { "ro", "ecd06ca37ac61ff4c34b2abb2a575c451f341003852dc19abd443409092831d14113736883161d70f1b98ad3fb0251ae59504dcdd253fa3802919468a0b95a1b" },
                { "ru", "5a8bda873ada665de728203894717ada5a306c8c6e275e4524001b6691cb3915f07443bf9ec49dab21bea22e922bfc01d61d93e384a700ec4ec0b7f58896bc2e" },
                { "sk", "d73fac5e5fbcf8579c99f40071a859367eb4431469b7a0d6745e843de0e802bd06e72b07448d0e02349c70a8c74badeacc243fb09031ae29dd4ad3d9e25480ff" },
                { "sl", "ca2f57052ea8d9b262349b7d8b8f7a97e3e9935613c36c63937def88b8807477aca3b00d1c8d2298be731fb4dd632b14b9536645658b8d9ae29fabbdf612c276" },
                { "sq", "19912670400df4d7ba316f87512d95b2b8aede9a2db94776a05816df81bdf1d59f1b7439c46648dbdaba4ad215028d33b9564c9331b258223272a51d1dafa43f" },
                { "sr", "d660bce6c1bf3e9236d422506cc7394b2d41eac37b9f0260d2629a7eaf1e12ae94b3ea6095d45aa40664fbf797b7c4b88e6104d59243d4eb0b292897f5a0c5f4" },
                { "sv-SE", "97453a2a6c676c7ddce897e1f055205d46b60dfd968136975ccd2c3e87a1f94481df6a2f9964dea67ef84e7a2027eef9c87190f788acacc5f7f85f828e28340a" },
                { "th", "67d316a3fc16d349f2406bbae2ece1ef99eed0ff77da736ae0cdd8f91c05f5b08911fe2416f78fc0db508733f7b4b39564f4a7fda0f6869e39f7e4f82d95a917" },
                { "tr", "009f072b89f3aafa6daa0788ffd9548f9940df7cce80ad602e29d725a6fa55d959190c1943e2411cacf7c0b1c12a01b03b18b1b667aa25cb1288bf3c07c94d7b" },
                { "uk", "35a526b916f7fa2393e31593a8927271e721db2369b80227180051ae0e7c7bde7d7a8fc9216da2e0ef22aed51ca5647a83ee1f27ffa2c32c6288b1140a61e1ad" },
                { "uz", "bfb4cd94a0c5ea924bd158df075c717383ea44fac4341bcf4b4a776f310115013cd167a5eb1b963442c492327603eb03ac3bcc5768420f6f0a73779d22b3119d" },
                { "vi", "11d08fff95f0e0c9b3c2e0a19f9a6eaef855cd905835ee31557364c21f456c828ee7dec41a68e00e8dcdb1ecceb51fefa50f679e7e1f49a046ae684a4fb0ebf6" },
                { "zh-CN", "55dd14e0b1c66d5b527683c170f67f629630e9c09fa540c3aa9a6c698c9c7df722ff7922182f028b1a5d12f6a8347532e08af37140499df2c6c26a8658c66edd" },
                { "zh-TW", "6078df69d9e6f7a9deacaa9765e98d6a33806e4f87b16bd096d165f3730a4ce310803f69b3b36a61555048bc75b155a71d6611acb6bc1c2f0644d06bccce2bd6" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.10.2esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "81410f81af5c7e52205e3b2dae17352918278cd33c1954c4ccd1d496952edc70734b91ff2a74aa6894f1d8b11898872640ecb3458d78bddf81e4cc4e0eaf5cee" },
                { "ar", "d6a4d3a85850e25281b47553f04458392910c0c098ac2b383110ab543a9016fc7dafc97e93c3fd0342fccfed3ffcd0db6b71c8601b4dce8110f6a71730f4d079" },
                { "ast", "020bbedee0ab7dfe60677a7014f7963269a063af5d00493e1e05c69202e6a138d33a6fbcde6778d26816094c57ec62579635b43d03a6b02a583e4ed1ab80d241" },
                { "be", "c29643d3a7c290fcfeae223c76a7e6ebb0260965f6aa6fca0e7cfb84946f02a51b1c1e2ebc0a8646fdb8e1ac64c3ce774eb4fdb25c68e603b0d72bce69103e6e" },
                { "bg", "2d67409588c33c6ae0bb15df91dbd890db78cd31cab2ab180acbed8b078d4a5b570e5b2c6774f4091314c1597435b88acfd0f9578f7646e912aaa13ba1431afa" },
                { "br", "635248cd389df5708c340a60dabda62f5267d60e3ea39d7fe09af1079ca9db0dfc16d203aa0186f89c05a03e32d5ef009b4ff479a22a4f7c2666ed6807ba4350" },
                { "ca", "1ca5a997869fe9f1097253cbf20fb0ea128e6a5d7af29d2a2eaa0ee04c837a280d05f8a2644ab59f072eed43d9cc1eeb58638675e103a61d00af0db0f2af8487" },
                { "cak", "da329e4ca78959dde96e5868c2e4a6e94fa1525c5b6f75a10e5c7794400878f8901e55559ebaa8769720faabe20c63e0107d1a14b09ed4e4edaf73357586b781" },
                { "cs", "92745ab7cb597782ca24103e287d3027c57cec6e1c9e29c5a970ec11344e40d49dc547a2c074c1710d8ab20bab2575080cf30a2deabe1cc6d11fcf5386dc5232" },
                { "cy", "3e9525fcfb6104042895e7dca4ee3e64e113eb1239da126e7ff31d82efc753143016cc8d31ce2243739d77b35ea61869d7ad2004ec3c2da63bb950d43fa8eb10" },
                { "da", "588955e014db245f987f934e720594f3d6092ee4dda5edaecd61ff7580f1d93b494d0e43c7eadd6c2ef159d87b085260924469a674873c20e8f094af351de7c0" },
                { "de", "97ec26823357e22469b13110c23b989213d766dfb348e9c7f4a21796d6d71b0c183219d7171e616ac78918ba4c813e759628fa65ceda8cae4a9d9a5191b22158" },
                { "dsb", "afce2860f92f69bd34f5bf71f119478728ab063812eb399c20f25cba6a7d6ae4125626219df3832e2ccba64ba5001c4a163c2e559992d0a6f5a46a93d27b4272" },
                { "el", "6640839c4527feec94dde9450696491a682450a170ec1a2c89273ba531a22680f635a50e6d5907f5d49518819010eb17c75dad0e27913ffbb1bb60db1c1d3b6f" },
                { "en-CA", "f4f0240bbfb81f4c18c072bc2f1cf4a856b578572c8b88451e4c36b475c647f042f94ee45ce96ca11ff824c0e56b72553aca38b9a078c270bdc35157b70124fa" },
                { "en-GB", "cb3aefe5245323e3d7d933db13c3f831b35d6d9a739bdc1d428e295ce87d42240e95aa335a6fb5bde6122433999cbf3fc4033afcbe7f6eaf13ff5183ab4b4c07" },
                { "en-US", "80caca0530876e32868cea5271cf9c5d7e7280851ca7280bc68084e2b5ab4a09259de76220b67754540a902aa7133716fe69e9282ffd2243f0b972c65757802c" },
                { "es-AR", "8901a72a28652a14e2882e5a0d3faf2892d569864209c28405d1265896fd90a5059379b160ec994be8695fd206eb1972d9b1a22aabdff11aa34802dee094beeb" },
                { "es-ES", "a1c2b3fb992a157d00c5dddf74b7962f8c942fb23192a21d4fba380e3914093a8b31a34500110b5534ce27fed5024ec00251b17c77a2aad27c2c700acd995383" },
                { "es-MX", "26c48fcccbe5e8b8d1e548186c50a460907a9ae80debf6baf8edaad2f82a02f213c22b77cd3ea9ca7e553d36cc572d83b18e169baff8bb67804da03eb9174858" },
                { "et", "d765d29940de4e301bab0603de03c8256d89793f2bdd80a67f43f498608dcef431ddd3a7594320e0829217817b775a0535cd8ed51226fbf2a94dd0e6312db02d" },
                { "eu", "68fe4e76490e34c2a6a5ab8892245a9060e7ad93c0e2ec552ebdec58b443c52750e86f9f9235373e082d33033e933e0dc1c60e371193f7008158eb9293d746e0" },
                { "fi", "d48a3d2bea2b8eb15c0ac1b20bf33140c6bcca91e5b6c626bc0d2bf276fd0b440eb247a5206265399f1122d497d1cb77f7709179fd178b1a94c03269a4c81492" },
                { "fr", "97d1a5aae9f3cc162423cab05c005a6b22d5f2316bf058ad4b9c631c84e9298249c7beffe4c0e7d699c6e21ce7a2524e6843297430daa4259dac0733eb7331ce" },
                { "fy-NL", "5ab588ca765c832d0230c45f0c9b69962ecf3d2b66e711bb4a57429f175f2e0d657c2212ca25c05ef11065f8411548174cf52426f2b09240e180443d11df92e1" },
                { "ga-IE", "057205970f613f8eae1fe7e039497402bb0cadd82e115cfeff998863dbb7cbf668cb42c25289eab7424f3edddea680fde9c6e165b8c5aa13a2b5d0c980477eef" },
                { "gd", "4f34d2c3c742c852597967abe9c88509ea06261a9d7958bd24f369c17df1d788073d3d0e5e9e750bf22c51ddf606b2db7589cca5a6ab92f5dce0832c183c62f1" },
                { "gl", "45ab531391abb1f0c0dd5958d71dd648062466a2079d21481ecfda8ac7cda1e2034c25e218c533c94e4fe3b0ed55bd0cc18d2d28ee8f75be6eb498f1d89ff82c" },
                { "he", "eb1759e50604b801cbe4830d32b3ff11ea4137c0d207b35654a6bae9c7a02e3bd28181cbb7f98e26a9cd8970e1b818e339c99c3f289893b196d9fdc58b50b964" },
                { "hr", "559daaf7cf931b709b1e47ac674aedd09b6eb47115cff98fba03ce687bcfb8b9ec08824ab8b109ee2ed8c4fec6a372953efc35650404fd9b343dad17e2756e3f" },
                { "hsb", "975b352f4dd77251de25616f861abbeb0105a780c974caedfc02f041ea761d65ca9efe085107ff1554b2f3d325010fa8988f0db19c69bed051cdf78e5588512f" },
                { "hu", "af2b8818c22c8dfe04cd704b7fc58fff0979c7d7f7d1c2b7f9933ce57c81193ab07fa7bd86a4b1f33635870ed76d8d34a66f03616a519744e9744f28e1fe3686" },
                { "hy-AM", "b26068900e1335cbc121bb724f82d143dab69cdfcc700311a1675a32cc2af7f8f380b47f0308edf32e3fa43f8f9dc702011182729f7f9f9348dee8b16c57d158" },
                { "id", "fd8793b06ebbb90f9f141da65d4f48161a6ab8bb5662f5f49d671addcd27e89410d78841a7443a8876e1c736219baa83544f04e59bc52800497b5fd46e5ee2d8" },
                { "is", "3caa2092a77a24a4cafcc65882a6703f8cc23cef9bbdb43291234e28983f7f66fce2aa1fb4f37bd4d4dd7c9053eb5bfe4df0297f2a068ad87c247024fed6a704" },
                { "it", "2bd7f817735e2c5d4710274e017b439d97fb5954e66f61832d24af1c7e535169662f44fb1487b8dbfd96aafe27c90bbcfdb8270dfdf9e29090c395a965a7626b" },
                { "ja", "010931b38ad4c51f6a9a20156c2caaab013e06d6087c839a31ace4eb7fb2db39faf833e6e7ec5cf70369bd8cc7fc00563641729b15cda8e8bdf56b40f6b62837" },
                { "ka", "c286435f914da10eaaab47bb46d9df920ef08bcb0ff13a51c0c73d353352a56847b9896480baaa5b6a102c3e1a8ae721373942e3e0d3084c0b576a33c882dbbe" },
                { "kab", "a78dc57fc26771f023b42f2b7198a0d5608e4c7b83ee48adffb3f63d925ca839e49d90d9167fe041ee8be784b4ba223dfe3fe4421e29df04ca5779886fa5e3e8" },
                { "kk", "a92493b499eaffc3044549b3a7cfd10dd2fc8bb7b4d2328ab63137034f19349ca09c83c2a662bfcfbe8600b391cb9ce85394dbf0a7867905676f270fe7efcd91" },
                { "ko", "6d22b5924fcf8daf198c69b0bbe76fc18ca1901288be8c8052867a52ed7beadad75b5900b71b2c73474f1a865b71f0e8cd875de240a400484a02bc4819ea9ab3" },
                { "lt", "06c043c72b0c16827ae152639595464fa1a6bface7a568c9ac5fad9fdff81a92b5a2886f1d6d3c0c6de852052d9c4f9e651306c91785cd3498c29abdecf37b22" },
                { "lv", "2eb1bce24c90a4b32d4f7ad96150c7ad0bfa134ab5c8175c8027b9b2fec679ecbf597f08b1c0cb6b498f76c892bc5d040cd2e401109d09719aa053bc7b2710fe" },
                { "ms", "d1028579d92949d9af7421b99bd47802203aa68420ada8c12cb95df299fea06647ec25f4a68edb50db8981390928f15d250e561434fee79dfc484f05977367e3" },
                { "nb-NO", "dc5164d41071f63ce4073470797cd12c15474ec12e372acece99ef8e85ed2a69be984303242e9e9b3d88d07a7989cf932cd77b0e72dcdb15faae99656a61508c" },
                { "nl", "f5c83e73dd6863790bc34dfcd72e74096746948fc55427fb39a9a2f0d7d81686c1e24917937e66c2a3a20d2cd77b93b0898ffd53681f3d7a96d170a2ad11098d" },
                { "nn-NO", "5570479f55b84ff2f0ade200feac845348bc998e52cadfdb6227becbd1f699c098c498f2ef53c27df2fd5c15d3ff5cd2475eb14be4849598459acc9f72b21a0d" },
                { "pa-IN", "8a7ab7a312da6f3dc32e98f9e5173ce2fc6730e71c107319a15819c81f909b8279d90220d5b57ba2f01dfd89c3c4377e6fe5a31e55ce2ed3ad6d614566a8d176" },
                { "pl", "13f59b131455bf60edfa223f03c669c7a81cdc64fe7f7dd246c1387d4fbe298e52c7a2d37f5d49d8fe0bfeae3500d948d1c07f761d2551a5d1f521c019e5d561" },
                { "pt-BR", "8d7123e9a0259a3bc4db52ca62ea7b45d4f605b8923c35d9370762278eea0393ebc02029cafe01227121f63fd631f9290ba2c4cf13efb3517c7ff91e2c9106f8" },
                { "pt-PT", "f9201a0459b728595006a7443ebf9b61d6848be9b3870148d5aeb25c611d39605066b143cde556a9b61154df584a374b884fcbcfcdcc82e9b706ccb6fa43f187" },
                { "rm", "2e78487237a83a0488ff50f2ea7cd6d5e0822ac917586aa4b21eafcbec5afd66f4aa95ff8ec19c453b0a4b1dbbe95fde7b219bb7eb9d95a63b64be9a91c750e9" },
                { "ro", "e1fcfdc8cd7631729c80bd658a7611a17403bf76a7a6c31ee65835950895f70d5aaa46f7bd88876388c72c3b3038e13039b4097801a08c3456f76654ce363ac6" },
                { "ru", "39685bae8b4ef2aa3596453dcba1151370058ecc5af698ff9e95d052b3ac740b7b19054eeec929c207f8abbe8757cd734e370d3c30a6786227790a731dd09adb" },
                { "sk", "ffeeac2fc22106bc77363f69319dffa9a6cfa9f76ce39e6ffd9a5121338a129303f2e4b8c12ad0e2f4685e71828d4138c5ad8485b4513b67aa86241dd680f04f" },
                { "sl", "c462347211eb0f39cadff21d624e5851ea6fb5ed80d904507fdd36401457cfae6834282ef29c9fca18570373601ab5ad5609dc55ccebec501bef50c53809dd5d" },
                { "sq", "87fd00e5e8f034791de998b80857d19ac8fa62a7f1c02efa692fc050a44fc1a94e741bd2cb0d9f352927d032ebff244f48f344141d00b194c88b88e2c8c89eac" },
                { "sr", "3d42f331ac85fdfac4deefb4ee2f06e100f4c64d344c36de0355375294e2abd148de57fe068651dd9d607df3f3d60bca42354a4f42f84150a29e5af683dda2ef" },
                { "sv-SE", "44cc1c40c00bdd3972348cc62fca1071c2824c5c6c0d3a7df1d79143434a95bef5b1e28aea02382716ca7eb7d6de4c16f48661aefa31c8c907d4d6f5698012a2" },
                { "th", "d860ab0abc2322685da7d1dfb7a3604c1f5409224d1303230865e84a075e4fd4e2abb9664120b09d90030de5d886e2ed3434e29be3bbc2787b6cedfa5a6202bb" },
                { "tr", "70d201c61ed4613402fe800472529f70a77f970a9620cd55ced08f764b6bd3f4c1b82dc9a43e46518ea4b20546952fc8fee8710822e38cbbf6a1fa6fab0709fd" },
                { "uk", "39d8cd26e3413bf7499035b67f1b55a6277a2817a1be6b67fd9879f611982734d2700c564a35ceaccc1dee68f7d5dfc66053ef77704c9f0cf78548520776fcae" },
                { "uz", "0f6d3826dcb6db20591ef3a44311c432c2cc8041c375e37b3c447384f84f97a48eff8e2ad58ebd9dd58c4fcae01388004710ff1c56b325f8f95234c4108c9d07" },
                { "vi", "efa0102cc68fe958d30f854abecd13de2b7e474f8ad6c55402b3a22df0432a448d76a76f92bcd9861839e4670e462be6ef8ef09b255229e4cf576b2d904886c2" },
                { "zh-CN", "8cc4e37e7a729dd2b35fa31498b64c9eca1b44266c9c1d113f6ffa96db8b93cdb185122a7f613abe9a277c38c3c3c360e93c28a5a216e265770c384d8774cb01" },
                { "zh-TW", "1744927bcdc6ea08915f2123f695a6faeb01d7292fd7c07b45cff6de717b533b9d1a8cd3e79b7d509a733b8d47c01c9d3906953b53d787189752ca9f5702f6ce" }
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
