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
        private const string currentVersion = "142.0b6";


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
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e892d50e1d8198105feafb495cd1e9255e142d83d2c78ee23d3bbce43bc4c8494e7f59eb651850a53c623b1b1e4a0383f8a310b712fd0d7fced9aff5182fa3a4" },
                { "af", "e6b77740d4137b7a4a077cd97a5d2a1113504f2191e7052627f4c5d542444f41d1e389a5427f0f5bd5d043c95e85ab1248a073fe100a098015e825c29988c5a1" },
                { "an", "699fb242f73d5208d9005731b367e5be6b6cb4c73982b28d8400dfd09a27e1973b7f6689c6cac88ad89ad2e94da8761845ce8825da99c9940f94bdb30d7ca7a1" },
                { "ar", "c635f46b485029ccfd7e0d7e5ba213f5f1dc190d760d870d8cf9e9ec81220fe5024898a083556b1ddbe0851df4a9a97f154e5dbb1ca3dd775f2f8949da8a17ef" },
                { "ast", "4d28f9a1cf1d0b4693198948814a920e5dbafb8ef663a2928334f2414221169eb60725bd6add4d0a089a384e59555485431ec635983289d0183b2c957255e300" },
                { "az", "63218e19ff4136e6491d0f420f8e58698ad41af4e2a9f17cc3f731b0108146224ed5775437abf8138cb7f4ff16e9b058ba630469356023f0c92acc6caf643e8e" },
                { "be", "6e1935f82eb2660abb0487ae238cd05cb5a6d395ea5b5a906dd062736e70073bde42d89ae8813f6b9ff2d6c07ef995aada10a2b6991e17068d3e4464f9468778" },
                { "bg", "82f4dce5d5d14b975421294dbfd232308defee02c3a6889aeb9be61dbf880712c1d5ac39b3c15ac139bfb6b692c8fcddf50bf22b5f4b627b634e02dde7e1b19b" },
                { "bn", "f7f1936b655e7828c01b74bc8ec5f3ea8662e519d12be704e0edd8012e664cdb929c5a76ed42682b9e389ff43afb519d902412ff58d7d383c9bfd0aef1df1fbd" },
                { "br", "f1a31b3f54c079e180b664ce57d45f518d56c958fe7f658f40c1382c239890f889a374731bae678eeff3da88d01024946b3b643b4669c5446b37b7bfeee48aca" },
                { "bs", "c713a402f72e65b41838636cbce757af32451e5d36d2adc6d1b6aaebaa99e350b2b1cd8db8e64acc8b50380be8a4b2035d66e93ca7f7767ebfd035537b690e63" },
                { "ca", "d32a8c35209f0941036c579e14ae4490d67cb060bc5744bcd9cafb4da0914ac9811560cab6f79668dfcfbfac24a07a6883dcb8209b17ea95ae43286ad2be7555" },
                { "cak", "021756ad64209f0a9edb550cbc42ffd66b0b01e941de17d63cc20f285dd558f6149f373e9e6aa55f89a44859c6a2ec98ba0b6cb0a89c40b2eec497d051322c94" },
                { "cs", "4eca7139077fa7fd8454676f5809c2f00234f436787109511e3d73262e940a579595634a551a659fcaca7e23ef7d399e6bb2a72902dd2667418268e5c72941ff" },
                { "cy", "b6d5752a803c2f5d6d2d119dd62f967348dbe14d35e9c1f25a5e5e58f548ddeebeb9efcfbf63424f02a80248d0576d1d7190917c08aee4e04bd3be0a09344146" },
                { "da", "24dc32406902d058116b880adaed748cd81dff22dd0dacd13f55446ef133d5fd68ec637c0ac3ae1b21329aea96fb9d64dd54aa7e602a8da16f0084bfb959d03f" },
                { "de", "594871063a702cbd3301b9982824e6da315cb4238846fd13d4fe2cbb5384ab26eaee422c9007b45685ed2cbc0f3e5dda5315f4b3d566231c974fcb8f2b2a595f" },
                { "dsb", "58629ff78350b0b6cb6121c6015287ff17d80dbcc398ed34dffb2b2e8d3f873ca313e191f1e2bf83b07f261f275185d1bb4121047008bdda09324e9f04b4927d" },
                { "el", "2d48f3dbabdc25aac640f7ec95c54ea0b56c3d4df6860c80aeedc4a8d9f5d5d05de62bd679685481e378cd79b07a7944f876250280aca028c8c27243cfa803f8" },
                { "en-CA", "9d0631f5fbb043a0460d89839a81588cb29e462d0fdb9bb57f413c61dc7a33bb976093bf8839baab518dc2138d8d892406359cbd30cbffbb2499f1330576a5a9" },
                { "en-GB", "b6ad25e8db84916ccc74c8c0ffb6ed6e410fc99b18f1ac49b80ca37bda133dac4f8d2a42c11f6ffc1304d0f828e9aa3ae620d04f279cc46a390f174ef969de9c" },
                { "en-US", "282b4c61f5aa43ebce9bd47e5f8580b5e19ad50a8a483a21301407e1e0076a3903ae3f8156cac03f61fe20ecfc3d4de974f2ee7c18c3caab0ec0a5ec184e0e5b" },
                { "eo", "6aa7704a2a77483b727a5396339bdeebcb62a70bdc75b92aa8a2787407eedf7f8dfd7efe8dcd9c62a05574dcfc599631fc9235ea5399c6998a6d80b54184a378" },
                { "es-AR", "3842e6ddd98c64e1cd1771fcae250162e28ae77bc752de550284e91c8d2711688901adee2548887d91c2ba3fd394a64e5fcd15d6824295dac8b0e296b4aa0946" },
                { "es-CL", "40a3e323c6bf1dda9861cba978711df603277f4f6f642209b1523d275c3f751d4f1f938bd3aa85edc8484240b15273f99b17543146b39a2835b82ea60f9e69e0" },
                { "es-ES", "e58f0941cef7b38c28355429f0b79f6e3429028237c5e8440bccaa85dc66fb3c54d718f365a22124d6b804ac03a50aa2eb7e5e2154906b1e7b1d7d40766919d6" },
                { "es-MX", "2df86dcbd4e131c7c6d712cc25d061941c131c12b826247ebc69617ef85baa700976d2236df83df6296ded20877ec0d2f4fb633fa42aa58fa70cd9d67cb9d129" },
                { "et", "da32c919fb3a7cc9f203852f6f2247b852aa97ecb0bc2292399dbcc7ffe37e5cfdd03413911e53ad94479f57f25644704e93d6cc5316b722e84e3f68f47abe33" },
                { "eu", "9a642c76514aaa91c0cb0d52621552bca9a441e2816f099898ac467fbaa449c75c4d6292469a815143db591b495163d858b82c1bd847b9241a494647c0a3cd68" },
                { "fa", "97b53ede637c80dc841b0c70907a63368d7601428197da26f0ea28f632ad4880184a65daf99b3fbf457e106749a67fe64e5cad7bc6ddc5c74b75ec3fc0e2c52e" },
                { "ff", "15cb2e80bb3046dda4d763130e57f95faf6688e3783be0afd6a8b1fbbebdc48c56208a31a0693d0b24f3d0bc6bf0f0494a1f361e8a311c7a9fe52700d1cec764" },
                { "fi", "98b3dc31eb6cd8dc28333f9fecd6303841eec9674da32a1bb658b5c6f2d820c72a8803f0411c283d4340319c385c346a149265fa4e0aa19b605e4dab2a77be38" },
                { "fr", "02ef842894abc47d4fb5ae6ecae26661ebcde8334e1316b43bab57c829dd04d92b953ea2e9127964f583d804374a97519015f8b9d20c4254b5b465f7f1951ec1" },
                { "fur", "d0504ae42920f6d6f68fadeaf0a0ddff9d3ebf060c0b853dd03d540f8bfc843489ddee6c1cc19b5036654333c050770ad85c3bb4805425e4928ac1b7368a9933" },
                { "fy-NL", "b340e2ee5bc8a9dedf954c752d9bf2f247eb3acb7d30107b05192a155c5e7f87073be9f644acc64f1160dbf1b63aee07ffc386daac78a6da8bc590541da33c8a" },
                { "ga-IE", "97e96daf55cda9b92620ab7c8ca8f8bc24441a182ce1a149abe5ef974fee610c38cd02a03feb4c1ff5f5244a4540ebc66bde8b91b106d453fff89114d3a0f877" },
                { "gd", "6384f8466185305b99415bbd3929150b4a6b2b2a5647fe7e7c032bd38a41acfa27a7c1a137b29ca9ef9f32e7d0cc8c8a7161774e79b5d4b1a3c8cdceb46707a3" },
                { "gl", "dc9d525c47e4822be4db4dcacd8b8f3a13faadf9854f8e771430289864a50b66ca8c97cc9101eb740f02e365bd62e5c47fc6a88c7148f4ec422ac5cccb092ac9" },
                { "gn", "75456e184525a049abc076842f939c08e6267826e8c8e327ace7cc65c6a83f1fb1d2f1fc90e33b028fef4a9361f56234734be1fcf9e5bccdfc2d155315df8d36" },
                { "gu-IN", "a276139ae9da65a72c3ae5a30efd0ae5a80f145f9856cebd8ad19b532d1116b1bf6af721b0a298911ac89a7b60ae01ca2c28f5e3c833bc20fc8a09d5a468e847" },
                { "he", "32068d51a7fcc4ae7d46d21e85e9c9de74b0eeb0e6ebc82ed464cffc2d51088409e83a8c049f9ead86717213d3fcf2d379692c8512db4e3ee5777ab43ea8059f" },
                { "hi-IN", "3ea3f7cf5f80ac87639cc2e596381cf598ed03633944581c1f4957438462054162358f7c2b7cab536a63cc0cf4070716e8fcdd97436ac30a4a744c6ea92e8917" },
                { "hr", "9620206a1d55ac089b0a2eae52c545ce5fe07e053abd9405c9cece817715c0eafbca38586138091a8eca4a4548f7c724f269f8897cd9980340832255c9d6f58c" },
                { "hsb", "9039e0a5ad3e877845b86bf1928593ddf825aefdfbb80facd5683cf0a557ec6d599c06163c9e465264a7d1123c2f40538b87303e039d0acd45fea08d0d9e6f2f" },
                { "hu", "95c0447aff820dcd2457ded7bd2a8b53f4f19477a667561d5d9f2320c663c180bec8d4cef7c4977aa6af135954ad0864e492488b294e8e461531096fe211df15" },
                { "hy-AM", "e3861172810a34ebb39365bb237476fd8d9ad5e3c9668e02607ef14e226b92bc06e61ac5cf04a2e72113d1b1fa0d604cc46506fe4236dce1d60dc4c3b56b54a2" },
                { "ia", "ff1a7c846de76ebd33fa778b8f2f223265b2ac010265f0ee108d20c38035f97fd22a83d8f314aebb7aa0352947c7e47dcfd2138ec31d091e8e2e6c8ba544cc3f" },
                { "id", "4563e172e3f6f515e5cdfcc3ca8993394a2fcd96baa6996d38a1d5759658d52b24c116078b84109594abf90dfd2242787ef5b3da755b9e74237865150d707a4d" },
                { "is", "cf3d16d97390890d1c8856c58f67fdee776686a247b6ea4e6522bc18e060f06ac2ca6afc9ba023b8f085b1b4aeca74d1780a3a34bad900671d8cd03b13030b86" },
                { "it", "327fb40262d001f57082d8203badeeca52e25b21a2ad8ac907837a4d3b575aa8f5d5130d1bd13fc0e02024b60c5a83aaca8a87e8aea2557feb73b6dce910ae6a" },
                { "ja", "9bcba8d39e447acc59161a1a9dd151553e3b08d436b7fa41cbdd22f1ab72e505e9a9e6da048b8c34a0d332cf288dd1aa537a1e2cf9d40b0808e6b6611c904afb" },
                { "ka", "899c6fd1061cd1c027a85600f40b55b95bad83480ae6d5379c26db85cced6e1662400848299b2f5ea39fee2d56701809ad72ba3406519b8d9e971fb825826ffc" },
                { "kab", "cfe752560e56a443623e8e319036980050bef458f68eb8fa60b70a29b2e625d99c97ecbaaa2f7e30b759b1a8963fd17047ebd6d2ed7d6246c82213335671d442" },
                { "kk", "91e2b73ca947ce3bf8a0640d7bdec738ddee2a9d87791c3a228273e37b6ae14da9e20c21adca2f8346bdceb180f8b9f0d0835aa4fdd74ad89a0cfb6e421f0789" },
                { "km", "5a20d529e879b94ab45d4dc41a5727634d6460c7c4fb822569cc068a674fd875dbceb86f0081c82fd3baa0ba99dc28503d85d2dd8592b532d76667d86af9f6c0" },
                { "kn", "8003ae4b0dd2679d93c6d5ae1ff9b11005a9ee5267cd7a9e499e1d1fe21f86ad7caa67d4d18a3c3748a844c8e30d8400be060909477cbc7c4ee6ab4384a157c0" },
                { "ko", "5e7c6bed5eed130cb32324e4f46eae39c6e9e5ce44d786f09a440295c286cd93ed751df2bb9ca0be50e712e1e9005849f43e0f950a5a9c40566423b8f2a9548b" },
                { "lij", "4c19bfb4d1197f9891d21ca607e4eda1d4cac80c2da1c6cab07acb89213dd901fd71cde108ad238ff3ceca5152052134a0d5c118ea5e572844501f38f9688f76" },
                { "lt", "f385a0c873348a291f2cfca2f750148ad0c1295266221c5f054bdc436a29a53111b64fc01be29e47f79e332395f08e1425867b62cd9bb1c0735a6634c36b5ca8" },
                { "lv", "a298b73fe5554affd1a6e934e3c05f50f57d28a8f12163ef232bf9ab3b3132616434e05095ec345cabe0e9934f5e765a338d37be2bd9d562c42f99b29f50c8cf" },
                { "mk", "f0325b70e882d43b4a45a97bfaa9642cf353e4665bd2ecea6a68c5dad942eaaefe3ebd1ab4a84180b890e55cdddc2a5416e504de7010f84e0a04cfa6e9ed225d" },
                { "mr", "037a33b439aae5ae721fd3724ad0b7dc4fef31970436f4546401354dd762e49775b293c27e7158b6bfdd5c303ca5eecffbc666d0f44607243dc0e4e91bf2b594" },
                { "ms", "16be8bf44b1d1add0ccb92a3b7b8c82f2c4ee7d57d9ed48609b7c68b24c86693da10e38cc52674f6afcf6fc258dcd50fa6e73dbf56991460fa95481991adee98" },
                { "my", "297d5f1470f8c33efe049d8a877a070dc059dbbf09c8f9deba211650e8eb93b8c715a1b19196e94083a33c35bcba0cbffbf9ad21416817447aafd72792aa9e41" },
                { "nb-NO", "b5ee5c764e5684f5b2c17d13d5cdfef25e439506571c2a17bfc15d96ce9ce62dbf1ec44cfa9681c8ac9e58c2cd24f59b6c10185cc35579f6e7f7909d996ec3cf" },
                { "ne-NP", "f0cf13bdf83c1c09624fd21ec6df58a6b57399b7f8289ef66cbddd41a2d3802dd6cb029d20453cc18e1bcf03247ecb34604269ebc0d878ca470f7f9cc634a443" },
                { "nl", "6711848217cbc142e3a538f5e013b10f11e779cb21866614764853e5947edf53724353a0aa9e5742a2222e7c593d944f8ffd845e520f83793fc39ef1d703e04c" },
                { "nn-NO", "6e04ba53dc8a5b267de3623d22d6ead3773f8642ce0c7bc68c5901364adefb8957dbcfeb59299c405b6cb37dc7e9b7af223721bea90f73643e466ad416577f05" },
                { "oc", "aadce1405f45eade0474ea91a4ccf8da01a1bddfe287390a09d3dbf547d3d1319e51f3b2e2fc553495be34701d15aec7582ba7dd88b8a65c2d4d01454a462338" },
                { "pa-IN", "d961cc446863192f83c4d813eb85a37b44715f0f6507d942c6c342524fd548f83fe50be770f5420a2b8b1907699f710af7602c1cb58582ed36bdf71a2dec1336" },
                { "pl", "ac040575f9535f6007c98d9ca5ddb033131240a10db6742bc3b86263150c86488dfd22f1facb242a4961235f22c7857b46831bb406237771b14e6f8cc94a0c23" },
                { "pt-BR", "0def7f7e9c68f6e15973c2f341cc5880b2a1bfd3eb2f46395fbc6347c6849391e5e81c141496e512e5a063ab43b799c5f381282ec4ddcd1b3d3a4ca828cd2bb7" },
                { "pt-PT", "d759b58d7f5cec4b09263f7b840a1643b6e5676b8b676408945f1f92fb1ed69e5ed446736de96a04159100f4df13966fc329a5ec52a63fa4c912c00a2c0ec7c0" },
                { "rm", "22523dce5eabede43e4a678d2f6430e9a7a4ac7caa624750e764626e176db2262fd2a2d90bad255a4cec7b233d4df4bafae00f4eb42f4937c79a6d37d1e31766" },
                { "ro", "d6c699d6bc18ebb848f3a95d52e1b90dede0f225d8ff990e3eb1b01f74f034f6234b6ee3c91a4a1ba059611457b21dd0c5baeaf806b3c49a0eb6bb139b462616" },
                { "ru", "d3849a85f796df283a350e33312b71154b7ceda944459bdea6970290558ebe390d95c09fc071555af9bd756d550a9a8933a6f3a5691eb7dbb6f4b20a610cd476" },
                { "sat", "d775e570e73561905d9a7e3b431268a75bb591d48c0330fabf5e371fed5ae98c5096ad18f9ee64d2cfb828937db1af9a1445f1279d85498f13ec6324399ead66" },
                { "sc", "0142a4b16d9d99c2fb2a241c1500a537726b67d126e62fbc81578195fd6878ae1ccf9e302a022e1b8aa1b98a320cfe297057713da71c5935fd80fd9cac2e64d0" },
                { "sco", "b51b4637c2de8978f1713cfe053bd547f8db37b75093d7b31ff86ab6b0b7138edaab74966b86f1ca028465aa5477577a34694387d8204cc88f570a1c181d4ab9" },
                { "si", "59c40acebba4051ac33d9c068471116883f8cc52fb97b717c7da826968255491cd0deecd0edb3cfc6606f6de072eda6f5e0f2d98b0440fe126816ab232bfc8d5" },
                { "sk", "50518472db8556ff67657d1cc24688bf87599854be00b014366c411d95baddf079d5f2f2389e4aed3e334ee8d1d6530b59bbd37e6fe6f7db5cff9ac74385658a" },
                { "skr", "a012bab761b5db6544fc18f76da1b23ed272fd4a255504c89043f3164f6f39f7e3b826fce62a59153eb4e11a35d2d3abf3022f37a332d62bbf6ed0b7a47d0f50" },
                { "sl", "7baa566f0417721d8e294975d2fc1599ca1bc06afc20fbf9b5dcb25419cb211b11d7d48dad6601e64b130ec2842aa798caad0317ae2fcabb6a35467fd26402c2" },
                { "son", "992a5028966f2477c2248fa4071ef93288b31c31462409c5db24b6bdf85e9950c6c75b799d172a87653c51195519328790dd6a64adc2687db6eba40e41d38185" },
                { "sq", "73496a5056f0ef4f0df703583f8d3239447651a2a52f36fae831ff08c04a1d9484158d86cf8e11df1ec89dd96e42274373cf3547518e06ab3a3ef47d5db4274a" },
                { "sr", "eb0a6740e764a2a536f076e142e848b50115fe47c087e7907d4f06072795390d265831bd8672c558c7983c5ab1e40fd35092e9cad09b3e26a499c154e6e88e73" },
                { "sv-SE", "3b98722f8a60175999731a758440eba24ae704deef0b0631b28b237d27f533ee30aca0705875dc59a5846e1a983a1f36fa37d0d69ad6c540cff53d34b347d057" },
                { "szl", "8390f9bbc1351b104a7f53925ff6ad62cb0bc96c074dc52052da1e7eaf088274446debaebf7a6f9c8ea58ca273cf3472eadca2253708286e05e49818f0c8fa5e" },
                { "ta", "2671aadd984216f10ddc79c8ab34785765b7a39d5c88a64249a7456d6610e45e117ed668e98d071c04e171a0dc97516dc3286cc641f49a01449e7404967a8688" },
                { "te", "185512c49bfc2068b5d9647c3577f2e1c2db16667c3776b338567f38491b805ac7e4660627434238dcf97ced8fc6a0c974591cfd05a0a968942d554aaec9f19a" },
                { "tg", "ec89980275a197e2aa5c9153edcc21b8101a86fd1079d96c9a7070f5834cb0ac3ffa946532e4c4de4cc9e0667e8bfcbb0f0092490e8734e4f336c6a64fc753f6" },
                { "th", "f2157fece38a90b61dcb7212440c644b1992cc10a0a9c5ed806ba4cead52dae3ec3cf12e22929f2a8c10686b47602a30a43104ba62a0ee47906d851717361deb" },
                { "tl", "e577886ec76eb662915797602a8506aaec25b6573acb0eb2779fcd5c109c2b8cb99136471688e8f03d28bef3c537732fcc0897a58875a669700cd1cc598044af" },
                { "tr", "23295e22cc37ef4281e33041921a9a8bf7c7765c8eac30cadb2f00aee2f3fc291c11299d0bc04f2bf640e7178db441f032c73308afcf7a04d81b91159f31e022" },
                { "trs", "c87df86f9229d9acafaec0c1f6624fdc5047f8600f14e2022d6d9d720fca8b3b94bc4f44de1ebef700e63e58223744b428b4619df4b792c9666ce3e642de1b12" },
                { "uk", "5d717791364566670468a0bdba10e1a3b0ec7762b5ca0a1eacefd4cd353011b1efda10dfb9c1419253b5feccc7f586fc2e09d38ed2b374ce997e033e3bf809c8" },
                { "ur", "84781d554dab786d9e58900634d4b013643684a228a632352635fb70f0880dcc869d68174820228b84b2607c57d2378b7c1255379488b580705138ec64e3800f" },
                { "uz", "e2e4b1448881812f7ea172eecd2321bb2bd6f96981bc6b115e7de4742065634c1ab4cef77803c109f923caf6ac17a22084a39d5e21ded5100e32fe92e344a4c4" },
                { "vi", "7302f9793a8898b4958b7d97b4c460098e2c08331bc51f900ba2bf532ef54d804392b013d4741037ccbac3347a27560f7392c8ba985b697d8f069b9092b69e98" },
                { "xh", "83428153ed41b6a0922dc025169ff873cb26376a79515eaab4bb021ba00d62d93978d9660be7a39d8d62e9df45b1cf76bb4eb61b5ba7761a9ffd085a728c8565" },
                { "zh-CN", "071d336629b72da4e6de64f3c8562f0a8d0c3e2d86889eb57e9e596faf32d7bf3aae3e11bcbd543743d82d80a7bb91665048ff2b81485030e3ce34e4db0652bd" },
                { "zh-TW", "e22464c9eef2525b1a3016c1456f067826c7da771487bee66bf79b2302ca2c9c3679edd3dd59fed282727810a27af860ca1b9392d00d4f59bf6b0d8413fcb73a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "55e797cb5ec165b7d199d8bb6badd312d72d4486cf6dafa829fffd484077a58f766a71f784bb17a9fdfc3f8cd2af6f493d6091dc1c940e66be8cc844eed691aa" },
                { "af", "86e4174cee3a6f15d2fde2a07fd5034366efcc71f071c3c69bb9bcff6b4c4134994d504c806e778196fc2666023b2e4e48b337f98e7b32141f6fb8b68feb2fe9" },
                { "an", "260fb6bc0d45156296a8cbbe2c7d56ee6090f1951e54bb278afc5d53be2c7e5432f8b8249af75c0ec9448f4ee44a554cdfe2fce0549ffc00f24f9a3707b40758" },
                { "ar", "79ff163348e14c182387084687e42237887e01b260d329127fb6bd4da8c5ceba461e4bbd274f00dcd94726380edc501bd8686eeeeea624fb55b6fa50094518d2" },
                { "ast", "e2a8371c631894009fa89ced3a178485cee2b28cf587cf069ec78bccd44d5a2188f96b2c551be086dfebfbfef6285fd416f15e3976b0eb3b33cc87ad3947fb6a" },
                { "az", "05e8eb48ec8df69950f46aeea632f0b345a65a46401095d21943097c04ba8c101ebcde2a060e1a0dc808e92a013fb31e22036339fc92e9446cacd51537754a9f" },
                { "be", "f9f4d3b2f2ff516343ae240ab82611c56c1edaa58f3917f858b293b1fda44fcd61c5c8a73d35040fa282387be29d27c1fcdf7e0725e26fdde5f9d7459b1b2849" },
                { "bg", "b69d6f2e48871a69b6ae9446fc46f9f0edf4014b2c3a33e8ea981f715652063aab1b947677204ee92c405f120c079ee29dc2776eea760fc195d64c89160711bd" },
                { "bn", "7a3b6f1f12b8474fa6a289782e9c72eab1df52a54275d384190884ef2eb8c2e13abf2fd4a9babc9c49a938cc038f0d72ef133af8a027cbe55ebd2d6d3b411172" },
                { "br", "71aaa5298f26337cd155548bac33d16fb044d1be2b8a716bd41086536801b3a3d306f4a040ea9ca2a269a1812c03a1245357596488a1254be8aa7265a80aa710" },
                { "bs", "14f59f40acfa15e5f7466990f7e700c8955d394c0a81995297d9fa982e05b04c104a4c9d4171a39a68969d9a6e06ed3b2b3da7ed4a47a742750011ac0923c661" },
                { "ca", "048e9d5e35cf66bd2ac368a2683445e9a5943bd630d24791dc0cc35f45dd54fc65339446a065c5b64c5b36899e3ac5f275214d3c81446fffd5db84d14161e677" },
                { "cak", "012f004e954b8bf8ef2f40d8ed227b31748986500d847279985272d62e4732db04dd5e938aea04bb38872d68322efe95d46c37666f4a776c830fdf29c7e4f4f9" },
                { "cs", "66d70a123f45980c9b10126ad349d9d38e79c73d43b18ba3811a143073dcc70556ca4a007064c5f4402f9f1b7b39a39fbec6f93bb136c35a8bac9a3933357dcd" },
                { "cy", "a73ec2268a8059f5eed15805ee04f9785aa72ed4ad1b07c9225bb44dcd6749b8b0239c02499d8cddd39461a83165b20d04242df7d5bebbb603dea1fbf0f065fe" },
                { "da", "973ca8f7456ad8b45f995f0d4f0cce044ae58ffad8876ecfce53243127eecd0fa5d968bb1e004fa9d3cb379b80fd27d48753275f657e27e1d37f246d229a5801" },
                { "de", "de57a4884a48944fdc69636801f954afdaa80f32abf8881e73922b2fb1e248e0335a9f6211ba91501e0cb578f04baff9494c8398036c61353ba3bfbfe9881d7b" },
                { "dsb", "abc7a7292bce8f900e00f7fed66d3da3f7c505d4c383dfee398518346dc00d42ae9ebf31fd1220d37b2cc81583122e8ff55e115ec750f61d04787446f29c6df9" },
                { "el", "f85e32afcb8cad23efba62479787a16620f225e03d6618007077a08b4243441520a39c43de7cd8733940aa59db55976f9e1cd17a404e81a17e84ff67b42869ff" },
                { "en-CA", "fcc39c5413e9735c53742fa197208dbaa8efdba95794de0dad2fe8c5d759f355b3e9834e3ab4a415accfac29c805ede80d5ae2176708cdd88606280cb4781a61" },
                { "en-GB", "1d658fac2d3a0622e7cb7b7ab6639392c432f46bcd6332a24621ac0bcf77d30d051e0be4d07f16b9e2a21b2d8d9b02ef29ed9875f442216c5678938f2576409e" },
                { "en-US", "e1cb3175d0672dd1891ab512b832736a6c4ab73da6abc0af9e3d4a078d3b380c8ff6ca2b061d2cd17e49e74cc8649d0de18873051b1098e9f4efdb3d4aeb08f7" },
                { "eo", "b5e00d9dab351f605e8fcdbc465b183c1be7c6537d4f8f27cdf4d319d70bd0ed02f56b2f4db70c4c7545e740380222845b1f56b35303207efa240b1ffecd6c80" },
                { "es-AR", "af9a6a2e9262273c6f3730fe92cfb4e1d89b53a5eea811bd4f37462c763e16d65faac2f10d0fb14410499347e438790914e7c5e1bf59d275d0cf04a63ebf37d9" },
                { "es-CL", "a8f10c7eaf7bb15ea779e3efa9e9cbdd7e0fcf9c2f2d12f8a92e9024c34b84dcf058b0f3135ebf7bd2fa4416a7178a0a897f6d932268566711ccae6037fa75df" },
                { "es-ES", "194410ed48673babce8a1b274682acd7c57b3e983bedd1608e8c3415629738fec7e3d43234389a615e0bf1791bdb8537f0f6323728caa42c9bfd7c5408bc65f2" },
                { "es-MX", "3f40bce803a159dc054e8646ddcf03c70e0a92364b17f8843f3c5b3f34c8c4893c80f4a7bf9b20c5dda8019d8c2335f6d06af35387f464cd219129900391cdb8" },
                { "et", "f6bcc9422dbed6ead993ec7cd9166dfb947f6e7d0a5f76eff7f61860153597f6a79f51df3358d1e8b4b17245cfe9a655bd0d03ed5371ecd45387dd4a509b8673" },
                { "eu", "55ed0b1dae04ba615ab51cd3a18cf7876ff714e387cf0d98b4ee5fc9bb28939324380f53b11fee22c2b04f0a159c0f30b8c6a1d6a41f3a52066d199ae6b4b865" },
                { "fa", "341c0af0564322e48b68f60dd425d933e9847ba0ffa70f4b62b7652d2c458664d3cf142b020983c03905793e7d7e456796a790b51ce05b224f3af4c2d2a08214" },
                { "ff", "36be6fb0a10d0c8cb85e6dc77abd0089bb5b870ff9ca60d55aabf1cb7f5c35ccd93aa89df049e38433e59e7478bb519143a970d83a6d10c2c8fa68bec0c376f1" },
                { "fi", "27791df047b4701165c64a71a929078eb5c92ea42bab008eb78aaf9b53d0c80320f1d8071e67994ea4587bf40d5b1018f9f9d7e72e04036e09507a2a08f2e108" },
                { "fr", "855c5dbda9fc01d5ce6c382246b72dbfd8b24cf9cfdfa83a1b827b2ac5c450aaff92dcd4e23f58f40cc784984d238b7e929b8a1afbef14321cea15870e72de3b" },
                { "fur", "4d14057b7f9b77879557234f01762e6c104985a49919ea0444674495a1f844662dc9c28f859f2ac00301f99f3322a440d57ee3a611b515147a9499540636694e" },
                { "fy-NL", "d6cccf2071572e889ccd16f237d4052ff79d2aa0aa4379db5d47a1694ca8c6db38051072be1caab82b62cf27c36bbe0aafc2997273bd1522fa872403b0af2109" },
                { "ga-IE", "62b8897280ccb75ddf44d46a5e0d2532ba94edd70892c0761d079df7f0882bf40fde6315b03d34898dbb7029db084e2446dc078b06f19bf463051398078e0649" },
                { "gd", "af9a652d8f1b8367d0ecb6927f9cdb80dc5b25774f59f0fe4ef0b5da22808f12df91cfee7545bc4eeb033492af0eb8dff127fae1b043a0042719ad745f41c642" },
                { "gl", "dde0f72e6667b330b2ed6a7d6642c862430aab986aa8e847ae277e48816c48fe7d494c21690947d866c65a1bd5b1c65a563bf976036c12c3252138909830bcf4" },
                { "gn", "8854f0c29d38c560b72eb7785673350982aa73b6ea99208d12198ee4a598ae4f03e91ad07298c0644681c14c5c9d425b1bb412003abc2e3a58f838b71af4d5ac" },
                { "gu-IN", "ed58b5991f0a9cc0269a18c24c2595f3496d74fba08133713eb331c03dce10f9251a207fd8143a49a285f4bcd5473e79713eece72dfce390170850d5f75cdb4a" },
                { "he", "d7325d0124b8a722dccb0077d8a1203ad8bac779819a11c3d19ba444c6cc5623e357006d106214d2ce983c8ac557b73ea59a4acafa8533963344437a6c5a8a78" },
                { "hi-IN", "aeaeb6ec7df11aa41dd7bec829174b95162f7c867463e5e621322e6f83d59568005ec3b37f8d6438cfe04451ea82bedfe4a417cca072cadbdd9fd9d991642671" },
                { "hr", "b7bda940c7049b71c68b770c4b83e67eed092888280059584b3c60dba1f3785a3986ae6170b8c2e11b82edec7d348ab5376377569630bdac9a51b66c28217f08" },
                { "hsb", "ccf4ffbeee7d8e502c1ece0f39124519405b7fb95fc28c5fd5010815bb66077e1d94340455fc0d6b3b1c7d7ba8fccecc6337358883a66a485ff942294c5de0a5" },
                { "hu", "aa31d97d40c9e5a8b4d95ffc3fc68d422aa4f0af2759a1380efeb7774c273fc41be900bac77cacfd22c33f51591f0998b67080fa3df3d4acd6d48e0f025b97e4" },
                { "hy-AM", "08862314929c3954ccb4e8cf40eb07ed1829dd62345f59829334b20da8a96d5fc3e8f7523949919c488586a30c07467bcf9df73f5f1d791fd5602f573c523e83" },
                { "ia", "9f102e4a158d8a116fbce58bd015097d6fe26ea10c7cbd7a08930e80ce00b84f033bf69fb464ba7ba20b653960d1283b3da97ad4edf9e991e1c141fbb223d427" },
                { "id", "ac8fb8188b52dfcee884cf68adf28479b9bc459f0e288393a5e1360d00805cb65d2b93599033cde08189476a9aa88e1471a411974a13954a9243d5b75fd8a0c3" },
                { "is", "f40868a868a7be1896b06a573b986d6d7f89628f3d0ff31fef77b388c50ac4546e47a507057e397ad37f01662379f669fac18583a3c9045169d72684e415112a" },
                { "it", "9b636259610c91017e51b6e7cda242a8daca76e90673e1d0195eb55347a7b3562700da6e7006d576cd80abd22526883d963725ca8573a40132aa60b7fab1c12c" },
                { "ja", "f7d20ad6cbbb858e5efc95945959ea528e8269761e90841e7e86b9afa7e8eb1cbdb337e0fb1f0c0ecad9be55fe6d6b2e9048677302320f3586a8852a83ce1139" },
                { "ka", "d77def19570a7e81e4b969f65417da6009f1710cafff40d5d8be18cc54436adb1bfec44b2456b76eede978075be62ba3781c64641900a8bd00d8e66bdef14d01" },
                { "kab", "fc67ce1c36a0c7ccab1e2adc4ae0d250d0a026f6f83f077b6443a65de7c9faef400b45da65bb71d4f79789f6a69fd14de6d38ae00ef3ba68429f49a203aa8e89" },
                { "kk", "ecebc0c86a5fec11fa5cb84823d40b021ff7dbe81ea9b07cfc5150fa6a5827e02454395273e64ea8e7d51d6e0cec63351cabf322a4cd948b26f741682557893b" },
                { "km", "1e387772c8b97fbaa1cf40bbc8dc101dca197c2fccb619a2e48f66712b1c0291cfc8fea68ebe940bf6dc5914a166aa83407edaf1944d92736c66a7dc7a97badb" },
                { "kn", "a8795ed7f6753c664c38ac32143d6cdda19240b20baf1b84e6b47aac27f1e93fce72d7e97f55639adafbfeffb16302a16473ba54ec0bcea505058c0d3022eea8" },
                { "ko", "ba2eaa0777b2ea8b9b3fb35ec33fa1278185aac871c1c15724d89c9b2a3ac48562979a9c23832aa87e4395f9e77de292710591b046f1b581762c018a3d1c2442" },
                { "lij", "c0ba23d319a4c9224e354e1dd5a941bf2f7d31073e726d124c86ee4ea84e7ab75ccb2a31a00985944ad8ed39f1a5f69afda044bc7065d67e8f64267b6d6c4736" },
                { "lt", "0d87e6c98e5b296c9cecd2984e365a7317f9380e0da6721f59d1c0269c2f027c0a9663c88e3ef911f818a1fe9431d45a9e28fd97eed96d88152e796e48992389" },
                { "lv", "6d69af08abd01c5920830c34378c15964d99ccc89945f435ca0a37dfba8804da43883ddf4ac3c05028c451455002ffae6f86cceb5e5f69289d4894d04a7465b1" },
                { "mk", "e248626a11e4c779ff35ec15b1d3a135aa6b63f978dcf2659aca2fcb0fe3c11c911e4b66b7b886d367af8781e94d60dd8359f59236f8576a1c5e30bbf877ecc1" },
                { "mr", "54ec1e06bf24f86cb46721371e2c6db5dbec678e8809da4c89c5b677970ca8371d6db291551ec4375c1717b391f8652d3e2d7b8bff75c390999a365afee73426" },
                { "ms", "3ea496e4f875a7390228ba44073b5a4a1d21fb245b8966c2a7143ea1aed30166707048bd39200a60a67232a4e4ce81720838d9fc58a060eb68273485eb0180b4" },
                { "my", "e6f900921d1c96d2871b6c2e73617014a6db69a46d2c1e0c0184654bcb45a37ee4ff36598fbb50bd0f252e18037b0e16fda25b25acd38c17829e35ee42d98fc9" },
                { "nb-NO", "17963ff47ec375bc7e616dcf2fd0f6ef71e273307a0a386a1a1273a47c173e9735e209a337e3c29eed6297941fc095c9f823c4d35cc04f45008a770b62020cb2" },
                { "ne-NP", "fbb3e925abe5452d2ca423c094e2ae4983a0380835833f0da8fe9b78165b8df965b65ef5c46a763885506a0e36901f41ea8a92eddf9927caadb40c736e2438b1" },
                { "nl", "1eb71ae8eb829dafbf2b834644782604060cef14c7b3b8424288894cbeaf9fc88e5a4236d792bfa2482ed05ce5fa43d8293a65e07132acee39702d06d2954a3c" },
                { "nn-NO", "22adcedf39dcc4d33f40c119d0b2a05065f323f6a42080c1a799cc1fa4ce8600ca36dc6d29783517c9c491dc76e66baa0567043a9c1032db44d3f4dcd57fc24d" },
                { "oc", "1707aab501fa46bb442c485591b4bd9352e6554ab2111fa3e2ce29e655ce161e412e4ef98a6137d56dec300e48163eb5630ea41b5131cb460983cae05b188f5b" },
                { "pa-IN", "e902a67bd05d7d7bf7356e28bd947988d10fc0185b66c9e27fc7d7a715d0b31a428023f04e05eb7f17dbb70b3b6d4e26c3c04cf3b8403fae9cdd1980c827b2ed" },
                { "pl", "9a72b0e5ba13ead018c468b77649f2eb42a6dff43f61946b429ba8032ee7e8f5aeaab1ec974bfb6f937ff310a94c9a02d96110127c7ff13c2acd3225af6f8177" },
                { "pt-BR", "9c2ea568dd039cf7ecc16f128d27ea1c72fdc37253415312d18b986fa3b04154e2f94394ae8c3289d09ac7af2fc8171720a257dcc5da7955840472479a86a929" },
                { "pt-PT", "6a46a66f7aa9fadd15a0aa148cae96b28f61d477131a17d6cdc8dc304c7a571d16398e37148b55e8e3bfc3546613518b2b196628b739d87f4001d32669117ea5" },
                { "rm", "fc66cfed0ee59a2257d6212a22e7950d39c4a91c6f1a0e58722bdffede09d5ccd55c3b4edd168ff52010cd2b2eeb869e35a8f5c55d3d5f328df277bc6d70ae7a" },
                { "ro", "2eaf5e2a5738d16c70227bf6877c0a15a54ee8465470565add5e3addb005bb277d00d023b3b994155170be37d01e1a2c006c3bbadc71aa3dd5958a810c642a6c" },
                { "ru", "7d9dc222fedad76fa9018441a8dd38474658a8398e06a4b1a2c6b771e843f7ec9f4b03012ad576397f735b28b664254251a0c2f04e57983985499a6ee75eb80d" },
                { "sat", "0058b179cd65b1849e1383442f5a1521a67dbc881de7dccfab55de396963330b5b00a74f24b4d5a0cd0cf04a3bcb239f2e68953db1d81be8584e23e2c276dadc" },
                { "sc", "ae9979ca456cfbd4403bec42000aadb0aab0c291a60a9f6825391df9c52074e4a0aa26b582e4108bb82ee52fad028fdd28984f50276e8cff4e552eabaa757c7b" },
                { "sco", "647e441998adf131a09e9c46eaba30264e5ab0d2a0da721573c5c3a9080ac41c61598189ccfcf6d235d45d74110c3f5d6ed68e9033bdd2ee3670c2c695153e7e" },
                { "si", "d903b6dea500bd840d4eaedb1a105d38149037530e7269ab709885dcd9f43c79b82f4aeb5616a67bb2f5e51ad99aac98aff9fe850e15ad67c634752920680d50" },
                { "sk", "ba992ef4cf95412dcca4d0072fddb7d32d2136f454355e50594865e179d72b9e413c94fc570a937d79a708edfe9a7dc74c90150225ad0c74a136f56140090f31" },
                { "skr", "3979a1f324e12cfc06c090178048d4389ac88470840d39e44ab4e5765d864b76cf970c0b037db7be2448c62136b2b60d19c6aa3698a425a6bc0120891dab0007" },
                { "sl", "1bdb44c2a41bf778d815713c5e195480e9a7f45a3e6941b7bd478ad466696f13fb7aa3f8744cb170e164505218eb029b1d9bc7d328e13e3a05b52ea84d9f7264" },
                { "son", "26da3bdce420504ece5c392200cfc1c93c29ff102f874f661a74f0617ba317d52f87836a425704269ebc7ee06af8cf3a179b77f8a9ddefaa1a60b5fea2b41db5" },
                { "sq", "0d80014b052783d0c2d799db1a2711c20109fa5c18f877c377c89e1bfa5c41e4bddd3c77f46bc5786c9435a010a4051dc6ee90463268f62d3213081208d3641c" },
                { "sr", "35f37500fcbbfde73537f0ebbc3eb0dd620a38b9a50c9169d9d40ff18467ea19f94505fcf01749742c4a320f772f21bc61ed67c29371b5bfdfd53163353273bf" },
                { "sv-SE", "6d286077284c54e2a5c02cfd3de9f326b466c39feca612543fdff2c809c006203ed0d2f701770a5b195b1641cb3a3a7ba43adc8568913860d696144fb6c602a5" },
                { "szl", "c860a87be095dda3aaaafb4e267be18f65ebf0c932c631aa96c0970cbaefa662b40af64e80366b6f3c77abf9bc4ff896be7fcc4cbc4319446ab701a012b86240" },
                { "ta", "be3845909c1b4a84a65849790bfbf5008d45d92d0c5279f4fbd241e46b405ad15b0dd6f46e32966c8f235a84719319e8af88a93d4a9ddefdba81d33aa58500b4" },
                { "te", "c6be5e76a9b6d8870c46ca633a6f9a44196e27ee9108d5b4ae0b14eb0e2852e30417f95d5581ca3f07550b3fdf681ad27495db411c1c45407541e284046f430b" },
                { "tg", "968361985a86ab6adb60dc39efc7b53a68e17c6b4163dc1f6c9bad83eab4c95d6c484092a0a9660933e45eae435095626d3e9467f209f0278b150162ba3b015e" },
                { "th", "5fbf970e2a42602c29e624df0cbd8dcc52f707fed0b99e80ccb9b01f2fd10a151ce7ee2b975a7955c20ec60526850756b04794276447a099ed8eb22d831d2100" },
                { "tl", "785db0aa21701a5fb0cb74098373e13b6e21172d392e3b96aae404f49bb7c2ad44d3aa2b31d3fc55d25a7d21e220a0ba4579332bcfc25d17a8b0ebaea37858db" },
                { "tr", "ff8ce8affe17b16016fbd43a97ad940608a9c92051a4039f7d1da008a33ef11ddc55432613d745c70801455126583751f0d2709c6e2b09585b14a6b38122367e" },
                { "trs", "e638e904871eb8ae2accbf8e2cda1ddcda6d843598d3588acd4336295b2c8cddf93f8b8fc6ef4037ba1a762458f7bad2a91cdabe8b9646833a8b5c229d554ff0" },
                { "uk", "1791e970fa6214f329809697822ca2109f4277b7e0702f0472a9fc0c97a43170d98fac29c9f58c71bacb8607e4241eefa82e3ec701838f2420a8b1531be83e7f" },
                { "ur", "3912ba43c8a651a3afa7f59557dd010f4f2038502ce4e78d8fcd49923479b49190377ee10189e3ea778427e47cc0d3e67fdbab15fc6c2991bef98e49609c22e7" },
                { "uz", "0d638ee0cbdb4c93ed4e158b7f4866fd42a9def1eabb6a69fa8823feb7cba9ac54cd1fabba21fc9f721e072bdb0814ec4937921b97da4f86fe96e3e44052841c" },
                { "vi", "a4130129b246fdae120050101035f1e0176dc2ac29786591bc35823fcfc6deb2d5c626fb57fda31bfd1f44302882df93a7b01c8b2d72d505d5a82f377f704953" },
                { "xh", "a6b1a2f091b747851d99237931aac932fc3f65125f396273355b0ea8f50656b11c82be5077138b8ce2d75b4701a6534d6e4e434e8481ebb1399687182711e46c" },
                { "zh-CN", "6413dbf84a5dff8dabe84a6a8bb264089d4708656b84623d0716d61c73573c0102fbc9736087a6a04b6f8a91e8dd6eb84dde95021f26a8b79a65051246eefcc0" },
                { "zh-TW", "8c9ba93712912f1b271813b77b0cb15cc535019b003a63580ac3ddaf540e2889480b6f7fb816878aca22f26d4217e850837101014b1c2e7a4cb80ef13de18601" }
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
