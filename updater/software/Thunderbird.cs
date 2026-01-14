/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string knownVersion = "140.7.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "8c4f73165a7d75a2cd229c80797ea51cfe318a7feb1bf40bf2b729e978261068d924ce53d1bbe059268e1c3b0c58aea33d178b8c87dafed68a8b7c633d1d5a7c" },
                { "ar", "03e5324e8494fd8514c3d86d639365b722ef3f6d9540f6ba7d2d09b4dfb98e072ce16d0444c71393230301b93841eb3380c431debf2a0a8183fd6d2230a4f451" },
                { "ast", "22ed97145d46578e3c90ed93af9da52b8b1d03a46dacb0b3852cc756c19d1600745427e2f2a72b9f7e7927ff1437ba69f21bf169de6d3484fa522a4dcf1162fc" },
                { "be", "a28a8fad4b27a029cc14075465fa291171dd0e3ec59ac185804b0b9166c4605b44609e77e953796a5f9bced2a41a53bf6947d97e994f7fa10868dc914826bedc" },
                { "bg", "5eff2dd67d8d3c2026a0ef05c1a91c429e7f915c5e8fec245f424e7765bde39a3536e5a7619689d27ab1d8dda87c476fec491880b8ecf199d0d68be277152fc9" },
                { "br", "2392ee7be93155eb9bfa840db0519a65fb9c964743005ffd4caa70746054914c451e8c6b65751f4f8cd9b1532e16ffc847f69bf26114e0a852482f0c93e84c96" },
                { "ca", "27e31a68ebd3f3da9c0d7ee94ba58f8e8d411e18d5a69d56da819cefccdf0e346f188098dc99eedb65c25145d83eb5691b26c6f806a82c0a33fe2a2f7278ae90" },
                { "cak", "ab72bdf8557e306ecaf3fa0d98a09118162a58ada5f0c748ed7327246f065241ba8faed8e6cd2600a1fc2b60855393de3a6b175870d65f2237e958c3b10f47d9" },
                { "cs", "33d7e01be7268077706d4a8b3ecd12d3a211605b90bd0d3bac0fc3d7d463be2fb0c7583bc2db18231c3140021f3165ca9a40fcafa17917aba0753269f2294676" },
                { "cy", "a4520ef3b42ed7f035a5c1524087a3a74bcb4e9ad1b73b5d092c5a6a23b085f63c8e8828e1bf29e1e43b642b474cdd7438da95535957330d0eb3d5d72993f93d" },
                { "da", "4ce39932096fad6638bf9a91488a189a352043bbd0aa5dd3f03bb720e29b7e0e4b5c03decb7410cc03e31155377a86aff1460051cb154d6f279cb57ee08ea06a" },
                { "de", "2880d59e09cc5b93548c35abf8c5a86e8b851a3c14261aa62e44d6ec7bbb823b9175c0ff501005ef63c5d2ecf3d4e972c124a93286e92e95be38b62479b14de6" },
                { "dsb", "7b5c70b478675bfe575505539d6f0f0834b8518a9096cad8bd74786ea20ade774029b1b4256263f3d3be47b7b2dde65732c1bc43a95204d293edb4fb29479e8e" },
                { "el", "8d2d08aa81cab4e947c32fa90e33174b02b55c9a6a633f8bd6460da73e9febebb6e60f23a685aed450def53f31729d22619cdb5f359a688dd214ad118cb860fe" },
                { "en-CA", "ff9e006ac9791c9825e2dead65fb0f1aed58ad0ce2289ac8c972ba48bc2e0644aac0924f9e3ced5caa0b8b84c5cd5d3d1302a003855665416dcc80322ac95407" },
                { "en-GB", "70d6f550dee4e918a364daa804805d4c2afc9d3761d99f5bcca4f7e92e70999dde3a3ea66044aaf7a3e11ff5d9d2e06aef3e810d071dd3a018233605f834b47a" },
                { "en-US", "088ab8d74733331247794f45b2b8ec1f695b7cdd6cb829d21147d2dd49931996f337128a152e9c9ec69f699efb0226046d5ab44dbbc35f1b5f9f8b5e5e1c95eb" },
                { "es-AR", "2f48bd4cb9518a712889cf8006a14bdf1aa07c053cae3b5fd9304dccfd260d91bda898bc2d5be476aa87370a79f9a3779bd8e91d78a517ada8a879ddd991f55e" },
                { "es-ES", "12e28bc6cd70c9ba34195e28ce1676824f321414ea2eb9af07c43cfc5159350e61ef8e639c7febae69b71d478ea74d578ccfe17ad830c56943d0678dcc28af60" },
                { "es-MX", "22bb68ab5e17ba09f4fa4c3fe7be0499e568c6696f47dc1b29bb2891a790a904bbaa72a868a291101a103a12571004d7b46fc604b7958a9196e24ae0e04a7b5d" },
                { "et", "eaadb4526520ee1ae26a798489617e5069a30e65b50dc35697d1b6373d118057bb50e2e4c5f7140b5a06f30a3ad610d00ecc435650ce096854ba83daa3bc37e8" },
                { "eu", "5a5c779a5f397e93109ab248981715a23cca77f40ce8baea235c143da0096b02c5746386c616965d225e241388256131272e2bef3ae02dd4ad3cd872f4f2b943" },
                { "fi", "005cad2b62b7a665d6ce60fc297ce02c5dcc8d0560ce7bd5dd77926a883d2fde67b07237ee93f4867d569d87f16b9280df65643dc706cf7be3398881285c62b6" },
                { "fr", "fe62f52b5237cb14a87729aa169334f880541ff611103b38daf3b6f9c51c504c6b53396f57848eb0c7e7674d7937d66159374ad7a3143d2d80a93275eea35ef4" },
                { "fy-NL", "f408a448be228e206d1544243e93617b1de7e81340930dbf863c62de4e25753a7c0abfabf6de93c6d6a7692eab2b73e4e28f9d9c00db1d82283aa1584e0a19f1" },
                { "ga-IE", "832eaf23da33dae2edc0072a586894e54fd5379acdd89604aa3a6c47a2f9da424bc5a4fc783a6821569ebe77f76b103ca11d17f0940d6feac32f845e34c0b9fe" },
                { "gd", "6a7250b2bea89ecfd5dadb770121d5060e54730aa6096793eb53a1045d0d1ee796b5be7af9425fc29dc22ba7c2d01d03a89a2575062e8d14a8f447be5fe5d3c8" },
                { "gl", "d43adc045fdebaf36e5eed3c0c7489bd3f8a6006faaf6bfa8168e7d3b8705125bf468360854d2ba54843edd50588ef006b581bbe4a542778f7077a62e62774d4" },
                { "he", "4bb3d8fe39853f1fd22f4bfe713fe8c5d98a802a673d62f07a48e529ab52c8502e687afb01dc79cf0e946321b0410c5ddef1d8eabe4a919dd3ba4c59c319f9b4" },
                { "hr", "a20bc081bd8db83a4fc3cea2a7685487e0ab40b0e8d5dbcef8037fbfa317f7936ef200b8df8245132075735f2cfe9bf224d8a8bb9627130fdaeb284a5b598c76" },
                { "hsb", "54793bafccf53f4db4be1c1e16327a5d519c36cae42e9ff70401b61f0bef28dc1eb9a073d91e7bdfcced449baf221e5f166ed36e6dc90109d990f4a490d78abf" },
                { "hu", "98443f9a4190600b918c5939ba2d7a83ab295e102557c8ca89f4e0622090a7220a830737875bd6a500f7bd63240d741751997abf4c119c69c08498fb3743be1f" },
                { "hy-AM", "c8e4ac22c28ac8d655a9e20e44742f54ca5fecaa4c56ccae79a7ae3b9549115d310a508e8660e8e26555e1979a1b77bd76f03930aa99e84705a5a4eca791671d" },
                { "id", "f31ce04ca4c7d47edc2c952c60951b7f70563dbdadd07c1d0d2b9047d096994748140d5d12bdf928c51f7124c820df0b19d286e99c508127d227c577d60d0e23" },
                { "is", "60e0f8fd93631cfc9ff0a440e41520dbcbc22d82ae522cd162948c821d7d3e3814568788ce78fc05aa7b3870514b0121771eeb65ac3914031cd3e19b4b47f21f" },
                { "it", "40ccc5ba8c0efb2b6a9e8cc2f6a37dd4124b0d050b62a87cc91ad70cbbe2062f0378b110feafc7a1a29c7946f2a674e5dd7e6811199cdde430e8e7f95fbb1597" },
                { "ja", "79c7817f88f1cee551c65598e9e312e035c2c99581e6b102689200475f05c0cce830d15cb2cd252800968ae66c01c54405231345611ffdefb9d5ef71e16eca83" },
                { "ka", "853b4b93e58a463a9c2684dedd96f1b9fd98107bdd2e9187f56e14c71fbeb03697fc351395e2cfc4cea03ba80c7034dc4c2735e12d8bd2a062238c4bbb92bf6e" },
                { "kab", "a0c96a88e42d099295c614944e2b0f456f253f9d411d1a7d66b2a40457e63d781c84dd2db3966a3f0c764999acd3209e7643a11541d70fc7c53a4b88ea2c54be" },
                { "kk", "fbbd9bef6e817af8ee384c46aeb7e497104e27e1a813fdc688f3347e71352ce394dab5fbcffa768a5ac83ddfa5cab34a7a885a0b2376eefae1ee080a13687283" },
                { "ko", "648548ed85d40007aa5ce1d6a8c4733a9118a43bfe2797df3bb04a2f9b8d9bca1d3cb6799b75a3f7ecb7ae11af13d90bbcfb0c888d737fdd82f11b7549fea24a" },
                { "lt", "12d9af49afe27ef42dad89310231728f113f4882239a274f439a495f5a33e9c47cdd2780eb1a2ff106d9ea1c0ac3052de65470eda312b737c27d972810fe9909" },
                { "lv", "aac793dda2885df482c8907a82d7dfc232a189b1eac04fa87f1b9e9b51e644b11e9fd9bc12bca128dc9dd7eed20d16f577cfecfd755b6f968ad7739bcca55944" },
                { "ms", "30bae6a9e6223e922b665cb6892bfc1c16b1bd899259a8d595c9f15daae24e23aad3a5a9c829ebbefc10dab864ddc3d9bedefdbe14a211aba9d9cf03be83b099" },
                { "nb-NO", "16b1eb26ff68e106724f7375c29cd3aedba9ec4d1cd6bbeeab0630e2cab72bcf8cc33f2444a7c47a0cbd41e29f80cd469ed3b4d6b45d776dd8492bff179e9412" },
                { "nl", "673829e4959406b82d306bb3feffbdc3499e92d0eaac412bdd554f940541d1105e75edbaec544d4aac8448195c02cb8819150ee1d3e4e930d2b57b6d0d9ddfb2" },
                { "nn-NO", "a2c3c8d7cede31ffe08407c7757cfd25b6b081e5e1b3845e844a7f73cc73c18226264b6952a17241f3f208606932cacde33c82d29c110cacb82f40330a88a6b9" },
                { "pa-IN", "595a9bee0cfb971e80ea0aa40b5cd8144f14aeeb9c7a7f710a9a3d8d262a1510f3bb3db441ead5abe69fd6a296297542a094d5881e52af5e1bac4fb938e0d76c" },
                { "pl", "da9191e468555ce16060e7a3c8f4f7a0fb438c3b7d8e1fbad5be1028141f55b9e73ae25499ef39e5c680afbfaf2c0947ded595cfc9507da4960811affd7ed6ee" },
                { "pt-BR", "5fc6f506e15b2ab38c03e25428070b8acea3dbed43bd6004eedf912f45fa36a9c30beabbe4bf12877ab0d7dffaffe722b039b7e9cfeca0e93e757914f7a0e8a0" },
                { "pt-PT", "93bd82f76d30054ed7dee67227e374215c57798a4a26755e1dc454bb9db7042ec2b59a8155fbec8a35fd239b9993a53103316581bbb3c51f93a2f27c51ce8613" },
                { "rm", "7788d35bef0b5ffeb02be710f00e9020bfef883e9021be20b59a8aa63ac0d066b9d6c02a863b42506117a3ab3065cc7cc09ebbafc83c6c2ed8f87a3d1d25d622" },
                { "ro", "c7ab8d5f979159453ec8d43f8d4dab495a71d4965b4a16bdd83d52caa08b8f1e7b59a515e9870c75f75d81a4d6b3f95160a39eff36062514e7b997277276d29e" },
                { "ru", "714ef6b6918f35188be14b0639ea5f594a2fffafebc3a0f7d9b75de4a830470a2f34c240e171945f25c44060a3fde7b35f0117854cdbb356c9a70f485a525559" },
                { "sk", "4ff64bd3234891402e0e81f573b434780dcf99f289f3545b09861dd5a21e9e36d8147e78f61d019ac69fe5bae3463a0d44cd4739fbdb4b08c29daf9158b19dff" },
                { "sl", "72834cd8b113d7698696957e622f070ddd5b083db48ae8c3b0ffe33d61c416d75f91c86f9344a1e9e2c1094ca431e22577d6612adc86bbe057cc2799e2f0dc8d" },
                { "sq", "8c0b352d7124735cc5c899fd87e87e58dd66bdd46d761761bda3f0286ac5ae941585d81c3b929c9c822f8104de50c126b0db08a5b460fd51f18ea88956d6ba11" },
                { "sr", "12f50fcd620c59ead3f69be6951e8781fd84cf4383863954196a346f5f2e48bb35865ba8ee6e99c068f9070f6253b7407a864db8c8547bd0841461746528e487" },
                { "sv-SE", "faa87fa0966091ecaba4893fbf5b901eb94ea7adecf7cc730867fe33a54caf194c525c7e914fa3a3d611e2013db0a9530cb056adfe84a6f05371b8df7726143b" },
                { "th", "505103eb54cef54adc55e9018f74deda2bf113fd5da2f56bde9b2aa212c056e5136a7045c44f28031f4cac8608d3800a0802f8977f71e6c0ec867550b58e4415" },
                { "tr", "3279671331a1cba59c188a394ce6b2fd12045c354c9436463fb08fbe55fba827c724e80f64040bfcc4f4b0658c0cb66299bc1b28d9e50bf688529f78ca4e3da6" },
                { "uk", "36be3fb2e2726c1e30537396b7914ab05dc509de5fb2ebe5890920bb16d29d37fd913a4b225e38e3447c2a025e710d88b3ad43ee73bd9f482a1e1dd432cdb3cf" },
                { "uz", "8ac710e7ffed75eb192f11e927a03df17d8f0a881cbd9acafcdb58bc0ee77db72e4b620ea8269bb4e9a2110b8fff109963e389523364547cfc7317b19d9db51f" },
                { "vi", "6115c79d723966ae208faa446cb38ce6ae2fadb244b429792b2bb52ce94c324f0aacc7b8eeeb74c91bb6debea5468b2cafff1d7c4e365a195622d28402345a67" },
                { "zh-CN", "aab4259b68d2fad5ddcc485b8a29371431605db9c32793a11bd70698c7ce829ffe1c4dd5da1cb333afa79693abf80c27af0b3b64eed6d92730e7abee2ddbb6ef" },
                { "zh-TW", "e050d0358611a04a9ef6bc442b40b8ab4c0c8dd840c79fcec5032a4ff1773f2333bfa94a1ae9a915e36311274813fc8e9c20a7f220c46dfcbda1d932f66a75b0" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.7.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "69d097a0b9b102fc1369e3625e72abb2b502cfe8e74f2429546364cc204d507734649530e1e3d222395da37097c5ac2b4986fd86fbfbbdc1ef3d048fe4d3cedc" },
                { "ar", "f2271021fb6934a1e53842f492c560bfdac7de9858ec8f8119bb267a94a7c80ac6e73a20da5502ab750d4211d2e6a53a14ffb524510ebd04291ea452c25d82c9" },
                { "ast", "9b912acaf0cb197ad45c525bed02549063a35616374f978f0d9b0b92175f63a7c25aa61b644943c072f4a4126f3499b76a42af57a24d9157b3c6603d686f9a52" },
                { "be", "ebc63dc633776e503c549f0e1c0d3395c708b45cb752e166fd18310eb6620c64b661186b1f65e29b6c8c82fc65225e16d4720bdd2a2f7dd1b66465620d1e1eb9" },
                { "bg", "ff279218e429fa1a6777b4c208bd76aa23ff665412dee62d69d7ade5178a3c5c9167eb4440b52f5be4cd9b063b709ceff497e89f7f0a86e0c899109ef5f04266" },
                { "br", "4f998b93259d5207423099cc146e2bdbea2dd4f3ebddf5581196b6d0eafb1fea0b548f806e4c2031222434e86871f008f099620bf771cc21cfc7cf3ab5f23f38" },
                { "ca", "b82ccebf173ea3a41360fe0c9f86b50a7b8022f00a44d185d2c4b226bd6c8a17c13c6b07bc7c8b0e5d0a6681ac0f311a9f9b1f16b69b1d7348a18a16346c0fe0" },
                { "cak", "7def5074276be39d85432ac5febad547641c89486996b57cef7dc86bf2db60ef0669ed71ad9e9e361be5e32a39edad11f105230267544c8b09797a9b4fde33d6" },
                { "cs", "778fd89134b2541b7c798215b2a6639ffc9db2bf7a785f2425baa375417db1d97d0aa7fbff34212a704ebe8987abaafa1f761e8a67f3b6d1374332b340671517" },
                { "cy", "6095bd8b29f56d6a475c73c9e468554140a663147ffa2a0a5437fd0b8ea30b4aeb39e53aee257606b558a462b862b285f21e254a1384287c12552d965abe1720" },
                { "da", "06c78664a11699fed9f9ed4cbec4f61347da89cd881fec3c9190d2bdff4182a69e956c57eb21cd4263e50ac239efcbe35e9a159a1b3c3a00df3d9d04f6e4dddf" },
                { "de", "65d8dd9571aa84b4c559cfe30f2322286fb91a95641f64b5fb55b712122900f3d38804fa44c75bd4f8e37028b8ef4eb990f2c41dd2efa2d63b2e0ea106e83e55" },
                { "dsb", "7d3a2c17ce0f158dd9ff8281ea1fc4025c4cfa2a5a03af1016de215d11191987b4bec0b1270b224c9c2e2204bfef4d1d27b38d665c7071a3f45d156c5be75f8a" },
                { "el", "dc69e58931e9cb2fe1308f23e7a01959cb5547ce10196dfd6f53e06217cd4c134ead99d927925afe64e6794fbad88117c5aaeb3b13009d85c364177ed6069e51" },
                { "en-CA", "89cb1d298199332a656c8d29aa08331570a287f0a329b1d66bfc9f5fb3dcb9ef49e388b2d249f7a9be9a98ff024c650a9c6ca4c50259bbde398dd07a4c6feae6" },
                { "en-GB", "01087117699731a27d186b1741a21b97ae661aa2b0013ef16486e3e3849fd69e5449dda8b7911f0929faf89b8e3c99b5aa076e90e7eac3fd82f61b0d19d4523c" },
                { "en-US", "bf23b51eefc8beb74784513c42eb7fab0bb0e30b6588e8dfc385b5662a2063487e009bf42d00ed976d3fe4568c4d62d35338be2b8e285fb1f1a42adbc853faf0" },
                { "es-AR", "c84e56a38ad0d414129a8efcf3030d50c8fd08d1fe971d30e049ef98a82a78c405ff58b0377a2e89f558884933bb009eb217fb18a00b92432fe61b3bad6898ae" },
                { "es-ES", "dd8ac30efd63d55744569234c8cd125d13df0a8359b0a8dd927774e59aa12f6dab98b98dec35a274bb03a5bd7b5fa7f33547e6cc0fc9710a9264974604ddbcf7" },
                { "es-MX", "b4a147c693d574ef0cb9126b616c7e29cf69517faec13668fb4cb85f1a42acbf26bfa3a1be30641e8e63209b97339ff7a8a8bbf84eb47544d6adbc4d52564f90" },
                { "et", "3b493cfe04e6345d45d850ceb5c4a2f3f0559f8be6c9bfdde4c24ab45d726873676f6d074c0e0950163c8600dd6c2d2899f37b68ebab50c5df42bc1b6b085040" },
                { "eu", "e08c3656b477bb7b5833e1e568308c36841821d2649f337b5a98d1233bb13e7d7b4f230ffb9068b973eb5cf59a1b6914c88959ea4c4c197ed263dbd6336423b9" },
                { "fi", "59541de4e4320e1274bddf2f34d3ccdbe31689f059366fa9c7c00130b2ca037addeec1b3011757c8810ba0a0cf5baa1061e93b258d5869b942bae3635a77837c" },
                { "fr", "16b497035248656c843dc852e3fe2c5c435ad5dab787321593e7a4abff5bd8b89dd03dadd2d886f2247f468c3242c6abc17d5ff63852437979e607c7093d04fb" },
                { "fy-NL", "25194ddd79a6e7d015e711f2deb32d5af99121d296bfbb7f6cafa67221e6b9201b4732a116c50b0eab9fa9541125c6e40f03ce274c18c14adaeb15e922d1c1d6" },
                { "ga-IE", "4f710e588f2ac47d768b99e2bcd72ed234f3655fdbbc97964d6639659c5169d6ce3912240e60171d9e50337772f9cd4656d3bbc94445100829c93509e9c226c0" },
                { "gd", "18738358789687db4bd3519373a46dc57ac446b211b1fce6335f9cab4cf55062635309923276cb545ad7108f56a5a120112f2c9fe54b626e7a39ad2e7583371c" },
                { "gl", "e616000e82acde7261946986c068b44057db6b326df7dafb55e07c772098596bc519f303e5c4c6c57cea7c2dedb2a6990696646f499912ac412f6a029065e3a7" },
                { "he", "44d86e931780ae463db7b9618855adddbc104e3ad364810403a6b42b66bd8b5e3f68ea2a78423e5622688b1152d428fdd38f8e67078b78d9f38e729227725a3b" },
                { "hr", "257b9f156c11ee341e3ef76e289d3a16d3530ddc6df7f8d466d9290e4237698f0a7d18c2dccbd4efc6c05a9f9da4d445dfa08dad69dccc433323b1e4dc76237e" },
                { "hsb", "9a4cea1d00c4bbcdb3d9580c10d3f9ac8b5e89efd5c1f3a61dd00719c3a39dcbca821fd7d4e52813cf2f43aab911560b12b7c75791899ce2ec592156c509d2e7" },
                { "hu", "a333914f829b39d8a97df514a7011a52f40b5d6fe63f71ffd084ca4ca06432d0e4b3d37846f8f583b8242edaaef417a78216df202912522170d9b96b19e9ab6c" },
                { "hy-AM", "0dd8c724c73252b0e0557792ce06f265d3c66f8124b693fb25e3865233e6e250034f7c840333b2b3ba3d8e6bca8f1d85c6ce0b5b6e598a2aa89a1e069a4897d1" },
                { "id", "a1d89e8a7617ccbe8b3492045abf598a6c810e8088c88778c1f5933d7b53fb01b124e7880f754c18a79b878c86d9569d0618c634a312998a37acc1aaa947df8b" },
                { "is", "7a409234c45f50ba7d1bc6c4ff3c8ae41f505b94561defe8e3307e9b7f3486dbb1f0955f0597cbef7addd45493d475fc357532f6a2fed3989f9e02a6f2948563" },
                { "it", "8439d9e8a9b00f46978538b9a49c25f08e74e76aa703878e81345ced3376de736d681759b39107693c9125415ebd88f325542baa31b7d22928b3e51d2683448e" },
                { "ja", "c86cfef11975e5804a0e24a864ae99f3d60e599962e5b6a9c040e6a8e91d84ac0b5288068b6eed87e419d23d112f49bc0eac0084ceda54977d59d5ac06f15772" },
                { "ka", "26c062329fa3ef53704d251a6ea34cd8e56e05efc72405447ebf549f67684416685b149b0d6079c7ed93d2cddc61d9a775cc5b9579963c6ac095b41284250f73" },
                { "kab", "4b12f966ec0078f84967675d76722155aec9466398c4a42463cc2648756e6a29f8ed573c3252ffea33307b98a2c753057b64621b4e9e9de3964d9c3e3f966ad7" },
                { "kk", "12a427517a5fa1d10f4eb0d1188485346706f67f0f614282c9cde2a4de71a7870dc35c3eec8dd909494f9098705772151d7bf52f060e33f6bc9662788d0b5df9" },
                { "ko", "9088ec907b3dcd5d7eb31dbbf23e91ef6afaa0d03999c37a39467b490ed98f693a7d37c4f95942ca4ca4033ce7306700d0dd540db45a28d666ab1448a33e191e" },
                { "lt", "9cefb5537e483a59dcb772571977d28fe00dce194c95ac389ee9de130f3fb25a521db40dcadd3972acc7071ca59c243709ffe5bd64f3b94d428c80a803694887" },
                { "lv", "a71c220bee81cc02e6cf41bf0bf7e62eff7bd0a6934828b5b934cf0c31611473d6aaebe00e56a6907d85cad4f2723b246b2cc5fb44f6857f60c2705934f1749c" },
                { "ms", "643f7653d1c14ea982a06995132e51624a31536b4c99e0bba9b51adba887abb576f46522dfdec815720718bbb2624fce3ea0df9534adb199894cf6a4b14c7a6e" },
                { "nb-NO", "a9118654ee6f972ac01f8d45a950cb0b882b9823c31d2c31255fad1f05e806afdba4e0d151f4012a416cd4caa1bf893cc94f4e6d536275beaef04793c88c103f" },
                { "nl", "6c4809bfcd011897979b613351e232e4a585b5d4f6f42f42a682206b81505de6b81adff03872a31b8947dff8f538f03168ee7eea95b6f99c0fd74cae40180a5d" },
                { "nn-NO", "383185c7b39eef9c15e5b6dd4e8772bc102b14b5d71d4e857f3540537f285cc703b287319009868381c7fbd9bf43e6ea16a4886fc87ac687dfa2f52e0db27938" },
                { "pa-IN", "249477a10997a255d17addcc4d5ef652a593767d7af29231c80da5e1565fab6d4591560e1c3c474031b716a2ddc376b1c825b02a81d339857a4d956b2e16ece0" },
                { "pl", "91d5d41c6cc5d53f80e24c8b39e0d71ad31dd8dd46d597a82335f915067e68578881f5dcf442f979a8089b800a21fc0227777d32142d7940ed3874280cf3197f" },
                { "pt-BR", "48f3b0ffe81badca00949fb6297582f7aed6bb3f0cd0295e1429d0b7998ae6827699d58ae41c5c754dae42e9c08836d15f4db9c69fd30221f925cbbbb7bb0481" },
                { "pt-PT", "cd6ee708b83dab3e6200edecaf7954d965e724f1c3332ec2e3d3355f6af8dcfae001218860939e5aa597b525197a412529a82723004f8e2154fad9883f871887" },
                { "rm", "9b2ca026eb834b6756eb4935a6f21fd10b1dd10628bea8075590d15d5be30858adfa4f9c03c92ec7fd665432eef7629721d1eeaaddd1844f5b3de9ce0c7d02e2" },
                { "ro", "c1df1fa62ceee04cd40a72825bafb296f476722bcaeb2cb053096f525aaf7b82d9bba286a16f793590f9884e0928614a3c61767680c25bae00564417d1eafac0" },
                { "ru", "db5b0f4a694032718d825132a77db584fb30132fcf86e3316eca0a60b9b8f3fb7b97e4a21d56db28e83828b12db41a79a9376c8c9c8a8478a989b61a2fb65bb6" },
                { "sk", "069869da7cc53925885383d6e41302c12cda0db343036a3ba41f5b343d06403b82bb71d537af084613a29dad472cc64d8aa344e44ab52cd8042eec35f7b2f5fd" },
                { "sl", "d2f3614cbd7a987015f9d3bdd30187219e798d649b947b5886d24626271b28993fb2b2e21e4d3c1313c583b36891c120e724e07d224dafe4aa45ae6599f68dc9" },
                { "sq", "d983d4efaaa1f6516dffe30e9a1d6b9242727b1889d57a7f6087e923d667afc4c035d27b30269e421a90d05451a3071e4482e5455d6d778f436062cd3e45bb12" },
                { "sr", "ffc9465974744b926882708a652d0da42c5b299859033928dc586a364e3b2fe8a0c5abf7a98924a60ff14234d2f7e1e8481a7b80a20b5dbb0038255014f30858" },
                { "sv-SE", "b6a9b3cebd61e94c1e754cb393b92035d4fe40d269a8e238770f38d5d2509ebb45479403713cd93edd59bedd741c01ad511ef3c96e4e05ad54633c29721d8bb4" },
                { "th", "0ec1b782bb9b768b5d8f6b724835e19b47a197f8d25d581b4243e98929b1dbd4e246194fd855258404740b5f6431ce7ca020a134040d9a3acd39d761c92ea3b6" },
                { "tr", "457e9249f90768a6f5616a656a97173f83db84c0f33def335552246df264b62fe0bcaa560b0d24f9bc5027637d49ca9aa9154529be11d9cd7c69d6b6e7f92e85" },
                { "uk", "877fe48eebaa435acd5a447830c65b06fbcfe56f98101189d635ee6ddf12d4a87e7e905e4c95fa2399113ce07d1ebe8636038205c87a03404bc72f924b5abcba" },
                { "uz", "e6a8fca5c3ba747a9a84223e253db758a827c6292b0a388b250f2fac453dde99e1d41d8533df89a32dd892d384be0580833b43b29e64e97b9fdf9d29cbf27e4e" },
                { "vi", "284732c2795b9bb0173fe60aae0ac83d21c3729d5a3a72133f46ebf7d5776788a6811fb93ac40569087f2346699d107f0747a6ba493b35a61522f477d0f325e5" },
                { "zh-CN", "21acbd5a6a8651519c1c5904e169e599958182f8d4ed7ef16310cebaf6a62510c70647e83bb1ebd01100b2e8bdbc4b600e81e208d990868f11b07659089acf5a" },
                { "zh-TW", "dca38bea94321b0117e2b39ffdce04b07884f661d06f52da834cb204ba4ff9f58ccdddadef9905b72fce67e8e5a703aee18b490c7cad937823560946398a4261" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
