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
        private const string currentVersion = "146.0b6";


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
            // https://ftp.mozilla.org/pub/devedition/releases/146.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "19be2db87be5c5c2643ae8ce9e8aaeb2ef924d753cee18db949f6f1e572cfae20d3e822af606a9959284572165f752516e4bcf025a4f0218b3b5a336872f0ec3" },
                { "af", "9fd4940a667afeb74b77bd65ac6dd12911eeaf9d0dedfb519a7103667241881c9d38af565e7cd59218fe6ee2714d180fe94715c508ffc0f3307d4ab6f507dc93" },
                { "an", "35d1421a3f37adbc61ea538f4e1791c95fa9869863c85130e8758180048a5739408a2028e079290742372f81b19aeb54970cef9a0088112bc73da088e0065ec8" },
                { "ar", "95e6e3cc5350bdf6423fe5153226e8834097fcca7f0f3efef2751ec938ffde857daff8264001e6d1490d6857b741180c50c0606bcf37ce73c816eb51b89185f7" },
                { "ast", "2d592acc7656070f9f9036a0de15df53ccc5a6495e67a62e699791eb741b40cef7a45538f27ff731cd3faa2f0c87c0fc5fd3c4baf7d751d4d170ba2c9358b35c" },
                { "az", "da04454da9c0299ed95ae9556c37fc711afca78c44e7a6019ebda0056f6711062c236556520a7d5066772f2d9a3ffc529675cab23024e0a1faae6899f115dc18" },
                { "be", "ac0346db0b6a8e981e6b296ce41631847431edc4f18dc8d70dcbb0cf132e5eec9ee3acf427acdc752e6241d29c9c9dce3f1f94691b319dcaadf9b969383b3df0" },
                { "bg", "ca56a6b22ff4f95ee190e8c41ef37e3c0fd7d44dcf29307031c3286c19e1dc4369e4339321ec16b70c56ad22ee24b0229b9868c9f01cfcd3fa4fa41b8ce4a348" },
                { "bn", "19949d6374f05c4f27d180a4e4b641ae84f441ff4863a97a63b5744df7ecef92c00cfffa47cd5e27a7e944bda153529796c2c6163a57916e1a37529043100271" },
                { "br", "c1bac14ae82d53cb91bd40e2ce75c6a3b3cca58c6651b31ef8aa9cdac68e3a24ec9b205eb622679dcc8f7c84ead8b263b789b2bbe48cdc3ba35f749343166214" },
                { "bs", "9c0d2893b9b56a759416385a7d984b1f466175c90a6334843ab794bf8904504aa79e889e4bcbeedd53d7c1a9b27b838ca8be540dd23156795bc902233305d08a" },
                { "ca", "f866cb3482d7ecfdcd41d712ea5d5aeba9982b5dcd98d77c19d93a0c741318ce74f9730e0dc3d8837bd8ae392c2e890c436ae348ad73b34b7b3900ccd64227dd" },
                { "cak", "8a393ef4a43b4d71e7a904460a9bdea8a1ef1dc19118e8fa6bd762a018c9c6a380fab5c6ab63d3a41d9f7df5e8c07b4c66ee81c6697186098a64cb6228519bfd" },
                { "cs", "9437cbc8e88493ede5a9edc2791c7eb21a63015e42a99cbb380101b3792453e7230c32fe5615188f3fb60067725d219c74cc5c780901da43ef1283e35f5fa8d8" },
                { "cy", "d120e645b4e7c459ba9ef0c6608d299523364fb31b42c61c82d2d987befbba6afc24f08b286863af120c6a86e241dddfe16f158a46d3fa8367e79d3f94c78f35" },
                { "da", "4727ded26c3e2d3d80edad9c999b67815f8363642704744201a3dc85b08ab735d176df64498b43ac5db68ff461dd85e03d99e37dcb37de9fb10c154f9a4b578a" },
                { "de", "2068f241af42790273711d0cbabf8158f0caa8c0afb085063aa36836c3f53c790f0122251dc838b99f0e4eeade717e96b341b2fb192c8c0b3271299395eab7a6" },
                { "dsb", "0cbb26671c69b567ab7fd1056778cdf975a3d2cb83e322644ce13865860a7b01174c10296524bc05736e1e479b5f66e6c5770d528a86e9e287cd94ab16addba8" },
                { "el", "fc4febb77487b92e222324d73d1de0fe0935997c670b677c01bc6573649f54d818bcb15b84c2aa0263f2c68beafa1e095d6dadc52d08d45378bfac070ce81ac8" },
                { "en-CA", "0958874b978098637ea53b275a910c1abbc416fd562e969359b2aa4ee44ddd81301dfde037d1a61c2b775674be6cd8ece6c64ccb6f9f3a1ccd7d5996f4eb11d1" },
                { "en-GB", "7b019222d16e3fd37c6a07ce863ad2a95939107ea98d63a574ebaaafc402a86250425a9671f11727cb4e74aea02be376e9b7075324ee2f3c1e9f59bee4a179ad" },
                { "en-US", "912c96fb3c5b18219112b6dc4b5494668acdc3745aba4963691519dc6a925f39e2ba6544ca472ef245d694ae54a639f77ecc63316e081537fc2e9fa90130a9bf" },
                { "eo", "4052a5c4fc6f8f6ca1072493260027efc8aca2b10666059d8e0ab56fd2c9cdd56f96832e5e0876283877f4dc3000d8ab1d815b59bc81b1fc84d80fa3185de08d" },
                { "es-AR", "c7647813474cc01655c1ee00363871a333ddc6d4d9f4dfcedc07ce372f05661b082fca1a29a12c8e9fbdc86bfe8f84aaa7a45aa03eae4e63dea64ad6fe845899" },
                { "es-CL", "980b56f0a76acae7fabcd5b825fe0d5ae546a1135bfa5af963f88ccd58d91cf367de51f8e80c3706df63624ec556cf55dc19f73f3b18c35e4844d1bd315acc95" },
                { "es-ES", "90ab01e4f3e3140f9da39f3cbf286cc727afddb4d8769e028b4c59b7a9f8f4635ddb5cf1e68e40ca64f34a5bc07f1395f9d75977d6bbded36004ad0272d028fa" },
                { "es-MX", "ca7bac79bec4cb7a2ae0c3661a01991d2ed168fe12c9e57235cfe6c89b56c717d961ffb4596b66ae2c9cbea56c551d005578940b24327ddd1b5baae63a8ee72b" },
                { "et", "f0f4ccad68233294e2e099e59c7856632b2f2951d147c502b5d12703060dd536cd120b5348f6875c8c58b9a649ff1a5d9e5191313245a9dbde5bf14da1edbf31" },
                { "eu", "bbae1e60441f988e943a22720e73634ab8aa0f96d3bc1fc9df05c575cfb11842e6c6d5940d89aac93e5b0b072fe6e6549d2ee58213c760a8c9472d48a9429c44" },
                { "fa", "982a5daa5ddcd11dac136c0b683e096054c18765e29b40d07b8302506a1f4b7ab53d5d03ab7b0d15799197adee585a2edfc941e53ec601beb2964839c9813aed" },
                { "ff", "153196f6317caea01f5f02b5c06b38193c80bf8b2ffd8824f99a828e2f87d25dc5305364d1869d93a9417010e9cc746a5b3ddf2b037b66e26679819ca86c6074" },
                { "fi", "e614d685a7cc52bbc87ce17ca048b6903f52339be6d78b77577a97dd705843484a526867350bc040841965671e461075ad1fd685299354b09e139c3da547daef" },
                { "fr", "ac5bb94d9b802c3f1970817afd9edb4bd6887d1e2bf6d35c2320b196b18ee212eca40ab07534eba072a0b6ab5a5a5ee765f938072faa06c5367bb775620af096" },
                { "fur", "db22eb4b6500d3592bd8d9348f064eca5f09cb602d9a4cb738a3b8f4e66d7e21186ee9ac3232aa0c756f515da78df41d05baf6006bdfc1480e7437688c1b93c3" },
                { "fy-NL", "2b0eb364118f40ba56b88e18f0da3e374f08f69c1c7e6e83c07143a45ce7a3901c88cb999f34e9925104b47a92bdf6e7c0cda88e27ff84324655f979cec0e47a" },
                { "ga-IE", "acab201bbd25875ae3acf3e061d6ca400e5cb22899bb054d827580cee1b2adead3dbb31e8086efa986cb70043f4366a2da869f6cb426ca99a3c08e20adb3dde8" },
                { "gd", "7f541281502b98f5d7e1271cf2e128f1fea90acc8dd0e01955a429c57709a22a8b60e468a98fb7ba0322907d931f76c02c335e6e8f3cc749d4d6af8c037b1b21" },
                { "gl", "cbfd90631335d9a82e2888c0f5d8d4f9a8457b7482c1776ced3928ee60fa51f243c0c3dc72e6659ecbf4a72419e8bf708b8abb5f2004964bb6d7b3a001ad4a11" },
                { "gn", "41cebcd937b934c17d7976adca00a96385c4fdf8194c78b52a6284d1f7d0105e7bbbb5ad9fec5ff50de8598c153077997674e6d2b1589a143128ccbadbacd78c" },
                { "gu-IN", "16d1d7108e53c5e1228a1d337451a1cc9cc5bfa8a9edd7917e785cfe91477f6e60391bd0fa36fde51b0e73ab4667051bf67cb708faf862d8f00527ab251ef202" },
                { "he", "54d014958c0180f837a03caa1f7ca1344a23113f0e9409b5aabdc44d5c774400af61808445c0aecffe8c1e1f9749b3ad0b50d4dbb35a4a8b88edacb60852b980" },
                { "hi-IN", "0b8497b7f061ecbf87b911157dd593d34c75431801422def354b39dc8b6bb9b5554d0a1a10ce420c2afcbe3c3e6027a8329d64ce37de50b2081b98e08168dc11" },
                { "hr", "8aa24ed0b4bc52845f245e54ef3b21b7c7ab7e4ae983eb4b33313554973900fa8fc1009e96798ae787fe7ab6f12342320ae1cb14a3085df52682d5f45803f887" },
                { "hsb", "1693ea60d2c17457885242c824eca2d8d7fcfe4022df3425e8f6c925c01455d65b123918a74aefca5ac8724bf5fd21d9d8b0b029f5a5c8cb1eb4b6d8be74fb31" },
                { "hu", "11a8a488ba05f216d8be7924062dc5f12d3634fc6c96da4f67d4be141c22fc725133a45eb6ef97a11b59e20671245d71b242a96ac9e26ce5f75e95dcc88f0d37" },
                { "hy-AM", "827fcf79381174fbe5fdfb63e3caaf17ea9d96169fc4454878948213e8a88327c1c1496d0919eb8942fcc3262df0c8c6edc31cbf4282141298e0bac5e1592bbf" },
                { "ia", "5e49449c03fc85a5584c89ed01ab16d5c3108c01d0148f666e57c62bca4d38518854dfb61d76ee9936dbbc58701c64620ec59270cc4b0e19f3653c0fce32301c" },
                { "id", "d1363dd87b6132731b9ac2f0310130916e6c3c0b70bc5749d1f2086d1f01c83d0f8e8f2c23f97dcef83802022a0dcc3165c847da14c7a1fb55b8d06b33b1d365" },
                { "is", "e81b3551cf0c6b47dc37c4e252b83ddae81ec25c8e9a4bdfb0d0f09609f87e78462dde7f9fc1ae49d64fba17d3a3c16155f7dd8366bc48a354423db7858850c0" },
                { "it", "b875c14b6edae95507b9ad1707d125b3a3526bc19d5559d419b9241c0f4573a1c51e93af212357290160cae727a33f8ad8a91247876c8cf3e6461b89a04bcd3c" },
                { "ja", "e50cd2ddc1acdf1debdaf59556bb7db3f33e29c26e14a0edb316aa970d2ea2e9a8beb3dffe1195102e53a438fec90a8cc22b55280dcbeed6de05d730319d218c" },
                { "ka", "cb54eb64faa339a991dab4efad51d79da81479ecdf7f0e05791900e00db4fc3bb572c3857e0a37978c8248f97df4a639c7173d0e0d517fe7dcc7a847af6818cb" },
                { "kab", "cf4f21a467b5f5ee4f6ed315c360c6ab0e8b1147089687f821e98303eb3db7a1af063b764e5811c98e67b7165a34f82feb9afe8acabcd4d4eda1bde59b528a9a" },
                { "kk", "77c37aaaad0ac407e69396649a7ecae136ce28d52a965c06c5c4c3f0d7c6461d4c22e59d516d07916b767e442a49e81428673afa63b44b7df39ee1dec81675f5" },
                { "km", "f93fb43d1daf474b2e50d9193719866ea1ea61467fec2d735bbcbfb1f4a899e2908928a727b314ebe92c6c25f8ffb453af7e975699d34fc60b472d6f146327ae" },
                { "kn", "31c38b83f9e2b74949d10385b0eb5ef3b8b2726123ed6871935e5613090318fb4703641c9e6578bc97d8dab2aaf85f6bed9516ba096f516d504ba6dfb7e4b8a5" },
                { "ko", "ea8dae396f1ebf1895bc3d0bf1ad2c4d719cf752222dec507a7ff9935cf3d081cdfdab41a4fe02bca513d9be23b4b5ca5d4aa218553c4797ee16dfaa7ca7020c" },
                { "lij", "2f2ff051e7b780c0e2daa1cba3dd4d2156f70b6f95969543ca8f31e56b4ddd9810a9f57235e3890327ec60da52a719eb1897dcc1b56bb23a57e615eba44f9951" },
                { "lt", "f3e887bbb6f13b0d66072339d191e9ec1eed31ff4aa8b454e70c08aa2ea27f237693196a62e5d459fa205682f3bf91f9436618b8bf9129517ea436d1d0913f32" },
                { "lv", "dd6e07978a67c31059ed5583704a5eb184383573288182234050a85f6bc3d034d71fb6b433d5385998bae97d61a19548237a85522656f76e5734b7ed5d946066" },
                { "mk", "e14a07c61886a8fc873c706360eb1f1423ea91da7172d3486f36f085cd7aa98ae336cf59cb10b467b54443c7607e0ac82ccf71153adc901530b083ef8cf8fe5f" },
                { "mr", "f41fc49f47769d3766e2b0b92f5a66f5c2d8209162fba951ab2a9926c79c8ac38cb4a1132f511b206f416f216ab1f67707de1b04c13179284f27b6ccca398d6a" },
                { "ms", "5a03444834ef45984cc934ce218dfa45cb94cfd66f6cf4aab82e39968f61571effa68b71829a9e923dfd8c429f230f88de137908a37a1442ffa0ee5cfea3ab58" },
                { "my", "07ab52d06a0f6840f70cd3aee33126a91fab54d5b45571f99b95cc3df891c040c2ee05f4cbac76c1760e12c2d0102a202a3aefc3d25b8e209cc06bbdcb63861b" },
                { "nb-NO", "fc677567a3383a7f9529c02877b77166b6ed8cf749253aa2cc4a4edfe3f37ad8f17c052d54b6aadeac3fda3516c3048415589562fa73da5d22546470030cc9b0" },
                { "ne-NP", "9847a66e890d2b8abbceaff178a3c42686c81bd30faa779d1adce7ed504728357e5011a273b52c72c466145954d074435759e0c7be0bbd0a294693e5f0d3d90f" },
                { "nl", "a12a3ccb914d3a4fb72f1a7dfa89d0f673aae46950a8bd94d8f121060c8b409e3eea73619d6018c3f34917b3dd6234dd580247f26be701dc07490fc3f82997ee" },
                { "nn-NO", "1c69186d8d2021a871c902257216a4fba1e19bf4600b110091578512afb90868a68b3a8932d9fedd9ee63713588086ec5081ac349b2ff9b59db4a75a0958d27b" },
                { "oc", "8bed3fc74d52c8df7d0c9f559e5412f256747dc0a96210cbe9cc0ba110a2b168e79199b23e29f079a5e05b989fddbd692de20f5ca8473acb1b90c2a4cc05776f" },
                { "pa-IN", "8e3204721ec4392a9849d4cfd058aa8da8061763f660519cf9b130262201c8ae2bb022fa86ae49ea8cbd8bea9e9c1e4a1179988f0f2a34b425d0d916586fcebe" },
                { "pl", "dc2d3346a0f5daacf28a2856778d9ff002689c0fe0dfaa3769f2b9f7aebb4e1dc47e9aacf90d87dfecae95dca13fecf0ef09663b04181dbcce0f5841ec0292d9" },
                { "pt-BR", "641a1a70c15214b71393995937aac98604e11a4b933422c8385a899d41e40453de23a6d6afa3d89eb319794e84f0fcb33e6431c4ee29b19e5ed942d3282a2d6d" },
                { "pt-PT", "be2d73157638c1caba230db76813dadf8a26b4a80c87e76333a324760f2c224ed22c944e741da7e65324c8f7461d91782f80bc63ad52cd297794902503ca1bc0" },
                { "rm", "84c4adae3a23ebd74cf7ec4ddf9a7aa4abe4f3876c064b9090e38e4a68deee9f5000e72ad41ddba067223b1dcc8977d0e670a0161c3abcfe9b251cae3c0a989d" },
                { "ro", "621b1df18b2b74c080690a036a6069932701549edab5629d7d2781e343aaf1b8352fd4784979b5399236e9042918755425fd19af9657e8eaa7245d1cae619f54" },
                { "ru", "c048abe6c490910bb9aa22e7017ea296d5dcb8e0c2479a50b75ab3ce7bc687f2478e5ad4eb3caf9cb15461f19866857f478ed0384230e01bcb6125de5cadb0ef" },
                { "sat", "e3e1cc725168a86a8383c0fdd78b12e45d1199eb4a8add6564f4ab253329eee15e7fe19abb80a59e9bd8e33c8afdff6af323e99c3c4d5c493290a5c786993135" },
                { "sc", "e4379bf94fbfc8ed1cc008299e3c39e95f421f16092dea62a4c7d0b968840e3aba76a044eb0573f34faee9cf5a858d27bd3d5bc0a0a51ef981e727b37ae7f4f8" },
                { "sco", "934df93e3f097dd34c8fb038abafd7cc067873e771cf2b50bcfe2fc8ebfcd385d510c6527f5aa2a7cc0a0e1a77aee978034a7449fe16b9b66e6d645efc14a933" },
                { "si", "60ccfa9b4a5b1a581c27e98d8aee2367befa272b9cc260a1572d9d0cb836e1f96c2ddb49d9511b265fe1e0d14c310deb2938daa157d4bfd28de981b8b9d27910" },
                { "sk", "87603a6d879ff07ef094f84b6f7444336b65fefeb192a80116e5ab5c8086c6d291c451c07bfcc19688bce9c508cca6a757c41fb1924d1b5ba1c88ff371db660b" },
                { "skr", "b733c7c6f84c1d990f599c3d481b9a4ad07c8f0e04b90db7bdd36474d59a35433bc54603e05b01088a2ff16ca69e44cbb87273e7ff870c73fd3b4368f841e08b" },
                { "sl", "5ef4b9f32c6c32070fe57a27becec3f61e523ad90e34decf72c3be2633bd0b58a1ce39a67b6d865ef0f3a84322c8c5affc461bdcc4fd555e0c1a2edee5469048" },
                { "son", "d7291986e0d2e6db372c1ca676db154986f202bfbd4ca9324a1e4cdc0f2c405ab423c7bfb73bd127dc84a1e07bcf70924f7815bfa2c78ad8821f45b5071c37c9" },
                { "sq", "f4cf8f8847a4abf68d3f506e44ae8a3f87d5419a5dd98cd0b5dfdc14ce726b71f577e47e3d4a3b2d77d222d8e9d94d044ffcee32dcaf3a404f1b80c95cf80eb5" },
                { "sr", "11d1eb2d6dfda5c7fdcde4c1c876da28c582623e2fadc3b89deac39e7de70eefe2e4d88048c7e1f6d0e8e59645669a2a65dcfc28f53d6a831c1f234515a6f491" },
                { "sv-SE", "2e225c6d6d994cd4536c8323f80552408f4eb97cf315e012d3ad706c72ffd5681a205a0d0ff0738dd0b0c63833703512570e655321346ccedb46967d4d622f27" },
                { "szl", "575ddbe401d2ab603a37d6fd127e6b3f2d93d373a5e48b05e41325c9a4a48c286aa9ad60ca0fd4c274e0479a87013c1f2f94d1995143cbd34ce0b69767eff642" },
                { "ta", "e543137746869c232660a94dd06eb8b1815ac476e3a2fc8fe8e19bf1be62ecdccc0cb97a343ff7ce119bcdda8d222146e54cb366f82fce62674a2b0ebc0425f8" },
                { "te", "3eb0f91571bca91d3c45044f29930e27431ef55ec28534b36d0c99be487c2b96cc69592c36992b1302b8d83ab1b4f56b6d6e715fa264e4280e52426086000210" },
                { "tg", "38c02cb0a71bc2336d245ee2e36ef43ee3e1869b2e4f0295b7842ae8e19039284acf2ca950b6af930198fec516c6f14b44663b4ac0608f4e6031eade406cd330" },
                { "th", "4dc3c7d16250cb32e0145e2ba3a109ebeb36f5e840c4882c7d670e37bb2e5c34f2fd4fb8d7d42ac108d6dfa01a2e243ec74b33f79156f9a250ab7d78c3f29085" },
                { "tl", "295c315dd96376434547f7f5602dc500b0f78237352d0c10d8cb05def61ac4094bc96b96ffce81f7cd30d6450413a4b50ae2f2e23bf2d081d77739bd26a922a3" },
                { "tr", "eff2832c79c8dcd4bd333388eac93536aeabf26339b873f38e677adc0170e43b31e206472420e317e3216ecd99f0dd13a9dc0ee8aa1c663334ffa42b4cb9eabe" },
                { "trs", "4ca6d405a67c9d0784e50f0fec0058fbd1c24c5ae159c68f2341e60b61e113619457d6878af145ab8b03af0c169191a28ef6f23782b12fe87212dad7ef14ffb9" },
                { "uk", "6f39640bdd3f4f7ff43fee20ba1f68aed555246c06e878f773764fb9ed224e2d65f2472f769e04ef542ef4db2d3c48b1f29441816913d547e088523db12977a8" },
                { "ur", "a3d4ec81f956a99444407e5f6c17b0981f6cbc27735e79ec8b4bb122a352c5a49f1ecc33025a7bfc4e024d900c94ab8f2c085b23f1fdd18ba1ad37f441f88adf" },
                { "uz", "31c09247059d65a4c3ce228e169e0a85bddceff3e922647a667ce53de2afed628dc8158a384c45c9d4e1d5830548b18c9033fa88754d86182170bd680b4af594" },
                { "vi", "6aac0ed06fcad09bc5651293e7cf929d4eee70e2dd574dec8b0ea10dbdec769095a7226791d65dfad1cd78091320fe49fe7992c4a827c449471cd4b2af052383" },
                { "xh", "045802e64b8da493b782e94ac4e7adb7da97457b6a02e16b13d8e45abcd31408916d736bea22c7aa6ad04746cebc73a76644645b74dd037cbc25eca30e472ac5" },
                { "zh-CN", "a3df8c7aac2e3f41d2e26a339f2a628f6590dd210b7d22fa22379ea9bcb13aac127c41f81125632b1499f29a7e8a657d3c4bbb78f8dd593a288dec7514ba1621" },
                { "zh-TW", "e17815fb0210544c90de74dc8b414a6ebebf86ea6787e288bb3086e7685a1ed46295fe9bd9a0538c4bddc4b0c600a704f14c7ae38b1c4579247259cb5bd64dbc" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/146.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f3ccacee9531dcfba4d31d06e2b18837450cbf38f7534ec38e7004d7ed413ddd0f252ef0aa95332687d78fc91dee5cc61878c75344107b9bc0ce2294637babb2" },
                { "af", "f80a49c892ba34bafc57ff7828e678f84e731701dae024d149c1b96dcec6ce4acd420c4e306182d75821baf2bf2ea9e2582e3dd4db383561fad47752a9474b62" },
                { "an", "a37fafeeff07b260d19bf76149f91149b5aeedd1194c0a4288a9d2c831bcddfcee62732eb7a6cf3eb17b72830011570c9ece2b41ae5cef5c875c2324735efec0" },
                { "ar", "bd7433c93eb7834728717a7d9f003d391878b8d6ffdb9ec09be346a4e76cac68fa62d2358c371b2a69f5508b866d667e7198b337f567e8f81f105fd9188fbb7e" },
                { "ast", "b50367f73cf21251bde332800c4482bfe18c9fd9d7f49b0de11591b56806bfdaa1e6f44ed05b187ce0cd9cf8176b873340daaee52625a6c17e661991ab58ca96" },
                { "az", "93c26601844f2779dfe58f691f2bc2cf39efc93b009a8e7e2f955539d1db610797a889b8e05aa00b2448c6a4d801819d0d82590f7de67f7b7ec13d6decc39d04" },
                { "be", "2f339065299c8a77a0277f05b6d16ada7b1622fdb82a5fe82a5a2efdc242ec468f219b993bd179434476d9ae27fd8fd5c1f40b1b2d3fa6e08060b5f153d48430" },
                { "bg", "64610338b784e061f7af04fe4b52a57f2db021f523bfcff2e5dd7cf5b25fe0d76e3b6cb436f51a25a8887dbd30d22c79ebc1920965cb967e058bd1548ede78c7" },
                { "bn", "a746e745b889d03adf990d0f09e9997ef5f0225da683455645d74dde8095775bc9f167db23e79b59dbcadbc0885a7b84d6fed94052411186be52bd6a0bbc7e53" },
                { "br", "1328ea78bf0ac5f7efbb99425a8fea899f5c61ba4976f3831b48a9606951f2f00638bc9675f4b5d1848a9fb21d87c7b8ef3396c504a6e1747d6345eee8ab1cb8" },
                { "bs", "0e0d8367204e2a6d566f0b754c9766aedd51955f54948d6a764dfd21c8315d6a9b4bb2cffbd4f3f505dc831ca453cac6badb6599936f329d0597faa4e8786f5d" },
                { "ca", "9d33a166cfaf7e98932653631172bf36f2168743ab8b799ea992c03dee275e3a3df6bb7f48ae5aead183a62d185cc3fb675c4466b1410bec1646848c588b8daf" },
                { "cak", "0e180d2a17ec1f33b2486ffb437996ebe2ba145014b26baf7b14f2154a7e29f4d8a20046e48fd89b22604199b6b2302cb6681227e4f7b1aebae865d58cb071d0" },
                { "cs", "15d9ad92ac9da3580fe0f6238d21479ce6d1bc53826213b65f5e5fa4146a193f6025d3b32293452f5a71d172e5f4759d1a835c5bf7b7a7e216d2385e328d9e9d" },
                { "cy", "12396e38ea6d4cb77fc6eb953ef14fed96518b0223cf729e0cc64080fbc2b90674ca48b70adcd9c8f95c4a86d5b9736814173d2bb6fae98d547089b202ffee70" },
                { "da", "e7deb7cf237d3ee8bbbda510c574590a04b923e6daeee72ab21c70626cefeb7f152664f9555750d294eb284f0d50767f93008b4fdc4014d7032604765d4e7742" },
                { "de", "dcc923799797bd2f56549a62ffe263141ebe366efafb1ae161b6eb115782410b5bc6aed418bf2eae3d40b0a89de2463c97feeb7ad92463e23f7f7987037c1896" },
                { "dsb", "b7f1bc3fcfb3fc8c7543af139ea28d7846bcd4e308b9d951402d66e0e56202f0ff7017bb01a71facd81853a5ee443a4e245b0352a01a2ca2bae7812da5959eb0" },
                { "el", "30e38205cd65221d92c4fb677f8ede93b2b84c64b1f5f67d24e8fcf08fe2e17def9d845fb7fdb0856d33dca774208f12ab6799647edc4d62cabe93242b142fd4" },
                { "en-CA", "897e6daa7517ff96d034a50fb06d6989345ac40bef3e7f1aa91e0cbc2c68b4f2074fb5f89f774040a071af3e194d40e66b8c09b2d07bee45454c41c61b669de9" },
                { "en-GB", "cca593fcb6e6e3e0e8141111a64685c79326a975f24f82c8a74279ac682babef177a08a8ffecb842b8ab6975f3e35d35714ae66b7f9f7a10247d92b8892444bb" },
                { "en-US", "ee1503067776ea564c184d63b24f7223f6a9da1cdba0551cc0ce7fd09c48438afdc2cc8f98a0dc699c066556fc37c97ccaca87965cb3bc222ca1bdbac1f7d4e7" },
                { "eo", "345a5d92687d92849832b4de69a448e0c94fe8337906eb8f566573b2bb69ff15e2be9c95fdc319fadc18a84731273108450132ef4ed649599870ba9b3eb7b7dd" },
                { "es-AR", "f735f1fee3b14f875c53c3ed631e6e3caf09775b8a92637375b17513b5b50146eacb7fe216ac42e059331ad6c1ab2224c4683028ed6e23596bf9cb4ddc0472f4" },
                { "es-CL", "c33b4933799b449c0b3304309eb50716441bb02a5b519cf587c1de0d305fc7fef9b76a27bbdc48a5fac057f679eab7475453ba704492fa2ae59451155fa4d1f6" },
                { "es-ES", "8c813647587832a54ebd735c66ec17407f98047fdb74a6af4dbed446d1b90ca98880aef33d3a222333536afa2a4f6a1a27d3c0018506077c34d970162870e473" },
                { "es-MX", "e1b685b2e925d89c832feb4efa18c5471f0a2b024d97a6fa7d704ba73931442996f6d061458b70a6487814040a6745a6aaa4561a2200e4c2985cf4679dd484ba" },
                { "et", "22d2454bfa7496f7ce9217ce340dd4c3fce326b9ddf2e50ce4a15527908a5e847ad441f39f844ff199d88d9af1749596755e2ddbd38f6c7676f16e57fba53b51" },
                { "eu", "639935a1d053b3c36c8a561d90f2f5a79c041ad713e1e4ba2b0429ffeb8d11c6efa664fd13c2cce8ef1b537739b49a13fc9ce25c624524f08fa821d657a53ca4" },
                { "fa", "e66ff45fa7dc2d6342a07b6db0cdcca3ab31431dd56e2a9f8fb97185a3dc9134ae68196ef081be5ef41bb0e7e5d70ce61e2e3de35430253ba4a5d9ef8f632e55" },
                { "ff", "9d325bc459785f092cda7d87c9f9defec2f1057df6a50ee311c1d1c401cd6de0eda849a8414c965675067e0aee23c9362a057b71104cb35e94ef3716c304659d" },
                { "fi", "9ef0bf24fc3a399e9768e33847fe0a2824d3e60c0e5871712d1da3f026547c151acd3f7f367bdd68b2968a336438247ef62e5a740ba0413ae8cfe750cb08a239" },
                { "fr", "f8e16eb4c287f733091d421686d77ddef0612626da8839818a0848f81dad404cc297e7d05979aac7c842459365034e2a6fc77a8750c1683480d619e4d159d386" },
                { "fur", "905e0dcea24b889e6f7da3eb2a5e3548d9fb5738bbd4f0da07688354ba0a9265b205f6582050c606b0127b194da0d26cc3847f7b4bf991d5965d245988017ef7" },
                { "fy-NL", "990e7107ba39c542d15b3bd1911b45b28c11075a71e2b19fd1a4ad0515284ed3038be11ea27d8eee35a5bf5af5c0cdf4f8042a89f7e15095ec99a46ef39fe293" },
                { "ga-IE", "d189e1dbba70ccb6cd3dba565226b6c75b11f2c8eb39de27ee797c91c431e00644a3774141dcde7c7dfdb39779ff6931a6800738dcd477340ddb26b115f35363" },
                { "gd", "00eaee2d2a294e8d985946b7fbf929359b2a13f1e167bf7315822416706ec8de01389fbdab4be518f639aec0506fc9a997f9b0d836e76a714fe348c729b0d88a" },
                { "gl", "76a681a1d964c2fff69ff2073a937a35639bd8673dedd8cc3d347cafa635f477afb0efaeb74533c9aa83f23f4e43029ba743c2c272542de0d14379dbcc121531" },
                { "gn", "a026977003428fb8e31d910f959fcea0de681a6e1f526e7f5cec704609a747ba813a1554bcc808e281e8a3c2db9e90efeee83e6ab1747c8f5adad5387992d56e" },
                { "gu-IN", "a521482e1e2f6116e9c38ebede2fa677312716e160fab6368f57e3c2e6725eaf46cc3b8aea129cb40d3d85830dccb5e87e6e298eda9c48b7a8cc57f4dfa02451" },
                { "he", "8a2c8baaf1ddbb41bbcf4da4a8a6c66f0375ac8cb8ca2e761833b86ea7145f9e165ae6761a2b454fcbc9a2f7956c7c765073880b5d114ae2077e539190102a61" },
                { "hi-IN", "bf1c077d46462610d1ff78f6aa21e154d13fdde6a4d8f234abc565e3d02bddd653daaaf738db7e3c0d7c94eee4cd59c9e27d923d1c1ece3c14c256153feb4a86" },
                { "hr", "b25631ce494e817ba0a0fca6252a0722b8fbc1f7281cf5b5c2f54f8603d5eadc78cd694eebfc407e8a5b1556256334c3e08a9e44048eb8ea4e5b9641766e35d7" },
                { "hsb", "d16bc19f4b01cc19f3203c5c80f9045dc73fd797c41a21a25f2595e350fa9f055237526306ee8948509280c967502c2c54c0b889ddb6b273c5f002e9d92a946c" },
                { "hu", "eadfdc62cd3c4b62016044bba28bbf2927574b914aed51bc5c6e89d3a57a814269843f2fa2d73a9ed04a28ed3d601b95b2d391ef2318a9ae3ea76b7d8f97204a" },
                { "hy-AM", "838b9c2070bf3bca412b589394554aac5cc697acbe3f34e99c1e130b682e396649489369d1036631db20e7c0b974dfd4d4d70974126e9da115fc46a42862ebda" },
                { "ia", "45b7599307a313968d09949b034b1f1e2a8b2c75ae89144793ba5a958e6943d67f6cbdfa826ae6cb3e19a10e8b6fe825e2e57120bc1b80b90bf8bb3233456c46" },
                { "id", "760efb3d3946b8a13e539eaa304c33bd260fe94ecd75a397de3f7e20ae30a47b24f951e3fc545c9e4890e0a3e45ef8e473eb49cb81c69a9b4228b6fae21e76e7" },
                { "is", "8817fdbbcd3678c537dfeee4c0d2c92a0621da53ded41da4dd6babf4d7ed932e6ca4be40a93a74d620aec2ec237f49b96f3a93592b4b895b87bbe7756ee92b11" },
                { "it", "1db80dd8f2e94eb809d118247eb4ed4008a1b7a4573c08f287bbac5d47d9fac461fa2e50aa89c2726300256b2415957c507da4d08ada34d8d11da9a8da3419f3" },
                { "ja", "68d3aab8e565b57266c5eb10ef3bf6e8c4658a3f9e05e5e151c0d9614ec01efdab9ab1bf760c476ff5c2da1e3ae1811a7ef8e220ee23da9b1adb6e73d2545243" },
                { "ka", "2beb61af5ba7dfe650661ddd467e0e8c2bd9e6a1f539f8602a4019cab07a5e28344745e1d86b4c7e566af92fcd4e512ba62de899121d879ca8241c98ad5fcf6d" },
                { "kab", "bb1608a079b46d2c7528653f9f9a2f1e3185cf1433f793d2a4cda3ed4f92e2bc0775dc0ae809a309bd3c703ac52548f2c1e52d05d32bfcb4b7f1ca108916d913" },
                { "kk", "5f74be0840365c15038f21a6579aa09357a1ae4c123fd283ec53c35a3ea72dd36d898a740cf78838df0b9b402fc018a3b13c4c7dcb6f2e23a32cd243e06ade21" },
                { "km", "d02f7b9b0017d51c60c50700f60a448e1d703388b1795a64427309e6ef8517b89192a338045cdb85439ca63917c8a2cce4a779a0e42e9d0639b6c58ec03b491f" },
                { "kn", "abf89471a80728ececd1b106874fc2c70785af3d056276faf7594a50fad78086825136c08ee6fd5f3bdb289a901d3a3bf723c8f3058d34cba7a8d7e6ce3f4cd1" },
                { "ko", "7bc43c408d8e0858c71251c0ad098606704f3f94e46929c7fc248a08c9f3adf1545bd38ad8e7b7ddb51280e62c9753b64f53e833c787ab8424fb6f5710ecc7df" },
                { "lij", "ebc73ef7f92b5c1f6295a9f1b1aa0df0076620482e8ceeadf85a2aa49f4a2ba60ce303362b942c527e5eb337e6c32fcb290978aba4fed673c3db1aa8281bc572" },
                { "lt", "df0f91923bf0d8e8c44469da0ba4d13395e058804f03a25c90ad628465cb059eea5ca0b91f8459129557944f2d440954d2dff4110519cb35188051e122163239" },
                { "lv", "9e1dc53bd37ed6386430913c660c52ce578df626ecd9973a5dd5e3355b906f4aac8069b689e021801e4863c8da28295b570dc95fd32e7606f30e277813a57ae7" },
                { "mk", "3c7a6d18f19663dd3695e1c0117a1b4c93064efcfacca1ecad7a1a56281d61077513f79905ad8c7f5f2c4b8c3edd967744f9e2ced4502b33dfdb0bb51177d333" },
                { "mr", "28cd12bc897885c600e257191968453b0a6a22640e3ea336c8a76e0f565744a25d10f8243c6dfb731339eadddba25d4343ae2a75f27d6a1ac0acd267db368315" },
                { "ms", "962687fb3c8379c09038d44a1d7a100c3ba1919251c88bc0c758333e2c8a76ebd3d6e0e81d7e21925c56d970e41ae10303348535bf0b0782e58dcc034f3c39a5" },
                { "my", "918f2131db12f418e463ac740780204b1960f2a08e9cb836f8590b17fa280df030e450beb7a34c9c80d5100454edfb60d12c2101016a92d8b16606f9aa60dad4" },
                { "nb-NO", "67851350239dd3ea81bd9d9b36b8955af050d9bc07a42947466762e8f4c32828fedeb4aeb8ab100e0a88a88f7b4f32582722f2a7829765f53cd3f942e2430133" },
                { "ne-NP", "1878c5f7171cfa218f0870ad861c805e301e474e20189e4646630fe40ae68d96722dcf0dd4ac2c47f5d4238074c2925ed955bccd78ecf9a8b04d35342c98df05" },
                { "nl", "bf81f4954514b17dcf2637fe41b66d266afbd71e0a7a13dae025435adae4cf93d346ef8bf0ab26e25f77636ed483d7d9dcbcae55c54123d702fd6b48cb439783" },
                { "nn-NO", "78f60377b13294db09c34864e8a0f77a5c5822096aa154bfca4dd0d32352d839c93b3c210d193d8d14372d7f8d60a24441fbd5b65dc42eb94e8c1e7f8455be07" },
                { "oc", "c1a7a5ebc58f8066679a89294d3a4f07cba0917fa29ee23ebe2ac941bb1d906f473be28fb920d29e8f83ae678ebeeb460c25fe0c953a5d9abeba758bf63707dc" },
                { "pa-IN", "7b737331333bcbbc082521f26518028846bb09141a2e5af00d72e231dd3b3a8a34328f82bd0f56ca14968bac4fe4ff3743b3b90607f42293002f25f97c8db53b" },
                { "pl", "d244fe217b52ef2a2ce1174521588f9c99f72087132eb12a9c4b87a28f88d0f346f9379b0ad81a885636abbcf2716fcb6f220bf2fd2008b852d3afcf6f70af17" },
                { "pt-BR", "38790d11168d6dfbe579a799cbd3a5f4b3f5ba69774b1e4718be194a487368918f635879cce5bff58f942bcbec68f762c622fae62ed9c584da7e6eaa74407bd7" },
                { "pt-PT", "9f203f7b9f994f0b7d750c9f46020dc271fe208975a518ce7846f896f09527e0bae5ab817f1fd5f295f58e2eab794d3cee53badf85f0cdbe392d70bf45d94d0d" },
                { "rm", "28d2b6bf5b32492a05f6dfc24961e556f24202c878cf100f9c1f4fa666a43a35cf6e2961b9fa4fbdd234e28f3e398e4ad933447b0dd768ed4842af7229182368" },
                { "ro", "90c8c7eea5c45f3835f402156d9b2ab6f808b28f39a93f642038855075c6530c7744be653cec15cd63acf31ac15e97a37407d34c2f3d9a497f22191f53f66115" },
                { "ru", "d12538bec2af8a06cd35146fed1e854472ba6f6c3781452c88764f6b03edd6ce9f73383cc00912c8d29cf97772b24778a7ed605ec8be4a6a7859b00875ab000d" },
                { "sat", "d84cc994a4f5079f6965ec0eca0d6a338bd5f7a0c2d683d9d02bfb070db506ef06c2e7aed334f23358be4189b7b7aadca75837316fd772de5ee916293c67161e" },
                { "sc", "20da0714602bc47d46bd308c42cb08c04ecdc31a84a7240995812e1cb1fd353d6f51ca8892f14bfac10ee871b6c0f9c9416c92f74a2a77ae854ad085352b4118" },
                { "sco", "81a311adfd48d8c241f04c2cbbf758678c10b903f69f6219c7d13af08a15ccb775eb8fab6616cfff4dfe6ed7b36930e983fee61cf87a2c2e26d4c74f07e2db5d" },
                { "si", "e2649b6381df3e43354bfb24baeb65696b8174eb99561801be0e60da24837743ab4637c4152da7c10bf0157ac820e2f13de01c698881b3215dda8f7727b943a8" },
                { "sk", "fba69c94fb90ba6fd5b9473ea52643c62721b7024fb1156bbc6cc85beb9ae82c92d6247c43946e1584d64497405fa49306f31fbb825a16489fd5772231c70541" },
                { "skr", "66fd578ec1226c07a3a443774fc1b40acc949798e43995c51a74422f7d6a21084ff5449967fee8a8a62155d884f70004cce4cbb8d00ee6aea80ef6558b78ebfd" },
                { "sl", "1d3689caff3284d768ded6174745f1f1d477447bf8e1fbb5f8f25d6b896580499f4218bd1519e64472276b7af3714aa26ca5655d7b7412072b4643899318bfb1" },
                { "son", "d2e6c7683ee41da7d61c9a62f8b09eb6b6cadd43040de9a38e8e5fdfdfdd5da50fcb8aae39f3101252c27e48e09633dcbf3ddf4caa6ec64d064648f6e8a6925f" },
                { "sq", "f21ae76bb1a75feae07dd7baa02acc2fd4e9d201de65e63f5e4040d95c36a24efff98ab280bce71ac478287b5707967311f4e4cb411c82c0761ca3ed353e19c7" },
                { "sr", "4c5db05fea5968ec3274eadd7f7876c1494ca76dda9a713b0e9487db3cc8d40442387ff834e8fe6a38ae7847fbeb03c0411e0009cf19afb6714a20baf72147bf" },
                { "sv-SE", "5218948d637f00819bef6b7c3847a33d9f423116ada5e9eabf18143e93fa6f120e802829dea25eb95eea03c485ce1422f5463542a594dea136ec049775ec5ac2" },
                { "szl", "20a4363485ef404b8e1c51265c234c145f32bdc278fb61d808b467e43de0a37f23412f77445527b6bf79facb45ba8c699e346cfcfbabea323f6f0d28d85325ba" },
                { "ta", "a988629d917d7f926485ce707956975d6be080410b326fb24c1207ec162f50dd34c12030475fde412adf44c8ae930a141b914055d5b83cd1088719c57514af43" },
                { "te", "6d7c20498e4b65b94a426c819065da197deb4f5e315dfa0201ddfa6c3f725e5adfba59084440db2de26d4ec96270ea141d9eeb98d25f8a1312d15725e7f8e5eb" },
                { "tg", "8499d52790c090aca055ad13be09985d10ec463de031415e6f19c0d0c7d7f4d05b5cc351c9ded245fe69f669e2b7e6c903af0f64bfb494aba809af1bc3d9be6c" },
                { "th", "436d36f1fe935454dd687f279661c1782a9cfffeda89389f4dda7ff94e885d72581b49e2f2defbfe3dc593274c753af5c48ff9680a6a870456ffa2cbcfd0aed6" },
                { "tl", "e2bab7fa840b636523070a9cf29a159d782278d98f8154e7cdfa79b9885e47c973d5a5ce9518f3c7188cc5a39e99d3e8544892e56e2849fd2a0fd7916b284330" },
                { "tr", "f336be84102bb85c205ade6512ad3f5fb97466c521da1562ae9a10fb541a36d20308b8fc6d37a60f3ab7c6fb4b2fa5c1db5fec99d2afb4068fc07a435c3f0086" },
                { "trs", "ffebbca6e18e512f84b330ba1789a8f857959f160a4da934fdd7d055e22209739d07ee4404b66a2f2facedf5faad89bcce2a0bf22bb5394248d96e462a93a158" },
                { "uk", "be431fb1b238ed939fb9d6ca6b9ddcfaa07b9c66bee8c1f2a987f237bb1a305d1da917933ba49f06fe52ff1e38a295bba8f7369c3e7a59bf8551aeeab707acbf" },
                { "ur", "5dd439fd898cb2f9a67aff308ed77df145b62464292382e33ed406e02f60105f4ae133a4cc2f27e1d1430f2b3d160fb92324122461b514af03d1969176ed6389" },
                { "uz", "7d40db81c8cb4f97fb49a36d0376305d5476cf8f94124258c81b4752fd302c9c389a92ead897e0db6d2d4a77c03fe9db5c0ca754ff6c8bcbc8ff2f082bf45777" },
                { "vi", "5c56bae923f6504db0e03e07b166bb12cb28939a63483ce35eb9617053794c96c4024c3748e6d27afda3bb291608686e43632cffc62559981fda3c1b06482e69" },
                { "xh", "cf9781b6452e4758d740d5a076bc32ec6c9c5a35b7ca527de86f22547fccbcffcd4e57bfd3248e99a2fc789c82a5497c23bf155417a77835a242fcaaae4883bb" },
                { "zh-CN", "73fee8d9db2b1c6c90e9eaa7286f8b449107e8da661f4f2878b17fcf41212e218df739dc6c067fbe5727fe62b57e5695cf04ab799ba69e03054062fb62c8e8c9" },
                { "zh-TW", "d0f89c01f5f48e1252742fd8c2eb34978c8a8a7e15f0ffeb02a0ab77cfb7838a489931ae0ee2c033e018615325c53ffa19e514a1f2ca16e719cf754814eba8d6" }
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
