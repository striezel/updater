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
        private const string knownVersion = "140.7.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e37399343bfd47401baa8b22436b73dd45e47298eac459a099ea0279e6232abe536d31eb3a9276a3b2c8d2ead6c01aa3e4f1e11f5efb06fb66f3979f805f18b8" },
                { "af", "5af1dc0d7eb935f35e5f319fd5ec2e128456beddfbf3938b17b5a9ae6c6d8ba14c6fe8155f789c44237dcc97381e7ab51348d234dc74445db8e14760be66312f" },
                { "an", "28ac8cbca44809c7496447f92779b0bc8827d84d56079e329a912a79e8271af4bbaed046b36d4fed3f6253b3e03a3779aa3b9f3913a7b50ae3d15fa7b73c3993" },
                { "ar", "0cfff1c5eb5bfd423a5003b38bef0a5b1c06a23155ed7232c50d142290f2e1a7716c8c783ae9cac89e4b65d6a7df136158c3e7ba548984d3c6b24f1caf40ee93" },
                { "ast", "a6138bd786ffa9fbc2d5c1b173e56b6943e82cbe60f5135be9c10ff7a605e55f4b5514dedef4e486ceb6d76b4e00ef1adb68f53745008bd42556f35487b0a109" },
                { "az", "97e46d0c088151facdf1a05cc2a10e6cf0365342e13b104281bf4f91147800ecb37b6f9a8c4f514eaf2e3898f1e380ed7bf5eea40cbad368c28449a6d5ac40ba" },
                { "be", "826e207f42f5f4048de99ceb95842bb1ca82c240fdcd658a022f58c312d7820117e9a8ab3bf7e6db7ac07642477b278ea92a102b0db6015f02cc173a571edab2" },
                { "bg", "ad1b1987df98935f429acc76d411043c9085da16ff1020bac7b6c5879b1f492bc4a765263c5a5903043cd20d8c5007643fe2bf209ea65714f100c8d522326ec4" },
                { "bn", "a4a9f43659dd9a824d0b6e8cb2efe3a4e4d9b09f2491b1d7922518ef0550055aa0ebaa6c80c125cb755937d1bf671d2a106a344a7c1f1604d1f603b2af8f23a3" },
                { "br", "87edf64a796839f1ce8c0b38ec39ec0770de09261ab47cde018dfd701dfb777f1305b4fc9d966964d50f0bfbeed06b0dcbaed0b68cfda6ae0f69ccf11f66840a" },
                { "bs", "d8e04933aadd524c1d366ce2daf6f30ac795a217dc97413538a01dc58feec5ea015cbb5e0c3d6d66e38b7237d9583fc706cc21fe3f4fb401cd0a0d9b2ce5fcba" },
                { "ca", "f87c215f665055b05a58efee8008b35ca680facd35fc12885e6f307a44348241874fffa5b6848a3c74c9cf0e007c596843742c3ebf5d337c3769b444307d92b0" },
                { "cak", "4ee7cb24cc40859a854a2397a1d198cc768efa8a27925d5a64149381be53636e728a0ea861a017511778ec5236e7271dd994839423e673e80c5fefbcacce6b6d" },
                { "cs", "a1d57180c3a02917748ef475f16c445885033229215a0b4f7f97d1187aa8aa1976bb914c5ba189f13414a4e2d5355bc8c699619ec0bf33d3728b1f4e9e3885da" },
                { "cy", "fa96dd05b5a952876354df5c8f3c2227bfffc0ada616cee6f89dace9e2fda9f597d642e5ac89d3bdb978c5744c00d34a1806f45fa6a70bbde0529b870f5f49f3" },
                { "da", "977ebfdda16618d5d7874699ddff17600192072f8a2a238f78e22ee92eef2a7feeeab2cd3d683c22d9f29350d1bd1c8e1857f638ceae6079915bbd109eef3964" },
                { "de", "be94cfafd1b05951ef840b9d4ca807e41ab0e478996ca6da3a75fb24264d2407ae1a0a65c4512fcef8915eeb1e26a977e705de9f55fc27c30fd2c7d895c3103e" },
                { "dsb", "cd10cee45f52c6d8a04e2caf0115019255ee056ef0d47e304833d02917dd88789b6eb8a47066d2eebf73a7ec3bd374ab0ed089b734e5a86abe9bfcb3367c783a" },
                { "el", "9e46f7dd1cb771e06630d15a8bed51fe1a0910428ed979990df8593d4d4ed6084cfcf5e717ebc1244ae2557717c27caa30c4818496879a0a7c4e93b09339932b" },
                { "en-CA", "60922e91355d129cd131fd60f46df423fd0a075e641f3b14daba2c63cdb02eea723bac0446c93ce356de7a1369dcb80449e79f62675a8361b6a9563365f517c4" },
                { "en-GB", "8176b88763c8256651f8486a939bbca8beb490ed664dc74ceaaee0e012d5f96545eed939d92583bd2c75c05976f6b18ff4bd8286ae03e937845a66a9a20e324f" },
                { "en-US", "56090884f20fd372add6c8be513770b1af294b0d27adcb87292f86c76ef2873c966992f9065da0406b35bbd045e312e2e7bf03234efba10bd256b057d72ba7a8" },
                { "eo", "82d3955f96cc8477d0a821e9778f8baa278b1316c7a9ffabc0341bba9bf413d045ee6fca63b8ecad8b5b721cbc6f17dad14f9c34bd9c8aab81fb98ad21c1ddb6" },
                { "es-AR", "fa6d9f2df791e32a258ed61b517ab9a1b84cf53dc496c21177628483925f8abe5663ec20bd9e8290ffe6ef5cd35fc42924794a23992e10911b92726da754bbda" },
                { "es-CL", "bbfe43e78942b4384edd8c2f140254e1cd26348151b1d709ce4fa176dee75b6bcd2b1a281dd877ab3b7026f9d35f646674a1c6a751ae802cf7d6ac8d99a6dfc4" },
                { "es-ES", "1193e7a1ccce5efeae93c41a8f5a5ca88ffad439207774b64203b84343df7027072a879044017bfd6297ffd50423e5a41dccf9b3c1123be06c932c7bfe461334" },
                { "es-MX", "e5f0af89c969c397025208168960b5e0f6638aa7c5bbed70c22ed6b398b12348b54ab4cd58094c5c869379ed4a3f7fd69040f8a870b8a43c3bbba4359a8bbc78" },
                { "et", "ed667eba779af11909b39e477c49d544c39603ddc697e595c57ddf65e2ddac5703fc5682199de63b58de94f060dbd40cdb50404cd528469aff2e8aa505969556" },
                { "eu", "6551a37972b1e5b44f8949a69ad4fa882b96937954d465e0a9f9068c3a3f3604336b2c61702f7b915c77d3402c8b57e8ff9b91e6c0f34d5c77c4686b4f10cc7f" },
                { "fa", "022d47aecd42c4680cddc48d3e65c8837f1a788ce97c2a64e90e05560375d20a6357c92736cf17ab9393b18ee2937b9bc1cb533e51a7a4b4df0c35d69fb4ec5f" },
                { "ff", "a3f3278f25abc00106f7e429fb5abca42e9d810d393bf35894eb3319b17a7e34bec2ecb1b24c647cb27639f96bf3568ffaf6393458892187024b5b52e0fca844" },
                { "fi", "7e388ad60fb22376272c73c5b88fdecde77b6a5469168eb5b1fb7b87c9238923983e7b64561f97c72f761719a75cfeac6c4ac204422b22a07541c7f8873e0291" },
                { "fr", "1f5851f78165932dc0a657086cefb2be0b8606722bc5e73ad82abb8ea69471d0ff711349cea09d9b32e827e2160f012561536fdf6e56234c484d4255a9e2e010" },
                { "fur", "3a86713d98fc329d7669f3d87636a7bbe61fc663a2b62bff9bf72d943b1f3eb9b51d2bb476d0ce9215f96c250bdc74c23a0adea0fd3c9d3172cd8c0eea35776e" },
                { "fy-NL", "53d57a015a7244ab8825a492d6c28e5b4b1a2ed907fcf8b9801e09fc7da47caad28c6f992008a4445705fc7d7da1df795098c5b76ccac2253407d88ae1799c01" },
                { "ga-IE", "ebefbd09a1494075f1b743663ca2758f202b902630385b71e39837bf20fbd8a8c787d86caafa6bd5ba7894513dcfcaa306f52646501a68bc89e46530b16093bd" },
                { "gd", "c2e312cc1279f9aaee6b7ea1474be47e8e1a60064d8b5f3ac84ecf2940f690010cbf9b7c34db7d2965a2e931cc020f3e9709840d6885bf94977b6055920a2898" },
                { "gl", "e25de9191bdfb014c55d687a447614f41a8832f9c1c74b174976fac7d2e6c30eee7258113b1802712dcf9c1fc21ca8f7ba42c15af20f5b9860d686e53a6f2132" },
                { "gn", "2deae5a3a93d194fdd541e3ca248659b932c3ccf2e688f6024b9f54adb05c8c211e02d2f9f3191b57c4f5350b480d99572c1c003460ec7eb45f4ac888bc4d3f0" },
                { "gu-IN", "d6d08a588b1a5a65e7e235b5210826a23854d31f7d0379787202a49d0b3d5ddf0dd9dc94a5d297f0bc4183b545080730347cb168f0fddd90db58de0cea8aa38a" },
                { "he", "f8570a74b08deb6b1f643df5ae15908b443a21c8397292524b3b088ecd201817ab37c67dd4ac71677fea8d6ffe5d5964c14f5e0f7fda95861f58fd6f4f1af013" },
                { "hi-IN", "4da80b2f8c490aa154b804cdf45f3e13f946daedda413e30f19013bfac39530404932f06ebbca1aeaab92f19e9948d5af2efc522f993e4fabd12bcb8bf8a474e" },
                { "hr", "c7217733fb3be2b41535a97f2e47cf0d2d188193662be97eb6432515954e0d4f68697d0e3f0f4eb99507b2e56ef0ba51de4a68bed5c0338d2b72b88c9658c6cd" },
                { "hsb", "f834a719a6dd18190a936d5e9ef22b4c70b724dab855356be64f86578ac29a7dda766a19569e444f3cee6790fc90d06674516efca0fb1801d71e691412e7dff2" },
                { "hu", "36c04bd5b8a8053c02c6cfc486a532950107bf92ac826442bbb26bebdd1a109412ef524de0694c9476d707d767495080ffbd1215b1a769b259c96fb62d63a3c0" },
                { "hy-AM", "cf03fa0aa8d3b11ee6602b6b25e10a1394965533de45ce39308b69d8d1e858a231c7abe3e0baf79e89d81717529307acb3420a103a62d3777cc69d855a5a80eb" },
                { "ia", "cf9c6be8d8257b49201e2da58eb046b0fc043c0c78a4062f673b29936b156b6eb81dc4840e35a311f8585716beeb87c5598c6440c1b326713662314c64fdb73f" },
                { "id", "2d1fea32c2c7a8c1e2a658a188273fb475e0368718cddad09726c37dc73d6a151a1d951528d7e3e430e2c3b7df2fb0a1a8072e549725eeba3fdb60d355ce00c3" },
                { "is", "8c4218e17c7049cb51df71dd70e758229a87842d83a1c8c7bb84fd79b7748d0de974cbd75dbcb1979d3de70f9b22e5dd602db5ef5aa018412ad602be9005c571" },
                { "it", "dce89b723b8a1a3bd83fa2a427001579d811a2aab88d27e271de5866e8b1bd4253c4e9555acf9de3be744ff5e2f171a6172f291a02d1a9c3b4dc47134c8684d7" },
                { "ja", "895b6f4d40dbaacfda23733df289ee460eb0602f118a7d2139f6af5fb092d6d244a2a1c6a4a83d33e206813da9c74eb7078b376e49d15315033248fa38d65f97" },
                { "ka", "2ade953cf8632989b6e0ab5d20551df6eb3d0e0e7bb5abc79b31b37b5e9e385307cfbeb9b248fb36e6d15e378b585446b67cab787b5dfb4969f150b5022f309d" },
                { "kab", "45c601e75c2a7ea8abc6ea1b62857bc5d319f72b8d04af05ee6b088d468fc55958fc6e315edd3bb5523d995405b2b9e142235fc64784106265a09c3bd4bc0e58" },
                { "kk", "2f2f714e86d3e8a60713b7ae4b40617c7a68576b1dd43e84d6a783b5f5daf1f5ebe3d3c4b4d5a910da59fbaa4db5cbdabe344f521ca51e62c13f23f411fc6b5d" },
                { "km", "be281dfac44b3975a60ed13d24d2eae32aabd5a1e656cd9094c556e835425b84a1678a22e16e513cab5c40fe8742045ea43ce0b00a35b22ce7c065466df11da8" },
                { "kn", "97c8c646c4da2961064d07ebbfdb161d24f8bea31e27e7cfa24f666f080db8e51441e8329e286b56f2f64a181eb82a4960dc7d3d281220e4a7ce8c0380fa0bd6" },
                { "ko", "a35c02b3ee66be7e850b0dd438d94baac584c2392f579e2a85b2cdb577dc21628106fb8e19ea5ba96ce5f095670280977ba76786587bda260a0f1dcfd7c1305f" },
                { "lij", "91885aef4f39eb4ceb9aac28c22d7dadee2eb41e4f4a603bf8dd7795a7f64c3ef250eea486e33112ee0fe170de69736787b07f790c336d0392000ed12b855281" },
                { "lt", "89602130f85fa8e04740c97d9f685b00ffcc606dff3a0cf908b60c3d004521f07c4e03d41ef474003f4005989bf54fbea1da9863edf3fd0638a6a6b68c6a42ac" },
                { "lv", "24e01cc812a811c62e3c5070b7e1242c042ac720964499edfd3ee98b8bfc571e21a04cb84ee224dd7e40459f6e1ba14dfe780ad3f773ea2e1aa84fc538e8c826" },
                { "mk", "b8ef5f87b3246b2041cb639b771f382dee89e14a20c8930d2f56c15d0cc02e88c92954c751ff02ee288c099526593d857044f8e87745ede5ea9879cbb06e2f8e" },
                { "mr", "035a8e7c406de939fa2ffba8ceea37c9b576b2330c432ac6348b441c7592a1d088e94d9af946ba36b5dc9ae4e7d643fdefd049145fa8d8bce3e573d5ea3b3e5e" },
                { "ms", "cc29cb01458f3e584065772ed37ebab42dc7fe692d94d2b100cca0af8031ba9ea52b2aadd6ca6b922014f902cb9ab68f738218b1d14d4af0625e1277fc126698" },
                { "my", "3ae9682d69794801ec30f760387ff92799364ae1f3d3ed0e98b50fd8cde883235d7cc8a88420a83888cfaafea5bdc3c7c17748502013b7cb3f14e1003442be14" },
                { "nb-NO", "dd76f27717a8bb04ed0e4af8c82a07a280ec4dd370288ec8839aa7bdeb781c6b41a945617949e3b2bbc773fbf11fa1d62aae728ea106c61b94352ec10b102262" },
                { "ne-NP", "5f72c054f3d780c00cca09f6c860fae856abae52f95c2134c8ebe996df9988d78cac542946d2b3f80f7d5fc4b3b722e118ec376b9c5ec66b036da7f61b55b073" },
                { "nl", "8a4e5db202a73d935df5530c26667b78ed47d156b33c2c64d4063049242dd02b76c722a80f356ae59d05a590553a57ccb636cfe261e6e71e0e96401a2ec89033" },
                { "nn-NO", "d54df4c3b3052fa1a3c2dd758d62b9d81fe98ec234e2dd77a6b60765f319f1065d67103f9d3ac8fc23980893d3beffbb6837e5f2d778ad6343fcd73626269fe3" },
                { "oc", "cd6fdd10aa9df2e6ce8d44605428621e57485a15045527d4fab22b85f0b69f8085ea54f41eca8a569bd3b4f3825ed2af9308441054a9559b2a8f4f24d13a66fe" },
                { "pa-IN", "e018721ba65be1a0a90ef1be18a2c93514e76fa3b776d45d707b4784a1f302d066e8a56bde06c052735208a0bab95a443dcb8ed99037e44f76a1c097fdbcb833" },
                { "pl", "c201d9e7f23fd21a03515692b81fd2be49cf50ab895add3f2d7c3284fba327d91c184ab73a7ec304b6845095b590fdf6b2de0776c8b1d7d1df4a47d90d26a4ca" },
                { "pt-BR", "ea5e656c68cbb642ee000ef8555443ad07188fa9f11ffd3c2703b34e96f250a1c36849a137acb344d7b42ac38e8a8c91f212d42d8c0484291fbc8664f5c757cc" },
                { "pt-PT", "e6f5377fcb57992af426a0f10836e509695d4487015b4dacd4216db43c597e6eb7ae4aba6c9cca20439ced70113799a68d2e5c8123f513b90e8509e76375a005" },
                { "rm", "65b07b7dcf26d8f70b7e14a19039ffd8dfa8e1d0599a7dbae3dc4ad217a93d89d01a9b7956d0afde1eae79abd17e839bf9eb40678beb2fe13407c4461e7b8e4a" },
                { "ro", "06375acbaa40e86c3fc44ba4acf4d9e02b2a0f8118d69f8e3045c56fba340c342b72f8c3590ad96f58891b94ea322a0ea7cf5d1033b3f6c777adc0b77cca7e08" },
                { "ru", "297cc55b2a5ae3c476da5ee2469ffb0175175767f8ed65589dbe4e5a3755719d72e9c6a9335a182fa2c3814db37b91a07bcb8edc7aca042de2dc178620e3067c" },
                { "sat", "5233ad3a03f677c6da1296b7fb33859e993f0a80a661f4269f0632b58d0723288ed69cce7403f00af4a2aa601538a92b56c4562aac20995f0ebc41df735236cf" },
                { "sc", "746d00a3cd38f9afbc4bb293a99952a765d0334bc0774530276a1fa25e5d590c3001ea1a822d610e753863c5c7fd86076f2a544b457408b2006ba5d362674aa2" },
                { "sco", "45074f22539c65ae2fd77b1a21310cd1556f2d233a732d50a9f465b2ff28db8c4a35a7b9a7f8e65be9b553933c2abfd70f2ce6f492b716265f2a68bebc24cb06" },
                { "si", "cf82cc423cbbc90a6be3d116658484ea25ab69123d38e49ea982bfac2863b098dd6c3e7d89203656df75f5c7aaf09be15de161525cb3ab51bf79c3f7ded307f6" },
                { "sk", "2efc48dce27102d889572778910f2c9399c529f495f75875fe9ee0ed0210a8ec33b34d91d114f97024ec6e91d8e3422ca11172a2cc9882abe3b46f163c437f7b" },
                { "skr", "73ced183a986c878ccc32b3916478e7278164f9c89b3a8536bdbecabdd46fa054ed292f44bc0c89c07ca187d17872bf1b2fbd2297bd60dc55f19be7a7ac8b52b" },
                { "sl", "301d22a942c45418f10f4fd0fcb9ba685c65a686c1f3dfeb9629049a0628969865461672dc3b20ebaa98fbba5f7ce1206d99cb190aeba2acc4f289495d8b0efc" },
                { "son", "56157a070db5d03e955e7c6108bd38349246b9709c621d3db05be9dcdc4b97b662276f29534ddce740fa2d51b0acbd461e232f173e0521fdd5ca64f32344796e" },
                { "sq", "fb7bdc17ad47aa9a3b7fb1d3564199f9fbc6dd90f440b257e87967f694e3c971601655325c226016cc951265e38b1f07d0c38b312875404c4b109c283fd82cf4" },
                { "sr", "206a5a5b54afa350a105ba497fd71a37adb0c176997a0e99d32c3951723b1f8a444756a670bc3c31bc15409827861ecebeb65ab0a6bbb6788616e7ae4b26e0a6" },
                { "sv-SE", "1d69436bad78bc4f4a9f84f6a69d3403eb2a828a8b8449e5f38a19bc0442e5e0a3fce82735558c6a102c1de5a8025efc07f70853c23d34a3393cac01623bcc4c" },
                { "szl", "3dd9660ab3f66ea2c787de0712647dfeb4391a1c800f298c97d3912c83a71d6decefef7e59d9700cf8a51ab6568e694e5a77d9fa09167958d71f500d6cd5bb7d" },
                { "ta", "9c266207dd15452b9be95983a2d8380eea5098ec10b2f0f7eeaed75da0b8c92cd52963b941d30d5c6240c64095f852a2e11955469c99d21c8f58c40c89923fd1" },
                { "te", "1e4c311888d862c0aa2942b60e176cd1ef167ad00a65d5565359fe92b93bce5c469870a3b9daf48946118105a2bc77fdacb612f137edb5c8e97c62b59c4a0fd6" },
                { "tg", "b78db3b778b9b3e45dc608422f25a2691dccb4672a566939e91288adf7dac53979880a5431a00d6e695d5617d5ca9c006c8aedac0b526f712963ad939c66fe3f" },
                { "th", "864f39b4860e7d8eb7764fa3fd56d10fefb10b49afff929711983c83d958b0a271108e583672fd4f598533a977f969871c9e67860d06f8608e60b1ae6d93ed74" },
                { "tl", "18f649c5ac7a109e3b3e152dbd07baa6c52e1e0908e97f9c083df238365e982ec9ff631968dbb82611c8e78f3b4f278d34b7bef09072798a50aaa377b0086df1" },
                { "tr", "eecedc95a3e98c7f35592cbe054618c0a8fdfcf1156073b54c48a62a80716e8f698dc934ac0d884000e211d5ba26d91f57785a5d9544448c719975615b3c36fb" },
                { "trs", "4195979b101467d8f320f08377cb629d55fb099b8b7d95f57b5e2e560ec5d9f92bf7d9a8a7cd33ed5377df88132d70a6e939dc7a5a5dfa9e500ac9223a4a6a6a" },
                { "uk", "ff83d84046ce42e56a56cd2f535514f104d9601326675abdaa49de45521f13895cfb21c95d698383217715e68d8de4019eca702a75369b225e67e8220baa707e" },
                { "ur", "17ccc7a212314c65386fb90c30eccba4add9387b2d44132984d59c79ed6a1c8dcdecada34ca0c2be74b182f8575af5f6a846ee3a8358df47c03054666b912118" },
                { "uz", "8936a5b363aba7a0eca2a8e89d295482fdb4a2f3758d9158c50ee2eee01f2f17e6b564056b361403b3cc9965af2ace5204d2a5e029f7923c15d058585e638943" },
                { "vi", "b2767bd70c5c804176ca4031394f32bc44edf792a4ca090ac6b920a32c6ae905cf50e7e75ff93a58e4c20d4c2995f4955baa56a9b6d3d79a2d509c8b0ae7321e" },
                { "xh", "c9ff9b5984faa3de6242ce2cc12a4ede4d4bef48817a3e3fe8d0827870dec0f75e33142a0b701699edc5d6f0b918249dd0f953f9a524152fbc417af3e78b6ca8" },
                { "zh-CN", "78e9448857c22ac491e0780d499a3a505b1f06929d04c3f5bb228d2c199c5445b92392e495fab034da7d4ad49a815ccc9c3667ecc2a8b0d8a3c2d7432b639d02" },
                { "zh-TW", "a1ef2ca39a9aefc9652672b1809561220494ffc08c097966c49a58a8a7db09cc945d8396424721a790ab463c7d42384526d7b200e850e495b5d027d65db2f5c8" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dd8c3361a6706c6cb18187608c3ffb5f1743dad701c27cf4366b49318826aaacd2216fe3c335e4322391d973caa5a3177bfe8c4e06d4b3c4d18f5c22c328d14f" },
                { "af", "28a6a92a9f71e2cf1583b376194d089fa6af7544a5e162f64e4f19ec8b7405a57e103e21b677f607a3ef14369c957620efd5c396c7111761e82fc900b04b00e3" },
                { "an", "f93dc7de58de904756541850a651492be62bf6e1941ff0cbd4a13ca462e2075c42ca6787b491adac61c630f03882717320ea1042ace33d7a07decab21b4fb3be" },
                { "ar", "c6ce680247d1d1bb8c94dc66e9dd7bb71aeac7f161f2c9222a89522221f29ea5ed5c10ae516eeabd9d99380da65340644746e68a6f7beffbac4d0f8f15149926" },
                { "ast", "e54e15fd1b10a3149357863e76ee222621fb1721875d79aca6e2e865d5e73f479bcf90a393e8a8ac0586e6985e943a53f08e6e6b6d63343027c3b1a51ef0925b" },
                { "az", "2f9b61003927d694179d53005db9f88c8a674078f416408b111ccf03156763eeb6c58d19f1d4aad8a384398cc3ef4359562d8796676f6af600489d4449e35f77" },
                { "be", "cb43d578a7572ed04881256d139718fba524fdabfc507dc2b7390a26af6fffa1ed0350a7c28007d3a035e730121f807527c9ebff5ba7b8434100559b43dec947" },
                { "bg", "d6aa4cabd333940e4efbf17788671f7497f14a3b433d63e438a010bb0223406a311e907ce05e522bb28d9d7c42184d01d84fbc722b7c5af92d936345cdcab7b7" },
                { "bn", "a9a9778c3640f76f10a4d8b82ad870bad97f2cc65973ce25abf6132e9a1e8522cf5e39aa851fda3f8e993f6b2e26edff7dfe213495b5643615559e20eb7d12d6" },
                { "br", "333eac70392611ee79d5e3e803261f9a0f3ed8c25e5bc3042b2649793e024f7dbb7d1bc14f3a5dd4b0ef1cc231b3fea4bac21e63bbd8344dc76f8d56b35f3992" },
                { "bs", "c2052eebbc033fd3a4680210b4a15cb72ba1eb36d0705d20c3dbb38386255158d435a24819cd8061b1eeed5dfcc1c32dc1c82ae068fd4bc6c3cd04103e533e80" },
                { "ca", "870e2898629d9bd6d3aa926033941fad870bc448e7dba7d96c51b8498ef6c9fbf7ebfca8696b6489617d005ecde4888f4ae7aa9e74660085c5150e44ca654c91" },
                { "cak", "6ec9b6dd0ab0a4ef735cb5ad1f706e5f5160b2ef8bafa538c4f6996e690fcac0f7a7436e4ce7d6f5a81932471c3cdee9a83fcae653b5726e0d0fc4b398822c06" },
                { "cs", "037a79d237f51fff8b6990a063bb3e0ec453467aea295f6ef5351c4a1abce34927858c309f507449802673f64062765b0a7b03d661d91440086558031555440b" },
                { "cy", "03378acd22029c2f41046acacabacdfd4b1b443551e5c94d35e3f06166866fad3804714663593d3e9e65a4d216542939f07b390d7b5d7fbf06e8922562638d44" },
                { "da", "1184e78399ffcec8ee874c018a79ed537852ccaa9d94fa658655015bc97d84ccd28b4a1e40f3b1fc64c79d482ba1551ea76ab75837cab749a1ba1a5a898aa1b3" },
                { "de", "f24a8c934035070421e38678ff34ba44e5ec33be2fcfb14f08732b458e2de769e33458ddb7dbbd10a99bc5c3a396b78bd758a35c5f0a1c4057eb987e4e99602d" },
                { "dsb", "d9771e732456eb0ecf837cd854f4637da42be0973a1af0f1f0182f4d0be9c899822d04c3e13ebd4367d8b4baf5331e560d1f6b5c813abd6a76af6fd503ff32a9" },
                { "el", "5f380fdb388f10b8b74ba579b5fc0e6927068a1fa1f0b9a55c6571a01ab69e0f1dbe5eed392e96d20ea5b3394909ab92a51ee2349196f4689d5656cb50f5550f" },
                { "en-CA", "c4e65b2a495212963e59b41b89207ca6130989782851ffd24b768edefe391bc053f29db1de7a229971840a28400650bee36fb3e8679563471da354c31d3f601c" },
                { "en-GB", "c93a7df471ac036ba9e89631fcf6a82a410c981ee81bc81b2e80b06719b15945365c1bd34557f36f77f27d82ab4fd95d80d78b31f97928362184eca50aa86167" },
                { "en-US", "b001b6b9d1d062cab370713b18748fa4c46cd44267af8c39e8871bc9df8a0533f7234ac43b989f504833c1b3655d15b2602451f66e6041eac140036ff9207878" },
                { "eo", "7a519c49e8f40814b85044b07856a4933ef4faa0712572dc8f28d7f5e35c6c5ee948a3ee323fecce4ead64111af4531c361a474f281f7771cd2e171dfe1b7edb" },
                { "es-AR", "66ff60078c675e0ee513cad00a449211ee06b675182d745bb45533230f988fe7feeb6add8e0cc523376024d23a9a21b1decbb42c5e2a6d4ad639a359b6b439aa" },
                { "es-CL", "ce4251174097d65d1b081688e0d488cb2a7b19cb89a7f1342bbf84def51b7cb3537c4c9931e3bd6bceed1e36b1414df72ee21ce1e5e0d27b8952afb319e7a7d3" },
                { "es-ES", "9f17a1e4efa9f88ec92af2f5089a6110f77847d4b8c9ca51a79b7709382a4a439baddbebaa1998b1e3e6f059adffb4ef980e055eff6a96b93bb2a9f3cb0b245d" },
                { "es-MX", "d9f0c2a9f320317b5118d9ab8f7e828435376440678ea4af81f67a89c6474073ade85e012c36eeb57ca478d94fa36d7b100a444351cbd546328b3525db74c9b2" },
                { "et", "fa2cf28e0eed98a2c54577dbf02bbe7f0af100c5bd1ad3476119d5f071db8b454b22b3359e60c8626a35ab829c7deab42f8b940ffdf0b8785fe77631e67f98f0" },
                { "eu", "cd7946c21467f48f903dd3fa31a1e6e13ef1ed02efac87022e616b0828223bccbb4d3cd92b963c57bd687eb4bb261965caf66ef8c5b31e0781d2c1f52d31107d" },
                { "fa", "20865b76bc16595d981d0eee16a5733ac9bf26498d1589a5e0a0e4cc956792b5a2f05c2f695a6cf20228769277c2c112fa8a0e7da68b4580dc571aaae9b902fa" },
                { "ff", "ae29c3d60b386d7a7065f1a5b7328efe4a28e043712f7616107867044d7f2fb0910ceaa30c80153f02918d72e4cac6337a3728badeca399b4e2ed2049c37d3b2" },
                { "fi", "f230460db584c5af00c5f5c635ec4282510ac9feeadeca4658299ab7de997a3509be163c7eb41b475c6dd021173a8a8327a0f3ced63f72a213dd5f9b51a3295d" },
                { "fr", "aef622ce8166626df1e9a83aeb990909da074d3311b348d56843796794d1e0447d2ca2c3736eeb015941c7f02014148b863e5274b22e76994c4a1446f8de17ca" },
                { "fur", "126b6fb7e73bd63398f157d97c4bba27be87baae87614cdddd07cdbde0136edca4fc3bc6323b3dc49c1f28702500f063c71dcf192cbb4f2e5516e1bedb22c633" },
                { "fy-NL", "c636313141e4966564e8ee36eeab82865fdc2d18d558e2adb7adb3ce4b8bd8b8c911f2c3e0bb3287c9da12ea00db195da963dea62294eca04125803ff99b9ab6" },
                { "ga-IE", "f8edd1190277c179490b507ab3ee98e31245ee79d7f4ce11f9d131159096e793700315a576edbc39dfcd65f260de699920652b41cbd9ff25975ab4c1f7b4b351" },
                { "gd", "a889f99c9636b6890a6c66ca4cd38261784b19a0b07dfa79e8f347bf22dcc0513c5b6c49f94fc5fe76d5731b83dadd0bf3aca32b4aad7f4062e0b29b9058a2c7" },
                { "gl", "5116bf8dcfed1a32172d3544a80e45ca728bb4616fcba334779c00938b3bd99fc9b42e25f4a8c28c1ce8bc76d5adf398e2c8115cde2c2e103bf07ffd34bba314" },
                { "gn", "aa73b96ba1d3a8428c9a02355752601a596d54710e20d06d9e4b09e1a43c668539f0c8716c05b8b3d3a7b841912edcb1622f0a6e71f8976f9c77a9d09dca95ab" },
                { "gu-IN", "83c2ee0a40b90e49e85dd889a0673701632a4d31fe100c310553091c2baf8dee3cb07adcebccdd6de5f32dfa03773a74069ac62f8d75514430bc353cc8514f84" },
                { "he", "e2c62995ea50a6ef60ed7d01c9b8bcb783bca4cd843a0e34d88f86af22845da7a9b85745421dc41aa6398f0454f89063c1ced669505e5acb07517d5cc0295fbb" },
                { "hi-IN", "7f9e939b8fb4002550b3f51c6a99c804dbcc18235f31a7e7182ac2199a84750a36411e2c3d547c4595b9bfbb466f5aa5c4ca09f0fa1a953b930aac97f23ab4fa" },
                { "hr", "2ef13816cb3deba8f0800e0b84df7e4b5e5535e992dd10e8487350488e37dd0e5eeda087f2989a296ca878f87a78931589d3c1c762e9a07c0cdc92ec3904eaab" },
                { "hsb", "8c0bfb49403ef11b38b951dec0182aac1e02595fb1565c7f7dfe34459855744bdfed291d8577742707cf6be92ad2f1f5220ec98be47a7a8d06d95bf558c8cc40" },
                { "hu", "37a165c8ee40f846ad783b19a6529f18452a3ce2e6200bc2d0b5d1295ea24676e745b1f9bf5431436682ce80f41b583e7e76e16aa50e791525e969872fe72715" },
                { "hy-AM", "c40fcf702c2d347164a6989b42baa6c9785ba1dc625420284c3e9442e4b8c3c4159d9bccb842ef86e6ec8e2bb6fc7d7d406d4540deb7f8bf38508e6726cc13a3" },
                { "ia", "66c92f48499e2cc761f8aaa941019cbe243d29a1b864e8e6e602c7082324c5e3547b874a36698a8b99ec49b6d61197e325fc147956d623878dd5461f4b519e3b" },
                { "id", "8a7b4e47d46d9f0b5dae002a2734d23061aa6d8bd8321c296f1e4e4e354a141024b08900a295d926f3b4c1babf48f3dac7c17cc22e11e7d84068b4bcd5807c1c" },
                { "is", "696d2628009d337f8aff763f0c890a9d1b8783ed5a03ecfc284d272e1fc41f16252afc5f813fa88ca527c0772d2d63d8c4512754e8cb03b0f0ec73939d98e17c" },
                { "it", "7010be35e1e984cfe3bac174e308b8468babcc8509655248d8329218e0c9dd2667b32680edfbeca2010661f311f02b47fd36a13b1b48a0ea395caaef9deae145" },
                { "ja", "cdbbae11ae513ff221db6874880501c2e67a63683856d5fe49ac6d7192b4873447d7219a06b1d969ed365824d54ff2e362adb2cc95ab21603c0525efb5e1f767" },
                { "ka", "6aa9985ad1651d33b2ec5301b0e5c275c183ef325aa328eb72c595f5934ce2de7b5e2589a894aa7d18124fc314647e4b02af6507597e205f7e1e69e3a9c60058" },
                { "kab", "238be0c53638202fc28253ab0cf86de973b045df56a987c03ae68b9f29a475d9d202d3d47d7c4bcfe4ca0be9ec352967a9038bd822aa6026c3c51e43abbe2ea3" },
                { "kk", "0dc2eba957d3802106af15a6d97825f6876f572abfe72e0b9c6858a920e57bc8b17919544528bf882d66a17791a4189ca6cf535a371729b248b0c1ee6f4664af" },
                { "km", "54e6e316d05d0265753afd5c19e2f9aa4ffaea77ccd3fc1c799df2f9c016809cf7fb482b0fdbbfcf8d25510469e41482263b9c93325b2860d8b8b9e542262065" },
                { "kn", "4e05d5cdc8f4bb941ffb35fa68b48c356f5a93082beb1b82d1943db5da3a6005fef0c062268f8cab8ca9e628ccfff41c6e2033da241ec2ee2f081dd0d09cef72" },
                { "ko", "a254aebcdd04c955764b35cbedf10e3a102c4ed3b181e7870038a67273f640e44ecf2363121d4ac1db48c3696c96bc5dd59342f9f1f13288d5cb2d640b699192" },
                { "lij", "ab921adc37ca54a5d36f4828b55514f3517a7af04220c2d4dc7df33b95d83b5dadfd215720943da5e7c80d6d16ce2644ec730a0848f273d50be01020c6ea4789" },
                { "lt", "dce80b5f70cbcccba798ebab72e43f22627052f49697b25b2227be10027eb3eaa25110a6c7d4bc814a0762767c4a2d23748e4f070fde1dd096caafc3b4f0e59c" },
                { "lv", "7dad77cb476a8ebab4d6660e20ab4f5217c0c5e6aff9ec4f38a1bafa2569824ba389efe140a555f621d1bc86cefd8ef1264f741953da9bd93caae86f6bdb8a0a" },
                { "mk", "1e55fbe19f9119cfd7cd20d3884d9b18377c0c0872caecdcaab30127e3ddaf1c9bd8ab9dbb7cafbd7a4171a972ec65bf736456628f089ab633a0e3871209f6d2" },
                { "mr", "6e7111fbd65e71bd027f78ff0c5d95b6a5b15c32b9c90fd95538496c1c1f7dbe1add7b99be29fa4e5fdadbd7abc0f5e29a650698d86b4ec8b6bc786a15d4b6f7" },
                { "ms", "ee387779f30e6bfeed72ce1cbce6de768313b1dc16709fcf3cc902335220b489fc15a598e8d6c6ae285c02d8e029a6b33ed0a1fcd27d8886fff1e9e2a9abb0a0" },
                { "my", "bbc474ae75a5a087bf08b2d618aad142ad792b24d9f67f536a6f09ce166c9048d4f433ba449ce232ab0b97f053ee2f19b3fc96e7536a0906bcb9c15aedf7189b" },
                { "nb-NO", "759c23ed70271b3da5ab5ff824ae18a56b2df09730be24abc71fd4f66023b00edf1c399b864beaafc77acef02a219fffbb175c77ae77553ab4ba17d65ba73da9" },
                { "ne-NP", "222997de6db440bdc7fb9a88d535a62a7fa818368623eac5c0b2aa1c308d430c310bc47efca9e0cf0a9a4954b0f1bb8984148b83a1d24b29993f8e09fee2b3d0" },
                { "nl", "12396f3c589c9d522d50b128a3913351418f59e2d19ae98af7c4b9e38cf0fa6bb4fa03eeac663bb041db40b00af3bbbd62db59d673e6252465076deb53dc8b9f" },
                { "nn-NO", "d5629c880a152cc05804c8bf30f8844073afc4616e5021e35887482bbb27cb31c50bdbdc1c7792edd7b48cf27ffe4c622b80edded0215cbbfae935d00cbbfd89" },
                { "oc", "b79f636e3e4ade0b43f7bf5767545d329ccbd7b3825fa7770e927cced8bb4b0e0f4fe09281916afbb937d6635fed4bdd5c00482701967229e437751118652cbd" },
                { "pa-IN", "6d759a53e0f77c27705e7fedefd38ec8604a72fecc77876de8015e7ec5fa581ed0a03539ce15c7020e6a103beb3314b6907a85b9ec57d5a384e92832e14d0255" },
                { "pl", "ff32dcff2645be9fa96ce29fff61d70df0b35336f2f0c1cf5b81b83959d82ba0e6c331d04e31933e2d526d61587397270e24ad8f65c8a9f949b4ee4bb7d9f475" },
                { "pt-BR", "fd2cdfe4a7a158ba4fc7fc50f0b2a585147c889227fac2645940764eee2f66ed1b1c5aeca8a7351dacfca371bb72f626ca60b6265385f188e84c930921ad9be4" },
                { "pt-PT", "f6220a6cb94ce3dfe42f07f0839ae9af2ab6cd9b1c502b7575054090c6b875df891eb382ca282c9699ff8ff154cc3329aebabd31ca62fba24298e7a05f74c96a" },
                { "rm", "f718becc1d38c9c15956c9d935c074a7a2a85e1a5f8b6c196bc08c197362e2d653402efdfecccb3510ff5a394cfd696274197e92cc7531859e05d6e205b8a310" },
                { "ro", "4451cdadd9f0a15a3276e204a4413ce0b35c1c65c06579f2475a01eded1b609d52ad4787355e2a76ee8033898decc093288fa700a7d6d1cb585b6b6fbd09358a" },
                { "ru", "a1d4f7be2f87bf01bd4acbb2a5f098f00b49ea647a9e1e39acc00127531d9df54d81ff89a86b5df2805e0525a8048df77f317d87a8c3076f1bc9a95cc74ac3f6" },
                { "sat", "b20fc5a8a61161379dcb067ae1c175b1a1e1e927c7e9e4c7bcfd67ae8eebb506fd9ca82ad813ba008636eb82490af206245b3ef53bcad05ecbda6b4c5a15b7c8" },
                { "sc", "212b766b347c5395b940c6aefe84078680990ec5ef5d526709effc33415d38e43597056a97478efa04a3f9dc3f0a0febe61db374bbf535ce37b09de85baaadae" },
                { "sco", "173584114b40916d7f9a61916e8c745cc65736e7e858778a57cde9f231ec3e2286bf1de0d2ac6ab79013f637781c62e5d5b9dd2243c5a3966c8473f28ebc36f5" },
                { "si", "dcd9844b9cc9e618399fee88e55eaf851756681becfc208d8b85bd5d08f7f539ebc3a10972e684189d485c6a281884743f75747178092c68b17042a25c69d178" },
                { "sk", "741553b9fa3b6ffa09cf2c0a7df0941c34b48958a2cebaad79723bea2af81cc18742e6e162e3dbb0c25017eb9a43fd035bb4c9ebb21b36915ecdeb21a26a417e" },
                { "skr", "1751ced61ed3ade1bcccbcccc810003e3b96ea1b2c9dc4d03412307fae75d31196d379eb78e43fb8b7c55320f05fa0b10591c35399e22459c9f68b189eedf0f9" },
                { "sl", "e08751439ccf645c156ebd77d2ab291a0a48c7764db1b5d703ae0e66068c9a35ac829568b9c1bc49cc62b7b85aad19bf22043953c45933c1be1f8968833d4fd4" },
                { "son", "7d2449147cbe5b14ce8ad9c97c517b66474685d0fabeab1962a27f381206e65830238a374e59f6ae1e978d6433d1a461f6901d92b8d2223f535302f24f422be7" },
                { "sq", "358c7354fbf08c5976cce50a742494f016620021bbf2501e0a71e48fec23dcb88a25910fe9780ae8b9ff5ecc2332f0cb998b7ff7cd6795e9d9e7d9b4c3f0e486" },
                { "sr", "fa2903f6e18cc06964299548d8ba611ad426517670dfed66b9aa3eafd3ef8bde29e1e389d63dfed36d81d5b23b40a1837e1b156ca5b1badb14a18136f9f9f07e" },
                { "sv-SE", "09a32fcfd9474469c5f85d664603e897b7bc37fa0826bd92f9215e747d5a1fc3a43cc88d8ee67ad324d600ca925ca461193f3eac679489fac78a038ad2be701f" },
                { "szl", "708f74f7956f1c6c31a1b6d12aa93740f3aab69a23ad80df6014245f83a2e15c6e1c70efea2af9787c13c802e2ec27799e0045901c3a341e64eb9c421fdcdbcf" },
                { "ta", "be12f30ed03ba48b05531542848d98166ea0c9ceb7987a79af244597ac8876be6cf845ff8ef8678687866c66280a0cdff480935da0cdbcbbc9ca790cd3f3a916" },
                { "te", "5dc0347856f3e23378065167924793d43ed20f0a6f905493f5942ea25634ccdb0e9cc449942ca77a48921c080e587ff103c30984dc6f2863dd1479861a3dabbc" },
                { "tg", "2107c277b00b57c0fbf5bbf79b3ada6f1ad2a31624b42c3dfe3c850b94ac82237e821958d005d1e5d9920b2d27901f064dc08bcb9ab869eeb304f2611e83ec32" },
                { "th", "bae339ad49ec63cebc99932bfb13a624a61fa0f9d2832257ef29a10bd97e3d55342df5318248f431252de94c21ce9f80230d5e4f4ce70d181f97e7c2886ea013" },
                { "tl", "cb0e1dff006536aacd3f49dc354f1221e275b4b3e6ee29eba4d2503238ed8df7ef4f65ee6158d2cac4ac45e687999f33db6df98c87506af5232c77d836c03287" },
                { "tr", "d9d627168a38e09a46457e51af8ea418d36a9436fde74fbfb6cadd54081ef7cd40d86b94499edf5cd4b74b25ccaa6280b214898bdeb4ca8e1068fe6f0930cbdf" },
                { "trs", "687c81e48e3fec34470b50d340ea1bbdb9d30804a59508a73ef2259bb61fedbada94485214604b193f169cb990eb60bb107be3f8d195d38f214052d05139fd2b" },
                { "uk", "ccdffe64f91e891864a05d84c130d7213bd217c03f3f2527a308917614c59c55fa83797ab826b7cdf9530a6adc7a21cad819de1ddaf85cb28ed7552b522ef0de" },
                { "ur", "e7e9b543fe7f84c5d21b1363d71ce50691ebb671f2cd86489b86c752f0c7ec1e990eee5e9e2c6661094468405a138837c6027b8391116d04574f1f8dde695cad" },
                { "uz", "a062c4d8db8ca7a07fc1e328c0861908fdc0b105670084dc29924fce9e7babd845fd9ad5c1c716e2bb288f6ff37226b55f8a75d04bbb06ff4605bd9352febfb6" },
                { "vi", "d1b5ff40200157e60605c9658c3398db33a9f326f4e7a5794579e408054d7b070c974a3bf5ea3f764863cdd65db32032c823fb3fc7aefc320bfb7b6d108c1e35" },
                { "xh", "f430625a58603460bf13554e25bdcf814239e08956ed2b6e6bf29a02826510c7f34dd74ada2e804661fbc11325508f6e47780b41ff8e41e0f781321e4abb6255" },
                { "zh-CN", "6bff88547e566e63ca5f16dab4d55fc7e67bf35a95dd45607cf0ed5c22d4bc0ca1bd7747191c2d36bfa51ceb8994543ca33a9f10a64a1aed6bbea954258c48bd" },
                { "zh-TW", "4e7e80da7a97a81390ea1b4f0fa9c0e138a245166886046d7e3a7ba55142318852a4194c29d5285bc8746eadd0d8b412811d205904fcf67b2aa234ce90c5b11d" }
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
