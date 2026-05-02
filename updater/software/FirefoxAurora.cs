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
        private const string currentVersion = "151.0b5";


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
            // https://ftp.mozilla.org/pub/devedition/releases/151.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "85652a02d4ff90c047fd2c3db0e8d581d6fc758d9e2ddc4b6d818d6cd1c5f5c79bfb9f0eb7897f3d4a4cfda2fe8da5878ba1104ffccedfd9134f82b351c834f7" },
                { "af", "f7757403a6c66e022ace15a9e2879d60ac1d34d89d8f9b061d1c071e90ae5ef8b7cb7dc2dcf7ccb13e81acac867a00718520edc7f9a4696264953dfc010126d2" },
                { "an", "f93f2995ce6d1a82fddc01297cf209735980abe1a29a9743c0b16be4e934f9a891aa28cdbcb52ac3040a50f0ba4ab477313715ebbdf28d8fb8f8431f1eaa2229" },
                { "ar", "01e6670d9c80a41a3b4990c8109026028fe837fcb38cfb1c810bb3d96bf9332aeb359d3b6ccc6cef3046e313b592b17c5d5e0cc9bdc3cddc9ebabe68da2f6545" },
                { "ast", "1ac991124bbe71750f2962c12eab48475bd585c2ec6abb6c3b53295b9b70bcc7bae42f5677c47da56898a4a02fcb1c6f26f25af099e066a9aa6fb6d5ae67a1fb" },
                { "az", "77cd5027e7d15a6c3831c6eecbfc4fd72c566f302d842a5e217dbf6f06d92fc89d97d0a82d0c9f819647936ead0edbb58fb06e9b84421945c6621293e1322815" },
                { "be", "a13c05ccf91079db62c0427b32bcb56a3c86db79682aa90f083efa85f76e72bfda638bb4ae90cafaade282df92e8495eae97e8b9f14568c7566b5edfda75e01c" },
                { "bg", "91f3b191b247c5c07e0cd0cd15196a5f6f1d915e1408fd5116a9d699a37ee6f7829e2d56b19ca236668875b04b15da73c48e9aa9c98a952d991ef042f781a29a" },
                { "bn", "13d10332782484b4a5009b3888c214b376febb2bb4f0a756f4a734a65706aa187a7a1cad45cc2cb762334652f15297f5a55755fb511e95ad1910afd4ca479dc3" },
                { "br", "bea1d12350d6220514e0650dc3ef9177addd9f3c9e1062ec6d9ac2f0511a2e538b4f414d2aab7926c211016cdd3812a82430913ed4589bfbc0186a599e151f73" },
                { "bs", "a787f2df1975475cfef5dc9a9c3d87169ce83db6adf524c3e696db80e00994105b37c7ec7dcea02af6e0a985a5c742a1a772bcfb4358d1cf5671e84fa7534842" },
                { "ca", "9ede992d56f70eaf5c209aee7f12f5a55d62ed33621ea9dfd699ebfe27f83dde64be0056ded1b0595127130e507c6ed2386db3db0de1241212010fb70610f7b9" },
                { "cak", "ec5a987d5bdcb52ceda13e6c4c57eb11e8aa4162a64f572edd6e845852f77b11a7640738dbdd3f4aab3eb4d0d1b9acd43083c2d4523ffe38f456fa921c40a9a3" },
                { "cs", "190bd4e557f589e5407fb922d900e03cf86fff3e9643e1398025b2bc549452e52d3981021d3ffc22c5838261d9632d38c6cf9b045d61ac9950c24668487b3554" },
                { "cy", "cd321d7ebe5ca44c17c37f1094c44e24032824d878c89dada750da7882e4e56f9ce47a3fc21d0411bcda773e6df5c990579c4cf7ee99fd3366174dda58996367" },
                { "da", "d7e234ed88dfbee61042dc0a3cc3d82295ed0336f79cf99478a940793addc78ce4577ab1a94f2126bbbeb2e18414e835ad8bd34c6e4fe1d29f5dfc3f9d8d7ab3" },
                { "de", "98107a4b42a454744f3045eb9eb4a997335fc8dcf6374e395499fd685abd3ae198f4f82662b1c1c9fdd2ac033c4150e417aa091a04edfee001389dc868b07c69" },
                { "dsb", "49d7957d5e8e673d04af45c34d159e8774904d3bc60446e7ab5b71031a4c9b7cc1384d8303a42916fb30364dbe4dcc0901a45be426c15e2500ffd197e7bcd162" },
                { "el", "1cd6c78b728c0bec8b4ed92839aab4d5d55ee927dde39d4cbbea21d3cbd178a707920fe31a3da411a77364a79faabcf3ef8548c0850a577eabe4e3b59236601f" },
                { "en-CA", "87b6cb8eb8855526487a54d4a033328b6665b89d9f2d9253a23e9d70b5024d3c8b966518d5c386ee5472fa75ef4b1e2753fdf86995d3a1e0afc806fe579cbfde" },
                { "en-GB", "0051b6363f015534727febe9f0787f30d2e265479bf8814916227d3ecb7ed12f3590dec2608a5a80ccf7b7a53bc0dc1dcfa0c2c1cd21a81116d80d4928e79cd1" },
                { "en-US", "68b00b548e32f29176cec703d52e4cead950ba7fc1d7394a4b53083c69a4b3b6294c80195625d485b7b38ff24dbca66adc635f8a976c2b014b99e7bee9b3b989" },
                { "eo", "e73fda8c655dd21b2e0c42174866005a5e5b7f65c661acc6b8d516f49d5a5b327463ad051ea3f8fb0846d22331e027c5d8b9d725c99bc44af37bd5bf80519754" },
                { "es-AR", "4d359f3cd18ed9194d68e8dccb83cf97e9a63abbec291592c9e071b7e22237fc8b5907942ddaab9becb1d7df0d0ae43fa47d8b05b89a9a42b7b9c055be6a5708" },
                { "es-CL", "676c4df877e72e425a19df4968eb9f76d8e5790b3cb275d304de91b7fbfed5f932ca7016b59473dc692cb6baed547b9efc6e16638421b2a0192a6b37236ae5a6" },
                { "es-ES", "cf8bcfa51e05c142688c7969d798c8dee82d5b7696f0152b30b2ab604729d2ce09ccb96756459de9e07c6d0f1afb5ecedbc089ddc2963c3cb1856363a045d6b3" },
                { "es-MX", "84f6ddbedbf8a18fc1636dffb4c8ff4d86259c76971fcb4ee2909014ea6feb9bcc6ed3160b77d6c758ffa386529f4841900e279de704f371dcd9bdc9546b0203" },
                { "et", "7e211bddd1e9e8a31ad69e3c3331c107fd4569a5238b4791f2e0a52504dd3e01974908f16ee138075e34dd447abc848268223b735a44cfdaf13de1be4e9c7b21" },
                { "eu", "0664288428f11dddfef4fc3a3d407408555f86ba8569b078a0465c806628c651e2420eb69769bdac3d8a425b20e2aff97a982da02bd26aac9c7cdffa6f203e6e" },
                { "fa", "2cffe2c089c4848a4d00e9ef6ccaa1651a244b507b08213163f2ff5ec67138aaaa56b64db59853f8541bd28f3f7360f0bbc3520ad971e7abbd83db5a03630178" },
                { "ff", "3bb01112cac42881d0a62c8d395b9724936d5922c95a69783732d0d821c6a8696d4fc7160fe450dc8bbea2b4b23aa07d150d89799b46330ffed06294d6d5a11e" },
                { "fi", "966f9f85586082e6f3ad5f14732a1876b369064f879c2d2b205284b5f06824029801a84b6ad947817d2e6c86371bbb8bbfe5782c2ed8f716ea2fc7415425f4ad" },
                { "fr", "ebf0dc2d47b3e8a38eabc2a845d6c238bcc81753b8fb7faddb6f88eabb494e78c8b8764eb871d4de80a2eef4ae9fc6437e9729d1b142878643827d94e0de2fa5" },
                { "fur", "61f0f28a929a9bcd92f02a52a53da2cb694a281166d8e6034cbfbc0d7883857ec9cc926ab12c12db064bc501e8ccf607d5c2fbab681be902fec23773effea7a6" },
                { "fy-NL", "97af2349ab655a613b69bf7a318cd3bc5ef481485ff71f5a71afed79324755710967c7e7e364e90cae7c92addce193b71fa41a0b2aedd6b709fec8269d9c53c2" },
                { "ga-IE", "7d6b4b0c974abe8bab77995f4143db6ca23a0890bf54878fe53d39b3e1cb2acc14b345945905044c49308d51bbda2aaf54328b102457bd00e8e12ef5c33b8293" },
                { "gd", "fa2f24b464fd1edd9d4c6f9305e08a005ebe62423094e8831ef23240da27bc23c20267877b67170a5b556f23aecb4ad16c4f564c9fc7420261cfa91cfbcb1c04" },
                { "gl", "4ddf3e25728def9af36a6ceb75de5af5396e7baa075891e7b727521507ec331b9e36ceb6124b84df8661b395a0bedf58e574f792df55ecd2ac2289b18db16f39" },
                { "gn", "710b2207730eb3c8130c3736389cf848daa6ae217a216e72f420103dd9fffe7948d696393e17994efbf559b73985ee8d98d25131ff5eb72a26e90c5c7a5eb7e4" },
                { "gu-IN", "2d02d8847c0e3a1838a579a0cf1e79d01e8d64d2859bc7ff40c05ebc9c229c8c97a798b262caf0c75b158d4c4ba04a034c5ae1a201707e1c074d9f63f259babf" },
                { "he", "fdda703042c75f49c572753a8e84913a669e10d54cfb175c724bdd872f412ccacc4ccc9fd596a811d5f2bdd9bdcd146a49d5cc7c341137e3f859f785325f5449" },
                { "hi-IN", "c236f29394bdbce4bbc01165a79d5c2e5de3041143825c506bff6e5b6d8ea59c677730f1fa877a84e79f802139de9d787d7195142594b0fae0931fad3036c703" },
                { "hr", "cab338e126cb9cd2af13d74dd22810c7db9afb8e96484c140f99dca3d9a66ac7706d9d8f6d82b672c2ea6279f68ef8bc3293aef77a642b826a004bfbaac98fee" },
                { "hsb", "fa0bc84dd9a44ad9c90fc69dac134217a71933c52485d9ef1adc22ec87fe39295df434a78042350cbcd0d7302718c06fd42b09cc0dfa7c68442d21f62852eb38" },
                { "hu", "8561cad01bcfb821eb30b0a1151d6659931eb24ff7ee85f54415045e76cd59d3c99f83ab520a8cbb3fe84e44bdefdcaedd04af2a249f5aef72f9ba97abb20d7d" },
                { "hy-AM", "4b43359c5844f7d84df93646dd8c53dc109d7fcade76775e95ffa1fee4cdef1916e8790041e76bbb384ab3d88a671c1baf508675b1ee849688decb00808ccaa6" },
                { "ia", "bb9673d3af7258835f40b8e66106366f90dcd527caaf474b98e1e60e0430737b75171747fa9e8201a13e02a3da0a4ac79f363a8977a8eb5b39ddeabcd8783935" },
                { "id", "9ad5f85c9ce7a3a0cfe1f30fca9d4c72024f437fcb31980962e86f1a937e958ce6ef2f88455d59b8d90d49dfe6f18397160dda13e429f70ed0cf47ee58ae5f7a" },
                { "is", "3445b81293d29e656e5a6b8e83e975828a816cb9d2377dd5f9038a76ff9749699cfa21407a11459277985a7b1c27f761b14d6ce94bdde3f58b0f350094bf8486" },
                { "it", "f3b9c308e14f22877214b572371b199e151b0d9876c91c99737b547e48d0bc9039982fafad81bc0b1b9f82e64ac5d0469ecc15603c33be841dd5a42c1b5908fb" },
                { "ja", "9965fa0cc56c462e2dff910325af283388d9633580cc14af6dfabc8675146663565cdac76d7aaae91ce7fb9d65302ab606930d477682b8d34a95af2a46d33f48" },
                { "ka", "8f1d0c7165286ec1702699b016191e709f8788b24bbbd0b5c1b8a739f55203c99ee29a694a8c8ef43de030c21b999a8366a09511bb3de1a998f7a8d57732ef46" },
                { "kab", "0149753f6608117389502b811e635efa9f6c549577f840cdfc30e827a5c25f5a1f05dee025fb04e1316a1975e62f3dbfe3c46c732960d2bc24fc5e3d6088abab" },
                { "kk", "ed308960b9347891937bce2835db73b447e4eca97d178378402e5e99ba80f80d49fbc8abd42757bde439f6d12bbf8d171c0ab8f8b6c92f4d4bf914eb16481f56" },
                { "km", "a486f6d51c7d687af0c03a02b39e170293ca58f9c4b2ec98867c35c46b1f3b4aa5eb851151c19f9d0315e8802ebca9a2b232108b77b41d518c5e2d33ba758669" },
                { "kn", "70d108fdb4a38d5a2382606bf3e26bc250b8312c63edbedd954d4fad03c77910286c49dd9d1ef6d19a45c61129367de998dd15ebdd33dd5dab6238c7365db840" },
                { "ko", "f83b3601c48d9d62706e19b90df8123df9a533b2264003dcfe3b0d5de0152527b25ca3275b5db5f2f335d6047d7af6e7e4842eff05e11dfbf1d74b0064ba8e62" },
                { "lij", "c86e55064385649f556c5adcdc24195e3596c770756334c98edf81433116f265a04e6537c7da5f124a08522122de8994a071117b69255b76deb5031b646fed10" },
                { "lt", "8e597a64f511bf875608bee003601daf4a2a7e6456a9d5a9d1dfe172b90a162c0455bcae5c36367e56cd8e7aae9df875680f70a4743b433085998da8e1bd39b4" },
                { "lv", "595cb4b1f337df51e9635dc960adf12deb605edec9742d01c1230c4b1bcce642c76bda30154ad9637ecbd23ba38ef62e86b6fec11aabd6879d132393c011119c" },
                { "mk", "5c64b9a09bdd806100658055bade7b1666788d1783f94fd6721ba9bf2074d15adf590635a96c2a73686479b8453c425edf01ecc0e8f65607be309df08a0d74ce" },
                { "mr", "bd5fad2aa0a0143264a755c4f0260bc9c3a528379eecb99d8624961dfe34b9f15881410ff8c790ef58a809552eb952399c6f722330eb8295adace0ea19184726" },
                { "ms", "a190dd10991f35104d84a29ab8b8e337ffbc218d7550b37c925f25f72f05598dcdf7f916eb6bfa892717c912ea1988e2c535f5bb730c040682f63aa0324a817a" },
                { "my", "143adc7a9b10b1b1d13c49dc61775c17f449d142b82eab7ee0ea9afe3bc8bf95fa09a0ebf97baba5e45b712b497d69d2959755d24511091b51451b37efba716c" },
                { "nb-NO", "c5545b3b43cd65549bee206dec82189ad0570df41f4ff02dd1ea43b47d52f38c3cb17eceb01ebcded18c100f12a61a43020aa216b8aa9051f19baccf6f2f5351" },
                { "ne-NP", "a51246ccaf66fc9d65b3699be4d99e5987c8e1e4dd409eefcc79c3c5726ba8c1f837cc312d26377f09d3056dbe3718b9cbeccccfd72e256b0d73243e8299400e" },
                { "nl", "53a19be770f6aafe70d878be4117a9fc91e6c52f5654296d254796e8b08373fd70ff72fe5c303a3ea489899512e30d2a87448bc4974c10783402aad2d01c6bea" },
                { "nn-NO", "e1c00bbbf7394dcd5071697ac96489790a60d83b7e50d0fe4a06d01d75ea839a0c97a7549e1ee1a9b795bf3f434fd15dca079e254a6af2d1179e7a0346be35cd" },
                { "oc", "4f61f949189b6e3860418e45655d50bc40601cf80383c9f37665a47fd43da2d9d7d4b3593ed9cc05f15a6f9c87420ff808468a404ca64597ed1b4c0c2b9e0ae5" },
                { "pa-IN", "50e2e43ad38776615573cf0fa64743f5108d4048137ee847e3d933b7335bfe9fd8717ac0ca7ca531e3472e8f171d68275279c356beb95749761e7a9ca6b49e7b" },
                { "pl", "59fc382ac58f577c3fb49dbe90aed941d4de45b7ba2f4047176afabbe997366900d46559261e9650104bf3224cb97f81d2f78855ad0f0ce13043706211f588a8" },
                { "pt-BR", "32149b6f87ca1f36982f350486deb70238ae3e3fb0d80d8a51de03760d8b2fb4667ff94245db0666d2ec930851e50697141a0a422910b85ebfdf9b33f43cc2fc" },
                { "pt-PT", "01bacdf54d4ab612c558596eaecc4c84380abbefd747cafac091895f2fbf5728f8a84488bae3fb7d258c858149e0de0fec011ffb8be1f743d8d603dae9bfbeb7" },
                { "rm", "535e02641aaeb9bdd73aba819c8a30e459f3775f640c341ef6c32600755ff257238cc51a19391786ef0514444c6ad546bfca74f6f43fcc13f98ba10fa96d644d" },
                { "ro", "b767d6a92ce02ec8a7afe2c4b9a361777186d40df5ab4e9b75e85095626eb181e3802bd442cce2b2d45dfd6c206968558fc2f885ccaf92566dbe8a3ccc737b50" },
                { "ru", "cd7661c83bcb5c4c27e4ba80573648b28dfd31dc8b4b7379e16d31c326c60ea10fb63ae7b496ce50ffc484e75de3aa255677547299893aef8996d2e184d92a32" },
                { "sat", "7ec5121a4bb26d50c1c0e815bdf0d04472661f7a0b297542e0e869b50e8f3b6575b476f6a4080f41d86d8f4dc6a19fb6e35c4df9bc49b494d433cdb9ef6eb1e8" },
                { "sc", "c0876650ceb7816554047a0ecca762928b508c67c3ce21bd60a121f10f8066c36274bb389f4cd1f61accad46a4225f6421d2dddf66fbd72c4cb0e8b3a6d083f5" },
                { "sco", "95e64fb58db5005ef770cd7d76f6b5377a6d101e16e49e1af892f02d4f934cca1f8d1436f95285cbb58d01e0db0001d914c1cd20cb820177d21310b01cb9d21e" },
                { "si", "a23ab37b5f46778c3aee6369c7e3fb3afbcad24a155a02f9776c866fbd9a2f8062782bb7056315d0e8bf07d55095084d5b7de3b6dc4c7c739bb19ac1a7435928" },
                { "sk", "cc9f4f9ccda535a12e3ccdc89e566a287c3b33fae7210a94072c65d90199e261ee95ad050adb884738da03c2cf5ff78190d1b9755c7e2c0979bb60a60bf0c398" },
                { "skr", "2cff2ae1396ab0f178ccebfcda4a9d71df12c23399353018f5752f4fe392cbb7f19054c51cafdb2611ceaaaed4840e5abd946e6afee0fa883aef71e4d721f323" },
                { "sl", "12b03281c12ca52455992e6a01890849ef6fa60732caa18895ffaf5a0cd35d66a52608a3e221de2adf8180587c56a593b968ca175159c88caae058a458a7b528" },
                { "son", "bc345a5942040efa9f51ed83cc8efa821d27678bef4a608d90cbefd2cfc2207d5cced6769e15ef06b894ec78513e69317846771a75f12e0427c261f7f2cf2895" },
                { "sq", "79b1cb3a6e278e7b06565d6dcbc44f118c091dd8e3a57820730c65a27c9e791ce2bcc213ef681d72d4b522647cfd92de0c0ae41505c6861f10f61acc7c8b74b9" },
                { "sr", "4a3a2ab094f6d22bc0417d96af1d434a950fdbd547e3ef44ba550852529bc6568fd0df7808351f90dd40ef7933f6778eb8fd2485cb7b5c6f7f41a56990b8bb92" },
                { "sv-SE", "d970930499f3021c26e7962919c01fac00ff1a931cfba055e7489feb89a0c15560269dac7cc4b3440fb6486c00af5a4f2dc1a34cf01a3c026dafcefbb521c47a" },
                { "szl", "dcb96d1510cc123b9c531877b97ed6ed046411c59b581e647f0b808f3afc7820e588362153c8542849d8844ee39eb9d4af5983a6f4e5fca5c57ad1bc128d596c" },
                { "ta", "2a2bd13797ac6858d48af3f63c9ef74e69dafbf06e4621264871c7a5f9a8078d5281dd68c6ea0c79e17af2aa0985d06e4ccdaa7081e486c9a427921d45449140" },
                { "te", "6c614e2dd1604d252628fa26d882566429c18e7b88ee4ccbaa4cc758357ab10401c255a03fa6636ba13329dc69320989ea0c0dccb567162e0995a0716ba6c665" },
                { "tg", "75e16276c8f65b4bf79bec0ff4ab678a9927534170c108f3699b7b7df502eee593046d2d6fe292a18c5e0d9e85cff76a4c4517a48d276df438d9af8f4c3e7b1b" },
                { "th", "fd0e0b5adc73028e821185257e8a1e1d1a8e114a0f2f7d42f03810fa96d3e21cebf81d9ea2d87ca643fcf91d430b4f5ea1befe0ab1289c656afbf912d296ca73" },
                { "tl", "91a1961e388d1dd216b013a00abe33171bb13072d9c8d99f190d5278d6300bd5e1f7dd59ac963e5cdc8ab723ad962e3a4a86f578862f51385ff1bd9ff037443f" },
                { "tr", "cac8439a0c5ba067d1e2a8dbe6dd713fad7d780e78f970bbd6dcc4d46c00039085db8df5fbe214791eb0fce21edca2645be6750b1666c2ce3feecbbb7a7d36f7" },
                { "trs", "d9d69cd2eb12fb825b36ae32e41dff530bf9ee64b513dc145bc5868ac8bc2c77cc67ff86b40b108072f84906da56d2f67a0d985fe42c79bcd7e67e2760a3ea38" },
                { "uk", "1ea9d795649844a85a9f244b4c57788328c31a00f74db661ab14dd53f099443496d13cf627343ccac3e9a6785b430e5d5b594ec1ffbf8e6fef839f63c84432ad" },
                { "ur", "8f5fb9524175262e55bbbde1028a42aeb8cda7320d5738e4972baea190cd4a797e884d3831830b55787d913968826139ca71905d0d4abc263b9b2799152e87f8" },
                { "uz", "a9e2bffe5010c2c0d0eea122ee358f93e324e873834d2bceecd0a8d076d55602a2b4faf193025b5a2fa0c76a0aa33d85fc8d5c86af3f1ac4181531c68da88f59" },
                { "vi", "5b618aed32e59f9a29d6a349a3b0f8520791b68b6cd6996eb909034b088b875f42e766d7bcccab09a4743503e3272315da436f4560566d5eda19e5f4b5663320" },
                { "xh", "521a754fa22b71b09dae54f42bd71bf15e597afb9f348ba6c93ba22a8840f5adaacb1ff6d5b19ba8cd985efb7b442db06cce689aebc10d87ff7e18bd0a81af12" },
                { "zh-CN", "06da981cda9af01500fb684ce9af5d47f7c4fbd22fd1d09738dfae9e8148ace03bc01e72f18896f852c5185c80ff4f1e79fc3be0c4b6a1ff10a3148dd3fcb54b" },
                { "zh-TW", "94d20150e72a25f68cf00bc0374965a962658c2162e4c423b897b4040a59044c218d9cb8a4334ccd3f0ab9e4e003655997252821f4d1839a06b3c6a957885891" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/151.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ced94dc46c26d7cf193bd35d29405ea60ec043f2fc2e821b5219360374c9e34a567e84deb2d535f782a5067b319970d60b2e41a735d34747590e0c8d0c476c61" },
                { "af", "afa7b870676e9aae63047f2396cb599c856a143cc3abb1da3acfc67332aeac3a4219d816f4a0ab8d4155478c9ad875cf4c1d01815f72cdc925e01876cb6c6443" },
                { "an", "be01ed8c30231c347ae27beebdc2897c73a03e4e19af0095349006f4b5f61e2dd710c12aa11f5673f0b8719f12f5799e462b421dc496d2bea127e3f291a8e00b" },
                { "ar", "5035038ac69e38a4b47421513ca52705e726f927e82d8f6137e21463af9cec445856f610570f7509f18012ef2feacb3ba8e4380cffcae66b49f62c37ca41289f" },
                { "ast", "a639f552bef891ec11f5fef156df027e1a29765ed9cce744e041483f3e6f4972f60cbad021b8111d1ec9b6895a7f76e698ac3c5e656fb81c15e1acc928afce2b" },
                { "az", "430abca2887ab1a9bcb72f6ecd57d73b027270c150dbe8e47fab57caae006626544c5aa9d2d4486087732d0b918a254dfcd0408807180c3d46d3de147111136f" },
                { "be", "ce7f2e306d0ccf4e524b561a97c8d91f89739d02aa2ddbf23d3aff3032a77c883dfe73e60ec9217a2a6fbf96377fc954d41622fa1aedfdf7924eeb2eccf1d20b" },
                { "bg", "06265328c4ee46ad6d4fb979d161385c7a84a86f080f80f208a8391c22f6bc0ed307eda9e0f0221aed2a11456b4fc9952890dff4f4eab4074c85682159a92237" },
                { "bn", "35d40c50a4c45ae359c8696d3e0f5595cd861d7afff1f267e40b7abffd38af9d5cb9fb1801bc6aac3c90296a396c305ae78dcdad36f6b453fb5e23fd8f109e3c" },
                { "br", "34f459741e30115953388a0267bc5062c4f715d82baa67c7a27118ab5e271099916cadd2bafcb37766afd945e6f4805caea16575172a5825fe21bb0e002b2897" },
                { "bs", "e69bc40229b1b1c0c87b7150da8300b170e8d2e683672ffdd778452709c0f94ca17c1d866f2406ff0c97e59a40fc3e7374526e5ae2c6d38b8cb54701aab2db35" },
                { "ca", "8588241de7565fd256ea3b4655303f4e45e0c11b55c3bf7c9df75d92fbc1f05e1e2acd79b089ca8a6ac97d65f44f5156a5a26dea9c8dadac409327b12bc450be" },
                { "cak", "dd5c934d0997849144170a33a1c49d6602551eaaf81c192f80595356dde15944891abe6b65a07ac9118c812a53821184780338d8a5725694c78a4c949df15415" },
                { "cs", "16a9d551df19e91165ad7061bd9aabc077972ad2e450c0e5a2ed7263b522e292184550763f22eb7ca4c006447aead88ea85a76b04269806f5a66496216033dcb" },
                { "cy", "3daeaad989575952faa787d2b412552235d0b41a4b15122d82d489eb159b1401f77ead0491291860f6191099bcedc1a0eda4156fc4e4b0950f6a791f20105541" },
                { "da", "0644ec138e3dc92c1a028df2fdbf97ec43479ad99d08e6e2e90a533bbd51c68066c83bb89a89cec9adde2287b4528e80fe08dfed5a910cbeda0b151525464e30" },
                { "de", "1133bdc7109fe3620d2ceff94232afe95c96e6f1933c2031cdd2f461334edcfd131b0533c3971fdd06142cfd31c6735bd37edba1e62ffcd41efdf8ff2899c86c" },
                { "dsb", "050959acff9a732da147579d6ae80fe45c7ea64c8c0b17170d805f6fea96644f14d1a4b25e9f4df6758722c5a8b8112e7c11d5e808625657cc31f2561e2184e3" },
                { "el", "25acd0a0c77c4fb7a659bb1620160d488f6bddbfaba187597f96d09f245fb5116eea294214645633734009225f2f9fbc8183dc8f0ace561a447f3aadfcf712a1" },
                { "en-CA", "84768fbd0208370f24efad5af7fd406d04e6b83f716c281194e55fc50d10c8f42ce5393d8a8698e218a46a092b93989ee25e1dc105f24b4db93d4d47fbf70d2d" },
                { "en-GB", "1889dcc8ae877a9ac21df83132c78da2fad9f864b2060e8820a83d6b28b05ed4500603ecb86c1d160fb1004f74bb9fe5bc31665b09dc9a4bfd8812383f60742c" },
                { "en-US", "28080afa51a9bbabf42f22b8dbad2feeae1e89bae555d347264de1d1a0bc4682a5e4559b8b665b47599aa2116c9fc0359e1a180bdf2f046139aa0a66f16d5088" },
                { "eo", "ec79371615fc83a0c58a7c11e8198b17923fb7b48e637290ac00aff45042f6dd8e844761895d62ffc1342046770ed1dbea5513f7d92ccb97752626a137a4be6c" },
                { "es-AR", "2563c5a61d0521ab23257bb44734ed4d1660422a690ac04b6149e952ae9e880fe44a6652bd972c7751fb2a9d25653af386d6d6463b7c96b5323fa20127c83682" },
                { "es-CL", "28bc9f96d71a2e7892d79e89a41e3c6e40292d7339be2022f04864400c0071ecb2a30d47dc448d6347c1d7e53f7bb178794b5d926d6df7699f10d805b5d5bbe0" },
                { "es-ES", "cec672776bea42c58bb0c057d9059c6c98f3eea08772cc2dec78c01a4d247f59759f5e5f44eeaddd0f3ec85e279484106baeae283788b97c2b078ab286ab821a" },
                { "es-MX", "8ce148cc5d96ca2b32d386cc4d5bcbcacc72af2360875daf00cdee9b6a2b8fd77790a6be3362db581f1e8382501a0f3691c8dc9baeb18e5e18bdec3ad60901b2" },
                { "et", "a4caa763ba73f56247a81eb3e7b4122664bfeb6a7e86a5338ea39f473b1007db8e8d6edeedf069dcbabff0f1f9bc22a8dd647a0b9f4f336cb7dafe0db2a1ef6d" },
                { "eu", "b9197b9a51e5dbe72b68195a7343afce1df118448bc98a905d9e34a8e555c34285210dd632d78059aaa2564b3932d2b0008363b5cb71b5a59a10e77a7a797d7b" },
                { "fa", "e020c7e72b83216ac589b9a2bd7f5be86b599e20c7dbcc4c4286c44fa2278b9f93271cbf28ff1bbc8037443c7ca881b642171e874f5ff74d342eed9730a2839b" },
                { "ff", "0569b6000a56b659a46bdce9602aee308d8215775858ce5d1a0817c6a43507a09495a38d27220c61eee01331a04550286d58f21402117b35dbf0812fefd12f70" },
                { "fi", "7b19ba59ecc39ce1b5c3eca4f374cb763af92ead0a598d1502b54ca129f7eaa43d375d173e247c1971114f8cc3f864ce9c83453e466552e6fd5c269bbeac70e4" },
                { "fr", "e11ffb6db4aecff363515d4dfdbc6aeaf50354c70d3dbf55c094fa262e46d350f3d0eaa844cd0e6fda2667d701c6e2db59553390b48f6d69d1ab401bf1b4f162" },
                { "fur", "2e45908f6269927b406a5182fb40bba19d80cb7267ed69a89f49a01f3cd2a5971eccee281c76b980663b5cfe8fade6acc11111ee0842011752440f9a8420d602" },
                { "fy-NL", "8b9f282b475fabf8cd456223247eab0aca33e2bfa81f5202b6802517a297d44280347f43065bc6a5f9274160630c42a59bdd215cfe2717e72f307184e5f5b9fe" },
                { "ga-IE", "c5de1fb307faab91e066c2a664741580470ebf89702f9f61f005a3fc530f567f8dda5fb4b499d2d5d983fa4fc9d20a8d0653cb3b9f850d88511fe738da8da197" },
                { "gd", "71e89af0dc3f7f3ab6c2d620824231cb25605f7f61b3b98ce5c53a52e72588c857db30430905597d5a8f6ba157faa1fe18feb227f7dac44cfe2eecb558f5c4d3" },
                { "gl", "2b98da9b32952b1caa5b3cdd8775eec229b18d6b52960cb1290ec87e8eeaff3e3542178b8c37675ddb6dbd76dbcf69c4ea449b597098283b54abc9fcd3922568" },
                { "gn", "1db1ddd42843ff79b5dbfb87847ce205ae8334afe3657d3669cb03b9e1d46e5e59261cd59564fe7459e238f98e14d2cdd6af55709b1d1a4ba7cba48845c12a4f" },
                { "gu-IN", "ccf64d0b5bf37642e029d50bded1db1ac77fd36b2f9ddef91b3bcb417433b8175e5ddbfea2e09607c41a7775f30d33b8b0a252a4666c2158817afcde887efeb5" },
                { "he", "7fad9584ce312a2817d2128cd6ab1f31abb9aa21007917c2ccbca8d862f24b6d361265dd988bd36287d94dc6281b72ff943c802fc92f7bc81777947524a0d1df" },
                { "hi-IN", "f48014bbf9d1c8800bd3d3fdfea58a6ff8627919f28c58fc62fc910991ed73f73e098c04b0056ceb0f925bed730669593f27fc148fe994bae70aea68ef9c044f" },
                { "hr", "c002c856c67466050e49ae5e3d9ed20712c233f8248617e0052b26c188839f11b4d5c16cad7f414b75d71d3f7cbae65cb8abbfd58ef3d3fe7b82f57c54d39965" },
                { "hsb", "377c562aa2a89aaf617c9a8ed216768e1b504afab996bfbcd1acaa6f2fe9f026c25307a292e0b350788bb54b299c5e049ea0ea477f1f0563ff776f2e144abb21" },
                { "hu", "9a001419ceb74f7f006ec4b14c7d390eac03848c806706ad024169e61f6a4009adf19fa3e47e59762b35e4e7dc7da7103f6c992d26a103af3f8e86cca2957d5d" },
                { "hy-AM", "58b3a1de031865c5b3589532b013438279490e7fbc7f1ae7474d2d6b3ef6f8f0727f413cd96145bb274d1f6c9bbca0b5d127386b1dfc72b31b0914e6040f4520" },
                { "ia", "5f3d5bfdb9a6bbf4b033a1792d18ca4e33c38ff29dac5238c1f82b52b48429ebd72a4b6d6645605f6cb2773b74ca60ec910aa638a443fa431835e734c0b75620" },
                { "id", "e79ca4f9c22d21b789eb2aef85da9c4bdc8a355905b0e4b79ba70ae19f04e19215555dfc580725a11f4d96b2cde16c1395af524e587e41483e2f9952f01b58fc" },
                { "is", "cedfaa1ff7f3bed7e7e23e4a50bafda4f78aa58d70b6d3d2cfc461b64ea29a8604cc930833007e1ddeaf3101ed75a2466ab4b7cfb1253787c7076af7f0432997" },
                { "it", "ee79142bec5ca5271f476d10c4c2ef2e926ae37644abf20c08e0b31ac006827f8ae930edf30643ba588dd6032e4f5a149abcb011718bba116c7e5510f5b72599" },
                { "ja", "9f08991d453dc4f6107075d0ee6ad2c635e66ed1485b1df6ec972c13108e217330f0048758e51c6f1e882dbd0c862eaeb0c906b40ab4a696eeb1556871e25219" },
                { "ka", "db9626e29634a574984588dd6fe0cb598d0859a50b60ad63a8aaedfb532bf578c7ca2cccb3e4ad47243b4d3b02c2dc561e504948bd6d410fc6cb917b53a7907d" },
                { "kab", "3a2d65961bc7712ec65967edd3c09ac16ab5b36b5f416962a0b83ea47e7d665cfc6d05694fd2cf53e422a724adf639c5812bd6570d5120100bce9b0eac73a5b6" },
                { "kk", "a92014b843cf534cb913da001d064027759320dc220bf4333e7becfd017bd6d4abaeb19987d0536ae81aedf0b9737867efb94a37d0140a7a89354121551ed0e0" },
                { "km", "cc21a0eacd9594bbbae496de69e110ba092327b415d71bbd8f0b0c4be64ac704a5bf130b600f009bd70f33d89943930e6d33f58395361fd78d766e9544515f90" },
                { "kn", "458d5f64a2e2b93f81450d26b4f4f47ed833f4d9a5e3c75ffe33e8570596bd3855bb17f2cbd339bab885be1ad6cc3178da69bc46b3f2ac8854c84b614a8b326a" },
                { "ko", "6586230eb7abece3b77019e7fe7609b22c38e0c50fdccf310a159c19c8fd304108e8b2ec2f76b6c46f384661af5750e13add9d26a40637b3a5ea30c7ec6ad35a" },
                { "lij", "2d326a1afcc8def5e543cae3570428733850927a6b81a2d98d1201e24c24a2aa9979c1cefc8270d1e18b68ea9d63cb3bf297d4937f070934c6f1a8939d7e4510" },
                { "lt", "654350daa870cc887caac4f923529968fd047de1ebb8834ff1963eb021979edc3100534ae7f1cb76f6601dec3cc93dd000734ccf3ec61a640a60abd40d324d77" },
                { "lv", "b18f6bfdc5be89a20e724fc75661661afe42a90c516adb0c195216b3c8e86c48f9fd7ed52b7a2bab3866fc550fe89cfb5bbe7faa2032a5c1ae7a4971270d5960" },
                { "mk", "cfbadf76a43153e15085c7671f88b898eb5877ab9a015c9fe75b2f112c7e482e0f8fa39aca04793c303d52f3461bacf257e3e162308607f527be490fd6780b95" },
                { "mr", "2ca26e07f785ab1a985bb0f9afa4e48acadbaf3d1b8a773e77ccd694d6380379093d7e73ba68d87d60a3163b76252d852aa9faa32af2f3106e6846542723ac97" },
                { "ms", "4ac27f0a271a50e1c5cdfc55f0b32a0cbc41831c136f65701bca2f6d0d37167b402e2e90e9a3d8f42a311e957c7211e1a688d3b0263d329bce9b507113c6e670" },
                { "my", "5965eff22990359f93327d4b08f3747ff2af2e505059f38660eacda19c2c28c2905709d9ac14fedd4d754b5e1f3423e45b2045c549c512bdff99e3a74c3b0297" },
                { "nb-NO", "e0c84ff4a59ff58bd5138c4cdfeaaf6373744fb23e200fd0d7c31b310218f96e9d08e473562964a0af99d481398985fd2d5918d3df748f30c0fb4d154274cd5e" },
                { "ne-NP", "1e5b76da225ce430536ac1b53b12255d11e2f003574c1d7bd8be5b9381e58f72ad4f7377747b63aa1d68d8fa4ecd907317db5376eb59060b6646bf880d1eea9b" },
                { "nl", "7308069bc3d16c25d886922dec7f4b9a1b08e7be3d020899d29fba8c852c7dbed9499f937bf2d4bb290f7f8b45b1c8c32aa2a0ff28fbff1bf93a0f9d5f987bab" },
                { "nn-NO", "e8305f7a7d1370c9ea3475e26cf0969f5151c75dfd8fef7135ea1b89c214a4e1068366b791fb98ba8f432a88320d2bbe8631be15fa504c09e62c393f040e7f57" },
                { "oc", "e02be971af3e320e363f68019299af9371983256e7beab756787d20fce3dd393be3d12050b28411323c99bb85186cf03726a8a32075ad1945442bebb51c1fc27" },
                { "pa-IN", "9cd96220bccd686ba6c86203fe329103f020257b1dcb39f46a3ab3d17a1534b06078eff6a76c71d1badcdb64829f83355d8d480ec4d071f2fd5067de1f0fea69" },
                { "pl", "843794f6edec3cf41bb2dbb2141679cee94dfa711d01a1c32b5b87601229a46b665cc33ee356e11bf599711a940f699e7cb8d2afe31d57eeda50b7a8e3fbe8bb" },
                { "pt-BR", "08a5d5d05e3230dddaab71a2d67cfa541574769043dc15d9c466747803c79d6c422cb5faa1afb16f9ea0ae01108a97b1b72bebedb838545d260dcf21d8789cc4" },
                { "pt-PT", "bd9bd5616f01eee0c9280c0e2fd3586fb69fb05ac05ae5460c17729ecca72ea3eeacf24fe92b3fa06b8357fa9d1b96379c5a871cd720503608eadd61c6ce4871" },
                { "rm", "5afb96b8ca9f0e2060db924f8d2545fde1a305d4c5c7f919afa856511c50e71b4a02f3598f0ad5ac607f4a2d30bc66ac68d2253a6dcb6b97b9ede89f6348b701" },
                { "ro", "5cd1328caa8e2eafc8de187487f1b91b051ef6c84bf9dfbc5b7b0054a65940df5cc8c363ddeb6f6808b6364b7cae54a736b16ab61089ab002fe3bbf5f5a20644" },
                { "ru", "7b1a79e93528c7f3aad00242985cd8bb754af654e3d75560475954d0ccd7a9759a67df71a9ad81f6a83d7577ea64757063aec70f28469b2666585b60d890b4c8" },
                { "sat", "09594c5d2ba9b68619e614996bef557faef6630e5ee8f298826dfcc61e5d6af9461befae3d3f95f179fceb63b2b48104962a4c87a5cf157f0a85a711f69b78ea" },
                { "sc", "82f145b444fd3cab6c121295e0888bad4a3e760a6900a96999733bcc2e9d674f3c92e9d57bd63bce77f0501f11eac7804368e1c548e8f81aeaf0996fa3de693e" },
                { "sco", "74ce246b4cec72b77a063e8a969bf9c91b9dc914aa16619cc5cc1dbddbddbaba9135463df6db65f2fa53d4aa4cbbccbac3e2bf2787e60a28beea0f8b6e1b2e18" },
                { "si", "09d8769b17da2b00f0555347642511abf8707abe4e0a72c793baa8416a52837ba8f4c5263780dc8fa6a3c00ec419744e36626b580dd5e913643a1eb04697edbe" },
                { "sk", "2f6604bc086fa718fa82a67d0940e166a08220e2ca2955c3ab2134b76702a12f108a9d15aed90fe98f19e9b4ef7c24b4ad20d6700a5eb0240e77ad190f34962f" },
                { "skr", "5e732e4da420a4f069e7553b701228b06223ee98d5c4ac4fb1cef304c766110bdf274c4d59de8447f1d7f4a5bb96465ff702e8072f05932a53b0423f70452e1a" },
                { "sl", "7e7f12b5d58af0ade32aaa562033b2e70f11bb8c0f3b2e5deac97dc4f9e4fe776a70440f7648f189631927e3a05342bf2b5beb8c7e086a4b35a30acf5e73b55f" },
                { "son", "96e3c13d00b00e4b956c37f43505aa14f0a073f7d9318803981ba90c08f857ac0c294ce536874289ad2f55b0144ad65bd808ee2b5f8a28229e76bea3b9bbbefa" },
                { "sq", "93426aa0081e64e314e01be42147f728dc8b5a1aa0e51adb0182daa9654427475b86e150285c958ff4514d222130ed9881b06cbac934621aa7e7e059424d3e1a" },
                { "sr", "11c606ff58469bd7b61497daec5387d978e3f4be52544bc8b7d0d36812dfbc5d7534c5e47e22430d9e39959ef766deeb72795a5a3e35b7beda2b146fa350247c" },
                { "sv-SE", "d1c99cce33643812ceef5307c46cb347194e36c09b1c2682a1d605f5644c1154039e4a703a8615e77b87ebc1192848a7aeb4eb1b4beddab1e43f2d9b6c9f6f00" },
                { "szl", "bcb11816b02afffb5718c515aa4553b87d2866d30591a2a4f30014fbf1443126a4123b0d6b1c7d7f541435cbabb619ca799d9f38bb6d143f0c4140903c2d3480" },
                { "ta", "10be8f17ca9406558858f96a599429e44816c74f8e304a2cbf81f873e34751356b89c598fd4d9852a95e7b1b88b6b4f488d253809b759392c27a29d1503a9003" },
                { "te", "f43cc5d1373ef4de9fd403d9c7d25296c69a0398c89297b378a552a078ca99115052f195455d85d8dfe128f35a7b945b7bf28ef87e8819ffd3a939a3d40010ce" },
                { "tg", "7ab9207c3aec78b18ad78137c15bdecc6c03d9b46ae2a5ebd26c2a3c92345e2c79d84c15ef62dff99d9b53242d9fc64094f8f1e28018d543b0bb45f4630553e6" },
                { "th", "adec4a29ab197bfc854e40f802f76c953c58f859478396201bd7fd5685b08bb9ef8bffa4c34a56dc3e0e004936e91eef8a7cb9ea8abeec8fafd7d68a04b2822a" },
                { "tl", "54019527ba8ea36e5f5b60942e277c758c1290f30fbd4e767a11abfd80ca72cac7a8783fba0c2f39040aaf12ba766de845045716c5619d9f5e41df5c2a0c4a17" },
                { "tr", "0abebb48cdbff7fabfb25825bc1151a138335d1cf52936ad485ff7bb56e4cd1fb58e161ec5fe3c4faa60d2f3e7a604b67f7286dfb1a9d95585cd1b12705dc45f" },
                { "trs", "a6212b8c27f74d85761115377ef4e30772d2e67a56320a24a55c330fcd4e676ea82387e569431c38b0d782988a9f94184d2710c22f3d3edc0c35a0b5e553c32c" },
                { "uk", "80ff979b79d7ca78bba3909ce65b1782ddd20ade4dc428f886e7dec1fdf91baf65ba6704e40041cbd73dcee4cb968a63b8ba5fc2d298453765250e59176650d2" },
                { "ur", "28d0e4a1e5b64775310c987cb1547b452848b5af2cc6aef379020582e45acf531546494c98920fa4fe3e21deb588c436b6451de5bb8dc66f93904d9b15f18bac" },
                { "uz", "68363332d74a951e26c82d499fc754a071931b53efce5d70578581e459262c80f847650a9f82dcb30cf0d372cf765ad81b542cb4d6f682adf6be90d9db3bd853" },
                { "vi", "477875c1432f44aaef211b555b500248a68a69bdb8713b1d9635cf9330bd859173f645daab2d9bc942a5b2ef51d6565ce9e025512aea0c9fcc4ec601eadfb8da" },
                { "xh", "833956afd90019bd4efb750d2bc5d136f16fcd9c1d5aec52e76aa0031d5f4f5c9d7d4d3863d0f5215da152b95501a22caaf21c740a0a2e48b88d3140ffcf94d6" },
                { "zh-CN", "11b45056a10107bcecb1b13687a0616323dad08a15454fb618f0a0ccfeb04902d08aa11172b0ed67a0224d26e31124de439d91eada7285ff4c07cdee41ac36fe" },
                { "zh-TW", "14d25acd325a597a017ffdb2cedacb28a21425744f0f0b22fe8dec5cc5ab1a1b44e47d2b4b5cda6ef9126e95dd162bd064d71ec7baf9397504ba8c36eb4c4eea" }
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
