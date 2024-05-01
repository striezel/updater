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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "126.0b7";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/126.0b7/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "23370af762ddeedbf12df0c6c2e6591f92c8c55bf154a9802cf1717eb2161474a50de4e626a6a01673c127ce0ace2c3b3dcaebe71d23fcf11c81ee4ef9984034" },
                { "af", "68d1e418d0e2fd69e9f0272102f40a140d7c0d56349f5042591c993c32dc77db0f70375ea3f7ca8a7dd926d6d1991ce52e1f5b3b155c52c94f336a70980ab041" },
                { "an", "c21abdd11ccef4e57e9bf1b6029c3608345d2fae65fdd67cd051b3198dbf8603be0e3a1c196a9a225cac74d4f1837a8d8aaab47b1dbe6d56a0a833e2104cfac9" },
                { "ar", "b330eac73387ff1a550f5b061dcd6cc2d53891e61935472b1fc3643c330d91926634b1ce86375fbfc8fcc7c7b32c0a75fad602c3b846bd4d8ad64aaa0aa9286f" },
                { "ast", "f463704410503c89a13d0ee5f573bb27b69d401910284348cbbb08b1dd2364ea027ee18338de7c3b05293234bbdc10ad3627403c97b677d8ac05fafe737760dd" },
                { "az", "43956d164da57f56e12455b891af9eb3801f9e9959346c100b21efcbe1bf5dd9669d3842fa38b152b47fd822fc514dd3d436207109fe09b9bbf2c3e6c81d7f2f" },
                { "be", "9d875c9c507068ebe6bc8a6eafbe51a40bdc5a9ada4e79dc15c75896b3159f05d236ad2fb8455f7289b2d236adc8e017b5e90d7640e6807a079fded6261d97b5" },
                { "bg", "ec914f3df52727635e5e85461bd08e0ec8ec13b9b6b0a747566ee1dce08d8e3035d727258777b3a7a56b8ad69210d90135bbd056d290dd3286c3c153920480d6" },
                { "bn", "3895d510fed6660a97220a3af8666e31d87190bbbc5c6466dde5ba18e333e60d38725e983e1810c9a92075af6e4df4c9d6b548bf4ba4d912d54087e7939155af" },
                { "br", "e852379b61ace0f37ac774d52aecb691e6d0c3dedfbd8b847fb56f431d3bf3dc97e5e70d7fb940605a6b0430b42fd14d81e7dfea82ef584eb6f65f36bab9fe44" },
                { "bs", "76a92613933670f40f641ffbc93c1e00e300458f7585d6074ac7289f2c12dbff232ce0afaff3b0f618312d0af4ed49d815de012575b562c6a93935d35342f67f" },
                { "ca", "99cbf7d1c44c0efa288562aca9d559d9c93f55a6c68cb89f6c7e4f03e2ae2641a37cfe1677c5b0d4225749dcd64edf4b8fb5c070112be56cdd7c2304d02c07e6" },
                { "cak", "cee54b334bc6426d71e9fd883cb7c771120768dbcadbc0961bdb26074dae955d9590e16ebba1d753857212ed79d6190ac8c28a58ac1f55c97a7ad87112f2b851" },
                { "cs", "70d0aca6d164a06e0295cd23f559ea984a4ec91590b4c0fca1d15c1e46dfb4a530ef22fb29b996e81728baaa6b15724542ffc6dbf4b9952c1f2bda114fed3d8e" },
                { "cy", "27f19c2c66c276ca456bd748d6283b050f434a304d3ba6e14e61b74f32beb29b34f2b01c4ce0b241f6fdf0f5154506bb1a39dcb095839de50fea24d51c4e694b" },
                { "da", "a5e1755c28c3327abecbcfcff4d45610821df3145d3c9a1121951487f0523d525a631cac473523c6e99fe9346e17ecad35e5c4f9803643b460a41f382da14bb5" },
                { "de", "b22eed825fdc24684ac33ba35f8094f037e08c92801c02d963beb747dab0ac7ba690613a258daf56deda3b865169e219c433b42a8e7d72e941909bdac343aa75" },
                { "dsb", "ac20009591ae84913595b313b9edc9c27bd4c17dc4dd35a71612d542eec705759c2ee3ce77629b0e2bd8171068ab18743246454cdec3c5901b8dfe30bc6c1f0b" },
                { "el", "460ecde2deb84e8b72749ecec63b0f77750bf3d4e96aabd37552340e6bbcc992824ef07529dfe9281c50627ceb51b993bd91c7fffae89268963e8b7c73ce7980" },
                { "en-CA", "e36413a552d43b9f6f17881d0f1bdcc153a4bb6287e66eaaa2886c53705edddc7300e3487db83acbfe8080282673c64377454cdcf74d59c273dc68713a9cc1f5" },
                { "en-GB", "f0c9a2e89276ee4c160b75303a883bf7273eaac1b4ecc17e7594bedc5f7c5833c283122f662352fbb83e0d8b1c8723d86bb6a4aaced4efd0a179b8d0aa7a07ac" },
                { "en-US", "bbf272487a1470a749499ab66e6bb10b0879110f093f118904c51bb2c32ef1d95e7c8d43448eb08e37b51807257aa26ccf29d397c3539722f25165155e077118" },
                { "eo", "c540f4a3f2a491e6b999280007898c7f86879cb38831f5b835b84befd5e90162d1b6b31708c82dfdee78d98db34aa961093986de0c0983a4577e2f7841f6ac2a" },
                { "es-AR", "71afa3c1ea6b0c41603190583e2efc8c5835d7f78b0dba006861befe7c8e3b7490a5a1376be8772dd93b4e3141250c365707d0a637394b723b2db471c761d119" },
                { "es-CL", "62e82f4a5bf92cbc2d64301a582f1dd990a290f5b19e7998937ba2ee5da465b1b0b27e693c65fde56b271fdc63aea9eb610f9b17d224326fd738d9a8154583ae" },
                { "es-ES", "75d9a09e09785b9d98a29b2d838d20006d20b2a3f540ca7bbdca5dc0d269b81e6a613d76e19eadcbcbf355098d0cfb8443775496be6dccd78828ec6d5203c8e7" },
                { "es-MX", "541ee8f64c3622172c87af50d2b348e0f737ea1099ce12ae886ab3501186aaaa65aaadeadc2053adb2eca953420cdf51888d6b2a008772ffbea462d7d94d5cfe" },
                { "et", "0b231de395e5e2ba0bf672b591d1344b4d1364add281690475508edeb652fcffbaedf0b32ff2acb3f16b15bebc8750c89dd2977adb92345aaba7c0933ea99023" },
                { "eu", "4d540bbe657465e04f1d846613f9a605342dd31a2d62ffc7f7ee3334fc5a6f5a7363e0917e0e9a4a7a92f4420c34cf0d15a9d15fede9fdca0e3692a412ad8447" },
                { "fa", "8cf14e9884006158178fe80017bba0b63e0d9a93ec458b0004437ef4b7784b0bf8ad82d931bf08840019aa85286239892f9514dec71c7537f25e94dbb9efaa57" },
                { "ff", "83f28fc3234e1fb0f8933a52d91a512b96c4b201ae94b73edd10a0e6790134788fd2827e801ef1b3f3ce47fdc601a5b089abf7e405023b7e0e4a9c4878ff04c1" },
                { "fi", "3ab10e4d8c474e47e7af4799fb989f061cde9046de1513103660c8f8ca1de09462c662bbe1db2711a20a6c6bc414f5b592a83166b4b155d792eb54a1129a5a9c" },
                { "fr", "e0633d1c8a9ee87fad4ac8eb23e477d6904cd2ed34b2e16e8c9b8827ef57ac5b028860465ebd7d49d094c4b250a71ee1156a348071922956fa5b41f3055ae069" },
                { "fur", "e4893439df8c990d5e8d0e80966b660891b0e7ad14d8b7b4030eaefa7774b900e217aef6f3889ef56ba458c02eb8b482d4f1033e2668dc4314afea2260cd9144" },
                { "fy-NL", "c07c11252e6a3b70f26f3434f9656a286bfc4cabe8f60a4c12293daff78415830a8ba39709418657ea691e165989eccd388b5c0ff2d9bf226c2eab0871354634" },
                { "ga-IE", "a949921448eedd94e1f33ad2c804849fdeba5dec0e5884bbf68b6accf5447ce9938193093d6809ab1525823dded73490fcbf98abe0e9a171ad966cbb0c28a171" },
                { "gd", "827a7103756a77d203a36fceb908f982086dc845f2e2ac8f0dbdfe1535a9475cb1c80c1f4c546e3b8c862b80c158590abce64bc1e9c10a768fa7b51c0ba26a7f" },
                { "gl", "abf521403d504a85c834a4aa300fdb608208196a0452324a751fb39790096291745eb7472aa2fe4a87a90c0be4275904d5db6d5f6185f8cb12b6431def81f3bc" },
                { "gn", "5d98c16b820066d7942e92011d101d50d596de80a4b1bc2a45519cefff70f82a2ed2d291cb8e32611cdd000bc307df1fb3e36092a808acb4b3eae6a434d90d1d" },
                { "gu-IN", "f48180b3b72c083aece1a815e2c442c3fccaed649e12403035dd9e518b1c6c540ff25b3d1fbb50382b40a8794168e9de71e81c13250667b36d0f399c378e7d93" },
                { "he", "dee8998bde714ca2dbe48780280d63cae304b10c1b16b84f62156b45e63f239320f396a400998186dca9602ad9d3fa9314defea5ad5c9ee66f74d3076de69223" },
                { "hi-IN", "b207ef98551ea40e1cbc167ca0e9f3fa73034e8ba3bfc71f1e1d2869e58f37435af61b070725ac06777ec01c132afb59fda96798ebc7425b9135d32e290ad2ab" },
                { "hr", "782bbef622e946187941dd28877e0e88baab19a91d503e4005b0e85f09cb1d3e36bacff08ad6e4a2050f7532041d0baac694284f42c8bf571572f44c8ba4429a" },
                { "hsb", "6b70c150274fc1388766ec68bd18396572d2db75d503c8bc6db3bf8f4cf679b8a510731341de51721bacdaad64887ee77abe2637a2d1f114feba8b180df7328e" },
                { "hu", "95075481b8cc7bd11c31a3019b9f66dde46dba94ab35048f7389465570661d988aa80d9d82e9147bb68d38e1a2a4d320aa0259fd90be3e1854cb76feb0b3ed71" },
                { "hy-AM", "be0fbdaf56b46e1f3ea57a76daa1fac0c1d3902fd3014802edf2d91070c5cbdd8e006e14c7316dcaf0bf5ea095db6edd51a3fa0980ed92b47746e140d3af5f03" },
                { "ia", "4a9fe0b5d5960381acb12a610dc3442f3832c48e9f06bb6050df36af645d969d6e54837640ed56cfbb1b5025a37b122ec2a5a70006c2fe8a367451a50bc627bc" },
                { "id", "f9aa77ce98f2cd62556ce71fa211540dd940610e3dfca535ddf0ad6837968ba08000b8aba86b134575fd52a33035ccf99078672b7159a5676053f3dfe8018811" },
                { "is", "c92aba7668bccf36032abc94de29e90e27f70ba5a01e867a97f6ff898f715ee5abaa5cac631a7c25aff2cb32d3283b15675d197a59dd432280889fe0f4423752" },
                { "it", "571f39b25089cf27473fb78def17d6c3fad5d5a2a5932bc65f6a7035c7c61d2cf2f74812e5952b2002e87522341cd37ec1c0d3b258f49e626e4b8ddc794cc022" },
                { "ja", "f4b965812a972b97f6dd81780f5833ad9948254e62a2fdc738613ec72898b5a371aeda04c62f64256ae48e6cd65693d590bcec696b53f71e36651092dd532571" },
                { "ka", "98b2f0752d799af601a49db02f6055e4caf8ca81ab5b52c6de1e54cd5627a72bc725269d84dc302946494c398339f0b0e338a25aa5c1684648c6c3151b1478f4" },
                { "kab", "e8c8802bd86e7eb841daa7293ad6af6c0611ce7235f3cca6481da18175b6e9b0df17c6fb37128d8441215db1c96692af939b488e2b948d8e99157c48f3560d12" },
                { "kk", "ea1ea72603016b094fe4e4da993532e5b00f7c5f19b1f36c061ebf9d565563098660c56faa66540e4ddfd989de0a89a43c5e48d560f5db6cb0d4a0d1820251e7" },
                { "km", "10b1138e85929f58e3b139a76abe06b342a51f16dff2ca612b4ed48f8250f44bc7ab51af8b4f5ff81280a5f6db18c17baa5d9edfc796f043be25a5802c9b7202" },
                { "kn", "a253d55a28a0b968c781008a6edc5c1c947d33feb78299084360fddcb7c822f70038d44a1379e2ef17c30cc67c414bb8ef931667fe76eabebdc39dbda26a1aca" },
                { "ko", "dad1beb9cc7e0ac934d526b631302ffc0a8bff29b9c2266a5c16a383df2b4ebd913cc21a816bb6b4c36c8cb70458e0b74a64aa03e6536235871b8f20e1f14409" },
                { "lij", "aac1e3924d9cee5471ba09a01182fa32114bbc160bedba0ea015000684ea4b068f7ad94207d692c77694998e7940fb7d028021ff9bad92965ab8fea8ff1f4f8c" },
                { "lt", "ae945d0f05ab13b1b161a5e545ead2026e64c0c6e1e3247d1bed184fd35ea6212380b4eed0671a0305c99719803298e9ff4b8a77edd8dcbd7de307ade5655e84" },
                { "lv", "e535452b45730061a40de4bd0161cf35459890c26d8e9db05648a594ddd29d4792320b97f12fbece6dee375f9aaf8697b66b1636ca14b6ae0791d58f87aece3c" },
                { "mk", "3b85b4729ac8c602921f95de220f6c8be7b9d20992b31db73681fea72b1d21ab4ec88fc153a8cff433335c32c7eb76be603e4e6c1ff02dc449f46c36df3d503e" },
                { "mr", "592e36ff42b1cf17ec66cb58e756d35ad856b323a0efd429742ee74fec9dd5318c06b3e7f3c2e9c4b52904a65a3a92cfdc447d3d26ec4387a59d172dc1a5c2f5" },
                { "ms", "fb00951e0561efe1792995342acff05d83db7fab8e589a3d3de5106b8bd70a77119eb4f0045bbed96921bdaf34f0bdbf10c64cc9079acae773edd6a69fe331ee" },
                { "my", "f8a6119ad8031cfe2047a468b6233f97897c4abbc84ca6f69be3f1994ce54d54c117d22e016f1e9568d6a441fcf76512bcb9cd43441691cf482f72a90cd2cac1" },
                { "nb-NO", "462f0e658f77ffdddb7db15868e8daed54c1649d4ed867d95cdf376f27a460e55d9e5da7d6f7447794c916592617b6b1d44ecf65bc8d46e3aae0b60e27b1a086" },
                { "ne-NP", "499a2ae8ea10ddab4a95349415a2879255bc46a2bdaa0ac7a40e559c802b15b49ac881a82b4edce9a6cb93ec6b8b79adcc03c44faa84535fce0d476f57639af7" },
                { "nl", "c4603038360b03285775789a5c56f82a9e8cf8a9ca80d615ba63cf147bd39f58908fcf5de2ef1863309c7cc39fd718cdb1b0254582443a09b3d8ce9885dda7de" },
                { "nn-NO", "8759fa1258c5d5f9ec4c6356c51a164414d082d22593c0dd173e995ad438b9d5254a3974ef3a94bdf8ec894ee467a9c4e17e9cf727ac86035e1be7e235c22c8c" },
                { "oc", "81d5283edc9357afa2c4254b57c7458c4382ad812f1f187d131c9ff0ea6ea7b2843fc613837dd2cfbad555d2e1cdaf301b82d864029a8c2708965b776f3064a5" },
                { "pa-IN", "3d96645ebf519d1fca26b5f29daa11acf9434a2d75e33fc29c2745815379ea61b86a078e17759b3d215244522714e1b43f6072f688902a91de76a5900e2d790c" },
                { "pl", "c46501dd5e15bdf13f2370a17af732aadd24f839b21513bd9f0768af07342eec3c77119fe29dea3ffba93bdc1f402f0c8cb3609b1627b58030f8a9bf43be1711" },
                { "pt-BR", "ff8e08d756fb39277df226aa0e8f600f0c509fec5ad96e82dc873225e233f43bb4bfa254cc17259827021ab5e9d92f344b68e144c1932ecf1dbfeb23bf3afefa" },
                { "pt-PT", "a4da66be8d207989707a855465dae8b39a695ca09a7ed8137d04f2ae4107a59e6551fdb62c138869e40587939f17bb7d536eb11e58462ef2d67368ed097d53cd" },
                { "rm", "f098a2888e104e8e78053ebcee436af75339c83de08dadc7e0638078232dc38df7c16926385f600666e9280b78cfc9c0b6b97f28c904cc0d9682f6a35b54ab56" },
                { "ro", "a1d509307ebbe09d9f47844f499849d3d38d409b7364e7a796d97697b23ccac4e06c9055f2098dd3f4e8735b8ef4e1d03b0f0a942bc7d6ad9859e80adaf927df" },
                { "ru", "1c2d8dbcecbfad6689b8869c4ed07d2e5c3ef71577c78fd441a14dd735a1e16a1bd8df3f8470990b663b6becc7d03a6a7b0bef697096f3eed6636df5855379ad" },
                { "sat", "d3b30834d3bc949eae9773606362cd090846511e60f13b91ee9c863a668d0d3c170176fdf6444063b41a320a60a0e4fb06a975559628b8c79672ede0eeea06b8" },
                { "sc", "f87dca4c3c703132284d6fe68d06e586fc443d9ed63f67b2bfd1596022da1670d50e68078f85d76bf9efb8ba5ca9c286a863edb3a0171f56f08e6ad3dea0787c" },
                { "sco", "ae3dda08bdcea85372f0fe5384ae8114641aad783be176038124e49afc2be1db0f41d80defe016efa2bd8905b73808943e592580003009a618b9a150651adecd" },
                { "si", "7ba42d9bfeef39a4b883ad8e3c2572c5837b59c4eb7f61b8d9360e084ad14506b5feff6c1458286bd33642dc3b62d239ae0b1994853a36ffcb2e41f86263c3df" },
                { "sk", "c8b65219ec95e5abc1069a7fa155c9be7a3d7df1ea22fcbcb0e271c31c8449030bb1a9332a7b4e0bfb7ab5633b09dd04e5cfe1b25fc42e420fa4703eebed5a23" },
                { "sl", "1d6a8317aea33eaccc2ae5f68e0b4c010d3fd4072ee0788aa7b6fa670066d54a72a5b60213ffca9912f3993cdd0da90e266408a174f0dfadbe5d1ec63a01c475" },
                { "son", "f375ee8c6666b28e48a1fbfe3fcc6849a123d4e8ef9c8c7635aa8e72257f259e77ae574d295bc64ce0a9605fd953bb9fb746a8a256703daaeb0cdbe1643f2c96" },
                { "sq", "8f0e714b08e4d0bea1888dd06345f6a4523d2b7bab93270c6033fe39b576bdbd0b9784970d8f600f990569da9ab4374399334914c1892fd61e814b392e8a422b" },
                { "sr", "395c319afbc54c66fe1d3708d92ed7ecf7dc8e5d66f9220974618603f22ef703419ffe094df6209a6a7c50766a14729d9dc86a1349825cfcb2c8ae95c1c9deea" },
                { "sv-SE", "29bca0dfd9dac32352aabc62c49918d14d5c52d7f3ea38131cefb0b3f336c59e1fe02691ef065ebe50e93e20da42d7d5372d007f4efdda2c245a1a1bae86591f" },
                { "szl", "f9b3d93f4fa439450151748ff9a9640bd0fcd940241363a275666a1ce136a02fda45b6316095362ac279e29526fcba97fa740750d9c23df5a4eba6e08010d53f" },
                { "ta", "462e9c16569843a77311968dbfd1f8d14d5b76d1697c26a155d23d7d22fd097167f78f53d6463265c253d2e0e87e8dcfbb41f31d386d396f8bc2c7a8ce4b7c34" },
                { "te", "132b8bcd7dd076670b7eb4ec6f351883233c2d9a19dd548bd205745b52933211f168e7464343ec28755a09ed2270ab31430998914ba6892fc3773536cde67d4d" },
                { "tg", "7f162797fcb25f6b8b0b3d8353f13239b3319c588da4713dfaa82e863298f97d0a20656c6aff59d9a04295212d9863b02367bffd7bdede1a9881cf2ccc744caf" },
                { "th", "4bd3df35fa305fa0622b627e9a6fddb86133a92d03fd6240b8d256239acbda4c06f7a185894bfc0152eb6c8d53817d930204514685f2fc22993e5b82f739eac7" },
                { "tl", "ae49d7f00158c02ae5ad378dbca7f3c4212eb2197e59247635d8d7bac31c678ab7a18506009970301b942df3a87a7274cc7cc742d91efc08b7d259e2ef06f8bf" },
                { "tr", "a2e5a0a1c331b2be9cf6be6f1cf40bfdb2c937ae7a8013103670e16bebbfb0ec795b74d4bdcdda6e1f2ef653b2b38c1e7f1aafee1f0e09ccde4da48be027713c" },
                { "trs", "21be8b5cdb408fd79a28814ee1df811631ad6c38540c6fec44d0bc9d3e3a0c7b9536ef7b8e13c7337478921833842628d67aefdd1f3012216bbd48ca76959fad" },
                { "uk", "88106ea6a7a0595d03d0c54a7476b26df051b3af2632b9b2048f52dc1ef0ba310111dc7ecc0e377532e6031e34be41098ac9dca75278a938d694bba4783b65b1" },
                { "ur", "dad3411b69503bf98ad0882ead98dd1c8834ad82568cd44971aa5be04a1859ae3cf718aa502863b93820cdf78548c057587e9f0f2bc7f7787b5c6fb461861f3f" },
                { "uz", "de83e3294628f6c7f35b620ca9b0fa1c9e99c656ea3671d886861190309812761b62d521b866155b1863b2fbb06185b41754d7b0e85ef0a41330239d55ddc30d" },
                { "vi", "9cdef3abb2c6ed22a3ffb301a7afe08044a92975ce7084cefa07c2c6b6e7776af434f915ef51eda4289dd076f642195060e2a3aea26f5d3abcc1326d6b85ba2b" },
                { "xh", "f1f5fe8cda2c842730580baac9992d767cb653bb8538cf951143281d3ad6927de410bc5b4714f5c9ca132176b58c8cf176bd6ec785794dad6a5dc9c864a1c700" },
                { "zh-CN", "983cbea4206225fd809f74dc5b50afbff21c95a02dd2a08e89af0aaf923e7a9a628022daa05ecd97009ff865989b7d417ccac5a3d70e8625465533a18ef5db15" },
                { "zh-TW", "8b9dcda2516150bbc59c968c8483bf5fddfccc60c26bc9abc87aefb9659ecc4731771eccb77120065802ef909c9f42ab63b2b04ef776953142dab1ef3af5c501" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/126.0b7/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "a02232aca4ee75512c43b15ba9858bb8eacfd5c4acc5a68e78cb7a598f4959797fab218f6497f78b0a8f3ec60f49b9aa020ee8c93190189e6e8a57b97268f197" },
                { "af", "5641382231fa3fb39e06aa0e587cbe6c51c1d5c438d21e6fdcc84133fc267d91855d2dc8337923d674adbbb06ca67d5f8871b0db094b9b76fde3d1be3c0bfeb5" },
                { "an", "8f5033350a9f3af8dade64b09bc8f7979cd45e1d20700f0e5e656360e179537cd27628eeea2f87c88c61e8c48278b85093751a13061c5771389138f0fb4e4bf9" },
                { "ar", "1d45618990d5f8e0383adbd0c5fc6ece65951fa7dcfa50a61a1705507a3f6d68dd8d15d948f011657dfbcb04510a3132df37aa661ae811c9652834500e2c3009" },
                { "ast", "1133a43f9ae4d98b6e3455d2ae549dbc4e5bfad3a7e65f2d470df293e4d08cb3d1e0bc9a089292d88978f8a441d2919b38cf64a90de5aaa1e0160cbedb359d51" },
                { "az", "a606a646e65a5a12ae3b7a081527369a227a6fe0078b63794f3d0831cd3c0f71ecd00c2dff0be4dae41c6e4283310f9c1b1fc734531a0f8d1a39b4683db7cc01" },
                { "be", "caa049749042b6a36e76fd53febf66df6ad4a08a8a83b91cf43e7af59da102385922597fbc86c36272d94de43c90d89770524fe7c943975d84f963607e0d6c3a" },
                { "bg", "b4dcb6bd0ace04227095489f7690b5951c6e47427bf6348eac686994cb4473078daa8011d4ed0c2b422f6d9f56db9ae22446e7e472687cd992df51f5f8f41ef7" },
                { "bn", "88ccd76db7906f3dd0067bae750da116b164f51082985334c1cf28b67d06413a99489d544568005eb102d906771d93f50a48bd66cff2ac42cfc8dfe8dfc7db03" },
                { "br", "84625d53b3792b04d2154bbe7fb5f82e224755be5b5422c3d41cd7cd2562551cce25860d8d3a6713f8f8e07f9da9bf746d3a0ed6ea21076e1375b5120b15e98f" },
                { "bs", "fe6bc1c1b7377fc720f97c8f9da333f7aae858e2529383b594a93154ceb4824c0e68e695f586f5f490a517fc61a400bce096b4cf99cee6d70e41abd62b6e258d" },
                { "ca", "ceed2fcafa843df900f715bab2c5f9433b63e1b522d17a9e8db5845ef31b938c19542801654776b932b6c629cfa2e97a2256c7e1885e52b6759ebc39d995c339" },
                { "cak", "baf757e8ae31662d3b3e5c135513fd1ce1c75cff4230da22f87f2709ebbfd360093c2c905a126126f727ad37f6c447936815d9719cf49ebbdade9a1eacedc65e" },
                { "cs", "610f0e76c8d319ac985e0c463586e8920dc177951dcfc5df54d30cc912f99dcba7bc8d3e9ce446ea7d427ebb6fefcc984ccb97bde9096ce607b8c0ce8b654073" },
                { "cy", "a07b0c5e9da68c68781c27316e7b5a7a45388749cc0b68d25cda424f9aa6e5754956bb1abe46c3e03bd211078f6f417b68674c5c212a98c8e5112fb3b1c21ca5" },
                { "da", "c1e406952885fbe13747e87d77a6855908982aaad7d36fb46d91b6d4109cf970b738c1624e3f8019d95c5d93f17590012c18572364bb5fdeb214e1dd04e22c58" },
                { "de", "b6088c8dbd594ab8ca9612a0b166af78ca8088b747171717a98f745badac213c4dc7367ecc8761d8d33cce884ae4680a43a582dcb045cb1234f8a9a814490977" },
                { "dsb", "4b23683b09f4b228eedca951374ef64975be8b5b8488bf9907532fd385aa437d10a5a2c99e6a5b1e2bec1d81094a1dbc761ba85183978a100e4092ca3227519a" },
                { "el", "d315b8006f97036a222f7f5a509bb9166be5ce0e766ec92afec0327a41cb6c78d31eae7d73fb24a475decab39cc7585f601813d140e03deb3e99494d6ffc8dbe" },
                { "en-CA", "6a89ebc5dfe6b7186fbb112e968b2b89900ea45ec3b6111336d7579a925f06f767753fc842968c1d0d438e5f3ab66326f662de90598a682835c771b09397c170" },
                { "en-GB", "22fc1a5028c047fc586d8c485c04b0aee8b90b002f4baa793ed566b5ce44c2de4ee44c52c5325e6782d9c82c352961d300e4da4d07eafab62f4878a7fe35c234" },
                { "en-US", "9832975798212545fb80e21225f19dfb12f1261986305da7417b9ce89c4e26e992c98bfa2ac234a3e9d34808ba65ed88dbf77c9bbe3f2f2c10d6b100da70d052" },
                { "eo", "7d610ff574d742c9358620f913162ad0e5931aaa3d28d10c080f7fe6097877aa3ee9a4d4eed3900de85b6538aca563f0f821893d4d209c39f44e305cb253b9e6" },
                { "es-AR", "3fbcf9af7798dfd67cb53ea6d71cfdbc4f7d2af37848c85c57ed8f795390acbf216aaff9c3aa85d1c324cb452c8981f17d5a7e86f537de9097a885cbd93a0a35" },
                { "es-CL", "6af26a489c0805a4fef30ef979ea76bc538599992b9782618c3a710f349ec99b0706800afcec50df451fd8301a17f6152ebb0e752a716d0fd8ab4cdfcdd91ab1" },
                { "es-ES", "a24316f03eff96ffbf99808c97fa8a3e483300781e71a8bcd75be9b4c287168fd7cc7834db1ab8492f2b32d9b7b60ef541d0967f43b5385c87d87b77ae74a4a1" },
                { "es-MX", "4813ad2fa926ac4998e3afbc1c08eb40c99c51f7818d3e8befd8a2576fa73bdbef800231c59ff88ec846fcf6b14c5829b65192e286557d1947ba0b083264540d" },
                { "et", "0c17302b7fdfc67019625797d076fb1571d9ae7c5ca5b7e7b4fee12562a4ebf8293a6f685221ba514014b9c2326a2ecd5950cd47990f7bc3e6836a45c5be24a7" },
                { "eu", "f4ad0f7d0848122c0282fde9f9f7fc6874f01d03a088bf4ebc73242b35da5b32454a8ebdace8382d2e8d8fc4363f1f20146436b271c2b2c4145e56334803a78c" },
                { "fa", "02902a11d5cd383fb856f5642fb63481cc87bc39e60a67f9e9e47039eea43695993eb4b96452de4ac230d691784d7e67df829835d683b208c498be8dc2ee66cf" },
                { "ff", "f30c8253a43c47d03688f203d80f9edd10d8eb4afb692172d50e5abc599103a3676e46493c78c0521828177bee595b65a1caf740ff5df12b4759fe4c4592a2af" },
                { "fi", "c6976f7eeefd530f3fc43ee5480c20bc476e815da7f3feefa36280ff4a91606d927a20ec9e07c986e71aadb4ec9a98cab0329241cab92b99990f28bc0e028275" },
                { "fr", "12d12d0a049fbc627ec86cab43caa5e9c571e34922dcedbe3b3efe551f9a0341952179e8f00325fb8af7eb51ff55e7371ed85b721fdc26dc8b189a8f566b5c70" },
                { "fur", "49cce3eb8d5a9ffb7e6fa422e6059fb2086e46f792de12e36d6b1cf10a65ff45cb9285a974b560292b0473b39cda19911676afe5a591bfed9b7131c0d23ecbd1" },
                { "fy-NL", "35d30ae1a472cc2b695be971a69f6ddd8821713b0c69d0a6a4fcb8f3e1a8dd6397023026bdcb0f87246f0b08b821178eac0650834505c43bd10791d5ba403389" },
                { "ga-IE", "21816c06626c4ca699b3738c3dfa71b2395ef9eafaa639d06fbf1bb164e474ea4154697388e172c114c0633b132d8a935e5c96d0839ab4d9caca1f8156416645" },
                { "gd", "923419ef47504257b44bceb64a57b8851419e55d663f557ac46461d5143110b351c22ba5b507b957575b1fe2e298359725e86f4b581d08b9295e9dcfdcb6e200" },
                { "gl", "6a222f9a064f0b8a54df33985a0bb905af6f5de87561d59a8b8f6487df0e92d4eb76bda2b07d85132ff91f3ba38a63400e37bd42f01d146affd2d0d7970cb708" },
                { "gn", "313cb598256f372dd1fae0e1871838ab63eabbf8b4f533caacb78f3f4a7d9cd1d2d4dae636b84416ca74b74fa93eb207bcc22d6e55188fddbb624d06f03c315b" },
                { "gu-IN", "826b2bb916e017310656f5c07c9ccf15372f875a47c49d25821a33f5a6d66b79b465d4a905a0c0f2fe0251a6a4c9fa2e5eb0a865bed461240fc8c08e77677e02" },
                { "he", "c6ab68e4f725c8e04a33c4977a49ab410cd4f974aa70cd6aeb51b1eedc94ade0f5a542931c113a8ee3cdbcc19d7d0840c1e3d2483c6a501bea0624407297f292" },
                { "hi-IN", "82f46e046b7a985c24501654ffe9e2bb7b4b04e0ee2f13de1a5fbbacf063af7a191709f3439151df9c7181a1be06d18678ebec22576f6b06b4ccf473d22b8605" },
                { "hr", "0917a5c322e16e0961e1268991254321cef22387772fed29d8808d84b96a2edfde9ae56ce53a445790c767c6178aa1683757e2d472612fe7e3e026f1d5a2a8fa" },
                { "hsb", "fc00b9f1d1a81d16e6e0c1ea2694729173b8de60cef11a3a295ce14ab07340aae9cd958b1566d493a6fb6cd72df107e17f55b60a56fe6410a349df24496fddd2" },
                { "hu", "2d7a00ca7536db50a47e016d9de3d514b582f99876953a24e19a21e6f2c064ae1d72b684d4cbbc8b3afa4ceba5792a79a4c614571267f81771a74dcadc4ed254" },
                { "hy-AM", "3ae293ac68f8d713a60a735ac8b816670361d16cae21e859ac464b1442132d3cb1cbdf35f15abaf862e4d02504757e197aa246619584940f18f094907b32a94e" },
                { "ia", "d46925e3383e69bfba503509fcfa89c1657b1f94f61d0da402311001b0bb741028ef71b3780dc3aabc96699a5148400533e51885670d5fecc6e082c1f2b796f1" },
                { "id", "3f2bf2353a18070ab455b1685c1b577c966c10fc03ff50e3a34bb9b38680cada383f8f7d0b8f60c9c449570fe6280e5a378a4c40ece5c9560238b08469e32c98" },
                { "is", "830c6bf3ce6847269d69e472219be61ceb79fec709577a8754426fa88f7c08cf517e5f56eb3633d9dcd4425c4064461dc3f800b33c30434a4a61b24fce23360e" },
                { "it", "f8235c590d6abaf2fbb1eaa7aa92acef9b3c6dce11c582acc282840e417d29941ae5630365cdbd49d6796e01cea4544963f600a48de780c3915089ffaa711597" },
                { "ja", "482fb1022c42f0a6f0b04b7bb533d67d8f42c7f29851164391de087a46eb6594b8f34e6fa93bbe417e0be38ccf4eaf6798bba3db893e35326c34fb69bfb0e47b" },
                { "ka", "7888bf77bd4fccd7dab7f55c775f479164835a8e6204e0f083546e21d676a038400eb46ef30bec8c3818f0eef7773a97afb6f2293d75849a379bdbf37e59f4c3" },
                { "kab", "6e63bcde60a8ab9b75d6e3734b1445e37bd54c8dfadbc399e3357bf7e0d4b508f44817591cbc62a469ebf0203b3b20d05cc2a2423819f310486384ef9c0fd48c" },
                { "kk", "c4daba9a33c5750f3008cbd3e4fdee000f0f66315c531b792587162e533e5cf36f1dd85bbd21b0a615eb6c552d3e6a1f2c15853cebdddc5a6bc5bf77993e8d9a" },
                { "km", "952ac50e14856c668e81fde25b0db420de55bc52bc3f29362373da0fb88061d0a599fafe0db4c5e0abb1ed2c10166155545dcbcdeb7a9a61b1950192015b9efe" },
                { "kn", "a4171c7c797c8b0358b46cc00a80257d370b8c8a58d70633930a5d7b62c2779700964e04852cd2c43debfcc9970477ce0bd73d5d394848e0e54be5bc9cbeb7be" },
                { "ko", "538d4c3e2ca1c78b1377807e93cb8ffe20e834ee0b5e3423a692715317a3d26f43032739ac31583c9b4fd671c5803a6ae35c12aa0676a4d9189569df06489a95" },
                { "lij", "65b660143ba1075d624ca810d6dd6683e77fb8b0e3c71fbcea03cf8295b00ebccc9fc761bc585e6cf122956a68d21e5ff6ef6fa821215ac6ad527e12d6145c2d" },
                { "lt", "7e75ffaf001ffd4c50e389e03d9a5b7d23db1d271452d1b426def977598fd4364aba9d54c0243dc13382e0b0eec6c929782d04fa54c84aecce17e21da3395649" },
                { "lv", "b2f0d1dbafd787603aaf86dbce94a2ff8d925f2e98355d0d8d3afe3b269151912c28654a18f9c111cabc381ba8f055c231bcb03ade8e2e95666b6ad98dcc5372" },
                { "mk", "32a4eb8d27a13a6021713c1310decf0c66f2a69c0ab9d026ee4a292a4468885a50b512e7b446c9423d106303c8f1bcc086110f40f2e6477f96a4c9f9ef830b77" },
                { "mr", "2df7f3bc65cd5e675fc22e524869c29d367d411b282b3c8bbf3681f7905ddb504dfb7b6f9a0d2baa6f37a5af364b9000dc26951ada0c7d372808d1c5770cb26c" },
                { "ms", "a3476465dc57ecd8ca7a4ff5a42338f3dbf117f853e4d2130752182c088f0a54d49579c97dae2edd902871cc753a70e9a58cd85a029c11f92971de969797878c" },
                { "my", "5d1feba7851c2e8087d887cd9ee62128434dde76a1929a5934149b93890be06014be216f9b14fad38755cc9d8eb32ff04717a5e7272966fb247c17278dff88e7" },
                { "nb-NO", "f7fe6751e7f7b8a4550f6c33c69052ca0a4e12d2482c78d711400cfe7f606b1b9b5f7812bf71c5002178748fb0845b540af05065477ef6a5f7f14b5f3c88a678" },
                { "ne-NP", "dc76b68498fc67293eb646eb55279479c67e2cbfc72bcfe6d63d6cfad43ccd7380be7d0464d9cbdb48beb2abc0779376c0c1946ff1bb907f299a311d6cfa3075" },
                { "nl", "00c16c2b7edaf1e784d9a8443f7d28f4269731fb74f6d55bc7149f41f457cbe8ee711eaa7d41d308d3e91892807dc0c10f3aad5478c1a6351c0075a0c93c9424" },
                { "nn-NO", "1fa8434b8e11ff9a14de4a19b8561e6bebf136f0570498d084ad34285ac70c00c224e7ec80d4c792803e6635134a41d73cc0982559330c776375f15a6fcdef35" },
                { "oc", "d9ca3fef5069f99a80cef338f01689155ac75e05acb8cb705e9548b226db443b4d3d0594b8e904b42896ef2eab255e1a382b2ff1482f95c1ec48039e92c2d8ad" },
                { "pa-IN", "f8e6bbead1b68b35a3043d2dd39d99ae75149805335127496cfd53874e3081ad97f9fba29d4f3258f8bf719986f3d773fad0dbf32e6dfd20406dd5fb3cb2c557" },
                { "pl", "c9a61422613694a86637efc151fe8371c6c23862c72a7ca9f76f8d58259c7cc6f5fda98c0d208cee97df89bbfef723a9e3ecfb114d84f5e5b67b237915f8b3dc" },
                { "pt-BR", "01e058c197c474c0901b7cc27af9adb9eae47f375d6312cafb2c0d1e645579ecf1a0db0bc7aa6d361c477bf7e283e738b93d707982fd697817eeac9a53723202" },
                { "pt-PT", "5a0454850bc1780bf55c8bcf85ebf4c614a5d11d43cc46dc9bed28a6a5ee9295670790d82ba9f372662c2fa3a233a0fefe8c0ceb2b08a6291bd7f04bd7ca63b1" },
                { "rm", "e6d9cf906b41a327fea652e11d44bf8ddb5396c8c6033f71e2e50b74a5ca75ad88744ff115363b7ba02c1520be49c9eec4ea483c46a4a6c539db1fe7531f8c5c" },
                { "ro", "872691bf30b94f5edb698a4313a8cfc81d9f41572410aba322b598a083a44cb5d8bba085c7c0dcab05b9bf964ae6deaa47247267cd9b20807f6c4d1e93fdcc5a" },
                { "ru", "91e9cf24b90ceeee2da1741c97245803aa8cd37261932ef3899f4e1cbf83f4238b26376bbc7c85a4f80d2306d5ab16567fe43cfb89c81a37adb3f765d2792422" },
                { "sat", "610e54ee83b251cc2b2c384e8c64e9a330b214c3ce4941c530de1242da9a504a801db35bb545172562755d7857ac092bf102b7123f72d3f5bac76f3ce070af43" },
                { "sc", "cadffc96cb475304cb88d94a480179bfd0d9c1adaa0985490378b637947d682ee447b9b306a67f1a7a9c6b9cb54c60adffdb0e2a8fd545190a842966a25978bd" },
                { "sco", "0edbca5f5818e5e3600d2c54245cb5ac2a3afa0f6e2c6256cc08d280acf31e0a16232bb7c3c63cc508b2dfed21a296c251bacfcd8a40764a36d4971b5b2a7fbe" },
                { "si", "6db669be424cf366674a0d636aadf6654664926fbf4fc64b941741500d19b2e9e1401597d8c629ac7b4644a075cb416ab7d4b1340f3c1242903982077851a2e0" },
                { "sk", "065a3af0a80c088e817347835f243b5dff3e435460d792ace2099cb05d634d13421ad0c57d1daf4b3c75eeab069e591eea3c0f67c1602f282f7d938f6674873e" },
                { "sl", "91166fac8f954e43f87a04717c701ad38a6b29af7404e6f77494ecbdc56d087e10929b01ae77b878131936b513b01d398e373d9f5e8a737fed139cf59b27734d" },
                { "son", "141db8c717ae3b151815ba4fd60763bd3de7366244e8f5823e1492504db7d149aa19a314138ef0e3a5168dc704cd5d5f4eb769ee51d1e32dc91c7cf92418d143" },
                { "sq", "f1126bb8b2655d761d3cf05443c5147c31c36d4e525b421102aa896423259c11fdf71b3bebcb364d7a96f56621e980af1d5b24464badda6d3329dce5c943846e" },
                { "sr", "e52679b8abb07f241b3e3880e6c7175d1760d7770a6db99d70e7c812c33bf845db31371721f648e4f4342ca9e3247c67b4d64d31d517ae80a05d364db65e0286" },
                { "sv-SE", "34afe347c195fe2644701b508f78ad25b19e55125252318fa37613d577dcf3d6e36901bd3cfd654e412f3fded65ca8f633c43a3073fa2d34c4c45fb1a2833ef2" },
                { "szl", "48633688e87d2010dfd259a684621263d2e2e31e89ca1674885bd4e8c02a1573d019b3dc04bf0291ce0f4cc09acb760cbb6cec72ceb552b87f89e8b33a94a08a" },
                { "ta", "0ea7a45497beba8c2e21a5026e1ad58da958504dbb64d67392e3c1f40d5eaa33169ba8eec172d7dbc292d9695bbcfcf964dffdaf93566dd3a0f039375a17a41e" },
                { "te", "12131cf9a54ebc92d9ed44829a628f6195f021c1dbdb701fc25fe2cedbaa076c18bb007e94fbf28d188b4ea524fcc33fdf40e826b410174ac601d75130ceae0a" },
                { "tg", "e2f823a5cd62ae6731f01e9dbd0ea3b1112a5c7d7a6be54d47e1535f5bb44a69f48ec2ed0b9ace8037c8a1610d281d6e6ecb69103d71da40896babe3a65f83d5" },
                { "th", "a4c54778ce7b75afd9f5f495e68f0d0917be63e2f3d3d02ffb0460ca008bc4ede398690532e25bce772bc8c48c1b031adaa4afd060ce6e1d32ea8b8c93b7bd2e" },
                { "tl", "8d99b82e7ab90dfd55fe1af6c4fcee3814df2b0e2f0543afb98e13080914852a25469b2b19ea265871beeeecef7b5e6b1a9544aafeae6a00de116c2311eef9eb" },
                { "tr", "150623b275ec4bc853c251b77862672c801350c167caf1e8cf8dc17e9467d16d1764d1b97cacf7408ee5a0c0be23299c1a5c14908ca8113d61c789859fd654ff" },
                { "trs", "e7148eb959497325fbf02210eb9664d4474b1833aeb292c5c45184029180404a908a07b2e9123f5c961691ab8498ca0a927a9d1fb088a9bf2a6e0c78bb9bf467" },
                { "uk", "d47dc2dd2998fcceed2848befd9011abe2271cc4d2f0caa034fe42533f75230dd9955bcb21a7d69a4958cd41f18272e5dbe1e88919f2a27ab974375a3d22ae4b" },
                { "ur", "37b7b0f51aa85677533e77434ef90adef1767d8119392d10e59ce00d43ff5adfca3a01c5359f11aa1e6eda92bbf3e4ad6ab2c7c948c0c015d22aeaaf2073e504" },
                { "uz", "77662b710bcc391edb6c2f51cc4b72cfc4e928f073e8a5aa45602de40cc58c092e89538f856f75c287a0c057e7de362c0a4da464e50bf6bb2fa36533ac6ee87b" },
                { "vi", "33b34840dc2ac10c1165a23c7570953fa1e5f29aacffc4c1c8f9f240eff3e0b0f8468e100d7228403ab60853b9ee7863e49770cced3fff20333f366547d6e798" },
                { "xh", "e5bfb31dadbd893ad4f0deee2cd4d6d3fcb0e12225c1387d748e1f5c297a000c9cf054e26e3653ab0d944fa5359be3f67e3274af3de082eecbd7bf9d56a99d2f" },
                { "zh-CN", "938a2431c70df6bddc6a3e067ac0c7c380dc25b926878b4983272c67b068f6cbffd6e5861cc7ceb24605d25325f4176d7693cfc4aaa09a8cbfd076ad448f5981" },
                { "zh-TW", "4c6f4199b08db2dc1181c278a59ae5139d6a8fdb0a710a6133757de006e149a3d437c1944df9779837df3036cad6b69ead01f09ba4259cb93c2856e02b8f560e" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
