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
        private const string knownVersion = "140.8.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "c00f3be489022b20ca054841498d8b3074675787c21525545c268fdd54250cab7836db118eba6381fd679f12046831a921433f10e7a6bc48627841e23fcfdebd" },
                { "ar", "703b166f8f81d8e18993656ad8c27389844934ccd2dd78e18df536c6fa304cea15ed01fafd08e3ef6bf485276c645c57060a00b4e6f18aa8a2c2ca614ac62a45" },
                { "ast", "4f3f2f902e48c33cd6266e9b68f1325fe0ff60dcaafe7ce5443650b2e69b5332d60ee03d23d16abc46fa7ba069bbf037c5ce3f0248d85f113c822f87c3c4d5b8" },
                { "be", "4ad9ef8c4739c2ae274b257db8c554ac120c35a4cf4bc14b1039eabf107138b0a3dad562a816aea3981aded25accd319fff85ac9711fab829abb812f7505f1ee" },
                { "bg", "cdc7589175c88a92a99a1318f9c38c1a07da482089f59c35f1aa79f0b26db26895ea03bc7f5cc1034455534f0c697dc9d13784e5af8a0ee654b374e9462e9493" },
                { "br", "77b48288b30a875f23e3adf5aeb7c2a86d66972bd4cee9b26aacd7442cc6a3b32117fc6f6bf34c7c260ad6765b4446db8e65c025ce6cca9d543d9255b7d144a4" },
                { "ca", "69228334c6b774a19d38623eab19f1c6fa81aeda413c7111c5ebcc83c9c3460800fd7ff778443edbc97e60eb047f2204c7eadbf83edf215b3eafe644a85abd48" },
                { "cak", "8621c27dc43184c7a01aa9ae1728d7cc029bb28647ac8173aaec63f5c4fee8921765d4f8411ac3fb1751712f553bed4c51bf049a547e4e9847bdb58cc8051c38" },
                { "cs", "f5bb936778f4bc77b524987ce4a32ddc2c9dcdb755d5dc8a952246ba4f04977502b0e7109caed2d51741c27fa0cf2477c0c09563fa25ba9d5a63fe3bf90c6726" },
                { "cy", "60ea17dcb79bdba4a2aef634c210631b17e9c596950e6105cc1834285575e1322c772d24899dcb0994a218269c4a387def440c637388e9905a8e6c5b52d20a9b" },
                { "da", "e3e3f5db8e9a14757544b829523a0fa78232c0111c9e3fb7669c3d14346047893e1a695c9fea9138e19e80653bb27209ad0c67f9f71c720b389bdf07207e627b" },
                { "de", "0c82777440d9278b80657b74ceaf41b99f2cefb62985913c3a7a43751910caa52afcb92ae7b54fc3dc28998a6bf061304879fb4a6625126243661417b459c74a" },
                { "dsb", "b2be2c226992b4bb5f5df566764e66d0fd1a6b03c4656b0751284004fe5dd513bfdd0cec673c35fa9e32140d70f51c8f2f5afcb3492c83313082c666b6d92f75" },
                { "el", "661a1c942b7d5e72c1afe0e0ee746c217f32cfb996ccb3790b7f8d8f00b2f1c49ac815971178c5b29c96753b3ce952be9d8f9a4721e2ab4b38c87a3f194357ce" },
                { "en-CA", "9b90d9a92c0d919ecf88bd879aa75796d7896f32fdacbc866aff0e0262e208daf402c1a6169fb0cbdfc67f1d7f410f4eabe48d1e460a33be2c889f80656002bd" },
                { "en-GB", "8c5cb7f43f58ef92d2448101523e9eb144536e5f3632dc12a6098b5328db1a1c74864710082fc2ac633d85f5df1f6a5b1c7b22451546a987d694beb3168bc90a" },
                { "en-US", "f3d83c6b92388d0da379e0c770a0c4b5d5e1be967223b875523af7c700613aa78492c4f629fbfdeb5b322909a3dfebb5d1629d243c750b8e0a1a3d9711e6f24f" },
                { "es-AR", "2b61480fd1ce36ca19e285311aeca1e2b440d3c3cbe2689d4b09d752a23da51d9ad0bd6e2695e265e553daf6b36294c7c03ae5e5d5ef4668d7f3f8e57e1d457b" },
                { "es-ES", "9b977ad96af6749bdf03c55c4a730d37c5d60070d1c202714ee182d35d583f03c07045b0b1e962d0f578f8fd53f376a72f7ff2595e994737fb73f91f7ad7194f" },
                { "es-MX", "38f5b4bf094ae73ceec8afb9b9241be15118f0a599b496f26c030025e24674030695793147431395cf7229ef4acd2b66915341147730cbd3e76b9f08275268bb" },
                { "et", "9b37a91d19c61301a56ca28072a74837bfce2d16808388e1cd4ab9389f33165fa957c03dcf3e5fec03693a7d523d7854d951ac4d59742c437826b1f6848e622f" },
                { "eu", "4db63ab10252850a46687c7f570e6100004098204d6b08a9ae4aa39ac35c2cae231890916774bf77700c1c812e64f34ca11cc1081650655707f2a659d144ae37" },
                { "fi", "daa9e8e0d172e5b813ccacce1f29b6ee92281efd55f838f98a22b0bc5d3609da668c05096ff2527421dfa5bad555dbd651bb83b524e6f00d43bacea7476ddad2" },
                { "fr", "d17898678424b199abc51a2cf4362ac3eae05a84d0c316f0797973372abcab4703bfc930207a9a11420fd0c107dd80244bf6b53476950fa921ed34be172dea12" },
                { "fy-NL", "ef537ad4a7047fccff52526f1e2aba2672c67fc71725e48bcc38175a24e72e30ef0334e4a0ed173a8c8a96d4192093cdf94ec59b56f0a57e012409026452375a" },
                { "ga-IE", "5146f3119eb6e8549a78b47e2ab25b92f357cfa5cf69eddc25815511a930c2da9ddc3f7c4da830e6c38a1e6a7be44ffdff4c63482687203f4094acc794afb190" },
                { "gd", "4f2efd15592e25b18c86d872527b3f71acef092b32545e86bb8fbab12b7b5b47beac0e85406222daccbb06031ea5a01f04e53507ef559ec4b5dd260df30393f0" },
                { "gl", "9da7d97b610a4d8c5cd9dd23d5a8ea18a8442595f408510228f4b16ce85c91ccd5aefed13b7a944436c6c21af413584f1e2d37a7a593fe50ae603c8d0b4683bc" },
                { "he", "8271aa3e3cb677a17db40c9fec7ee1795295f942e906b02d30b8472b58f404280c1a4c2143886aec552b67ff25ef03093005cb3d27e289409cb8ce689e5420bf" },
                { "hr", "320c0b42dc69b2e8040fa2f946891d4c0c3f4267d84b6a1964b04722a66569656d885f5cec179c053caccd4931f2fc3dfd2ece755cf8ad34d3c1b5f0df6b8137" },
                { "hsb", "0868fe9d02c56d9a1a14b14ce51dab824dd3c90f987d22b8ab6a22bd4632c55ced27a93d9b568786f5a99eecd4230120ead94e048ebab6c84c7b49d335b425fb" },
                { "hu", "942e792c709caae7e12f68281631b02c0b46ca1669662c1d63ec3fcdefb7b89127629512e29ee08d1a41fe99830a5c88a89bacee9c0f544a0037ff31085c81c5" },
                { "hy-AM", "5d0ddaa0a2e13fd685f4ccec10ccfe8ed255a54b2d7b7707f4ea40e5d428f2c2d7f58c9a81077bacdedc4eb3f021ddd93ba8b647f399917b047a66bdb39c5f6a" },
                { "id", "8c57ff1f7ed36bd2a1b3b795cb9550112e115730c71c8768c07cdf0ee062c9a8e20fe650714f7aee3afde15cbcfe3644a5679d57cebf285b107c043ad2a7ec1a" },
                { "is", "ed84c2399b9bbedbf5ad139fc56f44557ff4f22a121e4f8421f98548fe863ac409f8ff0bb80a598f42772af398c2caa421083c7ddcd45027738a3dd5c9b44da3" },
                { "it", "dd85dec44cace0c096c2454c9d24ca6ae78571b2b1b56433c00d85fdde354c36d84efa9e1db9ed8fa0ebc510c7889488443cf038aa2733c2cada9f63f2b9a3ad" },
                { "ja", "05cb7bb19e904e650d767c015500cd1f450c341f994cab035107997ca97ce2f1f408fa719c0e814027075599bd035cfc6d87b69f72d9f01ea03979f752972080" },
                { "ka", "ce8c0dc735231cce7ec94d18c76abcf8262092be2f5bacfe175b95438f35a52b80f8ce23bfbe06c5b5db3b655726a8b46043b8b7673d06d108e42dfc52fd8ac9" },
                { "kab", "72ea3d257275a74f13f5c9b84fa63996685549174a50a43b6caefd324e608ea826c364b036d631dad9b7c8740d12ae71a0f471ed6028ff30c0e968bfff54f087" },
                { "kk", "35ba34c4f6d0a517be87227e5cb7f4f94b3220b0362ae0fd65675a8cfd5b3bb55c30da9dc403ddcaf52e6a95f0306a4fa712031d0b6c6de1915103055ae7d326" },
                { "ko", "4fda901844ded3329ed7e7131337517c5041bc6ad7f9743f7bc57effb131502cc531cab4f61e5acf1f9110194e165fd34485a48291b63b458bfa92e71e9939c5" },
                { "lt", "e2c7f033ea07a5a231c08f4fe09826fbcc5cc53c8b2882d87ada9e95bb5bca725146e1f6a2b96c2f558bff62d8a79a44204db0cb952a9a984a4e1419901152ef" },
                { "lv", "b388a4a578dc52bc2541dc0fc6da43d1b4f7e13c4181d2b71781257ddcc565483034e6e75575c736b5357b86e6b295a8af9dd25d59136085bfd2a0547156d50f" },
                { "ms", "b6ef1c29542eefec1ad3289a09565ec85b313cb84a9fe01d2f18fc25337eb3fbf655d30fa7f8b6b17b9701110a38b8c11d55217c166ce3ef011090135712739e" },
                { "nb-NO", "615a87b699c6491e3764ce51ff32d5cf461244388d7d7fce5e0e1c121c238ad50e2c814523e8b5874fc5d92f451a06578d2cd43eb65855a23e3af48867981a27" },
                { "nl", "8a179d98b0b4e4155b947becf5a90265ab23e4a2ef85283a46a8711d9f5144b72d27ded57c7016a287ef821d9527d77e6895af724df2201ea209351e74cd9cbc" },
                { "nn-NO", "9d37ec8c0a99172cd15c28e6aaa62053ee1b13936a4ea20872751f9c0602e5b38c096903f46e0512720f574d4d805ad3780b0227c130ccd846a8e6972c0f75cb" },
                { "pa-IN", "71bd4a65dff7245fd1ad69aef1e7da36519147601a3f72cecb581a4f5aef871d77da669537a6b7fdca09936eb43b72893ef3a2809027c335109459e56c3e8b99" },
                { "pl", "9c098867da2696b267283b53fb39b2f52d2c2cd9ab37bc565c52c7006649eca65cfd4ecb223cbc6e38a60797ad8426a88c7dd378abceed1e801f7b78ae16c4e0" },
                { "pt-BR", "1a7baeaab8ca81df76391241a82469119fc30a63224cf98e7153ce1249268ff5296a799ecef1ee4beef780be39b5603fbc8cdaf8786149c0988f855da028fc03" },
                { "pt-PT", "f87f60cd7c0d22a73c4df7d393a1a87d178687b9fe3dd5310230a952749b01966fb1e515c59ed06e2b6a6f7e62f3b340b4c12010bb7a083be5dd02336b5af155" },
                { "rm", "c8a8f2503b5b7ee5197ea62e2bbae4dfd6256092f1a376eb2c2943338327ef7d2842aca43369c148f54cc7a79d0ae3ef794c4d6a710c3847ac0d803c8fb0e281" },
                { "ro", "44da1a87444ab851da2a48bf24d0bff7be9214adc23888e949e7a8a2da96a302a3db8e927cceb4acc1560574a89435e35e778ab497c4d52c3b27504ab5d6b79f" },
                { "ru", "735c80516ffc9aef3de689329bdf0ad4d7de3188c05227857c773f141ada9ed40c583f3c738b0e596cb9c0cf8e917c070f5fc01a9dd1fc725b303d3e395af117" },
                { "sk", "57fccc68b977c037153c4ace5c87481eab1cd32aaa1ebc9fdebd098d350eeea367c40b1739b86a7a0ab75d643c15a53a0d7e247f874359e71f4e812a986057d1" },
                { "sl", "bf94c62115a77431e53f9baef74a49f3327340a1a950d250e8b26f16eaa6a5555d81253d7830d89b66ce8cff6b512d2a859988d6f22a0e6dbc9552594d9073a9" },
                { "sq", "f70e951b9b61a8e50eee1479a5bf2e647bd07ba4b18bceed5ecdf5b7f5d2a912e33a2bafe4082bce74c4d57c4c5c598a8d0aaf5bb1f7b5c8acb20561557d339a" },
                { "sr", "ba46e371a9310652ce32aeee750879dab0b4d14ffff6ed31844c47a5d0d03ba28da06d6d92cb4ec219a020e52e9c6527c4ed07a4e091cdffbf406c180e997d7b" },
                { "sv-SE", "5c8fdc4c7c34a8c85b60ec1e4e54f1bceb8e54447986019080ef6754b43516ada8cbd800de9195faa07ef58c56740be6c555b53a0fc37743d5c995a0b1a5d795" },
                { "th", "52c24ab00267778e241ebaf573e3e18a25472d04c1b36a54a8634e61de5b35c1bbd386b2d674c6db43c460ef52614e4c58ae70b566dec851f1aa6146172c2528" },
                { "tr", "2abe3c4d05e2e73ba43c0a95e95b31484e01faed6d7c35f091f43b6dac82e0c470760d5a1c31e2f3664e5c73d3e05bb103b5a624aed417c099fa48bd458daf25" },
                { "uk", "7a7ca74e58e3bf3048beefa8a98711a153a596647cf935e35372cc693c797e1547d80d18f7c3e18b55f59a3cdc326c4d75e2902f17b77553d68366a233fa7b88" },
                { "uz", "ae7aa0530dc3fa64dfe4c5d2ba2bcd988f372c1deca0a7e92a3b838475acb0d1f51c3a1d552c7deeaf259430591c430befe05008014a6b99981730df5528d77d" },
                { "vi", "19b1afc889cb5e926e34ea87e28e8b82f1513a9bc7ff5bafa1cd0004aea091a0a1e45b6a3de157f884acd7b5e554b17a39dcf3d16d219510d1c3dc81a4eb342b" },
                { "zh-CN", "9bf3794cd23dbd07382f9c08840556f3d166b4d5b9ab1659a1fcd8a502ee8d28fbabfc8a15fcc0dbfbeda55a7c588042f1f14236dc3d9ad961b0371d6c0e1b09" },
                { "zh-TW", "9da236f904713f688e2c1a5344dae7ba52b8082f9af8e3b70b811adfedc3d63a24a19f326dcc3715f965b58677900b012798fee14cdaf4cb863a629dc4ed6af5" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.8.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "7bca73c7519b91f984620dec66c8f763683fe0b640089862e132b11ea5725657248911ecb914549424321286377f7eeb91f0a9ad2dbc758c360708c6e068cc46" },
                { "ar", "7a1fab8cdab0b0528f6ea5d83b14bf6d0947285de14c00fa741cc93d25b0bdf7fd78d352baa4be9252e39b0eaf60f06cfaadc5492f5375f0ef495766d847edcd" },
                { "ast", "428a0ade156d00beacccd7ca999df8c09f95e1a413f1e383f002f4bdf0d689d2dcd06e6d944e16c6a3f8d273375a9f3f817095c96bdd3de62a5ee17a8a4d266e" },
                { "be", "94cc487f7acf471b4af85a6060980e3cdd92677e4a456f58c5dbc6d521cc0dbe45f60f00d1138c64eaecb0bc70c1b6f1f880bd17e814cbb989807db7f04fa1a9" },
                { "bg", "daaf2be02156504fb1a28905e92781bbd40fb0d1de877dcb6b44d30696f20bbb28429455cec362b0790281bdfef5523d149b5cf0a7d03c8211a095db4207066e" },
                { "br", "a8c578db8869052ff506cb728c0ada44b30869629c7fb99b63ab1ae8e382b5faf39c5eb6ba8b8d19eb74ce7a20e981b22428a41287939ac99a7b16f4093e08dd" },
                { "ca", "cc1e7f5eb6798aaa76c09e0b6ce228f0a7a78d4998e524fef2023cf3da8f014e9a5e85400c55f774d585c90002edb08419e50b1112c36d584f4dff464ef97da9" },
                { "cak", "8621b073b29e08c527d0e56385968892fa07db996ff7f6c29a942157803c631eadbf540e3b5265ebf7a7a7761bed65ecec7d4c9b80c854fc20f13d378d604920" },
                { "cs", "ec9916b33f42ed2ceaab9808e9500f2d5bd253f95d0fe756568733ba68b5dd522a4c68664c48671717a83873179bc9a2a4eb4f552a4e01c930a645433fdaceb0" },
                { "cy", "1dff665de06986baa1d6ef57401a11a1062e7c26c112c59545eab716d697cd28632ece08e41c93c4c21a57dad8c8fac092ff1cb12050f3716353c020633b0847" },
                { "da", "9dd3648bd0816b885a72c1790783651d4996cdaf99d960b1df600d1194e4a81f68be84a78a7ed81fad5509300cb2daf8ad2829b38231c779dd1f33f9bacc5c81" },
                { "de", "0d03407ff309adcc47ddddd377dae00c8cfdb9fdb56831832e52b04bc46df3574866b36608dece9af78c3bfec56beb91e4dafcfd2799e1d7c10d1642d8b717d5" },
                { "dsb", "d83889f90580f8d23af9e116cfd9159ccba436c05b568611e570a91164d329ae73259722c5387a7d7dbf1bd3dacea1394e146a8987ae4bdb3054ce704d285022" },
                { "el", "c1cb0824d5793500bb023271368a9ac899fb6bd7f9a83746c736468a8d949e06db4ec0885a007887420791afd0d5d827410c17a087d22af4ad75b810bba33a09" },
                { "en-CA", "00e6cf3079e0d702fb7705100f8031862ebc6620fc2ccd20f181cbc1803b890a3e00033974c9c647fbb1933f23bf05db3f52917b55e17ed8b55821ccef432850" },
                { "en-GB", "7102f6fa7680c318d9bd03e2dd2989bf4ad3120ceaba14376de2d76388bb2df812b0e85c35d33d106f76629c05d3604690a3cd1ef59230f350067dc6c6e5a283" },
                { "en-US", "c9ae4614177dd0f8312994887ad7a476e189466eb236ad260c27d6d6310531fb402f32d65258237b9614cc3481ae2e55c35096e619af9c70168edbbdb51ff2ff" },
                { "es-AR", "feb42fd128f8b88f72eb5fe4d81b72b7f034c9c4724cbe216786c05cb1dae2e0d0362798709ce10cd1bceb819a50fcba15130e7268bd03d8e8eadeb4d10b20b3" },
                { "es-ES", "bae3372f34c08a97f26cea53a1f025db40980539ebcd43b6c66276fd5eb1239b10714f4dd8baeccd6b6cf488ac6c890892f4f64ee37df59a0af566bf13a81c16" },
                { "es-MX", "980dd81959216fd8fee692fde3a722e064a70b6afef601b17340da5efc11e8d880574c984dcafaf9a667919ca20bfb0d9998dc66be0a57d387568803f8674bf7" },
                { "et", "fc0b0ef5a845f3a0481591d80f5fd1d71c6467f31d4f8b3017c6e873e4eee5a48d59ef159119918d9ad86d7fcb2e2e648d80b09b95bcc2c213dca0d4d07b39cc" },
                { "eu", "fd0eaf0fe5c7175fd83c985b5f8e96e707261e8356f8ae60d87a309399c1ef49f6a797402d7212736241afdaece3136226aba8fae6a1d16737df1c56c35570df" },
                { "fi", "c1cea3ab3d91bd54d233ca3fd08637ff4a6bcef286f4ac6c0c6de27b098f5bcb088ebc761946fa77d88c6909a45d4952d01904f7314a4485b50119263fb2e1b5" },
                { "fr", "9d9a5bdd6dba0fc2e610dc0b97cec6090d15f6043ab9448413df17e37e0895f4d0fd79a7d8f56b4ef504f0c162fd8bd846a41fa43fc024c5a643a12f1b8319bc" },
                { "fy-NL", "b29a0b16f3ece35b171f53849c8a06590f3005dc558beea6b0227afac24450eb1f2723fdeb1758a00a8265febf46e5e383dde49b920341e57dda83591b78e9a9" },
                { "ga-IE", "48af9b2571870c2b7bf24ef4656a163ffe08391ae30a2b274123bfca1c0164c3bcdadb06d2b06a9609d5e4725587070f0cbe583da9f4775c3f601a77497c52df" },
                { "gd", "0d003daa47bc67fea8acb5593ef5129f78bd32fdf17f273f27fc6187fd2a2bca55a43852aad6a8211eb100c397695237bcb0632ae93adffd01efe080f62ab2d7" },
                { "gl", "f067e9c768f40ff0439f66b29495e7815eb93a5548eeda3dda2a444845b09e4314505f0329be17fe73b30fa6484af2d87822f1da9adbc2a229c50c41af537587" },
                { "he", "fd4359a48d19bc33952f860d658bd3d122be91afbc56d2fbe1d9a1bbd5f8508468f4502d313a4c199ee531c1063d7aa99bf91f648460cf38e6f41caaa5168e47" },
                { "hr", "3d31afa724519c4eaad4acf2dd360877bd536b408853a1c760e231cc3e018f056cc5c5ac0b71a5e9cc730cd237f3a2c8c4f6d5e4bb66dafb1f112f04300c59a5" },
                { "hsb", "be3556d22145f3c87427f823719e3b0095cdd0cd541b26fdd99b9198d4ef7d3beba69a9ab15920523fd8617f1f9ff7633a85984beb60907f14bd342b8857e749" },
                { "hu", "3a3e6779d6686b1c60506ab4b1cf4532575fb571073adcd9a4e72f33a8b323af216a38ad32afa2231015fe53f97dcc694a6c75720f3b3e0e8888c866a82a4c3d" },
                { "hy-AM", "b25fcb156fa16b5f4e95a40b6511a05a7d15761ac064a0a44f0d0559d46ff0a15a4dddaf480000ca934dbe93cf7472247179b6daf2ba1e28a8654a4b532ad7df" },
                { "id", "da02ec6af3f8b86dc69c7c94a093f2382344d6b907e176e8b54c587c2cd9eaa7b3bb1568b4997dcae24828779a7036955d766b822092b1b1b9f6b1496737a0bf" },
                { "is", "11429a021535286930cf45683ac06df3d214455244064e7f7eb73db1cf8c9935f99d61d97723a779ff4ea49d3dc21c2b6140f1e60ddbac0d6b97f49f34e9c9b1" },
                { "it", "66f4cdb3be7dd5cc020db4235ecf95dcc645a6c32c70ffec4ab02e34bd852f984f999fd266fdd4890e39cfee0caca7df8b329c4d9dde31fd8934ad81be08d22d" },
                { "ja", "1ec369b3e1704f41574f50ad662c68a463d465d1eea2eb5081db3cd5e7216ffffd5ac05c9ddb94f7aa7cc33ba40e627b16a2bef7b15c91edf66066cbf603ce9c" },
                { "ka", "6336b5dffbcf351f26b6a2ba894d08ce9842e1dc33d41bc1690c7b72f64263a9a71ec820ef744a49f4a80f9849ba16f9b32b13448913d85d97b04bfe6e7a54b5" },
                { "kab", "aad184de9423b305a158ba1e5022c8a04080645384ebd59a1629d1ef8a2411c72d47e23d2338d50a81c1c04d5bb6adc4f8e16dce32fb59461729a75556549bd2" },
                { "kk", "b822f6f9e522c5baebdc9ee35cd52a41a6e0e51b6fe36cf048cbac75fb295634250ef1febd02c8eaa54e9407dde3a0bf17015dc338c5bfc9f21c9e972fd31db2" },
                { "ko", "bfd5c9bc2f7adfd4e82039b9be05aa107bc0337a19eba65d515070cdd61a9bd370ad126eabbc1e85d7a7dabe52355bc6aea506d14e299072e279a3d36a6afde3" },
                { "lt", "76690ca683911da922af9f19dd672a3f1b3ea4ca4c1b3f17c13152f726c7fa2a1488168ead83b8b708126d5c08960e18c6cdb2fee826a726cc155cafc9c622a7" },
                { "lv", "9971f0245d51a38f33e147d0dc6b7fc5780c1230fd5c56e855872d859717b5b26fc3c5c70993a17107ccac867e35e2597c531353cfe9d54ff58a2e208e7cead7" },
                { "ms", "7f2caff0a561583650fab3f3374897d58c05da6c3fb8306208f3f3803d45673c8af43a4bec8c62305f3cc3f666d01c5b80aedf7716c2d0dadd5809068e7b74a2" },
                { "nb-NO", "4bba33ed68c76d93d620595ddc46d8eb2094ae3c6002abafc31b49d6416adbdc4faa46b31be37c16841fc1edce09391a149a8b5cbc585ea520aa2595d4ba6a01" },
                { "nl", "5a7798c7cdd0e489fb2c3c0db1659dac79c5f09cd4a7697e9695806666855582a61d8ab686cabc8658d899df1621e8999a94649a5e9a4140b4618387bb89f093" },
                { "nn-NO", "f3b82aae46d95e9704b2cb38e441b9dc748806504909e30f5256dfe7828df4bcab8a7c3857fa4874c366d343895350fbca74a2963d9e8219a64ce7b7ea860cdb" },
                { "pa-IN", "1d67e43886bd996f1c32bf301190f0362d07a983afe03b5063b371ae76d8d3428fc42dd86ae92ee236fae9bf1d76ecc1edf4cbe784d350706b2b99d244677802" },
                { "pl", "d32e5a08d1aa196752ad9089497d4881e503170e9e1e426aca6c3304130b745ef97831954f412652fda8088f7805224363572ebea9ca8979b6427d489dedc53d" },
                { "pt-BR", "f641788fcd64dabbbff9cfab251e1b598d750b1a513766ea4f301dc031b39e10b7ce098297336271ca02cc01dd3ffc1ef95e0a5c9cafcba998c497ce3cf2e07b" },
                { "pt-PT", "3b84f730267630a388e89a79c7d163384d7190a06299b6801fbd5151bb9a96592c74990962138e25c95a2c252f69157b8122d92d0b99b621c38d8bf054b0425e" },
                { "rm", "b5b328364290d708006bbd4cc21005a4cff8678250ad6a63b9b36e441ebd85b0c8439bfd1604814a73540fccfdf0b7593637f355a50441125cae05cedd5f05e3" },
                { "ro", "9bce1a1e42f9c5c4d27f08308d03069e4e74c16eb02a33501b35c9175757886460239aada388b3ff0c066c4df2d916b22e42ed72ac2137fef1f4ebaf7c1440c6" },
                { "ru", "5ec9560563551d62a2a3bfdd821f6688c78e8bd80adb97c627536447f3f21da28b43e41f36d5442cc98f996e751b31a52aec9ce4caed88252d5a0ba2a94637fb" },
                { "sk", "1b33beffea05f5e5aa36beb189ae2f80627c549a80434ab15f70843dc5412d417c2ab88b8f56b22abc07001b8943713ac255fa86872505bc6aeccbcfcf739b73" },
                { "sl", "f99e5f483ca31c4ee24894a67bf02b61713178d15e3930a8e3c1a80845e483d89b9790354cb4bf4ce0eede728dd8caf156fa81ee8fe77360901ebfb4355977a3" },
                { "sq", "753bdc951a3f431d78934f4daa085e64607ae12ef0b7dcaea1096d6a280c02b950d0a67d9d1923883ae85534cfa810c4d56735b5cb92c225dd94603e731e63ac" },
                { "sr", "4ad44999e6413ac920b2c41260efba5d3a6eb17841fddb7e4c034be86b8f06959f05984a6bba8a4ec60dde17959752024c2e5201bb9d17ef6e5457a8419d7e74" },
                { "sv-SE", "2fe04f7cdf094d2e430eea8c665c805447bfac2bb891f5b4fcf485291abd17f51272b45828bcb26a64fb8aeb0e5b2429f0cd88b838bcb6e58f5511bfe1f5af60" },
                { "th", "d84adc899f2416d5c76d296d74d5e25cce141e023a83b0848ee047cc22d719e0b343ace0f6d2e9fe22f9c7e0ca15cb7bad6b482a8022451aba1520aa10f7a5e1" },
                { "tr", "797c0d1ac24c9bfe0d51a1b978cb5497966aeabde73bf7a8c78ca62c369fabb21554b8d911ea142c632ff71d59993986d8c35d6213b99d08ffcff61b4f3b7a91" },
                { "uk", "df357a144c06ff81317cf70c175257beb28b3b803ee5733d6dd3ff7e5fa2f21293109b759c9c4c8c731c4163536e1d5f55c618424696f2b548c47a59faaa5244" },
                { "uz", "cee4f63f7ae51dc9ed38fa265b5b711b1b9fbc9e487debe0b4d9ef2a7b99e77d383feb4d241c53d8bc6010cefb267a9fa01a285a9159c13140edfd563798362c" },
                { "vi", "faec1668555c9fc99bfe1f9cfbeec6e266769b10a0b9177b78da9b3ce7edd9ef9d2b9b5d2d1f498c9fae09f7d63b61f48f8e00af3dbdafb08128ecad7972c962" },
                { "zh-CN", "62bd6cbc33686e1860ad067a1570f7205af9cadaef7f086ecc0c298125c459045e1da5f9019063837e61ceee599975f352f20062a345f74cdb5bbd20f0ba6167" },
                { "zh-TW", "1f55db8077e2d3c7aebfbdccbb4fd227f3912f02153620a896a137cb2cb318883b88895b24cd26b1c9d0ce245d514494900e5fd2e749b22f69f9e4ec41c06d0e" }
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
