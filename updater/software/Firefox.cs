﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/143.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5b60a64503db3b9c1eff655023c6ba1a0d4948ea2acc952dd0c73c6d7691d09e99fff703a0e07a490ff4326d999b66d79b867b2dde02d9c6f68edbfd074f1508" },
                { "af", "fbce0f8e46741039718cff0d941f4babd00e0ed237dbf1a01fe3bd0e2992beed3bf88aedbe56b2df443dd2b906ea7331e4171e908dc4c60ae1d5dc1d58b2ec8b" },
                { "an", "0fb8e1d0a0ee8b265166214e9d4c8843e54c66626e5a1f59bca6826e783e99e7a60d85728b113da7f8490ed0befc1c59f243e93204e41ed991117279951e416e" },
                { "ar", "40d3e53ff80c46594cbe3d826e59021ce66aec3ab74b7afa26c7867e26ce26fb9edfd2ed16ff2333c780304f367c6716dd1f71fa01d25e154eabb4749da1a667" },
                { "ast", "f85e73fc5e1e04bfa4bee67d351ffe9c42a41e0671352ef76a6a9be8a06759f8da0bda000ab96891826227b941a1308320b99d82bbf93360efc65c9a1063a907" },
                { "az", "c97008f86f8f6374d922e58399845ff9ba26ec707d88c54f57a80526f530dffae225a3894aaa70da8c7e9220c06dbd965578234ee28eee11cb6f8234bcaf9001" },
                { "be", "42ba7183ccf8dbd8c7f83e854db236570983efa2f3e6e2f3195ff42ace99eb06489a13dbdc3598f339ba6fb81289aedbdadf01d8ffe7a5e1bbe18a7ba4283fd7" },
                { "bg", "85ca79bfea47d4f6c93f0dfa7ca693eb433db57d2e2dc6eebc71ea832595308171935633e33eb9dcf3d88737789d73c1384f9efcb0e0baabc71c8590e7f2958a" },
                { "bn", "f19d2540b3979d6856abb3fc832ac5f856da9a507e24aae6815335100cbc9f0d7a534e6e556f0cc4c55a50ad271ad4a9ff9520f52d4da0f3131323056d16636d" },
                { "br", "fc61c1040b07f865bbf671451c61598c18a540bc5aff14357f0fc237007ab4772318ec370a1729c5e0d9117eeb745900bd1f9a54a54b84369e7419abcb6a0bf4" },
                { "bs", "4f3e922b6f273d26019dcbcc046f9aba8d5301ea318fdcac850508e3e65e8b5a28c08ad4eb1699781e88f7c15c51a0766b7adb3a9b8a9697c86a9977ba4903ae" },
                { "ca", "97bfe31b989007f3dbc393dc1972080a421c78f5a8822eb1d071d70609f6f7feb1ea617c0e6e9d87615cf1b2732c52984a6c6db2f6b39448a2f32b68fa26a267" },
                { "cak", "85297390d87910983f8be746defc929a1f2379307c9a50517c122b4df72c3f506edf28ef089bb0e786fe3c70033ab1f9b1bcacf9565694b1c4d599ec85180143" },
                { "cs", "47a0044d83dd26793d5d0af5853ad1515d478946a42b93381f5ebb158114b0309126e2b72b6f00dd77db29ab78374b2950d97eac64caf880fcbbf53f23265249" },
                { "cy", "49a94414bd8d3bd290dd19c05efa14a17f017a4b1278b581896d1d619945d04daf5e521fa6fefbee5d9aa6b4aaa2dc5815305f18251c4fdbc15d3be7ad78f541" },
                { "da", "d2b40094a254cc4a8fc7f09bc34d42945960333adf6f56681bb962b2aa92c606d3ca3af45031a52cb75e71cd2326d49659f4aec445d8930c683fea5fe35166db" },
                { "de", "2c65c3b0a2ddb3667ccbd2be5af20a825ce974d27d7559905f73bb91d2244b7b08db057339a7f424f2899cf551ba02c167eb00e37cd3474e2422aae2a73f5c2b" },
                { "dsb", "93aa34e095d1091cc557229acd8a9e61cd292cbb7d2e3dcd75020286e86222b9d906efb7bd776622170e4a6097963734c92c989a991cc48096ab26f727633ad5" },
                { "el", "070a5de51cc11b54c39ee1853aaf95b4aed01e37193bc91e3c481b94aeff9ffadbf7cb8ade1c302298ae6f16516d8263a5d7fcf556b3b0518a38941a63ba3e0c" },
                { "en-CA", "6e6052daf1ffd6597e2a8066919875f47fa2f9c1ec6aade609c1043f354534c8a28b80240db1f2b07a0b3357422dd34081efcf22aeb4a890b3623af4258b5bb1" },
                { "en-GB", "e5abcfcfd023eb96d5695f73d0b1a1d927da2ceb51892d8eb9af032fa6d2768d45d5da352d9d324f692933d296155379bdbb78a64e51ebfadd30a9689e9c7a79" },
                { "en-US", "d824054193f1f8048cf7ad905485ffc2f14f0cb3c53a82494c4de505b79906bbef996e840f48bbcb61adcf77f3f8fb38273463c56bdc6f319a784dfa004922c0" },
                { "eo", "3e56adc5b5d3ad35fb69bd98071902dccb5e8df2062bc4a17db94a0e4b3ef5b7ed9326b991cae7932c07455ceb0326e7a4660e7e1ff35c2a3e701a6d4ed300a2" },
                { "es-AR", "8763cb6677fe091a902bb7827adb2c16b7aefac6a8d0965e42b207124d878910a15395bbb15e912360c767fe3d57d3071b15f9204e27487fb9beb338d88c1884" },
                { "es-CL", "893d5504eb1687b3406490bc7eebdc442eb71647580dafebb03bc32719527ad61a8a0af55e50ebf2842849dc00bb4d9175e547ba2ab67716c766d177ed63675f" },
                { "es-ES", "6f0f28c4e74327bd4261c630d22344702d813373bdd37405f1da780b7e1403c1adf21f62ed0f61994b026dcb0cfb8c99e4aa429e8c091dc14f10549058441f34" },
                { "es-MX", "d3c45094b14f6b24004b09f2143caf07df79ef1d5acfeb94412d23c94f9fc7fb11d9140abeac9c61a1b8cdd65231db9d303702de69a255e8d06b74de1418cea5" },
                { "et", "ebfb965712dc2ccfe00ee18687849dcd4ba2858ee36a1cab0a51eeb1f5ad72f7fdceee80e13dc1bce336dc189f88917c9a35451a86d96b49773de9287cc96366" },
                { "eu", "32cb223575346866d47078e11a8f9520122284fe2158290cc208ea876a0796d774f4053c9d4ac950361ddb961b1b6b0e714498f144f0eb31e77c2d5a51df816e" },
                { "fa", "901fe07b6b733fe6a4f0971333cfff80f1882a0f97024d3f70e384395b5df958b48f8011e568011a938582a7f1a708d96bf6deff05328b98adf29ab0ae27383a" },
                { "ff", "401b79ee45b1868b5ff9b8524bba6b1bb64ce75b51fd73b62d1e56c0db9a72f2c290f1790350be0f06a46a4cb45b4488150be720aa0a6da994f59564662280ff" },
                { "fi", "571bc9ddd9d8a39bf1e4db0532545a42638b136974868cc19967d40746eca973f8587a87ed95d082bc9513e312f293d47e68a6360719ae4be8e4acea3ec02fd3" },
                { "fr", "ae272926f73fe5b0e5b5a9ec1fb62f80c49d3f7117ed3d762170cd49b529da9993d47dedbd8112ae2bdad23d9aab80438f57cfb27cf7b1d10ac42eee4cfc64b4" },
                { "fur", "f01b0a298bc6e6e3912d477e3c1a96d5b96e5211fcd471aef50bc9cfdbeee55752160c9a55f78c630f6b29045cad1ed3e4004e886a0b111f0c694fc62a914e54" },
                { "fy-NL", "7481c193394da6111bd6936375d04b6125647f7d98c844575fc2b5884114d714c01d72c51b89bd80195b7f583ea697b177dadda2efaf00ff253557bf75fb8fb1" },
                { "ga-IE", "4b76a8865d1c67c66c48befc12a7e20868da2b7a3410fff7296f477764f6a57e08594a119866475c0d497ac0d95a0e5c5b44087f89b27eae55be502f295904df" },
                { "gd", "188d399446f3c13ab25993e869a79a3ab7ce7299e8420ff58fa9689983135bedbb82d43c6660be942b553b1e264a3c7002ad60272797e652b7ae0d428c7aac22" },
                { "gl", "55759a14c9a9450322bf3b9c3200ecbed7aac1d334c8057f3680dcf7da81d4e8769fc25dcf561361c987c39d9a97a4819570c59a55852d9c28074f28e8aa3053" },
                { "gn", "0e198e54c9b112787355d710a37ba37c0e1bf3b4e32f9d52326ba1563b883cd4377f1f20b81b0a758c8b44c6e71ccb6bf331fb83ce383b7f983a0944321cee72" },
                { "gu-IN", "3209b4ef28ca83b8cb8f8ae982c7acd8a4e21849838b00cbfcba3fe910d1ff744d0f599c66e934f3ffb6f97d69892a4567b68b5f89054c3c3d077e426008534d" },
                { "he", "2d1658869560f6798f5526e574302cd859606fa92396e8a7f57dafcdc8c0b8c7dbd9329c7929e7cd7164b1029d5b0123089c9f2cd82428c4b4234cef2bc7d4d4" },
                { "hi-IN", "a19d6c4d71dba0b5825153022198c027b9be0c4a516642688b290ce1df83eec76d15e49f063c0964d72f9548d1f582b6470ac2c782e092e121f42f387833b842" },
                { "hr", "8d6880b12013b356f8ae145be23d82a8c36682233b9e69a51e9933f83399c4db73ed0f43a771f6ac58259b5fba33125929192940e826a8ff0357be7cf3129c54" },
                { "hsb", "d765879db47c341baa8c6efab332c37c07b1cfce4ede35c010a75ff2c815254e36bab7b6bd92f284d7dc10dfebb08120fe774a6ae486f02890daa10adb8c4961" },
                { "hu", "e9ec8cb5e798abbbafb1616e8cedd6465111ebf11729378e665777bf938f8700127bc8cef876020bad6b64cd053f1d489fd77c750804bf20f7e02baa9c65cc35" },
                { "hy-AM", "a5770a25b70fe04dae24ab47c6378e7fed356801b6c0775f23c31d1a8a932c3101a7f2b75584debf034afa05e057bf5eedefe3e167d450e46ef3f7d04b8527e6" },
                { "ia", "6e453c9731a0c9ea2570559173fae4507d0f13ece0a37b5825b72ba4f045f528db8be1ce757444e4546a221c082d5af0db6d6126533797f28d2b455d2cc3bcae" },
                { "id", "cc0d8fdccd1a88363bc0f411eb2211f4a03207b4c6881369bb13af7017939fbacedfa5f6aa67febd0c2bc967a65da5271c01a5143fc78b666c72317c5be371a7" },
                { "is", "9aa3dca2cc6079f3f4047b073f1e548f85b483573207781ea9aa298ce625b84d9c3007fa92069f34961cdc5021d2e3899f2470f391e1b7e0678384ddd4714e55" },
                { "it", "d22a3a9fce2dceab3ad53bbaab77b8a717e3fa8880116ba2c1dcfef7679c883215c57ee33f4ba9ab296a3e63be9cf6402d8dd5f701399ade55d60ffdbed9bb6c" },
                { "ja", "092354c60c494716f42d2e8133b0334d2d32d5b23beea182226f86404e854bd1816d7eb40f06f6308c819bc8ce86265f6df9448e1616afd6688505d1f4c5fd1c" },
                { "ka", "e0b4ce77c9990a5fd95a4d3885f30ddb6cdf72eb323155798e50f11d414c8289311c4f280087f7d7d1dc866b06fbda94fd868b37c009689d249757e3d70a497d" },
                { "kab", "33c456a21d8f1cf5f94ee3771c4ecc3919676b230f816a0bf76939629ca5d59008e45816991097dee1d6eddd777e1b0da9ce88efe4fe1a6dcdaec984117cd53a" },
                { "kk", "cc1ad5e3d9613b3c7f45b38a0d71f39d7e89a0c9710224cdffc19e1cf03d94456039a22a70ec2fdb912356c387aa1ad0956a61ae7164f4fabab90a4bd0974ad9" },
                { "km", "4cf5934d6c2e2700878d21a049c5ce028b0ccde46b97fa910484c22d97d3939debe2d72313d0757bce3d0a884d7036c951e80db148919eed2a6e4dbf9c5d07e4" },
                { "kn", "925e228eee89ff787803132759304d71d61da746af59152eacf5a2057c8ee9e22d1b23deb850b5c26ae61b2794e1a67c7c16923fe4bd7c186276794deb617c8d" },
                { "ko", "23abcba1ef6a7accb1bac28485fddbc81a13d0f2b64dfc61551a4993f6cbb56d6506e310e1b867b8f9559ef35d8718a6a040b143fa9e6446fc0bcaec228c7a83" },
                { "lij", "6f5a3290ac003085c2e2b67a48dcf709462f04157c8ea167a26bed9debcb3bfe0ca9682a0c54be29cb199282ef092dbd8142b64dfdd49fb72bf153ffa9c05f19" },
                { "lt", "5eaab469f0356083ad9bec3725d3b4b79d32e22299b2038e5805ec70f22d918f7f56eefc41fcc35d908d6bdd2793bf99f68432e66e096ccdf654749b1fdd99aa" },
                { "lv", "8d9dad22e80d455178886d12facafae33d58655f71cec52a2689d5ebdc51cc1a6adaef978edb4100298a7dbd59d113019c6de2a9a8b88638f84f1da0de309324" },
                { "mk", "798374f541e75482d178f05a6fc5e6bf877f333c6c9211f7bec6455f1c791831840409911a0d668a7841da850e837e842956a2b061b6c6fe83ebdc0f5991dcca" },
                { "mr", "c03e4abcbb07d58435e957cf4559f61ad361cb40ba3bffac01fb52a38eb8f08fc3cecbdce3907e3b8ad621962bcdb606983e69d5a510779538f39d318d1e89c3" },
                { "ms", "7bc02c8bad79507bcdd127ddc54346ead69543f6053da971e46458ddd02563a940dd5361be95b86a12a926fd722e92dddb1e395c13868adba8c3a18c6167a4b6" },
                { "my", "1e41ae9dee9076dd4c92cda638aa11435386341dbf1f51096d224ab3b0fd4a3e74ea99a8b8ce9f063f03ac5e2e42a08aea48a66f1df9a37787bd0948ca68642e" },
                { "nb-NO", "387dea51093e803825250d8792965688cd061aa67066f33a99fad20e40de6e667ce19e6627fb67210d2fd0c3520ef255630513236d638d5da0fdadfbc8803ef6" },
                { "ne-NP", "d6d19035efa68026129a804e256086a064c024bd6ebde37a6e2f469e75e0394afc39e903905b2ea88178c05edfcc0c8e8c7f8054f9400bc1669ef6deb13817a4" },
                { "nl", "350e29699b860b9188cfa1c8577f305ada9b110d4359b8a117d8790f20795c8f2806afdbaf6bcde4973b82e1391923b7702a96e425b17bc888e73ad4f3221855" },
                { "nn-NO", "26cd492399a1b2758429d64f7a5ce0077a6a6445b6a1761c4c714129bdfa29146d6d0649dc7e067bbaaf984fdf51edefd49be3767ae3488e117258a9bde9381e" },
                { "oc", "8c96e202e44d0b496136f8fe39b0e32b3184bc16193cf51bc80ee4c4109be1327c818ded3db06283074dc2bd8cfad16ef9472d6e6971d0c932b5ba9bfb622efc" },
                { "pa-IN", "e0666899d3efb8858027f46a0d1c6a3d8b835d870344c6fdae431230a34b45f51ff75ef77ee1f343cc2859e9e971220c0eaaf312429fe040c7e66b1c3320b8e3" },
                { "pl", "6c6ce5742f741597b6d628594bd50122894c33cc560a8de7e628709de1b7269c820125ae5dfe90acff7ef380f44a1dcb8e217f0b18f00d0e83bd311d0bae540e" },
                { "pt-BR", "8fd0b1c6e3569ab102ba01e407575cf26cbbde39d960c71e535bc10fecc36a23f060673642d7971ec3900a9f351a0bc681cc7b85f42beaf701337cee65d41bfa" },
                { "pt-PT", "5da30c1589c2ab8c10d54d23cf9bd4fa144a547effc2f0d71438510fa591cd9c718bc0bd73479c3447599af29fc704f3f3b4ce8af19a0e78f7f00cddb4c61419" },
                { "rm", "4ba0459523a6077f84972b16f70c31aea3432869a8b535ec7f86c8502416e80487d754fefca3d2baff456b87bedba496b4ccc539bd15916e2b33843c7f9070c4" },
                { "ro", "2ba45c4ed749ac0ce913112c5d9e73afd73885e55235e73fe6b4e73f30bf14dda9e8de9ca62ffec4a85f5e1b060798f4f5147460d068d03ed16d78030ab4c132" },
                { "ru", "710df52223c9eaae1c31dc7287e2108a0389ab29ed5acb2a01fabba6b9dc8e1071d522c1918ec50e866cbcf383f9e882a901214e7fe8c7f5f1fa3ebc873a0b8b" },
                { "sat", "45f8e17a2e88b2bb72123ece132d29503a7784bf4addd09480f496c8165e726f265dc42f01582785deb9b0e495e56638b07d0c698269f7f340705d466e517f55" },
                { "sc", "79958ace5b4625dd418fc42da0b824f4ff82f033698ada89bbe951f8df32a86775ae3e346375ce72e601e4de9d5fb5920c09d777054fd1851219c3dc26c4cacb" },
                { "sco", "d8db0a37c884edd7bd5311c1efcf723f7aae962c99012400219b79e86e00d9ffd2c4f2c8167cad983d9e58f71e7c2ff2285b8b3f62ca02f482f24f76747a484b" },
                { "si", "474d2d902c43487a6aea0c5ff9e7cfda06708184e44d1c092f5d00e22dd61da5f4a63db9913c4c92b519cbc94c010f7f54b5fc521d0bbacedf52d0a4ea8aad25" },
                { "sk", "1e6f9489cf8d633f8abb28065db03d4177c65d84f01f39b0ee0f01068091a776fe81eb7e1f99930fa8eb89fa887612f33021f1773a3ad63537fc77c6b43172ac" },
                { "skr", "328fce316c59bf21d3cf034bf78a5fdf19a0f97cb1c9106266bcf0f8eb4a619b4e99a6aa29e00d60b6de4f7899e40941e78f05035b932b7a0d365e9162c3b86c" },
                { "sl", "cf048ea0c00488c830354019523d8cc8dc7b01a5bc331ee99362051276822377e8620bfe41e456b646285ba0e7c0e6e7012936978a05da954f2e87c5413e6661" },
                { "son", "588672d0c2cd5ab4333c6dc5733ebb52c98714da4a44d9a88dc42d037ec247c38c1fbe7e4945dde6ce7359977e15d11ecc41f284cfb27cd2c10d2fcc420132b1" },
                { "sq", "7474936d1d95418e2147a97a4bd76d437618bedd75dfde9d4de5239b9658918a99bc187093ec9a1fe3fc52803a144e38ca205395d15cdd7885b137c81f479a84" },
                { "sr", "f83ead07edb6e731b46ea987a340bbc12fbd9bcddb363ceecd7bf3ba54d5731f9cc595ccbf63a962f5b014a7d82cb09bdc9a23defa400369618b5362e6e65844" },
                { "sv-SE", "145ed585b423934efa1cbae9bcb7bc8024f8a41dccb241d62ebbb10ba342d56464d0f2c1936c03e64b495c4e833a5732ed94b992ae5d45c5cb6d16f7288f0fb2" },
                { "szl", "56b0f38c5b7abc48e754693e855c038af580fc7e2b425c001f2b5a8e6b552a7c19e7b02f36776ec1aecae78af170b684a70da4f58c9b5f94ad0fabe407d90452" },
                { "ta", "7fec27640a432b19fb71c7bd208847186824dce84d434f87860f28071d2aabb696e9694bc39e11575b1cf04096a6d0bc03cc0bd38b260ca196ab58174f4bfebf" },
                { "te", "8e7aa37c5088ca12272bc29aa3ce47eb9116c4540c4a63ffef156d15b1afeb3e8fdee19ac298cb5cbb1daafcea5ec4433d2097de5edd4174672873d9770baf53" },
                { "tg", "992b22a3ef3afff446bc6b0e985eae3f81d5124dd4540d86e266d38aca7f13e7042bdf885bc8aad29a50a78d6cb3a7c423e73c4db8e5712bf2b053dcd691b816" },
                { "th", "6682dd7acf35c6a4c41c0bfbc5798a254c4ec9b424cc23bc6d49b0f8e5dd8a4972909243526cafc0d21006cf5a5258abffa56261ea62e392425dc596fdc22ccd" },
                { "tl", "7c3c1b606becc964581cc7007b208f2dda356d5e6c3535bd21b9e4b75c1568f446411b5f142be04cb8ef65d45dcf2e7730b3cb97e68ee576a48687ed0df5587f" },
                { "tr", "06c4a3a45655be82c01a892d7b33b0488eba8ad53e03b94d913b3ee1ec99e2f51d3a8bffbc98e68511619adbcba37dc3734ba59ece6c3dc355766c9ddd4ac43e" },
                { "trs", "dbc7ce4f4bd80f40f611df032d78a1b0b445bc6de378233356d3679a4b92d80ea610f1725b8ecb1f0fce4b2aa0ac27f6981f78fdfa6cb53638dc683ff6fb019d" },
                { "uk", "3a61c203d4ad2567755a8937bb00031846776a1577e3e72e607c8fd1f07885e436a7ccfb383ac6b84af69795fae673e83fd232ab77fc5395eecb6ae23130f649" },
                { "ur", "144676a006264cb5336f28e31c788ad11cef381c7a6983f87387165b142b72982aed27f20a5340b1ce03eb1afede840b4c6d5e4231c7758118c4d09d014f5e2a" },
                { "uz", "07a49ecd7e750f4fde961bcf9fd8a2b0f605c0832e4d602943a7d8bfccb831133db5c7748f3ba0db65985d40eb7b8ce2f77dee768c37e1849f1e50dda410d2ec" },
                { "vi", "334cbadbb944bb252a857a1113384cc98023c024393bd840681fbaaae99217fd06bd5c9738ba19df23a344841e46c3097410bb1bfe30ad8036a738066f5447ac" },
                { "xh", "bdd31ae674f2b85862f0984992287edfabc37ed3c5415afe391e37c2e994b68060f3f51acc0a961e434901e22c6b30f089d39cceaff8f30c9b0ff3d6057620c5" },
                { "zh-CN", "8c535d09700b36f864fa28adf1391bdd86b80c83e32b1f5fc14964ba3f009d2e3eddd6c3cc4b6ec74f45cffb7b3370147467c9d3fa15c9df2844bf8ebfc4bd39" },
                { "zh-TW", "a86caf8533603f019f335e0a2d9b6ae168acf99a9f9a788035de75003c621ab2a0c60c9419f010275842a7e1084212d1719c585060577e98255970e0f71cc1c5" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/143.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "844a0d069c90ae07cceecf85cfccec8f866047926455d8e858874283fd5001d97e6f73a59fa67cbbd2a442ee61864cf037faab4a0af0b543466eee3dff007ac4" },
                { "af", "54e6cf80c9962eed342ea41f9aaaf7509ac0433b395129bfe44cb52043eda6104dcc8c10e1cf8232c8ee7be2b31c9a4a48c7bb5ae37052f4f7d2410f6a723d8d" },
                { "an", "55010b5aee6fdc62976adaa4d435cc4072d0cdfcc27c483bc541e53a484793d3dfe9f42204def4be2884dbcc10a0e5011da50d898260e3c0d60fb07c208b03e7" },
                { "ar", "7bcaa50608fdda3363c8bd498445432b6665f75e028a45c09a3c57b30d57972628220e8b6e96090e3e03e1d863d3c4d2d4527ef9f1a3defaf03e9d4f055375a8" },
                { "ast", "34a1de2302c8f582e20615e6dc8cfe746f48f30d60bea9e5adcf65390473f59bfd7906e48b7da7d59990aef4db2bd4dc27bb55a838babd2af998b25c43749188" },
                { "az", "86dea7b7b3f343a923e5775b6a33fb5942ca1c25ec0a2e5280fcd216be34151699bef7cfada8ab1acfac3a225bfcf8b555042cdd00c13a550e8f252e70c3ee80" },
                { "be", "d6b2b4a59bb20448ba95de12ffd5b5e2ed2eac6d469cc0bc0ebd16cfec0c43cae33468aebe9d96e0cb45dc1db037809587624238db1b6493ed3d703b2fbe50e3" },
                { "bg", "03cdaff13e549789f6f9187382ea34ae1e4e140bef2c430e75034c482c191bd77bccfb387c75292be2649dd009432aa7cf0d0ed978746974117057a77426a293" },
                { "bn", "a0202dc3d3af5a2938721a415ebcc280b4e2ddacd61a3d388a985080325bd48d2e87f701d8cd9026e73a37e0e4dda13774119a8d35289256651c1dd8868f427b" },
                { "br", "a212d27983e07ae133ed9be985dd69a801b6718fba910151e914c82230df2f8533826fc3525433cf4ac8d273b8528a7f003073f762fe4752e1a69d8a09ae5a36" },
                { "bs", "e5616a0db538309bf46d08fe7bf30c533821e3ab5a201b266bf40839c67a0016584d24a17d99bcf74f83f00021083e5ac9b8d813fa724853c5866b17e5a1193e" },
                { "ca", "d97da0dae9e15e945e9d8e9bc5717c18206fced7ff8f6cc3a4d525a80a07637b91c6371a5b5c18f57d6d57f6183a9966691b15791c919906ba819955bcd5a3d8" },
                { "cak", "7e07b0b41fda9c31d9b61c203667d0195e602bb57cfdf28ff9fe6442c6471a1471acd33358870526cbc6656e0e8f8c84f197c2be8fa75aaa9c3e7bad22facf88" },
                { "cs", "3dcdd0f41dcdfd793aa01033bf715f51834b2a37b6cced62007097a98453337ac5af17bbcf3cde720ee3411d5ecda05bf2cac06e338a2ca34e0a8e5cfc0eea73" },
                { "cy", "9686594dc0ce22a344c0feda215dae1d97b3ea34e88209a9df5dcfdc0f06a88e2a9599579c063bc6b3c02094f3fcd368ef646075424b01f693072f437fd87d8d" },
                { "da", "cc3b894f6a949e160cf82675ad2a66540af9d3de845e35b0f7f3f99004f3ed5babc8df42b51b6dddf47f560da415211eb5fe730f884c15059808cdb14f1f2dc8" },
                { "de", "d36bde3ed0d20efd56421d73e7ef0652cf8feb44f9e0343eef3a16750916d96a83dce4afde4c30833f4e75673ad319c974ec2ee229675620c194a129922d837f" },
                { "dsb", "b71147603248c2833904a429ddf77dfdb120647a3ae0f55827e952f1cb735343fd02e7bec96fa30acdbbe7f93159b7d3ff3a094ca60872ff98e859b7eb6e2b1a" },
                { "el", "9403034a3758607dc8c36609073f1ad023da761e4e36381a044273a719c447b3178676453c6c05c5c8f4e3c85514a02c4329f0dea100d54f640ddd3fd21148ae" },
                { "en-CA", "87fdeae4293f5c897a1b56338a9951f81115ac863f8bb3612cf504b2cdeb731a7cf35768036f3d1e1115b24f24a5b4248ec3c5dfe50f8a3e2acf87aa9260f76a" },
                { "en-GB", "dccd633671aeaac0d3c258a0f7b20bfb38249c4ece28ee4dfe3c54e8dde49c497ab0a976827d63ec73a64a96a917f4f6423b2a42b2cadc3b6808bebe03b0607f" },
                { "en-US", "da323aaaa94d4e7f46044a937db9d82ceda3ee07db56d6a18ac065c4b2ab4cb8901114a954954453803f1aea462682af37d9eae2055ba9441d45b82174926f80" },
                { "eo", "d39c1194891275948d6911eccfab1f8a524255eb43fbf9b34557efe9d27f4015662ebf91b3fdfb5aa5091b154a325f8bfdfb7deb7d8ea3e7587d612edf5e6df0" },
                { "es-AR", "ec03222f59df6dd02e7e2a34a900157996e12a7ac453c883e0f5804e72c236e24247eb621112f1dd35f39ee7027a1b050e59d98263a6626e6b5c766700910934" },
                { "es-CL", "98df1cbd143e1c6ab8b9d159c44d0041560ea012191f49c6b8f46c7020ec1b18047f289619c5b7d54e5584bf8205a649c12dac5175a14e00d3be0de181bc0937" },
                { "es-ES", "672647fd58bcb854bd9e7abdc67f25a91d1a00f6c1ef3abedd73312f25b38de1a54866cc353a564b20e34e61990242dc1baed662c7b84f21973ae77c83e9c1b4" },
                { "es-MX", "6ceeaf3318df7c9e91f8abd284a0bf9ef2b20c577bc1be1f3943a9ff958d0230d8c856f98bb1de4aabf5b9d87e5a7d6987226bf1eb9e0fa37ef21bbcc8a1179d" },
                { "et", "2d7fd0bc5490d11eaab17f22550d7a987d522e90254e95c0780fe5a15110dee2010815db938a365d98ab90e49d779f192507e101e04a54dfa99860dcb44c2d4e" },
                { "eu", "5a6a8de8ebba6a9d1f1faa83bbc1aac331cafdb8c4080e7ceab56abe7e0b8c0cd9e23fb433c3a1ebed1e09f55d5550aa3ad3213302ace2ca98dbbe1e9ac3d793" },
                { "fa", "23a54f7e17d18a42720a6413ca563f886e3986d45e163ddfb27ec4c9eb69ea10f20d4af2fa5cbd6cd1ea16b2471f81684a8be7ef4f6c29131daaf701c6acbb8a" },
                { "ff", "909d12c66d06bffba7c49e536f6bddb0c406f0b58925a4a694b4e239296ad49220ddf2626ae7cfc1942ce3e107c1f7001bfb6a0086c655dd467e1a2c659e900a" },
                { "fi", "20939c0f7c418f8dbacaca7e0304f17b8aaba0e9591f883c660945140983bb9ad3e1b035ee8b92e4631b8b4419d780491841f0ada9a1c7e624d6d7c035b99d29" },
                { "fr", "fcc898aa95cc981a08fccb2b1313b2b96ccfc883f8117356cbfedf3980d939f2b080936fa712a06b6e50d5525e00b4a8e79e91075ea29dca0927cd960166d470" },
                { "fur", "b0ccd70ea9d0cf15b21a1cf96337008f45f3b1122f6c2e39052b1caaf6a86782444817ff5a615f45d014238b6906f8963029115489c28dd58c2a28ff5037fee9" },
                { "fy-NL", "9434e87449af1ce1ba53a4fdeec371cf36aa4505a4657a393ec508274edf0d083c37c81d04a3e444dc672a7ecc0be4c73495d196b58e11210bb9ef3bfeac14c9" },
                { "ga-IE", "e586f1c1fbed6afbc6c0285893774c104af06073b04013efe2eebb34915299b860d4ad74afe2bdcefe6e5d757ed32a7460e9c6030b1cf1603f9bdb4a34b5b51d" },
                { "gd", "0e0a6e34f2d5d3c2b3b160f004d059181f8572f533ca5b081d0b8e1ec08589c9757b7a273ef3ac2f38bf0e4eee76f7dbea3200809dc3c29e45e0098a84c288bf" },
                { "gl", "98f814206d31d0affd9a3b5d2920a04321d698d1918319156b08e0ea88c9f867c31d35228f9e7f2040fddbb00827ee368eb26f65254afa2683046ff1310b510c" },
                { "gn", "24da718fa7f02b4c2fe29f7d7e22b5bfa1938dc7dc78da1b093fc9cfe25b0eb718385efe8fcc22131c747c8ff46806360ff446400ecd892b8a68fff1d4c586c6" },
                { "gu-IN", "d52d708ba53e09187ca69358ccbfd03a04f68b6eee8dc6253a96b290d2b2e9bbe6a629f3781d4ae88deb6759e4e17cefae6162a04722c6a8eaa21d6144190f39" },
                { "he", "595d351c7d010a0af51ff5f466bf23c4798580f4325031b7c0b05a8e6f632a88f01c1be8c9bcea3a420d08e4e69f54abb23f0d6aa2b68dbe25ec5fdfee7492bb" },
                { "hi-IN", "d1bfb762fc257d7e2aef209a071b934615795c9ee0eee0b09f9c355463f527d71cc4542e3e6ba6074a6a318c8ec3ba8b3d45ff5a68e334f632e001a2448da06b" },
                { "hr", "c7ac84b7421068eefdc3e66f96c180733cde666974135b3dcd33bada5c3713b8b64d0cd2687ffa68490ea6e9876303abe465a2b9221e6ecf9db48cc9f057a57e" },
                { "hsb", "fcc4ca687a13846c71a50c2aa53a2f0e2ce23d977135b52537ca94763d677fd5c32f1ed67dfbb2ab114ad00ca71b3bca3be301b6f4d0787db93b955a7a3e8cee" },
                { "hu", "17bf03a99a0a82a1ee7c46d7234a68394d65ef47c9e10dced02812a62b79e7ec7ac5bf61de2c7817c337e7ec9028f14b51914e904d8236b6c95ca76310fe5d5e" },
                { "hy-AM", "116ec00861742531921996bf4e90c96ce96e0d0ca807d1df63f3b706b9a6d756e5aeda3ea01945be640d7293409253965269f48646d9975c36786d4afc7e23a5" },
                { "ia", "3757730976a34332b8a86f2f4c57bc8ceff247f240a79a0e069d1de24da8bfcc2fe25fef076a7e92495034b46b5aebe16211a69cf48dae9831b3918e2861bad7" },
                { "id", "b1b14e63a6fa3f607eafb81d09c7d2c2070f3ba1be71c4f42723b99ef9402371538aa8bc9876e67a9618ea31e37b6594d6698e9363b87fc2ec2065661b2ce576" },
                { "is", "24bc5f51c31061b7a40ec709f2b81519b57bd86773c427fd65ad93d1602b7b513bfbb408a83b5f7a10df2292b7f99a9ee5e99777848acd510c6cbdbc8910cd39" },
                { "it", "e75ee854aecad9f0a34cf50a6804d88433a3dfadf333390d61e2bc4d747396e4bc4126101b905fb1d67f0d63f942625e935ade23f285029ca94d2ff2dbdfa61e" },
                { "ja", "759d4521ea7a7fd2c185ee1e4210734e89205aa27431c6fae2d63494ededdd352eafd3203628d144462a8a6de22f7081a26a9ef47e96717722844a1660202177" },
                { "ka", "6574b56084aae78c398935cee7e06ae0abc7be9ac8a7716410a723f679324755c8a062a44806dcd067d7dc5d41a98d6a71b122083c64ebfee89bc70ce80ab15f" },
                { "kab", "ca2246c384679468de3a95660383866bcfa8786f4d62d0b69041b5f58ed6e5382d945e47d22085afd66d7e332231bbc902dfef86f390cdc7b9f1fa132c0087ab" },
                { "kk", "c2e43f1c7e687accaa6250c2c8ecf59f45c7197c753b8439bfdf383caa82ef9660f218eccf8b147e936a7ac876780cb97b2916868a1ed7964a0714c4d0439590" },
                { "km", "28aa8d3c76f4e422a10c9c24786d869decdd095d9d081c70425fe3a0eb8f24c50a0f0fe3d6ece00bdb1e0e793ea7649b31ef8cbe9eaf49ede8c961d84fc6d270" },
                { "kn", "1c1b394d40b67f482216c4c3bed7b5e2e16d242aec71678f62c4786f8a53a55f2714b0dfbf5e95bd5265097882fc2e15357cb10064a9d9172f96571f0481fb4d" },
                { "ko", "2610d1f3fbae20195c1edc03b7b7c4251e3c2b2cb8e9f4851fee1638136d2539e5b4ad12c28402df12222aa8048847932f1ee4cb068c1926a126696d3b2f5694" },
                { "lij", "25c0e8a48f9a128cc6c29807e3d295e449ab306bf81e408f8052fbdf3905a9cf566bc1fdda3ac6fbca0dc8e3f04bcbb72016eb32dce98b4db986efd3031ae1fd" },
                { "lt", "b746f51cddb1f1885120ecd34bb755f193c22d28e823a1f8018c682be0694f9a201c777a528c970e168000f5cad206ce3ef4fad4ce875466e948e7858b148f06" },
                { "lv", "9894ca18c34354124419c5f740c5e9df5fb05b7799e80786d0802268d06127141e59f381d15fd696571b6ecf3aff2eefd958bb19f0d2bc46d3ffb3a20359b0ed" },
                { "mk", "a8fba9e09cf1d264b2b78a0ef02b2d08705c6fdf93b06c17feb6e704bce650ffdea944ade2c5dfb14133fc58b8e4553bd5713e9f28035d77091dd402c14c46c4" },
                { "mr", "3a2977789ad0dff64e61c47189dfc44c90f702f052c51bab2cd12c10f16c0640e48a4fc493f992c06f7d80c4bb52a6d6a4121a414d26ee80cf130b184ec45839" },
                { "ms", "3629c1353098b144e7f6e9de87d299abc9f3e701bf142aafcbb0854f1168ed8fc17c1077012f4e7e2f3ca28830ff394a4a935584591a91a79cf17a3cf0c7c744" },
                { "my", "5e24e16fa05f75bef5df784a83ca0498affdd9f330fdc44316efc6381b81aa0bd1eb84cc78bc2a25af8ec10b4fa5f9af5b427f8ff9597243a0728e59d3df7067" },
                { "nb-NO", "9c63a14e2d7dfce8ee10430dbed65db16b6fb7e84091f1cd06329570fa0a2c800354f64898eb2b0cd9c2ccca4312a1870d67cd267589a079495ea0b4d2379978" },
                { "ne-NP", "ac3e9189423ef9c704fe8e0931b8eeea0fdab18640f96266b35080172d9f36a9ebecf3060ec912f252a436df2db8b1a31a19498bbc75c0256cfb1d779ff4fd1d" },
                { "nl", "1c5f97a916ba4fddfe9fdc1e4ac10da2a613dfcedfad88c02dd12a6f44115ea7936c1bebba6e43ee1b6b61be584a42272209f3b2f76438c9cdca396a346e0d4b" },
                { "nn-NO", "354028bf74442b3af9079edf1aacaa2e66a948da8a3a113a57cd9585f8c35290bcf2ffac42afe19e0a85d74ed2d4edc782739ab75b4c447b0b415a7d0c9634f8" },
                { "oc", "fb21b27c998aa310aa80fc3507dca2e348cb1bb6ec3fe93a72d109429ffe92a70890cbbb87cfaa9843335f88110fa6deed1a1b6cd546d9f6129d89b4c7956714" },
                { "pa-IN", "85b4e84546d7ac7722393add3c8d728a16e234c8c8868eb46718dadb7b8ea0f839179329beb6d28c6e3602c54648d4394c0533a17729954a5d0f10fa3ade8a65" },
                { "pl", "bd795c1686eff772cfb0dd70f0bed17a56dd06073e1013329f6f725e923964359587cf3cc09c23e5a9e88503d45b502ffdae1b7e580e54a06c5928ff6c8fe837" },
                { "pt-BR", "46014b635bda8790ab63ddb85201b08fd9b5735fa8ac7881dc181651a7034acecf1f5f89e0c07698af90ba2858908057ddd0508a94cc1b0712509665f2b1e061" },
                { "pt-PT", "67b23233b60d0f14e98c214416f320403b5df2fa45dd602643985c5a4a6cce0431f1b8607605744cc70a863328327a67ee75f5cf998087700ede5daadb928353" },
                { "rm", "ff1ec41d7dba549a53f903d9a15c49fe8153729afb60ad8cb66ea5e066e28ebf823e1b4408339c5475e296ad0597f51ffb2e6ec08dd0bad85478cdb810b0cabb" },
                { "ro", "0752557a7e33911d6763d4ab81d59699c350cccbacaafb5e41d7486d8150d36ff6237a2e77538bcca5f5d8a5b9b78a51acc72f58e3a3e2ee7c5c33c0914738e0" },
                { "ru", "7a8d680876144d8142e8052207a3c40178f48e0e75c1cdadaa14e6ff08ec4f702eea2eaac34c66192d65d20ae495036821ccdb2e22456e964323b81494a18d9d" },
                { "sat", "f0ad7af63bf8c98b516e939274480b8a1f39c323289b31bacea427488971e26fcbd368e7e3db0a8c7cdbcb557281c2586687b9b798cad1040af8d910390eaa70" },
                { "sc", "7b2fe09c3a8dd77d7d2242ac688591f090165e5b163e329df772bdd85f327c8da65e78792016d88a581dbcd47bea9067e7111a235f74a636a67ba957f29a47f2" },
                { "sco", "f1dde103f9ec24371ca0d7f5894ddd7896f4787b58dae10e9d3013d89ee98bfc44ba949618352ca7cbda43bb3e523a4d049aa2dbd8cdea9090f7e76101aa2ccd" },
                { "si", "3df5e1897f35c2d23641448989c74c4a72ae47366d6c25265e1881eb00c0501fb6a74765c04098c0c1937628a3c146a68318bc02b456274250772fe9c7282341" },
                { "sk", "ec05bb798716d3d2945f00d67ae6fe7f94e1fddffdf84817aa8fd494712f6578704bb223b70d22748524b20c12a426c51cec4d8f032f6d148dbb86a5688c6da5" },
                { "skr", "620da039c23a6a4bc62597aa2297152c8fa8a586dee4844d29fdd658271a967d7c26856901a77889ecf2bed65b642a536ac27909b88c744705086f9292ffc866" },
                { "sl", "1151f2e645c743eda260ffbddd0c2f8eba7ebc0103dcd601fbbf4608e7d0def42b8683cebf560225f7524520b1f686bb338fea869c58e6e545c40989199b67bf" },
                { "son", "d590819c9eca6d013935d14e3102b24d37e7e5b787d05690cb96cf1e2e442bc565d6403292aa50138a8f269005651deb335caf1c35cac3c268d744f90c4a9d06" },
                { "sq", "352e35668df4a725c7b279b48b585ae03babf808c1572d75efce932ab7cdff608de9176245a7196a1f2b9d1f6fa794130c74cf4155448e382bc7adf563d93899" },
                { "sr", "fe1f8f9aa0dbb5de4f0484655db10492327b56ad0f99b4533f0b6c9fa206e7855d5b7c387561ee5400e0b6319ef126fcd900de6479ba75529cc2962e55a1a574" },
                { "sv-SE", "88e581c9863887f3efcd91c60a10ebd43751fdd92541629ed58766dac8b9fb409298a19a498de1c2c9dfa94523d0c7ac6d11d542f98c7262fe3ab97fa159b86d" },
                { "szl", "d024efec9ecb8e39252b1277f0a426560248f029004911079e0777cb2a3a1263fa03625971a17c84ba56eb7563c97d6ecc68a03990403ff8f10f35638c431e67" },
                { "ta", "32b60910d862f6d235da54d74feea199080532408e5f5003dfa87028751306c6b805988d03295814b236c8e20c47ede35dc4bda8e2eb691b55cc56a1297a6bd4" },
                { "te", "0de2f6919e4fb56b2101cbb1055076784c4cb1e88512a8e834012f447b25a9937858f712f5a57a535bc96b75610a1d5a7355ec45ad72b6833568ab0a13457984" },
                { "tg", "8b730c33fd1d0decbfab211fd419c0e7b8a1a8f1483b893b396096ca065d21b56ff8b828cc6937ceffa1ece584e207f2068178850e01a52dd07c459840624f29" },
                { "th", "1d44a877b2f67f9b3cf0fe8eabb7f8c1e2e36184b02ea63f287d8129907b876e34810ef34f6fd51f1cba8f8715753da45c0b470fb40267eebd0afb621f790769" },
                { "tl", "3b3541833802adbdf793d4a842d8d595764fcacec43b64734520d6a3fa19f3c404f9b66f641d9c451f34ebdd105b4d5a67fb5860f3b682370b0c9641c8046754" },
                { "tr", "b8730410993472aa8ed54980aa1d651435e92c64f5761a52f27542131d26e59975a39c867759d85650e8c37e476d589f46c22f441444164918280afe6babecda" },
                { "trs", "e8a606a3ca317c578547eaa853d34a28a8506fd540e04ca28a24871ec320d6ba69acd6d70ceebf22b693d5a89c744ccf77e509d5bf6c7dea756f1b73b27cc15c" },
                { "uk", "dae8843a411018270ce4767d4654e64963b9847a189f98d8b32d339425af8acd19d44edb636204f99e2ec4dd2d819a1cc80e8b7d86bd915c8d0eb3334f821092" },
                { "ur", "57286a657e35f4d91329a1337e85d82f1bab382ba2fcf41e73e6bf532ab3640f628a39fe87b963be018b5da9eef410e071ebce047079ca3eefcf6383429c0848" },
                { "uz", "a83050c47300de8876e456f79f0b61e16f2e92dcc15785ae016eeb70073d5f89fdbf734fac2c0b5a2dab77e52f8aab3204ddc47bf23b5c03dfcd409c78357afa" },
                { "vi", "9024b00d6b0d19e7d9069867f9e0e4e7fe582a157f316effb8aadf1ef133492a9483aaf1a0a8be2d0376ec891464410c0e8667156dabda5ed73ad9c413e603b5" },
                { "xh", "c56432bf8f1c783b55e60ea663e441cf678bbb0e6cdc6f1989258764d2cd5bdd2e9023edd1b7179033001ba9157447618ed351036a76138e5b3fbd86e94227f7" },
                { "zh-CN", "06a1204d2a16d4dd98d56bbc24ba90ae8052bfb6edf0dc8809c3912fc4d463144b843583b2aa6c97c62ea64e85223e95c20fb01d09cde41bbceacbda259ac187" },
                { "zh-TW", "cf4428a3ead99448658e0e18b329b55af8d45f778206f4761f0e0b56e827479b8e0006e6b8d29f05d1c998fefd9e7f8d86a52b75316f9374f25765a76a3dcd10" }
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
            const string knownVersion = "143.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
