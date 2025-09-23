﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
        private const string knownVersion = "140.3.1";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.3.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "86bbd9fa694b91bad8d315a3241cbc01d2c7bb0c4b3f0e243f759ed0b2f2e535c7ac0c4bf5d75a1215ce669246a2d917534f7a64a7117c31be8be6d8bef400e5" },
                { "af", "40b2e01c3c1b053e92b19eb02e70c3b51dc2a9b4d4454f4be49880919e667207c3771ad6f6a21fdba767e9a287ff4c49887fe5ccfb2fd4fb938a4b4ab1a1d010" },
                { "an", "60d0ce7a65281ad12ea2067e00fbb95545ce890bebb2a9138318984d6ee6559494cf0a5642b97987798ac719c63ab82406d71f17257c561d3f6a01efb5f1f8ba" },
                { "ar", "f983844124f848985751e31363810aa49f03dcfae09bb03901f646c845bb1335f677a31378e8af4343ff34ef465242bb31478fae1f1da7397497abf64aa64711" },
                { "ast", "e640f1108f63496605c462d014676f0c913882e3ff36a6eb8c4b106888869516bda9da51cf4fdc826fd757747fb43f8d9c6506c2d86bf0d2e5113f6840122ee1" },
                { "az", "06d3de2c5c7d0b6bf82631a178bb085a17de03c2b156add43434eb6f5c627c873a6a162e067a76fd197d8215fdeaa8e7e10c89a82fb417d4ed9c14c1e1bc7eb9" },
                { "be", "8f71059ccae60e8b51daeb85620245aaf643e6166da1e26cc51b73d6b8115255d9b9e762f8ca010cab473bfe59ae4f9bbe6c8d2f07cb258e6319cf25dbade386" },
                { "bg", "500ffccadf2e36b34a87b5e72611fd44374a53462c5e920182189f0af358322998bbbc02aa5646c059c4487870a9ca598f201511d512e487478f1a60345273e5" },
                { "bn", "a4d72e6876839e55310eb4da38eb9cad41261df7d7e8e95263773e84efe7adf8d9b3822d8f1bfb93c0ce17cd3348f2c42b0d3cd1462312993e4a9c09e2654d46" },
                { "br", "cabebab0a125c2b4efc929e5a3ba0dfa435648b1df51c15514b999b97201a8fd6868c4bb94897ec6bda2a59e39ff992c20e5bf900edf2f2e1dde8d5018e3c4a6" },
                { "bs", "13b308c8cf30c6b89a87709f3153f1c1f255d6ed70f910def462968acbd97f26ba707182b5cc8716cbd3ef4520eedf48e056f154050ea5b6f44d5b07304a252c" },
                { "ca", "c513d9cd3ae4355e3379a8305fb267f689a7de618a1439268f999d9c022a22b2e3d32c1981f1fe787460593101259c354931d7a506bb6f54e2bef02dc1764e47" },
                { "cak", "cf663c7632520bcb8195cc37a112b299b6cf5e5ab20dc1fa182539208aecc59849ca2498c94ce1b0d4d91a2434abe9c41017d44f7e74c49c033aa9d95fcdc51d" },
                { "cs", "dc3744bbbb3bba5d1eceff2b545c846e0509e8f10772a202d42ed2a5d6aa698186041fb7d7b0ec2d2115e8e596718d673101b5e83833f23fc2eaede7d3cee957" },
                { "cy", "65a26625f69a7ea0c074585b6b507b36361cf157cea6a0455f9e92f8f3a0746f615a4707e33c9ee0c3b8e1fda80649c1a6de2a03c20ae1aa9ba54ce72575c26b" },
                { "da", "a042b4394a23771cf7e1e81e28ab023e46668c8ab276f2166c27b5af8d804453d7fdf6f38fa9768a7d1a90684bdfe0ba577e1a0fc942a4f901848bebb383523c" },
                { "de", "e4a8abd95030f8deb13338e0a5846eeac2e03a65d99eb0203adff6738ab27d1fcb2bafb1f3b2cfb096ae04734b09a05c0a409b59d00fb98bd64e0c6999ad7fe8" },
                { "dsb", "d5da2d6334581f5ddf15f64674ffa5f9f0b41c307b1c7e7eeac476181adbb0cc63fe8c53eb3a2a9b3c6afb982d8ce4efb388d672ddc82001f8c2258e05dc20e2" },
                { "el", "13b0bfca8115ffa11a7078fbecc9ab7cc00f8281a3a40ea730e60c41a89aa84a9ba4bdeb0a92c8b08dc9cab4b98855b5a34f53a4b7e4d91dfa74fed434a0cf4e" },
                { "en-CA", "ab4b07496971f0c8b43e8366b3b40b50a9f3281d9d9dd0a93e2a597fc866fffffd3cc62ec69f037a93d86a321ebe269890d9ecf947cd7d1c189bbe5e93e86bc4" },
                { "en-GB", "c1882644c3088265dfc4bbd940f70c1c2952bf7d453354b7aa85a396421db5ce584e6adab14041fb278c44c0f1a1ea2ea8a700bb60b47845e2a81138f66b22e3" },
                { "en-US", "776d1cfa89e47085e067e9f998cf1a994b8d8210695e0b4154f25b761e3394f785c73796a7bd0e53db984140c709747e69d9e967e2b359f3b7b20631ecd96315" },
                { "eo", "cdbfd28a18e0414d9db25976dd78079b990bee29600ba8a775509c3efc54eb13c663fd3290b60d18d9e0e3d2248d3c1f73ea6872810104101e2fd5e1e7c3a90b" },
                { "es-AR", "c05c37b5b1bc3bead737f141ecb87704bc2582dca5dc712cc065481b6c8508f393a98b55f477fecb9acf244761d4c399ae67cb12e18db15d4614377db4d4a59c" },
                { "es-CL", "0e8d13bd2ae4e892c617103ee41de9aedfc9e19672c285a71501ea8950430b5a71ed58e018a9e22eeb97c08651c47cdfac1697efa3e45bb73b488e5e23918276" },
                { "es-ES", "3932e0bc066a80272db52810c3c7358277604a6c12f970b9de8dbd79bdd2dc709800d225d5c006ce49f5ebfabc1eb83b5526d008674c3a9b31d44a55f8b3f0ee" },
                { "es-MX", "2ebb0e3c66788b9c871ad93ab32dab253f399f690cf92eccd2b345e91f0bad91d9f25cf3ae4c1087f6e5304e9f43de9945fef0c5f520e6189a358a62de1337ee" },
                { "et", "c2b41a1e04ad307124c272afeb6f1843da100b482d0cf0a7b9999af99710b584f3a969e0c3dcf2471a31010c8575d75c1a28568f263764b2903700543837161a" },
                { "eu", "70d001df40b1f0cb204320ec6ee342e98bd68b3311cb2d19e6a5cd59dddd6e188006532755440ef11db2a94c5c08d3d1d22411793870547df3666a4370c99dc6" },
                { "fa", "bccf8a348b2c1a58921be67fce98d263ef466526444a41a463af60419ac726be3a6cf764b2b013d8135e7e64b4b561a0b2333bbbea16135c24c73e19ab3c09a3" },
                { "ff", "2b83b11031abcaf1d615ea609b5bce5d582e23da085166ae250b9024b49ecd1ec5a2f072d623cfce654dded47878f0b12481432cb27c261165ceb8abc9ccdb6b" },
                { "fi", "630c0cc360c318f0e98ebe301fc3edbcb1aa4ef36f10f2ae085e526f75fd9eb91d33e44cf7ec31e40e1312e43b0c6a7b54988c418592a6f3fcda8411bf37ca61" },
                { "fr", "dccbacd9d50765668ea9ee7433e6b8109173ff0e1f18fe4fe6472372a525fee214592bacfa7f365d71d3412c6c3f7ff4c93444fe3768a64b3556704109d004e8" },
                { "fur", "16791cdbb8e8a1b0b3a818f65a959257fdd6996fab7d40f0c9bcf750b8d066b04c02cf219a4786622e3738c765d4db2b8416afc87777b4f6fa00cc6c840580f9" },
                { "fy-NL", "48c721d815304a69e04a52a88f0dd10993e123f01c0eb9b152dd7c67b2bc83fe073b0cc479f41c99eabda291274d218d52eda2adc9e99eea0ea9e5b3b2ebe47f" },
                { "ga-IE", "7add1474f7d9dffec9fab280a409678d6932cc15e9abea61fb4f7e8921adf426521baeed2284cdcbb990a057781be2ef4b01c025ba3063f49670aa7024e2238d" },
                { "gd", "ca0ce9235ec75d5723a23855714d04bfa251fcce559a041343198e157ae66e32ead0fe853a289eaa13d3ee676f9e8056c90006dffdbc9c94a50c3944cc1bc458" },
                { "gl", "c6ab873ea8fbe23a647ae8cb8fb46963de1ad520f50a392c00cda9043edf49598a59e0908ae05cd1458d92cee095d673d51985721783d120bcb6cb7d04a3c901" },
                { "gn", "098f3bb252003e90dba58d8158c1bb4d6b4f9d29ace8feb5a14c56501b9d3b683b5f82297f53ba5a11c63e47dc8b0c73ce081c10dfb1374864f87415630da1d1" },
                { "gu-IN", "62e2de76bae85dd79315b0ff51282055ffa4f403191fa3f360d0f27498cf269a109623c9acddd8f4c414fde3ab9054ba4d7c563013e35430be21fa8df89fdaaf" },
                { "he", "50713a9587e46294b4e43567153e24becf3b0af75b46b7ead30f79a5a723736c115a95668ae7411ce5228b54f871d29170a3da1b99def99288a8149989e51b3f" },
                { "hi-IN", "39b51ff22c6076f96bf30b4bcb937fdfe3c13d9f76bce8b2159c718cfa83d694b5c1991ad3da8453ab63f2610d1caeda7ac0e2aa36e3287435097b639a1df842" },
                { "hr", "8fa5aa709765b3c51ce90181047f19cb7d61ef791b386d1b12a89f339f5a314b2741d4f6724a2b5e2fc1748466e37faa6b2315e5ca654e08a001e70edb8e92df" },
                { "hsb", "940fca69ebb53f3cc0b837549f2d4023ac59ced223f64b186cff8f1d55a718ced7c6f0aa6a603711c16dd9502efb0fa8d0d4463518f1892a260ee2be7933dc51" },
                { "hu", "3e92620c1da96e36efde366d171df155c1572ee4915a44d8fda4d53c3348b85971a7d91669a3cc5e03502d4db776ddaddadc0fa2587aad248b5f87f4330fba46" },
                { "hy-AM", "051238a1fcc74399af2b28997acf92c68d93077c1f52583a2f1791aa5a3975faa2e26a40cd98d9042181c9bb21703cdfbd666e45a97c5c3c9653ddd79d556b24" },
                { "ia", "c512513c10e8e7222118d43b3fc6262e8f348854931f1177deb3c541a3fb0df6e6a197b2414f8e635ecb9f77a1ef321c32887b20eed6881d5addf5ed359f731e" },
                { "id", "c0dc31612a891790c64b3a63515e3bca01e83ed978015f9c445fbc5fa1fe8b89642fbcd9fc587ee358f4707d873975a955b4f42ca53f846d764d17980d95cc60" },
                { "is", "d99408140f217b987f25c5c187b9d800a4dcb0b7d51f8949d75c8285c3403aebc4852c51a9cf2e626fa85d3801d437f0eb6ab56212f0a5e74dfdefd67b9c2a04" },
                { "it", "63209fabc0d700dc0ab4664a32a268ff893e494321f02d4f36dde4634e22043a1fbc257a59132346ff422884ea5c6a67d636afe1047ea95c2b54267af1b8711b" },
                { "ja", "47e6606e0158d046d26f1c471555f73053fee0e3deb372adbe856930b88166a79fc3f31e2d9780a5193b0400518c952e026845818a6ddf79919658eb82cf6d59" },
                { "ka", "b06d3476c716233198124bb6406c3f25997bcf5913866539b3cbd580dcbc5bb2e562a84e12bf12060a26cfc72216069ca0812e11ceef4d098a7f844ef169c935" },
                { "kab", "e1d1f783a6ed6dae7212632f0d73fb85284f398550a3de81e8e423c51bb5e12fcb6f30db9033c1867be4ead8a8b46b17f2e51286036dec6d27d6780e46d11e7c" },
                { "kk", "bb3bd9833a494a5970925f6f0a2af6612c514dcd8c5a789c780f75b4331b8e33bfae1a69e3b446f53645e816de02ad5c35c4fa961739a739dc0b56a68175f0db" },
                { "km", "82c7a930a71bff54f438c23f9f5355b19ee59b349c8fdf0ec37065d3280dbb4fa1eced0a6052639a22c7bf07d6036ecb0367815fea6d819a391e096fa2f24396" },
                { "kn", "e84f3e22b591cbbf062e3ebd6e834384ceff564476c056c4a83c61bb5f7a3a212f76d6902d710f4ffbc1230ed7f9aa73d54e8ae0112ba0197211a4b127ba659d" },
                { "ko", "5615574659b5ca81eabeb97e5fc6f52edbae76ce2a14e792794f2f458dcc67a7eed91965fdb7b0226e8f00748416b4307f6d7168b3d163d7acc7098392373dc0" },
                { "lij", "0388590c4abea1c577134d74e29187990609e2c5c0df9090d2ff128da7da8198e2c796a2caf82cfbc1abc3f015ad270c8ff4cca4dd1b81a94951f96dd781ab16" },
                { "lt", "12cf2a9beb3dac09a9835da09b6bdfeebddcd801308f6330d7abddc54df89b2a244f317a128a3e564eb77da5b4180826e0f4c0a5c4aa3e7c153efc82d10b6188" },
                { "lv", "4b0a5609110bbfc24dd91aa8d665b8e14e5ab7984b7a4fccce4331ab732851438e3fbed98016686bf112ce017c8b9301df7b1d1f481269ba4d5d92f027d2f544" },
                { "mk", "93ed1a6b5eb4054345719326ca4b31e2768badc4e7e0ef6992f90e1dfaa5524837fecae84d02276b29db24f940ee82f45ce39f132cdfdb27d3aefeb40b7b0615" },
                { "mr", "2f7ac5173c794ab852098ddbb388aaed06028fad4b89051e9896fc89fee299b5f7199f9554047bf6b0383daf042f84039ee3a81be692cb0a130d790aa2603a8d" },
                { "ms", "9fef27e4f2ae336ddd47221a3b01ef50caa56b88d9494ec44742b681311040e1bf73942646a2fdc53fb173a7bfeb49a839c11e12aa25dedffed5d611712827f5" },
                { "my", "4dc8e759fbed039149d2e0a8b6d8dd494f1f0df4d6d73b7812cebf2066cd8013d490f28ba1b38e8624e67d242fb2c2c54c69663b57cb5bf58cbb46d6e1662787" },
                { "nb-NO", "12b42356568fdcbb4832e32848ccdd5ca254e6554719d827f77cd3c0bc78080324928afd3433f728a6d870618342e003d6e9e98b14ba0b86626651bdee569950" },
                { "ne-NP", "b7077c00f7da63ad78536b6b64a2dec52b85f31455d20243f898736757cf1e537c0f0b6d2404261a685b84c23bc3843638db799cad089272d12a102c13b0bdc9" },
                { "nl", "1cfe74d4ae9c9b6c2d73bf5ad289d4b4c08373e1d32162d32adc4935c33036c092fd27a8fb6b83b30b6256cef07492ec365ec9f8f4fcfc0562ca83f5c750871e" },
                { "nn-NO", "18d7914b8c3f4f6cae81ddc212f2038f0551b1730064ef4e6452788f8ddfa5205fbcba50867b19de5d0817928e4dd225ee9a2dcf0db308f3e2e56f11518c262f" },
                { "oc", "c11981d9bc5de3a97ec8b2975a447e9f15e82d7150b67463b7caa23fabb333eae3bfeb0791e0bd5f25daca8c73ed7337aacd631f204b37713358abbf50793b16" },
                { "pa-IN", "d642326af803448f3ade51b00b633f2ab3a012e2e0806c9301a880381b41526ebd0ac0eaae22b38f91877ff3423ddeca08cba82e1bc5474698f84458c8b322e4" },
                { "pl", "7172ba07f3faad3bcec88a15b9736abb0b2c65fd53393790dce5af659b0f5f8db42e55f8f7dfa782bfd73b5eed6b871d0b40f48e7f4e5f7b4ec31976e3794b3f" },
                { "pt-BR", "10a81ad215454eb8ae753e84679de6218878826cbb8289a99f9852bd5035b826645277cea00befb2bad2ac3d60b00fee04effcd51f87731c908b48197c8a6278" },
                { "pt-PT", "2c2df0bac7c48e120c6ef2a9f3dbcc66c786ef3e9e503612f8788bd285a963982a42bf15a529346dede75b5d3267ed39aa6f6561501ee4f36f366b8b3eb74753" },
                { "rm", "49a152adf9ac39cec600a5dd1cb6a6c2d4de63ff14279d6ef407bb9c22d94c86e790c13edd9e8ef405a02c0ad308d444b9d5abbf0bce2c29d8baa716315d913f" },
                { "ro", "3889adde5cd51d12b2378c363c793be2007b50602debb2fef3819c79fa1f226d9c0f84850bf23b0f805397e6e497610e47c198d9ce6340bdad2ed78fdca71882" },
                { "ru", "bbc9d58165cea7c882dffdd45c6af0bd3354f1196f88fa35c7d7c4a5beb8d177fa243e7fcbe0ad47c71ff64bcd6758df2359c6cad376e041cc54055bb8643ac3" },
                { "sat", "9febd721f1c7734c7e12d288808a82f6198e41bcabe88e23e1e6ef86a847c3f1045ba830764fe5ab5f9cd100f0ccadda89486a46fa4ec1b09ecd62791dc6c8a6" },
                { "sc", "b31137ef85cfe92ddd670a824bcd35080ddb833ccaab73f6279882840b2dfeb2836a4dc0bc655e56f725001e67244c3fc1c6445b474984b1f116e234e8469fe8" },
                { "sco", "b381e123da89f05baf0f9907409238944767c8615e5e40bd7301b802f078a6168895ea04867b0174ec550e07f6cd373db6498f45dc13f9ab7c5582231563f729" },
                { "si", "f0335460e33cf9b7f79c60f3d23598c0bb3952861fee6f5f0528132ff6d62c9f08cb92326360f7d2f7226c0adc4a47de819e250b353524d36df4f74cab8cad08" },
                { "sk", "8a0d32aff637b6698f5c436640ed28d593d75361e62f53a4f05f2be0d563d9182bcf76772a4e344142e76b22a378f9cd67f21e90f6025f38d8097780a032b503" },
                { "skr", "ece81b10550b1ff352deb5a0db13fee2c57b7643526cff119efcc06f3c64451f60a29448dcef664654bdf86ecd4a4f950104587d6dc6b63eabf3ba9b9eb4a725" },
                { "sl", "b17b3f2bef9d45c6c2fb3035ef0162f3006613e79329e7adaced95749b95af6eda5bbd1fec5394a39fbd7e43b0d2e0c33b296ea89714b3a63927d5549f7dd6ee" },
                { "son", "4973c88811daf7397c485f1fb804c43c11a30c3ec984d01e8a551c52e22816b7115429d593f0fc25d4f4763591d181a28f27a40b23215c413574c7c1a290ab17" },
                { "sq", "1c9bacd006183eae9c005d1cf83c1993089f341b5d4b8d15aa1ef0647312d364b50a4ec543c39ad204c19d9ceda5533c5f8352c925b28c91651651185d78ca4f" },
                { "sr", "01ba0025a59352057d47c673131567eddd0a81cbe6058a210c614ac16b122f0ce6e6b48629dab6294c82c2c7ab9b920f5ad1d82602383793a1a55af1038bbb15" },
                { "sv-SE", "396e6042a0a88bd4523c53ddc4bad57819e77596e3b47c032f1c4c84b3ecb4351fadd8a05b7647b6e835a490b8c559030c6d94f1a22cfca1c452341bc5f0f566" },
                { "szl", "ed841b66bfdd13e67e205b1a5444c06bf15f6b3c0a7a0f5b4aab76118430785ef293841684af55d89d80fb810b763d9af06130e17b535ee13892ac1dfa064b48" },
                { "ta", "a21777fb54e1cd2b0bf5aa78c412d2302f36d01ba3ddbf3003dbd8125a7e83fe30a60c494c78ab4951585f908de6eba82baaf63e333ebddc8f3908c8ef6552c8" },
                { "te", "b8735c0ead41eec26b0a1252c2ee8224a2063e366390a11181edd9ac8261be3556418b4fc35236e660eff8fec180e2203f27921801c8bf14222ace591997d276" },
                { "tg", "624f010a186e5de305965eb159f6a80014bd44c42b29736517156c89449cafed1c2995bd757fe9a1d92b7626a7d002ca9111973ee0af5e664f3f8f09633c6e26" },
                { "th", "915bf0d40ce42fa1a6b89ee19f841aba56a0186bf3c451fdd364339eb05ed99b66b22c9c7fc9cb6f6903b493111c0541bbfdaf8ecdc99470d466a6d50a8b8ac3" },
                { "tl", "68cb530839545acc84c705c752e864a06478a2673d7ab1d69266730d60db1d9ff4772219e88a895f41d75cda6b9e3da7537ff136219ccd26af5d9ca8e917fee5" },
                { "tr", "91d57e2bd791630c377e4c1794c9df6c54f8486336c03f7b9d104af78266cacacd04bcd0b395ed7553504d9d981f695500999ca6fa8eac185b0bcd0bf4e41e91" },
                { "trs", "8b69a5f546ad5b690640b15a5db6ffce85673731a75ac0ada4072e63ca0202fc05502db30b436fa198dee7f5f774cc1a78d5d986c81492252e41dd4998080a1f" },
                { "uk", "6a8a848b3b499a99637d70a3ddb6be681a7e257afe94a2ad2c50e3c77c30ea25df837d70687fca14909bf7115c659107245eaae979ff3787ddbe1b76e3184a6d" },
                { "ur", "ee8639e2d9f676704d1f794e07b3a37bfa1c98637c5171ed0e3985a87b0c39b92da79d82c4dbdc2c0e191211683d68e2390b5158bf4db20bc0defa1fbc6257c0" },
                { "uz", "127ec885bd62c5cf0899f26b0d5b83df3b59892aed0c2e6f428d82c11697c7591bc91b71d745351b74e304c84bb0a98ed82bd91a1ad9b42fcc97e24f46a17064" },
                { "vi", "8794560eb07191be97d81d9283928866114679527a4f7ad49642b7dfda5c0cf2728052d7789a186869d6294815eeee917cbc6b88a4923c50554baf7230aa2f9c" },
                { "xh", "13f533fb46fcf9fe91ab0c20eff57fcc7a604579720223b585c08d4a15947ad12e59b11d2e75d3c9e7e441b0162f55c26ace8cf480323cb64ee9a1c93f025dc6" },
                { "zh-CN", "91cf081d3f7dd00c01bb4fee968d0f1386797c401342dbe2789abbf5dc74b6705bfd6b3aeb3f42b6d2e77822e52cb0265ccf83be2cac4ddf4ea5ba222aa0903d" },
                { "zh-TW", "d048cfba153240deb730f5d6295c69db4a92734c1597dda23ad821d018f6969923f9b793990b80cb88f8596480a0a890c1c251d4aaa7691f9a418f5f28f70f02" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.3.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3a790b534328e6d6f9085617cb9e1fc0bd1a83a6d46c77ab012be6d0a2876f95ec6f38c9dc5340e53f7d67bb7d2ddc324b7915439656aee9a53b37ea982aeee2" },
                { "af", "0e131f7f53e06ea34a07500acf8fb3ef91c934f6599a08e28e2fe5cf9f6a954f6ea76205da8165ac6756a76fdbd407645a909e80139b4a48806d209c6f9b2a8c" },
                { "an", "2124a6254aaf4504a36c2feb6964c80c5dd67963abb682bf7d883374fcbe7ec7a9b3dd5dec6df71a9bb0dd51e91fee5d78f28435c202eec8da964c647c3320fc" },
                { "ar", "f847f925c24c07ac558be35504f5eec858f00e5da55d9859113ca4f4b8553fe233ff27b477b8b6b4b6c392b6db561b26912cdcd19f7c405d20e5e0db73219ac9" },
                { "ast", "1bfb7ce9544c30a64edb3dcbf6c4d0d7ce309c7fa5d7b3d4ac74e1490faf213461fdf388b21f707f18884bcc61327ff7e429a4c5f1bb37e0f6922a037fbbeab3" },
                { "az", "a409678a7d185e719c7ef6149d6625e6b24e620eb04b218831c5159006d0ee048e935fc0018f354a26282f6aec633cc5ca5e5975cf5640a4d30ce484b25ea52c" },
                { "be", "8079929044c841e725e79d0b2dc3159824f402ef32fce80f499af00ec6b69fd7ef1bbc66d9a13c6955c32d71a00cbe0e22e47742991740788af21b60e9522b94" },
                { "bg", "da886a028d5d127f182cf47df41b155025b7ee24103d24b040cc4ad72720f63ef4b32794b8d43ebfbee7c63e8c26eead9eb8b95c9e9b3fac60fffcfa7f63b7d5" },
                { "bn", "4810f822c614f8b68484ae10a040e7d6017374b2aa24fb630ec2f95852eabab9d3287dc8798ed96441a357cdcac5f58b7afa04b0ff631cd7c1c8ed1a7ed1f201" },
                { "br", "b92e0fc330c7feb68d0b84696a24fe8856c36c38a38b116339597940035cd65c14094ea07a8466e0838127e6cc69ac0f6a5565caa649dedd054e948a9bf6cb21" },
                { "bs", "8ebbeb6d3c6c3ec212a35aa9e7c710472e312753ef1bbb9c72cea2c9ca5ea5d56013320764fc76e03931a7ca3799452ee5d6e4a13ed044fa48c46edbfbcf589e" },
                { "ca", "6c624740183efbb250071372ed820330e8307bffa731de5534f49b7bfaae1c1e3e2ded0316e61a641d2709126bdad06b67dbd673930e4d5719f0a80f9d9a33d3" },
                { "cak", "9a8c51e1109840863f6aba6eaecf61090d80b7bfb4ad12409ae16392697aba2eef266ad33a1b9f4eabd22fa484eb9792d941d10295de1d1fb43edc91ac5b4ddb" },
                { "cs", "fbd24c425f0fdfcd5c6c1ade63e5797e079463ca1374cab9d20c8ea0cdea65f189269858a14346e9a96fc9172de687cc43c7c0ff61bf32b7545d4eaef8d02b7e" },
                { "cy", "c94c2e13eb172d990bc0a5696bdad9add418ffe5a3ef9fca18eedddabeeb32fcda9d1ff1dea0afd1898c56213fa4948d94c3b91a17ca98233649c95029d37b33" },
                { "da", "8ef5de67f0f723eb826bf4005dfa68b42281325a7ff33a895a2e2c7964bf95c302b997ac4b7a61e41f35cd40e9937f163e01183de2d16528e3050402fc3c2ed0" },
                { "de", "93cf9dfbf0115283aabecf06e34049b9f0d9e0f6bcb1e032b89605376e9221735d578a8262dd038d8bd01de527015b35e12f2b08ad3d74fa942f9c02e8f0c88d" },
                { "dsb", "8db3f6fa9a269dcb0284ba6ac4e4a539975d6eba45aa853818defcbb0f1f41dfabb7bf88792bd387927f9e77f5499cd6713749c798a2aa65b634083ea721c405" },
                { "el", "778d925dd1a05a5b7126cc55298aea623e329304f9666971d7665a4823feea720c226938920690d816ddbddbbf513ad1a01720537aaccc5611f821b24277b3db" },
                { "en-CA", "01d07395d1b4ff6d9ecff9b6397591c36ed18b23c55240da698340a246f62faec48b341d56c5b2950b6f6ba79197b142a26615069931c5aed520be64d053b52e" },
                { "en-GB", "70ad88bd1dae58619d91d21dca751538cfefec140d888931b02adb26b00c7cdc13e1c644104c816cd90bb54a3601e2bc70683f7304b00ec21351f3a038b604d1" },
                { "en-US", "35ac6beafc1543a79e39eff4def4f6aac4913cd5ed2955138363c51974d28c3fcf55339abb1e736f3e011b525a56ccffb38218c74b0008a1c0891c8f698b1de9" },
                { "eo", "e104a7591a218257fd33de1a09ae2c1b35b2607266e3ce29cdd3592f1e12f1225b665d31ac77df6f06b596e3196f42ccab5a7bfcaea98852be3a5048ee5c899a" },
                { "es-AR", "5e43e7c990ceeec0825e43730d2cd2bde21a04168e9e9543b227c7acaf9abbbd99ee730ccd6bcb39e34b806bd9a46baf98cd9088f8c0ced916234525990945fc" },
                { "es-CL", "e015ebad3c217a25256b4f9abacdc8b2739e1bba96a92d53aa7b6dd2d9d55a90045123856880b93ba08ca4c5cab8d9ff31bbf12bd996b4ebd846358b721db47c" },
                { "es-ES", "bb56b0f6733cb9fba72f8a4c4804f59a8b36f595b40739abf916a9bdcad6d00ca9f23afcdc8894f742a1d7b13c524dfc5b68ec3efc73b7a244c9e05fe22f27ab" },
                { "es-MX", "194f30b15b19c4b4aec9d0f3348517c1553b17f7b38947d663141dad15019aa8c06f5ce8958e194d83d307a7598fce4aad34c3cfd6f15082f4faf09d4f00f250" },
                { "et", "26893b6bd0c1fadd86f5e0da66342dc05defe051069658f03142d98094abd17c41ad4e8c26a762f48da45505a09818ada592089dd2267d16131027ba50ecb9b0" },
                { "eu", "0cd6eeccd875790c6c4dc657afa7404ccef9a28d692d869e0fe8db86878bf462fc21069fcf38cbe1c882f7086631cc58410be13e467e6b7ef2a4950d73713681" },
                { "fa", "1ffee4a3a443321857444a74d135f566b221a152cff0ad322e51dc9521726fde3fef9ae837ba900019a13f23e23bf6572aa2b17f5084ac10369b749119a9a7a0" },
                { "ff", "81f8e01f0a60b561d6a2c54353be49c75947c768e8db3d472618eadfb44d22a107e3e1260bd8ff3bb168a35bc1f0649bc4cc6dbb3048057d4ffcff180d5af6c4" },
                { "fi", "f96ac2e4f50b92e2c5f54be23c13a42b635ee81670aefc7db1bfd4fb8be62fd26102c176dcebfd5bf87fb8eda20711f4c0021085efe2e96a55a314f6a5e16929" },
                { "fr", "5622ce5c6c041db3082ff824cae4ef149f03a6b02d7511ea2d175f5bc4f1f57b02cc64de8300aa201431b84fb890d2c32fac17d8f9e2905d1da64f2456ccfe1a" },
                { "fur", "d9fdd8e4266c79d872549de3ba010e6246b6f4dbb7dc4d773f7692a22b29c6b08839941b18293dca39bf62baed1d0a609dcfb7748636c8c1887465064d1821d1" },
                { "fy-NL", "95983c97a0686202b3b03b791c50243261ede677d2f105a74e539452582a6fabcb51a677b2f1e4c7c7ef74357f240dff0c31534ffebd46a8c66a598a8d07d0a7" },
                { "ga-IE", "26e1764852a4a023c443138f890f0ca3fb078f83bc59d37531f8e016978f63cd1e6b1a03b9604a0bf17e347081d2078fa0752eeebc055381a5d8c29f82a1c364" },
                { "gd", "91f32922dfbf68c20edff6076d927c50aac82ba6625621208f99f2dfccc5bc195dfe8c343659bcb9f71b0e7851ddab67d95c29cd5fa2eea709c3e2f33ce74348" },
                { "gl", "12aa9c6ae11d7ae46d8526d05315c1414712ddc01b94f5655e29e0c16f6776c978a10f4849b0a7af423ee5358ac3412995794ce71129f59584cfbad27594f634" },
                { "gn", "69d9a8f0d03d0e1606378357f31ea4123919739ef800fc8107b4165529da9f6c5b8c3bf41734df36082b6a608ba9f4d03a8985a0a5a9da02c2b530aed5cdb7f2" },
                { "gu-IN", "c98c845b770f25babc2c7548a80374de7130bc65072bf25d1f4e4fc5528440565c8f5e10bd4267db00de13cde6dcbd2adcb1ad73e462fa25b41f21d54270095d" },
                { "he", "d3af07bc23eef8b5c9a255c57bbf5c352fee587aad64e881317773470e2200909242ab098cb6f744d582e45822ce1b93f6587382bc9063bfaf4cc0c910724eef" },
                { "hi-IN", "a273197543bdf19ec8a8d7802d4844a8f7389775eb67a804449072c46d30ef9a57770f02b5eb473c63ab794d9e788e6d64e4b3080734d1a7679c9ec120574e0b" },
                { "hr", "bd008b5bc24b7307f6194864162b85cf37163c9cf0e857b55d4c1f83a2b034d50fdf357c05fd2503ee1ff0118950d40ba426104da595783d0bb167cdcd0feb2a" },
                { "hsb", "5c44f8b1e63a20f46ab5b2c79d11918be8964927e6e9e4e3df97e0dba14b2ad6bfd80913223ac1e02c41a1aa04c2dd1c49ce99249317a34e2513bb2021bd3f54" },
                { "hu", "6d6f6d02f3f11ecc8b3f6affe9fb8b15200c0aa88568fbcbbb39574c80a8d6deaeec2ba8ad061bdbef90f4042b8e9a648e381621f30c55e7b373f4b2d5b188f0" },
                { "hy-AM", "da89172b8ec43a627a8c1f4860ac403f5beedc4b3c068bbb21b15625b64e14f274f5ea8cadb24db97b5f9985b6805012cc09630f259837f739e032f1cc3a91b5" },
                { "ia", "f50a90346a63f8b5df513f43ec48d787ab9228825f1b1b382adf7284174b3bb00519771f0f8b6906b9b02c2655c224b709c1ffaf22c065fab6ff3fca81383aaa" },
                { "id", "76cec21cbb296474c2ef848951ae3f0a95527ce0ec5c96defe8641d6920dacaa7d222a44922f39e6da7102245ad72a3263b94397d77d1696394a1e9de536f1f7" },
                { "is", "7b29153d7d153ea7697fb288c1aa6d9f2f0fec8269824fb01f0f0d5ec06cd1db78c88fa87182c0751789974f03aa2baa4528b7c22579542a454a0bb9f8fa310a" },
                { "it", "d0eaf81d91af9888b39a3cade6ce3e8ede08508d7009d5c656b836764bc5c2e7db2cc66861a5c798a0493ded91b540803f7e135980edfad22909b77225ddfae2" },
                { "ja", "2ce73a4a5f66b831cce467d39ca218418acfb8af963bc40db10b81aea14bb7d5b734d1ba7e57da587f2849c13b58427ce677cf6217527365cedf90a4b8a69f13" },
                { "ka", "015d8590f91d1c578bae2af7aa08960354ddf7aaf9dc0c11e57bc7df8f87c0a70ff8c551456517e7a2d41e04b42590f61b468a804217f3f247a67321e41da20c" },
                { "kab", "dc6f3f912546a584d93dace7ada639200abdfa4b96f1d81e50a2dde9922c1e2cb418d2d6f0539a058377d98d770691dca37182ff062177054524cec6bde3d28f" },
                { "kk", "9207fcb0adf34ce67fd4fba601ccb7704a00def8f07bec8e20a701a6a364328d1cd74f297aaefcc46edce97a7dde69421e2109264bbc9f88887f06cbd639c25d" },
                { "km", "7d4a3bcb00fd0f3ed335e50f5ff4f84043967a7d1cbab1c38d031d1163e4eef1d5b7173d5f28907ca63d4052eb2f0c52803cf8a588eb6fc33f2b6733ae977005" },
                { "kn", "90759f176e1e532797a324ff2e811090c75b8f173f7eb2d2f985044b91378bd7459cbac333e4cef5afcc37a0522e6dafc49a56f7abfda5e6d4b4a29e99a14da4" },
                { "ko", "84036f364d50df77285828816cca61a4690e8109d5ad93353e6b127179ec67c6f1b0fa7055a9241f954417da764382054d9fd76f6d330b00cbe6bbb71e2f3233" },
                { "lij", "71152085c3b26faed7e347f6553ed674671b73d87bbb5f9e736c98bc8b154dcd44a073d548d4cf9b2cfcb66260890462505bf06ec36ff1d19ee0deb83cf58af3" },
                { "lt", "1c78d0592357279617aad7f599d553540fb4c36f3a490a46735f863af1c8c822c4f15a7fa6bef4080a948bcf70099bf53547864e4b3e44afbd7cb5047406206a" },
                { "lv", "41cce32e2898ed400f0fdafe765e54b5152af1e7518a6b4b37e733a99f0828e7be7e313da8489c68f7e8225f44a5c619d71306b5436629cee2ef1858b9be00ed" },
                { "mk", "ffc7161bad10180e82661594063a48275deeee46fd52d2066fafc785493772da4531a8e75750873a5b656d1f4518e8d083cf021a0b6fa33bd80b276126cc6047" },
                { "mr", "1881cea94ce39d6365fea37def5a61243cca701c69433754d990b7bf5b6cc928d86a5f45d94ac6d5194e878fc596a43219093f851e9445ab0388b20ae305f389" },
                { "ms", "a1561bcc32f9f63183a2f4483dae2bb1d425da79daa3b0a3c55de4ff8bd3a5b54b3905b900bc9d25e114b3eab2cb6a809de04b1b039d2da75a2d607e5999dc7f" },
                { "my", "4d2414e677aece081510d963bdf9ca95c2ca349ca55045f9ad207d4626ddd5d73ebe76d0c5e9f3355f49cb14d8dc151373ee1cd8bfd179ce231b0d2db648c442" },
                { "nb-NO", "7574f6ec107926e30c5a8f35ab114c394f645c0825b56137015f84f2a6a1b8ebee16079f2d4df3dd5196d390a1811122a33b15f04f9ecdb13d305cdb1b0bf84e" },
                { "ne-NP", "a42fd079e67ba78f480101fa66cfbe57a70d107d09bd003e8dc5b9cb097255f84eb68fb14336903dad21d5e98b44d08b6de8e55cab8750e89ad8b7a4ff1f3a33" },
                { "nl", "cb24f2a32a3cae558332e38d03a55462f2f0a7e70c6c172ad3432ed637390b9354bf3d941e948384a55accf82dfccc6bce41453b47a8b7cc6e4c333e641f9e55" },
                { "nn-NO", "d5518ccd7b523083c196d1a3843d8ca64039d894d37ae966ff0397186aeb83f03b08a1dd0fd7520983380c51b7c4cca43aa66d3c1cb869d71d1bb5ceb7bd29df" },
                { "oc", "d56efe914b956eac972b3c8c91f9ac82b08e49e27277df9eded5f49414a28f49b59ed201b0f8f8dce7340db29e9d46dc9c07f0ce28d119844f168e021d91b2dd" },
                { "pa-IN", "ce8f94683f1a74b60e1aca22dbda9cd3955311661097820974c9c6357bb37702b117042f3eaac42d3ff8f9b036b468f17f80db027c25c2a6e9a055de62ff29d4" },
                { "pl", "b30386022362e8f4eb87399d6a9853e8fa6263bb811979cf6f13e737d6cdd425b3ee1ab88355dc9fdb56ceaf9e695ecffabf339f5eb37d94d664e645c65898b7" },
                { "pt-BR", "30cdb941136927ef5a92576ef8a56ad526e908d9c8a5dbfefcbac522e4d349d0251eaaff87464c3b6ef14a6dee3f816bac3e14ab24a42279a991ad1e64cc305b" },
                { "pt-PT", "765791c9bb35e2480bb41c51ab85b437e6158f57a6b23ca5b1533ae8540dc58f9e23194d10001f3fe3285b52a2c9783411992e6852aabcbabf945c6c17f722d3" },
                { "rm", "870f254d2bd72a3299cbbcd206938036ec82f70970af15975bf1cff741cba73b6960e3369f669abcc853e4d0b363becbb01e17d3733ec369d6b213d638c3167e" },
                { "ro", "bcf9e72fecd1a29eb39176097fefad1e56b8d2da1f6733ed0518290729eb657a496bd1f3960f0c2a3c2e46c33750156e7e51698012503cbeea9b9093fd4b95e3" },
                { "ru", "1359c29a93ba996fc8d696fa818a8aab4d2e4a3aafe6bde24d0e9e13e7609f19abb1dcb023fd0f9868a10e7ea6405bd9a0921ad259a8ade3c66fb44b2c661115" },
                { "sat", "cd840217f124fb1b18cd58b94b3de78ed9e5d8aedcbe0465e431a86f29ad75740cba96115ecb77e286f6f46bb8ac5d565c92ab92f2925251c4e41208f8fb8bd8" },
                { "sc", "8c5f5e8a040b99ee4b4b0d69c69d91bedf5484b1ede24ae53b09c4ceb200a33fd86206552f192526906b018aeeab47ab1e906008f2c82d46bd18bccddb6ccce1" },
                { "sco", "8eb90e497e92b284d56aa4b169f0ef44d9f33c140e8d76afc57efb3f1f115fc56e4e20a511d3b1ae7d4a1a777ac57663478027ffa670ad6a1dcc3c5fdff2052b" },
                { "si", "5ef896fdd88e5b80edf67b7ee136dd210bf939fcdc82ef11b9a2b2a6ab5e49166f9a3b60158b9d397fcafdf516fed98695c740a1562ea8704496dbafc03f9ddb" },
                { "sk", "6864bfb07bf9ca2dffd9ec7a078976732c98441752d20e0a7e8b2be461d0278534e8a1f71b37d9ffbc866b56ad33b2dbd344d57f0be6953e1ddb643737814586" },
                { "skr", "0fab6773dc9ce936015698b336f016e6b94b7cbd28dc28b07dcfdd85cf4f661955d480c3a4a6f1e1e1034580c5eba92c757db710e84ae2de1caed28dd2cab3db" },
                { "sl", "dd8962f0e1bce93b6f2d99e33c4dce6a39e45a1b1ad0fd7a611f4cbf4b5e030fb6dc2c1fe6d2e20f227af16d4e09260720bff00c13e83e8b4013e6193eec680f" },
                { "son", "2ae0dc46704aa27bedd21617774ec466b6c031dd72fd2c2475cc2dad5bab4f874a3a5865ab0adaf189d2a615adc35d63613a65d7a258aea8128e310390490747" },
                { "sq", "24963e609b8703110495e0558fb459916eeb46e54cb27b5a8a166891a05aa457b1f272e906c75ee5f2323feddb6a37663b783a495e083e6efbd1d4dbf49ab2e3" },
                { "sr", "ee955b7d8698b6a66e8b6cf6bd1f7dd761a483fb6911068d772c33e6c7ec53e64512c70d07ffd1cf064a7bdb82c8628244850f77d6cfa18e722b8b6fe8d0ee89" },
                { "sv-SE", "4efa8f937d5eddd02c2e089d76edbb3941d0bce5fa40c51e32b73e77b8ce006277594c13d207facad72388a36f238afcfecb81397a48005a3e4de30062c986c9" },
                { "szl", "b41b37070115b163601518f9c7deae736f4f26f2386aa8c8d48b743e8485ee607542e320c7144892c570bc714f1c1f845131af87b989748d4f757878e534f266" },
                { "ta", "90b31a0c75e54533fb24e58a86eaa91230d2b45d354c453047dcdb0227506a2fa14a2b5eea23a87e8e75d4e370e7168d17f1d29aa65412fd752bdb883bffc605" },
                { "te", "c180c57558e98fa1e1a2fce444388537393cdde3f015b7223221b6a8d2039a454fcc356aecf843f27e9bdfce11d6c727837c20fd079ae30a15e89e12fea2a7ed" },
                { "tg", "edeea816cbfea09c0b1c5c7023d3b82c632f128a0085e51410d177c5aa1b9c62a14590935422e87f4b6dbe00071a3a378abf1b1357ad7c8fc0ff39990135ae8b" },
                { "th", "cf2c145a1bfa2da95aaae159d0ee20824385d3fc9020b7ba0fdf619381321618455f57b083a0fa6daceac89051c85b5330f27678ea26c586ae0fdf9d44139823" },
                { "tl", "60419d0fe2c542c750fc168a4832248492c10d6502f15bfad0d02145593f65239941a43e75e081d6a93af43e608d3933c112663d02fde3222402d3cc71523075" },
                { "tr", "0c6101c645c9879fbbb1d465679e9ef47431cb58c7f8df816daea2913738230316b6901728ce3e9fa289c6f1d1ead068e500401ba1efc7a5fc7c1382198be785" },
                { "trs", "6f3602768e7cf039a75ce2ca725caa09f31dd59389f44d7531ce8ecd2cb095817a93cdce878c996fe48224cc1fec5da74bdb28091b9ff52a464f5500419c7e34" },
                { "uk", "09b28629a18df63e343e75fa837715eb277eba9587c9454807a6c89761a96b67002e912aa55140d9220cc93ee15d7406de1a21bdfd5ff5f7d4e7d0fd4fb90991" },
                { "ur", "d4be8be3e263993197f000e75c05bf5fb529ed4d784865fbc4d151ce95954ff9cf978b58156d6d007089e7590b7f331eacdd26bf788b4c23ad41095c7b2ce481" },
                { "uz", "4193480e46eb106bec9809690f93da51fba721535a9e820ecba517212bc0f3ead1624ad846d118848f5b9a011aec5e9d28486c902bce38378d09b7236e135e5c" },
                { "vi", "9a5f949298537a8e72fbd6f2e3d118cc82ff5b9fe31dd5a77cc10ef98047d4dc0a06601335989f29d353bd7ddb8d387877cdb6184d6edd963f5dee24ac4e4c06" },
                { "xh", "fe245d37709cf17116b3e4b47599f1d13b01b05c8f5a297105a246ea4666919f4dc1b9e6117ade9b22047a4c9e7e1f03205f28cfd8bd3cf2639be1e338f46e8c" },
                { "zh-CN", "f16a734953bbd610df9239fa2d1e134892b16640826b2b20d7d903d020107105367fcc0b3ae18f10ee6d6332568621c53f92c3caf0f92b063d1a68748d7aab19" },
                { "zh-TW", "761e30ede7e87ff83da2c3bfc277c62f37338b5dad2b7b425c104b65f5f13a9a63afeef250a0040e4b22927f8e65ac124d34de8f3b06fb17ee11cf343cc43f9d" }
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
