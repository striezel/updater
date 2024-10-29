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
        private const string knownVersion = "128.4.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "96b07ab8780750a23c3cee2801778608112d39c1b2d442cb94fdc6899db6c5f1868d699864230eb6bb25ddd64bf89bd34227c22bc9b1eee1f036c8d0d11c044e" },
                { "ar", "c8e1a876dd486cc749f1893c692856b789ba1b0cbf8233b73a1ba4aa1efbc8731c83e80a931f81a01c0697530e2bb3322ae5a59dbbde5386cc39b3a2e8fbc152" },
                { "ast", "904a0d6ac291dd113332c8ae9adb6ed309501971971d92e62ee90401a738bafa7c1acbda5771c12ec9b9798f804e7f8c8f870c99f38492eed10d9a85fc98a862" },
                { "be", "0f74b501a67a5541cf455c66eb91572b58113e09998466ad33a9be13c05e86cc79dc9da7c23635177795a97ba9dc51d2a224ba598a5913aa47a4b6fa0d25183d" },
                { "bg", "e91d8c60548ba294aa71893da36487ad38df2f2d5e1e7ca991b97a21d8e9f2dec983471d3b614875936464b0aa6dd6456feef2761d9ef89a2b24bc4163c715a6" },
                { "br", "cf76a34dd12827755bd4d2be5a95fb87f71275027c09dc8b3f0256371a004a8a987fef55a47e3512915f22f73f75f7249cf517ad2cee772992149717565641c0" },
                { "ca", "0b6a35c0cb9057dbba06c4c821e87025e39b1db13b89b02a4b4ca4524191e72b1cbbfe8ae7a541517c531501893b1628eab1e68d31bacc2dfe2a709d62ed8e3a" },
                { "cak", "0d27d1db57e979622d60ccb60a87c2885f32a4bdf47c1a389037e4ef44982559d3f9fbbd9ed1aa161505dce54c6f2adb947beb0d6c1e1cb38dee093f46ba79c0" },
                { "cs", "1b523654ef12cfe099e0daa9b9dbc5c93c6a3aece158b7fdd4d8f5ecb17b661cde1342c06c06e9dc1a35f18e58d9a412c2efd507e893693b96763b4d9dd1d0d2" },
                { "cy", "4a5e04f1fe211da6855502d58d07ff26fe212d1ce153bd503b86ae16699514563be903a2d281b27835a229e05b7a56b19b1153f47a4f2aa65f470353e970a470" },
                { "da", "ff1c95b061a800382cfdde22f57a7e113355bf50f20dc7b3385fcfdda59acba1f5e4999b01ea85d61a1e33ad690ebde93ccf456e3ea49ba3339bc08ea9cc6db2" },
                { "de", "3a8ab043e742bc2e8345677bbce5e82167bb0de001de0966d051f7a421b3842d94265f2a948fefa4d82f9272e30818ca7580d928a2a583763d014442827ddeaf" },
                { "dsb", "507de4c51a5a46fd3ebd427dde7c6c2cac32f0bde0e8fc1140f6fb71785df39c29e1d7778824c03ecd424e994b16517a6f480c912350f51de62c7d1e6a329cc0" },
                { "el", "385b9c5cf7fd1a26909bc83e9640a8e3c657694c3cbc85fa61520581a67e09de2e7a500e54647eeecb080f0eea37b7e99a28933b2d9ba582ba3a8947ea15f8b3" },
                { "en-CA", "ce18c5a49a95c3d67d78834e6a798e84861f5c8a884feb5daed87ce5f0d6553fe28ee765c49f551f5f76b5ba2d9e4de0730add0b9c6d2740d0b899f02b05ac6f" },
                { "en-GB", "acde566d3d6c70d6d7653dd8aa9c31f7b54d969b03afdb2299f04807feb53c8df8df596ec5e58d960d8b7b609d889e79cdcd19982a707110c83a554d6b4f6407" },
                { "en-US", "58f6b2307318e585d6c7d0348a5c5b062960df3ca85852af13e3c5194211d6ee57a68155d723658c21fc102792ae156eabf7481f5a1886d8cf44989bee892fff" },
                { "es-AR", "94e570ed4857d757009e9efd34dd24ddcbc5081e3996b8e2184bb10f45a50850aa87d058723a55d7f4d32e8e7eefb29212c11aa6f2353e88cac1b408f54be570" },
                { "es-ES", "ddfc95b382c9b0ebf98a5cdd25a99511971a73130341cc6f0913d6c811aeba8e6257871d4fa73921c4e1b4861d8cb541000bf98187af6add003d04b77aadcd15" },
                { "es-MX", "10a30fb69615fa1e4411f2d6bf1440f74df4d107a2794a983898395a4efde360d93782495dc0f109f9544940158f8c12d8cd0d296c0ac8a986c779a6d7da9eca" },
                { "et", "c2a2814938ae8052af3e8e24a9a024a15942206474966871f886438aaf9177b1375015183b2829854da763525c222afa6df92c8bb7b7525a72c1c1594ab653f8" },
                { "eu", "d917c22447312f0a61757aab60b6dc6472841877b4c6dca747ef9b73f6085d8e4e30db25a0e975df4af744031f93246785b65e7891ac5441d163662183678c0b" },
                { "fi", "f7fc8ec8cc399f9b6b9bbb5962ece91dedbda6e06ee9cd06f6acc90744224f016f25b7f2fd4cfe3a896165b522ddf7683bd678b5ca57d26f4f25a944cf23f956" },
                { "fr", "0f9f201abfeaffa5fff701fc0a5ab9d35c66b1d8a951cc9499768951251e5a0e8722945b8d6cd13490db9e6ab534ec68f93ca6c4564fd764191dba9ced88afa3" },
                { "fy-NL", "175d267d9b9d810fc04db6001fa92cc7618deb08e20195fe37a7ef06ebf2023361a3564b663d54828185d23ce95373756e7652bed6d18b3f3df82db5f030bd1a" },
                { "ga-IE", "fed3bc8f04cc9c28c99afc8ff7348823d64e7d9d9262a5e6afe1b203cf041c701b6b32f7b6df71e2fbcf227847999d603dbfdb924de24c69aed1d86f6fe56139" },
                { "gd", "e81856e322ea1b02d1f83fd4e99245839742bea3e1e9acb227f24e5f34a8b6caef396e47644067ee5f1aae9164f73d2730095b36747cc43d85e0edf5c63049f7" },
                { "gl", "7d66ff142b22a3d7b14347c7707af67ad182837f47402563fb85970e11205217c1eaaf7346646b8677921e3023117784ed20c322904c38fd52874856daa7d59e" },
                { "he", "ee1b215f75cbcec8a2784152f22b38bc47851bd3ead46a1034427f33f124f27af840fb4bba34523daa24d8c9894fd72da79a2d774c85c2ddff76f37a9749edb8" },
                { "hr", "3969f073f225bd51f8d3e844ce397dfdd4e397aeb1b2e0319831cb2d9ddc7b1820b98fbcfe847950367340d2f80551d8c2935b379698a67562c1cb092b37316a" },
                { "hsb", "564acc99a1415c2d346e2242288b5fb615c13394d6525bcdbf06f9828dd988fffa1b7b258757061e163df52630676f859af48916a1f61698c1ed8f9c2c17956b" },
                { "hu", "6fc0355dc264066318126591e942ee9e02ca44bbc550378c8e310e96c835c00cde01d8994509071b4448c9714acaf0c996a939ffe41ceb0d4bbf1303a06d9e1d" },
                { "hy-AM", "7f0d43056f3153445b9b8b91ae8c5bbb94887c8c92230ee2c714ec5a72147128a56e2c498ff335eebefa6afac14351e2cc70ddcfa0f19d6d2a8d520b68e0a0f3" },
                { "id", "576957e4a658f366d7e8908592b4c07fd781fc4bf6d13538dcb0e2546dbfb9e60ab9d7f9ef99e3ab188fa5e135cab50a332abca30851653acdc26a628ed4d0d3" },
                { "is", "8f005e266e3aa071f9785ea3e23feb927eb50a430b4890d58b7cf7dbe982ada05086c8b18be19fa06f90c2c7d262863dc9459933d8845e5a7e77a171e3f0df1c" },
                { "it", "dcb2bf829b107f29ac7a08ff7c15437b39f6ba720278adabf4ad504044a86f08771501b90f48478d8ad09ad8a42d64a10128b5a0c847badf42b2f15315d6c2ac" },
                { "ja", "7c7a64c783d248731262a2c7f97021a6960e7028cf6c54df6d2ac23f33396507d340e756449a32c988b524cd56fe5eca3cc4f4f81e89e8c6b858da5b5c360aa6" },
                { "ka", "4925f74a26a227885556b0d7ee303f2ad9deebea28d540a1005d66dcbc0c0d618ceac86cdd3b86a40e14a68810109e5280691c1d33dd17493a8b0378e280c7e4" },
                { "kab", "7f54129929f3546722fb46b8de43068ef83dacdefb9dabd78c33aac0fbd69a6519b75e2ac388ad8dbcd03acb57165fbd92e2ebbb34ff4fcaf2ed8c88a77d7bb0" },
                { "kk", "88da4f53376a0c0e9f3feadde714f24ea155df19785afd8d769766201191151acac7a0a472bcbe001fc75ad5b3dfa097d9f280a082dafc63d1c3a32fd4dd4263" },
                { "ko", "8d04036baf983c05715f470783d87c5401c78d74341ce4e6a21724fdc422bcb8e904ba85f6bee2d8fd05df427724e48ae4b2aec0045e3dceccabf052b6538d4a" },
                { "lt", "e29ebcd141179f617b4593651a1ca6d4a78ec66beeb0ef7b529702e0d638309ad67583353a1d12fcfe94c88b927177196099453eb35385b7e42b72edc546254f" },
                { "lv", "010ea486f36bd68d2822aae3826666e297caf11d41479c7f92c345fcf68cf01e08b069b42ae93c0f050ceb12f8b9b2ee09bf57bafc308ef24b50b88de6755795" },
                { "ms", "f0fdc729be255733b3a7d8412fc1b16cce19f5c7667be05ce210ee8b42493f4bfd9bd257c74b740db16819d6b315eed3b1abd4569876926f5264e6b20c154662" },
                { "nb-NO", "d6d4d1a397b34471f6fea1c149a3e9ac1fd928cbad0b8647a036665f9ce950a5b2d61e6e72c09d8dfb850c530103b1aa38e9236e088a4ac5a8ba7306596e9069" },
                { "nl", "85bcc30a928a76f38b2a3922ae8f835af2084dd89af305ffcd5960ecc4970d387c8024490937997fdb4290f2c63829b6cf8b0a7baa2c8d0b11934538c3eeedce" },
                { "nn-NO", "02378ebabcfef862d15faae60cacdb1d8111f87c2bcaf88bf4b57b85ce5cc99e4c89018cc81a57c8efe4ab85293c4badd787a130b6d07f4c7e7063f4cdae2197" },
                { "pa-IN", "4c15d26673a0ad5eaad36e52c0ea8385b1d8d12ee71571d43abd5680e90f0e9b40a72701086e74cab18aad29f805045696d087288ee9d275b02cc69b313b7582" },
                { "pl", "c0c845e1ff691b89d25fa95d404cf44dc57df255f418e8c9bd98c420d111bb525a96d9a4d741664ab17a0f30d8d31a2ad91ff43782ca9e2af0146482cc1fca83" },
                { "pt-BR", "365c9d2678608db0b12e24deb12e7dfaa2c285608f49af10245ea2aecb706c40ae6bc7c010827e42782df7d5f66043190e9489bcaf80b8437f81a45b8a3c7783" },
                { "pt-PT", "68d1b7af62150f9f4075cedb45f7a363894cf0da520e93ac066f5f1d4e10e659fa67146ea37e565bc174e7707a89a1bfaced75142c2f67aa0db7e873debbd003" },
                { "rm", "3378e489166dd2d5286146201fe988b61b1cdf1ab8a691d0214be1b2dcdcad110f9c9c0d8fb1487cf6399bb9a7b451c0503cf77a203f52a1279516224b2d8beb" },
                { "ro", "c20055f2c076c1928bf5d06584384926345406a077d64bf89e33c5f831c3ea8a19e052a90f5e25968b1f412b1a3fc096ebfb0303389d7be79a249f1c3c4fee93" },
                { "ru", "5898b0d32b2229760f71d00be59faffface9dfbdbc5e65d37d545f5022011dade9e71e2cbd3a3e4c2f9ea94dc890b50ceb9f4199ab2b762f2225cbddb3dcfd48" },
                { "sk", "9049528cbd37abc980b53dedd0bfdd7d2c8e79bd8407c0c3150661210fc60ecf2d7de1014208755bba23a5be584ef837e27228cb1d8ee0f031b045030c280932" },
                { "sl", "8c7ec3662d9934a4df3f06ba3063c84c64c0e27c90e0ed710e3696006cf45b25794be9f2e66b67a561d1ea460852390b51553207850071cf42c712daa02679a2" },
                { "sq", "7bc9ca74a10d2ccc4dded65b3ac4b5548c996701b378c41d7529874fd0806d3e7a41174ca866d5718a7eb5625b3bbe75fa86b9018b2800cc0ecbbd4c19d818e0" },
                { "sr", "7e0f4978f42578c99b0588dad7210b69b984a3945d37f7bc6f0ab2408f558f63ad3a89d2fee062772bf78945d4e2457efcbaaaa66c13f28928b250c5d906b74b" },
                { "sv-SE", "c01371de0a18ebcc749120ee74bd123db8019ef269124755da4de71b8833dfeb05b53ea39c230fba599c2314219fdb6878b214f7fc8cd569c2ebf36ac384495c" },
                { "th", "dbe41866055f1c413932dfd123bbf24d1d3ad8ed093e3ae88758b0ea12a1d2ec9dc51453c994629fe10b1297945a142d9d6bc52afec5e4e0adc27bf84343f4ef" },
                { "tr", "e18814b4a746cca1aebf26c29a6cf338c3681b7d416244bf0cb16240c0dce2041b4eafc4328b357bd565959c93d1600bd36f3e6b9a43dbb7d3cb17a4fd519b8c" },
                { "uk", "2ce1decc17524d6cce1999288e2684e457ff4d240bda7029b286617acd31abca0079a5d6acc7e6243ad188309704a58d222869d0d766f33d8667f4a0d7a56e00" },
                { "uz", "ba6ae6e153194c9b27431cdc9ddbe4b709fd552098af8185ca359a930ba9549fd5bf51bcbc4724e9a0d8a2f363bfbb92f3ad79da2a0b2d2f9af0b07ef16bcfef" },
                { "vi", "8ba11c479f5d2b767707b022290be1997dd3f84cfe36c64a6a8b7faa4666517948f6b21f7b125ce4d07f40b676f64c2cc158d6cc9fa6816efd0369ce1b67dac2" },
                { "zh-CN", "bae71fb9ec63de00b2d70a5198f39d3e76b1f6943da10ec957d45a0c9d0b0aabf99c49f59551c013626b58cf734d862598cb8decde49162a102aef004ee8cff5" },
                { "zh-TW", "ed8b41f3d088a8d203921c6e1b70c4051d529e7a9304edc3f74434110625f8a49bb3fb2e99c025908c02a46a01d282e59871394a6d5f108063970c5113c1f6a6" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "60537c9d580e02fd6cee478325d4fbe0a95b332705687661f2c2bf33ecfa0e4d22844c27ad1f1cdcc9d1f5b097c7b706a4f3a62da423c642a26d0cd08f4ed03b" },
                { "ar", "0bd747789ecbbaebe1d444183b7f438df2a6d21cbc14592c6b8dfd2a61af694649ab7697958649aed9a41938dc68353f695fe2711472f558ea8bbd6d9b3ee749" },
                { "ast", "fe32b9084a26f7dac85a0c70e98772c5ba27e567d64e8ee7801d1d0304405444ca5ec9f5d23210c1b58cf59025e3fc0f6690e6101a3d62fb45f3eec7249ad348" },
                { "be", "cfdb6634752d1a5d03b16c98aba4cd75c5555ac8943621440ca74570137ddc0c543550f5aedb513b80d5378ce3eeb03cfba2ae8f93fe7a7c696b84bb86d5b730" },
                { "bg", "48b1d3ac720bf84edd9c410ca0e23984463fd972ba05f642eeac2f8aa5e1d1beba9ba509eef59a16f67301bf7ceb64f8e9f403fd6089ed163598e77f9b40ea3c" },
                { "br", "832b1d7f7ed8efe0ea940e0afd2026408c154f7ad63c7dcede785ae8e3da72af66f4dd3f566e747b53c515bca983731d6705c486b588fab8efa62ca2b7cb9051" },
                { "ca", "55c08c0d20b6b4272c17452820f7022995939fc18e894452ee32ee6d99abe685a94b1e8550f82f56adafed4842e1cde26f20f29a0ad69c616f0f07842a2ccaa4" },
                { "cak", "ef1109887ab4cdbc282515b509263d1b702aae31f9ae57c6a3b79c13b995f0a40fed7f32152297e2902ba390fbcf8a015c4fbc636b99caad87c22fb689272b3c" },
                { "cs", "14b80bdb82e31b863caaa56a8b3bf7036867ce05aea3d28f08491475b627726b1bd390747306f3cbab5e1d390b822e3078f4860f35601dc72da5f6346a5b15fa" },
                { "cy", "3a9ae63cc2dfaa1f0d85139c0189ade1be97bfc349fbf8d97d9bd696e134c061daaab1709904692f1faf09ce04e8c685516afe2e6c82325b6e6be989c2044505" },
                { "da", "f52e9735b9b4363d62de87a219f3c37f346d5ed8c48a4b0334ae3be08dcdf1916fe08fe531ebfefe531eed79770ea59a02a4cccad05fa85894d390213f6b2768" },
                { "de", "7dfe1bd7e6d131c9e94ddc2e1a4c6cfa9ca3d3d9b112d468dbc1230eb6f6b16f2d83075597bf28f0949d88b954d6e2be6aec1f55e79a3606abf2161f589c9e81" },
                { "dsb", "9477315633d5a35527651c2198e04862505fccb412e102d27b4a25c00e6c2e7157f39852c3d546936f09f0b23ef21d62d02f63a2f5d57ff0ee7068fa88234817" },
                { "el", "3c7a1f8f9794d4aa94a3ed2f24f12a904b5f3bee9e3ca22db7412f64f46fba60f5f9c57703e5697cfb7ae1a2c4b74bc0ec0452d219eae13eca355260124f33ed" },
                { "en-CA", "ec50711e03a1949e685e12342956d54bde47141c518a65b47fc21ecd5a3eafb2d52495e93ce84f20699f9ef60cd55d2158865dd2ad37c924d90dfe3c46486249" },
                { "en-GB", "937fcfafd028d75f1751ea9047ae6709b6e29cc93313d6458872280be8d397e9b1b5299901fe99b6f26b1d6ddeb2d5fd65991421d4f1ad2d5a721b03a71d6bab" },
                { "en-US", "2ba7cdd931ed7dd8b22764b5e2560b0c161629064f80d04efbdcb9299d266df6df7bb1601cb66eda6927e6daed3f36f8185fdfb659ff99bf397d855ae70b05ee" },
                { "es-AR", "be37e22ddfe96670f2d259295b6177dace88f9d496157db688424673abbefa69c0c3321db3970a1b5a90d7e7e55db5deba3dddc3f88f154fca4f6184d341904d" },
                { "es-ES", "228644614864fe4be6dc72396c40ae641c5db3a1a1324deea115040fb62c2aebb2e5507d27d6ed6feec35e1fb66a57724ec4788263f9a4694adaa655d7bbe016" },
                { "es-MX", "68b3327ac15b317ecb9b6076ff70cc26f1eb720780a7666e73e0778b2c6d7d96feffd5af48a0b5f94e387e8a09e19a2a0633e5a1f08747c67618d9cf88f69f40" },
                { "et", "9d2f65bf427dad4b66ceb758bc8352d6c2890957b66999020e0ab2937a8a925c9e526262358113d09ec7c63fcf082feb65533e0f3e2fd7686744acf9f994b05e" },
                { "eu", "38e773ca8f366353cf2e9dc31bdc4a559d3c6a4fc1c253d422493bae45f7ac2cb4993b8c7817a0a2e6ff15f2c6b825e89d6c3e89db5fe879f102c831b4f1b15b" },
                { "fi", "1ab47484d97d04fb72758c2d763e089fa02dc91657e6b2dce5ec1ecc97c23673ff255e8ad1079777ecd8ca2c3b2c387368292bdf42acb0992a24bc6ae331f2c4" },
                { "fr", "b7f8f41c693c78fadbe082a24d56cb015b462861775cd253776e18caed83bce1131e029815a4c661ed82b0e11121d4a85f65979bb1a725c961aac1298f301372" },
                { "fy-NL", "dcce1f29b3e0a2f1bf158554ec7c8779f647438078069f65b7f3a03505bf612757b2414274220242a3a6ac630d1d2a51c9f801447804e2bc0d6a97cf39db9cac" },
                { "ga-IE", "8adf859e1b990ac26fa21e839a828d55dda92ed937516f073841b3e39f909dd9b5b64142d10f95c2a3b8a6b2257ded0b736a0565cab5b44965e6e8020a2b1802" },
                { "gd", "d9689b16b9f18b127e43df25148f9110d27cea85848b82783e934cf0bf682d64bda6d4d01bf634ac2f0795fe0190544bf746c6498812c6a6066f79024d33420e" },
                { "gl", "1e1d57b3a54bc0272bfc1e724366f74b8a6e0175173dff1ad5b67078312cb4c8a581bfca943a9cba434f0799bbe12664db4a5a27fd15d309cb970943ccfdb20f" },
                { "he", "69a4d900c71aca5e59825b08956948780a7e6d705c35745b3f912c54f91aad9b75ca5612e59d79d75760cb4ab6f32bd6e1a05605fd0a25c16e47daf8fed109e8" },
                { "hr", "d39d0c8e50ae45446f514181a87a8d172b44a1fcce132cf85295c3cd637dff0a7650874003ef1910b7391840cd13a910747487d50d252f236108b170bd27cc1a" },
                { "hsb", "0204120956425f14e4a2f2a61c1966cf1d9dbf56038c2aa7bd89e78a548435a0a156cb86125496e49ddbd4f5b8b56db4022b497e57f807dd166fe2314ac2234a" },
                { "hu", "b0f10ec5707fc53491f8898850f94f4eea45025aa6f12b425946fd521d9cbf13b4ecd9d0d29d43648fe93c4614ef6255750fb3952eda3b1a06ace318261a3322" },
                { "hy-AM", "c22db328a1084a0c0049d68adf3a6e4ba2c4b015bf6bde0906fd6569c6a504c16b11bdcafdee45acd4d6eaaae61c83d41402495ca053fb12ceb0685c65e6fe8e" },
                { "id", "372fe1ad03d8446f52ec0cbd739128e78fba0aaf0d68d0a9c16ac45dc8e17a2777eca88e158e583600c749afa50726a7a4059bc079d93307d019becec5299bcf" },
                { "is", "d76ae1fa45610afd3848d24638fba00f3902bfad1231b3642e3e37a336631cb10fb4ce731867cf152ec21bb2e15e16f39551c82a465321106a61c1e71c10f0ab" },
                { "it", "40662d69ba195678ffd0e188057f13029e4cd21462b93751ada31d301df03621922ecdf502daa26d247b7ac32f6f666e3556edb31b2a12975c5b3839a38980f2" },
                { "ja", "5b20611cb77116ed4cab67b0e306ada13e029b44e3e791ed51136300f641a2b53ba64b15eb83737abb1526bf080f9ea44f53b830b03a83cdfd48f36a6826f33e" },
                { "ka", "4f84e369691a5a5b78511cfe6329219e828f3b53870f30a4ce0e13bf35a6e24c3d222557948c0b3252c1bf69365772e908344c91760c00f2c3558b8dd1bf44c9" },
                { "kab", "b6819795a8f97a84798e95235907f7fd13d0e0582d98f5538c983c50696db42ba60d4602c7f55b59147dd1487bd35f888ebb352b24a8331c2ee04a70bf8d7c80" },
                { "kk", "ba9e2db2182f93870f998569eb5b600f71ab590eb1c346b592460996720ea6b8da3efa1f963eb1bee09bbbe5011e37c1798346d7126bbc12925b9effee5df951" },
                { "ko", "7876f855098d3b738ac188fe6e626e9394292cda6e5ec98dd43c32ee6fb594ff441ed43513e75fb74d7af0cabc16ef5d465d466fd699b536be28b9fe369481f9" },
                { "lt", "b1e73fd1c86eedf9156d8fd1b9c1c7ad60cc7f5856c3ddb9414f4fed3dabf87cced0c9fae2b0f98735550537d3601faebfab918b9da4ac84e876d47fbab87aea" },
                { "lv", "b6ad0db4f8547628a431d79b9f277239e74a41b6363bc32aa9561eca8c93cfb391c1f383909804c65ab8649afb276fe8a5940b16fc5f23b2aa6eef0797d6eb95" },
                { "ms", "a7befdb0ef78f4036c06a99b0347bdd1a40bbd431f665465da3c4ba913865aa629c37910a4d2cb1b12c72dbbd2725575349704a4d89cc54c97ea0a8ddccc3434" },
                { "nb-NO", "a7e49eb9f0a6e4e0d919a4f8e75e9965ca2bf9a2d7647696494f3ba001bc3ba5ea70e5725edc89c2b30a99a85b76b1067e540eeab8ab5d9472e894464532d236" },
                { "nl", "5ace45126cf0ad3488ea8fa5b2ff50dce753ebbfe0e57f0949741131e06ad7d07d3010ad0ae0096aaac9dcda553d8b5979f197b5397f2c429ec4a00ffecde476" },
                { "nn-NO", "5ef6e9f79035de36c8867efac55f66c62ce62ce218a53fac10266cb186c99d36940b28b117bf9c26bfabd2ddcb93f83c17da867d0329f8affd37aef451eae232" },
                { "pa-IN", "7b62aff391af1cfce24ce1d6ea9a4b6debf654c9ab91dfa56b17f7841998a67d8aebb97a1a086a2a597b923d2dd8a1f7fd34ce2a3c422a14aae83ca29ff4f14e" },
                { "pl", "b4da9a7e8db885df7866819bd9af0c117fcfe3fa6fff114093057ea405c28a86d9a9e0626c9f21d802f5e94f2bb9da669acfeea68f372bd33c968545549dffd3" },
                { "pt-BR", "6f18e24137f348f42c10b879eb320d4c0b53dd0aa23dfe5332a28f1d3c10c2cad32e3731118899e323b1005045e7ccc8fa0bf5263cb9a61796368f7a42e2c1fa" },
                { "pt-PT", "7dd87ca8d669c90b5495d4cf88f096e546fa8e712e62c769d100a4be08e13a8965962a7e1b38c23dd85c360a445a3f87f38843a30e4634899b7d38c4ba4e1561" },
                { "rm", "43cb035e1c3d17fb29d7a0fff15a7f3f3510d78c622b4acb47790c652434396cabb4b4d417599e0e8c2ac96a5de109f7dbda1e382e6671c2297905d73b633378" },
                { "ro", "344b79f14c1b8a6ed5cf5168b6f72e4c58b8313e59de9e8472c491a012a36fa019293d6149d8b48fe8ac3cd3460abbfadd038461f37578cc352fbc2fc23f427a" },
                { "ru", "5b30d7fb1da1b5961dc2e6b526a33e9c23a82feedd566ef6b9f9c3ef194df79104c5a6abeadcd93fef6c4af95a4a0da9df3f7b680887b0d37683f680f1d3b399" },
                { "sk", "819623bc49bf862cdc076ca7edf6ca200b1a0953c08ec37d6f83ab808723941ef2027584ea4d251c7991ba3d90cd0306b6f296e9f4a7170b86bd107bb61965db" },
                { "sl", "4e566b37baa0ddad6b39e68a79cd51bec621728bfdc30aa5cc4ec9aa01561a7198f9b4f8285cbcaf49beabd54cadfa2f329b1516981f37b13902962e612d92cd" },
                { "sq", "5e05fb9c9a31b68055f9e99efe13ab58e8e2df48dd4da1bb5430fa0e039ac81f61818074c2c8d53ac1ede1be65dc66c8aac723c7526747e7a4f52c55a8702a14" },
                { "sr", "bd3993c29d49d4b656eb9cc089e5683dc310013e539655cd85fa38b142c6e9b604f341ba8ffb4e220eb1bd3b966dcef96ee9882be4083f67e6c8dfd9c7ec05ad" },
                { "sv-SE", "c9e411fb9562df5c81d0e9bc52f9eb8c8861392e0cb6cd02f3c7e7fa8a5a651a9b311260431276a5add0551c52d0f5731612046289c846b646b959e4d602538c" },
                { "th", "84a5e45a8278ff9605197fbc784fe73cb652bd1e33c77c35e35aaf6099a3148b6b84f55718977c2a42634b4887f2236e2ca45b2900e34181b7e0c52041125dfb" },
                { "tr", "6d7309fd0d02b1dec67b5a6bbade7af7dbc1eedfc883e815d4d329a1e23db825490b0cdcaf06670b2d9ffb47ca9420922237bd6bb1c6d40e1770d84b79312406" },
                { "uk", "e1e0f73ab49121084c21e36b96be7ee9cbf9f1358946ad1eee88a69abb343a12f4acae2d2d656d5442c2838d1aa3ff7f0d6cad5ad95921632b2db18ea195886b" },
                { "uz", "4642d1be87bd4f9759c9ee1365444dcba994219d54b015984472285517d065965f091165149b96ffc6ca03dbd4be710b30c3aa655fb22ba396c1fab0c3097374" },
                { "vi", "6e31a0c738e29458e1e7396dd25a285f499ce05b995b797f4487dbc24704de4012671b9a5a3466271c3c67a4c3bc4684a8f6c441dc56de0398bb8b3def2f110b" },
                { "zh-CN", "550d4092e7278e800453e14e829974b9539c49f167b12dc7e0896ef0c64d94b6b1c5fbccc41f542cba5ba941741d31f69871c262b7f8dde23638a67e3380e558" },
                { "zh-TW", "708cf72632aba4af71d128566a0612207c4c2d114ae4e1f31187d2e8f7051a2fbcd983c9e721e2833008580d032f6707676097293faf4c78d63f011bfba21806" }
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
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
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
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
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
            return new List<string>(1)
            {
                "thunderbird"
            };
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
