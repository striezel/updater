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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "134.0b1";


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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a0afd2c1980cb93c2db73982ef72a9e1c0724fff6fd74660af7e6e3b8872c9befba0ce8bedfd9c13314a8e76d38f807b6522d2bcad7df962dd7dee8903ad5463" },
                { "af", "0de3ad479fad27b3944260592cdbb1b6f460631f707a7eacdf46619d6cd7f554df86be0e0202b616f92bca583694f9c2c378e487e2c449def1c6ab9148323290" },
                { "an", "6ff2961faa11d92cb5c91d357eeea4caadbaa9d908e1a4951cd636f55e9cdbd5e465b20a0c3529d1a6b921263f1e2a3558b8fb1b4a3a5a6b4a2ca786eeaea0a1" },
                { "ar", "96823fe4b5238500bdd34ba6cfe2484dca275d394438a6f589f5c07957777dcc5c199ef883cc2b3afccba57928c3d84bf8a0b26b8dc9b86e852b42a8d9563c2a" },
                { "ast", "e061d1fa9b121ac882017f9a798d7e3b3f124ca2490c139d6fb625642a592848af7ce52717efbdcfcd3b2acb9b82c669ed56d7eb020fbd324437a03ccc2baa4e" },
                { "az", "b40a3b6bbbd031ada18ac46a83b1b2a03678f798761cbc0336b680db62a75c6461e75dc494b6fe2f9e1ddfb69c490e87977074de36a19d406fd2512bf558373d" },
                { "be", "e9cb07d3fa4a8dca645cd70d8e5434aa10e4ce93d2e5c8185318fa645ededdc1f7596f6c7af8d96852552e8d2101b8821c0fad82dc767148d7a585fec3101c02" },
                { "bg", "590a4a0024aae6fc9523c2e8df3df14535136d3627655e7a9905a11caf8a42d63ddda48c2819966347899339c96dc3055c91d264166f1878005fe385ee03dcb9" },
                { "bn", "26c72a59e4d65af5607fae10984dc712349dc3101514b11c5d77e08304f0dc3de21177738ee0b2743003e658458178697c20df6bf8bf3a093ab744a2cf528e5f" },
                { "br", "aa7a5f48abb050999e7d837d6ca0d8d7ce9f6057b0f3449ef93f63811cd1c455e267060856a8a2752f755a2dc49de3065d2f0e4cbfe3cae280bdfa521f29c33f" },
                { "bs", "972b468f67cbd53ed8bdff92db42ad6afb56d6e3fd638eaa1d72cc677d0c991a11aafef94d5cfc818adcbbbf71b3655e0c3340f5d240ec16adad5ce66e90fbc1" },
                { "ca", "64ce77aaad6c99c3e0de1cadcc9f778d131d54be13df6cbc3f35f892fa47d8208e139693b7a553a94549b34f938bd074376775b311f64dc1bc8edb0c79803300" },
                { "cak", "2f3e3365bbad8851d9c117cc8581aac778094ea6b8779ac52040b89dceab5bc90c4e71517e98742ddac58db48dc26deace5ce228d311d3005f78224ffbfc7651" },
                { "cs", "e2aaed4381a0d9e6aca4f64ee9bf74f1937ba09b621f8a9c69305727a70e4e2a04c944a50eec83cf9b13774f6dc4232cd0de429bd7a4f4966740ad8e0024ea64" },
                { "cy", "8774feea6ba6476f857b23c939734edf63d7f9302af0bbf9073bed5feac40d8ed27b4d7f4c0fb38c85b89b07ba0c85ffa5e5227a5211e571c0af056bf186b841" },
                { "da", "f4f61db882b93fdf6c671a04ba83fdedcf5180c877cd3f533b81e22c2971086feefd807aa3aef6d3535ec926045fc77847d456a88689467e1453c02d97b0afb2" },
                { "de", "0ac207e8e43959c97b1ac7c35bada67b0a9ffe6334e26f8080e93c1770d4496a42ef67aa760f9e34e899e38ddc9e6f5344fb61bd0da71788cc043c399733ffbf" },
                { "dsb", "f0b392cc7cff0e98999035fd679a743623a93d3db5625fc1aec17c15fa2433b912bc13c5d2d57c870be8353e58e844dac1db4629d479b8ab25a7df5fe028a174" },
                { "el", "c55a63f0288a955fb64ccce9c5a2255c7ce288ee92bc0477a71c5e9f56b2145c271d5f1ab83cfc443e923d63d34ac1b8e0a3d9e6be77229eabdcd7733bc0eeb0" },
                { "en-CA", "b81331dbbfba6b7fc459807330adbe448ae0444bc996368a571495f0c3b468c4608f9a6303f29a5e68fb68009119d299ee4d66a80db4a0bba13a60820d4e56e8" },
                { "en-GB", "8f6bcb17171525dd86aa4084a61438416e38e52b756cd2e29427511409de24d52d70aa33ce18c51b268a428e1369b183806e9918b28abfce367ad5a6b78b5eb7" },
                { "en-US", "f8999b024158bdebad69eda0abfd3443637227a142aee73fe1438aeb0def8b9fa4683b6892d41f598e75c87fb19ddd834a6049d94a8b812435144457158ec642" },
                { "eo", "9534870b68d8e0be115ef657e28c003ea941355467f891ce5c53429d0a67d2049e2f1078b0478ffbac4eed31ff88f49787933ebb679bef05aac5e62a4341fa08" },
                { "es-AR", "16eb013dcfea0e7f5dbf859340a0b0c1a80cf556f4c9741ae3c389e75fd29a219af42a399cf30fb2d4c256606c9fbc64fa231202adad4f5d149fffc68c21d9cf" },
                { "es-CL", "ea9627cd3d89c3172635b91b591fd2ce89f233216ba25de09f63b36472401ac0961daae1a27835dafa4e7bf025a068858fd5bc0807b93344cd1e86a5c5433d8e" },
                { "es-ES", "9893f482e92cbebc0efa9456906390e7a7c3c631406d8a3820c710c51063cedfcdeda3c14fd6441305ccca59aaa2ef4f9348f48b61fd1817868601c7e8c5459f" },
                { "es-MX", "f0874429d9217c1a23046430bfa03b436427355a307809cc13b994906739a29f7b30a3f0e534f6ea7cbfefd7062676ad0e73a6d32a6a0683ae33edad36778f3d" },
                { "et", "34510207a62ef8924f1a9ee3d8ffb58cf0064598383e7b9437a6db7423d668f064f67ee03a21af2bcbc2f8d4e1bab30dc521940471ae6c7d2c47002aa8c985a6" },
                { "eu", "6f2f5068d4f847eda2c9d165aad46b36f7d78cf54084e9d54c3371472096575fecca2ec64477a6dfaedfcc2747b15e2cc2dace1e822ae3f38b13bcc7174d322f" },
                { "fa", "ead0a22f7e2a2c8c84b02503549ae7ec196c574789cd58c256029644f1a7d5a6dcf3fa15f2a0d08d0879ed4c73644fa1fabda5ff85aa47fb882c0b112b8dd0fb" },
                { "ff", "6e439e8986f7a1cb56cbce53935dcbaff22e715b3454e2335a23ab207fe66bf83cd6df924341a85034bb05fcf83567c8118620bb3c72932f83ac606dd51137fd" },
                { "fi", "d5293c8df01f821fe8f28ccd20daac1f798d7da2c4949e70cefb4ecfeee3b27e672f4746ee5e7cc136e193071012127040da5a2d7383979019dbfccab6bbfc6e" },
                { "fr", "12544d87c2080dd49be5faf2e3bb169c04020b69e9f54c6e04c8976e158850da92ee8d44f6153a4d37095f5ec5fcf5b7cf21cb9864b3265952956a3a06457fc9" },
                { "fur", "300f593536649f5ce3fcef77ccdff029c51b82ad2cce2eb869f70dd3aadef1117af2f6223d6e2d19744b40443ea179ba03e5be8d3fdf3d8fe6fa4e3c6f7cdbe6" },
                { "fy-NL", "ec34b90a66a42ddec5b0f4a49f170710e6380ef7cbc266c3e6426fd68b30156e774aff6b76da1be00b30db6d4d4c83e6f0480e67c41b9967b995880aa1c5b9ca" },
                { "ga-IE", "930728873271018b56bb13f25f7093a2197f1720caa09322d135f977ecd1c721711ec82e182bc898326f2732b8a50068a7150ced72300cce5c1b16fdb72874a0" },
                { "gd", "aca106fc2174bb28657ab1ef5ca2edebcb8fc66df5fa9b69e1041b592aff11774bc07e66dd58bb2c96a62800baa8e5202819ec6629cc2ee209095b9c7dda61d7" },
                { "gl", "1d1b51b6a5f8703c238a96fc1d49b2c72d2c166fa9a23fabfb26d3e4ad85095901acec05abe564af39a359ca62d9a9ed2a4442afff1e2de9b7679da4d7e0dfe2" },
                { "gn", "00fd2ecb9d7181bce1e0c387028b612f1c304cfcbf2e4e8bfc23f5a8da2ee844b8359044612f71c980646f0dea7790cca91806d2e384cb5f4b3ed97f978dd111" },
                { "gu-IN", "0029a017019bd10dc67ce41ae06a7475fb1f7a6cecccc8e6cd6653627349e0820f90150bc1bf134021cc625bef2def8e5159b240ffd89ac880d570e0ed14b61c" },
                { "he", "611b8115af523379092de764b1b79a175f3c0789bb53d9c094bdc47c9c55d100474d0934590a09dc994f38c62d3767daf9e601931c05a26c8a7f53adb0a14fe9" },
                { "hi-IN", "8c27e6f52cba6f1b37dcb0838dd6c719147e2fd5ee578408b78eced9e8e78691ed10d2db858f354819940bbcedf9f570bf68939fb6a7c5f1503f6f637af3f5fb" },
                { "hr", "c9fdea20b299de87951a0501ffbd160cbab19fb862736b9aa68a048c60752fb703e75936f00c2ff583792560efa5a3d6059d4d445f7632450ce562b9796e0306" },
                { "hsb", "e23ead7b3e4807d5e9c0bf4bf924d67055b60b86168381cde460a2662b3c395a59c742c876e61f95f599f199c4cf972c5e1a77144df6d2c05aa76c466971d74c" },
                { "hu", "905a244e55fbdd97ccb2fe88a1d8a092704db61d9d8e50feb269861da1c184c6fae66c413ad22302863c314a658d54c569d8b454f1e618f459037e1592dcc7f0" },
                { "hy-AM", "276c7c31f0c7a1261f45c0bc37f1001fd255294465cdace4b6ea003e54e36f1cdf70569cb5475309ac85a8a5a352aaf4faad636b467fa85945205cc4589c9686" },
                { "ia", "de9354b50b93df0bdee85d3d119f1e2b91848bd6c86349cb725045e701e6e0f1173842f0f680a1673bc4ffcda8c4ca6535e63c79c0b08abbd4a519edd6e628a6" },
                { "id", "0a77eab633a370f990c89c9b688a1bb8018ca88e94b0bcbc42bce98f077ff8bf5707e429b400bf0064427118abd163e30103b2826243cb2e11cea17ae888f8b5" },
                { "is", "efd8776d792d30074c8ade09f0a03522add8adf46d4da7acc08a2a36995c56afc55bd8b1a18a02ecf57304499f9d9d6ea63bb1338b462859d2a842ff370a0b4f" },
                { "it", "0a5aad8a2d2a5b9968b76e786e389f70891126822dda9dc7600a2525cf8e3e49f12534bf244f51dd40fabe2d3b8235ee3755f9f2aef5f8dd15a37dd6c248fcb0" },
                { "ja", "83f9aea5f2113bcc14fd447c5d618ad1199068b0e8d6e9e67c892c765c9793eab987174a5d84794107d93ad58b4a21d9b314d91cbc69c5d9cee4e629d0227041" },
                { "ka", "3984d4bec0262ce1ea14e97ba0d52aea1c68cd186c66a450f0ad7c0df260740d908d121cf5c9aac1e2d1172f76b3974222cf440af807105988905a5d2ad5c6a1" },
                { "kab", "feebce819ea7dd15a2f7f322860f8415de9c02b63221debce92382f5116343924d850347ddf2a23ee4ab2b903e4bfe8bcf186fdee79d1f489c608e970a152ada" },
                { "kk", "5b75095b67fef796449583f3d3705dee7a1c18211a0cb9168198521383055a6facc74761e12d90f07c4e5f5402999128898cd307947ba13aadda1f07e3a3d6d7" },
                { "km", "a1b3a2351260bf4d011f381160583fdd929691c73c247789ca0b410dfae849641a3af1412b9aa274df91e64e6905afbebed353b6081c85d91de293146f6695ab" },
                { "kn", "00a556f5f0c315528b22dd89de0fde0b97547e1f4ff63b7d1ef41b497a3c502a5eb887bde17c830dc3dcd9d10b1bf3e0b73d699ba0099b26db681ac902d3d906" },
                { "ko", "a108c5290500bab20c4db8c39fbe48b1bd69a7c9f5838d139fe45ad33b76b0d72572ce6e9c3449eba7f7e0bb35678aa4fc11d08019a86c49c980d4f62613bdb5" },
                { "lij", "a69db9650998a1eb73220c58856271f53b4b8a7878ab1afffddbd8e1cf93b621eed746e3bdee38336d0c40ef47faf4953b0be31c0fe476091ac9cb4e0871e235" },
                { "lt", "6bd9faa3c37ba36ae72092f23a3845ab6de900dddd0b7575efe19f96a099d682c5a839a408ff1af7b30c79e66df9ecbd3702d061907b9e3fbb92d7b4c61634ec" },
                { "lv", "2e26379e93b5f9edbe838220f7ffb36eb0fe85b8b33f0f1171cb31fd94a978b51eb45c2c2def690e21a62426b449af1f0ef5d06457befc02daeb1031defdcf07" },
                { "mk", "c20f4933e630261f8c3460a341a685e7d17b71192a2c58003ee69aad7f6eb1b18f5c507e8723b743f6cd6b30c68f1e14325102c88057cc72c7979d45d7ba6b15" },
                { "mr", "34f95677241ba1632113fce9c72c341fbf5944a0ca0cfe3aab038fac0c5236053066acb2cc56e84da241192c5c7e0670fdc7562d13c83e004e6c163ceb535c00" },
                { "ms", "5707d9e56b2a627cd55e3d3c4bd586e6a5477a88ef78cef3d74505d1fde73c81856a210002114b83af74c2541bbff4433525a4edf523c0693bc4e1dad8505d59" },
                { "my", "1cfacd10506498caa28a26c88e4544b853acce8339229738e6e4c33c9a79a1a40e23edc4004eb5d7a87c112e41f3d14935344b57165c761a838141b9b9665093" },
                { "nb-NO", "6c2696424e94ecf8724a38fd2efbe63d6625759f006d49206d1d29c6949bb6e6890421132060343bb76343df7514848f0b65e5c3171ae2238a3300add63005c1" },
                { "ne-NP", "2c6617a5c234e0b3e850858855bc2054aa5d230ecea35aa8a50c2fafc744c2211fed89657f7fa1d1a01c4aa74e2d6dcc3c3b86bbc86c704b53f413dfbc06f337" },
                { "nl", "16396b84152e010fb31b42bc39cf06c0d9dbb2579c77538c1947d4e8d4e33a1d73748f610975d7c3fbdbae2015f06bbd265fb12e9cdb0120f59b5b74f21004af" },
                { "nn-NO", "64b0179b05cf25cad1877db5b6139ad5f138ce8818f9a945530c48b45ad7ddebf919177060fcede7729f70d5405d4d6db6699b2f969f48a6dc572b75cfe0cd29" },
                { "oc", "46d4b842d31d69359715f6c1ac8da25c78eace720720c4f99ac0cfc3615faf8ebc0a046d49bd38d50b0c6a014353ed5309d2352100af8e71b830aec7a0f40546" },
                { "pa-IN", "028e327931ba76ae14f12982dbd58a1a7d762e7d2b636ecca66183e739503d10d1df45db6fe09c3002345c31f5604b5597c1d12722734d96cb5781d3767579e0" },
                { "pl", "b4be6c5d8feb9ba6778b63fcf8d40bacf153d604d83383380014071f668eb0f9ffdbf3257d5453615c3f8d727311d51d278f46f2c7b92329af7846e9bde5be7a" },
                { "pt-BR", "f8d2f518d70170d6633c297018e440715431368f2f4d99b5f606d20ed38d51b9e27014c75ae7f81d73c0e98086bb156c183a954d867435a2dc61c6b3fec9432a" },
                { "pt-PT", "03f74f3206bc8b7099b776a32808987915d09fb0e9ce28e3b8695e2b4f37fb7b2d775f38044eb6d6f41e25d067f5a011392941fb50785cbd43137b8f097b16e6" },
                { "rm", "4e7fc740d2a7fa9362abffa0a0fa54547de59f1c44fca46923411f558c3bb19d5023898c0f828b03d39c303e1475acd06575d0d8cb1e7375d0f05f1ca0104657" },
                { "ro", "9b0fa0ed271ea95324a0950949f28c2618483da81f0787dd42d2cce3728510f120b233ed42a3725f2a74a14860c1a8237a6e689d582acb7c4d591468d27fea27" },
                { "ru", "3a9fd1da5d5fe3d184a96eb4d17c2ce47d67b64ea9b18ce5bc42478a8b70e3046b43577c173b464523a0706b229eab5e035c33727b1a539a57a1e4776c8bf469" },
                { "sat", "c3b4ad2902505959ec9de122a7b8ad52e31d2ef9a1edc437581bbb97ddfad7426a0a4b16c471365f28cc703773812329b6fd1595b91fce700f9be5c22af9c5cb" },
                { "sc", "28c78641d283772b9534a8f66e0f374d6547c8325a569b7525f07c5b1d6f974140a458fa36a3ba215cbb68b8c4bbba2af8465d588614ac43a86a0556abf048bd" },
                { "sco", "c1a325ab57d2e988189f8c0011bcb57b7230e24b8d65ca7f237723d72752a70fca399c1be5302205114da10a70802056824e80820fed56e2fdb96f56b902fd2a" },
                { "si", "933a732213f9a7fd0b5d82617eaa30fdcb3f0e5eea74f96bff8df58bd58f34f265ad2d308f249d5fc7b575a530843102d3821f693e94988ee629e9a8d5424d2c" },
                { "sk", "06b3e954c8a471b7172651f323a929925711c203b10f603955c58e4f128efc46243162d53bb2faa505e4eedeb0e7ae48c93c144c2e10a5d19bb4e25200eeaf62" },
                { "skr", "f1ec616fe899a8bbf284ca25c35fa11c8d82c5426dacd152b884a254e5de9ecb5d20b885963cc35683636a0e1f34d730b041091f52b5aa45adf7a6ebf7f95a94" },
                { "sl", "b7ec7867836ae875727dcd70c16e328c7ab340795ffbf89ba6d6d291d9d173ede5b1bd3baad80b85d8bb2a2e86d39a8967d11ccb453da16d3197ae4ca63bdb5d" },
                { "son", "4d2fb29fe578ac2aa72c2feec58708e2bd05cb4f7c5364c3e0adad8f9a6791ccb5f203368fa3982a4459520581b11db831668bd2cdd88a64dcf27ae9cf6840ae" },
                { "sq", "7e106ee2d7003046f57df90dfec3f80b6c6b22a661be1d581b5809d64f53d3f9dd8e535e73fdb80bac0f17e6ec78efe1831ca50e7c5266fc78751f703071a67d" },
                { "sr", "35a90158799efe1dea6ba6de244da25492f428ce6677348151fa619401322a528509de7378f525693dc5dab7f4997d6f65d73c2246d4e15466a5c6de8f1b0269" },
                { "sv-SE", "af9cd27308446e954862a9b02d7cd8898dc2d6d5dbac5fe65056bd4eecebc54f18bd4b0383532de099c10b39a419f1e0f91a9fd613ce99bc9fbab6923fde348a" },
                { "szl", "a93ac939bb00056f63b95b122e7df5b24cd08be53a2ff3b17a535e1fbb2fd3a710e12fed75d8a44d48c4e80fdc6c7b3b99fbf6272edde7e4332285fff1c30a40" },
                { "ta", "7c9fbc189a6aba1c7a7752c743975725e0198cb8dc99f40c128c9ec3dc39bdf7b68b5b697c7d2c4700df1916ca28e0870b0a68419bfe38b6e7336b9e4858be58" },
                { "te", "d31f2f19f1a03dd355c08b32837c4c06d5e92da032d1178b86df79d23e0cdb19cf0f93ec59146b890a911312bb5f82c20e569d223f7903ff33f363779dd02916" },
                { "tg", "aed360c0bfbdb966440f2d379ef34ecc4b2e602b24e27fd2cca30d435b670801f487a4f0c34f3c1912a69bfc1c8de40aaabfa3457d522129ff751814ccfd04c3" },
                { "th", "4c015a5e8efee66d07632887c70ff25226d1b070a184604a1832a55d5ca4ec5fdcbbecc510ea306798eba2cf27d9c2b033b89b311a82475b3b0c3c88823cdcb5" },
                { "tl", "217a6c1fbad7ba8301825054a865ea2e7d54f01245bc361a3c70c4743582d2d27aa9c7ca42dc5b625d44c90b9a137b0219eadc588f281c642580ccc09eed696a" },
                { "tr", "7795f6949af5590573bbf414c6a4ee87a73d83214e8215637804bf4ad8b701bde24f79d2bc29c09d8bc768daa129d73e7eaa7dcf2db9754c89873af9b7276943" },
                { "trs", "237b48705801674d184eb8bff9afdd5c2df9ae0f3dfd587cd088533ac605d562c26416900928587f93af6a36f5b16715225e555d7bbe010331712364c045f0bb" },
                { "uk", "90ca4acc14013e3b22e2cdd2102e54f3f2a5c767753eb42bc50691e5a0dc26656606f2f881f0e576a9825b175eda700367393085207c683fea8977f3b7cd6c72" },
                { "ur", "a89c54580d3220f47a5da4c76acaa56dacbce2a24803e85a30917e57127f5b6e2aa89e089de33cade26794dd722fc74a47a6aec09ea026fa0cf79eefd9092a25" },
                { "uz", "7309331875c6653114c005395a87f860a00d77f209048313bd2b18f2055513ff80409d6479e16633a60ea5fb935a6137cfd96eeff43ce4082236032f02769ab3" },
                { "vi", "e993f42468253afc612e8e2519295b50bd568db5fc3eceae5f7753cb4282cc0ae7ad01226835f57f1e674f243534e3c8b801f46ec26b3202d530e85806f782fd" },
                { "xh", "96e8a6fe171912e15a4f28b28eba8294c161ee35d5b162e2f3ec8103857c74dd1ce0716545b6c29af4d98b923e6c5e3ea744fbbe4d7cb8fffb5c82c0fd6cbbb8" },
                { "zh-CN", "fdf5f156aad50d3f30edfe638fd90c47c92cc563a9fa35b560bc7c038c751aa8e6696ef3f3e08736d860668ba02b4e549bf64f437dc39a07f0d04d94e44ce63b" },
                { "zh-TW", "7565af31a0a6990dcf82ae466456d707d2c2f4f2c0c8f683487d4ae97b0d76abd8bd227b89a6b5cf89319185fc8450f4c0f28130f3723ecb620c97bac738b3fc" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "fec55e03354a192165927557ea26f69e6a41912254ae8fe9c01b7dea6218acd0616e9c48bd8732ed481072811faa51f7e06ff9f67978ac4183845e226466c133" },
                { "af", "ee616f1c31c4ad6197520f9c7b1954e163d96693ae1d5c14117934c676df3c4d092b951573de11a13da6ffe0e99082da7e6d82f62fae496f02e4cd518dc90b9b" },
                { "an", "d5cddd4ec2e2fce029b941a7ffecc3ed98189821c6dc90262da2d4b88180f4003510b3f9b5131fc3e5f50c8b5c173115eaeb9a682742b5590280ddf2f64f22ef" },
                { "ar", "eb50ff58148119db36df149a23e65bc35771cc51428607981091ae6ef814dbbb6d36439daff3cba6d0f2786238ed0ed32da622fa9fb065eaa3ecd018972d8f19" },
                { "ast", "d682ae36b7e63df507cf1d0068a4debee6fd94728f01d1c20eb554db5e127876a562e49b1ff8bed1e48176afb073f1a5004a0b9051747c6913c6a936a57a372c" },
                { "az", "63efbdd3f0a2a0afd9a44e1bf8777cc37fa2ec685b477e1f725d67b48d7af8049ac5570da3ba3ebcdf796863d7c9b2d5696e4f39c0f28f78d17b207b26e2f968" },
                { "be", "6a2091e10e755833c40a4d95642b7dd780019aedd9a7c6681883d86bcd2cc85146ee66ff0b2bc07cb83ecb38efe8a6bb0090ad7d1c31ca3a391d1a69ff339ab0" },
                { "bg", "80cdfeff49ad417e622883ff34af9d3087d5eb3d0d5e55012dfc8fe2d6bed45758acdff4f024b18239ceb17ce483445a0ef44c2617a13ca5864f92a3953aa6db" },
                { "bn", "740453a69823bdfc1f0bbb54812c032a17e81bdb4b7288e99a689464b59ff0575cb073a498ff734eec593f0b0320c85374c43aa5761e01c804bdf8d519651037" },
                { "br", "b1055d8b334471d90d5d6ab3647bf5d9a2d0e8a645ca66c48d63c8cc948afa6db75c2e9883bed82dc83e12fb3c4bca5025055b8f2f46e058b66e2ac2e97a2004" },
                { "bs", "c751f351a9a44324d38e726ec903473ff1ba48b2db0c07e7b2c13f8aeb34e727e78210e3fb0bd483803341275cc5a421190dd4edd9d860d622a29f1c4fbc923d" },
                { "ca", "2b819ca30285df2f3dab93be3674159197967aa0eff1feda35051430e58ae153cb0ce1b171a4b436edb1bda313cdb46e76bcb3befdea4ebe4a0d66a82b0f5b7d" },
                { "cak", "60f4353ec1e71f2ba64579468c10e6c62f2b7724d18d8239efde58baf4403c3762780723f93b621b7c29ab4a6f872db0afaa58a41a655db71feae2f2aae5e115" },
                { "cs", "3a0baf03d81ab849acc39feb7df179639933b7c73853aadbdba980f4148e92dfc795492347be690c628c19ab7045a36f644095c48fe5d1a42537e2ce4d5b999f" },
                { "cy", "80c21d4846f58de4351cc3d3987c53f78a4c292bfed3420c165cf616ecd8468410af34915df93d5b5cd32710b2c62a43e7bb6bc9c09d3f0a4882583c0304b350" },
                { "da", "7506f564eb8c05419da61bff08ec8774781e52540323b6f1f7ed00b829a677997ae16f34ca398ba47436422d2af0b11a58e2d31ccc31a842513f3d103f74ba61" },
                { "de", "6404fd2510157e56dd1281eae7f4ea7f7dd2dede8126509d8450bc3eb126364a95122dd34abc85e23b163a4e5f20ea0add41ea8670c211a7509e2062941402fe" },
                { "dsb", "75760b885670d135a959e146fd76d1a5f17d5bdc40b3ef167e296626afa4dace23310cd1d42a0414024b0acfa6e0d321ddcf09ff81339e86aa63d565a6afe67a" },
                { "el", "848adae2abc61bc152c87d3c3582df7bfad04bc072689b6f47cb1f6e283fd6332cc6a315a18ed527d1e18ddf8be7f1631e9dd3d53b670750a365cd56cb23af93" },
                { "en-CA", "53a1efd2a3f2cb9736a487ff13bd668ffcad534c9162354bd0a736246c7733e5a6b248f23be85faa8529f4ddddd12ac4c377560080f4c996be34c0b74a86cfe4" },
                { "en-GB", "8045355e70490fdcd0cd3a7ae7ba7cfccf85e9453ad9ecb8942c126e164fbafdb6d95d662c486915e02c97d8cbff8cdeaa83ec8d4adbababecc9aeeef6c6124a" },
                { "en-US", "689202b80e4d27bbee4f54eb29c565f240c3a3ffcc59f5301c62db4b2e25f3875d3bd493289b847644efbe5e20f7738fc6adbda879e29eda6f5aa3d45ac00ebb" },
                { "eo", "eb8f5b9dbeffed291a595b903be6e5e6afdf02bf6f8639f5e2a5eee7eb7547ebc0a155a0f3c4fa4ac12e2864c62838e048f7714961f6df604742435ddd894f73" },
                { "es-AR", "f448f0a72894346b1516f60e4165d4e4d776815fea233ea49cd12ca21d19f731679066edf6d8d8ae3174c9a776891b5e640666fa7b67fed346c661ce05cb02a7" },
                { "es-CL", "42ca2cea286fe93ecb28e502561e58ab16acbaf9dbfd0ddd19b82b1b153bc130841298922db2f0cb9b17afb837ee82d414a7b98014dc03f20e8351698eb830d8" },
                { "es-ES", "bbc4ea898dc5d0c5b5f6fc757d2def0c24550ff8d9b0d4508bf98aad9d111d77dafc9852a6f8068adab2f88b876e623e4f1d77393d78ee48015c721c1fc482b5" },
                { "es-MX", "153eea00ca2fe5c6f4793d8478b39082dad4f58493c741f8071bb4ab8d49d41290f4a430829c326f370d70de14cd60ba5dc26f6f48b0853c15544b46d93edaf4" },
                { "et", "b850fda4543ffb27916e0af76c82c3167357be06fcb47ad6c71fa31f8eab78a6d47058d997c9edb96dcfe27239b1260e93b87e0ce9bc73b0dab554f1d6f6fac9" },
                { "eu", "f6c1624a37e891c89eaf9e449e9390e2a4c6cffec9e4489d396f5c88ebb32d50e92e286298bb295ad3f4bb0a0354df684fe25d19f389dd446fe6ebbe87660005" },
                { "fa", "1c9087b1bf2e16133391aeef21aa84a01d0ba55a5325d4ba01b56bef38fad45fbca4f447fdf192726694c760fee99e88df6316f0d40dfa26033c775c23502606" },
                { "ff", "47cf90ea8dd282dfb2c270ba43e83606b78c572ef8f5a0079ad686c7bcb8ae124f9c887689c5ae75e7d17b9d5f0db215497c22421fbd9a5b19c11582b624f077" },
                { "fi", "f15b11223bc9f99b3b2dde396b84b65b90af20f4cba33b535d2bdb15ff409d5e93419c5515d0c66ecc72dddcd835b9b85fa35952969180a5aad42b9fbb5cf2c5" },
                { "fr", "bd6d3a2b3f3a88bb922133e7bfcc5e967bd2454cbed2faef1d7af44a3a5af5f6830e8ed1103a9d0d3b5b8ae518edaa58679117bf4525f48ed6a04898a22a3d6f" },
                { "fur", "b7b4650c6ebd0824901278b24fc7b04f4eaed4ff74a4ae0105d059e46b8b1d0eb3bceaf2260cfc70c0494dd76641e743d2616d4081d1696b99416cbd23360b58" },
                { "fy-NL", "dcab9a8f0181ce055c87c204903283168a33c99b67025e247c40c7f704d661a37ba006d76a084b7cd755400b090892924ecfe2bdef7d7b1053e85306965b20b9" },
                { "ga-IE", "ae2a06823bbdeb2aef71f0204f22b7a8b2caa33fcb1ccea00fcae078a8a537042edd230edac328ec7194ea50e094e5d94b76d71bf6f1f5fb03ab756c023fae15" },
                { "gd", "bf12301e8295eb508bba9f2f0c201681322753841fb007e92d8f1bf9006d26b4dc8c85024fee6e3357a1d8a412a9c7fbdd14da3ce86a5a556a00db55a2016c0a" },
                { "gl", "76ca9d33d75950dea779188f959599106c3f5d38af6fdbe60d9f3a8ea097a1e8a805beb281878cc8d83d1d84307e4030da6e43c596b2448a66863ffd1e785ffe" },
                { "gn", "fd56829ed83bc177a2048df9543c49796b07dd07e403fe975a2c2ac3ca7e89361c863d0493bde17a71bc1b8791945c8a3fc193be45cf316fa584bb3e7e8fe5aa" },
                { "gu-IN", "b0e88c9760228c51631b56a9771a3048632f00a0a40aee7353afa8e3d1582c8d614a726a6eb987a3ef85ac63beb166b3d0d8f50e40fc5b00cbb12c10c10cefb7" },
                { "he", "214a75ce5f3b4e7ecc8af21df1689f1fc998199e0ff386520930ad661b71bf43cc564dafc88bc9b9a7d5d1413ba9779278584c26da13d6bc43a5dd40ece0232c" },
                { "hi-IN", "837ea0405430ef779fa81d618e8d6390e32a1a0051078d52887012d30ed81a23d245064bbf5e8b66f9d9125ae2ba399117e88cf2449b422d39f183e8763eb8ef" },
                { "hr", "970b9f9987425edd84d11a910bf02d3d93a5a14954ecc4e1ee56a200ecfabe8f0a4b23abe594ca137f18cfcdbf8a8298104784f11aba51dd908a83785f9e6148" },
                { "hsb", "e4693221a40fc41be844d38867ffe2d89494275bf9bcf0d604a05a69fccddf558f34f6188074ac245795eb687ad65228c9c2f990fe9dbb7eebed3b18c5ce09ab" },
                { "hu", "597bbc1af7074d6b65703398a6edb154dc15180917a3c39e3e10f7ccdd61bace6f02ffaaafe83545bffd5d2416d93875a61d8685476684f654539ee0cb5f895c" },
                { "hy-AM", "8819e7cae79b4acc4237ebc1c9c87c5a87478bf788d4cba14513411b01939b00cb0a942f4a8d135cbf3587db81fc751f2a08de137e5bd23d58f2ef93914f9238" },
                { "ia", "3ddd8b081bb591339f504d34ddacb4de8aa2493d4f064639827fdd31f04a9209f571a8c69cce1667aa204fc7fa7160190e1d9e688202135d2cf0e524b0427694" },
                { "id", "9d1d1856f5e381c77f75e159f7e19314fff587f86565318203ec165695d60b9bdbec50176b8994f3df416b1487ae5abe9ec24f5fdf6c41d2e6cde49c169bdee1" },
                { "is", "ec3da875362dde152d92c4577aed59cd44a043fd0611893df94cdf458174268466c04c82155eff9f70d6a99796fe0287237a87f632a7a2cb3745fcaf87c060f3" },
                { "it", "52640d1e4d8022c375daafc4961a643fd419270722129fe2235e2c9fa025369990eef0b29ee024c7ad06eda64fba0f7c348e06db726b3bae72b1c0dc828f7ea5" },
                { "ja", "4f6f2bd443c3df734f46b98137998f02c44f94cdba4f2f9c18a5c1516f2d071ac46a6436d3c2a56f1b18d3dcb2396d6e4513af0b682d6815c96cd35dbb754c3a" },
                { "ka", "18d740c211897aa95edb06d5aab47d7f6fcd5ea247e270bb50edc76ca37920a965cf1c052b035aca8861dce6744cc38f119b799b1def4c9a07196430df1f767c" },
                { "kab", "57031e97b40f644364b8df0df58bb7d43a39055b11e17fb40e8557aa07060b65dcdbc224ed08919b587f797f326cbec78b1c7f1e4e92c529b5d8774aa400734e" },
                { "kk", "071ee9520e43f63e9f3430f067b70ce6ebcdedc8e33dbc748dd236d7e8a3630a3a4ee19895870dd400b404bde79ae16f05bce9879b151a42bfdc751cebb562c9" },
                { "km", "a656c8f142f150e9951497f02efb554b288fc18b503ce595c0c71a002b6e8cc9a522edd758d2211245f77f1c355c4dda73ee123d0d6e2b7b9a7255a4fe935d19" },
                { "kn", "bd0124fdd205ed27a5f73a60c4596302f582e8810739ca08af7bfb39004d6f45c72e96cc5e2b55fbc5cb32a058ca56d3b7e290f8b68ff5c4c3b3a447fe07fc8b" },
                { "ko", "cbb50f77d9338febe2f64011799846d910d01c8cad1fec2591cdf0549e98852dfff57d1c33652cf29ea06d4deff8bb15e713b512d349577718d9bfdaa84fa987" },
                { "lij", "2846d894d7df84ec5867daa62f11a5ab23c05830402053b8d33a55db925d24ace0f2eee582773fef97a9eea90005d502bedf811e95669a7c3535fddc952bacd4" },
                { "lt", "8327083087ec11bbe8915124d1702f82e9dcc4418ded0ca748db7f1eefd97d967b72da83c858abfc9704cc3c5a20f7f44c7932b4ee1f89c56af8aac27e0a937f" },
                { "lv", "684e7ef7570aec8963c416fa2360be0447194349408dd1d42af8fd643d7c86da3a4def77b65471f4bc5936b0225336aa99e761fcd0b2a91708aaaf6ffa5ebc8b" },
                { "mk", "cb021262ec39c0dc9d3bdb879ef4fee59d4469fdc334187692dfdaf649b0becb8501c8af900d1cfe7d2a36929c694aade685e7b56c7ea0f69e08aa4bcf4e2af8" },
                { "mr", "79ebb793c121e6eb88514e6b7bca3eca27823000da98f85ce2870660e34e335701c1de96c6c264a730b5b059ad2e45e08b8f5c4a52ae8eaeee3c2696eddbb1b6" },
                { "ms", "751503d187df2d1d497c8c412deea42e18867e0e2104626842733ab320918a65fb1923af4f8afae28907ce8661581c5558311ebffb15cd325a99c435a7ccaace" },
                { "my", "78729d2abed88a3edde0c7cb0b663bb0ad3845493d1f3b87bc043502b36de7d3cfda3e896bec81f55d52cd62656fa55e71d5e0b48a1bea722e5ba15e9893b5c0" },
                { "nb-NO", "6b7a9855dca045620536541f1e7e121f402436464fdfbe8bbdbe86a6d3a3688862b3bb821b094c74d6e8d34133b74bc00d1e824d6843e2ea2f3f11d2aaf1d45b" },
                { "ne-NP", "2118c98dc7394cda3326d806996ea0801c582415c8e526f1ea1fb6644c7f7e9c18fc6ca3aa5f731bbec014a637188d5f91ffa37b010a3fefb8d22b131c9c24fd" },
                { "nl", "f182231380ea05189b3aabfb2ca92769dfcedbd2a636194dfee09e9eff23c339faad66f21656f2e0808884435613814d3ad8ab5480ff0642c1a98624ed0d8a5f" },
                { "nn-NO", "a4ff4a304a1c543a5ab31a7c305de66174707e65fa2d566387515f67d27b5c257718331d61c0eb406fe9ed02b185980a5ef0ba0f0a981d082424a18ba1a8d662" },
                { "oc", "eed132c1d21a83e0ee6f507708e10590ce66ae979d4a57bd62c219835b943ddc3014c8884faa3585dd97ecb5478d8f2ba45b9fbf947d4c273abcd48dfd7b3538" },
                { "pa-IN", "0a80113785baa976dd61b3645a428587b34450c71da6df7700e57e1e5a0c7cdde2d7b6cb1c78c12a6fc72fda2f7486b89dd09e191953b43097d29cace84a575f" },
                { "pl", "a43b2670c67a08ca6f8213e3adf10d8b63d6a0ed00695c429085eb1af6a6e0f106ad923adc578c2ab6dc6b571985b2f587ee4742f1309dc726faa9bb25278b06" },
                { "pt-BR", "eb728a1d720c9ad975c0b8edde1dc159d3dab15bdab8c5cb14294e7db2fee8dd403decb44d5792cc261c2fad7be25fccaac05a36fbf69a6bbb92efd2f96a0551" },
                { "pt-PT", "250cd8569e2ebf99096c570d78c685eecc78e76f75c47f150b3232ecbeb1cdb13f52be5fd43a46b538997a13e9e86dc2ad85d70d9b07098b15f914bceb3348f7" },
                { "rm", "c798b3c42cd0076617fc8d90d137f9502576882c13268d6d9c42af0286b6c0b3a081615cc73f7f744d354e9604602ebb2f0bdeff20cf1956534a97f5e47bdd91" },
                { "ro", "3ea9b73d9991968d773b70298e8d74556d0443d630c9554c6298eecd8949f59d514cbe942798f9dc151de013ec09268a4a8b68dfc13baf8765d7c4c4d7c9f1fd" },
                { "ru", "64ce4ca0f76e470c6ec41483907e6b26c5197f794855138d0d7e91ab05a929296698a2f0b7c8d6cdcca01068bb5fca38c8b22e0efbe5f3896071a703027c1836" },
                { "sat", "6c9506f6cafe82c4f44b14416635f41f9534ca3f9e9a66352fa6bd0adb0f0da14a90feb86a1cd3b41c4986aa5394150adcd76f5cddd0e48656bba939dd5debbe" },
                { "sc", "9810b0af64af96b12f9c66ea3e01f26feed0657113203b3f311d5e13deecd9195310f490e13331eb21a6af346ebfec1809a19b3d42fcac282a316ab8baf93043" },
                { "sco", "ef7247307f0e91c2869fe6c9c9a59761ff067b9a639d37824d3abe04fcf6b168e919c14b31105ddf95f8aca88620397815822d4312e6c3125fca4eda1c61adfe" },
                { "si", "92dc1058b50c5145aa6a9c40d694adce516c57d541b1d8b23245280aacea08b4a5042e76250df886958003105b5d2fe9bb49a8d7db46e6a4a8dcf187c5f0980c" },
                { "sk", "879d2e81b942154366acefdbf4cffca283780d57a7f29aa514934c268aa3f8b78eb5411645271c160931ec75e183cfdcd5eb53b226e27f872647ef21926fcc7d" },
                { "skr", "c14537fa0feb146990b4155c508eb082bedb8ac67abacb07dcf27a13d7d6ed9a176f49650e844ac147d5c66da8fa4a8b3d923ce3bb1ddc2c6161bcbfc0afd295" },
                { "sl", "0547579b3b442285cba8481aecdcb92889d48b43f1d1ed14850a3b43b638ebf90871c46fe00dc2929b809a0e2dbe3b495d4e45b7a8d3d46d5945d17c7bd27cee" },
                { "son", "8eacd2eeced7b2aa62df55dbf9037fd8377efc58de897a4a55e0869e5c84ddf6f9a96bd3658aa195d80e7bdf0ff3679c258803540d12d711bc75358e1b5b2eff" },
                { "sq", "f55f586d4c7940694c5d1d151d0eb6df0449ea5b9c31a540e10a39f77e953c5e07ab6b252767783e794ed703d7c1f6eba4706b883cfcf9ff6d3abc9dfb8fe0e1" },
                { "sr", "2affe724612dc8d171ca49757c9fed0cf814b93bb04069bda75561a49a8befca344672451c72828e0e3cc233ffe2a4a3e9a91d0816b875fb4ccda9b695b5abb8" },
                { "sv-SE", "f6cacb64a247a41b94b6d7447684ff25c5b75eac8211bc4fc1b9fb351da4c71f0b0f0cd8b1c7e1ffb6957d039efad1a4c57f5cde6bd81a2aa64ee73e8b9f2bf3" },
                { "szl", "20f9129028c6e8e02ef525a08d41b79fde3486a01d08baa9681349e65b2acfb53fa9b0039a41736b169c91ff7ea21641689f28b45a8a09a2185e99664efa7277" },
                { "ta", "da8569d8a7e96ffb3a0c4122acac04641718c4c0e649696448aa1f54ea18ed7dc0e7f2d62994d9356a8862c9f5d952979021259b3c5e18d3350fda45ea920735" },
                { "te", "643739ebab0f14d58978a75f350bc71e32aa1ac17c85500defe4a1dc030f39735d5e1865e5370279593643ad2c4705990b5e9a5ba486b7c10c2b00fa46e6dbe2" },
                { "tg", "d66a3c989aa00cc2013b8bf2e91fced9f0436d702e0bc5948ab6ed4912fec57d57302e85696c80ac067edfb407cf4e2c565a5a6745aff51924714ad957fe8b35" },
                { "th", "895ecaa9a72aa7d9447f55bf68f6493831fac6a1f40811d212948aa7df02bc431cc37f42b0bb1a56ab503f17e98853249898d47dfc80f11ea3045f954556c5dd" },
                { "tl", "150669c6afe2876ddd4071f0fea7050ab275b8b85b07d2dcb5cfd88350103db8cdd75b5eff8a7e8784d59425ff1bcd3b2ee0b1a47d01a5c3ea692035b23558e0" },
                { "tr", "41b7ce0513f14eb97da73c7d4252f5cdf2b7593ea47d9f2b79fc648257bc8ff7ce6abb95550c2fc120114cafcb8100b3e63f5c9c40c863fb3b239e65a6dbeaaf" },
                { "trs", "55c13e7b986460812fcd221e78ad766cd6ede1fb58d40a4130075deda66073c10ecb0502786f746a832f986649f5a7113cf24f13e60dc126bd69513844f3a9f7" },
                { "uk", "d75a503f06d8117c848578ff1b6fcf0cfc4b2f64d48b40a399ae849282251ae8627bf82b27d676f55602e04490fb9a1fa108013056e3f5ad6a56f93b4cdb4c97" },
                { "ur", "67d6f551fbcaf1cfa4e091a66afd72ca0b48cd12e9da060d8a18a626ccfcb8f4a5f16129bd7cc95b9dbda4111ac81245dad03f652f60ad31877ca8bb265cc665" },
                { "uz", "be902d95b2620746e84f8e34f8ca27b72886f0dd56383e07f66aa9e4c8fda014a8082ea8c80b8a550652d10a8f0c1ab585d56ba7e20d49c9db2f96019d982e4a" },
                { "vi", "0882636c3432ea9ddc6ee463ca20c2bb716a18396f94d2189eea277ec373fb2ad9feac7ac9ed107a6b8d160535df13264c77e27376000709a3eecc61fcd78d62" },
                { "xh", "3a47eb42886b7aa0d5cfd2ef9e02d8205fcaead860e595afaf7510c9edea716aadc7c301f6bf6eac2d51f96f4f162fbb3110dd6dc56dfa9f16d954a674c54982" },
                { "zh-CN", "1c1c2b1f9def65b7031cd2ef9526799d34516616dd0cacd4c646ba6d001eda26f38cfd8cb5238a9d44b9efe23ad7ac9faf3982b21f0cfeb6db4b7783b05ad5f1" },
                { "zh-TW", "cf01bf4794a30f038a52f188c9089eb978b0c7237e822ebea04049c8774ef31b818f1d68d1ea2abe310f62acb31d75c54918b30d11da512db431337c5d51dc4b" }
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
