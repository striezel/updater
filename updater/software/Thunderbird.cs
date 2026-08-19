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
        private const string knownVersion = "140.14.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "e53c50b57107b4426883510383ea49b95fc24d98090ed81186aae0aadffe70aee24b556211e1d53e0e7e59ef884047b888aff9daa79d8622373b0addaa53a246" },
                { "ar", "0b3b3b5333def5c99c846f7af13c6bab9ad0d282527eada820d42bef4d7298bd3404cda43eea28694d3b1ccc380ffa980ecf1abe6a9e01756b03242a625d318f" },
                { "ast", "acf282b4f377c8371712ec6d940a56de5a35fbcda6e72f1895ee6b0a59e3094b7e1446810dec4b1a95c26eb0f7082770f8514ef31614df55945e03a5c852121e" },
                { "be", "21c881871a8e635142d27d3cad6fd2ac22c00ab8f266f548dd03509838304e617f9a72c03ba1ea4ff9ffa18631542fcd8b1397a10861602b9e6655f4b2d88a48" },
                { "bg", "573b5b9eb6f497499edaa00ed42ebdf2ce55507a7c1901d2ed23d8abef65300ad9d8dff414c742f47519a3d32c4d89c64d158c367af4d440344521140e4116ca" },
                { "br", "3b3b59cc293a58ed5656d9abd46b5fea5c1bdfc647cdd2aaf9552e16153cfdac9a510b568bff1420605e4481b4a3656d4d4e07e70e1f6dda24711e8ea7609032" },
                { "ca", "2b529af1aff2fad357eea5b9a23a195ffa5ef24a19722d37221d7b7b268e984df7e878dea5de12a79885ead0763a17b388f5220efe132d3a511ee111087f0f24" },
                { "cak", "8f1cca0af172c3e7077543a9529626546781e8fd28294f4b20c05a989947cc7dd3f5c873ecb6fa8e9ce15b9b56874cf608835521dc8b3a82c4307045a3f1ebf6" },
                { "cs", "afc39562aa92332bdacddbca1eea8173e54ae0e0aac7b49d8d86920cc1008ae73f2234b9be7e229804d3d3ae74d3156033ebaa428738461bbc168f3c1b103f09" },
                { "cy", "1456e865fcc224823493cb759306d96b3addab42233bfc83b026f35a9020513749c768a70b13b18d209df953b476407387661a99841fc2a6efc57cce0cd8a3c0" },
                { "da", "a5f8a496caa0e35cac7a94ca0878bef58d04f4f41e8c6c4386edcbc3e13033b952f4ef79db2d0378502bd5504376a29c19a4f5f42c2ab05636dd09099280cce3" },
                { "de", "1f4d82910bde0b3ed10439893fb8c66a9aa43a509e3645d9ca72af83196686673ad2776daab8897dbae33f74420da82fa645f00bbe1f09085084525b1e637f53" },
                { "dsb", "242752af4777f639aa2c34834bc3cedfbf844765d34db1b4c18ce83acb66e30da3db4f4f823d23aa1d657100573b78046614a6fa61c83d9dd5953b1bb1c3e8b4" },
                { "el", "964bd793b10c45b703b3bc84203d7587fa4c190e479a476e23f1e77a42ef004cff7840f105e19e50df19c36ddba6245c497a143acb72bf9d4bb07757d2cd3a39" },
                { "en-CA", "1099de131c208ab3764fb3b640c2f2a7d9689c3116dc2fbab59349c2be5025a6ca74be953a4ad404824f6d575ea9cbb5da0243d3a041c1f8fe789235304062a0" },
                { "en-GB", "d896eb3454329719bd9f157ab8482397978897272ec0a50d9b52843e344c1123bbb152f66f1a03d5b70bd810db0bc7dff3e0fd23cdbecfd14bfb35d683df4e7c" },
                { "en-US", "b94da4230e9e58814b34d09dedc613e485585dabae9cf5c1dd682a356b083f90d468568399fa3747c00503df81220df0c57582b7444a3389ff6634c02ebe28e6" },
                { "es-AR", "9a0aa3d568e5004e0d456c638a61b228b1ee2403d3f55128feabf6fa8270f20ebac94e21cec7e01b4f25e5025cc0027ef7f3204c0934812170785f0decbc1aaa" },
                { "es-ES", "15339ed05e539c23a4d1458ef89712e6215957a51893a5aa9158f0a57d1944910aaf0661267a4b19aaec0a00ab32868e75b7dd02075f873f610e539110309025" },
                { "es-MX", "ef51b85774eee41957d395ca12182e7bd70c481b3e35064052694c5c6dd2b020134b7b396ba3c23563a537666758d182ad9943f5bc2df561dee848a546316b2f" },
                { "et", "3a88f640b80e8ca6822ea54cf3f7dc4e39dc2f0cef976bfb60ec2c8c6aa40204b9370d8b6ac3d87dabe32ff90f19bb6bfd924c2ff6db44e490ad62819a7512b9" },
                { "eu", "2a1b79c423ca7315165d9b6592b6c83ea57edbf4203fa348b3d3b920bab625ed0264215fbeef8c20d6f86398ea593087cdc9d4249d371a7538df6aa8c999b39f" },
                { "fi", "6d19d504fd4c94df59efb13a314fe102189040651b1c6afbe10a291121aab2bb818fffa3f96035be1e1aa7cab3fc158e6d37f9d3834e34dee659b3782fc4d10b" },
                { "fr", "24b2f296a49393edcaa3d52ebc21ce6c35bc5e5bec41a64920c703f5780d746a89832f99f30413815c8c06c2f184b44f390046d9c11d2240dd8aafb216e6b1ed" },
                { "fy-NL", "44194d1b7723b88cb0e1b3c2d337e4a9ceb16390c67ea1ffee600c2725cc42e7403340a7b425611297e7faa801d83754b6994cbc4d29631779e1741fc5316986" },
                { "ga-IE", "f968a33f484f7ad5648f81910bc6befb3949869ad54402709153f9c0c82acf2be203513a659fb30bc557076730f06cdd842e6d33f5cf3b6255539b6fcb1bbc94" },
                { "gd", "957eb1836bbd88e29e1c645c25d172cf88c33b34c7f7e1dbb390edc8acd208a96813de68b32280f4272aed2ae53a11930a2d26070a13f2171a56ae826737f967" },
                { "gl", "72a59b5243be274c1fd0b25e10dc0f105276de3f4dc6991db32c5fc7581d2462f383b8f972a37a96c485f8db42d3adaa2413e1b8679600337600800075caf2b3" },
                { "he", "1a3c94382504e31387b5ca1ef8e46dc75f78b6763e9a29bc32a3fac768c8506ce1edfa23989654b5a82f3d448f41ed1ebcae96808ea7f39e2c34063ca074c667" },
                { "hr", "e2369df582caa20bd33d165402ff1093324fba5f8303a363a8237879ecca053a6aaa38c939c79671bae60f922c712f4284bd8479ffd262b29d9778a4d7ecd913" },
                { "hsb", "32fa48fdacdb519985a2a8d827588e5dfeb16638899df02bb62836b6a3637e51af510d2c882cc55a23f844e3c0567b2407593e6cd6a02251094e14184f0ca90f" },
                { "hu", "4dcf64496b72134cf7ef90b65724656ecc1be71ae2dd50f6df4bef7aca734927da593ad0abbf23587453f31e540d91e215cf3d41d5316167c8cd3319b068bbb6" },
                { "hy-AM", "955d74239152d62bcdc24ab0220244cef3e8f0b389314a443dfc02b6bd97c33bce1a3e61e4c80b591cfe2ea6dea566e2c68e98ca39f4ed88e9e8fa1247e59e07" },
                { "id", "efb97dab539616a31588737f50e57a002dd3c38d7ca8fac8c9ed0b8a5cdedfd9896a89bb6b5c47136fcbafefc5141eec98f63c4f69535f1357698f2ee46585c1" },
                { "is", "bc6a02690fbd50b1cf26944ae83639d64a148c9a7f035c872264a1b98d487d767d2ee185e657a1b9ccc267e907bf7133f4fa53ef4aab09ceab9e025982f17e0f" },
                { "it", "e692d9d42a0e112f16be1c4404ad4ed92793b49259a77f5eee183852d58ed980d8c20416875c69af32c7f3b0f6929680a26dddefc0dad6e1b6c801d0076498e6" },
                { "ja", "2111e419fc83b01dc01bd7a9ad5977797038baa07d69ccfb5368bdd0acc6e930c931b762a447c0f89d287bce25be07601416562a25c4c64cc6ac9e07b5ef6c59" },
                { "ka", "d709b436550d5d3accbb85eee5866233941d21e60eaf223a95c361f3b1fe18d2e660ca2fe6a5f554f3dd006ae9eebd15b74a66e225ff05ac980c3c5d47acf765" },
                { "kab", "5a14d32c0a2979049578e25df8fdf0dfbdcf79d85e8ab30cd08c243da8a7982a1b090d03ea74a2059c643061bf29fe1d81625ad15940750d88feaf0355b1947d" },
                { "kk", "e0641cbbad0a73f044f98527a16f29225ff1bae97f494b88596635b405747789b085b33d72cd683d038cb6404017c799d64292878f59b7638c4ad58709cb0c76" },
                { "ko", "52b5f5919e074465a7f72da81aa86eb57a98326d9a7bdc8d2e50b26d34eef3a5c38b82bcc22ddfa4cee63c69ebff96606c1e3246b50f9f1c1f5eb3facda0db3e" },
                { "lt", "c0d358bba42e5270ac84a64768611e5900eeac10d5a1a70589686fef2fb4f1fc644cb2a6fb55cd8b78bf6ed3d035b8488c3c7826030a7c6451618dcd6a4c9f23" },
                { "lv", "ca98ce99b5ab693f67667009008d642630dd08e519594f476dc6ff3ce378cb7317a796bca4d876406b291871f252a4f0df5ff660bc0647674161b508ed0e36fd" },
                { "ms", "ef963ce9a02fc5a0d729acf50278921b8456c2757c06f2cdb703213a591ba77cd09c98bef8c12f8cf83fb990ef6b966fa530d04da29624c8f7520fa1ebad330a" },
                { "nb-NO", "bfd608c562d6e2161631314aa5613ce3935ad6447ae1f1ca8a8a3525d56d69cca229cdc6072eb25a182cdce4f64ebf43cc79880ed3dbf20571b909ed7d144396" },
                { "nl", "2e1267287d27adaadbbc0431108ee1fd65fa2e2f4327ee947d19303df829b9434163c01ab96b203d000a06bf852ccc099e5eb07d0ee1f3440b9cab0429d36640" },
                { "nn-NO", "34933af3d0a294967a4ff6802db63fbf37eb8c392d7a0a19634af87299d51b4bf9492c5ef345146bcbf11f07eb5846ac87ea886843b26737f4a9fffb68c1d086" },
                { "pa-IN", "fc2f8edfedd24496a7a51ac0bd05f693a17c86baa9699bad9c42ce1411fd32ffc95739df632df328854f01699efdbff0996b51112aa656814c2afdf64c27625a" },
                { "pl", "4804a165fd563245cd1996f74c9e7f23a798ce8733eab1f26c2be151c4a505de20183d2f7e2106a611cb043a066966eb4d67696111be3465fe4982b711af33f9" },
                { "pt-BR", "d634dce09ef469644f5434a5e7ccbad8d6db7aef13f9682de4bcf26b79b8a3e06967f5b7f8101ee2cabc9deac5575762dda931e0dabf47c8cb1d241709e04327" },
                { "pt-PT", "a53aa6c05c39993f482669628bc7b97a60f1e8be762374f3062664d07cc35680ee165b59359dbbd32a9924badfa5f3fe5f4fbda9bc5a729071b9abbbdb3afb1d" },
                { "rm", "b469036d7fa8224816a2e0d6df46ea0d5ee97af6115ec9cc02630ccdcf990b238b4d8bfcdf1105223129248a5c7b7b983285fd6e1802f654332c2724bba48cd9" },
                { "ro", "e3c8739b3705a008ddca0754a1d7306d60574554d43b75db13a55dfad31a9e17a16442d0311dd4464efd8ec3a29ec2b5eda5dc12ee8c89e692dce90e3bd5d26b" },
                { "ru", "083b1bbcafce88bec7e408e2b52dfccf4a5a3f955d3c24ccc447563561d1be63a139308a9901f921179de706e6d46d2e10659ccb3f1f2561095b4503389db34f" },
                { "sk", "b7922709aba27d60d7bc1d062a29c15bb5d6ae76a0b08576a88c94b6505b161344d52e28bddae10b8cf4777ab914c4460e3275a81f7bafcd26a0c22bad06c4f0" },
                { "sl", "5b42a12032beb915e7073a180b911f4faa9772baf9b331f8ff238970d1c0d7d3d0adbd472f6d9301c2f34a90b3ffcb3dff36d2b3d358f2464f7bb784f23a914f" },
                { "sq", "a8f7a916ad2d08d10e013730f6a3a2414e8e183c403bd8d8a3699721860a02ad248a9da0c0c301108aaf84ad5dd37fbb725ff4f6532c48974be8f2e6150e4509" },
                { "sr", "81c6c12998c043c2d558f8c289ef3fa95b5e031df8a7af6f4a1291560b5d6e65efa80af491f59de974942b284d6a3ea6c09d0316e7fed5a4d794f7f71c9494f1" },
                { "sv-SE", "9d4aed4f59b7e84bad7f4a59d529de44bbcab7723887813d63c4c69e5bb85605da5c055ca1fa94600b5bd69f19db010896ea81f85eaf30a82c0565932fde1e7e" },
                { "th", "7e33c4671a0d3eee58dc77e4e6969515601f839980e5c2fd6fca5fbfece0f474e692c5d8cdd03b48ee05c400daa002ce6e6a6c24ec3c47a754ca990c813e5140" },
                { "tr", "dd4a56b1f74637dcd2f2cf24b6cfd7925af0608a20eae901a346f3a5ca4d1d0313865eac242fce9b3c688263ff7eeff075630977862213d879a5a433427f9275" },
                { "uk", "dd5e93a863ad042fe14b3768f2c0412c66ea67eb32fd12ac3587df761aac52da70bc47f0403453f5c9d24abe84f05203efa13ec8a0568dd0868796589cd1a049" },
                { "uz", "321cf622e6f34eb55fc1541588f72f3310ef6abc3172a7c685a08d1cfe04aa552860240f5f62b0139f7ebc03b310ab9ba7b9ea3bc10741fd06e1c9afa7cc1002" },
                { "vi", "886dc57aef26a8b6e1b6827206bdc4abf49f5334348ae65044ba2b71a3b2dcae156b016da1066439303a972e49caf7011623e35ab59adae64d81b1ed4f47c559" },
                { "zh-CN", "a378f639790e3a6b16f8ceb1161b3cad463dcb62330fd944d86bbce6236bd6ffd869c8f3f2971c5360235e20d4c1ae3f1e04d5f2d0eb09b50c951d85526c7382" },
                { "zh-TW", "28d6b11619e48b063972d4e47faa633ebd164df18b93d2d70f15ac99e93f394c266f773a70a6e0574ea4847e0f0b19e06e7ee2bec4b159fd4e432cadb7206ca1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.14.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "22aa1595f06171bc852965fba9b38eef44176054d7483b7d5fb98fdaf66a4d4c290f9ae28b30c0e07fee2c87294aa4a2eaf96d29768e481da568fac0345bfa2f" },
                { "ar", "c0bf4a224275447e2543a8b22ba9377b47993bc04debd764cac930f51c56df79a46328dd786a5ddf75b27e0013cf86435895eab663fdc7f0248fbf22a8f5340c" },
                { "ast", "1947a824e4a0569283c5c12f7c3d9946a37630868cc66c158138135630efa324cae4b4f249cb2df3a97f0c68e4ae227100b4eb421c50abdf17f46f154016dab3" },
                { "be", "ca4a1658723f62775cca8c7515de774e07f5abcab6354367e12631b227426f55c520613997cad951be59f285fa2b4b668668bcb43b0b57196d6aea871fea420f" },
                { "bg", "33d73a29112849c8ac3000d7a5552ed54cb08126f9c46d0cbdd6f1b641b60fb2d67ffd260375dd4f46d73c372401371e459d62b9c7dbf685a00bbf871404be2e" },
                { "br", "28a2e6b507203fcf630adee0b5a95a20de1d099c68d3bc5785d40d456532e804c43fd9017eed116e5a1dbe8f9d3ebe5797185443faaf7fda71a511c827d8a617" },
                { "ca", "d1298a3cfde5b2f9a19a80982613915782fa54554b7004bbc1f26787c4bc3ac18efeff82951bba7ec2aa73a742f4ee239a9d55f0590dd7304a790d673f22fc37" },
                { "cak", "9793c414ce83d9b8687f9163dbd778d3c51a02e4d8f75c70aa3ef4be25a0f6d0547c267b9fd9450dcc10ba60cff901dc011b5789857319f5dbf763f7150d3f86" },
                { "cs", "cc94b17d1efea5945d370bbac1da5b0b4e19bc9cf0803f46d49d4a7825c8dd8d9e871bf1e5714d1f95bb5c74c6d16cfc4036ce2faec269547b09b00be2dc9b85" },
                { "cy", "a63be2d3433117d0ccb8e5a6dd08b1db163f9c77ae2fa5069a218c60717310dabfbb04ba9a74a4a9760810337f31f6983bba99376496b298a52ffcbfb4b0b325" },
                { "da", "f6748f1ebfa087beb84835bb66bedba5aa9116ce94ff73d2a681457243c851dc041c342ac89f900242d24c82170812389e97ac2072e485439fccc74adf323f03" },
                { "de", "c27c1b5e0cc9c75114221683a3f08fa501458dba6bc0e99d327eab86badb4393395e10f8f92e95b522bbe14be1e85c185d1962b95524daa7f0bf4252d31f182a" },
                { "dsb", "e6da33a63a66d06167efdb50b042c133434ee4f2b57899eb7d44c2296924eb4bdc76b65f9160fcad21098fdcf1cc6dd208fd863cca9f4bb7984284c0b98c963e" },
                { "el", "0e354440a9858113f20d6a54b4a36e4b831bf9633ede2fdf44356f09047b98b7ca22fa01ac947ca7cddc3f564bb35b0bff7ff03e9484ac537bec429f17cebb28" },
                { "en-CA", "eec1ad60c5e60f3bf5a763cac9dc13ff1496ceee504d25277253ca72c7c4724cc461135ab83712621b606eafed9ca5e5976e7bb2f42af98306f71f4413fe4494" },
                { "en-GB", "aab8cdac606615a08046cab35d5d59200c80d9d2366ed1d99b21887f7a19ef8028c90f145d1c3933acfc232f8d1ade4ac145bda89996ec8c3300b1157c2eaaf6" },
                { "en-US", "021fe489151315c5882542bcaaf694dabc8ccac65d8fd6fc19ccb22277c33ba21b01618f8d8c83964854573e242aed180f087b228995ff585214d262c27400c5" },
                { "es-AR", "0dc6f8ddd14b427166efbea755912fdc7157d625f19483705c412dd6d2107d44a9db9ecc44ac34f05065754092305f0253e24f7e15707626194206916aff9468" },
                { "es-ES", "71d5aa0200692d7035a1d1a579346861362e5b8c1de9bdeb7ddecf179d9ac904394dcccdfd7d263926bd939ccfe514630bce875a3d9320eb1a0bcb9357516319" },
                { "es-MX", "f4965e24c42e9ec235445b88726cc6cd5b84079bb491b353e00ec4bba6f76cae5d544f7c47bb0dd82060581deb8a25efeca077dc9823090682009fc1019f6dff" },
                { "et", "99db744b448a5c952b3c95ae3588de32caf9a2afe9e54a34e996c4918ae74b941b586aeca3f264daee8a3c140e73de17a1aebef0fec2f7441300b7aeedcb13ab" },
                { "eu", "cdd3d4f4c4ed781925a31b67a81ee50cfadfda8f65649aa3982a37ac6ba324b2b338db072d3fd6d9557b19e0738cc2a82d8cf8e81dd98ed81faccda61998a663" },
                { "fi", "090bce09b3ca0723a80d1591b9c1c4a8615ee4e0bf9c9efccb028d3dc78e909ce80c478a5a13071309f9f65fed838e4702ba17272b5b6808b1ed839fa84dd603" },
                { "fr", "19668e6560fae8bf71ea8181079f10d3312402a31083152d895c0f09b63c12c9d89b2f4da0e0887e2d245e2e94a74b40a1e18e4571b03dced015462fd7e9a6d5" },
                { "fy-NL", "80ad62aec0770cf81394ff861f35cbc68eb36e2df1bc50b6f1a307a8edd90493e6a1e19fd4b79cf2a6d967b58e61a4384fe217832a3bb50a54ef908b95506883" },
                { "ga-IE", "4906cffc84c4cd9f7a49e46552e2775f08e0861fa8d17e1994427b3b981deba342fb2b1082df033ca5045621a3c71ddaa4894340413b4af82c1c3738a2d04b42" },
                { "gd", "d30ea13cb0b87e1bc6a7482e7673cbb9c06f3e7d013e008d9795af86dccfd71f3d37f688a9c7d0d3dc61f04255e95ca2475d8e78aa8af1cfe597e0f23d4bae23" },
                { "gl", "f4779790453cbdaf8ba3e8f42023d0dbe0077f94346403bea43ef66be7173662af8e9f9f422ad106e1b03c3986f94253d6b05f8ef9acb26c4c024a7630aefe0f" },
                { "he", "43314bd227de6e1b8026b078e2ef2d1e91d4ec0efc71d9b982bb9f7125c1f929ac6ff20ea2251cb98b74f1a78915a3ff29cd2274d699df97b565b5fde5bc4ce2" },
                { "hr", "8246250352a8d285d1d0977e3af9540c55902241a9d2083c707039870ea4ac95de9cb5aee1d5a1b6daef8776f3676760b4f24545e76f80e521b6951e317939a5" },
                { "hsb", "454e5262adefc0cadb744b659a5eea2cfc03c1604d632b3fbb9dde58bfda47c41d241670c273120b59311a914b39f4813648fecf03ccaf6f65a81ac3c376aada" },
                { "hu", "61358a6e2e6d57f378a4d3f63b01fc06e5a0b691cf9ea8a060aaeb7c2f6531d2e253f9ff0fa14cd0c320ae7f9efe1dac90edcd0a4edbacc32e6f6728e18ecfb9" },
                { "hy-AM", "a040d0e848969ced95d95cb1472e27ae032688cb4fd538dc62db1663950de4d05aa8496cf8195e4d8e3c0a653e916d9676d2638ba349cc569983c903fa925ad4" },
                { "id", "81d732eaa197ad1f2b57cb0a335290c9e23c8dd3b1afc35fe76d476edcf5d5a8bae27524516ef5354387900c98302a83c757afbf4c40042451357ad33ea3cb07" },
                { "is", "2a29808b7eb9b680703ed6acb565b39550afd77c44e8aacf8b2d4f9f94440b7f473fd3f2dc86d696547c2401b0f12f2138567267a80e25282d65ebf8226a7112" },
                { "it", "aff85e87efe38444b630f5c3d4ba5c7a7a2d4f71ff65675d97bbc21abe37c2037b4ef8836f7d8b304b731df2ee4324bf990ce6cb5fefaff7668ec61029bdb7c6" },
                { "ja", "b573e56b1fb760348a4748059fcb6c33340f3940dda31912433914e3450387e121415335ff8522f377c0f04d03bf6c96702f57004f73cb4830741a3a804b342a" },
                { "ka", "088cb7bb0a82e47e09d3bd2ad3b99aa6e881c3b5b9d38b508d108cdb98d7a7205ad9d870513f23504ed27bdb2260f9d83310b0a3f7d7763a604bd93cad8c2ceb" },
                { "kab", "7f91f7e5ad3f900f4dd553233cb7de5ebc52baae9f8160fe3e2ab679060e20332883f8ab456d1dad1b4ab3308dc569546e2b686b4f4cd8ac9b9e5f772b3c1200" },
                { "kk", "2f9bb46c664411854da2c66b83555cd8e904529c0aa20397d1a157aca50417ecef67a149103f0481c1e35cd1c72271976a842abe8530c89faff90e199d60c89d" },
                { "ko", "7c2876679cf6885f41269263d3e4c6c6eb8e5f929466435633826d1b32901ac11d4fe95bc67e44c6877775c112b8f0df1094d32f56414b3dc20e22e4601af39d" },
                { "lt", "99b4804eeb5c345b47b7e671fd9aa7cbd5dc77ffd62f3e33ee2f30872d6acb75b462a00447401fc120f035856f125eb156caf54c1f3a252a230616bf87d35290" },
                { "lv", "861bb90228bf13b108d096f90d4cf9c78b7728351a8c14b8d0f21146b58ef0681a88d9e9fd7da08a56548e4eaa28aff444f3a1854e3f4e4f2e31a32ff04fe8ef" },
                { "ms", "52486b2e5f16262e0148ae291a0a250a3998c610a0eae57def8414f716b9a9ca127d990abca5451847671f56a0d978951b4f21a1e38668dc877bdd908f9bf907" },
                { "nb-NO", "e252e5e1e95e1c35f1ece38d08907a924f341ac9d8b315be5e6c285fdbf55a3f6508c14493778e34e124e56d2d86383822a385ccfc8e09d99ab4602c4c906175" },
                { "nl", "243b81df579f343a6a41be9738ff8adbca13640a4e48f84602a4c1efa21a845f0dfead29f8468d909caa8f6c2701aaaea8aed0f2c7fbccc63b38b250e5adc24b" },
                { "nn-NO", "39bd141f9c9d88ab25e472158507e630b4b721d74f47d892efdc90970f498468b9cc78345483c0bd97ae60af0499f589e79454431b8936cd2184c24f20917026" },
                { "pa-IN", "80061e7a3adfbde3c7e1d7a9850796aa3f4f8ee910d36dd919b5f35a76668a2262de0781143808121ef6e0558fc7b83dc014d44dcf6ab54c7cbf6c76993a901b" },
                { "pl", "92852336ec889db83ab16374d3ccc36739ed1e8cdbc3a65593327bc3d0d69e34ff38680ea233c933aba88480c6d64378669832429e5a20e1a18aab06c6a7f103" },
                { "pt-BR", "e5bafea35d2f8201e10f27d121f3e8d6d6fd182fb2251173daa8ff1292f0906d0b6ecdc8ef4a4d4239d43ed959d1f101c917b8b47e819da1cfc1f48ebba4ea46" },
                { "pt-PT", "4bcd341fbf358aa62f04d1dc78b15f11107c6ba85b024c6ac2b16e63bbe95935a2a6c3219f5cdf094c1f1a192f7e3deb66feb30417d17d9ef6539df0837c29c2" },
                { "rm", "c24b9188bc4a214f1a1b456d36e9b962d5db8d47de45fdb48ff64749c8ff3f06e44a8bc0b41fd3a1b1b39a32b2309bb521183dd1e9ccb984fad02cecd24bb4d2" },
                { "ro", "7733564b0cf11060dc4e79c300fb53233c4aec6bbe139a02ad673fa35a8a81c84cc4bb095f3d9b79f7e962b56f336ff9374d1f1ee8670ea9988bc25135fb3c10" },
                { "ru", "daa9fb9616872576653659179f8c6b376db47a46a67bcb1ea63199debbf95625a9c18b0ced3e05b3e4cd22a55c75892c91fbc0ef06375393c504f3418374c57d" },
                { "sk", "bfd7e126ceced9194d5f08200a3df46a82be60ee5f0e70a0955dbc31d9a195aabca1d15da5c708fc2812d973c96b265ae5c98dc7f1569f3d4ead5a54dce67884" },
                { "sl", "0fbceb7c1664b8fe5eee8f61ce60a728de8f34fcef2bdfc3ac450543817c03e0504ede5a1277e0a28a1da92e1c6d5c9319b6410988e6665871ae4a91cc677920" },
                { "sq", "8d3f233a28bb156c4e9be6479f7dcc6c7cc9f63cdf10486524699769c307bf942afd9a5d8b159447c24151fc1340305566e706d36f2b4671b12764ce52d635e5" },
                { "sr", "4c926428a2e96b820ef62e54430557856bd56239ac38cf9ce2614e287a05a52a1a373a90c986ae87a9b2b0e06cc6808f234d14dffc1468ed34d950f7db760a2f" },
                { "sv-SE", "fc862b49c56e7f785c1bc2649634fa5c1629a1ec79c41a254a3fd9b5254b7a37a42280024ed3a5df711fa38c059ae16dbbf2a924c9600b9f53a7deb461918830" },
                { "th", "9ab74948f1382f580f37fe8d8efb710e7028a992ed9394fc7a7316610fe6b67abfa7898867af8f496cff5d32dbe96dfa31d413867654d68ab74a20693c2d2b9f" },
                { "tr", "9ac52967162a11683bb2f1ef2f43ebed460a3bb6fcd8067f9331c6a6497854686583a3c68b955490edb8187ffcd66ba0d91efe823bdb3cfc849b8ae4288b0c84" },
                { "uk", "2743d72e0e8310b5f6fc4d28943ee059ba9ba031c778869f0fb2e06761df75a5ae859a2ac8bb0030730ec879671f57424e5a098b1384053549c284eaab2a8308" },
                { "uz", "1f363776933af38f09fb60b0111f3be1189b5ed6b54619b8246f3851154fcae682f96304dce47573dd4e97930d383d972ebda84bd98bc4526834a78cc0d70209" },
                { "vi", "a85197a02fd30e70c0187d6da9934386216f4c12bbf7da2f813232757bf83c79dd949f42dc42ccec9524a69161d75c4ae9401630b6df1b4db9826a3f184f1964" },
                { "zh-CN", "bd837f131247b89d9cab473106a167cf44459c486fec75135421b9a82f6a5d61af547aff2a34cccfac6a1e550ea9d834752040937a4179d54903e6c7260a9066" },
                { "zh-TW", "585298ad543d69b910ac4abf08ec31eb75019c10a0756f5fd307be83aef2afe07788aa20fbddf1c46f24271a81bcdffa41b09538a1d1a52fad0ce42c007b66eb" }
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
