﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/130.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "709d9c8d76e1085a1ad67c6a1d734bb737c770e6944d245633ddb52dc8c9bbd756e08edb5549b2b83a5501a5a466ddb987150377da343527f4f728063eefb508" },
                { "af", "1c473d81b7c6c8b25ab060161a527b9e3f857ba76d4613775e53cec4acbc6a30852137d1731c24f571a0fbb503f37a361e7132c9384dd10a8c22f26f91d88f10" },
                { "an", "4db7df48b3642ef963c096fe686e3a39bf151e640a25f7949371bd40a550d2c3eac7102a8e40c477127ba6bc28791dc0752c606f6d16155131b855217f93830a" },
                { "ar", "6d5ef2f3b440a1fa3e3b0cecbdb124a6bec80664d145a4508efa8292ec0da3de4393b539ed0c1c630681dc96afd740160e9b697aa097b5469d1c247abde4909f" },
                { "ast", "0cc70980f31654d1b421fecaedfe6cc2bc1e8f12cc45fc606af05112939a3dcef97c726bc66888255ed8e02a86f7278173bb57c4c3f665bc6c84f6f46dd1c265" },
                { "az", "cbaa02b36818ce330af6843d266ba218d7009b7a2c4029f6b421bc71f8ec9e446b5a4a51e9ae16ba81d2e6f2cb2b33a7745e6edc014643e49cac8e8d672ae810" },
                { "be", "46d0a87efb0780d9019913fb26da243e93936dfd65e551e40697c00341d536e70d8a990caf40e2808ff31d5da3481fd8fc48c2951d4add9cacff09a8577a1307" },
                { "bg", "bbd272a2ae577517b21d69fdee7e6374f4da0ce07503c35c3d1477fd777c4733e2b9ab394ec44451aa076dafd965234a96ff34b2b6e1c14b12768cc92008cc51" },
                { "bn", "e54004ac4acc823edccf6e5e1f1a6418665deeecf73a169ea7e0f9f09e6b849c6b3cdf009b7d7591ed66b5251061ec88420292dabdbed716af69e7918b45ab0f" },
                { "br", "57e235d46e0fb7f932bbc1c433493759646a111f912e986a4f133538f609d4ba2ec5e7d84d1c33f226821aff36c32ceedad7514bba0c5ada6ee7f41ce2d12788" },
                { "bs", "f4ecb4ccf1b2422a988a3fd4b848bebe3c4173bcc7eb2724d4c3b100c9fa413a24f3daf6208ebf4bc1b62a7a476db03ea6bb2ba468a97f83f531e8daa623bb12" },
                { "ca", "8456bfeaa286eebd7b1726fa50f0f4ae3263cff5e71c959ee32535b182b1d0f1460c246215f8bf889ba313b1bace7c473ddb9e26c266ef95db74a7666f28f589" },
                { "cak", "c0c3440c20b06f8a4807b50ed080f6f4fcdc0006ea585e93553d059b59a22af47fa01554435eb89f5eca09ef9f1eaf335f4abd91daf3f228a4d8aa3ca4ba9e96" },
                { "cs", "b5e39ef18038ce6c9535327717899876d52118a79335c1e1b988d1d313d9fbed0f9651f31d1db5fcb3d6d367d3bb994af78e5a2d3364639a926cb97101905eea" },
                { "cy", "9e1f1548f9cfb1820b9bacc105088d7b37483d3e6d933799e5e28c0b8bcc131a1fcb1c26a2671d7505e52144f3239eb5f135ccd388ec22e0ce69bd6aeb55d17d" },
                { "da", "e8277e7964ada77b05417a582cb3064befcde83f5c896644e84d4403dd79eadf79fc1210d64258332392ba28e96a4e3257d768b1d26ce7b02868e3a29706a5b9" },
                { "de", "44e83db6b5e874508a90fd4429d22f5c7472ed21c3b177cafe6ce903178e74dd34658df3ff3f25d9420273b8bd04ec64b413279c63f2aa8c4ad93b64bf068135" },
                { "dsb", "500f47744a55e73594aec2a19f5e3bce3806b6cac4022921e76f174a91e69a80fad34d78342e34cc08226600850e40230e5afd6d0c05f6a04b66fe720d597adb" },
                { "el", "c314e363b82b9e74d38110a646881e208bef5a922842a562f36ac402afa08989cb126dd97ae6af9aa6d2bd853f8c4becc2aaba8f145eb81f8cb0218823ddf8f9" },
                { "en-CA", "d61a8d0c3ad6e7ce4bf7a10cadca79e6acbc82f38e7d1a6c6458757221e86a7a6929c8688ca676bf4cdfbcc33fd638206c6865d01f101ea577ba1fdfae560341" },
                { "en-GB", "85659110fa925bd740b4b560f3fd97085eb75487cfc6d104831cb082f8e3d65c1b4fb85ee2b91b9350f29a6d3e681003b63f93fe504ce6434cceac24eec71345" },
                { "en-US", "4a1896aa7376b3cceb7af6bd5bddcfad5d852494816d6824e2166a7fa498bfc7588ecb610856e24fdee3bbe2806595bdc653b4a974d7d86a68775a4ddf9800d7" },
                { "eo", "e76f5a875ad035dfbc647b5f6d51af69baf74aa7e07ed86f4d200825649ad14c2c42f9fcb46fbd74c6b7d05963722d1240a5bdcab361b119acaca1855af0aabf" },
                { "es-AR", "b5514f8b521ba0c9fc5cece6aabf6ecc2a97e72557dc828c0eb2b125e1b526c0539c13a70ce866756dc93845bf5478c7ab36a28e3a0a438e9a423cd000e2de5f" },
                { "es-CL", "c09d27a48e4d4e00079282c6c6e3e1883023d8e0ccad3e0422e7d20ae8950eb5997b044065ebe5bda1402736e3708e5c66958428fe4578a7d9304b0b701cea28" },
                { "es-ES", "55bcf73b291182491641dab0cb8f25202f1649228ad99864800f96081e040afdf2f252fd1e91be88f25c50c372c686f28214eed2a9697a9bdc1d630a0da5acf8" },
                { "es-MX", "bfa76e7ee8a017c67de7d00a96b78880a3bd94acbdefe8d322af0e0b16ef12d14443cba2a512446b745646f8785850dbe861e771ead7febbe20d7c565d2c3bfb" },
                { "et", "10cf47c1ff4ea935fb62c8c5bb4ca6580ee7c0ea22c0ebe7c6a8cffcec0d4f18be18deb084012fe03370bb96ff191783e5a3009e3ce54b819a833155333a03ff" },
                { "eu", "6c0a6392e561bb9779287f4599c20e03938ffd838156600dd67161e34cf8178119a044aa5b4d7b51da2a9d1260c267704a2e4e25df0473cb9352a515b3069d7b" },
                { "fa", "cab1036789504c697ac96f0fdc8f6819f9ba6d65b01b8607381c9af774dfd483d3b019cdd2e9bede132ac15aea54ccf2fae4c6c8528351e97a3efcbd22b7a4f8" },
                { "ff", "f779ae13a7d085c7229de9480dfb729624e7986eac0ed69fb3f3ae2dc71d22db62d0ad94721b41439c7a26c09ae9109107a31f93d6d7b399339193841d013752" },
                { "fi", "dda7527c29e78e519b023fdaf3360ec47606ce3fb6c31de63478bc2cac72ea9d39c0c628c526f134ebc3ae11598dc997bf697b0f022de11a6d2d7cb5fc9303c9" },
                { "fr", "b933b1592aac9f0ad7e16004a5d86cd5771bf72c6982cafb782b43b7f60d02927957e834c84e9b7a42c162a22b88b6a88b78f03c50a91f6e6a4084bec8a7d9ba" },
                { "fur", "56d5034040a069273a7a1f7b8a9fc0157e88989f892f78143ffad76b452e73629520347eb1aaa3e39b51226a371569e85af2fe28766d41a1905b2ad192362369" },
                { "fy-NL", "a345bdb24294a09f882200d607f5cfaacfd2929f506d84d24677b01574ed103211530ceaf99287aaaadb49450ee2bc02ca525b565e89be227179dd886f8814a9" },
                { "ga-IE", "8cd345a5b899033fca8c70cbcbbd1a5961a7bcd9493b92eb999b602e948be8e188d7f7aaa6fda526cb8fefcde20d387ba6727658d4c5aeb399a28e7acf2d6b08" },
                { "gd", "8a28f56a6d8ed61c78b91bf23e4e5c6fb4def0508d26d16672133d8cc736e83b56c82d7da72a411ce4dbabc4c1de9448ab822cd71d82b02073c4ffc447658fd7" },
                { "gl", "c4fdb3c0bedb6057c2acd4d039f5e96f556e8c83b3b860fc0e1b874801e7660c29cf5457a0ed97fbeaed32583bffe64eb49da9e54c5a8298c944fbe0dbcd8355" },
                { "gn", "98cec137e8da282564df862c324e420b5ba149b521072d3e18f557c53cafbc735ac70235d794968afec5bd5ea1e0624069f2f5d782e012193dace9b15444f2aa" },
                { "gu-IN", "cee62db427e28130c434907b029f5643c2da66dd1a2defb62d9ea3dfe225f22c6f6c1675b424c80104d32c1d875fcc04456750051d00e26d4f85519e9b9d8448" },
                { "he", "4ba2e63de5e2a69001aee953f6edf590428c15a3aa2d87e6aeb8caab67fed67d6256ef0e80167ff39dc9f33c2e2bc6566cfc493e7c552cf244357fa1a671d47a" },
                { "hi-IN", "4f77ebdaf8b8483a3968280e9e72553e7f638cc02a9c06e5dd31269ff7602db51cea95c77e98845ce9bbd1f143cce7e77f126f1c75c41f33ef31d14aa0f71b70" },
                { "hr", "b214338fbf053d50d3ec04f8214ba24164e2fcf4d9dd43da4e0a9a47fc6c33cb0fc1fe051f586dbfcb4278abb5599f69cfed5e16ad76939b9ad6960d69a0734d" },
                { "hsb", "a98323ba8dff050d833959745e1754ef68177fbcc2c04f146d40efe98d8aa07b66a9a8af912e771c36d99e7b7a8282a72af43fab6e25c0c444630d1323e4f09b" },
                { "hu", "979c7dd8bacbaf8fe9f8a0ad28ac438bbd7c66d02e847f744140074862a3731365690e78401e3e356eed1950b8b33375bcb831334ed1f918b3898371241c49c7" },
                { "hy-AM", "6e527ae34a59282ac867258acb6cf5d1fd1a2d0579e4b4ebf9d5fbab1e424433586cdc8276ba8d46f9da6682bd2e5c94ef70e10f6ce2c27ccd49fcdba741bc9d" },
                { "ia", "ad294196bb8e09e5cf9cb9374f790972ce113ef8668d75de4c0857d905822877bc243f0dd4d871b20bc970b476ff541a9c693ca8d0dcfe13e95956938db0da47" },
                { "id", "a5a4f6d8f247c364490de24e6e91cb479ef9d0a223ff4681bdd575fc3d0dd9e7e8e2b7189e9d57d5d3cf93ed7604ed9239e0931489d42a78e201e5911b9b5ca0" },
                { "is", "3ff2173194c754c88a1e39606d54407ade15aa6706716492c354c166c8076fbecaf9e256b244c5579a30a10ca83166c28eabb0f0f46a437e8a7f668039247198" },
                { "it", "f655b83b09b014a0650fdb6c4de322de1f793c0237740a39130ad1e77adc81235f33039315ab3e8ac3c26f9b717223251481d064d88aab55a616cf73d72b025a" },
                { "ja", "b7ed86b2c25239f4f6a39be3f7e814a046fed67ed796ead83c156951baeff9028172794558ec69bac659ba710694d89b07938ff7aba3857f33b694ee177f127f" },
                { "ka", "e0071b566ef6e67c9be4855808ce8d87ae578dc268206becae6bb43159c1765c4b07b9b1f2c0247a7090af8daf89accbbb60f7f7d0e2a1ca11503b7552d02a26" },
                { "kab", "e0cba631ac192990832500831ab55082056ce693db29c2c6a437e7d6d383af6bf497b2b8abf7514fe3741c692ce6f27b14349702ed69608816ccf2350005c201" },
                { "kk", "a9a584ca8e1760496d3aa5dd3615ba40c87a3d897dbceaee70ec3789451e5114ddd1bb6d49c486b7d790269b3011b7590a4607d843039d295c88008dfacac7f7" },
                { "km", "6040639c59b1bd1722fb42def12b39d38449838e936ca5fb5f8e74acb2f6fd07f2db5436f5c52d1c809d8ae558e9fa86bc2d5edbe83d68c05bf604a65a6f80de" },
                { "kn", "38865d8162560a6e48e44244684d2d60f49a8066c8fec6be7fd1609299e22865f40bc3bc959e33353c0a9407974e5af074214814a7ab030c436fa7bb13df26a6" },
                { "ko", "d6e4d6d647467fd7542509a353dceba8a07ea63848fec0c1b98318bb9a47321349a32c3b2aa89f1e30facb9ca06fbb69fb263dd49ef8987e0512984f802275cb" },
                { "lij", "649acc11e14a017dea7028ad875d91c7d4c419c0885fa934375fec43ff6981cf5fdfd96f281f440e1a2f69b5f7df70bede8f9312648e551abe0cc84c2941026d" },
                { "lt", "8621a540c45e0894dfb8e525c68b6bb4f794f03cb3f7166b380ac19490e5c9f0d4ec9594b82fd23042f278f525d3baeaa535463d5602327f47bf511257432a76" },
                { "lv", "e34155647569cbc5da1d7b2981cd4ad7ea65aa4941ea49e9dce0826750f216678cfecbf49fbe0e3f1beb281243d9596295b771d878cc260da476fac561efbcf1" },
                { "mk", "1b2087f406d3b326678b475a88d9ae09397c44a6c91e76fd6137bbdd955f86e98af2312621b0f01fab2c00135239cbac0c6f276ee684ed0fb74515c7e8a32f51" },
                { "mr", "eda9936ca76e46c6a753f13833df438cfbdc95bdb6ca573d88739f74e01b42aa3bdd6f0815bdd95d68aa7c9189c554dbc7fab3eee3dac472367e5e505f98a12b" },
                { "ms", "76df2bf877aef223f2459c57e0951bd7c6b08267893fb0a8d1b4a245bc7ba23028ff66d78f52a6e71d246c1972e12b874b2a4b9efb62b66262f86d172d6ff793" },
                { "my", "b90ba2ad0114e61662b9bc5042674f77e75e2261174140bbf8f291d2757b377e1d8df61464d3c2ddf8c7c9df3bb4475702980f4006eb5f10c65c8402d134e851" },
                { "nb-NO", "6b970d426e1236f3928ce099b1d56e0c42aae407ff0eae34389f37b8bd64a9d509c74284d8a82363644a298e935a9358350f6a937c85de2d995656f10cf637db" },
                { "ne-NP", "d24161c310b6bf666c9761c33120158e21848e90b46015be1c9225d3382a64d11f44fa38421377440cbe8cedd25883957391926071bcead04a941434c3f8f7c6" },
                { "nl", "c75aab08d558459a8d18ed157f64649837674e9c9725d3c9a40942246b053ff73004ae3a9a7d31aa7d92c63c66fb6ac78944888d70d446ab13d6ebd4419895b1" },
                { "nn-NO", "47206d0d821e9f2a5782f464cab2423e4e46fa2173d3d844e5e8e2a49d9be72f7cd1e00a2ef8372b17b37a205474db1fba6f94fb0c785136e2657ada887deb3b" },
                { "oc", "7dc84384d73415119773b45932c1269f8531d9fe9eca1713ccd939c1da3b02c9763c90b2a55b76dd006d18cda4c95cb4fcbf81e0385413ab1df17f97ace912d0" },
                { "pa-IN", "a63b5e1a60bd46aae463cd0c5c2e1fef8ed0d0ea453bb84735310b0e615848092c8e9a94781cbbe1fd9c8c06d1a3aa00b675e616cde902bc1d57b4e0347aeb9c" },
                { "pl", "df80cb03d951ccce29f818e37f3d2503db262ae2fd1b6c182a2e1a111fc86428e48da908981e469a30891955930a294e732fe36bff5134bbaa128d9d5136e83b" },
                { "pt-BR", "c7c1def43e5d53a32c9e468fe2b3338a454c27c8ef1d0f3846283fdaeda6a599e4a0234b439b9d447eea2d433b8e1f60ec0d1f3c2ec920c021b31606aebf426f" },
                { "pt-PT", "ca4e7c2c648b74861bb20a7f35a0e527cebdf9c922177528d35ca03146992f49da7bfee46f301e5f53a26f79d79e2a25ea34f2e0777e88e36b3e7ea452afd580" },
                { "rm", "276acadaab3e6e7ebb13e68856ca6de21351a226bdfcc4acbdd601230435a3614241c9f16aa8d60f3bf01f1654ae7b88d27e7520047b1fe9aa41314b9d6af64b" },
                { "ro", "58655428e8af9e4ce168b9e29ab629385803a4605432ec701fb6ee3ea4b78a16b2d1b66e9d1f7fc544ef37fa031f8b4593eecbdf3e496d89b93e01cedcfb7050" },
                { "ru", "b4311677c09a20aaebac5e7a39e06fd6289a74337d884adf3d75297b56d542885f14390b98b21097b0d9f883828d02cf2a54c80c4bd4b7bbdc009e84b3c5026d" },
                { "sat", "8b42893e68d424970dcd416f08e14bf7213385b045849629d4bd5acbde8b44a85983b9ec3777370c967a564d8122ef0a8278fd7385a1a759d9233fb8f0a30a0c" },
                { "sc", "fbd5c02427afaf927474f73e327923705b0f04b179339ede00de2177d58831943423b64fba27a514d68012d6db3d99763db77e8e8bebc9680b1f5c1d3d1e47ea" },
                { "sco", "4d7a97d7364f3e727cf1773e4e0c9ac49bf5aa1e76d316e97a4821887600248b321b62c486dbd4e405da936abded4880346bcc22d416e94302bd5b15e4b0c60d" },
                { "si", "2e629a0d5dfb9e8bd81afe7c1ac1c56eaa75289d276e8fbdec6f38c58a1870022a82b99e11cb2e1aa46798542f19e0a80b87f9b46075d519b0246fc4ec93cb07" },
                { "sk", "0b06d750dd7dfdda8e7c083e078caa9ee47ec2d6719a23658a2092a0ddab41b88d09490712aca755011bb1c2195f6d00e34e356e939bce00ba09cd93f9afd640" },
                { "skr", "f1f123256bc08c6e7ad04ab1c267984bd69d2879a5d1b55b47457112c81d80e2537922684b92c2a7900dc47c91af014ccd8fd62b07f48aa9b276b51fc4e95fbd" },
                { "sl", "730ede22e929e60dc4248355e08e0893cc0c4b40a9c3fd4c58ba3256d36a389282ab42839535ceb198e0c73c235963fcdf4e66f7702a2b24dc16474cd4be063e" },
                { "son", "ad40038b982d7ab6a6c4ce904aab6acaafb018a9f545c5cad289f8b173fb7c22f3bca1ce655436ddb4522b1a8f18be202810ebb1d70f7d890323f46b70174695" },
                { "sq", "777189de420ec29a498277ea4d29566308ea2371833cb20ade76f4e972430bbbad0c070fcf58b2e17762dddbaf0f4a5f5ad17991e2363d1f6cc81295cf6ef2f8" },
                { "sr", "f98faadaa13f2c1fd209b737b61ef5b8b021c3f24339bbd145e69b3b292cc9beb707ffdf9e8ab563d85d7ca395e580bb3ef841a2fd7ec668fceb68c362e2fdef" },
                { "sv-SE", "19369cb71479e78e6cee9d02769a8b39cf5a2ce5309b558f10327c5410effadbdff5ebdc07031163fa8e8088050b062f194b5db226a47de3c46e46dc9b1155ee" },
                { "szl", "209972c6b69899c1ceaa4f1a361ee80e8e54da2d965482112ed93bb3240aa5d5733a9cc5d00a8ffbc0510162c89457bf1de9c6ac0a4660002670ca98ef535f0b" },
                { "ta", "6b71dd05f3e0a349cabf3b854219565a8c2d55242c1d95eb69687a9251d541e9158a29b880f3741e000dc05669a4b0222317753797dca17d9de8205cc5eecedb" },
                { "te", "d256bd97df4c990dc294924693e5655685def1b1e20e178ab6f103c3bca34ba8ad6ccfa1abeed57f4e8c6d53d1f25c657740c8c88fcc4a5b437ab05b19680372" },
                { "tg", "7eb48d5139a12a1a1cde8843730da6ba27e08bf7c9daff25c1fe49dbdfcc55048fb5b5dd524a82523c004eda34788e4583b2bd99f006ec9567882c8a75ebafdc" },
                { "th", "bfc39db8da737357f72c60d578acbb9f7c05ebf56ded6d6c223afec2183ab9f0a16c19b26808620eee358199a5349f15fbd623ffeb5bc84174ed6bc5db84d876" },
                { "tl", "fdae8edd9ad1748426fc3daa330cf16ca41c5c8b18446a9aca885565109e49d08bfb2b18f1c8680548c3530704c6d61f9b26d114aace1d6b908e21d6f8e279b4" },
                { "tr", "c198747db433bb5921080e30586b96ae0ed7ee45817af4a55ea0222676e3dc3e0c19326d122ef6ce462cd1d91b9871206fd14bc79f057f9cbf912bd62ed1e609" },
                { "trs", "2aff3d7b3a157bb1e849a18582a9745432faeab0641ee698f8c53dc3f240ecb840b42adcbe5de479fa78da268a97677890ecb1c3d157db9335f9f746a0ff2f5f" },
                { "uk", "75cd40ef586cef80e6ec910b0d67b500c25d26d292b931cc07c51cc9a34b2894287061a6c54250d09fe76fa29c84325b67a37f31e2f9616dc83e395b2f81eda0" },
                { "ur", "399ee51213134cae744e774dd0c28b37ec9850accb9010e6bd64ab60a41804684d9564414810eabc081ec174c1214df261968c682d50d0e3f9c4699f50d9c5fb" },
                { "uz", "329a5bbdc003bca8174d0a2794bd42410ecabfa07f0f6b9c6cff816b196f89231245d3a002092ca60a23fc84c3fb77ff81636865ff1d790758b8f959809e2883" },
                { "vi", "6737aa135d1d288f9a9c7c92a740a526716ede3fb8d3d34ea7059f58af1e033f7ebc74571a3242e1e4bf7ee22581959efbfff1f1638b06131ff015aa4b82dbfb" },
                { "xh", "4bba487f056b43ce3aa1e362acdc55d1a39531b82b948c6f91e9a13f28b86613139aa9ed068a08237279e48730c4def14b43e6caaf641d73f58bf68213dd7781" },
                { "zh-CN", "f8a848e24aae6f4aee1d2362ccd774ce20f9756b177555ce90e3ab2b7d17ed5363987a608f0d63c1b48c3c36ebd11b38073b8798b78bb3668903093794e82010" },
                { "zh-TW", "56ecbfe81bc67910a25de0ef1d3a00a1ad1e2100372cfd296313cda78fb5e0e8c6f4ff78c874e1275f8aa3e913344610d2488b3049bb8ab08b8e16969ef58004" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/130.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "62dfde26b83108908f029a89077abee27352b3b4c184779c248f9f92f6b057989b081a7dbed1735bb45deca894ee21e14feb58d33f14c3a2cb309ce5fd2cdcd0" },
                { "af", "91de7ba65aa80331b9c35de6f53342c6b5d50f03eab707ee7f9232dccf4e53cbaed98610682350647efdd31358f1dd6a9b15b388fe7146503e6561c37135e3ce" },
                { "an", "64f4d7c66722755a4e469a39d27426d68bf613c4026f3799e15973e003aacd5adb87921e16eaf0bbe6576ee7eeca9a7a644b91bcc803904f8be2ff59b5fa1bd8" },
                { "ar", "ea1d3e8e1a61e1997995ef68300bda34a0dfd31c6115d24ad8e458a1d22a6486bd701e0c920cfccbe53a75ad79c0a68b7738b3f6438d3357a5d522ba72d1e7a7" },
                { "ast", "4992d61d189f6e1e194e287a0e662fd6e0e2add639ff04ead85a98480ed2797ffa4a516976aca162defcfd0b2bf116a1ff77568a7cf96108032b9666f705fd95" },
                { "az", "9344eff24e5f01442af3e24f4c735d5ec0c6dc67d3e766fce96050cf757199c4ecdfa14982498eab83e45289cbb06de37a86bb22017d4b8b0118e81281924e4b" },
                { "be", "697171a4489d24af3a5874975c075f74df7fedc27b25e39861e9d3b70f2abbaaafe24f9b96ddee3888ac97b425054319047dd833d6c5880c456b9fe762900396" },
                { "bg", "31bc39559a6c8932a5b86b91afc58df58e872101a5dcdc57b60c845ec92ead5e5d21dd6c22c2081891fb326a438fbfdb563045b81819e3b7d20106b5b93c639f" },
                { "bn", "fde142cc102ca97d52fcce40fa2d28c36e1c57ab69b09a1400066d54b302bf35cf3baa90b23418ff4166ceaaf016295d31807af77311e74d17418dc2aed9b851" },
                { "br", "f7e55421696864594ef3250043976e433a6ae9505969ac05dbc54b741d2e2b0e81032b288b3412f03a24b8062768cc1144cff32734118fd0ba6d9f82e142566e" },
                { "bs", "5daaee46f6b09082ecb0b9fe2ae050b397acd961cb760395b630f215ebfda71eb75043f720432e83b0ba710189a2f658f432a1200dfb73a4c6afbe06224bbd0b" },
                { "ca", "ad012b14f0a096f7be2a5a9cd72c94c8968dce053b266a7437827ac5bc5ca03263afcc788cec28acf6b1eada3b8e10f7e5773cdfef0a54b1c1c7d78dd14bba67" },
                { "cak", "c4263d1e9e44522108b50cf6df7ea72986d34e55ea405c5fa183428d1289a5b9e303e70474e8d764697f955b1597265d42eddf7d738f9141b28a9b225b4de905" },
                { "cs", "87a96f56eae46097a4ec69e5e5a7a9f41593b09b5ab62f68a97de9c56187c81ecd0c28e9baa44a455256d5eba2fe18dc701402c3551fb06944949a58e8055f90" },
                { "cy", "fff177d20718a39f38e1a89011f3a5f3b86b93457571265a97030137033d2f2d08b449d1b1cc12ca498c519d6c7c910f9483ecdbf1041a222c7e5af49205848f" },
                { "da", "42e12b44509139e950bc2dfc723c28d28b59a5e808a9056bcf6902b4a61d963ec15f18822231286a08fbd5d6b599b04f5c58204d9752d4b89008582285e48437" },
                { "de", "2a8b8a3c594f3cca21320207729ba4627710fa3793ba0345e6d681aadb858d87e904d57d98c49ab63467f95bc1da61511ff062a202260f86478ae2e431c580dc" },
                { "dsb", "db9f572f038a9789e0071f81849eb3db7a780367237bf7ae07b8f5b8f3d6d1d49ca2f5c5e4bb4e352c2b904de317c78d82982973410f4e86c19326be6ec66abc" },
                { "el", "ac9566282711ed6e0f24774bdedd3a796f7fab13044bacdd140c2c348d19206dbe848b09313065ab864582e73b972e1a790782a749fdcde35bf65900ba469293" },
                { "en-CA", "d3e997f1aba37a40b3391918032c0e7d64ea6d9e43eba74ed821d8d57a7076d236881d998233c1378c31d16099212059f39c4a29756377a2e2fb492992a980b8" },
                { "en-GB", "dbc11c6bf36aaefbfbcd8027014d3ee8ba8db894a243c2a0b87dfffa27b596ba94fa9c9d674b92b5b1733fe1a71d5c734f7c61e33e597e0a04440703c402d0c3" },
                { "en-US", "7c0a4e1d72d4908cdb7d5a2d451968d4dee1a503eeb7398254d8d094dbbfb1496baf43351776852ee3028b0af00b492c4f85cdd82453e98b09ca4f7346b7fc46" },
                { "eo", "eba3abf557486885750dcf74f0dc83a7a91d8f810ee989db0b878e372bea66b87969943305079f377e3d6e8cf6034dec3f018aa1e159fdf4487d9bd493279b6a" },
                { "es-AR", "a8847bd578f0326d832d5b3d744036b5b2d79b58febf05b9ebecc5601f3c81c7c92b5708189a5fac84cea5c02e269aea6499b6ef02db2588cc37a787541d7f34" },
                { "es-CL", "8646b3e66b98d4bb2e12d8ce567dd14d11af30256ff242b50ba8cfc957fa08c7af898930eb06b94b9fc35fa58a19db2b31f53b82ba00ba3543d09a6b5e810627" },
                { "es-ES", "f9ee88ba7cc46bca844ba5c09b8209fb164f156a4058678aa4bc38664467c2df1ccaab76c449059fc9f62a612715788adf6dc68ba75b317911ab912ce5854176" },
                { "es-MX", "188bb982f5c101b5b1066bcc675ce5c4c7a6e9f2be6de28186cb7f320177b363aa52d4cac063a1cb3d5a632e85722851dac7eed2f7af1e7d99c30cacf1ff12e7" },
                { "et", "d909bbdaf723537ef7f41b3f73524c8ba9d49fcbb556912851e45affa8fb0feadb139668943b9dacf4edc51bc991ace53b4d680e71057e945eebc714c0537f29" },
                { "eu", "0d124751f0a97c61ee2e0130813687f615d283aac7680808dd39d8c2fa85857c283f61671662fc4edc6dd180734a5a0d67dcd30a67fb0caf82bd06631a198e47" },
                { "fa", "27db95675ca8b1d998b8abdc6e889d584e44d1803861b3bf69926e399b5c7d8e7478d9c94872a6884006406f1b384ba570c5809c2b90bd4036fe310f5c301530" },
                { "ff", "220882469a017d0b4fae078246c9c29a7045278132f9cf3fdf20badd9cdb2a785996f43d31661b50de108ebc3ba27683c55476280310a078b05cd8c1ff197bca" },
                { "fi", "22440519a3591a89403f4dfdfe5af5726c48911f178269e9c93d3ac65afaf297234e303168126de1c4dc60ba655eb1eaa3bb53b6d81d18f46a967995d9c1ca78" },
                { "fr", "703b7808f8cb8a874fbe6aab4f1eec7756c90bd041043c311f2a8af8fec250732a3cca89956020ee1dcf9e5e69adee71b6c1bdf3d33e9d7f1e9434e74c811d7a" },
                { "fur", "6885a2788bdd1ea763ed22e5f3df845ee8de9535da23dfefecbe9c8c2b0c6dfb81d41beb5f5dfb254e269c04f9ef542e0c52cb2e1ee080aefa34bbe05168fdbb" },
                { "fy-NL", "a2b36d6768eef570eabce5c54e9e642bf490511f20919655b72ba9a8a1e8a7a460b011b17485a465ca06bee1740a1821d7b407d17ca6694c77662dddd9593266" },
                { "ga-IE", "182915d18b00f7099b2b9d4a19be20739f15686b40cab0d89c60f5a099804a08c7b33d5c7c8c3ff2e2b0d10e5fd41712990548afef9f0e65af866e393eb179e1" },
                { "gd", "2e662788fcf8b606c0dd3120d3c7a62cf41862b0c38bfd956de545903b80572710e6eb5215e27349cc0ba9852da6ce23d1bc2e8b4de0f6ae9f96d8096b5bebb5" },
                { "gl", "b83de854042f8eedd691ce1b1d9d5f80efb4b56af20be86edab2be365a255b5861c399fb5cd7936bf5c0c9bd7b930233483012cf4cc8851527fee10da7b1dc60" },
                { "gn", "2c5b141e603a87b3ac98107061ab466682393faf59e8087316077d129aa3e962d738f7fa12837462db5976a383438148f1f8f24ff2624d391702a4ac6281b0f0" },
                { "gu-IN", "627c3aaa2555e3b92b979e1d45cfab871e5ba231df56f137589b01dccb602e90d8064a9b851deb4b06e00a0d4f9246475208586613cb6d90dad04bfdf015539b" },
                { "he", "17181654086389ab1850fa88760bdf11cfd2585971d201be5a899ec528b3cce302b7f179103c82aec495bc082031a60169222048621591e17514024419980aa7" },
                { "hi-IN", "8a2fe2306af86acf84da88a553321c615cd3a6644f31f59365b0ae817326e37a1463e2e8d2113fa2acb2d0741ca9ebbdd4a85d1140eebfa9ec4f5f7d6010bee7" },
                { "hr", "82eb0d30e2e2f0d1cefca8ba235a1f81211a2064b1988f07e178c5e2573e78936461d9993d87e0311dfd680b9dfe247e7ff941150aed30e9e2a50640748c2706" },
                { "hsb", "a22c4e240b9c7a2ab9f9db4f8d29a9c0adb07f52bfac83b574645d6b3c98b41ca4f021e641246169ea6ea97d321af349c2078ba2a12a62ed2ee869355e3c5f4f" },
                { "hu", "db34655236e20d07e642f67027712b91d4257e35052031c596f8c2b325024c114c7d3b9f7212f7e63ebd34396c951cec78052d48a820ccf51b851a1e3f61fe12" },
                { "hy-AM", "084f25ab90894600ea8e99aad92d2783ebb47b689456937e51030243834e1fcf1e0b28a208ca8cb9aa0eba88c2671898b6ead254759d1144001016cb39510cd9" },
                { "ia", "6b0502bc3e53f6fdbc0c7151574e47e549ac2d179d608dc18e679b7fb8f65e60807b84ad1e7ef5b33be71fb73b10c72f241f1a5bc0e4aea7691be376ce33b51d" },
                { "id", "b6e729c75103cb79bfb9f3a2be68071bd613513feeb36cdf0716162b24820bd7836059cbcc7ef59878a5b04c2f899ae53c2e59c4a91db3076717a5f5c77a82af" },
                { "is", "aae18465f433b7f895fa42d4d3592e261497c524068f5988cd54580d5b16e1d6a738329bdabfefba2a0edc74e94ce78b4d893d2fe6fceb1f367d51f185c3d52c" },
                { "it", "ca14eb087dcf014c97daf759f8d1b972505fe47938b8536798992deaf1a67efd08e82f670e38bab776c899b4e1e73a050c7810a32bbb5987a9faf8991915ebc2" },
                { "ja", "2e23b26a5d0734291282bb9d43ffb32e54085ce3b29428beafc9e00c249ebf5bd26c074ffe5ce71e8ef4229cae84109ecf6ec92be2613588b40fb8154cd28d89" },
                { "ka", "1b47126c3b61859d398e6e6bb0cc3d90a954497b400f211f8feba03bf6635cd0ae312e9aa22bf555d333f543038bc46e7f100700bc3d4d23e0c13bc88d7d5ccb" },
                { "kab", "99018f4a7a2d3b1d9176bf0a069b33b2edb7acdae8e616524467c217b8d1c0f8d2d7513d93b47e94ccdfc9f4233e559903f0ea8c2a987b49541440dcfcc663e4" },
                { "kk", "9b85c736005ee7ff8c4b5adf4a9f3f750d18aa4721689f2465638f361c1ba0258b130f9a30120096946f173785c2ff519253836b12ea5ea5600db082433f5453" },
                { "km", "9ef671871dbe3cd6d3eeedf937383f6c1b1cafe54773c33d96610bec068cd38795ef1c88d87c52c1a954727bc935eb27e1bf9ed210fd653ad2ac25e8eacc1ec8" },
                { "kn", "82d487506ea2ab388963f24c61e9c31205ca907465cfc47730f702c9249f9d9d16bdfad0b83f6c17622749fa10fd5c3c2f6ae98f46e2d46406fc08966a9ef260" },
                { "ko", "82767a78dfe8e585637fe14a8fb21f98c1e6eadb0583fda0893fc7643f3fdea8575cada6889f9e70a1b8b633963cfe376da9c3d82c6fdd21c5a51fa2cb8e1a12" },
                { "lij", "4798be7b2f2c194cd828dad90adf42d818e71dc937448dcf26248399d85fbb252054517202b4227e478f441cb9e604eb1ac8a4743b6caf73ae15b596170d3cf8" },
                { "lt", "8acdc181d25916c6eaec7a9428d2b497c90268079950190109c702cc3744674f945d9d19b7bc4fde8951696623920da33acb540a1c8292d7d3d630767250fa89" },
                { "lv", "5700141c87ad0e0d05f962bec3b99718ced482e98ffd88673ae8ec5036a969951c3e2589d176df43921d7739963bfb7ba81bb241d058ccfbac3a6d91f6523fdf" },
                { "mk", "ff987760e36b11b8212f61a3ef7c491afc82a508db54c1ba774431c78a3dc359d0bc80e37f964297c36771a0f6c129a81708030d37d423896de587b3ea7c2f78" },
                { "mr", "06d083cf76c39e543ec7fc17f8941c368c595527356fec98fab55d1ab044de5810aabb7b70b6ef13b0aa03a6422e07b7a814b61dccb479e6c85de92ac44fe9ea" },
                { "ms", "ffb900366dc0cff082d0a4b68e22d3197f724db5d096a1b630fd0ea886c8e90270fa9dd14fc5f18b6698c809e8f9f1089dd8346653a9be0aedef9b7b320e9c0f" },
                { "my", "23daaf593896309ad7b618fadfe3647c426b5ca5e977e887fbe59eb96f853565b725ad74e2d3e0d133ebc4b8e2d35013e0649a3fe07a4495e8ee0084352624f6" },
                { "nb-NO", "bf58a7b8a0783d60c0c11108490151096e1dfb9c579efe23369de0bcf725e7459047fb65b263ad7cf7553e33812123f8f1009515289cd4ed24d1faea223cfd11" },
                { "ne-NP", "6e3e3cdc0654fbf47c7420da0388cb07b27006390f9b2ad4d951fa526cdc5c5cf03d1284914e52c16f394eaebee42966614e757e3d1251fd3f79a7fdc6bd4198" },
                { "nl", "649f0f4f0f3c23e08bc3357d5e3a5daf84ee01ce6f8f794cab51440345f03950ca46d949ba1e5aa9497e1c5859dcf1e4d6c0f9c61869a79986e9487809ea389f" },
                { "nn-NO", "de4451c5062fe4f1e565bfa54e3b10f6aa258be1856711faa883263430a58b8c1ee129f0d840394b682f74cb41d1258b4474edf243ea20b547b03dc39c3360c9" },
                { "oc", "4a0d40ff7b149a9a74d6b275d157fc6f6f8b34c770520dd0188b7a860cf6622bf7829fd3ee004c42140f4796e73f2e4aa1dbc9bc7cf6996c4f4e0d8563c9c529" },
                { "pa-IN", "54007cbf585d03285a1c9855832ea910adae24aa216433163147f219dddb5418ab33c669dc269977f02c0baf4f0efe2bbdbcaa760c322da073feca0e68d11e68" },
                { "pl", "64400453378652b0c1550e736c746c29686474a5cfe4a497bcf901158686b57838d71779a26d64c40084bd86ed870bfa03717080c60be7b6882596891fe49781" },
                { "pt-BR", "2d386604c25029529a08c8bcf687ffe2799a95a8ad3cb6d3de48f44feb6152d8d6dfbe1fb695ee90ce1a8a8f6caf01ce2c1ba424e2736c030f2dfb90769611b1" },
                { "pt-PT", "8f00ebc5d41fc9da4b45a1549a6ec17b7d1174dea1b84d423dde37956fa26fea1c300d0d7af7a9bbb0108bee293d63a03b28d176675f74f8bc06f6ecc8d03b35" },
                { "rm", "e632b938e692e61c788be38ebc53437ff89a7d6aec0495d704fb6eb25006b13a41ac23d02ae4dabe3bf74667397c9290c64053b0e21344627de6cc724678fe5a" },
                { "ro", "1c53f68f22c138da565677bd316ae03b5581de38bfeb9b171de182163cc8adbb0a1e78ab88ceca4e92b4315e54fc3a5a9c49a80337a51373118034fa0b0e5d02" },
                { "ru", "7855d4a645d5aa2c46375bb37e2c1cbd67b0772e3fd2182a7a71f6485fafc0758b6db7d78f4bee11d839c9c7e459c6276edbde63f1b14f7730c112f7b0339162" },
                { "sat", "8870c6d6b2f63a6e58e3772627c9106e0e717c8f7322afb204abe2044aba300a84f93e2e31583033db00b800b2378c2490bc9f6dd7fe381585d7cbb15dbbab52" },
                { "sc", "2cbf069897e434a0c9910b6aa041806b785062de30fa0b7dd175e7534d26ca1c594a8f79595429a9eb337353b1ba1598f948cf48f50410091ca40c05e1e71f6c" },
                { "sco", "2bd70f719e7850d622467199849574f7f4394be11c6bf544abead2a0b82b4b83a60361ae314a82e87f1620295fa9aeb3e3d4897a0d255f615712df7daf27d209" },
                { "si", "8bc7bcd19fc78c685d283829192b4447573c815485514b618fc53a4d16241d9f16f0c727f7c807313ed615fd4a5d72b306912c0e49ce6165cb2541ad81cd7617" },
                { "sk", "002f76ddc0055c615b761da118ddfa84e9ba3ac9431af50331db387e5c60f20ca04f135c5bb38cd9259fd925c25fb2b72ef6c6ce613701cc73105e43351a29f5" },
                { "skr", "fd4b1753fd5800fc01d52698cf8feb7fa9392393dce46fad298e2b89546cceb38b6aa2af864f1032125e460d76479d51702e28d8c07c5df359f40e0fae1ebcfd" },
                { "sl", "247653b3084989636aa26b749cf0b1e87bac8df66321703fbe55cb4dfe9d14af4314f52d9f6b79e0cb34ee6b5c6cf9316a91b52b07b8ae3ad9d6b417431bac73" },
                { "son", "6a361ae3b71223a0d068f4892bb31ca05b5cec011150b9ea7cfa2c165b5ef23f1d88e405eb8e6dd79fb3249a3609991074cc81ceb09d6709368c198be80d62ff" },
                { "sq", "ac5cd0bbeed4b8b973729eafc48f997f5dc5af1db3b1a04a23265dcf78e1b40692fd15305d8f0009f94310a79776ed3a3607a2f0184823a059fdf8bb131bb2b0" },
                { "sr", "cc49d1612f39a1843d3d7a29b2300fa0d3f5648d7d067dffc4e4564f76bcf39b06fc3a1b47a59bcd2b8db1d01b4c6a500996439876ee03416c657862da171c5a" },
                { "sv-SE", "de7fb045340db3a7e3b073a88339aa50794d8ad23b0ecf8dcf97c8f79cf49bdde2d4732d825352c5ed2dde468cc3ecd3a6462a922bd22e52f18dde76732d8a3b" },
                { "szl", "008ee2e5ea28fb3aafa4b0ac2b969124d202edda1cd66701fe3cf14877d59fb57b1009ef1e113939e0575d25579b616b48277e15fb2bcef469c821157e319837" },
                { "ta", "c5bb9f0ec1121fd9bb188752628159390e820eedac86e64280342261f24807e7bd4a6c7e2d6c6a990379655bf64835e93e2946e851f2499cc530cfe58c081140" },
                { "te", "b3463f3c17673421c38d4b6313e47aec056217ad44683a8ad28701a97e006b5d0eb0c8ade3ab895fb6a1eedae0b21769423c4949549b2e1f1deda362717af096" },
                { "tg", "e45bc83a893bddabc92dae2d0e1d95549f59c42874418e1a9ba749d5d635f41aa6a51a3f02856ab0c6f5341bea21ff5d63e0abce14e9621adf647680b1928c29" },
                { "th", "3f495901931dc3070587e59f9f0610fb9d108aada1dc8127d0cda31bc93dc64dc5fa498b7a2d938fc8a04d3f6a8b4a9fc208189f8fcc85868dbb8140ca48b8e2" },
                { "tl", "9627d057bc5451e9eb4cc6a24c3c20e7014a630617a739c018d9c00f8965d58f60f157e85a8405ab0f3939456de177a007e7c37de0785296e67a23762b3b99fc" },
                { "tr", "7ba0ea577d80ad3f76d9a46402c10fe0d3db75536e7ae65a7ac17012312e5b1fbbbafb9bda2ace68d2f8caa7fac4876888500e8f85ae6e954698159fddf41e02" },
                { "trs", "867462557ae75c84941e5eade115058f6ce0336bf9763d9218957d792d3775411e4ae6bfc4c163fd411714f70e0bfedee0f4c83e4af1731957fb2c4b542a2443" },
                { "uk", "f735ad72f4e06fc82d42b4f1a1fcb74f54038f461b91c1d1aeaa6c53a167ffa13229b0f59dfbb688174f2f2f5b1d5052e5d2845c6b33c9eb93b4443fe79be8a1" },
                { "ur", "245b72d8562d0afcd47c98920e059e2803f6c77645604b43a284649d22d2640a0dc7ac57ef186b5164aa92d23558e766f5ebf3c76122c33494615fac2034e6c9" },
                { "uz", "431ac4c402008cea261bd41564f40dee070fce028c7ce14556d02790296489673e0fec98d5e8b187f8b53a6d00722e295f727b45f155bee15ebb37601aadabbe" },
                { "vi", "a9a390f633c60a962e1a09ecb55c4138a681a2c3baec6481c8e83aa3ae65d365b10e6890d075f7ec9d86acafaafd1f280886a7930632912232d862e7e687c4f3" },
                { "xh", "7feb6cedd5565dfd2822babf6ff164033f0ff81c9e07596e65ab1906817dee3fc54c23cfc4862f3e14f976eb6468168e77dc39cd298d1c805018d9871f5cc613" },
                { "zh-CN", "bb89ac8f3a86c9d9b40288c9d24a3a3a2551240d764e548b7a6849e9ef2ec21e19a7cc59293ab7bddd6760af8a12b2e4e766c5b5e71524b398645f0ead26f864" },
                { "zh-TW", "31ce5cd8c9e143ab941141cd89a3810ef8f8a29308899ae29ac73ec94c62999dfd6751cc61cba306dd303b786bd9312fb16ec788b936674fc9544a21bd31ad71" }
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
            const string knownVersion = "130.0.1";
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
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
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
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
            return new List<string>();
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
