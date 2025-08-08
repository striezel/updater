﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "142.0b9";


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
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c32bf6bf83e4d3c05e8ca95a0601cadc19f2c345d2b5a0ca70e1b2b558854684c604b05e80dcb1b740ee12b83fe64596a105c7c72b874073cb892fa5302607d6" },
                { "af", "059bc071d11bc886fed0d690d4704f69fae908139b33b208c9084d2c82dd69433f51a8c18f893f170ce59fad58f1e6dc925b01583358071808c4b74baee6c8e1" },
                { "an", "0120a829effa15becccc5dd6727095c722c043f5ee8111a31090984286b30da20719e90df8117dfd22e4601672ed9f1fa2f7a004a4238f7900f79f4e6b2ca8d0" },
                { "ar", "ceabd1dba9552ead6f6e006e0903d766770d8999aa701f3f36c65a71ecd10074afddff49e906545da93aeb6a36d74ec5ca05d07f92caf58a025aa5970814bf6f" },
                { "ast", "0ebae5e15347edc160e15b2bc9fed5fa6834597b916c4d884e619e970cc3124c80c3748bef87c0576dbc0ca45e37d6c02514bd84af023484297c34ef896c35ea" },
                { "az", "7329f2297bb89e475e942bd560eafea8ca7dacd817c8ffd0b22824972fc516e321631e8bc501d2a478f3bdf335ca25223b6563b804391b373449d82a068983d0" },
                { "be", "2dbce67bf5e975a4b39b1e71cc8490798df6f74caf971cd0a18b5ade6e026db5aab34f3a176e993d07da82ba008aab9f7b670abf2629d1cf7a229c29b6685597" },
                { "bg", "71a9f8cc96efbfd59e46051fdf6555b2b5d827ca720c67fcc836cbe64dcc022d5b305a47cf56d2ff50fbd9d4a631c6cfb2b5abd481c140de3456ae5620f6e7cf" },
                { "bn", "2e0d6652cd63088df34fe14cd39887eee00f6e664020be3b0777b5a6810b8453801cb91e5e26f8f1b730e07ef94ade2d4fc1af6ddcab1c563a83a01d52f6b917" },
                { "br", "0905b185a006d3bc40ea6ad7d43d3b236c22cfb4dacd94525585d5b4b5e04ddfda20ae6ea261b14fb7a1caacc8e1bfebb5d9ebb3ad5b0cbb3a2e2c1278abdbc9" },
                { "bs", "e1058fc3cd274b921ba0175c950831bfb2eed3e7aad229ccacb1af11e1279cc7ec5176bb5056880c6766e48e5cf341dc19d2889296bbd43b928c269df6811b77" },
                { "ca", "9b4142683e7c8b693a8233e4d0f09f0ece8508bd97133c5d733d984e6ed160709b5ddeebd50a927c7c3fe9486fcbdf00139dc6100a10548427f1cbb5a305c9df" },
                { "cak", "6089505718cf32cafe564be0c8829e6900a04ef44dde1290cded32f51800b5873761b91b9203aea646264b4c7fbb18703d6fe1df22ff467259718bd540d6e322" },
                { "cs", "dba60365df685dca9d2d4d93585c2386a0738fdabdfb4035e1fe4f5493e894e6ed17a99ad7a023f4014b4b531bf18bcaf6dc981537a311acb4128f266eddea74" },
                { "cy", "aabe3a549f2132de40724abee7606c016f5acdf498fbfe2324abd796e8d2c6c1c08645194bd42166a83bbfd4b9595805a10997e86a1604aab1d590904b0211f4" },
                { "da", "6560b52cbba6174ad0fdacdd7fa3ed244d6dd9b02cfaa93349355bddd0cb3745c36155ffe194ee4a022e50451f98ca59171eb39733ad7437c7df18c7cc8f9673" },
                { "de", "c196e2843b31c05ff02502adfd752232eab0b9cd4ad06244b7497256b5faaadb05df8f6cc23c15dd2ffd93afe8541fc05711f4d604f70609c4c6987a53919174" },
                { "dsb", "d9c509f9cadeb1ab0f50d108cac976cdede34dd1d8cf9c6c84a6e749dc770167de75e559b307bfd7f6f8aba6f74d08e06bc555a0659d54c18f85ec3181f8fe2d" },
                { "el", "e42b4d507ba5d2c164ee475512a6476f969a2ca20924d4634598627f6028c9f6d2ee715290fe82e4bd7e088b42f63df1a60d6321a2dc49f3b09eaba01307aff0" },
                { "en-CA", "ee9d8c564a13651ac033835f1206c4eaaef5c758d682b30da700d65f6c1b1ad1786ad081c0cdc6e356ee5a56e2b89597e1093f71b80cf292f280383a0db893db" },
                { "en-GB", "79b7a174559a8be7443298a033378c9fab52cc3663526faeb4f03e7de7cbc94d53290ffc71071ffb0a5932ef5009ba55ab71925d01ca6c7024554861da7ba863" },
                { "en-US", "5d6f436f5c20cf1e0c257f8df58d562eda5064e07fe2935487c222ebda31141a247bf6a08f327f2fae23a41141f02dcca12ad3d23d40bfeb3c13d54e3d764f2f" },
                { "eo", "bebfd7de16586c96e07a61a5436bb43c2d0a7bf0949df9257d7e89111539c578e86fcc6c141f5bdc846e94ced4eeb9896bdf9c5c87cb858f0e30e96902e6e732" },
                { "es-AR", "a749c52b4af02e0100708182e904801612a47f814f0e0babfb82be4b46b93d77028d1203a597e9b4ebb7c6ea39c2db91a1cd0b9abe92809faca27a87256594b1" },
                { "es-CL", "38a8f40ffa89958876eb8fb35774d2aa9c71809feb13e21707ade5eea79a0bf7f19f75e2f81be232930c2715834d92d18d6aec6b49a629228f2bfd9d1a96fa0f" },
                { "es-ES", "f73ef55776a61baaf122a1c2261e36d0e40edc9f96ae6b807a1b2b7a8c074d81b91605c26537743c8be78f63944e09b3bfd132b48a75a3d204c371fc5272dc51" },
                { "es-MX", "1e39105ef5bb73339238685ecc44b8ee5d2aace875ec9503d307ee2825b4b7ffe124a3752496987a3739278c53ea4d840d0457e404dffbc962f57e5a2208593a" },
                { "et", "46363b28049e4089cc2746962b0f5bd8e06040015fe4c81db8491ee3b352e1bbc53e4a6dd792e4b7bf195d9496ce03763bd1fc51d22613f4c90dba4e7ba95c71" },
                { "eu", "d2a73bd7f07393319af8d9b923cc692bf65fa6b31ec57e0b83aeee5b21f71e4e3f445d792675068d8c4e5b67d94002744b5113be86d2fffbf7ff0c39748aefc0" },
                { "fa", "6c619743a2445ed3e920b9bda9359a304c96a9f926ab8452829a70127789be5de70aefe2b86e92b630044c7829fd6cc907014265218e9734c78cd4bd4384548c" },
                { "ff", "39429744d57f87acd72d7867e45774524b54c5a17f02013e5f8a00b5b8382e0b162d454c664ef03ef8e6f31222d229fe9c509e2a00e2f397a6ebc538fa98084a" },
                { "fi", "1bfd32968dc5184a85a235e86f14bab09f50a549e17a29fbb4c6ff638c9099ac27b8e2a52bff730c8f4e310eaec006a9184e2c71a877fe8a19bf545625315f7c" },
                { "fr", "236d89de160c0952fe12d1c8f9342ec9fef7f1de8d1ad1f99912da6e75eaee23c34d27d228cf1974924f8501e4d769b5caa9267ef5b4e710c84da586c65c09a6" },
                { "fur", "c04abe657946045fa222879de33eeabb1d49c270c75fcd83b948952dcdc1f384d5b9add6122192a005622d41f49ab94cc8c56a74fe44d68fd90aea9ad6b5364c" },
                { "fy-NL", "6aaf8b9a1801e3e00cfe1c96ca12876c1e1f2302d9b1523cb2b9e487389e1cdeec6552aa4c5f07e6ee674c77e22399a586d25e9f6dd6cbd59a9b7e4b6b7d9cd0" },
                { "ga-IE", "a04e62de97dab3c15dee79544f7d11cec7d2791ed0482c1eb3aca252cd9d1cad61e0cb951bb5b67368e3f72ba23fcc3489b2bb20325edf811820666349d51e4d" },
                { "gd", "6b041595553f1af3a633eae0435811481719f2660c20ef687c0b726321b7dd6bf63c34ee4a47e14a651b65317931420d8e90948641d0ccdbae948fca9fb99528" },
                { "gl", "e4fcbe4e30a5fdf71301eb4e0ff39b54fd06835da97acd5c7a86b42e637b18d48667d6ff7ddd7581644b966b1ccbf81ff99814837a530dc959dc44b0a5ede680" },
                { "gn", "c9bc6c6a7f70b234b27169fcf05d82ca01f7dddd38052ef8690f8ed2e44952632008e06c8f8cb70e7be53b762987a58fb0c104271dbc7a642ef2ace88bb27809" },
                { "gu-IN", "a033f6cc97ef4345db8ddcdc433c7a9685cd7bd3127bc8f496334dd191ead58c529288307fa2b451a23621316053a18514d52f5f9c061c9115b88f2098e0440d" },
                { "he", "c0d28bda72b5fa1badab77b9531c09dbdd381335a149a93256f1f5716ee0849a3df846b1a3adec60b49604af05b3772d688d8c497ad59aebd2a86708dc31634c" },
                { "hi-IN", "866c15be838043f098482fde3424408f51fddbae16dbd5a9db31672b661d261a11bbb265c84dbe49b6ac991d5cde702035a442557fb9c7d027e957076baf7de1" },
                { "hr", "25d7895f9c6600df93f0adae2970abd827d474b6f2c7d05a371121cac27230ad9ef0b09ce6086bdb3d4645c97a9c4d8f540bf034c22aa7086af24cabbfcd9b30" },
                { "hsb", "79a43cbebdbe043a14039432b7b3b0b4a9acf4355d6bb0baa53f66d0b06859d0478aedf81b8dbb753c2f16be54b48ac74558d80241cac783d54c60228749ff9e" },
                { "hu", "093182321771bf7d29bc9e0072b454e5a239f66c4f0902d7657ea7a79dafe0f7ddaf615cc170e37ba5a75abb629787d52d5e527d21ee7232375d612a6588335c" },
                { "hy-AM", "bcd5482f5ac247b361cb3b88a734301ab04a761f22c64de9e18ab7115d43cd65f6a3863d76ce995f3aaffba720fe1392ece0522eef5fabc5fc0eebf61dcff290" },
                { "ia", "fd0c4aed2691262a2d3b720a6b02625a3d75c539153298e01e113ca9f4e72ca591a1394fb7b86555abb7398a1f2f7376477bf52e9b965a05178b92f02e4a3bea" },
                { "id", "c8cce52141625f748a7af7eb94b0ed09f84e2a484e5fb489f6a1b5db3a66315b641c014d8b22e3be76ed4c7705bdbc5ded46dbffd4bfbc4680104fae9376ea9e" },
                { "is", "5d5d116efab048db2d08222a9a504d3cce94e6dc0815a281306723396d6c976ec5713cf8c43c23b0aced89a0bb07258a4c5e101a6f8b0531f001e0a54b3b2ee4" },
                { "it", "7dcea31638db3684d805150cb7188659b5d2c2720b85c4b7961d5c481395d0b701e01d7f7a480d4b901885dda39903bd2db83857756921ac4668d4f8092aba89" },
                { "ja", "5efd0c05712287298148ec5246918bf8cba13eafd1a25f3fad398981e90817b9d5994cefb39276c7e772972f2e0709392caa846eb6a663937f7d4067feeb44e6" },
                { "ka", "05832d0c46572af3e1d3ac3e7fcc20d5306287dd16d7d5c54208354f9a4e08aad924026b7d7512daf5680b8f19e9487981269e0ac54501ab2d430cc930b7009c" },
                { "kab", "7797a9a909988cac512aba2c8c694e0b158ea07b16484acc462a303dfc3eb01e7aac65f10dc550f31e2f3397366aef9839a0fe63976455ce0467b4b5265501e3" },
                { "kk", "730cc35c2d4d8e644fdd5a14b8c93bb802b378f5263f76bb2135f5fff54f3eff4e1d77d35baf8da5df87035b8aa612eb543c7c401fec6d2db403fc50ef66102d" },
                { "km", "8ca1c4b3b39386a37d7dfe39486d3c01d48b9264b4e91cd648f8e56f34e7c8f436715a9353806e455c5c2f879907f4617a5d95f388ad0ff6ce2e6a528629f8cf" },
                { "kn", "57dbed66c7d25527271ab1a4c7383ec70eef6b57d62eb09fbf3931bc01bf5547cca3f4142e910c5cece4c4feb6c8b0e44a734eb8e5f62648f09d56a0f471370e" },
                { "ko", "8ffd5983befdd7e3337ab3cdce562e1d7d7da2ddad07a241024eadc4641361a82b7528c4e56e8cc3ea217897b341b8c2e17d4c881167306f7d95c24e29e7d785" },
                { "lij", "0428e20d925598bb3be73e9e32a9a5a832c3b184e1cf2bf90fd8bc69bff3883afca77d1e778e0288fcaa4864d3d155324f92e65ba25c391944da4ebbe262c249" },
                { "lt", "cfabf534ff733abb025eece7b88e534ac7c6cba763d58074dcf0c9d4f719428d0b04be744e1afa56c18f35c0ec87eba4ace1b21ae30af3dff1399db71145e8c0" },
                { "lv", "0c3ac8a4423fe2dd07b869668f72c45d95a3f7bee280796f5625034b168d68acb6978010a234c9dd83a1f799fccea275e0464dd19f4b9c28a1fa2f09810018b0" },
                { "mk", "bb1076da4091dbc34638e7fe8427c8f2da6a7e63dbe0d787942fa96a95d2d63e51154c56661a56734517cc24b90e9a173ae94660fabc21b00f5bc4b190151f02" },
                { "mr", "85c2952ab711f5dcb53296b1857b4bd2342527178ca6e999f4e6daa9c36f2785ed4705a29def2a03f3f3a8f84aeef41ee6c88c2d894e41526ff467883f856b0f" },
                { "ms", "6d7a6a3f358d64d8b48ba4b3114fa10be7e8457a42a24f47a7d2d2ad6794988736113cdfea1e9c28d363cf3834cafc22409ad18674ad8bc2c0d3ce4f99a22783" },
                { "my", "5fd59ee222ca18bba53d186cf9bca0ab367cbc12b9b18523f839ad5398e1b096f0923aaf44e88a5c16a9c521cfc88c2c129880c28200ce7e651e6b1cee96fc2c" },
                { "nb-NO", "b1bac6f56ff4efad6c725204f206e18ee4481ba1797ba3f12a2161e128783c4961b60d1fe7bf73b14cbdfe4ab018782441f28ac4a517f3a9946561994941a49f" },
                { "ne-NP", "1fd74d9704bb98b90785798a6fd550931505113ce1f06e4a94a7f3241e35712f96b7c173ef8c7ca3c8f459d92f6520e06aec64c1c16cf10dbdcdbefdafd25bea" },
                { "nl", "8241241f876ffc650a2cb59853e5845c07e860905d58aa047238248d8db36cc6aba11089b957b24dd1ff32d99a65b696d3a72690c499f1c7bdd96eeea37170f4" },
                { "nn-NO", "66afbf40f8e22c07c790f22ba24ad06aa87b840c62fbf7068924710323f426be3096e14c06f554127a9aab8677058254a871f5a0e2d2cec556f6ef34a2027896" },
                { "oc", "87bb7e0fe67543938adef5b4d518331b9906c77dc23127c2ccd0a57db2f2226efa1637366a4e98bd670d1ecd31d91d14d584efb9658f7f0b536fda519a2e9c1c" },
                { "pa-IN", "b107c03d2e1a275d1d5e021928db1f8a505158ce3474e677de052df3c08efbca503a919976e5edbfc4bfaba6f269bd81b2802105187c6a9fa59d06df5be7d84b" },
                { "pl", "d2ea76476766b1c67955cbf74fdef585450c5aa3b6239a08f9b86cd596cdd91a8803940aef827a66c23ea66194310f9686a805cd29c1d5ac76a3411025d2a450" },
                { "pt-BR", "769a40f9386268fb61d206e5edd56dcc03cc8eb81d0f0aac1d686a81a71195280d3ffefa39aaf58def4a9e80ebc91e0fbab83418cfb375e452ae3ec08f4f4518" },
                { "pt-PT", "e900d543633ef7d2a73b39c25fd9940ce6b87e6e90e0c19bbd99f1f2b1449abdade4803866e466e5401e169a80e00376b93fb6361903d3c82211f9dc5541f7a9" },
                { "rm", "c1bb6ad5541dab2a59d7386d3c0279c6510ce4d11c3851c842b5780642415d81e7564272f25c61508ac127d1b6fe96b5d67939bebaa3011a31443a321da77fe4" },
                { "ro", "04a73b14693033a6de89e37150ffedf9770d765c70b67afd234d67f2ea9b8f206df5aafa32a5e3317cf5f21553f8c873e4b016d1c308b85001ef055495561555" },
                { "ru", "6728d1873f1dc681c38169fb2c684b3ab1bc11d6fcf79520df65646a90fd0d42f2ba24b329ee4429c33218b87d3d622c4c21f8413d624bc86f6a5c06d311fc56" },
                { "sat", "effe20c508b3806d59b15b4514a3667fe87429a33a32b871efbe58a3b5f043d9b39bca0e552ed9006e05ffeca50dde388d00911f280efc53e58f5821f51cf243" },
                { "sc", "970bd534814bfc31f40f857dee1613e8e5061e3a3e26e42f61e136987be60b2791bde1d6c3b615f1540eb3ff8c185f75decaa5d8e10fc3d495ecb9d0329b065b" },
                { "sco", "bdb61b36aeb28e044e5794ec8f351bb6887ba269450794e7902c43273b8b9f099822a25bdd7c1364484a3187d20af17b350d8c8c286b41b971c183eed915bf4b" },
                { "si", "93aee899441589c8f9e37d75175738c2e6ed4a58dfc0e886f02b892e4fa8a20886919055ba8746328d1ee8837e4cc580f05e1ce5863cdb380761b87dd9cbeb3f" },
                { "sk", "bb9fc29e64d21a94904a24d62eea84ead198f7352e5b021cf1703b9401f5dc7b177e92a36a9d67713e5aef72746bddffb11c8de3a27de8d08863f840e5c1580f" },
                { "skr", "701ec5709e69020644b7267ce976541e23746a37990f653e3d438efbbeeaacc611c351ae9058b42bfd0ec7205f6eaea3eb2a86d14b9b44d3a90c9d24f4f6de8c" },
                { "sl", "3bb33d16a36fe1ce407e699e3b7cb453a7d9c635e86c3d06973f9ad97ac2892368adb36d57a8060f34888ad44f19c7f8838bef8e19fb6dc346e1366aca2f5296" },
                { "son", "482d42a2928acea0e33d809cefd33fa34d2c69eb90ec15696ef707a61aae844c154e587b226d8531bb3f50d9bcdbedb955054bff7ae5c4308c8b64786e671fc3" },
                { "sq", "2cc5b48b36831c0e779b3bb5bb8ff30aca57cfcb9cd3ac4281c919c68ce92194cf991853f8d846adbb9b970e335ae2bc2f36dd655e8d94e606f4d6d31d9676ec" },
                { "sr", "7bfb6caf840f71a70cd04b3d3e91bcfabfce6ea5b37a050bbaa2a6182dd3f219ea97c62c3b8b5b2340765f86730b3425da28b852906e3ad6af33cae0ab594ab7" },
                { "sv-SE", "bdd3c2668c948eadec8ba763a4bae757fc73f88db980926ac2ac4f4cf601077b03566b39e1d0654b45812d245ce2172036a906c09fb6e8b9ca6470adc8909b90" },
                { "szl", "69d79d5d439f696c00e743b80d77397ed6f5f2878ab6a55667d52aea2957b519a91c56050b33bb135b2532aed001379376a039b754c9b02bc4b8639596f9e8f9" },
                { "ta", "cf024d865597bc6e71eed6772798ee098d9bd7d49fc71a7f7260dfd10765bc85e26c0edf8a6cfd8374a0a15f82813080cf32144493fd854d4e3614cd7cc9f16d" },
                { "te", "002e48b651ebd39e29430f7b24c732b5b6b8bd8437bc172d8f7eb118346f932b51e04f20af087733f9043b801e37ca15eacdfad840361e4e984e7f3c6244b52a" },
                { "tg", "7342825cbb37a1d392d71d6d3f7d1e9a65ef86be2d15945716d08b438b8d6f814a607cdaa587aa1d454d0cf01251dd6f037257c470ffb02d212272d759e18f16" },
                { "th", "b189afd06cf4cebc5f2eb64a559c2f3fab923714d5b756a8039a6de1ebf8f93f7cc0c1f89830636605f8dd2da69752cba0f964399b76b577ff70eaac5070a50c" },
                { "tl", "1cd5cda3252a14dbb98c1fbbb9ed1428b53a6e507cdcede551618a23fdefa5c7f0170665ed45eb43c4137c1bf4a5e1246323548e3a87b5321670ab9488a27c6d" },
                { "tr", "dcd4181e0ce04a4b3d5300c4f6395936b1e88b871878e8c643a8e0cc88961c03f6309b2f95649ad32ee33a34e15cda136100c7b4f4a65595e8145084e7087814" },
                { "trs", "bbe315980bae7ee4dfc9dc37619691c526487ad90d2107d7a7ba46d1cb0cf1be7eeb50469174810ca5a73b21034f40f1426c4116c57dafc27557e410fc3a49a8" },
                { "uk", "de4f89cd3f49e3e5d8fb34e31aee98d36eb0c50b83a8b7be75be895439a2583f5371257dba2b23bfb9022e71389b2326bff23632b627993db41053ac194c7d93" },
                { "ur", "14feb6d9e14076fd58d6b4ecb418c3b2c206879aae374f3af6aa16947c06604a15c490b3e0e802353dbe0d52162de9d77b520f30d6ce52387f0cd83ded9e2da1" },
                { "uz", "44e504799b99ff6bc1842b49524b5828480b90044ecb83d85913fe561c8c5c471bb70f4fb4267bc4aff8a4804685598b26c66807530979394436cbf1163f618a" },
                { "vi", "06043806bb1816a4c1824848a06fa53dde29ec6f247701a89872a9ab20f0495cc46f7123b297c9e16cb6bda11ab8e1cc200d406e6c8c5615ea2c6c3ee6c23977" },
                { "xh", "6c3c62844dcbea073589aaa5dcaeb2b8ed4063ed07e7878a64b815da085ee2c7265b79ee589f51d668e61368c08e70e67a7d7b8033f31fe197dbc394eea1efca" },
                { "zh-CN", "f6db6f3e6c5ce89f2f103a67477fc8658a04695fe434993fda30f3ddde27251b6d737949c429981ca60ac52408dc0f7a90552c673be32da01db575cfcaf192d5" },
                { "zh-TW", "ddeb9ec79cf00af8719e8f977bd2e963bb1ac67521a90258d85350f67c98e8a40acf4e02b26cb5baad1c4691bf79c3e1ff10d4d8a66ca480594222582303d021" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6ab9615ed89be3b4b5fb1b4c5ffd0f060e3b292f9f6369a3efda183a1d546fc8ecb21d7d9f43258411534e986c498c777f1d7f07f475a8ae15b924b0316af9fe" },
                { "af", "418875ce9186fdb0946fd9c3f519726f8a2a05e3c2edbffa1d814686c21b1054096e0d7ef437a8af0717e6cce573f8491a87da06c730ff63764ebad469375b04" },
                { "an", "e53e52995d61f9431a23cfb02ff9409dc9468cc1d3087441c3e9cd17678ec6952b6ff9eed16f752341e41e1e05cf50a220f37ecf46295166438c799faeff11a8" },
                { "ar", "082584d75cb14ce8aa5a0e655330a91b11668b0c63bfcaf3852ee2f95b1a7f88c3069035a831873df820b3b48201c9394d65b11492f77978661244b867b064a4" },
                { "ast", "de6069abaf2d4957bda01920daca99b280322de8ca9fc9e0bbe35f570ce8f743e93cb8e2a6f7b7080080461596c26bac86b67571113c437674b61643af273615" },
                { "az", "7d71bb5ea5931a27e6e92463c8ef253cfe643e8f0bacc9cdd5345f577bdcecb5e3da98fa66d444247e2d233a1a7298f2c444a7266fc82091f862da3691312731" },
                { "be", "b02e629a4d06f78103b8654fb7103173fc5acdf7efc43df37d08a4b52d4cb1d2ed2d4cfd5576051503827f429721a653172524d45dee08c4313edefe0db36b25" },
                { "bg", "da53ddf34b484626a7fb6b7584ef0359b058d773b20d4fcdaa342a3d49cfffc6f18995a8148f27ae102ec671e6dd84e418343cba1d345aa7aa30cb65042fc091" },
                { "bn", "63af3bbf16a525b4f406cee24f2d6b98b1309379c2f60bd27bc53cf47ee488d210e7deca52ad887c4e3c2a05b644bcc2d7e22ff3e82b7a3142fe186f486bd122" },
                { "br", "f578562e4cd65906bf7c931a873cc14f7b76f3d80c63df0f376872e183664eed4b4c46171e075c8495f94c77385923fc7bc372275e378c57cea5dfa18076bf9f" },
                { "bs", "26207c25b125078d3dda8b4fd5aa6ee7395c2d71f98aa961c89e9f98c955f1d6cf248957285ae37f3327d98c438d1a2f0e5271bae28f1f02d59fd4d701603e0c" },
                { "ca", "f892f792ce13623e8e2c05e7340e8edf56e891032a3d17d1e9c581d8d44eb8c4e2da6202035438a7217ca4e9b3cccab43e9456c0783158ef58bc91c632dfca8c" },
                { "cak", "127d76969d14abf11ffd694e1c2a5e4be61aed85cf68339cb6931fcd5bfcb7f5fd0f2380c72dd98fedc10912368569b6f5c3b7051e22095beeeb59c13114ddb6" },
                { "cs", "d5498cc8391d57f8e2c6095b7118eb721cbee5ca3f559ea765dca5cfdd63504cde187457ad1544eeee1539e970b53f46ce01b98b10536cf7f61212d818fd4c79" },
                { "cy", "b84b7137e913e886cc74e1bf21122dad453d390b8f59a274d3bed509400613f599b6f29e6ecfaa53b5212e956d03750ae360781bc47c3291a6299bc804c06bb7" },
                { "da", "72a24f4cf31998472c56318ff6e202b369845786de6cc3d22059e4d3cfd4be8691c1518d8eed6dd315f2bc4e982356fa736a8aea57711592d9d82593da155c60" },
                { "de", "6fd5959892c27c8ccfbf50d487320765b609e2aa2d53804a108d0fe0be5d6c64344736a54d4cc146265ec22fbbe5aca4c085abb04a4d278bf7cbb303ae706810" },
                { "dsb", "80cd87bd55ffc2a344aa367b5d230defd432bd279863a696564585d330bbcddf7afa6ddcb27a6bbe55ee3af7fc40472d761184b79ba7a56f4e83a183f0603272" },
                { "el", "432732fa44db1aa482be35e5854b362e89d3818dc91265099360efd5660123fe29d0950a852a56edd860e0e3bcc8412eaf61bc7800d4f4d910edd7a944567221" },
                { "en-CA", "30bbf516f2140ae3ec700ed417bd8253c31a5c195211a11bd6247ceb82503f06868f7335a073a94a64ab452f656a5ac39f7839187e029f94df5269e93f3ac4ea" },
                { "en-GB", "bbf61387cc183b744a7031e0a1378f84b307d49469bb07f5afd18551ea32d92b7f24b779e06ac5e62910d2a3d6aebb4bfa27ab67d127dc5d8d0958f03267f3bf" },
                { "en-US", "4f7693523b81fb4a767f5f65fee34417228d15d507798cd8ea820348ce0d5216979dfb87591a7e3af0273ba59c3c3a159b23d9fc918f8225ca0ac6a758615d38" },
                { "eo", "9d56e55b12fa1f2bb2702de3e6db7a66e8cef3e791372e51c3579621002e885f279d72bb2967aa61d8db5ef03410ac5d5d1cab68bdc4a152e778d547809f2fc2" },
                { "es-AR", "cd2e230077bcce1d6025836d54a0033c784950e8a2a022ceef45a6cd00fa3337c770745ec4dd8e798f0d54005635662ee9ec59c135c6b2c1767f934d102b5b05" },
                { "es-CL", "1dc7c491ca6bb29eba2f7f20906dae74cf7dab3367db641bf8f59a42b6ee0583cb2aaf32ad292cc7b82da46994db9f6d3a87a526a3f3273b9143fa68edf2efc0" },
                { "es-ES", "835cc88f429cb892990c788caece0a58af422211cdc6e61056938f01934d6880a45a8e87f92758c161f0c1ee4d91d1bdbe61fa677b640cade40e8a183b7937d6" },
                { "es-MX", "a94e7065ba331366587d112646af180840155d6638f55e0fe8dcb2cbd0c25a439faa1b7dbbc3d6915f6568985d2330a1c3ef15f476bf2404835433ffc6d5234b" },
                { "et", "16473ea11b7379c6628ae58d196277d4204850884718da101e625f6c80b342d3f00b3018e2d89c2148b4443b8f13c96f8025a7a5c67666af651a3b1623a6b51d" },
                { "eu", "c97de5392394c15e4d14cd998084a7f9534263c5a4943405a4f95747ab57962e41d78c1329f1ff96cea6ae31a672edab06bf75e495e8dc7e0848fffdb37419df" },
                { "fa", "d10aefa3af69554d2889be8d2217ea8c3545abcc628f3fb2b0a2840dd737949945fb5d53cc4c4974bc71caf5fa9cf37eb69e119cb414f78d0e8927913eaf6c9a" },
                { "ff", "945bac05dc1f3d29f8542cfb620f5f0eb69af3b33cd53c98924be7db0bd9ebbccefeab2ecfbc782ff60699765231308db18ff293d2367cd476bea9f08a8176d5" },
                { "fi", "62ea7cfb52dd3e5af07d3cfc26bd9239ed003e58895a759438e35a53a956b5317751a05d2af148a1729e48db6bb0d84a0183424976ab2867bdf7f4bdb13d8ccd" },
                { "fr", "b5b07d2497a9eb35219dcbd37a21baab69365c82e16b87b6d4ef40addc4305acb62a36e82e5b2b705749baa658c22695d6e1f5b3e19d730f1bdd7d3a0fa5c2a3" },
                { "fur", "a00b9edc677d01d978018b0eaf4dabb58a30adc596dc1ac6ffd73379c7d7ba4264af2159d4decce8af220741d168c4a83aaf612c8b9b27c7c806f8cf7465dc4b" },
                { "fy-NL", "e374cb33aa6ee703665ecc742fc6b5ab616042f4fe91ab9a6ccea97be3bbcea922bbc7b3c6e62b4c04a790fed144aadf52f8f92f98b94a4883ac2378b1430b02" },
                { "ga-IE", "ae8924b9512078063355eeb35f6bee7da58f16e69b5d7b312749c4def9be11bf166f612abeccab8c2b885744f57c55a9c35043ecb571d3780794910bf594047b" },
                { "gd", "94d45add37e2a30b0a9643e107317213c746555bc18b01c1250308a9a3c873b5b468609f1544619b5e5bb3be3aa8bc024c962855794cc595d67d857c33c9d978" },
                { "gl", "a0a9eb2da3695872961c826090191d02351b0df34041a9c2bd93e44f7f29f5e9df254bfc159f31ea3e0decb76733d15ff491dbd95a7343a1657ae199eefdff7d" },
                { "gn", "3273606a988bf8b4f9686623cb889f42464f13d71c36967d3b3c0082cbc22d41f194ca3338051481f7eeda521e18e0d3bb58d0b115044742a9f6bca9c7b6a5e7" },
                { "gu-IN", "a544372e949d6798ef83a96b659182ce10e8fe518c53b3a6ae6571e3209cd4ec09c76c50e2b0aa41567aff4b78b1a2c4c32506bb4a277dc0ab517189cc3b72e6" },
                { "he", "6cd120c623d23674f36e858d5777a7fa33f7406774da459e52dc8a326479afabfe4f3fb0c2b623531d060a815f0dc92d62fd1ecc958c2e31132bd7405c6355af" },
                { "hi-IN", "3c2fa6efcbf0c497c2de0a28e00c3bbfabb627299829bc1741e23712a89a9a32f6dc373822e1d1e2e7d23c71ddae0ac31466d0089e56e362bae5d3e638d17807" },
                { "hr", "3af6d18cbdd9e64a013e20dcbbb99a11226ad4d660d5a4d9f1017136af53fd3287fdaebef81febcabd2ca64468e2e1e43a963e9b1a6132830ef533d403b4af71" },
                { "hsb", "902608a9479e643d59775cab469dba5abacf4329b99597055e3c6d7f47caecade9acf94de9d96e315a025c93f95282a71fb864642e657cb6fe9a59dcec7a7912" },
                { "hu", "d296f10f5238897f6ea445b9802c1a86117008d857ffd7ca5fe5ab222d867ac67fd50ecb265623eeae30a8e324c9ede7938cb3b7136d38a4fcbca8613f0fe950" },
                { "hy-AM", "a672d3680b9c3ab20177aa2635874679e0a82511a8a12a43221dfa7a4cb231a0321bb1ae236604d6b35b5bcc71f52f959a53be17cfae0dc9abd3bc73e1488bd8" },
                { "ia", "0dc3a37a75250dc72814066bf37c91d409667651b04e49bcad6c6f80e5eb59b4ad05ae31b2db9f08d3a1fb945087d8256da1163a739e6eac6dbc9533305d1c3b" },
                { "id", "d03bb3b3d07769221f06298d0ef9958baf408e6ff6df592a69d6336302f97c57267b432c3d7b240e117f192457803c5b10cce2f3e41b157a630641b87f1746b0" },
                { "is", "17fef97d18f11789173b6e6d52ae56a8185836bafcb6ed8b6ccd738c7ded2b60e36f0248b201ced9e3a2c0c4a97f395dab5205d9101243035977e7b1f2a08dd1" },
                { "it", "c89225cb982bc52669922c5434376547bdc537b386fc9b472e43dfb0a5eb8d957aa72143bf4f2f27b3cdba564dad9c8780a89c44bc068a4c70979cb2a651c2b8" },
                { "ja", "96c73c7ec421e9256917df3f681bf4c720a95ee9c181163cfba999b7f4607792be84b00b9860274f3ad1b9a9fd5b61cbb39c7825749f978d710dd6d44bb02adf" },
                { "ka", "d11840622eac5d1850a8a14a9079948a027638f53dfe8ff6f9a596d8276c3374798eaee369c348b53caa8b89e003d4dab0ac2056cabf707c8dc458c534fcc549" },
                { "kab", "2c8371bd6dafcbc036377daa48e57a7896a7ded3dd6836038eec9e24be85bd5721596972b7796d79da000936639991c003bc6fb10c958187adc7b2acc2fd0e0c" },
                { "kk", "0efd4f8aa04e5e11c9ba7e82188ae4f25a84da473c171199602008799d70a4ef33315deb0adec5ca2a323bcf2f92492d2093a61bfc17de92eaed2a36b924acc1" },
                { "km", "d712d41e3fb2e6169c280dabdab9adf632439518fe81038c3b512c68fc1196bf6ad1109852134544ab50fd9e1f6f69a89f47687d4018509a2f0aec7f597cb868" },
                { "kn", "dfe98f8eae04b705526f02c2ceb9bebd0b711d553f1a5b1744261b9bcaa79eef8180f3e120785d276681860a125875bd80c9116d5c49ee34d25cc7c3e64f809d" },
                { "ko", "a89f06c698270d53f91f645c2cc9151a0bde1897bec8ce54d26d7a6e4b85bb4243ba87a8c38af5074bb901b0eaaf0a1b4dcea207ea6df0a4733cf27a46fd6134" },
                { "lij", "31faecb5cc88f6f814dc7912726113fd47ab4c842bb3c8fbdbc9baa840a1a31ad4084589dc2cddc8c273b90e8289d3b0b19e3562419987c633196f1ccd375917" },
                { "lt", "f702d86634253176351bcede7df520cfcf2c128c662ecd51a81bf73a0d86a19b10b5f521766250467a5dbb88907bd8981c3c8411f584511ba77d3a42e9149445" },
                { "lv", "6ebf47a3bf33a71d9237807c0d4364bcb553d3fcdee52361cc730ef9bf92327383bc7d196385859fa0c5ce3ec358ce62c6e6a15e42ca92971caaacdcfae554d6" },
                { "mk", "fbb2ace31ee2a5d6a1a4bc12312d08854d3957da6b9b55c1e126755da9499be03c44c98a411ee13d630ac5d455458266401bd01a5d5a81ed29edb3287d0f8de7" },
                { "mr", "eb40e89895647f2180590bfd23fdcc0be1a8a652c183cc9ec9133deb205336b9501bcc51ba38cc35b038137520a3700d77115f26b10dfb3a701e88cf9f471a2a" },
                { "ms", "8e1389ec2cf642b0a41575cff69eb7c3857d1025a20da79eab13a813c3dd633413295922e013c56e9fd31c1c6d7918700cee4eca753175c4e58d777d1dd34f51" },
                { "my", "255764a3cd1dc717e897447418b184e6759947fb087e3a2e5f6a611343e7ee7111ef0b893b2e8df5f3c736113f3d3d6231c0b9a8b58fbd60909173ff71a495b0" },
                { "nb-NO", "7368c1c73c9fc339c6790186bfd494d08983629f42bec4907085b70119cacf097d4adc5cbca8d04e294ff77dd132d8f00ec2f76d9b4c974eb72e71a423185b52" },
                { "ne-NP", "7a316042fe1e9eaaa620955ac307bab4da84ea8464670339acf09ae3127bdc14e7ce217bab23d8c339377624953cd0cc9e22cc79dd0e4b8679cfef4fc416925d" },
                { "nl", "1dc161b3803a8b16e1c394ed06172783a1a277d458b0b38c80f71d3138c86a8348e9c89ecd6c48b257a9233c6a4b7695ca94122cc363cfd2ae0a70fc308d8196" },
                { "nn-NO", "b743c5ec073f71b584c1eaa5302f56215dcf2050d9cae34211da6d57d4630c6266c9375b8e71af7d761d97ff54d799a0c16854f3d3911cb424d036e1bd2b2e98" },
                { "oc", "791259a23c79236239eb9136e9fe5ecfaf9afc8e13ff8b9949cd0a8ad28db55da81e0f11581a61aa00bf74efe764839f3fa4d9af3354feaeac6e878d4f93e76c" },
                { "pa-IN", "bbd42ed90d217c80a68728dda34f997f11a8ac2c90ffc8447a133bd7e8118684cc4c21e04a3940e2068abade046af5bc0aa171e3866b8aff0362c71f28eb2a02" },
                { "pl", "54fed7c895ece655488b7c85c9207c5ea4a84f6e7eb36416ce901122c4bbb808c1df71075865b4631278794604cf0fb55b9815a58c8c8696ac8a9d3107b7974d" },
                { "pt-BR", "d881c58e82756a7ca6a07ad19d14c08bd8f22c4615747906fcbaa6652a4cb770c9c27289fb6cb26545f5892f84b2ecc66daa3b999bf891f6ae870d326c12dc7d" },
                { "pt-PT", "da23ea1e363705c5bcb689be79ade1f3b83bbdbdd9717b6532da9954873a8eca26b59cf4ce2cc9c4af719bbe22c1a596461ce952cf541560a2ad6917b76083b7" },
                { "rm", "a10b5ce0b022360ad2e04b91a1970649884ba887509ab9fa0468c1baeac9d064e508b6f5ca9231eae3b3418a97124971ad4273258061e978e1011a08fa7d1de3" },
                { "ro", "3500524b8075f794b56c11876bcfabfaeb4f975ee65248b94519b089002da94bf72f4422585002e812fdc1bcbc0f580ed6f6556adb417fa4df7d9e49ea460386" },
                { "ru", "496cb1268274977daadf5d215f765ade06c7a844e5c1382678bd1769e60e3722b0315b4df617651c7f209f301edf9fd91d2cd3739c32b1e899308d723880e806" },
                { "sat", "08d739870be322022d115d03675548f9b1d37e39c992cb01560da34777142da0a66e0cf7d8f301d2f4a498add91fee0c755a2857afb7590c7d295d620af8b51d" },
                { "sc", "bfa86060b40ce2836038b80e0e6fd3be535b0bbc28217d8063103ded3b35c2364da023f213704fe424992fcb1909297ef06a48ef9e354b9ce7d9faf803598dd7" },
                { "sco", "aba7d9111645e04e952da6dc953e1ada0939c4fdb28ba990a39eb5facb920c887bf580fe8f70c94718278549d3eb511d0d8c0bd6eb3c9f6fd105c811e948105a" },
                { "si", "90d3279cba8d8c948ff02343245d2c24d5033e31649655622705b00f02a5bc451ff5b7102278cce37050ea9d5b83386a6b4cfcb6a8af079eee1f088508d1a17a" },
                { "sk", "140467e4949b3eec5242b442a2ae14a776ec10d92feb875e568203988675e1aecfe2e38146a2bccaf2aaab6c38ff568f9481cc40e6338110a7364bee7d1005db" },
                { "skr", "6b99a6f4b559cff1511d7d2ce25ef8025723fa3832cc538d2ed650bd5fa94322263b37b4b7f58a01efc7cafe91bcc414c0b2b53db2ae6dc9b571df02706953da" },
                { "sl", "a625999fe617e4db5d8a9eac3a91867692e3c009b9a3b49df5b6d193760386c2bfb9e43eeb0ea2dfd8da620104b454ae8451a1d452388c034b1ec0e281fec7b6" },
                { "son", "c5528f1efb03a7a43f4ac8cb710959648b06ca6954e76333abc16e4fb2e1c96fd0183ec85fbda98d9120b4a49b290bff87e5cf72f59b3b02d7e89e238b590695" },
                { "sq", "bf11f524a652eb2063dac87d5165eba2dfdfafa77b594c5537c9459a8553eaa6b253b6fd6ec7b62ff043e5468ad038d28674263811a873c7fb844de10959db93" },
                { "sr", "0df6b84ffa4bc3273762ace6ed0bf8999dd9eb6dbdd34f0101ab035e1124b039ea5959cc6b6ca4f0fe65b747724187abc75448bce7478df2219ed95c5abbb662" },
                { "sv-SE", "6f846fd1cfed172354d6fc74d8af2993e9bac949bb16bd99f8a2971742e91dc046b096989df0863d37b35cb5bcac2a71c0d5aa13978218c35fc97f039c1c24cf" },
                { "szl", "b5dc2c4e6f4bb9968e3feddd4eac84980752d12e63da8d6d15fef6fdd6fd90a1cae5fd23ee90171ea5cfd160bd5c1149ae41eafe4888d0aed997a21c36ecb56c" },
                { "ta", "5fcfb03f2ef5e88061310af2391d2423f84cd5ef60d8839f715c66c90e48d33002ea8ce512d929871e43849e2a5ca4bc2ddd05d47f5fb5bcd240a5337476f3ce" },
                { "te", "b7b8299e8f2e01bdad0a9dddaf96757f86e5b4c75906e18ba14091a161610adb2653c80deec0da3a948e8f19318fceff0f188ee303bcd1dc45596de624fed492" },
                { "tg", "a73e9d3066a067be1998b5974fdd9fa236a6a16786c5d2f0673d76f03c92c1356aeb10d53ef13ce009910b9e8504b57683f3ff526569f8587f89020ab91ded0d" },
                { "th", "2f7d0c1640f5b21f66fff5b9104b84195e62e135493614960288d10a26e577d8b9cabbe225899b79c2594f362360e7c50007aceb1be7a01a608228f125d69e58" },
                { "tl", "a1c78725e790a80baab447b598b1e1b2cad05b9768b7fd12adb3b06456da820dcf037ed1f00d76752b397507d0896f5cb416ec2e6b44e4b4d5ed8f9c5dacc36a" },
                { "tr", "a641de7d5c0741eb65c11e479fa122785b8d06a0a55ced28b00644d40c73b6675f534120212a6baa0112e432c88b654b50530515f3a9e8bb60a767892ebf00cd" },
                { "trs", "59fc405de8c5ea7656c237d85442d9afb909fdda30365782a7ee7983fc393aa6fff0073b3200589836d028b41290f3eed80610a39d18ee2db48dfb4f90bcffea" },
                { "uk", "243dac9824dc9d87414b38531459b7a67bed0e7c3b6e5bdf194d16ad87611dc9c7eb5f76414f286621113dd833497361317ec404e0909aedf8439df4dfee50ed" },
                { "ur", "4d089c2d4e26f01c4b96e3d91867fcbdb975b273d065a40f8e3916e913cd057a06346f34ca91fb809c26b337607604adc431957d840244aca1b0c3ef42b3187f" },
                { "uz", "c41bc61d07382e557e6921c8f7d1153350f97c78909732294c44a5970e34505f5adeb7a16e1be09630efefa069066b6c7d642a08723d90f2a1dd91c85e3277f0" },
                { "vi", "0d5cab71a03d5dc2e6c9d759b0cded598d219786bb5d30fbba9173591eae3c26175ff3266c29bdc63afdb22ed5d201bd5e3e572dbd185e13dcdd745287f4eeb4" },
                { "xh", "8a390fbb37d21397d58f889d03d0a5203217674a15411a04ff8cdbc24134a091fe964ecae50046a65249736070bc50f685803ab6fe581f8d2434319d4eb7b803" },
                { "zh-CN", "15ec6395f2396265d4b2897d43f318061d1ccf7c8751fc2ed36aee3b97b834b4cf0f37b23aa69afa284c01715b18cac81c30597a9ea885e4aaa7b02e27aaac0b" },
                { "zh-TW", "04164ffebda7d0c1ec4b82499cab88d7f2431bb4aabb02754a0f0c3cf57aaed2afc299923211e4214d0d26f61813328d102ff7701d9dfc889b8ec59119e53034" }
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
