/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/149.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d2a74e0be7b3efeedb17a10e74482cef6067f621a39e1dab2a37bae982eadd1ffc97c870ef8ab6d918c83c1528933c242b3ee85c4fba2a8afbc6436b21b480cd" },
                { "af", "2a2405c4a1fc0af0ff3084f18e626ab455aeee3bd8e93a1d212323a6419358b8014af75fd99b5958f3847ec22252884d5548386de4bf15bf5a9e5d4d404631e8" },
                { "an", "f25c02eb590fd84d9f48aad23259452f9fd859027839a39fbec3ab93db334eb4709c74fa9ac17f388617072741ab064ccefcb1e77bc3b1b991c1c604d5a81605" },
                { "ar", "aeb9ba3cfd77bda20bd9d36a9d00420d4a3753d2dbf57908e1d162fc81145f6f8498002dcb2e38bdb68fb5dc2bf660ab85d6247439c77af6cb2118529985882d" },
                { "ast", "0980590213c622bfe4073e6a411d16b3b15114a76d2b7664ce69f4dd567cb41b8931a432eff9f8f324d728e0887b40f85b4bf4fc9bae736072fc991f68fd5632" },
                { "az", "14b8bd487c04ca3e24d9f79710f15684f3dd63e0d348a4075a48b5b8650f0910f81009861fcb0f22e074573befb6ff7a7288230334bb2ebd6e14428802faa57f" },
                { "be", "1bde38b3fae830ce0d1b869e2512348aadaba9e7af2f0c4c9425e9cc85f223c49d051522c6c3250b13f04972bc6066c6e9be3398c89741284d5e435d682f1a00" },
                { "bg", "ae9a2ff338acec42b3bd822118004ab232eb11bc39bd246ccae87cd990d70ddda1e25747241f6b5d2c0979c8dbe85dfb429f206fa833dc53aee5c2908288c6f7" },
                { "bn", "76216948564d778130a45782b333202a8a92241d30b3f107e192e0eed12b9ce4ca67406ecc0efad945af0694fc1748179edc9c045ab678b23da4391f379d5add" },
                { "br", "53d891bb16401d94402cd51ab2d0a7aa37e42e47be169c7c9a8f9b7c8276a2b6ad5e3e0596ab67278a15400369c620691dee8baf809a8f9c0e0fe474bb4343a8" },
                { "bs", "1b007ac9ec9d72e0821d51d4cc595589f6f62f325e624279839c3531840be0b96e1b5b15a744e2ffc4ef3a4010e676547f88de9bf905c72a67e810e4d10617e4" },
                { "ca", "28740ca4092a162e91c703070e96f09e8aede402e55792d7d5e419a6a2b4e7846ec1ba83ee67e115e97d64058f35a489c95e4bafc4f7db3668bfa5010abd5b56" },
                { "cak", "61d12ceb8ded4b52f62f1b03f626663a15ba1e7d7ecc3cf94ec1360c704104880e21a6ec20e81f74ca0cd21c6bf093f80480741e5b8a0e164076f0d3c4daee2b" },
                { "cs", "ab8ead1148b9b24c56dfb791b10c32a978af127b9c47ce81fbb5de0c46cec52a2cdb097b145d4c14367ad4914982c542633e605d6fd8d908fdfaca2ce8e9a9b5" },
                { "cy", "6687633502af9aa3c7720c02843ffd9de3b86f2715ee001d50269fe195b65b8ad6d33c80f5ffc5b06ad4b57c7c90f6b2cbfb166fdd09e7325354d2a8854acacc" },
                { "da", "d9f7ccf5d40c659a4d42b0a89aeffb4082844d2551f480dd26cd854b48c51bc09b79968eaff7f49cc53fe8aef06cf0eecd2f333a27f0962132324e170aff3693" },
                { "de", "8ccace2eda7392a1ecc66b83656f8df94b725ac1d5ddcc9e025af5f8867cc0534f1ad5bd53c7870a31b525f2c92900bd3c8fe35c46de7779dad1c334c6849a50" },
                { "dsb", "df52bb53f36645a66790a3194d36b16ed40f5b6386690ee2db12834bf6120183f0e49e5c22f35abe7d2b83ddf376efb3475a034b6448ffb18207747ed48d028d" },
                { "el", "1346c45b2e009ce54b75c54a5025b7d8044f773b2e8fc99c83d53893908c9d7416a4e04292e06493c568c9f839d3e2d3e30411076ec2e05bb2a57c7e7af9f0ae" },
                { "en-CA", "43f0e099f2ff74c2cb85690340bda5cae74fccaa9934aed9aa6ebe667a85e5dd8eb600cee2161d23b21449678fd154cae1996ebebd8aab6ca651ba94d8bf80d7" },
                { "en-GB", "39b027175caed8170c9feeab99963cb064c3717fa1c3f4337bab437d2eeb1aecdf83e0560a8912bff999d85e4895ea64cebf0b7392db60a777c79b3a15a0b4aa" },
                { "en-US", "3534cd016cbe0932844c9d80c20fc9521027fcf740d9631c7555a1762bf7360c407dba58c9df5d22a100db9ff0c8a86817c7fea42cb2ca779bb59d543f116675" },
                { "eo", "d1de4ddfb2c7644fc0494d4f2a6a03be16dd5bb2b8b4ec04e3e286a4e1e74704efdff6a163ffda6f607be75c29db5e5cc187b6d5ab7ce54b1f1c605860674625" },
                { "es-AR", "3165bca1f4ed2d1b3eeb1c434564272667dd971770bb1298a7716d89cc8a5f433e11eeaa97eef3555a749efc331cd1df9f3a7b17687ad2d410035ad128cd07ca" },
                { "es-CL", "5016330f796365defba886fa08af3cdadd9d376c9e35f7d5beb95e73c6601ed6472228149c4e525d3d899aaaae2bb84111d642ce79e20bc1936faf09ad605de5" },
                { "es-ES", "195110a026b9ec8e45ddbd492c5171cd37244b4125afa700dac0b958df43f48eed5762b1677d8f1ddc0b42685953de5e723001f09a34ee4ec35f57f91f93af3b" },
                { "es-MX", "46f40599030277a234d57cad63b84d67b52fd0ecf1db4c21f0511a9dc6386d513ea1f19d1dc76ba6cbed7755fc4a5af922312b23db98f95406be48edeff25305" },
                { "et", "2b9d083b568285b89b39aef8abb507a1af8a90af31ca9cd5ba10424122db1067f2bec9995473521f02ceec966a4a76072c3107f0ae5d98b3dc2b5378749d029a" },
                { "eu", "48ebfc6b20014686517b0b9870d7f9c359c272b8f23ea91f2d1c015d676d85c9e9fc55fc5e750560797b99866dc644daf59073d0e675b0d736f9a52dabdba45b" },
                { "fa", "150186adb74a423aa2ef2029dd35aad20d181c0c91d396e9a2cc83e236d3ac31f47737d97f4b375893b4039a9f6a5860a8f73957e081cf5dbd931c5930c2cc98" },
                { "ff", "14a55ba6067ea9dcecbfe53c80b54e19079e0b94afad94eb62bd760652c0bec853dbb7dd47558763b5f95a0b8a13f2a3a6104ac929863c51e917ba49a41ee2d4" },
                { "fi", "9b5d7025bcf51361be6ea233f9169d6d714124ca3c7a8f79860b29f0fc777c971822c89ff4c6d5940fcdf39278ce730aab619109a6bc32a65f0eed798e094b04" },
                { "fr", "437bc3b022ac52c8c88de394eaa933b70c6b144cfdb2859bda3eaa528c9fc6f2eb809bb302929723577eb51839fd2cc274901dee5e159a4232b65e91cd57d69a" },
                { "fur", "9ab7f8d0c842b5aef7387f5616f4e0991820277db1f0cdba9edb4a32d77eae4493f6d75b28379b57faffd24c1f263feacbfc3c73fdc3dc7c54b24fd9bf1683aa" },
                { "fy-NL", "0d55c54c66ce6c200879e2f87941d532b9fe85c51e07f98648518f2e8fdf28d4da58f22ee957e3fcf445ae2f196111c205ff7743d7dd4238fa30085f35b467c3" },
                { "ga-IE", "0cabae4b87d5a51ba5d67b3e344f5ca25ca8067032fa41ae37c8996055de3efd3fa9257831c0d8737dfea0c99d6967a706fcfb022c284d5e3d761e181b800820" },
                { "gd", "de0135c3fa4cd6ff73aed965f5e986f0ee8e6b9bd0640c7a6f2792db744a15446d8b1fa30cfc39aa9d20116f2881fb3713ff1be8010e737013de58167bc2d8db" },
                { "gl", "f658fcbc8a71e1fd552222874f232acda737273c7c6a3daea4e376e5a3fcfe9404b53782cef5ef5ec36f3bf2e87a08d8cf1c9000983e0389a0e9b7e573b1d161" },
                { "gn", "bcfc5e4be17cb39e76e54b706346691025e5e84d38060ecaaee69cbd8e5b5193e06354235a58dc6d7b486670516dd965340434ed7d5cb857fd8e4f9519013ed5" },
                { "gu-IN", "31e1af8083452212f2967709e5cb53955b5f753143756608f7b72eadcb84f84553252a32eb0774d6a100b0fd7f4342ffd2b79f9cadabb929aa4d128b0da2581a" },
                { "he", "a125ea899eb8e02b93986891fc685dc0ccfce63e80cabde18668752906db7c87b295e0429ba1029bf2040c819c0f8f4b8caae835bea3a0532ea71c82008e53bc" },
                { "hi-IN", "915903a162b1ec1ec137090ef60e983d42d0cb467ff620876ef194b0944f908187e3a7039005c359dc88069b35d8fce57f1e56a6ca7c3c515c0d22049820638e" },
                { "hr", "5d4bb612c632facb594dce01b1fe16a57bb25af89ee0d2c83090e7140a4fdd6a12c24ad22dfc58340742679400218631efe5d5c121a1c8b0f2ca3582e5af2e20" },
                { "hsb", "e8223607ddbe416778fa7f8c56d806dfa865d3bc6395bb3b8c5a3cff46fb212e4d7231dd12ccebfccaf6fc3dd5f0484ee79c90343974b3d938f11daef10ba8e6" },
                { "hu", "c13a7248ab7052f2f0b576dfab6f3e70b5a1036a2df1f2c4a6c218f0504031f6777aef49a432e1e75c197bd1ad9d305d727e1be123d2619ec9cca6d5850bbf3a" },
                { "hy-AM", "30d27fece5d54485132b22fa32d6e2ffcc5014d3f7e8fc9d57eef40f6f3b1e0feec19e8e34a8f650825323d2e27040b1f8d622f55492dd59fee1ac0e2f8ac373" },
                { "ia", "e9e0ade56abe4bcc4e348e967b3d483dbd913f930b2e59cdeab602c6d241a9455910414ff28d8929a31b06d228fa765541a424595e5eccb5f5db3ec93429aa9b" },
                { "id", "5dd0deae06afea2393f705707e507626abc9027f5f9edf194a7c3c9ec326bc25a73c3fabfd965a8fc84473391e7bf389446e309f8cd2ad2a01bbe834329a4a92" },
                { "is", "e042f31334363164bf5036c8295289eaebe95161e6bed18fe00decc841d6287451f4eed1344947717e55db266712da649b9d8aaacb0fcd166dba3e981b3f73a4" },
                { "it", "84a5ded6eb233bb5fb58d0554f74b725972bdbd06d0ce3d8487aec7e63f52c7ac5cbd9947d7c3b5186988edb25006aac8d6a146a5f3fbbe920b5ea697df695dd" },
                { "ja", "9f7849c55358e26f3b267111964b1f659b5f79e6eca66e740e9da48b96575b95b7ee7e4d88587b6081a1d3ca0d51a779f4f866e8e03d242965e3981da5944c7d" },
                { "ka", "9bbd9bf94cac8e6f65bb1ec4bfafb5b9f26dc0aec99f29162b3300b49aaf5b87b6602e88d759942ac38553f1c9ff753528002d940060dd52a4a852d8a3d79e15" },
                { "kab", "8b30c67fc1e5337c9923b9edbb07a5e8e0985b8caca212ff9169321efa2a3697390e8ba54dfde4770a957f2a1f2d368ae853fdd159573cf0c12355d0b2cd6b9e" },
                { "kk", "61d243d0d33c22e107e99937cebe4d6a3d54985a67c4b22364f773bcdf240a58f61077da02f23ed2d53c6423ec66dd1bd9b3cc84e28338ed0f19d710d697ceb9" },
                { "km", "1d7866eaa556b56647ea15bbb7c2a9af9f0432412f3d4ff1ac091033aeaa3076416824727668e47a3719f0f6aaef1624561fbad99775cd3d5cbb505d08353240" },
                { "kn", "86a2e0854c6f015057f31dcb25adaa9e05e35fba4c0881dc4d4b2288d15813b61e521604b7855001dbfd85be851ce1f6f94e32d53bc5b3f730a61df9cc04cafe" },
                { "ko", "5fd704a63e7875b372f822f21c5736729222d17e557a442ed6fcf2cf741938d2f2a0c2122a8eb69d75562bc0ba4921521b1a7b4b8f68772f65bb5e32bc26dcbc" },
                { "lij", "f614af565ba9d6917fd2f0ec35a361ed43662507dd6532c9974c65ac39102e004183c0ea0b4f21b29807a841025de3664622037a4e59fe13492db158736ac6b4" },
                { "lt", "cf9ae314b4db9c9010ed4fdb56f970a5bb02c45261f273c612bdadf808684e2fc41d81d2c843ca28273d4bc843b864a07a8cbc186ad7704f1f17e220ad495317" },
                { "lv", "2de07bffe506283511ea4b16452f4c378722c71908c3dcc83a8c32441a7132aad9bdfc83fbe70078c17f241ed7ea856e542f2e60ad1a9c0a8c8514710e4e7a4b" },
                { "mk", "312dc1dbeda1da7fbce859fcffe2ffbca29e4ed2a74c9c3e59cd25e07237022dec8efcda2f64ac4d831e3645ae98d8a68fe494a3c323db022442a3f353238dfb" },
                { "mr", "ea3715c1b33a63724d5d612dc7ed97a201700fd15eea9bc152680eec9ed3236b91258d6e2037e4da37517da844c299ad63e61b674faa71ed224daa8909578694" },
                { "ms", "7c1669847d1aecd86333ed05ffe1e21c5d49bec1924d8bd289f4687eed0ca41642c42578d1e93cb4ac733ab873628c3b654265c65b8b556d88b5f3af2f9ec747" },
                { "my", "919e10791cf12a04d7ee0cefe45e1d106c5cbf5a893b274482456e69bc40d829ae749e3b3631e1e468bd3ebc581b240c0ad5e3d2bd76d5323eb0a63db318913e" },
                { "nb-NO", "6f4e259515a5f416ae25a30a888a681da70a28fd04ab69e2c62159cc8d5c5beb36f217ef663c1d5f640f0d108ae4d0999b48d60adf3210910a1921c55f290328" },
                { "ne-NP", "00bff983569f7771c20d9deed59de13d90058929957a1b68edacd2803944786eaa47bdb18d249fc79335f3686d039cc0f351b79f1ec6dfaca0aa943d4688bafd" },
                { "nl", "594d4ffb0e8fa59ef8705bc8c32c6e228e2fe2058e77ff4853a6c944e509684688f5e8cf16f76bcdcf60c620fa1922756160d4e96569c20574c73da8b719a0f4" },
                { "nn-NO", "40b24cf8b92735049218af7f907315365db293bbc181c5e75b2309c72f64c7bea8cfac22a6e29693cc6b6b3c21c4bbfebf5e9339e74d4fa25f9c66ccb41a3c83" },
                { "oc", "7a9c28ef827453d1dff3aa8422ecf8d20cc3674af6392635dfb99a73d8f183632c588d2da26796bac52ed3138cdc0e03a003fc4806ac0b1662fa42d2e1402d76" },
                { "pa-IN", "14b245239f4b19f806244c54badab2a3976a38a6cdda0fd11b25f671d6c2f8a9ab055d954b6d14be339e9d7e1b15098954484f4160966d893eab0a865c53db30" },
                { "pl", "06c73dbe3ccafcf2fe39cfb9b8cb3f730a49a4e4a921b2c8f6f00594aaf17cdd30b78a8c6ffcd3547450696f0f6bb98f08a5af8f619969418165ffdd504fa8f7" },
                { "pt-BR", "cfd57f790b5b6d9d467a61d61e370cdbbae18716dc8dc5752490801cd79c6c3fc1873e704db43de78f1eca8a17b256a428344a24bd2a4e7afd9f49e9a538736b" },
                { "pt-PT", "acc83e94a1a63dc0207c181e7b944edbf0d9e7ab21bf4629f0ece96028d6dd7d9469cbf55e6e078fcb904cf4c1c108ac99d501b24c57d8d2ef2269f71d5642eb" },
                { "rm", "7962d38d291801abaec6ab6e740503e155ff1d9f8de9c5d7f753f38d9dddbaf9ec3dab7556a08f4f359ba185e9914606bf674f26ff986404211227ada86fa426" },
                { "ro", "eec9e8d4a27539be8c1b166daa7ae47c4038867ac2acee3e8ebe262e5ae5a65dde493c3e1171645fa2f96634184e2e79d2323ce44cf93222abd7163ec83d270b" },
                { "ru", "7d40d3d52f5144bbf29418ad05a80d8abfd5d2c3ce483e09bde46ca6010a2ad39c60718742e3d4009403bb0259994d0825b016637d25fe22903a31842930d25c" },
                { "sat", "4ef0d7fd94da840400763b3858fc6a27c250b71a32067307db3462aba342cf5c4ebe049e76fb8e5f2fec35fd60fe3f5182424edaf3f1770fd9354c1e4b5a7bf6" },
                { "sc", "e87197b904c0bb48179adbf24ae54a05c3bfebcbe9fffc42cff2cf12a73ad3dbdfcef3a9d9fc3d9abed6ba895cd1d589bac235b66478925bc2053dfd8dd78774" },
                { "sco", "0c86a57c19b6b39f852f7a46fceae51b81efaa8f1ac66399a8448739f2c6237c1dcb3521ca609d976d45c3ea3a676bf2ee3ec84133faf6da015421a99dd09502" },
                { "si", "99cb89ad84836b2c7b3519f215f94b0ceb2ac091263e5be352a07d0fbd21be797de33f073e24030856b91774d09d185bcfa6f58eab1df6f97ff5d332dee2fad6" },
                { "sk", "28da469544a23d74b1fd47e4629676ea0ed5cf7eacff55a8de95268df2d568e2a4c0665cbe71dc8665d96db660e26a02699c52bbd0c30e4ddd3bfc83acacd209" },
                { "skr", "3f46af3d18ff9bd70bcc80f91128431a6ae11ac30e804d94110c6dd275f548ec1a7e4bf57fadeb833d0618e7585abb669ba62682e5d8032ecafac6f30079945b" },
                { "sl", "6924d1b846f425dbfb7959b34270c1f7645420c8e34bd88161ef9629b7a53db93a20befd902604ccfc79ac75b30a2a30dac738d7d9c488c133255d9ddf15732e" },
                { "son", "e7325c784cdbd41cd0dbc2c7909bcdcbd7a30ec4a48b8646e4b59d05234dacff248797ff4a5c435ba41b765433f42b74c443280ae6067c41ed345b0420f81c88" },
                { "sq", "8ae71e3a18060dc435e60d5b920f0f36271eb9345c124c790e723017c468123d003a63955b0b28aa1840c907c730584a3f5bb06bba7e19bd50941ee50526a740" },
                { "sr", "87eda59662e00910c20bad31f5084a8966222af61bbd21aacda33e2f057be38b33b7df72ccd373371178e74f01739574d945b1c4ea56dc341767cd37ad7d4465" },
                { "sv-SE", "53c77e22e148fbe6777e61bec006b4d33b8660b6dd9d9d23db6879a2141ed1ae3f0676ec7366065da38a91ebe4c317faa17dfe96c4b20f0fb4e6892dbeb43f59" },
                { "szl", "1c12db85bff4f05b5c4aab7b9646b67e82c898f74b05b4890d36e51862d673517416acdafc7e9d077ab8cbe40c77c8d2fff19e64d7d30b028e837e1a72d7599a" },
                { "ta", "6cd9370861a4154ec5b7e5f6544b26d9604edb0912778fda0b4ad28b2a95b3442dc768b7e851c4337730dc619eda0bc5674ddff40011b962a3334855f852d6b4" },
                { "te", "4b3df17f06109504eded1b5f94292b027dc6ffc6d9c89cc8a075144dd7512de016269cd93c3bab42c777bcdf5933f7fac9499ea6f0c68e71f562e3436ea80db9" },
                { "tg", "05afe0aff3930b4bc04672f01ceab3611467a28004905210e12b405ebdd32707d0fbf45f90b627b652c2948e84b3fdb7b5dc64f1605e50778fe6a15fdd988a23" },
                { "th", "527163785bdb3d66a3dfa59b2989d45b139914af94e8294916ab21b0c790393e618e10540fa09609b239a56d91629e74650d54603888326338f71bad19044a26" },
                { "tl", "3e101ab562ffa1f06c7ed2f10cd34819590e4a8c2e94c1789c9e67ce5f01261847b801b0b7891cdb65fc143c45b886467a64f6ed0bccebe00148f3f583b1408c" },
                { "tr", "b9242a39ac231ed41bfb44ff36652da4c94ea8f2e32d12c8d593f14d5400cc1b2f0cc272c193fdcad0cb374ffebc01691a4f0af13e5f819c36c9bbbfbbceb373" },
                { "trs", "6eaa9cc58f6d5e8f25b798a75921d96fad1f2179e5f6052993a8b615e13bc493f1dba739dc535743180721eebb9b817a8ac336a92a0daec93adb6b6fcdec8e03" },
                { "uk", "41d11c76e45d598d25370f184237efcd59f8d987f4ec1acbdd32f2519d373604e14ec65bf5fe00899a0f1b41d96fcbec632c02114637a0c5af530a3de8a9c5e8" },
                { "ur", "da079efa21458d527f5bb877b2b4fdda12e56ca35d0ea8ad0b67be7e90a7a99de7379afbaae2ce6797457fba449a99799a34b3a234097b7d583a8d66170b5ea0" },
                { "uz", "90ebe46c365800c2e59053b137718042ebe3ef1dfe3ef7fe605c1eed9a126821174786454a86979b22115d63b8cc2fb8afa5ed07c35e8958bbfdfa3a828f1bf7" },
                { "vi", "df17be8bc51e367f5cac5072820ed992f205c1a457b96bdc40fe99d72e649f6c41854679a8fbf10772ac0398c39a40afab1d4b37b511f47f6b1d212e6991598b" },
                { "xh", "e06ac984145b2348529b6b90ab8d6dc3f74a94936160e1ee04aa0f7e23f1ebb7c4bfba74e9556f25842337625b80225cc1b4e10d084117f691f54817688e3cc9" },
                { "zh-CN", "0d0efcde7221664e14306e2b5d74bc403d282181edc8594b2a48eb4f22730133d38216c57871286a8ffe75ed422b2b69064db2550623d5dadf1854d698ae2dff" },
                { "zh-TW", "638d15a23e8ddacf73e6b3b0cc64e44ae3186e43c8f25f6a954dbc0823f2f60ce72138668f49f0fc6f00049d6cd6847928809e2ec3b045b704ac31129928d7b1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/149.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "73d3dd7559ba27745377b4f5e2b4ac914424f59f6865856d031747860d0d14ea17a858bb5ec896b4a0ffd5ec923c7606e51ec01cb6b91a6e0d26fdbabcc693fb" },
                { "af", "222144a9930623fc57dd5d1e6dce8b4ae563b761d09bdade68beb04af2843fb6c097901a043e272c0e65a17aadbdfe1087a734457809ca0966612cf34bce807f" },
                { "an", "784d49abfe96d4c03e5f0c08c9b1f8845519244c9612f2d0ee5f2b567ed9a3729d60a2e2600c19cfb96f4b3e7d2be8e8ec56725e86510277d617ea1688c68fa1" },
                { "ar", "afe2287a0a769235ac558b8f011f304827b4c164bd5298fbcbb0b1856a8654a23be95107c02fde1bbef6e1a6f7106183ac24d348ae8617498e7613a21670a3d1" },
                { "ast", "71f9a82231dbc68c76719c9f08d4ef8b8d8bc7b4a93748f0026d1658d7792585339fe79ca91f9ea43dcf0c45a9a07a57dbeb0a7f33340713eddc4b89d725214b" },
                { "az", "1d79a22f3042052e394b6ee2fc8d328e8fc8ca125726dc3865e55caa9c5b563eb6f5b3e7edc0311e0131d5093b6cc569b26b5d168d5ee78f8b3b32df115c804a" },
                { "be", "cae142335bb1b5fb551eb0220801594b60febde5cce47caa3c7b281712ee018ef0abeacd94f3c3cd6149bcd02f5420976837dea41c1dcd256135afd21cc49b3b" },
                { "bg", "66195cf435d57947d808e02ebdf651248cd80ef61dce02e1be4228e1bd3622e180b48d3dd4158b95c0909f2b6b89e4fb35d66d4dfa3ce6476588663ea75f8bc5" },
                { "bn", "e6f4c2687e431e56608746c6456be6d015ccb13362e7ab913934d961c96bbb1ef5c8394daf95fd0712a92030ae393ed1a9207de8fe6ffee9b08464eb01296d79" },
                { "br", "239102a49a7aae4048ae49e80957a8a4ebbd88db29038e417ee650e352d4ec055d3172b1e9c987630ea86cadf65225b2fb7496c5d2b837688ba8fc4d589f6573" },
                { "bs", "eb5e68fcd07a396f0e52146f7cc658f2a61ac7cadec6aeb5d928acf3ec7dcfbef56c2f8d1aa3eb94f7e8854db7c47cd0cbb1f37ea7137036b86bae9feec028f6" },
                { "ca", "695f1a5e297359bc54cf81be187dfd5272ade784bd1353a75b1df916195c51fa8ed598db416c4cb28b076c79eb54c3833b6dda409616e26a54c5fe69b8a8a59e" },
                { "cak", "1d165bb377f924e85048d2e41c7ffe46f51b6b1edcdca15faadfb9e7c98424842470a0f74b8a09ee53499d4028346f329a233f1ee4dcb1759c0e69318660c278" },
                { "cs", "2d55611a83d05bf2d575ce74c72aacf2a0661164965befef308d24b9e96b2560a02f525e159c132e99519b9311238bd9dd3d2b741ac5f48dba252eda596c5270" },
                { "cy", "8265dac12739b9fbe9e9c1d67de74105ca79ae1ef551853048dc330ad8bd9a9ba0b19a48cbf75fe708c0326a04c4a85a4ad9f7ac104706f889f7227ec668f342" },
                { "da", "9f95cfccd190b143c996e790515a3264cea9cacbd53295dc1d2d756478439163086b537d990b1ec02a5d087b14297988d26debd1e22eb3c6ed8a0c92d4aab32a" },
                { "de", "5e97bd06c912f79cb3c527c212ba9b2311ab9bb2aaa13bb0bc85f251ec5b115fe7e6ba4e18e1f0b2f03bc181a433d1fc59c0487aae77f3d681348bbef2a5f483" },
                { "dsb", "67c157d3a8bbf70a76a94fd8bfb8854eb0330e37bae65abec4061d7e2a697f01d63956d35c2f07ef49a25daa043bd80d63f31a2e3b25a27c20799210c0e14a6e" },
                { "el", "98da63003ee02700a0724c3d12a8cff0678014c4664d2411d4862a7ff3e2fa634fc3e395eeec9b6dda7cff8f7fe977cba268e094c5a6519a4d8062772e06689c" },
                { "en-CA", "79f815bf6d47618c2134a236083a7f985f62e301626dc40754b3f9bc725f37d41951c3e47561f47c73f9df27864f6097384e80b00386baf810a124c48929027c" },
                { "en-GB", "23330014c764b89bbff79348ac091b74b1f066c88c421e1771d9388bba4ef0db7b6fc199038e96b73ae943c0739b6e173e9f6b927659d1d7645b5c3b07c5e6c9" },
                { "en-US", "9376e9f74677cca8ca7ebee521fd4b43de4091ea72c92bbe95212df0c8581c4e003dffe72279fb46f5149b0a71dc7c7e20befb09616d54feeda63108fc26925d" },
                { "eo", "c0d4e0248e0a0376e0f7ccefcb6907aae42ec578a64e72648b4c2ed6c1ef6b5946e2869565440c95f62548fd98f7c283d56fda89b32919a2756091c96dae90f2" },
                { "es-AR", "9a853a5dda36893965e2365ed6c39bab6e6eb9614c36dbc140c673eb31145c05b448926b98a8ec654347de3f3d7b70dc9ff3a967f58b9650c5ead1f9182358d8" },
                { "es-CL", "948511bd9d95d0d2e2304a56544a2481e8faee8f451a742bc80270923f97c9587b38c593c6ff730093a9ae1fbd9678eebb5ea58d502cc9f53a7687b7e730217e" },
                { "es-ES", "7d1b257acadca2bab02b4947f5ee5554836bb28861c1400341b1d358c6f32bec2d3088d15c0b107aaae1f6546de427e5b2b5d12ef38d9eae178c12dccd27e70d" },
                { "es-MX", "416a1693dfe2aa91216e324fb6a03d80b05458805656aa1b8164082cfb3bea8025602815f6b36713ca21b572279d2d8db7b4e64b8c191ce7bf1243367d5fdcaf" },
                { "et", "9a02042e559a026a338f6f408f27cbc0f90ef66da974091ec22540f5a536d2e66b84a429c19c28e5d20a0be098ca1760823451de7aa2e976b9c79830510d5434" },
                { "eu", "f3085ee975e21d514146547feb857fa9d15c427286bf4d24d70abb9b7abe0dbd80c83252d2aed69f5641698462789fb8d3057637868ef9204179ec997dffc637" },
                { "fa", "3b871957659d359de08b92fc813f6818492b3ac8dc37cf901228bcf6ea729652c93d21e3b1a90f8b0808f882ba452b6b2656f8c3e48f9f9f338aa242f7136bc5" },
                { "ff", "15b0367cd1ada016f6cbdc7041639cb3d83f40eee3a5cf104c7bd8cef1e6413f4d527ae9287097ce4badb71127c74f12fbc9ffc466b9c722c5b2a813274f1e88" },
                { "fi", "38ccb91f037778ed4f1f2efd2b81a114b178ab0f01abb1bc48cc770c46cfa44eb126e36df4afb507ccc649b92059029ae1462098b34b2e7035af8fe99b10c4ce" },
                { "fr", "40585d6d851d7a2b1740c0a0d28f1dcb69d2593829a1b6afae5419375b8588d336b7376c302f8dddea85e502d7b287a8f1ee51bd96963c7174fdf2d8fa91f722" },
                { "fur", "309834b16aefcd8f5ddae97e070629cb2a851c950d81996d5132f54d1e66d1766a01bc03dcfb3e2e06701016c91e186043dddaf90644338268d6ea259ef8e11e" },
                { "fy-NL", "3e9d1730cb1c2b68cfbf9b9a6c3b5ad925e90540985d34b2eaf895fc5e04300cca5d18454671211d7f3462cd777cee39a5882cefd29afdf71d7075a8a563c9a2" },
                { "ga-IE", "11e919e2b765609458ddd70048f32214aa1785043b5e84bad79624c323c6032baf917264ee2a1d4a8882f3e69d298c36cb6374d51b945ba12815c5c7af1bfb18" },
                { "gd", "003c9c601be6baa2576bc1587612884f1a67e449ffd9c701926f39f36c39d733cd4a38630a4caa63fdc43303237349b50b3252633dc4659170a4566b8b849267" },
                { "gl", "43050126720e8490319013d6953bb8b34a8f7afb4334c6a57397cd05e46ccdf06674672459adf6d823aa9a3232dfe2fc707b656a234b803415025495f7843541" },
                { "gn", "aeba1f083d16609f9d258503ebc6095349fd6a22d580357288e3e6436729500053d86bc0179148d7704c5b9dfda678787652ba1e8f0fd8b5f7a966505f3c0fae" },
                { "gu-IN", "ab1c61b7198ca43cbf745f261395cd431c13b5ab42a778734a6f133a536771c51f0f2ebd165f4ba0a79a739476f2ac45f51d78efe6eba470b493bc32d4ca6def" },
                { "he", "0c77f764b3fcd07f4d9db7cea4c8628dc1bdc2c241ac9e2e84e05939ab40f3f1bb603bd693f1b78b5d234f2b3f11979b3fd2930affb5a72704253c4e5dc09b68" },
                { "hi-IN", "8f8445c471e8023cd65d2ec965ac7a87dd57691491279bf9790fad18beb0483226e9f27690ce53656d2f6635d146030159214a222466b6e2786db26ff4de7c79" },
                { "hr", "f983c32ea29126f7c295672377a96bb884a722c7749cb06e43186a39837b23bd1e3d38b60b1f6166513b87481ca0e215d9bba1ec86f4256f904f954d9135cdf5" },
                { "hsb", "671ea7ed4ed9ced2c234fd64b1730324396c18af3811595d7f0a5b880fe5d2d7c2e6a304e2f12b3bd528cc8db3cdf1af25643b13f518efd414d2f42ee26f2b1d" },
                { "hu", "413e69f476f7deb96c80d268a05f2240d847139e48068dae7e64b7d8178818ae0df772d19515c061ddf011c668fac14e4d7792d438606503e25e9c218ffa957e" },
                { "hy-AM", "6246dc7b0f4acdb680a7e78f77ae6b1693a464408d63d327fccef745c7cd9f1cb997ed571076f8f2654bfc496c87fe96acd4a6c077184444eb536aa52c616303" },
                { "ia", "016d5eb83e0715a0c9de1834ba63a4155f2fd555ae7011081b4deb532cee78f646ff4799e01d9bb6ccabb6ce6f98a44cd729133017b60a9cfdc0d90537798ca0" },
                { "id", "42456385f31f4ef9725db8f0e74f028d644d93b8409a6e99dfc120866bd8c2ddc1bba2254000f67e699f6fd0979df5e550eba3056465358b6ffbb1e58181fab3" },
                { "is", "56f856d8183cc9c944a98f81973b8b9862a4d8f84c457a9f25b78bc14570166279e60b8122a50df4b09d8568984c4b9576460c031ea582495cfbcf58fea624f1" },
                { "it", "19ae07386ae5fc7829ae28e498ba4729f0c95b3a340bca6ce23771ae0a333af239fee0966b614ad9a6414e8e877fd7cccfc9b48f9e13b18550795c8f369d790c" },
                { "ja", "eabc3779ab4f889d87180f58abfe9537267f16ef6cec8b81315de3ace54e99342b4e47611c77b5b0da768460cd1949aa3eb43eb0e2bbfd0f7bf6e971b44bfe9d" },
                { "ka", "bcdcadd28619eaf523e59b89a0f369cffab3d34e28a8692c8488a9754e6330567b72e47c6d0771b15e3575f304f2144f36f24078cbe9fffdb463ae2614a592eb" },
                { "kab", "33b9b91cc9eee8cc04e062c920aebedc11156cd04e67e0164f035b20f760eb85fd82fbf743b63e6f4bb867d666f307f0f6ed8f1364b35b1d48ccfcaf656f1a59" },
                { "kk", "ce3d4ec35d30ded5450783b6f12c24947463d354ccbb48c1d8f93b74e0797766fbcedb93ff127057d8428c96a669f436fb5b8da3e09ca972c1ff38cb7ff8f2d5" },
                { "km", "4280f8af94bb0799f91bf19c81dca293ca4b8a0a92920df3e1c8992405ea736a51a6d1f45dc36752d0a58dec0ea31eebc9d651589285a553c5da493d82d31619" },
                { "kn", "f76853f6bfcd7bb0afae3378772b05c263e33cf77c6f32f31f4962cb219071e374c77188ed9879ee16a7fb672e27a8add211080ae203934bb6347d7ffe6a7d66" },
                { "ko", "970eff0631d9c7155c8af27d2b189ad07edd23c58e3bb31038adb6a44ada0ca4b8b7c554b2e13584b79046fe9a0d0dd594dd2db49906a33e449edec45e529415" },
                { "lij", "2ec7ca489d10a0b719940d048cab0d9abc880eaf1e4484b0134aab3d992d9a87ce8ca1f6939b9a5a022d091620dc47244a1de58baeed9eb90b31a5161dded061" },
                { "lt", "98119cacde585bafc021b35de16056be25c702d5f7a5f6d0012132507342c9233af6a40dea48cd151e001c47025c295c9b8d1272d79b3807a4de564d6704ab16" },
                { "lv", "2814b3d764a003104f8562e42f27f266c8696b1fc8700108cb9eb53193627c76b3d22c5020e611b5cb90992a6bf0e6c27ab8248945428be5508af16103b34fb2" },
                { "mk", "4370e018cee32a21ce15224b30a45fd544f41c0c02f41ef9f042cfc8d1eebd3c9f70a3b8d0ed4e34aff3f839d8cbb9ae3a9f1b6cb8a73cf9c1034b2f5964259c" },
                { "mr", "0bfdd08ba0e27609c7bd666f13799083ea7993dff59e466c31abff6e2149e88f76511928dd88d61a4c5434e614a5ab12152f992a49f731a94cd444e3631fcbb8" },
                { "ms", "07b450ac1e44abfd7327df3d18876f10e863677a6ff8bd996db118d4225ad1b44e7acbe7f085a69ee6b20aff158d279f736df711740799f7de32c0eba39ea9e1" },
                { "my", "7928b4ac629054ba1805b7198831f057e1fc0e3de06ea3e9f6b681d88fe13f1f261511f4058812c04586e34ec503fe99954a00ecd3fa8f4b1a96abcb68cf0dab" },
                { "nb-NO", "4e735991b03a4f4a8945d65b5990ffd0190e071ce2396c1c0fff0fb079268e6fde566e3d9edfa7b0606740f58db35440c5deac0f2af37e0a5e135ce63189fb9d" },
                { "ne-NP", "c764a12dce80038a85ee131784ce240ee1cdd76daedcb43dbc592bb75de87e36da9b6fc165f1765c77fdaaaba08f63ed1035e22b12fd589817079bd886b57498" },
                { "nl", "50d42db06e4bb8d4599422820eb1d6e8096907225fe94ed5327ed70659ec9cd8d4aab59fc9df48add818a5d9b0c4ae8995f66806e33f6a0d8027017709e159c0" },
                { "nn-NO", "df48f94a7668d4b09c97ecf771fc702ac9dd039527cc6446de7a3354775b8b7138ef9320ee434f73a7ddaf76f1dd59e661a3e52cfc748125ed543714e3126318" },
                { "oc", "9b6207c82c5316120b4149c11323444c34433ec0a96616b622a163ab43b3a4411e9b28975964c140fd786c03f9b7dcbfb608d4bc59e74593000ed5a43684de59" },
                { "pa-IN", "3a615fcffe3f23c39ba8497166d4c706c7bc66c93c975d6ea1e30a8f36ed189885a344d3f7326915dde3843687033c0e56e1e5523413a07f687f36a7c382540a" },
                { "pl", "49ed0ea01e2d0d21a753d3efe59105fc876ab22459c1727a7844dc5d14e9eb1926f2f9e23a8654302af5217cdfe0c772c2220d36c9942c7d853d0def48beb4e2" },
                { "pt-BR", "db80aae6ed5275122fd1e438c657c1d4c2db9b7f8ae304e813218701445b3d9a3baed9c20d799239360cb4b3e9253cfc610ee5867ab41103b4f86a41b43a8fdb" },
                { "pt-PT", "1f8005da6eb163f129ae722a41a8327f15bf1e25e6b03ea48c5688fc744226da1fd19e51eb62f64e11a0631607374d6de0944bd022ae6954b61ea11b7714bb58" },
                { "rm", "0f0c2534815b781ee6c0117c27f923100389c0e9cde1901fa39690f2caf35a996c6d660d881f59ce182680960a09d7fb0e1de7c8af6651329662a1f47323aab9" },
                { "ro", "7f7daad7127d86cb566a6e9615108522b83f8bb2cf253b5f4129c71531b32971baa89399d2bb088a05b4abac2fe4430838ba03c2f7ff2c8def61da515e8453fe" },
                { "ru", "04d94e377749c98e6c747f0ff28ab646660dd8e860fbd73d037e2dd4033da0bb653bb1fa9014a3ddb500b0022d04f15c32a0b1cd3071ab62811413921db31029" },
                { "sat", "e74a35d66404960154a7c90154c744dc3b0db4996a718f14016773b3b4783c202c1c948ad992aa7ce062f061b8f32a0450368c50f71a9687d4bdf732c690c243" },
                { "sc", "31234cf2312fcc6b091cf8361e45444219997b4b0830cdb71f9876bac951737a75d4a727d166e6aa67bd71e886b5e0c49590a3f43608dcb6a4abfe9e45b5ba30" },
                { "sco", "497069368dcb56fb20070968d589ed05df5ef793cd96b89601eaf02af856332d2afbd421acc818786f9a14a8c507256dca3897185b53ed32b7888f50749d0ce0" },
                { "si", "597110035456827819f3a59f9034674422160b967eb6582539cd6b10b5468587bf710a9f78ce61a96e6a1311037487992af45db60b58bbb5e71aefba703183f5" },
                { "sk", "7187ea33a74d11d9e442589b528d39dcac377f30a30f86a7b901ef2b3cb1a0fe1e03da956462eb0db6c06671aea50de0447dd637bbb2a07f19efac672ced95c6" },
                { "skr", "596e63208695b58744caed94fe6e666e59524005395b10b2cc58d0eb012f31f638a6f10b2b8f17eb367a7eb1dcc21a079adec0702e36c3d72fc68053dd3350e4" },
                { "sl", "e2d2c2211b378a0c49cd00ffe7a4711f308dcfe022b9dcba33543dcdf480d15d40d56baf869ecb053a367f3b8db4b457fa85725a086a0eb27d36c27e60c66d08" },
                { "son", "97885f5dad19709ca5b17ee3c5b38f1d65300b2d44361e9ee8ca0ef3adc49f9fb229c8460191bbfb04b3d40e6780362b22f04798842c5e8151aacc6c7fdad231" },
                { "sq", "9b3f6da4ba41f5d3e9e071a2e8cb7583af327a02a1cce3c1cda6239589eeb17fb1d8fd86fe38f3ebadda5897730db32a2c35b95f27b2c416d1fac74814816982" },
                { "sr", "8c7e8d85621e46bfac264c6802c82ded2c2aa2907b7bd2800c5c58037e8f08cf1ddf6f1b22d84477bf64e6645558852493b78c7f97e22c744643ca4a0afcdb6b" },
                { "sv-SE", "4971dfaa627c46103f6c89f3b32022bfe9c9552a6d41678184af2c343f13b6dc51649f2f3238105f1e1f1272d8b51de66160d13861cda4dcdeeefb2713a37944" },
                { "szl", "9256f39448da81998c775486fb5df349af969fce4690fc94152baf488d312a8c624e2ec5db318c7010bf332e27eb6f8e3d51e4e577dc0f64eb69087bcc218188" },
                { "ta", "c63078d2dd63564d0644fb7574e76ed9e592a535c5eec1f604c46f0bfa2de551182acc1834f6e80ed53b96400cadbd2c3f7a0c78f9409809031318e13d910887" },
                { "te", "2e46126fcf615c85c1451ac0a958d5bfc725df3c4d988c98b9657a110521e37110a000047c377a195df051c623455a935ee63987f700cce59be3c74d4491640c" },
                { "tg", "d9c606b1af36d8e26f87d5a9791ce35a7204f38022f341a39bd5c757db763fd26521c7224401d611d98f38c64ace4cfde1dc009e56d4004bd61d10d1927b3405" },
                { "th", "77d8d46f9fc5c740fcb533563a7e087b0f49957afbf035aa9ced8ff92585f117d3a8c9c738eb7d8fc898758c07ebb7a648bf5bf8ca55b8cd86da3716d956da3a" },
                { "tl", "df79ff09024c90bc005d50c4a52538a3cd5a8883ce4ec5a3ed8e7171cf8d7b4750705540d6c4cfcfca53b53bc7e6b5880de30676fe3c45be0830363505ef965c" },
                { "tr", "353b15f504fa2b854d4120796d3bdad36e8107eb5a825e035b67fedb495a3951cfeb1846d1b82759010b14fea683ffd975ad42dd88f8f8529b2d17209033070f" },
                { "trs", "323836fb7ef422d3fd75d3ff68afc4815abee0e75441c77a49d1c471ea4a617001d7d9846e1c646e8fa0b5844de0562f1ad30936e730e18e23731da61f23d888" },
                { "uk", "79f6b2a3937acd6e7471cfee6321897b1561895b9b9b315e9690aaaa6545efd288040ae005180784ad007be83e8b5701073a0a5372222464dfa386d129ac6afe" },
                { "ur", "d4a76bf938776b930caf221f744f3e983cdcce3862dae639ec1bad3a40936dd3ecce3b4b1744fa5aab3ab38f5b433ebbd5a59b3ed443c5afc98254422c5233fe" },
                { "uz", "96fbf02f22ce0de01ac4ca9dc191004e82da39bd4a6583f8791a41e9326f3a52a974365a2cf2c108b00827e0c2b6af5b97c5255221be63cb2d7c86445351b875" },
                { "vi", "718a5b630d68bab7d047c9e75acb852d355d888c10af1f7acaabd638f44ca354efb09244688106fba34b435db1b245d258b298d5c5d99dc6b71dc2e595f60fdb" },
                { "xh", "dbfbc672e3bf9ae5fc0b0be42bd6758587f022905f8b26108d26f722a194df677c248090d0a7e1fba502ead4477f699329090185d02aaa111c57c9aeb2622aa7" },
                { "zh-CN", "b81d1d23deaab931b7372b9d2b101ce879aac836cc783eb197da44e604f4fb2aa7bd0d640694e3286c76b641dff875f1fec91188586d0d2c12829a37544f59c5" },
                { "zh-TW", "cee8f29e0f8fea7db78bd431f8a302e7a92aa46355d8a9ce494447b1a0866142e8db67221f3faf180079ff24082311b652ce723336d2407607c97b786912c175" }
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
            const string knownVersion = "149.0";
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
