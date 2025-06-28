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
            // https://ftp.mozilla.org/pub/firefox/releases/140.0.2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7d67acb419d7ae8516193889a73c92c79734b628ac482e51439079538cf31b49f1edb7d9c2d3cd2f4d59c7bab90f0fcbd06b967a49a4e5eae2fa4b10ee937ba4" },
                { "af", "919016690faaa5f8715ab21ba31c2da8c01f9b175040353800b1ec453242b65ea6888f3392248957e0e0cf7e0af2de3e9c9139ac9dfc520745e8a43a5a250abd" },
                { "an", "d3f2e0f66704cc9fccf64c7e79885fffb41418f8b240f0f347df1e4fc08572b997ab9c1033da11bd34b1853c1726d252b2ec307bc0e92e75b49ba0028447d8df" },
                { "ar", "231cdf32e531463330801be7c33cb56623e2b531144868acc2f01de0effeecd664dad6651a1b770204dacc054da1ef93ab17067cb2d790d595d155f5af2423c1" },
                { "ast", "c15796aeffc2c3f66459e66b285e02099fd3211bc7dd81e3ead03ce03c1bcf39a588e759514de7b15b44e761244089ce35a5a71abdf0c66fc9358300c0d17c93" },
                { "az", "23d470fc288ea7d31ba4822e0c50bc76cdef53d181588562b800cf428dea28298e14a1cbb30892e7d94a003c52bcca2e4d51538b81bd9d067abd703f73cfa418" },
                { "be", "a2bc12b87d9f3f33c2a5c337162d178628103d4f254560e8492821f2d766780f2fab6d39f2110b420bbc07263dcc26c0d482863306c6fc75cc227ffed463634a" },
                { "bg", "57563a87c195d0a9ec631eede2e3870c867ae1dc7363b2a8948be533cd78aac3ab796f0ca6c752f96e402dc1aae7150fc29269b14556cd45502e5dc8f3244bb6" },
                { "bn", "c0135fd76d431ac894c71e5f1fc7b49d115fa422f656cf82e0b8783aae0d0a104c99035de9d26d9564e27da01af4adec012db95a7ae62cea520d550333fb4b60" },
                { "br", "33ac42c9a685e8329a6b35e6e3ce2f3418ae7602969aed7983f391c43598ff448f2e7cdc566f3aaf16d7dfff323280c159e85f7802330ad74ac75fccadb22bc2" },
                { "bs", "a8b17979221956f1c3248b2c2c5542bd80e0c3bed05bda0b392c57bd6afe1b551521ad5487cec4f151bc8b5daa090e1259cf9f6828d2e60b53d927d744b1febe" },
                { "ca", "d5aab7f72be6f20ad83cc407a955b005398a55385105267e3a243fec4478545f75fd11efc601ad8beb39a486c19fb0a5268b2a997b60d5f4d6685bc0d1cb1f58" },
                { "cak", "499c2ffa44d8f3db6e0546d4c13f39395d61c506f9dad669c40539476c38e690d117cd34d9b16aa066f44085674ef8e365d8f96f1e3744e1086b3925b74888eb" },
                { "cs", "c7740e275210e7e67c329ac51e2b1302d93300c52288f03e0b285c6b9d18904ca44d1acdfc28e170149fc9f87ea8b9e5e000644dae2551c045609154dab3bc65" },
                { "cy", "2b64126b17d9f535fe32242c13a9d854d38a56f444b78c08049cab95325acd8abbfd243a15e22d06e262aa93c9f3198cb009dc687b82fb4b94a7c26422ba78e1" },
                { "da", "85a5179b63dfaae14ad42e9a367ce998825c2d6e349b9e6209abc37878054cff9656ba41b8d6cd4b4a32bf9de9e2ed0491f09cfacde04e118194c37402b4a995" },
                { "de", "f36e092973768ae92193373948bf86b4d039948e80aad324783a57da5eff8bddb13f89591495d5b52834861a8655b02dbf1a9d942d47bc7a84bae3c25876f71a" },
                { "dsb", "805638ffa8fd57d928eb86bced5c38a313d4e4fff230b304ddec7cbd86e72e81da7f879fb2879aa877afad591831da7aaedbbd9666c60022dce0d7f1080d2df4" },
                { "el", "de88eb739febb003386377570975b06ff28e9e376bbd56515dec471eadaefe57b38db140a72ba4e06e2a6d6876cb718b5ae53f603c5288b94e2652ab6519c30f" },
                { "en-CA", "b5381decd3e16a7c99d5af6cf55c5fde5049182e158885b64cc282d425370eae34bc7a585af19b383a8d73e6f5039a0fad3c01b990e827242a5f71b3d3f966fa" },
                { "en-GB", "025e63ae1d984dbfc158153ee880e29438d68c496c436a7f24c44d82bd2adeedd2f2cf7b5c051477f9bcd62f7e644f1dea738f511bfa5d9383e31cc4f9cca1b5" },
                { "en-US", "88692ed1e78951efd87e7f931e61ab4b847cb1cc324b59c17c05925c620c79fbdd827b50cb072046da3e21621e908daa4306d97e4fc7c954b32d01177ee16524" },
                { "eo", "8aa62d5f150bfc1e4d12ffb0d7594549d6ec1ccb348c7dd4fd6cec53dada3397f92440b422954037164a64009231750f7b469a189e937cf2349dd10ec547ac84" },
                { "es-AR", "b28dcb342d06dcf30fc856ec6123529422ee353576498cd2ed931dd2d584475ae990da3c98c89af2b6ff1dc8d07d7bfdf63065dc68eb00f7b232f3f065702f0f" },
                { "es-CL", "62e1fee186724d52ee2ac68d645f35aa84e4b0856f27ab8e7a07a9560ee05f98d4c178ca2c9dad665898444d9800802d002ba9eb3e52551702b1c636274c159d" },
                { "es-ES", "ce272dd789ffc3645cdc4cfd776a2408ec72232dc679b5e1fdbefef06d17ee832c5ecde67ded275897be35e472302901f1a1425fd9f64661267d83a49426e9a1" },
                { "es-MX", "d1d6cafcd739c0c62af9fd080e4db50ad8e38faf50666e1fee9534cf96678ab77e40926063ba4dfbb09d4ce76d5c5854583aef14f070536f3805737fdd202599" },
                { "et", "6948956a55185d7cd03add013850be64c05eddd9ba798035303ccf287c5fb8b1fdc5376613eca1cca2980285e7f3f7144b55cb0fadbceeff6c56b03e8e815fb3" },
                { "eu", "559155b92594c3f46bb10639b6fb2ac8cd17c4da5d3bb7b8688b9d4d4aa62df1ba0967efc4c87ae471d0059efb5f528913466c80ec4b9c4be1c025434b611eb1" },
                { "fa", "530f9181d5ac088c1e79a0adbe8715b5323e0dba4cbdbb55f98f8e1e5f30007188f48e3ed8920c3e4ba8b461857bfcc49109eecb695fc5898ff62df1edf80e7a" },
                { "ff", "f9115dab65b4427746c400a743306d7c42786ae767737fde599fc1c97ce16403744f8aa9ddd5e40c4836fe482ac68a5dd8b905ab323e118eb7243df9dc0be232" },
                { "fi", "f068f64eb6d4f44143af64c11f7f386cfdcba945289461a172b4e81429e2431412564dea40b19279ac76d45a37b77ded7a06f32ffb2c6d056c4a03b094fcd2e2" },
                { "fr", "8cbad3768b19d1f6e5756c0db3637c91d397918765c2aa265deb68acb1cb6771280a23ad3388c732b36ef5fe1381d41ec123078026f634b87d43bcf52af09b2c" },
                { "fur", "bbcb0807bb50f2900175f27088af0cf5a46853e33cdf59561f8c1d2050ccc69b6e8946d0cc85e9a85522f0689e1fbd179d8bab588c08af95c8a32fc3eb80c013" },
                { "fy-NL", "0f7bfd54da7c4b9230c67d543ac701c1f234a286e05670c4d074924551201870b897ce35d9bbe0e966bfa5cc9b5dc63da76685225df28bb10037fa0bd6bce599" },
                { "ga-IE", "0e75cfca71c12147cd76e65756e8b7ced07ed43ba417cd596f6d2b0ec10fb9bd3cc37e9bf6864df55549bf88c5644d3bfa17d1d3209d39115d1f01bdabe62140" },
                { "gd", "863c832bdf909f9d6274fa48a3ef7c8bb601f5deb110c628337b22b09d1dff648d40454583cf1098a1f4200e4cb830b2f87cf2bfd849f459517239528f5adb49" },
                { "gl", "d6b062020addb86f7b8c301dd57f5c092f0c07d6a9593eb640001908124a6e04cd59a6a8ba1a38370f24df426cb59d7843918c15d1dbc43107f71b1490e84b08" },
                { "gn", "64b19d55cd6f2cb82b4b5705b9b7fede3bfc1b4b3e4655704d9d0f33d3f0c5a552faaca3d0e308ac8d66889bdae41eb13b6fccd682a926f36ab9f4d2eb562df8" },
                { "gu-IN", "0e376881883e4e037a631ad2b23a15dd18110100222c0eef9e54df069c6997652640d41f7b6366c8b2c33ab2f64f1414c693179b9ebfeb83da5f9d7df9cefcb4" },
                { "he", "ae0cdaa41a7abe7649fa321909dbc0b851751c360b104c8fefd0f621638099ca0572935685541db05c1908b6b48b895e9ff1011c4c305214f70d7526c66c440d" },
                { "hi-IN", "27bb77c752b15e6bc224e4cf6797e7ef061a157e81c82a013e30037c85597374eb8cf97419b468d397395aa5fa547522e089e0d1e1e9ae5a037da69137506a59" },
                { "hr", "d6d3185e445a97a358d04154d58e1e9f5c05ff5b6d97a89bf9b80e85ddac69b88d2589f224593b72e18360ca16092be51492268a76c36d05409ace4422e1c1ad" },
                { "hsb", "872dd2282b2725ac479050c8ac6bfe37fce44447884622155657dc7468797ce700bf0d6baacfe39058d7a989211a5d12dca90be80fe3456b418d35137a6a8662" },
                { "hu", "0e269207b7337373fd327169b68b2c769d7ef41c69d4fb4a5100ddfdc0aaca6c2af44d13059cce142afdd5459b11054e282280765ffb9f5d724279c8b698a0f3" },
                { "hy-AM", "7c3b24a4fedd1e68abafb16e713992d89bd4f84d6737ac827b6bb01be006a7153dac6344e044e32ea0fe68f45c886037eb70a2ffe9c30ee027da9e83bbb44803" },
                { "ia", "351ca40257f44a3dde1a0e83536cd6c0ccb971fa63a52949fc15e45559a848334daed48c882d1111c1c0397cbe0327759a5c882c88039ec2f0e68a6eed371f17" },
                { "id", "57621f8c6df753bd8c251b117186bf456be8aa6c2252334cb9a7981dad1479216c12205d092b895c2dd1a63e2dd7d21b992791735c68f551b2ce082f0046237c" },
                { "is", "2527cc8ea2464d18a4275f2ac23f01ce9279de4089586eb74d64649a88d85718a46fa10c39306d1fd3f25464dca6e8a97dce9d559fa9cda18417467d0e608510" },
                { "it", "4d8d8df999023e2fd555f5ea5b5a9dfd0faa284f960f02f2f42b821287f4f62eb165c7c140a8f2aad183abf3090707932cdb79260c95186f2db9b4c5d9ce90ab" },
                { "ja", "93965c7d8037b7e46ecf68459f4c877f5d954b2a03fe6bee4989de128fcf1712c1ac1e0b59096d80653dcc360ba27912cca5ef5c5dc28d3e034db6d24c426641" },
                { "ka", "319589a563f55773987e62e0618e6abf121893a0a7eb1370ccdbbc0a75c826f47ddd1e354c99b23848e490f7f811957696308b2e5eea6ba6c4596176e9796a30" },
                { "kab", "726f5beec655261df3a827d509ae1c8d99c702e298c4b3bc29404240b70fad2fac0e64d7da0f0978e00d1c2f4e0460160b2389bb862803f15124a9da5c99d0b8" },
                { "kk", "afc7166ff13bd4c064ae131f8a6e3fd5ba66c6ef3b8825995ed6c793abde7f0d9ada3ff13a0d90de0063cdb1f7702cb14ac5f542bd0c262c049a33a694115c35" },
                { "km", "cfb0ad88d0bcfbee18041d2ce95272c7ff7e6c3251f6222fae773b7f0032eba740dd5a5358bb847c155dcb53bd42fd8a12d5d0ca3b55c9b3a5f04509804ef9f9" },
                { "kn", "61560a8a87665f778eec13c86d2a9c6a4214bdf78bae78a7319593863507576c72034e9f6ceabbb9ee2487a275bd7365c1ace020e8cb26b66206b8cdf8956cf0" },
                { "ko", "bc4785f7b6b751923886f1c96537d8a81608e333e518b1ae75d6d634e280929f2f1388026283a52ea72966036fa3fcd1697a46b17995475cfad2eb81daf3508f" },
                { "lij", "ffcf24dfc7ba4ca9ebaf60eefcbe59fc27cf363007b07ec358ffb2d5013701cc5306e4f12dbcab7072a20d0e1896f6c3467306498e0a5a6c93a973180571680a" },
                { "lt", "6ea5c22899bf0639553dcc513b6de8e770650aa8d6ebb1f415e6bff198c2399a11d1d51b332b60fa410db01f938d01ded25ccf8ebfe0e6cb546325409d4ab7fc" },
                { "lv", "ea2d6b4c2e09c5ded8c23527afe242934195a096201693c84bca2425cb861dea9d743cce09dd235f253dd0b2adcf27bece604acfbeba7b630a3cf471647b9fa2" },
                { "mk", "4b9a6301460f5012ec152558d953c93429e7d838eea5c9c01f917177d2f6ed39801b02e7a7fbf19f5700f161e4852e1ee780e07a11a176d6d50a86a0f391d12d" },
                { "mr", "8f78f52266cd7a3b21ba078b037f892c664ace3f96403d3dc81cfcac1a9df12a0a0c493200ce319f12bae1e68f95eb6fa98055d919fe321b5ab62d225aea9e1c" },
                { "ms", "34747c5b41cdd79abd48060b579f23d067b6403a21a22ffd40b1dd5484d9a2e1551089f1fe201d7adceb08eabaf1e20b4fab97e229df71fe822773486aa82b2f" },
                { "my", "cc101179eaf0599862861469309dea4f8a947d370f3e72e2bba7b7af638bde5faacd928f52a2236a7c8582978a625a2ef8192f25b99fa9e61011864ba4b2b6cb" },
                { "nb-NO", "e9611d601619393bf0f04df22ac0b95fef523c19f8e57ddfa047ad4a5c787dc687c4f4dca0318c2f402ad709c117612d258f6df2dc262625b9408e0513a129d2" },
                { "ne-NP", "517960c2fa46cca8c91f22760835353f323034a25557f2f8c9695efbc3c525785ec20edd06d8ad2d84db7d112f990cb482d14ccb03ec30faa25bc1a9014c1f45" },
                { "nl", "efee279db752a22f112c65e3f7ea2c51c9813ded738e1f833ea24e642ae01c6186dff53b1466af50e0560c2c085b021eb4090ca4426714259e5e1a5e774f37b6" },
                { "nn-NO", "9343bbc1ed938b67f77de62a7b7821894688c9f93ec614c0e4f2bdabaa4414374930a77ae528ebf05f06b47005be39aefe49d518a0c433b1437ee53e60a23d67" },
                { "oc", "031b0ca8e1f55a20c57c1032dd160eec0edf36454cde9c94fcf509c7c3148ca8bb34fdbf5a5b9c9d00e6a04367082c1e80f20846ad0c32a3d91701cfb8a6072e" },
                { "pa-IN", "f8dd507b2d5841a5b384549bcfd6d067619aa52cc55d40b829e1c2fd00de23cfb4b69b215306fcc8dea6f505fa4ed07553c96dcbb54b65caa68afebadf01541c" },
                { "pl", "fa8a883faf634c65481dc0bf4f1d4d7c16870efe91309e8828b921378b3c3e3e95172417e444c769959abff228e2317f7ab9846ee23392368c12a299c2948041" },
                { "pt-BR", "7d878d02e16e2726d1425c61c03f99abf2ff4aa11de454b77bcaa13d997b94c302d2f7bc17a68f68e24e1dee867785199d2132c585350ea3f97cb357ee6bcab3" },
                { "pt-PT", "5c7dab12846ca5fb38df3d366a285cf3894d68939c16ed4cbfd43e9c0f05bd5591ea6cad9903d39b82f54a256a6a4cfd45c548dfa37725af2fbbaba414a3ea83" },
                { "rm", "a401bf7a908f420eaa1c80c6825a20d9bddc4d9c55ff8b48f69d4459c8e7f3fa8fdeafe1388c869caef83133b0fb7dbf13c037a800146689fc120c7f4cd1e287" },
                { "ro", "b0bc54227fd5563754cc41d68f599d40b0522f4878c4e206741dbae6dd23efed41521a16560829b07a2063cde0bda01cb973fbc725e2ea466f2a471cd4e67d79" },
                { "ru", "423172da90be84cada821a5e328ea4dba61c577717bb759e4583bb21fe6de66f3dc39085c6912bfb7262f0f73f63b91ed80f448617a77a4d76ede112254d2cf3" },
                { "sat", "9c3d9549aac7afd204b8991015887212039a68d7454663e79d8cbbee01d4dbc7a597d81047f37e15792487c47f7aec60a0494958bbeb8513b765ba4ef193e52a" },
                { "sc", "0b0a9daca4d691612ec1304de4a5dbd51c2dddb045c3484e1379c2e4f5b0e92a000a32a5db5e59cf2b783962fe2de4a7110341dfdc8d9947c9b84fe03b5ef28e" },
                { "sco", "203a86f8abe170013529f90e43d2ed59308d1048e97862351c7f85cbc4d6ef3be43e84047a7b3c23f46f92a561db741b1c5f806854c3353a9134e3997ff6c9bb" },
                { "si", "b17ecd45d73df381805b03d57c345698a85ae58d20d9c724e6802ae51ccfdc37436ea5cbe71e28d0802463fa73779eae9f213523ac1e27dea026a6294dc30dbb" },
                { "sk", "af664a75ba526e97f338372c94c85a1f7e0cc08cd976ac95e81e32e8378acbdf751dbfc3d9b4371b1dbd7b3a4262c64464871e05025fdc96f78adeb6fabdcfab" },
                { "skr", "68c0579241f20f5eceefc72068b40290d5e3fc08e4caa2e7b523e5aa9c06329499da812be887db6478ffff5b389271ddc3688c45f29cdd959a0d8d2f34b56d94" },
                { "sl", "40ea0bdbbb98fb1d6e577117c90725fddd7db8a5f8233bee0639cae3d74df02bce901784eac392e16655943158a0210ac6c490c0e688288df13aa0aae1e05de3" },
                { "son", "9797e95d23f8702d1b81a271079f59618afd50f93e39200fbfba3d05d399967bfc4dabfabc6ae3136e8fd824fb43d7884532a6901f43724ee40cb259c96924d9" },
                { "sq", "475087e5d4c8368a5cc526fc0b1a91fbff1dfd1ffc77908cc4e30c696ecf97250e856418f1d8dce5aa24bddaaffe3e24f42ee5f85107ea04fb98ef15af14e7ee" },
                { "sr", "ed632123a01d314c769e6c3b35a886b779e4fc94b3d5a298ed4323cd1ef0da709199e984d0a031227d989a7b0b412fc93015471f77bc04803396a9caf34e6c8d" },
                { "sv-SE", "8ee952d9e882bcac0ed6dafb112591c08e45714b8e84a77cd1eaae07f2e8f15f1dc728a214b904e4224e43e9bb3977b34106f8c113d75b6e415cd607c8d05300" },
                { "szl", "fc98d90aac4cfcb944c44e6af6b26379c4277430f92b62a50c7333a6b12aaba11427c63d93aba38be25276d576a01b32ad16b4b597819d6b73c97037c83f603d" },
                { "ta", "68fa7d37ea34dd9f41ee47d178f6e914ad522fbd43dfe05e4d9072dd288d3f2e90d93784d6515ad32ed9ae662c10a14da870c01c6317d3c005f17a986d7c43f2" },
                { "te", "f61353ee03bc05e0f6ef520739e3e91ce82f7f3244e45cba6910e08645e371f429b060bb09afa3e761a7aeeef3a21352bd4a8a3bb4b5ef08bfbac5a323633ddf" },
                { "tg", "6387d8edbab5d3483afb9042bb07e9feb706c966759a0d4202d61a5d2f4da6ae4eda2b708d8580ef411f6c5e6d51b694fe1c038946c1b56f0ba9c75e48c337f2" },
                { "th", "e1955bcf71ef4c39fa5012f84485e3075c7a6a545d44d52e3a5e7c768a5b8dc9c1c8c022fe6216f0ae4f19aabf8a07f5b6323a9c08e528bc81a179443677658d" },
                { "tl", "028de1e73eb0a5f339a10a31ce702856efca6e50f2d19852182c920eb488077fce5bacb8aaa7f8c22bfdbdf6f9b3e5b80eb3f3461db2979f6a29e9b1cf599e13" },
                { "tr", "2ddddbb56e440064284d2db9cecada6dd5a61b73e7d164b3c0047fee762938b0a055baf9d0ac3d88e862fd036c2cd22e6f70cee7180d39b7f50703f14fed7aaf" },
                { "trs", "3e7585562719115db0c60f2f15153e1c02202d0f1827c411d7d9ee110e6915caf5b4e0f85da17de8a7a5a37e3136d0ea8e1fe0babe3e507973f43d5eee2c3cfc" },
                { "uk", "866d94bbae499128d131caf5a09796fe45f50ef903a46d80448acf9793eb565d0c57e133ff3cb73fc1a96d26ce2d6ddf04cf3ba26e7701a5ae25e25f88536983" },
                { "ur", "7bdf398ec9f2b65aa4ccb2cd7e2c767b176b9399cfbf9198a38fa5ca635ddbbab0e685f19502211a438a61e45c1574733b384b519ad6814269e747267dbe086e" },
                { "uz", "ffa83a0ac39b27b73c7445cb6d1eb7f69f4a165110e36df0e3185e7de806e3fca40ce8855ba8c5af0c0dcc480a945d8b321e1cc7544c44dad5cc5325ef4a6537" },
                { "vi", "1511f075dcae16d24d8901f9275d3e504bb28342eed0e990e6ce673eda50802dec9899c64931bfa66f0d666f795919c8f2786538b3954d9f2de5e10d5b331757" },
                { "xh", "4c5d93e5fd21ee3ae4ebfd19e46d9ec2956ea42638527b0f63d0c6ed9f732cb5968df772f43df9e6c962b10543077e07d44fbcf1c32313fa198c68ad6f15fd7f" },
                { "zh-CN", "1e0d3a081ac998f7c5e2a0d9433aa8e841b3cc2a242768225112c0b31bb12e0aada6dc496743dd51b8bd81583a5cd787a5248c12eb9395e9e95a5357071e0ee0" },
                { "zh-TW", "e4f917e2ab3c87fefbae4425e9391bf6aecc47df900b35cdf107cdbcbec5d5a1e6794e65559c8d3f45cdc8bebfc2736234c30031917b6a9b8fc87965e8d88d0a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.0.2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "858c6c38f8af30edb3a9a68d15f72514cd94acf33b96fff135c36f0e81259a951c703d50f34283f3221449680dc244f0952b21b1f0af02d382de47ad18cd84a4" },
                { "af", "e78cb9f32f98135ae7263d78091a4af6b3c7977573b0c08ec77b964bcf240dfd763ec628a5e0667827d7c9cda8b6ba589590daa93b2d7d86bda6a13e17aee004" },
                { "an", "fe7862f9da50324337111ce1600962065ac6751b52c911728888d0f1cc9aa044874117019a939df32213ed29195d0e0c57ddb85ebbc658646365dc6882d1d599" },
                { "ar", "7419980af47e27330781387d286e56b2c643c2d337fc59a66fe203cd776bd38662da66c8eb8cb73667b0d573cd1053c624238cffb47899440e2f84f9168123e7" },
                { "ast", "6dea724c482ae24cee886dd0b2e3a55f7c84643aed47e59a06ea8d284a2fb91fd5f9c8fe7167e49b7adefa50b333bdc72c1037badcf9bd7250aae6bc29f7dc1f" },
                { "az", "9b91cd0b0f61baeefec96415677b9e27c4a14f14c37a750a4068ac43024cee05c94ce26654411776ea7163772f9bbc71ba210b46cebf4b7917a4eeaf4c7f6b88" },
                { "be", "3de89032b2642f8f9f9964263162fb517502351bd1630743aae00e6b517029f20bbfa0428631ba1d5f79e6907971007ebdbd713fa1f9c315d667bd3610f359fc" },
                { "bg", "1900fb7625229f26e1f21fc153046c9a9d6147a9bfb9c038944a969ef588d96795a4113de5618c3356f816caa7be0f36d76e57868bd65f2875ac68a68f5374ef" },
                { "bn", "e7ae1a0ec1be9912246fe05b679b02e687e3cd366889290a7fff2020fdfb6c30c21bd59add9073d3440fb61041cc923bfa8a1164d28625650d92f3fae4df35f2" },
                { "br", "23878ee17d7db93b3a6fb01a397e98ceb1c1b33286c4e263d007e520629685a26fe174d30f70597fce17cf94d1613ad6a79f8e6454d9ce2b20b8106eb0d7a072" },
                { "bs", "050055d08d3f58e4bcb1c6a5a639e85b0fd49544891f3b49116a29f7eeadf84af1de2dc85dce9d9e3de50ff90acbb5839cd6ef8c05b62cd1df7ace46c845446a" },
                { "ca", "e2dcc75d513ba8e8876dc104622437561ef6f375d1bfb70f6185ea311f101f82991b3e59458e2f65ba96bcf0c05fc02aa926d29275cfdc9121cf6703725d437d" },
                { "cak", "d9d10e5f64b91618789ee6afdf8978d2b22a75eda15db53e32451de3ad2f4432592561be811762621e15affa6ac840d7846a7e42d08dfc46407a2829443c2902" },
                { "cs", "ad5d5e7d78d24fe04cce42575a79e2f8caf5d7f3c6386489a08da0b9e6ceb7cef3bb7f1a3ebc38cdc8295538c164fe8de79a1578d82e8e2a8b8379aacb7e75b5" },
                { "cy", "26405dd57178239195d8b516d735cbd20b0386573b8cd86a14eb017f98e61a1679489fd36ccc6a5d47cbf5fa9b8cac72643513b758aa42f87b73b46777b1efc5" },
                { "da", "9d72adfc7a5207eb531e122b41a33a8df720d52ce1ae516c3d14e81fee19d6b6088b149f2e2a62dd04433e68adbc7d6854f8ba648743914145cb0e75b922c6cc" },
                { "de", "38618a0efc0b033881c392a56a57a3c923a23b93596bfd2be7f7c0fcfc140e11188b96259d0e13c6cded4dd39d22ae72eee4ced0d56cf14420afd2f3d54131d5" },
                { "dsb", "313ed8d6c25bcb417ef4fc30fe9645e566d6ad4d15ce8990fd2338c5ce9216daf18516fecafc9e115d5a553b7d3e9dc7d7c95abca5f31b1970d3b9dd91c4f4bb" },
                { "el", "d1eeee975445e16985225f786f0feacde2466a153934cea8461620d4272682067d422f45d1315118e10cd23854496e027eff4bcbac672aea0ccb7aed152d6804" },
                { "en-CA", "954c0a316b7f9b65d681b73c08ff0561f4ef6d7f0cb97c3849187ae3b52a825e8eeac971ba00212c543da716b580d2f8e6708822871f0f7e74d73bafb82b7f81" },
                { "en-GB", "0668ed8f017800bbb29796ea86395658ba20a7a9a97c68387b4f852120c39f690e6e21a6463a1318947ff217ded858b1b4bbaf10b4f3a4ac270aca4ce6d3fbb6" },
                { "en-US", "2789a5b9e001aa33affbd76a31b9ebd74401db1bce3cc0093d6f58062730663cb54768da3bf9cca5ebb1412763a6913226a7ec8627198b236af65220664f60f3" },
                { "eo", "bcb079c13bca22462c6b3038f3e6d178cf243bc0ebdf4309e2306fb2eb20e1fa0f8522ca7743f6b2f15b1c451e10faa0235b1325c66626b32baaea042b01c354" },
                { "es-AR", "d2dc6beb0920bb1bd48117a763eee69f0f726ed2949f3f5f4c3355a8bd0c14c485e8e2e2fb9bd9b80d896861959659c95ffb0097cee6edac0ca76986d52c7acb" },
                { "es-CL", "b50d8efc82307f87704eef14d103154cb47828618b12c15b7b6c65ccd83164bebd2a7744f95b9eaa14190746cde6eaa8878c1b5ffa7c2179485006d978288d61" },
                { "es-ES", "b4fc621aa1ae516f6557ea213f1a59778396c7b71318941dab676278481740b4c9bfaf8179d753b1cbbd3f4280967c574ca8c0b0439e49501cd2791ce9d611c4" },
                { "es-MX", "7add0908cd702c71dcb69277153bab957442fa4419af4531c2f644abe2449ea8a32629c1d449f357caa31245091ff072b76ad44a5c5d61c7dfae6596a013f989" },
                { "et", "b7a64afed36ff0e036cd9e2b507e30e5cb27d025f87e22fe9ac9355b78db35d4356973d1203bcb378b451677833193b2dd4638cdeb725cd57edb81ce5c868dd0" },
                { "eu", "47a5493fe56ac2f6b150a5d7f7268550f9dd6671fcaea8580b2f9f42384be67f3ad205d1b85a1387fbff7a1239a01c172f9b8138692a2706eae2d9742b68d4ed" },
                { "fa", "bfac0188d5bb85233031a492157182d482491ef9f1382cded28a388feb6a1cef29a202c8096beeb8089d268117c422462cf4800d3deb61bc7984bb495783dedb" },
                { "ff", "81eab8ddae23cf4f73439da03bbfa7afbf7551f31556d9966d40619ef3d67823b5ab8de6a649ca7b084a802e9abdf4de484e5b093c6644de188385bd73060018" },
                { "fi", "92ed9e69e5359a3156bb5f6d3b4e75adce9bfeef42a8e991bc11891dbcafb1055018df01cf2489a815268ca7c3c0e78a677b72a314ab7beeb0d34f9688828db2" },
                { "fr", "b6d99f75442b67b42f98af2f006277515ec149da0205a1d19988f1c4a7b4ff60232beb9b80817d8d68268477328644c94d1f86d0a82f8af344f241a2633ed8b2" },
                { "fur", "8216d85eeaf3da9827c960b3ce03f17594a8a2315bf7909333a09cd5218199fd61b4da834f50f211edc62669e39ebe5cb11f65b386ef2983f0e3e3247ebdeceb" },
                { "fy-NL", "94c6dfd0e15f97892081ded4dececc9234a2bedf3569a9cc6060b131803d8697aca07c39dd13d6138bd862e4018577d92dc2b4b91ecc337db3b8d360b52cbddf" },
                { "ga-IE", "a7773ef6aaebfa144a3b827888aca695bd27d064696a6e4570fae68d9afee2860bcab704800566e55afbeef1e482aebf51b1d75684275f3c993c43e36a0703b8" },
                { "gd", "a8c5ba3258f439e4a393e83a7b280e8c9e99f7b8b02700dee0a80e450034a3283184dbe929674e78c4e3a757fc4586a9850ebb2ac6b60901f3f276a82e16bf5c" },
                { "gl", "eeaa2aa3f833a172c932b91e0a89c253093e4d21ab333bd6dc819e7f6a113cbc6c6e1a8e7573ee61a3a63ed58846dd70bd120d3909593eb6af36c11deb8d25ca" },
                { "gn", "b0658e7d7656b0c64b4fba5d9d77973bc55629c68f9424a7d9b2ad8f40745e5fed681070b66f23756d6711f0a788e6aeed857cbef13e68582263dd22bfb2936f" },
                { "gu-IN", "ac6437fc3ba4232f7c1953fd8534ec6aca8baa77e8c8b3d87ff58401afb95d067933855730b041bd57dc7c19c3b5d0092c77b2b25896555272f52499afb3bd86" },
                { "he", "df6eba9769a059e5e80755c8c2e974589bce6f82f9159a2779068f101a2634c775d5b1ee29d139541ebab052de86bc7750177c8cfbedd2d8ef052113b3deeddd" },
                { "hi-IN", "a40eb8c82b7865b4b95d9c1cf3821facdee1dc3d5eebc143b721c9d870b35b82dd716b2f4739f8b37ce93027010364275adb72587b0dd7fb3d21fe99bb9bdb79" },
                { "hr", "74d3daa8cd8e87c1fe474c42ea4a746d8d889b474c75c882879f394a923d58e328a0fd93e0360e76098ce987dbd713ff79d2509240bafa77676660f7aff6a950" },
                { "hsb", "6cffd2ed06785a18f488c5d1e997419dbacd687a5393e9e60153d2c97e75c80ddbdd7c5c545daadcefb6ebe063e774cc455b3cbdee1917b19f3aa366c1f4fefe" },
                { "hu", "dfb2e9fd79b712b773164d7e27cfdb0b01845e131ee10bf289aba901e02852519a3723c0bbf2677541a36a5c3b42b0f985fbc0e94b41b4bfc6d76e8f27ba2181" },
                { "hy-AM", "3b07b924635652b870889b5efb22589047193e74b8bb36002ef463ede72be6609faa5891fe571ace089dceec0451a8c75f9961e8991eaae2d316a075ebc1af98" },
                { "ia", "67e4a951f69669603884002f9bdf11e11824e0b56fe26e445b6aa0925d56fefecab6b4d07d6a8c3d60681a76b4c2d6cd8c846d5a2bc90035530a6ddfcf556576" },
                { "id", "3177b1bc8e29823a625ad42d683e0a874a155b6c30e7bc0819238856899783230dc7d53badf7a32cbec52121b3f22ada9c3c0ac40045736726a3c2854bfd72e9" },
                { "is", "06607be87bd13abe398f5ebbf004a762de1b5068535f436c0d9a0fc02cf919200a793708d43a8dbc8f293e9777d8d6915a73abd7d2baa78a064d35a983825882" },
                { "it", "a527338555a591eb2b24cf34aa8c79cb086c73cc99d9bd9387184029329b9a2103e78687c34f7cd35db2d7a7c88d5e9c6266edbc5fd6d7d169c2b629d9048512" },
                { "ja", "b71d3d7b3a6b5d517e077d9cf693dc28653cd9f41cb586c53ae2dc180fdd0192f550e902bf8f1439402c3c3a25e5df3747427b2aa81f21ba541911c7309e7e23" },
                { "ka", "348d901cff75f5afb7999945014ebf780fcd8a4a40f835d57328292019a2453266ad58a89f536da6d491e75a9d17c44fa34d034dfc4c16681b730b1aabddb7c3" },
                { "kab", "c852029c184d4c5fcdc33d6d639375e528ad6a26dcf3a2da0a539626cf07bd0f4f5921dfa4a5b0703002de0c44b06439cc9b16bf889b781a3812c0f7b2b710f7" },
                { "kk", "e6e59675cd63b26df79192d0f688036dc9d2361a24cb70ea09696b20eae9118ba2856dc174427a248fcd5830edf284c48fa040cc8e0fc0033eb0b156dbe65f05" },
                { "km", "72cb8a4210363b6d39cf53d7c123af1c3bd89ad3f519de1725f435d0b14339e6ab24c4443467363ca39063d2adecb1f06aadd391b78c0a75dc666fdf6c2a67cd" },
                { "kn", "ab7768c46542fd0036a892cd9d0ebec53904c2dae5c3379c4b47a5f0254eda7a5755b30df639999faf6623f5cebb843ed9fe5890ad04fb195efd84879ad24b6a" },
                { "ko", "c2629e1daee5ee67791acc0ee848c4009e5499a61655717f3f6144b3339694e00e116dda3de691dcb031248de02bee37c50ce250fe28a4e3bbf2d227c623c9e0" },
                { "lij", "5093fe3afa9ad81a3820f1786a4f3fda5661e5452de1c508272363652385d96b7e0f1662ed2955fbffd9c433e0857c0ba9c981b6f18f604aea30f44e307bebed" },
                { "lt", "819963c4b81a3422a35b560110c42e4623edb86dfc41ef5a8d40cd274729d6deba0f07b5d42ee154cfaca629f0131ab1ee8f510f2ec8dcdfc7118c3be4d22ad1" },
                { "lv", "f3e9095da614748e26d7b3d4da9cbd28119ba96b828c349e4ba5a89174117d5a7135becbbcd866c28b73192f67e5072fec7cf6096906ffcacbf589fa753d6227" },
                { "mk", "f84e8cb8c2f18544812f917c756ab920ef97c216551d311d0580c57346e0e41234427332043977faa6f15428b9bc8809e7c6548495779643e84f5a9dbf8a8b3d" },
                { "mr", "a15d1b08d34888891c6663fd8a39a2f89def27a82c901f043ee6c71af80ddba0f8bb9f377401264270bb93d95ea09a59ba815853a5571fc54f0a2ae1085d7037" },
                { "ms", "2b35d34ab7435dcfae75b2e45a887e71169b4e08b9a2d4661add84062112068e7ab95b8b42ecbac53a062b610895d33a643c361c51bb19e50a48a51d67cdb551" },
                { "my", "b767335f2f6e569e399b3a5ac72049e2fb64573f7d54c7ac7bd62d6fdfbb166f4baa1eccf787e2001f48a582f4a8661594cd5381166a8af65c650b9a2fe05904" },
                { "nb-NO", "8d91163d82660fcdd7ce09455d7531fb36da972fb39367d9a21f854a888c92f79233f146da59fa87a8e59c9d9fc85e2e2748ab35f3598cfd73b1f126e18f0946" },
                { "ne-NP", "a1d37eea3155f4f800171b47dad0386a40094b551622aec54f433e33c702daade713b225d1594bf7796b34011f3f47cd446c74a1b0ad93dd30c6b357127b5650" },
                { "nl", "5082d194d01576dcb584b57e28bbf63112f48c28aa9364731799c22959a3736f5a424046b31a5a172ca9c9f6a1c211bdad5eba2a1a6f3b1e1f73a5ebb4a12694" },
                { "nn-NO", "0458871abbdcdb43b6f9c09d383fe7133caa15748118d804ae5279295c68cf2c6a035f936244eed0b3847988f850ca62720158899bcd0042a4c6eadcc6aa3851" },
                { "oc", "7854dce2d90534e1175bcdf5c70e0d1e5fed0738d23d07cac1c58145e7c2e49fd663c6798460ed24cfc072a1adad12407e86af24e64892d26a348929c0cc18e7" },
                { "pa-IN", "99ae02946fc8e7605dd2d9a217915550a2192f58cd84bd9ad445583d22cd72612c35159e657bcb837ecfaee973764f3f61c9ddf1db1bf82bc42318c4af0b83b3" },
                { "pl", "e92c1390c4db5b140bb695caff2d346d3190084c2313354aa072e803371aeebccceaba5e3c7471c4da20a1649e9fce9462c2df59781038ac854b4c37691649d5" },
                { "pt-BR", "57895b0a566e0fc06cfe80975df73b9ec02b6fb9b9b35732522f88cc106a9eaf1f5701e6ab7e417182e700e1426a6c5c361ed057a05bd5a603f6b9bb6a0ae4db" },
                { "pt-PT", "fb2e7fd4ac9e7b0f829ed7dcfc05c5972fdd2a3357d6ae8858c4974d08a4a1c3a7f78a285951ac027a6630c1cb6afd94feebb2e5dfc39ea1dd723e14fb2e6ba5" },
                { "rm", "99139872eddc7a4b22afd138c0dd105a44ada793074c804993c978e1b825f171148c9dfe74612b84a910d35a6ab1f499a490147e68e85e7e3154eb9d3457e392" },
                { "ro", "f60ea7b2aad85f4b1085ae6002482eb336cd34939d6653221ca3bee66916c67274c500b3349a76feef9dfb452d65597684add3931e2522cf87355c88db977c96" },
                { "ru", "e29270561853b3fcdf7034de63a80444ff7db720f654d559a47f6d426b7a3f36099d13a5de40314abc5c64ba3e1d6423664a6626b946f4b12944efaef5656fd5" },
                { "sat", "8e87cc5502e29d15664ed6580f04dabadc82325013a1bf1db790558e923a7429f6027f681d767c30865004a30b47f606214c8d839b539df9a83b920aade5f8fa" },
                { "sc", "2aac4d6344b99bcec57a522515a3395a06ea0ca2152cab937c96d96b68515bdd9d34774c77a7d8fe044805610c412a828cb62f95b00e79f426c59980ffa70b95" },
                { "sco", "7ae4092d9f226f74c325ba5ff391eea63f645e43bce6727d74d8710b7c0bb8f7d5bb59729818000999873b013762b0d73188afc21e88bfbe158e65500ae74fb8" },
                { "si", "286073469e9a834cc2671b28b8652de8097470c355e602d739cadeff3dee49d07bab4dc9c50a87fce0facbb7e54ad53d77d4ba58b7bb158b73ae4af61af7e3ec" },
                { "sk", "3b63ec4c8ca1e6bd9229aea76ecec39a9ba455a07b2b66614292019b7ae05df00a8ea243ef56886a7ddd441bd1b0780f563242c759e2d313bced1c0eab4762b4" },
                { "skr", "856f547496804fec03afe50f0d40494442c95214adeb4aa593492e59efea1a7427139d59eb1ea7d49735238110071ea73713f1b6af4af18b76061b7b0166a964" },
                { "sl", "f481ddda5fa308b28f9092d5f077bcaacd0a54f6f7280920a24600ba27f5599943244fa1552a59a6465496e3381728c3df5e1c48f6f53d6d3ecf4568fe68906f" },
                { "son", "eac850b25303cc82658c8adb303377f99ea6734368c8eef4ea41d5203c1f705d3552d7ff4981f373cfa960a196929622c58864b191254ed2a6b4a3a5d081e19f" },
                { "sq", "b692c32b3ccff33f29818121bd0b7b1ae1996f8901e649cdcdf0f1c8b0dcd68e1351524913b472d695e435d383f385540b289720b6420d57f6a34dcffe96a899" },
                { "sr", "7b93c8b9931e9ee9c6749eeae8365607db4dff3767496e06efcc9302a94731c254061957163836a261e906aefdd6d7941d264d20d558f5088cfa9e611675d83a" },
                { "sv-SE", "ba8999627e4d29bf0977b847d6f9fd8ae7edb7e2cc8bad3c523c6fa1236f3f8264467e491f83abcffbfee1e06b4f356b7704bd030d266d75ede86a157f4c9e13" },
                { "szl", "4900831e4434f6fb22e42a607c40fcda40eb02a25abcd1332e6ccf46c08f3fbbe0d5aebc85457c0d259695cf97ff2de0e5700d426ca4b453b5f74635d598eab8" },
                { "ta", "d372e0fc45894f97f6cc8d7626ef8cfc776add4bc93cecd1b17cab7cb62be1f2711627d7159ffafd6acdd9f7ec6ff935a47583b3588424f6a53c25605c90cdcd" },
                { "te", "2b13fa716637f6de6167c85638c2f37263f75fecc976e2a8c430515eb795b60725dbade1ef72ace2edaf3276ad59711a6de9dcb3490cdce69e97a1892da7971d" },
                { "tg", "bfe6950b9ece49985bfa7994067c68a6649abc1e4944a8ea408e5dad52df402d49dac121fba917f732c9fc87642bb0de9ce878a762c3550527fc2f8f86093ba8" },
                { "th", "e99c5f12b2f1beda25bb5f46a0e092836f448377451b28997d0d11ff954f459e248cdb6cfb0ec27582498d63247552fab92157ec00442e0d98346af6dd2dd4f3" },
                { "tl", "c06bcd340cd17fdf5d182b29705a12cb78cfce1972f1fe471cf36f04ce6eba9ebe1aadd4c4bd2319b6808204bcc4357ccc4ccedce460353dfc4596f5a04b6ea4" },
                { "tr", "1354ce64cac989af3a51c8a3c9da06ae24c76bab5b894967c99db8c93991b546d6ffb935aa37304517ff49761b2113cf98b727941a01d244f00a914f1ee7a48f" },
                { "trs", "8bbe931e930a3e1b734e6dbc3067080995dcc4c24ff4d8319e5211d04da548d6bcd51586fc505c194a455fde248b93036df81e4730a4d741ff4f58c7f8420304" },
                { "uk", "9aaae0298688f552fbf9d11cc380a214a1cbe0e3cbf4ddaf64c77299e9fdf13ff2e20cf823a0d6cfceb6f077d49c083b27936c13cd3dcfd77d564fea0cbe62ef" },
                { "ur", "beec7309e6e4b52eed0dc5d7e9405d7b4e5edcde164db18d69e657566bb69e2a811b60400b160522c406b92b4202b28debfe709bde30beb31859c633afb0d9b5" },
                { "uz", "6d7eff2854fe714ef8e64e400f2e68d918bb4036338f4879bfb293f6543b9d5a155c62a56df4c697afb902591c7a90cada697658bb8315b5dc938c90d3983169" },
                { "vi", "21ca7cc0b35deeca588285052a85143ea89469389ae379c8807dc49554e4bb41aa90867453c584e8eafe683ca7c2d5ee33036f76c7100e7e0c969791a57a9a24" },
                { "xh", "bfae9b9bfd0998df0d40c70b8ba23bcb70443b60598a8d6e2aa8b50595a57bddde4a9e4bc8a368e2dc88861812ac1563918e18a26d7db160ff9579564c577fdd" },
                { "zh-CN", "0adf138d49ddd0fab1cb607a634539cad8c77ac07333cfe7881a69f5133219be7ffe60c8e6207a0b36eef92d1ec60160009a02f806739318abad5cb3dfcf833b" },
                { "zh-TW", "f1d8183f23fc7e0aedd912c29bc031e5cd4d610af2992a1e967fe77fc28c7f3cec0d6604ce696d2be0aa0a8cb867e86f471e175cddf3f40a698b674741c57d7b" }
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
            const string knownVersion = "140.0.2";
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
