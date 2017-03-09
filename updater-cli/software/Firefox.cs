/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater_cli.data;

namespace updater_cli.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode))
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            if (!d64.ContainsKey(languageCode))
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "ba89f625da7ac251aeef30bdb148364ea1dc93d6d73c8edb2d7fc5b039e11ba74ef0b76aca616fd23c666fa9d11d109eeaf6e481f3dd32edf425c8632c460dcc");
            result.Add("af", "4eb0ade16c6a4bb14ea11ddc292007e216e578f2b508c0cdb143138210f5bd2b672b68434ebccd3aecc7a3552714fd265ee9055158d5ae01c7c1273a8ad834c5");
            result.Add("an", "b17d5b022a013c09fe6fdb1be3ae1532e141894477acd3ba8eb06136df3d4638e713737aa0670c68f31f33b71868f47fd1782bd1e89a6fb2010a52b1547f5d84");
            result.Add("ar", "4fed0be9709bb6b661fa6346e175876996acf3939c4447ec64ae4dd717e8218e3ecca739701da97e8a67bb265e0edc128e35dba7741e795d64c91e9abaca6bff");
            result.Add("as", "ad13f8336c70a3b7fd3f12b3d3d54317e9833398280b8834188b4716040ab466a44baa66417e18fdbc555430c0b1d9a224988260567b1e23e2c887dea4e43be8");
            result.Add("ast", "10d1c899b184c109e337b6831623bc3c6f41dfe9918778b199fc413d04a485909f17a82fd37497093d37ab9c0ea191918b66109a83556e346a2338a34ee9a437");
            result.Add("az", "356cdd132a2415168d23ce9fe0fcc5b2aa96aef25ca347621ce8dc45f44a02f29487027561e825ae4a830e4c83b1537a3b65652e1675e85fefd4830908838f8f");
            result.Add("bg", "1666fed564e874f2215e0d3ffac519d8c5ffc69c4cbb63b9b9ce4c1daf669436eb529579ade58e524a285115938eb77e7c63438727d33eef162da4096eeae56c");
            result.Add("bn-BD", "07b76c6917298db5030eed3c53067e0619465af77f49d4b5793a3719652075f5ade8615762e1e12ee4011f5262b13c7925fc20cc7f89ca43729e07fcf87ac9fc");
            result.Add("bn-IN", "325b76d60189c3e4ab341d77b78a25720ee2e695b07b3c27acd49283b481a86112902da2406d0d7d65448079e653e2139e73362b1f8d5768964874bb2a9af61d");
            result.Add("br", "987373564535325037c2a005169a571cf64326867da2a7cbbd9b20b5b54b4027d68b088ff407809886e99e22b1c7923d6835a0e1e7224344c9110b2e8acdc92e");
            result.Add("bs", "fe8ca65ce53a6f5123d521b11fd0b8ef2975e932295e8d683dee251ba584aff54d17ac285f158fe14d3ee05b0609a867a64e4ddf8e1206855fca1a7905e93d72");
            result.Add("ca", "e375276a660b051f9df78d76114ec7c34d754e65eb4d050ea3d65bf5d583cbb6d17fda2bc0cc87a49d50626eeaff2d29708c611e2d21f47d3ac0c1b577b44654");
            result.Add("cak", "6c2c6090084b687c48b4dd90a64b95f3b30a022a41b0336cc0353d3d1d632e9bf55b6791e147b3f2ece531b9f16b13bf7d7fd51c9f42f939a6218e6ea9d66746");
            result.Add("cs", "041d5d366690010c204889b0f2a567faeb49c4c91dd999ca068292f370f1d78ffd270bc9fb013f60c75dd258b99e62cbfcb9a3f625837af836652dad12db26ad");
            result.Add("cy", "4ecdcd37ac693891baa85bd446f0c53a428779930215e75e084702834e5320db8896bd0ace3bfb58ad0cbd21b4cdb5597536810a8e02007ac25545a59bfed903");
            result.Add("da", "f84c2f9f1377980205fb7dd111c35303e5ce0d2d4e9bfa28e32042476db76c67a622cbb4abece52c6c42a04eb334de4d4c40dc552aa27cbd5f6947ac031f1568");
            result.Add("de", "84747a16d0e81d8c1d439fe92d505479a9ba0ff84988222f5697ebe97e246b8f65af54c0c28334602500cb91bb5ab704c18f06cbf3480b9b03814d744b6b1447");
            result.Add("dsb", "6a185818c7f13b4a9ad5f21b6ab9adc8039b32be318e4520ce8165f48046c72e074650fbdc24458094cca33f856b82eb0fbfd3166a5636de9351e7fdac67f6b1");
            result.Add("el", "dc656643754079731c82cfdf5b1aae67e3cefb49922fa52dff86ce7a45288939aa8187da323aa76afbda5091ae3e8b57175eef2095e4b98a491dc518617b5bab");
            result.Add("en-GB", "62b3c81e2b662aa4a50e6ce15f80ace1ffdf49f97e2e72d4c098f24e1656fe5cd5d84bf9bc4b721449f98911afe93aa7f019a3641f113aaa8992e0b914e36eac");
            result.Add("en-US", "88b538fd01404a6b12999ff13bbe3612af0922de7c7582be4143fb1f0ed624593ccb27cadb21f61057760dd382abf4cc91d2e6e279e424cb3c7c62dd912ba9db");
            result.Add("en-ZA", "37b13f517a78bc9eb5a2f26497ff8311da483259337a83252079a727f1f30cf4a9271d62983be39d5fe4c1be335c54dba8eff85c3204f40316e35b0f0d2f6b8d");
            result.Add("eo", "a81fb6734fc98f886f153dd75a05896dac5b9db75b4dd68b7a3cb357712764bb6531abc4fe1ab9e635d0c0764ef6fb84a9492cee1d1579dbcec82881fdca38c0");
            result.Add("es-AR", "33ac99ff0dbd05564da0d809de7c57496d7bff8e20c7cc188240e1fadc29a7916b23f4cbf7bbb8256502946753ec746863503017a64ab70dc299abb049ad0e51");
            result.Add("es-CL", "7256ff914f33a2169bd2a10d5a67ca1f684c0ffff83e18ab8613253969fb9c42d36391bb24f5fb183535e93e8724b77faf92c0c73c698261c43a95190848266e");
            result.Add("es-ES", "f22bc9a923d4882f06c315c443055bddb1679623c4f5efe802558cd2e5fb0c55a1ffc2c7f92874331ba27fb9e9422153f0f492f86a76596f8adc869e6c525752");
            result.Add("es-MX", "dabe3118bf43019d61790ffe317c6b27a6eba4999a1599359594151f9249ccf4dcf29c92b04eeec91c02539805f8dc4e24e56057b198054da8c42a55123906db");
            result.Add("et", "bfd0195346327e48298b05fe4f7cef3364b20a924cf81abbe67a9f15bda375feea4541b5ea0d1d1c33785fbb12b7435a96e108ad370e039b5684be8d96f8c748");
            result.Add("eu", "08b9c6a89d800b2314e6b474cece0e60210a4a1ecf3744ef22c10cf240b847d386c0065bed55980beb440205e5050b580c87aab7cc387d445ed11964e1fe126f");
            result.Add("fa", "3699266acf0e40b819264514d27fb6d12227aa006ab33ad7599f238039c271536a64afd57c86396a99e367555fe9e2da70f1b433160e05fe84f8948468aa7c0a");
            result.Add("ff", "f25dc329dd1b8bac2fb5cd5b16d998e18d1d7231fd94ddf1e8b71af5df6ba56ffa073814cea7f1abda0da048a3a8966dd14072d7d9403a18cde52d755a0e29f8");
            result.Add("fi", "23b769e27cb0360b8896b1f558259e06aa362f0f2accebeb04c76600c5d288f246f5d1fae63ac17622e099d224724d5509e00158beb7480c11ff60b338ef8fa8");
            result.Add("fr", "5f594e5ec1708b55c7088d786d3ef1a1e540d7f705d90e84dd13990b603fb5e7044d3e158c7db22966eb95726aebbee4c9904417a6c985972d488f592c5844f5");
            result.Add("fy-NL", "9d789bc3317a463f291abee7a2c9921e1fb992901cdc9ebef4d3480009d420a0c27bfc628c4643209537aea8bdaefe6aebdbfe1ff2bcd6af5bef15c0f315daec");
            result.Add("ga-IE", "7881a5f9ae83b066dc89b2f7f46cd1512b68461760672f66a0d54200998dcf8e4fccf4ee5b7696925008717605e0c67301e7b9ce2c24ceba4ecaa701b043e380");
            result.Add("gd", "e9c3b80c00bc3f17b0d9e4d5f2d2911d975a2d9764f9f824db56f809d9f7a75d88894717ab039c00858aff69dcda427ba61ae5b040d27a710efb1ebdd417c256");
            result.Add("gl", "e9b7e4f03bf9b7cfa56cfe676aa4a4020facbbf75e60804ad95a033e631ea67c38ea63664aeddb217bca975755bffe6502bcc325e7f86ec4c647820b3a15ff57");
            result.Add("gn", "4b3c9e35ada2c41d59fb8c5eb4244eca43e81c2415801828cd2f68f8f22b6f5bdf63d3304df926ee493e04f5b13f96b1a25908e77b98e0d0db0a4a4fd566f86b");
            result.Add("gu-IN", "528b1a1b212380e4d64358a028cf4668f6c33ed25c0261f48a5e8a40ca54fdd680b718a5d6dd7ea4602524c26738616659f9899773786f6945a1e646c47bab94");
            result.Add("he", "cfa06d0bc1a87f956d8084cb10de4577ccc51eff0dea777c2982d692866d9d2b766b9c771930613cee8fa64d8a7aad26711b96e97d73cd860df4aa1838b567f8");
            result.Add("hi-IN", "54b7d70730ad42e51438dfaae0ec6e9724601dc0e36d45671a6c58db90d5a1870775798a0009032a13e7a18fee42796dd4d1563411009f679fc68f2e4949809f");
            result.Add("hr", "ccc8915fba7890be0c5e03b2f8ac7bb97bb949350f00ee7ae47bbfe40e9f36fb958eff23eb05f5fada52388af4dca14ccc94d4d2cbad324ee2c66ae462edcb57");
            result.Add("hsb", "098722f75d3591729f3679bb5cadd27c9e96ddfc69548ba604d6a80c61ffb6df64430a2441124f804d56849ed8520748e3c8c9869bf4acc5577f99741f0d3e6d");
            result.Add("hu", "a0fb55c881a34b717166deafcc75148c6d534732573b037e720b0dab8a5079fea59dce64655e52dfb4994dcc2c878e19d0235d0339147d905c43b240305e5f5f");
            result.Add("hy-AM", "6cce9fd3d89ce58fd37366107375fd20d044b2d743052ac0c8dd510a2ca3b2fd0d62e119207b48dd6e772efe19f2b08079e70b47a43127d05479f37d5830bdfd");
            result.Add("id", "b0dc3303eabc5726b6d48f8db6ddec488048be49485951ffc2dca00edd7e836065eda6d4733788b446637d40e52af175a7e37bd83e84fb58fd3e32fb451b7dfe");
            result.Add("is", "a1358062ef6be9d66143de9dd5eb14cc467ec592894d09d8a0d33fa6dfa8e1b7397ee0acf4abe096a0646471885d29248286089d751b4aba075c4438217b0589");
            result.Add("it", "f6f0074ff85e10cdcdf5e0276d737a89c39a387b8feac5afdfc24d2f192bc27af8a1e41622fa9dfbadc7c37e4702522f6bf69d6cb37e0531724ca9499347c16d");
            result.Add("ja", "69a0c124f21bf607df619aa91485069ba94ba06c9873432bfc2e00efa112379be94f0ba7e3c212610c4815964e1384af98356494a7eea8cf43bfd7485808ed82");
            result.Add("ka", "31c2d5788521c86ceee2d836613ac4ea1decbc463de6c818aa10c75501012dcfe9cc692b912afd76a2ad78ffc7b21cb44a13e57927660f7d09af90a50f2ea2d1");
            result.Add("kab", "6b6b8b6648bbe6fc1cd3ff55cfd989545597dfdba8034816f11601b1e1a12dfd04621b255f880bf20d324d1cdd6a066fb9176f8ebcd3c9fcf9d45d8334934958");
            result.Add("kk", "a7c7daa1abfe8fa7c3634abd0f33c0be63e7f902cfd1092545726434b8ce49db5f913ce838949aa3f821160f83ee1daec9c6d038903a6567f44c294ff2ffa4e1");
            result.Add("km", "975f6f8be18d993158736ed4dce2500af2133e352ef8eee35e02d97c4bfa0f94aac98f78c7f3157f19a84eda9d2ed0ae200022ab38a7a575ce364c33516a4641");
            result.Add("kn", "5346dfd0660b9db3454c5f24a5e21ad8fa846ff23bd91e6d07ec5354530d3999fca70d9791b532fd88ee4837a84437ab850e05b4c83004b0ff2813b565602e6f");
            result.Add("ko", "bd1cf31bc3a1ec93aeeb1ffb55bf8c3c751f1ceaf34c9ce372c26e43270accd0f1dc10ff9fd37d49f99cf08c4d6c813e57a4a11003daaef11d06f7ca4e5bd214");
            result.Add("lij", "3b1a6bf68cf9b39b6147f9186a25016bd3e7f50bb5cf4ec60fda7d6a8e6b6837699643f0ff8151d6062d51b2c34700da5b84902a569f06af88507fb83b72fbcb");
            result.Add("lt", "cab85c543b55ad167fca8528191a26abfc23a73ab63661dadfd2d88b93e9a8a4bb886a6edfed051133db79584ff11a0aadd4481c4d599af847f591991677f58f");
            result.Add("lv", "4cb3060f176acb38ec7485fd8733222f01d7352e8114b1f640c783a7f352c87a183f0b4948a1fc4ca4c7808a6daf2b3a2b7fb2e53240e42f958af87e1fa4d50e");
            result.Add("mai", "faccee3246bde8bdb6ce90fb674a11c759d14b20e08f3c6c3e9405d6943040cd2c3a624a783d974805277155ee26ca2d3f1b506d080aef4a632d422208dbbfb3");
            result.Add("mk", "27b9a0a6c700db49a1f76ff4c88b012e6bddfa41a1ed3434f76ed0c919a76d952d617cfb674e6a332ee5e7fff3780e84091659a734fd7d169b986fbd654de22f");
            result.Add("ml", "bfd2b23f807762f9c8ff203f2d4df522619d9b058110bbbb0c382bc6b6b1f2366922153ffe4d0b8f3a805a61c0169c6a653141d632750c789d7f7252d5232f63");
            result.Add("mr", "499d6f8ab15acff929c8753b173e2a3b21dee02afc5bb7e962e61f4ab6b2794940a1abfa4f46f2e8647b323b8bc7b5f7baa9f3e07d2989ff4043bc3fb1015add");
            result.Add("ms", "f150272ab07c868e296da081fa2188bf73dda24056b49efe840b468f75e8a8fa94e0dbe39063c3d8b63402bde3495d8835351f1a14769db2507eca2b12b54b32");
            result.Add("nb-NO", "c71abe7b004897a0318950ded6fad2dc5be580d0f7a966f66763b43880c24df0cbe29426ea71d92646670d782c7c593d1165d1f7849ac5b6e40c8de5f1c66045");
            result.Add("nl", "392ac7e65452565ea2a8ff0bee06187d07cf0dc3586d60b26c4f4aa5ae0e5c6d86d83a494ea46ac64b9d52155b723e1de431f8cd3e3acf244e5c3a72d882023f");
            result.Add("nn-NO", "f8af9bf8de6aefcf5e49649a90a9e44e53d9c23ec5aaa5e035bf04d78f690e2422b246ffc0fca101693885f034887ff21a3bba80c9c90e8ba9f586689aa7d1f3");
            result.Add("or", "1973e2c7f76c6db2f43d61e4934c39454e3be2664d1f970e48fcdcf17366b3d90e5b389d24564f955571e8ad6803ab06260448624815a41cf5e4d6539dbd33be");
            result.Add("pa-IN", "9dd5fb981ab13da6cdf6062ab119988af388bdbd69e647cfa0140283ca3ee5dafb966e204813eb4a22afa44db97481682bd502feb02ed1c0d1bb2687a59a3c0b");
            result.Add("pl", "e268a1df78461c018bd9f6eba20ba535ffd236ab59253662b907172a52f172f8e04beec41a76892d723d758d5d16996a9423da28a0156ffcdc83167a68573302");
            result.Add("pt-BR", "a557b874893dd3cf2fef105da5076a0b580bee40912d94af5eb1fab907503fdcf9452c83000b00dbb1a8e1427a3373d6e187802a103db2b633ad9febaf63659b");
            result.Add("pt-PT", "bede2956eb389e6c63d3f538fa7ca045bbc43c029e374145fc3a8121de618c8fdd09b50acd9e5129f7bd88b24e5ffb986c1fb67fadbda8ae0668a3c0c5318035");
            result.Add("rm", "a1977a6ce7c6846b6d527cabc2865d3d35c84c05ffe0284740d6426dc23f37ab4ae0bd4560c28927dad8afc0b956bc288e023f1e0fe62720af0f92983db60986");
            result.Add("ro", "3390c06dd6089d6434acb613fee561730afe25b816db484de8128030dd4f6529d22b0d048fa5b5e9b03aeb5aa3270f4ef635fcd60d132ddee22c5b544a4f8ce9");
            result.Add("ru", "bc47377cf1b1bed73488a708685d5061ffefa98d4021bebf488ff02304f6c0639981ff490bdb33894268b3d9da0fd9686f163a1eac4b6f27b271df493718dde4");
            result.Add("si", "f9b5d74c104b5978f551dc81c457af66f77a8fd4e8f95eed105388930b2bf16ed4255d86357147fc96d9765ef7646227b9563490430fe79e48628e8af54435ee");
            result.Add("sk", "f25231f67a70cb3b1889b04f1c18f9d54c1532d91ef1bdeb5e15ff6565611216b61ba72d7eb2af7b58188cfbf2cead5cf6a64d26b4de9ceecc450b977b37e760");
            result.Add("sl", "b58b43858f9c3ad669ca5fe5f7e766f4af7fa72c13185387771f953c889d49a5a4572bb92fd47b6883cf1f1d5baa0fa28b457223c97de26548dbf7fbea6c054a");
            result.Add("son", "8262c7139c4e03da191dbd8aa23498b4582d65adf77b17c4d781514da85de1c2e6e324238b3c2c7f0658f03fb6a0dd47d4004c39aaa508a629b3c9db2660dfde");
            result.Add("sq", "c94c6e83a2a719f3211d9a2dc7d3a0d3a070f31a4f90170604ce61a35cd7add4b98e2e9691c908525acae258e24bedfa96930cae36bffe6fdf30d5a726b5362c");
            result.Add("sr", "8991c0d46dc31683fb23e433741020947cbe40c5e71aade7468db240410f604a1a164fb7e19db494f82ed79beb3b7dbf614fddaf7f7a896a3cb880d27b66a9ac");
            result.Add("sv-SE", "18e3f903d983c048691f114039856a66798d232ddaebbeb8dfa4022c01de21f4a5b78d2c04c267418a708e0b648d86264bcca7fe6f708e469e437d3df532268c");
            result.Add("ta", "5eea60260970458563b6db3281957edd2120f80d05570623fdefc9c2f1a96cb5a933ef6551e1fc8f46fdf639fab9f35358d4bd33137b2fe32e0cb4d5ee21f2cf");
            result.Add("te", "1d778de4d2e69a9d214cfa0d6364b12ac78df48276cd66354dc6a22235fdc5a32e13e0dce8157c8eeb389294ff9fefc443b93478a1174647d7fe2eb98ce598e1");
            result.Add("th", "992278dfc8a71c409db86b870320669a7508c02f6a4c4671a38900c065c45d221ebb4fd73ebbf0e7dbeb742bfad547c1c8e0a0bf6d796ba110525281a4839601");
            result.Add("tr", "2c4f42851ad38891a11b1f9c89d0dea66807d8982ad3c815abbf806fb71df552c9364170156072088eb52c4499ebf6cb30f674f16ad4e7b3f7f76b247098d073");
            result.Add("uk", "0d9379ca2799e59601e01c6ef6202dee9e9fa965d1569cb67d8d9259b107e4a214f5f6c7a001cdfa8b5d0cb3732c3503d33cce562b7c4146b6ab53687f745101");
            result.Add("uz", "2b415d4346ef4f3bce74891f0041711a24b1261989f85eb398a530271f7ccbc5eeafb791cedda670777622686180daebc576fecc8cab37931c3f5509afd1a3c9");
            result.Add("vi", "89ce8fd397f4f2ddb43da682adf47e6d15dfdadbd4738ae98a1894d345e9dc7f39678285de8546ba72e9c22a859b2dfd309f4bdd4cd4592fffd04d9cdba62d1f");
            result.Add("xh", "d44eb55855641b2b3ce89d441d6bfa3053a6e2d12838a1fade9f4414dcd1c90fc8edc6eb6534352be7b64af474df8967a124e578ef524f6d3de6f8da27870768");
            
            return result;
        }


        /// <summary>
        /// gets a dictionary with the known checksums for the installers (key: language, value: checksum)
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "df353cb3df946feedd4d56a41cd8d64b67d026260ad86b72c495521f62173f6830ecea8eb47ccff8bdd4b38d96b2d86fdec78b0c692a57dc8158f346bbd6caf8");
            result.Add("af", "47d10888278e2a7f17d5ff130a58cdb8723e51b05e2c64d627923388c0291b02c28be7d06ef0af45d1a9dda6321fff5112b1711d16bd63a92282784a92804a66");
            result.Add("an", "24cdfbaa79901db97dd1ebe05c4193bf3c213e9f6448155b36aebc3fe53d5873cbbde947870e9c4b21c67186708c83dcc4fa37465b299020e058b06e8bf0448b");
            result.Add("ar", "0121b912f29217fabb84b45b67ad3e72d69446d16cf674ba4c532b7b39f77f1653e20e1e32a4bf2f70d1faaf71b8da38bd0195ce58603d0b523e9adc380b8730");
            result.Add("as", "439fa59761f1dff967c6806a5e4066b4c1aa369402f19bc1a4add756a42e4302243e7442b60d6380701be203c978d2951c9f754e94a8d6dc43202ac4b6082d21");
            result.Add("ast", "10866f8c16cd6f70510c8a7d82c30ad63302abef0ad17a00f1c7f198b9907ed4596b0d9a885740cbcac4391d13db6a032db92658eb289eaddbff0f5d27d33ea6");
            result.Add("az", "0200f3043aeb86f69447432f0b209fe7b4038591cfe71fb3f7791429feb7775e1bc9fc7905b859508bce41fdfe986da9e05b03a0fd9ff4b46e826c401214bb84");
            result.Add("bg", "a3d6d4e2daa3378e3f21114ddf7be935a56ea77593e89d9d22f769e9ef061206920e2bb0434af82ccb5aab814893ab89428b4399379fe18c9e1c9fd615ce1a8e");
            result.Add("bn-BD", "ba8e34e2cbf56edb8e7538f49a14ad1e0bd4a29b259cfe132ee9985a7ba2fc7ddd675307a518b936633acdef847a5de9f59c94ef08b9cabded16b8e66fd4f42a");
            result.Add("bn-IN", "3a00ae6199c78b216cef7b57661093d4749007f3a26996dce2f3bdc348573aece11363fd80d8d86bc0a0dc1b16296374b1990ff1623b3fb63c0b4b49f11f69f2");
            result.Add("br", "9e644bbebe8ee9c28b1b2345207f3cfd60ebea86d69fb8b37b2b64425b883f5907387af0822989dd807818dafd8dbdf552a4a073b764f6184a2daee9c8c625e0");
            result.Add("bs", "1fab1b7044fafcf48f1da986cc0f74b6b16a62c960aa33f1ec0ac9b664d7140d497f853d1afc5de8b51bc27bfb23094773ac45e65ba67ce029dc0673a86d87c4");
            result.Add("ca", "ce1256b7122d7d33347eddee499e42e3109f5263cb65d05ed78ba1ebd25ba707effbe9f91305b574537c27623435ac4e7dac57f8274f1325aaef69ffdaf73483");
            result.Add("cak", "b0be5f504595dfc8d7b1919dca50d381dfe61b428bf8abdc22a53c2f224caef3bed8ba4ae1e1fc03fed3d349f932018a771ea74afdab76c667e399d630c6d0f1");
            result.Add("cs", "e33dbb9db337f5951216ad10d63fc872bc50da6c5271f050dc1509b1278eace76d6db2ef62b24b3eed5403ce992eefaee02e4e7903af4ae5cabbdc929b91885a");
            result.Add("cy", "d32d68a2d52a726b8c9fb9fcc90a5906744e84919c234e39a426873309e104f5b9323bb8e20bdfd37773f49f3874b9dc7836befdb3fd5aea7329b1e013754ddc");
            result.Add("da", "5b9f38e6fb58c6a4ef0579bc17cc562db881c98a6a6ae491e12a5ece5778af4b289e607eb61cd28baa73fb507e2740bb4c4e2145d62eeef70bc2daabfa3834aa");
            result.Add("de", "1370c17922ee21a28d4bb2f2871966d6d33d6d2dd495461f4cff91116999da5af899dd22aa4a0dabb7e82b8ebb75cbb3e0ac304560d36ffb64d87a3768018014");
            result.Add("dsb", "45b034d0bd1892d84732b59958fd6aede88b83640b1116e7b1e3efd1771e857b7f4abad39d1b8455a4adf071c586a9e251d76de12aa961ef79c11b4b8275d7c6");
            result.Add("el", "541031ca7b3842364f334d1c29fef1be9093dcd8926ab596d44ee275307dc3eb42e897f3e76c825c1dd921900e8a6e43d92a05eca3106c51dabba3019391abb6");
            result.Add("en-GB", "02324d3a4fdb6f2cde8858802d7ebba29ef711a31c4c206ee622080821abfeee8247b30f55f9a7b64ebaa5f676a65a73548a471cf84877b54a79907646a29e53");
            result.Add("en-US", "376087798b5d1c04a8b8a3830fad9d0dd2c37c52f00a6e48c1aba83e1b8d2ef002d3eb3bb9d494bad4f6afc330388008462c47f9b1430f17490c17b4f2b1a5cf");
            result.Add("en-ZA", "16665888ac4e7f6edc48a4dcfc4e2ca46a74ad655274aaf87642c7b7eeedec8044da6cb9fd1f66a9b627c515d296bd52986fc1e3001d2ff129442ff6b2f62299");
            result.Add("eo", "bdffa08a839578e6e791097ef1d4248a3a261aaee8182f9108a08d5ea4d77b971328f173dca7a02784d35a4f4ea797407086b2480b8570b0a4a7b1e9559f99e0");
            result.Add("es-AR", "d982be50f0b68222db55877d9e6125aa0c93df7077d31bdd502f8a80e4f89a35c0c849e5c0b8d5f20f583e401283398ba26b39c73679ad13ca158ab512c2a313");
            result.Add("es-CL", "47b6f1aef193735d6c81330ceba4bd6fab49eb0a15cb0d16aed39ccdb3c9724efcaad3ab5b23f06ba7c17f0d1b8bce7df893367f97fe43c6571ac2c730ce2318");
            result.Add("es-ES", "61a3d4a9f2106adf4a6cf458f12c00bef3e5cc931cc78892a3a75df2217ff7f4898590fbceed0306d04c1bdd62654e7fd1eb6b7124e33ffdd1306dfb93408d36");
            result.Add("es-MX", "5b72283a909c062560ede104f63275ac9a331a43b0f4819cf5b465a75147940312368e0d1639ca0ae935beccf64b3ec17338469eaa47c1529df0c54fd0e07782");
            result.Add("et", "8dab3184c2bd2c100e3694071763e924eec642dee12f70c79e6bdf78dfceec7ab0bd8c1f846b03a9acb4c3dcadbdbcb2be3b8526d6656d48b25182e282d4de07");
            result.Add("eu", "0f381a442110204f99c7fc953c5ddcc2fae7e6ed66303b905249c09301a05961f96d2dc59c0123fee0c5bdc7dbc59f78a487bc466ec08882dd82dee1129c072d");
            result.Add("fa", "1cd02bb633667c6decda154f447fd4abd05d42f796f4d08fa50e4a5ef9bf85f507c739ba537ef7d981c952f032c10857f539527857147d17914223b16fcae6b5");
            result.Add("ff", "3e69a3964ac60f04df61b0a5342732d401a782b4139987082dbb2c55d352ba13da2b3cf8f4cde6d0667968f557697381a2c8c43adf57c327caf977743c4c1e54");
            result.Add("fi", "12b7779e6584b16e2606ace3d9d875fdd7c78a9f27cd0e933d6c28661086d6e9b3f1ef2d692d1e90c54d2ce7b90f8080a275a791023afb98481616e9edae290e");
            result.Add("fr", "1555f300d6de713d42d2fde716cadb142d0052f24d2dbd0d1cff2143fdb0eabf9903e22bf9ae442eb53f7417d0231d25def01d26d32942bc7357dc7a0aa5dbca");
            result.Add("fy-NL", "d7c80444d7e80df9452d8f411816f62e68ced3d6926d36b17aa99e55a67136f74c2b9e60ff1ebc8082440125d48d629db4259338538f2469d32bdb5665643f7d");
            result.Add("ga-IE", "c6395f1e7fa4076ac2a211663f021d6f4a97cf243e02a3381c1d633c6fbaf5897a11bf9328c91357a171eb9321e5c323df10d6b627283fff7a29632ee2ee00d8");
            result.Add("gd", "464e7df0bbf2889ce9c9a5b3a0fc8e5ad725aba667a3490ef7500c16fc12f7768920816db3eb18b60871de73549b31f9e3456fe23caeb39012e2b63a5cf13a4f");
            result.Add("gl", "fc1eb3b0f92c3559208c86684972f6d826a8bf0301c5c206e70785d6e15fb3a0a717b35cf6a0eadd963df4f8ce3815c437aeaa228476d260c67768f91daf8d44");
            result.Add("gn", "68f8284e0bf0e883bbc16de1f69f54136dfa9356a8e13bae3cadb9e13e77a5cd3bb8733228ec2b34d50a5071d69a98d882b1b199ddf9c4f365ae457327ab80c3");
            result.Add("gu-IN", "ca0e8544574ec8950372f47f1cc9d6dae716fd4876270e95980ba701e4f4325921bbfc4cf573c845076d5414004f3801aee7fe26cb0418327310c7769480ac2b");
            result.Add("he", "987a5d7ce9c0f6da5d914263efbaad7990225082fd9393696a0ae01a6e0c871dbee93d6719f1ea401d982a896d14d5fbfaed2a859e45df7dd3c9aa8944086b03");
            result.Add("hi-IN", "72d594c13431336fc79295af81361209711dd37f0fd8989adec597fb9d1bbdaf3c04eaadf6460aad93ce272fee64a77827f31c7ec084c94581e8a6be962e1cb6");
            result.Add("hr", "638bf86062a138a8d47dfe956b0e9e98901a4525f503f76643742505af18923a86e0be36b45c49b817361dd2a5360340e3173d2b5e0e4a313d52e43acbddc078");
            result.Add("hsb", "4fd198188b2379a432ef7675d3f0e363f9fb8823fc1439f387ee2f270de8265a91ca026b0f9439ccc0732e6cc069bc16ac7325326c8559e3b82467473ba54601");
            result.Add("hu", "925f2515aeb0aa1d347d27808640786cc66cb8db663b2b1d3eb6e0ae1aca4175abd0fdc45f32c7ea8a0f61e3afab8b2dfda59b4fd849ad5d19d31954b836d101");
            result.Add("hy-AM", "a2ccc774d555e3f1561b821de81e0aafdc7c3b2305b345b714f344d85ab49a0a96acb3451f11881040b8235c17570771a2b1c5f67cb9b0e9cdc16b407c218a79");
            result.Add("id", "10730239b48b8772b61af10e5fdc88ada0c81b8fd1a011bf4971b2d9d64f7136d4c6cb33490e3925a7286afa565eb11edca34cf7c1e1d3735664e3340c66745f");
            result.Add("is", "d8d264ac976a17b70fb7c4c9ffe5e268b8719d2d722c06a537d49ea2f88ab9f04ec1d9d48a115d2763b8bb7e03300d9e11e5543953a3ca26e64df719906088b7");
            result.Add("it", "011889bf26e249bc66798a642ca4da6e4fe129981a5e8e9900823af18add4a5597e7ad7efba82ff29ad46961697200172a25787f84797f2de7b156c9db6fa808");
            result.Add("ja", "d466732b01712baf3b022de4db5f91418a35f368594bd8e80e1c1c8d2e6dc6b8b5130108fd8d8930fc53415202990d2fb32b94553e27b349929a033eb82f7946");
            result.Add("ka", "90cb38de8b59b7d206b80feff032cbecc1cb008db836e6a67ebffc3c080b1ca837776e6dad9c44a984b8782eb6163878fc0205072b2eeb9b432201a9a35b940f");
            result.Add("kab", "f30603d87562378464baf9e2a9a67e2acc93484e2d2af278e9c85bb425cd8befeab0f05f5587b5f8fe09c0c13506c15ef2544ccb43467b657569716139286661");
            result.Add("kk", "b57867e52160770346b8638707ed397f4364187c3fbfb835fe4a115ab88438d9be2e9725b4addd758b74a4a661431f525c98facb912265b9eec0898bb1590dd7");
            result.Add("km", "972d1ca69a3a97e582cc2b7e438b1741a7f0cdcc3b51220117bd34d45fb2d2a5046ffe636899fd4ce31e7620204618cf6fb28a6fe48f72a62f457f1dd44e43d9");
            result.Add("kn", "f87ae5ad54c01a01bcb18f76c29819ef3aff06ac3e2f8e29078e88509518633f7902c4e9cb6c2b6c6b2eb9b7d9143d9ac5863907c092535713b7b7cd6caebb71");
            result.Add("ko", "a6e19db03d531d5f2ef5b906a8a4928ac2c87ac9da78d13d43eeb594d54fc2b3868625c8da8fbab9d243eff0e9d260f1f3571a678007d2eaf50845383835a47e");
            result.Add("lij", "015fd7b2aca74671477940bbb71bcce07d10b0fa32d08e89b43319d8497163f4bf81fcca2314c1998b84184254fd81d500a48ccc8240ad5611db9cd57c7b795f");
            result.Add("lt", "b464a651057ea2cbf985c67442c92027682b5897cef3d5e37e487d23376194e77bc297c145ba7df361715be1fd53cc356a990a678dffc990c6fffe5655ff3f66");
            result.Add("lv", "1310f9d9ba0c4745e80377e9da602069d3d66f9db4f9c9773da9fcdac9636d22c3e8e94cf3c0e766f4ebc2e953a6439adc786ddfeaf89b23a9c28cb6ade0d9ba");
            result.Add("mai", "7c5318c107323bd53c44c4c6947dfb81abb024e9a009f346d9b02c9e1e5688af7cb21510b641df4d11f9566d9b9fc58a0b8e93da83e49a25f6649a9e97abe17f");
            result.Add("mk", "259cac9d1d37240aeebd3cfcbc639ffde7ddfa6eafb5fedb8abea6cd5009ffca31226285efd567f4ef45c98f67f8a5ecfead7d3e6c1744b59c99ad7e15522ed2");
            result.Add("ml", "1fd4076daebbd9e7ff93c40a8cb5e214dc65756da84409d082b556b35ee630983f074ed3f69e54b79b2dcdf497e70e947f04c97414b910f913d588ac38c6a5ae");
            result.Add("mr", "cc19f01d2ec7e6f99ca87194e60ff3ab78aa7c399ee0d743ff907902af476418b31bfc2b57674694a952596488703979ac0fc28b62bb799931332debadb9c618");
            result.Add("ms", "5ceec5cf63ddb9f38dcbff0d831f937dce4a29b356366167c288f93941df31a3f1bce04d1c58766cd5730cf6750629809dfb161a64b1343e647f6e7cbd3088c1");
            result.Add("nb-NO", "25467d082886d01ac5716680228ed76938d56da41ba613bdc680b09e54b7acc68d5bf71ec157dd25486de270ce68600f058ddb25cb1e1506a9eb32cb506681d2");
            result.Add("nl", "18786179527f7e651ec3a14d266758fb3eaba5199d3b2f3258322c96014c6eee658fe45de221e17149aed93586eed4638a0ba6d61c246524949da8e094d7e39f");
            result.Add("nn-NO", "4ab1199df267f666ec4866674f7e174a3ce8ee86e95a9e4383a730f9ca4a38a651193616236d1710ec9aaf5cd5348d645f05f635f22c11198f3a3df0b4935975");
            result.Add("or", "f5150a0d0f7bcc7cbb0d2a104c963301cb3f4632c54ff49a0f7e88fb4fbb6d9139ebb2dc20d45494221372c6e917f55543805ac613e1a82a6737ce61eb4fe71e");
            result.Add("pa-IN", "f194b524582ec1942a429ba57fd6c5dc72e7d20ae9681140047c8b2cadaf9aea1278ade05a78c68d32026a5ef49759c9a65087498c6974d4c5995cffc9968f46");
            result.Add("pl", "28452d9c86b12d1a3669a28b051fefbb24b2589fd72d26904d748002e6fb45fa935a2ceeb68374fc5acfb9a1b0e84ebc8e3effe97c00c632b27797435933d0de");
            result.Add("pt-BR", "5701e8af49c1df5367cd4019b8fc1372100b382eeda5f3d47a9e35c263e0451aa43d6004bab112793af842fb2478bfe70bc528cdfd09571c5926b7ff9d6cef82");
            result.Add("pt-PT", "b6a9e0974652f5878f2455fdc89c19c57355ca385dea1450f4959bc24c957ce5fae2e262839b6c7c7ee0ea4cd006a4b50c1b06ea4401b05ee875972057d33ce5");
            result.Add("rm", "951226e1a96369d90123e6d793cab09570af44a0c2721dccee8a594afc5d05e3a9fab02b47577028946b572e78ba2cec1c4b02a7eb99e6eae9608e885b2ddfcd");
            result.Add("ro", "342758644126047c37b8ad20aabe452b5979392430659af88f2eb7e503a4d328b596c1ad9c1af9b933ee72efd43fbc2650b1c844a1ffb5c2c26c41689b1d8f92");
            result.Add("ru", "f1914ec62e6b8ad328c31527fb2ad6c29eb190868b6c17c05beecd5ee2515013379fa96424ec8863ee84b83341367517a5730ae4f9839b76c0555230e2fcdda4");
            result.Add("si", "c3cb218ac23492426422389a7e071243dc29be77f03e38541895a5a9c4fd940f1ff8772b4ae48882539eb4b910b69bf8dbde3fd71821818a263f619c750ab50b");
            result.Add("sk", "f218d53d5de2d90fbc2f3477437f3d10cc4c0c30da112e47e88b5bf7acffe59522033b6004893dab8e519cb67d86ad1a4e7ee789ab6c5fe5a874e5931b6fff72");
            result.Add("sl", "543a3d5846c72926c332caa6110b06cb0f5562224f0d0f10b028d9dd71fa2c64c24eef5a8a1bd863f3aacad77b0f9b00e3bdbc0067aeaf5606ab158808eab6f5");
            result.Add("son", "0b330fdfc9e92a490b5ca508f1af22774976e5dfa6bbdd498080e1165ecaf43bb5f5af5e1d7bdafce12daf9f60faafac88a2b83dee000a59bb6e60757f9d553d");
            result.Add("sq", "7ddbd9724227dbcba43332c64331e123117c37430b7b4d6a393b4771b1eae8be34e73e1bf7f521fe1255f32cdfcf431d630f6e04bfa5775f83d48286ba9c78c9");
            result.Add("sr", "3096d4dc5a2defd65bf13b3171586cabbcaa66f754b60e53d42129c2174749c47f3d5b89eab4f152fe8e9b7fa710802734b56e2f0bfdad876422724f07fa3dbb");
            result.Add("sv-SE", "a6b00e92a9391247bd41d777636245f4f2d3ede7bbd9a5bf0e05328a77b295c37e615953ab11ac7ffb1a3cde73234f9c55ddd60b554f7e39c48d43bc46cf8f3f");
            result.Add("ta", "b7ae520d5c19e26546715b58ebae360a68d352f640c297110e607fe96677c579a2d72acf3a85b773e8161df673a4d25b866146e2db9203b4de669038f5e7368c");
            result.Add("te", "60cac406ac22e7c2025b63d0dc4c76d825046087393b6122eb07d5b6dbf0052d1b393be942aca860d79c352b5d6d2ad4d0e780a160f11f3612069c61cde9a6f2");
            result.Add("th", "75618ef2a3a92fb17132dec8366294dddd1186605ed52683dec3739d779f3917f269fbc8e312cc97d11a3bfd3a2072e34af0ed4882f04cf06670e44be8767329");
            result.Add("tr", "a66d5f4c7f44f066ab105a9bfe28ca8bafe51c6c6c570a948f205ee505a8bb1f9ad3b209b3810c142e2b1a9bbd97da6c841e92e1d5077d0f08159302043ef99f");
            result.Add("uk", "819c2369d2e8bf6cb8d2debc6ab7899511e98ea4be15cc3786b117446c162bd368a27e9a65fa0eaab83922cce2aca56cdc2880e91c23014e1bfc8e463d57d8e1");
            result.Add("uz", "0f8d6f218d7fee1361f9d01e05365988989ea969da1063837bf47f3c34c56a890f63ed035f819a014b6586502a307bbcdd44f4c7ab828130318dfdd0cfd99fe7");
            result.Add("vi", "09d4e4cde9bcf16b5e6303bacefebb5d34fac2624283593f62f56430e73640c3412f38019cf1a9313190e4a9a3439c0c104c7ba187653baf53ec542afe329f6c");
            result.Add("xh", "93a3616d74176190eb6e1889538c46f3a818e8756c6a2a8e1915194dbb4cf8a5a4646add5926b8540880f67df2934dcd40ab0f39bab50fb3f29e5550973dc8fc");

            return result;
        }


        /// <summary>
        /// gets an enumerable collection of valid language codes
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                "51.0.1",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                //32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/51.0.1/win32/" + languageCode + "/Firefox%20Setup%2051.0.1.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox"),
                //64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/51.0.1/win64/" + languageCode + "/Firefox%20Setup%2051.0.1.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    "-ms -ma",
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files (x86)\\Mozilla Firefox")
                    );
        }


        /// <summary>
        /// tries to find the newest version number of Firefox
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// tries to get the checksums of the newer version
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            //If versions match, we can return the current information.
            var currentInfo = info();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
                return null;
            //replace all stuff
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
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } //class
} //namespace
