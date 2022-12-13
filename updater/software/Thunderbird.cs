/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.6.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "41c0c9d3578b12e23df63d0e676cf7d91ae64e467564b204fdebdfa406770419e32610714be61f877e1cd5ca215babf406b3f667afb7eed04a86b5e73a5c8f4d" },
                { "ar", "a82e47357a348815487e141be969fde49f4805b739317cbce534aa41ce49a539b2ed2f7397012886843d702c341ea38fee395f09c6d8c5c89d435576e7ccc662" },
                { "ast", "a1fedde771809479ba1043c15f00118f06e7f218b0704f043494f8d749362fda22f8bd6fdb04715f65d59f80717eaaa889511732ee738c7b597a20e67af6fb2c" },
                { "be", "dea34ff998b772d0ad054c0761d56ffd8e58714a9ad64e266fdebfcaa5d754c9513b70594b6dd1b11e9ed9d86d42c807eaa268e51bb20fc48349aecd7f413996" },
                { "bg", "3fe24fe43769a4060cd7fea5e252a28c2c6eabf5beae2ee570058928f01f3c721c84900cdcb1f817b7a60434e08f6e14009a70ae5699d67adb3a3467dabf7d27" },
                { "br", "3f59c66350b5adf922d94d6b1979804fd5f5441935893a9f4f13a8793a6a883d7dc48c5e99a1622e562aee753baac4ca0d6c3d822a9166c66ee13e1f404e5c5a" },
                { "ca", "ba2b352bd90e2df9df6d7d9fca6fef8105d94495d5f1a2661e23ea799dc350b727b8829d214c030603fea0722511970cf7edd35190a70928aa18c848968087a2" },
                { "cak", "b8d5f81f145b1953cb7df4b888713844f4d05a807020ab15ff2208790b4e304c6185d1ea0ae9e49d325883cc7c8e922ab6532cb79e7b9f1dd4ba6a21cef87d12" },
                { "cs", "a63935bd885dfc32cda70f11b9dba88eb9988a819bb5e77ce11283b718ee4ed8db15dd81a9b2bcc4f6ffd0e9044796f89ab8ab521fadf96cc6a04e0f86c180e9" },
                { "cy", "b49645a138bc0aac71c815b99ff350a265fa4269c54f3a84835030458a01db59e99a944b505cfd3beb810b41c7ca8a4148d229a882113a552f27d863e56dccc3" },
                { "da", "750a698e9c900553d4a32518a42367767c42244f6664c76b60ffc961c2b3e14039b39329d759485eda13eea4f2e92b06e02398f4aac16e9c120d3406a9d79801" },
                { "de", "40c1c7572633ecc8dc348c11c3c811ac426c41067ec4b569121d078ed6e53d5fe535465f598fdac354552a2cb4cb9bf9b9237b6924632ccb4c77bda06c7c77c3" },
                { "dsb", "33fc061550c24d6b15e236cb76d894b198c041c1ec12df08faf2ee6fb8a50a96b0cc113f7dc4fe4a9fbc3e1a1e4beac7350710391671b1607e9840b6fe0c5326" },
                { "el", "54168861262150d58e0244136df44eade4749f3f3fb9a5be0de410e9249cb06fbcec84da99f609628966118da7edb27ad5131c8654fe927f2c50994b1a6e8648" },
                { "en-CA", "32a48383cfc3eb4f927c86162c5a6d666c6978a16c8dff0eff77bd84b24e23e6cf6c5666559dfa9805c4a6bc535ec2c97c1adb35ab64c680724fd429f00babfb" },
                { "en-GB", "2b9d0a9fb21eb3cc2326a9df52556ccf7b4578015d0143731c0e139dab280bd4164383cc08e5149f863672996a81aba4b590229fc821cf966154c64c1c047056" },
                { "en-US", "50fd1494f17c81e9c68fc42f7b24a7c6471d426aba2fd31c5a3edf8ecba118c51d0d09b1d253c4bd9b7a44128a26135513d9801e70eeb041c8704152164d37db" },
                { "es-AR", "43ad540401d295a5c0b7eb72741c5a6e4ca37fff1c971d2d21c9c608f391b2d1ce1db449dafe90d721f1e6ef4a71685d31786f20a835f9200058ce8961ebc801" },
                { "es-ES", "69720293ff85922a546a7eb2e09cf8f4dea6a6c32705990d47ac0776b243a347921130c21c85b2550274033973e2834474f1bc8bf999cf2995270f32d52a8a3a" },
                { "es-MX", "ca711397443d6b0f4d14bbcd661b4b6798fe1cbe2b5a3a6c42be84ff2229e3fc1da60a4f089aa8251ee9746252d5f37b788a96b3e5e7fc9a7415c21fcf6b7e51" },
                { "et", "2710f58bf99448a42cbd81ba1c9e2a6c23743cad3ca77725db33845023aeaf3914c9c33c87ec1504eb58d9fa71e305f0bf314a58a9b74adf914472b64778dce4" },
                { "eu", "efeb161c1e331a51aa3b027bab5b704844f57d94d2abebd7cd0ef2b31e11cc1878f2688dc427871f95e92a0453f78e3dfe267314e6f89ecb3ff2a63baa1481ce" },
                { "fi", "2886af56e9c2760a913e179e39e80e0287a65da4fc33a3d19b80533b9197b5d00f6f4328b014cf92bc8e9809ddf8a3c0552418c6043ab48053d3156b226d88c6" },
                { "fr", "31c94344e3d84523abe63158174e0554f4a08a50f278b832b72cfdccff2f167eae13205e9925c692df5ddb90339ef98e3f9e5c0d94c38ca54478c9a6096faf2d" },
                { "fy-NL", "6cd83818ea1f899bf9fc9530da0bb850c4766133b0d31fa21e1494704100cbe8a4d2bcae3d8a7da6f5b1226484cbc2aaef799aadfd5fa51f30cca00db63ff49e" },
                { "ga-IE", "e6d5d55aecb032808771f106f5668c972cf8a5eaa1bf7e1eea2e011b2061e5a4f2d679a6253f7ed60c627d0afe28e3efba3eda6700caf4e0b689ba8fbd3e0a21" },
                { "gd", "3f1352cac58cedf42b421d2baace68680e6e9c03cd303d8a80800d4c59ba128548ab08f2c0db34886c79af7524f9d03e90b8dfa91c04412abf41ac9c01cdcac7" },
                { "gl", "21a4bf040fc4c457644eef5eb517e4ee512eca3896bafb87dbd8d8917df24b07e17904d9cb30c16dba42163b5220ae38ef010c0bce987aba0676033455cc1432" },
                { "he", "a60fa5f02cb8c6d5b810f7d8b0f736104b761054554058f877b0fac8360f264d666312e61960395662cf444b50cc70e652ad0f55a49a7916ae3fd2ccba7f6998" },
                { "hr", "a43d52f3ada6b95d85f2d47a77c67c90c051c149b07ed3dda0a6ae6feaa4c9cfecab597054eb73e0f3cc55a7a603b4479043f40b54f1757a09a6ea61d049fd5c" },
                { "hsb", "fbc43a53b118d1264b07c40043807ad1bb024009ce08fe517f6d58872e63e5e175d6a9694eda25077eeb3abe3f8d93bac31048af5496c66c46b3848f387f763b" },
                { "hu", "487ac69ce3f184a8a7445eb218e66a00761d1ced84186c7da70d4c30e2f6051c37013017e841d09d4bfc6da5cb6a94bf43de14ccd9ebc3bf8437983b212c54da" },
                { "hy-AM", "db5a0eddcc895286e6a2c4ce4285a4b77a22a0ddff930745a2767e0f1a979971c61e04292a73a6cf590a5845f763a4adfbc4bce4ed35063b7146d82d9571afd2" },
                { "id", "60a69181c8b305477f5de9f0984069a5788d38f25fd73c90b0fa5973cb28964da6eb3ba3d540f6c85bbcc3726e9a4c1a40e94264b3693a5f85bce916baa33122" },
                { "is", "0443bc7b0ade090b2ee4ac2c47d6bb39fdc9e5fb5b9c5f373076fc8501a5a09f597e97c3a19300952432ea2a210fc0b7b67fcaa3fc6fa55374b29feb1dc7d017" },
                { "it", "a166f87981f8c247b089d475da38c7952dbe1c34930d18a2d91897496c22ded46ac00de7d4de8f3a16ce32e5246ef82cc0015be74cff88263f05872b4286c41b" },
                { "ja", "945c7137c4bc20194a7c7a594e2fb4ff21a94b5310ef21689e36b54491e7baeb1f0c3bc41edc6bac2116ee404350c0b0e3395ce44244a294c1f81441ff77647b" },
                { "ka", "ba0a905335e9be4fe8bd92cf8b43e72e91fd1ce9d5b9381e0403d828c21cb01e822b0558794bac5babab17a53618ac7f478fc0a2043e325b3b2f7b911672b20e" },
                { "kab", "8d1db77d8b98e0b121a7a1d7b2f9dc261f01509c691bb66036f0fdac7c7f269824120c65d9c8da7a1408c8172124308379d75a2901e7a256225ccfd73682d939" },
                { "kk", "13f1a87f780f2fd47291359489a2cac0b22adaf61c505afa4101ba97dac623ccfefaf0d66e1665c04e7e47d6167fc494c26d8fdd61da24adc16e8b84256ae4b8" },
                { "ko", "15510bd385e1b09212797c61ad76f5e127689e8b98c585114e9ce7236df2347439258e11cd5e0c98860a0416ae0a89b0e1cfb50b3f31e532a3a83ffd4765d369" },
                { "lt", "eff14bf00f07fdfa62ecbf3f30bde0593c243f4c29f60d3093dda7d9e82909d993f406b77e322d7bd069f228f3598e4fb4e9e9a4278b90f5ab69848124e624d8" },
                { "lv", "540354e2520aa2cba7bd9e6d20d95898d8927f3ae06137afd2d5cd1d3043a97b07f892dab96996c3699ee767fa29d3e1de80d7d99ec1ce978cf2540fb07a5a96" },
                { "ms", "d03aa0edf946f1ef35ec537d8b9c0a8bab45b928d90d922dc105f82a5a0b4ed7e0aa365a6fc5fed8412eb7bcbaa37a1593513e07b8b5e218baea5ac9be7dcacc" },
                { "nb-NO", "5ec183ea41f77a22fe7e560f1caa6f74b03e6e4074fb5c972a4901001eabe0d7c7fc8e329fb0839eb8137f90940a2e0a00bd3017a18fd3ce3f288bd649fe0c89" },
                { "nl", "d7c62494a85c6f2494755df22d93e3b9e09b310d861f81a385e84c9cbda8d0564e34296091a5ff11d68d7cd0119c226feb1610d065adc2f4e173f96264ccfd38" },
                { "nn-NO", "95b5c5a68881be63e5847cf48e990385d39bdfd877b4ec51605aaee03d18b0104493b6a689453625e643d46314f67521a4a7d2eb002348393843c14d90bd95ee" },
                { "pa-IN", "1b3eb75669850e2866137fc7174d1372302f855055ec3cedc0e82b6bd5e9f06c33bff16e02881f718894c4936044698428f82821a1326d5c1e85ad3f06125dab" },
                { "pl", "fb99396dfcdff40b9c4dfeb4c91b87bc8e13a765d9daf2a1346e72618d57e69d5fe0bb0924c1572bcb3c27659a4f2342504cafb0cab5aebfae0a0e893e071c66" },
                { "pt-BR", "49a24035842fad807bcb239bfae4fdc547578ba02aa0be95e5e8cc5656ecdb70ad4d3374fc5232d5feee0b6f1d34f9205643cebdfc4a42ae8791ac0714c567e5" },
                { "pt-PT", "f20272607f2956eab8553570d382ffdf92ad0f2b2334892cdf9fd86c309c4f8cb229abc2d8775b79e77019fe21cf9178a51492971d8f444ba5ff03d2f73ef4f4" },
                { "rm", "d1bb1afcf365a80b6f25e9690b1b0d204d36c293f91ec404ff6ecb5b202034dc94dfb3f8ba8f6e80b455cea2b8f3a3d75a5d99f5f8da3e6d8e4f3c50005ff527" },
                { "ro", "2d02dcb7c5748cf3a7ecfd727fc3463c043d5401f1cc1b7f4ccd67fcd8b1d4343e9cce7b1f0bf3aa9bb59c3a6abb227e3475c9948b3dd38db0cfbe97129e6781" },
                { "ru", "3fed0abc5b669484cf2765dd68ec05bb306549f7b7db6f7f22bd79fb81a7cc4765458d389d0a915108621ad4f7a4e69390ea2e37dc28fb53c32751e2fa175b86" },
                { "sk", "6b73b2659c5bd3563eaadbbcc1855b1c824ea4c4a3d12107eb90ee78b21ebe093a0436a746d1e75458197459334d72a9c1569305395fa8fc7ca40473817019b0" },
                { "sl", "78d845f218840e5e7b3f69c11afb6d9e1bc074f033a47cfbba92abb6fa85a5464e8350751d7690961ffc935393b4d407a3aca9f781c0665bdc93e67376dcfd32" },
                { "sq", "5f45b5eb72ae058b1efb2e9c9d43fd632d66bd353c48034573232e42e6f77434591e26ee5f06fc82f584ec9b63fac92be9e3ee9b71eb724ef09121d89e56233c" },
                { "sr", "bcae82164b9e04e9a1fb6cb26156a98660e8fca31d1148660ebe0fd4f3458d13e85a724102a95d614250588a92da549f497df392e47128c0af165a2c6addfcd9" },
                { "sv-SE", "543f99b7546c1b0f9c80cb8df5c25fb9500defba5fe4a3b9b99212dee8fcb40716a728751a9dad165aae182c6ad472db3c913af99ef5e15138b34cca9f818855" },
                { "th", "af8eb988767be3889ef91c4eb3cf607b4189fde04d8e3b933defc9ed06269e6c7c61d6c1de8c275aaecc1ecef4b2d48bde1a7e8daa3ad1b5678f892aa9b88c18" },
                { "tr", "c1e8d607cb410cb2563bf01173c65834a84f7ad7723509cfe71e660be318f6d7bff3f6780ad36d553f535c345da57eb5a3644666d82822d13582d98bacc48e14" },
                { "uk", "dab2e32b3d942e42370d49d05659e356de1178b7ce49ebb1ac359fa8a080036841064637c79521755fe4f202e929a9caab500cc578ea5abf9acc3d72ee69bc03" },
                { "uz", "b7c02dd72fceab95fe10f4beb992907598e2eb5efec789c29936e8c3970eed70d9d33009dad46887b723101bc65b7df0a7545c32f401bdd597ffd8b3e86076b6" },
                { "vi", "855840a0050dc8984050e1b70156bda80d167c3c65ab2c81afeccea875905b5ec899e1d8605856f2c56c55bb7b3637a6d43e0e14865c766918d6c934e74a3cdf" },
                { "zh-CN", "2a83f564aef1974148423e0d25d35ae7a497851d4688715b644d8dbff357bfc21a612e2de233f7dad40d2a98d7c09f56227ddb18365a440bd467adc0a7d81d42" },
                { "zh-TW", "667be0a37122a158a20c6dbc3892ba6b78a437abdebcb9bcf28516be51e5f6eb78d40d87d0c73a4af6b3c749b396ac17e175ed2dda3fd9a4d8a934a6c34e61c0" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.6.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "984cffaa5d3b3d93841eb7e9fc8cef4489068d7ed2bcbf6766fc01c1c4651b58c334bb9ec0f8e67a80d0b4f3725996e6b3430c2cab8d6e5dac073423c3287e06" },
                { "ar", "a80ed73a026872c2a6086ddbea81f98e43f6615280f0e9c6082ab2b3645578a61f59ebb43e36a528bfdc474bb95a34933f86817c942360b5965a4b8573efb110" },
                { "ast", "b46e5e044a046992705e77136b9f9193ec643ed0f0aa0588e870362787a6d6a032a360776f47012ca2373633ac93fecffafc96d449013d659857238df833c342" },
                { "be", "73540ff7941542b5e5dd9a8d6f5aa8a68af976d40416992419f567ad70926880d60f837ca6834ddbbcebebacc1b7a5a48dabe69d36f1ec7c061da501ad3caf57" },
                { "bg", "5260f13608179082551edad93498d4752ccc3bedfd6cd89e7db9ec561bbae0acc7dbe4566c51037678fe3541c9afa1a2a7f70306871a0d7e947efd0ca7c08072" },
                { "br", "a5daf91ec5a212ab72dd11daf6424c975252c594979d5f8fc640464935791b96970ede757120becf3cec93e59893023c10d063b2f94ee09d4d0c2c44af2d0b30" },
                { "ca", "7867f6300659d9ad76ab227e4e593f78f59e935a7871d4a2995fe86cc4f734bdefa424d60f81c7d7c29e4671142247ada6cd350336f2079f8330292ceb1d8ce0" },
                { "cak", "eef3217046815f8ff5d3f1a63e19010ba66c08332ed7dce0deb99581ed708a4c93d7a92e6422047e11736a5830139499a18908bbc96f6a272eafede62370e49e" },
                { "cs", "d4e1c18b4865cdb8324e02555c27a0a8256f8235feb6b01f0feacd1d467028d05694266c745040aa44322fe129c002f15e7e8bc8b91e668fe7895bf995b875ca" },
                { "cy", "3213eb04e191361107e0f6b1971375ac8954f974d80b0759aeae2b56a700ca85a12371673b0f3b28e724d7ccf13251b9e083716d5142b2dd45e3a0ed4c085e6a" },
                { "da", "1d5ef3cec942e3bddc6f37ea3c765e2703f6803d979a879f937d9ab6de48fb76c1173b574caa60ceca3788d8290b7d2719a97f7248b9eee2a15afab5de8353f4" },
                { "de", "eddcc747ea910d91df245bb00bcd36a1a597596f39619a2f22af77a52a9a7d420b4f04bb9d7a277829557fd1e19ee38bc59d14c468d3268f10dbcc436e1bbc46" },
                { "dsb", "90e724cc94578ad3b6509446a47963980570ce957f1a4484dabd096eb169342c89306f2ebdec62522226ed6108966a97db94985870115ddfb943ab816ed8b1d9" },
                { "el", "b999580ee73d4144f5a086370f34e89598e866f709bbeb9fc758a12b46bdae296af8996d24750ea6641635e20d1856d206a726d8b4e231b41ba5b018edf05f91" },
                { "en-CA", "e27b7157e61682e4d904b979fc997c21aff38d35cc9c4dde1d7ffb65819c80dced8489c4643735487c0a66d570e971d3f025ca6465070be155a963c88b2608ec" },
                { "en-GB", "217b93b9a1e800d1f9f736f42b30b73034be73261aaefccc11817717dfdea837e87cc5e9eee1dae3d82140f2400ada2002b44d37ac82bd2fc4656a7b369f756c" },
                { "en-US", "1988eb8626ea0479897d2fb684a6da244f8276380a4cb0cd17fab9b63c44a8ade2cf5fbbe39a6dc4d3e0d4256ebc4420841e05e5636bd8e557d367188bac7ce0" },
                { "es-AR", "d3ae8369d26289c541953e6460c96b7358b95c8f8b7fa4d7d7ad61e215a6eed231064d168c5233f4d6fd1ae66312a38611b5419dbd3825e44e9c7db0b45c4df5" },
                { "es-ES", "99b659fb10a07046941f000e9d4f40a0e8f268daf02da9a682444d0c16fdacd3d3e9f97452e6582738073a781ae3ac15f3fd80ce40d5543138cc64244362fb04" },
                { "es-MX", "e43559c843e161c3f4abdb11679334845629a1aa5010008df438c013cdf9688ee54c49cdefdd1bb0cf73b61c55a193b7f63773a3ad759da4650d3b50502b7f35" },
                { "et", "7addf4a1b2864e2d600e9f881fd5136ab14daf9f89cd33a6675b4e459fc0add52b3020fa44d1e8577c131518494846c20e78e5eae3b2c1f2bba880a6d4316314" },
                { "eu", "40ca07fb0d302c82eead9b7901d7ce2eb09f2a140bcd6d775a81de96983c6d3df750d5088703ed1e8c63b7f0f0e086bc679047f437456e07458b9404071e2259" },
                { "fi", "e4a13fe66987f7163a344e723efa76076b11645f09cf021986759e063ce21cd5cb3ea5af1a9566c097b9b6ece74b7de11fc6e4eef378c7cb52c1b87254f8c6a0" },
                { "fr", "27be454dbb08ef64d61afe74a771bc889bcaa3e7ea48b04caa9525b237413d1d68984cf5b34b829fae6b693e4f165057f0d67700036daa947b2af9b81f4ae2eb" },
                { "fy-NL", "f9d644a0b089a7ff31d1bc7c447e27323be605d7d101340a5b6b53294cdbb02a0354f5ea9874a9e256321c692b7d83bba484c8e6a524ad91b743a305aac1af01" },
                { "ga-IE", "ff9a41275f3819b90fdd61c024e6e609ba1299b05fe1fcead79eb2a37053c03f23d2cada09bf7f3583510dcd1509ca44fdde5e71d0d2c0905c8c402c6a1663d8" },
                { "gd", "ee48530b3ae43536e75ce6c3497306a070a805a4693084188f53ec4e8163f301a41b175e6933f8b30d828620c839b1ac80635f97e041e859437e1e090501ca09" },
                { "gl", "54357413537324f0929a48d1fe3eefedabf30de5af7599c0702d4d443353e41d8a24403b3855a0972de7269fcc45cb92bc027b6c94ad1311dc9460b1617dca3f" },
                { "he", "ba28b88227f40a9e1e395a13c103a348b8302404c1694edad229ce198c729c974a05bef845889b47c1fafea3802db209cdcaf2a604c5cfc4154b0cbbc2d804d3" },
                { "hr", "690cf0e1e64977ccfea39cb4764dc38658cf24ec2f8a3509a3412f59984b2ee45953923937148bb1addd382237680671d91956f65375f90d137be434bcbb0b42" },
                { "hsb", "70de841b94d520321f6c146a2b41caccc3739275fb53eeb0c648fa3c5bb104b15669ad6716740bce68c40237412acdb48b05d8a03de61c975f3c5e960488ad2a" },
                { "hu", "b14470889a97d958f91b06e89fed1163699bcfff905889b564237ecb4fbdb28bc912e5004b652fc39e3f67cd90e362d64009ca64682d94a074a6137f6b11ae24" },
                { "hy-AM", "f63abd37d7c0a448768f3de5ed8d33785d334a8a52d191c33c1292d1bfa961ca1f34910bd485b520fcc3833e1b01309283668527816db3d2e8dd136153178208" },
                { "id", "3518f8c7bfcd0228c9fdf4fc2af2135e7eaedfed9acd5907d41cda5a39bff3dad876233b9b0f7386522754afd96776216a847196ce8d5f7924f33067fdeb93fe" },
                { "is", "ffe598750a2a468b92811ba1083f4acb89336f53caeef83935042e28a64d646a5eb50a0f68b9d389f39bad65a727072a267ec0725455ac0f1bb3fafbacbd1570" },
                { "it", "2520d3f8af8cbbe3c0184223d79c916ab99a65ee47ec45b788d06685272f35b1e6f149f9f67cc92a647df38a23fba205d73b042ec8d391ec71a40625f63888a2" },
                { "ja", "4bbc0b441eb4e76e5908bbc2f5ec3cacbd215934b9029e7b7b2b97e05c5b648c4c6b529b9def080bf285eeff4121bd86f2cbd6d4f14007230ca11e97b6973080" },
                { "ka", "b818a33c5301661706066a10fb4e9e180a7f9b8942bc5d4cdf8bbc4457d7338b7c34a50638d0005fa3da805b825708e49d6accf3c9e3de09e1843936c3fa89cf" },
                { "kab", "ac956f6c9bbc6e619ca8d387300233973798d91ff06889e9c061795f6e5f905c409f2f8d7b5f816a2f04c4d3ba1a90cd6eba3bc0ca842dafafc6385d5a58628f" },
                { "kk", "f4947ad02d95514e31434d970eb088699a7a81fe91be0cd1310da0bab819c3ade152266028fe0c21f3ae15f4ced9d3b6ee63cf0e2d16c6ebc53aa83600884a25" },
                { "ko", "d7c084627d250f4ec92f8fb3d43dbceb595f6c2c58ff7ffacf10b97bb9226f6ec8f5d2795462733f6f4921fdb0b3aa393b262d1835d5f1f209cb0ede5ed8af6a" },
                { "lt", "675118ca4fd982c755f1021b1b2bffa92f8e03625fe01e23b50c0a5f1e709a8a1cd4a8c03ffe8e2d92a34fc30037a5ffdabb556303f0e022102236083a9705b5" },
                { "lv", "a5a866871e9a1d48e777e446c356fb739bb80e1f35aa54c410625814e74df8c4e4342f69f577e96617dc50bd0b18b2ae01665c48aa9c7ea93cd005e1f8deafce" },
                { "ms", "2dcbec786c1d1aabd93a96e7080526e09b1d50267780aa1801aef898023136a53324bec36c5e023613c8bc3d766af3b702a7900dd67dbc6d58f67cf2069d3bd4" },
                { "nb-NO", "7ddc0dfb6551b35c8cbe9cf45049813c02c607b550737a699f627bbcfa3dd68e2ab66c1f22e06cd18c6c8ab7102e49645b8c7cea47588514d1c019a6f12e8283" },
                { "nl", "4ee64b480685ebac716ee543820ba931f344bec19218729df1398df48ef31284cc10e1b6f7059c59b28cc0a9dc8fa6a32edcae3ea60e584e5610975b3db93b17" },
                { "nn-NO", "594174d98cb2c9cc98899a36e9925e2b7697576b182819e1984c36d5e79477bbecad88e43a146d5e206c2470ef2198e11b980f0ea0e71394aff9c4fd1178d2d5" },
                { "pa-IN", "7007ffbad7c6ed45ce07016aac858daccd343ef72dc2e7cc5fe84060d504f7f3e3c630a1a1189b59c9394d90f18cc4d4a87a166eaa18f04c7430f9b54bee2f8d" },
                { "pl", "34921a06fdf177f6f66c75805fa6b4e2c98720def0df4915a332e13c882f716e94f6f0effdef44315cbcb20cfc5e4cd429677d6a1ee51f024b80cd08a264178f" },
                { "pt-BR", "5cd6dc9cb23935ee662317d4863c5c1f37cf0ebd511970ed1cbbef88759442bb326918b9e0af1068d2db43733bce342139aa0a686a23f7b0eebf8f5775f8b2fb" },
                { "pt-PT", "486ceb637ac9925a846f64051d22f7216c82cccdf0de4ba87bf95f3e7e42f46b338f964a9560fbf6e9f78599117840d5f5c35d3ff2b334b9e4d5b04e2c5af34c" },
                { "rm", "ebec6a0ac3287d78decfc9ef13bae140ae03904b6579e9f2efe9db7bc3b0dbb6e7090a5bc1273ee0722f44c4c82dbdb3e5b8c1a87a5c8c8f0f5e141b8c5b0779" },
                { "ro", "1c04ce79f86fa93406ecb4438ba1d5388594f369787c884a0ca69c50b73e133e945126b6a853b602ab5c3b978027d7536b5ec61f7ab8b8502bd2b70c63baad00" },
                { "ru", "e4b8daa43f095d82877dad514260b3e477455505cd3e7ef0a662da8b6a1a3670a3a913e42e6e3851e8bfb3acc8fa8ea129db4e65864d004b2e8ceacb8c3fda11" },
                { "sk", "0ce5d97ce4aa17b341d7b68a058a7f775cc8d032d8a8a63131fc5988d1cf378d497122fae23a09b6e5492883bc8000ff8e5d99ec0ce9ccc06370a69708a6ac88" },
                { "sl", "3c2df0f49ce60734ddfd9809fb68030ffc93d4eb5e38c425b65ad462bf32f32bb5ee2ffb20d19222978d0714aa22e63539ddd1cddd3984cd09d000d3a6210e3e" },
                { "sq", "7a53b277b664c7fb8f3e7e8b8d3429d90818fabac898fe3ebecd903f31f7f491cfa33deb958537bcd40e4752e91e56ea133e83137bbeb7fcd6ea37878182becf" },
                { "sr", "a078093ad445bf61fb406c5eca5578d7ed4dfbfd3e6a5bb7a8164b35593b0a4e11cf6d4fda40f225a46e3f73b1ec100f33c860277ed231a8e910e06a3731b2e1" },
                { "sv-SE", "c471a17731ac05f8fd49915bd7402ef2cd1240f2a13461b9b83ebd86d1e01b58a99b02c49f4724be231c965962918965c7a848608d5f6357c49a21234ac6e104" },
                { "th", "d7ba722a548f9e5db5639166313333aba11c03b2f9c30d35dbbf83d6cc0c8b3634c38ee412126274c37dcc95fb30f4931535d58da5862a3f205b6d3fa59c29e2" },
                { "tr", "8cee440543a9f268339571d56eacfdc76e6f96a42a27b159ff41170ed653fd2daa63e8414bf0d27ca041dc7ed441d714a4d42446818de9a71d1f06ea81b3696c" },
                { "uk", "400df98488640ac9c545194d2557a427cfa9220d4d0b5a986ed7348fa2498abfb663622300ff0f5618719437eb07f91fd0fd83220c3b3044ffad57439b1a0b9b" },
                { "uz", "19b571d7bd6447fb48d71053a1afa94cfa609d26871554348951811ea93a19315f65648a29b9513bdd9dcd7c0778b26ac65544360e32502135407200ed532dea" },
                { "vi", "c9a3cf10e4ce42264b9ac74ef8bd415e3f967520927321fe506af77047521e0b570c62d57e1ec2d9ea49326d8374575aeba02dad3ab2409d261cefd98eae9bc0" },
                { "zh-CN", "f97b41d219d86d05ea2f770c7af5f8c0661a5f53aad256efaedf78aae2dcd2ae5e45076d2dab205c72dc2ca324b800baea4676d6c926db2fe2a3f9bb49549a03" },
                { "zh-TW", "87409544c292fa593c4ef70a1150a2d6f834fdb4cf317cb831259ba42e2f170b6f716d288b92a6765092412117c2d8dd5c69770304de25451fa1976bd2e95723" }
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
            const string version = "102.6.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
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
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
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
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
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
        /// Indicates whether or not the method searchForNewer() is implemented.
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
        /// Determines whether or not a separate process must be run before the update.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
