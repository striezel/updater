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
        private const string currentVersion = "159.0b3";


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
            // https://ftp.mozilla.org/pub/devedition/releases/159.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b4e70b99894f09c94b2c2220b7910faa6ff846508b9139f91e028e7d4a8eea1b48808281621d1c6c92daf5753942c8e5259c5a9ca784edc35befbebf9ababcc6" },
                { "af", "880c8cb36957eafdbd04dc4c7e8f7252f9b9db4bc8fff986d3ae9da81643065e22807b0a9b8b2638a8a47cdf13cfbfff5f3f55310f7981c31258097fe6e34739" },
                { "an", "474088971efdadacc3583dd242c79dd715f35f03722e76b10ff2136a29b32de171c9cf80c1c7dca4b0ee1b2e573bb0269c128f47e424dd95948836ad28593bf1" },
                { "ar", "53bce683c63a2dce4306af36286ccbd93285a3380ce5caa990e7ad11e6dd01d51c2e590091833fdbbbbf30e5443b9d648542a4dddb2af1afdc18561aea93fc18" },
                { "ast", "0864105de64af607ebe7e1fa3d64ff2bb8ba0e24946f2639e7c2192bd2f71391cf7fd4061dc435a8924d3b1224f6fb452deb2c8d3f85cacffee3dc2cbd632cb2" },
                { "az", "06dffb4b516890c0d4759a64c19b27e1f87bd2e65f84bac1c671918089d4eab423d72eb1b821b7e4b6ea58654f2a1b82ad650adc4caea9fff568b7875dd419e2" },
                { "be", "6f6b6c659f709c7ea6c212f58207a7d6ae13067355bbe980667878b573a9c8f32ce29e0a866a94e671a9cdb7bbfcb6e7658c72756f2b3483fcce0604ba4811d6" },
                { "bg", "74bdac226ab075d85552727631b962b583448fe48d523e02818bcab773d44a16a25c58a61231085a19bd57da7246fff087a1a0f8f56490ab6f9d3a3e9b5117a4" },
                { "bn", "e6720d4ffa433057b0ff1450a43c998a714c454ced8b99553cd4e41870394e33072184f136a4fd22eea8a2289b14bc93fc29f5880a74af94e0bc1cdeea20a435" },
                { "br", "fe027c92f1f7bb5bbc23fde6eee440c00e9132e4210155963df6d90b2d8994fd8e8b29ac35208e5cb110b465033ee060a0b7c9e19441500121c6276f1892a365" },
                { "bs", "38bbbd5845d91676c92207ce20266362710baa5f5ed7d50039e02e6a16a22a4208f10880ec0161a9e909e6a3ffad145cf6b13981c6a49a51f5646aa32420b7b1" },
                { "ca", "8e6b85da2e5082e75ac0528a062c9371b865a0fc63d1a7d36f243d1485aabebf42763ceef88a316d3b87d8f3379da82ceffbd033108dca0863b1e127a7839a3d" },
                { "cak", "6283c59fa74b47006ec0b20769ad054267b5fa03b74944aa527cec8b609f46b041449f1f73c4e361335ffb897e263c8751cfe36d126d0181a8e720554e1ae9bb" },
                { "cs", "ce9feb232f675a0e326f4f1ded0a7f6f51ced183909c009573626297c48c94b3d6f0e25a007662a9b68b9a10fb9172d201523ac99d69b19b7cb7e0725eb1b766" },
                { "cy", "fadb0a4963f643a7d02c67215b27e8135393391b053d9e042e516df7675749a46386937337a879570b923c9ff0462e01cad3f957c128f5e27a2328a63f16a84f" },
                { "da", "e9974fe13aa0d01bcb561b9fe1638ca68a8c18b3466928f8f354433e1db7393a41dbdf16fbfdecd281079efa8cd090061e77eae6d653f1e3726d8fc3cde9a4f8" },
                { "de", "397e91cc8ff840cf8ef2c60be75ebfe5aefce760c96c373a537906f4660672bf70aed75ef7723ffdb0bdd0931bb24698727b9f02f3f1e8031267939ebb9e8ed3" },
                { "dsb", "c1fedc0d02b532982c676e7b4aab23b9ee332769f5b42566baa47c846aac5da6f87a7202c34d83d3c3b627d494e3ee4c82b85e9a698e4925b3d20899b4762812" },
                { "el", "01b3cc50b1688cbc158079caa81f00a03e9fe7b00029c7d21c554dd6e53d1db2ecfbf66b2d8d4406ad0472283cd75a0a5afbbf3bfa756af8d59990328834962f" },
                { "en-CA", "be401c3141c2e73be6b5eebb6e47c3bc1f0647b80579943e9b0d0d54fd3e97700af827e6cfd4e36474c69410a9df91a968f1e361b01be5be5fdf5a1031f35b43" },
                { "en-GB", "d0d8e8ff0de09499605ba47fd6b8807a56124641c3f37502d4adeb1b1eefb6fc0808664271665f7220e7a1d87c73b05b5189be700d4cd80b88fd90e282ec85e8" },
                { "en-US", "70cde4b21856fb0bb43e601f92a38f4f07589cb5d97ce7b63e83292f81f18d0c484d9ded0f783eeccd2aff4af54a4c052bc092a070fa21281ff2113469d42e9f" },
                { "eo", "092a211012cffb58fcee8104be8aa64f9f58a8b5cc7d6d8b5d8a07ecd5446386400fab6d57cd5eeecc8ace9a7433d00b8c80261df4d6c80c87cb347a8d36687c" },
                { "es-AR", "f484029940ba9a51af12e04c72ff76d9afa5c1ceba233e80261ac96d84a43ad4e22063683dbb5eb45bec1774dcfecd12d51135c41b51805ca5dfeb3a4b3a3a14" },
                { "es-CL", "fcd41d3e4becd042e5cce85c2052a39dd87878f1a9d509d89013744a3766cbbbca1714f774daf348cacb51c7683a16a0319126ec0b33d27ba3bbd40c2f02904c" },
                { "es-ES", "58dcd8f0550054e4b3919d56dc6c28765b7abe3b4aaccf8e2eb60b113a14c2d74ea7ff623dc53d6a9f51cbf4a7a5a1f77a652324b1405ad7473f004b956d306c" },
                { "es-MX", "25f1babf704952b499bd6d3c4bd7257608f6410b9659e08f7694233446752b9b598d2a84cea1782ece29abb341494575b6af577f0b7044a981354a4ccc21d1c9" },
                { "et", "d7cf45b85540d55953e11677e38822e0780fd94146f08879d7e07712b4a25f79a364f8cbdc8d9805347e4253b9e7f5bd1f8b840eea62dbd366c946d786512537" },
                { "eu", "37d3df80e0134984092c97d82e8f14bfc6a7246638b26732fe2f2988c6f4db9713f4c2fd04def2e80f60dda581a11b1d22626149f8295f9f19b583ec784480a6" },
                { "fa", "79914ec85d21110878b3be11b447f44eb3cd9e5ab18d4d5daa96a25f22b89c8cef686bb27fbf20e5eca7b2f2cd4c0d27d47b1b943fb0608d509a36fe624cfbf6" },
                { "ff", "826c928f5b573b3b56eebd305a20feff85d849ebeb32f229be43d68f8419dbd9a0b1be10a2576b00612d548f6cf72f899aeea7196f30e3ef82cc97f74fc4d748" },
                { "fi", "aeb9b242ed294d080b99fde5d67355b7bc04606a7f24a967c560b1cc34959dae24ab1a0f02aa8e056449046593974163991e9eee598815491de2db7580cccd30" },
                { "fr", "7cc40f68df7b0f23b91cca838dace58ecfa47be3b96d881ce06d727b5c01a9c4773f26a57d250ebf3ed6e890ee96a3c0ab9be5367e49dd008838a859d45e87d3" },
                { "fur", "843673ecfadbc9212d0d21771ef7efe41dd61dcc014cf1a9e056fc4dca939b766da5d90c4e6a3dbc5742745618c348a4a2356a85de94f90cf17d04c82067634d" },
                { "fy-NL", "3230092a78f876e6a5ded180e81a6268effe752d6d26257a9b9e846eddbc432519d7b5de660c13f0af0867ec9458e5a12a6494696c6d0c2145a36ef46f7d7c2b" },
                { "ga-IE", "100515e2f1c1593bd79ea5aa78b36e2d71c2200e6c582747c90c145e06e7167cab62ffc0609fe2d2ac83ea2f535e77680e009bdd67d6706c4414166430398775" },
                { "gd", "77b244990f9a54367e30a37347742a3b81c93896f541083362df81e3ca912d65c03b8c3c627f53d9db596c7e037d3d2bd0dd4ef3f287783038aceaf564a87d3b" },
                { "gl", "5392c04a2024133bc89d1b78d62372082e773a38de54b5f4e780f90bc24e6eac28a728ae7a2a865f8a464e7b132c0e9ae2b6ff9b9926abd7140339ccb248d149" },
                { "gn", "46681506d7597e7fb8efcfb243b9fa42a18f6434a950d7e177fd0c9d8aa1d4886b1a5459db62f7b200e656e08fe433d75cdb8278ec262fea3db9ffafdde22c95" },
                { "gu-IN", "26315d81b4d8e7295b029956e729a1e683eac8eaa1127d78fa69b4c62b02ed5abcefa8595935d20014a92dc6c8a02657d63fb5903d149a6cf35dca88c29a8c36" },
                { "he", "a9fff1b5a2d3c91e56804f8b553f4c1b5a19ac2b79497c7922ed4c553c0bc92af6f0dc13437c625822f0819ac1b52d6fe0c679008a4df9ddfa79aa3dad21f15b" },
                { "hi-IN", "10222a55854914d095d0c19495d84c7e41b6fbbcbace1db78665092e8379e5b9ccbd3ad87f2f47556279627d89c9e1cad6050c5a7ac43789448c10bd07b4e436" },
                { "hr", "ede74e21588ea668baf45ae538fd3ed7684bb17366a1f5b6f3c5cdebf1c6b5a5d6a60ba03d684ef895e65192b6e7214b4181180de7ca771104837f30984436b8" },
                { "hsb", "9b45c0d32d4ddc607895e7b64693b5267ffc143c2fb8bbfeb6fa009d828d67a5b8d59721423d7c33dceaaac638dad65ccbab96b45b408bc4a0720fe7520554d7" },
                { "hu", "7a9f22170f9cbc2f545bb60b0df827e6724c0e87490c47bf0eb16681f19414a28d2dcfca22a582927179251b0ecfb7002e1e1789b340f9c1e98dcd059a9c3ecb" },
                { "hy-AM", "870051ee05434303851796f81d88694853abf939e6fe5d637516c293b2209fdccfd449ca206c7f7250cf62ebb5f8d78a2bbd516206b9b3a8001c1e7a408277b5" },
                { "ia", "5fd5bfb98c9ee606f2e693c6b692a9e01a3257af596ce2850dfb7ac6384c60911aeb1d6e814e51575469b4c76831172244d0574e9bba8f258ac1036b4ba83654" },
                { "id", "852856c2f359c9dca44fe5f4728b6b5d6d5bc8671cfe879422e66255d46dfc09d95b3d4165e89650ef1fde677e9ba9a502f184dc90350cb5a8e70b288aa4fe45" },
                { "is", "c41839e110a792a810ad137f5a54ca4c439c20ef4f43856bfb5fe6aeb36219b36a37b04dc6675a25db9116f9b551ad64750975e906f27982006b00e392eb3535" },
                { "it", "4670d6cc1811d9c41e0c0ac2426356dd7a72e25542dc9d254565a9e5df336a66d1ca914d0fdd7e2b09c9369bc81a3ad862d7007d1045a98b1b388d8878e4f56f" },
                { "ja", "b9f10cd7f146fab6c132d1139d4951b8d81fc981bc19f8aa3e8ca4a51d941be17952a2256ba2c13b902e5367a8778888e58035000a657bca09baeced5c65db5a" },
                { "ka", "e2d33aa714c73de1f50c979b0404174ac8678bb090d8f34a1ab965d4fe9c759f801552f65623ba61cdaeab5fe300139a83fb8a28fb33f38a2f29b5ffc5846faa" },
                { "kab", "8de2fbad480a709dd27aaeddd6e58b6c766fe6f913761c41b959ef17670566a1eaa5a301263303dec2ed0017b833e00c2924da9aa3f5ced394b09f0ac2bc1886" },
                { "kk", "6af94ac9112394c354e2e3bec9f9a6fa15b67df33b9741963e6d6b1b35d6362e071276bcbab7dbc1d8ea05bef03e3eecea50211f6e292b20d464ae2248c44f3c" },
                { "km", "8e27578fdb668e132709acd79345b2ce838c3e4703a98f3fdf6c3493c023ad0b870f6e933a170af8b020d327a49f761566304e5770f59ca1e144b3d6ad93fe69" },
                { "kn", "ae60023bd43c652090276c24839192c81646d484f5cfa7f53b22b9fd3269d3e7e7d349964328faff798c9dc7b1038d87ee41a9ef022e949040088ac3095def84" },
                { "ko", "01b310012771ba75f86e88f3a214e0b13d59877f1486bcf50332e28b9acd5d3ee63193dd9d4f051e1993323759bcaa86475871e8bac75e2c86f0756289836012" },
                { "lij", "41a46919f07df835868ad1be9320ec93056a2c24629399368ba38ad9b7ce14a8a6e27c0322b55a983ef112960fad9020638555c1578f2c6f0f09bfe1cc72b764" },
                { "lt", "e4d1b9834a20a46f13e8cd7fb1a3326bf720cb89b01252fcff583692cc065cce587ee2a38c5443d0634a0302da4aefe19c85106e076e9ef658bfe2cfb67148f2" },
                { "lv", "526e3d7f4cb58e04f0b7fe5b2eac9ecf36fd9f841310a38ede1c34afc17429f07053f14378e683c9149ff77ba772ce05ae05d925d1ba01d04922ff35cca1d1b9" },
                { "mk", "6c14f04edc36da0fc58edc7210893ecebfa060bbe5ce73c423310cb80f5456b87a1c6eecf404852a866562f28e759f288159073f50194a22ea9ae9028155e8b6" },
                { "mr", "cdba912aee3ca37bbd3a760556bd1a044c3ec5601f317a41a41bca81db2f0d879aea08fbcd271f4152f817b2014bce07a5da2ae8ff589ff2e87dbe6a7203399c" },
                { "ms", "f36b858e1284a05da338b6a58594958bf10ebab6fe2432b3dd1cba5b48026b50bae68ae73e47bd47bbc9b391079c9847ee0b79e20875c75548158d49e1bf2dc0" },
                { "my", "1f818f45bb24b394b059427a3b3c0c77cf3d9060283d856d4bdffbd8ad5c80a36df575969dbafb88a11155731ce3a6a8b7240dc0aed8fd991eac02317f841d93" },
                { "nb-NO", "6c1994e5e59c1e3179581d000acfa38c3c8c320cb0fd6343e2535953440f6062dce8afed46adb9b10725e91d81016c34ba0ade6dfc11aa0d78d8e9e4308c03ac" },
                { "ne-NP", "da79ed490322fff8c34252745ca46eca73e901faa04742c7399fba89d9416804c5ce56bc39fe9a26573d734cdbb7a089d0442a13e5322f33eeccef9227929af4" },
                { "nl", "1ead64d31b231ed003597730f243d91d08a841b3a344845b78c16798f2e2d95b6db032550dd77116aa9b4683a8ff761e505ee2f57a6c050f831f6b355af14a5b" },
                { "nn-NO", "3e4a681701a487e05eae09501eadf462bb64d6ea7593413cf13127e40c401fd0a9de3215da12c4cab903557b4beea188e535a507e08016500f395639772e57e5" },
                { "oc", "baba9e39ab43b4de8eda9effbcf074edcff9d14d7376e348e19a6b59d1c4d8c20bfe342698e842985684b5cd260fd17b473d67d169c44a49861eeb03f35a3863" },
                { "pa-IN", "056ef943ece5242fa91cdd13c6bf2fbb488b678caeb7693e6ec1bc813efaeb881601593c35d7219a72aa770623249adef540da18caf383c3c8ebcb145c15b0a0" },
                { "pl", "0bae320ee579cb0a7ce2eff2dc0cbd9ae15b5fd8e06ec1b94a6de5c86d1f055e1fb2e73c0d403002cc1391d96e3384cd6bb24385426b21479de6c4a8b19e96e3" },
                { "pt-BR", "58582b2a6f2d4e64b022088dcafff4e7056bfdae5d34a840c021253bfe73b22d6e49e09d21c031cb6e4120b9f1a7964e91d4b56d65bb5d824fb7959504f974b2" },
                { "pt-PT", "ae139b78f5105b645c0e51236f1f5986ede72ec250299ecc4a5fa1804d1662deddedec9020f52177845bf890fca6cfe07ebc2388eca8cffb2b77b09cb78e3066" },
                { "rm", "d7024d5b35e639871db243611edf6926a02e3c6853acef1dd3af0a6db640b9d113312ee411283249a48037ad27d4b1524c9b0e5349856ff0c365dc1495935b7e" },
                { "ro", "44063c57c27109092c27fe38bf23e0ccb1da64ecc6a393177be41185839383166796a29b34e887bd0b01a10de812099093c21abd9c9c1b9f7d698b12a5f66129" },
                { "ru", "20bc70fa37438dc5e2075458c26536e84e1b01596a8d34bef6477047722740670e502418b93d55f0ce517b75e69131045283cddf127ff276d4abc1528218cd6f" },
                { "sat", "46843d29cd0b5408cced979dcde1800baea04f04b778348e3c6798c5b4b58b980c479db21d8dead7d6e5a8a97d3b5d78403284b5c0413dd7395edf554b5e6ab2" },
                { "sc", "ecd45b36c9618c1daf0fde5012e82f4c9b390b02a1975ff69bc8c7b3deed92f00e5d5b02d0acc51d38b3129301824fcc5ddfe355ae05c271a448816e8a5136ac" },
                { "sco", "3c3d4ed63958f9f71a13371a68646e007d73873cab3780e8c984dfa7138ca90faabe1019db61abdc3be8d9d2a2dc2f019f871a153e5aac33cf5f7df135d6caca" },
                { "si", "b07c77f5ae46833ead4395a402610d79c92a1029deb5da0393ef9a0447cca22a8cfdf2e15cec4e9ac32f8f4edbce8505963c2db34395b5867d7a2f46bd3a640f" },
                { "sk", "cdbe2150e824878176e52c60111820d43fbc330cf63db46a0fff34665369d8b36db3dbd68632244ef98a850c8979c6c6da5a4603a986f7c1195e12fcada8d23d" },
                { "skr", "b726ca7d800c2dc4708884ee88aa31d6fb3ffa1357c4070fcd2c8f849982aa7d7573a82d09c638b1a232f2e8cf9e33d0b6c8424fad5c33ac4e1950cf4e86548b" },
                { "sl", "40672a676d93be468962e35f84bd7220ae5f47575d981999467d0529653c8638d1d46c5b0d41a5622823d35eb844f123ac94698afeaab3ad5c2022f02ac3c853" },
                { "son", "a37d22b30505e2ac7b49e1bcb8f60962ea7d40cc4c0a01dc8188c09ed25ea2e95d0089cdee13524253e9c31037d87a0ef9b688b5a0553956e66d84ee72f4193e" },
                { "sq", "0b300a65ba0d5304a83013476a6069afd1d9aa5b53677aa1249b097d6cb9473873d5970f9e06253b267eadcdd8306bdae7a44078c9c3b61bdfe8d5988af08725" },
                { "sr", "917788c2354e56ac493bfee73aa50dec74fda22e423e71f48ba270458f51126ad73d104826a6f5de04d0df4536caad9ce678b7ee2aa86fbafd77360713e2ec74" },
                { "sv-SE", "0e84689e897f18f84df0713d295a2666effab1c8a02297fa34d627250fcc96decd925d76c106fe1b3a2033d42464a088eac1b035cf346a558ffe613cc2c5797e" },
                { "szl", "fb7b972a473ec8c1f2825d8d676b975a10ed5f0a3fd4b7235c4b18cf89abb6c03433fed0781c5abccdb383b9b0eda0308e05946b0b5e8dfb684f6b32f27724d8" },
                { "ta", "cbbea05c66b2cfc5ad87589e559db0db25bac2b738461075107acd8e9bb1c4e2d335066086374018300aafc3e2ba49e54cc8993a8931e95fd8a9cd289437a732" },
                { "te", "a785202bc9ec357a05b300feeb0dd9d92e4fdb9c707e6e34514a92aa1c7fa40b9dda3ba9f5d60c2c1a9ce60e9c6cd48f32e7853d200f1f86b09c8d7041808c0c" },
                { "tg", "585308ad6a5b63ebf5ab1eaf870e1d8be36ed17b90b17bfba47abdeabd18588f1cde8ee0ca300e4bc73754852c23323a42c03178c5079995795582797e5e37a9" },
                { "th", "34770a95cd915e6a90cdcd97e96636dd1708bc4c72aefb6360dbf4ca89db2c3f0133d3c2bf4f5145bd8d9c2610bb3b910e493f356bd1cdb725045e283f795d48" },
                { "tl", "2602a9120a1a2d6e5dfe6ecbbde8f49d3e6a636013bdcea7facaaa36cf776f5c95c1aa7b71b4ee7c5b168062ddac7b28f4b3d4c0e7bc08ce867426850e3dfe6e" },
                { "tr", "7dcdae9c68f038cb121fa3dc7183758e37732a945871b4fdb433b0a8299bfd83738d4dfa86c9226391b043a89d34852d20f79f08c0ef1fac42824c4665a6cf93" },
                { "trs", "f6295a230a88896475d1df04870dc6c5d305fc34d31f0fc0e5ab7595680c16fb831dabc853b250ed60704a52ae51bdd3eba8aab593a1aa1595171d8656efd68e" },
                { "uk", "31b303456a84f368bb4bf83eb8a2abae2b108e7bb58ad7dbb9fffdf86f50ef65d85a165703986dc551f214260fb4be903a385dc03a612c438171b30edc3883e2" },
                { "ur", "deef4b821f2887ecf1379c70554b0caad821777f8aba5c97ba05d065bd3411f43a2f578739068dfcca260ca56989d23c2bed58dba3629da0bc66b1b4886e5b95" },
                { "uz", "ba9318c92136eead5cf5226a1fe6c28afd770027757523b5d67aafdf2e45942e652e7fb9f096b7b955df1092bc846690ef611786c8cfa08505585667c1843809" },
                { "vi", "42580cb0c6007f7dc0c06a30ac1ce7ae22a6ff6c54cecbbc2395ef7309fd0618b3e7cd8a670a43ce92779bba42e2927ae6cf3e612cc1ee4eb17cd68fd80ac956" },
                { "xh", "e4984eaca24be616a9bee44cbe44f2640108a7e50b4bb317a47374866c52aaf9b912d37c0b97fc50f8d17e7cb791977c16f0c7fbfb1716301a50de961c6ab677" },
                { "zh-CN", "35c315d5cfc32722ac6688ae8b4298c738fada71cae0305f0868fbb24745547e9483ccca9b69959f724167bb4f5795e852b4620e879e4c243bc850063859a46a" },
                { "zh-TW", "aed5ae07eee37ee0d31e2dd3f58763dfe7706ea1124516f6f2b75d72e1d1f3ca31c5abd7703fe0f2983b3d2cd50e5e5720232aebc06c6d53a94e9ac0e39b8e47" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/159.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a948f630da7f696794fb8815206dbc7dc9a41158bcbc981c3b4608950fac2bb9d2f94f03771fb8ded130d1d72aa4eacf755c1ffcf848e2cf1c2b6e9cb50b381a" },
                { "af", "bac9851209c36848caa14c718b872bdd1eb49f6ce97b98edb9099c98f2c5844f6ece65542dee943ce57b79ea92003779c347a7a7661e20997e69d987a699b69c" },
                { "an", "7a413e3f1ea355b34321a8fd149b2603478a134544f7e7901262f43a8edc203f97bd292b812998814ddc72cde42178ee9461a2d6b9c4d7be5caaf25d4baaeb95" },
                { "ar", "ff0b34141a647282939e54d1423c8b9959eba6bcc51096d37ce372cf8c58612e7687675b173bac7e3cccb0fddeccc48a30657d8aee1263efeaf36d5c331e6bc4" },
                { "ast", "0aad38d74f0ac93f57d5783b8361b96656fb3c236dda42cc9e5e49c9b9936a151f79a3546ba2e0db5bcdf12476c5f161e8d7098bdb2ff0d64e6352796f410d78" },
                { "az", "d939656f95c3fee935e55bb6cac002b19c0b402580fa0e128b7427f9e402db10c1ec2d24295d3929e3ea7186074c5962b254066c471b8641ca46d8b59e136504" },
                { "be", "f58b310a361f2bf50e3cf1ac6502b195b9e3ed967f56aeedbe9d6d5d8e657467209d71fd697c2c11cc420393c7d178913639071a16a75051918a03a12e01cd7a" },
                { "bg", "b1b0bb8e25791de24b14d98ad6f998e2c4635e5e69bd41fb56db93ca1e6ec088866d1cecffaac6ff3e020a3e9fb3f42593ed3f9e97ef2c279b7140386fa2ba54" },
                { "bn", "b32e2af6f029ca1393c3dbc36c8699001a1f59721167402f14a19aa00b656ebb3a30122b68289abeb74f15c32b0b30818c18e38f8d357e683a85d431212cf10d" },
                { "br", "450008c9be5654c0db482ca48a41ef4f268a185fec9698fd7c635354097aa1a608521242a032e969c708feb3c7c88c74459d169c77c47b6d678c03531c46f70a" },
                { "bs", "88d24523baf6a5c1a45b062c17c18239da6f82913f23cff94fca71ac1224afab123f7a9f595870462fa6875b28f71942b46ddea29ab03f154b597e9c682eaf47" },
                { "ca", "100f0c941fe2fda26635d66b8700fe77eb886166b49c4d7802eab6f3021c6990397f01b2f9ed006c0221b61d553036f25c68769e6a782e1abe3e22238328cabb" },
                { "cak", "ad505be4bbd53f3272fae835485627461d30002c109aafd9e8824efc4cb282e7114b4be450ed55a52f73370ad3af75762e6bc9664024118e5c19a8efb3c45377" },
                { "cs", "c552edcd21bcf0bedf27fbdb200ff692599ef7326bfb9e29eca5f006afbb5d1c1688e7c198d2cd91f5803e640fde0b61ab8d57c348544ff7bbe2af60e2d3dcbe" },
                { "cy", "7a2dc421e9e6c7f9a6b80f06fbd1eeaa462ede0f58a1387855f1cac7c96123ac512b7c4de935e482109895a9363063cabcf2a76a3a60b599f6ce5d2d5f9a78a6" },
                { "da", "36e2cf50507ede9c905920df24a9b92ad881a3845526f0b1745faa8f522f1149309fef5e488e605abfbc5d21f272068d4e8409a7da1ed22123ff36139d364b1a" },
                { "de", "a6760587f0dbd81d55346bfb98dbc6778bebe9deb45568e8579e9f7b7075fa089fd8382dde5811afe53401d740bb1a680f61acd276991f6be18a3f3b16d3d823" },
                { "dsb", "288c002307e935d1382059069669c36142fc845976d7ac2cb2f3a224a01bfd0f1f28ab4f6872084e5b2c2e2a185fd0b469664939277129c8f33ec9ff68b7d7ac" },
                { "el", "a351035a6efd20a33b1ff6b6629f84b3516bd2cb6c7af9a54e32aeebe2ef5ae2aa32b6a9fdfc7af3c43046d4af9424c9f32d1a13ce1b68764ac6cb265a2c20a5" },
                { "en-CA", "e431510309d373b915de4b69f4dd4063f03bc997815cebc80c88856f9a9088b9dff844e2ba6959eb2fc42578418bd459e26cb5e25497d2d44724f423dd493832" },
                { "en-GB", "49991b363936cb57b5e68f6d01f5dcc1adf65c87b1c18fc83822d968ec9a2d878932fbb59a9f55c1ce7dbd2417fb390cc3195390f0a2c46cfc2c3e231661f412" },
                { "en-US", "816181315ec60aa7daecdf4389263c76ec5e78ec7001a5a5f02d23c2e1dda4d004610ed6ef387f557e2a6068ec44af023d8cc61728b9b098bc5ca4834b00e627" },
                { "eo", "d835b8ec4c6aa1e16c179e73205ee19f1a1875592cda4f8db9836be76945f11057bf1272d0921cd0ac501d31be027d2cf5d5d4aeadff9b6621265f9fc4b6daef" },
                { "es-AR", "3abfb5927c98f2a022b58f068f4574ee6cab31951978f2c1f5d935d02a331bd21bbf34fd3f68e3bf4ab17c696d1b141354b3f38ca258e0eb34fff3e24673e4df" },
                { "es-CL", "aea78bf8b27b422baf567d8ebfa0bbbf458b3af45471c29d173cbfc81cc76b82744af50e135fe17909f513b60e23615544f1cdf13e17a846dcc3a5be2a0a522c" },
                { "es-ES", "0e5605e7ec223ec529e5d549911cc41d877c548478486309f195d11cf7ed5aa56d830c39821b8c6385a766164618910412d447c065b619b7791cbdf4cbeed7d4" },
                { "es-MX", "4ec4cc830fb09cfd6fe8046d63a29fb834e897c1df7fb5f2a6b9a3c4e8df74cbb309263e1ecdbf009253e9614e0d80ee15964abf744346eb9d02bdc9f592baa7" },
                { "et", "58b19f37ee5a1248bbb12542cbfbee5fe7547341776037d1c57a74e05cceae15c8b10de22c5e1af8af59db9bc25104bc30fa67148d635275f0089f81d30b7370" },
                { "eu", "92b47fe0ea0e1da0bdac378c5346fcd31971a5d9689295b094bdb3bcb841407e9670676c7d1a1cedb315e09dada9e12effc08e974449573386464324bbe9afeb" },
                { "fa", "42c399a667332a3b960e3f0c916edaba90113baea7e7645a391c31e0b880e3612076599da10fc96097ccc0cafae9598cef37d0707c80bc1a0eee060511d24fec" },
                { "ff", "1d96dbf1eb113fa8bbc0b0af4678606e813969ef5fa6de53b2150665979cc507af4dedcced240c4bd79bb985873af4400ea89ecaca1ff9cc8cf87d03833a5b69" },
                { "fi", "2b931ccb752705b30584a926d5ea6237aa9edd188db0c307e1688d0065149a9e42abf5ad87f5c973ba889ddf6879b263137092e748ce437d84aa23ae21a73587" },
                { "fr", "4eb04b72ddf8484e1dade0a8d8746c5423322deba53fd6dccc821a95eda195ba581921f662e35b2bc003d9f2af8b3f1f86060317426a8fea907bdd5cacc1eee1" },
                { "fur", "9d30b8b4ca8d1e843d843624e16ef794f56aaf19f83d090efdbc7beeefece560c504732cdcf79402907dd5c079b6e3f39a940ae4bc599f3299fd5036560141e4" },
                { "fy-NL", "d632c3b6259b3c6689900e0a8cec86d388ad5501791b14c1c83a2e0020113fcc0bcd727f0b49760e0d3b1cd210be6fdfbd4fa64a47289c2e2a7d41958dd6e42d" },
                { "ga-IE", "f8c6c26deef514cb319a67ed0468cdaec9052d66881426599b5b5f79f3bb49d9a626c686d5d2bef4afcb093091c849685d04b587aef275dffbe1b0bc5f056de6" },
                { "gd", "ba9af28a25d3d46c3a9507513f9ff264eea6ef66a0c3960bf8ff172fed1a7fd5ecc03fda01f07995832dc89eb0a59a1945a29be79578ab83ba0c973318e4120e" },
                { "gl", "53625db4f2c73b291b931e59e800956fc09c37bbfd32b706e0947467d754d4ab9be70a3967e2213c4cbfde8abbef876969b69a3eec6cfda1d848e6d62fa8fa17" },
                { "gn", "2bffe9219f1c03d4372f2dd2b456c5170dea6aebfe97f5067c7a6b2130a6020c96cecd0d5fdb84e84fc258b3a16c8e96dcbe634c90d98879144921c09fa46092" },
                { "gu-IN", "1f65429b1a5a948ceec54a74bd98a8de0469eb3e6a99983cbc7b0cf2cfc6eb56e155797c7b84a9e8ecc4ad05ad2ab5658bb29087fd62ca152960b17bf65d63e1" },
                { "he", "1cb746697388b7984ebfc9605020872659b769bde5f30263a799d9d65c5c3ca4feab4344db6663a915175dcf408103c9f71d9013e589cfc297c35dc030351d9a" },
                { "hi-IN", "8b7a79cfcbc17db103f25db108d3327bb51f968c6ed73846f8e86a7029f238ab18c0c2351560f3888bdeac637d21c8d0d04d46801d8c5d69a7c85a5110a0a4ac" },
                { "hr", "f802989725574293b5877cf3b6fd91abcefe302db0f7dee4a44483385423cec7d3ffe649c5bb2ac656da67de875c245de303f2b4fa490243380bd4080323a8e3" },
                { "hsb", "6dca3a58d1daa88f24934a436cfd1daa7c0e548e2111c3250a86e6a6e074f005adf0b7baac922495eba6c9303c81dac276e859d5591a09c6d07cc19737657069" },
                { "hu", "c10c9b060dd8400d4649e0f56c136738fdf11d372ddfc72bf423cb2e9aa82f3a2d747b07c5e77ef7f9c38204240ac17350d81fc5f3b487df52c0bbe8831e459e" },
                { "hy-AM", "8ebc0a1c00952aff00715f101c1783cd46eec290f4bf25afdca28f9969d2e0a6a446cd0aad6d14e6ee1131b1fa1d4fcd94bc609c529db9704f05684f50d728f3" },
                { "ia", "6d48da6cc20805d5dab013d6c57f4251874f784893a745936a35b05e5da2f48ec8ccf9fbe858bc81d857d4f7ed61b1afa03cfd8ab0a3987fb99aa776282ece8f" },
                { "id", "d7a4093f7479991c9d544dc00f97100af13bfff397856fdee1205e75dc8c48c10e102d5717b346259ff67eacc8fc9c7d034b242ecc1db6404abb76eb9a127639" },
                { "is", "af750d9cdd0e64107490b5a1cf74022084860b698f6fd4b9607fccab0bd5c45773c25d5bbce24ae77ff4b8857c8573fade33c1d1b6936ef8699ef8499c79689b" },
                { "it", "4b5e9b4029dfeb99d4be22860434436c65ed6292a41142d19d68555114ee7cf78345e0045a7b899033b00261a90edcb9e68a6924172ef04e42f442560cc9cc87" },
                { "ja", "984ac2489211a797fe572df61c515a760c1f35ca63b906a0acd031f6e8ae6c0d8b6f2fe609ce372334076404f9a9b78d411295c302cc0a43c801bafeb050b8ee" },
                { "ka", "ac7669b70113e605b0e85d94e48ad85a5952e43c4633c42627eb2f2ff5b54b9d5a9a63099fc09972fa78b73a5316f4d345aac2604a393cbdccfcde781778c307" },
                { "kab", "2510f380c9bac894925381b02464c5b81ad6ab1152c93653845b4b529f1fdef8bc053cf9877878521c60c15f18f14450dbfb052bed7052a727f03570df188b12" },
                { "kk", "b9a36cda097d3377b4f0a5ddd953e1948abc95eab4fb760b27d131dd72906c8c296efbb5f788e9bab75679d7b2cc29b17549044ef288b95b20411c82a6d807b5" },
                { "km", "727fd6f3bea15a809fe6aa63dd6d87a9e175d4c49bccb4e95422d9a3efcb413ff2406cf9fbd95c2f5ef79ea8b78945bfbbda338b6aad9bf3cf6bd0c5d8caacbe" },
                { "kn", "db9e224d88d2ac76a7afcead09910407b89c5b1936223c7928f007ce9b72764bc6516e48237fe35c72e808f3ff6414606488392fe0cf3d2fde153c957aae92c9" },
                { "ko", "90887b7fede20cf6f3bbf92fe625b2dfab0839049615f6cc99d48d421278017d5b9c3437ad89e12243ad32beba61e6de31ea9f76e964d97b6666b506db3d4c11" },
                { "lij", "b440ed7964b50896ac6ce071a768de5d3498af4d4f66cb35a445eafd7396a076665cc93a03863cebfe7283d478da943b38e0d6cd8230ad593efcff98025fa042" },
                { "lt", "ee635cc7b5c56315e2f2ca49b4f0d76f62fd0cbedb5b351fb99be2f709df7af46584fa35ca644fa10b5041f66d9cf716d17f4150529210b4aec09f23b406aa81" },
                { "lv", "1c371b2187e1aaab3a55253fb1a1934682e921650aeb63842a6e222d90be5acb1ad31d08a84dc574e151bc73683ca7b3cc54693b31fc6a46435f8e7249a21b08" },
                { "mk", "d8b8630d6edc5a55a27ed494ff89a1c8afb511f3ed1f027805ac1087221bde1ca25d4ea7a5de756258ddc12bea05852f15233b8885f41580f5b85b6771fc0422" },
                { "mr", "2cc8e92139f951701de37337142c4ee51ac884dfe0aab402665665278dc2eb0224c90ebf4df8e353a59677ec85e066e18ce2b6ba3b885644281676c8c3ddd8bf" },
                { "ms", "83c56af486ae4a7f769907d334c740ad9c5b45ad85f2f825947c0774b9a108606d97d737e09ad9809f38daf71aaa96ef896854a18cf0c3e11cb38022d466ef0c" },
                { "my", "671d3f42a762c2e85ba00a5919f95b20b5792dc46e4686bf4c7f82d9c3f57cce38cd51e18263653632fb2078acd9c7f300c0b9da8b4c638ecb97d6e4b0a34b4e" },
                { "nb-NO", "bfdc079c38ab2543f8856f9db59b7b47c7afd8838e6170a34e88e21980b6639d60acb7c0802f069d1083e9e70eb24a807783e3aef7f9b5894e1e39f3bc4bf738" },
                { "ne-NP", "45fd6364c2c6ca5c54936c60c62a57258778858503db7daea9ab5d7adfff878e3aa15edcead98e8ec423efe66799d27ccb2b2649a1003d5ee87eae086ef5a01e" },
                { "nl", "41b9c185346a26e811bf84236f9e81de43d08bb433329bbb3d6f77314a68c52057b7bf0b9428fd7159fbeb21f9808d20f4372c960fc5ce2c3777b7b2c0ea1d26" },
                { "nn-NO", "e078e01b9ee207bca58ecad269e1c96961d7aa4943c11050d4da57f981efe01c4a5c384737bdec87f198f43f7d94b32dac29bd14ca3c26c5ca3936948f4cfefd" },
                { "oc", "4e54dd4488e4aa67916038c1daa151b463af5ae24ad5ca6aa096e50b55ed8ed66b75492292462281b3424bde0a1fa952fefa4bfe1bdc9467230dc1a26c272af8" },
                { "pa-IN", "74cd223adaac2fc4f13733db3846c1d5764534ecf67d37f6c852a9e2a67dfaab7966cae44be59395cfe7533610615d775c344a63eef6793429890d18367762e5" },
                { "pl", "26cb8417ac7807215ec97dac5e4903f4e944fae6880063412fd134ae92d991f432385d585220c7aa099259291e1cd0b2d7f843779409492ce44d08fb004dac95" },
                { "pt-BR", "bfd2950809531177656856e5680f4b54ce9228e08f5f53d5ebee100fe8429ebe49e538000221bf70feb14d13360bfc633b7d5ff323b40c6965b76ce51a7a8e04" },
                { "pt-PT", "b151c84a6a7389a7280accd12cddb57035ac0f71cbf8797d513350eaae5da6468aced3fe1d84c9b638ef55f6e03d06d70b70110d930e058db9574e2c744ee3ab" },
                { "rm", "5873f2b4ef475b8b9092c4b1665bec5581389674f15a6aef9fdf5215224cc24b2db0d9b7097455b999ff549954c81293205b51104dd807d19034e965837b0cb8" },
                { "ro", "0fcd069a38d8a0afa163aa997b1aed6624bfd669a7d1267b15cae15999666ff4657282435a617fcefc1fc993688cb660298cd3cd7e791fbd031a81b516bd5ee2" },
                { "ru", "cafd9832d633ec927b2ab54a33afd46983916c7caee0ddce4cf4f0e121abf6895752dd1d210db14a8da90afeefe16270ee61723c9a345692a7c0426420c803fd" },
                { "sat", "303ceb29ab866bd61a30c1ad8a3bcd158d4a16e0cf9421eecd3fd7ff3b31f90477d4fe9473264b680055cde00a33c3196188122b15b66700c016152ca2d205e7" },
                { "sc", "f9b68cff7eedf32f26bddd869ab527e4011ee852d8c909a45cc7722894d5ea6aa92008ee6f4c0aea1009a11987e3a800abf1fb95fb485f346d8c3dc8f1fec0c3" },
                { "sco", "2534df0369f5cc512a400f0deb56f2d75b5380f81c3dbbc5c9ef5c26601fc4672359ddf2f7e6d7dd4dd920c8fbca6ba5ad071a16635baeefd227386ccbbf5d6e" },
                { "si", "abbda4c37d71caa73824f53148dbee1cb91590559384d86e19e8f0dbaeaa77306460106eff8aa942ca8e6f5c381e0f9a5c5e0438f2c7621fe8ef92b2aba8f803" },
                { "sk", "5710c11aec42e341590fa7a4df83a2e2641a48e95a3a02e78ce91330f5df77f804f6b9d50233c6c7ee8ccf91635a4988442060692e92d01c01465a97e68162e0" },
                { "skr", "1cc26eaeed8d2a656e6bbd909f4b4736546857691e2638314ee11048d1048f5ffd7b9e21ac082c2a4c910a6f28452e65805763b1d580db3241ae67cc164e5abf" },
                { "sl", "7a550c0147c18eb355644bd88652bb4a05872e6b7ed8018a20649a970ab30d516f7f94abd5025b8ac5c79d99e294484fe7b34d7b0a3a9118915b2810917800b2" },
                { "son", "816358c154b716006cad42e4b898f8375011758645cbf6beaaf7b6f29057b5ffb547fe78bf04645a7de0406841c812db01c47a09c0c44f4bf28036c7933d23c0" },
                { "sq", "18ad8f4f90e0d1121b7d1a64a5a801b1990bdd25c035a3c09ea090f99c727cacea2018a6ffce02d2a2fd4a4ebd1b7104c39db76a3a5e3881a9311e1a5e82e9b2" },
                { "sr", "7659344463fbec6abc99c7cf80f1917b2e23e1472e9c637befa01723a61c30baecaa816dcea0467adbaa95f556f4589aebed731a2ec51bf4438d0c8b7bbcdfda" },
                { "sv-SE", "e82ba32490a52ecbd48c592af2ba91d7774bd655f0c35852a64b39d56ce5e9f45051c7e4f90cb1909e784a8f8c0ce2fa8f07b0f1735a1a65bc41d52780766f9e" },
                { "szl", "4366c75b9772e44dcc05ac9f680651bccd4a1c0b44e778621b47f7993796e34583af9a6baa33c8ed6701a373cb71fa985188fdab97cb3e3aaa7938f64fd64dea" },
                { "ta", "01d4bde25d957b987fdb7ed148a55a1be4c8b204cd5688ad7d2c8c9d6bfd00abdecaec126b7c495c306e7f90b71045df45c1b2d2fc4c9c726d5ddc12c7efcac8" },
                { "te", "5217368061f0aa2f5efb057dfe81e0c34bbb53e7f7de94a6c2d91c83a2ca47eb63984bef606d25d1500945c24308a7096bfbcfd2642a61d1d36b047e03e87dc8" },
                { "tg", "635c576e7f3aeae7a04968f08fcaf0dab96df316c62f4150f88a8601153acd87de8660bd2ade638f5ca7b1e46b5d0fb1d5d87ba88527c4ddfc8151ffe791b92f" },
                { "th", "27ab0a0fde185e4861b7616f6d2dd0ba240678374a02a02404fb2067c371937530014ff1712f01d7a0de406a6e87ea2a2a437057ecda8a8d55d9f0eae082ab77" },
                { "tl", "08fa3fef69fb6bad9ece98498ae052f334363be6c8c43894bed4777f0457dd3840a11a7ffc16e9e1af3ed642c601cabdbbd4f1f0a0b81cf1c78882daeb25986e" },
                { "tr", "c975f618c49565147c80702af3a7807a59f23e6ced54c8131c46edab369519cdf2aec9a86b2ee5dd5c6de68563f7c092f9b05a06c329227ed31bac28f6acb6e1" },
                { "trs", "c6417bd2d6d705f47b08892a842e9282ef193f81f32f27c183ea456063772fd8dea2576d59167ee5078b10be33ab46d94228813d7cab42da331303fee2590880" },
                { "uk", "0f1c5127e148a3091e2b3c4e3332748c789bc6b490de0230780d938f9852b99418146a38e1354c4bd0581670feee56c6e455b358e6bd42b7e9520aff98b4dbdf" },
                { "ur", "1a11718028124aee235409a24c81a3b3d2d0036f2b3a84d833855f064ed5946f3eabfcc1411a6f6ef1392b2e00d459de5c85b4341dc7a709ae441a405a732a4f" },
                { "uz", "9642278dc9e861a8a0e64dea6b12c98d845b6561e6fa601e6d62aa81aed165aaade0dedbbebde787d3266cb294ca873d404aa95f538f6e031d649f62420e7895" },
                { "vi", "19142d7ad2ee5d5b5c288faa9fb46a8add2df890cdc1d44e56e552b49393c914c7cfb0a4f153fa587e0349548784b5795df12963788f39b0139f5a6d97d102d1" },
                { "xh", "52e9ddf8c45fe86f650112d983992e51b5f3175c65ef35afffc6d24e11cbfebb6d4402ae3e341e10f5a9c5cf0b02fabff4c82066c876c7ce4f9fbfc1d67608a0" },
                { "zh-CN", "871f56aadcd2af9f85c12e83b958ba993bb8454f987ba3a6dbf93069599fa5952a26f17b1274fdc7d5c421a3fe992b186d3a957096afafb8bb480caf2ef8feca" },
                { "zh-TW", "d442c6f6040fbb80adc3a329060b22f9caa239432af5e4211080cff43963bc75ee0e8d89a398babf915a578eaba9d7d69853ae19fec38bdb6155ee83f26242d6" }
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
