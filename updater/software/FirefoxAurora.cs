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
        private const string currentVersion = "154.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8f2bd3164cac6d09a1299cb4e15e900b261759be3db44b5612b4919d4938bb1e11e972a8d252f26851fa0c44b821f3c1797a7cc6bc16ce013b7a5eec53059411" },
                { "af", "94be2d6e2b64c86c848853a3db445d10a8bb80cbeeecdbf75ea23d7b8b5ded77da9539ed264e676c0c6b5cf9be099bc1af232b9b019f4d576111e59b5c715688" },
                { "an", "f7cc4787813b0b9724463114e3863526172a077829b72f280738757c091977791826b1a1e0198bf20af6dbea0702ead627a8266f548269816014eb9534d1b8a9" },
                { "ar", "80be5129e216124005fff8f7768b72badd360afc923bbd972f587625ffec1fb817ed5240877f034b62e2bb105d1c4b88622d9ee76ace092efbc9db8bb5a61677" },
                { "ast", "fc7dc7c49396eb5256d8562a7c57e5de70cb92e30db0fe7b28d5478872932516b04dfb1fdc07e9413af894340018473958f6f3b704a5d9e5e89230c83533993f" },
                { "az", "5c59767b248ebfcf2c5c7022cdcf20f94ddf1043dfe6a53b48b8437ea00b61f5efab2cda43f472bdbaa091d050188730c36986c2294c67db276e011b8dc2527c" },
                { "be", "1ef43fecc646c777a113569af5b14ab017b670689f0ca7254b6f780c2a03a116274dc6988121c5f5b44ad6018464e8c61ca8d83f5ab3020b8f1a1d250d7e7172" },
                { "bg", "d9050d992e03635a62ee52586f113cdde6e4fe3924bf1b03af932c1dfafae8cb92fd36ee265c8eff862325aa36b506d5128222a8469d0e5a19d0f40446d055ee" },
                { "bn", "09d1bfae5e352f38cf8fd1b5d0623244051ffd7a5818173826edd65f3a28982ee93bf6a4243ef99ec7a5f2a6b4ff9cbaded808c30eb744eec7b7feb4cd92b600" },
                { "br", "e41618d518d578b802c371de6544d5555850a6bcf448afe6d9e215e8470a1b4130a8f6d4c697f1a1c277af8bb164b14742bda233f2e02b847ee5025094d17533" },
                { "bs", "f4f6301763b3dcdc78572d40140fc3a8e8551f511183026749e2624268c7bc621cec1ab4317e6254e4f452a971e2c12f537bca969648ec77fbb1904f7579a510" },
                { "ca", "4b438f67fe22fb1c565d2bbe43285e1e2ba6b11c9cec3afb4a8a3bfd1118b082898d7ff374674d615eb980841749f0ff8c35d6715f52b43c4b2bf46025ff3227" },
                { "cak", "8bf85eb2efcc5b18b01f88490273e939ff1acce2d6a96ada444bafb7e3869d11bc3aa73d94749f4aeb8df9a1c0f64301d2bc15b4b9f961bb24841564c5c0b6fe" },
                { "cs", "f654ffe6a3fc850eb38b988acd7e89c6d13bc0a2a03ecc8f1d2ac231389e04a600c1712bde8c861f7011e8bdd5e3e5b11d54a5de49b77040aa3e600e82363845" },
                { "cy", "bedaed0b8a482cf5561bf8a91ce2c1e7a86b41aba485820df32d117102637c6ad42817d51b2f1ad8ac809bb72aeedfe4567644fc88b071633cb9a5a93237391e" },
                { "da", "565ec994629bd0f7787cf40bf32ff8e5de6f3b02757b5f3860ba5f39342c98a44cc7479ed64f42251a5a8e53d1cac0055207b4a1f6b976cf783a93c4aea59957" },
                { "de", "36aa6a8b5109406f66898571f7a98d9db46fbbd837a7f0f0c25edbab7e3c784a929b04fdfd662110361d86f4ad68aeb58bc6242bdbb311e95f3790d4a88af47c" },
                { "dsb", "a9727a7cce38de556564283819d3dca85fb8d71883e1cee33ebe36021cf07382f86f6f692c958e1a25a22bdb0a2fb2e5d63e9f3039ac3868dbac93e636da3806" },
                { "el", "01646b6d9150075322b00b261856761c48cc7ee8acff9a233cfac4ef01e8b1205af9e317b389b22ec2067c93724a17edc2d5b9816488f02ce8a93a574afa19b0" },
                { "en-CA", "e27d69a3484f0fd0e8169ecb7fbcaaa03321c0450c344db594637281a7a44a6d7ff4acaf7bdc76a942c37888f7cc696e4136a53dda7e4ff6f35b5d8dcf92c8db" },
                { "en-GB", "e78e5e92adf0ad1eb7575c84805a8a7a82dcab77f2760ca681c168fdd46049934a802fd852f99537b96e00bc91793947bbf413c6f091128c1ad733015939dee8" },
                { "en-US", "2e7bb27686f8931ccf38f2b06006cf51d545e05398fd180a6e506dc2c40f1f08f0768ea336fcba00f69dfb5caf0ca22fc82d3b9283991b9d363dfed07bf27dad" },
                { "eo", "76437675f706d8b069ad8b85b9418e3d056217753efbf1ce0d03eca8b40c9d926afebf840b882c5c33991818d1970447ce134337293d21f86e414c2d6ca15448" },
                { "es-AR", "a2e427ee160d93b6aa85b1fdc02a9ec02cee04dc851a0e6748030e0ac6e6495ef4d770365a3129c68d71d25ed0ade3b9ea8aaa1719307d3a6177ff23bf6f5aa5" },
                { "es-CL", "4b7128d795e244309d1906b55e6489458572862e688a6e61c7240ee002971e4924a30c574b80743f17d3d9958d1412cc084fc3a6a384e312e963e64e7c1af30e" },
                { "es-ES", "cf1cc5637bdf1d807a0173d4ac5aef37cfc9f3af55346bb830a54eaa1315bcba45bdff11e1107a49cdaa258565b68def732fcc6106c4ea16c9c68edb39652f88" },
                { "es-MX", "c4629d7741b7901d53aaa3a31d563906084e0439d0ca9bc02997a38362dda7137bc5ee9270def9b7d87ae2006e308ae3def347d3c841d31b3445873cc973d293" },
                { "et", "5579381599cad27825a2eb7ea6b10b2f4209e616b1562788e8ce56ef639b69da0ca457513178381ab7acd1c2a1ac1960f37d5b7b0f8de6bfcf5d23ca5816da68" },
                { "eu", "6e73560f90a5cabcb5b034715d491202b77b57b81a2a7ff7b13e3c1c352683486377939c2a1f506ffb40611235d321a150f4943fbb1392d06771bd9105bb7b1b" },
                { "fa", "b4af851803fac968200faa6273c720c3c249ab20297ffdd6a17f151b7ad9e2fe7f2d50aad1b4de7debd1bc996d653744e8e91db341ea83d95edb5fcb456e2d98" },
                { "ff", "f521691d19c346bea5c97b050308e0ac71d98eb08b368bfe34349e5ef270b888b8497e31af5263d3c99cb6d85d3da5707d79132da8b856f9e36d2ec9332b55bb" },
                { "fi", "405f9781082257aacb1d3f9ddb2d3bad4c86949fda3fea9bd607bc2745f37bd75b858563f957917f0a1a80cc5ba4f14cda9969a4ee229becea5b147faa105810" },
                { "fr", "b5cbf0b275ff6c3a84b89a146714690e7d0f0aba9499ce60b03e1404aedf74a3d73e52474129c8ddb7bf14995305ca8ecab81663ceda096b2ea01ab64a48a0e4" },
                { "fur", "f2de110f0dcb90c322d5f582e10bed186f44f5a166224e4e38d75756edf4c1df160a962d2b83808864a0f01932f67295dd9d53a25d6350ac5976a86083733af8" },
                { "fy-NL", "78e701791cf03e22463654888765aacdf23e07a23249d168c4c22a1c9bf8405a3d864c93e75e5702c7da3de01fa9ff51c8e5603f648fe00a74e712fd2795dba7" },
                { "ga-IE", "40cc4945fbb80865174ba66cc259864795e4415fe4655aa4acdfa1ba280871f4b9a0980c2a9a6566ac809ea6ef7eb3b54efa0f11245953263c4f00c0818bc4d2" },
                { "gd", "cfbbadbfedbcec2c7b98622f10c9aa7a3514205c54232abc916980a86dce6822c171abffe359640705af406ea3eaec3af9bf44a9b999a148cc8c7751eaa94919" },
                { "gl", "443b2572122ca3ca8ce29cb6bcea4d94625a7e6901f5dcc0ec98953d146ab6844f24325f13905620f5cdfd3f0968e24b2ca03e423beed08210032c7d052317b4" },
                { "gn", "18b8f2eb6c8c8ea56a4dc5d15095df5ee334556e40877ba357616419ed6a63413ad972595a8dbaa10c20d4faa4aa5dcca579bc0300476d344f8062a42d8b47c1" },
                { "gu-IN", "a892123c6773faa87714572576d5f00f79bc16d32e1362d1a3754295a8721d0425f78afffe771f8ddcf2012b8cf2c0c03ac9c1a96ca898932b9dacdd30d75dff" },
                { "he", "8c9e68c89c4ac7b424859733e82ebeba660baf9ec30eb9e9adfa493a444623cf9b206fabf3aba81aa2893dd73ca3501f616a0d0edc1b7b5afd031d7d6401b035" },
                { "hi-IN", "2198246a84a6255c57a0132ed989ad7889f45973c9d9d6bf335395024e7431d4aa1053dde9617c73cd7d891934c934f9e58fd59e08ff925dbf34962669e481ff" },
                { "hr", "615fa0265c30eb0ad8e27e0e4b1a95b15fd9694bb52b9128f8be17b16b282d879ba7457cd4474321bb83a14d1461c89aaa06000e4bcc3a304b7ce5b80f8ba8c5" },
                { "hsb", "46f55031fedb30c9c23b50f43ab6cd230b208cc4a05b3c1ec7f3ba96c10e8e20eefdee3e820855230e7e4ada383eb5cf4e4e3fe87616c8fa5e7d1e47251b917c" },
                { "hu", "a7de04ca850578960b60f8b563d908fa972464388b74fdec6b69e691b502b804ca2b34237064ac413a52ed581ec59e1d33367cbe76fcb6582bb73bdfdb14610e" },
                { "hy-AM", "5d83777bc8ab381bf278e1c34838e65effbca2ca0dd5df3ff7e198b0641848214ea24cbd8d6f302a30b68faee7c030c79bdc1722e0e7a8351867bafe9a78d7ca" },
                { "ia", "e12b9e982ece026a1a980f42a57450c52cf43f1bc4b99ef6f65d9696eae857004a73d19ebba77978fc346cda0d491a100e67efb547b17f0d56aa3f22445b2f59" },
                { "id", "cbb3f02e666629e315a5bf9a25068e51997b2d61f535d09149dd56e9dd0b3e6d2183625fc1813a1c7cd76324339e878a2638ecbd6fe041650309971e47974ffc" },
                { "is", "6f9f9029cda14925bd7f8a32aad23f83d4e96e6921545c8a6b18dcdd73917e4015c90177e690d475c43e5fa0fdbd2ae87d436ce35767ea78eedd2c7e81e04fe6" },
                { "it", "48dfe5f1cd94378e34f8f00b9c674fa5a5b08b52382aef3660541b4eb96acedd66fe0bae5e028bf70ab1acd5101b3500982f10489fe073af4defa20f3f2893d4" },
                { "ja", "54fddc6719542920e47b460102705b03f9750a48377c4318b783856236833ebb9d2e4fbca0b01796c34704394ad466eda2117c57fe682cfa90fd6c27a94e45f8" },
                { "ka", "5dceb92bcc85aa3c7c15dab32790d6f54608b8f07bca5abcdcad3dd72eaf9c6643327bbfa257e441b6d801979982f46220ef9137cbf076e824404584feee5b02" },
                { "kab", "bd0ca672b58f055fea580883a15d77a53eb1de3dcc0fe7e4b14ba0aacf940f0274abb16aec58dd23b1c23d3797c58a54d531ed5149bab1637fcaa549a48d03d0" },
                { "kk", "a458eeb6dee4ebec74dd9e700e3a11076b2933a34d3e4190503f4c4f11b013e0217c26f6959ed98480d1f24827fc424ed1dd7cb17b52c3d7f661c554e322d0b7" },
                { "km", "528ce5dec9b7001e38ee23801d07bc7f055ba4296f99bd521e013ab0519de5db3af0c32e3f3c5e13c4bfbeeed41572afc02d127cddb6503acffd5b42b38ceb42" },
                { "kn", "a26e45684b0c6865da2ab36090a9a2b309de789ce5f0f36882eef17d837cbeb10d15aa94219c69185b8dfae470b5684059ecfd38f4c51e8bc0195375197a053e" },
                { "ko", "0c63ca725276f19d095fc93a58be4931aec8ad4fc9a76351fbaf61982dfa307b210798f20aaad9a4e6ce1fc6c37ab4c9c0528e063fce4be55f137b924aeb8a73" },
                { "lij", "b2da83e1da36df9cc11977612af833d5fba3d0788d8e6503f1be77f51e05d2cc557ab3aeac77d4307632a4e6a2b2afbc98b80fe9af961381007c8316e74433f7" },
                { "lt", "9936196ebc230e50060be0a1790af230f05cdf616545ab6c89cf36a52786f3ab51421e9828012fa3b07c86b3caf92cde0bcf3ad2d90f6d79660da08832e5d2f7" },
                { "lv", "50f2db97d7f26271dd96c83be849ea721e273c3fd37ec1e1faccde8b266840b89d6806255f84b63f503023ff2532a33f15d6c428864fefa3eccd6e13f1cae83d" },
                { "mk", "1fed41f36931dab1eea07188db8a453e557fb79a11770175987fe6a9a8ada82f95319de0444837409ab167bcbcaa61122b5ce516565170e9356b2f3226537e99" },
                { "mr", "77364343d5212fd046f139dae351b9204096b1c657fc60902f958c260d8178b95901f59e707c0be45ac1c9216e73cdf4482e7c9e4c5601303519ba4f86aaa483" },
                { "ms", "9b52d6096f5a711fc617ccf7893b2265f1f44bf6919827a06278674ad83cdebd8ad8e688ab478dde6555f8c66ea28d1f8af6e85e7f8ea9ac90cb3d857546c661" },
                { "my", "89c672c634fb3e26cea44038aa6264a1299e358cecf0cfca487019c11eba9fe2069893e56d98d0b403d4ac9f2a012dae1468a2539c81bd6617a27454ee5a5eec" },
                { "nb-NO", "15250203c6c21ad87cc08d35cb25776e073b28e8d846756181994517a9880f811f0bb18c68f5f56e0fdfec24b15633bdc8bc9ccdabfe2807ac8c0b7eb77e94db" },
                { "ne-NP", "e2a6fa5f7ff28385c4f9f4a7df8b2c9148609a740da45b83b6074841dedd6ae1c6348cb6212a37ca672f2931c1c036988bfd584a6defde8399dc6a0c1e6170b1" },
                { "nl", "6d42c9c9de255f80a4c235aecdd2b6dca13366d7eb29b4babc51f588791bbcd9b604fd82f140ccd652e7d80089aae184acfb747576f6c1615b29bc01d2664105" },
                { "nn-NO", "e6022a6c07caa60842f5b7c6fbc3a6348b05cc15a33d4ca29d647d9293ef9c371a13e4e98d26a67938a37263fa807a45fbaa8e14bb72b9b4f6ec8f7de8058745" },
                { "oc", "f43a113616f55e635d7fdb0fafbba81274a1b638f2de0f77c68e43238a44507bcad308cda367402ee2abe517d7018f7983cd1ce3f294076013d9aafc35e3f765" },
                { "pa-IN", "9894132fc17a99bb01eb31cd02cfab9a5eaf4086974e60898ebd56b547529c013d3a67e8e107867246705b1c9d70b2fe687c06447348379501b8be9d63ddd800" },
                { "pl", "dfbdba04f4f191b71c3dbf436f4e82ca9e49eb6a5e21a69da251e63c61164cb6948c9e24ce6232ca0a5bbe1adcb963596aa8cc04d53a012dc8a394d1d46849ef" },
                { "pt-BR", "4f842a1a62ed2c374cd03baaee472db978532c113a5728c8ceca9478e0c15a2ec501c2fb7155e465178a0aebdea0a5153acced413a354ebe3206a560cc822daf" },
                { "pt-PT", "3f08e6993712b30c707aada735fb740055fd40597e9a3fcd79c8a9a4fa369e1d04c35266ad8606e1e82c5e24250b00ead216877c7bd484a4a5d8ea4185bb8faf" },
                { "rm", "fb35faac96e548cd13e8613f0f8978087c5a739114598919db8469ad383bb0c070c3740268a6b3efeb30fb0f7722a68d70f3b17a913e4610b21c46547213a1fc" },
                { "ro", "bb5e4566f04a0138f95fcacfb27626eda3a2521d603e180e0124e1442873af29f46ed1d781ae0abcc12624e9494c8257a12718b83e602e886a528d972f10122f" },
                { "ru", "d494de151195e142e2bb681fcac9a4c4e56191a9ec0afad38f2f697368e8605c7d03e22feabfbe772674119c6a4e038a23b3c0e86f60eedbfecc998c81e707f5" },
                { "sat", "3e5a5f4d862a5248d32000a80a2ffa8bfa1972d4045717c6b7fc1d962a8dfa08a365bbf12e414fc653b9d9ebdf7a71f62349d998e1b98687eff83bd3847e0275" },
                { "sc", "7a3566fe2dbb711e90dd951db9fa3a14a10177a870db10ff507b84ac8a7d3298f6b0584749d348627102d0934e288c9df04a8f0dbd346204e935ec3f1b321292" },
                { "sco", "9a7214c067454979a0463ed25cd0c834df72f8cf5010adef9568b693220b773e4348f8fb6b6acb22d311351a1c07161eb73b5306a4984672b42cc42614207354" },
                { "si", "c261a413c6c0a6bce514e37ca354dfb9d732b39fa4341c8960521b72b8dea7546565924ba5a29700c38193ed0c35683e6d30b6992b85b54dfce4587628276cd0" },
                { "sk", "fc0be286ecb282af63e21b4521e879278397f9e1384f88c311a70d43072712a6059522a97584e505ae2f52d2bcd49d7d72a6f928f9cf10b6b841abb2484948f7" },
                { "skr", "10bb53dd976c999b7149c2e417b903d44395dffd3c05f9781399751b6a891145a7e1d09f8cf7652a9e997a50f7d0ff687a0728c5f5f26b24174caf012994b1de" },
                { "sl", "742e58e102650dc7b529c80781fbc937d2b0c8e3fbf3b164e3360b88e9f5101851b47a6c6e2286661493894399cc077e87de308a1e6d1e5ca364190a629696c2" },
                { "son", "f5f4b275ab8f720a289b81b563dad2d947ccf45385f47045d9e315d1dd9f2acd8e198d85a701d81712866d29728fe791224eeccf3d99b8d9dc48aa6f8f2eeea7" },
                { "sq", "abf22f5c1314fca763694f93fe959b07f8ca7afa265fe6093b231a3c297fc38eb0bcc4d4a6c0233d8052eb235f8f1423d26339865a62384e64254a000f522e5e" },
                { "sr", "4bd873b049e05c6a806b58615869dfd15a23afd9257125fd32eaadfb5a8cdfea80fb495a409b4b33c11e82af16b4695d2f807b3f8ddae292238bc39e86c086de" },
                { "sv-SE", "1134506de221ed6bc1f7329d5e49a2dc508c243dc8d7b6c5fbacc9ab36b623da27dda3c3b8093b9c6dae860568cf69daa9d6511930a737da2b367012f12228d6" },
                { "szl", "0f20e2cb6c4b77d84dd93b5913cfc0343456e29b004db621946fee7f5c967444a8e7d823a3514894ca80fab14b1c4d19bdf3ef6b48f61180e2d8361468dbf94c" },
                { "ta", "6ac2eca944d91d05f249c1584f2bacdd551bebd286e4127cec915c834600a6265848242d6c568e6265eeb121c1bf49aa05bdfb4b448db560985f01760baa51ab" },
                { "te", "bdb5024e623b95c04404f90574156deff8d42b8c8e05835c5919269d2e116d8e86fee61e6e61e0223e985a90c6543f3874e216e4dcfae472c5c5dc815e7f3fb6" },
                { "tg", "d39f60f1dc203a03fbdced560c8708dec27288d32f6519460a23d45a102b2e1ff1534c1905f1c47b6a5a3c1ad01bb7da5d4982dc446afb39ccd53ef894ec3064" },
                { "th", "e2bfa1c81b5dfbbe719796239464dd754caf70e12fe440b436e29b9ae66ce9d8268e7a367600d87b7201b7b884faa51b80e9090f945819a3336f2b0e85a2b691" },
                { "tl", "834c4c5ea17d5ddc9fada74d4674793d8526761bd789148ea2050a6702839d7bfcc01da1598f202916f6527aa2134a6bc31e8c2d8181b82eed64e0e29b09b5ee" },
                { "tr", "5c254ead1260640e8e3825f36da0dc172f92d0d8dcba85e30abfd5166bed81b1b6124084a8b3761c72659784ebe4e4198c8e578adb0affb7f5db1c8b12c80d5f" },
                { "trs", "34fbd023c43f5813c2b5ec64165bffbe7bfdf2c224eb912b22a04a180587aebad7298e3a6de40277389cd8fb358b53597d2d7cde2f348a691d408bda954299b9" },
                { "uk", "5b64767863978e576d6658ec8767d8d73d6284b772924c2022228f013a6e0dcd2bdd24838cdd85ea12c933332b9f26c5916c1086aa7bf7b6d2e01581ce10ee12" },
                { "ur", "75ebd661f9a44704a32328e5aa53e2c75c4e7f99d37240bf96aff594f3a6c1162cd1986105da8e56becc3ad64c62012ec319d7b0405a7f10c142f5d1dac564f2" },
                { "uz", "5d711142443ba2f5ea93d2553d275f4fda041d55e6cf4cb22c3c1abbdb88fb46fe7ae048eacd4a0c8ee119940b61a4c10403d8ae4c362138b1dafde549d621bb" },
                { "vi", "c7f089a3722afa6d6e900a7f4fd81c48f5e843f72006bb1a9370fb92f5602ad067506a0ceacb75bb94292f246f79974ce45acd9db78e5002dc59dd4c7a3acd7c" },
                { "xh", "2d88bdb2dab59a7e435ec4b50b910d879a5be75cc9658eb9c83b0b1a291c0d2801262a0f7c36b513314248beae147adafc316cfb7c9ad6d3b0c31775b82a0993" },
                { "zh-CN", "97181ba56543a888d9e489315da1a194033115d0a34c8d9bb10f32ec93f156e06e0283be5fe093d329c33b1fa814232c68f317f465d2d8500fd4b5fd43abdba8" },
                { "zh-TW", "b320b2ece923f3402fe620e7e45ec56e29d208596517146b0fb30a1be37f12fbca909c4c3f63702d63bad06f57a84210a3e0e551bb48774c21c9434667204627" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/154.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "cea8948d9f3d92da2e51a27081a802951110f4ffe0a8a294f4b7f3c637959eb0d44d4da602b82bbe6657b3381a6bac4e7daae9d2631cbbdf631f000a89bf015b" },
                { "af", "6a0be1eb9edec19dd363000c831cd63f41dd3ef06556c0bc11e4ebb229344257eec2c0342e17ed9b2578ae922f948914bbf78c35f617b722ac3df651a2636321" },
                { "an", "acdbad114149fe01d074a9d566180cbc3b36c4f1654d1b4d9e9e8e4a3ced7f656832bcb8dc23eaff00c19edf0243a5568a049b6a603f7cdfa29945ba38b4ef3d" },
                { "ar", "f63f53fba7a6c646520087f4549fac20d927295a04077fb08ad3d0f75d8e8fc64a9bee6fd96f258965f284bdaac5766d3b83f9603740030fdecf7aea0abc2a61" },
                { "ast", "0746ff8353ce9a925b0cd5f349a570c1cc96324632b4d35d904db36442f9ff049e7926c5d8def8900f24f5514febc3c04b6dd016db10042df0cb173154b50fa8" },
                { "az", "64540bef13eec693083e17cb03043efb7047cb691660a9d530ff048910041e7b8f5d7b27c5e3e4a7445cfcc3ebd692af63575097fd988dbdfecd6a205ac8b176" },
                { "be", "e71140ea055666f817b8a58120b142c0a13f0a431a3d403c6e1839593ff5316dec5b7a840717ea378f26f55f379ed73767364059013e02bee2d3fb229458f2a7" },
                { "bg", "f651e40c9e682b64a69bda54c7136aed465eacfbef017c66a91e7a2c012e47906944adb0061bc5a4852ca01e7482f6ab76fc293e502ee21b376ef808de0d6876" },
                { "bn", "363545ad77c8e2c398041bb45b68773ed8b3a95c32ac27661ce8d31d90b1433604506793cceece9c76fcd0b4c6714c2c97b34ddf99ddafbe30bc4012bc8993a8" },
                { "br", "253370f4a65f3c0b2a17ec91ebc1227138c71d0b116340aff663c73cf0e3d2b1e7a89699213602837d171e08bd8c8455c62071c69e0c57546e739054403aa99e" },
                { "bs", "e4e850b4c2e5b8e5a217ac9d164d1ac3a9e7d8af6b2c266d43313da222fae8da4ef9ad73faa9c1499aad42c9e70f2268f3f8de248dcf15956efe11a85bc90033" },
                { "ca", "d43bbabbf04ae80c2cf8abdef202b62adcd4f32f4b4420926a629f46a49457ad562e10a171f580872bc334379c942ff179abba2ce9ee49cb7dda1872ee4da5ee" },
                { "cak", "5031645255f719977098e86a4a0be917c463b28f73f92b4cab8bcc85650dd70d773805e50213d565a68be1f9db1313da1d668a2204f5aa7bb477965b187a53b1" },
                { "cs", "1ce969d2b678fb8134e638ff09857f77a31accd47198a3eba4b7d755e9ab3ae947f21dc41d8f8046e80404f62d7d45857c068a41e6547469c837bb8118a7e38e" },
                { "cy", "d148472746efdc198699a227bd6209c2e6527567cd186a3b95dd443690852b5169df6b086c74a76da53ff12f81066a34cd6ba5da1f3fa35f6e8f5589e279900d" },
                { "da", "0f28c217bea7771ffc821c787c996bd063c2b8a2da03b9a11713669d7521ccca24a0499423ce3a88e3363c20619db71df367d43e160069357ef05279efb9d7f9" },
                { "de", "3b45bf8b61302e6e4564b176d12a53a3300b3f661cd6a13e3f9dffc68e69fea485e2e2059766614fbf715417a5cfa8842d337cdda6ac0af6749f2b8efe66dc9a" },
                { "dsb", "bb131c0905aa06e747abe8791b4f3128780c238f25b4ee286f6d22595c574a0fcfea36fdee6d3a36375738feec8803c064157dfd7ac892bacf4e109c927640f6" },
                { "el", "36a9bd7c96a0a79244ef1e6becd951622b130245e50a4a8db88da2d42aea41b760b3014d77fddcbb17ce1a51f5d8865bbcea6ec9f79f835f2d8d022267b0b173" },
                { "en-CA", "cffec4578f6f6c013154287ce4a02b3d53d9cb55bab1f5f13dc0a59798594759d85e2d58591a1f34830b0b47ca8cc573858cc98a79da77c42c5beee6c36b05c1" },
                { "en-GB", "46e9dcf42eb45bad40eaa3c36ec181d910f58a744d0a3fbc266ffd406583104d2d84b8954625dadb0c406905a8328b3604b469162759ae2dab5ba38b2676af04" },
                { "en-US", "21b35a685c4778a4f6832be33a99e6bc148f72c79d13e0fd3640ce784c7f5f64dea62ae7fdb987fd727a751520a730da2d1ed029c0a70ad299d5d052a3950515" },
                { "eo", "522daef40d2a3b05c090548194dcbe9cd0269c6e59c92b0f6c7ae2bb1ab9308281ba86e46ad28d990f773733a345ff227ff707a38d773b702a64dc2641deb023" },
                { "es-AR", "ae91bd025a8478bcb6a05b0aefa445ebc24f53523ed59abbae18c622a37cf198781db682d949d4a20359a8f7f63d2ab73d0a95a3dbf5e0c5b7832a9c0bb2d5b3" },
                { "es-CL", "a577f6c685056a91513985f71b3539d7357af5d116dabecb9257a9d65f31ad656e7af6313f014b8fdfaf7bc872f3d7944241e8485e884b186499376b4e797ed6" },
                { "es-ES", "54260f2e71000681e312f4341dcc9a635b012e9c6fef3ec649cbf3c6eea5dffa26118cddec259b9a051c3356962e8f3224b50ccfe61df0563f7c69dc13c0a76d" },
                { "es-MX", "abe0e06fdb94927e9f1002d6985289b81b0bb28203f1f83f9380a6210f6d6a430cca25a18e9c4f52672bfc46e8b5316a8862f0e3fd9753379f135d3de08975ea" },
                { "et", "c262e4ea535933f2ca5284ec9d30808f4b42e1af39bdf66f0c507828da2236db1c5bca01c86d8d26bd6a0205cee67a2d6b3019af3b7e183a553593169704ff6a" },
                { "eu", "c0038955883a9f79986340d31ae45547d46b53be0db1ff1e3515114a560ac94e256f233c05df53eb5ec3331184d87d3f3d4d7f46ec064eb28413fcdbbb575d07" },
                { "fa", "3f2370ccd3cdeeedc1d467ea5cffdaf8f713859cf2c11d5a68de2178e416cca378c0f07fa05fa0ca7128f6d0db76bdef2abdc5ead049c7e3c871d5b4fad0721c" },
                { "ff", "6c5300f3a0b5ad0cd1938f6e994e64fe6af1954b647cef0fb9beba7bb683bf932ac55bf9725c795865a17ef4be9c25fd0e795d4ffc1a74545d2d099727b7e9a0" },
                { "fi", "6f12b1c77b239df6df114e004fb85fcfa1d7e48414031faf1ecbde9ef5934b28503acb70ddb361696a36db06c673496424a2dce46a0c6fcd797cdc59eff48fc8" },
                { "fr", "d9043fbcedf734da36e490285317152dabd5e568fdc1165bd9f4a7b5823cd916743b8d53a1de1b189f9ade58e80cf554f6b57f01a23acedfbee99b62e44e496b" },
                { "fur", "11d61eb04c418015a4f9ba444a90879014f594fcf5fe1b3790147e7dbb0afc3d775eb4f8c904a540e091e54f5965fa9d4265e5cc8a063ee8b11d431ca2cbcded" },
                { "fy-NL", "050e9a3f380185b3c6c7c2e5d9379582aa95b8293a38a9644fa96367049bd9d38413bb179513483ed2f6a7165680d49ab5db3d312e72264450f3ad6692667e9c" },
                { "ga-IE", "623dc27851d570c713deee4c2b8ed7857f57d72035c2e571e465f6bf3808a55e599e4cbfaab56b835ce4399381363f7c3cf3940f814edc8a45bf555e4a496fe8" },
                { "gd", "f96afea5bc6676fe61afc5ebfb67dae4fc918399e585c74c2a048f61dc33b600bdf120f0d9919f72c7b59963e3c5bb5a3f8c7379e3e21317b0c514b42094f94b" },
                { "gl", "5ed6042804388b7bc62e0bfe2dcfb96fb573103d62fccabf291904c566f84287f532e4db17071c62a18f99891173ae1f85cd7b8192d53ac775f16dd972983c94" },
                { "gn", "709ffa252fb9e0d33a05d5162b992faf74ee8bb3aba0ff32b459e522e035b3a5d29693596f82da2ed74c3267a4ccd482555edf30b4f9e94d2ff01660745700c2" },
                { "gu-IN", "7eb42ff3618984c69a4a74587b86783d67dd95e3cca895a2fd7d2eaeb166667d591c3968bba1b37d180892ab5a55839d20ebacad874c170128e28209679599d9" },
                { "he", "ec8a630f61217a4e613db2e02c42e240383b629658e7d8a4c7790af9437f175365194ca596e6967ea8aee3bcbbe38717c2f98fa10d1721128ae25ae30639a3aa" },
                { "hi-IN", "313ba0830b1d00addc11f5f8a609356e8c99b448a137e2641336e2f19f235c8b5f49e38eca49e2c2aa7aaf99dfd14c1d563489a90fcf91a9b4ee8bd37ed5bbb4" },
                { "hr", "64fc043b3682475a4a90d8ee77ce2102de8c2e76d1b4049ee65322dc8c1e36a1ce7367fe3063b54c3f28b2fd258d8203d199ad1323f40776ce4cd0bb0d578fb6" },
                { "hsb", "c16e0337c0f62c33643201f07071726e03c164a7a5f2c66475fb80334f734813552d41c33f0424627f6476d2e067ed44e92b9487b4af336e48e0a3feba10fe23" },
                { "hu", "9ea00d1f2bf2647f62a004bd3e00443128085f960681aee4fa3330ff10be36205425747028c2445fb0671069eccf359add6508b079b0d042b8212a07d92c9c09" },
                { "hy-AM", "a39f3785271a11a3ef1b15174a2934f4832bbba3583b67dce9583468985e248f6c6a16d60c11e8dd0c043745a6eb1090c93175ed74fd644e14c18ab84fd4cb2c" },
                { "ia", "eee5d48e48a2a816e3d61b9838848208101d7697880d3d8e9b72ca78a0a9c069f6aa5be9fc35bd49678f6d88f6a9c50fa1645faec971e6e361acfd40155c34a1" },
                { "id", "cde4b380ee168ca3c6e1e195605a38f25235e0b383106def1659f83e6dc794ffb473fae8a409b4b13a012502f1e789a4ce19b299e81c587631c40c46a7e2e2f6" },
                { "is", "3052af82af6506ba8169476e7f55d579e123318c75dd4a359bdf4a2664824a0f948ce2756eea895727d54a314f1638ec3baa790e7de5221f8d5fe8e0502dbee7" },
                { "it", "7c4d691fcc90f4a8036077217d14f70366f205c4d3a0f7df8979d98461ebb2cca8a90aff223709ade4f36836e3540d871186e177cf865bf9db55416aa8472b89" },
                { "ja", "3cb76166a3fc3d6d666db6c9732075477059c7e6c1d8ed5ab4c276830480f808c4cfe497d364975d68e463c3af6f5aed9e3a8c61a7cfafe5b2d6a75dd5d49a73" },
                { "ka", "0f1ee15515e646a926dc1ff42d1243765e66f0a631160f788065b5c570228da52b07eddce2f7780304e24f6482995c4a6738cac2b90a4efcf9b28769d44d80eb" },
                { "kab", "f1f52153eff9adb3004dc4c1e98e5282946f67ffbec7ef2ce51900c1bb4cffd467047d470eb0bf12f390c244395ca5d8e79f0444b6bd7f3c19f9158723dcc3d4" },
                { "kk", "b51a1d1bb5b7386f93017d6cb696ae54330be08ab5e0dfb7fa2838e75fcd34f1a513bb3796a356f1a5d092079346269f97604e0b91170da35cca91d7b9248096" },
                { "km", "c3d5874e76c2addc6b6938953295e17f74416a274c265e37993cea6f4ae78ee8eb8d69237e9258823143047fa5c120a8d6f589bd631f02cdc0876121eccd6490" },
                { "kn", "f328d1058093176194b81fd6e33cc867a722167048b27c48d365fb2e2f1ed272be7a37b40e20a5052befec4570b39d6dcbd286d0a0c2c9978f612240180c454f" },
                { "ko", "90547db250be3487750a057ebf323b9c91e80a03ca7d1558d99830c6b22c53e4fb51fe20dcd1c42f363972e732d5b66f472a7c2d52290e02f8f8b38e861e7ec2" },
                { "lij", "c313740d3574c0f38fa45892236ec720122f1ec778bd7fe62efaf678dafbf5ba2fe27a00d2f9ba6a62e82fcd5cea855c01c7a76a336417097495181d48834463" },
                { "lt", "e74b9995466c4812b3ee6cb3b3638e2077f9af6f5b9b9c614e54b605a8e3addcd163d025fca64763fb8205905d84f1c0933b41497ca39351d32fd3adf81be526" },
                { "lv", "f236f93418831c988901853635d540fb5dbafc9b3d69894349251c42e86b69d32bd327fa3211b42b82849b08d6eb5165e466bea6f2ad2f5bd4496298062eaba1" },
                { "mk", "2f92660d8005210be538e835961ad1ac418da62abd0f3798271da0192e601ddda3c837012e0e77bdec043d9329bccdee0e43c240ea02e89c62fda3a3eb11c236" },
                { "mr", "cc2402c7ee9be550501f64a56a5ef10cf611a6442b1f28e6e5dcdbfca5169743ac85ba6b37013d66130ce6a39c45e100b4902426d720ad849ab5d025b554cf5e" },
                { "ms", "88667f533b47d252990d4d8d00d6dae9997b6b55b26cc9d3842680ab8f5283f4b93a0aa0242dfad8fb3fbae1dea95e7dafe6276001d6276e4522c5598a4f0a05" },
                { "my", "6e40ff1fb2ab525813e896a75556e9befab6c27dea16c05c2f07d6976a8960ea91552e273846da29dd0707d8d5a8cc519800c23d6c39bcb65da6c7754ec6ae3a" },
                { "nb-NO", "3e4ff235d24c9ed7bb67325154a74b040c5b98f8d611bccae0444a4ccff16fcb52549aa98c02155e70b0cb53ae4cac07bb5cb799e5b7aef8997d425506c31c2c" },
                { "ne-NP", "c12ead688bd8aacbbba65792e45ee6505942ae496eccf603290b366b706cecf10d2b26acdf27447e1f482308b815f3d0ad4cf0f495f24695138251889b409647" },
                { "nl", "c1c0a7130b5bf0cd4fd350ecce5f8abe1818f69ff709d542a80fe077cffadc03b389da2926cb79be77646bc3202a01587d01b7687246e7b10d3017790434b72f" },
                { "nn-NO", "ec1e7ad2030c66ac9c548c44f8212f31a101d509b77ba66d1281d0d70d8a8ca528e15ad13f2aa0d5e4a908f45b45ab668d2e0448127cf64a8d619469b9818337" },
                { "oc", "e30049429a7ab41c033cc6b4838b14d35ec826f8f0a3c72fab681876426daa88cdcbccac9eb6c41f041e24d0ef3103e00a3a4e6d51b83df701459b521a4fed77" },
                { "pa-IN", "678adfee01beab7273122e26cfdda636d7644625cdb8543306721c4b51999b22835fe5949cc260410880dbcd26aec773b3328e23d2236133410e22699e3379b7" },
                { "pl", "87aac12d0cc4e2c49eb9005828bf1838c1028a50c25e828e4534e937ca491b460861c156b555763e467079ce41bef5f9f263f508386935532dc368ff173bf734" },
                { "pt-BR", "0ba189c38c012bf0efe62f6cf0c9c5ae4a8e15cb1a61e2981bc3ecf00205dd7ec9221f0a73252c2e484db2af0684fdc5ba393cbd0de31de076035d539208e46b" },
                { "pt-PT", "f123ab3f5d2f7df7879509656faac3e08b06387e80dcde8375ee4382fa0efcb9fc51673f7f072173fc791c4fa8d474721d81b83319deddbcc6ad68253fd9260b" },
                { "rm", "d2b27fd79477cf872cfa61ee1434fffdc18d98c23982fdbb743c4f92b65f94dff6895fc7264a8f4649d8b828b6a25cbca85f7534350573d9952518e46bb07c4e" },
                { "ro", "4d478bde90a70ba7be7de444bc999fc4e7567119c58bdf416af230d8d25b33ab6addbdbe227530e0f314e817489a700ce28444d94b538292e444ff0cdb9f98f5" },
                { "ru", "bbc43b8ce9a1b232d89b8326347e50befcb83997a3fa02b28578ef3ebe09840a08d972e703fda78bfab151ced7f60bb93684869d81c390ce261236624b1d1eb6" },
                { "sat", "3d99918b28caa1294d7f87ba7922594799b3e8d402ce825557d3b8d88c9a5ffcf60acbc3f87b1b646a690167249b22a575059b3cc4c0c5b0a6d60f9274e6df17" },
                { "sc", "b88c1027e74adea9cc7f6d4471018791a15545a801288ed33ed4997f67603da5194c55dceb815e7e99e5d37d74f5169f19289f9ac8b272f6f1bee97427d80fdd" },
                { "sco", "aa2f09468a112c3c980d3361ab3ba308dba1784c2be1343f0978ec9f9b597f1981e635167ac4d4f9de44c7bb41906b4645783db4d965a90d305fbeaa2b1346b9" },
                { "si", "090d89a80cd484f49416b6d912a1dd85b777a0ba097f914d78381085268bec529239f558b0dca041a7f889fa0fcfa103f51fbd3b18229edf949288410b7cd6f1" },
                { "sk", "eb04dd1a13086cd6d1433c57445b3325c6565ebd8869363d071473e3991da7fc0c7c3e98575f74212c06875a28872729c3a053dc6f3cbf704ceed65165fc5ce6" },
                { "skr", "c40e86e8ab37217a16333e2282814df87e75eeaf2aecf13df4b82f8de16a21138954f746b0c6161430c5c589ddef4f2b813e4aaac34f39a864bc73c24d95d6ff" },
                { "sl", "b85fe0879960a7911ba4399cc0b3e8aa405d475af340d890ffa868b345870b51a46dbcff603bf33686f8da8e28abc06ce495011b9bd6f13a130f4b98e1c98c39" },
                { "son", "fde3d27c2947e50ac64b6b767cead295c2f34768333a8ab41fbaeb956c944eb8a8b3b037e7ab2cdcc60ec75c89cfd28a862f4fc1e3a52c7c64b6eac1d395faac" },
                { "sq", "8028f489c229f46fe30afed671ca722214f83c0e24f1d0551196160160fb9212affb61f62eb77d17ac00fb76c192d709b779beb4ad6f618bed2f525d0fc17420" },
                { "sr", "ccb5c25c74d2c3f720a270de721cc5eaed911840051a55193b695ced31ee8bf847824d3d5a623ffde810de279991770af9081cd0fe89d93a94527fb5c6cdf5ca" },
                { "sv-SE", "f6ba6ebffcb3395171500a9f45b4f5e39ffc95104fae8d0a4e040b768a629d4cefdda5945e13c74f937d5bb11a6efaf28bd0cbbc4aff97bb83050f4fe8da5aad" },
                { "szl", "1c7a3a76499b21785cb6798a910b6db8bf467d85805f45689d8bc5e1463201a613e5f069a257639fc79a2fe695b1a9133506cf3547a1dfd56439afde4da95b2c" },
                { "ta", "198bb98550b9230de63c4d6f4f316e839fcb61a0c8aa9f88af608e75f9e55a89d368325dff88b0a566c91f8c0c48092b833f0f4d3c70b5e198aeeb3100d56288" },
                { "te", "221d87a69fecd4735f132a2db36b3a555bca7b2ea6d02074a8eba580a7e7e305c8937b57fc2befb5da15715b7a82922352adf314f2bc933ea083d00a50fb4d44" },
                { "tg", "8af4f7fc4fb413e7dfea66cb8f1c99eca8d0ff2a5349ad64b4f40b16b36d75efeb2c531923b171174526ded0bd5a701ef3af0d16b23f39e71dacf817fbfa1377" },
                { "th", "51f96b31957774f2615206d4bc397b6a6b8f1a63ceb47c83449d702cf7999ee8445eca05e423907559aa9212e52a274efba26cc362d612cbe53375bcbbb7c66f" },
                { "tl", "1f489e8d229826af52c70d6dd8e053f6cd52ecb6c34e1502366ab14d4c2fcc7dcbe50c793c4b7e8bd28bf087df821e451631d08007360eb6e86872a7031f6dc4" },
                { "tr", "f369510fa7054156f7e57392b62945edd2733d6ed9df3152371d0aab58f0eb0d72dc97ddefb3f39e0de832a6e5fe7fdc6bdbf53a387852de49b52bfdf6b17d11" },
                { "trs", "94f37d5c221a63395fc7990b538592865501d26ea3af9cbb37e59bbd9c6b21ea9a6e2466e8d13bb2d1dc921d70e08edc5b90055df11bfae56163b642bc9cab51" },
                { "uk", "24692ddd2cf7f2ab31575d7a8c36e3dfd9580e359092661ba1c38274bb05bb44a0eb1705b3ce032717ab42ea69fe1b63490647f48e78eb40592eb8c4cd29dc3c" },
                { "ur", "d28b08192f61b1b06d3ccfba4ed489dc28dfa4b99e8bd661c095c397e43ac4513e954e680ec4336215cc1c020d02a7ac3e10d3d0f387b91f702fb742382ea3a1" },
                { "uz", "a29d7c6e8a1651e8c394ee3f686e6421e2e062895318dc7505e694f2db0156f7e4a84a344cad3b792c95792051cd813b9857e9bb3c8480fcd8a762d43369d884" },
                { "vi", "a71c73cd2d1b19fd0314cd132f6a6e6465f809b0694ab67aacce5fdc78fe0c5bbdb25bd8d6cdd2d529c80596ba4ea9ba8b41c81eebe4456833d90889ebd777c2" },
                { "xh", "7416d3ce389eedde35d1f9ceaac1c7b1eb3d5a530910974e61b92e0064f022fa1f82f3297b5e043c24f0292efb15270e67334f5b537bf08771f046d4f01684ba" },
                { "zh-CN", "1586ca83b71d6394f3a6ef41a44bdaed8a1b86130402917a3aa32eed6ea37118bc4aec6aca5284bf54aed2d1c8b6740214416a6d31dd365e8adb04bfcaf2959b" },
                { "zh-TW", "29184b7f6860da70f1c3cfb7c3fa773f3c7ee136fb93f91fc36ce94ad6bc4fbeb9eee7cc358b35620e1c335fe3710626dca7357e9340e78cba13aff2d4417eb8" }
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
