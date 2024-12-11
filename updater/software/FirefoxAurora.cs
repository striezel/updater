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
        private const string currentVersion = "134.0b9";


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
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4cbf09a9d628f0549e1cc05b3f5c4242922fb7bec9b8eaad49e6c61923682e9ac1ebdb7357536358a89fc4a8d550c8c6756f2dab0e2e309496c932179ffca074" },
                { "af", "6dbcdb8be898a963ccf0c53829f2586d647492de277643cee1d3b56d2b2a1668f8d580c126271d2d48053668f12bc314f6aad5b6afb9445e7886e77eb16d802e" },
                { "an", "04aaa963002184e5c974f43b8a0cd7c8456aa9fb12ec0b2be6db1221e0ca858e05a93da8b405901a09a5ccc7be23b87e38fadd8bfc9719fb9d95c9f39cf62be2" },
                { "ar", "ec87539bdc81710f532062b949d7e81c98d02f604d1784cd79859b460937ac770e5bd0dc073eac0e2155a81dfea1c7af0663bdaa4c0be56f92a01f00125b79d9" },
                { "ast", "4dbf058d10fc47f7cd3ce06196ef3e3b926b3afd836119538666d488df7a0670b8e9397f71313a21819c4b879cc0aa2388dd4208950f297a84b0ee69488263f1" },
                { "az", "a4432f0267136da312b7ad4c69b016567264d90e6cc042a6da80463c1585abdd90245e934e096566551cd0ec9a720dab057f19faaa464af7981605e81e13a209" },
                { "be", "a59d2b39da55e8f7408d8ada0e8c825c6fc3767e59c8127848cadb1fa4e3bf2fdca1266174d8213550098525e1c91c8c56a8494271ae9f99bd5b73918fb2460e" },
                { "bg", "c71ab3ebb143f27e6ba82cedef02b3bedd3ccd167b76348757847bcd615a86fc899fdeb1428e81787ee221d8b06bbeccb7d9889513e8db69036bf6a55d922c07" },
                { "bn", "8c6c5101921bcbe2d1d0e3e4604f34f78652d4b76063ca11aaf979aaddbef69567aa0e1d377b409e7a76558bc3201f05f8cfd802fd9ae78dfa2ee62d986f8885" },
                { "br", "179f99ca99021bcbd81340655c0d49dbaa4b6e95c6b223e8850c27fa766b6a773b69545fd405bb5bcd30aa88c5f8d1dc5c35c84ab774f59f27f47089bf0c228b" },
                { "bs", "077e877496ca8cff8dfd71859f0fa93ee8625644c0a1f84d55d0efa328dad0d02a8e42c31b53c8e8804a204ff1207ac3cf9088413f924a79624f75752c27ecec" },
                { "ca", "d5599be37316d5ccb350725b52eb82950eb1cca7770cc79e79fe808441de67935af39dba0de36a6394759bb344735fe492a473de52ff276f999effdbd6e592fc" },
                { "cak", "be473ad89369d07d8aa3dfa9263c2bc962a2d0977817d4b184a33441bb8bfc6131c9a1fb873032f107796cd979c46ececc0d2ab264d87078f924e46bbecc351f" },
                { "cs", "b3370b82ed56c4a135ad5d3ba249b36ecc8c1293c0eca1e0728ad2cc404adf146d6521ef4e455c4d1dc5179af2b18a1da156b00f5674d9c9375701f87aa659c6" },
                { "cy", "96e9bc3dabd985cba42a01f744712b14b837cb035f3b07e1ef6ab3c9e43762a4ba05f07f7bb77abc7da176e8228b5c3adb5eb3db5ac6f21ec4361322bd8c4f5b" },
                { "da", "b5a6709f5389ce80dccaf0a12b222b2fbaa73d042a8d1494b8c987830c50109e7b7835da896f3d2df249d2e0e916ce4a902d30df433e6d97ffcc7522eb428abb" },
                { "de", "93cdd56818331d7270c45a2f9e648f35f8e2d79a96fd8e2f54712fd2829a62f30d21d6212a39de4f6bb9d627425cc0c83aa4d22048d9b6ec36d89127e15feeee" },
                { "dsb", "72be56e2d9d812cf97fef3fa74cb738d6fccd8d4606e1df485c5436b7b2bcf6be1a7abc5824bc782db9b88e5f60518f2d353ada9b6d6b53f1547f93c515e5e40" },
                { "el", "229f7c8e49d95a28717b2c10c52b84ceb4671462452cd354abafe494821cfcf2a6e8ca81105a327f3a9569eaf3d00c0aff11af041b11207a12de6eb3c2633bbb" },
                { "en-CA", "f294b634d3ad3f3eec6023e6a25fb1de8a0db757f963e2aa59c47c4eb2997ca31ddc91b5eb1a7cc13a780466e10f5db21e757b98e14d54b825e3eed781898f55" },
                { "en-GB", "c9e84ccbcacecb722981deaf225f1cc7dfbf0e33a7aefffe64e01f5fd65562deb54a030816baf5dcfa4813f0c39dc2f530f7b2173317250f1d4bf86566ae9efb" },
                { "en-US", "defcb14bf83173eb575ba28097b725e7d34f732afa9ed755ae7c40641f3ef8554f3d0cfd1b0782c9f6dde1642b42d350deca6d40a656feb91437ebc9530e7f1f" },
                { "eo", "2dad44736bd169bb062a9ed2c7cc665e812018a67db53cce1388d004c1a1eb21bf76a87f9b73a0d06448c12d1c8c034e119a45df32276aafec349df353963c7f" },
                { "es-AR", "369179ba36804522c5ea6151cc3daf75379184550933298226c7ef4f61ee17ab370335bef3a3e6e41f2c9d5aeed902ddcacbd6b6959a99b5a4620267f921ceec" },
                { "es-CL", "c9444fbf1c5c92ca13ab6cefdb505583a9ed7a0e3f11d3e22d8f4f7942233e7a4192d201ea0969d4892f3910b32fcc1cfcbc18d425aa76a8e4dc095dc02a4d71" },
                { "es-ES", "f42f913aa5f7651629d4d6add38a2d1464efeb15f6edd1e8cca55d1886e59f84cd2beee1c0859b5a52ad44a19f8d960e7c5d18a0250eebd638038eea8396de88" },
                { "es-MX", "dce4a285f7c2777ba67b1a2ef2bc5d4f6565d2dfd873a16c4cc93c3210bbd26d35d2028f47256be82dba71ac38d57adf022004a56d41f6c60c054973e4becd6b" },
                { "et", "a79c35f531abf85252ed3b1c64a5e6660dc86f6a082586d8716d72b0f31314a2721da13307fb7858f3718b6ceb18c2abd14ffdbd7bd88ae97b770fa868c04fd1" },
                { "eu", "c83766eb708647d64ad09701958d9f9eaf2bb4d81bee8c87625a96c7f6ca7126e4bbb6e1936cd4ce17ca0feca51cee82c2586cf6b992771f6c69cd69d9389722" },
                { "fa", "adae0df5b93251ff682ff571df7230617de29f60d14520a9350ecde7130e0a9a1c45f66f2f05e2c911d855bcf28ad0d268006f5570c70beaa7ce706533b63fa6" },
                { "ff", "388aa8155f6a25bada9489eddebc142911818ae147e3e7e433df51576374b1ad7ecea224e99640c56b365a8f940fd32a097ed1b9636c91ca02eebda7e657faa3" },
                { "fi", "f4380403076a9a5ffb8b760a661ff895e7bd2d6f63a71fc05bd110bfe7d78f9a7aabd8a39a894425027d7848498fae6ef714e9fb9dcbade8504c966e47aa0f00" },
                { "fr", "b96397ca7342f42df620d02b1aa51c8f66ddf60039f1cdacac31bac4ab4b1894220d9730bcc8e57806eb6620d2616d77890c9e530c507b1280208448a70aee3b" },
                { "fur", "3cd6b051fba43ce7f4ec4c9c58fa837cc31415fc298dc48e1b858f52412197fd0e36e42d14a94fe52461682fa15137d38259be5ec1c78a53a6deaac36929a035" },
                { "fy-NL", "964bacfa141509501d60f88faf90ef1f3acd23c00d50732d34d374ceaf27cabbc473c02e20dc029b10efd01c87aa00c09f2e0bfe93c4bb4ad360958af8a4eab4" },
                { "ga-IE", "7a5ac2884d75bfcdfbaff85c7cac1b86854eaeb82a56b0bfa3c304e7b973154c41a0ab922fd28c78765a0cbf482af4f20995907e9e2f7a13e44840f3a9e19d25" },
                { "gd", "7b9109fe8c1eedd3d634e07640948fb7c0ff5646f4eb10606a251a1dfe96a5315311e674b7a5451810d2cff68514f051b636844da887471a909958b7d5f633a9" },
                { "gl", "5befcbefa6d2791c26399c16fedefd27aa5c4cf3e6ee92075fd229786d4e5687229195cff346a3e4cecb7ea4c4d0f9be829efe47b7114c5e3957de136dde0bd0" },
                { "gn", "b493bf6a9ce62347f3b0bf07678003ef6827312f43077f8a5f3a1a1bdd0474ee2d4da8276c7df01049658c9d38e33fab478d45ce8a9feaa5c448253f6dc088a1" },
                { "gu-IN", "33bcf0f225db5d7fb526e2e197f2bce8e8ecbf4aff2025acbebdf5f68a39440ff94090f083da28af163e521c71eb37f4be551e4331b2ac7b238e8fdadf145f22" },
                { "he", "e42c7058c4d68cdebadb9e7cc7f15dc4e2f422624ca18bef16976f74e9f827d8798f476ceb98a6fe0fdb3c7bf8ac856004f327e29d8b379f57c5b3064737bbce" },
                { "hi-IN", "e9b25434b4db5af2ace9e429b81d325bd18d7a30bd53146e3902ddea155203d8d74d985d4632eee4a331e11461a4e56696c904c89d27d43bc99ac75ce3f60812" },
                { "hr", "8bae2c70bd8e2b736d7f2dd2deffb957c3a71d9dff4d8dd83248412201447ccfd21d71ee5dcdacdcac5009a019ea5c90670361922ccc39fed42e9a7be59494db" },
                { "hsb", "c0c8a06abf05bedc81c15a6607636d7f79f92d9fb4e453918939ce404aceed368d698bdf77d585e8183540b877fb02f38b46b4dd2a533f972c11dc1fdc84b8cd" },
                { "hu", "24de40b8acc98bf1d1c5c072af23e4944ec8ae06930981cab91e9cfcd2f259c2c5fb53329e8574e13ce296291d537f5d26727d6ff54f9eb43537cdabf9bf05f1" },
                { "hy-AM", "64d0ab1a7994bd1c112e2b516132bed78bf95556f393cabea613657f390580b9ff54716f454ce266a8e60c4bdbbabb2867faca19d146fd2cfd8574c0920de730" },
                { "ia", "e645d76ea5a0cdee9966d3a2c5720fecc1f7c442e72f1d93888df6a968abacb209d777a32efb42a481115e21378a4aaedeb4067279e70e423cdc384e5be30576" },
                { "id", "7f46af3963492582c9507264494c4dc4f9c9a45232f205bba7efae900a0200a3af26ce7cd5d7feb4013348a7e3ab414a42b9f178f86f2aff39a1ecc88e28c422" },
                { "is", "6340d6e076f8434a8224e470c6471fedbdd48a182cda325aedd57c3fb532e0de69222c86aefcc63d291c40f2e747b2c70410e973133047af223cdd0a47eff583" },
                { "it", "edfcff7fc7dfc1599ae934d6301d2fbc50bc52786e5d1d7a8649dde7228adae63d7c581ec61022f139ed1dfc6e1589062aa9143a4dacf909781f6d97197b8d39" },
                { "ja", "ec515ae53bf702d5cc679e0aa9e18892c4b7aaef9e1b7bcf5b0308b9d8ffad4915e06a668d14997bb5700e3374ec5e5d4ff586c342dc8e2f913db302901386c5" },
                { "ka", "b77a963fa44734e8ac880c79b66161ddf2f6b8de27d90c798f5826d4d02946d246d70f5f7951cd2b7bce217491fc9b4a39efb1a820e512ef0de60d72122a8445" },
                { "kab", "a8e8ba2e05f1b33c9692f3293b819f1101bfa549e0c7192373c9d34ad81ff121f6d14b0871736ef713b201fcd39da854c1a00cd9f9da2a0d36374c441c5216fc" },
                { "kk", "80ce970f9e8dbc5ac540595e9ad25183997bf5e4fc9598aa4690c9e071af48ee38e23a11758d31e91cb4242dd53df655f7f1071520861b54e17e41690eac26d9" },
                { "km", "68ead39bf3a8262073bf665d18550bfff0b66aa2aa42b70159bb233ae2ff2a3fbf19ddb66c7cd89c9e83c6ba9bfce1b1203ae0c52354b9c7fd96a290c8b1d558" },
                { "kn", "ccdc31002cf43b01f19687d7d7198e22aa02a01910cffc820025aa0d5a99bc22f0ea680a57ce61ff250120e3c0260c75481a4c77fa60595fccc28da76c6c9119" },
                { "ko", "c927442c9514f3ecc1f7b7128099a66f9600b93c27ac801ab7ae97d1f839257bff5cd404de46f9ce2d19efac3f334fb66419a178bf4a1b5d57d2d61e23270cbc" },
                { "lij", "775703643aea7f07f92cc351dee4697ef338a2f685fb5cc2af29aed8a7557aed5ce4bccc46279d5d3a5941b0c5e698eb4871f6697a3aa9448fe4567f65adccec" },
                { "lt", "7beb6475d14f465cf86ac2400950c485ff90a13ddb75edec2093bf57e88a1e969923c7f8bacbdf26c54f94ca4d1b08631f50edc495cb2802b9ea8f0267ad698e" },
                { "lv", "cbdda34d9a84d57bb7e2826d9fdecec13436bf37147812e1bb8375b28887d4b62e01317f974dc29b8418b2c7ffcea96a9706db48160ce8e770bf639bee963cef" },
                { "mk", "7d94b0c81f79693e9c4f572e296dc933df3451ea1edb29416eb32ef30ed1ebf3532d861b9eff1f59c7d43655cb084c52af577e383e84e8feeedb7e14cae7a181" },
                { "mr", "dc0a9f942b83f5a031c7acf051cc4d31c780aa10734dc20cd2c313e4ab3dafd540860b548704cf7cc8195f9631311cb2217a9eb744bcf41e33cd626702435962" },
                { "ms", "47791a462056de127911e00a2b9694aa1cd4ee8b7e0a6f37eff3e969574f4c975c75be6de6224b6c2071ff806c35e41ee8c1e4c96332498dc04c80d4c00e7fdd" },
                { "my", "cbae6b0d75f01293cca9d99c88bcce2780e892950f602795a482f4c9e02a6a49527a5ba1002875518189f18c08420d39fc8c0ec3897a26809ff6b4c452af9769" },
                { "nb-NO", "cecf11657997e359480a3777d07633acd001188664f9d98b179773642565179132dfe4fff6610b7435824fcc3097b32c384ee43d39fbd9ee98883519bb32f736" },
                { "ne-NP", "0296c75719bf94517723c9339bf33cb8ae263c7292cdb97f63bd26e10d5bbb78cf5785c01ed615fedbe51eec02a6c8d67ef5fd66a24e8f8654fddfd384049730" },
                { "nl", "71cc2d0792adc64132d276baccd5bd98a6e67ecc5d2ee7abf470c73e94d85aedc13a38da5fa983c02927051f348a42efdbebf4e3503e105924e4c4730f438f0a" },
                { "nn-NO", "a18ab1c0529049ec26e80570c817ae94405d72af0d072b1a10fc5a6d5efa92d20837d6185cf2a3914a50ae1baf7b61cd31dae0a945621dc0e048325ec747c50d" },
                { "oc", "21af086adc67e2270f5435c7f1ebb757ea6b7bb2f01d2b546c260e636ca30b77ef98d655130a12688813a9b9de088bddc4c5e38dd89ab9c24c0d3a02ed2433b1" },
                { "pa-IN", "00ce50fd6e737cec2e20148561e5647ab04c6ecde1496106820b4f627c903619f2be7fe06c8ec6a1cc8b1014e428e3d0c9ea946870e02bb8149597a42a665830" },
                { "pl", "797896891b72f1eee18112625baf1c07017941c7f55516893f18c5d565df05e57138315c13f9843c3d4c0500a9c1b673f61e86d752f0c90bd685dd576987f646" },
                { "pt-BR", "13d72a30a2a8a7eba14da7a2c6927ca971f17119631c6e77521e757d80890fd70bb3348fb47614fb8e8c4684c9dd06e39aa65d4a814ff80713d8e432441afe0e" },
                { "pt-PT", "2c641b1c9c47b6f458b8e408ee9de79b14b141f965ea3fb7d5899eb2ba1e106ad50b9999c89d143aac64375d3d17ac267f11b44db69938a76585c3844d88a0f4" },
                { "rm", "7d4209244196d115335b5c2fbc942ee4d4c3a569dc43af508545a01792fbe5749a3d93703e3695c440f179a1bc38906391ba17718ad26b0a83e343b504c01d3e" },
                { "ro", "e0a9f75b115bceed17881bd62ac3f1d5b8d8bdfd22a55f12c98be418baebac7208f27f50208151335161af6682f45312d5af188ff3b352e6c2b612a64e7ef3d7" },
                { "ru", "e1e0884018985ad316509ce97428e189065bc9d251bca4be1f68e3b46a90c40f6c72c2d4e4197f69c9a9f146fdce4a682e893ad144b33402614c867d8343e524" },
                { "sat", "6432a33aa4c38252f86634af1fdfb8b530449891dd630a02a299fbb667fc84717f2e8c0bed61d2b5e830477746b9910d8585db2aee57722af1891a0a62539400" },
                { "sc", "1bd92fa5473a8cd4b2740070211281b907e1541d2af520afeba17288fa2946d24f82c8ce8c162fed68aa22d7cb226d3d4fbee2b3c41e845990bff18a221a59b8" },
                { "sco", "fdc2a38fb5d73d999d488939bae4468d195980879be45ae2b2225198747dd6ce45f770bfe7fdc815b5233a34c2e1a5eca611a1d4b1db3f7834201c33f2a923fb" },
                { "si", "b2b421bb2d75df4029e0db64d35c98ec4326e15f3b76c3a13429870328592d029d0d6ccbb7558cde2d2ba5fefc4d0b59203adad53b46ad9cec10af38575c8791" },
                { "sk", "45794d20cb1118f0c89dcb1292ef599fa6b7d70a0f8137528574cfaa4048420c7b5f092024444c15c69fb1427f23eda76dc226d956a06a37199fe4123e138136" },
                { "skr", "5adc05251b207dc1ff197586ae238a8d3c029c7010ef7af5d607610cd75c099b42176976eaa9ea8d5a1917d2ce76c15d708adc49601f5449d929da54cf99e1c4" },
                { "sl", "8621987a43dd0c3e67929c313ae05ac0daffa79a6f9ba1bf46178bd37cb02e9f29c380927a05ba5abc430457b85e2098c272bc7491a4f0ac3b53a38f52b1b75b" },
                { "son", "93eadcff72655d88cdb0bfc4e8e3976cd6a63ba433d29ffa9775c59465f4ae744800a41bd6f9ef6c2688c5616445392b27b87c83c824245d92cb20e996aab1d8" },
                { "sq", "5d39ea5520bdec4ec7edcb5ca03fda7221fd01bf5c7312553c3faa9558b073f44c65a5a172151099368b89a2b762a1592f53f2068f5e7d1cdefc3ccef7e21914" },
                { "sr", "df5f81af74154666ab6616d2b1a013302f45d0a33380f60366c62a8a8b63708fae71a2ea3687125bb66d20f1dd64f08b927f47541feb7f65cdd31f7062691949" },
                { "sv-SE", "437cfdef3ae0aec22a1464d5304058db893969b22b00be7eb9d3f733af12a6094ba5af1cfd9a0b01c388a9c931c0148f7e2ad3bf6f9bb2138f1f5efab165f13e" },
                { "szl", "414cbc58fcdd2f07e119d58f185d002b9fce08c6a2e92183f1f4d23e2b5e9792cdfd27642ddc1471d5ca589dd450f0370e59e1a12cfecc5dd95aba3fc32a5998" },
                { "ta", "5a97343fee1af0fc2cb98f90dedc863bf94553fc36dd646ccafa83c40d1e2586fd196a2733ab3c37e0b1a8eaf0012362c38a2c42a1582ef1cbe7e5148212f800" },
                { "te", "c28f3d7f02880767a14676e88959fad6d1afa65089695b353bd35ea7d81f90edc5eae356eb000fbec6dba0d1bc1da6fc8d482e618363ca5b3e2478115b423596" },
                { "tg", "7a7b113ce8cbc235059b2f5423925e7c1169bb7d4e7f35d1d31f2c4a093209eb7239cf82da3ca25ab6cc30baa116fd15d27cf36f622b1b1ea5cecd77995304f4" },
                { "th", "c26b6266b2f4a31746c7e9f492f645bcb302d5d7b43086cc29cef4be477fc865f3480ba58397f037cd030576df7aebb7f53469d60b94c8b655e065b33b0bc9d6" },
                { "tl", "351e9a9fd7279413dd08dabcc5d359a9a9af9b41f566cee786edef905aaa848ded019091379d73557e45a10c8bd2aa44f05f13987a27808df06019bc970978e3" },
                { "tr", "f76bb2420bc04fdd1b66292f0278f88ca12c442af50c439e49a34e03d50149e3b6c9b7b2a26afb77a63fe40f2eae69a528ad1c078fb319943a68f162795b303a" },
                { "trs", "9c0b775d4c4dab384dbd3f9624d51437cfadba1bccd17a154c44bb12ed48d067b34a15ceeeab27fb79ca1e87f8b2913dffb65d7a6e3d90bdc662026e77f25938" },
                { "uk", "e78bae15e1128bbe809c8833ec17d468be7bdd618f0eb27c5ba14d11471f90dcdb18a6752a1d1ae3b93a5780c415eb2c53b5550816fe0fdf07728594e5e5c34e" },
                { "ur", "e141a560aeb5ae5a63d283422c515ef5105ae5708829d3f28ae7e02a828f6589f385f62e94e51229293585aca40fee1d726f26fc83cc588df434c3e6c86faad8" },
                { "uz", "f4b60e88eeef97f2fdfc8fb6da36ba909ca0612f76bd80e1e59982bce12d14f49173cc168420e7d48c1eb0d5af565c5c73b4e0648d3855333ddfd6fc395158db" },
                { "vi", "6c9692ef3dc24affe25d4fc342e7d481166b870ede653b879e5cdccd7d0855bb35667464e7e91258b43416a1d233b7e3e579a176409c8b47f5df034d79faecb0" },
                { "xh", "a9de3a67e230c1c438dc24d64364036928bbcc4ff0ac800ef2ae1f7b6363479c2302152ff71b16c16eba8136151e5fb9f408785aa38b5db8b02c8d25015747e0" },
                { "zh-CN", "ed5185e91f1656ef9007a01a9b869e7020cc895ce4e96db2dcb814385039b02973d8f7f484972eb0e3fda15e1eed63641b7ae1c183759c95832adadf743fe0b1" },
                { "zh-TW", "9a7fc761379f48fe0ed679a7b09651bf0e0e82b5d4c32b952eee3390cca3762a20dcc535a99af023e7970ba1483ff9f714fc827df78b49d63bba822d3ec74cb7" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "cc9b81e049ff313a51bd06c2ca438bf5595c2724b4137e3a2d5165853e4dd86457664cfc837881ebf2c3d5c3a26e21d4e602708f54928665238b4db326968a11" },
                { "af", "5e3c33150432616430702821747d0b46645d2e0d8d0ed9c19eb9345ca6aff62f1c4e1daa91c70618091d6c4576bb81f8b967a0ea8d1ee94a0774b32cfade44ea" },
                { "an", "f7048765d9449d410363d97aba29cc14e2e165600ceef94ff1840fcb237e1f49e98c10ebf1f7ab53983a08038aaa42bac8ca15d77ea61ad4a891d86f2707d076" },
                { "ar", "17d371659908b9f4e66b3d23208c20619d275415a56156a2ff3c95ec8048ecb43f11d63b2ef3ee055e91de60020f11fc9fc75a1695c8a41960d2edf1d0acf3f5" },
                { "ast", "3d712900b00383ccd76e6cb45855cee421e08964701588b3daf1b8044f7bd2c8f87fedbacb1a7c49b1c7ac9591a263b05fdf3a501f627863c1a27f80c22100d6" },
                { "az", "34d7db871e98143b3b7c2abc0fd32c6de085be35d6ed02a45d4cb70654b0c9603012b16ebc48cf9237965505071ef81bd4e287da21c4d941b4e3346e47c07b94" },
                { "be", "6ba31266ca0820800477974918359354212d888585e49814e7689556854f4cb5c0665f1f94423078b27df13df1abf4b488f8ce069cf308c8b9f8aa914291a273" },
                { "bg", "6247e957a12a11e8acfe39f03f65e5f7fa9bb51d50b7ca7eaf874dd5f731a7707b88ae10aa0e7c065dd12e7298156c7fbaed4c4bc81c6f678603c21050d19d70" },
                { "bn", "88195d1d57cc29f7b751747ef44db89e7b19c1b74d26996a53fb63df664a3d2ec853dabd8d5cd904c4332695f8c8d7f8ff55d082e2dacf870935be82d409ffce" },
                { "br", "ffda22fe5037ffae576eadc7f2f42c41c82a81af3145cb9338d0eb51d68f8430a369f13c086d5a1378b944aa87fa3f3d00b584979c9cda1e46048ad55b7bfa56" },
                { "bs", "fdb1b1349fa3ccf8210694376f6b83c9beb5737328bfa2d59b60ea32473d4bb334d69f5aa8a0c930e45d8f2504218b77b1bad8cbf3b2be19f762fe61b8779f2e" },
                { "ca", "3211700b3f21ef968c681d2eadc6b710abd6001f1a104fd138304638c6be4971399cdd3a07fc0a6c3e30bcc25037da1b0d3b89d00b31a5bc33b19c66bcb1f6e1" },
                { "cak", "ad8f26cb469bc5751a73d119ee0b3498df765b1fa2f62297ecd1918ddfe02d782cc7030e2ca7e070647b68fab9e450eed2e856028e6e3c27075acfd350bed2ba" },
                { "cs", "4a97761c8f57bce478db177f73174b65526fdcda99ebdfff97e9ed43f8354c1beea31dd4b24e0dc647561ee919c30c5ecc3b173fa996783c0a33ac18fb7c8194" },
                { "cy", "d23c07df1306f73158f34e22d06be4b906f74cd73df5b7e16a0ad50e190ac9986e34f5946a89f31d5023d45af91ecc9eaf4f3314a624e0380568a09b8e9e47f8" },
                { "da", "49417c9ba229aea1a46791225e772715f55b47ef2cfdee3ea23a3c1c40db82fb0b175ddfc8dbc587e5e2c9089ce8262ffd76392a1c80a30f94a4b06518f774f2" },
                { "de", "76e53b9df27779ec9ef781fc4cae33cb6753f2eaa69a9593a64c187eb1b3dc5f56a86b318b2764fb7cc774ab89dc99f15893e68237b5187a36d557d10a7220fc" },
                { "dsb", "b729d0db35aa28ba295923166b22c8eb0349e48093ba8af63075266da05a9f91d2c47401389d680bdaae0ca7d2cea66bd1a68bd8d80548f2be11f3bb38a20088" },
                { "el", "2b7812340fa9663062e731d8b178de01d6801d7618611710cfaa5e592107b828f967ee4df35bec2e265f0cc1660da9495398526d0de7e912b1d70bb3f8c07e24" },
                { "en-CA", "231a1d786a8d4d051359d4a12cb78126d670c9ac285597b9658fca3311853f533c09f5a5c442a6a2a3d7fadfdd2a12d3442c63ba232c9e9824d37cfea477ec98" },
                { "en-GB", "3576ddc4886ef90f6f029e0bd6b48a43dcf0e2f821b4fa21498b2b4fbbaf5e52d8be30fe450561a1b1eac46937744096bb785c5f27afa0b9e87f7334a359a739" },
                { "en-US", "8092b0b939b95f558409b4596c448eaa1c96b6ab52452a886f32d5662bcc33e1a85afab2848088f51bc9ab64e682b8b9475e17c87a4fbe27001c442139d4c3cb" },
                { "eo", "3cd7cc5e85c40088357bc79a8a0e52a745185597cfed97929f249c78ecb873eb90801fc4cfb074a5ccab54d344c58da1d0ee92f4b4808189c9a72338115f82ba" },
                { "es-AR", "910c716aaa5661be553ee9776ad8efa257a4c6b76bb92d995da1926a62181a8d5529d5ae645e83fdbcf8fd5066290a35833b4952d453aa4792285544ba047a1d" },
                { "es-CL", "8eb9c7dec1d75acb0ba77cd9ef44bc20d24c2dc476cf9e30cd631bd5d4b2522230cc45d1d89016fc5fe5995d03a512f8d0ec67259f01f4ac2f72320702e259ea" },
                { "es-ES", "b24ea90d79b31698279bbe612bf4a6aab70aea1131c51ef40ac0d316811b286b6311c494f56fa8198c2ab8083dcb5ee35d0215a7f5b8080ee9d3ee68f9fbaa24" },
                { "es-MX", "87d6d3a3b42c0890e5570abada7bf9915137056608900d75207b5f70f83e2202ab5a929376d6caa05da41e9d0e925e433860156c954b882b89b7c57b7f2190a0" },
                { "et", "8ee0f8f6d23b981bbf2f7f9471b3c22243c37cc50f8dcfa4d02db9bc909793d8e03d2e7bdf7c2b8d378c468f798cfc39d81dddfe12c9ab2c1a448bb3ce1867f3" },
                { "eu", "24394808fd21fc3dcc50975a9fc2b9c519d495b781457812060c83c4c9744ef55631786d990ca10daf4fc36e1d92da3c9a77337f213f91b56a994deaa40982d4" },
                { "fa", "2840f16031a25880ddbe34a4a67b60bd8eb27d5b50e89943c81da68b3a1f2bf9e235ea4884cb733a9c36c97c683d13e4db076d816a8bd13b238af6b0efd6f4cd" },
                { "ff", "05d44666b6fda29df6046ebd76638437b335a7a2483ac6ff077c585acf0dad0ee9ec8b922876a90423982a0266d3167ebf9018e18a6b1a0cd2d67160ae7c0278" },
                { "fi", "3bce88b58076f9f3096a2885a8c38467a5aff489ff048a61df45daa4580a13c98d99f8d01e7d1d0a78dbae68283f2a5bd4b34072a6e0adcf8ec627e9d82d3b09" },
                { "fr", "74e00713504539a7c4781150bdd8e304267a5f0cbffdd7034892a5d9df703c9d4519c45ae60265948283435f3b74b9c1a05d73cc5e683e6836567f8bae733d23" },
                { "fur", "fd3a09e549295b0daf38e26d05c3ecbbaf4346b8bc5413c55b6f5642ac78a71df17ac10b431f62e2b6d6dbb334f107715685d5f6a5d3bb204c5bc98ee1fc1859" },
                { "fy-NL", "2bc7918df5512ac5ca1ba0ba8da6d5d2e386f77c76f382665c8e55f28387d945f5b498fa37fa962c85638454e56e9c7bbd2addeb4549397d2b67a8e3bc289251" },
                { "ga-IE", "b1e6ea175fdccf7d1dc15bb600fbbd2cb4a37dc307143a00f87abab86a07d3602e6d702a8fb08448babb448c6adb0cfdabbed769313c4888cf627c60843a2e35" },
                { "gd", "f0dd3b45c6ae09153379f16c67014263ba6c878ce5a52618b46e3956d299e13c142004bb58ea881bc02a114909550131e5eb6aa333bb95fdc753cbcfb366f9b0" },
                { "gl", "651e83ec04759ba3433893ce146976861ceb06817ef469ca379647b217945ad21d99bfbb4c61d82bebc3d5b7db349c3376bd42e5df4e28fb8456e33ad146b622" },
                { "gn", "997855c4a99f9519d721ddf6d63cc94dd5a0fee679f7e98de7936e3045fe841624f05c3afe58928adf3f96cab6f7cbc62b571228aedc19f409ae9ad4f72de744" },
                { "gu-IN", "6bea32e4f32f4c70066e8e850d435dd59cc92faf5d9e53040cf14115fc916c45815d5652cb1a9caf9ca828925a7e5c0a831d2b8e6c8984443b85fe8f5536b92d" },
                { "he", "11d5279cf010e4b006f4b3e08d7cf41094957f25ec5bc57dadac80c70b2fcfff145cced54910537133d25428db05f7a26281a548bee0f581aaf3ad50d25437fc" },
                { "hi-IN", "ae587509c632209de6ab08243671309115116d0530c9f0b5520ff89746bc7fa4eae2ad8ac810a9471259eb1dd5e0ca6360bcfb0a367e825abf58731fc0028270" },
                { "hr", "084d6b2a8757b0a737b477a847b901d316952a53d9b3c90066a147ca161714819e7d05742b5bc6647eeeacda210afc13ff19e7f34067c583d8e3df61de190611" },
                { "hsb", "85d87dd94f1c4e31dc1fb181d551f9e1b7e8058820ab3b6bbfc2317a8d3b4ee5a6bb62e5ce02d87fdd41b0158f03cc912edd632131312b52e8ed00abe4fef67e" },
                { "hu", "0b3967ad746f1ed30ee7af4c753875780579c576521b0d6b60dedad005b89b0cb02b8d46a36ce6e0542227e7727b902352cd95f0250f71037cc39d57b67e0190" },
                { "hy-AM", "82622e5bae1ce10dda483911cd1f48a31cf45cfcfe385e1f0e22cf7058e358a0939aacf773398644dd6bca4694f13f7f0289e5b1009f91ce6b135716eb6465e7" },
                { "ia", "1f160a85918dbbe0e75a75769cf612aea51a6221a8ef895416ccfae92ec81d6f0bba39f4764894028ec488039c103374754045a7bd609a24346651a739886c5b" },
                { "id", "9b10a20c7df554254bdeb28600e28871adee8fa4ee87c36dc285e89c5052eeab9f91c04f1a8ad19cccd97253681eda60177d641fea26bcf7f5054b857daac2a9" },
                { "is", "44ad982d67bddba66592e3604747cbf292ec3d28bf1ccb6d6978fb1508f23f7731444f53e9c70f310fc82d405cb871e6a2abad4c2d39ffa39c78f0bbc95194e3" },
                { "it", "83a5d4c894d7bc595a1658cc7452eaede645804097d6428dc49d15226b13f1b740919c6fdf6e624795b366ebd0f8d931235b2ddd30b824bdf331deaf74c2eff5" },
                { "ja", "828de488c1213f3ebb73cf936f1ccaf67bfba9c227fa8987236d9887ced741c816a8b72e99bdefe9411222813e63dc24fbaaf74881d93f8c443cbf077d0a582f" },
                { "ka", "85c0c42a2a6e2e5f7db8e25a031a1b077b3c44be088446f69ff1bef1fed52bc5b3307069a4bdd73c58318f95e21caad213fe67f112cf2b0037a78a8d8c8a57cb" },
                { "kab", "3d14c44476f60d3369fad3c9e58249628381a9c24e9317f9bd97f78073f852bd86f47aa66cda14348c0fdd5f512d6f12b5d73daa7da6b50e62af25787c3ec945" },
                { "kk", "665dfe77e9da31ef1090a8371c41d96351be28ef9355cd1b5fcfdc1bf266ea6f0e26f0081756c636216359265afab9262fd017b043a78d3830e51b34466d439b" },
                { "km", "c40d8dcc4f9cfcb8ea505dd4942c92f55fb29c731cba215572110243a3c387d35ff73e2ed8035a0707c7fb72b152405cf1d89b7b021765d7ee8eccaa23751ddb" },
                { "kn", "2abdd35abe089244a95a6ae75df659af647078809d639526b505cb20fb4eb8caf139e23abd384de226c19893186e1dcb9e4c71f322d089a1f800da2b9dbd990a" },
                { "ko", "bc968565ace8164e3a4f727d927a5fb02163d470d6726e2322a0e83e51e10e9aa7729288b29261b150823ca4f13b2d89582ab28a32e0bccbdff3fb0794b72c0d" },
                { "lij", "ca322fd94a5965166d592642aca0f6dfa88eb87a58dc6a4f5223fbae6c003bd74564c76bab2a0fff80b62634a358a93cd994b4bff97376376d3c7e3450a008b9" },
                { "lt", "a3b020c2c00ada24d636221ea819c08977a5c6d67ebcd8b993d344c460f21764fbc7f2f6cfc7b7303e2e46c40085102a63a74ff3811c3dc572821e2d7fdb0184" },
                { "lv", "f2d68b9e3506b852271c17d6b4d459c1a4f970ea16f680f14675b3270ed36eb5b2aa2256ff9fb6f0ebb9cf22f2d2c7dabc66f0d41ec3b551de6aade33d403433" },
                { "mk", "63df6e7590aab31a1b1d1fb6b0c739954b7e10c3b8c2cc0af6c60342b4776f4a8768d54e1a93a72371ddec20b7b1646cdc8e6d8cbecc4a893e6e3dd9f86f05d1" },
                { "mr", "251ce6b0e77efdd487271eadc5f0eb6c5aa8aef08ccd51984b92b8c8db05f4e3022d7a2e920386555dae24474044349c1084a13b7b88d138b073c49c0590d7e7" },
                { "ms", "9547080200b53b613f6978537a8958bed057954258b369f382929f4cb15b430dccf7669f039ff386755556e99dda65f68ac2183b923b84ce556ffa8308ea30e8" },
                { "my", "e892a5c172fa71edf37db26afe24a2fcff3315faa05b2cc78646cef051247418965c0756b1d293b3317620dac99e25ee48e4595537c22367d9874ed9abc4e2e2" },
                { "nb-NO", "ce3a15b78f8314965e7639dc44e9dd3313a7081279e9ecd694224dff44d63a3e3db95c8529d5c7daa41686e8da772b3171b2fe036fb469d0b7559573b888e6c8" },
                { "ne-NP", "d84b46381e9a8b52dfae3a11ad97dc7539ff41c9e9511bdbe753098eb92e2c7f0eb864e92e8d311e69bfd3c6a4865a9bdfed54ca8ddabe03eebe939056015532" },
                { "nl", "ceba8cb4f415dcee3e6050a979dc8df8a6b5e6f534dc9ef65b066a832c45a5ca8e6e6b550852242476fd427285557b35b56f0aee441527119ddd011682853f17" },
                { "nn-NO", "87b2d73014a6457e677c14a6a596033d1eae051326a45841272857b1db0a8ec95acd3dbc017b6ca21058779315cdc0691cbe637d11e8c058921931fbcdd4eec3" },
                { "oc", "e1ca187534db82b86b22a687b9a5e7c250af19959d3a4c9626eaed3ee4131fc2fe5373f835bcc6b678a91ee99b089d40cec6b49bef1df83662f4a2c5485360ea" },
                { "pa-IN", "b884ead56309b2745dbcc6de915cba7c3536f05fc39a99f3d1e2ae1e8d546b1fee5eff69f88a31414d20daf792fb078af63e0b61cfc785243ced2e82b5065953" },
                { "pl", "c19b1de41b38ddaa9a0bf1a069e029ebafbf22867208db5f25c783a7d0d7b19384008b0c66c10292901ce5a1735989f88c3568122780a8cc7caa76d454f21f29" },
                { "pt-BR", "892a977172c4716c558448a09b3ad8c6e4b6a0d61a4427619677dc4c6368901ece9a57c9474b0602de998340a29dd791c1f2d02fb13a64152af2a75b93889822" },
                { "pt-PT", "b803acb750e0fdc8716d1fc59e18f8e71fd3821b165dd99f9ae50b5152c9634849069d1925b0b0c34a613c7dad55241a62556a6f2f2e041a0f9e945222c51e5b" },
                { "rm", "7d2dfaf920eb6b9d77e057d8808bbbfaee7aabd3adf54237449a055d1200ed8df985ec3f0b0a291288901f6803571e025ece483249261abb0e3e26675c37b43c" },
                { "ro", "b7f2c97093367ceca7dbc3f464ec67705310035a1e1caec42061df7b330d46ad2878b9fb64ea148b1416afb4af37cf0aa513863a9c2f55a9603a02e9070dec9b" },
                { "ru", "38db9f2967687e352863270312071c14eedf8b8a5de7d502e123837d18f230e387727c7ac57eda42a69a6d4a08560dfbed47e9a2e79cc3e6e4826f626b112d84" },
                { "sat", "5a572856b23e3275f3054fcf2df880c1dfcfe49cd958edf626d077dc660925f489f3e5c42e5df2f1c16384bd98d82604588c6a9a506a21a49ab045667b0a5f8d" },
                { "sc", "420ece77a4ff9a82e88905ba9ee7ff3cbd3bc4cdb6aa6fdb7fcb642b9c6fc2411fd074851ff541ed8caa7638314203a0392b2e4955d7e6a7850c083142c699fe" },
                { "sco", "fd222669e7999b493e9039918180b8a0b9522734595bf7c1427c105d5d08dbe02c4a041c05013a1ac34d5717bc2d54b6d4900834a073ddfea9d25a000648bb69" },
                { "si", "f297faf4cd8ab392260bafe1a12dd5ccfb9683decee029a0f9cbccb410f80f4391c8fed5c21ec7a35baa05fe7ade02f53ccfff77964df4a3aa16421f0ad44639" },
                { "sk", "dd766e1cbbab30efe3dcb1baf08a3a712dc9f1a0c1f67461b6f219e7040d549310dd1d282934251e664cf4d6576f8335787b20e9c7043f9275c66957799a0dc5" },
                { "skr", "ee7511a495940ce99676a2fa974a206ea5389ded5308bd4bc838c8b4a55c0e4f57cc9bf46b942bc05bed7daf882d378bb65ac6a1c8b3db701ce473b277bb9fbc" },
                { "sl", "a69454eb516e771dee9406029d47cd89ab7fb2ed7ddac97ea041cf47eb7ed535a5f04aef4a773c48a9260199d21b081a2a539274ed4e04efd8ebe2e461a992ab" },
                { "son", "17a4d53d120a78b67e932e9438a70aa8258be453cda211db810bd1875fe063b028e3094c3cedc9a147a201be23af7bc76971bfa82c6ff6dd0cb31cbbbf37d21c" },
                { "sq", "7c98cb28b9959a72c75847f703f93aa8622c4b07f2ed8d3ccb86c79eabfaf5292e604edde7ab3e90349ac819ab06ce35bdda241a6e854360f7aaa21fe645210c" },
                { "sr", "65b4b10b09b0af1c8335bd1154dd8392970f889c606baba53057e8bf4f42f63660e37c4308b06a3f041bcd59237183a6270297440a50de95cb5e2cd67aa56da0" },
                { "sv-SE", "fe0cdc87e039f0093dd0232126918506075f10a9f91dc0f494600dde44e832a53e876b7703e76183aa85dcb04e21d8d5f0526dbef6cb5eb53020852388b5d0f4" },
                { "szl", "1ee3219fb6c4da65aba46526e3a81a7d69ddf53798ab09856d5284bfb0aa75ffa013cdbf76078090cf4f29614168e4658b220884374482a5b2ec3975a1a771ce" },
                { "ta", "22d9fa0221a33b103572ad4a5b290802f2764bc2a80bd3954b33e3db29516b72be4bed732baf342290e46f9442d801bf664d2f64fbdf997de0029ead4c7f48b5" },
                { "te", "dbcc4f0ce8ca73718114d6e5db12f21dd803f7a2361ce17f7384cd49a7fe0972645fd27b3ccfed51f072e822e5288affc24b47ee8827fd627a647dd665b575a0" },
                { "tg", "0a98d7ee5b732ac2589150f83c803bbbc183f6ba37eeb27486d771f2d9fc7c4a6240856be02dd4f5afab4b915a93d4f54b1008a9b1b38a161b1534a05fb7f3f4" },
                { "th", "f20d7e3b19d908808226dc64a94775d104ff22b99e69a68a08385a0f9c5ea7d34de267a12ad5f3365d91e21a2829bd4402001b62874d71775e4592c4ca66ca49" },
                { "tl", "26dcb36b5666ab8e8a08808bbad5c17d92477950f627f136f250b7a2608635d6d7e9e3cea6a8a1198dee93b82b7fb68140fb0da0ed9bee4d7d0995fd0e3a2a32" },
                { "tr", "067203d337ddfa73cd7990882a0fdcb052f9fa3b8fe8ea38e91a00af448afa13370cc7e6b238bd07da21fce2ff4d353c84df230ca80a9a3dd5eebc12b4f9870a" },
                { "trs", "8558ad834b77478a770f1e170720df9583904911b5d133f32666558674599c3153421d9fe368b2fad79f3a91e9cead4bfd5f68e661c94ac8e50b3e433a3872c3" },
                { "uk", "f0aa86f9cd901016cddbf448b9f9b00b515a03f0b4d17fc970a242b95e09b99fd7edd17afb93390008f7947b2f811b087fb8fa9c7ba72701a6b44136ca363fbf" },
                { "ur", "89291fbf2e2a1556225343a59879cc40f462482fe9c81442959b25bd2e3870357ae52f02b2875d7161314bd632ab3ba4fddabbcc01e3608664d0078e1e933269" },
                { "uz", "c1831513a5e69625caf366567023e2ad2f5969343d128207d67627bd28ad3152e05e0a67207312d544b71971e5fb1a3ea590d4a90be344cb24c1cf4720a46cb3" },
                { "vi", "d09869263038b9cd3c18788d4c57111e8f517cef25c11881a280ca9e2d6169d1a2df4978d953222873f93e56617e3415a244b82fc2cb69c1679b24ea9b4d5e11" },
                { "xh", "29f90940684fc30f475056ba44db02569f620a108de66bfa033bb57fdf38fd22e6a363c366eb71e9631fc7a8ac8fda777e9a4075250c71373f3602891c5ba5ac" },
                { "zh-CN", "802f1af5b9f23c94a33ac13261f416b4fef60a51d91eef1787a84c9a0aa2cb1f828b6e3b57b8a73afc41bac3941d5ba95470d29deb837dd963b748a6afba9dd4" },
                { "zh-TW", "6e47219522a6f67d4479cbeaaf929968115242a335abf0cba8c8779a765739bcfd3384082abd7c66c0c2bf6de2b72ca67b381d2419a6313607d1a48726c33bf6" }
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
