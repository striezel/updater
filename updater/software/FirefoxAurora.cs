/*
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
        private const string currentVersion = "142.0b4";


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
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ab450cac05d234defccbff317537270c5be234fbdebe81f26e4f03830670b1617c82db0922b766b2ce449bab36d1b35a3f82368a1f97dfbd07a5f9e374c708de" },
                { "af", "020c15b404b2b4fc383e0ebb04595a7bdd007ed5ce05d1c4f2ed1f9600933b82dfd6b8772e6d91b8ebccd9c96f10a90ad92b354ea3457b246101eb66a6705227" },
                { "an", "eb0eabf7ae48e3f4bf859d24ed37285757d35163a7fcade6526cae8315c9fb52760fd832f09b5433a03287747fcb4b9d1e16303ecccf772d175b9e3e5699dadb" },
                { "ar", "84043e08f0896eaa87b5bc373211ffb65736fe02e8458c15665f315146fafbe1478f75d697a253b52afa64854915bcd17c891cc8d3cae25cd27c43b1c71cbe91" },
                { "ast", "5749f77512129046bbb2901ac1218bbfca51412812be42f7f75a8742983a44b6a81abfca496fa633a76ff8f70137017c072ba56ef70de259dae349bf41312ce2" },
                { "az", "5f6a816f088233ba2ef6ea92346f08b4fc55c3efa0125f1e7ce2141ccec452b1197e0acb7c0ac7698be7cb0b0fdd160498add352a6fd82f39deced45f83c48d8" },
                { "be", "8606096e15f486ba53ff6df38bac993bca6cd99daca18d2757eb4c7ed251be30a16336d22076f4c856810dfa2ff84eb40f2a5fbe387cd02abe9a84572e8cdfaa" },
                { "bg", "80b747e1ca597edb1b822c9500e737989ae8bd10df2cfe1514c44db9b31bbd5c8bcaf55ecfff45e8694f61df8a9e74ba2f085e4a03a07a5d3dc3cc2bd4835241" },
                { "bn", "5dc67d94646ca3daef850a20a0e11882419201f9b26525017d183fb5e4ec226e370645269496cdf788a9debf78c4e9eee6af61b945dcf09d1e0c34095353a5b4" },
                { "br", "4aec5df8cd28ac5c9ac5b9276d4a381bd0f2c4bcbe2159d60c5ab9926a25cb8b001decf0b9c381f2c8122c4e7483eb47a3479160a1dec15d585e41188c8013f9" },
                { "bs", "388314e1234723f3f26f7989e03cd79bb1c2ab59bff9ad42f95b9367951c2410340957e62d17f8bf74c81c4859c6fae238a54905fb993b24c603a397e7ce5788" },
                { "ca", "e279ee3711bd472404ac48e3c1b17b328ab65fa240fc2035a9c29a21b6b1b2eca38c5704b3ec458569228f2e10c940b5d7fc3b903a4d0e126754300c7940191c" },
                { "cak", "e5f347b6311215bdfcb842e7627dd547b44904420cd13a09ef3b136eb074c1acec3ae5cd691336d628514b7c6d93692cdedf340d4d3c4ab325edd36328d9f773" },
                { "cs", "64e3049954bb1c69fbea3d4db5cf3ef013c62b5411b0cc6007fa77c476c6e3fb47d3e441ae423268fb19d14b6226a56a4ce79537f3fbd924f34cbc97035e7968" },
                { "cy", "97ed2681b8567fa4a65eaaa2e0cd23e2f648bae65695d942f397a2291a1de481501c6b39a0cbf550fe09ce0e0bd7bc460dfa11b170b222a1fd7cd20a63469534" },
                { "da", "289955ddb7f7ee60b29b8c6ea837b29a28e0e23372ba9b92d674f4765f3ff8864800159bf74296efc51e9a4c496a1b850221e956bd9460f0887bca8ae6e7e4a0" },
                { "de", "5589c08b1b46bf2242faab639fde0cb28977b1fb896e599d7575df5d55be85f55300e3ac81845cc60e6783b1989bd565603dc4ef3f5e367075e0c22188f3d2f1" },
                { "dsb", "e46cf258bf271692a1e06a9ff309a8d03d5f23f4bd5d4b8ff63b022cc11406af6525b6ab321c092c4ca503ec37e1e5f344dd62d1b4e9005e1f2c84269a4e38bd" },
                { "el", "2dc164a2b7e7edce98b724f85ac220fa870640dcec1b1a293846ea2942cda37042e1bbcf26d1650fa727c5feb7e894d49f872e629a5fa08dc969885c539a7091" },
                { "en-CA", "a1315c1bda327e6bbaa00d56bd7eca2c65668f6d2af63cbc70c0704cd094b47c7f7030e15b64084f6a8ba78eb595dd4302e02f08d6b610277729fdf8b75dd2c5" },
                { "en-GB", "f2dc4f5935558bb3b78a6c1e3d9aae6bff7b7869b405f5aac9859c138d25ef3496ca923f62e5a3961ae1d62479a8e152290f334df573f8604f2d8ce73ae72d61" },
                { "en-US", "f442c37763835616affd0487152c357138a71f0bc5ab772a593b67b1f752b7f4a8b7385ec27e278453f84cfeefecab78d4482c08d97be1e9334ab8f11d71c64b" },
                { "eo", "6429d4ef9fab0374b74d3a40a5eb7dd484e790aeb7dd1a825a52b7a1f6b8668d8eac17c1dc6635ac2fd9d0a2c3dace458ca1156966d65bc44bdd6268535c0cdd" },
                { "es-AR", "f3c6deef9404eb3cf7a765c41fd58812ee1f08cc3c9d456a80dcfb80339171a2a0ae0f71af5d019f2ddeb77aa91ba8e8726f772409645e07c4f3edc8ccdcab39" },
                { "es-CL", "76f0966c834bf92a604470e4805ade29cc6e5d7e97f5badfc6cfc78722a4874d4a7e8bff75f61bfaff74344e365845bf70d18a13483e794e1624360bf9c9b1c9" },
                { "es-ES", "c3af0faf6adf6f4fc5e0ac05cb30dc8591b0c67507e3208750d2ef7963196ec639be586a99ddf0d149052d862f29b073d4b1cc107cf898016347ca7d9b60fdcc" },
                { "es-MX", "13e78f2017a0d350ad9807741086638a9ceb77843a05d0f4b63a5ebaae73f56ea610788f323ce846b33ff549f6ddf342c5faf1cf322acf6dc4e2ee53ce2b1a1c" },
                { "et", "0b4e1088d696fc9305c43e41fe0b99c4401233dc81159a3a38d79286613e702cbf5e979092cd7faa70d7a009cb2d5d93af7e9695e0123975eb344f2942ad63eb" },
                { "eu", "0142d1a3878a89bef5d2c58670c716a5a851584330aa80e134fd022a2aa753628fa1c2bfe62f3b75cf3ad2ee1c1837d565aed2a16aa572c083b7507755fff6e2" },
                { "fa", "9e95daa8e61d4057794cf3b9eb3c0336aa0268c6592efbe6dec24a98e6dc96538a69d8ca2b255427529847c71f63f3fb4833111061c9d8350e73df6f604d059d" },
                { "ff", "b337f6bc014498428a69323bfa4400f950b1a3b3f1784b07d7c78ac1679b6a6455f02c9c654de9932392331a1f8ded4d561eb99df5e5418a849dc714700a4e29" },
                { "fi", "a93f7687ced26138e2f67562fb97d3924b364352b966d72d817f259b58fe5294a09bb7290f10db8f64641d8b43e1fc14c5286f4ac77ad925a8533392321034bb" },
                { "fr", "2a36fc15f032093046b4ed6452a4d7b94cd4edfa9ac63bbfb6871ea5164d5cfdfc0d853650922d0fadb52c09a330446b63e80484b430a9dcf8c104a1359a2e24" },
                { "fur", "9d9d03b22fecad2f0c0bbbe8d85652f03c628910a9c6e5ef8267fd4a7de146d9d377258bbbfed861993c6958c901dbc21145b5ab74c5cbfdc86813e112efe54c" },
                { "fy-NL", "df8dd0d8629645cdf4f4ad278b76f4c41b8ee5b00b5384b9285c790d1798108817ed36815aa0355901a1ea74abc57e5e561f33543ba5eff9fbffbd654e2bd153" },
                { "ga-IE", "164009dc37eca597d99666f79f3371c93b14f0367ecbd6c1ff0ae1765db924d0da6f96393becbb69f85d27eacd337983205209fcf7727c7e65205b5bd0615e08" },
                { "gd", "a8904f50fa2d2230a727eaa6b93707a395ef0386684264f867335649db839f1d8d44ca2a0d7046590ddbfe621e86491fbeba66977535a8e0a865e0b9e940833d" },
                { "gl", "dfcfea51a635ee2290ad453b39016a53791064369b7553462b44b2ccf7892d35490e87ed8289f348be31e36187dff4f19cc1933f32ac6d80d2b2e2305c0ea66d" },
                { "gn", "a37de91923716e2ab9d39f27946cd3ceb6a2ac324400080b2060af74231a4011aa96386dce1d2118dc2e82587c5841a95817a91c04c97ed91acf42082a04100d" },
                { "gu-IN", "e8938bf960e11951bfce496da7e6a959b9e1c5244b174be190d18c15f721960f31aaac7d3c67798f524ceca27e5b5db88d71a51bd207a2ad0e4757ff1d2bc755" },
                { "he", "87895655367b4bfeb879428ae8c73cb943ffc6b863d6e277aa362583d506ef73a88978c2d498c5e4235b2ab6a7804a36a38a95aa85e104b9d81f1fd01a5a23c2" },
                { "hi-IN", "aff2dcae69db51da3dd1a9cc6d89074090e033696a6870e65056a832465098c09ed1a01f707076211996d021a643cb517599ac352a84e6b45eb06df7b90028d0" },
                { "hr", "c6786d905e5a3d70ed095c73d3e78194089067a03bb130651ab1347bbba848a7e06cfed2f65e8eeb23b0f11cce1debb5cb234eba3823447803314376d82d4efd" },
                { "hsb", "4ba4f16fd99f655da9f03ff89cda622f93c47d627967a190b73200fd920f5019f8843b820a16c8362e29c5a5933ec0871eb06f72a8d53da5cec1dad9b560cfd0" },
                { "hu", "f828393861839b2c18da19f4e94c1ea5b5676aeedc44c79ade4a3de7d213b1f218d97de4fa2c8c22474847066457957352f7c3ce143bbd2a02e891ea2060e036" },
                { "hy-AM", "696b31d758d87644036dc23e0a1f389e24d502d41fd0f39d1925fa8e2c98534d1e31a311dab56fc9c608651df0cea3faa40d87bf97429b1a36452e56edab3465" },
                { "ia", "c62f7e6ba798f06d285d6f6f5859f8b8ec7ef8e4b89e541fa6c31ec525746f2b8057236c2b0da64cf641384ab4fde6d923400ded3055fdc47e75b0d6c8e03038" },
                { "id", "bbe5b98fb683af83eeab59e06ddd5262b3a120bb35dc19e8a0ba08faac1dd7918afc8f5a64b57f5e4011b4fb5cd2837fd9ab854fa3f02773af7173e8499ffb69" },
                { "is", "e4c204c33637d88a0a01d254880cd94aab7b474ff03cddb8d4c1e2c87be63c98e2a73c328eddf5c14808ca1659363a3499d6704b05ce0f15b4ac06a31b79d7f7" },
                { "it", "fae3de0974ff379efcf2b1e29b264ff4fedc8294134c42b272f12626718492e1eb86e67a852a4e5cbf57c504cf54b285faa7141992bf4e632b9969f515debde8" },
                { "ja", "cfc388271248b30d4bb77c57ab866b93eb0858348254dcd77e373b52fe66078fe23ad54d5c58d1f39a146670126f8ce5a0379b8bc244ad04f34b63ba608af1bc" },
                { "ka", "535824e7ab062025f90b4a92d36529637526c9bfbfd78d3a3d3cdaf7177d5cc83a47719078b1d05b07090c3df562b72442c6b898c9fdfe1a3c76bfff9f598e36" },
                { "kab", "e6055e7dad655700bce0e48323ec9aa735d8be64072013d9f6bc635a35ed1cfa6b48755c3fac13944aea11bacd60feaa9294cd1268576904f523e0ed363dbd5f" },
                { "kk", "21451be795583019c808467a5c93f700d955d23884f42cb7d9b6e21411255e3c806aa7425e69e0663aaf7ff9970276f51368691a2d2f7fe80c5df245f7b4b978" },
                { "km", "279ecc1f9337c5c95ede17f8bb74a5943489961b273fdd31fb161d45d200ef88e6f60f329fd54abe9b1380fd1fd35ca5269e7e84fbd0e464537431ba75888897" },
                { "kn", "1750c214c665e27679c4d0326c46725e074b38172396e8d64b4ed79626e10fbc3e362f5ad41b36ba113d0e0191d3e8da293cdd4f86c543b72ef191e7eebd7d7d" },
                { "ko", "5512376b88b1a7151ce71716ec3c9c17cf2cbbf5049b2f31e638eb6c79d257740f83fedbd58f6131812cf5bc9c8fc7e532b3069f3c5d0ed51d296fe7e4086425" },
                { "lij", "549227c717e0ad774739973c5c960ad4651d964499bd4050094d384600728864164688e524fedaf0d204cd954c0d0f2d8120807f39822846c720992647eb6bf3" },
                { "lt", "696165e2007d082cd9b209422c02a803b07ec3d4750ece08c6562fbe3c8e3e760b6de0cfeec47ab4dd6775e0888cbd5c51dca6174c299ea1b72d58bae27a8f03" },
                { "lv", "d8bda93496e635954e767678ac37467072d9fe95ce2647c503515ff9c3d34fc4b32661e03d7acb3cdedfa3ad40f474b20bff766fdde4a8a82ae4e606e4faf352" },
                { "mk", "9c280310e389fabfad4bc7ab40eecc05a8f0a18db38314217497c405c85c5b594f59109bf5e5cbf5d85a70c8f72675ec08d0ace991706e6f3446f194585e5382" },
                { "mr", "ca98b8ceaa5f5cd7ce57e59e7c891a874dc7c550417872cbe7decf1d23a18250f7edb4d36aa9f80f758e03fc5dd1c633ce3fed84991d70d559031f644d624d95" },
                { "ms", "e44a7906b3ffb8169303728f93906f4f7ee503a09501998f4ff0c609e8fd9618cf71b6772fdaa35e14e8aa6a2565b2c42fd8f5174761685834d107a7c0f8fcef" },
                { "my", "ee5579533f9997997f78ab795af711f5a1e45b15aa9f7ee1ba2a9d0755b9c2aaebb5a34a443cf481345bef5bbf8edd4faadc6d93ecb98febe3aa644781fa63b0" },
                { "nb-NO", "b640cfd71b283b5ab0b7b0647f28d5f6cb522c16b7a956e348d1594a51403139b8515f9c81eed64b6fc955e74f98a8c28c3570fdc5199bad4df471538ff58401" },
                { "ne-NP", "c3378ce7bb27614683aa9a7d6dc8e1163479d30fe755b0d26e94d112651ee1a88e9bfa09e08817e63d13b6caabf30b394db767bdcd4ce12d58d5a21a3d6fab24" },
                { "nl", "90a41e5103d614d7c1262a19b7f27d704d9beec99858084b552794d4900e391cfe53b11a8cad1484c9cf9bdf8632758ef49521e4bad7ce48cb47be423a414f14" },
                { "nn-NO", "c8fcec038058dbca78cb089931846ad01ae751ad0817aead9a9487141871a74f265aaff35b22d6779ff7c326de58dffb5714c4d42213ecef01fa0d03966e37a0" },
                { "oc", "39c4de34bd597c08cc4f470ae8e804856f47295d5302844aa43b0eaba7dee4a5536834a202a3f5d7c9ca96bdd72fb2a7668370d846366ed4443e0aef81db9ee6" },
                { "pa-IN", "eb762b874a5d0f697c5b32c38aa2efebdc48d1a49c40d4a4025b88a11107bdddd5ac50f93fe613b8142380ff85413917a2083741c95f710230821da625ef6af1" },
                { "pl", "26135bd4734e62f786875dc3dabb0fa1531bcf89d5b540a487f33202d050d7b449d4d46f02b8e6758d54e8cea553d4d1110569297218eb2010aa51680d62c6d7" },
                { "pt-BR", "fde399769e78fb3e6f352ff0e9a759cb1b3331103b4f4bed5d24567edb90d2ceffaeb57d7753dd814f37708e80ac8dfeddd2f8d2bb7e4783bbd831eaeaef06a8" },
                { "pt-PT", "feeddb4ead5af39a6ad27ed12331d61f42364c6f79679cf2e261f86c233fefbdd63ec6af78ebeaf32e5266cedfbc2e34a22a59e563c2c8acd4b74feac7c0d65d" },
                { "rm", "608ea5f24be3f14614d38b9043f557c97a71c26a201531e97a2269569bf904223ee24561ccaefde13c1bc5a58587f85464915eea27470499cee8e83d3e713b0d" },
                { "ro", "6c7b32bf482e187cf64e3346e569da6f504d257397bd260e7edb0d78335eae8016f87a9b4d0e993fcd4e76bbfaa170afa25507c0b20782835388f2c7dd059482" },
                { "ru", "be82dc2acf8e471ecea92a2a0a4771eec811ce53501b6582d03252f6108dc2ac82afa51f15ac322315dcd888b392237952bd2e6232b6feff644a4cb3e9904d0f" },
                { "sat", "c0547e6d0ea98b1aaf667a109bfbd8d875eec76400a2fd54eb845b8715c3930c2693ff1ba4b46cd5f01627186ebcb01488c200ded2f9a843f960b22f490efd7a" },
                { "sc", "e492cf3dff00fdad745e2cc4065cc2847dfb3ec422ef4db1e3fdb35927747223f15709d8c9216d6aa327f99760612b616476eb159e15a7ce94d8425e345ca9f8" },
                { "sco", "77c2978937c79f73582fcd25b8540c93ffc1ac0b720db5070c0017034a8aacc290ff1fe4bc879bac617d6559498cfa841727647e8aabce324322c8ba40fc0ab7" },
                { "si", "d1d3977b038dc155ee2d79e8276c008eedd04469fe879f09cef42b82d46445edef981643352ced91c938ae8f221d2fe7877eda45289e72f2926efd1f1ef2b0c2" },
                { "sk", "1ff5a80ac58bca64fced187cc432ac3e827de2485c0fe547ceaafcb5d8f72e0b08f49847ee75b21a32a311e0ffd7b99d285043606dda67114f042801388d0ddf" },
                { "skr", "01d39b6c73a5d272b24999ff3ceab0c93f2a1b5bf9f7a00fb653d68b641ccfe07367822e17a3d22acad92da40151635a01c43f695635dbd69dcf4cadcb0486c5" },
                { "sl", "16a04a78e8da0d768c974cf73673320fcbe93f30d9a825a748921db54a2355e58ad1dfa40ddcb475a08793195bd3e1bcaeaac580deb4176ac83b60fa4d6c39ab" },
                { "son", "d4705568b0e0a72d504c5ea62dd76fe30b5485c607b2181fc114392fc5136f4cb3d1a3760d293b19e94fa0f234b5d326e076c5120b43090b2312829465cf9d53" },
                { "sq", "188ff4f28222f5aba8eb2608d8d3762e2dc7830c1b17f1edcf9553e5eeccdb72636f8c5d2e2e8e850d0bb63805425718ae93bdcf1500a4122eb6df308ff4ac37" },
                { "sr", "61dc457bdb75dfdacea4080a4b70bf6988e499b59b87a83c52d942ac5c7de98d325747b1b190e24cb7e9650d773f5cbb187e11b3419855aba816cf9ef2fa8f09" },
                { "sv-SE", "b200d77e46e29f25dfebd0b8b4752b1bc5b4ec1c16d54cc96aca68d36bf27f958143eea180acb8a3f4c719207db3f30d93c0e148add1fb40ab4bf7e3dde3a7ff" },
                { "szl", "6d600e2bd47c52fc8491f49caa6d9ef10cfe2bbea6a33e21d740a7f794794140e4cb30333a4a0dbe6d2eafa97fbfe444de316fd578bb2684f3ddda1783dcd908" },
                { "ta", "0cc2eabe1b447c20d0b187f47563a268e3b8daac1fc5be41e7d45e81d05548b413a4c014f0714685a994a9890d11f5747f7b50c415040d7104603211eff381e5" },
                { "te", "ed39ab8cd064337eeb862ba09f82c86e05a3537d64bc49cf7f444daba7bd3bfd7f50099ead9e441c297a1aa860af14a13c845ffb7a23c506ba8c06fd09cc282f" },
                { "tg", "5afd34cd40f291f0d3ff84362c902e49c6ea274f9c69716de84d44e3a4d3db50c5ac95ca3de85f66fc226276e33a2c356bbb637fbcb217364c41bf033d0a7ace" },
                { "th", "8c3c63d9c4ae29e037e76fa768b6e4ba675e685433fcaffed779ddda09187110cf9070b514c185d30ca0792fbb6729fb3a4d810854f8f168903c089e6ca75f97" },
                { "tl", "d7e6fe5ba7c466ed71ed86c6a1ef268d486da4c9d0adf871a278acc9e9a937f0b5e18864c6839a4395d31654fc6eaddf422d3581dcf355702c0decba59c23f3b" },
                { "tr", "ceeac1a08f5ffa337c5735bef7aeaf9d8120f2c6135f431b506e7f2a1d49dda7cb6d289dfbcfe874bddfa67336ed310e0c0cb4d6f8076834d70e2c0dca50d7e3" },
                { "trs", "8d8c92ff62d5f9d548944cf7423d76bdc90e5d6a47b7798635dd0f69b67588ea3cac9483c53b19aa246030fc7ff6067029511a57e6920224ab954e34127d807f" },
                { "uk", "679da2ec7be7a45187231fcd07d6489279f36159560f4e8e2e97a4008714d6e52f309953943186cb1c7cb8afa8ddb6ec8b2b6fedfb9e10f92e3a9260fe3f5b58" },
                { "ur", "ff160b134a6219519f9028007a6be3049b836965aed2727f40c5f7af27cb9e8607733f4e2a5e4c28815c183c59abf14013067200b4f28ba61294f947bfbc53ad" },
                { "uz", "3c91bec95c0da2942467d383a43bd89d62309ce74ee93326a612c56a38f6c47308d038f5ef2ea491344e62ea7bdd8395131d9c92cb93b0c8537099c4ebd73be3" },
                { "vi", "ad98fa621dbce1d5e43b617c938e2a7b882dea5328bc9923bcec24d59d48209196a042e75d9465fc42c311d67cb5249b64cc508188870b5801521d4e3e0504f8" },
                { "xh", "da2b1b423b36a6841361f8d39a42d5c4aeb3f15f9be1d7bc85f12b0f9c1e94702ef9ab544d1a7e6e97306eff92383fdc0cfb8f8d41a5a3bb907a727d1dba8c31" },
                { "zh-CN", "57d8ed385a16c6e6b6ee0627493328c797c7b97934c7e3b4e7cc73083159547a3c0689b3afaf11003710ba60ac80867abdee229310286f03c565c2df5903309e" },
                { "zh-TW", "de778184d020f971d29910ec54bfa2d130dbc221f391a95e338ff1846927645f75d4d8fbcafbc7fd2b774b3abb45c0ab042107db56482e047aa6763c3f2092b2" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "99f645642ec2346d07239b7749f2db226a1101b5b1f79647c590e891b6e4323101f0528af2bf31591a7e25912789f93c572594ff42f36d81684e7cdadcd0d8a9" },
                { "af", "37564ad104932227068400718b49ad76e82b7353953c1aa7ba952b4918f15860364022d95e59b353d0d366f924c112bcbf86663209ce888d5e7b7fd89b009f01" },
                { "an", "6bcae417105758b75b27d160b7ee9e24d279c6dec16c9f07c5729e33151b92ebbd0e711543a284daad0aa5afd1730a1b02e69f49ece3988c52d8630b2be92b2b" },
                { "ar", "56b7a0c9bed528bff81eb7cf0667f988a7fd316f87b48cca16bbb17bf2775ed82b66a6b5655f23a23ed36986620bf187a93fc49c49e33d520488d59fc36c219d" },
                { "ast", "669dbbe525f02ace47ccf884aa3ec24395b316c98458da87b487b0972b7d8c22463cca57217c2c17bc3aad0b95b1a6add60f7faffb2f19089b71cefb68a61a5c" },
                { "az", "9ac6caa1781bbf50d6c907dc34cc81cc36b7d46f8772f5fd8f488009b90c4c7d4e3b10713e921ebc459ed29ceaec3645bd31644d3e0360cb3b3ac11c344fde8c" },
                { "be", "5a01e7b4de365aced5d3ab843cc79772b50bfe470c38ac75b37ad6835330edcfcf93e6f1071c47accc0d14e51142a6cdddc5fae3e2ffff78598f0245372fbdad" },
                { "bg", "d06820c4fd2708f9a495eef29a6cc915b5b4760f653eae26dd8d35fbf6f9cc99f97ea50980076c961489c5b93e81ae4785bf25aec58700de79d8cd11d5c25621" },
                { "bn", "1869b15284d36c5bd2065c9b9203e9cdfca0670b4eef932773772eea4bf5b7a468ee46015a4824c5090783bbc14555f88190b7235429f6082718c6ae1d6fe324" },
                { "br", "fd0eac2c8a17b56da5e7e7785e39a1438e36a1afd4f16dd092ff3c4de8b773ed25bebe4fb0b04d38d2da56c66caf5b481eb6618cf90dfef7fc805ea36264a9a2" },
                { "bs", "0c563fbf3fbee64aa8af3c88c35b5c665be7e8779c712aeb21b2a1f628829e9aeded1f4e972a1856363f6225efb8b391f2c42a772f56b96a3b5708d1ddba167f" },
                { "ca", "67543695a43e311740ab4656fab67e4dc9b1d438cbee18c082c59b3e7ad7434c4f2da82a725fc8733bce1612b9927428d44c6682f4a7b320c358ebf74de661f2" },
                { "cak", "1ba1a74b047cacdd4131f77f638c32e3c3a2707270413791bd421175dd6ec62363e5089ed24ab04acd02d7c92f0c52157a862f8357ca6b6a9bfbac960116b6a3" },
                { "cs", "fe943a84569618b3480fa96dd68e43980b0400424ed783597c60c7d944bb108ac948faeefb4b0b337762800297daf77f7df6dd1b7cce2bc55ec58730e7278e1c" },
                { "cy", "1add337d0c504609c2779c2e42554f9a8734896c59661dfb4b922d7d2439c59c4c44bed3ba0c491849e5f2d560ab3b0d43d4979b640423c6195a36d0ae607c03" },
                { "da", "3ee098de3f9143b30d02c3320f946b0444ac631cc5e3a3112b30704542908dec2f478618f82d045c031d819aba609874d2ea57cff6e5c346909661ab33e8c770" },
                { "de", "c200af2a73559f7212c830181fb3b0d215722b313e223e08689fa7fac92b36e6b7e5f94396fe71c384e05c0f9a02199496b594e650907b0dc26db759706b2573" },
                { "dsb", "29a8e8d46ec18957a647ba0ea2d5f96dd10312584e175d85890f60dd881c86caf2b070143fd9112d35e29f0045b08d05a37c148bb50ed95c79d98b15cb79ee23" },
                { "el", "067acb228e6d25b4c07a782c4b1e2fb43977cb230289102b5952181dcc670746ec0a822e9cacbfce84eb330148d6c987a89960a4586f552a0a3d726f39a180f3" },
                { "en-CA", "55ac129942640a332d06da985e124cd7a61f773814d2b59320b90a054c50820bc7dcfda90446a652d82999eac058cd34e465007584a53806ead60614ed3ba6dc" },
                { "en-GB", "2ed223e73e517b8599c77c63a85bd575eb8897b49191edbf3d53b9691d672e13507ec553effe927b814b6fd84d2e6888f84833e128e4c933719ab75153e98259" },
                { "en-US", "baf98170db90d4444a2609493317fe817d9f4cc8e3fe73969ad5a4e2e93552428f3c5548d4a16e4250600a80390054a768288cd48a1323cdf0bb17b9cdaf6dfe" },
                { "eo", "b70a7eb387745637919e54837d65bde97343c09ac909e191257c6e64b851b070ad7b3f63eebcf601d09ee74ea6e1ae27174870b2bdc3ae4718d30e33da12104a" },
                { "es-AR", "c44f175defa05891831449bab0804ec6f43355a1a0a43b109c8896b099c0ce3199c10f6754082665db282c94d73ec281e45155ae8c56a99d4f30c3ddf52f3fa4" },
                { "es-CL", "98567b026d3fe81c0a93dcb5aa3d3b42a6dd756dfaa19e4982293fdce406e86cb8283baf4ac62b243635d9b5952653d52805084408c3af1f42f4be72f0bd7b04" },
                { "es-ES", "611e81d6b315042b32bcbf8f8f9e29116f150813403bb6ac2fd0a1859397ac9c5eccc0e95185ffac2607a9ef4451cd7fa18c9406e95e67179df6cdacd8190412" },
                { "es-MX", "d1587c69ca6d588846abc5495ac66cb2a2911a2583e51a63a0b0a3a769ab9c49d6986729b4fa2131c05babdbcadf343a6f59535040b203a12edde820f4f4799f" },
                { "et", "eeecb133215b2972067415168ada707bb307c582e5b5dd038dd1da6380c5081e7e2ce09b6b53b4b1f0f56646af228ea6c1f885345ddbfb6a9b2f5f1e95560aec" },
                { "eu", "35733a4fa919fe4af3bd8430afee83adbf340f790941988661cb390efa627e2cfa0e906dc9557af7d93b16386f3bc370dcb259b50e7177e16cfff8db770941f0" },
                { "fa", "2d480fd8fd545718a93e8243f61d432cfb374ae1bf0190565ca87720a3efb68fba7425b11ac9713432978138e13a9a7388a2776e4e20fc211d71218369dc2e6e" },
                { "ff", "259ea67da3d294e6132cb495978a3d3b4c03f6c1480867316348f65c903d907ec9c255c8389427523e5374f16855c4a948a471281ee1d4f4d60e48c057e79f55" },
                { "fi", "f3aed4eb58bd1188f86f56c9188bb8b4fb6057a657b9fd3a464cb2e5ef8d1e1cda8a582471bdda619e368bcd0b564a8b30ebafafb2140d0e448096e11a37d618" },
                { "fr", "aaa06be313cf19e21fe56c3dd8c645469de11fd9b910fda725abf26e00e560b7cadd95a258e80b7d12189d9c215af164a56c04dfe82c8afef74d7385fbad8377" },
                { "fur", "75e8c230ecab638b96da776c6301b4b1722b38dadef1201fc1ac69454e8b1a941635de0753ee25627a3770375f190285cf3bb448bc7e4e510cec9d06ff35378a" },
                { "fy-NL", "9123b93a18dd7058ad71cca8d4d2535455e764714b61aacd30e2b7ce5dae8a6326a559db1e781025c0b34a5bfa78bfc18995ba17925ba1f35e9c3e6df1993c9a" },
                { "ga-IE", "b4e483cae9da3242afc6fce6caf43ec929808a2b0e4f9cd517a635aaeb24cc766c4a91f8582cb9e7798d54a428c490a6ca40e5686654a88df892f28a43d2e2de" },
                { "gd", "86e543b6d0a83ca528854f2e4de44c5333cd981d4451edfbe018e152850e601d1de05f31be274dd16d86977010ee665a49567b50941cc9e05a6deb40c7f5eb14" },
                { "gl", "c9ee656536286514fd8f39717d655838fde7a8fabfdc2c5accc59b73c99875f812cc683facc5a2ea5e6564d9326037cc83e80cc4e74dc4f72a069bb9d9f57d6e" },
                { "gn", "7e9eeb8f7063a66cb56dba49f36bacfb9d804dafc9fc14ddcd7050f9192ed9a4eb03cb209ac800b880798829ba5eee1c99d205058a014c1126aa5060d8405d11" },
                { "gu-IN", "3ce11bfb0f6626b16d8cf8ea4c850413e2e28768e60013d2e50ade78a4953eb37a375e1f06e78c280f2517056dbac3d5879201f3f1d5c018d2f26a2e440e8c09" },
                { "he", "4cd223a802b84164a657ff673d43ee727a16cf7572503e9543deeb10401a72c4958cc798c247dfc9e27afa1b2bcf42a81eff46b6f0bd45edd38a2a3c778e5a19" },
                { "hi-IN", "8f5f5c508ddf25efb304d997cd22b8c934f96449a0c70ea20036f216fab25442b53545fdc9b26469e658f2e8d0800efa7ec81f0a360f8f321f5b9cb2afa436ee" },
                { "hr", "35fb1e33dbf45c2ab506910541130d9c086a4bcbb62b7c8efb96139b70c648fa4f757ab41a2b14fef9bb79e47265dc0af87cfedcff54c6e569dd7db832eb2a98" },
                { "hsb", "5ef351b2ea48efa4a814d55eaab612882bd696ef5ca2b66f981771dced54c7de43f4c0fbdbbeab4d21a275761aaa20da69c64475bf017dfe2e43011dccf2b8dc" },
                { "hu", "dab90f015340c6f77c5a00bb2e66faa4fe021cf1aef9ef811a3bcc9da97369509f3854acaaf8367d15bd323dc3e9ae957994e6f31de31ae646fdff0c0c3ae02c" },
                { "hy-AM", "e4d22e96728e31dd4d71fdb3fef3bbaa4ad2600f47a53cd5b233763453f8ecee8ce9ebea5b1468c1f3ab8d44987cd77548f6a8167a77dbff9596f0c462e63e9f" },
                { "ia", "b4db547b1266724ad50d53db0b7c372254ab1226f1ac4c88beaa50a7fba1d60181fc6a04e269462e7830f42d3d52135606ac89b53e61983ca0a45e4e3fd9062a" },
                { "id", "223c45b8109fd0fb050bedca974a91d8504f022e6934747aa2ae51ae3aaf48d29a656ee3c84cfe4e0e7f06e697dcd53133f97740b47c5ff26dc159e020db7ce0" },
                { "is", "5ff47c2c4712a7fa4fadcf4c2f001300897ae6ec91f11ec623c4d03e0dd6ae25682545520f698f35e95027217517c865537d13ed4f6bdce780260ce1317cfa4e" },
                { "it", "40bb1966118f62bfdafe8b0d0a00c8f1e4de8c859a5672c33198189a617e36883bd7370c5393f3e1a97a2d88cf16920240a7d6e8d87c8b4697a551610bd25995" },
                { "ja", "85b6f0751bf4e2124c3fa6b37060eed51a391ec8c1d449de498a29d4902112f36189639aae571a1d2eae889ba7650c5186045bee8c65e1159aa0019561391236" },
                { "ka", "c3bac702c3101f9c38d183e4025b9de76ff5beeb5573b02b132ff746d1a53348e4a92a8205dca0094308ef4ef553c1ed0ee935becb7f8ff1529df212770a7e69" },
                { "kab", "2c07d76d1b388e420eaf02cdb6b75aedf71fe2c2619067175a29027762601d42d0d737d0537b22ade892530ca1992810611c8f12f2845fb9b0576adc3a8559fc" },
                { "kk", "3a573248163b736f3e3004306898926dd12375e99b8bccf5f8b617e660b6f031f6c8cb3729c510643772dbba353dd674ee632afe92e5a825f75c093250771a5c" },
                { "km", "a6c989f2013e16ec35e9538df29242d5ab84b969c0eae0f837187d246b59712fef56e475920e43563dce3c3d9f909a08fa580557ea7361922318086097c3f701" },
                { "kn", "fb8865e18381aa1cba492878766f90a1c28299c3da51278e14b12b244f9d9514468faa67d4f1cb036bf8609bc3f1f9f1b062db774095395841985a02477320f6" },
                { "ko", "4622bea30d9f2ba5050fa917ed9e2d52f0b190b39759116401fcec3abb3b0367f0aa8805c5ea50ba4713f7aba938c413deccaa6aaf8f0a7fc1883a202568cc61" },
                { "lij", "14fb55556bd2d259dab973e90a805cfa2e2e9556bada0b4117673bfaf109000796eedee7e1681a44470ea7967db9105db76b83b5d9bc78f629538c178a46e681" },
                { "lt", "408ad3fda9a97bdf52ed57e22756df032e9c6b14e3a1a0ce220c7078a33cccd939c115b44e7ccb89a998a34c88a2d9eb038150439c4cc2e28064331e741086c6" },
                { "lv", "7c874639d3136357a38de4c23839a2172f857021b348283f73dd2ea132c36245081dae46d5ce0a2e33fd26db788a432b2b6d668bf448d980ba6083b839789caa" },
                { "mk", "c548ea108a8323d89de1f0ff4cae039b03d73a6f2f1b32f81cfbe1e3725f062a5520cafab427dd3cda03c4aed0a4fa8a404678f7971c4897e4277ab36710d979" },
                { "mr", "0edcd2660d1bc4cfeca7c42120188c8b4f1f0f33b41df096feea633099b323b6688cd798d0d8203df8c2f20a7d780b782075c242921aa4bfe0d32719094e004d" },
                { "ms", "ff8a98f4605b064855029f4a3f2bafe46ac9f2d762a7ca00e905480356c9a44977cd80585f334ba60919f235331abf7f4934b756d21f081073f5c7cc0628ae92" },
                { "my", "5a2efba8e1f815e5f64acac34674210863c4db94591d3d3f2b4da416650e42382b38769ca51cfd8c91daca2422c8e47820af7570d0e25d028282396398afbcb9" },
                { "nb-NO", "94d1f71b8e45710b3eb1d6f09c5d867e217575448dfd5cc8f450a277a2547e610f84bf9d536359bc5693330771e9707be9ddac1620e22ba50e6f902da7bd2c91" },
                { "ne-NP", "2bbb1a2bd76269fad7d642a37f042010dd7c47612f2b8d6d46bb1cab8cc7b0863caa9fc1d67f7f0a69ba41b42fb8e93d360f82302cc24f94a4f3e0c6f05e4b39" },
                { "nl", "06e14ea40f292279644775572921d30adcd70550b9953fc4373b8199f13b46ca180e7b0fcdfaeeac5d3d572094530eb5a6128905b083f22422d3df594ca043a6" },
                { "nn-NO", "3faf47f10db36dd707fc90cd07ab5cd9baca0cd5af5c7aed0ee2de67d24a59a08c132978daf6fe088d7c36419ddcc83942b83034950c72bd7854909f5009e8c3" },
                { "oc", "7edf6013bcc0b7d0384e463fb4c155bf0ae96de65e8620e3eff186f446307489e1546686d040ba59c08502c5fe16417c4c4dd78f41262b8ece5e10f8832db92e" },
                { "pa-IN", "a28d3c1157b19e18bb7bd93967285173e2b9ee0e7d21ff050f0827affa922999685b2affde00ed637f2625ae25ab62e1d53c99a0e8554e549d50ea08e5896623" },
                { "pl", "c0c27ca257317f6409824d9578ba986c0e81402d60a32db66e2b0d4a93bae6162f5c84bcb6b4c3727b58c78da37a9a195c60d1393aa6aa34f6e9080dd50ff5ec" },
                { "pt-BR", "e55fedf8422a81a0dd9c8a7f3c0b8cba052196712e17349520d9e5a8edc61e75e5fdd7a480a58059adf066cf23fc6d7ba30a8709edc9be2cab20dd7e88a42685" },
                { "pt-PT", "17206550e4dffd76cd90f9fb8cf14c6c05ea947a463c27b77696a2d84313e25eed6cf9913bdcee81694c8ef9514491d2a59d1f836c7c4e8abbb6ed7f2037bb0f" },
                { "rm", "090914dd75524320e4ed40aec42ba3daf9a85e3add4a378a4c4e73fcc723ae4437b652c10869c9638a8d4bb359e332b83503cdaa9c918d8411a868e8f9f56e90" },
                { "ro", "1c56b97f12124430511a50f7cfbb68d43294e94d120b0172072fa24a48e7783118fdf355308bc5d7a91592e69ad4def52f92bedca403ed997652b3012727a2d3" },
                { "ru", "9e71dae7242bbd0aa6022414f92b97d322d70ae4a2bc8781178c218c965bc9106bcc8bc0c18d5aa1679c762fdae6091d5e99b7fa8c0ec6d235d3cf898f1a1576" },
                { "sat", "ff4507b264807d61924f7bae5b68bdf1aa379598cac6cb337fd7e49605f7bd9bb47584c3e4b6d704a850adb5cb25e982c7ec4d26b84e4e15703a3ac19c707854" },
                { "sc", "b5dc650726155fdc8b876be1ac514105099611b0da83e1b583dd7b3be1a3afe00d48a58e84e7cd035e724ed7280cf19324271a0a78de8128337f57cd2f21ac4c" },
                { "sco", "4d2855cf865c58fe5e3daf66460cd86fee9270d1309d5d448abd7f27d361db97df519062972e6ddd20eefd724940d41cb1f85eed33c1196dbc9098c51f136cbc" },
                { "si", "eee40fe90de2d0a26ac5c00cd983271f2dbe1b849dfff20c5f6fd8e077b266cd464e661efb070f572ce5c97e89070a626645bb7956f0f6f5959c9e7f04683491" },
                { "sk", "af10d41d9d911e8d8fa3c5dc72cc618d9a7d6c54ed6de8e74fc17b47732cf90b8989fb6837adb804df7e0f01fff302fab076c405322bbdbdc4dac174c206262e" },
                { "skr", "7961fce992570e43f892dbbf874dab588e99e40f902312d405ad3f81ae037717b1b570cc911a8980680efccee0deb4ecb9b4858da7ed2b0e52c6918476cff6cc" },
                { "sl", "296b16cf943e4742aac1c5c86f1eb36286839406faa566784a4e41d0238067d1e5b3068707eb096bec93b7f166c7d7ed65459b37aa4fb72aefe63c6ccc9d44b7" },
                { "son", "69546f88a8da6d6b1f4699a932c1d7895df91e94f726d4701609be96bf0056fe8ae99e42e342aee2a87a39d2c587587e9466055acb418a4db80a41ce8f24b980" },
                { "sq", "57015045be2f7844925f2ec29ef97b276030cd9d0256c94c6d237eee202355373e3346ef6314c3f6e1d7753a91ae236ad9d627c73ccef9d5063fd42a7a3ccdc5" },
                { "sr", "de11cf0083755f7fa1377274d9e570d2032fdf89cbcd8a7b45f4531c230314baa98b1293f72e2efccb5790471470e8a9b475d11678e89bef2063b27015533d7c" },
                { "sv-SE", "57c24c00568b57a43ba8ed5b342955dc098e5531faaa6bed03cb7cbe367ffc285bdbacb63f53a8f611fdff0491956923036d7eabf6a3111dee3258d986430740" },
                { "szl", "fb78992d1f08900e4eac70fa5f20a5b8c7cd41a47f780691bdb1a6a5ea27df2eb78d6f3a2da04eb00a1aa0fb9449dffd8bb4f732ad1f1ecd5686fdc0a2986fa0" },
                { "ta", "76c48adb7633ca964ff4ceab937f928331709ed24943a613d9d1bdda7174d36d85814f22ed405e4c0e3b1d697375a4a204e87caf4c90bc95e5d2b33804867bb3" },
                { "te", "f1699b0cc3a53270392febbadba6ae041e6ae5ceea0d07ea3deb1eecd7e87770d98a94dbed8f18298006166d5d080e0e82e913c66267adc1227cb6f8d29f7037" },
                { "tg", "f07fabd078fea65c3d62da969482b489eb96d066cd1b81cbfbdf59ae38c369f26adaf024c50bb7abd5fa2210e055a8f5d6d0ec53ceb32c842036ff7a943fdb46" },
                { "th", "48deacbbd6d5f9e33d55ed280efb2f34e6328086d21410c1a5b4df88aa06538a71642ecb69b984c56180c1b2217b621a29185a2672dddeb27598a8202055bde6" },
                { "tl", "dd66f9cfed3e9577b9e2ec59b739c56d4bb3dbc035428719448d13fb644a2cb0393ed5ecebf58f2de22a27cb02dd96b528af1c19a25b731d492bbfcfff63ec3e" },
                { "tr", "eea1a66a8c34a95ba0a21fcc17377ab7ba819284253e1dc6018ae8dd57d075f04613340f183c1c75c2d19577cc3d47297c508b212d268e6cdcabafdc427983c9" },
                { "trs", "4adc10df4138e76ec21efadf3478e04e7b962f256e503c8b28f23ae43246c78d7039c0ea966f89c1742c04269d69aaf493b597a859176cca5345a2c44bfacb13" },
                { "uk", "891d844e0bb8cbbcfe8a65f86baf1c26d59c4eaccf732fedd880d1806efe7d4435dfbc4453dec47198277f7891479f72063f55094a20c949536b0726c8628388" },
                { "ur", "ce84b5179cceaf9c93bb822fae0bfa8cd6a2cb45b39f6ad6f5b482bea9962017f0d8ad26909aac889d00123469e06387df8ef1c137c84107232ddb907a150802" },
                { "uz", "5d5ed70505a28d65a95e32b14c14526f0f509d61cafc41515151af86911ddc83b2a6bea57a37de452e333b94ccefc3cfb66b7816d48a6647ec450881f3ce559d" },
                { "vi", "8c142b49f938f0a3494eaa04ec07edab976078c921329c1295d662e924abfa2b3b097bf907e905de0d8efe64c5e3030cb22fd003f74c2adb4208e32e9f460b5d" },
                { "xh", "ff38d91141d9f7c2c276c4d5ab51feb62d08c68a98bb4be39c8912a4e3f697622c7ce71707e11ceac1af38e17ca4f377c2cafdade998bb718ad8aa16b5409b19" },
                { "zh-CN", "cb38a70ac6ce22f7cf43f7169f75606f10a458e9ea31a866fd6e8e6301a34cb3ac1e069de86004ed4447d56046045b9cd843e55e17acdac0204b18581497b91d" },
                { "zh-TW", "8fa4e455c08b74704b86c54c7906d0a5d12a415e933a660f892444fc55cb08d538343433d76e6fc273274bbf4351a3945b8795cd6a85f4e23b20bc82502ba047" }
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
