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
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.6.1/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "abf2361aef6f8b4170039a2c6b4f3b79dd3e4322651975357ad861c04d46ad118d9672b1bb97d5be0d804d66585392b17ec0b0e2401e0747fc6333eeb3f7fc5f" },
                { "ar", "c92a127a126b6b4d57c32f976cbf0675574b93421ed626e136bb91b9621cb383dcaef724b9f6a3194feacb8f0271af1f16672c9c65a9707a966080b0022cda9f" },
                { "ast", "68e60ccefaa980f2fb6185aa2c448096db7cb4f1badbe03d69d727c41332d4e065fca875d0bf2c4fe65a6871d4f2ff02fd7aeca3130b78990f884afec0d163fb" },
                { "be", "ee641ef0bcd3ef79e4cf10493bc7ddb7bc57a5ec2fbcb76d4794a2b2259140bc268f766c5d4866d117d1eaf510171571f48dcf7a9e276398f6f9bede14468f05" },
                { "bg", "581b03b5c86e6906e3a3bd5ffae61ab68b502542f47ff325da8da2727ffbea7545b638057becf91964fa90a5f4390c10f4e183ee3897159f30839bdb0966d832" },
                { "br", "f80685858c2a9f5d2357ce33456202f05198768a1a50b4e556ba2f5722c639f75dd3f54a1944e959c85a01463a58ec0fa424db61421f022896def1ea5d738dfe" },
                { "ca", "73b4f7a38878dd3f0ca00f70a8d2d294c8258793d0ddb44388a234abf58bff1bfb03ef821e6b144d4543a3aeee88853427ed8f16275657b34e1ec28ba9aeba86" },
                { "cak", "faf75079a52589619ce478d662eab694bd37fac76ebbab7f293d3edd774281d13efc0782cac87a4657b811067d13ee1c8fe90a502a1a0e50366cdc772eca020b" },
                { "cs", "776e7a3612496593c81e927909db70001607bf16534fc6e63cc4697a352e54b9f702c51647622ccb3eaba34e2522f48ea527e3cc4169ecd0365451aa3222fc0f" },
                { "cy", "c3cadaae332b2c8cebcadfa8d2bc84d17b5c215790266acaa9aca436d973dbe8465d4db2a8d105f1e7c6c29e4dd25a62eb20d2d03e6796fb92d600194d74ccea" },
                { "da", "0ce39d83cbdb12aac148d9d446497429ace468c5c616d3c050401f06cb159362666cce17e1b2adee4645b03d8a186bbffad7e1e9d7b652b90ae08900ca4ed3c1" },
                { "de", "5c48dea4377f5ef7fdac17e44176ffd0018e0cc02cf83c90c4c136b0fc7f59dbdfc89d8b2a2951bd19c9d0092609c086ac595666e7606c37031e17565edb698d" },
                { "dsb", "4fe1857c56c6f00df7c5a587f3abc6bf01c1c085bf88559d1fc26a698ec01f127d1bd5cfc0af046bed802803ba6988b345648e968720f456d26761f6887849fa" },
                { "el", "3d992dfd2e152af3aee62a0b9d0b408c92d935954ca00678e3be7c4de7f84a968071a56f7f9df79162457ac46e04d3eb1d9da34e8948e64830b82d5db188edfb" },
                { "en-CA", "0c2c61168ed1c1486c1a5809003c6daf3ab35b23336598e20b362df6aaa49d5850136ef9af91e9281fbbf2e83750a4990fc57a50ff5d35a02f96ce9df4cb7d81" },
                { "en-GB", "a99b2fcd93a6e97577291e6c5ccf0cf5d426bd4c35e8c4cd08553204fe71620c592e085fcb9a056a73172bdb5ccd3d2198501b033a21d9d0061c2fada25805d6" },
                { "en-US", "59a3cedefc9f026c4c45e73ef584137bf9355809e4aee74b6809c68212a560c2499fd45866850b6674491a8a08b4a2d934588980d20094385be8a6a99ab25dce" },
                { "es-AR", "2af45e087d92a6db40b073c193d60cec30ee2565438b6fb59af910eca0f808786c61d1d60f97f7ee75b7455222176fc25e4e58ba2dc1d51dc0150951f3b318b3" },
                { "es-ES", "a419d8cf81c41d30aeefa5e99a97c5c9ef6d58e9085f4e0c8576634f6b311dcf4355e2e341eaf2af84ef7a2fa6ff61a8cb43cf82b4db503eab05f54b9eaef606" },
                { "et", "676d895310b183fd908038fee8caeab34bc24addac579a8825929ad4a18c0e019ed948d9e7ffc41e27ef8b070b0dd49916efb43e6a8d6c5305264e72eb8f226f" },
                { "eu", "85a4de9a6afd8dda30abbc77e1b0d2354bdf5b6b2ed9bc3c6f855700e3c669e618e768bdd9f770387419c43e179cd438173d02aea048fbf670df4a38d045c937" },
                { "fi", "a33499f3b97eb1fe60afebe0cddcb2b558a246e880a2c0ae1f05b938e2cee3dc8771b4e0ed217166e621667d59c8abff0b02db34708aefec645c37652530960e" },
                { "fr", "aa64994b9c3c4567dc23d9c311f8ac5fe11adef2f4a92f41a399427afad8a306365441298f59b4fddcc80e32e384f08fff451c37d3a74900748e7b37d36ea48d" },
                { "fy-NL", "d0ddeeed832cf224809e384e635442d0f8aaafec54cb30a7a7b89139739760696a0cbba518a72760efe2bf8526fd420396616f2f0a6a41ca21fb8354bf928013" },
                { "ga-IE", "dd3cbaa017fe97483d0f9e50a1c3fdd6fe5f306efabf69d4a1d72ae057d3b7e45b85c485b38d9c95738ff4a88b8773cadc6b939107b772c8c305a89643b1b3a9" },
                { "gd", "7232c41ca43e83510be05f048e99e3be57fe4862b337e1b93e5d7b7c62a85f89a61316d71d0ca8985da79a97f01278785ad1d26bf898185c53a36756e64ab3f4" },
                { "gl", "e8a845f662a2b5ec6eb3d83e024bf97f9eadc61864f3e5a3073ce956f3adb0e39754d265a10d5a837f78625de0e82b01afc62df4869d4695bf00d260449c7831" },
                { "he", "30388eb61fd6c63bf4bf2583913bcd2d36b4f63c43f26f535b294481e8b0503b1d253c4483eb017b6ff5605e5a030b43c1c2742204a66ca33070dddf7478ee28" },
                { "hr", "70d20a5e5fe83409ff24a2eb563fc58fc3ca1f56bda43566862b4cb66269dc98d064940fe7852a8e3274585e79b9673f5250b91290956103cc06db72187dee13" },
                { "hsb", "91383079ea031ee7beb8bea66b040fae7937d2a2f8d6ae6e76932c278cec2c62d368721ee245ed2ffa9dd1ee87b1ad42d897976a92e8fe143db3a2d50915d550" },
                { "hu", "85a96fc0d067633cb671f0b76026b7f01ef489377668ba95316d568107eb5b0537bf2d815892cde2c969c5e363fe6b7f90d81e3c5c12f7b2924b1342b9549c1c" },
                { "hy-AM", "4117b0c320b273c7ffde4acdbd2d44627df1ae51de49f5364336bada491c97ea3b5cd42e8f645fa9102fa38106713791e415e0c366fe489c38fc3d87ccb1e190" },
                { "id", "781a79d6133cd4fc472122c6c6074a79873acbe92402d12e9bcbe31557dfa286f0bf22756feb6151f605766fb4b0607f9c483ea5222d9695da31cf2afcc13242" },
                { "is", "47557955c0632420c1b6b86fd5037a61b52c6d71486a51648baa36f836875a42e784553d0f8b53440dfa6837671caf441aa36b3729756773ed20543d81c07e2f" },
                { "it", "6db429f99f084439bdab9211332632e95edf0268d68ec41511e65e9446cf7afeb67ab95b1893dd4bac80de3d5fef63269838f9f49d3f56c931ddd2faa781e147" },
                { "ja", "4321a31e014c00be3be314c5ff7b70499231ea35cf5c19b9b5b4cc896793c81ec2118b374f986050cf2c080307fc7117d4ce0d20fd31074b283e7ecf00f12258" },
                { "ka", "9a3139432592ed5196265992b39343c3e53dd924d58edb0182895d7e43c17d87950ec664c949c5364fa31978ccc86b14bfc6c5dd378a51904491bf3ab0bc6fbe" },
                { "kab", "dc59ab065404658b08d8afdab55c74e75a4405afc2cc0f2b5dfe2a21b5abdbf075f4bd8186b46cf99223755a05671c44f0ae5f8a0436018e66c6df0793675565" },
                { "kk", "6edcf24a0290976a6001ea6c9009d59eb97c90027174fd93e4ccd73377bd1a781c97d11bb8c3de2667263bb455f08dbb22030ee0b53112b038d1f8d92c59d94a" },
                { "ko", "19e1ed27c0b70ee9b320bc09c234ea5fb3a596478fe6e9555e460e305fb69c2089111eb31fe1d1f9858fb005d8a540adf4fd0b9f9dbf2f084aa2248d396b439f" },
                { "lt", "64f1fa930c7896393f47d11ad0e462b02a42733aed1629d7db276314180af44e0b75d3500b7db186a043bb2a4f4a6dfb38528350d0a4f8b32d547df45f383c28" },
                { "lv", "0881743d9e1af834637dacf41ecd99a72b813ca2dc4eba6d5f060f0f6db7cd10dbb7e4e6d3a70efc12b7f8dd81f1ae47690d84633911fe2e7319b22a246f394f" },
                { "ms", "e989187376b1f1635debf79cec8b4038cf5ac6b28a4007e65b52db5e05cdc91fcd76b954bf465d97bd78e3c35061258262a15dfcb655cdd4529efe02aeeeec4e" },
                { "nb-NO", "30c779bc1d9329e472703d9451bd61dc30c3788ca6b5abc6f995c6d437d607f5589fab3da3a919f790dfb89f6ea6a4d0a566fc9dd6e30086dba47b7b5970e391" },
                { "nl", "357f1f979531ee29fa6101ee1c3f7ccbb078d7114acfc5b76a5fa0f2585adf80a0f9e511eca896f6193d428bf9762a3dd5ff763599c0b0b9272d9b83320eadb5" },
                { "nn-NO", "d4831e467d11bdb8566306db12c53b97475ced8dfee96af6e870925dc6916f869c929cb1d9aea7d082f1703ac5dce88edaf355f17f6f1698760a11fa226e8dc6" },
                { "pa-IN", "13ef2088822c2250529b78c2508065d52a2bc9d5b912214cf8cd4a7e2ca13b47113d07d158b89511cc0dfe4b665ac466c07513bbabfc6bbb4f0c45d3531e3524" },
                { "pl", "26e94d19e84b84311e542876c180300cc3906782b06866a5daee069ba04e5c22b86107abcc6875b74084d6d072d1603183e31ce102e51421f5d771bb5ab32b9c" },
                { "pt-BR", "7174dc3795be57a1b7e42fc4502f08849003bece754dac39a16da16acb1b32be354dc15f53a2a8df3b726d82115bc156789c714d4ce5cc8d85c0e565f894db03" },
                { "pt-PT", "a5fe8cf665d99ba1e09794b0cd23e623a3d519ad7bd9cb9f6b9e93ddfc1854e2567186a3df0982a345fd7e0e7b2b3cedeb28d3b96971744c8a3b4b4d7089f14e" },
                { "rm", "550bfd43103f23354639760d94bd7d2d95ce0e972b21121c1e6a803a5b7fb932b51ad1e6e1df6a0e3923024a49e125ed288793372753ef8ddf99ba56d432d480" },
                { "ro", "67cbaa0a7ca4a46426dfe5ed7c9ddea2182ef04200e54c3951957e55b6854e602f48c3800d5120ab18d5b4631f82b6723c9f755be2cca31c3ae1169dad326901" },
                { "ru", "d2e039f26751dd3e83eebc1859e4945a600101389e652938914616df680f2d145fd1ee94073401c7cfe6dc29dc8d2913a513ffbee92f1ca3da2b77d2d528281d" },
                { "sk", "5d85be35541ee42cc63212dab2a9512ba11204a5f3fc8fd2391954342de5b21b4533a73e351265547b16953364ebede704a939db1fb84024413cf137a3f5ff25" },
                { "sl", "364a4416d0ac820e24f2a307240c577d792d51b8d6f643bb454b7515f1b7ad917c7e203e722e67a59344e6edc3e152ff2231c78e23c76725dba0490beced1e52" },
                { "sq", "c35fa2d3f9cca0f7e002a4929b21ca005e2573a58c592bcac508220ce82f0a3805c3fc3e7299dea006f73ff2e658261ab0147583d36ceebc2e5e9cda197933be" },
                { "sr", "868927beee42cfdabf1c62e0a5616fd6f2b1ed8c6309452bb138a525c1dfca575a0476eb3010edfc55c57dbf1962b42c0f678cf09b57c41be674422ca2e14105" },
                { "sv-SE", "70ede73d7735fd36f2675bb734b8adb9f170818b1cf8ae30743261adedccc95bddd3d67bdabaf543a53a0d2a60fbe1a6a9f3816375d5152bc9382f76e4d58be2" },
                { "th", "776ecb1291683090f9d6e8a06d0192c10f3a12949574ca201052d8878a639cf7ddeb805a399cf961636b335a4bbc8ccabc8bab849919d30251b6c1384b4bd288" },
                { "tr", "500a64259ea41a45fe45131d2cfd9aa73e45ef19c3ef70aba7b74394e03303b2bd001eebe8ed6ef39f1cd6f8ee12c56b7db722ae5779a3f5aabad4aa816dbc38" },
                { "uk", "b4c74644cbed860eee8ca1e4c910ecaa001cda87b2c3f0c91f72cf87822606c06c4773899da9e0e9421b00b8a7851f4d49f140e6630da4801fdb4e433e1f7058" },
                { "uz", "c093d959db29c2f65564bd9e246de4e95b791a548f40fe329b8e0349fd05f803788b8d21cd83a31506eaa75c2643fb96b3f2c986117ebeed6cc7b39c18a861cb" },
                { "vi", "c81e6b8a097d7ad27e7f3d46cc8a8352b186921257c6885e3bdc7dda17cc0eef8d290a51e864028b1e1bbdeee3d16c7adfc2fde7bcef657980ed04af2293ac1c" },
                { "zh-CN", "53c80bf939c20d02f9e1a797cc7c67b47b4ec3e60b4c199d265e0d7929b8df007ae1af8fd996d0bb373823d74ecab016ae468753f75c350dead368b136b04469" },
                { "zh-TW", "0302fa42aa7eab2cf0ef18cf6c2e0cdb410c52818bf377557030a8d7952dd1e2383c9b91dd28574ef1c78d4ea31d1fa07185f51492e4a946c095a165ba606ef2" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.6.1/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "534852645a1783d7613ae5e8cd3a21393fc8584c845ab05a37470c0feff4a55591e52772ffed96ddff77792c7de26066e3fb86032cb7dbf94e0f0521781b270b" },
                { "ar", "55e02f635ac544f4ac7dab55a1451a3e1c807246f4816e51ce340b090fc0c3155eb22ad06d04ee6fc4a031fcd321bc88febbc46b3145d001fbe727aa17a1e4c1" },
                { "ast", "a8dbf4bc7f9f590da8858f068ca2f8430c2cc9ab67f9b8643b340222aba3152f7da2db8d8ad4de42d3266d961a9c68cd537f2ce1318bc94a1a0b66b39dd325e0" },
                { "be", "89231a6d719f1c932c8b1b560cd1b680031de7e1907e120bee41c3f5e424674cf869cb4efae20589e2daf45f60ba5aaeb02e6b749cb276314038dada37bc6abe" },
                { "bg", "a6ed5bee20ac9582172e9e67a1e13ba8b66b0b110e1680c3f8131e3d64e4140769460b783043cb84eb06e1879173793c25529ff732584ecc43b262920eb096f5" },
                { "br", "b6bda04f8f270363b21bec9e6ccc8f6b7759d0df0380d06e202eeb43a8d20afe4f0b0c852e577b44535b9406813f179e3aa72b739448adb764695d6ef9087c46" },
                { "ca", "18a82eedc40094681168febf27c5b688215a5096b37575fe064344d311228894d332ed01ec764157592b3135eb01cd9252ecb4d5b48e3a2040b0fea0b05a59be" },
                { "cak", "3462abc8ab982c6eecf9eafb8d653f31cdf7a37de2e172c770cca75d5f19d05b159ee00dff00a713c6261e1f0f0b97c7f7709eb73d2c981cedf7f8e805845d4c" },
                { "cs", "933bcfd03fde7ace9e4fce47350ced20d62425bca41096dd98cb7ac504cf888d917c9e5ba1789c283d88435456a88f837811322c425e2d6a22a0c2395b92e63c" },
                { "cy", "5a4a0a28fab5083177bfefa0df751cf6eaea6234e6c6341f23f1cf28d386e9ecb8a44cfc789eb3da6d72ab6baf9dde6b9e075df6eb4d99db5410114aca6b3141" },
                { "da", "b8d3fcf82d6380594a81508117d2adf1de70eb5435c8d85f5a9bb6f5ce15f119838c9f1a9968ea8a66a202d507b513900537a31da12b2cf6d559bae84ea210d1" },
                { "de", "c17329c432f436c44600af1638ffa8a79ebeeeb0c7882f7812455fbfcd3e56eb4a0bf8ff888d91e95a7d48e1f342d368bc674835b94a093466bb0be38621136b" },
                { "dsb", "1915e4d319481d1d687d5be3cb157e9e0486761a49d6531af139f7ec34a6ed2c208f1df62a9ad3d06526459aa423c04ce566de916250b1590e2ea0f207f0b93b" },
                { "el", "33c5fb4aa0f7139d2a97a19e566498f004558280268dce50e31f955a00427fd06d51463a7ab2df7e13cf56b9520b62cc4be6a1bc94eaff2f68c6672d2ca61a71" },
                { "en-CA", "cb310fa359698cacecc943a841c25b955cfebc53d17ee14ee06b3c64ba95ab3f9923127c4b30d59ed0134e25149ebba77c3ebb6a39beff7c40c9b8f50cdfbfe6" },
                { "en-GB", "d5f734bc312a642a04afcf0f9f849b6f1f3c9dc9ee2495e5f1753e9f4ccd8065b9590564ea8902571f4bf35170fddfbfb70aea2207dc3b5658a8d27f5d16dab4" },
                { "en-US", "1bfee6b29718f1d07892113a7a99e31a2e13b694596268083fc86a51bd3c01ef395438ecd78ec6b838ae9dbe1485266d7db141696b7dae5e094fe0c596797418" },
                { "es-AR", "a2bf2db1434789c51cbc9b505c105f9d350145c05315c808cc2df51a7ba7bc28210aa84d46399087eea3c8ef41c650f29433fbb5e5241ed7a361642254ae3ad9" },
                { "es-ES", "91a0c05ea47417fe61ccb6669205e8612a9bc2223963d19f99dc0849bcd63dd7c1ef81008613cdc4f73d89fbf4643a2035ccaa2083e6a11c1045694abb2d6d6e" },
                { "et", "fc6666141d8c8991e0f6535a1d46e3c354747ce93b69f05df2aaf3f56bbdf461c9a52762da1ecba18b860adfda68f4015a5eaf9c465923681c748bd867535b18" },
                { "eu", "1aaf3fc5a36b8be262fa8009bd53e9071a1695787fc28a602dce18817360238cdde7fc979fbbc219fff2c3a9bfd8e450e31550a217c0cad59dc0b8f668c2b148" },
                { "fi", "60d20acc82d35e9911a128bbd1afb2e83daaec127eb693438589dec23d3635c076cbcac1fcf409e558ede279a885a4dfb869e6b63e0fc7416341ee1de87d3638" },
                { "fr", "09cdec4da73047a5804b912a5348cf59dad30df63b4e943f0a754ba6a10229fcda4139434bec94bb4e2ab9621e0e3659cf35ea9e5c98d5f56077c12cbb055155" },
                { "fy-NL", "b40ea6edf6724f782f889b290ca7b51c2eeab85d98db960d54eef4ebb2fed204eddeaf9706deb1fb2d543dde64c4a2fd622b5709463bbfca6c94bdbe827099aa" },
                { "ga-IE", "8baf5e2795d59a72839183435d6bdaf876dfde62bdd53af107971d452393ee99272dee37cdd8278168e16f290bf3e11bc244ad93417437a4a40331242cbf75b5" },
                { "gd", "f9530f02743b73d54188235d216fe7d7f1303d2774b2b2ec7f3492aa08193efcb0c11a6fa6d322220254e1ca1870ca0f3760b2ca346758119c76f97b45fbe4e7" },
                { "gl", "14a091753e86a9c96793ad58dd57ee3ff205e1b600e62454cad0d95382bac1b12b17a68a4c8496bc270b1230594857611cadeda82c6c5ed592d4cfe007ad6b9f" },
                { "he", "e4ecb087e0d81bdfe0765ac5555d18ae4fd76b600cc31efd6c5a008183fa765cbe50542761027a50ec5f19fc4523e4783f65b1f2c5379aef9d76e7eb389c2f96" },
                { "hr", "6e779e560d674f6c07be6881144e9c937fa6dc4c95b5f04a1705580f8fcd35f419d16b534db9b8a4a4ed7a8c559a4e34fb5ad3ac88af5fcc4dcc22e50c75f3af" },
                { "hsb", "05f71f23e2142797e48e134e26f746ecc1105a52fd5bf20761c1efc15458a8f742e0a42a0d8217b5644f0f2e441b9fa69eafb807987b98a1cc14b02830241d48" },
                { "hu", "1f918d8dbea40fdbeea7bc4099862fd0c5c09e526b482c0641ff56b594d426ea42f536bb937f285eee72a86ad78cf864e0f6953149b5c133ba96b0eed7c93e08" },
                { "hy-AM", "360d86a4f0c9ea46b0221024a29c798d968e48f17326248499f22d261a3cc81d073e642c4ccf8abf7488fd1b45930f12cbbe06074f5f1562fb65d6849260db9f" },
                { "id", "8dfc848daeea6bb03a15029602b83784520498cabd78472ba411bb465e8124cd1a918d7276ae48dcd93f1a0ab696e4667ccbe3785ce889181251eabeb2de943e" },
                { "is", "80926bf17384ad13f1263a52da4ecb135877aeb656fdd0e77000f1364ea8de8fdc49f96be3155cabd78caf9e7d87853b3703cfc6db9df67c287711bcb1516094" },
                { "it", "71a40ef5f755fc21255c642f980d7eb9121d6a85050d84fc664fd39789c0229ec6573c201d6fcb87f77760becef2adf576bbaa139b7b1734b065ee4c5e666e6d" },
                { "ja", "30900ee6062b13e20511883a3647712040d40ecaaf16c4a37ae0131a76a1cfe4527f26d75a64982f5a6878d666ee081a7ca2f687c0d8db81eb42f6b0c7dbe606" },
                { "ka", "fca49106cf1b48193680bc86b7939cc17921a1d31e12ce6c8e6bca5a0fcd0d316e5e40d2ea4b1a16027b30526c76823cf08339e5276b7640b7fb615bf684609a" },
                { "kab", "f54e01aaa2f5e926a7350e450dc398fef0462a071855b4d0243a1bedf1c6d70dbf73cce4f12b37d0afea106504bbc72c59f403747be73386c6e7bc60a67381f3" },
                { "kk", "7788f4b9290e96352a750715f7a320cf931504ae3290078a255958527f2ebf70315aa6470ad1ae6bc69e53cd5c1ccdd3dd0bc1bbe64edf73d191c26a3f824152" },
                { "ko", "ec947333312da4180e2721fe3ca7ec8f8cd05dbb9997d4fc6a37bb98f1d023196a4aa6b2ec1d7088a05c966e4d541e7ba7edf89b152b25e0bd41911bd45fc94f" },
                { "lt", "86f7f928b756ba45212f6b9c3307b669823dc3551c117b7fe65e02d14d34159598e1dfbf6edeeaa64f213d41d562ffb45ac7fb25c89b52ba74917ae561337ccc" },
                { "lv", "ca3f919fe6dc8bddf62c30023737c2081685859cf478d73e3676268090af85bf328f28a532e6b6b39b3d4aab925ff82f9d0ade91c2f73a635aee18b0068be26f" },
                { "ms", "bba1bf86937aea2d65efdb21dbff011d0546940ad2968d0a78d7a35bc178c705fd145c75c7d807dcde069c19fa84b04fe76c994965282ff00906e81b9c3cbf2e" },
                { "nb-NO", "f1562da46476f8c69d78fb7be6a9634d52a21cc88afd513015c9b566aceb1bfce949af301532f9b1a39b9e5ec7bc50abf133e2e09d1d987d80299792273e1db8" },
                { "nl", "4322f0936daa34bf931aa5ed329ea902103d4431b4200e65f4f27f49269811264017fa5c4f1f1d2cd9e15984fed88663784514a73653ec42f253fb6781c0560d" },
                { "nn-NO", "20ee7eefb009a82f303783fe022489f6756a097be825bbcd770a68cf73a598de4b452f38f988e34856857a94a5b1abb126c496ab3581baeae95ac2ae9f7e8c82" },
                { "pa-IN", "008d79e637bca5930fab187e975e7bd5ea6cf3afa37d8ec760ece6dd4fa14e94bca9ad4b016c854afad0a779b07c9491e71dab5eddad183ef5cfc55afc8ece76" },
                { "pl", "2c33ad036972f46dd81383c5eb869af92c6be20302c91242adce40582925a533a32c9ed403c0e0f48fcfad3d33e232885216cf81b4a4ebddf2d12eee370f5204" },
                { "pt-BR", "fa3eef6856730cdd6c85561c50e1dd4e2adea06282f057d8a7061c00b46e62fc5261f0826ab6243bcf156045756ad7b375c659d1fa8e54c2ab00fb8cd67ad3aa" },
                { "pt-PT", "359fa7f7dc53af850e7332e8278c7d304d2a493700d11d8ae2d724ab8f690a0709ed916be27dd474f28da8290cda657feef5e36c71ec4031c41bb365e51860b9" },
                { "rm", "6bf0816f6048c5c1991fc94b37fbb58d7aa6f134818fc4f950f61e189b64de4cc62d724091453223a67c8fb857b6c9f5553361802129accc3db4a45fa9bd5bb9" },
                { "ro", "b4f586e11257ef926c31b1e3786c82185dd859813a3ea95b56ee303c3aa236ec0011cf0bb473197f39eeca091dd080d4d06e0e5c5a75fe721aba99a14e21bd58" },
                { "ru", "b6614b8e251f5509c087f47c376970b648cf4afaf3370cc7620529ea472646f1303abe844d1f2840412e0ec579caca36dfd468da1d9e6a429d45ec057fd93f4a" },
                { "sk", "79d95ea127f15c2d8f7242e1fe5332f096a4cc764ce765a4f02edf8579f72ee162dab08648a221ced8fcebe5549429f2a8cc22422518a177e70e05c30e39d60e" },
                { "sl", "f96dfb41fda0525818b3dd624216daa726e3ff936efe21a3c1ecda42fbdf36e4ae568b40743d8b7f1d4a075e64277efeb5ba339e157a9b7a39e157717737014f" },
                { "sq", "a980973be062518d2abcc481001031cbaf7f5507824aef30b4df8f691e13dfd43e12c50e8d92942ad61ec2263c1f3a7070c04ce9f1566f880220a610ab57306d" },
                { "sr", "7b1548d0bb2902ff8fe08f72e4e49d277aa3cab284237e8fd54132ad5f5d379e5197373d6fd0b6455121d703ab70d50450170129bda7937d10d5958dbd7d2dfb" },
                { "sv-SE", "7bd811ffc2c7e418fb0f970e089190890ccfe91f5cd87201db3d29833f34aa5d8001438847dc8a01cc7b7b0a2ca4377fbc373238b0a2c56978b60776e80e8a87" },
                { "th", "5c29d215372d6ba50c5c2fda63da12185a02cc5ee77744a4c08ddb433177a49fddf934282fa310519289791b293788381680e49d02e3d3f7bccffebdccce126b" },
                { "tr", "bfdbffbf0484aeda0889936300bdcbec82a7f0d5936ee7d3e72177aa4cd4a3fb043c273b23fa9eb72d1b8afc2c444f143f45151a6633143074eec75c1a4d1018" },
                { "uk", "bfc7ea24f6d430721a422a97f3a17c7f277608c0ef30b31f6142d6120f57bb1cb003e46372b0572c755abf22fcf6d0b898619770c27c88d21989a1d6451723d4" },
                { "uz", "38696710aa304b019ff0c98edaa3e3379667ed01d0c92b55c7b7cbd178edef5eb0cbbc2b2e335a24a39ae4ee9bd85614af77cf560d098f12af527afc9508bb95" },
                { "vi", "c464311344763fd8b920d2b486ef3102967be2ea5b9f9e75b4e2d5a38478344450010ab03918f31c8760615ade968a48730457a46f33827e9570bf7772615f14" },
                { "zh-CN", "6ee4138ed1d939a283416a31c83da586744eab3697829282aaf8c488ec6c7be0696c0bc40f63d397445eddaaf70e8854ccd7cb04b872273fef1cdf7a430382ad" },
                { "zh-TW", "843545ccacfb221bbb8596ffb5aa76b7e3ee2493477fd152ee283dbeb8cfb070bbc3fd71f220859efc5b4b35a925232026d179decdf56a3a25c099641f069f69" }
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
            const string version = "91.6.1";
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
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
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
