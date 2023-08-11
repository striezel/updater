/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "117.0b6";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/117.0b6/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "be6dae4bd1bc8208595a2b2bd9968cf17a9c6ce7fd9e19950c97f6351a79b105bfb9af05f17089567a028b5c2363916288d59a3effdc9d3143e21d2f572ac98d" },
                { "af", "3514ad8a8bbc7df2c8fed120f9560e1e5e9ab802e4873bfd3cd0315fb8c433e665bf4dc330377a50cd315c25f6042430e0a87031a82243d6660588d28deeb522" },
                { "an", "5560421ce0e276f8a3078f0b2dbfcc8ddb6eb18e9cc66068f7e1d10c1c3788f4ad1abcdbc53e946ee73fec10fdf4d44aca88745547069c3977ba9d9f94622c8b" },
                { "ar", "4b922fc5a73e20968e5c2653aaa6a27becb48e506d18bd98ad4393bc716ac305ce5d7079fce3e21046ba7fe997e8fe042b281984ee684213b379f4a7ebec6627" },
                { "ast", "dadd3d22a9c75fc3a24067402bae981c8c4652b619c28a7803d7a6991c3664cdb979fd548620b167f25ada162c7a4af20a0fda34139b8ff88af8d0f7c34016fe" },
                { "az", "8f23080d57ade7ec699edbe9a630dd4dd90f57043e9ce80f20ecc118f85203b5c1ca2268460d33aad701ab759f599f91496fba091a15a3758a3cf4e598060600" },
                { "be", "25d8e942cd9eae3dd8c367bafd2f519c99308bfe55fdd7b9113a11987f0f193c8893ed079b15e6da850caf4445e2093663dd1e547e018e4beb91bd53bce3d4b9" },
                { "bg", "ef14acb429a39b5832b5cdd6389ad2a8b036f3564fa9f958a793f914d63b4f59601d36e95fb68ded50b0f431cc064bd6a21f392681868ebdc24a777472f222c2" },
                { "bn", "405a20725a8cba64334bd67c3d18d9c447ae9881d646f9b94924f1286a9b9f0bc3a852d8c59f8b85efe90d395158c2a388894cda178121a0fda5ba47856310bf" },
                { "br", "4d14a8305b1a54a30cf2c40faa9e1a183df47badb641804c81b4551337815236cd595fc5955b674e6c814796a263ad30de8511aab334e5b3cef6d0232563c72a" },
                { "bs", "12b8546a90f5364577f19238a4d709c274ad112f78481a49e9a58e6843d1a2ae6bc5fbe2fc9579d45a8e6e32fcd0aea2a83a3d93c82b7aa959a1ef6cd77747d1" },
                { "ca", "03ed8a19bc7ee3c4d6979756e981a3c6cc967c119caefce964785a58a85d2f1fe9753fbb6b7ee5f6dcc0df34538dbc0f7735b7c170ea995bca75df4da845b239" },
                { "cak", "589ccac816c9e4f16b089658787ab9e27e48b285296c187974348e19d2373e5e0238fe2af163e3537bfacf8fedd42afc81cba5b89369cc5c4377d6fe1a2405d1" },
                { "cs", "a2fb5a1518fab137a935c80a43db6c6672e1d0ae500b8bde95e42ad252aa50a0c3e6597a184b442ddb5ab1844d1a9e9641de6082f3fea36bec09cbe0d68950be" },
                { "cy", "dec96f9de070af92d27d113219e76878ed619f41668fab8c021130973216cf70d2b7dab0057cfc7ebe3196bff3156b00197baea9da7255d71b76e447e940bab2" },
                { "da", "e8028e6815460e02482cc73688f2199f095f7aa1794d36956dc10b1cd74c70aba48662d7161d4dd75fdc3cb4a628be4ece48cb15dcf4eed70e872399d8a414ae" },
                { "de", "e1ce68ac186c6af8d8c9079f11495e83f303d92b8905291edcf43f99d0fb14425545f55bbd7cb04dacdb86b8000ba99d2af8dc43f6e2d5c82e75307894e5b401" },
                { "dsb", "fdd7d29bec48d96dbe0e1eaf8d30ac9c243a9802884a53bb9aa56d0291ce82fc84a4e34c0919b7599eefd0c08007999636c770fcecf5c5837a1b28cb53003a2d" },
                { "el", "c4ff96840b73752c55a70a49017a2c184bace6ace84454e6dabc4c69018e2863482a20a5ef2ae2de264423e5a10dcf93a2761791ab191d9331718419e1c644f5" },
                { "en-CA", "8dca621e3883d82dede56208209c71cf2c309954047f7ff96cb73a5f818b0bfda4d8fe26ac3ec190554f7aadae641cf4e8ec85c2e1642432a620f9d6c37b44b4" },
                { "en-GB", "020db94f9bfab9d0d86daa0807c16380836444294a4707208ac6e9ddd48a0b466d0b61f64c110a430be5a86110340b2780f2c1278bfe47c7992bc44e5f8ea63b" },
                { "en-US", "c319d1b9f288c21178c6d3c52d738807a6f96a77a339b509155e03376a4158837b414758eb2c90457ab4cd2219e2334aaeafb2ced90554b4b8c965ff2fb03a7d" },
                { "eo", "202ab36f28f0caaeb47c3c1c32b894a6fee51eb7b27372cd75c086e35faf0698e3fcd509687a6b77a9c84f0a1764357f50ef3351160000cc15e730dd96780581" },
                { "es-AR", "6ccba6fbc9b6ca94121f333c5ff621a618ca8bb9d0550de890b27a43d498b08245a21871cdeee8728fcbe820d8cd5bcca9139be3d756030387f97c51cbefc7d2" },
                { "es-CL", "33f30436faf43320b2ef7d909ee2359ae6c8e24808bc74a7ff326b08b065d7d31cd5a9ddbab97a42528ad68d15b6e06bea0394480689bded8ad391b2db810ede" },
                { "es-ES", "5cd5f224e7a21b50ce8b64c8848fc3e38f8874cb737c5ca10c1172ab4c7625abd9b5b5855c51ef9983e8e5a4cddfc930c2df0edbb6df4c73295ae35dd1af6a58" },
                { "es-MX", "34955f3bf5207ff78ee161481b2b191051d73dd01638b45906ad8a3bf3c0e29488f7b6e1413d39bde61617dcfb285642cab46b503dfb952e49d85ce5a256174d" },
                { "et", "f62e66e113c90183a082a0751ec989f8835acbd13b1d60eacce91cc94ef3e36e62667b92cf34089d210f676c25eb7de11178ac49e2801b377d1158e6abcfc2af" },
                { "eu", "7c222ccf488d469ec32538b85ef8aa2ec089d32af1e13f8d979fed601a40dca9423bfc7f9d3e5edaa54cb55653b28cadb61e870c0a33392816fe1695264477e8" },
                { "fa", "2acf0b9c37689ad12ece29abf32fc79d325532129e65efc8c97c35fa565ef47fdff84ce529ca5a82c74faf0797645c64092980bfcbde0a894a01f5fdf6150f2d" },
                { "ff", "35e78f25e53dc54b696ba94a5144466b3f508718f192e1dd1c3e130e9bd49012ebde7bcb1b6ae4944ee23ca89de8df3523195e82d3c9e2b3455871ecdf157e36" },
                { "fi", "c492a3a205640f8c86b83b9a73eb41ef01abfc7fa31c51ebe42c761f8d5d264129a4509760121df0a08dc9d4676d10881ee23a6b1355b07b517c940158f00bff" },
                { "fr", "97339977a310460ec46b9f1fcb74946e43185ad1d8b3730651b98c5f6ad7615d66fa7cc88198a672b1263e248f4a6d03e6dcbf464000d7db73dde42ccbe8a2d2" },
                { "fur", "4a1ba5503e5a19e54016ce6ed8f3b7837ddab2864fa99fa0865c0b1beb7e4982220574e860945de1592c49abceec5ad6f143fee189f29a18f05d689efd68551a" },
                { "fy-NL", "b3f033f55f2e3b7447041704e31ddfc8e3ee21d4570076a2e1c1415e2e540d9c9f4c55e3246613e5082070cb22dccdbc3b577ecb85bb2d5c247b258db91244d0" },
                { "ga-IE", "9176a98c10173be991e89bb23f9c72c0be02f5be86a4a692bda68ce80785329b559c9ed95e806af551b3ceb49b41455dd79259e0a6a360c93c27d114ddaf2173" },
                { "gd", "ceda038265e5d388f69abf522b77b53b13675969f5a079d5a11464106cd6c8c6cf8e19511c88528c3a8d0fae986e5f0c347cac6198634ad793e191e991496358" },
                { "gl", "c6b27f0c02de8c989d5258c498343b68270b781a9c506a7a832ece0d8eb110a4b039f70f43105a05354d6582bac09cdaef45d06e50fd07ace76da5409d6be644" },
                { "gn", "15d520965e61ec3b5db63b17dc6f84ccdfb41b2e8845b7ff1cd2d2bdb961d5ca0250dc4218d20d252f4ac3587b3822d870612161e2012dbf3073c3dbf43746a7" },
                { "gu-IN", "142f06005b8335999078824e938bef2e7582dca80ade812e03a62c05406d85c9f7c4bdaba233cca468142e19a751b5de57a9871ddbbe4876cb427de7c0008f9a" },
                { "he", "fbc1040a4861047f0ac6b39fa24f8a107bf246d8ceb147708f938e0de7b50c62142a871b14757680844460020fb8365192bd9d7d2cbf6449d759edf561fdeb24" },
                { "hi-IN", "c6d6f274743e20b9ba89aaacd86ab2a5251a4f3dad2e3a62ea3f2bb0df6f17cf96c9c3a6fbd61355fa984b3cf61eb3d141706e194cdfc30d89ace8a296d26394" },
                { "hr", "bc5f62519bf306984a2622619d2645ad8095159d9adfe41f9855f6a82b0564f36a79776ea71e514c0bdb230986251ccc9177117fe58962e26552b76acde5988d" },
                { "hsb", "908fb05ccb8c5952496dcf7beb0c76f4d4bce55ffa8e5272d68c1f06f0f78065adb212bf625931f94ff24913ef2ae9c5a5d9be2fbf624d7ae372cee986ff0077" },
                { "hu", "a72cda7789fce9f36a60d58d1fd53d7ee828dbeab75cd46fcd31b2aecafa82c3d3f3aca961e16bcaa681ff598ca1ac085e69c31f4acba97b329c8b245bcd2fb6" },
                { "hy-AM", "b685baf238e0992695bc749124811d6c0fb9b7ee89500b412be316ac75dc600cef7f52b7f1140f369d6265f5c31eee625a285e910528734c5196f92ef39f4513" },
                { "ia", "fcffebbec1736abf92ce0382f14028d4df33b8352e942f7d387396b18ae1269086fdbfb8ccc8750dca6640a6781d928dd8426121df59348de1b2122f41572119" },
                { "id", "60581f463e593d5520ae0779dd2bbf6b8018e0a49fe2703c68fa17e38f176fbcafbea6a1a4c6743fc247e6e02b307c3182fcefe5dea2eef802ebd753003b527e" },
                { "is", "f65e0a22c6d13b8fd3105acf320db5237610bf49e666bf870c483a015966d9ccf97b4bad09aad9e6c776c80c97a3eb657ea48c18eb508a14088c63afe352122b" },
                { "it", "f18e454f9b916554ba708177a7a21cf43177384c2037c86988e516dfa6833bbea25c6e443c2fd334999f509c283feff21fc7de875d15c02c4bc50726eb5dacc7" },
                { "ja", "0b776ae4dceea41fe7a115b45b03b45dc3a396e754cfc4a126f692b935a19e878b3b36589f1bc0d5859676cd740376b67a0b8dd379421d333aa71cab62e19ec7" },
                { "ka", "98b59e79b6269c9c64a28a240e4a31d2f57c56ac45f00e17db1f7df96309a537b70500912b97219bc16d69db46d51461a50264ec2f25d06d214ca7743792617d" },
                { "kab", "a0eb25977926fb61f6431023412479e35c64278820fa08444fac377cffd3e703fe172de4d918363e0a4a96aaf96da366a251c1ac5bed1f8b73f032b740b0dd9c" },
                { "kk", "f525c508d7641cfaf453cc4d3d5d08535ebbc70079f4b3fd5655b58b84c019ba0b47cdd3a215738d2e2e7046c2031ad967657cff12767406ad9451866acef604" },
                { "km", "6caae39879d3777dec8114bef27aa72bacbeceada9216a4a254bc5b29b9608f99c4867801611163382a04cc5d5ef13b30b649c36b6687bb4db749a8791e406f0" },
                { "kn", "bfd77d038238d469e5ef33f379dc86221f50b395ceaad7c1124df7455d46a700dc235239df7a0b8727a8a6e7221fe0b2bfd876765fb4fd9b91a6e52e154bcb8d" },
                { "ko", "0876eef353406a4a26505a3f663d158daa75372396f9a7e332b795dec20b241e47c37c9573eefdce7dbce6d6a6d4a1525082b854166106ea10ca388358fe0783" },
                { "lij", "393f783a75d70e566573baebe8644906ab6ebd004936d0e3f93e1627c560a15861aa5601a4d24b7c89246d13be6368722049ced9a527e0e6e447a5a41d5cc1df" },
                { "lt", "e05c78ce80b783c735429a73ad70434e721698b45de79a8325879ad12a1fb0a201f5f96b452a4cd66181ab168e83b201f567002cdae6bc136f0c274a5ce0e1fc" },
                { "lv", "0945ff5e73c55b33e28a0f7cd70d4e5980af1aef380c9036a935040eb61a845befb728105074c54630ee74a7e41c2a71efcfe031a5fef9be07a6f2ebd4db1aa1" },
                { "mk", "f3694c2ba279d1e269070f54cfdaed6e1d993ed4f862e4141a774b13899b5e2b6fc423e325fd6301ada75e11d58094b6d6f26161c0302d14604222433414616c" },
                { "mr", "d0ab3d6e55151fbb8bc9486918e07932e0933d02235687eca84e579c3d94e282fd9332d752f0c40563a85610fbacd227c696b3d790bf118956d939f15f9f2b93" },
                { "ms", "9a5f667393af226ca49ea0f97a624fc3f30e03ce38c6880617daae24972b701ecd5ef34243e9ec34d178966b87e1af3c9ab480c9581873704f99a9c7a0d47ec8" },
                { "my", "ca93f6ddf2ace44cbacc17f249ef1bd699b05544d4313f00bbfa6dbc6d5d382996a01dc267fcf8f2ba61b4e28c688a4489baada3e2c0813d7c290a8a62fd7932" },
                { "nb-NO", "94279e6cf14e790fcb30b2c4954ef7535746b3ce3a88afba0affb29c0c929402592b15fcc101526e9426ede43296ea7a76fe0ef5900a9e8f09c84fa16d320ae5" },
                { "ne-NP", "8468a2ef93e7237ff25e35e3905a1d172a72ad7e4ee4cfe15cdf36cebe8942e432e15a085f10eec0b56d58152f7350fd87bca4257dc9b2de67be02bb7d57d473" },
                { "nl", "f3992d7485d351373dda6a60f0e5fed74ce69d5aceb83e56b62ad95d22ecc36ae516aadf681b21c5b4c7d7622b3da6414e90e9e8d81dfe121756c6df235f1ccd" },
                { "nn-NO", "f9cca8d69c013a13cce62f2d0e356075d23e2eef7373bbd051773aaffcdec833bb8da8e0434c1e2d3c15e9f09275e79150e9154f32735b70e0ef7ed759ce5a1a" },
                { "oc", "0a64341971630e55c1d56c552faa3a6fb9fc22bb60b5c49e1705f4a1e22491ebabb20d2cd74509f99d94f89c3193e2b70068d68c2ca25d4821e3d742ed885a1a" },
                { "pa-IN", "8379bfc454546cd76b8d1ac144e8c5d58a62303eba21a735160275f4b2d540065fe534fca2ba3e2fce7199621e35f6d27854604b17b8fa9fcf8abdcd512a81fe" },
                { "pl", "6f453008c87ba2d0def51e5b988703574e4f3f6b7f8aa7e9e731a73dbe69d4b685926aa6fc04d8b3fb2f2744902db10af6d147163fd97c8a753418c15179eef4" },
                { "pt-BR", "b9b698280117f17797f83c9f701989e9b18c5ee473a5235ad149e8d32543248423320959ec0d40b571a8007506123e07f7cd71c890ab5938e700fbd452a5e93f" },
                { "pt-PT", "be242b083b478bf6dec3297846547cb61dca68b8455fcea26c7f8eddda107c42aba206e6ae2749ec6945d6b86c9357418171cb64c73cb2819edac4ae79ad8cb0" },
                { "rm", "c6377a2c9382a52f402dbb165b84f1ed9ecd22a342b80a0594c4557b69152dfa03f597f1e880482330fdbcf3aa498d51948186cbb9d4c530ddd17c29fd5a6cb4" },
                { "ro", "28b3e34ed29183ba9470b534bc85279fea6714f2101c7e79a406235b01b56987b6e407d9362b7233bc57a4322349edd9c327171aaf037b7518181fa2484fb329" },
                { "ru", "4889a906ab464625ec953f92753c576b37cfd6dd472b089789460fe3aa4143d93757cfd475a15aff74600c6f872aefd79267249d0e59afadea14896d2a86df20" },
                { "sc", "96fd6b1385cafb66d9358e7079f5dbba0a9a2117c471e7af87477492e5d4406611a3eeac949e9f5fd6b8cc53df2efe5d52194047d3581368a2c704c7b022f74e" },
                { "sco", "fa759455f95b53f5b1c2dc8aaaf2d780da3e7031b05afe3417a859f6f0c96c41ea0ebf7b04670a213d56f823bd8743296fbca9dac64dbbbb550f1ba15fb3fd0e" },
                { "si", "69dd83807849f81f91beb42920d36ce9634e85c7de48f0b14203fc211942e591bbcaffa1f0b6bb75f6543a60548305f108d14b0f912927ac00426390c7c7c3e7" },
                { "sk", "ebfa063bc2972eed30af8b42b06c510c40a3ac3d7b4c69ed0d116b69cce9e19a6f0b985eeaeb5ca500ef03eaddb266fd22ae617be52e4a65b6b120d7eb165e4e" },
                { "sl", "9e1e52518ab860a6a6710247d9b2395f8e11bf4405541cda9326398cebfdb11232efc0e5503623a292a123833976704f5c4c550cdc8c19a653ba0c29ef6c9e1d" },
                { "son", "cf36823f139086a4908d38cbcdaaab7b04522dbb9985689199758304d85611caf09e5f3955019dd204c211c5cf3336e00dd409132816f6c6e623e59784c925b7" },
                { "sq", "76e70fd4814c142aeb5ceeee49233777cbc362af0f45d87c8c036fe53805febf7e8ed46a4f2c0f2d2e4d214f1370c28662cdb393a96851ad63793f842fa37731" },
                { "sr", "eb207328af721f4932864727fc7cf93f344be67ddb7d759b4bb2a6475f9150a60da67335b00e75d342b97364fa6b2d72ed22e670e6bbe37053a772ce698b3a6a" },
                { "sv-SE", "8a2fed57f33634418617fa5d5a6fa7852a941e253204566dce485709504e2d2f965ce8b4d08c7c0c6d029bc8732e7040a706993f71fd2e699215a8cac62e0ff1" },
                { "szl", "9c1be8951e29d838a83122c1e06ab008479e2829fcbb4a5dc45df10d0a0229aa9412ddace75e23fd13b34712a8fcd0091fbbe0993229e80bbfcc4e0be32b492f" },
                { "ta", "3da13c6a33ef1b8f5d9e679026d23ec188e9b67722b76a9580ad22e7b3604b59f5c35743687d206eac380b6293995acbf392a9c1a24048b5a46f9daa17b59c3b" },
                { "te", "8e6b9bedd7e34357396028a17e035bb46ba187fed57fa7acb2ac3df1cf1caf2be9a5359767d8aa8dca794811def860bdad64d4b59610473adbee51747b63bb0a" },
                { "tg", "b215f3172bf8c8df3ba983a782bf72c045dbf027c5da7a22cb85fd38645d0ac2381c960eccf5176537d99bfc77e3a755bf9084f26579ba5e55e4bb588cea33e0" },
                { "th", "6aadaf91fd2bd1accf19840be2a5e6279e4c3eca606d1bd21cf2a50dc8d178638dc8bd7f449683b71585d9cd2e51b2e17ea0e1f0be8b462f6db20350439dac61" },
                { "tl", "4e364575dc0149fb8e28dbc51b79b5d561fb8a3e03a08fddafbe710b7541c1b864071acb8631bd712b18c94a9f83b313d8f3f5d460fcff09b5fc57d8ac0793ed" },
                { "tr", "3e9a5d83a6d7139b45faed009333a8bf34fc668af93fd05ea0af3d8146a2d3552df74c8e855d90f2608604296d60e32bcd240ae755dd98e749d16799d2eefd14" },
                { "trs", "79b5de3a4592ef2b9907fb4a6715bf28ab655ffe9f63013d045e18bafb4f9e1d8aa9811e6150e3abe2feb637bf5c48fab0c17d0d992306a90e56628892bf51da" },
                { "uk", "6c0ad64ebecde0c606a07a6c962726c4973495c01a24e2bd5f5edb033a5d1c411f2c36911682c30de2eb793ebc70171046ce0feb5f67ecb7ff6a14f8405bf6eb" },
                { "ur", "4c5be419611c8a4814263081ce689942bc1007c1c89ba2f3cc7ed38d072f2bbc690389c0c80cf9f47580adce96b4d3bc6ade3c0333c8176dbb6166b9aebfab31" },
                { "uz", "0427b8cf8a99d9eed88fbc19608c862a7b49ecff824629c86af04db3f5d3ffe7f15281a9fb1531e876e3b6e844af48c2655f8370fa00eb140600f2f2918dbf20" },
                { "vi", "d880f6701f44032f9ccf1a47c71ce98265720f1246efd74f9bd81ed40fdee8cad06fc505f1a0c9dac1d898a1b93b90ac06b6e2e5106cafd6262225d44f883e93" },
                { "xh", "019f7fa7f6b89fe9efd4f95b70bbf521e84d545429b6200afd457f62400aff4dd723e67caf723f165c07bf1b5501c0be1e791aec5ee52ce93a5346c37fb15a8d" },
                { "zh-CN", "41096c40b4622632a374b5c4b8804727adbb37144eb7d12d9630ad2baeaeacc4f7ba0d9507c48cf975454ac3ce80570ac86eb04dd949ba5f7c2d986873c5497a" },
                { "zh-TW", "fdd3d83fc44e01c5330124b1a755bb4734272e8f0b3bd418030fa99671650ae360e963301aadaf74e4ecf7951994d4c7c3766924c56866acb5dc2e156a6ff02d" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/117.0b6/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "2756fcc503d1ef7dbec4035c9e376c2dd4d99bd8dcad7df49bf24d2d9ba7bbf898c84c6dbd4952894ef8bcd0b5122f0d1055f0087fa3e577f1a7e4b1c59484e5" },
                { "af", "2503711d37578da356f7a926d05dcc93b353762e625f8c462d5dbb40040f89f8e65322c88d5ee9e84e808aa0d7d525483740653d3d241d255f96e4095f28e6dd" },
                { "an", "e6288bcf9d9ed35df210148f59d9079f96a5845690da4342aea60a301fa3cd4d06794205c705da7f1f39df43d62a65f93f8b8054a2a02d5236def8acb31d4f3d" },
                { "ar", "f6734c6a048b9a16ebc818dcb05aceb977777648642e060041e3db2fe00dc74100efe77f372a70c6a8ba174965976eb86600a3c6ad8c63014f4cfe5a0453bca8" },
                { "ast", "68dd3eb2dd2dae260f3c7471eb149f47aab2d27b7b870992c1899de023e5c028a1fe271878428dc32ed9caec638ca39ca6ee1a15422e5443fb141c1f7b4e25c2" },
                { "az", "c3d1f3d212977e76c5dd70b3e8811b8646306bf0de10ae9967206364e14b90befb122532078dfdf2d596185b2be5103fc871661357425d79a38aabfab2d95f5b" },
                { "be", "8058baaeb1413f7da420e344dffee7a34126817e0d6f24a25dd96b66f0394161b2d40157275653385e59d64031177d300b26ad929c4b36143a6bfa258f94077d" },
                { "bg", "fb74ef6aa3575803fb386bb91b103a738c7bf7b694693225526494798697e8c8e12cfe379fae3973231b47aad354fc3b302c3fa6542f3bd8d3832eca32e6b0ba" },
                { "bn", "3a81f5ea4735ddaec8da5e6b4646757fc7b01878c4724a2db875823cfd7c289610d805e17e59058a8fd00d2983014403dd959648f78696b1a8b22d2c8ce11879" },
                { "br", "74cced918ef3e272008728e049f2ddb533c0d7bb152d9339c415c64a0451bf20e57ceb58970045de294aae894303114bdc4cd05d9144de42aa0b8616c5d4645b" },
                { "bs", "639ffc8a15b5703dd5c46d6e95642c19c2fa468d34bb2094536b87507806896ce47a695760e39c489b9ece32b9215406e7478a7e122313f8fe8be27e9332c51b" },
                { "ca", "62666ef6ae90d80f163711757967240c40c9c674232b569f95b6768c4dbbdfc5bc505454df1d0a1204e512badb668bc54118bd8c1c75f5c0dd5612ef442bcb7d" },
                { "cak", "b7860d5cb008b1c02fd87ce75064909b81722972821c5c00e2d7415b25aba210da805b590d6bc7c433dc9cb7947d9307dffa969d6ba05a69242fd1784d025432" },
                { "cs", "e995a6d04780c26ce6abd21793250aa626f70682cf0183f2f48ee452240d4ff6181d034c09461d07e9b4b8243aab804d783e7a3210731ebf54324e1c5a87e9a5" },
                { "cy", "0bf6d905d1116f8cca3e4958375972a53ed793f0768804ce049ac6bb397caf21c2bacdcc363616575f9acb43c1bb7e74b055e6193bca45946c71ee92a63a3905" },
                { "da", "3c2b80b5994dea8f0c718bbf4a326ec2b9657e46b255534d0bb54656d4a6e6144c67d4365de129c1a44757fb2eef58529c9357fe00e9895e0639af9b480246cf" },
                { "de", "8a6162d663fb8b808ed952f7e483a66635a6f541230ff5dadc1bfd81d4d96a5caeb6eaca21407bcc9bd107ab6414f1b937f471a690cb1ed1abafca9188831996" },
                { "dsb", "c194ce9e1fb3835e7df65271dbe1d3185f5c272edc9f742d817bed1c11aa5bac9718131317bcd40a46c2aeea8d40024b390aa308d332fd1bed419a99b920e119" },
                { "el", "751f6b54c1b8f28d2289fe2b928a409844ef7388381759224a69773ab433b534ec10a1e537a5c9cb3fc02a1f1ce111c442485bde284a84d78e9ee5708bab2cc5" },
                { "en-CA", "1679754b4e0b31ee66a6d05491e53f4aa4235cdda2839167239c5d6477ccb6ca023e598c70a882ad04c36770bd72bde4fab29391e32ee948b90e1d39154657c5" },
                { "en-GB", "a2882a0b8cb30c2e242047ae7608ba8809befe6794b1a6922ea229e88ffee68abeb3fd6d58156facb8fcdb5d1f52acdd789f9457009c64c9ae208e2874d0aa0e" },
                { "en-US", "847fd9fcd3ec1275e426ba291d6b8a9b3664b818dd8f5cb680256bb7334d633f25e64b0923513cb3c0cef87d8fa71cd18220be4d1c4915da9e302f5d161e836c" },
                { "eo", "62bce16b5d43b7383c1307bec2364225c5491d1fc9777121efb60a4a9404d015a2b2de2df894378cbee9ba97a0a3f7afc692d76b1fed9aabe4fa08c31ed6b0f1" },
                { "es-AR", "6d0e68bdf54da2f3cf209b789ff1017f3dbeed959467fba92da1220da8965e58fb60591b91057ff577bc9f6f2114a417b4ca96aec71b7b5d1b20503c72f320d6" },
                { "es-CL", "54f20e4f7f31f8dcae7268313e12de3ad409d94ea8ca88922983ed0b2bf9513117c98b74332e049abb3bc7b0fd63a09d2f6fbf1bdec02dac9ca1679bd9654e8d" },
                { "es-ES", "c7bf28879178cd29c4311c61badbad433221b8bbaa6943b02c10767a0914dd98781de7dbbf3b27c01291c1e0dbcdb17b205445a5f9ec890004a83c08e66dfa8b" },
                { "es-MX", "06753ed23ce1bf1d131758d5795277bafbe8e087bba8e4da09fbc351e6d4bb82a86e71d2242f37f974b272d1ecdd7095e7ba73718c239a2e67ad92deddd47fbd" },
                { "et", "e38a0318a71ffbe989f9c9d9801a50e708f3b2455499acbbe6be79198bc486638e86d3035c67a9009bb1b504e597338c99f21a09f61fdeb7f081150645ff26e6" },
                { "eu", "06ffe62bd368202e033232ba6463761a2bfb3b82a15bf9961294daa3db425974a164582eff5da8b6b59dc6236ea3fb57f4ced15520cef7e04a61506cc5bd61f9" },
                { "fa", "9710ad5a39db775c222ddea40cc3024194d6fc2091ca04eac780d335b67e8706924dc72ef744132b401fd5f7baec76bdb06ea543ae669b379ce963e28bb9bdeb" },
                { "ff", "3943755e7ae2532a69572ca1612fb4b17af23f54faa6ad5b54a80c9f951dbcd313ddb8a889726d6f9dc061d044fbede831d0919ce9024b843d2f001fcdf13d0d" },
                { "fi", "6d1841157281473bc327959bbd0ccb904e77df2ee781dffd3152010ce624f626e81589cbdf9b3748c2670a013da433d04950375f47bef03d6c8bccd359078fb1" },
                { "fr", "2185e59ee9de6b3b8665bb711b05401271d01f281b5c7ed4480315be8e57e34ff8a2f7721882c1acf3fdfbd81f23c0c308fc80d82297c4bd38c6fc872cfab580" },
                { "fur", "266993a9b819cba2a42cef41c4f4668d2be187967022e3f36d4ae21a4f87fdb38f72ab42bef0b8eab9c0a7e05a9546a34dd7efeb827f9a4807258e64d4948d8f" },
                { "fy-NL", "378f443cdc67da6657e86543cadfc973b2dbfaa2338032eeb7a0f8b87d22102e5e90c2aa9f65b42c1778f8baaa032bfa17000d4f759b935d97efc04f1d3fbbe0" },
                { "ga-IE", "3593d55c791a70d8b23de64f7928a3527800cd0fc18a3770f20c70b52e3aa27dde43ff494aa70d5bb2ff564080307b4931c8d7ee3980556e7bcb2e2af862c2d8" },
                { "gd", "a39961e0120da11cd5f18c27bb61faf09a5d2ba277b735bb6f4c91d02b79ca09527d9128dfbf32247a929c9ff39e954ed71eb1b588ee7f1024a71306f8bf1d2c" },
                { "gl", "bfcf062fa41117cf225c67b654cebb8e6f163598c6580523cfc7c1dd9b3de4658838a4814ade205851734d98c568750346fab0b85d13599a6a3bff0293f8eed8" },
                { "gn", "b41c6654eb873f1ddc5a90d10759640ba762d080c3a5921f0db23328b6e7965db39704c2023e7fbaa8f61908690d269e073ab3bd3c1d1d7dcd2250458b71e7f4" },
                { "gu-IN", "111b1dca960db343fab9414f018f3c45293fb8843f92f98f6d4baae8636a50533b6a6405a2ff939691ce0b3d017fe87803de95568012224099b5dfa2d7677e0f" },
                { "he", "4e34d2eaca1db4f502e321bef263670523384ff8e812e227a2332e47741cd00c3d8366eadfb2ac0f866776d1cec731c6e2bb24f683a1d65fed1ce203a01ccc83" },
                { "hi-IN", "b0104d00e923fa5b52e1a2c7ec4d645cbcc3fee14d59d61206dbcf09cdec4cbbe82ca8d00eeaaf9bc4cc03c8195ea285776abe0e63f220791f5eee1b451435ef" },
                { "hr", "81e829bbf1265546c0da74410775a81e0f8170f9b50ac38da7f2c180f6eadee5cad76e7f089440ec369cb02e8c6985f28c20e9af8a073f268d4b3afc4dda070e" },
                { "hsb", "c9430f1c46a886b1c19b0e79fb228877159355748ae8eb26ba52e6cc4fa0b320052eba2d5ca4ef1a85dd05e64557fd74a2655ae8691c1aaa710ea89de8547fc6" },
                { "hu", "ede2de8dadf0aec817531e74d9fbd639777083c748a88cc1e44e721092216dba9fa7ab1dbeac161c48ed88b91efb67d06ec3d4057b825356956721434231f992" },
                { "hy-AM", "23d58b50395fc2fefb523fc31af0dea70fb7c1d004c637e64700dd0902232a1a4df5c0268ca12840a8a19a87481f5c70755b3cb86048dbdafd9eaf5c88698836" },
                { "ia", "4d41eeba9752d67148b5fb060ab9725d9ae7f7fa374fa21d9319ae6bf0b842fd5c910d0d6b141fd5aa6acfd6d758449a83a16af5b6f38043b173517eb893873c" },
                { "id", "4ff24898b30a599666de760a780fd1a1b84a9e309773bcd4971a823c80672357954589d1823348c6c4d1ed2920775f565f729dd5e6ca9114fe24f65fd159660e" },
                { "is", "e96b05201a2443ca7048b48d4f1acd1e45cc1a5c83494ee8e64368ad8f177ed7ee4b612c5644eca351b2266450865688bc2e00959ec989e1fda1ca9d92522350" },
                { "it", "410bc542b08b6e113e7ee6ee344123be4fae811a14b1d356f147d746dcd37c6851cc0ccf49a78ca037a87bf0a75019646f160cc1fd7601f5ef01f4776e2a4491" },
                { "ja", "2f78104d6e9b5348b947d64a4cd5f3cac0a607eab8b76830c1f3df7225b5a649b73460affcf24b3c18b0b2bccf7674d7b3ae7e366c5bf1d1aa96d7c33ad3bda1" },
                { "ka", "f4819e7833d007a5a1d2edc7fc197bb232e9e128c678b400c3b3f5ec0d674bf25816f06ccbcead835f361ea22325a1a21bae3b3bb711afac1bb8b502311fb62c" },
                { "kab", "5f5d44904bd6e8f5dc74d93aef1c54f2e137728b9559e4a4247ca0b26cb1e3975bb172d2cc3f9f97902dbccc3499b43ecc6e6d17108a8889f1a9af3b2c3a3451" },
                { "kk", "f99fb9ac65b799c6be3983c6f698008c1f684f135691126574506dd4e16f819cc60cbe18ac0840efb5b8c82fe6f2e2b600c53f58f711e000577003312d6ee214" },
                { "km", "7ab4581f265834df141e7664f2622eb982974e65fe08caff021af4fb7fa7ba7edc2b650c65d1ec68880402177bfcadcee3fd2dfaebef2d33218b48f41e0a3fb2" },
                { "kn", "b1aaaf5038c859791abcec1e7d6eeea63fe2ebc51ded76eb71756626bd2fd3ea0c73377936376ed971d8e7441e783adb251931a4bd22154d48fd5ba223a2a0a2" },
                { "ko", "bf35929c67420003615483939f9501171758d66624757a66f343d502b56b8b4a3d6b54fe00bd62f819431776c320ee1e5c325bd854d56aeb28d92d5931e21cf5" },
                { "lij", "c3ec846e9f12677c96cc1c9e3fa9cb4a919131b8fe17ae67785157cfce3eac5235c265ec1363e93a31254c4b972c8e6d7ba89e8a378572fdbd4b281049333564" },
                { "lt", "3c96ae6fdde9c0064aebc0645f8acbc0e6b0704debb3b4652471d6c94e921c5ef5e1756d927f7624872b034d49225a19dd5ac961deeceb81b109bcf8159c3812" },
                { "lv", "0fac73cf9498045879084ee04dc57525006fa2a32f19ed37fb6abc610319d99e02678e0cb385e7ae4d6f295d8564ba02f12149b29903246842bc0bbc42d04c61" },
                { "mk", "c5c5e05f5cb646af7174edd53f5609a1a7a08ca930fbb4ccf5951dc08fc19de1485f6cb459162957ac2e6e4807a716de125111b464b9039deda54e248e51c484" },
                { "mr", "aaad72ce1c65864dbe1ec69242ec6a5df1e0f44000f1a9e0e1ad4c4ef1f09c84bbfae4c3e6b88f2336de81499db98fbfc9a1a5ff20bbaefdbe0232bddefd98c8" },
                { "ms", "72e65185b4ebe4d535d8ea2a2c07a330c1d3396204a5039fdea86f16070443ff68b2aff8aa03c6c30bb0417e344435f9e442f1cfea0e36bf5020d8f2384e4eaa" },
                { "my", "9c1702b76e31916e172000b2401990b7a2d0c9a66d3625d669ed2e7f3a4f219689d009602294434e5e4b44ab7445e50f59f8ce17adaf914d80fd68a90e0a189e" },
                { "nb-NO", "fec638940d3a2b7e2aeb8483ca31e0b42923ed2b6f60689127e296b259a9d7c0e30e0aface88dcc90fc23e5909eb66f63b7b6fc5a37f1f01cdcc586914ccbc74" },
                { "ne-NP", "7c99e495fcb100b471d36eb96e87df8e8bbbd4548cd2642b588c8ee8a3ff05cff0d163b5d2587c83ee646fe00427fbdd9c62720bb41284ecdcb165db52960d75" },
                { "nl", "03c1f5f6bf27fb967c629ead3871cae1856151d30559cdbc0f03128129c8bf160f56f9facf5f590fd8bbb62f8acc90df66d39f651ea5c4c30ae79f251b5e4fb0" },
                { "nn-NO", "7fad7312c5df16b4b73c41aea0721665cd6a21cbb74dab83c3b93324c8ab5eb130b694c50968392b06702f38cc292f841888d09a9c70d1f352a5000780def138" },
                { "oc", "1f605736928d7d15920099cbd97370db9f7def9e0f7ab0fe9ba55a4e52fa287ce2ce672313ede3e2d612eaf2c1112129694df902bd4c5d6bc3d446b343256122" },
                { "pa-IN", "7719e2a34348ce9bd13e12df2471a7bfeef25e832d02aeee376cd3c620d35756c3793a1537cb73f7ee2a55e36861d3318a19455c3efd08a2e1aec6271f6cd742" },
                { "pl", "5bbbf05b91f9ea678dead51318d30880886110d220d9cacf4ea2dc7681c3308d8ca5af2461035012d87fb63d78a51fe622b9f7e99060a220f87636f9089b259e" },
                { "pt-BR", "852e1b8b47944b36cd19caae9a72c141a699b0148161a266e11ff43989f1e455e8f4aec0c4844d87d1b03bfb2f8c37a3c7d457901897af8b883d3b26f3f9c59a" },
                { "pt-PT", "623ac92a165020dfc091cef35ba5d2184223cf7b8b38c9066a08e6ca6ac533e17062c48bc207d7fe8ee1ddcc05eddb59697b0ea198bf0d28406a13f7a676a6ad" },
                { "rm", "50d8d932c0e61ddc2c286abca555c8eaac68d55f2cda277a1216895225ccffeb20ce226647f0083a41212820f2e4b904c0327b4a56e774e395271b685bae3b65" },
                { "ro", "35995decbbaff3daed0b2b8dc07549725bc94643d8ee0f67ef201161d046ca99b0b3ec11630c8fc66f6131da21c8fd80ce9e73da730d5507728ab934b28ce558" },
                { "ru", "b1a10de4c40569d547a0cb192246c3f0216dea1123bfcb74b2216b5ea38ef534ae82f9d91d2f06307b6205bc8bddeb99fe981e6b1b7000611bf615601d6dbfa0" },
                { "sc", "11482b70a0f5e48285816890ae8301aa2f3ddc53a37f20ebf320a6d0577490b6c7490747308d34fc86478467114196829164e3e67e9fdef24aca471e4c47db3a" },
                { "sco", "0c75b1e2464b16d87bf5a7dc0d4ff46e5f438913055b5dd782febc00bbc8b7785adf02e5592737d5345f554e63a2a18de0d3e62de4724dd38a9b65f617447d6f" },
                { "si", "f9e72696e17b36f3377d8a1d6e43d2b9645230ab6e63f174749d68a87d34064c33ae59154c9833e907cd093d4c7e73953514eaeb45d2a7311d590c3375f451ec" },
                { "sk", "f4adbb5e800d552158342b4fb1bcc2f6192c7fed5f040a8044fcec51666f54d3ea3c68e0897ccd3c02b63012ad8c77df8cfcc59b55eccda7e89753832fe0ebd4" },
                { "sl", "c558de8f7158870d4f67d6cb3c54cc78270cc44b5877bf085a2d45f60f37cb09c34bcd6b45357b88ae831c7e18fced72c95b2e14920398c0bebb45a28cea3cc4" },
                { "son", "7c6b6a42c5df1f0b17c0c799df1ca18a4266bb891775b4ecffea286a99ba0f81dfbde1e077c15a716bb3c60a2eafb248b3f42687599e7d98c646371f72e295ec" },
                { "sq", "4031029f79aafd7f6bcadb146b1eaf0528499078024da0ebb5891c2ef0d46c5ddb54ffb1efca4cfa57727036a6423a65f1bd8e2a266702dde40f13563904d383" },
                { "sr", "08a5359cff9267fcfcee8e118e51b0c5272091aee2c8db28706a9cde748e3b4fd7bcbec53f5950fcaa2885c70432f3083c613a93ebfdf30373a6b32e45c15391" },
                { "sv-SE", "d37a665db4cf0adf7a4e555590ef1e86d9827e68f1246344bdbd6ee5189fc8f423996f30d9addf47a57365c17042b4a87ebd9ef05a885ebe096f91b411311f23" },
                { "szl", "a0f274b453e7922b666964c9703722eaa82ff9a6b02e95417f90d3ee42181ba3a5a72747d91067962eb1676a83b0eaf52df0d09a8460b68c41f02218b2f892d2" },
                { "ta", "886acfe4939d91732502216b8374642015958cb883d82113812d4d79e718f4c8260d330a4c1b8e7028615276290db76f0a37d882f2f408a5c902589a5c0d485d" },
                { "te", "5996816f19bb14d297016efa75b756bfb952bf68bbd1efdb12fc5244da62d7b9b6f2e55a47c09864cb98eef450653013277aa9f886bce602e54635781ba0c3f2" },
                { "tg", "37d6e15f20da7b032946115859327518802d7de4b0c461629a91f13ae1a5c3cda6211caafa9d4a2ad98b496eada8f54d635a1bfc08d94ec08f42aad818265bc9" },
                { "th", "2eadeabbbdf5cb9fa950fb8654dbd44bbc996dfa3466dc8240232cd2ed1648eed2bc348d60f1bdd6212e8db55386fd17e0fc4f6dbf3cc3ce400609071b35e5f9" },
                { "tl", "e28c8117b2c6c980a359278e029d46555aa1bf5f04667ced690caab3e020b5c137d68e8dc6b48a8ad2b8e594889ea7a428384dd79adc6a8a91e43cc44cddb0f9" },
                { "tr", "bb8f85eb6c84621fc4a7f7f2843926e22b44884c262ed6e64aaed6f10a22d900243974670b58d649ed40bdc3ba935018a11d563ee2bfc9efb02a09d381feea08" },
                { "trs", "4e88ef19bebce24a7cde776ed02ed5204e9434859e4429eb2074a359fee4436e97d231fd47ea5f568026632fe8596d8d1e1e3f81793c5af847c4dc27a69367e1" },
                { "uk", "bd1392b38eb30cff4434fe123af6055fe56efc73bd983f7430dd555259ab9dac65468b7dda716add1ba3f0030fd42d5481926bbef0f9451402bd2b744beac631" },
                { "ur", "d6e023e60662137d179fcf355635fcb8bdfcc74e20efa0a4d812bdc1118a167b06cf75ec56b59b01ed0c1d6faa73db27a4921ffb58350a686c56a7545b74197d" },
                { "uz", "a83fa5dc8c031add8bfd1b03ebc709139851df60c326c265ba6ead54bd8143f6a179c83fe9b19f1420247e2ce517ae7becd12a3f34acf80610503a68a2ab37a7" },
                { "vi", "a5e3b1b2e3d64ccd9b43715613b63991627a3a5624b33a6b6ab21024cf21036de3c1058af571756deb89d4dd6b97afa7ee491102def40cb8a4e1567979bccbf5" },
                { "xh", "2df3ebfe3341c1622b1ee6ff711aadb9d2b24fb26560d2ab60f38909c7982bdb831fc44647cfc5a53525f918bc5e2f6338eae2b223da49b98a94b6de1e533be9" },
                { "zh-CN", "207d202b0739d60f7da4f8aabdecfb73e5f935ae65bfb80034428501f1ca0e6ca9b655180af6b8227450c203e75ef9bfc01e096f248c2ccf79ccc09f286f5026" },
                { "zh-TW", "dc46f95c892986311b29d5eaf3d06d6e341896e084a65839f6488e828dbc0507b7951f11b43199e26e870f042f45382c01958f28a6f2d235c95d72ff6771e530" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
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
        /// Determines whether or not the method searchForNewer() is implemented.
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
