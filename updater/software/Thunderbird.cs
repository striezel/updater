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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.4.1";


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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.4.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "b56515576cf480a1be004e2577af85628aded2c7edc472bb2b04233b4cdd7db07fbadf3968e45b09f52be2f2373d02427b0ae24d985ce830db7c23d7d8030286" },
                { "ar", "e3783a3d783599e024b76c67fa43fee8ddff4a90ddb22dd2e12d11692d6fa10576c69afc55c198c6582b1821d93fb443ba75a5bb0ac63fdeb705f45879e241f9" },
                { "ast", "0f6f52880a21df006020ee349e2493415f4343001a19d05f0338b8d4a19fa5344a8abe0b21eaeaee0870513864ea21c11963dd297a23e028d2df1f67ee89f6bd" },
                { "be", "b407a9e37394c7cab9a305010abc0658009d4dcc083716e349dee8eaa7d1b7f06c4ad622acf929036c05f043da875abc95283cce420f73baa3cb309192e40f1c" },
                { "bg", "cad0bedcb93892439628d7d2bd781825f7bced864859fc5b1dc251c057a700c393dcc3a4d499b4eb7b98f1718e199310b4033645f5a6710e325679b3cd01cffc" },
                { "br", "9d3b4466ee96f9815a85962708b54f5f32005da96ef8fa124ee5af3ea1e6b2481851ec96d37c8053afffe8985742ff900e6992c670401ebf19641069801fc174" },
                { "ca", "a7246c1be2d3bb4ae24e4a46f24f09936bfa096af132a808333052eb25b0cd531b511044ee32ab462b2d4382876ef101572457b563cdc93511aed445f877ae9b" },
                { "cak", "84552ef664cee40c869b6aa269df66756db383fafbe435e5a9b804b887e4ab79e2090ac896d82bbd13119903673f1e9083b0c96b236a1f0afd9950b7fadab4c0" },
                { "cs", "43086cc1526eacd73c4262aa829695dae97b0d3655102803a9862d7dc1f39b505e51d91c34faf44942bf5688508108e858ddab76bd08748e3823312c5ecc26f9" },
                { "cy", "d77d1591f2c6b747e73c1bd775ab2cc563ad6dd59c7d64480637bd1176a3ff084c38f1b15365fb9dcff087a0c62982b2466f08afb3eb9d6e23a13db007ae993d" },
                { "da", "c23b458cad66cd1b12502cc85d229b0d39e8c2b61941604af950fa0ec0b7dfe413a26227280795a4a9405b4356d3bd116ee4c88e469c11bc31baf90ddde4ed33" },
                { "de", "80229bd56b93e294ebbac071ff87490f246ecb7dc15cc449aaaf11cd92549d09783b8590d20767c8d134a34677b2a83fb374cc10680f3de4a458944b91ae5b6d" },
                { "dsb", "e5ecc70d4d9dd8b8b9818a3c12b25c8633f2c6572ceaca9a116722654bddf160e05db7a87bac1079216b11be8cb62c1e13b203bdcb0294969b6c52b2104a6a2a" },
                { "el", "329fccafdbc73eea29243e27c90d94e7c314fdc440f82735e2890f9ed728eef49a0fb46e1330bba5f4e956265c530f357d3436dcb016064aa60a48783557de6c" },
                { "en-CA", "f1d26a9d0e3357084ea0333f7146c2156e2146500e55208fe02bd7996641273b3d83f3ab4b0da37df13927f25270294d88935613929acae6b82415aac91c1570" },
                { "en-GB", "9c68c075782e13b148d1c94206fa9a35bc29239141c03318035bbfb69a64789ab66d3f746fa64a966a25ba70d6bfe7be6d18f710789feb0f0b2bf8e4572af3fc" },
                { "en-US", "87e9833792621f9cab018dcbfe61101a82b4f91b49eeedc286999b6f9cbd554fc0327fc2935bc8ae10a65be1624897016a0171dccbefe1d4ee96de16d2f44376" },
                { "es-AR", "c1a1f0adf68b42f008c099e93906ac9eaff8c065d20d4265892a3dae28cf29a45f415b7f0c5c4a2a221ba85f3e198fb5018ab5df7bec4902faefa6d8fc9013c1" },
                { "es-ES", "77a7cc6f48307d7c7867b422e8e2b16a6f0275f02508be1375d4cae429df2f72fd998c8cde17c0bebf55ec6234dc8f5f5f843995c3b2ddcbb85310e4fb32b3a5" },
                { "es-MX", "3cd7a322fb4bcb9baaf2ac26268c04c7e308817079f2b8c4547ce4e0bb6d7339925823e8c0e71c8f48524d107c4e2ccd4dbef3aefb672f91dc2f9b0a8868b972" },
                { "et", "77a5b2ebc5e6a3ed3707a7c49c6fc4dbec9d372a1c947e240cf4a40e85fc81c170af83f6e9c9f2bafb1df1a62b6d12f9378dc2049bb3d906c92bbaec855e2c77" },
                { "eu", "4c342e873c9c14b9b9dc7f48ce9b1b13dcd980cc7fd2ba451d977f0a0dc7f1536c92ce52d90248c51263d72c155e85f548325158069a8111fd1f249597392bd1" },
                { "fi", "08c1d85c3283556ce06ad7210c0c5c55ccc968e25e35e0c3ae05765a7416624796f058d79abedfa106c0b7aaf1f19db4e6436e522d9fe3f512c1f61ae63d8269" },
                { "fr", "f0f0ea91ad80f87f4fa4d1e3701efc530e78446cd92d4891387b17e138880bdb688abae7258c2ee5723d3c0e96fc77070b94327bf0bad9cbe64471f70e964a1f" },
                { "fy-NL", "3aa132b55025e97ca431aaa52a7d82a19b8d1fa5735580f4c6eba7f324141844ed408fb3e3dba1cdd7fed98ab5471816e9158ade3ec6e5db67c3e4ce9c06c9e0" },
                { "ga-IE", "17bec1a907d1f680f6935c01e44c54afbabd36a8dc3e60f72e5cf3142b393818652f645d487ae1280d7bfe6c5bc863cdcfaa43d001a2f6f733aae67137a44e64" },
                { "gd", "10731501b3a2161be46569496ab4ef17b6eac3be39f25490e8e2b3138aebcae969eaa5ad620dc00ba46aea334453ec561a0b6c01e6d31a7a0f5d4504889b0117" },
                { "gl", "7e410f2dc5adf2433c395078ca0c478b66453be9b536b41eb9053b1170da1ddf01edce5a91811d8131c495ae48ae294754627f08cdd21bbfe411d0cfb33702f7" },
                { "he", "d278d55301d1bacc8dd33ee6fb9e9b60187414ef935f16c51f99c9d5bcfcc1ef3b86b9f1f87b8137da5d87e8814c4b95c9716368a22b039ba4406cbf866a0401" },
                { "hr", "75be77a4439558696b8c17dcaa569403a97155998000678cebd90b37a287e10fb4030af9a46754f7f9576479efa243f8487c12445c19ee84013a3a41a3c3bbc2" },
                { "hsb", "c60f9b5b0443cba96788504d93d5212585687900cb1f8cbf628e48a893fe78ca9146e2170dea06b37355b7785d4e970870fa60be154ad75182b082059b3fd41b" },
                { "hu", "0ec2e5e37ff4988f955c6af1b3f7c0a640693bc495d57f3454b1a5f9b84292bf4ac760262a4d908e79f876165ed97b29ea4d21706b844144f0125cb19cdcbd03" },
                { "hy-AM", "f2b1bfe7856606e9fb0c7cf784fabe1ab8346a59ea5dce32cd4b3e570cab4e4162c721526dbfdfb8b33db70bf8d0f42148c4ac92a38e467ed0c2a3e57273b867" },
                { "id", "8a10f71c744fc24923672f6a555b4b228cd254f8e4b5ccbb9a1e8a7b2bef8fe9d5a8b4e6a2d0ebbd79a3ac85b88b2c8310d9d70dadac2a30202ca9aa3b160a13" },
                { "is", "ae8ed88ebac40c05635b922cce30ae6135994a3d609e39adc5705b2bb33e58b0bbaf4a6c205825d2328cedca2985edd2aee7db3f644107b6f3e85782c225ab95" },
                { "it", "ca2dc7e31a478a27c6e0b66526fbade54cf80f7c2bbd095b08fbb4b11caab262198bb7081e3df22f6678cf117ca3ada585aa746ad8702ffd6eed350d057fa237" },
                { "ja", "3f1bee2f7f5387468b03cffbefeea01db446a733bf7ae8f85e887a5459cf8c9f082e2aa75df43834eb2aaffdcaaca5df01fe847bb017c9c0f43417b283543b4d" },
                { "ka", "1b0347e38e454ddeea34a6f97a20a622da2ca6c9d3277a9905dc74f96566bc797dcdeb0b8b96f9057e691addb6a44648fb8c294f5fb3011d2ba408102b578081" },
                { "kab", "257526d6c1078aae3884224b918ad94f452c00f47fdca28c99849713d9a692df364e17385ff5b51b01cc98b820a9a4b0123269cdd4c4e81dfffb655ef58e750d" },
                { "kk", "7acf5bc3f07b6fefa116722f609385564da7c4b103aa90508b9a99902fe0ac8c89398a5ff8d726f8127af09e57215883025ddd797c1a871a3d868b46b246cc43" },
                { "ko", "cd46c26698d0c2c05a2b3ff91882993b35f28be1e7d4508211d7ddc9ab55850f7afef0d91c76374d7ea8e096d5324066e2174a0e442912785660696c2795ed6f" },
                { "lt", "9b5ff72e64077576b2a51d7b91bde20e3c22d1418b86e9a5bb2ce6e583df2870be8d51f83319b2b23135cc729cc76210c07aaf819aa18db57de69e3e5c7e6296" },
                { "lv", "2e0e39d7d4e09f2dbf0995819520547a16c0bf799a1010cc98c2349f367b443106b60380439f1ce46d9e100d6c2ddee12cc9463e79ab204e77a4c5fd39d76996" },
                { "ms", "c8966b952911b29621ac3351b093b9e538af7f4bc5f29073e958a312ba0689f3ebfe02529b99ce34616aa94b83a3ab3e2c21b4d7e2363614e230c2b526d55398" },
                { "nb-NO", "65aa4f17845a8a71ee5c63910f5a5a5aa2dd6d2caf65e8f24f6b8f2587d7d129452a51d40f58191d86ed779bd3609f043d9eec7f78c3e57a9259ec67ae274096" },
                { "nl", "c858057785bba533accb329054e51c9c6b4b648b21bc1f2429b060a7b184d71a146c5705afa19fd4e08a9e5ebd0a46837d5286e243f995adcfacaba9c7a3fe73" },
                { "nn-NO", "9b618f7b4c97076c7d0507011906a7b0acfda0a90c072169674d00534a3b76dbc9c404d4eadfc1e490393967c1da3aff1ab9930b8da916d113dc5c44e11bed3c" },
                { "pa-IN", "63c3b9b9563b5ce8fd41d92ffc04c0f8ad28d581a990ae7843667347320f6e9177cce61fa2fd7033f465436a0f0ed1c1673cb4e19f811ef8c569872037c512db" },
                { "pl", "401c4be30562dbe38b71779efee44136cb6c1f1ef8da8fcd026278d294c7761f3248efd5b20db822e232496a6bb3dfbe28aaad981da72c7f26d91f9853cb0178" },
                { "pt-BR", "48e24668bed3f9cbfe75ae78ae092a369c7a0ef50f2a79572fc950094dd1656ead7bbd9da0c94e54ec9088ed8d0ac6ad5f4500d2080718714b8e0eda809948bc" },
                { "pt-PT", "c0f04de8443d315b49d844dd083732251c9ca6660c03b1326e5ba490ae354e94368315b373720d30954bc667ea0decd5fcd9ddc1a60307e9ef39feb37698dc16" },
                { "rm", "ec5c106aa42203e130bfcd9f3c62f5f6c6f8bce0237dc70aed4517b48adb10ae3e8442f40f2cb0eb71e4d3552932ffac9ff294a8e838c0a8a487d33b00e0f5c8" },
                { "ro", "b9624c885a8196a46c613acc982fc92a89fee113cdcb9050cb3c3126b1dfb556801dc72798e299340d0f49d268b06b41d5665c5df85150d8d88275f712391da0" },
                { "ru", "bae0a2e7a83d25a4621caa5bc3588a7c57d6718320d555412bb41b9ff1e23999ef23591c38505ac6b50d5f7382a4bd494855da6dbb0c30078e33823954738a3f" },
                { "sk", "711b7b181b59801bd8abb811b7f605a58dc6d6a533abd164cc4d3a837396b23748f6e6d0dfc86fc2ac3eccf371a92f04916866b8eea3419810cfa237ab2f196c" },
                { "sl", "51f8a8316531d48aabd6ec01c9a4138f7fe3bfbc1315b0a252f0fdf0209535aaafdbaa4fb71be69d5a33670d44b11d9948e9209e746e282fbe49fd1905844ba6" },
                { "sq", "1d7042d32187dd0dc0eed1a707968c764f3f238683d9da7449f01d81ec172d59fd865e51af1aba5710bca1c7915c179c119ebae1ebc7c6c96f8e5074c332b391" },
                { "sr", "000263bf31b72dcad2e2883dc90d8d0f36ef8de3f8bc9d3188e795fdc371278307886dfd8f21e260134ea433e88e46ff64ccf8bfe9ec7ace0cd1d8aec8b26146" },
                { "sv-SE", "2f3e2026a9702765a0fe4f608f6cee4c7e3db0763db261343ee7c0d023ff7867ef11debde838eb665fccc45cd52e43cd5d67c9c3d40e05e64741a93c8461bf67" },
                { "th", "104cdb65af24809f7db176098bbfe055903242f5a4c44acc5e6c0714ae9c8cf4384a9623484c12b9ef11945eb0caf4bee4cee2ebf6f8f25ab372337389457958" },
                { "tr", "b7944e570a1ec2b25d6094cd0338356d7077ccaaad7b725358449ee575e98ea26d4605d0606de8295ff3ae8ae1ec2506c7032f80a822f16a46e13adc7abb9890" },
                { "uk", "a5a2a092d66c3e0be51c3c41a6936ac3b997a1246b0084a66116c2ba47ca90fb34388e26f43c5aea5253f10430adc43536d318ab223f0abe1e4e2e07165aeaf5" },
                { "uz", "5f60fb6c43de2eb11f98ccd8892b60fcd4d97178b1c0738ceb13fd8970124949fbe3647f276671a5d3af5df8cd4fd44ed7e9b376720094dcdd6feda2fc16c057" },
                { "vi", "f19be166b8233babd3ba340d164546894508ac50f0961107815f48aa340502b34c3db65e983d5c163f8edfeb8ed9cb402b102262942dbb39b118cff3debb5dda" },
                { "zh-CN", "58023ce78f004f4c46a4defb67e18b108033da9a4ef809056aa9437b50e4d00edbcbe97a253ecd5e329cec49e644b7ad09091f67babd978428be7c5066cdf183" },
                { "zh-TW", "09be28399173a5df95e67da7af26f326c85708dd643ed7dd78b395f18c32ce5b523d11879041e45b6d8ca00c6c55f512b8c451080f2eea8d0e4cf1db9b4934e1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.4.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "8b4ddae740e94769d120b31dc8668dca8e9dc238f17bf7d840ad4ced320bd62cc281cd8c50f04dfac7957395156c3f98d553c568875ca48aa78855924ec8e1fc" },
                { "ar", "95d9d623de340f4340dc1b685d690f0fd9049556fd3996a1971fe49bfd1d03227cfabe5d38134c06a9601daa332ed582835f20a31f41da7b16678ed6c794f1f0" },
                { "ast", "269df7be74cacad7023514cfdaaf9f2b89e518e9400ffb1ce7165dd18c2592f7db39ba67987efda097b063aca978ebb1d384926098d2ba8277b3763a774e7536" },
                { "be", "63be909c0a539ce5896593c827af5110c9babcb0e0df2431de73d30265e86accc7c0ad4e9000b947c7468572143a4e34dbcdf0dcf84fa3d8bce7744b7c012b01" },
                { "bg", "9caaacc62922a003e33c9e3bbc4baee1ec93b33483817b91400d08a5a022d84c9de677abdbe41c272a40c7ee89a7979c0fb42b8cb0cbc09d5ed3415e5a5200d0" },
                { "br", "b9df72f210c13145e9bf9982299f9df8c1cc366280bd419eb97cb8f83b37b71cc8db67f8bdb94f9aca5a86e45505d28488161752137c9b2561b78af789039810" },
                { "ca", "9e9eec835ef746e9f208a703e7ae4bf8863569c81de5996ef7a71a74f127858c2c7b67f7e1827f1bb503179d9d6bc0fd8259bc443606c90fd7ce1e30744dc0ec" },
                { "cak", "88220c1dc15f8ee19bff21e38cb761f44415b22ced9b394b63ec9b45c2f7e39b72d353e2b2749308b2039bd6b67f504b032e7d50c09a446b7d9ec5509d763301" },
                { "cs", "8522b28621ccbbc9128b362ff9f4d6252cdee941aa0d9817731fc96cd73c1667516c2a3bea0df964b5afd5ec3fcad4a57303069df7718e3b19b9c77f34a45369" },
                { "cy", "59c85bdd51d18f38c4e3fb8d52a2dd2944c35bc209264457b98c948345d454271ad927c15ee50ae943c149a55fd8a9e4e1e9d32ea3e3b573778006397293c12f" },
                { "da", "3dbc670922879b10b1498fe7d4afaaa92ed2ce7fadc46e09c2f2b89e56275834e377e822750a3464ae51e6380e5f6b008451fe14ad563959e6e7c5336d43188b" },
                { "de", "7c039a5ed9ccc80c4a3989519947fd30f09a9a500cea579caee7cccbd289dcbfcd44706ae8aa0a4ed035ca60b49072193b5d30b61e84a578bdd0ecb6e3085928" },
                { "dsb", "baa174a324f51c6ba51f960a26d16b05d3c5c7f0cbe264894610e362aedb67b4c99a557bf362e94e8513d9239f370241d12f51210c066a289b57f44d5b2b9235" },
                { "el", "d5067d9b8e323d55d4cb59135cd03d63823abf7775ead49d93df5a6217d5e3e8da9a38d49aad5000420ae77dab3ae36f029f0ea446237aaf32d9972128ccff56" },
                { "en-CA", "8c6183e180131bd33b60e8f7b1fe0707a82d086869d04032ac25de942d9ca859c1424b6d29a3779bbf2ffbadea61b8ce74754f0afcd78078ab2b7755ebeb6ecb" },
                { "en-GB", "56736f60a580308ff7b69ed39017fb3751bf9b1b820478050648e5bf3a94a3a65e3ebe69854866ec52c50d25ba3a0241c665d4de7059ab037bbb80c837c65b8a" },
                { "en-US", "9f159cd4a75a79612155f98e4ddf3742ef1c32ce7dd0d99da173e414ebd9ebcb3b72dd433e9c7d9cf9803888c67449cd67bf3e434e28f31b2d6c82a7cc3c1d21" },
                { "es-AR", "47d8677820656ff9061ff22475a34a7aeb38d61d4c8c9498d54fb9a19edbf103473d9d9c7a62bf901590779f68e77cf282e1ec5e55fa45e31ca4fdf22bd85f62" },
                { "es-ES", "6560b45b77a05a6b05cac0230774d76d8b697ebf6f52bc401a67b355bbd29f828030d0af364cc55f1be5c61eb29e94466ca1979168cc179663961efb14d6d0f9" },
                { "es-MX", "0d837c701f2eb9f12b6aed5e1a2b413c66768b07f0d036f99a8a51435cb7e3cdb2dee3651ab455a923240a4488f57e3411eb02d180db3a0ca0617ea64b0f80dc" },
                { "et", "1b54dc1ad7c48f4ea75519f21df9fd2820b8cdc2aebd752cd27d823987408b1a3608053436cba9faba20c03705cda0f28853075a7f67f7fbadc6f920576e31fb" },
                { "eu", "a1efe9d4476c9de57eaa93a365473348f43fc3906a06e9969f7703a008a47fe60edfbe06c262cc8eb6171e38326c3529aa75b2ffaf02b234fa5c252fda7da87f" },
                { "fi", "37d08d7bf42345d7606ae8ae10967bc10a4de71cdf9c234b5c24e0fe444a6cc58d03ed5d21f9525f4f0c9663b34e3240c439afa80929231678862d8966e8841b" },
                { "fr", "f2eee0a01468034b0466ad459f6af019df8b9f04b88757b4a93febb0ef511d284e1695735835598c873eb0d5f3f1ba2372d431ceac80ad74728303d14ab73e51" },
                { "fy-NL", "1f7c7e59f77de78c8c4dbb0d6039654994aa72eb7fe6965ae6fe6f51607c3fca3ba0c9ebcddf6bb8bbf3042f90012254fb269aa8def45234472b834fc6af4707" },
                { "ga-IE", "d867ae3250288d1d440142faef4a8a212cb9932c1665268170be69d13e18f49a29e39dcb70083cdb54fe47a98b0ff83616b936e02a3d2b7448d785c28da7d97d" },
                { "gd", "6600b0ccba196d9fce2ce5f1591778232ac9406c748fe40ff90832fb45d048fab206ed56cf9cf631289f9fd864c9165085902b8b348f471910be0661075c17a7" },
                { "gl", "078581afc3137454a55d48f3a225439d022a0f65046a5c68f47a3c1da6821b1cd7149894c23c8c0fe48ff702bfd1a1ae027a6616260231fd7b13b75bbbfb80b7" },
                { "he", "bfb41e93d1c979a75ab1cc0765ac6832721382fb1481cf2dad3e6de0671c8e349ba0f1f4e45e4236c2f6111e3e3b9a8bdc7d6e47590bd5848851fe6c4f74154b" },
                { "hr", "9483249ad44fc6687dfd50a65ae63d6925c89be09054bb3ed3c56ea07a2568e94a6fc2277d77e396d994a698d21958b2bb52c51d2714613a2e0bdce0ee8ae951" },
                { "hsb", "89aa989aebd2515f00f4479c680e65a804226075728985a1cc1b8b8e2bbc109f7206962d1485f32bf8426bddde4b59b4165580b82fa9c426b0418fbe9a667beb" },
                { "hu", "b5168ca05af351b4ef10b924685db59b25f8ff8df38ac5469e468798b46a182712bb5fcf68dc285f4b6db809ff11e5e89aad3bd40c61db1ec180ce64cbee3c50" },
                { "hy-AM", "837cc27322ac2baac2952b2cc0012edfbde05dcd12638bb36e05262d7e35b57a8b911c9d13fa3e3999599c6473bd9c1bb0b4bc804a60e82159e61e1c7e684456" },
                { "id", "3c9dc42d810bdf645a3ea4ca3c7d1000ff681c64b51291e1019c334f126a9c2b7fc0f5ea1ed3db8c2ce6fd95efa62487c036b7f2c45d94a6f7459f9d024a12c7" },
                { "is", "ecdc8643ad7c78846c5d9af52cd0861f5577f0a8b86c6090558abffe67702bcf3155983a4fa2fae5313810f068ba5206a67a5f2b92e73cd1d84b87c06074ab0c" },
                { "it", "6d7e7d3f79a0cee64e6155724a92d6d93703f995a5025ea689277ba206d49861a753643bbbf96f2735a1efa347bca9497b3db7dbe6420e91f03794afb921ab2b" },
                { "ja", "ca8a8c4559bf5cf4a14134261425c5c8b150091cfec4826db7a715af859b75ea52765f65c344f346b5f949a194d598b3af747fc0d09db1222c50d4ead6f6518d" },
                { "ka", "df6e24c2c9b338749a1801ef79f3e6c7cd5c99f97a9d129591acd3a37b65deda7b117736f10cca216218415cdf281e897032764e396f977d6b925db0c7940a65" },
                { "kab", "a74e3ae87cd577b4ef598534cd53630a043c9890640f78d16c03291324def834707ea39a6bd662bea47fa4668af8f0ad97074d78093ab6684f6ec6cd8a48e380" },
                { "kk", "c92a9851607001e88d83fcc5b7d9ef57a6701c9c79ee29ddc7fafda091ff3729ee2f9b82cdc17cefa62019bf51424a1882795d015642c44a51a899398e2deff1" },
                { "ko", "eeea9c587f5b693bb36030a6ffd840ff7709b4e3b58a499d6f59593865c52ed525569b6631c59fec38dc4a71dc6d6bee51fe53cf5f7c70e0cd97502c0d5cb45c" },
                { "lt", "a87e97c81b67656d111826cb2a96e5578d22dd11aac6ccb4611749a7ca77136e3efd50712d4ccd7f33b0ced9077003a986bf565ec3b9190507244f652d343f43" },
                { "lv", "e86754f4c9327941b122d515d37e4184ca4a5ea6733269a330d361292fb346ec2a482bd981cda6499408fba9c115f1d1e2f2684d2d06c1f91d2edbd712a02b4b" },
                { "ms", "8f225576556a1a9c34529c803820fdd45c5a57c44d84fe9161d66f90a27de80b3e845f6e0e3e648b24252afb341051eed45a0458255501886e9a3b31c1339acc" },
                { "nb-NO", "782b1ef5fcf852eecdfe8fea9da2f287372e237fc06531dff1d217e1dc2262e9ba5374a125da593f479bd311a4a6cdea8534e3c1e5fbd9086170e6875ac0ed3d" },
                { "nl", "30de0ff0a60e8152fffe9439d4b911c36541c41293a1fed0c1d958f26c160eb4eb608ce27a59249d002de2b6565b4c26ef2ce063569b324521766b819c90e894" },
                { "nn-NO", "fe79a90d4f13b2ded7f13073fa5376d64ec6126f568804da2387efffc24cbae88c25d8e7808397dcfe67a4edacea2b5789adf5a679c028d95ab429b63c2abd2e" },
                { "pa-IN", "0f1324ff14f87031618f95ff0e823ce089b86f7b81a6ad49da81a8d1d401ff52d7dfc1e175cd2a87481c185506127cfa17e9a90a960bae65648f8339daae2fa4" },
                { "pl", "51624b80bb3aefddf26352f6205d4556894652a2571c169966ec0590b2ab55354e0d22ce7d82b3fa9039a65c40eb664cce7cd84db9f726fcbf6317abbccc1238" },
                { "pt-BR", "2039c8a03017afa4d7fb52218418e7f807419d8f8cd82570867f7c48b71d6a0b51d32762d40315dea8dc343764c93d912093c18b03a82f713d960a6d058148ca" },
                { "pt-PT", "c5bc1ffeb3c486365052e306f61b0fa34ac46e41bffaa13d24ae58f8151f78ccd72ca6513ca2211a5f1fc9b4e8dc1ad56391c0038a8116f98e36d5cd72f20575" },
                { "rm", "cc10fd0ccb0709adee43592d24fe1f55d47995a8aa63781055fa7097ea0e33b9e84a710f75757b3c1b120c7de2db3c06df0749720cb7bab91cf9b75166fdd8a6" },
                { "ro", "b5a18c9a12160da11d0f96d06db2d7b46618daafff90d813c3fd4eb64d26f0cbfc718b6462091822d8147e92f6c70745fcbf76de169dc0ad5eb013134e5dae59" },
                { "ru", "c840c3d799dc18c55a2db70bf0543d2e7b4b9c922a47a2659bdc7b5f4a7cf66b10f027b60d6101811184b2b289034571886dbad2125e17a794126e1340697398" },
                { "sk", "0a00c850acee0ece9a028c0d00dc2e5eddbe3d64778d3d6d1dc7718e6c6ac2a07fa2ea00630c15d75aed4a7a827d8e6e96a9b683c7b0b505224634968861b305" },
                { "sl", "4015b55aada675cc38b96148dd1bd3217880c7e197ecc2a60f90d2d1556a5d769eb1a39dd88a1cb156d736a8bbe2beed22cee6abae0d03a6889bca8bded673c8" },
                { "sq", "19d230d3bda3ee81862683429b5dce9782383d1206214d46b1c4d62f906d2fc52c7c61846e12e3d0961992ea4a438d14828aa6fa74ff3289f314388b5b2facac" },
                { "sr", "b9128c3472b3ba89def463ee8728538ead122e6791eb5cc820a6102c832644279607901a799eeb65381cf041b269ef483ebcc326d6f20ca1690bd19ce9105eca" },
                { "sv-SE", "049ee92e0158086c3b98caec88e29b788380147facfcb437441112a12d6aba70ba96e5f84f6f4c45cf0c6c586d6d1d874b599f84661f3f4ec3d03f96d4067287" },
                { "th", "c1e0295fa327df01f5fd569293439d558168d41ed6f50778015a5f669e00c76ad5f483775b648859308cfe4815feb485ed7484108b5c08356e177216c2745172" },
                { "tr", "8c3b9620b448dac0f95682c47c428789d668efb78ab4d9aa58533896eb1128c0c312e3849f6e67ce3aacf7d6553015c63b7133f46f2e0462cd2377bb1cea8523" },
                { "uk", "95dd21e0172f0cc8345769e93cbb74d395c472afb352db32e14bd29a4aa14cd1fb6b33beb0e8785d20c545ee3050e03ead3bdbc581e8e5e8b40e0fd381edd0a7" },
                { "uz", "99a864bbfba6f3d3e006979968ce3dfc5304bc644ac5163cb80c2e6784132133e5afd5aa8982cb6b85093f32b000abebdcfbe0f92d7d147581723ec106350b77" },
                { "vi", "d4e44aaca43e9fe7b3895706155c3fa3fb91c25ce7b8bab3cced1ac90f521417f50970762456bb231f689d0059a3e2ea793ea2de43ad9c62e33794cb134b2b51" },
                { "zh-CN", "48d6bdd86a215c95db348ae7e2f1de82be27f48db19b16cb53d38c63c8e9ee75b9724e9255d84634d79a81b16cf26aef5b2e551a95556923d16d9f38d1247429" },
                { "zh-TW", "c14e9f3d0ed039a01fd497b7f7cc2a772dd11682ebb86f80d23f0fe8aa762affd9c5548411e83f3036c6bd3c42ebdbda7ee9f7b4f945dd00918e49e9006fd80f" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
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
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

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
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
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
        /// Indicates whether the method searchForNewer() is implemented.
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
        /// Determines whether a separate process must be run before the update.
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
