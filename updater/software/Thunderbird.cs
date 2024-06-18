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
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.12.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "64968eb185bdf27af7f5d7503531866b0a68197d7eba733fd9fad4c0d8e869715cc6e51368ddef379059a9a49b24ed4eb489a1fe9e3d27f6eb50e64ffdbe16f9" },
                { "ar", "916609d87f6737113200a6d9b900d9b8645f73a2d9bb8d8968945bba3ffedd0e41272c93f0b1ff9f4e4bfbf957568556e1a0ce2d7ef9de66752ea7316b20a96c" },
                { "ast", "3cc365c0e124f0f559c56668e07e746928aa603e7c70a46067c623be4e14c1bd4b8b1a6e76a9aa4341b2e17aa3479d8852c15a12d541666548642690f3a78727" },
                { "be", "3ec8d4cf362f5c228339f02cf2e1d2c63b21c64bc754e5475f7229b53be34a881567c159b9c16b252e1e25eaccb0bbdea340861ab75a6a03e360dd4e57aeae3b" },
                { "bg", "945aa0ef2343c98f2eefca880ef61663291b7095575188a600c1292bec68963269fc411f9c7de9a67353d8ffbb378678777d32cd2fb4478a95b8918b37d9f202" },
                { "br", "9f7b4ff193528dd3fca16a64301626f167716209f1fdeff837a295594112e74c646bb2b85c37ca0f56995c1a912ae064a2485c373ad03d1b8d31330e86e66eb9" },
                { "ca", "12cb669f340f131411e20c53627099b0c3ee3b202e01abc9df4faa2a9f9c0782cdc01d8a85576d5add44965de8e146e75d936a68e0abf85e0b792dfd46846883" },
                { "cak", "70ae6980cb100fbd873481c9db07f95ce31cbcad515034ddff5bcaa011f8dc8cb0f260da8402863981778e7ac59bfb7a7e339ffcfc19af13188fd3e348d30e05" },
                { "cs", "ce470d7a9ef1e4d55edd95bcc7dc8eb6cb9f8ac304b03d7fe6d31a43afbb44ca64d474159736c69424827a3a780c360c30e2245a40c5f2796cce14fb2456656a" },
                { "cy", "59cfafa3a30a1b0a7570fe941dc9ce132d02c95c201505445878b27dec7a7cefc8ab811590547a8f9d5c26c751b693e39b1545118b3a33d2add7f3fae0f8f718" },
                { "da", "aa4c8da3355d0a5702b54ddce938d59f3c6740b83deba6f786d34f81df8757949409f3b0750f6c6325b235ddcde85498cc01b77c64159a648b4bcd6dcbbcd510" },
                { "de", "82acd023e37cd9fe1277c75d0372c3e88d0ac7f3ca8ad5de2f64fa99660c8883d9a6f4a89f371c18475e0dbe52e9476f0a5d007a83a88fba92125a72fdb1d888" },
                { "dsb", "98a0ad3bd01bce4158719cea19323b6167622e7ba7e3cdec7dd6db979a6918b41e69b9c533777d91f82ad205407a87a0214f6333e76d7961984ab29cf5481507" },
                { "el", "2ad7cafc2b791cfca9f6cc69cce27352e22a5d5f5d93af0bb962021dc78f831aadce989fa731843c282ab41c5d8c676d49ba5013209c9821826a3f55d1196753" },
                { "en-CA", "535e6c05f86b66b29c7d52e5269e55690f689f8bf534b3f739c04ae98282869753ee66a652debee00d06eca40c85231b7ccc0a61be045a1023d7dc2c933df94e" },
                { "en-GB", "62bfc00d063cd714459bb895e165afd47ee6310ecf4742dbf86a952313f3de2cca7c4b5ea5400cce614a83d306d5f99b29b981f8f0596df07572799788d9434f" },
                { "en-US", "3387e7fcab2c72504631bc5e798eb5aabe6aa25ed9467d3ea9bcc4f287b74bb783b05615d8b730288fb0e245dd3d229a063b4b7a47b088f42eaeaeb4a20f4ed5" },
                { "es-AR", "49e526084507f0013bdc9fb1998880021615c31d13b4c60e1fea4e224be815da13dfb2e8c8628457e69a282fbbf8454ddc18ec099262009292b3b74fc0dd0803" },
                { "es-ES", "bc71199829ea518c179bbdf89fecc78e2bc5f75ede7cbb2875f052271cfa97a5800ef415648a70312ccf15c7e5d97820bd99f223532705019bb53bae445748e6" },
                { "es-MX", "0c16c45e459cb197037288bf20ae68511a34699e50d154180156d17cb9b9f4cec3f6e4e9ef5938f9a5579dd2e9f20d2cf65d80580c25578439cc812c9ab6e1fa" },
                { "et", "cab96f4edcc9fbf45c7bfcfde1668502f3f461b1eb9fd349434288394b4ba3483731a321f96437482408bf5bf7b080a34f33f9daae365998b977347f96a672b3" },
                { "eu", "1290bbb3f648b2ea7b72d725539bc0d2da3df5ee05b829626124d34b407b56e4a3a2c1ac8085c882f6825b30ad0c4285f5f372627df1d414fa793f41a216d0d1" },
                { "fi", "7bd55e0b5fa178d5498ccaf8e4c117897c1d88b4489d0427e7225cfd735c1401e2f340c87ebb1c67547ee98475517fd04a81a721a34ac133ea70c17bbfeb8d8b" },
                { "fr", "63159dfb0cfeb6b989c14fec46432627df330bd60466942245dc68a6c0c92c58df3f6949569c67c78ab4ad235ee35466c5a7b6f5d75694c7b10b59c18e6f3305" },
                { "fy-NL", "547b4033b38081f880520ae538a7485c910bb146e724d93a5a0955d42214f5af878d2d93f5d20716c3a9490fac6e22ba53e2a1ad6d89b9759eb955e00ef02f2a" },
                { "ga-IE", "7614590e10d7d2428f5739c6f3c5825771946007d18e27b72414e425177e1874894d195e612b5ee3372a5ca1c516ed3c0f90c0e96f208a678e40392e337b49a0" },
                { "gd", "db8dd3ed086e1d0642c950b91b0f0e8f94690371fa64c8e598fd0cecbfb043f5585ecf25d4363c58d71adf3eeafbb8c7d21ae397aaf85c38ade66467d8e8ff7e" },
                { "gl", "fafed2ac66d33b74b0de20aaf05339278e4a5db35f3b683def24af43b9620a42c9e765a4c5ccf63e52e152e1446c81f5e11cac3a9bf8059f435cec179c673de0" },
                { "he", "f7c157a3007c7ec76f170a506da88850559a09cb2970f7cf8cbc5ea910d755a7e5013e292d1a7dd126eb9f7d9e2fc9da2164264c0958749e4d1babfc27881c3b" },
                { "hr", "5d6febbf565ac7d9fe63f297b37835cc75392b67835e3b5c6d728aaa73b34f2dcc8e31a0add15c0cf5b39b1406864c9e13ae4e2b73b32112291d77130578f985" },
                { "hsb", "31468128f98a2452f7eee397242378da18b6110a515c77ef3fc32c7972891ec7405ac0c00c434c5d9a70c9f3756835e8c0bda793245cbdd243eddc550044f818" },
                { "hu", "c1b5b0e72b19b82c387a8c2002f57ca0b2292cb361879a61a336de9ced68d7a997bdd654ecb1ab3a86f34b5b937e88260154de874284a315677b0edc0c70ea10" },
                { "hy-AM", "4cfecad5290540617b5d394827dee2e22418cf197fccf022d4d67a40fc5b8cf97050e4fbc63a3dcd40106d2e10011a208010f24c2e84c7fee0897b5c893d6144" },
                { "id", "46f1b1e4e7d797770e19bb40770a63f467652463f52a72c9753820c2302d8efbff7daf21b66ffaab1485b245ecd3488e06968a82c71588a05b740ae9abf06274" },
                { "is", "70a51e8d1fd608da345a759b8a3d271eff9d607d537b83e6b03aa71c9e07449f6965585264b1dec8ee31e28ea267b2e50c4fadaf41c638af013c1b9ed075e787" },
                { "it", "3bd6a07212581f8079d04c8ccb9a197aae976f851bba24be2947abfc36bc182c14d3125c3ade827f15a1f75f748682f02ba281be73825278ad0b993e5d036058" },
                { "ja", "e1f3a3a569d6298ceb933904a58086cc0469f6d1896633147f3098bfd5d7650b73fccde48b6393f5d59532bb67aab1b9a047abe78875e9b2097c7e383ef6da62" },
                { "ka", "8bac86ec72077ee980205f14e4871f696ee48a310ecd9802f617011bead02f59a91372e138b8d4b9f73e2a9afdd361fb99ea23ac77b16a993603867377b90877" },
                { "kab", "c4942f7de0f9f9e62b27653862c6776dfdfdf338ac0aea7244a76aa40c74dd915afd1ca1c79b7512c3f582ee11c041fa94e0a4d6701c5d0feec0e286acdb49f7" },
                { "kk", "d316327130f4e8113323ee21d8818509b955c9b640f3e9bdd94431a795d90aa6f4673764daef0573812184ced330ad3dbb247f1feddfd73b8fbe4e46bfe2a767" },
                { "ko", "5700a5a27a8fd9ea1239f5197e05eaa064e1902157105df358167c5e4e29c90ff4d0ee3cda4f34315f2d0022d523aab4b93fd9fb05f84f24d4428dfe76b293c7" },
                { "lt", "be12240bfa5f75fcee01760cf30b4ab66d0686a09982766c7a7ee676c2fc2acceea1b9ec0fadabee2909a1423b596fec0115d8103d73c4ae7b466c6e5825e60b" },
                { "lv", "d851499e8cad53a64e31935185843022ca4f3c132e257ca79c86076e5205d211d65fe1b7f9fd9d2e4bd8fd0acf4bbc63bc4879e9e0ee054ebcb0df68148f63d6" },
                { "ms", "5efb133bde4816c2297dd53435207e0c6fb5c096e36bad1711595d4bc94d7ad24a78a686a4e04cf835d15573d6f8593e77d76c96918b55f89c3a3ea5f8a6ec7e" },
                { "nb-NO", "21ffa9e2f110054daf32999559426b84d770c2a122a8c56ce2e943d09103701464f683c12e43da3d842b7f6c32479d6cd8fbd9a7d999cac11be5e1999f441bdb" },
                { "nl", "2fc801d711937aa2a893946c7c542723c422c864c038045e9cb418644d6a6eee1a54744f2f5652c4ebae972237b6ea8c7f097bf3b3bf8a6a9eaec2349906d15d" },
                { "nn-NO", "3e57237a99c2e2ff81708ba852da55c4a92e3618034603d7e3a8e1a714e0eaec64e0596ef4594024f2f3029ac21ffb7aa20639a473a506d42a58136a1bff94bc" },
                { "pa-IN", "1fab67270f20144bdb15f11983d7c226edc65d556abf6446ba2996db004b4a437c2ea45097904078faee167f4db2a7c9f0fc6f5e3931fbeea00fe2b14ba7f663" },
                { "pl", "21bf35aacebea072db5d4b4adfc535c0f1769eca2cfc825a2b06cd4047416bcae154944793fd27bff381646cacd8c90d495d8e0e838e7b9330ef1a809a9056a5" },
                { "pt-BR", "eb972be7498581adf91aefd50b25d087b3eebe74d1cd8deffa162ee1d57a0f547bc172d50b7675aa6b49e364df68cb7744a51fb624a3809edb26879b84b64ac9" },
                { "pt-PT", "3d3e01f03c7e82c2044eddd0380508e2eb0c7d164e64032818fc16a27ce2db40956a6575f6e9af2245cc9bd2dcde620f4506e3a42179ace5327f74e195083e0f" },
                { "rm", "6883aac7387de5884f308e443fbd12b7fe784c487a6494ec34caa6214e0bfca773788a80fd003e8b288508b10ce354dd22a32c579287a5bf631ca9fd6e4707a0" },
                { "ro", "98329fe6937cb52b31bb2dc4d872c80abec249fc356c965173c7a93f6fccc85a415f70a584b2907d2b6cd8336053f1d9cced0bac67c36aab44923be5842ecc8d" },
                { "ru", "6ec70781890d7df4de44866b0aa4eaef6f94bf66fc5228ca6b33792e4abea24ee96dff2064387c5f35b29cd4e895c2033886bc63c1818c47b4b07e0b04ad90da" },
                { "sk", "3d438198f65148a64c0fec45334bd4eadd286e58aac6ef32e410a37c3880b4c0a0eb2af97d54324646687a22a120a36cd60d426136af8c1dd28900c4f184c424" },
                { "sl", "0e4edecc73e2668cda29caa66b5b482e597ee0553f0cef45c89f477853ddea56cab17c2fa83e7dc2a711385bde4ec1fdcc39cc9690fc9644eb90cf966dc4474d" },
                { "sq", "31978e62b1e0fdde8a60ce5ebf595dde4f3aa2b5e2bc5012ac351b72f16353122138411e0d681a811cd45de899a4a7744e2526b921c7ff54733e3ce0d596820d" },
                { "sr", "a21bb426374d03ff125fd8330595e17eb75e47ceda38b1df73e64bd868c53b1bd4aea40af7b7cb94422567137f32acd55f7f1c98757dcf7da4555d9361a5e481" },
                { "sv-SE", "42b3599a40eb76190ee9996cc0c6143ea0d60bceba4afa43b419dbcd6018941de49e46e704f47e7261ae91ff17cf805c9a533bce574eaf1f0ce5683a9fb05d71" },
                { "th", "cb64e8f794ee799f40123e4718193dd53e4cdd1c2c862671c3a27604d4dba5b57d275badb67356d38462d540f1f4d4b58c48c2c355f18831567c6bd4544880ab" },
                { "tr", "a3c57333c5e88bf78c123ab223aecd7395b8ee3db35da2a7125fbdbc70988387dbe75094794db86dc9ea694a32b3a676bb745af0afe67eefb930e3e7d70526e4" },
                { "uk", "d2b78230a0a82d3cb204dcddc7b027a28fd0e22fd29998410b8fab159cad267f9f2414b9ef939d6fcc5d7c171a75960385284eb1f26c45a744c90ffaf7f0e033" },
                { "uz", "0b7e9696b8ffafe8bae3e04368a661a0f9be428dc8e05f6e17ecc432b8f736bd0628e1662c1347b9ce7acf2ea05cc98dcba86ae7ace46d0f34eb8ce4703f8250" },
                { "vi", "f4dbe9450051552ff506e6baed0d002c5987845f9c303fd2a8d35dbb19c4ba395a1250c8a4eb51005b1b70eadc57023391e95bbcbd5303f615b971f9855a9a81" },
                { "zh-CN", "ac1964dd651be67712af8b0c67c2a775bdc35c921e85cd9c0bd6ea897e676f853f26f35d1d17d7806983251a50ef366f3c36e079469a3e2f43d8b7356aa91544" },
                { "zh-TW", "1f383ff178f15dc54314560029f4df6548c0a2234fe87736256d6a61ba095a70fcd7570141cf0e698d5e431d94f1ca64c52e369e60b0ac32ea6be58a19d0bb42" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.12.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "e12d7480b88290ca1eda4f7d59b00e06ef590ebabb7af6437603c7272e17d8f2b80deaa9b24622e65e8397cf68a36c046afb73526c8b45d0b1c2807be92552fb" },
                { "ar", "0b663e2db6f8005fd99f521bc87722d38ca768a44f6db7f4fe3054a573c209b358d13ba3c9c5361c80173df21dd1ec01e18dcb43e0e67fcfc6046a77d89bb7d2" },
                { "ast", "6da3098c20d7d3a12e04459d6cafc8c027060f8d18be8dad9ae1a1ed3ffaf9103c6fb4daf350ff7c5f1b6582c021044ce13391dd50465ab1f8989dc4d15dca9f" },
                { "be", "a775870746dc3df74ec095e9bad9571d44bb51c0901b76fe32be2e6656030964d091ebc07ca3b598696afda409dfa20ab3567d8217060cf4b493eb06c6871381" },
                { "bg", "647216b625ad5ff531b6547fb1604b9f801dd7b1f7b20ff6ee92816de0036daabd7efc5801d68c14de5124c608fcafb7f05fce8b50ca07cd02af2a12ee996817" },
                { "br", "ee381473eb013bb11df94d0898c363102be53cc424a646378f5bcc0e472ac176d6b2399633d8a73076c6a9703f00d4633196291bd3f9e482eadd65557e7f212c" },
                { "ca", "e3927acea1041c12f410056d09d3a993b229263b4759864067d02df625203ae720fd8d9f7136c7e70f7e772f895cfe0c57bfcc93ca126454c68ddf84f07ed7b3" },
                { "cak", "82b224cf27ff18e255ed50277a2be4db2b76046b51155a3d6737a23df38dd5d35e2f3596c4e3ad5c5cb9b03cc028b4985af9d448f90b80744db03b76a0f11468" },
                { "cs", "075bc10885646af9d85378b27d1dc7bd4ab6bf413dd8ebc8170e28f22fa4650ca8be6eddc628d260afe227e92f579c09e9481e32cbd701b8ecd803778620ef0f" },
                { "cy", "0d2958791e5687deaf1cc31638b8ec7b9729cdb796c6935b3922d38d7335c9672dfd008d0e1bdcc097f9943ffe06dd4a1693d3e834d0a6f31ee751ebe7574a2b" },
                { "da", "491ae99a74a29035fb89b4adfa141854af92b1c5ec1e480669e56e1b202c5cea6132ee567084a2ce77612048c2c1748f10548896ea79e7153d2a6c624c192fcb" },
                { "de", "ce1235818f97f19f0121de5032b295c8581c8790b29cb8a84e38a7cd33b3924b2fb707671f0fdd8a460d390d576c8741b1bcefaa224e5bf40392818696973625" },
                { "dsb", "027fece5373f60c38150398199fb6a076ec422b6182b174bd561b29bbdfc226550adda6ddf91916e59c5e8c6473eb002273d77c35271795c78c08bd2dbac2c02" },
                { "el", "25b8652cbb04d5c1399933376608c110dbe1d3d5e4045d218ab9dbc47370100a0cd78c4f5d1299dc5192685904ade27ac67836a427983d6c8203bce78b419552" },
                { "en-CA", "79b32b0af559f0d796482b599c60bcb2b667cb6af5930ed30636f0d5e96d45160f4bfce7140a57c2d263a30aa6d7d1b87254adeef341bd9275c0c3fc3ee5d73a" },
                { "en-GB", "7bce22f3eaf7cdc2776917c4191e4652347935e122ca21b6e1574cd17b2ab1a879ad07469ab00ff3e274105a2a018b0b5b9a66c62dc03e830822ca322b691bb6" },
                { "en-US", "b0c9e361f8e658e430d0183a166e7250d8191c262c4e0a6036d9d4cb816d17d29e7dbba4597ab13eb04d037834446f795240e218d7c518b474a66c13a0cee1ce" },
                { "es-AR", "d226858159e966d209cfad5e45848dacc4668ae9a62cf75d286028833e88794cdcdc22c318793c79475fb607bf6447e130eb0f029296015bd25844e5c55a2f53" },
                { "es-ES", "95deb87a86056b676b2294dd6876e4da9ce70c03311749a1ed48763b9529b0aa99bcfec419c4e19edd03cca1c4848b06938c7cdb42b286c62a7fbfa562e9b23a" },
                { "es-MX", "1562324f80b3ae62a4c1be871cea6ac81b80847b42887e7ba86afe13a731d527477f32f42f5d6d515879c6a79197a7eb8975b16e1b42a0fbf0c54e57803da035" },
                { "et", "ddb985ab40b0e1685b082c44cae4d1acf01ba7e3315f8c9a1ab1c8a7371f5f60b0bc3e603c23ca8fa6d01735002878951c4fe19cd66a3c9a83d32e6b3122e481" },
                { "eu", "748c9dfb3560090e0266030b02346459df420720809699a943d29a326ab3965399fd67f74dd711ee73ed9ce6b35a201a838c5fa2002caf11de8ccf2dc33a2118" },
                { "fi", "974ad08e292229b1ad6a2ed95bc1ca3334e79ebe1618838e5592b7e13ed4fadff56bfe1d42a84338cae9035d2f15f2d2a1aaac6760621230c0a9e4c4744444ae" },
                { "fr", "3bf318b5a013cc6d1042614f5d1d2d8b3fec4f24ed4037b6772d81d1f8fd8f3c44e6c69a5623d15bde00275fe71c41df9540e6e8e6ee394bab90aa7c32867ba8" },
                { "fy-NL", "9ba8f1ed2ea8d2e4f51f344851332839d023d703530add83bb95a68cefd7b16c6397d76f36c8be7bdbab88ff31a2df23e95e9e640ccb410e90df252d9058c1b9" },
                { "ga-IE", "77e6efc187bc4c621778bef1875e04eb871b5acc42e395bd40bcd137fc26de042435f9fdb9a69a7f86d41606395d7d48d27492b5e167410d76aea67d924138cc" },
                { "gd", "a4a8f527471ab66d51e0861546e0474c0489bcc8b3331da9ace74bf8c0f7199106fee4a3aef590c72305328486c0890e2e55a2d56d14a8853762a66530f15c5b" },
                { "gl", "11071d3b6cd6d77ab28aef76c042ad6dd612e07c3e4a2725729d789911099710938c7e0a5c636a8abd4e9196b0c2d46c61a6134a55faf837e878b15fa668883f" },
                { "he", "1c1184796647b2eebbcf0703834aaf508968324c5cb4518e148e59b7f52d5842c62cc42938bba0b76af9429f2d12cfb6bf48337689ba0160bb0e9b8982555981" },
                { "hr", "c66e7755bdc8e242a69960e80fc80b8969cec05ee5b5779ec1a4d62dafe322a1f968551cb46c2d448840a4b3c4ef38e45a82b53be3b201f98e475e24b652be90" },
                { "hsb", "c13dc90797bc4d466580bac52eef5980be55907bbf0f748e7be2f4666f9fc351b72c0f50f917f2edc23f1d849b1accc8dd0091c44b8eec0afcddc24ff091bdb6" },
                { "hu", "2fd881e8eb6f05ff15dfdf93975ad5cd3586379c2f98a51ad684bc76dc15657b3390956cc15b6523a1a7dde002b0118954a2217bcabcd11133cd4603379c614e" },
                { "hy-AM", "8347bb5b02f5ce63b4a18c3a257f64aa02092f0c587df4a97844041fb278b13cfe2ce36c4926cb07ebbcff2aabee9d93ccfb3de2864dc5cbda33c5ff7c58a8d5" },
                { "id", "10fddb42be1d7210b661b79ebcd81e88facdb8bbf491f595fec21ec36ad68eacbb5a56e00791faac1bd693e180d540590aff5219ea29542f7055850f7f7558c2" },
                { "is", "30c25f98fdb0fd6a286b5304e1674f30cc0bf4ce76a376a1e8c1f3820f31e729459ed37e1a7c8e369f18e904b5d01c2b91808fdf9d4a8fd26546f96adcb64425" },
                { "it", "516311ba4c1598f786110ec10a5aa0eaa312ac2bc0adcfee640949e74151736970cbc5abd544c2cd373dd638793adaaceb6dfe015fb19cc150e4963ce82ac906" },
                { "ja", "ef6858dc6805582ea71108842fd90505a94760f19b8a1abc799598d9de77291a72121fbaca893950bc55e91c2d0fdedafe0f3c5cb8e43eb336025294aa8f5081" },
                { "ka", "8fcf0544a1f8c0ce243f967478bbec02736264c5c71de813c25daaaeb6fa3adac3298b1c2efd45423a089bc272c87402238145c90c8988dd0e81872212018f27" },
                { "kab", "774eb70044a44d78b6699a9b0d4581bb0d9b3c9010efa35bfa624f9af09766f84c4eca17a1c7eecd465c105a72d5af531c42ab58fdcbbfabd82aaada3a82c67d" },
                { "kk", "be010e204b802f27d598e2af5c2b81bdd4a39592c714b0a75ae4ed568fc9962709e4eca0b8065c15d52c7a4834aaccfc56bc63c145431d982e12385d81748a8e" },
                { "ko", "e17e888e4942b6aa8c4c7b49c81ff97a7f66e4b00a492003590f06467bfe8c0d356cd13a377cf7c05436ad9d03ea909bea4438213284f235a846b283c156ab03" },
                { "lt", "85e1f77021bd40dfa4696e9b6cdf398d96f9c488225f4caf547e4165e2814b22394201445b73212386283e0c220573d8d1341e8c19b03611f1e04560f60701ff" },
                { "lv", "650cc1593f4ad49377f91dcc38cc180a4f98ffb62c5b64ac23444ff5b06731f3f911c7c94ad4dbed47dfff337cd3202d0eb2d6ce443b0346ac33ece14cdee748" },
                { "ms", "e783bb09cf23ff1e12b77cc054309be815fa1fdccc989bdd3bcb37f79a8d74f3903d2d40c465a34e1e40e396f38d8afd96498c630251365bac614c326dfbe545" },
                { "nb-NO", "860fa7eadd4d7846de08fcd4e077b77937ddca5d8ea7af6a90684028ff4a8adc2c7178bd8bc3c70a38f1cdb2ba5fabe9ee3f971af7bfd13f5ee5005c4c768f17" },
                { "nl", "b42c9b882307f7f9dfd7c73b074d7da847a2574bf1f359de6d9f5a4ffc18a6507b9f2645472d696e2e2b0376c54a63b295d75d8e50a95c75576e14205dca99db" },
                { "nn-NO", "7430918fc32428b3a83f27f06f34189e2a8211128e038aeaa83f54320a781144ecbcff969b89771ed6176859f43d0d4c43f45e7cedbcd1a7690100ecff1a778c" },
                { "pa-IN", "9dbde582e4f5c9fcfd2a81fd6b288b0e2d465bab10cd52741f2087e5eba1943d3352531a940f6201b3d44b3c367fd675cca145c66f16f7b098dc0d6a4abae047" },
                { "pl", "3b35bffab4b81ca2a99876a12b2dc15f98830cf02ffc1310f35c1f07cc9d915f0bfaa5d81ca35c62fb1f929dc87be3c5ce428cacf7e8673aaacf33f95a392d6a" },
                { "pt-BR", "bcf0c117e4e75b7a25773e695c107a2c647b323086c8c807aa8f0a14d539cd0af9dcd791668ff4f462988020be406868a2f2442deff1d5b36a52a2be3d720728" },
                { "pt-PT", "593731b9750bbfd1187b1dffa9807fcb652797fb4c2765aa0d0dc903f7665bd1fa5ceed51831487fbf9d9982081c7fea3e20c685a4a4b4c863046d61e2fd52cb" },
                { "rm", "99c924c71f15477c0898ae0867a84117d84fe2288aa85761804a4959cf631726ec11ef3fc3befcd52106b4ff5000426b446d22f97147ce222f367c50ed466ab8" },
                { "ro", "e055909e29be9ed8b2180fa00b213a7d76af26b0a94f805414d059431979c5604fe65e072f5308ea206e9bc0ba1c6b2b9bca4cbc562628dc6240f30b2cfcffeb" },
                { "ru", "0d3671be5459f84c85f7e55908651fe9d89404fa4f7f285fb2af4b4605a4873097ed31fef0de7af5f1db502024c9b4fe6688eb45f6fa9664fcd27b251c860d79" },
                { "sk", "65e2b6b426fe5eddc028423085620f298d116758de57d591e7a3b7d7d71c580db48e7b7384ee4c197d81252a05090847f8edbe9d313b9916caf2b2a10d30c535" },
                { "sl", "9f41294320f92b24c1dbace7107fd2dcb035a8a0d7febafa94a7c8d43cee25d6fcc38f26db6e35ed85434fb530778a179cc5222303dcde096899c7c758bb1d43" },
                { "sq", "703c0ca6ea65aa291510d40e4b487a27159354b496bcc1b514f321d63d1ffc95a95e6072e8da6ed7185361203b64c1842e1e4ae447b6631a402df5ec29097557" },
                { "sr", "1fc4a9d6ebc9de1bf8511f8cd9941675bc310c1474b26857c9df48b4886370cf4e60f345875395cf40375f413b82078cb27ae2525d4f9f671b927d423bd30824" },
                { "sv-SE", "c62fb8ad7eb6954a6e8db1e39a65016d4a819f195da10dbea23e5e47408b65b9d5cfe13bcdb5f861c49ddd5576229d1e5af2067f7fbcf5f211231c6dc78fb9cd" },
                { "th", "a85a1467f9c7fe8879c3c48fc29d917c504789cd9c7cf7a58d6b6689ebde5e9750196cd0648530c09a5061ca2c78b2e6753406dde53da3c425b728804d3dfcca" },
                { "tr", "8994dedc0bb2d026eb96992f38285214c3653916eb86121969dd3cb8b11bd81efc7629080ce6b3bbe0478f2e6da935718317175251b9d5d2ee17567687208861" },
                { "uk", "827aadfe5edd8ce5cd39c95e5bd3b1a85a6f4b32df9756b9e7b0bad6bbd6b9bc2909019d79457c4ab8bd895d4a2e54bf5e7168d457ae35a2755cc6699d57b920" },
                { "uz", "6b91f69b5e2bcf8551444864c0feea663c0cefb6a2c66a18c128316a5957e1faf9642552eb5d4a499511113660f74eec56a8be03c48737f81b18993cc889a146" },
                { "vi", "9b60af4bf68d7cca006ab81beeb2e6126bab3bc6c46d1b6b22b30be2d75fd75abe05e231fb02cc9e3036a45e824c2442a23f0b3caee3d771c19c6d2960e9623d" },
                { "zh-CN", "55c80603a64917b5821004013798834e096c78c264ac7af1317203268045ff2c4bef160b1337f1fa38bd2d6fa3023fa6336cfe6a160eb52a84e673945983a7af" },
                { "zh-TW", "51d70c814226bde8fb63d2b0c952847f95630bce59b1319acb92ac1b9e6d041ac219f289a0c5ba90ec5e256aeea9fbb7da6ea6984e8c2f5c6bd8c5bba5ea787f" }
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
            const string version = "115.12.0";
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
