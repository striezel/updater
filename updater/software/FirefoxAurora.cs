﻿/*
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
        private const string currentVersion = "139.0b3";


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
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7295e05b84bad7dd2fde19c6e21fcca7d86d4b056e94660ba43936e1d1abc08cbcd05eb02750257127908c9abfadc916ee4085d7f8e9b5790e5a2cd84414791b" },
                { "af", "a634cb1c3ce5c75e4bd5409ba36a69e6108b728b7881d78dbe1c0a55bca835702b6f2ad691ed9ffb0b5624f2ae6ebf4e9ef7caf63a3f4a5b9e23f7c9db9d6658" },
                { "an", "30b5050e958ca16e1dfe2d140077077b60aabdc771ea0f34c1a421b4a131154f0947f7ee1de69054b826ab34d2433893755e6dbc4824dc551d9fa14526c14b1f" },
                { "ar", "bd8e316e26d097337c0ef865f8e56df249373d2d7dad4d3f0106844b900c04a4a673a1b1b5fe733d0869534ff32beeae11ed8bda19d78694a4903c9d9c63a76f" },
                { "ast", "d1d2ccd9e03e749763e221559ada82356c01ef4d68522ca88bc4adadff0f14ce853ee25eb4141d515da1e111ef001773e6f73727687a01a557ff5aaf6efd2a78" },
                { "az", "bac88adb209e193cbf57cfb7a266d5e874c079d86e71bd0f03b18f759a55c9c4ef97f1e5b31d98d209d5829fc5b6d2050ed7ece493e6842457b444530b3f8397" },
                { "be", "2835ddc67885f36a1481ba5b0d3e486a4e278e13148d7334c634a8d7dd791adca1e43600bae367f1ff62db155ad262535defaa7c26bcf2eafc1df13d7e7c6119" },
                { "bg", "b7897966e740639523832ed19efa4da700ca64add0c9294aafefa31ef6eef700440eb452257df77350731f383643421b317a8307281a595ad1831d9f198e5d4f" },
                { "bn", "4ca2bb3139c57e58429d44ba720faa772bc33ed5358313039aaa7869e6919b79a24b2f8371134f6bbc04993549f626c05d9833bd4ade1426c319928884d07617" },
                { "br", "5f20f909da3ec0ebdbf732b19ca1f4767c87916815a776993242d4a80914cfbdcc2519764d510255d15ff5d656d50bfa686c1362c23faff6759ac0a847597ee2" },
                { "bs", "27a595ea5039b06ffd5807e17a709bef25319bb621cf70df324b7afe36b7b236d8ae16313dfeb1862d806b89b53d50c3dc8dceffd79dcc1a87fc0687610286a5" },
                { "ca", "49f1a403698ba40d16aca6cc6f00ebe7d105488a338e0168efbfad084c74f349a707c9f087b3e32f09cf4c1b3655e250b2fe920ef1eb7e751be2d25b30317d45" },
                { "cak", "e948696f3d97b79a2fb826f17daf3eca1bf4a93cff88d94d994259d0bd3fd4d4433f0a4617bc7c098656f7136444af657f196fee5bc31e442eec6aacf8068d24" },
                { "cs", "a4227203a1d150c6f01e46ab29fb93127f207de05de2e121206b5ef47d82f4d7fead68eed3d3dc0b89c43717d4e3d9e636c38e2734927793f626631a49d6bb45" },
                { "cy", "fedb33898507459631a8933fe84f204e74eb7ceaad37852f7d340c23270a1d83c339374e377df809aa93fd3e30e9b4e1a2f2762e095f5d598fd26c912458c245" },
                { "da", "3a4f56ab8064e5272cb421e69af8237b694c70c08894b032a7be41cc6c043fc9d4daf8126aa535e91de0ea584c86746c368cb3a373ba26dded8318229684eebc" },
                { "de", "4e9e9dd0c3edd8c38072fcc74594be48d1009d9f11530084443008a31f00cfa069f14d8d81ca5eddea0ba1a5cd68c605f4f34e91a21a272b706d02d20feadcb5" },
                { "dsb", "1b586c4ac0cb429e486847101413fe1dcb88d15896057e381be49ddb16f3b3a143e7c3d8e6709c083be9c47caf526a2654256e6570728d60c77b6370d4aca768" },
                { "el", "241f83d908612c964412c49afda3d2a8da832251026cb724896411d33df960fab06410906f9c80ac27391418f2683794664b8a001f42a20e9246f8b0d346f5b7" },
                { "en-CA", "6fdb523ec55648657403a0a4dfb350b628092885f98218c7a76035bab84b6870e40b5c1740673753f811b5024baefa7d8d3c71d61e57378e3aaddd733e134930" },
                { "en-GB", "be650378d36bc99b6df85b045abd4890779e98b70c51a8c0ffa365d96edb6b0b9c218411a0ddf1be0a8f92d063fd45a8db8775d63d192224d0412b79b0922678" },
                { "en-US", "cc584e33f062d455fe272fe4dfbb5d23bb7749f8e89565ea0251703c3814c37b22c310a702b201c7842fbfa68baf9ab7d9d81d51297d653238eb40baedc12e19" },
                { "eo", "0d2aa198977063b363eaa4351d1767c3343a606eba8938431d8e85f1d20a016b90e953f9f8ca7c43322fa1aef861ef614905442b8362d72782cb026f7160ba25" },
                { "es-AR", "0423b1891c26c958b2fffa05a80401e713cf12e6b4d2cf2a35f1bae22a747b0874798d906a0c4a2b8c622a2d45d01c6e6a836f8760523c54cf819a7b6810a013" },
                { "es-CL", "94070aa76d206a5a6cd3a7ec696fd15d85a535b2849857dbd71c368818ba2bf4eda61ef8d023094a5c9b7bd641d9982a821c73f1ffecb4273d0d016d8136f13d" },
                { "es-ES", "4aa7e226a7e06395e82a8f3cd41b5430f20f0a61aaa00b69b17d6fb64a9bbc48bd8c7c226437605559ab0ab1c85d5ca1b76fb779f43cdd19a98b26b23598186b" },
                { "es-MX", "e3eaa1a59269aef50e98b3a66cbf0de8c8b737ad85ba347c389fcee3c0b3e0b8b4cb9541bb0cfb9418d6b0847b89c20c91d01371d01ab6b0d70497a1a0ccf3dd" },
                { "et", "537f04d538db7b865556ec7c92cd3b283c8561d9466dcef90bfb2d5f70d8c2b1fe3f927e149d0bcdd7610b614da5918bdc6c8bb06bf4926fba0309d761b529c7" },
                { "eu", "dba4a62a9be17c25670c061da6bd893a9f7332e1d25aedd50ae6704c2807f260b6411a01c042b87242c3711e2c049c9df551832894b514e7dd76990bddbd6813" },
                { "fa", "47f6be8ea42b1c9a847c3644be26869695d1c53b2e1455dc5d2af057e59919a47cc16ba39775994dc2d7facb8b12bd2715226ef56a5f447f9486a526b62e1367" },
                { "ff", "c4d61c26499f6f7da9c9c222430bdcf1a6b5d065be50a0e519228bb2e7a8b2aa46ca0e63a30bcfc0906224042f9028cc68194ab7b21670080d340f646ae43637" },
                { "fi", "723c5c5030b3f8f07c02b4f1bf923198368f01c82157dd5c4d3ad9b1a54cf0415e2a9125b8cc4a0843e31c779deffa0a07707dc47980f39819a64c4c39971bac" },
                { "fr", "c4cf5622a723423c3fb6061dc6d4d1f8d72ba3f1bf99b5c70fede41a7e1298fdc11a4daad50701ad73e2254b5103edc4106f8a4d29f26b9dec59d3de863d9a7c" },
                { "fur", "7e436d319228a9d2d7508f6461fe2533d118c35907da3b32a2e1955bb5f9794fe1492495548fe49ba7b4d890871b93c7910311aeab11172b6ee72dd5eeba8ec7" },
                { "fy-NL", "e5a1e0c34fc14e371a434027f7bcbdf28c6788a0c401a500a5996944a060fd7eddafffe0c8f43d43c59921daffa1d26bfc1d33c2443c23d5e6454d220a8f5d28" },
                { "ga-IE", "829f2b28abd1b48b4799540d8cf1638fdea0c783b2b3eca6f82c17084afd4cd8074bb205257028d4ab04a7ca6089e848dc1b1d5807a83bf5fd30fdb054d425a4" },
                { "gd", "718e9e3838dc280c7bf51f6feb0077bb1d0610ec309f8b5653709219eae469cbddd72dbea67fb26f3c2d16c3518fda5f997646d4d529ab9e5698c547b9c1f70d" },
                { "gl", "156ba6cb1b5ae1fe05f05a93fef5d667dcdf1c201eb95625ff15f550909156e44a9a521bc7d0109be1f1016ca0a6edd74850db1f65cbeb2e83d6396bf3096db0" },
                { "gn", "9e5e86d30817a2f764b7ac2cb025f63a34beedf4c82427dadaf7e150eb5758936c07b9cde91d09d1c4bf17f43946710838a22b6b7582cbf29a603f830b4932ef" },
                { "gu-IN", "1f2bc4f9322f50fa315c5c0e4989ddb8f3562fe2dfc2920b676ca3df685c48c3a6cf5b339aba9b7189830723ac35e0094abbc07e780a3146ffdd43003dbdc770" },
                { "he", "d06e3c4ceec8372a68d5c14e33658dec0feaaeed8b30a1c2a0378c2ff597c19c6caec601bf86952d48f89e503bbcdf1c1bf6c941d25890840316c8fdfa19ee4c" },
                { "hi-IN", "ee9cbeece20aca52be8f184053c4204825fac5dc9d0c427390030928b9d1a8ccd246da519af859ca05deeecc6a7f488dab02a5af510706f003ec29de3ee82de1" },
                { "hr", "8ec352e8f176d1e47f83e9a5e673bbc7526393dd54a000d7d53c3008109c99a8e01560f7e0bc99e557c1fecde8324d4a462243c4abd73f24d900273c1001da3e" },
                { "hsb", "20fd75eac9a9a8918238b99a5e84ae05207ca838f08d812b991a7743a979242b6bf69b20dcd446dfb79ee2d54eec950ac67eb2c061bd13c3e9ffedfd9fd90330" },
                { "hu", "289b5703862e599de671529b01d364f4aa1fee3e31843b8056d361a83630ab5c010c23b345711ef67d121e9e1f7d4ba92b73cfaa5ec9582160c4e39b8a2dd5e6" },
                { "hy-AM", "3f1fe97232c2ea947251cf839bc2e88ddc2ab6d5a7ed3bda34d3ea7409d392705b633e10e0e495839cc5b062aa4e8aaaa53eae332d5432728c0d5f3ed38f43cb" },
                { "ia", "c8145696b4aa8acc456544a2184a81213500ca1b5a5ed7166ff4e63611617d8ed60745cd442801d172ef64b789905266938a6774862b5216509d3e2d00d45e6b" },
                { "id", "e8a70612a78ba3f0840282174df9011cf5bdda5f565f14b66756af330ddfebe199f2ce7edad8b56b1223ec5e3f8165fd734710f96a28ee75597bc0231eba88a7" },
                { "is", "41cc51c4d90ca9d9c5203ce1dd6b98f2e8750506599a5ba047d84d368f4cfdf91400fe394a01a237d15599afbf88b626bc05360f80cdd82219b95296046ff606" },
                { "it", "6a2078cff29788ce4951b35542bdc1ba5346be2b51beb77efc3626a636b015319afb9809928bb40b60e0877da0a61b3cce8873c7d88778a47e7828b71b36bbc4" },
                { "ja", "d34fe40840ebace422802b25775f936081386c25bfdf8f7d4b6465bf0a964867a37c3bd4606016cdeadc24bc381a54f0d87fa21500b35b63fdbd676306203567" },
                { "ka", "0deda4500c0a9312988733731ff15ef18cc2c38b5d90228427242eecd3a7300c96d8b0b4813fabdcc7f5e174dcc44e55bb8ae4b743e6e025d288540484f2a83b" },
                { "kab", "96a13d69ae17b551e162145bd4719d04f636328b5a50e5fb919009c2280c36aceda16c1efd6cfa96a17b41fec714bbe1ea8ab12c5d43355bdc159161b2e247a5" },
                { "kk", "799e5ee05201bc9cd7d656ea2dac930833783fde98978d6e327a43a0c1705838610ff8318d3f0b52161b6e175e16627fa4d51d0d0d45be88cc1b8605a790a0a5" },
                { "km", "8c719ae17c1777262fefc342dc8d0f94b2a5ab7b0b888040fd7d5bd945cf796e17ad74d67e3c08f793298575501608e1431bf566b98de911f3c01539fa26798a" },
                { "kn", "519aba6cfe41fee0d70ea5deef63c995687cd694149fa55ab10dc6bfa95b54cd2023b3edec0dc58f7f0e9fcd05c3ce4b715c2cf32b4b0caa1862f09cc83ac168" },
                { "ko", "0fbc26085440cbde340eba0448cc3d5a14e86eaa5000a28190722977a8fe689ecad0c67c64d0d941694ed77ab48c3975443c4c0b4fa0474a1e5c5aa4be928826" },
                { "lij", "4683f57b5f44c3dd9ae0ef03f075a4b8fc2533ed5a966f7e48ad5d9dd63ce3e98cbb3d73b925cdd6206105679785e7d0f825aa0ed5611a656ead94fbf2c14635" },
                { "lt", "72627b1129cd3cc0b188f37d0d13e568c8897f080e8de3060f7443ebd41b93484749693fd0b8b9eab0773d0b8700ed260dea23655e36aa30eeeac5661d3c6f13" },
                { "lv", "9b8b1e399ab3c64ec6bf04ed8fd3d5bfb68a8f9dfaa2ec2e6c9fd9d2ac15f0d0bff8ea0743758d7cf25cacea1bd957c3516a778032a58545511c0449f177bacf" },
                { "mk", "7d1e8cd17b4e6ae762f8fcecbc36e442458429b52a4efdf0a61f752c1e92590459458f58c41d98d648deee49c33c1ce813e94d55d57d88f032beaff39de1a03e" },
                { "mr", "2a54ae88eaaf33232b20ec6d9a4a2e19a949c8b5eea43d26d66b1932cd011289c4c986e6f1e6412152d2bee6b264b83137a162e6579cec49b78ebd8955ed5e30" },
                { "ms", "22084f3b557c0eea7a46e891eef9f4976fa60130e8269fcf9194b404d4d0f73757d2c085c6e457ba497fbadcf91fab0053ae5e5573ef3b81193cd7781d594a2d" },
                { "my", "10d8edf53941b59d33a28ce7fbe733813707e628386e506ff5628205ed2ea975da2ab65c91e1272c548def89abbd296438996b7514d297fb491fbf576906983d" },
                { "nb-NO", "2efea5216ffab0719bf2867e96fd68fb39d646be46c39b4d97631a1b5a94301df16ccf6c2b9311d2e4e47698b6cc98816289884c10fba1ce6695ea66c8409502" },
                { "ne-NP", "8a90bdf426d5db658cf93c8479acf406d0eab105b3ed4a5250b5cb395afe4c083f47e56797106cfd375a32ebe559c90a409aff326b61124e031095bb2b225513" },
                { "nl", "4facd1681da96895ddcbc7ed195fb4bb418e097a21334ed5cdb66a6378efe7223e61ca4efea5cd13433bf175e69b27f1568e4f197b27194e0a7547b49350b91f" },
                { "nn-NO", "959f53b332d9b1940c4246569e7615144506cbdbd8704353ca837514a1de664b1fd345d3a28451db16b60dd07cbfbeeba73068d8b91c66c68ad9d955a4d6b029" },
                { "oc", "442da9d9a68b62ee01828bd7865cdb8080a7d408a2f9b903403c67606b952e6a209cf8b068f2ccd6210bd99023b4fa375500d18b6997bc6bc133c0da1c1fa5d1" },
                { "pa-IN", "584f92de343f596fa2a502ba79336a830b82202b2d8143599911cf4e38c5e8f2031eaa262363b7e9dddc9b3a68bbcf2d87c1a35a41a625a343856daee4865771" },
                { "pl", "025f607fd400a22f71fd91c7ce295df187ef7b1e1f94713ebfcb9eb28cf861f825a9845fafbb2326bf766cdfd5a3f26aa77c0ab9e34fe59fc091ec592238a715" },
                { "pt-BR", "e0ff1c01d94408bd8e5e764e4e3b03555dd4608f6cf7b37bae285f49abf7bba1cf908f82db0d334832d5c0dfb1b70556cf845cfae57eed7e8abda9d565b8f130" },
                { "pt-PT", "91772e0694492d0940e9a722d7eeee2a50c19998108f8a4b5a9bc5349fded1c42b07fd954eafcf3f4ad670d69d32bd4a6056f91fc49e4477a81a17d0d1efdfdd" },
                { "rm", "7c6dcc4570c55492fa62db6cf8d9cf79944b295a927817f0bb70fa6d5f922f57bb2731ecc3942ddce794ff9be8b4ed4b2f06f42cf9a7f07cb45aa6b49e28a781" },
                { "ro", "f01fa861ebe7092d2cdb7446e73e17b18185bc69575a2ae1635cae7e62d3f6b33f3f634f2a2f0df9aed9b872635040636a211c27bbbb355085b9ea69c3522434" },
                { "ru", "08c295bf144459c952c483f87358085b371459c341af645c4fd20c6e86041156006323188a660e7b02522ad8d5d37d5c5cc934601f3d8b7b737b82359bf11e8d" },
                { "sat", "baddac416ef01e2329eb51eff73dead1b1f20c534118f8146069a6e55543b9a447dcc10f020dd6cecae2036792006af5a34863fc1c87f44c16ba23cf22b49403" },
                { "sc", "d961425641554329d68e7123582f9e9ff6aa8fea67ac1dbd2e4c580c1da1eba73ad3725a58cdacf2304b9a7d02fcf6e7ea39e6d29f1b2fe9f17c29d6762cc276" },
                { "sco", "7bc86db8950ec92f2cfe5c47ebed4f28aaf407944add5b9a28890b760f1bd3b1de1f35c74f2bf1130ef31e61aa54e66bcd5f4a3b03dbf6965fe01f2f5b803763" },
                { "si", "864720ca0d5f20949a87b5015298523d9993f8b5484624ec9f5b04efb2fcb49a9913d63eb5ec543f4f350eea40fc0148be6d96c3b564720e10debbbd8798aae6" },
                { "sk", "da5a48b250e961bd63cab1189832a9f8ec45ffd05c3194e6fa10e6bbda7053b804ea0c121dfe9c32a010cb3f3e4885f3cf91bf18844e13fdd2c8eaffdf03aebf" },
                { "skr", "90f481868111948a1eb50f35559882120b8ef9ef44428ab92e31748646b55c1b1738670489213dfa32892c4ed3e133d26e5685d95e7d78e2395e4cc3141c87b9" },
                { "sl", "98a36ddda5019a912296eb1f63df661aa4ff0d9caeb10460a3ffa177b699bad30939ac6288f2e06a62c33bf3dc11961b447da1a388609db088fac70bebb33f15" },
                { "son", "ac67b38c2f61f0af2d7fcf94283448ee51a8ca7eef14571cfa484ce3c3641c33fd86f35c297f4cacdffef7882721707212fcfd7bc5d6f36684e66afb49db064e" },
                { "sq", "2eb917b5be52c7087098c0a33fd8cd5a3494d280cccc08fa474bd05fab3dbc93931c298b91b661fcc608525f3eda793f9fe1c8615bd9aa37c840a43f4291cd9e" },
                { "sr", "d5478c7efd3046bb617106a49398570bb0d876ce1318d2a2207ca6c6fb28094a1d4bec0210b0e062f65d4df89870029aa1bec50a26264b4b75f7f96c537443fe" },
                { "sv-SE", "d9b1d7e3f60cd3dbede1c6bd829667664eb4270c32893aea4db00679741ee9bf6a1422d90820e5507e52589cde0289060c4e6575cdabf1974aeb73ad314f4b67" },
                { "szl", "abc33c28e0011cac73d7bfa00f7f2ae0bd71661a626a74c1e70ef56ab314e6e471e5955555c719d402c60657970131fec40d1714123695b1ab144eccfae39071" },
                { "ta", "9ee6ef61142975f1e5658e69531faf1e45eb87ffaa461fe1571d4e086fac01c2d50ca9ffb1f5c147904fbd2a77a435af31b6b171a0effaa30c8aeef3433296da" },
                { "te", "4bb6050b443f572b03588ccb17b5d24c33b00e4dfd84ade7164891176eae4bce957758f76ef8f989888ca78882b3a12056830836431ee6674b76c466baf3715d" },
                { "tg", "4cd215b94ca82b8d7785b2e1aa66c5015cb4fa6d442a65383e173517f1bce1db7c19ef07d47e0273b59803fe1e9c922f3e55c57348e29e1b3ac71fa3a31a844a" },
                { "th", "0b13eca584055459382dc97f24e1109b10b593e68f8c1c81435495e27bf7c83522cb852bfc2165775c2e615a37bf9898e8e2e24b1188fee6df91a8f29d1062d0" },
                { "tl", "4958eb76fb4ecdbd11b216e2a9e96820dc81690f7da2964f26635049dd32fe94ef8ac3ae091bc15e0db22982240e3ad14b462181d7b45bfa3fbf9c4691e3a711" },
                { "tr", "dbeb5391403af6725df2b16dde51645c8ffd3dca6de133c01da7acffaf9d9b4b9f16e6b44e93397874132185171408fc6f139e46a7a817596a57505016f4ee74" },
                { "trs", "f91c16cb812e99981a167d761dd21541baa9a4282100581479c02363bccccaaaa144cba44a6f452925173e9cf807dda39ddf051c4d791655733c8d7a9035286e" },
                { "uk", "23041e6aa2c415f1c06eabfe4e437a0643b26cc49807fca1294b35de7845f5f9d9354f6d011d2ff55adc78a1b9e081f704109c3f82d7e3bb32f9a60d0a78a9b0" },
                { "ur", "5ed1f0d4cd3ae1e3f7d155878389d9136a0fbcf8764a522396c95f2768bb42a9031ccb831b51a9386ea3198425012f5c58eb077c692f6aa2cb94642f85dc2852" },
                { "uz", "caf5e4b7ea0480aa2ffd13cead49928782f99047a73ee055204fd9ae2deb1ddec4808ec2f2633439aadc76b12d56e27e90ca26350f5fa94570b1f8e473564322" },
                { "vi", "92310adca42ffd7911a8ba6b0a5c6ef4a0f8211797b23e9060cf07c07555215b2e8150312bf528e21e2ccf61e87ce45d886081362de76a7324bfad0f0bbfda24" },
                { "xh", "82f7e18abc936291369d362d19927d9aa3870883f6dbac4a94fda3467297c398548f2bfe8f9e3aa081dffe2cc1b7ba737bc881b7b80c04920999f8ff96af8577" },
                { "zh-CN", "45a488a75b3720af55407601d1fd08656e3d4376299ec5f934d30136e1c32bb99b71a23cfc9d00333f1c01a5a72dc36469876535e60bd0bad64adefa9cd10c45" },
                { "zh-TW", "45333c4546c732c376639304ace46ef5c05a7e42935d8b2f0c99d47256a72ffa9eba25f017d39172173a492456b5051422b87a36763bd11685c708d9ff8d4ad1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "df31a48e56a2a3bdd4fa112e39a681a6cee2cb1c5bbdd84ec75fb77999a65cfffddb450097d745e5163c82c3e4fd44b4f32933402bff0b3186e6eea8729c44f9" },
                { "af", "249ec1957cbffd12bbb8baaa77996f12c41cc8fe03e2a7d98dc821a014cb742cd0e71f0758d3cc8a9f36e8a22a0dbaa2c94d4db96e23293b9c7747b9686c4cfb" },
                { "an", "4fa0bb4f8941c9ea4613bcbcea8ee7ad057c4fa94e566ad8e4f66b9baffacb7b357138d449cf3b4f20c01357915d97afb620b6e8bedcba7d3a32d7f83f472260" },
                { "ar", "e170a1c433c591b4d709772c1df611d69199985c60daec05e51cdbfdcebade4dfd4d5ef8d49646897956184a50dd2a77aa793ea45610e6db4f8188579488e75a" },
                { "ast", "9327999953ecbe9bd5eec76e82369cd425ae1d2638006e79f90de3ac0403e8b7afd6cdd771eb9e58854c496dda4ec45f336f460762fd3b21cd611c2451e7c16c" },
                { "az", "13a798352b13d72403c4098f039156aaa9bf62d0a8e3678cd8b7b3abbb7491681d66a548043b80eef63ad4f6093ba2b5b009feaf100d4e16a763bf0c75e71d86" },
                { "be", "5e1cf3245dae4cd86c8115c7c27fc381619c59780bf91c77f7513ef924ed01d1fd50e4241cb74d6d04ff9fd3883ff18e428a5e0b2864ecdcf9fff3e11ac5d891" },
                { "bg", "cab0b09239601179b002b1c3dd11419fe963caceea340036f6817fa848da36e3d338dbd55d50de85320aed4a89826eab200f7ee2bb42c30d039563a714d5bd21" },
                { "bn", "1b0733d27a2ccddb27c263d6803e1a788aa3540748dad288496c143b12f0bdfa9c7ba25adc8966bc84bf396f47e613f6fe1c6902a9d6fc18513aecb0f003f805" },
                { "br", "f234d093d1d8523bd2f3abc2dd123b851bebe6f2ee3bd0eb038a736fa3dfdc40305b6a5dc8185ab25ef6b11655a787207c54ad8de68d3f6d8342c746996a68f0" },
                { "bs", "2cf60bfdb2d6a10824ea16b016496f02d5b6c33c477719dfa3f4443aacb8cbf19005abd6eca3ff7ee8c37cee26b3fff6a7f02c3192cec8fe78988622f7e4d885" },
                { "ca", "890fe7ad789fbe850c8d3452e210b4db6a225c86fadb4052a39e2ab8bec43d55dbf26e6f44d7cea8f4627bac4a512cfd0b83cf08d7f77ca76e286eb57ccace00" },
                { "cak", "103ca9e1d6eeea0efb7ac6bfb736925aa9098335538279ed120df2ac3e69ffbe38f85f209c3da5cc2a8b861b1f31ce9af1172a56ae3345d9de0b84f46e5e6018" },
                { "cs", "479434808a58a96034067abc428f5c673788b2670cf89ab999f52ae30031644111f4606ba2a3e2db9d4c3709c991962e4dae431954f7eb1937a4a28365142dc7" },
                { "cy", "e4b0e4114ef24220bdfb27bd28455eab1e4227c72fe94ddd3265d64264702425668c827e345d1f0d58903f127f6631a1a042f206f5236e1bad857f74884e2748" },
                { "da", "ebaabe0d19b227b7b225902014fb2f0630f4f905c937f7623a846764543e8dcf7d089e31fc8e0c0f6bcf65d0c442d307dc8ec1c1df7930fabb5e733079681712" },
                { "de", "6aff6eabf87b3c371f8e2497ebe231c9c5c35048cdc16482e22da1ff2899530e641a2323b867deed5cb55d4fc9ca4e84ba322d23d48964c40a828d18c48771be" },
                { "dsb", "5c9f894c03c0bc469ebe6f47ea9274832fe137af101736f598962e9c47fe6963bc22079beb06f909172f674d5a19ec4d94959fa108ed90823cae96ab294cba65" },
                { "el", "5bc067a09e6a4b484226150d798221aa0fdc7a5df8155e6b41246406db46b6634de6746c21d7119139caf821e417ad5f11b4fca655b53c18325b90f0f71860a4" },
                { "en-CA", "f58281c23259a25862de43672b0074bdfbd0bd46a99f57acddffbc118586c6f01bd15c4a2a17923364012fa143fcf912fcf276ca89754c191f7f671fd020e984" },
                { "en-GB", "3aed67d30dd5a5471b91d2374d842982d187ac6a00fc1ee6f67f242bdd57d689a06aee2e841b69769e69dc53143ffe796855169adb2b30e4dac2cfa40a05cadd" },
                { "en-US", "69f742e45cf3444d49910c9c02ae3aa8ad4a077139288f39672f31cae97d0a7429543077bc6e064e17cf25e265f687e51244a5f30ea37760a2bb0b5209dc9286" },
                { "eo", "5909c4bee5d49b54b4aa3935534ed61b92c0f160ac920a2dff36ecd129ef944ac7bb040b631577c430b7f021f6bfb2398a5dc560e51750449fad48fcd8447d84" },
                { "es-AR", "f93e506959bd97d1d487a68aea0e091929ba804b3c59777774c460d30958fa5fd7620bbbf0d692d1533d0f05f54a8f04f5db367345e1d91d281ce62e050b9951" },
                { "es-CL", "636ebf87c821eb0f4e578963603a45e9b31fd337d7c3096ea3b54e4a444d62e131ef6ab83533fcb694d3f510ba2c5e8dfa6e7b415a4d9e165e2ced4e52083b7a" },
                { "es-ES", "2f5dfe13264e9db7425d1d5abd6d07a0dab181267b6995f56aeae41bf4729cac585d6e19835f5fab1e77e8224bb2fa2f38ac558df0e7e1f8edb792c08c30bcab" },
                { "es-MX", "49adc87129c23a7e97699b2c41f6494072f3abcf6a369e1d9c7dc3ca2f5ba84770592544c26619df635fbde9933972478b1d8e558c5ca6e0a361f1999d86399c" },
                { "et", "0443520836b759e7647263ef5f42237d0927e710068075bde76f07f4f9e9e24ea3e3a223756573b659e4dbe2037047c20acbb023c150deccef29e68fba7eee5e" },
                { "eu", "7ac4ed6f9417bc54e2325bf750cac4f198fa9fa321ddf937137b3db35c7852fe3bfa9894da09db93977d1d80628df87f06f5ef8e6a8efe537919707bed8d5b65" },
                { "fa", "249d1c0e23955b8079d93d25f80cab9b4d940e161b0776e2eebb8ef6c12f42ff7df290ced23b0619984963ba51d7b2e8eb59142cf0c11416a0967fd9d019ef66" },
                { "ff", "b3848b81f16f086bccc71255c577d65e3d35c9b47110dba839c1844ac133af817bf505e52f148629d25e7ec0db15fd1da0932d63f5124d45de64cfcd7f06d62d" },
                { "fi", "8caee35a9ee15a72b171dc94b7ff82391929bb9c362d6ddd4247cbd28a8fc1808bb3e26bcff989eb90697ddc6a00be372cede608dcb596edb7c2375fd6bdae77" },
                { "fr", "367746f560a84f5ea9631c3628ac0bf514170b2db501f0c16605ac5a5b18d3bdd3e64c9250a9c85718303875c99fbd73234fc0d107fe2d29a55973cd4f3ec037" },
                { "fur", "b893d28f642e7f27bb5f50c2dbf7966c9c871c7ff79228125ccdbfb0e0142c453012e63fad06bb3938d36d10f69351162ae687d2f5fd5d1032c2d4bd9963472c" },
                { "fy-NL", "19a2cef5938817b46a1727497f881e35d7c1c9f861347f4fe5729652a840b21adf04a6a03f560c7196c30a104f412eaa027fe5138bfef175633b93140bf54deb" },
                { "ga-IE", "89e5b1e28bb3c66f6250e456feda671c261f6a94e6351236af606dd8e1e883008c586d9cf68098c6e8882a1c650573c4e97f8a68c750e8ce57040ba17ba9cab5" },
                { "gd", "14170ccfb7be1f8a92400301c9d4eecb756b4af5db9e45456a122c233e9b4dc2cb17cff485089fc6745f66d10c7a1ec2ba2b934ad6cf9ab84caf960fd5d7ad94" },
                { "gl", "f1be6de283846c90d8d6a36abdd5ca6e9041ab5b08ef00d7fa7e6af35f2f06ce21b024080b471564854983ed5e0370feee7942341e5af3f1289d45516ffd6d4a" },
                { "gn", "dbc8047a9277d9a155cc0db68e3200f1fd614edc4b40640c5b74813107cb2abbf7277b33ebc31c47c46446fdd054c0ca80717c6b2f45f5d4f1f2372d0f55ed1f" },
                { "gu-IN", "af338f39649d9dbcc3b0b2e3d9025c1032d9f698b88ad8b178f60b41bf0e6a8f616e078ba4d566bf0e1413d53a3825cf0d755bb7619f284d855642e224606d55" },
                { "he", "45f785f71a30ba4f005c3321d38a77b01b67b2ed918ed30a43aa191cd7e5a209e7b9c2f68f62bd2d040d3a6771c47c890075f19559f707b65420793427d93599" },
                { "hi-IN", "1d947d96f0c28d1513616428f691a3a7d223755a4ffc0f8762288e315134cd9d4f8c3495f23bd08ce67e9692b1a912b32670366de6cf2e975780a0eb4b8aadab" },
                { "hr", "329429ed82a7816f82d9c8b5a4fd7948cee934ef24da13fae26c3024772c6db5683a5f64080a25a8f60f02307834057050011cb2bb186d7b4e85c57aa7c4d402" },
                { "hsb", "fd8ef47d6dbfa03897b4d342f525d73a8a6f54169c7733555620cb84fc3195a541c6e7dbe43ee4bb8f554de9c64cfef4e50a1408199e95ddb54a57c9ad59a8e5" },
                { "hu", "4149e5e62c4b6c43966510564ae55577345966551d6c9e48bd471b8eec02a72075464507ba85339b485c6f16c76d8abecbb2805335c4f5bfbb0678bc40e61ffb" },
                { "hy-AM", "bcdf60061b8bccb8b9d88c8841a5a57b374a86850896212607dbfb2e7abb7008545936d42744b62494d4439709d1a698d0670a8a862a46ab74aacd76a7ca1997" },
                { "ia", "5f6a72d20f46fa87f5ebe8eb72135938db2747ed1bddaebd5e4c6dedf3b286b76340a813918a90417e54c7389d6eea1aba9a2e06ca2badefa8141f1168408aff" },
                { "id", "582c7564094a4fc683fb7d34fdecf3d0eb180e70dbe5080537355df1a6883b780b314bf08d7c1234b05a85b48353432fcb5744ad90a8c4789f4df32ad7cde60a" },
                { "is", "85c579ae6e868eddd353ebe87d55086fa070468d5744c4a12e095071ec7d165bf3078c6c59cb806e5241f19e97cf994e6fa94997db4cfee5750d9a2170b0ae9f" },
                { "it", "8a3e2306cfddea52612340915ea5188d95c8e36b9f1864f6be719c2cd181269f0eb137d93de1f84a216b49f3666bbaffc861e981d9db9133d8f02d570f65e90b" },
                { "ja", "e9a977ac77fdaff6eb294748d7e0411ed759f17804070744f8c175f851fa13e92d2d01d9a35b97bfc9e882d13ca1c3254fac3c3bd64baccea1303681dd618f49" },
                { "ka", "b99eea72442f999e33e6fe8e495e4ff8327db702fb6c85eeb6358fb8cc3a68bc69570af3e5bb56bab702e935fd575b543181667a89695b6daf4307677ccc8e09" },
                { "kab", "e5a38cf8dc8a5eeae6f5610611293fc63cdbaab1a47bde254d2901d9c1b3092cce9c73cf5dd3b3a0c017879af106d4711603d2f92a9e1ee0be650a485cdc4c1f" },
                { "kk", "3d5ebf039fb97c9e1d4176c13759f8c73f5e3abe487e974274a0f354aa1baea521d710a9c6c3b6dcbbf95f8eb9708fa42bc2718e5a6b18fc64a30a5ddfb35d12" },
                { "km", "c4e3dd89917acf8ba63a26ddc7a0f3cce1094c0ae1cdffce1c0ac589bdafa77ad31533973bd36a5ed8c703830d3698d591b4f3c234e7b384f094dad67a06ca31" },
                { "kn", "85f8f1ab14a1866dd92649b07c59ba3bb4601fc4ec283ebfce249789455fbca71fe081160fbd89a4a8a0a1af242724d5dfe04bd6e045fc5b00fbb7747c252f83" },
                { "ko", "996ae48b240d3877a6ee874f024f9f8fa1a7c842e542d51a712d07f8083966689cc195976acac0fa296da8bde4bdd9ae0b799958fa6de2e0c11b94715500635f" },
                { "lij", "1e33da3ed8f8a0c365920525a613800660b04bf23c3fe9040e692f4254dcb7e6ba3847d4e582fe682ee0d39cb09908370db43dd69cff715d0d2b3f05a5057977" },
                { "lt", "cf4e631bf5657728faf132b7e983ec0e7e048edb5796ceac74196177fcde07d7d12389c6fa71b330f200d307f0786336700662e923707f9ed1e9293714abf499" },
                { "lv", "79128fa1efa467018fd5ce36c2b26dbe2ca1f7ca0cbbdb92c41da74fbe0505306a59bda142068357a9326168597d7af894d0b7ad8f817dffbd6139f347f50672" },
                { "mk", "40ea909c09263c5771e979a15f4a38ecb27d5b838ba1dcc4595324920c3eae6a7ca5a007481cc102e5afb4acf33cdebfde6d732d2c3a45f99094bbc6747e6b27" },
                { "mr", "196b8e25ee2cf6cfe07d6cdec5fa95507fc9c5a76498286d539f7fdbdf31beb920be08182f9c6a4d690d459723939fcdba74ac70fef755ec9bb2ed80b5dabc4e" },
                { "ms", "3829a1202063a9039872433f3cd1f739041f33224565b728401e7e7a3ef1f21fdff49ff4ab6d1696e8fb07f21bd4baae21b226d4af2d19b7c7851114143bb9c9" },
                { "my", "b276eefa23610d3d86c78c2bb602d12132bbb3f3923363d1208ebe4cb5bbaddaec33e68f6d9401868066ae55c083b8176b7d6cf1f70b0ed0deacd9972c29eb99" },
                { "nb-NO", "782a76efd3fe6737c67577f74940703d820a509dbcb7e4b175b53b2369d3d7987fb0920c135360519c49c339ba5335081d0c6f4e302657a85daa6e1443943711" },
                { "ne-NP", "e975259d2b0f4c0f87f3cf177bb894fc3ffec5436fc61feffe324b7d2160d9734bca3679185dd5fd81f16e813a4459564b23afc21ecaef5fa1dd63dee4226a44" },
                { "nl", "dd49b9bec72febd82b828550f3bfae27c602f7c9ca263d53439b36847d8575d5a3bf39e584aaff5090dac10bb87405a53e42611ca02d8661b6fa630b3b245e3b" },
                { "nn-NO", "9ba786e2a1deeeb996a662aafbcbd4c24b6cf68400b76844111a7543ef4c1179fed6e2ecb0ad369ed9464c01b329c5efb4a5651cab2890f6d9a939e023112963" },
                { "oc", "36156ecad1c81a8787865a4d4d9d58a46654edfa076112a2a9362de0fb136f9ede486f80b32cc0ab292f3eb70ef25770f6d07dcf30a32048d9bbeb4f08613641" },
                { "pa-IN", "66e3beb9ef75307512a4dea0ab09743ba2f285a38996f01d7dd4c24ad6ee94d060b15c116de0f47b267a426fe584724beb4e943fd1f7ea0ef0d441c2050648e1" },
                { "pl", "394a4a96443881e722c3797d780fb3ee97fc6ad0124554abd6f98e78748c8def466d38618c977c1f3e3dabe5125d01b08e493d099584e02e081b2aed8b43e26e" },
                { "pt-BR", "434dc0833d4175ce274bccfdca3cbfdb35a016b2d88aa684519e8cb7eba28dac10a1532caa0660abb13d73d65b8082677762babb180c9184f8ea4e2443eb59dd" },
                { "pt-PT", "99e82c87ed502df167c4673fed6433d796ed9d5e31f16c9acd50fe385e90866bd3c8600bb25e2843dc3ae92769de0a1c3ecd679f0183e50480e48b1c5401b59a" },
                { "rm", "a8ecdb9ac475231ab5a7e083b36f4aab02f2145d0d4dcf8c20c4244e96961e25f9fb52f219eb59eb300da9cd7c378a827380ee45cf51fb95d37a373a443b2a39" },
                { "ro", "1e5baa66ee904d8f978b6726b5b9f5469931c283a705ca0acb8c2b0f72f1ae525c05e0f1dccc4862f06a9a21ca1718a63c82e772cf2587ecc3d3d7b96ba3dd5d" },
                { "ru", "58496deed4f00e1336d12695ceac75de2755d368187e75851664259718b2bc420c28225853ca1b2e01e767944fe013b1a916dc6580d3a63e96e798853bcfd944" },
                { "sat", "b598cc64659bb614acaeeb0bc37ae0524b7c577a80f0fd3696900bc411282c9abb9b98a241d32e63a1c7020e9d84682b64b46dec70fda8c6f5cc3d44a46ec3a6" },
                { "sc", "20db3d54e99fcf20f543871caaed00e9ea8f8ba2e31420348783c41403a20c0b5f698d0971a4207d816d9996ef50caf79e493c978153da3cc9180b1d7f7fe245" },
                { "sco", "1b676c2dcb8d6f8ef52518c1d55299269c6b611bdf9b11ed2241f4928bf3d7d39301ce523edcd0ba3ed2ae3ec1bd24684e711fb3551a999f7a6eb24dd0cb18ee" },
                { "si", "91f2dc5cb725f186882cfa9e4534ebaa2760fbadd681ba91db9814752383ecc648f9277a288695c71c0e5a4018096ad7f9fa2104e1146bafce388a3a4c273f31" },
                { "sk", "0c2f04d6231a98aaad0d8b1e66fca6910e71efcc185529a69c4145c3c6333688d373c14700052b4d15e49afff62bc51e7f0c11d9ec6d3f6069c5f719979cc16d" },
                { "skr", "057c344e280736ab4ed64f39c76d6e57b7da84695dfec5a47fea6b8fc032d8a01d6c22a509563154a2f16e8ae26b2c3052780674677afa701b59254737802782" },
                { "sl", "35d45ce8b6cc0b5ad7c99d2812cbe5ffcd1fdd21ae51da6ed3aa614077dea37da0e22c42b5fe9574085860cdd9f5fa552baf02268ede7f81b606d0648987d32e" },
                { "son", "a6b4fad9f252617ef2d7385c40cc07e82d1e3bd275052647eac5bc38d90b34ff785f739c153182781d5a867a973dc91bb9f2acbb32f8a64638c6f52028bb4b45" },
                { "sq", "ceda5aaf2dab6ab4bb97dbe4a04fb9d203593768a68f22d8c3372be9cda5927b737008cedbc8310543dd520962ebe53e9ac3e3d31e683fc68527b246d3a3ef19" },
                { "sr", "add3e63da5dc31612cfcb474dfae8418d4b2b58c840bdb987716f22217fc6e6d466dbd5333e8857177f863f013b79e252a7e52a7f3525713554e1f12f80f3d20" },
                { "sv-SE", "e81cd82cf5bc3ea183a01f7fa94bba04a3dfe44536066d385a4a5b28f70b6993dd96634e315ed37f9454823e8a0df8dc04bd3a67ee519110eae495e695b5321a" },
                { "szl", "ce914cd7ac10502b96c4c75a1d54d2c91369f40901848ed734e77ed71af3da3a6a2818851a633b9d0934a8c6970791183055efcc4597235431e4e511af490473" },
                { "ta", "2d4e1ee0155fd6b940dfd18e9f31d027d4291943496b1a20bcc8630b162cbf18a2568ccef6ae8b6df933620d3e0d6bfcb176a5c5783cb7cf3a36c05189e604fa" },
                { "te", "df7d53cbb7e3f2355ded17eea4bf28970abdd8d8024db432bc90293ffa20aa982732775937b3a52e99bc2c4a28a374d7e7ec0651ef6e7fd6e41af80b32f64eab" },
                { "tg", "167a624bea06be8d36cdedc93397b44a324fc7107a4dc80f288108a1c1fedea89109bf2f5df71e191388a7881003fd9a0e68b2a46a250289d60dae56bd38cab3" },
                { "th", "a77ce88458f05a160a611dca232e2a8118e084ee2c2b74afbc7d4c204658e1bdb2e48ac9c2c6d703b17eb5ff92c291c0d6e3bfe3001f3fc750b36b85b4645c99" },
                { "tl", "3bf385e01bcbcaf0d40c2160781b2423d04ccd7474e9a131b673a4de7a2f63506d8eee139ff1410feebaf14870c73f6c608402baffad9e74a037ec4780c0ab58" },
                { "tr", "a3315754a5c7bc422bd51dfbeaae1bee10cca61d45ff6cc71351091e4a7da60ad5aa2a17d721099d2ccb85de18790b61138a3440945d7debd81852b5f0d7474d" },
                { "trs", "eb691f28c8bd4ee33aec834696d0f97d3bd6113c4dff5dcd06e66eef4e6f90674d401182b5c815e5c79b44516af20fc79b13b9e07bf777085fe67f3502774417" },
                { "uk", "7a67db1b363860fbd4b14c3c3f85dbb3f8fa75028aff30b01ca225698854496e68bfa1a7eaf983dcd8ea17c120d1f3a78c031a96d21fa01a6f0c293306a8fddd" },
                { "ur", "00daedd237b5cf20c9873e78986614dc825ff2d7ceea1867d7d100f3e80706e5138e720d08800e569eede8974f27333f4d4496b2118744b1bec3958503ab537a" },
                { "uz", "f5c070b7fff3cbfef51bd55d14fea87a8cda956a96eb5430437ca5b70343f96e5807f299cc0debbaa71a63131b1145798b256b086a224e24b5a0ba0bdf306458" },
                { "vi", "4b52ba37ff8d3726df5af9a099740b14cef722587441b3a3795c9775c3412005b638d92890aacb5e61ec204e1ecee8c7f1a0343351d1d43118c9fa6d7436c5bb" },
                { "xh", "4889f3cc61095660064622d72e529e9bdf17bee3c5322299802943c70c6f9028f931cf8e4d6390532f56cd822c7f265edf15baac180fe50737b83652d32d33a4" },
                { "zh-CN", "50a24bf0ddedeb3466e2ac08a9dbe37f51e172be5ad4051ddd4b12a06c7d90609eb217183f3b13966f52eb02babe314b1bae3fe794dc94d9055cb1ed2272b0bf" },
                { "zh-TW", "c7f42dcd2cc52bf27e130e253f75dd54d4b96b36e958fcfbd4446e8bd096142a2d122b85b7d8058c0c0e64434c818953e19f1c0bc9888ffbd2a56ab7a43d680f" }
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
