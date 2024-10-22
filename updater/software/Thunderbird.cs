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
        private const string knownVersion = "128.3.3";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.3.3esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "6549df7f66d629edeb47ccdfd7a4c069c73d9ca2fa924b7dda69fe2d03db41f5897dbee6cedf62696f001e4f7e1f2abe50cbe8ca400f5e174665d6717010fc12" },
                { "ar", "57480b62ece9a38ee307f23821e34f1f1e462d2f0b38ad77b66fb5225e38f37e56112f8f5cc353756ad6b7916ba99e3594ede4a60a4874b831ec541535a4a408" },
                { "ast", "18ee356881159a1a3fe30b82b29d32db7221bb6fa763104f2c4e105f494feac679a6a4ee05d95ba0005f271565987434219df18550ddc10070ea368c1bcf1330" },
                { "be", "cd0d5e6987204b217d8f5f3f25694177cffa886a347848dfd926e7a16151eb6e6d22d1cfede3dbaadc920167cfd51bd1af5d661149419c4889352a9bf1b648c9" },
                { "bg", "c9b4053f0d009ce472671d0abc39f293439404c3834836becc09317043d00e0d17be3c8f35f273818120f6b56babad1e2e15edcd00e86fde7c1482b74b814292" },
                { "br", "bf254e8c501a63a9013792e24088097554d8e59e29c1425b54a6613e9a43a1ea5a5b2f6956dac52986b0ea241f73b92b690cf0f738ce2558b27274829c625827" },
                { "ca", "fc73d62ac8a327ff4b5d071b7ff2ac96be58e5521c7c26845196ba82ff5e66557e79119c0e22099854f99d596cfa8e2c00f1fbe0e38851c905cba01ec014a826" },
                { "cak", "7441633b9a4a1a14021919b54d8eedfbc65134fc7bd94798e51bc1fe67df3dd0359185610e15217178bcdbf137f69bdd036a28b8adeef6d79f1b179c40316a47" },
                { "cs", "c6dbbbd032e5dbdb4ca77268da59373c466683c170201fe01b3beef8d7cff9e700d18911f8a8ef6fe342530fba2aba62356a857d3fcaaee7f3b63caaca740716" },
                { "cy", "3d533ed589729176415504436b2c172b0e7db59afaa50d9666b4d5afb2fed71a414f5fc280849e23946f30eda1c491b966d4d316660cc903b3cfb686f181f02d" },
                { "da", "315becdfe0b0bd27f8cae95af302def200c338ee85412b6b8b8942ec46245535cb263012efcda71e4b09991044465501314124a094c06446c0309525468f8ac8" },
                { "de", "623d788e40c21457bd80cb5dcd38f0f07d26872e81af2592555225ee94c621df525ce9c212d5f0b127732821b7d8caa3de2821f9294ddf46b1b4f69ddccb1068" },
                { "dsb", "0aa56dbfcaade332b699833309c1e4df9188266e39b1f4bc7ff0bee4cc8e87532cebc35b3e2764c9eccd9a8ccd84c8eea39195814278cbfc19be95c502a94817" },
                { "el", "43a9ad23ae7fa3a7e5c8238d6027b0a9f5e3d6ae2c0c43a36d947ff160a7f32bad92223fe776c43b1923234643209b8367ac6eae1f3da8ece56803a180637409" },
                { "en-CA", "6eea9cd77705e4a29a6bd6e92cae463bcc68abc499c3426c46d63c711da5ed09e77b2b0b7b724f0625e5acbd871ccbe1f100d5fc7322082c02de3b5b12e12925" },
                { "en-GB", "3fb9e537d0bce2726ceef84630ade0af99fce98c1d6f6a6b47701963b17c88e5f66c102f11d2a151dd4f0ebb312f72616d11f581f945b9d5b410579358c8e9aa" },
                { "en-US", "15f2e8444ff61e439e9109a85b5995e3c73b763af081118dcf430b6936368a965066abb5215c92c8928634a08adce9905d02e1bfed706556bf2a40b327777278" },
                { "es-AR", "924c7b81e61b58013064648658e1df32ecc14f26d1dae4b40856cdda2ecc200452edf8361fe10f536ba03c9f615272d93da15d66c874c34ae21969b3025ae325" },
                { "es-ES", "e79c3c73967aa7430239ff5caa635931f91b6f898ba2b748e0c21a18fab0488ee3edf53326c1d6f1c1db0c105fd125a072a5ba7fae7396222f1babaa45c4ef90" },
                { "es-MX", "e869bd9cddd04feb60f30de6b1a075873c14190d1ff865d1087a30ba0ca3e48d056830169e1f1edb9ded128e8e197bda769c70039cd7e635e06f65a08a046e02" },
                { "et", "50b0c4f8373aa496078bed6fe60db0d6344d9a10b7580612adb2af24cfeabab7cad85c74c92b47ae75b9af810139b9dbacf6f19836960780c2ba4dad4ad1bdfc" },
                { "eu", "5a2472019ed78d2de2c4ed18613160d9384619f487bb837c2881dc18c0555ca367df6c77047257ef6eb499adcbd401c4a49d68c4685ef9d65a3bc5be9eacb1e5" },
                { "fi", "113eeb9e1c5a634a7af8a4c96224b9bd63dd80dcc2abcd94f6dcfce0ba2c8bfadf763690caacc4f0f958c8fc2037578ed595c10b9288ca2fcc098ba6ffc030b1" },
                { "fr", "bb51a11c1569fb8b74d77b08a258aa0065b77ef773f8503f10b940a1e60f2fcc831ce8b3037c5d5fd2bf448c67129ca8d682c79ffd195d10bf48bd162de1d664" },
                { "fy-NL", "6b9accc0172abcf3a6890a53d35eebb774993906df1ddafc2cdd99f0cea6bb7e3992a5dcfd6b946605b520129f274c481bea9542e07e173316cffe869ced4087" },
                { "ga-IE", "c4ca345e4216b56abd48615249c5c33664cc93d3067d75c523d470fb6fa7e7e835ca0e4899bbab75674dbc44aaf8bc9a35aaeb43a87eb39ed4d50572f902f04a" },
                { "gd", "6fe98670d4d0d8a89136fed2d2e84edf96d2344c8df52aab0bd341b3113402f694e8111783c354e3b6329e5e09838c649f4aceeab80facb777a49e6fcbe91579" },
                { "gl", "65b83a8e161f17c7905d0b86122ae2c357a044bd70b89219e273cd2a1b8b959f98fbe316e8b0ca8bab31c127741b351035480b9ed1ddc7df7060251d0e41bb5a" },
                { "he", "9cb80ca47842963321ea1de690bf6de67f6667535bf8ce3a0038db0d5e4e6f6fe242c935766ba92480f1e0c51db3c0f854dcb6aba53c2e332b80a580a8de580f" },
                { "hr", "7200e1a0f9a06930a49c5cb374e4ef521cd08a713eaac263ab2075fffda63e4866f76a1e134bb34fab3ef9b341c234099df2e2fbb03695e68add9ee69d5c6b8c" },
                { "hsb", "123d756f7f0cba31d306d67f7dff3f1d7aa1101350c34c5865147f382f086219415dbd7ead48f10c208fc1d9ac7992ae863b4ae304c5aecd0051e2732c6195db" },
                { "hu", "cb725c460e51201ef7bf31d06821cc814d69a23b3955035b3891cd672cc2c0a8964be487b4016c507585bd543f3a437bd0e875a6415cac56299e1ae03e02434c" },
                { "hy-AM", "57342670331065784554c11d9da9f56f0c460283c742e9ec8e38a104e935b572582af4f57fe445a96248ec95628e651acd59ca5eaaf06097c329c40d05884029" },
                { "id", "75b295024edfa2417b4859e3f8a4926e313bd85e81fd80363166e6853763bb0071b99ab1261ee85cfc5a26689de6648a1ecda06314afa3f12c1ed0f265a7fb1e" },
                { "is", "0650ac2d207a02c7d482dde92206586ecbb413b300911d351f4763d34a8c9cd31153a9b1c13ae75479b6ee672e1895bf1f5417a468de54c37fc36f102766548d" },
                { "it", "fe66c50e2c98016c1b69a5fc9a4eb2e717d085b8600cffdc9c33846338b3a3c27e21714fcc5679399e26e0e4555b3cf0b37acad5c62690077b0a4007b517d3b9" },
                { "ja", "b84c3d55cdb3e831d2463ffe8da512ddedcb0c79eebfdabad767dbab61a3a4758bcdb2329e1497a5e26322b4902719b0d7c86192425a85e19a14e8b1c2575186" },
                { "ka", "318ddc0d5f595d3f0a2c7476a0a017e330772588310f223a02c46d865421b4046e64f6444cf2cd0c729bcd9812af16a8f37d9498ad6d75817b870a90f5c11f4d" },
                { "kab", "3dfa1d1694f0cef18c95f6573d3b110406930467904037fa481ea388d3ed9deea2575fdf2d3a7d25e4f3042774cf07b9c4ee5c9a434af4a985963230b25c2e72" },
                { "kk", "2f769b199144d66335cb7da7c8743442c3a5c1ac577c25c447b1442de038d1eb7c868b80023a072ff27716a01e9dc4833bf38026f79f104e340e515b3328f911" },
                { "ko", "2c9dd263c529798cc1bb4f6cd450d0725af4c95552994acf8841bfd8708786636a7ff7d32f1a529ce6eea29d0c43fc0349164dff2cd80b771a58d872cf1d3242" },
                { "lt", "87b8c16b929f61a2e74d5f277dc73e76ac82e11ef002420c9e613ed63bfec3787c9ea4c360f4caaaba14e25d9e07d83b91dfb7c5a4d698fb17a38048a8109d0c" },
                { "lv", "bf2e9261c33e91a5dc0c007918091c7d75a532720831d3ca52653a824ac219f730564d23e755df5e1349859e20a4b3b965930b69141a1e04d8ad48f5ddd86bca" },
                { "ms", "52403040d619098c11f1888aafca343f5902a6ada86eabb8c3d2ad6fb3d9e41a75ebb1ec07bb26249b3daf60ecab1b1328f53f74d7d1673814bf310ce8fcd235" },
                { "nb-NO", "ff1261c3039184a12c8a22f1d3c590b4a773f8cdabe10ec015f4d90bfcb5085dba9abf8bbc4ed9a028dbfc3adfe3dc0d107a8ec0c54e01afbd87d2b5b5a669b1" },
                { "nl", "d92dbac9367b4d7030b92aaa162a12be9ef03de26ca27c40f61969470f733001ebb82278ac75f74f0dc9775a52f2e92adbee329595fed35e725e689acab33f02" },
                { "nn-NO", "1066625df1b746d73b3d570cdb8589465a0833a30135df28c39bed9d60ad6499e31e0068c216d8c14d6d77916c9e98103361c9d99065a04112a602f9861a67ba" },
                { "pa-IN", "2f5f862f447685a36dc05b4ee2286c98eb0f8973ff999c6c05841f42bb381123a65fabbe8ed803cede9df00efab82b22d3f7061f7a740c3275fec788c1a6acd9" },
                { "pl", "98ce536a6d43df7dd2870f95e26fdfd7be6d7b0e256ea1653e27b1f4e5ab5665bba3cc1c4324bcd5376544134b6c590c5d1faab81f56c83c89fb08c42bd0e731" },
                { "pt-BR", "cb513429e802a2dcd596c30d19668fad4ea3604765ff5b04f6d028c315ce0977052db62c9870d9b2c9506323ddd6a195d8de12c5527c21ac3218bff72c44618f" },
                { "pt-PT", "1d3a99ce51f2ba4caa59347eadf9efffb1237ed7c4dd61e800ae3857414fb0c573fa95c8844acf0e950b2848ebcd201c80638aabdd067d8178b8752293ed6bf2" },
                { "rm", "5006f3d29a4db00b863eebb3f1e6554a411a4f0fee537ffa98188a594527459821f78721107827829dc71bc0723520b28c6b0e6db146c2008fa04025f31ef25a" },
                { "ro", "05bedf30b2f2020f46fd1cbcd9ebcdb228aa9040648a41f862f5ea67ec4d062ea892505388cb78c8c8b95c908e6c252da693896cb62503933bf36747fa0eef3e" },
                { "ru", "568d00f649f9eb03f42ea6113db7662c73ac9ab74c0754c85a92a4d08e205c4675430af9c40673a467037d80f542b8d662414aae850b75c73f2d3e53cd7fc49a" },
                { "sk", "ae621f001e02587c2292daf530d79a93cc7fd3b67949b542b0666a42069ead6c8a58c5d05caade2eec43b6b955d367561feb90a5c155390aaeb40367ee0e3418" },
                { "sl", "9243f2ef052e82d65527cc950e122228d8763c9a217ef27eddd3cb81428962aaf821adc17f572e39738533b8f9abc7878ff5f4513c9a20c2e483d845a79f4cb3" },
                { "sq", "45f1c1ecfe2a1fd8f5e40b1c126de2873249249b61b29851d374da7697160f869a31c0c907cbf5b7ec95280d725b0efec2e99626d8763f1c2e1c227a35f77889" },
                { "sr", "96c36fb54ac41338d67f8595f444204a30e9f0eeb2d089e6beca08c86337a36b4f0c5bb960abca04327bed12a9e40bc5bc9f8b318c23ebae868a350716218c44" },
                { "sv-SE", "97d1d8ab90120169877152292d5b5a4f924eb023c2f891935a2cf000717ca6b31b6b16858c71700d764b6e403d3deda7cc1c2837788e1fa53d3df7a3730b6f3d" },
                { "th", "fb6b4edb7c3eb6c252a113bcd6b3cb7555ae49aa5ef32884cb0c855be38c3d10a00d37854ec48af27c82586c53e55c856b8268c875bea09dd0ea47bacbdfbe54" },
                { "tr", "c71f793b5e3fcc679ca4e786a5eea21bc444e6e5029ca6ec074bc9dc0af159629f020b714edf0f406edde1d2ace31fe37929bccbc60d147bdcde6fe1526e4c36" },
                { "uk", "101fee08762b046b939d90dbdc2f4afad24e50093f2d3e3c7f8c67a608e850f44480dfad8029d5d2c7df00c9346d70e2fa47ce6157b0ce115ecef9a43536b8d6" },
                { "uz", "b10c8460fd6ae632868e8535e949a5efc96b9bb5fd82a72ba192c9e04bbb2de74279f43f9488df1739768aef294fe43f1d32dde283af82afd4c5f0a41b5e0602" },
                { "vi", "ffa83f303e6d0a31323a305c592f972a35bfd728988cb6bf6bbc1645a17b598006380022c386314d51cafffec5ac4bcdaff2263c6529f334b53d39a28cbd7361" },
                { "zh-CN", "4e5be86799046e38aa6e2343257cddd08842c2045a274083900963c763f4aad63274e4d830eff406fff465e4b3d3be43ca28dccef50d8d752d02e6f0c16b2903" },
                { "zh-TW", "16bf237af11743a0f70fbff5886feb70cef0a86de8dad8049d0371edc488d1e836f467ab9ff2d4b95f27193a3381d3a680d31e665203a10012bc00ee348ab2a0" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.3.3esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "41759abb4a51f22b6485ce8746df8a1eaf715bc8af1664275745d4e6b9ab6de317ab351d1a9ec1ae88cf328fbcd5519e75b244b329ec67f9bd8d99592b45b837" },
                { "ar", "bf03389efca6825426e0bd0d8da114514b0e40e1f893b46931ab0fb0bd73367958f5651deb8927acf60187b0d8edf018ff1af814b7c8a0e172aa43f7b90798f9" },
                { "ast", "8ad77dd5d99fcdcd4243b4a7fe59deae454b475db9456e68b6b566a6301e9d5aebc16b31cfc50d5ced3a58703d4e03834bb8fc5222349e85599cb7688f71c256" },
                { "be", "67de7b0d2ba7e5be329f56cc43ee7bc45b152edc82638df7eb23cf68b3ae45dd5732460e317ed52fb3889b0548a203a9713cd2e453c273752ff3bedbb939ddce" },
                { "bg", "45f0799196651f70f2d178622b031bff995553ea62e6ec38cd489aabb5e196a4f5f38897c2b6c28638bd7d195d30604c6923785947d21e5c52a8a55b31b07f26" },
                { "br", "e1ab675fbe6a56df4f609349738370e553ba081a0bc6d629d4ee698f396477c3311f1b697f5434df0bdcb877a3d698442d7e78dbcc786049b2c539b523547cbd" },
                { "ca", "41b28d425bd3ec301b44cece4515a50b02dac97bc952ccfd3591766b7926491533bdc09fbe1bffbfe2a3c9d055f780e795d291d0f79b8641e3455a629f339d3e" },
                { "cak", "d0d4185d20cbcb78307d38be9bdee0633ab66a8a27c73ed562506ca31e625d19f7a2a578924ac2e840d5adb212b6a83cb9f465e7139b52dfc71059e53493ae9f" },
                { "cs", "e6b43b7f30cca66b348249b6fdeb7458bfeb8b7e5b0b0cc1994bd5804d427b953f8572e16c34c90a342c8f3c1d5399d0907f9b166ec2721e77bd0b8528a52615" },
                { "cy", "3faa333e983700faa4bffd434e5e726efe0443350005666828a7140a3c71e6980f5e25bef13c38c1be33ebff9699dea7dbbbcd1eb02b2b7fd4540a8cf7325a81" },
                { "da", "d61231291569634580091534561f3b7878bd1bae793b280f9bc1329213ae9f0d1fe6076f8dcdcb384b525a19ef645db23df74b8ce130b8ed297a62ff8cb998bb" },
                { "de", "2c64949ae0e4e130650ee93cbace7cd21cb95ce290758dcf722ba40da63a2cf1f7a825edbcab2e79c778fed25e83f5e21cc5efb6bcc8801d3f80bd4ec5ce12e8" },
                { "dsb", "c84d48f57885cbb142a759fc680abf3b0688e0d1c220c9402b29fe6e496dd5153642cb69afd1fcb5b81c8a02e847c02928f5763b9f7ba169ef473e494b3e2ed6" },
                { "el", "1a5da314a539ccff48f5faea98a5d81658118dd805cf9b03d7a4313c3581b697d528c63700f88e7fc7d7ad247e10a277aabd866eecddbcd63cebc9e57710166c" },
                { "en-CA", "81132b9eba062e6f9e29a6375a7eee780a3dc406db3ab06491dab12ab09259f700c115811f6530a3a8e38963c4010ab282fe7184d96021c771dd725bdc105196" },
                { "en-GB", "d2b2c485f20b1e2f875312fe99c94ac3fe89b2f726e40c72e5f42d04de3bf6cacd03c88a0d5339935913527ef82bb021d13c94b27f89c39a52bc7401d700a3a9" },
                { "en-US", "961016e00f7a814bf45daaaa694fbbfb9b755cc28f92acf8f279e3d29aff6bb8a6753732470f3da19d17d3fcd4da429b91668bcd4265617f37330243bb59fe3d" },
                { "es-AR", "151b60687287eaa940639542156a1861cbce84f59df0ea45b3f028061d56b342d4604b78d032f9c350c0fa424191ca381521996cdbfd02d442b861e2bb35ca9b" },
                { "es-ES", "3936f2eee6e42cfead3b05348ab901928ad39b4ff73ec8d37d0cf3c3cbbf5322acf4fbd7efa82825fac3fa04a7bb521e2409e162921452e2449425df1b2155be" },
                { "es-MX", "b360328055538b42fbffdcc0fbeb08eda5c5848b4c8a306e80422e5688d2e2d936885c2c1abccf6fa764fa8f24888f0a5af08733221e1deedf09051b58ae2d61" },
                { "et", "eabdfe6b697d1ea5feab7220ddc271908429337808e34bac52a8339c858cd0e9c95220b28fdb43724786c69986512ab814e7e2e296860b00210523949905b1a9" },
                { "eu", "80ecfadb7acdeb5abc09fc9100333b44e6f721f37d7005f53dba7d8ef7e163d653b6f8fd659f94f28c2759d0edf060a6312eaf1fe7be8bdcfdbd0216a26665a5" },
                { "fi", "f5c212d0c74c77f0fbb9b44d47e8677233144650b3e192a7e562dd41fc951855bb657fac43339c321b60ee84745e5ccd88b71e2aefafb8d8c7f227a2923b3804" },
                { "fr", "de8770969a4f9113af757cd54bcbcc31c96989af37041d401e7b1f35d8d57a926ab1be6dfe7ea3d7a7b0a95b6adb122cfc7a6525628c9ff28decd61472188276" },
                { "fy-NL", "c46d8af0b3ce86c73399b72eb326612c9302aef0d615c4c3a80cd406b673dbedfaef12bcb57d4d215b0f9c7e56b1e1946921f4989d3d4f58b88f6692d4bce31d" },
                { "ga-IE", "0986a008576950322263e72275d4571e7619c7fc90b23daaba000895bdbaebb2c8c022e1f7d5b751a42f7a7db021f2d65770efc54b8563ba2b7e023beb160ab4" },
                { "gd", "ddf89b90db1a69b14b6d5f432169df84b32257c6ef7f8e6d33713476646b8c84de1941468d3de9d6d9be037be17d48ce594981bdb344d6b46646c37eb25095d4" },
                { "gl", "f1475ac62ea9f5f5bed545420c0ceaf7b0d03b738d21ac015fadd415223a2c049ef8c283728c0132fc7fd80909da351314b50bc9e30bf4b3664440a67289e8d8" },
                { "he", "6d6a1ab47704d1e6d7a59ddc36e8ab09222e562c6e6f40c3694c3dafdbe153f9df4fb6d2228ebc8184687203a796dfeaea0863f052a42971d6cc55969ecc2a12" },
                { "hr", "ceb2acf718276e8ed92061999905a190c675bad01fd2ce1666dd361b2efb634685269277e876effa321421a7332cd2019088bfc15651f3864aae61bc7c7a13c5" },
                { "hsb", "f653f24cb7b3524d13c3cf6c59710b29e68a0f85fd390ec0d0b9c3067614c21f425b3eea037b9218ec0952a0604b9fe77ae2f25a3e9f330130c294d49c6d9f65" },
                { "hu", "16877eafada02604c74622e450228817d9a7a6579d64f74a4d58d90d26f3edae232cad0035324648ccd9d3fb72530d8f26a30f2a86fb4af18579f2417cf25936" },
                { "hy-AM", "3b6576906923cf4faf3239d8aca86c3737cad79e70ec6fda27e8012c4efab86588338664a36d2f1e5a1c42abce62c64482acef8c194020c7e2a833be9b668d8b" },
                { "id", "a50ab70bf7ceb38047c815fbf8636269a07173506da32eeab80e0a5049b21ebece9c35129902cd77a3e9a0479687c2775814434c748f845a9fcbdf61a5fbe66f" },
                { "is", "7bbb1cc41b18a96e3bf6d38fd83526e7150fd2497493acafc7ccd1e108f0721f9f1abe06fa64d6afef4c869b522ec01207deb868bc7d452c3cb33c9c1984a646" },
                { "it", "1404d8c459e381f52a52175c432db2b5c642a5fe4d9055087c191f44ecd17b95c6fd5e1cd7a12e979923792c4c976a7a1031f6c6505d74ca3e0a5229dc79f51e" },
                { "ja", "b8756ad1d052a4d7ddc02b0beba47d83ad62bf0a3ba7746f74c691f66e7108783f58bfabded70caab64d538b86d018231d6fbd1cc9ac7eb53627c4170bce6f14" },
                { "ka", "bf3a93f8b923a42f83107970cf48095c30e7c4f2a28de23a799e1ec7345c9b84b087b4187a344bb75a9a72c5731370d12083b0929994d30703ece0ce1809ed6a" },
                { "kab", "c3be9eb7ed880ef39eec24860c48eeb40582c7c45f3daec91641ba2c1ebf4aaaa9bbefa89c15aad67e01d3f5bddfb170e19471c7a3a472595827dde8e5a4b469" },
                { "kk", "34f9542c998e084a8695a743cf8a6afc72ff8b8935dfe833d9c94fbd7d2f097100149c6995e0e745df60d9619f27cb0182f86de47dbf1d49e635a0e99cd865cb" },
                { "ko", "9461e141f987e5888a1c895c743e2966c1246d475802e3bc6267ccd8e8a9b183a86f4d4111362ad185c4e8bdd724bda12aaca2ecb331b7a8dc510d1733022f37" },
                { "lt", "bd948765206e652b5831ee7cf9e7425a121aa137c5041355de7d84917216fa3f1e4557308b1a130bc274d7f91c59f131d71651393b6aa4677d831c4e992ea643" },
                { "lv", "b3d99880b8453bf3728baadadc544e8e9b3c53df4ce41fea47368c9dd1bbe38f8182f15124a3cd139104a18a5df5995c0a89832e4f53edf1ec2669939d4e227d" },
                { "ms", "1f7eb654585fbbe443d41cd8d0dd352499c458780ff721c9dd7043de907f4b21471d787dcdbe843c5b2381cc402eaeee6a2d4bbd40bcc25756f05c77574ab73d" },
                { "nb-NO", "fd6b75653cbcaf5e636b5b694a1637aa21da3429228401e9b35cd741f274d78e2ae3c2d73c0979e4d74ddc586c55ea4bf3fe10823d538e6eb83ad19c720d0fcf" },
                { "nl", "58b9d866ac4279381cbf185580fbf46749658d1b19182c496480103c47d676da7ad4defcfec8acede3f9860e88d58529206aac65ebba31941724ca65b8c5f962" },
                { "nn-NO", "e6c32d4a01034a60157842ab5d6957244e707f81908efd9e6d98cbac1885e3ff4f49c2c2b4a3ae6566e19073af2229cf9553e5142c2fb08bf796da5cfffacf33" },
                { "pa-IN", "f7f1439ab15c45dc8d7fa27fe76c181e82103eb7d36777d6f7db6b28f1dee02beb94d4c71edf05626ef23483eb9ad5453b25ea5a4e01055ee05fa399ddb96fbc" },
                { "pl", "cdc245e2ed93e05f3918a7d9ccc7616e79e6696867ab0761f37a5b127cf876d64efc443176d964570a18df70f151b360f7bfbd3acebc1f95c24164e11c4967ab" },
                { "pt-BR", "b0c5bdca62223950dc865d281899d2c5e9260c600a44ea25afea4d274a98de2aec9ef699f96076580d8950a17423038819fde15891a93857afc663708e36d122" },
                { "pt-PT", "f910e66f8c6bc82a92b14efa96a0b4b4d86ba0e203fc41a4e7ebb8b26de7362e51abe44658df54b22da9604a6426c15cf287bab33f1fb8601905fedae46b0e14" },
                { "rm", "df8bcc5f0574099e8a759ab7f06f7c2f8b77f5abf276164e0c0739e186cd04273fb5e5e62a6c915a95aa1b7d2aba4677c2113e819feae0bf1d650e6f4e801f32" },
                { "ro", "044e5bd2e2a84088568e7a6ab1e69409bfa83463cfe63c20264e14d48a3d70bb9dc508f62a2e99627f69f500c10c770a9ab3a6f1e7d1e2f1fb2102263be0863d" },
                { "ru", "ee6b040f2f65fbd69157c631b62c642dfd2e394d24688b08711854b02c750be4903bd005f7e4899f90724b2a0c5c7bf6615dfe6e77e61f8d751d986ef7930b6d" },
                { "sk", "c9c1af4590f01c937365369023e8babd49168c4eaaab46a9e617df347396b6389b3db3bce57899827c6ec08b2aa3872fc1eec2a2a3d8348ca33057aef1ad21a6" },
                { "sl", "033946d7eb4ba390e53188d3f37d8a102672d9f169f14e3ac8c78746a296fee97235e657da42eacc464188462c26fd293ac6a8ac067925fbad515532e2eb25ca" },
                { "sq", "5785284dfc511dcbd9d9ef07449c2d1469dbf8699baad9eec473d18eb780c85fe83547bd86218de9d8b13daf0a390237b7e08db7a1ff814f8850b868c15b85f8" },
                { "sr", "d4143b80614bf40d2976d19eda3c67cdaae0ffc71b6f814a978a21ac67c0ffe53de02630e77bc3c6ec48a440651138f88a5d70c2aca0249505553dd5de6a874a" },
                { "sv-SE", "bcc7a2af4a33a7835a113bbdb345c9c22d12791b39943a7831a63d9f78a540664ca33e2e4a7a4c9f3867e8ba494005d83984edab135e5c2304e9b48d55a61872" },
                { "th", "625922cfe2860f313c0f77f8337fd398fe6a089ca9a131b1c1ee94749a09dab96d2161b7e3b746e58339a5f8580df90daafe1bf5f4c8e846f8e585311acd6e41" },
                { "tr", "58463d4bfe5f0b82d4fb61b1419bc0585d1113b3695ba80cc8e06aab04d1020e61bef8c27d4e216f331496af95b1b115616203ca5d8bf24cb3a5be2846a01b37" },
                { "uk", "4f85512d1e929481d90e14d61107f326c1c0fb6a3a7aa141f190db6332cda0efb88750c822086c41e594e71da44701a06baff3ccd74e0671f623c16cd9b8f215" },
                { "uz", "28249ec3b006ad764fec1a99917b2241274cedfa58591ef806d681a056751b76a94172406aab9fc21e5fee3c5ccdb8676017d486aa8c7f393fcef379770385e6" },
                { "vi", "a772c5494490b5b0de216ee0ba93410dcb130d6576fb160e0abdf00f195e31ce8b0b2057520f34b5bc624465af7b5957925ce8a453bfef75927ecdcbbf47752b" },
                { "zh-CN", "a4f63c13211b6a5e8759801b6beed59c4eca7e902fe351075c1a6a635800316beca486531151460d45bb81bf14bb150130e47fbf227c6f885ea3ee66b05bbaa3" },
                { "zh-TW", "6be18cb58b7943ee38c982290ba981b25b7355ece3983e2e9c14b222cbc6ea715a12dd1d410f3f59d05978f71d0c22f12dc147ff1cac1a1f256e7d5fd5a375a7" }
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
