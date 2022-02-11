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
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.6.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "c6c764bac805ac34108a69a68a250a48febc2b242b32101ae2654ead7cee3f6439f8e0a3217bdcce13acf8b93a5567abb19389def0204fc1a25fb9aa5b102fd2" },
                { "ar", "5761bee74c5e81d09d3d4fb0d5748cbfa08729be20ec09a50c4b2d106dd9135eb2ed95e770dd28a1ca28008e3f47e2dde42b59850b78f100c30d304000273b2c" },
                { "ast", "c018d5733c6eb34f1853dcff1485c4b70d7531ba88aa8f2a3d284c7ce180b0cfe7ce686ba8754a1bfdedc165d58ac41dadb48663ce51a38d4981eb4d74abb303" },
                { "be", "3b102eb3476e65291961172ef0b4088a30c8cd8d1d33b8f9c9782aa769971070340d68584af9a17086f3ac81caff6406d2620ce3972cc95941b040b1717c5623" },
                { "bg", "abf3212b768fe9a28071a25860ceaed7bd42d6c8bac048e5f19c5851055c6cae10753f2fcb4932b8c65f2e0ff10468e955a8d7cc7a02ac34de92f8f2a81ecef4" },
                { "br", "13434d233209f6960c86eb4002c66dcf126aa47585a912b8bca500568601e5e3ec533e616fc39c235bd70be9115361f300c1beae28f5851b08733a911c61e8af" },
                { "ca", "9fdb2b10c228ac5d6b9a2c985492812ed1ae2a0a4ec8837e0616562ed722270f2aeb64bef795827229e1e201d8587745a09adc324866f224843554a9564d43d3" },
                { "cak", "ef5735c42126e3b9238979a8d3e7e0de6602590799f9f403b8d50257333e9cd7ce81e5d0b4e01da99264263aa492ca5c03ad7036ccdd78a77f6c40ee46e36849" },
                { "cs", "3d5a2422642e980014f8761381ef8bb08bcbacd7bb49a5a5af6a9fd244bc47bd05f6c437a91625dd88377774f1f515c25eaf39036f831447c3a876526145d865" },
                { "cy", "a833a0f51f8c9af47d0da0394aa12a4b2bae1caf9e9f4a3bbe5b6f1c1b0fdfebce8610cb18ad13e5c920120b5ed9cc58055c07a012852b0e095c0f6ff23aae8c" },
                { "da", "d9902a051ec6257720f60d464df78b6fdb23d0724047fa9f42e672475f5e433faf17b962a0f3a15fbbfa0358b9d01d0c6c3966054766334f3d55e06cca465535" },
                { "de", "be33baeaa3effa3e2860a3cbe6f1563a7e00f11541f62d36862ece5f055bd90b0b1b3be826a81a3a99f44884fa76caeaa302fd261b00d6e4b3dd3f4441671e34" },
                { "dsb", "72bdf4b74dd1955191cc4ba84673f3d3380e5d255c7c9227bba47ece1c2cbf1885d789dcf30979e512ea7f2da05483a0162dbee200a47aee9ad28de4d814bd28" },
                { "el", "483299b1c05445fc04fbbb3b9e3cc826304fabcd7d433e7b6a373f1322e52eef99bfee2395e7071a5355da9640d6d6c3b4650b74cf71dc9851a86aa366511282" },
                { "en-CA", "3866aaa0c1f7e6f6945f4a9015d31f472c8d9a230aa1f429108989ef4519d5f5c817a0feb6ef31332d3a9734f099dbdefad72c2512e1152deba866dfe0b2b1a9" },
                { "en-GB", "befdb752f9c486d39f7c7ffe80af687d1d03f1068753dd7f3cd873262f1328d5f9778527cb94f47f9a9478fc86ebb68c34d75bdb27c9e6acb2b8c9bc6f1e8b25" },
                { "en-US", "eb83886f42aa7e8033684ddedff6652a7694fcfbfebcabb6ce589a63cfc8b70a08eb816ebc05de63ecb3de92f3d2007bd79cea5d14a466403bdd7d36334a2e7f" },
                { "es-AR", "61792660a7ddb56e497069b5e464e173b61f491b0cdb1917c7b72c6b05adc3f913f6435280b835df7cd9a24506b453b759d30fdc0395c61d64e35e41256275e1" },
                { "es-ES", "ed319a9e96504dee0b8c5606808cb45e345fdc12d5019f30ca229b99a75f05674460a957a4349312693f3460129a1f786a614ac9e6a80341c38e7feb992650ab" },
                { "et", "a0ad4a6280240c699f68414a973f5041f2c9d12e99c573c10cde97fa851bfca0efdd4fc8f5e658c9e3f2af3dd1aebb592821c3af71864c68a79d177364f792f8" },
                { "eu", "f8a56a55e7839d9af39e5578b308e7581a349d246cc2dea48c963a9af57db77409048d4e2d18aabcd857cfdad2cbddf9f12ff1a8d01f1e12d3c400f5b7d6b322" },
                { "fi", "1f19f658b45e706f5fc6933f34bccf81f7ef19ff7424d7711c66fb013c09e239ba579733b697eaa5cf5f006f39aed85e44f8f729061be748c876d89bf7fac838" },
                { "fr", "edfe8504f1cee03a775e908fa7cea8319f0129bd7b50b49e7052b3266f79a8a8f78c5025baf2c0da2b81a14e2c1020e37e7ffc45199e6afc51ce9a038e51755d" },
                { "fy-NL", "fdc93abb966559bce6de78733c3dab94fe17cf192eb3838429497c9f17f8f11a34488e0d994ee90f12d1bc660f726ea016fc9d69a9966d7ff41c8ded7af7edf4" },
                { "ga-IE", "fcac1a1343345a42bc43d386ad81a8599deda23bec0cb8b70542ca35f139ccae1aea76e710c25e23dad8b2b32ff993e765f1982c69a15e0b4558b716c715493e" },
                { "gd", "4dfc9228d82f705f2e954001ef48bc46fd5710d8615551675ea28f2969e7e3ac9f24d088889d37e1c9ffff647d9fb002462fbeb23bb6b86f6a0e2e9c510202b9" },
                { "gl", "3ac5c27c9e87e34cf5003ee55adc8fe902a8bd8a0eb282fe6b5e9451b7b32a95f5c8da674079e80f7152461a242ef70d0d15d45ad598aefa851f170297417830" },
                { "he", "8063750fcf68235101e119215885d0e0ccf24e6d83739ef863e00fa74e927f6d4b0897938dda87f607bd531519055dc2bf9b1aad32c7891e97fcf86ef0f898b5" },
                { "hr", "18a312b5e1b7a9f715bd9d4152f59397442fb869a10be3e2783d8d4c697882ea94348c762debae0f71965ed01814785d00d40a43ef1eb062fd1312621a90d74b" },
                { "hsb", "808467f1f02f6ad4766d5502ad4ff683e529ff0745b56d36f1c5add58e213bfae99a229e22daa94140d04a51d2f549c5bdcad43e9bf3baa3a5a809173f5e54b1" },
                { "hu", "437979b293bb3d350524b372fe4d776c826762508a2c0c638378d97ac644901fd6198c5f59dd011049e388af965429329a66398e1f99bdd93c2af12b4c9a9590" },
                { "hy-AM", "6d7b60a5b920f00d04ffb8dfc2409bab9ae1f654bb64616986f3d1154c8604b62e7f918070ff6caf9e95d5caef2a304e9f58f1345dc94cb635c68adf58c2d4f8" },
                { "id", "f93bdb164d81be25356b7f60d4b79724baaead9a3e0fda0e5bf38722903723013605abba1871d875c4afc161d42e009433cf461c2a000bdbbbbf2984f3a7ec0d" },
                { "is", "b717059835b4f9b8eac5171da736c358c1fc28f465a8db787ced27bf82e05b07e844effd00210884ee70cd6a25e1d5d5d20c62f26ba38e2b1af94209d3875622" },
                { "it", "efcf5d53603b36defae4a8cc6d110d4aa81ba9088c0f57ce066af9eff74085cd954893b3e81e910139afea39133899178a672ac82c9fa5f17a3730e095d6142d" },
                { "ja", "dcf297a74235019d706dead1b64771b9256143955bef7a6e0faa3e384b8a040cf3ae7aa308b417f4b802b34f07c57d7d7d9782d682faf43cdfbf3715c7fd4dcd" },
                { "ka", "c5f052d622db7051b0f21362a2d3b8b089ec62d9efd573829bab108a50854424235962cda9822f330732dc53a2d5bfffcc9bbcab27fda976e085411bbc36bf02" },
                { "kab", "6f4844ddc73b1dffb89695975e3b0e6e4d4ca9680025151404af760a7897ca95c93412743e9d329f4603af8e7bb48ff30d7e3acf017795b6b071cf77f48a72dc" },
                { "kk", "d0cf66d4431e36a99c2672959178850db9830b13b74a59df56b2975bfeba7b887476e85acd657fa0b32f1803a626215d347e2226039f1191cbfca8792eb2698c" },
                { "ko", "7bad547c825c3acc434c83cdcb8f4e848a8a5c158ae7241286f870ff47b16eb6bbbd08a265f77823fd4b3d644b8be5d9be3c600e9bf0a82b5ad9e08eb0a40ba4" },
                { "lt", "35c89282f600e78e3c656d7b2c766c5d399919f61d411ea4a5ccc65e537936c5e2317ea2b7b691e8d3a46df6625eb07e4d2b0eb4e4f4831a38b08de95b8c1fbb" },
                { "lv", "a98c02f9c033fe1c9bad163142d9c3d1e9c9ba72497e34519bd5e1715c082af2fb1490c66392d3364b45118e79106eae34a75fee7c8df86fa708ea06a439eeb9" },
                { "ms", "67d2f1c6739333d25bdfffd868f5da4e17e19b1d4093b42eaf19da0b1b9542c9a36a02d88a88624fb7a6dfdbcd354995dcd80b601e944e4f6cc2979ee7dfd642" },
                { "nb-NO", "fc2bb7fc7f71bab1ff249f28f1b27ce5580c69fd1a1bf37499c950c729ab435553fbe9bd1daf3da41340c0e7f2e3dfba855868db962a7611b7d07d74eeb1c108" },
                { "nl", "70ea8c87b227b5ab8d7a130cfa239c9cd0650d20256cf31085c7113df5f4bcba5874089337255738c47efde14a477fbe10202d0a04829af8c3fd55f4907a4fbd" },
                { "nn-NO", "2ed18390c21b5737f7a22f78668291057a9f2a498e26c898dd7d022b6cdbb52870082cb539bb26aca92f288893b3c4d4548b08dec55446ba5f363eacd2a0fa09" },
                { "pa-IN", "6eb90be0e680b706ba84c44febf383bc6cb9943a8fb9e32f5fc5269023d1000a42e0e2357459731da312e2f2b4c0dc6c786068215a3e81690f4a9ba085549409" },
                { "pl", "c111e6b6146dd546ad7ebd06434d2d722b000b3b4afa951eda21d483f30c549afce4005f2d0a5cb5504bca007aadf05197e4842c959d6af72438c5d1c1d630ed" },
                { "pt-BR", "ebaf9ab8cbf9de12da754a8396f96ac86847c2c912fc4c627ad29e4fe961281df43657d9be8900e4485e5f2bde11bded5919ea161a41033d4c2e087ea15203c6" },
                { "pt-PT", "c0aff9dcd436e1a5c7ac6aa72324343171d60845c25fea343352ef48ff49002eb67a9c0afd39bb20a437a075bde85159d698af867cb787999809f2d5082cb872" },
                { "rm", "c99c241b1bfdf126d9b3499801da264485d6f1d0020b8533b7c809906c775f8b54e0c2b4a03f1784e242141759c701c14381d92c7434b76c6f7948f94cf49dfc" },
                { "ro", "98df546414e642e49f453df6f28d91366f127ebc3ae82c6b516d4394326fedd2413804d0bf81a154eb38cf0b411ce8945a9c664798c00fcbe2afc6a08634d160" },
                { "ru", "c0d98e110c072c3a2749011e59183cf7ddccee8070b41f28327f235eda2374328690d60b3c1f681e612398e5ea1cb767c6581d089cc5080ae1f314bda2e6fd69" },
                { "sk", "60070573d9c2341bbe65a91ff27cf736cb861b64055ee775b45a7e6a0fa79ef68287695289dfd25a66909ef9bd00ba32d8591eadb616e383d7200126fee0d61d" },
                { "sl", "3e0514a4e91df2e64c204f3354670d505a7b0119a9f42d133f8215558fb7e3b0f3db47b543149973f17284eac69d0627d71cc9f3b10d25e6a94997e0d5e6bafb" },
                { "sq", "27f5fcf5970ac2e0650f2d17e597aa090e76873e0b6031756a196712b6273b7516f844c52ffa90c29aa6b0143f324cbecd440d88147e54c26acb4fc28e2b7a50" },
                { "sr", "a1ca341ee8ee3543203f1107ce9214c98c5402ec8be43597ef9dcbb9e726745eaa3eb3794e93710ebfbb9308f9e6cbf003ca71c168272582d94943a04453c111" },
                { "sv-SE", "f4a1ca56a79bf146a97cedad32c72765ab638a993e2825cfed49e6bda6be930380b7b8088a822bcf0d3404c872e57809c070781a5c5294cb26ab0a6f335cf989" },
                { "th", "d3a2efff794a1a9d6fe207103ae4c6158d19d057875e60c76357c67836de937c133e50148fcfb4b456086c2dbc22ce820546f97f8a18659b9a8bb3c8ebfbf812" },
                { "tr", "7d0d4cd03bc8ded308a2e30cbb355bbdfbf16da4313673eebdde35183cfe8997354026680a6f6106162b3a5e37148e3c9cefe01126e1656244cea5212027b431" },
                { "uk", "4ae600aa3af875c8a20d6d14df024033b3b3205b2568ce41e352c407604abfff82d46dae86e90654b0b394af3af23acd664d8ab01f0685b8c111ae3719fea117" },
                { "uz", "0685e8c011960e0769e924846477a8be97643c826baad362bb05276a27c3f9871b8c37493d53795bd5c6308b7303a20ac0c97430e1eaa228ef7f82e29002bb45" },
                { "vi", "cc4b9332e55754f7a8318ba15dc6b7a39606aa9a4b4201b7fe5a485d138e9c266ffff5f3671bcaed525e6818eeedfad6fe838f67b9b46b72709ff9385cc42d7b" },
                { "zh-CN", "1eb6f8438b893be7fd34bbb4bcb948c832a496678255ac06c7979b65b006a51be22eced8b4aaf016798490178f9e40142b3e0d2f73b04f2d3501fc435884ea65" },
                { "zh-TW", "29bcd0acb8f03486a94df3aeada48c7d49023704c15f87f83cfa1e3da87fd3ab2cd19a22d923b674fbf24dccf7aa3e38e0e413f7356f1294c4d830560f90876d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/91.6.0/SHA512SUMS
            return new Dictionary<string, string>(65)
            {
                { "af", "f2ac21cab188c18df0a79b4376421ecece4b267e046699f3e8aeca787a6e015ec0468dd640b925a9ecdccccb469ea3c523328e788546ae66767b2d75e441578b" },
                { "ar", "f5af287223b91cfe1d9164857333d13f0eff240e6ab28e16c6348d332631ba8269466a990cde6b8fcaaa4db6e13bf0e8342af635758e7456619937d4898e24b8" },
                { "ast", "f59667974289a81af47ea857177a2802fa9925048767f6c927b99f997858ea97ee51bb3a6d675637f87263185a8d70fcd98146c8ace5d5aee7878a6e60e84773" },
                { "be", "ed98f2dbdae6057872e8b7c9ada27470a24862f29a20f8f1e2de177a9208ecf45eebed6929ac1370c074b19ea5e036b8ddce1582a1eaf351c1964c1e9f2eec93" },
                { "bg", "b45cd8f02794354d4fa27914054822f60d9c3d05878d73c03c41b5378092a4c76ed9471543c9a1c4858be0ddeaab44eea71857077c4bf4e233a896619984bb5d" },
                { "br", "14e6322ff341ec547f3da99028287295dc8cae25a7284d75318cfa5cf6532b214c4255e58589c8ebad0cbf71bab7f5b0a6ab7e09fd7ab29397f1da7def98e045" },
                { "ca", "ad380707bd2dbb9c8bc44a5a566caa8d67adfea48cb48b5235844ea9adca95a77d587f47c4b709bfa1e090ce34622a9fd56b774fb6c41d39e27f68392b19dc7b" },
                { "cak", "3ef4d1796b0cb3aee652fc1ec5625413a9ada8fab28c976311b55b7b2fa061f14719eaa9d79c296b63aef2c7a99a538e7678c97e2f5a3b35e421682c81e43085" },
                { "cs", "ffab1a020a876a9ec989bab7119a72789bd8d63c53b098c06c6b2ab4051e8de8851cc44c59d8ca50aaf1cc82dabc99cd0172c1ad6d1fa9a2f709ac2df302dedc" },
                { "cy", "dfab7b6333ac25e6683ba9bb0727defad09450105135b1b50bfc96f580e9fe6b8949055649fa2d15a274e0c4891f7fbb926bd154d1636b561d4a8e00c4cb1018" },
                { "da", "d3d5273ba38d3845a19d423c74490878876a324230874c2076d16274d9e1f15ea6dc5df6632ce22b82ff1cd975ca182a8f09005e3818adc034ff2a43a5cbaea9" },
                { "de", "d8fda25259111402d7fe98610cbd1505712ea7e5e2e4a4c738fa328fc0f3ce4ee29695881446f4212d75a57c2b1e7d62628fea9a5a6c9256234400a5bf8d962b" },
                { "dsb", "b0306698608b2d0d15ff90eefe5fab37d716db2077bc0f3f086bd1fe0fff6a8667b0eff7c0bb05a12e1aa66373c26bab7ceb27cbdb5c93610cbc5b4f9ac42b7b" },
                { "el", "dc9af5dce5234f5a58c10bd3708ef3dd95db32c8ff340fa602aa806f8fe79c1fb02ffc5bd6428772772314ca2127b4ec4247673118ca6fb84e062a23ef2b7e32" },
                { "en-CA", "85fa85857ea1fde31a0c96c3ebb3e7c7a4a43368c095ed352ed59626ec9bb61ba6478b8eda7ea1c5cfb9d3fb71878d5d1c8be08019638cce953c910320f17413" },
                { "en-GB", "ee43cca0862dee2e25b712995d015ec8bb0eb762965920d62457f661dcf63c442fd935be062a1d02b79c2768d13028e9ce3a2301524e04d6dcedb4909ce99a82" },
                { "en-US", "42bcdfd5a6289d444c18b7bc058f8e1cd4022c2cac53a12e27e0d0277afa3723fb5979e5dee621b762f0db64f59ee504825f57a36dbc5c117c019ddf2c65a624" },
                { "es-AR", "c3e97430a1599d1c17d569c367f006b4af15172bf5f0ed91660791fee44cc5fa127775aa86eb55cbefba43516649dc572b34831ed4ec61b3d42be35d90307cff" },
                { "es-ES", "76e56b5ff120538a9797f4bec1fb874f156045dd45d3f7035c5cf87ad99553be0802918740589682a0af8e735f201ff1f6b1ace7fd66abbea61f4cdb6244c943" },
                { "et", "a6fb86384814591597afcea29d03f6434fba181e2949342f84a0bb69f6a5b3de5dbe52f552d36adb491684c978ae63357349981e567424d30227a3780d478d14" },
                { "eu", "0665b15a1ad1550841295b7425124670c7800c84b1411ac2c82cab3d6f6662ead2264bd3da6ffad83f885ff485f51eb7a6c7360313092d0f1a85d28b644c86e8" },
                { "fi", "28a27c0c07b2c873a0329163d904f4bbb1b6e552116719b5e6061613f9bfdc60cf2d12cb94d28f32f24ca0fd3327f754a40357a8744dda43be7cfb214a827a48" },
                { "fr", "047a3034e2a140294cd474b34116e84cfcdcee077d2e19fa0755de1bf99b7166d875e7cec4f22d52654115200041c704dd4669d7b5e51d5513339eeb856d49a3" },
                { "fy-NL", "c20eaff71d5ba162e3eb48c7adfb24b32490bc85747f441c9afcc126fedf2298cfba66dfb170b4dea1fef94dddfeff33ba54de3e0c23308cfec3b65b8eb1651c" },
                { "ga-IE", "ebeb6540ee54ca54daa4866eba857f7b0c25dc8d96667f8448c1946410762cab748e4644daab166a33b63dd8988b1d377afd3ec3c1ba89386819166ca4616afd" },
                { "gd", "ab48dd79fd26685b2f5f218fb9da55b8f27c6a2dc40efac3d7a815a6c246402b217c0235ef2cda386b741f6d853388ee62b53133e7ef41e9a8923f3b5d213b5b" },
                { "gl", "822a511c7f87cdbf76d7ea5fb988c4ea23580c1f65b5ba9bd676a29ddef38427065f2056f6ee2825b9bb1dcb359433d1695c141bd57045c2ad41b6f556aa3ff1" },
                { "he", "ba43ef09ae4369796ed4359a847f463d4cf21c3fc1293a10e4fd61133e3d34578200f8383f528596a605ed195f87d473a8aacc48702d5632caaea0d8351c5076" },
                { "hr", "47520c538b66ad660ead521c3b9d4bf074f37654889d16ffcebef3b4f83c28a5b6b734903abbc71780b0f9a11fc0ba88a60149aed28d1ba3d1d1ce44525f5c23" },
                { "hsb", "9b247368ec2feb327628238a5939a9e8062fa7a7cf4991b8068e3449c50ebbee7b6fcd6d560a1fad92434fecd18748d3c5b8b9f701ed8b60c39321f41113585e" },
                { "hu", "b997e7967b5bbd459ba3151fd27d0a92ee2d78a92c832fe02a76eae609ae7c8414a366dad12512c8766d166e9ab200be9f749e0fedc64fb5da5338cf514fdcd3" },
                { "hy-AM", "c6ded6dea3727a2dd500aca07ed8b5f7f1973b707813e6ac00dc94730f47836c740deba03a7bc108461368ea8df6b216e38af79ebbf0c9fec6df1f1b3903547d" },
                { "id", "1cd3f0624c7c13f3abf7920c3be2c9232feaae3947a6b4e86ffd67a1f54ef75dc6a2ba41360fcfad9b769604b7c6172abda060fe182495a50d9ed98a03550a94" },
                { "is", "a5a65d34e1973ed58c645c590281a147d7c995d80c1450ff562b5fdf798a2334c6acdd9ea0488bc2cc6ddbf200503e95d2fe1615fd7ee49f100deccdad58d705" },
                { "it", "ffb1fd91cfcd9321cbe9a19ca743af30b7ad486102a15ac7ed831da3337cb11fd7a0d23eab2597d0a6dae1b2dbd8b8dd3ad547b30e63e1fe6d7f299b5771d02f" },
                { "ja", "219cad0a990c0618a62d3872e50f25c5ffebde03ed6ddf0d025231247b7c24f567176907123f98072b9c54a5fbb32170af337077e25c4cebe5d7a48bfb569e2e" },
                { "ka", "5629e251bd05a6ad6b9a2da2e48d3747a515e0636718ac2cc58a68393b7cf255081d003e1d83e56002919a6f56796e0f3e2db0dac5984797c44de2ff403a08c3" },
                { "kab", "359d46c2563d6b9ee3c058ba569215f997daed2dbe8e56094c3e1a46b8e7a0927d402daa25b943c027f1694ff56d11a846cac8c403cb58822f4363a7939849e9" },
                { "kk", "a35250212b90edc9239b22eeaac7ac6a9a9c8862df4a46e0dc3b72322bbf32196390abed153e1ed7e065389c8e327951b8e544301fc3c023dc8c48ef318593b8" },
                { "ko", "495380f6b8ed56fb6b98f29ad1c5f17ea7535ea7eef24899b9d65ca407a7ccbdd389fb0677039613965ff8661ac878998e1b7e552151cab341051ea5eec4461d" },
                { "lt", "6519070dc706f124acb69cc0b11201fd1cde34e96afe67c772b3eafa6cd57c7749b811a45147696ed58f91b2f59cfce311fb8d03dc51fbc2008b5ab8b2f98b59" },
                { "lv", "77d604f8dffeb374c2a1b75644dcde106393b2d889ceb31b1063f0390fd28d634d317facfbd51e17c8384e5f1e71f5af88fb3da6cbbc4af2d47676b2d5c65b97" },
                { "ms", "b72a02c3d174fd38c1f5967dac30829aa2923e1c38803c229f9e57aa0541d06ad42616039cae8034516dd62fac43e38cf839603b3fbbeab631f736da79a1d030" },
                { "nb-NO", "dcddd6eab2af92e0f3e15b4e43c90b7235e3dc5c3cc58eceb1e3f52a938c5c2bf59151c9b8b577ff67c26328b6fd7a879b53feb6513220d6f2f7796bce853b85" },
                { "nl", "f943c90352a1fc042dfc45ce0de64679a9b1fae2d8c9ef9c81bccf95c8b6d0a165c515538a8484e4181966b7e1fd1ef8ba50dc44856a9ab4bd3d2824e674f9b3" },
                { "nn-NO", "9ad856ff737dc7e4e65415471919e6d25b315490eee8c3bfc4e7faf154a15c4e7cc5c9471b42ecb1e21de91a58683871efc49d2b999951387a1dc453bd4d5250" },
                { "pa-IN", "7642ac0d32246b2da5da5345f1f97c73e7a1830211fd541e4303c9a6ba2b0dace7df7086cbaf3a74a4d21ed867b80284e82c8bd37d8179ccd191cb9c377acdd8" },
                { "pl", "b13c4d3c6f8898386e64a5ff1855fe846712e19a671be3eb5314ace9158b384a445a4f2a2aac62c2b887697de4a0ad2f114048f05bb3f8fa1dec6da5c79295f0" },
                { "pt-BR", "46c45bbe9b210a851598a5dbcc76d54892099538a674206a475e7dacc326a1dc718f0cb612474ee0b0dc6a122b0a5a30642d44994749f655895fc7127751f901" },
                { "pt-PT", "308e26036c2af4c49864dfe9a148cdc1873631be0a26479742f82e200678e16ef60bf2402ed90b46e512e990e1a838db55e11014d9009d7242bb07aabf80c459" },
                { "rm", "e3bdd526d92a5845c6d6c93e81d0a979721e0ac4564e61573c0aa6e6476072c30161b913ef4cd980f7830e711005a16f6f0b7bd149ba442bf6d7e56b0c54f917" },
                { "ro", "38bcec527194dc96fa80ba17c0a5b51b4f1a1736136e3190e6343b0446fe3ee6753d15fe535ee06e074dc5e51c6649c6ec3f89ef008867536d1bef60c73cf88a" },
                { "ru", "0ff4629607c512dbb0c97a7feb66efc21ef265cac4feb46707fc9020aee9e1a131c71f18f9a7e1863444dd510367ded1c25d20dabe60ae28c98c2ab3b404d68d" },
                { "sk", "003b7ba010c6e731414a0d5866e91f9b689cdcac221dcaf4b676bf8f331d9b2fdbbfb0107bdbe6034e40e9ebc6f4ba08533af0f57f10ac1eb5dd11bd834139a3" },
                { "sl", "8ea5a1e396cc6b311d7ab679055f69ac407c5661866d3367b79e9f20677e7d2d1f37b1f8a0fce92281577a5b060098e078ab51659b93279d65814547f35d66c9" },
                { "sq", "2cd337e43a731eb760bbd6ec8c4b10d97e20c5ed46619439b58c41793d7c16a01fb3d6eb0c4966d59bcb26c14436b2ba46b3769fb12947cf714ebd27ce27729f" },
                { "sr", "ef3c9dc993250141c2e7eb7e31273612162a6e9be8f6b31fd9ca6804c16dbd1f2a8a8280297b68aef02ced1b629776d919148c088a0fd94c7088abac3a2bf564" },
                { "sv-SE", "b050bbdca52077821d370cf982a7b67b7c8ddef5a32b40e69cfb2d574dcea823834a668f23e4458176b846ddfb97a8b9f6f693c5d68ae89335183cbfd1d66cad" },
                { "th", "d4428ce126dba27ef370c782f450ffeeb3fc618c760f9fa9c99842dc62301f9c677333385108b4b5216b82be80677e43f490bb9195daf11ba1719cc3f79ceac3" },
                { "tr", "0bcb60af31c71dbbb6eb6a3589ab3e13c2bd7699d3d654fb7e84f296e5bea652884dcc07f1861248a225e34a3b919537118fb7442e880d14b2cde610fee6fae9" },
                { "uk", "7c52a98838d21a5b7d2e7de2990b705df6d1974a1c2038d9b044b5806b33331c19f72478cc148600c6c0421b6f2fa23b4d2ce8e6dabd66693ca72bcefd31b898" },
                { "uz", "4eec6b3ce5504634d6e3c6b95e00b7972c983dd8aa7b69a5e11cc312ad44b5a3fec3d8cf93cafa8a73c5e0ea3d807c94573c790d9ac50bd74232be7f475ce549" },
                { "vi", "3add085561ed4dd4af0040cdebe9e4225837ed3f604dd4b959140b88d8c318b20403d87f77b8c3db42b34691255f9be8e35bd59203eb66b59e26980763154ae5" },
                { "zh-CN", "90d41b7e6630435b3216d37532bab92d98a2e9f8f6d3f2bb82d465e88265d6b9ea7b473d2164cefe71f260f73b52e3ed22df0d95177079ce46679a8eada10c0c" },
                { "zh-TW", "ae61cb20052c1ae1c0127db74d2ec52071aec31497b56118c885de84ba80b4c93d7b1682e00d7ae5f153e008009a4379b9543319799d3edb71e687bd705ba21d" }
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
            const string version = "91.6.0";
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
