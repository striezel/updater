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
        private const string currentVersion = "112.0b8";

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
            // https://ftp.mozilla.org/pub/devedition/releases/112.0b8/SHA512SUMS
            return new Dictionary<string, string>(99)
            {
                { "ach", "28230022c9b27ce22064bfb2d0af4d2958fbe277b6316a2aff0c0a26123285c69153ef8161ffb6bf3dbbd4dcb21638f8b8d83c71984481019643aa05db3cc9d1" },
                { "af", "2bb8691e9c7d55432b2fc248878134ae10b7ee27c84b352e88b9b04e2b9af4963ea23853582cffa2e44942b7c669f7bfefe8f9a61b424695d984eb340ac16956" },
                { "an", "57bc1f5c18965a7eef3b9ae8b329c0744d015973ca1a033f3c6a778994fb2cf65907c7b4ed160c9f3b515f5d5a17d951a823810c3b0c3da59c58321b9ff1f813" },
                { "ar", "208c638bacc254900e875b5e139789e6f00701180b6b3ebe7e6a5836dd49d34f71522c21300ea87baa5d1373b25c1ef09a38dad16198ca0be6d54d23f23666b3" },
                { "ast", "08946af985d735fcf071ab0a94846299a364de25d40f2537b958bc3e072e93440bbd0ad482f725f34969a8640e238e764f1bbbaaab5bffb8f3efa064150fa0d0" },
                { "az", "e2c7bc078337b2ac2e9bdc04e75c94bd819b5c6b807111a9b4752702507712f06b3dc5612a60d399a9fdff131484939818574fec345703dae0642dcdf5f0ddb1" },
                { "be", "1f9f9b334e3e1fd1ba92b694df60939219225118bdad1e62ee728e1a786dd079fd7f9a0d4551851805e5428399d43d5f0d517c0b238a4b7dacd2837781561007" },
                { "bg", "e0baaecad4643f30ad6ec773fbad05af030d53d2b6db9c7c145235458a4653460b2c23251e5034c03eb68aa2d175b14b615ba4c00b0de71f5e07d71f38374359" },
                { "bn", "5af4fa577c99c0abf96c832bb1c0a6a63c35c1ddf8d638c570280df593656e1664ae16c00e3ee40eb463d4eb24b782f1e40ba8b9a5af80b5ba8ff8c2ea84bd3c" },
                { "br", "6c16045980c2fd6da24d4332ffcf08167d9145f9f03a63221c2f9e7dbb44b1e72d1828b50de24bf4628b6d6b313b83e6fb6c86b4858983c5753ab79aaa57fe54" },
                { "bs", "6ced400869a12f7794b7adac331884bbc989a0ad46b5b4f2dce153b118e9fb1abedeea5ff7a2476e42c31a0ec3bec059fb532cb68423f6153956d312119d0426" },
                { "ca", "af60a31ae4eac6f2e4320cb3d4f6f4b3a2391d423ed0d2005913e16808d3beb3013aa002a9695648485ffbe400b41b6ed3b2b32dedcce175d71e30a641586ef3" },
                { "cak", "f1106255058c6b131fd705e763a2133cfeccea2eae6d9a9c4d6db5a6eba1c8c7a22131ac9f2661cacf6d4493991017b4c1aa75a45151e59351ad71c550b4766e" },
                { "cs", "48a85bf36d159f299f03bef07cf2f85b6bc562fff6ca340f2510448c78cb6a9bc4cbb3792f3aa1dbddf51ec573a49bc520eb98b6480e032285fb05829c6f1756" },
                { "cy", "7b1f5734b0bab9adb33acb558f4fb2b2e60b25a0aed1de0d4f340f19e441419cc9c57d3046726bedf1fbd07537966a39a6303e81ecffab138e1ce8e7a098c5c8" },
                { "da", "48689068d61825a6ab267db644e9fd2f256569684f8d3f0a6342d3102143c200f281800c318585bd7a70556357c0a88a1f30ff68fc213df0de5f6ef3d3d6c2fb" },
                { "de", "3fcef1d458691efd3f00754f4413aec2a89d93de7114f196e23ab13c67c3482fc734db9e25888eea027af263f36087aa19841ba804c1c74da0513327cea3b2d7" },
                { "dsb", "a094d3413341287bb34fd72ba0e8d1b1853ab0c7cfc5d6549fd95a9f2eaa4f8b6dc4a3246b0cf4d7fd1900077c502ab6b695057bde653e8d3eed3b578eff34c0" },
                { "el", "42390e09812b6e491ef735ba3632f7885b5cddc0662ef418e562f3daa47eea4ef52e07e8f7e1953172ea89d537b9925fc2b8dc4cb591f45b9de01fbe6c5da5f9" },
                { "en-CA", "e346b0ea8a0c20cf64e5d2fc04edd29bdd416581b051e70f5c7985b4ef2946aedf0986f4f526a192dad0f13468714fc13130d42fc56f30773c8647cec7f31b53" },
                { "en-GB", "597e1b5fb9aa868881d2fcedc1ee70bd505bfcec75998baea508b7c68ffeceba8b63e1fadf99cfc1d1eec2ec042a1755d633d1d38d7f19893db7f6135f051da7" },
                { "en-US", "f92ee52e7450f2e78728fc64643eecdc957b6f82e7714c76f685be12377d76810dd525ee93b5761f82c90e88102f5f865200c927108e0a3adae5e4caaeb1e99a" },
                { "eo", "f954ad1e243aa98ea2933799ed247f06ac9e73ab62db9ec960ee474e570bd605a29c1a1bd68c2fdeb6664686a5e3ca3195c9f0ce7af896c80461a6fd6c2ea90d" },
                { "es-AR", "e619f246d7560ab877e26a73016410529445d5ec65607805955b9013caa2bc2fa9666b5c577bb1b8463ffa268e280077f3b1cac392fa815b1abfc62715c7e50f" },
                { "es-CL", "6a51094fec1c56313cbc9b10f16a109249f4b45bf1bfeb0a4fdfaec3a4be713331e8bdbbb068f04f0ceeae1d76c89cf1491c78775d44b18fe28c34d7356c14ba" },
                { "es-ES", "c4074306ba8cdefa2b5d2a9ceb758b907e579c3c285991844834151cc2c93366f46b35f522027810c844d8e0f35d2967441abc1e0a137a03a7af7094c03377c2" },
                { "es-MX", "ca82fa03b987de734fca614e3055c01a57f681a0c4f0f04ca6eeed09e13f2410c28ef8e5ebf8f658d4a2089d2a5be4257069d1427de2305cf2738a835f0e79cd" },
                { "et", "e93d7212f42b60c97503ae62142c8d3d29c175587c311019710236b30c9b6bc5adecce1d58a8aaa5b087c8f8bac9d834f2fa75c912e74f7f1c03b4e5153bc99f" },
                { "eu", "76037b7eed6c3e6f5ddbf26834a14d548e3b96d3889230c557bc254c3c1cdcb8969c6e345bdeff3b19cddf07918955f8a7c300f0628ec9c8180fcd4a54480c5e" },
                { "fa", "3798ef18d7a79edb5d8b7f2a2bf835cb01311cb11b4f2029f320701e9c156a2b39e627673d6ddc7870f5cd5ea023b32fdff058bd09c76253703c987ffa3c1ec3" },
                { "ff", "8e9c69cb623d9872b8354f247f2e89d8a384fc53e35de4926a7206d431e89be3eb3db8db3a93e11ec220b71700a30e9a42a642c151262c48ebb60076512c073e" },
                { "fi", "739ee5cae2ddcbe42135607a2dcd49d93496e6b2f2fa68ab1d95c6808809c5c67c6c8d825d465061b5e02d72e4b5bbe95e165481c88f5058a404f82f88818f91" },
                { "fr", "c22c2afbe7759997dd2e649fd20aeb568e6a732b53c56544ec91d0607c1073542e1d1d46a49c51ee1f99a5f0bd74ce8df771d6d885da510c8e1a5bcbdff25d94" },
                { "fur", "be58b269d683c5b40dfca5b4fc0ae018202f46e9c7b91e7484cffd62fd060f2b07a92b79aae73075d0bcdb3090073ea272b9020af845b1db13240e0241944bd4" },
                { "fy-NL", "cf513054a5fa34e7ba6eccb14badc6ae5d1e823760e2fc5e9486cd974f6dba1bf9df785b836706829a202a42d44529d9059d5021fe0ec4e89606445c99746630" },
                { "ga-IE", "7ab6d94f1486ebfa7ed39198f885bf86ea94add64ae9cf91fad08c3fbea827d3461d455949b491d39852525ba32b4c01780fe2d5e32c1c434529980a1a786a5d" },
                { "gd", "7def3ef8ff91321ad594cc651d2f35c7f65a06f04e56909ca750ea84ec2d0f936a56e3ce5df45e22cc7dc992327bbcafc7a09958312b33d34b3d7acd844371a0" },
                { "gl", "4fc3c8bfc53f43ed856e559b92358c31d66008a56b5c87911933276eb3b5783157b82012736ac3179613f8080603a0a13e85c695a7d70e11b91a56170822cf16" },
                { "gn", "52b3f457386edc66e696113ce78a443880e88fb282c3b2962ab1b2b7472b8c18e30acf3314f0cc0b731310c3fbfff0f57f485ee86c683bd1283d74a51eece9fb" },
                { "gu-IN", "fd228046212d5dfbca2a62d3f87264213fb2979da2077c7047955d6a0b29306ad225d9360863e72083a57cb79659674337d449cd1c0b76a92ef947a9c26bebd9" },
                { "he", "7dab51a29b50b087b8fa524b6bfb098b866d3148cea6b50b57e3eb2f95c0c0c6916ce25a30dcb3e04a97708cc3c324763e761c9c7b0d1b9d1fe31756eee6ca32" },
                { "hi-IN", "87b504911bd05ed1c134c82043785c459db3bca25f9921994e9ccad0d3d382e13b2d66655abd860bf1890627fd8a29e95a9ef8d4d3b5768215df6e11dfb35c41" },
                { "hr", "ca953a4d3d0edefd020285f528a334bd354747cb18ab7dca3e70940f234b4c29e9492b2af6ca439aa941f034a03a5565ec23fdcf1c4e424072e3b925ce7129bf" },
                { "hsb", "1324c059b0ff2f6667dc144bf32e300b6755a846d1ea07d738af3da629e5a2f5dbc706f1f8df8d9ce78b1ee40ba0335b869949689d45668aa0111760d7a3fdc7" },
                { "hu", "ac644952f74e9f3942ed7f50f17a1db232fb33899f7c4744545a79aad928173a72a2e538e1ed89830c55bb9e28db63ac653242824536ebe5a2eae35d6c23d05e" },
                { "hy-AM", "e518eda945158cc3917201db3bd11a0d145221476267230c567de418015980ae4314923690706400a6c4468758872e02478132208238d41854da04e3f6969fbe" },
                { "ia", "b9c78c5afb225ed3caa7caf00e5edb71e296f95bc0d95a8b21456892c85ee98682880ab48553ddd1ee4df6e43b5eca3e6cc96cb87ed27890441e0bf05db91437" },
                { "id", "c7986b20aca13f4420d0a17ca475242ff141c21679c8d893247bae0273c0069c00a17d5db91040990aafae143a8484a62b4a104718c6324f2241202c2acbf884" },
                { "is", "732bdee9ed34610afa7962a172175060e9fbe6dfbad3f31759e8005dfa2c6f9cc6051873fced54abfbd19a3c1888734907f88ae930e2d0a0496af20bed84792d" },
                { "it", "320fdd7111cb5fdfbc24fd20e980b82e2eb0a81e41f3a5cc0ca5bc489d2db15326a2c351ff203da92dec0cdc2041dc75b06d6bf4a853c69eaa6c5f85073083f0" },
                { "ja", "a1c0a5d51969aa778d70d89579ee96ed70a0f5578e3f54978a42af6463f621ab9de9ffaeed8103059bc01083a2159621475e9a5800239d77525c1352378e645f" },
                { "ka", "64788f79c8b13d24bc91163b6fd2e310c37dc5296e28a3a1881cae001de88697013a31399dbd30718ed4ebd14cd96dc047fc078bee228ee211683b16f596d62e" },
                { "kab", "d2e2b419a261d8e68071ce0bb9f697710c69f1a27879698f47b0a369664b60fe7c7d3aa08ad1e71443db185f83f5b398683625242848f96df4d5e3c918461f42" },
                { "kk", "5a2dfd39d67dfaa1fbe2be3e0b3f0170bdc795897cd264f0250dd971260b353945a23f2c8cdb634999bf065a5950951f9b4b36e6b8c4cc75c290e812dc6be0d3" },
                { "km", "aefbbfc4c5e69608b390b38ed2ae8d0132b3999db7a787540be8b3e9fbce58b43bc9993f778d02e8aa1192d155eb02e2738f0176756ebb1d37a32fc7e09cef24" },
                { "kn", "9d01c76bcc63b2c4888d87470c36ae99e19a8e1d7d2ba6a2c764b2b5912bfae55794158c295de3e7b6e3981109b927f6334fe3947353e6e6f719bc7e9a50db99" },
                { "ko", "2145dba6e3c9b8ba3db393397d6e52e61cfc0c6465ef576db96f1aa9184c39621fe7ca7eb2f52750df6730087eeea6951abfab911c9a919aa76e6ab18712b95d" },
                { "lij", "bc5add7ac133e8cc826f9ed128e3b9407463a5f8d23b19467bdfa193edbbf855ab6b30e6203ed30d955a27fa8bbfd5c6cdfa824332dc2f94e9ffb41451c45c56" },
                { "lt", "c6c3be2f71b0e4938b0a657ae2701ba9f001394a7c980b28d95e7416ea30c84e8da0db217b05f203d8d25bd2cf538a145c619fb23cc945f3de34b54771826a18" },
                { "lv", "f723e376592f9b83d9a774491ff0ac561339fe3a7b79f760cf7cd79adf1898c7b40600ade7e34cc75a4e346e0129a8dffd64e2fe2befa8502d03d6d25678ab32" },
                { "mk", "5bc2be8ab13b8ef6ab6b46fdebd8a332a3197bafc6faa0ef36e1cffd587f6a9b4013f6a883479217bb3afc724c21db2129e5476108182536db52398b6bd5b991" },
                { "mr", "c350e8b49f280fce4984f45ce952b7ea6d95494661a7cf105a08054f3b89f3f7b6cebc4a845ed65e029497bd001a45ff9dae9c4ebaec7f0a2ce355b7ff776ed0" },
                { "ms", "c1db2428af6a40b4828c4f340529d828bc44f4badb09d0a1cc893c924f3d5c2063e89c64d769e1aa2cd47848eb16c1217680f9412d74b8645f1b36ced1f26926" },
                { "my", "bb8d73c0d4bd5e325055e230da6df92be3df9ca8f4a9da252edc6130366b09891a82128850b3c16039e3764f2b1f24a3456d9049de9375f3777e79f4d73ff07f" },
                { "nb-NO", "127adfce33b7243ff13ab09e78dc9cd8a29ea1dbf75018d7ef182e4c2865b8015642c4355f015190179b7ae4c5375a1c872b007403736217724c1cbddd6f5415" },
                { "ne-NP", "5d5b338614fc96658d744253cefb733a2826a181d2049d7fd6e2a4c72825575d2b871c04955b0f42632ca9594ef93f99fa90da730a002cc20f8c329e6be80f9b" },
                { "nl", "62afe22705493810be331ab5ab463be63fb82879129a07622a51892cdff7079e370bb620ce22c939297dd0ac4b2284c67f3f593f9ba173c56d10078bbcc6df23" },
                { "nn-NO", "4c24ba3e2fdb3f1e41a3035cbe89906e3059a7daf78353b0cd18fc59a8e469e1750d2d25d2a06e7409c036e2c607ae0a3ad9e8eb270ca5e1f7c429129e42fa3d" },
                { "oc", "2082f25004ab5730880608e5e7dbcedf6f04ac4e88ac55629a0f2961df86ce803c2c0084bb5d2fae936fc6a2447d7cc110bc7827307eeb46fb46e51de9fdbfac" },
                { "pa-IN", "224a9775ec44dfd46465fba9857d5b79ead00ddd6b69e48ac7c55e715aac0b45f9d276a3bee27fcca4093bb81fd93e3e2f73ebfd36c2567d01e0d87098ad1219" },
                { "pl", "b2730cda70e8e02e8914398c923e89d38216e073e4da38d8a3a851718db714d7b98e47eb7c5028da999064a6eb95934e252c609bd9b83bdbc484fbcf93787b47" },
                { "pt-BR", "e3533ef4d9589f608295c2023a9dd29bf04e52e073391e6a1d1f0896023a962ee3cb22f2b2cba9f10d08e21201ac94cb0f6f8945484672a07e1ee2bec056e58e" },
                { "pt-PT", "d7a8e3667ad3bf7cdf0b1fe002114d6e90bb7cf0f5eb31811434484f7bd70c3d26f3ee21b5023f977c2404d450e3c515b84e845357e138ddb7eea78a8b2ce968" },
                { "rm", "7fdbdb6f5765015361d9defe684333e24c28f383897c98ce05147e5130075b1ef5af2b718388adcf55fb283d4ba5559d6cf1311c7d470a46955c552e76531131" },
                { "ro", "0f39b471a758a860544b1bd310638360f522e1730af13ecec2e485d2136dedb4dad10f9901892e7d1a8a6d9539bb9366668dc62e5725ccd3bd1955dcf21f0715" },
                { "ru", "d12f2d1a60e4a55c72bd589f0d0ee310027544b0cbbfe2e7a4982df87769ef2867fecec1854a7365098c712d0b1344c1c15a6b81d97980e8aad22acdb8340b3f" },
                { "sc", "9afeefc1ca08e6fdf5af0670f295d8a513de8f321a6dbb9bf4e3c93033ff49ad76f204f18dd8cac541902b9b4ff60fcba428ae45219dcc62208516213ad95180" },
                { "sco", "15d640e78b636c29924f0ffd9cbae9e6d329c209f919395655150eb7b1d74d2f61e533707642418deaca3b06dfd37aa516ab34ef9ebfde6cd5e9c0230810fa67" },
                { "si", "f7af3cdaa16b127fb15d4505a1033c990620926761dc43c13ff8158231e2c85b8d8b955ba62db3f02b07c4d6f3785af3e7c276642562148f9a28fb76589c2e11" },
                { "sk", "7a89f945771207a0c7d3e6d9dcf081b2c4732eefc8b43d1d9c09e62e1bd6a05b2fa407676924eb0ed972be6db468358d77bc00264889c2024add358b90c2be27" },
                { "sl", "91763730f46e6a3afe7f82c42cddd2d26f1665a3c9f4cf76b47258c052e32cdc289a3a4bd6fed82a015e10cd8719e68ba6d93dc6a7fa121b695102286810212f" },
                { "son", "f371d7dc074ee2c4e37666f01cccb66a81a15eace3ef6047a024daa93e79ba2fbafb1c04c2f25329200d0ea9dfea873928b1c8dadffa13a059503a401a8624d2" },
                { "sq", "66d828f0c8b505ab9c53e280aa1c8e50e181dc5cc75bbed3987deae523413856f7c4d8843833eab822658cd313a8fd59f3c4e62cab97f1e32ff1e6498d4ecca9" },
                { "sr", "bced9e862e152ece4a50e43687764c436fd3aeba23217b3c31f0d1b96782eabbf1697c50787f333020b0ebd0117c261c5367113f99dff4950004695597f667b5" },
                { "sv-SE", "9998d72925917a39e39368844c2eee79056426ce9121c6d36568a9cf8d904c5e50fc5f06d4019a94d662b0b0dbc96bb79d7008b7d476d4d949c8b32cf02ba546" },
                { "szl", "93327ff03bd0eb696c72f0342015ec183de7d0584f37f0aaa4624cb873ddb7c43ec2b00cae6f236e7a0532e3d88d86ce7b99bf6bfe58bffde6a38621242b5a2c" },
                { "ta", "d61a1784517a9d6d324877abba87f8c46e0a4d5b90b08ffd46156cb50c83aea9e9f65ade5b209f1b8ff01ea1357c68bfcd43b7c8add39f14cf00ac7af3108e4a" },
                { "te", "01ddcb9288ae806c041211b550b437a8caa4cd855164febb576c6ebfb6a9871f1e92f8a59a4978ab1ff93fb951772a0a2cfe23fa84f347996bfbcded088e0241" },
                { "th", "bc276ea4ccd0d1f42ea993cd290fcb29ddeebcdc72d99265befaeda3f91c3e64269a424c0608ed2e96ea568308dec56bf4b0d9d428b13abba8d6c43c9e089c24" },
                { "tl", "19f4d555a1dd3d6d940d9e5f0972a417d4f1b012e6f7cf49ff2543e360dc370a17e1816d6a5e8e91e9bcb80e41ebce5ee202a0bc0c6e6751da0357090cd5663e" },
                { "tr", "ef0034744be02bfd0accaf08a38d6cbbbb6f4644b4929ac27c0d7ebd26e08b79b9f0c25c98d83f65c6e719f2f04edee6ea03e220d8550424afae11d265ddd5c0" },
                { "trs", "6d7175ff0a296dcf5ce8662bfeedfe85a456bc19047d0e51fcba19d95e62dfa1a433bf6d9f1d4662f6c97d7ad5b5d611c2af4e8c629614f8abcf49600af37cc8" },
                { "uk", "20e1d1733c227293cf7ad85a2432ec70cead660c69c4af03e3a7b49c3550b650c7bf1d7163776ee5d2904c895c38fab2563f55f27f412dfe89bc5c24117a40bb" },
                { "ur", "259f95fbc0a68497ddb91daf43f027b4c42c78a82e246d0c8059892e76ccdd38de42a71de40545cc78eec774a0dfefbaa67864e093444b7e5ddfc80135efa133" },
                { "uz", "bd2d10d4bef9ae1bae2a0d3caac67b2aba452ee6b5c413d0118ecdc3190fa94ca9c4de039fc5f49c6400ad1c8db6de0c199dfdbe39148b77cd4ebb89bf15a40c" },
                { "vi", "6f635e92cd5eb1103fdec2049b5d417b37ba4308074e613663e755c4b2d3a4a2ea5821cfebfda8041441307dc7d9e5a7a141e41ba5841030eeb4d63e603804c5" },
                { "xh", "e2b19478e84e247fabbb9dd9bf53db7ccac09b703c361e2ef69cac308bc752a3f85c997eaf8d4750ff4efbfcbf99020fd3cb137e789fc766fabec678a45d7218" },
                { "zh-CN", "3a1eb50056688b055f893efb5b55069a775d374f82e4d3690284ad05bc6fe3cdc59321ed7d1dd9925249521ac9f77f6895058766d5acf58fdfeeae9592005d6e" },
                { "zh-TW", "ece1378c47fe752249a0677a3ce6890ddeb9c2dc2d5ddfc520578f90f27fb8b4d496d1237a8dba997dc2e9f5bcea9a4eaa0d0f6fda19955a9c0c31f75fa1a98c" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/112.0b8/SHA512SUMS
            return new Dictionary<string, string>(99)
            {
                { "ach", "2bf1871745cc56ae9903eb5ac975a1489db7258c31c37ff0744cfdd36a3fa64f87e4102b60e8537cd9e55d9f21e1a765afa1d86fcc133b830074e4abbcfa72f9" },
                { "af", "2499c91a0c7698f800ddef724123f1bb329439f35c8059876fe51405124af7f30d4f21f00d670e204b5a4237701d44398deed02eae9855b936b65814be1eba30" },
                { "an", "6fc1d10940fa22089edc43562661c6e527f7d6b0fbfa2c792e7440d45d0845de23789e1b71713d2fdd272fb10ed464a28685ac8ebd4c904c74fa4e5282fcbe7a" },
                { "ar", "ef21f5948a1993bd8aa86b2613254c63d93fdf7e1c46eaf4829125c00fde218d3ca497511cfe75c9be27b6ef0abe0f9290f628fc0376b88af391a5d4c2c7e115" },
                { "ast", "9dd578330b337b29e2f12db3a6ed57ddbafd1a0fb60a4d192812f2107e6e58fae5e3fd33352d99f8e113259e1a0dd3ed46558bbd941b1be754140e7d5b20b098" },
                { "az", "7df76b7cce0d385746da652742af5ddcba8cf70e1d8c17ebf63d1a3b0cfa5fe2b34c80fce423c3de37f9b14b1bd17c85590b55837af95fcb6a5788659b55666c" },
                { "be", "bb8bb2e6a1075ee5c1ca7e03b867186c49e871bc0c74bfe7a775647a9399b5bb691524d3921f12e255ccf50af45163a4dd3a917840aa47c3de8d203b295b57a3" },
                { "bg", "4ca4fca2603d237f4392f3670937ba05e0b68b5bd34104171eeb1c00df1361e335c9ee2e0768a266203b41bda1d7e158ac6261dd1bfcf8ff1e602f3ac46098e8" },
                { "bn", "3c3c4d14fe1b550a348e01b8dff7f4206cb28d7e223c90b4ea57b5562ebbb454c88b47dd1b920406699b238f02d54fe36ea0810ebba7f64fd734cc11d27e5f13" },
                { "br", "3c5a8b7d4fec9df06fecbb4beb9644a8dc23b9f570ea52af81e7c424223e67d75646f581fb0b7621dbf047ef91ca5aaa0bc8a272b9ca6249cb5cba68ab855e90" },
                { "bs", "e0ca466a9ac701976f6615da1ed0dd2df573ac99f749fe6b0476998141f960d533679fcfd91648aecceac26af3e868a7877a96d930ffbeaa08023e349191c4d3" },
                { "ca", "d09b1538b9772ce73b47284b9e58560a8fd2be07e346397ba26aeb48d6638eeb128a6ebbb94a2d1f107a5fad4fbf4a63c49eeca8a0f80ab9c8df9fde99ac8348" },
                { "cak", "f16080b12eb565dbb7ab592b1c4c64b62288a7ab747198c70faddfa1027d94f36d75d88f8c8b1813f6dc0cdd3344ce94dc907513c66158ec5c073769f410e7c5" },
                { "cs", "310e121266a74e430971ed8ba95b2fd3f57703c2072698f4c10ad8349820cfff75d5a914398815480d79b463dedfd813c8a11a1de348cc87033ed382e954c061" },
                { "cy", "b81a679c0891b8451fce17f53392aab5349d51fd9d8dd93714eb6706c30a8c2ca9d219609b4a0187cf5aa29fbb191eb5f3949627894c91c02d1369a6f844692f" },
                { "da", "15ce30f33b89fac04090ffc7a169e2938887504ab2b63e5c13134c3eb553a6d45d781b7dc1d9b94d0abede757f11e6b1f80aba03b84b93aad2c292b622b81e80" },
                { "de", "fbe09f9bc9c510293b94da4babcda88e60b812a07a69aa08b0dc611bf8819e000190ec0cba6f9ebb8a4213af0511d1333cd9e62b2c12b35d99ae27fbc7f4c1ce" },
                { "dsb", "1a82a4112c1dbd051aa898d18540cf8995694074e154eb780bb56d3a85e2c2dd10aeb358c1510f24749bd4a6e1e31f565b090c280947c74c858e8fe4c94bca6d" },
                { "el", "b76de22607f35f68be2b6562f0373a1be1b667fb00be0dcfb8889b2f88027c164e024822432b42f6749a407324fa0983a3044cfaecc24b8a64d111147e353754" },
                { "en-CA", "e5e0217681c2b8f765f80edaf4bbf53274fc0dac67406a307b5b98f32dc9b72ef477b5d5994472a4cf9dffa631e5373da1025043e28b9cae8736d60f4397f4b4" },
                { "en-GB", "e439f62e37757f191152decbcf56cdc8d044a0fd30b05ebf9bd1b3833260d00f4e2231384102112e7871ed2b46c5456d99e4c42cd2823571a0f072ee156dfd36" },
                { "en-US", "b5a4705017520c58b13cf3423680f872e474d950d94a10fe390a8af8b9b74e8c5a3c011d5a3f090b9d8f864049da7a4b4a83d60749704ef2fc29d23991d3b7a0" },
                { "eo", "d726bb195d4036b38748fd80bf5b64a9b11f06fd438931c56afb79944da72bb4677a0bd49a3a61f00b9e82e96816f3c61774b41c0622419066f3c5b48dda9964" },
                { "es-AR", "b3feaf97c63dc4a55cbbfd401a32fdd62e725717645f16371293a23d6529c70e17bbd4ff155cc32be64180097e72107fbb71fe69c2ece74f7bf882e60482eae6" },
                { "es-CL", "a147408d8c78d9f90c73e87ff31daaa23ceb73b9f3e60a1ce0f100029e535bac4a31473c93967dcbf27f0b993bad1162ff052b5d5c4f3fff12dcd400199ad803" },
                { "es-ES", "3052183c9b471b748984d20ec623bbbf58cce7dcc03bdc5909228c3dbc372f37d0d9765230b1f4b149e098a13294675a3c72c1ada8a2efc3a35b44c7e020d2d9" },
                { "es-MX", "1d46bbd45f2d89b3c1a62f1604c4d8914101842d88b142a6322178230c66c6260d2a957240db6d02fdea1931830f3562e888260ce4fdb4a0d44443cc4ab51d27" },
                { "et", "cfc984adf11c01dbd2f4b8f123577c82d0b153410e2b4d81b2a04ce18966d6fa6395766e261c77df00e03a21e0a9f0f740d75888ed490582508435ccc382831e" },
                { "eu", "da636102cc20537f75a53a69927bdc5e5a4962596d87fd6b292df06a79dd8a656222c41e8f66ece13c3741257104d73aea7f005e41348bb397c7fef8714386f6" },
                { "fa", "93ee61114a74480acdf2d754b29980b54f749533a8964ba99830f9d149d504f66c210abfc7fdf7ad2200efd4a588f05e0b29dbbf98ed813dac4fa5f947082ced" },
                { "ff", "046d205a8cc9eee344fb0aa553536b3d0ebf7a932535c53b8d02af7ca28b52cc68030e72483d5d9c15788edf41d5ccc7e38f449729cac964b953effdb612d6be" },
                { "fi", "84184b807f56fab73f32acca81142695ee46c910978b60c35bb87a5490d533881f98091e477352a3df049f98ecf1a3477c30f3d05ebdfe5c2449eb56cb4babe4" },
                { "fr", "bfe1d16c0b8bdc53f0cb3fd3f747af61112fac9f113e05b252a6d6adfcbe3b4b87c036616afdac2a7ada9a805533c9b6e0be6354585c0dcadeb90fda4c1685ca" },
                { "fur", "e558efd48384f66c3ddecffec0dfd2ad1050c9d2506f7a2c6bf12c16c326bca7f2062e78b823c51876084d5181c603e303dfcd4c27e565538fbe77c609c46ef8" },
                { "fy-NL", "6f0f085162d0b1a26250f84672672fb965cec289a6f0867b559a8067a5625c15a28807dbb02c63bddccc8bc6aa6454bfedf65b6a64c9c7c822362a1f1035b483" },
                { "ga-IE", "9cb249c647255c5a6299c3b9979c3577e738afe92a21ee83dd34d436ffe471655c54fbddcc11cca19a1c635bcd348d6b7b6e5ebbc42d3b14224c685472661209" },
                { "gd", "3cd910c5434319bd2013fccdae9d0c463d816af78896a4bb6cb4de7e4f9b050bc61a7d4a2a0b93269c981fff1e5a3754fab9c4c3177cd9f4abd87c732c8b93d5" },
                { "gl", "094ceedae562c3b2c8d44b8c05ff77ba570c23aed48a32d30522e17639dada146c85651a3ddd4502ab1bc6517e8a7cdd778949c2b4744f17b4ea5e0799d1a848" },
                { "gn", "3a7d3ef536e7c8067fe2ddba5bc7f637b3817a9cd0b039ef2a57a13cafd29d69ee6464c6b3f3898960164a70271824d4ef87f392706044d24fe09abcb73a09e1" },
                { "gu-IN", "417e282743f4649fbe47a5d3219e070132d73067c0b83f1567c9f7fbdd3bd97090313b744968623f594c96b84a01b0bb0d4d30814888ea5cb47faf5f0d458a9e" },
                { "he", "33acbed8864e920cd96587ba6fb42262bc216c7dc5b0dd73f82fc531744af6afb5cebd11394bbd7597b76bd20c9dce0be734c3e8696c1565e8876cc7996f9f55" },
                { "hi-IN", "f7fa488270a0daeb78b2f2a46a6f6bc707ad25211c557940ad635a4e1d80914b92698decf1b49f1bc233ed1900acb1181271b2b53809e48e48e8abf7c2c64a2e" },
                { "hr", "7dbcbe37dd059cf78f75d35803a246c668cc8da9b649847c5b6a4a65c88266afc8af413e39837aaeafb9f90e14794076f7084f217bc66450c762df16921f1ac7" },
                { "hsb", "d007cc713454c15869b241baf1ee5615f2210995bad442136ebb1c4ecc4fb8da9372777ffe0c00db2f780d338d5da410c4028e724ad003a95d7a38d536a169c2" },
                { "hu", "e43f469ab912cf90d7bcce70470a3f06310c7778c2d670261a98926191265254f057b6d38e67a459746d37338fb25be0b6196515e146fcefb7e664a314a2049e" },
                { "hy-AM", "3ee8ef9847e62192157f16faf4126a972d4ce3d5bdaa00db934682677b20ac31ec3f2b187a0b72132e1d1c8680c97fbcbe57efda36d54d98bd701b1d9c18df5a" },
                { "ia", "cd3098404a6bb5e34e8972124740fc5641889a15bd32bb1c3af1573fed30feb605e6c96e84595c05c8822b750aacea22f7daf30cd4a96d2d9aeaca9f617cb5a5" },
                { "id", "d1f0865f319856d48dac1d1a5d7bc867ecd2e23df42e63f43294d884a2be35dc31fed0e3c5cd4534804ba8153fbfbb3a8d6f7841b15023e7a65c4f77b176a06e" },
                { "is", "29586dcfcd928b5da5cb0076dcf7cfe42ba0a7e2f3d7c2a234c75219a283f65ea7dc5e87034d02b54d3ed04d83abe8b9a82312570f8623f4b01f2db76e758731" },
                { "it", "b70c4ee7ca0db7ffbba1e9e1497605d530c9ac799f486c29b03eea7c86f31d002bd789fff27baa6304fe77af9015cc9c3f7fe67c1ca84e0db5d6c31946e2c1ed" },
                { "ja", "e5715b71ff8892be025507e7ba545d30b1755e5898a4f1d4015577cae71c4915618c682ad8417355eff18861dc16129f567b73d4b099cec86d4e446fe4e8baa4" },
                { "ka", "7d21d4fa18181b44aa89199ea6d76df6d2e9a80d96bf093ba4cc7b48f4123f0ae8a78e8a63c534ff117354124dcc13843904abf2f29500ac252c6292a13a33af" },
                { "kab", "9b0c3ac6eb533e4c53c9292ba911924c03680f423e855fa9f12c075efc5692ceba6b2460ab2f845f0b7dc9b01a55c7073d721ab633d34cab461a72bfb9ccd1a0" },
                { "kk", "be651bce4564cbbbcefc0989d685cf0fef7cea29fdc1a5c3611e115e0535c64b62670837c343760b02090a2c3257f309aa157ecf4c3b9431fc25ed89ca714ce0" },
                { "km", "e1ea0865d31bfab48ad624f191a61a106df39cfb064e26ab6c55ebca9a9f4b3b43f06bdcdd5ab997a1acee3877cd09003bb8e6cb0ff9b3aeb881c19ec106b1da" },
                { "kn", "44b04e1c7764145bd2c7f16550566171fecc01ea7ee6ac310c0b5ed32566adbdddc136ca4f9b0eccba74230769ecfc20fde80b735b8eba110eae812f82d3e2cf" },
                { "ko", "d849e28cbc91d2c96775fe0e5cba8e11cc6c9d7697608277b84322630ed5678504e3eada45f11a45d446d78e5ef09c6c1fc677eb198a9d768f7aeadf8352b7a2" },
                { "lij", "dea2d9daa8df1d193997e72d22092c8f9562c23f19265f45a599e78fc3c1e93ac1da2a10d813f28eaa013080449d403cc60a548b02682844debc387c28749d3e" },
                { "lt", "8a2210e3b324beb2662afb7319a6ce2e69e786adb0facfd2cf0b68a6609ab6f508c369ee081bb406f505f56446175ffc7d8a123f61ca03a5f2dbfedc1b20d370" },
                { "lv", "b711903ffcc9b3f6c59486c9043504ab604ec49b923621c3223fe6470fcbce1bb15a06a5acd42aaf6d3fd6eb499135a4e7584f7951ddc462f49f5f42e5ec28bd" },
                { "mk", "c9e0442bb5bba117938ba608a7e3f9ef9c8fed2e5a55babe75de15cfe7303b46a1b0d28eba1036e8519991c11b12c1700133805cc124a51581fc2085b2bb59fc" },
                { "mr", "42ce20c564e3392e2d0ec0598918bffc3260b249d934875ba7fa607e29df4cc5cbf4c777d76a800434482b4faba70440b548818f3147578479353ae2befff3da" },
                { "ms", "4edd3217c4d368d52e3ce8b6a4978d2d9f8be6fd00f24e91824f0351d53303aeca4a2e7b68bff4dbcfebf7a63ffee876c05c689df13ab51206a074df0cc6a691" },
                { "my", "12c8c54ced052a7e797dc95267802aac8124570e2fe3b2ef770aa2d7d7783c4068f3dc25b41526c8876aab3d46c3ea3e62721672f0d416ad92a4dd976e17753a" },
                { "nb-NO", "cc64e5a2e54554da6df09dd2e5a4a46a1cae566edcf7008b02ef2561f973af37a614455f2d3374405c7232964f59a94193fc33e58327fab28eecabbb2b256165" },
                { "ne-NP", "8c0e500350cc8c3e5dba684f923fbafff575e831d1a51333663c3f27b0d84e7bf63635b5e91c271fe02066e2124383167c29d6e313ece794e4e15e2807bac9ac" },
                { "nl", "7353b91580c96d87f2994b4415786eca84777878b9d0c4a9f8e646d7eead17f14e525cfa840cff28f13c78718fb17a7c99384f2df9620e6539067d2912c01f98" },
                { "nn-NO", "491aa1d1e3e8969a06a1bb4e3c65b2ad96d7b6cc973b16043aeab9a8813a1d86333a3cce532c810abaa12dfb2dcf165fce071ba54e3998814fbb1cb8c2c662db" },
                { "oc", "5bcfcdd8703e41c5a8ead0d7eb2c1d1b19bc767dd3011f17eb54de6021c91f364b2ca21a6d17e38dc1686d99177ea24e892a1f378156b9115493d0585fa13dbd" },
                { "pa-IN", "93348de0ba862dbb910f5b0d504a416364586664fdc1cb213ceca8870fc284b295649ed63ea5ba086dcd4c2755355f9d5820d148d15e5b729cc71e224e2daeea" },
                { "pl", "d82e35826cec924a42a09b52d5ccd30d217fcc28b57e5d8e75faa171a587dba0b1176853c1c2003f6515b35117c58e460c3caa5d94f7c264f2703ca38fab3777" },
                { "pt-BR", "1f4ab8758930f0673936a415047182d7d62e58e4950e02bc6722ce7618596569adea89ccdfaf8c2ac77726cc4a25602b0790cfc9b5d4b602ede57f0eb311b890" },
                { "pt-PT", "45b5243a327597695128806aed5830ba470635f6a30258a02aaf248b191dfb1ebb56fa0d3de7245d640facd998a8d1dcdf9b4c03259ea04bd0d7f18d8be0b6d8" },
                { "rm", "3bc7d213d4f2ec71c433b568e1755d4d0223bf5b040d0d46e18ab5ec1336fa88ba4699b2e9e43fa0efc424cca17af0822ba027e87328f8d106747ac974b8cbfd" },
                { "ro", "471439b5aabd78234bd90bc584faffaf62122f8b655f00c838a3a6421a34e9c6901dbd5aa9af0beb56d7f0ffb166d63c9a0b60cc349b80f3cc52108d613adee7" },
                { "ru", "f85525c535262edc37e1519f829e800c24216267abe0de723d1b16125ce09136da94498d288ceae9e9bae184a5a59ae01732f788e8e354ea90e55d4e54e26ce2" },
                { "sc", "0d2dff4ae44fa2dcde1cbd69c1068cc07f11c62c5dee4cf6040e477f878b351c9ee26dc65e173b017049ecf6c2865e7b84fa4597ed61f42ff39a1c4bf4a0bd77" },
                { "sco", "ba9278d7cddce5c6993518114dbc1fd73ec483228d53f8e7863eced5f79876c7d1ebf64d40ec64f642f64571c115ac67ffae1edf5c1b24060a246dca2d37328d" },
                { "si", "bb5d434644bf8ed0ebfee0c3013209cbcf6da1aa71c382d8a0bed181841a0fff97cefe44999b4ab7ccd11f85d57a71300ba393b9a0fc4039b9c6d372a44622f9" },
                { "sk", "94759c1ad5620cbd539592f201c598ab4775ff0e243af0a0e0772f1fbd2ff10b1ada267f55f883aeb92f58359b50718a3b39cb8de13f6573d33944c2563e20d3" },
                { "sl", "ca55219df2a87022d9bf1f00b90446286820fbafa2b73b5e93808cc2a12132dba94b9352a69381d9c6ec18f8e39b38663609ddacef03be3b4506ae34cbb038d1" },
                { "son", "f850222080043e0644c3fe6643a6540149a1d089c0c93fccf8c3bdd1d442ee456f6e91af537f796bfc021baf4bca9bb6f4da1197637a82a54d7c8abc98fc5cf1" },
                { "sq", "e08060e3b3cb701ae84713fceda31f996ab2d1249911e45c35af5190a9b484613b428c4def630351b27339f26f371a8106b68e01ca3f7fbc12b8d836107e9a8e" },
                { "sr", "7e4810e0ae07eda2c72372f2afdb7d70c770554acc6c8b48d51f9898bc9756ea49f284f9750296f82265f868ee5f85e45bcc183cb62b8916563ffb6be2e0ffee" },
                { "sv-SE", "e131375813989dca025d1c7a923afcb1aa44e9141fed66a5f3acff1ac77f5ad865484ec6940ceb3a5bc5f11c0623a0a93b8e2d7ac8b76e49bf7fcdefa30c9cfa" },
                { "szl", "98d18a58c9566805f4cb1a88df836bdd7306eb3a5540163dcbafd3a596d8e4cb69a5d80e8c7772f762d2e4e6527d1cbcad6436df61961831bd6137f61002d797" },
                { "ta", "a7eae8d0ffc5006ef1a15318a3c56765596f18ad757edb9f202a7f62f45137c0e5557b4dc2b9931bd6ca93961be6f259a89bdeee3f7e132eb3c5add809340ed0" },
                { "te", "e27c3edc987a492337534f41ffd399ba41e06d1987f0f1eb99bc782968ac8f42b3acc65847ff45b6dbafdf086192e83a89e8a3086cfeccbf1633d557f83bf50c" },
                { "th", "306c616f676d9f4c8031c3c46e6d939feffe7535ab1454bd78f3e0f4f029814159c83698d784eafdcc8faadd5042d8cb1a13640c51319fa464e5524004f09d08" },
                { "tl", "9e8ccbf94128711bb19946955aa5899db9b871642233b90603b918a94dd1e02ce7de988be94669ba4b9bf5ba3a9053932b101c3bbc5549c8be03fafe252d36e0" },
                { "tr", "6a2e6f88c3dc1f9837482570071bde29e83ae04f5abcc0e3a24acce9984f77d6a38ec5f66655550c645e8fcb3fccdf9e7e8c89241813c58f08e1a00ae638d8f8" },
                { "trs", "558e14e1637f871630cd19f39e8b59dbf8370c3707ac27b0fbfa4a8d21e98abe0df2f60d0446a67237ebc4de581314f64731c81f4fb7bbeef2463e3879cf0941" },
                { "uk", "d50429e8ad20547ccec318aea09aa70df5f7c1b136fb00adc31d409d82fc5dc955450a75d6fd5971b6cf09c3f9708c70ce8d74f28c490a3eaa7dd1d10b99529d" },
                { "ur", "74af20e521af79b5081e8a596b9846c7fd1e4a72913f9823c4a6c11e376879c44980c8cce0f28ec4d26a3d8214920c682a3374f3d5fd37012837ccd9eab6f3e0" },
                { "uz", "ebe7e823295b4408f378d9cb709787bb725d01a4395a86d176d3ddfda57aa86f62e28b33290cecae3504d452d05e4deb4461bc2ef19ec0b233f5562276d2ffe7" },
                { "vi", "3f6a90c16f4523eba37ce0f48764bf98aba4494ab772d4fc98aebf8ed71353ff53f5185eccf70d8a06630eae81aa8f53eea280ac93e2c1e21c0f31268fd318b4" },
                { "xh", "fe89a73002cffb4956156cce2d9fbc09d60bf18395757143adfe881aa715c6626bbb19646db9abb14ea8801acd2e9a7bf74a9d490f4bee985bc687e85977b014" },
                { "zh-CN", "2e3b3f9a4e68591bd78bc8b2fef13f0f5764c00103ea1eaf304490b32d9f354ad7237c5c7c15105e8fe46fa0269dab6ba8dbce0afa525cff59fab8d7cdd99f5c" },
                { "zh-TW", "1638c1b20ede42c761de960424f685f016c1e60c59f0941c4132cddc9b227744463167e1749fa7b84135d98d7609683462d86b5a0358473c98066973ffea996e" }
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
