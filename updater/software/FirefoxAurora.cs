/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string currentVersion = "152.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/152.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "15aa0f1fc2687a8e579806ef5ca15580731d8ca239dfa720c3bf649c3b051491bc97ea6b1ca2586b76190f853f176d1a4bed40eab21be7c009c980b1e3333c46" },
                { "af", "7fe1d675250239df5d2715711e2f0a78deb9fb4ebe1bb468e0e15ad67d3bb36acf285c160e6c007ab45b0e91dcc1b26dddb8e68f8461f00ab2ac744bdda1e57f" },
                { "an", "27f3a79f1914b6f4a1c8c04d6e7d59dddb4607768828e4521c85583bb34cfccfa09f3fd761492753b9a23ed9ba3ef3393274ec16554e1b3783148348967b62b6" },
                { "ar", "ae578da96442177b0c734acfaade7cb118db10b1a1f84ed26340ec39d96ebd34495c1a3c326b3ab571892640825fd4619f38b1949a78f59bd124fa5d54138a4f" },
                { "ast", "9be82eb380444bd76230dadc142a26ebb1e1d9d50da1c495bd6bfe58fc7e4bed3d0bbbafa2e560f5732b35f936c42966ae13aa454ee88afed9912999ef301564" },
                { "az", "9a8bccf2fda4cde51b6efc02b7c3cd24de6cb159793eca598d10275390c2d71e3d45719d8dc254e5d885f89fb6a5c1e9a2e4c2ac086ceaa616f97a4373c2532f" },
                { "be", "102f927ec2bd3f860f83edb33feee8afbc821c4fcb435541e73d794c4f8b910e7400b36ddbf1f44022ed858e85623cc31e8c46a4d5f2bbacbfede0023d71e215" },
                { "bg", "e58f11854298481792f55c3e53b773a8f6dd31cb397d0cd99512b43e2f409ddeaae87be05eaa0292d0845c49e2d070b645ed9a92d6127b285b6ead9ca84faf67" },
                { "bn", "94f81926393d02ac25a31597d9eb816716ca351033fe910e9a07b0636bf196bcd1ab4f6562608c052b56654ba90e884b2cea41c1280ff840cfb6789c224369df" },
                { "br", "66223a26117d7738a9e1718de4aa2fba06d56ad77441f270ef4442805e4236ce39b11f08f54f1bd65f4caa10410ba605356aa615985c6bc0aeb96c187af85c0f" },
                { "bs", "a87d7c0b142dc8bf48f98fbba6cfc03048922eb77ca33b4bf505c217f1e8d3ebff272e960f6d8cce797585191126e45c72beba8298780b45b8bcd2a361c42f42" },
                { "ca", "fa7d6fa904b8ec8c4dc4b6515968b7c88378941700cc66d62ff3f367b0d42422c1a5ddbc5fefa352cd1e4f88a98889eb29108eb166c4ee9947c3f011067b411f" },
                { "cak", "bc9f81cd62ebbeac2d87b6128d132070f8dbf86b44a11fb0658aa746dc9981fcd7f5056d3af3a3ea98afa56ffe75d39cae735ee2e2ca42b4dca0574d0ae55aa5" },
                { "cs", "51c96e140dcfce45467b3794b5e9d2e12079fa4edba1459ea6d57d31d9ae70740d0d1fc4309d37179fec2c0d601cce020d5b877f741b651aedb6bc204a9f226e" },
                { "cy", "1ba609d6635cb3bbd9372f710d71cdaa383a8f1b019e135a0365d9e84c4735a97c5fa5de132080266d02cbe03b969cd039719a1a48968b1544025c18264f80ec" },
                { "da", "2d793b0018dc3771051be7deadc4867aaadc607aafacd0a2edc63dc8910b87c695a307212f7f30c31949b878f8474577b849288d6d2848c07fb5ee3305284a98" },
                { "de", "30fdb8b68302a9723c43c0559d450061b397d4c9cf26fcc459b096db485ab8715591f01ac500926df2a78fdc12ee149b879d40f7ed13ecc852b8c74206f46407" },
                { "dsb", "ee67043445fa5874367a3923ac42696186c12be25c7409a87034bc16a661f1d34c9350376f6bd3dac8f4b39e5a8d05b77f56bc38fac75b7a0cd264a2a943fd31" },
                { "el", "7407cfb4e18c076047a9bc19b7c2d521052d248129d4b7c5765d3b10a0d03d30b97d44620db92c12de6620eb446953b5eb9c18b045127c6f36fa9842681fcc01" },
                { "en-CA", "53f107d0e0b15d7bdaab85a1545ce5830cb8f58ed50e3350f9a301c2804e0251aaba12a1613ca4e04aea6973bfaa658b1d12b22a8ee5d43a59bdefe13c1fe986" },
                { "en-GB", "a7d3a911b046e8773ddaec88b72454b479377e09d6a81f754e3c1afe14207dae42405e5f67a835c0239e246381d5f4f42b8fea9cb9d3868e1ccf97d3bae5478b" },
                { "en-US", "65af1eb1944821feb88bd0f537d1eb16157249e05a98c594f932a6bc49c9ce97b90e06bd39e3d7d7645ca4030d207fdeaef913341cbab9205ebdafb3153ab982" },
                { "eo", "6715311670eecb9aa49a065b073399526bfc3ef6eca499ea12a58d08dbbf68832cd1c493aefb8cc7a5c1f7e582fef649b63e362f82230bdb8247eb725578eaf1" },
                { "es-AR", "6d80f8d0f421732507ad84525162eb3c75adba9f640fb5e6020e138f00cc59eca5e9923828dfd1705e06fe27a0e284289deb1f667ed4a760285d66ed953adccd" },
                { "es-CL", "defca66761f18061ee343f563181966ae76f8bf393865d21f1c558d23a2a8f3420f66ade1886269d0bffe2c8621cf1d0e7c66da1a837aa15fe8d8b79729e6405" },
                { "es-ES", "9e8fcdf6dfe31953b3b1700e79faa08c1d8ec401ddd7183bf950da1562847b351829acb46bfad78660db0575387fc005cbb1e5b38a0014c0adaf1087e885b687" },
                { "es-MX", "066abcb4eff71dc6904de624de7e43dc5b4bcfec5c375ccf911a282e1852b3f59a5bc82b0e565555dc063e1bd526ab5286cd562cb2e42f89557e6cb3a6e5b94b" },
                { "et", "8e949e95b80fa047fb44cb1b96a50f9d98ad8256b522e633dc66da2f5029e8954a5c173766f1eca3ed8597c450bd325c189e09a0c04421d6cdf713c3a381bff3" },
                { "eu", "130c306d6e1a9eeb840bd77afc7281a24b66f32b0c7d21f5c43176e6a39f8c187d3b956584734325cc00969bcdb91c1f283610380fce2a852b4e228d71d0ebba" },
                { "fa", "dd3a7fba2fb47c1742b6bec22c5698048213ba95a268c59f82216f80ac2208818d906a1bcb748d59636caa85a85f5b4ae1998d02cceca0d9e5bc62b8bfa9df1f" },
                { "ff", "e378c5428bcdd98e12db96087d5bea78c795ff9d2c47008789ac3bc45b1f65764334773a074a164fe049293481592411effc36c38612c4e5b122de1bf87b8227" },
                { "fi", "177342f527147026ae67098c0bcdba7d989e556d7f7b330b065bb664bd1ae627101ca6b69dd3b69faf41ad92a2b11fc1aad4a86f611453e1970ccd7a7ddd18d1" },
                { "fr", "d0f3abfea9717b42ad5489e6271ae3c1f6d7af550266bbe8382e080716b255c51c09b5b5d1f7f2c03f1241d7d1adfe62cad2549408f11264d2386a663e5fd3b0" },
                { "fur", "c4b057fc16f39bf6572aa1c86dc133f09bc5fc2081ca946779500913a2cda0e7e3a134ba0f12fb7ecdd7492b1f2fb113a964c9d6cbf0d0120c7dfae84a94ed12" },
                { "fy-NL", "03811042fcaecf49d6a6978a652e65cbf5cc0637e12b8943c2a6e21a9026c90618f3ad65d208cbcfdaf975a03615c13ea964d84dda532e4224abc6c29bd59d62" },
                { "ga-IE", "004ee42153b6e78ba0a691697ccc7d11f6a756421b6be01466b169e1c7c2d459afa34570dca2fc7c69e24449461ac1cc8a3a4530c5e937dc8451137cb4cbcfae" },
                { "gd", "733311c5ef296709e1ece001738cbab92ef0c6a3b7f2eb390117aae585ec01764051ea80210dab14db9d223e3f36faad5fa274beadfbcce39d0f0aae7f4512de" },
                { "gl", "3cf2a69b5f84f55ed161bdd126df753e0f005cd42d0b12f45c9d3fa95eafd0a69d494bf3053381baf7e39cc34fae42c95696a4cd576bb5cda00e3edb05068f75" },
                { "gn", "00235f416dd6eeef7ce155b1def3895c7011a64ed656ac85b3410ff6433d136f2914399d86b424b3dbc04d5fd79c466b6285e3ab41574906b34a84376d6f96f4" },
                { "gu-IN", "0cd400839a84b9afc1ec2f02c0d6bf33f8b28d244f9b2ba74cb88e89d9e1c6ac1bc1eb4f9e981242f74d07c278b4ea33388bc24d0f147a522d76a03d749482d5" },
                { "he", "08b910ced5d87527f05e6bed17e56d9a1671a897e4bc0347eb53cfb886219d6527dd92d5170cdca902556a927daa6c2532a4c4bb21ccb8741359df186cf62608" },
                { "hi-IN", "fbd7adf0b60a99a603322b1812156a24d720f487c5f52fbd96c5f69b3791ba3084a403f94c1409e806296d13e32c2081b979abae115f08b3fbcb895139160df6" },
                { "hr", "d4c4a1964e195a47b90cc9a7a59854fadd1dd477be0564e09af04b4fd1ee41e5eb9c7e9e560db540925bbaa17ed800bca7ff8ceecd7c96dbd6cc157373f152fe" },
                { "hsb", "f0e3f0a9bb955eefdbeebb5fa2bdbee5e64e57794fea5186cbdb2c9d4e300998b5bee2abfad92afb78585b39d1f75c029d23c9fb2e82d1ee71bd38909f962fc0" },
                { "hu", "aff5d053f0e9af702035b1cbadd5d8e0e3521f78666f355cce4b8c97bb7338ca8a8f50c88f9503eea9db7a81152742d2bc651c57fa8c58278c53133878e3c2ee" },
                { "hy-AM", "4bda72e9eae50bc40bc6a93071f83b2fbf54ac7f1711bae45637b01429c7c668425121020a9fa36bb1acd4b9f021b3400904cb0a2729f8d326b95eb6792b9593" },
                { "ia", "113a78378cb9145aec07898f876b50cade59a0a2927deb8d811acd4aca962173a9b83279464d5768fbefcd0d65ab8b90595161dfb99b120d04d43012d426bcd1" },
                { "id", "225ba3bf248453f123d8196e73019ba025383f79850c353e089bd82a850716413a733bc4d552ddd6c0002c513f09432da0601d10c847bf722144901184bb2e5c" },
                { "is", "459664e93a027c9de60cdb2ca99fb77168f14ef0b608331d4763ca25dbfe615178df7a09b7abb0c9c0c589b8ed500a2f8cd3bf6127949bba8f0b1ef3b4bb7ec7" },
                { "it", "0c205028604f6c2d0ed1777f96bf07f53d9dc5c9ceb97ef2f51392e07ad8472747105a88d0762eb1cc508da7abedbd613074b2c0cb70efb466eb95601ab70e0d" },
                { "ja", "9b1c6b8759dfc9d80c86134f11e83c97631fd6b1ef18de495a9d7487e7d2f46d517c187777615565a8047afb3de3fd94ba01be54d4a379a92e7bc42762f1d665" },
                { "ka", "f161662721a93482a0c2f046b155000a1105156fcc64b78f1a31cfb2c7cd381ab135f81700c49bbaf083a3b846f66a91e6dce4783bafb1afb5f36f9e0d953147" },
                { "kab", "109ef1ad9d42ee9fc2f0e152a78ecd9bfe66b7517b8bebb5c686e5a4f7ba4670b4814de37ef8f0fde1ab0ee7ecf4a1aa9da37814f3c77d6c56fff26ddc16b14b" },
                { "kk", "35d4ba95e98e289667947aa926029131409cdbfbc63d76387bf28bd6ad124bccc5bb7cf182d2316d49a27647044786da6bba0fd2de224d898bf845e234bde96d" },
                { "km", "3aefd9a0de1ce52cf980a74aa870d235588930ba775309b6fa3a821e5b14bd2d8410ebcf87f0195f651da6e0309d7d31909fe662564551185feab57b0fd76618" },
                { "kn", "81b192a3c78093936cb0267732ccf320984dd86aa465599995370b234ce8cd599f9b8a20481e40949cc0f9971758d74904b4c19898d4b8984120cb3b12a97f8f" },
                { "ko", "980a9f716ea765a1862a7683b4ceb44a0bed71c46dc2de51e39660a03fb8b12505cf07bc4398ad3349c489b5dfe2e04a6cb755d39d8d6e909ef398fffb244b0d" },
                { "lij", "fb6dbce204dd3a3b2174bc388b08897c5fbc06d22b54dbd8d0070f339cd8e66848f39140b174a05c40e42ed74465e91668d6ea6ffd510d009cc10788b2106ea1" },
                { "lt", "c0fc6d2be817acba0dae0c0f23d82ef10b2d03599470dea365a780290d1a1053ee5b2c79752f431839c4034dedd34c09d7252d3cdf3b5afdc30bf13348babfd7" },
                { "lv", "f49cf24c9375b9bf87d912da4db8b5b295c4535b28d51734e3bcaedd7011cc36f2049cf9aabdcd6cdf26ec00874e4556da35bcbc3783ffc3588596fcaaf8c40e" },
                { "mk", "82089686e14f2f0ac15418e53e6ef4584094da66b7e079ed08399b4bb57a855c8629c2a2b4b69e9b09b94fcd600f38abc66b953a45dd0e8fb6c9b735c0e93cf4" },
                { "mr", "0abe37cd9b60273a2176cfe311ce7737e1791a4b68a91fbbd8f2fa8af49e1ede2cf1cae1d769fcc8b8293a33f6bd4a72ae730dc4de7fe9d83e34cc28ee476ede" },
                { "ms", "791b6eaf084636e6203108d57c959ce948c25479c2e48a9139c4de8900e096675f95003c7f29e0e0399bc3d75824b8c5b74fdfe932285764145fb2d70055b25a" },
                { "my", "ac3d7d129fda544befc5e595839316c810e5b77c2cee7d19fa5ab29e3f405f7baa2fdb9291d5392d49792b99af5fa197d792d4bb4e070209c0fae891e3880e06" },
                { "nb-NO", "529e63338d7ddfb2c50b4b6f5a3c991b45b5a53cd7630d3cdf4c508ef5cc0e79a64e1e0f5ea0c34d754ab4750d7923890fcce9bdd14aebd09fce40febff62afd" },
                { "ne-NP", "762774fa6130134a404b2622ec0c67b8950185af46bfc3040ac64666df2ccb54fb00fa4839d8adf5e7bee94fdf749e93b80cb7deb54b0bab2f13651447a7f460" },
                { "nl", "6909e2dddf7c04da0daf384845789711fcab9ebdb6d3f65efa362dc3e9aba730a2fdd5e9d08ba5ca7f841d2f2552da734870bac2978b583a3dbadb694760aa06" },
                { "nn-NO", "53630af5b3a1691a13ebc3b63c535c14e6f62818e68c476ad6944f2a8484ba2146a6837f59ca6e3ec3f03b23a13579decfae12a745c80ef36270a2dd61437668" },
                { "oc", "9d8e449fd5a80e5cdfcbc60459570497f6cfa939d13a12804fd46153c8d555f0743a38317b50e7981ab4b781c2970a155d4b87c576a3a8a3548c516b5e714524" },
                { "pa-IN", "2864352975a0f0d272a6b46dda218eb12e8538df0d49e6c34cf2141f51245469159baca92f8c6b53d486835fe4aef88b50e4ee00a174a52369102dee78e121fc" },
                { "pl", "47f1e12bd4b86c8ea4bde14a959bae44cb8dedc5dbc8ae31ee3ca7dc9e7d650bfc2b853ac7d548f372a78a066ef4bd9c13b86356f82aee6eab11f10c723ebc40" },
                { "pt-BR", "4739960b977a608453f7451c8db28f132e33b45d52a4d05d9dc7a30e41de913b26230661995132243766585a674bc6ab56007d7c9a26fccec37f06d181b64043" },
                { "pt-PT", "8b6e16567cb2db2a3c54c27bd114af8c5a0a870cfef4b339ff3f4d743498f1dd0a2b47fe8d570da2add39498557066ca1a290017e3991118b5a6db91cc861423" },
                { "rm", "3c2ec4de65c7b5ed8d616a26c285edfcdee805ae3211fb98562218b0724f7f7a38e80008919910dbbef844e530c7450690caaab9dff6cc4c10d1799732c140ff" },
                { "ro", "51caf64a4965e8c73d95b7ddcfb7668f0f8cb1b6a2802c06db9df96a2145619ba33e0873df56f0c916c6b3714106bcdbde125b8c389485320d565cdc3f0fd94e" },
                { "ru", "bc92f0edef31caa47abbf78b44ea57d83ae3bb25c7148504b71fab00d80838e21f946726ab7632a9af096458b01ff379a0d917dcda00bd8dc3f42cacfcba1309" },
                { "sat", "8bb6762982a71a8114cd8133d84a1633647f5969fa5542fa7e5da729de35e01981e625d1e843a141c44d542b12ba0cee13f2a0d044bca2334dfcdd1567175c4c" },
                { "sc", "9fd334214369360ef46b4bd0ad3dffe01adcbf7c0cad44a62cd0d1d77e39f26de292c60de86947330101c362bc479f826eae532ab09ed1213e53b19572cd4cf5" },
                { "sco", "f1090ae41448715929d8105d355d22085ac57047807e27f990b9350dc5f5bcf0c3b6ebda9ce2ab4cb6620499524081c8fd4a0894840399a1c545005a6d425e5c" },
                { "si", "96bd092c9ff4fbca2afc30875902925d0ec4e9899c5d53f2e0f0cb3be7812505dcaece401f1812bf939f03ebccf0bc50975e417c0368be0009e5db86fb3eedad" },
                { "sk", "6c9803562a284417ff89681fd250e91855e9c6fe6b2712766dc7ba7fab0e35c391fb6e94d5e15c44fec3c2d5a5d17efb2c7482b2a3d32686e8afafdaeb73adec" },
                { "skr", "cdff69e10a029fb5d1a4773d21af122ac56b1fca7b92d41c731d39e836512559c5e54a4a5b4f7a0263aaceaa090f1e9140c0724ae15972ae24298bc58c31c4eb" },
                { "sl", "f40a8ddc5493e2cea89b4446b8141a75b89480d41e9a2a25684b6d8e8ecd4916195918af3676e18e4705b012320c6bc45db659dd3bcd9cf4b9b32aa7599f68f7" },
                { "son", "5020cef1e62add88f0eaf373619814896b09dac55cdc0d0bf99db3ec0b3d7fdbf20fe493496676155fb01c87a008d61d6d5c8f150424f088c8efaeb5ef088ae7" },
                { "sq", "3bb90647353ad50bfa7ca44e35f13c03371c3e2f2475d42f67e3fbb883d126a2b95e10d85a3c6a560b7ae412dbf003edd21c2c971831d0ebb17736b0129bc987" },
                { "sr", "03b31400f05814b4c5f01f3afcf3285bcfd9901844f37961af1c199c0aa55a7e52f9ba5a00d1ea5bc157842d6585fed6128f6f376d01d09d6db57a5e2c6cafbc" },
                { "sv-SE", "2b52739fe760dadc870f41dafd79c1d145a5e180a635c179667154e4b2bcb9aaf267ba461d354e2df1248bd00c1215fb06bfa0fa3d78b52c7476efd8909a98be" },
                { "szl", "0890836845eb5f17b5def08b5cc9052cbeb2a3044c352fe1df4bea435b0501130f75b44f4a6ec41a2f98b7b1fcfe1c3d00510d447745896ba2b06a50085fe5dc" },
                { "ta", "fd8f4483a02e71ffe9ff1f6b7d65e2b2bf41341e59c54fa65445049e027dabcbe3ce7274fe102d14ab74dc240905a2dde6b8766a12d92725540fab78f118c15e" },
                { "te", "c3939d6c8c63add664298c6d13488aff16fb286815fb31e7d88fa91bab7aa6b70c8b74821affa0c6ad9fe2eb3b5e897a54f05ef3263ecff1a74d124106265fe3" },
                { "tg", "99550bbf4e6eb6c389ba2d5f162a7084d720a4a628ec237f597e593088f93e44ed0f97a3b58a24cb740b3752837fe39337258d552d9523f5643715fc9678b514" },
                { "th", "b8360f6800b610f6842f7076941232fa1856e32506cbca79222c378b8a10bc5c8a1520d800570ed330348750bef6aa7945a9976104f7f89c26d366f9529c0675" },
                { "tl", "f47e410f017d1217239528059df0e00c8765fa2252c69677b723b99a0a243e3f66533e739418f2fd373629be9d215bee6dcba4fa2ec0d7901a23c9b08f0a70ca" },
                { "tr", "4727ff0f5a06e48946880061c2e2741395f993160532d43182e994783aca437440c2ff1d4e1f23e60c35fdc7bcd2c23b6b5a44ae09b0aa7aa7ec1199d7926579" },
                { "trs", "d3a4fadd63d726b01f9176cd5b88a9e14ed3b4805cc097a821651ff37448fae6a754438db9e6ca93b66db0b7bca53ab215869d95fc689b6ce90e7443a6c7cb8a" },
                { "uk", "6f924198c623589ef4305e3825a9fb30ba082faf93b3ba5da248099108681b018253abb930fa2cab5b73fa01867dff28b30cc1d60cfcba380862f3afe346ebad" },
                { "ur", "2e394cfcb8e5338907741699769d2b69c7e9f544a6761793fdd3a20cf289637dfe7e1e1f78b5878f08db55b5abb22aec6cc1b51ade770dc7c59b87e61e3742b1" },
                { "uz", "39dedb373825693c64368f2aa859428275c16911bece3e8c897a1b8828ac2fa70c938b099ebca14d5f1b4279762f0c5bbfe69c6464b8c9fdcd4c4448d8354a95" },
                { "vi", "aad7ba84bb31c707576ca88de43339992621643ae9dd07605d7653e134dc4ee72e94bd51609de7a5dc09f821ed684250c04f684d48fe5f52b651cfec90fd6b31" },
                { "xh", "6b01cbfe72cecedc19c35b260147d369ea41eb0d3388c6f4cce0bea73cfedd2b7cac41c019d52e9a9e3505dcc24e0fcc16c6686570c5d13fecc7b1ee8b8708e2" },
                { "zh-CN", "7512fa9453481d18e9e35f6bf9b6381f5bddfc84fc466fb9e7372722632adce558e0cb72937b19cc754a77bc0c141e19faee783d3610bd6873c081cff49916e1" },
                { "zh-TW", "3c51f647b26f3022ef86d238ed17b9ca52643a01aa38850fa352c6acb073be072e67c7b8f3bc578c28fb6d85a409b23cb0b92aa06623470b035eafb465fbcdf3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/152.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3a07a61a5cc5a40516f7df6acc9f4e5fd9bb6755f2289f5e7577c2dc1301acbb644481e330241a03fa5e63da64e98bda57200efd1bac7dfbcf4532a09453a42f" },
                { "af", "eb090da2182fb80cf62cbf72000cb3f90124013c4e3072673b63e1d62109c620f7d54c7e9d6ef09a881243c3f1bc501500edc32b0cca0d9a33b84af9a05febc1" },
                { "an", "c7b479d5941be9004a338577b5cf8c6e59df65e98f6d27bafc63f41bb8a827c8ca529ee43a066ac310f0302097917f7718467c83c9560cc1e0f23afcf514dad7" },
                { "ar", "93ff9366f82ae0b436fd2f94299bcc23489dab2eca6524ac7d82eb367e1e4bc6ac3a96fc406ea5d1678eea9df89919b200b3b411afec55e19c72c79992168376" },
                { "ast", "81f1530687f51f37f5ba9ae18257db48b12671b63c4493820d90cd6682c546bcff7625252af7ce352b48bbec8842834a6321162302363a0c2367d4eb83306a81" },
                { "az", "89f07cd3d0447fdc20c4bfb54adc0ac11f1ddfef8a557a6240868152b6c3d2973ea11fdcebfda1cf5c1697afa374c95f07dabbb32fa77d7b0b6379d8203ddf5e" },
                { "be", "eba72db666098c45bee3f01cdb33da98d972b3900459a0e828ebcb89541665d2a4567e6fd9af099f47845e6904ae82b9e0f8362b378b83a0200c2b539a6121da" },
                { "bg", "2a9cf437d4248ab2321e39568b757c8ddb931b7c31d86c0f00bf90283bdfa95d2b4c0cb449ced140b871366843c7405b8605dd30f1cebe17516b0899e4398584" },
                { "bn", "9c160b0dc6b1df185ac02c92cd484bd7f85bc217a3e5ca85a9b2bb2285f66a2775ec254ef34e7a57ab1858669b4fde3cb6d0d471b0a98e9457593648d6143cb7" },
                { "br", "3ea8e3e670c9a1a711f89426db3c1ce3805c9c5d501d8d091dcea2a0840b6aef89bdecb57530fe0bd4820050cb36bb5194cc58cb8e1de3be1bccec3b95faa24f" },
                { "bs", "3cd90570eff2642e9548deb465ff581582ba926282da57b574cb5479caa0968bcee4a789273c2680c3a6190fdbfa1c46f313ce7473d077fb5516b8b0a6feeac2" },
                { "ca", "ab494ad8f03ddd3125121af7a818794593b51f4eebb2aae29a7ae1a3f13d89eeed9548ea9e99fc32beba716642589723fd4c69232d27fc3fcc56f87718909662" },
                { "cak", "662663da260cd130b90a70902d7b2aea79f572d80b96aab15b1f804a3ae2feda2b46e9af83fc99731b35370f17b1d1dff10010fd4b4ac21f1a752c89275e418f" },
                { "cs", "203bad979acf719b0025cac78cb3f84f3d908bfbce88996ef662db6180e40d58757b19c8fd7fdb04ac1c5f613fda1eca0c469161bd126103fd3fcc33cfbe9d94" },
                { "cy", "99bec58c14d6181f8f516ea5ae3526e10cfa7cd62118fa861ab7d1148ac8c4eafa669c322c60ec40989e1d6012c33c56f4e0af788c56fc7eeb9c5f6dc766e031" },
                { "da", "ad51dd534dc6a610c282ced4026fd7acfff90b8140391739976a8175fa1054ae36a940951ad22e30b93bce2d4b7dcab628148e047e74305ba6ca8bf0b2248714" },
                { "de", "3f2b527aaeb522d8f020be1d9bb58ec62aaa023248357c8b785a0eba055fd45dd0db3b770c711866cf70f4332f7e8ebb3a21ff6af42cb51ca259416d7e9b186a" },
                { "dsb", "b8834bb012e5ca72009f46a12c08e73f61b944dbada753f42e0501fe8a3e7c74128b60079fb463ab7d2c27e399796248aee4222a02dcea6a231906f0a5ac6196" },
                { "el", "ce1cfcb9bfe325e2c41456df5238ea8b95f317c40cea8815c134c13ab039f34b6d5e22e08af2113c36c0c2f957d66a2e1fcb4aa51fbd2ce077e661293e69e10b" },
                { "en-CA", "97899d66e1567ce04f53de1a4927542de7669f14def5fdf0bfb9955bd374ad6193ddfcc03371bbf27300762769cd4f67d344686a905f355f27c9d674c2e39790" },
                { "en-GB", "1b75b9c7ed9951f20e8cd63a65f4e45658aadbf96e85c97c2bf12981dce7c3a4397f16f7285e2f342fe2f72befa308950e7d6f6a3645ea9aff25d9f1d4b234ab" },
                { "en-US", "1956d8922568b16d19c814e68c0cffc115341b819e0528d4341ad7cde76375cbc2897e377c4385d4bb4aa6e31577ca76320b3025cd2501a0ba29772ed557548d" },
                { "eo", "aced159974cf78fd010c0f06936aec9c5031cbdfea4fa482ecd6ba67a951fec4f662a1dbcb5200667ca3d5f32c0494629979b4544ec2a7c017e49d451e58aebe" },
                { "es-AR", "9131d95a41f053a3a9416ccc034fe1a24f840978697c5d4c31bb4c0dbde8b2a7d412bf11d0a0843eace756f2566686991b6d7228e91cac6351a0a1cd61c6616e" },
                { "es-CL", "b30461f761edc9aadca3934e2f9afe8024b432daa5786bf48b0edd639503c6e0ada134ee332c8530b0fbac8262ca165e5c00349ea7f0f1848af487c7d857644a" },
                { "es-ES", "30b29a73cc5aa452ff2c72baf7ef82eb47bf199f092ea4dc16d1a690eacb5094a04ebb8bb3bf4997c0123769ea2606a0d0449ab6ac5ce96a237b211247d9918e" },
                { "es-MX", "bfba5625cbdcff2217a80e51934a0455489b669b0c4f3a87758dbb7c298d26ef1101ea8ac95eb617f52f5c22b6506ea586319e922f1aaa4f43faaa0db3ab74b5" },
                { "et", "c57d38254856af65f5385cd0509485d315f4343158b2768b4f840f9176c91ab2b79b860343a4502e2cb2016816b74d97a9240a30db5e534cf12f43e54f8d803c" },
                { "eu", "97c9a357c2a34d283ed954ef669e5976a6b84c4b3dddb107ec8949073da3bc99b40d3b8852a351c62ba397f6bb24205e459e7e2e1e56227d0017da32775322b1" },
                { "fa", "4acaa1381c1858b70cf1d3c939b4c578436a0909c641db4f5e5795b0514337238ffba7851834cc220761180639ab73aff7aae5ec4516f91803130d980903960d" },
                { "ff", "8afa8b820ecb53b9fa0244871dc1a3b9fd7bf988874fc451ba95538bb1f2747fb500f8ad8a0c1ce9e30da6e65ad6bdf85eb015d848af0fdfcbb656937117e6a9" },
                { "fi", "9f0b53184b76e79c359d02ea8e1d752b49980a4d55450675956adba713a19148e03d69994382cf5433104dabeee4e02b28bab3bd4bf4938aea295053d71daf23" },
                { "fr", "a277bdaae5efac91c23604f00d81cd4eb92f86f5401037f840ef867b9f6f59d73813ae65cad875ae93ddb74ded02efcec5dd1da52a06e0a0122dd725ae752bc9" },
                { "fur", "90d12e1a8c654c29cbb460799ec428103b760fb3f8792ee1c3e347f7b0ee1d41b7923678dbb2f91deda4c0e5bc5c2e28ab4eae11fcb60360edee40d00285934c" },
                { "fy-NL", "c1061e3fa94751dfa517c0a102e1157cab2fffb6ee14802fb77f93b5366bc118610874ad7e621932b7b38f2bf6d485bcdbf72329ffea952ca44bf1c3cfe783ff" },
                { "ga-IE", "5399bc93298421339abf03aa22138502ac377bd86bc5dd3e9de5b041004a6400583e473aff3133fb39a614fdce0e569d5f783ff355fe5879eddc4ba2c428cef2" },
                { "gd", "9620fd64b22443cb60337ad97d7f5062eb5b9808600c6d0493ece69e7a3ab245f70147c90ac1df8cd7345972f8d50905deac9ccd878a6383c58ff4d2c36d07e0" },
                { "gl", "9478ffdc69b3d7716c5fa4d1b9613604084fcf1f1367bc4df1e27d9159d8cf4bf52c79b9686d9eb9b974ea23acfafceebf995ee6c7b33e8c858a8e1664999567" },
                { "gn", "98d699962baa324674a700589b5c24d4f723c19d2ea96e72a4bffe0d80f7c8828b3d43112c7bbfdaf360754fd3d81adffd01671268ee29d0faa6647687e18260" },
                { "gu-IN", "a3cbea3f1f61eeb79a128fbb8381214dd7b33a8939f0fff4f106264d81b7204529826b44362367a869dfdc2ecfa3fd33a0eaf45c2c38499c29d6e6fda9efbe08" },
                { "he", "595133b9753fda772a5d67fbea264b73769963746a4ad9f4e208a614631ddd4fb8f681abe1d5a9a4e3f4fe28c8e2e1133e1b9a71a60cddf379836f5c1d8682b0" },
                { "hi-IN", "db7ab5fe4d1b92df043033fe3145015072c00851f7cdfa1c3591d6393e45382933108adbb03da9b4ee7fdec68d6e7871318b86f34efc1904a5e597aba364b931" },
                { "hr", "1713894084fadd0f4ce977ec02a2017c2f7ba17a7d9641ff3ffe67beb608c23629798ae5752d2bd813f9fbdddbe30c8f8c084085a073a095054e1d514547ed1d" },
                { "hsb", "56adadc40efd4eb56e8c8e4f1e00a5da229b0b6e3758512e26dc198466d9091452151bd9782e45bc5fbd79f5b3487b6e6a0703e291f150f910b07d5fb3f5659f" },
                { "hu", "cdc9fcb8e80cf2a513929b031e59bcfebad7f781e153ea8a6d8e9b79aaacb7a501190ffdabb43199eb08c2218e43cd29fbb180bfb141774db64bcf8a9327dc20" },
                { "hy-AM", "7cf949c0f893b6e5b6df68c25bca8278e06800653a0bb5bef085f0af2c7a62c68ede1427c341dde0aa4322de4e157801e0f882046c731f235f5f82eba80e5e32" },
                { "ia", "7bef3e797764354d3a11e1b733115dbde4323f29c22d57cc741d9c713262a87797a359a17f153336e7455a54d149abc7e2b902d62e4de2e46972658bf8ab5e23" },
                { "id", "0bba2949acd6a570ac7a7c2c4e76bffb52afdb5c65f9c12cbcf5b8aee70e4468211c832ef01227cbb3364d2b01bf53ea49953f4dfb27a8aa88ebf6353e874b33" },
                { "is", "b3e20f868369b79ee85cba3b68bfcb27f8d846a9a1f28b058de53f3cf50ea529ccc7bbb4a7cfe36779dfcba980398a876dbc9ffd18d1453195843106b7409ba7" },
                { "it", "019180bf86561566e93e86c901307138df326345375821f9537987997265c12b106112ddba4ca1f3d8107f94491aaa8ff1af1bc55f7e63512dbc80a9d9110364" },
                { "ja", "e95c8a7b9f86b1acbd704620ea1e1ced08eccdd01791674b86ff3f4b3abecce1e757231f1246df74d367846a50781d2f2b16fde456b53364b6fa7e128c653b2d" },
                { "ka", "4ff2847a060b9af5e4d5620e5126e5f054375b46136d0e673905840bc2276d344ede5effa317b91cebac763e98b699b37b53ee62e97b0b1aa03181465eee89e5" },
                { "kab", "785f49e3892309f81a2a594f9a8f909c8489521bd6e024a3018f4331b273d12a9677fdaa286cfdfa7ae8cfab4f7a124b6f3980a37ad73d436dc0db3d56bab69f" },
                { "kk", "50b8f40fba3501cbf32b4bb93a58365dadfe4c1160540e86357591ef0056e63b803eb9fd4d6bc78f03eab3120339b37cbf1279c979f8365060e752b3225390a5" },
                { "km", "4a4db103d921281f7171c040345e180a634bf688a7ed6537d24aee544037802b1181ee7fc1ae51fd707e6ad6211629402437e4ffa7c336946932b7144d598694" },
                { "kn", "3077089d79f73d438432885f66abe9033ec488368ead82b2f7050d662f29476b8f94165eee9325d669dc6b8dbc05441dd9c3ee1cb701e675bfef4cd62071ecfb" },
                { "ko", "9cd0f75f701e05e9b0363ee2ad12b480dbeaec89a52f72b46251d344af84bf39b6ad556a81c4e4dba2f087f5d814c7b75f1a4f564e74c3e476302f2105fe9326" },
                { "lij", "2b911ea191835f86bbf520297462b4a0b2b592d976b979036a3a56c93a0281c7162d529908103ce5b6430407ad035b81ce32f253990e4fef93ec138bf232f311" },
                { "lt", "e0657394dcbd862809fa4a98de866a6292476e407bd2c95f1d499886b2d85a40da3412eca330babdd111f82710e1ef9dd89b7365a4bda54be23d343871b5a567" },
                { "lv", "e74b215c0060ac004bb4dfe123e81a7961b45e8ddfe30a4cc2875931828c60b9739514c49ec5220f4c733a27e5a17312c7c2f26746032f05be25397b8b5c3728" },
                { "mk", "7832f75592cb9db08040a4d84c312049e0f8977a2a17960e61de9d8bea8131eaa68bf00c760e4618b57d1f9e7cd17c9f0753d8272d4c78fb19bbd6b7f2509a7a" },
                { "mr", "f952197873140138a87420d4a69e7a0f87cda8906c4ccbe37d6eb47f486832d139c58f194cbbf83837877a69eb4ff746bc05bc8991a5105da079c7df84ee6a27" },
                { "ms", "66833f1a471b5e25e5752d5778a192e5f78bc3f4eff2ab0e585f5781900681558ab9a15febe165e80bb97c0957822d16d09c8f70280d268c354e258c638c5e98" },
                { "my", "07cc2b36c5134deabbc508d7838dab2b60f4a02c8c50f2cc085b98ebbf678703fd772a94a9f0fc7a3fef4609eb65fb13a3cd2fe61879693129958bc2bf1b6471" },
                { "nb-NO", "ac42ff962866431b057d36e516a5fb0b23f2440389520b8adb50455761ae83569dd8731ec99de4bb89050607cfb91b37ff6b9a1b940e65152ff70491b76fd037" },
                { "ne-NP", "107461d7bc0de80f098aab67cb46626811ff3b1cdcc078702c51ded4b006e3da4cdfff8b55f15f9478baf2c2c54d63a4f5f4b94f7d6320fe60234e3214d308dc" },
                { "nl", "8158a389b128fbba80f6f4d64c78bee6498a351d40041fd47c924d1700c59612e18e3842154a87e10dcb086bf6ab7993065179f1fcbcdda37919241189ed420d" },
                { "nn-NO", "6a3cb9dd3f93ceac426200fc4251ccd37e278c582ffe96d9be40ab848905c57b44d69f297ba8ac030da34921044a693b12d330ed530693136a8524acaa385929" },
                { "oc", "5e311d94161b2a2d23a814988bd4a6e205fe0e023f316d9a358063261cfbf220242eb84a4e5016a4786dcd6e63bb3c6ad068127d04874348d80558ba80abffac" },
                { "pa-IN", "190832192c111ab93c5f9c983bfe519e3f2e6c5d4cb0833749b163cf14895d7aa358dbe7c9aea696c743ae93ed59a0d7f3f854179e2156a1e004e99c58587c96" },
                { "pl", "2c367e87c9cc294055ca644d7a0a77d885e812bfef306de0b725513e2ee6855935c66ef73554a56339ff2fc78f70881a668bd8c0daca8abaeefd22dc18b74a92" },
                { "pt-BR", "58c3e8f061827e1d31a363cac8ce62c7b47385417e46a35a156641f230a8381ce5757c455169f81bd6f7ce9fd6fe095c159a691662d3b3ab633f6c2192d76bda" },
                { "pt-PT", "e3ed6a425741b9d19de17cbdf0acdd5e57cf16dec090994a051b348423bc0f0d03feced25d16694d51e12aa5569307fc459aad839593d5b78057a3ee7341239c" },
                { "rm", "76c936a200fc64893ccf6c1c79535a7a234c6cc3ca3291ab08062e9297028a7e5ed3d71b8549664f0f755837702ae7b0ebf1d7c6d3b7d1565abcbbe6593d05c9" },
                { "ro", "7296babec5ab6caf7dc794937f9a048634b369cb09105050d6c6fd1d0bbaba73f2b54442e641073c7243895e680e3f969195b621669e7b9612886f2dc765115f" },
                { "ru", "b56eab2c3dfc7aa734982f8f3d65d1a16634f60de4d73655a84a41242b2db2b0f106f30ddde08a43e2a50e7065e94159236335c7fc2af454ddc9a57ebe5ff8ac" },
                { "sat", "534062770447866bdbf86950843b56927a3c548c17ba34646cbce4d82fb8e3255c232e6525fa3fd7796ce27da9385be383ef73c42a69464da741256fa481f204" },
                { "sc", "2569b62e1b27293569cadc935feb142a23ba65ccda4640ace8bbc8938a85a0558b5ab34c4198698114494691d69a1488db6497420606f27d335a5776077b99ce" },
                { "sco", "dc3978aaa650b488ece5d9b34d0695280c68f2de555da925d9f52c0f8cb20d99b5aa8cc8a28197ea4318ade050383fae1fcbb3163bfa99aaa83b02b50ba37aa7" },
                { "si", "e0190631e85c463e3d5e1f114c11adc25b14534f8a5087cb80bf8b2ebb6a250bf9e708e0f189ed67e3edc904a12fa124b1f192c1d015bf2c7e600ff1674e81ce" },
                { "sk", "346a924579c23c0866bcea962c31c997b18ea5efb4d2aa25244d8926d9ddbb3423a585c135acbc79e54b8ef8aa073e818217eb1a9315ae7c25aa463e151d792c" },
                { "skr", "4d9d50dfe90cfa8f7d091669146ed4efa0b69420294430b25fd7f8af85cc9a4b0c9bd798a2e9da326d3560cf4c9c0dced7586cbda673ffd9b0c644005dde2c7c" },
                { "sl", "7403f2fb2a408a79c0925198fca70b3b097849359b6f499011e915afdb0b1f239bac069e55210578aad37fb4b08fb0ba01c25c9399b51407a307154acd7105a5" },
                { "son", "e7de7b5484e6f7a6ddc74d3d3227e89368b26438e8d3569cd06402b19427909525602184286fefcebed84509cb6ae99fcf6e19fb335790da76381b28a85906b5" },
                { "sq", "b81f32107d006613bb9433780f374aa74aff71336a6d39badd7c8278de08654b18251103bbafff4a13b33492d5310df44176e24ace3915ad9b0d1d4e6db170fb" },
                { "sr", "0cfdc78efc3239754b9116308dc8b89acbc355e42a4d7274989e5380d5933ebb3b966675617204eb4b217c0f00d64d7ef103acd9552bdbd2af56c3de3f70fca4" },
                { "sv-SE", "db539a45d61feb7fe3aa80c9c15a9cadf88545680d3dd93c11b3fa84b4123bb4f2b1970c414229318e13c3f1345e667cee09e869e6ad0d23e4e5b0d7c980a91b" },
                { "szl", "74dba280c04671fb33d0053d890e43bda5b0addd45b4b7bdb01acce64b221219ab3578123620de5bbfd4bdec098fc2fa6f8f4e86923b673b64261f74793962e7" },
                { "ta", "e254b97b76b1d13f04fb1483a18c37474f7a3b03ea5872f8e1ee3dd8688f812b0a516aa0e2dd1cc5b639a330f1f17bd01dcf38344cb91d9ca1f94d70d13ffd00" },
                { "te", "ba1c5e772132619ec8d2f44f670a278d8375bb60756738ce606f0cc44ae7655509a9cccbc86dfdbeb41d5b27922799bdfbae60d60c99bb132bd39050e9a5a5b4" },
                { "tg", "2d85694caeb4df44c87029331fb0ba08a3f38f69b6738f1681ea8176d88538bc2428654256847d9c86103d13c6f1677a0c7d52546af5c8f987df3c44876612ca" },
                { "th", "2d07062ca68dc49ef870f0fa43c269692cb4395d9c5fcd411d838a2312b6a6139e4e751a1827152a3e6bcb42c9507c97a77f06ffe2165fc691e624cde173d638" },
                { "tl", "3b49f66a7febd179303f6a205baa2ded14b47c0444884c95938a3ed7d5d5be84ece35076ba264e0a8d85890d65b9a73232a3571860b8f8eee773f54716f6189e" },
                { "tr", "d7ba73fffd45c8c192691452faff56d064a77181be8c42bc7982e205791a5b69ce791ff21de9a1f0e0c0c059e79fd8ce7fab962a935ab06c37a36e167860d378" },
                { "trs", "4c8b3775ed0524664a7b82c384ce92bcb6316ab3d22e931bf18df58410fa2c5d88567acb0475e62e22bd0d30b04e616a3c58570a7a79a9901214df16548ec435" },
                { "uk", "36b75c9d7a8405a092cc68dfaf459276181b9e914c04704ba663f978a13da8699f45e3810d6efa7106b2dd21213674eb272523f1127374c39e072d30be8bfd0d" },
                { "ur", "436da80b75eb8b244ed84798cd85d38a7e0ebb239b9eafb2e772db0f474f63a7c97eb6b4bd2d520707be2821f20e00c05f50515a833d5f41190bdc97a8920e0e" },
                { "uz", "ea08fd91d897d41a731a3a05178bb164a9d95b4f1e2a1c4c38c9c48e15818804d88480113e82ae89178f11e999e11746e4006bb2fa6b1f0ef3b9d51cc0df0085" },
                { "vi", "98bdffa73200d27b4b585a04309d9ceecb27207dac5f4a3b37d684b43778f4152f075b0d851b527e7f66f4a813c8ef7b58e5834a6f6d970b08b90578767458b1" },
                { "xh", "0ce7773048daf91fdb315ad16a910638cd9e10f2ac1349d73e606e73ce20cd6a3cbe2beaedffd1ffc1324e9a99d303ed6d832a64102c94d0efacec0aa687748b" },
                { "zh-CN", "e26942221d608ed498c64f8c8861a1b91a28be3e778eb36fc19306018c32716e31537dda48909ebd78991e5da6204cdf8efa8535ad83e5dc8634d805d15b6639" },
                { "zh-TW", "c10b0129ced2f48e766d5fbcbaa66bccbb38991f6319c24d4aace0e34a0f49230f5f861ebaad729c5535433f07c08910c672da807f1116ed0d6f897c191b80d8" }
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
