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
        private const string currentVersion = "139.0b1";


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
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f0dc78b06333748b2a07546b95f0b2b59db58695169b5b2263e9a4a0b083592249f95ca09e162e6477331349a9fee4a580e525142e0fa0fe5787142da6c3f26f" },
                { "af", "2dccf185feadf6c716fcb938c0f8bbc10456c4e259d13531e46e01d6f89e07edfa0e3b77ab5f1b660707db06b32feda7c6e2293c3d9e19d0becec6fd70001282" },
                { "an", "a85c874b5bd1dd23dec50362f2a14cf1bd8cc9bdbd147a4beff360bc5363bc57341b3a0859bf81a15d02836932003b3d021ebd4dbfeece1d065938ace284edca" },
                { "ar", "414eaf953aecc00959b85a524246880756b51d60b61e15f75e8f9d5259da4bd627aae0d8b7e7e3142e4ac4c82dc0feb9b96e4d5b77711f9cdb95d05eafc998de" },
                { "ast", "49251061bc475a29183374160c87906cfc5b847f7a7c8a8df994648542d430f0782db74134bef9e987b7a285d3841372dfb2e0ab183d6f22c14fa675dd5c887d" },
                { "az", "2aba5b43787541dd8b276360abfc941722ad51d460fb6479cf935067abf0dbe4ec5891e58ac297972c2333739eb4e29e76de014587955263113cfca4bc51883e" },
                { "be", "8a756fde85b35a551740977a27c8c17cba76072c4826446947c32d7b8937aa0f72a62a1547c1559fdf3ddf0298abfe3e551d2395ec459fcad7fe6514f713e655" },
                { "bg", "4e528103d3ccdcc94d5642c687c2ff8dfe85a7c8684704c7e048479285ad22a1845e66a6567704f01a0391dc56da5c9b116327c09b54ae9d511e3271f338d334" },
                { "bn", "a5308d97e7adeb7adbb062c70f184881e1ad941d0958280641701941fbc93a35315d23885659b47a1222183b028379e81c75b5c46d15c7ffa3450cf08c3b1865" },
                { "br", "6a2a2e657c997c013d6941dbbec31bacaa2f06e7df0ffb6a12e3baf20820e26a5352798914ae3a07e6958edcf46d96494b1766efad690c0ced8793a35b2698c2" },
                { "bs", "bc2a6b93556370208d158398f479e010d42ad34cdcbee1c66d6d852cdc0462f38853f5e8d0483064649ceddd25230700f325ce0d54971199e4be1159edd753c3" },
                { "ca", "9529559f5587fe89eea6a0d13a329a467c9b1261347fa1d5c08cedcd994e42395fec358cc30f5e6d97dbd0a33bc2c036af7092e16f6073eeb0f63ee1ab3b7f6d" },
                { "cak", "12c1f2342c122b9e72d187f6163aa809ac26a00d5f6c6d6fd03bc8e07ea2eff07ab16b42bea3febef159003ad02beafd27d79cf83560e2112d77475fec912b6c" },
                { "cs", "91346991e1115eea9a9eb59c0e69883eee4093e8030dd15d577743d498afd396d11104ab030ec4d15cda6d782df3349dd315536115f189c8aba200d10a9f3b58" },
                { "cy", "0e1d3b00dfdf4c6de54e5ee2695731d04f60b496a63f25200802f9ab1a741691f57435ba8b32ef68061a6031ec1192db9a154ce44444ce0be1786e80a92d3c00" },
                { "da", "d6904307840c7abdc73295e82d001dcbad0ff345d781702d6ab17101295f1f35398b51eb9205078859bf69679451f4ec08860dca7d471413c035a558f15245df" },
                { "de", "b96f427ed38291e30b41606d9fbc8ea305af8c98d31dcee23a58bc5b8e44e243ca173d924dc59c5b9275fb5cf8c62c44a09cdc2d0c0f58d2698c47649271a07a" },
                { "dsb", "68f8e09938fdc7e26caee80a4a46e86c93bce62cf9499173acc2687da531553813f1929d4bd3e903c3e209f8a28ca3e61aa064e34826e06f818dd30a9287c428" },
                { "el", "e3f0b0e3d37f0d3f8f5746504f88f61cf10e81bb794a62a11e0ef55962a4edd177f9fcd2bcf9c025a503df19e4fed8495ae20314151a3f356f04c48f00871f15" },
                { "en-CA", "c8668585e10ad0ef5e63fbf0e6eb80d7e9feb92b5742eb5e163438f199e77617cd5c45080bb7c7d117af111d17f2ef3d9f09b8fa87d7681f44ba89a59a66533a" },
                { "en-GB", "c7a0bf1e38241bc65d477bbc6d2494125b5461102758793318bf2c499e3bc21290ba5aedd501a49ad4814839171446abbecd77774a07bdf6cdb58aab20b2cb1f" },
                { "en-US", "0340e7b1b7d77d639f465dd2c33e6516031c895fa0c7dbd6d9f85a56e796a2eafd37282ff6f60bd2a096b3d311a0fb722ae0d32d9810f558a5dfe890ffa2f14a" },
                { "eo", "d317ac83f1f0698debf1c616301d0b96f90d7156ca05e74bcc0cd3d38fc64b18b566b9a8b4c09e1a8eb48f5d021f71eb6991fec0b9f72a1605ab6fdbea806365" },
                { "es-AR", "f5f414e53a85b3b177432658106ca0ac5f65b1efea3a5ca4cb50c55eca2b5b2c28f81efa064c60250a0fd4144d76fc6cc9181c394079bfd0b008f5521d609258" },
                { "es-CL", "24baa8007aa88c82ef2f1c2d50d252a32830b479b730af4c7d489c59acc3a62d672ba0de83d4bedbb60133c460281a12757fc6f9bb104c6919ba2bd6b3589130" },
                { "es-ES", "6d0f53185bee554f97de6ff5c6dafb2c2fb084b9a179a91b3a0d7191089aa763e8d3c71f418c8b2c1fdac4dc936004aaa7fd4f4567a0880da5f301f37eb261e1" },
                { "es-MX", "f967bd1f26472e29e5ca279b4ea06ab8d6e52b609dfb3b78733d643c3fa9b123804f78b40e8b632af61e68259349986c61af2408f75ddf18951194ba13b4607d" },
                { "et", "15e61663a4c4eb79ffe53d7a6ba17a180eb03a7da4727b7d89a8503290dd0437ffdfe6a5ac36157d90be51c6d836332791512e10ed093cdfe3ef3c0a147e035a" },
                { "eu", "7f03bcf50008344c217ea5f8f558fdddcd0f0dc2380c029b54ce8443ca65ef89dd53403787b560a767438e90697feed926239b82d64099ef854031ddc833dd27" },
                { "fa", "59f8dac0e416f5bba57d0ee5b8d8874e218cc551849bb43ee40a88e7fcc6e796bceab4f1b483dc586b5e2c7455f95d5d67c4a448ac898155c274e7e78769ceb9" },
                { "ff", "59f35a108e25aeed33574ce5fb1c76b4fd1f7899ab220248c13910e57db87f4ee8c360bc98a8aaa69896bb339c816b0ea848dc6b1db2d6573d364b579f3ba03b" },
                { "fi", "1b0c282331bab8aad604292889a68c7cb43d093ad92446226184429d6b4b5702a6484d106caeeb30dd61f31b1477aa61716608eb074bff827eaaf9f01490634c" },
                { "fr", "de056923257067a880ba2f3064ab2ab4e23b9f0ec433c98c00bb36a16ee20ea7fa803712871ae887bec6fb90da4b54b74721ae53201083933c44136e8c8a863e" },
                { "fur", "1825c2871375d2d279128d9e39c0e59ba548f27e10b50f99550a8903c373c68ac1556865d9711532228cbf47816e7a5acba810d1cb5e060ff98a7100c7a91fab" },
                { "fy-NL", "5884cbeb02fcb225d1d1a815ba0e60d3bd863e33c06435ca45475b15462bbe29684bdb8225346b0f4f21e29d3994bbccaabd88abb1d8d4686b99e714c6c3ef88" },
                { "ga-IE", "de2f4607c4670eccf66eda948e8f45163ffd4b9d75ccb247f8cb29b58d1b73e9e3e1e59f59927f4805daeac4ce36d010307f58ba5f55db1a3a69b9468d13a011" },
                { "gd", "b109a27be9d43a79ac0e08cbc007bff44e917fd96289ec1c23072782cea51c6a8921cfaa554387fb6c82b7b861b205fa0e68f1bfd96fbbe720a2378af48623ef" },
                { "gl", "1da24e8f7fb7796cac1354a96429611de0e0d9a3e58e018f2631828d1fdc71cdc52cce93c5aacbdc36533cf4230118667da316ce8a336ecfcd80cc1aaf1b79a7" },
                { "gn", "d9a1799bc7142bca36717887aabc7a85c9500db3f11231c81f7b4e51d6cdad3d17b52c1b42725d9af286ea22862a7f57949b9ece7b47ec6f50913f5bad86c667" },
                { "gu-IN", "0f0865088a4ffa806e0689e5f9c7a288638d3406077c26c050f387dc595a474ed61136c81c9b50bf6f70a24cb0265f6b92155f238a6b2160b042aea3764a8775" },
                { "he", "d49121f8337e03b21610055ceb69e077d758249c012560a526f3779e55c07c33d4e534d74accb073c5e1eb8a300e9a1247abd57a3dc97915cc5fc6c1f1a21fe1" },
                { "hi-IN", "41dca8194552fa16a17245817b48855016ccdb408b0df0d79e328002e7d38bcaff56bddc3fbd44b4481a48491f221f787d00379aa3bab75f562e3d7fa09655ca" },
                { "hr", "3dd53a937e2d11930e34b90d8f740f5bee210257e53d6fd3f97659ff7329f29956cbd756c65e9e34027994eedd92257540213ea5580fa660e3c0cf1b082d43c3" },
                { "hsb", "4fd6dda9f9dc459d539332e61c96b95ba1dcc71c6399788559ce3f5e8c510343338076bd7661d10d07b5609d324df3adff807c8eee020d4aafdfbcbff1627c52" },
                { "hu", "151ae1edc04dfda1231e29ce6518c675697cebeeddad0d8f0d8a594d0f0064da6db351ba7ad3982080f08c66b27677ba1d30fb25570d349df27ba59e0df91772" },
                { "hy-AM", "d63737fd7b36e6f59c60b590650862285f7ed080aadf0bb142d20db5536ef901f4ad90f45a03da2699455169bfb90bd8ab0f5a2f5d02d72925c05e37e8e1ccd3" },
                { "ia", "fd4847b35f4c7235e58cf5a0bf9e69c04ebaab1cda6ebf25ef4e1bd0fa939f24e397c67eeb637337b2743c88de4a9522f7cccf520f4092dd05073776157d3e63" },
                { "id", "5869488d7b142d9816b9a3c9c1e306838a003f04916a3a747dcd882a596864f79123c698ca2a0dd5f0b1082ae1ea6e7357577197991d5238d88110eb6ad301c7" },
                { "is", "c0e60f2ace24722e23b65b38a01526e77131090723b4b0b9c13983c76fb7a53c879a2a44d3e8dbdd42851e2b33eb31eb276bb3819189d3c82b899239bd299136" },
                { "it", "6892c538287eef26b47275f27f5fde714ecae306ff87fd60fde5c9dc2da1701e1ed2d496c756c159a94e03b6462d3af900860f84c8abcda5b2b9340f7be05c21" },
                { "ja", "46a09ca2efcfd490d66a4d3bfd5ccbeebec718eafa2504d49595db127f7a58bf046c7ff713fac4a989df94798605cac6ea7bb9aa6a4335386c7f021abfb2872c" },
                { "ka", "737c2b4dd12e443b56aace581ebc5663fa73747be2c99ecdaf83148a8c718306d5785cc14864ccc22dc3d1e143aa50b65d0f03aa75f185a4d021c53be7b7479f" },
                { "kab", "61afaa9f0c6fe448b231ebe44ea7b746edb03db4484fef6358112c335bf9e886e02aecf37eae0aba29340cefdcf8ee3cd66af81b8462012fcbb934851dcbdcf5" },
                { "kk", "076c0fdf5c19be93d1a912a6e1f2be5e909d4e09caefe23d1f2626b486c92cead2b765c08b3372bcc90bb50454fa10070005b08fb177e21f0dfa3d78b3f1fc2c" },
                { "km", "749b56ba055b6e85beccd1c0222114e18fe2db725b7af86adbee688d00fcd6e7b37393b6f67723966adcc4b870dfdcf06d64a82f754b5ca183173f26ae88e82f" },
                { "kn", "598fea18956004713c8fec8d4c99a1124f0fdc3bd90665579a94e3c3d40ad8b6ad052a1f40f742cfe74919bfae0994536d15a6a73c07890ecd4ddd0b95c9d784" },
                { "ko", "a798a4b58740b78b92eb1d4cf864207ecafd6cb930f490ddbd87e5bbc472b57a0cbda4e560e6a84423e0c47db7154ef51446b216b326e3b341015381aef7e344" },
                { "lij", "4155b928c11265f4afdbd3b5bcef41effa0d54959655e2c43e7c1491a90423d1435f70f267e2b5ac65f87da40dfe2fc4484bff3028d55558fd312539771c0e90" },
                { "lt", "89f10046348f3dc27ff75a5596dbc7af990d8a8315fed226b1d129f327814da50045c4290e6a7627d58fa72c0659b161c4bdeccc39fe19bed856348e553b5a52" },
                { "lv", "a86dd6e18b902448ca01b1ee67838128a7182d74a3aee68e8e18a93bd77d85b64ab2fda8996295868c9a4b8b086889aff9ec9f954c78d1551abeeffdd0032a7c" },
                { "mk", "1ee2f4f16da54a7b3b4ab6a6a56a2de67c5e17ab11a449ba5d6d12f8c520b61647789f3216c7ab8e2979dc5a38b62d9db28e4d795edb9c83404af17d2593d1f5" },
                { "mr", "1403a9cb788ae71316112f30aea74c1937e29953d47bb6504ee071a8a5340e62518907afd5f3d3a0b43764766f65bfbb0aff79e63572eceed6e071c51b2a9524" },
                { "ms", "3480ec7876a6267af5c54901c158aa715985caea8019e303a56acf06b06749bb63aefda61363d424799ede10e14f861dcc03ce4f10c05356478497b100553370" },
                { "my", "941b1b34ab62611729b7686d3c9cb0466f297d6c0c577ba672e6917cbca089e5e8a9bcab2070c80111e6cd55f37f0e9d29f338a27ebcbf5d314d398d3cc10eab" },
                { "nb-NO", "95e6d2adeabd94e92ed495bfab503f6e9f7d83ac9b5aef2b54c52aecf31fc5589cfb2bfe6de4552a75b22f8dcaf6bda35d50c873de5f6c45ab6e9924e08a2dcf" },
                { "ne-NP", "aff2172d5c3e1208eb009636304495eb694328739d333589c8c6b84c5d72a27f4647d79c0c62b15347e7aef09718fd140471fec0317e4a0c3077dcc1a3445b7c" },
                { "nl", "b530f5366e1f05807ce939d7edbf16e0076a532f946b29a4b8a20fc7db528e99afec8440b6c9de923b0a20da66c02026661ab492042757dceeea2cba9c2063f2" },
                { "nn-NO", "fe0b4e4ea86d7290863f3b98f7064535fbbd1932a5929bb2388bbb1c52eaeadff54022129a7193f864c3765fb38fbfed89ef4e51432d3ac2b2ea5c1c5d48b3d5" },
                { "oc", "485eb14bf65616f3e633252db1f871815ce6cf8a3e3136325bb6e114528aaee0cfec0f347729640f1e227d519430f55725fc7a3521185a46d134796d28d01cf6" },
                { "pa-IN", "62d1e316423bc130810b4fdb6da22894cdd1efd35385a72e88d81e04746452e212c900abfcec7dddddc3e2f464fb3e32b9d65998413335038b2803d13d4d9215" },
                { "pl", "949963979262281d80bb59d2ad6d63eb1734d50ba6eec34855b7ec6572b8425fa288c3f791f8fd87a70c17dcf488f87f9e30aa936d6b2b8230fa3b1ebc165205" },
                { "pt-BR", "4174d0baefa86296f7e94ff7e8b6067dff0086e0be7818c54b77486785cf39ab273b90a883590b3d238471bae96fdcf81adf4d04cbc489ccc6ebe0d3f93e0e09" },
                { "pt-PT", "6a8d1df71befb8d6de3b6b2c095d73cd9d03fd7bba3225c81e3ffc19b90ac203e890f85aef94f25a0fb3f76b85728bbba4c236908a3ee3dafd23ee425797a266" },
                { "rm", "49f9d387bbdb91c1c606a9a84974ee95c8a7fadee20bbfb184684651a5f38e7433f925401d855ac3e91bcf0a4d9db3d60ce47e9c5094c700dcc750fa2e1dd0e5" },
                { "ro", "e029d465d9051efdd10efde6646d5deeba55998a6eec6080cb1dca753fe9d1351fe4e869d178fa8ddf67d4b0bfe8f4422944f1c4023cf5255d5f2f3d1c2732fb" },
                { "ru", "cf30edd01a8a976c9eebb296201c579d163910ed9d1d2f12bbfe21719a7b97286ba0f3bfae0dbb4c522e9e2dfd33f630b37a04ec9b2d4fa37d9a01777d0b231e" },
                { "sat", "09a5a4de3185a4efd6a8571c70f1517d7d4c729b6684b45eaf9f6c2679a063e2b6d5dd97aaf90cdf42deae14ec00eb4b35a04e35d793a6923876260715c2fb1a" },
                { "sc", "7b530d113891f157d06beb63990306162d9d5776091ab23d422ca444377b50189b16354521e6a4bafbc89762950c362932990add754083b2a72e2af4d57893dd" },
                { "sco", "7f54395816dc1c4c71d4d5a3a207c1901497cafeac0938c2a1bdd0e45ddd0d97f2ba3ec2dbed9191566a4f238b3d45d478826c0a3c337b489fb63663f3642033" },
                { "si", "3efb1d59db83bc52aff474bc6f2d6445adc09dc55fc69e397e1b52a9797e86dbd283885f5a1c80c880b1c95d97ae7a84cdcd15d469ca7af69bb9aad7783a2a1d" },
                { "sk", "8c894f28e116068c6e201d9468d2a0f08e08bf95b7e44152799ebcd995f50de1bdf1d7bd116a6b2b59b34dad8923790589eda20044f7de8eee283a7f4ea7df5b" },
                { "skr", "f3c5653c97431048fc9c6c323c7113ba900d89664fa1e3b48d4bea9e72e170383a7a7a1f5293b0b5540c9e0416b7d7a0d29884747e42bbcf390831d3314e12ff" },
                { "sl", "f4972b0b8d6994734c6c0fb45854124f025c1fecfda7b4b3a5d3a198662c717df18798d32e02cbef94926953ecff6fa157a6eb82274760f5db4b27303caed0b4" },
                { "son", "d22185e9cebb86ca7e9e1fbe8a4da063288afc983df51a7afe554322dfb12e2e2a6d16a62eeb1395f49413ccc629dc21768b5590418bfce8d744efeea8515e22" },
                { "sq", "818f67b36b9b875a2aef5328bf56aaf571b8aadd06d2b2ebae0426a7566600bfacc209945ac89841edaf9882ffa7b865e2b6ca53801f3fefab734048a24350cd" },
                { "sr", "226195a73224742eec1091b983cead4ddcdf640e71399f26b143d3ce6b90bee3db70a516215aa494f2f34b263af4d3a5e7bfd3c6e389906d84a36d74a0f4001f" },
                { "sv-SE", "5a44025b2d7f97208c43a46b9f937d760a9c204651828809396fa5a2d8014d3fea6f550b705c2e7f9df55f1796ec7e16c8cd2a475d975c254bcaa4cf0306e752" },
                { "szl", "9514f89ab6d395de5dd5c05f7b21816ef7501f3ecd4c5c847c3af10aea5914aa666eccb66af3c9fcf38a22b0952a3eec1cc6b883f761bf865708022915867229" },
                { "ta", "8b5e5b9361c21382959d6a38dd838688b69a3d34bbcd7ffb0730ab7238981fbcf61f4859e9489369fec6fd6ea6fc79ad2c60867e1ce6a243cdafb4aca5712942" },
                { "te", "8f53883f0f6eb5f8b3b905493b878e73c9b821c98475171d19a7667153c6c2b9ce4c5314682cd64aefe7705b68fcb8d599556098c9e43187b334182878f90478" },
                { "tg", "ccc9f4ce5b9b6855355898eef7e5d670e94af6c480c6ccad7a7081cc28831fdcbfddbeb25bd7ec188e8be795c6853312f2ef926eb6ad960dd9f761cf630f6732" },
                { "th", "cfe52976fe3c0aeddbb1d423c5a7f1a89ec0978eeb53538b3c2049548967389f9960e72d5a1a5fa0c863b7851d4fd0d67980615a1e5e12730dd1e223ab4de5b6" },
                { "tl", "dfb16c2758752722f11821ef2c035fa6b6af9d56f8eb8c747631b1f8b799965abc02bbd60dd8733caadd392d76414a855e437e1ed565b83ddfd1f7a85f773cf8" },
                { "tr", "7d15c27cf370aa1199f1a302bbc0be864b97668abe0f281a84128a518d965ec66602123e3313130f7671ec91bceacf35f4d5d07c6c9200cf71a3707f5bcdf5ae" },
                { "trs", "83784294295b5e6c6e4940fec952dad7fa4992f24067d2f1038b2f844924c637ffbd21bc2dba2447623a934bbb3ed7b88ec3cc9edca44b3d51ec18337039e7b7" },
                { "uk", "603edcc672873f9ed5d4080490550af4f5a3625933711e1f09c9dab8c8e98f0f203ef123362da56386dce749517f0f50074841c3c3d1e2628b5db7bee66b6d1d" },
                { "ur", "7b970f8da878f263e63b6a4bec6129945a7f6309ccc5e1137049f1d8951f532bfecfe161d41edc51efa9186f0bc8f21c4b0b9f012f946f91a6ea82a11acdb585" },
                { "uz", "b936cbbf2ce5fec9bdbe95619886ca56324a723bb99fe50bb0c5d2fab96629355c2f8da7c1e859fd8bed567301851eb98e69f9b4f2b83e05fa826e4cdcdee037" },
                { "vi", "9ecf546002212e758bf3d747ceb08ab8103730b684d8b7d056a71c2d8413e58b5736a95dbcc71080384c865c762429423ac7968cf4d7e897ac15f070fc0fae52" },
                { "xh", "875278841befc2c6f45085df2fb819189bb0bf0777a3aeb27ea00dba6af7fa302bfb7988b98bb6020df5f4a2420ab0565a762e44edfc5cf27cd3c711e308bd17" },
                { "zh-CN", "1c8efe62a8ac5e7d676dd2b6bc886d67d5be177ff395ae26eca9ce076a072b4262e5cc0134d65a293e4c8930270499cd6e0b900e0df50c0ac91f0c437c575026" },
                { "zh-TW", "11aa167d6d51c501523467811f267f8a4bf789dcac6d54e1c33be0b6c180f34c96e63595a7048aadcc734f419c0f70807f80b54603a476277b70b68fc8cd5e08" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "429681f296376f5964dde5da1b7e1df364257b60b0e64369d4ec2a8a18da268f3a6ad5e203b7c9a44d8b4bacd3a3478e08d2fed72f1e6ea7c1ccb9867b105e14" },
                { "af", "6e77892a4799d406244e116fcadf07bab18f2dac62caeca689cdf23356b2de7ae9bc0f070e09134657734f9caad310ea1e98988afad81623a51b4e78c31b21b9" },
                { "an", "37bbb6ba55d6eb4f55999de94888aa4651e9b18f6954970ab384f8f3ac15dbb62a22de54f95420ed8ee59277d2c6359edb0891d45a88d4c6dc1738f25653d04e" },
                { "ar", "19964815b9dc369735c5093f62d0e46d4a952ed656fe004ff5e1fc07001c2a366d00c447db183f0c1d136e83fff57058b4f5eb40debda8c1b9c181252c5c9ca2" },
                { "ast", "43a276317ad0f9f1a8fcd5aba52d8ce9b4a0cb751e685bfbeb636054d3f453faded7efea5781d14bccfe7a3d9f773129a1290e9fe790ad84d253b63aff015fcf" },
                { "az", "72087ce7778c6d78f64d12c2b4a61f34deb5fbe27293a6a1adbf62dd4eaaf1cf83a48b251324c05cd34ba468453e1cdaa74fb12cbe73020138a08626c42e9cea" },
                { "be", "fa762ae4d3271cf9e00e680fd2b3bca1112839d6998f4d7bf4e5ef4c7c2549a3b213a05fed71ee3e7173341bcc0f2856b074526d0ee17a60d71990e149c5102a" },
                { "bg", "9f6e1313f95e48b0c9f25893afc8a0cea1c8e410620fbc8927058b246d2fe0a1ea1dd80850ce4aa42200c65ae5dd09bdd41e8fb131e0cba562b496144e1f0f95" },
                { "bn", "76a78136922574cf1d62dbded62f80f01a458ad7726a674afbfac171d3df01bc65a6fb6fb421b1f91096d8e0e686c11e7d88acb301320bf8ad93eb03bd5c4714" },
                { "br", "8de2a7178e41596992e7da85fa44137ff0049d877fa47b15f938a9206589a0c0980ce8ca304af38b8c1b960195245ea20f13f2225b7362b2af7ca2cdfd397ace" },
                { "bs", "1e5275d065fd1f88b3290a2f26db7149cb4056a8c58c0f42afedca945492a7205bd1715e21c249fbb181f667c75f686c140303329af21a36a49781b762654d34" },
                { "ca", "d2ec37dbff2709cad186bd151d7c54997c3f2d2bd74515b104a03052d5ff8c7c344634dafd41ad7539bef9f496b35f84e75b6f231114cf94065bdd7196e16834" },
                { "cak", "0fea4b263480dced7f58c9521f7f98e7b76553659b3521b875d28af1890d9b490033164aebd70f7e1d7fdaac42799240a422f89e4fb84f2aa5ad84e418f66d94" },
                { "cs", "6460aff3d47b850106b5770066a65cfceb6f8ef45305236d032ae6d551a27e4a85fdb0b318a85278ecb878cd04a39bd0bea7dd3097ff1af72d798b231ae828dc" },
                { "cy", "ab952acba18b21ff3478d0ca83090481754af8aa6ce69894c4dcc4f04cb0e52ae32c49c7c5539beb736f2df348046748cbcb8cf0c2a603927ca8120d363f33ba" },
                { "da", "3db4d3b48b3bc7ec33c702b2d48e88926d02c82854fdb780c9829834dd669f792c506971979cd439a0a933eaf156b1be3eeb76970feaf57c736f1208cce1da15" },
                { "de", "8c6c68edce483c272afe6f15e63eb02191bbeedaaa48f5db25cf53bac7e86dc9988c395f21bd42cc21af7708da36d75949ecf6c1e6e96ba7b93a247a8df3085e" },
                { "dsb", "801355e2bdd1d2d4fba39403a920fa009529a1d367185fcf804289505cfc18bb5b885e8a662f081959d8f70342b4deaabc1aa03ff95fcaa25d3936ad0b7dabb7" },
                { "el", "92392d8aac7607a1fa083814b2ac16c1d76ceb9b4379bedaf0cd22413ac347cb4373288cbe122802095c71f8c63f37a56eec153ab2645ef028cf52bb8d2f8c95" },
                { "en-CA", "fc1b4acfc9a6438976657d4941110015028384ac243e5fba26f3b2316268a29df6cfbb67cee2b41f97b4208568cbe4ab5c7a439b2dc6fe9a204438cb04cd9d20" },
                { "en-GB", "0309850bac11607e1f6f1e7133db7de6b510d223f447e625b48acba1dcfe76587867c7b04da38fbdc99e381594e1c860c3b692af69cc8d5e12818c92ee299413" },
                { "en-US", "e50e5bf6f7973115096eb24b9f1114742e5a40624bccaec32fcbc2524e2be349c226e09ca6ed8354f910525824bc42c7af2a42230958e57d12d90d0f40f7aa15" },
                { "eo", "4db5d607c98c7e479e0357a787a1f66d9d3e5a23d6925691be0c7b26a6eebfa472721a52d529599c0c46a982effd6ad8e5598e8752b9e728a57834ba4c7c393f" },
                { "es-AR", "38c343909c14081cac8a0b11f7dc673a993f714643edc1abcbe8f06da60c71276042ff7c1720017022c247cb822fa1ad75bf9bc493009530c72fb989b14a3374" },
                { "es-CL", "d4a6fe0ca65f48e57a21ea436e21d99a0ce608da93a524c4b5054510ef40146c5490ab4e682b48e51135dc846102d813a0a94a0e199c0d8c2b1b1fda118c3e6a" },
                { "es-ES", "21ef4cb678ee4114f6b90475a61a095c5eae37687cd97878f5f0d86990691cf652bd0839a1ec7b3fede5ecc3a485b21bbba503f7cdb91c94f767a4a2d398922b" },
                { "es-MX", "bacaf5dab0e9ce3a1ba539f00960ea57ac49d4491add63fc027568e6bc80564c02504c6d7d7293ea6650be90f979b52bf1aa112c65c17de80d7ba2de37f0c3d7" },
                { "et", "64421f2292def06af6a8136001be1f5fe4eed39f9289c5e63d264b06cefb7c9f4e8276aa8430e82ca9ab865e2d2710572aef73b6b0d6201dbe869226df01991a" },
                { "eu", "d4b6ae14ad197dd54c67fc62b16af947c17fb618615afa8bc3a41f76ab4ade457919a00778580cf7d0540486721a7688115d5cff5d4c300715214626af86ac07" },
                { "fa", "e442780d2a82b92d3d5e098e352783cddd6a28c1a8495c6a767e0d67c11000639b0e9ed7da9b7ef4c1ee1cc4be8eb9051abdb36c0c8e0189271b57e98e632d36" },
                { "ff", "2962ccbdbeea7539bb86977b0db5107be351e6b5652e05c42ff317dcf682d229c24219b7cef23a36622c36e90b29d445a597c8c18cd01462715f9d2a8684ee6d" },
                { "fi", "c461be8c3e1eb2eca06796bb53cd1f11845d3d682a99d606c0528fdea56d8502a4df4d7590f53c05cd32c4db2fd14b81046a302d9b44240aefe195306a27380c" },
                { "fr", "db9492a30357aff09757a644b17832cd637805dac177c988f95b0d16beac488f2171c6d21e8428e58e88293d7716a7fb0c764b72bbf9afd586d3d96615d02a8a" },
                { "fur", "f4d0d8c5cfd73d2305a2ab5cd2492cf7ea5cf5f5463726f837c8ab6d456d863a906753f37e01ca0e90d9285397723801b80367e0b5e43ccbb505c82238c6bf71" },
                { "fy-NL", "5a99983d531ac36a7a3da7b4a6b9aafed31fb25e924ac05d9d35f11e538b275c174d88707421697529fa052d5be3a0733508a31511cc2ceb60af61e87821a271" },
                { "ga-IE", "a005aaa7f659760eb9b49f9be9d41b564f640b81507f0ffd6673db883f68c452e488ad680513899e52ed423dd508f877b3382b27a4e97b6bd675b12c5891af6d" },
                { "gd", "f30668a92abe1775e3ec8766d16d3b3f80667146e922bd884923822d42abeca00d66af957af721b07226b9e492fe4c20a9196ea2016c5ddb66f70839f68c8f7e" },
                { "gl", "8c35769b83d0bf454c981a11480bd5d47a8128b1e3f03d490e439423b7b8222b6344685149edd7677314928e7b835229f585f4fd4639427dfe8fa02f27ea250b" },
                { "gn", "80e0418c938d05d20786d87a23d559f9caf42c3c73df45d0fec4e463d9ea5bb1653a7cb413182754117de6ac2ca179e1d031deb5d28c876960172098b41b1fb3" },
                { "gu-IN", "89cf855175bb112c0a67580bf15b95ac0343a8d3dda62960af19207151736793fd40202969265b8a670b8d86a42f67a9dadf94775e3335d6a402108109708eda" },
                { "he", "3dea8c2a3db00a969cd50ff88507e215dc72d6aac9c527b89a0a9c65ba689596ca675379e93d4466526edce42f6835aaf0b59cbf4bc57fcfbbb222784033b1e7" },
                { "hi-IN", "401858469e40b5e1cfe852fae2c015ea26ef1256b7439583fcb21aa2b5cc0784cc9058c97df4b790f239bc237e4e0191a0782afa17e791cef92d117a050d0f10" },
                { "hr", "6958dfc4970d9ad96600832f3272edd8c6a5e02a2d91f867a5abf8a3e9536f89a6f2916dd7d9c84560a3c126a468b3f241fafdf8283e5f1483add7fc4474a181" },
                { "hsb", "2ac3e7e8a2952a701b0b39fcacb58b4b6ac77ce11edd2cd661a9f06651bc1baac180408e6b428feae0bf90b4baa7897845771851ee91ab1479200f4759a2314e" },
                { "hu", "c42c5d442a40c191b6ba20902390e8931742478f20d593cf4de89b4e15d8efc162cb7527b07074be08315142d8d429cd3713212c617a9427c5e24f0510802d40" },
                { "hy-AM", "fc0a0b82a8c9f6ab7106ca88d02d3905b2860c239b2b722e9fc18641f4c114c2208bdb99e94d1e85da86f2a25c71054dbc80c0204c18f15e516adda8926ec2e1" },
                { "ia", "71993dc5a8fd8dc53c0f299789a14a627980d8d7a8d55aef72ef86fda1cc04ce88f505297e0ed319d33b873f99aece38df0d15b23338725de50490880ec05de7" },
                { "id", "43f066d86724b8021d4dbcb045029aa48ca381ed485473bebeb7713877fea4aebe4fda3a90700909574202200b50c8bb6b10905d4aafd60c25e24d6ba37c48f9" },
                { "is", "9b4a78c77d710ee96c605b0516be9a11eb286483bc7beca0c07957ab169c5f1ae8e5d5f4519f7648d6ee6aab0232e94d41c52292d8d097d3f8325c2e497618a4" },
                { "it", "3f8b617640796dc10a1d8d29a2ea97702ba39c932a109fc538f5dfa187f44ba633e52bfcfa5b9cfc7b56e067fa828b6fee0ff217415c7700ca984ff7796f9754" },
                { "ja", "9e75d799681a38c490d421458b24735797b90e72ffde934e24f9ed1c4cb9eb710ea1ae3d2151cbcb18998f51722e4c71ecab0ee1949942d219d3c362dc3e929c" },
                { "ka", "1ea21c7e950655bcf9ef512b6394eac5371f1d8f94ee9bf237aeccbdee95b02992b86cb96f06f61bf110f2cb6431cd2997a13fd1135909bcd2bf05583c85f55c" },
                { "kab", "fb6604a367cb96df00e5ef037d2cc5a61386c358ca456ed6fc47041fa1e674071f131d0f23683d9c75b881b988fe2331831b3bea72a31ec636dae8628a535ad9" },
                { "kk", "3bbc78f68ed35398ba533f96c56e4d986dfa7dfb174f4bc7432550c275b4274c1b8a600dbc101846b20cc8267728e45a57e4b3f9ae6576aa8eb9ac0d6ef03e33" },
                { "km", "fb7057413ddb173ba60bdb132dae6554fa073ff876336b2b473714933a3af677d7edfa66b71a500b9a18d40ed4b7df6669330d31e7d8f9db5800c053ef96eb66" },
                { "kn", "b8de11f40c68a7cf7bcd229837dac470e7018880311521c475f7eb1dc828a6fec85f3845ee2d3a30c4b698b9a7b12f3d4634f623f7760401d9d39ca5fe853f83" },
                { "ko", "85cb21aa6d08c610a989838c0396b57fa8c59435952e26c7f3b8b34379ff5d6e723dca7a77587f7e2f935f32b436654bc5665f57e6b1bc0ff10eadde00c48845" },
                { "lij", "7e53b48886616e83dad783441e63e467b91e81e47d372fe8279690d886b16d93c9527be9b30fd84d87668064fc456d980367137adb85cf7a6513a934b622b1c4" },
                { "lt", "3d3658abf6e6d6ac44b5035f67c7a3932241cc7022e4d41598ca9b0089e664576418878a1ab0861ce7248591de8b6ec396c0df299f97a6f8b14d5829dde3031a" },
                { "lv", "5f0560d8d3b60d6432710984084b1d5fa0fcf028633d15c7e4bc8188face523e8a06c3f6d54dca262b995662bc42d7fefe6b8ff508afc4f5d7aba71936acb9b1" },
                { "mk", "a1968268b7e6163d14cee557b4d7341a969a9d6d451d5307a10c664b90f725e13e517f7036c1d442b1926ce8efa4c2f5192d6a63e47d137714f4dc5e71ab3c46" },
                { "mr", "c40b29343961bf03b9e653142f90764435ebd9bf46c4a60b4530ad60c51c6f5f834216236e202b7754c63071ec8698784d32a27062fa6a4621b31ee1f44a99b9" },
                { "ms", "2e825c8544d8f7ddbb29870aa6b45f81b099df6ff544de81ad6ce4fd9b8b0405bfd08c568bd03b7af4caf01293e00ce1ec308a933e6cf1edc99d4309b8442ee7" },
                { "my", "b8b99c32dda1fab0a1bfdef874d70ca3072eb5534223d850ec043f4a94e9a600bcaa3c44a0f596a8f8976b2fec52cae84dbf944891e3fb4ecbca7f5f85f029c1" },
                { "nb-NO", "e872e67bf72b18c1cd471be66bc19a3e11325c52ed6e98edc29abec4c0dbaa73329109f62a0d872c08ba11d8f4ff1d61a455d0b3fcf5db66ee7403d14ea09f04" },
                { "ne-NP", "4b63a88253afa2f2207835445e3e7c40fb688d8134d00daa682fc7876ffe7fff153bcd1f72f7777376737bf757d402dea663cd18f2d5803f0e08c7380c7ee4c2" },
                { "nl", "478945be10550ac67a09f9985c798fb1302b51c385eec8c7c1d0d8eff15c6f9c4f7a409727d0e60ffcff671643dfa85b906b252382baeb7f899750ca45109416" },
                { "nn-NO", "d8e7d0c9c71778ce66e15a1eedd7d2afff54e559e8b15f016d4ce568acba0f9a80497f8cc86e04d75e944076b059644dc1abda98b57b93c52f686b757cd4d228" },
                { "oc", "e08182826dd2611c175e8e7b44a2a79bf0260a774a13708f68135b6c5ac9e14a5efb33399caff07020bdac6b6f78520c924b5002aade64a39eaa7d844264a79f" },
                { "pa-IN", "6f043421570b15232510e9c99de21adf1454cf634d9df1a447b1cfe137eb82b99b426350ab35b933eb77dc74a8a677198757621fce899529d488168686547b17" },
                { "pl", "f08009ed7d63a93ce585207777a7dac3549e27bbac4d4bf4251ae8efad874bf4baae232ecf29a1a9d50c788bc4d3438a91e7c5dd284866327238e3d3f5aa9222" },
                { "pt-BR", "b75cfd8216c24581201ba082274078c35088186364fffcb2c402242659ecca0a300d616dad341be25ec5d4878034a48b71378244831931c9cd83da578a85a193" },
                { "pt-PT", "9b4a159161d4d7639466da0112c2dd2b1c4b8ad92c48bc0bbf96d44a3daa9e2b8a414c1e9806d7d8b1636caab1ec4e5671945afc400d9178c9a1d51e5c842b8c" },
                { "rm", "2fe270e67c09b4e8577f48a5620c06b2ffe31946e65f43318ed78944d46ac2443c0af658676b14550e6f35408a02d913241147e893dbba3f1345dd9f46d97bd3" },
                { "ro", "8abc255fa7d467cecc92e2003e335706d329128a77d16c3a63a00e26d396979ddf2ab2a21f917ad1875cd65725d7a4be041465246d092154171485ed10465a36" },
                { "ru", "fbd5f23d14b185c8fbcacc2e70b5f016c68526aa42bd8441933426b873deda93e98292b669ad2f6a16be379a38fa63bc01900ecde26fec12ff08b72fd0cc9d52" },
                { "sat", "18aac9628a7e0e3af62dc310f46a984b3199302570e98e4b916df54a0350cbbd4753600815259d8ca6610ad401dca519afd06a903309645120efb1204200cc5c" },
                { "sc", "33ab358475537d85cc84e07575adf471c4508865a99cbba8b464628d58a30465ba784d420228de14e58472798fb239786fe25a791b8c5410400bbc665fa1b140" },
                { "sco", "1d767109bf1e330c6523eb576f147a77e49a5f5b74afaa81b6bd9fe2d8bd49f9e3ef75594a8598c386527405abd283b83c54cd801207199494b3e9ac2b33ef6f" },
                { "si", "8fc45e09b69f001b6ff44d52a7331abab4525712bda852cae075abdd4acc03fcca2247c30bf4497d74f88932cff1439cf54d6e7e70664a8a24371e52053284d3" },
                { "sk", "e7bb484064c91a4e988d8d8ecdcc94001df2028cb8529e64071953624b8a69120768d084c188233bcb988cb71ff302d1ccb04ebbf14f8ac5baf36837f25bb0dd" },
                { "skr", "6aec53aa49f3526cf756bce38b611c2c69df62c0609e7fb17b94d7d76bb06f7f9a5b5d7cc85df32d444cd5813a6a1a26629b94f8b1da6a7e169a3336b4554b8d" },
                { "sl", "06fa57674a418a75a94bd951d0ed79312c1a388500081a4180cfaf333e23223214a1acf24de84dfe1f5245518255d74d72eafa3a1945e0ff0c4f6c241fdcc3b8" },
                { "son", "4d14da000f64e85d76ab808787b35c3b15797070666134b4e9f2bd3ab306cc5ecaab2ad9acc675bf3895e1d15146deb5977a37bfa5540dcee4e973d344a42f0a" },
                { "sq", "48a536a83de4a728884329aa91e21384bd6522fa2f07185a8a4982216f39f3a008baf2cd5bff3f7eeaa18b5a1bbaa856301969b44e0f9b4837b273a0d18d0499" },
                { "sr", "d00f5555f1910aa9725cf894d2ad62caa744a9ef5a5f8aff843f05a96c06ac9d162b9b644a43e57e9e00a97195a440c21d8d397e4fe4de676dffc3e70c2d6db4" },
                { "sv-SE", "d8edfdd4bc50c9a2c9abe793a0e534ecff8f80b1deb235ff228783d21c87ae5125a0cd1279bf5f3940489487bfff158059cfc0d4172c6da5d3f16a9762743e01" },
                { "szl", "d7ded9e0e23352170b33e6a5bb7a1ddc6bd331171dfd24082a89dc78c3346bff3e0c737b8dcdb5691fdf931965db6865907d51a0fed2768e6f0adba2c17515f1" },
                { "ta", "48668c8ea900faf9b4fb8cc3862713ad4aaa8fdf7c24520ec6ebec820c7bde4b301267cb6ece53d1cff70049d10022336d83b53f7fe1a0b327bbd33244a067bb" },
                { "te", "049546df8bf3ac33cda4afeeaba40de13e5cd2f7c34f168446c4e92af3665c77c502f8fafbd747eb4ff37fe05129d6efc66768c4973a031036703ea7583ace55" },
                { "tg", "00d6d32f91dd472077f6a261a9c182a8567d1a7893be8f1ec5a456de8ff05d45a1f50fe093cf44e7dfdaed2594e7b7cd7eecdc6774c1e9fbbc1f0e1097f0ae29" },
                { "th", "1afee1783af6f8f4841bd6164ffd3eaa17d04b34a382ead8df104f0fae18eb0cab7e3407e2648eba9c04835dd7f7f2c205f00470c2ac8f36d61c2ad8df109d8f" },
                { "tl", "31b2bf3e7b4fba269a9af1e234a62e3a337003935ba90cb739c0bb6ce3ec62586b790616a09df7ddd42ea177fd138b13ac591c91ea83163dde2261104ad975fd" },
                { "tr", "2d3f3fd240445c1e738bd74ab64c554e6405915dd15147e032596e2a729ae2c1801cf215dec233d1376558969b59b359059d666492182fb02cf4966c5353e4b2" },
                { "trs", "ff70390f132539491b511ec39cb43c68eb14ad1c7b0147893f9ab3790dd134a4243072a192509f32471bed5f90587b6f766d0603fb4df046bace960f15705739" },
                { "uk", "3856cd9ea851812ab5c6a2d672a7ec743bf3a642dcffa6a808f33ec082fb903e46b3a44da143b22027f6ce7c9be70587d629626e4721a72eea951038c038ecd6" },
                { "ur", "14a447dbd166c9abbb82f4683ef6315dd909a40a576ad52a7d79feac71977c0bd4b7df49158c63000d47202276dc5950249b6c91375c7cf934d5b419a16f62c6" },
                { "uz", "439c0e9a979267ed51bbef76582e52b3de73d71ff988226738bc0905e71c6b12520675f644738d333bce307e10596731359aea217f18c494e6b8db18fccfdcbc" },
                { "vi", "2c32c88ed0d841791db3ae10124ffa2ce8507713ee55e67d27373d043c0d291a2c050413943bc6bc156a8792c5c2a369e86f9ef25ffe784d8f678e09f73d7016" },
                { "xh", "cc54c2cf80e43e6ed4b506b5bb77e2d24da5d747d5be45eee84f497bfd01630c9f03fb40ab6d49e55e94a1a990491b9d03369bc553ec522886d766623e6019d8" },
                { "zh-CN", "3fbdd6722c5485b3b70c689aee9302b73dfd2f3ced07c4cf23495e212f304177113e96217d076a5af7bba7833208c24959f3a9a1cf8203b48a67bb5d26236429" },
                { "zh-TW", "1eb8b30c739c420d933b87a492d30f77a039884b504f1e2533ed5d30ece63f2a1954c8082638eeb352e37d080e5601f4f55c5d0c8ba2469cec4022a05e663353" }
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
