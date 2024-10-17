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
        private const string knownVersion = "128.3.2";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.3.2esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "24b9a13ac74d132514cb19f7c3612075ad1f8f0b7d437710be3b4a82811e7188db130dcd9d9848ee889f9bc20c2ff5edc69d359dc6b126391cf59ea9010df8d7" },
                { "ar", "2cc9e7b3ae29c7322ee5b43d8bc7971ea12a6354b837647fa70c319a0d7be7f359ae7024decb264a427543c513b476512938d03760363bc87f78946d7ced20af" },
                { "ast", "8c09a55a5dc12e5ae677c502bf5fd3552cccadf2bafe590e46e5543addcfbe048a11e3144ba6b20e51053664b7192a54595ace69455c7ce962c6620bb075cac3" },
                { "be", "7092c2fa34e7ebd78c2f2fba37091f08936844be38961f0183ca33eceb7e9090c1b7e7aef2c6ab923d80b5fcd6aa703c566ed796c440b3fbee00a277f218e41f" },
                { "bg", "c360affeebb62fe071f3aac549730e4dd55e451c4f3a995e54e5e3d448b6dac42abd20df151ae999a4ee91dbd34f60d25710da827f7a09fa9b6c0a00ba9709a9" },
                { "br", "f99b39e48f82fac87a15d2e97f02a147d305dbd0616fb93186d427d110f018823cd3dcd1892e6948ade1fddbed685bee5b2cb223e40e2ac0b928ae19f8ae025f" },
                { "ca", "72b2c41a7705ec505560816eb81267c32218a83d947bcf850c1dbc4786cca53b201054a14150f8118170ad26caaecaade74d79fa306ef9677d833c3f3e75edf7" },
                { "cak", "3b7581b0330f7224f190afd909e3aa10f3c2ae0af79afb49f5ddf83912ac44de57461a73682e810ad0d556a93eb7188d1c4324bb2c1088d91db52f126eeaa71a" },
                { "cs", "c80c721a25f836df7d1db1572da88faf3776ab62c98bc8be173c29bef5c2cc01f13d4e4b4dde5258f39c53617856157f3823337ef6e0aab70f86cb03de05a883" },
                { "cy", "c245efa6e68faf982ad22dc46319ee0316a7040af78b1497f19c3122a3d0e51c5ccb210d4708b72acbf0c69bc52a04fa663de3d22c02fa26c04fcd79a658f842" },
                { "da", "16f5560c9d5a743e4475a7dfe60e383616bc7a133aec506d721e080c3bbe268994596da7356bfa55d2a1e7555fe5152f4f313fd5dd51c204140565e80283b748" },
                { "de", "394a02f39bbd35e7cb208bf030a7966bd0614a46cfd4b573fb5d38fdf9464abda25cde41a1f154ce11f12f21d376ecb05c45a7fc176787c7b1df76b7de006852" },
                { "dsb", "e69b5759551323b97ae6aaa513abc88eb3f501f77102e0ede6c008e66548637ec60ac7ef5a67f7c6cf761fc4cb3cf9a3745023ac47863e22fce9562f226d29a6" },
                { "el", "533ec49c30ec4d2971026b5d0ee0f80f295cc3cc44fa9844380d8a8924f25c00c6c849559d5a5f4eac8bd07c3a65ec98b780db87a1bc02d71944009ede2ea685" },
                { "en-CA", "73b02aa2eb671b2673199fa200ce679d4f6f12d086ad94a1495a18c5715040ac4eb34ddfa6482d39ce66e46918ace1d9d06c8aed50cd7a61e53d84758206819c" },
                { "en-GB", "9697efed8eb3b9d2a64386d6f411ee5604d7ddb366d4a425801a5506800d744b67fbb874183544fb52e4bde0403204dc12f4da8759e321b478dc2153b6db4477" },
                { "en-US", "10d4b98341e544dc00095d6cc5f72ba3390daac8e4c27017a79bacf5f04c60fc6a2c4070ba8a0318d3f055f3031aeb4d80e7a9472bdda23e26b5a00d0700f20b" },
                { "es-AR", "198c7acf67832df70427a6ebcef72ebc768a3429936860e4063d899ad6b79fc0598bd001e91fcd7a21640e285a604ade82ec8f20594b806b11a8ec48d04e3664" },
                { "es-ES", "d7d8aa172a4bd8f0c0e4332c4727cca2037b8b102f484982ee539ea1e3dc7239d331b61210071fd4d70545a7ae281e45af4728cdc22c0b92c56bf98e51cdd96d" },
                { "es-MX", "ff59610022499c35bdc2b159da94d70100d9f29fcc6d1033ca63585c597b6b93a8812010973c3f94ceb554252075432f96e6e57b7cb1077063b64d57c1996418" },
                { "et", "e8f5a20ed558e8c48076f9dcc5f425e802e713b80118d3dededa556cfcd3035651213e6b778b19fd5cd7c8608bea28fe7df210a2294e17fffdd87c2257c169b0" },
                { "eu", "49fc9ab26af6f75b3249a84b9e7912524b9544905acba9d72b4ee230a62b49a26c4de21fb3041158eddd7947d0bfdfcccfcf247b61e7074fce3f29f464b4f1dd" },
                { "fi", "e6f4f8877fa110db0815232b7ba729ad1f4712f60d05a3614d41c1fa5b1352160f7082368b38a44adba89328483513e8b84bcebe5a5d4da7199da32c82f04cfd" },
                { "fr", "155c0db35ca2e3d411201b3ab064a63ca2e38fc324bb1c32a91f504f54467a5b4538fd1b937eab3f70dee94655edb9f4d49a7ea45bc6c799ded804b42e3f9158" },
                { "fy-NL", "eeb38e6f32dbc0b88e9017f23a17878a28efff224e26f47ae02a002fd8cd1bf4b88406b9c66bd6cbf5b83fa3e0ff033d2b071915ccc5c628e360a92833203c56" },
                { "ga-IE", "be9b20ea8df1b06ad66c3689cba35b6475602efee7071d955c9a4e1bc9d2e3b581aa92880bf0c32a16219303b165d6bfbc34495550a40f45f6ba4c4a3112d773" },
                { "gd", "1569191e411a8644d3206f5e92e4aaf46a00bcfffd01e48cc28034eac3c49e9d17c62a5cc1e2e59bd3696f0bd678c37f53a57badcdb17b9272f045599dd3cb1e" },
                { "gl", "10462ac97ee22effdf89eeeaa4ef775a97598bc67711f38f22ccdb869fc25b719713d39b8b799514a0663cfada98758461c05c3a8f39f678a1d63b5add5a7511" },
                { "he", "2a359f64c1b1a5dd3b8aafe5baa7632a51f6fca5fce938cc3ed3b92d1db42f1b722bc855e3a61e764394157977716cb1420661ecdcc3afe30ddf264f85209b27" },
                { "hr", "0b2a3833f980f40cbb30a7621d276b1e5d5ebfa2165ef448812a5a04e49fd5caa13bcf33b5f904cc5cfa0f0ebba25009d55a94534251782c680858402e87b884" },
                { "hsb", "59ac6e0bbe571299612ff4ac5e80857f613c4659714c8f3f1c12a3744189a767b99cb29c440d1a18a37e155bd98e456f8558571438e02eb0704e4f39484e54f4" },
                { "hu", "4d914f11510dbeef1f3c236e60ce9129f3c0d91f7b28ce82c8059ba42dee4b61cfbddd2fd9f97ec4e4b523c131ccfbd701d5d4e0cad570ab126544f08bf35ff2" },
                { "hy-AM", "eec3b0294fff2799e4ffa60198afd80dba2969363bb4c8260916593d78a0343c1956bb21e3fe5ceafc9a48c337972b96128d6614eb47956b90ac223bfc996a75" },
                { "id", "67d6a8233b3b4dd32b965924165de81143314effa17be1568e915547d3326efa25b1efac53409d6b2c6a6492b709fe8e342c97e79ef3b23d43bfe04cd4ac1100" },
                { "is", "123655877912c03553da6fdcd3c462095d7d15886f1415e4bda012ac066fec4b163d31248a1ceb501544e53e11c83ca42fb91841c0afa584a9e5ecaa734fd407" },
                { "it", "25dac78063d1d7363b85f3b3c5a5713d71b727658850e373263f4a56fc8bfd50c05fefab2b258c3194110cd4ea8d7df73f280b63b30ece793dc780abfcfb7909" },
                { "ja", "73b0ef03d2f1a136ffb18cad28a0f31b95aaa5190f61f98277e9f2d3d627142901f8b9a7cee266a255bdc40eaa949d555de216d26b73f7171b73e24eb00faf2a" },
                { "ka", "8856dcc08a50dc86fe4be8b46e6c9f5f3c831c2631682a98af684daa68962964d787dbce239007f7d58ee7489d8425f07b831acacd1a598c5e4b16daf807545e" },
                { "kab", "35f151c8bff6b8481a62b5acd6651273345f64a023e197faf3acbecec846dda368fccc020545a54d25255c6ebda6b44667ee0d051da0691ac725755d7f516885" },
                { "kk", "95bc08a47a2d38b283f11381d11823c9e61ce57613df1b5eda9b3ee54d74656f7241fd4988cd2b45083fcf6d73465811eab5d286aeff5e60b74be26feeb9ed33" },
                { "ko", "ed6fe4be9b0a3f0a301ec771ac75a9c1395d8cb3041a2d0c37fcd2a9d35e8d8581279f6f34ff2c14b1b108ecf9eafe40e9f5942a9826188b894cf763bcdf7915" },
                { "lt", "129e1eae0ab19e630299d50e48a367e5e99084d1f4831a0b74cec769d4c271b923cfd80a40827e203cb9c72a9d55d47ebc6338b429f858af16d24e60df9807ce" },
                { "lv", "e0aebda8e67c7df8c9613387642597f578d635d8dabc60584b26da376659f2bd244c9281080332941928eac237569b60f465f23270873345350db298e058f5c0" },
                { "ms", "b6130ca2a629c04971369d336cf2bc549ae91636ed4465d80334a918ea6aa21e944f507d77490b798daaa832a9773394127d84936ee00519459253b4bb625b74" },
                { "nb-NO", "aa1d91af86ad8b61f6ff9f3ce246b948cddd795a3f92ea67313204b40b49e0f0ed13f2154e87b368a06ef8c7479b4af313032fb9dfd7f0a89c04a8c4151142df" },
                { "nl", "40594fd2611ed7cccf036c6341bc3af9e54508267b82a52d779b5c3ce7867c63733ca4a38e7b59581ff15ebcfc47f9e2f0624639be958e32ab197690430f6fdd" },
                { "nn-NO", "ccc8dc9d5bfb78bc84285006f44cbd356b3574ff3a644b6d8d41c840be734f783178a938b948a453539fe2f93bb6e7ad4098c5de6810fe1a20512329cc940ecd" },
                { "pa-IN", "d51b2fec67143c8e55499248b9a5243faac35ffe9fde02548e807f005e3f23f2072a43c3d07034f09a04724853dc0db3a00eb608bdb464eef17d9a53d4c7a1a9" },
                { "pl", "65bae56bb5cc05300010712ed10568612325d25a28f394f95694927e7c4e9ae173c2ae85c8f01ea3bf6055de4dcbca6629e1e175efa1f4547616eb30dff9cfd1" },
                { "pt-BR", "8124d1bfcebf4e99c867c38305ca2ce1713cf8cb3802d2bf8f7e64b97878e3f3b27758d423109eda4b86aa0e5d6d72979892ce8898b2e15a1d2e18ea165c8f9b" },
                { "pt-PT", "0c91c862332c0f0b8caa05d833091a97d7f57a819d45894d59bcde22112af5ceaf71a90fa87d24e426b0b000ea97b239994cfaf1a140d2b70aa49cbc46687f4e" },
                { "rm", "5ae5f149221f915caf351a650b1cf55a1f4b3612588efc9cd28788f95571bd6b1ab45c7b95f7006a491a054fe6fe8cab5a53c3d8640f3938ec46bbfec9c43746" },
                { "ro", "fafd16dc62e2f77dbfdde8e4b5524055fa5012dec045d7f6b12a63ab4713b6304470222f6f4a0efa7aa8f5b86defa98a8b26554b303e7c36013aeeba12762b3c" },
                { "ru", "4cdd90017cf2c0d304205d1de23d14c431339746942b0e492134bd6fb3d8bf656177fc9470480738475c1460cb3287d3b9f1c4c716cbe64258b9d10bccaf738d" },
                { "sk", "5c795d966ac99ff7f6e3c01e11b2d4c5bd2c6000bd11ce9bb6ad490939a2f12eb79dc7d59e452e1021bbe2a21cc9ea4e39b8e2a3c0e4790ab8445978d8e2aacb" },
                { "sl", "d2159f8863c5cd168fbb98e290f977072f2156cc2ed74f5b6ad6c096ea1a02747ed929fe8e64a98b3f8b18592281853e502e4339d558d6f3cf06785e9666f720" },
                { "sq", "f3d71c5e0a2b5e5f3f6553a9c45494cb40d60367444c8835c1da90592b2db78c53691d30f4742e6f2228caece2e792b45d6c2ad8e6e48acb9ba278d7960c35bc" },
                { "sr", "8f1e3d2440ed842ddd90baf395a071811c564ce0d52e85d83e2671d87316f464e2273b70ec178d2c710974e85d8bd48b6ccebecf94aea7c102b9094a26531d0d" },
                { "sv-SE", "bb62830919caa9681a98c93fdbcfa10cd6c5f9b2ec7456e34d3fe97dc497def002dacd077c8bf4f90d22097b3a1ac93d90f207d912a4eee1ce30a793c35df4fd" },
                { "th", "84cbfa846ef78274c5fdd9867fba89563fe1dd965b47f68952a46e9df2deff57dc89c18afbc31d5d38571b55589902423a84c4d5b69a3b9fe53f779b49c2cc4e" },
                { "tr", "4f813541db7d7ba7dcdf9277dfba18d22a7dfaa106f1fea6d2b3670f8df4d0d2c77bbebec1ab9ca614a685ec8c9cefcd4f655cdc5bc2015de129f5c9fb55fa92" },
                { "uk", "a4bea4654c80f5a46912aa5f379191ace5f9515c49f63923944bd1d488bb875b3ce4ff9e52bdb666fffdc735fde701e10a4a53c806fab4edf7b249061abd8d0a" },
                { "uz", "19fde958012edc6f2452bcf6a9a07f6e906f0c565b406b612b7f4d196c079db39670facba8e5b9ea2d80f22b8d7a4c69721050430cdb00727f06d339615e8508" },
                { "vi", "fa03908604a3831f8947a829f2e1707e225132447f2dca0ea3dbe526df43118952f2ea3af296584752ce088050ee1c0aff741306514dad3afefa11027924a7a5" },
                { "zh-CN", "fa2fd1680686e8cf43fff6e4d6aa492b9eb7ac953375d4efcf16e925b77f5cc17991b9c5a22ed3de5edec3e55dc987155c3e2990f12e1d491aad89e512ed77f9" },
                { "zh-TW", "83327a9b997d5f68cf471dc611055973be0d40100e5976edd1165238e27173a19804096c15b2ebfbda64262a162aa32ae44f41b7bd3c8fcf3e4008c7e6a9dbbf" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.3.2esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "09bb7d5f060850661f58d941f39eef8883ccde1c101d51d5bbff5523185dde1d838c01532ecc21698bce47bbec978dd85599dd4c9af179d53fc97a0d324c78a3" },
                { "ar", "cbc6788d6ba92b67395a4a23ea71ea11659e6efbb6fe21886bf8bfa4df1cb16a34c0e2c818ed21c90215549c10986d97f1acff93bada3484c64a2ea3b18c0b88" },
                { "ast", "3b50e1dcd12952f7dd0e23c9edf6618da6fd5636e0c4074a8234fd4a5cc445dd84523803528881a0e50695f00bb8e82f28e19efee1889f66becbc80009e3f053" },
                { "be", "51ff5187f614a09e5e51fb44911e03a85c688199670d7410b968b833c60dd3222f550f7db80acba44a654bbeec8a78513ba13a366e5f1010bf7666bef3d2c0a0" },
                { "bg", "1086e7e7a9bb1a76cdcbccceb444298ad3974b737128bb0ece8708f548b7aa28a38adc9b89e80945bbdcf0561ced8a75fe3dc00b6d5516422a4819dfc0259b14" },
                { "br", "7e5267b9057ce2fd21ff6b23f1b9f4473223c8215a46181c6c6570c3c05b7c51addf6cd50accdcbd12b06d6888349d8cc0395d7418b5067727f5c08b588c7ea2" },
                { "ca", "66f2cf9115bfc257cb8a5741facc04885fe8f1ebf47e54b59e4489c3910a4451b482029ba16f71ae99dcaae7ee42c18aaa6035260a3bddd2bd1213b8cd6cd81f" },
                { "cak", "ba331d917991f6a33750500b0ed2cf65918da6ad5bd5cfbc9efb20741764bd36512ea982d872a4536149666e079d685aa49f3adbd816b422f84e402a02afd587" },
                { "cs", "81e8ef3ad03693889a09e5c0261e2855a61193be8c2e5a5a082b5bec89562fdb6ecc64a9fcc90192de8e0917e3f840f21759171fbef06cbad6b4e82bf46d1b4d" },
                { "cy", "03c0a010e43b66cdb238ca868ece897d15ad2449200e6ec1cc8e459f9528bbdb11e8f9248f252fe459cacd4c2a74e6ac13beb56f2bedbef369a7cedb97907040" },
                { "da", "15c2aa61979b4b8f97fa643688b9c6d58d7a33553d20a0d4d6a5cef52f36dfe65ed92fba722c94175e0d949d322a636d5f9be4aac45d841ac6566c1a5e3478e7" },
                { "de", "18eeabc03dd8871219924c37595cb5910c3764cecdba5e5d256b98e3546f33036606f0eeb47f7e2c693b473e13884ed7fbd72e44b989be5bfd9a6f627efa129d" },
                { "dsb", "de9b01e1957b7c4dbe5d3f9d884a30e1e5de5d27733f631bd9575e710ebc5fc63ac7abbb8d341d450404cc3210fbbf7d577c6107a7b47b9a828717e066618d5b" },
                { "el", "9c45b208b3742571a2272ce63346faecd1657975855fe63d5df4ab91d174f4f9c91df2aa04609a0c0676936d98c12d47796b5a58aac8f5117cee60c2dddd2438" },
                { "en-CA", "14ad1af8837b90d64167192bc38d4d0bd2eb74fbf3ed68fb072416b9b93cb7332bdaf82ad7860dc5029237fcf4ba076b8f0f604a2a428f37ee93a6fc480b26d4" },
                { "en-GB", "943415b877422704aa0eb28045ca6e9e3c1f45369ef7bf39997617645ebb69719367f9b8de73390bd79d66ea5e2cbb4b189a25af4320ec1c098ba9918aea8244" },
                { "en-US", "97476c4901efff1db3f93f327d35d1bffc759fba2e5a253901027aa8bfe7629eb9e2216c6347259a5f496eef872a133d55649c51ecd1854efcc67b91b5f6e83a" },
                { "es-AR", "2367057c1c458cb1ad72325caa0634d6d638e9f3efc9c88747dfdaf55a78c61097d3e97829c418e9466294a3d2b5c2b1276cb9953a9d0d92ea5cc76e227aa321" },
                { "es-ES", "67b01718ac13e91bdb723f95d4e8a4f59ffba8e3b57064365d4c84d9444f8ff401540d7554bfdc52fc07a7f0b201465fc6678819b13ff8f4573f29d43a37bbd1" },
                { "es-MX", "957acdf1358b5a30d97ea1bc8be23edc1d37c6d35a28bd3c0754aa982274a673da0cbfbda7204b01f99b1d41e786d63b855cd593b0f06ee277bf4b55b75cd8c0" },
                { "et", "f6b055705ee2bd946eece411fd54f45daac8aa99e7e0ae2907cb5fcbe8b41efbdaece3dee1b74e9d2eef9ed1b985b8417608556253f8435cba921ea50a742cd5" },
                { "eu", "0251bd6f18c6afe8794a3ac960b2da2ac41cfcaf59ed7cafa836431cec60adc9fb3cbde8addf5ce4c0c4b6fe33e6f4a17bd6eccd133547cfc19e199d8403ffdf" },
                { "fi", "298ae2c3604c9389f6a7d339fb02db07ba69f2c3b0012910880a315def91cc674df1c4079c533d0f7e8870f0f42fba44eeb6cdfac0d2d19f90fdeacff5202650" },
                { "fr", "161a22741e39696203462eccdcc2bce50bd0ac813e4cd8c540e2a3500b8cc174fc7fde7ac4e6506a3108c2056d87ddd645df24cb5ae958f96201cfbc763c89cb" },
                { "fy-NL", "2488dc78af870e5b3ae31d438461d314c117228344e9249952f21cbd5b5aec67adca04aec5c380c93c0ee71f5b8b2ac77ee84245a84db74b4e97b71ced6776ce" },
                { "ga-IE", "ef5944f12a9f4eb1e74d56d60b8d831b0833ebbb1d9b319c6e62dca17f4bd63ed219055fb31724afc5b8cb2a71237ab1752bfb7f4c76b601ac7441c309bc42b1" },
                { "gd", "cb31fd9ebf48c74e47d30f5379baf643f3659d9434d5b592f18bc91f368497dc857796d2f5f8d280b680fcabd9c324c4d68f47bfef5cf2bad98ec7ba03bf990b" },
                { "gl", "76ab688edfacfc2fb2ff17d4c39af7a17d6ba683aaf919dbd29ae243734d914d9746b7d315f22fce09dbe0bd713bfd725aadce61ecc2dac91c204334f77c8524" },
                { "he", "3d9d866e787c15f75db07fd87e083d06252c3cf169b94bfd17de98032236b79ff1443a6315db5b496445e96b90ffe366c60c843c8032534a3b7c4f3a0431ffa0" },
                { "hr", "799104c3abf73000e40697d8cb599b961e6bff3f9dbff5dfa5c1019acd67ba44ac4738b519fcbd4be5d1a3b5158ac1eecd1cb772c116f601a90f5a50ecf66e05" },
                { "hsb", "e71e2e3e796d4c3fa8b526a5c475cba614a545e21d855742df52cc2c60aec233ed2795ebc02c22fa584c0909ad751d7fbc9652a9c636231c102aff7de06fcca4" },
                { "hu", "68977bd4b4efc195ba6e640b29bd08d21ff3393d20362da45ebd71063057b09c3ec815f301760dc4f4169ade5b00d51a0db1189cf4871848c1c2fa3b157a6727" },
                { "hy-AM", "11cf73b8b5dd1d541938f3457878658af71da179d9baa3cfb5efde811885aaeacedc3143ebef915d4c904c3b24232968c8caae88bcbe98768a0b3b1be9882ce2" },
                { "id", "2b5d86d386817968207e7f25547840d1212c5c0dff4a171bc123774420aad2dc1e8db861f12750db44b5f1accd8ab18adc2b2b7f5c62a212f233ba4eea9e6733" },
                { "is", "dc08b65104ccfb37ac87b0ebbb63ae796edde73327133da0146577b680c2e6f26cf7c60f50943cf650c5e904087e6eb52ff431ebb894bbd2d9ef520bab9f59dd" },
                { "it", "33d5ac5a1f29a19615b4212385d5ee65fc5968ffbdefa41c461e77690a370c57b8536fe28ba9b0026839d1f9cbb834b6a51c1b1922d675a0c6d3c0939cfac99c" },
                { "ja", "960db3e12f28a197f540927cfde35149f3a855b270547ef1eeb2a286684b68645232ddd7dc2821184033b80b8eaa3b95f52c341574ea69ae27500d144c24ebfd" },
                { "ka", "ebc3f5a2cc2763530666d3bf8a807183f1f7ca6dd722a7bc29da597d9d026b72e77562c553009cf5c5a0247bf7384dfd2c412a2a020abd9da6a6e2d844367878" },
                { "kab", "29cdc576259e9887731e7792809747a354ddee40369c1338c028e382038da08a1576dc04694dada916394e46e1a3c6dcadb39133ea8d0bc1fb9439cafb5cfab2" },
                { "kk", "9d208f556d3e52007a394f22b0126e4a8b1ef3c4c3bc8830e1360e812f6a4e47e1f7e2db2f10153486095e0de6911d785dcaaba1ed027da12839e23944c0de0a" },
                { "ko", "93eafe7b2f9b69600c52b03064ac98119539f22b66223109945fa024f15d0b0ea8a2e89d2d4224079bab2401af3fada0ce820951abb7019f4c3bad1143bbc3de" },
                { "lt", "e8a001c6df6edccc9fdf8d625279c327996ce62fbd05dcc541d2210414b41fdaa7e0e2ffe0996f4bf49a0de667f4324b94d4eb089d23f8ce5b885bf760d80ca1" },
                { "lv", "f8a2bc1844b83b3e947a3a323442de852c5d7ad163b57e2ea321efeff7f18ab6a1bc2093f001c0613c51b474de75869534750a80c31a29faa32f6377c62471f2" },
                { "ms", "0a53fd382ada167294befa56f003daabac0af3b40946d4db19ed4f1532ec91ab5cb92a4af654fe714218d0bed16cad65df05657278b71e79a6fb345a358b1c5b" },
                { "nb-NO", "391de88f266460c7976accc4bf4d10dcf6918095ac643f9f1b5ca906892ee09a51980d3f2627421017202e9520c6aaa023fe821d7fbdd99d36cc0d5c252f0e72" },
                { "nl", "926123ffc254ba85503855062897057752bf7753612474736c76baee4b4f328a1214b7bbbecd600f8851e8e246571e8aa59853af5cbd18783485020d7a6d3754" },
                { "nn-NO", "3acb6aba4fe7b68408b38f6f6904e04e5ab05dd5782a877795f0b13729da7df860af7099d86b2585d3dedd014e74102078b696cc8ab00953ff6a7d29c9a4cb70" },
                { "pa-IN", "fe34f1782a97dba2fc8a593df83871841cf20ba8a1a4db4d167ce629a5052a5c1d58af0b98e79cfcc8b2ab7710b7f3edfceda192a124f7970b663182bee8f2a3" },
                { "pl", "866fbe8f2bb35016a9cc786bc9abda6faeb42140401539f463b92d1caea382ef6c0501769540459772ee8b175e598e36d71d9e2d5b9c47b736fda95c1a259927" },
                { "pt-BR", "795e0fc71ef562932d9cf40e3ee51af7d4d7b397a32027077415c1ed65aca0f4fcf9988725011d5f714bd1e74e5bc1080d036b6a46ce8f00daa579361a0e0b51" },
                { "pt-PT", "b07f4474b02959714a1df86bccf5014439dba742f7c88c545799167c459d59ddbf08cb53d38c74453f5c6e8c6e6affd5ede87da51ba128c646b2bd99cf5df169" },
                { "rm", "2fec88e89407c7a7bd8907ad163c426941cdaa9a850f4afcf588d5bc540aad7ffdbc8dcdbf6e19bb3dea1e172c42f95211e587141f379fbeaaecb8fe64470650" },
                { "ro", "9bc9e1b200fdc816c04b0cde3500652c7777d6baa6ffa93f7bf8cc587d46c5cf932c2e37347a91845d99d3b50e16a31465e6fbe9e97d338183e12b212780c003" },
                { "ru", "e0a6ce0e2c7d3f1e2b1d19d11aba4c19b65fbe31497e13048f30ae03324afba31e534905772f392e4e996759c584a105c67649102625cb22b8b2c06ed59a5036" },
                { "sk", "d4f1cf3103051af3fed20950806841ff5f0e93cb2617153e9f5e3deaa94994e2ebe44d9111fa9de01ca45a88472d15e6519540b75464662227bead47ef3033a0" },
                { "sl", "4cdc7a4738135fbc6c0c8ab67a215766c95fdc892c664d9830d6d00970ee2ebbd58e0027451d69081cb08a7d27a12fc13aa5734fd7c34c324bbe4d7afd9de896" },
                { "sq", "8cf9088785302288e9dc34e7f562f194a27306c6b4ccf273c528151e7a3903e7063cf6fe7f904a730d872b0f7454c1efe9fc1bf34b62d82d8e2b33703fa68e99" },
                { "sr", "591d971971ac680e2353ab3a0b13955a36e82ca72e56350b9791574418419ba41b05bf8610f28797f00b977f4c6e522bdc3718c4386aa698f0726d8b68d08eb1" },
                { "sv-SE", "4947cf7527c184a34b98ccb90267fcfe1171bbf89746a63601bf6fe5c8356d3f8350dc022082642c7fcc422090177440c6f9d3de14722078b965e79687aacc7f" },
                { "th", "b98b1345289e4078d84aaa5ab3671d87938c3e939280d96817a60675ca4d36a577aa6ce917fcd186364257d8088255220110e0fe532fe464a1cba3d4b8495486" },
                { "tr", "cc72d6d1efbf0e8c031d3d28ad9e05f7365cb78456018578c464696652a7ac63ae97f8ad5841eb5fe6f81e67547ee285dd1a43d3e8a86ff293b3812d23db67a9" },
                { "uk", "7310099aac076f34ff8b2895809a0c9703f8effdf9f1312ad096e0488d67b38759a50ad3d9f96d10762d077b1f47c31fbbdaf7bb863de6c44f3c3a9af3a2536e" },
                { "uz", "eff45c6f5640e07a3ce5b2d3a5050ace642f2e1c541d6d979df4db420187cb8d27e4aa1bd2acb6b6f4849817793740c4efd8b172fd93a3075a9c2cfe554512a7" },
                { "vi", "300a90261c04cfa03bed2cfefbbf4e16aeab940a2da7a6473fd7d39968490fd9112fe4702413a0bb0e59a89bcd68f67abd7e0150762b1c4495bdf9bd64161dcd" },
                { "zh-CN", "e77ebdb9889081ce3bf895b1efc1bd1027c1038ecb192d8ff6bf9ed21f486ee97dc7d834a4d7709377c190459dd3e068711fbc528dcb2d9ec1b6580931b09155" },
                { "zh-TW", "d35f4ab3d066cf138f938b35d888a25f465a427b3f4334cfcec9f79d436630535e4ec6226b3b9f096c666220892bcff95b8092a6156e4239c15de64f8aa76277" }
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
