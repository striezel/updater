/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
using System.Net;
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
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "93.0b6";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/devedition/releases/93.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "5619534a2a6ea3c96fa6aae6369d086ca57fcf54724b7b9ae2aeb0af00f862c2b6a984f00d5feac6b63cb6abbe08506429719d5e2be2ed96f013b559d9df19aa" },
                { "af", "e2d9b53a25015206e85a6c4908e5216a7c38f6be9666a53d5bd399a72ddc4e9adb97ab2e5c95f0d3572bcbd00524fbf419f58b2d139537c9a5413f0b3d17d1f8" },
                { "an", "457f16dfaeb552076fa776e22586330d9ce548224eefe9edb33d97c205a8ef1bbe6eaadac844c6fe87f0ff3d2fb454c20ed23e96985b4f12e779eb3c8e207916" },
                { "ar", "8f13a08e3c0e23cbeb832f491ca55cb3cc237f5d88ef4dbecb9f5fed7b727a656016b216a38562b2dfd4f563f6132740d45af2085e89e58892ce1909f7b695df" },
                { "ast", "bc8ddd532f27c7ebb746c99a36aaa36fddcf259a733008cd420b01af77370252a6a2cf7159ebbdf181f32b1bb08d04af5343816eb176dde13298665b0cc9f0a0" },
                { "az", "894fa8c1d11e40625234144365108dfeaf6448ed5b3d1f595e3aae0d14f5181bbccde654f4770fd381145278e82363b7d0923f02a7102563d10b6d4c61fd22fb" },
                { "be", "98f5739e682d54e56b917bd0bf3ffa9ad092dd168d501c1cdbdfbebff568cb732d83ddd8970e214aa8161dc059fe6e852aa5239234f672c9c1cb6084a7a805b8" },
                { "bg", "db67ed982d29e963ac98066f33b5c9e4df20d6065fb864c389d98185ce7518f2fef79b4c962f73cd41b33da13157f18beed12d62d28cc929fcda673317b78d06" },
                { "bn", "108b8d5880ba3e464c28c70c124dabb0d5261dc22fd200de4e1c7344980eef704bcccf72199020d37d139c98fab8296ac922cbe2dbe7f418e449358b2b690769" },
                { "br", "34f9f87efa18630e9fd2d61925b1ef98807c71fbedb2e541fb5b9eab76f24d5f5bdd3e03e8cef06f65f2212345ec54e17b09929f5ced1362d9bde7bdaed68947" },
                { "bs", "1a878f05898f83d10dc06ae40d258823850a2ea2b27371b6cd95e45482b22f10aea95c882e01d94382d645dd16d3044c8fa14393fd47b5a0f10c21d0721b1484" },
                { "ca", "466fe913a5d7284f547a4c338ca5af6202f4539368ae16a5a7c70cb07a62383bef3cdffc3994095bb52ce40e27e0b506eb2d3b26195d16a16a773cca3c9d8e7e" },
                { "cak", "337fc1d914568117e47f4e22ca7b819963cfd710ec91303e590b0929f383c10a10913fa1d19f075d1b65b99cbc13f084b0cfb068f98298ce679cef1925177b65" },
                { "cs", "3cf64d5d392fea2334f506dd7596a68f9044d4eff2773ef7a14223f3aec3b9026fc2833feafb309ca9c025f13ef121c480b0963514837599881b9c0884201a7e" },
                { "cy", "7dc5ac835070ba21f4eb617b881a0b0cbf9fa6a182a61c733f0cfdcb25172e7af9ceb09cd805e0b5c30596b865549714076e07a707015ae4ea84c0f530a59adb" },
                { "da", "19f96d685084c794977a17760563310ecc5dac4f5dd0fbfe605a0c1300b7b8fb08b34cf4f836c4a1c62f9ce4df723d591a44ec84d248a36c4f7e00b9a2580785" },
                { "de", "f95786da73be868b78c54c7bdf1d553c64e248ff32399f77104d8acb009c071196bf8c8393b54b7a84ab4420117434da91f03c531aa026bb85dec0e9d9cd3faa" },
                { "dsb", "81a21dd3505d9a0f7e83374fa5221f0f61be92151da62fede8a2857baec4b707e7dcf797adacaacb5289f69ea4ffe22b3cef26c9b179cf3251f3a8b31aac483a" },
                { "el", "91d93c9faabd04af42ae9ec53712182eb1ed9234618d51904748995627ff6aced33d06ef25cd882e767a64f2660ba0ecc0e3f55b38144374ad1737baa16a611e" },
                { "en-CA", "aeb296e01c9f038b94290149f5d3a3af81571e566b6006bdd776370fb572f814d0a9611d21ba0de5e8b37461c6885552cb307200eb7c7bf16ae41d4280235939" },
                { "en-GB", "0e665454dfbdf64da4df5540c5d964c0d933202046b7e447264b51879d5f9bbc6c0450224a2b3f458e6d283494c7cd16e81e49ee76097de73c15e67aaf452db0" },
                { "en-US", "897e2c1a05f76684f63f604cd32e60cd8f4582c9f3781bf2fa9074e611eda0615b9fd1b0733dfc044a581dcd158ecae4304fb93aaab2e18a35f92d83e06f06ec" },
                { "eo", "d5cdb2b54fbd221a1332ec92683de56d67217adfebe7db0946e4d22f672182369d23e18ebcfdc5cd96ff5188d44cc5b4fda70eae921da1f537412e4072e5ff99" },
                { "es-AR", "1265ceda14c4615c54d12695634763f9f3e5b4376d1b4f6bf47e26d3932abb671e43e8a05f30202d1f71116f0c9cce10be35a17434c64983dd6041a20ce1c9d7" },
                { "es-CL", "d41eac79229d6818994e59c4d8c32f03c9b60bc0786dcd4f6a03a155aa441af8dbf13b21760e1878c6db1694f46a5260bf59588f0f2f38144a698335770b7ed0" },
                { "es-ES", "34ee2b8c97fc504c61d18d312c9a2e113330197f25d72ff3d8f6470d7896c2bf471a616c8fc6c8a6ae69d5671a1b7bf5da47db2d31bbedc35eec14f477676cfb" },
                { "es-MX", "d921115fbe6abc2285c5e81c9586105c9f1d96e718fab7d3689ef263d308dfb7e45606efcdf44560a42fcdc1fe2c787cbc69b6296fdc1d1e08e39c78f83b0071" },
                { "et", "45b6144f5db4764bc2a3cfe80329a5d3b43381611cc89a42352fabf20a4b4f8ce4dd4e2d424dccaef7e6149e7965f49d4cdec52612e6f85b8e3eafca8eb64e31" },
                { "eu", "211a5db2868daf539d9b2d0de2f800da4e6e1dd1e501bb6c0623b58fe5daa0e7719d13bf736382c31d47d92cf458e1d8601e4416b39d126f14bee2d4e7ea5214" },
                { "fa", "6a52f675e823b6f00c516aa9c7e780fc775f2e64bab983da7300e140607d70a3760fbdc65b67e7ea9b59de561e587c8d77ee4184f03d243f914014f37de10c45" },
                { "ff", "005fae6e3906048641ee1b72310d93987c1db60a1ecb4db7758cce6d69662214766310a734bbc5877eb64fe4cef78b9c1054ee805071e70b15dbbb05f03074da" },
                { "fi", "56b61474151db753db7c48f4fb9a9db8f967f8af5068e823723ef421a1deea4f3d556a3aea9de11eca6de0fa2b8a2a735836cec1b650f474b92a30852b9ba217" },
                { "fr", "fafe5a3555a8896008a40a2e0135b26340df3cfc119a36996bb6e583c9567f726e55c298d009f413528e9e82e92f1ee1381b51da607197c7eaffa882fb96688e" },
                { "fy-NL", "5572465243b53116bb56bfc7a1ae80a76b00ea3d68b37f1fb8f265c79b1bad0df6e0879790f997d19ba3a7dbb5cfbaedf63cad8e294540926ec168acf049cfc4" },
                { "ga-IE", "2891d1e4a4d41c2f8d8551882c2505fb2445ddd1a9b8e8e97f16c38a15ca51031e5a2eeade5b5167f3bf62821430c8c441bace4ed6d1bf801233772047fb2941" },
                { "gd", "1b92dd1e6c28f8083331c84c1a4089a2f7b01928f1c00eb9b1475284a79f94dc84bc40372d3bf26ee66453a80ea1148ad8fadaa98cbccac9cd5a487135a55f9a" },
                { "gl", "bf0c6055a2732e8e2d5080c7af44d9b7e09d09ace88ba63912d4252254edfa9b0b672c2093816b3dd5d2fe7e342abeff9e6bc999b901021c38dfd0fafbc78909" },
                { "gn", "934110d96b3af647bc82c8a889d7a944ee47f3edc3149f45c7a1d7947f715f8e58778069aeb024629ae47ad7fa34b10c7c28004c7abc0c776b3d32866c19548b" },
                { "gu-IN", "e8ef70d3264d7e014ba81004352588dba98cc9e8f051478814db4f833377dbd55ec83e7f38d9048adf367a265a7c2c37709c0dfa801764f9b961f7e518526dff" },
                { "he", "e677c07097612ff7e71fccf52442ad228b1c0a366314f19fc7905d2570a8ba44672a76a932f03d683021b2456d0a84566a646974bf6292db699a9c737db9a27e" },
                { "hi-IN", "e2bad5e26029f2b9e06c42e5b7cd57df1eae84ec91af934cb128be07507a88ac35686e6f383f45f2e19fe792b4719bf5f2cc34f9de5e90d50ae28aa52cdf0936" },
                { "hr", "fc6d7bb06afc164da8485b0d241508415f975b14d98ec201495c6675dea0f50dd8f261bf5f00bb4aef78dab9c0d31547a0871a2335b34a82a1c5807b66ede66f" },
                { "hsb", "a7a0cefffaa0ab855505112cd2126e48246bfb92a9f507e0a98641a69f4383eaa5ae5c986f70cc265193354398aa00d7b0741ec086251e222138c5524bd88b53" },
                { "hu", "b1400dd6f030de149349bc2afad591640f2644f741339db6ee4d63b92f07f6ff3cca9f122eec18e238ee9d129b64be522408eeebf197aedf43597ad8b8006bb5" },
                { "hy-AM", "0299aeca78ce5f4315a3cbeef1affabf177d2071ec606606e418ff56c05f63474d4964815f46d479bfae5abf17c27ee004aae7353ac626cf1cd82e557c9cf98e" },
                { "ia", "52f5be3cc9c82a1f2ecce098ae9472727e50cde88524ed5097e5759de9704adb900290d2e9b836286a99f1ffcb0bea9391f68c6c8734049d6e5daca7172c1ff2" },
                { "id", "48ff9eace8168d85e64c6737a76759f03f76545c20006c00c5d13f7fcaf52631a5f780faebb7a0c0312163eb37becc6191957a7b4ac26623d1921a115ff057b3" },
                { "is", "a7f30560ac42716b5e77d426f7b4886395adc887f018d76a7544b7589fcdebe5283dbde5854ae93f3581a2f1faf9e13388677d736460726f8ed7041f46a83487" },
                { "it", "f920d25e4df3408daab300855c8145d0c8a09bdf60233f92eb7c7e158060f01b0d35ebc88d0a6f765b94241761e37fc9161e7917352aa5c724d34306a52042d5" },
                { "ja", "79d984444eff21478efdb7238562ea2448580e7b139134e2c7884b631cf4b89cceac8aa4deb6eeeb05ea7b7c35e2755de486f35e4addf1c029a254242d80dfef" },
                { "ka", "3da75e69548cc041fdd216ba177bb8ec2b72dbb8b4e578a58ac9dd05fc1c4d64b0787021c5049940ac5a57143e4b080bffe6146c4a9dbf4a2175cebe324ce094" },
                { "kab", "baebbe3cd7ec1e956b4f46c571bb0f0096aec6a42a699e06a46b307e7638639b6a27cd9276d9c8e1f75b8aa4a44635b84675b870540ba55f591428dc7fc98d1f" },
                { "kk", "fa54d81e6714677ca3d1498001b5be3d36536e77feba318f725175d3dfd4e60ec46e1048d75b55723b8f3c98758832c27f96f01c11d078bd707f469fd4c74de7" },
                { "km", "ae50a890d3b3fef1bf4a0ead0fdb52bdcdd3fb0deabebfc19c565c938e3b2776e31e959481a0e3f4c69f1af81be0f572c2bb0482b796877a3d0def9914cf36df" },
                { "kn", "4b8e9be56049cd8c945f13642ff5df3be42aa247c29915ab24ba3ddcfb6908bf6ff9680f2a737eec432dc5e04dec46275f4230365cf66d0911b134cea978c2f9" },
                { "ko", "2251ae4774c0baaa4f26444189de865de887d5f686d5d2102538924bbac1f38ff1f01194726db2dae65a4be6b6a59b4e37e4b5a2da18cd07f5586d0f94a9e3c2" },
                { "lij", "f634094cf43a9ae5742cf2d5426fda65a76d80feea0105785bcf465aaf06606f1c18ba42caa05494bbc33771294566239a59209d2d82d41eff7772897b2a8d62" },
                { "lt", "46f0572194fb4e4e5906fad4be26d57a6319a100322774def3f4c1f841f8cc8c032e4b1c46f1f485f329bcdc29e8a7878ed2262534751bdc66099bb4d56b46f8" },
                { "lv", "354ff059e9e54b791c328bcfc0c183134cd04c33b39d7b44868c348c0deab883471246ead15a66a08b6430876ec7f0df7f1881ecd28d8d31642b700f97ddaf58" },
                { "mk", "044e2aa94b5092e642479de300adeb7dcca543d8cb7b0cc77b5a7857853b4dfafc71423dbe75cb222201e0badfbd049262cf33658fdc332b9495273394143136" },
                { "mr", "d2ba67ba87e313a2077da1a1286a3a2bc102ccade68b185477f221eeebf61c5fc893094d540e70f9b2605c447eedf1999ae9e4aadf4529ee476cfb497323acf7" },
                { "ms", "f5cf71f376f9072faf2d38660301c4d7c74e9da57fd0ab5ab289b651c752e779294baa17b1229a3fee583e94a1da4004422942347213d7af5f49b571847b9dff" },
                { "my", "d54c9f9fba8115a9ac378ba25e453c895afcc489c6b2e4a3459ed8b7f1d8d31029c450afd4548d3981f141998f41b859b26070112ceffd9e5582e1ebbd0f0d29" },
                { "nb-NO", "c534f78bf68d3007066b0d5884dc3174eb6bf68ffdb5fa3eaa9fae719a6253e4446b3e0530bc77d9e3a80738154d55b99b88469322f8102e3d4ebdfa2a5efb26" },
                { "ne-NP", "0ecbde497917f8e69c2f63e026ca61d19b0ec6478b6e7061072864baf2d7a245b99a89d73037f698554936f0f55e98c63860c653a089c3a6fcb8fd1829670f3c" },
                { "nl", "af12a4bddc87ef9b605d940b9d0b49ef8438d48fc4435bba8f586be7fb78a0f373b76483871330961ca27eb932f507c3fe2cdae3af2db74bfb873e5c294443e8" },
                { "nn-NO", "0cf9d87ccb727b51290f5ebdd890bde207b7e341d3ce10161b71681a3fa83af45de0eb839f56d901b5630657ec161e3e7a922358c0b5b0f025a7a103a4d14eb8" },
                { "oc", "46b9a8bf424bf233de9e325b808806e39d897be68fb7171c361903e022fc9ba6be170e363f14cffe2170c4d846c141dfd934e91fdd785fd844f5c38bb0d0edcb" },
                { "pa-IN", "2851b3327bde416fbab115e691f48defcb1c99fb296890d943e9b199f901e2064c417d20cd7bb00466a07d7459de621374da4919cc5a081cda2cdf36cabb6b4e" },
                { "pl", "43483f2dfdc109549d476e59a008988932c483aaf78e1d53dc691cacd0387e3f2830d6cfb002aac69723e200bc094c00e6ec52d9abdd6e6ca3b03b50f1949a41" },
                { "pt-BR", "2cc8878cde9fa4da81f263b699a0fdcd274306d78a4e7853421231b6df8081d43dd88c254063e2e6be0d62743bbdbcd5a8ad69c190ef85eea229f2ea65252ccc" },
                { "pt-PT", "f74b89a682c5639bc8aa3a5604a912eae108fc4b949687fa3407f8a37cbcca8507d85838ccd2a988976505a13655b4b9453f78dd007790fe37e281f464e04626" },
                { "rm", "6f176abc598d3e3c37595c1ccf33d6f4426f78456a8443de159f3dc649eb063b27aa6b6b9fa152255074cf703f22b347f9805e27b4a290a00ac8fce26d3722f4" },
                { "ro", "2a5b94db84c39dc513ec68d5e22fa8982bbb92450d12f2ff054fbe61d4e4cc5ead0bcc0bf8ab200d47e5e37e3d8fe35500cdce9ffd42f4415833b77bc87d7e34" },
                { "ru", "6387e90b67f8e1cdba7990deb364a14089c30b86d9eb0e923f3ca6e2c24d4cc614e59fbb8eb36e39d4e7a3a525c4360a29fe19fdb1b00624468aefc427d77280" },
                { "sco", "483326995b44b0f6de3df91494e36731a0083ed6ef418116d6853c259cbdbf2dbdd8e3e35476160421633e46df2273a6b4c55119d731654a6e6c10bf0d4919cf" },
                { "si", "80e2c05c1fa44495e9a0306640ec1e96ea04dc72a2ca31cb8ee66bb751eee81e65883f7274dd1ead63aa55c7d3f09e1dfc6f33b6d83e64786b2b9449e886324a" },
                { "sk", "7d475dff45a96eba4cc1bdcf3bb455d9dd4b09b049a42e1efbf6fb1c39d405895f45a25f44094c0f142e32c1ca93b8aed1429fab0f0695fac3c17103925d0cea" },
                { "sl", "a674e1a9bd766c78528cb7b7c1f9376abfed38b88d97b09cb5bbbf9d7a5fa9e707fe0ac36a668d524998d8b494a5c4852738be16a4e13af3d3519c724ac37b70" },
                { "son", "cf5a860208076d1243b8f7629ae98ae00e4dfd0700fc2a28aab4c9e9c0db962067ec5079a4274a30676a908a79d0d518c83af7bff6c2302dd7568f40f2940ed9" },
                { "sq", "ad0d77f3017104a39e5f6c7d191e944068fb465861bee39f2af9ef2acc4862ee31a37a88481bebd9f9c12c73ad7f342398e6ae6d63c900127f254cff3e38fdf0" },
                { "sr", "112a611842988acdf97779b069ead4377e74ca18195dd465dfd83b84f1d2cb0f66ab7087337542cd905bbd0873d807442dc30e0c5163778cb08fbb108263eea5" },
                { "sv-SE", "75aa0915e955097c08e502d14dfcf93e37aeba5edc3bca1ea2ed9c3c95149e04620dd8e876d95c91d3fc71296a3449b7cb771381b378b0b8bdaa4bc433cfa7b1" },
                { "szl", "26684f0cc9d5fc545ea04891e3d58c2a43747466ded2d6569578c3018972ecf12d374bfff3009aaec63fdbaaf64618be4f44c58fa232c7616c1db0af10c42461" },
                { "ta", "3c002c8518784c6b63fcccb3935ff9ebfdf75f18985d04895ff48d3840f6c080d49123fc5edc7e8e29923df485874bf6a77d75f0e94fc58af452e613aa4503d0" },
                { "te", "09fb4751f50612bc1443dfb35fb1f729a06922abf3857231cf017ed149b688fd67e2df89e5ba4742b350ad8927c87511abeca29f26397014ba65409e43798a52" },
                { "th", "ab8d584fc7490e87de11306184f92c88fe8d14e353eed2bf6c648cd994888df87dd83946fb5d1656acabdd68bf4adb641d4d8d09bbf007afaf5f726c990e24bd" },
                { "tl", "f9d2dff2cf6759d71b3d216a9aa36a222716271395dd9144653595e7a0227c669fa89d16067d27cefe4aaf9ea00c5210c7646782b310fdec46c15928aca910d2" },
                { "tr", "f0c0ef221778b60eb8f97310564c4f9f31c5695382e44ea9d3941cfdca1ca99e2d656b7e3d0f4f20acbab17df4a55c0fc851fefddecc0eee3c0a264e994fe03a" },
                { "trs", "41f48da2337ac73b981bf614a11631271babe2abaf96115b5accf4c2a55c41ba153f760da8cafd5ff865917aaaf14115758d91e0f7e7b0278089b29bf75e96fd" },
                { "uk", "21b70465d6884051a41f3b5a72c8ef126b13c74be18f8158b58909a1c1a6dbe61dbbaddc4f536f1ffe57160591fcbe379b2ab08e3d9a5a520f4f21090a185894" },
                { "ur", "d836ada363810a34306127a1894ef525a176e9f43cbf06102fe1f63d16273bd21a0ff48ea37ba7989af7ad27539d0f6c4175d80b728c64fcd71d31921823cf72" },
                { "uz", "03b97dd20d4d99a87cc00e906b16a050df0558199dfe1f184b36c136b31c76e8860d16934bdddc9f6b5faaf144921f44d70ffbb38004365da898e89014250348" },
                { "vi", "e06b6712c8ab97844fe76e850cd5c8d36e15138d6fbedeab9a9fc4d71adedc9f815e855eeea2363640d1d9ca3033324612b948799a1efd00d8249a6751383cd4" },
                { "xh", "ddeaa93a525af6a3cf80b60e283534a513723c6463503acfff13d58fcf2224b28ecfe379e2c920da265b78d965d47ee6fbc963faa8e9b58fda5cbf5a2d2ca8be" },
                { "zh-CN", "76f1f0fa3009eb260894f5401e540265c8d16cc74c72f4ac9ad60280d3fd163d21a9ba3384f8b63e53cac3b9065aa54113d0a75f83ca0f1c11ac5078367442b3" },
                { "zh-TW", "8038dcc574edd5612adb21e2fe6f939a251112080b962fa0d88e619194a3035f3d5108a5362735ec0ca3381f0b4d3a361c40f41b442c27a26777160cead454fd" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/93.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "33849cf66ab1a9c19f6d256a7f2defdf02ac4b962e947a322d396673d7b71a03c6f37982f2d048dc595ab966b4d9373289013fa08f520bee92f64f49cbcc4cad" },
                { "af", "280e3dea8091ee74293554550fe4ff56425929bd3b205d3efa1e0c3359f708dc24802462e899d52d2b59cb1ff4398f705f02abf0c12078332acc8830f6d66e71" },
                { "an", "ff7694ebc0e86ee1b248277edfe5a4b322ad235cd3c24ba9ffb82318794d11a19148a1fd077507a6846af455ac2515a11323680fda0504f2c3943096b4097281" },
                { "ar", "439ee4117e00addad09614a918467c72012f59d2ce9b14f3ea91bc2095fab82b01e4a1fae74b4ba058bddf5553244e8d8f64f97d2fa67fb8089d847df8543606" },
                { "ast", "cf730ddd655df29c61c816a0b8b9d1cb0a718aaa57a27ae28708a0a83bbd18fc810490173d9eeb9de9841743ab5cfa6076bbfe70bd0bdb3ff3bd23f58e73e9b9" },
                { "az", "b0c1686c537c38e97917c6a1c3b0483cbf32637a2cf40a5590db10ff02e04d6cf2ca3856733afe432588fac5c984f285edf47a94ea7896defb5b1c9afc4bb818" },
                { "be", "3af2a652ee22c85ed646ebe31c69cbd8e05426e4e3fe72630cf6eed64a82c5623e5c6a983a9fd3c5dce3c79ae4f807b6007c28cdbf7f032efffcb8ea47a63f1f" },
                { "bg", "3e41c570cd9e1ba13e077a741961ac9eaa8fc161c29302277107a9d1236b47a817f571758a59a01ea7fb6e87ece700252c5e80b37b992c6497b15f2df87a39ea" },
                { "bn", "ae10db87720e6290345cf3919a3038130ce267748529a0cd9128e530fc28c3d141c60affbda712b1495ad11ee93a9951859c35f58c48e23e11423a1c4306e555" },
                { "br", "d9aca60100ea46377e9a8cbf449e7cee1be282bede90df9dc45cc1ce531a9f0415a10e50af232f05fc356dd28566ca29277e7b5087df89c9187d0a90b7843bfc" },
                { "bs", "2e2521806f640a09727cc7791b27d39be5da99538c0eb2656e32b74b9981c719ab108c3f1a8776db39764435bfb5b2635b59bdee80623160909fef4f0a243c7b" },
                { "ca", "73af68c84c64becfb195d093bcceafb5b181535cc52338d73dbdea9b3b494807a98759f8d203564ee033b5db41bb70d87dbc329ea852e58b031aa01e8d38a91e" },
                { "cak", "19d4cbb0224afc33754481168869ed0093eed42a113648792cb44e8a9aefe4c7dd404a98154f642443b2f3e89511fa4d12ada1938e5854d94836f33efd9e2306" },
                { "cs", "133d3813d4e7240f7173248f21f5bbc6641abab75f0426af320d7aba229e20e7e14c89cd207a65bde4eded6071c8c58d9d4a554196e64beb36c1dba65e55754e" },
                { "cy", "03176983c76fe891531e13090344e142504455efae6da33cec10f56bd2e13d7b616d0eb692824ee0051ee3a81bac09b2df433bc180a8f9d0f7ad7c65c16644a7" },
                { "da", "56fbd745c4af0d0bc0d7ba6de13078a00bafcf2e5845123258b90b940fdad47adddcbd6f27ef6d5bde56ad6d1a445594802f7866e14504bef196d33d3577c0cb" },
                { "de", "6cb9f45d7db7008b83da769852fa5ae46650c13e559133edd60afa6907e4405413713efbfaf53463182fdf196ae465a764495bbf2f4532dcbbd1674987a29a56" },
                { "dsb", "e2e47a0b05ec45af73385762d23f50c7dba9d55e301f8874bf185831c07804290b8c8d21b58f873d879043900d41155e6692f311feae2b6b1b07827555761eca" },
                { "el", "059c91a020aca2037155d82986fd2d82caa7f613eea8d14624360c4d6ef48358dfb4fab03efd3d8fc497f67f5755c586da2edb53c662f263cbf5118dab05fe02" },
                { "en-CA", "c69a386ca45171cdfd4cd9c3d6e18f3587af2c50bf54b79665a3b6327380aa4214c1db548d9ee56ff504f5f6ecb25baf8d34e8309950ec15f07ee32d5164ff7a" },
                { "en-GB", "4b5dc7dcddded7be6bec399b016b5bc1d6222a1e569b26bf4803e4e4c14817c264f1ba5c1e1677f766643c203bef1766585db0c1022f065c1c2a1c853878a2db" },
                { "en-US", "c4f4c0c94c59bf2c60dcdcc044a4dd1b125d29791aad43fee857c81ba48aa8b95962f92f0f0faa2333eea1074200cd28c10b61672f2ab2370835fae8b8ff2802" },
                { "eo", "2084580abed4ad7baee9d023963766e1a3a896a27bfff620313afc8ced764536e9bea1a96afa654abe2ab529105fd15ce38f443bafa164ff7e172a0ed05a1695" },
                { "es-AR", "6a5df0f461b1a3e8c128b0a97e326f2401bbe8aab69d56ae273365f87ca7611aaa3073dd87ec00e2a493851a9e97e80375980c3c6fbbff0f53e9bbd79c76cef4" },
                { "es-CL", "3afbbd42b577a337b62f2848a5e6cf4415ea39f61b75f9ea2f9d47c4d39d77e19441017efbc525039d938db1ee59bdef51611849dac315da869390908394a7f7" },
                { "es-ES", "dc98b03038d42082edcf3cf8b2c11bba6cbae36fa829ecfdebcdf19de81e18c9c3a51c16ae306d6791d6581ee24430ffbd4b3bcdab7f1b65aa2070dcdbe7c7c8" },
                { "es-MX", "aff98abcface3cea19bd367e386204eeb29e8b5d43162c0bf0d545e03006ac7acd9f9d29567ad03353195022c5a772a497528db017ec8979ed9ff84dd8a19e25" },
                { "et", "dd7d75aeb7c3b9509ba4d2c48c528a4708cbe7a21d897e42272bf0cf39766eba15fccf76db801e955108157fd24da70608e5e8b8a39eacffcf6fcd2961f5addd" },
                { "eu", "b7a05e9a2a7f9703b6e91dadd99e59ccc6da54ab967a6449b668c72b556da93191ec5ba82f81d95262b5369359d927e9ada4a8a1318701c0d358ddcabe1bb4d4" },
                { "fa", "8f5d29607c2d5828562804c381eab377a1064e82580ded4f3c2a4e6a2d39945c73a22403be55e6e8fa9ea26598337c19c88a113b4e58e510993c62989ccb8ae7" },
                { "ff", "bacdbb43b124d50e94e4f61796f0f433e7479e3e044c0e1eeabeff0da7db2593d142c56ae5b5f4c290332c724a9420bce062ac13130bf3718d365be6ecaddd7f" },
                { "fi", "d85e331db307170e6c9cb02ca899661506d3c12a24ca09d0e80562f43deaef693da465125a8e405034c946ffd73e71bde001e484cf753977e4f1ffad0844f4e8" },
                { "fr", "4846364f193586387c2ca3f80dce6ad8316ba9f4bd2f25b55d8b59d2ed1e820790e9f74401a9560832ed9c786834c6b5bd3bf96c227ed6ae8e6c9fe58e39e0d7" },
                { "fy-NL", "ba576e094536d7e17dd449b3d54b5bebc143e6fc39571ee2f3e28134fed9fb9bf7b4d58e56e7a83e942c411d299a71aa02017eeb978c1373030b35fe71f78e95" },
                { "ga-IE", "72d6a8cb6a0dfdff74e9c1507126add8c1597a79eebc6f073cd4407b88983669699b98af1d884ba387e1d9827fc1928443fb4d4f6e2189f0a3b8924861839496" },
                { "gd", "48a59beffa9a8950a14562c7cf767e842d6a050357e1b8e17b76736fea612041f3cad3d980053381374701298a1828a1b50c47f6bbf89b844c9cb5dd2a658ffc" },
                { "gl", "4889d1a304b5033d6d721373315ae426f8e184a5a86888b2cbe60cd94ba652d1dd71b5a6fcdfdc3e5a461e2e9922b5963f6292ce2d16c804f6dd5301cf5c15a1" },
                { "gn", "8c4b2ec61e44b5e1f7453f60c55cd116c740d8b14676e65a9d53016c943b4def1638de3f5828c2bc51cd773871ff6037e88fdf12e06c4c64795574708bb07fd0" },
                { "gu-IN", "81d633b1bcac44e2c7a8d98202efd6bde491bfab36241aaeae61c6d90852195100eb4733e4e530909114cee70ea54a79f5112b5322e3da03ed8f1e4f7256f152" },
                { "he", "2756a422785249e2c4afacddba41b5264f10939134b2ebd815af3737f8eda04c59fb6488c90022e3c9b3a994cfc117bf6a8130ec75378c6eaa7078905b682802" },
                { "hi-IN", "162789da7f73985abdf44579396ae2459168fbaa679711ddfc57c494f27f87d0e2f6096d6edb18b7ed26456bd2bc3a4b3d3450d710cd42cf7b1e112f60e3d8e7" },
                { "hr", "a0ce675e0f9d7835ae7cf86c6f9edab1a5bbfb1284dc2e58cfc0fffdc724e24b61a02c7d8a0f3727df5db32320139aaaba1a2995afb7552eb18f9912157562b5" },
                { "hsb", "439aed8c67ce605ca8ea61236aaeadf62268af0cc2ffbf3a0fb7b4fa7db8cb9778b77207653a234e0001a6bbb0c1ac84c802ddff9c887b9e125b7859117fe5a3" },
                { "hu", "1646e2d45078591acea9f4448813992e359f9cd344b8e6df64c06f50ebfdfc89001a195260035da264480090646626bd6fb737d915cf2b0d751d66b3db7ca5de" },
                { "hy-AM", "b84288ac3b3e39f25fc196f011d98377ac976c76ec2f8792d50c6e5e022eaac5e63ce8ee76d9245e6bb40d70dd1b3b8881ef35197d86ebc855fcd0dae4c2de75" },
                { "ia", "a27969b37e23423369124dd05cc9d6886db96b743bc684d1fa5041c76cd575606a25f7a7004908552662f0108b5b506f77370a9f521db08c06cb4d76e5901bfc" },
                { "id", "bf081c6050679e8fcc40f3708b47c9fec5a1821abb542db6c6aee9f04f17d5bd9da5fe46f1d0d432fda00d28738f69ae65d7a08eba122fdbd3a0bf37672a8a66" },
                { "is", "cdb0a0267551d560dc67124b4cbc041b908b764f775c1cd92e09f5db38ce831884c2b05fbbae91fcd036e270de050a5d99b11c923ddc4afd24f8a0af30dd546f" },
                { "it", "91e0bb993da285bd8f3a53cefeb82b3912110933ee5abbacd5e096989d01cb8aae985fa38a135d5e5a3615f7165a7c7a47ab4340f013e12fdd1a75563b5751c0" },
                { "ja", "ab92a1f2db37f6f74a72f1c28d2666728b0090070534f1a459aff7bae0d940965140e9491e7cdaae1d8a8b19866af2aed946135951304193b9db7ef8c9a993ca" },
                { "ka", "3feb0ba061b0843af294dd045d0659a6c904c33cb693ad6de816c897d435a5372ea2fb0d396f6ba83401e39d78e13408d83d1ecd60f5062a0a5cd570df61716f" },
                { "kab", "18043cb14d1f4cc0672c366e273cd76fa4f387fec5fd4d67324101d20c32622b97795f1ea20b9bb5c110519e322cd32bfd4ec11ae6233f95c511afac7061f84f" },
                { "kk", "44e9a7c159be597624f9c9390072aae2c5443aafae9082ae7893a8d01b1dccbad7a5cd1cc5c492181cb5f05fc8c241e2a1b77f2ad8bf9a846a9cc6bae8284fb4" },
                { "km", "3d81ccb7075cab0f3df36619e53d1bc3909d9f7f78dddba995e249b1b40ae360c37e307a0c7d1a37116ef44145b84008c72ced05a2491d04d7d51edd91d6b98b" },
                { "kn", "8659efe2f0377327b7bf40133527d32e74b0b14614634bda8b15861f98654eabfe53ae1f63a1b87f1a730b608f094ec372bac70ce901e8b520c0ba0af3717ff2" },
                { "ko", "1725e07c0bde54b0440144f19b3721bc87b28376a033fdbd56e35cbbb4ac3acbc401e7c15ce10d586056221f779a0180d6f643fd05d50da5b70cee1d5f0e420b" },
                { "lij", "821b5f0caf44a354c731c64ee29b4084269d17b0bb57e8a1ec1c3086c6a3716839a79e6f669140fbfe9344c1c94d9cf228f27ca039f85e308c07be53a6917d61" },
                { "lt", "b9525aa76f5732ed52546e06d6ce2e400fffff326b67ccb441fdb6732028a48febcc89d23747ac6d863b7d19da0ce347da8910a7b5711717281c683cffd7b8c6" },
                { "lv", "b480a1769889bdcee70903c4ba0d9e9a80419e3f35e66fdead925ca088d21f02589a50f7a2f30fc136455f699ffadda6199cc1a8c9e361a306ff98095d457cf6" },
                { "mk", "70ebbcdbb2910ce47067d90a303d33a163b37088a7760f3fe5d077bff359b00b3dfa2fe095a57d9d96f903b7c9dd103a96e1ebc0ad9eca0b601a5e48b34b2ba7" },
                { "mr", "9304d7ee16137d573813506e613daf3e9f4f38001e56ed7ac16a1a7cdb1b5d413e86688ea69ade363022d30fd4380bbe01d38ddec37455695ba98aee2ffd86b7" },
                { "ms", "7ba260f6b5cacd409ea1ccbb9e9450bd32f48b4afc61988b7ffbc13ab7f4cdc038926b0a14cc16d40bd0f2ba23b92fbd76432f226648a5d7def707b8b707c504" },
                { "my", "8857b9d7cfec0b6ddbe295dab461230edc6a90a08181f3a981a5e8e2b3ced65a54d31153db87cd6847f0f2e7c76599c999e4619d02a3ef52134c1236a76d73e5" },
                { "nb-NO", "d835e751929455d06654be55c937aa5926f71bbb8d586d5e7c77984984f410339dbee375a5c03e44b02700a526bb6b05545fa46e22d088a6a2355afba87eede9" },
                { "ne-NP", "a5f256ca6520c73bd3c36e8f7241002ad8593a356068639ef38852b5fa538ef47696e7df7e567c33e8621456bbe32c6dcac359c1f3422327322b26c077782bce" },
                { "nl", "19aa7942ae66dbbd1790b92ecdb7eeeb955fc3f31bf3e9225f2ac7521045a156739dc116a185208bd84365618d2960411d9d9b29d8aeb3f496f61dc90f6d69ae" },
                { "nn-NO", "4bc531e746791c7678de4d7ab17ec3e427f0422a6be1aa80a13116e3211b59b42857d07a88ec6ccdb747b56186c341ce358feedf3ccf0165c76a36d4398a77c3" },
                { "oc", "ceca2318d03fbd276be816cdcf00a03dde0da2abbb6a9dd6191d3e7bb2e6ae5af0dbfd8ced4db33b51c5865ffe99cc7fce1be749ed360442f0557d3b93d10800" },
                { "pa-IN", "acbd1112ab0cc3f2dbd4f66f5b371db631e553f3ed5dc5a58ce5bd666b515d2c4ba8a98f2898b2ace720294aaaab25b7d614c20bdd26a4b0b2fd20191217725b" },
                { "pl", "09b822ac8889e60f93395406d6c04e5b284d05a6fc68ebb1965b81d81ab3bf81577b75fe5bce58b7522afb0cbd58eca7d1b3220d5d0be35dedfe036cfea63e1b" },
                { "pt-BR", "bbaf2674495949b810176d9bdcbf3bcc48c4b0ad587e7278da95f7f8ad37a20335ae0a06ece5418738d90ec2a8207943f44307b22512b93c5ecfabb3b72b8429" },
                { "pt-PT", "f3e9a440d58fb1c42ab6d5e8de0d2b839513fc916fec3e0cd2a2aca135b6e0613fa259ff1f26050169dc41c148617caf3e437ed46fbb0188515a1dea5c9d9838" },
                { "rm", "3108f029807e8e35740904370e8300d92f7d0418972edf5436bfcdad02f7d2d8ad4ca73bd4a16c8b46d17dfc8115abe2dc23c691015c4643961bf67013825ef2" },
                { "ro", "56c883eee4a29edd79e72e8bd5acf7b18d4f5113e39a3e6fd78f73b7f448482168fb8e6ed1ca3d15bde3b9b4af649047ee55e477434089330db2c1b61cc9305b" },
                { "ru", "ae7b2cbc4d4773719ef8bae973c2e54d53eee74dbdafd94a1dd290c2cc98853ebf6beb990e43bbea2f5b0a2de305385cf6f95625b678ea0b19f8e735158169a2" },
                { "sco", "483518bbc8a4364731156d20716c429d536c5cb8cf7c0a303898e88761817f53d4c0bde26671b6f0e8cc89365dec625cefe6f02123e605e723a688c7a73336f8" },
                { "si", "9331b6eb4efa9896744a7c05c56ce12064d3ca1e7ac0b15925807215c5d7fe8a91efec8f2971679cd6b1900cb1ffb9a4ff872497fbd6d85e417174ad920e9f27" },
                { "sk", "f3569fa85052091bcbde84d14e938f2157656af335fb211da2ac53ab832f04b7d20194535063e7715d89e35355faa7f891f4106f30cabde14b1b55f607b52068" },
                { "sl", "fec0f677580a18e9685e2f0f4df2eb0a10cb5fb945bda618459cbc9612bc01de96d258f9e0896c438951ea403e209454ba782d764272724a35c543a58fc554ae" },
                { "son", "1d3a74a30490155c68d39091e3f9bb78d0777c745e8ecf1272f90256a4be8b65a8e1036de297b5ca869e32d8ac8b9ce159398f2a0f7a5b7eecac806a883aa924" },
                { "sq", "0ba5f985d7ce55cc1940a34d26162916a6af3b40f0e943bf98918cb36ee183349be056fbce3cd22f94a4a9af866bf7a159599073793954e8b1a2b7a7c54b26e7" },
                { "sr", "bbceb1dff46d1892a427db107f7990b77115eacd5db7f8d4df5ef93c0760257cb03361a433356c0dd2f29ce34a7bc4689e62270653c19f8f74c18f6b28e6bc13" },
                { "sv-SE", "0cfb0fad7912af0c49c7f92dc0b597922800f0c598f50f26b6b34b6158571651f6538f1fa94894a366b477f95a6cff1afd148311c6108b5dcb78ca935e889d58" },
                { "szl", "100ca6a84e2499277417807d40d82cd8a91002093f9c564fc458c92060f127c3cbbacf821a0157f66b865627b8ea239d540c31a9fcbcc13d8fa67c95b2683278" },
                { "ta", "cd2b090363490dfa5cab6a41fa4ad26e13c91eb0569098b298da8118c40cae7afae520b5303290ebc13b00867b15957946102e9178f08c171e7032f6292a1004" },
                { "te", "106bab014f61556c0d839f4d99ff1697f678f704fb4f0c945eeadde5b8d71b4305747d2cfcc7f54a889c4d39a8e41baaf953e831cadf969dda9cfe7261c1454d" },
                { "th", "51a734c9221060591e67a2a43c9762c48cc09ea03555297e5728ea9089b18494055ca888846d1e6e6e315c29fb0dbca1a3cf34e004a3280c048dce3f8d1b95b8" },
                { "tl", "0b6df87d4a3eea36cb3c7612e9be3406bcec5c15a6342103d312f7e1b957b897d5a2365741ccbf5bdbcf7bd3c8a63d16418bebe1565ea9dc6f02cd9a09b569ca" },
                { "tr", "e71ca49af0ee2a6dd5427c051f3725ab808338e062e85f48ef13b112f265a972d0e4f4b0e9faa6c3ca3f780e7df7fbfa0381c75c955f6f7fdd4c2a7ec5222f1b" },
                { "trs", "3f8a9b46cd4925aad5d567e84d1561e21948e428c792d7eae48f3f21e1ec55122054030a844ba459ca1d19315fb6da2d13d3aec838d87d097d1d7486bdaff953" },
                { "uk", "43ee6157101bc4a38d43eb182b84940838972d0763406ec97667be12277ede0df4ebe29a08ede587646f5e24bb9461733b9b080e0cb501ffed6de9dcd02092a2" },
                { "ur", "f92ab31be789aa88ac22a54a98dbff89579650862d58c509c735096908c3a0e6244bea359a73e3ef78e71869174b7cf363b1978dcbd82ca94c378cf2edb481fd" },
                { "uz", "64a1f873c26db57d03ddb40b9094a674a4175735e0d581f078d2d26cbee2612f6ee651088bc1e1ced88e43bd1fff5e541bb621ec9d0e7fab80abb7dd6a3721f0" },
                { "vi", "a87a71b708b54fd81280779320450309a0ed82e319a792ecd5a6ae35c2532a80541ba3dbc1326ebf4174922186df87fe5a5a8c7dc867a156bab2f7d3d046a0b4" },
                { "xh", "15a1042e0111f849b1fae494570585259cede6d062af5d972270a9744672ac00a9b1418da5f10ed6b541b88071adc36b5f98e42012bdf7e0c88a0a5cfb3fe930" },
                { "zh-CN", "7341bf0d3e1ccbdc89e6610cd8090b0d4249d675a44853844ccb1fa123cda281fe9b68e2b6107761deb380dd2ec498f7962ec380b49628063e5fe7051cce05d9" },
                { "zh-TW", "47196e9b5c5355217f85f57033c75d06315f07b648bdbc079dd940b26b3c7404208cccce890bab74b36c12ee34b0691900ed9ecde95119d78a1fcde8381bff56" }
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

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
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
