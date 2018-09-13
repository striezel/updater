/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "63.0b5";

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
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
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
            // https://ftp.mozilla.org/pub/devedition/releases/63.0b5/SHA512SUMS
            var result = new Dictionary<string, string>();

            result.Add("ach", "a6d288b6d5b9e036e4cb6af81c4159688b143ae886d9f7acdb7ecc19e4fe20e64899ec57b0106f322867cfe8ec00c1b698570c95e038424c0593e36f1adb5678");
            result.Add("af", "040a3a152d9ab2b0df3f3ce75d0fceb5c8b6b3cabd15f9762aabb2fd2430eaf01ee36620d0872104b201cced115f9a8fbf631e98037ae43c42ece646871d1c6a");
            result.Add("an", "522f079aa61169d5e688efdd0ea4efc1be1adada9b929d106d665fa594bf0d9b7a06a34779d5f9c8a7cd550dd7cbee1b81c9670bd969a8ac547fe3f17519db7f");
            result.Add("ar", "2e76cec2c95f106c2c84bd93bc7273873e38c018e5fb14a7ce19d016aecc8e957786f73b1313b5b3ea8cf4a155428595a9bfa7be51d4532006bb51f1f75a62c9");
            result.Add("as", "5ddc522b2c93f95a10b03a9289b8389e55cce2d37f9eae5a445c6394c86ea11352e80e1e0b0174136732ece4dbbd5f246225f48ec7d8039d7eda16511fe98b16");
            result.Add("ast", "2b843734793dcce7df74914e4a1d04b1338ad1a810240f8e866a6423599cea3c913be9796e29ec9f971e0610ad9d391209f6ffc05e76c058c2f07d74018c9344");
            result.Add("az", "d03ebf73e12e0535a958e292cef4c20df85cecc272038d9a8e19b63907039eebde18fc096cf487e192cd84d656430e0b4c8bf2eb0954970abbf9ded231f2b826");
            result.Add("be", "1a3203b30799be6a8194c05b5446a5eff3a0795a6791d4b51d95d3fe99c9f0b4a44cbf635f1a2743746543f203bbfb4cc8a3a72e5db2b4af92a3fa4a3b6d7e37");
            result.Add("bg", "dea8c8441065aacd5f30716156159f1dc2cea4ba3aada8f212ae9f26d58bbfbec7930bd45e0e26416c4bfca4625f2f238f8577029414cf1a0b4dc9693a6745df");
            result.Add("bn-BD", "55d56632819ba445a8becbbfc20eedee19723a8e4b88f8649b25eb9de98d145c950f686e000b1c59f4235d7f7f8bec8a8bbef8fb3ce2dff07972998b72053c63");
            result.Add("bn-IN", "75c48e9bf1b155d15ee8fb88ea88f0c963a8ef37f283f125db8bd014cbdb22d1daf6bb081feb57c2123e7fe8eeaecfc97ddbd6a5689d8bf73962bd2de304ed38");
            result.Add("br", "a94fdcd28ab64ef1fe5cddacd54e78c0b9a76650857a1711d58a3796b7e38ce8a518ff6b9bb8e56072cd7ab8754a4ee016df4c80323785efbedcb30df605536a");
            result.Add("bs", "03683a5fda27b27a800fadbc2226baa7621b61d7e03788e88d82413efbb24b4b758300dbacdec3ab65f9ff391e17755d0beb0f85901e3ff129c6cbd469896cc2");
            result.Add("ca", "fa5dadbbb3296c6db631d515715bc468aefc878726757685690973127f1819004ebd46abd651b8e9448ea84e55f866eed3f65a331a9d6c40e3d56be53cbece1c");
            result.Add("cak", "d6a01ce919595e376044f2a5787e418ba5626e678f57b95525de8c83dbd0e3bd7b0c14f4274a6a4140145d04e83ae294ae9a1f1d780caee527020a07e6cea595");
            result.Add("cs", "57ea8ba333cca318f2617cbefa64a5ced875d22a9a6a91ecc2edeb91d382c4acba41353329dd7bac92b41fae101098bc59b1e41e21c9046547a6c1995a2bbb9c");
            result.Add("cy", "5944749307fa02ac666e643ecffd0fd005d5d92f498fec3167f3cbf522b4de2b1b243c833ddec2f0402a35e4db9355d163fcc176be82c17af435c93ab2935f5f");
            result.Add("da", "07a28faf6915c0d42477c1b9d30967d10d6136aeb71e05047a654a85ebd1f5bb1131f4453ddcbd173e7d67d628040c76de03affb635c104a43cc0604f5d67078");
            result.Add("de", "50b0a9b4efa64f53fed124a3bb7ef591b01ebebbe1ca243fcc8963c03f2d16b54e7e1c094feea613c9a5176864660a2ba9a0ab8a62f7070c50891b39339175c7");
            result.Add("dsb", "6cf2b9197e91f71c147ef7933bfe184ac5d9a791f662f500a3b2667eb7c3314a9a978e1816157d9fd1637f82b96eb9e3e82a73eb3381337d961c82a6900ed976");
            result.Add("el", "458120f97500f359fd0007f5ef30f1ca913884f21e5a31cf575f00856517a92dc8eed375e4d7475d053de5a56915aace8a786462474df570d923c0491b5c42fc");
            result.Add("en-CA", "be42e19cfd1ec5428c98be759825c674255f379baf00a2235196d00f46ff5dbcf270a46766303c6b6eb741b7ab9b19c87bd0bc146d325881f189ecba1e2a5f4a");
            result.Add("en-GB", "3a9559b31a7e98a4578d754a3bb77e8e342d66ae89ed5d948fcb24e0f337b7c6975e920e3882031cae35c70113f1e25439712a0dc078225d388dc671d5fba02c");
            result.Add("en-US", "0bcd96801ca47f65d2df5c5d270e41bde314d2e61a7f62e34c37b6c832278109d338e4219d3c21ee8508e9e519e8904303252d92b4ed9c0c8f2b21a71f5319ba");
            result.Add("en-ZA", "a91bce2e30e5a93c36a8fc7a821ed6c80fcea5beb78b5ac3ff022519f2368db103fa824579720123329a1a22db413be525af44cb32cbf2c93f3567f531e915fa");
            result.Add("eo", "607f8fb15e50376a1b1da15d3f867029b7c134a5bcf557935ca2b54ba3333700174360d5b2c164dcf472a3c5dfeb76f3720f8a770ec4eed59b498bd6d247b02d");
            result.Add("es-AR", "a57369867a5c7539ed2d191a4d546d5861be1ff4b247904ea00e5f3fb4d4f7d13ffa0d3cf733067b8ad3be581376fbe1260b53a621a50f0c21090149bd338c06");
            result.Add("es-CL", "ad926df6de67406268470b7b1441ec4972b9fdba0a72d5a0c0d62b61f3f02b955b53d38b51ad6fbe82bdde5dc72f24e3c43c2ed94f1e29287c6168465a9de183");
            result.Add("es-ES", "c232bcdc725bc6280fd39b490c44ef2fb784c507fb039ceffdc0b498035938d16c4b183ffe789c18af39cd6b7f823375072302787c0b05ec3e6bf2776fdf8e4b");
            result.Add("es-MX", "b4a7d2b546de4e7b4a89e8f413059b2e148e4433ff1b88c2419500fafc94c9644c6a1eff70d77bf57043f1ffb35fe9e5da9d3e6d53925f0566e74fbffa16a6d7");
            result.Add("et", "c8b0869e03ffaf8a906c107e6b856495cbd39f01dfb08d2ae063fdf8dc228c2c76d3c53322f8b49782bb2b3c4dc6579806cc124de84524b3a6c1a37179cee2e7");
            result.Add("eu", "a396e9903728e9dd2b499079f8b1f703f301b7dc618e7701abb0d73b392d799da9c8f67f373a84417eb31af1570aa523ffd046b6db137b7d27a343f943e5924b");
            result.Add("fa", "e93ef8d46b93986ba58fe0677de459bd92830e41989856c95c5972a4b1f486783811e35c0c669d8e94717fc0885b583df0b2e1f7ef6fd5824146f189fce6b2ca");
            result.Add("ff", "3df3d4496c664a12451d5c2ca66ce4918052756c74ae88c5909f3fde44a5b6a639046362cdb33828959a0589a2c68bd07b3b4a2acf6906e611a5aaca06265536");
            result.Add("fi", "4cda3fe97ea84030d1b088bc42a38740b05f21b10a23dfce88ad5f4a35b26b65a3d8955120d13374116a7b9fb805c4424cc0b2ed65f1b20649698b49ea053a6b");
            result.Add("fr", "f4d53186cf0b2f578f330144f8c4724d2d325488059f257db862569ec7978b717b71c6512dd6411d2e28566250c4344f7b4ff2010696c80cc461c7449f929ad7");
            result.Add("fy-NL", "6fa944def58fefceb383886a7a7f6e77bae7b68724aeba902c10bf71f3cde5677026bfe14c98bb84e2ab784330f7f9d91cce8f60df6b6d8f81bc0fc49acb1cd7");
            result.Add("ga-IE", "03550d1ff1012f02362638462d65078b7c1d1bf7ca2b6c2df38a671190f4e39a4ad1e0219d35e1165dc3faff883a931dd1c0f62a826b8b61d7c360a387f6688d");
            result.Add("gd", "1766774084b84d3816461b75d9580a1bb0aeacb8f82a15accd5408a72709834aa72dc14580fa922b861cd9265ee1c3c15b6e9515f7a6d7a348c7526b3c82b9e0");
            result.Add("gl", "6a326c7efbf2202d8e7a0af38aa2e851b7a58248cc43e459fb8207049c6cff7ccc179d3d9982f499cc03712cc48f8c64f7c2eab8c9bb2672f2c4233d174d2419");
            result.Add("gn", "19f5056e3a948d23c528336e4c092e5a73a6e6195f99623c060df8f3e96f6f872a8f25207cb67b7dae36fa2096aec19d740f2e5d5f28f5e2ff133a82acead378");
            result.Add("gu-IN", "9a4658d112396b000bc3ee56597419a642813a16b29ecd4a21d2b6406027fc57baedee470338da6d8aae8ae323716231d1e3f89f90d3a265ed52c897a8f20172");
            result.Add("he", "5d5e23afffb354e8234f0256dd79e15299f0b44dfbaa48f5c33ce8aa5768cfd52e8a0e8af45cec217c46fd37836b5a431a5fbfb396a3e9ef69e17164720bab76");
            result.Add("hi-IN", "b08ef3863a950b9482705cb280b1a47dbd28d87279439afc8525b4677aa6e58103323f53434031e10ec394e373eb293bf1cb0e57ed68d6263855b88541b362d7");
            result.Add("hr", "61b4c36b672efd4aea7354b67856e449dcd82edc71345dda974dd0893a9b487919859f5904be49862c2786da2ef884025d103d3dcb937b3b48ec805edba7870e");
            result.Add("hsb", "0e34055ffdb2dfb3e339b3313a4ab8653a9e5420fe7661b84ef616505536e755206bfb71a662dc106aa3b5b1ef7606f56ba2358272fc63e12e5c538d814de6ec");
            result.Add("hu", "299719074c552e36919e5d776722897a14eb269ff7f7f53aadd58dd0d4d9eb4e73b183709b2d6e0a721f56744693e314f61fded164e6dd66157b586d7a4a7f8f");
            result.Add("hy-AM", "98891febaf9f9086f20d592f6734fe6e148c548d6fbd0a2b1994caf0797cb3d6b9c6293eeab81d22784c6d9cd818ed58749886326a13471dd2dec2a31ac62720");
            result.Add("ia", "fbed601437b3bd1a230a515f1b5bb20351c25e904ee37d5231d52d0caeae458ef0c69d12b1d92052b200457728003cd4bbcdc7732ab42682adf8a88002fb9084");
            result.Add("id", "10aecff043ded7669da03bbbb20e978d64b3367086ad2740334df72308d65f172e2d34529c7965060faf47da6ae4fabc76f4a9708589c71ba66b6c0a124b02fb");
            result.Add("is", "0f2ef34822bd8895c75927d8cf5f28a38f7199ce080cab6d1393d5fddf9b9837b1a45988ca5e6f7ff65643c22bdb67bbe80541f7e53b405fe10efc2b08ec78ee");
            result.Add("it", "40ea1cc4fe4d06505719fde6507f84e849fa31268651d418b1c5d39ab0aaacb46aafc049c23a63a838150213fa7863eb82ea7fab965ec80c5ecd3bae905b73f3");
            result.Add("ja", "e76e0b6b851cee57c1b0867ea1f3d3d8980a37b70ce027f20a9b4be6f4f90d69f1139de81a9b93fdf0583f7593dcc1bc911291f2b10f65474eba8a3ca0719147");
            result.Add("ka", "9e406f32050ae984f0849426c022910d54815898056aaf7aee09ef12580fee24d8c1e2db1c270cf072d8cd3c21a1abb337b5f52a6dc392d8d7b91488d36c0957");
            result.Add("kab", "0077641947d30e0e0be78535a15fa08e9e98e1555ce0d4697161490f82f288ff772faea564bc84e1a5105e0e02ed5f9be059f08f5b05dcc44a84c2ba974ff94e");
            result.Add("kk", "798ee295b656270f0e42b4fb241c6a3991e90b3eb202e8a73e11b84df25b29891e89dad97f4c9d67ec8dd1690dde55b263f3b7109a47871a427693c571f94b6a");
            result.Add("km", "9acce8bb5c0e2d4379b690de996280cbaa7ae26d3d138c817f86aeba189c993ee65a40220e23a5a991839bfdf37ea8d0e44d9656d5652c7bb3651609a673ee6c");
            result.Add("kn", "bb751f84dd9dae69a1486d7f33d10f694da4f3aa45b601de876a18d2a3b112c2abec423292521f3592b7b35e03d3fa64d8d386f4207da33f9298d82343743e5e");
            result.Add("ko", "e3fff96eb6544e9e42508c88b465dbef48aceb5cdaba166353e48866d320ade3e4d6bc497583aaae3fecc59ab71e897b937db13d2f41b1ef5944723359210a64");
            result.Add("lij", "268e5e56be491dbabedf568dea17edd57c5c225594257ded0156e0b4dfdd4387377f6df1a8c717da0a25060910597026c049957957ecfe710123088025bfa2e6");
            result.Add("lt", "adb57cbbd8a045080bfae5e0a11bd31615d550e11a3b655be38899550bf27de7c653315dfbed18d27d48652471879675159a6ef1bb5d8ae630a7600be55127cc");
            result.Add("lv", "d62d8f9d8d571d4c7ebe6c54ffe9130a002ab05b8a341edbe9bdd53b74c972e2bcfdae19a5e5fb6314d3139de5ac8a6f79db7843534d5cf2734aa4a9cbc579f7");
            result.Add("mai", "4b26e35909d747cb117ea85115d25f0b4649413a732bcb640f1772bc485bb94a41ba45f8d8f86f7605d4b6d106568728f3c113723af5076d6e170276744d24e3");
            result.Add("mk", "7118561391f14a4a06a7104eb403b8a06a06b8d820443fa92034eb578a831bdf38024e1288560a9cc99c8d170f770f1c50cf40dc9d41090f8dcfa04fbf4ad106");
            result.Add("ml", "b9f8820394fd8908ec641504ec7097bda00c4a961c0a6a77d6281094130b3f6cebdc251befed4fc2a1d6657ee29547552a7dc336af0c1166fcaac251fe1cd712");
            result.Add("mr", "8573f9fde7980b2cd34ed2d0a83b92ac56346eb2b8388ac88ea2ae3084663521efa96cdc9ccb72963b34c7dabcee97955af4487e025929ce9649a34ae5cae03b");
            result.Add("ms", "250cb19120037444715dabf39d4c258d59ea18204a895f35c32f426dd654e8bdad32de7366748300c4f5ef9c305634329db07b3c71c597cdb01b5b65457a805c");
            result.Add("my", "3a242fce08bb430df599358b0426059accb009360d23680a843cfa8c9571c9673591b0cc1f7de9802337f5fd9cde13f839f5fb2c6e77a73317276b959db0c2c0");
            result.Add("nb-NO", "d4aa2e45e13c540a7168f226b3950e8d0ef7f89a7d927bb2dbe5f6eb248df98b01d0ce3e3702e9c4ca9c3686eec301f875493209867039cd42d0dbaddbd8aeb1");
            result.Add("ne-NP", "d17faa8780a630e26c25cac1e60c72f9030c6c9190ad1cff0fe93c046babb2e793c464335a1cda39854a9c7e9dde4e5561f548ab8575257f1c87a538d75a2e9f");
            result.Add("nl", "ddee1800c6ba4e2da05b1718edecc6910e12e9b5faebf3d6a25e58fbbd0fbb914361771ec41836eb6994954365e6947107fc7914137755d72de2a96393ba7fbf");
            result.Add("nn-NO", "ae9d8ece109b2e8e911767ba0853475756f2cda9492737dfa136b453f871f4d1bb5e2f77f9e556f0fec94746063ad3de5c80fcbef2f3fc8570495114b5430b44");
            result.Add("oc", "490188f318095477324a0937f0c739396bcf217b083e51dda36cefd3d383890a579fa0e6873161d397a442d0ab479e42fc1f65dacbe0c14b184660c070ffaa15");
            result.Add("or", "6782404b5afe34863a9148047d90a8ddb0a42d389ed2cfb7e69b266d63f8c4571ebb7d2cfbb3eee29419b642e3834f858f2e771605cf81b4ab1bcb47bf957384");
            result.Add("pa-IN", "85768a2bf68745b71046e116fbeea65a0f1897da334b1a8b84bfa9c17ae7452cbb9c567d80c4e39c19d47ac9ff4a51234eb047027782e9bf44c4d26bd8a74249");
            result.Add("pl", "06fbaeb47c6fc851237c0313ad44590e04eb97afb97f7f1f7e471b670ee9ca9723a3dbda0fe959ead3bcf9bda95e724ad124f9c0ce11d12036a97f8b4e6ed3e0");
            result.Add("pt-BR", "0abe6a86014ed7fb9af278751c60dd1c620c49df87d3f16c9a10b324c6164d8cebe8ba336d7d7cae48c9264e6e154d9948f09464cad3e86d066b9d965b3c233e");
            result.Add("pt-PT", "9cc5b41d3a24a9f2c84e0bb21739c2e8b6d1d46d463e893f64f19d92f2e33f45f8f409faf7f02eae010033bd030f437bb07c53f349e5d2575b26b40a72b85c54");
            result.Add("rm", "b73a51157a8e03b7fa2be1435a9686c8b8abd0f6139daf29dc0f59fdd880a55957346b9ba90967fcf10e160b4c3ec7953793040fa2ea397a36323e2485b05bd2");
            result.Add("ro", "83483033b5a78aafe21f6d37a71a0fb291f53a06fe13283a46ada1ec273e39a50cb77550917305337e2833428be4396ace12b8ae36b191d850c9818ba35a3791");
            result.Add("ru", "8c0efe0aa95d3644c38963044dfc7055e52446c13dcf7c26ef98e30a2c87fdb5491eaffc9f6158cc2e546626b90a519c3e9b1f2f76bcde7a363c7226354434ac");
            result.Add("si", "d4e49a5517d1eca60c977f9c0be26c3ba33cc1bcd0af0e1f22287365210d86742e3fc87fd1d716bfafb138228a1274dbd43f69a657ee6e018c36c1b7c3030297");
            result.Add("sk", "5f6cede216415919ac1810a3de31e750ac4af11b7e0b452781d9f5d2a4835c684c51e4fe28eb5cd1722a85d1b64b605e0161a5d8650c9849ade11a578d294ff1");
            result.Add("sl", "d130e26022a7fb8069ff78a5689490847d2751e2a754a5197ad5befe126bf27c8b792020479283875e910da25940712ccbe75a3bcec063980f005667d957bcb1");
            result.Add("son", "1ca563912ad9b57b11127fe760faee76239686a6e69ea4015eee21006b9e848165a47118b3e6000941e45315841d31b5459ae803901bd2e4551b576e01c71106");
            result.Add("sq", "3fd879e41e965d373a9c8bf39c1ef51c7440f112df3990eeb18fa591002b14d76d11d4dcda6ce3185701c94818bf012d4d674aa5a17950fa0d4430ce7d825ea0");
            result.Add("sr", "5955cd1dfcc20bf9a4e512bd4936daf064bc6c8edcb3ea4b13d51069a6bdb9aec6e8a623082b94cf0ae00424d2f29a02e2023a9b4573d3c82af712fa37cf9e0e");
            result.Add("sv-SE", "3c15579fe750c67574f81c860a1d4310f42b3f6759c9e80377ca29d54ee1d875feda1ed26e5795beb1a2d54979a2756f29d94cce3a0c93e209de07255c2b1623");
            result.Add("ta", "dacaa3d5d8d2296f7fe3a22888b488edea6c4b2773b4efb7c2cccecf13ae903adc1ed1e607e1c452f45c6ee7dbc8f53f31afed005663c4149240679772f0d6fb");
            result.Add("te", "1186814fce89154cbce05eb7e853d52cf2cd517ec69a947559c7a5d43be3f859b2eed9fdef0aa11d65bf387b2067aaab236eb23badbb9837f70351b38a47225a");
            result.Add("th", "185775f550f6162a4f0deaab51232e9f2773b3e475cea2b2591636fa2928adbfdb6e973e504409d7696acc2a712358e6134ab5de18e2c744c992e41177d71b89");
            result.Add("tr", "512791ce66b78491d4830095e9c7dddc2e9a9108b0c739a08c1e391de04b4582259271e235403b1295aec457830ba7fd2fbce50e50f42f00ecad5ee12dd62e0e");
            result.Add("uk", "749891ce06f7bca4ce942ee76afffed4022f144faa7f79378004d9b5ec55889c380dc885937451901dc409cced02dfe7da6998d65acf3ece36e1127f9cf580ab");
            result.Add("ur", "054ea536ec2755da8610b211660ee6bdaaec703fe17fabb7e6d312664c60762354c675134e06086432088d35324e59821224ab3430cd146d37078279504d246f");
            result.Add("uz", "4bf28885340ca28aff43698747c475412a87f4e0a831b136cc5045d88f2cd17c58ddb2f62ed261c6fdf36ac9d80f4e18b339f3ce9dc399ae26cd38d8a797dcd0");
            result.Add("vi", "268178369685911b4d2d3adbcb688370266bcc85dd5884b24e7d803de182b4c6f6c868bec435893ae3022383ec26f20c49f8393e4dc9f498086e2a4109b31896");
            result.Add("xh", "269dff29878f920bc53487654d41ae2070192aa2eabdf57ca85b3d19068a3a3f6db78171c5b6a9dc6628cb39b4dc047a7ef1368a36d537adeae5ee6dac74b5ff");
            result.Add("zh-CN", "27a5cbc39cc1b0eab8d1a5800e15e978004b747328a11383aeaf0f13632f5c662b0d6d7a4540079909f679c3404aa60ac2a229393fffb96769d2e629148d4f0d");
            result.Add("zh-TW", "0f27b0e7d492ded2ce675ce8aeac3b420a4d761bdaaef2367ba8f1f8c1765a43f4868d510aa957b78db151a1f80ed8fd6e2124be27296446c30057615afffd10");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/63.0b5/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "2b86b1faee8516b74f78284ca37337f0987dde3bdb25e64d5dc6304b4cc55b4ccd819483d528d36c5eb72c22853d5cc3fab5f5a751382b1dd4f099e065b0aac7");
            result.Add("af", "f55500006984dacb522173eed18e5bfbd0be04d583c78448bde204ce0f8cc92717235fa87a21432518008856da392e05964df7fd96fba9bce2365d9aa29bb947");
            result.Add("an", "23680a76f9cb30e3cbd432e58a3dfd77814082d431a8057c37c28fef54892f31bed4354610aa77a968b795d447416031208e0b6621306b2ad7f3effbfcd05c2c");
            result.Add("ar", "7c1bf8ff5fb0207290ca94b8f2e71194d6dbf3e845cca9fd128c978f9e7262fc8b22d41d6b2b21b70166d23c1de3b286d2397f6581960881b54c1cb2ff6e3dd5");
            result.Add("as", "5354ffbef8b76937c0de365f6f663253b6e13dfb927c690c22a3e7cf35798e4b96fd7b1a00928bde83b4c0a8b53ee20599e13d8466a0115cd23162e7ab4cf43b");
            result.Add("ast", "0b524a460d94058061fe0039dc1dececb0e32a60f4f236c5d1ee0718d0d7b0756a5cc1a552261bef5440a3a209e815742aec3b6b209ce35cb65dd995f59bcabe");
            result.Add("az", "e4e51ec47ff4eaeb54c7ac2194be492bf3a44eda402ed59e75538e2fe370f36e2c3f6f4eaf542c7d43134bc88a62e76d77eca2630557681bfb46c1ffeee4a0dd");
            result.Add("be", "28fc3ce0ed4cd67a2c59b2fc8b8a0be85c99026ad76185f0ce77b12e85c32cd9f4c8323e812823af75804245b4b15c7e37091ba55a4e91595e01bf3699cdd0b4");
            result.Add("bg", "fadb1718115949c9caa5a545411c371f94102ed81d1f427c3a0221a83b704d720e2ee8161813c3b2624c30134556074c89d720a81fc6378a3f287e7c2984dc02");
            result.Add("bn-BD", "0e537eb3495abc537d5dfce2b9380dff645e0e79e5a0b1230ec2e4007d62f927f074b7a9c90e262be7605600bb8283d631280dd96aec81cd72e7d84dfd3a7de2");
            result.Add("bn-IN", "5e9917c39d5e49e6b2f40cb3b8aa7df60c754b18c20a463f8bd02efa556947b80cbf1f10d3d6a8a77a8003ad73dd48fe50b1f8aeec4e809128250252f03d6383");
            result.Add("br", "21cb5091f90111d2f76e6de3235f3c19c853062e376c4c0ee34f812b0d6ee06937415b5ef13ac73b23b0836cc8fa47890e198ae67f286b61e9af4bccb1ca7d53");
            result.Add("bs", "fd25c2a94785b41890f3e3b697a6b45b020d91c02c222078236ad887a2eec72aa92ccc52ca814165e3f0c2fbdfcd5f947d3ff21e772020aa7091ea64ddd6a800");
            result.Add("ca", "99dbe8b3f87e8a6206b11cebfe7781827549a086d40b448f5074a05704f6e7ff73658df681d210098dbf2b4c8e464b25b4f507860efc48985317c0658245e83e");
            result.Add("cak", "61ae48237b86620b66030be4e79c3e79dc18d1179dad14ccfd1c8691d6aae65dae7bc72fd74bcda8e2de5b775b551eb51bf7edeef2f3b97cad37e8395ca396d9");
            result.Add("cs", "f407ed5a37b0a7fee4c5b4d684eed9543a27119cd3a2f2e530cf5706f5322f9cce1474e028260997d33a6528eb5bb017965af0201b9945099ca6a1bf1605cb0c");
            result.Add("cy", "e28faad808b50cadc2beed64e163ec881122011fcc2adeaa5df88dfbc50afe4b72afe4cd272d6583be8f4e2b55c292d9e17200f6bc7bc937ec2bbe5a66cae21e");
            result.Add("da", "07f79f5b601c965454c6a6578c3db07dc8567c22f167b2cc97defee0a69f23a3968dc92206602cafdcfb61f579eeee1c7ac05077c92e969b13061cfc6a5fd0d9");
            result.Add("de", "29ac639d7e9230edea4baa04b5301b892bb165ede7f8b5d974eaa7a356ea857351dcf5c493afde26d6b75818366ad76aa558c7b54f751152629e964593d08196");
            result.Add("dsb", "bf25521d016d899ebae96a766cf9e47449e45df455a986ee2b7d608e631bc6493bc6c1388d12d749eac6dd29b7335efa5aeeabe4a52bc88f00c130b3e0df1829");
            result.Add("el", "a07dd8b4bf15d40d2a01fe763e2379126217a4450e5ef5920da3a763e409ae049bd4d1c919ff61c45f1e276cefd9a48bc996613235f65bcaa827f586a471a5e4");
            result.Add("en-CA", "bb0b22d5a710fdf81f414d0c9e338153120267b31bec9b19ff6743e9735fe3672856513650259f46b709c96e674aa96a52c8d5148fcbb78922c1ce5fcb00812d");
            result.Add("en-GB", "4d912526fee7835960c037c242339db4ba3e2dcbb06339ff10c1f2ce268d726250ac0d57c830dc9364b3dda2695f5ecae262cb5cc37965aeb6a1e0b95a1ee0aa");
            result.Add("en-US", "fc93928475884d420cf162668464b2d438cc1f6855e6d9a9b5a99f033a3b58f04c629e3aa7876a6c2248b3ef8ce17637135900241f77cb9997ae127b91fddf05");
            result.Add("en-ZA", "bcf0b0f9ee1a3a1effc86a9d61becf1e49834ebb4d85ef2b8656f8f4afca0e6d03879ad0ade9bd0ef7e3bc369b62345b4e53a243b4766beba5380d7943bf8a3b");
            result.Add("eo", "e02972d52e3ef0d12603a604edc76172cc32d3a39f8dbc1b396c187f36013fddc4230f996f02815335eb9edb5ae956119a8770a680fe535f3ddbf11422627836");
            result.Add("es-AR", "8321de24364113e83172fcd62044b6ab7575d750b1b3fd3f3f4edb0a8a6558d7e12901c8159bd4f0776169ac8295617ed57fa2fa17e6be91cc36c2cdae2c93cf");
            result.Add("es-CL", "71de1291f63b2b388f1125b627d42487c65a7b1e44f880138a69008b96d24cbd7dde6ece8059154dd7100df42889f6b28aa41e13a80ee606062840908478dd06");
            result.Add("es-ES", "27ebf5f65b73d919ac4f131eaa0d7010589e3f8d39e39054d265e3a4fdaf65e8fb53523d720d32361279455da83e0bf55d4ff1557d5dac103e648f6c6df58387");
            result.Add("es-MX", "ad1494c2ad7c178a3e86a4d1ee2a4a0b6a4287ca90ee9f87499acf33d1fe31e1326b2ab6f7cc2e0caba2a7d5ab5ea2a33246a749f8f1973fb6f6d15fb2514a31");
            result.Add("et", "55e9a5a05f8c8316e7dea6abca931662e9680b2b9c51d51275e4adf5fb149dba2ff46f1644018ed5b28b44d646f138a5f4b2949b4f5c6f9bf541335868c3f9ca");
            result.Add("eu", "5a55baab63339d06236072bb7babed2572c94ca50b637836def3835184de808b3d56f2fb6d3e4bdb2eada3e76403907a09551f05b589e90ea5594494d4b40bdb");
            result.Add("fa", "bfa805492e4d6f752b767f654eee75526f1c220e85d0b4f14b274f030dedeb6b0541dcd293c5b27f1840e3d1e0f899cb6a5f33895c26755c1a76361dbfcccac5");
            result.Add("ff", "2b396cbc0aa34b569dc315b251caba72f65a94e4e916e48fc714fb46e04c842c1c8d575ab51591b596175b14fdd1fb7c5428f8cf00e194f84dedaf275bc0f249");
            result.Add("fi", "224d88ffbc2cfffd42d0020a6fc1f4f6021d20c13959eb8e2eaf96e40c9a47390c84c876c8e1cada07dd9172d1604a7094732d753193a35c03b275e6a3517629");
            result.Add("fr", "d0a1ab4c29e0606a96273a8f1523d647c30ac5b21b51c03fc03c1a7cc81cbcb08dfef1c5e00ebc5c1241302c89d7493795863e740a3fa2bc6b80c5e9720147eb");
            result.Add("fy-NL", "9f3db9caf97dfba5a909454f96fdab6a9344f5ae80afafa2f699114b709973b8419a847ed8d579e4fd140a3b372959781b7b8c3f09e2d01ca1417eab4fce1c15");
            result.Add("ga-IE", "156aa6019a1b9b613318faf138ead1d45190711b2dde9619c9aca98858aa7781993680f4ef2f32543ed42fc89ba55a43ebf0b8b5aee85100da120d46056eb75d");
            result.Add("gd", "79afb76e16f0ae8d248ee7fb6098ccaac4314465b99c10258c710286376a5e573359e7b1347bc5081ab506123869f3cfe7afce0a0285e95ca6b440271e9c6d62");
            result.Add("gl", "af2f35761cf724399a7983435d70bef2685ffd9a90d3c7e601510ef0040b031c27a410617482890be778c43b21e5c5e94c81238de7f19265fbd63c7dfec1e0d6");
            result.Add("gn", "94be861f879d844298acc08888b36e3c336a44f6b0e02dbc64b549cfbdaeed0e86d78812df0d0c69337b158e2bdbe8cb5b3156d345b72bd41b026e416bc58274");
            result.Add("gu-IN", "0d550c433e58f7be5d8979b28c3ddb9c6a3a07395dc5e269761066401fc5c18b5dc03da45258e17321956bf47f20279e1b0f45f9ac33dc1ce4235491c6fe43c7");
            result.Add("he", "0b60a9a0ca44ec4888f1a57c7282475d157bf3c7061492872a78d50401d526d4d637a3133e80407eeb77f521bb98a6de4eafdc5d04f9571271a1aaaf66136fcb");
            result.Add("hi-IN", "1dc734f3555804dcf58b14c0ac4aa6ca25b56306b9aa8883ba6cc39b801119ea094d7fe970bdc53e65d00f6bc9cef766afba3d443ea0b2531aa5323d0a5c4999");
            result.Add("hr", "72dd490cb99693dd7a85f93ea756f022172993a3650ac0b3b279b4ad4389dfc6a7467dcc756d23601739dd24a3682cee28a334638e3feca94ecabef167496648");
            result.Add("hsb", "46973dcc1847545a18b6d86ac318109faca9b8422da941e74b12e746abb1dcd94b19fd5523b75d9e57f884d8cc4875dc0578fbe28f581de266b75cfc8b4f47f0");
            result.Add("hu", "becb887854212d354e696007918c15f198f790211ae362d5c7d996b82eaf07c6e9adbe1f7b3d86a441b921a51d28c070acb68f11545d40f7811bc0f1b1a14480");
            result.Add("hy-AM", "4420b85adba42faf00d40c4d892fd33747d3f7c7572647e5014fe048668fd5224ec79471edc9e69effa63ca33ba406e5af8471364c9e0b2f0125249815013831");
            result.Add("ia", "f840c6e940ca46c6aaae9d4ef1bb2b8f666d419fcc9ab11598a2352ff9ea33daac77960786dee2b717a21975fdfc4751ba977da564e599915a9b3b188fc59edb");
            result.Add("id", "2b2b2eda18dc541874e224ea252a45f42756df1f10a97995b11e6d9ef9bee84cb7788041fc61924ccc0edec5f267a3c15252d79e17f0921f0a9e7999f2a3226e");
            result.Add("is", "2fd2a099401977ec53746b3b1b9786ab48d2ee00b09c9ab8eda9a295c77e25fba574fd8e0784637143c262f6fff97bfd39a6954bbb6765c126747daf21e32901");
            result.Add("it", "d9e6a879193594e649634c5814c4e0ead4aee8dafda6abadaa5fd180a78546e5a5a6692d9686a1f2da57b0b13c10ecca6eae7ae2979037890e92c774a8089d4f");
            result.Add("ja", "eb59754a2fa514e4bcaf93f7bafe6d5a173a9e2ff7695adf18d3b224a31d62f697a82776ca4d4ef27b370763262ca783a434cbac0bffe1359d19ac6f6282aa10");
            result.Add("ka", "34be8bcc0ffaaa8fa2a6b7aa705f0bca05933542ec3f8aece68f4a974d54dd2aadd34fbcdae49d8481f3eac10e3e9338740dd0101188c3ba8edd98be0eae9190");
            result.Add("kab", "3dedb4739d432c05e21380a6180805054b6521d657dd3fc1a9f969009180212ab0065ef5dce4c0c16d1f34671b43a287d0f649f02a20ea0842249a7f73d5f621");
            result.Add("kk", "c9325c6302f4fa89b2be6fa3a2bfe4f576201cce7f9c8d8ce42257ff501e8de4214d6cf329a39086de8cdb04376b5035b1461737e0c004b093c12931e3f679ca");
            result.Add("km", "2e7fa98cb9f21a2bd32b362910eed54b3655496b136a0ff6ed088c121dcb4919afb2fafe143bb85d59518e39c60d0d720c1532ab6bbe455218835f4aa1787370");
            result.Add("kn", "efd9fc5cf1cdf491e1be88c82f3ceeda8798ded09b00b70e38c8258c765ebc2bda72037b3c1104812dd486241726296212a458aa4e2418f27ee58c15164101f3");
            result.Add("ko", "3853f272af79520396e26c990d5a4270cb1301f814711dd52253709fa6ac8670fc2645b48a1d9e447ca3371493cacebcb032a39349873695e117dab241a77b9c");
            result.Add("lij", "d0e8a948d1c4eb2f8714be00a718b1e0ccefcbd688c2a1cbeb5026dcc8816b128c2c5e8b803144db2cd3d2348287e45ea831710e035f3cec5cba4bd6f76956cb");
            result.Add("lt", "07c1f737621ce0420da903cd816b9ff648bacfb36ff26f0d6fb7b9746d4e1b8cb40f44817ca4beb33bdf675a8b0d8fe09f5d25e73739315856e3d34c82410b4d");
            result.Add("lv", "d16dbdf16c0ecf5a0f7b592c2c338d151b836e966bbedc4647e9174e3161ab31e1008273185cc08ff6e7bb69e245727ccf794245d8d4fb6fb656dae476e0a166");
            result.Add("mai", "f5a6e167cb6afe666bbaaf17ea4d71f9463264d82c7d0ebbfe8a246a6e4ff9529ddf42b37b59e6074ead1a8dcc21edf71487669f80ca9fac5914aac3e98deb51");
            result.Add("mk", "f3eaf7856a77aa9c05d5fb2528f30ad7e46ac47b89dc1bdca394b5b666b63518ba549f6be012178700eb649b1b41038f3dc8dbe2801492dc5dc4671440fceb0c");
            result.Add("ml", "2a0ef7ba2c5db740716092cae61fff5d40d2ab766e62bb24925a6e9bc627d2f2e3f14e024f58a50bd32eef8a952ba69f738481248a55f3a1212127be0adf9520");
            result.Add("mr", "3b6ac7a851a51973cb0699334e588586318dc2f43275da2cc339e915fd797d092a0d42b1e271cf80c56addaab4a008878de303d45c74b7a24f3bb2426c975df9");
            result.Add("ms", "bd3449e8413a306191003afe89de66ede442f935f845222071c90aaeba13c078d789b2a70cd270e1dac4592fdf7c691c1cc637d8d5c3abf66c62a974fa301664");
            result.Add("my", "83d04ca3d49ab4a06fac3065c1398f1f99bed34e88f637aad4e73e2731fbede2eda67e751f33b3162593ce52f44ed6567451d6e415f642ec98cf094ddbb2ddfe");
            result.Add("nb-NO", "61db6ac7e5a5ac0322c5180ea057131e2bf90e7128f26a414be3cce257fe75c8c240fc81ab28d229a2b565b9bbe8b2aba04c9efaa94cbc5c44ee64fd389ddbcb");
            result.Add("ne-NP", "d5394471bb132de3e9f0c4b4cbe956fc46707f46b1dabf6bb70b85a2252326912b3fec233cb98b31851d19672e9a743e24c8f74553da36dff204b7d77c11ee99");
            result.Add("nl", "fe63fef8d56d9bfd289a0aa3e819ead271fe589f2208f02010c5235995b43dbad6708420f900876348df157aefc8a652d0c6b7d4df9f0f257377678775cc6eac");
            result.Add("nn-NO", "6df72a2dc80a6cd93c3f269c1c1a03a7451e8c356b9086d7bbf5dde762aba3afbbcd8eba4a34a0c6143a04fff26cac07e80de1d88d353aa6961c4c40bcbfb4e5");
            result.Add("oc", "ae953a22895d3f2c5e0f9841d1451bcab982990b16eff615c18e1196033b00826565d7015c41b90b5d42c63f3481408a31cef6c6a369ffdd501d60d21a525caf");
            result.Add("or", "067d2f218b838931d73db4219c07cc4dc5a9d89ba43056116289b0678da6981834305a196133d5ace953de03ba3a8c205d36522a1eb9e2ee1a6ba574a1d273f3");
            result.Add("pa-IN", "726945a7fcecb44b9bc57c2e5bc1307460ad690399c2419c3024b0d2ad86a2b6245c5c66d22cf8ce2685c6cbd76979575143e346842d92ca005c5a470ad28f37");
            result.Add("pl", "288576ba98a8b15627cf12223b2b1e82a477a391b4d610927fd6ef3ffe4cda24b245b04cbfe213f8e78e20341b9fc901b93d0ed6a643a3e2547d3f5e598a793b");
            result.Add("pt-BR", "536e0378f9b47e1417714f30d73c9b0c3362a6efae6dd68d5cdf904e431316d4f495490dde678e0a4fcf06655633c828df9e0cbdc3112735cd3b6d2b00e4ac88");
            result.Add("pt-PT", "30b2c9b148c7eae953dbc1f30d18aec291eb559d8c77bd0e0ea648bf76d8a62a3d98195d7c80cd16c4a59794a54afd7820f2a50e07365e9b273b44624e66ca62");
            result.Add("rm", "bf43483fd5ed83f2a451ba55ce74d05df840a70d592aa72fd08aaf24b017fdb8bdf0efcb2bd38eaae8111f5e19795e0adfdd513bae5055259e5b64045eb4ae8d");
            result.Add("ro", "32e094f1fed29fe88acc76a6f4495cb190e707a2c28cee03003198fe7e4e94c44a006bb5b8a6c9d0ad6b47f09ddba28a93dc8821ee5e7e311cff862f9d03c05d");
            result.Add("ru", "670b76c74d744135b709e5f2dcbfd700a1cd3fb8fa5529fee5f0216f992ec48b51bfbcab6eb80853a586f5b9984fd4e21ec5ab0cf4e0f868ae9e331c25d83f2f");
            result.Add("si", "b336030cd1f931cb1b18015b49ae96d0e905f0fd38321f522b56f16d085d2c91f6bdf888e5ab265370e570fb8ebaea8830d61b6553ff100291765840f2331800");
            result.Add("sk", "1c66d5558af2bc514de109d07e78684b37672d99a30d5c67d7722ee957780cef814e04283e89470ec9c48cfd0252cb95c082538a40a8890088a255fc69fbba22");
            result.Add("sl", "ee4bc68bce5fb74a6270673cc7b058f3cfb735f224c0ff8eec891d19d4e703796b534e960d7c5c28c921afe435970e109b4976d45aa6f6e071e6aadedfa628bf");
            result.Add("son", "7ea651b9b6572ed8ad1fc9f0d759cd5b5c369e2524f38999459ad33932df4019f0440a06e02d5cc0513414a30b49d02bff59d522c8c1981d5a9d1a581f73db88");
            result.Add("sq", "bae546857872e8a00b041e5f69c2f9f9c531a5bc9408c09bcea60db9267a1667fb61cdf06cbf88251c7e7092994f45a32cffeb5918d3c5af0a8e76abe8eb80d0");
            result.Add("sr", "7d849b7e4445724c0834855e232bb5df2a13d23c1fd3c6d390690c99e46bb53ac62aded1b1598fc8ea1e1e28107f082a3a1905e42770dd65ab7238c2e61c4fed");
            result.Add("sv-SE", "e2e08ec426bac537ca06def6ff2ff4663305d680949427da273a3329447fd1efe8a49826e774e002753a4190706ba78283c50e3ad8557ec697d7ea08990fef83");
            result.Add("ta", "b7c8b37805881175c4ea62daf5798562ec26601910083cc27f67fb49c69eae3ac2496440fbf5afd5bb3c9425dff8e1718cf7447cef11e16e929d9a42d39adde2");
            result.Add("te", "b1008f4c6af587659eb3da31d8364d80de4fcf87c53d2d9aca21b27413c774907abc6ee33a915660b5ada983ddd9302b7b5fb068b84f2a69ce688719e385de02");
            result.Add("th", "d534446f637216359f7e91451f6ac3548104521ae7476f48870bd19eef93214ebfc6e5f2a81067a1274ec68410d0fd7e36bc3f7830b66fbe120acfb03122aba8");
            result.Add("tr", "841bee8e2909729977b759eb94482e8d9307864eee613d020ff5e11fd5ead5a767ae436daea9f53aa015183bb6a5eaa94a47b384474543bacf6eaf7b75e6bae8");
            result.Add("uk", "8dc664b5a844f8826afed252b5964b826d15846c202afa3b3017ca119671f5a0b7fd2d90fa93fd794017c683b23509ad87bcd6c703e2a18d2bf1149d26f08b63");
            result.Add("ur", "96519c3a28c77030cce977967466d089285a46e8c57fc50319c6e7aa2baca019c22468d8101c85e3796368411f1ab75bbdcbd3a041cf58d87ab2a2e41a37430f");
            result.Add("uz", "4695461e10ebc7714df83f1b8943e04311db6fd732f289015dc8eea8a3fcaa882b848644f3c4889d98178d58c874720507ca39951cac8c4742d8390d20da63d0");
            result.Add("vi", "b7311f511a74eb584510018b1c1e07656c6af70b96566fcf746863e9454fc52be882ab1be6f9fecd69ef249b2254455148d99f66abec158b9b8f47aa84704b03");
            result.Add("xh", "1a82645ca0265c9b39af67abd4d13697f332c0dba369de721ba7f0b2e91c079b431f9f7ecc97cdcd8d272e5822045f041827a6f7eab10015ec6c8da9c988fcfc");
            result.Add("zh-CN", "2b72c4b89f501293c1da2602ddfc3b01cd9c4c53ea1549d662f61e53b972669fd76ad4973f231d33f8a5d83d800bc25e4755e315615506821ae589ead4e7cf3d");
            result.Add("zh-TW", "006ee4c7346b4592523931a6245975254ab684a3d57a0aee7683916cc8bf471643f885b8e91278165383f2ff6e7fda270793926894a5fb523f1ee8737dbe2d9c");

            return result;
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// the application cannot be update while it is running.
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
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;


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
