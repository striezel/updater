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
        private const string currentVersion = "119.0b3";

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
            // https://ftp.mozilla.org/pub/devedition/releases/119.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "fab013987a0193db34ffdc17583a446945ab4a020151b7941d6efe6e34629bd08c5ceb0a34adec37607a8b8526021e2b991d6f8c8edfd3ff5970cd197b64796a" },
                { "af", "33380e0272a1f48ed570073a277f652db6477c9747aa54f483779d40e333a08eec467a441e18ea55538f024784a2c03b4f6e889555a8cc0d46e23e16e03215fa" },
                { "an", "9961de5d2ea548bb773ca036e64bda8d17b56737917ca055812c186e205056cf1cb9b15e85a44a7ab871e3aeeb5e86dec089d4a17ac116a8ed4e5a25726a2d46" },
                { "ar", "9c60692abd4f3fe23615eaceab189c48dbc1e99e90943abe12132b739ac1d3d07ff32df640d59b180f04ff99703af239419503d33dd6c76426474f8654814c19" },
                { "ast", "b022b1e17b8f2ddd803282c45662983eab31627a53fca3ef5f47ff068accf94dc5bb1b2c664d386215f1956c9248d37f772bbd602ba70d3e497080c608f3d2d3" },
                { "az", "045415d821f29965c8da81dbb2f850b89f1e485b830a74bc4b98f45632780fdbfbf95441f6c53bc0fb880013c0fbc081d1a67470382a6e999680c90141ef2e73" },
                { "be", "d7f522a2b425c17c861c290658178b91f09a0cd7888d4f687c55ffc9e4f8aa311e834ccd1227fff7e216f1358f47095b240446f789cfcaba75ac65f8ea887f3b" },
                { "bg", "53b9395a9307e8097684165b90181f98fcb4139440c1453178c9845c345b4c1ab94b9718f10dcb33d5c4de0452b5a840a1e7a7264605e6e8dcb8e317ea3565de" },
                { "bn", "edcb0dd875c2c0fb2698ced66e9d40a04dda7daba60c8e087de7a3b566494ed56dbcc3f6c149dcff3a5b73b7b8196e3d66dfcfbc1f81bf00db0196bac2fc59cf" },
                { "br", "876b2d67ee7470f029daeee02763b02b0158e654782c9ab8526fd2b8042b31f4d6e96d5a2264eb0a8bb7f557543f4adf8203c7eed0277376f728ee5476add27b" },
                { "bs", "e07f72c3ffcf47af9bfd54ff1090511b66f982fb37e665e4089806eecd65bf96e5dafd45e7e4653e9337e6fb78396d965ce6f40e90caad37f455501318d29728" },
                { "ca", "f82b7be6288cc72f407a57559a47b3cb1c174592b40e5c46a56958cf9b3b38176993350d1e69c6015aa5fefdd73e9ee2843d73d960892707f01761fe943acf81" },
                { "cak", "7a939265232d63b29ea393ba0f5e8a25bdc7224bf030e6584c7993faf5763f735e3c12f8447f20e164cce51c5bb8d0abc3dcd5f3953dd5f340b906c4f3a0f209" },
                { "cs", "2cd0cdb53a91d3c4198af595361951daba5ea3c6a13b80d37ed1826861c87457cb5d312c54b867b757ad125e1d929e48bf14907dbc99f889d289884b504670b0" },
                { "cy", "23efa249ce1304df7e991c8d87c47758ab472fb7086bb1ec4b93713f1cef9bd42e88b081d711a69bc6cf25df0d6533a635e0db2fc87d726873f77f33336aa94c" },
                { "da", "597490045f5205fe408cdfb31a89454a8698fce86c64bbfb2362782ac5c89f6ff16d0499a0f6c7fc9322a0664f463056f4178495f2f4ccf0486486db5dd68dec" },
                { "de", "1f0daa5b207c27b5cf855ddc8e02e66c73b2b8bf42516c80f32cf1e8043777ae9856a39ba34a5b5324b93e2b05ec0d87c86c630df6e60f0c31285add377094ab" },
                { "dsb", "4d840c1cb30b0b1f5e89565c7893b558aee5c1b2cb8004c6dfac8f640b4110dd73165f34adfeb5cad3c49d097186934e603a07d261f1f79df9fd245ccea9fa89" },
                { "el", "2f0e48677743e41f15e8ca0942b80b8afc0d639f9dc595783705719db71e9562678b3575d9ac8645922e4a25dcc6febce100d0e154b456aee7f9e237ad27555c" },
                { "en-CA", "e688469765db4da21b8508cab4ae37f718aa3ec16685f51801ed7071d86b318961b61995ae5467a1835348bb89bf42148a588a35c2bacd1a77dbc530fb3e389f" },
                { "en-GB", "a3a4edcefc246eb6cfb18e22423c23157de976855e75569b3805ea5a3298550a2462a9666cc56b9f202dbb31827a4b16366cafd2a0c1561764dbac8916075115" },
                { "en-US", "9f45402538fa9eb9f917661ee11bb8a8064e68ac86b9122f60175ce07b71cc8478083d0fa8903a471e9f9d268b1227f0dd63afcf301fa8045e9c2fbedc993629" },
                { "eo", "6bffb76b6c01e558e0ad4e57fc1aade08b919a7611ff010d94853a0b07e9338a9884425e4b47c2147099e509ea5126e0cab98c3f44026be63fee6a32e6419ed7" },
                { "es-AR", "6caa7700c147387f549daad5aa2db5bb5377e9f8db3249ca10bc57d797471c9b718e3764de2bfa0f4f8ebb32df96c79b85b9190269a1993e871cd835b68663aa" },
                { "es-CL", "cc3c4ad929b47e4795cebbb9abb9aed180e1f9b8fe7bf8fca99ec46c1b2b320133fdd03bef259b558bc4cbfbcc9ece20fc0d25862f76f9dd21f15ae0dccefb72" },
                { "es-ES", "a5da318133a3cb302d31d012cc1cd9c3b03ebda407936d49aabc949c94bb8103b0371df25a460ff0cfef3a83f0ef94e6431706f0dc4d3ab57a42744fd6a87869" },
                { "es-MX", "212c1523d77e9bc9eab5df80aa6218d6710a72ff9b6b5f00ddc263c8f5238fffe6781b98f9f48545a2dc48d9c4cdcb9ba4f941458bcf4276c12a016e5fbbaabb" },
                { "et", "438f22c4ce5f0f09f465f91d45393fbf5eb1a056d1051104f1683a125107dbaf6abce4f6ab47ba2aa441cc778aa86dfa8da7ae53d7a04e49cfe0b7b3d6ae5982" },
                { "eu", "229699eeb889ee6271aa9bf282fbd0dbebfa838be444a8faa8ef5c1539aa686d2b04ef0b37aa581eac117e1381bcf9dd603c2cb6206b0ff10f73e217dce29e3e" },
                { "fa", "fb47bbc6d7997f7e8539b1d040749e1fd4edb0b4a3823a0906b110d4528092ffe403351fbc66c2dcc1dd1eab26fd712081a11bdbe205f071ca4a0e526bd6c662" },
                { "ff", "50e6764f89a962e9aebec0a23645b5e17afbe2fa33735ac06d66374eae5cb690d2a6219cb982a82710258da60e4de104d8bf531a48318d0ab770f763b258ea1c" },
                { "fi", "c88d1927669f32dc54ca483ecab4ecd51e17c6e6deb93f113e8bddb013d9101ad073cdd3d6a1b9c7e964ed9c88df6d38656be8e248dba4e7949204b458f179f1" },
                { "fr", "7849f95940c12e1e9379e92be961df2a256a90071c3ba1eafa229352e8c4f28d14365a286343ed7486831c99c69ce151f0012990680a2ed25f184f79ffa1dd76" },
                { "fur", "aad269bbf6dc445d7291748740021eb7a1743f87af4e73d1cc7abd743ae19dd88914176dadd813856b2593be9da35a0eab92d51e97a617dec513785eb2758d11" },
                { "fy-NL", "ec4f200b56542d997692c8735acffbb37deba9c8c19a2de57d4fb4a8b13a38f8140c23fcf98512a029372210fc7b1b9bb0867df49af3b5e55eb51fd2122a3115" },
                { "ga-IE", "6b951c9be769089e6ecdb98921e493cf9701568cd948e425de3f4436ad4e2072736cb98621d7883c44030d889ce22e8a23028075523c95e28264df0f11b02e7e" },
                { "gd", "0d02de26f517e7af25b75d0a2bd332899bcff64eb30e163315bfc965777a0e2402c75ebb257c62bc354c0795cf74cdb2882512e86b1dc25985d2ed53d401d85f" },
                { "gl", "60841e759e5ba61fb182d266c0bb55482203de0b85bf8970c65558ec8ad3ac98d14d69a4b373b7188db588d8b0cb13aac36f9367fa8783224a35b40198ce2ee4" },
                { "gn", "02adb9fe3c719c8b91734fc34ae72e623b1511f0db196b9c71627e5ac171a56b6deb99835dd9e9585cc48b3d84c731f00a148cf5a58c61dbf5e62233ca892bf9" },
                { "gu-IN", "db234b1fd956718c660d6026ee32dfc730d458408d88dad5868c07415ff1dabf393415808a8fb1f3aae4a06447c9206f3b59cc6d67d87c9c288d3227098c0878" },
                { "he", "dbed8b31df8d714e8b54623bdff31809837c350db9a34a05229d2a5f3121b20eba04da34fa11d5a12209b6fde4c2563396e1a278afe554b73a75455e9d42a147" },
                { "hi-IN", "51cafde67f70f859ff9ba69f1d8cc8e58ea6549f5d672095c9efb4855d9ac231d291d324fed921421d7135f02f249d1a926c19313afdf409d8a8159b86ecf0c6" },
                { "hr", "1491b54ec333bca30dac8150a397ca09938dfa1940ae5dad77bf76ed670257ed4e607d08354e264e625fd529c452999fab3845a5509094df821ce09a9d43fe08" },
                { "hsb", "08fcb8f0b9c151faad4cdd747b6e2c659e32155f08198904656d1b4684a602074ffc57a2d57573b9773b575c118cbb108ebe328acefa060a260c1640068e13d7" },
                { "hu", "cef870014735bb922374967a58056a20f5adbe09aee6a16edf9342e75ba44af92027f4b49fb6a7ef0cd1ade3e76d4a70c30d32d5e55c5c4b83f73437501bd33f" },
                { "hy-AM", "57d6251875c800074662540dbdc5bb633ec79671302504cfdd99dc13f66977bda7da4b8932d1703b9433afb3b9d062da57021d2b5162ad604652e0a26925465e" },
                { "ia", "28909d62189c28cd76737f745c6847e4dec4af7054534361aae6c09caa94c9362df9b380344ddf03c0a7736c6b58fca4853f22d2c77b7d1a63ad452b134dc165" },
                { "id", "aa34e9fe86279dd4bc2451c7967ead4220e93009926354a940f2915707a2cd29be8187734717fc65ff1e508d688f18c982594710aefcd0c4dffbb26c3e4861bd" },
                { "is", "48786e0dfc0bd252e1a4e3d26d64b1c05b760a84b37420cbb7b7aa0645e77f3ac8d6c20c49993de243491c28e6dceccbce18c528ab699827ea9508268a0ca5c3" },
                { "it", "750032df248f47eee60838289a75752ed6d6d9e5be3e65d6f7d51ff158d93c9c6a7bf20ca0867ebc121506e890fa58611bc4dd4cdc982012d95c7010a172734f" },
                { "ja", "4dc9088c0c2ca5ab26c63e83d90866158b49ac71286d23fbc697204d779aabc705b97ad852f6b599174cdd3874081c4c77cc67a6aa77473bd16db0d50f2fd963" },
                { "ka", "d7ba7f764ade918b23b5ba6f4f5dc07693e26ee42e18e2f0affe707490b00413824213da0d0c3c90eeecc6e61bdb7c36cfa07170962b6ba14f198e577c00e7cd" },
                { "kab", "2805ff84e9bdc97d7beb8b855bb4d79c27bfacb1eb0b4a0a4d26602835f151467c9a1263236babbcf2ce49256458488123387ccacab09789199e2392d0acb2a2" },
                { "kk", "79a594c3de2258212d7ebf940e114e7b899f71616cc91c88d9c5e0620e29e13f56585b249ea84bde8212f78211e5bb1a6014bf3f5febb0e7f480326d71957ac3" },
                { "km", "3e3b3cb46c4b8004fdd0e56c478079445379aaa5b32ea9d2a9ce08ceace367271169d5a0b19a61bd88cd505f4cfaae32b6bb8e98278c33dcc33de1dfc40fc137" },
                { "kn", "272406beec8f6ba5ddace58772127c24a6c5189dbffab4ce166b7cb7505361382138dfba893a83a3f249a4bc09ac5b604d4c6d6907c471bca3544e347ac3389e" },
                { "ko", "a4680a5c0eb82194cf221a7a1e34f44bfbd2eebb03fb41c341061f4b9ac25bb41f44d273dcebc72e527c243a33efc0ea49b12ee88d84e8d3a4372876b899b3a6" },
                { "lij", "73529c97f5ada5693831be441f3d7adb559b264c70c49aababaa098f7588b148a2d7171770b33f4ef762b9e843976e0c9e7291b8b87a49270c351a555e1cb2b4" },
                { "lt", "34a5b3a498d4af678e783473e3f4e64403a4983d2dc6b270b4f8ff2ae47a34965f4038f88106938de2f47f6117dd283809e61991741f9cbe687fe81b3210179b" },
                { "lv", "4655871983b15c45e53cc52d55c1cfce085dcac4ad0c02a810c19facc21e6a50edebd2f6fbf57658425ec04947a74612bb0fc0b7d5edd518f6942535f6709ddd" },
                { "mk", "b61d7a40ecbc57865919b389157b6761b8789d8176cb5c210593e30b7fd928be2435bab033b06b30909132c3e5052dd5563f57742b8752fdfd7cf015a75bf1cf" },
                { "mr", "e902cb83d9b4a106ea49eb76e880032a1b42bf00c3ed473a33900188ed394f3233d09ce5b039ca265423f79cd77ef8ca22cc62b5cb145631b878e46f399f8a10" },
                { "ms", "38dfd5d373d02c26ce55baff98404b2b1a971ccdf75090c7a8522560da2f6dc97c5d940d479fdde0ae99d27a4ec110eb160e72aaabb8571797422ac3ef0f4a98" },
                { "my", "aaae430eb57042f905aea12965b685e07b082c02909a6e6896265b53ef815e679ee27cbeb1d01b1906243ecb7ffda813d2f2bc7d925fb4ef667c9118183edad0" },
                { "nb-NO", "c6f599b581742b65373e9ee31964585b7a17e98b60c6ca1f50b860dcb50a2f82ba5424edd13284300bc5ea32e2a1a84173e2be35d96f4d87226d0cd30382dc60" },
                { "ne-NP", "b6f880b106bd9931451b10fb977d516677953ce6c7d0a111a74abb0d7b51462e084521a4c03aaa052254901a9e34a5582866484f133b63839be4cbf9da31f909" },
                { "nl", "28b3329aa1d07914bd78a4e3247e50b94613812e9697e0e56c4cc7f7bc71ff57293ce802e977d591ccba15ef34c5e4f755b7eff44748d85ae97f8f8b40c016bc" },
                { "nn-NO", "59e29d48f7da7e540e0581682e735219276bea02ca87cbd854aaff9427ad8784ea501062b2b6ef3e5619f744686f60cda7b64a96fe4deb49e67e4f47b12b2c95" },
                { "oc", "d0ee3ac40795ffc1fb2954df46d8c2136272bb924a268167221258f0d47623aeed60020ce5fd574b68124d952770a20af6b243f24437a0076f97d02093f2a5fd" },
                { "pa-IN", "98780dd4033085d4875e4ad741708f11f88011c25b83c6807604f4448f68e3493dc83d6a9765a6d563636cf6f008e6d7bf5577a4cba33a12a1c0f40b11a4aea2" },
                { "pl", "eb5ee88e567c5ef3cebca51d7223542a658e81fa811e898ccf3a9cd28d7f43c4e10dda77d1fa93bfa52588f8c722319d01b74ad8f3f0981f7347234b9fcf21bd" },
                { "pt-BR", "f33ed6e2b7a49ec2d5a8cfc9d8de2b0a1620b5de7484c9fdbb95fe44437354d655a74b72d6bf5572b1d117b865e7bc4898a40656f9208707e67069b46140b151" },
                { "pt-PT", "603bbc09a85f814c7317f0c313b995b8ccc0d56ed31683e84ce88c40e671ab23933d10a74f4987db6cdea1a514ffa8ab6a9de324d4df593972b4c2482bce1f2b" },
                { "rm", "b535a666b5c9c00be3925e19258bacf1190a869da932a94078b3ed9103406fdd49c9b607ee15a420dfc93f55f5521c5fb0929dc82c62fbf83d9eb25b9387eee9" },
                { "ro", "3cf3006f14418bec4b54abdc0a380a0c7fa63ae987d1cc5b4874cb72b09a104eff639de5b8ace5cc42883a6d1b255931c5f7ef753abcd1320f7520425cd25cf8" },
                { "ru", "325221a46ff5851a43e81bafc1f41f2638404afcd3014f70b71af66f11902a9cc3e1216101458587e227c6603bc16c5a1c6740901f51275e05655033453d4701" },
                { "sat", "a2c3939075d57300f604f858b6733dc98650ad9c5262384b028f0478f9faaf0fa409ff0f03b212f517e9412aa8b155bed685e7b8a232d12970cb41bd23c4b9f4" },
                { "sc", "777ff52f54496893b311a194997031ff2bfbb99aaa5470672f528d269f7e5c9df45f56d4987dd6be002b3152bf2bfd220e13b22c771115afb04930f9e08d84a7" },
                { "sco", "c3fdbb3412af5e548da8edd5cf86a31b075c8d190882b2e04119cc86fc17681ba9bbde1fc72d96d11fe6ab617094856e9e18bc786781ca5a3fa175456e431093" },
                { "si", "5d15d140534f77e3b86fd05d36afab3aebb8e0c14f5731a3c9c72339b5202dd33b1c7cede7b645a78e3fa638e638a81b864c91002fdd6d01d7c5410de5c89274" },
                { "sk", "6b463fe53bad9962672d047125b42bed7a672d4ae74171e36bb5bb9b4e3d9997c6bb410aad9d7cac320e054cafd9047c1e9ab49374071fe4cfcc9eb217940180" },
                { "sl", "4a4f2a7b7b55ecfd771e05440d972bf175963797566f1b2f95283bcfdcae378c6440e7ba69bed997034202473da6e32917473f51d4aade6fbecec6e97ea9aefd" },
                { "son", "5ed2baa0a91a60030c2cf9478a166af753d8589b403456b4ac8ca916b1f6ab60495c5fdb2dc007d3a323158cbe0dd3a0a077236fdf9bc9e5f15b6c52e2218944" },
                { "sq", "ede7b4e8591c9f674e79379243bb2116688f492b34d637a8245b9516d743a4f05a938b273265772e17ca9417274e35668b59265b991832324666387afa55062e" },
                { "sr", "65cae68b9e831835bee0a3c644e2bebabfe072788d938e74fbe0f75525225f66dccb2d3e65071e355c1ef709301a541066c8409d599c18b4c04461147817c379" },
                { "sv-SE", "718f5b9d9981aa051a5df5ee49864a00e4c718430357e4ab75563b27aca27c98481eb7ab5688b0f3b9bfc45d4fee481a17f9d90a9c2859358b7fa3c58d81f7a8" },
                { "szl", "e34c10eda7314f3a62f26e50765e4564616a849646f05474fb090adcfdd6652f9e21cad0daa6a08ef7f23aa06d7978d21c33fca634f2f127c7ac819678c2844a" },
                { "ta", "6ddab6207aa00e825a791bb8a86b5f142c14c01174a233bf45424fd7cd0f3af496d0301dd38e910e2440a1d68f6d4d0ba1e65b156b95377e8ac3fee773b118d7" },
                { "te", "d4dff7013e0ffd04d7b06d06b491b257711d0737e514dddf0862bd82baf394bfda28662df5cbfab7102d9997822b70eaec7c7a7c93481c8d0e34cdccfb91e65a" },
                { "tg", "c3a6f42683462be05c691d1af2914da05842096f7c3816e0e422b4ec5092f17c6a74b1a66ba0a27c65b27bd87cdc07a4bc6ae898dec3f1b5e9d9c31a504d9149" },
                { "th", "e00df5cea1b1da37ae7fcf7d53b20bb3acf2e9cadca4f2fe22d6c87f8b4459061c00dff50c86e6a17469026525d39f9e61e8a1c7862e2d985b1951295077a5fa" },
                { "tl", "fdb2a69384e8c7af723e39043e43cfe865fd0a4df0d8ee40f984e9e579af7daa1491d9bc77976c3e45a27a39da5a7c372e203f0672bc25ca5965c69c81866aaa" },
                { "tr", "71d8493fa7031103730287a5a4c248e756da9eae140624d65590e92a48abeec9bb699acc4b8c0493e73823123a8ccc908fd1427a86388e474882469db28c3e11" },
                { "trs", "bcf7223d96d3f75ec0853294f284548a91da74f2344f7b5cbff4f020bffc5dc3d6089a2d455834791e06dfe17e5d5af59e34313ba07c52454df59e074ba253c3" },
                { "uk", "26dbbc302f7b93873dd64b7dd4f549f96a19d238882514669e7fe1f7ab7aac2de37a082752a623dd87c31b24817d72ee50f986ab9478933239bb5a4a72cb08a1" },
                { "ur", "7fd20c8217df20ed6470b08648410ddbbe82a7d4dff2bcc7cb27cbd3fa1a11ba9c4849620a89db261698eda27dad6796662d96928a277cb4159a158eefe5b934" },
                { "uz", "de1d59ea27981c3a92fb0e589c5a1a88bfc594e5f0b25d42f46e02406b36fb74572fa018695094c1231354c9694b6e1720503d4e92116fc8d03b1d08aa8e02ed" },
                { "vi", "eee72c72c7ab5140df39434f4e5dddb3c9531737b80a25e4f76e2826f6ef53cd3f94dd670da182f07d2d2733ad54acbca4594f78d2d8b1b75bd89e3a71a88c06" },
                { "xh", "3bfcf695949586be7e23fa2da917a982f64bc939de60db79f5faeb13b16840dae9426ff7d683f2ee85d8234d8b0d7c8996d50877a076ffd21b82e841da0ad59a" },
                { "zh-CN", "4247f0edd1914454c849d25321492c3ff507abd7955ab0b62d347838d95b1f111da0130c92dcee988ccd65fba50613f6b5ccf079b279a426f7ef6c1fabeb0d34" },
                { "zh-TW", "8082c2038cc09087241c95d0dc5ae1e1b9c08692954be111cbb37494eafc7e54af664b219b1053c179a7fa4a633cc6719dd86eed4ab09a29673d9576671fdf4a" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/119.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "8443769bd778467ad99fca05671c26ab4ae4be4cb522816e23ea4f4133ab51d99ad81719cfa43c11bab742b5b904abd807be0d62f8c0a51072b2ce7a2aa2a0a6" },
                { "af", "602ddfd91d6078506f4fca3d55cd7e979c7f847b2be6e9b82c2ac7d7a430681444c30b881104dc8334448ff5173fb3915bf67e7109c0d00ad9b08aee7b62f3dc" },
                { "an", "8ab92808aa790871896e1e1f35c104a7d2dd11da5e4741ee233d5083346ae330822f8a0d3c7f0eddd36e4181aa94bc6b49486b643fdc919be319f6f9d4729a6c" },
                { "ar", "b9a936d8e24b44246d144d6fadd417bf1f36ed4af1eeff97cbd62480647a649e379fd67bcf72836b8ca3934552bb00876efa9d90111106275a6fa1c97919f50b" },
                { "ast", "39d7fc5a9b65d66a50bbf70b7985304c373e923e3677a9304c8ea0b692259d12892572913cc0a830a1e8aeb34dbbb80a1e064821cc9ab0cdcab9e6678e620337" },
                { "az", "bfb9740e9bdb73dc9de29be45dd2f7b511c197597920545d7c83a18841d48c9871d675358502b52bd33389894cb385024efb3df79936a632687ef089cc23da27" },
                { "be", "0cd5ac30ab75c51c3499030e175ea0c09a35b73f5e0eeb033386ad103a757ddbabf076402c9f1abf7bc01daae3f851ffc9ba414fe3150714c7812b584f343d2b" },
                { "bg", "497ec3aa2fa3ca3daba96812f10f4ac6f468e528e257069e9e6a224978909cd382e2dbcc17d125f8bfc3ac0dcf0ab979ff93867c6ad4690ac756dddddc43c40f" },
                { "bn", "b5182e747efd6f473c2733c0a66400f3829bb5629377dd9c84fd519cb2e3159a3b4d3c613ed89e1ba7c3e6502730c2967d466673eb6419a297fcdac3d2016d7d" },
                { "br", "3e6a27696a2e788752fbfd0321b53822256b5c951647ee8f048e934f2ada47239766eec81c8aac53f314a237fed8a38bbd328e15ac95111bae74d86f3171f1df" },
                { "bs", "1c9c23c250f6cf1987b55145368db97c523535baf60f7d866f185284e1dea1f5ab443407f661b1dd7e26251eca8510330e76e012c12a7e7e655960c65d0bdf63" },
                { "ca", "354dd6777a908ddd73197e8217581a529736b89cc22fa5dcd653661d9f169864b5ccecfc22328e11e404d905fb562b1ca06339ea1a0025f42d3b6200030bbe15" },
                { "cak", "198197435f7aad62873beda86632ad1f0ae163d926b63e3add28e4f2210926cfa5e5bedb8d083918fd4ee772729b8cc55f6e947ef8b821c61b76d6d493b9840a" },
                { "cs", "9d508881920c89547c8b39e6207bd21e4674525416de8a077fe65a55a435a7259fc1025faf73a867e03cea74e0e19b5cfa67efd421d011e49a258ca90521c3b0" },
                { "cy", "3324b4a733739a50230d59d7b1f490131ee853a1ab60106cb80310893dfeadd0f075d8b20431e629da092cdafcd6b490307a5a34c890053f4060aefac7163400" },
                { "da", "4709932b2cdda672acb617c6bce4a9547a8baa8c530c7187eec18101a841d5c189db9bd2a4684bb3b35af00a2060b827802aedc911f276fb292fc456622a903f" },
                { "de", "7a00ca384398597bb14a95330658468da911b8052a457e78d4fc2e6a99889e5f226cdc6757a5820b1c90e9ec09ad85ffabaccf91504335ecf1517ff9829b45dc" },
                { "dsb", "55339560431ba00a767bcab7ce69065da69e75a08cc48e1aaf7ed0c3bc3399ad6f3ce4987955b78208074c7412d71b959c2af484be0b569838083f3c8f0e58c4" },
                { "el", "3d3edda9aadd80f1e0fc953799a9218a268032dba64f6568e31e6cb0337619c3b7bbd12256bb4adf32d7fe874cdd25fd5b31f87ca0ea325129c06d72387dee1b" },
                { "en-CA", "54d16c02505fd4fd64b87a06ff0b59c6fa98e66a7741bd0814b933dc751199016845295d70e7be79ec6471e442168d1cf7a4a1af9d54bd02184852b003dbbbc2" },
                { "en-GB", "82451533564b7f706bafc566ac94a558126e713b8a65daa3b92244f92eb0e24923fdf809b943ade3c0459e71202f7b25bf1c00898b930662fac595614a7feb4d" },
                { "en-US", "8f69467a5ea9b320ffc4b68e7e9929067da31ce5fcefaae92884de9d76edb933f7e26bb4ef1ff13fcad05f8765619176006aa7deaa22c7fd4d686186d337684b" },
                { "eo", "4797c0488082624733a225e8221a38d0a569d1d8c3cdea490ea839340d31d583c864435e390b8f21af029dbba5ad090dbef33805f63a9ae1b28508203a3d26c4" },
                { "es-AR", "33b6ae15f8bb120b16b3fc91f916dffb47d1c5d436ba21b29ea6d41491c39a1c1fcd60f4f7cb47a0ccebe1aadd9c4976b3c26102fadb3ffec308883128a6bde9" },
                { "es-CL", "97af6e8c2db8deee378ce1a285ab943662127d6b72303bde8bf703d06e2e2ee9e3e0696615bf0e34bbd31701d01eb8835406e28f4ea761d7fdf45d28d3451add" },
                { "es-ES", "787a4be78ea202d7efc75eebc26c3f3b24ece4f2dd0010907ee8a09b382624440a964bbaeca2b3d03dcb68a4b6716be3e939d37994786e19d703d9376b398bac" },
                { "es-MX", "56b6ebe6724f504ac34df224aac2fb56f87b7c4fe67f12432fe9702790ce43f1f513a384c87c52bc8c998a3fdacaab10b910bd1d6394b4859a8ed7e32690530e" },
                { "et", "1e402949b63514846b17eb3109b0147265562aff92006df89c8ce5306936ada2fa8832babe063843a748aaa698caa7e7b21d908e1f30d207eb29635ae599b1a7" },
                { "eu", "94f6c4cd36caa545500dfcc7a46ace2113752f34f19ec526716b89b171a9126abbef5621736f4576479e0e229b5963724567d2cee6e4a3c413c0a0247dcd4736" },
                { "fa", "39e2d329c26cd6adac6e018fa43e1cf0f0d0b764b29ad82274e3365890a0748ad08d5581a2a406f1c708b5754c8a1a04a5269df30bc03dd7d4bff5fa64d53b90" },
                { "ff", "d99f7238a853e432d482025a6fa299a9ce740cdaf96efe355c352f89bec10f96034c652f8369be6f9ecc2692b6a66351199df75c86929becd2965517f2c6a995" },
                { "fi", "65de2f2252fe583ed90213c7386e13488c65937a784050b1b5adc1f6ea4964e1a278443ced2f49095b2f0be2b2cc725b438baa76390fa78f204bf252628cc464" },
                { "fr", "994d9ad986590e1db14d8523319d50f0e51d20702e78bb7ae29b0e0a94b1cca34d2fd7b7aa9f2a048980dcacefcc48c00668d18fc8b6b786b2bb64049d3cf968" },
                { "fur", "fa99fb999a93c377db619c56549209518e9ffc997eafe1455c7d18af5369f4462ff25635d32e4f87e880930e4932b73efb587d56a9897ea42719f2540090e2a0" },
                { "fy-NL", "88a76af498dc747051b25c6c070b722be48abd2632491e3ab3919e1f5db47bf4e6d0e64e868cf029075585915fdffc465eeac89e0c2ed9f57420972a868e2298" },
                { "ga-IE", "809a098e2da1fc97f8a757df401c1dec80a6567afe108123fa788a4d67a40daa5a05b85f997b0908cd601b21c3f47f5259eba38f529346f5c59f9c8b90da4bb8" },
                { "gd", "2b3aaf9ffc7cddbeabf376bd4e61dc432742d3ff9c243c930432861d44556be62b1a25664093532dc8480e39d388686ab9a91a65e563f25639e137ff57071d5e" },
                { "gl", "b649a1822b29705805990d6561a85f6e523860907bed2a9c0db78e501c91b941aa288cf56465dcb4bee66830e8de103ef356ae2b3f51594f0de423138c6755e1" },
                { "gn", "059670c310d154ca1d46db4cbcb0de8b2bab7ef76e5e40f71cb03118b27c5d8e15e69ea1ca4da87c68b199be1d251420a5653b85c9ea8adb01f7c36aa0f95bc1" },
                { "gu-IN", "570ab9c5fcf38615cd4a9b5decea9a943a59984ac7dde382791897b468aed9f91f75dbd0c2d3b78be1fb8a573e137795e7ed9d23bf77946afd194fd8491988ba" },
                { "he", "1944863d002ab30b8eaff240aa2ca9be001a6afaf09a91c61bc9a3fd2903bceb367d939e9693e1ddd8cf881cfd97c7236f1131aa08e98adfdec6b8a6306fad01" },
                { "hi-IN", "8dbcb1e306df3592fc95764412ed3e3baaff3356a752228dd1c3a667de576b5f298ddf83dde66aceee9f9d5ef7c5e5a23cadf6ad95bf3525dc545d0ed2c3821e" },
                { "hr", "c1954428ba7c6e0f2f734dd66e09b91632a72db3b85e3aa9ff1b6beb7f40dbe08b19c6999ed68fe87d25fca56aeb902e5e26f69e8ff49b20db90facf034436e8" },
                { "hsb", "099a94123fada013271abaa6d2e7c407f6fb0837cb5afa3cffdf9fc4101e70feedc2302441262dffc3eb197bec8f6c425fd86eb1a62cffaf9f1d00812e22b544" },
                { "hu", "912728bee24c5ed1d978c538eecb74fe785faae4cc40c6d3d16e8da228b6d0320e6e205a12fddd680f5df0b2043c90dacc1904ca1c8f3c1dc9fa9c854527bb16" },
                { "hy-AM", "72fdaac881e295a48c8a2ca59902691fd59d403f327d26832d52be8d8650c67b1e20478b9eeb234d19ad276152ca020b8714d41a9d0f0b928cc191a7c08314fe" },
                { "ia", "c6320322b425fb49b765be3a20ca5965b33035bf3cc87780fa11d30dea2591837f9f29c93b1d494b7c3021ff2c49a0046c7be1bd8f0e47d69cfd80a3130cf463" },
                { "id", "1248ba68be51bf4445467e5d0d29dfe1d8ee4afa677bc7a2a504b39382398b4e38887d1f2eae5b788dbb42ce022d8db00feed9e2fba0cab43e862fe47956a16e" },
                { "is", "6f790764812252a83ce7e2b4f66b84c59feecab41a509aaaabbf9227ce7d29b5ae7fd960130817fff0e7991821e0a1fef855cead09934f90b6a7350255f5b1ee" },
                { "it", "7645f7f9050a0c00393d7bca9efb8a8a298f31bdd79fb5687d3a7adfc363d720565fa095bbb40e3917adbee835abb7b39b4130d912e43e24a4283a2806308345" },
                { "ja", "a1f377f09848a448c6a4990c40765576f2381ed58c98de49abb23394269ad437f405670e9a4cf78557748b20c92aea64f2156c950047b8af7d4f60f5a8d4d754" },
                { "ka", "2aae85071f26661e662224ab2acab9c88c2444b46bb0c768c9dc3230e72ec445e9852759c3982af46bc0b2d003bec77df9316fe9564e3a2fd9f88fba84d6ceaf" },
                { "kab", "78eed30beefeeeddaf642a860a25c54b613c90ab4725657ae9f7f219800b0b6e1c1ad64a812acf0170e87b04bd875ea61169672c02fc6198f62e87f290a4ab4a" },
                { "kk", "760074ea85238dc831e24f3c8da692aa7c3e95a7e1cf58fda844f06d2af5716c12ffcefa125e864b366fc171fbb7083801fe03947d43715e3736d154db889816" },
                { "km", "11d165968ad3cc7636131d4739161ec5c72f9dda7c1b5a360726fb582419b6b05adb098bdd70e363501aa86c66dd85e6b41c84fc52633c69da6c7cc7c592b99f" },
                { "kn", "d0c594fbd14603e701f666ec809032bf18757061e74375b4938f974b887c89aeabc8ea2ad06c066d8625c922d4c30b24bae6d5389ff10a499764932ec9937cbd" },
                { "ko", "836db28b1a513574d1f5f0998c02b948bc807e4e7b5063cc66c3bc1fb17993d31f1fd6675226cab7ba6646fdf6968a9d7e2bc77f6fe3c7edd74d016c6ec0ae58" },
                { "lij", "4acfe020eed567b49b76c539c2f63e130a51e5f394e84509508ace48f445b145ecfd5947e5ab0f1078dc5a878c4f59df16cf0f378f458d85daa0ba44c9f2d9b2" },
                { "lt", "e25672863e9ffa67549b913594c3baaf344170c63f132b9f2681ec759cfc31696a1ea03cb75bc5969df28dbf12520b719ced72d86d26657bf18063d88dbacdf1" },
                { "lv", "26326611bd5735a63b15f573e9e32e1a20b0a001eb0cc6b0b7505df1f20a1ca2c1f233241c958435ef6a0d6d7e66f96a620a1cb33c8c929bdae8ea6d7c532d69" },
                { "mk", "ecdff4ace16cddfe910c100af34853cc2366ac7bad0fb4239cfc026f242e55a3f122fdd3c410da8b899e0b9ad07c0204f26bcf2a10a86bde777584047eeb921e" },
                { "mr", "c992327b246bad3faefa02b8630467d9c848aacc74d1c57a81dfad092893f923a88b22ecbe7e8cbed903efabab0a1f93fa7af03fee071d477e692d84bac777b6" },
                { "ms", "2fa2912a56b67004382a8a3863f08a52c0907e5ab0a669f08e3e2788882f94a854be22cec22fd6d3296fd2828e538edbcca86ad750430946b4df9fdf484a25f8" },
                { "my", "e60fd5ac08c03af0184dc1fbc2c22b406c0170a486e23588a17508cc61ec35b625b5853421f145bbf6005d98e479b098e52c4970267635e9d2e37d99b2887f43" },
                { "nb-NO", "b0e04da4b51849ae3d4578d311347215ecbf823a4ebfd326af20b09bb93f3da031264fba803df317409034a4256de9b34afaba152616c45ccef38e4aa7998b4c" },
                { "ne-NP", "dc1fafe86b3683fba42c1b250c7a650e915dea34ede5541a800566718ee8f252b382313fc7626c79009e564cf5b99365bd840bdd8977e75e99143e12d3ca66d8" },
                { "nl", "d00cddddac2ca18465cf6bafb1f9a2f9670354ac9c8315a868c0fa76fa5752327269b838a71801b1eca7c213cb18e519b2ccffd6d76052749b35ed2cdfa51aa6" },
                { "nn-NO", "4fe7acb089b0d0560375497cbea0662a7595365d32340f26a9d8cb2b9ab66f0e02c1b3a3ec27f79dd6041b14dccd8b429c5272e411e3cc8550d7525658bf57e8" },
                { "oc", "6a9aa9cc6866f90899cfa51576789b8897cf375d143aff412ff6fe398670825e4f0c449069eb76308fff50ef857b09a3ea2602379a018e334d07c7ff0546668c" },
                { "pa-IN", "c67908061aa845090b5c15a9c32b1c5fa730a59222bba803f7807c58c4829526f27ea29a08296dd4d1d3c1dd1e9ee227a43454921b614ac869ee4e77f45b593f" },
                { "pl", "eac4d4b29ede9df846f90ccdc3f425212fb0366f535a4744f6cb349b4ff64e7ed360fc76437c919b785b0b2e480fb9b40b64e7dce2845c22b0ebe2d05a47ac54" },
                { "pt-BR", "87c0b103ec410b1d60d0c6b8c70efa1da292490d2d272a2e4a0bc28ac1f9538fc903252620e18cf0fef041eb714bed8d68aefe5af9d3749e6188e57e5b8309cc" },
                { "pt-PT", "6221e15352afe2b6fc87f7904c55154134a3de6704c7cafe68bc951ea97d703a9dd4e6469fd1216ebcfe488ad5514b80cc572e53ac471c23e2a773a025fba707" },
                { "rm", "f302f6b3e1e75107d2cb72c6c905abb524733ae76e1a1db3d052b50a650214f385f915c2c9eda76e0508531b7fa698fdcc51c3539f0763c497a87d8e2d5939fc" },
                { "ro", "9a3b2e68194d02ac2e4a11efda44ac261638a95d560e2dbce64e216d49efc897fd8b6c02679e3fbca4d6a02d6db5b344ac035f603739a5a2226ae56f82ef8a18" },
                { "ru", "a051dceabaad6ec9e10340dae5abcc15c9a2a69196e2296854371c9dd46682dc1772865b8b3d28f7513bee6f4482c91a402b64e852509e859219029e469b0a41" },
                { "sat", "f0809fe7f3fcba902dfddad10154950d52d058e1c6ff37e9d5360c9e11f9fd43932cb326dafd624704b427d4dbcc25955e79fe4b5df90974ea0b08974b65697b" },
                { "sc", "f6179bfb171d916b94702224d74e3566a9be5a4bbbb5fc484a9000ed5b213be0d6216b0df12f459a7bfd3d7de4d57a7367e89447d2c8fe0f49308d64043c1e87" },
                { "sco", "43d41c4eb5b16f21a2ce9a6ef5acc4c52fb858448bc9230cb81d4321e464af08c38447bf61363ef2b2b77f47f98be9d150cbbf5a83a5dc76d3608c8eeabb8066" },
                { "si", "05b9116ba702bd1ca4b4988673ce08e232bcf85d818c3c4f062a6f1d93ff01218054dcd99cc57cd26df7f00c90d6bd2ed1100743ace73138bf55a1a335ff684b" },
                { "sk", "015d5fda6e3a11b9fe8469e861bd376dc0fe555d5a495fac2badecb0003a7295b0383df6f25bcacf3cc6e280369993250ef1017a977e05ad3c64195e9ed0ed00" },
                { "sl", "53f051ae3b9c0887d564853b6b716b3cd6093632a4ad1988cc7ab3492b111dd42aacbf1a799e06810178f25dc8328faf5014b815128659ac12d2f741373a11fe" },
                { "son", "ad2144fe491982228c6d1c6e4b52741f9b195974f180f1d09f39d13524dcaf8ed5d473b087e538faddbd05495ddd8809367dbad09a382f29bbd9d78789527520" },
                { "sq", "97f52e60fff1b75eba530d3815eae01470e1e125a984b006473613edbf5994be55728164782f4971233e95a6ae5eff1aa72641da1a4587ec07b322c9b9634bda" },
                { "sr", "41c8798389efaa7edb3afb14b8a87b840f2aef3bb44097ac0aefd5c3ad34cbc8fb9427481edf00bf4fe29cc4ddc3d4ff6919cfec2432462692e024851b4ba824" },
                { "sv-SE", "28365284727fd39e902813bafbb4493e5cce3cb0cf6b0f58ad4e58201cb70909dcf8db90db1a30155dcf0b985091dd6c6a0d649044736b13b3154b0ddb67241b" },
                { "szl", "2beabf90f2d91ab7efe53265d9da6aa6852619aa5d6af735e5a06287ebccc914c32a91c94f481faa68923e31f5bfee3b8773636d0f52a1692462775d476a0016" },
                { "ta", "fa57b3627e27029e6faa847f312a43dcb3a267df6a0d82179364b3b70cce41d2475e179c2ac241097230677b8b877faa07c1825af55a5fc4253318e535107dc1" },
                { "te", "94ebbaf7f2e1116b27887f2d228d79a90e0b8f6c922da6d8794f5526c6fb3d0b76e993e6ca54ca94a811ce719caf4bbc9fca2deb4d98b2c27aea73a83568f988" },
                { "tg", "360f0de9e273c6dff9724351a3e47aebfe6831614617c27f8e9c496be6b4c80305ffa3f745cd938bbad5308a6657828b58cf94dfaaad36a9da6e1042322c5833" },
                { "th", "e57e8b1077756d917e58966346a449d558d066e88f983766ee47561da21925008fad0c7a983d7b37fd2856e8b2b5d7156dc0b3452987b5fdbf8998fca576e26b" },
                { "tl", "f88c5d8234e6fb36c4f5f383bb7ad5e5a3a2b5f55c8e4b0d0a6c97713eb1a9f1ccb3adbeb5d1fc8d9746796f3f81794a88911d3e96ccd7cf29ca068c9f6f53ca" },
                { "tr", "f800a3e2f94e04e908951f9fd0800c154410b06b7aa1973ddaba502618a06238d79f1d5a59286ac17a4c9b1754a230e4f1b2734fb7fc411fb397639381d942ce" },
                { "trs", "f86e52a4d4616a81e35a480b413dead6402183143b3a1986e09e85e672bc8db87cc2370fcdbfc26a621de7f317bffd84e229c03ba939c9284739c853fe23577e" },
                { "uk", "ca6e63f6df25e4141f6ab5bc0533e63380884e81e353b0918862ae7a8613606528114ec01dfa72c73d31d5a66ec5098d3c954251ac191acd8c099dce5f25c049" },
                { "ur", "660ba1739642faf1a840da212a7425729db216f221f936a84d6d9fb7033bd0775bf25d49ea548c215eb09b5b66df312e7cc182c6adbb3eb5536d575fad29b3ba" },
                { "uz", "8da4d9fe6b205c02d18cda3edbea3660d9608d3227ee34b171ffff447e47440434739b197f8ae7a0604bded88c4580338e3cba32da74bf66b2957c03c8f03b71" },
                { "vi", "4dd4751bd62fcbe918be70c2c0d28bbd3e781c60f5dab5a85b276f7780641d7bc13798036e0c1f0f7e2f3f1b7af5afab5373202e8971cb9b73047e4feb2dd3b7" },
                { "xh", "0737de9ff67e4a24f8b420ae532c823cd6b5443e5ac233537f464c72dc011a33f3c2c4c056cc5bf6a8d854b67dfa70a5b4ca24b4b1a1465b8f7f59d994ff1120" },
                { "zh-CN", "7e98787fe3ad30d90bd8eba51a5010b997a6693fe81c9f84459f79e3ce7e0dc2da8c7bcfc52471dd511662927d256c6be579bf234625090edf3ef720506a154f" },
                { "zh-TW", "d71392b667fdd397ba7d2954bcb95c86b4343b6f16b8650f3a78dffcc00312848769d847cfe9c76df594db7610a0b286346637eaa670be9ebddd98730ddf4a1f" }
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
