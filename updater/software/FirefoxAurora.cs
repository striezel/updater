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
        private const string currentVersion = "135.0b5";


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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/135.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6cec93bd5de8955b6956ec8022c9e5086a696a28355d2d4d59d9d32abe2866499427b46a48b5a42ceb8b54a5ebb2ac10b21bd8a23cb3e0a306b2cb44f4c496ad" },
                { "af", "ffc75aae7aebc0fd2f60d3909122e34c091204c0cbd90c383f272c141d4d30591c2210e76f54f725c21f9ecaef1b6b8b44a861a9b2f6bb37329f6a02579ad9fa" },
                { "an", "dbf300d5a8cca752a15666e67fa391728a2e0ddbf1d971778e20e54a51fbd4ae9f9181f8aad551b3f5ce402347706f3bfaf724a11802bae27f906c12c2b9067e" },
                { "ar", "4459cfe765c4d4741a08ffbd78b9c7fa440cdcb4cf9cc769329a4d572109fd04334cd9d5daf6726a742cb51c176dad8f05e64e2c9a86d426b1b81daced22aae2" },
                { "ast", "1ff1d2c671d159ae833b3e17b2e7fef4b17c7773c550c8f031498a349aaa6304094a095b30670c1fad9c8a17ca172c1b357dc02ba145a66595e575337bbc0b58" },
                { "az", "8a116042853d6bf4b334cc2fdf8a439f3dd0dc1c85c545b70d9329335251f51135dffb557bf8f64e11afda1e654126c386020528883036ccc258ef0799f9f215" },
                { "be", "5417ae1cbc2962a6807d1c8b75bd677158aed49bf5a5ec739e9b291d6dce1077c388bdbb7c05f7d48556a4286684ef812f489aabfac25345cbd870951bc064bb" },
                { "bg", "0a2ffb808dd6bb207b3b1bbe57f902abebeeb7ad779f2cc59642923b56587d20247abcc80ef12e790a3f45d6a239ea9573e9fe345a72897116d15570a86f492f" },
                { "bn", "d29e2f0aeddeb37729ff4290ac3c5f96073373c101784f183740d79483ea0b241dd75c2dc9d759f8a7e87d606d724e36319cb19d629a831411bd43baa455f7f5" },
                { "br", "752b734fc1a084eac4e983b01174db82b41483b95aca95918ab317f1eff4e2c2d1c45a51b635ee8b5defa48567da6b3630c3379302adb310fd216707bc5a861c" },
                { "bs", "e1a5b45a3273a30b3af3ead618a1dc893da6ac70994797045e41ba6adb8f4e685d8f974f32ec7cfc3e799de8e46402b431ae0037095986846de25501c223c322" },
                { "ca", "88b6512aeef1eb5c0ac8bbbfa23ffa1004d4fcf6e1ca7001695ba6d94cee42ffc97a8efe32837f887a414c6ba7aad087355afab3d246bddcba48b3a103b3e59b" },
                { "cak", "3cb48e66d61d2ec4fef3cc1c7b85ca6ad31c49db6c6514668044e1539270b339a724d43022966b12860730f8174f6ac4617fd5bc61081cf6cd667cc948f7695f" },
                { "cs", "3670c75c024c84f42db4d7ca38c714c89d117723fe3734a238eee44d56e7b4dc805af357cdf7211dad35f94f35a7a8ad2febf9f6bf8633e51ba79ea88b6410cf" },
                { "cy", "13c1a733b3641e7c60e76374c0cd3d03ac614a1dc0ff8906483e6f7b094f231204795928623dcee0484683c9f5356e657b384fb55c5207df5ccef32bd0bbdfd6" },
                { "da", "426a5f7cedc0af0420ac12216c828b325cd0090fa55bf2ea647302eac87244dc2d72c8c38a941626a2b256477c71366f7a72942270312d72e8771b0ae632d1f4" },
                { "de", "0eff22fcd5b18de49a0d1362d9a5df77400169e3ea6abf913b995ccaeb52f860b7f22cab4dd9ee162f59c10f2670e8aec35a1203bdaeafc77b8ed7c29dcd77b9" },
                { "dsb", "09fa4aaa4c5f27ca768a26cac659bdd1545c1d6bd810f017e96b3f32daf09131a5efdb73335479a9a7dbc4f8acaedaa018956b0187fac68fa8c996b355d3020b" },
                { "el", "9e3df3a9bdb88e96606b586953bb816680d39e32181db142a7a81722767561f9a94a519601eef49c49a6b8e00af9922bca53a70a192cd534523c1795723783c2" },
                { "en-CA", "76186ad7a44efbcfc81999dd1518dd273ac8f3fe92947f7854102dd8704c8c78a1c6a918a4dde28b6083c786d6fb65931149640399b25526e86857d895ed29be" },
                { "en-GB", "3057c881b9ea416f447a029487824f92584915a2f8517d40bd1687e00edd2db143922602a14da653c2ac4c2ddf9c7236f71264c8ed5fe70f89ca3fb0ee5df95b" },
                { "en-US", "046c0e04408263560c40324a99855e671173200d0faaff8e798b7d05bb9056c17b32723edfb292a5b13369204c25bd2d337d78fb6b77cab4e47e4e40b9eec7b3" },
                { "eo", "c477bb709b78b2b6dc95c81ed3e8db5c44091594da183a1a3c63717e79e7d90d81aabeba09cba613dc077dc9bea29945c7ca893ade46ee83d2c3a3b03bf9a7cc" },
                { "es-AR", "b7417ea064bee08615818bdd8104ee79d60c84800899ee92e6246d66bd8eec2bbd641d7600b211699646b8b2b7df6360b8d30c90c11c3e39748e809320ed1aea" },
                { "es-CL", "bbbdd5c848952b82ddfa5710ccd17b3433d24eadff030987d053dedc605570e0f2a8f93fb133d8f53fc92fbc3e6f39248421f16fe686d90d4c22b468a5b41c68" },
                { "es-ES", "d1dd75bb64cf3d8c67966b720defb6e6c4d42c3698349e3cea235536400318fc57e23595ae092ac47e31c972975f447adeb546f277bc0ff61eb0f75cbc552a13" },
                { "es-MX", "0b2fcbdcf88af1fdd81d7a8bfce38d8e0bc0b4c4ccf08aa11905c0c0f87a5b4452e3e2bcafd2966fd30e52d069507a2d0116b301a35f64e810e90a288afedffb" },
                { "et", "b459fd300b4994a2653c912d351f6aa8fe6b9a7ecfcccab90012c77f7f13519e0ca122078f14539850df0eb893007b4f9c75896df56b4357aa38f1be0f7f5c8d" },
                { "eu", "db4c61654e951deec93076cbadc60cdc91251d1ddb614c6366bcdba685e5ceefa06f8923a0ae1e00329d99bead4ecdf2099ad591e9a2c0037e5dd068e46fe363" },
                { "fa", "610647e0ff78f7e1b5e79ed5dcedba708d5af519281126e09969b5408b24906302035c9e770952f99559ccfb3f8ecabc239779b97f703b8e50e12e9bb2502297" },
                { "ff", "82611c8109fd2747d0fbb61ba94a66b4f087bd5fe9c970772d2b2a997e90d032d9986746fdfd49cdd4f1c129ba91ebce7dab4a68034075b92edc9d81a1c4210f" },
                { "fi", "70ac272ae427748dcf17598fcc045a03570d816a3ce17a26909717b086dc02b9ae7e5d29bd829ae37f3c86ebe79c62dac2c0b0112ccfa8060f8f570d7f56ed92" },
                { "fr", "7d4fff74ff73498092bf796792abbadb0068680c0f4ad633d90b3fb9da66abf4803c3e517f2c4156f7b22fdba4452151baea51d0e6c141626b983baf1aaf83d0" },
                { "fur", "068c43dce4de57bc60fe999c29cb71022f37e8f817c5b3161814e6864b032c431963b78a371c4f6b318241d29de45fd6e46ed0ef122ab29ca62850562bff7bc0" },
                { "fy-NL", "49733f78c88e6275eb7108a68c9fa81596b95956f8711dcf860798b2ab4b31dd0c94b45901db7934ad1ed32118b36fd07423231e4e4988755f042038c697b2a3" },
                { "ga-IE", "bd9c7f4d1ee6be81be052a001bfcfbb96a215e5a9d1cd0677c46afab3a2b326e92293df76181708d75f826ef033e31743fc764cc961e0f91d72dfac8eac8f156" },
                { "gd", "965bf0359a824a3a1d9c3c84b27f74b3a7deae18b2bb5178a64fac6af49e4b6d57559e160dd754bc142364256264a7bb6c53ab5cec74c02ba654447ad941aab9" },
                { "gl", "8e68f9e015797be3452e09ad3017f589750d5b3dfc361ee11f19111c6cdf8321bc1454364f55f30cc36f2b411ef9633abc75054c2260c97cd3096bcd40bfcd1f" },
                { "gn", "9ff913173dace34ab1a98dbea20535b94c5cca3807b984fc4c23c20e72294c1e955fa73a24f739e8e8bae5f931f31bed481a67999bdbaa053d6ce30b15fb4aa8" },
                { "gu-IN", "63454a9d364da27d98a32b5b94f28dff987750af3bcf42ae2426fbacdf95fd8034c1671e90f1a8630bbea19183e6bbad30cdc6f9cb4bc62ead0b8fea087e8aa8" },
                { "he", "a09b4629dd1bcbbbbc2fffb9fe9de807e18e17fa66aa7a1e6f2a618fe27f76050daa4b194afa1e55985a99eb42601dd5355acf519b028b97fbbd18917c4ed457" },
                { "hi-IN", "131fc172997a0b5fd6940a07fcc38c51418c5dd96e7b457140274cccec9330d5c3cc7e624cd4be128286cbd9e612a5e46244608e29b3601629a936838645788b" },
                { "hr", "9f8c20f0d8d6a484d79b9da20ad3e3a4a11a20a461aaf71627b2060483b51e56b8dd9ba03ace8e9d7271873b5281058730e2f831a193fcd4cec83c0f32056c5a" },
                { "hsb", "312e93558e7ba94c531089a997d3df528ecac202d553104fa03c8bb87aef2b6c912f3da150184a7f2f147077addabe64d8638b00246eb51c63eab5c3441b15db" },
                { "hu", "3031c56feb8b30037454993a17ecee662e58dd93780593bbb9a255360f1ca64b8f2a183b087b38dcb2fd402245ee675207963aedb661a21f45fcde810e621581" },
                { "hy-AM", "bb2fa7519cea0e4b6b666804692cf5ce32362764c956762b7651944d1c871fbeea01ab575579434e527a194d2b71ef9cc43f76e35f3aa524256b378965fa7825" },
                { "ia", "94a79a63375c93f8af60ec5a2438a735c1153d18bc7c3806708e4671ec542f1e57be41d5472605a3e735f62a6bb5a06081626235753e28543716d078777a7dad" },
                { "id", "b8ef6c882cac7354f12c2355d2c7fcab4e59d8f955a9018ba4be61ef0503ea157241862f028aa6ba3bc958e1ddd25499f6f05e089a1427403c2c0563a157e88d" },
                { "is", "5325661fc088161e44c2bdc7d1ac8464a90fa39393c626276fe79e5a5246c714d9b3c0ada2f9339fe54e74bfcd33db1c819493e7f1f2c9c6c9f79f5f71a1aed0" },
                { "it", "2699ebed634d6d9ffdaf366b02721d03a92266e599557a4d3faf95f7281c3df9cd45c6864defcd8d39ee29c33ad82040a2db9a70f3ca4f33cb67e72aa3044efc" },
                { "ja", "1f71354ca9880d2998f7097666b1d55d95625955666109d72db19ec93ca8c136f3444b79b8bc3447aa3cecbab0183e88b85d07c302278882258549e5791fb6a5" },
                { "ka", "78264948a49492b2b6b1272b4572fea2ff2bdba2a32cdcaa4d8971d79d12a4e7b38aa6454dd8bb33b5169afa7699ed03d4425dbe64d8f6e70ac5ab9a97819722" },
                { "kab", "b9740fa4dd7192775b5da53f45c92d6bbd4097cdaecc72f7dde0fbe092a8279c4a665e5f4913ee52379d6675dc43e0ba70413a957c93e5a6fda6d5339ae73add" },
                { "kk", "400c99823b734fe7a19e7eae571ab25b0a379b88bf7ced2d2a2e212935104d85ee0f3c50c636322f4e0c0939b55a24306a706200908cecd3c86ad26aab298764" },
                { "km", "1efc006e1b2533aeda33817372e6a55b6b6df73c5c0787d14ae534faed391f3c7e93af5983650deaf25166a825b6dc48d74c3b46da4baea1581ceecedd9713e9" },
                { "kn", "4f311d10aa9c9d4fa9b7437a64d82eddd38a8e4362ff89522e1984928de21c48ec204d62c3a50dce343a0c9a04ea751e34200887deefc8d79f3a8e4637a61bb2" },
                { "ko", "0c39251a39a30e5f494f4978e83ecff119c9dccf33e9fd7d7ec31958952ed3123fa55b07bbdfcdb7354b332b1cf1df6769a39539a83de3a4ff7ba7c2c01aacc2" },
                { "lij", "055ff471f9c0f7d8a2eb6866e6d4df031ff021bf70cf24f334c638929cad6d1c24f46da1a14f9dabc1eee86d15ddc5aabf39778c0d54163c7f60be6d03fdef32" },
                { "lt", "7a211379207f6d11ff547a9c66fc46cbb3bf997511387df6b28a4ac74d3dd1497a002a99df5d12abfd90c788f733f6245f07f39cd878400ff856e1a75295b636" },
                { "lv", "177c0af5085df9978cea651c4f8b4bf28cba33d2cad07dc72a201d593e2780e96608705acd894bb886c926ee101b22dc0eaf04d8946b0e68de6c5b0259ac289f" },
                { "mk", "f2f0c0ba1978f286739e30db63937b2b61ee9cbce62539b7f4b07b90df76626b17b183d66df3e32ec8f687d62b94dfcc064627d782079c9f2c56ce80310fb155" },
                { "mr", "41d08947558e8ff283cef5f6947ac694dd18e12d215a02f3453e950fd828c68b72ce6763c92c216f3e6b678d53a9a117d8a41a2482180e1d5f8ac0e48ad4fb89" },
                { "ms", "cb5ab2d174888b842ddc4101190c1558206c1f119b5a2a165dda93d2f3a4e9bb5fe792b3ef2b510340b520549212392d9c02de13dd6afe6de41fba056743da5f" },
                { "my", "d4d7e460844936aa0aa3df1ed3ccab78a31ee74a2d94f1d963a38f0f410e4186ec8827abe1e214b01df209fd69ff62494d04a12ee1f3f3438e199c6c59b6809a" },
                { "nb-NO", "4b468f49b50bffcaac062ce1366323420c532ccebc67cc0b67551ae442b566187cd3e7a969b92ef8b8bb6bec7d414c561aaeda5224a9ff1b0c10910769510e64" },
                { "ne-NP", "9f3c97f1d81c3249db4c43f2687048ec7f3b5d085d3f43d1d0b20a9a00885a9fccb7427044d222ddf4ae4f6640b2177b74754afaaa35b7e38087d3700a288069" },
                { "nl", "a5a4effeeaaa480fcc1b015466841c4230651db6b2b9769df27db18eab679532c1c15b8dc6b5ecee52d7d635cfab0412ee081f921793303cd26bfddd6f916afe" },
                { "nn-NO", "97d8e1d7aeebb755b099f03d9dcff33831b17a405a3118005184ad044ed2f4800f2ad5067cffbfb38f271d92462de273ad05aa8ce61229310c9bd542ecda2ba9" },
                { "oc", "48dfd0e901fba3718dd5377a9b5f49516a34c67f1a66492b1f44103a044974264c318dae846b14cb0c63c62a70debc6bc5b2985efa82f2472b5855f920dff1d6" },
                { "pa-IN", "36a019080b96a5e361551bb650368246c47e03fc2cab229f120f5f25d2f4238b4f0906a07b3727c21e634855dd1bdd5e92a4b92d37ee24a84ffc78cc6f527bb8" },
                { "pl", "cc40911a157135330adc83902d596e23564e6ad9f0c701242d44130f15159fee8046399b5a767267213f9dc55f925d7498c1784a9ec65d800c3ca0a95eb815ce" },
                { "pt-BR", "07d433406803529b16be80ffd55abbcad85cc30d171686b1d8b69d6824c5343236d6481a58bbec24c3b1fb481d5df69583a80643466b53c92b5bdadd617b3fe9" },
                { "pt-PT", "d2f8baff0214af8b15fbad2bd0fd8766d8ecb43b945330552cbfa09cf0bf36b02fcd70ff28973492a16d0602a79781021f0f7ae6dd900f51ea4ce2307b56870d" },
                { "rm", "c2dde90db85d26ac3605d1781a649353eea28a6e5efe8f157aad6dc5022c15a795a16cbedad119f977d16059ab5a853dae846c72c5fde5eb967bde869ed689a2" },
                { "ro", "627c47e37eccfa09a8b09fd194cb6d8d70195246ed2c983abdab370da08c8e2eb67b4d9b87a06b3d4953aacc0ce06c6e001ad34312471b81cbe64346f8161967" },
                { "ru", "3dd899c256aaad4a777bfabb6d753f908a0354229beb72073d3f4aecb75be3dfdde743da182e7f3cc4f8a2a5f235f1ed1f9491d3375e122fda70391710acf9f0" },
                { "sat", "55821fd34ebd069b27537bc8fdd7b263772987246082a4c4c68e4ffbbedc58b4e409478a7c7c083ff4c54c694e2682c06676aba01446dcd46337d8e3e1fd1225" },
                { "sc", "2aa583d63240a2d9371c45f7fac952b722164a68aab8833763598eafa5cb0ee594fc7b3cb38a834af1626b5cc06074be690acf3ad44dc696a56779d013bce0c8" },
                { "sco", "94c98fc4ffe0f6890240017892033067a29679da3482957b39edbde5cceeaaf6fa83cd43f7ecc981f923509cc1611d4df6e29a81f91ecc16d27682fecbd3e17f" },
                { "si", "039a9061a11e09fca0ea0ac52a9c0c025c7d439ed79c28ece024b5609440e8bd55e3ef639d6750c9d6d3a451c4feba0b1ff64b78f3623326d1bbfe02dbfe6ae2" },
                { "sk", "3baa5bf8f0f60e5d4ba23a44e173cd62adf7da59d7eef1878c156efa3bd964df005bf0a52e8a6cbc23ba4baea6373c444a8adf86ec2c58b1b2670447159fa976" },
                { "skr", "81c42f15fd916ea186946fb14991998d9833f4417bb1261bae109f3c886087a6fe75581ee70e7e47c66472b00c1c42bf50c3eb2369109eaa09f38dd8ee04aa21" },
                { "sl", "55d9792832bddb235ef5f38fbe8ce8dc84ad411f746ebab316c913539a8d93a78460ccb895d8a49957940415e78f791c06cbdeabb5bbba0893d9b17b7c00f28a" },
                { "son", "cf5ed6e5435c99dc8e317c48e14d75effab39293d564ca84301e90faa402677cd5c0063b7b59c99a7c90c9bbaf15ec3b993abffcf56245cb63dcc5dab1f79d89" },
                { "sq", "67a4d34a5c030bfeac55e28d84d457ec8c27e18337d4b7f949eae03af6f722a530415c1de46aa12639fac641910e50f855795051ac53f83541580d5dfb485b87" },
                { "sr", "4f7d72e7d036bde285a3168c0fd324f5f6795a4acc5bb027eadc5f20e4b1a734baad7a535eaa0859982313c2a3978c6a84f8702a1fd118112dbae2d979414044" },
                { "sv-SE", "9da8a9844f23c6fffb509e2b822eb5a224475033a40f0fe738e2be17266904a0d1c663d929168231b7470826030e8d1519b72c58f7ca7b78522b1a57e0010220" },
                { "szl", "fed04913c95b2d61f26acd581fe7cbc77d70bce3943ef299feef9c2e3f127d20841124332d96c47d46da9ce3cca1c3ae00d5cb4b180e1dc640ec4cb15c38e208" },
                { "ta", "f94d71358fd1ea30e57f98fd3b575982fd9a9251828726cf5a59c9f46b9bfd6a786a555d9339cc087401fae37a0ead3cbc5bb6f6397794314e3911e1356fd5e2" },
                { "te", "e029e9275b6f26893c994be3993e99ed6fb0dcacbd1d884b9ce52391bc4e3524e9600f68e7e859db894d8b63233ddceecbc53b5dc60c07fb76adf7a2d541523b" },
                { "tg", "e19690c7bd5279ff388cfb6b9dc2509c1a849737c9644f5b93ababfe898550ea3b2c1a80116a5ad2292cd55a448ebe47e9050ad35bb1dc60b003a9bb781f5e74" },
                { "th", "16867a8f7a3985eae922a7fa77e779a0d630922d01444601ed11d387d2a29d238ea27ab7cdc142408f80b1dc5b31ef2d7e75faef017425d1e65e2f824f80e4af" },
                { "tl", "a3387b665b4295280f59e0279524b8c39be0aa056863d66ede235950cad2a72f2ad648ac82225cc7f8574e3008608e643faeb6785c5cceb00de597ed55984817" },
                { "tr", "32505f602b395ebae2b1bc325e5975448d404f7c2298b8dcc97ee0ba30743623f8ea5f9e8720c31c642906562336bcf5eaa464f463c22e008bf9d203ee3f31fb" },
                { "trs", "0cc8b1074fce2f617cf24fa80b658b62386f1e9925d27fdb8cc2f0ea4d24d5b45192effd9783e577fd18df88593d79b41ae089a6ed3ce11d7a40b9303b1a9510" },
                { "uk", "9733db083ca8bdc23bd36faf1cb79605f9705f5adf486632ba2fbc35bc94eefe00a34c183302f713b71e67d8bce5a804ad64647d86ce43896c3cbbf2a06a554d" },
                { "ur", "0241489a0eb7fb87a820681d936a63874ce8ef004466ac89defd3fe719687a52c012ebee1fb21e5926b0d47d608a43650f5bb8a648abed4dcc4855a878d82327" },
                { "uz", "e9c8f7fc7318de91d32d8c0a862efbe9a795733f28f94e351b08b108ca62ec9ad0f291c7049e6f95dc0dbdfad09c9157db421f017ea3f6ffa07a9b8fd9e3d1cc" },
                { "vi", "a0a10bb20e63ca3e939704fdf58663e8f3db6f5bd3753122debe696fa4751aab080b9640673cb05518ec7401cee80aa76aa0f072cd8a0297ea6d77248c13efd0" },
                { "xh", "c3d010b78e8e2bad0cafc0d20e0ffc78ec1d0ece61b9b2dfdf88d00fe5c1b3f6e9c08ebd2cdac0826481be57055fa7ae66cef51d3da350b7b728effd336d8ae2" },
                { "zh-CN", "9614c354636000008d96327de309374d0b3c1234f87fa97c17b7cc2ba9811fd6977c9c447fc58f5adbe065951e3e392527e659f3679aaf65c39b53ba6cdf026f" },
                { "zh-TW", "9925bd2b5c2b2d9d109b88edfa47cfa760eb399f556640237cd2ae7d1b275abcbb84d72a3f4c9483a40cecf67d1dd0ad878e25bdce1b7d76053dd008b915cf75" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/135.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0bffe4e20c94c760db5bccb4fe4221569d076bd4c16d0a2727aebe1df193379dc6d4fffb2569433573e740e20647f640b1ec63cb15fef87c06979fc6193bed4b" },
                { "af", "c36f10d65383b777203d8bb035bd217240f4bec9ef8cc8fec56161b57415d31b84fdb50a4c264b75d6452ed83b9c255a4c2c0bbd08b760e0415d3913ded33111" },
                { "an", "92e38467ba92ad17fdb8d4d9b9d6e8137360a43272294483f4b78946ed966bc55601579af2cb3a2465160f7facf072279fa30139db543b6ece004d26d64098b7" },
                { "ar", "4cd47ce2537f8fdca2cdecb1564b6583d6815dde0d6dd4484c33216e9fddf08a4d3d064d05f08c2af7f11b1cf4cd88aa2676ab4d179fc31df01b3717f3480dd6" },
                { "ast", "eb2e1dc2eb42c73ed01bdead1e58e793f747fcb19c57e591de6c2646d27ee4aff06021a729e67930eebcf57e3417e10cb1016422ad382897f599d6544edbde07" },
                { "az", "5a08ef0f835902004c6b165579a416ad524601568e58607ca1f5af8333673928afe28f1da0a5f7a2b35d1a86f60fb4c6c5306686d4311b9371cbf4efde424eb5" },
                { "be", "6f0aeccd3154c6cf7a33f1de233f92d5877ee5cf1162b62b55d06e15eed96d4749992857e4230229d75c2716cd438eae790145f43fb98d3081843c862252b34c" },
                { "bg", "d1738725a728130bfa89faa67cfc881781705b870649842ef169b3d0cf48c7c0d4cb645ecbb5f79791fad8ed437039d9d1b67a2ba7a2c73eb01d7f61d063fa80" },
                { "bn", "7d9cbcc24ad17c6ae055a17362f4f076cdea57c8bf0288b5b068c19402e0a98fdd972e54fec239ce6f35ac597c4760c878ae3046657530785dae7cef0ff9e5b3" },
                { "br", "5c606c90275566a89adba6697300a359817ccfe6fdde431d953faad0d879989ccb27fc3dda89b3f921a87e47750af27c7c43753599d267703ef3febc63a47473" },
                { "bs", "e740de4fb12929411ebfbdf9574555a68f14590734ccf77fe22a92161272107fa01ed81c615556cf1c8fc606c9768b49cf2309cca847acdd7232b867ff4f1247" },
                { "ca", "dfb91b890a95fabe89aa84461e1db8a90af309c12214c797e7aa1981987ec3b75a38f746dc6f6353e3e033ea9087f7005a494ba5f30d2a41acc4bcfc7fc52e7a" },
                { "cak", "231785d848cd2a84de9975863741739ecaa1777cf21ad5438f2ad274051b53c3c499ad93ecfbed4cafe78385d519480c5b467813199352464e0e7893fb66903d" },
                { "cs", "0d0c86f8c461049c6acefb38ae605fec9366f2b959b1ee64a3f1080a4858fac4214b32257b46a58656855ebbf0d3d8f1bbc4b1a337b3324fa33d512923024ec4" },
                { "cy", "36739a5201991015a46d101c176a6114535b27c5e99f213426e9abc8c0e575b47a72678be64fb4563affd86df9a1bb0b82466ad2630c319f458dff04e64c0fed" },
                { "da", "0102d5655739c2620eccb9887389a7b5ad260e60f07019ef8bdd9e7b40c5a35e796ec138c13ecda50f9c4cd2a521e153f802cc743e3b335499936cede67faf36" },
                { "de", "b2fc1483b6e81519e127e95a6feffe1cddfa6a38fd1bbbaac2a3e2032c0bf08f2e51a541821d463e70671a3b63e7a7c3dbd51960c9e69979e17643977d73654a" },
                { "dsb", "edbb65a5cc86c163f24ddcd30658660d8d7158723b1f102986e14407efa1570f4abd1d9d107b076d17e962d7269c309b41bf0d177aba858329bb930ed3412783" },
                { "el", "5f55a54987103b064af74e4e951352152056ff6b0084033fc51bbc868d34d289d5c87e18b5a7443394f2f1dfc53a9e89352e70b87a78b8a484d5de092dbf3969" },
                { "en-CA", "aafeabced5d2908c0c160b40051dd8dee944ff3c2f5a3dd9fc529de63f302e6e756135d734568320bb9780c2afe0fa5981efaec1e8061d4b82d7cbc0b8fa4b98" },
                { "en-GB", "c43ffa851d5224d2c1d9377f5f7b093e5c06493bbc263570837b6f3ef76337a723ec2633f32d06c49510f54fe4320036bd6578d57a9c205912b261c7480e2c85" },
                { "en-US", "edbd6dddaf76fc0cfd8d3bba5c09b4074e2af3d598fd39da3de54875bc4fdd918a03c95456c3d6d1aed3d4817dec0ec79a41f4dab9ec1eb98a57137a3764a669" },
                { "eo", "935aa995ba2f4dafcf52266ff8f10d5e8ec0e1ef084cee5160e34a17ea502ab9c80fcd8135965bee9d1ff9373c0f38d63f2ef7adfa5ceb8a01bef80089c503e0" },
                { "es-AR", "b8cb2790cd284faf5a7a821fe915423dead2d3ad6d1353987c73af22946a6208f15a638ba9ce030da2a2bf5491650c0dfa915061290f9a4b46d9cecfcd99fd51" },
                { "es-CL", "b4e4636ed61db281c855e978ddbe4c4b90cb813db652bebd0a06c411c26e21e49af26ed6ed6f068f6541d879a8e05e160b036e0cc671defd63682b2c9361ac73" },
                { "es-ES", "ae1ca2443915538fa7ace7c40708511a2f8a4f95658e0475197c8742d0cf6e71a4f2c9b9af46bcd2401b64c741d2734a9c06ad73b12e46315722903d0be45128" },
                { "es-MX", "2ec0bb564b3df22521321ba00c57bd97a1cb5a17af16833eed100721e1400ae9388a5d52b49e9dda3d9e8bb3924729e639f24435f2465247497d61c03fca1305" },
                { "et", "94c83e7849cd5563590045308447ef498b7be063627909d86b0b94d02f0fde5118edcf08a3839141fcaa9020b5902e67d70a9205e346ee0677bd78dbb7e7297f" },
                { "eu", "6a9842720d7c9b68f4bb43ce107af19a76422256b9eed7facaf1dc8713b97825cff6aca62ea1a1c8f3e3c1bd62cd1588af69a741ccb1378bbe0a20625a6c0ddb" },
                { "fa", "c514ecc127997832b3ca14dd231b368e2f14b2c0e5a09d5a78ac64125bea11749acdc3b1773d68f8c5fa3646a7d1caf5d2f089d9fe90f1d710f7df9f99d7d091" },
                { "ff", "9ba5a08c12703941760c7ccd5697ae5d1b8b6c2fb9eee2da1e50c0b276d26c84a25451e733e3c0126713060145285430ddb3ce1e16dd3add4fbe1ab41bfe8ec2" },
                { "fi", "f45a7b859746e6606aedb629973472e541de53fdfce722b7b9fe419ff65f58a76eff65f967320e4ca85d4da7c4f48982bda365ecd16b558e4151a5bec4d6198d" },
                { "fr", "bfd5a54dc9329d65e39294fb0792de8e4fc3f6426767bf8fcbaa99d751f1db8c13edf4b162d3092a60e9aa07f5045bb186a2f16a73d0488e92714311d43bc4ac" },
                { "fur", "98eff25e23c9722aaa0f59ec9808f0461c992194463956b2bb6f1d6c532d18cf1bf0968902d6dbd7172f0a158cab32b0a53bf9269e645cab422d8bc4f0b2a39c" },
                { "fy-NL", "41afd22dc69d8aaf293cf379c316089d8fb67e29311930a08a416d28cc331aecfca9ee95340ed2d277991d21afdd8fc2fe11652d1d44a87aabd3facc4e05d971" },
                { "ga-IE", "709b9e1efe027d73452276c37fb2e8869ca68ebab0ade8cd285526ae7def9c01d31113f66ce00db24b07d88c0e196a49a1c7dd5f22f03d7449ad25aa346ef65b" },
                { "gd", "d3f3cd131a64cfaa3755c5bef1eaf50f75bf3a01597b00d97881def3aece1cfa60364fe2c9a44c3744b0cee3396454830540ff8a5e0fbf205e6bb7701d5dd5e9" },
                { "gl", "693f44628b5ba6c2ae28a16543019b932c1076dc1f450102936af6e21ac455ca7d110530b9715778b680931d50291a7f1a528507a79bd2d0af3700abfe2a419a" },
                { "gn", "60ecce046d337a3fa97dc52b527c611e82403fdcad982645f4a08665baed954e971acbc6a98221c02b17545b8085d67ff1cb33920e2d8fa123eb348e96dec672" },
                { "gu-IN", "9d17606102a38aaa1ac439104bf149e79bd872c0081128e14e3d530c407879e2efca5e0e7b6eff537985eb4b8b8716e3148899979d9889d76504825be71cc717" },
                { "he", "f97b52a45e06fdae094fe18856c5f1809791acf026abec3c935887338f2632553d39bd4c8712b68a8886ca54917c556792fd5c2cdcd5d75cad3b6cab3175709f" },
                { "hi-IN", "f9518ed25f0fc250758e338e2132306c48c7036898f6c87aa64f3c45f60bf623d6798f9881b13a073990f2ed450111aa7b5dcb48fea88a14575ee40ca1f5c53b" },
                { "hr", "9923b798ad7c9bac2166f5f76a1e6b6f57ea6d50f96572cd096e60c2321a7b8e0cc50d8bfa4825f6aef4aec23399f417d510cef07839a894e6e7bcee54c0c40b" },
                { "hsb", "82588478abbdaf4d3ed9806cb82f42235e705c484cc5e9240e332a1331affb55082d707859e5cdaabc44661a646e9d2f319482ed8622979b20e89dbab7c2bddd" },
                { "hu", "6ed55952de714bbe01bf001059176fbc9c5f46f23187085b26c5348f3653d86a3bf8cfff82035132b966cc09c0f0f2efdd2be98e2da62a825d05cc4c22cea0de" },
                { "hy-AM", "442a10bbe27d5a99d786e9948453c041b51f6e5526a4c30d8b1c9f3e0b2da8d5f5aee664ae8bbe479a716b15c8f3c5d5652fb15d2939f3bd0ac3f068bd26c019" },
                { "ia", "8b3e9d3ba169a650e67dbc4218362a51c8da98a93d8f61fc23951e2a3f45f12b2b35bf06a9fe0505b5842c9d4cd7e44b0057a28e8413eb938511580bdf8cb839" },
                { "id", "12bd0fadf81f3ce031940ac68ee1ccba936990e3739b3c362fe7c48a07a09aeb7cfd23600d36f850d0fa5112d1d378ebc875a0b398f7a7ded982c86a3723ee85" },
                { "is", "04111bcf4978e25db0d166517e85ac15302e92b1b8dc93a1736f844ed1eca48b0518795a1baf45ee6eea844b3ed392177b051a8fac10fe12f4de584f88514151" },
                { "it", "a3fc30683f0277ee815f4e53eee34dca5119a916d488f200856c3f5f6c233ddaf0ae8af65f706e8e5211cfc8b3ac31ac8299e02b4356bbd5d479dd6240fc4675" },
                { "ja", "1ed2fd22055c22c4e9e52fa98f110d838fb98562c655f510784f4369567a6eda9c84f2307255ef3f52c33156bb050ad43490795ed6cec358519b6add5b56ae8c" },
                { "ka", "e309d052dcb2383b143a0f8c9c8568cbe6fee2e54baa370889f05d43627170bfa8cbcf9fbedc47828aa7186db82dcaea36165bb91245664fb7b09343347ceac2" },
                { "kab", "4041970cdc18850e5ac49335fbc59ca0c7e159a16d2483d9bf59ee8b5ab974f0a7f6ea08e28a04526d862598848c616d1113c5320fe2d6c69e6a257bbafd61b8" },
                { "kk", "46ad5015ca6fad2507577ee1ff10bd425d9622d46587900e5faebc6ff6ef8987aa16abd0311e384c09836458abbccc59396dd245d9bd5d5d78248240e430ef4d" },
                { "km", "40cc329e89eaf0a019cac41fe4ed7ad416751965281892b4a5badc55db9f5e223bdacfd3537ba617e69c013a92f62f121e910e45f65cfe8d2936b2f31c940fec" },
                { "kn", "eb6cb0fbe8def1f09d334fb70f560f80e660bc47dbacacab39e7dddfc793c712967fb885843c813e65ce92bd185a464398dc50f47c9da0f6fce05fde37ce7184" },
                { "ko", "0ed964789b3196614e3dd1ce32e516747c211449f5af3e63f4b530aa371ab78d0630889d9e6a6b54a9180102dea6b38874dfc807578833083f4dc42cb3b3ae1e" },
                { "lij", "cca38ddb28d10bf306ea5c7b7959e0e6d649652a6bd7f0a17f69dfbd6875f454eb029b4af8090cd898b71ea43a8d958c7167aa850a056afeacf5593a2c22304a" },
                { "lt", "1ea6324396ddaebf4ca7997d2a3b2421ba46e4bd8505d0be641157782717be288c10ac810c4740cb746a21265a0dbd88804301b5655d28685743fd6496b1292f" },
                { "lv", "4f832bf1fe1f8f5b2f35e537b73179475eaceb09b090808acad5105f4fb8c751477938eaee20c18c7a3952fae6545fd9741dac07a600a76e704509bfaee47ca6" },
                { "mk", "3a482039653de5017ba583073f4b2d2ed5c671ade5b886bc028fe3f821ac12af150afb55de66405aa54da81b1f0861d50c750e06991490f9794c2a296b8c5581" },
                { "mr", "b695ff1e7a15b807d5d3be27b5cfe746ae7c3927d7552979f624a40c363011dbae8decc2efc5482d1aff260ab6bf406997504fdfacfc458baf1e5b979a17918b" },
                { "ms", "a92d0a64b7bf30e138d828fd4bfe353c16593f2bd7eaadf2dd9e5e84f001de3a75a4e42604408595256d2841c69da96c0f7e5b38e87109d17a1d785eeeee02fa" },
                { "my", "86ed31dfa8c9e962f376ba23d3fa4abae64799364f0494719cd9919b1b9a093bd6d129a99e78b2c2978270b20b4babe0dee24178b9bb0025074b9eff9d545c5c" },
                { "nb-NO", "199c9ea17a405f1e4df4df306cda17a0d37371f745e9f4f67537a63a5ce22e44175b9567b4086e474cf5950999bbce723b8bb05c4afe92c62c87cf96b0896533" },
                { "ne-NP", "8876138d42e5b18660489c236fbaba2c7fc3dbb33e9622094c627bda2c3ab942c430fb0600964d38c80e7e67006d3eb7391c3d9949aa309ea6575db1981eaaec" },
                { "nl", "b83b742317eba80adb02eabc5e7aab804ab1d7af552c2a7935e1755fc7fe6b24311391cab413190b87900672753af672aa90a223e4427fecba9d572134cd9a0e" },
                { "nn-NO", "d037848e201bcf3ae9668ddf3fb560b96da92937ae99fcb7b8caea5db34472776586f93561fd5f65c572fad20a3b6c0455a7b86b05e43e697a4f4813269ba53e" },
                { "oc", "6254740b8052882382d19c022b6a8f19563875177e430068cadbacf82b01f4b3ea41962267a907f6e6c51ff98b84a109e96eaa767c1d2f44a7b363d508cde07f" },
                { "pa-IN", "2f0e199da45eb5e53c5ee0776eff97418a86655ed7f0d2e71d596c0fb5991dac44ef97610b91ac39ebe1de06cf6fe5acce8379fa6b1b5ff1bae501834f03bca4" },
                { "pl", "072e168067664b65b89d2c8210250bc220d86b9646ed42a35af83239f957b927572e3b71a8a7d4c381f04639309d2300af956dee1415944905d7e5f4fd7f9fe1" },
                { "pt-BR", "20d9fb75948c35a90231e3a4ec730f058723ad22b87c8c2c09ddb064917e55bbbe92fb2e0980bafcfc4f0773945360af40cd203baf24a6c500ab58631b259132" },
                { "pt-PT", "1319798da31962d3389c54269cfb7a8241ad9f7c7e10f9a48b448e64d804b604c4e29bdd5e2ee392c8ec70a31751f41fdd95469efe7e83e73ba9f306c31d0448" },
                { "rm", "e6d94d7f538edd7928c8574bc49362a54b61bdc6215fbf0eea4d414ad9c2a1d85d8afa32db087fe585a68be6eb7b2cd8d1ef21862a5638e5559e8ab7697bbbce" },
                { "ro", "a13366bd5b7a2efc996e38c3e4843271f09202330381f69c740afef1d569ef5b903f40748855eef6e896655c539589a565327bba99bc96341f16824b0615a162" },
                { "ru", "d8e53d2f95116aad64c42db6b111444afcf12246a623c69af99a75d39ec3832c3cf6a6f23214d8c0ce7f1c69cf07b6a57d66a70606e16a3da0342485940e96f7" },
                { "sat", "e97daf26f4404ba15bf8a2e56cabd84e1b247fa4a5084516edd3717910ea312aa136200cdfe62f2a9a371c98cae2809807cb495e28824e95f16049283d2e81af" },
                { "sc", "c4bb0a6af14a46657d88597f778f76e1f58cd418178d7ad1001e6d33bda52bf4a063852effb3c4ab7448b370b0f9865841d62c1f94fa9f909f882b08af4bd354" },
                { "sco", "99d6febf2bb744fc636ac43cda82aca4710544148bbdd6e8b669e4153f873679afc9af2707b21dfb7ae46b11d95772bede99f7058764bee5c07a9276996c9d51" },
                { "si", "820de89de4db3dbe6dc8a8b570eb15a93bef05b9f0ac93a2f1751950af627581b03163fb140370cc01bb5abeb380d18460289e8fa6c03ee7afdc80790ce5f746" },
                { "sk", "3089a462b73fe1fefb603104f8ed5213dac6d74350225435534416c5ca3bbd83479b115a5f0fe9f6d268d8e871fed36d841393ddcd7ad4ad7821b69b8eda5a9b" },
                { "skr", "76677cebcace765b8d476d4a6a20163ceee7cc9b507e3568e23abbcc36159fdf2edfe7e3726241edc255897291f0721a43bac6c6916365c393ec07568f0e9ba1" },
                { "sl", "b1925f7e60f36e3f509e36e6eda6d4d4313719d655121d5e1f00f06e3e3a1c54bf3614add751f2e5db3a3c2647cdaa3ce80fe9d57b249d10b76b67c79ad52957" },
                { "son", "f7091c6e9a0bb5fb6801d51fad830a389f1340d63a3ee9ead7fda666fdfb6d56017bbdd838712d613571f16913c1cadbe7e0540bbe4dfc234b7a5cf0c6863277" },
                { "sq", "d441152964f09b031f80b6990c9c1f7e116a54c63e2b5b6eeb0353f73c7b1752d4566427ca538e018bbf40697a721a94b8fc93d0d17dafc15020f5a7db69c086" },
                { "sr", "0be00e9975e2abeabf42f5b7cf3018e87be83c36355dfdfda9429f6f53a174a2227132162907c9c06e459e1654a097043c679041a0a6e51f639a9b2824e0fcb6" },
                { "sv-SE", "3f4c9a05be242206493ec7299301a163d1ac17b25603b3ce941d0928850c3a9887efc8648bf0b64974ae0edf50121db0dfc49062a28545c0a451b0586763451f" },
                { "szl", "2f6df16ce1257027b6a2e14489eebfdc0f91384e5c553be0f17092745f79c27724da7e89bd9aa9c32658008e71e794feca672e15586ba69bb6c7398c07a171dd" },
                { "ta", "bf74883758410e62a68f6f55801f3917e0e807bfda7c25d1d59b8019202ca5878b661649e989c2efb2ffab866fab0cada9a42664deb1611cbc45a1c04eec322e" },
                { "te", "f056b27c78f2eec8dd1b93034486ffbc772f972509c3ba00d8d73080a6703c7fda294995a7ca789850cbe09cdada452a4c85f7011e0457f570d4b10c11d81217" },
                { "tg", "09315719b805ec6264e9b2c05d6201ee92094cbb7c600cdb53b26f550661a82864a1f9995389abb6b9e47ab74d1952ce78fce27ce5e5bbcb1dff3231b9dd3b44" },
                { "th", "6a2bdb2fc6c998a1b1d01891b971d030944a650dbfd0f0eb54058c6f611cb8fa82309e8ccf3dfccc4049ff9818b9114435a7ecc3336efbb6f810610cabbc9bcb" },
                { "tl", "9efaed40f174f250f20f232286448104cad173f4bcec0e013675806647eecd0fead31bfa7748c3d8492706aa77ec48532e7e844c11f3ee16179c9615df57d460" },
                { "tr", "c0768d14a25ebecdd0c5237bd59b851991e35ecee26c50c156a77189ec378ad8ca71eb2fddfc538cd1377bddca132d94e7238011a58dad6d53f146ecee555847" },
                { "trs", "b34817b9c774cfe7c3bc4ca5ebe52ad4eff25e41bf06a8758d311564e8aac7de42d8eb45074624397106b59f845e140346fefe1181599e979cecb6fb6ff900f5" },
                { "uk", "ada2cf0b096a0952c79a52164e5ccb6d94bd63640fccd62b6a4e073e0c78d982c5ee98a1724b2768ca1b4c0b17c3db9c36a814e565db068f4f10ac6622591592" },
                { "ur", "b844f7fdce8ac31db6270305b3d61b9b7fbd05a8d55d5aeda17b69b2f5926617fbcd019c24918b6a03a5a4bc6110ac7723be53453c67d1f9be1a524ca8a15d4c" },
                { "uz", "e0862b6b233975e0e635c1dc2a0854f1f1dbaf94456502ddb5a9d4838d9f49e86528e3fcbbd62f274db48af3191ae8faefa139db021efcc80313828b18a222bb" },
                { "vi", "3243c3cc2478240f46baab7df7e8f22278125dec39e6f7868ba0669bc8b673ef51e636514fd17a8f52c32b4cd079954cbb557266054fd43809c3feec5b805b5c" },
                { "xh", "609040a5c6102812fd7cf84ce08d24223870d95bdbd4e73f661f1c70cfcaa95cb5979ea33d7c4031926e8431db61fca00abf053d8824e6da9ce17f48182b0e5d" },
                { "zh-CN", "baa9327db85c14d837f089892e307ec71c312f20fdea4ca0fa31fe63239f1674318ef61dfcb33dc6254c1448000328fdf8390535cac801e545b928b28fc0782d" },
                { "zh-TW", "9bcfa51e15fa3917da3f5eabc2aaaeda937409dde0d3170d38955d39c75bd895165029d41d4e415e6b8f22aeda65468edf1d91dc9754a2d520ae0061b3486885" }
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
