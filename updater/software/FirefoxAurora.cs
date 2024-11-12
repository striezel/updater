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
        private const string currentVersion = "133.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "16bf83cdc5df7352679ec563ddcc6a4685f905efe95ef18636107d3d466ef2a29de6bb17f39c503cf07301483435ef679a3434ae5d68489b1f66639d1dc5de9c" },
                { "af", "3f73587086e85b7b46ed391752755f55444f6fe5d4a5fd5316576baa6311ad4421b95fb3e30f5a3c84fe0c07027a5269637979328f151b726ae8d8d262c5a541" },
                { "an", "e0cef6bad935aa08462eec04139b84e310d9fc386a73f8800ee4866a0a6cc1ea967520cb5d379c0d975aaf0076708e51382d19771ed5745a19dabda66def89cb" },
                { "ar", "ecdc0504e1ff61c0e0447c4b9ead9a36fbf77b2cb6a278db4b550cb8a17309fbc4d34195badf2eca6305aada8f1326d2d0c2cf259a0a2bab6a3312335699dc4f" },
                { "ast", "3417a0c4fbb4f747f9b52a5825200b51d7ee1f4ef33295a074850144b00b5a1a3b2a14d4dd944a412509b43abb519730b344dad11e98b5c12c380d3e7c755756" },
                { "az", "3169370f299e8bd3b84f01603d4c96ee7c7a154458a43cc123b70e44408fc485dbdeca7d8c90a5aba1a2c7b93dffb3909a1a1a0c3f1de8765afabe07c33875c8" },
                { "be", "4b176d30214bd267e905fc4debe80e1db953a3260ff1027675c8ca3f7bec09deddf1e3546af0260d774adae1453da30b9ac7b446920493ab3f1b2c259d0e0552" },
                { "bg", "347ea0a9bc320dfa382ebb141573a0e6125a2671ffd7d6b47ee70e21ec2b87a1ec4b2614467577f2626eac368d186f238b27086efa69e4bca47d31809548585e" },
                { "bn", "08f6a1c693afae76ffd08b5539c4e706faf2196d5126e06ee5f66c5eb4ca9cf56c670d9177bf71e1529d239c42ef77ba42195c0e7bb7fe92c7d0c754f7a126e4" },
                { "br", "ad5c82126507b55afbd8db942aa5adeb2b4304d585f190ea3b65c97ceac1f94d478ba0bca54833d8d1ec5d0d4f33e653c88a2136cc8c76595754fae2ca8c2d75" },
                { "bs", "955b56475f0be490e6a111da2306ba5c95e7a808e46d74fa2d156eefe0ce67465abacf7631445a93686099d70c49c9c5f8e1f1f435fe0ebf8ef3f31054431d4c" },
                { "ca", "9deb1501d14377a6518649a6bdce0bd5f3caa5d828120683a75c3fe75d7213966df3e5a5b8da6a6686988d3c2b62ae2508dabeeedc2c0621e4af8a1eed09f414" },
                { "cak", "965e20127a51420b6d74bd80f83555c59b27d204eefadd33d1877a9e5a7250a443ccad56ff33264eff052c99516179c1ef2ce332c5033274f8135ba238ce593b" },
                { "cs", "57ef1a01f21a3d7a02b6065fd13522df572c26a15fb0b8106588518461025c982edd26c88be26668f83e9d509e9665f8cec7a7f45e77e3639dcd21d81852595d" },
                { "cy", "d5125adcc0b8aa35d915364bf313dcd686b1b84e720023fd0fc0b1d9ae3cc6a6cd2ab8ad9f33c75f8312df87b48130557adf384ce90d4f346e00ad9c8f23ee84" },
                { "da", "7aafd4fad1cf6f2101d5246b25416a1216b9153edbf5a463c7399ad7145a14550731d6f928cfa20fe735d9503bbbce861f465cae2f6110b298cc926112fffcb3" },
                { "de", "6485e18930528ad5c3a8a3246f13d194d467f1df745595985cdf2b51209a08ebe9301f1f81629be657d2dd6cbe2f52309e455578f5a4413d48a8d2bbff9b1ef0" },
                { "dsb", "3b24ed9781c3ce3a2edda7a0526e84becdf41ec9de8de63b35edca1e56f14fa541af141729016eea9bdc1c4029a74990695cb8c3fb4bd6f6feeb6966538c4e38" },
                { "el", "72e229f81bff11f1cf11f6bc68b3765e88cd1058a896b6c453ddc2ac61dc056ff2c4f070d09caae426274d17f82f790e440519f0ed7fa15ce2a78c63fb05fb25" },
                { "en-CA", "097cd0ac1ae436c2a6bd393aa41d1372a836d034470ef8cf60e6afe743453331d20a04af8baaf0ba4543e895b03ca9510847c2df18cd41b2969ddc8b2aa1c758" },
                { "en-GB", "1d3794e9b0458fbabe8b4a4f95d204467d394cb0d8e1d7df5ccd0ef170650653f5551ee590429233bb9522e8bc8ade9aab622dd8e429f1e322b30004a0ba42d9" },
                { "en-US", "1d7462ff6624d830a6dc073fb2501419c0ac0aaa566be5bc6e718a51c84a975d49f8c137fba25b62de0e542b7f93f8654dd91ae79a26324179c432589f093c2d" },
                { "eo", "0b8b64a3027e4308002c6f09194137b969530a9d348b2055fe7e53bfa2552b9e6da55021f1620f7bde2fb3b4cbde1273f5ac3fb087246b852fe6bee64c6da269" },
                { "es-AR", "08fdee3fca4ca14f0e789d9ba8d648f7d318605eafd8391292862eeec70f6c6de51f06990a92a9288dbeea398f7e81052f31479c6560e4402f60230604cdcf8b" },
                { "es-CL", "5b417f329a10145cbf6e3b1267390e24d5cafe97c7f9c5c76a1ffb281365a053137303172129aec6897005cfbed977d2f5879d87de30b01594d6eb6e41b42dd4" },
                { "es-ES", "5d25b95f1146101be86dc5b9891cc610ad6ca87f6c21d9ab588e24544c754b992bbc581b92923709ecd1d625f62efcd90460862fd2e2bc3e5a649e9ceb912ca7" },
                { "es-MX", "7505c2a1fc1d298434b0e2894170589158f6bf83c23e823540c6980b665fadb904de91114e9818db65566dfe93bc39322a64b407ad6dee9a2539e5959b875a40" },
                { "et", "e7f39b28d890e910e49c84b7ce298e4dff2638373fc8d2bac121dbb467d573b7bbd782a4c2f9a6ba6e4ef9774237b06b464fa784572d1fdc57467384efe2d159" },
                { "eu", "9a369262fb5e318328f244f50d54bd12d29548667877e67b48513637b6d8e13a2fd82f35d5ee74139d1d5db0b5151e551ad5bfff3fc967e023853151b9ecced7" },
                { "fa", "21a57f5b6867b175ec8f1cfd0484e41782307dc2c9c6dc1e6d65db068e830f6a298652ae9de3499410def228a5ef10984406ba4e8b9aa787298ab35175bdd485" },
                { "ff", "eeeb0ee1d05b07926457b574d449ecd147c39238b397180947ed94e6acb7a56bc5bb644559fa750bae6c4dd34edfc8386dd1c8caee7451a5426e756beafc5f7e" },
                { "fi", "41006896b5644b5a9d3401ebbcf30888dab0b0dee4de51de6dd2906bd75ffacc536090efd229f8f964c2627715fc06837a6626b9578fc64f1be7e9d4ca44cf67" },
                { "fr", "4caeb2978204f6c6a0232062adfabf6d268080d142dd64be316a4ccc90588e4c6aa4c1697d70c4133c17164455256b665bc2d8f69f9f403f99a10b7fc55082ce" },
                { "fur", "2c415694ba57e1f933791b3611cd4ea004080b9e3c5b4b777cb76ce489b2124a2cc567036d00abbf067f80e8f47a4e6be87a241973d9d7e71bb49199ac407814" },
                { "fy-NL", "9b332f9fac1d1e9b725239195c4478ebc822192ff60414dfa6a1255e6005e64baec579239f37092e239bdf0a0115da96841f71ee5a39ece0e5f8f34190e92c9c" },
                { "ga-IE", "8d23dff4d28a708505dc436e96436ce48b380519d4d8ca9fbfd1e0ce7f6a407902bf033f71f4466c794a73006c268c4d983dfbf9ab11c20bd0834f713431c690" },
                { "gd", "972169d5b781580f8a05bf3cbc3c48eb9e3222e1b75d4b10648eddb9a05f3910dda036653887e31e2839f00a3a5c0d9fdccde625bd17c12648b3eb7ecbf099b6" },
                { "gl", "e159d27ff399d6d6a8f8df03b64f14c89de982890af1792b3d288d45437ad17fb9893a4b230cf70a7b8e36874b2d37c4fb53cd10579a8e46a32e00dda7edef14" },
                { "gn", "2507a96f264ec41e2338d58b4827c7c0415ce34602b57d046a502f7612c6fabbf078870dfaf2d6e6ef56d89d2a59e21c5b92f82071a8b3725af7719efe5ad332" },
                { "gu-IN", "13038c8ab41c966a0ec86cb20e82ddb5076153ad2512534e9b2f01f904963224b5e7ca3f6e684619f321fb0a99f6418f95eef23a1f2911e064faad919ece3b04" },
                { "he", "489b040905786a697f5f8e2f28587f74871f682505a5ad41499f4491813310e19b09edb1fb43f71a58fdc3adbb750cbe84b7719cc7086bf8312f6bfe2d011d4c" },
                { "hi-IN", "c2ecdcc8c8b1992f7b45faf51b158ff3219c0afd3d5ad2a0850b9a2af5407a0b7bf0e58aefcf3be648e2731881719aba477490459633fe436fbd0f921e338118" },
                { "hr", "970ac94f8f06a3f03ea614c0ce02a5efe2dfb1ee6d82efa02c2dddcd4e9ae79335c878d4ac236c78a171ecceac6af4018bea50738edc54315bf4c0e13685f9f7" },
                { "hsb", "e240128859d10a14d84c9c2b56f4ad4b678db5d873fff2a5ac3e834da9002513599aa38d051afb8a1c7a203f4ab1689c9bdf93558405e5a80ca3987d0e1dba43" },
                { "hu", "14868c4b5f92803803dc299cd966eb77a822bc5309d9bbfe26430591c5cf2c429a53b2bfecd9ec5debd63783a51da2acb15eb608a17445ad6eb21730e2c0dbc6" },
                { "hy-AM", "0b1935d52dd3647bd4dc5a9dbe53aad9a0ab3bc4fe9fd588e16bbd275881b603387453440a0fe6b433302c3ed63f96390a9feced4e9742cdf52735756292c52f" },
                { "ia", "5df2d51949354764ef4554b075551a2b8928b10094e0ff1e1bc2608000d32fa83970ecf3553f1ff7ca3d0f66fa789f43837b628777b469a8bee05be0b4bb0940" },
                { "id", "2b69520cc9822b96f9d392b9123065acbcceae24c06c021b5ead97111a593b2c08e4e39fb9fc3a54ef07df169dedb53ff317e85b92a5e456e20a2ea16f63c69c" },
                { "is", "b9f7b5137c9f5542472d0d21adbda5ea3788174dfb7f210a6cdfe70244a421f5a75172f62a7d51ab31f0d4453f09cc288f098a5c3ce39a13f41cd6ec00268efa" },
                { "it", "a4c9243a34024d792da54674578c596961e0330ce0e9116ea44b34b9ac1e54cbc5572760b01a2c8f8dd97447e8423d0f1c5f4aa07fd3438183158e8ab316737a" },
                { "ja", "5ea6edd676e74a8f44ae4b1b3c87dba03fe0c5c6014f4d289878daf4a56b16ab7c27a6f48e7d26ee514f4fe7e11c704e65c3c41d23e67aaa0bdf2bd0a7bb3edc" },
                { "ka", "0dab4ec98e38aba680d82f1d916372aaf4af3c68cb670279592a15205705dd7b815cca2316ed1ece19c1598db4ddfa7aa2897f78749b681704fe9740acc7ecf6" },
                { "kab", "c7127d067445a11e5619d312b0d3c0d9310dcb86092515f2510297c241b36b86a2324b42fcdb2a449d5a6f33667fddbe63c85ba60abba1aa2abb757462eda33b" },
                { "kk", "ff9e584189de9766564588f373fdc1c7b09ef9138b1590b4ab88da52054320f9f493460cdd22d3005c740b2cdf5409b3b0a2f69e43f2763be4e04953b66c281e" },
                { "km", "33b5cdcead9589a578bb7d35d07b3070daf3b46783483f2d36a90a66811ba6a69b9d141df2569ca0aab615ee91b64a7937886ce13dcab9254cf8760f63de6354" },
                { "kn", "687d020dc00f5cb8c8b7f9e1cad2de83e81d0826b08eb3359755e7215ab5fa34b47ad808fa798a80783052e41f72cfbb41e319c8dfca8fb1129bd6a09cb3f14a" },
                { "ko", "e0bbc321efe14d95f247160a4fcfbe98a33d1101fe12901fa535a04ef36c4998c6f3228af74cc406253191894a4e96e973a2ec9d582edaf9bd0b65a39d1e98cf" },
                { "lij", "b321d65587a49142e3909f3aac32cd86109f119f340fc245c730273ee56759af4103f2fb0490d8ec385a96e4e76099c02550f3f61a1ae1a7cd2784cde28bd95c" },
                { "lt", "26b3e01a26155f42eeae53dfc74d0f2de50dc2dc7df4ad99f6808cb8ae142ab02a41f9c0a1eee097999406fdb451417c9720f5b7b94753409a42c70fea446e73" },
                { "lv", "0e81b9f2830519fbb4df08fec8924f1863855be2fccccc1dde98cfcb24608301b813da8eee63f7a0561f270e4cb38407f260e272fe2119c98a7551975cc74ac4" },
                { "mk", "d0749f28584a9ce644cee38b5fc0c45cb437a578e54e37d7a00f8c55c0e4c04a757dd0f4ce7b1ab8bea6d1371370aab496c4e86cd05e1f38c84d54f90b8d554a" },
                { "mr", "9520b6755e32234f022dee5f253c836fb438e7a06b366eb65a869260afbf7c2d9600a3920316bd143893bd64cee830144e5134cff4043f53bd52075437c68bdf" },
                { "ms", "d8c03c9f170f9ffa1d8383157a8015936c65327a2bf4cc80070209607f5edf0666caffbf652b5f20d3c60f5d0de3a09a61e62c822bcc1d13e34456ffb351f8bc" },
                { "my", "fec17c73244c6f1e489b2f278b11069ecd96300aeda24fba192658c3b1478b2198a5ce1920e13e6a94f2a0f9cae41d5138da93a8b83f8250419be27b05237635" },
                { "nb-NO", "cff8e8aefd6dacc1653df7383715fe29dea95bfaf62eafe5e53d211377c260c3462b48c1785e68f7c2422239af89b6b783ebc2853aa6868e53d47dee7a01aa67" },
                { "ne-NP", "340effa24ba8c8496ac63759b6adc829e9e86b3aae144203a2c6662227e44a77ad548dd3e7f6e4820fead2bfe79743a8fd6a5691694902c3a87cb16fedf96759" },
                { "nl", "628a91f8aa69d3257b235eb21d199839a3edd77e842c68c82dc709faab6e97930a09fd9c894075004a5595dc25df4009baa50da60e92d4529e978229a48f1bed" },
                { "nn-NO", "23c31f7e4ccb2514f9e80fb92e4861987b838d86e8a83a0cd7652d17469ee18421d6a1e97dfdf54914540efabb0ff045235be4a3330870e3cc7cf4a77592dd2e" },
                { "oc", "fa92c7dbcaf2fe404d50fde94fbb9a2fcb511a6616b179078afe775fb778acf4fd6c29b6fd9c43eb1622890543ae9ef126ee5f6b8e94eea6bcbc00c0b3987ac6" },
                { "pa-IN", "e5320fd2cd1e081bdeeb9362a15ff81b3c78466c12c308526f49d6145e95c88de24ecacf5454b30805a13d4f92f53b52794ffe584b5b476c05d0511509690189" },
                { "pl", "0b4bbb75d1a28dd3914bfaed1b98d21cfbfe3ecb9488995baa56c5b63392b272660637dbe4314cdcc386cfb347446ade99bb8dda52b999711ea75ec8e9fa8bf9" },
                { "pt-BR", "f62d452bfd656c6460233337bcfc81593c87b563f48b11988755ea1f811ba1dcb087da0ec39adba018d752d2f101c21c5c41b6cbfe90f9095d878933dbcc8340" },
                { "pt-PT", "8edc27e71b1d13c37efd44dbf47ec191f6f7d99d041401845a592521bf66991d4e8a123f099708bc43d2c62cf3e1eac7dba46c9d32990d7fe5d69f77fff35a77" },
                { "rm", "738e70f475de4d85ddaa57eb92da41634609f838d845a3025f5299f6e727129cd590b3f6b43b79aeaef39d86051dce966d98ac5c866e124b3f18bfc5bdcb0498" },
                { "ro", "18219e20cc19b6c433cd5048bd28f3559d2a79af99511cd6be804f34cdb5132e1f910af5c6c86f37aab741e26ca637dd3fd1d751a0f4df57901aecbc3b536a1c" },
                { "ru", "ff5b028d0ff6faf38de58687d07fa53ea623efb9a8ea0e545959416e7cb6e04ee28da7aa0e6c2c2b68238abaf78ea3bfef9a4e197fde1ca9dd039937761ac467" },
                { "sat", "14313cc681dda4e13c61111027182ef39e9a5a390ad0328048a61670ac0d76ba2639917b56081676b4d6aae011b61f3df177790b9d9c11b0985de704480a3481" },
                { "sc", "40edbeb92305176ad7d0b0d7b5eddbba27df205189af34f225262fdc92d3779eb63f83efe0ea5249573922b1146b5c9ffdc55c1fc4626d223798a1dcaf98e0bb" },
                { "sco", "fa3a9e6b3b84045536cf24f660d14e2da34ab721ba6a6c1924743a3115b4daae17054a1cf9112aa2e42515c9b45bf2c11b07f052f477ba015713a1f17b792d23" },
                { "si", "2dd033bc00eb8ec6fd4416af44a554c60d635f15c497df3ee4861639bde3ad9b2e9d17e78c5b71117b7996f88b1c03a17b9ecd9f01c769a9b48858e141344cfc" },
                { "sk", "2ef90aff010423f285624e722e891506509e65cf7ae72a2ee0f9eee4889c142ac5c6596049572f5966ed5bf0390f5dc280b2015ae54d92c6f69b25af26f6233b" },
                { "skr", "ba2d363814c3bf52b71505153d3e212932d1a48e16b201334c4e2635065a9de858e87b72cfb1c4956e812b3506633308eb6587795aa1d4dd384312cfef01139d" },
                { "sl", "10a803a6ca9660c5d8049b1d2fe53176bbb1656cc1b6ab194931274bfa3edf1a426d81732f165014ed978c4b8610678c121be048fff0ba905a7046cc7a2d39bb" },
                { "son", "838e6e952d65f1193fc7d8eae59e72d662d309cf65428fa3ac329fd67eb2897c3235d9f3d8e567ca7af64e6d02f0bdf4e981ccb4e282a79dd170de82b414a361" },
                { "sq", "12ec344da7be061cafef515560d00ee609c8f504daffbea48fe65846b2be77e76314359bc53c1494879c90de039bd7b8fd5a3c08524940f0362a9ca592e7860f" },
                { "sr", "93a2a407306aa91478374243d9e4a1a1f1fce7e121da3432f7e3be1ef539ae0e0858b9a555bbced196e310e98aaf588cc8a75a8852c1b2f5e70f27c4fdac541a" },
                { "sv-SE", "d71621a841e0ef946825ce8355a5432cdba1b37b72656386429d13fd6924f38020f9a3e332666384b65fc02662a93ef7225e3c13e90a672e5ddc20f3d71d55fc" },
                { "szl", "6d6f387194bc956b3e8968e8b6258d68dbad222d74f2145ac34db21ecef362a015cc097e8f4f4eccf3df11670ac05a695caaa99a3484224e89dcb9e272b06149" },
                { "ta", "7082911d8b9e9780e0c6135bebb1e032902573d5f40c325857421082b6717e46321818d0bef3d0619a19b5c084f63eecb223cda818f090706ca3491b6ae65296" },
                { "te", "8ea4f6b28cf163ebf82fbd9a5d156abf7c1b633645f79b5d7202dd12951b71d7097df6f3d72bc956755cc6e8d25e8c126e3b35f94ef223001b4ccd1c8096d63f" },
                { "tg", "c69ae397f0e9617f40b768564723774a056d313a5320c9d3eafe69f734a9cfae8b785a017e053e458c1c40938cd48a223a4f4a3404c56d462bf1d05a3c1e669e" },
                { "th", "ea46e5bba3efdc7831a2548d1817a62ab0a8c62595224d1f5d0adc7d0a57991ab315a8265d2774616bffdd6ec9201250c1c1d0771461e04ce65123040102ddfb" },
                { "tl", "20943d89bebb9dba387f1a8b55f1086ca9d143ca1736d83d11dd9faf5fe8760dacd770b62898ba44d1879c3f47cb03853f250c5cbd393590a41294cbd6d23a76" },
                { "tr", "ca35cdaf654455919f1e2c4d109a639134c7d52f981626a1f4bdb1aaaf5ba435a866825b1d877bd769aafc67a666cd2fb99e9450c2eab789fc754ad978dfc397" },
                { "trs", "6aad2932cc193f885b87731190271d10de60021b88aea2d1a671db8a60b50011ed8218c04f42459218180938c772f356282fb1a57720a68fbf0b952bfcf1a891" },
                { "uk", "bb8115d36438fb32707bc99773bb284aa3a0b7fe26f43a1c0365830bbd05e74bf6569e31867f15037d8bab9c1633a9b73073114498ac69910851682e7366b75b" },
                { "ur", "aa44803840d6f04e84f24c27436d6cbff0826896d5e833800a8b6efe9af18af79bd3dcc065fb11592517058dd5b938268859a36eb73d5dabf197d1c8049b3c06" },
                { "uz", "798f08cd5b5bc3064cd3c612af0c8dc433edeb9fce0432718775af399a36a490688ab5b81626912cdd81b8d721f35b6b090fe2f288a91cb5ac6b4a1dd930dc60" },
                { "vi", "f9f80db53173f94eaae45f7822d031d34189c0d571782cca79a4e8c6f478a07f0fac06f3b08ffaceed7c199739d1047cad9db349f3bb82d6332fb673974222a0" },
                { "xh", "10212c4d3c7697da31dab5f016b3e586274cc84fedd25091ed0518c2b6165357f9da239dd6253ace1270b880a8111e75a906e98164236b4397f19ead3782b693" },
                { "zh-CN", "70648a3cf20672852b0385d5ffa3f654c5ab0949728eaacaa993f45c8a6677beb1fe9f8c20fe2140a7b80a41be272fc98d9c2154c40001db99bd4bfa418991c2" },
                { "zh-TW", "c7d9ba7f8f888835f03f599eb4375c92e7ddec14944393e57d696e8c70ad9b3419377949234bd813372ca4b4df38db4ff86f1eef83f77f2efbc86ec50d8917ea" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "45c291dea70e32040a55fb80c6695e5c30cecb5ae19dc1b06873fd09d3b5d34cb60cef7c3ba50a936e0801591f31817df94588328fc82038140889f3d9cc76bc" },
                { "af", "3a9ab0c69713904b68eb81dabddc22506f538ef3b77e04220c517289d138283075a420d07d8164d39227bb026739a1a131f9dc3075f1836a314c117a4bed85d8" },
                { "an", "9e89affc8bb5253842e245872367a07b0ba5d7b1febb86a9c6c9bab6d6c2d6bd5cac35af02e37e759353c5fa8b297b88702c4141738481c54a28387a607bace0" },
                { "ar", "0ca30fb156e02cc3e29fe88332d8004a2926e30644e89a5f1d8a3e9b2439e4d2ad071930dff1395669c1142a73be7023da800912a95211b8d1402246a31aecf2" },
                { "ast", "537d8a6bf1f3e79e239ef5bb0d327b9bdd6c253d1457245d3157838a6cda9fe101fc56f0a1ffbb367fbd1b18d5dc7bd4944d339610880d14f2c86a5327f865c2" },
                { "az", "f6941505f702cf1bbbe7c3bb954da7416f8430ea493df43dc3698743b10a783234479e53a9e89d01380a0a881d5c75a249bbe18555e8f218faaa8f5a4604dbab" },
                { "be", "f67156572ba44058b5eb134ed12c2c40dac5eb6c3135ffece83a0631599e723ad789471ed9e4c7d6566726ab1837b8ca93b104410ab0d0e73d5b79c14da7e78f" },
                { "bg", "f0ff5298822a26374e0a59d86bf36ff41d9dbab90270567fa4fd96dbc2e93c688cd3a9e005bd62d0507e5a205af7ebf5ede86f49ab4c5ee896b273b9cefe4d2d" },
                { "bn", "1151f7d777a5243734ef29ea84199c584199aa94c2e1820bf4107b53108c6b4c0584704c111e002d2c09821bb55508bd5572f71fbdce1d5cd8e9a5cf42c6285b" },
                { "br", "d63438e8b1f13f9da95d1e4072eb27e116e1afff5bdf71e75db83735240d4ecd1357b0bc93bbe1b70b92bc6ad117a9f8b7569938f41432f76243b1f6704400ed" },
                { "bs", "606a11c22ed9533ce1deee799f943871e19f30bc853121050fa013ede8ad6067bee9cd0fe4fc7db1637550f5e1ce5c1443c8723deff48a1e6435919b38a2d9aa" },
                { "ca", "ed44e9efef0f2d6b370e3faa8cf6fdfa0cdfb12d5203bd5a8bea3c101962603e2aa782a5f50344a53a9d708c5b386c363220d15e6f8846325d8bcaf4d61477ce" },
                { "cak", "f68a0eca29f4de6325316065add9ed63306db286070abf318d2cad5db6fb9bbe61af90e7f2d54c1410a2bafff4ed13cdbe4351ef8e473dbea20bcfc5ecb34c39" },
                { "cs", "dbc3c7829960ded76fff6f8372e1e7c5c3a84e148725af011eab138e71a9e35f5d00733b484e98282de146026c5fee058f3b2d20a90126c931840b4dd47ac3f1" },
                { "cy", "1aae485b90cd810a5c9acea5cd7050642cd9095351e7c334b82e0843afb13fd15a95e19f92e7e4a563963146b8a55e73781fadee54d963c34210c481b6214875" },
                { "da", "8ed0c2f6af8e3b3c35c4585e1a11726e6626969603d8c4eff0b831bfb2110893b0e5dee17a37f2f80d79f876fd67ef65cb9d51106fc2c4729ea903c09df7777d" },
                { "de", "7bf71e78587474c6d198fec8b57a47e66f47efb648bdb93048c86a443eeaf373c5df1ac1ef61978310b0680a122f31e6945d5b53903d75d261ad05e75298bddf" },
                { "dsb", "7c068a86f3f5ca6bfe97b8c8d7385e4faa71ee641dba29b7298fe3b0036f165657e7fa63b46de006210447af84ec16f6d0b91a7f817b1df0d6d9cdc5ffab4087" },
                { "el", "e6d24b74ec9fffd41c1795c3d49581262047c26f72074cfa8d0b238b2c9e68cd0974978298d6fd8d8e813bfa12808ee8cf2b5d6c34b82a2b4bf5dd1c16bba8fc" },
                { "en-CA", "f37b91c9814ed7cde0ae0d87a4c5835af00f05c96923a59812a8179cbe2730ec5b3acddfa80c550d4b3c026c55a68b52722c947e514edc73131346a425fff43d" },
                { "en-GB", "14b8ef7e750fcf93075e40e3f3508efa87336461fdc495cd7794a2e0c19277f490be4a617bf499c1efdc4ae6894dc632c5baf565720989587f8f1affd8e8b499" },
                { "en-US", "9e9b907303ff7d3437a5435972eb183b2fc1c4e82391d1a22a7540e40410360cf3854bf3c98d9d9e4e55a8c5bde070df5e50707828a8545380474468bda1e463" },
                { "eo", "f3ff684611a9f40f98c76052121e24627525fb034caa817776d973706ee0db492852a6e8ca4ee48f74622c154b1c132e3f013d33496651ce5774126716f0143b" },
                { "es-AR", "20abe01eb5b9207e5b865396c862ef1864949307ef491a4ddea0dac398d3befb86ac93662c546955b0e4ab53bf2a01c632ec9b3b49f56f10f281bc1a5723d66f" },
                { "es-CL", "a6e6e893073a26cdf9e4934923fc08c8f877aee0d92268c3aa932eed87aa6c8e19fa0669fd641b1a0a60dc02a2549b4e3277dc8d0024e94a687919192012b26b" },
                { "es-ES", "3e6b916fa3f4c6c79adc7f23db05151d4b378a7e514436163b5f59692595db57a95bfdbe656c96f2b0ca70ed9e184b5470969beede6aefef71be01f2ef3bd8dc" },
                { "es-MX", "3913016f9e7232b565ba136f1e2ac5b999029dc65c5ece7b4e8c32c270fe3fb34c2779d7e8551915ed5f79d094a2165e556d9e6602cc6de0d5d89f39d60c22ac" },
                { "et", "4517737176eafa6f03371f5dddc78000e9875aea4e25e63c1df000126bd42a05f6f49e1df3113583fac8348cbb5f1b6505a606de6511bda6e5b14fa787ea6d3d" },
                { "eu", "b5f896847a99da62daa517458d51527333b0c03d99f48a8f137a1fa4d39dcb9b09715eebbe3883984eb4f1ede23d33d821004c64d6fafa2a23e03524a460767c" },
                { "fa", "b79c2eed4706bb8a0d2133c14de567e508ebeab5ab84848462f1448fb5bea79c15008400d9c43711c952eb29401c9dfaf55d3781f6ef4ec6ddc584de196d9df5" },
                { "ff", "a0c784145dfa1479bf85e58ca281e788b82af5f7b92c1fd2e2be94d8625bd0d50ba9812e66472ee473000eae7eeb88997fb91777dd7b5882771cc2946d5213b3" },
                { "fi", "ca7abdf361f082f0365029d40336d107654309cb76fcc19a57604007a692fe9e3919afaa2b459decea4a01fae74a2d21a37c2b61d40a3a008138d7ba9facd870" },
                { "fr", "aec5964b03c780a0b15758ebe1ab375fb1b6fdfe4664078a1a2441cb6b9d8f7512cbeb7d64174721525227c13b2596f907d4895c307faa7eb724e11b70d40178" },
                { "fur", "4e8679edd279b114a266aa969955ae6fbe2c27026f23c60f570a8c6ad3610b1849af194c979978bd192beb9a01a9cbb530934ae5fedde24545f10727a7ffb432" },
                { "fy-NL", "38527c6cddd1d2342fe19af4072c8169c0c3e84367ecf26bd7dff6351e923ed51ffa7dfd85d4a087f4841dbf60f897c909c01199ed5f6d59ae34f15ef8f0e2c2" },
                { "ga-IE", "499de188ea68f0875c4456b1e13dc7376451dc990424ae1dbf1dbd8485ac1b9d9983c74a8784e7c5e3acb700f367c0611553236c44482034c7a616ee53ef4269" },
                { "gd", "840a568f3778f356bf5325353fd5ace6e2094c48fef9a75788483b6537593ef51d7c37c4ee07fe7d3448ae8e30fba29624df0ee43d0ee190ec57e556c3dc4a81" },
                { "gl", "0ffae9eb6e9ead29ec9921644aa3789a54b3294a71ecc236cbd483c19a1a35c5a6e5fee82fdcc0238bbcac60429b9a0e9263f6c858acd9bdaf269b725f363c0b" },
                { "gn", "2ac8435fabf2ba5c8c0844b3277c1bbe412b033e4f15a2404c7e125764d21ed2ec136f7250fd784fff35e4837219129de80e0e29bd557d643319f0af298c3f12" },
                { "gu-IN", "9af037c9de95ed7423ccb32fe039f26191196b76f1b6723a97102f23cabadb3b948fa898975d06501fa0a4ec3d4786cc09753c5d48dd64ee802ac18a175d6e1d" },
                { "he", "5b89541e90eaeebd682f9b19f94282984e6a468e2a12a94168cdeeee832cea4329ea5a651c23716db595f4df185d439a3a56aaa9c9cc8ea7a4a07ad8066390ee" },
                { "hi-IN", "315272634914a01c0f346ebd0d1fa800bcb1072c548e2dfc3c6a3c6c02c97905378b1aff862ddb49604a06f13739ba9a0504befc76fae75c1cf78e0c0519fa3f" },
                { "hr", "d947331d57133407d3d128618a5fe3068f11a7396d9d2b474e092dbba359a48ee424eaaa183f7402a6fad13d632f7305e5678288b8a052396bb6983037ae1434" },
                { "hsb", "1430a12dbd31add60726642fa311d35d7748be2316fe12b603b229448026819b8ab6ee503e2d30f69f492928fbd126113a8e86bea6c5a3ac653818f020a418a2" },
                { "hu", "a4f182523c0e4014954231413d74b99b36ce8905b3d7e44b2868bd67f298daa9be58ba7e2d70bed9e8ecd05258a011bff8e2191f64aa7782baa81b09687cd565" },
                { "hy-AM", "20e9d90792a1155718a2d0c099b6648279f2523879cb0ce3d93dfb755a7656c4bf49af13b86029598d06f3b2875f27160c7f92dc639de30c27164b0d58dc17fa" },
                { "ia", "a1d488812822f453d93af1a2fed78de204622a99467527d0ac4802f7dd1c695fa563a8a1ef541ca28a7e7750d634f69a1835a54312ba213346bd71d8e79515d3" },
                { "id", "2a412e612cfef5cf36dd0c813341841132fa0db3372eb0c0d173d74a7eb17fe49009b32c93009f53d6e98e2e477853f726a6328c1524a143a8ecb5ce0cea3859" },
                { "is", "6eccdab125fa1f4835adcbae7c0b2d085ab072d5b763012e75c4adc70ad0ff5a6bdd9a78558f08f17a66afc7968d8071ab6e00d3727fcc1c49bf99660c705fed" },
                { "it", "749d21f75e2ad95cd9d925d2a1bf6add6b25fafe63be590929b5eccbda60bf22bcefb2990d5177f8ad5070733b94bb292991d2864e7b595675bd33c45be21294" },
                { "ja", "a4b029f35990797aeddd7efc63432829e4e3c1f4c9d514d622bb63bc39d11f7838b1ceda464f58cd1f1643a032de956fb81f3d0cf5889c421f4292e73a7d18a1" },
                { "ka", "082c011e1a7695e9cb167e30432344890140e3b514abf94968bb44f73ba69c962587fde575884f4c12c7595691f1bce5bfbf90dac93925dd127ae3e85bbc2f35" },
                { "kab", "b126b9cd8c779d9faae70bf6c4056d6137713534f168c2a284d61a91360e04f4a5a453ca146b21b2cebe18753eda212a7924920c1d015d4fb34c7be1ba2c666b" },
                { "kk", "5f0789ac6e51b656758964408b4c73ba3452210573d61b926a38f1d1db327c2c042bdddddd6eadc760198ac51a5cfbc197982268bd2f7ca81979c7269746e99f" },
                { "km", "75f37247ab44f0f0d642751d5b907fc1d0b536713bf53bdd435ced9c112d9fc58f499e650c20851395a63a0a2ba5d4f2561ff1452c7983b7ac6c097326a49300" },
                { "kn", "58ccb8aed91aea7a8e2bbfb28c364805cb9f1e99d17949b907546259a07edb302823acbb244c5eb21cc97da9683073f87a38cdca075650a7b7f30ea9bf9900f1" },
                { "ko", "29611ed059733f78562d435fdb60d7feed4e05a8ac8791c66e62bfa82c24be42c24208ff24c3fdc8d217f1f1168d44ed2b55f53a667f4ecf963fe119520b2cc5" },
                { "lij", "daac0ead3245e947c72943c2a4e047b9b2c8f85489cc93a7f93298e1e38854f2c591231a866dbd15c4c25c28d3d812795530b9113659c3c6908538d8481316a4" },
                { "lt", "3c8e5ebd1b5584784252438ed327ac5f4b46eac1063b7ccce3146a970176cd408d38d7d5ebe08e508b240f041285173c3905f6a178184d2980c10403ab2c02cb" },
                { "lv", "c0453d06f9dd85933f1aebce64b82ddaf50d5bf5b478767aa29dd9cb3ee040520143bd8329122fe4a11a6bed7565b8858949a7238c6a13ed47ef30e64a4c09a1" },
                { "mk", "c34ed25723c41ac852990a874fb32b9bf843a18a5fb6bfddf57df3eae75e6531a5b62431284edaa37b842a72853470a9873f38e8003a87ae8d4a4a3e921c0a71" },
                { "mr", "10ecdebd6f364cfd39be48e86f33143efcf36298f1ca66b7e830e4579db3f0ce0c08331257212856de1a21444fe319dcfbeb7040873e8d45e5c4c4713c54ddd8" },
                { "ms", "24ce3dd9c54050c7590e8561282a19a4563a77456bd38eff95dfeff5c66957fd035846c9fe0a5ffd14a38f93a23bb2da354821c7c31953737e950a37add8027a" },
                { "my", "ce37a63b956a28b4d3a51eabd3430bebe361809f990326e628d58349f595d69ca86b522228126c77694cfa1101f1da510bfb626a89a178935c4b35b91dc011b8" },
                { "nb-NO", "67a2ce1f90aac58d67919a520d57a58bb984564bdba13357d35d8eb2f31dec4cf5c55112a17e73687ccb29a0d0c5cf76e53304762c2909f2ff963aed743fcfa3" },
                { "ne-NP", "d8d1c8ef6d83043ceedd0beda0141f608c18923024c378eb00bfab08d414e3d11f6691bcee5433a11f61ec89c26ea97a3e69225d6b0c7b24c7e7cd616e534af3" },
                { "nl", "1df4f7d14b1ccc65a1117e8806ed3bad619680a3ad2777e2e8f9ca7985f627c4f84bc6f669e8ff327fcb0893675ab75e22eba5955398cabdb9dceb1a9a79dd28" },
                { "nn-NO", "8db98d2380ac9b67a60179eb5e55d67b90acba67cb76ccd64333fffcc0241e49c8349cd386e53cd7c97586a4c87b51017e936a0b60814270533330c9936401aa" },
                { "oc", "ca6b859f04da5d2ff6bf1685c11d4ff2db0f3e67a878d6038dbc447b691b6ae0f39565a204b267b805c7c9baddb18fc91c33e28f76ad640ade40090ba5415898" },
                { "pa-IN", "6fa61d97be5da595aeb3fbb7a201f0c05912644f49b92f053b18a677f5fa253c91199ec3ad11e2e604d4d0ec7c7e276ff521740d1d82dd123cf29292089f29d2" },
                { "pl", "f78a941b85ac546c80392b5bb16784251cf815c2d437ec6e55d98727ab60f47ac381b81025c77cc036f96ac6ed1d23dcad3a82e3b1abd44ae0131bb0a1312d07" },
                { "pt-BR", "3256fb3c85d411a877c2abe75abd706fdca647d92ac217fe28aabf6f2b64a0a8eb2fb98764ecc634ac9ba0bc0ef16fd7e7172e80a691bfcf77117f41466229a5" },
                { "pt-PT", "bc8753d4a7dc9f40ad2752bccbea04e52c1082a6bb8f76e0e12d468b81adbf54a4b0af3d6e5e850c02f28e08c1cdfeb5158ac740575b3d62385d2ddaa896179a" },
                { "rm", "06d9d1ed29b4c3911bbc10f938aab40ceaccb647c7c66c8d8adb873637536dec92755c7499e70e5d53966a97665b393b9b97bacbf7a97d9e324ce85c9efd3e40" },
                { "ro", "c92cac37aecabd0d91437c36d9b0e785f28fae2f4c420c8d1bcd919cfbceaa5e4a0887ccb9511c1750043d07a3f0dcea25796ae05327d5f04bdcc7b6214520cd" },
                { "ru", "ce6d8c8438f6124b153cf17dc46b5e2f1683f7645078968b57a66aa732f566017cfd64cc4bd8644a30010de10033aa0f6d8213a4b9b3bbb3d37aca5bad93f985" },
                { "sat", "a62b79ca93ac1e13cd66ad6c77cc63d041e7857a1f42f892071840f998c66bcc92f5cb4bc067d866fe59b3cdc9b8c533110e54f0fd755f1dffff9fddd51e43fc" },
                { "sc", "4e645724304bac63e068e7ff64d40af37826c7aeef798657af7514a32866653bcd8187677e971ed68ec3c7aa5cc45ddcd0fdc5c550b79dd4efcc8ef8498e4559" },
                { "sco", "d21ea61ca8dc3c666eee70b6b74ca7a4bedffc66459cb4ec6bc5f57878c9a94b6f99cd0211f7e3b43e6aa6ac331dbd534cc0423cab3e12316820a3a3bfb13953" },
                { "si", "7ea29f503b162a1c9d59cda62922e085d5cfe992a7105e638d789b03d966b622fa769bb22956c92d3358a1fd49fe7a2794adb2cbbe906a49de473a7285ca9bcc" },
                { "sk", "ddba8947d393b691f15f0c198f8745c9a72373cd622426426029002bdb3bd6a26d5bf66a8acd64ff0f4ccce120e4838628f58c96edd6d2761e93bf496eb5615d" },
                { "skr", "74e6b7926abfc4f99b4eb9803796bccdd32ad34f38f1c87b0038f366e02fe3d7992d488d484dec5ec318062f7fb6c51d5ebfb20c3602d36697530e381d47fb7f" },
                { "sl", "98727d75e8c9b9d8e3ef9707e23916d87d99d7b39a98ab319fb6f53cd727549e892a9ed033f557792e90b5229cc61a64b810d6c03981b5f70586e88b51e1aa36" },
                { "son", "d8fecad92e0941506827184c685c42dd120426266ef0d0ec943a63ed6c95d074e209871a832b1f183686ceb8b081478630a8f0ae1bf4c8b9089d1778d4da2a5c" },
                { "sq", "7486750bf7ef56f8e89ce7793f8cbbd9f3303f7adee2c9fa991c92e23944ef4c59aa4785f3c631937d889de4ecbfb94e2e54414526ecfe81929d39641c08e204" },
                { "sr", "a90e5713ad0ac4c762b3a84b56edd78e851ca08703d9bd72879b14c0c1d73e027fc0accac182d4adfb42f3460cc0099631df135b4ccb3a03259fc166d9453056" },
                { "sv-SE", "ed916c1988620fa5c25c0e5577224f0c2cffc3210cfac65a8870f8c5d5f9a183bde0ba9443054d131d6f71e78ec2bdf9103ca09209a51673f48079cbed12a2e0" },
                { "szl", "3a792129f0c2e915ca64a4b0ca70685191a5b21c4b10d6bf3d7d50d4c3898ae620b4c25290a63a70f14ef649038c4d9a5d25c66a3a52d18e609d2a6d98525301" },
                { "ta", "0391959e3a0e7dc95f6036cd9dc8094cf7271579368cd3afc661b1f0d94ee68572791115d12a35076b7a37a6aafad0a74c1a91b98668079603a6f52908076195" },
                { "te", "b6ef0a621d0f7986bd074ed984ed8512d1b52360a5e4a95b2407fabdb6c79beebf7f75e8e2d4fcb740e458cd8bf63fc529b51069226c2ef02b9bb07900679d56" },
                { "tg", "fe36432f2cca8c3c7ff13992a2a977f0a3e485a60c0cf6a2f310418b9741e0760a13ee4d182c1dc07e65e0fa71b11e48a02ef95b24187d57f9d059beed94bdd2" },
                { "th", "66431e9e2b840350f746de790029c8cb2e91628fb3f883db01a88f42b3574b589d36a706a44471f8180c68e6cbf6a189fdf4864022a855cd284c81462d76c9d4" },
                { "tl", "2ed6beb4e679c1b9e71bcdab5452b0ddd1bcd99b763cb216d351c381eea838953843a678059a16d8b51d0ccae38801bae3f7f6ce43aa8bcc3803795e7a39a4c2" },
                { "tr", "7d41d6735840e594beb6912e1847763d04d5435e368a0dcdce314eb2cb415e14acb774abf31db88fb6fb26fc1ba3066a1f434cd5c2164696f34240eff64cb5f1" },
                { "trs", "6f579cc1f99f51edfd4d04c629f4bcacbbfc573860cedd0ec3dc7e28453ef3fb003d6784ca7f8cdd68de7a37cda176ce678c3eaa128ebf739a765143ba2a4f5c" },
                { "uk", "2acf35bd48b6ae09321f700538939bb09c416f8291d5f99df79488991bae28852788d2aebd8da03b7301ac5a00e882adea987a893dc009042e4a058f0080ac96" },
                { "ur", "5b39cb7e9ad50e27fa30b3d9e9da7987bbe830be8d2c8877f68601e2e2658b585a9029e26e73fe7d5e01503448089742ecf146607cfb835b0cebb9b147786521" },
                { "uz", "9d294c1316471341d52d6f630618276b51d348e00007a41cae7a7498a27f55c77847c8f6332118e3121b17952abab6429fbb94b80d525bb14539d675d6afd1b6" },
                { "vi", "e28a768bc2d723316d74480b2d4a551a0b677e06ae08faf56b9544e8e8630b511579ca69681c05e0d13b3e08c29002a9ac8d4866e3796228561c660b557ebd71" },
                { "xh", "dcb2c16b3937e288f944484543f5f2d2ac90d5bbe193be0c26dd42cdf42be71aa64b52cc201718681562deb9a2598b86b63cb154b12498b06a97bff9d7e42459" },
                { "zh-CN", "1f595b0dff01c18040bead5ca6a8424545765e985fb5a27eb61b1968e24419f860e53599f6a2b0cc10990c1b25054b27389ef34d06f080e7323def09f10b4c63" },
                { "zh-TW", "97e134b3b385ef870eef77edcbd8f2b887ab0c0913d9782c4129747c149800d81516ebfd662efdbd37591bfe7054e68869320e74a74c381805e94975b3f8cc2f" }
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return [cs32[languageCode], cs64[languageCode]];
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
