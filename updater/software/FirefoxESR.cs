/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.8.1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.8.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "bc3f533b01aae600ffce5d749395ca1caef3ca699536d74adb6908d363387be973de09fe263a9aae871208c45682cc653202512985bf548991a398932bf205dc" },
                { "af", "4fe1e0198e2dd023eda9aed607b20a76446fc3222f04caa433e43d521011f2ee71851124d3c1cc9831e732728a98410b0bfb90bd34e5994d9e14e935f1799a9e" },
                { "an", "ad15d9ce4b3e432fb1777f4e1dd33a8db384870766cefa7e1c2c7e0c54c27162683674dd0bfb5b04255bfd4ed62aaad5b6babe66b11e63a13bf708b18fd6f82b" },
                { "ar", "d488cedf3e95298d4c176bbc01a4a8806a48591a385c3bef029b89711484d728415c79c8656cc878c96740c294bdf81801f2afbc47dfc070941561ead4b269b1" },
                { "ast", "21b5e8ae216d8abb6dd998fb0df3392a8b96afc79792a350e66d2306a13bf1ae0bf1498037038348fabf6995804c5c96d53dd3729e646255395a8e0a49e0ac36" },
                { "az", "a8bed20ce919f3e8ebba37d075251d57d973d0d8cddcedb7a57534da6350cddf9092cf9e43c58377ed9aa6065c31c77132b969a28df9670d4af9c00788166005" },
                { "be", "b16c814191394e65d49d25fa44c8571b5d6157e64981708ed4f42224f2c67a14482d518bb2fa100a6e02d57cc349d55bcf4f055a03c117fedcdc185dff65e316" },
                { "bg", "f62b2f13f9ddc9d0cd4d2bc0121595d4722dcdcb65658088b5c9eff968905ea6b089c6980c96c4b2656f9640f62aecb6b7d064dd06d07359b60c1e873b2fed29" },
                { "bn", "7d3b6678d2dd0c6b9d38a35ba08435fd2d7ea7aad8ec695a9481250a86b3e39b53b3784275a36b996ebc15805dada1a21ca7bfa0c027e8f61a80a95afac5ab94" },
                { "br", "fb48023fa40479dfd4b94f0a02d362bee93a877e64b7766886e5d5904679960b0f81d325ce8546dbc94c527514cc96e6183da7250a98bc5b6f74f86c8d387cae" },
                { "bs", "5494254b1abaee911853c3134b40666ccd0caad10fea66f065cf9c4eb9a63363d57ed35009ce041b7c96fd24c1381b234acb65354bfadbfa2be43b5fb546807c" },
                { "ca", "b9109a9671691330419c691eca6a6fcb63c72c52f0a916a8ca9dc0eaac61a2bc2e8b0ecf98d22f597a48a2f4f5760fb5ec6ac1e3e0928fc182520ef162798409" },
                { "cak", "35f02518dd9975e0361355852bbcd04f1ba95a31319586040da49dc828d4c5a53fd145a74a6e4d8a33c5cb62259a53acfd598ac478bfa0d4917fa38b726efcbe" },
                { "cs", "f4bc57c348d6272a11f6ff4ab2115f1b0eface4be2041e2ebd8c378c3f1826a73358f69a11d111e56ce2da267eaccc1c4de77133369510135033fb69372d4fb4" },
                { "cy", "ea4ba7430ee73f0fbac755e28c9540603e52ce924488efa14d81e06137cb1bea50f4de19d21dbadc359a55ad3ce92959b9e79cf35ad742d0d80e1161a823a99c" },
                { "da", "5431c4ceb2101924fc1da916fda801fa205997df45e0e4d30aba44cad5a961c8f070d31a8ca4e76b5b7bcecfa0b2756b590190a3be707b9c0fadd696f0330d51" },
                { "de", "bd42a883f23fdfc25f5a51a5ebc860cd2fb64d359a59027cf210c6aa767ec2d9771b698e80bf3ec6c50ab326a0e21a84fc782e580e89051d5b3c6db0dc018f0c" },
                { "dsb", "b20bc2ff5e5ae8f817ec6ec758a6b6b63e80651b4184b46f18989c8ab3f2a0ac04b60dd943d7024ff4b5c77f47c5ba69e0b2e956446c7d676982758d5dfcc810" },
                { "el", "85abae82a2ab0417dc0cd48ced6c33f84bcc97831bc3e64e258d08de2ceac771cb6bd5250d7807ffe6e4a360f0c39e67f15847e5f4f4cb8d5a0d5f7d214f3b7b" },
                { "en-CA", "52fa83bec7f1467c53f7b90ad22cae2c7aafe52fc12b51c5473ed2d8478cffcc3e9dfb746e9361fea2c646e4b2933e6bc96ed97786db30eeb808df66693d4871" },
                { "en-GB", "99797753597e2be282be1126bdd4cae61c4c7f75d97766de1abae18aae320101036ef1c94ac0bed2399444e904ba2b804eaa9a2e90b94b507ca667a33fcb681d" },
                { "en-US", "e136e409613521bd0fca10435d1ab916d27a44d1b372ab39958fd2030e2f873c52f3f44a94b04d5e0db3869946757a420b44fa61addb1b2e0c30d05b9b8a1b95" },
                { "eo", "fb3796577a44024e5a816c29e81205b8a5ebd739af7bd5dd7f2e844a6d32f468f5dad1f7525114866566f7f69fa25e3be03ab2e6c60a5d5dd1d060865cb9df90" },
                { "es-AR", "967aefcc13883a8fa9630e77271cc20cff06806f1ac3df964b61e8b1f9b12f06374427b81fe2244bda6537a16e78a389fadca720f1f4781fc2696d6a483fc8e2" },
                { "es-CL", "7e4a8cb0f7c82a849c0d691b452b3248e45f2cb841e46b88ebc08a87baa854030cf00c93ccf7ca20c63af83d0708f3540e2c4d94781bf72e9caeec21a40fba29" },
                { "es-ES", "a9ea8540a79dbc359b3ac9c495afff89ef2890b6277ec8a7df28702232d072176428046eaed45a69a36d402d917d1f3156a87aad315bb966b53d91aaa1e31840" },
                { "es-MX", "bfbc1138f2accfb78d5ed0eba30684566049531037a509bbc49f40b3364e7f1ecf90e285e861a5c6319ebb10c8c55188139d18a5384ec8f083aa112adb4819c3" },
                { "et", "f7a49e342c79892e6def540c3c49ac81fbb25feabd1d5ce41668f59188d2717bb3f49842297649f1bc803a054b45c447a2ccaed964a55c746801d1327f4d0288" },
                { "eu", "294e782a5f05aad9017735b291bd87af4dcd06f3e96fe9516ad717d67444826a6c790b04b18338f31c882bc8d929ccb46f056a34aa0c207d6232b9794e172907" },
                { "fa", "8c885c9da2572ad58b23144726143f69548935412829bb68f46bcbf5a6d89d488fe8aac8ee368e98e6a2f35f06624cddbed29d0577392d6a56527fd93eefd892" },
                { "ff", "733f459fd4f479d9d40d67608f52dbc2d9851b54a7e0d262abf43cd4594f7624aaf81f61aec316b88275d5da77051c8e6e967d5a551e50b0f2ad6d407e3ebb0c" },
                { "fi", "a2cd0f520f12ed98e7c8769b43ed3119bac1edcf6a049163b0410845bad770467935df6c786c0ccbe19e09166a6488026bbc940b99c2017fa4531015d7069252" },
                { "fr", "5400ea1f3a1df685353ace3858dec4c03b67e2c4ab0181c7962cb43443ec35da0592344db9e94652d42302c773c7fa4f382f3843754e2617b4f89afdf9c22764" },
                { "fur", "571eb44ff79f896f19c13bd4d85e3e07d1e281d97853366078138b9408f22b75580d8d066b0efdbd190944a22bfb9765cfc37a6faeedf205127588e8bdf2d6d7" },
                { "fy-NL", "ccd72d36c1851402b5d883335bcc49e7b740c23d33a0f65423060dbaca9e30b2b709585100fc206b8bf709ef0eab9a1a1506ce33168b1e98220bd9f7af188e66" },
                { "ga-IE", "9c0ff05a83efeb366be26288686941c1bacc57bf9da27925e668c5468428c2692e711d1bb14dfe9a45fc54334d482e6ecba8c7977f171ddcc77cc8ab31bd7edc" },
                { "gd", "9713413255d25f2094f3e537e561f1674a1b784c1ec706db98a4374bd05e9fcbd997ab6b33a7672a2574a0a8a2575e775aac0f65e0fa506e5b8beea24ed142fe" },
                { "gl", "784d14dea69eeeddbbeede9827b10b1923d3a230a483b3744836ee7021688a5dded2feb0bd7ac2791784026d23d238da72a353ee2e6cc8e812ff0a8326614ad4" },
                { "gn", "efc98a29af9452f7ca5df8a167ed03207b30cc03516a4dddfb2a39fd538353f946de41106713b01d448a81276d2ce089984f05090a9d50a1a5b15b89c7d32483" },
                { "gu-IN", "0595cb3096145d90771b84b2193337865c316f01bf5df5c9bf5a90b6d12b92379ec5286321c292e7e18fa166915032badb889337765f11ffad41c47cc1150330" },
                { "he", "3a29ad0d180ca144b0905bb414da78d4ebba291c966b34911b2f37620d068f7664ad22551b3c0082ab8aa304890a18b041b73913568af15ada3020701384f6be" },
                { "hi-IN", "19603f511ea59a3e198e02429f61aecc51c17cf7a2b7390633419cc77f2282c1ccab8e04af2240ace3d36d3ccbf6166fda38c3894864f4b3583c9e47843e8a15" },
                { "hr", "96898094630035e339229826efa848d505f751fd4c649767bf73d32cfb6626c0ee932ed0fb3dccf91c05a5df580aa8b9909b9196bc76c9347094934582dc2b67" },
                { "hsb", "7992d9fcd1de320b1c75044e655ee08a4822665ba22a4dc27d217595d934de671f975676686cb430c4456d5a1ae5f052bd742d316c459192c3b2911672a4eea4" },
                { "hu", "43afc26c132beb62f88b50f736bc69c1f423b681647061287de287d30a41720334e15812d32096ce983fbba6e0c7d8ea2018547f87a045608a7771b01664185c" },
                { "hy-AM", "91ea56ca544da0e2546aea9051460bf9438404184ab1bbc22784829014df6c42f43af920d23685bdca2d23c566148f0dfd910e7ae536b324fb474baa85105a7a" },
                { "ia", "5058558e63202aba4d24e1b78016e056059438a6e5844cc29320c0bc721d3a0c2b700bc52f66d74f76d6af765107a454df4057c7996b0af93a0012c370faee3f" },
                { "id", "f900f35fad9d1bcad44934c5ea968f0b7c355bf263a512f7c75bf458b5e6390e15253c70955419187086545e3369587e432305b9e8d2732017c6b0d1d8376855" },
                { "is", "8ddfbe24bc223068aef2cdfeae172f69b1c2a89d3f5d8830b2c2082a8fbc3e2064bb4d4a3d3aa4590620001c8eaadb7b7c6086f3f62f528488daa5a5f5aa50ff" },
                { "it", "2da57010acdba90ae1f60d66a406b937f1d0d830e22a8eee9a769f902c3ccdd23f2c77334cd8424a092507532314a56188c8763440aa5c2206a013066efc3cb0" },
                { "ja", "a2aa82fab684ee3aa9afbe6732e6153ca24afdce72b641fd358f1b2e0ccae408a8a20634c35e3a50119bc614c8c22e85854805d57acf4d8eff4bd3ae02a9b898" },
                { "ka", "0e99b11feeb16dcc430932ed237a675ee63ef89fb2966826876ff1b1229002219dddcea487eac463edc218726ee144371c2497a21928dc0456c2f78d71d92e8e" },
                { "kab", "74925b58617fa229777977f1ea9de80e6240646baf9f3070ffe0d420f007241f466331abeafe9a96235f466c4f830edb246df0af7b3b5b68801789136cad3488" },
                { "kk", "f643992580d96823f8ac59c495fa7be4e43bad67a794ee8f1d31637f9b97ac4cf49e6edbfc5d4431ac8920ca2122c3a1f609b51de42c81e4e7dc1866fb216291" },
                { "km", "ff8c0815c0ccb61f0fbd2c48db5744e0dc270bc964b55715cd2219c5d6932635a8b86521e84893698cdb58de1ab1485381765bec29a90e15f263b721c0416c2d" },
                { "kn", "a5e3dc89bf28f63d3bf7b518b4a9e537c5ad74aa1ea47af7107128e952430da24e6b9e35c13c21eef6a2f8510b746b1af7ad06ede962258a8b97c188d4013c17" },
                { "ko", "9417f116f66efd20ffe79154a98f7013bb5069111009cc1f05e70e6f747d1222591a0e717563256527556014a2e7015bb34daca4a92f2f6c8100e7bebae473c4" },
                { "lij", "205c5f756ee06953d90495c76d6fb5890058fd32c8509b2f22cbd3ff1d7feb2331ab73be978f082f7581684000ce667da83636a7f8e9ac6a2ea8e5f87c94b522" },
                { "lt", "74aba3dcddc4192793b5d1fb164fd989c8370d0a3d88538881eccc708a083eecf547154af7970bd1a91da73ead2fa8e50fe4e2585080627164de315cd2ecb41e" },
                { "lv", "1a7996a655868a3fe9b99b1d7b333de386738ba62a2414e3ffb096b502304d7f825981f77376e726b4f84204503a03155be8adbfc06f5542b1f712d9ddbf48b3" },
                { "mk", "8e2c516e328c05c8f6f2013dc5b62183854a2cd219dfc4dea610e20d120170f647816864df4b6fadf0cfbe4f1f7d73ceedea44649fe443e17f6200714022c543" },
                { "mr", "a44982d5b19aae460b442f7bddec00278dea2ac1550485c3b12037da1cdac43e01a1349dc160cb44b72caae97f6789cdd51e7d53d49821f4da584dd11029d209" },
                { "ms", "990c27f1071d2a32b468da4e2f558a3ab016655186f47792e1b964c14f6674ac2abecba97995fea03b49f22325844fb6c9cf1e26052160eb6a6689f1d1e27d5e" },
                { "my", "bf8783ad9d5834eea4127bfabaa9584f49a527ec6d387fc1588165d847f18b597af3abf847585755e2dcd07c7ab42093f5b432fae9f8ff747bc11f3f78517048" },
                { "nb-NO", "61d67c0696a2cfbc7f6ba9c9d594dc7b5f92b30f4aff1fbb32092806e272cbc59f225c338b694044a18ec463daf67074c1716dd939a2bc7a6b6932b0e94a68ba" },
                { "ne-NP", "ab59d3ab2d930214895d6a7575c3316d825434a01705dc37a53e375da17704b1f28555d190ab9968df68921d5ae161e2d5a1b1cd846b7d7275b8551d0b02d2a7" },
                { "nl", "670d0cc5ad390b148a9e22b205625a81cbcd15d20143dbd9b2c527ec9e9ff4957ec59318dbf831950d67de69c2a3eb14437767b3b887b0633b4c80e50a7afe9e" },
                { "nn-NO", "cd3e4707c8d2ecba049f0c81743ebab251e767e3beeecd9d3b1b3b3da1b61047ba0898b57b2b2a07c8f98b125fe971b767741d12ff5571920d58beea0dcad3f4" },
                { "oc", "0dcfc52326faebff50f1296f601967178f5ac4e9d10f6d00c45565c21d38023bfa87707258a9f84220b0ddd85e81fe8f7a132bf817acf3d8149a78be80d33464" },
                { "pa-IN", "963a34f830f68442dbe14ca3f54f70155e911112d76ae29f14d2e37bdac414172f77c020916e1597113563c579efa16bc86b1f3aa742681caad9329d00b11a25" },
                { "pl", "7c496cbf616d9331a3be71e61237ed3b93d08f04a8735c123e6d8c53b6f0e15487d9e207b690b564eca0a8d2b11d02287c82314e27012cd626cacfa94f223240" },
                { "pt-BR", "4acde2f237e2194e6605ac962fbcb39ece2f8dff94c52c33df845a5cdef659c63d03f2ebebc553d1a2e7ba515357d96579ac2e8db11e973305d4ef05588b940b" },
                { "pt-PT", "21107c251024045f6be121dac0838fea461035236eef1e92eb1e58d0e146adf944810c63ccc3e51f75cdcf93827427c158f4d4ea39fa5349a30b907c9b5ab5b2" },
                { "rm", "87e6dbffbff66c01490463ae1eee5a1201986c99714ed216de8183a202ef91e4c768e324e64dc08b97ec91d339227a851e6dd425a1544a1b0932a1cac42c84cb" },
                { "ro", "133df6d3d0e47b2ebee1c7d9c5c86e7d24f51a2f02acfc6438e641215cf423aa4d906576d720f6937e0b6697b3315b5968af25d056372f384cd5194d7a728fd6" },
                { "ru", "2acf3fef290cc0c49f3e587712b01bde78b7cd395751d1366cfaa637d0d47c5f88bd2b269173322c91986e39ead8311037f8ca3e4c9705efde06a01554b89ad2" },
                { "sat", "fdf12f4fa102f46058a4a2ec597c231f4a1b806a10b00f636481cc24240f2055fd371d9876d51d1c1d809fbf6b113039b09dda0de40e4e92038c0a49257b531c" },
                { "sc", "31cf2bb6151cd489ca9fe674a0fbebeaa18d4cef91a1f1c5c0865abb92d6fe07d7f3c4775ff18f443421368e6eaa51d6f15d014d03a26d3b1aa21572cde2d3d0" },
                { "sco", "2b3a4a3c7be29edd1d1e10b15df76c753c0692e9a3f1431bb58f615f2701286f4b7f8135149ea70716ece5d3e63703b08167cfb92c9ebca23b732aa4968435ee" },
                { "si", "64717dba90ada16b7c250c57c8e30488a1a3a9e8da2d4da4d5930b9d07746ec690d5151b0c235a39a8c27f0131a3e619c1921a51639773898c8a475e21b6a39d" },
                { "sk", "ec4da83c6fdca55c072f1452904c974b8b0751728009c60e08b122c7eb2f1c3d154a89ec2b08cc153638b08bd4bd57f2a3039bc1a02a13e5ca2fd2887e2c6925" },
                { "skr", "6d522b4bc90289c9a67eea09bbb81132a0203ee8ae4a99f844f220560a9fac75f3f1eebb26dcb4d9a437adaaa5a12952096036291434f0b774f4c99360fe5fe3" },
                { "sl", "0bde8e2d03b5a7ee0ba70b8ba06a18b13efcb782795f5c99394965de4e4f45e76db5e479dc430215c018fae074ea40dd2d1c1f4a5f2fa5b48a604bdbd012ed37" },
                { "son", "b102f28cb972361b23eaa58c989a2388656018798f53bfb1a81372cebac6e4bfff48f2ee394411f9542d1f880c7b80c67be30d96d6d6b815a207cd5988475588" },
                { "sq", "b6795911485be57dc0d3af466421f930d18a11aa78c0310cec83595bfbce53172816824e1dd61f33e680efdc811b6998182c826454390d9e6eaae0b54ac673f7" },
                { "sr", "5543a344388609bead76c2c2f4750bbee721750ce5c0b136efb67a9029e4f2b409eb3a18f629a6709bdc6783a16ee79721bfc66cbe8fa2e312a305180a7f1d7f" },
                { "sv-SE", "aefbc4ac30876f447262f2fa0054f92092f4a063e88b2d4d3349bb429a2792956740e5651e88d97a995450c4f423dde79791bcc729fed47d2987e8b9896d86e8" },
                { "szl", "497c0e205086ab1191da894754a32e8d506247aabad20701d2d5a9fef5b2f3255222d3db1c5c562c36540186e974b1fd9c0632d0360117c44ba74146e61945cb" },
                { "ta", "3bf79032f7e260503e7185fe56e2bbecdf2a591594ecd3a63c02757fa658a3e22a3838868cbac74d3e3ba20e3770ccbfc2d60cebb928fe23e16e22e221eaa0e0" },
                { "te", "d3577030f969e7e8363ee81a30b87406e13ccf6d4bbb9d2525ac38a814862019c0afd7cbb8abbf6c19143ba1be2e55e20575debf49b50d67d465cb03c771584c" },
                { "tg", "c95f35677793cf83f024796df1db8c88121b8b663a88c0aa61712f83697ce06da9fc6163b76e65c5db76a142eed556d8238d284906c93ccea379f95596534527" },
                { "th", "2fcb60eeaa650d7b5e52eac83892b0f5e2189e70f7ca4eb5f7330aefebb8247c91e0ea6c86ed2b39a62ae70238e4b353bcc8e9cef3b48d33e54defc77ffd7559" },
                { "tl", "9658c04e20686630113590c2a46040b031d676b3482ce0bd6dcd9c6943c3cf95e2cd2f2a3983b72eb33d31e4d14118cae566e4a33dd5286b64944ea02ebcca50" },
                { "tr", "7b28d10a8e636b3f7e9a2f6aaf8284e63d5c6e824caa8d56e0bcc671c3074f7ecaee57c59e2b0190d0aed49c3e4a611989649a8a3547b7d0c28498c392399118" },
                { "trs", "59269281bb2ca9fee8f47ee0194f7f9d35f2d90a90b8e3dbc2835c0fe50d3998e22bf678b36ac9c5aa86c1f5a9dc867c59fc2932f22286e3e69b20c29b345cc4" },
                { "uk", "ad4ae4e8ad0bebcf1ea0ed3f981a5aaef7752187808519d3c8d97b883a899df41ba2812318341d626c0fed4fb0061d83e17a05d60f6a8af636cfdce743771ce7" },
                { "ur", "ff7294b75f3837862f26655365a03f153b37ec3b829ed0e7f45080f899ec27e5c4f261a470d894e49a65dcb073566551dfa89d0dc2f14f69d33e73c59eb774d0" },
                { "uz", "c93cdddf4050b3e640fdd58c45b5281bfc71aa3924e0348b17d4190290d8617526b38f32439cec6d47f9b46bed152479407a85dc3553a838a57da6c99e30d9d9" },
                { "vi", "c7817f7cc4e4d9e1a96b7bed8431b248ad18da5d5d60bd6ed7aff2b06f95941993ffa4e20754ba0f119ec8e925405cec0776399b4dcb20f03d3f4eb9c64bfef0" },
                { "xh", "7fea87a4f37e6be7ab0b62aa2d3ed80aab995c0dd643e5ff565540376857f9b80c4e574c250b037b957015bfe6d992fcf661446113aac8542077a3e757e6d235" },
                { "zh-CN", "f785ae7fa6acad0490c77236aef7d0a8c3a4583b4b9d807431c3f22fa1d7b3705d93cf2423a9529a3f5fbac8c984656f12c862f5d1a02d02312b6c06b0a60563" },
                { "zh-TW", "e70743b207a932b490f50d4e549307dee9651cadd5ceae2297d79a4ca0772eaa4eacbdcaec66154d65ace18cace9e0bafda0356f51131124bfb9fcb70979e687" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.8.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "57c795484c5fffe2f764533596d6b58019d8cce8953177f137a9e7e4e691bfb426ebec083a7f2777ddb2bdabd09c3aac53b70cd571bf14e0336025ac022d17e1" },
                { "af", "4a931e962c2538e9cd03a72a231c03b7452f728de0450ce828faf11d3e61b2cb8305f1d491d2d2c452dd3d1911f40827021f0ebaddd94724a21a9d1131bc1cda" },
                { "an", "f6abbd25e9361a234ee9118d4b6747a5ea5c5ff1c2476209570aaba3a565711ccea3ef3fe68edfb52b65b4c3f2bce5545239e2eef37db9d7cbc18d9fdcdea3dc" },
                { "ar", "110d4d33bf6ac235b6594ca9cbdfafb14171e0dc5ba7915bfc9c0a601c76e7bdf8d987689e300a32855a7c7060dd7dc1863e2f353f7e7641ff1262151e85d104" },
                { "ast", "f2b5dae26e600ea4be944f4fe8d830bf1498ce1109bf39cd727475999b2ac88dc66c2d0015ff7ad69c476e17dc595e313c6a8ed10da788411350884324ac4dd8" },
                { "az", "8b5804779339b8b62d3fbcb1c8dc0b07551b8d27e0163d3f90d44ddca9cebe98960e3bea5e7d4bd296c2f632ffbd8245dab8c00a5815f38f545f59ccb6b02514" },
                { "be", "0ecb5af836afcc9d636e115117114405e46fb42b226788a48dced6ec8924758ee3107f2a37e18ff6af25e066fd13a0cc27d0afbc4c2fa6b672b909a14397542d" },
                { "bg", "f747a01b2a388ec878788de836abc79d67e38433f93c65afcd592c436348d9c9d94bfc52a02c7e13c7cf9f42569224d61c93b0f4ae5afb6705c43db48effdaae" },
                { "bn", "428295a0d2b290e59eec29d247b0890cc4f0866b02fd1db09f5b068674e904537b3c365c722f6020563c3a6c499a1808a84e1f03fadfc298fd8511c4a1db0078" },
                { "br", "c6ff344223eebf083568c4e757834b502dba8eb9287948e6c921b447c59960c8dc083bf3b2a5829d52c6c5ea2b53eb0d3d29ad84b3f58b785bf575acf8b6fd45" },
                { "bs", "53539d4c0c116191e7bb0d29f41644907ae0d01bfc9d55e58243c1776b6aa28e9165f15fa00462cfdfd09ae6ac2378224368d8fdf40f8f56262e2d237456b24e" },
                { "ca", "a985ffec791c1eb021f293a21ef643940020cfb8d24d2ec3f7ae2c720569485912fb3d1254dab64cd7278ac088131b4f66601f7daaadc30d7c16b7bcc16f27a2" },
                { "cak", "4af7ff2be9d10eb404ec41721ff1fc4d066978f4abf45afe5e97b80794e6a7ad106bb479c1e244c179788bd6aefd76d71ff19f057525e44e21d4620d56e122ef" },
                { "cs", "872bef617a3f87d0203604c46612557594588897928d6415f9bc8f9c02aca6fa487724c17ef1c62792e3a832d4bc3c6b093cd71b294c3ef20ee57a2a240ecf04" },
                { "cy", "81ae6bfe62dd1374f752a690518885b07a2629c8e0955bc529b3ea0905034c615d68c26d3378172ff7f7dd185e623d3cfce4277239d23788a562a3a1df3726e5" },
                { "da", "a08ab1fabec83f644c2e117d48a153c883c3ff4d3021a4b0916917c86fcea7a5c9490a4dcc5f592db140435c9ff3290eab11743dfe4e3e76abf77586c6c47570" },
                { "de", "198813e6bfc8c1e4a96fd60268dcf543ccc322742cce6823c65098f0cd59d763250b944b7e37f58f22a8583c18a45514fcb6053e5959a5224b3e20b9619ae6d3" },
                { "dsb", "92cde25b80500250d2f824b7b536c4363942ccf69a9855c716fdd091075a460bdb5b5331f719180f78c82ba104f31b251755289590f45813dad6e85fefaa9349" },
                { "el", "1dd34073f7e79015b10c700ae623907ea9fbc6a475daf7f83bcd8c7e93d96c742555d4451e32139954e7546058d7e0b49edf61f3b23e2dd1892ae63f88e47494" },
                { "en-CA", "f402cc0b1e13a833f0b878caedd397cefe227dbb5f9515fba1975883f2313540ee6d44f1a140a42850776cb9e58eaaca721398fe4929e35780e86cb0f250a10f" },
                { "en-GB", "0733ec69402494093248c26b9397bc0328589770a3e7730ea6ba82d86891200cb0befa5a8d1b27b3c3189cf0b83351fc62b15219fb9653522428a5fbb6609c04" },
                { "en-US", "5eb3aa4e9bc4f17ddd6468df8ab9ee10f9d5553e6842fac620555a9a035c58c3bd56558332f2b3bfa553ccf5ea26d1d94af9aedbab7eedc7a481601c074803d6" },
                { "eo", "b59f0ef13fa21de7b8a7f2664719c5990a86be098b28c0c0a2787aa120c0f9f5b9ce98b21d29a8176997ef71e5d0ee03db5bba6f8e1e2428522c80944ca476ff" },
                { "es-AR", "5dd2735f57e479dd9b5a119e892859bff5c11111c6978df619c9de57a8f85e6a76c02117aea744834e3ca9a08fb40fc1aea16ef4240847029714e5f84203210a" },
                { "es-CL", "5b917917c7308925cce5404e1d8636ec87e992d96394f3c607165d644e0da45c5f9554d8b3c588027250d7dbb494248ca1c256a06a2d4bca255ba862c0655633" },
                { "es-ES", "268060e6c18c57134c4aa493e65f17663e9aeeae084ce6940de951b6b233b97586eb5c63b2ac8db2f384b029a133f00330f8f56ade397ecff787c64213433c89" },
                { "es-MX", "c30e9ab29a8a3c58e5d656186ad8e4c2511dc30a9ebaa69cc43337efae2bb637bbcf975d53715382bd0f820a47b21520c6aa0f128840b9fb150d71766180ffcf" },
                { "et", "d33f5bbfbd95d53b581c014f0c26b6ac6a36a598b2769c44af1d9a87215204c258f3b7ba94c3ddabd34a3852c3db1bae19dc00be977954efc4ec6d6caacf039a" },
                { "eu", "384744b3318c196f0b9fbe62869a82674ea0aeeb0c163d6c32133228083c6a6ec7f90740503309f32ee6cd12705358fa5b92dbee9bf7daa9883a500c76051af3" },
                { "fa", "9fe526c064328e03637af7e25c58d3cfeea37fbe4c48a3388a1d5deaa451581f7a42d3e7874648a81496e12175c5a00d78efbeedcb34b726c1ddd676f69f77fb" },
                { "ff", "5cafecf5824e4dbcf2c0fe33bb50fc9b29f5a53f731ee45a17b7ce62ab63051a00a2e592287275d0fde80d100266f2087c572de04bda53a5b9e9a5dee73a1310" },
                { "fi", "0b3cff72bc08ad5f9fb0bf8b48835895d649f18fe3ee7da861618961da0107ed488c36211fbd540135821844de6929264d53024d451659ab48416b569818ef49" },
                { "fr", "f1a6aa51e9070c7f7f73fcf5142e31aaba7aa651a2c088f03a24c7701c31aa7455e83d93f087a856065978f15caabb0b8053e06f8e13abbaec6bc65829d9b97a" },
                { "fur", "095cd15bda1382db859da6729d8488d43facce05789088caf54d583b49876d4fb0fa9a6df9a6a3a4abeaac0cb370d9d57c0538f53321e113caa9d6465d602972" },
                { "fy-NL", "adb40bfe738dc1ddcf6d8f536a63109081298de34bfe26fb6b3507613532910f956012bd105de545fd3d4c40bedd722c1fb6e57457bf97601762b308679fbb43" },
                { "ga-IE", "9480fede17b3acdf1e3f3beca9ae7080ca9d04babe9e0a63050395c9b6497dc7552c341dd51cbf079aaa0061a99cce49b2e8589df0a15d2a0a4e251eefb4689a" },
                { "gd", "ec4a759da7fb2657bb92c208903bc5a1dd5a7eccc513c8483737105d04a15b12bc2ee2d4af0c53d3955386f00eca508c5206739a03ef229c447daf211609b69e" },
                { "gl", "719dd06b90cf523d353c1e8d5178e8b6007ce990c14872220562985f0e5426417c44afa41946dbcf592f901c1e1125881fc35468da6b60c33702c872c1ea8a9e" },
                { "gn", "05e2519938dc6e7cb17fa7582169b553bffd34643c29a1a1cfb5bd3a62a3380ff924e695ae74b58b33a6cd4fe92344652b6a2285d15bcde558e0015377a8a020" },
                { "gu-IN", "4c39f37f951b3852c7d0da8100da08c45509fb2742e0b9139f2151e8bb83f8063980493edbee256dc88f0ebab1a328a52e2e5a8c61d3393da0f343eb4cb19475" },
                { "he", "bd8b77c14df6d61b8696ad67738c518228290212b780f970dc64f46792d61fbc0780dfd6adb1e631892fd55fab2311af767e80772dfa5ee6c4157cafad3962b3" },
                { "hi-IN", "71e596c2e15f3bafda228826b82e04d0adeda9e84133c0c94b6401df19ccb7b8f253ba939bf68495da9712403f46127ebc98dedce8f99589af3ad3ea17625628" },
                { "hr", "7d10ed59696e13923044c606a29a5ddd4ae1081f9b8366309c305871dc4159ebd75383a328e9ef94d32c13a6f8cc68c51dc9b46c1aab1d0963cd06c4688b98fe" },
                { "hsb", "7d9e616243ac2ec877f2a0d8411de850407891525b4c1113cd717187767a603d312d0f9aac4e1976bcb05a18bc77d9146fdabf26886c426982fc0b10d2d7736c" },
                { "hu", "011d956fb922318fabec95880ad01ef95d9eef7bfa3553659df4b40d8a496ee68a6097382d36c8cf54ba1b9410616876d3d294f5905b17b59f3cb8ad63bcc12c" },
                { "hy-AM", "f494616568052d59899accc1fd5947b7b1a2119832b15bd90d95eee67f040ca0444df333ecf1588411e8866bd5580b39176d00c7cee852cb605ca71278d5c826" },
                { "ia", "da4948eee34193fef786b667390e4c36047cb1ff404cb00a48aae7d829803ab5e13b01d8e2fb9fdc3d0301d8667c9a8df042916452c42d45a7ab1cc5a2d808d0" },
                { "id", "0ae560462c8b4d40b348cdf3e7af23970eb6f27347b6df2fb91ac4c1cccbc729db690ec23d171a9b600c7992f94abd51765acaff9acff738ebd3f0c613f0b27a" },
                { "is", "9a18a3aa48d44a8eecdd88aa39debf8a004253c8cdd1b40f8282fb74d385bffaa0ef59d7e60d1d893a984c72040540c484895b55a7aebaf7f12171c9dd28de02" },
                { "it", "9da9a0c1b9258d42ba28862ff6738cef19ca1738957e328048503642c45515f36d5acebf6abc2efcb6d71f737b4ba93b093d535ef861bad9985106d16b6b17fc" },
                { "ja", "7d0eed02ea986620b02b33c8acf75b00e63e04b12425015dd09ace2c7af957381763d9052c5113aaf1a897eb6c26c1afb728f09488fedae0a2131a69eb82b55c" },
                { "ka", "aae37cd9dd643378a7749ccb2f610a3205944b04b7d10c59760f04566714db66034eb08826eab60b59909ebc9249d3b25555ed453b8428e94c4db3e0bb96ee7c" },
                { "kab", "735e82fb921e35bec33c6f9abc7ead7ab9920bcccd4c0f52e84420c64a409701cd7a717c0bd27bfbcbe68b03e7292500b286c17d66124c3260479c4d6174368d" },
                { "kk", "6c69e2bb3d94527cec4834c4b5890a70eb142478a4e0228f217f44e95aa2a355a6f451fe53326c910d3b8c43b90fd0ae92da15ce572f82f3c2be6bc07e9612db" },
                { "km", "e72343aac658808b24ccdcf43b92d7a021972dff5957b79d17801ea2949bbc94c1f150e1cea36cadedbe0bd6bc8408db97cf1b28dfb2a87a73301be3b2654c35" },
                { "kn", "7a0fdee2aadce98f223a4cea153c4b7e9ac13d677e1d3604790456ceba65917012f96f7e3fb70e340c9b50e6297ff1543cf64ee036e5b33e287cdc6c8ff00f87" },
                { "ko", "451b157d19eb407dec5571fd68c82605aa2c2564c8c6b82483247e6c93d13b318b2340486a03c9d5c1bb20dd1d15cce341f7090e33d8970e300ffccba7e310ed" },
                { "lij", "609174360eff1b0239fd50b6595660bcf477990705a58e0b1cbed1f959a9ca82dd90d188c00a6628830e100969866607e6304e3e272ba8c1f32c3c20aa8636dd" },
                { "lt", "3cc1e70e0cd1c247f46f929e2fbdc63baaaa9b6e3721b1630d110a5725172f2c6c1e4ef819db98cabb286d59e6cf6c2bd0acfc56722810f849791294692de14d" },
                { "lv", "b3fa5291d17e4d4f1367cc80ff40a9b8a4ca4fb791c2212089d2df492af58534606b8f5463974af3b5f64c9497210a813e3f0ddeff06409f5925e26d265d108b" },
                { "mk", "b89b01758ad8aa19fbb6875e6f4b92508c88fe605fb761fd5c13d66cfcbd7072c0d4ad25c1f79aef0f8d25a8ed94e59db2d396ca99e7c8d0560820de765a7551" },
                { "mr", "6b83abfd7858b6d7d63c1835443c9e46d78328e6534be4e180daa7a9b6fe8b2758fb94b60575f07853f4e4c613ed6c8167a58174e2e1d1ee892c4137423ae2f3" },
                { "ms", "4698d2e8a880d544cc3ac656a4c704d5367fd98ccc90c2c25132aff30977edbfb3ba36a274495300433403f6958d3a4299ca0a47a1e8367e261b6637f96b2eb5" },
                { "my", "2d729699c63c3a619e111b697a74ae05c89a2f6862ff75eafc21d845ab9c4166bfab71decd32634ae4678c063c99b58456c91a7ac05b7c62d60706138ba6f447" },
                { "nb-NO", "4e791f68bf3b19fdf3b4dfe500deaf723217719768d38672fc2ebb9e8cd7a4ac8df8ea1acdbd5fcbc98af5517f730ea84b2c6cf0d25bb6a595b435bcf133a167" },
                { "ne-NP", "2c85cf97e375182a37e70afc9906263ea648bcee752f953916883451ced628ccd7a1f67e988863abebd41cccdbc33510458dd07c359ea64260f5b90c4321f070" },
                { "nl", "0df9ba61f9b5cc4510e887f2a68ae6d23653e7f3fb1253d098825a971c34780ac335c0a4d9946ce797e3a616066f27bbf3c8ab30d02741f606aa960a80bf4e97" },
                { "nn-NO", "a3d4df00dc79944443f3ae597822878fb2347524293c9da9f446085f0da9428bc70b5eaf88cefca2a4a71dd44a35bb1a9dffac1b998e3df06f268bc6d873c3f6" },
                { "oc", "1d0ede46d669ce48830ef877c32c8c820d5d3f9836a9d8beddc4f406d70e51ea6113175c761a8b9cc942d7666e9da24ac50b76818efaf5f6b0754ff9fe7fe186" },
                { "pa-IN", "162b20400711bea1ebc8e72a35120a9c76da779aa8942ad4d3a1d7253b40f04a67c387bdab719ef6784f46d41e592ed38822b1a0526981f34c3de1c54cb92ced" },
                { "pl", "ac17ef760091fc4a10c5810aed67cdb3139bc549e3275320021f09246ef5e722cb70764e9794b8ed4433c267ef77a16a3cfa262a7df2ba5a180a6914c2adfd47" },
                { "pt-BR", "2017751a261cf0cb6361e17d1ca337a81f960421add6c5ac0b8e4aa5ca004f8ea16f39325246787b9073af1d1563e23a8cca829840f23f0e2c42091e90b3c44e" },
                { "pt-PT", "6fb430cc110b54a29e94aeb94dbd49bc8870f6fdab51b092fe66c563ec6e62ed6920b5f73f78d9c4025bab39e9824414478127ece228e7da205930583b46f11f" },
                { "rm", "670a769d966d69b3c2cfc2706566c3abe292ffc9e85378dbedaabce5a247b3fa612b0adf036b384ec39096339cc6f5e458f77c579c900103c966f4c72ca2f1a3" },
                { "ro", "0a4516f33e0d5dff73aceeef65793353a81ccb1bc1f296e40c6c644088f3722365102855a5b6964caebdc8edc0e58e6a1fe3214c3bc22a76f130db2258435420" },
                { "ru", "d821f49dbcdc506aaae9cfb6b3bef0324e4c552f6aa8be42af71e3caa4185369651118b6f929302619936d1e361f3038a8c868c0a6b27818c8b90c385d2e3cf4" },
                { "sat", "419f874db295fd3468398146bdc96c6e2796ebf4f786342e98d16087f6a0b46911160cbbf5c8fce57c245d5e6b048973a8332a497938841bc46a537fc560f07b" },
                { "sc", "b2a9438334e2cecdbb1e7752e67ad392c23f726a33667b9952b7cde08956eb03866a0c490f1616756c482a69adc945bd49a3f2262014775d9411a68aa0f9c42c" },
                { "sco", "e86ec07592222d5debaee68d5695ef8e28ef5b4f8710226539e6daf8d81273991ef5601e99f8aa5576c4657893bb2261d434728aaee8876619e80f9dc110481f" },
                { "si", "a5f61db78e5029d4cca1ba369bcc7a4e0fcbcf1186e4429fa5a8458fb52e6077c1fd1581f2be0a516d10b8eceadf3a103f2f5a9d93bfffeeac75035a8061411a" },
                { "sk", "ac4fa9b9859b9d8d9c6da74e909ba5ae5ddbee5533671944c541c484e9dcdb20614a9c8ce2ec67fb83bbfb02149726eaf11ea4ac93d811d88c88fa27c78704b3" },
                { "skr", "65109b554bffce0fada526237b9d29b14616bfd86285d71a3cbb63489ca5a140d940b23e915ab3d58a9ebd9e1ae33614586bd66ac3ae3494ab18b8ed2bea31ff" },
                { "sl", "4dcf5f3ae00ff265b16f4dc43e5556df9e367b2b4445f972bded8840cdb83d58eb868b7360f75ff3bc1b99ca415162899d81929aa8207b82a0f97d96539284d1" },
                { "son", "5f8cb4dbd04282778d1258d41c5f4d61341dc29ed6ebe0e2cb6ebc2fe6613939eac28efd88bb54e1e60ae9c83012b530991d92d04880919446eaf57bececd560" },
                { "sq", "bd2e2f6b7c83e804d40cc27e27da471707cb87b8b256fbf4af9438f8b53be95dc00e1db029fd18b6da14d04ef7f1309e83257b015a261a18f73afa3d6d7e87c2" },
                { "sr", "7e9c362d1b4ba80e73d838b712710f47fdc0d841689df68d255c78a312ed9af0087480cc651a37993d0496843b48b446c1caf802311c67b8cd4ee3255f512489" },
                { "sv-SE", "b1183488e997ee685c4fd12026480c7b9ad54752d5d0b3458acf83a5f1a2ff86a61d7f3bdab37a3d2efe6bc9aaf1942e17aedd9f7bfa481e23dc89290ab60987" },
                { "szl", "c0653bf3fbd4c4a9dbb9deeebf620476a5eaa63c737e9318e42286feb186b3df0544fc03bcb0f16d1f8b9a9fbd32dbd8696cf27b04dda26e6fa3d272cafcd510" },
                { "ta", "8948e76e90fee440653779b61700c3a8e6ccab77655815b486948bdc3d98ba15f3a46702a9d78a33fe2af1d2e72f04eccfbf42eeb362284148686600af7e4e29" },
                { "te", "46c746b05ffe13448cffbabbff222a0b939de7137c102d32d332c65ae548f9c8b00a7a5b6de6fc48ef509daabd4e558872307fbc05884acfbd8c4fa23db9c02b" },
                { "tg", "e35c8b40438ce99435cef1bea957e0ddfcaf95d5f18d72cb72a90b642f2a1d048bbf5b3565898963d27bfebd86bed41ff6fa8622bbf803a3f3e0007934c8128d" },
                { "th", "aa44f23d46b8a9f78b75d61550fcf16cd1a935d53f3b3c05fef0fc64eb5a6c5990d0be05bdf79c68cbd8c1044932429603f796c0bbaee74e3d110870eaa84f36" },
                { "tl", "03f663fd0e96cc9b4fe34ef9263bec5133443c2a90da41b3fb6474cbea63fe77c77b6a3912841e81367c16a5b38522fe55119776418c59964f67d75ab1afbb97" },
                { "tr", "13ab485a242daaff41958e241a5a515435ac7544f2a9df5150b6b7ef068dd29577639eb2dfea881c7fc07744ce02c6f583016ccff2cdb96b14b84ebccde124f2" },
                { "trs", "7baee8e103428ea745beaa03695926ab22b1ded36cec2496cd3a7ab14197febb272f7604ebcdd810befb39e68c58f0a47bec67a4c7a2a363784c335ef70a7fe1" },
                { "uk", "66a550fcacfd893a98878f8990f7af4e86ee59faba729b821448b2e98d0096e63ecec67f8ce58b1596f71ba5f978b3fa551dbc8d0246a1b8935a32575eb6d893" },
                { "ur", "d4bb9b9e3867a090692f1070462c82ec965ddef1c52ab01c23714429eb81e460a5dd86c6d2da0a27f513f93c82c20d0560739cb56a296121462bd39f24d5e02b" },
                { "uz", "1725b4038bac820beeec94ffcd1ea067d7e308c9dd138783c59f1a35ecd586ae124c79fd8202b63598e47605f081103451bd1e9c2e6b33f3411ba88d7627984f" },
                { "vi", "fd432f6a2af36d3da109d9e07ad2de18499f6ce1e99a27ab38596bd33af1e1daeaab385c3804f55acbd9138a6b8ceadc0d02874549800a87c7c6508f43b561df" },
                { "xh", "9125d46826648bbd0f677107bf850aced8b4af0256af1656dd1b65a98441ed924283adf76966cfc2ad8ba28d5adc545d63894f84da26ec093786ad249713e0f1" },
                { "zh-CN", "c55c4ae39f7c3d8f0a98f77a611830ce71d441b9451e376427d1a79ebc64e95134c631950d8f8111663b475d8f4d856490e8917df874c8df178fe21adcd42d8b" },
                { "zh-TW", "d36433c80c88f4bac89665c63b53ce8059cfb922efddc4a6cbd27017eb4615650156dceefb0d6e2f5ca81bf8e571ed7674286e23a9388330a52a658a515ca10a" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return [];
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
