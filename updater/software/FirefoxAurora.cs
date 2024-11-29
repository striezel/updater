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
        private const string currentVersion = "134.0b3";


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
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dc1bf9192090433e078f092ad9284deae93ae529901454cb38d58f9cd1902736aa2b0913ea70ac4ef24aa55bcae881b92fa9e3c4fcd772865049ddba052653d7" },
                { "af", "a7b13d9f92b233c5c6a0faf1448b3ed166b68948fcecd7abf8c2cc8c96e646f272867b0e0cf3d119e5c304a63f287958b1aa05f0c78b80233d29ec7a153e0a48" },
                { "an", "e34e47dbd3197bf7a21f49bd7e83d34aac34cdf2e7ae9ad482db53f2dd5c0ce31c54a645ea58e8d042f96594ec589c06ac7c6cfe99b38ca6157db2ea968c2232" },
                { "ar", "0a9bf40b214ec52625b711e2dae604ebaec384c0689d286c0d521fd6d36b6d5ae618f56a2140d7b47b7296ddabd6b96e127d29e5c98f1d14d266569d3665fd62" },
                { "ast", "0b7fc326b03c4f8f940b504012560851bf33c67b832136fce3eabc91a6ea8785cd01d9f295d253ccdcc5b683f2c12c7836aaeaafd34773a0b7df7c51d96455a6" },
                { "az", "86bae196c758184f6f760b82dd4440e7c88fbe06996e6d140539d2e913df3f71e0a080501f2ebbe70938b9f130e3ba344eab0a00e016c977454d751b98fde853" },
                { "be", "2ab38b06ca7b25901cfe735714b6c8cfa97f671c3930215e42c229e709d3bf51f1e0d9814e20b698a8efd6b6d1084b7af178447c4edb6ac8989f3a50afe0d85d" },
                { "bg", "b5914054c54330257fad3a8dbd10d602b8d73c596d2317875b0e5458d1ee2578162b67112b3f9f41aa2b88aa97de533d94960c5fb51328b9fd627d3de170b9fb" },
                { "bn", "34e892c2b0f3c0799e1f6fc899ebe184481d7d0c7704e1d27333cf7e27ae44b73f401123ff44519f07e6fef9ef9336a1c28e6f80e1c5d756619a94a37d4f0b72" },
                { "br", "4522fd26c4488e15eeb323933130b6d07ca04ba3e41063456020d44087cfdcf899ab40ba2d26b1268f2208961877e10732b324e61094a1cf7f05c02dabd70596" },
                { "bs", "b1d9a570798db62758a9ddb746684fe83792e9bbb3498b189b2ed7fc781a7c0f5b4e2c820c8df7c83059680901b54c4323100001441d6263e1f940a2a929b126" },
                { "ca", "479f7ff1e197689576397c62ff3e71054925c8e49ddd987d7886448f3ca180933a8c8162374695fffce47ac30524ebe4c36e69d6aff65caf8f5cd7b975ee1690" },
                { "cak", "198fc5483e97f2f36b04848221ebba81f0c3d7223f0ae6fbaa44926b67a0b9cef5419936ee2e20298e67daf19fd9b908efe02c0d579fe92f390f85da01d5feba" },
                { "cs", "f67ccdd0e103ab9b39807d355ede30a2089fe7cb9f163dae239e32b425737c5ce05112cc1f3c21032e9604d2b34479eae5464d55e9a91842639e4bfdb9732c08" },
                { "cy", "c66f1b1329bd339f33513565487af9485b01e4b64a40ca3b7237ed6711f569658fadca2b05cc9bf267b4b9127aa4ee7d00f0ad5a6984b3a5fa02b11ebaa0ea81" },
                { "da", "d5f6db881bc1b72fad2005c9e19a0d174575add42985045b468d72653fd312f328251000b9c85901d003c51e35e3924ef02ab0246a32c1806c06425510ba7df6" },
                { "de", "d54fb617a6f6889ddb4051a74edc473d55688937efea7e9317261a1a6aac250bca56c98c50e623472ca06d2154ccc735acd2cb706f475d17b5672d27c1429f27" },
                { "dsb", "4baf3cab152a6c6b25ab7450caa27dd26130d8db6106a6aec9491b9cca0379340bdf5c23b17e2e6d969c53132f882f763b35260c2fcebb9d46441291e5dafdf5" },
                { "el", "f48c5912fcfc96c69b78d3b02cee52aae6754271f61a573e8c2755d1daa9f8f43fdbb5fc93cf82992d318599527aa9cb530593b418402222530b9ed42c0807d4" },
                { "en-CA", "6d572d4b963d6d1c4ba7857541aab5fbd61c9ae05322a88beb7b1c53fd08fcdc8678d85b062957f6760100c980fc7cfbfd9eeaad3edc6d99fc91a5d3932dbbcf" },
                { "en-GB", "d968674283c4f42f564ae944ea560a881ac170f9754eb01aabe00533caa0981dfcc55496b039175b10d179d2d4f6240548e24a6e01b04c3b2b8413aeec99a0a2" },
                { "en-US", "7e88f37b9c563b50a58bfa24aa9e62bbcc13db03327f3229f758524750ebbfffd058cf6cf9b110b54e9af48280a4fba4d5bf76e377dc64afddd05b2c8a04f2ec" },
                { "eo", "cb64f7141123ac934d74ca8a68707daeb97319010a272974c8b49f4f5e5af158ffa9c1c6cffd80e31bfd5803234de25555ec9b2c7bc22b775d6fd5f87abda8cc" },
                { "es-AR", "ade1f2223316aa6bc7dee90e656e80a7f3abd49d08d2b6b13d0376535fb66d46ae392941383a7781effe64ea915419cf62ae5938a3a8070702e8017ce89f119b" },
                { "es-CL", "874f45a63f0527abb7f8d261cf1f51d3d0fc5f5f6ab526b9de49709022067f29600905fe12fca874b8db17e3b25b6f7d685910b892a1f1c2eeca85468a322ac9" },
                { "es-ES", "ffd5155c7bcad52f21ea8e12495d5723d814b6bd152ecdccbcb817a2c10e904044168a61ce87f2bc071e85c99112fc6784afd7aa4055ee10d5209f60a9a659d4" },
                { "es-MX", "799eca20c5f833d778f3b5dd8bd883bd1bc6b0a84bf0ee3db59ac66630f006d3833515a0cdc74250e8e4435ab50da01bfb59b550eb7cd940bc2752b44137d1fc" },
                { "et", "d3556112345ae06fae6cbbc084e9d44fd194baa0d99f8a1558b8a0fbc992691c8b2c98a5ec96260a3fcd9f6d52b17eb24ad9433c0d2ef0c78b846f90fe326b5d" },
                { "eu", "f9807e6c1cdce2815e5f0eac2dd90bd14afa0a581e9ec5b1ce870738b066d60bc5313f85031fc5386ec9b0f7166252170205ede3cae0f4f39f04c2d79a668c60" },
                { "fa", "7a6a22767ba0e627796a8607e955a92b8a5a56cf59926605278da1507d4e9118ca7a54383df172b04a71f8866a4196b3608c66223adaa251bc0e99de5c6e09c9" },
                { "ff", "d67611253e9a7ecc828e3f569959294dc299dd66c0a4020d36b64e70a2e168cf30ee419d5bcd3ffb643245d2394f95b19fee162c660b0a72d5aad97b19ad625c" },
                { "fi", "4f00fece34e236dff5c7069f94d92482b26768be61a925aeec3c56aa90f54de1ee8b2cdbade4813d73959e3f70f1472dfcb60cab2edee2123f8eb881d78cec50" },
                { "fr", "0d4b052841595afe850232a2c734176b41683197ca502a5c2ac9f29e449b4d626afe82acdff882c735024eaf83a6fd82dcdad9312022f00f3fc8e04ca7b082f8" },
                { "fur", "28e78cb803e91d23e931876d6da506863dc7c0ccd5a78689ae8e2f6a2539e9568f00afafae4a2280b7f6476f0f7eaeb7dcc9c20eca5726aabf9f3df8d076fea8" },
                { "fy-NL", "24bb9f06e9ec913606971fd01f127f5fd5035e3e86b658769893793febd994c051c73c234b00e44838dd8b258fa1c1a4883079d6b18970d5f71613f4bec4ac3d" },
                { "ga-IE", "469ad9911f50c00ef453567e8ee2a2881c63ee9c50bf40d1e558518df577f8028485ab4399262070f6a521433045c9296fb16337cb723641ff7af6219f5ea9ab" },
                { "gd", "2a7619d14abe3076d78815748700d9a3edd7b7299df180f1672a7acbbfa1fa106792cfbeea31f2f412eea8ba265f4f86618218d549c4d020794cf9c54b5f4671" },
                { "gl", "62e558a2db545e8d7253ed49c6e3c96122157d17cb6b356e1a61e759923a359d4c200b19d83b45e9e94fc4209148ed524c15abfe3c68faa315b7382af285e81b" },
                { "gn", "1cf33f5fcc7f4fffbae644b4561489c101670d06a1632547730fbbca75c5c1891c76a54d208eb234cc2d7b9ffd965be6a216a1fa8af7c27190aafcd773de029f" },
                { "gu-IN", "a22ac6d34581041efebe0811e3e771f2b29b4636548c6859539219119996712f7f28296fc310b8affbac944a720b862a840a35f4a9b629b94b7d1b120102a831" },
                { "he", "975b8e8dbc3926e118187e8cac2b09514f6b9788bc7a14bfcaeab7b5ffb65946bcf74e38c5410d2a8653ecfea5d41b655b4150f9ac6b625efb53ab9823342e7f" },
                { "hi-IN", "83379604bccbf023d6d40348073e95b740dadb353e417ee60c7236422370ae53d9afafa61ff795c02a5cbf68739660ee4d3a10f4eab956c28f1467a754f379eb" },
                { "hr", "a90bce1ba770b4f9d4f8654ebf990b1e1adaaf0e975cfe89d4dad226b2c4d0b38ecc8d03bc579c9816ffd6f03369b12cd46496515d8cd44feb165839e4904a40" },
                { "hsb", "89b551ac4a43a0d303d2f256db48c3b53b01265bb82f44a774b46568824ab6e57efd536288929a4ef61491ad7a167dd617a6072f9f877b50c9cf7c43f81b18ce" },
                { "hu", "54a580bb27ad756fa8dd834768306be1e0db22b85687f645ecdbd8cacb3e3122f2f486c1d99ca24162aa0e1fa7fa6b86642574fc7fced843d7a20b3c09af1246" },
                { "hy-AM", "4dbe933dbda519af9874d3c32485d8f91787ab17694983ff5f4f3e4e8dd0b3005a04143a20f269c58151705df30eac249141c7c81527a4496b20cce566e6a359" },
                { "ia", "047845fadd29132911e1a5071e5998fde53544dacaf08a6e16726879523bdc1d03a4aa71f48619dff1350a3c9d9d797ee0b5e0addb10781420271e1c5248ab9a" },
                { "id", "68bda7e569a498fce381482f4d4f82270305b631f3d579fc1c264d507a94825e6368f3c9ca2f9ddfbe3aeaf069d2e6c2aebe503ce8f878b423d5a1589126e56f" },
                { "is", "d918469595366c9e2388435511c625657cf638d25986608e50f917268f9e6f9c76fbee084c09d02041ca1491f061fe139ffd1cfb7536b55ff73962d7bf0a44d1" },
                { "it", "3d7a3eb7cb0ece158896db67deda83653ea14f091476d7e72090fd8ce6247b2d29235c67992f9aa9113014c545b0ea4547c98725151f9eec22deda877bf0dd8e" },
                { "ja", "45817877e89a103277cb9562209600a3324e403722e3c15edf661513c14180c2ae78c4519582e3ebe214e6115d124e3ec41ee0f0f591a743705f84a03c4116d7" },
                { "ka", "e29962e69688ee726015293a57ddac2532f8bf688d4c696d874ec01f1bd09576072f3830b18ecc5d89682d236b96674724908cb0df57e6aecbe1afeb6fa672c9" },
                { "kab", "6b5751fd299d78b74f95de9ec9d0d0b1a19b57d7487f92e8f384dafb5cd42aced560e3ddc7af0933718267b1f425405b64df657264ac0bbcd7ad17401f06fdd1" },
                { "kk", "20ee3f336ab8aefc0457e0327f6bce72e1f442504fc8bd702ea36d92e3fff2662be94b10c9d925eb882998b21f441ef7d71c0ba9bea19375a7672a4df4c21163" },
                { "km", "fe4e9a4f2770d9506bdd1f058e4877f79a49ab86f30a39e8441ac0f8b401e07053826eaa37e281cc76c3bc84df77723084f141a3cc8bac1a8ee7ed561e2ce102" },
                { "kn", "8e748dfca82ba375d4e859de96c9365878f53ec7e427e66e2481e00376c4b4af7e17199d125b1bff7bc7383d5c5f598c58762b0b91d993160ebb11b454ad7781" },
                { "ko", "a79f69690adc452aa1855b486c94a29fd4c3b305d4586a950140337e9c94844b83e1dfed545e56b7273d13a50b873e726b36a3316c0f6107e87877a66f3b27d9" },
                { "lij", "c9625a88439b92a6e7aebe45ad0712851da72b53a2a87fda22a50d549761af437431236b3767beeb20bee6d8658887351ec0f5f0c855f712f082d8f817a37375" },
                { "lt", "90fbe031aca7698d5d1c8e9e8789e377a2aacee74093843ebe4c39292fb429369c334a52db21fa38b7ed4d0908f6fb517e6c736d99e4d5478fe4166202f56e39" },
                { "lv", "5986c0c4515a60449ae29cd563e8d9c0a64054b4269636baf7e47cde6716b508bd77773352091095998d715226b07334668c33787045d8338d40d437dc11ea8a" },
                { "mk", "b5e2ee1db8ed7bafc04c2db0f5411e5ae93ce6a27bb50ef0f554b7a39bee741477bf9cc86f469e67bf0ae124c3b303a8d0c13c713837077f4c836cb12c19dd2f" },
                { "mr", "f69b10ffe5cc697ec50de97390c9140266e5af15a1af278f65a608e5e6278b07506dabebaae8470bb9df4aee747d8d9a14739da080c3c727cee9cd538a1982a3" },
                { "ms", "a4f0a7470775c3c5a4a5ae2e2967a1cb1f3af5f6386209c93916952f2b21b391b4ce4e03c8c6890893f54da9b6d4af4efd433b8b641f50395d6724a460420c10" },
                { "my", "33ab2707e55a0fec112db45a2d113ad8f9d4efeb92e5566a411747301647aa72dbf0a18e373ab5b75e1bfd7bdc3559f82f278d1e9b0fae4351f156ab36ab6c88" },
                { "nb-NO", "b92920a703bd7e097fff5aae48950405f7910e0faa47c5253db68065b6b70df2e301b93ab49e2900d9e400a2b60f33283c792349b8f17b8cdbd41bb4ea35b150" },
                { "ne-NP", "ba4e0d30d098ce16ed11aecf68308b3125f22f61f4ad3a5f6201cc3e763575493948d13bd27cc6cdbc6fed216fad939a73a00f8e08b0e55b044d6a545f403865" },
                { "nl", "0075542e504097db2333b15042bd525b55d56375770bb505f383e89b272d2dda778156d54d527737cdec2e6ffa895b583a99f036ffd839427b6df20f4a8e25e5" },
                { "nn-NO", "aa607e4f047956f5bca5e5a88879cdae5518caf4815b2f7805a4319de3753529b2477af3c13762c121f8aedfddab214e027117167a1584ec2caca6efa2bb27f9" },
                { "oc", "5db97cf69160f565162118bde3ff6550df039ce7cce64628f540b942c01e87910cbcc7c5cbedeeee6408d687bc286e5373d458b02f8e6f94758216e779024a9f" },
                { "pa-IN", "1d30af8c0fe55177ae1624d1d6cbe1c2ad835383327eb640849d7f814634742efa7cf140391bb1c5edb52e10233f74bd91f44ba2d3d1414fe5319e0f165fc4a0" },
                { "pl", "eb8b5ecf3b8fd01b9fc5b75059117e015d05a12012d7e45c395bf55a00cfd147f3ff1530f429aa7199eb95e1ff7a533bb46390e5be4ca7d57e2ce1a6776535c9" },
                { "pt-BR", "c616889926fa6ef4dde0b2df98a3bf1381359f44b5df727f704a413fd78735a1a14f9b9a7f48e130e7642d730222da27c7f4004743f612ad91b4512df819ca97" },
                { "pt-PT", "9d60a5b13540ff8ec2b116255774217846e5e52cb3d6852f6ba75ad8285233360a842249b4d3d687202bdd7f97327cea3b344e4df378b71059195cf60aa9465c" },
                { "rm", "c9a79af003a07b5d526fc03c473a958e668dd2f62e0e67ab8f68ae448063d958efde164ff5e1d7dd9591d61525d992f56cd58a28861b1700b68bd740f7f87cd4" },
                { "ro", "f6cdd507ef792971388b3992941a2744ec74d25a0e5a23633bb22a0b0ecd61d924f2a98891ec68bec3dd4e0d8aa7ca919a3fe15cd7e5c24750f2f125bcd176fa" },
                { "ru", "631740dc9bcf78a4a887e70b58649553dc5cbf975ff142041c588e51559f9c45de4b741eef6222a9cc5daa922b9b9db3fdc9dd03c1c3ee95cb927f214f193335" },
                { "sat", "bdec3d8c923ff8b398a3af64cd781021258fd7bb89c38ad11c44d69bfcd1d412699b21f80dfddf24975d04615a066b734358abb809de6e8b42cd88ce5b51eaf5" },
                { "sc", "cdb1aeecbb6e418631321dfbdf7fb590380e1b5361da8b4927aedc077156899f7f62c3cdc104ab0c839c759e15a19e5faf537de4f984b56978f1a22486884df3" },
                { "sco", "ecc078b92a19af4b0ccebe13741ef566bf46e70f3b55a26f6decf5dd6bd01320f568b43be24e7727c4799cb635c2e06f9b0150e746e697e897d2e6668eabb38d" },
                { "si", "c87f2eb0c0c0fbcc9a9cc1df5bfd52bfb005b5842a8ec4f27ca95ac47c79a1a87ebd79e3091712fb6f916f926b37eb75abc0ae72a52adb61eb10788462e2a82b" },
                { "sk", "ebf3a6fc13918a9e96592dffce374bfaf1fe69736ca2f93989af7e09571d34cd12dea8e58bde025543a03fc9f95df516ac82c486746e494b2615868c023e39b0" },
                { "skr", "90ec33aa567fb565de10e23c0c47ffb5a7d9ece894b649ee4111065473e4a4aa4947c329bb3f3eb95a5b90df1de61bc429396630a326a79cefe217924f0a5acc" },
                { "sl", "f34da6cbd3798a53ab9f3258d4931bf499347274939dcad46c01edd4f1d436bac99940b0debf17de804ca7eb01a3700ce4af5c3f5ad737fb423d7ab512edd86c" },
                { "son", "d2c36c005110dc204633784e58dbed45b8ae4fdac201e5f8c15c47ae75ee3da092c916aaa7fa51632e23634b59061f1f096d9e2e2b3eba23e2f3f547ab3b4972" },
                { "sq", "8174ae36aa334682eb682cd88096044181fd412cccb07230ffa4458692bf0007a308dc5121f22940d27ccd2aea63e9de482cc6f0885a96215b6ff1cda5579049" },
                { "sr", "4761b6b9d3ea9d549e1b880fe0d97387a21053e90691be6fc63f45d59bbcf70afefc27a9ef885c887ae0fe71d587a5fd0fe328cec1e8949447e1492da137a722" },
                { "sv-SE", "a0cb332699a396df204051d5c964c7ffbe573754d995e596e2ce416c2bed4272e0ae7aeea4293334d4f14176641c92472e891c8f60057188ddc049797e11db3a" },
                { "szl", "764cb4d4d75e356015ef4ad8567f182f68a5457821abd4429a4f75e8c063dfc2cef477dd6d08ea153cc299e1c150a406859996aff84642be4a338f3e0d50ba46" },
                { "ta", "62620242ccb178848af834e67f953118be15ce2faede57109645a3dba8dd3598c547752ef430de4ac0c5141f8f878a4272b8203a63bf1ed5d4493331a4f26169" },
                { "te", "d75894bad2f87cd2e239d8d3ff70e82355b72e2c1d7f184d5875bf6785464b158c482fd23a82773f67ac538722db3773e823002fa7c014df876c1a4e544502d0" },
                { "tg", "cb8dbdcb10e357fdd7d8cc267e277d6b736b68fe007d275b4b067f0704afc53291649e7e99e5d63bce1005474507f5166af2690bb50622e73718545b98531b6c" },
                { "th", "57ecd9e9ade2e02cffb25dfd2dfe899d0aa76257260987fb1698634626457e7588d87abd5a85dfeaa70df10638685fbd2717b109b6618eb7523d910e640641b3" },
                { "tl", "7450d43f8bf33a86586b2a949fee883111c1cc86e192b4b1e1ff69888f2284f4b892d050f004268481e874688471868ecabd673f9cd7dd71edb2e428db1526a2" },
                { "tr", "f6e6cca113d27d80b8a38c12a1cad57d0dcfd9147d15934fd99dbf012c1837c38516f01dfd21000240de13de1c20c3335f0427ebd533bf9ec866dc8f139df9bb" },
                { "trs", "d20fc272193c32e66d6f0f746ec93d98a524dfebf9036cebb187d478268d7e5db2fb3bccfb4d063c46d9d22f14535b34a91ada41f0c1c0787bd76b9cc47be030" },
                { "uk", "4ad35a4d87deb2a12804c699eb3a2ec58efbf8f487143ef212b950372da922e5a2a2caa8360fb01dda5dc6d772ca00ed39f90bb1c359673aaee220f19cf84d1e" },
                { "ur", "38fd3bbb4d1c74c24352f873d455835fc48984371230c8d8fccc6721bf61d15e62271868234f41cde0cecda0127f7dd587118060721f964a363245ed52735bf2" },
                { "uz", "363ec967997aee5dbc0913ca632b73e40016393d3f92400794f5ef84872e8c26c9b776d8ded76f7390cdff1351a96bebcde33415b1dfa33748bcdf287c9337e6" },
                { "vi", "2aa56ea4ed4251b6e70d3a54ccc7d7b29ea86e8dfef54cdb73921c9847d9a95c2564ca643bd803eefc8605e505081ed75ec167364d45b4ed2d6da88b72473fcf" },
                { "xh", "3f8e480effa6e25d98db077de78a95a49cae4bee02e8a9ef471379e2d160f794eec733fe01c3c97257409cab86e23184d6194d7167e08e74b2b20ae7bf6e74fe" },
                { "zh-CN", "0b2bb1d86e784a96775ab8576ff631ec2f98742fba0c85e65ac0a29ffcbfdac7b7f79595e1e55963629d790fdf93cdf334e0b9e1fee0d00040df125174b9e50e" },
                { "zh-TW", "e9a40b3a06c7195140a7332a96480c306ec8a4a76f8dec253cbdacd130f7e18a127dd314c9a25a340e06cc2d89b95d9a339d8745336085b1917c42118148e83f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "25f4972ee25a98a9e88170cf07ad362e5a2be0304af153094884b249d0230fc7a372ad07d63f335971eba7f2c7bcc0bf37f79132c2ecb0f9fe8412d2f4342b47" },
                { "af", "328f9d1e6ccb1ce72862d90475ec3f7ba198be96bc0c4427d8aef0a41bcd051c52dd557c24dc9b112f737fc282a0e8613fc2b8ab6be63b86fafd27fa1b955b63" },
                { "an", "fd743d430d981d9f474368a73c63bb23bca034d1945d4f6d4dd8a6e450d697ff6c3f224e7836ddbe22a4c0f737885e5a59283f4487ee8225fba571d384fb4574" },
                { "ar", "976163ca0beca4e5564de6a29aa17fc98aa1e1228c04f2ab0aa309090f512ffbaa06bf6710184455253171b6e6cc9e785fbe99a246bef7caeb6197efa4d3a73f" },
                { "ast", "5ef839f54bc26e44280090e98652dc5e63a1bb7f4b667b036243bc3897442eaec9bd96005f4a911dcce93c664f4723f30f9f8559bc8e9d6272eee14e9bbc794a" },
                { "az", "2cbb3b5980950a3705cce166e1f78018cd6c163209d0b26e56da3e51ea8270e475943f667662ab339d152cd5d004cfb61d62bdb7864bba2c5239924f0308a67c" },
                { "be", "b8c45b0bd6fb0cdb6b27cf23c09c8a34382793b4cb4ed4874f021ab19cbfccfef357fa92e538b5e41bf98b0b779551eedcdfdf818214a842444a334d0904783a" },
                { "bg", "8e3a5a5d4041cb991ca76c5df93e4ec94ffd6b88001dc05306bbb8c84838efeecfecb2d9535e276af02aa1a39d83a67afa9eb33a7a30d91bcd24bbb79ebbf4fb" },
                { "bn", "0734e2a2474df2fc02b08e2995b0c5ac02998071be8c41d0f842cb8bb862631fe29fc737c362870d97a8a4f77305aff5a82219d20bbf33a812fac6112d13165b" },
                { "br", "4eefc1c6505b16b60e01827159ff0e09625383bd3b4a3a6eab6e59fdc6cd3e7be8983b8dc513a22c5003d233415fdf870846a68e4ede6b82db7089db915d59e8" },
                { "bs", "598793bcb2da1bb4d51dfb1f8d7720daa61857efd8e538f6c78ba81d07701e50c9b755e61366031e69b361ed42f00b5e42aca507917c8470a22ee464e6601e5c" },
                { "ca", "d79d875a61ed09ae9d3cc2836f7d91325430f702cc2b425e3ef49ee98978293691323bc47ec7aac49b2501ad746bf43ba026c16325f39e7796a3137f5954878b" },
                { "cak", "a526059c51ddb23c343487c5998bfa3f4ff12b2cfa4c911c421ec6a8d3497da821c0014d4da85b9dd4f42734328bd89b467bdb967af23a3b7b5ed236ca04f019" },
                { "cs", "24de107d3a076f5eb3a8edff85dc069008f23356f6b036c3d84b0ff394d30e99a2ef0b1e5225e044d99fbecdaa44c83990bc3535178d767f93437e989917a8d1" },
                { "cy", "a82d2ff082342c645f5bb1c068b6151b5b303237af4b7b0e5b4e6233016a19b63d3e3457fcff2feb41d30f01f43fd20b0d79ecc17205d8455377defbcf7eb940" },
                { "da", "009ac72cdaf557447e755b216c87bf784e87bb726539120bfc4a05d64c5764c4439e4123e7cbf819f0724de043b4e83ebe2f1948b152c04676207bbc32ffe692" },
                { "de", "5e5ba8d1ef2effcb98b859d17fd8c0c479c10a13e2d2aad28127faf1d17078076a197c7dfb8b7538f020f6f3cdc229cf0f07f34c8a75d7c2360a3b5a301c4411" },
                { "dsb", "ad1b966b183a9ecbb82ff4b0f287c7dccfcc47fab9053d934ba8ee1df6522d1eee0ecf8c08aef3512eb180fe47c086e9252fe710838dc63795669cb26601533d" },
                { "el", "04bd6d5ec15e8f47254a89b3a70f9f389306614d6999e368eb80eefd60c1fcf086ccfa227ba04f8f0c003272fc2565a94b13fee627271b78c4a6eccd7b368b46" },
                { "en-CA", "1e04adc428e0e54a095a81614612edf956e5c017773bbc3a3cef2a81f8b873a6b1d7ba57ba8dcdc2cca2463520638679091b0690f25ff3bbba7d7bb24718c124" },
                { "en-GB", "5981cc1c4636622249a05992363d2c631048ec42f248206cda3ea0f6428b6bf129702e4e40686b61fc38b17e08a9f65fb592191916fe78d1e67d83b29d3c288d" },
                { "en-US", "d5025705a230babe0f3f98f85d1177cfbbbca8508fe15aac0b3e0feca823422025982acb3ef69d029c8be9c92a0e9cce8abed1b841d5d8367e2d30bfe88718db" },
                { "eo", "543221daae0be63e894c520f21c6a3d1a8d404a8fbe268326e20c639ce0d51152b78083faef94cb8a372b87a27764c698c6398357c43f38e398ed00ed6d814c4" },
                { "es-AR", "c47d80a54153ab63a09f1de89e842bfeb033be2a88565e11c02d23e57d979cabef40b49768dbc5df3de13399d68ed49b8b0d27dbf931298797c04ea336680b0e" },
                { "es-CL", "fc82d4e9d9a23ae41160f8f5098b281d9d2b0d2f4b02615218d79817d56febb2b49525fb61773df722d1d101171f293e812deed9768e49fedc2a0f2146f27bfd" },
                { "es-ES", "37ae2a91d7f9ad33b827903afdfad67783f96910dfa9a9b0f678e9832dd0e238eb9a10474caf5028c96b90adf6258a75ce5a2dbdadb5dfb58d988ec4c17ece97" },
                { "es-MX", "f45a4b747213f2f12f82e6cbf00a81032ccf984044d721ccb35fcd1ad15ca5820c459e64782117f5c2ec43e7273918f420887a4bc5017b4821c60e596c2e140a" },
                { "et", "16283a9b5fe435bdcb6613077531fc3799e3006d2837a9357149586d2a32c8aeeb7d9f055583257db702fa7feee96f48c94b66ecf24a080e1a53a64bd0ec52eb" },
                { "eu", "6ce5ff73cd43d9999ac332cd72823f902218911f04afe23a7f884782f63a14fe0a78e84fc9374204923fcae91fab836f4d084cfbe356fe6806035ef1e281cf30" },
                { "fa", "37fa632088103f5a6311c856d1f4aaeb74aaa43d7f3c64758882c892d88dfd2cdd4ef4a2ea8d33b3f57fc02925c3fa8789cf605ffed4f68b17bff7c40247ce84" },
                { "ff", "b60607b07a93a54386820b6bafe5daff623b760bafb8089ccbc1202217b3bf7f38d42ab048f941b1504dc25c33c95e8c841b7e508ccd7082548bfa1cb8fa76e8" },
                { "fi", "f37bcf1185c35e5b831313a15af41a652041644afd6d69e324388e36568fb732843f305efe2dd075360fe5657442f4f24be7657542752c642d1570fc71d8348a" },
                { "fr", "96c25ab0e4c594211b6c6a0fd3f2a583735e1b3b2ddf5ff1145aa04d1bb3be03d87b26cfbe58c015f31f927e7f208f8d130cdd142f5b6ff4f1e2ac198880184e" },
                { "fur", "d01c69253e9b5c2b91a395234a449ca648434d7c849e2458d4cdffd01315ea71366004c27a5dda5d6b4431b2150613a24b4bb072879fa16f4b3a79b571b69b9c" },
                { "fy-NL", "4b81bb71978d8e04aacc66294407445410eac6cddb792d54fe675fd2e4be87dae3f2c37152b2ff613de6ce2f7ef74f85540ff5c5d9e966feead1377171615dd6" },
                { "ga-IE", "c2f40cb4ddee428a93059bcd4c1a8497f57eed534723f5917547f4293cb965afd7acec353a172714b49b20898566894c4a3a5f22bc2998ab179602fc1d006e18" },
                { "gd", "de420b3506215624b804f53cb880294a98749812c7703af2a7e79f06ad52574315cd6c92fbbb457d8eb45030e574ea6a9874fc212ad16d0afc2116790f964837" },
                { "gl", "dada7c412180ddfe62e858cd249799fac8d9bf2f7fecbb6142e0e89fa47f95bf4caebcf8941cc3d4ef8d5412147391911c2d6bf55ce5227ad213c9365c2fd61c" },
                { "gn", "bbc6ed725726da9576ffd553bea50963787c6379e0d2aacce8e3d838d6edb0fd8ea353497e9ab922d5094208fdb2fbbe49c718897cea7668f535f4adff85c6c3" },
                { "gu-IN", "67c91103b20a07369d2f7a6946359e52e9902aa0f1c9a322e418baceef8f301a644ed4dba5a5276aefacb13bbbec7d1adda3b86dbca02f0338933c0062bc09a5" },
                { "he", "e135ef199effcb70285aa54addfe88a7fa40ad105c7fdf9a9dede091d393ce78e281e331e6391e5119a9542771e8bc31bf649b8575d45d8d8e9930aa17853431" },
                { "hi-IN", "5a1186993b8a469989fb93dacec544d77ead9cb1124def285997fa9f1473cdd92e0ee831994f2ac30026da0206e854be7cbaffa51b37e015c0faa4d7dff19ca8" },
                { "hr", "8d948b307cffd977664e73e109a9cd0506b3b2af7faf77ea1836af9a06fc94d57932fef3b92a09c0e3f2d4d9e86a68ff8fbfbef3f2b5a27eb3d9918a98250999" },
                { "hsb", "c802b8cc7ce4b1641d2b074c70aa35e9a6dd16637b702c6cc8b8ad7ea98e3c073d741eb2012af7ff7d09d7c17551258fbad51de82e6c577b9a9a50ef5cedcc4a" },
                { "hu", "d0e6ff0adb717f4cc8211d5d7d3dcf4dfc743362e57c5e1ce1544429a23e509f5d26d8db6d861a47e157d2a27ebddd1180bd7c2f25119518181f20640ee6c519" },
                { "hy-AM", "b2427815749b2f80775d1a1847c8d6a8918a33d2999f0b98c17fc361174e63db9a285b0a658527e69787c7557f8af219443bf9fa3580f8170bfe1fe175ca5881" },
                { "ia", "4d5137c54d9b744c1213ce4810938d41ec2c2ab531d52a0da76e228334977fb036e488ff1863f3944d237034f7cab62db4ff02b5b4d2a1f6704894b2a2b8850d" },
                { "id", "d7445fa50c2dc8392b5e18070bef5dd44cd16e277c21453e46225b4edeeb3507c49dfae33b979bb5d6501bd4f1b71f5e09e38f805dc144144fa073ed7321c24a" },
                { "is", "dac48e02da3e3c83331aff938067711e08442f08fc7b3a28860261858fc8732824458bb144c9d2f00d6566fbed349bcedfb4480586afc3c7450405b05c22c92a" },
                { "it", "a450920ab3f6e01b00f269f4e7fc80cb9ec18c91b027d7d7db9dfaefeb8d7bcdcb1419aa1bcb42c921e07581a74b23e30dd2db2f37570d3d81da03fea572fdeb" },
                { "ja", "84da5288888e46515f56365e327b751c68d5546a9f54f6fc58dea6e006061c39fa8b52892a34e500ac405d14819d9c8a5b064b86118d731dd5cfdf0e6b470543" },
                { "ka", "14ed06146c529ebe1644c9f738f74e15890e5416a48b74d3cc10286d09ab0c252fe751c46144d87fdf4803c58c496879edf24191ab3533264e1f84f25c815104" },
                { "kab", "3d60d36a065d072840fc3b622d73db455bbcc9b14163c3705b37c59a415851ea75dd85e08b395fa24ba65189128869bbe5057a21a861e0d4e0ababadf673ba1d" },
                { "kk", "e0b0e67bda52ee63809aacfc68a8daefc4efebbdc5fcbc97e0aa564f270e544db6964b5aaf99fcf4ecef3275692f1cfc8ac30473dd759745f6061bcc6d97406e" },
                { "km", "3242d25584d5d2289f4592865f36f24ae259024b4bdcc7da1e3519fbdc0c2d54fdea84125414ba744cebbc698236d0c0256c0a86907990c7294e33d956b373a2" },
                { "kn", "ee76aad342a59f40cf5ff61cfd9f04984d340a7fc07ed48109bd50565d73ee98aaae9b046aa5dfda200150a0491791001d4cc513f49080d351062085172cc9d3" },
                { "ko", "8e2b12f37dc130a5a98c49e3c014abb02393d72f9b7d9c0947a9cd2d8fb89a285b773a6af3ceefcb442ee8d71139e1f1e7624abb95c9f868de7a6cdd7bc41662" },
                { "lij", "b9e3c91e2034b687859b1490497efbdd95e08a07fa0d6d7d877c891d90c195f64e6edd5a698b41ae1c21e106ad866bc83557c92eec019747f8c8ed68c50bcc5d" },
                { "lt", "becdc2863c42ddb3b9904bbb1d6223fe389c67cb9414e238a7b919aed3b9223fc5b1c12a5e1dfb69591b2cdc16c7591fce14ed4f38fb7638b421668e672d130d" },
                { "lv", "24a8e87e883e149389c46259e2f3a72789ff7dbcfd822e1fec55de95f8b4be0cac871f25a20d3bf83589323d3bd54ec7cc0096bececef13c9c4c32512753ae73" },
                { "mk", "6b2f390ea3ba2e2514ba698f021f3e3b9fdcc0bba2a5bba94904971f95cfdec6afe35db8115bdee92e6b35db5412a6fa09f4949216db009f100bd12938b451fd" },
                { "mr", "affa1a3c025112f9345daa9b7a2db291bd69e84cb139d73d80530b9649d03b6ee708284d2465206b3acd1da407f0dbe3cac4d7cd414fd8d6d33b0d09d1861396" },
                { "ms", "aa4ff73bcfc4b2e2412e2937b5e616bbb5f73b4aebc436f8d413bd4447e9089c6c5e312094075a10be23bd851eff2c588a6fb29680b68f0ba0ca61dc25213aae" },
                { "my", "7ca9ee6357ba76be774e7d109d25d0dd8dc60df7dfea19f3b3674202e4fd289229b440002f99c3d086747c3b23dbf803a8b98fb14c2c5c1d66b474f1a34b82ca" },
                { "nb-NO", "3bc0e8ffb4c81f82059435917adb8ab672237efdf6367eb0992f417a5a71f4ca13bbe3f1d9e684509cbdaff7894f729d95a42151ab59748efb1f5f852801aae1" },
                { "ne-NP", "533fd276d2e6d8d90579a8713bf1afd8db585b96080ad0a728396c770c1ed3d9f50df4f94441c3103ba10fb244bfddf9cd12b678530412233c8340ab11a26542" },
                { "nl", "d63841c3a3c5a2a4273dc0500d9cf11c4d7ff33c85acaca85b4686b6e9ffd09c89fc9f65e6223e325964d63371f594442fb2ef83a2a7397f5a251d10ad38c5db" },
                { "nn-NO", "94ae37bc115e507d149cd8fd8fb51cf9d43a144fc12501342f4c0a28636182a790517f547975aed7594a5622258f8fdecc96b4ddd719a5fe72666562fad89161" },
                { "oc", "93b68d1ae0ff6e696139ad9ad425bf8229fcf45ca64a9fb80e6e283771babe4e5682d6b0676877ef78de3a91b1a8e279cc2d3e90775f19376801847b3f2db2b0" },
                { "pa-IN", "fdadde68014a843e9931a2f1eb7a6476115f744397273d26236617632c9257e8eef07cb62dae0a9217d99c8d9b32f0e6c99c404c38a85d26c068d5c881e1538d" },
                { "pl", "eee325935b87346a13b6559dd6ec9635562950efe895d18baaebb60880987715e0f7bd1995c09389740d22a03493871b5c89ff59c6eace6e31934f710cd28979" },
                { "pt-BR", "cb5471ab94e19b3ec6ab21b3f254c47079ec7cd23b663e1d886fb187b70bcb90293b033f0b92cde98d8ae49bba7aa74bcba50fb9fdffa8c9a970855eeb344dff" },
                { "pt-PT", "437d0f18d46716d896b0f68e54d3ea5977376ef421a661b980fe1e49aeff491ed39d76d678a9e563e4fd6081b92cc07a1f6f2e730180f08397a15568310ce486" },
                { "rm", "948f7b67cf57b78d66b3ff8da9d7358a6797d85e88471972c87ffdaf2c1f9280cb150a4d1df23e57bc79b8703658a71bcd163cafe055cec23b0c8563e4f7c0fd" },
                { "ro", "14f13594d672a4bbefd29012a517220dd339488126a237bab413d9c94226f7a66b950d151819e4b392e2d7635010f4a0dc8b58c2cf3bb6f2e744fd4c1704482a" },
                { "ru", "976572d49014c35ecabe865eeefaa760ad3e895de604a2549d47265fa7e56c5ed87c72fcb10aa169329190143810726bdc6e8a0ef55735de0f6f3b9b83907167" },
                { "sat", "007918b09922a47b02bd82689e2097ffa4391682cde55dadd1615c134a1c0e4e94619433b4b06e7fa1c3d973afb51d0781809f9c267392cbb2dbf2d8c2507d52" },
                { "sc", "704d9079fc77c02528a62fdfe45e32ba9185c4c5f5eed3d6a88b5044c09ffac7a46ca6ca69421b04b89195019b4de9a7341b4ac0f7bebafb9cff4762bec0a5c4" },
                { "sco", "bfc94bac490b559742b5c864f96d08a844816b0abc20f566c535406f865d4ec7045241999f1324639918c58e098a4619a15317e8b9e16362d86bbe37c883b79f" },
                { "si", "8f9525415d01c3ea2e94e11bf3f26656ac93a5db15506b7a162449e4263a00cf450c881b5dfe3941dcf7c32cd9b43a49ffe4591073fd52ac518eff5e117b245b" },
                { "sk", "483ff4decdf46230a93ce4e59090d6e00e9420f22dea85fad52b8826cdc86ac76b57f5690bbf73c971691bd8e4269581049663c4f9ceac7eee7720a674d27dae" },
                { "skr", "7489dca1c8a27ede41231ae510df5ab77a547357ca74fe3ac2b1b0af15c6e0a3209f0e1b182ec669ccb9ba939f3b4bac1fd189f0b46e83747ec60c9b339418d8" },
                { "sl", "205bcd12e26969693d8ef9a5609475f355309d3190aa5005a0ec49cb02ad76b98ae9cd1d9670e8588d992d8ea25e2a510ad91e843a716136e2db45255d2fa2ac" },
                { "son", "27739fef0b46f0f24c622c9e1eda52ae6f5d84d8fcacab67b4c0fafdc776287022d056bd240258568015b3d95f608c263610684d5b9999bef5aaeb4ec1ca88c5" },
                { "sq", "1dd1834c93ce3cda1d64f65df7890f805fb8bec78cb054107337ab0b78a21c6f094e1993dc7929f371ad2d8c3b74ef1bb6b7a13c0b184c9115d9de5d6318da6e" },
                { "sr", "d77f3ecb140cb106cd0d9faddfd6820c582ab49f109083a7e03eb2753ec35bf1f9c952cb0d7dc6abc7ce278cafecd32635c6c870cf59ff3ad4f3dd62de6669c4" },
                { "sv-SE", "d56e069533e6426ef8b9bed02c73c7ff5b10c7048f3f9072072d276ade047d29de18d4e70dea65e3989ca5657dee53ba21df1adfca6d0a289e25a04db78f20aa" },
                { "szl", "2a13fde087315ad3a476829aa62bd9b6a03c85486f9d96c64b4c21dbb01eb91fd9f35767573ffd5db0057ce8ef898525fdb4bc0287e727ccb1b86d4a1efb0aee" },
                { "ta", "ab041763184a1ebefbf77e35c61ebcbbc50211d539d4fe3526d26416ef70ce87c1c3429f9dbc4110f53a827cd0011b320956bea0f0e59f3cf16af582032d8770" },
                { "te", "2ac6b9b740c5ba2849920236ee3e22fd8c24b5893f2a4c4e6b4741f4f3be07edcac43941f0e2526fc50906644b85bb19b2940a9e8fb394fefc02e5813bbcf5df" },
                { "tg", "11917f20ec8f857dd1f53211b6b8b1893556b5742df4f297e983e299f99600831a5697d8ff43cf9cdc9947054c2fb8de17cd06bc7873a6026fbfef466a61fa25" },
                { "th", "5be53db0d4a14d7294e8932f527c4589267955e60a20fe01817b3e9245f4fb0f1e59b9d047928b4c76f1bfd8873f5397767dd510b87bb0f81c5bab15fc567d29" },
                { "tl", "1ae30aa6ed70a036e10feb96a06bd55180fb527a9ff03b0af36296a7b09795d239a74ed2eeea7a3dff745746cd913b59bf870d37aafccea0b5973962d485d711" },
                { "tr", "17b22a87fc98e989b932fe4d2528f6a8b4be5f603b8141f62df5ddadb51f17bad2ff19fa3bbae4c364ae5ee4fa03afcb3e7d3b1c687511b3f0ae1fd4648dc06e" },
                { "trs", "653b694577993802380b7e23c558c7681d139ad7a1e49cd856f5ba7f41ab89e30bda86b8b45e3036b3703ea6a9e488606cec497ca3f6cd7d7b332a4d88258786" },
                { "uk", "c4a2f2e90fad92371548975dd4b572c8ec9d5a82f6c3093ac23582aae1b97c1e02b5cde3d4aee70f3599ab719df5ecc4fac116f1af8f6e6213a1f1a8ead1b2a8" },
                { "ur", "c22d0b84c8366440051f7e6174ae714f33207d9b3efe7d05e6f2d9e05b548dd65aa8be1d4e55536a6fdd1f7278e0c99fa50611e1e9c5e264fcc6a2d246c2a3dc" },
                { "uz", "0fa61e55743a672677625c85ec4c8f79668b281d5adde765d9814242da0a7591b910930a3bf0fb88784ab11c82ec256938e858f4cf0358b34c213257f4ec930c" },
                { "vi", "ea3a2c43ecf7c2d557e7db0ab15f932f5d7a1fbe1f90c034d2870502c8314eb9a5f474a9d4ab9897d5f5ac03b0347996d0ef643e8f988efbae85c96c203f91c7" },
                { "xh", "4fdab35246d4561984b239cfb7bbe837efda1e8a7e1960d7dd7c258561c9372ccbb23a6e2cc4a6247f10995889ae7a017b0cc89f4032dfc621ac3c1ec3b35f09" },
                { "zh-CN", "7befcafac5d9039515d68b3c0fc9a46cf17d1ea4bd39841e9fec62228671d0b345a3807b37145864b1fa3fbbbdc6dbe3871a59e8a979038b89a5ab5ad72048b6" },
                { "zh-TW", "6298b80c7dd4b70e9c0b239ba8fd69f449656dc64e717718d1287acacb55c289c1327ac61a56931e567229e37e1d690e995a7e021b9dedf298788d6ecb054026" }
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
