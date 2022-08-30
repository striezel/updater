/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "105.0b4";

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
            if (!validCodes.Contains<string>(languageCode))
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
            // https://ftp.mozilla.org/pub/devedition/releases/105.0b4/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "16546b9b431523bf343ca2536c79e0f3d0f5f157eff1febc2523d10ec63e1ae9e8cde6d1a0e9d9186c4c4de5b9e1b2347ecaf20fe42f4db71516959251f54ee6" },
                { "af", "7c7d59f680b4d21c11a17e2ab569c5ac4364a908cf3dccc0037cebb735f5fddff8c878f416e87da22432c9344a2eff74739b099933ce8a7dbe0cebc86114f548" },
                { "an", "bdbf75a4b3c2593b25c41236c3af502520d1b3517536492f053ddd82736a4ba94582d7e9c97c98e05d53e0f2d651623da4cde67439034d0b80f29b4dad06a4c0" },
                { "ar", "e3b48f4fc3bdbda959e48a58cce9361043202aa7fe31098ebb17790e86726e4a74155a1b61a73a1c4ac11b311103601c99a48aa8be45f2929b50ac54a111bab6" },
                { "ast", "05c068c86842c8cf7d215a87603697e1892d0d94aec563110c0cad77167645f4906c4eda08c3da1771f033facc0ebe771ccc2e12f4190a68116fc9ad687993db" },
                { "az", "add73f733580fb7f05ab51ff4faa74bc439fb6953fbdcdd9917057b0fb7c7d029cadd56d994ba7e5e79cf7eadf3dbe77fb67dfe99bf631148590ac2c3bf4a35d" },
                { "be", "7a45c51d02b58fc496ee98838f82b692104d1a08de29024e92a20c6c4ee9d4684d9a225f975cda025594cc7ef45e56edc6a4400db20f1505804b8290e857a132" },
                { "bg", "44c66e1005eed0f5b3ffd1c99c96caaffb9492b78ffc9705e6f73045b0269be37b8b26854f60d876bfed42e65bf785c56cd1735e60736f9a841f1afa3e85ffda" },
                { "bn", "447bb4e188a4d7830ce3f6064ee539a8b89356a87fbdc900e537bfd19e43038fc0d7f248ed2de4f82ed4c7254d0e161ebb56776f4dbad4ccdb82eff11d7ada01" },
                { "br", "c5d0f3df7eb8385ee602d868c1ea811897eb9d28171463573e9d736f37d1382e2aefdbfa1129a64a6236850055daba68e40296ccc7b5aa695515b7b79991a376" },
                { "bs", "4bd9953499ac8ab6bf1954dae89a30295cfbd585945cba2cc3480965ffa7dba725cb36fc6dfe4666daf9bc16b89bc296339f91104cea3ce9b9d076cebd79e31a" },
                { "ca", "58c16755d59f41c590adde4f6e74f6dbfca19e750145114b48c7a0e808d03fa913025faab068f4ecc1e85e90c0d823b9b8fa93a83e3410aae1e6d32379ef62d2" },
                { "cak", "0c133a2af9290224106e824d3d15ee32782e4805676a097fba10a556171eb74ca129947ee4fdb3530182b4df770448b335af818abee797ed7b3d700532fc2594" },
                { "cs", "6a1d5613e5f4a303f367946e79b5a58f53de6e0f67ecb7f6d425a7a7a71aa2a6fb6a0ae3533f043ac0cc656bffe58825c7242435dd3326dadf9a8daabe201757" },
                { "cy", "58e55c988d9149b65d890ccdc4bc44b4cb1b1555df68f0bfbfd61b23a80fcc8498f9c6e5dcb88531704ebaffe08d3e0359c22a316c36b6ac8d1acac05c7d88ca" },
                { "da", "f8c4cb7e3c2536c84ae88e85eddc1d0dcac3524cde28f4dbfe23941741a2ed4393f069d4303ffb24551b0ead4b68b322eac39ed4ffe1986c2d56466f6b0d3cc4" },
                { "de", "34ad1e5b8b140f56789b508ca1a67862f676b8770a0365277e99e1305b9e8a4ed5ca64ec96337dd7fba4a25d54cc99ea8ada2bbc2d31cd5475dc00ad011c5e6e" },
                { "dsb", "1feb9bb014febb6f2963cbca7909a83cbb65913fab7f75436cfed5ac06d5cb2e9215fd099ddec4a43edc08bf6c0ac79874f9a18aff3e455e2af2a9707db8af3c" },
                { "el", "6c69610548fc766e8b33d90596758a3af264f02ca53567638c8bd40c43e3fafce15cfef8b9a62c74d101fdb553662181186b8826797ecaaedcd0d9c7d9f4fffd" },
                { "en-CA", "dd0ba52b1e36a188fa569286f656ec77f98d36caf2c38345ddcea4fafe83caba342e66011f05b762ff4b12042b1c09adff67fbf66e65f6461d0c8d58765592ff" },
                { "en-GB", "29e2132a85bfd8099bdddb071ccc8da815a06c06b8352c1c508e2d886a4f209966ff644f503372faee23c6eb94ae18a12b4507bd0c585327dd5bdded695630ad" },
                { "en-US", "2844d69ddce7dd6a9696ccb51834589c58cc3e49a4b8ae62af7e3f5b2e258ea0b8beb76e3f1b6df4f1ffcf531c8084b63b339ac7426d26213d0065f2b684e015" },
                { "eo", "f2d9062fd8ed63104d0b6456be1cd89053acc2bef2a76ced5f3e28b540cddcd102576bd57157b0abf93f10bd4eec6e5c83a70e96cfe4f38c30775fc9bfe355cf" },
                { "es-AR", "7e8a588633362e1e8a3d979185f2574d6faa3672dbcf8315f1aee381e00f8467cab9743aa5955447976b8bb1eb87d5df115d2f0591fbcae4ddc90050a987ca73" },
                { "es-CL", "152198c3aecce79c53d0e63b23c8088584178e9bfb158c06feb1c200a70f31f128ca96d5e03c5ffe65d6b022e78203f8d7500b94ead08f4c9c64a05d4b43288b" },
                { "es-ES", "e694a82398c02f5b8c53f391dea3e85d937e562f6c9d638030f23104f9c7cc7e3dec5e23cd00d262263d2af240beff157a65c50eff396d613ccb7d19f7b631e4" },
                { "es-MX", "8703f59711990b7d7008ea224fcb7fe21a33fd0f2a9d82515c088a84fb2c11b6c11ef7112f8b4df95ffceb6f472815884dc65b00a0028ba523c68d8185126f91" },
                { "et", "212d63f72afc4833192629637aecc3693a7f4b808ef31fb8a1b32f7080d1640c91f8e112bc32eb96ba7469cfade2debc20827b37a08daeb0f6f2c359cd055605" },
                { "eu", "15ddb8655009b8e63b35a96051c31465f4bc3ac8fe36f356005648db0910ea16d050e136f2a38a55e293de8313dd3b31dd9c56635cb5deff144d9777701738b7" },
                { "fa", "7eb4cb70cf77e1fafbc6fb17cd69f934314b15b15b13c85cbe6f4fd092a566fa5cb224a768960086e2a1e1fc62daf4ce3688fbfb6fcd24a0defb0558d63b38f9" },
                { "ff", "211999ecf0dbfef1cee36da131d68f928d0fd4cdad771c8103d872bbb9b7ea2d621775bad9af023e661e398908cf0a0fe57339ae649a0e7a5a2afa16dc13fc3e" },
                { "fi", "625d5414850796e192860ea6e1c5602a9803b24ed513cca31c26b1f3e267f96600efa56eed4c8f226319c3afde210f1b4f4dcbdb8740e93b6a5f55521266efd3" },
                { "fr", "52e89008d0bb85eb1d3e6698909b54e26ceb6c29a2b1c3ae3e02978660a6aa319fcc46f0195003cbd99caa1bc4553638bd39e1ad1c1a9b797d8d99ca8464169c" },
                { "fy-NL", "b77acfdf61116f824d8392124c361f3f73ff2e1668ee03fbd91a024a4ee39e475fd5703c6ee78ad3d53d0b5da1e10a1d0f5a80c141717b1280d296a2a158709d" },
                { "ga-IE", "c8e179badc5c10c2c51de20eb0c433dfc3f2da474652313ad072e45b93937fccd1dfeb7a0c86dfebf0c2628865851d163f97db101155b7306914db0ef6f2283c" },
                { "gd", "1ebbb7bf76b42fa813072b55066911276e07fe0fbbb1a468882dd69d0e5ae7cd2cbc6ff580c94396e26abaa93fe6a39417dac80b75241b335b4393cc625d4d08" },
                { "gl", "37c55afc2dab615e33eece04029cb313850fe957f6f13c7a85fa6c8377d7f77b80da978d0dbbc23dc68aba87c659c49ea3c6973cda279d5a0cfb64cc198bda75" },
                { "gn", "9b56f4913f78bfadd56e71af77370ce0bd8f5a024e2d2e83af0370eb0c9e6ce53a743b90ba22bfeac9e7cfdaee62a1b60c33b450701eaf97e33d750a449086ed" },
                { "gu-IN", "bd9a035b6da34af83ccd367c5756afacff8a6f15cfe06445d1ebebb1aa8d69c696723cea6584e0e1c1aa5f897070472554aee07ad7e5e9b40229183fe15603d7" },
                { "he", "c1022277ee64d9e7518ec544066bba827de03e4467620286d8027c8c992822e6c90b11edf3849fd7dd299d2511a997833453e07dfa233b0797e8e99909cbe452" },
                { "hi-IN", "9285272c16d20823485024a36c6595f7979b8763c028e59f12c4effeefed821791a4928973e7eb50439193f34e504c7f8b91833ebbf63f2ab1eeb90ca786c4f6" },
                { "hr", "ceefe07f9da903a06d28db4b55517b8b8dc8ec2f0607b3f9d09768fde749f075d00ab7beec3e1873f25d36b90254bc5c73122b21ca8718682988ff66150dfeae" },
                { "hsb", "34983eaa93f11e1c3e10aa0f0ca6b8e513c00e3b93ddefbb60534c54661e07ba8b05f9b6031ef68717de5cdddf9f45729513e03db70655ec35a098671043a067" },
                { "hu", "367ab95993c599c8678a91905bf1c32f2334b10771a4bfbe609defd645e91fea95eea4f445a6c19d293e8c475b5a18f5dced00626f5c445ddfba0b0b07e4831f" },
                { "hy-AM", "8e903c9aca70ad41c7ee188088e10c501cc9f427eb385c9b4de9517264808a2a2f775202e4c3fc0b002ac0fe9b293de5648b224ab3eba1ef6e3cd66c7e587286" },
                { "ia", "0bfbd516ce6c6bd594f238b668e57bafdca24d36284e5cb4835f45df0f541ff8eb9e3e1ecf789310985d431abee660841d5f7d78a38edc99b36b62d6df2f0f87" },
                { "id", "01acde9ba35e5d14c4bf7a26056d63fcef97e7273777018ec0a794ecb5e1829cac262d664da4dbcbd6d45e38dcd6f377b6a79e32b92d8f3fb4afdd07e23bac44" },
                { "is", "6c329efeb6191c837da8b6af14781f4a4e10171010c993ce0caaf9f9ce8eec3932d14d2f37d78266fc31832abd28b4bbf91ee3955084df39a83bf94567e22a2d" },
                { "it", "f348166f9dce145f0dbb2f068f667c0395648b015edd81a299cdf08ac0f29cbe1abe6faa9968a17b19869f5bc992b48d1365a7d8c77b4852686ff7e81e3e234f" },
                { "ja", "2211a5bfe7c967ef1a0a7d690c4a0afcfd3efdbd42bee0fb8acf72807466af9d35dd067954dc9d8ee610323a2ea180e719018f4a37580eea0bd0816ef31de31b" },
                { "ka", "5827ec37bdef32c8cae3abc613f2b8e0867d50ea46fbf5ba4237e667c4ffa66eaaa3ffe3644944046bb46b433c3f66b1a68b9cbe1f79bf8aa631b910a831f7a5" },
                { "kab", "be94fdbf21c482a1886100f30a03d98eff52dba2007a2c5a5e1869002d3a86fd1b40d57cebd06a06ea07ad9e0daa50e22d2adfb91f3ab17a208c357366c35a89" },
                { "kk", "f9e28c07a1cbcd40755176a8a1753808f1e6bb19e76846736048d9aa15620e57a098ee6b6fb2a671cc94cf8bf66cbfa6bb3743f952cf8722b84b722bd1b0f25b" },
                { "km", "024185edd84154353553dfe35b3c5147693daf0809fc5ef9ffc58d57c0fd8cd55b786757e1d64506c811cb3234662b76c0ea9680868abb6af5b242037d35c3e7" },
                { "kn", "d5c2261cdc62e6ec1f13bb6302b3f24796cb2a272a4fd51b5ae2e7ae12245f43c019eeccf9a5b5e005976a680130cbe6cb889f01c52876dba65b3f15805ad72f" },
                { "ko", "45271677757dbacc7ca0d92401c33cf682f5b4fc91393a200fb2a63a0e2f4d01b6d8c7aa84a28ca81b98996483d8368e4d634ca51757950290c22efdd861f8ee" },
                { "lij", "de9db3f67126d3fe65c1ef38dc6fedd71f6c1e86e2e9859ada67f8113160327b1e50bd559a8db6ee046e8d360169460dbf73214fc3ad2f02119f1aa860a9462f" },
                { "lt", "476e854dd99dac3aa21921fc4d09a5abd9d6573b62f3efd86fe06ee38691017bad7a33ae78fe43211360429151a32fc926a395567492a25fcb5d1c66959e4789" },
                { "lv", "049f57366c58a1c3843a45414e86284c525a54ac387f6eb43f2a2a69a6171bafc894df8359d646fa53161862f1ebf9895e77d008cd9252c275c53842efb2c77b" },
                { "mk", "55383198bbdc22cc260e16154687ecef6536590f39610719827f466e9d4bad3a9ffb22f4eb452b3e65a3b1e8be4d3d509e837982696db52e8bacdd6b9cc66004" },
                { "mr", "0a61ab5c18d2dc31a99495a183137c47bf3177f921f3d354d43d21997064bf38db603bbb86d1b74fb2827edf975461e57f2d36018d0f892bb8576aeb3eaf6d4e" },
                { "ms", "eeedef56bd91b73c62dac1899114dac05cf7816d983bef39fc74664f45bca49fe68df7bc72eb593cbda3257f3500e3ff0914c53545d2ccb7091b47b2e4aafe85" },
                { "my", "c4c75bfb3d5c6eb3addabd31a985e6b2c59234f8097c0c032b475fb65e48a402904c93af24790f88b1831917da13f399ca24cfdabb96d2724d1dfb4b87f3d12b" },
                { "nb-NO", "d628edfdfb0b97badd6ed7511b41eda8083055adcc9ffbdb0aa6187403d64e985456e38041596d454552a1a24e3c399d67801ec9ad402534e6192f7a8bf594f3" },
                { "ne-NP", "8a9c5ba9e00efd67fee367c901101f817ffad480ff23f14bd248388c6fba5eff15fa80d8dc7d8f72967e826bcff249a70ef0a9da6e3b1f8131a7cbff68067a11" },
                { "nl", "8f5ec656a91bb4f273570f319f86b94ae2648ffd04949f857d096138d936ce8a07409897a3566bada95d9dbaaba0166f305b9216de722fedbbad1d8bafe5b419" },
                { "nn-NO", "eaa348a61efd1f5677a8ceb6a9feda2863053711a355f9dcce5700fc275545e5e1e3a93e4a77eda30a0333fe1b782af0ccd8f3d302d4de1d575601fe105db746" },
                { "oc", "c4115536e6e475a8755017bb9acbcc381b5910a451c09b5de87c12c09c9183e5cf74ea917e1e269fcdbe2834462f8c13ac0440e5c5dc31de9f7d1d279d3fc7bf" },
                { "pa-IN", "887ee7afe3824adaa4b02525c74855fa62adb1415a03047ba5aae1f5ee5be0f4f2b7fbc677cc9dcc187954f86a6b76d7f033d091216bd797f0be5bec74d1f1ac" },
                { "pl", "3c24b40f745984cfb6f3362f96bab3ee8b8109167cc5096e4deb9c6f94df26b7b646bc821f334720903156c49af72aa3aede0d58a091ecd3f7b1d2d18616d35f" },
                { "pt-BR", "3f74f5f950e4f2b52d46e3c0d29dec70f623e83a88f4f2648e3a0d5ea3c56e869e5468f1cb530b7f5a2ffbf74e94da242c2d7a929f3c59d71d98645971f6b6a9" },
                { "pt-PT", "e1e90117088c003938c5ca026cb26a5b5a98db132c3c8f6461d634a3913252bd964b9172f0a2626440096fe25ecf839ef72dea01872910fd1ed1d03f8641c87f" },
                { "rm", "720df44bcb42b756efde138a53a229b5bca34f192b379074256dab3e8ea7dfe4f6e17ab5eea8407bf2e73d0732e1737a9b02854c5826a01a507da8dd1c69e9d2" },
                { "ro", "a465459f8c957b4fbbd9aec5c185247ac7309e7d795ea953bad2003aa89f3ea1735831122a2d31e5066b9ea270d940d2f328ed6945cdec635b36efc1b228c745" },
                { "ru", "bb3c6da0bf56555832bbfcc413e23bbd2c8201ef0f460f4f0d85d51431dc71caaa2ab99942554b52e44b2872fd7488d3a492f78f8d89bd5165db309ea041c4dc" },
                { "sco", "438b8604a2e22495e8a30bfd997b238482d4ca64f38c67f4485b7ae8ccbdee3f7f09de6de96dc579990d4494fae818111d7242824285a4aca1ba3b9a4dd9e0b9" },
                { "si", "c53fa40abea39bd2410f2586dedd8073c96c8715d75f74a82d456da7b98f713132d381f32d6b01b1cbbc49a8dd04f5fec2d6e722302859f82aa848541280d4c9" },
                { "sk", "57e71a695ef0dcdcf8078cc03ac279c447e00a6603dcc5f106a25f2d15f8a70d15518a3feddaeb7f8f83120963731f9675c9a590440b4fb275ae3d7596e22046" },
                { "sl", "44af9d7a19020e35b2bc29dcb2113bbe9e728acbbf4e2dd7b195b281f7a1e980077f84f1ea17711fb5328da7b5ab408e0e4a8341fb9a9b432b8b7bbea17bf1cb" },
                { "son", "7e3eb7d719ef9f9b8a45c0a8124ac535636a7653f5627983b660532a94675aaa35b12147c4a00b341df916e467aece3c347fd17e12c4910a3160d5f35a3e110e" },
                { "sq", "70a2e56de4dd46e241dadf7e010ca7ffd7cb216bb0d070e0beffae24365afc069b4b291d4a29f8fce03262799540a686569c9f8511ef1cb47a048ad5d2727ba3" },
                { "sr", "ab6f2e494aa427f6587ab71b0169a8686ca5811b7fe0f62d14de8a41e888985d9b3ef7a47fece89178276941ead4c930945a94b325a8a7b4fee9754fbd42384f" },
                { "sv-SE", "0ca8d82cc2024dc493f4efe3e97e207d81cc6f4493dfecdc0abc3856565edd4b339743f316df24a1475d07145a6c1555339e3995178b8a116a615d6910e8bf95" },
                { "szl", "d9d7c8b7d2ad189be565107beaca7f1f0b31c1a439cc83235c88abab13119eb5ee1a051a827ad2d919f60ec34a7d6f1ec260f3a4976223bf63a62d5e2187b313" },
                { "ta", "0c0a3c8474df2e9a131d61d53cc5df186d4c97ab0d5f8b1f1d3ec0125ed4f2efc4c628efa62b28ab335a650dfbcf32694b82811cf61488090d17f784e4c2dbda" },
                { "te", "471eafcf77293853df14bbfdc9191608c15a896e2fa9822e949f94e34c6fdb60630b241b908b4af9836bccf258137bd3eb29dfb62bbca76a103d4f25b3d569c0" },
                { "th", "66739fd1e984033faf7c29027566fd2e1e230dba9a091f7780bb0fbdd6f625a944d96e373a48f678dadb737f73cfa985f4139f6eebc280df6797daa9324df057" },
                { "tl", "948c4cf21a32c3b89dcddec6d5e8324aa7875b36bc6498d7f980d7a6dbb9919e091acda9cd183dba59df40393963ce3753586a68dccb8a3ce6044c171dd1b2a5" },
                { "tr", "137279317e07cac3ae045eeefecf442aff296d5a152719403cd635f501a16ce07e7cfc55be0e8ea6a539bbe4c0501774dc514e5df8bf9a537429cde6d3b67bb7" },
                { "trs", "d947201ea06b64b62c378c6c7a1e55facdde3b363a4b18a27e366f6d4fd5214efef4a0a1b0f2a404f72f4a98bad63ddec441a1355402112b35c34365d7e98de4" },
                { "uk", "0dbd8011a9016a0ea44b0104a05aefd3ef63646ad3a4850c72eae7e232034c65461532dec40bb929c70f91607661c260a0ef05703cf35d3467b9576ed5b2ddda" },
                { "ur", "daac7d9f26cb270283e38a193226324542a2b2553e72b0898bb73d8da960e73d756fa19e282e3068c88ea6ed637995f0a5ca3d9ce90128fba4f040f6b3204e61" },
                { "uz", "31fff8e303438505312ed982cc7f1fd010e5609c2e7344aa243bcb58d6f4511af02eaad3383fda0bff1cae8e127a6d0d4a025d48aaeec377cbd8c23c39e56eb1" },
                { "vi", "4b78c98b100f5dff278673c926280cdf8fd2bc24b7c811eeeac5f910cc030f4b90531567e3b4aea33736b9c4a9cbeae7adb192d8fe4ac4090ad1a989635ff55e" },
                { "xh", "475186e5b28361c9b1c88181b27612fee57a0838a69dcc2ba160b19a3128c782ff988422dce791decb4cb68c1f2f9f585df3e4c99ebdc6d893161e079aaa36ab" },
                { "zh-CN", "b0d6b34e86a89b23410ca7093ce68ea1ed2bad0845ef218ab231003bfa22b53334e77235fe07fa98f17308bb5be9f245ec30a721f289da6f0a76c04f7c2663cd" },
                { "zh-TW", "24375c1c9c75f6ca59d46957b3704f18962bf4550ccd2b7890a7c5ade2d9181c72fa5fc06ea4aa77a884c5fa4683dbdc1654bd7621a17fca38f261910f6412c7" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/105.0b4/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "af8c92e350dc94725ecffcf307af3044edf3269fb708f938215bb2320108054c79e05c973a9d09dd9da64229eb36b4369a6805c836cc2c9ac5636fb1560b61c8" },
                { "af", "4c97ae2be805beda3c119cd49969a0e583f8d607e05a4fb08ce72bdda410377d76e3aef0b88f64a4ec7a3f520170dca879464c984bb69f8491a112e51166c024" },
                { "an", "a1a2db9f073a104b4fd573d91b48b2e277c22ac6470992a325a1a7ccb07979ea12db00b729e11cf6b35ce4cb27a3bdf334b0d8382e3a956e285a5011db01f38b" },
                { "ar", "26f985a048661d2cd78c5beab2ac369905d511364a7b5de8f11bfa4a89b54008067c03be420ae7c4166787f1fd5e83ae6ad8bfbf57df9050523d3c8c1a30c56e" },
                { "ast", "e335fd36da9ef4e890dcdfa2b03fa5ff20d11f50b86cba39ca57a5c118ee147d9d34e7064d5c6bf1d1e57c38ef1a089a37af14ecbd65cbe0b4c14014366292dd" },
                { "az", "a522515f0f51066926e8d3a19055be3a1239fd5c50628024f936fc8f91ab558df8cd141c4d28d7029c8454fb8133d5ebffbcc075fd08ca5178f7043bd7e1ce14" },
                { "be", "92a9ed156f432608f912140d4b4b3e4a9732d58c0d052af0393255d463f301f9353fc2084d797e700aa5045c254495a5ce2e392a6af39cef6788c8f9417c7955" },
                { "bg", "47198ad386c03befbb342920ccf3efa6a3a226c4986dc1ce94f5b9dbf94b7c2786978807ef8b01963730238ac5d282c10385ef0db25a748e8830944e00c75dc4" },
                { "bn", "19fe0a1479b072888907fbbf364d980a3689a45f13d82c07f6e20c8a3eca2a8b9360df81a5384e78b1f6a2d30d8cb08f77925fba2404ce465a69c1b4677fc209" },
                { "br", "31f975b1f08c9c024e6d5ab3ddc6127daccbf547b94b4b639c3ec28540659579f6fdeb6bb17631a61b6e08a8c5b655b168261e9227a9e6fae88f560fc1e32f61" },
                { "bs", "24d8a8938651a6105f5a0c65a0165bdb6bd918e42acd264f694f8a1302711e6b6b3e2e68897215d6257dc899cccf2960c0d2c2f7c65688c14037c57304a9c9eb" },
                { "ca", "70371fbd6920d9b7bcfc4aae101f74666b390e6087533b0024110c860e365739eaff7656d41792a7b08e8c27231750e01c94b8838884d869564c9af46818e4a4" },
                { "cak", "b5b3990b176ca241d6f621f1ece115de7c19251bddeae6081bd9fcbbbaa21ae51c2972a01c2f0dac7f2b98b0fde652c4caf88c4ced96039edb11865cd82198aa" },
                { "cs", "8ba1a0a2271e4e59efb3c1226dcbab9cf4f32b57faacdd4a00b95be5f71bd69bdb06b50b81dfc0bc13ce92434839299f378ba575e6b506ce9d7adf079f4615b8" },
                { "cy", "31348899f5e743dffcbbe2f24fcb4fd3fe8a24b64e8b09d9688ea6efa13a8f50485539c4cb11deaf636f49d3a8d24d5cc64b2de87e139d9b33654614ab219d7f" },
                { "da", "9718b4ad5518ec4dcbcf81353c6ee003da1b1259cc7672c0d234a059a5dac797424e8f49904bb68edcf0fb2b30b758fbd5d55e8870378e2a1ddbeeb7f09e0cdc" },
                { "de", "66c808956ed05e51a1ac9c166d1e28c8173b79f6007d76135103197ca502ce2bec8592c283311dc700d329451fb8f1fd37623b52d85cb2d2def1f9b5b6b07078" },
                { "dsb", "96341d343814eee218cf544404c4abb15aa1a79300a5f5964c29bf92c617a64cc4ce9c39ee084f8af6b6c9c6da4092a2c56235f05f1e1fd2b669adff43404442" },
                { "el", "0b5d20b5b54f9e1d5db34508393ba048152c21107f0c12183e87b2498c7570407cd36a6762676fc2d396f6779c6fe32d3993d20ae859f6ee7387906e5e2c9e34" },
                { "en-CA", "1b4ad7801657b9f23cee169e5e15acf72c51a6d613733f7827b7d532c9c691c016e6606daa0b101fc4074e33769712e335336e45ddcad86e639c28b418d6e643" },
                { "en-GB", "f3cb62b086c3ae7c508d43f247a66bc52236228fb43128a13401fc1fa6a3c8982595dd823f69023ede677737a73847677ab13df989d200136ef75886f3097fb6" },
                { "en-US", "0725d35dbdaec335aab8423289ca741d209f72b47845f128796202b87fc2f6da31b85718e969d7408f00ad29b3dffd576239cdaddf9844bcb0d5a002e8d17544" },
                { "eo", "841b09d4b75de6c646d8290663888c150e0e352e29ff6f50e4ea14e8e3b6b4516d5fd2b57ddddeffd5ce1c7ef56132ef71f82a2c14631cc9c3d775a82659eb94" },
                { "es-AR", "29e5855d31e14a67dd0c6d3088eca49fd22a53eaa4d0bf10094bbd8a9a125765edbf56ae696159e1135440cc18625280e45f2933d2f23a2162b488923b77ef09" },
                { "es-CL", "3668dec095ffbacb0c463f41ac5cd6f8c80a7a7220ce5cbfa7fbdd217fd1e4fead6304744d7942bcd5e62bd3c53423b5ed83acf7fcc2bd773f8f3e16c63f4be8" },
                { "es-ES", "e682d2dd8e5c545dadc803883f4ea57af6146f293715a47862c25b1d5f7b75f24c76bde7136b59303de1e3e17e9449a08ce19d377d354ec2e44330f0328bbf0a" },
                { "es-MX", "714292adb178a94417043c98ff5e63cb454e1b88b743bfad210e73c6138df21ddac4b7759f2eb4f57d62b6dcef8b081dd10a4f36d89b999326b399f3ccd24350" },
                { "et", "01cf5ddfb36bda1239a54851594daaa052e2d37d7e7ccd3178f063a37bf02eab858797e513e1c1167c39887e72e8a6b4ec4ba5e118577119915c8663ceb60f0f" },
                { "eu", "77518ca6f3024e316a0ca7b1df3b07d6fe1373bc8ee896394295a54aae3a741509e8b5ab6891c323d874e3f24849aeb7a4933509a85e6b68dad43c53663e3878" },
                { "fa", "e89891158f5c09d89d69c7cf9141bbb363b40641459925f3e4279589abcad4c82053ef50d7f3826fe338c5a522d01d5f54fe8eb0faff58135f29ed6f6cde6caa" },
                { "ff", "e415267f25cd975f3f75d2a5eb17db2fef6eddda8b30f5cf05b4e435f6bb27c9a064c4620d1a348409a9c44cd2ea13067c09605a99ba3cb37eabd75ba42f52c6" },
                { "fi", "247b8c6008a8eaaa6eef410b470b04088eff5622d1437bcfe5380dfdffa30482768a47f69c688ac3a600ae793059fae4b35723aedc90394c793e3ff21579419e" },
                { "fr", "735ae686b4a1c7818454fd89aaf54e6e9a5b7988bf7ab411c2d41f82b4b7a0ac0e0e8b557ee9f61f894bd0078d867274ff62ecb229aef698a2cc6a209eababed" },
                { "fy-NL", "286279bf874e8cc2364e48385f78c23fe1bac082e533115fb21831e7b3a8326caefaf30f6aa29d3c7ff553bab0eb153eba98b17b989a783d9fb8f4a37f8a45e1" },
                { "ga-IE", "75ade3ea65822ff8068a3671f402f7fb0b73df47b10ed03d63346493b981449289ce40a9394bc13335e6447cabe3270efc3645bed37d89502bd6664b9a5448c9" },
                { "gd", "a07c40902c929e3e4acf3e4ad32045436b6c646b7245f0169df8c5a6be21049b8760a7b5178abdaae97f125272c6e8d33122e772423c1b2749f9f00726752d33" },
                { "gl", "bcf3d37c9a1a6ec7f903ffb7e0e96ae057749ec4f895524ab07fb6777cdfceae92043bc255929a71c690370871f176dc56dd3b3236039686ab761b463129dfdc" },
                { "gn", "314e02e2806abcb65d0f562fd469fd0aa28ea857ad93c5935f29e9e256cadf81301d0d19f99386fc2f3d808dc2ecdc28bca911744d45e3c45035dfb85798e615" },
                { "gu-IN", "8048bdf16864f9ddd5f165c9235eb3d8b9859968c8b16873a14014a2753b50c5247514da9c2f3955e7b034001a8d89be0fb1a7791dbec249eb0d456f0b43216d" },
                { "he", "f87ec4edfbaf68fe9a262c54588d519a0bd22f533bd942aad2331734768c8f15be818bbf1c5b27688635e1cfc39f7078f1593eb26ec3b3de8d3d6c848752d056" },
                { "hi-IN", "70cb105d3ed50d109af8efe40aaa5e2c3e218f1d1ba83203745ecf52f4b0cf7eaf3a16d6d702cd941029ab69be28fecc488c9c37c545b7917656a6dbd3fe7adf" },
                { "hr", "1a497e08119238fbd3fc654be5e67e501c4180579258caa794585d708051446d47062618b8e997d957fe1b83b9f82a7d5db8932ff364cfc7644ae4dc041347b9" },
                { "hsb", "88db359a74a3ee3d037127366281efaeb84adf4050b8a75ee7c2dfdac6388c9056a71f5f478c8793ca9f6b990975c708f93c82613b131d75b55fe9bb44240e1c" },
                { "hu", "52f4b881d4ccf47b211db3c15324ab1c20cd1bca6865bc20fcb4d56e3cf0a103597751117e457867aff5409196a807af9b70fa94e20eaa80182d6a58648cae82" },
                { "hy-AM", "f04bf048a4cde870eb398d4794ca57ca5ccf6aaed828b0528fc6b2d9e35e5210e2fa8254f76df45d23a66eee42a544db8e7e6f0c9dc4fdff15b654bb0c6caf1d" },
                { "ia", "07f12bf782e2ed4bd534c65c59adc4ae41afd097b81c9587b01fe1685ee7e56595f0ac31b63143b5532ea70a09d7ae9159dcaa8835d49c251e1b96591ecede80" },
                { "id", "4957dcb680fb74936457f3096cfe0f7ddf34e4dc3248ffa4b40a924c5984d5cd86e4419358ee5f83b044e6afddbab018de1eaa95ea8928acf156fe25f7d5459f" },
                { "is", "4ffabdc7910e22ac65a232f34c018c28c9fe0140a7871ac62a7c5dfc58665a63ec45ab206490cb84c29760106d304c315840a6705d1b6457193e24cc4d98e065" },
                { "it", "b109da73109da134f50ae28778e83bccc8b3d487530d37f6f3357fcfa1b48fead48a0b3ba05eb8c77e907067459817c93365dd5640abf54984b1db48115738ad" },
                { "ja", "186e091f1d023e83b785a66a9a35310b8d720c808ebc7467aed228ea55eff9a013ec01fa4c2dbae62e126703cdcda7d022e90b0be203465c78d0366ba4fc32ed" },
                { "ka", "ab8eb2d24e9a0b1e4ed86229a007d5f9daef988ef276dfa105b78d1af34100e1036c2c3dc85602e6f266cff9d0423c2872707e077e4624da7cbce7352e328fe7" },
                { "kab", "eeae598a091ef18d975cce0d8f0caa7a64d718c4b7557f9c23742a21731cfade4ecdc1ae2e287d0df86d410cc8cd0ca81eab418085c164ca446a8dc042affd79" },
                { "kk", "23fc447845bbc14d089d49d41e387287fa904a6633c032d2ed38c8681f8097994f74d8626a5e4c7cbaeca1bcb5a65f2c92a41154d9c95af1fc6fe99c7f2698cd" },
                { "km", "16f2b82953353de89b79fc26dfbd00dd4923aa86a4daaa370b40d62de3a20e8738bc7760bdcb908e79d14f22b3d47287f3fcf0ce9bc387fd46f2a1c7543868ee" },
                { "kn", "e780a1eb2f5cb5e9b3e2174f3ed2fb161f6a054685eed88fce75de62f4659145a85240499b30120e763f5f7489757e246f99cb15218655d6618552830e8e7c3c" },
                { "ko", "56637a6628f439bd5b860414222e42b351f31cf489f20995397981334893abc52ca6a6735098bbed79ab153794de9d93c25325c6713add5a4b597a9a85aa6a25" },
                { "lij", "26f466b0441d295852e39aa8d3fd0988a2eac7722bb2b4911d45844993b75fcafc19906abedbb07f8eb1b5164bb83531a1c5383aafa035a760872ba684af86ef" },
                { "lt", "00508afef6794c33209cbf3577459a29b2ca0c96c9b128f2cfa529c5b78960e233aec1be0759ddfc967b55b69203479bb6e2262f3b6467a7ca6facc8ff0ce5f7" },
                { "lv", "ad8b0ae22db7f54d9a17987d4e80d2deec9e4b40efba205660aeb5e9d1e2dbeaa88b6eccd5fbb257380aefaffa5ddcc21103a8e615e63d446668745a3baf3209" },
                { "mk", "5e6b9ff21912a11dc84949d2834b282d29ea459edd3ccef9301828aafb1f7de53ed9dc4bfa8c03107f78a6e15d32daf305e822617477d452cdee4d4b29e3dfa3" },
                { "mr", "b938ad32114dfc0ee7fa22f66201bf8048729573c8b8b909fb0e776ebc3bb32dc3355a6647dc028e704ea5c78fbdb88a82d501f1b978b52a4f1fc5d9af2bb0a6" },
                { "ms", "b5b947e2f3922c5d143222cc24031dfc7470dd4b2433becb75dddd350bd9452920c9c226041200e5bdc964c1ecc47dfc0c874271b1d88820242f6c719b26472c" },
                { "my", "96e816fd72a58b53564bd79532cde7ef1ab06758bca9b96ca4b974e4aab279992dac13b4b5c92048404b4ed5a288d9f882c9d2e9be8ff5066d195de0dbbb7270" },
                { "nb-NO", "5f61a6de3090bf887c1c4571ce9a6c7e50e7cea495d30e5cdf2c1a9207711e82072ffe4cfb736ab7d31ebb8a76a3bd44c7772da9f34562393904beaa951d7ff1" },
                { "ne-NP", "fa1ea5cc55de3f9db4d206ab570c1027be1c4c47ec3a0b1cbddca0694d830f3413d31573f2f311519d863d0800c4990c3e7483f326c2a51f0e66db8afe3095a0" },
                { "nl", "80a16cecf294c44904a411f4afa2a6ffaeb51de020d6994d6ae3a66d7bc35e9775ff01a3737da10806a8bd732586928931c6104c78918a69e8e36157be2a55a5" },
                { "nn-NO", "76c6192de169739b3f0e700cc140c0c69c52c3189ee236f9750882337b3fe31d5cacc5fd3e3e1fe3970e4f5e9508eb8c071805283e6474a90f585c0faaf495df" },
                { "oc", "2af1e02c1dc6188fd5a5491e5533025bc9c203cc71e1f8c22f44d0ecd128db3f195100272e55a13632fa06d9aa515c836b66c2789b509d3733816821be67e4dc" },
                { "pa-IN", "c4ce39c005c5d63bfa8c254cfae4914a0e8e699bc8f5a050fd4ad8a5b44f1f8700b504e60a4b88d8a76d562d49e425d39edf4500b3d0166ec9d9071dda6bd365" },
                { "pl", "fbd29419cd3da527b498d8400217332577d9c79816e76886ea2f38ad22714cfc1c753883872bbe76f9a323a87b941fe4c5653e0a057d1b93a4b3a4aaec2ff984" },
                { "pt-BR", "d9c84158bccd96d0fa6dcdc70f9ed390e156f6754663777aaeebdf98501543e2d72786ce21223d776b1f0d684e9b759cb1ea9a23533116428dfe094ec8e66f73" },
                { "pt-PT", "fde9745bf03b7b7e9adff1a0d758826955aecd03ade7dc114564fbce29049c8afe659d79615ecef1c35e0cfb89a4da11b935650581a13f957e58df52442cb4d8" },
                { "rm", "de63f3c9cbb74ca298a5e65cbd6c2e4f72a4bf1d487763fda7843b4837d6fddd81914876885ba913a20cb939cba48f2280201e4b9cc3fe97c4eee6b14244cc71" },
                { "ro", "e267082e10f93046411065f5ab6954cce5682142803236f9ac68e9bb4b8aa17157cb6d28c0f78e52ac3b3aa98b4a8521061f90ce47f4082b50bf8d79ca9b8856" },
                { "ru", "c0d66e3388035716a3d5ff320878ba53053e6e1733e90a54e9b38c10b01a0cb1b7f35ac6045de0ddc1cc1ebfe921ef59c63ffba7e4362fbf14bec6561d4a6b0b" },
                { "sco", "cad70548146901d64a476a6f2c9acb48ef0ac93be01f3dfa9b848b795e400c0043dc52f6e84ba79e2a7df42ead411715a7d561a4df355ce175d1ceadbe6daa4f" },
                { "si", "dc0a98c13d2f7ed7c83b5eb1af68607b68b757cf4aaad6d7991a19a4705cb1b420ea21431162f03b8ce746b8bc5f3d046d215ce16cbae93e240a4ee65c8bd98e" },
                { "sk", "57ffd7dda500d605ef5e3604c1640f7bc6c977057c484dbaf3177e079fe2ccc971c0f2f9220d4ff38e52604567f3d18b27cecbc0d73d39e65923968b3ac51db5" },
                { "sl", "b571dd69075a7a6282e2ff2649646d9bfa239f4f05364400edc0299f9937a1baecfa37fa6c2d77de96181e9b54d8a57900ff4c16cbcdc83d96172e4a178b6202" },
                { "son", "d0e5633f85258d49a4946a8315a1f8b25e4b4e32136b9f77e15e31832b3584ee51d2ed44b30a6fdcdb51220a37ee1f75b2568af54217ce05109a698da23f2466" },
                { "sq", "29cf9d427aa90f150fd625d00582d4159dc052f8eb73621212c1f45c75ec29f5deb395f1b77bfc62cc8a017556011358c554fe1ef00e6736c5d8b26dd1c325d8" },
                { "sr", "7320a360eb0d161131f87af8b511d6661b7a1aa2dbced36428eb82f16536992540cd2ae38dc6fb690fc7799c07a04c56f7d758aab31f7fa4af9c208e1c039661" },
                { "sv-SE", "e0d922d16d73ad41f2d77426a6e098ddadeef71c9de86ea98f4ce7b98d462de414c95fac1622ba1833726b76778340d56520406289061950a9c0a33ad076d5bc" },
                { "szl", "ac5fa6de56a51fe10f873af904420d6f8b7f58a095982d559fbe19a33ce8cf2abddf034c5dd754871b7e6ca35001f7ac66c7180e26d9b5fb580b5ab7a028beb3" },
                { "ta", "a46b8513f5263df777010c5b6ca62fab913a34dd29fbe9b43ff14bad1b89df93c3afe35e5fbbafc432275c4231292d86279399253145f3399f9ba7f7633d7e0e" },
                { "te", "60315cb3913de28a526bd98d834837ddd3de563d231a1b88b43cba187db2b9188276a5f5f3c6148e9e1b13526209f955003d262ff1ee8ff01d92210dff1cf099" },
                { "th", "7b1a3ce015e062ed6c43d976cb9b36261a9ec84edd5742106d34e9ce71f38f1c9092d7fdf63b3886751803df0c9f86a7ab07f3f5a8b64125ac5222ee017db0f9" },
                { "tl", "5d0cff049268dc4b91034e293634665d50ce01c5c6c5b3fdd6ef4a583993a7022b0d7d75b6ec794cb39a5eab4768b0991a2dfccef8b6071c5db0232b8683715c" },
                { "tr", "39b319512889e65c3b1f5fad663a4d1857d4da69826cf25ee3e230ee02f9af8e9e3a5a1e3a5db0f07d72ba06cbfa0a46b9a27c670adf157993f33f96f15b1247" },
                { "trs", "2435dc65c42bb4317ae8a190a63e9e19abd248990c6626c0ec455687952ba4f465a122d95d0e55e868d124737aba39d54ed64208a0eaedda9e69a273a816cdaa" },
                { "uk", "8c90eea9706b9251ae130e903a923b384ca342bdd6387c8d01927ac4938d929150e859cdbe074a3e64efd80d079aeee9795b83fdba3176622348d89749141202" },
                { "ur", "19b8670e644dc9d1a814a5333ba16fa517fd0d1c788eb663f44b423b438e395c7d88350d7d94a2dd7625215372b6b702b42881ac3bb179134b76fd7c331cb9e8" },
                { "uz", "3ae94e80f8ab6943aafebd13052ba4e236f6b739f7235ecc389c39e0151fb5d3ac7bf8f3e577a7af44bdd3de7f1fed3bf9d16fbae9dc9d063ba0a3aa53185132" },
                { "vi", "ff285122a951d65ee3e5635ffc5342a8d78864135f83e8b19821a84081d71faa11cd1827a5525d7b6314ae8f646d43634686a45527f47af915e5618c7b504de2" },
                { "xh", "0819c67d9ed59cd330020fb67f802a51f3271636c57ff186366e2821a1fbc72d4f17aaf289107a1e8c9701a3004597b2ea1bfa74091f3cc702391994502f3ed0" },
                { "zh-CN", "844f78a6b0bb85218055c773a14e18edb02445d9eb4a74f45f0c2758506d84e9cf7b2e897c195c19abcec495594bc8d2b4fb791054b89e6cb726d14e59576de8" },
                { "zh-TW", "618edc6145ad5c54fed4782b267735555e71e8c5462e5e305276a6d6efe7a406a3070c148db67b4b8b3b6bce4a10bb6249d39b37d7ce3974a65ef579552a837b" }
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
                sums.Add(matchChecksum.Value.Substring(0, 128));
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
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
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
