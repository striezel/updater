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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "0786fa08caf13d91d18d1ad674affbae03818e953f1e60a62c442df8e4db7ad14092185cd1e59a1225a2b4b5790d69081745c75b901f5b1cff926ed1e7c3b3bf" },
                { "af", "e64482dd1d205aa0902dd621ff44c438ba6ac2612037e09f4643d3578ca9b18bdedcba4394f9f6b9520a48819fdb6cae15876504149b49afcdccb4ce377beffb" },
                { "an", "d44b3d9ffa2228f1b4c43b1465fef292660be2e6f2de909287c858f02c8f4a0d796ee9275b63d55be4b90784575209f1a7a0b363f6942c5dde5e10a72a4b0d48" },
                { "ar", "d11540fc2e590ab8858c576f1976f6a19ec68d3cfd7dc1bee3e169310663f14b22d582025d5abba22d93da6e5e23d83c71f3b8bf7e0c8eb302002fcdf4c99477" },
                { "ast", "c690ac4145e88fdc2a2bd5cfef79c0c8d50826587f40e5462a8e475e8d38492147e6c20ff842ee0d206c9c4509d09be6c005f891ab12e3b7e5bc9e6d055829cf" },
                { "az", "562d1c0c25690f7311cd050179cffe5f851f2a3f9242d6cf8dc8ddb6015c1586549f29a46d0320fa60c6c5d81712c41b6be60a6c8bba5983b40ac6db29fd87ba" },
                { "be", "d272abb55c75f555cee43658d38b6be6d286bec4c5a95868480540188f9099204e8736b00887df13a53bae943208790080e118d0f453c9bb806294f38b5cfd71" },
                { "bg", "e97b6d062ceef1e1f34b34d8f140f109c290c7fd6387cba18d9e8ab712e203d873c6cffa478fdfb90f6e52e18dede7a4c5aa82291d8fead7df061731d516d8cb" },
                { "bn", "c34c4c7c91f291fb752e6c54797fb22b4fd17434ca70eedbafbff17e74441cb2f2c763f81f476438b7f826d58e2482b8e09e09636244ce8ed57e07cc4ccc8ce4" },
                { "br", "386cf77f2b693b3489e564897c68c8bd97a55520a556555cd60a76f86fc4c2fee39eb04b1dc62c1900af4db92f8400c9cab10521166622e519a22308560deeb2" },
                { "bs", "86225fc76d53d8679a521a45e6cdee62f97e79f940319a296cdd6faf1f4b8bda7d6446197410ed0e2c96817c42af0436593a8201918f4472af351ef3ef6ff5ed" },
                { "ca", "de08fedd5da0624598170d87fe428b0e186531e2dac58f364a11fa234e2fc00cc43932874a4fe8de578f38e895df7f8a3caa58cc9f502c1bd9086bbf3b8cc9e4" },
                { "cak", "c4e153cf9267e3c1920c5a7a153e698f9ebd4105c35fa199f435ee34e404190ad977df912321892a05001e0051f7739f4dbbaff1a10460fec2f905ec7f47312b" },
                { "cs", "5efba5ac65a1848c160662a4b754e195c6bfd71b29a697abf0d446ccba4feaf2ae40f69c918d0e2ef588434ecb8ee0b782f4a27d225011e7975f7c51d24abd12" },
                { "cy", "5d54fdba108393614b8ce0d67e9ad78d37e9d8e559b37fca60fe485af86599133418c7c21264a4a4724ea7537eb3828687d608458cb2674ff12dd2e524782fae" },
                { "da", "c7cae0e92460f660cd3ca1f8b32babe0df884e81c7f1a640917fe140761784f0493591581a0b75b8ea616c0b6a736be2fbb99e413634df1e76e55bf292d9f9ca" },
                { "de", "85ffbda10a7f5e1f0a5a36fc6c6613aa35e233fcbaf86daf507df6561224519c0f80cad5c6c0550f6e8d58824c06f3b11dd2ab91f11cb6d374a8abfe670d6e5d" },
                { "dsb", "823701b80e689e7a7ffc03a77c1cddb378a022b03858dc0bcc598ed0043f2f9d11719c4d05831e63c76d6b9721475a780be4cad42c86007244c03d3992754e2b" },
                { "el", "b127a65b0dd82ce61cf4aa19e4ad1ed64ef9585cfc96f1f857c6ed6366c421069d9183ecee2a8960383dd0ed5239bac2b5ebb559e948046a4870634119a1912a" },
                { "en-CA", "b46cbb2190def51c615b37327c6fa3bf8de8b76c3969b4139575cbb3efda6034b64a96d9bc0472af75e07298c87ac2faabbc12ccc0e924dba414fe885f78a57c" },
                { "en-GB", "82275cad2baa3e70a6515a4a3440ad8efbe227ae55434dc39fc1a901e21c75318acbbfab3a490c3b18d2ff16ad0e6c989f3401291a1187ee1a1b9fcbc214b7a5" },
                { "en-US", "89213a8141b3f1e1199c5f8e5cdcca6d1eb8ae9506d497a7027bbb7ed1355f933d74c91c69ecfcc37c8831cdd20803d4bd6cdbce61eb24263bd5f6d92d77d552" },
                { "eo", "538e9893152fd837690f9f59141f891e2d4b52b59a5e2370304c7dca631a1afe4a887d7a47ea5104f266b6a59184a8c4b5b259bdb2a03cc32391a907f3f9bf2a" },
                { "es-AR", "3ca822cd1519ef19840028214f5aeb89c78fb750d89e50c7cf815445f5d1f6958c13730cada07ecca9a60e6c3271351dd168f57bf07cbf2ddf905389a1909ff3" },
                { "es-CL", "6be41895aed2d8b88fa52c88991a5df37927f3569121a872350fa24d6f825eff18ceda3911b7824d8e2831e29408003880fe26d5e47c46cabb7e8ca5d5c968ca" },
                { "es-ES", "789977f7592d267b91526876caa3906b8cc51a8edb033fd5aa37bd723951195d5d50abf9741588a6e6ed285f04f99c4cc0d1c4e8654b2e449ad833fac2161c59" },
                { "es-MX", "3d24e49dde72c9ee97da2c00dc03a9d918403d604094aa1fabeec16004dad9a18688ee739db53cd0b7bb426e7885244aaec7c790cdfa8067cc369ec8dde07145" },
                { "et", "56e6c74834dd9d60beda10cec6882311ac20b5d69e48539a87649f7d5d51629aff9f0a7f9d94ab1a5f29514424e619ea0f1af1660a17ac480f73a58512554126" },
                { "eu", "c095289e4eeeec4c6d5703f400fdb564658ff1a5fa0c9fc0cb724ac9b7f963c3d3e5c9cf7a2b72cc357b1d4ec458ffe93b849ee7f0fd787a11a87752e545a95a" },
                { "fa", "1526ae20dcedf6575bad182f42cc0fc91890931511527dd88e0e18f09b7eb1a664b7106987f338add62840c6e5daebdc1f5a91de99e7761076a39903a14c484e" },
                { "ff", "84f794d5b98fa678036396352c2ec91889fe1657e225080c1573e9e1525f2c6f69a3241b555c5f5790b09cc16f8a23114d2145daa12913d0295f8eaa81ebc809" },
                { "fi", "a17aecb0e449b3154718f2c2e88ad2ccf12cabe4134dc3dd0d840f2ce355389328c6ab8ef6c0a13be82e22602a023cc9bd8475d9d0486753dab700aff4b2ee8c" },
                { "fr", "39210c4acb59277b3e2a4177391ba7a20d35549a688e6697a3f9d6b80a4696156b44be1d14bbd722ca895ab9f079c195120597c4278f4beef983e31161920856" },
                { "fy-NL", "38e950f38b8b3a75717b515c9508380544fc0f744be2944d2b51940fa8df604f3a6dacadccf0110fceeb77e5efc7c24062eaf901b0600db9634df928469768ac" },
                { "ga-IE", "8f2d29789b746daa4f563eddc2afde70141f403350c24b65d9ac90f6fa328aa65700c833b65a38cc5f01e7ba78fad7f6b8d5000ba71c8861d5e446b9b730917b" },
                { "gd", "4e70fbd0744a61850f15623c1e469efdb8bfbe0f67ac27c253ba40e4b03b348ec529b0e43d8335e49a89d59a67b22522bf4f01045e4f05637a2f3a0bbdaf985a" },
                { "gl", "3afbff786975b6dbc9468990173d4c4cd5a00523d967cee0b898ef091596d48c1e2ce44df3d68feaa3ce48140a0e3a4e3442adf52aa9ffec60f85b932226638a" },
                { "gn", "ef74f60193ba1d9396b04861b131442551b9683e8cf9351ebded7814e258459dc33d82fcd34d87a2ff57d00bd1b732710f4b934d609c6ee6eabcde4144d04d36" },
                { "gu-IN", "9a4774fb463b66632639566d33dd99be04637af9ced55ac7ef725a9214e0f74d68c36f37f4b0ffdb352ca593998b781d4f2d4b3d462f1e661610b6cf5db54778" },
                { "he", "fcef2e7fd8a64bc105e4f7a70a29193fce91dc24b5022e2c665142f3bd46f319c8ca5a20f7171b45e208ea3e8dc329e2a3fadda421c78488afcd22ac74dfbb3e" },
                { "hi-IN", "3e5b7e13129c5848ecea5535492ec35a8045b87677cd89a64f19551bfb17c65a0eb3db7fce46eea3fb566d401be7f54bda06fbae5042d542bdf43e665b91ffa2" },
                { "hr", "22b9b97fe135a5132bcfbdd453ff529e7a757c8d11ac9f979ad3216b20c4a36dc0c1c6551e13c54bfddc952303b9fd3fa9c6ab1e550b3775444922ce2e12d657" },
                { "hsb", "1b36998893fed1f3e68f3fc3706722811c57fa512674d3782094fc76a8cfbe3e3afbcb70dfc8a299b033d584e843bab693488a620944eea554eb4e548beaae93" },
                { "hu", "10169da91802f2388e1c5ee5a4a5f53858620709250795bb6ebf5e4ff0ff05dcfceb481eecf5f9fe9db009e16ce1f198a5ecedd428f919966b42156885bb5716" },
                { "hy-AM", "3593be38dbaf0ff8c7c9dd360d554a1d2debad75c1a351306c4657015aed8341d4a289ca23bc5c1fbfd32e913fa49a377ec214c37e7f8cc0f89a4944ad15c8b2" },
                { "ia", "a085c836b1fa8344611f104addbe5646061ec7264081379826347dc4f1dc407be45a249b29f53e928ee700d742908b3b4f75b5053b921e461e188130fb2d2538" },
                { "id", "24d0097b9cdb0810d08a2fb146766dd4304f28497ffa09bf386786bee96643adc88078ae3eebf39ecc65109b0bd1c45a31ab6c324e9d9e3ae563941c17847e76" },
                { "is", "25d878a13057bb85b51123dc1f9b8b53d1aaa8efbb989967c82712480f354a1c5d7ed8f77557dbb142568b929c216e766e619e5279b0bab2f217dc10a9a10292" },
                { "it", "1a221ef8600df630685b019241b18be20fa393b1be2005fde4ec072584c7b2fa7989ae3212156db393ce45dde70246a5d9a20835032e1ae212174d720fcb1d8f" },
                { "ja", "84390eb5b0e002eeeff3500ea872d53eed70005ee1fe0a5ba69a3f629697eb14fa6fd8df0b3b3dbb04939a39dfaadce580180a37cb21f13da64cfdf70fb03f7a" },
                { "ka", "521ad667ec33d48fcd16491946da94da2107eb71806229fe725fec86c4661f84bde9e37079bb5f88b3531ec05d662312a86358e69c8cf39a03a44b394ac7514b" },
                { "kab", "52f97f81ab794e10ea037e9ffb818ef39dbaf03b959b63f846c60d4ad15ddf6499215dd1f7b06cbeecc131c65fc66bea9ded03c9c515d846c762f17fc5891557" },
                { "kk", "081c2f676d27e1f96887f3b9d71a37b898fa594aa60f83c81f936a27460cb96e82838f85cf818afda29378edb5dad0c807ed434166144bc05016a17a307356a0" },
                { "km", "ba6f7ade127e108e11abf9c9bda3263628c9e093bc6878dd8294fafb338ddb973a7430a103100f5d0a3fe6f52d030b066a86a84bb8c7437f783c6c2b94e2c028" },
                { "kn", "2a1a5f7edba45c567a47714c7b4e7787d26c0de1960f4bbfedf8ce27f4b4e81352258ace49d9de8b91ce1092a4bf4871f776c219f79ffcf360699b24db2bc547" },
                { "ko", "72b3d1ed44dc50fb1dcc3fcc6f5a0809547039f70ca2aa51dcf03811085bd3704b0c1263d585269085aeaca8f31c1f54f7747382dfae6cd0e3ac96ca541d084b" },
                { "lij", "e739b67d08a35cc51351f9207dfc6d3ced09715c90d689604dc46b34cb0517f155c212187ba0590d243c20bf757016294e3997aa362e823c99809d3cdf35ba06" },
                { "lt", "d19ca7ea7218e4883dce7f115947c8a94cc06e8be2983bd84d92bcc6a662efbed5f62f9b8e033016e3295f56ab159ec3f136b76a0fe656ceb89d06faebca0d6d" },
                { "lv", "2c74b275f867ea671aa6ced354b449160c2eda10ab9c038c60df0935d8c42c411d4df0170a755da6668381801d879bfe652a1c85c64a949ff98c19bd1e07995b" },
                { "mk", "94105b265f2c59695d731cfa396fc3cc7dc20db23fb34c3d02777fbf793951e9f678e3ed058407c0919256ce70eb352bfed22cc6eea6d87b9d53483c536678c2" },
                { "mr", "42626303112b41b01c96941a2036a928bc4ca0fc07edf8a20f91d46086a4b816910d6a0220a23a3ed6d16678da7c80c510b3d939c2ec3eb8255f5903dc315664" },
                { "ms", "3dbfd34929833128a0ec1ae3d8ce2c11dda50940922ef4c7c35b6dd32135ae4020f1e3c978c706f0247bf90c83e505b28f90940d444043f4ce07e3a04b154aa3" },
                { "my", "24f8c43164d695836d9ac09c069884d31dda7636a622a593e67418ed761cf980ccc8f4b37d1a74cd80ad803273f9067b3ba1ec26416a4cfa0626fcbc44585af3" },
                { "nb-NO", "4fa26b468844cfaf4a4c8bfc3f290c0badcd6c1ca8785ff90700cd0e71218a55e55ad54259ef4942bbc6079a67c18f13a7bd2c46f9201fb0475df3679806444c" },
                { "ne-NP", "bd0fdf8b40e640dd4b90c3d59b2b9bb66efad7090b9dcd3a126c9f943ffbb5d4a61d2cdf0adad7a1ed106ad033c1dce00be5702203472ef9032d90bc0c1b4e73" },
                { "nl", "1ed3fb0f516099e61bed910c8af0e7f8c2100a64327349ff37c970fc5ad516932ddd97f247e53bca909880962b8c281823795d85fe31edcb97ed35140ef175f3" },
                { "nn-NO", "0eb56f62751664491e6346c5783419a79524b09e121dba22f18d2372cfbed69f961d217ed3e36a2ff7c0e740c7c53c78d11c20871e62c312b2108960561a9ec3" },
                { "oc", "52d9d6b8652d11d537e733de04f8716495d21c2204542b1b277a308d0122a656c22debdd11db46cb2a69b0f2f6dec0967e0f95d427f83019edf162b8a5b85b95" },
                { "pa-IN", "6360481883e58c894a92a8bfbdb930f7a231577e3c3eeb9c5ba1cb26489b6ae7f236895021617fc273e38df661a63e97136f16d24111ece3f2109c1452975041" },
                { "pl", "e3f6c074f56d201f74047316a4dba729a1a84c956236d4c7648a4c77a8c6a76e044f9b83357fd6a1499acffe415d9d091b1435d55796ac786b5a7a6aae3aa17e" },
                { "pt-BR", "96bc174e5f40fa6a1d35901936e068eb5058890589a5b2fc0b88ebb085005e75c2308f8e6c5e92f9b2a2a3ac9b5e4a6ca0cd9696d561a219346f141d9d35e0b7" },
                { "pt-PT", "42113c402514ad4c02f669af962347a3e9df1349b85138e47c3302d99491318b28154c943fc9015a5c309b040a3fe6e191066dcda1d7a401557123234e29fcaa" },
                { "rm", "b90822305da1eb98b7fd0833ca637e786a0c06a5164247f98baf445d1133ab1bf312f71728b3bc45da9ff2cdab342f8b0f79bfcf7715e0c5809a2bcbaafa300c" },
                { "ro", "41ac5617dbb60218e7a5c1546d9a7830c7b18e7fc49cfe0657f523736ad0ad779e171cde94cee278bef58bd6632418eb034e974270966de320c96bb39902b605" },
                { "ru", "fb7b76b1daf7049ec4fe7c2074a7d1809c97779e8f0522ad461cc8432f8c73f838f9c12a4c7d343c0d1df30872db4d41cbe26bad7ccfacf7a9dffe7d5ff80fa9" },
                { "sco", "1f174e4eaad6728348b8370f35e2299c7f53cf5d6975e2b42ba18ea298f08d4ef599af5f3bbbef171d4ede78667c10dde8a434dc8b0e77a46004f73203e6424a" },
                { "si", "5395aa405806fd2522ed8b979ea27c450331c38617ccbd4167c902ffb321412054c38b7f44f04c4a0a39932ba7d80adaad60872f5e8c83bdf2fe3820f576832f" },
                { "sk", "6c48990bff37f9a54d2f96becfda60fd713c63933b352dac3e9e329085b499ec373164090cfdf7f0839b77b8e49792f744abe30d21b751e65a9fb604a86ead70" },
                { "sl", "0d0477fe0eb5fdb1b653cbcb962fcc4165d160306085d80b2aaff74c59b41a7c0e0bc9ecb26aa11443b27e2497ac878adc8075b7f499991d374cb3a96f902988" },
                { "son", "158b98e254e1a8753f06f00e743d0e60128f72c9db8e77f2901063bc1e12712aaad8450d361dcaf89018dcd054ad428c5947214fcb6d00f7eaf9f5dc1810ce9c" },
                { "sq", "34293c97bddbd4d44a965f51b7f173bc5890acbdb6b3de538f33adc0196555ff69aa59d4ac68a6ce28e6984009aa021c5f4d691fa8907b69c8c12434965136ca" },
                { "sr", "01f279ac1e0c533634d35594ec41dd1fb701eb9c2ecadda9a833351451d2a05a3c996563d8355d3aa10d0e04284eae73c20d9b571360490314da5c961c16ddc6" },
                { "sv-SE", "8fe022879b24647e49a9d9eecee0c905e63c8694622a74c199d510857a25cc563b2fe4f8a8cbdaa2087e87481af5652dac2d576f8cdedb9a2f23c56b06f3f0c8" },
                { "szl", "b98bb06cd83f9f734e8b2c3c78d0c4405011743cd8c1ecb51120f9c980f7581432ff8a437f4c9d7d655f4cba0fb8623e753d801d02f1ea445aa62800321aecc6" },
                { "ta", "6d2d3f5a5c0c6e7d261780013143778f13b895c6f403ebf65d9758584b4f400489daad261d334be559e6d5979d3075ce43b0fe988f5601b6beb991bed3ede5a7" },
                { "te", "cb6d38b98a405c25964e2ce06ea6f3fd5bf5f4ed56edc4b881a04fbf2c6739bd7d7ea7f3dc962f3c1a3b8e1b515594b48399aefbcf0a1eafe0bf83f0562193e2" },
                { "th", "f42d7986bea5757c1ac4841b24c8697da1e47b7af9b8563efa820271eaafd734e8c3a70cf15b7b1c01c9099ca8fee0faca2044e55b717486e69842930ff66b38" },
                { "tl", "a7897fa02ba24df20a115f2f75f307c199e07b717dcded340436524218ae1610b1621c6185a69c00fc878e5e1e187f795c53ce67c4a32d4a9e2751a1f6270c0c" },
                { "tr", "7d3cfadc622cb761c3215d21a99382d0a22ad1be2f331937d4774878e45206b79bb9247f7dd4662a9a911e43642eafd2ec602de2841edeacb101f0f1477936a0" },
                { "trs", "58959043daacc767306ff05e3a06e9545fc396390cfef3e6710fefb65ed1dd30c096c202c376a93964fdad6568fb5bbfabc381bc0117a5204c55d18e44f32eb7" },
                { "uk", "9e90b6962177b82375113e823cfba9b34fdf8c775db5b5d346eb0a791e3b16bf68543b0fa0f9bba05afa44c0268a572e6e5de5a9de6c7b7b44625c1a9e0e54c8" },
                { "ur", "bb2a393b0149a4f39c268eb2a804eeb7a6c44af29dbdd13c611fd860953f88036f91bd2565d490b000525784f2893cb2940bd552d0f687e292dc38bea2f7d760" },
                { "uz", "5c8a5e5775614b08136fb53132c1129253ad091e5e7e60d9569b67f66305e628982f52270d9192b6b5963778ce723357f5131c165603f8b5983ff6e5b517fdb7" },
                { "vi", "904ff07bdfe2df7c87e27eee55c12f25ed8672a09e8a47fe8e42e9a22d84e2124ae738b901c445019f947117d61a4620a3fceeb37b8af96e7d5445028b55770f" },
                { "xh", "02edf2939f3152f7d0e25880dc880889781101bf92a3b606a169f46d71537aceb2d4b43aa7440042e33fde51d2352c7013b8aaaff4fab4518d671b3651ff7afc" },
                { "zh-CN", "e4c7d1c8946b0acb18651309443cd147bab75fed9a4b7b993eb520e6852c116a1be1280509272b5a28b0d3e480cde43a8c6f2a71fff25680518402bc68a92f70" },
                { "zh-TW", "9be1f80730bd5f141982d5b1f6b221c24ebde412e7c2c0e79935fa6019881556a433e8528131213e7c51d0aafebc89db7d7f1611fb9cb476b9e323358984c3f8" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "d85587b05e43c1f788aa06d465fac6651a28f2662a4dad2d7d1bfa7fe0df3145700e21dceb794db020d7a86bf669cc2afb66abae20ffb4fba7d1970cddecaba9" },
                { "af", "fcbcac72b954a7d8c6b06d4420c384b634ce6605908f88f942955062863ca4e14080661ec3acd1aa3ea3287b9bb60cbc7e6123533bfde40d5ebc8ece658dd187" },
                { "an", "271bfc403178912136ad6994f2349df8967bd133055655aef2dc2cdefb2e7e344619d46a18fd676642c09ce9394f9b100dbdb915b4c8693e04b9d1cfa1c3d8fc" },
                { "ar", "7f6aaa16c830907cefc2360c3cbd671f7e9387cb3f464cc2ac92dbf3c349c8295fa9769444ce0d355b7d13f4ff23ad3a04633a7726b6236de412bb5803571487" },
                { "ast", "330061850d7168f301e4985f629200bd1bb88354aa4eec18de659969a49e59af9a594f12559882a96190844ac5498904e97273d51ad8f6242754bd2bd92784bf" },
                { "az", "23fe24addfab681ffe8b78577a6ce5f94abf799b86b83a1038f2856df8fa6cc1712b2ff133428d6eb7eabf90441bde9f396511bb08daa5dd7c2cc1168aa4236e" },
                { "be", "885f8c238a9b68e470b8dc25109d16fd0aa10a8d7bc98eacad1ee9ce0971b91c7112f2a0154cb4356c344c99935dd8c162553684ae8dbd7421928efb90ae09cb" },
                { "bg", "4fdf923dceea34fd34c7480f6e6f60546dabb6f660745b32495803a771bf9ab9fe7c79263009d4ccc902c58df6659b4f5281dfb7c2162a4d5a7c00b75b4b8b9c" },
                { "bn", "aae45ce2b4242024a937e25cddf8a422efaaba76dbc7aeee5451c77a67f9f60f1b936c9f9e6c3425bd954373c2d7340c091197386b39f4256f10a59f96ea0b0d" },
                { "br", "d1ccaa1442d535fcfa340dc6a17691aa6a061432448690246b8fadf9dfb805c45d552b5976da2d9c20db5bc2073bc2a18156568d86a5a08dd614fd4dac02dadf" },
                { "bs", "14ccf86da0c1af622407186e94515a4cd100cc0d8b05a448276e82eb0e96a5f0877318334a4cf3bf3df6f6fac58ca07b149ff241a7215e8a3a6844354a4d3280" },
                { "ca", "11aeddd17ca1d06daf6b2ffd7f5fa06db17fb374667eb5fe4f5865ef07b9d8e50ad064001d41b08889079ef9783a0a51e94572f72631a2cfbf98632949148033" },
                { "cak", "a37cff9d7bfa9ac8b949e9b2230244877d2a39bf1b29b5f7e8effc49585fd90a33c2ac74c7a79b67f45118a7ecec91857013195b62a150cb37a36fa0b569b34a" },
                { "cs", "ece1f739de5d2abc59ffb65658b9c2620f547b0466b4916af38523e2ce71bc8229760fc174e6bcb9fdb872764585fff9e7270a81a367f872a45f4fad8e9a341a" },
                { "cy", "0520b0534aa5d29ffb05508b480d7c3c327817bd5ee466cc7367952272f9d7766f62c6ba04d7c586c27a61a8008f9f841440c81870a22acb199b85a075fd558c" },
                { "da", "1f1c0637c6fbf22a0ca0aa4e8c2d2b804ebac58e4902ee7b7417c9f8de0a713a20225237afd963dadede91eaf5e7117f2f501fd9d93e34dc09b7e1983682d7a0" },
                { "de", "3d2591aa8095fb4425b9af3d7896017aecbf17367f11a4d806d50c3c93f2695cf37181486320605a4f91b3625fcffac336b60b729b5b49f74bb33705b47a84fb" },
                { "dsb", "50ba79e4e683e409440a36f8964df181ab19479085ffb8fe018e116b15076b78b08fa8308c4f402c38b821d01876882d6af0956587f714cdcb87901401f8a69b" },
                { "el", "4e3bb080532b1d7d6535873f9aa6c3a66b9a47912913f8ee20659b00fd37ff7a2a4da7c1788aad54188647cd129967408c95154075d7f439afaa8f1297facf97" },
                { "en-CA", "ab100fc2d988389fb9020439dd4f2201ee6922f97e745e964016cb3bad8cf09f7cdff0f4aad2854414b6b2dae35ebc2cb40b269ca4be8fceae6f626fbee3a372" },
                { "en-GB", "cda090e6d25389f0943d1c34db208c39280947811c7ef871e954cbdcec342e9050a304eb957c74342ce1b7dee26e17fafdd7840b72f570d4e2984e34f3dec14d" },
                { "en-US", "353198484254ae3222be6552dcdc983be20435c6f26377ce93e2c27dabe29c17474adef8a071a283575fdfdda92eed9283675207c9ef622de7e80eaf29fdcf12" },
                { "eo", "2f3dc1bd28fe506f4733ea0c736b9c562e8686399f4a1ec13275698880b93e667807c573132c94164fa26f99d4e9100149ba879e70e39987939a0972a6f8680f" },
                { "es-AR", "af9d108a8d45fb9390f9cc5958e302c46456b79375f7d5ebc4a2328645854faea18dbc379cdda1cde41590a0a855aedad4083a102bd2951f786cf0450ca6a602" },
                { "es-CL", "50936b6a040ab6c1ee2e4e4be2dfbdeaa72d7c703c175113ec9ee2a71089b5e00c1f238c5b76fb54937b683d73778ff88283fa17805aa347e2f6f033986e78cd" },
                { "es-ES", "2ce60835ab81031438ec0caddee2e90590a98484546572e9d1ff4f70509badeb50c95d483d2aec629550cb3aaf06fb263d2fba7c8525754cd5f21c9f0df23dec" },
                { "es-MX", "86617c0568ab99fc89c576c55e77b8187059528042ae1f1d12ee55b81289724b7592235c82700573c0260f7184b7415b2792722c198a7dee3793e777fa993360" },
                { "et", "10e79ba557e5b963ce45ea739fd69a00e4898528d1a068ee4b916edeb29fdcb99c8f26db83b08380660679ba63d9635c32fd9f1740ba8365238f626e054c6991" },
                { "eu", "20f82b5b1156302051af8bc778b5c6b1014169f6c1f6c7a6c342c6f4169cb5f45c2f1d64cef3cc2f97fdef2c3af136439b602c8ba5d003b198e119f5f5dba8ee" },
                { "fa", "0b9b489e0174b7b43e975b156978b471d2b98684bab4da32521dde7ae705ee4718849fb90ced6df1a33f40976eaeebb2406f25fac16116c2ce301950baeacd01" },
                { "ff", "a6a2b1ac25a70dc5dac8f1fa82f0001d250f62f450c35da0d168bc9a70a25ec6ed0f90a2ebe99f9113ae1aff74d77434131b4572973ed8dd1ea959df6f779692" },
                { "fi", "5ae70bef8ae6f47bf15702b9381974f37656d2921f1b34067ba42ad192f8e81eefbdcc652d650b622d7e99d763c6d3a7b4749d182ef807aaca6413a95922123c" },
                { "fr", "aab44338d8e9f8e5ee4615ed26cdb86b6a0e23a8e20573337e11877c7a83e0018e4051ccdf03673c96c90b5bc7ed5a711b3863946daa052a122925a2a5d82b78" },
                { "fy-NL", "31dd77478b066a34a67b9090e9a47b63b58fdec5ec680794ee287dc9b24f57210b00a024e8bcc13b159cb2bc8a5de81045fef83ccb21b4ed97cc5a50d45fb247" },
                { "ga-IE", "3c0f28a19c0f0f38b986d5da64df5f0119655a7fbd6fcf1c034e97f9b8222853ca95791ddf70e81fb6358cf82ed34d1f7de1049869b9588ea18db32b8b1004d0" },
                { "gd", "67ea9f0a5543f32d7940602837c0009d69efa1b60c5d0e43e0697d43462cdddd839708f19d1edbf8944c276e7b44da98a647e79cea36de878dc8e8936d635029" },
                { "gl", "a7e6a826c5f9a230996458e173a1052adf01ab36c2f0410b1fbe9c32fbbf25047c78da974d06dfd270f4416f343056b0acb9e14b668729642d9ec2ca7c26e193" },
                { "gn", "48626daf58de32364cb933bdbedf342e14d92268607ad262ccbb9725f65392d29a3117e11843cd909ddeabd595d91653aa66d65c386760bc96dad1bda054b0e6" },
                { "gu-IN", "39f5194ba463a7d633e87439631505cd003137be02e2a50b0a95715db864a088e9e10844b6eab46e951d746b62d9b6077b7074000f7c7229fb9791df7a9ea692" },
                { "he", "c035d5677d70fbe3c9e07759fc5076ce8bfc42cb4aaece728c9b4bca653b011b6717d410151592630c19dbc567fc59d91a1808e6625b5c652c0460e04d70140b" },
                { "hi-IN", "5958a773a4c835e0d79fac545c1329d85d5cab2aad5472baed2f9ceac3eb9498bba44d71df80f8b7ecb584174ce05e197a4d102ed7df94aa1fbfbde20166c4c0" },
                { "hr", "b237cde8caf1f25fc9ba556c24c72b6c2f6bdd8c012c6c45b7751ca839d2f11683720c7432e5b35ce382ca26e924842a36d75bd43a9c367215952702cc7a9d06" },
                { "hsb", "89e6bb39b739fe590af5b76fdbbb7441f0f7220fc2416759044850418d1991ad9324919f5a3cb511f00ed1ad1d3640f8224dcf19cee98cc040486e2bef981b7d" },
                { "hu", "49b95d205d72bcfe2c27497e5b5756db8c2fb7cc00a4c8174a800bfa43fd5e6f1f624b86698e4d42b23ee547b809e9ceb6483dd862892877a06009fafc8d1220" },
                { "hy-AM", "207a2c0120d1501cf7bafeb3e64be1ae3349a0b21aa0cc8d51dcfab57ccf906d2ec894d386d694f3e74f01ae2f1ac32bbbb9dcfa0de29c6294917aa24b414856" },
                { "ia", "7551bf131bb0af562a2b7e9a820cd8a2dc0ff6142047ffd9f0532f2945f3cd9118d021a37f2103a738b3aaa47ece529a4568be72206aa3a11c6164758592a570" },
                { "id", "e61b6b363f02ac9a56d0254d83dbdfe86d02c128503ea2cc97af3b68f08109ff5e70fb5f173b586bd41733e8280834b6c17cb74018d8bff77f95bfde8917c65b" },
                { "is", "dc3f00bb8aeed10df66caad5bf77d3c5cdf31a18af5692ed74208b98146740113e39528b703ca3bc2d83c4955ebdbd20c9c3af08d36ac5afd23f8c728c716159" },
                { "it", "af72ee05e5b7522b72c05353af99fa81c2a0d92739f3c4ae3f904cb25d673e29ac52aa3cf0473bb789f289376610654848a92b5113cf7fdc36c12e9a72e8a0ff" },
                { "ja", "c80f40a887ba75749c4f036c7a7706f3632527b9ed55332638d5b45aeac7b098fbb2dd0b8368e69f39fdd058080771dad97ed8c90a0e3e1ce08f6f28f5d73f07" },
                { "ka", "85597bf2c2d4bfe3ac8428bf8ef9123aa041275798d0cfae454dfe04ea0b197323f4c70f7b2d0a2920d5d0b21be852b3be0ddd522a9838e0f860e394dd9e7471" },
                { "kab", "540e221c8f16406117d3002b3176b37f79e08bb4cc3e9899b8ff17d558c8b32cf4151ca5c7141cc3c8ba651ed1601e97e0c4ab238a08eddbcb6f80e0557ab7d5" },
                { "kk", "cd2c29f416617acbc5857c013605e71c8565baad0eca673b559476e45071f829aa9ba3a4b6eb3813e03a7f995e2c59f266b3f9be931f61259c6a62032da1f38e" },
                { "km", "97535ff07a25b5295f27fdfe97a4f975da85fbfc64f079fc5d55db240cb9d593d9cc63c30de119ad6b990076970b4122350365d4701e90ed7b1d6bd5fd831dc5" },
                { "kn", "bb614364a777ac5adc6143721553093131d6aee09a7ac011f2d96faaf3e273a6307ee197195ad383c7e02552825f90554354d19af14592c1d2e0a3f84b2bcdd6" },
                { "ko", "56d650b3afe277b86c15e2c67917941591777137765af4cfe65d54fd6e3d61defbc2e09d5ac003a67323d29aa9395d954b6f2592c12b42f92b988ed3f009b350" },
                { "lij", "06383c3a507a908154208bf48029353a52b0837e2d62051fb269c73d9db3cbd769e15cf964d52adae0e24228dc53897d324250f8177fbe58d3a8d165ea2e267d" },
                { "lt", "80c51da69ed794b2767e98f725130d7e21833192feba565feaf70aa9728b4da837a43dceea1f1508c9da35be7a6595e99b79d3a63c4b47ec838fbaa55065ff43" },
                { "lv", "8287c785af1cff6f6d20984763d8bd11fd1f69f9baa4c57225d96d91fd4bd8e8e99cfe3e9af64c0c7236faae499dd1e93fdb3ee61afeaf8e11becbd2e2770cca" },
                { "mk", "825bdb15da3be9d95c357ae17bb9a193800ff71a62afd249aaf2050c87658c3bef1cc6dcba53173d9ba45e8f213c33088a90722b80d3ca7e9eff9786eac37de8" },
                { "mr", "9e36e44b69a74eac79cd14afbfe6d2f932be6e13dfc6e613ce99611896291a3c76092711f9f89c99839fc8e982ea8782cb028cfb7803e59edeb4b9e35bfa91b3" },
                { "ms", "16cd48ce178b764e9a44a09f3dd742420991b4f9dce2190f8a31a209fa217905af78bb23e445c60a3b5fcbb2a8571fb4904af88cc2d9aac6a1b07abbca3568df" },
                { "my", "c19afe2033945f696b3a07d5e83befe41d7139d102e716285456c8748dd9d3b7cbe0029bc8019baea7bee1d3118affe5c3f65ff60a75c44c521824289910631d" },
                { "nb-NO", "708e37f8b8c9320086ceb58b28f90b2fd80da42fb8423af8b26d81f01be31bc774412c3cb1064315c7b64d2fe069c673d251881a0348f7f00321264c69b3fc07" },
                { "ne-NP", "d8b32b4c9cbc093b78a711df8df9bd16000a8a0dd89999e1dac21b52e17090af36b96e1e91e4dabbcb0916c73ffacfdfc0b34be23e483c76c90d708d48ceabe4" },
                { "nl", "b5668587073b44347024f390350b56c3c0f0d014795c4f979cab4446c5d7d62a008a25901fb68791cd4b773d2946e909c5dc38cef816e7e3d41d3a4b25eacbf5" },
                { "nn-NO", "9f4131c85fad8013acc68f2af3929125e882d90dfeff2657fa5c7b9f91fcc28a43f798db8b2f66f875f95b5a60e14e0ed73725980d04170fe78ade9f4f2dcadb" },
                { "oc", "07b0d46213174b21f195df81257f247f2d0e4fb4c68c0c9ba16f62023dc30dff4fb1bd2af980c5a5b8356019272506cfcfce83b7cb526f8da1036e3cf197d32b" },
                { "pa-IN", "a5fc9d9a44f012c7b17b818b58a2f463796f640d56541d9909126496b68c24ea417e0a53f9c41f4b709e8027508de629d3944d23c9670ede6e5d21d2f1c696b2" },
                { "pl", "4f1ea9e1507e8e95edca01d788aa7aaa5363bc49525a1013855adf01277b29a521868f7137a8b00eccbfb51e4f4411b99304a9092af6806935e1cd509ae38d3e" },
                { "pt-BR", "5f3e69432def6e2979d6162ddbb780559988280c8936c42bf0c0773ab40942c42c6cd717c2a8b79e971501b4790c993f6283c203f7940ca0b060e05666bddb03" },
                { "pt-PT", "dda893a098db645ae53c2201f93cf4f80e566eb04503d0565d6782b0e59212052949beaa66ea08435ec3d6adce6c22dbfe1e3cfb01e69207f20155b32658d32b" },
                { "rm", "12ef3b6adfb7f393ebb0dd8f089588da0b601a1ba363e2f67b4ef7f1ee528682986f2a09be80bd90f0dee6e32deb5d36bfed48fb73f0af8172f0e8480e29a080" },
                { "ro", "7d874e297b0220525ae9abe99d8bc3f39722fa7afd7b59450c2fc49a7bef69d7921306b9139fc702abb7a8c3145973a462e362902f53513760cd3a0b741f7035" },
                { "ru", "e7c531f1933a354229494e4ca827521ab5df6395afa99715f0af8d92d9d27a86bb8b94079c349db8badc5b876ec1056e3cb3839f7615d3c8b5a5b3192b622072" },
                { "sco", "ed3627202f4cb3e0491b88edc3aeea93c354d5afa48a941c855190948475d752e5558e76dd425153a06fcaad0fd86268aace7012d874bdfa373feec0fec7bd97" },
                { "si", "54cf429f4237f8967d3522ad6d5858ca2b7ad9f3e7151157b62be2e326f9691c17cec13f6e1eff7be9fb957f4d126f6a12c5bb5a2f6afe9c62a1f37d3ec1c75a" },
                { "sk", "fea99baf63f47675124c66ade4395ae432283ed0cc08fdba310a3b03ddeef533b338eba11b1a8e467620e3dd43c67a452ae67f2900846390cf5cbc8fa9eb03c6" },
                { "sl", "47a834e3c879015980dd3424573b402f0784a3a94e87f14f328bcad0965284712c9b9a5870e572609f82f59f2fb9926447868ff3a250201ef6dad56d61c21bcf" },
                { "son", "5896ded2c681dfd9ef0d707a9fe3ef266fde7474b1f02f00a8d2ec0de5bebefde825364440f64d813b95025b5dd58ae06c649d12ff97da01e821639b17735a65" },
                { "sq", "f530c00bc7ee0831c1f6e6346ea2c48cc4e8257c31d56d427884534ca2bc990bcb899226d03b676637dfff7284441bc303b02d7022705e1041b80602619c0544" },
                { "sr", "0a6334086369e407a1de65078f2908067aac53f930eeda568f3cc59fd844ed8ada4a5e40fca74f9cd36b622befe32098f6fb348cb3cc26b9e545f46d8a9f609c" },
                { "sv-SE", "2dde32ccf52d68ae9a8eccaf6a4a0d83eb02d3b98981a2074886d5b04498eee5004e8e395f76c0b07e023954b0c8c484f745f66b2d57c549cffda74a3f16b6d1" },
                { "szl", "52e02d60ce65c51be3d91027399d42fa5d2653695020e868f0022a57de3f2bfa1839a94cf76fa9c6a182c8051de048c83a61a9cd5a592e40af43b5fea3e22e32" },
                { "ta", "9073f19d05073941c3af3ff62c15724d868ad43bce5b99f8c566890607e471b0cdd099a51f82a067b951b9013eb5ec5276bf6ac840878c1bc63ec40187a7518f" },
                { "te", "c4e1db0e0fa7408df608ced48b6ebb929926e251cc0d8f3cedb6c148b24d89cc7093692d50a19445ab02b33677308e1be33a36c18df97481ce7bb949549d408d" },
                { "th", "e4950735f1f896369f2ec11bc7bb4271efd3fade0df38f5ac92d34f14f28235ba353e729e0dd4e66c286307688a485661685cf7709c90299dc4f6207401a5c74" },
                { "tl", "645f3934d436615007e523db1701ef2d5174c10c0f8e63514f71742e8a9bb27611861c17453cb406d204926689011faee6cf8ed90fdf9f5a9031f4941826c509" },
                { "tr", "5df0de68f14b7634e8ba38a987ef36653bfbc519b6f51fae79a9d1f39d46f05fabdf45f6afe98151fcb52e79cff1b6e4548230e54c12ec713bfe7cd7807333fa" },
                { "trs", "92aa8652fc2b2ee86c3e9ab49451f962fbe279219e976fe6199072b6772a0f42093f8b0f48f66db3088c4ab0886ddbdc8b776f4f3a04cca3dd42bad73f58b5a2" },
                { "uk", "8c46b3374501032bd3b25fadf96c8ac7b1a0a30ab51d22b02668fd5ef27bd9237e82311fecb282f716608bd128449bd380bdb7af7236b5ad44909e3b7444b29d" },
                { "ur", "c8e28cdb6e7c2c7c270d25f201e542cc583380299e2aaac431b87777e9591f34c4828203cdb565e07c3832474339a3107e00a9ec9c0378ad557605f6a30be101" },
                { "uz", "86f00da97278e4a3c58c9488adb214f32fed0255c91c4ccd20005e65bd6e3cedf96a8ecd945e19a66488ad710912648c3207db3f7594122e5acc39e64387f77e" },
                { "vi", "06f762a2ca2335f503b16116426cc1b5a5b17665c98fa5456e4e70c6d7deafdd544e5bde334ea07472c2bf9be8659bf20b218ac0985640ee74515d425fb0bd13" },
                { "xh", "5124a2c0fc67b37e0fb0535e86bf9f5d08d831f1bb2462d4bfef49de84e0ac2b99ffedaa822da2327bcadea76e95b868bd4b3ec8912a4c4badc3e8930fb07c28" },
                { "zh-CN", "e29324c1eb4810e2b60df48d096faa1bd3c7b642eaaa4afce1d6d1acb48fea0e91269e01d2d111f39440cb3a94567c693636484391b0bd2d76b798e2830ff2c0" },
                { "zh-TW", "491dab749098b5474a52b65f1749bda50e0431a3b332843f431d4617b0962d852fd984667400970f39ebc30e91105bf6dcc9b8ae8e9c86a3781708629919e75c" }
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
            const string knownVersion = "102.13.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
            return new List<string>();
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
