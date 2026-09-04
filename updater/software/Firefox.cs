/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/155.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e0304261a2d1bd57c9a175190cb6b14894acb6ab7472fcc01a6e9d052bb49ff33084f0b1af7e38f1450a3570a49c7e0ed048492d04ecb0697f576f8c8b58d067" },
                { "af", "aa568c24c021869631a2ed7bf541d72bc1e704bd494621ff950f99f9ef9e63fc7e107744adf01f5b523d300005c2cacf013ca87211a4a371c53d302b7912b1eb" },
                { "an", "6616a95be148ff4e9578deb13bbffb34214f49e25106f84ea011010eb937f5866c3a75e2ec70343be5b826066a7245f2d80d83c14c120c05c5b0204e4bd21220" },
                { "ar", "1c6b0ce0d24a5d4ce699302270d0e1efeaa445bb89748d9d3a06538ed3f38923efce581e6fdd233269cef178883f94d6876ddcf07f80339f688ca273267d659e" },
                { "ast", "0717b49fd4c1e48601de8fa8fcc3210dcfac8999b3bb71a55ded8806bc305e8029a4b5516ee4c750758b1b4371819ea7ea5394aa917b4243f496247f9dd9e517" },
                { "az", "1c2acc268554a4243f382962fefc42531db0e81b79de5e62432ae7852716311c73cbf911823c6ffa8da5c2245c102b2f11d1f45f1359acd9b80b9b99bb8d1e73" },
                { "be", "ae09a91d10f9b0acbea86cef2abdadc85e6b49af075d4d4d2854105fb2bab27e0ae867551c779ef94d293bae40108a9592477670f72143340c15e168e1648ba7" },
                { "bg", "137f3baed966d5a6d0dd7bfc797a9d5504a4e57ade7927840ec237b081f0a8b990fcd791dba4940632a0bc01a66f636be9c1df817989118f7daf17f52ae43944" },
                { "bn", "30c4109431e5ea68e53cfbacfb6ffbba05feafeae5c439b9430b9e08afccf024f5b7043f07ba73490b6f4a92a40c43505a5f9ede9c2e7ca73ccf19f94f08e905" },
                { "br", "9ac60424104368c1027452253be26eb89f8fb6874437fa9179e6c0344792f5bd5fcc5c360240d1707bbb9a5efbefe5ead114cc2592523dfb57902cf4f962d185" },
                { "bs", "1861557b44739c8bc8740f30f720cdb30b5001245d981d989cea4cca07beba307639b932c01dea1b9168684c4f1d8ce987a8eeba5aef798f219ce307666b74ba" },
                { "ca", "51c323025df0519a05797bf9aa07a3f3cd26940dbfcead3758964d565d0562621461a3287bbbe0795a6244cfb5abcec6d22bf15c89eb720bda27ecfea70d6642" },
                { "cak", "ba441980e128177ed7a8865d6f7bcf7ca743319d10c74dca491b802dfd2984685777c125dfd1a2ef82020722db5b7419c621924ff47039e661959216ce7ec620" },
                { "cs", "e11a35d79ea6403eff459516d083af924ac5424feafc10f6c39056b7b7d2f87c528b939518af59198382bb00df61b33e04855b0ebaa2c9fb3ea1688a110f3c24" },
                { "cy", "2ba2fcf86355d84e2c69d5832bb08c3ca5a7ebef1ea880821a7b2393ec7f149857693f0306ee28d98463b39f0cb0bc569589d350c46e1f34f5c56708df08eb6c" },
                { "da", "6bd20572b3d936cd612717b7b7615812a1b389c14d83eb6e62cb297e19d6d9817f16d93d7d71d78c5ba8d04d84eac8b47b1ad20cb6850c29281190f3e4ab685f" },
                { "de", "178cb6b239ddfda52a4298633a25211ae3362112d5c4dc8bf0cb5e5e9de234fe9f1f76daef0634469df561d9bf9dd0ee9603c8ac623e80e45fb12e9c240e17ba" },
                { "dsb", "cc3b3e021bb06f439b2188ec21a491eebc34d05aab2f9ff9323901ec2a2d68f8ad43af3d56f7f340acc19e8ee6a2324dd17de6dd7d8d7490f22b1af4523e374b" },
                { "el", "8e2a31e99d90f92eec89b364f93b05e60ec7eedb8ef0ae579c0520271b37d757dd22a6b380eb0cdfa3a74e4498976726a2a413ad9d29788117aeb0b29d0a1af4" },
                { "en-CA", "199749190055c6998aff651ae52b647333d5657462d8936e13d627f8fb015322c2e4d259f07af163a8f859915eb2e9a92e5a27ea777d4db55a33f6e7b9330f8d" },
                { "en-GB", "1691d21ceefb494465a496b25ff2143b4af72780ec10a0901e7382a4ac3595d0c9e768ff290904a7ccf52c3e1fdd3c090e5e58200bf32526c54e7dd705902a96" },
                { "en-US", "37695f302447efe42f3dd2891966227a6529732652fca25a97b784288e28bd18ecd83658795bd5f1c5b99eed392bb91b830a9d27a73bd2888b4d7adcae97bf03" },
                { "eo", "b983eaa9f78a9b93dedbf8174fd2a79fa6ff48472dbee49924cd5a1b0b2ee488342270797f3affca7404cc26b14f48ff937202b613789378e37c683dd7456cd3" },
                { "es-AR", "8017b851877ee41e901a29b246521da39217a8b905a18a01e84288fd2790ba862d5d4898f466b59f2ed5acd321c920dffd29663fe6529e615a826fa1466af643" },
                { "es-CL", "c630e0a605048794f7d63117f31786dbc2cd5e8903237902456f4ab3326367ac8238eda52fdb9d0ef13256096d57d9a40def5fe26322ec126ec160be2be86b6c" },
                { "es-ES", "d2fd11c7a664a9b48783c87759a4d8dc08ae8f9201f496c6db0f290f7a64342db153d9196b364a450591cffd95cc8517a673b833f87ab4bced15afd586c44e4b" },
                { "es-MX", "8da82f5becde360e6d4ea2b0a50f3ab4b2de793e97091919393c1504b7c8542e58d324fc14e588f2039943caa7be941b50986651e9e552e0abcd14b8f47f02d2" },
                { "et", "e2c6fd43269bebdf20fc2211db900cea4876a607003ab9592a8666453312ba6aeb1dd39537005bf1c8911abd6c9683f1a7ccfda496285bb0a2d9b8f58564b0a6" },
                { "eu", "40ee829466a6ddeddfa1420ebd06f6d9b2cc786d31e37ce360c2e006dd466eb12514a7726cf6e6c5af8e497b790179282aea5818e9d82e7444ad1742eae2153e" },
                { "fa", "5490c3005e5455059d374145073eeb50cca495846ce4a4e1c7d15485763790a0609a7b0cc53e061005f1435debe36da857b4229763616175486a2b4064cc81d6" },
                { "ff", "b75c8ea12222975e9f56350b1ef93ece31282e8beee1abcc267e198ad9a0751d03ec4053acdd29f5abcd3b0456317404ddc1982b3c6e5016c3ad58cac3cd97f4" },
                { "fi", "d1ce4cd9e95f75bc5d7498e127d0aa6b87b242049d05fa0a05939da698932766fd82bfb016228d94ee7e7c6fb741c460f94242be7babdb31b32d43bab016c873" },
                { "fr", "d1af900f3a80ad4a415921cb2567f182aeef1d7fbc8e6deaf7848741fd5faf22560094fdfa863c258d2458b3cf70dd5b942f75399d3c26a5a175638607a7de94" },
                { "fur", "847353b5f9dc6d6a44c99d32c9ceb3a5a79ec3cb115ef6ea7328323c07b14eb8bdfc2c04ccaff6a731a313cc315708ef51147315cc0001b7a36340d5981c2872" },
                { "fy-NL", "bdced5a76a1eaefc7c81810a1f58f24d1fa048dc10a5a102025d5927d966758065e2c326a6a0f39bee6e6e069f5e573c89828ba25ea40f7403b2337ee7510d60" },
                { "ga-IE", "b011271f4cfbe63626ddd4396be2b8735bae1764c40db66da42ef1bad0831bd9b423b22e948000c31b873a8dacdc18ce3ccb7e197b9dae990edfec08eb85ae62" },
                { "gd", "4b32c701f3facef535a7047e9aced3135be689638494c53de1d25cb05b7914d6274603a3482f9e36e6b6ebe485369b1fe65e77ed31bbcc435337c5790078bf84" },
                { "gl", "367735a023d95ee5a474eb9cbd69c71cbfd4564a2789d0b3deba93d560b68c295c7fb650d4ac47e5d7084a6b9c4dca06a2aff5227c9c91f13a01a8a6e66d3699" },
                { "gn", "d4927203c3404cc949e2a55fb723102e1fe55423e1b0dcbe96bdf635800191bf7c25c1da763c13ea04f266085d769cf7b9e6a68a2904ea65be284690aa4bc7f1" },
                { "gu-IN", "443ac14e570345069bb6fc7ec3f8a089259f67451e09f4af2564feccf27ae40455d8e25b8a864d803ff7f052c4ba0fd60992e96233a4cdec9ce4780e6d5e5720" },
                { "he", "8e8e342b3d261a66b238cfd8adbf9c6d23b653047ac61a23630409469e22811675a56d97c3300a4177bb33a3250a1fc511d8d379cb471d232bbb53b88180ecd2" },
                { "hi-IN", "262c24c6c70a49fc7734275578d94ba9af33bc1461bc538d842893e5322d761e22e6f8adf3cac4800dd73c705f0effb4b44ffe6acc93043e24f82af9b7e0ddf8" },
                { "hr", "9407f3618d37369726609551021205beb4a078b03a22e9b0e2c105cf593c50ea20c7256c3754fa5a9b4f5ad1b97c8a931c0ad6000c1d9bad7dd771b392a538d5" },
                { "hsb", "c22724bdb880bf44169522302a2b63e2c1229b0fffc31cb77610659b0c5ca0dfcdbb2e536acd6235b3079f074202bbe9dcb3579ea9646515f9277edb211195a3" },
                { "hu", "c8362ff490eb859b4157948ec6e2a5fff3b73ee04718a1591af2fbf685e8b17843f30b38f57214df8c0b2d224acb20bf5eca77a67a196017e953f2ac6f0ac4c6" },
                { "hy-AM", "280699e6c9950aa76f6644a11874bf3aa12c97f12e9fd9efb119a2b42ae210d1cdd18f1e9a02a4a522f837cc3a0b5dc71472af5724dc80763f1eba51e5c56438" },
                { "ia", "c0f65cff1d05c21f04b55425a341159964729e0d26819afe8df610059a715f1d2122a71db67cd871736f957164f9201f8e6b365c2db6d3b47cc3cfc9ce19c518" },
                { "id", "a64a921deda43aa6ba9264dd25e20c34eba1334d4109a44e59b05ce5d79c37555939ed5261234156312dcfafc3016618ff7c79135b74a7d3da4ee8bc8b00d93a" },
                { "is", "d4363244a562b984fc17b3125eb68a1d097185ce08a103d75ea86d9d81e3ec74b42e8f95bef0bd48f11e47102863bae26570776e182ed583aa4063bf4a79f3a1" },
                { "it", "de8f11bcf4737a2e35012373f6713309bcc8586ca59fc4cb131409906bfa3000bafb4b983bd4827b1cd94436504b5658ef95d72ad8fcd30198ea32ebc7a90622" },
                { "ja", "996a143064709d4a782fc0ac8eba3701ac7caa48a4770ff878d2437babb320ffa49dd44be0ac21543f200fe81b310fe0ab60efd072edc6f9e2d648f025fb533b" },
                { "ka", "d278c2039d7cca76535e8b7b5aa20055b29e05fdc9f733c07271bda6bc995d6fc1193cfce64aecec8447b7b9b1ac6d0a96c27d3b01341d689acccd222e7e3d7d" },
                { "kab", "92ad063eaa725525b1458b5a9e317dc2b06791cbe4d569ab4e4486e4625b0bac9ce95f485c75a23765f42ac80e7541162d712f54282f8ec457489f281da665a1" },
                { "kk", "db8d9d58b9806919a57f3f21ddc5e91f4380f776d44f8485625eeb4e50541a512794f2008e3ed6d4d00aae7573661a30adf5ddaed462737abb6b9e5744913e2b" },
                { "km", "9252341508320b9be26c7e92a09bbb469c4700062b77a5e4f2b7c8b35d99fac5c9f36b6a4e9726af6c78b111754b9e3fce412f1c9c3b4cf75fb5c11317c74fa0" },
                { "kn", "3911718efef84a8ca84f760b36d13ac8729361fb0a1f084c4b27a7766c7694662833bcb8d06d02abea2f37bb7c63661e9623f3706d58ea97c812907fd059a8b8" },
                { "ko", "451c1c7486b612a18e9b641627504e4712375cff432d04e4f519c6d6c7acfb6031bc54cc31f056b8f937fc6f04d06a9e62e8264fd65e7a991f1efdb05eed1cb3" },
                { "lij", "03840c40e0bd80121f0cf89afaad5531b85d23c53eedafc707f70c36285b0f80afae5a939d84b6a6c8766964258dae73e4d3aad2c2e201c1d43f9691765bce17" },
                { "lt", "4e645949d558dbd8e599ecc65e78c4412bebe6ced5ca2e23c3787fca40c2e0dc2744318e092adb770e75038c0d4ad2d6e8eb851d4fa3506e9e4a9d001edfe520" },
                { "lv", "f045a0d47f89aa99aaf24bcc3cfd6be7057331918850e90158f12447ab4bb38337ebb0cdb27466c83a206d3ef0bab10cd786223cf1680dbc8bdd943c4f9c467f" },
                { "mk", "512f2f6e9a848dfffc19a92d80633f6563f32f9f3d16318e0fa838b508b71c6d415b261170e72aef9228cf9b3a244e8665eccb32fb7aeb2f3a9c6b707d15b90b" },
                { "mr", "53fd47d23940f3ea71cb561f0fbaa2ca06761cab35cfee213555ad2d6e3a977847c432104ae73530239803a444f93594d33c660244e5a4fd69552621e36fb9e0" },
                { "ms", "8022c66f889e3f9834bdfe4d8096673855e3d859bcdebf29963f806bd3f604b2c7d9167c60146c2ea487633b5767d3872e9c1530f47b2b76ccf86b6ef6243ffa" },
                { "my", "192dc00acbe0732d7968c1c519a9ad6bb675a96bb9a1a5deb9957e93dccf74873e2a4e1d110e93e8fe21c0c0016fbf94cf204b9371d391fc83feab1625286449" },
                { "nb-NO", "b673c1c0a6b1bae1a12d43587da822b3b289efcbce98ff6d0a182b8ceb6878eac6531fac6c6a905ebf92c76f19f711408077e8ae956c02100f183aa97a26d63b" },
                { "ne-NP", "1f813a8bc48b54553e3b4fbe216f68356c8e5ccc6172aa2cae195792e19153f63f9dd9dcc22bcd6e606bb9d716f9b43802bdfdbb3b876c285bb8bcff19b816e4" },
                { "nl", "4e0ff819911b21d4c0ce9e63b150643893cde3b67daed3222e641bc749e8f0c5a12848bd711dd82094c7668c37ad52a07ba43db19814fc99c24e101c781399b6" },
                { "nn-NO", "016fa1863bcc77129e6b1243a51adb274be0ee8ad236d081f498eae2c049f129eb8e634bf73908a2c7b64db796b767ce7dc179a9c9a327cf12224fc7496bd8bc" },
                { "oc", "cfc0bbdba3e14aaa249f78c9a0c2701495fc65e47a7a2aea14e35fe6d004b190763180b0f83e61d286742ec76c17b45cd29629df172359154a0492b00d42314c" },
                { "pa-IN", "b988a75c1abf6e47703f54eef16bd69d6f3e75904f422efb2d3670d9a18b79208bfaf19381e963988429e3b4f73b30080aa68c857731e9462c228939df6848d3" },
                { "pl", "b21afafb7c8e8462c2c2fc4af6c023eea32b6a86806f96255b24f4112f9800b66316f50d279a0e83e45e965d84d29f05f60ba189b18cfdc57941288eb02d953b" },
                { "pt-BR", "39a7b97c3d2461bf31b064e6850d99d7f0baba87eace510d9b8e077c2fb6f2c6b183dbde41b658901e4b0164662eef57d2e2b5f2a22739347226bda620c01c38" },
                { "pt-PT", "0551d119a35df3e9a2f333331210d17d3536a91d81a40d9eb78a6d3103aa5fba37cb18c0ef608700b0d93526f33d9369693ea4656d7bbd1b5e5c468e2efb0757" },
                { "rm", "4996fa724b46c7629972ac91d47d6f723730dc32e85f904b68ed403696407c3d39a3552de82062d3a90a1808314d3c7c7bc5d4adfb8270614e761a4d0b4dbe19" },
                { "ro", "1636e064d0a5c16661efc07ec6cef1df7765a4c725e3adf0fe29b2212570f2116f4f3fa1846af72089e9c8c45ca40e0382bd47d8e6a1ed2b4ae018f2fcf60686" },
                { "ru", "8a2013c5598ea2fa83910f7de6da18a3cc44744c0e0519d1da227f1f98f4729b9acfcad894692096d4fa7036cea4e910d69b622979074b3fd2fe640be054aaf6" },
                { "sat", "4a247e7e41e3222fad5ea1cd734d2be75993fc5f06f6d760c53dce810e799c428b6ed34f717059dcbfe5ae9a41f033e9dd1dd0e5a46a6af7bc7660b81b29fdc8" },
                { "sc", "e0b52af6603d6fc4900a49e0e09cb763fb63ae0ba86d0d27f3e9bbc09605bf28d17ec07bc63e6dc6d72bfc2006774d00673b8922216d4722e2c85c0408daf964" },
                { "sco", "e6d70265265a4aa58d75b65338c80b08ef550ff311a50420e36cb93aabbd80efa91a19e908dc6ba9b248c7df38de41fb9c6d5ad75417e89a7d68ac4bf068b8ac" },
                { "si", "ec0d3b47e4c4b77a324b13b500cd5707840e0cfe3f2f9a82ee1f15e71dac36e4befe780525a329fd123b5a2b5196f48c59a1eebfbbf0e2f6e82c442f6a660f59" },
                { "sk", "1922b32ec1064b1822fe7ac2e81151cab46327dbf10c149c2af6e2acd3b20b670ac4b00de9f1b8a1af67f164fbf9c59a0c03bc128ac9c057f8bf59112a1aa583" },
                { "skr", "3d5adc4cefc06eaaa184a6fed4285139c21a72a711a3bd3edc9547ab7b00448296faf24122a75726bf8c70c3bf5db828a57275eddb9f940d74deb35fde677b09" },
                { "sl", "f38fa1cefb12a4039018c2eee12762e8393a024a12983e4ea89a13c386f2d3c1d20842f6be00c649c49a1348b7a7ab1283764cc79849db0b3d5682de3f5ea3e9" },
                { "son", "a849b8c99ecc48bb8405d5f9980d15538a86783eabdf5b83a3866600a335b54bbf51cbc85568a7b1e809c2fb7fdf4028e8a67a25a150c504208f4aab36d0b028" },
                { "sq", "156f409a441500868c23981066c40ea4a7a33365fa4d109ddbdc1f409b645aa03f32bb1d10badcf2d4762c917c660a2017a588328c37608869be169635c9c426" },
                { "sr", "62856900191c24d3714d8e0b882fcb6658765f550664ee2267767990815abfeda9e3a5a1865a31fd7451bffbfb47f5bbc771202c1d06a92470fe6e4aff68cfb1" },
                { "sv-SE", "e6124b5d9d3b190fbc4fd89af2e66ba79bd960e70828b9be6b62f4e7e59e56d1fc0594a499411adc04059c8b6968c18bf6619c825685d7dfea87aee907ead158" },
                { "szl", "5fe637bb272ae61543a08db1055a6365d051551107bb8b4d8753b8e0566fc6b249dabb83fc7526a6076f63b0a5e7fc539387fb25eea5fa7969d6462268f1314a" },
                { "ta", "261c0e11535f68876bbc872c450e52f63779e7123cae9212e8d2b522cacbd51829649fb4d31707b066de5bfad6d23ca2798dbb89ed3432463a15ac753f94ca63" },
                { "te", "d742b6bce212354be93c814a3abf9f70779e42bef960b122b87b40feac30efe753d97e2ffa7fe4006b7f6ef38a8fc1bd18e8bf7170ae4b4a248a1c9fcb5c0959" },
                { "tg", "f86264346a0a4c56faa29de5779d606ec6a3461507956cfc74ed04d4838b92614af9960a022303733f5216f4176bf42fcac628ad70d87c20c8d92350c3249e84" },
                { "th", "aae651779e23fd6f6a076ab8cf54dce8620291af447147bf235cdd51a3f2dd64564acc8bd82a8c1cd8b6b56b5784c2a9c5cd68e7a67d6c6008db4f9e8fd8b4f4" },
                { "tl", "8af0ef10a0d32941228e933d31f841954910baec347474e46397d8f18351d25a70ae080665f641e119cfd2df6cc6e342356cbe85790fb4054f99d48ebca8731c" },
                { "tr", "89e59561ea16a5f84e1e358cc94f0ab80c14e38f6c37fc8005e78fc19e58f493319b7aea786de728d348ed2cb307c400723ad04770ca24b67cc80d8299fa55cf" },
                { "trs", "af78117578640571cb617fa0e2749a423147b761e3a0a211bd240d3505fa614f6d8ad18ab22c0d7de94d01d58d1706304841f1bc81abf8613d24f82123e2bf78" },
                { "uk", "bf3d29130cbd43880fcaec4173280f724a119f4b011ee116eda6448f289744323eb0f00827e40e21101da0fc651fd8f702fcb9e1c8817c0f22cd357a72b8b62f" },
                { "ur", "289a32533e91ef183e98a92891038c397947d83d0c6a03ceb892c334110d72a166f02aeca4fc30d1912bad6ed6bf96e3a58a671b28eaaee2137f7eb7207c6714" },
                { "uz", "94cd032a4585abd65be74dbcf3862f96eb92cfc5d19130a314573aac3e0cbddbaf0bdde27ad6c244b1fbcdc8922b694e0e306e71789e23fc9ac29a2aee4d4eb3" },
                { "vi", "9b454facb9c8aa0e5f3eaf70adefdd85d4e3935f0b829295819b3349f866f4c1b3cef002afdc38f0ae38cc98bf516ed0918dc94657db3310e647a7d0b765dc0f" },
                { "xh", "76a937acdf3dbf7f2b4521165800824233c6d5d0c59ad31ec7b286d0a17ec48f1408ee7c247914775f0dd6987b6cea00efca84860bb768be4f7fc71443dad623" },
                { "zh-CN", "61ac931e908fcb609e235351042cfd4f5fb38212bc6296e6e024f3c8ef7720137cdfd851fbcbb5e06714513757297804ff3a542ab030f8a2f90071433f35ab84" },
                { "zh-TW", "e592b4bef6440fd0698b96ab653c623588fdc3c7c558b21a52bb0dcd802c853412bdae89319a0e288320546f4dd879cbe7ca581feca506989235fc1b0bbcaf88" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/155.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "94ae24ef8bacfc10627ca74e9c144217e1725ac557060a4e70a5500703e934831f0272324334e3b78de38bbbb332347ce743f7f9e98e2b126539c279b9966a5a" },
                { "af", "a47451ae10d292301dbf56bf7bfbdf49727baa55fc656e1f2b520a939183d3f4f26c2e11a2c737399b90214a47b9345044c47985066f7c692b363bb34f82f9f7" },
                { "an", "7f84ed2450576a575fd3517229d71ea1e722147ade9741fb3755d2720119970150c15e4eac7670a61cee9f13bde1c50a6c8f3c3cc511736017a165c9eaae3cb0" },
                { "ar", "82171e39364ae89f70895315c9ace23b51288f45f3868c6d45e96dbea50e09bc96eb096ee10b64134f1161c01d5952454b1dddb7c319b548aad296159b56a2dd" },
                { "ast", "b235d47a01d4da2424a2af2ae8b7c615217198baa3753786300daedb46baf5c21970e3927d0e4e320713167749e562ea0a92186fe3ea6ecf001a555b7a39dd12" },
                { "az", "a512c7afdf7cdcaeff2ff15e9c0c4e3142543519151427207d3a161132e35b62e5407bf13c6fb1a54391290be29f4d65d6b8f6d025757c9f583b08f15af2304f" },
                { "be", "647e1a69fc23218ff0ae63a82bd3f2f012175d117f2c4ee3aecd32b5a8b8dc15a73f285419c1a7bf69b32432dcf03df9ab366088a6306c816c7f5082b60bc5d0" },
                { "bg", "594430b46cba638ff4942eacd68e2433b7e159e5785885afce834c3446770707822b07c3f4545af122cacac1347a53070e54e6730beea04da10dcb0f96d10b8a" },
                { "bn", "cfe032700531e678bd7ce4a1a1dcf01021f5fff635668c1f4ad474751ab7abf324cb707825fd8fe39d7750d2d4dcc950beb86483ee46e8f30b8488964b31b6bd" },
                { "br", "886b6aab6e8ddc5ce6377b9c7b2c14d1e17756ba98a49955c6268bdcf4fdf719a438ed51474ca88117bb34217a852d72fe318ecf172b721b9d1eb56f6606bfb7" },
                { "bs", "2593b14a27cab2702f3ed4c69dc95e987825f9635ea45bec1cbae7e763b99d0cd39a40fc6f9298e43b4a5d0ddfab11a7782c4be4832c67cd61d36bfc78b17ab1" },
                { "ca", "7d985fc087a79787ecae22ce1ad0db97bd1ae725b7ab50698aad9dc475766cb04a405772e8d6d1298d17b3be2e0c9ce455137dd86b344637effab3a9321cc315" },
                { "cak", "66e39388cb34a56ed922e18b3a4b7842f7ff7aebeb7f981736487ca8b9d3e6db5ecdd5abe25dc37e965eade26787e93592607217baa1a163e89eeee9c4c7313f" },
                { "cs", "0882534e245d4122fac365c3aedaae05ba4aa4a82213e17256d0abf94577703800ffa841792a1cd0b21e1b8257aa6886c4fc63c9bf2f26cc42079a5c53729888" },
                { "cy", "1683b4c58f8c696b99a8964469850f3d030915f410d84256d426c486cd28ebd940e2fb6655eac8899c7d3a7d24855dfe98ac1a1fa3e3e5d0c45f538967560d76" },
                { "da", "84fceef663ff3317435509bcced978958799a7a06a140550ab9d7901730c402ab71ec68f46723a196e890af5417d33cc2f4a564c2b1fd0831cd7322317c75672" },
                { "de", "183d29554b325513cadd8858bf0c1d3dc369393e3df91b4a719b5a0b43e6fef3cb43a94ecec2d53ecfa20a1f4a0ceaaf14b91906bf153f801d68b092ac6122f9" },
                { "dsb", "26cb291d4cd5b268229daf4b711e7867fc4f920e0996fb940b30d0a0a245c50985444f6ee9a31c84c4a2829c8395a272d524e1da658ce53af0d4616144df38cc" },
                { "el", "e344b6541f98a6e1424a2c68a19c56d4a31329d938c1cb7ba7f7fdac4db99b5c82f835b0aadf0a03fba2c31996ff4b4bc0103e89e26d87386c686f5f297aded6" },
                { "en-CA", "778e3e784f9f2e99c884cba416eaf12d73e81c72e8da61109e33d2802df84452b2cebe056a170ed8ae44d8395224142fc597d0f84db4bd0ea1dd4f790505da6b" },
                { "en-GB", "24b568c4b83681d745e5429e8e92c7d9f924fa1164b4e54113eadce513c6a039c5a1b9970349feda6ead6b0968f141a358719fc75feb684e53d6c75e11f8a54b" },
                { "en-US", "f82082520cb7592c2b56cdafaad2d908fc9e7b41bd46dc15fb0750a1210eb810258f7b8678a0a6516a3f6536dab68702464f1379321bc14e4b293e9560599f8a" },
                { "eo", "95e3996273aec23f1efb6108ef29318bcfdea27ce5a916589f4b51b4e53debfe73c0bd7abbe722e2c61f90e9cd8c71c59d57961fa15a7b7edd9f740d50bf1eca" },
                { "es-AR", "9558850c800eeb321ffb8e3e8d94d15635d50b0ac6201cacfdf92f415d009a412bc29da87d03cfeb3eeda9f46bf1e87de0432f1b6dc43fef777ea87cb58dd87c" },
                { "es-CL", "cf1d268f350ebed8bd5b5b05f25209c5bb94ab08556275e74d416522ddd4b5f0d0bba4ff95222d9eb08250223b3829b31d3e929068c14c07154d8c918b661762" },
                { "es-ES", "677c998cb97a932ec27cf7f3521546837ea6ad0ccab20793e4835688abf5d2a70b43f56cebcb70bfcdeaf2fa90019cddb381d245af3b47d7db4f1c7477a38655" },
                { "es-MX", "18013070b6a1bea7f4ebbd9fa16c5cbf1f7026a8933f9f43d5fa14a29dc5da73e023ee82ee66b387816b64b4fdcc232a56ea13a989e7c8a1d46ee1a05060b774" },
                { "et", "10ea51f370cb0a5253fafcf36e0ffd94bb4b4d94606bbf82051a5f1a10f8e11e5c3eccb57974eb361efa798710572c16f282b55c7697139dbfc8c62f60fbc566" },
                { "eu", "14bfacaa16e2c3de31fb09b88c7e6480d18df65f335b2599dfc1707ccb06af32104029a5da0bac78d079071f3387542558d99cedf513d60aba729931cece88f3" },
                { "fa", "2ce8161696a5b51ce6b85112bd2a872ce0482abde8e4b5462575a9ad46a34ba7724fca634b3b10c9ad28388a54badf555cba46889bdacf630c6e468e94ae4f32" },
                { "ff", "4f848885946fd3cdb82c2ba9f99d8abf8f011d83702eb5733eb1fb4579fdbc3911b50f9e90c5d45b6dd9d2b19509a2aa5c8ae750e0b03e0e8982fc79474200b2" },
                { "fi", "2936ad8c45473960bb9ead4165fffe24a4510b91f9096520f594c2688c4ca27965b586719496de58baa02a024dc7c6a5f3cbeaddcfb1ae2d2a9657273f2ebd0d" },
                { "fr", "0fe4c79f769c5984ae93c08a28f77e900758c3d47087507a6e889793586b6055712a767d55698abb0097a687718cd6984c2d0fb323c208d2e508155b10b044ed" },
                { "fur", "0f8299b13501a65417d273d98e24d2b629eb6ee7c844d2f9ae4351f20416c1fee92500164df0d0f51bc71d5edc22aea31245a6aac60108c4344a53f8ed83368b" },
                { "fy-NL", "70b84f7b0778e174ed6e81d2345d7fb2aa6f38147bd50dd07ba0ab45854416b8d6d7b0f1f09d60424fed55cf59255397fda4e91550e603491089fc991ed707a2" },
                { "ga-IE", "b9f5a81f492e54e825a0290c9ccfdd0f961a3c7dd9b74dca009785b235c8214db247c502746def5455bc4e4b4e92d33ce94e1c9657d9667efb53d2bf5b23e169" },
                { "gd", "145dde15bc2a04b51758a0d2533950afb7cca6fcca7eaae808fb441d978a7fb8b15d0924d87192bf15827793d830bb45fd019f4c5f96fcce2948b53c81723360" },
                { "gl", "05e06a2d3dd7bf719aef3927073d9b18378ab0ee069410329055181a3d495b037df5d14cc45584942f64b7645ba650c3b59eb82ac4f753a13eb42c0af99000e5" },
                { "gn", "1b3d263b87604326da6cb296004c537359ee23cabd893f5c33e40ed1bca7963523871d4163b22040c82c05891e90b43806b773734bb924caba177020f126c7bc" },
                { "gu-IN", "6f56bf889fab6c14a94974f5a45fdb3281d37a0f784b871d8019a451438dc98c8d2f49ae107a9cc0cc2cb40ce70b3c050a2046a72ffc31e98633783920020239" },
                { "he", "b852384e49f18ba9a55a0933c77b9489350b0a8140e1e6d9a7e48550f61edcc4a9bcd4f56d9850eacc802c90a6b3bf8d89611f88ea5271feb6e731a7284770a0" },
                { "hi-IN", "0074c7a29a0ab03746546fa797ed41036a64510a61a36e50d27adf29862ca7e68cd15df77bfb3e6797dd9d66f307527d5fee99ed74da06dab1350157e066524b" },
                { "hr", "a2c3f3c3958aedf1520dcfcb5d5d68cda808d5048719f9a130781aec060077960e3c4094d207f1ff1bd12b6a012eeaf6ec40c71ed759daf0dc3fc9e37f4d3e38" },
                { "hsb", "606a536f0836fecab4a1f5b0b422d8ab1ecfc6181e2a31eb6b6c8b14086f36d408b1feb040dea75da042c0bb25e81a106bb19c78245ef9d0ff9b92c1aad224f0" },
                { "hu", "726770737d3328308af654a15cc7243632686611d7f7fb1cc156c94de5058a91b98c2eed954921406bd0b120dda23e63ea50a6a2388a827fe0dea8d604068702" },
                { "hy-AM", "31afa5a8301a911a724bddff62d37e6d0a2ffb3899745bab60fbb18eb54287765e217a7a13baacb5165d448ab8382094384969a0f94e30eeb6568f1f6b39dddd" },
                { "ia", "d49a95c86476c6365cb4867ff441138a4e75edd18e8bf656243bf1907b7c7330cbfba413f08aa0fd6eaa40d36cfd8fad8315186d89f2384543a6394e6b7e729b" },
                { "id", "df7cb3ee369e4270a19b3e5d4f2d05db05845e5386e66217966cba63a5a8da3c2bed79a38967b0615a2b7ffa921e65c761bd14e4caaeb0418475bae08aa0cc8b" },
                { "is", "f7080e7742759a28cb48051b70854e5cfa637ebe0cff41e69a3abaaa44718fae516be5a18fd5998c4e8eceae14cb6f74a0f749488f47b43af98c1fb1948142a1" },
                { "it", "3f9796a09314dacb3fefcc17e018875a1bff38374673102014a5998145a27825da5cdfa087984466e7a6671b2d0cfbef51a52f9997691207194c190461373f73" },
                { "ja", "525d949762460ab0affa50c960da4177e772c936b0163841daae87cac1442864ffce431c4198e082cfb0b86c764196ae36785800102bf7d834b8aa300c724d5a" },
                { "ka", "5fda9cb69197cdbd33607281dddcd6dcf4c8c3572d12046229399ae67f1864c17754859814d55db79476e55a6df624272cc9c51dfb35906fc9278acdc32ffe19" },
                { "kab", "17156413189a8b1978c90be0db68b7f71b1b3f4e65a4171d43f518bcfa0dbc94b9b432729c6c9938a45b3c8c0bd055164f8b7b04fde4daf9d3b1abaae14dd891" },
                { "kk", "4948fd0eabad6307763d2924f679071eb828679616312f8a075e1f3ad28f70c2d22bab5be7473e0467d5c7731d1745702d770fb0f5f65bdfbeb182dc5a545eba" },
                { "km", "09b0cd43be4167c83d6969f8982af9cd4ef67823ed9ff4ddac8424c7ede6d4c5e5554cbe9a016b2924a616e7c81280fc8111a5c0b675f876bccf9bbfa8c60715" },
                { "kn", "6bdf1bf561ca72f6a067ae041b86539d091fbfaba2e1d681460577a5cb5a106884a45d513aae37eab444b94367940d0d6d88143b90c9bfbe13ef595314345ba8" },
                { "ko", "53b1a4abecf8ed8a49166bfbb344b88de1485bbf5c98e0cee7fc03870955c30185e26e4800750baf4147067c3af8d7cef8b8bc4736a9520f82e67c35b6f5809e" },
                { "lij", "d3f1d272c2d8a7a5b1c062956e012356e26180306d5e1a2612b9336b07e6adebf8676a35eda6049a3aea1ae5aeab542456f87279ac94f737faac1ba8ae023d07" },
                { "lt", "bb0f95094549c253212270bb649f5e2a6c6c2e2faf3d04d82aff88b89f5a50f7738495361793626f0457a5d8e4daea22eeb799463f033afacc30ca9e5af9b953" },
                { "lv", "dd2f0420e6d8158f16fc147238fb1296d076907a64a2f3b0e3d311b8b3f68871b0c6784e5be095f8a22be7dba07f8ffade06d276bdc5f14ac01dbbd9f2394541" },
                { "mk", "2562ebbd8c48bf5ea3ed1e78d4b812bb3953c93383540794a10cefeff31f76ceb0592b72b74a8b4ad6bb247c795352579c3b7bdff34ef1335eae59b6817e1982" },
                { "mr", "04ffd54bb83ded60c5b8fe57d3fd86265111286ea30f25530d330f0eb1d612f844a3acc9a553dfee0f13c4e03fa968c696c91937d71eaa1b846079579d0c7e9c" },
                { "ms", "02cc52ffc844cc9864b66eec7b611a317d67a49b1df5a2c9404b0ad53bbbf47811033d2a145b99c64f75748b3e352e887d7b6d79ca8110b2fe499bce28b25a71" },
                { "my", "b75019b433b4c4d44df5990242dcb3bf6bd39b8e7e4038e1b8c1d85e156223d3a1c76938259e6a6103af222eeb5b2726520fed4cd2e9bd7bee9067f567f75693" },
                { "nb-NO", "580f1e834e6494f1923ce116bc27de5ce178844e9f61cbab62ebeb7c01256dd40d364033e4e6fb20b688901c8ab4651c66d7ba9af715b08e02fc8499a627fe33" },
                { "ne-NP", "f70f0bc53023be9b16d312197254c720f2b7c83372408525eef38c1147c77f781911023f6a7eeda1c4994ab9475563273dcfe7f89b63d0878bfdfefb16347d29" },
                { "nl", "fed7e5f52caa09453dee75c72f188b8e146790b8dbab041f1aaada2f70bf0bac5ff3721fd748c394b4e26d04b550675c08edafb6174c7db43bb5c5f5a149cdb7" },
                { "nn-NO", "beec8238c32d00d4c5336f80a01b73614b89d36c87053a12cedaa0affedde8ca5e6fb46a76366f64024aec91562e26b5e960d6309407de555a0581bd09750e1f" },
                { "oc", "6d5987b7ef8db1104a70e9464f73b7c8f3b973ed410b70de68803fda45fdd1de521c392ca2945655c4bfd8dec02159322b7752d8a877482c4418313bad2e00a9" },
                { "pa-IN", "b8a5d8ef1314cdba2e5cd81eb5de9c3f6dada32e5e1271334a78a638a6a01d71785d071a0114e5f7847b0de3f272dafdf9b82b3faadddea6b54faa95b7db74c9" },
                { "pl", "a5ef5a886466f30def93df2adf8af9c27d70c63e157575625a23f329d826c2afa57f1a72aa90d544cbaf784db989426d6dd5e92fc1aaf54b74f15e3785fc3e6a" },
                { "pt-BR", "0e0e3c140c964ce051af66771ee4887fc9a1f37409a527e7a3c842fa6626284e049a1780574dec275f054a12a3eaf94f731b768184691b6e5c5526a358237592" },
                { "pt-PT", "9affb129c8d4643a463246d846ebfa91f47e65ca76e042090d505add0eaf303166fd0b34db46a8a1c5fa2bfaee4380b914e88ad4eea8edefcc23b26a89319ec4" },
                { "rm", "fa6460d43c98d9de6d309f260321ddeab23c7800fb4a3e2a65adfee60654958492ed797dbe70cac8f03e5c6aadcd66b1e5fa8c29a7db42a8cdbf365f9e261e50" },
                { "ro", "1f4de7f34851d18993d3454b2d2db2955b7a818ed04c8dd984ccc1cd6628f9214b418632419f210c7ed2b319f867dd97bf9aacf4b5be155aba87dd83f2bff9d5" },
                { "ru", "1a17944d52926c8e2f8bc9a6e7bfc050fe2c972c25ee6dc7e34f44a984cbfe9950e1b54b6cc83ad602082532276b4295f8518d5083a88a4fdbb0a586becf52ea" },
                { "sat", "57e8edaa97c58665b52e8a88cc2b6840df395fdbabf0f93ec25f052f89fe7597f4a025fc6c6274d4986e076cfc1ad49c00e735421bfcc431b6204c970f4718a7" },
                { "sc", "f281eed1c24c086effa97302b52242e970be4b53e97514543f562c41d600ba2edc6f5b915f5594d17d6ebfb91e3046b15c0f92668f2d49ef90944c3d3587550a" },
                { "sco", "c7c28ecdf0c9130f62ba61409027f84a772a48de61404e259e6989c5b3bd3da1005dd7fcbabe32ef36c2f1e3158be7c9f542c49b079d6c60690c6e28941efe59" },
                { "si", "002b269d4bfccb939c9866ea8585858bd4191440ff333941d5dcb08430e09605e06c620c93e707ee954919e4bbe91df2df7a045e5b3f4d27b0bf8517c20870e5" },
                { "sk", "e775eceeb16a8cfcee290e50fa9d3be0768046574664fa62460529a1f6a6219937d77698ea200ddf7a7a0ace761deee667aa8bae160b3a098865f83a9e643417" },
                { "skr", "d088b9d7555f02b9d7c8d19b34a217b3268e9ebc3b801561352668189dad1781a7dccf889683ff2f142281ce476ce0c7121aea42c7e9a63eda814cf86c762f86" },
                { "sl", "9bd6f7808f3d551fc8d593821f543af6134543a8bc1d02ffaa68a22ddb634ddd732ef14f6f406a4b2696f1cc2cb0b3add94ba7debf0113abeccae35f758938c7" },
                { "son", "e04c08121d2b0ef739e789fc457c415c4285f2f688614c91aacd69fc8eff690c2a6d07b32a5784c1c4e8340fc729342370d3cc59ff5d13915b2e7c3509a616ad" },
                { "sq", "944e7ec6dcce522ed9dbcc68a46c474c297c241ebee44c7dd40482a3ce9c2b84ea51b328323bca6d7549f5c2840e1000a9c66d7e9b94a675bf2d4a1f982fb21b" },
                { "sr", "c5ae96aa0cc7ac355e9e7b14debe57208faed5516e2aa11061a8ab1505840c9a00592810b301ab7256271dddc8fa8aca9e592b88f8f8d98d11f6cf3909974e38" },
                { "sv-SE", "1c19336d1129b712f7a273d4b11f2ccf0bbd6db8f5e2cfec7462af15c23292df2f6b3610703ee3140bebb24668d3b179c949c81ed5e1be05db4a13600a81bfa4" },
                { "szl", "914a4a55758f4aeb64d5cd30226cdc3170545ac7f9bcd6288e4006fb370097a172d30243b645e87edb49ce72e18df5975ed2eef65d5a31df9fe82737c2c2d5e7" },
                { "ta", "8e016303ef8654c11d18b75c8a0da0daa7b19c2bf733a4300beb59cba4054d381aba4d8cf5ddb278cb30562e2d9b9eefa4b6e485c3dc01b5161d54b02d1a1888" },
                { "te", "e4ca8aac803e2c76efdbb470bfb71c69475bdd85a4f2fa17a5a5981fe54bcf88c088ac1986589d33ab1c9b251a2c3cd247ab23be7f934a1a2a566bae07c14e47" },
                { "tg", "a2a75e92aa794fda8c43f1fe3be9b9705b9721630023dbcc5922d6ca2273cece75128643dfc002567ea76780e0b424d0a32db52c8b70098d4c5fdda489c28057" },
                { "th", "bb9769d0e5ef8cee25b5d0f9f8661620c9b1d96d54660dd8f04b72d8da5217f03ec969ca070edad553f0345cf2d6ab6275d2bec216b75bbf00567663efcb0862" },
                { "tl", "e84d95efb6c389564d4ce7b684e9041fb33e1fc685854d9a07390239c0770ea5905ce502e6c90c5576cb8fe98a9aaa23547e7c3def58ad39cfe7f5138e0ced4d" },
                { "tr", "3ef9fe4200f8191e049c9cebf4aa0b0e93fa17c6372b912b63d3342ec90d81d62cf311e8184de027c3c7c71964cc55e680b435381403c072f965c3c9de3bd92e" },
                { "trs", "6ceee7db4f885d10a408f895f45f8bb890f55ef4a8cc0bc05c05ad2d8e9d70104532154129e8f5137bf2249b35152e41bd9a73495835934d4eabe9c0242ce946" },
                { "uk", "74b35852088c2a612e963b52c87f8b0a5d77887ef9773728905c528a79a509715ea4d0ffbe1575221c29973fce64f4667d3aeab31ea99b908da7a9ad4f5376d1" },
                { "ur", "93fe0077aa77fc5d46424437ecfbabe1819c4127e589d3343547415b112812c84bd05679c19449d8166f26fb8d049e98bd36a2535c5541937c5ef3e5b4f599dd" },
                { "uz", "307ef7ea1e62c40b2daeff98133e0ce5ee4b4de323e0f877813541005536f75fa792b3aa3cccef3f90df4af27d459c2dff4d6d2cf5650d345a9ab06acfc10561" },
                { "vi", "e1a6479281d805a47735848dabcb92ba5183f94f4313320a54e0709090731b15f0a38e84387c9148ed6e94e7e706596eea5a5b585803eb086324a6280d9e1ba0" },
                { "xh", "cb5096f3895b4669ae26960df2cf7ae4a854ddbcfd0a38215ddee523e4fb7e819b109c1de6a01246a0a604ba97c3d900e072190ddfa183c85fa01a0fffc833cd" },
                { "zh-CN", "87107b1f1ed400bb4ea5ef168545b6813d1d7e91d63cd6cc7bf98da3c7a7c84c00355e440023d9ed1385f325cbaeedd749c38f939f434e69724af7265953340b" },
                { "zh-TW", "da0eb94a22ef6dd6a562f5cc2772458d5f6752d3a8d1803e12eccc4ed782502eff67a0a92d39dc77184cef9ac325492f9e720a64ce7cb792f74650ea0e228fea" }
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
            const string knownVersion = "155.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
