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
        private const string currentVersion = "140.0b3";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a99256b0180efd57d485c6c0dd751d8d53921e5b0c30e65642372f2ad297ccbdf119ad7ee2bbdb41f02cf5087f1e7338818866596a8ec648aef95998c1930527" },
                { "af", "6adedc3af205329ef8dd9188edfda7abbdc28452e55d3f2928596c24291b5c0a15cbd82f00d78cfbb68583674856eee1b3ea450b8bd52f8f98a272f6bfd5221e" },
                { "an", "5cbaa37edab77089ffcdcb79b9d923fc977d8c03295fbec8b5d5638708ff7292bde099f5bb15c9246e17755ad6cc94bf437802b779187342db30f7d07e00005e" },
                { "ar", "26165bc50071b94068b50cbecc188fbb213c8dffc0a60934cce1cbd3f63953cddc16606969dba14cbd69efbabd6a8b17a9e4d4d0db8eaa36f685ab2d1a73f732" },
                { "ast", "eeb07e3fd45b224c9787ea996bdcdc0234483ff6385be50fd9c4165936451206baa7ee6aa6b1238eb4ccedb3f45b98fc75584e3b98f766642bff0844c3b6cda5" },
                { "az", "c98f976ab1304734b397fd1429a8816e31c43f40983d9f9076aa5d0f4780494c6cd9a2439b03be492d43bc8fd4b894976893517d063ff58c2ec24c85875b9b35" },
                { "be", "29a3298841fd7e8a264b544d941b627084e47ebbb072ca4f314b121911ac0a16c5a3adce911ed656fafc996ad74d943cb8d622b5c85a034320a05b874d4cd7b0" },
                { "bg", "14df0db70a1cb902a1cce119bfbeb3194c4b339aae7597f628b9398351699af825d1a4e2a65cb11c2d84a32989b6d2eb5bb6ecc38a7246df058af659c8d6e73a" },
                { "bn", "1ffe1f708aecf60ab5875103d23f2e3d8df61b3222438f407b8658c80282bf5e5d9d3c07eeff5396e97f0c0ecb1420ea9bbb442c09d34db25d53d488f7c9f15d" },
                { "br", "a763dbb60d63dfb437ae27ceb50d75a7e896dd51cc3e3c3fd639b3222a1b76976853d5912abe7b0332db6b7b4f66adb6bc35e1eacceb7cd2573c05b557a3b162" },
                { "bs", "a9012fe90e6d009cbd25a857397edd4ac8506222f514b09ed63aa803299a48ddab064ff82c21465314857deec685352ed088af5402435a84320f15567badffa7" },
                { "ca", "59888490ee314df9124bf9f38d5a0fffbbb3268288ceb0ce8f3d62b2c02c5f20b2bc533d52661504938dbd85d7dd70c92311ec297fe04b114bc91a59ba8e36dc" },
                { "cak", "56193da7dfb0643c4982c49e2899ef0087fe73b4e9c6941e4e3fd15bc8f388ac73264b6f65e21705b6b8e560888e3b16eb88177c444ca794f98831267dbce4c9" },
                { "cs", "f055942ca3a019385705b5ba51922d656f0a8a0ed5ee5460d4a3651692efc5cadf5a77f4f46b5600e6f45dd5d381204e6c2515fbe80de52a16a18e51abf687c6" },
                { "cy", "1316dcfd2eaf743d1b167202bdddd5993b9b729bc00f441d6db6b11e022b10364e11173af07dfa847b8041e5adc514297dea5d3c046b19c941f8370ee9352aaf" },
                { "da", "c881d57579ed5f5e4b0362af99560eb9e6470807e785dc6d35e304e7beb90f583a0e65b254d96f61dde048f0c0a557cabd4053a2e139a43e1c5877d69f70b6be" },
                { "de", "51e6f766fbb8723b1d08e53c9dc73713830631e1b2cc95cc3e4d2e5a6f85b6aa064ca05da9b62634d4a997538ccdc6f93bb623a94d1f456f34b34e92c06a4b96" },
                { "dsb", "4e234b6c3525ff18cc7f4251012e9fef0c41269ab51f87347b8476f3a397d385c97d58d22e0f3e4f5f7584bb030c14334bac93a7433e7829ac09f0e3a22f854b" },
                { "el", "031fa9231eaaa6d8fc0eb43e7536571b59f6d9d677d7c7940bffb5660cf4927fb44608735c4331bb102c171ba601b3de7bcf0442328da8fbd884b0669f50d72f" },
                { "en-CA", "30e1ae0720abbbbf414415f4ed748775cec3911deb9ac2f11b4b06d1fa9598ea32a6d76e02394e621144630280efab61e00961c2f67400119aca14815d414650" },
                { "en-GB", "901af3de7116ee6fddc0cc1cbe02b607f501f340cb16f99d6049fd5b0d91e494b0c96bcb9992ffdeae73056466cf98c924f33bd85e279d67eda0741c5f44d175" },
                { "en-US", "7f85407da91412359ac5f7082156b1996b6184a393b11756b37fdd5e7403a955b746e64ceed3418dafb9892c27080d77c51e9b79e7df6fe77f62435a49b50b28" },
                { "eo", "99e215948ef0e324f4d749cf7636da7619654da3fd7e5a049988f9c865905b4b0bd1095f59011be6709b27b4a65c78b27b81d6dbf8e345c83e5f7fc025e9c6df" },
                { "es-AR", "3828dcd5ae6035be1cd2b4310a983511fd6c510a0cd5716e5a5b51706b95dd19714482a463db6b7c636d85456a112db49673225f8f5227b3b1d5afd0ebf88a70" },
                { "es-CL", "abff065f4d5ba8205cc925b23c42fbba30de4dee621726fe194b9d73d04047ae8e2e1113266c73ada9ee5901b70f154b8dd38b7de3dc45141cabd9e578090cb7" },
                { "es-ES", "14d112fd7d281bcbc6d60de141556f82ee701dc89f07909f148d5ed3629d4aeba5e402fb6341967c9a2caf6d40b9ee112a6631a7b5d7d06cdaa4944f5d303d7f" },
                { "es-MX", "a760130f328d55c459fc47d750770774ec03587736c44f8a6884cad3f428821ef7620c7e9e3e1de310a0048501e51f32e971404e9af77445c01726a3a57343d2" },
                { "et", "0ab70c5836f4c3bc22329b5eadd8ce8cb11dd426bc6b680cda7d2f183c13ab722f613d01eff9bd17a1db03dd0c582d4619efe0dd3dc5e27e4a7d32a599011469" },
                { "eu", "a2c6b7988a4b66acca870a0d1cf026223c86e6cc6b96fe920df6113b20529f8ada90de01e91480196a481978115aa6ef0fb7aeeba7720a3b4556454de167dd9d" },
                { "fa", "336e49b52a8d322d8e3ef718e2189f92e3f6ac68bc2ca30eeb6e2eb633a8a9938f145f53e94f5087c242f6a350950c3bad00ef437565720b5f94f86feb8d3db6" },
                { "ff", "3e57e1ef936cac0d9d55c5c32ce2de76849915e7f46e375b0e4d61b6b8b2123f184b53cdda625d26d91cfa1d867049b388fff098655a3285c426409beeab3c57" },
                { "fi", "40629fab0156a237ce300625e18e53a1825c7b3cd9a36d9a748040249bed51f60880f56f0e7ebd1f02fbfb562d35aa6c74afb0e2ecf4da2a8e718def846df8bd" },
                { "fr", "f9280b227fd3e3bf6ec38c5fbfb302721a390850e23bd574611f3a4ed1b446f0a4b1f36f9c7f52cefb68b1cb9afc1bd3f619d48161fff501c3142032a5187040" },
                { "fur", "e7952e4f5c4debcc44b98818c830e0b627c3d7eb781c0852ec3a055d6cac474d7031a1e702ba41c0e54da9e09afa61117ddcacb9694a9bed0890076abd1b787a" },
                { "fy-NL", "08db8852c71d996602114553a498e32ccec557f357f6bde0d87702a734745924c2bf988752d58766b0a82bd264c76e02861f8632f4bf364feba97bc583caa892" },
                { "ga-IE", "af82a26dfe9fb25916ee3ab294aeb58f7ccaf0ddf63bbe0246a8f9f64a9ec5decb84d827192934eef09c6c2e07211cf0483be558a5f738f489b03c00a822bc97" },
                { "gd", "275b8782c1743e39f4c468fcde03451f1e27a3823c764411bd5bd519f040d5e702d6358dc78ef7d5e6d1a965f518a8a115352676adb84c3cae9b5be89fd76ac3" },
                { "gl", "184c0383751c4521349c57521b46af95d7c3d3f1a70310791ec547b287956ddede91b06de223ed9f064fa60195b29554a5216bd23b7cf7f06078f7d8394c2b7d" },
                { "gn", "322ff68004028e26c3358ed495ad03cef835aa30a142563331d29ae3e624c0ef238a30eac3fb4bb391e58d62f29a38df9ae5fadbf8bb27d54a50aca2779bf8c9" },
                { "gu-IN", "942e134c28b4858d008bcfa4404069df188fec8e00d4d3184b67a76989c1e4082e9df30c6fecca8fd2bfc959effa237e9464c568610721c240691674120300f2" },
                { "he", "48786146aeae1860d9a580b816fd1ad3631d14e51ff19b73153c9b9a75ce9c84754c1004c44bfbc599ed0d9d1372f27966f91b583ec40942c622e9c8d01f6979" },
                { "hi-IN", "8a61e1f1d236ca95e01c2957844a11b6ddd3664ad1ce421df0392a824881a136c5eb03c82e775bd0ed99ed2be77ae3fb60056ac5ae562d6b49c824316ae8ca99" },
                { "hr", "06297fdc3e13b765797605f8a64e864a4c0a6a3c3baaba1556b8a490f1b2f7eb146c5e7f137899f9eff3db39d12c1e7c4d6c5d41cd6f4722818497b3e41d185a" },
                { "hsb", "45300877af85c284d4d424c5fdf1250a63557afbc3a29c201f1a6cd3d317f4b8d02f7acee95fb1d5c1021befe3b58fea833a92ce010de987f9b08607b2e17fa7" },
                { "hu", "a019d8f21bca43a2d5cf180344a62b4e357f0bb2705df97a81d002b365e2f3baf19541b7124be6170536a3039e066f2806ca793d37d8de43d3ecd8fdff7de415" },
                { "hy-AM", "55391e1640f8751e8f81577f440450cebc8794a7cca1a153e9cf47fa06cb1ce20f4ba26d9f4d59e9b1b00ba264f4e77c2f05d8905ed20ca3a444039f8fc8ed97" },
                { "ia", "e45f62a6359b6e8f49b2c93ad9617623cb017e1dbbe64e7051246601c0d47666190f6363b491a0b6757e517396145fc499ac23a663f085106e6342e7a5da459a" },
                { "id", "6819657a4dbf2bf9fdb4951768500f7afb4357b9324ac8f6c38e93f8cdf2dc82c38a7a9881a346b032aab60f271431a80dc135635992068bbde9c2699158826d" },
                { "is", "168f94af43ae3fb93b6bf73d6b8f6c2656b32f9670bff2240a8e606693bf26568936ec39f0ab8201c720c0939ffb4a5bbd192751e328b714f491766be6194676" },
                { "it", "643bd08417ea5d4515cb9e2cbc7fe837a028c563070b7b3a62947355bd3258e5c05eeb9f05b34d61731c0fce548209b08000e71e49cc2e3528f51992b4422424" },
                { "ja", "9d514fe43bc65cd018a038b3e65ecb66ca5900492c4c9147e497809e76893f2ebb91c77fe3e08fbed686270cab59c9f7642407ff2d3736f93ec03f36af3ec54e" },
                { "ka", "90e19d815b09aad112425dafa84be4baca9e637c141790c86e9ccaee8375a754e5e28e43858073554eac6a2de8851f6a32724c58bc515250c1913e4101b4d71f" },
                { "kab", "f04e35109d40305d2a1746afff7a08997fb344ebdf8869492eba19f0804def98390d622489f59fa073b8af32812ef69e09c9bf0bdf089ac5ce27867a12f1d70f" },
                { "kk", "db28f7618a4f6776f18d2b0160a52cbd1ccb1c07babc0bd02838512a684823dfd2b276e1e9aca238b1a53cd3c7bfaa8df1105a3bb01904a579a41f732df9165a" },
                { "km", "c4d43b302924f0a69463ee94ace64b95f35daf5fe976962f47edfb72aad3811c4675f9a30b43149ec458b18d4c7cc78b721c79d4cf9002f45640b7c1e77b6eaa" },
                { "kn", "c0a038c8427f2ca7a5b51e3f1f176df65ab633e743b57cfa4a2855a30de5b89f31e4417b08a4a07b0d4785459078ae94a89e5d5f0254f6701242a006e21fa017" },
                { "ko", "cbbcf94809fa7038025432dcd9d4a6786f16be4e28804587dfd55bcb38ddb9fd0a47c5dc22996119c375e6f374d0c4b168f90bae33759e8e0c78dd03d0a79252" },
                { "lij", "d7d8feaf1ab689af3991ed02ca1113e5ec01ed86723d9a9b59eb2a343e81172394399a764f62a6c90a64f6fc9f8ee44870ed614d0a6d8c80046127c82d11c69d" },
                { "lt", "b02b8541b9ba1bb1ddc93a77bb6473ccc8b43151a24b9f27f4ec4b65c509290fadf6db50dc6c2a7aaea65b2ca604a455a3eb7b91ec68a6f0aab1e7bf1751578f" },
                { "lv", "fab0f0d193a52e233b6e3a3533a7c0ef98362ae7a465bded1fc6eeab760c25335a238fac8031cf4ef6952a761b22c94947eac851425fbb6fc6caea6bc22c7b1f" },
                { "mk", "873f612d64312697b178af7c865a8cb1c17585c9cf3ad0e12e6f55c1f32720bfd7450042149921297fc7e42d9abf427a99f63f78fe66aad6156769df10222ed9" },
                { "mr", "7c514d5207e579d6fcee3dfebf206786648eb9cb4bcdd8963ff979d9d0a715778e248a516575c0f148e9bf116babde102795ab867a41789ad06dfed62c579e40" },
                { "ms", "6e306b84a3ea9d94d63bbd64d132ea1d171b0e6acb2d7e15055a02711f23f5f36a94553e8d65694d36fc5ffee3586df3bf00d1ebc77c32f076552f2437bb82e4" },
                { "my", "9006b04fa67602c26ad89aba95524914cc65291f11a916cdba3f58c1c8f6fcaa275cd8f4610a14be1a09a2805ec17eaa5ab13541ed7269d67e0b4bfa04e02d3c" },
                { "nb-NO", "2886ea419bd66a279d102ef3df6a2a0e021b26bd1bb94a805175df96ccbc751953c59b63af5e37afee3e6916225b72b63191182be1eee794354e32e394df5b26" },
                { "ne-NP", "2ff292902861d1463f0470a225a6e131a3dc006e2f8698e73b0786b1e87e902c8dabe10ea2c138d2f13b691cf66f28eda7a3447b95997eda3c8c53ab6039a3a9" },
                { "nl", "38531497963f3c30eafc5a9a5077a2fbd79a94a57ea6cbedf81f8fe5ef169983e40f8e73988f022a3c356b3cfc35a078065abf79858b33ec1a92b9edf1c4a3ea" },
                { "nn-NO", "dc492b95777ec3588f4c5d39bcdb8547517c8eb10057905e6788064be1b19eb55a2f66b67b5a020811d806661f363ea67dc75bb14daf28c28aaccb6c3f1489bc" },
                { "oc", "b7465fcb584910f7820f24f33adfb1c6bf1d7948994942d7c78d038c7b9afc0efb314988732392ea21dc4dd4b72515aef3ac12322d5c4cdab8323daf121cec0b" },
                { "pa-IN", "deafb57fb6364a7e1ac49245bfe7ff238af2e1cff7be9246e4794de7db3ca36fb9b7fd94c44a36badd0096633bba4ba54dd06f15f43fc4cdfb4a6f2833f14fee" },
                { "pl", "7eb8683b45e33e157d6106127fd2cc1bd99aedac7b4fe7cdc54d3c10ae6bc147dc0875c3e44c2544711f768e1c1c6467fb70d72a265c1b80ab0865c1306a0d49" },
                { "pt-BR", "7ca64d7f2a84d0d700a0eb57bf5868f96607c1c567ac8bb0a3a76ef8706674e78fde0b1e7dbc3cfa6536f84e80737aa82318cc9f6f8f39730cf5acc370865c3d" },
                { "pt-PT", "2d5e89480b524b84004f788853085efb7344c346654bc8aa0ecc4ebb041075de723550246bb20f6cec4775e6c655ac653de976349803788edea36f4df170b5c7" },
                { "rm", "3eb82c5b97154ad502791e8d1a76d92cb18c0047c23f4ee925190a50f66415f51ba72259196c0c8b00e39f95fa6c3adc208707867365f19220c9069a1477c018" },
                { "ro", "0c0d5c3fba63b50bcb3d1e233f1c7581a3afb1674d1e5ab70ac79f57d8f22d6754e3117785f0d441f436a1153ef0f7096923f2edc3aa88345d4687d5236258d1" },
                { "ru", "4783b39da4e3addd80c12291b89fceedf8f78a6eed45ac8b0849e0b7a214e15b3d221e95622e6d652df70f566c5eb1e28447eb0bc8345e3beb51b788942a1118" },
                { "sat", "1757a68b8e741c0df200acb67aebb2a6b69b5ee22b0b43c13d8db914619918b8c572f18b4431117576a01d10a476f6641c0bae59c4000e6669a39be7b3d0066f" },
                { "sc", "c1dd1fd69e33b00b2d82a0ce9f32cd413684b4083cecdddb1f6610fd49cb13be1c9b9ddca403443966de361ddcaafec4e7fcec624faf35f6a592d57ce7a267a8" },
                { "sco", "d310fba6ecaae8d5d88bb61271342d6dc1f9fa42f2be3caf57784477423adef4119eda72df018aedd3a55f6289518907e719833fa0a4eab4cf3c8a0e48fea30d" },
                { "si", "02aa54520aba924f31fad9e4885bbf27a99f71abbbbe51d99ff71020c8318e2a4548552ed2577e34437a0b50d4f521f834105cefd2e0390336ff55ae3444377d" },
                { "sk", "650dbb7ced925a4c07c140d3b6c7bd06929af26c871ddadbf1369cafb33b7217e7d0e483df224c820e923318ecf6edf4121dbbfdf57baccae37293b8efb48aae" },
                { "skr", "d16191dab10660cb0962780962cf22e0422905ae0ef313fc94b9358548d50bb5589c15bed0c8b5fd2979f564867fc5c4b1b4738b64e673eee0e2e7fdfe18b82f" },
                { "sl", "85781a81d7cdf7b397daa50ffe06f16760d988f560c2f22e1f31dc74c357497ee31730eee8212990ec7e0d912ae7bd9c59970e98e0dde76114b0bf2c69b2bfba" },
                { "son", "3fdd354a16a513769a7dc31e28c64bd7e8486a7b185e821d8ed67e241aa6e3ec07d721f758565728228126d4ed4833fd4913be0918673b06fced61f08611ad0b" },
                { "sq", "bf575e5878d47856d8c9d9590a285f81f877242ee9085ec6596e4e3a684e307374b435a546946a8be1e89c05fae969bee3d42f88401f6b788238afe9df943458" },
                { "sr", "7cd8d4ea3b2fe1deefaa740b0084000f9a380a520f35baf65380b0ace185aa4bde4a5d805e542f4f51ac7ff934c9ea2d038981ab869027bbf83ba97a214bce76" },
                { "sv-SE", "ccc840c2ef0c06ec86ac2467126af27c03818dc6f0079277e92a688f21a198102ad23314518cd7ba3186335b60d0d6120ab2f92c8a4cc5a1d49c96515d3bacbe" },
                { "szl", "9e64de4899d284f1ffb2a1e2fa566366c90f0cdab02c203c68a7c6b8fbcf7e123796bc2b28fd7f306e82e1b9eb928ed702c93dbdb90aab705ef3c4c5a181b2fa" },
                { "ta", "dbaca2978139f842521d53f4eb1d031a61c9315ce9dcca2125b39e6696b4b17ac3167d08ab6d7a549d271cb32a1d80da4db3b34932bced8d324677a9fe5311e7" },
                { "te", "d9cbc7b75fc945b6794b3a0c68a5e70c2dc577acb7c6b5b09381ec60cf81215417234f1ac3b6ce021b54200a6e0a6bb0ebda342bc75de63e487e94e20bc3d84a" },
                { "tg", "6f35cea189c144cd82c7f4800b4dbb1d2d86404dea71878d40942310eee1eca495cc8714d565957975805354873dd960efa69f2d4aecd4f0d24c95c72c494d0b" },
                { "th", "b22a25ffe67658fb52381408033d728a2b813b6afd9efbf30826f2e56aee05a15c90c0efccf23aaac91056fc083f479d4b00c124e050f592ae9a9d57237a4da6" },
                { "tl", "545bd1fac63d31dab13c402ff077bbeec2975474c6cbd4bce80efa7a396147bf3dbeeb60fc9137803e7fa2b05d4dd435e61f0fe367b004ac06f5b20ae193e7b6" },
                { "tr", "f5de43cd3c24f479e316c1eaf7ef40476ec1804c8d8a4d93a072feb1400e4b9ea246b909183891f1e5e915aadd9f217a446a08bc7afe7bca6ed03a26385bab4f" },
                { "trs", "a0f4b321fcd360f68b5f62fdfd5a6542ef43a0ebb84dc8a9d241a5ce252ba62e9982cde4c728c4b0bedad744974c159fc2a4b6ca744d7c8c8c51d90260578e89" },
                { "uk", "8fb0941a958c62a6672cb99107c99adad2159ce30868caaaa4bb7553fcd606bf35f31d25cf0d5155e4e486a7eb1fd119d1efa64722447470fcacb52edd35b4df" },
                { "ur", "83129d035a0db13346a35e575dd0b396704a36477cd7a0a95e010ddf1f71e394163e70df1912fabc4fd4afac8c8c341435343a1e7d62a6ca9acde5c653657d1e" },
                { "uz", "469ae446fa6273dea0e2b774254098fea7ffe348b030ba866ad44043f9ceea590f37effda94402858bc16860a1571e50c7031c3173adea94aba220d7a9261bf1" },
                { "vi", "62d5cc2dedbeab14e7df60e487e916d41a2abcd2fce98ed3f778c76a70e51730521f4ea3f6da07a214f2335e461b44af90655eb8154848aed52eafd1ab958117" },
                { "xh", "808f62c0d6302a3f5870b9c3a6ef773a3705338f3548a015a729948ac8459b35bf045911274160fbe11370fe511df83bb7082bcc6e11dcb7abf3863ccd6421da" },
                { "zh-CN", "ed68c8206beefce2f7094d2d1b8cd6d1b8aa8441263ce980912fc93e73cd7b27949adb4ece902109b72e88865e6152fd65fcfe2b814239d8ce8880c9b194970a" },
                { "zh-TW", "6271c611541d51f900cb1bc20caf6f70763e91603a6a936bb826515a17cad22c46da5e3c50add1cc0367b3e655dabfe4362052dda3b28ce2993d8dc964962713" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "67797e62b34efcbdea43df4816009226eb42f2b669423f38312cf030405e7284ff93749bc2b713be7454730a2525e79f47c9a7501196c5e3581e145f1f6180c3" },
                { "af", "6b8631278abfd9d0e59ccef1fc59d6ab8546112dcfeea62060263be4203f2e0f1caae794eda4274fccf4e4be8a69efff8b95c37892e5b64e05a9be7c6c49928f" },
                { "an", "6e62e99043363b0d17aa64054f37dc4370f9cc5439f37009840db1075f7becca27b936acb62bd15d496fc9c7dca98f49dd8ecd4ebc84b5170f3aea5be630666d" },
                { "ar", "19179b9bc7f35c968c8f91b825f7040734e2d4ea5f6975866415723ba1f6ad6103747e308aaf3943411a134aabd96092eaac005c55c89e4b43cfe22fcc640719" },
                { "ast", "fe0e249333d3a7adfe46fcb6b7edb11685b8c110d82aac39d85245d06233c803f828c44cdfc766db0665206e12f1fde9449ab9477011269a03f765287ae7a1da" },
                { "az", "76bc034c84afeb2b556c749dac9b8390c413e612ee1e14606056c70815689c2a133532cdbe43b30ea63a918f581d5fd04fc1f86926f3bf1dd803dc75b78ad2fc" },
                { "be", "d3d20a079391183234989c79abf04b610145621c5316ec5d9716798372e6a939097a4e775ab260b26edd22da5673e3d9258a16d57cf4d49d742484505a1a1783" },
                { "bg", "1de957bba483ae1b0e666c5e56c17e5f75bcbd72888b9c21529ea05af58354e4261923b37558c7d595d6868a82fd2f0ae62ad54122e6c1f358704db309592977" },
                { "bn", "1ee6a11c64df5cc2778873e28c20480aafee015bbd62085ee14528f58f2ca44183197862c83dff1b5e8c45debc4e4c5c574a49fc5b19b724452cd3a7ca717ac3" },
                { "br", "33de131c8e52680c7da6b8bf026aa89ddfa22bdc8029444ce875ad4202e32900b1dc4691d78a170c805f18a8c8cbb26460cd9f99460718bb1ba0ca4b3d9a7f50" },
                { "bs", "41e2c5adb61ab0dfe501568bcd16eeae7dd1489e2b1cc1018dbedca11b938dc6351dcfad0d28581aa8dacc7e7efa2ff5993ebd1b44783b3e4880d15c706b3166" },
                { "ca", "3acc930035f6781a15709ebef89e58d4bd2e9381f52f828c35fab0f05a8d443f7e6b5f53fb69f2d8a8d0bd83d6cd8609b61bd7bc3197e9d1c875c7ad543ffd85" },
                { "cak", "36751d7f28f9b99294bab702e66900abe9309ca87e541b16da84f205fe3b9fb35a04df02117a1941cfdeb6bc7bdf9e02aa0977a92538b758a6f6adf1db45c536" },
                { "cs", "05ea87675bafa647f66f31dc27b645d69bb5033d552809e44a24f6668198e51354d240272c1bd48be1b14b308f6e173bce0e16ca266d0ea0157dde99cd933070" },
                { "cy", "73cc6b7a0db8251644d9a9fed7378208f09a65223f59269d3652c9cc1277f630df827586a48b234dd482c3af4a86831b27c88bebf904f17a74e7d0108fdb7117" },
                { "da", "2506d8350789e72e71736ab23ddfbdcb63793261ed9386f373e8837a2c2dfe852313addff32223f8d10ff14674dc475f40caef51c82e12c44aac96a3fd506912" },
                { "de", "83d404bf206802338f74dfdc847fd63653d385d5f0efebd2e00726468101163bf8a7bc846a9dacd3d7bce1b5af695c4724ad27f19140836fc0e7483454a3c63e" },
                { "dsb", "e63b10f837ea8cb554ca31b0e2702644478266937722f271987b17f31ba73f0d9068003a151c5abfaeff2834ee75f6c444bb1f564e0961cf4e5af23aea9dad35" },
                { "el", "fe79269d5982e46c820b950c19ab159bfef20e91c662f90781a7c9220cf44879d55d197a8d6fdc447b9a13165e526f0fa251a05bdb58a470c143d4b9adcfeb5a" },
                { "en-CA", "bbbecbd79ec8c4419cb3c46f063cc5dc8b305a4195af12a4eb38aa1f0aec6d2154bfb4161d3e8e9c2448350806517a0d2e1f43d54c98626f4f30804bbc3217ba" },
                { "en-GB", "3b5144662f1dfde4fe05161a525c968e52f82fa8573143f4074a04cc7788eecd0704b69327c1875d918585b05880a76fccc29eb5fa390cde4a6d1e19b2a28c9c" },
                { "en-US", "85cfcae56ca95b4a6383b807d839d61fe7d8ecc94bff4f896dc7f207c8d165aa2a63559cf8710f5a314b6c53ac61339f3193bbe4b0f462d56665cbd5f330e08c" },
                { "eo", "2dbbf763a5227e699bbab4284e10bd163b987ddb0c20c0499939983baf2be94988d29e8fd08cac4a09471f43c9dd437954828606431bdbd24781d8521f17f755" },
                { "es-AR", "dfcf79bcbb6ff9d1796a57c82e4757780fcd748ab28f44266fe6d2eacd15ebc135c9980bf8b79d19ada18af46be92e2e289380a9c741c236e1f90e5c1b9d3a60" },
                { "es-CL", "b30771255e6b4e6a4dc595e493c0fe3a39df04fee9c06c3e952948e3cf029ee2e038ae60b02d6162bdeb1458c6218e038660fd23d431903bb5045cf121ecdfc1" },
                { "es-ES", "6587659318c846637b0526c7e7e70eb19cb752a6892d47b45025963b637c5f34395939fe4195946017ec5ad74c761933c8f9aaa0fe637f5ce5b340c13c55d560" },
                { "es-MX", "f7cc1b4946cba3cfb854e37c0a6434056a52f18fc5e6b4157b921eee89ea0905447345795f005b6b993aa76c2836109e9a9e0154e21cbb2403c367af41f79195" },
                { "et", "4a284c168453b3fec3719b8ea5c8c37017bedcf13a061fbbc8279b3e52444c6526226fcb874b4eb9c2f30f1a8b4201ef240f740280c2073b7ca9416f3bdacab4" },
                { "eu", "5f2a0dc565b723493d3d357b9afb602c7cd79738c5c2b56bbee61ed37e0d915fa2641b24892efdc19f641d553eb74ee8ed3bbfc14829f48048bf2fd50f59fe2e" },
                { "fa", "133e2232c83acec28d69f73426c4b3ad7e73cc6d7b28cbce96cf093f731a326139fbe2bf88000038802a2e43749551f7d45e2489c683b73edac918d87971d7e8" },
                { "ff", "b7cd4517cc2238e22c32a8b677df550bede851b1094ee9cb51f6029ee9afddbd8b4e99c10cb8560fd9115490f80c496cffb44e8e36618399ed6c221cd4b1c86b" },
                { "fi", "2cbd096a26a75f64cffad8454c69bb2ec3d1d22b2ec162d4113de0d053bca2c41c0a0f4f39cf56870bf09c44967895855e8b80218a9d12104f894571758dbaae" },
                { "fr", "50a8daf5abf9fcee6809b28325968392bc69300ebd2d82d4943e3932ca02bc6648b1e24a9bd168154c98354881b943d277f5271bfe2fcd73a4692161079e7b64" },
                { "fur", "a003e67181194f72087cbd05327159d1d5ed510ec637ca0173c63b0525818bf0dedd2e55daa8344639ca44ec2bbaa6a7ad457d2b1f75e864ddcbf7a3073b446a" },
                { "fy-NL", "f6eed3aed976832bc68e6e1fddd2bb2e0d220794c624e97f1a6408047d36f6f4d766597b7adba6f75751419b47f6798b24550fe38ec9f88ea78014358f55eaf1" },
                { "ga-IE", "293c2e1eeb1ea0d8bf3a08c604d84d48a7be4dd30c07f921570a5fd57da52085ecdeacdf0dbf0f4334c31e98691aba6cbd2f65439c851fda4d50d982fe16c926" },
                { "gd", "839caaaaeba1a50e91dbae2524dde9933fa6d2e238ba52abc0b26e996dc60a53a467c031bd4a02e8d8512dcc38c85c842e96468682c2b7613075a3b4d43fa7c1" },
                { "gl", "2b9b48a285b5af847a44d96d20290219b21c1bf0c4e2788add5d3885ff5ebc6f2501dfc0b4158c6a91239dc5c3d945d1dc172b087a0fd591445c2d21f74afa54" },
                { "gn", "e830f3d669644b40250077792d5fe80944c938a24dd12ea67f9f9e9884bc012256e21b928d59fb70e2b389d0c4850a05c04c5426a5c4d48609f6746b34172dd8" },
                { "gu-IN", "6a3f41a25770dc614534c2ee88cb947d27a5ec0593c1fe0f9207cded50f96c92a094da319fc2055fc705c3d2691cf5feefc7df496c1e731449e4d9cb7a6b7b41" },
                { "he", "17ca333791c5d38e2cd85120348f1fcef978516765f9fb5cfe9b834f8b84afff42f5a0e48e5f5638a97c6404535540f433e5ead410212db0626e23e15e3b4bd2" },
                { "hi-IN", "3d18b0d9b9642a224206728af6b7f6a8b43b673cf5328ada4e4367881ea0c8b305b446af9262036e428f86da63a476cce1976e4ec008495aba6e411ddc12d9a1" },
                { "hr", "27c7105107f033975374b0094f77aaa181757fdd862b7906085c87ccc917c86501e20f87aa5a9746826dc88d10413552a24225de782c2e709d5a0e54310ecd3f" },
                { "hsb", "2a87ca28edc3921f559229a369e065ff5238696bd2d4c54fb2ed4ad09d47763880072fd391b2479b0aed47aa8a408cffd3933093365a7ed4a14bfccb862fb9c7" },
                { "hu", "d6aff4e675c2e9444c6bf0bc4cd0db5e92c17c6dce0b383bdfe147d1be22e71f2fbde9bb09b014341386f58a25a6c27ca32a9d28e12420e5a4048d579a235428" },
                { "hy-AM", "bade9326290be6dae7701533725be757bf1f078072a8f7c526be6e49a4fdf468057082a84840e386915fc9b1f758c1f2471c9ffd83b35cc51ef4b184fe76ff85" },
                { "ia", "dcaf5f256e4ceca739179acb9bd004cd80953b2d3ef421ea98c6d49d96524d3389c7c15ab19587feff65b4f7cf4ebfcb607c89b9f95780b20e2063b79702a0be" },
                { "id", "ab568a0bb780f549707a82ce29d85c35fda2cd3954702b46fa5c7ff7c02a1ca95b0e83284d5471083fd85abd572cfeda39eeca81e769a0cd1cb0eaab74ae3707" },
                { "is", "929f90a1b1ec7f7a8ef8d6bf44f9da8a4857f729b8fd9340c94d58d1bc937d35839f16851a81194ababd1d41c351dbbfb75f1befb83b2b9df501fc487261328e" },
                { "it", "f637005b41c7829863106e9fc53a02c082573956ac404687196effb2d5574b4d1d7a99fbe2fbb53284d63f00a237e2d03a1660ad62fc58f33e9c9cec5b522d7c" },
                { "ja", "d4c9d8c7dbdc1ed54b212c0387e63368aae6be8149212e5670d736c6b839373286bc7951463d346e1f8ae18d8ee4876b983391e35e18b745f9a62d884aaa6dc3" },
                { "ka", "b1c652df32e0eef82ccd84cf736bc11ece790a8c5ad629456d393607f736291d0d0ffbe7e61d32d0f6cbfa4195d9e85e9b2f643127cc65a3aab2a936aee7f5a9" },
                { "kab", "bc9ae0df73fb1f70ba8a94677411d12c1d4e246c8b87cfe407352f6dff91e37a16238a01bf93674616363641b6bec431934a94577380b862749df9b5c26bb570" },
                { "kk", "6e8c059ab3847627674d0340e53d1a5c850e895e54fbb9ae6b9bbc756df3251b711334b3d1506e4b425f2344233141e7eb872cf7d6a590b55a24ea9867358572" },
                { "km", "30545098495966f695a062af258589406562f6f4c90252cf89e668dcc588b5ea5aef7fe7b7772a9a47a545b24de648f42180b57dbedea595455ac3b10cfdc409" },
                { "kn", "7fee800958b47d2a6bf0b317cadee6fda6dfb0499c68ac078eb46e4f9850c3cbfeab784f1a7b1ef1cd9e1e44a92ef7e909a6f1eb79d80dc04d7353b7df891528" },
                { "ko", "7e6d099bb1b5297790a2345bb971040741aa2bc43e95ff7056af8f03953ee829caae39bb679305499d5096a193995eda0c46cc18141941eff307711ec50ef4fd" },
                { "lij", "722f1bac6076af150ce0b355ccb6d2cbd6ea67a261fbae1d695708cbb490e7b0448e055486141f46ccf1a8ad9a6e3d0fd3d32abe15fd9194a505e151c600d511" },
                { "lt", "ae48614d83d0535d679a33a11d885d5a612fb61f854682589bc0d77769113a4da66a669e8a11335c9ea64440e195c14b2256bcdab39ade9cab21d5ee8a7e5e86" },
                { "lv", "236a109b55abe5c0cff8cb1936a07b9af3c7c808c5e86e731ebce908531cdb447a9432df97596e2d1a2096661212398c0ba1c3478feba3fe10a27a986c02e4aa" },
                { "mk", "0189f4615c7a023b61c4fe6e01827d004903f38cd0be3d0b40aed39a1e3dd468454d7ddcfd91a1ba9ae806101d04cf9d901e0dd8f7bd8adfc73a341d60d464ab" },
                { "mr", "2dd6ef0bb50726034d8030913bc9051b0e6d807dc12c31e708b626a8765e88f578b9f9624b4ecb72be8440ebd39444dee06752b0b0b5d0171f526b4f386aee21" },
                { "ms", "72f43def5f0239575f6ce131f1a9c35c4e3ac46a6df38a187a3087f263c2886069d9043e9b359ae6b0f4c1f48a7aa096f91187339202a730c866657ba5cc224a" },
                { "my", "52cc8200a020712e49e370690022c8f189496ca8a832d9ad391a7a7617880a6fe9768df34c510e9d11491c1ea0dad0aaaf81fc10d2bba502d629c55334d3da89" },
                { "nb-NO", "c05fc3120e0c79e111fd071f7131df323c302345609fee72467ff3ea06371068192f9489b3773888b26f4790840009e50f13919f300ae7bf500a4cb702a1675b" },
                { "ne-NP", "848155f5dd4c5c49e8e28d2592a82772fd720676a2f93f536faa8a6f179e2a31db7507c95d871c60fb8cc40536311d7f45972ba7c3b844de28697d585016ad25" },
                { "nl", "1045ffa20fb01e49eeb7b8dcc69be536886fd7cb048f33ca8ce3508fbddfa8348c2791250b09574d6912b4bbb583f682069bc5b14b3e22f9e2aa553e7fc4ce50" },
                { "nn-NO", "47c1b663504fa1bfd1be9ae34f03969c18c09fa02b09ba48947eea176a32ba136b014b6971c6e4c7f6cdd4401d6ddd8591cf2d2f188552d56900e49a7aa9c994" },
                { "oc", "b9dfb400fec7a339771f927a8d05a486392d88c162091a65f48e087a89d5da00222734476c896df3a0b975625d88c6c5774038dbb4be88eb9a40e7ae2c800b78" },
                { "pa-IN", "8a0ef315b8858dc5a42b16cf0ee611078fa582992fcd564826abbeecd9a2760007a0bbde5b0efeb7068396a37f164f17af64ac23807cdb8c58160f0b4385356e" },
                { "pl", "c363abedded3fa33f00fda7281384d1eef208b68fd0e18cf5ac5ec3b870b295b0f433de058be393801848c618756fdf04f8ef1780428ae2b5c7603e2b8de6f7c" },
                { "pt-BR", "6550661a9a1cc4c97e17240865e39478177ef579d143d5e3ec43dbb613c5898f19cf1c404187a7ff3ea5b8ed98c78b8002d10c41cd8fa4910ca2e72d44d0c810" },
                { "pt-PT", "d88640738ac09d230a918a82e30507dab4c03d3a1d2ee1925bc4c2a62e29309b8d77879bf2e535bac80336b0b427a66f49f1b5b550aa8e5b056a04d4ba767581" },
                { "rm", "19106b6f1da0224775e072443fbcfc4e9238e71dc9ee8567cfabb9d846c9b3e9a37499a8254e6b1a94cffa0a3f3cc7277df4f9fe2636cc31a40800e7be34b156" },
                { "ro", "35efd3ed65203493ba49439c0ee0265851421f1adbf6b09125051f0dcd97192521d6151b62ee1b235b2b3de6486a7bb34522ba59e9ec0df66ce27437153420ac" },
                { "ru", "636a46de4edc290f5fb40ada904aabb3162ad7bf4ee49018807a0f56e947b22cfb55c19871a4bbbbf5507d58ee2f81d239e419c0a27b2fb02bf1ccc13a4a3f60" },
                { "sat", "79c72afd595c26851e14706c1d64a01849b30df3c960e1a68b132458f077810e2f51a9437a876ed8f57762ff196e2b8e306e249a519555022f59318aa815d5ee" },
                { "sc", "d31285d91d181209353cd62239eda6c73810c63a4843f7c6ad55b8e833337d92323294d3c3ff0b60bc7dffbbd9cc101e98df6cc21167830b368424ce440cab64" },
                { "sco", "3108522526be0b2da895a3c310d99b3579bbc54a47e2ad5360b79ee4bc38f5303e2c6671f91ceac228cb6a85cac6e8d02c2b5d23028ed0ffb58e9270bf5cd724" },
                { "si", "803a09f2ef6e50857bf31c4f4a70b420f518962733e6cf0626f9dba0f467d31ebe39f297ff0a9666ad2ebdf0ef38a9652ae22146315015005a9a9e842a2965cc" },
                { "sk", "f676cfa7c4786aa290b05813578b18f6bc2fef833b928cd7278a81a85ac19793a796edcf5ffd61ce042eebdc584e8ecb95d589ab831020fe587b3761ed91b84c" },
                { "skr", "5128f22d472bc2356ba7626681367a75f4007dfd71e1d4e0b81f98bd218c29c004b5a29b2a71315f8273704ad7c58ab1789796ab2a24ad50a30571178f56045a" },
                { "sl", "e585409ed2819b1d6f55aef7d630eb963ebda3e05af89447f84519001880d4f64748288a1eccfb3cd0a9773a57d586428e84bb3e183841f46ccccd4be2236cba" },
                { "son", "d92aaf671fe99447b96e2ed0a2ec45825867d993224487c1b664a0ac8f75831325b7f1ad7b9bdbd1ace8efcf6bc89dcd018b08a7a9105d740e3430db8fc93325" },
                { "sq", "986168957e7ab77b4548fdfd0078d34453fa9c4723a98b3c0b1faf266cefca3aa521ad8d5c724ce0573a4313002c05a5e73cd185f0e08ad0d472555910dd0546" },
                { "sr", "b35e148205a80a6d5679c6970faf8e48b9926234474ecb61d20f84dd8cb9f967ae83443b412d479f94472ad3fd8a3b4cb12c82e745b24e3b23f6605dadc62f3f" },
                { "sv-SE", "4e27fa94a3847211143d704d8d4cdfd7d34edc7a4e3a025a8616b79f51b3c2ce106af94cd4299e366039983a3e0295a4cd923d797bebd6b0e0d0555e35b1d328" },
                { "szl", "f0f315d2d640d2105ec3b5216bfa42daee9edf0e0b63ea1a9ddd5bf91e7af994cb7b362121b342b72416bb35a81e3001cf8a4eefaa1c9964a6aed8dd94ff115c" },
                { "ta", "ebd2834fa8dcf7ba79b2a3abc06d28eb5e9a2d680cd51137abb04aea19f0ba43de674f9d4df8b1ebf79c40b55cc56e69aa91734857ee45dfda81e8a2a6e46326" },
                { "te", "56fe4d915190287ff1fb05b01c798b9b88376113e802c86c5bb8bfa75378b0a04e220e810d93823b056231c16d2bfc9178d40b5219e535270725beb180b18632" },
                { "tg", "09d5dfafae673bde34bb15219fd15082d596c388149b020c3b241b91c4681cdc480714de6d5653ef122f403702e82bc134dff5a9a06ff7cc96dec5d997b5a9ba" },
                { "th", "4ad14d5b00e43c58f7fc135251b94682b75a37e1d5bec1abd48467e5ab9a92ff139686e34373ad5fd9e5b315b9298f5b8b84ad4c8eeed6be7cf89035e442f444" },
                { "tl", "efbe3e6dbac062545994ebbf81fb3bb3edfaab1f3c4c9ec86a2bd9d7b23dce1b660f853f4abafb8dd637d9e633b4d1c6854a76fe77742d8e20fcd0ae395435be" },
                { "tr", "a54f06234908cdedcd54327b89fee028a3e04f45f4b64e96fb18d6c7bef65dde5acdcc4b23eacb7dd1822ed1cd4419cb8a56a3f9d4db730a24593f4ebf6c006e" },
                { "trs", "9a4e28c2236355eace9d1736c9f2f898103147b52b3c758bc3ec2ca1778fda881908a5a842687f02414c0ee309201d7a70b2a177a273a9649f9e7a156ec340a7" },
                { "uk", "296a941f522103f08ae4458a154bf4cb08ac91b07feb1b3837296ada7653a0ca639fed6905cb7483e3f204f6db5ac5d725cbde424e80b246d6040918e41782bb" },
                { "ur", "570b79f31e4f545f4e0002483e77b264fc429aff9dc0ded54710e64d98bd9f50bb6d05cd1549f41e3f19d818f95e5449625d1f01ebfd3c37284a89a8750e526d" },
                { "uz", "89b07d4d8c5cd6cbd42379829ec7178214fe27b0edf1c1ab33911426a15d5cf903316936985f6d1c4c8f2f31f421e0fca0e0e929ef2744d022299206a2114538" },
                { "vi", "7e3d7993a06097e26b09f8c0f1063235e1046a89155eca480ec243502760dc3207078a376d1ed5eef4a673a676130601e6b6d426aba72eb17c68916da252da3a" },
                { "xh", "e1f340ec1cc8a2ec78a4dafb1ef9c1939213fac45d3adfacdf305c1948cbbfbeb3ac6bfdc64a85bd6c3dbf63cf75e71c76b1380605117f558e10892313f22652" },
                { "zh-CN", "ceef975747873d2ce982807e15b00d9dcd2389ca770e5223278321c871345de9dcd0f034652d5eb6a1477baabbb3b403f3ad2b2e670778ef7f349c48da2d69b9" },
                { "zh-TW", "dfb9cae0e35248d0b4bc68e1cb252aceb86513e6937173d2286d6c077ba73949bc8ed7e82e0f3d299e1254238ecdc0006dbe4d2c460c5fae46fd011e008d6011" }
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
