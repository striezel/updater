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
using System.Net;
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
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
            // https://ftp.mozilla.org/pub/firefox/releases/91.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "775c7b3d7a7229ac522d0831591c4f2664701811998bab1cf629eb8c48f135cc2cba7210f321859c2d7016be594085e2868ac35945e6df5053af71bc5620ea2b" },
                { "af", "0c58425534cb49444010192a93681cf92e98e0147a1f7f738bcc626fd015f26acb59b9c3d726688d6791d7fd7666befe116955d8ff94b1c464107403aa5567e2" },
                { "an", "bfe800af3bf6524d5b218f2b4bc0825c2314d124fdf15f3dcfc01f55a32ee61134ec0877f4650c4b0d9df0ffaaf705aeb31297b972ec10bd3f7009144bbc6994" },
                { "ar", "b2968391094d457903abd1e3c017ffb5d4e5ce6926ab26a0026000fe621339c134ef5122f5c3154eb0911e9fa804097ce9d2921a6f43882764f1eda67c7404ae" },
                { "ast", "d5e1f07e5be95b350ff412bc0ef7adec29f0b77be44eabf6cdda03eb2e8f84715d315430e47269df8da3739f90a545b2b7bb82fce9229ba540aee251d048cb2e" },
                { "az", "49a3e4f52026eea58a015256d7b0f26323fda3389d28ef908b9578436308c69564b743e3058589868fde34751d659579de65ddaead184c467458d31d200f2d58" },
                { "be", "687aec52efd97426602a0781b042843769d12b7604455f330afd72ea5657853b7db50cc559bffff57e4d11fc388706744ff46df2e0e7b044e2a46e19eccaa64a" },
                { "bg", "a2a6932ee8fcb13dd1d2d701ab93ea64e16471e9bd2731d7aadf764f431677e5b5c0b94ebe7357d4b3275aafe2f7647eff1afb8e1df20d6b739f6034aa01394e" },
                { "bn", "bd389220132c53d5bbf3878be871cde8af82e21d8c0d5b144727e6d7955f5b49391f5cd5799e81063914a4f949d95b734dd96622beb890bf0d43f63c5c918abf" },
                { "br", "2d3f564429d2e3fed393764778d64756a10b34a58253d76595d2b6670ce311b29cfb81e71c9ef449c74fbcaad7e6e169ba42913278f359c87beb377338e9e71c" },
                { "bs", "6b9629042e05a12f1e4b6f0cc351a141e3019706f61514aace6cc136bbaa87007f6de598d47cd078c26c67f136a9e40ac4bff1427f7e89ca7f1d1e6e9d9ae861" },
                { "ca", "5fd4431181314bb8842233748ffb08a65ff70c65d28609aa46333ee64724b298997bf55259e958edd222b9ad3a9978fb6a7299a9f51770926098ad60f8d28e60" },
                { "cak", "0430f95c06669debfd2d3a08c7bc4796288f378e110789e7800daf1f2a93ea911fa0536852b32e4322567ffecca7ad8dd498bcd968ca94bf179d15a6e71274e8" },
                { "cs", "8ea9f5e12f158da52b97e7a26dbf4b1a6f03f8d73593806a16e667eac823af42222942a5762b2e671d8464821513c6aa15f26c11dd83bab7cdd07c46d0d46f2b" },
                { "cy", "f53b403ca24b9b58d36c0f63799f0119a605d1cfde07aa6693b00613135948513501cd12fe33a22f8d5c03fca02ba28d9693d08395101c67b5ffd7248e49aed5" },
                { "da", "f95e856046d1f561fd2c3adca06dae50b8d00e76464aabbcd53210c780b8ccfd09c7cc86716ef9f983812d6f16f80dd7617b5cea2d617788264de5cd34b835bd" },
                { "de", "d52275419edab1ee76d74b4d359bae2617b5750f6dbf351118cc753bd2492e26df95f44181607b3d40d026540c0565060cf7aafb60353ccacf7951dfbe69c434" },
                { "dsb", "a08dfeac1cdeefe8d0f3fb2b90472b10e42b271819e2902e45fa7668b930a5240523726ec73830cb61b5ef7a51ed8acbc3c7aacc580fc786291f953230b67121" },
                { "el", "a39459d65b9cef3fa3fb04fb259eccd75ea9e9d5ca6e426f0a7b6f77958acfc94ac56c6b58fc04b415200a208db038a7c57d002408832bc9a03f9c5f0cc63ad9" },
                { "en-CA", "0a714c560adff04e8daf87d9d5cac38471f4fe40df703a483e4163db57d7a80f87286284eaf2d6b415117e4f5ada5de98df6b333f2356fdfc96fd94ca1ec660c" },
                { "en-GB", "d62436a43a5f67ab29259af81040c17337bafc043bd7c41d819391ca658f8b3e0951f9ea8c9db0032d4578b9caf54d8173cb4555977bb22624ce0cd107bcb73b" },
                { "en-US", "6914d0cee65937d741088a81fdc2d80aa2ade8d636387e6e576f7dc074735a1abc7e10fca0617de265b7a5f916b5d84b5b00ce837a2c356ee51f3f9de3450e6e" },
                { "eo", "ed4b042de49d08bb435fe59212fc0f17bbe8aac2c89a92bcd487727073dd6dd705a8d76b3e6953583e880efe7af46ecb876435a63d7ab6aaaf10dd17c07763da" },
                { "es-AR", "bb495d9ba0a1e6f6d3d4e8acbebc4cd91286761258107358bcfab91af93b4ade12f3dcfb74b4e8607804479634de537f060d9aa54012501e0d22dab0852bd902" },
                { "es-CL", "0401ddb716b7a39231067f64f91c19a19038e259a05e5816f6e1f62cba668f5e8ce670e33b9c2c2cd88c9efc4b065c198b926da46ac2701547ca604ac20c7701" },
                { "es-ES", "85e509906c6395f259e595e6029f91f1aeda04310920234c6a2094e6e6c777fe5db520b2293b09838b17b3294e06d2c0ec96716481128e7c00a3829a2d0f3436" },
                { "es-MX", "a2d277fffd440e13797a64a5b7aca813b5aaf34c24491eaa95da7fbb5c8e4f2568a4d66c4f2cfd7e465ad2cf326709d95a03c0304673609922572f6f563640cb" },
                { "et", "3df8189d38390969873dd239b2dc7d260782dd3661d27172227bdbbcdf28c75d2a012a567ae4d4cd9dc67080d1175efaa71a5c19bdb817c122c7a487e2509d3b" },
                { "eu", "da60100a7467360e42d7f7f487422cb3801fd7505e1c5676133d478fac48d6a743a236267f23a6ec112fee2c1122fcb634c08b85299a1c64dae186a87212b7b5" },
                { "fa", "2ffa2fc02231945c20dcd56e223d4857333163ac9e0f7d28e9c53094d01cd3fb4cf9d4d9280cbc2814fd08e6098b777a56aeedcb058f6b7e2e26eef87acfce04" },
                { "ff", "814cad86a0479098c0603f95586397d7159636b0313503f2545173a00bf5d63facd4bc4242018bcebc0f95df443fcf8a5c0dd0f2fd4fe4c3b00fe0b7590300a0" },
                { "fi", "e25ec5e26e18fc6b79a864a2ec3c88ca8917c5bfe17236866d708ccc1fb93354af150f756433a670687b24f2e9dd7deb1164319e5010ba0531a0c5c7112fab73" },
                { "fr", "bc2f0a06c07060e33c20dab7d8620b66d44f64dfa230f4556633827c1040361f3a856d41eb7195f66b2646b1cd519b97ee0d8faa2907c81507ff11c4affd7fdc" },
                { "fy-NL", "205952e45d8c55560af5d1e9a6fc831f4b72f5adc1eee950adedda879aabf5ac68b5f15fcf12e3a580a01d7332af1bb9be973b39ead471e386ec1ac9161dffa1" },
                { "ga-IE", "282026a640b938b4c16afdf3043d8e23c766de729d5d09db8553652a327085b73f8aadfdea4f06fa275def54d1a100644a0e4b4e6577f658adbecc6728b614bc" },
                { "gd", "291c161082bdd998c062086be002cbe7508f33fd194498e196eba8f65cb13632517f97e04cc580e161dbc43c462841452ab49b1dc58337fdb314b5d87037f4d9" },
                { "gl", "27bdba5dc343022ca7d2d865c507a4aff31fcf3c8726bdcf6485d173f70562e8f34ffe182cde0907919fec2e6776502a30f213c5798c664201996d2ccca14c6a" },
                { "gn", "cef9cf3f376d9ef1fff17b1c08f94316dca33da79c22c3a0e211fe1b989437c3c6fc013defb08434a784a2c48617407dbae94f306179917a396dd38c9a877587" },
                { "gu-IN", "b75963ad68ba0945e08fc4628f61b001771fc230de91fa2d373f4ec54f687b4f1a6fe66db441a9642c7f1c27285faea525bfe7711075ff1f1cb06689e0c5c65b" },
                { "he", "8db73894361004c847e9ed320e4c02f034de963b57f86b86e4da669601b9cdbda557b23d55ca96da96baba026aee529a374023d623814828e4e6abda56c9b49e" },
                { "hi-IN", "511f7936c3db954a4867978d50176ae3909c9d1f138a997463f777bba9360c8d07959cc02c699d19ec6b0c76ebdbcb3341572686cd470a65404f7965207d1a0b" },
                { "hr", "67c8c18970c9b22f4fa97a3b27725fc1cc61640957411ae0e51fcefcae067f19bf7f71f4e21f665c32f9985793033896bf01f51ceade1dbe03b88331df3423df" },
                { "hsb", "8fbb41509709a2557d714a919b0a4607896ec46e297ef234e61395ef67c61915cbc6792177390ec8aaf9d3255a2733574fe9c1dcdc230c4f969fadeff096d482" },
                { "hu", "b18909d47b1644d1a1a4c499cf9e1ee74dae39d8d602c58bdf6a642319b1b379e77c388534b6e56715bcbed2d4825c0d7c4e19219ed0f16b376c1ca9e097e38f" },
                { "hy-AM", "9a4d0bb4d018c666b85b1a102bdd5012b6a28bdeed06584e3f467b5921d69dd17cf11b07b5f53f3e14421139d152cb25d6723acff4090c9f166a5ffa86ad052d" },
                { "ia", "82176b8506f153f37bba4276e46ce57c37ee3fc4ae9e1eb1f72eb0397ef0d078d17353dc018d46f3d110c43750c374b9411fabda7545cfe7f36a0ab1566e1c43" },
                { "id", "f670be19af1c9b6ecc281fcc23932dc33f097c2a06de19b97d6a66499530fab98d0dc302f749ef455fdd76068fa207e418a06e08d0b83a19e5738225a2bb6766" },
                { "is", "4b864f736c138e9fca89649c36ae01787f4e0e00590671b99f71b4ad2366fc6e0edc650747f8fde6497bbf673882062c53059f6b3cd6c1a7ab695e3806588e2c" },
                { "it", "065c6d86c519a6b7dd5adb2baf6cf1da951c45f7458c6299474c5decf4de1e1d34922d88e38c7e4061853e8000c17fa2faa810b9797fbd762075728fcbbb63ca" },
                { "ja", "1c4508736a70a2232673dd37ebc59035bcb567d46f3b8de28cb6adc53c33879a02289ac482d1e95068ec7961b78fb080251deafe6681cab30e9de422a4915cfa" },
                { "ka", "4e37d89abeec0aae25f0856abf87557c880ffcecb95d4bdfa08019499bf29479ec18944c1b7d9e66099648a16042e7c0430ef744833ac30260d7e9ef072d3c28" },
                { "kab", "b7bc5a3ed2a684b59c6b11ba52cb8bda49755221e1541d55c40e593f66a9b524ab7d29a42c57e206ac14397d9d741dfb4f85949cc79db2c8427ae212da69d7fa" },
                { "kk", "c30ad1f0ce32882382e3ddbcfc2110fe43308ffd315a73fef39785f11a1ceecd205c9aebd4358afddf18d6b09c2b881660f1827750fdb7677a6b30cf95dfb74e" },
                { "km", "8c041ae405a40a6eb57d76d72541f372652fcbc45042b4a6995ec8c65ec805492acae9dc23fc7d9d6e41e73942067171c6d754f0cc3c62ec2fba51791882f2a0" },
                { "kn", "fbc30392c30672f77cd99a6c2ef56b46216f9b02d7974adabd06d5f53b821bd20fccc6be2a0758b9b57efb9a38ebecb28c1f7efd6651e46ad94e9e6fefba5c2b" },
                { "ko", "25f03e946b4810df5130b0046f2144cf5f2f40ae7677c44230782d43c27544983bf7b6df9235783d57eaade295f3591f48238fb10bd5b411f3fac7d51fea7b9f" },
                { "lij", "45467d544185ac5b19a0819c392949b4a29c56b2b947907090148702239fc008cb7ffe69ee8912dc6d681baa519e488978739e85c3943e83d9724a0cbf3e008a" },
                { "lt", "93fcfc46a513c1b09e0cc67eadca8dad51627c614a00c41ee3db971e52216090e53015befa7e54754f81f3a7cabfeaef3982f2187777e2728d9c684874a7f549" },
                { "lv", "bd45140c82f4f1184ea69e96dc8737ecd59687cebeba1322e9e6f30c6832366cf71127c8cdac6a7dcc03aa571dafc96cd872c3278b8bdc30cfa6efb4ed1113bf" },
                { "mk", "8855108632ec2529e91727c0cd8d70e91e91cb4c33d3da4dee7fa6bc4831055415f8a396a892f8b20e2536241682196eeadfe0f0a2725a35e709f3753f76ceab" },
                { "mr", "4e7f49a57a26d45e6e50d29cbde0d5390d6785cdfcdab6844833e58d939f2c830dc7c4d0c6b0850de14f10b13fe3e837cbe88c885ed81e6bc941ab42b7004bff" },
                { "ms", "5e8fe56d737bdd66d3d08eb5247dfae980b9164236cb28d6bf361504ea59d05b6373d482e045939e2627d60894f3d05baacf7553671312f4ac0ea00fe00b68ab" },
                { "my", "9bfdd1f5a15bd17157114befb10e8b14e91613ddeeb73f33e95d6541f3fde538eba1bf1e522be8e6524fc2521170b3d6327feb7be84299efc56e358378ec2abb" },
                { "nb-NO", "836cdb7cbdd0e49071be4899bafb34f2b308ba667d98bc26c6a4494d2637fb2e7908fa171aa22ae9ffcd93ebb6da3986cf5b367f761576a538f6a44f1d9c173b" },
                { "ne-NP", "bfeae1a0a2da4064589c2813a860eae0f1c0485a017c788af0d948df8842185ec6129a8f8676875cae14e8ee28fab79086e4e044a7efa07c586ba7cf2607e129" },
                { "nl", "322890f25963ace00bcd668864336ff02800070c8c8f73dea9d7e7e4ff4042bcbf8b31083b2c40a7680ade58368d4c5de76941f919742ff1e959c04663600865" },
                { "nn-NO", "aad1b36ea5b0f10da3a893a3f5983720f7bdd3241d4711fdcb16313c743aa15cbfc42b8ce5c0c396713818a1cb0b9078cd05b880ed8e2248acef34259453b3c7" },
                { "oc", "74ef702b9ffa8a6bc137b6e98b0ee3ae864a04f555dc07e14ac210b92d84493643f0efe893cb1bab313f2f71d63ca4a7c997cc4a1ccff557440709026d5c7b00" },
                { "pa-IN", "0fe71a7716502026e0b92a9e59da33115447658780c017420f306d49e16e8b316000b65fbd1ce0747cb413627fcd5908f3348c8c07a08b4eea249e20bb8c833b" },
                { "pl", "91b3ef234fe851311624bbb8080cb2f2628747b5ac88b64ebae7939a615b62f3781192e444f06e39d4827ba309bfa6a0aeee222e069ba2a7dadfdb02f3f39e91" },
                { "pt-BR", "a107bbc8b1970fdbcf5a267c1d173e91bbb999590f00cafc0d23e67484483f7bc4f16bce57252403442f93cbe891f919c64ac6b472d718d114654d28d582d0ac" },
                { "pt-PT", "c1d2981526ee1d47ba31996ae2202fd042307e9a87dcc136ac2eb1b015971cc2ae03ec9d95130a43dc522fcfc25e12e27c23c6fab541db8655b7429edd78ffe1" },
                { "rm", "5951125f6b70346878dca47238a837372d136a8723b94efece5d880bdddb76c43b45b52cdb0a70bdc0a5c6cc3b03e1219cf54f3b679b9a1a4361c8f2e3f7fc15" },
                { "ro", "3a3fc3bc25d2c6779265afeb5eae347279629e0eb2b0e38936f4b2d8535bf544cc8b987473f4b9b59caf8de864cbcd85d9ee5272b36d38b3d0124f42fa91cf52" },
                { "ru", "97bb85f1ce4f006957bf2729e3b2bb8cc182800cacb91dcaad947d4ff07e78805112bd05e67ed057fb5ae68334e55c6e397c56742fc488fc2ba7e82bbdf228ac" },
                { "sco", "0e4bdac5dc11f3b6ab9434db9b89b16be5941dcded1f381ffc95f5b9632aca1cbcf44d68427a9f7846345b876a5bb98eaed513354e8a73df987f892ccc636275" },
                { "si", "cb10d5b2dc1d3e79bd24005f042ed3ad2036a59f0776282ca6591112935aa9570cb9e4be432bebf188f32ca0d6580cca39526c2efa9d3c65519b226f8fbdf05f" },
                { "sk", "677b46ef9b0429cf3aa7938d104221d805f4ae9e2e0b5e659e2ba5ffe32966da3b7bb51a37ad22e21aa5c1296c36bbd4e098177f97a21b7e95222cf2cf529499" },
                { "sl", "a4c29feb4749fb617b6fdbfc6c02de19c49556a945a6b69ee41d699e4c2c5cab379dad67a3a280ac284792288b4e20012a8988a58d1b51cc56a5ed1edacd926a" },
                { "son", "ec0b80dbc4cf98485454bb0cf22a2ab90eea240d550deefa50f85e2dcb99c51f65c2f9472a3dcbd808603843e79352e8d05fe6c813399817d76687995271e682" },
                { "sq", "19ddf221612aee8e60ff3de33c95d270912d133ff2439fc14acf437f0829f91ec671e377fb45e2a89977b03729e8b58a9caa35380877fb20801c72980d5ddfbb" },
                { "sr", "f354b79dce0eb6c1d96d5ebbc3a2ce1d0d20df69183911aa493cff5d8a64800ed25ef10977b8d073784c52f3a20b2ba5fcf80962d6cb50f224eb399833eec74f" },
                { "sv-SE", "02a8e0ceae723fab404950a3d020b24b7175cdd81cfb4cdf0cf8e951fada42800c1b57cc5b2d9589317505d75dec39d634285f4a979e1224c76791e37acfe584" },
                { "szl", "5ffc533e93b54dca7a3089ef9e005569af284a74928a78806f06e3531975366defed4a5fbd75fbe1ac4a15615ab77f0bdaef602293d71179985381b665cafa14" },
                { "ta", "8a3d23e6a46ffbc85cdaafd489c24a9fb757a996b1a68b7139388f070104e255f25920c787730398da3149e622bee0a4791f2cd41aea55a9b08f1dcb8d51866b" },
                { "te", "0ed588850be437446d834bdb8bc5890f5019ad51b1850cbfdf36fee75d908eefb7ad9cc479d9ecaaf1a75f30945fcfd9f937795e0e7e8ec8da1542a52119a447" },
                { "th", "a7894e5ffd02f932d27e7f6bc6474a03acfc8c171dd380c3598d01cbdab7fbee36093d569e9bc1cc92409ffbea0a245e27e45c6a3629b79f8d9db593b9df9298" },
                { "tl", "78d49c62dbdab9c97dc9bf84ed7b7b3f1a5e4b0aa339e9ccf6aa9cbe89aeba87d24090df1041e5b568c50a284e46fdd8c34f60d9a3bc2887efd1f339ab12f3ae" },
                { "tr", "d61167f2fd6f9b68cb86d82aac065abade276921355769ce8b056c35264f3948055a73d27e29cdfb3e5857473a2217c0c0031b364536cc648b637d8cf6c9dc87" },
                { "trs", "492fca37b63076d8e7d4a7e26e7fb0a71b4a8d45101db858dbc81ff9d6f3c76eb8ffff88bf11d2e9c3645928a284233c45f81f8af50724ffb7b79a9073c5dc6e" },
                { "uk", "ef20b77f7de311549e70cc99d8b8af8eeffeb438edd8ac748ef41737b0c1fb73fdbd76e79c00190d4db22df539621f6936b1b4814ea9a69756d4ef2bc98440dd" },
                { "ur", "2c5fb89ea2cc199eb9442db8070dcc5b55ceec775c1a545be15f49e33f17df847d231ad84e9b528c238620907a22258b9642bcf83d629c19a3660990a83f3ac6" },
                { "uz", "dfbdd5f24409d73281f8a56d9db1370f6d58eb44c550a02fbe507bd9bbd7a1c4c3ac3784bedaf538e45b17c67fd1d373348666709c37fae883b45376722bffd0" },
                { "vi", "de35b5a304d83c0c3f9144f9c6313a14605d3bacba9a4c3fed0e651047f5d2564d4fb7143bee0105a4284c10d4b75ec47e583e05a840eb08802ef041ed832978" },
                { "xh", "5098becc567bd9e027678e22f6b7fa18e3ea9185a4110f07c1ed734c01868f997afdab7d3b9916151b4c11ac0f1fa4683973a445fcef24ab0cfc6f47412fa518" },
                { "zh-CN", "05d46323316437766e82259879e3d45b82ac02d7e057207a057bc17490347983070159a9bcfa2161da20a35152246ef85870fa81af9fde5f512b3293a422b9ab" },
                { "zh-TW", "c614bbb2f422bde77f548d81189b737add93e9fe0bcf0f7bc9d2b820861ae3909e14b6f2d305b85b4418ddf368df5ff060c6b4f5fb2f92a19290850480712f42" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "a605e4c5e1365b59c672cf84e01d2652bb26d18aaf4cd7278f043eb016ada5686baf8d72202d309893242db4ed147333ef2cad5bb5804e3414393c7e5b80c70a" },
                { "af", "b80e9f186c6c7632936eea57d0ab90d29adb9e0e4f2a426ee4af7bee9935f15c4cd77e6b6745c2968159e7ff07d37378859b5d3ef67dae992ef6678ffa1b83b6" },
                { "an", "ca1dcd969fe4b5dc090e555f3fecf7edccc6a7be70725ec519112f4e12f6a6bc55a6d1b734cd94ef34c867a01f04ee5ae18d1d09ba282c9b4951606abca25e98" },
                { "ar", "5da7220526592f9d272aff0a487b7dd6769445610d9cdc870aae84bc32e8dae0065f61aad3b978ecb09b16940c941c0f6fd83636042f9e81e5fd24411fe1abf7" },
                { "ast", "36e772140b93e7f916260d7f581580e4217888732f89cad360c6bf8c957328a051ac8c75abf48bfcde44aae8153fc9723d17b3a44e4958ae14614f9054d08cab" },
                { "az", "477ceac79872052c2267b2532ecdf1aadb0c436577cc391632698b21a51d215c7d83daacf82540fd7ca1df26f8e3b5f52c6cc2debc23ada5fec4a7a472a8a970" },
                { "be", "ada3ac07dc389e68993763642a186b19970e00987095612c620b3975235221e6e3d154c506563ca3b702bf69a21dfa569c3de42dafe4c7a647eb1c4c6001e4dc" },
                { "bg", "16290f3e758abe4da5c2495fb1709e8d7a6f25d4e15574cbfcbf4c79d3971c869f5960d2f5405411b48d2245300f62339489fe628775f5bfc12a90722b79b89f" },
                { "bn", "ec7b832ddc8037ea26ed23ca2a70a575f32b35f4086926daad560492eb41a39c806521eda179c737fbede8c45adb0cf8e777102bb9e5b8b174807df76ccffb74" },
                { "br", "1b6ea17fb78ba2aee6db3ebc63682532d0ee34489b05e9121bddf3bfe606fbe0bd5079cb6124013eb5f5612eb93f7ab7b30df3ca87b90a2d45f8152252bc5948" },
                { "bs", "879152ba759e4f5024fb84524bc0c2c6ba88c3419c30a4278ea648f335d9cab0843c8a834b9e0dc0a98f922a8b5e239c1f0e31d5290510313809be7dc224aa11" },
                { "ca", "2258a3481c6b271db523dfb9d09e26b7afd007e0c4d372781e4ac09d2786e52ec415d1660e2f4dbb9670b5ea8a7d0b23929687e622df8e2dcf16d01af8dc6d74" },
                { "cak", "4c9a8f574ac55d8603d86eacc53f5a5c25367b96d656910f8e08229548c481b3c26d3c8eaf5fc9aeb00c0e37826f16285ac32f36e400c6ae9ae8670a01cc0672" },
                { "cs", "46e1637085cb14a452238a5f3c834ae0a9be996f4152b5fba0fbdd018dd9fb682281828336abe788e64ecfef5ab10859fcd530999d1cdcaff1e5fe522ec42ff4" },
                { "cy", "dfb278e8e2236aa271546a474fcbb3dff884c94101c08313a450c4763c392a4cbaa5a0ae72da76a53f126337acd8c19a44c73a34d792fbbb91de4c966f7669d4" },
                { "da", "7e7287f75f82873841b67c0141f529270ca037877fc3943ed1d97f46c00c7617975549d6cab5daaa6fa330d0d56ad6c726f06f63ba9223480083f3a9a0f4a0f6" },
                { "de", "8402f1145ba68eee7de9751a9ca76763c296c3c7f365cbd26bdba0a0bfc2aa3360aee217bcd640d5c7fb3ce347ac305c9428c4182ac73eb076024fdfb83ba22e" },
                { "dsb", "beb4ac09f9b192bff8a2dc3c19cf00ed020bb27df80c819be7bcdcf38fb4a84f50daddab833ddd5ebb88c2a9f5d2d3d57e59a2c915e6ddb02c0ff2f46b812dc2" },
                { "el", "626a43f36a89e2e0a7e241dea2852d2b9474420b26e9ef65a3fca746fa5d666db40ae757cad3ffca1fce66c5c9236ba44e277726359edeb8222bb9cb5da0b3d0" },
                { "en-CA", "f9aa35c853d300b196d43d1484493981a873786df3158438619629107480367d0f97f39a12184eb8ceaa8b145fb582ad56968b26f8fd4d0eaeb1178a8b9bdb4d" },
                { "en-GB", "a81ad67b8f5ff57f4e921ad2a4e5ec343faf5db6dc545b5bb20ac66903a19190115a04c6cea05d853a8b6d3c160cd5e46af69aea0ae346378b23a209275cc193" },
                { "en-US", "7939796852db26b81b05517072d6e41873ea34e43d4fdbac2b85598d04449d8cc0166e1739509007203966a7715fc9bf4942a76c172e447e2f844a76ebcf34c8" },
                { "eo", "ce68aa54cb4c276c7f14b6826f466b8d16c2061d89cf3d5e5eeff39f709f3c5217a9074c4a4c967bc7e38e828dd9da5e2b62ca4f7059785e94b4fe3b237d3b63" },
                { "es-AR", "3c7b9a10cb7b231d5fcc427001145f70d5fbad78e9f332cc0187004c3afda02b8a36a0c90f8b7089e9f4438e3a879a8bfce0469fd232358c25c66c5cf5226570" },
                { "es-CL", "cceee2f227c23b5ee0c4d829acd397a082035d06db717b0d8c35171a4bc3b42870ffacd21903c325446853d12927e4d4d68cd0ea65d47d65aea4d1e7cdf76b11" },
                { "es-ES", "002b78dc7b817fc8c9c7db9edd99cfcb71f0fa539f8434c8d5fdaf39a31398f6691b2c70d8d56ac4bab24dc6dd0e215ac8047b7f64da19e82b4a9232e970c22e" },
                { "es-MX", "1096cf86bfd1494c9f0a68328a9736953be41f41d5a9b3b149505d878062c9d244134900e492b56f2a88f64301996c16522483b736ddd6a8f0183bf1bd1de717" },
                { "et", "5da3adce7e600cf6845b85a362b11b1459851021ae7a4ff2ba8177ce5b26a8abd805d62cd53cc2c6be7b83041ca622f0db0f1909154806af4649cd14ffc4be78" },
                { "eu", "efdd70e9c487c8a36e51d64d210059feb9bd1ba42099482242cb31527ca14f8b0441da39065232f9ce7df5ee5cc17a8c1953499ca725a996d21b8fa504ce9ca7" },
                { "fa", "17b7c7155394e6e02705b8952427ef7aca7eea237f734ac9960806b4edafdeba4b0731f230ae8916480a036ae5d863fe5c953c8a3c0b9ab29de0ea2b2fe5844d" },
                { "ff", "e8eb10b1c6957b08e9f87a8acb609cdeb9670f45910bb49840158e3808566252a561c10348d5d0fed7f5477d35414e0e16800f33a5ade1ae181548023b1840fd" },
                { "fi", "607bddac154fe520b991c026601b5a6883a60222547ba84c4e3f07180cc5b6d58c7a53c151123578c073e86d26fb96e2da5153b6571525e06a45eb95f46332af" },
                { "fr", "85368e357df39b3c3782e7a2df522a21084575dc315bab8be706e06581b020403727be91b80220aa193f498429f68619acdd1e70e789171b72d593b1ad5cb42a" },
                { "fy-NL", "4fe3a6bcb73a6ede52f79fdfb9ff9ab88dcbf179e1426fbb491fe9a150458c4692955867a16d610d7189943dc023ac0f2b9ccf1bec5e26bff13b8ea16bbad808" },
                { "ga-IE", "6b2368adc78484d56f0c4a642cbc28bdb07b5d3d090636e7a3ecee2be336cdc00d06b31a72d43da56f1ea956e58092c6a44c202a8a4ffec31fd782ee66899e8c" },
                { "gd", "547037df1bb98e614fb7d985323330b8328e1264c24b688c29ae2207ae4049318d7b0bcaf77ef8b897256476ca66d5aa87f55e0092ea85c1daa4c8c845cc3ce8" },
                { "gl", "d0e317d9efec10e6c6641c92b059e7007378e024254837509f5647080d386472c663c232cbbd0f02c608716c430ff7dd16fba021ace95308c6e7683fc14b6104" },
                { "gn", "6f331d2a9609ad91b7076d269080390f6034eff80d32e5a99b0aae3a7a64c4566baf2a6b68774427a886a20d2fe9b4d7b8aeb36829651120dd0ad3c2077ef5e1" },
                { "gu-IN", "4e76a88b9d9e70bb3ac27031207e80fab7014a0ead864564f0e3b51950299173d1d2d31d4e61a9b33c00bd48ffd1190818b03c1992c779bfd236f442f5e85dc2" },
                { "he", "70ad9baa3cbffde8a508084cc98d3bb85f0439cd78315b3e3bc753c863cec220d012f37da5c220f81ba96ce412e8bfb6984887b5f63193aaf89553ec175c0378" },
                { "hi-IN", "41bef75fa9c152e7492eb2aac7342ad51cd482be63edc34a101866b322989849be685bd4ba9c2d002873a307d482db2c388baa7a44d396263c688994e3ec4a54" },
                { "hr", "42218aa317596842b0dfb2727a8e532908201f2ed759722002523cd73611f364166ca6770a6ea30c9d7d52397e521958fe2e8204c34433feb5cc2f933476dc2a" },
                { "hsb", "c911f13170479600de6a72c69bfd16701094151fa725675a56c4cb7caf8c644f6a8fc91bc64f65def88f1101a8d04b1e8c74b2fdf251b32a0ec83ccb6bd089eb" },
                { "hu", "9599282a4c93a1d50a3cf42cecb9e8e81f3712e497f6ad916946ee1c20ff70b633fc18326a30b7f3aeca9e479b9ffe0893756bc7b48e4eef076b983018ffaba1" },
                { "hy-AM", "8914aaf7c17a70c5e328f5e9ec920fb8bcc2c2dfc1f49399284680b92927753a21276529dcb3c89ba072124dcf2cca241c6afcf6155155d0b1f3e4bdfd07eb3b" },
                { "ia", "2ca4623664ad17357a90728beb7afcfb13651b60ed46de57a8c76cccb113980400194672f648b419d09d5ef70924c55822f5dd809c7d461626d8170c7cb7d5e3" },
                { "id", "8bcb4dab7c40f977d4e2030d1ac21d2c19583e114f8e799a4f8f39f51878e0bcc97b9b0ec057f0d0d2d4b93026dfb26303dbc315b885a7ae34efa5092b81c76d" },
                { "is", "1d3ddd5882bb619d9cee14616e4eceec34bce5a8750979704c64a5a3e8acb151296b209b4545a79f6d65756e6a9453808e164a7f4c74d4244f40912327537987" },
                { "it", "1c9b1eb83239b7ecef3e0f25d10a0eb03f382725121018bb6b1613baec962f804dbfa65f78c010369bba38106670dee5b8aae36c8283b1c3bf5229ce780f3b72" },
                { "ja", "6476766d6de318f04ac48f8a1c9f89d3ae26df2295ad2d910402352a8782388557aee03bee5e2484c774dea9fa71e9d2ee3ed73d1201f203ae5d9be2aac4ca69" },
                { "ka", "3ebe97ea6a56d6dab5f3a9631a46cf410b4ec45fbf4380366d08a65e809e3c8eecf40b5c53bf68e576c8019250ce9259676a03bc886b0e78bc66a70257be017e" },
                { "kab", "2ac80409154c994bed331ef372e909ac826462719f19f7d8ea5cd68419a0a6ef714424a8066a1b1ea67779b85d19f03118b1d7cd0517958befa43f61be61c598" },
                { "kk", "859ac6c8cc345363721cbb58b86599dd17f451260228b88c008f841db71de547a42e2f0363c0f2c45334dad604c0d9c5243cdbe36b3a18b2f2800596e3ab90a7" },
                { "km", "8edef696c602c844995a80d018dbe284e5abde284079452004f008be0a16432cfd02a7a3c27a83136f02155e3c2773f5f718367004efce158f42f888f2e4f793" },
                { "kn", "09dcf233c175ebb2e0e8afbd8c62aade1475db2e2f58562ea970db2f1aba73f07dd7d06525cbc0975e2f40c6184c6371d888ac32364c33c281083f15106d4375" },
                { "ko", "f1f07b71f52e67c5985f44f1bccb41f86606740632b54cd7fcc5d8d10ec225cdf2767c2e7d93d7ef6b70dfc33e014595378e0a709176a500ab525f08b34d601d" },
                { "lij", "c4d69048c5e9942038f51fbe4608d35d15c8e269147f4de33eb909bb0e4eb5345914f5c7d3d25ea387e60ef7f3c27c19e6c733a10c9b81eacba5cd3dcb3707d5" },
                { "lt", "077adde634911d6a686f6acc67a698772db5aa7c3d6cc87f6b3f0888783364c1f5a6c9a1e6d6ce500942d77012e3cc88620daa1e86120441bb7d36a09043fdda" },
                { "lv", "7cf5ccb9f39a9bbbdb4681962faf7a8febeea950172d7b5f25368b692a0c778cdafcfc80b26d8a688de5ffb67e78fa27656da9652ad55b7530085bce4496facc" },
                { "mk", "788f5042c16f26b741a704907842fcea289e5211e6720c2b8e0e39ba53b1c3babd901657eb72d85ecd6f277391a738647cf8014d152136538f44e4159ca5cb2c" },
                { "mr", "1286792acd46508535b26589e4aea68eb2d2e2829e4fa29772b932aa09918c8ec65db9c3a97ba96ae26f3e90810e630544952d934c987eac155140c71c48ff90" },
                { "ms", "700fac6acc3d6de9b76ec14a8b490d3c9e3e23f87a1c1fefab9c6ce67030bbb7c8ad71274bc284bb090cc294c3ab2bbceb39518766ca2ab25823f5a185527cff" },
                { "my", "065c33e1b5944fa55ddf076641c565fbb62ea0cc0ebbd84104ee1c4ed837daf7d83e44639d40ec6247299b43ccd4ab2ab73272d42f20d158d86e4c9814e6a018" },
                { "nb-NO", "405cd4db752ba230c5e49435d91752a31e4a2bbe599c728bea37214887be3fb07c6432b3d12beb90afa5f7d1776ecf8518c68eacc6d257a363daa82e73745086" },
                { "ne-NP", "ae5e53e6d34882ffe060ce9b1824553138f74635ab7e07c7c31781fe20bbf0046f049336230e24a81331f216a6a16c610f6ab1689d6c0af16b755d9afa1e7739" },
                { "nl", "f92ae61b5d373d4473d2ee51798131cbd32bfa54328cc7bed782e74e0954f96c7554f8115d60034ea5703cd03f9ff09631a6f75703a2557a29b05596bbaa7712" },
                { "nn-NO", "9393f3d6c75508f27f71bf5117590c8b07e4f4ded76c2b4f541fe944adf48511e23dfab58d851dadd73495da2adedff8a2220eb0f30ce2b5dcaf14019cea878d" },
                { "oc", "32d8e277764d96446cb4cd967f071154e5d8ff5b86aaa4e5476e4cf928b0c4eca0647228a59ae01d9943aa962335e602c58eb704c83e34e359c9fd86d547cf96" },
                { "pa-IN", "d94f0e880f84b01b4291886fffcdd05adea62750549a1be1cb65023162421333cdf19ce59ecbd45dbe9dba4372de2417cd38dcbbe47f43a192db2a395c9ce142" },
                { "pl", "af3415e8ab3e042bf843c4db2e2571a7e2f7099c3cdd11afaf84ade00fccd8621d4efd66a0aaa26fee8fc6b3dbb4dbe7d84b809937f635ca1727f72c1394cc2b" },
                { "pt-BR", "e1549ed523e9562893a3c8469dae1ff3e0d1f7cbe1b184f00f89b391ae6bda39ff2935262984682279df57c5357ac9b80d23750f46f5ae58e64d8f110a55c14d" },
                { "pt-PT", "808a05d2f3b5535b19f5b7af76928c6d28b3bfbf74b51e175016a482f7f81a35024bebf96d6ea71fcfdb4439df0fc122d98f1fc8bde45a0376d76d61a198f64f" },
                { "rm", "109bff4bf0d5eb06fb5fe8f4fd86bcad9da29f94a1533bd2d426120c942c886c2aeb2af82fb41372b584fce7d8ebc1f57f3c552459f7e6c7dfa10458bbc9656e" },
                { "ro", "e6ff49c0840d68b95fe67258f6f6ed8005317a2e2ee623595ac09904da31fa8d25f177e1b83ea7faed39da3de88be18a699d1df8b1509350ff202e1b0b5a41fb" },
                { "ru", "7ac854d79f3e43360c03504ece3ca6c5583acc86de87e1901c4c7663beb42a84b1bb9feb44f2e5856a28d6764f39b7d278a52727a0dee7e11cce243127238cd2" },
                { "sco", "6514b542dcd69be994c6f30b4b3b4230721a866619582091c3d36780c64416275e15b51b085717ff142512ddc35a9b6521a9c45cac72c0e244ee8bb5641e10e3" },
                { "si", "a014853503a6cf2818416dec84074b03e93fbc3a1e8e78e27a350318389bbaa26d7e1ffdac694c42fca3de3513198468871de5a34e52e86ccb95466050584cda" },
                { "sk", "fdde27a779feff359e5d4e5482a6dcd8422dff2c9a6985dc83fdaba012dad1143e25552b74c1a63ca2d3091678e79ea1351d88b8d293df6b5b7ff58d8fd940cf" },
                { "sl", "21bc1f5640eadca9ea041cb5b4e8941f6ec5c11315c92ec85f534d4a7a1af6624dae314e12260279574c5cb8e47f63ff096ab43793350d9bcaacf761aa06c914" },
                { "son", "8c337eb027abfc7d8d93bb436a492c7ee248ed012b7ea5788bae44878cfc36aa3a691b8127f5fa360487c56ff600feee3a0fe645185ee9766d4d89a13d497b34" },
                { "sq", "8dfe657cab7dfea906195dafe62f619c1424bccfdbd744c45772b95686b93a7c7703b1e726446ac1577dd438eb01be4d8187e1162c58ff4976a4f17043cf565f" },
                { "sr", "260785b871384e3e7e9da79f88aa2702e98f285e51a6b0bbc1a376657338f7b0fb87302405fe595b50946340ceefb17187d38125e404ac64cd9f0f6cc017b4d6" },
                { "sv-SE", "eb871347862d4f3365a0d72897d7ac897ab31177ff3fe3bb9f1a62687e9301c6fc91c71543ac617bcff26a4718afef1e312a43e1e675ca4b48cdc716e67f992d" },
                { "szl", "809881130bd5181ad6ebb3a495a1edd56913e67b86af9b908df8e3a53237f53986e25f320cfa4ac00988a658f5f6f24f125bd7aa8dad5d98b6bd013c3b690e2e" },
                { "ta", "ce235c8d92eb4571f4e3683d7709c355db17403119a253fa43f9e8088e9a8d30bf4c01ed53095d502422f131fcf5f73f60d7f88f418855011cceaf52f2761e59" },
                { "te", "85e4f7118b856b600dd9963b2c90464396a82e1b566852eaf810f374cf70a459d0f640c3863c1344dfd9968ad12b4abb5d268593e5c544616af80e646042fb28" },
                { "th", "135e48cc4f04f9ab286414d0eee16963af8e84fdcd21e88416c9568804ef0faabf053af571c8d3906ed6008129e70157b997ea0a4ed00f488591ef3f22bb0377" },
                { "tl", "90b3f4fb80aa33934c57e2efb410abc1566ea2c4906e243e7640512322d1c4da0bfe622bdac305ae259aa923463d5cc9c680fafe803ea8d81ff8f7263ca780f6" },
                { "tr", "eed854be7c3adfe4fd1e67fa9df69796c37112cca7976372295f430b20d40b3ca132990de4bc400dc223a7aad14d386e0bd23b5b56ff688c6402c21a24c548d6" },
                { "trs", "0e9fb79d7163c64dcbf04781ba4ec155e54fc0585096ad417c009359e9296c67fd835918536d68a3a0dda31559c07477acb7b516efec90de8c9a3b128ab130ff" },
                { "uk", "715a5cf57e81f16dce666c9ea0dab708cc5d097c98ac124e28cb77304cdb9d5747b39a4cf7f8ad4ef6275f819638b6c0f8ebc5beb244a00b7153eccbc3b0c118" },
                { "ur", "0f4c1c500b65624bb8a3e16bdadbb3ad0d3a7f05051ad7606b1fc3b0ff8dfc0345660e10160c762b18cb38fdc6a1e680195aeb96e6fd9f5988667cd82f94e2c3" },
                { "uz", "a9bae2570053b9696f8fb1d49a336f254f4911990ac060f5bb28e393be382dcb89bd4b2fc19b4b87408d7f1a91465672c5e042db7aaea39a054e60cb321454d2" },
                { "vi", "9089e16a09129229a6538b4358a59804bda4cb864ffc44471994d8d8d678bb8359dd360d1fcc4ca9436422c9e051ccc60750b63efe36768825ca64bb05b99c6a" },
                { "xh", "9fc729e9a86958afa1ea18203f2634cc8d62019aa561e2028351937a0862ce279d645ca105115fb3b5ed377b70aa11c0eb5ebdfc0f0848f67e6508bea9b84048" },
                { "zh-CN", "1811b5c6ce0d2332194cc58bd5a93cb56d90bc24a8afa8a96f859b09ed92875292420b645b55c3cfa5fe5026b85971f85d82f19e2281a5c73bc2e543d6518c9a" },
                { "zh-TW", "e37dda4e25337c4468e68c9c5fbdfb46ca687700e256d6ea64040f74b2f05a2ed17f78551dd0e4595ad870993b52780e1e3c61655206935aff536fc6e1ba9ed8" }
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
            const string knownVersion = "91.13.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
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
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
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
