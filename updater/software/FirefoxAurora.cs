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
        private const string currentVersion = "140.0b8";


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
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "63a2eded6dc82c788f1ae5713b41bd5cc6dba59d251cbe4c120fc34485e7f721e97e44ef733b460a85e2f0daf0bc08fe935fce522da2e72fcd44febca01f3299" },
                { "af", "9e793edeedce07b2dfed5ded2cd11273632ecc52202a2ba3d299cc54d5bcf09658e5e711ba4502dbb91aec6b8b0b966a743fa722062c8174ea2a08eab7bb839c" },
                { "an", "5ccb67d9ace787fda7979a88cdc84b2020b1e0421c0ec3bbfea4f37ba7d23ed705d2ee387fb287280589050ff37f2bffd71e8c8e47c7757edd707fe14e736c76" },
                { "ar", "f859966a75f88ecb64013992c3412b3877039a3af5942257d53592181ca0e67213661151491afe957804783f657a699b7e6e90b2badf52b19013953997c64ee1" },
                { "ast", "6f0d8478e08701c43ab2f682c30463b47b429d03bea2064ee1e512c1ae2505c4cc708e763fa889e3d68b5090ae5027158b771764e5b390ce29e8ddd158e02858" },
                { "az", "82ec4891d994f7c74315ef60c699610f8c79b74b4c3efd724a1d19f249b5adc92ea569b52ca4c1824fc3850bbf16a3910738f8c662671375f3d3387c3d21271c" },
                { "be", "c17b585c4997c79820933c1cbc5ca5e343d9243489416852a6efe057f07d6bfcb0830a122176716be796f211f5638c874a23588e32793ba8198fd7905c332549" },
                { "bg", "02ab66eb9c5364067db7b74ee83347d2cd87f2b3cc9167db016e7d331f1a0a0607b3a7e0731ededbd03928093e1961270b4c32c528447a276eb122b532b3a01d" },
                { "bn", "b57e51a56ac6c470d0b2f7257ad66141541724864090d18bf743363d1753ddb93b314ed18e0e8137c3a7b2af5a3b077793e9ef36b4466b1f030705645a514637" },
                { "br", "adf1b9447fc1fd72c4ce6ad2c85d995005d54710654e2021505e0116bfb79144a20b34964c329426f69a5318cb7c386ee22cc236e8d3e7c4001787e8dfd267cf" },
                { "bs", "5a50aa4ff30c661eb611658d1688d806f30571f4d06eac09fd53941c1610ad78815eef7a21555eb020a3f031e1af774b00b1ff389d51ff9e7cb722e5c638112d" },
                { "ca", "99e432996ddbf0e9bd61c2c81c7c343c5c9e6a60cd83ed648b0e60dcecb324421638ff5a48329cc490df6438b33e4bef5c22755409f43d388f1cab4ed8f26f75" },
                { "cak", "a12ae668e29e7d32906a9b593e8fe8a6ab1088ac2d570cdfa862362ec3c0a975ccd00c4775ece56fba08bf92c3f77bc215c76dfadcc6c2d7b2bf99f72e4a3044" },
                { "cs", "9ad12bf73211aec7fdb32ff052a6e765241eaa8849764591abf42f42b5400c3db6cd9546938e2e9daaaf4a96eebd8b0dbca745df2d62523313e1e5a8db7db9c6" },
                { "cy", "3b681c8fdcaf30495d6192c3ee75ead0c907789af05b82672a41b50a3746e88174847076d010124e038ceb66f898b6cc3d878793bb6c1310fdcae2641bb01017" },
                { "da", "a74ea20f05040ff578ed58a108f89e969f0421be475412d2b9f6fda5b2bd88051bd7885d4ca009b8ac6d14dfcddad206b57b49711e459aa9ec2a29f2e0d815d4" },
                { "de", "a2cfc084d0c3501dc0333f6e4f4f662916f97b61145791203aecd93bb28b4ec41fb61f3e3012360e20e8a5612cadd10a2ca0831187da2d7fc419db97f6b5a3eb" },
                { "dsb", "3c2f6b96479bf10c7cf568248017b8b45a06af3cfeda2b4fd98812e9eac8a28d03836431d2870c2304779f13690aa93ad490a95b59d8008e044e0f022532e50b" },
                { "el", "8d3c9bf3f89af4f8f597a3392c742e9931db76950df1e5b18681746564efd341370122926b413d4103c5316c3cf457c2154c685a469e2d28e159ac40b5953d32" },
                { "en-CA", "dfb2cbd6f7f18dc92e946ee51fd8673c79f8e32f74dc2456c526b69803cbdf3f749cafef589607e4c50fbac23f69731f9de25c28760415ece9d945cb1207dd67" },
                { "en-GB", "c3b7165a193920c81fa2c3781045a8fd1b82408756991cbbbb83d46ebbae617023353a0afb7cba239ff7d8ba54e4b8e33f32e4c29156e6b9566b1f320c08fe99" },
                { "en-US", "c3abbd7b1b9e7cf7dcc5e7f8ce178b87f46fbe6998e894f7a6819440381e95ab147eaf1eabf3356b525c921f65e98fc0b10bb48f1705fce9d399b826f978a3ac" },
                { "eo", "e09b3a04edced8453ed0112f221b7c2ade88f9170de35fc0a07493e3e4dd7ccd5ee4461ddda33931fb9607e6033efb06c0579190f2b183a8cef5b22768462e83" },
                { "es-AR", "def6dfbacea403fc4f7b9805b2bbbb86ea89704c181f924a2292def3fc9be03023b9d807179c336e76d028c1737049de1cc138e2d18bf80fdaeb80cb55c2465f" },
                { "es-CL", "6432c3f2baee78e408bf75225f90ff379f56a5f9f504f98091f7992f670e3dbe7221a4afaad36b31a408563c447b983aeed3fd436bcdf63944cda53746bd28a8" },
                { "es-ES", "a8c995d05765cac9eb50d1cbc6986a4d72ecd50080ec1ba22c5f9d35cc497a8a38282c1e605306a8d435c7383435638d575fe37ec0e024772d5903558b8493aa" },
                { "es-MX", "5a823f914fd6a697dfa6f0c56eab0b193256e48af4d228bccc0aadc08f3e281f21e97f2be32005cafca5f99157692da93f34c99134277f724181ad62971363d5" },
                { "et", "01778e43077d2b1cc8dbf4a827a76fdf400c7cca604ae2e151ff577cd7a5a5ab29508759dd2cc7e3dfe782dd4ef902d7bdaf6134c7cfdf705fe634a0ea7eddde" },
                { "eu", "9546ecfc66c171d742501bc0074efc3b329bd142511bd5eca06721126f08f8a30167a681f194a1ad29996d04046871e68675aab6881746644ee21d27a5c123d1" },
                { "fa", "bd288cb99f970958a4e6449e1425cf6784735d247b97d838c7cde6fe7b17c2eb5a1c97cf83c6e96643ad2d1a5b53af6231e83cb1872b5e2c41dffa81ee158f9f" },
                { "ff", "ef96248061f059c56fe953ad4db6a1b4f58ab5f936f57917668d17a7894432cd259c97eeac6d4396ad5c31e5dbeba8329ac70bea2684be959b73724923402829" },
                { "fi", "0023194c210169fa81a623afa07759d49c189313e6499aa08a8828b6328b994f2c00d598835846a5a973bc87fd0f1090ebddc417fa437b88c89632d6ac838c9a" },
                { "fr", "59544775f19f097db73d5bb136779aa0c32bab899a17734c76977ac458d4eac536d73e0290b6b4f31d8b79bb44a6a0fc9277d9e0eb845cf7de4a32599e3fd1fc" },
                { "fur", "b507fe1c4d2a59a4ec2c7837bb8d28def8b625373a182849776edada4179ced1e81ce6354ad78466c1fc2f1955f342c989fb90f83fca02c608099aacc3913af0" },
                { "fy-NL", "51537c0f5948299e7f6621d15bd8044ded918e847e799004289883241e525d25d5dbf606fd43cbd64d05b699120bf38f9e316d2fac15daf48fc84aa5489d0b46" },
                { "ga-IE", "589c14c92bd55811efeedafe5483625d36e52d85a6faf82039e333c96e323e19eb7153c2f1dc451e058a7653b220523b0ebd585cf472b100c81eda823a72e8bf" },
                { "gd", "c705f7538e692ff90be3f18d25a279c56d11eaa26a7fb31823de6fdab72bbccc3420cefbb4fa2db77852fa503828fe60c8d0a1bae352b5739c871e23fb224ede" },
                { "gl", "7ec5bcb7bcd7638d1a0b0f228ec89d8cddcced729348b4b6e29a8279fb1c2bb6c38131a652816fec42b6bd13053534e66fc917b377195117444537e26b527ed0" },
                { "gn", "b10f3941e80fc20336d31129d36f9eeb1407b7d4b65b7cd2d2bddfe04f4f983d3d626aca68efd82740948865f2c1e30e495e63330e10c1b1c4644280b9160602" },
                { "gu-IN", "8aee97b571f2084e14ce3f32595927c84954e09db8c120935a90c3498c574a5cf1b44b69c141e9629d352af0c940330b0ce380e64ea65dc34f7a51bdfc0a0f2a" },
                { "he", "cd5c3738e401723adba3eeaafd52776f4ae3e0c53f046bb028313b4965616a8ce067d7321183fa15d85b754bdb05a8c82fcef84cad840fe9f9940add17f36cdf" },
                { "hi-IN", "f7527418396690185806494da11b7130ac32bf41b885298bf77d7758f8d73bc07c91c391f607f39b4002b7d1bdc4b49d5faf4f742321cd377a05593da645fa44" },
                { "hr", "77f6e3867c9ef73968b5955786d5bd86004c2ba6ce006a4ee6003c54ad8dae8d5955dd0bc5f502936b841fa29df4fbface540c629417d4ea1f9618576fa6c711" },
                { "hsb", "d36497e00a5e6faaef05aa2a99231324d9458d4c3f9d8c27ea3fc7eb199844187c1468298921548c5403b28e374a97c605a2e828d8be0555819a0260404fb4a1" },
                { "hu", "354846bfed5d6df634cd403d9e8aee71ad93e354c9eec4743369a1f695a1ffff0f9030bb5f7aea003e3d4883225d89ae3a21d7ef36ee639e18268e1d509fd3b8" },
                { "hy-AM", "9628900d1f52fba59e06a1fdc5748ec71530692bf390e51fdcc7ffd597cca6a608d348b444f08e12262de4902a991e851700458879d934faee717321b208c046" },
                { "ia", "62cea5c71e97d55db64f8f06d19f26c7f4ea7cb9ad9b7e5d17f0ead794855fc32e53300289e2667f66292e45baaa90c7b0875f9abc69adcc748f52bad7d029d0" },
                { "id", "85297dcf3334b28b0d615696899da4265b1ec5ea8d0da7aecb8fabb021db23fc0ed8b78a3330a284ef6ccae8195c365ef550074e5cd8c02c0a4518ace20bc32c" },
                { "is", "347d752fd6b7d16e629a82fd6055b0b355f6e6124879e125d4dd874079c9b8cd9a18d78d55dbb576aab1b22583160a3ec4b7244de824b4788fa3c35f26c9c166" },
                { "it", "4c3523c6e6c427508e567e644cb907edfd4dd3676dbd4dab1d5fddb494ffcac073a8cd704206a7cdc35073498e08d1f604065e7ae395fa28744930367ba9a23e" },
                { "ja", "7cfebdf8de0a96d3f0c7fe4c20264f248fd8e95e61ff7d2a24b0ca01525f821b7ed1ccc4d0045172fc888ef5d60258ed115895bf3cf2c86bb5f06ae84baf74a3" },
                { "ka", "1c1196428f3282fe16f3c0ec59a165b2a6f42620197f7d63a5636fc97d3381c83d813576278c927db340f8db27d19575c769851f74e1d4d5a6a83f6d8990b003" },
                { "kab", "5f314df7a23009556a8bb49e1dd3876290e570a77f3ef9586b6c370418d5f315131d2f59bdbdebcafba86c7c304e8d2571d5b66ad7c0958ae7654eb1078037e7" },
                { "kk", "f4db7e0956579d5c6aea61d052e4c6c0cd9589d4d4b8261c098056dc6b31b8f21b4a80f111f1c5ebb18da405333d7f307c2d7fa7faa1a1a49dbdc8b1b6f14b0b" },
                { "km", "c34d6d8d481b3d6828a32e11a1dafd668b2b4d38514cc961366bc8fe7d42a6a46d88f1b16cd70c2c95123382a605d244ed977ab5e509c9fb34ac794907e3460e" },
                { "kn", "e04468ee578f0c67fb55c2a7ebaccd62ac117aca81ea1f6c0ece0ca4c96ebf210a5cbb4b8f8efd939d900b899840a0e44b7451268be902c041fb1af22f271974" },
                { "ko", "a24e07fb7eb491f157e2c2bfae08ab14682a9a7631a24204217a0dd6ff4c90907e929d48d53fea48869ff4b07c259bb71a40aaea8ae7712f4bde9ae3796dec9d" },
                { "lij", "477b9836a4b2f00b855a33d80b544f359f895b11a61bd90272fcd7cbeb8cded9498f0d8b7bbf4ee533c248a7086b9c426f0fe8f653d5e0ccb37b5d109a7a7bba" },
                { "lt", "381ed2ed0006f877c88cfa2e5c4424df3ad61f2cef4edcdd35bb99fa7c00a7cc76db73fc90ba8f41367eaaea0ba1231dd4cc11963179356a8b9259ef18d88389" },
                { "lv", "b82db15426ef3047649d50798d9e3df06019255ff61e80b745c0d841c6418c552d831eb32f72f512c8c84aa9d02c1da5f5aad36fe0a4c443ca7e8d837f9c36fc" },
                { "mk", "2a5190abceac54ca872f0bf189b96a3edb19ea3b748efd5e63a2c3f2daa214ffbcee11c2fe665d91a798d746d46fa7921daf604e5c4d52410da480dd6606aabe" },
                { "mr", "1bc93f6b3d9f9cf4251d7baf4615a64d0d4302ba108f285d2eefe738a1a213f1cc74ad9851c8fc7d5f140182979ed7fe70a93497895e11ec73dba17a1ab8fadf" },
                { "ms", "8e6a9acad16231ed888c912a1a2006d9256b38a2fb4126ce488fb6a50713bec1878c2fbf35c3a9bcaca60ab3421d0a057a266d5ee5ac79ccc175f2eda998ea7f" },
                { "my", "797969e6db66ce72f873a4cf426d7ce1f304079ab8b83daeb93b81eef9de4b627426d6901c49a71a1a3cb92a82e9fa2192680b561e9d871beb525029871c5c67" },
                { "nb-NO", "d492ff4d6f7a033ca82f3e85759fc8da35607e691f7d5879786d98c6ad1368058ff1aebb3c41fc01481db9fd863b2787bc72191b00e7d0653b73722586ef9784" },
                { "ne-NP", "ae5bff2aacb01ca417eb711598e7f35754b12d4691a15cc3058caacfc7af8757c5db3d06a05a77d152b1540cde9a63886dd4fee21688cd3e519cfcdca4c4fc21" },
                { "nl", "d94d46d3fd40c5a0e735e3afe56227a3305a8de80e4e743e13d7943030ff3ef606fd50d021671237b3d346252c13e44a6acc0310a8cf94744f68f47deda4585a" },
                { "nn-NO", "39d4a79e856a10e676e3c5e0606a7e28386ef43b96fb8d3b1c8c925c8f59e2227e4c9e381124b202fed5bbd7d0fd8f8f3303d398ebef8a99bbccb464aa4e8585" },
                { "oc", "227adfc4db4aa32c54fe860ab61b7c94d6d8e7fd4b7ab43342bc4fd09dfa07f163a061295dd976e527aee792372203e9e6ba3ca606afdc14a07c29ff35425ff3" },
                { "pa-IN", "8e65be923313c986fd015dac7aaf9b16af84ca1ef6b004c974ceb18fb15ef0e8e50ef75c0387541a1a35cf57bb9f9e78c67b01b76552a4daa5f62cd8a7f22d56" },
                { "pl", "9948486c69447ae1fd142460266f073115be1329503026e1d6fed00dff79aa30cc4409f8d110a5d5c20c6ef52a05d2bc8dd17f1cc0cb3372f8dbaefc70c6f0dc" },
                { "pt-BR", "869930d5f57039496bb15055e1cd1d83e149e4099e0b9ff3cb82433d35d10f04532dbf14829a98fd2c22c56f3b995ad9a32890be101d482fa6a1d795a37b8911" },
                { "pt-PT", "8531dea4dd4280980cdce6343d5cc7ccf56524ece616bc71870010ff7dd09dbae46d42fce665096a09a372ca6b060589c35d4ca9a6e57568923bf88abdafb144" },
                { "rm", "e9cb114004ff1257379b066a3504919d5ca5ee48283746165a1e2b269a91199fe91f0e32932b1dd969dbce78503d4b20b10196f8a2e6f523ba8f4c3c192f4b7f" },
                { "ro", "91e5b3bb2eb4298b1a359456e7cc88c2d68d43e6c657db85925b9d17b0e804a2183b244e187cc39af75e75578c5915f1b36a89d1bf8a11c4779077087268acad" },
                { "ru", "9a494fbd67284244bc74fa35ec5c11cc24a11fe78eb4948db25289edf6a1691c482c9b64cd6ad777d85f9becf6e06c8b2718416b5e41b05d1c814dba2c5ffbbb" },
                { "sat", "beb087178d951471975d8759f37b97791b6a573f0c32c30abcf16b0f6ec9a5ea7a013f0e3d88134879106c96a0514c31972df17784b2eb68401a243df2eff06c" },
                { "sc", "38522da67459e61afeebe42ada5c60cff6eebff18e11de8242a6235fb0ebf19c291cf5dd8f73f2a297b0302602d845faf2c3cae9700c905c5c845297f6dbe5bf" },
                { "sco", "37ef9751c7c2a920e491220d2e9977c03fe3e042cd23fabffd6c29e52d6bfd8b83583ac5b300017de601b6acb7de17e58aec28815e6d60f23a12218e15b64a1f" },
                { "si", "e53409cd1475f87c4c5d7359cfad2b3cd8626eb8b12b2b55fdb6928ae6b4483a8ccdc4c81399c66339fbe536832e4e6790ea50c2ad71955dfcb891612ddc25f7" },
                { "sk", "d8b4ab24d3e0ef00c1d594b1f37d7a8f54d044dde14c2af9d77034a96f85d30e8a9ee7cd778543a201de75b7e35d7519f247ecc37c447426535bc89e5fd11c05" },
                { "skr", "3a8dfe7f6043e25f42af75f090004c36c7fc9158281a99fc8779a88b94125daa5bc2915e1c37f7552405bc3c22448e577bf2296150857130235f677e9c76d357" },
                { "sl", "936f31036848a4ae30a8346f1a11714002c4cf3fff3e134b5c82e98a40bb8667f94f7bc393d6179124c99ff6ef75f68f286a8474eedc39216e751665acde0142" },
                { "son", "ce580df4bc24b88d459efb6003363f0b9373083ced51ae4d0bb5e61f88c912194272996d24c28a3e74c132c771a97f3bc85ba4918b1d60e205699aee6e339bbc" },
                { "sq", "0b2461f3f36320d77dcead0a98c9a040219874711c60111c3de25d0fa6af38a1db431d121b377a700203fcd3fbdf31f9e62e95052c9103f9257b3dc004879416" },
                { "sr", "d8c6c1aba1fd25567f79fa8bc044469d08474cd6f0e7ff5da31caf38d4f9f03eac68a5acb8a6982e3659a521196e16cd1d063737213292f4f923da6759d6e728" },
                { "sv-SE", "829cf774a763170c6c45510d82972fc43c493a1b1f207838b42e3b3a882f8b68cbc1b628e4c23d070fa404602189c225b3d469d4dd470d9bdc58a3a481d4e5e0" },
                { "szl", "49d225d8a6dd8ad54e6da9356ba4101f6a07f299eb506ec6c6d063aa49b1db6cee1534586f231a8ddf857e048ca0c28c5a1d173f244de2d0d19eb302f198a89e" },
                { "ta", "21e6ce22f9d4c251e0605b497806c627f90f31964e54dc9f281860d3e817b766c4db811e1cf3970b6b3d805dd42edb6cf2d322e2acf12fbe06907229a8c5266b" },
                { "te", "12bcebd3b999601156ac63ad2fd6bae9a30c279f7bcce92af24faf3012c36cc822372efd327b83ba880768cb5ea395c898f2d45e682e8e280969e095a8b9b87c" },
                { "tg", "044f4570f5a010f5be8e134016d2a0818232c34a4c370548abf664f1ac4e6d3974a6c2470988a13e211b23c20b1da0d297b6a26d594ace2b5f970b1818d852b4" },
                { "th", "9b4c4af44c883d46036d70fd100159c8386e9e64b0d4037fbd68579db5eb857f02c1f4d64c4da107f3e1e29f206eb3c4ac129b72f6937ca7f3ed22c3fbb1b242" },
                { "tl", "6387374dc37766a81901773ed6ad39642083f20ad89c6a7025a8da154a46dc49fb08fde2b0097a64fe6115ab024f415759ca95735ca464c00509612a6d24468d" },
                { "tr", "1aefebee1b51d7c9b4edd0873168fb818493b77912fc4a83735b726df5e29039a7bdd499fbd854be677a706f34ab39309ca2b804b3c553a8ec8cc6f714e066a9" },
                { "trs", "54d20ec737740b4981fec83a7a17010a9f7797da524779ca5dceaeb15565146a8a4dad9aa39ad2b1a2da6f06fd0639169bbacb41fbc4d9a0f95534fada3f4143" },
                { "uk", "1699cb54d685e1df84ba61bdf3326f8070b0ed54ed8203e28625919283ad20ee1a18f4113b1faa9dc44eb9650916639bc9292bf1b7c62e2d775c7229c6956822" },
                { "ur", "24de288826f0aae7b7dbbf1111c644e68f01bd27bd84ce4769483e667fac7f967e476cee0058d97bad6ee1274dbe0def5af49360b222b654c4a97870d1b6ad2c" },
                { "uz", "f0650b2592999607bd7684f9975498093cd4d7a848892ad592dca59a45d1fb9d36e3605ab939ad4d73cf2d04d265b428843dd2296fd1e6a5388df5eeb78a2f57" },
                { "vi", "3646a2965fe5c704958f4bf260aa94e6ffdf7d26b36ecb80d1f6320b2effa45edbe501e1bd2ebaf8a546680c0301755cddef07a871cef284501bd25d7afaede1" },
                { "xh", "cb9acc9515fb71cd81eb83aa610f0d56e950fb2a1f6a7674f1d9ef7ffa218453144f3a7213cd8b69637624f83d292734558bcea57668814aa1537c92d72de730" },
                { "zh-CN", "a21eed1d2ce8400e7f0b24829844d508d78ed9ac2685a9dd4bee5cf86923f190598fd2d05eccf6902f65f7204b5990eb947ebaec47e73d1ad34eb933d41e4b6d" },
                { "zh-TW", "169ac438c95db8f69b11ad38cfc665792ca0ee3847b5ffd3286f718fb068beb39f546e32cab0fdc38f32560d5230e5f11e41fc4eb6e67e342be98e179ed44463" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "cb7875cefbedf6185b68cb65a55a5af5ed1403b5416d82268f10a0e0ff1b5c8c28366478785439e195e1a348ba1c042a67c9a9e0cebe9b93ef61ded9ca51eeef" },
                { "af", "8d898b438aaeadf0715740965a7ff33bd48ae02f3e31a189a33807e1d2ab0da1d12787b9c4b93780005cb5d83c388e526e3d8670be315d26fb2aa77f12740a2a" },
                { "an", "8a8c7713fcab57eec76cfd9c30a0ac9877201911d13faf1c82182f28b0b9799dd87821866b1a41bbe399f9ba1328680b10c3b5a185141fb11ac14ef7207cf050" },
                { "ar", "17b1dbe42a7992421a0fa5f773b39d7abedb5a246ea196cf3de3d2e848286b17798b4ee23233f4386578bca60d30866de43cbbfb1cbce74bfc4970669bbba011" },
                { "ast", "2a7e6b3af78646cd9df4f7f8d46e8096a1d255366835552d153bd410a41f53758a8e2f44484e87532097ea02f752924a8c42f98d3d27bca601aeb0b7cfba6cac" },
                { "az", "3040a6f3d822bf2a5829cce78ce902e15bee048e849c9e317b4975b43ce9b2ad0642c02f9f19e173eb005dac318375c10a9a2c35383ee7f6385f1604e3c5fa2e" },
                { "be", "bfff9384f0bdc6ee2573fa70490c36ad5cf8810f6abbae01d2647c56a27896f1f7de6922c6ad9d87debed8d88dfc0a75030ca2eb5d5550d108cb352c1a85d223" },
                { "bg", "994b3e2e6125e7482ac4ea8033483ded87e0c04edabbc3f6915bea7d8e883bd1683471918b83af2f83a22ac6d0706d7c4dd9a5465715938eef015b44a1d502d9" },
                { "bn", "8c1b99dfe85020a4ee8554a69f25520357d847eb34d9e0091f9a526ee968751d367ef104dccbf347e4d6e31a22b96b961b93f9e4481be753fe98a991f5b9bce3" },
                { "br", "abde820341b0da9d5a67178b6c475579d8db9e77d3c79ca38380d9d28136e05294d81792cf25dab12d98fd2374b81f92e95354b47552ea442e285859b846de8f" },
                { "bs", "206bf0e0b6701aea4233a010374ea867cb0f6ebb8d488281b0d65c7c01539afc2d6ce1cb5e124d3386ff9096c6f87f1755e41f3fef70c644348780f785c1392f" },
                { "ca", "7edfc84f2badac933ed14a666831341ea5cabf4ea6d80c07f1012b0d140f569455d7ca770367838a3b8c3067b110019f5515220ef3664068b3a003dab662d2a3" },
                { "cak", "a6bc7d7207b4568c81065568dfda9ed3e261de10e890d76932d8100f9d8d8bbcf5d9acafad77082dc2201c6af18ab9d1e1008e1010ac39962df2017088de37c0" },
                { "cs", "bd975959c25e0e5f03b84b9e22ee21d446a4c960123c4b4c901f50587ff807a30a3e5eeb48d5667c929dda7f47f2f28d36a533c0cb89340b5db69b8531fb01f3" },
                { "cy", "4238cb8fd71c60b08f8d9c5312f19d7ea9a24ac4e7b000827a439934d2880500e6b592b66258c513cfd3d5b0f46e4d94f0bbab3a891c93313daebd18fd5757c3" },
                { "da", "5cb8c6f66f09acf15b6353833ee2a884ce2f47f225ff86976fffd7d81ed08252521b653eeab5de3a2751b76517d032ad774ccf45963edad31b9aaac6e23fa893" },
                { "de", "271308c5dd7ed29fc47dfc3d42f99b79f0dc0be76c2df6a0b98fd8733bb3c48d22b4199bfc1474cf05bf3299d23d536aa1d205bccc9660b213e905e3e24ee403" },
                { "dsb", "e03a7ccc76ae592f0d35f275ead137d0b5536eccc9bc0196fac145ed05d12ed58a1326305b57c6e051fc2c2dfefbe4b55c2401fc1205bc9f357e60154bd748e3" },
                { "el", "26ea05a06269d5c3bfc425acdd698c84a354820c189513c2a8254b6d01fdccc1427385b3ce13b597dbe68c1d7672e2db215f1e6c62afbd7c30b96b7ecd098c06" },
                { "en-CA", "218b536d30b41ac9db9ebd593c501f294f236ff9c6bdcd02090e3c9958aab488c6d4d5d58db599cf15142188f45e9895b337846188f1980a55ec1152633ac22c" },
                { "en-GB", "6af527095806e5c2387049f12c8f14fc0f1c0a47b8fd229c112d234e6f22ba4cab1153258fd95e4dee46b376e8621f007baa48af7dfb8163d7335301acc0cca9" },
                { "en-US", "ac043c47f09c1f07825bcd31e9298972eb06a5839511e750d6ff64147305409e480b457945f30d13ea56d89a9fe68e7e17d44482af2933b2e30eaa8e1a87227a" },
                { "eo", "dede2c7cf06d48fd6d03936dccf1d5f5b77127062dad0af966d058ca68113699a7000f76a9ae1b26f1f0d2e0b34c239b501a25ec5938189cfcd0493119cf21b6" },
                { "es-AR", "36eb6c540b7df6e81bce158fd318f2f61dfb51fde17d897b28154564af0205d42baced38784d3bf3bd7865711b253b0cdfca96be67857daf246722f02c8ba332" },
                { "es-CL", "f9d755bd79bc2d11d09679bc46b9cd8d780f29eaf915595afef322ae567e49d5b7ec185504b6ada66d05518d14361bb342a21a7f0451fba965e2da815ffd119a" },
                { "es-ES", "0690b8463703d94bcbbb114613ddd44839108ce6beda66f8d1abdd92905782dc6036e182145892ce75dd50ca0f706b30fd636a00d3df4837b117815a2ca2c75a" },
                { "es-MX", "d6c0c92b405caf962b551c242116f7b752f302269cea5ab1b0a169cfe5aa8a11562064454d08a2f38251cca7469ae632e5effa95ad1acef11c71fb437d9623eb" },
                { "et", "f089ec78970c466dbb09224b1d5bb7bf4be735350174cffb175e8681871ac832581d5b164f83b260799bb67d8ceb9d5176c105829db9bfdb673c84721bf77346" },
                { "eu", "7d7d057e3d58dde23ffa38dbd0dcdd314e7e45756fcee6e9c4a8fb97d7164ae0158835e4304f2201c639ce0f1e07ddcae34f80e3eafb96cac15d0f6a9f2989e5" },
                { "fa", "c88b2e33e782cf17e015406e3a04bc5d28a903d3fa0895320c3eff7335a7c60bb126e97a97b4da78496ad1e0d1a5d4d00c3d7ef470658f82e069ddaaaa2c2380" },
                { "ff", "4c7f2bf42b5493f42c09c4541fa4cdf765ac5b7e5b1b2937fa00dc111cd6252e54e049bc16a21c7d8b076c6408f1065325e6bcb44b55f752044fc9dcc4493482" },
                { "fi", "6a0898a15ae5f0b2deca94a4f0cb14a6b73bc8cd0802bf3c15c2c93cacc3b79b8f8cf6420d9958d0cf27260d887e2da1001a955b13895d0adb9f659a1a153d0e" },
                { "fr", "299e1d6cc2ba5b62730f1478435606edcca8de97b17972a2c15f25648c7c61491898795729f3b738270cbf4380acd25a47464cea563e0dd3ddfaf991d1d96865" },
                { "fur", "91a5efab7cc28bcfe7f8dc1c6cf76b01d44a6166b3026f28f7c6e947c20ba645a3a6ede6def0518d81aabbec5a1c8322131799be9642e4252a168c38aaacc793" },
                { "fy-NL", "15dab51bc13899cdc82e3ce9f6436028f295dfcc6266fb4e21cd77bd1bf65ea6ffc0942bfc94d239a6dc0d5dcc2d1068021da822e758f747ecd1919312b7b39b" },
                { "ga-IE", "5beeee00f22aeb1281c9f084b1a367faf20244a8f2bc96190b82d5c33271310df08796942d5da99ec5e9ced90f47368adc64134e3beff2130d12fc7c8fc621b5" },
                { "gd", "c686da40382aebb582ced0d4b91b3340c5edea6ae9625209d3870d33a9b2244a6594d6856e28e611ca16a6581cb442b21945f1a233e4bd6bdd94c9b2c67fdc8f" },
                { "gl", "2689a611c97e29222e6b12b837d0e926d3526a11977e58410930f916486157733b1d4d7070de33e05d8d0695111acf9bf18a2b69666a8b95d4e06426680caeb8" },
                { "gn", "d0ae7b5f541442e8e09b33e4375a41f229cebdda3ff564d2c06a714e20806f8f61f7ef212eb6adc21c56ecb141a161026f785f5bb9111cc11c23f66cccf1dbfe" },
                { "gu-IN", "24f77de711bd1d83957814e69b75da4855f3436bac66d999c8b058a383d0b6c0959ad8168343161534d53be15e802167850ea519a084d7ba6ad3e633058f38b0" },
                { "he", "86d7020646914cc75b8df0df411ba0baec178f5baf3eca68223e46851433924feeaf827c8ab69aed286c8cf415e2aba027c3783a502e4e388c66c14b78959c84" },
                { "hi-IN", "804b2d154fce5854e762df359c3c266df804ce691c7a8827d0caadcc3481ed3830cf7c22536217da7d5ead52b590a7ec2e02e396b07429b26e4778675f0f4f57" },
                { "hr", "00e9178debc8168778a6a30291f8a0ef2a7ef2b025f5461a35b42c8b4f17742d9e23b02a300e0a4207deb2a5bfe7c90eb68a2eb4d08ea92fffc93fce5d66d6ee" },
                { "hsb", "5a229d7dc8767cbd29c441ab177285a3366db43b1c5827ea53a584490e2885511c34eb8dc1310a7d669fb1568213bcd229ebe0bee5bc260971747e7b380c8a0c" },
                { "hu", "3a47f77b42d0e4db40e724cff4abbb58441c051ee83904cc0a6c9093cb6c5f5c8543b2d76f5cb2826e4f1054c628af8300cecbf6ef2c8846cc81b2aeb104fd79" },
                { "hy-AM", "69342cd49505213fcb0943f2d708041611d8968c287a6518e99efc49765069c034d98530a58cce11f82b226a550497bfd10408386d0eb5bead690c84f61c8604" },
                { "ia", "58cadaf1c6ce48361d99d27d0cb8b683232eb7383f050ee42943ac41ef128e1f3d389bf0ae53cebaa41b00c99cc80c2816106ef04082179cf888e17ec2e34115" },
                { "id", "effc46c51abd7a9e596a4ec27f5768386851d41506dc5c8f75f1ebc8f02bdb83584c32a340644e1591eebffd9a650222f7388863497043e4909c45ec502cdb0e" },
                { "is", "9731c707845ccdc3bb7e706dd5d2a6e600f8bb5d5d32bb745c7db24990299c4218712099308bf7dda791a15d97b74bac3edd47438df99ae405904f4be3ee2cf6" },
                { "it", "32e11b83f0c8460173c02b88593395e180d830222414ac916f99dee825078b7a9e074ae82382fc203b6a1a9fdb9ef2af24610c1f8e5f59c96167775a9bf2afb5" },
                { "ja", "9cf97ba3f558e38ba114448e27390de0a1f950a2f07a9e1b427738f387461911b47c3edb8e9ef79088c180efffe7f01bc2a43e3d91cb1b406a78792aa527d469" },
                { "ka", "587938992160ed2d3e342254aeebfbc4415ceb8083395a2f1248c5aa986b3a92375c0a893bab004edef2a79433b538f10df5d767a9644e6e32ebd8f4a17b7ebd" },
                { "kab", "20fcd3a3193e440980eea5d994df7e3aa8b272f4336a7b56aec3475642fce06f8949133477eea568fbe536fcc1846f5b3426aa5640b937ebbb01a95e94eecea4" },
                { "kk", "3242abc73d427dc9eddffa668c3f72fa9efd78c6c3372b40417783380e9eb5f905d889eabc081962825c03fa0c5d7b543dabc99fdbe69fe2ca6758f25bb8de6f" },
                { "km", "e9d0c33c6192f91e0ef22401963a84f775cf39e8c84d886577cb3ec435e13243f889706a425f1ebfd29a15c8914580d7be8f5af5658be5cf1149cc6b912a44b3" },
                { "kn", "f0ea6f071b6e004707c66aa811395f5d629d825fd740044c327debdf620d5394007ae26d8270af8b48dcf6056142b0b3240f7c599d053b7ca737746db3f17419" },
                { "ko", "af0a0d324fd9af4a3daafc44d5ba096c1ff7f753d300204309f7ce5b6b163d5f35ccb94ecdb703eff1d98fa62fc048292a26efcfce81391fa519dae8a74b3448" },
                { "lij", "019e73e4bd83e8d3a1ff186d3156ca67347ff7538e4e93d552090312bc4fbf3b5b44b331c54538653613b7f13b6da2d7335f17513785e6913dd3e01794dc1247" },
                { "lt", "0a9599c1cd8052d5ce417cded275bf4cd55eccdf9415c235707e36b652e61f61c39cffd9db1ba2b702744d3e5a2de1f9de6b881d57b6029264cbce92373c7dec" },
                { "lv", "31196be1faaf5bcb4c03bb039725416e70504898146fdd95ef5b7ceabce39f413c7154175831c81cd596917578172d11c830ac28ce079ea893d049aeb5d9ab96" },
                { "mk", "8524ae266c8f99e631b24d81c620e4de7e9a692b712507ec67409675fc27d88700ac9b1565cdccf768a67b4b6837987a9ca6bf55c0f3ce25b918138da5c1ed0b" },
                { "mr", "83d925161e7fb53a513a52c7b4a2f1d549821a0f053b3fdaaa0688865317ba9c055ea4eb211f642d2643c1d6e45beda132ec71126b785e6624e78819fcdd3281" },
                { "ms", "2606f3ef18bdc12c58a75140c1996499e8a5a4294aeebb0434d2d2e3d94f41db03e1981b96c04ba6f8f885cadf3768db69eb6c51a40d6ab62be24a51dbd42e00" },
                { "my", "d2a781025f2ed0f6f787b915bac630edc6be656c1e6ba93e5ef6e2123107a25e98add5a31cd9612d39347a2cc808f8cd860de1c2402aed2809c35bff449df990" },
                { "nb-NO", "9ae063e3552680bda7988fed28ea7c7f2d0488d95cecfc0949ed9eb428e9b871964618e6aebeb96c2e020920aed874d341534563878fe18555e9dd748f6c6371" },
                { "ne-NP", "e845312eb7a20a466e8a27a9e58818afaab1db7e07222c069ccf9ddbaa48dd3df9bf27c18c987e2de86767bf7cb098f6d6a86f37973d638d830c4198f1ee037f" },
                { "nl", "a629fdba1abf1130c59b324b37d74aba6a18de1fe964a0f4c466f05cca255ab4fb2274ff2cbfb7815595c7350ab2af07435efe81655ee59065c0453e8736d541" },
                { "nn-NO", "94154de31340f4b4365bce4996ef19fb46e8284237fbff3892fac9510657e4ddafdc7df8ab8adf257be181ff67e8aa4afdd31956160b6abcfa34f37089e9bea0" },
                { "oc", "0917498f61e5e4255c5da49d7f16159936744ee26acd5deb23aadaaf58d84e6b437e4b5ed3b1c89bfa1ebe483e2fa88d3e2bc1bb8b108928548a44c716c7ce4e" },
                { "pa-IN", "6279b9bf92191596b05ce2169b1d7b0129eec5cb96ade8dac8eaa528eabec2b78519510eb9aad5c064ccb0292928db54bb9247a0e7cacc5b8a729146e2ce1e85" },
                { "pl", "a95415bc41fe5b93d44c472316af02ea57220a6f8ed00bb538fc634546f31fd86d525e44ac47e9199f1987143860c3d18a4537d0452bfa89dbfcb77e23a9d4f6" },
                { "pt-BR", "46278da9e3819f128e07824eb5c72afd16c22ec38b6c3c94d3036e2436daa274c324c0e0db9e2645600872651b12b667c510ef702b7b7f0f0c8a3da5b0ce72f3" },
                { "pt-PT", "c902a96c018e89d62b01affee89711c20dcafbda83dea9236e429820609bfbc044837e327d892f4a92a9ad72b0fedaaba152e4f9dea1409a143a014c3718eb1e" },
                { "rm", "39833f8cd6e9f2079c068cb9688e70eec4a1842b32fc5d364b9e4b54fcf092a72a350af04112ea9d0d69b3b51eca4510fbd023b5e9ca41dbe9746fbc0b8df4d8" },
                { "ro", "8aeb26c42f159c286bd122ee3c80d9e09b5598978b1ccc0f89436a1b111f89b9449865b8c8ff0c04822768662323ddc9fc5b11c9cfa01de9638975954270a7d7" },
                { "ru", "412bad450652dff74f231002cc37f8dda60b546072fc9f880b571d0b5ac61fe9eb23d38847c8efb82b7477a80ea64da953edfc27dc9cc3e75b0a2371ff570722" },
                { "sat", "6f3096eeac1d80064d30f41d533e92b5488be514ecc963164ca812a2c542a95ed93b17287a28db122fdaa1b50b9fc7a267b0a195f65feeef8a9ae9e5a98ddab1" },
                { "sc", "a5fd46affe632ce24170ec85e2eaccc4aa17afd32ab7201b3fe9391f991e7cdda75bf753eba3304962746122866e8b234c682d7c772f0a3267376bf8b9737794" },
                { "sco", "9eb720e6541de2d10b5dac4a8940fc36002ab3b2ee8b66127598675f721b7ae253b13b0d552e2fcebe0910f89fd42adb9359798bdb7636c5566068cd1795d736" },
                { "si", "38d80df2314d9ad6f7efcb0d47436b393ed9f1b393a287d7d022e67740c9879d6c40656297b52f6812a92474d6977bd75555d0cfbc33fd6b781957b1503da4a5" },
                { "sk", "2fede486c5abde718acffccdf7492db91d7e9c9fb2780ae0709ef57a0bf6313d9bd3777c3f9da4805011e14d46fd1c017017b137b64f09fdb8430cd79f4be8cc" },
                { "skr", "024594a6fd8ffe6971671a87054942c896548d77f3d8c87a42c97b9e55d59be5086824d97c257c021b99b780fe34a7649fb1a24e5ea30d1267d38fdfe38da267" },
                { "sl", "f27fd4a9bebb46701e1236fe4f6459b4e6847fca9d43cb349826e59f1bf713d86ce352b82b843c33dd6e10b64565688b3d38ce0c4955283ba5be4f57eba02790" },
                { "son", "144521526b3b1982d4bef2013de5a5e87c0cc29a061d1d88cae6e63fddebfb42631a408f5fc48df583933eb9e884886afef7218fcca239283eca2b2c1a6d1b7b" },
                { "sq", "dc8293e07878abb59f5f07750fee44e19a58f344bc3739e702ad9edacb87ae872799bd9f3e359bb3ef6866a1c2b2964cada27072fd644b4e3e4cbeede20e0749" },
                { "sr", "c4fde952de70d9b4e4ba013f78411865986fbeba875bf350e86979e8f3cd233c44f7609a22f62974ac9eb1036ed23033320d24d3f0079036ea92f7a1920f6e6f" },
                { "sv-SE", "936a8d58718e125e01c2a7de387159e7eab6da6064c383407b03709c8e9f57334b4f82da6ba135ccc6b69752fc1b5b267c740188e9e40ec8cfc78341e90c3a76" },
                { "szl", "f9e85a36032ba3fd99f62c34fad29c428e0da5418374eb012601bc3d61edd2c15f386034fce04d0255b286535d3a51c8020985e69f162d314d1e787aa74f5b03" },
                { "ta", "c4245f1b7f8bea513c859c62924e97b2338e4c73a44aff80610311602b88e084b6ec9871369e9e5fc21c069779c411afa2bbb9e9b2dde557a419992222438a05" },
                { "te", "5ff264ba6322ba3e69782fc6c9b1701d63869d05754079af918d75bc8ddfb4ea40b135d7d9a302caa845d21dbe1b533846192b32aa2e3667b186bcbc4c88f3fb" },
                { "tg", "97946c70625e941915bce7e8b5f3c4a14e844baa0d9a3302ec50876ef009a1105063c01a5c86a0432412b30956cdb84f72871f9594cfd5a006dcbb5988f801fe" },
                { "th", "99fe987d4bd7049be7203206892cdb8f5d03136d3203b30694f088840c38df096a8e91c1d0f59e205678f9ea8d30132898cdb92493604d2a07bf20be0852fbe9" },
                { "tl", "f76a980ef1a09653740408f901fa64d8cf828f5e8d6d6b03cb03fc2c3877dc9a4b236fffe7dbbc2cd44be3ca5f0df97c0adec957eb1174d0b0d50daee0fe606c" },
                { "tr", "2c4b46fdeecc9bb00e6d0f77f8c51d7626814cfa483837fa7ae3e47547098b8ce5d02920037ab64901a88673bf787265aa341814e65616c1c632d11560e8fd51" },
                { "trs", "082a035a8e6e32249ff56653aa8cd64b2bba83e5c5945362ce3262e27abb6f2a8ed220505dc4ab3211aa15d0c6be76fd65e00b1d7152e95fdcfe8e881f6e8296" },
                { "uk", "06fc3c6fd2677e19ce0b0d48be485186c72397438b7d5774f0659e184b61490e9b5bd57357afd6440b58d1d454f59854882c081d43a1d36e036f11e0a6935810" },
                { "ur", "1112e31ede83cb9788b820093f6cd75f43a726057f2840ee72abfa735b911677fe763fe377d143615aba4ac4f9f712c32c012eef963e31fcb44387cc66192862" },
                { "uz", "8319c804ac859179334776380057f578d5d504e82ccfe5ec2844bc7b9e2c90348d149f7a575724d7b33989f71ee9be3a306dd61cc3fcca5f55a40c88771e1fef" },
                { "vi", "aa7ffdce28056fcea5df417bd164c953292f04b7f700c389fdc258031deb48726e3bcf0a47306aebb2ce4777609b13dd400e056bb0b59c10b5b849cdfd5c12e0" },
                { "xh", "a8e0b6ba2538c089aa3f7f74cbf7469e1b4d2e1f506ae97e4fb26c4bd86d2dd9f355a246f9e5ab8c88d160d9ea83c0cb96e69aade8d64fcf2488084b447b223b" },
                { "zh-CN", "e17669cfe0f449aca6920f8a44966e261b6462c785be485335231e42f36df75fb584fdaadd04f4b0977d6a82a709ea2d1b1939d21ad052d41b44d64c28028e70" },
                { "zh-TW", "acf9200f204642c4fe47e6fa4d9ec3ee9c1fdcc2eea7fb39d5f2f802deba2077a9c628ef04c69c9bdfb95b68e42b7bd4fd733009644621dcbaa3469768a3cdce" }
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
