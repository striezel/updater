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
        private const string knownVersion = "128.10.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/128.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6d2c0bbbecbabc514cf0f0c08903ba87d54421d44af09b4a489538e2aa6370ff1cf5fb93bd454665c20033a21afb3757eeb142397744ebf276b3491e2db4c638" },
                { "af", "1bd3cd68afb4dbcfabb683a5431614626a9a4e7b5fc8712f93bb423b03d3bd8168429556bada5a25a6103b6e36a752cbd15fd1a7ac5f0dff6ef7cece17296d26" },
                { "an", "f8e5542151a1594d32dfe7746ba48b810eb16c03f6ff1a1ed0f89b6234c9618c131e126c54846fc04812557aba833bf945a720bc2f7506f23e945f34a55bbb28" },
                { "ar", "460effc41a49ea26e5644439d101d45c4f3d800df729f8aa427ac55f1d992fc10b95acf2fc0796ba07ebe2488f6be70e6f995e2aaf3d64ac708ebcf0eb74cf87" },
                { "ast", "28057858d0bac87cc15475603e77c3e06396b4ff78c8aa4af46d597a1106464bc4391c9c66d987fac59cdab90569d0500ef5c000ebc7cacfe18761bf2e2c9e0e" },
                { "az", "a61823bb4038cf2f934071467265cd2b5922fb01755ede5d63e673dba7c2ddc70d5d210b07567015416edec94c7a0ae048576cb598eb3f167cd57a627928832a" },
                { "be", "db20d3bb9f9a1c4003372f1d2153455a72d4f3be244894dde321c9cf0c169e6785743bf57d4e1a505a18a7475e83dd77663f4be210462511a32a63f72f055c2f" },
                { "bg", "1ea557db5201d2eaa1062c455d279d92fbcd049dad105e1864825786fc7e37bc70d71bb6a396e3c218a2b8cdbaf4bc06cb9264143154698614bed886a67a68a5" },
                { "bn", "f92e57d16251ae98d83cd5bebe6d7147a3dce970965a016d8da92a72c44175146bc60cb4f943f0c46b17591d6645375776cb345e04e1fce9f7c67467b7062d64" },
                { "br", "267615e3ba623509c45141f0078710e3f018722c28e62ff7ee46058982682579cd7bd6846451171f82b6164a08028806c418b0d97e674983b67b810e501977c1" },
                { "bs", "b1ff981a7dbb4fa60d256d3e47d816f5d88282a0cf56e349c74268aaf9a3bc28fb71cdc345c900c134e13dcf5c0ebc8599c5fc0e4e5688dff10dea68f5316d4c" },
                { "ca", "a1743d688c66502ffca01632eb9e982455726591eb6a218b3d318c66d195879b794f8c8d9052df00bb57d4bf3358319bd244146baa52409c6619947b679cf172" },
                { "cak", "c6bbe1522079c8a706e666cd59d9a19f544b252872d18515f41a840508f73a1f425d1ab5b4789bcb4070ded39af01365f2514e454ab6ad992d7030f53a6dc50c" },
                { "cs", "c04217ec5d105c3ad6af6189a5a022e703a50c994f9897884f957bb57c293e6011e71387ec8898243405fca7a2a18ee1cac13faf7d439fe07f4f69098bd2319a" },
                { "cy", "6031e3a8d53ad851cacc2892e9147a59b05c67457ff10957caaf0778a62a145ee992eadc8185a48b7a010d6a980da5be2e8e9ae5d938aac149980c2de51fcd30" },
                { "da", "4412dc079a9da325f384436c285f2b993b4b80abd9a6e94cbcac4bf406c305ecaeed5ab79c2201e8238f0d56dbe613f6f5b99bd2910b4fd4acad9c60e35cd359" },
                { "de", "a5d26f6123111ebce19319a0e6275cd3f16b5a7749a9411ffe826f08913dc9de657deeaa78a5c4eeea4f30f7cdf4ecc892adf58fc4a303de8a5dd4327ac4cb35" },
                { "dsb", "7280a5dff8dd1d74f308d92700d0050c492a9a199f84eabbcd4bdcf27cfe71a6c458c0210f22e642e9c497e731ee676ec6ebfed08897ac368fd6b7e318a5b07e" },
                { "el", "d2e84f9b3059ef5e542b9692aeed319850f05250215f0b2b5d635f8b2fc4ecf58540c5e5cfc4a4cee6fd8796e1b24ab0a0cea61677a6f06a9a00f4d230158a33" },
                { "en-CA", "27d90517b00cb8137407ebf5e7a91ef456de408cb24348ae7096c6c50e1d80b85d89435c4502182d5f3710f4d3ca411567d334c5f07789c7d2c8b2029cb9f6e2" },
                { "en-GB", "f64360bf09ee85827a621dcddb90b275a6d02366f322fca3e25955499876cde294efe071c679d2649c7cf0209fe5b83334e94752f0ad52ebb23373e972c34266" },
                { "en-US", "407304ae053d8c962f1be2a1ff5f61c21c5633ee8cff73264bceab003cb703284a5573636c19ca3264ad06858d3c06351e4bdf43f7d8ac264a10ad3d64ddee18" },
                { "eo", "dc84faac47bd42a8d94af1ef827845e947976be93d76e3bd74e6aa1df25d9ff2062f7669b7b220a169a12ee96976a9837f8e7a0b8f3b493d6eb04b8f60dcbdb7" },
                { "es-AR", "eea1ef669b98db5cd2b4b297273b1fef6b979c988958bd902802b3ac821b39d3efccc876fc612357a3b72ae9843da3cb2511d6b70753a43df2d9e89718c5e7d4" },
                { "es-CL", "ec77ce034d8d708dc3a64882dc456dc5e72a54a4dd2bc7ea3094ae04d5d76418d0a9a801824e892e96d079f47e6adf0e9f66d17c28ba938b14e4c6a2687f3fef" },
                { "es-ES", "907ccf34ec0872dfa900f2f1a9c4027e9fc165fab588b4f231a172445a4373b6e1091b413fedd667749e42237514080edec961c862ac8b1bf6c4a6e54eedc599" },
                { "es-MX", "f04cca86c4eb1414d532dc370edebd05acc01e46560f93eb50b2228062997b0eea84417e2bff4056ea000a736079d3add120f20cd0b9a1a84cb2a39e8ca47a5f" },
                { "et", "ffaa37fdeb297a76f509fb0a40220664166265f7b9105a7494079e1b200c23f448a40cba8b72eac355fc0514eaf98284bf066bbb7fa48f5539a064a188d6b2fc" },
                { "eu", "b123627f079989824bd3f3cac4fa9c4d7baf37b9f13b5605e981703cadb4054658531c24b1875cb4611dd625cc6de46428ec536a953f17427371dcbcb80f10ec" },
                { "fa", "9d0d550c62d4d41692a0aeca3957e67de585ba6271028a36a7d088e96e17a2928ad698131492fe17c9593fc249d296346e4c7d1ffaaa5ef42f3530120fc63ada" },
                { "ff", "2f6ea5480c2d519c5cdc5428b17cc439df02a1a54330be4130a2e3559d1cf70366d8bbf1c16c04694833040ffb5f19c271692bc712725a50e8f648ef3d82eae2" },
                { "fi", "03927b6cf5587796e0f53ea5639624046d2d2210b3d7d2a54a4cf19b3353a51c80e08bd8bd3c4381e3255b0f5c522a53a1050377772d161889171c2ff6cb78a3" },
                { "fr", "d9170158dc720f28a5d58bfc5100dfed6affa6d520e270fdfd06af714934b37c29ad0eaa5a47206ba7aa62024388fe7668864f7f4abaed77a889c18a45a5595a" },
                { "fur", "4a3fad7dcc5c421a9afb6dfbbeee41a8ee860d329730f4dda9ae79f611196fc4022f8c832cc2fdd8750492bb9def26d98c883e8a2a91a09be77e3f428e9a7bba" },
                { "fy-NL", "a3872ca3d3391ed06e28a8d6eef37c7fc24a06d6ec0f11e30e1bec061cecbc7c4364b0bb9e8e09d21dbd139df9e33e6f02d934f1c0d821ed40ce026ce07f2c40" },
                { "ga-IE", "392768a9585895987120142dc803f090fc676a6e7424f6e4be4e62e5837d8fe012eeecc1213f6bcf777ac7a99fb0b2eaf6128137cfa7bcfdf800161ef469f24d" },
                { "gd", "7b9b2de17b0e17b1c0f966cd524ce9127822ac7c8dfe72bbac2a9d239b09fc076a6b957285badb0ffe53602857c404932e89294a8a981b63d0d0afc595690213" },
                { "gl", "58ff17536085c960db918843137b7edaceb780c87c30204ac5e9f520124c2d2cf5bf65f7e64740cad32bbe2e19c4f69ae644523d7154433a58f1567c08d820a3" },
                { "gn", "6f1031f0812cfe60507b2e5f8008687e0eecb956eb7e93a2bbb015575a38b7f63dc726811544bc19d8346d58d02f6ec23381d108505cf916f688aca93519d3a0" },
                { "gu-IN", "7b96070bd09c060fc261d05c553338ac2c227677a5cd9af7b2fab9d479bdc10f0e61d1c5c989aed89005b8d98078d1422499f5b9150a2eaf6e3141c63d58dbe5" },
                { "he", "3e0aec86e07e709d31e1cecee4868a686efc903768e1849e407d21e74ec0373069dd7cc688f6ffca62c5243639ae179354c3a3f23c2aa2c1fa7d4a1ae21328dc" },
                { "hi-IN", "7074ffe74396060ebe90438e2ada54ff88888cdd5e55915c62fc16a5e51932b9e2346f0e50c1043c31b43eee6eab1d7bb670e42624b431b7d03a3915215bb95a" },
                { "hr", "94d6a6e4a25d5aefbc0286e1cc80f58258b7de306e5971d65c0385a4741477a0a05b9b29ba57d7f2cede9435ffe5cd6bb964722b0153c8910cec405c15a6502e" },
                { "hsb", "03f17857627e3e08fcf50c53d1696a5e8ed210ed77b498571bdd9691dec44e26f37c86f66eebe4a545a9ad60f5af0f2411e7d75f0ba6fb3c30a05841ba7d7ec0" },
                { "hu", "6caf91a04d64497197884b3f3c520cc10eb76a832aa92138300dc88a5a77188a7100c38f881d5e206ac6e697cb394b1c63447b53e75d37f0f1e261bc621e002c" },
                { "hy-AM", "4eafb314be6acbfe7627caca624903a09fd7abbc6eec90dca922c64efdbe9f7ab38f8f5d947b9bc2648c16698e700e5cbd1bc10dcbffaf74a597f10bd5820378" },
                { "ia", "9c6df57257191e55b46ac4293d13d4e03c568abe651e6a5cda8a878f7ca77610983b8421f4360728fc091b0bc2483c3c9ecd299c71f1f7e42bc3ddc2d981d828" },
                { "id", "7bf2bec681c5863c7e5ea21e8266eb47dd62c60e5003b706b66de372d60201562ce87f16d19354715d640507cbdb11a4d409fa7e8f256357edf27835dd2b1a28" },
                { "is", "eeff3b69d696a98fc0797a69965adb935b71938abe4050dc59e359bd1e15a491833bf0b12422bfac76010dc99fda2d69ec16875961ee6471bb5d04fa2457447e" },
                { "it", "a51736b29740397c23f82afecd5070cbf3c3c8e25ce22a04a654dead07f40275724a17850984448834ab8f4f14c1e88da256f270b33ca83bfa14458c73f41b1d" },
                { "ja", "cc35dacda38e4ddb036d6878cd2a49762ef975b95b4e313d31ce88ba8ea7820d0c5b0103ece709ae82f06103329675015582f975bc82a6adee7dbde1528e82cf" },
                { "ka", "23844e1d81f98466d785b7d034e69f651d9e8dacd8e2ebf80cd27b41245cf29ba0ec1f6bc5d02aebde6c891535b246fe576255c8fa4c21875d749980cebc6cd3" },
                { "kab", "91a515f616d8c2a1765cd86a18c566bd5bc26657b571a387408e72a44c89a42c122c8d19e315155d00d0cd7636e1cb43bdf846fe7f95853bcf287464c36cbef2" },
                { "kk", "310e0e16fa3f05cd647cc4139c9dc69be8a322f8a0f31a2d7a277eaeb168b7e61c8cb1897da4ce4e1773133a35b998c6558bb1b19023c7defa0b6ac774209a4d" },
                { "km", "8fa5df8ad1c2f2fdd51c38639c74795fe0353de9081a79004b2808a2e58dfaec696860636f7f8e7a4a900a1cb51629fce6d5e7b391e5ee6513c71d133797d9e1" },
                { "kn", "39b98d8b1e7d37a369ac3ac5738afd2567270411bea420b77ac96d82cb8c376ae8890ccfea66cb03bd51c9d61c27d32b30de0d4c63ae3d5a4d76f5125df423c0" },
                { "ko", "d251b8e5270aa6d2b2ea4c6c50a90991090b4d56de194b5512075d49679b8c5444d686543f38ebb1383e8470841d65670c25ccae5f75b261b52176fa6c72cc23" },
                { "lij", "eba0864ccefa0152532ee1c0252d8f395563a38e4fae4e2df8790087b8ffa9836c858e8e794aa6e24c28f4c087a53b91330ce876a76c74f20f809b776003ed80" },
                { "lt", "56a6543fa9dc8a158e2175bc82eaeb3d77a0abd9f43542fd0cafd5c90cef9af1c82307e11bc54cbbb9679439664dccb14f01e787143dad14e6e1a179bf2a925a" },
                { "lv", "4dcf939525faf28da48cb00bf95638654bfcc4f0bf2663a5a3c06c7c69706119c41bc32bf2f3b6449bb8aff0f875427b544b2e5c76f2c5c7d4e2e6bf9f7c6084" },
                { "mk", "4c7005ed2890c57f6ba69bbf21e7961138b88f205d7687b6df7ea8f47cb65ad25c525bc6602b15b1efcf3b17d45cd17eb3889a2ef4b5f5076751a7db34c46c8e" },
                { "mr", "063683025fc93fe5a7baf963ccacf16e6e5d53d009c38f588c70f41792bf282ba522e37f49bd8b8f1807f6ba564edc8e8dd73d857d05763434c327edb7db28ad" },
                { "ms", "4137de1ddbfa103c700cf029ad6b043c03abd7d59ecabd24460d6e3844adc0f8993de31d6b0b5d76553fecce4b50c264ae0115cf02c967deebc111d77bdd8aaf" },
                { "my", "f7d0cbc90c7fd2408ef592b2dba734ec8f8f6e33486f84aeca8143aa55ef05da703824abd8b7505af065b75d29d3b0e38c2670ffc0615b3abb4d5d3feb13a758" },
                { "nb-NO", "40a46f3b2e28a0ab8964bf8190b1bf7774391fa2bbd5d41f99d28c97b398bb4eb6c8d0f26fe2c8e12eecd559a7ccbe972bef385ab663011c732e07a5cf9c767a" },
                { "ne-NP", "9bcafabb83b20d12800861dd11eb70a082b9b20eb5780d569d6abaa6f8884d7bbe247fd83ac7f18cc2e67e112eafca482da9adc99956306dc6089ef79aecad82" },
                { "nl", "8c137da1c58c347766b577a8dbb8b7a1a2e382db94bd4cf0788327f7c191057ec0772666e41a735b5b4e557f11e6d0cd8905a91beb3644e25d1f8249d519e712" },
                { "nn-NO", "33272237f966432a08c238b063d3acb7ba7d52db22fe8bc3d1be5c286e508e2139a8a8af23398f51a2b1560cb2f12361623e5670bb1480fa75d485190533c8c1" },
                { "oc", "dc5b9b16b03295b14fc4b7c60e6de5cba06c0daa542598aa3216a25912e5cec9e193666c824a08fd2a5f12632f1e0cb9e09e255281f5addca7a035f800d52d6f" },
                { "pa-IN", "f79c1942e35ccce192cf977725ff76ed123062df3e4ebd3620abb4561e1f37e3564945f922e511957e3bb986a1f2fa331977a5144b03607d3b87694328c003c8" },
                { "pl", "63690fd82897aa6d38cdb8b9f28b59a53bfea6765e29f1a79455450549d198f51c76e5a0178f4f8b39793a828169a8b04c75afefd7e2c44306bacb5522b6f9d4" },
                { "pt-BR", "0fd33b76ee5a895600f2407e4f49731c1d47270d73082fdd24dd3c5cc63002fe4e14eae4fb795f9f51e95ebed1a892d52c417dbdacb8f790c8575798737f91a7" },
                { "pt-PT", "d516f62285d1386f1de66b2b31288a9f616f6b4b8aea6b4fe1c0fff21f071e562bed944309916532232378d40dbf72b56c53fb87b67178a25d85020af11bd6d9" },
                { "rm", "01f6ce84a215f29f80932a02a0a90aca87b591c855b40776713afd38a08c592cd6d679a1a37766f03d5adde9e34f8c74ab1dc7ddf1eae7c0007a51964a2ceaad" },
                { "ro", "b7b4abe9d1db6866de395e648dfa50022b91152c039d586ceecee3f124cc3f9c5b7380714192227aaaa517165a9e29c669372b07e3c5b0acf5597c1d8659010b" },
                { "ru", "fe4169171c086326e7f46e15f556dba29e6fc62a3643c8f3836432baee083c8e0d79937281a2c2727741f3706731b6872321dbff25b7fc98b35ae5584c8d72cf" },
                { "sat", "fe44f5fa1f559b00e62b5760d3a5852990fa619666a3426b1be8189111e2543f452c86a661bbf1e04b4ed4fe85c87977eb58ada6542707ace6678c4f92282a73" },
                { "sc", "6ee09ee29bbf0e52ea8ed62a548fa8dd761fb2f7e347accc275060258e00e23cd91e32a9377ed1186081474f45bfd1cc3da91377c6199fa0635e50d0b95ca79b" },
                { "sco", "68abb035bfae4c33f9d1315a0c69a8164245afb56fa0c5a2829d855494dd63f3c4a370120a2d2fc556576b18fbcbc02ee7eeb082e70c3e6ff61d2a214c2559f6" },
                { "si", "1bfe2ab7c17e81115d4a3aca592b5fb6b501bdbd7ae7f5abee230dcf4bb81fc68c27c725ad6e6941644bad1320c57414455bd39a2409c490257133f339dc00a7" },
                { "sk", "5fb7f472c21c8c9720be69afbca50eefe539bd7874806a8222ef6b77e8ffe398cf59aaf4e852d454a7a560ece93c7ea6997c88d09ab6158f345104bf21fd228a" },
                { "skr", "86d73194908e535327e210a156c1075a1cf3731d0426ad1fc436e2fc3703bde635dec3ce7755d70de27046e4ecf8242ebb8cbc6d4dbb51555b2c46b3f4cc71a2" },
                { "sl", "062a88d0661addfb9c471d5f4db99d78f4bf885ffa7f546359fc0ab55452b03faa31c8e88082b21f5b1fb151730186528b16957f6d0f9274010bf2ab1bbdd333" },
                { "son", "fb435cb9e0b45a89cefd26003d74b7c3ad770af6a150c733d6b6140d91c3e5cbe79a709c16491de1630488dd4c5d0af958c3e2cbd927179e4de621848338b875" },
                { "sq", "09ca81cdc2480d0f64756e042b26ac4f72e3d59281c4127199b91c122b06ea421a0cd47fbcf33e82e9c03516cea5f00bceb14329b2087c08cfaf18c10fa6d2ef" },
                { "sr", "f32f1664e2e0252c3b673602d8bb6e18cb47a493eae5ad1639720d7e67a15bc1a378df0c9e3696e057c03f84ca6b11f616bc4733ca5eab9c649b1b0acc736bab" },
                { "sv-SE", "e8e5bb7a2aa58a250c7455c5e0739f0d12b9d9047ed99fa6dd8b14588df372bac3d04aaf43109aa1b8bd794033bbd2c38585848173c1e7814eaf50a509873d80" },
                { "szl", "26653313d3711a13ac4d3e7ae5d0af6699802edf808e4b305955eaec09a5d0ed57a70bbeb7a017b3a325fb7397414df59c6d2088edb5127fd84de00b0446cb66" },
                { "ta", "cab3d0f0e82bd46af632e2d12dcc952dbaedcc4463557aae92f9d313ae6bdf01209f8d41ec91a6a3c3398b2cca7e803615e665ee4c59b22c80fc15daa3d529cc" },
                { "te", "87019ac7dbf83c2d9fefde5a034fea25f4140357a89d32093f1d96b93e356e1ff3029e1a7b797ac7f334346fdbf473cce09c6f7a9815904537b17887b1af50a5" },
                { "tg", "773cd0326f4d25e5557012a22d8f9a56d4decf00be63b4f70d087ee3285a946c929387eb63d039d9de884dd070cd9995c67a819c967e69c8b47c796eadae1585" },
                { "th", "5e3d50936ca6d2ad7c32679d56527246cd2e7a1bf2d563815b7a4a4064eb45937dcc6b74c884d996b8589fa3dd6684cdb332a9dacd4ebaf13be181867935e08d" },
                { "tl", "c63f0617166f8682432716433ee1af2665bf639a78f0e02de6d958be35b8dcc49243b5da04cabff8c76b7a0a11b399a3ffdd3bd706c9cf6664fe866780240124" },
                { "tr", "55bdb2692adf476161924e005f5206b4a25d6fb4ab45293679db24d7853af7c561f8e0554865759bd7124cbc8551084e2e647c3e8e2d1f8b9a22a57d547fe79a" },
                { "trs", "c22e37007cef32019dad6fc7f4add91ceee8655f435131a9cb7c993d9c9f1a2943e31325f6f2f9cde95f7e19cd82960980f9cda0ee9b78d897bf097de829e723" },
                { "uk", "41f0ce4079c08cfcf76bc6887205f5e1df793c360fee65b76da78f3ea0eccb73a6f98fc3d929372bc051ce57b4e86f225f358558908a4714dfae3f3a9c4e2b3b" },
                { "ur", "ed0897e58f4b38a2da0d78035be4428279a32f9babcb198e261b118d844f67241b83b5b1df96b3ffd3082ce7f74b2af17e6cfdd199c726cbb06c1a194a9acbda" },
                { "uz", "0f68d172e3a6802e506cc63f4fdb6223e585fde36b93496f406cc34344b5334fcacfd873cc8a9e535bfa4107cee0b8206007e291642dc29ad287091b796ad59f" },
                { "vi", "64f439738981660133db9a6ee2eba74005f398b7c17ef853ba335f0149b610ef286b8d0f9887e8641450bef79491dc9f7c12ba1ff13f00b9148b0337a8f06a24" },
                { "xh", "850a05bb2978d2c66bc8df870cb6bb57c4062e928aa61cdbf765fe24f8bf65af8db383d329944cbf8bf35bdebb475bcb1c1f7922e8d846e84becb3d445fd32e8" },
                { "zh-CN", "b353b3b4bb03d1a3bd1bc6d7f185c3a959e73f6cfb41cad39c07547be8d2cfe5977405a11aed076bb1469c3826a698faa4182d2473e1be48dd7d361227a3c7c9" },
                { "zh-TW", "9b192653ed4faea40a197bf25bf955000293efc1fc50efc1445d23cfaefd58f69aa78845641961983726ba3969ea25306f64c8a5bf23bc72e4e2a5dab4bf8f69" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "88796fc37ce3e3bf73c71ddf3d3501025a258ff7963fb343ae83728257979e40cba0041b7276938a039d8d6fe353c23f97e49709769f428a2df8f87a092dc966" },
                { "af", "efbf524560cf894017c0b264b14a5617999c3d45f1b4a69a997c0fa66302e399f8212a5f6c4c75dbba3fb571a70994ddd9378891a7cee4fe395ab67a495bc599" },
                { "an", "115de430b515c1357bce2ef19e04223be4cb23a177bae970aec1f2021e209e22dd9562f68641a45f9d7499d5f81c353ff9a168001341b2a91d59e4b6a5845213" },
                { "ar", "db55f86be13bd9c75217c3a8490ee5443cba4b7664ee37e503196fdfe5b57b56bb868130038021d8906593865cd606e445c9fd05ba38cb3c93016fd1ca5900dd" },
                { "ast", "99974e0a71bd6d593925836f824fbbf260d45451cd23019cee4b7ea4ec91df186f06802d06b929fb128d88deec8993aff2f3cc93632aa86fd2b9b45846590146" },
                { "az", "14050b3a1ff73acc1b544915222ae08b7e7ebb9437dfaa15d00f0955ae41e6c90df9abb1422176442101548f085ead005c24f1a4bc46b72acecab396adbe8446" },
                { "be", "bb1515879047596055a42d42751329ab6bfd009d655a52ef748ca6a2aae9e449f46b7f1a439859008e81f8c7144f804755e2bbcd06312be19cfb024c802cfa53" },
                { "bg", "fd13a0daf7454381b097b74b1ee4115ef9cebbffb277b61044787c666c8f2c8e679f63ea6bee3b7ea0a57b89ce46c6bbc7e2baf4d3e6ef15a36a545fd08121b0" },
                { "bn", "6417d2a17a4bf283a5c8b688989d5e01dda0b1435c46ddf4d8ec09a4c691400f14308c013144956e34517a57ef002e7802152566379342a5d496c6a6bc0cecf7" },
                { "br", "d36a0a21d69aa634985cf1bd920d8e08ec942db08dc03c7a643f7e363e75fc68884dd8ededc18a4690cbaa1ec58b50e55385a2b52822324216db1f3c85365594" },
                { "bs", "8b95465942086c9d875e1d616eae3f3d62ffea7baebb841c5ba806841ec76d5da41768961ed6b21ecd0ceffebc85ae6dc53e0925b8c268aba9e66beb090a59f4" },
                { "ca", "f0d6bfea54c0faf91a29a3a90d072537efc7b986957f7c9faf938a25ca7ff29fdf551d6d93d015796811b1aab4e6c7a9c98b9a6dbfcbb4ccd0342515407b8c41" },
                { "cak", "57ad09bfffb1dd1e034a39d1232e39f53d8349baaf5d9fed9ea8baeb57f314c5c0e534ec39ef44255f2abbc8e024e01ff43fa64b0c07e7be0fef42c0f1211270" },
                { "cs", "190a8519067e86b8d1f3e252c0ec408306790f10c5a2b4ad750d115a4014f37ceae6993044f944a28eb43c6108d694fc2e010375b24a086c1f1c214f0b20abee" },
                { "cy", "f9103ee7075bf731b396d1b03dd65bb77be0529da257badafd0226833ebcebe71a9bade99f67c880a6567f7b1fb0f99abc342bd08fea75f8ec419ecc9c681479" },
                { "da", "6174536886476e78b91cff6a0b66c99c5330dbed9fa5246ae9be6e9c9c33a05f710c9921f3f828316e12fd7dfc1f1493801ced374a814b13b338d46b161af1cd" },
                { "de", "6dc13058139c78a10898e58c86376674101caad13021f39a1eeef5867fa31cc1e1f9ecb9ed9ea54b26017ce26119305b2e660086fa21789d95bda01f833840df" },
                { "dsb", "836d54fd2330102021601d5847eced9c68845a36dc40929fabebe44fd4fe45b72054ea1f47f4013566f2969fe2c8f6dba6760b7d46ca3f5a72ee797f3fc39e72" },
                { "el", "4786c2579d82faaaf12628ef6fc747f58f72f0bcfb39ad24e86862fc9332ddfe06984fa904b2916609da8a57ecd3b67d505256450231978db6a202beec3689f3" },
                { "en-CA", "4d46ce53506ff3bc872d72728bf5ece2a1397365a84b89a7aa8c95359c03db6cfdaaceab0babe7d7df76448be6473758a93c0c669235de74e5427975751b6101" },
                { "en-GB", "152316097402acb131f9a98830bf6fb89763117e5b336187f0345562fb3c638cab7665fe36b0e5df011bf2ab906d21ebc1bc6ccddebfe9719ff438b4b041448f" },
                { "en-US", "14ca703a9179aae2ce684e010f19cf59e1031bb092c7b0f737eea12c476373829cfed689367ddfddb122ead3ad942a35fcfd2b4e2859a0a420b3c0ac26f41e7f" },
                { "eo", "a02f1fc8476fcd1befcb5279dd580ae53e336e76b6a798affba4e910d3b6c1730bdfc3fbc3e94ee024874d934cd11cc0dea37736605ce732ddd55bd8e0e7ea3d" },
                { "es-AR", "85a7a486f6b344105c598d63f977e769dd37ada22800e0a8395375cb139088d96eb45868069b8e383af0aff6fbff6e87048dc3cec52724c79b9408f93da6b141" },
                { "es-CL", "f91f50707985ef3e0a5f977fe964c082816681ece4295a25ec7590d1e07c7b9fc7c123d19193fe934bff216e58d51a262b2d2ba54bb5fbab2c22e4abeded78d4" },
                { "es-ES", "b246ecae752a6c76ca1c1c49df38c94abd50fa008d86e4ffe7e5b928c52f2ca4bb7d2186b8600b9b73e2e51c9d13a7428e8fe2b5647fb1f818b708b8bfbca25b" },
                { "es-MX", "8f4f26dc97cbccc186effd8d5d845fd543bfb5a7446bdb0e70d5fb9bdd023192621af912914eb4c661779043c0695e0ea127359c716a98b1f4a9b426da04eac6" },
                { "et", "22893dd79d535c152b56ef623d812eaa23e711d018369aef1d1673f91462532031c3ca3e73f07094a0eae6a030169b6066bbf566ddcf42604ecc5245bcd27c43" },
                { "eu", "e45d49de627c6917ffd806eb530b0ec816dcf1f038610b71dcd452085ae5793d0b61e09847ae3c7c0d81b5bfeb5f5c3cb9405985a751da168950dc63e9bb9dc3" },
                { "fa", "d688917f6fa563b3d2389493dd4bba64712d045ae330d91a7a23ced178726da405d089b93b6736d3053e541d3ab953960f70056a628c0dd18363f0be09b0c3c0" },
                { "ff", "31d36cb2dcd8a5c21f6840afa1d88ea710e511024f8e764cfe2284c1d76d171e5e1ac4d22320b7cdaa3f2273dc6225b7aa5d7c58d191fe12444f36e8be41d7db" },
                { "fi", "df42c1c70c2be25c83978addd1833b24b3a105d09aaeb4406589402f235f7d120e119f17b9a97e49b36819fed50ef3accaa87f28b2300ef10395ac20331ef99a" },
                { "fr", "a49a5c043f7c61b3581ff009fbce6e556ef3f2df566a21ddca723cedc25a6ac0fdf746c36e868b71107dc40c247aaf2087f855a54783be65bcb76650a652d701" },
                { "fur", "3907b2f2fe69082743d6865240d43c03504395416ea486a2d6aa4628c09e8ae7b44c334018e02808c6045fb14449266d5bc965f18fcbcd86bf3da4bbf86954b4" },
                { "fy-NL", "57b23d590cac3f8eea850b060eccb4e668be3db993e02059f6c7496b2c8e4f94743c4762e61cf7869d755eeb1027f5bc63088915a3248bbbfba972a42d8a36e9" },
                { "ga-IE", "cc497fcf2364b039dd53bb3d054216aff79a318c36afd5cf18715f9297eb7c46c852237cb5700ef19e98979e3f63d892ec1dd3b36cb8ca61aca3e77be5b8da19" },
                { "gd", "37756b5fa1e83c7bbb79795050a3593468ddde6716b278974c4b894d24073db961dd6723770dd37591e2ad88b1a29c215165af0e939dfa9789705816e00f036d" },
                { "gl", "893a399accc91e6b4211f2329a42c2dade22f75f0724d5a3ada749a362c50f6c9afce389df726e84a7909390ea4276ff8025173533a19110da433c477ebb6029" },
                { "gn", "06a19650b23468e36bb291d7f2c95e85faa9e0281997d9fc7743f916e64f8e8bc04cef0623bf2386a9315e47f93fc75f6e57a79d8ee08782be39937841133611" },
                { "gu-IN", "55cc26a7c73e85b05cb09dcfc3a14f15a7a3f2ddb8cde35547b5cb522ce6e104112850ee69f31c9217719558ab9bf3298234892785c93cc79c0fab12c47fc1a6" },
                { "he", "eaaf28d7868f796f5caf7488cd51c58bb68094fdd4fefc7c604fd388e17ec4ee2f2c3067b1d7d36d1e5da90343cabf9bb227813ae833310e25de473f78d864ab" },
                { "hi-IN", "698f9fada644db24ea62ace1ca05cdd50d0ac826dc0b5d6bec33253e0f07e72000b5013b06c6253b2aa86076e2b8938077faf7631ed3b9e850ec9c43685579af" },
                { "hr", "844db4351972ee3297fce2a01be10572b9affd695db4b4b77b05709920ddb756f4a169b27f77c863b748fc3de1811d12eb0f37d2e081ba99772fb0386dde19bc" },
                { "hsb", "9e0d8189a8cac6af7f30eaed9d13611ea28f8ce899c96b78efd25baa105947fb9f30a17b57c0096661d65465c12c9e29bf9fa37644a73b39f1d7627bb087c3be" },
                { "hu", "9d81d0ec8ebdfeadce52d9f0891d17ea7c3257bab3fa0f86da9b6d03f48fb4683dd010bbb40914a8f9bd64bf1f1caadc1713e5bfb8d05894aa527e146a27a334" },
                { "hy-AM", "3bc12e4ba39bcd6b1a615f9741e95411af822c1f9cb1c56f5cdd60ff9eba606d4214efcb9739bef67bee69601bf6196f4c4c42ec3ea785575641c0919bb72440" },
                { "ia", "5dcd4ca99f08583569012d128cd27e1e1a39ac501dcd8dc520e597c6a040b703c0323e1444f85a0805a0dca160e41b1194ea74a4942503a0154bcf455697d7da" },
                { "id", "3f2a6dc1c9528cab3cacefe0f6f525a9e7ecb2ad16c86ce8bc62bdc8c02d2bd1e72b7be516c24703da84876ac586bcfcf759ed2809ca2bc006c40541ff8d2271" },
                { "is", "58504582c0bf8562a2f51cf53f0385d5af757e11137be4d4214f61b6d836354cbe2371d0d97dfe8fd60972098927d4f91297e84a6bf44cca231e4ba473b86501" },
                { "it", "ef1f94f2849248b0abc37176eddf95c8cd6df9db466652950212925d8f513cfd9f532de04ae7f2a2377e669423f156108e45dafc1304de4b6358dedff36f31ba" },
                { "ja", "7b18f8328ac302486010042e96d7f5bb3560a85edb80c925063cf8022d7223679e171b0dd28666f4cb2d849f3477de535df1d5a13f5a7e0d5d26607e8dc2e738" },
                { "ka", "4f8fadf98fbebbc164f6f8ba631af6c09073d0ce2daeb60b1d33a141bc9cc22fc37e056af09c03df4a8548b4a715839e6c8be73eb74b400687be44342458eb65" },
                { "kab", "7a45ba90ad4d7fbc82b59e456e01c12d49a1edb64c65467b765de973585e53df739fa73dfa6ce256171cc8696c15bf9d3f64bdceb3bd56554139ed6e104d8a2e" },
                { "kk", "61be8417f3c189f73daf781373e8c699131578008b19b81c81b31ec4d74b4f1f777d593b5cab8735bb2ef5c46ab672f83eee0bc8a581d323b1ab50448c06c9af" },
                { "km", "346547516eed5fd13381803effa5ea9d085c1b2c20cc06dd6f96deaababb61ebf9cf5d58adad818eedf01ee0fbe76509b31762d347672281c7c7a44b043053cc" },
                { "kn", "cd3f6e855417233532c54538da91417524c045a247fa02050c0f72266376dacdabb17b21c37b679af38b48aa010f2814d9ae3f0905b998bd4ca40e34b52a5dfa" },
                { "ko", "44915bbd76dacd26745c860c85bda1b271192caa1db84f856d63211a3003fa98232c76e6c343b1afe30515f49ba43105776b97cae5ccb88bd33f231bb6159977" },
                { "lij", "0d011311db381bc2159c20af430360a8999b5fc2ea65cad1cab85ce19606887185b0901e05ad5af324d1b144228b9a066f69ae880ab989a6c9a2b1ba38eb1b1f" },
                { "lt", "4661918b0c14dfe07a02d333408ddef492dec6933f510e3905cfd9df0312900124c956d5e8f1a80fe5aca448d5b8c5d89141457a51add54163eabd8d0ee48249" },
                { "lv", "69c360c0861fbfc945affd6fbcf0fe417b6f2f6b16ac39a9ad19ce72b6039b7dfb2ac278022d8631d8e5b5f9769d1df48da0e9199fa68acebfdf2a2efaad3766" },
                { "mk", "994a27776be3f92b7d0c5e740c445d86d58108c788411fb831c7af93ef7b887664d96e07b041a8518620be2114712812901964cbcee6cb66a709fcbfe895ccfe" },
                { "mr", "993ea3e1080eda52fd7757ea8d66527841222b8764b1b9348ff84dc70a8422e6837278c4a30eb03ab6da97ead68f7a8c3e95cba3f2dd619349504f742859d5e6" },
                { "ms", "63543a14575772b157e2efbb8c930a8cc84d8d59a2823b59ac30a3ca241ed0d1d0e9143459cad7e23dca3d004a3e45cd18d0e9933f0d02b36dcab5aae894b06b" },
                { "my", "c68f7a7eb106376ab4ad7127e08b9eeeece337a19bfee40cebd64bd10a1e0cfe246b28b01977da4e62a10657f352beb74705da733acc0486308eb0a2c0fa6a98" },
                { "nb-NO", "7cffd6f02903ea487471422b034a9aee731b509074e3a3ac913263088a13000d71a0b41d49f2a21d70c9d42c1893cf20a4eba033e36fc01953970c04a0cf9f22" },
                { "ne-NP", "b4efd36d4e3d6443246d483c469d8bb9a92fddfd0838d1f2b6dcf75eaa2dfd43ef3129fdc3b260283c8f1db9c568752e66db34bbdbb19dd41d19d5d526aba866" },
                { "nl", "38cb97e5a1268f58bdc78a44582e9f60660211b01b27536f81578b24a8de72178fd1eb80f9376b2dabdcb9058e7b7912d61ef404fff98a4b263d98da0f13118c" },
                { "nn-NO", "e3830747e5d825f8d7832aed8fd93547fb959f97518e376fff946ccaedc99dbab5ee9ef13b21185768572bc9dcb5643c3a70699e185ed7fd61e8cdd2863157ad" },
                { "oc", "7729c1356741c62f47ec2dc521a197b3923ce28c61d5b2d8d1a708de64cc5498feb5d76489331ba60da9cf4066e4a43da3f982a8e4e96feb8a6021ca2a12cf47" },
                { "pa-IN", "f6dc4331e44d6de78d409a535b000479eee90fdb116991b2c5e0ff20b59407e258bb7c8679994a8cb6843ed19a52d5f8ff47985b01b1384a1155856344495c23" },
                { "pl", "36af397393f97d1ea0831c2fb1f0be395c6fbc5fffce0ff91bf6de0ebe98cdb878d620935da4ab6800c22dffc6f8222299b994b9c218ce3836263fa105258a06" },
                { "pt-BR", "1db7afee74c22996d38214c7a15056c520806ad954f4b2eb8203f3f9b8537c550da88e1bac287a2bcdcbdeaaf50132bcb234413a9e65b06f1de72d008351bb7e" },
                { "pt-PT", "7b13b2c22b026c426bd1dfcf6051c655418ae075151d57f5f24bc483a6ad50f1f622b449c175bd869a0fadff1c22436a23bc3c9248569d6c5ece5cfba409e66c" },
                { "rm", "281b10ccbb746f76396f3d20d61be1783ec466ff2e080553092318080739722930f097b266f49b5d0b4881fd35c3472fafab5e558878ef98d244877a3832b276" },
                { "ro", "f709052b92f8d00c26897b7b652c22e918107a9ce9b452724c279442ac6faf0513d899305c81166aa1b12f9ff4fec46a09bb1cdbf63b6e322de8edbc4dbf1771" },
                { "ru", "db603180e664c085385dbc4f3b552063f7e36901db890b142f81b7d1dd016ef79063b6b8532bafb3d8998fbcb846c02fcafd459c6b3cd2e07bc6837fa1dc510a" },
                { "sat", "04d3f29a7090a874f4c0e3115e1639c84e571f130599360a86ab78bc05a6f64e38a2d9584bf69803ba7d931e33c27c2e2b8ad1a2457c805a24dc01d2cd4590b4" },
                { "sc", "4bdf5c4b3ce86991845104fe60bd5e7b5c8ea5988f711e044133f3fb62bb3872b6f94db1001ec45b9b0bc0c66ef26a506bdb4b06d27f9bc4a407721d5407d5b2" },
                { "sco", "f2f124aa8854cdcecef2325c67a383ea1f8abcfd3b174c5113d4cecfc38a91b097f6164819a88c476f39ef4de8b05568f5c0f810f7c2836af2073b8b82a9f8fb" },
                { "si", "6803b9996846038f8f0220ec91e3ca744630a17b65159372d428a532267d72fac7b27c65e419e6a007ea88ad0c0cb5534be4d58f1a188d12c1627793463fe5f4" },
                { "sk", "34267689015e7413ce79a73d5f88efc3887c0f51ab5d737184d1915ee72151322b33ad111786e30a1f9bc6d432e9e8a70268b81ff4184e1f8e1de98fd3c7c574" },
                { "skr", "570b3147fd32243747aa40edc517b99f59b38d42c697b56e0ade35aaf682aea3ccf7c59a2136990db82c095878f15bf0a0105faeb2d60772e9129e9dcb9cb248" },
                { "sl", "979abf4e84614d01515783398b3fa566b888a8e2d680f455cd80bd38ea312a7a6f6402cf1870c16e8bee76c40a27a1d478ecd498f189803260395bbe9a5e3a9c" },
                { "son", "5b792d5a43f2789bacefb75f8bbdd38b9ae832f58927aed189f00a5bf8498fb80cb5890b24250e77a94005108a19d435284696a358b53dab4b27d62fa2ddbd99" },
                { "sq", "e76a45798413c94954c8f25340ce95f6b5a995cad2fea1d09ddfbb79c14473dd34535985a3d0c2bf15d85d345c480c9e4d2e6cf32a9556a760e71793c97cc784" },
                { "sr", "2be1d7312ce1444237db090d73dd30eba25a9d33e3c121ac743a60994bbffc39a74a57d4ed9b11bbc05f18e5815dc64f54dd48eef465819f6780b123a5d2dcc8" },
                { "sv-SE", "0f234fd3285bb9320c011152a2d06038595e99ebece93d81c1478a60b26bbdb3a52bbe586de2c6c9a3c1f296881c99d1c6bc90473efead857333a327c08f306f" },
                { "szl", "0e01ec18a384e788a47422341e00c4c1e23b0a8ae5bd9b46448c4ff9af33b13c9e27ef5a69d325f294f718c3a7d70f90d4f25451d2ce24979b23c30ba09aef30" },
                { "ta", "148c10fea84c414d49787d2258bf35178853a5b2845b239412d875e5d6b460ef6f755800875d9f6ae23d0b0725dc3993c6b11998b67291e161d6a0d1acba305a" },
                { "te", "34293d089fea3daf72d19e36c991d0e24b7196394989a7a6714ef6cfc91a0e5614a3898737a11d5d16cbfe2713f6febe2a7dfb7b34f71452497cfa8e4d4215cd" },
                { "tg", "432f15d08279b248d9bf5ef86a7b1b99624093375cae6a9c1cc7be4daa4c46bc8639adac5b05ca8b371ee8db0c8933b1206915a4a58549609d0125b34d33cb97" },
                { "th", "093f575bff0189f7331ddd21b6a52b4c6238e676e0b1d5d2e92cfab271c50ba400f07e2b9cf2b31b7ca6492f853bcad55ab6ff8ee01ffa5e384e74109025f8d5" },
                { "tl", "a1c503aa032415ccf446e4a39314f860cf89e5388dccb76d3a549f2ffeba210d1491603a8281849082f2e563fdac19179faa77b0ef613cf9dba8998f8a847119" },
                { "tr", "1f0742404a040d9e4ae42d02e811025bcec976304f6520bf36d545dc55483e6abe4f51d2b625330bbf02c86673c828d33dcfede26bdbb2c28f751f7e970d93c3" },
                { "trs", "f176d868156de1b263aa1f85ef0ee2343ae1efe18c6953f7ce826a5e3b6aa564ed614ef6638a815d267caa4e545e22aba657d4dcc5f42553fe4dc600b6e4a776" },
                { "uk", "4251afc3c1e67bbde74bd1eac13b7dede9780cbb77a68f4621ee043101f0704a7d7e23824219e4cfcfde2492d8b32784ce2abf64437188b4d215f2c9d0d51cde" },
                { "ur", "bd7a50be5792120ea61880337600fae30d8d17cfc48a833abf763445323c15e46454eb246e5eb08ff3e20ebc68ced99a72a82e1a86d0155bfe912600b974a949" },
                { "uz", "26c40d663b83dbb19d0a3b9bd6953d7c5a5854f7dae8376f7150778ed63ff6408f0f6c5fc1246ecb01078eab236d42c6bd92da41dd1b46cdd8bc5dd27ef8e089" },
                { "vi", "bf629e41d68ea5db4c1bf395b16f5dff95aaa2718c83e0f01a37b2663bc17af7329cc1dab8569f0a0e1da3be336ce26d13544364e5d3a51d0662d39f7866a022" },
                { "xh", "7230d1771e60bc0592e2e06191368bd825274e5cb9bce0b21dc53bdd2f286cacf1dd29d3c813a418c0d8185343ccade4aac6bb2ffe0cf27bd18e613011690288" },
                { "zh-CN", "54e09cbe286566dad952db26b27e73d9e0db80b0a54d723cee06a21f7a5992a00c28577d3a75b78ffee9f1e9b545edb12b4b2c221228ab66dfdc483ac1ef56b2" },
                { "zh-TW", "c0e72dfa35aafd412c1876e6b596768a04f9544b7ec848c87b1b8bb263d9a2f527754521dcd23afd9e83e0d2e5a3d86aa51aca37d96cb270ee0ae7f3b513fbbc" }
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
