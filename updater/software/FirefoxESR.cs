/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string knownVersion = "140.10.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "e0d02fd537c9a3860f011441a5beeeab327e268cb0e237bccd87bed1ce947655c45ce63dc838c8b5cb897476da4f167d689508701dcb72e2c85ed8d7a6448a70" },
                { "af", "022777f199e4968749611a1bf6f095bcb387731ec2557ff5a5a8b89704f86f7f4cee0d4affa8481ada6e940e8327ce5460316a3d5c5e4dcb9c0be1881c4a98f8" },
                { "an", "ce3892e28a70c040c1aaeba3d1976468821991aba96dafe4ce9dc4ebd3c19c708e9355f3f4e2ae39f797d322b4868462b2a6849c3f866a3321396bfae08b144b" },
                { "ar", "08e8b6565a064cf23026d02253c3f2688b01914497bde86dc201bd3006f6513eeb38517d1aba5ef2e7b4b1b46a2ffd43630b9e481daca9e66bba43805bab2cc8" },
                { "ast", "f0db3e1146171ab85ee548e9da5846739a5220030186a9e57487f9eea9bef3e3870f6b9a400bd36ffacc5015e16204d93aa72aea357fa3cadeeb4956035db954" },
                { "az", "0ed1e80959cf4e151ccb82a1d88cc03e597bdeaa83cefc925af64180f2fcae34c17c52abd5c053bb63fc44f1ffef75f5b24dd19a86ba3f3705f5879c931ad1be" },
                { "be", "7f16996cfb72463286de2e5e1473ba78ecd03ec4e1c1896b2e05ed1ed1cb527bfef35f0faf83fcb5f079bada936a7aaf48f87dd7a5c845a35e588b1dfa7d03cc" },
                { "bg", "f7319172f0b00fbf77506de4909e939dfc2efe296b3f8d9c2e1e67dcdcf1e32476af4c2970d8bbd3ce159281720e61b8eb2ba53f7161540988061fe1acd9f67e" },
                { "bn", "c524afd7873ab5b705de3ba471ef6300ea774c0f74cfb951755d28e6a235e8f34d70d363fe7ad07d0f7b6cb13e663e87b2c98854ca25ddb50a8b5575268fa37e" },
                { "br", "76e21355b3bca1e2e7efa3ea08780e57a4dbbb2dbe6aae248e45a41e82e20d855ba0a1ddd71b3453574cbe2e3efb4e1cbb65fd9ae15b52d42ce8d8edf004ca3b" },
                { "bs", "f4b995b52375f3d1eff97322594e0d240fb7b93654fba1e457f0d0c4efd5616705a49d785e72b2aa35468ef1c2b35869fd7bfae505dabe8b48b63b68b3dfab72" },
                { "ca", "57ff8fb6996629f06f2de04090ea626ece9c6713e1f4f29d40f1667903abff21998e7582bd4eaa909fe70696493c795bc1110fca371f89096cc189f03f4381ff" },
                { "cak", "4cf15227d23d218e97673bc9fcb388e1a44c06a9ae6d8dfa672ad6ecb82f9ebdfb7e1ed9fdac0c6b36cf2167fe66f3099a0fc3e9dd221c44f00db2a461e43e05" },
                { "cs", "36c5a9623fb1d6719ac7b165fd465cf42868e858e55cd6a9875022f5a1791edf3256375478bab105f7f404ba2b3915cb4666af4c27010d341fdf7cabcd4409a7" },
                { "cy", "84bce61c295e40e54cad7afa7687035852805b4eeb4e9fe1827f8088a9574fcb35150fdb255a57b4106de32a6f43c941dbe0fa61f1173b53f03ed561629b5643" },
                { "da", "0d870fbf4962da9ba11680691250037784fd69dde2f2c46cf22ed1484d7bcd171c0cf70f3b837e2dec8b136553dff3a3fe10b138751a1992984e8dd145348f8b" },
                { "de", "97874ac7c8f56316d1c4e6768dee8e03f557895089594efc81252d4ac5b61ed28f8e0d9a505603218e68bd4b413ee03fb580c67d1c1126344ccf39a36f92675f" },
                { "dsb", "a4725082c057fa4473e2bc42007729ff0e387c5396d10b5dfc693eb7d90fd86838eda0c42f3008e07fd7e8a43eb06a031b1da9b55a3e4ada41062cccb47a4983" },
                { "el", "13eaebd387403dd7383cf302f224691953e054ef9445405df8afe43956efb27dbe43fa934eb8d3470e34b582f4902280bc298ab0ac3f55383bd8b12251b1f882" },
                { "en-CA", "e0ea1cce0f9100c298bf963857b75d888da2e0956bd55a5926550acdc74868532390699d49328644186a60cb18f954647aa948665383b630bd1a259b3fd5a8f3" },
                { "en-GB", "7c84ebf0f1d2c0037fd9ca99a3384389877d5c044ff30b22982370fabf9af855869be1e48a6fc9f1a7120a4e3aed88d644908a9c640565249cee7bb76470e694" },
                { "en-US", "f63c764abe7fb5fbfdc1c38debd6496c21cbaff06da4a5a011c6b89d08419aede8b77f6d5e7d6ef4207e635b39ed9069341b9f4032970b7a5244a393e3d2902b" },
                { "eo", "2292c3821b0029fa9bf95ee95bcc4f0f9712543e04b36dbef75bb02ca481556ab93e2819fd9a4ab9d541b45df98b786f0bb2a60036abe4773dcd2dd3b2450fe2" },
                { "es-AR", "3c27612604278c16ad672b87a236609b60a952fe30a482c9c1b0ab1e1c8e1eb1d30c1711d10d28a8cec22d3da70a3ecd532bbaa79a355ef10c6701d0c57d925d" },
                { "es-CL", "ca65820547cb223621eb6fce48faa47e5e5ff367f64351925b206ae310281c9892ae07087e526541d28ad0a2a35273e2f1a6dbd78a3857fe8db53785fc526595" },
                { "es-ES", "801bc2844a82be2b2234adeb0ea26f0e6e259d796126bccdad1720fa3bc872bfc8ca43be041d913d139b5c5dea0ad0447528898812568477a08b1ec5038c47ea" },
                { "es-MX", "3493dda6a55e18c9e4f826fb0f4de5e90facc876c64cdb0f168fc9d2ba786af9a6e2e871b03dc537bde7ee65dac05cb7c9babe125cf9bc704a441f26864dce8a" },
                { "et", "712875da4e4dbe85afe91ef814f5ae32bc013bc0a720df24ea6e9134e6c27c83bcc8a2ee4b3aa7d385b84892c477c8f576524090e112ef7993fbe6b25fd29861" },
                { "eu", "a5bdccf51d7213b1bd841cebe8fb48f11a1e4a44ea62a29f2ccc4b4e0f31b71d047a4e81eeef455e1fed40f8db6364dd9d97eb2e3d81feba6bc6fb5a1178e62e" },
                { "fa", "b4fe9e304f31f82622949cefe49b593523ec2f873188172d8d789ab72576e5afe8ed65305e1b9fd62b4a06737682656b0738d03fce1b0dc81b50e70034541891" },
                { "ff", "9a81ddab961ab9547110d145804e7e0aa4e6abcc5dcf73c223667c1816cb95d716555c54f8e1f48b7eea1af7d3a7315025bc624503e40efb3ea5486b5a79252b" },
                { "fi", "9f2bda4c1e1d2e6f207370bf80dd4c3332c33a5f8f5034ba3c8833a96cc73bc491d827bb91284cbcf87e29e39235eb981b2d906f10addcb0730ee919451b1fec" },
                { "fr", "9d3ecd874c06d42371cab0eb39486bfc3b51640e41cb43b9ff8847504b0c47b49b9d6582cb5ecf690933074bc6fa385a74ac33c054ce3331fe119e1f192f62e8" },
                { "fur", "f20d757d868eae48fc18b15405a457206c04ff3bda2ed1f47c74bb9eab1f710f1fc95738a57f6a2b2fe9dc937371dcad287c1e4e8f5ab46a0be4657f0037729d" },
                { "fy-NL", "16513ca1af892f7439822ff5b4782a968705a7e22bb0669b583a6af6b6cba582be793a1253590e202452d7ccddc5881e475db8bb04cfbc67272be9cad8a2db6d" },
                { "ga-IE", "8745e8391986c09b3ae06374a7cdc8422bf78dd0946c7bd70e0e9106609add06ea7bcdb9cf7ac664b908977e697b70d0f65318e4006e16d0e5c0d8bf9a56000a" },
                { "gd", "96f02bd3b2dbeb3108c7d95b32d9ffe3176c565f2dfe7c05cf0137c5e13b18985b83e1c55498b472c055069b1c582aa41123256f7cb11dad83f0fbe717b2f2e7" },
                { "gl", "a91d8bb3dd30cc6186d1d3b0923ed40a03a6b53c857db36878cc11d6802c221975da68eb831423a9a28bb310b803cc7f39c7ff1f0b4d460620a948f79da146d4" },
                { "gn", "1b621ed0f33d0ffb202c996bf37af625d0d7e2a139fa4fb2e9d5d79a0465a2ccd2d24000b0707dd941c7b38d603e19cfa2b2d60ecc222e458e00d1b091017f31" },
                { "gu-IN", "f5a1ffa1a40ab14f1fe4839a290c745594c6983b511fc809e6f39666174da426af069a8466335dfbfa90d5b835ef4bd6587a74ac4f08dee3e4a7978cee205540" },
                { "he", "bce4dba07ff16c9fb29d0c2347ce936a705691a1106155da0340c78d1a1d8b9215c387f3eca0ed8809bd70cd6bc8048fc6e100ad964ae44aab0ad72218693782" },
                { "hi-IN", "e5cf389e9fd7e8ae24fc82138c23ac727d095afd25eb3bc8f0e5c1d2c7d90e52c6be6905a4c289f2def9488566a5a2f65857bd666dcef7ecc3a9d619e71369c5" },
                { "hr", "a7ceb3e36ec7afd7043b2ce5fe0c9bdb761564d640d015da9a343504e7ac3d60be8bd0f423b98074cd3296cc0114b1bf029fcd788f6ec2718081955e71da446c" },
                { "hsb", "522f6c4ac001fb2d9433a6a823d86b2def3d4df956a1466dbfae245269029ae47c456149702477d5fa63240e4916f8878364705c10a8423cef5e8233e080c397" },
                { "hu", "7bd32a7d1dfb8bba617e57ede5c6e489a8685a81e998e87568857e5ec59d45564c0b220005284030bea362681d9232e2e27481bebdad2e600ac996fb0a0ef5fa" },
                { "hy-AM", "f22b5c361e0de03bcdda2fca288c7d0241f1ab27c5eefe1f2cdf952daba42aadb99606835ce2fd634477105736cd1c757cbae1cd137825e943cee618a0338b56" },
                { "ia", "3e15fe95e4acd0e62a589674240075e604908c87877618b5b960aca1c23fd6e9d87d1e707b0ec32b6bc68366ebc820d09ca29cfee0e5c349baea63e50438e90d" },
                { "id", "e4ea118be248b8d1dc845b65eca3a9b324b04ed1c8ccd742db80e1e0d7f34c1a2f31bb2576566e654fdb79e60b54180eff27c7a8bf8137b6bdabb1d63da65dd8" },
                { "is", "5e12772cdf5d8fcead8eb14be1883422ada383e4ee0ccc767517bba530397d4124d6eb7277ccc9be86838870386b60c6591e470eaedd97d2d760c6ad580c1daf" },
                { "it", "08f2b1bcfb0a0aba458225e08eeca090f60ce1346ac8b9ca25e579cfbe5ddeab90782768e1843a8a1810c6e68d9558725a2281e17a8512431f1a7c62ad373ef0" },
                { "ja", "f506787e5eb615dfd1ae9d83fedd3dc267a9507dba10bc57acfc63c90ffe3386e943c75b0a01f9b487860ac63fe653de667f362123a46418c563d66fc8f63674" },
                { "ka", "08e1b8f08bbed0693dd19ea627649a715876eb3c7efd31da1bb544da8e0230a0ff6ee9fa06ea60d408289f137b1c7e7c64045e4c4da7ffb1b85b641a70184a27" },
                { "kab", "dd1ecf276b951172f75381905790ac8094372e65249926290f808348ac6e2f76e45bc021bd771d1ba4b4647818f28d77009d0627e145eebf4fc46716574e1902" },
                { "kk", "516ddea37a9d4c785c6714b44f1949ef0eb3420e0be90c654bc4add88b06c5f92db591677f858a888a79e8db62ce711e3f9a050812493092d1a0465e19a52f37" },
                { "km", "9c117e0c9f5cd1985ee2a78541047d1f908f6b5bec0d9a24bf3ef74861fc6cda89b9eaaef5907f327752e041799e5a2f869c1850c8b7663c25148f0308902871" },
                { "kn", "9dacfbbfdac2bac7e364fe43a4b2a66b0f315e733623f03cb57c36806b13c35711c783ed309141bd1f460984779d01246076c191d6f316b65f4b93e9ff904b1a" },
                { "ko", "b5c5cf52f94c63ba94c73ac07baf7acbc23ec20b9a1059c47fe423a5c74488aa34761f00b70247bbb7e51ef90617fda93ec719300c779a0381eccfb1157d062b" },
                { "lij", "dc80f083d9e5e2d842cbe5131d4f5a1fa707b6a6921e41c4ac9a59bac1caa325e2b87cf57bc701184dcfdff6e7fdcc50c4345616f27e275761b28dcb48ae92f1" },
                { "lt", "7a4101152f97737fa6db7d4d94feb5204631bd795351f6ebcb16123813136a11455255acfd469afbde5855f35d8689b94dc5723c0c1547f23bb708c96b09c57c" },
                { "lv", "f71562b183135f834014c1600971e670c92677bf846bc56960fb777baff4d182c5a5b82cca6153296b59b24d66c2b11145cb076082577ce4f8a05cdeb6dbae75" },
                { "mk", "470cf5f3946226c59730309f5deb244944d9c47ff4079d49c361b4155a5a9316eb9bc638ec361e1b6b8ecb30f7ae803af78319ff5bdac1aac8120a144e65dd85" },
                { "mr", "b9286cffa91fcaeef8537c4e1df2283893cd1d6f6b4c0b9ac498799cc60aa7082475fd43c706963d601b30797386454d360b1ba93969aea7c5155d2fb5332642" },
                { "ms", "fc0992c2c440faaf38f2922f1125db6e2273a53f05a065b4c561d3bc25242e4df61bb32c1490f3314c84888d03f5b54c135f95b278f623d41266cb8cb265f334" },
                { "my", "ff964e9ce651c598f30ee3939b46acaac48b580a25424c43572f5d46ce55c295fad3850649b39fb4a3d8de142ed812263b11bdd3e959b18d69478050f40bc4cf" },
                { "nb-NO", "728b5b7bbaa12992532a8a1f37cccea8750be4a3d85569ea5256757f440e5d40e544f4ff8d8c850d7caefc81a797dc315647d7d94a3417839ad4fbad0e870def" },
                { "ne-NP", "e6353063399a178a4ed9915c65a9855400cf5d060f6bc1fa6a9ae9842822c41ef051c2c35ff4f48e5efc9103a0836f3682a8c39e11d84bb2448074f1589fafa4" },
                { "nl", "e19eb6b350f4d7328570fa459e4ca014433cf5f07144bdaf8e673f98d1124ebc4b2ebdeafe4fc7e6d7e6315df473efb111b2a2768caf8fd9818db5d63e75757a" },
                { "nn-NO", "9cc2af94e0fb758edaa1855a893489f0bbed534d5d4b7b17d94895b8a94ee1fee44a9ad9c7bcb6c37a223baa47bf019dfb86cec7fe15874fcfc688676c9478d4" },
                { "oc", "fc58e869232dcdf8b9a4a4fa69ffe262ad8494cc14c9da1cf528e551f2b4e98790aba2c416a583d50f36f94a5cc0a7609e520da0a2e08d3e767597c9ae96cc08" },
                { "pa-IN", "9a49fa46d35cd3e67c450e7477bca52980f838bd61a8ca51ccf5f1e409a82f62767c6deafe3abc84bde08b562a19db01439affa3cad71d2bb5140cfe479b2977" },
                { "pl", "e0620419435d83c111fed132a0a63efb1d6e4a716591cfab2107a47b63d20813e2be56307f9816cb80bda605f0f1fcc3b4113941465c7a287ef7b717f24d8f87" },
                { "pt-BR", "d1673adba24e33bc18ad0374666ce7ef0409ae90dde1265f344b4937ad9eb70f14e20541429684fa29ca61077cecd36035d78db15976938c1727d73c66198831" },
                { "pt-PT", "ffa83b92323986177323eeeee99c04a948b8c30ff7bf77c3ca742d17583a82637d0fb1d4ae7abc41ca798e29e5999f0e406b512b4576b39cbb06dcaef3fb8f3b" },
                { "rm", "fd58df8b9752a6eda532ca32c5de0e5b88ec91dc08861a0b588ff5ec5808b8b5fd7d5e0e986cad6535eb978fa49142dda9777eece5349938da8c765dcdc0d6fe" },
                { "ro", "f9ff48f9b48c0b5aeb2446ed7e464215a3d94bd1411f3080be1fab9791575c54e2328652b11b60acefa3257e9dc76795cd0908df0bd2c31d6948d041abad11c0" },
                { "ru", "29f39074e99b68022956d43c7e8df3af01470f2b3a64336ed480282eeedf2a50e8029e38c61e15416776a903aae9d91f546d91d535f1b1bf291f836eb052e38c" },
                { "sat", "064cef08c9e9d307e52870acc899e5491d4d2caf75675242ec1cc624777a837a5d6beb86ec1f760f13031e8845b1c5202758a98922574012f01138a6bfae9bd1" },
                { "sc", "f337b0cdeefaec43e2f05c491376c9f8c9c98a526c6314706d325f81a69c2dcd5b73e28bfe6800069c0ce93dc9c4e261cec29759907d9f455f242eb02d0ae31a" },
                { "sco", "5ada500d717f67f2601712a9bf8d9134304e4eea00028e5d2f094f9bbd54900073594ef95564227b0b8c13f424b0c33fb7752a3668578af588499a8febb004e6" },
                { "si", "363ddf831f3d0672a875b829871ecad2b982e07402e0333d4d9331b86a9d58e897622819a2a439b8c0db1058ca754a29613c8a3e2d12027cfda83fa08c6654f9" },
                { "sk", "397df8def2b1e1f1da971802776d01b0fb84880593733706a5e0cbcb4f01aac484567b07fe73663e1719f68357b0b12d3394e2d3aefc530509a21195a1e368b9" },
                { "skr", "b7e92b52d2d359f741c35d65b2229899a5fc48d3f3667ef3f9c6501c775cbfb5c1494ec7fe3dd06029a083e4536429c127d9fbb7f9f26a9da4a553c933d17e41" },
                { "sl", "f76a85710372f12f06a9c0331bf30f02f0e272ef0ead9b8d137581a53def8066d07ef4864072865f8348a0ebb09a52727dee51a27e146d1ba322d702be15964f" },
                { "son", "794232ab3879c95dc9b3f79f7fc5253900aef271a960cabb1a6cc45a0b3d54bc13db9827ce999decfd635583a88016bf42d093c469fee5b5450dee8b0e024b4e" },
                { "sq", "3283f2550cf081cddb9032eb3623e202e8ed2a5f0f7617f529ebe019f88a484ab36d6cba80b999d056cc17ee89f3e5ea8b58c991b968efc3553d04631a698fc1" },
                { "sr", "856836d2d278ac598eec618dd81192c13d7410224d414825fa21acb3fddd43fedcd58ff30a27b7b9bd5726cb52dd63ec8b9c91a6696b665487d9e6f7d0cc87e6" },
                { "sv-SE", "406542cde7fc7705ea69f3c7e30b13b6bb3bb605697263c4beeb48495a0be1e133c351c211417da591c1850ea96bc46403bc280fad0d863cbfaa50458baac3a3" },
                { "szl", "bf66a315ecb2142ac35a121933e80d21a85da8746d57056cb9e54fb7dd29e08e4cd4c7e0ca1778c4565fbb2dc061eee0d3fea85732b49d65dbd0e65fae8cce0b" },
                { "ta", "76aea4e68f485c54417be8a97a2a53a71f1dc2c1ccf6ee6063f5b49f0710de743c1a6dcbd9b9ffbdb2d9f41afe1d37f8e96da7d66260667ca889721ee5eae15a" },
                { "te", "128a4b38d0a60b268d2f337641811f9271c02d165882cbf6ed2e34c230acc24aa25bda1cc9382bc3e640868912b9b19c3cf03fde85f1924cb1dbe51ee15fc798" },
                { "tg", "a54de01bd5b2aca66b16a85206df59c6368c19ff3475b622620aec85024e30d16a59be31ed3b3581427186b08980caf8ff02eb4007c18d44e2b05ab6a6b3c5ac" },
                { "th", "7454ea6c1507d158ce00349c1502cb481f60fc7ad1fd27dcb76cb1c95f6708e7e11221648fc318f64d25de53582e7601626a9dfd412f3ec63f041eeb64b814fe" },
                { "tl", "ca80c2c3a38df316128fd7674eb478fcdbf7926455161ebebe9643975f8ea13a61b6eb98d886237e29f7756fc9ce35f98f7beff5a7d819e05bd20f22dbffd2d3" },
                { "tr", "2488497340a115e26ba64d48763eef4613735d2b47bc54b16b2b50cefbe4f2d9637860a959c423348c268bdca70b935bd3722a3cea2b92864110411efe6792a1" },
                { "trs", "6dc9eff64d72794b46d0ee0695b39d02005b25f413c0b9bfea01f7c8a144c39b5f4669af995ce61bc0ebe5b43130e7f51625630d0c4b80d3a28920c56539b9bf" },
                { "uk", "1221d8b76fa3c091e8a7f8419bc6ef33455798c53e52824f80d9625fdf2df30c4050dab8e3cd57fddaf75f2ccae8a9fb344512765d0afc467456e690f9720b7a" },
                { "ur", "89cc0b794f9455f9451d4b5dc37e0cdf99ddacdd9886d05602349e6f345a432428231ca5031a0dfc46023f7972f01f84b9067d7e77e2cfaa830e8342fb167a43" },
                { "uz", "816a679fbea18029f8c7f370b048aa99ec95c0db9e27e71467fbd9bbb8de2a7f52f31cbf1019d5101d0e3e25864a901f9d07e489aa95f0a6182a9964195afc0e" },
                { "vi", "fc10f671c25772fcbdc546b126c8ac150fb6ac3dbc62bb5f30cf109f9b0986976e9668ee9ff6754357220969323da5a888f3d09a865e4e924fe689b862ab4d80" },
                { "xh", "fdbc40e302441f467672a91a17cde9742f1405807cbad93eaab7b565df7b6d8f60f222bcf45edcd07371220b075057475e282255db2a8e138a218b303bf8d485" },
                { "zh-CN", "b11f290ef9fc3b45d98573caf72f5183bcd73fd0e44d4b116014652b7394902c3331dd43032ae265668b6d63c7be5990a9e5777897d7f10b498a9dcff68a9c2b" },
                { "zh-TW", "ae2718cb24b8f5da1af08b1fec0263a93c9c3e050c662ad54479766ed17e9ecfd114ecc4b94353da3d9778d33d7d62a5d5fd8f31bd6b0c03f24a9afa9548a0ec" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.10.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6fbc66f89ccb3db704fdb7705a53cf920d17934b6b06ca53a6d405bf409c2fe1da1c0ebba345c853a054a3f8743e43a0e9d9566a611de1dd7054afde74521127" },
                { "af", "b1d78a3a08052a238c4561a06f3dc1699c7af869c926e0917679116d366eeec97d780ff0e954bb3e77bf2abf3dabaae529b6bef19c3fa4ed820059936fbe7f27" },
                { "an", "e179ca78156f17693931907f604f677c85603df45cad9a2295176e2ecc2c5c62f00893fa722acab9e043b17e86e002138fb4181bfddba43a036671ef857d8a2f" },
                { "ar", "c6fa557179f3141c627aacefb70c0e6f3b7200b3f9b10b2bbe8919cf037e6ae060b2dc26cceb78f08db10998519d60f84e84cfb849493738bfb9d5af837c9452" },
                { "ast", "126a6b84580143617e49b02bc03446668eebefa411e3782506dceb716ee0ccd8626c11d6679636c43df4a6019e93323309d5f9f2aa9e6038647c452fa18b8352" },
                { "az", "46fbb126b727bf252680d8355748a10e248c00400670f65c3f7db94ac4980c49af25118b18785c38daa3d73f3ae5085b954a588e29a285e438e549b9f9db446c" },
                { "be", "c4cc6c6b84236011edd2c09d99f1315dd4064ba7aa510bab6f03f02d55d5f124824dc37abf083c44e2baa7abe67eee9e75b06f3e6b3a95c177505673585d564d" },
                { "bg", "b0c4fdf3ea16c878918422b43333fbcc73590d0facc017707d90bd40646af4d8650b79418c4ad2b937121c444707afca4ea8072168bb9aa48b9361330e769455" },
                { "bn", "0cfbf0c4778218b8a68b7d86c863edf1b7891e35d169ce301d6fc65d6f1ee6b245e8072759f9413ca417a2a73a90c60689b9cc8ba56b567e5defbea98f146acd" },
                { "br", "e414cd77a89d7557e024880c4e70eb9b939ee5c90d2170bc30a8e083f77772c0458a9e6a1f24bb29a4e6be3c8dd1115eeb2aa2cefd14bfaeda6e0c403d0ca191" },
                { "bs", "65cd40b5503297dd7dfa63e98b6dc9ff37252d29857b828771657afe688fa5a4e34b87c76744eaad93eac505207317a3360413ae2ada6f3d6a86ef99ede3fc55" },
                { "ca", "761c8326313e416ee31b29d35e1ed1fb879ed57298e71dfe225b5f5570b0bae2d65340d6e1437b8d74a91705783ab7766432e207e944c1f2f52b37ee857832bf" },
                { "cak", "5209c5aa376a9b832bea4dc4a873e594b0f740571968df06efa0c95b9e429ff5b1584d325e2c8f343974b23e96421349fd1e78260e0a569d0a8e6cf9bcd5b35b" },
                { "cs", "1e299ecc9dc45ea42e2bea5cf93bed40f43ea43bdf8cd43c231fbf7d9745da4fef44c599536642b7f14b5a42bf9a79f7dd2253c7744eae0536cbfd7ad8ab7cd0" },
                { "cy", "05b4d05da7183f5d54c5c9c55a1329789fdee4009a276670dc15f6cd98a1070be6fc689fc85f8d419d6f6153a8fdca3dd975ad9cea868d4336268874f5616fb4" },
                { "da", "9b0720dab9ce91e68c836bb22f72513d490ff1a6d8152fd460065a20ab23960132fe691a74615927dc422be2e23a00fe7c478a614dfd5520e3c771b1d9be8825" },
                { "de", "08c58c069360bf507e4b8f34d3d57516951a319a6882f15670c936505b157a61b6091f05574c2fc5021390dbf63634573fd34c24f788b625fb53fae39e90205f" },
                { "dsb", "43ccd7b7925b9e8b49ccb6683e3eda74f0a094dab53084e8ee37ed5abac273fa475c10197b4f60e827fd95eab96ad7bfc0f0a152e1e6c4c73055ed895b4110b2" },
                { "el", "80be5cf2e74025b2290a4c4a425c4a61b2be4387c7d9c8fdbfdcaea5f8984799d8f08295b578805ed03c81f2ae3ec6cff516cedddf59f89fac1fd988256b94a1" },
                { "en-CA", "aba2846a83ee42f2a5e5d2412524133d0418b634ef80f8ce00428a42b631f7714c492fbdda3aa19ebaac7b4529c86740f75d90de585f68023e2dbff76d5e43a9" },
                { "en-GB", "56437ccb68701d51a548f7aabea571199314dd21365e1fde769820ffef61c0b6fdc5ec7260bd2288b57bd242a04e748a5ad7f4230d09d194d0f5b70df0803f5b" },
                { "en-US", "a6288af2b3d24004ae9100cbfa157c05eff4b330ab098e68427c66bc4d0b343044b66b89afb59077fa1687ab5c1296788837b2bc88e268e6b2ba46d83954a537" },
                { "eo", "487304956c711d9813c99540b5a1be4d1898258686857c16313e24261f00ba03cbe616325d3edee4898dc1b4257180398455b6fd71f9f3e981cf155faa679b39" },
                { "es-AR", "07442ea491e98754b9166db6a09686780a374f675b8a8c0fdd4812d687a7bdea3f0253241235ee2c4f38c68166f7ac15bcbd2bd92bcef0e5d9ae76a58a315bdd" },
                { "es-CL", "55e77fd8e6e6dafe1c3759d0da8d0f582de934782f7984f9e7eca679be470b2210d96298f9a0beaacc0cb59cb37df2ed429e51c6e05f6790fd8ec8e7bf81d6c5" },
                { "es-ES", "ee8e3f9a3c0d2f876633e77f07da3ab17b186481db319cf4adb784ffafd5e4e8630b4fe39811e09ff5e08a5f069f025d052cf81bde3f9a9d4d734466f75693aa" },
                { "es-MX", "f33e300331da8df4dc8870cf3b144a9a962418946ac0d418040084bc7e1f2bf071a931e75e9702553af84da5f9d7600e59564edae384b009bb4702a95b94d740" },
                { "et", "95f1405314694dac92b3f9239722701d19d92f3816cd0328cafbf9d6998c3beaa469f3d4670efe4776bd124b5f4aa9ed6fbb254134392fbf4d40a93959887563" },
                { "eu", "a8b04ff2c686d5c02a0dc18c3ddd318bb0b9a60b4f1802084a96ba79571f91e6fe2b81f0b27059e7ce82adc5dcee197a233a4ff2f28c5a3fd3a5e86265f20825" },
                { "fa", "bea346f5963ae3be463ab6626470c07390227fcd67f2f7bb8d8b038ccac3c3d87de9237b60cef13a53001c9f678bccb69dce17ee97c24ecccab4b068439e800c" },
                { "ff", "f38ebec6a645f97fcc795064cc4e9a4a3d79afbce8bc71be7e7e32aa675ffe30a5e8c1a8abd33595a94b2d6106d30cfbb029949b2d0931baf964b74497f66384" },
                { "fi", "af798baaf776ab444cdc3ab33d67ebe82acafda2e8a43f853d1d4231bc30f4e18cf892a3e0fafcda1686d60c84b9f28f73ce513ec25bc84fd5ee8022b495ba82" },
                { "fr", "e02a39bb36e96bda75a448083390faa2e3054d26ca4c9c05eb32b0ff27c5d989d0d177eb6d167bb8ed3c294ad3de9976d3c7f9c03cb0d394271fdf6675897d78" },
                { "fur", "453cc475e65d7619af5cd556896f7da156843e3da239575d673e046513649c0a11f31514ccf758ed1269bdd2b1ed14ddb00417e2315b4c1aaa37fde06e0db294" },
                { "fy-NL", "eeede8569df59274a0f1275fb251020083a119c26ed53961e66fd9357b064d838a0d15d3eee8a791f6167a71a425160f47790ca1014bdc289e00d93b70d401b0" },
                { "ga-IE", "6a67b16d436f40872cb2c4f828d7fce4ac59616de26337ac84800a14b589b272a0331ad9a9e68f730f836f128fdd51316bb6013372d63175097dbb37beb1f154" },
                { "gd", "85cd322d8c3e361a21d3806926b4f7512387e06ded263466d439d951265f4feb49096cd695cdd288aaf5520e57ff42b73d8619db3704bf02ac42e6131ca014e2" },
                { "gl", "113d631a2c9f7932a8ee3dee5cf769ca88c7f40b5c83f339dfc4a7a0089bd77bd17efe02906df25755a30aacfabf845c28af4c1629f16a5d9e18b8bbdecaee7f" },
                { "gn", "0521fb44746e3d8b0d2aff8c94ffcc314a19cc7c0f0c65f9c3836900c5185a85584a97b702eafab9e620b2b09f42a86c0d0a90354ed5143077a6be5586df0ebc" },
                { "gu-IN", "f1b68f7228ad02add2885e1862108655c04f51832a6eb0b6e784ef00267c72ee871da4ef4759821eb256a5f1b3f6db291399ba6a55f1055156ff1aa11275eaf4" },
                { "he", "483afd9486f646c3b5df69ef9129d60b4dead7d300ae855d5ed202b4a13b0a05c2b9bf3a62e71146bd9b5e102412da89dad9cdbf3b581c910a7b9433d48b0738" },
                { "hi-IN", "cc32f5d6dadbb5335fe6513bb9ce8cf8efa431c1b361fdc8dbde84b575a772d0e9f6b2cc48732aac29005c5fd487b21f3361c4752ecb9d62f6c3c9dcf005b2fb" },
                { "hr", "9ee882555591b2bb1d0a651c7fa86b77d2fc555e0ee6bcc88ff369bc1c145382388e0ba0984da71a82d743c3973d9fc944c3443e0bd49b0f0e8fd36b3fca7404" },
                { "hsb", "edbe1eb29166c043ed90fa25fb7917498029f818373daaca00467ef003a153112bbc7b31ade99237ffc6396b13bbee1eebc80b2b9b2db05f4759f53f033ba253" },
                { "hu", "b53e6f9b5bcb791bef8b50643f992dfb92fb32981ef03f7aee551bed8b8413a0f31d9df8d354da0f6fa096df0ce232227c27934a0cf28e516eb866d5cb706d1b" },
                { "hy-AM", "be41a6218b7aeb1949072dd801f9c8a957ce6c0db7cb7e7ebb95cbf04cb24e7e8b672a0a217b2d419fc70cd43869eec694a4345e23f85bdb39ae4aea05dfe9c5" },
                { "ia", "cdb6ea581e3ca2a5a04dc0d68aae46c8beef098b566aa17654864ac7ad98b2f1f723f1e2776934a659d4ed3747dea1a6ccbdc6e568bef88718fd312266ab00b1" },
                { "id", "8d5fde43e24f6e41ebe297fbd3bac601315fc2c0ffe531124cfac84da76367aaa4f0213087a0d2f1948d6068e58c2635d3612856a2a7a79979000013f5b17361" },
                { "is", "2198c8fd2c58ed17537bb915310778725a7a640b022bf2d77e3ce881ae2cc26941539cf0e04a0c9c2f5f8d7bffae876f0e80df714a8953ae6f9d772a65a185de" },
                { "it", "3dd5e7245948cf848ee72b181a882c5caf7f7de6505fcab90ae81de97ea465080a288a2648735cf9e97196f7859c00fed7b67133b08d4b346240f514298ff0b5" },
                { "ja", "89aaac1b16b47280248bec2a2cc558c215c1125d2c6c532c1f3fb9c8ca4d1c2eca12096b6bf1a96d558eb235e324b7d123576a007b6645c73badbdd53e2e2b2a" },
                { "ka", "57a174acce11c4169293ac2b31fe6c8ac7920a674a9c1a0ae39d8ccee64a5006d03895de5d317537f94703885d28db5fa16cf26f2375c456a82485190234d762" },
                { "kab", "8bf00cc76175f74fb65d5717c2879291e7a1bb976c90c8eb00c757fdeca4be124a0843125c2066c17f3a84a1aa24a05a88cd3a135acfdc81da6a23508ff8b9e3" },
                { "kk", "7bc5c795a773dcf0124e54a7dc284ec27013aacb552d4a7f2edeb36b9eab0ac60e984e317df8c500b60d71f4c3d658fa04951b79f7a6f508233699b83a25f071" },
                { "km", "8158d0038dee5595212df8f02b50d785571507f70001a33f3efa96f1ff76ecaa482669d54343470d9c7438ac2a051b0ff3bb54e2cbb3c9e71803385ff0976f3d" },
                { "kn", "babbec595bef47ec507866492d1169c03f82166488674c558c3457b1f73fab6097f10ec002b26e09cd8cdfc41e1cfef6af8b71fe2ea42d7d94889afca87ea0e1" },
                { "ko", "1a0d351ab8897113a378c72e0725ab758125388ca5dc8565d2c75095e5451bc9862f996c84887e818d7516355bf270de9eb0a7bf4d1df4d7fcba6b40a15f1f94" },
                { "lij", "ac5254111febb3ab8998611aee9aef498496196ddaf9fca00d3090f8f36b0d1976cd6ac207770966e12f633f513844d1e7c18a0775f0a3f059ee924b3ade494d" },
                { "lt", "a83d1276d8aa9795d3ce37fdc1c2dd8ca55e6b8c6c8c86e666fea75f23894e856561eb8bcbe62e1f4189deda876be2fed055d68fe5bccdcf118e7b6cbcb8c2a5" },
                { "lv", "93ec3af566292f328433f8dd29f0cb29af6984a0e0f5635a8603df602ea75a24ac7a819d2bd2c89c7e5ea1f95c8c40b8a0fd73d416b64a827ed747e5375d917c" },
                { "mk", "439b813c1b21edac36f04fb931b3ac8e3c23fde09e11acf4c16bca66eec5f163437b2d74ba5a44fbc92e00f85975c1b6c60fe4fd24c889e86ff3c3293228bc6b" },
                { "mr", "f4d0474336e2a6546bf0291900b20ed0f8c75958cc367a3530d36a4e163c2acfb0eedfb06eec5b693d4603b1252d8163d2bb77d150bdf39aea3195473d7ef104" },
                { "ms", "c4bc6cb7a298d2e7e5e4c32dc886d56baf80ac2c30c6deb3e95e5dfc14ee232d1e2b48943cc5ec538bdf861777ce6525b77c57e5c23bd309bfdccd8a44529dce" },
                { "my", "5cb362f324d783f1a456607695067ac4ca23a4e5e97dd682b47229f3a041089805fe74fde944b2b778a495c4c2d187cdd7f2333fe3bbc556b5204f4c191f4f70" },
                { "nb-NO", "6ded0e8b04ef0bdf14f7f2083e5abca9c25d9347b8dbaadd1e743c7368a6f9e47c36845397ccb1fc07275e07c0d2257d24ef2b94af4ae852c719760765983d01" },
                { "ne-NP", "0b7e3b4655722eab559bb4cbb127807a78138785645f3b22594995e48f4171be8f6dc230e4e70ae3b89ad14362df29bae777bedae88701cd4b8b2d495835c639" },
                { "nl", "dc6d2649cecbedce532551f1a1f1d626405afdd4b865440a9a47ae1ab3ca946be226a8c861b53faf5c9c93be02d05bca3e96e3dd59d8e469fa825162615efb9b" },
                { "nn-NO", "d86a5df043b9aa4b3a15b7647404d9ee94d32f4ad85ddf691f8e89015e95b3a6e58c4e2bf911f9dea8d1d44f05fc839eb9e62bf3f9778eab54a1645a4f972ae0" },
                { "oc", "30f0ad7dfceb749adf78d05f6c6423a9074df66c2dde5f619efa81afb39b9236404ce329070ea9000df2c9194f1d6879de41473012343ff5d844590ce55bcd67" },
                { "pa-IN", "5e8dff634628a120f349789d74b3946e204b38e27038c23bb8ce266d6e7d8431b9518bbcfd94f388986536d1fe8e417123a35b09ecbeaf5f80161eaa89195454" },
                { "pl", "1e28180aae9b8f3033a23ba7184a3dffba5a52427aeb59e2ef7248467e8e4784b354b26d1257d1ee5c12d59ea56c6b30a1615e487b4f8c921afd053e779e5347" },
                { "pt-BR", "2c34b8b487ba035ecb6b219059d187b423331a743a269fdf9ec566d4418a9a6eba54a0ece4296279558003b46f393ebeb42fb3cbb705a8e7a82bcc30778b2e3c" },
                { "pt-PT", "8eef327f5f215c6f32efe193aa1caa8e1a5e056aa0b6e208b36d5d64864681bf4f22eb439bce4d2cdeb70de3d1ed1705145b33d7e847aebed34a0b75b7870750" },
                { "rm", "92d3a73219cbf44f88a2a6446560f96bb2a21357b0a1d16fdb5491fb35fbc10131e790fc754f846647137d29d9c134ad613c6c8814ecc3adbc11c8e53d513dfb" },
                { "ro", "69aea305a9e81e9a3f8a6a1d82efad200eebdd1626116941fd3ba691329f11a25fe722fd454f719ca34c3532de3fe846f5477593d7cd97a4b8c2dcc875c4f5aa" },
                { "ru", "66e19480790ac493e2eac79c3cd8e065e7cceaaa68e75e4e95aab5b160fa9e2588a53ecdf19b85176e340e24f04486edb4f574ed9d81112ecfce96c9bd943ce7" },
                { "sat", "1e79cbe10dc733edff01b0627132798ee5c6907ffc9258b270836d0051cd2a3cd38406c3460c7498eabdf25dc610348131d1cce966cd0270fd06a75ba3b878a4" },
                { "sc", "01723c4c294126712e887fcd97cb4397e87208525d6531160abd71f8786f8c60989fe56ce7e57ff81f8a1d61c0a9d1eb1df5d1460696bff41c442092b9e72d97" },
                { "sco", "88cc582e45c9bbff5d69acff89e7302e102dcd404cdb3cec1c0316c741d67488b1aee5e5533e92697852b0bb61da463cf36b0be90b85b115d523e99bbb14427f" },
                { "si", "d1c35b362acd60c455d84045c9527e0e94047f14eb738c547a73564380dcfe2313d56e3a88409d7ce80563f826d22fe91ff03eb6dbd83777b500634a52bb94c1" },
                { "sk", "b47e313c790093f23a0e8d065ac8a7ee15031e00d830629679784d5bde39192af30adca1974cf6de124670ed4f43b901a32307d2d49a99c1194d9dd166efdda9" },
                { "skr", "d6b81fe21235c23c52a07131bb8194c3ef62636af59172b608544240547986f03bbfde3d8046b25748ca03cc90a2623510c60461abd1019df21b19069904136c" },
                { "sl", "40d7e5cff2da03354ec521005cfd29306aa1ae67a2abf3cc981d74eefac45617d1cb0e6d2355b06c6c03fbcbef7a1b851364c6a13acf7ad2a19c01dbeaef8c0c" },
                { "son", "dac1915a9d37cbd8131da998bf72130f16ca8864161516ce20862dd51e42c0d3268984e9d3b333d55cd552febdce63444284e7400a7a07d141219c4cf5e5d0f7" },
                { "sq", "96a26ffbc934b86645687f69ef4068d06acbd1937e735030e4202733884ec82200f804d0dc0464b397458a77116cfaeb4b83d388618c8215537f0e3fef685e9b" },
                { "sr", "f0ac27b24484c63359bf8b4900cc8e219729e23bf90ecef3866e5da6f29672ab0c6a3698c3b712a115f531642e12152a646ace0f73ebec6eb9d794cf6b4694ba" },
                { "sv-SE", "9bae20a25de0fdbac7177ed3503434c758c4be04a4b19bfd9409742379b3263af63ae16558e44e026272159f63d51096794af5a56aed6f91ee7ffb9aba92f267" },
                { "szl", "d171309cd9a1ccb4ba6954f16f613490141d604d1ab81c81574820c80fd6a81238b4e58560cec0c3f2d84b2ee0eddbdb693efd2a796670fccdb3c6e354ed7274" },
                { "ta", "2eb6942a550ea9b8122180164d5958fd76e14e3aa05926676a8f1bbe9aab1e636f2be7e98e894c74fd4a50ddf634755f4454d783470a543c50b72530fce2ea5e" },
                { "te", "f9a4c21e5e87151f8bc9a01c15a3e8feb9e89256b5793f507c907f76a3bf94c7fe44756251f2d5101feab6333c7b825b68fd172531be6917370ac0ac42b91b0a" },
                { "tg", "5d441dc9882923885195f2d2948ffec0bb1665edc7934117f74d40dc433458e8558e638cca3aa996de310b69af5d2075caee9c1ace39504e6d86e7cc16673ab9" },
                { "th", "98b6abc7906f59f5989154890a61e49b0f37daf97699839fafe1ebc13bea26bc28eec1269c1178a48695fed0168a6f175f84beb69d8aa96624b0e2b64ecc05af" },
                { "tl", "092bf929de5d106e825844ceeb5b172862c4fb54af80fd66baa764aa0d5c19b58694fcfd6e73d189f58d5793059b44daa35f1dce97a595b58fc6e50ff51d4618" },
                { "tr", "38cfe44ccfcf0c7510f0903e6cdbf8e18e96d994303c7637bd910f6e9e4f12208ee325bf1786df72e9fb0019b951644edf0430addc3795d1b5db37fb44d12020" },
                { "trs", "a4759baf52f8d08b62808d6960395de7b97668e9b926b50c8a94a8e6a99879f12c6268e1be642ccf01484ede0f1e9ad30ac109b483fe06fae364d9cb8c2eff10" },
                { "uk", "18ed54abfc6ef5fc278286cad4e9888e4644df0cbb60e32f3351418b0a1b8489de19ff590b412bed61a82e548e8b3b549461f36a2ccf9119be59f4a42cad2516" },
                { "ur", "4a048d4359073b9f47258cb25ec9d9cc59df9a09e145752752b7a592b0f8f0df9637a376656e7c2f917eefbe897fdf959612a9cf0e7aac87268c2d0a7add734b" },
                { "uz", "8a7aa80af405e46e473526d66fd0ac4c34de9e181f02fe8d147a48dd639b2b449d220a7638eabd2966a1e423a9375fd79974e1b319c71a5916352ca0a0c1943b" },
                { "vi", "178d14bbf66c486cfb13fb96595d71b237c77c414725df225d57fdecbe2157806e6fa7979f58dc2c1104b0ceae1e82aeba0c2586987a032536d8c3d8eb2dee89" },
                { "xh", "886e3f82eb340b9529f932136d9c30fcecde039dad709df4d9e1c326bb9283886f8cbd074f435dd8ac53f02923fb1e1dd4ef5ba329e3930d9733cf528552a190" },
                { "zh-CN", "8f010e735281e2d0579cba81ed3513cfcc5374ca24f17e7e60fa825b68423e4dfef021bb69028a9100e6928b157fe14bd852e0e15e13b1808ac4312b31ec37fe" },
                { "zh-TW", "4774019227380da9f0e8fb637ccaebe2ccc6fc49fab35b3329d0a07b6723e05dd21af33e9ac84656939171f8c5a6d5d47e750093a4d1856c795c55c5674b5b6c" }
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
