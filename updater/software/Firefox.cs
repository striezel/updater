﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/139.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "362e07c5d85dca62e655881950d50c488f04228ea51d9db449534ac0a53598c6c927885d4de894715ced4e7c6b2d7d632a0c8fca74bc3d8d115feffc8c8808b8" },
                { "af", "fc2866d87548dc1e51aeafeeafa57804b144fa454b998230c526c1a948bffff43d2562dce6b39c5e60d076ab8ff95391f568bd7fba2877bd544c738aa1056de7" },
                { "an", "d00883d394c792330cc20c58d5fdc647862393be8ffe756e58e5c322ba479aadcfcee804dec735b967d35e8c8bfd7701ef3558330ed7eaf15ddf83b242385240" },
                { "ar", "b766c58a4bb9a6f325de4951ff69b5c7da40e649036018b2b96dc675c08e3ab2602983bf1446cde450c087ea894e05bcab72416c4338880f80ad0ade5031d047" },
                { "ast", "06f4b5edaac25529c789649a0cd597a9f59c69e8f095576bc922f77bb5a38c724cb2734137203f45288f08131566e4cb10d3e51c2488cca571223616a1d9e65b" },
                { "az", "3fc42d16ac2be2b2e32c512d042c4597044c8294e1460bbdbb4ab759854d6d8495e9ec9a23a853707705cc6cab82836ad8cea8958849beb45bcef0fa2be6476c" },
                { "be", "99c806f4e72be74d8926a31da6da2e7e9ffe9505fe7f612ecf04919e7f68d1975a342fc69e114727403169504a16cd5770a6b18d04b5bd265c8e576751529be5" },
                { "bg", "ded59ae19643461cee521710c56ae49c999d60f3e3592959e862404da97022000296eceaa977f039f7fede2a8f80ce309c786750e282f5d28a1df54670af6abc" },
                { "bn", "e174f5cd9b80706dffa7d250c82819a7047320f8a66f3b6c0a6432c0daf3786132a82fac390bd4e14aa9ffb2d50525efe03cf35f444ddce621e0cae09a67ed31" },
                { "br", "278af9f2ccf1610d12cf3b5cadc4cb48824d873c27686e57158121a150c04b5d29fc6ddb0b700d17d03351b69eb984811f07329366e263d530e81f59d178cb16" },
                { "bs", "d5cd3420d9e02caceeb103e1ed9eedb95c8fac3226f3e49af07fafa075b53956ba072aa400c2227d1366c6ff588e2e5b1ff2243116ffa9c0f2ecf13f298938bf" },
                { "ca", "63c91a6335b0ec0c5a4d243f45b0d4e732187241e90ed51904c731d68dba7466825f5437361484330984cd779641c5121315dcac7a779a4667b0042a0afb917c" },
                { "cak", "59c3557ac82159111bc907f5a6d75254543b235d723f7fb1abd5c35b16776d025f3069c1a5296a41a173330f4efdbb42c56a3039e5bfa173a42ceada759b9cd2" },
                { "cs", "37baf6d69df051fdeea3eaacc370f2f576c7886ad73bfd106cbb19e7871003106d0b82b154d2c78644ccf0b73827b5a3389f56f947ab5d0df50bf1d59944e7a5" },
                { "cy", "1eaed05bcafce0332683c22549769c25738e310b96827e4f2e3587db5a474f0846adde7cd9238a97c9c659fe00975a85fa2797237aaac347999b12910bc88bae" },
                { "da", "750b091d20b05e6fbdf4df01080b0286b5115adfd491b0738cbf96c4c4586d9c65516df94868857f7d7068fd4e6db5660002caccd87c8136bea53bb516c50fba" },
                { "de", "fbf56be9229e5eb57f49b12ca17d6a5cdd9e0a1da4ac421b5f47df16808102e223b3df17d0289d632c47513269f9637a7c903d5e8a818f7a360c1c7056a329f6" },
                { "dsb", "5928063d3af63ba59edd3c99d6687d13d1407ecc2c4a43f9a1e4a8dc4fd5489f79adb784cf8f075bcb4f8d3aaec221e7cf72ce82d75c2ee56fe8c050e58fa5da" },
                { "el", "2f5bb67d4756318b1d3afbbd55e4796646349d782f40eca0ed8e8c741b0a57ef3c423794ae3316b3cfc9b7e6adda8373da390053f9c062a593b200343f426895" },
                { "en-CA", "c9e114f42c56930b38c4f556ec0c0570840fbdf559e2598e49c3b31eef2355747a0180ae54bd58cd10abd2f6adbcb7d38bc7158e9d8645c8149b80233d5b81f8" },
                { "en-GB", "08b42e0e314013fd30d99ff6b9cb19338c432656cf1707f6dc50f37ebfe52eadc178e02395e9a8054f12975bdc826c1365e4105de38245c7d035ace90c3276ad" },
                { "en-US", "adb4c32346d3b212c19e8bc1803a1bc77e0eb89d8744e02930302f4e0ccbe9ab5841e63e59cff8ab2a32fc40a7fbff8819b5cef21bae8bdc31bb571d64944c39" },
                { "eo", "852981229a9c7aaab11124d664c1a308964f17331f7792dc672a0870c730d6cf4affba3fca51f6418e2a1fd2a2762e01ca8edf6c37edadbd08ed5030a27f1c7b" },
                { "es-AR", "a985d92a3fd7245cd807289123e3f13392af48cff7fa5379aea60a247ba56a48091adb5928842029f61ac1295d9204bc3e724fe858bad831808b876693e108c9" },
                { "es-CL", "4d0ce63c2b05b7023dd4b7e29a0b5e9fea5ca70edf09a60c1ac0ce56ba46bd5ca531d447cd59a1799fa9dd915b621600973806d03124facdd904081b87f69559" },
                { "es-ES", "570c4e3d1beb9b46a3b15b0739647cd3f2bc170a1f16ac6e3d4f07ac089c0b437de7d7cc558127c1ccd82343976b79692607037d4af7bd6194e1528d74e61cdc" },
                { "es-MX", "60fae2ee03ac16f2a835d953abbe202995c0c5563eea6f552c11e39ffe9235d0139307bfebd2a66128b837130216bdf0321e1006479fe11e85fc206ecac052ed" },
                { "et", "f3be854c99ecad3250831b95f4c2ea0a4ce0f9a45537cc9a8a98115ec9f8c6c97b0c707344d93aec9c77f20cac4bd537a750c7d4b6afbf507eaa1c09c0b6723a" },
                { "eu", "48e5cd9f8f9a54a0bc5842f57d391b65f7c141d163cb5ed1fed86b3923deb3ad835bbbd49ede63a12f0381029e98c968002e4614851fedaeea207db2439bc9f0" },
                { "fa", "fc8411a95ea07ef4a70a299dcd3253c64ae7c9a1abe18af4a867fe68a5f85f121770507db3d84bfa56bfc86e235932cfb7f2c8d4086d522f0e6019f5c1ea6f68" },
                { "ff", "c2017847e4673bdc85638d17ac7e80fc857a92110da1cb74755b72aa781a76c857a7d210a668a5f5197dc925ceeb90e026e2c8a2996b06ab476bffc42cc21b42" },
                { "fi", "d0b90d057529bd7b841bf3ff4cb291d511ca8ae0adc9e81fc959647cea6f1d1386ef764b89085b07e8de1e52e8308fe9efcb36db2b2c59771441e73dfc696ef6" },
                { "fr", "312260c9d1553f2fe0c86aa3edbc3b2d590cc8c3326ded80b5c815102981c7baccbf6635bb24dc78de84f8623d5e81186bd5ee2440a66a5a011b5a3b5fda1a71" },
                { "fur", "6344aa4cf1237e808ee8c4aef16c73247dc5763d1adb2ebee3d20c10d339359ff115c4fe9fab6058254e04b99da358572c2db66c45cf4985640d430e2f7f215a" },
                { "fy-NL", "538cbfb68501b8b995629a67ba03f6b8a97705f179563f5adc3e2a8e101c162f050f194dd54c2fc7cf8f7a29d6a754a6755ce310ba0726d5603f25ef6d220153" },
                { "ga-IE", "573f3c0a235008e846468d27bff73cf3d39ba78993aab60c159916c02067c04804fc1044ad9a8615b55fe80a9a9b3fbacf8242c77666278af16794d640a580e6" },
                { "gd", "4e11ea51354f1028151c9e3337422a3233480404cf382b99c01bed775c4bf0bfa6d7f2ec6ef02fc6a28681db99995428218bcb30c0ecf6baa5851063ed8ce2e0" },
                { "gl", "1a3c11c7536535ca1d1114f30f397215817decd22c15fdeb0a4fd857b5d5874509c744a01051fead9085e92b087bc86f918c87afad984af7391bd9689a9c9e4a" },
                { "gn", "133b1c9d6007353b9c013705c2407b75904a57a1da5cac909554cdb4cf324dbbefad6c781e6d5b78276c5aecdbf5a3f9b6eb551b0c62a4f49d9f8758892747c4" },
                { "gu-IN", "ac8e8eee7ff94469434fbe8bf06d1a81ac41aff5255aa537a418acdf2abb4b06170c369edc1a09b9e8f5fdca7126516443e67af15bcc2c9b9b655eb1b535e374" },
                { "he", "6fe8352a3674c47e04fcc961e23ee385999ab3c64862056102baeeef03a5e2ed005b00a31895095a7d62b865797c42a04e764d5bb4d466fb7f5502eac934ddd8" },
                { "hi-IN", "12974fc56537c29d015411bbd35f906da926a5dd9338c3e56168a0fdf2c3d5d6e0ae1dc4d695245dab5cfbc37492fb1289b41de3e46eec6e69957fb1ea1e9f85" },
                { "hr", "090d9b44b8f251a623690e880ecb384352bae234faa47186e4dd4d3637f04609f59fefd3188a2460fc9e11be1d37361815fb9fe0d3f720d53a59cf0f930fe054" },
                { "hsb", "d438f80eff1e37c688529d51bfa1ade692b56a3cc0222af1f9fb4228ba103cd20d57ee067f081683d05b9ed268122970f64f1ec1f5eac66bc1af436828d5eb7f" },
                { "hu", "2ddd3a7d3ded0d41fce909a00f7ab91af4d782d6f01d06149799191a77fef9465469e2bf55e3db0f3adfab09f4e70edf6ce7bc5df06841e8c9a84c80ee954269" },
                { "hy-AM", "9db77743a3de76d9ad080621f6e31108badde2d451b0446cee9b8e09f983933999b0930ac781283c3afaa4a549a2bfb13f34467786074a6843e8ebcec83185e4" },
                { "ia", "3483725b5cf0fafe0d2488a64266d92fb5d574a7ae1d4019a1f555d425fcdef8116979a5e641e5fdee8e0b1973ed4aff553b55f43c74b494ff3ada12ce528849" },
                { "id", "891294bf8b66c07fe633a9b2d9015dd28efce15766c81e0f7d071b575d9dd2a11c2d21df51bc7eef6938fce1d070dda06140696ede8c9a9001478993b5d3ed55" },
                { "is", "fd47b4fb71b531a4f40f03474bcbfe0d11c43ec668579febc77ebcad60d0ad0f7aa321e85e7943c215ffcfc582708db0ce6978e7d335f4196cad5eb94c806911" },
                { "it", "c3b94a6b83b8716a8ce99bc2effaafea6b6339d53d0a7ca3c68078d7a93fc96d37116ed774620b8bd00f7b4f4eeabad41b2866f5507015526b578b1f467b6c22" },
                { "ja", "f83113be75b5ac9bbcad0b9d0f1038ea9cb74f0c0f778b8f2b673933df2d0093ba20443cdb2e4201f6fd64b6453ba9de22eda52502dc26ee80700f74e27e6679" },
                { "ka", "8248bf6e8791dce3dec46c3f36f05009f31ada5e7810d0dddc2ccb8f3148533a8cbddd7af22f20a54ec033c5046ee14aad6e379baf0ddafcbd73889f455c1c2c" },
                { "kab", "d98cb1e9b2448a64fd191f71a391b07996d1dee8dec0e461de84f94aad5bd7c38304e44116f53f915b314b267071afbfdc01363379e7d9f23f14dc93117c053b" },
                { "kk", "dfe8044183d4964bf54af4b5fb93b8bf81f51198b68acf71fe9fa22845c123c35ade5f7342bc1d3cae4f7f69104cc2b23163067d32637272ab324605a306c451" },
                { "km", "75886e963ef42916173704bc8c68a8c6f0db8b8a729fbc536b81e840ce4f40e77ac2a389d688f713d5f2f92b62f61fbc9325adc0e6873e1136d3c4b1b85b96f4" },
                { "kn", "3c3c7beae004ec1b407f76ee7313729cd225c23efbb7250bb8b1e811181a0bd0a6ed68436b43959300b1de5dcb7cedb4c714557b50c4a5889628405d1448a37b" },
                { "ko", "4f2375e8c388e6fcf2d374fc549acf5323b945adeea2437f65f10dfd07af4a31ea490c224f97a097902cb873f78c207bcb932b3966a9dd2dce4e77eb5b648135" },
                { "lij", "8afd1df1204f26ecee6124e0c9bbf2d4d593fad227ff3847bf1592bb3379edd751bb6608cd6a7b1d6315d86bdcdfb7ae575ca0f17f4f69632468d3c780633f1c" },
                { "lt", "4538244a70e47be279e3b9e605952b1a227e5f2df4162a5847ed5659667f157844c61e981d9018023983bd5d6dea6d9b4c4e7ef2d389819f4935ceb9926dffa8" },
                { "lv", "ed3b836b8604ff682ae1d4f2f693270f47c626615f6d498a52222fa9cfa40c5eb961d483dd0c9cbc8077efa6e17477176b7db1407b9b7e5ccf927e0df31b5a97" },
                { "mk", "120bbea4f674c77bbc3ec5cecc8064dc23e8671cb9ddc9bee2ae68bacac0aafca0004a11172d8d17e6ad41762e3ae118cce974973087597a333cb6b02f562689" },
                { "mr", "5f0afd0225f5262a827cfbb712a21e1c86e0bc834ca7d9372e23742623da856fffa41dbc63d2b95dff0525c163d4783ce79a75caed19bad050821eb2702c2c9c" },
                { "ms", "8af8bf422fddb6dd510805bbc32ead4600d7171ea83cc83006969af55b9fcd7cc54127e01d03f124121cb1e77c8edd612280d43efc8fbd64bc3bce1ec190c6d7" },
                { "my", "a33d28a96817ec90b790f74f6d898fdce400a745ec6a9531c564662acd1e38c7dad44ced5d789ce7c12253fa8cfc3103744f3c6d640668e80f3db959a7d6f811" },
                { "nb-NO", "d9fcc053f4cb1224e158be4772f9c625cd73a162c0fb5f16c9efbeb1a81a017d5911de02467732008ca8cad01886ff2bb6fe61b97a5699477c2769e102e89597" },
                { "ne-NP", "6866b63664c2d6d8f68f18734a70771f34ebf86b3ea74a75770bc6d8eda0934968c28f057d7bc00a0db7c11843706f118931c8577b9685622218ee263e3f9034" },
                { "nl", "1cf0e7ae1f74b5427c857710be858977b5953b8d266d69e3877e4dbc426a811bfae241322b521864bf5fd6dfc4ed07ffa67ebec66eaddd928c5e90f1fd1ad8d6" },
                { "nn-NO", "c1f26c045fa8dde3fe948a145da088efb1779ccb1f158a13ac35e26ac418418e8c8caf0e671aa7300379341acb2f6f89f840b6dc631eeb1d2fcbc036e418afe9" },
                { "oc", "3db95c0ab6e23b47a4bf95971df7050b30f2cdb2eb54d908983f27b9ee6b2852243af7735ee109c6c4389b2533aac8541d7d5c1857a5035024d2024762cc5420" },
                { "pa-IN", "6bbbd95b27cfa8d31167a3e09f1664832c6bf99516b4b013dc47c6b97d21a05f7035c81a299d502a8f9a54392d6fbb4aaaad1eb0f58f871350e5a9738c1d8d6d" },
                { "pl", "3597c4dc737607a4d8864ac8a12d961072f9c6272674e5d7fe04e493e8babee38491672fc4428e473290b228207ae9db157ae1428a348232746ff8a90c303a3d" },
                { "pt-BR", "e0c14e2f94c3e1e86081276c7bcd47a2500ffce8018b113ecab39dc07585768f21cc9380b68f80181acac9f690eecb36501b3ba093f0c7c7bb0d95273a9f466e" },
                { "pt-PT", "4aa5df04c4b1f21a4f9c53c1b782a42a660e86dda7861e4108a0f5955a51ed10856e0c6581c45b99f73a0a98e16be181a226b26b13dc3046483b008d8b774053" },
                { "rm", "c6043f8a4eda03b30519d1dbe6d4192e045e608c1b54c6f9eeea7b2d7b975678eaabc95ee38143d06ec150ab1a9dc8d0337edd199fa97450f234171e83c17d5d" },
                { "ro", "52ad84ffe5d26cd0a95d02654daa128aa8778af47781643e45119937353586d7395c75b43914ed4e81eedcf79d28123030e02641beeff975bc710c33ce7a5117" },
                { "ru", "fca1354cb812063fa90b0935d4fa4815f0ff62ad8ed383f2e1c0b367c5a4e7b7dbe410a5351801a6a1fdd02a527b665505ac9701ea26324d1d4e82d109edc4d7" },
                { "sat", "371f1809108c33cf6457d9abb80cc14546b0de49529f289c918927f7eb8e75dd9f0a270f317990f1c10f2baf095841def5ccff45b77bf980f9fadbf1a9daa755" },
                { "sc", "00808c603938cce38a725737dc6b6f48fd67240b59aa4e39bc280d88f3e7e7c5f8065840ff03315c7f732e30e7dd5ab34a3e80244785269928657e98352d2009" },
                { "sco", "35514f890cbc95555c41b5105594ae1cc5d985828dc6cdb0ea765e33d2bb4d8a75863e2b031f61c156ccecbafa67f745945f039dfa6090dfc958ba9edf47faf1" },
                { "si", "a9052840fcddc6abc8448525d640888587c5b22cca6d94ce3e977c12b8a766642716d82e68da6dc723125c6235318f15451c7b794e182231952f8549003f52ff" },
                { "sk", "34728909953a905cbb71d4e83669e3b5d62777e8b95374e3896f1d125884785d50f3ac9faf7c74e28de472094d9a075238baf9544856b4bb5e48fb22075a12d1" },
                { "skr", "9cf140f46d88743f68e3fececfa679e8eb60407d0a9260e2b1df3d4839c98bd76c2f1bfe21cae3db55c3794ae0a3c705d8b2ce4388ab00630488cf10e87f69f3" },
                { "sl", "5ca3487ee3ff13c249b96f5a2766d83c345f61731c9bf9fe12be98e1b52dc10769730184c63fa4486e624c4795a13e1a88022122248568ce19956caddf6d97d7" },
                { "son", "52621f14d39132692e83876163ca1676192c6f6d67d539649547fc38f8dc02b1f47ebac7a15ef6bfc7aa37aec81cdb2c705fc6cb4ec9a8774bde5a0b21b6fbc6" },
                { "sq", "42bd4cd9141782378566bd327d243986cfbbe9febfa4cb5a8483706a4eec7e63480b43827e632a5aeb2e9fdcb3599a6d9bc35158ca942b8afb324d72a7a6a061" },
                { "sr", "2dc616c8a527c0140049a69b80f6219b07e4fa2754be740db4765cd94ea624ae31221322eb861d2b27ffbef506a3127d52ad7d423b2a580976768818be3ac885" },
                { "sv-SE", "baab878e12cea5cf41aba8d32d52e3cbbd2a432bd544a5785f52babbfd86dca1250e45629bf04899015c8ecbe41cd632cc0973a3539062bc8fec9a95d5ecccbd" },
                { "szl", "e368f7b38ba075e505b774e2e5d99e7bca9bec8f9333ddd3a6cdba9d507a1537d7eb40c1cd8a8a2fb953effe6cd14f1bfd40914b1d9b76742291d3f6e55dc1e1" },
                { "ta", "360ab0667b9c04c409f08972e9831c44b3c709d7a997bc77b4ee6d2808881c74cbc317581d54258fca0d3aaf750498fe1c20aa9b2ff34c5e96f6f10befae8251" },
                { "te", "31fe80e96c251b8e4d26d563272220ad469df7fe895bf04d826e2257013e9fa83e6e89cab706cee24bdc674891feda672cc1dbc590eb9cb0f3fba58d059ee4da" },
                { "tg", "46b4dbcdf2060f685a58d0289cfa44a130b77fdb5454dcf8e93ee7fa82abe9c2fb5f8695a4a5d8529556e2405b35ac9ca5d75bcebed32d65bc26d87bc339d259" },
                { "th", "a4fe14643c506ea8c6c38368ae02371e7c878c89fa8fc2e1fc07f1567983aabd3cdb02fb196060b7a8201b73bc23ea5de9f130d4cc494ddd9e957b4de0718bc9" },
                { "tl", "8ba83ece6a904a638902430e1cf30433039fde6ab1129ddc6c6d221ee7f9b3c321030fb85d7bac28f5d6a2638adcbe41931a86cb391e2638701cec30ae839f18" },
                { "tr", "68a0e4a34c13688d7caccf299b64b72abf654e9bb5b7e14ab95ad5701e5b9a18b7eee888b1242d3ca12237767a8122d6dfcdfb11f5cb0d58f792dcc1f58ad5ac" },
                { "trs", "4dffdd2aae6310b6b0557ea42cb2890283885649877029ba1fcc2e4305a464e2d8a55b6a29d3db16e2948e63aa2cb807d411503852eb5c0b6c9acc36190e1719" },
                { "uk", "2c652d4c0ca43e6004e7ad34794169ed6bfa6ee6b8d5b68fa92c0c6f56fe29f1612239a872b69f4b8f610df02f6db211a0bc0876729587b24ec82114e01750d5" },
                { "ur", "2bad818ff7e223d4a2b6475058e5d075c3efe8142471b5398a2d43fd0ed4326e35f6331d3fdccd11e464884c09c65f24f2958ded7912cefdc563b7eb123829cd" },
                { "uz", "89c2b2eeb2249847ca40065e261955a3b872adc2febf727a2d2fa9d6bdf5bcb882f2a782e5d385f2c7f436cf9d6350a7ae84cebc6b9ef7bac470f69dd9f1ebe9" },
                { "vi", "e29d147aacc94c5add626ee5d2d90b9b5aefa139b35d85497d21c7b6777541c281429042cabf5e5b33b3adcb685dc1095456101cc8e003de63fb0dd132b48e40" },
                { "xh", "afbc64debe52680ad9ff6e39f5f62478686aed6ba4219a315cca270a3c8937759f9460623f5d5015f7d69d1961e5a7912021b17ac42dfa63e416756cad551ebf" },
                { "zh-CN", "744bbd18437507cd490d3a0fbf8744b881dce99f3ab08de95e12f71362d1eef6c80858daa5d4b48a65285d7e890c89387d9d3c913e5bb7af97dde90167f3958d" },
                { "zh-TW", "ce3fc93767358de6c24357f028cde79b77733cd9dafb5b16b58324e1cf493b2ab880b4fd2a83d0afdfc6552563a72f2b281d14cd66ba7549d26f75a9b7ed100a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/139.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7e46ced51dd6be63fe3e562111877fbe8bd1c7b8d96c43b03e7b827012979375f76e5aa02cfea86fd5f6a27decf33890e1b3449993697f772521c0ab5f15a03e" },
                { "af", "673d28299ad925e0d85da604f002166557ebc4b0ed369a4a820905025b1f2299d473190a77b61bee61e99ee0933a663f4c8df755a6e49adb470f2517a94acdf8" },
                { "an", "f3d0d284732e3bac0c0e16d841abd9a5cfa5369292fce1cfa9c4e42d0923db2a80577c2afa79519438bf76191fa7dca95a6bf87037ae0cd96a931d34beb81d65" },
                { "ar", "9f5e87892fa1aa2efd9073370e73f8fb96d0c2245ce63c35ae279bc4831d07786030fc37e0aaac5ce0497f2563eae84d7f21341b1bc9da4168dd254fe5b410df" },
                { "ast", "1bc69e1fbfe2a52eb3f1364afed4b462fa3e23c19421b67709e5abddb95789375ed1dd1fc6be91b66154869a125ba53f9c52b9308bf467a2dabb8bc20ce3200f" },
                { "az", "8368db6bf97c855f71e5febe4e7bfd58c74f0b9c84ae80634497d7b182c646a78525e286a86331cc71bd5ec901a6f930f12959bf8f37b8c30e6348bdcecf65ca" },
                { "be", "40e6a7661bd6f865fb1db3a0c795245f631a95ac53e65c980f3366e69d0120ccd233d002b54130c8cd5e3dfd6e55d9ad234f88e8db5cb65b9b2043b3bfc59c01" },
                { "bg", "c37de9b321998491b02f35e500fbfed656bc0f434a411ff2c790d504eb1167a2a5cdadd94fe3788480ebf13edd29ab80db783c4815895e70c1b10279352b0cd9" },
                { "bn", "57cb654348be982510d2eb3e3446fa76e907e74c672c8e3d1e398d9a5eb4aa6e60708c24dee09ccf604b2237edf5f59e624e2b83bd1ff2fe2afb68ca47142a9e" },
                { "br", "3318accc65acb9ed6c3b3284a1a20912fa4d30765c353b3815cee1ead8506b251d892d3a9bf5a40c3b6a6c268f003895babd140caf78d771484cfe3ed998f33e" },
                { "bs", "29c6996c988cae2919b332c346e71e2b89bdc92f75cc7cdc6910fe0a5bdff5c4bbe058a5e54cefff4451db6c82d89ba70045bbc0823983118b632ce5f50e3a2c" },
                { "ca", "afbe00d683e4679f60807b7bc263dc5e2993c0dd8eeae16d3828f87758dd10f9edfb68a6c29d4328c13e73adfeddcc964c6ad28740aab0b1d10e0f857d2a5598" },
                { "cak", "969ad5d7891325385bc1fad9d56651e8050cc5e75d902b256f2a2c5c41265f156c13668c452da751139f0f2793a238bdd2dc0ce277423fae883d2d5dbe0850bc" },
                { "cs", "0275ad5f878f20d314c300f84dae40c66808e85fd57c16f1569901a32912e7461ea7597ff902058373254d2f5fa40e0266c455824bb2fd5bda3969151371f041" },
                { "cy", "d44c877945a86b6d009ff354a42dd18dc9ab623b3fac317d1d5ecbe83e958be4e2350097e53ac67252e029384d2bc3e07555ec4501c5fc1aa29e017c88553a9b" },
                { "da", "3928a75d0a36a6fd0cb86cc956a7301a0180350ee130514c74e580166e67c8e35694e802c05cb7d3beed8c04c2aae4a4e53828e07b582252bdc8eaa7a0da08fe" },
                { "de", "d0db807157c1cc89d3eb1c93e2fbc17668012809a1c234070730693c709566f5423787cbe0a878c75771c518e8a6b6d5f8c4d31b400ff763d7fc1d831bc0dae5" },
                { "dsb", "ca3fe3cce54bd21f066c5e664a071106a20bfaa644e7ff61a62e8ba08c955c024a577b2b28cf289812c78789862712b92145d0f49745386b5379c432e9fa82eb" },
                { "el", "b0d92bc1d429404290943fee071b41d3a6b8932de6717910ae9b8de7bd26b0e7ddf032939c039585786bf60e27522f1bcef208d21c6e474c861d69b839992291" },
                { "en-CA", "d17fcff39560d6dc2df94ba6faec77f462dd989b2bfe0cfda6c46fb1a7620226b80bcb313b3cb7039d0bc856cc691cd51a93a5e9aacab86e6785520d9578480a" },
                { "en-GB", "687b11c7c83f26eb7b4d27ec536aaf09f4a09213ba87373d20ffb58204b6beffabc593b66bcab0c45351ee1ec277c53186bcfaf288777ec307d70ec505ea91f1" },
                { "en-US", "5788c91a04c88e1dab6b00ab14d3b693356bc524ac920c8b8b48ba76b0c8279b0a751a7155c6ff4e95772d7bcc62d3fa7773ab829b025367d70efab5dad7e829" },
                { "eo", "fedeba149debba0194c3e2f6a704919384c52b414828b35a376d88912f0f7851f87d0a9698785b03e7ff88d0353c94f402c7a50a2d4f5a11cf7760592f4dc909" },
                { "es-AR", "ec8b7d2b4bd6903a62ab7031743cf5306533257c0f05f4143c634d76fbd8c81507840e0851cd72e4659108ffa38b00bf6c4ac68b1555fbcef66b1f26c736a042" },
                { "es-CL", "c9af74d374fe92c39934476786ae6da8403306a6193b14307d9e642b4259539926500b654a85a47a77f1b8284c004531cde4505bd20171f8e972e4e00b8a44ec" },
                { "es-ES", "639a9645ad22fa09e67212014752e7c132ca95c6643775d5b0d6da1e80887aab4497f0e2a363fd0f21167068a92e4e0db8e0742de59dfd8b9f991ff64275e60d" },
                { "es-MX", "22336825a413dbcb6082fe9248b31bd211602ddadc410d6d308512ea941a6d53c765392c6bf73ea67fa8df86ba4fecb426c2b08b2c359fb3a013a1da9e693024" },
                { "et", "6049d06dc35db993052aa8224ca45eabf20426b3984104b059f0e0f46adadede618764f03f352051c6a5db99e8153d81adc5369708bd168506e62ba7e10b5992" },
                { "eu", "4f9d1cf55429ada76f4982e4fb2269f82161926c63251c15f45ccff2c64e80becac10da18d1a2d2fcb8219f7bd88b356ea1bfcf8cddfad5c42a71ffb69336a8b" },
                { "fa", "e15487536dfb05b50893065c14e5c040a92df40536a26de04018b409723de6d745df012b64c11a5cd1254c8cd86ed99ac789d6c0d1869378f3d452e8dc85951c" },
                { "ff", "7b732bc5b7e2a73e74a966f4d588fc7e130a9f330bc047ba4fe6bfec01346a8a3a3aa68622419435ef16b82197afda2864694d05292554da7176ce116e5083be" },
                { "fi", "823bd9ad637a5ca1d1b6a8094887461d43aaf0a5a3117bff9888d2aba69449b7cad472c69c263e76261d7cefedbf8856104d444bf29fcca849cc5c822836336b" },
                { "fr", "cc3103523a8540b241122492fbec6f70cb8e2cac334c49b50c1b44494a1fd0a456134df6ada90996dc7be685c1fa0ef192074af3380b0c24fba49b5418c7ec59" },
                { "fur", "58568106f28016c9959966e98eff7e201a449f5aca27c9dbc9de4d24cd3a217eac9d42331fe250e5ff6104b94255e8b13f6c213c64dec2a38de013efc418a4a5" },
                { "fy-NL", "221bc2b8a113dc58f869a1fbcaecf2c5f7591e542b0c19555b0b16e1d68c4f905b590784ecb5e16001dbcc421dc71c46af385bb020ee53a4ef0bf35fd881a7ab" },
                { "ga-IE", "ded75d5b025beb0ca4d2510e446be3e825078656ff4f87fa24c7a989efb97356099d3b38620e14c37ffb703b66898438bc65c6147acabcb1fd33f416942edcd1" },
                { "gd", "2bd6668863c944681c7dec02ce0b3bb8d26691151aa57d789329d2a2af3a36d992a1e10beeba46528a7dcda5c052a208488b1bfb2d0cb757b341ab1cc48d9b6a" },
                { "gl", "00c147f34cd29b36e793dfe451a2114c1a3af4056ebb146b428145d8b2de01562d959a1dfe50adf1ab54801961e5c874cb3258d5ac9379e4f92a037d30cc68dd" },
                { "gn", "f58cd0729014a86467fa869937317b6e7b999f9d73ee8855fcdf1f97373f27c7bda40d9b1915722c101efd0fb33d8acd022ba22a7df391b0795273b56f87002b" },
                { "gu-IN", "4a93b33abb3092e82f2302cc29d127bff0f29cb45bfbee91b014407b9a8595232c749c5bd59d6c0d653367def3515b9ac927f3f7b485dccd343e54bccb129f4d" },
                { "he", "98e801be662b20be88b66251f256787a15a69f4a186f235751446bd082a78b7e02c230d097d2a1c361f809f65f3d97809972cba3bf241f22766e2d874d85f3be" },
                { "hi-IN", "13510d9f151dc0eba46f633f54a44d187f7e24ffbf4a831a54c8f36d857ce17d1c24073f64c409d26108be2dab015e07accf6d2c7eec74d3b193cbfef0ab850e" },
                { "hr", "bc0c66496a97500251d1a3bec16f4ab922dad718c7093243d57b0279da0dc496644ce6f22c41437901d8a4222669a9fb43923d81c54ce1cfc03705e2bfe1c2a5" },
                { "hsb", "f483d8fecea9ccf2bc2ade062d367647de9ef4c3b941af1d735751454549082f2a65841d1c95756b21bf0c345dfd0bf39a375e1b5679f6f84e19e1695e65d410" },
                { "hu", "2729d8563e27116f4656c8feffe2559ed31912dfaa7f59e49f80168ac02ef4251cea93a4d94a97de7c0a9856d3a1d0ea05810057f381135995288f51ef753dfb" },
                { "hy-AM", "aa3355370a726492fc405875036023aac7942c93198205a9573bbccb0de744df5bd2abf92de1615e38fffbfc85a4ccf65aa448e67ba8fc92f5b978c397b49121" },
                { "ia", "05e6f90414c289e4242ecb43ba1d2dbeac6b3b7e8c3ac67f6f5c37047678dd9306224f25ab4d5ed41df85f5cb298bea61c9070bc0b9beaddace6d00c45b90708" },
                { "id", "b00a96a157b861b438170dabe9ff484478066d866853d12c52c789c8e7cd1fb99a9c276e76f0cef9e6aded0aa29117728582e5cd321d74406838144e315061b7" },
                { "is", "c105328c2733fca20ef2eac4b4bdea6fe1d5c0182639ecf51d7f84e60270097b9ba49ebf01fc9648ebe3823dd18d7a7c7896d2e29ecc07af355b8427c0866677" },
                { "it", "b8fb0d1ab7af8c20b38892e3416cfef34210367d5376f6e638960ea0c671adb5e3978068a0c8dd2401deb8f00e3614ff8b5125f096ecc089f33b82ae39c40182" },
                { "ja", "2468866ea5b42a5585fdf12d0275407481442b2c5b13e5438b6beccb9bc77475bc70c64c0b608eed88d49e9a436fcb7acb09455e6bada39e03a9b36760591f8e" },
                { "ka", "b98d74f47aa78436e78c44d68484656f87608b6f82853543309d234fd9a513db96fd6c3f0054033250cce7aaa7b37274ab05f056c084bc8f87300dc2ac4621a9" },
                { "kab", "0bb1f107d88265f0c7570215c325ea0e077c00d919782c0fae9cabb92406f14254d38e288929b0ad99ac929b117087d42ae2687915bf4cbd85a9e3bb8bfe0e65" },
                { "kk", "e63de04ec71ea4f214dd4da045f8bb7d8b3e77c02091842736f07defbe1b48fcbb1bb6367650e526ebab2508801ad69646a97aae2633fb178e1943fa82526a9e" },
                { "km", "8d8c287486315f786a35f4ae5858761321ef400593fe84f9d2635fc551d0dfa73612ec924175be5386947555c8a35fb913cbc486068750a4e81fc92a2429a669" },
                { "kn", "96b6844195c349f218771730121b4cd27accbb8db35e8602ba84560d6cda01c49262af56aac25cd977b1adc8e77effdaf236889c12c77675b66f89183492dd5a" },
                { "ko", "57d9182cc87dd0d18888b9b9693e2e80fb1c6df2db1f4cbb67b564d59f1eb711f2ff22f99e9b391c87ce949da979ffed92f815f26086d92c46d7161a4257e361" },
                { "lij", "81d6446744f5e8605aa185a5e792d066d17e7d8d11572b8e9891b916dd1cc2a0533be41a746f848971a7b9915a515be0c43f87c91746c82fbec15028b445bc4b" },
                { "lt", "906c8252e9b39821dadcd3f4cfe6ab7a948d1e0800ae3f23688deccd8ae555440ff82205cf393d5b0f66aa67b5aa09f80aa0e2a1661b344760bedf4f6b7a0e27" },
                { "lv", "00c606d6955f24edb3a9187763286be5311e464c66cf5f9bafc04fa380514e754e2908c5acd553ca8e01be7ac2bd4b669a5ab2bb6f837e76f43c689355f56b9c" },
                { "mk", "491d7ce08bf4f4907850846b15ed1c6c486f0382d94d369535a427c397f43c990a0adcee43ccc6fe4e396e1ea2a7174a173bdaeed5b2c09e45d441fe7763ec48" },
                { "mr", "a01209ff26fa0881c3135bf5e06407fa8e830ef4a9c6a9b50cbc0845b4c02ebd078719fc3c741dafe7d4199a06be952dd63715d5235c8991b599643ccca3fa80" },
                { "ms", "3e13601b0bd993977cfcb653073db4c7540908675e75695d90b2d207dc86b74cbc7a78575d6968f3921d6ad368b585880bac9ff199299cb7483710a70ba83587" },
                { "my", "f6c04e8eb11cff0706d52af7a9d03570e927339c0302801ff38dfadf6b2ec043c5ef10803fa87167ac44187919c6ad6985edc33f8473292410ec732b705231d3" },
                { "nb-NO", "b90efd242982b085ea368f9cdce0f4cbd2912da8cf762e24195c0c8d2bd59cf08c528168144df71a61354eaea1e0a77b6db43b706059e0d93ff510329ab41747" },
                { "ne-NP", "35e9093c0f51d472abb5ee3e4c073c3b70a3fb9150e89b96c09ea863e2d63f542a671dabe3dc391b1f7e51cd76fef92222afacafd7768479c260d54ade0b5125" },
                { "nl", "41195ce9036890e9ccef2f0d803351edc76c03770a9f429b79e72a3916a2f181964131d6077f4fc80cead6a91e69682c7a6289143ed438cf42050e66dd522ee8" },
                { "nn-NO", "d913d6cee4f842bf34e4bc03af866518e59a51fb971cd750124d16ffaea0aa7062511461d5b44c01230a5c4b36ed24108209298f5e50bf5a0f592416e182a180" },
                { "oc", "322b2cf8cf210775e992c090c101f9afa9206afa7f015aec21fd6cb6dd65210bb2500c7b85a5f22d34314b9e5d1e7f4148ccc27ebaba03be1669409c5dbcc650" },
                { "pa-IN", "6d9fbae1fab31d6b85acb2925bc1d4e0ecd4865a9670c2ab09b310aa3dcc76aee22579156d4b8e0ca994a7391d8ebb152e0f2833c11fe7e2453332428906f4fe" },
                { "pl", "c70caa7f100ef893a0dd5313723744499b7139f9d3572f0dcbb902af8a18713effe519cca44b633c6d57e1c1ad5cbc3c2bb1deb2211d0fd2c67e474d2fc2c7f8" },
                { "pt-BR", "8ffa1e3289534065a9ce187f66f2bb364e21a9ffdf1b16a8da93adf0118e7d7f8f3b2aa1464e419b28639b31cfec00521984b8f1471252c150acb592fdc97c09" },
                { "pt-PT", "6ea5ea71391f617b9c5001203fc989e3b1b3931900cf40923afa5b3ce0f82fc8952f704f116f7d5455ffcb33beb5d0bb281e2cbf19b01d67f9c96122bef883f2" },
                { "rm", "e9985a319a71b7ec514f853dad9b6409434c08ffa52be4fce1d9e7c0ea2c423652237d7cea7e20e5b39aea4d16dd29f98d53310843e29f7a35f3c1bf056080c3" },
                { "ro", "54c27438c7e5851b1670900bf00d6a69548b9b4c14b3d36ddf2745e97351d31210ce4f0df271b33b0e627cba813701bcc3e41c0cac9aa99af098430115647d11" },
                { "ru", "a8cca5ec7b57c59315cd9f35eda10ba8b8812bee92d34294d7617635b25b8711356036a8dd9f1ad8dda56abe9d076da09835cd656510ad77a8bfb1ceb70f995b" },
                { "sat", "4d39deb3c6c1d9dda1bffd139cb484863dba355e329d085ac4bc55503045faf49e7e8ca01523cde3f69bfc2e2e5c83f4411844911f833906caad90ee15b20512" },
                { "sc", "23059c01b62228ad63b92045b50651a61a51483649de8dada852b45d1c2090c5c4796e149ee02db3d7ef7e22fd33630af8c4b295dc0934a31013cbb3f6733a81" },
                { "sco", "ac3d71c1301b85a5171068e930c1ce98d8e01cf6ac4bb41ce6c3a42506244c7712d641f201f48ca8deffbbd62394639f36d890427a8b0356ccf5d0806fcd6189" },
                { "si", "a62308feac010236bab21c23f0e6995d08b1ff25c872eb83ae02a4d84e7c8749cfd4a5fa6c870d0215e75c0cb2d07879950b150508d1ea9259cf3849eaf8a981" },
                { "sk", "ad9e00aedae15a5109c0c60972e7b139fb5e70bb5a783f01c6520b42e59c2436455146ba1898da105d533933508d19e3caf167ae6a1080840517a9c0d22fab43" },
                { "skr", "e8d3934c7b95a58b424d8b4c1f2b93f6b9ce11ba5980f43acc35dc04554e4eebaf251caf6b07f80f791e53cdac86b687d21620128bae66dc0095ea0dfa5d4eb6" },
                { "sl", "f757014d169f027aabfde920b0d258cbd86d18aae6935156996feb13a603176106b500bc452cc34164dff47a306057f59b00f214edbc69b821d91665a0f2d53c" },
                { "son", "2bb2244363219e77db66d2806ac4d3e6f9ef054ae018304e7bfc5ee96ef34ea8309ee33b5c4a20582e8cdf10b6cc523d4d9bf8b49d5287e8c15869ec8a90759f" },
                { "sq", "a7bc338650583f07bb3ed67b0be1b383bba83abbe97c7832174127432dda97f2ed603a454392fb1eca5e712ebeade43e2a4cff00b2a1bc6ccf77361130e96fec" },
                { "sr", "fc67d256a83614058f386ef7d95d36387db1a5aa4412086dc7cdc9ddc98289328cdb603e60d822d0b9b4e5e247c905fc5f30fa24193bf5179a2415f3d517b171" },
                { "sv-SE", "edf912ecaa41964e75604291be8283c89f8a4c4ddc396c65a85c441d35d6a3098eb7cb3a48e3c12691ecc326e26352fa18ab8d63b02a4168f89e92f00abc2141" },
                { "szl", "92990e0c994a38f1ce8c2165bc3e7acfec4bf606640799e37b764389632dcef8a173d1df2c33296e5c83f2994990a2c7b5e511b0b92ff3965ece1cd5a86e4856" },
                { "ta", "9c9c4e6fba160e4e905159ca145254dd8765d20575706ff6413f0887402fd06e6c1f37685f640553336102d36293285cb40858ecd208810a8e249992be3ae0d1" },
                { "te", "c2c2b528a689aa350e86469453019cc949d7c1d4aabb46774bfd6b07f31e9505b262b230c57897845d91bacef1ff24c40420167b4f9a040dae29e5fddca7251f" },
                { "tg", "fba695352569dc4879ad0eccf68e8b219e3fe78995a1bbb567576cb0087842078a42e80daf902feec6695b1b8256c599b29dc294a2b5392c00edb8b54a99db46" },
                { "th", "bc9199b698a2abf2df82d41f821eada2b839e3cd765ab2274d0ee42a5b568ceb769952153adffd62cb54e36b1f96bbf10775f56681dbc0837fd79f4065f560b4" },
                { "tl", "d8cc6f7fc1a5f841b512bd3cfff4df04c8b00613d5b65bbe0789c3bda26c4717feca4fe054547c4f13753d73566fd4f170df44a6dfbcd086670107d01bf264d2" },
                { "tr", "8587d58e6c613db3f4ad82d7619de997eaca936ebfddc55bf84f3f62a45dd1c167a53a7400c63cfffca78b493e461f97e2311f67762b674a71d8003edbaafbe2" },
                { "trs", "ce3793b25c7cbd606c6a20bae171a608ae2c96d638811ce6ec0b6e62ce4cd9bb7460ca0b59bf2410a9cfcd825376be08f8aaae8326113875406622f1fc572501" },
                { "uk", "80affd41f5821ade091ca9bf675b9337e7307cf1e4003d93ac493f50a3d4768bb8f1084a7b4f46646fd64f805f1acad11455afc2a8040a57a4f769b0c10e7434" },
                { "ur", "3f1630b0b6f4c3c20771a7fe4a28a28b7043a4626d67dc9e507cd09e7e6b475a8a1ea86958e04ca37aedf859df4feedd16fcc779ea827e58789ca62880a1e516" },
                { "uz", "e78d0d874675c71d3747c8ae23c7c71e3a041d0d30f5f5f94db693ad9d2636cddd56f3e675ef6cc689e5fa3f16e113a209dad8d2857988ec3db6826c7fef91de" },
                { "vi", "f585600a1b1bad26a87a91924d44912ffb322cf0222c6184af271be5609a72879f0d332aaedcc1fd0695424891702ab42810f622ba87c844c37ce20f1d968f49" },
                { "xh", "d4d783a49dc11bbd3612bc8e15762e8e489078efc873349fe2bd682bcb213621608c350f2c53cda97f257628ff19d92f3d63b56ca1dc82b96cf4b571cd9dbb66" },
                { "zh-CN", "bf92dc7d9b6f54e45379c00a6f9f6f6fca3ae3778b257bfd87745e62248022c3853102a82fc9523c1d37ba887edad8cc8747e245bb2a841ab51166406262d95d" },
                { "zh-TW", "f94937de1530718c32246c16d26013cafb6905738ae8540c56ed22850bc4ea5be0d7b845714118f0e7a8b80eae16bde75e8799fdb0a38df45164ef63b916fa5b" }
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
            const string knownVersion = "139.0.4";
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
