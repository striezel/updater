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
        private const string currentVersion = "134.0b8";


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
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "290cc9c5564f1968ab935298e3558e1c248241df79f2cb876485f02b53472aff409a634c1dfdf7a861ff6df8c2fe7dc3c6b5afc426a1b78bc5826b9df840d47d" },
                { "af", "195403019ed322ba8262f459972f78937110165d86b0d3be6ca168bb12d2340a7651862cfcf6ad1c77f0bcfe18325bf9db2dabb5497f1920d03909ecd6178759" },
                { "an", "c4cefa4ce574f4c4aa6bfd1cdea4f065ca8986878774cefb419280042c25224e5808d4aa870ced392d30b6d9c50bbe9739a7ad635365bd834abcc2876a85b622" },
                { "ar", "cc2f054a80e79c2412a0f75d0674ff8e81cc6a232eb22b836d73c9513dc1f49e92a6390d8f04b1846b4a9fa49d1c4f5ba94622bd21569b2fa539f2f59d82f9a2" },
                { "ast", "b681a350fefcc0d2e22ec29bc6ef59a5c19e52092d392764b9b3498ef881d75cb4e3b9378c08dc097c1b08b194d21da517cae29219a3de9799e783042f5d3720" },
                { "az", "858af579fb1d7534cfbc97117e75e85dc9b628af45541c68b614469c0cd7acc762873a46790a0a498566b3076394beb010a5fc9c02fd4fa2ab4113ddd57c91bb" },
                { "be", "8d0768b3f03e6ba8c2414bfb6a7991bac227828afc0462ae8096bfff72a4605423fb3a2f79715ebf32372794e406c9d7f0e6fd3373fe0caec73de5367d7214c7" },
                { "bg", "91ef00067f235f367f65b582b96577f3d64b5883a2a2aea58708b87462627ee4d6985fdbfa7c5b95414c944dc009d81044e1384a9033571f6eb275a8b45d530e" },
                { "bn", "421bc3e6a5f6447e0aed084204a32c0c01ba8ef4b2564854f9c4921bbf481e5b55fe81477e70985be8f92bb728258bbe287c07e29b51460a6db175d8539bb42c" },
                { "br", "6cbd87d5e00bbc41efa061f856317da9030bd2096fcebac7bb84ddafa687e32dd9d441ecb9ebb8ef33524b75388dd98e3b5dae0f852c4b6ea9fc6dacda78d9e2" },
                { "bs", "d5a0ac33b75db95d1978d14fa72784db273d2506c9aed4228de472c8ec1364c4204907950cbbd0b3d61d0c8b35e39950d7da2614fbbd450e2215ed6eb298c4dc" },
                { "ca", "436b5a71faac566c230a8eaeccc7ee8b5f2be0dd6690bd792047f14fc5a6448bb38c18936f7bbc70dba75d1cec0d8c2b6665fd671e57c84db9e3ad42dee0fe03" },
                { "cak", "41414076e1e14332cc46a4d21c491eff2ba933fa43a1141d4bd356422c34b2b0f1c75439f8a685d4d1c01af1df6fc1f8ef3361e084109f1708779d745b8dd982" },
                { "cs", "6dd29a7f14e854606538eb7db364c9a3761e90b962cb6e55bb2ba911b191319f484c4ee6f382a083b86c93deafb7c4941ff56be8c9661d970eaa8435a40f1bab" },
                { "cy", "99b2f31c34cdf4f1c4c56ebb78e3a82e650b4128989e9922fcb38cf03d28a50b328036f605d56ef5ee21730f9025939f71c9a337f2aee363936bb81107c9c388" },
                { "da", "a1a0d77129d84bd6233174ae432087091c5b2f135caf07a7cae86b2099c02bf9202101629cfa2ca438bbd2ba3e51d6914dfd5c485938f3793471c1590cbb3019" },
                { "de", "9876e7d77a53d7f74ea77af21e480d982f0606fba727d2cad7b473d6919fff76a62c3589fd558cf9ce632588423be14474ef451d857d23a1611547147810584f" },
                { "dsb", "6395b35d9ad1ce7cfdf03cba16ffc4b6b6bf6c9b24694c729274f03e3266b0a6c2ea733e32431df367c070df05d70de22312423155c07f0993a255355cfb2fa3" },
                { "el", "52c6fbdf267d04f19e0bee1ad330cd8d7b56111e32c9723fdd9bbc902db66e922bc24def1221dc98b114e33ea909fe01d97e0deb71275aab0f170606aa1e2654" },
                { "en-CA", "1475ba52035f88bc5821e6256a89a927f11770e988b317bb0c0128bfc05934d27127aafb99afa1668ad54510ca7189569ddc1678006e869db05eb3b8695c2abb" },
                { "en-GB", "a0f5cf3cbb7d7fe40276454eff25d44f33237eece5aafda4ee3c85038c5c09a31c23859bb0ecd296a382be0115a98f33ecca37cd95cd39237df8f4de14b487b7" },
                { "en-US", "65533bea4f21dcf1c7e120aa34bfce3762c636188539b0f9e82ff9d0b9ce6b491396647a0d030657f75c760fa1e8f00c30fcc804a1e5b53cbc95940c3b6b9a3e" },
                { "eo", "11a65e8fed752f2cdeb3bde4bc683a5bdd91614248176988c5bb19a70339f0917e09fd14769379893a9542eecf3248e268e4a9660c59554e889530dcd22b1533" },
                { "es-AR", "1de57c2999ecce2703cc3027bc8fa9d09c161f3c16696390579bc1704fc87cb792e1de397283ff0cefcd46ef992273cd37a4fb18c6637f1bd1a5c60f9b7c13ff" },
                { "es-CL", "f3889aece3ee9f55a588f5ced8991a75c8d1d51ab995a90ff7f8399e90ba131dbd0e4bdc1f31d342c61c1a67c64e82c54395505ddeeee63af278d5f312cb4d2a" },
                { "es-ES", "1c8ca42edad6f9b226f3f2604fc48892217ea389a4ff691a9f7e7f4ac4c4c0af21048410c149f75f80add2f876ca8be3273a09e268de8aba1b7060c7c73ec237" },
                { "es-MX", "3a2234394dd944f220c7b105ab4401a6ca34a06c648ad3cda0c23b79af1bb6c54c1805f6582e8d1e18c0d729ba5342b2bc3f1dccf1f6b145cb99cc0a837180ba" },
                { "et", "94988c828b3dec68175d32d35dc03cdec5352cd6ddd9e885817933c88f9a95b68ba499ce630395c2f0f53c27978460c896837942a429f26886ad5427df3d9ccb" },
                { "eu", "a9efe875234cddb602ab92eb0b63541811b523eae4c91fd2b5db414b9d80aeccd2560c74354c02705e29dac34a1b95fe2048852b8c7b3725243ae7fc296e7efa" },
                { "fa", "3a394979a223299c3e00d832a567088ffebb685a6f0c085efc73da0d3a91ac763510091facbc0647cf3aecd0420b17752caa4a14ae3d86da26b165e041e569e3" },
                { "ff", "9e8f42abd5fadbf103f6ac6c32fad50a1f7f3bc7c9e65e9605d85c3a9903e813f4a7127f7b2fd12ceacec731295b70bfae9c35f0b12e1f77e799bf9a79eb2f7b" },
                { "fi", "48eb0ddbab81969038ee784bbdfee2a214cdee60a54cd63ad2fe5411709876a270aa04edfe0f401ab3eb0b71b619d73f76f0aa03890d2fb40d549cda5cdddfb2" },
                { "fr", "37fad39026ff53cbe67666e3c43feac6fa3226b02bc83d99fe1aabbeb266c8657ff4f98fd8c2be04b0d2034ea4f8ea084077b561865f1c636d232a1de6554544" },
                { "fur", "bd115cbddf4bcd9c277a55dd968d53351437ced2cf2fcaf83309a95f47bd04f9165cb8508356c3d4d2897a2e1dc82ea97d45fb178f17797aaca06db5d6272133" },
                { "fy-NL", "5707719432f512abccdaf3050cd4a2a22ea42d0c6ea2bf984f3880db200aefebc0046edbb66c5234a1a67b30266a538d4fdfbd026d977a9f6e2b7b7c73d6a2ce" },
                { "ga-IE", "610e969718de69b5e9ceff06ecc90596465676d9ed8255c3967cd45a0925c942c83f5779027903f80bd3aee3ce94a5c1d61b525cdb0885d2647a0f57b12d5a1d" },
                { "gd", "672aaa73a160286c8e28bdf691279714d1612c901a259953f7a0f7ea8851eeb51ad9fa3a58d2d219c31548046ba892d920236db1833249b432b32ad2c1665713" },
                { "gl", "39fe8a93e39fd862e89e0cd93d153434c8688bb786ea7621ece772ba835717be9d2dd1573a295048950882a2e2ef625b8c0c21005d2de8fb44b604009909f526" },
                { "gn", "bd07a5e2d910dee2a98ea4643370326c89ff5cb1ae7805231e0f1993d1d3ed1774c7fffcae1eda94e0937270ea2440bddab53f5066dd8326bc8f08d845d5b1c4" },
                { "gu-IN", "772f370c32012505659b649764bf3cf90116b0bf5844e6142e6bbeae52f61fa3a5d5a9794ef8cf6bb82879d2d9b5f00e928885ea93efbcbf35befbbf648cfb0e" },
                { "he", "2eebe839c7d4ddf78a7adb0ad02a8f630d52f292210ffc8d09ec27873d7f34e414405fc7a44e671ed73f7fc31730a9cc8e1cac401f810dd95ed0c6300b3c0f6f" },
                { "hi-IN", "8a6806dca34ac5991c2b935a2a9f4dbecfbbaef14456a54e23ebf8df77d8249a48654cb33630e2b5aa252d45cbcbfd7c975ee8d92186275b53d9fd13690d46eb" },
                { "hr", "2e713874950e03a8b2e93883ec40be47eac757ecc68a3ffa9638e58dc4c7364694fea8326584395bdbcc5030f8cac46d089706c922ec37b2b17fa4e572bcda2c" },
                { "hsb", "ebcd4b4224637a8ca613846585ccfa64d19de8df8d7648eb25c88d6854cee5806f653d63c1e8272b02831c5cbca5ae6012b5bd4d125a004434809671c1037b8c" },
                { "hu", "d93ab1084f0d4880bbf545452017ea401a6dcf4fd3e66a2c6aa91688cb098485e1984f1aaf8d1ea8f623b671a4eb70c3789c22d41b2fb265a2d8016f34f9a44f" },
                { "hy-AM", "5d45e00a5776fd84ee5c40787656a66c41a535f368e853259430523cb64619e2f08bc78ec59c0207701dbb5b969026faf9ec69b67b23d9eb6a7f7098c6d50dbc" },
                { "ia", "400f58c8ed1d790d124b47e7a3a4ae16fc0d1f174d039b05e5aec77234419c74bafa1b8ed72fc18e7cad7d48c372116a9fb6139cf68e1c0d758bb360ef1f66a9" },
                { "id", "b5d6d5fde24a04761d4ecaeab547043f81e79f73aecb8b5a82a737f93d68841840e50165baec6b2c3c5dc177b0161086a3925a85620d83746f5ed12579bdd6af" },
                { "is", "75a3d06d5eff447b1b5b45762deaf47c82d92a4089333e540cc2c5e02e4622600813e3ae850f62de2e12960df5777cf9caa515eeb681f8fc1573c9372d264c16" },
                { "it", "9d758a3000e10e05d43e2062927e2f5de89d6740dcfe25107593a1144d080c1cd2fb210429b3867bc097f9856e956f65551faa90acf1ea72be322e5fa1acd2c5" },
                { "ja", "c854773fd7b707824908da18aaab9b0841babe54eee4169ee872bb51569615bcc77577c653dbfcb8939d7100293171df0b207e883c21c0c1df3f064414fa5fae" },
                { "ka", "f6d723f88c899049dd9805eb22b21143de11dcd730f273f310d147f0168f42635ada8817b781dfba1b0999ecfae5e01e4e73c0c0833d1fa5f2fa37b5be2d5642" },
                { "kab", "21478ac419730b178c8d328bcd684874ab45cfe0ab444549a8d278f9995d56b97ef5451060913682710e0862c1cf28beee798bb03f8fbf2e4b3a2cd8d35f5089" },
                { "kk", "76274e22e2696bb8b7d41538e7faa9d4eb2d802c732cb9c4eafb32a0678c0cb56c800cf8de246fb41e93ac444e624176650d8f5b9b64cd8e75f47dba0ce18007" },
                { "km", "b53bfbbd22a5803cc30246e0c16a65491c456a6e68ac0dc15f81164310cb348bc94284cf3bdf7aae78e0c44ea5b28dcd16b101727521e5b5e3b7860943be6981" },
                { "kn", "f507a9da92307f3a3f0c3c7dbecfc818d34eafb2695da669304dd9d8adbbcad6f44840b6956529ce2cdc981e56dfc659cf53318f9c994a709de9ece419e362a4" },
                { "ko", "8b097dee2d05915562280faa6e0f2815b2a4978df23c3ca01a3e8a7457ccc673833493260d6ac35e0da78b1ad0ba3b1a7c18a266d4cac2e0002513ba36f3a010" },
                { "lij", "d99eac8b36a17eec9833287d0c1802648844fd361c97743532ba7d4585526f7dcdd96aa8fc46ad59e380b31df145d85c7fff2bdb30d6bf6dfa917b4c478aa78a" },
                { "lt", "20a19520974a8334df02eaaf6ceddbd8fc11d2f4a739a2faba52728569a9ba3255a2b3e438e36d94427c074f2cc025d573603ed773b6b4d5a303f6df608fb393" },
                { "lv", "aa3d368270cde664a601476cf435119a470c37c0f7abda9791d282ac4f14ee25540a73f16b9e48c4b72f4076337b396205bd9aa607de59cea6d100bd6553ce25" },
                { "mk", "debcb642014b70d6e75f415d3870c4e5c927b7f0bbdfe502e92fbad792780b4297ade0352af876a59dbcea73eba11b95a7c64feb1f88c97f3b6305de3da2c710" },
                { "mr", "331cdd4bf4196549280a3d6e6451fddf9af8f5a175ffd53bc77a348211944eb5e64e35812475416aa1edfd97906fc165b601c108988bba88be46f3a9bcc95649" },
                { "ms", "233215e294a557f699ae30d67c2de0af5ce2c1721020db79c14b2f5143679d4d5e031b72ea5818afcfef7575df7f819f7f842e57a972b6e0395953898bec9314" },
                { "my", "4bc2137a254ce0874b25c2ba8dad00363dc4feca8099076f6986703d9bc118eae125b3422b9528ecc711d7bf72e94620118ff11220fb2f00942be74f1fe9e78f" },
                { "nb-NO", "63275f515f542223d959de1521a7f17d2c01305d356676ed7793fcfccf32623400fc919aec5db6f045c96fc89d3d8535050a15da2d225213f449db74295f048c" },
                { "ne-NP", "243cbda49f56d841219be3972fa7dadabeb55726d65cddf47900a6926f178837a647ecd338ec91f2a29dc087739808e797fbc2951c6d2e07049368e4323c3b08" },
                { "nl", "5183c13ccef6e21e1e7180c3b96732e42b781836cfabfd9585b301e1628e77d51c991f09bd8603d262b17be4e02156004de0827e3338de658e4f3e22a72a25de" },
                { "nn-NO", "ec6a52bcd5dafc625ecb234f765da41bd57baec5e15eb3ba070070e00faff3c7d084afaa7ad25750aa04baf0c263332f1fa7dea215521110491531835b7a0534" },
                { "oc", "a15f02678c640494c08d43c91f72a18b0f161b3df211648261ad2ee8f2cd4ea6139e6afdfd1ccfa60ec74d6f41952c99ddc49fd86e43481b1414f7e99ff12e04" },
                { "pa-IN", "7f7c4058e069a454c177e45b4bdb1aeead2a950ff5ff52d582e4a039999c68741ad57eca0a449d5fc7a27a98da2280d83a6b1c5fdb4b0c45c473e5eb6d0e1a8e" },
                { "pl", "5f2e75f700f7e7d962ed0395ebcf13b063ecc364b0f5bb11b7790a03b001e7e6f46f7310c0c3c61427e8d18f2bd64093784f76d6c3b6f078d664c00bfb35c18c" },
                { "pt-BR", "442a2ae9d8b3163a98d6401beb31038b3b8196cc2631855b5c5c021f89b201a4f313d829a883c9ee074f9531b1c242d4898903a0f15734033705d06bbdf54bfc" },
                { "pt-PT", "ae86b366534d23f936105c3406a30f5a08e92fdf52df694315ead7f83106f6f4edabaade7490b38b29cdbd759a571c5a7c6cf9cbbae79f5a327eba4497747840" },
                { "rm", "2a66961f17480b072b1c30ec87573a2f016d7174462d5e514f4e7888a4d4c4e415fb4dff234443e0095c0ad661b917a5fcc8b8dd10e55ee5327e2cfe9ab868e6" },
                { "ro", "6c53dc2417e0bc6047c797fc3c67635c7662f49f5f0ba9c4003165924ff8b35c8202a3e60ac43051870547cb77f0a38cb05280b8990f36b147725c5ac830ea03" },
                { "ru", "23815a4a9db7aa5f918cca4e89f76e6499581e80b17d3dc527db9820e2569b8377521ac5b5dc81d5be011cfcfde779b929f2b9c718f7f108e82b8238300f652f" },
                { "sat", "c14c4cb71b04a635aa8f3de54a0654e6b639f3c848bce5991892ac46910fff7b4cd4734ff84285a840219536444b6238f12d754c713b01aba5a691e9532a9fd8" },
                { "sc", "a81734627a2be2f9aff0790e94411761fc5a631ce4d7ae37da3d681006c290fb3996616b45c157c0944c54c2605a30f5020508995fd8bb0c2d8d3f6c0c671058" },
                { "sco", "90d6df00eed3cc028fcd5535c3d1a6a4ee2b3da0d85a5bde7111601933fe6073b8010457f36fb6022e8acd90a096a2e8cf808ef0bd29ed0da6c78e6ff127931d" },
                { "si", "f742098041ad516f90f37cab16609ff3ec86b10f15783c87c33001378317d8d1840aeb2d734eb55aaf40f5800b74b312b127974c78b1674425c7b42bf061502a" },
                { "sk", "350a6012a1e64217e308e70053f2b7549a9bd4edcbd21cc25082f26faac8c13290f651f69964ab5456522082cc670d560fd1804f86674d6580b16902e5ba322c" },
                { "skr", "bf220fdf53203faac779d3d14a11159e7f3966b9a4752c1103279243265f410e5ab00aef98e5a030c92ec49f9d37989adc8f9b219fea250bab3c46d7ec6f463c" },
                { "sl", "454fc069a4d0c54aa115efc56d454765f85af1d5762e31dfa2ef1d9cff36a2723800a9ea33411041f337fe8bf4565d7f8378c58e60263a797b246ca344c54620" },
                { "son", "bbc1c65ab337157b3032f46d5741151f56e0fd666a53ba7d71adfc4f72fe3e0b7f4bab99470d587b99d322b5bfae8e51463198c0ace2efab08bdddc753dd49d1" },
                { "sq", "81b1e3f5da38c35ca4ba002feaa20f3ee44e5bb02e9375f8bd2a738f0f539dba66fa9c0463d4dfe0bdc44e0425a30d3a7582892a23817e7e032ae9b6051beabc" },
                { "sr", "14b2a8b3e589e29a504f242e84cc5453c2a023588fe4764ae5eae0f10469aefa2787035251c6b6338e61c374b4995854a5736afd64a5dbad05e82557d291b9f3" },
                { "sv-SE", "7a6d48785a6f42240b350ac0498ee0131acfcda5e65334941bc9ff41b9c12e433342b3554820b71f4653de6ddfda141ca38dfef3a489e3aac0eb7172224b6a26" },
                { "szl", "d89063542d9c89002560cc122f93be44658397d9bbef71b7efe828dd43635d12abad2230ecac5277cd2ec89ae7162e15eea1f7359221c2c58662b43cbcee88c3" },
                { "ta", "c85a686dc7a969c6d2ea4d3f5bb1995e2437fc7abcc58688397d9115825341e875bde3e44d5a8562f459b1af251a7f0936dc9e5b487eb3b59ee6383b02d3aad6" },
                { "te", "6f922e2b8cf32056d1336ec90acb91eb4f73d838052fe08cd05dab9c589bbb90ca6986f54219379f65a87db63c591a8e72f506415242878092ee0b3fea1fae3f" },
                { "tg", "4f21201885e7955999cbae892dc4ad56dd1d4a35230ec5ccf2da0a39b698fa09728559511f73b7a4c9d33c04748e07f52885f74b168400bd91ac8e6a6bef4286" },
                { "th", "1ef1c6088c2491c15f9e784308158901740835f642fcaf554ea28662523ab2744ca159ebd04aea91f63dc25d30a3bbb5cd9042c8fcbc7b94f54ad86e2a89ad62" },
                { "tl", "66da47d346efff143694c65ead706febbc33741817d343694d33ab09b90a1b2160938736c1c7f57c0b5aaa4968b57311b49a1159dff8319c5d6f5c539eff190e" },
                { "tr", "237141b6bdd71eed40f8d5492d8e6b6db30d495b5a66facc0a3c5e8f10a472f8b78b01329d0dcb58cc879f192241c8c3eabb66ecf0e6892e856ca1208928ded4" },
                { "trs", "22b7e78db864e1d80d9e5bc6d46ab06f142e54c300ee3bdfb232ff6675df2681464dfbf185af5e0821fc4733fb6b830cc9f3c4445141de5fdfe744b2979c95aa" },
                { "uk", "18a926d0d474547c731c80b09905f1d3bb1489a612fdf232dfd91092dfa3aa48c809d5af37c82da1ad4c6a07e6eecd4dccc91bc79c3f2096898b9edc318a1cfc" },
                { "ur", "3d101762ed56845091f2cb931ec283bc4578c84727ecad494710edfbfe7470cb01d0aab2c0395a86d8dde167c43d82d8b495492bfc6771697a552c1cab0d48e1" },
                { "uz", "dca14e9f21367f8b3cc1f0903a0d3d341274a1e87f976b11fac7502f695dd99edace33f70c73cacae243197a7782bff58bfdecffac429fc93b3315773fa2e625" },
                { "vi", "deff66291f6b78d57d527cc3a9d55add7642fe174dbcae2e3660f1acfea847770e280e56dbdcde899d85900d4a4c3bc5abaa637be93c5bfb46c9e1ee52c91b59" },
                { "xh", "c37230697b423071a31ee481edde4bb881a7a7213a0640598c945df994080396dce5974733d2b8be08a6b8060b1a600eea61202ce54bfd677fcf3606143fbee8" },
                { "zh-CN", "8133830b9a510c213f912b1c7544580bc6364c9ca368fca1322077b74a59297c01cc2b031eba2140e5621986ba99a498fe7ac1ffdf89bbe943147f9b04dd8891" },
                { "zh-TW", "42d941c7fc3ef47aaf7932c462c4894a25083cb308ee843621e8e7f41f2f00790ee5557e50f26289f917f4db731057906f6ced1de5467504ee10e5747e7279ec" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3260114c67f9fbab0ee9429156800b104c6f45f276532f1e982fc78d6dca8ab362f6211a9f09eced8bfb43ebe57cf8a0ca88afdfe4ac7c200fd9e5af4137ae09" },
                { "af", "b0c8613217dbdd34f304c8f88c7f1f7a8a9dbd6588371d0f00b92ee9d17b986be6d04041d44affbb02698741d68f08a09cbcc32ae0bd2e2ed8fae7ee3da085a7" },
                { "an", "6ee650fa4f04251aab2170eaab56ffe103db5657ea5fdb6a2e7bc95a9851e3cfc2a5830d56f8c591a4971e9fcd93f9d315fffaabd998c4cf8f8b1cd9797af5b0" },
                { "ar", "3396591cccc71279fb37cac1167af8da77317dd1b545f11bd7229c7c954a51a5640460d0aa6942865121580f58579ef5be2a0ca638ae5514318b3246d83c204f" },
                { "ast", "b6fb8cc4d51dae80ae6feab96fbb54dda21a86c49feaa2f66c506fe1d9c457654d36630833a3ec4d6494e83e60680e2cc28403f871d2e9bb2e6ba5456afc7234" },
                { "az", "5c45374db9fefe54976094d790c189a395dfd4928fa483a21bc1db015e0cb2bf6eda9b9c98f9cd74300a226b8d1b8b73adcdf93cc58cc4ed5f527d2ac3be1ad4" },
                { "be", "725eb608df7e134af3a63e9fb79ec6fd98b2f82e280185f3dc86a3472eeacedf7c941fe18330ee564e430b8b8dd0d8f3fce050714c72d6d132f165daf0d3e41a" },
                { "bg", "1db956054d1e709c9f606f65397c1c0daa44c9a6d92ae9c1bffd9639d5c977fd6f096aed5db90351a0e518fcaba62c6c15fcd1fe2fa9e457aa53ef8e0ba936fe" },
                { "bn", "ba14464e7320e42583b53a1e5046a43c9aaccc5100f069e41c8ef45417a293d7c7e8ead24b360617f28f773b8026adc421127df3f3b0a4af19a975d2e4863d30" },
                { "br", "b5582491b3ed9639a87c894bd3e64f7c75c732a825e6730fe554b6533af0871c9988cb4c4be2464976371de3180d94fe952bb27f26b148389ec41d18132679d7" },
                { "bs", "a68f1afc606242c9c88fac8166cced35c82a886509b96d6cb89e44aad33d1289a349390b55bb0539f3e7a4dffdde5d2a8b6601dc29b757ad1fce6ff5c1b7584d" },
                { "ca", "45a1cb6c71fd274ec55985c5562404c4d7694ce2d2cc5e36ba958217b2059588fd184c4cf76933b8fef2ced81bf5f793426c393d079fc1ae1e8d8be522f3761e" },
                { "cak", "17db3ada163931c8da108db7b15693435a54b7c0234ed03bdba27a990e939c966838a0e3f6ec3949b36617d3aad3b29cd07a4415df0d33e928249c2f0bd9878f" },
                { "cs", "4bf187dcd375e0b2cca608782397817161f00f5cfc73eef95ccc9d59c61022c26c9cb064312a716bed12bbe8d0af1ede23ccb2e64f212234b61fd21f28f2c5fd" },
                { "cy", "bfb6b19fd2703d13ca92e0d145be0927bdb77cd1b22c33093a0c2268e7797c7056eb683d1047a1239ba3c60290cded1b2686c009a8bf100752e5851f0321fd7b" },
                { "da", "d5ea7999c8c44d74938b1b216f49c500b36acfd00ef6dfc8b26967232e844a24ab335f36bc908264ff06bbda176ab169a49289a195f187308763c796ccd97e68" },
                { "de", "88217e7fafeda428bf47b30cb6f2c81d95033e192b87f1443d40ecb992b117a70b4f7df71c68c8092a925ce7b128553441926facc583b311fa6d321bb88d51db" },
                { "dsb", "5dcd7d32add3a7028ebbd672d04d98c4719207cd12eb757e3390c74c2f1c2a2d69a8f6d267d6efac37b8ebfc8c6bd3e40f37c1b87d72fa4e9f6d1536d7b6e345" },
                { "el", "f92c2971fb20e72e013f78e3dbadcb14b1cf0dc8ea83c72795bec8759ec729bd12c08f32a323aaba5dd9c62d0dcebc02299be7d01bc5eb71f13675a89de7bf7c" },
                { "en-CA", "02fedfdee2ea1002a21316e2b642b54578ad4959a439e1948f3d9f7e505d055f7787991ffbe59dd61d2ef4aeae4386f5d19deda01e6132842e023d56a8539c77" },
                { "en-GB", "3d95eb33fad26fa70b4be8694d79d4610aeaf064b1e87dd3b1158b9c5d553d69476547fe7526e773434b75546e433c251b428b14405c5056053fbf552fc53785" },
                { "en-US", "65dc8af49d48375bdd79ade69c8db4f5c7ce9a12acd2fe2f60f25cc47dc026814d55caff7b842952809c280991ba5e1f98997417c4edc9952d0e7a8f6a9d23eb" },
                { "eo", "80a30878455007459a0a1b40376cafbf97db5979075f1983ef7575559d5330ef40f8aa9f78101e6a4fb5d6b2906726571226790d2c9e85b885ebe9d363f0df00" },
                { "es-AR", "15cb7bb43aa4dabacc0fedca6f57317cb09048b82ff7366f8e2e7cc67e9d975766f6ab0bc8eb527fafa14247d45cec261629dcf8b80283044cd401e4066e40e9" },
                { "es-CL", "550819ce6a5dd643114093015a9c8a3eed2736e88037ed70cbcf49e5f67d2cfedbc0a3dd7778868402a5fc206cd7a09df80bd054bec3d2070e0180dd84a13aa2" },
                { "es-ES", "f7d150b572ea9590b6a7659ae9ed4c4d8c6a928f0e84a8f1e231a890e8199310420642f19bb3560ef364bbf44b441472e609fe6b6924bce6e8da013e07c27cf0" },
                { "es-MX", "1ccf8ea8d10bc21010b18c81c980c98966b8219ffc3ad03d7051d018d0166d05228af79eb7f692ef5f4213a8d7f8c2b4ce7409a92d1fe552fb64ca5825645544" },
                { "et", "618ed8e79e81b60d0610e00c775e5674b05610dd2fa6e46da6ff98151157e0c10414da142661bf24efad0e490fda49811826975ae5781ea3e370a8014363a1a0" },
                { "eu", "4bae248e7a0410a1878c79555078b33431d5a0da71fdefe5e144f80f54be361c0f7b319ff880bd0b2a77b76edddf837e1b3a4257c321efdf7d9302689710aa89" },
                { "fa", "32222c5d5ccdb6a8d67d5b8cb52dca44a7dc31e244d2979dacef745dd376b9f7436b365d7ff7fb605cc0d1f8daa177a3d52549343bb3731829af0cb3f6dd9928" },
                { "ff", "01b02ef2c4b053ae182faf9c112285b95e9ceb07e39fe3a03e827c00953cf4715b7507899c421ff28d5a05a2293eecbb6b64071bc9ce3f355ebe9d8a25eb0da9" },
                { "fi", "03521b47fb8a6cdf219328fdbd6dce69c06ea0676469944a1ab19e0e987375ec4ad4c921e4ebd65321d169c4296009f11d282172fdd07a79dfdf3513c8f15ee1" },
                { "fr", "1c3214ba33c5bebcee5f3946e93ca3e0263aaa9228b86feba848cd990bd69fbf2aff9157fb7268d76ee8aa0a2ee8677b98ceef618542ea7e482d95c9fb30d602" },
                { "fur", "8f56298664de0eac46f75fb14c12a78000829c33df3ce0b3ea429b97055e87a180af12c2d9a4a84f325dc8c2645cbb24992b8d95c7a3e3ce79762b8c4aedf77b" },
                { "fy-NL", "6b0480750ce3c616191099526c9a213ed74039ef04592f46619721fbfdaf7cdd1c9e780854b521030a23404a247e5004d2d2cdbac825242dfe3a51570bae63ef" },
                { "ga-IE", "d24fc8f139dca09a92076133e14b0e5551a6cfbdb5f1ab7dbd14dcf3075456f36f57e4251629339df8aa6ed22cf8585eea82aaf128efac06dcd7b562e69b6e20" },
                { "gd", "e7653fd7746d12e44f985bc85de193e3529366197eee7568964d526c1501a0e9ccb42e8aca27e72b74cb0bcea6ba665635c1d677b6b215b2777a83bc6f983742" },
                { "gl", "d05a41bc454199846ed04d00b8bed68919eb00c2c80c8cc7fed95fc3b889664ca30004493533ad0ea978d1ef9c987ae7a9ba7b7facbf43e891e11f3b89c6b4ed" },
                { "gn", "febc12b9be0138989eebd1378a77d3248c085b25e078dbd7b1f746f2bd6745e702423c98ea3f028cd6d77e07ba06f9df61a3496e3a2431ec5f988e1d4eed154f" },
                { "gu-IN", "3312769c4d74698cd6ef632507210e129251a9eba71528f6cafc9683f06cf5fa557c81bbb65af7184afb9ce564f5181d679853f70510f68559e20f54ae69d1d2" },
                { "he", "53943710559e201f15d7c2c94108ec5dcac7177afec683452c391acc2505bd8303f264d065bbf46c62f881153d0722ca9ae4d23921f00948f250f3c55687e252" },
                { "hi-IN", "7c777f30abd8334a178063cdf046a147ddca82d537e172320eede15a0d8f3b6fb96af7cc4b118b055467e2647355ad14deccde52fbb52ec3b27672c22dd2278b" },
                { "hr", "25039e935cc97a608ed06874f89a1f698b2e0463288f5eee5bb996ff5c277b9c3f98bc0447c7e6221737f0bc2ade000be926bfd896da87faae89d7a9ade1b5fd" },
                { "hsb", "64949b536f9da53088c5665175e70f11c8f4e010408654266ce0d95c860562b24597fe0ef8fb8d2332daeb405e3fa5c8a401d672cce67f747d2fac3a0e3d774a" },
                { "hu", "0b97d9dd912a0de18e56427618c007a40f7ec187781b21dbaf58863af77e311ca17953bdb0435654162ecf58f9b57b3fc596d8a3e9e8c6b9d914a556167c45f3" },
                { "hy-AM", "5ab394dbfcceef7111ca40d58131962015968ef4b828a9b345bc02177c9d2a70ea89407fdfcf25b557a68761a82b1a9670125a4a6022a56f4b299a3bb9d31652" },
                { "ia", "585047220ad82c612935640585084811e7de1db0a1b52e06cf0bff5ac155b0fe2b69a1ef2d6181c972bc099a53da0f404f2c453d8ca73362f4db42940faff547" },
                { "id", "bec2fa018fa890cb862c12a3e0bfb64539174a7004bccf8abb6fb7945a2d0c0a2398d5e5cc12e0f9cfbf1a5d34120258cd93f06e9624be62a2767eaf64fc5388" },
                { "is", "685d943a423b614159f479de9998ee083f6cf0623bffc942fc32e48e79b83affcad602f18031823b7967839723408ed333c208392864a54a15607feaec0742f1" },
                { "it", "8f2f016c8eda2a959d11b6a4384033858c434db3458166990b195ab51ca9f39263af2933832f79d83b7b24d49683fdca3681f53b365098e2ef117766605ba6f8" },
                { "ja", "7e0d529e723a9299738f5374ef547f030acd79df5e600aa98c3175a3feab6a3d5aee2ea307a4c9e98dc59747627bfc0ca261ba61e599018a6748b7c1edceb465" },
                { "ka", "f06331b6e8f19cec524fe94ca5436eb57344ab177b7971aed4ee29d37cfd1e5da5abd353ad017b4ebe7c4b932b155f998f4bdd2b9acc72c3a7743782500c9c8c" },
                { "kab", "030d974c34dd450b9e8c9c8f265167296179ca8e59b135032736f72948b86009a1545acaf28eb6a3ced182c84b6bc2624f00269a08dd310e44b89e4cf8e8fca0" },
                { "kk", "06c4acdefce7538be2d0098e13f522888d38b2698f2272bc7b8f63fd950a8c75f5cfa863942a1fab43c6c9bd39ba233ca8b8d8a2ee6161dc6d7190ebccc26558" },
                { "km", "e98862f7249aba1de01f4f9552bfaaff6b6d4e02e0bf88ffeb13d3c2795d94aafba87524749b28422005537beaa88b7c69581578de81d5e364cc001811b2a93c" },
                { "kn", "da0e947beb5b6ab5cec54ab81e11798720e282e76277b98c7fbb1fd352d1367c638eeb5efed37e267af86b094dae5e44eb261084e699ac5c533f8c27eac63bd0" },
                { "ko", "f171dc8dbcecb597a6976e6da71c47038d6ce7304ec211e10b608c3993ea562ea4018167306aff61945f4743392bbe8ebcd1c53c6a9e4f64f377a5be43eb270e" },
                { "lij", "27b274fdd6c19b07b1c362ccec47f113ce46ea46ed4d67a80939e51f252975df9af2869b06b4f3d6a6da33b0246019da9634249c7850aea7894edad3dfebf2b9" },
                { "lt", "c72dae2815921f01e5eea887d8b2949c9ae2233e53e5b7e43288cccbebf8ce6f090e4da57382585443ba4cf64727a0a57090c19eeefe3b9859ce6e3e37b546c3" },
                { "lv", "fd99821af493759d90a7b8eb403cf092a7311db15a572dc2aad97770cc3bc806cb4584b5ea2fd2294309cde601e9547d0bee11d73ff80f73c005b7640908d1b4" },
                { "mk", "347dbca048b51d175474d104803dc27fb31e6420847aa6f6bcc69697bb5a420a6205a9ba0054c44ec989ae8ce7333cf89905734b307339f00a6e54a86b3afa08" },
                { "mr", "c23b1926f5e4002e668f0e8b5cf36541b83c6e25ba79b948b1b30f94c9496f60f3ec327dd486fe831348767b4c0dc971bad1c4e6e2cc7e0eca762cbbc303cc80" },
                { "ms", "0a1c9f4da61689cf8e98ba75b2d6948124cb456a5688ba16c5c59b505ea7d7d6a0f99588c45ef555975dd664fa4436618e4d1a11e49dee77ee15448431302c22" },
                { "my", "12e9439d0d07599acbbb73175efb3c6eb21724122fdb105dabb403fd4106dfea1c88b187403396816b230c2ab785565ee0c763298ad8cd4759d121bb103e50c8" },
                { "nb-NO", "1a304d6f27eb92a9adc4b96324c661ddb5adb90fa6c8b91b926a362a8ef4179d2bb01090a91846e0402cac51fcc1ddcef7a540a3d317ad6d0510579afb166248" },
                { "ne-NP", "243b10af08223c5d55c61e1cdfd43398ead08e007b3a6d69ee73bcfa65131c78ebab81aba7486145abda9e913132e2d944610a92c59d1a2ceccaa1544f0ff044" },
                { "nl", "9da95fd6f36a2af587b9cd1d0588cb4f42e1d00cb8bdac20b839362458d156ca7a10a911e8d46e72a9e728e83522200bb90ea2919518371868f9f7f9d5ad6541" },
                { "nn-NO", "3dafe55222e6aef02540dfc9242334ad43600dbcaf79c711577f727e7a4823eec206afd2ba70fb0b4ccd81518e94b81191af0edcf5f1ce7a8a8c08d6c9e2e020" },
                { "oc", "6668b4f600182e515ce0f13c16980efb2085192881fe268b67471be82ba66fd3a0f8db4470c440e7e4508177f10c5ae136e3bf49df235d786906fefad672651f" },
                { "pa-IN", "ed4e54ad0af88e9ff18896c6645d29934f5fe6158d2f02597226ef6d4dbdc909266149cea414236e31b37b8609aa2527393ff259d52628962927293b860835ef" },
                { "pl", "2b2fa734eefac06c0f3483758c5b1a2e5a299a047a98e7919e17b9ff216e572ac62bcfbdb5aa230d684f11b9fafc67ddd4481692d9e577a4f6cab24c71e43860" },
                { "pt-BR", "65e10bd12673196bb454d0c2f6bf5fe8077447a0801dc50cf3c553865733341f99e7cd171de5012b2adf407111d54d9c9d5d4586a3e00d33d3859e459b2897f3" },
                { "pt-PT", "614b87e29298a58c1dfbdd52160c13dccdcea8a76ddabbff05db286f53269206ea10284703284d38f6507ae1dcb690ce6786ca3d3f93bc573471cf74f3f53e8d" },
                { "rm", "909337a8b896534ef3876dd40e91050f6addccd4e4cfe3178ab65c18376afb987ad751af43df2797fc9604250771dd752feff87373220403f2b5f44c11960a99" },
                { "ro", "e01ba5ec793d7482adaa90834e766aecb8aa34337ebeb88da0f7e33f335691905662748457cef0c32ba7eb5cdaca3540bfe118db6ebfc44e504df7ce02bd204b" },
                { "ru", "a043c313967d531c9445b52ab196a1bc8298b32822142da0bb5c27b9ab8e9aaed309e0b8bf28d8d243d06ea50ddfd8c3647dc4a824c3b71fbe06a6473cece638" },
                { "sat", "e6183a75bc25834e252b61a88e65e9936fbc78ae2ae19fbbf11c60cf2eb9957c81d5eb56f45460833a5d741d54b0c31bb05d398874dc92b24520b4da24ace8b2" },
                { "sc", "b36d06d922b2ac78bb56f16ccf5e0a2899b3f7589d61cc743eb3ae910d015cbca3ceac7dfc515a14911c55903637be78ac99d81870f441525e2d81e997b57472" },
                { "sco", "99d76e2e78d8100bfad659d88ac135ca3457feb74976e531507e0818afb441806aceded979de5172e9610584632ec18aa4efd7135675a1cf90f37cb92037abc4" },
                { "si", "fe1646a1a4298da9c9661cc748e4dd1b8687907de1042e369cb98e5809aede139e5bb78ca14e46a37e428e7ea257d3af7060b5fa8808ff40af98eb2b39dcd0ee" },
                { "sk", "d99f9fbd159ed21a2c067587b8598f3633f27f14dbaec5fcea3dee79f1c427d282e1e7623d1c531491a75b6321822f7dc4446565352f16924f4ae0bebd013b2e" },
                { "skr", "d60c9754a1e478536b1f1c963fe03457c64cfcbde8545b7e9581a426977f0b68691d05a29255d428f5efa18a110d8ec9121a6fc47cabbfaab5e94ce7e835a221" },
                { "sl", "79a905c67ec0fd67671efa5566298fe3b1f4196c2e18be8d2e99f85ca57e51424daa9695f2fbccee43029824feac532f2ba3d967b05a75eaac12ea742f6a921b" },
                { "son", "427496d7c0c233846e2b1c8d3f0bd5c7a605cc4ae0ae8557c151ac6dd987e1641a33d144a8c2cef09a72af6fb9561816ce1bcfc6c830439632530e3aca50d126" },
                { "sq", "c07c3703fe86ea8755f934c04b790ae46c754780a926eb86938e849dd1e7d86de7cd14b2f31b2d3c5d4ab15f5b8c5729a601a4b21763ecfe1fe5f9af456caad9" },
                { "sr", "3840176c1b015ba6cc921835356df55b3158bfec93b499707714012129241ba2263d5a1f24b95c1556fa04911b60a0a0eaa529ff694b01b556ffc916c2dce1c4" },
                { "sv-SE", "01007aba430ae1c91dca8ef6fe65132b5a0c2f912c0272200f620fb73bccf05230b05824f38ec909bb56ddc927b22efb6c4b90c7a0077071c60878fd805b971e" },
                { "szl", "aefebc4049a76d2e04980da477cc6f3dc3d332381c246d541885cb6b5c0636e0b684d7b6b2fa2423e0db203c658138f84f2e42a267e5ad988958fd30e014add4" },
                { "ta", "ed8944485bc816caef4feba066dc02d1e6f01a20fc5e5987fd409218cf72ca944f3034f152cc8598667acd1ce4cdd06545f773af0f1e00637e664fef0b7611c5" },
                { "te", "b9a2740b41669ec918581cd044bb30bea726435056f7800ac14df9199a7855188614b7f3abada60b1fccb83a9679647c7ee134d6b4ed753cd0e736efd942085b" },
                { "tg", "74a95e2afa8981d7f39df02131b90fa8f9bc44f17a2eb81e082a53adba1dfdd176538d20b626885b9929d02948e4f1033b1b2d695b74b98aa40d3304d01b53b8" },
                { "th", "bbb89c7f0183f9f09ad1d59d49f3ea110c47b55ea8b4dc24d571584cc20dbcdbba1ebca11e74bf1a588f4adbcb7a60b6377962ce30c2d9ade5f0fc148a1da3d8" },
                { "tl", "9ed7dae6cb720c0e57a90e006b37db1f835e2b346897e0b03ef62b578dbaca247c4f196cf0a3ea3b04dcb81f22a85fd84a4b6a75a30f7280084fd6147e1523e1" },
                { "tr", "1161473332869b9930fee68dcf4c037a9d1c8cb4f30aa0f6ec3db673faab0d0c2c33fb59f4b00d03cac4d618f9fb98d00c727d6f3213ab0cd1e0bfa39a465798" },
                { "trs", "3adbceced170f11edc3529423877ac942902c96e06b763d0f20f549cb8366a3b3bdc2ad9d7d9a8dc9140ffdfd842ebc64ecaf72126a9df090d1f5dffe2ad3094" },
                { "uk", "b70bbf27098003a8b529a77eb475541043e7a8a140f9ecd479faecb6028a5473e336045e9abef796d469f6c8f9e88f129edc833d4d52289a9ee3fa69f750078f" },
                { "ur", "0ba04a1a6c8d0228a498086f9e582e580c91313898e566126fd7e4144c8396ef1e5002b1143ceba78c043b3615df6fe62886840c8c2556f288f785c881981cec" },
                { "uz", "794342219717f0f5a17673a9f57b04067b9e4ebafde4dd93d3b8a9294ef067c805d88de1bfd07003cc8aa89f5ad7fa724deddf8a42f868f6c32d269cd934c0a5" },
                { "vi", "2605dbb353f7b12204abce527b3cd2ca1245b0e62b86ca71c3d8067e7418ed2ab56084a5fb4e5df243377c705562da822572d93c94144f29fd8315c9ed8362c3" },
                { "xh", "f41422cafac807a622575fba282b7e5d8668b193010c2111d4526fbda54761b8f4c8a9c4e5cd61c8090a4bf885213d5963f107cf72b96707bb64e1b47cdd7222" },
                { "zh-CN", "21c05234cf74d184434c1c18287c8a2f685ebfb7c286b3c3f5cb76fb270acd39a39af54075aacf7837ebb32dcd0ba8c57af4ea38fcc938eff25b469bd09803f9" },
                { "zh-TW", "5e6b12a481e93ed8204937b16559d79f78f8bd8ac2875badb06e725fc8fdc115d0b1100921423371c691b760e07cf935cdac0acc5f54b4a5abf964b042622ef0" }
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
