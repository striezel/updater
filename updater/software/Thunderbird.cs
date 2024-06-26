﻿/*
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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.12.2/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "fbf7d03052c184b5b238385c49a7056bd2774503030c55c2fdbbbf4c15ebb74ffd9f03edb9b3027d9cd98e7f978b718ffa2f522b6151736082cad4652d1fd4bc" },
                { "ar", "6f9d5859984afc617bd05e24331df99a2f3161aec1242f9be45132cf8e2f2e2b60d6a2d4d4b7e2bccc2c0e9b16ad9a1fe683bc7c00d8c0bcb08f63a3b3f1e3b3" },
                { "ast", "ca4b18488acb418ba3efe4088cbd86fb7bea366bfda4134ebca51befb83d35981a043482c270dda9e32a38ca4dcece8fcefa951365ac7b9392ba9348e2b98442" },
                { "be", "c9cce3509aaf8f4b5273e5e418f2706c0abe99598408a4036d6f2f763b42f4c4deedc850811fa93479fdff93b5167d80713e9307c758bd833e87a937cd0ed0dd" },
                { "bg", "1aae7c23c163aab16c857a103600a4eec14dc460b34534c3b4936e94c9433058381d8765307fffafb9302728a3cc8661ed1c85fe403ecb7f22dc75bc22203487" },
                { "br", "1b9ba70b9e724c082c69373639f34e4406fca07d4c6fee2dd209a5125f553f476bfd2cfc356876ed51d235270bcc4ab40507a86f4d64f1b16c603ecda37ddcc7" },
                { "ca", "9ae52911879900fb3a75ce72d8ebfd0e0c6e67ea26438c651bcf6a8b4d9a4791706e5ef49ad0185e218db170ec271d35110669fe732525b70b4cd30d6155ddf1" },
                { "cak", "20507a2feeedde7fee2570fe73beeec4b55e15ebe817fcc08b3d75ceed90c920f63cd1f9f9b6715ccb75029e0ff459d6edbb28b8e590cc17f4089ee38e21fe63" },
                { "cs", "158b6817ba253d27c419af4870eff47310267d81dbd869eac48b06455cc8f5b467c424b06de6482c53c077444a28368d3fa33157422404f840e9bde24ff130ba" },
                { "cy", "11e17c51eac60a2ba54f58967978a8257755619ec0b44b2261129e683c72201e0ba247644f22c7288f0db2ec75a9eca6a05484f3b73b6ce0b478e1eee5003a56" },
                { "da", "c4636d2dfed23c4fcd1339c40b742671d19db50ce20c1c42b9790260913ab805bde34dbf5040dbdf8950685f10205b3f1e77a6a7ce18fa55e1d46fab4d6bce39" },
                { "de", "f60952946594b7ad295eb5d23029a6618caa6efb0948156e93c36f292ac3d5e0db3a565a57ff8fc1f32a04be7b99445db24bdb744eec7b95c07872dce64e5fe1" },
                { "dsb", "9406e3acdd247c1089d747c69aa989d11d650e8ceda92425eb17f372279886f3b3000ce8bc0c8938bbf7bda6e1cbb764fa3b9b810e5544258fce31512f6b77b0" },
                { "el", "3e5028ab5e4abd2182d1f60be8eb7edc9a9d026ed6832cefb99571417b42e9bb6dab26c355f4471d7565d157d1b89ddb91d1cb24a339648ee3a7fa425d729801" },
                { "en-CA", "25377f2f5c1aa6d9a497209f6295d3898681f7f8f431278a9fd57296a894e5222d0b781be12e4dfbc9d66318f91aee0c3ed051ae1354a7d25b3726b4842673a5" },
                { "en-GB", "522d36d2273b225b014071440372fe99552c836a68e56fcf98b529e56693a01bac4c1fed87b2de6bd70d2bd0c725a5869b3550a8e3c0fb01c4b6ba5bbc80dd7a" },
                { "en-US", "9454035c10f6763c235f8f8c08cc1adb8d1b0d6023b54885718b6cfc0fe25067c99d650db9a3fe7b168200525a0a923bc9bb4db0e0068f9fbd31f264c78bbcf9" },
                { "es-AR", "95f59c977901512cc0df389c2eebf05955a1b60e2bf578078fd5c1a2cb0143240305cb8df9100c567e8273e91f063aea5aa124e8198109a67bdd58b9a932b8f3" },
                { "es-ES", "526a4066c06e7f21a670dcdfcccfede1e3221761ac283d3b629b8f7f644c013924d2f7d178c0d2086695c25939eee07f736bd936255e1a646dcbed7b7f6600f2" },
                { "es-MX", "d4e92f4dbc43515f9257be3dcb14400555d208d561ccfad386f49990beae302ab8f92a316679894df838abaad30c3c831a12559791eef85e4f6929e5d494c0d5" },
                { "et", "46131a6d8d9e976df09372fb006796869a2c2b64c2f95a20f604f67968b404efeb56d8d6b560f00b3560de15e6a81e551139bdd7492fa581ed9fe1d5ff0577ea" },
                { "eu", "9fdf7881292c5811bb5fbe251a5e4b62de94b91693420251179fa03fdadca2554bee613ee6a35624aedae3dcab1b8d4f33c6607fda67ee7bd82f0604cd5f5c54" },
                { "fi", "1261bed807fd8969eadddc024bb52514c74207a6f05d531cf4c40b6926e7dc1e1c7bda20716f00f3f2f9421d1343df43e5589f0a9eebfd7068ce305822b21d25" },
                { "fr", "53f7beb4048a86a504a50e98194ac27ca27f350fec59e53489e375e6e27d4d4bc56f483e81863387d1f3f04556521599e33dfba1be853993be44287c57d52ceb" },
                { "fy-NL", "99dd1012a83d41a53b952708275442b5061bc560b0fc4ea460d0c3c2f0d5af0efa4e0f5ae52427ac96c89566ec94b35d3d39119959c2e8d3abad55054325d28d" },
                { "ga-IE", "e63563b693062cdfe8a4164b45a5e708d8fb92f10e95652d87592c46e005566f617e0800c713a9374fff080784e84d7384271d97dd61a0b05c340ecd408d7ed7" },
                { "gd", "b9b4431638c044efe47805ee3d116858cd68d856749c8c60e750a1fedfb5136e9fc34e12eb1cb0fa5c426a2914e5e27819e8f98e8f4f6ad6c017a711ceb6cd5e" },
                { "gl", "89912f6c43aa1b35e6e4c1dfd282638d78afd56054daad94e6bbfa5ee00b468bf110931b651d2b7d3d30a6cb928a727ddd7d9778ea96049851ac8e923c0b2649" },
                { "he", "1a87006f1e27f2eb15b7a43949e4633c71dd16b5c469e6c4589119d7939280020a9ef171f394445130c49ab3643e52334e0bbd193d01f688f424ee67a1127ff9" },
                { "hr", "22d314546deaf47c5cb8dcbea3a7f35d0651068145aff66994047b093a81077dfcf9e2041dc6cfcb0bae20de73b06c46bf1260baa3e835127d9b62f7bf2241c9" },
                { "hsb", "e792a10eb7f331a5c6d3bde0aea5ddeb40068b9573fd8032b29be0bef1dbb0766d07988ab9a69c1aef523efad7a1dd417eb0b51e18ce5fb37a0522728114c16c" },
                { "hu", "41baea28926dd038a4ca4248ffe87874d23bfe593623a862bc5df91371bcb5e0563969ce32443306401efed7433fceb65d7f637a74762073163ee0a101804909" },
                { "hy-AM", "0355d5cbbcc04cb19e0688f3b29e41f8bef72d4c27da6a4fb01aaf20fcc23618a8926f504ec667087a4ad3b292b0c47cf929794458605132a666ab4eba84fa6b" },
                { "id", "b01cee7cd859138a0c9f34bf546355ea6280cf372a79ae11d977a8819ca6c903ca74a1cc1f2ea534c0509b91a6fd1e49b1324336d6afc686101fd7c81c3c3a6f" },
                { "is", "cae170d3e0ee06925ff9c95de7385c7c8327607aeba54b8f369f2d3452fdd77414348d660be60b3d48d778ff09d71fb3c48aed82b62f98319da28ee6df6a5a92" },
                { "it", "4d9875e0ee48f2373b8f5e75fc85b9021eed70666826077314f140b0dc5c6da961e4feb6eedb984d07230b7ded5d956619d88af44d7a19ed408dc20f05dea312" },
                { "ja", "4f6053ed0036325db5e722f22ebab9353a4e26f287f057a1addaa995c4eb8f52edd630d29343ee64fe37b56c734dcc028599e8328b48c0b3c625ecdc2b45b996" },
                { "ka", "2323593804cf7dea6e7c5dddbb3d9ac88e447af6cf92ab8d9aa3528347ce615302ae94347fcc63ff28af256e73f65bf9402a4df00f3edcae90a2634641028f09" },
                { "kab", "6cc4257fd5973d6d9759f5fd097cf4fcb8810db88064274e173b6679586ceb980fb690c78e10fd0567d8f3f3b2a5b7ca54dcc1faae6bffe0e7a7f9de1256a59f" },
                { "kk", "1ff83d8c599be072dd7a32d869ccf5280dad897ea1dada703927666a99edcdec5b929566431eca8c997e007ebc66607def1aeb3c86337401530e5a81dc2faa57" },
                { "ko", "b76fc24106233df4dbb0681f69b8d5984e08404135b449b14d159d43e64940a3c987eaa29f9affd878e3d5936dd2a9f7d8fe7fc1e55eb755c6dcf1ace497de55" },
                { "lt", "d360342b2ece9664a408ec9381ac40c9fc77713ad8eac194498a00f3390ffa808f65725f78baa11ba18eb8246fbf197c9728975bfcfb63096d9d3741718168cd" },
                { "lv", "37d194853cf0be964a041996205892853d047eb35d0e19e0952a2dc6a970a94e7ff6bdbbcb3c81b0a4e3adc17e0d839f99de18119232a5a505db5709f8db8281" },
                { "ms", "2129a1b8d785c3da3604d9a41486537a6793220cfdca48e01702b0040661b8e451a3818b7c99a0448749035b2c2f37ede53d62f736f7b6bf9027dcf110086e18" },
                { "nb-NO", "c9f37609d0ea483ce091d1256f75b43a27ff38c24518209ba8ee29a8a21a97d0529aa73122167f8260dcc2b7c36f9318eb6b440ade57d8293e6ee9b1dab4d2a1" },
                { "nl", "10284bad1a5235f1126c193e2e3793accf793baa303104ab6e58dc479efa81eaaa597fa978dd67577a545f4be9fe0f04d8f336e6b6e5fe4fa08ca787be88f8e4" },
                { "nn-NO", "d0539cef852890eae2bbabf029c82d92cedd1a7651a826d4a9e9a9df8e23ae1e7d4a44cd15bfa1d832b61245a140553647fe05a5397442da72a28593b1150696" },
                { "pa-IN", "3d964f5ae57bf30c342aeb8a432f8f8c01d7c2eb47e63079c843b0b3b7eb5230ea06745d04f36c1531fde59837f427c8ae81b5d4fcf2c9f54d4db5599b811bca" },
                { "pl", "2022dcf4c6a6126f41fbce50353a3425b35ca03221c55778321a628dac19fde37d11495ea6aff2a55e4fb6a7f976b64949bf3919ad8613abdc047b4e1f403235" },
                { "pt-BR", "a8c92cc2b35d5dce0a987d59fbb3740f1bdc0096f8989e222e3c93738f675868326649a5d839bf3ca04fa881eff20ceb2598403d3f8717da063e16baf4e1159d" },
                { "pt-PT", "6007a211933a16e99a83b2caec7db13957c475846f0b47c2a9b9fe2974efac10fc8df5a6f12dc2760cfd6a47f97c0710836a3da4d74671fb1aeccbc62332a83e" },
                { "rm", "92b0d2b758129b2d7589df7bdce4cde2fdaf5594ead139734e50c8278bcdc8cb862680f0170293d7c9ad1630da318eef409a945214d74358a0fe87ad006b071f" },
                { "ro", "9d861b0ac9dbc7c0687ffeb19c640a41d4af7bc1ab6ddcecad78f8091b35d1289d81d5670514327f0033221bb6ce5ce2cbff40740e3cad8106a43180a021261d" },
                { "ru", "ee24d9c22a82f1e6ef5482c166dbc73c55d548620d29aa60dbd73341fb6a374f873917190d474bc086815cae405b9c5f899a4cb8e3d1e7836c549f254f31a4cc" },
                { "sk", "042895c1bca4dd25e422796914d0a6dd54f158be13d920cab7a00589c7c9b8189d048a4a5253e7ba4c4e81cb6ccc2ff80d8c85a2a7dd630dde4cc505e726e283" },
                { "sl", "a2be56a18be6be4f71bba8dc4a353f70aeb40b100dd326568be7b8697174ceda9e6107d18dd34c046f01710f3016281499b637da85b0163a3ddcea4d0f8434d5" },
                { "sq", "cac37a3f30f509d86314b8c331502ce5fd05036a9a17f0376bbd2a14c565a7b39579dbdcba0005c060edb5d3cb02f6ae9fa6a06cd03e64a8a9cc086f244e045f" },
                { "sr", "0bddecc11e490b9d420705f94cd618eeb73b8878fc8c97fff1269cc989e12628e7ace21303736d035638cd3ae845d7b2553cffd61c79e6cc748550cd0755340f" },
                { "sv-SE", "b334ac4e7dfe59ad868ce2e18aeb70699789d2f016aff5c7393bec0747c84e5db12b068a3475c91dab76cd18d0b526e63142e76b8877159175ee1095de9b9bc6" },
                { "th", "f7c456aa93a5830a4c30a4399e43c115b3f378fafa39b107e99cdd1305080fcfaa1291fd3165fa35d63e187f1b452a236c32ffc62a4c5497ab3620563a2927c3" },
                { "tr", "adad75e52d2b952865809091b63c787ca50d5f63a5e33a1e183ed7bd2b535dd7d29bbcde572de9745c04ef293f12e52492ffb7255aa12fa5fc031cd8a4228274" },
                { "uk", "5ea1c57495156f096de9f5a7766d1830868630b0447a28398b2f5cb9c5069b28913d7ad369b9f166af9aa3c95a74ebfeecdb272e4cfd73f311a2d1ed31735b9c" },
                { "uz", "0c16a6c8be3ff771e93cbd7a9bfdbc21d73a4a142fbfbdda50ceb1b363f8ee07ef538f759d246a6e2fad59b73a7dae7bbdddd3b116cf3b0cc286ba2cb6ed4d94" },
                { "vi", "6e28f488d97bdd07d9bb3d8bf6e04ffa484bed0be8a2ce1790c0900cc48204f0893df0ee6215ce80db81e2a98b3c5515c555f02537d1b2eaa909ef8e23b1e9bd" },
                { "zh-CN", "cdf7d7fb8e09a377667a91b06ca8d3b35515834cdaae55ea9bb3f9ab09078bff9b30f069ed5adf28ca842c86b52f5e340cd4436e3582c30182e5e94a89d0fee3" },
                { "zh-TW", "e0b49cc55ec122f8ccad243c81ba73067e9c47bef04a681689845487a987ff7d0397453086801cb10db4c77d930412808a27cea943c141467b51b15bc8b8221e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.12.2/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "ce0763f223859e5d79b6fcd67b8fb3a0faba8e6ee89b28486d505539a0c4c44c9af4b70cf689dd91aa8d5fdd48df95d8233b339b1194c103cda417f3e9d021a9" },
                { "ar", "b26c0aec81a3cfec01b275b65023357c9fff4e2944329cc139704875b9c795ebab7739a6f87091d8c2dc900523cd9b09fd520d8077278cea4e4abab142232195" },
                { "ast", "ee07425498479ff6eef1f02494a3005c74a1eb370b3ceb596528247448953e7950e6b133a873ccc33714333232ba964baffa6c4c39d9a1980981954bf148218a" },
                { "be", "dccae943e08b0ac7471e7a5ffcf550b5236e751bf54b75ef431216a93065dbbf5a694af6b3fe47444dd3eb0508e04eb5e203ae54c0ff6f66660a05350892dcd1" },
                { "bg", "689100b0514a1c35921f4b1a0c8bb720d5875f3d7b5f04f734e2dd60d642ae956c4dac49af9d9746f5e72cf213bae5d2967aaf2748d18b738e38ec2b58dfb395" },
                { "br", "f28c2cbfd5f8c2568fd17d213cc80d86cea2cdef9410ff84795df0b58acc70894d410b4b4ab87adcb54311f6eedb03c656365a84f4f5af6928882f782915c5f9" },
                { "ca", "410316e6c20128d75e54ec26d820074439c9b84f5fad1c9e85d8406a78a0ae024b98702faf48b45b6d828cdfbee17ffefabcad56e90fb11755e59242de79918b" },
                { "cak", "81839f3fb39945504d3c844a700874734f8eade9df97c6d490fd247a6b28efdc888b7a708de59714c7540d19d65a84ffc708967c672ecaea165020cff8d99947" },
                { "cs", "8c6906e8ee6390ad3b6acd39b8b74dc45f29a7d1e8a50cef10ca459f067b0c4d4edf64cae74d5e8e669bdbd8fa7e8b38383d9bd8b7ce9e5e08fe93201f4f93fc" },
                { "cy", "3025e1f978c1205da47663ead5bc2b4e097742b2f270f186dbc250f6d0516f4ae34186f450170d51f4d0f95d64015b3722fbcf732d37750fe1970d29696c2692" },
                { "da", "bc464869a4571d72d582a6565a77ff649deffe824fa5bb5ef88a97ba3088fdd45292ca47f62da2ab27878047f588dce3349dd1dd6e0022c5859d77e2bdaf7cbe" },
                { "de", "719fcd1e647354f05c2f5dd8a837199eeb7564e021ca6b4c1e5518b8812a726af521bdd097ec1c38c5bf67feaf1297b84b376349595f13f2873a7a107ab58122" },
                { "dsb", "abd15abf04e0b71804272894bde7acd059886f1e615029d6e18ddc2a93c05a690f4b3a3c61f52fddb8ec2049fc052fe1f9e5a8a1eec262e5efd94d3fe34a6fdf" },
                { "el", "0480ef77ba599454ef338b084f82359352d69072b4be587d2f46340fad0f124847264478ebc4a160a981019e8a9681da315b2289381ade995debf245ab9e53cb" },
                { "en-CA", "9d1222a42f0d8065352706b80b4eee88a4fc6166bb9fcbe7aa955e6bab43dff5f109725c3c298126f357ab64803c629be72cca2972c5550c8cdc61eec6ef14e5" },
                { "en-GB", "39b2e85a8a5c4be2d2c101f8b60c427dea5dc2c582901e975a409e0c13254f888d52fe7f619ec50f953c4c5a129ca813e470d27c18c043488056eedc37fbd8b8" },
                { "en-US", "4c8af71821646200827676410543a2030757f85d199e37db08249b04f79abbd7496b8a9ea7c9774e301f7eb478043d35f1d3c6024f60184757c0a55e3468011f" },
                { "es-AR", "82ada580e326da427da118bbaf63c1d894931e3221d610d42472b0ee2100536e2f01fab5e9cbcca1fa2a4c1ef9bfeed55a58f50e3fe061c616f37714623dc8b3" },
                { "es-ES", "7b0018fce7974a168510039348852e8c579e31abb9c962d3296ed936042899300acad41a51a7755472f3890eeda5674f4218dc757ec4804c9c9e151a47a90f7b" },
                { "es-MX", "429432c3fcefab468c39d5c6104a614a3b5f6b248765767be05e084d68da3891c230ec4d4169773e3d9af75d19b592dafffdeccae8ac6636168b4779f20ce916" },
                { "et", "1f5827e447a9a58f3fcd34c575de5fe6a61dd41dcb436e6293c9ae32985cc25aa98df580564acdee198e147ba6ee10b0346305360aba0c870566787d482978ef" },
                { "eu", "fea2e6722fbcad10a9c9a28616bc614982ce603e5e027d2017fb7b4066915ff4fdfd605a8241fafa01623850d17fc824a63645a3c6a2998d5c05fdb6770c6724" },
                { "fi", "cf79f9f940339834b76fe328bea6d59f3dd499b8eb5c2f75262e5b35aa095b8d387bc1e1fcb3276e0d3fdf5aa3234fe6eafe7d3fdf2a5c4894551326f87fc49c" },
                { "fr", "2769b7282d520303fab90105d54b82f540a8974cfabcc1f3f960878a197b8db1a112ebdffec5641bcb462075b71f3d710e4534ac6d1a2f1231b0c6e82ba84ade" },
                { "fy-NL", "c9a747fa69a2f55a931716c64f298758f560008a5a0981b068b85ba09e6b45ef4af3c583eb28f1b7b99dd1b21973f9abaecb0c0bc670772d7ead6072c1d99913" },
                { "ga-IE", "c63b0d3616596f5e55b86844919af4a950e29446922d3f3aa8c32a43a06a1a8376acaa88f3c4e3b6660fca1517e686fcfa2feb83079fead509d43e474d3d4375" },
                { "gd", "16b4262c40ad981845c3ddd5ba9fe95bb976911dc423c7bd223e12607bdd5633b904e86b525e480cb461d6a00e73496836960285bcc0bd6d993de92aa5379941" },
                { "gl", "6be91d7df51403245c9ca63484ee34df52cac4fbae7c81e0532ee918de135a2c0d803e30b76962fb21a418f895f7f8b2b09ffbfe616da161d01fb8b60cce57fa" },
                { "he", "05a7e2dc751860e03801daa5262b2a560cf3d8eb02bce11c002faf2d7878c78cd64522d6c518ad44883763e7746f090d1790cbff390239a230b45b432d20678e" },
                { "hr", "2e4b043ff502be3dc1b29759d11d6859dae5063f7aedfb598851624de92e514693706a4f29b020495b019bfc01e1c36da4fb3172bc5b4f5fa460eccddfacde0a" },
                { "hsb", "dc9705df6451873e0e107890e3f97ab50fafa39029879643d336198eab9a73c91dcf462e0ebebf8abb61923a8ed8d1e80343818a62c8528a20c035fbc87d91da" },
                { "hu", "a0de73cf1b7d03dc7eec6b750af6cb71f8723846c9ac060eb6a5a2d2c282b7250aad68d8688c63e2b8ec4df76b8c75063215ebe7e60cf71888883f6322e05703" },
                { "hy-AM", "65a57fb162b6c479d3547f0a222d216a5e0f1d82c22c219364f6e0bdd6fffb92ef8ea62a036ec47de20ccf4c87bd48b3eed258e77172a450904bb59c977ef6fb" },
                { "id", "2506f17da536ade8e3c1ded4c5935a4bd8b20bebc3ba616d96a2232b07e90670e7db88fcbd5e348b96676b8d7da8c53ef96b81069bc85bec7f393d2b212bbda2" },
                { "is", "2be2692140d7a05a4aad301fec876b1fcf0313a058c6da29fabbbcaf9cedb130c45753ef8ce0e73eeb8ae1e71f0e4966efdd03225c5b9012c8a0e4334e03ba62" },
                { "it", "c83432c8a66225885f2283040a0703cf96115a55d935a9276aedaa6c4e977a3bbdaa4242d6b99cc5fcfc2ab63b1fa81897d9575ab595aa62cd758e02d844cf05" },
                { "ja", "68f97e1c2c17beae07ba38e49c267f347d316c0a4003fdeb5902f90c82ecbf17dc19917df9004b40a87de97dfa73a6e47883ba16bd9e145a2cfabc500e3fe366" },
                { "ka", "72b6f3ccec3d3a2b963eff2e6b10a11087f9b21ac99c929012ad4d3fb5e6d892bbbc9388a94634a119137a95a80922bf304fbacde94550b0f474be21789fe5f9" },
                { "kab", "42b394a2f4e1bf4e4823fe96cac057007a012b08fa884f131dc0d9cb57261a90737bc993242b9c2a84f1b2315be4f2fdd02ffe64ab151466c8763c3c34868ac9" },
                { "kk", "6dbd4f2aca8c652b0d4ec82169aebce94d1f8d30777dd380a502dd06371f470f9a9815b6b69aecf490b563c9eb02bd3866bdc48358b72a8a1b5f8f67367c09ee" },
                { "ko", "635140abfa067d48184da89259535128487017d402d85f5db1cadd0aded231ca197ff695e1607c9d118c0a67d5445955d9da1077de61b4128b012f47f6edb723" },
                { "lt", "fe65d6cfc59351dc4dd2c40345a54aab2784fc82e94c6db87222dd5bcbf03d5c30fb2ffb778dddde80358bca2b38eca26de8b59b0ae5746d603cd6277201fdde" },
                { "lv", "9da3c48f128ed7a03610b98fad7a385f4cff818e7efd0414bf9eef2db23edeee9fb18bf1faf8d7998968cf86f2cbfea7773fd1b56b8359c25446a1feacfd07ce" },
                { "ms", "d80f124fbb5bccc48611f32f1ceaaa05d29551e42273ac64e6f89051975516739e896131b38ce2ed59fa769ce3990e69ef38696d3f66c48ead911bbd488386ef" },
                { "nb-NO", "bc86969f1238687fce0518723a43a94dc8a85320b2f25fcc32391d4e39e7f0e9fa30e48268289ba316094b286091e49b14a8ba97b1c77a81a5a10b1edeb16232" },
                { "nl", "510194a552fa152dbd215c7d6d03a041a61460665ffc07c1f33bcfb891678a26e84c91e83b7447538450fceff019ffff958e74bf0ec9fdba553596debd3d0428" },
                { "nn-NO", "4965032cd80854139722119929a7e2fa08f107972aa2a11fc27b5e168ae323ab9899ecec0ed0b78ef51075e84670c2417d22fb4ed14cb19dc15180a6af7c41d6" },
                { "pa-IN", "f63da176385a1eda37a48726b6ad7ef27374b05a8b0880f1e9d71e7e9e7ff9b8923367cfcdff5a7f2f7fa1c4aa8c6033a5f75aadcf3a825e00d5d5635e00b6a9" },
                { "pl", "d535b7814ab7359f23b313c5b2a7891f6888d7448997a39d79c3a10c55edeb7fea1b1194e8f698e969bdee9264ed698f185adef53d7a05f313370b7e0c9f9403" },
                { "pt-BR", "4781a76f8d4d669298b21c97ab4d3c34117bc798621533d9d25fedec293f2ccd55ff6d4557c754885195f13516aac20ff6c2eaafab37a11bc1fbc579cac78d60" },
                { "pt-PT", "085250194bb7a70ecea3af53e01cc347092ae8550fcd5f119bd6d89d20cc0693cd68e99e93faca9c86d02b9b86b0ff0334314832a0eb9353acaf3a7390891476" },
                { "rm", "14a96587cdec34d6c60e52bd7f6daf4cc96aa8593520a6daacb2028851ff897143a31abf69be18cbd4f59c29b5a870eb7f27a6f69140523a65e27ca1f0c3c6ec" },
                { "ro", "19d687ef31287b82df99199ae1b09be1f5698d7309c8e8b8981e715713836f93918f4b3313be6c97fc8e1e4c5619f668f6abccccbc37af5ad578b372c129f84a" },
                { "ru", "775b62a3a354b108cc1c464c4b7bb0a6f696613c02902e89eb3be96d710d337bb209729a6a3ddbef3cc8cd3f73b68e2738caa953b8f2ae960689f496e4c266e8" },
                { "sk", "d7979ff029166ab40e084c81dfa7549b71cb7611d37721ecf43211aa5b8c3e7d399c77ff4492e2536d1b67f5589e90dab30a870b265a04d5c062b5a174f66332" },
                { "sl", "8be9ef4306b4192d1cc54ae2de07c758186788c52cd1d004ee82908310c8d7d9d3b42d9ad01722e31b8f92658b08404276433e37cebf3b39dde0c9828af9a43a" },
                { "sq", "ce80e3cc288e836759b060a26e9153e41c8d77884240b431ac900b0639bb38f3cbfac573f5b93b9e6a1964adeda1ccb2d65bff7d2dd2322a50e1d8afe9cb0297" },
                { "sr", "924c1e76073580e353b03838c6d6441f40384dbeac928c6dfa2e747c1401f77fc89935d5b3d35883ed432a87ecec4912e2c478a5209100a72eb6b5f5f6300d5f" },
                { "sv-SE", "b0a7abc5f200371080c579e11e40db0e6866c8bebde3ec29694ce1b9b3d3272ae26cfd4a318dbffdd35ccb72148bd4c3410fc1e573567e3429d49745f8fd77cc" },
                { "th", "d93ef5f52e156a7b01f7bc42d3de24a8ff67f338c568189826de12e21dea8e73453573b932a2c45fc2eeab26e588cb658a5480aa1379ef6b065c9a1c51a9a4a5" },
                { "tr", "e29ecf1e401099010780f7c57bd8942195a1fab426568494ba61c6eef60cecb08b6eb04ff21cce81393f646a89191efdad1e8de30f9acb98b645e205ffa076eb" },
                { "uk", "1939cfa4c76260d052de0de063dd1fcce46aaa9012deeccd668344f1d617a6a600a9ae1cd1822109859dfdaf7b978dc4e3593be615daf7badea5fea5460261cd" },
                { "uz", "9a7b801278b1a63f849ac8d3a7a9b156d30076a55a2ade46f113d2966b42210cd925b3a334e4c42610d674986abd79516b61fa293507628cec06349523f2f8e0" },
                { "vi", "20a77827dab3d2f44e8d00ef67004648d30cb3d7855b0dc5d528d4d2e68cb138e6357b62bc1fee214aa903d448e6e30af0371431af4a6663d40e747f19205bff" },
                { "zh-CN", "69c8c1e9d92ae8d2c8a65f2ddb44c23259e7ad2c8fbc0d194d2eebb5aa62fc6e00ab24d81f9669dfde65dbdde3715fe3b02e903460fd11bda00f6e56320fd47e" },
                { "zh-TW", "5a02c28ea6823e56dd7ac66a12a9d15ea91fae80b85d5f20bead43139286e98d5146d61c57666fc3450c0b7df8447ebfca0ded99fd97c5f337add620a9620c67" }
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
            const string version = "115.12.2";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32-bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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
