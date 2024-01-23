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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.7.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "31504e4b8330e44e2d93e70d403a1147cdd070cf361f608a72fbe8fa37c37de223b71b0000e2c25dccfcf98bc30e4b0a78b5fdb1e98827b259a41dd46b1917e9" },
                { "ar", "eddb4346cf1fda93fd229576d4534a1680a051206f49b26b440318eb9400514a7f0d8d01d0cb5e126bcf3d349367a805be3ef311ce9544627d2baf79c62787d1" },
                { "ast", "24744438039a1f58b1cdd1dadaa20af022e3256e8d00dc57d693de92a8b60e895be621759733f9ba91fdb7e17d598a272d5481f38fbf0a5a679e232eece652b3" },
                { "be", "20478225b7fd5f1f946e7034799cc549027f88f96902c823a76b753928304fc413ee20d5bd6451a2a837da523983a59de3e1dcbc7a7accefb650d1c3bc4ab983" },
                { "bg", "d2de35c44cd93f6fea2327929035439ccf96323d299f0bb6377ce1a280c769fee5db3367b9f0a9f07b84059cc91dfc168730d519020705c1a316b8e248dc7c06" },
                { "br", "d1f69b8d34874210336f0230a42b2b1c2ad9b18eb4fdaa07626d7d07ce784bf24ec1a6e60b45190b1a39a2fc73f5b71b33f1be908b51d5681c7c6cc886b08b0c" },
                { "ca", "363863421fa68368008ac40909ff8923fa111419c1613e2831ddca15f328e56ff92d9999065c1d9295e4bbf3bc989c5b87f31d8b1ff1d39a2ee83a7723daff0b" },
                { "cak", "a39b4420bfcbababeecfcaf54147e6a3541a15f3143084e9b419e28baba024f831e584852f569b7d4cca7cb5a9e53c9a35a285b92d02aaea78ad8453e18edab9" },
                { "cs", "b0677849a7ff6d0e4652428645715865f61af17f77ea658c7c93b4eb91520714e1f3c6da21bb01c50dc63b2f546a94fc42fa5b7528d6d56505f4d0fe4504dc1a" },
                { "cy", "b1df0b2504906879397aa2a654cd760e23bd84af3338e6ef24cd9802b4f972f3a5dcc0694d59a439ce8126d5e3eb310a55bcd1d9707ae03831eafdd58b31f6d5" },
                { "da", "29980d2f816452c75eef38b8434d627cd776332e1b5c936ce1ca1b71b281116d7ca82699b58447faa2e39c427cc85d5980232cb4cde30d7a717a9dcd76279bd5" },
                { "de", "3a38ea781e0f78da3d767f62d52b454d239e6a02c315632819a4178cfeee276f4251174a628b9f74b8a5dd2dfef3c8461296be2bd3f9df7ac77eda911199db5a" },
                { "dsb", "e42a37e1c2f9b51933d557a67d7ea28d10064f36d4372d4037445ae136e6212ee511b7717c43ffaa5d2c5303e45148618937b6950793ab82c82de05d2337b124" },
                { "el", "f377d5d126a7906603f81e510f4f8cd55a3cbff9ced14263fefd4ef8ffbb3470704dfedf48b70899001f39a4cb98ae3e19bd8609d13881a9c0ffc922ae88158f" },
                { "en-CA", "8d9515c8827f9c4d0ab5795781b17f58cbe2b5c0578e35da4fcef8c3a281c531bef4cbb14a565973386e35d27f7c87b6afecde372c5153588b56d0b364ecf1e8" },
                { "en-GB", "03130180c10764080558d05d64c00a3b3b1e6fd5afa86f5c6071b95a490bd686e615ef9c1cea7dda6bc490f0558a8a0fdb7dcbe7f1fdbf5771dbcff06732df5c" },
                { "en-US", "20f204f4ea9d8d81b0f60d9d9414168c8db248730f42407b31041d7772f259872e9802cc79bdd02cc2b7d4a7a939a060c8ad08bdc4df8fbff6975ab07344cc6e" },
                { "es-AR", "a6e10333be617236b5cb2596f9d9d482c57746670e5abec4486bdd234a2be086c513b9eb80b7f4bb8a411a869e80406f6dffe05e19bd9d5b217df2c5d98c3a88" },
                { "es-ES", "de696de6f0bae76fa59e3bf4da010c92de5118bcf80c30ae83a41154c33f47b167b7cc7d4ba3422870d8ed54e757ce841fc061f84f189738fd00e5aa7b65c9d7" },
                { "es-MX", "fd6b8fd656fd1ad61dcac8db1c6925758b25a1905b72308a96ff0bf93bdab7ad104f349c7599b49aa84737f01fdb70fc8bf6c6321bfa5c9cf5e464a90ecf26c4" },
                { "et", "5abac6b2acaa1228eaba7d16aaafb62868f92f65d6ad2902db32d0c5fd306db20ca1c164e05610c68dbc3b029fcf4918f31512a74a4bd90b9669567c1573affa" },
                { "eu", "7a68c1aef045cff7e2c3f7e5339db886a3888c73254ba1e249e994bea6ad33a59a06ee6e32f179d00ef9f96893af1c9dc6fef9ebe96541973b225226c1f5e23f" },
                { "fi", "51e3ca421a1ef466f469b22500788338b2d3016a32a04805e9db2ca63fa141fd1cd8138cb23beedc5154af7cf814fc2307073134bb5e72c026fd70d83a60816b" },
                { "fr", "f0a2ec7209ba802ba5f33cab8c23716935589783cfb46f750c94c592cde602a8118040f2469b57422108d0999f863d10afb532ea754615afbb65619dd4dc9a79" },
                { "fy-NL", "94ff2845658479fa6d2db8ab064cdee40901edf75a7e2fa19831b19bad7734c372caf3f4dfa54209863ae18677b641b6f6420b2115d40c397d0a6093a21ee7d1" },
                { "ga-IE", "c3dab7c79f4ad568be5cef5fcf9d52729f67715849d3d258116e43c786d79b2c3f038e961c25385417080a4047a545ee1fa531b57f4220d7c357256cc92e41f5" },
                { "gd", "9bd955c220bf0aac74a16393c9ef99f3dc2878263cffb7b87c11c1c3cec3b8f34d24f21c35aa03db526c30c4f86029a60188be6652d472b31f91b0ea86782d74" },
                { "gl", "bde9c1bd86df1a8697edd9de7541f4bf0b3db1e1ff7bd9ce357d68867c8e42cebb6b45b3458058a37b590518fdebc6227fc69df6f4e90ab75479ca8bd9b7b1e3" },
                { "he", "8e4d466cb28a9d2867912064c8456f676d4c409383a4e09a0f794200bd30ccb128ca0c8ee48870dc974c4631b9c0dc188f7a288300ac3ba9db115555627ba2d1" },
                { "hr", "6148ef47c5acfca78b1ea4551236fd4c2b694ec161a36ea2f437898d3f5f1982999980f28b20dd398d232cc68a09ce85f74b2ec6ba5a65668cccc86361dab302" },
                { "hsb", "906f8f2483b55103f1d0ac8520e39b8d853946c64e03bc1c6b1337351e60c64265c3b1bb32ab148d4e3df84e9e8b2528fb545b9519abdd67d4ddd81c592b79ba" },
                { "hu", "37eddd67c2493dd13b70e844604e4e4a737dd97d3a30b9e984b326412ce838c9967f43d69a95e72e89caae1d1028f0dfe6ce9459e66ff92484e21d7126c098c9" },
                { "hy-AM", "10628e6ab9a91e53ec3e01e77f2f044b94c42ed6ec35458e7055ef719cc5a520dc40c3fbe8ab28067a79736d946394e90c3bf7009e4b19f6d8c56dc2ecb6d90f" },
                { "id", "e272ac20ffa653ae88196db28593472ab8fde8bd34d8c79463e94824ff48116deca3fe966c42ee8addb28999bbd42c9812040fd9bd9cde7184be1a6f09ff4f8d" },
                { "is", "d3b847c00dddec9fe9c5a4fedc3cdf14e9ba208317295378dd1278dc0465691b54414ea6ad1fe7ad3a38364e897caea1c099e4f4bca085dd7d1065dc9a5e0421" },
                { "it", "3b09dcdab9f4eea97ca765a67f2397455fbfb2578a49c9ec8a09d63ce844e6348fdc1fb33a3a81997a30aa23d27db95014947a05fcc0e8d830850fc5fe42ab58" },
                { "ja", "f3bfad3469d2508eb0c790b236ba2284e137a767f545b2da426320fe7503450cb3d0829fec58eb199f0d3a3917f9aedba7e53a54dd7a4c50f3de64eb9bd5a993" },
                { "ka", "8a9645bda0796df8bd98d91e4b6b6e16c36e80dab52ba10f30c0e59fdf4550c4dc47d70f9eb72816f6b586181e684bef7954dff6896bad8344d9e595201b6558" },
                { "kab", "607ceeb4f925d5836c9165b407b395a709712dbef2682ced7367a8d5587db050c3682d8b4d9d7773ba2a9d1f8293161f8e49b48bba2a62b3b45e94f6fe9b58f8" },
                { "kk", "2d240bd77cf6842f3ff821e01ff9ac54e9c9945bcd849f0c7696c9348385634c8af466732056a9bc84a46491315ade0168d950354da37b360570584f24dc318a" },
                { "ko", "a26429f72dc50fa3f72f37579e793b16ec3351137be08f0bf2c26aa7f505f0acab910d148180fbc1fc1077b487dc776c51c86226d853ff3bfc4adf32c0188c0c" },
                { "lt", "8e310d55c152bf79f266beeedbb770090c8b4ccbf6e1aa7f4d0a015d9b244d84c4f0e407938a1282bb9082e4aee1d943417917217edb69d11fe38f09a01cd74f" },
                { "lv", "bd2a2a4b6e54abe326fdaa3943b18053bd859fb4706629a144cc69ab4100f0129a750bb9b86cc37a595a4959caebaea3f739aad56466f0deba740d59f6f0031a" },
                { "ms", "b686f591fd1eee1122a442d3c093b005799c306c8eb02e212b2bdc368a9308b93a313eaee950a14a3159df64a5d6f1acc1db99ec05e9d3f74e162882fff88991" },
                { "nb-NO", "37959c9c8aeff40ef144d23f811286a6a37b228c67075cfd9f221cc8b40435798237eef7d7d68105b1dc3663520c7714fe27c5601843b19d7e3fef847a052e3d" },
                { "nl", "1533588fb7de15df656148984b98fd4ed63980a0f0cfa8b25fbbd7e5ca2aceb6b8ccbde6d7cd72bd504acd3a4d6e35ac18f38c51c965d84ca67ab96480a14989" },
                { "nn-NO", "1f6954984088b21a5a71100a74c0bed6a6266823beb108695b3e2fc78a3abb929f962db6c8497fdb659d424fa1fabafa917b662a9c7937532365f994df38689f" },
                { "pa-IN", "d66a89216832facc7d4d4c613133c920acb728401c72c78ca692570b0c94f70ebbe955dc443864e37b8f4fba7de84d7c192b52eaeb3e21a71ec554cde126d264" },
                { "pl", "aee5a2ee53bc42be47f4dfadc82112a2778c65c4d0ae846611b0c670cd6f1aa9c37366f6fd6e4b6605d56bc24daa070851da068afef448d183f98825134ee3c0" },
                { "pt-BR", "0596e74809b51c6547db4567b3f193f6fae9470aae88c67886baf359551412657e0cae202b29574baabbb55ba8688f551d3ade84e059bf6172d4414efbb032ca" },
                { "pt-PT", "c71c8ccd61b384a5b978a29037844655373ba8650ffae2ed74e60a75c29a8bf561dd9a2788c51c3f16a57e1cda3c6b4ba838fdccd6ed5acbab9db6f9db9253db" },
                { "rm", "b05fd93886708223e8e67e3fdba26e654075ed4d57f56f25961cf8461391ca49a38d16a818f46be35b616a76c03d28dc1b2a5121f788210d3d59274e04c6007c" },
                { "ro", "f8edaf703bbac918d239e211ae978fa4db0c15f01b2fa2a142a1e09d43baabb79aad829f413d3856fb9a625894ee7a8dcc34513588568c5a72ea9496d80a9fcd" },
                { "ru", "db8e74be87b81d0d0d7fb3d9365ec4c3818abad595fb8468994e0cdc8d4b54bc073d1d1d0e795490385d80dcf690765006193a4e6db1f8f5139de4b2b0944a76" },
                { "sk", "4ede811c29d8763233f37eedb05fb7ef05ef542966325dafab3318f4d9a439b4061e8937f5e7b5c959ab28492bd1e1ee16f7d64dc3a2e5fb38cf832608b21d62" },
                { "sl", "e85e7891082a2d3b9415da93b8966d9ebffb7ae0993caf29d78c8e251e14f4c9c1b9dd2b0dece8fcb228b461349823e3973dc8d93dd3624d7694b5c870b49c75" },
                { "sq", "3218e47e2beaabd406a831585c117dec5300bc0fab413c63beb9a991598bafd934449087201eb49184942b39f45d8569ba6ee8929e350afab00c590a40e4fc37" },
                { "sr", "8da96ecfa4e4f073118490a705b3fbe69e39a1dac8b4b96c2c6fbda76fda1b714bf07beb9d3959a822070950b78a7764c6b46dba9f64bcbda29fae87d59c5b6d" },
                { "sv-SE", "94c4ffe07eebce1f5408a705aab2fd217ed62d600d1c36b0a93045e4a74cebf5076ab2de1d2c5102441065119f4b221a285e035530810ae3106065aae045f282" },
                { "th", "eb505f5e98150e1215f3e081c3ccf1dfba1f462ea87fac728e5dc98af1426f88c1d41897a7c36c5df539b58393f62671c39a5c38c773a082d9093dd8c21eec10" },
                { "tr", "fb5d2b436a668d449c67a421a24bfe1c23496ac8a3661eeaa0fbb6571e17c2ec51dd5d6511d997d9936b80784cfc7a7ff18bc5e06da6148ccd8b9dcaadf951e1" },
                { "uk", "f60a15c8b423099a63533bb033fdad48414d24edf809fb7ef005e9cdf5361808e25e3cd26fb056390eceaace3ffd55dd12957dd2c8f4bed493d99206e00816b6" },
                { "uz", "8eae0c18518b689a0c9044999dbddcf01c9376a3a490e36604aaece7ca64a03ecb3481f46ac655624febef8441067815e58d2fb947866227035ea702c3c607ab" },
                { "vi", "b654ddfe038f2d0a859c5d3cbd30a0fe96f245a6e9dbbfecad6436d9f5965e9810a95e68e5b6e7ec06075a3bd5eaf1ddca815c3179b05397529e1d2d15627cc5" },
                { "zh-CN", "2fe66f93a1f60d19dec77ca94936b5da47e466b39b1f5b7e93b94757891f4e539fb15836ed1e9a6e6ed19b54ca40ebf29e0d4fb254bd185c55a932fc3a7ef6b9" },
                { "zh-TW", "32245f96350ebc2dddfe1798914831263afce64cd8929cae9aa8a41f73c1f4a4e4578ead40699eac27482221adbe5057156cb1c9ec104cd9cce8fd6b434ad542" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.7.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "5bd7a939b680c546e3e493904c49ceab7fa6a44b84bb0a76f23ddbfc549a2b01cfdf7135a5b096140331059f17c76fcd648a714bd37454ebf793c50c3e8ae6e7" },
                { "ar", "c0faacb11b75e894069d1cbfe5194997b3c796e2313e2acb93d5d2b2c6a3fcd5b04b544c72515fd3f67cc314b7322d8be133f1ea14ffbdb44960410463ac8d1c" },
                { "ast", "ede8ebfff584aa148c9da2b0237c7805fea7b41a2c78264c1fbdf5a24aed26f1933075f9b0166692a1fd0783573383e30c1e1057b9890a39b1affffa5a59faff" },
                { "be", "9100c9047ff4dbc38d1885bd49e6da2854cd7cefb183130fd4fdf3362716f1dd354ebea7b8f60be1dffb3fa4279ffcb6957e263fbacbbb24668ba7ff5e0bfca3" },
                { "bg", "782d76b50ec7f0cb891069555d6ff1fe3ff2e221e474b20cf4e9871117abdab4543c0b8a27e584d42730b7b318a59927017e748cbb2ef097f8d3d2c22e88fd98" },
                { "br", "48273fa06fb9672a4caf50220d87aaf137f6625c23aa8818b6e8376fc2a2a2c89e5ea439017b673ac8e9854c01542a4c75d7e1804c231c74c2c7ed209d6e05f6" },
                { "ca", "fb9c8d27985aada3aadaf8d2e3b86b42b1170fd8fb0c0f9621ccb92b434f43fba3456aad48506b4feff796a3a34cb96e22d5800d6491468b8470f37ab196f972" },
                { "cak", "c90e589679d7494650c858936b8536ce11972e304cfbc74701495f79651a9e65f6ac462728f4474d19fd044ce64c34a94867c725d81fd8ba79b02c70321ab118" },
                { "cs", "7fe706c0a45002968cc48f9091bbc0e1caf2aa097ad61b320f810bbeaf1edd181cfa9d0d8ece6b1297cfbb9239dd68209603544fb6336b61342a2a8324d0c740" },
                { "cy", "f63a6cdf13edac1328f616862da8ab3acfe3ca8db37d78118ab0d6eb013f19a432da79649fe8ae03911d6d2d60a231c51a9d7ba304605e0c17c5169f2f30b7c5" },
                { "da", "feb4e7992f742cbc4b8db782d3588a29bdc8f8c1d18bdc8a39ddae30c333e3480785203cc747e7e34d7753e255da941f6997dd8f53e7b891b65515e1ce877a6b" },
                { "de", "e84a7e3992bb7ab6ce05794f0705b8003c106d18705fe387ce148838d4982f29c7cc2266d2b5ed8c3507eb807789b2d3a14035adb039664e5c8bb2476a536c02" },
                { "dsb", "1a8892b86b7ca0b2818545e04604eb2fcc278e6d7b82c8c6e2ef6c102ce8352e6640a404badbc2cbd97273abad3064d7b3f104d8be09ac27aac92e4e501ce4aa" },
                { "el", "ad4e944cfee3405eaac7e859f5a95ae9b8b812955407a7012f39326aa98314a80915fbef8cf43b103b96357f22d035ad4f29a06810fead35b03659158849cd7c" },
                { "en-CA", "3cd28a7b2ad1e5b6fef39ace8ae581a8447cfeab51df6c1f0bfe862cacac916e92c59f95e946342a0eebb4da32650af121970d9ed5c64ad5f645ed431770b3d7" },
                { "en-GB", "ea2e9d4fba1f7988ca152d74a30ab0865d60520eb23fc2638bae6fe1ece6f19d6edc05e834004fa0bcaff7d558b5fc68a16db22ca8bd8afea7564f7f1767dd30" },
                { "en-US", "ba5e7df5279a409ebcafdcb397b1e68f7cf8a578a5644b52cf80cf9f8007fed2a4204dc8c673d5748705dc824fea9b9329a79108ad86362c18c948e65a1e937d" },
                { "es-AR", "19c57505c3eec6704ad800e8216f9ed74f3a7a0645dba76cebc60c79fea3d0429250e38e3891a9e930a530872a7b76bd107565066e86e0a4c561d547ff8a4565" },
                { "es-ES", "3306ad77a54680116d811c0f0123dc2c6a48b55620904570b6dfad63af5b3515aedc5ec77d98ee89f568937a2f7f6875dfddaad912d8049eaf0f256fe144c1da" },
                { "es-MX", "c84c113081791ebe324b9b3e47984b3f088d6547aecbb58ee936ae98bbb0a7e7b13e9c57d2dd3e108e710d1c6dc7d269b8299916973c85ce7fa960a2d6265a19" },
                { "et", "314e6ae2318521c2102c992c0bf9fcbe1d4ba88f94c6f299aac33a38667564238fcc7d94f02f11bc05af0d2eaf2871b4ee8768769940cc4fbbc14eb648592707" },
                { "eu", "53b20e8ccdf30393f2316c6839a639cf4cd3d72feb4434c9b5727057b46dad56bc96c513a9428ef00ca837632b393dc35573217bc5882cb666b435ed0549d728" },
                { "fi", "9cf06b02ab8681e9a9a49fcce5926f1fc1a2562667483c4ca46a4991fd4ccd9e287dbf4c6efd122b7a1f4be1e6876d52882826e16acafa98f2785d17191e3798" },
                { "fr", "e63bc50941bd10b6a2878bd585f44e81b7995d7276c1175aceb90749c8331541a819b444120bc0b563d45021c2375eaa0a417bfe532daf8ad6c0ea9f9395ce25" },
                { "fy-NL", "c65af27b5a6e37d908939e264683fb5a98bb3c5bc408c8c8a4cd4149f524a1f870256f8dd66d2c760a79c15c26d90113ed3825e6a618855370fdd9448c440d52" },
                { "ga-IE", "a397ae0f37363b810e454d92ce0c696c6fb81799c24520302cf376494a4da2b5722428bb2e95dc068db55a943d19c5a6cc14bc004962f04e97f6821a91ef56c1" },
                { "gd", "a883ccef2329a552a7eff886f3bc8f7b7611dc654cbe8e3a0ccdd5eeb2136eefac8caea7ad853f5c79e009acbd5ff4fa312918d86ad20cfae7437f0bdf0e84a8" },
                { "gl", "6e58fe9a877a5d47460d27810ba28b375efe951116540a1b3fd1e8ed9356b1f4aac0ff3e9ec9d75d0df1b2ad2551d0f61cdc3ec920c6e2a2c8dec40831887497" },
                { "he", "9d1be3f58aaa0e4c2f7dd442749ceb3db91f18dab77d33dff75a15964b3867d9741eb7e90f6868fee490b6ebd0ea6c2fbca2a051303f8fe494ea3a131de115eb" },
                { "hr", "d5a5f6cc5ece9030e461bb056278c8ec5f70d391a80b3d272250e75e5a49d6b71ad3944c3594c4aab70a1e004c736fb86f54929757b1ae6da8cad32628110a16" },
                { "hsb", "a06845cab795dfc925ac4db39f25bba98735618586397cc32220b022f8518a87c9c04c7505ce5ff357d44e1e2b2c3f0310af3f7ce289ca49be150a307247dafc" },
                { "hu", "f987031d010f883a4482f0bd043d120cdcbe838b55e005f4b0376ec29f3beca554dc62085bbf35017b778e029f72d711c0ab79e3b69af74a5cc1d483559993a5" },
                { "hy-AM", "35182ab8bb9a5ee182e3c57213a344bd332274daec83c6c1d9b2f3fd5761e2d813261aee889bc5ea56eacbce342aba355f1d63d51d2b4e3942da88f7d6c928db" },
                { "id", "ec1efbd01ee6bd02761e68aae7e18eeface89b918aec046307709961f61284424e75efc514e8b13e0ab8145afdd9d6088291b85faf7eb5c8f50c568868e3e1f6" },
                { "is", "661eab50c7128da24f1ff7fd9bad954689055e7329159d27f29ca8f2a8bc60a3a7e87940a5cd99dc30a7c4621995485daadb4d5b217f661625a119c3e1df698d" },
                { "it", "f1109bab581abef87530b8787b6b81e6c7b3ab92dfc2f7f3b74268e3944b5aa8770174db088551ca3c969d5f27956aefba459e404d4bde13bb16ec7d90ef9ab8" },
                { "ja", "0e9de7db42117e69036fd364ed0acea29bd4a469d98f4af21579b7d1c482e7560da52a6d70702ebe1a4545b5dd066fc497243440c6f13621143429d33e2507ee" },
                { "ka", "8fe7ce88b7d0bdfb921cc70d12d0887a1481b26ad91d5b88c391d226f11f12af3b20d1c7b5fae7ec8bcf2919caa5effc1b5915373b1c941113d3bca4144d4c71" },
                { "kab", "85bb530223c7cf74309f4c1203ef3fa18f5a48abb35ea0aa3a17b7b7cd54ad1026dc2d364d53b8570d0bdbdbe75cc662ab2b9fe3bc4788993d5728e83e1e03e0" },
                { "kk", "e5b6bdc29cdb44ad53fef36f3f2b0bcc152510ab4354cdc9c05e0e0733b8b835252d91496f360bb5b40a66f038ca7571ff329e0f3712945282e1a6fc467b00b6" },
                { "ko", "61c7059b6e308bbb0cf79836a86a10d5475d21a39b1c686a371d234dcb1f55eeb2b71b1ec68c6aad7677ce0427f38b688bc4eb69cb9e21261d5b568fe7d15e25" },
                { "lt", "138947abb2509d8050df5847508ba2c59e7d699a8bc465666d8ab115cc9ffe0fadcddde0f6ad4c8a16c77553b43d7a476d4cd0e3cf89a426bf77ce9624aab037" },
                { "lv", "df4911f59bda8b15424c93710434c001283fa364b413724c603346bd24512a4811861071cedbe4a0cc25a47ba8fca4bdfa53aed5463653720634980e83e1423e" },
                { "ms", "9276f9a6896bb52daf3e952dcfef289cce71bed36019f5c546507f4ec1d1efdada0204b70f5156e408392be12cdfa168516b7a3517a97947dccdb9e6ab8546ae" },
                { "nb-NO", "9742d98976993d53220383d4dd939ea362484856d38248c830c4d04cf8649746b309265392df2cb528ff6ded03f9735ac8b739e84f9944be81ccfe6c759e560b" },
                { "nl", "53fcd5a8c480e4ee04ae9f918263cc823e56ac4970f82f088beb394ada856de97e53cd6ed467986fa246df7c2df1fa3289bacd3ad28366c5fb44e42e895b3be4" },
                { "nn-NO", "a81d14976d92f9eb01548b5483de7dfd5bb3d17e7b66cc9ef4124e914831fe46cfd210e8bb243dc219a55227fdcca4359bdd8ebc2deb74a47e1a94a9eefa596e" },
                { "pa-IN", "d7910b1fa0b1bc1453587d93f64101007038ebbf44ccefb893ceedac72a6ce1f50bebd46cb9009a0615dce9081de3c91098075f3a58bb5d8f78836e1887484ab" },
                { "pl", "1a0d7cc5fb333b7a8403908163fde21de33b90886de2225c3ee4b038be59c0c6fc7acbda97dc1b5967390c086a017f05c260b101b04880f2d9c09a837893aa7b" },
                { "pt-BR", "6fa110dc9db13b580cb1d5ae30a78b387f2cf2da0e921a775944f619c3dbb05c5585d14364c8bfabfc1d612f081ebe9d5a155f976d8e08419d3c73d79040ac73" },
                { "pt-PT", "ce0be5d661ea7aaace71c0dbe0474739c796d56d2d823e67326e4fec951741a9d4145185fbe11a13439b64f63dc464887f04c2ffe559d91f9856ad3dbf72c138" },
                { "rm", "fae0019cc1dfdceecbfa6b256e1afec4d5c96d5738b78723e445a5d93dbc68f2a1ab74b30bd3c11a8a0c36873e7a75f15f6e9ef75190c612fc5566b0cb93530d" },
                { "ro", "6bc9b66d4f452d05ab54025947f144e2205169ced0a2bad0813fd58c3e42601b2094d45212c01c064066db89da88d838033011410c2754c117e0361de7ed3aa4" },
                { "ru", "a6eb6e91e523806b63e60ccf43227040a55d6c67335a44a6680517d848b28524c57a1701f45970a25fa4123abac30522c50b6a862337a0020eaa2bd1c0cbbb6f" },
                { "sk", "17442ac5194d591b9f4edeb258e0ed1dd514a93b7b9dd0b35dcfec6dcfe202f6cf2f01d1109abd00327a4f65a22b0942849b6bc8558b05d2c821a05cdf40f32c" },
                { "sl", "0ec46c67b1fd0c81b95f2538704dc4d346f874a61c8e3372c51c54973fb7abd31682f0fc6649d07dd32d92aeea842f83926b20c7d02f467c1266cab452045f95" },
                { "sq", "0709e709633c495c3b3830a2e03f37144f5740f4800e399e70645fb0c5423cd5db293d4143267e22b7718681afec6fc7d209d4a20cd59e84be3f3722d3a2ec21" },
                { "sr", "ff169b0484e43946b52456463e2f6b363ce1385c5f1a86c2050dbc6b10ca3e019ff24e6720785804ccea1846d47a0b1d7803212f50cf188dfd4867dc707cbd03" },
                { "sv-SE", "f486db318c3a3deed1da9046e6c45802e673b2cab63686f7c2dd6c8224b9bab079e60e1279af319f741a741c1ad166fa264753790a0489e3fa0597ecb98e39a8" },
                { "th", "a9bfd7475eca7cfb6f45a4920a226e167d068adab13449cdaae115f3a2d3b731596df848bda7a2131d8db86764cec5ac826aa1692ad085a1891240d26c7656a0" },
                { "tr", "997bc20875089ff314e052314ee8f0c0ed3af20950b365308aedc88274375934d516648cf9830c54cc49a11a8eb40f983fbada023ca945671575e88bc9e67bed" },
                { "uk", "09478ee49590e9e76b9b6c30f535dccb5ee97cbcb0d07f27ccefa4ef62e102cef707568fea96b62a801216780b49b3f5bf716101f61bdc7b43cc2f38794a70c3" },
                { "uz", "fbcf7e8e41a8b6f4c5e3b5526423d81f4a74760e0f67e1197d31f480bfc685ca846cf4539cea6e46eebfabba948dad1c9278937994263fc46ba0bfdec926ffbe" },
                { "vi", "cf6f102edc299b4512cbd515a4099ef78672397222873df11566a35736a650bef30a01c2131191cbda080c41c645c85ac3a00aec83e8e51c4b52a47ebd3524f4" },
                { "zh-CN", "a747ec164bbfc39db304626c8ebaf34968e74f040c6e55dc65f1008ea4d1a3836f0e7032d2fcc876caad9cc30d1dd7d32467679f7e9287779f5d1962862c036b" },
                { "zh-TW", "8740894f6c4d94dcdb50a68769e3414f661705cb6747fc43c3b5c2de25359a158ef42840f0775694e47182e04df14562d21f1e5f80950d2e0b18204682af435e" }
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
            const string version = "115.7.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
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
            // look for line with the correct language code and version for 64 bit
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
        /// Indicates whether or not the method searchForNewer() is implemented.
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
        /// Determines whether or not a separate process must be run before the update.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
