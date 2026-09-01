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
            // https://ftp.mozilla.org/pub/firefox/releases/155.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "56a3c96e67ce7f887c30b57d6ebbb87856cd01d12a79d688e0bec4cf8ccb1b1914b12f9265a032f3e37d78df659fdc91d4769a492481bce21d2b9fcebe6f64db" },
                { "af", "e9ae9953defabd5f44691c1cd76312c87d863de95586d67668e6a722a6ff760d71e1a69a19af0ea413407f5298ae2a33553e0f49019037321cd5d2564a1d919f" },
                { "an", "a7981a0249748532021ce0fccbbefadd4d3221700fc074e69d75e9dc536290a21b2014b197bdedc547831c12839438334d47413b9fdb915278a8eb138de2d8a3" },
                { "ar", "b6383040c66f7a30e8b4c0726241529346e1e7a36285a48ecc331ffeb790ce848ea4ce044bcef05597a0af0e057ba2c813885648becbb6508a84c501318b01ce" },
                { "ast", "1ea471718b0dd05882c0832ceca575018d36c9ba0d89d156af795556731bef0de5798e0d6d4ae2ce03a8e2639d50d3d7ad2399c4c73127989c6be65eb4d9f835" },
                { "az", "179f65eae2620f8151a5d56c096030f07bc57ae2af5f8dbc94a7097c0980c390d352afd003397887b8d4f25468315cb03d0d6075c77ea9ce82ef49c87adefbac" },
                { "be", "e7392aad7eb2ee3586c44d64f474816d1d231d5bb81afa9054f38ecb596cc15e11baa68c4a8124e07366410f109c183741c0e8078a68ac61351524bd2aa66e38" },
                { "bg", "39d1bd711c16bbdb7438202dcaf744db0295b5235f318d261c4e1c04dfe357286893d0b1b1cf5f4107efcfef76879b72d26685bedf6ee67ea3f0c92ba63506c6" },
                { "bn", "66e3718974d9ffd94b1528fd19566169a5d0eea65307a5307dfa356ee7e14aa82500bca418897fe7d16772103b033a6febf93ea30f67f01d6302a733ddb7ec96" },
                { "br", "1bc034f52ac9a03075839ba47362334de187a287f433c7e7f92ae5cd7ad8965efe1fdda4a33e0ada3442d07d702e96987a91dcbfbead4f769fbdb591df20f001" },
                { "bs", "e9be51fc812386c78b424873a6c57182f641ff1825d756425f610fc890920f27ed3d539f2fad655702ae3b9c222c6b7d4c895410d3ba6158fdb75a4004092666" },
                { "ca", "c4d71735767c1ef48138d90b1a0427117aa880356e5e487d8dacd5fbfcfc720fbf39cb3f654f49d0669621c64eed5eb3bb0a4eae098cbe47d261d6ba39ada935" },
                { "cak", "dc7d8b373e18100699e2421dbdf58bef9a689777b2eadcc22dfa62622f81270071413a53cb16cddc4c705d1aba3b9abc1003abe3470df585359d6ad5f4773cc6" },
                { "cs", "d47750ce0e97192fd76607279055ef23b4d9502ac8563e04133df38779c38c7f96ea9e058c3e948f79ac084dfdf5d624033cc4080184a9e32fbeb074f5ee405e" },
                { "cy", "28d92cf949f13b41a139dd58d159d106effd7ef45fef26479333876387e22480f1724a6951b2c467da205ba04e49b6d5d16652eb4a64435f67cd5bedd1e8dd13" },
                { "da", "8b1e586883b8a6f106506ee416817e145c5a1fc47b83d18836c20f7a5a6c5a879ef00cfc096fc8254ed9a209137bd3dd0d61148c5283ec1819cb965047eca2d7" },
                { "de", "986bb97b1ce12995918b05acf5bedcaa0dc8fb5df351fdcdcc4cf5e1f03d188f38a94b442fe4e2bc04f3351de3582d4130dea3f0e16bc3bbae45200653c35d9b" },
                { "dsb", "c1382a1bc5f94201bd191649147a1bf50f872cec7df1cc2139e00104669bd321ce7b0c51e305da28fec707df6e6d2218567f4782ead42a9d4c538c58db5ff1a2" },
                { "el", "317da2c7cf7c8e5e0d1274173f26537bca4d1afd2e47a48fef633f0f4c122e18953274bae0724b27c53732134b10d9125c1867e4f2d5d310e934206a8929cfce" },
                { "en-CA", "31398b67035b90fe8ca14a2835a0ea77371575f68ea6b45f952b038905dc97ffa9398328fa7cd5361b970c7821a6cfb3354cb5c8010108f4eb693ddeae197419" },
                { "en-GB", "11ac6b9d276fcf754e63db238ae8d377ad24af860d3d297d94d48449328960505e003d3ec863e76bb2437ff1da4d516af047e20e9ba238a339672a3e78af7981" },
                { "en-US", "54bb5b9d57ef7668df5e2b5ff0af602a040defec260f39e798140641cb0c3a4de5e9a947003b9653895b6a887a05189ca16d1828610915cec0e49b4f83a8b12a" },
                { "eo", "30c38629f3bc4b30c3dcc3144fff1ceabc2bc6a7204bc8369c4345f71b00767f16067c371458c8d7938dc06a79a1a5ef50dc7d5a0ab2b4d950cbb1f11b7187e8" },
                { "es-AR", "c7f1145bac3ba97c3542cbe09c96ef102e033805548934fdef0dbe2ea48fed857fe65481277bca2e8c6c0c8604fa39814a10458c643fb955331bd70edca35eee" },
                { "es-CL", "ccc4074fc4642e1c68777ea1182ac0d964a00fd8c512dd2ffe28df78c053902ddeb83123df10a05123fc8d15685a19d87f92f448344cc988e35bf46d9a2f5be8" },
                { "es-ES", "827c3bf412a8e356fe26e21c7f0a29cb1c29f35ccc63551463614477c827257f953b73656a99c8f350cfb03970c62cb18478cb9fe04b5505a468d7a8cd5de2f5" },
                { "es-MX", "6e4fe3e1d2bbcf261ae0ee71206001af410a9882425f21c764278bed28c6d8c2c804919b02e3affc1f9f9540a8a0dd5cedec42663afc6d147952a10838236308" },
                { "et", "882877a57b4af269590f9f336cc96c90306bf2b609469529ad8c8f35522e7bdf8baf9b0a6dd0c2c0cf565cf5b9a2ee230abc9a3289afc971b518fcbe0220622a" },
                { "eu", "c88554f76673459031e3f505d347324166474655b5ec1868fe0f2b4f24b6c1e306fdcd3f2b2661a13f40454eacd42604a238ed351d6f014622fce50d22402cb0" },
                { "fa", "89bc5dafc7eabc404a1e09db06bbed3bfc6bd953d40a10ed97e0049ae05396169800d81366ec6b727d67fe10230131a20aa2b6dc4215e055f941a7568f6d5343" },
                { "ff", "1bba8982d1a5aec169050a39209d24a7fa497241155d60a0658252c1526cde46f9d70709244c9c74e0b3b44e7a6aa698245e324c8d8b1c4883b70a36b9e56464" },
                { "fi", "86eb96d5c3c6dc50538d50af7683d66ff0f6f55e0db7e851058ea94d2d1badbd194e10b8fdae7c7874dc264df2056904a529ee8bef3b17d76ea13c998bb8fa75" },
                { "fr", "d4f91044c69934e47c56a3bcb34575cd61d58585cb67ed47b77895105cc1d45faad9f399bf18b81773656d6baf717f1bb54156246358332036583c10faf70923" },
                { "fur", "3b4f3a8faa905a0a1cb8af6f50b1ddb175b299f5e5713df0f4de688aea9bcfa95c50775204ad50f5ab3f0964b508db9a35309227dea3a50dbb9e01dd2d7cbec6" },
                { "fy-NL", "8fcd57761a71a19caeb68ad9bd21d944e3715aab2ebd68b2b1edc3a7873e4c695d0376843a8e98892ae375f183ea31060532ad519a14a5d8db88bc1d4a576f9e" },
                { "ga-IE", "f07c8de77d3eeb8b68449f3763e47b910a526d379fed5edcc79f5df3c3a5651995b04defcf7606431a37d91dce287bc57bd95967990f7de58f00debd294817df" },
                { "gd", "338aa7bd75d3472bc9b0eb51cb339db553b6d37f9b3e40c4312adc480617e23aa5b0a40cd232ba1e4d5b407bfa14840a6f51852b5d698d8023b2fcdce4c6f956" },
                { "gl", "34ab1a2e868ed996a1e945760f72a493b0bbf9087d4eda711a4eb659d80ec4db4c9982115f4b916b75c8de0a6804bb62a9b9cd5065b456740f2cdf8b9c4f7b90" },
                { "gn", "35091a46fbda26a339ec65ce5f30af8631dd7e578e4f180041ca3bba0148f47581fa3aabbb1775abc00433d5c672c733ba19bba875c6aff71095f5142be25a11" },
                { "gu-IN", "fbed1d3a24ab8df1eb8f9fdcd0fae819d9da38e5ce13124e9498e6bac6707a5687fe4ad1b7fa70bb1342683bc5357cf4ff8b85ded517bc36f8bfff27bb3d4788" },
                { "he", "9d2dcb61df8940de4cfc3c155326fe8370e5dcf9281569b19c64455a6fe9a5666c845f62a690d504696eb7b4624f6ea450e28dba4a74f83f396dcc58c7415024" },
                { "hi-IN", "e32fa8c1d38cbb1aafd6f911258dbff1eb6ded0f873a5c8f3fa2fdbba0489ba1dbc00d166c40a5bd9026564bd3af708dd385bd0caf9cbe81c8c3a80a5bd578bf" },
                { "hr", "f5c6e30a6e48794fce167639a4676545b54dc25ba34c37b8c374f7b79662fad664ee330685bc29651a777020acdf572e87f32f217f939481b3b6b1a2481bd04d" },
                { "hsb", "315b997298f202219b7e3d8ddde6bec2f32ba6f4ba083a3c959178a705ad137e8fbdac8686727d4019df54e0f780ad6a4061897496ded8eb5c2ece2eef0f7671" },
                { "hu", "906c20cda0aa08e913d9acd98ab1860b890ce0ecdf1d41dc07c42479000057e2c52b1191cfe3c98f0017c4614da21e74df54a649dab3174ba47e28dcd27fb3e9" },
                { "hy-AM", "da0435cb8025698e91a301e8e6216f522b8510800961e2d96d6eaa201fe0a2fcc70539f3199c18de62b682b24555caa9547b09829a657e288a29039d9289b290" },
                { "ia", "5a5b469427284a504c77c54a5f81303d8a1e2cbac1a7098d49d2651f0a752a636c8b75b12c0004d8dd9efa255110e44e1819ec921136d74ff053de2441c2216a" },
                { "id", "2cb452521bcc7daaa42281f4332805c88afdffb6ce87851b26d53b333e15bbf5d8a5e03ca2dbef09326d2a6b1255bb893ae8a64872fe910b72e037503f864a3e" },
                { "is", "10605ed3646d7dec25e3897710e57ad8a779340756749275f2e05a22cb886e7cb8660a8af79b271af79ffcf4c367bb2250f7737f3769993b0d9f9b8def4c37ae" },
                { "it", "76a317860997cce3ea1ee2cbcc1789e55185f429922f3aadf3e76d55a90c8ab359281f0efdf016f1c7b23a751308c18c155e2aa83c173a88aa5fea577b1da012" },
                { "ja", "1b55910215cabfc606959095edc9b7b1665b9effaec5e53ac287776b87a2be7a79de87dc15678c8d20249b976b4480f7ae399e7f19394ba9a356205e5c8ac292" },
                { "ka", "80d3d5bfe2b628a98ccefdce240a21b330e1c537e1690bd8b76cf48d3842a866e94f21626e165ad1b26917118583730a6d9e5d803b28ff98668d1922fefde90b" },
                { "kab", "0d1ca3430ae92731e0c73304a31e2400506fca5dc15816e5b0f368c9e8b39d50a34cd35b84d533acb7a854e391927cf995757c5fbb912f8b3e0ba26d79fcf05c" },
                { "kk", "e1bb62d8ead0e7a9148465bc8cd5d2cdc2bb86ec390d256d95478c1153a90fd024894788ce7035cb4bf22885fb744d67709134ae87d45a4165f5a2468c4c5b72" },
                { "km", "1de818640c1753a6fbd42db0a5966542cbe74a8fe427e925c568cdf1d4f941ab15d9c9ba921e1c60cf0d622b6c21c8b050ac5f8ca82b3ec0ab6ac66ac0c91a99" },
                { "kn", "eb01736e4b94bec043372aab678917d35a2363bad309e39302aa3772a1b3e54cf019286120021d10035cbc0586fb9105eb15f8c6b791e25e51dec60bd1d8b89d" },
                { "ko", "1cb54eb472f284e2ff777602c5c2811e74fc7f519ebbfd50d8c32dd673a615cf459fb8f140858cff749fe014dac4c12ca3d28a57f3e503a26bd70d72287bc01a" },
                { "lij", "f46e2d2f90f4c50fcceb07c0711166e86e68639e14a3718cc3d31030fc5d9d564b77b197fc50ebe0af8927c60c74dd0fb1cf558de52827144a0e74da683d7e6b" },
                { "lt", "96a68f79893e5af72c223c288fb64cb368f158c702d833fb1c581df47c668997dc71a6e715746fa049f54326fba18e0d9cc71d1dc29dbbf0affec2fc3f492aa4" },
                { "lv", "d3e70831aad92b9e1cfd833f5dcafab1d68b13bae345f0deb04e0d0abfb1d4487e87dd208f4bd79e8cddf8904af79c9f88b9d3fda63948066b7fb813b34aab92" },
                { "mk", "15a818aae987ef26fa0ebbbdc5632674f9501c063911f697810ab206963ea7ca6310fc090c2e7e18c8ed850bc49b84773ce2d2d0c7eea4232d288ae38343db7a" },
                { "mr", "c61751bf743aeb79b61630f6f014f2d5f98f7add5240dd579d1044fadf6c2cd31efc125587c5f909520734057bf7ea02b812bfb1cd2d41bca2b8b2994b3fe92f" },
                { "ms", "d5154aa199468d542c1bf79b0da6fe1ec9f010f51d0089e601070a0631fc9b5e341aef89ca4aa6d8e349953ececb8e83f49d368c2c47baf68e139f52319c30a3" },
                { "my", "33b9c95d52443f8455d59c5b3b12db8c2b343b2c9fd07c4f5fb683b8719d036dd6877f35649ce8221263b16db180db89b99894f6b25126172f224d12c436cadb" },
                { "nb-NO", "4602f14fa0d301e085c30b914a1c7041c0d4582a5fe3bf0ecd5996564c1c575a67c6404e913d6624634817b9122b6ddde9c98d8ef82606263b7d59d68be07afd" },
                { "ne-NP", "3e06ad7e1d8a7e1494b3d898a809346661edac8b4728c4cbc51b5c8c01dd5f93f0981043b2eb4ae26238eeea82b13fbf4bf63c376ee9a7ae01f083d2466e4464" },
                { "nl", "1369e3ab9c0a3e55668dbd5437eea9aa4d3c55261c8fcb6261533dc7d5eacf4e85c06dffcb5d49bfa6bde1550df83a8399dfd1505118be5073faefae66267de2" },
                { "nn-NO", "e3582b92624f7064d732ad7b8e8fab30b17543219960939aaafed90b6e2dce8f319166884a45848283887c3792147612427e883965b52165e6fd2690ad269b91" },
                { "oc", "5f6bb5ed59dc52e135716a8509e3e5f4d4ba112fa0ec6d7d574b1906a01e81847bdb50937c9c3294bba419a458291bb5b9f85178852fb0e1c37c90e0696e080a" },
                { "pa-IN", "fc14ae2a9df9af40f2d0ab8ae8e57c24787d8ee9f0f794f8af18828ec8470543bfd3f6718b20e3ad11182e074d0bc0b1728af48a23bf5a1fd457429b3b28ec4d" },
                { "pl", "12a0ca2a6820139bfd9a3a3677addbc3300af3ade0cf3712f3a3e8f18e375ef820a7e8e26465b813a59fc0e7274c4412c87c254706595d95c9087990573d5004" },
                { "pt-BR", "afadea856be915ef45b787fd47e2010a47367a9f1f8c5393c664c3fecc5a88854774748b119e1a75da6c7ebd1ebec56f00ffb656fd7cad41c735d21682a35e3e" },
                { "pt-PT", "0311343df0784aed73516525838998ad9d40690bfc850eb9d2e889f25244d63c5421f86bfa0dd9728165102d8df0c6402922faa09670e7b561d79511226065c4" },
                { "rm", "fb8a55cdbbd42386127169b421d145f15a21503d633ec8e64c71a2f305b223f97c45b3d1fe47f73a762029c899d58c4ff37d7dd15f0ca6b54d436beb8025bf61" },
                { "ro", "950c05840e2ce72f66385aad5f05746d8a3ad6660fba081af235d39c3a0cf1c146858317552327c70d27b41d1cce59eee7e2f4d2b72d9966ea6c7744ae41e04d" },
                { "ru", "c4cb689deae0e2bbe4d5ca8fd17eadd71db9f7e7fb01e4d624873b2f7e40d5e90056a21b30552cd7c57182cc89d3d2713cb4989e3b045a6b731cff830044f49d" },
                { "sat", "748ab853d2a3eff1699843cf340649f7b55e28af12162d10a29f591a63407f6ef51b2fc42dc7dc0ff58dd57f7bba0a667b5caf345492e6b9ea423d826570b505" },
                { "sc", "94e8e9f956deeb107759afc15339aa2a9139e621c12c973b1fa39aba66f786bb8799d407c40de388dd35431a6305e19284b604575c273a167b256b0b80d6b76c" },
                { "sco", "b0757eea2f1cc7db78e484edc1d67f88e56889d1f5d4208168067a24d3bb779530ae1af5478401625f0027652dc0abbcae26797baa02803653eaba6fb1ad326a" },
                { "si", "8bcd73f5c468d9982cfd3aa2a5a3136e5f65c5c3e3a4076eb29573eb64e72b1cd021601c4c5ecb5199c06644c958a8c45323d62a51aa0e2903b1477474a9e942" },
                { "sk", "26267ef54548b30de4df846051d670f1fc22d39fc8a3c74baf719a961d17b01551d2ade35dc00a6d6b98b35e745b7eb5d7c0f743fa034704867a29629d0e5c34" },
                { "skr", "f62d6d37bde8a1071ec31747ff2418c0bff0f63a7b590d6c859d7a102e6e5912beb25d758dd03f9371644883045f9707fdc78144ea40332ae19bb6955682118b" },
                { "sl", "684cdecc743897dcb5a970bb7192d5710df61c8c63688438163b0a70086a707665921e24e4f3bf4a24e5cec590c8ab84a0766379541e01269d646e7adcf289bd" },
                { "son", "090901e3b29b4e3b5602883a79fc338c2a03fe517f49c2266f7cfba8c4275f3e7bde94c87ddbf207e7bc4972cb4d5555092382d1165aae3b97b37a84b0760822" },
                { "sq", "e2ee55002a2c3816ee4c99759819e20368f418b4b8171c06a8cddb86cf3b5f406cb65cb5ceea2a270bab7891fdd9bf010ca60c62f8fcd71176fc8747fbed850a" },
                { "sr", "06d51498c037dd970d6abe84ec2f157bd656a6b2e85abce5ea749efb5b40af2618c3d65a631bc097e2b2fc6931b17baa85628be31f4ff089e5bbb728928b3a3c" },
                { "sv-SE", "b057536220d9dc930493d43c91b787cf291026e507a20a6e3c3c0ec3c5e3bf3b94db0552b1937614e46cd7c59d08d7c0d4d9b29a8818604f2774fff023dd8ea2" },
                { "szl", "4856142519aaa4022344963126a9c78a071fe9b88c3d88a662f99c03640c8c40f0dc48378019b3f226e7e209a7379c636abad9b8d8cab868b11827f19c71640a" },
                { "ta", "99592032a157913da9c7bafc18abb99367c835868ba22d418ce67edb65769d7fbb0ddb7ac6c2cdcdaa106371c472214884ef235ad91ba026dcd2bf2e2fd62ab7" },
                { "te", "8d5b0e6d91058dfb52c2ae1bdde1a54b88e6f5fed893ca0f32fbb818d5c4a708d198efe38f4a753aa9e15fc1627821ce2e7a6255c55c1b4009e0a4d180c4b8f1" },
                { "tg", "84ef84cd664f2a60735fd58617c1032f45f086d00b107df85d1717d424d9150a4b9fedfe6a6fc9d274231663ec00aa617088bf09237e63cf60f0a2ad6620c35f" },
                { "th", "83214f1bfc7e9885f3b5c853809232355ab40eafab376f8e7d4069216d3ca94631bed2f1f9b0e3e5fc23de4573d2c47af6b06fe6bbc3c82f8d908c71e9ba431d" },
                { "tl", "b45b4a3ead014c4c5870926d62b3b156f22f8f33bec09aaf25451cdbc75ab3668da5980876f3d2a0130d79261dde170b54fa323f050b9093d9225c6ceefc3d86" },
                { "tr", "1a89df65de90447844c7632ef325ffe5b19b32e730060925240e27b9054615d0e82aca672aba2edbe4457bc3c2802b19a54c1e55a17977154c22d20f4a106a8a" },
                { "trs", "474423055e43aaf67952e075f9bf34c93ae7f9c7e89599e8ab16f09f784d053e5e56bdd11c056006d6968b6dbee3c61f71bb1d51e53f3b97229f07810063d016" },
                { "uk", "5a9a2edad0fb424352a85ce44a222da12817e77f96c681c542e43db3af9b56104baad52aa05ab758725daf590c628826f376da3bc02bfb0f21eee72ef7762918" },
                { "ur", "81a6116a2c9e290ead008ac18c8f6af2be135200ed2896d03880aa84a0a0c4257c65fb92f73c6259fa60ddd04fdc811eb27d69ce32bec04732b2e5325754375a" },
                { "uz", "3be2b944055b3e493e90d4e0de9659f83c62c4320bd50abb335478135c049ec28a5fb475667dae3a1de67ca4283360f65469b3a2b3664276e69c5a159b9c34cc" },
                { "vi", "f148cdedb9a7a57d46568f22bf933d2b619628154b51db68048ba4f94ec4c70a352b859e3dc71762cf0cca049a61bcd8098355e796e115a29f4114c1b816066c" },
                { "xh", "0ab076400eb5c097d666645325707dfaa5823e520a25638300934d25f4bf737aa96288c138cbfbaf2237ecaf768037e419ef54f8d7accf79daa83c23f13ca855" },
                { "zh-CN", "81e17ec9aa2556c7bc7682559a92f9b8e573742d9ab182dd88edc5b61bd86dc5b078eadab0b310463d1549e57295f3a742b4311415e3e14a11a06e798382d7ed" },
                { "zh-TW", "70748a2ef2999427a2cf271d00021657c93a4fed2104abf365775f30d0ba2d013d0aaf99e9f17faa82f8c78b4aff0dbd7efee2cab09a3259891fd1a34cbd5b78" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/155.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "99626ef426a52ad634248b7f7f69be897fa642f7747e8c8bab03f4ebbb2841cb26d918c9e88cb4869ee701cc4bfc7604eb6babf007b9e316b38d6ee5b99ac622" },
                { "af", "3f69fff038e54285f9633433c3d0964b1c71df384c559644c7514a66c0b292200c2173226f59abe161bdf6d973951cb76e044b426ab5d09439528b6d4747b4f5" },
                { "an", "5e025eea4006b3d7905d5b2edf8a0f3ac3733fede665d7479a5cfc78e997ce81adbbb7a018eb773b386d9c7732fbf99942a800e2f8738a58bb811e8208937dba" },
                { "ar", "ebd4a29a1381199f9bcc6de8e2c6d0da1bf003c9a92e3dcca3846dac7a5c0cebceb43941fe5ceeefdf17e5ba62edaf96fd741f63515d38fafa6f7af0dd15d252" },
                { "ast", "fe0b7ae6e687b91c89feebf3798b599032f71a529ca53900565f94090b06270d8fc9fe7ff75b5714ce621f91db00d6743b295c68e2849d37855efc245f1b17bf" },
                { "az", "7e82851cdec2bde9adf87d8a4089509f4a7f2d878a11002eeebcb0ae54efd2c7bc7dfa5e0347e8ae6e6a35d2441e7d44df9ff55b90e959829e8e750ed2991d7b" },
                { "be", "349a71d2ac2d5c4493b87db3fb8f05b30f2aee7d46a7e2ac4a32b5d7068ff8518ebba5b5c596cdfb294a4644cc9ffcabf877e3a7c2d637e75a876dd65de0d75e" },
                { "bg", "9394094386e67ae7ee9e32a0a6325db4c29a3391d421d17fd464b7f65c6203b67e9611a3b77a465aa94e96f931d5bfa19f36959842ac6a82cbe37521a6581523" },
                { "bn", "7054836dc64e2041e54e17bf71abc2771ba6ae6c2a3e6759f90977b0608772cdace1afea43dd154edff9e7e68723c5efdb6bba8cb98d40334d605a494d220ce8" },
                { "br", "1f16103a1ebc205a984aec0c3233d2dff2998da0aa70096a616912126dd67b98aa855c68c227cf540f7da20b5de84271b7de2707e2b66bb048bd2394d3166bff" },
                { "bs", "a2380e78e4a88202b2e0bdec5b8ebecc36c14fb16461ddb1d62be704558fa8edb067fcdf4935ec5ebb9d89fdccbb245ce279a3448841245660864b8981493fba" },
                { "ca", "d343d66de943ab7e4495b59cdb37177f5ad308de901f1cd4d749fcdb7ebed70e506e058cf352e6326c4fef58f2d593a206471d6fbfd4653f1913fd1523340d36" },
                { "cak", "b7ca190caf234d0cea7a108952e00a63bb4ed3e002d2777274c456765b0cf8cc334e019a018679a07c192463bf8bd7bcd91a01ba86c76ad0da041b8f7b30ef1c" },
                { "cs", "9de82361511b3297cc5a28a4c0020742c79e2974f91d3e3c18763ec9060a7c40393975e32d2fd38de48b64b07a74f18c2dd389baa5260c76568109252baec109" },
                { "cy", "5221be356dc33df1d111b492176f3e8b83ea6bf127fda39230103082941b2dd873ba409623732eb3fdd48d659fec9e2f5dd4725a9b90ecc051244422606d6977" },
                { "da", "ace06433306c63a4638db131d78873f39d9e8ac7959f94a8448af51c57f6ce6c28140d7b35a7419e7dd78c335bcb6364c7476a281d964202d3c8c70076db8202" },
                { "de", "f105c39e5c71cbd4974a631653b59a16e9bfc365b54106c335a8b1b70b747d82372c2b0df1669325fe532a675d3b1b7214f495d81c893ceec453ef056328a49f" },
                { "dsb", "cdc5721df5bf92ac8c99b471814a1b0097b56bd7f52fb2c602dcba727daf4d03a6eb354715d85e93159842e19678ff3ed0fb89b349806c4f2b4f06f2595a3e48" },
                { "el", "973745b5a9484ef94f1851eb6daa02669d0079cb03ce17cd1eb4cabfbbb53e23b9a83ffab6ffff20fcdca23242e21d5757be53d29dbce634bc5df0c08bf857fa" },
                { "en-CA", "23364315083e883120ea6f5c341b2d29f6d53784f7de762ba826e7950c62a29f11f7411b79d70f3f29cd6a39953a26086beda69ccd6eb3afeaa996ab01799e6c" },
                { "en-GB", "48016397f9ee7af7f5a81af9e63f2b470c4a33c38c001be6f566398cddbbd9351a0f79611a33c01b4fd586497242e503780813795907ce0cda9c82953c133ac6" },
                { "en-US", "64a4fa349a8d58577e7cd43b8c7604e9e9f206c971b4fe8a95010c405f49deb961dab60b94e014af3f4efcf5e6590efcc18ff241e41c658275966a54233acd5d" },
                { "eo", "ef689d1ef5d238437d2f4004c6647e76bb42e80b2c9459b52460ed2f8423646210fa7dde258ee5ef392b2f71759b159c17086bc5c07ab8e52d10ad7064bca795" },
                { "es-AR", "3972b3f3cb37527c39d72585cf22a6b0db39f6c1b183c69d67bcc9a04aff469fb0484b11874c04cdf8011d77470c4fe0806aa5a919ba80c7eb6007e87c7e2350" },
                { "es-CL", "c52602d73fd49618e6898d21ae0337a1fbf8c113fa82fa5a44206b30829db6c9416a1b20e7894f3344dbe332f7145eb482bfe9720fdc184f925bfcb05e8439ac" },
                { "es-ES", "afa4b01e656ecd890e810943ad39bf7e3dfd15f62127b3d324b3144320f4d7fd9d3619fa6260254455995ff87baf45a3e5ee52800e3ce98e90868b78d57ade88" },
                { "es-MX", "6d3ba7dbafa36b416ff19ee55fe567a1e6fc117a041f7bd0a5aba32d12d42cd1bcbfcc86d0283354bd5eb4e0237a440f9c8505ff6e1a9e7b435aaef3c8ff70fd" },
                { "et", "151953057f24da48c666bfd6d6cd025a6e15ff9e81e01aec6b41e1a4a4fbd433f0444d8b69e8c832c27d6a81e39585d5d4c575437fe0a84fd0db2f0bb182e1f7" },
                { "eu", "56064d55a9bd4aca9c7b0c69901f2118421e1c8462a9963038f19cdbae194f375243aa53b7940c8da4cdeb3297f8cc59c6b0a7cf44955d0b80405346b212d65b" },
                { "fa", "3314cc80a393ae3666336034036b51c05b9d25c47d8770e390ea3abe348c304eef73a1b7a939e946f83d9b742b08c75747c4e43955155d4b61432b0cb5be2021" },
                { "ff", "2e2f78abd4cb2520d4f751f7b82e66047dccb172c506ab9daecbe12e5c1472d7578d7a386deb40fb3c8dbaef259f816cd53c0f15bd988a4a9535b10c5230fb1e" },
                { "fi", "e8f7050b76a7d82269947fc2f57d6d5991e1ef8f70d611a02d1f57239bffc1107a46fe27e7482747a116eec460dac57e2578bc8a77fc25f48b8491f75ad1604d" },
                { "fr", "b4837fe5b545cc43b5735213a138a2b787fd44514997c84d88770fed812caa5dba84db6c1f26691f18428ba4d02d614eb7791cce5c5472b71975b86a7c5c379c" },
                { "fur", "1bbeb6c3902d3c12a38d36f0fc011d7c1de3a56fe2f5ab83737cae62cbe2302ea34caa776c215212befc1ff048b5a9614e5f104ba3b7f9f627d8269a18ad3ede" },
                { "fy-NL", "f6e80f822d8374a11b63f0601519471d37dc9036ebe179cb8767f7c336661a6376c4218b79d9a9585384b28e61f102effd38af3eff922a21253c716ac46399b2" },
                { "ga-IE", "61e4b70bd0ce8f60b50e09bdfd1a13d0e3a32581650bc9df6fca418cca303a4b6c9256ceada4ce618255febc21fa3aea504b65150fe644de84fa70be1eba103a" },
                { "gd", "b1836a2382c47a86f6a621970a5747d0fe40deb2a08eb0a4a57c9124b9781cc645ebd519bad4a9c3989e655784e3883d23c132406f756551b9f2e557f0000eae" },
                { "gl", "afcb13a1a599ad8104f50bdd0b9725bb84251c7d637ff6b5b369942ce256f50a22b7e57005f39d5d2c649fbbaf533aee7dc72352c0d34b84282d62734536e2b0" },
                { "gn", "79a46fa6cfec515ece60c1cc963fd2b24a7526576136e5ea1ca29517ef8199d40faf72061c3e335f348e8dde8f85911037bbf0dca68da62703f2cb0ce8e668d6" },
                { "gu-IN", "e0685248d7989f4a6c1fdb09ac66f8afc8864dd228d2c029e9cd58513e847fbcf4f067fbfec4b9517329449a6335387505895c3beea7cf0e1bf83fdc342b28ef" },
                { "he", "e2efa9de99e2952b1876d4993a4727306311a748e2c4c69f1ccb1f3730df0ca8190f6451cf6fa85ed82d9a77c5fdfa73226ae81c8a982f99a7f0570fb915255b" },
                { "hi-IN", "e01e5fc2e004f07310a465d128fee66fd5f0d0af37e05ad906c4418fd618d63cbf5ef5b2b5aba6151ca71661d746afaa1defffe1f1ec8797a636f119d664955c" },
                { "hr", "4b89d24b0cb01a99a3048f0c9cc51b5b3074cf6cb481c2526116640a59e1e8f8b9e412b74e51e885a95f36e354cad61d3d33e085bf783e6a4989243ea7ebf778" },
                { "hsb", "38b5dd769c77bdce40a5da5f3ffbfc6a16e241864f6e21b837ad6d0def982f1cfcfd0dc11bfaa9f9d3f921c2045fbce529646da7d1a49cd80b3cc6d3566b952b" },
                { "hu", "70fd6d11d24a06ed507067cc3ea510eaa5911751a037abe51c9fb5395e582a927ed1613073979ab822d731050275a6380c7c7d9404ac27496396521aa97cc6d2" },
                { "hy-AM", "39c1e175ce9dc3f54ca384c1965e3ea05e7a33d64733e418f5202532824719f5fc9e0acdff36e5918e8e3671a7db04d75ae713b37194fc2d1513c188493e9ad6" },
                { "ia", "11f06e83ab7ffe97070203d0c5117cfa63b30b5f94c1bf1b83fcdd6adddbac174f93318d2fae4e8660472078bc8219c891d143cd85a46b2d79df5cc620f12d87" },
                { "id", "c2f9fb4ef35b553024b23f473c66be465150ee54198dd04ded5a487a79b2fc0b65ed9294273d32ff265c3dda9593bf88a34d7e82404896d51f44afe740905e9e" },
                { "is", "c8fb59315d970acfd4b1758ebca940861d9f2950ebf7ea5d1536ce8936ce09897b137f9bc9e921f4866ac1cb6597fd7262eb15a90c3f8c9a1267efd403722b99" },
                { "it", "f3ae24d60d5ca8de298e851ce27b0cf303f83a008efcb0ced58bf4c6df56ab9d93e2260fc87a9cdcd9a796f4080910905044f8916bd10b5ee2ef75996fbc69a2" },
                { "ja", "03e2ff101ccbd86cc3599f5b669775c67ade7256b7076401fe71259ff8e229d42bfe79bc564a4942ab25ecb04a80e0df3f2722504cb884c344f038ea5ad047e8" },
                { "ka", "6f0acc15dd1ed5a287e206242f3f01263db824f3aaa3c15f499a94164801c13be3950f9b77b880fc4133424f87d1b9aed90480f52fcfb857fe16abc55672b0a7" },
                { "kab", "3161acf49045368ba49d947a3a84a1f3c3aa15bf372cfdb51931c01302430884ff48a3aaf2dcfec3379c937dd573b749da4438902c6074760b32e5789f9521ba" },
                { "kk", "328670114c8d0911265e2f0cffc9e34da970531562419430de7ba6cf4c4df3ff6ed7eda163fd073fc0fc025ee97ba88bfaf05c9e7fba5de80d3b5ac7da8d41dd" },
                { "km", "b92aed21656cb22db08137dc3c6d24fef46eb7fdacac242752ad909b0fd38de8d84dec6c48c2a1f2efcd17e2d268ed7baf3188654cf737e6011df6fdf41bfb2b" },
                { "kn", "adf8dd991028d9e2a0719271023ea3738b507b6b8a85f95297959180728a6fae35827082f662cbb344b8cd21b2bb46bd3791205a7388c065c53c3510430fb398" },
                { "ko", "d0e6a486d9a790452f5f4fc6acf9ebe408b47adf199eba68e48042732315b01eefa37d67e219877daf31b469c9169812e2aad4fa5af034bc71f3555c3ce491d7" },
                { "lij", "366f134c3e57bb508510909fe03cfb185c56e671e8cd4eb22197707a40189f352c0364597fd349cebaa788751f7190390b42fb6d720e4fcbb604177ed677b4d8" },
                { "lt", "2e0027cde1f2a3d4bb21c786e85bcdb3673b149d0d0de99080c9aee54812a8e238b6761e8662a9ecca3c4f82b41365d3d63ea749d51555858e4f00875213a4e3" },
                { "lv", "774d0ab8ba01c3f2566a6a59a9b385960fb408444a71a50486b88b5e1f37788292a59b1eb564ce8d577137988033e365105037234ec10b22ba196794ac29d1a6" },
                { "mk", "823189e836882ce7197e126025081940c71077da6af6c0ee315cc43d742c63326441193284ddce7eb4297aa04b08c27347430c7a2edf32576a366f5bf7481957" },
                { "mr", "1eb2e03f3e933df13aee2964e44bab12431aca4642086e1896858cd3f65330fa206ac3068547adbc51c5bcdb4f440aff248bf395f57f5cf242d150247ded2a3c" },
                { "ms", "b8e98fdaa0eb2d9c18739706da86ef139bbc5e4a9bca62972cb3e411d81f2607bdeb102da484f5488d58706300e792e9952a58315b51b53e2d1551b90c65512b" },
                { "my", "c8f97a58d7866fe20e1223e18af73c17a27adcdcda34b4e337a5de1acede984f2b09fe9ae33f76744c36261f7386bc6a34e572ef5db36fe8bb9ca4af7f9ea7ee" },
                { "nb-NO", "e61b0d8b3dbd7d497a819f671ad744f66a877d5768b377ccfd5ab05d8fde2e89ddc08503b21425a3796bc2a86e2151442bfe71a120ecca5864ad2d13999162f8" },
                { "ne-NP", "f6bd717f02786fad12e283bd2645e26ffdfc95fbd5842aacba4284a79d687a843023bb8a2285e0b3b67859db92128ce9f533261d52d46795cce817b34d6afd3b" },
                { "nl", "7a31192aa115f9624efab2a6397779c58309b0ab0a2eb32d5bbbeec08685eef858ef9a7fd22d60b90794ab1bfd976ef6380a4740a5e15f3ef7a2138684a9020b" },
                { "nn-NO", "9c0a20250045de08173c6f3ed4db13dd00462f605948272bd8bdd048991a36778539b9e6243cd45a0c817e76fa69eb19db655d78e50b7dc0390fbc30305f6f7f" },
                { "oc", "04bb6ed742a804557784382226d7dc4e2dcf02db95dfd992a0bb28489e3a8662ab89ec4adaec753a4430555c7f38f20bba765be035a8a688d575df7c24ec988f" },
                { "pa-IN", "936f404474b77de726e049b93e6d66460af7625aafc51dbf9fb51b57fff5443e974edcae68aa96d7fdcb772ac94b70fac3c4e0f3e10820b974181a073b00fa6c" },
                { "pl", "87f67b1899f9cdefe63549b59178e3e554fa9ae14961f69bbbd448ea2e35c575a8474e57a58d155bd5748c93687006779019f40ac07f90bb597ea8780b2d149f" },
                { "pt-BR", "1168bb7c8f5b1dac8228f66d9b0f449cf9d25d33dc8681fdd87a76af81db528cbcf476fe44b1333d85a81ca4ee962d0674b16d5a9b1d525a98cdf11884e4ffee" },
                { "pt-PT", "16db014c7ac191dd2f4842527376bba2735e5cb0e42c18beeb0e5dbc6b24f1c946e1a39b9152dbbf11990f5eb3d08c202813fbaaa490c005e3782d1a0644b6b7" },
                { "rm", "ab120913b0eba052cf00afb766be8d6eac4546ec441d80c37f30a1938c8e32796e67ee09a95dbb424a950c48a011af5309dd6baa096bcf292561816b655df053" },
                { "ro", "bfd2868f09fcb94772df5ba01a52f0bbd52ec03b815c0ec3a32fd8abcc913d22ff560ea1b5e186e6d0164672c5e6114c39103da7166d5ee5a9d01b053958054c" },
                { "ru", "11b83f4555e8bcbda2561274ba4b5f21cfd51e17ec5d5c10a2b0aa70e30e8152174b94f919dc393179a9f21dca489059eb0f1f834e21cac70cd04b1ff8fb40ba" },
                { "sat", "c8d22016f3815b161dd27d39a7c63397895051cdb3e8213ccf7268f4ab5ea362027d9bc9143ea06da4b21de1059c6c0d64aac9a58ef1c68e6150230338b1d020" },
                { "sc", "82a54596f6148c15105c48ff2029b0e8f4270e40a1c78699d194e68da3867d1dc4d6ed6f4b9b74a9a5e59349dee4d911290df82423e8d3626d32a7eb8c1d01ac" },
                { "sco", "cd1f7e5dad8f1ea1862b8ab53f3cfa788b9094c0381918172a1c60dbce87f6ac3cb8142ab11432f3a891059fee0143358567dbb34692faac5e006aaa4ae253a2" },
                { "si", "65d1340f0e1944358c53c644be1a8bb843c0286c2338d2a38ffcfac0a0aa72ed82bfdd21f085acd946eb87398d1383da1b65c35ff06784bf41ef316f74188a71" },
                { "sk", "e12ffb4ae5d7230015bb033a698c4e14a066ad78bc46516532632911bd16f1f08fd8bdf456152f105d5a1f4d296f43a9319927fe9d36ec36b20ef907c8dd7948" },
                { "skr", "150db6504fff59883316390185237ae5c206a7a1b965e628e4a966b92db2a7470872b7ef95910caf29dd10405c0ecb8f5a2e35205e82da7717a47d317ae0b9a9" },
                { "sl", "47236d989783c4a46ee69795d3030cd75facfd4536de040b6667fc667bb0486e0bcf214d7592528bef93ddf91b63079b00435c81daf07c1f414d8ba3ffbc88d6" },
                { "son", "50fd45cec67b7ceea961e4003b8c630370a85fe13be40a828d5e0c78c61fed4583b01a0941bbb7c9bd72f75e16844dd55121a1c7c00f648a1eefb898d6aa1420" },
                { "sq", "dfd7b9c2d6d54a30f8d8bc54a8708353f4a3dc7e09f23d43101c88ff6359976f42004784953c1f369ee68d7fa3584d929aa77f1a8192cd2aadc7c2be7bd99d89" },
                { "sr", "1f65560460aa40dbb49451804003516c6c2744d585d6bbe7c87ee7b361fb04bb37f8c5138d683a1a2a46d466271e0f35008a3745960eaaaf5dfbf4a5185f3779" },
                { "sv-SE", "b1e9a5b6a4dbb63e914fedc0e7200d3cc13c836f6146ad8c8111f41c7ab216fd8e5acf35876022452eadbfca0a83018506d29b10a56eb29ef272b1d82ed0928a" },
                { "szl", "b3ee4621bb53d97f4a9efb2d5a325e667d6c35ad0684c946de1696d04708fa6b08503e2867fcb684b7c708ece07dc741ad464a4b5814ef2ba4261dce5d6064d5" },
                { "ta", "55ad6f39f31d7091edd0cd71d3f777d2c64d7f22a64804c00dd51c1f27438dbe19156c9add37f34971f225220e2f67876204f56916e73826098d53754d5db896" },
                { "te", "5f5d6a0028269b6c84130411fdde1dea2afddcc953c8d7c7a648c9a3a190a02e9269a20a7d22f31d829d21429dceb4fc28d88c0c421d0ee124ba7bfb96616679" },
                { "tg", "60d7d1335e48dc594233d37cb243ba007b568f2d040c2cf396bb566b84da443fd202bcd5bfc446368dd19087e1daa8ec8d144294ca9030b882a149fa9dc8f367" },
                { "th", "0ab6a724c288b4d6c81684873689b0fa49b188cba33e35323c7548db272df6f02715a1733d8418818438b077adffff059d01866e869ae3d51ca9ecc6fc4f33c9" },
                { "tl", "e5953d60749b59bcc233799d3e83c8579d8707bc372c8a27a641ec1986c7fbacbecbd9cd9c875f9efefbb306cb80e54eb1619ef5bf0bebf21bf07ee51f26e835" },
                { "tr", "f698b5fb43dd16cae99e7c12ce50476ca2f1428f0138f36c3d77bc7adca16032c6e5d24c10320eee4250532addebba03ac069f8d712ba73ad4fa31e526c5780a" },
                { "trs", "380198bc2bb59bffffedb3bb8151ced58a8609e1e58d577f2412bc981f308018487c989b07b80129e4736a5ada3e696085dcb0dcb2fa295ad6c58fc6aad61f88" },
                { "uk", "c87a034fd1877fe71b99fa457b0996a3ac9a4e676be1d81213b81beafb5242144eae89da5f70966ef460af5f133f183e8bb245a4013cd7f949119001648c7f46" },
                { "ur", "367e76c9b4da3cdf97eff4fa37f6fdb502e6c7d08d4016eb5dd980c4fc1258d8e635294299d8986d92bb7f0978f53aa41e88ca015d3c3e6bb911ddb3d56425ab" },
                { "uz", "1be85cf3379e569f18351b17a9ee883359e94432acee1dd6a802f24380cf11ad12c4788340bfbfc1ac062cb2fd0f0b74443f60105fb0096dafe33eb6ed5289d6" },
                { "vi", "9369370ea3024f5ab4e38a2c77f15b247fde0b94b62436d4348fece078680047ea2a678466f743ab05b81b8dfb97217e049d7c9f06ce6910cdbeceb6d831f1bf" },
                { "xh", "5d84b49764327e275f64fb272f99b33e939b5d40811566c511bf7d1937a2c87073ca6822e65d5c0e760e05bfbab996a2c833e0b132c59a937bb8d2658f9e8bbc" },
                { "zh-CN", "0e96561e14cbe888d3b25be622b3b1d7ed3b9b669fa4a2928befa0b7dfc51974901633cfd402259bcfabfa7c8608283adaf0c0ad8e1a171c0d34617214c163a3" },
                { "zh-TW", "941f9391bc250cfce0e8294e579ba6a4f44ee86db62cc76720891361ff98ccd6c5cc664769033e9dff67b7bcf3b6481464a06f3dec7616ff8edf918e599dc8ba" }
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
            const string knownVersion = "155.0";
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
