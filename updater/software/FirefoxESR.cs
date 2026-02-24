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
        private const string knownVersion = "140.8.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6e9d779b344b0635da6328aaf87f5acc3baf423860c87c73a23a3cf54bb90b63dce9080edfe48e5efc20373f2fc146191a5426bec7bec7e1d483c9b590eb2c3e" },
                { "af", "5a0fc7a08ef9b7e48809568b69712a507b00821e24151e1f752e7b689d635591ba53d2c354a85b84c8c7ea5e90fd8722736792da9fee723cfcba0f9e9a3e69eb" },
                { "an", "502c533efbf6d2ce2640238c258f56a7928f74e101fed198acf70aac0b644c783b47c25acf2a7c9b23a04e59e90f2daa31387d3193b1012548bf3209aee3406f" },
                { "ar", "2735766ade134907192a2d633da4882b5dc3b30373086d04b369277f305093b59fa0330054e8651919ca1b781817d772b6ec9d5bc64d969e79c7d491c9ae8836" },
                { "ast", "0ee67e4fc5008ecc5dde3941dea98183682019da22e118be8e748055d1cc96f6af78320d2ee63f42f274385bb07e6913665e0e39f0b310e76af8bc2b16fb85ee" },
                { "az", "cd3f2ff547eea0a3488baaa9a49add73720f615d475cc981ef4881590ab721d94a9202c18e53348ca23bc6ef972938602760f679bed5006bd323d7d1c4df253a" },
                { "be", "2bfa0b948ee8fa6679928a5e4162715867d4130b559394d5b85a2127f7a666f39b0aa0f40837f52867a1a25ee04030d98b4e1eda908f1ccf77fbc04e2e2c4b0a" },
                { "bg", "977fb9e910516736726f29c1d4aba9c0f9e2367d20ebefe09b9a8beec2866cc0db24eac9f2fc76e70d6b3e912fbf3281a21867a7adaa97cbd858db06601a3262" },
                { "bn", "0106e5d9e0cb690453ff7b7f5ee5fc356e0adfa61bc405b6adccb1253de11f376770af5327f7212d2b6baff102e65015af518f84273f10adaf0dedd9c4e39305" },
                { "br", "a40c9240f3d20fc29614a02c8d9274ac41c1ddc3755ca1b3ccd382b86dee9c971dcfaca6559675ac45709d683ba889a64104d29c9c9207b6fc5495ba0a30b8be" },
                { "bs", "2940ce622bc3084ac86f8e72884793a42600623aa5463545c10c84eb6282b87c68735d27bc333ec62a52b9a2f17532ac7319a076d226102fd054fd8826b6ee7b" },
                { "ca", "81309568281636b2684292bbfc76da3ea24f84f9905720a570644b30c8ab924111b2a5f7846c71d8bd07db46ce0f831917d4f23beffe382194d66fa88b594dd7" },
                { "cak", "99ad87acbdb47ce476e5b34b47f3133538a491d885b7d3eb8defabd07df3a99f12e5e67c90054c6cdd06ce38a62c3a838f34ebd138f5d2ef76d7f98611c967df" },
                { "cs", "5e3048c3951215cde0bad246d5f2cbfc9264c4b4b35f6406b20ef276f453c7135974bb08fa6dc34d41d467b9f164e6d100823fa764e1c59e02ccbf86e014abc6" },
                { "cy", "e05fb66690cba9a9db9440b3f821ce409092c8edeee05be5786d26a7e8b6ca375dbe448855ffc7ac404ec6903646b25f884376bb2dea9cf577065dbcc1589801" },
                { "da", "d09440751e1a5c2f519ae10f7c3e291409b0c7e2e52af91913e9866e4f966696151a94ba5759b3f39ab879cd05feee21a8764e52ce42d6f0441ccb12ac320730" },
                { "de", "14354dd4949ce4647ee55a0658d825920e5b3a6fbe7ed01c67375396dfee4aa3c06915f967656faeb8286257a2bafe83f1c3116b03c6bb19643f014cde9bbe9a" },
                { "dsb", "1f7539c6d8cee2598c37729084d3324e1e6e43ff471c946cdcd0ea2983859ba8220d36a6cdecfa87119dd01f107221e7407f893d772c7c681d42e6bff2300394" },
                { "el", "d0cb8ef3d4f7aeb2a6115a0839cf22256b3155060aa128f7313b68da902dde3dc6dfd2dd79314a7d34d43ec7b1e5f22420cb98acba01c55739d39bc24b062fc4" },
                { "en-CA", "ab78809010a5f1410cbbaf7fc36351dbcd6b932c7ebd58da822996cc887a1be3b850c1a01ee0979f3b7f85efd7c05ad5c2f3de38b6f25ba85f8fcc904c4673fb" },
                { "en-GB", "f3efe94e543952e8e7f7b81be8c06951f4f7e6991711de882444f3ed041e6c13bc38f9721e446d0ae7b5954759e664f3d9033e93c8a0e78c53f21a43ac2cd200" },
                { "en-US", "4e2164c2ed74708fb3d06e6e04d028db33c33ee356a3b4cb3be439dcdf3ab57e442c27503df3fe0e9266038593bd30e15a528ce5951454d82152c159acfa8a48" },
                { "eo", "d28b3e68ce7e4433a9470497f404cd245917e92a7eca8d587794152e33ea4291945c0f3551d000711003b9262e71d6ef3b9afc81725780ff989ea30c16cb4f29" },
                { "es-AR", "00ce9f820827fdf79d9fe1d11cae107f39a67da2a88b172975c29471434b7dd6d13a5f93561d4dacb2b948f9c23c664367429b5e2c90a3882172be204efa0c50" },
                { "es-CL", "5ef358ca965ec55d40e88436ed59be84ab7cd469b33a587f5352779d5561c7e7c7c53f3a6ecd1ca6f348090edb2312a276bb63521d1890921fddc0c6fa7c4576" },
                { "es-ES", "e4f53751c70f06e98c656c150ed31fc0bf07e4347ec4c6f03a200b789da2c76e4748eeacf21c0a76a2458e8faffc44065b9d1ca21d1b59f956b3d68b44300b33" },
                { "es-MX", "29bb73ad42e32b7ad605ff80bda6a47813d36c9ae065a21e4f724054d896d57cb0413d0f670df97718e8479b702a4525e855f5218ed84e61299f8cb1bf1deaa9" },
                { "et", "767585a5237ce69667f143e952bded6c2639dae5e80aca3947204f7a9e3aa23b56ce076d5b82b661599b7c3795db5eae79ab642b0cfaa8ec14911477dc7226ee" },
                { "eu", "b9bf990f791e1123846aced0b229970d82f7b42ecfdece6cbb205b87052398228f171d43c05aecab4e526ca95272df6debe635b1284276a58751959de7e671b0" },
                { "fa", "9f820d6fd0b2a22734d502e0699f6fda0a1a6b720240ae0e0cef8be8ac6970d34c46128376faab5c485c1ef401d05217c809bdb2e24ea132727ccb96ff6ed1ee" },
                { "ff", "fe9a14bcf0a75a9a76926dcb481f7c1e2041a004932b3566318b36cab86d336339dc79cd8dfb62cc84e6ba5e2e638486a0ae79a55681dfa17e5ee91377d0c70e" },
                { "fi", "d217af8361634be3166108c8484d377d7fd1c33d552a342a71a7d4c3582c5b57af32e3b1eed48f4204de6c3ad972cb165e4db96f69b8a205386edf857a7ed7b6" },
                { "fr", "77978e5097238c216ae6e05902ff224f070e7a9d5fabeabadf76a3aae82131417b3a09a565c4e7c3ad47a5f7833cccbea97af23a48a25862b1376188516293e0" },
                { "fur", "4e0fd334021751a09ec8b9c85459ac45623d2a6cedd4ac06de0c57b4ac4542548850447e86e0ca6e30e856a3b4f14ce366631ed06c35248de93e7a0e30247264" },
                { "fy-NL", "f5e2340a111552a55611d3a66b0a4cba1fd80dd0795e52eba2a1b30549fc63d6b940aedeb241be8110e9ce2487f8d0918e50248f70b371594e4f7f51788ac9d3" },
                { "ga-IE", "5a5b4bfd4e53dd2142e5f21ab681d656621d1359215b35bfc3a10499745cd8f6af94e2556c62f58c09e934ed85f975a99a83bf0abaded1e660ddffc803da3479" },
                { "gd", "58a260ed72f62374bbfa289f239661fcda7751021805a180fe4373aae36292ceed3b0baee2a0e122e5a89e96822e93383d8656e1ee3115d5b97710a2ca2d9517" },
                { "gl", "f0ac6e779f79acb7b4384c3d161bcacb47b44ebbc5fa36bcdb424da708a37392fb5ca8c3bcb710de0f5973e32d0160a170f0844dac62695c869a45198986da35" },
                { "gn", "5035506b318b6fd977c4ebefbcfdbbc3a38e274b594547bfc369f33f772a630fef98344add8419136f1189afda3155b31452dbb674e64b35ebe68062db294fd0" },
                { "gu-IN", "bad9563a688db636a8cd1c3196122ab311d82834a13dbf3a95e28a80191bdb5a2a8bcb3b3f1c00add8b32cedac39343c1faa79f9f838950f63ce498699ae4dd3" },
                { "he", "58affc6846a2845978fea092e5b77d15fd72f39ed043ecce0789313f7a9361d82a0d6d04cdaa50a0fd272e6c76cd0e4b42914c3183ab12c86760ec2b188d02b7" },
                { "hi-IN", "fb1f62f8f3d77add6fe79062a5bcd3f691792f1419da32f22680d1c9d1eec07641d6c9da060d5b1d6c7135809eaac73494def5d7fa994a307ae05f74c466bbf4" },
                { "hr", "f6af08d4d2d730bc850a99461655fe361dbcc0f54d9ad9e42488558e4b86cbc03aa8043e3a198e44fe84534047499bc51d2ac73455e4bed0f633fd765ef54324" },
                { "hsb", "f4a7ef5c629034801c4cb1acf4a07c0e3465818ac12cb359e3e2ef370629904b2edb01594fea7c36d34d5b06e88806632c1fcb58a45981911d8463daaf1739e3" },
                { "hu", "e1191583fb37cfcdd933efdf851c1c82dc9dc3372e560314b2d5f9e88bb670161e2163709e4d05b0d448000df6de4721a2e88021d12e67c22bc1fe6aa734b360" },
                { "hy-AM", "8d4cf0091ee9b46ab9b8bd3b3d3a8ea15138d6c904c69ba365749b7a1e6bcfb61f4f7ce355883f34256831ffb04c8286c280a564a9a177eb0f95d2693384de6c" },
                { "ia", "96324dfc5fd1c18f79747536bbc6e3703ecc4965c39cb34830c95180b2a0dbfe76192c59409feedc06704d23a2dd3346b4c879389494549b24d79225370c4b3b" },
                { "id", "44d6fc4de61d8fe4b84cd3407844675d00903e0ca0062239031e58c31f978277848836edf6f15d6e5fbe0dc90f4a83f34a3c631303c249a4798f39a13aecfead" },
                { "is", "b4236f87eff71ba814d7cf65e8db5826c5d42ec4cfc44990f80fcf8b6b04f10d6f9e6c14813c28776495b8254fb3988a46057515f5ca5cb8dadae1cbe10fc2b7" },
                { "it", "de5ef76cf3381aa7a950bd5439b02e0e887d3967be96ab861d0cd2e38ca55aba6ec9e7ac41d94edb3c75ac0faeb639454e8d37386d6c2b1727f10e1b2b4202ca" },
                { "ja", "ec2e59d270c6379731997614a8b449ee72b94f7f60f796c510b94426235c244a67446691b0975a089ba421a38b79815891488f6610e5b132e829cb42a9577b89" },
                { "ka", "118f974c1fd0fe30c3f03f9bcbcd8213c9609f81d329b665e520a1138ab8ac424a89e0fd97ae2305ba1fa77ffdb931b879499cf2c00caf497dd7a3576bd15c92" },
                { "kab", "a1e879f7852efec84acd50f7b2f6b14151b72224ab060114721fc7a2cdce01ea9e767cfea672f69eb360c0d776bad679019815601ce18d6df033745f7918ea5a" },
                { "kk", "8f0beda16250e0b71d92b213479bc7b177baac3fe3fa4997b1b7b889a667253a4c02a793c66e9d5854a991a1757ec32b969cd220546cebd213848f1e0088935e" },
                { "km", "d2def0b3431c9cb559e33d96f7b6a0fa55aa927f81c112f9f518c18cbfced91a77818c30f959e2679c352c60f91f0903575935b34b97e29b226c4cc4d89c869c" },
                { "kn", "e4d538b35afd8c62533846de5f08a376f7194209861c03c6469eec8ef783d74c8d62d94b679230b4d03546f42d49ed3ef3bddda2ee9b1516a15785755c216b09" },
                { "ko", "39d6bceacedb8e2a737dcb78b352610380d5ba2aba50255e2200388776e3e6d283a7d9ac8e38901a0cde4526b59bc537caf8d94097698c889e8ace0d7fe53142" },
                { "lij", "f9984d55f161b246eaad7a082a8eeece66335ef1600782286045f243e5509a6caf1ad06c59421d216b34e768bfc4a8f84ca3455e767ebd189b9d9e8c8b490116" },
                { "lt", "4cde462bb3babe26b456c54428dc9ad2b7a3425fd2ebbbc752143dd47f1de9111d97692c69d5af19f52fb647d9fb89552f8fa37497def0dd224afa14f2b359d5" },
                { "lv", "a5a98851e6150716a9e8c47705057464e914f7be6e86f574fa20029454cfc571a66922585d88f06c23941dc3041a69bbddca3986f23e01516e983c5f6daace06" },
                { "mk", "7526f5909028c658486cd5b1f0b5fb30fe7f41aa93515828db7c4549bbceee0f85c568c328f83235d0267b246350cc2b5a4672ca7748856909399fb62cc3c7f9" },
                { "mr", "47c3f121cde6b51d92d4321bc202647ac38c2a936c7d0a9d6e2bbb0f116b97656a13f5b786f9fdd409929b8a6ab10259d372d5bcb792eec37cb3176b1d5bef18" },
                { "ms", "4cbc22bd7de7b43df4e06356261a5952dda57163f9ee54acb497565507481d555234d10bfc2b4c1606bb0ae80d3475e37cbee22d4636dadf142dfa14427bbde8" },
                { "my", "b5f8e6ee50541b330f574fffcc29513071da706e9d72b3cf735a58415c9be0adeba7896a80cf3fb33dd5e83dec121d1d0e05eee1158ca9a54e6a66df54653f65" },
                { "nb-NO", "3937426fe756b918a347cffde2d575d2f3d6681a5be82610dd3db9f26c1fdbbbbf4be80ea7fdcaf5755ef815e0b10ff6224a657f269fbb82046fe3c0af600acc" },
                { "ne-NP", "33d8ee71bf77bea78a3a38e6a9cc821f160bf76455679fc4d809affd397d8c0fea22792879bfede2729829d9afd9a441c2a4c3deb48d5dac150c323533333bc4" },
                { "nl", "c8de7068622f1a9018f9f9bc7c2d53045001ba2173bd0fd8c2a5f889ab7bda5bcf6414a883575af064372d932cb29e340ce391e2364c0af42e0245967cc091f9" },
                { "nn-NO", "7968ea16139489790e925e67b813a442c66f228ac300f6b9ae754d4604378a7433fe055e265c5d565c0796ab557ab9347cdd94a82ee10ec18833e3448184ac92" },
                { "oc", "4be78ce7cb51a9d67285f52c55ca1ad3b12376b7952589a5adc024cea5fcf5b39d3157f59bdaf3a4f963ed6b7a09513854c7db61c9f98cccdd884dfb4ac5b188" },
                { "pa-IN", "457766204c480e8156ea05ad73e9d3754e2433400fdc7d2ab6b3d3ff7d786e1e06a5810a47f2b8629f78c4434e9f98c8ca999f8878c8d8e085b501ca35768462" },
                { "pl", "ca7c63a519f11baf041103570b8ecd46f834cf1be1c25f0a7baf1c7c724be8cc23aa1a4cac83d667d2c0fa0e51bc620f2db17a9357a9ea68f85e59e043ff5bf5" },
                { "pt-BR", "6c9a440ac406c8b0752c95fa756bbe5766f7e56c1f714017be7c1ae067b8e9daa2276931164db3608015b69d261d02d29b6001082e6d5caf012ebc58ceb20a5d" },
                { "pt-PT", "45676e15cfe92fd70eebe724a7837a6c59e0d3f790af3172d47b1b2fecc9d0f4cec74803f90e3150d649135e6b89be4f220c7dd9df833957396ae4d6d953efa4" },
                { "rm", "cd4796e515d94afae7bf1966cc6f64455c6408f35373cb75234190e41300bf2518fc03065c7351e7deda3d19a067330086b5c6e692495bbc726f7c30c48f2bb4" },
                { "ro", "a0617cca1e01eb18e2d9f78316e6b00fc61045e560be20a3694131a8744f6d738f8926de30671fa44c4bb35d559b35c3e529652375c735268a0bcb5e0af83ae1" },
                { "ru", "02ec027d78b10380cdb204b454a1339dd48f8864e303d66af8c8fb082cb81223413ccc793bcfad76879d6e4cbc7959d88d5bbadd849df076e8387c5a4f03289a" },
                { "sat", "97b07ea1d8867d4bc0c70ddeb220b88416794ad37543eb1db1082ebb25a57ba89728cb0118e5ddf27f041da5a5d2de32642fb29fb5ec9be7f8bb322224187f8e" },
                { "sc", "a4087a25e4a99ec017d1c87d0febe69ed348f5d8a4557124ce24b74e936f91616b21952641c07bce7088f080bf878fb60bf63979fb06c2dc52ec9debd893762e" },
                { "sco", "c23810092b84234eed82bab63f3a72f78de23323a1895e31d6556335587a1840d84565946218f9ce0407de0c9e41875385daa1349fe43484cf9a99cf23e873fe" },
                { "si", "81bca62977f1d22c3c3a3406fba3754cd1d9c750c18933f78d15eb6b0107661f49fb91d45848fec07c15ff6cb308026f8958612c15bca4bc3e9920af737da3a9" },
                { "sk", "2f899ba4f6de685f1b1d71bd91b3564001748dc30671de96ded4c1b1c076452d75e3f6c63c1a10bf4f6afdb6c96a71847ec86f2aa5af9dfdeb208072af9e4c36" },
                { "skr", "025491b62edc1e41dbe331ea1d292b50d76c3c6c7822359ec376707494fb5f9c63887e465b81bd8db863051bab1b721e04973e9c0512dd4a71942e3107c15ec3" },
                { "sl", "f3addc70622a8020c5e27130974bc1be7184d84baa7b85ba64ce71cdc335c3837fd0bf50b3fbf497c3a5715cc3429d89209d5f60b5e59f8eb936c6ce52ac250e" },
                { "son", "370279c3307ef37ef2f928c501ec6191ca8be88ae0b17b47661a31dcaea4d9c60e7236c90cbf54c3728534db596db469d6b64876db48eee5074f00658e6b4c37" },
                { "sq", "a3d1cc2f8da50f9b8d4872d5d971901c27ea93424f39fe10935fdd6ffb205e47c580cdf6b3b7f3faaa6bd268a86274aefbdbc86442245f053c6326f4cb2271aa" },
                { "sr", "58556b318f95312f5df7b93c3532688657800e500faf9c2d05dd309e89ffe4a214cd641053e629654bfc0b53372b64d2c47f5479cb6f8ba65467b94286cc8e94" },
                { "sv-SE", "6ac391b078c72dc68c2a81281d416cf84f28aa97d8a3b2ec83ebd3ef94b9b3d2e43aeed859be57e0714c71214ffdca46272fadf7b29676ac76f7af60d0dc642c" },
                { "szl", "8d16bbe73c9f3e65de2204d1a5e29df9c130479c8e82004438c9d10bb822c9823bb56c9295b2c063518106df2d8527879a0b6ec5cbfcde698339351acc1072cb" },
                { "ta", "72527cbbed224f8bd2ff49f7755939e3ef9475e772face1b605a2a7a66268ccade2ab63b8e9cde2dd8f1bee31b2139244233368bc31f9a07efa9c280b03843f6" },
                { "te", "f58a47fc8481500bd7ba45a98ddebc5fb06ac02a7460bc5a6a65140d6247019dcfe04f725d1de9f15e67694d9716d1af3e2c8b534f19a954060eb2735d75c356" },
                { "tg", "cb3d2f4c2e9f2a6b95eae347fbf540662df86b6c24bd922175ae24e0cd875fc96682e82fce00dc40607f1722edae1d77aa178370e768b573a90f192c50f7131f" },
                { "th", "e04c2ba3b0bf0b231cae3e9a25740d86b65610879e5fecc7abeecbcdd7c4de78537fdde8f80f4d80c36823fd8213688fe98bcda5c83a6ce94a9cb9a946cbc2f6" },
                { "tl", "1357c7354dd436528a5d5cdec38ce4c4ef57aca07a3da0287477ce4a9e07fae471cffe69b73b1bf314b9f9426e99136b9f3d292bf11ebf510bd7245720942346" },
                { "tr", "bed32644959288a78e42af108d57354fc0872951ee6797f16f673e01bd4ab2dad4e794d8a03dd1dd97c586d2d91f33c12d97ade7637ae643385e809dc8384baf" },
                { "trs", "9bf14d1f0b923ac53ea2450bd470fb14af275cb358b1c6f98891e469f676f2f6ca78084a9aee327c610fef4564cd919c1a45023590392ca326d14d1729852a92" },
                { "uk", "961ae7ae728784d56e5332f90182e3b40329f7642905ef062cf92b7c9316df47da52cc486645376b4872750554582ab846883a75198767e7f27e411701a0faf4" },
                { "ur", "b9956c0069e00b19fa19150a5a953660cf14976eeb5f1cf5032fd8f4037fba440c69d89009ca61b76f52d69e53227d4b4339de7289e3cd9db25ca33d78c909b4" },
                { "uz", "b2958bb36c8ab41b108c578d90d74a842636c99e8af33e45a837ebba5025887bfecf4b2aa7771d9c265f81accdab03861aae777718ce5371c4eb56f6882c9c05" },
                { "vi", "752603892c47a8f6433a522a8a51f58365401343286ebad4e1f9f6da6060ea9c2062fca953036d8ee04b97c7c957ad6e5bceb9d41c0e06df2d8ae46108e6d118" },
                { "xh", "febc81b7a97fd0f3d23a97268f91f64c7b483935c86d41593be74244ce17162ee29e6a3030f1bd94bebe6e46ccdd5791a25e8ea799c03f862dbec2083107ce75" },
                { "zh-CN", "4d936f5f4c3965a74bd11ebae48af2979233b0009187f0091232ba8c3e22aefca7bd0045837aa5692e7f7cb1b7bee5f7e330f36e5481e5524e8f9c09cdeff6d2" },
                { "zh-TW", "68913309380a71c4577d88879d0b99fa1c25babff7bf84ff147eff754ac16608335b5bd936793e79321f83b281da64d3c2275b0affe39fb45385e2c8366dac82" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.8.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4950fd47dc3f622d767f40be6dfef19a2557691f0580ffc72437b8ffd6e3a32d36be7e37fb2096839e3f59be3933a937d60628ade1fe872df4c4ee33d0cdaad0" },
                { "af", "16481182dd7820265273d544ef71bf4287ba376612caa35d285cce06aeeb8e29a20211d98dd7e8131e28ee685a527e7a24bf03b42040f52febd48d7e28136662" },
                { "an", "3e3547b292e631fdeb5f7dd7c227a4da801cb55e6d0561c5bfbceb960810092634a1be90be03bd3103a3bbbd80ea8ed342627a0b1216a903d7de3b4e3eb32568" },
                { "ar", "fec6a95a3372939e3602510ce1333a91b735072cdd15e90bca964540595200788c31c2c9e7c3fbe94b44f1f49ad877e7eadf79c084e7dd25a6d50114c6d3f901" },
                { "ast", "d9ec14eb20fc3ab0c793b5e69aa704106cc7bfcc005b68d8bf1edd60b9bf89b486a505df7dbde432a336be9bf51485568e0a021744f4aa32136d789f1eda366d" },
                { "az", "7babdf1a9051d15274ad53d7c9bd657663c0145712dbb5b3f37f2bca5d7f9f4d4780aa306bde85926ff4f99be3176343b609a41b8fbf74a06547ee1a3ac97ac6" },
                { "be", "db855f5a84445e80e31e2e9a515f61d218835084823811063bc652384867c94958018460397dcd4eb11d319096244af6a70aad2775970f27d3a70e56f2f73637" },
                { "bg", "178dbbb3fa4b7d078024996b6ac96f2a921873206f1fd447313142e415e45d53ee9b2f9c6b69bb1329656add48bda4da5b0e1a2d4e8e970d1b3ec7944eede0cb" },
                { "bn", "f2c1698ba199a26141d059eeef64b9519ae4f7a5ff1c021c8fa405cc75902f4faff30eb2cea27262a3742da87a856b306e9eef306c928e1cff152ef7b2e7713b" },
                { "br", "6286239c1f05f15e59605cfcec5c901441637d800ba7c02e3aaabaf0822a482e949d8b2d2efd7f52928d7383707ffdf5d766c2e10790f682fbac24b528bb5926" },
                { "bs", "2592f610b32f4a39c777d1776e332ef0ea216e804552865755600d5106641364e51f0bb0b26f2959397baa21c8198b6a3c8b4484b9484c1a8fc46054699157c3" },
                { "ca", "0c9ee98c6c6b7044ec188db2c0564c6869e44fc8344fbd2d12ddd92bb8d5a9e7949557d2237f2cfc73835dab0d4c119e448a7141b890b9811ef4113977d10839" },
                { "cak", "71ae789277caa190a2a3ac81c09de5e07172a74cb2673a1d4d2b33a823499c6d174292542af6e1e1b8546373fcdeb4c3c796e9c2fca817326dd859d8d7cfc443" },
                { "cs", "6883127fe7a19681c371eeb77fd43933d0d912a7b91365c5e212183ea84930950397c8da34351232687913d396d409950db5e008c86ab307a1f731b022cd8a53" },
                { "cy", "2f3019d085cc766031d7196052a57270db24c3088196d8b3f1783217a319507382628b20eb3f08f75fab118dad564fcc73f7f587d9597fa9f15040ff90eb0497" },
                { "da", "bd3805744e20f44295a8a1c66d369e6fd5270e8ac97f6d8d9ae51addc8ba5dd19b7cad6e32fd2e0abae875f7b157e3350f00b286999f3cb1803a83ccc7fa6e5e" },
                { "de", "70091b9ff9256f4fdf26f49ca5e4d52eaa19d6610c08af341c557a50bdc1021e074a7be6310cac3988ebe6ee3dbd381621beeaeba00dc23e4ba80850bd83a833" },
                { "dsb", "dfdd305fa6cd05c93fc727b0eef4b5c94ff7612626a625ebc9fb26045e3767d0486c6de8059f1bc7cfa8426df57994d3eb5885d5796b52abf8dd53297a16976d" },
                { "el", "80fbcf7bb7c42b8f5846758ef9aac6ae98e895eb4ba7072a01e336d7c5e77d3044c5a3a080583aabd267a58f419fdc403c159db307d29bb6b289b77d11a29fea" },
                { "en-CA", "a866522efc851fc37b7719881de7a8818f4591e13a69418bda9dec39cc58a9e6ee18f47cd35cf154964c2a27af8e4e2b0cdabf38a8f4fcec45972a50131bd282" },
                { "en-GB", "4eb826cc61f815f41ea778b2e7e79ba6da4fa57e35ec1cf12eac0c43b1e463dcfe914d47b9a13d4ad35b7ac70ef47dfe919399290b255468c64a1c0a8ad162f3" },
                { "en-US", "c4d62a474d1036cdc233b007915d1e80864476741d6f353e691f4d649d8a3168f93729aa273740d24adce64982f3eef708cd43e38c520cefacf4739fdfbcd221" },
                { "eo", "b9ea69394f42a44889756b4139de778c45cc51e1f801d1313729e7af687b8bf799bfe52434aaddbe8b923377973fc4c2a649b9c8396c977b7c13ff9328cd4807" },
                { "es-AR", "c39ac04a66850ce9d33a85f61d1fd29a23b49bcb657ea7eaf07c2ee6747e5d8f670d0afc06321f3e0dee747b6c9533a8bc8b6a1330c2780b09dc7dbaa4ab9320" },
                { "es-CL", "c3f98a8418595f49dd8a00c566dcf33355acbec0cabd5b1ca76fd7aacc1c536aa4d355d36f4bb8412f127bdca51f56d432fd2b3e4f61d501a99aa45ad3466293" },
                { "es-ES", "a1ebe152234990d0e77836dee43fece75cdfb298337d5ae92556c9a96d2e71a54b39942d726b97f9335c8192f1715e4f88476b488f4f4b8ba231f638a038bddd" },
                { "es-MX", "fa40bfe97d989a6618c607b32df9b1927217763350565283401207a8947d5ad2d0ccc9f88da9925f41b7a97e70a2e7fed0f1f4bbfe4433f4dbd986258e0e0b39" },
                { "et", "60f051d7062141d230d31bd6a298c8f44eefdb95df946e364c8662f937a8c791ca730258931bf4ee88774930948d8f4e2943dd36426b3fa4afbc2978cb3b0882" },
                { "eu", "b7db820e812e60eab061d474b0504b47fcd1c739eaae1785bfc1322ab06849d64f8cb9de5e816362b728c43687161c6490d9132fe1004f81403f464f033c4e2f" },
                { "fa", "67d7dd4dffa655c2bd0f2288d9a62e7ceed6ad95b206a6c92f3847f4a932059664b568ed985a0bff9727f0efcafa9b09f134785312e599f0ab7508169ec8ff4a" },
                { "ff", "16ebcce084fc3bd12d1148c86b7335c84deb687a0048d059037931bb1bf672d00aebde5769f1b2e6fe6adcedbd566e73b69f2cad5ad86e3c43870c0b3a91381e" },
                { "fi", "d72f5dce2a0a357993400a838501d52617bb63a59456a3fc51ae6c47e06db744b6501fd9ceae2bb29aa8ccf39cb3075acc5ec8ad990d79fea25772eec5876c7d" },
                { "fr", "c2e2ac951a22b71640f4644bdf3b959fd443f72147f9295501a016f3b32bfd734a531ee2f97d47dd6efc786fd40c9131b4d5b6edafadf9a398ddd414fd1d916f" },
                { "fur", "34f320ed89d6c292d4ebb93861a18f90809adb902b1155e7ace15a0b4273046ddfe21e85df2df354b89acd1efc9d845253df760ac3d9d4b58cd63c4c1f502d05" },
                { "fy-NL", "f38f96f5688d26df3d78dda09408d8e5c11b1eead493312e2daa0192e37bdaf77035d9c678e233b4d252a774fe8225e34d797bdeccce992b32a3ac7f76c9e8e2" },
                { "ga-IE", "9f27b03c1305c21f3365e02f1dcd20638ec75dc6397593607faaaa84b62ded27ed6b2f27ff5203b1ba6e91b36ee39db7a7bd46c0c2e0d3bae7e2e20aaec0cc0d" },
                { "gd", "8a4261ca0b2d6ed41c0bc74f874ce83cd1a98667fe5bff197b43d2555d0ca3d3bb197d74e9f1e1beb108e4148a4e1304fcf067626d4768d99d23551c5c748d96" },
                { "gl", "451e243fc735f15f18c8612250b1ab58b7cabab8926ba8c6cf40a532c9636f749fe14624f152abe839304fe68741320e7ce2e0bb3805f9c3fff3559416f0c13f" },
                { "gn", "6aa32c744aa5e5e4c41492ba1cf252452f044976a215a319c20a4566aeaf840a81cefd387bdee48f373defea25913db465b16619d507342aac33faf02a08264a" },
                { "gu-IN", "7ecc0e285c9aa0e716e86930f755dae2dd96e87097ddb2dd0a959b40e140f86eef42ffee70fcb8a179987fb13d1032cc269bb28c55b43aa6bbaaf657418bf688" },
                { "he", "1e152a158a640e14cfe338c40741e50ee6a030ce15592117e54529665694c54c3a5e5539e860f77765fbbcf9b58d8e0fccfe11b25d90c7b69856c5270897e228" },
                { "hi-IN", "b3b5f0d8058e03a0a0dee6f5f86656fdce438c0b8d177d713f871a6b21ad721ed63a589dbe41060263ee034447b8585720310b70f442a194134e56c181d07c05" },
                { "hr", "a50baec6bda540923ead3a690c41a302978597311250365d039b31556cf6945b3cd2ac4bf2943197fbd85194dc78b1a0ba91cdfec632e1c846ea7f06c694d8b5" },
                { "hsb", "0c851d1e55d7aa6ae33726ef74e54d08a94730d7cec3ed564a7b45c8abb5fe0525e43d29b4de3c3f2b7f16abad0954b4b99f8783aa329f9dbcaa716e5c91c121" },
                { "hu", "0c74c239dff200499ac347e37e8893b370ef4f94b3eceed8299345e314f26481840052443353241d1abedc39d3e73035e78485998ec9a364d41620e5a7c9ed5a" },
                { "hy-AM", "118c289fd6b7a10e35b3ec780ccecadba926c030d8d3424be035e52d5c46dbf24c7b95694e86742ef7cbcec0f6bb2e37665c73cb6f3d27e09cb5b131a764a2d6" },
                { "ia", "34adf0c054daa0c578985545a14a76387f583b173a89fbc7e7275f58e8b3fc29741b4a49094c4475496997989f8cdf38275b8497f652d4c27fae1c477d0397c8" },
                { "id", "7692edf666ae50f3cca6cdf31393ffa5d45b3c9db941a2dae23e6867102bf5ecd1e040137f687fce43fe4a543b87b2d918269d4dac3928e9bd2cffc4ef6ffcf5" },
                { "is", "3ceb35a6acc61b9d934242c513a02af7a34644705309809aa9303cbda59f35b13ccd023b8b3c0c426cfa135e31a83d2565539f9227832e0dd60d7d3eb95d72b7" },
                { "it", "b0c707a0d0c4db7d45d4711cf38fc28065b25cf477f27e04a8cb77f5f39889d38f23415752cbf63ca41cc86f2b52524256eae5a65a78e6646ab4d0bbce3f09a5" },
                { "ja", "54218af5caf652b928f069b37357595d8a35f6f6d96979195d039093ca6711e6d1311637302c2929cdec045a8069d424b7b6438483ebaada1a1ec61aeb2b09a5" },
                { "ka", "5f6ef222365b21cb1264e133938139fbd50d967b482aed8a23d4140d7674e3eda30c446b7390ac4549dc9dc0b7d2953444ba04a8e91af197444a913e83240a1d" },
                { "kab", "9b973eabc84559c0814e03828dc4d20454d97b158150fbf62bbb04458b5bd3e5f0e69a1e34992bc878155b4968b1ae593f6255d84686ff0d98d2e991f9089e3f" },
                { "kk", "1f83fc8a72b9b956869132c70a7e425bdb715201fefe6506ad2b0cf5eb06926150c90591d94098342ae9e08ba1c5dab9c22de9caafea02d3340a334266dbaf22" },
                { "km", "5c2865783ff20d05cfae8f3d36d014317affa0b172823cd2a26070d5c9ca41f229452c0b5cc3bce3c8494122ccae13a6ff4e2db9a88a478b1582a92899b08c64" },
                { "kn", "47e0e03289a1907555e664ef09c886ab1bff080d67c057333cd34095651884b1199f15a33ea21928162fbedbc40feeea754b8a061c3b62ff7f054f271ea232f1" },
                { "ko", "deea963cf1f32541e46a8ecdfdd8e1a6b87a1cfb23d0567f947eef11ef2452ecb7b6e9bb0dc78c11596184ff798a2d7f394b2f4e26bd3471d43ebcfcac233df0" },
                { "lij", "4cddf2bb528f8c9910fb632b16e2a6b864b0c025d84d35eb060cbf2d2b11f7553ba4403395f203c1c17effe16f692c286cd2c4c26ddbd0e2bd995e4a46e512bd" },
                { "lt", "0f65dc490d7ac481833feeee546fa8b173b647c5e0ff29090a025086d9f83c03e104de5c7b03cc5b8317e920aa9614ca650fc20a1fbbc4ecdeecdfeaa8600205" },
                { "lv", "b358f9dc78a1bcbe737d4cc6fcbc0b32b9d141f0a589fa05c4b2590328c2363baea6f10e74909d7c1ec5cbf964c3a6b894265e46fbf63adcbafc595841d72d41" },
                { "mk", "7f4ce5c6f24877e5b457f1668d3d5cf5ccf55094b1e54bc3567690acd45ffba9330b7ad93eef02237deca990f0026244ddc7a3c5dd1287c918b2d7189ff30dd1" },
                { "mr", "35190604500c0f0143811c5aedbba2d3a871c7c425176190623bd52cdd29d6be56289388fb9284f14ad89f57a4c9fb53ad57040fbbb7fb53864f7a731cad3d7f" },
                { "ms", "73d3ba70ab0b352d52698a5538af6e86344e43d3736087726a003ce7cbb6c3d2eb2eed8f963f2e989e08cadebe0def9561bb1e9f1d0d7f3ebad896349762a711" },
                { "my", "25a8ab11c84999015102bc27b745f5503f4c5b207b6296287ee57db3b5d6126bec8c428e052cf64e18e3b0ee5837e7b20af6d1adeda8a8c0ac03d941a1c32cfa" },
                { "nb-NO", "5aef5bb71b55d914d9f8792f441a7ec4786aa2ac5911a3d46cab22aedb3e27e6fc628c9da0c57ece523310ef3fecfa6e6ddde565d63f4ce68324de6cd6d4c49b" },
                { "ne-NP", "0fd52a6b2a0f6ef454f634288c428af98e31a282ea22ff49fe0eac0dfaeeae34d5c915e8a072fad58ead95f02357a7421fb78de1ddaf34aba48812b1dde2573a" },
                { "nl", "060a29eb6ba31d40d4599d515b2c7de1cc09328ef60c470d3db8e2ae743c9d4b9f340cffa3f7b1b6e36f59a71f5bb25d5a676e224c85f54fdedc9887ae2134b1" },
                { "nn-NO", "04d171ab21b749872eaa521a799e0c9ca4e317c53c2811591b54a194ea84811ab3bfcee94568dacdd5714323f31c5df8ae9887a3bb29308db6520a4e5a05d6f9" },
                { "oc", "2d2a0be877cfed1e203e9eddcc26a9a2862babbd3e8e00d99708dd502b4834ff30c5eebef9f1d192a1fd8ec6ff59c72caee020c00accfbda4fc07351e6c8109e" },
                { "pa-IN", "02b3e496d7a4d245422effcc7b6ef56b083752723cac8e18f1940495cc343aa4b189e2ff6e9947c04032d2953deb5d1832c6ffeec2d2f4797a04d6fe7fb48eff" },
                { "pl", "d3ba34b8f4a1fe0c419078808cd182f3b5366385e8331ad54b212014019a34afc459fc54ded371fe1b146c28335d96ea082340efa09bec1fbf0623faa3a0ba8e" },
                { "pt-BR", "d4a90df6f1065c41c9edeedfdc7fd50a0f16ca6742a35d092b16eee9e206e3feb96fdae407a6b5fdbc0060d43d7086518f3060315d23fddc248bbe7e127c771d" },
                { "pt-PT", "847d450a2054b26b2412941108d347134228ed6c043ce0375ed0be67f628c0ec2b9a797737aeb7bc47a0671c6edcbf5f9b1cec637e1f736d546593f09145ef27" },
                { "rm", "56d31c0724f17ed0eb94908d30eda1ab822eeaba3d17fe909ad064efe29e58f07131746f88a027c93a2d998e45075c2aef9d1fedf0ccf379a9c510f7c17f363e" },
                { "ro", "3d6dd89611b0e7fe98d9ea36e9b3ab5e1a129616b77c68cc1d9ab50af17559c3a2943a617f67ef5570463d81a612117adf3f76858070a4332b4cd42e7163dbb0" },
                { "ru", "7cb884a69f38ab2475a4556dd9b80a635e58c76784d9f9d4de19d07d5f3df344a6a3c5e6c6fae379fe282e021a37d9af7204651b24b75a77d1509bde546a8999" },
                { "sat", "ebbbd05e59757eeea5188b884e208936d3020d6020ae09675028e1984094bf0b9a25a65364811ee8dae71f378831af5b8c61c74b962e66472d95d93eb4d42782" },
                { "sc", "5e0d1d1fce188623ba97461fa5e50e0b1657b87a7169f742ae34d06a99f94a4a3e61c350b2c3e501a2ba5cbe0beddb7f3f4be4879d3e10bcd1591751a410a110" },
                { "sco", "7e50acddb613307be3a6e35d5923b43cb9e9b0c737c4cabe2690e223aec2838ab681958887739b2ce1516c68e202f670c2743ef04638218f5cd6c150f1cda159" },
                { "si", "95e2fd0f1fc46e1c3347c5cd381be313a49ac7b33b57530c55fce40bea56c45f0a4dee3e3c5b3245430bc2c506604df0d7b7ab73086a165478e26d996dd058d4" },
                { "sk", "f02f001e55e5d79152a56ca2129c985520458c3c7691871ec587d74a9ea33511047d9dea468cad9a585c524b2ddbfa152c532a40f3a3ed51fa6dc7008c837782" },
                { "skr", "e56ace66020a295f5502dfcc638ab2185991714678fd0000b50e9783b794efb07d6819d36e6e269ec3ef0d8777ed38f2ec23ba53c206a7b8be18459e300d697a" },
                { "sl", "6127f2dd850d23ddab8af80d5eb8d5bf098b033fd0c521523653892fb1f2ccf69c3b2e25a7161991cc160f4510d734a2aff8cc04e5698c28afa0efd7ecb371d4" },
                { "son", "2a762ff29152c0af196c526c88c3913dbbadcd60c78e713b244ed76088b6cb807d966e6f0677c3c7feac671a5b530309776e29291b147a2f9a986204cd0f9970" },
                { "sq", "2fa5287c05e11fb6b5ae2694863236648aaf49bef877e9ac53bab9fbe5ea839c4c0d8b7692d0ab0560d30776de35bab1ba0d9f45a1cd8e1e6829a44573bb2bd9" },
                { "sr", "824569798a3b43d00cbce2a4e67bcdf642440c10f2ad109199904fecf6543e61a9b15bc6cfae5f8870020e8532e1eb6dda7860da1c87f5d05da42ba5ffc4906c" },
                { "sv-SE", "47f345426a8a391a3c7d11afb13603db5fc5bfd0a87add7bf3762e8c41a03b740f36bfbc1d3351595dfd3a6b6ab2c0d6ed33c12f8d500df8a05343d46eb9fafd" },
                { "szl", "e4b0958d9aca03dccac217df550d901062a26110dc1b04b11e6529ae1d0cad4af821c31846aee323626e8bc161dfc07b06fc92fa27bb7eeb1dbccddad85259dc" },
                { "ta", "76a012ef88846c46a075c9d06a9184351a866771952351733be4b9154cc481de30e042853bcd6a2cfbd2f6a28c185499be84ccd1577ea7dcb71d392dc617d226" },
                { "te", "82d01907d9fd71ebfe958a0e57dc2c4fe44e2dd161ef6a534acb0e2050def6d3bd494fbdaa326bee6493b902d603d619de0b85eec9af8a21d06619d2ed5bed25" },
                { "tg", "6b3f4c2495f6ff0083dc5c2cbef3660812dc50c3eb03b3f873c419f1516416f12faaa8190236828834ff6df134032c13d5d6247c8ec065cf8c998c991830a70f" },
                { "th", "276d0504c1023e18c88f085080c1fb448fe10c52279db5ddfe67125dede644c803eca5d68012bb812b7f5e5959e53cf6ffd4937e94347df6cda886e45c2804ee" },
                { "tl", "fec571a3a9564f8fec672913c1d746f277a4d845944445894128b02ef5f0d0f5ca27a74ba9cf9b302ace2a92991de40a67c108c63bc84fe96ed5fd795cfdeae4" },
                { "tr", "49a91d5624d41526ac523ed932afd5eaa3e3386797e24befd7eeee63de9be940e95b2a6f023492e5b05cb56dc1e68c1bc45b35bc60bbd758e9ec35792d46589f" },
                { "trs", "8b96dfbd7716cd1ab1175923f699d266f7f0f9cfc9a56d3955ba288a7a4ff1521485f19880ee129da9b94da868e1328388dfd772782885721879738327cb26d9" },
                { "uk", "353aabf1d7b8d7015d07e7661592804c3293b38ccb19d513e71ca2879c3878fad4d0862f90f9c900cce38da409f6c72b3c503953e5195cf5200d6502cc7341c9" },
                { "ur", "25fa5d5fa952e07c9cb3e10b93c7d0a9b048e7a4d8d580f2d0ef8f17644d3cad5f8a7df935dee824dd51d1e9144ad1f412321aa02aae847868992f0c12364ff5" },
                { "uz", "05111b364ee494741a26c5bd2feb483354a3e50686f3a11a01e26d44c96e46c9ddaf919e2f7e1c3bf69af8b56de5541d3268b2f1d050d4f6538b68863be6e7ef" },
                { "vi", "eb335341f55b6a16ba9b5f5ec84aafefb06a40fd37fb7194146a6417129f9ee4525c44aeef1ab6a87d3a4c5e59d1a6ab7bd1ae04f4e61352f7065d0d39bbc64f" },
                { "xh", "cde3a2e9a4a1fb6808dd44e177e0ea9337cf7e0cc8f1756257d3e5257a485e91642ec463088e681472c6a53edc024b6947e5546307f6f6e40587cfbdf13a04ac" },
                { "zh-CN", "803dc9281558b46b8fac546bd778c624decb314402d75edac634c31f335a563103d973c17ab951bbfa0e0731bb05191615f16224424a7b28a153e964b47046ad" },
                { "zh-TW", "922d7ba000e53cb9339fe74457014af0cc5b6751218c0f0d76ee31f08c347ad8076b87b3396497a6e0eb751599e5f8ecae353ad900babfb07651d3be4fb7fd9e" }
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
