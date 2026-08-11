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
            // https://ftp.mozilla.org/pub/firefox/releases/153.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3f6518eb8581cae4242fb6f31af3f57e9bbf40a9390fca7cec562c0b3c6f24d981b28c35d0a641d8f13a61f65df097aaa4737b856512c05016648c7edf8f6254" },
                { "af", "a22a383d382a14e8b1ab75a4f993f09da3d1a27d492abfb9929c02c31e415fa1259c97be7c99304a3d1ad89c3d169d662fa7e8afeaa3c6bbf91965266229918d" },
                { "an", "649882809f851322cd55d3859e21360339f09c5272cd28cc46a70185709fbf401798c171914a9c4323d687356b8dd0f7a3cdc935c6ea6f002833ef9162ddc4cd" },
                { "ar", "043b6c7c761292862fb499a0fadb34e9c2bdc5a67f53ea66ea18b40a2b29a964cf91d2bd7c330c80aa06205b5dc0ad54839958ffc2d15731286af9fa0e7dfbc4" },
                { "ast", "76c630e525d283571cc990e0d6eae264b144dc738c35247201c5f60b915a8161645cbc3d4a327b3e31797a36bdbc26023760ac957ab6f442fd204cd4541e5332" },
                { "az", "06dc80ee9e2351411cdc43555bb66d35b10d4fd87fbc02a2b06839f500ed81f9942e4546038d3a9fdf0125514a81e4810a71e3b4bc38fca48706aae425c30042" },
                { "be", "a47bc08e869b437243fd44a0c46753c2209536248b3998fad47f939ce1bde7695e9dbb1a31d2646e6c9ba63119e6e458b13abd1a81f0652435db7731f7ba70eb" },
                { "bg", "35e6010e2660b7b4d673910190a792f3638c372abdd4e8f25afffbdcf2e974f31e1089556d423879f0a1a0eab69e9eca81dfdedf2822258da02b27ecbb074b92" },
                { "bn", "7eba08c6811918c682d0adc61943c3a25276c01d997781b6f781457a07aae820a4c5be5a0364da3f73a2cb851b9fc079176f7c625ee9f2b4fcf4feca55abde22" },
                { "br", "eca24e95bf410af4d486aba334d05c29ac88056430713fe75763a1d150049ba3ee58fac1df64e04f27d64d15aab0bfdaed5c44d39c293052fa4d45c879b39bd8" },
                { "bs", "44a4e013313d1a55fad55b7a2826364dc388b56fa9a7e7ea09ae69bb76276d1cbaff92117027fefb497bed45196fdca5c04970912c23d39b430af4887595ac85" },
                { "ca", "bd75059fe5f617d692f0e01d4e1b5c944e3aeb8d65b69b01a55db84bf70272271b8a279e6db698f637d63238ed12dafb283aa03dea4ec94c242f53222816b47f" },
                { "cak", "6cbd141a73fac73e822368650bc9ba6d97e13c088f91c2f779ad3e9416154f12b7379ffea57dfd73d7d082e1cc5b16369a1f1c2f730264e672ca77266c53a9f4" },
                { "cs", "446535b0abfb8ce81aa1a3d45b9c8d854f87db0f184eb81dbc32b1ac129caf0b28714a6ae4ab6783763618e388b45ecabfd7a5310bd7f65c111771e4bedae15a" },
                { "cy", "314c84bad09db61635ce14fc35acce2ea803a22dd53507e2c32e26000e17b82c100ace6d75898a157511bfa3e0858b63abedd2284925e4e9b7ed365504e0e099" },
                { "da", "70d65343878e72f36ab7f959b6f180afd75c588eeecac59ad800fde1ddd40df7a30150b31f80309d4156680f01d1d4a70d82bcaa3d6187a36f327742b066b36e" },
                { "de", "3285b925154d440b26e11691dc0e13cc7c57145bb4019e89e3e63b4fa3f2a01e5368cb9411257f516249865ff417177f474191e74ee8147689439cdee2b4a301" },
                { "dsb", "160a96b2aef3637f4f88c0a635c90334ed5ba53df1ae4f109e9209a50cd9ce0223b3e3af8ac857d2a5578f91cc31c127b40e8e4212f7dab3b1745c83caa897b1" },
                { "el", "974fe4325ea9b4b8996244b1002e127a65e364a942610bca89c77bf3dd2ec39367fad3e2fa48222666b8c4818fa789fba5d6d3b5ea7a14cd8752eb56b396648e" },
                { "en-CA", "408017093dc5077362c230c36573d6db01bcf7259ee4db69b91eeb50ec2f319277964b463b2408b53362124acc838cec087680ca58afa935e0ac94f755717a2a" },
                { "en-GB", "a5e1773c9e3250e35fba10131f4299debce160934a370636b2f449268ee481e64b855d922cd2dcf3a1fea9b87efd98820ba6adf1cab79aedbd1059ce638d650e" },
                { "en-US", "810b0ac78934698122939e83baf8330822d6ed82db962e5b288814f382213267dee5ddf87182d78c1652d7f3e9b90144befa9a137473ff483fdb15a59edad2f4" },
                { "eo", "a05590947659597409c08609a91534465bdae640e0a4cbb0dfe25150b463f4096a86f76db8d51e986979205529fe808128a8471e3180f06235f48af955f49807" },
                { "es-AR", "c826e4d8e885e58b959a852b74271205b8cefac0eb120a97f791492d060335219a2fd343344ff2103d33d58cb27866bda8872d2bdf9fc571fb75a4757e38bb32" },
                { "es-CL", "9ce12ede0326abc3d4914c08dd995bf33d45aa66932afb4032944d01e3f88328364bff28496b65f2c20b48427f5066ae159edce62fde567dd5b1a98aaebd3250" },
                { "es-ES", "a6878ecb6c1d3f14e2ebbd6ef8c2684f84e9e534c252c164afa852a33c86615b3eb64d65a410cc4265168fcd158619749ed75fc28c33fcd2a9c859e7a2357999" },
                { "es-MX", "f0cce5cc107c3f4f044fd4698585b4546b1f45cd2f222c273735d8f51556308d66a5727f04b246abc546a350750e51e19d5729516354d4ab84b5148847857ab9" },
                { "et", "89a525972b97f6dcb9babd506cb1adcbe0d2ef3f9a9cf650c6dbaf622a12101f78ddc1bde4051e5abb366cf5f74745970f5a8ba0dd578d280ab124cdba7c6c89" },
                { "eu", "29074629fff768ed8a2a741b24f18c4fc26f32f16484cc11d9ebc8d454a0c7a0ad7a9b2afcdc192ccb1e1596237ff7d8a62254ff4cb87312cebb6c785ade325a" },
                { "fa", "5f89dd480f2a6b4db579e280aa99de79c85347d8450e85541a5329f585ab1b1b70a40d9685ff2c29bdb18464632592bca86e92e600da675ca6c46ab31b6f3563" },
                { "ff", "6d3d3a37375b405167fd25b079a7ac8c4c917e828e80b7d992e91c914db6b86f4cb071f56fa2dbc37f119975cc762a813bcee21e80b6b91fccce4a8a661f2c8e" },
                { "fi", "13247172b85a507541bad3d1197d2dd5e38af9f1f164417c499eb442d993c5e9a38c46e0ea601a7687c45067cd36e5e3f28c1366d67797515655ce16058be405" },
                { "fr", "12f3d4ec22b7758df0c5cece5e7b25bae0da3ae16102e40ebf7ec710f8fa818ce32e38a2ca600d8e5cabef49e4eb4cf71d436136f1a8dcd20658e0394b8387e2" },
                { "fur", "60ceb091e20c6d62b855cd02560e2652100f1e95538d6104520e1e168c6e53a1ae46d79afbb1279cf7c43f1f304f7becc76ecc3c0672aeb5f82bfbdc964c3b8e" },
                { "fy-NL", "fc65b7e57facf592917e5cdd7fbd30e12a49adff61a5e5b26b3237e10026fd79e391b04b180bc3aea72831f971fa9ca58e7f8feffecba41d449822b76492da67" },
                { "ga-IE", "3e99fc7aef2579536efeaf86ff411af66743ef6753192d36bc904726b4fbb69cefa466c0353cc2a19c74e6b53ea6b87ed511f8d9ec297186d357909397441c2f" },
                { "gd", "6b4b937d26248c97a98a3f40fc0bcb4977277c2fed8cf7a44b064da9cf090b1ed7ca6ee0f2212445387534fcbfe85acf5cefc12352394b170c30000d67454515" },
                { "gl", "07694ccb752a7df817361bec269275a8397ce0eccfb80293be211a7d08539df7615e898c8fa3408d51283a027370bcd8ae90eeacad4f0471ccfdbbf0a9acb587" },
                { "gn", "a75d708929026f1d643fecbed0ad50048804dee2e255bd932d1566134ac783f8bd2f3d07ed84a115b2725402015a5479274ab7c5ab57214e5797a7333b3246ab" },
                { "gu-IN", "e3cc2db43b902f3d2e9d86809f851c25f0cc8ab86851ff7435ba4506fc6c9fcee7b2eb8de7268a9e4b61c4ab768d2e70f10e5f63fab1f79ddd6e70ce836dfa58" },
                { "he", "16cb7b2b0836747d71acce5091fafb8c7abaf0df8008f8e2c4ac6f9c2b9da1a980661155bfa70fc30337b6e619f8245a05364574273af78b35c485b544550e85" },
                { "hi-IN", "119880af68b407777f5332d030a8a2e40652709e07725351fa3c99ee0dedaeb6c40cb1103f455da176189bdd29da41c9dcc0d14ed5668ee6b082ef11a2f9cb5f" },
                { "hr", "a40a2c43302becf4c5c2fffcbaea60841d2c2f6d2e53fcb24c3099f491fbce5e80d1746bd23c5a297876768db28809890cb192b323483be014cf0aa883edc904" },
                { "hsb", "e0fe24aa2e5c020b6c4a7f88a076bb5ec97b3dc5e54774aec986d0d0ceeb77b0203900944eeb65fd570582159f52e14afef0050e859a70ae229ac318f0c3c2cc" },
                { "hu", "af5888c04ea7cf1ed107c6f5e61c983682fabd1c3e30aa1cca73c72ead0310d9df8addd7964ae04b1cf59a6e334c6e297ebd5c20e2688fa81223ac98916ef0ed" },
                { "hy-AM", "4956bff84b26d64142d7b11901998640737b67c1b3994a2ffb8c2e3956938524f4564675ee8eade5171f3aaad90d4971ba7d6f96a0502535c93df8fe5eb97041" },
                { "ia", "1ec258654ad76cd6171326915332edceb85c7353f351f7e1cd949979fa30e65fc36e23ac653c503250d39f8d32859488f02e239c8e89965f6d6ec5b2faad8094" },
                { "id", "ae7e09ac8427e273f716b3c34ecf729bf629dbd3942bd9449d3cc56acbb5fc2d92cc37f3efebab3be10ba0cfaec150832bee9eaeff59dc726b45ad6fd23110d2" },
                { "is", "bd3cf8d15308b25b6d3b1e7ffaf52a9ec2b946915a2448691f8b7854cd5a2ebf97e6186cf09a10d2120a50ef547dcb424f72676958212a082d73f8db97715f19" },
                { "it", "e57278e0b3431b902b1d8bd2be382f2a6387a7efd033e56f77df69ea29b6e0e413744b69fe7313a904211959c93f71c69f4cc0c517384686e8f2743de6a6639e" },
                { "ja", "33006b69fac63e1edbc2c0bda33e77b8876d1a157a809a742937b5be46bfa6bf831d51f84d664bc3f9fcec15f79b81343d85b65ca6271a8c5c31ee5e60eeebf1" },
                { "ka", "41380ab7a3de3f26d8c27bcb7f4cd41969ea2a806d3c3485e86c061764f74e920152e8e0eccd69b8ca29865b8cedd8821d674e0376c932e88d675e8f1006f677" },
                { "kab", "745cfa2105fea6ae7816629a77a9361116fd05534ca5ebe6a540580559f10ad70d887e286be2961734802afb38a45bbc5365dceb9abf3399fc339f732889fa54" },
                { "kk", "ced8fc325814fe014c4ed6e8c5efdef01a6cf2443b2768ff6ce50ec16372d103d8037a981b0f84aae41985f53b06c2120717a69aae5a596d6ba50d366de2cc28" },
                { "km", "8423db32157a4cf258bb9fc3a21231605a21d0fcc49bd609cd6d65d73688e99b5c053d38f3d30046494f65c4b8e704ff4b7e79a77410c76fa11f17e87b526a63" },
                { "kn", "03b4c8c0d3ddd8b858a36c1dc2d65e42c32242c61da33791925d8b06afe69978f7514079ee0e322270cf572bec0e90449aae25754d009e6b9bef2c5e4f869260" },
                { "ko", "b36c428c4e0b180da24d8ddce28059bbd902ceb9f5913b1fa4be2090193b08a0d8e41319d326d039d041abce123f723d8ba6e3749567d33b0174061cff429f2e" },
                { "lij", "bc74321570ab88091603f8c177159e31853d7e3018186c7848c6109aeeffa1a7e400b4265ee3f6a826659d7f5eaf1341c80071f22439bf45587ae3a65b9d7e10" },
                { "lt", "e0d4254c191987c0ac0557fbb7a169bbee88eb906aa22c414256eea3bdd15c1481ba75ccb6dc889c1dd08cbdba4eb559f367508e884d1136bc695aa44e87a748" },
                { "lv", "3d86c36d3c35537dc865cf9da70b2b8e4c0c67e248959335a707bbe12fa5f2504d1bf135588e3703f8a8751f6a1a9050873ee57a2ecef8ef9903a91a6e6d1bfb" },
                { "mk", "d1b643d917e30cdb4fb912b8b9d44aba3161bbd64fc76efeacee7e41d9f4ec59800e28016248cbe593b30c528c8d07774547e81ec0c10a78994fa40b35fed5af" },
                { "mr", "a16f7262cbb278d9c5fd8d30b0b534d088f787cc508f4b7f0fdf61a390c28dab3df28f3f646b7a465546c3904fd34608572c5fb6a239019d2f5e1ff875098d5b" },
                { "ms", "80a6e0d0a4624543aca8575ed11a736e20647a63f7589a5d7c5acf93dbc70723c48f83145d588920ba2ce7e0a5adf5201e39e7e0ce8997d1167537641345c968" },
                { "my", "ff5527a7b1f5e95ea9afb6ff623dcee98104ac835dd1796d3252401a3eb3d75032bf4924373b763d13c29f1680f7f9982b1254af6f46a9fd1635e210b18f44ac" },
                { "nb-NO", "2c290e1f06b0772421b9f0108d845a7f9128a3d443436e3f325b894232552d33582f9fcf1af74b627f0f04dc4ab841371a4bf0db24f8e1c103a700cbf2be2a7b" },
                { "ne-NP", "606eafc930397b5b9e7aec86ccaff4d56a8c87283b83b15a3d2169d67d03a5e5b9b9d4f822305f04ca0ae2bfaa930e380da1bc2ccb054994b81784ffd785d30e" },
                { "nl", "f08ab7984cd2a34c5c7c73464701106810c7d7f619b23f95aefce8ed463cfee87bdde2169d03867166d6aa3de3f82ad8dc29a100f3f549bfdb9bee7b652ccf18" },
                { "nn-NO", "cdb9832b9601fbe12a680fd408029b5616a89d6c01991025e245d15e1a4ad63fed243968abd71f8e7b3e6a7b99fb35f6377fa36cc1195d0d5590a802c7e579b4" },
                { "oc", "ae4a33d068067e9b1c52e082546b895a1041da323b0daf4e4f54d85439078ab0b30c45f06d63802ac7da97adde9abf892f4f47e3218d4b5666c43c695d298dae" },
                { "pa-IN", "46747cb3812fba6698ea1575f98e41a51ef28b102b918d21debe475e3190be156a5b3f6c65b4f04b2030edeecec0144275c3a606dad1e5552db61331bb0ebdaa" },
                { "pl", "f5be75557c2c4859bedc99f9bbe327dc2d91dea2a57481b99d86fdec1b7b29a089676852e2632943518a4c59b235af2af6de630b802b460d3302f720b6508926" },
                { "pt-BR", "c3d43889b6f65de6f894332d6690b834b1c30ce99bca5f8ce5b71607ce6c334eba6721d50b48f23cdac1ef49b335db32e93c12177f8ba6989e71ff9b752d831b" },
                { "pt-PT", "670a38ddd7bf8d79d73525af4336399775c62e19090ace1c36f9c3e029c9246ce6362cd9b36c361fa3d6bac5bbed88758479a43e1f9cdf2a99d573648dab88f4" },
                { "rm", "2e61654a16816ae6e850b3ee079047b88a4c35945385b194d7a66783da712be077f12be6a38b5778fc0d75057ea8d8b2ab33eab46eb6709d54d1502b0f6e7bdf" },
                { "ro", "808f25b8d42482a4cd2d43e2ff654927bac881221ccd82c967d034530f4676d30683cfc7ae0ccfa91b514062f879db28a7415ad66aeeecd8e4e08b4bfa6b2c35" },
                { "ru", "5f32a6595abdcc1ed68896deaece914a48c4646da183a504308ceea72966140f26b513dfe6c7a5099d91cb7c9c7441eceb59676851f4479256c16a4544eea6e8" },
                { "sat", "3cd5d8d1342b3643ae302f1e14b23b1a027319500ed8555615c632c13a83b571f7ac0cdcb6943a285e8c561a57738485aa0d35d80afbcf7f5749b359542d133b" },
                { "sc", "0802d95e9797e18874a549faa4ffb0e4a2ac36ae8c48b53f1abaa6f376eb7c637c73e696974654c07608892515aa72060f6a00c08b4b68aac79c9b8d79c63234" },
                { "sco", "9f701f7adeeaa079eb3f999c8e3c9dce1b4d357dfc5fe82337f0d33dcc6ef4bb946b68f8c07091ceec9b428270d00eeb6cbefe498961723e871eaa0e9c49d355" },
                { "si", "fd1e4f9599d2ab6d21f103c864a1464cbbef94a230dbbfa722b23eabc882adbdf2c07e58e83463633cdeca8285f155198866646f76e0919470707594b04abe53" },
                { "sk", "2460b4914262f5dccc548bc6bb544b29cefd1d0c4dd1ea0d5bdc0a85d873f19999b9668800326a0705e438e08b1abd3e114a63c3cf43948472006fa777192341" },
                { "skr", "a22876538e15796889fdc479b886826beff146c7ea5f6a484c993d568625c9d0b778bf3c4d17e8e7f5a74a072711eedcb75bbd0045c745463e0dd3a8942e650b" },
                { "sl", "aad9ab9ab70cbe58bf1fbcb5765370eaef87e8e2d1d5a04a8f2794fa12d18c2e1ede8dadc8f6c2db734552355486cf2d5934ef78db3f3068933fe83aeddb7f23" },
                { "son", "83e3020a47ab02f7f851db0aaa02cd8b60410ab8e20ce293641da7bc38361947acb38ff6d2f59dc114e5a0f20c3a7bececdec9a59ff2a11e1859d4641de94c39" },
                { "sq", "7f349f26804fd055cdd0275670ab559af171988782398aaff251cb5b84b85ad341cb0f54690239a0e04bf5436b04cc34221d49936eda0533195d423f7290b7f1" },
                { "sr", "ef0c5a64902920e0dc382efbf360720a3e6ea3ff95dd4efd38d5fe351fdf20b6e681fdf39b466e291485dc349bf279dd278a7004e1d3115aa6fb24bda1151ec1" },
                { "sv-SE", "7ff49f13631d76554f235b925ed4320eed5f5e6823e3d80164c2e75f463d027895389fd5960ce3a37d5a248a56ce964619b2729f0e9a0c4bfdd066e28f55bd64" },
                { "szl", "7523d1a832059fc70de0402f1bbbf8c495f6a21ca999291714094c8d7459a09aa8444582765ca5693e9f0003cece62c02a8e6a7065c293cf19d801c2a98886bf" },
                { "ta", "ccb053424ada4bd29844ab5501864d8f65db0c8f83ad7d6635491ee449ffff8a136a779039179fa388a93833ab3a7011bf35f29dd4f35b1c2b54c370ddfd5c74" },
                { "te", "1da08e9235d0848ed7d822190fe42e119b02dee6fe3c40f1fb0a6896ff6a1e74a0992fc8b3998267ef25b978b24660b844718cee155b9ed218069303496f8c6f" },
                { "tg", "47090cb14dc1f9c11b0dc38ba90f39009a2ef7077bd521c1a139ce12a1468b3279977916f99baaf472799e8a6daf69e9f4543ab771292df7c3cde7286fe25cd2" },
                { "th", "65159b29b8f5a8081860708a83f806cce42eeee7790f48b621fce18bf45ba2c102eb408cc6b3146b505ec663fa4b82f39c1dfb87b05d0125d7728401aa924410" },
                { "tl", "64579ff8976c1ca2b476060524693401fddf8708aab0af01d20505a504241ad4861304fb13e9082850da8b0b153ba19a4debc070dab770679971ac926a078922" },
                { "tr", "2833a88b75d920f3a3dee183b3951708200607198e78a875ff4fd19c8b252272f4eb671042c35c67a48795c4897bc0fc7e744ce7874e2450f4572b7980823d51" },
                { "trs", "abcb4b8917554b5ed1182bb060b30ae1fa574c6aaf49929fa71a2404007e104d03fb586657d7807f836224b546e86d65a087c23d36ccc6fe9d2446203b60e371" },
                { "uk", "1577b9f96c19de5021160c4c7d0365d035b532e61cb66d058b579fd2655b683fbf4e9153ae4c2dd3918668413446cbcb74fa04c1639038289817f57b5471be02" },
                { "ur", "01ef24c62a92d5491cc614cee43baadbb54807d1926e8d5a3cd32c00a1cabce8b5d0ce2318e20f64c49246c40964075cab7658f581d00e6be7f268d667168075" },
                { "uz", "dc383e6c55d051733e756354457294bae5ec038bb02cdced75fecffc2e6963b353d3fad363c002f2b4cbbb2f05febd02e02c55eee2f7b1c3afa3b75053b3112f" },
                { "vi", "f963502117260ed86fd3ebbca6e02039b70c1b33ce50cfd9232683f9568c6c8880fa6fc49a2c12e930e0be15e4ddab86f7761cf3ffad028a4be4294eb3f37f8c" },
                { "xh", "a4a1eb4f72c9724e41f0eda86b4edd45697d0e1398d6149971ac594bd933d23438da727f3376c0f99b8abc0626090ecdfa11a9cde048313c02c878520cd00836" },
                { "zh-CN", "1575f96f5070c7916f40cccf9f77bae4dd0b671b098c666a2795f3f1f1dc452224b33f45367be18110db798acf06e8d86733cfa76ae2ac6802a9fda6d2469590" },
                { "zh-TW", "79f9468edf485adb09cbe3b5c9c4de2c2161982f21582ae1999a9d1fd3ef17f53d7825910c28c1773235a7a0976bdc73d72f79e6ea30b841a2bcd4b75ccafca3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.0.4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5cee6ea6f70f252203795cddd8a0b8276c6c144aa074ec3e93ea2495bb101e64f11f203237e2bb27ba837d9397767a39db04a944ca1178ff6298a822813f3f81" },
                { "af", "9a450ad214211a6fbba4447962d167e51d7888f887907738322c58bdea9963e4419f0c0716476351f71ce2954edeaa90fc2f0c1fa5706735c142492d635cac2c" },
                { "an", "d0a86a1a54d207b4202d97a4a5023af5539fed6ebc5b6a1e06bb5116961aef2a78c1cd43c060132e7c3f9b88c87e302890ce9d8222acc264ee6a5fb672dcf66a" },
                { "ar", "ac942706d4bedc8754bfb3c5a2d50d04b9b97a988045eb576503aaf5e45109c20989e3b26f055d99542aa85edc98731855b4b01fa4baed45decfb1e69e537b7a" },
                { "ast", "5df5630a86512306ca87a99630548d583d217b19619dea9bbe7b8539d5364cce13f8bb9324db3155d9d39a76eafe02a21084a635a379ed8c483a8ca1d236b3b0" },
                { "az", "511867faf1266bf53e5082ace8e1d4885a262856c18d19eab9e9106492911383fb8e9348ee3daa39c0e21e87cab48c869ff8ab2ab02cbc9fe3c2103e16a7c20c" },
                { "be", "353a4b3f3007a3b4ff91bd549bba73362b6491a4299e51af2fd7bf24011a959b8fd222474ec05d8d3ab53debed956e509b82f172478ff073650f85571ecae800" },
                { "bg", "619934edb26c4de0a7be06cc6dd2581521e056431cd91106b4faee772e2a1e727e4cb9e40f15ace0231f6efa0f788c76f438a01d8c54d733c733e2291c7944c7" },
                { "bn", "4c83b7f60c3849965e361e0fd7f8931e6be847df58b5cfbd501c03e19c508dd55a1674e92771056f72ab8ffce85257ca905cce2da91026103a6c29958ec93c38" },
                { "br", "720900dcd8e8a7028b03b3226d699e9285a09b01cb858a295e4d2e2095814c553b600a45537a96dc36a40125fe06c40e0a6203fdc82abbf603294309fae5af6f" },
                { "bs", "9e8870f7beab4a8eda9761f1639308154baa3669a64e5ec4117630f3b99057424a06e5cf9ab86fd1e11b91cb5755cec60d3f34da303b475625f83db1c64402a8" },
                { "ca", "c09c8f729ff2090341745300c073a51bcf51343b53b8011f64a6dec3dd2ec2059673401878de0019408b264897f584b0b007f46d3e4582d1d937e7c81208d872" },
                { "cak", "238bb08923188b78cb9676d1d14dd2f3138830eae5e8e459dd0fd0d37a497a74d353969eb4f610f6f0e8ab6964b81a62c23286769e8febae0f718b2e0220ee5b" },
                { "cs", "8abf02e21b76981a46cec82d52516e33e8a6c7ac7e5ebddf9f55c28e25fbbcc75515ebbf63378ac91cb3ee71e276a96540b46b281fbf48d6a5a56e158bc88dd3" },
                { "cy", "1f854e80c8b1c379ee14a2193aae039919362ec8124f56b3761d2bfcd56e566dfb0537ba2fce902ce67eb5fe796899d9b17a2c7985409b17d4d6edec018e11db" },
                { "da", "ac01c1d3790f56abf523edc2ee6297796eeb8db9dd06c100d3aade393e8da482855041955e2bd9384a0763a660957f8acd67809ba52542953d6d1046c6deac3a" },
                { "de", "02a04db58b441eb5c22bee9159daa3bbcfc854b7e9fb03339d4b06c48834479a604202ccbae0f1b9fb5af1a3b2f0f11c0f8dc9570e6e7c2f90b124bee1d16a77" },
                { "dsb", "7a1a2021f86fd2c1dd16bf39d9953c289d9eb439374d84e7f6d750c15da77d6180222e53cee146eae70e1292a29d9cdb423ff5ea1160c4f005611f71fa1013b4" },
                { "el", "7c4b704b42dd8b5e575a162f8b5c6569529d7ba5c9475b71036f39316a93babc160868893cc3f752cae1164ba2f689a6102f7a2d7380342089b33388b34010bd" },
                { "en-CA", "385f4ffd149d0cd7e9e2cd49a0243048dc53c8d7c000dd15ca42e68d276295bfbd019166700f2b350e92beafdcd273d104d7c7b9ef834ce970c9b4e1aa78cd8a" },
                { "en-GB", "5d353f0a703fd293eea7b39cae48c1a5e9b84ed76ff282ab432a9b626d5966d82246ae1bfde2d7d95d8e183576482ae5c26fad2e57cbe2ccb0c0e7e26555c14f" },
                { "en-US", "e31ced9519982aaaec05393f2dbef9b51dd35286bf133b373c135182306503fca5e37bff4d470d9f6c751ff98badd4a6ef1baa81da323cdb564302f3c42350a6" },
                { "eo", "40a9a51155a7c4ddde5a67c3b065017cf1b9e9e92d6f3faf30f524bf16599b4b033be53861f5323e5451d3a0dbc689560cf55eaf4d39296aa0254c99196cf933" },
                { "es-AR", "53cb591640a84a8ced305d3221cb517987375f27eb8b54ed90aca4e8b60dac5e2b5719efcbb49e0959c059a28bc59bad09f390e4078b81f93e3143881dc34b2c" },
                { "es-CL", "19ffecc81e07c4672b6736146ddfb100fbd7cb0e7f0a8366e4db5756b685116a32e1b036e3e5d48d1750ced0a1f8b826a50d890b4fc8798925dad7dc66fca1e5" },
                { "es-ES", "d7bf3b4bd1824e63237673a5dd4d789d730b419e204a407eae0fc41885e5876e8fdd224f3f50b8902af52f1522e3db097944b6a1d13736b2915adf81f9b12466" },
                { "es-MX", "0414e2a006cfe90d2cde5645c5ba6913387e394fe10b3099965036dd16bb35ce8e15ce3c98884ebdbaaf79a0d3d7ff62c5c6bfd65acb9c3ec0908d318cfd07c9" },
                { "et", "4024b258d5810b3a6d9b5e519325de3108d30206481563c60cb18aab39b80604bb0b908f67641a0d6b649597eb16cd00b7902beb271abe0b39ce6bd7f226ef88" },
                { "eu", "fa86c0091388e4e82b09d61bee5576f18492715ddd5b489ed7b5e246eccd9fb45bb942bd3e0472b606cadcbb280d87534c543f90fd6bfdcb5a6a8793022e2a9d" },
                { "fa", "0d068ed474dfb8b77ef58fbfabf8f0386b6c803c2bbfff7bbe7f641316466c20b74b4e05177af602609c8ad61df8ea270316b6c6ffe64fa9141092d45da7875b" },
                { "ff", "55a85ce068ce60ba8fc587bbb63ede31c765dd1f4c2f4c314eb1ba5d111b29e4558e678807a2676879c8cf221360cc05f75c43362ffd833a4b1bcbed6a09b3bb" },
                { "fi", "7bbff4822c0fc44eeec59a6cfad5a2ea00f86059e03e6af1b72997ed1f99c9139a079f0171fd4cc93ee775a49ef189deaf931e5c6f7d02b4ffb3a58140e8e798" },
                { "fr", "0137b30eac32ce9f18260e43d28cf00bbb4029fc42d4fe5ea0a6afbbd78139af614b149d07c3179136016e6eb3b3f06ce743f6ec55bba22a288ddd3b275c8ee3" },
                { "fur", "b1afecea2174a7e75a55c2b114c02f07587ad34f2970e8823bcfff5a9b9f179bd92ec652fdab388560831c13818404a7ce3ab8342f103e656dfea87c2e68d446" },
                { "fy-NL", "c637de29464e8a5beb85fa2711da80f54a82e7bae61df3f8cec77fbcd0baca3669794f88b4441defedb75e435faaee453aac212a451a9c6415cd13915c60d847" },
                { "ga-IE", "233ff1acbdc14700251c853e43301c8700f9bda9d56331dd06274d6ff32e2d98f7a9b0bb84cc47671b73a82d9acc61773edc923aedd619d79ff7909f33c8caa9" },
                { "gd", "ff4ded108d8f8b7424bb6c2da98eefcf90cf200a7c8b122e0240eb3f9d2e30a2add05a9b2d5862b1db3eee45f67de64ee9cc4038987b4b25a413c065988b7b7d" },
                { "gl", "b069896f4188fbb0b33f2daa1ca9de84cc32030766dc494369e77efd4c05aebbc2575e5f7a12d3231fc651ae337d99f8f9c9c48c61768c06ba09f139c3ca8ca8" },
                { "gn", "e84dbf49f49291390a4606b70b365cbe7b3b02ba9a32d69495f0a82e9bf6bb422b6e90d7e1164fa8ea85af533557b61daa901a2715c29e32c7e882ad9f95a720" },
                { "gu-IN", "5132d3fed3ec19d7cc1dbbdcfc326b6d7dff2d961574547190733a1fa2a6cd83ecf07a7c79f4f72433616355b036a9710282824908ec82b8fa74f2bb9142a99f" },
                { "he", "12674081d2132a32e2a544f44f1b205f137baedb3867fdea7bada2f84c8f83155e73701fd0197621ed13adeeca3b6c4b0b4598bb458e72c99067cef16502bcb9" },
                { "hi-IN", "b520965cc34b3b811b54eef98269614bde7b7fecb2241e262ef9cd31eb433ad4e6c5babb32fe5c4f348da3e643f1fa9a0fddb155a7e8e5dd56ed41ca40676c62" },
                { "hr", "62dacd4d656fd25e900ab4d41ed9b478cc229daebf0089bba9c3b9a08851fb62b19727844815d46f23bd68e3e37c8625a8feb9a5a0437e3ae59ca5d59d072142" },
                { "hsb", "92bfd42cdef78e4a411cd5f3fd9c2d12eaf14f318bc15ed785b35d8c026c81f1c46f036d3fff922d2322853b4ac849830770e1d07e2c75cebce18812645397f0" },
                { "hu", "6f81d77290e22c5c1ebb6316f69d567be6d8a9f1e2adfae6110d286aaa68220089fab977d624582d432eaf20335ef7fa6aa0f31cfa423732e9b37754908564a7" },
                { "hy-AM", "a700f53c8e0a21d3f8fa43414a88fae2281234b7331b82bf01bf81e7fe254f012fa1857c155146f86b3a1cdb06f70795b8a293fa47f2a2549803783521946f9a" },
                { "ia", "4743efeb47a7f5a3be04e5bc4d9f901928557312ca0ce52c173d46f7e0f1adddb71273dc46095dc395e4b5f59f3266035fbc8614f6fce7787e005665f7a1eae4" },
                { "id", "7c92f0c246727ea734fa86046a5c5591e852945ec5d16e3b3f94f4c21beb3870e591e8d440861306df8a3891a18ca8ce8e42b97820b296ceb34b4ad66d7ceed3" },
                { "is", "40238521814df611c7151a934d2e12c54194bab48eb8fe4d991395d95c817ec2fb540b4d0f31a0ab08edfc3ba1d0930e10ffae8258c8feb89f5eb9389e661e94" },
                { "it", "dac51b454ee22720c174734600fac2f30a8bc29d9641830825582b4e24a5f6d820ebb84620b326711d9486bfed8533e733fbb9d6c130ce53b0b8ca1c09b4bbc0" },
                { "ja", "e510205ccba255b6920192d58087a165bc59b8643c958da354924effe2fddfbb0c584f94fc9e71bb9a070cb3afc0771a8636ccec9d838badc59cf26ffd3d4251" },
                { "ka", "0af1822afb326132b2c5deee57e8d82901c444e9741ceddcce83bbbdc70cc5916c5bb362fbb42c06275413f6bc04390e2845aec9fba262c6cbb737458a2aa0c4" },
                { "kab", "e7323cb25ecbb13c2dd25b9fd6b055e682e7346ac03544c7128dd9bc1181734bde340e0de74c9448d232e380a9efba9dafb1498763eb8dc1c5ec400270f40c27" },
                { "kk", "474eaa61e949da5840b7b88b4c868fcbbda3eb135c64328b7fd0209da0120f60f8e6aee6a82932c946d8bf9514a36bfca55d9d55bda203254aec0027f1ab6635" },
                { "km", "d356f3be89ee2f6814ac2eaf4f46bf20bdc497d00c190a82871e4a50652ce17c711f8818f266ed4a3ce8886dcaac4eb530773343a74656ac310422a53a806cbc" },
                { "kn", "b83d1f1ebefe8e74da08aaa58cfab8dd70158ab9185791891ad090b63ae82954ab7351e0ae1625775333568f6a765c61b2587a46f33e6598bfd59544e1de30e6" },
                { "ko", "bad3a2d46fd48270aa51122bfa43e71819c5e603c8c9018db737643990b579bd338d99e5578610f2366c8aec7686d4305982d8aaa00a2f0ff6c17601d0bc45af" },
                { "lij", "57d955d01e4403617046d2bdd53091db5cb455decf4b359a695ea41c879d39073fe0df5a755de790768a13c0a032d697e3a7cef701581e9b9f43e3b659cd317e" },
                { "lt", "991065e6b000ac14195279105b71efe3fec739920e455cdb7b3d0038ab3305482e81cdc770408e307655a819dc67c27b2bfc1929875cb0f73b9114077fe16102" },
                { "lv", "a62ff80a08d05dd7167a70d37a32b83bf35d36ea088c0fbd832798e7996a7f8416d366cf9cbf931ce8f9529bd91db62da92c21291abc8889e8a2282953ae4018" },
                { "mk", "315b4d810c18b408ac38888624f0bd25ef540e182ff29ce52ac87ef55c598262f8d0727716f0c9bd43a59d6d9b18a07b893a4dca57ebb6ef7736da0940eba479" },
                { "mr", "7de2298943f6aa52e4ce993d6d3356d7ba12c8f9cabf9297c8a3798757889e4e453cacc07208af127435b353ade902dabb504b25746f2f7ff2f8407f77f6f3cd" },
                { "ms", "470af5bf76ecfcee8940edbb34a0356c394b80ba4e9889054754679f1cb0333cce56c2178ab94f97ec89b7d58f98426a9b5c91826771c35e359463ca43b83fea" },
                { "my", "bb6959c6060326dac9e57d47b6c502f7849e80633713fc967f0ab3b5feded2ccbd3afa86cf5fc05d9f3a46527c5fcbe4b7c94b3f03c0d8f441dcb3d069342d12" },
                { "nb-NO", "aa3eb4f252217c3794b40b468abf809e320e5479e62290f92ebb4a15946480678e35bcaaef364bc89af87f9176fc85cbed89730f554a114427c918715f5d9ed6" },
                { "ne-NP", "d97e53608ab530a00c947ed0a815bfcbf8d605bf01b5decd4883a2c65179bc57a57f31471c595a286b3a32ff6277586ccc3f2aba1b50acffb32b35425f46e8f8" },
                { "nl", "a095f1bb61ab00765346892b7a4a686bc31c08fb7e4ad74344dde45d441e88f53c0249f3dfce64f98d28ed6a3e963e0d6be2954d2fbaf739bdcf6beb7dd1d3a5" },
                { "nn-NO", "a4c273753ae1b16306724b9fa3e28254a167a93057769bce86af447a49be6e450106759032c118a6ed60306fd1c2a19d644e0f127de64e8dbaa9ca1d355ce3c9" },
                { "oc", "41a23312f5399b9bbc0fa495115d8ad2dc3a7a8c6b10fe36b092d29bbc6c56c9c71c9ad71b2a02684805b8da9ab0f7baaf6f682d071cc9f3d30b07a2a5c38eb6" },
                { "pa-IN", "5dd6c0312a5dec9665f492d2ac15c9358553e1d885dd9c4854e36fb0d6b1d0c5b6dfea06c2ab8c97a2ca5a9d9c052cfc350cd1f46bc7ba66e566025b2e96e0f0" },
                { "pl", "41c47179f91d54368c0d51af2ae66fdb64e78d7d47ab7bbdfcc3dc1175000e2097cb7636e0d7efbd360347319eb50231bed21417bebd62eff252cc833132e9dc" },
                { "pt-BR", "a820cb3abf83626df8676dc2b162ff20730ae8ea559b216ef3aaf03f340b952c866e824fb9a21eedc198324a40c0b9f4fd922942fb34b2216a5baad5a4bfb6c2" },
                { "pt-PT", "c1ea3ba98483cb9b9a73b5713340c70b3a387ca235459827d501461e53a747d55873da6d7038ea41fbb14f5064ec7dbb2c2f364e5fb69ff344f50edd8f89b5b8" },
                { "rm", "488b16f80463a89ca92579a45bd6f448743d2c2eed89e3c930ffecb394c4062eb8debc100d6ac82c46633714f8797e5cbb4c5b711156f0a09b6d52d7ed6e50ae" },
                { "ro", "2dc87b78e480d723c3fd2af1c55cc4a6e566e0bc16ed71d6d953c5615e26f1792c11289407325a04c60f98f5d1ea5b530254a62033e6f45da42198241a1bb748" },
                { "ru", "ddd4ce743e9e79553e4475fdf25c379b77831bee33d313e5f158686dbf3a92f8e6b71557598db22abd360bcdcd9dae9f56f0cd20972cdd0eaa84d193bbec592e" },
                { "sat", "c83b431b07921af0bcd2204d4f91cccd79184d48aed9bb3030751e8c53288f7cd8cb97f17fb5dc249cc0e24d3620d29e640e958732e71ae381cd5213ffc0a236" },
                { "sc", "c46b34f5211dbe5d8cc778f0579b5d632d8464d8b9c61ff9e1fec1d06554bfe62277a56eedf164325bff46ebe8f356c32a3973b264416e9f01153380c996e4c2" },
                { "sco", "51379dc82ccec3518c34f72ee10a630ea8fc4cc7c5a13cf5fb1ca3e4942a5e0ae2b65df34c0d059634b9d0dcf1b0dc137fd3fcaade94a5b1feb343aabb72cfbc" },
                { "si", "49ba58e8a0dcbfd3b5e4bd305296919348ee5af874abab15bd7a47812100d34fb3339e9ebfaed139475280937d1258ebccb6b937f426c09a3e3eee2c3e7d322c" },
                { "sk", "81adcea0995ec393310c39b44330178ac631ccf28b7103a7bf7b3f97a1b8d952277e103a4acd7ecc3c5c48b63c9aa9f9a2c1c0ad06f582fd86146f45eb1d064c" },
                { "skr", "e14ac61cf26b2c29556defe2b89c62bfe30908b26a9d1ea938ecf60ff986dca5a001a288f82342c970ea1f3c70d94c46e1b47a7b6eaa64733a506bad04e95bb0" },
                { "sl", "e1104c89928ac7e7edfda6155cbbc36a0b2d458ffa6dde833b9e0c60c5fd37fe5a3ee8ebd6e9035d8fa596086f0602cb974509f68a2bed56e4220b73512d99c9" },
                { "son", "be95b78f00a05008e221057e3272bce5864df9778604a299f62cf4fafe2d56822f51e36f2ff5d5fc573abc774656106cfc744f9c3427c14eec2e1286fe52b053" },
                { "sq", "41a3814a2440d8b773688f68477d4e528c46a2847ce92a13691c9d6a81e36d74760df66ea24150dfe40c1a6b67dd9a4712574b945da1d529e2a087d2fc958664" },
                { "sr", "75b1c3542212c461736d2261a1f635dc5a8178acf14c1e8b7ed9037af437cd5ae3662a9d9e8d67a57c85358ec94296f96bb340bf174393ab870cdbe6d4158b2d" },
                { "sv-SE", "c5571005d174bd9af77521aeb1178158e48f53ce65faaf18fb750427bd2d446b1be03b13de8603e923d4adde35846c9c27f406f206989c780fef91fed2f71e19" },
                { "szl", "874fd087c9664773e14e53710442998e4424d48fa73c44ced150a9368c24186b1cce70e52dc58d2b8072658f1e4bd28ed588c871bf75f04915b665649f114d46" },
                { "ta", "785a78064cc40d53b1ba94f516ea5443ddb631421898d5a4e08957690d966e1c3c928613ddba6b4967e407bf4d2ec356aca9074785e18fce8f6703534d3f61f6" },
                { "te", "c06955e9229a5793f25c63d17d7a969ae092b5e0f0378c39f438d26212f50c31bcdcb9b7e6751fa1e476957d9fb0398248936f50c38209a951c83fcf92f53ae6" },
                { "tg", "3ac4210dd0d6589541dbcd387af8e7a0d8ec634b28cae9f4f0a1652a367e80eccd8ec503dc2409921fc540c1a0d20917b9e015b9edda6f89a1131ca5e64db664" },
                { "th", "824501245317664542abfbd4ff25de621437cd06d46b6fc4a6ad12316a14e52a53f58525472fab2211a4abb1172d41b8eaa01ff4c5c89911cdd588bbd2416bfa" },
                { "tl", "ee947956968830d25984bb1d3d52931630a4eb847ba17853f602c05760369a89de155a5a616191c6da38ac532e65dd34aa081bf9f638fa600f364f0884622716" },
                { "tr", "f66aec893c7e87d2b39d944cbecf4f3ce5b49c236cc73262bc0e0d937fc29cdb0738fe842d5ba8a14713184a077636f39a85fb83ab6739828412603bf05b7c8c" },
                { "trs", "67c9f95acb9f39c555fb7ab3c0bc093171043661f14294e2e9c280e7d6a0d3b94748b10d59f1d583c08c7d6116867bdbc2c1cd99815356f458efb824bd68c925" },
                { "uk", "72b37bb40f298b629f313bb8abe28a99a53f84eac39adc4e8718f5f7022b1edeec80c38c070d27228238ff1103b16c32bbf78e1a60a797fb419add70dedefa11" },
                { "ur", "480871b36d33a8139ebe1a9ef1e9dfbbc78f88bae99e309f2c1a5e53c9162d2fd5976293bc543dc90bd2f14b2f5de4cfbd1aff13fa856498e0521a423810f0ac" },
                { "uz", "a8bdb70387a42a7d8d4f1a9b05b0b30bcda8426b02c091eb8b6c31e77c9403103321b289f47f7bf9949fb761855a22f8dfd2685aa9a5f2f29d0055f60e4c49ff" },
                { "vi", "98c225102dc0e30ad27bb0f8a0d648ad4115811805dde8765c48eb314888504981258cc3e1958c4e12dc9e4badf5879d5430619f32d30519fc0f96404cf03741" },
                { "xh", "c2c3cfdd500e0b709004727bf4b7479ec56860cfdcf272fe654295020fe2cfbd3198051d1f21ee93fc39837a5ae56a7cda4c2f93dfec8a6894532ca226e964d5" },
                { "zh-CN", "e0941cfe309b3a87193d8b3690945b90451f5b16197a7a495809a955175a2d482981441a586380b066a959d3927244f95519a3cbb690bb61058a1ac0118b506c" },
                { "zh-TW", "743dd8f92b45f823b161b32a71fddf4e386a3636c13daa64bf51a4403814f68a7037117bbded4f0caa8ca91a68b21d591fce513bbafd3d894d80ea4cc0f3f99f" }
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
            const string knownVersion = "153.0.4";
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
