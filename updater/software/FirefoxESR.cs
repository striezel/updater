/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "62c78aa2127a7100ee2d33c8f61ff3fb4f1dba866a2064b58ea65fb577865e3b3bcd7c2590ca15f9db7ae5056b16b2efdd6f126fbcdbcbbae380e01617ff4f78" },
                { "af", "6c42247711d5b27cc20e1cdf359ab1f1d1a28d8d27277d970b538fbf7c7618b1de6b255dfb0c924966d1ded16bcbbb14e428be4e16ec191fd8e8d10d3c435e3a" },
                { "an", "d32ee0631ba9347711a60a71bda747e8c2e04f00986806b8413f90755b232155a7fd0c836e9d89b6f43bf22071675b1da9afd6b67c4f35de28f70c530350898e" },
                { "ar", "041316cacfcd3d1691e630ac278fd0cfc314246b04861e98de16af05b63ed901818a6d21644b3d189d1bb986d2208d006c6bf856162726e1f5ebfaf98f17724b" },
                { "ast", "c9a2201562fbecfadee7331bd7ba0a56dab7275c3e80797d9a3c432f7d444f68bbf343d436958486ba1fb89857a39194d66b905dc186bd3dd046183ebfa52675" },
                { "az", "ceee091d18092186c8faf2fefe2d17277eaf0224ebce3e3f0211fe20a139efdb0aee108b19c834265f9fecffd9d06b39eb25e328a7ae28171a58dd015c558851" },
                { "be", "2683f50f5fd47b9386359b5bb5f2171d023dcf9932becd696cceac90fa8560ee6740a1c7c2d139cb60f4773edfce61f1241de94ad47fe0874d9b831d2f898b80" },
                { "bg", "1bc1da4059313a253ff404d6f08e86488089291794c7f0b6bd1d43fdeccafe66cb4a42336258370639aefc2d6b3dd389528302b8e4d4880375a7baf4f7ecaf88" },
                { "bn", "b3092a8dab0333f4e93db46cc0050f963a213308ebe9eea6d52a9affb319ca72af68014d5ce8fdf1f1be9d179ce67285d304e7b3052dda90e3d195d78b294e6b" },
                { "br", "2d6e0407f660fe6fbcdb1b67946bbb3402375af5f5fc298b2cc11f734f004f6d084befb3126b4e8a4b5a133aa04e9c27097454a5ba76036b620944954ab9e3f2" },
                { "bs", "2b6ef4ca012403f7aefaaa014eecb179a92a5ffd736dd84ec17b1a4509177a4775fc140c6b29af083d4dce0ffee3a5ab62a0dbd743ecfb45eac8b07dbae2c50b" },
                { "ca", "713c9893407af802a6cfc25c74747f93995a2726232acf1d166ff518181a5c42680795caf4e2000f933157e939de7724bdc6ea003abf23719a5652ffbc681ae7" },
                { "cak", "41ddde28c6c0c13db82c2b9d8aa007b46611bf7f546e99c82ddd7d862d5e6a75b4f678d63ed3167b28924063edb44a3491b5602a806cea4a451468ee19eb1436" },
                { "cs", "e67430125da577062cfc40ae0536dc876b2fc57c767304c3b5920ffeba1f23549fd9734be8d5d63f4004807e488f2fc3c2e2eb0e2acb647b82c47bae32f97a50" },
                { "cy", "7688eb7def876c16471abdbfbf3697770ad40de7d161d14186704981805ce6c6dafdf2199d53bea3cce11881e8757674b25464453d48a3e72fa13c8ba47d25d9" },
                { "da", "c75f7d111322b8bae26180d9d4e39918f222c27dec423060a05cc1d4d606a4e145965cc4e94c0e247b308b05d4b467bdc4a9fe22277999567cc8d5fc1910bf8f" },
                { "de", "da68b1ca60bda3c5cdeeb635661d85a777c172bb2bfb477f8e5ab0b52b9a01c6c6accd21f8e3605f74486a92ec4af64bede54f7a009a44bb4d0d4cfb87b0fdbd" },
                { "dsb", "060a9608a9b65f0e2eac558ab705be3bbcce0d93d3fb4eac1c0a833696ed9eab13e8f20bbe342b9fdac8cab623b288e90e2d9fdf51e7873101562f99349e86ee" },
                { "el", "4817b661b7a0e8ec5ce4a6c854278158a8ef3dfa4343f5fe2e321f5bb1ee645eb5d463e5d68ccf6ce3124419fe8fdc00e796c5a17f81f9bfc902e57517d07a94" },
                { "en-CA", "4946f6aaa98dbd273c889ad4672c77ede332a06e777e0381454fa9027ef7abc8e8b86c3301d843f4eb3a9b855a13829d3f8646e15b99facdae8ae5f02b9ed25a" },
                { "en-GB", "6bbf082ea45b6aaba51b1b3ae45dbcbfd533574a5d6712c9b9f27214e2a61c455cee6746d792ee8476f5aa6254b11c30a5cc4bf343c90adfa9849b3a2560630e" },
                { "en-US", "ae2fff6f9ac7408f8000132bd79ead5d948b33d121f389cd6555bb31c415270f1dee376c38eef6089bb0df9c9977ce77c0c1cd0058508b23bcaa240849997c4c" },
                { "eo", "b1dc57398481d5f8d746d8cfa53b09567f378ac39d7cabbc1653399a5efd10e6adc61d31ed78f8959eccbba124c2a45b67523d3d26dc7be8164f6f0a02638fb9" },
                { "es-AR", "bab0c10e17573162eb918f86dcdc1ff2d79d5a31d242aaea4acb204422135bfe09a70fd57bd9c59001cdc96b187a48dac35469374ab7fdaad7fbd754d3587eac" },
                { "es-CL", "f969bb85514c47b52a8f29c7cc470eb5c0178823a7db2768f03578f87341c54bae7ce8f53496b6f254f5893b46d5dc6c5ed3bcdd32cc70da524f817e596c411c" },
                { "es-ES", "93ce972505b7b6c55389e99be4a7cb4e0df28cf66a89762869a91f97ba666c86b816486a3edac604f9e4ff9c0f640196474a298e55e6370996c172adbd182f15" },
                { "es-MX", "56f5820e7cc15d42dcda3ea7bdcab85c6a7d0eb47320b198501fbacdd86933994164719ac26ce7ec92afc0dee03f6b9a9ab1c030b157620a03a42b05aa39cd71" },
                { "et", "41ec06922f8c5dd32f0f637373769af4fc53f618ba263a39a785528c3aca8cbad6c88d0e2b926251b043417fff59caa0194e03d8ba9a9bfe4b5931cff38bce0e" },
                { "eu", "5513619ac7a9a389b1b477c212f4736ff8db7620ad8f2c56e77769ff4b42a07c6471bfa0e90f133ebb002b6588f352c3a5b86a771567ab081da4d58f169b4d57" },
                { "fa", "a1eb4968e2594c3cc1e67a213a5fa2f12924b661674115afb0375d5515d66d06defd2fb7b4c41bde1dcb52f2867edb9c0b46801549a80cb509a0fc0dc52ebd97" },
                { "ff", "1b317e7b844c37358b3fd0ad12e636d3fb4dc08bc75c7b589d50adcf45fd2b2425a27c81c008a420e584dc3033d33ab581e32fa235bf424cfb2a77aff3caac87" },
                { "fi", "5fcd98a912fbd54f8d299689c436fa8a3befc8e8781b3ae30f1077381fa8b205189884c41334171749f0dbfb005465d678050e91737ce8f4b3c4da626aa55214" },
                { "fr", "3e81735f7e4b3f9986ab8760aed4de5c4bb734e545f478f07f4714c314109f2c7f6f7f580042c93958f94dd37dfa17b43ded035bb87b509189aaed3324b00edc" },
                { "fy-NL", "bf7ddcacdbdc4e6793c8d16f4ab0c8b372b9af3c5cfea410c0e7ac7d59d62b858c2247ba1ea8b45c156d18312b36a6db85b82c0d9effc7359d29dce91d8b0616" },
                { "ga-IE", "fddc9ffed20e1beab9f44eb4e7865325a7699cfa4c838cd8411af890f6443fb09c49e97710575200dc4b646bd28e0e24f942287fce83dc7c1a495905ed620795" },
                { "gd", "5e3d2945ffc002bb9d12d307184a365efa0de2aef75cefc58dbc3685ac9a54289c26e9d059b525af041f391e1345314bfdc50601646d4cf29c054caa16d39e27" },
                { "gl", "1c6316e4b7e8a637f1bd97e3c6d3ede6177c6c58c30716c41b4b2bd9faa84322f04688a8aa8df66829d4b313c105297267d479f02500e476174ca63a6e1ca4a8" },
                { "gn", "d5caf564601da345fc3e60454d4bd85c24e7f385bf522b2550325561da9e9f4d12adab612246332670fa7420028902eeac0e3a1ef0a4fc4f0f095e965c75c6ae" },
                { "gu-IN", "621e729779d557666e5819be69792a3718607d672603decd71b61ecdca987cff0978cf4501968b81c17d04dc5fb036f81ad6b4a52878f0898bbc7485c265ec16" },
                { "he", "bfb844ef85367fb47f57376efe2b313a3b6cc46c048b13dc135ca71dfc5b713061772112e290b4cda56cf4cab0198d0f37967015dae00c7c835d065a7faaea1d" },
                { "hi-IN", "0c6b3947bbee012795ab987bb1ec75f95a5bddb0edb2742ae81741ec64ef2d1439f1335a6235a34577d39ab8e5c18dea97679899e8d72e70f6465100e462a3ea" },
                { "hr", "149a2939b997ad74b25fdbc1515d37f7eaa14d777e354e9bc14adb66fa77957c95717dbdc386307e99a702c8982500082ce4d85d12cacd535e820885dda924ce" },
                { "hsb", "06bd983d652070bb8ae6b69d56fefabd7257ba5e9fcfc97470d371cd69d2594b4e9305eda6748359550f201d75c02edee024e6a674d9e47d176fa8d60016c5c3" },
                { "hu", "aaee49fd3e25c09ec884fcb05d3274ad2d355cd1f14e8738ea572b25ba531105d7a18c42f9f2cc6fc17f30552d23eec63140b8598256a84c7edf1821c2dbe6d2" },
                { "hy-AM", "465f4344f07b1d029700fa9368360c084d93b2c7646eb788a6b903ade33ece809a3e3b58d0af3d359884950893019a5763ecbf43b659cd421c3fb53f425ff95b" },
                { "ia", "24a60af0f8eeebf5550803f8603fcd0b5f53ffa601cd265a7e3c6568042a8a65fcdcc2f3196829caf3702c5b2129b58505faf7abca0150bfa7a924d829a33b8b" },
                { "id", "bf746b42416593fea11856a81bde5b9be7352dc0dc8874069bc6ae6ebef83fc05261f51bc396fe5892b8c125db41b9e502e1cad97064ac83320182b851375c15" },
                { "is", "a51d53f013eabc954e063757de1a47c62ab4258d9eaf07483dd35cdb93e1fc0063506a4c4aef108e9f79541c28c513f27531dbd380f1292878fdf9b23dd09347" },
                { "it", "d1ceb6859d7e19ec623a8cd3679a5dce380d99fb41edd7542d69d539c725125e1c048a46cbd7ae94fb4557a54c7529bbadddd61a453a03af7e425b8521097cb3" },
                { "ja", "3ec0a8931846320421c59e4e309b30fddced9f1c0834593557884b847a4e6c9485b84332545c354d4f3919b7dd465c79b9e306f66b095c2b044016ade9f15f44" },
                { "ka", "f681c0ea6e7748c30e30cc3c9251dda6e701ff3f8e3b6ca58cf04a8e59b6a2aa4f47d1055aa0261289e8d23bcdd85b921bb84f09af4b1adc3bec5f7238451b8e" },
                { "kab", "fac28e9f1ab11442c5f8581fc42f3ae8d8e7a263028273b9c63f9e2724c5bea0f1623729701abc2851a733cd6fa4709ba6ff1167a17fcff0c334426a30fe602e" },
                { "kk", "64ad2768f5ace0e2cbfa920a3cb778f05ac1181be9f5f58ac7207cb187cc9902a0345dff4c8bdc6cf0afb19f1716cbe2068f1bd1ad4f844ef102515666012820" },
                { "km", "a90f41d5d848f987c99f0281b213114ffd65ca2e33570b7643d3154cc8c6da5adb6bb330c662ad331a8e7f8c9443f49966499a9223d3306c82247115cba13197" },
                { "kn", "9f9c8f19c3a55e44807ed6f6307005ef1e5948aa21f7d2c6fc030a506619d43a44ece9ef13ab6d10873e4e63bf85c2f2db2a628c34d2ea2d349a561efe0f217f" },
                { "ko", "59050b4a4e77a9f94f6d02f5b5891835ee3e6b1134e0c517adb8b3ca6f7bc74f84805d1c6c7ad3b14de970ecee72f1dce7ec2be9b6ddc306546abd6fed7c59fe" },
                { "lij", "9aa8aa045c6bb658e90688b671ebb3216eb011b76ce9e3d60df7b18ead24fcc921c7ec73a914cff17b176ea7bd7013f2eee644c9893e645df141b9e0db6f3284" },
                { "lt", "acce077a2cb148e1d1953d2e39ad12b6cc9a814000f5f8dfa7853366a21a74056b81e8836c023c89fb996bfa02addfa69a9345dbf5a0aec50bf9964fa18ba38e" },
                { "lv", "bb8cb98377c17d339c7507b0b0382159235ff13178914970a92ca04d2529c0f8b1e3ed510d43594868cc7b53a27a6db682aaafffc177df721476606eb382066f" },
                { "mk", "28bde37fd197da2beedda480b7d731459c13dac90e04a469a250418ad3bdc833269d7604d93c7a0a8c0da1e297e3a1165ea4a476a5984f62a93ce44c906b0178" },
                { "mr", "457529e2e497b79662bbc7ad31951e9b958139bf956a19920a93cf3968a76ce623f088ac211598d5066ab9eda1ed5bebd9491716994981dac683c5955fad5967" },
                { "ms", "f22c6df0f7148ef0d03ac3c997699f560a58dd2b2f30cc7a757dcbdad992d60d97bd034c8252a0c074a544c25ca2b2e05947f6b207a892702fa2b2d9111d8a89" },
                { "my", "b8256188cda7a4bd6a5b622ac7de2d70e281e5cd79e884a0afdcc7200ffd24807d9c698dfa39ccfbc15db971c6d0e5e8c266ad7df8f89b454996f285b526eb1a" },
                { "nb-NO", "f316bfa570a0d9b96e3526dbf3fb04f1da93b28ddccf85e04d99093b6d9ef5002f6c34bd9f36e389faefd89bea4122baff3a39766e775b0dcd35ad2db8551687" },
                { "ne-NP", "78dc6c25f75efca9d81fd888f8fc129bc5a0aa3fe77300e8e8aff748f6712a3beece7cf6107ec04d9189bbba3539a9358330159924e55056c1dadf083ac98ed0" },
                { "nl", "3b8178085af5104af817e461710751c7f29e24a5b1fc391fae9a9beb2886b0a828be4df8ea0f3aaacaaa0117474ed3e17f41b59642c6510a40bb1e64b4ca72fe" },
                { "nn-NO", "5cbe46b2fc22828f1b3030d0ff851c51f93fcc25eabf0cfd35aae69b8f68b2e8682436fd0972f6931229a00cb602061b0c776cf22285ef9313daf2b77212a24f" },
                { "oc", "1f3b8a8ff4a22f14b45424f2d788dbb13c1f798bc99043a219465aa2d576ddbea8a4730166ff2ba89ddadf19758d23baf71a0c7e99921b1e608e623796ae0b20" },
                { "pa-IN", "533e1e6363ddb8d6e537340e38aac60c461b04ef03c58c555565f9149ad7d2c3d9e65108ccb9256b893c8a17e9ff30698e595b72b4e47e86fb1f84f60e2685e4" },
                { "pl", "2392914b3f2d78a0968f69ce280cfabe7c768bc498ee8ce0ceeb956212daccaacc8dba2650c6d33cb2fca90c813ff42c34b8458d28a2aaa0bc704cc374cb985f" },
                { "pt-BR", "0439fba3f9461b2184558ba52c102eb591501a97ed5160a66994b88e4d8dae029a2b911a0527cc104e19ee462865a6d47f847e9fad782d5dfeeaf1779fcb2c96" },
                { "pt-PT", "ccba64034388e5c55a4e63d91da787ccdd9a7b343d14df98c50ac73415d1f5c9cb04588ec5331ba3cff57dab8b554ac08800f81f8362a2ddccee02773708750c" },
                { "rm", "34e61b039668ee7f5911a675b12a06bb9212bffab13a9937528959fe43a13ac3c61db767698e9e987b01dafe211cbac30a76842e66eb40631e383fcd66ce8781" },
                { "ro", "70e4bbdd49ca79dd34568884eb60b0b347b25c620d844c2fe72166c96787b425bbcca547dcd2f659707986384224ac58e625cc1f68f3e5d6f58ac2c4f2ed0c24" },
                { "ru", "03e79659cc6787c83f28b7fb334d2eb13d9c3baa25433065103ccc422b08899d6ce6dad5b5175189490e16135ddb0082a9205c2bdb549c237c307584f98966a9" },
                { "si", "259b032db2f8440d2d229a9be99b9396b6052d20a950d33d1e21b3a9fb1729e48c6b68baab326f25144e8f40f3a932b7cad61c3d94d16042e4e7ecc914d73355" },
                { "sk", "960bb0f50bf795cde8b93e6ad388d5da2442aa63741f4f3a306b9c431691ffe4461a72cffe5b29b2638540faff79eb8660942e53bbda16a1e8e5852067877dad" },
                { "sl", "a6929f67380efd540fca5906f949dffd0bf13d8331398f3a27a5a65bc0d4842732571c483879829bbb3cd6ab2efac73b0a2d999743e4df638e7129f88b5bb822" },
                { "son", "c60106974a63e1ae3cfda973edf12fe942b578c28530a11f6d625981e6f1d0dfafddc150cf6a537b9528c4b5cb86b2118995b1d77572cbaf0cfd3d51c531a710" },
                { "sq", "b7042ba5d798fdc1ceebd48ccfefbc00ed0afb8135e679fb65d70ea75008bb490397f34e5c1d9130230a0d99592cf04441160cc3e3f77034afa40769e4be6c53" },
                { "sr", "6c891733a03f2a6d80dfff7cbc26cd17fc051b06b3db77236d93f496130333ea3a5362405267610cdc6fbcbc8488fd992311599954ba3791010c91af4622981d" },
                { "sv-SE", "c0422e243040804f2b1b6b0c670a78a964f438e1cdb52d399923ec8508ad104cd2af0077bf17484c6a8523f479d6ea25380ad8924a61c0930b19e1e0dd43f47e" },
                { "ta", "8f7117134e94040737cb5e8bce31a5feb4812d7f2dceea0c3d8f7465da06847f035fb88da84a3ef6f41cbe4cf1c88b7928f8e3002fdcff2faddd8ea6dc9d7925" },
                { "te", "f1a1a99c7085a4c5fb8c47200e9aa53a51e436cff7eea8b06edd807eedde04cc6bcae2ea25b6b443f7d4593a0f13b7fc90f407330a7f1b3e06519cb99cd1d200" },
                { "th", "fe9fa61d5c44547e9bb817d149058c88c7f63eb8d9c1e7c5ffccf9705649021ff2689c3a1154ca5d3ffba8c233bcbd95b32f7715c2128189bc3f9a160ac3e8e9" },
                { "tl", "11754a81bbd0078f04a5251be5b919b787c76207b6ec2fe21583477915c5faa284aaa563ef9e95eaee9b7298078928f43ccf5caee80ea8e1225b5a70760d119c" },
                { "tr", "96105a6f33359440965ee76af152746f483f71a0ec77c76f01145df68f02e5cc2e41f0d5683571457d5dc9b9504e8587c00ff10102fa8277f184f98b1634a7ad" },
                { "trs", "385631e07c9f4d5099f47f93dab80012ae6ba2daf2b5f380d4e9043fcb49b8ad31057870f18257b499da011d5d577f4ce7e72fbb13737e5333b2e24634a8650d" },
                { "uk", "e1302f83678e7fe154bfe5e1a45f49d80c28c3260c20bd402025b3b93213a91a7362fca8189dea5bac4c53317d8235a93afb05ec7abe047dc5afcf7379b12f31" },
                { "ur", "de96ce2788229c1d96fffb76d81e97a7717c8ef3722c18b1af28b5edff5596b76aa7769a7cfe11a689c0aa28a7382d069b1e5a01ca6d31c64587287a456c7a69" },
                { "uz", "94ad9631d65bb4611f913661b209ca7cb1a807a3dd510f83ce7e22cfdf60248c9817683b0fe7f2719d30923034b420a854947460d8e724dc00e0cb3f0c3349fb" },
                { "vi", "4a05d0b1b5db01d0dc089b9ac0dd79a24ccce9db7243a5f8139146723d7ff68b29f5a048b243430ddaac2e556a81c6d34d99c7e38a3a44c5b763b43f3b509427" },
                { "xh", "21ee85d8be7b99d5ad4916749a52f5d7d077866f73355b1a4dba57c14b0750cb0fb46872ab5924c8d254a9cfb3384b1e468f0ea0f3e09cc49fbd15f31e43375f" },
                { "zh-CN", "d04788b5a56bb6e635aed127d6759f5b5ce5a9f1d79308c9aa1589b8f915c3240c8e883a4b29edd0a366e2a059f9127ce2f42794353a73c4ec172b5123b4cf5f" },
                { "zh-TW", "08678b1eecc99c8d9290fa440371119ab486833043b403643f071fe867e123550e7096d07dad0cc868ee88fe750e083378ffe4952c9c0e5fde6a6cd3b4af9302" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/78.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(95)
            {
                { "ach", "f216e7e910f4501ec386279e1271a43aa5cd7439ef9c12b99e9bb907b20e53f63561b0ba31f7441ea756a62eaa2c39d4475dc79f95559c49de464e2b452aa0a6" },
                { "af", "4b94fb97d2eff2716169cee03ed002d56a2d6d9f76883407bf32d884c2ce1d2c42eedc9b969e6ab086956470012d96f43dabc7978bd64c662aea985e21f51c24" },
                { "an", "66370b43824de109b503a8969f8f80f4da0b1cd0b86158161df7e92feb9893f17af06761ed3bc2b96e0b181ccab9b0f1b786d3ee07ff9d4b244d36a402c88601" },
                { "ar", "0596f6b8a16c8617c8fcf31a3a72d4502f2066f9e192d3a4cba2f5af9be0e3daf8c4d052a6b048cf9060f2a1b0a11d3f9eb1372f79af7e2c111971187793ca92" },
                { "ast", "516c624419af5232dc32af3d6bf78e1a40b60ebd9307d0d7bd17850f2537fa46113ae3e849ad98503dc4341bf7195184c9ec23a1412f7edfc8065b69ad740f87" },
                { "az", "0d8ff8c1a07b46e79004c5373a9b739f9ad8c2ecbc0b7e0b3be6cbe29fc020c22b01cb1a173c95cb5076e141380c60dd27ac145fdfb7cc77f518cceabe9b5e7e" },
                { "be", "ffcdd337b213d0e0d9713574d98d0281692a6d1f0ff16104857818fe93d2cdd36b5fa79630c2f0db5b5b32a1cbfb5c4593a94030392052b4487524204f69c4c8" },
                { "bg", "fb79ca1fad41ac43b3841ec1e10a38cd7903f64f938ff66fc534689d82b858808fc496e4afc516d97f5addf87d689a28af40bdf7c002ef896571d635ad689a74" },
                { "bn", "c381f01d44e3f1f479f7774e20146ff7fcf9c7390a8ca213b8cc046bb55dac99b0e256dc8ecf3dedcd39bb0c41608fb31d0732a9517d19feebc1fee1eb8ace9e" },
                { "br", "89becf99c44867536ef9ee76ecd1b09af90650e6cc8ee7397c348199ee2b52b19ccae4709af3f39432bcc0f399eb191e1e974e5464d6e6e52bb59eaa94ae9ede" },
                { "bs", "87a2eaf5c30927c3e9aad2d9a4658f9e2941188e56df68637f22954ca17c863431644edb2a6cc76b604ac178796bbf90835bb9bf8b46affa015fd57867b0389b" },
                { "ca", "4403342c9e62140fc2c00a487338dc25068e073f8212c5bfe2f84bdd4be60dbcab24a1beb1b3a0ed507685e1893f0e0217f42790f4e71b9f1f3f6573adca74c2" },
                { "cak", "bf1eea4497dc39acdf1684c7e5f976b7e845ed7150121c28ee0b040ab85033ce10531652517497fddd991378d820fb99d84b7129e0d86d24d03ea9fa4899f86c" },
                { "cs", "16adc4f8d8be8d54037c3984becbe5a040a58af84a0fb8ee5aa8b3de15dd488f74ebda4e10cb1c04d73022325770f702dcd5ac4372f50afa64350fad4884eb4f" },
                { "cy", "9902e1b735c93da0940d7b2b48238da48005a5c8d2dd2e0e2285ce39df450382e05f33c4d08f132905c6959f444a96b3584b1bc990f3cfbf1d21e081420b98dc" },
                { "da", "0d634cbe90a3b849da9145f9aaea3dcf54500a601cb489d9216ada41c82086da10432f5fae18b6d7354c665de1a459d6f8e985dd201581db81d268188003ae59" },
                { "de", "8c0858417bb3be83ff2df9e9b67bcd9bc59b3d2ad9683185ea29793a2508fcf9750dbe1b2f62a3050cef2222bd8ee95c7f92b7d94f1d9ce183e9d62ac58337e1" },
                { "dsb", "6068fedf2064fc878a6629d67fc295e6a158c74f77a864c5d66cdbf3f4fc1beac636cef9621e679ceffe8110e130662790d2c8a4b8a7fd018ddc40130869f21b" },
                { "el", "5205f85ee3b1234164986836e80c714013cd87299f425cc04d12114ddc676c82579db61aad859650602262c606035c7413c1feb83505197e89d48fa69e5b4976" },
                { "en-CA", "23559fd2f69bb198310b4ec4763f462b7f810a84c5c3aa9d5e8c97371e4e08016fca60b07f48ccd5d1e235bace2aba046361144c0c42900f818a4264675182e2" },
                { "en-GB", "7a754bd920c21246a65becd21eb407d2a5646ef674e24f0a24586959ed9243a2ec5c0d56f53a96d1160c15f84ca7deb97a005263663f79837ae57e6951a958d0" },
                { "en-US", "dba5c97be6ce8c8372798c4e8401dccab445150a490220eaaaa0990dfc106f5b0f6a12012298f704e5ca347cf8ade3bb806636289060e78fcfad9950232be2e3" },
                { "eo", "36b3e580b0f24716c75d7c5d1d70e214f95bb262fc37d0fda8be2e44f9b0a4441acb3fc0428f6769787db186b6c42e010465a04f720d7a4c4fd3c203f1efddff" },
                { "es-AR", "54ed1c1c034c0c2abe9577027bbce683cf39e083198832148c11ec74f4be129e7f17515105aa985678fecb0b53020854539f5612b1431eb457e64ee58d32fce7" },
                { "es-CL", "235f32a64731735c9bb72a1a540b3c47c9b174a0fdedc164940656c06fbf501735aa3a151cc399837f56903f06a1809f4cc67ce7dbd830833f0fb39499c6fb68" },
                { "es-ES", "d17497feb415ad353dc3913969c914be1d3e930f9189c642d66bf080f2daabfbf8e550a1b80ba2f02b6c9b5070ef929f419b776837d11eb1be38ee68aed74938" },
                { "es-MX", "d536e57761c4dc116e7ea6c1f37628b097405732b5b34ea0341499d0c05d146c24c2163bfe36bf8bb90da83f4009704b0ded2401ffee3861b6b6bf41be0c8103" },
                { "et", "625bfa092a3d37ced2725d626c12d9309b15af0b56b6cddb6cf18e657629aeda0e594957e011cc26b8b24c67d83c1fd81e046a0070ff2b986ec0c1cd7e5fec94" },
                { "eu", "1347589fbe53f23b84e6dccc3636cbcbc88b8d6bb01a480da83dbf738b89385815ccf4122f7acf7c79368301bc241f1f9413a8d19b1aa3a816c0f946abf9d583" },
                { "fa", "741522574baa2a9b1212e15a35c6a1a269488e9837624269922650c24419975735b2393d99a672746826aee07dabb6bc5dacd191e04a9354d23bd858e83514ad" },
                { "ff", "959b0bd7f1fb080c33fea4da39264fd0cb64c2daa93013413f2e05d828279cfd5232b4886d56d8c0faf50a55e575f26db573fdf32fe1ff72a99ada1d429f0b64" },
                { "fi", "1d1286f6b60cd9b800aa180163e62fd2bec5a4043cbd8193c0d78399f9892225c177b0611f974eba263afcb91a59240f87afb1fdddbdeec3d6caf73fd8b34a78" },
                { "fr", "6dc3678a28592db062e34247471fed31e28a72c3668313997d6aa9958f5e33b9f4621617336a2d98ec17146007dc170b5e9c777fb31b8c63abc8bb1e5c51be95" },
                { "fy-NL", "e6bbf6b7c9c42453b1aaaf38fbf5703dd3c9dc50f104d018d789bc551dcb60a4a7daf4aca6b1a5e45ea57e1f2c4c31c5f19712ed1d3d0c68847b7ba86458ebd6" },
                { "ga-IE", "58f080db6246c44e07a2c351cdbfc226662320fee70ac4cf1525ca31e276938eaf19fcfa3aec836fd3e29f88fcf803dc5a465937d125c1d9bf69d50fa092c28d" },
                { "gd", "202f99231053705aea7bdb43f23a6cffddf258050200cefac9aacb22703f424971bf845b81334a91980c59753357c1f1225077822bff3767b0243bc59387b103" },
                { "gl", "8d8ebce500732937f5f1434e9eb367438c5b3a8005398ce2442b800f333117370b27e4639bbb730a4f6afde619a2368755b70866032ea85532f7cea28136c783" },
                { "gn", "4da3e76ffee4316c0f5a40d1771d458bd0bfcf54a36d763c2487eeb0d1d8f50c6e8f2241de6656711ce59f177d19c74c01ffc08c27de2f8e6c9ab039813119be" },
                { "gu-IN", "25020bb8e9da08fac5409dccff7a4ebea418365f6f05b5b7f6e7edbe8b9251e72150ea69378f9ba10a35aca08a6e9f0b568a8632edc57f7a82a29e94cdab111c" },
                { "he", "f9b5d3a11c4953d98f785da9f386b79854b065711d08b0170419bb01db781cb0df9ce75c06421255bb25c28551d4970d038aec0dddf1cdf3a0d64e1b0b7e5d09" },
                { "hi-IN", "1246d692e6db7c0242c5a1bad4aed93e5a84703ecca0235c0d5b7f58c5cc7bc8457ce756079d4350fc8bc8fb1dc4a7c5caf887985405398dc830f49edd7b6456" },
                { "hr", "7b422a3c54a9eb837fe4a1d1b89d347f01f579b193a7b27024cb6dd09fcfcb179d12336d0ec2154d93d3db6307e1c6fff5e50b973dea8312f821ecb37165723c" },
                { "hsb", "08af4874f6f89aae69615453b5ba246652c50ce70c6c3f2f67f9796e5546aa12ad15c5aaea9938c83eb2eff5d074ffc4339e1df6d40a990c1abb63a675bd838b" },
                { "hu", "dea10c735d90e419eb3bd5a760cf472c591c66d7a320f2fa2c9497c01297714cf327908c32926545059b6a8a2e6d59b70286399e87d2516cd9a915838639e78d" },
                { "hy-AM", "4cb273f99ab40ea08b87dea48b9df31ac635c1d55d272c00925bd2562d1e908840afdaf4bcfd234238a6f35c99a3d57201f950ed958aa396728bf956fe53cca2" },
                { "ia", "05e86a6e67bade0ec2551bedc5b2a6617ce7643f86d7f7fb4020d67a5859782bb8d2744551bd59f7095323694601e011817a8097c061ae43b2f305c6d983c995" },
                { "id", "c08d307e92c774c12fcc2ddbd89ac480841ea52b05eaa54c0544a2d86efbf2a05563059740cb4d66858b2a137b6e24684c862c943c0c127d47ddf9107db8c408" },
                { "is", "180e2d39574b068e65cbea609aedde98583d98585ec4fe9ecf477e7139bb1926c8c36469f453691b056d3dd1455d16d78dabdb54320ff88aff3fa43aae9419f6" },
                { "it", "17756249d73a0f5752fe40efa3dab0af01458d05be1146b1158bd9e41f9e7ec5081db780209d32b158bf740f4027a133b776d3db2b8ae3798b41a4d27efaaf4d" },
                { "ja", "9ca865321fdd83bf2472e075ce2a8d43ef511fdfd5257dcc2ce4231a4730eedd226bb08a0cf36169d75d0535fbdc2a05e254129a7036737a8f09b9825a488428" },
                { "ka", "809061d936e267efae3c213a4cd3a831498609e79ba9279340884ee32efa1b8e9146a45c821144ca430956e4aa2a65e1209ce662beb2760b1d522b4927b883fe" },
                { "kab", "22806be3fa6f904ced05756176e2abd7fe66deba34effba4e838ff9a099c3bb5c0309df16dd6a962571974e04b13952e2b3ba25f65b1c39faeb7346e4b74df2a" },
                { "kk", "7c0311aa231ba0e34f4e4c3795e37c490f74ea66fcad82ea3c2abda62cfcbeb5ec1a889b629f28224b76b3b376cc0e2b143088dcce75181120bf25a9abaf1edb" },
                { "km", "5cdf48f46d76f89177e1d003634c98f665ffcaec44eeede3b78e2f709d373152eaf0d6ba924188543ab65bab57b888f7cbbe930c450146ce8859327f1b0f03c3" },
                { "kn", "fb5a1f0145a9b423d86bff74b2bb8cd6bb0d13ff33a650c666c7926ec62b6145496d734ac5dc7ab63268a8b2501ffa44eb3d69e98806be06dd4269a5c66c3303" },
                { "ko", "7bf5071f45ce78de5cfcffec2455d299d57f51365d5b9658435899e4fbd00d99ad8494da1788b56b2a16874a33f7c168c67f57553a9443ca9f1b61b53a2808f2" },
                { "lij", "6d929cff4313d8f5cd069b8ced9a35bfdebe075d77fc6ef1704e8e564d0d3ca260462b885f7a1812466a720e8e0b753d51b4c7a665e78a4b2687f1b8a6857302" },
                { "lt", "383908551dd748542d2734e724a63207078b293959d4842cc00602772601d3b2e91077d767b175283bc29341bd03478a84640a656bbeded29a0c41b23de04ecc" },
                { "lv", "ebf1bce402f1d5e1c6b4f265514bbb1db8b3afcb2abe230f221dae738ab98b6a4b36cf2e7bb512d3a1866c16c47d2f51d3e4c038e490b7a69007a8026bc844b3" },
                { "mk", "5d38ed1c2ef42b280681704bbec715cb93da63ea38458ade3969a8d650634c13d07119611677db4d53faf41ffc92de3b32952920360041b4fa07ba93c2fe9ce1" },
                { "mr", "5485edd42a1cfb7d107e17a7b9d6b92ef8ea801a0ab96463b90221e24b8cbf0d615c0877bca5e5aa9cc28037a63519ae2815eab5c3f4f721d53c30289b0a8fb2" },
                { "ms", "ed131d7c445114489907f207e29fde1abd9a9413d752f6cb0bc8654d2c258a32e2a6f427b4a9f91f589ab4c2a838538a6694054657949ecf1475f447b444d837" },
                { "my", "db0598fb7238594d41e932fe500d0a8a5c3fba2c188ef1b56be568a30ebfa66385587dd6a0fae7745caa804ece624bb7c0f583b1def6e7003630f821b61c54bd" },
                { "nb-NO", "89d9e761ee4def817e5664a6c77bd68c46ccadef3ca2c1e5d1a3302db33f28d2e246d4721a6e641d5ba7ca7cfdc02f5bb473391f67cea1d598343a37cd9ab0bd" },
                { "ne-NP", "a0bf6e83cf891dae37c96e88268acf476efea5b4d5d3b6e41af74ece2e69af9f9166052558e859e2cb3214764be12a372b9ad3f35228adb00c74af11c845b8c0" },
                { "nl", "ebb795eaf82843def85d2c2ebc85e353abe5593b2fb1fbfa5af51c7571beb1496715c24067966a4de7fbf158b538adb7e87d844ef2cd5a1eba1aa6b21015c7ad" },
                { "nn-NO", "ddc173088fddb86a06813f8d31104aed57a65c30426b951d462433d252c6398af2505045641dba7516319edcdc48169fea2dd72754b87f7be3575c36079361c2" },
                { "oc", "a2632f7e3a3835bc4b16281706f5c73ba3133dda59998e02f29efe92e5ef6cddfd0aa3544e3f41297d30de8604521e4817f556d5428672e0beb66f3ac4143fa8" },
                { "pa-IN", "5edd725f02f18a5d6b0d00fd599c80c0799921b4bdf2883e730c7d83c7875f7dd7834486cdd1d40e02fc1357ce971c222b21f4f7173b3660488f1bde8ea0b37f" },
                { "pl", "11864d4ab7d591f1111368e0b9aef9824b98a9fe4f47a5f6e6b59e9903138f9961db3ded3b84f1617dbe352a1d4a5c3cc2d0eddbdf240fc556fed3e1b6cef40b" },
                { "pt-BR", "a787a7d8ee338be5faa7c2a6f66060494998b4628d6156abce57fc4b2560e565ef8533e406c8c1eea1b9faa44bbe6ab0f6861c26ab92bb1c2c916268a2445a74" },
                { "pt-PT", "81dfe6c8876e6ac71633afc189d8de95391c4dec395bc2820730a27c8a1472390ed7c3236b075a721d04fd6ad13e2aa5316e21054413f046502ed58f376ee34f" },
                { "rm", "1fd036ec244b6805a625428e79c8d3aa36ac30b26b1b595bcc7a3d734917aa0235623e73e6de272dcc7d8d48ab36119c1e47e2ac06798c86cf820afd0ac22c95" },
                { "ro", "6235547d6c96dfb2aa644bbf42ec4c38b54911ab4cf9b9d75facf7b682b0daf372837b0d9361b16b7e5a5b7d8b6c9bc4aa6a12abe6396b987f857dfa343c8d30" },
                { "ru", "478ad426a28adbce00b2a809d8963e932e7260d1fd526926cd9f4ec01e1da3f11e35cdfaf1f2098b16adfb9407e6b68489ddd259e81a0b71b5828d0395849ca0" },
                { "si", "937ecf08267ccde020ea3214630afd8ac0e2cc62a53f289517027cdde578026fbc1627083f64221f9b4a3ca630482b04c89915c0483be5c869871ff9f120f20e" },
                { "sk", "1498c2de9f0d684bab811d5dacd718101dba2babeb591f9d2d4d436b19898cb52402fec4cb7f6bdac6f3ac83033c42e6c77f4a276ad4898b614b07d4f84e4aa4" },
                { "sl", "5ecc55ab21514e681f9ec6c3d3064cf619c013de412e2e780d2a16ff7707a9d2c829267d0f45453d1c5a5137c6a76149fca10afae49839bd437c6999bdad0143" },
                { "son", "ec6f7c7c551c2115240e49ef941f97882c2adc23446db449a1183f7936436a49e3f825becf08b38530fdec3ccede0e266b0269c9c74d1d3878af459018c838b8" },
                { "sq", "62019d5813bb5cfcb824695021eda3deff796393cadf675bab9ce2e2cc978f23256ad22228c87c0c58cf35761ffa7e62ef26d6c4b618614573a07266fa37c003" },
                { "sr", "9f59d33cee62207de834d9488e3939284fa53e4c264aa7764c033d301c90668f3793aefc19db8af9ecc6f227ed452336aad75bba6470c1b816741b1effd45e13" },
                { "sv-SE", "61d4e4aeb8bf914c9b898efe1df61b33ac724b478e870ba098f92fb8f2aa01592d9f91c2be97123b8cd8bfcea22a90823400e5b18ec69101de6f2b7fbc11c9ff" },
                { "ta", "be85e268316b521a3f021df6745258f67ab487c6d7a79511a40d3d8f24cdd28d83d28a6477f4b015219fe88545d0473ed3d0a598067887157345b58b0cf29324" },
                { "te", "7f93f671bf3c11fde85c7a0648248d2aeed3e17bcaec571fdd89ec5049909c0f449ea1d5fc65a63716f4cc57fe03efaa755e60c9ff97c0406814a3d87183c49f" },
                { "th", "2e5b7095a01c913056a6a0a961f4a8e0dcb64230c23ccd3a53b58ce1cfb06e1bdb172e78c7972fb33b8e75d59580015b0e53645db94a3d61094fde3af0d2e2d2" },
                { "tl", "08a6a047257f5891d7387217fc7b1618b83eeaf78549234b1098f389234f2243ec55f900621e46ec4f1f0be92db15f6d2941c91f6c1f3ab14ea846a31a448778" },
                { "tr", "b336e136054f1e7a34836cbe001d76562c468b3ca408270cee18604a2ea213078271b69294ce8455f4264f51c708c2834149d3c9809890365337d0fa8210ca43" },
                { "trs", "22ca2d11b17aba638479411bc75001599eec4af41e2336c59bb1fdd7d360bb1e2603f64f8de1ff5b65953b5675be5d5a59de8658ea3da38f50c6b719d7cfc4af" },
                { "uk", "2b08054fe1d41eef5d9b150091831214ce27732a9c481c701ba42521c5ceca02797d6ae3b6f697189afe952bee3a33b53c7e0ca10f2de08346aafcfbf9898876" },
                { "ur", "c45d48f1b1c3f67b1d9c48e37b6ff538490468e0eac3a99190454fcaefebc4fc256224cc783650e8ef6257c9ff694d7ae33e9931bd6983a187b386553f271f01" },
                { "uz", "039db738fe51a496d426d71c28b60536adde5c084c1398d32f26249cdf5e54ef1ab520b01c175edd65c1e604e2eae634d8eff11dcd83b63db463e5becbf0a451" },
                { "vi", "67907daf8cb3c9cdcec432a3eef6cbae5f19e698890f5febed7518999079451706f0f2943307c6fe2d329c46dd4b742d027823562cce230532c54c25037170c1" },
                { "xh", "5c50b4ff4fd7c68c29e9210a88b1d1f3b59c07bdac57cd868dbdfdfd8e13459a0bcb36bc56ae835929ef24b1b3735aebd2aa94a81ec317335f95fdd7b280cc36" },
                { "zh-CN", "2018a5b01737473c0fe4fca45ab36606e15627679a94354bffe78859585448158b97e73916cead1acc2a485b16e3dd975fa93d49010bf8bac9ea490f0472ee28" },
                { "zh-TW", "a9f4e6f181c9ca9f8c1eb4123515d1b68ed328e95a498e63943650a624624a73bbf72bd1dccb16306f3cb629589ef86fadbed5c33eeeb31b31611c4cec73bc1f" }
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
            const string knownVersion = "78.14.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
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
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
