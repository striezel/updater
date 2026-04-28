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
            // https://ftp.mozilla.org/pub/firefox/releases/150.0.1/SHA512SUMS
            return new Dictionary<string, string>(113)
            {
                { "ach", "a6b83f5f641ac96bba316fc609a294120c80286f00864dc23c8155d47dce8232d5d25eb873176fef371ca8fab27139c10f5f4bca2f68a7db32ce56d6f5cb64c3" },
                { "af", "12ecaa1d759bc83cc0a664c5af47f4c6b1f3fae7cee3d81ff756deaa94244ec17f782355d4f7c5b9ba847f1eeed4616fe20d9c46b01930688b322075cd507cb1" },
                { "an", "ef2c0e0da874e3654cba3c703aa9882085c5c3218f769c381bded6e826c2f8985d3e5687da90df2e09de5a7a394f08aabc766c70e0315213aa744b226ab3b50c" },
                { "ar", "8d953a43b3b54137f0794e1ddebe493c781af3511023b49089b45cc696e9d05d66d40b32fca0281c15942ebbbac6fc3a34835151d7008a0c3d80a637acfaec8d" },
                { "ast", "15e2a936a18656b4317c95a18164be84df99d77cda8c7624849818442869ad1e9d7724c38eac6b0b76b64aca4b6d4e30f12e665d2ab13fc1390a7861800d125d" },
                { "az", "285e09b062a1a2f012473f82feeeda941bd16f0e4b7d1f55ae576fa66caa2433d642638edae746a883ba221b884e6189fbe5700003916c04e4325df29cd9bacf" },
                { "be", "918b2617d7848a2f30a5b17f070ab1159bb43601af245f0bacf57be43044d3f3e76eb35f03080bcaa9bd48c47757902d5e2230f8f3fc360f3d38925a71c560fd" },
                { "bg", "2963f11af0182133c09ee6665d8c407b5549d79dced6801cdf9e01195e79c515dd474d252009fdbd872eaa6c7cb2f8fab20965e24baed11130793a0ef13c3298" },
                { "bn", "9bd5238d2d2da97cfffe1ec71ebc661b31e85d4a327ef44159c458a098e800b4b8550f9084402b34261db7aa940edd49025c1b2df886224d932214c4d94553eb" },
                { "bo", "d2bdf95e92585c740abb883e1fee34d12674388978c62a36f5363c6030a23418a88e5c5967674876745a4273b97281bce1c12fa36d6aa7af91411e4b9f19c44d" },
                { "bqi", "bf6edfb5124dc2322481fadb5fc94b8c5565b16a03c5f9eed7b3d8026fe2f6c753514ddca32e344d74cdda6055865e0342bf353021ee3ffbd8c67c08b862a669" },
                { "br", "82603865aab32f4af33fc4e474b794e2d2d235ca35b440d1a047ad1934bdc3e9dd522a5044b9a4c9390f9c5bcf29b9d0e54ac9ac1c669246e482160c11d3eebc" },
                { "brx", "af6d6d919079f5503f5ad3feced68ba7372fa190a7804698e9c84e9b530f3c3373c1bc744eff8c646ec35485c4cdfa4bf9b80c99dbedcce9bbbddd49d9fc1eef" },
                { "bs", "305c7ef36866b029ccc5547790bd70e335d04643438d092629544e63ecc839aad06df436e59cb7b98eab011dde1d551ce4c9ad4396db61981a5ce57ef9ced4b8" },
                { "ca", "9621716f10ac345968bb64eb68e7ba1181f7541f3ec8d99819d85a66529ac2cedfb80936e5a1563fef4e49520378768317c3b4dd93ed9d7198c69f9dd048d069" },
                { "cak", "8c0ebbe6056d50257eb10b0201581b1c5be439a1b985f3166006e3d8dc7330a755bd132a1d0f7392c037064b3af4be4d4c8fe304f4292867c4761ad203466f97" },
                { "ckb", "49bb8750e00080d2943425fc898bc8ce2911e80e76f8c384c1551e72a4a57733ffd16ff45d35a78987437ad0dfa8910ba20244d911de0b206781690a2247f6fa" },
                { "cs", "60b4fd3265f736faf4d1f55af4a78c889c0baf317ea29bd82348d416d5d2f4c4ca5f5c5c687d33bb0efaff986f50257424cf2c8ffebafcf7e9f1dd3d1c0b3096" },
                { "cy", "954bebceef27cd655ee9a1ae3a4925ee7b80cbaf8c14efe8c59da1338e8079da16fb3315aee546ae8c9842f245d96eb68257b773861e84fd8e6a39f7b3edc5ed" },
                { "da", "43d3b2a6de8bd249f3cbbe720faa11aadd07fdde99621f9b11dad00ff42fe625bb2ca9ff6803bbbe506dd7db3fd19d34036ea73806959454d9a1e5f48296e47d" },
                { "de", "065ddab5483ca90b8b5205a4f16ff964080d4fa54339eb1311095cc3fbc4cbf1446d3d4d3d07a8a53de25eb0c6e6df29728c9cc7c3046d1fca1ff2aeb4e7b531" },
                { "dsb", "4089063c95ab146bff8dcc6590cf905557950ecffc3581d685780c14c2e7a0699b0101d6cea73a47427403f5e88dca1b5344fd40a3daf6d838e238c4c86608f1" },
                { "el", "419b8479a65523ed6ff3d4e70a67113c9314e772693715ae6b7c8eaf534cfea66a202408b3888f0a2f50a139d4e850d7742f453c3eb8b8a0f244ad018bd98001" },
                { "en-CA", "96875f9e114613e5d20ee18002c5c5b59074630128fe1cdbdfffe2e99d86023f9329335c92fef35721374ff0ff687f57b33d921e8d818acb2bcffae054f1c98e" },
                { "en-GB", "b3c1fc71f49b82842eed709ee9378d7f82819e874f2add310e745baaed4b4d50bd45e78df39c59fc0f6cb78a95c23a0399015c83a942e5211bcf88f718fea8e9" },
                { "en-US", "178185b84ed7b4f295a683620724fe578d25720d46c00c51bffb83c4219eda280e9549071603ec5b1fa2e126832e8aca29188f68ebe74bf0847faa3077249acf" },
                { "eo", "7f8710518ab2cf30433a17d601c44c8c2725528b1b5c6018a5af3f5880801f008abe0d7765792fb4385cf456dc0f48012ba02b1cdd5eb396f5bbe7a363451ee7" },
                { "es-AR", "0e9c5b90ea6051e2e791f94bb6ff2d912ceb36d494be6ecc6d7782998816b103f6ea1b3a0f31a92327b842ce1e2b9e59f91d37f00fad839afd95be01d99441ee" },
                { "es-CL", "2696451e843bd46c165037277773d22be7327ca52879f6071947164eb7d4c330acd547347843e7088b8ca79271f6de9df4cb36f6eaf1ea0efba17e6ed719dea7" },
                { "es-ES", "1385699e77332bbcab52f908de745c39093dce4d1f7496cc834a97432d939b2e41e87fa4732ad6642d5f0a8f89d522bb3f76c8b565b4918633eef276f971ac54" },
                { "es-MX", "712125fb2cb1d91946be958de268e8d59ee2f046626807f18453ba07891902c13d09d09db0c4f26c6ae2a3a2fb0a2508905632bacddfc0b6b85d0fd85c36f321" },
                { "et", "9d5f0118d8684e77dfff9022168fbd41ea9127b883e94025398e61fec4160232b6ecc240925c2e6bfa28bcc7642b8b891a771896873fc5b2b68ff68675a4208b" },
                { "eu", "f0440f66f1447669e8102ab61a2188e6de021d74e2591fcb0c18e0f1e68ba9004de40c657a610488943dbab6c68cfbc7d7d122fdbeca4673d15eee5ea0ca5efe" },
                { "fa", "2256f9ca9438bc209dc82683438094211436bec69cae616f77a9eccf52427db5b7d486257105db5b2945c570d44b664e9dc52f0425ae3861d17c397f203ac11b" },
                { "ff", "e91e76c1e76b254880c332c92259e95672226d5f23d0407e15c92d2d6045c95bb4fcdd7cde69ad0ec81b3ad5783c5ea29c79fd2420d806f3b1131d74a215234f" },
                { "fi", "ceccc0aa55d026fb86f122482bd0990ef147ef912c8d5c254ca6aab70f343dc6bcc08b5bd78c8da7856a9335bcf24886394d8d4694f07af8be2c419e17b3e9fe" },
                { "fr", "577650c6dc3ebdc2ec0e9edd899a4051b6af29746fdfae0ca7762895144dfdc7479bc91669187d28e9dbc7b1b9ebc32b1f2b3da270205bb057aaf9439b12f5ed" },
                { "fur", "0529c5119182611a58cdb477b5c785d411a8c80486990cb90d1b45c952960c79d0c12bd1f6ff1c1fbc73c5f0a82d770fd6e07d1e65d24613e5237845af18ee4f" },
                { "fy-NL", "52ef6f1fb0fc277be311c0750c98e34635cb9183f6e561eec6529f74dcc9a467c8299af166d5173aedcf228262a95c156049d1aa00980058f3a15563057d2ae9" },
                { "ga-IE", "f473a6675a807f1a3468348c526c587c7f386cbfbecad7cc160542d18af17a52b3bba266aa5c125639d105e569b3791aa9bba7f6434c5f96979d982d79af7589" },
                { "gd", "e17fe9a14595d5cb0c010575394181ce0e79d35d36c2c05349c92c76d2151dca901073a9b0d2d04c01d8ce94a1c6e916b8d06dcca4b4fa996176db88a9eaff4d" },
                { "gl", "a87682933b7fc37a62fcbe9ec105c69d33f04d12bda05ff3c1caa6dac96404b3624caab32737f9f9e4db4228f0826de85ca1af3e17d9ce2dcc673089076b7f21" },
                { "gn", "e058afd7084f5280f434a836aebcfe86f11c77c752f8ba8b3596e6f5fed2235243e94637d2cf2509c3a0d265b267bf2d14590524369b99eab61419fb4b16d300" },
                { "gu-IN", "65e30d9c88c932f75f138904807fc5a8c6c59cdce9eeb20abd653f9be0e87521d9dadb1ab597205440ea62fba267410f3bf179baf11eb5d185459aba4cfedd70" },
                { "he", "4245ab62814efeaebdf9b7018b60585f8642413dd5d8142797d14ec7fc97983cabde9d40c47a8e458fd4f2b1a48ea02e8fbd74595732d2e8d334331fb3812fc8" },
                { "hi-IN", "25a8d4e9f32a275a3a07cc7ddf38bec4b0e2ae70e597acea644c2e4cb0222fc84b427b7852006edbe3c157b86e412e2fdfdb22c110d682edb8184cde9b4d16b1" },
                { "hr", "57bf9ee6c7fd910f466aa94bde170b38bd320efdac52f407793a8e79223fbc8fc988943b7e5477f476814349d11a3440a3dbd36b1106f006578bbf92805b4975" },
                { "hsb", "2de3c224e3b07d6f920186c4c0e52eea3a256991824f4a5ae72744ead9119ff8b95f996ca2165319de6b36d92f8dd2aa29664413f8c4e38d0e26defc6f23a1cd" },
                { "hu", "0bd1eb9fdb14ddf32bdf2c20793a13cc707bb557f0416e28c760a5247c7f8e7f25d6d0f40d2ed92d0cf3f58c2cc3c6697f0bdc71678f0d29188632cb9b62b26b" },
                { "hy-AM", "aec1e093548f0276e1d79038cc91a488424b4d21565e787c3d8622186e2635527be22f52b123599a7118e8dcee8be3d33b76578dd4896be5d547ce2ad14b7569" },
                { "hye", "a719afc8b7a6e3d355f23c669e266eb7e6509c68572bde85a286090ed9b04af89a148fb9bfa3bb0b6c12d24f7ce2f45a5bcc0747e6b8f05e7140ade7d39b47ce" },
                { "ia", "57b2c2a2b4d5bc94a162ab47a1cb9f6015c984609d06767596eae2dfdebc9cee2b488127a6e267bb275ee51aaf30be994c7955ce7cb5a493ecf49f2a73b45a93" },
                { "id", "727fe073cf725b1d26f0dd0b60192b53efb6b4e3f55ba703bed099d8c97fa3565a34ccd17d19ded70c233f63da57fe9e4132aec70eafb229ee3cfe02e49c2898" },
                { "is", "a63d597505bd66d4a41e6992a242893abf19d434493df60dd4c771fafa08040bfcaf0fa1fa2a8b05c2243178ca466b54114599f045745afee4be7414ec383692" },
                { "it", "d419b165276d00cf6642730ed881e4e9b4997a463619cf6b3824bf0b81e3e7e6d02ddde79b6b1bfe06d4a4f6259c7be6d2800011b0b2fa91eb7fd8320b26f3a3" },
                { "ja", "c02b36f4afc708b9bddc177fb80e2526fba1b5fe3e267ae5bf1de66424c9ab4125d43241309761a44b97f61809c31a104a02fbb575021dd1a8ef6e87331882e5" },
                { "ka", "7e1e16d4108429a4ced42911c1124799ea48e71d61f109ab3b3341e26fdf6670ae919347a27daaad5a9baac7898c375590e2f4785939fbac875255c41f3fcb7c" },
                { "kab", "605c25914a54e7b5e0ec1b75373a178eafa86997d4524ec5d01e0a3245bab880cc9ae07996a36185adeb7eb450c28c0a5c9601abcef11c7163ff18f8eeb3ce56" },
                { "kk", "056211d7808317a3d1c34c9b59d6f73ee996d2516a54d160333444a3fc8e31ffb5e869080254887fd1878b47c19add63d4f2d5b387c94ab18f1fc6ec5b7403b6" },
                { "km", "10ec7a4536c7c3c7700b613e77d589884595ef63841ae68791ec9078a1da458781cac627ca4c2e7b4039cca0b41eea4da6d2abf0817ed701b4bbcbe7fc0dad65" },
                { "kn", "eb6eeddf899396c713e33a4b9cd71beb82d072ad025befa63938c7851d476fe65de8916a80fb6c0985b891b814514c4c06549327c6cc4854346b2c524532e279" },
                { "ko", "23ef505ec821690744e0428c61e6046794037f7bacf8b656f63cacc6c02ce56738fdc5e9d545619ad9ed4f5a436c3e2769df78276adb9af47d02d174dac98c75" },
                { "lij", "3eca3eaf74eec758b70f4006f6e42fd89241232c7fb5f0392753c009da36fb3cbb9a10be55dd062075e0b447faedd656b045adac5e3fc18715aa2386f9f6c2c3" },
                { "lo", "5f28451253d38cee951ffafe52b6b86c036c0bc0e0e0324f12002fd0411b421d09e3ed85b12ab3a0cb08e39b34f100f57abafae100c6b42c5ccdc4e2141e0f8d" },
                { "lt", "93a0029c454b793e2d105e430b8d0cf66f05f768ecb511699390cbe668df74132767ca56e244e1e179067a89e7a69cf00fe61dd6c6f32176f9381769833c8fe2" },
                { "ltg", "c98019ae34dcaf570551ef4528f3e6155fbfe72b9bb9623d794e1a98c661085f9b8236910d5427d2f78ec337b2af17c1c966857ea7bac0e5153873e13c7eed1c" },
                { "lv", "40e7fc8e3f155d9ed57dcf4d2da767220392660c3e6074ddb08d138ee203836f626bf40b913022a0dfa5d33d41f655c55ef5b4155f40b7baaf850df577ef9f87" },
                { "meh", "e647fb9209699797dc0a7f7223a21017126dff4bd884182d86a4ca7301c00d7891271d96abe447ab6731991b315656a1bbdbad13755bf9de9633d2481bb1dd8b" },
                { "mk", "e765e1750053aacaf234909fa09c029e0fc125d0c51bc11e145ef5bc2bbe54aef451a54871060292cd5beaaaaed9084970d2a3a4c41c710dff821482a7c6986a" },
                { "ml", "315b09c23057906ddee3475a66eb195fda8f97978808632fc12e33911378bcd1337d92db7485dbd382e97dc951a844b802fceb417cf52e607218eaa57ff9a936" },
                { "mr", "37ee7d35a54ebc073734674cac8fe4155169ec56cb42bcb242859ad995c363571ea29a531c9bd6760897ef55f86f1426db76e8fc3dced7c1782c380927b301e4" },
                { "ms", "573107c4d9f9028bf646dccc57a534bcc4ccfd69421d66ef834196c8185b5671bff369d6a78907569358413418c0bd2c6c1871d999baf1a3229756307ebcc091" },
                { "my", "5e34534b1c659a3600b38f4e581f2ded6c3b41de6f489f1bf520d31239c95b832aa24e69f56fe81f2d5dd7818235d217a5a50e5366f0a13f969093aefd7707bc" },
                { "nb-NO", "8c5e31f6287401b47f444ff5fa15e4f02c4858804c4d4eb60ccda74ab973458f3ff82e2fce2694da071136c967786db8cdea0994524f599d1f62b361ecde4338" },
                { "ne-NP", "6602eee2800d8b5c396c7f3f1fda0485142eca668435b8ff15cad0d2de5075a45c8491842d63a88e749018ea1307dc08da101517968dea27476644b64d39e57d" },
                { "nl", "ab5776eabc035731d4332836a88de065ac6b19a9d6200d5b59e3a7e5fcc91ecf17fa807af44136d0d3b3fb00e895920d969cf0cbd3199f73f9dda905f66740b1" },
                { "nn-NO", "b5fe733a1b60ddc4398b8e3311f6b124732d13d9a473dec078c987608abe5279f5020374609d0ca754f9f3893521dd6eebf45cadf9f0219006708cd734ea917b" },
                { "oc", "44571a6b43e56f30b93dab3a7e40b05a2a7dfae05ac4ed1a35e8f9afefa272e020ab77661aa6b71a67788719e949d6ee115ec5e5f3e48870eb61fb6c9e7f4bab" },
                { "pa-IN", "80a9a2e32581d40b5f1d74ec66ac6eb8b1a286e887d6939b0ad5acedb876715d9d64f01f2c6b789c9694b44fab2f7a438d6e91dbec3a97c5acc33e30347b9acc" },
                { "pl", "2f4857b026dd2503de76d111dccca4efa621fb7d1dfe6170d630999e1d5ace556b237b77bd12227c54bd770bd59593fd63d715ada9ea7b4819b895457caa9802" },
                { "pt-BR", "229758c44ad6d4e0e068561d768514603402d142941f78eb3c817604a6d41331b91ab3364c9cd49cff1771eef0140593ef8ca806ebf7c9adabd393072de2a00a" },
                { "pt-PT", "8b1be32287aab10effb24c743baa6152a29474ca50d1937f6dd8f7712138ba1fc98e53a77af78519744e78754a792fea12d977c319eab3759a8ce2460f0b54de" },
                { "rm", "75d8feba43cde2e3ead785a9e783ecd359602bc69bd54fdde9624d6bcc02a7abed0aa738f2a06b23943dc2aceae4149653a862b008cf02ad85f20db5e1adbde5" },
                { "ro", "7132f62236640fb5dc9aeff0e820b5b882eb813b46da7afbd5c480b91c6d27a289e4fb77c854b567d779cb28042f99e94aa43a6e1de2d7cb1587ef650015ef1e" },
                { "ru", "00ab072c4a28a43b7c3568609d346843d6679a015b863bd199252b01468d20f52834b3c8463ba63fd20c8a73fc638cc82a1dc9d5db0d7d6de9fd25d90b2f47ea" },
                { "sat", "1f4830802d811d08f0902fc6f1877b9d40709ae5323e98a6d661f2f57dad31fc128794d0804a07f833d766607046fda969c45f89490e8b2a62255db277dfc45c" },
                { "sc", "a208a38e6460cc583dff36923db4b5f777c0386d0284dacac8579b7f7a9af8246cfa1e4aa882a3e1ff02008ba36110e82f00178ce83786703efc5065d3aafb34" },
                { "scn", "5920a0671458e7c14699ec56acfddd11b8beb295ee55b6c8fc1253da55ac7e388e031469669c5b9928a0b17268488caf54cfcfe158b77590bbcf6f8269f89a91" },
                { "sco", "54799a1981c3673baefbf63969a0a4692dd7eb094cef352be70c192d2d04a7d22e487a94fdfdd9cfa2e3320f0dc003ec698af2dbd0efd637afe4b4898522961a" },
                { "si", "8e7467d7cca0198015a0a77dfb7d380b1d80609d452282e15f2415a78942790c7a007efe18b381357fadbfdb3086752771eba02e5a86917c83418e44da452b81" },
                { "sk", "60dee6e9d546c7bdabac1b17d75413804576e3c2dda8afcf21da8d38b50f2734c753f2ae91baadb55675db8f0a46db2c3161d47d8035fca3d05dda8ca8b0502c" },
                { "skr", "1225e3948ac0be072418c944198d39238477c4612a6415dcbe456a9089976da6f5ab22c2ae1b01b265e27145c08b13b955687254a4d666e172f52095aa800d50" },
                { "sl", "e6c81bb387a32d3e4798d770406d803d4ba4ee4cfc064db787caf0390eecf2147d64fe9c3f589b9c4b218017466fce79681d82e772ab7313fb393c006532ddfa" },
                { "son", "ed09ce8e417428bd19dc4fec352ace8d510e09ad04ea335a3d436e0377ed32b528e2953dea8a37907cb8619dc2d664aac797925553244662a789a5038b63d68f" },
                { "sq", "0d310505be27df2562505ca992e62aa164f95102276fe44f636e6b839663f7f0f347f05550c2904dc10eede889b46528b40445364682455509992284eb15b3cd" },
                { "sr", "b7ef29f9dfb0beae43d15aed8c662c672e0ddc8711f18d7aac7b16351e78e9d323cdaf62372724075a697ee2ccd56897a0b1ca26dd9c27dbddbb014c40d56ce0" },
                { "sv-SE", "6c3359c1a6d5a96ae6883649543d43bcb45b1755813949f05f86086b952ab6979b28fdd9696f9e19170bbfa9d7bbdf942069dbc6b4e6b24d74356c6262d4aa1b" },
                { "szl", "02456ac82d9e96497475fb81ef495300cc2cc0c07a479657b5ea8ff9a58a1743dce9a009b11cce7674456ed1da3705f230cc6ddf009c0c3e57d0b8984c9e1b79" },
                { "ta", "978b560aeb2cc67799246bfb857574a8b7cba6adc0aeb0a47186a94666cd76714b0b9f3ce1fad9d67607302bf9a41ff8eca069e6263d52176a40be5fcff81c04" },
                { "te", "b79832cf9d2ed2851455b3bd83f887278f0051b321b39cde475556e75cf989a9290ff4968f22caf400af58c5f74aebea08e44fb3ab7fed0d54326c74d5099cb7" },
                { "tg", "bbee6dd7bf2db4c4f5f59b8374f4eb060dc3a55148213951341e2db199b852e807bdd691ba25d7027536eee0df2df301c059e6ac34bbff7d9e274b2b20730865" },
                { "th", "1e0d4ba3da68d93947ce479cd7d87a62ea8682ae403574368adfa9e6183a954dd279804a2b5fec6288902de67fc504a53718c2b1420a1a614f287ef50c70dab3" },
                { "tl", "3e725df613abc647516a4f3d025fbc4637c366e07770410b5bada5a0068577f61695e6c473f72931bbcbe9714aebd07505bc5367422bffbb907f0d0315a37326" },
                { "tr", "18b01733705c1a1b9da3d68008e946ff9e2238ee6492794b534c948c02d9d7243b89cb9bf5ea8c358397dcc5cb7ac00b426287f76342242a955bc8df9885c065" },
                { "trs", "cb0ff87d0cb76fb7c81695080803cb3bdb9d231f4b82c702fe3f572502f8798b893d1635b9ef547f3068c708887cd2bcf9b31c681224c2849e68bd4290a95d0a" },
                { "uk", "afbec28d9c802b01832d027587c900738b04eaa46ce4a299a95152c010831beb95f5b48f7134ebfd37d99013b2ca443a285c6d1673382071e1280f4689b77889" },
                { "ur", "ae44c3ffdf3bbdc73b25b2360c5c0f54dd6a00cea61ae23b78dc60e057c94f4dfc1100657b38550d2723b2878ff5a42aa62a365f37854f001fb8155b256d2932" },
                { "uz", "0d6dafdf9e08baa7020691fcc560426e17675be446469fc9d44fbab1ea521b0ac5b25f1af2aa38bc9d05cc8f3663a8a736136f042d4426ae4bd1704d117e936e" },
                { "vi", "bfbdcede5289841ede8d3c69597e7368d8bad89159d6c288c3b403060e26c76a2a80cc843d6d52d15eb802f375d20f1def95bd585daddc6d8ea018824f884f03" },
                { "wo", "ce3e85693323f21717c6b1cae8ddb76f5741892a4325c4acb03c26ae141e29e213ce072e287ea292c3a4449d3bfcda384e0e44e716cfa58bf422b9f96e74fdb8" },
                { "xh", "d7266b3dfc738841168d8f28e071e04b51f6d3433d5924a441987b3f9fe55997c1da1175a8a1e40a5580fae8d3e05a41a77155432ff5628aeb47aad129fa549d" },
                { "zh-CN", "21378f80b58b7d74b778d7ca58a18b5bbe41312c468e9e41c4b7e40c968b13c539db0d4a1aa4e7b2d4d8f7cbc1eddb72aed4431cf293af8fba6d130009fe00b5" },
                { "zh-TW", "f4f8612443650d28dc9bb67f68a25ed716af70cfbddba7f958de6e5afcb24a99f691e1f50362714145c6850de940b58776ad49ca4161d837ac2fe577a8d62c91" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/150.0.1/SHA512SUMS
            return new Dictionary<string, string>(113)
            {
                { "ach", "865ee9adaa3cbc6120c5e079b7de26f8887b745fdcff24857483636c8025dfc2e7e4aa8a8ce2f10b6e4afe7929809a3020a56f44f52f14e8c7659061870e9b63" },
                { "af", "603340f23c0360a31a9a9c80d8ab63d68c6529ca5ca806ed2d39c1344d4848c0dbfcb1f05d0a55c8b780950e6726feb6c64fb952499c380dbea088f1cc55b779" },
                { "an", "7fcebea884b09336ad8ef44df12a3d3916bc1f5b28295ed35fe251fe1e94495b6f0c832328841fd6b3398b22ca9bbbc25e8ee52fd0853271f4632512f607766e" },
                { "ar", "9518e9e90edbb679f4d1e83c5e33ff30083d6dfb1b1b987ccabe78d917271b77e32b0d5ebd5eae33c63c9f82c2c58b909f84b3ad228573117f0f4acd422a98dc" },
                { "ast", "43ad81f829adc7b89a8e8a41530c7315aa1ed3926eb62e39054a40bf429e91d41eb3a1ce0e38c71e4986d3705137af450d9703973c466d6ef22c318ee299b9ab" },
                { "az", "aa44b2e6367ed838947e0166d2f2cbd5a7b54d48b517ff0938fe35cc103333b8f894d45edf36459e74f7fb073c3e34ae94beb27d7bb10d91fccd7af6445e7d4d" },
                { "be", "fa60b2721208e74ffba777f6fe1c6e0e7dea31c3e42cee4814ad6ce83f54e819c28e3efc6bb5855d69ca1220d056c6fa8246e0b256d7a020fa4e2542b7eb2776" },
                { "bg", "f3e790fe1c6d65d3e22b5d05dc27e835cdd2753e0a8ee3d593db6a46b0b052852d90c33683ae82c708e2f0d41a00b3a0e02a97932f4eca60c3b42c471f85c5c0" },
                { "bn", "b7232d645973de1301c86a67fd055b43fac227003df8ed59e4f2f2b29ebc5e2fc2c6c7dfe8d54bace92211f4625f2e59fdb68dc3bfec0559f4c2cba1609c0dc7" },
                { "bo", "169d3e5db8db79aec50cf49d1dc7aa375c2e436ca1c0a60a1a954d568e4b63b6eaab03b03542ec5b36167bd71ba4d8ee8afe46623acac5b3ee095adf6c7479f4" },
                { "bqi", "e16c4941977dcec0856ae0b3982dc8e14ce29ce1d77bfa90a8f624cb1ed350569aaa5f5aaa11fc76706c95dc958c95b52b0b2daa24341aa34be641a4901cbdf1" },
                { "br", "2381ed41cedb10cf13afc000c09cc80ba67bd1a8d62f111bcdc03f469713ea1bba8526cc8bc49a896414c892e1e2d0494610b3162e51853be38bc6a606193a98" },
                { "brx", "e217270ddeaa5aa1ce12bc34ec028ba795e23c59d7d07c75494fb4efb32ae84eab9f74d34f414b157aa66cb7d591f59ba470dea6adc6f2f923d046d312301dc8" },
                { "bs", "022621a61ad65a38280013260f02de4ade274d187f27a8c0e0e9011d80e32b14e9061da38411d658c5cd50c33f1252b6dee5d1291370001b6d623508ab901aa1" },
                { "ca", "bc621f39fca14cf54e4a966ca5eebb02dbb64bfacfe2c89a7bca52c54dcc51ae266a9b2652cbad942e90820c277e6f53100bb2136bc660a338c95f659aa58ff9" },
                { "cak", "5044dc038a8246a6f23bc7285bf04b7aa7c40dc92b91322f1b2bf999bf8a2a4bf86fe6d01ac6f88e28a3ba935953b5a8b6e1ad4177ef925ec0dd1a3cb58767c9" },
                { "ckb", "1a922c3f7e844dc43c945b2e83afa6956528cc6209dafb1fc70c6757ee4b68111f9f6dd0296c2641aed0ebe23396f2b2e17722a88035daeb05ebac7ff7ab5956" },
                { "cs", "06d95fdd9b837828866bfa25a83ff9cac593e57fa7a50f377f13f7e0b071cc76a5b281f8b05bfdb7da1cc47ad80ad1d7e7c81cdc17b1969aa21a07386ebe8a1f" },
                { "cy", "485aafbaf3113dcdf3f79712c2fa980327c971dbdc80990428f4ce109a4c691e28adf4a437dfc08743f002fb596bdadaea44331d64c5947ab3c484bc25fefe46" },
                { "da", "65eb2e7cda97bb09abfe8ab700fec62e8d3b751543e9c1ad2f2695353b24b21b24ab195fb95dfc7c20761cd9f100c30f988311fe7aead12fb2f183561cf29c9e" },
                { "de", "fb10566a133c7617c8645780814cfade05ce91f275bdbe1871a805d6353d6d76e9c983d0020bf5268691f32f1e6037fa65d78f85612767faa9e8ab798e37dc10" },
                { "dsb", "e067f0010789868cb47159dbfc79b29b10422f4ac893aafe09bf41375e688039fca5028f3b6d40452194e26c126239911e6eac05e267c616d4063a4ef67cd378" },
                { "el", "63e540252cb82ce9849bee513420950fcd5bb0fe21e5acda53f822910a427b03712e5e0cef9f516d6f6ea818f418b474f81f08db3c99fdbd5d07b0eba7ec1deb" },
                { "en-CA", "d231b08b633bfe23d89c2942fe05c3010971d08ee60e6848a62f14fef5d848407af5feb853b0fe6c459cfa71a728159f10198d283b53ed78554dbde1e3b3e392" },
                { "en-GB", "70e7e3415df37a33390553e0c3637eb6e73dc0618d17371f9b9c35191468e321773a5d46805929f40e589d20df2a4b2f4f48ef45c774f936b2a21084d5c53f52" },
                { "en-US", "3cf708c2b7ff7b35235f437606c0c472d3ce1a8769d454b732f1b2c9e1eca2bbfd576c700a4228e0a9f74a30221e210c6b81a4538175216a103d6ba0f07162ed" },
                { "eo", "c739904cba68ef382daad86e218e6101fe829eefb5ee52a51c6a181ba59b7b57928258569dce9577c7f12c4fde3e97d25f3a4be08636bf567ef3c9bfad59f40c" },
                { "es-AR", "c67d98daac2dca107f087143c6963726275dd1731d8e5fd2cc9883d94581433210a9807b60cd1e75dc7c1e52866f15a2c852b43d0305d96da1ee893bd36d23b2" },
                { "es-CL", "937343f190fb9552aecdff173ccdd76abb325c8110cd40d9a48c41381a410580d940d139d601fe44480e74cdb82a586f1d9760b3142955bf04ace3a7f6efca71" },
                { "es-ES", "62ad5cc86e228c17b285fbe48bfde8390f6bba9dc5b7667322fc9201fb1ea526cab8205acd78060bd62682b01f6afb2c54cd0c232e2df6b4af70ed25b04d1d16" },
                { "es-MX", "d39c5f063d6669069c6cc1c6eda0c28efc39bec502e75174137f0edaeb259f3a32e3ed3fc75c69af1023ea62bf59f2670ac1b7c6386c3d6b48889ad8c23e0600" },
                { "et", "53635191d3e58dd3460299e9c6bbfa02e2ad2df1a818527956d69fd3c0ee2c1107381b9c8dc0fcfadd5b8830a3a0bd3b012db66f14dc9a57186997c2e15d3638" },
                { "eu", "e17cc336f018bace0911c55f15f75fe96b1d239bc05b8b7a6d22043ec56b2c2cfc9fd8f0a28ea58b1447a67803157918177941850eae82bdf6137033eaa826c5" },
                { "fa", "31604f9f43218959d45f4555f1ec51159e92c41a9c2b33b7290367ef1730979432f76284d31c0508a14bb4fae00b9057b94a2cc048a76346fc3d164511611b99" },
                { "ff", "12744119edd510399be0abbb594362f15ef729a1a30777cfe86e6ef19c35a6d976bc0b54f388d16344c3abd362693d3836bc41aabd0429686906e730f7010e58" },
                { "fi", "98f66b1055333337f4f077bbe395dc7a488a35995c3bb1dd0b0987b15b7e782ec42b9515f919d3c9594c8d8104cf1510b95ba58d012b04c7415cac79adc8444e" },
                { "fr", "7e163da1e747da7b2f289bfa30fdc6cc84b0aff92fa563bba9921b8efa97724d41ffebaf76d417ef5d5fa486739e154a644599055c3c7d13bdc7990c44e05b9a" },
                { "fur", "9346a5383cb50233bfa02a8dabf7e302a39041ab61c7e53376d5aff0d98c9a7f54aa0bade08c0cea9972cf05e139e1f8e2172e5cf47efc051d11e3238a9b3a3d" },
                { "fy-NL", "60b1f7955c5dae66099e70eb11bbf4c652441c9ef0976cf025ff37250e368df76b9c27d3dad682021444fcf2450b3a8d7d6d1b23cdf78bb788a692c90571db17" },
                { "ga-IE", "48803c312e6d683037aaf07708ef21f81c48c414c2e671aebd7a9e67fb704269ff779ad361e9c59eb141626d6c93a64cf634dc8348e929da20a1f9348c73ba94" },
                { "gd", "e633198f6542f2e231d3d55aa4e17f10a54b8310b06df4e55d817f92e55da9897d7f7438208be01de2bd05d8ac5498c27815ede10c55c41453d758ea0afff209" },
                { "gl", "05c4bdba834d9fe89bd7ec856b1148b90c6b6018c5200233bb05cfd324fe9166c803ac0c12cf863e771d9a420e84cffdf7f6f203fed2ace26acc69101258488b" },
                { "gn", "1f51f5cf81b9aa07e392449c8177380274a2934cdbbb15be565bce522a60b683a081f38a7a2736af6e73120053d3b47a0ed9f871eb6a3817744ac2eb785095a0" },
                { "gu-IN", "38c85ce0dfa87953e9434fa12ad87508d354f80e5055991e2c20a870ab6115b1cdb1e637a30e158f1b3a3bd7db7a3209c346b0307701bc63745c6e859472be4c" },
                { "he", "7aaa36b33d6fa080df83953b13f3e65f38fa67a8cf58c6cfde7dfd219bb4df2b2fdb0abbfbbcdcc33750af9a49607cd9028e5f77c3b0c272224734796020f1ec" },
                { "hi-IN", "3c5691956df1810270de54fcb9137c992b04bebe106ca4114f5f087a4777046d6d61285ba940cfe66d00fc962e0bb4279a58159b87e73f8d01d2d4c61d6aa78a" },
                { "hr", "018900e381a8c38119dcd8a9e259a311815b39492eb7fbd8e4641b6ffa1bfb11cde2684a7409cf6f06796022f7a630a4f0ba675ffa507a702e4036f6cba001c2" },
                { "hsb", "6fdc0bf48909ecf0d706a0df186f5f763ab279da8b0623ed224a5b1b9db8555e646b7c718b5ea66f82ebb2256ea49a5c7d0783c0d340b3910b0b26fbe9bb286e" },
                { "hu", "c0b0d9edc120a585b2bbfa79c10be0ec78931758cc7de30aed18475f727ff4ec02dfeb48baa032d253c4bbc2fd5ab28c875625212d9d416a679631d0c2c2976b" },
                { "hy-AM", "5a3d4d039bfe4871f0ee8463a918e5dc69c8ae795d6102a3bc58189f207b7f1ada6144a8157e438a9af9b6ff76a91ef7c2e2c1877d25811dcd5f337efc0aecb1" },
                { "hye", "39fe06385d0e9143354e19adacc7e854d579a1248de2b5f92aee521bf48675e3ea62bb732e10a6309e66f94d0a4c267b9f9fff169a99026586bebba8747066dd" },
                { "ia", "eea30bff1f159c4d6b75e558ff4617a2f3c0cd6ad53cd5ceac9e0c514a8afd4b4904fa5f61eddf645f681a145ce7e7af39bb29391cb8ada1ae1fb382f5c5ea47" },
                { "id", "6c8442d6ad727b9839b641e0df30b8885aac15ace1e0e8a98d7e71a37e0ac6a130068cd932c081f9475cf24d4a22c6ebc14d12d819951779dc70d7d52e8eaa78" },
                { "is", "73dc20d6fba79b5c99018f1aba2a5fffdfc108834ddc99be3b807fede84dd1e44b5c089dd42dc8d0b1f94537b0985ba886c563fa211b8030df176b8ecdb07637" },
                { "it", "7491b32fb02f924aa488a7cdbd9a0d5499a4d8a53688eb60126de31b2b453030b86d16d1bc578666d717d21b10623b10f378f31b711b2216a31b03e7254bfd0e" },
                { "ja", "f63fa214f56149d39cd3fc79c9700672f62054e65e8226d66a558baf15c604dfd8911e67be55421d473d51170c0573101847bc30ddeea27fc2bd5a581f79acc8" },
                { "ka", "715f77addff79fe369b9e837ccc229260c00bdb8476a6ca750fd35552385cc78e87a355634526b50ac9a8809f0305dabb2b60cec9bcee31982d8db02bda7fec2" },
                { "kab", "4901fd7f62ffb7efab100f02773eeab0a33368a4095d01d4bd9ed31c59112fc75ee3c471554dc46d697b0560a733767b9c6180a40b1d3421a722947571bc6ff5" },
                { "kk", "590e99bbe324d18313edc625888b37013d8235978922c54d25f267b91e838e4a215733db44e14f3ade2cab36f869aed4b952297ddfb9e9e740d531ceb6f755e1" },
                { "km", "65b19cd9d1277c21b182447d4af27c345988cf276ca2d1c25791f4bedc07b8f4fd74c33fa231a3061c30eb331107b2807348ea9c5fa11fb97fe0ebc727c04eaa" },
                { "kn", "5e45dc4473332c7470502b9e23eca2d6f668be019d364dd0ea17dcb5cab69dd3c2869b35a0f6582db88cb55e7101da08f40e9132114ac7dc6f7d10cff01d2f75" },
                { "ko", "bdfbb42b35b0503160a96cd121560f1af2a939d9146b26d16fdecb7436017cf2acec856f28692515d35c69ac8db80043f338420828eda726ec74cdc1b904653f" },
                { "lij", "80f898db6523f215ba25c6acb2af719fb1aca4acbf37a6508e5a0c8a5e4d3be4b2d97927c608687b36378be9d649d948abf00dcf6ecd873c236bc1d30655226c" },
                { "lo", "9c5e63918ceba0732bc910d8d9e48c3b14791d1136b2f6cd01b17be516dc68bba939820d0ec159c33163ab40aba2656ebfb8dcf3f5d672c50a01b608725deb92" },
                { "lt", "8277f31a49a3744f5cc32e37157eee1522a96b8bf435bc4096e0abac981ef2be051f9b41f6b2535059e4c13f630b19d800b9d2ed7ae8547c84bc19a0aa76fe7a" },
                { "ltg", "b7ac7eb71fe89ea3e5f82ed371d33cb9d8d8b1f56ebd73aba018488f81a90a546b7421cfa1a3059566e411afb0e769d2f8f49246774053c1d4b5163adef212e5" },
                { "lv", "16864b51a897f2ade50e39ef6346d319a402aa7ea42b57e3212d06657b44ac61ec6eae6d59523e0185675560f7a7c36e44a5bd77ca36caafaf357fb787e73cd5" },
                { "meh", "438d2ff2705d12aa47146cd6552c144ac675235843f6404e433deed1ca4f7d9bedad1bf6b5b0ac7f3fd901510c063a9f817331f97cc3503848404f91fbb4a3cc" },
                { "mk", "49b018399e2f0db28c8539d8a2341b3fa66f1d51f16b8f877bb9aeb24f7f13f83a85c048d41932784bc4151a988337e81a7cc8e62dc04fe394a46a89b4d5db24" },
                { "ml", "da180f13a911a3ee26eaa501e0def9d12a99023f1d768d0a9d9e560003aacb8e42f6e5f830cfe0758428ea8483013f704178aa5e438e9a8aa0b78d0a276d780f" },
                { "mr", "b43c7b8f66bd66643615f0b2c0e7f904fdd9a3b233c728001ce0930d67c4f07c9bbc8b5406d0f5fbcf2eebf50ccc3ac22d83e313d743b31a699e68e57048827f" },
                { "ms", "01f57a735a6760d645b7fa022ee7af05e3dff7addfdebd69f43c9976586250d9a5f7ad15d00cc5b86e24879b3f97e572f510b6dca892c9e53c5465a98181d7ac" },
                { "my", "896428092bb773754ac052b7616325fc3cd3d8d6921833de20b47f844459ad5dcb14b23e931057a7ba926930209c0989fe77e3add9bf99ca4ad2fc2236c8c321" },
                { "nb-NO", "cd8600e91a143f26ce4b403a26686a8b50e037dc8cdf7d1a608308e40dfdd8414ddd736dd3d115804d773d4e7b40e78011ae3469a359778a3650f48ae597738f" },
                { "ne-NP", "de3f2641117074b1bdcd63ae03ea2d48b3bd567ff0e5206369cac18edb253824473589fa77f13829a81836e87297f80bc3cf05929f7ea17251e682ce521479af" },
                { "nl", "04b43b00980e577e4a9228c5a5a1dcab8bf175f9b56e4dc01d3e9fef1ef58c321ff9523433b2c162af8ba70a80497687e27cb692951e2c080b94a2c156754c93" },
                { "nn-NO", "62ced4ccf68dd70f8875cf9e0f15f3c464f7ba05b2c867c8f33e7364c563a08e491367b3eb9acdf792e5a87d423dabeb5908566f19f4d388f6b2f1c82456e98a" },
                { "oc", "846342970faa3a4f108b38f58ff9b078c94e8d01fc604bc645ca2a7699d09b54f1a35bdb4d080d472eb7a7bf446e407de1d4b9bd81d84ba930d6618399c5c54d" },
                { "pa-IN", "7bda03788ecf46847b7b6bc0c46ed2e5a4e7dddeafe6ce21f720404fd9c7e9f6141e3fec8e06d5a615e865e5da825e2d20915da8035ad4ce7829e8508ed75381" },
                { "pl", "00fe9504b23e2bf5af635a3e79e9aa735ba32bde981e96e7857f4cc901139fec90cc27d2428570187a00f2fd87c7697619722895b90d2da920af152a9eedef37" },
                { "pt-BR", "f7b10793e498fda71e409b34d5aa63801c66c1e007d7f9cb45e7f9780a3b79e85e5d93f853bb92f11fef108f4c408c2cd48a04812951a55254868875df175d25" },
                { "pt-PT", "649249e2886f00240b9079af0842ee1f377344b890e9553bafdc38bc9e6090fd803d07eafd85632cb2924c9ed122175018f3498e662c3a3417e950629c62d4b7" },
                { "rm", "1eace53d19801b31c5978fea244959b4d93e4b770bcfef43a77503a2b617212009a4549d17b2669a448262ec3b53932b16c52d1d9103ed9f668d1d5e08f23250" },
                { "ro", "00879ac7acf6892db4130b025820ec721342867f1e90d6245f0a01695e340cf95cecbae5f8619cae6314065a38246d9c3b0ffb39acf9da8148e60f7edf982669" },
                { "ru", "c7824eeca4e61f2478f0d519e6ec3392bb245d37a9456d17be378302b42c1a6154b019b36a7b623423347b500bc5c272e001700c486eeba1fab2f982e058b15f" },
                { "sat", "d4ea741e4172c50b42073a70bc45f414a95c3412bcf7a6459a1218acb9aa55178afbaa6bdd1ab2411c0d2a7031932a0fdf9b49ad96d1937591eede43cee83690" },
                { "sc", "90033dc4c5d75fead77ba1a9a15d08febb8c06f4c5409cc17b720ef3c57e0e1b8e5146b1511c57e11a4bd2ab9b8e30d145f2a9289d45de332462cd753c455df3" },
                { "scn", "9495007625ffd540fef5b2e0cf2cd2dbe78c14f0ed2bc8ca3e044469fca3fbf980720b31c9eaac070bf336feb2765e19ad9b089f13a91a63ee3eb0285e519b79" },
                { "sco", "f7f7e14fe25f02115abaf04dab2352008ab942ee814cfcf62875f53f253577670142112749da23b0b71829ee2372c2015ed07043b954d94ee97d2454c3c749eb" },
                { "si", "3e4d12d616cffde0e4bcc88efb98d84077bb4194ef17db44d1766e250c35c32bc4b134711203221556182854f726d7ce1549e0bead7c4689cbedd153d86b31d6" },
                { "sk", "78922bef0017b7f3cf0f85c1bc218653ca31849b0cceee7ad1da80747adb03b486f3bee87460149e74439c5ea95a3cd9dc3abee7a97915c58b133f66c8a28d0c" },
                { "skr", "cd47540c942e8d7867532303493b40d1b6bc8e6978c623db4049ef406340d5a77eaaff29abdbf3994f64b8f5c41da90ab6cd7c0a4206f2a3a7d9930a2670aea6" },
                { "sl", "12fbca064a8445ba7f1568584ac170d92bf4b31dcf1c2b7c9a8eebb5d33783ca390f5d6d9f4af214cee203c1d2851d475f35e6d4ecaa4dc93f927c61b546364f" },
                { "son", "9aceac5455367785171f0899651c4c28e7d6f309963c79ea675dfe1bc6a4d18ad1d7679e2dd0d3380ace4df841c8ece72549e8d82737444f2d240c92084c93cb" },
                { "sq", "2d2ed621ac3cf2cc90203cbc987056dda01737c962a6cb3b044b3c29dd7f84f76baf9b9cee1c3eba1f6a54e44abf838ab1a7020559639138ce4cc02706547b1a" },
                { "sr", "ab951eebca2abdeb64a7d088a549bb380f94d6876e22c21306ffac130fda44049bedf842b6963f40eb2cdd2824ad623b8c1c26002d7fc8032b1287d3380d6098" },
                { "sv-SE", "02c561c6b52afceee8eba307e42ee6029fe95dbb46ac828c83ad83d1900bdada9fb846c2397ce0c8691f6dee881a1030738ac0e7bed21ba72df0fe04f75c6fb6" },
                { "szl", "a7402decc56630e59762dad57d353ed5c6dd2e7edb460aebc7d6e1b1d9b1be55b482f58e079c79eddd6bb2826cb4dee4407588edb3eed65d0adb7d09e99128c5" },
                { "ta", "5283624b77ed772e7b19c1301a49c3aedae18fae50b99929769cd4d94254329a4eef2a8de10d4ad9c86f9d12f695dfece9561fd764cd5a288c677e8796700369" },
                { "te", "3be5b9aae483272d1d63355189fbfba5bf1173f6264e5eebb1441b02977b4c5966fff3afda076cf25a2b22a64a790693263fb59362e607cb4698e36a919fb0ad" },
                { "tg", "da635a6acb36a4ca99571016ccf70aa3ebfc7600fe558c0219dc78fcf0ab861b7b09e25a2647ce065c413b605f1142286c5a18a3cd6f81d56504aceb94766b88" },
                { "th", "e8611dabe5c9deb685f595e77977226d3bb6e66bb1b01cefb2f80f6ffbfc2ea7784e25de49f125dc1a16e96db9e326b8f325ae1b3fcaf46baaf25046acbca531" },
                { "tl", "7bd8a08c40e9ac73313fc20bf92450e2ce7bf771e0f71552f9f5073341b9fe5961030a486d7b72b17eb2fd3a36cf48a3142985999f4ab3165f812f3b0d266bc7" },
                { "tr", "3a109fd3a9120387a9bf9d4a563043aeaa100353c20bd5291ecd7aae5c4e2ce3add32859792cb0381fbb7a732e0106bc98c9ac23d3fe24bf54f9055e5591c880" },
                { "trs", "bb38e3f89b8c45a1960c707a2ff774f2f32c7ad61c19c07c25b18fd758238a6c9b4ee7ce3adefaaa7038e37db543f91512f48c52f423d28f01079d3376de4060" },
                { "uk", "3d00f46dc407bb53103d06fa5dcf671a597c163b3ec8f47cd57605902a251331b008969332de90969f78158c75f42ee7f1a51670441ad9c36825db66ce3fbca0" },
                { "ur", "ab2d2bf80889ce3e6b43d3635d3b4090dd48991abec84bbb737e8810beb0bcc221eef7f51994c9f9b931832c4b3aff990fd95a22d11463e56871f9e471f9cd8d" },
                { "uz", "42e11e94923bd4be5c3064d47175d8b9e4b49e2e50a8a92f1f60377823643090a5c784c3d25b36c4d6a92fb9ff61da74114bb14bf7c9e9447069055ad32070cb" },
                { "vi", "69a2f04acf05ca78120a055f80304031d9db34f285693ed29184e52dfb2fb861a12ce4b3410b95493d0b3ddf715cd1f0038067502978a48b7ef22b767e8dcc5f" },
                { "wo", "f0549dbf856c9ef94d5b1c911de7319f5c9c8db95c8980869cda39d7c3e0d4351b034fcc1218b1d14e066b6ceedbf88f7d965bc6315f8786baffe966db4b338a" },
                { "xh", "07b92e9aae118da2471608cf42d1acb10d6a7cc8e1c4402d78f26b482bd16341361e19f2da51f36fb43f600c361d509eafdc8b36cfcff3c3f11b0a87cc96761f" },
                { "zh-CN", "a76c951ad1a2b433b1e7e40466a6a29377fa114f2eb4af72d7a6f441f82b1d8eed27d4e698ebc2635aa86825c5256cb07e65ce6ce46add3f3be5547b485a276e" },
                { "zh-TW", "26ab98af11c349640b8395a91b44edf74fa9c5110692281cbb3a094e3a27f148c866b693f3261e2b5c6c8a50477171df6191b91c1e8fe8e8633658a7a541b395" }
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
            const string knownVersion = "150.0.1";
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
