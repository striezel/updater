/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/91.9.1esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "84a96ba3cc47c6344b293430f8e5a19cd255424dac52401c62528f76b1f28f63a969709b8104b0587bb252e7c86318b4b36c19d43f9234051c521844f6eee2c7" },
                { "af", "fe51af35688c09bd9a8d2ad689ca4b7981d86677eacd20c8911451c6a3b53a65dec7bba4bd008f9b3c1fcaadffc6585acd992b1f3f4307f011ba7d83098ef23c" },
                { "an", "a005a6c33df992879111b291a705c38ae2427d6895cb3280ef433897f71b5f86784ea6d3168c5e57fdc52c3fcf014f56ac8a1a646c74da4edc807665f2625a35" },
                { "ar", "d37592dd42e1c63fc2edcd4ec39d61bf05440a7e07cfc7458d2c3103e17925adbfbfee0a55eee9d31ded4508dbd8f1db22c4030a0838055da6daeeac29143637" },
                { "ast", "922a53bb608b6dcd6a0abb901ef9860d4ab32593d4be78542748d8a7a1aeb611b964a810bdc74585104932517996922070ab795899007f08a3554f37bbf77573" },
                { "az", "0ab0f22dd1b43dd1ed7af8cce67421765e0d086775da34d4288a35f5cc61c0024e4dd9bd2f1dcbc23c4b694a78881c3d4cfd4bbff64c0064652ce0654ef1b2a7" },
                { "be", "0959c1581b4082720df026ba1abf6a1bc4236e0a60a4f0e06a3a062a9a2a418d8f8d5d11bdd55a930efc8c9e2051d170b235c3429dad909c76427e08f95a57c3" },
                { "bg", "84e5b2c61a5af19ab3d5f38c5dc47eb453260babe1d93a1ae0a412f5cab4ff2ee3f0b7333e078829d5124b9a6d269ff34814220a3026834edf73c98822aec730" },
                { "bn", "8bea18db67c914770269dcaf436e439ee5eb6d1a7c4e7fc89abe3f8b8a042ec91ed5e6e383691f89997f3a8715adbefffb34f473bb5f628e482514750adf733f" },
                { "br", "81ce1b880d9f5ce9c88ecc6325c2dd604bd604a277e0b54c938a0b50e31cd7cac340c73b80ca28b9dd4e86e2ca17be3d9e8679602b89ba5b73f553608a061fb3" },
                { "bs", "8f11cdcbfb9b34462a558a3734f93caa8769df0f30aaf8fe4651827fa9a0836d106cc26f2b3702dc0dae266230da040798d6bd43ec83938aee471d143054fd13" },
                { "ca", "07253c932f9e82bd5c1f37f2bd39b801229f2615bfa4a16a3e469b9cd2bf84383a854e992e8c8d328d4bb5e9366ffec1438a02d4d7125c9b9411b29bfb2a3e48" },
                { "cak", "fd4ed8adeee2b172a2070ef1c441a2a753aafdc04e4e3779d46e2d18adeb49a8df1e59c0b98363f48511ce68d8e8e60cc44bf0b9a46b88105e24bd290b6d6e4f" },
                { "cs", "9788aab547b179f5694c87cac4f0005a0707c40fcfe464e73576ce901974efd1cdad5cc7117d2b6a534352245c293208006df839db07e72cb542152b9055efad" },
                { "cy", "a2180bcb139cc424f95e92af40579a0a53649a55d1d47304e9cef4983b4440807c3b5c2f6db61f8a34ba513648bcafe9def62dd88340661cf64315f0f4a6a34f" },
                { "da", "e530419a9af66959dedb1aada8ed66bdddcfe95520cd71cc2769d79eeb1b804126c87d80f8cd04a1e556e9f58258e3c355d87cb257eca0fcdbab70556fce81a5" },
                { "de", "3e6ead53e858fbe0c82449e63bedd012215a18285d5a2e968788fdc3c947be7569d9804d0b21437d781be23360b2fd525faf4a0d8403c055106badcbb791a276" },
                { "dsb", "bed9539889224f038601e851b83532e04ddfbf72fa638c6982c3f2454c085f36d49cc75d64fa4a6d1bbae5ad532d3152904af8e15b48d7464cc3977a29c60223" },
                { "el", "f8939d94071bd845d5ed5915ae8b1cab2b0e696ba76a2ab33a35d4e0340ca3a00f2947264a9c586a63ef6e08a5a469290c837681c528583751a34e42e07a1402" },
                { "en-CA", "3844aca8db09486f6db178891eadfec3021bbaeb2db39e30d71d3c12a62c7d968712cab35244ccbd9291a20fec83a0a8daa59fd621742727f4fd80f90b58a0d7" },
                { "en-GB", "642a56dff5e03a03186f260164625700f7ceb204739051e8fea69cb68917eb5477f9e2665ba4b1429c0baa1c48ba86cbc4cb2d1f59d65a647d6496280daa10f3" },
                { "en-US", "edd52f125fe3d4d717665aadc0e525364464f03e9b280dbb96384f2b8ca4170cf9958d40efc290e2eb269553e176ac287ebb22a009112edf0b8d6665e4350f54" },
                { "eo", "fd6ad186209da0897a5c6885c67d7382ae3a59d5be59e9cf595b28f192b0e83f6173a7eb592c6e91a8755f2fd947308ce93f891d88ef00e63fa147735806e8f4" },
                { "es-AR", "01d8ef3cbe01c470c8a4fcca78a8e3fb1a28bf3505542b548cdb6ffce69f5744ff6502a6f21eacef43064ae56ebf90ef24fa9c65434527571a35e369a125a577" },
                { "es-CL", "cf9a2cdebc82a19cb59fd41afb2625949f6a156c7a65ee48f0ade1142fce3888025672079ce8363f534ef096b91d35b18db04d1580659483673978ebdb6b4004" },
                { "es-ES", "650bec289a3a13223dec62abf040e7a6517ad844104187416a3a65d428a61fd826d9e3dae64d95010f9dbd521ccdc4fe7cda71be5dd95dfd1805fb34dcc1c0d2" },
                { "es-MX", "934ce168ac6680a93bb3dd6bc75c569f857ec3bfd818f2cc2243a3adc2bc8d9d4f81854e7c96d9bdc578d455bd4eb50c5673762c734c8b3ff2d2021c9e916a32" },
                { "et", "dae7a6d7c6938e17397b0fcdb82a43419fcc66a6341f6f5cfa8fd8e42c49d28acddf07acb92f7542afa7bf64dd25d26c460462e671b8e7a859148992833a0329" },
                { "eu", "5eb2ce86dcb302f40f38c021012335acceee26b448f37795a379e9f20b9c789c8a947fc2bf5cddd093b416912e41fc080580620f23dd5d5066ebeafd95d12fae" },
                { "fa", "b6799d94f6c7ee3c7ea790c7eee6b8abedfdc89ec1c6402aeda44112a7484e1f29f0e3129d85174f13a1355025807bbbcde7069d9fc518ca2c6ec1fc6df381cb" },
                { "ff", "fea6c34ebf221988217cd24d5d85c61a14648a506d48eea98279491774d89d5c81513e9715b2db6caafce9f01b001df5d5ee68029511ba9b42ea89945bcd4331" },
                { "fi", "4e2beed0dec21090a999cf014ec6e74fad029558f37510bcf474981ea2e26c2966aeafaa07bff3be95836ed632763083d95738967060c52ef8d1a3510cbe80d6" },
                { "fr", "db3b9c872213d5e0f4919a364731d7bef75ed260779b13a08af85fb21bc6435f8f54bbfda49a4748cebc960a3f0dabeb8dc163f44b754f3fab5e797b9f757882" },
                { "fy-NL", "a78145ca0fa54dcf9e81f04bc122a4c29726742b8b09730132a86a454bdda0b5e52df32dabfc98f35b9fecafbab6c30cdb1975a0dc085757135b0e2cb0acbf73" },
                { "ga-IE", "9e5ccedbcfcfaadfd2a3aa00788b3228d1ffdb0e44b2fd72cff01b67f7a481e65b9a61e242db928f73f9ac1cdf8cb580e5062eddc09549501cdb97fce7247a82" },
                { "gd", "7bd2f412a224192901223ccd1626c521798ec0247ed0a73061ba72af146d8a59189376c2162ec0b34da7fca2ba68858e375aed703016ed7fcfe56aab6bc1e45b" },
                { "gl", "6f8dd4dec2c4b9d2ff51c68ca6dd5d510a7e5dea1ecb07efd378fdedb3c17931ecd34168720fc6a76dc321da7d5cc8291fec8b05524927ca13e3d6765fd597d0" },
                { "gn", "92d969927b505d43b196738f937596a40ce1b59f95868962e44092955ae51cc540486b7392fbc92e89382acb4d40f4329f4d1c38c63cd56aa097900a21bcb2d6" },
                { "gu-IN", "6d73b35c176de4f698c060f35de77d75e7e55f23985c7f698d0182847cb5726dd51654e35c532b3a3639f5d4cb2251ed225009d716854eb91dab4d9ad9c01a5e" },
                { "he", "fdf8a6d6aaa60d1a4e6e17a9666e28a73c3b8b2ce2c1d1c0ef112b9d9579b21e80838668f1a30af4d774419047f02670d6c03b064969b88cc40dd9ce8c739f99" },
                { "hi-IN", "17a5df56252d8ae2dd846c2c1c3ef4bfb580c40e79fbb597a7be80f8b3990759e49aa608580c5a06ee2100112d18062e3d64b527adb8fd615698d45c69a0dffe" },
                { "hr", "e3032738229c75e0c4d8186fbded8d9a4b99c33dff2f5bc422288295d6c86a7e934ce5506817d6868c47378e6c10be7bf807278c2e36d67d3c6810a5efeab435" },
                { "hsb", "1bd8e3da634b9cc1070a6d70b7ab24ab87431cdae9b56e909e43d593667711a5f08333dc097e0dda05ce705d3a9e3cff821999816b6c604c91b784d5aa0fffc1" },
                { "hu", "d731357aa6df600f846d11f553f3d6fde39dd17ccd1592bcbe0c97f86f6a2ef4c5f52be061294cc6b78fdfb56581ae121be3b2ab9799bd9ac74b69bdd742f3cd" },
                { "hy-AM", "a9aedea5a2245a17fc37e049cc7211001ea57f120792a42d5b7d4f59deff86dce1c3eb4d5ad62208a34e1bc73f4f8f9b5774b07e10f3c6ad18a42a8ca0864577" },
                { "ia", "767e71fef29cbe87ebf03c5e9cfb814c69e3a220249a4d8cad2678e40f9f96d85a8a481b7f4d539d940ce03fcfbccb0bce01cc5983d11c3ccf116a59e42afe0c" },
                { "id", "adf0fd6748a5cadcd92b754e389eed7b226453e1dba4dd22d24e12bd269e72861be10e57284caccb0af34ca92146c67c3b45e364c59a8d273767441f6f343472" },
                { "is", "50b749227472890bd2315cdf72975489eba3e617a117b0dd2bfc0a587721f060b343666a2abd4c15626333f7b5b725d74841c4cc9c9af2132d6026ef1f8ae47e" },
                { "it", "0f33889f3ad34971f8533c31a1b2c5890700c8f36cc0b166fe1a2ac752f83eee6eec7fbe676e23bd4bfdaefc83dec25d69f86a4709024cd071dabf420cef9770" },
                { "ja", "3fa3628f9c8d19fb44da85318c454c7dc5d67cea2f209312e67f2b4be6b9b158b3c9e0c71e2e3e674a2e2d9e5eb014cae09f98b5be97a8ff61879480d8167f97" },
                { "ka", "f299d1a8b5a65724ff0b200b66bbe3c880933ca7abe398e60278e1198e80401335603178d1d53e29923ef97d91196695cff457e6aad831c91f74ab1d729746b7" },
                { "kab", "7e18120072fbcc7cb15e2bf2a0ed34a0e80b593ca43626d1b2440d056ac9f1ff79c1c702a40c73a1dd865a127f8a39239ea24bf6240f9e3f813303603d892f12" },
                { "kk", "55aa06974a90af467a540252940231006abc9b17eb3c767b67be511e6941483b5cb4c394c26e2398107735a956904a526d84834c1953eff6423f29cf026851af" },
                { "km", "7722814aad2baf1e846925326462bc3ea13e9ff0529e8aa1ba9a3aa087a7ca97ecf6fa739e5f8a0b361d08f49400cd12cbbf1b819ce92999b27aa6148f4525db" },
                { "kn", "17a0cf53d5b43d9601f1074202c15bb8e7f5151768aab8393eb269ac40ea9c7c65df5771775e2a0308c53868431c5cdfe2a03a6fe422d77627daaa3b9fd9ca3b" },
                { "ko", "53b777b9e58167640c98fecf1e30591336ed66b7253a786c16465a0963281fb8bb522141e89892eec9cff8ae5366f30afe93b064138b59ede64842d0126d915d" },
                { "lij", "73d530af6ffd403060a73c27dcf5db307b66030d6f83cc9a4f2ed1cd8144e5b8d92c5158cd4ef63612681f4d3ded7d1239c4fde0de13b05e3d429297402c87a9" },
                { "lt", "8176a1cb012fd5774d09fb314e0e26890dbf637c7ec7626046be1baa3c2b2843d82942c3f740166510d325899e534feba0c65e43a1ca1d4b03b8d62b3706d4b5" },
                { "lv", "ab48b7485f508628dc6630af2acbfd6f1ca53674c00f96b9aaae9d06e2afd1dfa3aeb0f32659b864fc4ce2c498f3bd434b0d115d7c7674db8001b70a72f01648" },
                { "mk", "d51850f16d0ccfbb7576606be797eafa5093354001cb6d9f53f33bc7fb91d89c015526af9c022184a1f5a53d1a6327214c1268023768c0f0674031865cf1286b" },
                { "mr", "6eba4d549bd6fcb5935087ea67a3111250a814179843b664498a00fcbb713165ab793393afaf0ac1ecb225d8608d2a13d20cfe0f6c14501330ff9a1a63351d42" },
                { "ms", "037d03aaba6fc60136ca1073b3b09ca7b2779420c1932712f617d0b22715eb69122e2e769043f540eacc80e53ce2400a6ffb336f5026e0ed81148d48ea2786e7" },
                { "my", "58badc1f792fe95f188896d65c31bd27df29d8896ac056c7086a6bec0059b0908b56a6bdeed6db614a4559a5b6b11fccf70a67533f2c0a3d737a9588641de955" },
                { "nb-NO", "9af4ca28c2263db073950a8371f35b686685363246cb0958c2ce00d881e023c84a2d1f67d2da77bc42ac498a4a3ee57be5321ed047509a2c7f68bd9ec53f843f" },
                { "ne-NP", "2a6760faa311764f4d243900d5bc73a07e363fb1d7a56e26cc84e9e736fec615beb6c182478bd3a0d7bb562cb529ded92edddc87908bdf64c6a6847e5c8b668b" },
                { "nl", "2a42c56902f935c637faf122fc0f2ec1df3f75393cd025996aa6af18a4aa001c1d8d882cc339705f568c276477194c6710543bf2613916d83b23df460660ba50" },
                { "nn-NO", "1fc139b367e48ae361f66ef208e70cd0797beb128ebfedfac139cd86c78b9368db9336513ab4c2b6d1451361b979fae169b1cf7f2cdff0bbbbdd278879b0644f" },
                { "oc", "a739d765fa3e366499511368aee30d320ab4a0349f51c0986ecc45a73b1c2263f0f397a37366ca5ca3d9c9d9d9987fcf53a282185f88b06f94c2230b76579568" },
                { "pa-IN", "c18e6190b485edf71794e87e3cc73bb16967145b9cd0055f4680411436228738f2a6600921d7b994720d3973c2cfb80273b6fc3b6ae6a5449f026a4f595aaa52" },
                { "pl", "7317e6319cc3ae2fe7ca21fa69649fb54821db3f4e5f7d0219eb27a4b06675491673935c2e5474d652ead57be02477ffab597d43bea902767cc3348ff0f8a82e" },
                { "pt-BR", "6ab8e8ffcac8ae970c88ea79fec72eb2acf37b3ff005e8069f34d92457f2b5dd663ffb5893c9e6e5b010871b4b3cc2aa1d24bc04e3089f6a334481936cd2f81d" },
                { "pt-PT", "cc6b85cda1980266c07ca988156b428cf2265b1eab5123506f25038c2d93a64cc5101bc4402becbd41bf64f7aeafa250ff21cc3c9ca24e863a12cbc7f7bca64a" },
                { "rm", "e65476a7ddc97c58da5c2331be0d97e84bb1ad0d33404e2c560cb7fe964b1115fc22a474006602d111e82a2ee6b64cab9e4121d4a01e867a4a4d2ce2f0e614c3" },
                { "ro", "76311240159f49bd3d1e48dda28091ff6ed0e32bf521585100163d153e4161a719567c010a6f4d8e29d0ddc4b6f783e0587cc1c9f8829ab9bb15ff0e14b2d084" },
                { "ru", "fea20d2144194d8da4b47f8080962e188bb0b6dcc9f7ae29ff13b66dc287027346a46e8281149ba12e7639631cc0be2aff8dc8b8b6eae271886559594f09668c" },
                { "sco", "83283bbb736a3e85ab6c58792f7d4773f5e85fb9d4a7ff0c6149de7c13f9c83474931ef4c5321526fb081ca3beb40d4e2e5979b99d57eae2199c239b35df18f0" },
                { "si", "da277d703e3a69ecd7456bf97b75e2ccb984e755e7c8d07e053927f369cba776905142a552fd8212f2662dfa72abcf9af84d08897d0e1b8bade804a93a81c07a" },
                { "sk", "f4e0f5cc1dc6a3ca06c4054d007da67c4277e11b9492515875abb8f81a46fa7a76c6735daef7e25c6756345c28d314b6079a6fd04c5dbd5b5f36614dfaa6f894" },
                { "sl", "a505b7f8f4f8ba840a3cad1637c7f19640692326470fdc5266529e7b55f6b3d4226b6f54ca6af9d89fde3dde00b629a5c276aaa023d263d20b42cfef040837d2" },
                { "son", "559ee36afa198daf2b977391a2e7d0e9bbacb4dbe43da5879d9eeeed3c148b26e3780cc336cc0cf4ba6a0eabd6a658deff807cd0f6ddd7391526401fa592d545" },
                { "sq", "9220924b7face19a9fe99f0c849fa2f057b10926aa35533e12fcf7753262074d38a4b96f70ffd4d4107f8b56599f79f29080194c1c6a07f6a4e848a5d8d4c305" },
                { "sr", "e32b996d47b85d5321a3b868f602be15f048db3cc361186cdd9073526363b7df1903ccb2f9425f9938cbc4721d22bb042e288e9213bb3880d1e3a890d5da755f" },
                { "sv-SE", "d04383c1ecde457e4e1df074c967bcad21e3a56d607b4a8fb8cac44e889e1dff3569e8696c559006dd61915a9c013b45016c5e496917dff2acf099bbf10ea476" },
                { "szl", "eba9f1e685bb69c3fffe05ce6270a2173e9bb84b49fe976bcac2023572a023449da33e23d76d6e59c9f7d849b28d6778e0293be3238378acafe17509445105fb" },
                { "ta", "038a448b4891d4cb3e1fefee49e00b4c4f14cce2651048641dd5d68dff99f930afa14398553e4f70c97a72ba7a481f652e764e1e1cd682205ad33248b1005ff5" },
                { "te", "442c64423435a73b49cf2948fe740020a2b5cabc589aa95ea81e236c46c67e06e8afc84ffcc57f60ea901f7b70b31a8b61cfff52d427ccabfff67b2f34ec7648" },
                { "th", "4717d030b0e3b8fb76ce13a77350207b8a2cd8668c5ed6d162825eebc08e8436c898ca84b7fef93b9c2abba8813e55fc0b727309c81e6a422786b069542d3edb" },
                { "tl", "257e6acc145e2aa5f9fc07583b23784cd8862e4ce37ba53a8485cc51043035a6f3058b35e0cd82759681299670d65fe7767894bd4b5388d395f339b507f2d488" },
                { "tr", "b75d0bb260082f65a910a46fac1464ffbafa302879e2236a0d6f37f456d9ab4e26ee55ec3c5aef3bc2d41dc8d43dde007bfb61c0c3d83d775046352d644d2d7f" },
                { "trs", "f11f774228d5f442ab2060b536a2fc6c056f05ac45c9b67a32bb99cf250579e274cc796428609b516cc79adf90280ab11e585f496cb12dc72068a6931fce474b" },
                { "uk", "7c1d03d7d5ed46f719593190c3cd807a98684d948a6b02d8daf40978133462948c16eac8adb450ffbe29ddc89dd4036023e9b8726f6204dd04a2fcaf0ea4809d" },
                { "ur", "8dc02beb0ad405b75c26db74c990db342969da6f751a0b0e63c994ae1a3dc4bf5f92c73d832697da70d618ae81159f951d632d9322f150b291b2698dd756f6bb" },
                { "uz", "6c3f8f939f2741d6b36ed2d90bfd1cdb8afe968dbc8b3a80b82a81bd9cc6f51d7f1e2e6cda662effc2e4d1ce3a1c64d6572dfca99a7b9e99c900f7c111151009" },
                { "vi", "4020a9e00988b577a09bdd7bf2432f3676d07bf8ad1650a98f918cfe5efc3412c9e0eaabf75395ccb3092f0e3540200c9a728820af7b58c6272700fd9840072e" },
                { "xh", "098cb268d00601faa7dde8737e478cd8d3a107b1a6328290e7ca098fdf936d19b5bd6d454d0843d6ecf7550b18d2d0c1d39f797fa0f764195fda5437faed9232" },
                { "zh-CN", "0021ed99f0d2a867ca226bc67eae812ef7fba98bee220233bb02c0900d56b624241464989cd20278cd3f17f4df7d55b73552e40a2109fd5a77712998cce1b877" },
                { "zh-TW", "66daaf5ad0b2181403279ec74f49d21d8ef84f7803e16d2a5711a3cd543c3fb4013d737123ac3e5767e3ee02f6d43206b4ef2c7eb51d71aae05f69c4678779c2" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.9.1esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "b607a038991566d67b43e806f80f5a57dea4edc7f32238377e41982eb0cc791b3d01857b0b2162c482bbdf08506657f2a508226c00090efba62c00eeb3de9f05" },
                { "af", "ca3deabec34c4c6d4cae0602114250d11e48f477fd58e8f026f4f10605d4def84c4202b21be47ed681c965f2518217fe9a4007da6a41d2eba94dba94b1f060e0" },
                { "an", "ef49193a07b278274566545eb45eb5cb112e3083c8cc19bfb5da287adb2a10357b1244aa685631722c4a06ab9762c30b33e1881e2f1c76c04ab7148b812901bf" },
                { "ar", "851184d894e0a953f6f04eb8d974dc830e8b3de5eac7e4fca594bc0aa8da0a65f0382a196035b81bf643d506937e0be6265cf2e32370c97fc585387bc87d92fe" },
                { "ast", "652bdff9636ea8811e056d5a83a7beca9086a805460f916a2ff2064e2b6dd61457c2fc17360bbaa5836cd4d42d2e23e8251c476ec1e797911ec43815f2836366" },
                { "az", "374e28ca50fe774331153fb83007aab38988d2656172a7b11e03ef86e3422de019f3b08861fd0f020e291368d4f91632fe78bef0e12efb54a1ec36754955db90" },
                { "be", "68aacdf0b01c9ca6a10533817f83e94b8d2a15164df58991efa41903b04f79970f6ff23cefed2f305bc71f0292cef1d90e1edca23ef8bead0ff70dc0a4e68c76" },
                { "bg", "6c9ec8dadcef488cdea8ca848dfe7ed564e7031c59813ae1a728025e4f5232fa1b3be41a6327c2169a5a90640936ce1d2d8935bc747b0d8b7bbecb73d2b7455b" },
                { "bn", "4d9e80f4055b9ca17ead5273f17a810292fefd91d5e54c358fa6e59b365354e6f7bcef6beae1527e27a8e547ba0b9094482a2f69a54fc5ab9abdce992c669850" },
                { "br", "313ce7b8c0f993a0d8a2f8d7b74a3cd249309f23982a03bda1c53bea4c63a19b8b253551c80256913f7a95dd12788c45ad5f39b025b30956f34e1cf2bf5f5b39" },
                { "bs", "13843093ce684068c3945d9224f91d8f024c8711aa55bdb0a7d3efe4418204e509d016eaaeae1252cf529fc0c8ba72cfafde321030e0160e47fabe1af50f989f" },
                { "ca", "d0069f6fae9efb8d1e70e2f31f81c8bc75440ebcc5101e5f9aec1ac407b4ae03ef9fb9b2a5f35e34773fb53b1012459211e6bef0eb1aed35cc5d95c945bf52e7" },
                { "cak", "0837b4b0327719e6258a176ccebcb9847984c86334bcafcd8ed46392ab8154cfa8a8c98eea0db60325df029a036bb5a8db02c27bdd697c24e4baaee39d32a2f8" },
                { "cs", "364c4c1c271efa96dfa7bb7099958ee3fe331e8805766ef444baa52f38658b153e09a98f6d24e1291656f482b8500f01793853627316e5c6ad57fc8e0c74400c" },
                { "cy", "de026383e5f59656f11b3687398e241f0bf9a495a555c29e6eec466bd65dd49b4180539bdcaead19a37cd84331b4b22a7f89d8217fcd36c0f5c8c3235fa3dc8a" },
                { "da", "212c73c3bd5fb093d413f8bbc61e67e8d35efb027f01e19f7a4d89de387b87c15b96b1e5447d67e8340a8cda2d90b361a7a5a7df0f3e594beabd3124d8f26bfb" },
                { "de", "27cee27e106e48d8a4f303aca728952c08c3d653f01c4cddb0ac2f9eb22876d52e3ed6e12b471db13b4e3c6aaeef5cb2d8040037af0a441c904be1795a78713d" },
                { "dsb", "87340d3395d103dc8551119d0bb52b304bf77bcb1a139ace2ea175815015fde036185d4cdbfdb33f4a30e1cc573dd57184556dce4c86e3650b916a8a512ef2ec" },
                { "el", "097bcd1e698341c2db7aa1f47529630270b465da5fc2b47e4eba67a4bdc5a98d1c1090476b7a869e30262fbc3d0954012b558495b68c2403c3269fddc8c9bb5a" },
                { "en-CA", "ac5040b07e2b105f3c7e28bce8a757ead0269d564d66f4bc850d9091cd475a5017b8c2d9a21f9022db89375531a8a509b75cba54f7d744e5846bc936670d0d4d" },
                { "en-GB", "acf88ca4ffcc30a2f0e9496aba00acbac45ac7b9f2534efa754b31ae0a99c728e0098308b8b2eee18d7925c763b09b5c1b2c764bff7a345b9b2d66ba00de572a" },
                { "en-US", "e279fd0ba3c2c80a8cf2a986ca1b8937ed655e7e21b4942acaa786c2bbc0f2ea4e03a03803ee1fc3cac91759bf93f61b0b4237c9d6c097e2d5c7351123947fc8" },
                { "eo", "22f40820a00b17bd6eb7d03f22a51a8ae1b45babb7f71baa3c16c5119d26d75c6f75d5703ab3a4754fd894adf14ad95405d2cce2e5b2068af1d41e6f566890f3" },
                { "es-AR", "5aacaf5561909ffff06bd5b00e0cda0ec836dcabaff2851c8b06a99a119422c3daecdc3e7b763fc9abb6d9dac9adbe22db09e98421f1499647e21df27fb7788e" },
                { "es-CL", "5bb3117a4f3c1c138497b3d7d2798e785d322d9aa6f704cc73e0d385791022a647c4226590934122054beb9d93586e34dcb02d8b94cbfe3a2e1ce8fe4b84aa52" },
                { "es-ES", "b2045afc94de411261e9fca26894c1be21815442fb3caf918498c60d756b32a5a2f7f53592a1eae3f4ef95e62e3f95d01c7403eec8d245b97a8aaaef4d7f8ef6" },
                { "es-MX", "67532d763525b7bc3a1fe0479cc2e151944990bc1f00ce9946f2348f84de02187c1902a57d2c6cd0dd745076dfd5101c31f56ca8ae4f57631b7ff56298976816" },
                { "et", "3ae3d376395763d072650b49dddb547e7b945b79e2f1f19ab720cbd0fade300b5ef24435a55a753ecb33ff65e561da1bfe877e50bba9483b8aafc8345936f8a9" },
                { "eu", "679aed71cf7914c6d60a83adfd9fc9ddf541bf2762c58f95dee6afe7dd9413219dbb46de2ce4fdf3b0e9b9e569e943d32f46d256cd7a42945ca1cf867cb88c4d" },
                { "fa", "dad66dc0f5cc99e9184441d488c2e1858a3e1019822b5ebd8001405f9af1fb29a8dd39b50eea55974d520c2ad01f6b55251a67411a52f532278838e3e28136b6" },
                { "ff", "bd29b60075b0a212f865d58697aeecba5685343f57bfefc5e15ef0b61ed7334c129098a4110a254b51783ebff49fe22bde80c16f59188a88150952630c922e53" },
                { "fi", "d362e091f0e73ee31e6f98e7957b1e1d82fbe2adbe55022142f23096e06dec28e53af5315a02e64b90e3b05d51b99e0bad14a8a9605f7858ca9539a869bc6040" },
                { "fr", "bdcc62784be730efddea20581945a3ffc352007b3bda29b36c4c2ed3394697374969714436029023e99bb2e01e0f59a53a891c9b73627d5787fd52e6b6bf78e9" },
                { "fy-NL", "a3cf5fcf24cf73134703d9d2dac8b835002508b18162d647191cb456ba365f2a314e55449a04230d15460c47b4854f8c766cbf9d88189e4a871134b0bcb3221f" },
                { "ga-IE", "cc3cb7f9cca2f2b6c7bdb0152ff8bc930af3a3469705005f3d0f3c1fa00e7fac54e149b2041c7728e8d3ecbcfcb99adb5d21462285e6f305ec201b119ce91a93" },
                { "gd", "d77ebc6158e65e71c21c67df186f48be2fe83a239da98fe418a660199a06f0f6bb0134e5d330f7ca5aeb2e31d43826391d9fb1078ec908c308bcae13fa3aa28d" },
                { "gl", "39eb6566de699fcb7c7c8a83822d47d1a612cc52f99cc2d875c9e1bc12b253ea93998a27cd6f719bd2e8aea6d48f8677021da617331059d0e349c1aa927f96f9" },
                { "gn", "63b87549f5e562e9adb3e07c6d03aa738e6c9cc7bf7f5fccf48b0267fd93720f963205b2d2532731d2099441aa71e61c59451dc51ae7057eaae48d09ef040e0f" },
                { "gu-IN", "74e4f62f19d3e25c4ef1664fb2e0129e3d25c13e9ce8cb1bda48a41816d01d27070cad5da8686d09c064fd2a5bf3c827e50874e30b32893764efc2a38abbd1ff" },
                { "he", "14eef8d99f5b1c78ef5fe7ea6dc8e6b5d60f2b783144e815ce28063c3a7bb11042761cd25349b643025bcf8dee814b5087f050b011866863f5aae68b3b2cbb21" },
                { "hi-IN", "4f15326b82f1b8ba27b0ce91b03b3b5ddbdac91919a9fc79a4304ee6975fb6a86fe1ae28125775914136219c7aac4faf54db15dd0166908d8b892e6d75784aa7" },
                { "hr", "25b84b080fa1e40c6c6858357f3b626a1408c1972a98c3cc7a862224af02194ca69f7751292f4c6ad8395eef9db60c2275b7e80501a8132d80fe1812041fb3b3" },
                { "hsb", "10eae1ea7ddc0d2f801e528f53822eadf9ee3c9b9088e39ea4e7960cf42d9ab88ce103d64573c454054d4192fd58274fb8b280a5dfc47f18896286ee5eb9d7e6" },
                { "hu", "c28d1b4629c5b3a374f07526d53668b0030ea2e0dfc29dbc271bceb576b8025d681e8486c40921424083287efb8fd21a36075086f8f56e15f3f2bf842ed5c0ec" },
                { "hy-AM", "20a56baa18413e0f5b876dd95ebcce02075e5975fe395626ef70161210def90141fc22e412d1e8b07057dcefb472e78b8306371a93f451f77bc2e1e26f093e74" },
                { "ia", "3c34379fcf5e5c05b51f74886c44c0b229a6b93694d31ebaba6d25ef4277d51db723403039b5355567cecf4834fa7b13c9e1c6fd8ebc2c16ac3e480bbd129bd1" },
                { "id", "2b8e66099dac772e8ced905cab9a0611a733f30646425017cbda7b985e2efe7e372599d4f211387e446d910fdc440f0c8c9a180ab4c6cb5769f1f5df5833bca6" },
                { "is", "33e724f3d8a215044ba998c019ec5fc2e26dc33a69105b2bb11cf078bfc17175935c2d9ba507d9a21a44f8849390256df0a6d005cdb596e0738556474c394cf0" },
                { "it", "f79a9c4f48293d1c1fb31e280aca22bcedfb334dc6dc6c1285d5d62d1c2e367660a984391f2adf8d5e6b19eb981e5b1f6638df2c3b11edbb5ef713c2e4fe6cc8" },
                { "ja", "2f33cd19462b8820421efce86fb1d8e3017bb975f6af136ec8bb6fed865b42a59264fc1504af92860c4c58e65a590cf611a16b34c43291ac6d3df8b9f8564e3d" },
                { "ka", "67aabf17076042c31eb1a0253da6678fab3f34624c0f26cf517ad898aad7c24b965cf24d4faba977b47bbf233b0a1117db1cce55a209bc8b582482583e56449e" },
                { "kab", "93b260ecc507d0e07aa035685cb16b95d38e6ab13f8729c85e1ca0f7b59e958057fa4e6eeacc8da02dedc43c3ea7442db86cc2e57dbd1108b11969ae8ee0a560" },
                { "kk", "97df8c058e3b938e67585b77fe35da88b32420fcce586650602811a5d4073feeb8e66e5556322446454eae16fa10257004a37745f342583490a599310d4ba7a4" },
                { "km", "94c216aaa3e529eb87cda83c6a5891e8f447f361ca2ea53adc001292c847b981e6eefab81968c005ae63830e7d3dd86729ea22132103d42135502fbfa50a6864" },
                { "kn", "7ad5147c99e2b4478baff1e3894dd71a5c2d747ecf5019dd8efeb9bd77c63e7d25ca1b1ca95902c284784e56b301618d003ea4cd90f31ce2447b6a17c761c155" },
                { "ko", "4d2b77a38b4f7aff8396dec74739166793e92dfa9ffeca0aca9ec249f8db7815c3b56d42bebfc6b99697f90712baec462695e8dfb650e9b3a7ee9c6c0087b059" },
                { "lij", "75178f76dd67dd8e24675dc9aca7bf890f929eeb2803b8aa4411e9120202b69c11e5698dae131877677fe2cf87c1c23ef476abdfda2de9e4e2314030f5ecc3c7" },
                { "lt", "5b953c02dd1709c3d35371b262c8ff71da1cecbf99b1b57aa005b5ff7d0290fb2bb022d5d2682e313258e8edeafc3fc3bd5e08dc2325c697cbf0190bbb643d91" },
                { "lv", "dc34a348378c52e27cb3df0f11d8371cc35bcec9149fe6c36031f6073e96b1603e50aab1b55f183ede75977402ebc4d498847fd3d8dc58b0f1449e52a1880e94" },
                { "mk", "4772be9372c3c3410678fabc3d124388dd691d3779d74497138fde9c7bb704cb9c942df74adc7db4ae8f95d97dfdf002da51815fd28ce47d00e3ac09017fc924" },
                { "mr", "a5f4ab8136ea6f405418c928ecd99d51083ddd3817f1e6d3f3353b3fe5d9a76876d8933dd7fb3476088257b0d9b8e4122b82b2b14ea75566bfa595c9d50df344" },
                { "ms", "bcf76772f0447b464da6d32dcbe22ab8fc06d9d3901fc13b09db9e0b43cb923e3cd40c4aeb44885004a49128f09246ea62bdce5e982f2b3ece8650677fbba2ec" },
                { "my", "90c83359ae4832cf7edfa62437c0daea5aad712b1d09e48aaa8b3f2ef3f3472eaa64a5dabc5a79b0daf57dd28f35ae0638c0366c0ee0684200084053c0f215e0" },
                { "nb-NO", "ea750c6d2bb7c853c7af51a594d57b9ea887d22e375f3b1ebdc1b260dae56373555067ecb149ef12752b5e961034876b61fbfe2118f7f6d842dc3c41e9690f3a" },
                { "ne-NP", "bc7bcb8952b7f3c15602c3c0b5c776e1090487a59af96df0290577e78ef808d01b6d02b754dd19b8b8dad62237aca1388b76620136e499be9a303f04ec8d08ca" },
                { "nl", "aae203758353fe8291e3cfac00263392b85e36ef2996167434735a49b4193d8abcb2d1295271cb07ad27026117a0ae6e85f19295fe045d9bf3002ceef391261a" },
                { "nn-NO", "873d950d80d331db22629c03d6ece88e31d9d75695f48d4bddd899faf0a28d63dd2d4cdb49c21c2840c1e6d3b3c31869f8b24fcff0976d73a6829846410100a2" },
                { "oc", "843a9a876f24e50385b2e5e4e25eb8f97fab6ee48e64296e736ec2801881b3157a9916029a0754c4d6f404910f8ff648b5e0117b2710d7aa222faff31875d54c" },
                { "pa-IN", "51d6fa44a2911294204a8a592b2ed713788be6beda6252642276d4482e28e1946d19cb80e1a5ea6005f6bb11338fd59f2ec5063ce8acbce15be7df053c0145c0" },
                { "pl", "cc760a6c10691687147e640e753c0bc080e763c29ded90092251b432f5dbf0fbbe42050c5f52ba3d8afc191119bc9fd8e42c6868f37f984b15919655a5ff9c17" },
                { "pt-BR", "3e6699315292081c931c0138e37f098168d23d6efea1dc5cdbf11a529cb7eae57c25322a5d36aa64a3961fd1d58dfd1ea5a66c8ef87374b22950b36baa66fffa" },
                { "pt-PT", "9dc64f6cc8f5f0a30aa1bf54f67fd7cd41b5d6e065e7653bc68559b2cdf0e8b4382fde8552c9c9fb6706689aaf617cf80101127e39174fcc8d52e8051f442d81" },
                { "rm", "df82a8f2735211bdc7eb6f7df5f5bed3dcaf3441446c401fa4a44c6b075945232f82d2674f8bf9e242abd5d0db2c2aeffd654a1bb0dbfabb14c937efe8841186" },
                { "ro", "4be87f8d6262ea52930a01d7904b9e1af5c6ee8c5b0e957550b642ffb4a20aa1dd0e0ca02ed2680edc83c43d5d8db76798e3b8b26f1de3ec83d0154a4d15df80" },
                { "ru", "56d9b9a6d38fcf8cf593ba7993736d407bcdec0fc912965c31165f08722c054e40a4eaba8e01bb68319a5ce40ddbc702ca0792375f19e350b84e2b09750666dd" },
                { "sco", "04e51474b8b3f356c8433d2b6a6939d92598e64b77c72d7e7c84dd3947eaed6c4c33628ee2f0b9d05357ecd67c07965a0427f5f2ba325de39abe31ae2acdfd49" },
                { "si", "5656047c2f9a5b1c9ef0de73c65c0f6dce9322174d7569cc2211828f9d6133e11851e85b230c8b83d9058e8bd35b92c0a505bc2d9f9ab3ba8b9dda90822e1e1a" },
                { "sk", "d9c65a840cecd163743b8c702b3c209b0816895dc456e43eb51bbcdaec343917b4c61f92efe0509ad0519d2e49111da4cdc5e09b4f1b76045c2b5c160ac0dd01" },
                { "sl", "3d22fc6bf3e0038ea76d5b1532616636fd7fa1d47bba7acd494361eadf9b09774454d02f340a605caa6b0bf8cc6d0723402afd1ed67aa27d373515992c8a6d6f" },
                { "son", "bdb88900b1f02a5238905b2d35bbc848c5490e7a2367cd839c58f6a5e0400477a1020b3152347f7db79420a7482e41fd229dd0e6e314a570f96796d1ca5c87e3" },
                { "sq", "0c271bc7cf27b9a212fe436afd0ea48d40dac9cc4cf76ff5a91429a91bc3b9434fc13308f3bb16680f4a88f8bf21b5d5a18d58088370b26903a2ab01b7222ad8" },
                { "sr", "56fd59d26f496f5e9769d2d26c109c909f8dd7d7337dbaacb58e11c8df3ec2b235d7c0a87dd51a2946ce2d2aacd401aea74cfe5a8ed493addd1988802e46c881" },
                { "sv-SE", "79a24d40f29742bf7efcf19b45be7e85c9604dea9498ba7bd6dfb9fe3be340f497ac9c95421a428aabf4b8b1c49e8571a8c394185a539aae258bd914e4a3c9d0" },
                { "szl", "7c1cc89fe4532aef217bee29ad76edb6574c93260b4f1f96453d96287177b6a43da55ee72722c9dd780d63d7c5f04418ad37ae05756fd2a009d6b10e19ada172" },
                { "ta", "236af884c255a213882746e1515d218a6db82dc1016633c6dc0a20bced42ecb92fb7953312307969a48f2dc68c481883716867c3e9ad6f1f4e716bde889d0e08" },
                { "te", "947f283e6348f26f7214a1af610f06f78b4d0845b1e8408fb6d2a141dae2711c08b9b64b2fb042b39e425bb0c0218703afc6ec8c419b6ea80508bd1b64262004" },
                { "th", "609878e6477cf3675b2037dafa812a2b2be334fe1cce960ab61cdf021e5937221b13c7ab8ac65aa5d82ba122f0e859399147a9d074d58ecf42972bed17a4788f" },
                { "tl", "b4bb32b73d70624ae0762d57d63a56f57419b7629db08095690ca3ed4c533c0ce2149bf6170fe366b3583df5f32a6e07b8ad98130942713a58d62a354523a80d" },
                { "tr", "ebd59f75146763524bf3a89b33e06b29cdc1c5b010db09f07e502e7d59c305bdbd568e161c100a343e64c86b4892db8b111864f058955a2876797cd6a3a7b828" },
                { "trs", "6872fd93d191d821ffa9b44f0e78109712ca41aa1d2d49a488d393923f62843f2d9b29af8f32f2408c5c49439c289b0163af6756ce1ae1a5e2b90c3090eccc80" },
                { "uk", "172a2a029fd481e0a8048779ba3e5a3867948c113772b49a68d83f14051c763a95b715294d5d26d108050aad29e29c84d8e9408d00dc69f411b81ef07f58d10c" },
                { "ur", "a85c727c4a691ec044508dcd4ba485b82b8909c62ba04bfee776be7564639f242bd7c5769519965310bff9fc37ba2325886350b3f567d2eb941d2555aa567532" },
                { "uz", "1f3b4abe65a67713383042ecf22af62349572e55c4a08b818b8265befad5fa0f1ce81594eac183b1a513a46657fc7103acbd360da4310c35cfd86074f8802b29" },
                { "vi", "32f82f73fb36074a28e0feac6caad2d004de3059fd4ae1a7df86dd16f8edbc8c06a456192623275dcb6efaacee4146139c350c8cef28cf1611d620374042f0d7" },
                { "xh", "4689235817c320df82860c9854f4d59525583b2c5e871c4b32c77953b4cc1ec62cec3528329e5432da467ae94f90add83d54d8456c4b3e67d356f1670643e6c7" },
                { "zh-CN", "ea80aff8c405e3dec687c3bff09744a29a198ec84b6607c8a594000729cefbc2f9374ea569a1308a2cdba5fb4212095d019b69d9b7840b25baf3eebc912ae47c" },
                { "zh-TW", "f74bd8c6de0fca72b2d19520a577f93c864f832de770a42f05ff99a69a0bdcfb1f71f951b0006ce8b4bf50ff1b4f960e5d12b2548eb113f616fb0d7683df382e" }
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
            const string knownVersion = "91.9.1";
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
