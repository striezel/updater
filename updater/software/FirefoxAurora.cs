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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "105.0b2";

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
            if (!validCodes.Contains<string>(languageCode))
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/105.0b2/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "7bde61c1af0289701d5f6138eeeda7479b38e984b8e655346416f8cf76e737aba3ec1ca79096711c56ae14b462c51d97f9059338b32230da6bea647f2257311c" },
                { "af", "d4d48a8d14116531192554339b2ee922df7eb62d14f994637e6d64ee68bc9dac047b8b170512aee47aa9578517bb6947ff457ed7aace5d42df6d34c23b81c521" },
                { "an", "607835f64d36eed2e452d1418c8eeb6776f0c65758780fd8bc86d9a0a23d10bb7cdee74f000efdec6401dcb8d40065c3daee6287fc7e36c877cf95a15d5aeaec" },
                { "ar", "37b50cfe280caafad52b64ffcb6998f56ea9f415d7e95bfd1fe88d7b0e2965da203f1931b07f198d193c79d413edb0f80f2a3cf1894ff04a01f67d6fa358dcd3" },
                { "ast", "a53db4a99bcf60e52e4367203e377002599c688cfb821d550541809216e88d014a5eb18b82dc36176b28b3ab8742de14938ca9664bcd13d014bae833990f6509" },
                { "az", "677cd7290d7fa41b38a1128b83887d482f3d25c2adedcd9c28689169611d8d34d3c17869dd511c94d4ec75f158e4d86088885035f60d747dea85faeba12d5c7b" },
                { "be", "bdd6a182c75c4ab844ed6fd368157ebdfcf19a72ebc6880d5818028b65d96cedce16a989aa37f85d9da5724b454887a51345c8f6370bc5226612da45e88e3f5a" },
                { "bg", "45c12a323d1d0327f0e1a5032690e2698d2feb2eb2b653dc2ff254639a3481fe2daa38f8ebbbb8e610ae571e6870ad17b2147a6a1ace90172e0608cf151d7439" },
                { "bn", "bc32489b14f7279cc7dbc408fc59cfea5855545b1c9d98b287202a2d59ec43bc9b6adce5fb223689532297035edece5971f9979f368bdbc345e28d36d47bb322" },
                { "br", "5baa8225f26693e11b9fc966bcb87d1edea0d1190c0bcc747639b3dc1793802612cfdd642ebd8de0ff2f2bf91b0a965b2a23715995f639952994e946efd985b7" },
                { "bs", "7a66e8ed89339d603bff5356e067a628b0240baf7221c7cf2c6bf76227bbe20c8fdcbc08c375a7dc7e0d1b94fe0c85b19f67d72987710a06d1b1f072980f7af5" },
                { "ca", "255906920b4be55968513240c3920505304c4f68c4155b0102ff177aae4199a6ae4dca45a24cee1c40320d31362c4ac21e3cf15d84f5261aeadd0654244cbd80" },
                { "cak", "a98c8ff2f2a14ff8eacc872bff400078e007f28bdcbe444f4a201b38a7c2bbd83ee96fd88f3164faa80476c56f3eedd093d60df4d1533c139735a7e9f54792ec" },
                { "cs", "b2dc061a1b96d431659f5cc7a52323d84180a7fce73618b09a4874e8f47272bd9eb9977bf94ccc37793828d51cb7c4d887e347fa2f2c6e7c1c0031b2c252a43d" },
                { "cy", "15a9bff879300c06eac2abff44a989cede4f68e19896f2fabc81bd5c49f381b9ff96c380be00e414745c95fb4b0e6470a1e2c4530fd0cf895677ca14a06f1add" },
                { "da", "c54682b6b591daf1a7461e8bdce19052ffe8aae9f4d237f1ca2edc0c2a2fbd5a16aab4a979d6975be69ca81c7850dcd05e891487c9aacdcb9503199ca4d6ea64" },
                { "de", "1e1fd428e507b2eaf054679edf1f3124f5b03835a24e42dbab27c08a138204e36bbc08a86f6a89ab3cbacc2f4cb32336880490aa51d8b7defd4f3c524c74f67f" },
                { "dsb", "d30d47a66c664006ae2d30f451abc9ff0248568d4094bb817a0ed67fdda64dae8b8af3bb6a4c5924b1f39bb696bf8496edd6a160182d4fc535252d265172512a" },
                { "el", "4381184d2ed6db62f1e297a8dd7d49c56999d8135a8f36f17c2474d49e03842e8702be4c09012044acd7a1265cc1512486d9ba9bf6132453cbfc72fa678ed728" },
                { "en-CA", "e1532c35e39e57f18ab70fb52b5b990bfc2f40c2d51afcf48cd5a769780ea437bd5aacb08401305fd714c5fc5e4c3421081af0e39b56ba597e2946b876545aff" },
                { "en-GB", "572942055c8206a2e532cef14574237351b1746c7f2e58f600a069230dfa6beeb420ac03f294086a367090ecb9d46b67cc835fedfa8b77e6a84fb09ff7bcea64" },
                { "en-US", "83dc06eb9316439c9b58ca087467b875225021601e49d196ec16e1ee7aec465c61790c667c6f19c03af1c866306bae6c0ced00e11a2c60f842338a4f63b60ce0" },
                { "eo", "9c5ba07e32bf1c7918d5e42cb3490d116f81254587365d3de08c4aa5aa5b33a1e390e1d26a9d9d4af50589852491aaf9599198a0aea807f6627eb762312cbdbc" },
                { "es-AR", "7d33fcd84d71710e520507500089279b6c6d4c624118d24ad47f3f3febd1bad5c3695700d018a8fe3b5531abad288129e0d7ecf277f9e241c6b16945e17bcfd2" },
                { "es-CL", "0a07b0ed4ab347b59323bb19d4c3fc6c45915a969d14f107271b8afd828fd702aedabc319cc9da7ae9a0ae73c0acc4a1e4fcf496a31e6aef6a850e090625dd83" },
                { "es-ES", "568b0cf632a966680b346a3fd34cf2a99c16f0d006e7d57226eebb3e4f1aea60d59ad822db433f1c0e5ec229a2d0ea5cb88400d995ece218889c7d830a66a71e" },
                { "es-MX", "a26354ad6b39d7a54cfa2e694b0f2ed6be04c1fb391ae22c1f1ef169f494ad519c09dac2c72f278c0d17b39e33598865f75fc64ae9df80bcb058cc7a5e4fd727" },
                { "et", "738cd2bdc64f64533d36374a050e14e14d0306527e623e8b89b68fd40566b273b817f430b8289116da16b48c6e6abe07fac95a9f01f20f70bf2ca78ad44be401" },
                { "eu", "dcde6d8b544b98fa11f24b07e8c60b42018a369117c19e75fb693edba17a81f252a127c676edfc81dc56040db87c644a220d215ad0df149513ca249950840933" },
                { "fa", "562c27d596b77e7e73bf38229fa8f0ea4a102c65748a529894d422c488c47603d41a42d48f416cdba0fee274d18f9a46c5ef27cfcaaec82d2cb199c8eb646e5b" },
                { "ff", "29adffafc06c4b766940805a3018411d47c3644149261cb439a15d48ab00499e9a2baf055fd6e3aef037edc9f44dc720ce2d5c22416f9475e03fa2f261a719c1" },
                { "fi", "a46a678373d212d6c62eef10f9ab98ca946dec86c24441700f29ecb080d3e39b32e92e2e5d6e106e1b4723c27b0784ffc8e3cfb0d389f7ceb352e0e74e0d0e43" },
                { "fr", "169fca167a540c08e4d9f36b13dd5342e8dc52a8c032ce09b989cba267f90e8e39e1077fc59b0d5d6443a6344358a625053eea72846507d7a21328c813fa2f9a" },
                { "fy-NL", "19c212f7081cf86249ff1215decb8e6343a9ec966b0e1df0ec87babb0d46f520e795847e0d2090cf3b6b9ec9c2914f22acff2c560aab2699cf6abb76c5801919" },
                { "ga-IE", "4e786a0d6e2682fb51eb797cf9f459fdf80df4038544b2cb5f8e9e4e1597dbbf56ad8d5de26321f2db3ee7329c100174c6838eb6da74f2eabf3277a2c44f23cc" },
                { "gd", "42dd399ea56cce233616443054d3f11e04b76598b259fb1c8b497a455e33ad79e70a1c5a083c79d155c4ee55e3ee1590848240289f3b1d5639968264c3689661" },
                { "gl", "3543a4eaf66b956dd8f20b48ba17e44c0cced09e87a3277b4b2f15cd61157c447ebf6532bffb2a695a867397e5979e13b40fd8bc65609195705d98e7e6a20d02" },
                { "gn", "811520dedbf7cdda453478ae4b4c070109397c77353f22c8219742e72cd9ef303c878fbf45e649aa5640f94522f77b13b222bd4e832ff296c1e1bb6799ade58d" },
                { "gu-IN", "a1b9183d90bcabd7d9bac84e8e3f50aca72cd10b6a3e8b2baa3f79d8a3bbbd74f68d42666ec00903e258e0ada0b0f5af4e66328a104a1d105ea11df79d107570" },
                { "he", "1f70d1ec5fc19d5bc110812b5f26c72e8f2d6f5b3d918f6b7041684cfe897f717deaa14224ae0f80af8551447b55f61a30735993d62adc1a33d6094f9df9a9d3" },
                { "hi-IN", "c4267b8d62495140e39ab822d310004d68bda9d770a455de070b623024310dcdfa6c371728108072ba56ec6bbd02395fcdfd8d73a6a7923fbb11bdd6174780b0" },
                { "hr", "58f073d5821d6b17ef26a0b76a584eeba8c4c88b70b845c5863c2651c769f3505869642bc1d6b5b5cd9d482c68a3f09b013e6e39086cf31f40e25428e3a84b57" },
                { "hsb", "a72882e278ede7b41f7ebb6e7578dcf4d85a9c101d6a48e8f0dfa38aeb697042d767cbdae3b839140a94bc48eb64eb53f8cbb5bfb4106826ead713ffaddb68b3" },
                { "hu", "c0289f9e658f1e7d786aa2ed6b04e7e3e0780224a6f86f74e1c640916565fcd182496939a555a4c0372d2fcfa0cc6441096898754e1d35398caa8bc5c7fde297" },
                { "hy-AM", "c0dc79f3c8547dea99b26b7caddd5a1b5ba1088f68e7618085ad2ce3d61fd79cda4eb3d05343b8fb511377a81740ee2670c20ac376da8b49ee759df819ca4daf" },
                { "ia", "07a7f61213b99a096aa8a02afef1e0dc04965c85c63e4c7043b3723a9a1e730d60f42c8da075251376cfdd579296e3576b8fa995d180bf4ffda95b83cb0cecbe" },
                { "id", "762d049b6aa1565360004d9624b8123760b0bb1f126cd140ba799a4a13dc55c4c6e0ded60fabdb9198a2af1ce513e6607809e4f7af718b5ffbae97efdad5e550" },
                { "is", "6287939980775aec8c6cd4ecc87f3db3cb8efefd03b1b837313116d5d376faa53c3f0f4598cc7e0dd3bc514f9e3726de806af95b9a64981395b7eedfa04c1c79" },
                { "it", "e0698c0525b83fdfcc96a41d56a819e8e6bdaff862b03c6545615d6d511db9b33c284ed556f0f7c34323da479e66a46f5409008cdfd33531ee75e3a9d059a65e" },
                { "ja", "6b0e5b677e7809033bb3a78f6f99d5feab8fa77e12ab7404e21523c3fad8b494a0135b20606249fc2113e2549583c9aa3e578704cb7913256a47722d8cc25e8b" },
                { "ka", "23c21e2c0cb2ac7439444e92d1e05803b8c531662eac06f7db98049246dabf5dd70f6b64a3e5cd564a0fee4c735a19b4883fde42faeb4a84c0331b55cc2026be" },
                { "kab", "2b4fe12463ff4396b44c8de6490459afa706d40164762fb816fdd165bc06b58bbc0d50789a12bd8215444aa626ad25f84c046fae8a3c99a3b5f1788ac8133cee" },
                { "kk", "2fccaf7a952bacc5a19e688b060f59de5c98b44cf4cf1151e277be0a536a34fbb9ac5929f99552e352784c30e6d9f50150100020bf40777d24ecb04d566300f3" },
                { "km", "689f5b2afe16066a87612570363b0830745d5bbbeba6676c3a7593703791cfa7901630c4f64c4caec8c9337aea834c091862d28cd9968a78ae17325d20035627" },
                { "kn", "13f13518aa18c221550cf50f879514e45f8ea626ff25a1e290d89c425433271127d817784195b3763bef7c3f8ff1baa61a6821a45aa5274f7de0c492e599d193" },
                { "ko", "0ea6870b6b4c1bdc30d3261dbc635103baf7fe11f2ea702cd802153589328783b00f1ffbe2fd0df3b052f6899c3476d1f3336fe0cc4a7500789a77085cfafde4" },
                { "lij", "964f0d7bc4aea36849f2dcd329ccc4e8adaadc849acd84a3d80a8b1f3de1e534cba5885cf39080615850e2c180a6146f7d45cb5acfe5c8601fa068516d5f39af" },
                { "lt", "d43bdc2af9619b6f17d49682b109ebf21dcfee4513525321a3a090c3ae404a65671c30c25fab4fc2a8ac114d5e8f6f70ea045b035c86a8d38aa843519ce0bf10" },
                { "lv", "b2fb7062e146b571b1d2a7101fe558173ba1b3aac19f9e78a339a69fce765d942c8af8f032f771a53b781d07461743ee1158625b6e1ef3c3114d466be8041bb9" },
                { "mk", "6162ed521e4594ab0cbc8d4a8e037188c4051887659da36d6c7e5408eea87100809aaf52eca923a8b48fc397b64c3e461f63acb24458b6f36aa08299294b9113" },
                { "mr", "9bb66b41c05d9df27b0a8c7cdeaf051b85e9207e30bb53d76f78ae9dfc44f5bad2a9f7a606ee37d1ffb9c71db07f860d80577937d8f4ead513cf94d6f537b362" },
                { "ms", "8033f2851be8a20df10660a40c29c73ab1dc56789a2d095e38b943ef746a7535ce8fa863c81252ae8d6242a9f0b2a99372990bb0ea75bf0e628f4ca6b0a85a51" },
                { "my", "cde0009eecd8137abf4d453ebb77080f61f0dd642c8aaafb2311c7700930c82280d6b57b242ba5ad25b347a027f3ad9056a9f648afd89ae1353b62a69d41b7a8" },
                { "nb-NO", "648e1785ecc7b6db0af8dcd2e1e2493fed0ae0c8331df14a01b108f6f980b195a53f0c3da7ad7e4fdeaa5605b5c9b3045b5354289366dfc95d44f06c7db48029" },
                { "ne-NP", "57fc884705a77e14d0335163a1e589ba7a6684f52f057f5af17bb87b5a43f05c01cc845be45b8182b18bd477e157261a0d9a5f398efe922b073a3fe2e5fee020" },
                { "nl", "e7cc0f2cb5adad0d3ce6809808f7690ed251c58b1f5d631752745fc74fccd60890973fa1d669ae1a80756a2ebcf6f3131dad7e49ea2ead9e5e2ae7a5cbf9d39b" },
                { "nn-NO", "5dc56a3e9f31cf3e80de382579cd25d8a7a74f27ae16b29dd707e65721e8bb5d142637c39656a19349a26a997f0c18ec6b8d29c9fb2aa3c7fdfa0bd03001afcf" },
                { "oc", "a1e8411fc14ca0fbc9de1ab83cddeb0ba01d43595763f2458b905a112dab238e4e0634bc935e26c8dbc77d6288681ec8add6fc36cbe192d8359f5c9b4f70f467" },
                { "pa-IN", "d8ea5fc773f6d9740e370c7bbbb00b1cbae4edf300979e11f6de063dda7bd0c0438112f8a90cd147eff4b1f44c4ac24a2ff0e2515ec918a54d12d034b4d52f12" },
                { "pl", "394a0976f6762f8c230b531de58d8a769152376dbb5de7e552861a689492760cc67883b46ca7612968870fc0efffa6fdd34998fb0f4c459fd278139b646e3924" },
                { "pt-BR", "46ff14b25267f79b20acdf124e8958c540abdfd778c32c11e6a9ebd50ed057f5789749ce75db3289baa9443ce9350d2ef673fcf328e8739a02274f74dcdf14e9" },
                { "pt-PT", "07979e26c657f9c3ff5a475fd313a92a359f8e55e76bb3d3254cdc8d2a57f5d43c9df6f7909a2fd5d2298b2c359590ecebafd9e5f07c33ce69f181c9e7bcb804" },
                { "rm", "38cb8ae5c10d9354b080ffda6f8f15035bb7bfdcf457df2ede43b69a90d97ba02dd87559278b9f86c8b1512ec55032d56dc228f7502e53d7a9ec8635e5e4f3fb" },
                { "ro", "390eedfde6e11751812305b8c03ec0d8ca45560649bbd43ed5b60731e4e0b4f64426c8e7ef6c941aaeaa2d26f3d12601f93c500a5f53dc4648ee9d33f8967ed1" },
                { "ru", "b6654c7739c295b5a413a5ebc1af1a1d4361071297b3cd667ac23236c13345c3df6b4336b0b84209d50bcbb7169b8fc2604b55a2a0969074b72a3d3708201600" },
                { "sco", "ea021e24280d6409bba825c4bfa1fce484051a6f84275e11ad891eab27c6f2a21f0a6b34b66703386fe665943f3593c67604298571af52a589cbb85474a1d37c" },
                { "si", "5159d211d8ea4c8fec321fba276d8331b5f1031d28fc9e7241472b8c98703dd58f3b782bbb13ee4ee6813212c2eaf369022822de33cb3660743bf8b5d057e5ab" },
                { "sk", "cb05f23d954c33c7ad6887dc3aa9d519edd90c996daa2c320424b4883afba07738143a239a6792a97af9508afc14829b1e82ad46d993ce7b40c0c4cbbb219b70" },
                { "sl", "7829372f02ac2c028d949c53a16526f52847c7297bbd48dcfd3692b1882ac3c1184ad1b14c3af8a15187c4177dfe4bfe9bd4025a44f191c9fc4b0c038ff7fd05" },
                { "son", "0192ef04a630fdb2cac6929b19387fbbd18281e48e16b535df82d1b9add1ee947a365e6bb1219c8afa396a6ff59eea65e03f833a7bce112b8806bafe3946e4ef" },
                { "sq", "6ccc43692a8ca0b8f92c46cd0c63e5dfd67cdd7abcf623d1f1ed8b3ecaf5948dee13375f79b3336efecbb1003187a18003fb13534b789c855417478af2c5c6eb" },
                { "sr", "d13d3088498f7cc4d3900742e22d44129ad8bbfef78f2b6ad5efc9ac08ebc3ea6a5dc6a2e7f5d80a92c26ec224eb5dd5d713090eb3cf6983eaa4215f4ef6f626" },
                { "sv-SE", "08207c0ca52528149905d9218fff99d59138a254ed72a0aeadc7105dcd30a7f45e1e50c240444cb1e9b810a6a36dce604bed6e6627742577bf61d53bb488bdde" },
                { "szl", "af3ea5a66d213700371a5a2288300481b7d64116817284197d1b491ec6c41d9ee737d32d06a21f86a4a739907c3270cf67464bb0a5974dc5642597f70f998726" },
                { "ta", "381e97b55e924570c2a504581b7e8af6938484c2da77c9220d22a91d8dffb31b35d080ca07ba97809d0ed6c94530583a4c936e708056197da195019ae5fcebbe" },
                { "te", "ee4eb3c29fd412db74d15db2d8e2acee9bf8af65f469708c44cedc8ff79de92a8ff15cea75aaa0c65b22d4cd6722f52adc7cf6150404663a05c9636e8a8422bb" },
                { "th", "44e8caa27005df72e277a5061abbf9f90583a9dcf10598ec8696cc2249ef7a710234913810f67e417e0d51a07486361221c05872da13d5db646e44f6fe97df0e" },
                { "tl", "f31774dbe3b6008656eb1f76932132746c0ab6fce2086780787162dcff3b098983a1c5d9d58751fc72fd784e6816a43a9abbd9e4f18779fcecb4973fdd343234" },
                { "tr", "1a8dcc24323ef966064a023de3d2b88ae2cfe1c7a12e13128b03e4ddde008a5b74126e650bf69e99673a3d7715e586c74cfaee3a98824279ea69c655ba6e7dcb" },
                { "trs", "1da7aaa3948e8041f5745fdcd5e3c782a7bf5773dcf1817870ae05dd7c77781c6574113d191bc9a7cd860bb83ac3ded2728bfa63eb34fc92105eec6f479e8bfa" },
                { "uk", "2bfa41087651c68ef6872f35dbbc92a018d9bb5039a211898f6e740cf55c42797d8324c75252ec73b082effb9a59aba74f9bd3c783e5621b94c357ab32780bd7" },
                { "ur", "6d17e45802e14e6ba6d95b25bf100ca517116ca330cf537c07b84ab92e1aad0b64b8a944aadc3c84899cf2616f18918ea955ee5bec419f04cf013ca9253465af" },
                { "uz", "b9b2290d4a5ebb2bb87a8ea8a794a899f440a133eff5c82bd225dbdd4fbc7a611f80d9d01178cc37c9cf23c8ca14d8586299ffabdb6077393710ef7aaae74d35" },
                { "vi", "4494d2e8b69081242a576046965b6c3488df93384e72614b5764440a570759f39cbefd63a41773f1043acf12e3832898c13a9dd0d54146605e91fdac4fb52192" },
                { "xh", "21b866e6bd468b31c4c2bf0a8c9d82ac9faaaeac464caf01adadc109a093c215bb2204e06bf456694aa9f9f9a25430172252d607113a7d1df613d8b03b1b1edf" },
                { "zh-CN", "55aea4d742c2f92823013e8e18f9b5263dc626391ba772a709d124aa90d8e55671ca2b40185c13732395110c49d1231424cdd7d6118c135a059cd32655d1dd07" },
                { "zh-TW", "6ff32ebf82e21c49a62e1f5417ee42ec5cb6d9d4f5e17cec49207d31bed9bbd049847769523ae79eeab10e886b623ea7d400f93a0152d62d68c2a2d43eeaa5f1" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/105.0b2/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "976554ae85941ef8ebb1ebd64a1266823c21993720476ec961d2f8e70668f25bcbbd5c9d142d1df725311df5c09ae3268bea6b02dc448037933534dec33ccf19" },
                { "af", "4d23f7f52a20de2f5a4be47d21dc9bd178c213166b4cf840fd35d1b7034091834bcff90df9f22c90e81d60e6dbd31b45d67fd0023f1f70d318198cb6c324530a" },
                { "an", "01b85dd635e9054462993971caa41b208fe207b03088bb8c91c67ac65685a8c1b09e1c5ac68f134dd26bc6fd47790e3945756ead891fe3519f7a6379b36feffc" },
                { "ar", "9c6a11502442d46ae4d309154a3a8666bceb8a62b416be71289339988c3b635f614522cf244f949cf2203a931f416a619b47228f0fafed636deb1232dd578c2a" },
                { "ast", "cd1ffc147fba852e9cb1aa613ae582b4dae3deae46f42c49e1be9a0d8937878bee3ed20292fdaea6a0e99376f8ba965fe8c630705854a7a993ec17f290a41ea1" },
                { "az", "b07f0758a810873fcbf1d79bb83294bb34ddc2b98b80be3b13283cd6657d0ebd51beb29f8376145ebd520be36ee5d4a152c80205c84b2328b08e3b956ac23cfc" },
                { "be", "85fc90e2dd98f8f1d21e6787a47ae026ca4ae5f21d33641cb2e2398d7d3ec65ecb58d37987d8b60b5ca39d56ca0ded781710620002457ec9b9912a1f722e923e" },
                { "bg", "1f885bff588d0e4e5c8e5ef8e41f2507be6f607861290d1739b9e273f5926eae630b942ca9d222b746b9fd011dd2deeeefbb98c4d5331f58d63ddec04869ebf3" },
                { "bn", "4a93c1b514eb90fd804280f8b34ac84bace8596150fb05973024e6d70e52605fab1b99c19b5bd9923b2f38407a46ebada865470b3c9490840ff4e9e664cb9fd3" },
                { "br", "5120edf755356608b8ff6796dfe3ee672a2b3b3cc56597f636bbc835e8cea7edee05098197705857cd39efc1c851456e1a1b69c5d5f16bf2de1bc9768376a585" },
                { "bs", "7b51f627057ee4ae9ba3f36f787a5dad560ac4299911a82f4d1b1878214ff6592e021f180ce4f2205e00628c6513183f16fa5679c39b31994de2bfab785ddcc1" },
                { "ca", "78d696a728064ec09b88eda55218a6683ebe274ca7170c3692b4a6a996ca0fbad69eb0954fc1eff9035fb38131ee1b6adb12cbb60a5a94e4a0682bb3f468fbe2" },
                { "cak", "0519899841ed86218df990382681106d84122d0fc4a900c6594272c440d2818a721f0f09a8d52b1751ba68174cce67051b6c77e2143bd48742ea55509c08e417" },
                { "cs", "f304d61c5c6d624f46f17395f5c7326a30ae035526203396f1a1c7eef5923dec6af6139e12dd9ba09b9bb3a3ada175d80ebf7733b8b9663d23cfa4aee632f452" },
                { "cy", "02b2ca4236477c5850166afe68d9f27494ea19f27bc7dfc3e17066729dbd52a4d1b05ca17271bc1ed3ac281d31953a28190aa6d23ca1290805085d8dbe522826" },
                { "da", "7413954dea4d6116521bf6cb5a9cb1e6cbcd8a9417c88da17387a3f0a94a0add04948a56be726521630e58efdfd087046f0a7748b37f9dd2b8f6d3418f16ed5f" },
                { "de", "9f082027aa03f83b90c89415deec573aa6ba9a08385def110d3216f8717292cf497bf9ed8a7488a4d2e971794016c2517d4d4a47047a212ec3481c7d0ae55600" },
                { "dsb", "384878d6b34f28b82f46b99ac40dac7bf6388cd8714bb4c31873a4ae84bbba291dff043f7c347717a0d5b4431502ee1dab4d72ef57c428b115832c378d03a770" },
                { "el", "52deecd850ad71143d21c2f995163c7e2508220845d027c833ff5e86c17a19fb02eca78e35576a9b71788ed07de687027eb2e424939dda453d7fae0aa9a39a2c" },
                { "en-CA", "c2208e74458d97e1f1292b0ac6b2dd92cd5398aa5177578523c470af93c70758639a9ce79e6f63f4944b8c1ca69dec636b9ad7287dcdb0cc5088faef345d29d4" },
                { "en-GB", "efb23bbed23f70b1b1bb3a74194880a09c9eb561acbe37e9769ed323c3fa9baaa343afbc821f50babd0879c6bff01ff872444a19b063b18f8d6f9c7ce1aa5772" },
                { "en-US", "c1ecbe75f2d900832dad45453e4cec9776b3e91520cd14b784bef5060d924e26903b8ddf08a011d6f43b017cea742f572aec611d365cac2a8b9b8736ea652480" },
                { "eo", "05d94ae37a87e5c11f1957329f1cf56a1ed9cc95abd2309a06484b0ea3308fa383ac56bd31a8480ae51887422e418f8fd4fbe6863f2b1ec5a3c3b385c8cc201a" },
                { "es-AR", "9a0ca5c71b96daf8a8f67b1cf4988fc603b510cc0830121e67ff944567991abe54db6d7e5bce06d8a115e70e4686ae4f151b85367626c56371cc528c3a3e0b20" },
                { "es-CL", "5ea8e66c0c561a714a1447db53e90528c9d140a45f8de55fece4341a0e8e6cd56837a9d4d08c91936390968ed2d864c9ecd241b485e831244dfbcc285fda8ca9" },
                { "es-ES", "36e1a92c8eb608c2e5d4447d3745bbf4cc0f8f44b4b005ce8583c4abc9aed7bc0253e7f670a7a2edbc2e55bc76da35ab135cabeb1edb653e7d2b19a2dd5c95e8" },
                { "es-MX", "bc34a589d2c6e935eaddf1686468cf0e92b459bbec8510d93ec3311934a5b48bbddc4369a918c8525296e43050fd23a184adab11e92fd77d95e05fddff10abd3" },
                { "et", "4c65345d23ba35f6d60c2478179b39ec44b55ebc797fc78882d7254d4197dec1856b4063808335caa703ebf6d3660bfc0d17dee0b99bae02c3b14239528acc08" },
                { "eu", "5d0fe5175547e7f89c9af64fe8b2042c612acdf0af8fde7dcbff3baf62dd459fa7673aa07924d27b3b49d5ac9da11fffd55d03a19d5ac4d569ea0616ae7fd773" },
                { "fa", "176cd2d8e309479e4e8c0db8e0860eed127ad3b694292283596567afec35b56b779778da29caaed6236ae54edce472a0c2dfdd559d27328e76f12ea1fc587ab6" },
                { "ff", "3cd299fbaadaf30d14d57cc62e6cd6cb0402fea2a13ba430cd719da3253c26e0a2b266f288788c2bbec5ffba39a0486aa4b14fcde9d8c2e38bf944f46fe945e5" },
                { "fi", "5db419aa0d8640a40bf7087b756aee2fd92a6e5bc659a52925bb8c29efa7f8061fd8dffbf9d0dc50b00561bc860246ef2675f83842856a9f79c38aa661d30ac2" },
                { "fr", "252612d94391941695160350163db6525f27e0119d889fcbfaadde67c2519bd9db7b24285bc910333b5ea854a1983f5eb7f9cffe03b5362dc764e20ce462b2af" },
                { "fy-NL", "3db2c9f2a3378c4d0491344a8bc12d4754fd68b4a6cfbb110b56f2dace94064b040a0138aa507f6c791facb2cdc9d3bd274b34e89d9592f06f75185c3869e958" },
                { "ga-IE", "758637862beb73cbdeb46e02dddc5344aec0aa1e3c15765f6f0c07e3dd9551f5ff5f6877775f0f3b3165df1448390bd50e118d7fc0e46188d9c889631dfa8645" },
                { "gd", "a7d5280fff7c9de0993e7aec9872f4cb1c35d874a5b24fbcaee44cfd668c3c359b679c1182aa7264c9d7a5205ce8d66b292baa7e02685351e0404ddae279b460" },
                { "gl", "18cf5b6ad711ade5d55ab2aed77783927ef580f32cf39f08fe3efc7cd746ef65c13675f5c8bca1719aa925d054aef1e356f840904171caa0f82e98bdccc440fb" },
                { "gn", "547fb453329849909ab4090fe962a6efa9da629f87cd75996d793750fbd18969c4cec2b22487cf6330ea8f6f27cf3ac5f0100270f7ee1f30cb15b757fbed20f1" },
                { "gu-IN", "c44e09744574573bc1efe42da797bcb6e3495fd69f82655c74c3caecfa57e1735f9d0cdd31799b2896c2958bc971ea90979a25881740b084a1c825f6b1a84b9d" },
                { "he", "d233b44ce245029cc14661f265c20acb8406a13d0f8d96d55a543c13287c4395548adb896161ad72021ac7f4e8125d92333dc9ca2e79c8aa8ebdfa0654a6571c" },
                { "hi-IN", "137e0d22f038a05b96542765e12c20ba1d96e18d8a5862c68a862eb1ab2ccd62acdea3a9c3491a66ce3524116b67acd1ea1a0a9c7cd347c0907c3749acaae0d8" },
                { "hr", "a03556e68a9392ebfe6a557fa39c27c29c3e97af2a805536c97ca6d2f5580423194d27348322bbdf495329fb30f0aa83f5d852cba7fb7b920dffba4375b2fd14" },
                { "hsb", "8014d4d3cd8452d20d26b1e8b0273a00ac89501042defc77d151c31419255cde7619a38a22964d35255ed65f31afc259ea80b277dc67b5f4f736632fb100f382" },
                { "hu", "d9e35f6e7dc2d8e150d8626c8463d85ccf3e69043a8c3f5cc8cc1e95022fb1f0e9859fbcc7b4f87982d6996628405f0a116145ba3a27acacef1b686499924b99" },
                { "hy-AM", "c13956938b47eda4b18706859b03d43fca5be6e2d5a2f588a654f42b7edabd977b19f1ca097b99b0cbe5908f900b2322dfa3d4a4c982f49a5d31db3a6a6e16ba" },
                { "ia", "b3a37d3e7e1bbf94c31c75764eeb10386e5d02981c4c0f8a815a822785bcdde08da3d0c634f05ac1310f5e2edac9e4451ca12328effeac61c3f513cd232dd816" },
                { "id", "76971da427fb7bcfea7b35e3b3c0bfdeefc1c8bc53c23c26891eb467683a424181032990514cb6d53c3a978ac736672d8653acbb147ceb7cb6dd3b67d4dc2aaf" },
                { "is", "90db6e3d7823a20df7768a0d25647a0a1254a029c7e240e5d2a29ccd51f29629fbb54b4cabcb3cf1fdebb4ebd817b8c8886dc108871b3742a9d7251e28b79c7c" },
                { "it", "0ae27dfa4e5e2544b61be03564d43eb79dae7f3c5d67e51eea28f29ee96a380c4610fee8cad743c772f8052fc105d405eadc93a8f846bf27870b5bd2edf22705" },
                { "ja", "704718276d6bcdd67b7b9c31ffe71cc414f3977a2658388981057f97c9e023127e8d6c276d95a5cd7b5408d62c36ff55dfb93344a2ee4966f0195da583cecf35" },
                { "ka", "c9f986eee93ed1f2f0c49525aa60b94d5acda476a7924a333ba7065b6df0008aa61c83b2977324efed5cd93353aa9c6e54e9cd0a683f9a5015a83dea1ba017f4" },
                { "kab", "4476e4e72afe22fb2e3c360a929afa04dafaf0169b62b57f63b7a274a49993ca7fdbe00b452ad6ee58f4b92c5b8a682a6723c57313fc8d1f0f8a7da123e63073" },
                { "kk", "cbc0ed761b780654aec892b2e02a5a731e5401922cab7c967ff7e0312b882da2abba448ee066b79a1fc0be2e00966974e3debed7f61b86737d2f7d99ac55c54d" },
                { "km", "70b4319b2853fe4b7f446d1714be4c368b868a5074753a6cd071e431514a9631ba7ec2ee26f4856c7f48179b643a385e629b96d7e4e0fb9a3d9534a20b874328" },
                { "kn", "e234bff6209ffc46a9da69dfcaf7b8c8954fd51d25086c9bca21989ea490ffd8febef0c6b51016d1af4e9f823a354aa58dc42cb52bcbac3bece7b676aa9f5c80" },
                { "ko", "19ca505687cb7d3641474fe9f9beec2e7f241768f80e2769cccb63f8b5137dbf28b3c567ffa5c9d15071da9f7f0f5985742e18c15e4c996322101c1e1ee406a7" },
                { "lij", "ee4fea1415bfb3db9cddafcd6afead850b028687ed072c9f452eedd411811b97df664001d9144801f819e8fc32726215b66ebce97053ad283b617eec3241bfd9" },
                { "lt", "7919b42dbd2329b883b061bb53fff7d0db00ebea0c89a1d4c2e4c1c755460039f35a2d0aa6258fcac5980dcc31147462bb5fe3dbd0618235affdc7fe3be52554" },
                { "lv", "b10b4152020ef3046f9ebbb252396be2df0d8bce9a7ad80b2df86da344c0557dcfeaba0baf9825897044c0954769cbc140f4eb7979bc13dbabb7021b56fa0881" },
                { "mk", "dbaff51841fd8e16e7e18717b8488232ff44a085a1b1c4c7b3b33d6262e46c951cf43b04185decee442501b7a593279a7cd675498f03ad31b22414c4e30ad10a" },
                { "mr", "7dc1c162ad543c90d1e76874c8f0ed9ad9ac76161942fec0669ff826017d85accb4e24317891238375889c4b06255db9effeeda13cd549839118e57faa237d53" },
                { "ms", "35d425d6e53b41fff64ac530837dee515dd38b74e12a0d321eddbeb20bb27268d06974585ae4a45cf7496f9731294c6bb8f6a91e55f57b8bfb31a78a1b467abc" },
                { "my", "9a6d958d911eb29bdb86bc5202e4b897d05ad920941db87b826b5be2d837a75957d92c62504385acfa878a5dc537e53500dd5d0572e356c1ae00c6e6ec44322c" },
                { "nb-NO", "09c5c576f0ebdd0404e67a59f5621e25e2684b54dbef2606b4c35861e5c096e7b277188c5c7aa72d5afa6a198fe3e0097863af772060236ea43e2dc3dc139a7a" },
                { "ne-NP", "2614d622475b426473489e0084b20874ba73eef45f9be649164eb14ecc1208fc0b796e4b9cae3016c70d9362796b41e4f2661e39c055c0426a6fd29e4712eb60" },
                { "nl", "ab2b3c4f7589cfb884690f086dc25561a01b0ba7905be709d53d052d3fe0dc231a519f2c870492b21f4e4a4b824d8faf268a3d295c3c9891fe9c1db9d473870e" },
                { "nn-NO", "7ca6762432ecd5e8d280841e6ec4cd7d3dd407bac40c948664cf985693c324c49b5cd80344b03e37f1ec2e4249efc16dbe0e909ff26de3107f0761ff28fedff4" },
                { "oc", "cfc0de446a4273b9593c075e8e51b5773b124c75105d1ffd5d1de1cb8dd374c4499401aa38472ab70edf413e8eaaf46b3ae805d742198245ee1f2f93cffef12f" },
                { "pa-IN", "bbc3f46f447d00fcc3e0ff828f0ab180ead89a22d0cc4542c9dd3c2eea21826363fc63726a8607ce63821a69a755cbd7cda103335d90ad2908e6f9914c802f80" },
                { "pl", "07f6bdb92daf672de96790311c7b8f7d222a7e6e9e9522c2bc042351fb069160ee84786c84e059847794f8c5adc08dc8f6d8d1bcfebbf70e29b3953e998d3603" },
                { "pt-BR", "962153d8bf183ee439167eb05b24bcaf59bd10b7a1e3b2995c147cf7f9fd739300fde0c42cac603a3eb17d1869052d78ae87a8e470023ef0dd910fcd0cb3a58d" },
                { "pt-PT", "5e3beb8f1a012e650536bae8673430594438f65a7638d4437385ca977d8f65fd8670e6ec167cf3de55b0ee5fd0d5024aad6d3efde2cc811418127a98a0cebdbe" },
                { "rm", "9a3ebf398108e5c97346c0c0b4768e13b3e5bdb27628ac7846a1f53b37541c996b338748d22a69cceb68f99d353ec42ddf0698c8bc6259cc812452d961f0c235" },
                { "ro", "1f3abbd1e3efa45fd6efaf24881a41a424fe4721ab6db068d29161eeb2d1015bea71f1910829f06880fdcfa41b77d14c9e821117aca588b3049e0c33f5908cfd" },
                { "ru", "71a3e6fc845c2d52195abf055b305b456caaa3b2df9c0915e6d98be478a6db6ceb9abca068dca321f51c1e8ef6762b31cf9140ffce08688decabd50b5b48f8e2" },
                { "sco", "2974be4abbc30e5f14f5cc7f73b43a3fdcf39e1c4fcba92fa4fd950c4a516998831e6e7104f4cf60a84a84c5a3aeb8cdc52d4e0eb69b97298fde0c62635b0f57" },
                { "si", "5a692bfb42695eeb51621678b4639936c13638867723b11af137dd8fba721baf69503a72d513cbed77b83f92b837761d1f822a01300519f3bb86c54eec9ae144" },
                { "sk", "473cdc8af2f63f760272f92d326e7191e7808a518048267c0beaa56a6f1c4335c6eccf538e5d7ecb3df8cc8cd8980b0e4bdde34c3e7e4dcc5f8bffc58ceccb22" },
                { "sl", "6ea1d600d04f3b722a617dd15709b2cb55ad1aa2aeec4abe9af69df6a0480d7fd0e2d955ba00db509f49dd570477a4840bdb5378c921d1d842c6cf45557a87c5" },
                { "son", "dab56823b9294b67b5cf6ca9b6e63c3cec7bdb3d2bc25212df1e4826354374f7aa76a3ebe3ca998d0cc1179eee6d4c2f093bc3bb8aee1c6e87841a8225682554" },
                { "sq", "ff47218a44dff4071e685e891e79111d0e146667975fb2a0d2ff4a606d9a5052ac06ce722e5b1298737f8d14c6965727cbb371aec07191c09729025373d87a39" },
                { "sr", "5113560b455c98e50763ea591b4806f7b92bbc5e7f6511b2a1a092e92a581769dcafd4e16e54f7099a22c4a0d4a1f454ccafc83da63f34dfc5443a9d971959d7" },
                { "sv-SE", "84614320d94731a9ff54f9c9ea0188dcd329787c1766c98510099f5c5fad152dd6eaacf1e73c57ae721b370901f2b306942bae70b492a7614bf272b2bf9bd60b" },
                { "szl", "d2040b394bd3ce74dffb7fcf1135bce3359515f704c779944a39e213ecc9e7ce2a4276850ccc2adbce3aa10600e7fa6331f103081c6f2a2cc218eaa960900f83" },
                { "ta", "7a45e518e82c482e9ad564a7ea590bdf2213146ab30aff655017ee9608fa2580298fe70dbff1087acf8ee8cf3220649831eb26e3314c3596455250272071e994" },
                { "te", "f74730e3c6f556e86d049323540f0ad5d8715458488d2a44f4b5149021c292c352c62bd47b40597a9aef37650780ba5ea86ac7cd3220167f934f00745f52d140" },
                { "th", "aa589912b86cd3dadf01c755191ba33db8e5590d8639df98bd9da375abdbd8389151b21e25a70d67a7e2434a2d914573b34e7f15631926ba7f84ed8c7fa6b40c" },
                { "tl", "44701efdf4b0504c1670e60a195ce65bb3e7b016c0484d1779e2e2f301eaa82d7b4f91c7bce2685b38871946d026920e6ca826416be0cfd5d5a2e076c13da247" },
                { "tr", "80fe1584d0cbe2f40b1c2f926e347540c3f30db4ba5e208e1f5f5596135f49d9e72a2c52bdfc174522af751a072adaeff138934169c8a65cb79eabb91d47062b" },
                { "trs", "30f8f5ad3605926d71ea9ccf3ebc285f4178c30d6a8c5405a0a42c0d788f5f766a441fa133ac62cf3b1c8e88c58b1bf19e3c03d15e0f32d76afaec7b629d2da3" },
                { "uk", "c0c66b29b820792e984c0e9f8095bb16454c2d493809362b7b7daa4b7ff93e04ea0b1c3b816d38fecd5ce0f83658f9916d036f7af69bc15c859c5f8562816dda" },
                { "ur", "af367ac63ca7964b6243ac37c85e4f24b0dad6ad75e31da2dcda4a12b85f9830b3f44a81301575569f60107d378b0151fb6a07008b9264cc38a7247c23952273" },
                { "uz", "a93e4cfd793d3666b5e8f7d5ffc42d9de5f0c366eff3270d8e41d2054f69ac63dcca5f45554512ce4a2341e45f22e3a0cfceb086bc4beb8c0880cd5233478de2" },
                { "vi", "d30381f6bdee92c0812e51a47d6167af069fc764c2da6711159405ec1c7600c2744d9f00ac93e38750c659d74288bab53e09778b671e8784929fc3b693165d55" },
                { "xh", "9e4f3be0fad534169571f5777af295496c661ff09503781b4aed5ed69846e338ebb12750cf9d149c02b5fb08e6e34cbc98229b4bfc0689fcd7c847c661073815" },
                { "zh-CN", "655dc7de543c358fcb67467f9cafe59f766fd642b2124666f00a63c46b1057301ebc1b9d1b3bfb0fba139b34fe40ad021e6ff24e8214bd441db074f00e3f0a94" },
                { "zh-TW", "554acf714954a788ad4200584c066272f8821ac887bbe4d76e9708ba0a7cb9fd597d6f3dcc48268621bffc4c48857416a615e4dd22298a02fd9807fd672a0b11" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
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
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent = null;
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }
            }
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
