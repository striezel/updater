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
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "21cb07710a851fb176b69028c051351989e8ca3a88f6be8ea01f0b2b3e7f80f8f8efcaaf30e0b784dfead2f0277fb130fc8bd98ff25f948140a323eb7a89ddfe" },
                { "af", "0bc7f32be94866ea2c4da42fb90855f37d31265d635e6c3931fc2229b672ea650944e38144d98c50c8a87fbcf2efebd5a4511ecf0cf61019f75f4c6f2730daf2" },
                { "an", "dd59bf188532457c2c63c96865b6b376d2b149a8c2f3880477304a3fd1d9aefa03e6f59d9b29df99c08fd7205f5aa029e3df3eb3d8dfbe5183f0803d236b771a" },
                { "ar", "ddacee73cd85a9dbedea792a2a2ac3263210ec5e261c44160f16d27af8c09575879c4465466dac73ed50aecec7c7d08dae35e5ba941844cfb782d029976234a0" },
                { "ast", "43f4e5068b8492ac0e08c88e9d4973236cde08fb4a396f5cf1c26d8310957a896eb24801a7db8ccff799e01e28b69078e5309aa2d09d869eb3467abee3ca8633" },
                { "az", "5727a4da2534d8b32ed2e0d496fb3e76ac72ffb85e12ea7c630fb81b849b8d068152e79a4603b895e98d1e34eea4e33a58089cffc80cff8f4919c61e5adcfc29" },
                { "be", "b83628e51bfda45e2836889d013a751754d9e7d43d8bbd2d95e68f46a2f28f71bda69dc61a18b58889c92f962e5954b6f38c7a91c1db6ac664730f4af46080b8" },
                { "bg", "3da49d757d95b9fbf420d8c5d5e1d49aa319fd8e4025cf95e59e4825cff214a81db017e3e1680dee74ab053f8650089904a5fffd06861f722887e28e66bc87c6" },
                { "bn", "0a7d8b2e4a55563e4d4ccaafb83c4c7e72c4e414f935697147355694ce1e637f085274a9518b6a707d7ffb3204c9ed42c1a9e86b4838cd57b03144f3296ae489" },
                { "br", "934c83130f0ec845868a4b6ec7b284ba5969ce88035e442dd2a17823b7e2ef4948b984a84fa0ac22a82e5bc9d5ea771abaafc58922a9a72b96e96e363029e77f" },
                { "bs", "665b40775bdad786c55222f856a2ac643eb0fd9d684cf8baa5cd228eb15007bd08827799a21a68f6cae439f76847388a170a7fd4950033bc675968bafa041e27" },
                { "ca", "847305fc4aa731ca54408998fed0ad20c189e7b93591fc991dc0a3c72621c3674c0d304f2c9b6fce5bde46f94bbbbafbefd8fbadaee2e2cf533b5293f8694a32" },
                { "cak", "b6820c32555dc3e0257b9963ccc1a7b5333a30bbdbdf895e444d28628dd7e86c9d1ad71bfdef13c13ef593ef7ed538da8dfb1ce87abdb2ed83bcba3b671af00f" },
                { "cs", "92223a41fee26e3947bcb1aa972a24be8d063d75f854c63fc54992142667d418eb81a8a2b56c3e77e40317ccadd546d460a0d0dc68488ffaf8e60d60607c64f5" },
                { "cy", "02fe1833ea7e1ebe52cfc3ad8992bb53d2da6e33e35f276d6b937e1ed854f2dd41c40c3d97ab5c1815d5e84661ada51b0b42e7c8478131deaf3c69f81a156caf" },
                { "da", "e880c4b1e8fcfa7e97db77375029db2fc0614811f427dc863e1f1b97bfba560ed23fe514e5875c7397c47d60b5cfde37fcc53371ab18ea7e9dcc423fbec6dd60" },
                { "de", "163ef0f29a1848e21213f0c1259cdd6ab42eb34cf3d79866c7340ab979c808c0abdeff7a6cd3e11f5d05ba23dd529c800ddadaa060d389ccbef7e967fda76e3a" },
                { "dsb", "0af7765b350a31fbffd8e38d58bc72c825c818131fbf4da5c27680788f0db95f363cbc42acfac4d080a37901052e3b301f72226c11c4cc1ce46bf604c395bd9c" },
                { "el", "c8fbfec76693237c8a1a5eed8e70cff2902a2e27c0dac7d91720966c345d1ab23d717c12d17f25847b186913fd8a0af80441e4f87a0c1623a53c7ebd4f8bf18e" },
                { "en-CA", "b48f0c4099d7cacae79a0524f314d79c06d2a83eca632c5db48d42101c0ffdb54427a1210949d7a340a2c245426edbfcf0d6f6105d4a3f253f503ecdddcd607f" },
                { "en-GB", "7526acfb48f0ef64a64e9968991b702e093931ae2dd9b689d3cf41339587d7c7fff23fd505190521b41bd6e1ba69c7e15c653aa3e422032251bd14d2f47787d1" },
                { "en-US", "9ff2214792331b0e64e0dbfa756e4063c9331a0bd055776a6e8b899353710b33c2f57a3dbf1b7687aba9b1e5b944c7d1d98c27924db906065fa6d672189c64d0" },
                { "eo", "4d062b46082ab2f74a9cdbda8722e5f3c1308998e10caa2d4a8b6f753f3c7d2b793952715e4d9bfcbcb1e7435a2700003d2d7ef8536435c432a723a8daa676ea" },
                { "es-AR", "49981afde3a3577b096dabd86fba689e8a081271b56d2b9a32e2ff557a5217d2ed2d434707f7458fdf4c464b6c85b8fbc4b59c53ce02be050e594c2a932f2131" },
                { "es-CL", "518376794e57052bf84763c84b88277d69c966fd09603f118cc46732229c0d1751f1b7407d104ecc9a6bedb0c0f33cf43e3c375ae9e12ea9bab3f0e5c8b00ab4" },
                { "es-ES", "ebc49051ca784e1e8c2e49e7a74cfb8e2ac2f5e84cf4412f1467a0b85f4345aca50c0db842c343124527413ea79ec4c158daf3b1ab87189e5a87ce8e117049c7" },
                { "es-MX", "2ffcad82dbedf0d74e9a9691780f089742303fe25f9f3a93f420e6e993779c1f68771aa24faafa3cffef3b16df45fc81aecfa69d3b5c20b3f76e0c69d2930e52" },
                { "et", "285c727ef2d3f633f2ce4717ae00d41070ba2b168fdb5c620b128955fd5cf1963b586cc4216becdefc440aa91c50c1fbcbd0b8a7ed647a41b22cb1338569da60" },
                { "eu", "b76a86cb9f6039b0b98432373fc04a9bf60c998ffb478b3f121ab7fb534a876fbcb5f720ec6f4f0ed17d7cb2275838ed18b1e12fa2e80f76c66b067cd31d25d2" },
                { "fa", "915f77213466982b3477d91141ed30d093755a0fc092b6b25cc82f760c3065b97b6e13404579e7c1f04ed7d280ef226fbc6f6103e0b490ffdea9f4e309578d7c" },
                { "ff", "7cbfefb75f32f119f56df1a988d2d454c35c0878cb86f467bd37b0af07a4f38687f10b1d096a4441a9847b88d8e48a16ecd9d960587da7daa805bb00762007a8" },
                { "fi", "46cbefebbc344c428a7be48278e859cf721e6b304295471937f0228899278f384fb1b4bff22d451f8f1efbd032e8f6b7c51ef92fd0a482a9d24d5f73d8675d1a" },
                { "fr", "6cc569d6d9f71a2b80329b5b2f2cfb0a7a371511938085d6748228ebdab48a3d35516469c9877992f33d6717241194e8031e52baf972ebfa9a2da22cb144c0f5" },
                { "fy-NL", "8568648ff96acfd12311e5ac83c70cd0f0956e038d1568c4c381914ad7398a56d2c331b6a64c639368aa56554bf31dbbff9811519e3622578964d6b97c9e1e80" },
                { "ga-IE", "245ec5ec42a34004af76240826e942fec902dd4ccfca075db5f29d2188b2c9a7b1e1456666e7ad833ecec7018aa57b1ea3d3efe8d4e64a996e565424d3ea58e2" },
                { "gd", "2adf2af715f4b04d665addb1d210b902707cb89934f9d57c27acae753ec216c402ecc353b2d53c1561262cad309c0bb82cc88c9966e29c5627f008aa67de05a2" },
                { "gl", "916e5a0fc78237bb5fb9c804259f12c7d4b4c02554816ab45bfa8dfecf0c98fa15e317e49831a2ae036d24ba2b4d4b47b5578e5b3bb082e7a78b2799c27e2ade" },
                { "gn", "44b774c1a2ff3f65dc220c7da697223813ef0fb605ed1e11e9c72eed27fe0f9091b0727ae1e122a6146b3bdeef74583076e9e5df061a01d97fc217f53d2623b1" },
                { "gu-IN", "4343fef023decde47212fb8f5593d5dfa4351e4a22df7871e7aad43808598d1f837ec63e3fb7962774a7b44f159358dc3ac0be4e0728cd015db975224ab814a6" },
                { "he", "a49ba1d287575f57524c384881d08b2d5f666231103f87e845b985c18e2845646ee095b8caa3e837ba13ee76f4625c131d8168ba3670cfe358b6dd1d89ee33c3" },
                { "hi-IN", "a5b0c2f141d88b5eb0d050d973d5f6be6575eac0c41470612818c0a82f964f1913daa8d165670b92f8bd408240bb64540f02ac172922f4a2982972ee13e4ddf6" },
                { "hr", "6c77437d802bc7d9bcdbde8aad237a1d253fbdee47a65525772267145bd1aa61628a6b017532e3d22a1acce9f89c671a3ed9c2f3762decad7811a78c96ac1a6a" },
                { "hsb", "c5d3ea361c35335b1333837df0bb66e3d4cafe3180b712974271ab090e4397493fad9d6f7c6ab5f8387d9558de750b97853670f07c64c2ea5f2e442d0b9c47b3" },
                { "hu", "c9396c7eaea3f262fcf0e3ee58843958979ec6a91f94184ea12908c58915f54ecf1ff47fa9c216cb89ab0fa1c6cb04a3f707a5f90d2095995b413dc84333815e" },
                { "hy-AM", "0b71c2e0e84c1b02ab7e8c428ef4c5cfbc17f81a8d4707a4a6a5b3607848f235c1f1750a2de1667a69f439c0f6683a9d30d737eb90a03179376cbc2048b824b9" },
                { "ia", "43056efc5fc8fcc82a2e4462cd5a24223a6b31db0418029955d0927a9c804ce0ba950bcbd3716072f15aaf4cdce9de946a8c8ef4df089194546acef99930b4ae" },
                { "id", "e96500fa03387b53d6fae73774acedcf11ed819dca857fe34f0b7289804abbb76700e079fecec0576049ab93e6459edfa0e6dcc4b10c47217b987eed53bfeaa3" },
                { "is", "ae289614da313494052d5e8a6039298c04c586a5b6890916c38000bb83d43258c8480e0b2398be46f91097b38c9bed07199dd33f49fbf7d62b1eb5165787d5d7" },
                { "it", "e20d4e15c42d466f5caee6c5de8270b4332b26e32692a229902ebf2edd17751a4aab7cfaea86bb4bbed4c42c993ea9757c1774bbc6e324085e4904fa59148095" },
                { "ja", "23328b510b9dbd6268dfc5a5b470131b835222820ff8efd7dcb58dbf20581caf06f33025800a59570fdddc917045f39fd18e03bc1c425ba959270be085ea7b5b" },
                { "ka", "5fd1812850bcdbd7d4aa9553a65765f755a77b2f31029ec2adb68bf9732b7c517123e1fb95df90b714401d28d36a8f5517b331761f1dff7ad551579e894a45ed" },
                { "kab", "81ee94e73bdf0314bf6f312857cebbf23d53507edf9fb2b0a2d8fe3e2c030e49cbc6a21ee58a4600557d47c43e0d7f1acb5174cc482aa61793af864c2ee8fbdb" },
                { "kk", "49e87bfed7f8cf9ab94c2c01a578365fe97d6ae08ce0efc16b4c835acba04f73f8ddb7844d9e258d749d30140a8a2f109908b55e6ed823c157d7cd7c7331df02" },
                { "km", "9e38329cd468406a853f215fb5f8063e1e25a7fd8be96be0694c9e281d8528f31b16c327060694408e9399fae2483d1c4bf2ace752684c77b25f99eaf317d481" },
                { "kn", "933653566d272abc421477408dec9a9ce39a2d94381676f747275619b512b964fada5d909b4bbb27e15a3fdbec66d1a79dc810589e29c53e52a4d939acd6bae6" },
                { "ko", "d249593495d9577bfae32f426de1ce73a1619e61f42060760b660271ec40a1d512456a8f23f8fab28b1c7eefea8a897b05e7475de193ec418a91117c1e84fa64" },
                { "lij", "b470a416a8595eede4c1e237ec897ff7f3b9a53fec9f34abcfb42a075ff7c764987d0377ab07415b6b78075abe718726b4a2ce4833083e09329ef93505810674" },
                { "lt", "af6ebd2d1a2aea080c2d8b93e92d62caa7fb3afc2e07acc39fc387b39acc0be1c0bad8abe54f5f6c144e23f48d70c285cee49fb61420aa833c00342370be06ad" },
                { "lv", "b30377625281522b56c43bf1d61a5274d713ee3820b43eb7d94b48b1af2eefe981b2fcff363011b5af48c122067f36b556ed99dfd27091e2e6a8e7598fedc988" },
                { "mk", "d5f3e55ceb3fb88c053b7393a80ff003a0ff75864290231da19a98e26d37b55451bced5ec034bfd585a7a917197e8d252a8dc79894e7545b201c2034260ff144" },
                { "mr", "c9d7fc588d82bf07a1cd8ecbe195d156d6c8912386c1d2a85bf076c3101b2129278a7d7608a220dd3ace544954eb42c520f85d800201f004b0f22ad30b044985" },
                { "ms", "278482fa30a25e0b507be9d0e6000cc91943137e978db1f6202abf89950f4bca8daf94cec2cb7d3be24de0672347de994b3aae20eec43e72a3cc2bad602161b6" },
                { "my", "50cedf1ede79f7b5ab7f8322ea04381a3d86daa8dda7d7def5e4fb822b67bd92e3be7fec748b33fdf6a542e4c29c638bc869e856e2cc00c99768efa7a6ea03e0" },
                { "nb-NO", "8b6ab01de4c5f1764c866c365e1aef61e3e340fbe76848f8831e15fecc30397b5d968b6d115ed1d4d1becf333e87bec9433a36e6310706cfd1b56cd0d5275d7f" },
                { "ne-NP", "044a5534d0792851283283faf5d45bc88718eee51c60c837890ef8ae154a7da2361c71075e6918c2094b5bd4fad2f4cac24be9ef59db6982a8b9da6156a6f8a0" },
                { "nl", "93f1baaee94a78eb5b635c0080377114acc5fb153e24fff9069da0fbcb55059592bc2265520036d9a97b5b535c3a564d5bcb150f4e127c2f0b211b6cc3a77e83" },
                { "nn-NO", "f9ef8bbd1e17530ba0b7054e595dd2b5de0e91050bc455e2da5931537898caada5048ff657d91079276421c1d9775fc7d3e05fdd056d276e60ee8a9962c38676" },
                { "oc", "d79b5377855ed630ee81b44f4d7161f0c6f83f926162b67ee8efa4b38119366f07e3c1cdbe834fea21308bbe105243bd1f7059cdb07f9347b2444d01243a4d50" },
                { "pa-IN", "01dcd1547f17e67c24daff0b4aab11b7735e7fb5ea443b4d27e40546f78d97c96b246e64522e4dc66d212c6681ad46d6d8b95fd41def041a3777323bbeb10c5e" },
                { "pl", "fa1e82dcad5945532cb3f8eacb0f50c426ad1935d82e91dba9d3fd89ae96f9c57c70d3c4e54e064c8a5ec524d3a1032d788c3f1c076186231c1bef4a791828db" },
                { "pt-BR", "e1a57c3ad42c9bb3d770311064647d415a3f36270a8f46ef13df6d9fe16c49a1da5c4ab5ad79e6d1863326c531b03035239659abc6567387ff2e95dbe87e860c" },
                { "pt-PT", "81ba625e343b9145425d448988ffb3c7ed4e82576971d41361445ece0673afeea5a1757406f4ed282d0f78c9a5b92eab80492789637d592f895365f1ecdcf09d" },
                { "rm", "36abab46624525ef871d84c2b29e75bc194fef2073ae127aa07cc72fafd48fa9f80d4e788e3549bd87d586a92356ad0174f9bf4865d9ea3c60a641fe4679b4fc" },
                { "ro", "79751d127b4b16530bfb1aa7b425ae8bca0ec8cda133803adac8f34dd210223652565aea015b507533ef2e3094d96b4e640fa7eaa53590db24d49c545d280ffd" },
                { "ru", "5bf78c70985713bde7ee19b47e3653a847042d7678684abbf2b2c0e5a902fb68e3b6e338399ad42596d8c316d255a75989ec7bcbd21c37f87f5c8dd0de15f8fc" },
                { "sco", "3cc9b19d2177ce21ac6d14a6d3c217566d69c7ee1efe978da8e8ccacf495e6cab6b1cfe42d00304cd9fbba5262e4967ec0016640a662e418cf4d6190ffb163e4" },
                { "si", "2eb0af155a13bfe3396ca74eaab57f4e57bc67773abd70700ddd6b6afa98bba24a24462e343c71adc4c5fdb42a52159d5e6e53b19353b47a3455a69d787d603d" },
                { "sk", "781310e8b047e4db24d3c7210babf93dbb2035ff0c6df3b88e52117c276b3f4087b9c382bc04e7dfef695f5741f1420158c479c5408aeef02e080f5f39cb584d" },
                { "sl", "b50fb7bc6f86766510d3595b50b47af92858a1eeb0bc8fd05bd5afc649bb2ecde467534734f0aeb307cdc9fbc5d24f9371f1e55f078b35a5f5a538e0ddddd637" },
                { "son", "c934b464f053a1f0754e6de20ca2e1334b1d401c34f321fa98465dfc049b8dd8ba11130895196e4e19acbae30314d9e136cc12f7d9c9bd5c16acc2244c5fa745" },
                { "sq", "ca0e69387fafaec94ef35315ee372fc9567c95be4a4359f3c9c6272af3f28bfbd05d4bc7feb24ee230de34da778f090b1504658c256a88aab5fc252d4a043897" },
                { "sr", "81aa997dd28558e23432363ef8fbfdd6388edebc14c7636daac044f6dcac2d83ebbcd31c6d366960504d50c25b6133f6d885e9cd1c147d97370f58db276af5cf" },
                { "sv-SE", "6592e7bb799d788d1ca4b931670dad65537b2381ff396cc86797addc200275dde2d1caccfbbd40ba5510f0c9fdb8ce97dbb896feb903ce40fb54ef3977b0f95f" },
                { "szl", "1dca73dacc2119e021f2cadce812eaa56df35a0e64affc99d67fc0179c0eabe0430324c19aace9cb3ae5fe394454147f35808d21210c5230a43a101acc23e70d" },
                { "ta", "205971e67c19931e6e9e37dd9693a32c5c21acbf543de8552ed503f75754f0e031bd3b80eb70fa8786a28dd46c64dfc61f9791027bbd9c5d41acaaf7b29e4860" },
                { "te", "e8f2e2c8088a5fc83a291675da6e12a7ff27c123dda56650c41c0232e5b981539d57c9dc9c88162bbdf12f389dbed6aa2b9a4dbea45b7083a155dfbcf0b41c6f" },
                { "th", "5f3d58055ae2187c2b6ee61ba53f9ee034c68abfbe9de99e2c0a8a9bd479b54b3c73cc08aaf0f68b9236d2c8783e7af97d394d2d43a850e8bf45adac76277fb4" },
                { "tl", "1cec6dbe34b2163d362bcc2bbdf9a5db08e954d98c2a082fee448ddb7f253469e51e16aecba9aa793c75fff810cb18a2d57fa958006b30ec1d7627fae9d391a7" },
                { "tr", "10cc0bf5a35217d776232c391a421f36ea8983b013019bd7f86a5cfac6f4756d8fa34645fb62ee8ac23f1a655f623e0d9f768066c22e33a707e5b43eaa478aa4" },
                { "trs", "b0eb386af138b8a6634eb940280f39cdea4c06b84744f3673eed015372e27f67e70f1f90ac1d508fa4039c2c00f95b8f2370f1828328e6b3662d1f26c106d960" },
                { "uk", "0d1b1cdac559f2719c0b39aa23bf27e2b1deeac84c1f416b8ef9c26e2ad69179f3fa953ca6e2266130b35d286b316184e7e7d4d6918d75b33509d62304807358" },
                { "ur", "15982960a6c56661a81219db589a9c2833a1c6338d9385242d4bb60392c3a154762b10fefe84644f22b28b9d0ec7bc80c2d19e76f5579929cafd14e790842014" },
                { "uz", "457deb3e48cfe628d41070c298c22757deacedbf9bb076b6c65ce3cf573d4f8ebe749f163bbb0773c8d25b24113291e21ed464aa29368ef1ca3117d9d6131221" },
                { "vi", "3d19dee42d3f01c49db21453fc233e9d0e17791fd5c85cd94ccde7ca9894f94c3988b1eefbf71b4af0be11de026c3b6899ae53c40375f694d40e693c96d3292d" },
                { "xh", "8ff6275dd53b3cfe5920405e52d28cec5f0f02f92dccc6c00cc54c5293d703f0481060cbf164747452d98085edae67a4c50e8c4a751076a7cc065360da8a4e49" },
                { "zh-CN", "31286c4b52a3678e2b7099371a6dceab3b2531888ccbfebaeb6bedeaac9edc0017fafa932397aee773f43af557a3907e7d2aed2aa82a8f4c0ea423faf6ba1b4a" },
                { "zh-TW", "6a6c2bbfeee6611b467a42d33a7d28215d71205b5da25d895f7071bf5194c786596299c46958f9bfdde0963378ac05de22afcc162e25cd3895e03c4ce55b7bb1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "a4a3de0df05d6b50d3f3d571751e61aa5dd3f5d789af9b6b5c61528a00cb384f8ffc73760debbf214b3b19b5e6908359cd3320502208fadedc272cb236ac6789" },
                { "af", "e0d46e01bb850a69eeda8c3ecf4e1237b70907c5a703dd55a4162ea62236bf87d3fd5cd6b01af2c55aaf48e6c6a070c1ac988e5b40c14115fd316c826bd9c49c" },
                { "an", "a223a0d6421c75f51c23f98f1f9e73bed1868ab85906da147a570e5fb6eccde1c8e0b05fde948cec0ee8ac8b80aa5ac404f6d4ec8057b6888fe6ec1a4579fab0" },
                { "ar", "409c629d22613c2ebc504475240419f517cdf1a39bce2b9bea9ef85607941906dde7a6585667f42caef65fea536d5a49884a3955ea7137c3cb08d3ee5edd3445" },
                { "ast", "4d5037e57c72f52c07e99e3dd20e7312bfa672aa24e97f9200747fbfb833a227f2a48dad44b32a00cd76f31f95275792eba11bbd55164d6216c0fadbb1c1a030" },
                { "az", "2910590ceae3567f5ee0b0689e062733a1ff623b68d44a8798912a469d5b85a81897fbfd1adcc84a2e888493d037303015276bedec4d8d4dd98cd1bee407d12e" },
                { "be", "cce6d9e90941b81c5439fcf26dc6a6665e72407299a58d7ee1b9d3201d037271f5f72762add03defc50e4fc1cef9412e2ca086b6ecaebc2531faba0535d571dc" },
                { "bg", "dec96180fa7235fc78f81a4cdbaaa5100135a6f3677e266f53ba1e584a2eea56aa333a6698419f7dff5d4e94c7de4185c7528f32b6c0d8946f41b1ded166243c" },
                { "bn", "3a49c0917ab1501ce8307454035bad47d2d8fe516a6cec72d4deca50477171c6d94c04daa1f62030d2dc17b236190cb0d04acaeb2ddba8ecf44398f32ffbc5d8" },
                { "br", "b4e6f3e93850185e1a7d93925e5f046792aba703d6a18794ffbba4b2425d6b8b63f53c135a57c7bc5a1ecf773ae10650163f6259144ba8f5fa3f19e9c7322a6a" },
                { "bs", "6beff73c1b2007d296bd2af4dacb7660ee1d7acee9ba84f320d333c25adcd52d445e9690a103cbd6316c02490f90013173529b5818ee0c5277f3c0de57979da6" },
                { "ca", "6745f5e59c658ea81d6286a120d906b01f2c1a65be0034d4869ddb5b11baa0a5d5562b1c9976c6f9ad3c7dd1939aa5ddb95a06d17ffa012f74c9b97060e7bf6c" },
                { "cak", "80583ddc62cc26ff931174645290c463ac529f0d45f75ea2a5de7648f8029ac864ef81725772ed0641074beea486ea07045bc76b69e84799ba5abf465d4d77a5" },
                { "cs", "2913199a26f9f8684089f0476f5a817417c5a3e851b39c61d64118c65f9d611b39f8b06284d61ab282c7410a557a9fcff0d89ceb2f60d817d7bc48dd6cd80cc8" },
                { "cy", "af4a85806478cbeaf3f4140fee05d32f575997abd293773bb97426932196e11dab4cfe1f1f2671f378dc178d2940cb3e0c4040601124ad8331e075861b0cf5a0" },
                { "da", "fabbd9cdaf123f9b94e53d08b70ee95adf55be8f72404fae998b2c1671bb153596cb8756dde14f2085e56898ed6142d256252c1b076d2276330f1db47a9eceb3" },
                { "de", "2c6e93d423c330916056f72171f40b3154d81e6c05a21bfb80606ad9de02ddb6777f4508791650fd4476e66d9e50a5e496ba5b30033ee66e4b32e4690e93cf2f" },
                { "dsb", "3ebeb86e731e6f75fb8d8c32ac9b92543516148d93dfe6c681a58f23a83c262b78c236f574fd08e351283f5c5fd158f00ef2c7749f7646fb843ba3c18ec3142f" },
                { "el", "84f5dbe03dd51d127f44a1a1d40ddbd4ba52f37586b9b32725a7e56388dcc1ddb0019129c66defb05ac1f2dbdb062c63bb8ae7a642f2ed875fdfc0beedb1f583" },
                { "en-CA", "11bc1a2d1df5753e1d4f3677a88a9922d985814edf9f4016bc87fc276090d7534a66b59017669163ce889c02a84f07ecd60859f2ffea54224e81af9b5a688990" },
                { "en-GB", "a86f41508486f7129ff5d638e57fb918e73bcd0813988519114fb1fb67135ab5d88451d45ee1f98c4b77be3450de40d7117c327ca1a77d026a6a8f3bc7879157" },
                { "en-US", "5a9a00417b0330df13bbd9d7a9ad40aa332decfe6d6940da5a257e7931869d0d117a91556a661cd36de905f2f0c2c7286955623b03fcd1731c00c3f0339cb30b" },
                { "eo", "694af34cb386b898cacf4329a7121f92640cffdcb475445f2d2261daddfb612a41ba55a9e3a86150d4949b981f2d8dd597d67626c45cdd7623abaadf63b28cbc" },
                { "es-AR", "94929404bb2605d1bef49d60939ed4c9558f7ce5b3dc70fa790f39928378c796323ae9b647912ab06597b32f3e8a9b9f05dcc536e38e4e7c11a70369bc975f77" },
                { "es-CL", "06d9ead99df0f82d656c8ee487bf150494354c00ff142a4b591db7ea6e4782acb9317fac7a573773d3f382396b92ebfa8070fb48a00246767384d70aedfbb23c" },
                { "es-ES", "dce75108f85e1e42f5b9cdc1b9d03449fe5c09f110e751aca8784b7faa0baea1d9ccc7624cad453d5ebc98f75ce94a8f46099640211929ae64ea2296a3d3f2a7" },
                { "es-MX", "2dc0e54203178d17af077e65b181e9fe227034201d355de49c8d45e6b8c77b62a507f3251faeb47ef5cbc86e59ce74c1705c9e6dc6f30c75a50d4e32d327cb6c" },
                { "et", "cd1ff3bfcc86dad7baea730c3040edaf70594aaf399409a6ba0ea741333c2baf9b0cc99abca03291a0eb69f57715c904087016b4985a83eb3102ac19718ab3db" },
                { "eu", "046d58b26b3e788fe76e1a9edbdb8d119860d592c1252422fd7dcc6b44061e5fafe59021ff5338aee21d15bc3aab928b4a2742ae3518d182c0edd1722da15371" },
                { "fa", "f0e543055a771e2281a26d14588f9f80fe7b3e7d72eb9f18c3429a5d960e5016cc993b0fd8fe3ab195e5aa47598a6b1430dc90f8953e41c7b7112f88699ca518" },
                { "ff", "bfb1e0ed8ae67c7574c3f2338b323bf62a168d83acf05882becf2685b985a62eb046da560a3e0fb03146cc732c8055401c69f8f97985e50a357055fe9912180e" },
                { "fi", "9cef76344d8ae6aaf495e24dada14e5b452b0da277c95cf059ef4f374afcfa5dea1e9b0ec3fbd8cc2cb80ff32994343148d596e7cda4354c021dea7c53f95a88" },
                { "fr", "afcb0111dba57b1bd80c566ba509dbc08a88200287b70d51c7020dc5b6b98ca5157455e991729d7d9bb57e74572950ec20b3826350e45fa5ebe613e074fcd366" },
                { "fy-NL", "98f70db761f5aee85b255a91f06fc0334d9b8ae7ec9951a86d56983881fe94e03e356c3519fe49414e1132364575519fd54a2ab78e562a6e0d09749714f749f4" },
                { "ga-IE", "dc155ff95bcd8d28b0ac247421fe74b9d07eb325c2aa3f662f28ad0f93972dc5643c656093e7f723fc415789cb8e1d3746de615f27326d4a8a17a4c7e0e6688f" },
                { "gd", "a667591bd92700918132c90194929b38a889c6f42587eca8162c9d6515e59d491cd27afba7aba0541deeaffe9f1dd80b2a38fa004c3c250f8672bf3ac2292a2c" },
                { "gl", "c6f487c064250dab9d9c8790729760f0b8dc159a464d02e05787ac61c5e6aa702bf205add5b3ae507c5db46e093b21ba4176497b9513d5b19300e1890c25d95d" },
                { "gn", "e21e866f05b88f92429499d005b27087970e1a53eb18d7e2689b73014067c0ca8b0e9a2e2d737913bae2af594a5b533945723e6dff5dbe7a006e4a6a3ec28767" },
                { "gu-IN", "c94337ad5d970694a9d1c0945eb74575c9fa922b0a7e51fd474f66e60a71c4236a34d7f21e1b4803516b144fc153d84c33d79ac9872f30beb218fa662520c636" },
                { "he", "b1b8a52864d70ca89045f917c7e6521aa93ec2783c0170ab0096ebfe02b89a8bcc746a43b6c12bb75879069df4fdf9cebf9d29209b571e22a8555eb9f2e96577" },
                { "hi-IN", "03616f57affb1889d379a0669605cded49c0a7402cf01bccc9fc11524767a7f2921f477f985951a5bd56ae876ff7adb900df1d384770fe46d8c6eda8d8044063" },
                { "hr", "0fdf5f49e40ef0c3e667f89af1cf54f8e713e8eccdb07435cbb2c95b15a6855250576e52210df0e8e9f6b0d830a1b8a422fcb4e5592f8e25cefb57887bdf1317" },
                { "hsb", "c3abe1da59514861015ac652093c58e1acb6ad54b4b5bb4fccbad6ebc09549e8b12b3716dccc956771e4d944f3773ee023a910e0eeb171b8afa99caa4cb6d496" },
                { "hu", "c6bbbca3fde359e5c713988e5c16b2f7f89020c425ef542d456530478cb28c79290825be89961758abf242f78a171f8b0360ec6e2aa8c8ae8b83642a97af1e3e" },
                { "hy-AM", "c4abe294164fb98d194b29344c837e7f2cb99f272d9633631fffe6180ccde6515c8a9d1077a0622de6b40babf4fa4edd452c27e2513907719c50366c08f92a89" },
                { "ia", "1884309e967afa0b8f95533271a85a4b473dc9b66592fcfb9f48b42d591081a69224a608e6c349cf93490b3b5c83318c5304add9ac71db5e257f5a3b61c86a38" },
                { "id", "d4a048fc0632bf08b873ab9a6cfc0c3b4771d9aea8e8debc13a577b6eec60f11bce796fdd3d38c2efdb5868f66b7438de5f4b242a8fb097f7a96ed730e10edd0" },
                { "is", "60b00c14b71f4dc4d5d49ecff4c308abad74e572a5df135803a76aa209970ed40ceefc917afcea454228eec45e53d3d5bf1ca56de4b352f0caf63eaca4195099" },
                { "it", "e5e4c246ce372edeb759d4694c0f005c6247759d5804c5a0888a134a40a5cc42da68ea608f28c6a83d1fe120c4bbfef3a66609042c20ca916af69cb6b6780d38" },
                { "ja", "1a2fa4a99a678413a50a1b638b927660e29a7c1138aa0dc8d9a9fc563b9780ced05dc0a7e28419312034ddd9eb086f8e7215f8a776625d79120f1736d605642e" },
                { "ka", "1c510e0867390532f403baecb071660f5c74c316be5794d71d163019f54928aa329c8f44b668a7ca2b12ed85a627b5deaea8da11238c34d348b9d20d45780c18" },
                { "kab", "81e3b0169e40e535b79557fc75a7b464a56d9e4d95aea12d626319018f7bcbd810931871a34db761915b5eb9daf1bfec8fed289899a67eda09fea1dde2870260" },
                { "kk", "14e16d23c32c111b5d178aecfbfd5717edaaea5ce2e15d3e1b08e2445270c9d25685481f1a333326969654e943e74f9a81059ec09123e8ccac0ebfcc8990af95" },
                { "km", "e65fa7e274566661fe729edc6ea1844bd4aa2ffbf19482cc2225ead340f87a2af34a63bc9a0d2e66a5b1b404ab89552ac0df741911734b2324209494bb289c58" },
                { "kn", "c5e053fa5fef908ee50bc72a30cec0b9cd625378b20315cf222eb060e20e80350c898135e467359d57ff3ae7edc771c667d04bdbb744f304388eb7a8921e2430" },
                { "ko", "564dd93c703bb7bec0eb2b79efbeb41a9a42a0debe6fccf499cf2ab6707e2ca60019c7d3815b54a4ba2df6313b8a9ca59347ed7548f90cf757c3901f11e0efbc" },
                { "lij", "0b1a9bd6387a1f1217240ad6e65e241d73043240fbea5a59c8e8864bf6f1d3def63816081f4a17b27a46e9dec251c5d491b647347b09a024d4d0ed386df8bddd" },
                { "lt", "494ee0fd0148d4c4d4989b527e210f82e53413b4d0a2fb94e9a41e0041116a42d70b0546648a2a429c0f26bf5d11f39ce49aca0b7978f9984af6d6d390faa869" },
                { "lv", "a62758d1f82d23c4ae132cb6d6ddd0165900c06faa677daf049c82bc9855a0a68f9eefbf8ad12e628be6423a89b9ecb0fae4016821a05028cc60be3d3d480ed4" },
                { "mk", "d23907ba625a95aa36db372386946dce5732801c2862786906f2bd3df37382848fc30f981e96b2cc2689bf1f24fd4bcbe5826f2f8a74231aeea1b2871731aeb8" },
                { "mr", "a121936b0dde33f33146a5c400bdda7612ee6e7dadf3a395fd2bf04f11b45c4ee8fdb0879528287690ddbac998b47467b66210112ca3a8946234fc4da1249e5c" },
                { "ms", "b77cc8dac2407fd757e3e4ff724bb03453799223381f8784cac7972c097e9209eb4b6330ae31df26e78d4ba4a8afaa1cc8f319a63ae90ec9a9b4f9e16ff5b823" },
                { "my", "802726cb171230b053776b84827f7ffd0984d1ac876463cff87a90a6fa5b9abec4c6c568d581ce2066d4437b0c310fa5c6662ac61388a67c0122ce19d01eccf3" },
                { "nb-NO", "4592f0f0203965dec1131d84fd6a596f371863627a60010229d264bbbc57455366b16d38827092295d7cd4dc71dc8071b3e1812bbb1a522b31b88cacaf58bfdf" },
                { "ne-NP", "e7fdcfeb6d524870c331d371caf0fdca31fbae69779c451e722c091256d511951cacda5563d17ea15fc88b39f3eb04abdc4be4762ea4edcce20bc43a2f6332ff" },
                { "nl", "2341b9cfe1990781afd86e95082961243587139c8827ccc3961f49b824d4ee00bf1bcd4a9d8a26892ab3c909e0926c51b39a0d36e2bd6c6d78945cfac423f7b7" },
                { "nn-NO", "c10a7088d0fa2d27daa2be607a97ea900bbe385b706f94908c52d936f9f2b7d76e0586bc7bebc82e73c97e98df40988d7b7798341dd42ebe4ce455ec8983ce94" },
                { "oc", "3512f8507cff9982d49954458133dc0718343d3294bbbf204cd578923af4c0ffc9e7a56c57a337db5975511f55ddd4f22fec4eacc5bf211b8618488dae454644" },
                { "pa-IN", "cc50bf3a48289c77f69efceecb33421a401df42a7d889f7458ffc63c4bed219390e6b52c38cafa5d5d0532a21f30d6a51ded39eb4f95958ee751d483ae007a22" },
                { "pl", "92adbe5a7a16178680a524b5ed5bf478a81069c8fb8c82001369717b8ba8c73420334ebc0be7db855225792446ede5edd559164c757b54e1088ef9c054703309" },
                { "pt-BR", "0e76cc17a04b3b8a3e2c4391e8ab46beaeac1ec570f73ec68cd044ed8ef1a1367f0125693d866ad296e6ba683371e293898984c553aec31d0f49184511a4cdf1" },
                { "pt-PT", "28042fadbc3bac40145a0ec17b808ba390b4e52621bcb0d4e8f01fa21a8c5dbc1aad72c0e5d94bc6f05da8ba308f3c0a46b8b727538406b3e882fbc48fe5f054" },
                { "rm", "08e331aa2aa3609f457253aaa25794d9586d7fbbf93263af8276a26ac5a22ae3c8c6f4a3bdd7e8b79ad0f65f0b5a96460b750b154e6db96369417e3610873314" },
                { "ro", "767e4af96e57099957294ae9e5a56c1e39566acc119fb919d97bdf615b3cdd0d9371a3d7d7dc97ab9a54e24223736ce75ba4a1b94881ab4b496b07ba4f5470cd" },
                { "ru", "fe82effec7b130e1c5455462dacdcf7fc7083930da19a27604f8b7b05be3348f9030900641b50727073a3f774318ec3b5cd7ab684b1a41865830978d0ab53f1e" },
                { "sco", "0d3676480e0e6040da9996455b5c03b71b41066820f4c0d5516f06d9ba7dd9c16065a882ebffbc1f8f469a15c748822a53debd2bea5087603feae9f21059a98e" },
                { "si", "ce7dc46a0592c5560d88538e08ff713f521b9310363869c05c2903de89af8a6f0465627b32dbad9d9479dcc1200bcd255ae0ed1764e96a8bda94453b430ec745" },
                { "sk", "dbfe6ee49333a0b0d4e0307040efe511ed8263184050c33aa70472ce28bafea142368a7cde3cd8ddad2669acf2b3352e68c37521088232df1edf234f9bb43f99" },
                { "sl", "bbb998ee8dd729f05d07725606dbbd44cbc7a11c025706340040ec0e8c7bf89880db644d9f755d2ebc030d2365d6b6a8463b208f3c55f3b5d147fe467c2f97e3" },
                { "son", "aa84d44d7f652e70c53c713fa47c467530ce43302212553711340a527609d2327cd8487754c0eaa472816817134ebc9b263b819f5566ded0b8ce093172122772" },
                { "sq", "29f68012f10422dbf9a49066b052b43fd9a4dbe78543579bcf467b03015b668a87e25bdb99b1373e98d22aa87f05a935693d0ea542a3f6381cfd5be781d7c8ca" },
                { "sr", "c06dfe00f94513d2376bd2f32359d74e3fd33bd9134f2093ac9fb1adb788027a60ea7fd414072db9ab8d7425f4764fbffb5f36d7a017fba40fc732f314ccfea6" },
                { "sv-SE", "fb2da6a3705e3853c8660bac79640d6a70bc107b26ce30ef961294f3ed19b5b2bdf2189ecdad1a75b0a7d881f2ccaa8a04c20395110b4a31611a2898265084bb" },
                { "szl", "75573f798174e8dbfa865f543790aa35be0a933d16069c4cd6827c2c5fcd4859fc0ae18192f868bd0cac98bba82f2b92d69222f7aa1d1524e1a5fbcff45501d7" },
                { "ta", "98f362fb12f3bb3b8b732bff7117d41f9f1333bcc022bb4e177b6df7f26692ee6c5ab3613f3cce4493cd36d9207b9e8fbbddd012d2952fad867fbcbdb096c193" },
                { "te", "7ecfafbbd0437ffe136ff3e6578bcf2c2fdab6bbfa667d942adcc6b86ed603fdc2ecf2848cb289f39ece00903e67f3091126f37e751a143ea9611aa5bcf9a3ea" },
                { "th", "5e8a9c4c99030623d1ffa0829b14c8eb0481691fb535e52b716f73934ebfcb408332bfe630f0ff2fe8376ea0f497e42271fae7720dc2622b0b9b80d97773d1e0" },
                { "tl", "4b45da19ef60bd5e3c24848fc2eab91adf30e6b567d89d789d621cfad039b5a1cbb6ff2138b7defd4660ca68ac88ab1f94b0ffe71e3f79e0a7e264fd37e8faac" },
                { "tr", "5de45b8b51973d3e98ca192c5ae3f2f1a0292ea58b55970bd1383fa243af262f2d94020ab4d601fb44e8716acf7b4e5d6ee057aaa10e6b10ab25f1ea3498b7e1" },
                { "trs", "76dee46fd40f47fae7221c2020d289361c383c3759b7e790566895845e7653e0c394208d33c90df0a1af6370512b4e8858b409f0807aca137bc737f176fa826c" },
                { "uk", "635376f3f6ddcfd819a4511083afbf5a2273ed8ca27ca4a7bab0301e08d520a127a12e1598c344dac384e777ebd56253b19ffe9eca2c56b60a04eb96ea029eb8" },
                { "ur", "e4d74dffef9997dd3440febefb7484a72802c1d2fe5d7849a41de78babb431dabb154fb180003b272be3c683dd00d1acdf3d3a7106e20c922df422b20df3241a" },
                { "uz", "d71a345a8c3f57c476cef02890353dc4182bddceda853537b53b244c5cae32f6c30887b227182416d033ba112eba6e5e3edbf260b552919ca01024bb8234ec73" },
                { "vi", "ca9736c5cc87227141bc931d4dcc8b3a25dca3e1a38c7f6f8024c39447477c2668ac81aa5ad696443a7980ed71a777f556096892f7a1d639620770702b77d613" },
                { "xh", "804a12bc1f838934dd8a0b1364879c934bf823eb41df098c2f9fd1a0bdb3f7e900cd0aa077f410d42538b28d72e21d103dbe56529280963cbf646a0d864fe91c" },
                { "zh-CN", "b47d45a886c59961f084f621b2d02dc151e85073d34af2109cdd25687b8819336cc0de05bbe065dd6d0e29bdb343ff843f811a1c761506ec81d402ad5d76e24f" },
                { "zh-TW", "5edc0cd1abc3f43b72b7d76043bc9ebb0c289a56be7f2c6b6e7353d696a24b8b1c22b4cf6705245828da3c648741187115dae2073943f1267cbdf00a0b996d05" }
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
            const string knownVersion = "102.3.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
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
