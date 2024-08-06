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
using System.Net;
using System.Net.Http;
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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "61119e06e79ac3b92701a4c67774792ead84dee2f6c6038a68d4f0ddfefabf94b46820a1aaf8ac7542465fd075f9ce747a6eb94c186f2a899ad349bddb216ab1" },
                { "af", "6833e1c70ec67905b94e5a5d9535f08929dcf432105fb9c46966726668b9f8d17488c8bad81405a7d7f89e07e19a098a1ae86b698b2c8183c3aabca9a313e744" },
                { "an", "8aeeef7d418797b2c07e84dd119a8328cfc9f0a60d47ed92630bb622c184379d2e65d60d7de867aff121d31e04767f18040b441f34a1a663c8612745272f51e7" },
                { "ar", "32593a9a899c030a2d9d774c7368fc7005812fddb367233a9818ee4c88fb0d79a4cd404f7ef86d2c5d0af8e2fddb2356811c3b6730091b43e13e918eb794c66b" },
                { "ast", "932ca2af67c95d54fd09d9d08994c2ec6e8187cd6b5678748ea3a47d63cd1e86c3c799fe0ad6d23f5b03498e106511eef0ecfae4271d96a0c32dffcc6cfd414b" },
                { "az", "32b9cce5bcd905657f68a58c8239f4c090a51226e0930880bff7c8299a08dc0aa4c79708f66b64b46590f56a56daed6c74ff963c47f8acf665e45cb5660aa59c" },
                { "be", "18ba8099c19df40a4586f84555018f71aba7409750aebd0223273bc85366e643c9f3c697e73e6bb274fc43c64bfd377f7a50265a2720186fc83bd1d8a550dcd1" },
                { "bg", "942d53d5073bb6cb191b65323e6e80b824aefb24eba0bdba6769156c4b74d8660db4f94772eabe462bd9891cd5a82c99610b03ecb93cea43ec48cdfb1b65e0c0" },
                { "bn", "314116e8f774b0c1c4aa215b688cf1f04df822263e6fc1d5977da17453926adc289044da6893811960adae770a4955da473e440c327df8709f5f4439ab4bf703" },
                { "br", "4d590e23a9f325866b89d77507178cee1f4492d5f8ba9af4f84926349360c102c7bab718b3a9aff901fb1dc69de6177679f63b269bdc92fdc4d372a8d11427a1" },
                { "bs", "cbcec7a65c87dbd0c433648b4b6e699b0824bc03001ed65371a95aeb6a4432a5c7d1b8586753d9f6a8528a29a55a539309383e3d03b24a0cfbb7b079eb398036" },
                { "ca", "aa76e254ba63ffd2c6a17bc371d89681921cc156e92f32d88dbfdecfb1c8f3d804444cafd8d651f07b9eaa402a1fa6f83015df9382f55ce04feb67532d4cc7eb" },
                { "cak", "283e18fce406db5b59b2f9010d14f3075e6dfbd59c16363a66854a7b58d17a320aaafa58ad88f789cfccf90be3ed908be01633bded2ee0790d6ebd1b54548891" },
                { "cs", "88386044e6b461e4fbb96e0018b47cb0bfda61daec615eece871a49fbd018cbac06ed53778a192db99ea32089ff4e7f7c916a448bbb427eef80ca89dadc0b6ce" },
                { "cy", "fc4d36346c3603bb5a7b8d5aa23feac3e2fcb9c43137c7bd6785cd2459e4efebafae6eab30b254dbb7debf5c0c1f684bb7bd00d85924c15fb6a49361b764987f" },
                { "da", "4582a13312b6182b5cfbadff5e52ec4512e418a75eda7c03e432a4a11dd9c9ca9855839cd3fb9aa18db36440220e8e4d0e98e20cd1b37047f84cc301402644a8" },
                { "de", "9581f3eea68c9d1b188d9a50c4cae18f6e0fc9d9163a2192b71796a76fe68b7505ee22a2e0d73a0d338a3ac0f5cd3d2178032191e8ff66c499df961bb2583107" },
                { "dsb", "fe920ff071cd3045852361d66bf70fdecddced949e2c9c2aa11de9b9e7a6d27fe1825cafe2be526867051e6dd18dd733e57379eff0757753a9b40de27f54f61b" },
                { "el", "580e38fe3ae63fcda5baea5ae34ef5341e5827b16bbeea0b38fbf5099cdf0fcf1b2fb4c1a5da7501eb462aff300b71bf7f6f4c88bdca30277a25c4d7f43e74aa" },
                { "en-CA", "7e8c2a7bd0a0b379f9c8925305eb3cabedd610fe110b031f5828bf7df5eae82d086a01f6364dfe7cf5d9d14c693d729df33e9fb0617a59f90d0088be0fcb2a37" },
                { "en-GB", "a521c1ea3677c49a18a79fe75bd49de3f09784782323131e9e8430dac8e959fe8cfe34a72c5c7ce0836780ea285c7cba07525ea22b4a65029f19409a367502c8" },
                { "en-US", "6b35e166863de70ae311df8a035ee31ee709b234c0603c6cfcc84fe2463df94d854472ceb6b0930e74e3f4357e8cc15ce2cb22745a832e419dd56f7e3dbe252b" },
                { "eo", "04030b1d13d3875cc636d956cf98d59468ace2219740a31dbdb454c279fbe536704bb04ac6ee02ab10b1f8cd44265a3b727ae1fb3e9f9aa6e3c53aad571a8f33" },
                { "es-AR", "97b2ff3e434a5d95676e5622f21e7999e51ce7e24642e2fe0b4b7b198f88a77f927cfa0d3c4d54ef9cd0e4e1ecd4d65a564fd47fa612927600e9bd832c82c1df" },
                { "es-CL", "408beacaf1753b10f5c8864ab99df9b4ce327fbbb4aabd85b2b08e0e15863cff27895fa94104564ea7f245f80c0a57cc4e51c302bd871dd3ebfbcebcab379b24" },
                { "es-ES", "ee7b74d7f962e2b674a4e2f933bd8ed259344db71eb5ae2e59911833c2de633db1fa4cfe393393de55aa26fc555f9069bc571f26197549d793c97896b6608909" },
                { "es-MX", "f0c7f442bf5a249f971261f5e7b17f7956ab1f2f852c8a011bb76a82f06a3b88e834030ffa2ba2722b902a82d43330b82c0cb0d8e34fbba4573a3541ac09d2f3" },
                { "et", "e1e6e6f2269cfb0328b8a3f581ea93dfe652d0f198603e9ae414402eefc048d19d41e4901ff3b62353c36ca31bdf76f4627c0f1aefb34d5b3611e04913b3350a" },
                { "eu", "77ce5aefac828d110338db3c266683ca15cf90efcc883ddeb6e4f9377a616822114686d6f83e8b30ecf585973a69544220141072824d45cf25bf91a06c572b47" },
                { "fa", "984026b60adaf62a8116044b8ea35bf8e84a31dad9b77044a51df6aaac64eadec61af5aee3fdcd7f31530670588456a73e44ba9366c5976a33c103fd72612839" },
                { "ff", "d38af14a930084b39f841ac38a20e7fd7bcf397b5b265c925ec76133132ddd769cadc3e38cf3551cf33b53814d68cb5edac2e5ac9782e740febf870a7c53b10b" },
                { "fi", "c2e37c380ea89d2942d8f39ef27798f890b0864ac2f27a5b40267fe7cff774962fa5512ea8c197040b9ce0ab3a4fe0ab9ee1fa01c7a7856b97fa76caca869269" },
                { "fr", "0b556022d9b9af355c5cb65ae953f79361c4dd5658072cc3715337d12d9268115d85859689076f7a748f1c107b1a3d56e3591c61536eeae4ba512f3bef035af6" },
                { "fur", "170630cc61e386b23b227340bf77c580dea9eebaeaef19140600527cc008d4122329468a2c3ad62feb27280a899684183de5f4116ae307a7d91f789101187e81" },
                { "fy-NL", "c878457101eab984abcbb25361f8ab3f5d05e361eb0c73c2901ae9315019860601e236100c11c25c89d57940554a75784c1be77f99ba2d3d76d2fb4953dc8f30" },
                { "ga-IE", "828966c1cbfe93608defa9f99eaa392d3d0574ef39c699992f2e83ea5ee5d3bf11c32ec65e35a2147ebd09bc9009e3a10551cc07b4a40509561865b72559f32a" },
                { "gd", "af9d5e4cb571dbb05834fcccfd0f5f771eaf4d67d58ef1e2b2c0377a204785b4697965fe607d58ac55aaba12590e0cb0d0d2e61c35b833fb4e09c7ee827c0817" },
                { "gl", "6e328dbcdbe84f6f7128079b2e4728866872d61b22ae50d95c78eed70c6b8a961215e368e9323d3cadd80ac6dfa72fcc053972e495226caa830582f86cbfd604" },
                { "gn", "4041bb5d84eb78f906c07f64304fea3999c3360899273adc04eb1f1bd2eec13ac6fe11e54b0b9a62b6fb550e33959efeb20fd204c9870921ae817e5d49bd0694" },
                { "gu-IN", "932b1afbfd66653394dfb8ea8b367a9c5430eaee5b086c66a8d4ee224b9e843141805876c64edd7bdf7bfd1e8f402b07b159a189d6e1c7eada5e9b79cc64b559" },
                { "he", "96248467f3ab9c0c387de5327d7e1a53fc422318c217ccbdda76933ecbfd322183ed3ba46733bcfdb65507466f3e1375c9b81db7f6238cad887d67960aa36630" },
                { "hi-IN", "b1cf3a193c62eac7c8e6a1141bcadd5efc90bd88bdf79ec67e7fc8ed344631852a9aec96227653774463d6e5169b5c7c486057e4f9200f500e32759e9c637528" },
                { "hr", "ae5610b188b449e9051d940deccecab374100c6c860041338dedec623fedfb0914100434072ffb12d4d95e7486147be02e06f7a3ce9ee93ff47bab06743ebfaf" },
                { "hsb", "4f44470a6f47bf29002cc25c61ff8411036e8cfad81cacd95347ef58c6827ff90a91c406f5f734a9b2615aba55e963abd6323e7b69a3ecccb61025641ea1043e" },
                { "hu", "c103c758541229c4a9ac20bd0c64f448e666c2f414f0b646e49bdd5a3bc2b6fe3051bf1af8e3f61b2808fb10c62638eb95d0cd689a667f6255c46c308b7516e9" },
                { "hy-AM", "48a8f1521ed613ae6b511271c527f42c90dbf60a616c931bf58aa8bbeb201e20cd7450e7e0dfd9bfefbd36b46349ff16a04bf454590b4a6ec77fab8f9e083435" },
                { "ia", "0351e85d8e79538625d80ebac455d8dfb239f476b366405d4fe3061a24960bec24ecd7c3fe5c45336af0f12f589aaf4c34a00b640367cf25e818b369038fc396" },
                { "id", "4ea2e47bfe42c7431848d378d0f84163006d276cfe2b8fef507171f06b424b3efd4fe7f59b7b3b3ad25a4ae27ee037386d4b5112b65bf60e400ccc1608f01c9d" },
                { "is", "6de61cadf94381f1703cede1a18a1a2aab64c27729f25c0fc12632b4a7bccc36ed08742dc74627d56fea7f9e35704d7f0102ca2b92a797fc1e522b2f594c3160" },
                { "it", "ae687353dd7d7073bc0cceb5798993231eb7f60a5aa8638855f5c64c8d7034f219311c9afec07dc4a6e8736269207673e1e839cf325f83a409f9de5dc3b91052" },
                { "ja", "24bf49c65d7eb9284cad1dadd45ac1ea8dde3a0477a8a781f16ce3b794cbfb31075f7162a5b7ea2b84289ea0d0d120002dfa3c1fdf5f40c30d6d61605a86bf7e" },
                { "ka", "4a115e296435d09c9d8db85d3423c66555f166d2e21e8811ecd754ad413fe913a069460f71aa5ad3e47273a4a042e54f105dcf9298215c33199cfc8ab5ccdec9" },
                { "kab", "5e37713181d29fb6acd07be8a5d411d88429afb203b6d24c5e0b4d0e9961daf97c23c9408e6ffc6ab58fb8105bb939dd64247a477dcb541e0dd7b17d9de2eba7" },
                { "kk", "083db444266e822c72ea6f5c04d763f43afbc8a5d313ba9cd99c918502134dffc8f54342e7bcf02e80fb6e6ce0be7214db77d944c4cf2ef8039dbaa954000e3e" },
                { "km", "bc05ae1b91007fd05604dc9486daa1882ba692c193677ee6b9e6d92134bd4d8667486e322cc9b8002e63c6c57571678cc4dda87fe1e89d471549113bcdbb9f78" },
                { "kn", "9e871a2b5c59d09267e3fcc69fc96947daf8a7055c8f50d25903687106abf6e847cf3191d381f85129f0ac7695d918d2a8c92d5d6bbcc3fded4d1d82fe250952" },
                { "ko", "fea557f865b6ef1e123884b7c9f6b5b1f949764e976f767aa945de772d4f14cc2f5413c4ce2f5d0153aca839863bd09b8b3b793385a8085287f35ece8607fac6" },
                { "lij", "4afb86266ba9b2ad81441e60c482bfdff7a4a66a46248e31512c3793bcd8aba7642ee06e700e71cfa0aadd2942ad99ee8c3cf3268a438558504cbc366a55d37e" },
                { "lt", "d9d39b56e79e6e14b5a9ea3c686bc88ab01ffecb27bc3b9c084ee62b4e9b5773978802a23cd10070bef88d46bf3d56fddd10e9c88c55abba40cba77d239f601b" },
                { "lv", "fb11474b8ff824a512b89f0725ccc1b778f7cd0b6702c7854e09bf18ea138daebbcd7bb5408f20bf02166042b1278ba9e563020889db06bac7901902cd6ab3f1" },
                { "mk", "3603cc0656ce3c1c63c8ceb4c7ea432aaff2db2417159a4661efe5a0c867911eb8163f00590446d1e90f9db265b74331fbf9a194ad31cf9b10a4ac413d117dd9" },
                { "mr", "17eb39fcafcdd15ebc9d07fc9400d5053f0849c17018cce61050a21e97b19aa17dfc4e85445819083237a6f4e7b7528d2608e3cda3ed36ad37a9ddfebe0c41b0" },
                { "ms", "c7c202c479d7948177a71ff648290f83c659435b99754136d1cb49d5f9d922e27b4f78a250a3d2aac8f41773730328fe439fb3d8a8f73355d24bc9fd017dd12d" },
                { "my", "4aa9d699b5fe1d52268c7b9f76f6d215a0d6976acc3333d0bfc05eb6221e26d55626cf87f9cfff60c66a1dcfa26c1c78a24835a6eaa790cd70cd43d53b336e75" },
                { "nb-NO", "0183146c7af8584f14881cb2f129e5361dfeb8aa3123fb80e6ee501ddb9a502fe48bfa6768c077b4c4e0a866b01667fa7b7c784563209f723a3fd7bd9f089c03" },
                { "ne-NP", "e22d242bb9a836c70912cb4b746326bfd2c881ccedffa858acfc61b6caf4b549e4d11e524b6f08df26b9f8d17fc3fc97ee066bb23a08d4e9087ec7c9ebd67bb6" },
                { "nl", "ef6e7e739d5896607513d2a96d91962c0d7aba46469b0e37fca0f6055a66408cdd20744187e1b78422a4705d21a31bc453169ecca302c74b250df36cb0f45af5" },
                { "nn-NO", "d081c0aeace1f31448281cb2bc52d961b2c34ce1c15083549fa48b801b7fbcc46578fb7474d5df5fc975d018099d205fcaee47a291c85530e84afe1f4b2c2269" },
                { "oc", "a92712c61964c093cb73b64b200891e4e36d6a4aeacd557886c3ac6d11ebb6e75b33f2ac0d4a6bfb4beebc9441287d54d524d697fa098bdff7be79c4edb76421" },
                { "pa-IN", "62bb1a92a31294c7a10668079caa3ee9a7902a5d0a442ec4d156a62648da5c80b5ac1de68c53f67d4898e420c92e73c3fe2a96036fab739e0a5dea7cc046fb18" },
                { "pl", "138e4ad5956ae96c739fa524323841f0b0d47532d484ec638e5f6cc1272a998880806cb3c6f1118592b5753bb8ef922c92a122ad1f10bc5e033582490ed860d3" },
                { "pt-BR", "21fde2c5d913b6d48b2a3c958b0a75ff2ab6ff506ea76c2c5f470d99c08a32f454316c7921cd0d8ced565069dd5be4907872997792f34dca5fa5ac35d4f4ea49" },
                { "pt-PT", "cad9696778b9fba59d13cb60ca50736c202c0ed540801c7ff09f07b68ce22d0728cdd6dd527beebad2eabd24cbae1c991b98168476c1e7744e31fd592c3c4d5c" },
                { "rm", "f33a96ba83e7601b829e8d95e5193a2d7294f6be70ba9e41e972938e144fbfac33c510acdb2d82bc94070a94b1b57dcfb3cf1d0d34c2782027162689d109ac51" },
                { "ro", "2463c8236ce6e2b7a2b32a84246392a50cbaae71d71102cd27d9ec726bc0f531ad6bc58326f1b5ce303da07a474a61e556f2e2ba00abac83c7d741dff771d65d" },
                { "ru", "654f1c3452ce570ecae7bed065b0382f9bbde6a6821c03c2288b170aff44fdfd0362e0c4ab9758955de9ce35db8b0e975bae08bae16c6c1e936b47bb6828cd56" },
                { "sc", "e10a9e1020440f6d4dfe7f96bc947cc506a0fa27509f7195c4c8643a7eecdf3ceff64e64e7660d2341283acd379d0dcc4244a13202a12e0c46942b88a2b1516f" },
                { "sco", "037fa368221b2cdcc8d63925de36709643bd55a57e7c383696fcabe995b20ed25437954f7d537ee43d0d6b03a8b057b23af41b7fa5874372ee02081223e0f075" },
                { "si", "56030dd3185cd3c88cd8613f44cf4c8943d60fae316f778513a445dff0b76c42687b703b7de36c07bc2b51b7301c1a668c98337ace49ebaf0044c44737665f3e" },
                { "sk", "72672066dab7afd3c84f78570ab21f56342966bd083a2c95b375b509a63be7ec833d8221287587713f328d6b5a959bfe0560270bb294c8e8b0e31a09601ecf29" },
                { "sl", "6754320aeb1d16d4055a70cd0a2445578cbc6aefbece850402e10599ec420ab8ad3afa0048b48cb11e35827886ca39984f35b09473f56616ffd538901239daec" },
                { "son", "22f8f5d99c415ccaf481f8b57a4e87b9559da56f141b2977e3a14fabfccba0c733da34b009dfe80caa5b8493c4f85290002b72acace802092ecc38e27d0af550" },
                { "sq", "092601304944a5606c60ff42bbe67f4f68f7f5609b03d34d53c0545754e99a2f3d7ce31f7e91d0a600331850f16b09c0513a541af596bea70126707dc6560748" },
                { "sr", "42d60663c7517bc10fd26865202799f5475e074975e3e15e9077fe98d8f6bc9938538a1f3fdf13733b273e44fd690b7a0ddaa147e4a2031beb5af16a4e9cebbb" },
                { "sv-SE", "4de695a710f3d7b7595acabb5b6c8e2df88bae853e85883402a1d558198f6c24a7a48e985aa310a084236f43010c0f2856ef1ed710b56791d73c539d204e7ab7" },
                { "szl", "eba4fbfc0aa8851f5efab9d30c56be7f58f1d99d18625f8a204fea4a8ef0ac66bb103f3875a048700026de1d7dfa9d81824f8427fcb0b8213527bd2c32f01047" },
                { "ta", "a9d83cf34e7e793f7044ead9e8e5731a947ef19e1d405c370761aff5dff4e750f1ec795e460d2173fc9405ba08e8474e519adaacdf382f622166a28c583f5d1b" },
                { "te", "5abe791beb3bbc78748c563f4db235241f55b21e00b0af25a2e8fb2306b75b3ff916bac6ca5d17fe19d42d9637ffcf0a9627b8cc2358687e62b4689e16895fd2" },
                { "tg", "c81347fa2c064b0e525df1244db453d5acca83420933e4a4366ce20e06d96583b0782ef2da06d30b282d57ba347a90d0092314bbfef7fb1d2b6b67dcaaee4e25" },
                { "th", "30e0283e65a28da6a9acc6a4cec0c50344279cc91568186e51927c375cdbfb2b1311c2f8fd82684f9369d82f6d8db7e4baae1d5341ca38cd2a07ccff52738ace" },
                { "tl", "239c0b67a484ffef88bd71fe3e05fe38330a25346dfdc00ffa1413cfd0b7be7322083f7c36a8069f00bee467197155dc0e6746dcf281de8c87413a7783e0d110" },
                { "tr", "9a164d74afc853c09ac1ea6ac51efde31acd73c3bbba11bd9d39d823c7fa5c3051355ccfc2c59f703b4326743c0dca3b78f7bbf1a58e023b40b6df9b6a731be6" },
                { "trs", "ee96f7e9807697c1027014b61ac2d043a934dd2ed8f43b4323fe0826c26d6b67a3fdcb7f90af62360cdcf12c46e66dae98693453cd420b4b316483315fed9ced" },
                { "uk", "dccf878f6652f3437c8b2c5ed0995b824a3217c4b7f9f5ad78970c7366234f43d4985485af65c0f6ff07d48bd0674a5ced218b8d8ed89c82f5e622dd24f39e32" },
                { "ur", "62277d2e51ea0dab81bb4279f4e2b76bc77a16de28dd95eabba5888aa57fa9f73bfd82e7511dfaa38b1811daba4dfc98de08ff7302c777a583034a6d02b9a1da" },
                { "uz", "5077a4ac4f1005fd0d194f49c6d91b7f57b8eb7fcbed87a11b4d5e009c6fb941eb39ce0ee288da66a87c0d484a78f69f467993037f3dc5366261bfabdefc78c1" },
                { "vi", "52af48dcc8e58c469d0c0de2e7e6257a450076249e1fcd26203affcb6b47b89c9f0271728b4f72da5c30b56f6208f8f221462872b76fb295a3b192e30469080c" },
                { "xh", "2ee6a1d298003381a9e909e398cccd8a79c3fc898d6bfd3a9d23d213d63f5b4e473240612e366c102f75d012689e8a7d06fe34e855871203736e17c57d454d2b" },
                { "zh-CN", "17dc47ba0dba9781381f51d4dc3c05d876d9f3346ca9ec9b9ad50b9c607fa3bec0c4522a4384e40bfbfc5a2d0c877aad386ace452a9cf14d7ce066dcb08495ad" },
                { "zh-TW", "b3c3588dad5a08fa42ffef8b5e7ab0d711a2ace37f42a5c17b61e8c50b7dabde9c8d6155951bef7b02cff3f279c824db6f08f643c068e88d32655e1121a00d90" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "ba2cdac09c3dc001f15ad9c53f3e69f48dbb330c2c7a3d8561dac1ce84229ad07cc15d87ef6b4732ffa62a915db437aad628b94a9bd29b10de3d12888502152c" },
                { "af", "90231090722d31e033594d1e7e3cf70f49b88bfe6a988bf567073a692416ed90d30267e2fa0e16e4114bd46400c9ed390542a763dd41278c64154032e26b71c8" },
                { "an", "c0da912c81bbbaaf95e6cd399697e1096016b904c16e9255984825ead2ea8fe8a103fd520f70f33f15b0e679a77d36956cdaecc49a307b6d7d423c4c3e171940" },
                { "ar", "9f804d0784540fcb9dd496e432843a4e99a8c31bf1251766ec58acc94b15e737b3d49bbdeee316701a0843fc99402da3d2b82489bf937ff9ec2e87d4b7bbd354" },
                { "ast", "3aafbc89729e52c33ce37cfff195b7c97d4b407f3ad5b4e39dcde670e03b9d9f3e636ebc5bb2915cb2a590127146801c1e7602bd448066ce173972394cfabc96" },
                { "az", "6bde867e0b3f41e9d7e272f39f9744a37dbab9923e5999b565df6b0e688020829b43649bec79d64a8fa9e6b05de5ca5d0bed1f97baceda759854d01b2c397469" },
                { "be", "ae1e4cc7712a4c9f7ffd3e81d163d6bee6a760a497e868df90385f104efc28e4c5508757b02733c391d1d13063c4b93724362d0429a65e553cd75c97cd6d8b3d" },
                { "bg", "df4978590a5a19d076f09257b4b41cc1334a55a28d0197dc4b1ed758123df9f578ab03ccfe0b04fd19ed300ae101ae6c15d7bcb4bfe5630720c63f499f5c8567" },
                { "bn", "b9723dbe4c4904ec7be53694747d67e3c505740dba287204e1771679cb20d198cf0a04899a169e59d0b0db79dcdd171ceac469a9c1e4d076be154b1525a68ba2" },
                { "br", "2798d49c571eeaf85cb8451ee398ed589964161c30eadd2df2252988edc61c1f841c9371255ae371efe709bd823359aea72bbd9c2558edc646e2178ad5522868" },
                { "bs", "2edcb437a8c765752f2909a2be34961bca261854ba13d4cd794963beb12a340f31b5b8f21a6dbe975103c44f469417c0590383d34c79327c52161fe7bc07db52" },
                { "ca", "66e1ba683b1639a81f9813751875d9ea1f98a0a3bd9e8d01e1536c4aabe9d28966291b4bf0713fb14552a14b4af2cb7415398839ec187273b6c94e3e9698f714" },
                { "cak", "6cf48582826d76f68dd0f0a9c2124dbb2bb5e96756f9304e79ec65745c45ee26167746c7d2d2dfe3abf549c27cdcf8af4d5ee63f2d8a3a8a83fe84cb81eb318c" },
                { "cs", "9bf09adb5bfeb0096f046f1a1e0b0884fb5d8c63e405e3878ea1df858b345b14dfdf9b7dbff5522d814a46d014edcfb23b70051905b967a93c16908ae229f27a" },
                { "cy", "d296c8255e4e96c7e381a4193ef24ad6494002f0df181e3059e8e90760b4ddf8192b6bcf5a25b5ad064691068c02a14c7c1bac9a0fd49605bcba9b069fc47d9d" },
                { "da", "10a55b689cf30099ebd9e915428ebd87b0bb9cc88dda5feea7b0ef813dd1560c8cbd1680d787cec438a7b990ed3804525c8e970e34ff7d4595a7a79a4b69ad00" },
                { "de", "312523ed38cff750275bd604ee1f3576f839d77ecf9f888228a86f08591f0363e913c49ed0f3c4e19f2d736d2bae8e442a3540df8cff918705ea09f6957aefc1" },
                { "dsb", "0dc4bcaba31d0abcbaf1d06d22cb3a0b5e7da2251c72182f55e045d6195b59ef196785a43d8afffdd1083406bc3d4e1ca66ebb85a7a8f4a39dc8fdb67305e327" },
                { "el", "a1156aa372e75e822ec4d618c506b0354006560493ebc9072f707bf4953a0bd84597467e9a837c8bba6b5806be0f49cefd25bbf4359c86331a9d0d714ff8ad76" },
                { "en-CA", "4e2325e8279ef714bd284e168befdc18fb21dd21cc9f0c674afa3d09b6d2628d1728b9e0b5e84c7f7aeb76288c6634027901d22ce87e767a9dd32ca4599f094a" },
                { "en-GB", "56403f20384131b72a5f3384d57cb122e7e9fe69f4915a394d0188a059c86ecbfa70c27c5160d322ef0ee1336539f36fb52e117f226923944249064c72b26358" },
                { "en-US", "3a272fa59d1e83d3005fd286dd3c7dfdd1f46c0b5f9c3369f604e9f794fc73656583b2c729dfe329fe042aa923af50e746aef835094d0d198ae8effdd21eab89" },
                { "eo", "e3a758bd8539af84d7f836335b6bb94cf6076314ab7e10d49bdc5eb71849cfa3e22c7004bf30fe21980dd69eb66863afa2188ef6dc5fdf9102e180b08321955a" },
                { "es-AR", "9a78d0371adbbec3df2b9f5f6805a1db3755789fc3847a5c4c833b5343264b4a12e7d207453155e0e92703537dc82e9114ca7350565346606e5cb1679953e2f4" },
                { "es-CL", "be34b658ce8555d08515f6d31b539b5c75d7ca02cc50613ee7aba1a4199be6674bc5a2d87679a921d1546b0f0cd13cda53ba399f4cc0d15dd826490d9fd6f287" },
                { "es-ES", "af3d4bb079a5084c1fc4a553669a44bb503445a68228a2eec203304fcfa16e7469a9ef4d516747b1c19d283c47e1649f5eecfab9fcff5971e33ee33e31d498ba" },
                { "es-MX", "a2d7b6d1af004d95ea743758fd208295c0bb01e4ecbd0c8ac0f13975404b6409eaf73de87fe283a73e47ff5ba6a8e8f0f4d230cd276ad0a88a565073f3cdd01b" },
                { "et", "fd527b15796f2acbc7fddc486d3b55306ad9613ed7a9a677cddc8e931201e3aeff4890a854f5d66af548e8f4f4765735211fc2386c41b84a9937adc20f811889" },
                { "eu", "683b488fbdd8d080e9156c38d8a5acde0257d7c7defe98507d522ebc9166f151bdb505c8fcf8b7066d9cdfea89254fd328c197e5a7572694e2a18025e0a547a7" },
                { "fa", "42c7520f0832feff4c22ade9c2cb5c484d3810a85e62a32ff5ad79c7a1dd9542d1aac71645a9584192cb685ba7b8619a452b0a73b6dbda0dfd9071cbc13d3220" },
                { "ff", "a3cdcc37e56eecae0aa8a5d9aac346fa70b3e1718ab46f05492f6b2343e069eaa79759910af97a5ceaa5b6b8ec501ff18ea09b0f082b5d8bafc0b43d8935611d" },
                { "fi", "51f9974facf2d9565fc257cc11f810395448399adbdb37a9819e6015b1c43fa2c1b5b5cb5047628fca296fcd93e3fbfbe445540a4fe89cd3120cee10d1d8b954" },
                { "fr", "23c08d3e826adf4046806766a6ee42c3091b8c949c318263d91aa878b4d5ccac48d9807cf428c8f7bf99f78bcc8d57b1a432bc2c327f7f148cbf890cb1dc7bc0" },
                { "fur", "c48c7efba65b65df2cfa5d12fe100a1c8dbf5b00afc05e4febcdf5af499de89018f49263775c894f535e5ba8553327eb66446cf5d2ef5affe31564ddd7c7ba5d" },
                { "fy-NL", "83672e462135cf42baa5f68044cc9ae143a6813cda93b55c2cacfbd72094e02e443681e25c4bdd8cdfb1eefef39fd1fe13a4fd75281290dedde01beeffbf2d24" },
                { "ga-IE", "53ff1164da81926dcd940de18e6dfb88ee19683f1a94e69c25442fb51a718852e2c9be58b2b7cb702037bd0f9cb05033c9a5a16c82489b0d77f5c1edfe867fc7" },
                { "gd", "4c879a7e5f1fa16c77d3bf644ea2df9fdc90e1aa51f579825028391e45c0314d24b44205395be33ea157256554e1da1cfdc44f8a6312d7f0ff4da0c2bb910c81" },
                { "gl", "9c18522cb2b6c2a33c9d83c129d76300e3aba68a988f489e5a41720b8edd166775597d49e9760adce1336f4e4c89b5078abef5c96c0276d2c8a78327c71ffef5" },
                { "gn", "aeac48ef021bb7583580a5a184e215148e93972828ded99b3c0aa0319b54e475bcd6741f693446f6001e1c8fffc61e7967b18ff6dd4bd231c2525226016c0b9b" },
                { "gu-IN", "75a160212b7d4e3b09c5b279436152f984adc7ccb97ce8ce73ce32dad8f9b63b171ca7854b2af89b4a3f358367c6dcc3ef22d68a33043955227377915635d94e" },
                { "he", "ba37c67c467875b6a70d7dbd419f6e535fe267866689248d2a87aa7b9af604f01a14a311b4118be9b5c0856756b7db9538966a3f421bd305a4ce09effa1f8381" },
                { "hi-IN", "56c389d1d6166ba4b5f6a0c6e4bb2027fdd3fa6bc0ca89437d070ec6e3eba2a7206f078a91d1dae94919b5daa459c1df8030d777e6bf27f440c38725bedc9cd5" },
                { "hr", "a5a044a97bbcd447eb1200c88fb133ba669468f4aeddc0df4e2121bfe73d2f7824ed28816d8a85acdad3b569dabf43fe874c237d99c622c7cca268ec28a4938d" },
                { "hsb", "ac1fd18ca585e1bc8b8fb1bc4fff759f0fc5ea351e0018b47ad9772bc2839bca3fab416f1358e44f8b36fdf398c97ec3c846b4c9a9b944778c446b139bce7d05" },
                { "hu", "4c5cf1598a99da774280a47041ba486a5020ee43d6c43d4b3f701b426faf59a91d2f3a5b2c462a1370e1ff5f14e4a0e7b4afdfd276b484e9b398117f45c07fbc" },
                { "hy-AM", "93ec25a38fe5c880e2eb26488d003296932efc9792567e42c2628e88ca59924b878ebe7dc78c6dc5eda28e7109e7fe0a81948017edfa65399503d03f4eee767b" },
                { "ia", "44960ad61b656d4231a6479c28d66331c6e06a8382facc98e9888df4a03709e402242c5cb525879f57f83dedda0b0646e93d9f06e813c5eabf9938e4f44c0032" },
                { "id", "62daafed91486afd23529a3d17c8c16e57275934f5e52e155519f4d116d30e8eeb63f437a028ed04f1fcd553f326ead1350d25f7c507141e49e94df97bce2629" },
                { "is", "d887d9ee288c267b20c71efc01b3b677c2573abde3f60b61be374b2010a13380c6e2646e8acbf24bf6ccbb6bd5b989818805a213c6002afc32e784ca079371e9" },
                { "it", "788bfac7059d49c6c1459637aad41344c9c0b0ccfac78a9c8b6c7b8b07a15d5a9287de33153f4b0060ab2f1430f4d4398e07cc397a83c3da5c54bdedce6de128" },
                { "ja", "2a65271650d8799cc812984d4a0b5442f1200e9ce5718953daa6c4b0c2de3d44711890e768464ca1da57b3a0db92a25277da1464ba095fdfdd85b8891354ecf6" },
                { "ka", "ec3e455d532df29716fe1e01ac574da89af5a7b52576b9f20cd3ef46a9a1670a23c6cbb426315e630bf0022196dc5ce4a447bc57a1df8bcd5697f31fd63b7ac8" },
                { "kab", "42e3463a4c2170d829ee5db2e863f23057e5e3da7750e528a56653eb60a4808da2c9d889077f42a3c5d975ce5c2ef8298eb3bcb658c0baaacacfdd0a927972dc" },
                { "kk", "366819f96cdc663859173611db305c8f922f27bba8c5fd8dce8727aa9137b7f4956700fe27e913acb30c167fd910bad14ed3567f6cc6e65a36e84a7c59f1df24" },
                { "km", "8d4551b281378321b81ea03679c0499dd761ef597d28985646768675fd2ea64b88dc695a03e2925f18f9ee630483128c1db5c158c1cd426d7cc15b726d0c1935" },
                { "kn", "00c40843560f9a091d6a667e44e7cbbb589597d22965513b6c94acb0fd8a9c899164ae58372b13f25033910402be218a93c19480b72213924f4bdc8904208a5f" },
                { "ko", "091313a512f3a323cee9b05062c9517d0b61f3427dde1982a17aa5a4b476965eacac5c1c354f6cebf53575976312baaba6d85a2c130d78fda3ddd42c80d62155" },
                { "lij", "07ecfc055605690a75a4ff29ead60e562716c4b2bf2278046312b6eac05b9c690a3bef522ad8e24f85e0ef78d0cdc1eebd1dbdb95baabbda4d41a0114ce0c901" },
                { "lt", "6bad236adb5918896b985c60a60eb62a858208ae5aa5635c5001d1c6d3c5b9e9673923c0b8b88e8a66c75a6f419c721a8a794224d58b52c0cbb0ff308f79da1f" },
                { "lv", "6f0a73b8bd0acdb819cabbb2fb28ba72c4cbaae40cb5fa25e78ac39881b11cf5bc94fa502738e5d80ed519c7d1b6c05598a630fe3bf0e69ce1112fa2c41f6d0f" },
                { "mk", "a013a81f58bdd625e4298d3639d6549be1b8321eeab6c60bdf213b651735172179ae32e865b3efd3318294d616e190b825df01c611db02dc7c3ffdd817975c6b" },
                { "mr", "6e59c14f5ae77cd6f3098343ac103ee63522589fffc2fc4724413b8328398e203c554abbf35797a82d5fd10365a6b740f0616109eb6ec166a6ad8d0fd0a7a4bc" },
                { "ms", "c10637ed150a2897664b0d928ca927476a7da71ccf384b3b6d9abceed662ccc6a2336b461b4ff67a870e4b1bd7bf3a176333315069c3498353aca26c03df0c4d" },
                { "my", "976e46b8e3a0c4b9553d56105872d9ee8744788250048f658e3aff2d77682129e2b262282f958221da4ad49c217b755a084257a6dbc5930cee48999183ff8719" },
                { "nb-NO", "294206d380abe385a353c9631ba1757e2c9d2b6ce8f33e7679b7d7acd03017f5baa41f89625dba4913b85e226ce44b5ef70b6dec6fd5058161da63c7719e4937" },
                { "ne-NP", "41610ff30d77ccd33dae60fe1b8bf053bfaf51eebee06fe0b29d0f54ed725801719a3694fff6a8b9c1d760c4ab1c9a9256464b21eee1abb661ccfb02def70f52" },
                { "nl", "688c0c7250f148d45830e49366d1783dc8cbdf76174ba3548928298123f7d5e475f7ee1d13bd70c9d55af9fd03561c2c4ac7da7369b108a3630a8b7707559ed6" },
                { "nn-NO", "c97bf9d10cf56468abb9512e4247f061f48f8f0b516713844f9d3da8283cc546e75f4e7d1985fe2c7753da68c30ece633b02fbe743c34aab3458cd7404046a4f" },
                { "oc", "ec0f835603b18bbe0f0c172abe4d930da26b87dd0738f6f77f50aaadc2b4366231da2d8a06d57cee1a61b9df8aa72e2739fb25f8d15a11b474f71e62b95e80c0" },
                { "pa-IN", "b15473708795e133adc6d83247e873fa6ba838c19ceb6512485eef79f5081b563611022f56cc2e1d48912a5d62c6832125cdfe66632afb00ff8b9b662679d7d7" },
                { "pl", "fc6022ae26b6fd23fd0bf45b993769899c0ab8066b2ca6f95932b3e57aac31c7752fac874e54039589b68db8d8c20ccab8f368ffdb23182999f3c219effab3c3" },
                { "pt-BR", "bde2d9967b5b578af1dd904dd5acf0e3a09299e970663f5d385c4c6f46bd1ce43966f9d9e1db3c91076b6067dc09e55c8521ea1a57affdc80b7a873da41fdf31" },
                { "pt-PT", "36d2ff53d6875ba39a7e1090f2451acdfaea01b89e36041ab2fd399171dc72b004195f7b57388e396b6bc701716d622f7a968a4f830950929a2121b8bdecda8c" },
                { "rm", "d1eea41f418d74983ce050971c68bdd6f15f0c98676b91867aac376229ab56eee665f177ddbf867fe924821e96cd042c6bab904d1026e8d185aa90566709218a" },
                { "ro", "8d858d0cc24e8d2166f01303893516f99b40422ed8d1148bb8400098684422253a720a4804aebe33ecb0dd753aa339a0bc821599a3eb7978a4af6e51507c89db" },
                { "ru", "74eba75fdb14e4c2791b610441a5b7274969def9d2cea490d9948384c028a070d3d6d816ba1eaa84a6684f71f1dd2d2ccd4ca40483cf051c59abd3f5676756f6" },
                { "sc", "07894bb35014120d5c845e1d24c33b2d326a462575a475bd0c86c49667346bd2e820d6a66d94716e91ea68400f792f464003c5ac75e58c210a92abb385fc02da" },
                { "sco", "90707d3080e4a800b4c62e9ff28e710ab4ffa5b0ad301be5b81a51ea00272985fd2a394fdeeabcc156dc76dc9b73ae4cd723d6f1f0a455e53e7d9f9ecd5f35a6" },
                { "si", "9586ce26faecf2d39714087395c67275cd232f1e42a0db25c5b63390e2372099dab85984dbe7e7d5829f997270be46b08e97a690b496722772d0ceeacb592060" },
                { "sk", "29a328253a423cee940e6df522b57583372c435a856919faa8894f276c8aa2cf05436639a91ae209df68ce9ab7bb9e98b8beeaa39bb608f75970c9adb5d3fa1e" },
                { "sl", "0f7f626294743d31bedffc6f075a8c34fa8a63cd5735b592451ce94a555de69006b247ceb869bc561f1c24db0cbf61675a69943c7374f1e2ec15d0da276e4333" },
                { "son", "340915f2353ddebc949587fd12731d92508c751ed197843e52b6c3852c5582e79dc5e865ab9776d0d008d6ed58b4a8fa9f6493db2f39c65590915c621000a485" },
                { "sq", "d805e761756f1d627f0da41c7d2e34ecf056d968606aa5e0b555916afcab4347ebfdd39adc972438d6f238ba4d2f325b9f33c037e17f23a2b3f6786909e98e15" },
                { "sr", "036d0f4299623bb2377d027e1e0cc60629d53af6bacd17b2c23c28d086df084a4bb2bf047b77ea01923075f162eaf7e6da091213534df0095b65ca2af03986b0" },
                { "sv-SE", "b86211e95ff0744a56c230d7f64529cd33ee78e093bbdc3bb21675039c3aab1391b12d9b5f9b4946dff2e9ddf6b6341aaa0272f7e884057c9506fb7c9e685605" },
                { "szl", "e20452dce12ef2ee4b31733a230fec8e13fdef080882b2f72bbc0d95eea9294f989251e73fc311cdbf56d7b63017fde164c2ebc7f0b389f30570864d8333bb1a" },
                { "ta", "145b18a7c1949739f440abfa285d30092c28bd88ba158cca68ea91578494878fff12e7569b5963075d3bd2cdde28e3ca16f74a6f1959b08da930ead7fbc0e4fa" },
                { "te", "0fced8aecb82de70a7ab18e62295974f96c39a84bb0596b0d49774255f2b5653327e5e6854bd657513eee1b72ccb66ec6dde55ad94c652251170652023c8ed38" },
                { "tg", "665c9a1e3f7ef5cb688ecc891bdb44e1e5ad2e43ce35584ad931ddd00eabc54e3ca87dfb6cdb4493d74ce8242d129d2710511d1ed481a7e01856b0ae5335c63f" },
                { "th", "fe2d7fa6d08cc240efd93c8b70c0c852c0f2db68864ff5937a840d77c18e5acba3ed34768646d4f78e41f02c2d1f92173fd0cf876e68c734b432f8532acf6b1e" },
                { "tl", "231ed3e858715cb5a77a8849bd54799b39c9cea41d4354cebcf98f0cfbcf2f30be61058662168cf1d7c846330ba341192b93afefefe56ae7027d535af8f2d446" },
                { "tr", "f1e955d3016de400ec7ca8f661d06988760d2aa2f6495656463a46423d2dfa8b0a61b491e62dfa175efc5d07315a2a779d9bc673c9880df9165837ac3eec6f3e" },
                { "trs", "26c8649779c4f6190b247fb3fe027357e31fd747f5a3c8505cd23afcfdf6fa33e5fe9feb48fd2f62f1d761a55e3a231499a1e01c04bec0f25bfaadc0bd700597" },
                { "uk", "67050196d5137f8a0f6d7536941dafa5bf1a62ea8ad1a0c978b673ce02be0b2654c2ebeda1d72b31758f463dfe30bcefa17ed20172b9fab2f3a539e21bf547d1" },
                { "ur", "dce6648fdce46f5bc7ce9932175232811cc6cc3a4a66190d45f782879030178d88036effa981513622d2377e0647063a8a0d936f93fa16b1e3c78cb40ff477d3" },
                { "uz", "b265c3cba85a6a0a7859b8de084f3632b17e010d3486d7e921e2abebb6d8c6190e1c2402fb15b66482793272ad66caf117b1143c4666aea826711a612656bb26" },
                { "vi", "0380a262597b9335375076c58a63545b9c465a86e26677e4c4e139addd3e540f7fe799c911bd152ff5f6c3f4cf22ad6fcbc59797c16768e60dc675cf69e03015" },
                { "xh", "4814a627f017cbb9b99d102061c9bbb4472601b67896bd8792360f61e34cb50061bc396f99c26513b119caab623642b312e1c2ee89bd11352a997ab1b5c62f5c" },
                { "zh-CN", "c84e56c665aed3a8ae42cf2acfbe6e3446d2ff3ae49da76863aecac956a0c7e31f605790df74c0a251a59ce8e09f6136c7ca5d49f3844a4673eef6147359046f" },
                { "zh-TW", "4029949efdfade9fbf8cd7ef4f92843fb36cdcc9237c1b99f6b852350fee1de2f5309fc2d81728ec44e0324328c803dbbcd5957f59b26b478defa18311032c21" }
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
            const string knownVersion = "115.14.0";
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
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
