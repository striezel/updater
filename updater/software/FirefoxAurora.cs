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
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "153.0b12";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!validCodes.Contains(languageCode))
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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/153.0b12/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "be3d6fdfd285677e8f1afd1a10f30911b9bbc93063f76094965f0e6a875602ffa3970f9df7525949876270eb21090d368f85e618eb1ed652401c3f19203d18f9" },
                { "af", "04a9bacbf217d89f4a6411327e28e4597dff550931a8657717328bb88a2d3c8c9f26eeb15d2d5639647185c6fc298d64b9d9a650604e08834ee16ab3afe0b62d" },
                { "an", "91451e20dad61a81572130710bfd0898d19f5c4be582d7fd84347f898ca1bf0a7b19bf6b1555146c92701a663b164f9a70b0e3a41df0bbff98b76396a2af9d1a" },
                { "ar", "3989084da44f8ef192a00464ba7b707f21172f4f30cf8ce4366bb61d4f87924132258c5b9181c09936ca539230329232050aceb2daa875cd1ca5cb9971592c9b" },
                { "ast", "56102be91dee83150ccafda34bfa146a79c1d0fa02a12a8d56d3d86366c97be75fcfa29276565e85b2f2cf99e3f3c6ba9b539b367e34fddd8a686747f3b331fc" },
                { "az", "0ccd7be9d62e03fc119488788ca31972f08f9f9c62e75fa1b2be4428b3fe2c4e4ddf83ac7decf675a4adc57a6a6e920d2ebde495f70ec53d64c27d3a1e88921f" },
                { "be", "958eaff198afc147421521cabe2a6c7e5542f81f961cbb28ac101bbde4e660e0ae00f35d7d1ab15a311dc19992b472270eebbe8c6ebcfc2977329458ee88a437" },
                { "bg", "1ce0254b083d12a50a287d7fca4fd7d5cac1646ad8b68bf452b192f700a05bd6691859c05f0f5ff2e30ec97209500f0ec11946ce8e8ed91c55a263f54b8f40a5" },
                { "bn", "6dfd3a81a84f679cc57d524661540a99532b28eb0d357070a97a532381db32a0271e64375e2cbfd19582b5e4901b2e3e21982201d9c9deedfae38fb016c274f2" },
                { "br", "dd647cdb9f4981283f1be14a98b039fe4f10159b87f880a55be7981bb9addc2b67851afa4b5e4554a0ea3c2af42831e7107ee6722e0a9410b4efbb6135b4a064" },
                { "bs", "a4a51188fea837902c4e05566795bf2f94a77ee0d93595e210d972d238a283f81545b40bcff86d5801ec6d2f1b57f87e2ba484a405aec9f7ab5fe7e68487ea5b" },
                { "ca", "aebf14629d3493d042d7abd29e94036f7b783735d4396f60fadf1a3a1d00d9cc18ccdcbd66fddbefa74866b9be77f031b8b55162ec5df1991803cba516520188" },
                { "cak", "97007985f19f1a951ae23eccc9963ba404784f7e9eaae8188460a61fd8f5d56d6e1b88057d3cf7dde126d204ab10c37913e54d3e12a0c0df8282d99402215e8a" },
                { "cs", "f337be945ce061fe760ca2ead5189f166634a99d1796519ba94c79d74b0a5080b3e8f89c8555fa68b6eaa1b81ee28ba8f68c8a3da6616ac293aef70476350d20" },
                { "cy", "263358bfbe6190b6e55481c03535936f149022715d2939a8f447502ab8e14bb0270ab32331415bd7898edb3a27781bbb28e3e0264451347359bbddb81ed56be8" },
                { "da", "627eb85b8e22e87b4123de958e9a8050704058519c7305bb8ed60e1d0022b2dfbafa3c598614650733afa5ea8211d645fe9f83ec2960da447aab0b4954ac4791" },
                { "de", "8139d48be3a0126e4b736f71d60eb0fd3cac0a5c80e7592bcc2fe6c624365ac093a516ffc2df97271dae5f24631c1a217bed652475a157d8803892e0d4152e57" },
                { "dsb", "1e94ae8a7487df3ecf12396d956ea37361ff4ab0641cc3cf69787fcb21eacc7f840af1b5ecefe96255d7c4e24a2f9ac07f08eec2cd4cbdbda5fdcee5c6e00572" },
                { "el", "5fbc52614bf75ba65bc184bff775afbc213b4bdcc5b82d2cab423e3df1babf288b56c0e4114998d50ffa92acbcfd5cce7abb5e5c1f8e2ae24bd862d6818e25cc" },
                { "en-CA", "03173525f940288e70af6152fc70a5074e8fbbef6985380dc02cf92212d14ef244d9210493659ba598381671973846f749382c5455149511e176d76166bb5cc8" },
                { "en-GB", "427b8e8aaebe646fc8e5a5f6c1f05165c94bb33c0b32cb46918de9652657f854cc636891aa2fa39e3e26d2e9aaa18041b347d31eb805b620d944f27f10aefa5e" },
                { "en-US", "e2554e5c1c6926a6f8c14cf8ef3cc80f1bb4e9d67bf64d3f75915703d2bea7288b4913f6c7ca2dbe35b0d6c459b5c3462654b5efe82e0e4f5b2387bb1f0a4737" },
                { "eo", "8ad852d48efe20f0774e92d8e98725f094469add20ab1e94f6e059126bdf19cf6b378dda0ed2becc27c2a1b778b6969b9281e72d350d79f497d4e609c6d3309b" },
                { "es-AR", "16a94108e8f50cd7b81aaa9bcacb0bd616ced7a9fdac4913a266942a11b660bdf9b15a73670c8d04df2f32f87985c5c6523184f4e8bce6be2b01bcb4276cbda7" },
                { "es-CL", "33b1fcbd66849dc70b69bd2c3e2bdeae10a22f94df9c18e46a510ee0d4243e2c3de9a67185b03567ed0e7f548ee12d161f60f48304a3062ee58ed5d22d470605" },
                { "es-ES", "e8573eca48195e184985c3c45b507ec0f015af06be33a5c3e9fac150408d1df2fd04fff6b7375699b7b08b601f9e055acc1edcec6369113bbf3ef2584abc22dc" },
                { "es-MX", "590c89a770c9a9e379fcc88afddfe49aa59ffafcb6b00c83b718038b8661ecea1d41dc5a430a121a7eabf4e25eec26b7f2d9425f07606b4b4e352792ebe31050" },
                { "et", "a61fc492b276e0dab48997d552abb58e107ebcce7d197e43ec1d12d2a74816bf76c77683169587a86d17eac866b01e265c1a3e1033f02933eba9cf3209529ff1" },
                { "eu", "c5f8f7152d07121647d47860ba8d534831493104b18b4a032b110fefbbccf563ec6a4f3cad12739d6b20e178648ecc8e878b4c34c417983ceacfa182c9f9ed52" },
                { "fa", "72887abb533a4fa2a67a73bd4451b0ed496726190ef4e179be966999820bc4f6fefa9b6164ea0bc6a44bc53d23568f6bdb0dba2c25ed02908ddf177308ef6271" },
                { "ff", "a356c0af194a1e35d12637eb626f48ee259bf9651170467aa8e551061370b3e475bb661977db84a5f5cfaa5d8f8b98565877a0f141631e4c2f6babdb6735cde6" },
                { "fi", "56f1f9e3c93b3b94c00427602312ccbe09c15ea1c2e301eedd5954b2cb6315658d92303ca632ccd52db2be932b02e1581a146aacae1776a5bb7b91b9ea02449c" },
                { "fr", "4bb4484ccef733d6a243de0c55170d4d87aa3f4236c829afb94c75df96d7397f1605cc1fdc32c60acb2f64e5c2c95f6ff3d59116d210ccd452fd8d87f100af8f" },
                { "fur", "1c3803d170d02aae8d019cdee2776976e3e8a754bf1c0e7b84a01adeb9bbe7f8171a17d979209ac8e1532e4bede8cc5a7e008365df4f480acc747998436ce9df" },
                { "fy-NL", "357a5eb1dc5fabd442710a8a339d6cf48c814b31320d9ea193045f1d4bece8320cddcb27b04cfa98670fa68abeeeb3e6e4ad34597314d67e3123ad05015fd8a5" },
                { "ga-IE", "5c9275c83a670591014b0e8ab1987048d25f780a18981e08ab5631449a778f5ef0d3e5a2ee5193d6852adbd256058568c2aa934ce97fbc6312061ceb21fcc36d" },
                { "gd", "c28a425033da2308d9d0456f32cb6724a680b8ac5f83d4e25af7f291b110d8fc2d998e9e1547d897debc079bf8d15f80327980568b6b2265a34d9f1ab13f7d95" },
                { "gl", "167cbea9e666c2c7177ef1453c22e9b94e08b01286e9ab90ae88507e1d433db05fa7583cedd4b0243eb2df801449c1ecd7e8155e909a823fbd428e10ce5a2982" },
                { "gn", "1d0d9832dc9bf272148137623635d1db69adb461499ffeb345e433597471f94ac923fffbe1b4c3c0b8c1c6a313a0f988aaea4896fb51033e5774a34544c6b10e" },
                { "gu-IN", "1541e137b3b8e78dad0c504d4d981cf3c7ff0e625c8ee3bd1326796b29bb07ee336b0b698823c42e612588d4c985320956ccc1c9f4f4380125f9276d47be4aeb" },
                { "he", "e1944f045aa6cdb3c2e097f79cf94dfe58f6444d0c2a14aeab85b0808febd4b34c8e2417b59e8f2e064d9555e06ab64450d24a714985612c9406b0d16b00b4e4" },
                { "hi-IN", "33a995be26019d1515a2d24a46272317b7d111e721d620c4a4ddfc4f7fea06398436210cee284b9d31ab8226a803043a70e3798071d591448530e24ea3270c63" },
                { "hr", "dc3ab05b2625625a8bde34d2d65fe1b6fadd102a79a828af5681c9c8ef02a88fb6280e76833e2f8cf1ac35e6a689f1429e7cf1dc84dbbceeb827bdf5977cea4b" },
                { "hsb", "1c50639abe62878b02f078b13880ca7362fefdeba342a78c37271b2352161860be6738d0c096a53bd2133f9346cca1499ab7cb43008fbcda46810113089c13fc" },
                { "hu", "8960366024477eebda2ac3f8a31e82b1f847f41425209519018c1f091d9d09e6eed7e323a03399465feb6e444d28eb24aaf8f1a02105c02536db1d287c337ea4" },
                { "hy-AM", "59110a711723c7cdf5d32f7127a5ff7d2d2eda3380159d5759ae7a5f7dab79239a3dfcb456ff38264ed99982bf0d96ab06c58870cb5764b3047d3e79d15311d0" },
                { "ia", "cf10e3697e50775220b6a762760d704941d42c3df1fac532ed954bd7614367bfcc19bc518dccb64c4ab445f025b5ba820dd1df12de5b33fcbad7a07ded650918" },
                { "id", "faa37cac3cc540041ef6a7b1d06262be1091be8e59472f3fcd8756f4dd97e5f318bc632bf8d8978ec2e8a0939f080fa9629cd6cb94cc68bad72c2b4f499e5dee" },
                { "is", "cbdb786fbaca922b99fc7874bfb6db6f66a5c3161e09acaec143de6e2ac48dad16b5201f1f6e68130fd5da5bbdc63921f20b400aeda6cc659281f75baf7587ab" },
                { "it", "6b8357301c1522bfd41873ea50c64e0a22c50f6a110368d3213988969089370f75e46efc0bc5d4e410356791f43c33277ab2887a65c061d9124e34f3e50a61c1" },
                { "ja", "8dcde52ef6ec56293bc6967cd04d247006b218caa382079d7faeb43d9da3da76011a9edd9d011aaeae27e046a94a3dd799b06bd8617bee273769f2573cf9fc0e" },
                { "ka", "2ee41f4e43745c5df858d0588b7726e55371fb37400650ab538b1b211c82c158aa561825db5622297ee1af1f8c0aaeb0d001dd903484012f9b476cc59f4858df" },
                { "kab", "65cc51e3f3686e7c7524e4a38beb3f48888fbeb71760d5dc391be5d7dbd423b36a26cffa737bfa7014b70568b00078bcc717648b4c51a9c4b0cae4888f79940a" },
                { "kk", "7d9ee97d21d60f302d46947889d91d5fb1fd3f722b47a82f005fc235d01636958e06786831eb8cf6fdedbe9492a49907cfad0ca3563bcd628f62cf0080d6b582" },
                { "km", "807525ccc0183b7d84e2ac4834fedb28160add502d6d6d1f98bcef408d1b5d4771c27dc66ada17466008d11b4c5736e3e6ce09d459f36c0d32329a6ac4ed530d" },
                { "kn", "dfaa1dd51910e6388f0a704ee7c96e2f66f08ff7a39bc1b4b1b44d3e1e3ac5967cb380ce23dfa280cc0906a24742eaf1e5caa889c6e1d517e9d103bb8dd1e332" },
                { "ko", "5d0f96830c516c40eaf12430f38c08739687063217c143399ffd3efc2ad596fe7f09f1233ec61db49422c7a102fe122a81fee7fa528a07ef6fc87377f67fdda2" },
                { "lij", "22f244851b7c2139999c1e603142971f23779686195d56e1fe8e786ac085830a229a744709dbab74df85cb612cdb6118a6fc37ed1befc7ef56ceeb5a10a6eb98" },
                { "lt", "ae4a0366091b09b68d71976e57c79b988efd9054f50034feebdd310a6d9e3865e61b89be1e1433d1047a33bdb72c275df4aabf037716e800220f51dbc7cc96e6" },
                { "lv", "43fe1a5df0921d32500bce116a6c517eb875e86a5b85d118ded6af4265461476b0f3c3e1bc33eb5291f0deb9bf04b6f764bd50ee32a2bf9f0c57526cbe77a384" },
                { "mk", "fb7177c6a2211c870c1943b3c28638998145405d02003354565f070a19ec1d04004b2d1c33936fabe3b077f3117840225d3460b19935158ea809f02f122530ad" },
                { "mr", "1c9521deeeed82922d16643240a3ef5311b3216f9ce66b1464939a185cc88759441925dd22a121ee8db19e8daf70eb871e4a347b27fd8903d8d7f79bb11acd67" },
                { "ms", "a533b06740fd0d45d326c53e436c85d1b7358bb96d785642be44df92d838742244fde6586847916f8a799c83df8d1ddf38cbfb3b5d007226fccb7d3bb4c1ab97" },
                { "my", "f3bae326cec058413b3b59cdb921babea8ca73e58c5f98909ae45e7e5c0f358b64699efc4626dab1aa7e80883a3bb9584408311ac2b27255bb375aa42509d398" },
                { "nb-NO", "9cca53fcafb3d01029f185d126d583582ab6ee08068cd77ea3ef8d404f2b060b23d9fa0bd474f4d529e9cccfbd71b8e26ddc93fedb0d15441ad6e29fdf6a961c" },
                { "ne-NP", "df0054b8c7e96c3e6646601844146c975298cfac615b9a698906ec403c8d093b05ebcaf682250988245a2198f78b532ec36b570ea8db306a9fce880f5540b114" },
                { "nl", "feb627b8f4356422d9ae5f2bc67a9bf06b8e2d4f26fa86d84888c47e709f185e49d335b2a430e447ff2dad807f9f17859a5aa32455c8e9ea73b73f51ee8409a4" },
                { "nn-NO", "2aec64c229b80654d93f1c2dbb8f4224677984ab941a98c076e01b9ee7f1e94fdb1c33c35d7782ca92ef51f0186698616d32c227f3feed98201cba5c4b74b9fa" },
                { "oc", "feea0b697bc8c43dd387e0a3003aebaf7bf483fab5678fa531e05b553c640604d0747ba6496106f2fccd9bbfac4975bb17233260974986cf4880addbd5e27a5f" },
                { "pa-IN", "4ff40cf5a84b803ad473a8050c95f1a573f22c855e3c34c631a7d2eafaeb608689168df65cc44b9498f17da83756d3018b9f5b25996ab43ded60a71ff3bdaf52" },
                { "pl", "a8b47a11efe3a23d3bf9fc231062f9e9daed56bb8d5b6f56d356927b04fd104732621e2172307ca93607ac5fa42d2663dbea9df3fd7bef8ee7bc3c6cf567e079" },
                { "pt-BR", "9f63535825d669d48468cee3c6fa329d30e24b3569e314d7427560283831a83f64ef65daf4b810d2c1b4116949291130b2b9a8c25093e2ab5b0d0197ea4046c7" },
                { "pt-PT", "5368ffa117e19813ca35feb33ba6561c876c642096dafa3f2fff7af096804c583a2ee076775c23e7cf473b3cae2bdb6492c1d3feb80307eb4ba4aa1c31e8c4c1" },
                { "rm", "b6bf9424c79156df4643db58863b8fe058383f18501e05590aa12e1c7bb08dc075694b656bd2f9eaf0578a94699333f1c2ff8925c1c7c7ab36287d9acc25bff6" },
                { "ro", "b82a3ebd051bed3397a41ab6b7a2f4751a3d3aa45fe6af1837c7aa3468c0f6bb5dc736e47d000b673f1c0d7952161fbfe34a0163aa3ae23724da02b512773fc4" },
                { "ru", "5b34f5ded43f922afcd3217e920eaacba96c4c8a2d44fdb47d0e5ee2d96825077e0d2b8048f3d66a99f1105b7cddc60711fbf33bab5e455cd0dc190bc404175b" },
                { "sat", "9fce364914c11edb285d6ffed37bc697701c568d46296cbc45f8350409d55147bc1b73a790c7e804f64d22196b501c76efb698ceb61cdc347d85c70ef88975b8" },
                { "sc", "dc3677f4a3e5d5a127147ea3a2c47df519af4bb2ea76f894b72fb7136a855d29689b363b38720b2930dc4077cd03f3d959b388b4a4356e1034226e61d10cc1cc" },
                { "sco", "7c816601b8790c7a82d19a6b357ce83772d0eed946f5e10b68ab8dfdc549ce1ba0d1f534b5759ec9bad0944a97729c42c1b490752b8805451bde07cfc2dda666" },
                { "si", "82f9b580d00bf912f63fcf74528119cb05312e23537db332bdde2a47048979c4417b09393df54814a5ca16afd8816953615a48ebb789c9da46af19d8b36ee3e3" },
                { "sk", "b2fa64fa7bcc9cb5359215aaee4bb7686d64bace21195c3dc56511f30dd147113c4f026daf1683082b28fa8271ce805a83284e674926bf0d758f576c5836eafc" },
                { "skr", "48f2e26f0bcc3be30c5786dd9ca3120ecda2060b4c76844acfe1a8bf91411c115781d3a4d413f5d626d45ccc1d57c64a16c4f4fc3fa5d76f229b0bc882d5aee4" },
                { "sl", "290e34c081599021259d31703d9dc287314b86e4db256d31e5821052133cffba175921d9c5f6a2bb44a29b35251a0c5efe9880c31b653b0b4c9ca004c33e9694" },
                { "son", "22649050ee52a04630b2a0a1e397bcd987be40ee57fc7a339ae4fca4f845cf5c45b4fe12fba6c634267591c8381ffcaad88717494f83e1a5f220ae000b71ae94" },
                { "sq", "d6f58d94cca93c6f9f60a71bc89fb12040fd8dcade33a17f834a4c1fb51ba510226424df0da81499615c81ff0a1806607ecaba42b9c6273e93a25c8f756edec4" },
                { "sr", "762a60aa858da0fdb439767b092432607e11133f878895cf5a61d94be89e0367d54b8622220047ed28a90649d3c6a105314fe13d2cf2387369dd802578beb97a" },
                { "sv-SE", "97d83fff7967c7a8ec61e94fe18b1939bdede2ca1c0c4eb9e79fd227ce15f0606a06ffe5cff03251f321c56ab5010fc7db8f70fbabbbe2c3f6bf68d8740372b5" },
                { "szl", "2a2feec3726947843b6517ea73acd973106ca4e0b88a2a3efa91be322947bbd90957f81dde3af838eef1ae0947c1ccf409155a9f85446e15f9f8d893e36ccb75" },
                { "ta", "2bc5b31747e435b453717fde56e1969a94978c65d27f3e8a5926e285b5f8010848221db6e754c837c5384391f3f7b57f5f22d9c66f935b3f85e151eb63d28791" },
                { "te", "2c11d1c19bcec2be4a887c0b8558466fc6511202f7980405d7c3678ee48b4a45e8eb0d10f28650096465419741d4e63c64614d4e3cf7fef23cc0c8f042d3b6f2" },
                { "tg", "e5219b65a34f6f916a839c6dba4bcb749f88c35adcf30d7c4ed66b7974e4b1a139f1561b6542d20bdd4c69d09c21c0e4af04b8dae35f45e3f93fccdc1837df64" },
                { "th", "6650cbddf8bf627a84940f1329050e98d12ca36f23245f04612a1bfafa6fb496859f4d1e774ccd93e81ad6a5ce97152170b4065c6f23740311024b7143a34ae6" },
                { "tl", "3198382e77bc9c5200e82bf1b5f71ac292c0e5e0b23089a362e06fd2c3eaee7352583ae6c265cef71bfe5a020d3e85c94ace50ea2846b5693736e61b2e610c48" },
                { "tr", "79bf1e9f9c8e6f465e79000a577dbc9aaf43a924ec49cb1430b49ff35c621d432fa09afbbe262ec6cd7ab29ee21ee43d7040acf2f79463a571242b79b88077ec" },
                { "trs", "d27912b6fd394de7ca1c996114baa3bea8b058a7c0d38aadbfc67f0331ff03ef3765119619766a30e46176ef40d0a4ce79975d4bcc009dfc268e9e0ef458ae08" },
                { "uk", "d23084208e0935fbc51ad76fe59bc830367a4a4fe844eacc4c7f5f42df2e5fe24bf21c5e0b13f9c65086bea5f900d6e3eb23f142efac92aa31ffa1a913450045" },
                { "ur", "867c7eda66ebcee3526f24561e4f7443871d44129e2c136368c2dc0b6a42dbe8b15a7b3f22c085ed64ca07318890177c11f68f9b15c42ea7de1c508b5857eeae" },
                { "uz", "36fb35129835a7dde201b08511af394a3976be08beacb030839c32f8c48ec675e8acb68e614191bed9149eb01aff9db0b35b4da3424694619e5a82805016e618" },
                { "vi", "dccd6f18d968347c98221d0d4f2f9dd4974a391239aebe7dee6ffa8dee6a21d64ddd5355f61b80db1576a5b8caa292da612dba686c608f11bb18fb1db91ae230" },
                { "xh", "dd6ea4564b0c6ece68120b3844adcd69c3001c140a6bd3615d706b0eb1a22f9ac558850661d4212954fd285a330cd0af112f19b99c6af23e731f2932c3b546b1" },
                { "zh-CN", "7007f01a839f3955482da0c5939eb60ebf4801782de222c28d8e48ba8b732a68745df116bd6c6d9c537a797239534d3754697f3a11318b23067b5e154b2bc346" },
                { "zh-TW", "198fc97dd9cbb16d0f160fd107ad784d579bda6a58bb12a2d30fbbec2c9ffab67fd9a598419a3357f27c52a1dba12882a7b7ab0621f3c072a25009e1b11ad566" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/153.0b12/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dffb8bfcf94523024d506382b85beec3f542ab16b7389178541090fbd74f25b56f9aee8d9ae24cd0beedaa0a57c40ca94c2cabea4caba182d9ef5b2e140afa08" },
                { "af", "08e371ce8101f10794494614e857dc7bc1c516fe60e36572cfd66bfc19e39b484d25be4169c79ab01df2a75bc8c1ccd421e6c12d7fb6ebca578bc8382ca58100" },
                { "an", "e0135a72313045fb65b2b435405e3eb9adf8abd38611cd32b5d4578488c128b7442f7694358d6a402c50c8ed30764fc6a458e128d2752a217bc173f81debc31e" },
                { "ar", "fe1bd8a7488ea93449b9cc221792930c2dfe1b790c8399f0abd4dd0e1d0aaedb16b8b213960c182370e477d867c6c875ba4140efb9589e1c4a9819ba188f88f7" },
                { "ast", "5b1bb724b8839eaaca5c44dc63a452f76d7a1ece00c5c3f23fdde350da769246f07c6700c01514d43d511e69a64b32e986845b1bb86061a804aa089454a043db" },
                { "az", "d11d9b1219fd3d5f15b24141da02c8f7777c4ebd8dd64f9dff82538158c50b77c2bd32f48a31200cfc3e7bb03628151c418137fa74f9fcaf78d2947d4658b222" },
                { "be", "6dbfc080692fbf36221726df24c02d8f1fb90708e0d5c70ce2197229bf6945e22b27067d6af2713c6e4d37e531c6690fe22b5809956cbc7d6a4756c673a120ae" },
                { "bg", "5ff16e44fe6a5653c312e7b9aabc73de39e027c6fe487864f9834f3d71064df1636e6ead913905ed67935f8222ea5b05b60c0ff39363c6e040d6679a9e73d663" },
                { "bn", "5d85e7581a4ec5269a089ae858bd6c4d1ab948fc673ab7a4d33b0255b0283f3d7d5ccdb0556bf00dcd3661e2b2cce9c379a005f1a43888e2a8a2983f1c808160" },
                { "br", "0643092f7128062d5b2057aa3a4f9452824ee2bbb1ce29f438da5f3af32039d9f9dbacaa6e69b8c94e61b6f677587e6f0fac3820ba4992c6615db99e60effc1a" },
                { "bs", "843738f165bae8e9b998da6a8627b1af684d23f565be44cbbaf461566ec35cfc769262be53ae3f541fecd71b4e4c9df514791e7964b44c7b990383338109843f" },
                { "ca", "8c5c5ceb1cd2892fdf038d17a7d1eb1de0b297eec226f36f028fa9ca517869fb2f3706d21660edcae9bea7401b4097ae1b99f5d1ac88ccb98ff6acfb5bab2efb" },
                { "cak", "e6483f904f51223c98a2d4e1532ff6bf813bc0e1a9a6109306a237f440df17fcb90510b405add0cba9219a59ad5b184e97c728cc1256ec3eeb1854a5348ac33c" },
                { "cs", "ff0ceb99356acb832db7f910026f5714dc2e5dbe80242ffc7972c6abf4cec6516d5033c52ab43680098699350a7d2878d852f3bd4cf8825a0417c2e7dd1773d5" },
                { "cy", "72e7b43a8b1c22a1533432037c4e04f0542de2a2b9d4415c00b66b8d38d860425b184d6d60c76b0735812d0d3e08d72cb96c4e822d431bda7c266944c4fc7040" },
                { "da", "8d9e4763425a78008a1da2f7b0ac3aa42aa4c352ec306ac79c7c2cf970d677db2347fd96fcc850b5af309599c937eae31902bb32755156842366993f651fd9e9" },
                { "de", "e539a0c7c2ac514bbf0a9e82cf32e4d372287cef3611abd19bdec334b1dc43b65baf22ab023dc76dc2ab3aa005dd3a6481ee46532b80839d41917f1970ca1c73" },
                { "dsb", "5128dddb0866334a746e68c06c30daa2966f27f16947272063e7a9a7d527bc99985b6b98435cc236029d7c2c7f1268be48d4b0a22bbb387f083438a84ce3174a" },
                { "el", "13454737e79fbb53d6739831a9eda5e79348741e5d64fe940f03c19966c0805e871334ca1fca8f9432e67d8880f78f4ac3b7719645a73c702bfc427f89402a43" },
                { "en-CA", "631f6adf753bceb0fb21f514cf75eb11bb3232e260854349b535e30c3045bc21c9852602fe9ad2b47c6d1f6b626ece61114551d6c3f86ce067008fd2baf53d46" },
                { "en-GB", "7f5827ce37684012010eff81c31d526312e65abf16225dd1a05b9a5f412f018becbffc07cf0d2624e7f210cede236edcf32b0558e20d46c8e724316d4c0cd50b" },
                { "en-US", "081767db5967d4c987cb43baf04196b5941c8e93cdd6e24e1cb02c06511b5bf71da4abe1b8118c628f26b127bbfe110410dbfe8087f884d6d232e0c87e25bb24" },
                { "eo", "2f62bbd9abe072287597e4650b907ed51d3f14a804caa5f2ae13631acc8ce54bd4c94ae8c1e0050c2d3e9d44b87ee0e1d0262ab270fa21bdcaf20c456028cca1" },
                { "es-AR", "8f46bb0cb7a8966d0fdb790f412179a370e5f27c26dc72eb06cbce6bc60fa7998bdd9219c5366ae78b03a5656bb6af04a328fdf2618743ebc3435108f924bb6b" },
                { "es-CL", "db0853c11af1e431d30ad450556e27af11457073e3b33f45ad53743eb240cd196ed1ca84e9938cacce1ede4227b8fe23695358949f742cb21f278387e115ba96" },
                { "es-ES", "f34304b6c31f085215c8174c5189a6fb0da6acd00ce3b07c4a2764eb52390431c6fe68454707eeed6ee80a688ef6f2925170a3a97e26813271ef80290327ae81" },
                { "es-MX", "2168d6cd23530f54d45cb794a5bdec62c3aab41388583e9bdafcedcd6fc9f5943d81ee140a9d18a4a1aec811585bf849df74bd01165bc9736a883f35a2ec3eaf" },
                { "et", "0edc2c79fad5c6e41767f1b7c85929fe904a134bb55bfa0d3779c25fc20c60db27137d69ce300fce732a23d6364f59b057b1b4c62381383be5c90f3a6fd8650f" },
                { "eu", "1e1e7bbc73842b07271f990155fcdce4187919787c6613c441e26ddd97543ac2444b2745ec0ca2df5cdfe730f85c54401290e6f2222b042cde836bd28b061818" },
                { "fa", "fc286415b838d8197c29bd40b95e94d85fa9bdff51306e197bb45227c68e69e20d2ace5a47d8766f3040d0f9084f87c18ebc639f7d7cd4c86b4f807102a38b27" },
                { "ff", "b952b190b52043aa14cde0ad0140e85bec5f6ac2791a674aba5a27028a7cc85003efcd6f6758afb8f07ddb6aee837d601ce4de04a55c0ccc76aeece468b5f5ed" },
                { "fi", "f9f27ef94ae88f0eef61ae342406b49b1480c5e049b37758982f62aba4d118bd7a324cb4fb2dcbafa0de6dbfd04014e270694c371c7e531fec4bd24f290c7a17" },
                { "fr", "c7b77cb7478666c735c474291407c7fdb150e1bbcedd78c9280353c5a0297c9282156e43be0d47f52ce7882af983a1a5db1055957dbe991f8b243af61e205e84" },
                { "fur", "fac265166c13a5e14fb0f2ecbacc032195c50f78fd68aa10c280eeea8640e319ad35ee6211143850445b2caf6558141ee69449de2455a1392cc4c41fe6418f12" },
                { "fy-NL", "bd51330d9009e55184cde4d61204ea1fc0b8d12414cfda905404d626bf8de6ff6be31c3dc14b689267a607d503246106a45f95b8a5b8ea037883b712737dbb7c" },
                { "ga-IE", "4e7d6df0b40391a7293c8de93cb5cb7645361a0f61c95656eb750bd2462b929eaefea5d9f5fa8fdd5a40aed2aeadebe376c48f15816cc91dc7330497bef2e569" },
                { "gd", "14e406cdc951616536580c8672187c2e9e08892e0658e077434eeb709ea375db6a04064f73f6c5934a773af65e2b8d6c2dffba5c159ba4b11b48f172c9503450" },
                { "gl", "c44f0661e9951e808fac9b65e99e644a6ac9c5eca6439722dd282f6a7422c168e5155744d0252d5ea7861ef334c44a65a940e0bce9133cdff2c28ebd23c8e61f" },
                { "gn", "1ed360d225863c530df77cb930d997c99a3d0917a12e0f1b8b9e875ac8587d0f72d102902ee15cea88302fce1580188f186c5e48ed8222d8800856d57155af49" },
                { "gu-IN", "945c4d895412e964bb05c3f968af65a3eb3bcbbe966a31f5f61a55c16e7ae38565ed3c56759293480fb6c997114754fd79d27342ac8245de87ea41253699e88e" },
                { "he", "4e737c0a308be69f1ab8f1b5e785b2d4601bc18f323be6d31b7de5db1d1c19492714a6276c3bf866cd2684106eee9e8b8b0895b2f74f7c986ef0115153fd81c8" },
                { "hi-IN", "345e9c56ea989748e2b12c8f9fbdddb88f3a3441b8a23c4acccec066ca993978757b2a973b05c51c13991cec8cc3c8533fa78433ce258be9608acdbbea70fd9f" },
                { "hr", "1aa4554f6a09a20ce11f7797b73d5e9b8663dcf16c27b2bad5265ebf7ed90dbf66f7e271c65db705be533f752cdc3f519ee7a8825efe5721adcb426136bc732e" },
                { "hsb", "2481d20a679c475c53ca35b997f80caefad1a38ba9778518c602fed0f0dec1c21edcc9b4e2f3152770a60d11c46f623477880ad0a9e6bf76732a7d8afd465335" },
                { "hu", "1b3f4f57897b64fa1615ce8c28a78f0f5c7bf569c0c42e6fbab40a5f26f96b8bb749869aa603d2eeb4c8f3b0dd43f71591c7ddb077c184068c83d9efa433f922" },
                { "hy-AM", "97061098db67df796420699613c1b5e375f55d9de2e858ccb382dba548766f4999c46326c9d99f009b7e7acddeaf2d2f87c00d6ef4eef7dd51b8026eab7440f6" },
                { "ia", "1152aad03418e21e9279c702af317b040144ab319250d37cbe59e89f31b92201a76e3e310f9524bfd05550d81a69a0107fc74b4ee8aa7e6a19180818c165641b" },
                { "id", "fad3117ec35073190de41ee90196a93281a60ba6764f4a251f729371d6c495ee8635ab169383905db855d30856779b381b74103605c2f9b3601d77eb77faa179" },
                { "is", "4332af94a60487d5b8b348186d2ec4db68d33405597c84ff17c91670936fe175378620620408e69ea357561bb815366ef273e2798c94ae6d6535367bea4eb6c5" },
                { "it", "4e54421b2a382938b894cbb74c84b5919bf51d54bf5c9d4f72bcac17f2e50f9d836dc193c92b5753604af20dbeecbc46680205c3f61785384d77a5b1791a9597" },
                { "ja", "feb8539d68dd93c03c6bb0cfb7d651d88c62a4172a763215fa785d2c3ecb99d6151d95afb2e4654261a3b5832bb5fa8f212607fb181bb2af1e525679f73cc3a7" },
                { "ka", "255c3081944f8a26cd38f1002255f9732e51c14785cad79b07ad9812e9f69744510b784a562d9db09328a358a51bb5cdb933fe5ac16cbfdf47dba29626520408" },
                { "kab", "29d4cbfe74295c837eb0c1a3a02a6074c6b86231cbb7cda07bcdac25857b961ae7b4d630d6525e18974c015e510bde073a2eaf1fb99a1e38283d15fbc5239c47" },
                { "kk", "41a1ad9320c211b25610c49f69c844dfae6d02ed5412eb4e200505e4e82c2744205ae056a56dd83f055c6681b03d7998c46704f2856e35e60b57c550183c26d0" },
                { "km", "da01f87bf6ad76236555ae5535e2bb3ac1e8cf54873a07945031008e995e7c8b415b4dc3d635fd21161a6e941f3c61be40f23d8870ece5ced6ce5940f4beb588" },
                { "kn", "587be86dda5fc9e96420913b7647e81609e3d9328bde4d41c4164fd23be50510dce700b4d593e3d35b12c4ecd36ca434bcbe4318e360f265b000576450cade90" },
                { "ko", "5fb205cc5b83bf4276b781d5b05522ddabccbd5b59d70f7aa495de5f73d3e7ad698ce2ddf19aa5a70f07b032faba213c36ee263943723a5348ae8dd681765a7d" },
                { "lij", "9bdeaee9fd516ef05e9c63de80dc8e5b97f1af48afc7116bae7f03e1e89fc09af494f4e1f73df86d9f0133602e87acdea80681a25aff0bef4a22a242b080a3e8" },
                { "lt", "a1f3c09110ae3479f5eed5461e73e36a0a2d6740c86c36cb9566cbbe5bce6a1d946a06233e0f9dd45e87dae781806d63c6a95ce1ad86a1a3c07c4dfa6770e7e4" },
                { "lv", "5c0ec93676021a73950655d7e2db6d8d56a7757d96d67bf7b5fe236f247f3c7d3f00bc8cf8fc42c0fbd857ddc69a4db6034d5129e0035b8bc13237a6be96439c" },
                { "mk", "3a73118960d4fd07f0bd9bdd91597e204d933c3c2ac0ff166b6ebeda92b428b121e7956a6dd90decf16b7a7136de6f481d69c1ce09b97420c637d22d0eb97ead" },
                { "mr", "e462bb7e17990435995eed3f94e039d38c8fd1ac47699f83ee0e00a6a49d415cda89819a7c4f2c4789c4f941b69ce516f576a4fc7dc5d7fb6301a7cf101cc88b" },
                { "ms", "6795624fb0efbb8931e9edfbca159b6c1486649b21caa31ec5df2c8ce30471b964116bf3f867cc81c4eb0cefe3502f817edefbddd5109f449f71d4f9ece6c2c0" },
                { "my", "8e4eb344977e03fd14ef2ca668e406cb51fe5dc20392a29abf4f6017ba1a0b30ba189b18f7038ac3bc1433afb35609875be67b9b7602a5f966acbfeb9e011207" },
                { "nb-NO", "2982ab119d5f7ca32ccb4144082080b36e65d1a9fddc951c4f349eae10cd1a7fecf768012e0ee19684198bc076435ec915e33ac04b371ebf8aad9888d7b488c1" },
                { "ne-NP", "2bf05c73a3896d5101686b323c0ce5bb6f4697bc3c6081b5097998ea9daeb927313c73cac2aeb7fd79e1bbb966a0002eefbd59ba534665145dbe5adcf85dcfc0" },
                { "nl", "323308df471e72684b044f52eb5e15a4f72d6eb45c6d3d31d97b8170cb326fac4aa7fbcfde9cfc866f87e6b6cb1ada4eba2fd532645e2f3a9a93ad39305c2b3d" },
                { "nn-NO", "c1311f90c021764429159821a18245a989dffd84b00dd7da729b3b2131cc7e51fa36ac86b38d94759598fcd24f18d07bb88d4a7b28b443bbacb6e5a4360110ca" },
                { "oc", "8b85f327203adff63c27815ca3fed27d40626acd62130b5aefc4dcb3e2aa3165afd93438581ee1a3e0d8a26e98e304fef10ff45a021201b449b9e03b916e44f1" },
                { "pa-IN", "afa4d4f45111403d4f30a292fb8416688533d7b4ef757350753d3ca7a1f3f26c20f67fa5eac7e3f977ac966c0fc88a6c203d11fa82bcc8ae8483a4f2f20d328a" },
                { "pl", "6f6c1ef9fc1fcfec521f17ac6c1634f1364a6f85ad06858379d9a94bdde4c7e5a6454f26ded2142f58f702c11249c506a15cd7e499e4472f3e738329620dddb1" },
                { "pt-BR", "39ad0031e858bf18dcc70f8080f990ed6d8d114c5db7786a1d72c03bb97b03b8735a2c3daf96d23bc4726cd9818fa0249dd761838d679681d0948f2b3f14efbb" },
                { "pt-PT", "757e569ac7006b997c4153f238285f25964f2b4a95214828e51d0129ac77c6e149f444ba6fac3db1b8a61faf52b05d304fdb1fc4fa110cd60912ae2bb2a7b97c" },
                { "rm", "c5a19a7f52634fd2b5bb34267dd775ae5769d656ac3bc5e1550d10b987887600a3fd3d9974c2a39fbfbad094cbd17edf999324915eda89381d95d91ada0530d7" },
                { "ro", "84aaa73b565ea59af66f07f4b7dabe403bdca7424deadd44c8b0c4287ed96e2818da1bf2c1b47564d51cc56ff85789329b1115047950b9ac90ecc09935291a38" },
                { "ru", "37ad6f20f31b2f722d9c84d67cd5d622a1da8a550ca2ebc3157b0632eb8fa8a7441c8579b9cfc5e46f15058da4315fde22baae625b6e08ce11aec32e1bfb246f" },
                { "sat", "0fa8dc8d8c55b527f870e8943d34f352840fdb1801f47c54f84eaf586bc274b2dec896145b85b5fe7e5dce70436582aeb4e260d156fc65f2402495e05eecaea2" },
                { "sc", "e3843219f31fa884458d29f63dcaa6cf606d41fef871e9fe832fabdcfae2a3e4904ae7ab085bade01fa3bb3e9fe447b33d6751628f35794bd2f2871b55266577" },
                { "sco", "74cb4e6b8612457335c768c39f507eef1c6ef90a04cab14a0736d870defa4b5de2b23949ee81663cfb2849c532da0cfca027a3ef5d2d95e7aa53b8de5a34723b" },
                { "si", "f1b8cdcd0e090c4fb6cf4c1c9879d84222944a2284719280b38cee14ea37e9b453f60e528c6bb106ffbfeef74a37c444ecd77e223ee7b127916bc2530dc96cb4" },
                { "sk", "46b9f56f62d176d76bcfebc7b882f269b16c92e04c1c4b5fb5b991b2c605ab7900466ef21289b0d333aaec0ee2c552dc34648d5f67eb47c0093373018e084b78" },
                { "skr", "c28a0c7c3bd59bc3cdb0259ed2de9054b26ff99c07502eba9211fb8d72c150be90a6e92fbe127bcc23a54dddee659451aa7de0b7904115fb360c7e82ab28a282" },
                { "sl", "d6d8d625fac5eff6a15db7e577d9da0c541f78114bcf2ff83df47db21a73db295b8de47fb7188ae72f357e952dded0ad80ca444daf36ba927fb301ce71bd7dc9" },
                { "son", "69df0f0368678a5d9b3445b403259ea6095b6bdc3903ffe125d92f87f7b177c4a2ae412faf726d53fa701fe0013c340d58c45be572c4edeb555237cc52cfae2d" },
                { "sq", "0d0708b2bb3c5f52f1a503930da28bf07ca982880181ede22061dfcd19748f2e61f38f654861f1298dd1d5e49f3a75cd3704055fb6514b2732d4c49718b9a0ab" },
                { "sr", "21e7370236e07c4580dd32af35c21ba6123aafc4aa7249051d5a722951fc56ddc3748717ab488784888f99b99b8326551f35d4820d628798b485010c52080826" },
                { "sv-SE", "b343968b840df2685444a5eb8605189f8e7449b11bc1d2b39f66108464d8818c3d5cc08f9fc330af7b6c0483157c7158185b7fd8c763c4457665127074818f8a" },
                { "szl", "0ef6c141362259ff7143eb7dc4d4429473d78129e33ef4678ba520ddee507b3c9f411d7153796e770ba6fca0a48d83fe0081287dc856a3281016dd1a63d6b6d8" },
                { "ta", "4b1179ce26b9987a7d1c17af6ad874b531d1e000d64feaf221eb53bb3b1349ccd9c7246a1134806648c66d863ac08f6ee12f332216ae91159e92617f3a34ad63" },
                { "te", "106416e0fc9ce575ff8d110ad58d0f4300949db722c6c77b411c49758fc6d680063fa32a833276dce50c2b957f1589678c72e0629072e0389a24e71782bbd74c" },
                { "tg", "0b6c6adc4c0c76cce88fa5e369f9a0d2ee31b5a943db4ba495ea5b8d89efc8cf0fdc8a732fdd5f706b53cb9bd65bc4595a55d1d7d7d9853a82ee659d5ba68958" },
                { "th", "7ba054b8ea702e208fd5ac1fc58aa5b853cb1579b188024e19f189fa5f90fe2547638f18b5728ec6bf5d1fce535fd22667c2f0a5d9c4badacd6ec83398d10358" },
                { "tl", "5f5fff89088097c2601fbf12bfb31b52f0d9ffe5e66e4c3664acc1843db3d1076cfd49906526db4d82145e1eadd44d013e589ede2d0c37e1cf2961f172ff97c8" },
                { "tr", "6569ef87a569e79ea5a44d3d4371b89db6e5d0b7c192b21667783b909cd4b65279aad22945fdad0c75eb711dbdadcbefc84b01cc4d74b8921c365c5ce16011ef" },
                { "trs", "7165b65827519c3a0fba592a243bb12538e26e799e71860ecf0626b3fc1ea2064adfecc533ff6f1bbf235162fb0aed7f8a863f6fdd29fd8939bab37f8a54efe0" },
                { "uk", "2956a79b180b8cf4070fdb2972a8e923f33cee95c7b1ea81e39f6a386edb7b18aef817ee9f34a7bec6302e8a283e270fedaccbe6b564800a71fe2a90524f641b" },
                { "ur", "c22f4431fe248395584dddefac7743bea81ffe2bd18115eb82c393d99d719c53a774268edc5736f09e20650e7f0c980e5451f446f14561bf0a9e1ebc846ec292" },
                { "uz", "dacb8bb6774c58e68b7ba53c623e8fce704ae1bf8434e64f49bd02a00093094452b0deb2c46e23b1df94adde0e597752ff11d46e0b69f7778992f4c2bf7d0852" },
                { "vi", "c5b9c5d8ff0dfc84ea63ba34900584d5a18b3ffa2096f605662e3c68c05a9d723750195a39ab09e097ce6043d332ca8c7594d26628784a3330f8bd410ac33dd0" },
                { "xh", "3dc71cbd8758c8dcc25bf2780372418e2f0b5eed788f066506ec95218cdf7abe1cc142a6c7673ad8e5b11b3e40202a8838df99b586e1470eaec7bcbce0e54706" },
                { "zh-CN", "9b8f0a58eb7756ef37b2b369e78bcf63d6a19360607c61ad16752908ea77465449f002d9d6472330bac6b03aff351abaad5148d2e9e0e142c17492eb6dcfdf82" },
                { "zh-TW", "b688b758d2a14bd22a97b10bc9fb175805a08cb519dc26c050757fe9dd9d2888662bb6f7ae5dff6ad344739032857374a28a852267b14460e1e25505c652e04a" }
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
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
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
                return versions[^1].full();
            }
            else
                return null;
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
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
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
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return [.. sums];
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = [];
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = [];
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
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
            return [];
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
