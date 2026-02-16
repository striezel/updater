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
        private const string knownVersion = "140.7.1";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.7.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "bfcac5882c19871762bbec0690fe47b70b315cd82751230f15a922d8375286336eecd92fd2572ab1c1d84a25452a96a0cc55919e5fb95d6e44cb30b9281431f0" },
                { "af", "28ff9fd3ba4f6349d421119052edd0406da45b5a19308fbb9f491d9ceb8ebd171e89ba646ef379054d3b94d4c432129edc861842b82cfab1500187e91a33b32d" },
                { "an", "d44ae725da436dc00a38423506af871db301cc75cd406bcae1024202a75ccb2d669ebeaf29d7255889055bc3a143d4c7b57c41b03e154193f51a7b1c692b2d88" },
                { "ar", "f209d3076e23b69e21f33bd5551b04b6bc5c6c64d37d98c16176b2f5ed50b6183ec1694d868075964cac815c7ff7af8988ace74912dde9df587b9f55e4dd851a" },
                { "ast", "cec155e48b5ca3b5dadd1dc248eee62286d8bdef16a5bf71c6edf5763bf368915dc058932c612ba0beb0cbf10e80ee8757e44f803b88faece1143c9c5b839a53" },
                { "az", "1f3dd2f75582aea0a80ab19ebad82e055ede1f439e9191f66e3a4dea39b9c62be00d2782cb99f80785516526350db8847be8d6069c05bbfabd626a4a64c1a281" },
                { "be", "5089144e2c15fa8cc7d1259782e793fe260617655b8d06377898e44508db595f6910e38f96fdb27d6b77ac30e02b93dd06899f384ef519417c3e5535fdad141a" },
                { "bg", "81981a26a443c10b0357f0af3cfeaab812e6c14f3f3a4b93b0c9c9af9bfa72ab2acf493494398a9b6c73925caf32809dad3516d29287269c62b7a32447c1d864" },
                { "bn", "0cfd656e8df6033bb1f11d7b0b0545a8daabcbcd182f42794e84b6159efa801f624c3f8ee79a2f762edb74caaadd4456a7c5eda7d39892425be534612d4f0c62" },
                { "br", "5178c84f13ace626612e5014993ff6c3e8880804f8b22c352c070bb738fd741f59dc7b6739d828c8675e0ca4dbeb5ffffd01abd4f2ea6510357846fb8834f8e9" },
                { "bs", "d1a13f346a1ffbd7304a4185b3348c697dbe1a9510dc6ce2cd47dba12703531c3295af9fa862ee563cb7adf0e046d3b56fb2fff1a593c5081afc1a46d568ceaa" },
                { "ca", "00cd84ea026cf8aa277879c736f689139035da46fbbcfc58451bff7ecf75463e93e432042df394fbf7aa74a771c52088bb35c658374d2ab44ad9ad5ff2543c48" },
                { "cak", "aa69cb80b90b8d893dda9e7bfa8072d716922d91314bf752237d929e8619a23a9d5982cc1cc05835707ff463449cc1c6a09de400678ee567b22e4ce3f1eab53d" },
                { "cs", "d51267bdcd6c5f9fe2567b57bff2bd3d63392a7ad9a35ff62e3dc2832735c276a3029d8ab6321a1bed1b485857a28dc1de4b312ac50dc57a929668310911146b" },
                { "cy", "b495b65fea74383596061a10d69cb64def719884c0cae8078e7c91eb6dff59db4809dde753b1d649b9e35f6688186c59234ccbc0cec0b6a00c64c83a9df9a474" },
                { "da", "a7d509e765d1868d845919a72b6691768db850dcfbc0303b0ddd5ec1577345e3222eee6d2cc36fcf4c099f7158e760c523beca32fefa16a425ca40ec42611ece" },
                { "de", "4309c1a81c048e563adf2a55a244ff0ade46b3380ff20c05ad1fe0e67f2fd0f318c3953d30295a9599bbe54c408d43417b907a12e720a0af4062be4c58b224d6" },
                { "dsb", "f52ce8539ddfc7aa296893dabb21e2f7acc51ef0ea6b852744912704a6b34ffadd428ddc6b1a2d7bd3c34ef55ca679f4bb0eccb50ec4070901a91dd7d4f90f05" },
                { "el", "534240a387d799d3fab58cbd18f5cf9969e636265e30a0fc1a11cdf6a44dc0f802b5b49a8d873d7eefd026b87b534ef2e6e7f1ab7860c474559bf984abf93f7c" },
                { "en-CA", "eb4add88034ca02b1fd2d92fa4da81db5eeae0530120e32fde0d8752a5f8ce2c1039e7260c324c4a9efb636a1a6a6ff5c486937f666d7271e4b616e86611c812" },
                { "en-GB", "d565c808ea7e4985dc7f110d0534c59338bab90120be03e41aa7cf073bc43e2cb5ba04187d56025d06ea3924a04008c9514e4e2fe79836a6e6d306e4f1dbb0f3" },
                { "en-US", "4d9950679224d8a0ecc2d8e01666949cc0569e08ac39e379b08ad9235ddda0367d4a089a984274089257376dcce638b2b059bec7edebac916955754557f16f23" },
                { "eo", "b906061373297f0a9abd50cf6b06417e464f057e2db2e72acd81aef1b7bfc397b0aa7a160c195bc68bc50795038a1679482b0b3eaabb55cdd90c51ccdb585a55" },
                { "es-AR", "7ac0328ae26e7ebfa6157fb45565358ed38f55414de5055b44857c6645f293c755e7e21ce64b7c4f71501954c39bf01e0dc89977515210df9f172a614b256cea" },
                { "es-CL", "38a404bce6c594331700f77ebf32e0d7d40685198926482aedad1e8f7e1ab4978cf44d8c834adf2280ccdd59e69c3fc6b6c6c2e41741232482738aedf1f5dc2e" },
                { "es-ES", "d7f688ddc90c1dd1d348081f79513ce7a95226b41ea1cd7f8f29c1ae8498910374968ae39fa3e42330f0d037cadf622e92818074cb761cd9cf7fcbc05c747042" },
                { "es-MX", "d211192363e4d06e0050607c7bc6058e79b6c117cadf6bdb98bd744054e4ec4dfbf2dbdc83f0be50d84436544ff53ee863fab85e2bae5e93c1aa89ffd850c312" },
                { "et", "80a92473932a7feb8d6c127a3da8ef583c240930d0f349a4f3c5c40b2222cde3b5f544ec9b355c74727d5ce4392585d298af0b8f309a2aa15bf6efeed48044a6" },
                { "eu", "9e13d893f6fc306671da7dd5987a76cc9e33630b9d7f0a4f013ae781e9377d396442ba47baab5ff132846d5dd466d5332ac3f9bdaebf04aa82feeed4164fb04b" },
                { "fa", "b452d59f1453c646485d0b091d5c7e55463615bf6fefec48f9014932c1931deca36f5c38cb17bfd20f7b8dd8741ded1ac611d40043d9f602bfe0d57455170a36" },
                { "ff", "57b298b70096445e7563d6cad16b82f6703352bb2a07e59ea82983bebd53aa9a6b389a69428167b1c956191cfbf12e6d04b8e5e50c5b1cc8a187265a80646ef4" },
                { "fi", "c3c28e6ac3221075a90299b94c6cfa1daf64906d7f29f3e6f533ae5fb2e1f4220e03c1a069744c485a742f797f710b776773263289d9a1df15148b98bb89f16d" },
                { "fr", "38c07dd51426364f300a682928ab44b30d3dc8e54025c5c13ef13abbfe88f7abc93ac9c3c73a0995e1c12ecc30b0f74c1ce165908937de433ff4a804cbbbf6b7" },
                { "fur", "1a92a0870559b5a17a823071e39657b801e257becf04995a7a61d3051d0bdb7a49fa6e6b529c2f107e6b2b9917cf722895ddbbf45fbaba8cd0a5c6b0aa0eae8f" },
                { "fy-NL", "fc4705cf8f27bbb0ce5767947c48d74a011954e4836422a0ee9f93e437d082fd95a079bd2f59433db217d8e36d5e3991302d8fbfa40bd3ce3d95fa2a9eb7e7c0" },
                { "ga-IE", "52ed651381197744679275d73c5938787dcf2c46a8dc0718a2d415e339c203630868388b17e0e343f363c1adfb3e4a1b4e7a816066c78fefca653e247b7a8f9d" },
                { "gd", "5d9d2b8a771cbb358ea2635356f254c388354373d7b5cfca5777294e75fc08dda585955df4a08bb98087e0801d6065338b3997a916ae6c68ba563c6eaa76618a" },
                { "gl", "41a1e639d167d7f617c49ef95fdbae1946058574926f30a7acb3eaab414cfa7d99d3f8a9e99bf33f15d06d7ef9a4ab719438937e9be688ffba60afbfc34a143c" },
                { "gn", "e24007f8a0566cfa860271004acf6c55853057f474c23f7538a551ed84709ff765e3e20263b516e40267b9fb1ef5b3c8f2669b2afdef8d25158222c12f207396" },
                { "gu-IN", "14b2bc43f2977a346c913bc73b4e00a3087eda5b7d6e58cfc679d71789e05174845f6ac86c99117eb753596c0d20008324ed7d200ec0f784316df7e3a985f863" },
                { "he", "5aab7ba9e8c113f220e185ae3b40b93c9fed93c6da7a1e099b522bdcb7f42f8e1bcc477fb2c5d140f96080b075a91a63642c10a8aab10de2c6d0e272d59c000d" },
                { "hi-IN", "1b741b3075aa280194c33d8d0014ad887c4e8a9e7cddeb572875aba16ec73efaa4a3199bf553077bf9795ba7b9ae7f1141c52a7d9dcb2e46ec35b9ef8c3592f6" },
                { "hr", "d81b76e1b9dca6f56c46b2b1639b161184df42c3b390c7fdde40d3979f9898d21b41b5e457596a83ee9ff2735c4cc5fdb4f7fd94cfec641683b20c8b1e1fa64a" },
                { "hsb", "927290dcd8522cd474bae5a22884f3b2df44007cd20dd5fd902e9f3c15fb5ff9a43ef0e396b2feee7f5df05bf2369360c824704ba693f3ad53c896d4e0e5dac3" },
                { "hu", "251db0660e21be099d0f61f942ae9a682600f1a61e4319231708e1416fe2b953c961e016649eb6fe2b98218ee3f30e4b5d7ca81e25f7cc7eea953491718da1c6" },
                { "hy-AM", "0ac52b92e36d6085ec9b28fa7beb6c4ba85bc789bd9d6c27758f878b6754668db6fa28492b6ac09c465e2c5b30452cf8aa2351b2f54cda9a3e090ebc1c11f05a" },
                { "ia", "ae34a20fdf83e2af7510a1f2f22d09d12a5e8eb2389db86501d0809ab400d4fbd69bb636deba181edc86c23abba7c8311862fa9dcf4568a91731b2f42ae9900e" },
                { "id", "db3870568a363d37c95b916e5e7d11b5142be33c1ec9b23e3057b8233b8a6a6feb66815ad136f14e34c78754a30325c199b04484630a0491ce8c43ecaaa67247" },
                { "is", "10d760e5f89f046351198dbdb7002d9748d6086773474ef918ce26acfbf4476e2775c75812dbade34f427ca1593a6db1240f8406948924e0ea16f03a1edcc093" },
                { "it", "c5fb92f4b72dac325221f6ab27afd7a48212ebc6a1ce2444e419f873561b0fd207ab02053c10987ab9ce157d09368893e9d83d5c5ae25422669400781bbeb5e3" },
                { "ja", "9df8ca1b1b512762887867bcfb8b5caca026e534ef1270144650243483b4e3d5124dd031ea900384e1634c4486a25a1cf3e6e971c8d1c75222bead891df39620" },
                { "ka", "f3e8dc4a2b1bfc778719a2cb693962530c84021f279f725d247096ce2013eaad5617c086437343a1c44d090bc3a42bb089f9877436fe62e55e1c209815a40eb7" },
                { "kab", "3ad169ff1d8e911a49ad06d831563f9e516aea673864b0cdb965387cd8e71efb6925e562a6f5bfd7f7526bf774f0b0f04e1f832d44ec00309143575df822a1b8" },
                { "kk", "00aaa414e6bb8fc2b25624e3ae8416cbb24dc45e3a58229494685d1f012427f2be1d1afd7fb0c38f3e945068a36266454212a578145d42226e66a1b8eafc408e" },
                { "km", "c24fa2d211601cfaca4e48c5176d2c9aa406ce3db1e23809b3e65569a341b105d4cab97d960136fae96280500c611a364d648c70bbc2de6a4c9b666c8616cabe" },
                { "kn", "4797df0e60f6affc09956b9cf524643e6e495f8f7c8af8769aadccca0ddae98bf5a4b618872472a17747d4038734aef6cd92f4e4c441db63309deb35f794d05e" },
                { "ko", "530e1b14807b43f7a1714a0294b34f4c4fed3c7292d2ae748d3579c635bf0ab02151f6b03ef55f53061ba0c774e744dd632bb39e7f3636309b5f079960e3b163" },
                { "lij", "cd4d72158b34d989846b7cd1c81319148f632b32227b0df71c8e1eeab942ea1b99cb1310f1f0a0f71bfcbd9df5982f97b6006c352d60c6bebc36768f4eea9a9a" },
                { "lt", "480b3b53418cfe56b100673a47bf131d6178143efe0a45c95a3c056c648e4f715fd1c21b43d959af3970dd70fcd1d1e7cadd9e53092c04eb7695a8e61947f4de" },
                { "lv", "9764c4be4169ac3cd24bac36a7fecb072724c4ecb8afd73d3612ed9f3d6ec425c30cf913baa44b0d1d07fe721fc519122aa55cdb74128ca6f4a3bc258c04c221" },
                { "mk", "b74a27e0a8a0df0437d73d647b4da64f1c14400d592027f8c32f682c7276b58ac2620e59ba26a65d7956a6226a7cf32365d1a0efb395267a81336a0239aa6322" },
                { "mr", "0d12044d5bbd4acd895ebd525bf6e379d71edc26da8b2211f6d81fb726ab0be2e41e3926604236576da8fc178645086fccb8f24d9ef708ecd669ecde948451e1" },
                { "ms", "f57eb54eafe9de94c7618f496d0af98ce98481086be898fd6f35f6363258191d2917f088dad184653a9aa233d93554e19e41dec43a2df87555aa491f25759774" },
                { "my", "e5cb3491974de2d1832b43508088697623f46a04c10c426590efbd4af63f23832a1c85b2f668d46aac174aeb8270f661a17c4b354142feb353e5020424c0926c" },
                { "nb-NO", "6c51e09ac99b22108b03d712446259aa9cac3f49f62f8c3f3bc3cd9babec309b195fac320eb8878ca397e81edf72c06b7dcbaae3095256dadc1f78a818899c13" },
                { "ne-NP", "7c7da493db19eda121d58d0a1e35cf7f5decd403c7b650a5c22e99c52debfdb563269f3d1f1563a795f1b581c3153e1abbfe243bbaec4e408f5bcbf65a0a38da" },
                { "nl", "ed6277f7b26af2e1193bf944a0a3885780c0544b833d92fa04fcbc817466063b7c0dcd9c0864fb5e6807211ef5e834e926e74325ffc39bd0747db9d8f2b8464f" },
                { "nn-NO", "7c78cf91f82919956c881a116d0367534d4af06d808dfbf95a45968b6d4929493a149cdf4e1a113de08daf6a8303b29f638ce519ebed87b84b5256f27b358f7b" },
                { "oc", "fc67359f3e8de491d36f21c33004fca949951d6f51be6320cdea2a862ca4f0a47a2e65885fab6257cedaffef489d85bfe81898d97d876aefd329510a91846645" },
                { "pa-IN", "4b3c769f639232e4b761d9d07ebf3abf6c6b2570beb68aa9a529e54dd39f69aad03344dca141594f54d36fb0fe41526653cc83715d0c4d8441a4db6f87cff380" },
                { "pl", "beb18a703459fa819438bcc5a40f975069cf58cdb27a90ac7110b281dc3f5b9a42718946824fc53804936d5bcd32f88d23dda6453454591e5f8ab88c47486744" },
                { "pt-BR", "930835eef2682a6f41646d0e7a7994f1056746b86f3ea993e6bdac93a122dc8f1d9e4e4ef3e66b61f42cd9bb33ed3ba2ce99e9840823b6611ca5de560bd904cf" },
                { "pt-PT", "019d133b2ebcb517cf86456e8604e3484105b3330b27635774a376617235f801b85d435c9d15b3db65d9a85136d0868250c2fb2e555a3604b409b3e62e694de4" },
                { "rm", "b2c889cc60df3493695e83941dd8f8d40637d000b26014dd57c89a98c9c0237c3e487cbc7f61431f17324ec63ec15089bdb03d6d29602f056e1b59f31a1ce072" },
                { "ro", "860e882a33a18d7a57ba48f639959d91231c9389fe3587dbebac18eb585723b9be02562a21e466a6c703464d51bc1bc32e7d78f9fac876dc0fac198ae50815aa" },
                { "ru", "f710568c3891331b7710fcaffd05832665276195108fad7f73429e0979ac9269a4460076022a86890a4e61e1051f0d6a934a0dd844c8d11f4916e87d21d3fe74" },
                { "sat", "719824a6fea41839b516f84ba4c09764ef102b903822749897f9ec2bea1042d2406ac5aa8e4f35a8eff15fd1201d0dbe8b3c3fdff132c2b371b8de14553dc9db" },
                { "sc", "24dd330cde2eb8e58054a6a398a23e9b365cdafb5d36aecc6b1017600227f0fc96e0f228f19dd699a2b06fb8a099254204248063f7809fc739f65c94e11005d7" },
                { "sco", "9bfe8eb737754d3d100692989f05ce742a7ad487bc5c052f6f9b07382992ed58e5560e0f24278d0d9217b410b01e919352d400866510f152373efaccce776d2c" },
                { "si", "9fb7c8ed1b199e7c247372894ceb3bec567cdc127f00b8dffee0368ba4be4e4afd80a3cf4ee36297a2c0b6480e577efed6b2c397df71c549e330c46daa02cc16" },
                { "sk", "3318920a1b9e1e44e0d6b44604e96218830383189a3d62107dfd1c0a2886116fd70860632e7e2713e40cc9911805ada76b5a69b14d313e0407d7f6dce3409fe5" },
                { "skr", "85dcbd506562730c0bbfcdc25d17f77fa22884e50db1df31e0c2554cba049b9f836ae74ecce4b076ac29a6fb34b26f823f8bfb84e369e83b3cb1796cd3e277b3" },
                { "sl", "108b51cd84c5ad938af20beb6b5b8685b1512d01ff82ab9e06760feecd7e980d6656b3907d8406231c62ddf9dd4a34376ecc918c35562781a75edf7dab1e27c0" },
                { "son", "63d32908b9266a9ff504b91b7b20495605aeb57620a38627cd05325645d890ff3b404b1664a10aa3063616adf590ebbaed23b8a23a28daa46d412bcbf6de0439" },
                { "sq", "bfd2aa71f53ec8bf57524e3c443b972b6dd13f90e50f061e96a13d7c1024ee26d76ec37020adeba0f28d95666f2c32661f60ecb0215aab40e7a0023e663c30cc" },
                { "sr", "49cf827607bb0b5e391f5431a0c2dda857eec7ef2ca194f7e17b63412463c92a7b1745136ca8c5e07ad91c3fae95a8cf920403d045a06278c7f5081736977d9f" },
                { "sv-SE", "1cd157f854f332e3e9a79a4d34c258a257873fcdd547e107256457dda3d4cf0a34e5beef779e80bcb098ae521176f8aaa872629a4aefe3c497526ca0e63cfe1d" },
                { "szl", "4a278138f705ed80aab5467a7d4ebf5003688bbc88837b99781c990cd85f4e341f7d08f713d7f2d8ba8602373d2590949edd0a3940140f61751990e06c60c7c9" },
                { "ta", "a414862addc62b1593581aeeb7d01a7cca04bec94397a33cd66a57ee135f6ea1fb0334283936cef5caabf8452340dd9effd2dba6a00c62f763be6abf70cff964" },
                { "te", "973fc2168991f92ac12672a5ddea6d7b131b279a66eaea754da00c68460db6a7d6aa99845e1456dcf2a98f1c0c6a4e6290796fe72c84c5240fb6599bb1d7489d" },
                { "tg", "ae36be6af66a530174f66ea1a99a0ca1de9eeca9fc98c36d7eab1a5de5b4d7ebe237ebf4f7c94fc524447bdc4c25ea1856b273873ead95d5600419a372b1b261" },
                { "th", "975bc43abf969918611b2cb1613ea61422cb0f0408d9e1f506014e346c7bafbf8b4455c6ea03735b1edbf62d0f83aa9439b7b0a753cff585de47a7a979d30d2f" },
                { "tl", "fbd39df54cdff7283da9959f8d6750ac8e1643f664ef9f42c1bb92a9796aa114bdfffedf21d2e97e6ebad84e2b2823d6af8393efd1ad8b6b623220dbbce7633b" },
                { "tr", "e2490d36c91c565197c2c7f0f22846144191c88feceb6a57538bbc17dd66e7f169c00c103e22423b4fc5d8c8dd851bbb8b9709a397aacfe1e955745b0b26d24a" },
                { "trs", "f05bc0b49b360739c6c30a2fd0c96d1f8b03a14b88c283b6b36022c5640e34b15ec7260717c4a8c425a2c4add993845dce18d8052cbe663643dbdf51b04e26d9" },
                { "uk", "a9ea6e70f8a9a7740bfeef35c510fc8d4ac094ae1dbf6f9ae845e9c4326077a068b4b30c64364c46c66f89d1814b32be65456d2254b15985c0f8963bf7c66e53" },
                { "ur", "95b81491ddf7cccfb55777578409cc97f4667fa94fb1f8cad702464f99b40f38c733864ab0478b86126360886b2dd250a14fd5f1e8e0e9721f306a451f862ea8" },
                { "uz", "0fe70288c49fd3779994db28d3a7924db81b8f3ee67e37f58b525a3ad869720e7e202ffb85ed1d7a49680862c8930ae87c182d903308e80e313364b711471241" },
                { "vi", "e6c806f72c6aa66e2ae4ac2c36635e2f9b31a70481579dd74d6bd5b17e96b43620eb55feee0898ccb2b8b27f4432d93f672910f0568ca4adb098bd1a554fad5b" },
                { "xh", "fb4689c72990ea64f1e0cae5ada6d7211558125b254a0584b1407a4e7c624e496c7b27efe95f5b23d334ca0caa3220415462574c3c16202b2311ddfcf25f9682" },
                { "zh-CN", "c5e63537ce6e4dbf05cffd1c0c6a23f9a104fde3b8c7455e89877d9b541de7f33516f42d2d74e8db1e2b898b7d009ec57d8021c055d86212b637bf3684e07d55" },
                { "zh-TW", "8502a574be8819b640ca7e0377aa737fe90a270b1847b9074fe0a2296039f365cab25c426692d745fc30047a0a5283eeaf4bdace40652b9351fd2946bef0279d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.7.1esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "278a3df3d80dda85d3f8cc4ceadbb959797453435687f94b0cf44dea4fe0455d1970e54f6b7439e56bbccc0bc290dc3b11f5b0d03ef3fe636f49b4a3eeb9d7e7" },
                { "af", "31311da9f83704c3a92db3d7cb8b0cc591981e0430db131489090795d22d45971a0b48c8c635bbca8b1a49b28b09d3fdb3da75106a8d2250d65139309a314f1e" },
                { "an", "70dfdbd8217c22c5db4bd523c4b23691944c50854177f23f143c89039d63b2ae15448efa653473b241eed745bbab7b7fb494fbb4594a50afcf8764f1c7436d8f" },
                { "ar", "06cc74972ebc5918717d6300cb626cac29f08a739746aa28b28cafde71e83e2e3f5d6be8f2504e45ccc0b235bae28f26f36cd7edeb7fd02bba24dc6b7d2dfad8" },
                { "ast", "3b4407ade17933266a3d04085c4721b1d306193c2c878f8b4d309c54a9128410049a79a1e518766131c2e6bd828966dfdfb5168464c374f645da5255174b29e4" },
                { "az", "27d796352ec146875dddbf9d3ecaf5266f672249940cf5475d9e5276b686b6adc6cce86bcc6bb3b450fddbe3b1cc8e95385a23fe57711e307ddec5be3e75c382" },
                { "be", "07bc6136b6abe1fa9048079408022a5e23a2775d379a9304a6afba9096d75875fc2295042c9e4407a7c5a5abd2de55c03e59448fdb5c793d8608781f8015477f" },
                { "bg", "3ce2c658f060008ece8c000e1871efbdbb71a302df3ec7277f0ce86143c890b2ab10eff90f02055206b269445484ccfa3d4cf4075162bf57389f08e05259fa19" },
                { "bn", "14d9b519a7906eb6fe44edf73af5e0f0dade10a53d917ac0f1b93247a46445762d7ed0057c36f1a5da8c1a458812868ef583e872ea9eb6109801571b0024982e" },
                { "br", "c5fa4464f29bfb7a3138e7109efd364df1337589037adeb955d2a54fb4e3d859d42024d2050b66332de753431c617a33d2eb644f9ec574879f17980d8d089719" },
                { "bs", "d25fa2981ac2b527ca55896899533977bc8c04e94a913857759894d459ffc140e931809bb42aa1bd368f99c0dc05ea39a36cbd5a29643f624e01664d987b886c" },
                { "ca", "1566fb852f45580b49edc4ae80595f1666a3529c7a6a497713a8803c10a45b81d28c1866e77df61758283e27cd36aed24206432454d14102ecdab696bf0059ce" },
                { "cak", "01875203415c01230b20e6fb9b6953d71ba737d31846b41ef563ecda4838fe6381370265a331f65cbf80506ed9f3af9cc48bcd3559ce42dca6aaa90c4aa9b35a" },
                { "cs", "aa61f7f4160371f8dba61c6ac9de366cc4af4dffeda7bbc121a00401278514df00337a375da4116d64b593fa6653f0eed2d102d1d42edbfd516b7fc75ae1fa72" },
                { "cy", "507547a8f74921cd42f6e53c62018509b1bde81ba6a3cbc63019670d03ef5656333ac44bdc0b16de2930f6efb037ecd8a14b2529a39abf45926af3f1154785ff" },
                { "da", "284c8110dd95c42dfde604eebae2d34c33b87b698542397f97d32ce9b03b0cf0ca7a86e5a07699f219aed9257b5dc874fc350453f454944b349536c04a74495a" },
                { "de", "bec040480057c9db3c07aa90766bb8f9c93f970ba9d77cb93591caec66adf42ad4f436e1e1a37e3c56c338cf23ee58a9ba11f08c15a193aeb30d649f15b8409b" },
                { "dsb", "f22bd428a126eff8710ae50c3ef6729c0882b84db3d0a2da88b71262d788e3187da0817f85a97fa10f8f372b4c5efc558857c86cdd948904872225e6d54375f8" },
                { "el", "a3d773b4ed80a4094d0c1628aef8d39b649c09c473f052917642cca94ad34e4ba60cc944fdef1b103daa3cce91863e25975add4cce3313d0a8fc7883facf0eef" },
                { "en-CA", "6106ec01ef46b2e39fe89a94faf0e13de7cb80df18e3009f0a88590b0786abebf75194b88acb73a3c82b6d18f60656b67026cbb7445effb08d8004fc8673c045" },
                { "en-GB", "a01629009059e245205d7d22c563364b0a19829294402c951fbe158d01cb132d8b184ad3a01d094ed04582226dd343a3db6ef1ad7c12ab6d3f911ea24b7d9d75" },
                { "en-US", "2c668eacbeb6c67c2d24bbbb6592edf5f33bae8a3fed48071fcd512e79c418d866a3a6cabf9b6aa48c114b446100c37c5aa04b1d772511997a2b183c1c6180f2" },
                { "eo", "a08766c2ab4f2e925d757abe2f84ab79359ec0916d28ba30db1b1a86ce6516b7b865650074f3d02974dca0e846651032a91e7b4235e520ba401a49b800ef7b17" },
                { "es-AR", "2a59e5c40ae9930ca2d24b9fb5360a0c561930b7a4a255addd4cd2cca334434dd96ad97a03b4b7fda7bc84e9a29d67e510c68a51b22728e8f5c28d8236fd4213" },
                { "es-CL", "620ddda7b72ddd872413261759de89ee58faddafa3c4cb94ef7e64bc06e7201579b99deccfe0daf5c9f4ce067ab5ff693c3e8b7e1c1c0fe43eb2fa9fdcae6627" },
                { "es-ES", "e71fbb2143df29828ad398932312617d9685efe8881f564a07a38678633b2b8344e59254bb0fc8029d7bded02127c721e41c1f3673c2cb0b38342c7014e6b1ff" },
                { "es-MX", "34a764de4a847366044530c74b13424b1d5965591bc8abd1fe29c2bb857af9ad108ecb4b0f73101bf1a037005e19b3546061447c773824b4facb8ecc3ab4afae" },
                { "et", "1a6f9e0e69acb45584f53960e18548cf9fd6711c43f04e478b9ad11007908b8866af18bea294b6608dc8191209154b4e52ffb88273bd2c0fa5b1eabfea315bed" },
                { "eu", "1639055897f42d6653928bc311d56e59721034da2fc035a8fb07aecbe7759833a09080971bc8b17f415faa1592c901b99e7efd0aec7b7c9fae47058fad7a43b0" },
                { "fa", "6ff2f0c2079d814ee6430cd36039bd51deec1f18ef9c1b3e246d10199652736acaa6e8d5c8589227634f3d38372a35e5917e19d264f53e17808c6579b3da21d8" },
                { "ff", "64f966cc0cea97d2b3c57f7826506a40c4fa8ae9fc1fa845794bb04328ee9938b0215bb511651cbaafdef4b859cfe36675d371f3c66495f9bb16a11ac26281bb" },
                { "fi", "49e24bc99a7fe4a239d5a8aadd204722e7121cc8b1a05475cdf941e2d81c7fd829046973a490bee93210284797ebee3c2b017d3c4822db1bbf93d927f4784211" },
                { "fr", "8a4b139e7cac1efc5ba1137b0ff24eef4f09b5e0661ab15247f9ae695d035beb9c95330af0f31e8d18eb53c779ff6f7eedde6d016e34f556eea15f8581b5549f" },
                { "fur", "9485b11322d4da977ecd486a30d9796e1a6b89fb7f32a4526d9825cf5c250eb0aa427e50dbb2c88c24ee597596475ca1ddfdb3979aefd128ace4793514e955ee" },
                { "fy-NL", "db87506db40f9a92d1fa6962f17c7dff629ba71be1d00eac0e7b8e84670d9628e878a896fcf2c971aa0cd555821cc85316182ae41b76383ad2821062d288c548" },
                { "ga-IE", "6872f4bca0bb936c0769d549d593aa34cacdce968990d6ab2c61e049a1aab943061d98335ce384d44ac461eb011bb77738cc0c95104d46223f96d4b17e4ec896" },
                { "gd", "f294b1db3356f8d29eb58c31530ffeee83fe93319b6f5286a0db384a8569835b3ea857e9990de82684fd377b07ffc453785df0506c919f602e0c44e317906e42" },
                { "gl", "7354c1ef94f189da5d779c8e6dcb7d414d6db7137e3f47abaf62f972cd6b91e8f4999d86610c3574f435bbdbf37862c4f0741732c9d4f24a02c5546976e0c399" },
                { "gn", "cb1bad974bb8029b27a1a258020a8641e26b8ef82dfa116185ef3e5a39a825ce5982be2186830bc15eed873d49799c61c2280b794745e124639bd7334957fdb4" },
                { "gu-IN", "67e08aee506747ccbdd30710c35ae71b652f33d0311afc834dbf338f389a09cfdf4a4b7347217c7f52787b53abcfe062fd0bed63e0e50058d46a8039d828b2db" },
                { "he", "eb1dc2e1b2a521017a9494024af5c38ad8ac5540bdf2dfd636ca40793f42745a7c49283b301baf9a07c8b0a2d2417ccb3e5ea62ba6f54b8e3e36401713fe2a9f" },
                { "hi-IN", "96e133c8f5d0b88851ffb0bedf67902135c8cc9d5f87b42c28931a71d7997ce67f6a20174496fb117a80b3fdf9b616f98da101bf46f39653402163aa3e46a342" },
                { "hr", "31f3211cc0f6ac5e785bbdf0ce89d42deac54337d7bde3d3eb6ea7aa2c2694b412bd493c10dc3397840d17d9866c896f167f2424dce036ff25bd1c20cfd0f4f8" },
                { "hsb", "954bdf04f6d50b2a6d4b352ed5f35d61653b14c465d13370b0e04c8335fed2661b92006d6b09856175db156fa247e3ec5f87e89a96daabd7f0bce24dbd89c63a" },
                { "hu", "3d06b1abd818dc93b7b47a8cb0108a0e20b0ad49c1ed3a4ac25bef1042d664a39c8159ab4a1abb92205fe45fb0bf069eea75ab1a0deccdfdc9da7d30abf03413" },
                { "hy-AM", "f61be66405abc1d9e45c90601d1ddf74a23fbcc288b752fd4ce99230274a494baa2109ccad2accb162d732e1d2392f919e27e2121d545feaf4fb63b860a23708" },
                { "ia", "312b8b93c783ee0c0691d2878a38d589f66749985b3ca284cbf1b4e4d6b619847c218b42cdaae40b729f8cf4e29cbfd6d2ba67019e4c1ddc9c440c2ab80bb219" },
                { "id", "a77dcbad623436268be6868da7e0bb1a072c62ef2cb1025e825c2e8217df401c043fc342411c77730101d4b46c685d360176b5aa4fad83741c03c580c29e8283" },
                { "is", "7fe4505968debc367d9418492d51d3ad67fb76e913bb40f594bc817de77ece40cdd29c873654230e6d70f18ddd8d44aaefb9fadeb32aa4726a8d3c1165893d85" },
                { "it", "adb5c63c077d8c8e604f0e785c00c7760660a4797a66cca0f0f90eceddff76d5be2911e1fc0f7ef6d862876a7f3e83462c4e7295d95cf57bab0a9e65571a8c4a" },
                { "ja", "7b316d70d43404f89ee0e408aec5fcabbdc962a9f205e1950f6550f99def1034d3352fb130fc109a4413dc0d838e72d89dbd053b840fa90f831c39b10b258afd" },
                { "ka", "77272e3043761f7d64269ff1f007c3762d21030de1122ea3ec051cc8ec98a1f8f20d296fc41a415a3c37a50e3303b499d49ad8d11c90a765c7e45cf8e50797ff" },
                { "kab", "395fc87bee156288ff77cb5715875e994f051857ab6d448665ac4fb21acd17c5094321ca2922203ff2eb41d3eebe3eaced57d14f0d5bde2d1e1645724c99b823" },
                { "kk", "29bc3d1f62e5655738501c31f2aee32622f2dc39d67f6fd9a12f2f63b00528b99c30bb71757d2901edb1264dbc2455a1c6765275ef4e1265a8c214e3d6cf64c9" },
                { "km", "0e1242dfab4d853e396639c9bbcc69bcdddaf80a78e2620819bb9e5616d46c8ec168308ed2bf327dc434923e6a1fc7079ab84df5c8cc7404397417b4be0304b8" },
                { "kn", "3ca8489cc351ae6fb72d6f05fa6fa2325292a4c0d140c0880f585b829133378b8e25899157a826f672ecaad8b98c36919090396db7e70334d3d43058d3df7626" },
                { "ko", "b1fe0aae42e82ed2e9c5b1820393c4a50d49ef5bd1d16e2328d4a9820f087c86689c830fe9d4d5ecbd13973029f5dd6eefd9da1a89197305d2f2ec81ff5aa58a" },
                { "lij", "0996f4334f3dd1b77265c3a7f529806560a7acdf7a1c1715d69b86618bf4ff11bd48bc4fbc2afc36827704025e826ebe9a00af364bbea1306fbfa33256336690" },
                { "lt", "a4f771bc5854e4ed758502c15e231426a3be5abcdb8de7993f5c73dc4f26bff5581bebeb36980addf28b3d55f44969bf3d6f30869fea99d7284e599117df8e9d" },
                { "lv", "893f305f3638a4f56e528457c4ca1bfb99611ca7421446c1ec6474b71ac5a0e8b3556f496a85148d6c155ad6a160da2f2df7ee308ecace04973c6135d467e523" },
                { "mk", "6a04c290436e49b1c83a803def7a3616d80ae4d6431529ff493609c7afde2cead15220067ae5a84159db874380a077f8e906c63cd50eec6dd8a7b26a14191d76" },
                { "mr", "8190a27e9a0850c5afa7d8aa3e946aa6517c49c6248f26fe64fd6fad3790576630b591041473a14c1d89cfb691e844a03efef4af9c746bb009ad2a92676f64e7" },
                { "ms", "00d0fa2842b91b8fd7bc58fd8d24c5eb0424bf67968300e265caaeaf10835df5e1f7af0e1c76391c091f48fbfb31cfa51251687e4e8f0f8edb52acc32acbb5c4" },
                { "my", "459a9c001d3b3bb7ffcb072fc73a8f6097176749881d9df950bd2f1f9c92c50dea271e691efe0573bfb2a5ad245fd0c11ce32b4640bf7eda1d5ab1e1588edd9f" },
                { "nb-NO", "1dac184fbc9c10f63cf694e0b9bc6be73784b2c98aa4328b0e87b7b7bf598fd8c82b3ad151bf53be41338797068eed2eb389c93830e38522582c99e53d390c2e" },
                { "ne-NP", "9b7f50df0e068c154cb99c72d92e9b152bdc30ae43dfa49a33c0eecb0d4df6bfee39cf3bfb572468fd993ed0856bfc60e59b1c58dd6aa700fc5835d1f98dabb1" },
                { "nl", "0c930f0381a87067624b69ac159322982f8f1dd31334572a54dbd9369fa66840bb26f5257fb32e9fabddf2550c8ff41c6d445ce1e9c64f9a6b8c547e7a3126c3" },
                { "nn-NO", "b853a3b00c728b694c4e06028974c747722db599b51381f22d9466bcaf48f31ec03adc2f5850230234939385081673dea9a4a43712b02985673a21ced6fcbb26" },
                { "oc", "f1dafa0f83df426122ada23fdf286af1eff93807fd16505226375ea2532e9365cc3f3e4ab10943d163c39974575d365eb8569df474a8b8361669684f1c06637a" },
                { "pa-IN", "c36e3c88301a628c80214ea5f4b4c540e112fd953defe14d8d0831ee4d28e1a365c51742899ad6cf036eb3e1c4c38a592e409fa7273efe6fb55a5c1581d54664" },
                { "pl", "5a945eb54ca4c23dfc1fd63c60f5b60f4e8041b117da3e88cf062469856b626d032d0cbd0bc0d095d85739ec09cee5c46d9e1e09214b9a492b5eea6c8bff7f8b" },
                { "pt-BR", "3e596e724db72dc45771f5a7e6aa20b7507f2915a8de6ccf1c201f382a3471ec057d67830c72f317a75f05df7991ff385cf0dee1d54e990e1b0740dcd9769b37" },
                { "pt-PT", "9fa08492e0088904016bd3bacfdea2c975065160089465959354702b0e81be4a782b34523296bed96d1aef68dc44b09851fcc72373c5242a46caf8cc89009ef7" },
                { "rm", "7963ead44c2aca8f26e2cc2b9ef56c6fdd11793b30cd1420a0a2ae66f7f22faa90be87478aa9edcb3139977dd09d42d9957d17f24376fb8e56e0d2d9d758f731" },
                { "ro", "4260ec25766962b14bc4ca89cf7380ea58ad8863267e2dbbc64788430898b7b71cf4d089e372862172cdc6f7cbf708afeb83ed6cc486e93465c1b0cc1ed53415" },
                { "ru", "a2509999ec905d14568832689b3ea97796b3fc785a1d082e7e359d949fb3ad9b6858eaaef1e76054c568114ac0a11e5ecd6f09d7c8a0d89b3f62b4f5ddb6bdea" },
                { "sat", "7eca10b3db9a1f06744af9bbbaf1f9dc06aefd62ab94c372d909745a8e9b2ed1e201569e420e87b977f8ac0ec3037f210fd5c5c5b6cc22c375b90f723daf0596" },
                { "sc", "b141eb2a8705a5c923ed0b51a7ec2aa47eb3b320fae0b7fb786b4b23bf4aecf5a6c3d399d80af090e0ae0a1b05cab29221a6adee53b9b8e287c770e796e5e98e" },
                { "sco", "e43f933cd7ac723c8c1725ec2c1411b76d7e3ec9264abd7343d1e1cfe0abc7eff6e7dff532e7ee22fa9f48e366133e07a0d1bda719f6c84534f731a2c0f4a217" },
                { "si", "fe17f604555076dcdf044fed99354df73558eb1cf02ff34a8488090ce0bb4334d6f953d3a4f21448e0d12293f46b09948d65aec752efe0c7f361f1761169e4d5" },
                { "sk", "9e3c9b8f5f1c39ad510592a8fa82665d4e8a15e8ebddc155cc481aefa369e9f584a0bba520f5bcc5dad0721b89d5e8735ec16461be7d92f43107dc23447aa5b0" },
                { "skr", "3e3d4ec66e5b4c3026bfc7ae75938dcd8aa0822e864fb55ead05e312ae8236d8c07058ddc5757d94610db7aa11efcbe1dac487704d8b1c20086ab095a9b42e82" },
                { "sl", "792694b44662aead0e8554ba6ff42e1e217befc049bf2c0207a2c9bd0ce174ca3a922684d9b1fc9261282236b5cfffb3bd019804a027b6dfc709e3159a7f1e76" },
                { "son", "b6db3f0de442b02ff4006a87f96fa2edf3ab1fd410aec84c02ae4f3ab73b641b18a9854eb91760f5fbabeffe6731f0b2dbde71119beee27fbc4af22a5787722f" },
                { "sq", "d504c7073ee3fb2c3d35b86665f8902c36564f62795e48ed4c3d6a3162c55361a4dc07e0e98cfc9a483f64faa09f1b3726a670fa75fb3ba5b69a869b2150ed19" },
                { "sr", "bf468dbce1cc5b3f10852bcd1f103e8e53d38a03b7b4249aa66f704ae964533add1bf57d203ca510cf2ad343bece5c353fa218362165d565c31f9d9bd9db23d4" },
                { "sv-SE", "aee754f8365ecbc7c5184175585cac09b48adb8d9c1b427a064e82a0f75bb80f2b1de447a4b2f1a0348cba84cdd2eb41f311b3ffdba25f87cfe87dd142a03c2b" },
                { "szl", "8e4c9877897eb1f192d9e5dff017509bac23bd0e7f6d28e91259ab4d49da03a71e229b72eb5dbaae7cc5026865118fb372ab52b4f10b5876d4ecd4389f6b4d13" },
                { "ta", "01746d3f1229ab622485930953ca947eb7f81c041e53daf290d81a7f2673f098dfc2421079784d162f1ddcaf45becd5e22845dcd67b8641251e08f80b7a1b237" },
                { "te", "10e7d54837be4ac893b9b8162ec36184c799c0cbd0af72e55a51dc21b49e8e5094adfabef56a93141834a39067abee7c045cf3314d921e5253e6266257d01311" },
                { "tg", "93a2551e74a80f8c54948782c86b09e14a72d03e50d4d325e132ab8beda584e1100caa846fd547542d958cc908e4193585c78c5ea089ea6e6e972362db5d9f96" },
                { "th", "51d38d6c65134fa05b5e20240334ab07552955d3ab51dd62ab77e5dba506bbe58599e2474faab13643628fa9c62cd15bf7a37b8f31fa91bc1a6f70761e1471af" },
                { "tl", "05e42ec91793d111d3b44342231abd517e9e9bd55c38f3253e2020ac543b423f2bbe5015f46271ad4758b41c9659e6d02a0c9d3096f2e6f796f0fdb51fd749b5" },
                { "tr", "8c6fc800b31386cbbf9023ac66ed2f66e722c11033a460a5cb302120299a6f44ad9fe826bf8e81ca8a1c7f04f211aabb8f3f2c516988c3c8f635130674bac955" },
                { "trs", "fe1b0d1e547cbfb1d57bf5c7784c4e5ced9f5e6648f17fa24d007e15ae52931c8eef51425a77772b7beb6c2041cc44870b459f07d3592419305f004228cd97ab" },
                { "uk", "50c37218ee202485c04ef12088007b3b4651d515d0f57e8e94ecba41afa5e0a97eef3711f9b4cc63da97e3ba11a1181c37d427dbbee9b53be15ecd3cea96887b" },
                { "ur", "77a380db5f3e2c17f622679eee433e54fe674425d3b468fb2a375a4d49cc9c96d2c19b29bf40ece8f586ddca74ba01b770bc2d0d6bc0d72854c49866c6fb5611" },
                { "uz", "1bda78d352474cd6777a7570590964dc2a8ee2dd0bfff93569c86f1fbb96a1da1c95a42ecb76e7534f6bada840ea12ec60cde74262f83fb9f7918749ab54805d" },
                { "vi", "1524a1b206c7462700666341fe9de13fb87371b79fcd5e6058bc9e5b06e3be114f1de4d0df8dda7e066c168136ef66a6c8c4ecaabb780e6f648deca075a2dfcb" },
                { "xh", "adbe587fe7520dab9cb5a74ef4112920070c12cc4c5f71237de17a19db91ac40a08d065dee9f9a9a7b62919e4787a53231e8bdf91edde58116eabfd5f23739a0" },
                { "zh-CN", "38a4c9f9c4364dc47aca355b0e92a0a44fe7c5433deb022caa7dce43b65b260629ce1bcc6fb1ab692010703c9327a2f7cdb3c799562d5de7e72a373866583b96" },
                { "zh-TW", "ea11469b78e070f7bd1b744370ff836b1391ad3493b4350193477b779c274b448a50bbe5d6dc91979847b35f3d7475b036f0ffe757ac06cfd8a2b03e251727d5" }
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
