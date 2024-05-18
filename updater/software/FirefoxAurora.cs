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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "127.0b3";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/127.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "293f19760f5f3f0637fa3a92649de607f83e4cdd69d6a8451b388c82676027ab06b30ae81c8fd39358ad632b45ad6813d5f7d7aadb8fde55c7bdddf481dbbb70" },
                { "af", "1e21746d7a6ef7587354f519efed28dac4823014c67033c9a0826043947edbed5f4eec93d035b56d116d0a51f3763f43d874ab2d948e0fcf56fddeb71e2fdbae" },
                { "an", "ba3f234376456fa585b855534ceee40056de8399c3db2ba5f9e2c7a986389d3499e2ac0c0fe6117959a3ec9f619bc7f9aa4f567882fbf120db84383eb9da8bcf" },
                { "ar", "9ceb20a5ab61f1a902ecfac4fe862f7e5fb8ae84996ec6a2abeb59cc20520ffe82a9c30135d8760903eb157bd9888f11f8fcb9b76d090af19ed681cfe40fa38f" },
                { "ast", "c43fe6d2a368bf2b6ef4f4e02634691660fb1eb7349e9fa29cf650e68b6979c2000d962e6687426b32bd84430043876ad5282c2df8c8e443b4e147a9bedd43c5" },
                { "az", "90875fa5b6bc5e940690a3ca8f06faa42e994c5ee46ef19ba9a677bfce612e9fcaf75647f119fefb9a6b001f29ba03558955fce2b24661c79c8b75e9153f5d5e" },
                { "be", "081f4c7ecb36363d75841af3d1032f15b6ef7ed6f367ada5da0a371f39689c30119cef50df66ae5d5e4b227b4620e783f11d673e090011e54a79817782231e40" },
                { "bg", "eb358cc6e6116de0685b1b239f8755bf011d280a820a8a0c37e7d4fa6a4ee8edbd82f510a29eaeb5ceab108b39b35a1aa582135c88256fad413c987606f69fcd" },
                { "bn", "4e7d0dfcab7e2c4db19ba2091ed056aae5c45af3023d9c46d7fbf78c2deb43abcbb4247cf49a222f7982a97f435b72f1c6c6c15d2f8b9a2b16e973c5bf912f5d" },
                { "br", "8906e5b78c663ed5d66d1ddd2ef81b07007d1c72e1e3d317a8c3c72b3bb0f0c5249924a02c5c6efc3b9ec82a3ca6ed5dea076de86e8f23777cc55d57d33f8668" },
                { "bs", "aa90d446486ccbb78bf5d6dec21a86255c4278224bd57a5c06daba160def1f61b5773fb174b84e9b37f7b27671840652983e6d1b3c3bc566e89e5effdc21cc69" },
                { "ca", "5dc33bdb73cf203df2d28baf26a9375ac80d1344cf15771e38b82e00abccde6ef29762c2fa0c9b86cbae7ac66f31419c1b4254b1c157dc66cc49b9ea90b1ffd2" },
                { "cak", "33240b955f585d9aa175657d8b14225472542a3fd7053b37320c6074c9d7aa138a01c797275e1da3fa1c3628228625b98998c0dad5ee61d5b3e1a40d87c2c911" },
                { "cs", "269cf6a4a6ecc6720ab283459ae0771786a6b0c43c2a55134e13c1827ec711331074395af525299b20785a27262be819a63c5e61f4ad542f9846170af68fadbf" },
                { "cy", "459e7a8efd2be8120f79b8d3c3b917f3333aade3e25fb4086cb15d983338e2c327a6efbcdf4741c06a0d7b8b3ccb98c3b3ead0df604f7ee33a349e741c0c94b3" },
                { "da", "2db218a01b5259445e8b7fa4ffd3a81da65cb8bb37662df381d9ce49e758f25cf0e814f4b09d14371b34cfea2e10c264585d28358a6b159c48b3e677ca5fc6ee" },
                { "de", "577225d454f0b60f4244114e396c9efe66d8608ab661e3e9344c7698f00f7ec480b44d70650bd908bbf2ca9ffe88f0a3d44d4c1a4658d542fd01c89bc260b721" },
                { "dsb", "b98c166003ee2b1faee2bc2d528494d3f8b6ced01deb2458f98ec203edeabe5f9359d47b07eca261846ef7142c7a0f3288d866f28c18d40018e55ac2b2052d92" },
                { "el", "a9abf3ca324b56eed314b5c51059b62298c47ace0ac1437858dc6e25cc27253619cd303eff655d6851a3a52b3899d5a0fd016c2630d2178b1b87833cd79c13d8" },
                { "en-CA", "60068f433a47d554818377a72dfb07c51ad1eef3f6a33e1b9c5c69f44cf2a971c1bb28327cb91b3023c7c931dbef984f4cbd16540258d7dfe955d68e59c38bf0" },
                { "en-GB", "c04e67806ac38d37abeda56c9b1299d29baa744b256bb4c41a17ee70b22af805cb52033baeb14bf32c23c6dd117699e63eb43eed82181f4c760cc8f8bdf4ef90" },
                { "en-US", "bb1f39b3ac09ce371568c450733a95d321060e6212203ea7adb9d075e6e2fbfd247461d19809677e9c893f388a4a3ad7ca155b01e2699059a4a55d05ed6fbba2" },
                { "eo", "2c6d1c4c8c26dfce6e294a1a6ca6513cce58e94aca2d9e5e1f643dd262418b62f3bda3f72c47c1ab7e227f4d3d0aca1ee51676bb53458e725d61e705ba6c2009" },
                { "es-AR", "6468a79b5ba0caccb5ca2188acc6d49ec10e282e4d242721436a184b573e2d78f28f87f73af14baa569d48f07116a080b878c6d73f83144ebaf4f804deef5c38" },
                { "es-CL", "d337cdee68a51d2a793e2b2cc0eab9aaddefb3782c5d7defa4e1e93d2b08003108deda1c074753085ff843db50108bbf6a023fff71ddca14f33c717226f79fee" },
                { "es-ES", "26a1993fae3d3941e59919ddabb6a9745decb59ae834b74d0573499af89307333324a07fddcee9677a7f5a96d177b5445c3c5bb77503536e1d59e9486dd2422e" },
                { "es-MX", "d4aefb118e5709a13d2f82cb2622aecd1bdc3bf8a759d5e977a5658a36ae229275779da316f27c7d86b6fb429e141be730b1aeabbd5a51ee1075adffdd37a7f9" },
                { "et", "ea9720ae843e24cb405b0ab51027f094aad95da210c909bfd3d5fa35154bbdeffa663b9cb7d1215b5c83cd664099d09307de1b311dbc31dc0023ea45b38d9465" },
                { "eu", "03da64f63f91dcd39f300758f183714c574d7ebc7634198ea6140bbdaf9dcd364c733d9c90047c672d92352c23ec4a7d65aecaf4d41fb820f9405d7439b39cbb" },
                { "fa", "7d761c0a951fe90e3fe3ca6d1a4523285b0a14b4e64ce0f6b9b02865cb68c30f1534a897c2256279c4f4888be342da8ca62257bb07cc98886a34222a1cc4e2de" },
                { "ff", "4a4d64b9af7ef3154bca06f281d976d6d7c4d1c53efb4ae1b6e91f44c64ef42018c7f1bee2ff937ae29f95602f114ddf7a0e266859cd9ac26d91941b4dc8185c" },
                { "fi", "a4c414a685c1b1f51806c3c2e3c13819472c0d11113679dcd8cdb9cf1495ad8918d52a931758ad62ccb4e6fc47c4ace2808612ec414aac418a9538572faae7fc" },
                { "fr", "87a8ee6d33b443c65551f37e1cc582bd324c12f16c269503c3d0aff0b78f7c561de8131494bcdbf9a6f585aedffb2a3da3b9ff87c296f1268e86e4385c89a411" },
                { "fur", "0518aad77db0f761704cafc94593aeeaf340141602629f43778b0d861233c36115e56b877a769122d5958765b7569693c7a204ac65af217fa8d3b3a61cf5cb07" },
                { "fy-NL", "ae9c508e1fadd88596ed8327e86ccf7c465debac9f7327fa99f8eed9265e39c98e160d1e9998446a5e452ef05d92ea5f8c542538300c576c1d8c119dc2ab4e8f" },
                { "ga-IE", "2bbb7994a38df9fac740079e2df56af55caa23a500dcf74dad4a47dee5d415e802405cf8bcc11699bbbf168bc4353a7964e6f51f695821904982cc389daf53b8" },
                { "gd", "1c056e91766c4a0922817199bf3f4ece706feb88e310f97c578728850e20ac2cd6df9a748c1c946e5c09b2fb67970a60640f25a00c7a964d6b5a2e437ca0da9c" },
                { "gl", "c117737a17e3429a20748011dfc56fa7c106bd23f5ba519569aebcc707e229c30b8528b23c899c0fee9be7dcb09fc7456270ac706be1e9d2ac499962483f4be3" },
                { "gn", "23a9cd9202c58ed5c55143c8272975699f1774f53fe4479d5b8e9a67783a7c24149633539d8261434d954d323c162fecce40e8856f722e95491ee13e482ded74" },
                { "gu-IN", "0b275edcbe97e200965583852b7d25f3dcfcdd86e18520ba6e81f19eaae6a2eeaf6cb69481b8910c3bcbe9ead91f792d1bdedefc1c3dfb58cd03aa12ddbb6b18" },
                { "he", "3e325035632d06408fe10076a925313a5f3b1a32ee6da4b975997b7f5f7ee8fb482761a043920481335d8539e93d2b60712baca581010f1bba831d5ee278a2a0" },
                { "hi-IN", "24551f182bfe628b6b02552e497ba331f3b29b208df3fd1a0cf74d49ef39ae08ac4942a3c357af32e150a9a3a0b4aadee98f238214a0ba416a515dcb18e35bbb" },
                { "hr", "973b35b415916e2e21f9e42a89f3fcc264ec30f2d2b173a16775b6f5db2241f6769bd86d61dd6451ae51e0c2cf7d767ba304ef2724baf945189adf172fc2cda3" },
                { "hsb", "41fa4baaefdfbb229ddc9f92dd4b6cab1b0a6d56349c450017227280f67fb643a40b6ffa888264f5b3c7cc2d79d6253622e3c98d1c3212950304b629bac592d9" },
                { "hu", "109a6f8a21437f4006d661f3cd6ed7ae74c374b4949e5e0859aba499bd163c7caefff56bed404773e2b44a77e45c87302a4d54263b09a96342a97d370b8153e1" },
                { "hy-AM", "309154e9c7fb7742df46815029fe92ae02c19ac8576ee97c190823e12ced0568708d9fa6fdbb71b36864345f8baca5ec51db47597a8932ee82da929b79264825" },
                { "ia", "92ed996b154039c183e7d5beae917ff3b0a9811652c6fa183e35b47a8d68a96e06fb06ff8573238f554b645859fbd9c4a41fda79204382ef64823f57379121a2" },
                { "id", "587767ace91560202726c66e411f128ff5efb4e57891e0fcc7fb0b2e8cf27d3d146b14d7544edc916786af7fb086f4bdc12eaa9864aab0de404217ee440cc1e7" },
                { "is", "ee61c2fde39c715e44513d30286b3dc41d254fac218d865030d899de95b240e266a335a98486a373b8ed76a156fc332906eff259c396b68baf9078edc5c9d2cf" },
                { "it", "de9b918bcf5a1a24de102d30b15900f335f3a4cce94e67d5d02debe3dae62b73088fbbbd961d8259404da4f0b370ad7eefc3c1c1d33125fbe1daf7281f8d7bcc" },
                { "ja", "6205299faecb375c8bc8cd1e4b93e4814f172098fe87c7161a0511ed238bb1d8f09e98d5df54c3279845c92aae1e59d1b83e1d9cca2d8253152dd7aad9720863" },
                { "ka", "a361362980c5f8906c18524b0677937f5ada57ac7482c4e5f225c9c54e0a06664d71999446144e5edfb59299f58fe593f571f36adfdce4cc79d8d3e5bc8a5bfa" },
                { "kab", "58497adccf59948c1c523dce84678f03632d73726ccbf2426c111b5d0bd6a789e6d5631e8e2c3cbe55dda6581a84263ec95be088e00440d6966c1e30ef8dd0f2" },
                { "kk", "a3155abab40a2d91b032210356d4878c81ee9b612d093c9c4f9142a1bddc789c8d1d2507831cf0d624bcd2ef7e0d06966d7fd7cba993242e0416ab420d270652" },
                { "km", "23b03deb345e22fd8954bbc3b5fdb6fc9bfe9e22f92339978512b80537c86b776e3de3d3439ff42607997772095fd06b56d9b753d9bcc9c5bafb7d30b8af74a2" },
                { "kn", "887e7d4f46e4fa84fff09427e1822ff6120dbfda386dbb32c5db2543efb190b3318c3545a6cab32f344553df7e4c301a6f25a7e60aa16250883c139c2579f10d" },
                { "ko", "76c96ef323f68134275bef2f8e750b6ce526c90086468a4e8868caaff3c644c42c8111dc891f3d8b35b393df49544e3330fb59b590e42ef9c01b2f7f1c2bcfaa" },
                { "lij", "a6bff4eafbd807c21ccc8d0009d02d75b8695c6640ddfa6191f2fa7fa32ae8f1a1b8c408bc5faa940c8624e3986bde6908a86f4752d26ec722367308a5a57a1a" },
                { "lt", "fa248b08aed82496185b2562862eb61006401d827664c2f696e9f6e17d8980a2a8f8c9df8a1671b6265d3c38aebc36fa7940bad909a4b445b2e5f346b019c6d1" },
                { "lv", "5e37ff9e96d88fbcb721695c74cb662deec5c97cb1d6450420f127b1f0cf452f130514760da9907df6e20495f057e6e05e89747a5b7aa276c175286ddd5124cf" },
                { "mk", "764e16ba46df7d9571c909b4a3ec49bc4d57b53ed0928fe4230c66945216a8283406f4946e82623caf8e05a68c7f616dfacbd7e18fbbafec259d6cbd588f1747" },
                { "mr", "cfe65cfbe60b1259caaefeecad0fcda055c55f2ab385380a1ab7a58a56f50d44919a4b03c2dd4cfefce7085c364c82273714778c44cbd8ae672e7f866ed2790d" },
                { "ms", "949f1e7b185ff13c40d697c15f1a6153551e321b4241489d8cf79d6bc6a971ab280d4a55d019b5285ffd6e4002bc8ae5b92bbeca604d20799e00f0ae681a8738" },
                { "my", "4f07c5a8c5fee1201b8fd508a29943311e81737a6f515f268144a087b9191ebdd3ebf366da9139d34a44e02ea42a7c2b33498b479c753a1e80f345cc171ce142" },
                { "nb-NO", "133a3c9bc0e487c3a5a8c40e29b55b134919fdf966955c6960d06eabab4bd07e25e69dd4836f3582e73fb38a8e2abe5104468bc2c47edd4576de67cfb8e7850a" },
                { "ne-NP", "18ea612d25fe530940fd2addcde7687e8dd1c509670c4b46c91edee0fd01d09a2472d096a05d3e6cbd60f50c006a9e895a880879a43610b4eb136b0f481c3263" },
                { "nl", "3b8b6ba7db815c77d6b3386fcff69a5a307dbbc7e722b0301da073cd3491af449c61c8d25dbe62b904eec9469a7fcf45b242d7244f1c5e717d7c340356b3fa1f" },
                { "nn-NO", "e1f6f71755d193eba5330bdd6e10bd169ff98147ff5f290efef35f8e9b34d0d1bf1e0eac3f3b562f3233a5d4e40cfe6b79868648551678a58e2835ab27239845" },
                { "oc", "0d94a3bbc98ce3bbb4fbc1632b0f4fee20491eb1e63821814c27a21d77c684af5ac19a94b2b42886b8c811705b85bf87a8d304e5c27a1a1d6a0d65a59cee9a2d" },
                { "pa-IN", "54638c9ce141a8ab1cd4412968ca271a0a7197b9748e673beb494d087c6b394e5d15320798e417c97c81c49511c69c5d89c829cf347fc297cbee09432d9edf8e" },
                { "pl", "65b2d47d2c2129f7addb119e7cfe11c13c7068af6e3860e0b6280ee57c89702cbb02b47a9d7cccfe05821a0dfd32e4c7370bcd91bb9897f7fa4919588ea86d4c" },
                { "pt-BR", "08069f0e00f86c15b64bacdad1710eb55efcc9e16dd75f92fcb261539a28d3f8ba610f603324aca7463b1ac4096d796f8b7f7d258ef340f9fda59a9e80f07602" },
                { "pt-PT", "53ebdcb9eeb4728525d14e183d2cbfbda8fafe1a8f7c7efcab263dc772c0791de4ab8ecc8b3c775141a25e76883944128659c1fb7ddab2651e9654f73b267664" },
                { "rm", "f3b26877e3f8f25b68926c19886265710ac87aea541c63d5fe88b8d0254ccf7837fce9c5d29715dcbdb3330bbd895fa94be13c0096592b039cdbeb06bcee229b" },
                { "ro", "90d585fa32fbf60403fb957a97d517008595eb4a4a7b9568360a1213356dbfb9b27847846003303ae9191cfe6f9d30bd59516b64aca4c9db468b8a2999294e36" },
                { "ru", "e3f9c929dbe6cd4d2b568d16aca925fd38c2e9edbe4a665c5f969010ccd170931dca31781a570f9de3c0175f71f2236487e1f321d1f03d2c3460ba2d0754cd44" },
                { "sat", "c02b3445b910fb2a7b9c39d5b179ccceae67689b54400fd190913ed06207c80e6697bcd413428c5a0883abb76ccc3db0cfd5a7cee70d63a7312266cbcdec6120" },
                { "sc", "51325b5bfa99d7f1378a8159e876d0fe5f4e7ca5e6d5c9abf2573604d36a021e18b2f53c939c788d4224197e7c7eb3207ba59fc0db274e9fb8f14360419414a1" },
                { "sco", "f6ce315c98d1ef4b77187b1b900512d1b3a4a77d70c0adf4d94d65f556b14bce01e48ad6f54e1944a6db6d9c32b5f5f9bd157655c3851ae128522981469d8de8" },
                { "si", "6221c39d38b427a1ff27a5b509b3b9889fc97db1f42f948527b52902e6dab380b615866a6652dc6cd9a89a7413273a639e3b269c5cdc772880efe35d175c743d" },
                { "sk", "ef72b30c0800cda98b81cf3fa23c4930408441ca4189d1a52c49fc550179651a70e15d29bdba818488ee7f30070c4feb45affd490934654389efed3a316f92cf" },
                { "sl", "5b6fcff0de526f8348eed862b3a66eba696cd6f54870752d5ca999c2bcb6ad455a656273df6f6975338381d0c819ac991a503e432a972d84f4fe980a631314c1" },
                { "son", "3a3f8212dc63eb85b5fb2d5fdf27c74dbfccc42da8ce18ec577fa8587520f0f03b185b4d4cc3882adf31275c6740d93fa73e91f7fa8cc614eacd852e50781647" },
                { "sq", "4f1faa8a1592f23cdc8d0f81244e71092d7d2d97d5804e9397fc02dcbf4dd3dbd172c6307560cf596702475083b22d96c3a471f933e5e3633e12fa50248ad6a3" },
                { "sr", "5811cdb7576920f4c517a9b3ba5898966c6fda4dbaafb9a9d2dcbfb46baad6ab2d1b464c007452c29de8df341793f28262eb10d37b799037fa85ed959ac78176" },
                { "sv-SE", "e700a2f61d3b28bd6e5d5949d9e9fd59e16adc0aec5d5b64164582e80f6b17f4f6ed9bd191b69ffb26a1bb2fe88f2c5ac6ce8d187638390eef67ece880807b93" },
                { "szl", "c341c6d9922d24c01d0c6cf108b6c248262c2d7ffab0e465f4075068cf0a98727ccbd3e8f8c87e0551ec13cd724919c94ad7fe61f3786100af0b9375993048ba" },
                { "ta", "ef9c126cb53504c4aafed03e331c548779fedd1c4f81f5f0f9c8d0eeaa5e73a85393e2a3774f2378667e704f59dc048765351d3f94023667e724b34cc6211c8a" },
                { "te", "340f5b3c10191e6e8dec3e1b12000d4282a3f8f0c156020b4ce2a2a0027c8a532634be7f8ee3342a6bbc7bf9216ded1857454a63ee3df862d5767892e5c15385" },
                { "tg", "0ca7bed0ba8894ce4ff6ad62090f0bef228dc428e7b97f222f98c6db6274052d3501d4f5610d62f3190ee238da51939f126024c8508422f6c0682436febc63e4" },
                { "th", "6be8d48df7379bc4185a7d89ec1b176d5e0684c04a26c00d5a02cfb59a2d6b7141879715729058854e89f1fb572caa3af78066d3dd64f0c932a403a59ca15d6e" },
                { "tl", "6e9cb7f3b1bd8e646dcbe252aeffe14ae646f7aba6126cdfdf3a645f4372326e785dc5492d4502b8861e33f86002f6ecbd5609355916758f080c842db33249a3" },
                { "tr", "b9cbccf238104fb03bcc811ecb8dd1fbb864d080fa06808614965ca5b2f31589d8025f77c7b58bd55d0d5313dc983f81aec88506cf7b891c44057da2433f12c2" },
                { "trs", "bce27884e2019dcac6c006313283701b4e60cbd3d2b00ff1138b32a36f9a87bc7371f9cb6fbbcd9fc40689b79af4e722a8b5325a6defb404cf6711b32ddb6a55" },
                { "uk", "6e35c88b0f9a6d359ed6f29fac161e7cd1606f96a2587fa8fe8f9f85a90edcbabb2a41e3a44b7fa37a381fe65f971972b2783916b3d32aa30680e4f0b4326327" },
                { "ur", "241def8bd5e28af524fffbd31c03cd064c1f3084d5afde97ab53a1b10c86022d7751a9f761f691017413b1f1af6b7709770c0370f832362b9722a45198fe835f" },
                { "uz", "d5e66c861a03bd27bfd7fda36b5397c1ab8739441ffea8f2ffc79aebe57875ab59907c9d9d3261f7ae83168c1a1aa2e0da09063ac90b1a14e49aef8530b5de48" },
                { "vi", "7c2aae8a2420c9540678cbe528b5ea4216ca57c4223a2ae875593a6979d32bfc1be53d5e058f4d9ff1aede815bb6398858b5b079c0e6968562c9be8f45e8b2f7" },
                { "xh", "2d8ea4f13d4f38a42ccc6d1b9dd09c5870347f080d42bd67895a79dfb9f55b3bc4bdd373c56378545fc542879f63bc0e3ebff22f9ec24e23de9da5300786c06f" },
                { "zh-CN", "ef4bf6e986a9beafb47f2d7725ec84c7066cfb97458d5392241292eac054911f1918f4e72a4210dad68068ba7476e2efe0e502524af13e443c526e3b12af9ded" },
                { "zh-TW", "2bace83770672def09623ad77ba4de01ca9667f599f3e32b8713a9bec52aebc79940b5ee9745efbf55b00c5e449ae44c7e20c3b0ef37fe6bed45db00e9839cd6" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/127.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "9da7f4af443357eb93313bbc6f294baa8b3d2c332c04288b2024794c4f42c5283c5caabee3592fc498c7b3bdc06b311c7c2f86ab93f43cd03ea1b3031de91d4c" },
                { "af", "01d2e49159fd77e54f5d6b30fc1a3a6638a8d20e50c6a47ac67ce2e6cfa460dbaff14f6557e789d106d55a8fd20252e9bce1a2e6a93fa8057ba2f07ace4e0ae6" },
                { "an", "573d09a99ac33a1e7c962c726871354bb93e9b0fbb27451039524a0d8209e4b3a587baaf33f5d96ecfb79333cbac90894e4dc787be69bd4a21e55343c9c480a2" },
                { "ar", "ce2e5b60965222835263f4bc787967db3c74534320197c90a71949150421dd87a16151146ac668712a673f53145c9607ab93dd59e829efad36003a8899e53828" },
                { "ast", "8d0d7dba63fcf0ab79f87017dab70656156273ac9b6278b6d4eda4378b282e375332fd4aeebc95bcf7249566d63e7c01b539495e5dec5424bdec527ba63cc601" },
                { "az", "dde59cbd7868e2c7b0d517bb0d83514f4bc4de79d21ad2552e5fe07cecdfd65bd80881d2a56f858656be0fef0d32bff26a79ba998c4726e5a9b95250e988e7a6" },
                { "be", "748f68079f6605035a8c8407ce202ec034a6709d233d6d45688187682bdeb44fa988f7f5ea1a8f83108e6daeb3dfc24160c75d1fcb6e4b2ffd5f3c722d4522dc" },
                { "bg", "b667efe3e59991b0900af861cdbd594bd17335ebb6df983dfd1c5f5209204d2d1e2ddb93429bc85e925641929a6bbd0170f643bbc15407d40aa6691e0b3596ef" },
                { "bn", "37b25c5520877ad900486720f68e2619a3a3aa765a35ad7432b0f227372a641d44268765dd18080b63c74873cb45e6b849b025e797adc92d500ba77d73170d6d" },
                { "br", "55ab7a22cc6a8008c88fce5feb7ae2c0f209cbda6f24c2ceb12b2f90cf58c2388ec435d4395c1ffeb7b9a612b0f39478599c42e6c637d14fecbfb80d0db8924d" },
                { "bs", "a84f7018a5ea1c17c764f789ab0285ceb9a18f42263f2d4a57110b453d09c3fd47a924ba8667430c5e451a4490331c4da2a0ae98b77902795347f47dd5701f30" },
                { "ca", "a5456f8c808fe7182f0fddec64d673db62abc98fe2482ee41200a14a4d71a399bee5166e580fe5bc2e0ac7474f5e2f2cf9afa229d8bcc8d81e926f42ed16d79c" },
                { "cak", "17c5ec24e1768aa563a4c5fcb18ff6f06491bf5df765b4c7c8b1b388ab853eb1856c39ce59fcd8bdcd4f51f99731f97dc9607d1b5f10883c03a8859517dda3e6" },
                { "cs", "3af020fe646b7b590197d6f7de6cbdc747a6957c0e8e7b78afad5e82d1e182bc6ba673bc7979a52e498b19b1a97e6974c855b497bec31e703f1c60baad665759" },
                { "cy", "9685e18b98f313c600f04856ab646d0430cefcc0bbca8bcdd216bffadb4da24f2501e35bf7f0e5f82556dffbf46585ce2d1ed8d851ddeab1834f81d66266eddb" },
                { "da", "dcc1345c5c35407f9dc53523513e18588ea64317baf360a5378c52913cce5c50045c10c0df5a17a458969bf393ca1f450c1f52f31de3593e1fa4091e736ee55d" },
                { "de", "588ec89fd3fb599e891fb3e4d47ceeacff63d166996a4a041b99c76ad83abd8ce86bd447cbf5476240637d28dbc638d8da92507d2bf66b87dce83b12ad152e66" },
                { "dsb", "f758a8e2d1aa12ed6bebfdf9fa9f07d0b59a1e5929669ac674b6cb6ba9e189204caa15b5d490279e0e0e8c956ef1c0b4774a687602cc660eb338780b995dd2c5" },
                { "el", "212b6a8b44b4c6c4e59b734cb1ff656f651d5a166340226fb3099126c8144ef8de43aa29c352ae8af0d334d50cb924209d8e875dc889abdfb13205d8986ab829" },
                { "en-CA", "0492359f951c81e870632cfd32966b5f9b936c7973001a08c4dfe0c805a1857c81f314a02409d798d5056f6fcaf01b48f08803fef631ab4a4c36165ab3687934" },
                { "en-GB", "97c267be09d00c7d805a1e84b77100bc599c28acb3337b4fa3e353ea295b53fb08b6aabca4625589d647308e94856879caa48623aca20e38b38aea7369c7b832" },
                { "en-US", "e879be7f1089f81132f70e5e2ee47479932b8a5f05a1111d5a5e9be679a51d36679d81ffb41297abd44686e4b5ff50a61b196543c0b4219cd05f51e033c3728b" },
                { "eo", "5d3a13e8f41cfc4c19341f3e1c0ad67255e9da54d8213c5a5c0f57bda7abc7cb2b90a92529c04d17bfe61fbb0406cd907228653efde8cd8c03f1100bc7e305c6" },
                { "es-AR", "650f1f40fe5cdf03ad8a995951d923c047f4ca6dbf31967dbda616fdc2a933c5ea384657beefae3b0104cc5047a85e631a3b7d88235307ced6fa6765a55d9c89" },
                { "es-CL", "6fdc35485cbeaa442b1800cee98e4fa4af4f960d50ebd6533d4ce6a70324e2bdf3e9f76aa92f7399d34982a44054413d1a68c74bcbfcaecd0ba48df27e16cb3a" },
                { "es-ES", "c1af4d4d6ed9279e0aec7f4c40a4afffb512de1627abbfd30740a62c2617b6316f87590312075c3ec239ad8465bf10b6c92c135fb10291f4be8b73c02be9f57e" },
                { "es-MX", "f86aa1166112820632c7fa5fd6037dbaed602920acccf599962e1e8d2928b77b13b2511281e93c365a954171974033729d0444768b4b29a2de4074f3382c79ca" },
                { "et", "d2a2a1b64574a1a2eade97f6338f39f72e958aee181c5a900dccbd8999f67371b3a30665b8f306e6e250f5226d4c607bb746f32a832eccffe35f1d372c6943c1" },
                { "eu", "94d4e4d6ca0578a694748afbedf1206cff855187edf2e3e401c41bc0a22fb75e19441b45d6b59afd6f60b3e18341da501e644fe330f17744ce0f879613f904e1" },
                { "fa", "87389e42d61b52d56b0f8ba398276b1e3be03e7d5929fd86c260ee97ccc3d5542bf6c9f7e9d91c89c424b01a25d1942e5d8e4f72ab394a4926d5721346e599ec" },
                { "ff", "3151e37b76d90676d366bc6bb8d1f2358393ee5408067df5fbb3fabe6d7fbcae781a1c18e91f144dbeccd590ee743056ad35462b12965b6aaf486a08167415c1" },
                { "fi", "d6fd9b24faabdf6c98e061528bf0754a158edca516ffa9767fa9c51baf54f3f7aff4f1e8e8431f492ffbfe77f49d688b2e627811e1b95b48dbc96f1e9409b59b" },
                { "fr", "f6472c94b56936240415dea6c52b4f09bbbb965c3491360b0c7911be651b013bc4faa7a92dc1b06328b1881d74687523eef23a4f3ba2dcb53f3df6d13bac621c" },
                { "fur", "8d29ed4163e42a7b1f3d1e4ec68f2cd90ea01de607d2a9df38504c37d53c95db99b9ed18b97c86ce42d3a66e45d36c97d1ccaf23b9efff74624cc23b27ff23e9" },
                { "fy-NL", "809c7f66fe7d905bf9126968c85a055addb48e1214c83fa681aff38a995100906f53d6e6eddb932a6716b41f8aa70422ac1d13cc6c1d97535d6f8f49d2495f92" },
                { "ga-IE", "6cb3018e2a5948095e2066e19c4de29f47f75776e706de5e5a57b4772a2db5b12719c818ebe232eff795f44c224df9f0736183df65e6b4da3264ebe4597a2f5a" },
                { "gd", "4c3afd8b59bfeb36150879bbcf2328eb3533b304d72873258de01dc91ac8fe79b87f6ad4561a3d9f7a8a4da3c5c68671893442e3e6fd50cf4da302510508fc8b" },
                { "gl", "89d454b5abf043911197912e22754fece67480a0d2148d68f87e4ca8cb79e4ffb480507efb5885a9ce052b789a9e7cb233cc1ed6b3cea33dca4890796cc629d7" },
                { "gn", "1fc12c98b9ef3a3d992dff76b3824e156cf252134c7be0feb8563cda3f62943c4d82619e1f4b1bac85a568fe800b176e2a976b8947a382f8b70ecfd08315e27d" },
                { "gu-IN", "89519d0e167ab25fb8f69f85e23ed7a60bdd0f83062cdda17ed69af9cb8bf1cb68e405c37b808eb1e2043b1a1878b042d26e0400eeec1072e20f811f2faeca18" },
                { "he", "7f540f9db1e489f429b0dcbb286ad61254c779a2d1d3dd287896d52ccb4f1ea2d052a622041a06b58ffad8d18aede45c815edca1c05b9824f0bc19e41dabb530" },
                { "hi-IN", "c902ed70ca23d3c7ea6a339c1a627b348dfbd27cd1a5f85e7847b60804aa1b5da9d0b63ad045b63522afddf52c549da346cf3011d322cf95b0b54262a5d02cea" },
                { "hr", "209d31f260e6fc8fbe13b560892c5dacd99f3297724ca11f2aad6017a39040f26a961c70d6e8793b5baa342177e0fe69db0469f93c7b523c086567e817697824" },
                { "hsb", "1e35d0cd6dc09c2ac21e70a72a1154bb946acffde7177bdf153ef0addd85c17ae2d83c8ea651a55b6deab1a374ef2a153409ea2a1e0438805c747ec5bf2dcd44" },
                { "hu", "fd6f1626e17b921a8b57e94162b2fb8d435fdb890bd4745e616fd207fad4b9180db4c46d6f9a19403bcb5487cb3c5e4bcc364bb38d3140308974c8266dfd1ead" },
                { "hy-AM", "77ce402f2b9ebf7cd666e67713fb0932714b46bb03084be225f412fad24ecb4317ba46ffb354f01c451b89debaf87a4d138a4d138474770c16ec6d53e2479cb7" },
                { "ia", "069d6c05e99c803200fd6cbba14c61dfe71c32e556c1cf81b4ac79af36de209d3475bcee143eed04f8bed360d4ba13f9208496de7ee9ae9412f6fd2e998384b4" },
                { "id", "3e8da304a1ab783272ae6057ca47b304ce7652c5360ae2c2bbce3edd144f528fbc1a7c614a4740c4f55a1c8192429193ec39a3b4c4386f0828c0371628d6d8df" },
                { "is", "8437a7cbfd2b024f68e0cc2c41f22f0c54b78369f8ea93c773744e3b7a5fadfe2c7021299d81b32143552674204827abee76ace4d06029c37af133ddf0b7b031" },
                { "it", "f2889c0d955bd0a4ebaf81f5d861e559fed5acd0c09b2c340b1bd497fcdb538f51494fdb5097964b2c7bf8026f164ad582c7be10944417312b0d6f1f4ccd0252" },
                { "ja", "605faf9dbc198eecff530622d98a2bbd7388f43aa965c3648e6f08ab0191292925454f250886ed781c4be625f349261b3f7678c6d186761ff1cc9a9e412e2582" },
                { "ka", "525d9d5f54b8f391844c9ecfa930912c803bf1fcd3dbb98d1cbda6d5941f3957e72620ae7f0839e1964c92dcc877c7c72eb87ad4ba929f7bc114a154646f6f78" },
                { "kab", "a06ef0006ec4c8cd7f7140f356f9a1b9e1d08d19298cee647e71809d81ebe222b8603d12682c3a75384751908459855f6ef4e7fa3e6c370d47f1f25693daf812" },
                { "kk", "71f5fa7563f27ca79842ff6acb25a8e226cbc0c6152621f9b98b059596eebd6a3a66f3ae09f3fb33b4d55c88cd67f451a649fb986f4656a8c345083209fb7ed7" },
                { "km", "7a57185e23ec49c901901b84e30970ef354fe2689464e53868902642f32863eee9b3fa4a3a9728049824ba5fbf207f85b408c92ffb38499ac6aaa683b2107dbc" },
                { "kn", "48de16388d78588e1bf53390600c913d035ccdbd9264c7e2f9c21ea8ac7c593224065c0c41c9db2875d7d5df1378bd767ec629e347ae6f9a755c8d503c803e71" },
                { "ko", "1435c1c98c29868e42577426a79b6baf49efb02251ee346d1da73a19c315f47aacbd6a2cf4c645e0592eb73ee85c20461d4ab11130ba043631f234175c71a33e" },
                { "lij", "a1d7c065cb26316e59a97296e3e57af2520573ffeab06fd1cb15eff651e058de78d0a8acb3826822b8c9d65c43e440ae2dd08697bd2b6d922e9e075efeb9122d" },
                { "lt", "9858f694ca87aeb25eb24307ad5373b16ca1b5cd70c8927d475c024cf1fd670c8eb4c1734e9ed0d5cef4d63ad04a4a2982d0c2f6d10bebb044995e3a6c82c0a2" },
                { "lv", "73835edf78550ade5ac6c2dec8077e43e7d9f225cb64f4d48e19a4348834dedcdca93df6cb2c7cb5dfd865f50b8fc410b14d133cf52d4463eb28ddffc88c7398" },
                { "mk", "8a43ce196b12ad06b400d7e9300180ea536f739795159d4aef0e0a440aecc50ecadf2ff8ad467476f7cf96d2cc3d64785745c1eb804389ae85a4515305db3fc0" },
                { "mr", "ff9baa23db1a9565bdfac0465d7e8c36b562e3a2fcf76bd275958487da567a8e6124587050c001723b7df91148eff09517ec915ce9f2710730b191fd29c34398" },
                { "ms", "c357841ee176931ddc0f6059061228097102781abf9e27e4f73f0d984efb921808ed1aae237b46d85bf11c7506413cec78478dd1ca41ab636994d67b933ce763" },
                { "my", "044d15a2a1f7c57c5fd3a89de3d9ccdd028bb608ab0e55f208d760886d472f01b5cedcdaca5690d5ea2c83a340c3f747fbebb6e2ee42f1c741f57002557990f7" },
                { "nb-NO", "77d2cea0824f2ca7676cd90587c020c2551e5597c651fde76c17447243d1527ea2236faa9cfd3e34d56bb3797f398a0d83be18daa1a07779222f4866eba6b2e1" },
                { "ne-NP", "5a90d93b19d3908b3055f84c9929e8d0353f388d8c8da98c1ea8edefb1aa0440f975a058a92029832742637e1a5a96b6b940fb20fe223a1693554dacaffa6193" },
                { "nl", "f5ea3cbd3a502e5ac30d8d9b1f1286902b4d0e475ce158c65fb99fdbeb7f4c881400fba9b939e49fd217e456fe8fa331fc361acf116db079620b0061ea36f7be" },
                { "nn-NO", "c825a7b27b04f1d1cb8d3de421ace6c30419aa59aa872d45fce14b6d7022d79e049d390ba80359b7eaedf6df85109a7320ad9cec522c72328f204634f7dd9a24" },
                { "oc", "0646c452d046cde39c6e7a0453b31756c267991a90e12ab7236a698ded9c9a50206c747600c5ba1a024194554a8d050bcb9d51bd6293073dd332d5daaefbd50a" },
                { "pa-IN", "c89435a77c0cd7a2969616a39753ae684212c4eb0c19b8644a2d4b10d69acc0de733db8434a25c9c7aa9fc8c7fc995e3dee57fd9ab26c73b633d336c3e829296" },
                { "pl", "54f60210b5461ee453fd7ee5ab391dc96135757fb7d0304d22590b00fc274c83b5d5bc1fdb8e7e860f416ff3470595e8144db700c62f301939dd6f0ccb880ba5" },
                { "pt-BR", "04fa3ffdb8efb639974a4d5537715966e3fe7b1ba16b235834e8283023b12c057d099320eefbb9306196f382f8a6ec77d2b4272d085c5c680acfa726364c7345" },
                { "pt-PT", "81bd61e380427bd590b7bbb425f5b163d192eb7f4e4f68b8287379bb761b0faf49551044d7b785b4cd2252f4b091aa1e3b8b74deb806385975c281ce771cc98e" },
                { "rm", "8a123cb0edb81747b7feca8259125695943a7aac2aaa43b3ec7efb67124ab1622456aea0a7bd26841b6005338666f7b82d9551e1a5abbb4e982e3e075a25f1e5" },
                { "ro", "bbd9dff0d34be37a759f6a80685b3bfa3b1273508768a25ce47ebd86784f9e2753f3cf8773d0612296021b158b167a1b4e6af1d0929b0549bf4c862e4e0f1df1" },
                { "ru", "f1dc6f143f81c29f591f88f66df068b7e9dfe3755018fd6a8d2fbc6c6bbf2b2221d33c7b2b3dd14148de6a5540e37862f9bd0ca2d654a25fa7cefc7efc079555" },
                { "sat", "35132b7f4579101c0a13d3326f99dee3164d482df44486676d06bd35d1ac42e03afc24585cbbbce4586b4f39872a81c8a951ebb3cf7ceb95ea0843463657c13d" },
                { "sc", "687786640297de7f55034fac804c515a4bb4c467f66785b986804510b96a20a25e738ee3e899a00e46b29a5cb912c4b457a59ab83c8ea4fa0d9e8c18d7f2e8df" },
                { "sco", "f557323b92363b5ffce65cbe3ea7e325bc7a17bac4d38c41dd3a1346a3afd88edcf3335cdbe204344c083cbb4fbd2c118ab2a5423dbbe15d333c18b4cf1a1e7c" },
                { "si", "e76adc2297f7ce0b2b8d52fa9ba52c78943aba51eec1057c156bbebab4fedc1c44cd7213898856438b2cc8a26ddce40c52b8497c5b0505d068a210ea731d574a" },
                { "sk", "4fccc420f3e4ddcfab346d1d8552a1b601c6c7cb69cbbe5b987470e67f4e07027ad69882035f7f4d44b66f1b0bae35591301f2496608cfbee4a263d7602b50c6" },
                { "sl", "e749e5adb306591a857a2cd76416ef0a46937830bc0d63b0b728499cee5f4e0f9e2303389594b2757166ea9e37be2f7d91c3e9f91f5603887d079f98ba8c7b12" },
                { "son", "e68ee516b9dc0ef7f8e8eb01ead223bdaa2769865dc04301071faf1d6847303966080cb8ec782cb6161e79e266e09fb33c93946e9d196b3aef4a6bbaaa4bb34b" },
                { "sq", "912fca24293a4fe885e4167f371983b7a605c7a884066e5a9435829deb049948d325d0af678ff35d5216d1909b25ef838c22b1bce04078329d8c075cc8f6aca9" },
                { "sr", "831712fbd3eb83e285c278c64a7a06eee91e2561f81058bdf95a41576c9d9e54e6376e6e5b319c508a79416f9d571a9c877c9b6518b353eedfc4e47eaf730a92" },
                { "sv-SE", "f1adfc5464fafb75326e1880f2447e2b732d1b41bfc21f4b8d204fa93a8546d6a546a36394f1dc0428e194a04bef8cac9702d750c2c55d193d511c0358ef12e1" },
                { "szl", "e9630b71cb2db05bd98920d964a15d38ecf7c3bb63515e166c91f31321ae0ce76d89f86dee58ab6649840947c783ebaaa18b25e9a876d4d39c78e433452e0c59" },
                { "ta", "fb5fd87b1630cb7522d65977ab18f503c34913c8180c6cfca591ed90168e8c4f9ef297ffc8c7ccc71c4f21722c3c47a97d14e5e8344b5c3678fb8e8f421c6caa" },
                { "te", "4026305f9f19ed11c5a0053e934017ef5d4d2e90fa4205b5e6815e451e7fecd34c20392936a2daff8bb5c57a443fb56cf9e4c86aa19a7e396634adfefa0b6217" },
                { "tg", "21ce7d5f1f36f8ef8594da99d33b480f331934a9e647ad3625217484ddf20c8f51a5de711502e734479c8628198a31f732b5defcfd99b0ab88e3641253502c3a" },
                { "th", "cad19e718e651711935eef8c631206c3f6ddf0b6f54c35a5d36a32e1f041eee3fc665f25fd723682afcb5d07325080ce6100b3405ec900d8db287e9b6a4b7baf" },
                { "tl", "0c067c3a1b4462bbd23c2b0cb90cbb4a553295cf1b6dd832188a4882e2bbf72e7b681906477e193f5a7fd359e690cb0d5524db796e68ee25b43afd800249cf21" },
                { "tr", "7e8c5e8e3625817428a2920072d40377fe39568a60ca505344d4b144dff11ea74acc9ec2aef860e0f0bce70ecfce76d7b5c32cca4a4811f65f42688ad865578c" },
                { "trs", "5cdaeeb534e9ab9e81bc8123103ef2e0e27745eac46d178d8071594e8d72436c7f9ea326db21a3349bdbf1860fc6a9cbc605ced9cf44ad4987bd4cfa5910781b" },
                { "uk", "6d49c18313f8be0769689ba8357f719b080f52c7705c333a04414ed74e94eb0dec0393b6d2b045a02666a87a59d8a39319d82c61e0561ccedc88e2fe79998750" },
                { "ur", "ccfba9c2144d4657474d0d99e40ab07eab37fd35eed69fb1e4dd3280d5a5d17f627e8a6c7c85018eb7ff2c55978261907c2511e1467c6976fbf99016f5d88601" },
                { "uz", "0dcb7b80927b7a550f2558d6f6826622c39c50810845741f8e8e86a6f46e665fb2e500e355050131c72e9232c89b2896f11bb376b024cd268badffd0bd9d7b91" },
                { "vi", "7443b1c0b9d5dd0c40d5e8002ccf57153bec6b6372071afad425d96e44dc3b31441d441af38db6dd99776fc55550d4db422db5355a9fb7946aa28dcd21f75d9b" },
                { "xh", "7255598c1dd025acfe0c070f99549be249dff6776b75db8048900dd1d36a433d6ffbbd1fa932e9fcabcc50cee16afdf769bcf00763cb6eff1de8aa46ea7141cb" },
                { "zh-CN", "94f9eb2b9d1c655f91588d61bdeb8bf25fa7e9e2db11f332be480f4f61895cc70e510720b5a34de5ec39812864a5816e3481a0e019473456a5a27663e56149cb" },
                { "zh-TW", "ef8442dc569b4c395b52d4c34ea849ca83785c3e279fa59ecf40dfb4136e4f192ab02fd83e9fb8e698a12c09b89b2508ae673822416f1a57b22188db8a63e923" }
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
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return sums.ToArray();
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
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
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
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
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
