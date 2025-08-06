/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "142.0b8";


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
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "4ce922f2d73ca5098be42168aed22fd93fb956c23c69c6a73ef41040bfa9c575065331d15c3c71127011722eae157ff350e156830f954d9a5ef7c52e83937237" },
                { "af", "a476ad9360f44b9b3a9e78bce6de000667f12e5f1dc0d13c5c379e8e1e6c22e24725123e69923bfafe1578bc2690c112dd793157167531b19a23d3498257a2eb" },
                { "an", "651b3b34def19bb524cec2b2fa174ad3fa2d589a8c82a12d85410a942d2a51a9eadc228e2c8cf43a1512a99fa085560e3d8f050f8457d091eaa89c784e30a73d" },
                { "ar", "1c73d0959bd1e07215ff2d17b8f1b1748047571ef87af2067c753b8c69f5c384aed586df3f2511d77017f499af5a8c75585c5bd40d40eead12cbf2d15a740aab" },
                { "ast", "1d1fe92aac449f605c26a24fad338215746cd841db01e01c51eeae05588a8a206aa6a91732060fad0e2d614d78b7a4d4ae818ef861c7d44f973851f6fd03b1dc" },
                { "az", "2c95cf36cb234bfab095f1a868ead739111e892943cb2fc3ada83e89dc2d4866b4fea29a76029610202c128a0de43dd5d1a592dd46e38f7342dc2a4fae473572" },
                { "be", "98e5955e945b32ed64cdc41d39ac0112df888130b60455cbe629718cfa2f53c1d4472d5335ed437cf3a0ce730e60bb373df293cbf454e4a885c5a55047ddd657" },
                { "bg", "91f6517d8c0b734c222e8903260146af83a6f97278a9aefae7ae8c9b60d92989bbdfd29f96f218428016df1ad10bd06e0655dab3664dd82db6fd75d4d45f82f7" },
                { "bn", "374097274f17097fd2e359aeb3db041a97b3fa65a10939fd7fd88799a1248da5f0fabac763437d3bc3516dfb3807d5550ba7a7477bcf200edf95c2a4cec38a45" },
                { "br", "e134950bfceffde3110930ae195beb10fcdc6e1d46f43a4e2f38eff95f3b7bf0b4ae5cc901cd456f82c4768bead722f4e6d0e4465e13aeb57ea46b3fd0c1b8ec" },
                { "bs", "3eaa8ea039151fe919d25b041da3d8463ef27b4fd732d6116fa5c6a914db9b944b8d50270634e8a90e04c291fea40ad6c422e6c4c550cf7783fe445036e397b3" },
                { "ca", "77699cb642c4d0d793380a1919b40c626c0b07f49a4979fa76531c88ed76fbacbcafbfd6f3e2971e9197be72dba2a5790f08cd6ae8836e81f8fa7b1f8e991c72" },
                { "cak", "94fe00e0ce00bf9581312d7102c8d932dfc8a2a65ee835af92f784e29d40b5c0d5c5965e9019a496ab863cd868c7f63755d171c25b5204643d8fd63afc93b0ad" },
                { "cs", "45f02ee44bc25c92ffbd9da4e5196d7dfb7efe43d5e6644eee90f2db1abb2016264525bc46e47cde4cff2b135ef68d62f1642f122da7b1d2fb8cb53df5878772" },
                { "cy", "25bf3532a7961bc9d27724c08e903e10de39766899a119296ded9ab74ac24c37df3f53fec263664a35409615426a5a8be71267a30fd5371b1962b0fdb2192cef" },
                { "da", "a2082c608ea186ef1437ed0ba9efe0a34aafe6f4c7328da3b68f068f209f603e9f622a2a432cd659a38052d06e7e3bf9cc54205840e8266d215b2cd31c9e322f" },
                { "de", "fa206d069953302ad6a301d846feb94fd6e8179c5c547ff8c5da4608ee8e209e7402cbe3ccb8a0e4f57235ceb1315613d89b8277ed3af9541e2746ad099f9137" },
                { "dsb", "f01ef44be447a77b8f11c11dda4170ef1f48f1628b2cb70a4f933d806d2c1bc8167bad3457a25aac55c93eba976baef3edde4da01375d7a81ed2e27f41e40c60" },
                { "el", "4189d8b4857c0be137e8a9ef581d145d4c6e3708c88e21800e8aa44dff485381a557447648e6b04e3b6511163d5ae532a9f987316bc360e26734773bd2c1618d" },
                { "en-CA", "d3842ef97d80cd23d744ce8f1551520be7cce202cff939b4a56c961eaf49e4391457cbd07d10744a106483260b3f51932e1e3b7aec69d38452b0e458cf375a5a" },
                { "en-GB", "00fa90467b07872b2d392c43fcd8d1ce6d353de22e45a516961ec09cfe59105fcd4c787877476e2b7f807b4f2a8ad8f670405158ff6b9e9ba9ad0ec537bdbf8d" },
                { "en-US", "e811e5b8cbbf17d1af0c729439b889511bf7af05a2b83cc94f10c39e2c99d1398bb23e4f2c29fad3c9405f29600144cc83d71029aa4d389a6b4417ac88aab6c8" },
                { "eo", "4d296dc19c9ebb29152b0c8f1bf4ee632e926c6ff64ff8d1f2bcf4185311f81523ea9c62bf6957dad20903561bbe064781956fd28fe6fa25f614fa61f83c8088" },
                { "es-AR", "d6feb13bf899c590d6d6fac4b5051289252b602c56fea6f666cf867f9f47d3c4ac7b0f317ebaf23855af9c109a0ff4ef7cfea7293dc2f13bf788fc2915d6c2ee" },
                { "es-CL", "51aa1e47124f7f4e1d1910a70826b28e562b76d4f63ef5646cff0649a44f81f540b803099ab188de9215b3197039339522b792e98504cfb58b6ac695547bb15a" },
                { "es-ES", "7d70b603093fdc831e1c1fc35c1de3f76879328ff8b6593556cb9557446632d0dba5d24555fab412078b92715b4186b14f62173c339c9640dcd355a840dad709" },
                { "es-MX", "f0cf57224c821c39318eae70b7ba5ef96f563e2720ad9058b39828f52398fb81e7d5fce21a5e8163f4b01e4b5f8a84453a23432648c822e818fba431543890f3" },
                { "et", "bccae6922c9123a16ccf8507d3b1ab147cf9537b8f1d12987a3e0d9548a5cd33531a67fef41a51c5179cfe524a03ddd3b91e1971c7c87583b2e63d23ca8d22a2" },
                { "eu", "7292183f2eedc12e4fc75abe9d6596acad30f874388e4dca3689974533c585d962fcd0a7ad9cba11dd01fbb818d37d81231d4e10f321aaec01971d0b9b1ecaea" },
                { "fa", "daa30457a839553bb2fc116bfb6ac77934285f565abca2f62de03063bce80be71401c683383033ce1dc5c9889c2688407306192504abd3c14495a75af2d1ad53" },
                { "ff", "8f9b1272d670968ac4091b97e233be6b2625ff89786657cbfdb57239cf9b1ec3dcf42d0654293139d3c2c83e181b5d69a8549c8e8f5c82411e8971c2b0b8d43c" },
                { "fi", "0a6e058d236498a84451b221ffda9762513daabdfc660b00612f2bce5ca3c12b6f3e20f34bd85437dd1b75091d3d8534b806dfea8d1396e2d705c70d51d41a5c" },
                { "fr", "532ef911f17f138925541ec295c138e9934230f4d8b010b74024d1d79c749a72d5ad6a2c93651a1364082df0f7748a47f310f01e0ad3294ccbc05d82cf020557" },
                { "fur", "3bac8e477520be6a0cdbae573a1477f3ee5b9ce924911f5ada925b4750693d1e7fb3e9941679e5cff0fbdb727f56da95fd31f5d3cd51623cd93d9b6231376e1e" },
                { "fy-NL", "e596194ed9b0108c6bd445b4e06a135fc48940faa4a5d4bbb6f252b9b34c947f924ae3e1cf6aacc9b407441a41669d9f237d559d3847f7ace2701fc3940d2d58" },
                { "ga-IE", "a9a1c028903ab66262cf05b232a053024215581d113723391a06f91e6bbfff536dd44a377f21142b17c4444675e7454a933d1df1b9bec504002bddc620a61888" },
                { "gd", "ca7ef5394e516dea036783a1e0899fffee476c290487aa3ae89b0bcd3c804e496d3214b7433d36492352b69bbb692db3efb790ca01daf3c88aa4843b052141b6" },
                { "gl", "c0484347b92f372c1cca59448666916b8a03c3960e5e9acb7a3e6251ea4bb9bd0c6c6b37bd9167f7f1c71f1f3e922932008b8bc708ad7cb57b1517b88590b9c1" },
                { "gn", "8836d0409a2e744f972be76aaf33e81ed70ff1a3d00e8bc475aba35a4f4f787ddbaf79da3130fb7ba78185c64478fc4e04f2880ccca759745243d68a1abacce2" },
                { "gu-IN", "8d46e3ec1502b3bdad0df9b9213d85ad29704c46ea537e6dc2f06fc1f4d11bedd057936285375e21c1eafaf9efe815ca417e66e461e659e1d354b7e475e24a46" },
                { "he", "f91b95d88dbc282370b03f4256fb47463b2e921e91ed731a066ebba9ad09c3612ded498d7698eede887532181278dcd55ef41742e0a6e80e15cf6f5fa20fa342" },
                { "hi-IN", "5bd433a54c102593537f098d1d889bfd8189cd9d9576d8fc106bd2a3c6a0ee816e1ec4016a2da4a55912d5c91268454adfcbe7ebadf6b83c4e90065e8299d6c8" },
                { "hr", "ca463dc11029f2f7434c7fa6a682cf6535fccb5ca47074399f7fb51710b5ae4fd98caa9e283b2c56d3822f66c83498850feca60303590814583e20a284c9e598" },
                { "hsb", "b3101dc0f0af73626a940ec28e99357124f2d29ad79fe345f6aad07c7da275ece42d46caaca8e5969223fc9bb4d1371be972123f0422703f6169ac71b6a58780" },
                { "hu", "30a89239f22be6e9799a15ece552f459f36d0009020e1aef4dde9b07c53c3f956039aadd328b1008282407c8881966ed097ab1e9e894d56722d6877670afac60" },
                { "hy-AM", "e219d6876c0b17410a923aa36348737d7b27b56b1d86cb8ffa682b6fe3f7c13b59291e9f08a6bae6503ee96519a70f89567b97e06df49919d010d0fb377c8c48" },
                { "ia", "1eadc0ff7e0cd03cd78ec2ce2513704e6e43bc173c0048226f3f62e985baa7706dcfccd7fdc3192b42a81288ccc2da62f927c32262c84748f82343d41181ed53" },
                { "id", "9d20a4a6aa07f6734349ce362e3b69f45fbfd759953b41f8d8bfad9b597dd436abed88733515ef616336c076385561c1cd60c2ca36cc42a7180184aa72f89336" },
                { "is", "d00d444f0e6eb6401f66839c2a27d5fbe64e1eb87085848fa8067bfe3ee86f044148c0eead45340710655f93305b4df50dc00479db76a069959b568ada0774c1" },
                { "it", "3f372182aab99f563d446bbd35508c230abe944561c512c76c0cd2c37f7ae4bad0129f9051591704a9ebdd9230277b2d246f4abf540180ad08c4c073be7e3171" },
                { "ja", "09bdbbfce0f5e5fad85a331e8f897533308e1c57632e732df3dad31902c424ff145db8305f114186fbd713f1c03453821b04bad65e8fe3ea53c43bf76fa27743" },
                { "ka", "731c511cfeedda3547e3274015ae0b7b028bc3105d2d20f7f563793eacc788ba68f820352997055a0cdd5517d0d909afa1dce2dc2c7d539be668f368160a7e1f" },
                { "kab", "234ff02d749e3c1dbd1e2fa70edd32966fefc7e31ef1683e55c731d6b83e88d9108dbb220a3f2797ec8be8d3717e7564f7471776161b1ec78f3ddaee35ce93a9" },
                { "kk", "3d42ace046cc76198fe5848de8c9fca5a22f449173bc76de7a9c21169e7ebb1b22efcc17f4e2db593132cd1a0037b105e674f361412442b59fdd66d2ff7d4922" },
                { "km", "d74608c1b65524bd436463161d3e498ed9e06e3c3d6ae17e560e9d59a1ef92ae7a8acc281574952ff667efb0d9e5dd9eba3a523940033f72ed57b80814df55b7" },
                { "kn", "f1c2563fcd8d36b5c4eae5f86ff373455b5a198a2a0aeefcea0e1e8ac8900b8c038d5f857c037d0955378332bf07c513970ca4a2b80ab0fdcad0b84b91384c0d" },
                { "ko", "4defcd4ac328a28e19b2d61e8f8f862b494a8e138cc225502e6d25a467e4807c95e2b387809a3b780311092e11b83ad126a6d894140fd99deb6ddac8288a4f59" },
                { "lij", "fb2674d9cba03798ed9df3c24362adc224671d99468c0816bea51d34f965696b8d1b5ad57b9c08d739b3fc8d6ccefd7999d2a4900c618b8bf1b1e1862ee4eb60" },
                { "lt", "486690137063de86408d36bc7c7a0871b63d1cc15de3a19a7b1930d181b7d32dcd78c41be08127b6c6bd69cf084a1bd7e4158ff855b06f3eeab1fdad286b0909" },
                { "lv", "0ef5be61a87a0ac7e0ed5a8cc2ba7718531951684f47e43ae11ad5d36fbb087f32c115a3b970f7c15f9ccbc06d4e88082e60a4cd57ef48e0056681e32f178710" },
                { "mk", "886e962de9842c5b8947d91c8b36e0424ddc35fb6bfc01a49ff093d90dfb5e2548cb437869dc5f77cb9e053a7abbd0d94c7390298c8f402c477c284576fb2dc7" },
                { "mr", "e3de3b7ac28989dde285f651d2105a7e0e7213624d1cd842a5704314c64459f3abce4f124c86d9470374f7e0e752b0f5ecc7132a7da46cc6165f85cdce513a13" },
                { "ms", "53666f8d641058bfd06afc0c285828a17d08f43789c7a80f1ab64af236de667a858ce28ba8bcf3177100eb249f1f54ff21044b1a3c5388bf3aa5dbebf2bb6538" },
                { "my", "9deb1c0f426c53716df857c2e15bbf4ac44f798af0f1771703c5099d15fdbaa77baf7f6b4b0184d8f21103a16c917fa955257dc135c4e0ea7789aba16e806945" },
                { "nb-NO", "5d761fbde1e75a8f0c6f1b90258b60af9b70c794a45913e9bade3f954395a500715b070090d9f72bdc1b031ab5a627b605ccd44d895d8aad7065fe3ed546e5fe" },
                { "ne-NP", "4ffdd986aac691b79e7caff6985c27678712f796eae4e604728c4ed00b38069ce823a50e3765dca0e48c00cb6878679da565a235ee84f77caa7672b6ce8d0199" },
                { "nl", "0de9997d0e0f172e8b0373898eeb0599cc4b5c75756c463c2c7704fccc32dbe6237e55584b9251ca48906eb370f1641e4634d7082f82c7ecac2b960b2e43aa3d" },
                { "nn-NO", "eee1bc06eb0b9ab45e624d00a2bed1f7edc6e4496ccb3cf8e44a04e90b909ee30649a1e4d5cdd052347d15887a74872bc9906fb6a9a5231b2488cf948fc704ad" },
                { "oc", "22c52709d627428204b5e9ed12e82585b8bfac6832f27c2291561b2a6c025265d3ec20eebe2484586bd81f5c93010f0946084cf544c98cec01ea06154c70268b" },
                { "pa-IN", "fa430c43630e9d61f3c25b12e1858e5db46c19b5db38e9e544135cfd94ee44c7a9b18b544551f61dc139330efaed04f77ad6efe8af461a219827860923b4c4d9" },
                { "pl", "19de24d4b6584df17e0a68871b90c8ec5fb89cee6fc75589258e1bf95745b7e4208eab40cb324fa001c6de83a5fa015db9df9d0ff5dcd16f2fdf7c53fd5fdfaa" },
                { "pt-BR", "8e29897969999ce1f69864217830523a0bb63b1f0fb706ed33b110ebddd389c7409131ff88710822bc1d8ed86350f449482f4f94b90ace96e849f007cbc8985e" },
                { "pt-PT", "e003ad70c9db0901b5151cf5121d218bd7d2bc97521106a85c2ede1037c99f8418d8f3d7261bb8fbb4ed18a7d453733149414249a4063a8d3af20441f6cedcaf" },
                { "rm", "922132486c5aea1f94b6d9cfc7dca8658497102b14a11251ef4198528bb0d5b6706c0f3918f0cb54c995ac3dbc8d0502529738277bab78dcdb82005ee4d5fb23" },
                { "ro", "a7183710123359e3ed6ffdc7355a5a5f07fd3a0dcad3ac15e1a4247d049438d950a2826c99588c8e6b1bbab77936aa69624655648be0ee06e3d7b8b749fb1afe" },
                { "ru", "fbb0df0b9934e7b01551d137c0ac2bcdac9b31de94604d98cba53d350dd679949c73cf1efb2000639f5b008eb2873ebbce3845d430b5a9df337cae229160b44a" },
                { "sat", "0775094bdbe95a178d7c802294e5ac79dfd5c2f4f2eab4ae41006ba49fae6cfa5e295ebfdd7015296f37d23c2946e7c7d74e600fc5f7a711fb5f4c4a03a405d1" },
                { "sc", "403c385479e22c614af4689afb6ec2cbd2e01af0959fc6240c70d9e734b33638b61579fcc5e39d6af489621ac2c0edbffcc8709fbd199b718630687bf17a67f8" },
                { "sco", "e33f79c0e1037ba2f737c108b175db140c7f61679707587cfee0759bcd07b4052b02bc6fe0043e00e28594c3d652f4bef2bd39d5573433a767d294fd7970fae0" },
                { "si", "cb058405ff239be5da1cc25cdcdd4881b180f562f68f97aeefeab0ace1812b5d69316dd95c8538a249840f6dc33a0f562a60b0db935615b3b011379d06ba5fe2" },
                { "sk", "8115e1ca8662cde55c5c771db1e2c8e94aaee3bc2794134865788487d8d517bb1ac105ed8becc97bd3562f4d7098047ba124b606d3dea685b73e7aa92bb84d3a" },
                { "skr", "2eee2d373722d8a6aad7fbc2fd5b21a13b3ba49421065de7232d426c59dd49bb24f669edfcbe2677441b4bf27eb94e537da0e775ea230dca428087fe5247ab1c" },
                { "sl", "31b202a9e54a4fc35bb352ce88b56bb7f7e039f57a8ff73015c6c853712385a7aa60128d1b1017515b3ce9532c3fd2e97d810a2f7cec3caa50feecc494f69f97" },
                { "son", "fbbb78b03d97a0cf3fd65e369679056557f0be90cd828d5a4eaeb1b97bd32da736a41102deb7260c7fd834de87296e39054ad26caba6241cb1a193fd66b5caab" },
                { "sq", "4f394512e4a385d7dcdfa1fe9695041d3665b4a0fa119df766bd2f06e21e36d0691a67a0710252defa0b16cd059d19cafeed757059d2451890ea04c3e3057432" },
                { "sr", "59d6aeaa6133687e3b7a4f0f954ba90ad082b8224a92359000ca8c7d06a6e96bc48c35e9c804e9e66e2a089f6d7eeb9aff6e5f2b7bb2708afecf1601e500ec42" },
                { "sv-SE", "a659686f161b492958e79b120b7366fa6cbf4eff88b93c82a8ac33f54c644f9b06368f0b662f43ad7c8a827db493d59b261c1bb3dd536f359bb5002c2e0c07ae" },
                { "szl", "faa489abeeaaa21b4cafec417fb26348cbe30fbcd31b5810dd4e76bdc6e9dc11ce605c709eed2224ed9df6bb6fabbd50c16f4bad9e6d37a40bc2798d6310fdc1" },
                { "ta", "0634a8143e82bef5c0c24c09865eb4e2f2355a035adff7d13355725c55e772d07fd6d2baa1df2d67f81e74c8846870db82cb0ad72eb1d92de2ea8f5dce9183e3" },
                { "te", "8345eaf57e2851b034c7abf5788b911c39b9eb16f965240ef32e06b4c75411f15d62bf5151f44a2a32879da2c260bdaf3f342cdc2a76914783fca913b7f400f7" },
                { "tg", "bcea4d3b54a8910f5180c9c068cf034458178f1c6ffc3c5d7a5ab470dd02b8c65222b7e3906c2e85163094a4b7f0ab80ac67badf005801ced1ca0a17cafe81b1" },
                { "th", "1a33d200d3047e6448825b2608a4b92ee9e2065b60101686a91b64678356774d2ae75eb8f0bb36ff1f110a18c74046637a57b9b03d206190992d9cd9b3d3eadf" },
                { "tl", "57800bf2762611fbf6faf5a2f031c26eb2ebd7170305f504cb4d315b15ee53493d179a0da422d957f0ae3fea0fd44293a276cbf14d33893b84b6b57cb8a6c864" },
                { "tr", "925d19b7f813244bdf92663cd0509df67a9289846118fda2287a92ab0e45747cd154a61e36db7ed3ab5268abaec4898bc6fe776c90e6ca18810b326cebb2c804" },
                { "trs", "6011b15b8b7ef535bc08b1e0bbbc512e32c20af77ced11cfc8a00e651e5a50e1ce4b4a68da47c43b2163774d53e682f90026453a508211e5c505b313c36c5db2" },
                { "uk", "307ca9e738c1cd19ee0a0f28eeacf594ad59411a192c7264777b410fca2e9d80bff8d41a78a653821c4b5122a59dbb0dadd8e1018098899d7a7c2411ac83baf6" },
                { "ur", "947b7c2b0f4a2f10c37db909c4951f2c9f6de5327bb3018f89a6b18481da9bd7782d0eab231d8429e06cc43b397f083338e2819def6d9bd14af1d0455b64b8e9" },
                { "uz", "66aa9fe7c3f1d960c0721c83271d09c3846e0fe0fb89e1ff88acbd844ad2c08d8af8867baa46b2c284778588548a7f9bef4e826d8072c6535aba4753a152bd55" },
                { "vi", "a73a9337f0c506f99c75cbbe7c7165a99e85d629f1054dc0cc824bd4d6fa0a3d9a024c18aa8954252270c30217d7d2626ee6e1fc27cf24d4bf912c2f0a0f9171" },
                { "xh", "209fd00423ddf70bb6e3d403c768588db1d556fc4729c1f4982a910a4672c65e8d272853ed82fc710c6361b76157265c7fb71bd88b8976a03c5cb53e76197b1c" },
                { "zh-CN", "b32398328e562f26b7efa0c5d96e2b5c5211b0978d61c65c61870241a78e11253ad12e08a2588730c89628eab529cfec28d797a392150482b202cf61d56b20cc" },
                { "zh-TW", "2a60752b0c76edb31003ec4a0f444229316a77cafcd7d60b7a28898cb1ed03e6f2c5efa47f0e4c26a099c826e24545d59313f65336375df7d8dce9caf9f954e1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a6d1211baca84809f48af79cd22910a8def1bf6cf2d170bba2ad8011865754ba33152cb1d843a5f756fea818f724d51b5b90190a3752f202c46d6e6b1edd16a1" },
                { "af", "a1db811f7c6e20c34736f86fd7648ac1cd8eca88a4b947256956742683d1a0f24a756a0b369b2fc851248dd2cd731c0a5517d84f8e71c015adbeb541e7b9abf8" },
                { "an", "38df373f4c154912b90f8a7d9ebade417eb1a933f8dfb10c7aa0fa8ce344e45efb14b1425852b77bc62a034ced1b6621c4368c54403b26999bbfe447dcb00a56" },
                { "ar", "92a6b5fde0a031b21d2bb15a83b87fbd8a52a2ae9fd08a6d439515c23d6672efe6e2d4aa6b011cc03c6e1c6112986a3a6b00ae3fd1aa76a9a2feed4a5f7a7b9f" },
                { "ast", "c02eaf910d06123c6fc4da65935b02fcb44115cd34ab65f5eacdbbac52f116f18b48a896d551ba8ba4d51b525dfdc466444f5561419d537bf0c17841700293da" },
                { "az", "f90ea76c2e11b49b9635d08c544f7de1700127bfce8381a5fcfbb6ba58f1fc7da0ea990931c05cf8afdacd0b420b4802319c18543e8734ce26953b55f0c85cf5" },
                { "be", "9903430b3a1df56a27731131e5c937f3dd35b5d65b98c7b20fb512bec6d0a0110818d48de7150952066995b82c441149cb7dde55543894641e88bb94fd77a454" },
                { "bg", "e62e419b553723c1f928386a79584515b56b97493f48982e41c47e765f1cfb1e57b69e0be14ea0627c753c4846a927e49c56be181ff39b27555a403d3f806fdf" },
                { "bn", "fa6010ee6b7d8c9a6dc7d1cd56e25a4707570949eab9b22f3f00d130ca5ccd20d33cc21fd2ec9bd6f46ddc2220a9956707259da9829f9a94a09074db30de552b" },
                { "br", "ed86cc449d3a93163f5951a23eb7272efa84d3143fcec5bfe490efcdbc0c13f0b69ddbf7fc470896e642ef28a0000275fea87d59ffcff2ae0b2343227a750820" },
                { "bs", "cad00e88fc689b7c55fd3021e0a5dd0ecfa5eafa9e9929c6e74b9ceab635922195ad806b90de9abd83d75b6300d9dd39c86e3a79a08eb623e1c46984b9fd5aa5" },
                { "ca", "a2d5afa402fa1e988720775d4d55be108b991d0745c600672dfd4f07c794d421aef3fde035339cb6879ac4476f8848fc24b4fb7ab01cda3dc4aed33bbc2cdf5c" },
                { "cak", "8d6473239d4c10b94be43c8b58b2984ae5322d356399b5ba2dedf6b29d2591c04162c84586e1d974dc7a489989db9e805ef42a7bd784e5f1626344c710d7a024" },
                { "cs", "780d8b267f525f2fb4d2e57ff28eaa802389044035de26a8071d86ec133a5da80f679eee76ee5afdde93e3ef9bc072c1c5e3af0f10053f05b24917ed398563bf" },
                { "cy", "02edd64ab6bc9ca05af3acd33eef18613d04a8637ad1edd4b70138690d11504e5ad39c96e6d8e853a7976cb816758476493d5ce9429c0e5ec951ef3fc34c89f6" },
                { "da", "0e41089cc319b8e35517258592eeccddf02cfd0d4b0a1d4ef36bbadcd8b4d6472d34c8cc34db107ecef4d4cc686ef5cf9d1e760faab86c10318b34ce08de5ba3" },
                { "de", "205e15692e6df326957b50b7946a2dc6ea5351c86629c38a284bd397d11c65c3fd467f9b4db48dfe80cedaaa2a55e6b8c8aa2e32b3c129d61a8b16575cd6e793" },
                { "dsb", "97770b1b382694bdbe8ef0e312aca8d7fecfbdee46cd91346f615957aec569295ae2994a9dab4b8f3b4c3e523e32a76792216ef05b4fcf9972a8e9d09226ad69" },
                { "el", "e4814c6cf6485550dfa2c1e8357dedb1a86a46e35bee5d8547a13cd457ea3296270a3ee80e143fa58a96f601c18cbd5f9369d0bd7797435b701294d83be3c1ba" },
                { "en-CA", "2b9002a4d8f48dd20bbad1c116fad5266a233a5c9a62b7da32d913dbcea5a2b0621ec6aa8f78c6612cad2fa7a05a88643dd744ba88c60b075e90b5772021e0b8" },
                { "en-GB", "7162bef381433aaea3a587f2017e345a97b4e4f351a0d59cdad38fd96b17ddf80eea0f3953f9478ab041f4060fea370320ce380ef911e14326fbd74bede8b38b" },
                { "en-US", "64ae26c5ee40d7e678b430846b509718173559438ac1eac9de3be157a6bbe252822ad7f72103f4188bbeb9e012c556b8cff27ca71b5f7c0b3eb2c539a5620257" },
                { "eo", "93451a4520c32e3b20452b967ca652299ccccd4e31e4a623a4e59ef489afae33015b05e9336f1f5e479f6f292b6d4884c99cb31897d8fe6b634cf04bf011c5df" },
                { "es-AR", "65672e9747b93453ecefa3a88bca0a4e0e2ddf0b78c367b35e06a3ccde54b2f33d98cbd1e39625f2721f8505687340f97e175217a8cedb262def63b1d71d0673" },
                { "es-CL", "9770ea0caa69ae44937d0304e3d3da74d8c50ed290594b7da3a4bbe63c6a816302d45b99b836b1408d7387e41a60a45a723cbe7c9ab5c5b40f6829e60d84a051" },
                { "es-ES", "c8c49e0be15c50be61d473defce6f8a488531a71d9b22cd1d8d04ccea7d4f457e26c4a639dca49d29bf481b7482993e7a35c7fbda80855b709446a83c3edffd5" },
                { "es-MX", "3d0432ab0fcf112d578c5e315921658e3f0e80b56faacb007fe532bd8a355d8674a785f151936782820b0247d4d5b099ef354baa05a01c9ea68798c824e03054" },
                { "et", "fce41924087be335c94e3316aa446d75dd401dc852c45bda4528e5a1cca4daeeb6897173c7058e96cefe1aac4845064b4cfd50f72f4c953e8e553271f10806ac" },
                { "eu", "c957b5469b5928725522e52085aaadec09240743f87f615e9b8af98863391c2c0e825d0cbf85a3259534c16ffe1c7f01f9ee5cf5040cd20a12060311546e9305" },
                { "fa", "024e4c14c1dd9e5a539a51137a9d00f63c9a9687e1a7ea365336ec8bd220925f0640dfc4a83ef2242d82f1755868daf84771a0b1b9a6d4ef26452ad5d7fea70d" },
                { "ff", "8435e46266bd6135eb1fa8b3888cc7fd2464e1b4b12180756f208bc6cfd0cf6ba7bbd435b170ab88aea2bde8a857f89c5c2c8b8e94f5afb40cec07a915f13474" },
                { "fi", "bd92fc1ee342e296472c9c89ef3e780dd1c317df499dfa6b45ee748225666244578be48a2a1ece396504c9457d5038a96b2f1f87ffe4e164ce83171660dd0747" },
                { "fr", "ffad2a185d3eff67627b007bcb5f7aadc25d285869a0dff3856d0b7479bdc94395177e376a1b0c6e7508caaef92154ca14ac98c17315f9e1e1877efe90c82a9b" },
                { "fur", "bf39726b3ca23f4cd0d61f60ef8c87a145ae64de5f2237bc86d6073365e6dbeb2359e60972344d49902e81bb65004c049fa1d97c7de146012e304267d5f00a62" },
                { "fy-NL", "cc11182a49540bd18b7e1e1e0309f92b70a556b361b2da2d0575c52a16cc51a905f5249311473323b620018f23809e0b442a25c0c91ad10383575ae005cb2f2b" },
                { "ga-IE", "1e8d52834916f64bc7e392db0a0ba6efff4a97fbe5f01f46c61f6feccbdbc68f95efc03d4a4bca090d831be0bee28335867dbe4e1a278464d34e772070b32236" },
                { "gd", "6915d34546cf8f41afe4192b534d382d6ff605e17cea91b7dfa6e15ff5229694810594158ba592605db0e02adb17fe7bf6c50dfbedc57c93509616e3e3d04048" },
                { "gl", "f1679b4450364f2ba871f4dc8b2b29d33aaa9828e9bdaeb1c2f6302b6a02ed29eaf5a86eefdf77d3f4c343f61256d5ce980f07aac3ed95783780fa0366b4652d" },
                { "gn", "51406549538eb982fe59abc2cd0a3e4632fe58e8f8a2356253e390b58cb5195acfe316c5848713fc3393fa7a44c575a53d6914f1812266d65f3a15249b01a608" },
                { "gu-IN", "534a7ecb84787cae8ebe4bc9f44592cbf8e99a8607ee1e8f4913cc80391de499d6518ba82f74f9b293ed1fa64dae7325d245f96cb87e62fa35598cd6214e7a33" },
                { "he", "9687f851e99887cf95c07beb33ec72f80a14b6a5342f04ee26e0b100f6f8c2b20e8d0a957e133f9541cc1a39bab4f786d98ffe2bee6a88ae4af378387a901915" },
                { "hi-IN", "35263f366694849b9a4e241260c2730782a01080895058f3907495a5b9e74add58740cb454371924a4a540d0983fe273ac013edcf43435462b78bfabede841ca" },
                { "hr", "2f16a51c86acecbb6d90a636c9049fa10df32440315973512b3ecb1e4a6665290bf2183f4c0c557e8da5ecfe8ccbc034e26695b54a9221c001f3cf9f4d57998f" },
                { "hsb", "701376855221ce888268487d2c1394ef94aca5f5928df8d9e217897ae8b406a3766b4f68bfaa836d42cf46806d65136f3d067556f11e3f30c9b189f3a1007c0e" },
                { "hu", "f80dee03450501b60757c8ddd9a3b996bedd2cdee4f72520204eddce976f7235c8bc1b3c5d16d6c800e3ca8955939e994fd8557b93e1045d2f3c55f201a70559" },
                { "hy-AM", "334f7dfa0f9b3175e83f6c491fc096d8a533df817e767afc51de7e56d8b96abe39ab48618cf57f75eaa535fa377c9ddeb06abfee121387f967120b3a0ad22251" },
                { "ia", "1eebcfdc972a08cb491896f47cf6d8bb7cb06059e0497a075c3868a645067b2a546d3eaad06b7d010fb735b1a10cef336f431ae218e81de5eb77f9f3f829fabf" },
                { "id", "49981deb4c1edadea405fca30b5d2291b1ccfe89023108887c30d99f65c2893264d163056ec6fb42f43e5321c9566d76ed4d000604227586f62881089c898f8f" },
                { "is", "6f4445e027b205a9a02fc8eb27178ac85e49e143488e10a307dc6016be93d62e2c4a254261f9552481383bf6718894fdc091d0504050d09febf7790ff2080653" },
                { "it", "f2e2a37bc48b1b062e3326cebe42dc81f5227280237affa4191242abe551d205e827f33e88ca1e936e939485e62d497be075096f016496a334769fcc33ee7081" },
                { "ja", "71c4f5d26ec06e3e4b0b8f543888f92bca55c8c1d612731efc5b3f4c8346ff85be884bd6a061a0a685cb151ec3da7cf1f0259ae8b5b85fd6eb44c8bb088d8f86" },
                { "ka", "e5ed4384c93e34dec07bc1a802302bccfdb9c3311c5a7d93b1206a4a89fbcfc87488f2e21a77c3ad08274c2f8d7c2412784a10ca50964ad17073c21bb542ce3f" },
                { "kab", "e229196334eb74ae6ea642ae93ec4e70d39710aaa91666673686b10e156a0d267690d70b08b33320064888f3672fe74c91442ea28cc7a63c5476f6d62867fe34" },
                { "kk", "3766632729130a9c650fe649c5d6dfe9c9f99dd21119e7e5cd36c8329bfcb2978d7e3da3901ce5e981dab026d708695a74cd60c44876a6e88a9ad62d7b4e3306" },
                { "km", "bd97bac2cf2a3101b1a1e21f75cf08e4ac47bc3df1a93e777bec470813dbb62f605f7e5b0efbe8e0edbe254c967a483282c40aef9b2fb9d9e81965a64488b9fa" },
                { "kn", "17c487dfeecec70ae6cf3249c682e6ee9d9794c0a25ca95dd7170a4d3cb90a860c92c26c65dce27228e324e6a283442667a8000aa4ee1c2f80c812a00124b591" },
                { "ko", "f4226693abade5ac94863f11aa530cdc6ea8fea1e240767e61b585fff9aa4f4ee50d31534f0d1e301b359718252cf68221e44e414f86b6910f23a58c3b2b6cd5" },
                { "lij", "5230410bab30c53a1a1b7542c0c2b41930917010d4b5f4a3ce632c1d2c7fe47c862b664fd27135fe39451736927be09767f178c5eb908efbf80c9eaf463addbd" },
                { "lt", "fb5df3e4bc0ecbc7b51461ce08dfca28c4c7312931930dc06090cf3b683634bb29e4bb0f04ba0b627132ecbcb6b32b6306487870d0569b1f751161b92d0c3e4c" },
                { "lv", "213c23eeefb59dc8db0c197f888f43da3186eb59a1ce47926a570c752eddb4ddf40b986ed68f332ec491429c564814333a70883d6e61fea3d74291ef99cfdf85" },
                { "mk", "e0a435b6a2344ed12ba314647aa916798866d17c3b1a1b262ff70d4c6edc49568d35e3b2018ad8a971d3024c496b7046f20be9dbb135f1456b0d092a1bcd6e6d" },
                { "mr", "a4146fd143b3902b2feb90001fa47ba2936f55cd97431d72100ba7c8e8f6fce276a9566a984307dcd58589b2947404d8f2ac9109e4fc032e3260835d5f8a5331" },
                { "ms", "e906c64433bfdb3321c54a2f666d1cb05e28228cc5c987be682c22b545f29eabeab089ffa19dc750128fcbbf2a49b0c4b46a07e023571d5349b1d5cbe1e33e8c" },
                { "my", "d3fc45e35e855e46fa6255c52027ad8fd0604a3a56d9b3b88e0bf0f9d32391a7516eb195e48ff6a73f9661ddbcfd7af2fc14737974e00f545844e14105668dbd" },
                { "nb-NO", "45bf5505ebc4be760a9c5315cd8ed92c19740c4b6c99c7b75197e3cc12a99e751269452611bb7e0b128236168db56ea09fcd2aaccab66857451eb7bccb9f45ec" },
                { "ne-NP", "5b535ecf1a0680b865dc48de3610abee7064b99fa91f182267132d3687b8daf1942bd91e36d11d2ab66f2704a0f4f5f5d16af6b179bccdc22f486678c1aca582" },
                { "nl", "c5c0bd84ed06bdb5b9d5ebda10947316bb050d6e5b1eb480754a4c85cf957c6dab031d0ab710f564a2c7580ec9855c8cd754dff6d1f9701e0cc03d1e917efe59" },
                { "nn-NO", "6068ed7c4b5c21a09f920f4a540f95f4807ad87503befa5d270ea85520e31b7e7aa684c4466c76bf323d8d0540ea5f169291bc9399a596211c15db6d22d7f866" },
                { "oc", "69c0d5c5bc35eb2af79ccf13f8abf12c9f9bcf49eb755aca333bbae4143c68b4ee91c83c1925897da9f34da72e702962ba1ee30c727f101def2b71577df54dcc" },
                { "pa-IN", "26730dc480f41a4ffb89631336aa434035a52198599b6c6726b99db784a0bdefd83d3b0c1e178465908a7428b00b86cbbcd7742d5d9a1a584d0a8fb87a10b6af" },
                { "pl", "a9587a13425d1f03380967539c4b824943042875cc6f185afe92558267c499d26ad0ac7c385e9252531751412cff1925d940bb3f21f2bb99ace2d1a38ee60eed" },
                { "pt-BR", "cb0de5862f9e185e911c9bbfbe9258f0f0629d834365d07f26b20e4fa41e4f7f52abfe12898d6f68b1ee0fe56a939a7e1e892ad9f2203ca1a634f31c7c1e5c6c" },
                { "pt-PT", "8eb32d1e4fc9340bf0ced841c549f10001e104917243e90d6a2355e6faf0b42dfe5a18c9cad80391be8dcc471513485f9e366a1e1e4e29bbd1141f1f6cc0a47f" },
                { "rm", "7ef5e69330e67c0d970c5f09106e6702ac24563cf72cc8510f297ecfd78aba348299ce5a4c337997429a5b966e9e5522c97f1d0e035211495c9f1eedddf0104d" },
                { "ro", "6828e1f119d824387d20ca73ab0f2ac91be761a370b809c4de52c8831b552fbf988d5e4581e1a0ae7bda8df103289ab86cea2c42ef7491cc056a7f00fe510370" },
                { "ru", "01a139cb30ed8dfe2acb22929b92305168e7960d6e53946a2b9e0a7c8db08cecf0b9dd4085d32a3ba14e069b9acf545b1b8ea3cecad25934d1d230b41c76c654" },
                { "sat", "610ed411996bdf07a74bf0b58f92d675bbab64631976d183503b6075b065a8f3ed10cc639e56f27f09ff97df2af24ebc0583f86193a1c46210d0d544cd17f047" },
                { "sc", "15d80d280ef27e989e917c7de751be34ff4cc04402e162cdaec69642e3cbcd2f3fdafd276e69e46df1b6ac19c30cef36c0875878bb483b39556cabca68d2d364" },
                { "sco", "eb8b7ee5758cbf50c767a3e03d0e6ec320f42ba9e39337f99bd0cfaa1802c3f2bff3db822b6adcec676565a018ded685c8e7ef4668e6e2c0cc489c4821c4474d" },
                { "si", "ac8bb1c936dfd5d371acd8c2d14c341369d12724472faf57ded74865037487a154fc3119c2a9bb0b939734afa6a276c229dbf154caeb7c878669ef686e013f40" },
                { "sk", "0b81770d941e54e62781c83fe8c8b10e7a356ba6e90e9d973e1ae318e81efc7231fd8ee773691b33d6104b6c6b3aa65c42e2bfade765a9392873568f60f847c3" },
                { "skr", "30d7b2058e1d49c5b9fc25eaa1447bb6ff61285d3cef679bd682cddb0be2561d05c2cffd919bb7ec66b7f9d284d44f296692d05bef7311f2de2cd49db366bbab" },
                { "sl", "78cce8a54f89515b14d1e4adb8995c4f31cb8ad5dcc1b5641e8ce9ea35b82b4906dabd0806a64223909061098d0ff720c8c8af24979052623ddbf68eda430132" },
                { "son", "efaff7396ec9bea14aed414c03751346e1873755aaf12657f1a341eb460d88e5699d2d312f8c0d190f12c753844693ae6a723f6f00258c232bae035bf4c66bb5" },
                { "sq", "78261e2f30848db1f96e6e903192cec0e3c2b0b7385a75041ec686461210260265aaaa9aa44c71e22ccbc4f4d89e80949d9b58638d214a99b134e3642f4dd971" },
                { "sr", "c088c461b6728e72ab862d40c035e0cbad34bcb758a517244f71cd65849cdbba21ad97d9a2bfe0d935bd1325661eb454b0892a08630544d4682f305f1bb87dd7" },
                { "sv-SE", "cbb600db626bc6124a89a6c6192eb5b2022be213fea4b946fb712bc16b8f026f937c39af638373f813f2b4018d5b7fca4ab11957ba117a0564d90181834b1cf8" },
                { "szl", "186206c2223c6e772d9094ba3e1e2514ef580c1a7535108ea89985d4e84f3b3170d9729b3e95d098bbef0be01685881e1f937370872edd83936e8f506a93d6a7" },
                { "ta", "79b7727c542aae7999e587a052280db4527b01d2571139677ace11a2c7ef305b27efd5b078b81f4c73e78bf07e7d7ea6fe6ef8cc0e8b2da69c3f0edea3a08513" },
                { "te", "9cb39cf917b8ab4ca552c2a872f2997912f7a2c36b50c71e91df3403c302c23b135c72f4ede5468971012044b48233e16c75a4914ce18e2e85f612c743d90ec2" },
                { "tg", "f71dc854b26d16bf8cd9b1c53777802c13d680455dc307702e56c05b0638e59994e1de39270bec0e8f5b63baf71926967ec4229f8d13153bd229d893b6fda345" },
                { "th", "0e9418633b8c66ea084a577d06e341d01b764d8a061256bacce03a0bf2a97715fe2eae718160bd4848080502c1c0b743e4508eab55e2e5d7194d7949d0bdf57b" },
                { "tl", "8ae4e1cfec87ea2f12103d1dd590c10c25f3d0cad7ba722ac1f1be7ec687ed6e111a08cf2c0a62da0f2d42dfb555faab81ad3de3ee00a7c209fd3e7a0f4241ea" },
                { "tr", "89163964aae7e5e77b0a4ebb8179195858ab718a498c52331bc0df6c6b309ae36e57d89fdc47ab686b1a0a0d65d47466e687971a653d99abde4ce760c09c3be6" },
                { "trs", "a3018eb24c79c43380908e0fc1e90bfc9d03bc77516406ecb4d385edcaf5eeed8d691fb2b590353eabf164f0e1f4e59cb350a0e232c1a6cd48b89a36de7bb445" },
                { "uk", "08841ed69c7323decf226c4640fdc129d1a25daf863ceabe22b5e929f835606ead3998431d419d666a5f1d5a7c04be4bef09f766d7a8c1dee78179a9285bd2d8" },
                { "ur", "97f45a22cee617cc5b979bd25d5f5416997587f8176f7dce61369b4c16e5242db03c634cf47b7d48123c46d9d39298dcd12f101205e3ec6b3d49d1b5029c6b71" },
                { "uz", "5fb7b42a994856c499151c15283aac0d7212e289e0bac4360e2194070079e57d6a88282d4f4cbd9d79f0f370f1d10022af77a8ac3e0e76617348422ac6c773ec" },
                { "vi", "f46f7345ff8cd88f037e47ee6fed29f4769ce2005d54cb395a2b9796b7ce65e4136f57146378df706c11282fd9096f900de9f6477647bf76228617914fc23fa0" },
                { "xh", "4793d3990b6aa577dbf907141d46da4e7992b359e5771ddf9faf2596015589db3c5e1d05e502271fad35515f1fc21e1e5d3e6e67468921806844251b754f6d2a" },
                { "zh-CN", "f0e24fdccb80dbb9532246d80a3228138d3ef34daeb88dc65f02ffba03f01941a988e9a858a9f8a33fb7f79f9273ef3bdd3f4de6739753049d39d8f15e1e1cf7" },
                { "zh-TW", "8ad8d9b13399f355ed3dbc2688540d35cd699382d674c6d31b5bde070c523031851f274eeb356e0f0ac6db51c7e435515fe25a3eaea65aac54190a3601ac370e" }
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
