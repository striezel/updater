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
        private const string currentVersion = "153.0b4";


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
            // https://ftp.mozilla.org/pub/devedition/releases/153.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dd9ae3a1eac0f71ebb054c265efc0e2d0aff450f64e954606e07c8046c409667d4009db890a70390acd102a14fca7dd5a14245cf81c99c18a618f22aa733cf7a" },
                { "af", "3385d567a9219c32ae292ac1ae6d0b350b3ca402c4ab29f604406189409aacd5e1677ae58320602081151bea4612e37bf032a8393641fc328af15c5b125893a8" },
                { "an", "053a52d8567fa4c74d256368ea411a132deb9e4e4579dd02b20cfdd8b563eada742135c9a2301d884bf2c3f16c57aeb960dd39025bab5c464a886b6f5018cfbf" },
                { "ar", "59cff12d4bb6598dadbbdbd337ecd049270dc1b3dd24addf85cc0eeae0d27d04a5d6fe3e0381856fb998016e449178d9a4da42162004eea9f3d0f0472afc22e5" },
                { "ast", "e0322779a7b0f965bec9a81bdc468fe8327e8abfe4de2f197be38a4e3b1dc4994f1ef169aba9318eb35768a8c35e832608852500a72346154c14d01ebc4125bc" },
                { "az", "756c7289aa1b2c5c75a7dd18c8fc65755bf694f3253b353bcefb17c9532eeb63c7abd024bac32cb0f8d5aed6d479143f510e5f5903e3c9f7886a8f61dc4e6710" },
                { "be", "2546c2b846cdcdaf6d6a7d969c46e487bfeaa450345edb21640c8d5648ea4660852b54bae2e9c6d201e5629b81860118c5c5d14f0d2e76c3bf5e386a666e39c8" },
                { "bg", "c38da0909bd67823e39f86500372a1961b920ac60f32f0ab7701c36741c1a2dfb925b3da16b42557d8fdd1df7bb81b52c77da0471d4802ff1c3c6bf0b14a7e74" },
                { "bn", "68f7e05b858ef2ca0e0183ccaf8e04f805337621ca6ac1770f937b1297f92f988c64b41f73be38cb5d6d4120310a426b1233635ee07aa9287999117082628acc" },
                { "br", "d8b9990d00fdb031a269d5d5df32013815d3c26be52ae6c7b506eb680b41d35393c841a77f90611a718c38f66d8644ffb22cfba1a1e45ba74d46dbbffa212784" },
                { "bs", "46e388b0609b0e84091170f0c4d61fc6e38d2725e67dda03c8833690d2c7be6aa4fb52e6817d2fa8ec3beb6b4b68cebef0a2dae94b72d962e2ae2c43e3926606" },
                { "ca", "a3228e6ba5595e80070509b964ecca3fbfed867d29be7e0a35f56ff89b1e19b039d2107d33deafd2e35c5dae82ce4c9e5b5663d6e42102449804b00ba1b48bab" },
                { "cak", "d5f8df1965fc375d90253a14c07e378a45d1cd42bc98dde265a929ee39d74586ac7e02fb26fc26463b6575320b6a049fe52fd9c970c26f42384cdeb48130aafd" },
                { "cs", "f7c00cc6bc44e6d3ae8ad4e89b442b297347f1a780d640bc9e92aaa13ae6fb48b236da1f9cb12fdb2d2b7728e7469f05158a8eb76e35d61d14ef8bfc046a205c" },
                { "cy", "556bec0c099be26733a2c9fd809e49ce9e62230a9f655fa83c6742c7583d6af10e7ff5abe972ec287ba7767aa9d2b5a6091b72130894c88a7c3a4d6a0d6a4f10" },
                { "da", "49638b07d6d1c94a31dace74761ffe664661aec8c982cbfba5ef5844b51d27f020ecd08a6bc5e0c924c5944f88886977e71cdeffc5f3861af2ed09a9525991d6" },
                { "de", "396c6a65f6e1be2eeb07b7ee3256c2bde226322ed2364e4ab3772b2614871cf3005aa45486340fd21242dd0b0697e171ea9b21b5b1efde3a85be428525cf8b21" },
                { "dsb", "a56393871ddfedbc9551b812dfb2a0450a87bdb8811fbe0f6e90b05958c7c3c5cf537e1fd05c67267f48d6673f0a667ed0e99ae5c22c9ba9bbed5e0e712ce945" },
                { "el", "cc8ef33283474e77a851c484c60fd72578558233a87a35b0e7727f988ca284175fd04c3321bc79e8f8e880a370574b472c10564d484f7edf8712e186ab484bc8" },
                { "en-CA", "17f9512378980179c01b8fccd8154da14fca6036841cf19dc3901dc059a695b09da69fe027ed32488d7c4968675a993c0350f58cf3e5adbc527937a6dda599a2" },
                { "en-GB", "5f3aa0518cce48904ccfd8eb2bf0a966a0ea98efe19e4b8f4ba5c6850a46af43a46fe70b92648c07036d7f0843aa7c90d3919f53ae8b312c6844bfb7de2e7ef3" },
                { "en-US", "0f86f5f8256b65928ea3d02dc6ac08c2b72fcde7162de83d5f2cdb0d018840075c0466718835cdf2f44d004994beabb24317fa2835de52f9a682ec98392e3271" },
                { "eo", "57aab28d46468bf8770d9a1c4c1a01c1559148e03237f5c1f723dabd14dc4b715c0f3c70e08c0b5e44b47419edb456f85d1ea0df15001f7911ce2df1ec496c40" },
                { "es-AR", "0507af429aaa8a91aafbc52ee6301f91fb4175d7c203f3a7545db51e16fb7bebd41de67fa6ad46bd76113882031e5241c1dc916a0e161033e820f3b640ce6539" },
                { "es-CL", "7969b36441ddea1c69e3ffba54f3791de487704a5bf94a443da795c8687b92ae9d4df27ecb63ee07c531493c47dfae6963026550233037f6bda0c07e59e42f6a" },
                { "es-ES", "907deb43d93b75916aae3b348316da67a51994a02545442b0a7d7c5b2f6477c39f11b19984f0aa57ed0e5177f937ef25c86ae39d0f0cefc2781b484d58700f9b" },
                { "es-MX", "4aae1731ec57ac00cc9d89d227dd0d08a517d5400d83804a9273a34997f2d1ec1c7c372fd04c87a9a0a562e5daae80c4527a9a28af5df1a55d66b13717651150" },
                { "et", "5a4bc40590ccc48d972bf9bca821d7ea06f084e7c6688e5c93e826d3ac013946a55a9e52924158f4f98ca9ca046da65c28217edc6dd649e3b9f41db3dc2327b4" },
                { "eu", "052274a55c224ecb9cbce5a863daeea256756c62ce47223417160f9876a6d62b43abf7565e1c3da5198eb0a690f59e76d9ef1fd3266431ab25755e1f72c9bc7c" },
                { "fa", "a51e8c64cd3c259c6652ab0c3c059f3c9e3fc65756b8a2b95af7b863db8be4e1f49173594a6fa42f64c8050098dac654607ebd38c22b670230f286140d5d75b4" },
                { "ff", "ea8b09eebac5f01322d544e836ab614dc8a59905d44d28fa92770b521f5a62dd5a93e34517eaa0b2c4737c403472d67812976b7251d9aee541adb112db6a7854" },
                { "fi", "0cef8375d905a387780c84cc8fe16794d488ca1b5075e1ba243d4fe3a3e036a04515dc2620b37b0af6e139edda8128c708cac3802b36547d4e8fad3ec7dd2f51" },
                { "fr", "bb48a7332a716e548e69750240b23ff796280751dccd2e11c11f871ba0d8bdfdb5ec3e209b400c415a110df236e8934ba5559d6d35b40d50c4d357b62305a7f2" },
                { "fur", "d304561a686024a0f8546ff28d9e3cb085f3b7346ed1284da85dacfeb2161ae9106547b4faf04e439262105f8a4558eff4f1928d678c7a314ec93a8b6040c89f" },
                { "fy-NL", "76495da1a7b2356b772018e36c088a6baf492a75c312f4acfc6dccd022c006638f3664de637264a94351ca5c5a5b9580fe31d8c1c6717856c1fb5c545bd7622b" },
                { "ga-IE", "75880aa93475ca4ca4ae6bee65b7a69545946b4faa986c2e28da1695182cd287053e06ac429b1ee64295041bd71113359777e2e4ebb8fca3c80e57b147ac8691" },
                { "gd", "68c6e04cfeb07ba35b7e571ea40efe5c6cc7b82272de226eea37e5603509aeee7325fb9b03f5c006446e033458b988adc1a9cd2388b758da7b90ba614c1a3688" },
                { "gl", "4c60663479921cab16ec8cbe51e54b14ffc905b2e177e1d2e4cc1df487f000559128edb918d845306fe9645953470932d58d50ba914a6410dd9b6dbacf915890" },
                { "gn", "9e907c307e6c836bbea4316ea365256d9608b53f59664056c26d09aaf65a1a7961961871d52a19d20a7f3f0de5e9481a809c9dfe0f6e9bf2159637ae9a33c404" },
                { "gu-IN", "eefcf61947ba6821595c43648f35c0fc462f3313210f59ee8cf41750a239fec44710897ae96ff7a74b52726e2f3eb2133f8d5b734e94f76904b322f127c0f5fc" },
                { "he", "f927da0c463141fccb9f58e5acb82b26302f5c92279bc65c043153bb8177a9383c59e7c448dc251ae2245a95c147040f523bd54351c9164ddeecd1fcfecd1157" },
                { "hi-IN", "0c599987c1c9e9dd926e0bb38ff762d56b664bb6c3bd231c1fcd850aac773d92ff8d2973a45831ffc408b03665b391d3ecab1b8dd3926f2ed4108b97e3cb06ce" },
                { "hr", "8f2a93408c20662b11b8f4110547b411ee61bb548be945e6115c10107a7d245347f2ad80f059a4adbb73f9c16d5b423c1732c9c329cae5ba78edde5a74115dfd" },
                { "hsb", "8f2698d01648a6a17f3240d62e15b02c3e150590a4d949f3a38d985e2e35a4752cb82755c1570370d5a621580495162663fe8fffcdaf3ffaa16c78299322b69b" },
                { "hu", "794b136901ab6342cb96fe9bd8a7665c1808e465022ab5438c49f0e2c0107f1ba07fddf94b98b8df2e6e9a43ac066045212d5b16ab49e55d3b1829cc2d121c80" },
                { "hy-AM", "58d975d880850cfbb70a771783fa3207babe05189d00ee6bedc63a3a556e11dc5d0002bd492868e3bf9d7256798a2fa50dcaf30a0f9accab71787696d007df6c" },
                { "ia", "c48767d12ffa5e8ae05b1c4cf56297b4de4f84f67ddb69557b1a064f4050e8cf8dff2408418e4df4c1c9dfca216b9183f2ff2ffcc4674831125bd5e9138f5f44" },
                { "id", "cbb17706931f487ce30f20a4fd6cd3ebe4ce3f7dedcbf0d5dabc855df8c72d9eccbb831895394651911a63174672afcef4bd3e49dfeeb9a21c41451dad6e9ce1" },
                { "is", "b7e3f3b348a678cf521ad564dc292d3b67d3176638992fb98f3b799e8adb0c0a3162c7e41aa75923091567948e50e69af0052d3ef0ef1505248d2432002969ca" },
                { "it", "a61cdb99822eb523eea83256a2d1a1587d7b4faad0f5f0a94bf2ec9825e3fcb8b36d01fb25f7dd24357e27ace105897331c868edbe9b0660773e36af1413162f" },
                { "ja", "8ae3b29346a8a089e437cbc4402094a6a6a9abb667434b2fd0ac48c9a801ed064e1d784c965cde73d9a45b35467094d511a4a422b53b02e7396676edfaad31b0" },
                { "ka", "b8dd6d6138360369e88ac495bd50174a197ecc56b3e422b2605001000a97786cc37ea899efb729c168e80e13b5e7ba138e1fcab0e17ac9cfe4dfbf59fdb02277" },
                { "kab", "f970961c13df0a9e12bed8577f153c7fd67ccbb96449757853940dd7654423a3333ee2da1937b3e66e494bf291e67545a2bf142ada82d3f0e6b15de08f5f9450" },
                { "kk", "a1c4df1fd906f300a44b2fc0584efe453c8de07b26595552d11e1096dd9b591b10f2dde750775ca1442ae0b9f75d74190cafb4677fb28d7e74326865a1ffabe6" },
                { "km", "4345708794b09c419b2989fcb0b672645cb4c4d68db66a5f1f2cf43e15c3be3dbbf01e7bddabc8c507aad2bc196439442b32cebc2e7881bb459f1454b6fce494" },
                { "kn", "ffd3cfa0f05a915eecf41b597f934cc3842e227e8113b15053e6c248cbb20a229620e66ba28d534e69dea8b6e5b5736b18055aa59039fcd8993e030ed0332c5c" },
                { "ko", "009697533444f8f9ef1a1342f8915be17839e8564590fc11b2aac35f0237b3a6023ae26d1f7e7b4eb10f69fe31cd236351bf95890814428b1646ac7e62ead672" },
                { "lij", "996561da5b4dd531fa82b3e19c880bfcfc7784ca8b97f3b2c3aeb940ff6b6e985887901d61c5e7bbe7bdd66eb56b03cad8acd577cdf58707f7e20aa2afd80d78" },
                { "lt", "005014668663380a2bca05d9630c8d7ef5773c16091113f7a61de7ab7b1cc5048b56ce2535ec58882209649956280dc7cc6a9f11fa1556ffb97b634fb1e2278d" },
                { "lv", "1eb0aa271e3254b823085fde7395dab57af8b3a89af34ce18224546ec7b828c26f5124d7ae449b560698f1556189b0f84a5321d5e19df498f2d25f7d7cbd9c40" },
                { "mk", "9e5786bda315ad55a2d4cd4dbf9b4a953507728a0a0c669a0adf528ce1f2a318bb6c8f47be72842aab264cb3465222724416dd700fcde76f88d2916454d462a3" },
                { "mr", "5cec256af6c0a13a56dbf71f37b6e3bc596b5210ca602d722edfbca88bb126808c71588bf70364e1d3febda3b6a94be1cbcabadef056792d979bc3047c94ede5" },
                { "ms", "6c9cd5bdfb1334616ca20cfd6efbad8c9b45a7726754bb6f4c7efba4cf3e09e4f01809428b73e0df91891bb464ce0bb1c001a4be3acb134c4e1b2874c9488a76" },
                { "my", "8a0c94a5b059a7d1b9a8bf14d86291623a5a2d6ab1dbddbd31bd3f98894a6fab98ba06b54060e5ce0f241c521b80d76fd651736a9b2f917355b10c80ffb4637d" },
                { "nb-NO", "f664ab5b365f93c20a1559b56960af076acd78b4e18cd4fe102a92812415904988f595a1deb5a712918d2de423095d28446f2ccd444199f8db88424fd877b104" },
                { "ne-NP", "2db5b0114dd6e0f1f3a657f72a5f2ee1bdcf720a37b2135c7738e2e2d351d872c9a791dd2e32fcc5a01d45a569bcc57afb3b0bcf455437e29582dc1ee7142060" },
                { "nl", "a037f4707444cabc1e42d957382e1b9d32f332451e4e061d9e55d09074c6786d78eefad8ca24dfd27a7c4daf6b4559726d3743bf23fd3a26f7be17622802d276" },
                { "nn-NO", "fc743ff5d68f85c45a0481a1dadbf932bce6f73b7e311f2bdfa8af29abf5e7d2f093f0b167f17a573b4d4659b1bbcde2bb938326305bf0640a02389f773eccac" },
                { "oc", "9ddf03ebb91123bad8e1c4b8ba1829ccb48c6b5f2478af978f66db348fcde619b683d66851c8dd705b002f22713c6f6f019e51cf626c1d3244d1da5903363ef6" },
                { "pa-IN", "25b2d5b36132c85e022a38bd82fad8ec4996be5a523142bced3b4d57e52dc7631446c9daaaa648c3ad013ddaeba81b15bc8e87438d93b64a60afb64a3ed21876" },
                { "pl", "aca96d42387c7beb1fb2445596eb03f5423a0f12119e14f01c2dceb3f70988666e617b17cd16fd0ac4c1a9bc8407aba24b35b85ba7e467b5e82d7151aac2766d" },
                { "pt-BR", "c33c3134dce637321242ff9ec9a0e5a788bb426db52d27daaef93886e5676b939fcec8e505d18d4a42c8c96adb505905d5371d432ab08f263e5671fcdc1dc2bc" },
                { "pt-PT", "68795b8bfcb6490f22705985bc58b570e1f7b5818f53fa46fe9157ecd7fb5a954d29188b413b0ee74f92a852c2298367feaa8bb736b92a862619dabe21c228dc" },
                { "rm", "aecd0428d882e742441581a04f6a8fd790b6544e7529333903b21d2f033422fb008f72747086fa3f0902a0bbe624707421e6e87b06646a2be0531f0aae1e9a21" },
                { "ro", "bdb50d776c1b1eea9edccf719df987634f9c22f843703b530cb54e627b02b0c64aa26a140872b7bbcacecd9570323859e4e75fad3c538a3d298c6ee86031e797" },
                { "ru", "e3868cc859617f03f047e1ee29f66d170d4a576b09eab81a422ca83e1095d44993d89bbe3f05b629aa9d100f350cffaf16e57f66c54f96809d6cc933453df4a3" },
                { "sat", "1f8432407d30ef6c70e336ae5a6f8eb3cffa9ec8421aa2481b0fa002a8ecec9ac9708885a73e2e50bbcae8bd4a6f69867d51ea84286820af2cf1af0c0411df4e" },
                { "sc", "0ae6435c5c72aa46181a6a17be71ba2710e6a3731851cc6a50681c1f74fa8317491b7a7fa584eb754c5e2de5fbbca9ef595e50687e53b7b0581eea1daf6f26c3" },
                { "sco", "c74a306fde40ee76063add0e51d3a14477a0e839d7fd606261f36ebe780857ff783919b03a6921e5470762171f3d2140fca15a6c63db3c4ecd06fe81b9ab33c2" },
                { "si", "c240ed1228f6c5a93f3d31f6d63bd84ae91cb711b944143b0ca464e39f0fc042dce3e14759193150c31f412469425ece499f32e473a710aa2a1773c12aa899c2" },
                { "sk", "f8b10b0670883a0a998c7cacb71777319297e1e56d8661c1128fdea136ed04010ee27b6600e28fbdcb1843770e9fbd8de9a909bf9058e2d6ff1a9c81fb079730" },
                { "skr", "1295fe2c7a55cd92e2c1409909aa4b96f5c993c024ed66a7b2035f1fc55d9cbb8fd29f456f5edab1b435212e62ade4b012de395f480f277bfdd9d0fa59877ecb" },
                { "sl", "9edc00e3bce6b5699b9b85bd5093ee83bc7047c0fddc8f226c6af7647f2ac805c76a8dd2e089489b1ff71aec1705acb13cec96b1ae0178bdf3925e4b14702d52" },
                { "son", "b3e17ab9460407205fc3d9cd099cfbacbb129a6fd31f1b907b4af13867feb44eed85d4ad7b01a12f874f543f13f7602dcd1fa816658453e73a48b45e422d60cd" },
                { "sq", "575064094dfb681134f631d6ac009179fc08c51a9914302c74ca0dc056ca878ea7cefabfc37749fc260d484b1d26e172c82ce7d3b2db3207ef7491d9da254313" },
                { "sr", "43429816c9918dff23721ecf84b2bfff5241fe8e2543e42ee9459a391a49e3d16f6d183db9286b72ad1348b9e815ab5936c0596ef7f8d98b572c5aa87f859a02" },
                { "sv-SE", "614e5cc384a5e52180824b0e5d87c05d444673b18ac8e188b75eb15ca38c3c07e676a0955023a8365731a53151fc6bfb7b613e7c0212d098956daf41d6f5bf8a" },
                { "szl", "94c9d504d2f1e9cd2c2bf1f6e05b427601f2fb1214941f9796f952f7794b5f6c67b780cde1b918b58e0dbb06062424a971c8e23a568c77aa710470ba091cb2ec" },
                { "ta", "f17266bac9d716225a79514d44b8ee8776194f69eb7900ded58234cd8ab3fd537e5abaa6bde8532bcbc0846e160c471c7292d29ea47307722c3b2f737d271276" },
                { "te", "3d118d30926d5bae2400aeae85db7694ccd36140ee5cb24fcd122650576d14621cec7e4eef5b680412cfd93ad5724ce718ac0149378f53f8ca10801bbc905c92" },
                { "tg", "9264381da47a9a128a9a86b6c5fb25e75ba8621bb992949c91f2f4dced68b32772a5429e91174b6a5151ee45f7224071f87f93a8297df7d0d9406a1cafc0e0fd" },
                { "th", "15eb31c94df68bca2ac7415d133b2d3e58f91b22a20a4a50fbaa39561fd65a66d9345e1df77e121032332a62b9e5e3fa6c5a6eaec92508d5a03a62c5fc1ba1eb" },
                { "tl", "00a5303070f967895a08c5f793b2fa567d4368640f535257db103f2aafacb71bb530a39906dffc9e754748d4592ce87e463a43ea1115c1fc461451c8b9fc281f" },
                { "tr", "40028cbcd3a886c675854d1995c435836fb006ddf30ab072a346fc94c618edc10b0abf69fbcd7af0eacd00cf8c1497482b6da61453cf7df8bce41612bd0afa2f" },
                { "trs", "66e7418ab560469efd1757a5fe644f2140511b894ba0ccca111fae418e9e2ecf421ebf9581b9d4dcf4df51795f16f3165c555e4602a26906ea96a15210996c8e" },
                { "uk", "c5343d176910ffef7759a8ac25b423f3bc6ec2e66725b613fd199949404b68bab20eeeaff0ee2402450f0de774f0807f5d81aa62266a9b453d9432531eee3134" },
                { "ur", "7d0541c16d4752c6fd91055ceb014ed04a04388eb7c2c076e4fbfa4f7de4978d51663c6d58be0c27f0c2a0dd6fad93c6b4076de0436fda7dc0a4c174aec4c7df" },
                { "uz", "1f5487227c793fe638471ab347f1750c1d8414017b734f858d8e82c9b78d4aaac8413b9a23910788d5b8d866e73bd59857e9a305d78634fcbdecf9fa56e660b4" },
                { "vi", "321251f20492362b585018ab3b147955936269a4a63bc758a7602e47d1f86ae0c3ce8280bb2d7484088ede005d5c90504951bb4324e3dfed297b3f8650ef52f6" },
                { "xh", "8442df8099550ccc79f3d085f1bfdcd4005ac68fa598fe38b2017adc7f39328f1f2a775ff16b5eab2f2164b9947643dbb3545f8c5fca0874a46ca4295ff29225" },
                { "zh-CN", "90f1e260c9af3c34efcee638c8aad095d341debc025730f6baeb6df272c7d665bf5b1f5d208b83824907e6f6156577207233ed6a76e216ed2adf44df84c92469" },
                { "zh-TW", "a8fc6d3bb4623ac91e70b7e5a0caf82fabf09953b71c1dab2eeb43c800618cde0632b2f77fcd6e03ad9a9106ae7e2c6c4c43ead3575a048feadf65c844313bc7" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/153.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "da1d329319b3d93fa4ece8ddbc71c5b54fd558c0365738b3ecdad6a2937122ca0bfb108829816f6c3a85eebf2edac02a6359dd2ed4f823ce43ad0e9d0e41a4b3" },
                { "af", "e970e4bc6fe2e37dfcac65186fb0f87851c40a1e824965db6db5930a890bbb83e763b5f130192457714d17cfc14a11e6e15c7207a3f917145ad08af4f3dedca8" },
                { "an", "236c8bf9c367ebe048043ce8a3f5316524d5e095bca9ceebd38dae7d997039a8d72ee99bbb15cce2f443c65a8213928846cc6c251d1ff4e831e14dbebb72f859" },
                { "ar", "6323d21d012d83eab23701f8852022915c752dca32bc77ec43ae00d1dfa59cc0facaa5137ebb3555784aac457c666cf37a5840427a3a94c55daeb936a32aeaac" },
                { "ast", "522341ca2195946c3108b2ef1ee5c464814f1e8c7ebf2e17829a54fe9b9eafd041308d788bfd7d87b5afd5fd5a5a57149e6b2a10d9f79c3fb9c8520b2b1bf351" },
                { "az", "611200ee70bfaf769bc0c90dbb8183c7a8acbb54d6578508d7af43e9399f4048e42a93e721fedbd3325a4863513d2a6d699b4d26a075e1d848a0f4eb529d6bda" },
                { "be", "f9df161531b8e28c66c0c67449f27185f2b0b01eeb26c71e29e72f55816f4a3553e8f7284356b60add3a264939e81a6500186fb8c8d1cad6432df08bcb91b844" },
                { "bg", "7c1361300691d12dc31d15c15ce273ca4dd3468a121205258ed26ea34fcbaf87476e13e1901a8efc7d467597c990f582d0bba696461fe01fca443689dfb7c176" },
                { "bn", "5b877678e946f41c0e70990d89a496312b3c0a99a5169a03a76d9a0ba9c9d11d1d3d741f373924a840df6d2a5d1ddf4eb006ec1b6e56a2c7c6f23fbead7a3cf5" },
                { "br", "f885968fe43a940551eb95fe75d8515a6e93a0ab97753ad3e745cdf40661c3f90b694102699ae2ecd60b9e3a6b410e4360af1e947deac79f5c54c7e0ada81c52" },
                { "bs", "0c4a9b0e3a2338f364de89d479994d018e5b6fc7cdca362b351a0cc6e5b9154d921f87dbfe4d750a8eb1a7259baff6784afc7c7106ae6bb3e93052aa41533f6d" },
                { "ca", "8b9e4737bdfb7dfe2e93a1a17d7c40b5605b5c707646404e1f28c2d549f034d2ced8b82caecdecc757a33a85ac3575c47e0f88e325e13e7905a4b10a18735d0b" },
                { "cak", "1542b490cd9dca2e51e2b093e895aa13688085ed85f434ce923c2a959ab0a9b5c97e5a1870b7dfd7f195d09e92c911f7e0e9cca6e6271e9dcd5f9999b2605865" },
                { "cs", "5c3e3aab948720d632c6430ceeb9630b8fd290fe25b9e084f2602d42d3dd1ce45b1bd680e8ec8cfe415a44768da15b9720d80c356c014ae892692c69963b1d21" },
                { "cy", "293fb7a41370a8320e312f6f1ee8097e8914eb50ebbe0311a478d2d57d6a8acbd4f441517fc8e5794ff15743f55963740223c3b1a57e38cdc54583a514938eff" },
                { "da", "19bace2ff9473f6c18d2a845009340c9706fe07083cdef3fe6ebb1b46cd0421688d3cc8868bca95e4c657fc39acb5f1c744fc3961c4e96d9d72289a67e9f4a52" },
                { "de", "98c338978ba2a5b782354a64cabe8af712b8f14ad56a0f4974da72fe0c3947d8bf1fd5822321721df3033985190b2365e8a5ac6dde7256b45dd8899cf438eac9" },
                { "dsb", "95e9412f9af374a9507fb62e311e530c012634f7fa1426d0a0336c56ffc1f5393284ee12733c751d51edf623a04cafa90f3e1eeb298d22659cff13ed3f0671e1" },
                { "el", "79266a462d1537cdc166ee29777e855e3df74c0d45adf071f2ea75f790167dc3171fc8e9066912268c14b0246cc37bc3f9093fcbac5f356f86a9d5850beeebbd" },
                { "en-CA", "34901f546313e6a6570a571d99471cc01557f62208a5fd37391b5129080c09c1bb982127a1c1de2614e897bb94ce994a4895a709641dea7be3b888c77ad919df" },
                { "en-GB", "e3462c77d8d95fe0979063ca4af0484ecd747087fb099442bffd0d0fd4ce5d061f16d1d53ef28bc6084d5ec5cd3c2b6a40d4fc1ebaa2ec5e81b57c0afb943dc5" },
                { "en-US", "26cc4ab9f5f5cd09c3ad0672cd9f37947a5835a9967db54255436a60bb3a1a443a2b4c8b8b16b7ed74a65df0d5330c7e39782a83cdb11b9491ad1fb91e2950c4" },
                { "eo", "0600e7d6ef662ae48b7916a2f3ac5ad855044e9c9e604427865096768f0264ff96a184d12d6ff39592932e40ff0250de362b6878b3e0dd3b276c733c115b2739" },
                { "es-AR", "5154214418f436b7835d0ee74c66c439c8ef83706ab70aa2e4a26dcffb3b6bc0150c8b35c85d3b71535c6660ba91afcb123166478d177054887bdc0a73dda968" },
                { "es-CL", "433584807a979d6633bfce27c72cee37e2d905ebd9b2b16410738a7067396ffc31e4e032f993dc8549e5756a2e7d296a171dab11999159bdbe9e465bf66221dd" },
                { "es-ES", "14cc7ce154f868bc93b66eeb3227867f4512dacd10762d46dca968bef184684f6e512a23b7584c5d5b49567b8fd67f3131badfd518eb82fca9e822a1944268dd" },
                { "es-MX", "da595567b9456c890b45e03e9334d9d39d2deea1fccf7d9ffb418d5c741a1856f46a9a47c49a71175f69fed7c94cb8e72914965470c3a1c8b251297813d1f3c6" },
                { "et", "2e8d96497a5e7044bee02e0566ab4e46bb7647204083bee08bafab281f614544c81da1e326cdbb9b15db3f14ac0a564ecea8d6981a2a91794939ea1978a08d0c" },
                { "eu", "da7cdfa471f9ceb4a239eada460e2a16a45f1660d2c0dfcb2522c5379189e7b97f4f7322ee0ced85de0c0bae5be18fb65b89a078db11d114aa815b5d7770cb39" },
                { "fa", "36111d1aad787c38217d719a8f62b22948dacea1564b98b30764c08817100a08ccca8c97a3a503d97c7c34f325bdd6fb1c740de1d6bca09fcff4e54fd332fc16" },
                { "ff", "efa9b4c058c69c0babe0c13ad15ee1ff8881cf1298bb70419dde6899bb8b37faca5ddbe77a691f9190187371e0033c53d7d04da0caa66734c6ea2f9af3246b0b" },
                { "fi", "0e603b573fdaaa1cd13683f26ddcc2c95f56038929b16ed46068cc6c4c7fc8a5192f3d8bf38083097da0b33b5db998a2bf999e0e1ffc6876c360c99fd3e9a130" },
                { "fr", "f5fc62713be548029d2fb4b00ec15093b83da27a32ee23c6e33e7523158987b15fe16698203bfa0902282245c4118c5715e2fd01cb41db361ec5b2f87161827d" },
                { "fur", "c5d73d79524411b8cd4b45e1849052e64f08f74c7a4f2a93df48cb1737a983c0140bcba881eb94eccb29c043060e77c7255f548ffb247c12adf51823e47bb74a" },
                { "fy-NL", "fc517929148e9d56550ae042c87e11b8d35a7905832ebe14eec88399c6c1273a0ebec3340b377a62a84a7c2edab8b6afa30d270b4acf7c735e93355390f51f64" },
                { "ga-IE", "c3f3929b4b66fb1ca64dc90e1340db90c1f670693ff8fa15e170b8968206019ac459710baa5061ce082046a6f0323432e3ebb85f56097c9015794bc07bd0b70a" },
                { "gd", "92c02fd97867df3413a7a2d72df5859ee5c69b1e44dd18b61990121efa06922c55986022b1ff38632e6175bc1f5f86c30fa2d0c67d06fc5a3361aecc008b1ae0" },
                { "gl", "ab99438f94fc84112c7c5cd66cbea81df690e339957c050a035d2897b1b64462a00432074dd7df8f06b85ae3673cd5082a560a09d69898d8166a680e1d9bc1e9" },
                { "gn", "28226aa58253e6e6e7f0f83282dea053ab59efee770c0ade84f7173bfbbecb71e0cd0084549237792b25cd0172b661c935f8bb88aa3febee69cc2f278cf35a75" },
                { "gu-IN", "2a0ad38a8782f9361f6e389cf94cd3d3133fe314c6159b01427d2a281bcb575665ee2f97b5d7400f32071a7d5c2c11add7a9f652757fc25451107fd45bdb958b" },
                { "he", "51dd996aacc253c45f6894a03f52f688ee755958b0221e7dc0554126e60800e38fb0e31536e89e85c3a884c333dc88bc5439ab07732608eade00d3aedfc92cc9" },
                { "hi-IN", "d1f28980a51f03c582490b7ac75e1f402959b2c2e75e038c7b39175c78c89eda1f2e776f4c1bb2aed385ac1bbfd996eb0536eb99adce24f18e9344eadfde78c6" },
                { "hr", "4404ec04f110d4493f7d0f20781ceb84562ae099643af554821358debd6a0267d1e27bbd415b8167225c2810948d90c6ac51d146a2891fd039b2ce56f14c7f56" },
                { "hsb", "0f69c566e78ab425c8fc4f9468f570379a0abbb1343d908bdaf3d3198562aaeaf6cd6d7b335c614deeb815add2a86ec8430388c449b0b693d9a7197a303eec17" },
                { "hu", "4733f12c477ea43de878a8a05d8436184addb69bbc0d5d2fd2ff7868589515fb53102f6612ba7e8fb09e8ed6cf6f4eddaa60f4f585042ecff1e6d5b57358e4b5" },
                { "hy-AM", "4ecb293129a236fc45ee6a736485fc8ec6b951b0a0f669637a39ba6209c73690a27f4f38a81f18ccf0d8de767512c857d73fde059729f20345f15da9cac52306" },
                { "ia", "30c219a163a1419f6e8bdf941f399e50691a1374959a499d1bf8e562a81079461e82b8f8989e344598818579b1e499dc1d65eb7e3d4c282adb1d789177798f68" },
                { "id", "607d37561ba56185a478ff4400ad8f9508240049a2e4827697f8a147acb6164eef3b17ea3402e3f9cdca2768d5bfb132d0f5f2a854cb9dc10ae01167649d65cf" },
                { "is", "71860e4fe13a7262af3a92453967c19cbf63acefebf1bb3310a1054d0c85f76e64f43b9c666fbab7aa69414312795f742fa7af7d22ad7f2ef3ba3bc693ed9b0a" },
                { "it", "16942c7ab112d3253f602048374e75118dd0414e2c89fa0abb50cfa887cfd65a1a5dd288b9281232f6dbad2f29a36732fa8f18a3506d8199bbc042d7541f9e98" },
                { "ja", "70d751010a08427d4283cda9f3e7f67edd15a5b4b884f4053d01fbfebd6761965432c161a63d2f3e7369a72ba957fb65ca52578537f6a3e3ea621e44c914aa90" },
                { "ka", "616dd32739f2c8ef2f567c43900460d726abd624af18b75ffb72999136e364e9c6b0aa9112f0943dbd414af8202922c74ab4fa22be24114b4ede6452f37cce67" },
                { "kab", "6cba84271e6498d3eef9704244bc003baaf89bf00be3a4007c33e991856c3d0f95d93c4b9d8481a228f73c847c025a5e6af74f5bc01a8887456ec4973c41a8a1" },
                { "kk", "6066e99d5392865c3b5353d83e619ca1ad2428ad6ad717eeb5e5c318fe459cca16712b62bc300f4552f5c1c94477b972c38b17892be7c107aa13cc8bfa146da2" },
                { "km", "8985b388964cf9763bc2b714594ef96a685b9b47f106892b38038e0117109bc8fcbf550d547706b8d7cc93ec77746dcab8863d4f3f6af6828bfddc8218f535e7" },
                { "kn", "791f73dfb398ef9f354f589de79d383d4abfa7a0df52363868fbefadce8e97f4e54ccbeaf46efe162d1f9c0849a7817513373d649b22f1778abb02b2839e701b" },
                { "ko", "b9857e90166138367c8c8dc22475c70abbdfea6d11ca2772235065c2fb8ad83f04da2631f64d8402cd2793d6b81fddbbee01a0a06d4d7c85aaacf807023a9a69" },
                { "lij", "13ffeae574021e150c3686319fff89cf922cceb4afaf12aa1912731573d747b49de50e1a5b9c6f0afdff80a558471a09e9101879767994140f13f098cd0199d2" },
                { "lt", "a0b631ea4e5aa2b706720234387ef512dd61d1e3cf0158d9baf0b8d2e8c28f88ff7eaf627c5820427e585ed936332b49a456e32f003e9cc9b1b435ad8616737f" },
                { "lv", "59e070f2a4bbad5ec35e7a810fa7bf9be76ffb85597a8849aafbc13b67270d4cff0326e328efc65a38ec967810fa01adc170098cb53059df51bde0904f0e0e7d" },
                { "mk", "93c4b18fc1fba8b00088799ceee3867147631cbdda2a20b353ebb14a7506fe7a1812c007c3b25b0f0fb3b1cf14479ab89b92421d000832890101fb0cb2a39f9f" },
                { "mr", "a660cb8f45905a7143e97c740cf2c88b74050f54b03f9ad581bef9ec3ef98382b97f22772ce07c172324136a22390ceafb6f3597ec73a6669757b80e37d1e929" },
                { "ms", "eb11adb0da77f46b2bf09d25321877d3e952f2cbfd43f2a1af836434c9dc63104c73ae41b1e91331aeaaa2ed086c7d6fdedbd812a9471bc02d6a710c6ab560ab" },
                { "my", "bd7053e05bed919807d557ecc86f8b70cc03f9de7ab6a387a18593c279165c5f362d71ab640e93cdf15c733331ffc5e31b8bb8f13324f1b2840ec82d26f64922" },
                { "nb-NO", "406cbdf78b89067c914079422a61e4129c78b0e8500337a5bb8997afb9a0c2335c8b5878a7266b4c6c13b3559a7bfbc2db20cf288fa38d0319b545bc7543f17a" },
                { "ne-NP", "ae71a51dcbbe0d7a9d8a802b32bc6cbb4a548e992177e410dc07905570525a2f831663f9fdc904cf5c3e4fcfb7da305cfc468e28e16160096f33c0f58318d07f" },
                { "nl", "61d0deb9262b5b48c0c94571af17aa431e022ac3f4a45f25aff636322cd917a77aeb77bfabc6d0c292d68edf032c633e4668def354233c05e2a24719c642863e" },
                { "nn-NO", "dffa5cbb9e73d5b678c04da379d6700e06b42fc16e608fa6b2fb96cdc813465f1cf2650cf559e9880a04547200fffe7babaecbf666535237c56784ef84c77522" },
                { "oc", "e849e28cd99602d1f71de7837299329e0dcc9b7ba5adbcb215a48d270b143ac81edb62db266136e77898d3885f8a719d46d1ab21c13a2eca4fd87f8c2e883770" },
                { "pa-IN", "c370d85b131406afc61a9fc56eab431908da85f9937ed34e187d38c16734bf29c1bf501ee51bd4421ad5c09b7703adfe07fc91cddd92125195c48aecd6afcbc6" },
                { "pl", "b91d7da47d584028edf51e3e9e49e1ceda0fa57b3d9507d4a9525e6fe9b48a15e5bc40af8b66b9b3dc64f22cc7b1ed82f2827ddfd0f0f6772145ed9698a2ac21" },
                { "pt-BR", "233d31eff0459ab53a4dd490426ad19d4299f0eaedfe847e14b42bb91ef574f8d12bc18b19622c07a5a32a32b7d20e4f22a86bb08adf95699a5ba15f40397f5c" },
                { "pt-PT", "5b6194c38768e0f72cf4188148ab1f66d086d40f3460de49a57866f80c6b59af926fd5ea17bafad7c8a391fcd475736bbc45708f0a500ab3b3183d9a0f1ceb2f" },
                { "rm", "44b4258909c03da8b8690deefd57afb6f2d00df9270a018ce3b478887cd4c2b7a31721fbe7531d808543a666de60f1b1fac3f453e427a51d8d23f64e5d88688c" },
                { "ro", "f3ad403aaccf1478da63da560e69cd7bc36685a5c06269435a19ce07a9d89aa4b3acd97550bef7cf353c103949805c3d9fcf8e8303b577de11404eed062bc6f8" },
                { "ru", "4b2f9e1adc791a041c5ca00769b9f75e07b6c9101851fcfd090ce6a2f2f81e2ca7a0948ac481f14e55e95d406ca91c681438707234b5fafd895d8017cf1d7799" },
                { "sat", "f2c5237b744be56d942dea8060bec9e797e278f5b93faad9b2622f1e58271dd6b2b566dfc393730adb43e90a51bfcd56efb54c4797f8777c15eb7d45d5eec4a6" },
                { "sc", "fbcbced0ffb71f150da5e2906f6b2f379ff503573325e518eb7f05b22b0dfdb8095b5196360b3ecc428dadbc1c671d038f131719279062620db880aeee08d419" },
                { "sco", "56c3896c740bfddb724efe74821353f00121fd6077176ec5850a560b3ec2986714c26ae8045e74bf433949e877207a202b50820f586f62b9436a8685168e1ff6" },
                { "si", "ae72429a7cb08b185024accaf8faa569c5bb98de4f4093bd96d58821f2f82f477b7fe2dbecdbab68fe3db8f6800c6e220d833cb69cd3ee4e9975c7bcae0407a4" },
                { "sk", "366f9648eaaf4cc1774e9a52576067581984f7fc4efd7cfd41ed4f54092a1ea3bfddc045c5cababe590f4f55cb9b21254c22d43793bcb6abfec8bf32e42c0d20" },
                { "skr", "50e416bca4b8c86d75eea56a81d32fd37d0dd871b2b80ac7ddfa71c09b2bf83d2d1f848ef84df605f6fe93d828f2979b5555984b66194366995e7e9a6b5a9ce9" },
                { "sl", "63f623b2081d6701ef8034bc4d44e8cdfd0683cb53526bd952a5401efeb8239fb336ec7975585a6570ca78041fe8c841cec872f3f1171c41eebd2eee28ab3349" },
                { "son", "41bbcfdcbea56b79fa9f9cf0d2915db0ab555c49e2c54996a7086957e0b57d10a5237b41f65811b759b5fefdad947cd4950bf21c6b9bbc45a3974298634f93f0" },
                { "sq", "8e35d35c11c299414a5f6c4debebe742e51da19b66e8c73923d5730943855e35a7377729294c73a58aa9eec763706213c5a123e870c79300935fe2cd0fa46cd1" },
                { "sr", "12c9b7792d70fb8e649487acd890e6364515ee34dfff2344474de9aac7ab72c3fb8d5763bdfa12f1d3b47bbe587c1cfaadbc77f11f9e28392e383ea9f238e7e2" },
                { "sv-SE", "1a889fd85fcfd2ec2539d8108b9f2906cc41f478c3dba6100286231ebf012bfa48eb8a36884d604fdfc030236966de4dd9d27f02db5a89ce0f9a83d07bd40bee" },
                { "szl", "37737d78d94c75f8d3e420bf106ebeeed18d0c2be8582b4cb183aeb6077cc29964455bc83625078ec65ee4c814dd6fef9a9169053055bd17d0dbf3dce2a65602" },
                { "ta", "1c12db374df3930978b4720ddb792bb9c4ab05092845552e8763c3ed601b08fa9af3d409be887fa5941af3969134a87176ee65366c292d6ac30ca33cc5190e5e" },
                { "te", "eb5845ebd55be74c3542e9b68255f68e4da10e6047891c3902c5b4b7df8d24fe508ad3a85dc22e992a1cb46e539f3d18301930f197fed675c52863b1167895a8" },
                { "tg", "65f06a75df1e9b91d243649ccde32f7a63a836f98e99c0c1c926711fe583705b1bbd544683a10a09cb31d8a08ba29296ab314e13aefdea4bc018f635adaa06a6" },
                { "th", "bca6a16e0f9f3ad630ad7e4000141fa51525efac622876e8e1f1ca209ed10c38b18d62eba639ac41fac2e999875e44815c20606b4eb69110b374f90ea7987577" },
                { "tl", "af711593f9d766182a9ec937b3be363acb5ac03361980b17a91383e8f0f88b70903ba436a2f7df659d5e1fd9a6976abbbb39fe9ffb5e615c8d2bdc5fbbe8d45d" },
                { "tr", "fbb605b33278d3ddefba3225ddf4f39f5cbd78df1af7ab97e4f1c7075853c0e3607b142c0e946a1d9108c64c98f37ca23201fa33ea4ee436af7d653c72759d4a" },
                { "trs", "7efd930407a6e72a9e16598e8ba3e547b01d01e4d4b168a469a5c2c64c1c612fc1327dc913bd220d523b174bb68dabb5bbe531ad46995dd031141c5dc6baaaf5" },
                { "uk", "2a31c6b5c08036e096a96aa365934e1add7601ae58282af0992f21f86286e1e5183ec698104d72a31db5c83bb9a96c886bee2a8b70ee1e66a75a724576480a92" },
                { "ur", "51ad8bde7e024747ece531080df2780a9bf763ce48b90026c033981c79c84103bce45850c4f30fac1ed7903e80a9c59043093ae2030ea7ccc0ef0ecd3abaf3fc" },
                { "uz", "7c8abab77db0a1a045d6279f074501106544ba3490cbaa41808ccc328162035b9ae30612459f256e55a27e8a0c7d63842bbde999a50a6e7dbf499cd4ea367c0b" },
                { "vi", "cb294a18bd22e11b827344b0322eb67973869c21f17ec547af3afb6138777c9ed1ce99909ecb49a5fc13a44c62d3aac9d2a26698824f5f824b946912228d4d7f" },
                { "xh", "73679564d6f1b4c52277e365bb9ae381808373239f53c28b82b5200b5bd7dcbfb401b23d1e8eb3fde7a485f9acac0393b7a915a7da68599f0edbaa6aa88cfc9b" },
                { "zh-CN", "e8339105f0b51c10138bc969a19b466e370671b71a315789f8b2e01f468ffb1d46cac808b10c30a57eeb1de554c243b8ea59ed9f35a6b7d3d44416e367f53f1b" },
                { "zh-TW", "47af0a586461737998e14709f2f6b2592114383f264e4891eb3915f39c7442e776d901ea360d11fff68a935318c105ee2c33ddcf448527515e922d85c676f1b2" }
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
