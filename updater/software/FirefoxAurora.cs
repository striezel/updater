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
        private const string currentVersion = "125.0b1";

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
            // https://ftp.mozilla.org/pub/devedition/releases/125.0b1/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "f35718b3442f4814b9f5170254edb939bd86508186a63e9284a9e93636881d2048cb57c4af7f5c41d0088c52e99792b99bd9ab13cb7c68c717862897d5ec756b" },
                { "af", "8c32dffe6c819f44aa05473f2fa31f40564a62813dd629e0b9aa87d708c914f93edee9df85acdf0840708674c6be77f050ab8f2327af82e508638bdee90c3490" },
                { "an", "5b417e6d4a08c0c3dc45e94881ea977b2aa6985b000c5cc7671aced46f0dbd4ce808b07989fa567f2e30ffb9a4efaf11feae63e68eafed51af4d3bafe34cd932" },
                { "ar", "0957295078f2188327bfae9be544aa8ccc3ec7304e16746a8d295ec1ddeebf88a993456140adb61b9d16fca713b922c01b38479c55a1c2b6d49d8f43034f139d" },
                { "ast", "382af7227ceb00e604dac51cdef9900b1fdc866b35603deca5990c64f7a2bd7841fc7cb33917d3a2f2d62772f6d1e9cabe3fef439672797d74bf44fa368fa118" },
                { "az", "aed770d9827fa0d19aa82de5e1c64806e21e39ddac63ff70b5775fd7a03e54891d49bf4b84f92b9907a58e277ca61bb531f14aa051b63e78f6652700341abe21" },
                { "be", "d6070611fbaf3492ebacf1b184d2508084f5a9ac476855491797f27d05f80c7ffb647b2778db3de495b06e3fb0996540f9ef9262d69a38aa2bce34d7eb40852d" },
                { "bg", "4ac8e227665347917f8e375facde42c1567b1382c8a4fecf765bebe17341eee6d26f9d332c71146b4f3e3eb270d766c4e92cfa20f07d2452d454f7b3361ed539" },
                { "bn", "23ce429eef0b536d4638813c280418ca72d964e3970aa6800a74fd8b7407c35af9972b973a04c2ae42fa0e49a984da0bc640897f5ca403ea4897a8ab519f04c2" },
                { "br", "2d5e4e85f108d263a52bfd7dd52f581d12d3708492c906f5fb45a99c6a1e42112773156c7c19d6ebe2f042ba5c399325b8bb6c57d348d5818f47c94ada0b367c" },
                { "bs", "e3aeac303e39e91dedee475f3bd833924ae6b483ec0d03aac706ad08335f835c4be46088179594a9262471e2f57ee03828673b08498a086489fb4e35a69954c2" },
                { "ca", "c5f6e788709c2be9857a78d51f338158593c1d12d30e50e6950960f81f3af2e298aa6e452e93c39d1e7cbbb50530e3661131ddef6a6f14881070f2c5c1704cf9" },
                { "cak", "340a1f0b0480a9f1067150be00e9444ac6e06f8c1a6cb86ccf7b7971ad4d94cf523890f8cbb3066c441a2ae7dab6831d0fbdec6323b2ba55e5f5d7686b5c1347" },
                { "cs", "a3860b2d3abc7c217f20be6a41eecdca3ec6a22ff155c02b3dbab7c1655306e32de5f7a8dbc4b6f0e298bf4e746998e3f33c784c5f38fab05557b3384e18034e" },
                { "cy", "820406593d7aadebe8b302a9c77fb24c01bc78715d1613001405126449c82be4d0a0e364d4f5b719eef7314a38f4a6a717427acdc2de2eafb708947ff2f7447f" },
                { "da", "3a915b5634eb464e3f494851bfea70c0b8bb585f89379648f78c9e0e78eb46b509baace068bc8261fb1c95709366d03147eae9b0ae73d8a3d50bcfb667e408cc" },
                { "de", "8012e60b6cefe3759c9410605035bfed64bc17f04179539a0d1e92f396d1936912392da077f8cc52fe1ebceee5f82f096c649615cb78d4a116ca2ed848a511be" },
                { "dsb", "011c7441231d0ba76f4d6a374257ebd53a4434b49c14eaa92ac1dbdac2c96eee317538d75f18df1b4e031b6b67b1d60ab71f5512f12fd4b2a990c4dc85a84560" },
                { "el", "53ea97cd43fe11e1ba75193561f166ebf6adb389ddb5bd5d6da920271cda6856a607f161eb6a8722cbd713ca37261b18380ace34d78e655a565eaaa0290216ee" },
                { "en-CA", "86811ad2dc0a7bdffd34100ba7ee59d56b59d4f9ac35d4edda5dbacd36fbb9540e7fcfcb9a7b3ad69c9568888fa91a0e61d69de8c821dfcf7cd3452e9f63a60c" },
                { "en-GB", "bda9136a35468ebf217cd099efe77019a82b69b0d67498832cfa6c06d45faf51e963529ad30e7ceaadc280c48e5893ddae58b19d878865eb4b597df1358b91da" },
                { "en-US", "fa0467274979a626e7ed1bdedab96d12bd316e64e29833573b752567e2be5ed6a51b4c10fb449f7cd4911733245e2aa9ed35320c850ddf3a5dcb076e3c11c320" },
                { "eo", "0fc2c145dc52551c2ddd302debe3320b729446508d1ad84b25707ee43cbfa836e1b929ded18e9e9ffbaf812c9e5e53ba81fd6404b247994b0b2ba3f45e86883a" },
                { "es-AR", "5b11296fa31605064b3224421b8000a3b8327edbfdd1ea20e7d707dfdd1cf52f8a56a97d64cdcb14f7aee8bd40d9079406548c801457259d591ddd96671d17ae" },
                { "es-CL", "31d30921690fc8e347a65a1d5ea65bba267a6e197db291affe2d046dfce9f2828d106837171b8df830fc454b2027f60f370baff19ce38821f8a3b56535bb374a" },
                { "es-ES", "e32b5676bc685028e5a15c925dab01109173c4c92546c026c8d6e0cf142726dccd847d3667ab7f157036fd048f9d302de5284083c6193e15958fc51533fd3cda" },
                { "es-MX", "e316ddcabd4f62de7b24e739c28300558d289815e1da646b79897057225371c31c035fd4495df305bf9e7ac8c8b710d2a2e651077901e8865850abb3814290a8" },
                { "et", "4f9d2303f2f8ec84706475d217a797dfd11bcf71287a6447194aa4b7409828eda64d8821867ce661c68e194730760dd7c528c378ad8e1de189e28bad43be2ec8" },
                { "eu", "47a602f74ad11e2fb5fdc92ada242344bf29705a041bd67324e253fae841b2b45f57517b47e471732d01bc6282ee7a5a2d8865f555cfcc209e9d4e81581341d7" },
                { "fa", "87ed97863119b680dbccde2e02cd5b428007f8b39378448524babc9073c3ced27b0a5fc86b5fa86c8292db9b4cebcd03eea974e2b1684930d2a48d491797b7ea" },
                { "ff", "8da1ffdb4cb43080db9473071ab9ddc1459fb4d1f6f1c21470ac53801a16502cfc22a62fdcf64050ca368a52d87635909cb4f3317f9198c7376832fa8cc11479" },
                { "fi", "b6ed2e22e010c5e5ab0ace0f8e1d90af3ab21a4ac957ed6787836cb93a9d0589540f082b1eafc695cd8cb425efaf822e4c3d8bc19dde958b1758b698cb5e0703" },
                { "fr", "ce192a1f674096052195b957f97ee455650c0975b56b415dddff526e6f4eb64015e0acecae0fd7ddb1f134fa81ad2d360b145e518a0b2df66b1cce70b7651dce" },
                { "fur", "99a5898042c406ac8e7ec969b9acd011399b811de0ecf20cbee155a0f8a4cff0e5cf0c43d3fffa2b1f277be9350095e86e9ba4840eeab7d3b3303281d8189798" },
                { "fy-NL", "d1d9ae85cdc6ba6a96d8d4a35601821d6b8d2d7098b87df1a380e8c2f77b925ab69d92cb9eb2a34f732be517f2dab4b63ce6fe0191cf7e1cee0a765baad65bd2" },
                { "ga-IE", "6115d7c754dad8882e056cfd8dba849a953be192bc0a0e8aea2dee0a1bc5b945a661d2d1c3b859ab84454915ef7a005590655a0d9affb8ccbfc7f4f945508f5c" },
                { "gd", "11595b4652186c4f5b6e9742fcd79f44ed5118ed5f60b9d10d7206684e60a52526a4c03f190910feb7f190b6d7433ce6f38f7948e3aa8df87f8d28fcfc158cc5" },
                { "gl", "b4836f34766cba6441c169fe41da62910630d12ad6bf35433c1c96d282ffacda58d024ecca8e18c9522eb1f4d95f199fb6337874a5d7687352943f4e20cb8ca5" },
                { "gn", "e8ec1aa269577213748f27006957be7d3ca4a10d6c876b3d48309abc55186728f77cc1bae45a7a109f53b4d68000cdde70c0e21b783f76620e010763a7a5a014" },
                { "gu-IN", "9054634d006f5ed5a35ab3919044a21d258b242f88665f1fbd5073055b1f548351edb64a36dea20d682b401c8fab52f336d3359ca8bddb19fedc29317a336602" },
                { "he", "49a1407faeece00e37246767172faa14b5ad6c0c16dd0ed43e0f85df93348019938da565bb75e974ab277c67abf2c324331ed99c7244e9f8d598d40c3d96bd69" },
                { "hi-IN", "f49578c6ca49b7744ea2c348a45bf4ce60b87af9b7d6297430b09efedadc9ae1f10949045dafe57c2613439d18af823206944cba810dd81a82211f23e630ea72" },
                { "hr", "4ee2b0d26fece9c4bab3b76468d8633ecc582cfaa7946077a434907b7864b4cc03584ac798a5ef274e2fd9fb51b54db09240d97000c9616e4998b9470fd4cdb7" },
                { "hsb", "4a8c63cb3f1d844176b6110d0e8832a0cbfe1b010ea43f72e5219cf2982a7415035d4501c0d464feb117d9e15cbef46a055a1811c256f7c1c055d3efa9dca4d7" },
                { "hu", "0f83b2411e794f309c0e45eb07e4c447e229447d04b16577ba2467fd5667dc8c66eefe32a4874c14fb9336db6d34791e84470be4774b64a085395e7d85c6fc6f" },
                { "hy-AM", "ce8d166e3b6d47d83aeb94b9ea1b1d84ad8f1d2adf2a0720e9c14a3c9b8e286d0e7db6f52a4c3cd6776373fc5726963b92db725b1b5061245030ee97e82fe1a4" },
                { "ia", "f925850f97f4f69a5436fdca74518c3edf71620c0bfc1eed2f858956fcffee7d4a1ecd811a3254bb7e98839e9970bf211aaa09ad12f38caf75c880e79a1d6ab1" },
                { "id", "8265489d96635171239b6d8d2fb04f372d84f74f21b9f2c70c58a0f24e239b9e9dce19026cd0c4e42058fa1e4188f68b2d249485a042b5b6d2b976bd1fc1525a" },
                { "is", "868837c7d55bbf6e6ae33a55698aeb505b25c7c86f939f0793ffe08d608fd2fa1043f53c3b236a80cdae504f3354770cf98bf12060b6889ab63a80b34481cfae" },
                { "it", "37e56979139813372dbbe4d81e7490be90174a9618b00d62b19a2cef24075d776cb700acda899f3064ca2c35ddbb34fac157a26622aec2373f890051bd662af9" },
                { "ja", "03af4dad6617783d97f80e4d6b4bedf22c0bcccfee29cbc205326af7c37e02a9852e24ee50e124f47c743fc29a38f854e9eb26a5d84b169a206e7393bf767962" },
                { "ka", "1edd662f5903f4bf23ed95a520fa5426af575242ba4d06a4f2ec69b956967f31dd179129075c738700368ad40369858dbb90b30bd2010e0f3167d9044f91d648" },
                { "kab", "39e0fe5d7ffb2c639f95255f8bbe8196b5b5c45e609ce8e9198a245cb3bb275291cf1082ec2470dfe545093e43360bd2cb21c30ddad82f936f24a7b26a915f0e" },
                { "kk", "89c8bf320859ae7cdedd11b4364411062ccf4839c67f4163a7869fe4188030315e2613099fdbd2ee2d234d42d16a59fcd57c33ceb06a650ebd81c715df1c0b18" },
                { "km", "a85c99cfafa2ce0bd0ead287974cdde7685b589abb9febdfbd3729cabbebd55c4dfec4865586e0d1e6ea67c4662738b92a6f16ad2d0edc101ff8c98c259c2a9d" },
                { "kn", "1385d23ebc58d168f80683ef80d40f2c38bf390672794ee25ea489184290bf750309187d06e34c26a5032ba138898a0f9b8b6517bbfc425dff9eda9e722b2a1e" },
                { "ko", "166a51e973a74426b7d9408d9af09f9bf959ff18897fb8a5f153b48f62b06177a0d4ee37a5b4d7aef972430962d46bbffb79a0940d833604853c718156ca2d95" },
                { "lij", "8ccefc54dca615e7736ac0ada060ec86631fdf06c7305c7cf6059e7f3c6a58e08292722a034637e579a29277cfcbd43afe82d3f2ff8964d75f4931154d4bbf81" },
                { "lt", "b00a6f284a35e537447bf5f4d517d73285bec16401e763f7831de430e14b995f2e2bdb497f9fbf974f847cfd6b39785d20293d7d910ab39be0ac4827a3c0d423" },
                { "lv", "b3594540870430e11f285bcd067caf719a68b75c5714f023cdce2597738e3395867e953d9c7ae53875656bad14196243b89d004609833011dff8ccf0c34ff3f7" },
                { "mk", "4c1b180ab8b673bc5e75e5eb4e063d5f9e920f8fdb33fa16b0bb58f61ee4a59863df2d1b8c05be1f47af0eaff21d33580ffb86e8064093b82c1eea48cdb8c42c" },
                { "mr", "df3775b56492eb98a17602a37705913a65105251c492394187fad3e4553c4e6b87c5bd147371a649906a1a3340936924054fb7955f7a9fe32524a87c90f051b5" },
                { "ms", "aa68e7e595b11128f00edf770acfdde3a032f77bd6a7072d23a75032673552bb443881b505ae1009678cc69fc8313081c02320837ff93ec3537c4639a998e44e" },
                { "my", "097bf35a4ed28465761fe83b4a3c470230f3d3a252c7d0f227e12cd6d6f95504dd6ef18c866fcdd92d493cef3c8c718d1c75a601108f1d9868fd7457dcd8efc1" },
                { "nb-NO", "eb10d383f106480c9765f9c0612e40146f3172ce0ad85aed8a78fb21a016eac5a9895ecfa450e235fd2c4271c98a2712e377d244867a22204c49ebefec706f20" },
                { "ne-NP", "547d4878cae416db5b84f9f23af6fee5fe07077f6a20f8275a04a22f435600cd1f2ee62ede1c6c3a80ced8f3b32cbb92bda898b65992a1b660c817635decb1a9" },
                { "nl", "cffbf6d9171a9a19824740cc81734266d7f6f04a8ba93f3b85a8a5a464b7049993723e44fd38cc34483e90e002a1a7ab16d22f1f1bd3e46b1297a9655d623299" },
                { "nn-NO", "5ac2ed0617bfcfdb041fca8e904c84489f74cadd12fdede216d370a6984875d13606ee2d29a9d373532f83614c650f9825dddfeef267ff7ffac55d40cba6fe47" },
                { "oc", "c6a8b696b4490d4b753c143d35a0a0ed9e3e743ef56d6e98c6e089c0f76a21e15690a3720f4c97cfeb8841343ea59eafd2095cad4312c77353725fa6d479421c" },
                { "pa-IN", "bdbbdd6f8a1196c8303731eecdef531ab9f14e456d05b12263da16625e3d04eed833dfee0e8fc208da446c09b5368d91ed70b61727f2cf4f52162061987ee17c" },
                { "pl", "2f724449e2ea6ba2cb922d0998f548d7079aad6d3de1bc913253d457110adf4a3608f8c4e2970a92db35053ca68c88b170cfbc450aa570e4e03f3e750272d0ed" },
                { "pt-BR", "7c04c5f876ac48b6d783815bac2c2f535ac2b0658c0361d0265863d759f84f2a0a5c2f7b82c4a7f8ae80e9760c7c7fc5c130a26d267a989b20268c92c4916904" },
                { "pt-PT", "047a6785b3cc87efa012e17d61bc0e7733519696813d0ee3db31338e5a5c076549cc9ec5ea2fa445a07342805306f02c6be260a4d7b682daef41bc7efc8dfbe4" },
                { "rm", "dafb4cf185cada34c493669cde77842ca07c2a1a75cff2e4bb3d9e1494a18434c276f3d8673f704bc0efd20b6fcdd9e10546dbdd658df7f27dc7a2d337180bd0" },
                { "ro", "141b797fac122dc6a0b561d826d96c961c5ff2dae33e1ea7babfc7631c2489c2769f133ca90870484624368c9113d8352b44168df173511fc42e56c19ac61642" },
                { "ru", "2c5bc12e6b7c089735632c1af6044beaeb071528c8bc5563f88bdc3dec1f513ca301919c5242349b8f072fa9b08ab9267e6e5fc939cd119e6f66ff0ac597f0f2" },
                { "sat", "5c48d4a9f89525ed310e36cbb39c7bc6980bae98bba81244f1036fec92528a307de04888df2711681f334f3492107ac69eb4b21c45c6d3943d14ff31281b6b99" },
                { "sc", "f733b5368e4800c8ab708fd97d937055f1b564de1934c876e9ef47176242fa2d11bd88bfbd576df85593b823b4bba7ceeddde09a82a423dadaded300a2b1c1a5" },
                { "sco", "68854a5ce9113d592695d04261c4d52e115d99fd0d4721935059cebe4bcf8311cfc9603e705086e46fcaec220c9da09b989e39c60bb95e393843e84946beced2" },
                { "si", "1bb85602ed9a6edabb5da9d1d7262f6c6c756f3a95c734c81f44e34809ac8fe99d12b887b6b56fcca303e5908ebd4d6864b9ec2dadfaf5c456d3d719cae27b3e" },
                { "sk", "3302752db64d3828bac323f25a5c2abce7092c7da7ac190458b595d27ba0036b2469bf6e7442bfb35c53036052c09aba73d7f772f4088ff50b8ffbde4ff0ca60" },
                { "sl", "f92609f2d57dc6cd0c347ff7eb1040fd87ee4703b087b4c239d59e1504b477b00662226a043e660404c52eb238e62601f9738c63b9de01a6db1eb1b8b67d48d7" },
                { "son", "e4b3a2a1ec665ebfe5177a6e9b8c941be1d77d39385f0d07ef58a2cbba13a7320f3c88f41d52f59d0dbf6b7df65499ecb4dbfd912b496665b4cc69359251a669" },
                { "sq", "13b1f68140fefeedb2b7b83020438ca0fed1e2cf46dbf1877e22f3bbc74060d7b4f241bdce9bf657785f36af034196c5a391cf4ba217cf7ee660be9571d72c69" },
                { "sr", "736449ebdd1f2a9133cdc927a1c7ce5d9ccd5fcc94e43fd069306eaf1b24beac64c926a6d57c10758a631a5c4533ee5a68276666ee03d3f591883173e7e399e1" },
                { "sv-SE", "4bd0b2f529b51a08fb2e590344350b305697ef1439eafd4459bfd42c1c60bc752f367e6b5e0c1230db26ca0233609231c5c6f39b7b6c38e7d4fd200aeb5a3983" },
                { "szl", "12377af97221865e3da8d8d466a0ef61c6819a7cd91927c06d9313eca5027a3b71bc3f11a0bea983eb385468efbbab33ffd35ca368b4ffe908b933d00d060202" },
                { "ta", "0ad4ffd3ed4eb0eb824bb8c76d151ef265465645730a04df87b9191a3ad90d6f79387990de75d53777c8ddd3e9cf16903416b568e5d318eb49a1bdfd99562555" },
                { "te", "342b3273405ab329262fd3adfa3416d9f43c9bb24a4b559e17842517ef5d190adca0f39f0d53d17f82fb3a575001d484c7fb219a077f31ec3c26325326cc08f8" },
                { "tg", "8531a05d4d637bae618fee63976857e409d69666f26a428d66005417cbd73bf9b393dcb7b8f81a54d7502ea501985c84bc8500c728321b0bb6e5c7732ce3cf22" },
                { "th", "39f9956f9e05f173c57a86252e62302c1b9ab34663089a980070056ed5eb157d4b204e8bd12772d20370f2e773a43f3767d844a978cdbe642e705985ee184a5f" },
                { "tl", "6b2d9e01c6a73ce3d8c0cfc5f886b1b3c99e7c2dc6689b2c1928341f7483026d4499beeec1a6efd4dd07cacfbe66a295f5715a03b2e762d985e6f51a04b5fb85" },
                { "tr", "ec5ff78a53a3434458af858fe78382b7a0a57632517a2e068aa9e1de58349914d2bca41b26a040aea26254dfc2bdea8b2d8e7248033ffb126d1e42bcd9865694" },
                { "trs", "d77670b22f18cd3a935457e3b4db4f0e439bc268bd0f4c350464528be5dc92ae15b7f5ab189f6321fb2baf13fcb0187834c5e3b69c12d4fdb445e1b598e6932b" },
                { "uk", "6630cd6ffb6e5cba2de6535a684ad26e7daa41c828d12a24ba5a350f1cdd9229ad92214886a333481a4097e096e1d5bec68b69a737608de2a97f8fd50cdf45a9" },
                { "ur", "e083a435348b349616e0b7d870ec6caa0637e5f28282445db6085e038d6f6f47b2f2c7f5a6f66ecbdfd0d7c585e3095e3e45e4d7f0cf996d245bdf81ff44eb0d" },
                { "uz", "e856c5f180b6a50241be2771927d67c95454e5b4b22b6bebbbd4d7d1db87402aefbba7acfd2b0296515e4671e47a781cf27bfe61d22e5b9ffb1b3c64c9844883" },
                { "vi", "d0acb901be45733384f3e635fe1a08d249cc281d00377afd9aa92fd6df7dcb20857ccbdaeaf9a28fe6bdb191b6d2edac737858e64464aeb40cf7d7b1f0b6afa5" },
                { "xh", "6d04af910d2850b4e1216fb49f5bccdceb8235a0357a3b5653168964f61145c435b6782882a539513f41dcffe6d84e9faf42af7087e2e4a449cb41713fce6d09" },
                { "zh-CN", "2f45860f241170971231b3164dced34fdf75055289e9334530a8dc96c43910876a951b5d26281cc007c0d04e732ebe00422656ae1a1b8ed9c993548e95d81368" },
                { "zh-TW", "927af06ef59a164c12c766940a9705af14d1fd995e7cd1677c00e02ed2c0fed8ac9b2e6990fd4e11f978397edd9926e6fef1f5720244bdb419959794c8a8e31f" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/125.0b1/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "9193f5dbbe82a999b373e7d46552ae44a20493d8feae4629ed3aed3b5cb27d4fe9efef203ae2166ab18d957e8970b200f2fd14f986a5798a22bbd56d780aa9ba" },
                { "af", "00d6bee89edc3947bbf5152c10d797bb402aa8e617233c480f4eeef7148ad54675a3fd0d63014ae82a314fc8a6e1c7c3a0bb5601c65d8da998870e4223d26efc" },
                { "an", "be0e8e6c31f32ed5df31fda26ba7971bd9c170008ea5729fb16d01c891449201ab56d2d07e1c3a9392234fe3ccf942959fd91d87caa7334d9a7460da7a6a4642" },
                { "ar", "9c9972c13c74add8da49af2c119691f4abc9c99b2d88387096625bebcef735b70c072df26714b6cf1c4055379ef982f90bfdf8d7bdcf8a7c2f74e419a6c81218" },
                { "ast", "7f0ad2fbf5daa99902a9d215c10a52ca54bf4acea75616f359f9c5dacb882cc15b59a550dc9a941c46bb0397b90268b879e8f76a63636aae5b5f4d8f183feae0" },
                { "az", "5e4acf86b1c8d609da801990cbada265bbfe79cf441b1d7daebb4753a45debe27443ce25437d274ada183389471a997463e8d8a645a95d57e1ba6f5b001f4007" },
                { "be", "808f239de8f9392d457e64aeb7b40de50621e7ff213dacb9273957e32c7c1d86515eaabf51fdf9e53adc7fafac121b390c8e81c076b979f413191c521e553ec5" },
                { "bg", "1938eb407170e8e86cf5797fa39e17a7e25c12dab3e64228fe0bc95aaefc3fd842c4e355cce0a1c2892947b93769500ec34750a622449f95ac78226f0592403d" },
                { "bn", "7ce183bc9175cf99c00ab17deadc71eec9a8242f1544d3415cb4dc2e86d19da9d365c8572aeba204b55c364ba6442ca72ed40a8073e01ecb57b32a95236f92d1" },
                { "br", "0dc51355097b0827c162777b73c3a71ce62818ac39ff9c570bf32ff6cbdcf3876ed05c35c760e5dec51504120dbec346a87f11796ae4745342fff5c47154e321" },
                { "bs", "af809403d57841350e4b4e11584dae1a67810d3c3b5459706ed6fca01e8e5ac4236f5a4f87ccc7d4ddd1becce940ae7682025eee2c739405c3f2a946c95caf90" },
                { "ca", "6fefc337975d4ee8a25a5adb9d60e16b8b209d130e5713b8551cf524f673d54a61cf89cf24345570b2e6f7b0b41d3eae66013c131f7b9d75051926a3629d03d7" },
                { "cak", "41097f50dafb2c314c796b967642d5a4e1688fb14c34511bcdddea83a43b6c7957730f0d977872d6854016c9266f3676b9acb08cf80c136142c9e4741b356a4c" },
                { "cs", "e75c23f12ac08f0152a4f1fc5bd4b80064ac9f600275ce3fb192dc33e9d8520acb49811cc4ca35a6dd5fd968da9c94ea12449924ea7ab2ff249f13d3b9391a7f" },
                { "cy", "887e288bf100ce50a502c70f1f678e164d5a65f4ebc0644aae297781ff8da2c2d1b9d805ba9d7ae74e8415016a27d900fd33b741a6bd91b50aaffbd3335dc3da" },
                { "da", "1616b220f40d3bfbfea3324f8f5a4b429dce5a32643ef4da4811f3c69c9a573ae0d162408a0dc99f6ab8b04454949bb366a76d7b2b05db7a9ebb322638781a7f" },
                { "de", "8c12a41a2f0fdd2be71b570eb21ca87e2f35355d8f903fbc35afb103416c8f508f4c8926ee8ede118b543d7d0cf0a7a8d7d168de124cfc1387520ad572b7533a" },
                { "dsb", "154f83b6542dd8683d29e2e5f1b2d8f7272e5a4d2c239a77c0a78b3524ceba56430d33f54e18c14db18bfa8b624fdc72ce1f06724f6db3ead381c18676941d84" },
                { "el", "302417806700d370409c138025b92f3827b4d8bfd289abe4ec9d678fdf987996b4b80ae32932c8d2920b1b28f8dfdafd6119f57aa259a50d2042d51f6aaa7ad3" },
                { "en-CA", "5b8e992f78d094c3b80de402c749ade6791210a069bef56195c666fd9f6b2f7e63f1c9601f379934435717cc6cc8c4e51fe98ce5541d068f05aaf805ad53bf31" },
                { "en-GB", "ee3958c595e66dda0d548b78bb366520fc085def6fbab2bfe258711c211bbf44920dfc3c7a83a33b0a2b9af4fe91c06d015a97343bd0fd067a9f4b6d36e18f4f" },
                { "en-US", "da0a670c48d7e11f005e5c5ea556864386bacb6b30da9fad63326f11eb98bcc5b6a85c0d449fc92d9853934fe00fe29372253f6065d93a78137d20aef4bd8393" },
                { "eo", "e4bbb742f55b2935299ffc6a5f673f221eba97cfe4aaf55434c2c76e6a734dfec659fce5e668287274e18b71b2913872fe0f0c90af128a3d01e36e621b8452e5" },
                { "es-AR", "77a4ecc6f3c36cce5a157306ad687a91402314b9d58dda88b90e39391ed5a0d0048b2eeedc51f1ec99b5d444cbbe06c9c840708963b9ed5a3ef958778f743467" },
                { "es-CL", "8211a4da37f47622a688dd9af36dc64a6f43b6e906d3b6e7858e399f6fb10813208e1e296385d11dc56fd755dfb7da79d9aec55e6d2051eea2ecd803755cab9a" },
                { "es-ES", "e48f38f38e44a617ef4cade5fb22e1c8f9c769e2b799647772c4f32528a09b2c985f0a16012c4e07bb22641d67775da2058cc84264d6b900603a693806faa77e" },
                { "es-MX", "0f980255b483a877e9b458a38c1f79b43fc5dbea9c849fca28cda7bcacefd7dc54ab02c3642ec3f727fea6dceabdf05575a46f0d1a2d8f4ac9bb2c809576350a" },
                { "et", "dbd36d5e19afb25bdc2a85862a09de325d1a5b0a98f7573b11d0e109fd07ac8d5741ed3ecc6c2533ab84ad4c07a4ecf7c64581b842a103fdb58fdf439c68ddca" },
                { "eu", "85e0f71603152fa1fd63f96e3042de25525bce8c71b0420255d60f229a15ba8630273480df67bb807405dba5b21134b8f4b6e6d7768d02ac6434e6ae49ca48f2" },
                { "fa", "ff5c0bfb7a4fe1bbb41e801395ece13cfe44103aa2281fefe0fcab41486f6f8cd203b4b0b9caecb1ed8ba17e35bc9cf68deaa8ee21e5da8a4aa99d109c124aab" },
                { "ff", "d9f7b397bf0d903cc5cc30835dc9b75ab0e18aae331b9dbffde87dcd0d46a415554941eea7976ce8eb435a9670b3820a6b940e85773e3fffe626c131e461fdf7" },
                { "fi", "03743f738277fd5d320eef87c47bfe802279c69d686bead655902a9c0389f2f4485caec5391bb3551d8a549f8fd66253e80fc8f13ffd4d285cd19a8e7e8cc66a" },
                { "fr", "83e12e2e52526a8ec48ac25968f812f60a7aade34e79012f1fc7b2b5f5d62031f13d531ba58e3b1084f5c3b759a66ef7d2dfbbda997c20281863aed362e5e94d" },
                { "fur", "f42e99b6f7ca41da077cfa276b1487c69968e1b32a53f05465ec65040b5d2931e0ec9499eea9702e952cd2fe7a858e20efbbb57d4b8ade889e446192ce8942ac" },
                { "fy-NL", "4c0f8a08dac0aa3930ee86741315acfb6ffa4370c58c469ec84d86df15a7fa728317e982cfb0f7545aced0b3b06e9674dbd0620303f452df6f596cb0048d09d5" },
                { "ga-IE", "751b4719357d96ae2025806079e44bb58b25aa623eeef5ba53ed5d333239e94b10810928faf10214756b9691722bb3ff3f8ce5617d82a575fc50ccbf0174f118" },
                { "gd", "55318e86ebdfc54e4a7a304f38f1d9f3f11fbb3c684891d4991a85c12851ca9e4b9ad483777b5c2d1da515d2c652cf8a23a2d37fac93c020adc66e4bf18ac0e6" },
                { "gl", "7a7afff2709d0d888f528b462c0fc6d04befbe9f149c5d02f1e6236ebcb589e7610cc44e4a34ec20b5e4301dc3fe042c0a97e1bc14a40e46c2c9eea0c8fe24f3" },
                { "gn", "a3f59368945d3862192718cf273fb751af31e860c43cca0f3f1c8b9c2c46fca4b0946210694278c9f3a9ede501c9a89dd78cb19dfda33ae1a4bdd9a3cab6f711" },
                { "gu-IN", "b13647c3bf85f1f64aee49dc549e6444cd99cb62eeaefc1538dfb1844013039beab43921e7d68d244396ebeb9a99766eb5e755854f78742c935791eadf71525d" },
                { "he", "d5de7e770a1e3e032e9a12a4d3f6d985372808092e4bfabb0f88369049d577f0bf497d596da42a68be3ef55e03e43ead94a386b3030760a311b4e03ffda87782" },
                { "hi-IN", "36dbf130edc6eb6cff4c64c81e097d52e2d0bf1baac8127399328824a2635b5f70dbf817736b99ee5f00fb3f58ca924ad4099bc7fa3f7ea291727ec6db71f77e" },
                { "hr", "006585e29ef73537130dcbd2fcd57b5b56debec12d1ed5606e7eac62a831fa23d0fb6cceb333ebd9e5a4400ad0ffa68f3e142ae66fef429dc65af2a41dda7c64" },
                { "hsb", "80a242b0599c7b38383f9673f329d33b4666111f0cbc3b1fa8bcb273b489e529707e72ce5994f24a8ba75dfeef797f340ef82b23e2ae5991f73e727f24bbdff8" },
                { "hu", "3403352b7466b6af161e70abc4cabf86e839bb66818ebf50ffdbcce069a08b8aab8e98534703397b3962d3701bf8400b726c2094c449b25e160b796a5b58b708" },
                { "hy-AM", "cb5e832290f8efbbafab96e5f8337079739c6c0370efcaa279bb426a5a2948398cdc5ca7646b1e71e1dcc3d34391479f335974853905140378307561140260a7" },
                { "ia", "ddeb5951def26119340d2a38dc1c97871aa29913e8b6b4ec8b469a7b260111edd41730ef917d59cbccec6e5b9e8bbc38764a53ab92180d758ad60c9ff0a5197e" },
                { "id", "55de041179975474179a51c2a42234da3dcf5166921ac9e9d5440f9e98118f5dd421548bd74aa4e6f4c150098b4d199456ea545ae79e47400a9acdf5748aca7f" },
                { "is", "d91dfe35c9d062e778f830bf243b7dd7b8077881c6a2ff5e924b22453571a7a77e73b0eaaeb0e4d12b236c7c4612b4959b965d6169f4a2e7df66d6dab1c61100" },
                { "it", "25a2acfdc90ab96cae33f3204a23f7aa8224e9f4df0cb292d32ec59c3bffe7bc7152d698445c5ca4ac91561ada304aa014343583122e5f3aae285796d6c0f7d9" },
                { "ja", "70f7935e75a89ceeabfdd27a5183a940030aad6a03c2a1fa02f1768877f781988b68caafdce9bbc6e7f0838c23d8580eb973f63cf8b411913f667477e12b0f76" },
                { "ka", "6807a63262a98a54ca0c14010221217ba50e56e2f37b3e25a95c326c45fdcfd4a8c58c51e402b6b453a47709e21c8331d7af10d55cdf5cd2527aaa4dfa8226d1" },
                { "kab", "d19972e50599f49da4bb4c427c83fee103ecca8274a0ef987e9ccfc135d84cfc29d2535b7bf5dee785570e68ea1595f89d6361b21539c490c3d1eded14e40def" },
                { "kk", "0177672ea1e2f14564a9e002caec6e77f1d2da599c9b3bc3a88d3c6625ada67430f1172057c4571f3c1f01e3a359c745aca2db4aa0e15a407691946b04c73eb9" },
                { "km", "7712dd5e0fdd8bfe426c4922b19c80e7ee9b26af5d04087de275c9643cd6af876238ea019715cf2b713ce9ceb5fcf21778f44b9eba5a81914cab3659b126f10a" },
                { "kn", "2b5ec7e76d271c80537d98d3acb1345f8965c28260447fbf44703fd31690bce69319ba20b93de664e9a4b2c0ad6febfde7ceeb438258514473b2ba78c50f52d0" },
                { "ko", "bb4b1c44142b2a8f074912efe3b897c37922525a930e59a6211475fabcb5cb3c8a9e792728cab258cded0864c9d97c177aaff57e02576a4463b65ea69935d3ab" },
                { "lij", "972f673269ae594bb12cc76bdd5d6fad820567ea99c862f273973cc26eb3724a9739190c70afa3aa5d282aab76e238ae5389ee032c5d38a0edcdeedc5d6f9b9c" },
                { "lt", "eccc615b501f87982b3a1c9ab2ec849863cf568d45b51f27d297d87c20834288f2d09801a8efbb9738d75b0ffc32ef5741a5c70fc3c0ec6cc5e0f31939c9ba5f" },
                { "lv", "eb670f2f80fbada82a7f5f2c1556235b2c431ca036a967c47157590aa510b5e81b006d4a0fbab3f6d3564ac895a68348594b1146e32efae12323ae42aa086c0a" },
                { "mk", "30b3ecc3f0fcb3ea5e25f3bbf903556e46bb5b3ca36cbaa0899be0154953da9f8fbce2a36dc91963b7ab04e9dffb5cf0a4f8208578e49ca13aca33ff5e83b4b4" },
                { "mr", "74af637c062a0561d1b4906d5cfd4871312f3a16063af1c1c9c343148cecaffc67979f41e58c669f3eb4870f4b9b06cda0fc74afa339c6c7ad5af9026fe2856a" },
                { "ms", "0bd7136051213967995c1da11a063a7673a3589b22eceaa524ab773c13e8718decd9d49f1d3161532c92887d22cdd403929a759189e8fcb9c9a64324903f5cb2" },
                { "my", "ae2192ea80a9f1032f92817c3e79bd7f75d28c84eb57efad36bd6b2a2b6c66c79be4ac74888a02871ef4f86c04f923272cda84d6addc3e47a00c16319fc2bef7" },
                { "nb-NO", "605ebba7592a08e95b13de1bbb221dc51455ae265a306268106a9f7d1b37a9a4b4486d6ebafd5b3b2c442b477b3f1f22491b211b494fa372e6823d2e56da5ada" },
                { "ne-NP", "d30cfe1d76273e0095392ff70e690976c3fedb7366516c6ef530c687a9cc7df31a3b856209aecac8b5e21a04f92cd58ed75e6fae848a88dc970b0848edd44f78" },
                { "nl", "f047220923e8b8a2e2e83d5b3dc88118dc62c95c318be0d6cd00485a1aaff70e295faa16660d1d9608fc2dfa4f65729013259c8de7160ba9579ee3f781dd7245" },
                { "nn-NO", "4977c62a7e7a992528e533eed3dd7aa7f135936977404fff4ad1e9865f336444be8c844e7c58bf1ab7cff828f216b69fa38bfc5d2c7e2b59be8778be6c541193" },
                { "oc", "cdb770c72eec54410bac970d70330271b5f82c9d6285667508709fde539df0b675dbe1648595820f5095f04f7efcb7c04bc77f1c623da37d9a0bca019c32e79e" },
                { "pa-IN", "4282722496dda31a34baabb88ee1a38c8953f92be37c0e396acf79952a3eb7105b288edf95091c204d00704c0fe0446db90b87f15a264ac16cd4ad0d966c5ea0" },
                { "pl", "f8067e634f3101eaea37a24d07565b1c4dba9da43ae5f6bab97ca4a949efd30467083d8c94cc3feb1cd02786bb76dfc68922c46e90519943760f044c6c623113" },
                { "pt-BR", "6335754d62c02bb24dd6fcf88e9f5d7fa46b860cb2f959f2dc27fcd9fb7947bc44ad7285ebf3050a60fc3f15075c0171bc2f9c1e568050f1a8c53305327973bb" },
                { "pt-PT", "85e08aaf4c59fadcb68967dcbf0bebca6746ad3057722e97c1dd3a9b655d5ed463792e7bdd9a593413f275f9a9a10b235997b3b0bcb2bb7b1d5418c149cebb14" },
                { "rm", "74eae449649f41e5cc6d67e1adce5a3de6f8e9f1d62d50e1ce8945bc0179bf6ebf7ea94567cc98b95df1078190cf94f6eff1191b77dcd9b428b6fbf536e9178e" },
                { "ro", "6ba055845f3fc6ee2c919ce1f289a9f9a709b30c962582c08a87ca31e2af02d5ac05f0057c98efd89c4dfddf943d883246e1ab2e06e293eec22135dbb518557a" },
                { "ru", "0ee620c0cb3b06df60845d670c9222edb6de9b28499e2d0516c87e8445229382ecac16632b07de17f50f5a59bce8d82dbb7906061645c3f9511472c89b181fb4" },
                { "sat", "5637d1164dbb4801a586fec1c6f67cae1afa317ce5007cd0909d43a71b667fcff93f6284a5604cc067d0d9f97a9826e96b3042a4980c851d22d1c12730e9e3c9" },
                { "sc", "daa3ac34c19c955b858d85df60222408fc39a867614c18368e2760242c5e4dbec4456a78ae6c1c530bfcdd4bf2339f22d8bf2a83893b6c5eba0810cd2edcb0ef" },
                { "sco", "a46fd20cf18986dd4d300d8449b5c8f6edbd42ad05fdccd70dc77faff9ba7d4c771c03df1b33a56c2a872805540a504b55880ecd4aabd8ba4b8a5520e589b062" },
                { "si", "acfaf0365cf11e276cef1b750c04e374d7e1539fe50e0599c3335044d05bbc2a142c63a16a6ccb41c4b06ccb2050b9d15b1a768ff614c7414d23fa928c566647" },
                { "sk", "a058038b3ab200c3b850a9a9e175608abce178a91ebb7ebf343a8c7b587bef0611bb9cb23ead8d4e8f99700ac6200660694767c97fd99f0d9e627c181a7f059e" },
                { "sl", "56049489de28d1c6d092eaba5b7621f61cdda237bc44ca46fab0c2497f13f8a0fe1a228357383a59cc8909b9238f9f11195cbc2af34cda071f8ec38afe8c3dc6" },
                { "son", "ba575765a423a79899fbd7365ed6fc9f498a30734052498e1ed3a620aa4de101ce9daf43f7f57ffc191d04c8c2f0cdc99b52f90b60067e0aed306754cf98e7aa" },
                { "sq", "776a0b1ce6da9b09218c4dd34b4a9fa03ad5fcbd4666c10bbd3196fe883c739716468ff0db78aaf6b54236173d531280f61796ca634327c5084bc129d24d9bdb" },
                { "sr", "591f3873da31ab5308c428c1783232f16f0b5753c8025bd205223bb629ca2503e0ebd90fbecc4b60333e47c76d058c2d8112d8294bf676e0c1511ad13489af83" },
                { "sv-SE", "9f8217492abf2bc1e3fa86c758a5294ebcea3b8313e47d20327395baea1904b934b1ff093193009296fb1304f948ea209d95a48490136a477a37e32295dcb8b1" },
                { "szl", "b9fe2180e14f04cd1ec7bdb08a113def1c7b877a175cce6d334ebf81a055d815d1ff3c1229143e89c98009de1bdfa41c45c877d69f45c0ddc86005e639ce7b4a" },
                { "ta", "0359c1ca6602e56fbaa1e730e28f81b1de4ce3fb93a9774ea7d3177c6ed9f05c1c6beba1b49d5de416e92e662dec7931d5bf87d8296530ceff6d05bed5715d05" },
                { "te", "df5fe6792d28f9c00a40b5154b0232add4757fdc1590bde2db53808c77c3dd82a2eae2022a4adc5135e2c99e4d7449c8533e9ea2045d569319e625dbe31a40cc" },
                { "tg", "fee7ac7d4d5facd41c0f124eaef54378eb65b057c47746915d88e5ea03d4945b035fc8a610e9cf6ef463cc436b9bee4aaed9a3d766e2941b4faae26d3ca6aeca" },
                { "th", "81f62a44fb15fa01b908846fb5d664b7b21a702ac399a1cddb7e22fb0b9065ff2df9a02b972765cb1150adba73028a7ffefd110befd29da8b62ae75bf841c2e6" },
                { "tl", "d148b883404d109b6f56de68225e5edc65ea5784371bab8a773ba65ee0a281e5fcda1d3839baf9bb8ad062516905d6a0c52fc89b39dfb6491efea351d0386eb5" },
                { "tr", "e090ab90c26ab204b771a0d1f4ba5425cbcfb0aa9efd60e2f52518b4384e286d5bf3e8601acdaca30aa9ac66c6b8efc22d8487898697170cface677a7f25ab26" },
                { "trs", "bc555bbd13687d46651e9959ef17caae0b341a8b006d0fbc50869254857d64997d9157d24e403d2a7c96a307ce106781c1466b0da3713652cd6115fe27bad66e" },
                { "uk", "2cb7f29ba8958260d03deeb9920b14f0a2fbaeecda0731cab117d2f350a6fb40d553eb68ffd18156119ceeb2bad974c7aa6c60afdd1fcd08f76d8afa4e80008d" },
                { "ur", "92f982d644286c9a918392c4d1a313de8fed9b67b971009ef4fa1e311c358923f80d03a321185b5eba897e5fec5f95f59e30e7d58c7b1d09bee15478021116b4" },
                { "uz", "dd635399975568a1c52ecff9d1a9b839dc48327955fb11bb7b0ace2373db9b8e0977a5c8b2c8c291a2a2db87c4dc2a84aa86416de2239b3c966d384b2c7c71bd" },
                { "vi", "5fe5368a8913aef551dd68474be79e51ae41a45f07a208ea344384922c7c418818907f4833e2118b2b323cfd210b39b9f7d8fd8c83c6cd873723ed71dd9206cd" },
                { "xh", "ed0e55fd6940a7356ad7a9419a6a28ec4143f3d9636ceb3bc689feef5d6f1f52dfcb31161f8b2834512fa228e26b52e99da6e02316ddbd77164351f35e87b5c3" },
                { "zh-CN", "46e769138741e808ff61e5e6d73a1848b6b2b1720e559fd607827515f5ce823d9f9b0769b58569fa15ed129669d038ec1ffc654decdc2508ff18c6d783038e33" },
                { "zh-TW", "fbc3b6518a7d7175fbb9441d1d298bffa286c4c67ab12cffb6c253491bfeecbf39ff373469b9ad8d86c833773cf1785c6cb6c00ef08b140a09501473f8d8e827" }
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
