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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.5.1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.5.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "91d078d82776bfa6f43715252a19718642de665eb44207777b2be877e53e6920b4c5c8bbb3b2b3362ba1fe10a58097154787b3e26da48b44c101c1337c24d97b" },
                { "ar", "cea4bc84f0e07649b56e238256be23bd5567912c8123c94ef2d723e831fac8ce03871f22c6d91f913cf000f1d0f2595468280e0da2d0f05e08892de3878ecf8b" },
                { "ast", "1185774b6c18809d69670e4733c41b3e704f671551c58ee483e05804cfd424597f460d1e6a880c218a5c99c0c8657fa1073c89b497ba82a29b9e6da19e97e31e" },
                { "be", "db99f30c4ec0535f4b482cfdf88ac31702248b941b8b197583a3ccfd4f4903afcbc038579ffe247574cba38331d48e39e12d551a61606d674e78af60c234ae45" },
                { "bg", "9b3f4a34d21a66ce3da0a9de6d255e1164420f62df3ac07fb2dd97a6d626af329a0149d678db367d7d5c634a7ab3961abe7c2dd5b14432f86efdfa09b3afdcd4" },
                { "br", "74010fed993b390425ca01195c15c6cfdfe7b9f78ff834bc94fdcc20598ce03a87d5f465a5f606fd65496d9890a774074e9bded948eb32eef8d37e41c3095319" },
                { "ca", "f7dbe9a70432ea068a2fc16084846eeed2fb6fa57914b148e0365f66d6de3540b552c543fb27586db54e6246369667fb6adddd806de3467a1f4b3f5af21cdb5c" },
                { "cak", "dbe8c05cc3581fb7788750e784fddc8e987ac9e3f1bb097bce00beb5a00127d2d36ef4291be8fefc0a8ed46870522076a17ada28e9cc98ce694906fffb21db72" },
                { "cs", "a6c790607736236df2cf20c7525aabc48cb6968d1801392959a4dc3aa90faa14c77b2808200bbee847496a6b9667c86bcb4736f1cdad07c173ea292cb3678bd4" },
                { "cy", "8132f4c99969339d742af34bcc2155bbb1b16841c4d68d88f1ed41b29e69a4f99fb0f428c2aa4709fa2a82fd20c3953213313186d89324c61fa8d39a7d707ade" },
                { "da", "d3cbfbc55281471c00e13e5dbdb650437e9b45fb1b4a304add74d4e57db83137d5064765ef77e066778cdf406b4d5fcbbc99025bb61562c2c3152792ce976936" },
                { "de", "406e118dadf9c5436d60e4a045f0cfd009da96b98a388e4ae6d64568f534e122807bb5756fa80679d3d609b2e41e7e62f49a5e69cafb5601263cae6f5438cb37" },
                { "dsb", "2e124e6f71cd4ee3e13c29ff42d3615d0b0ee95757a6b053b02e922ab32cf5c2ee0c139b377219d9ff228888c647374a4c4a7ba8fc6650fc8e5be705411a488f" },
                { "el", "d2b35b72806228c1aed503533394fb648c2f56a2677baf43d1e42b51777353b1808f4f3af54c0769e60dd1e32998b820f9dd0be9b2de360e0c6d227a91f22ef5" },
                { "en-CA", "27570e9a18d50ec4d87b71d2df1c8ce89ae91c3be5b18d3e4105aa43eb1816e49d55464e31ebf888a4883601133f526766aaf3ccf593aa3591b4fbdd68c960d1" },
                { "en-GB", "62202f15a5181f99a3216f398f93f5b252169e8c9fc370b82ec857f5df0667a1f3ada160f144276659b8340c916c743eef24f2d6a99452e18406de11b1c21d74" },
                { "en-US", "0d3c426338cc3dc0b87143786944801e730fa33aabbee5c089749f5425e21d10f12e2194e3bc4196de97afa78a431132c1c386aeb92adf6b4598b0cd1aabc22d" },
                { "es-AR", "41adce45f1dffd4e481faf1a9dcb1555295eaf987793c07a79857bab42fc83dcf074972666ab6907f3a6065c6ee46d3743fff2e4b8fc139f6443c15b884b352b" },
                { "es-ES", "28c69aafd0fa9917f49a0a491817ed33fe2734d7d9a560b985ec4716186d499cf6522a2c2afdc96983ef52ae21957cb07526ddaccb4e636a84b605f7647bda1b" },
                { "es-MX", "e07a42aaaaf1b08263cdf8d92f14a07dcc21d8f903c8ac7100f9d61d95fba4d95ac70f0d7d43683de102e2ef20c1c739abce85d297323294abcb1869ef4d8a16" },
                { "et", "19787cd28a0a9a021d907c4e399d795d2705f95bafa73b9acc168641930813105f5b9aee2635ce55ac49b0f472341caf4daefb83032ff192ef7faa9c2e70fbc5" },
                { "eu", "6f5b98349bf07786846f83e9f49f8d60d00e1020c4fdfe2974f40b7f75a1841375a4e413c2250b8e48e7e650bbdfe8ae449d9a3545f73b3216ee792a06ce2d54" },
                { "fi", "ddf14aadbb4503d43887339a1aaf349ea1206f2af6955c25443e5619c2171ae19e1d57d4b8e92aa52109a753d6749d6d3cca6adcd7a89a6d7ccbeb1d32dcd22b" },
                { "fr", "a0978646dfd88a14d36fa2fd8d2c60aa0bb4510ece6a65a8cbc2179ddd898bae6f8aa58ded0af70dbecf00d3ad4cc6b1763d779fd32d2cc2d6aea35fbc422b41" },
                { "fy-NL", "acedbb95297f2e376c37b6f1368e8e1cebb1e50cb96dfb5c1ca02cf5ab76e1ed0e33d7668f2dcec188a22be5bdbe14eeca6ac67aecda08128eb15f6585badad1" },
                { "ga-IE", "255afa1dee0bc3aa9cc46281ef3ef341091ee30909f8b3a53d21471e0df806d6354cd056df79620a6ea82b889cee6706a4dd7171487b12e55c9bbb61c35df555" },
                { "gd", "a4d6d6fe485f15b28c4aeeae29b8640fce29aa13b21a86dac20f82d1df36f0c691baa7a5bc83d0b952e9c9892305f60f2de69eeb64ad8aadb04bb466e5812339" },
                { "gl", "954ac33b26b10c42638ac2fce84b917c2409e20ab01f3b13168a6ed5f96184d335d941ecc101609c40ca0fb107e4602ff1a6fb1298ac9180c7903f12e00b74f1" },
                { "he", "eebde361cb8a2192d98a05785e0f9a877c45aa0353c4ef364e2a5227ebff447001e8cec448fee8a8545f7051bfa35410fc386ab865da47f020197debad106dd6" },
                { "hr", "0334e9cf791c4bbef2096c8d2fd2aa4696f261b85c381926249e7551cbd4d75015b0ab5463226b2854feb07e6f600bacf2b4e42d9013d57d20e08b5caacfa1ff" },
                { "hsb", "fadd4a16dc4aaa16d5295489cefad1751f1bcc5087fd7411500bc056bdfc7bbf22ecddf3f788233b6a7716fc157c9b09c9683c986a82a438646891269ef83d6b" },
                { "hu", "8c0e253e7f1c3fa276fe7cbf6fe20139467403cb8093e64fbaca261ce59b966c9c6807092bbb16d1b7dd48428cd78e4429102a60cfe317153cb640d233f85eaa" },
                { "hy-AM", "9da73bd4a24746ecad8ef38ddacc522786347f66c4ff28610265cdff7fe83f85d3b636fa56ead5628a1301fc6c76fbf9f12504444f59cd362d0a24f08f78808b" },
                { "id", "39172b9bc56a47079bea02322851ef11a484e54afd20fadf0cbe4d04d2939dda3352d425f914252c9e0c0e9736157936273d50826d412b156827b22fe5400d10" },
                { "is", "964df5a851dd48ccf58386e1638c88c49fba72e890088156719405fe0286543b6d0c0004a18c353feaec3b7bf6a181abda9d5f81b52c50d149c34cfc056ba560" },
                { "it", "0a97c3faecc958ba9febb92874ca6aa1fa612c86050f8f9e3c8df0fa72b443cc4b80a5d7dc5b6f078d45d5eb2b48e0b6b7b4f7695d1810be007e34b12e8fa8ac" },
                { "ja", "999600442cc330d2192160ecbc32f118f692038b94347c9f82bffc1f134acffcc261d759b44f65bd14f2d6c0a62ad66730f2fb8b07ca760e8db1bc2db0978ffb" },
                { "ka", "0904cea8f22c719570471bea91f68b5eccb1be2e3bd616c0bf2b61d559c49a16f958e5ad1ac82f3a4090beaa17975f49590db9c3ac6fe416f8af3b91350b1252" },
                { "kab", "68a4c490b355aa1241e3dd82af753cae839fc97fc6ef406aa4261ca5a32c4fc1e7045a4341d281d75312ccf85060f0bf5248a33159641e0df7d70a21c15c1afb" },
                { "kk", "c5a0581ddf542d9251bff8ac01e390560367c9b7ab6cf9e3ec41e5522aca1985d22573ab91afa8d21d817dd8db90c48ad03d4b37549a9da0c85b17ca0af961b6" },
                { "ko", "c5bcd5fcf5d4a7688d8257b404d754c09ecb259e33734b4cdeca75b8f829da655dffa42499ff39fe267ce4c125b4c3cf3784c0da9bc5e73fae258186112ef834" },
                { "lt", "8f14485bd12f4b714f995f5bd7db033dcf17df163e134224c5dfaecb788ed7155cffbbb0ab224db5603bbe66584d25648ffc07024b8067ba1d73169c7ecad3c0" },
                { "lv", "d36d01291d478769c8fdf9be662e9ac2910cc11bde21fc14560c49bdee98ca00af19a616cfd0db19e21fc828c100667a1b4ac1737bdb41800731613cf3844989" },
                { "ms", "1b2b6328b2766332dea71f7302414cab7ad8289e2f8cded3900c8a528755e42f4a44639b689742c3a84d9d94314f313aef75e77e3adf2603ff772b7478d5bf0a" },
                { "nb-NO", "6e3837bb2020f9f2aeceaabab142cedaeaf1a088933f7447d9c389b875772bd27839b11dd2237bda751182cc8801ed792b7a6fee5d52d58885bbbfe2ea3aaf5b" },
                { "nl", "5c520e04a04a0b7ea551d2d9caef97b4f05cb10eab474af1f79189634d8e3c53ba035af2055c2754f2312f352f5876b4ed1f82754ca724758da7ad1f6ffd1b3f" },
                { "nn-NO", "ec7aa00cae3141ac212eeb2b8db7024e837231297781058456859456c07689d06e9b0718dcea92e24202e5a34097df90122a6dbf9ecd96e1fd85435d2b11405f" },
                { "pa-IN", "9d43eff58ea2ed6d3537b096c6685d5930922d73a32669680222944627df46723763795d365979b256a5db82b6bd452e6bcfeb0aeb5d254860b1c7f4587a7a87" },
                { "pl", "55508168cdfa72d3a218c3ee0a9df900b1a8d7fe6e7f94afc5765fe6c6303e4736b11a6b44cf6e3a5a05d63cfbaa6796b1af5f0a6c087c420f55e889eda654e3" },
                { "pt-BR", "7fb2e747fcfa1a8fa3e457b7bdb2ab91a1de4435fe54f8415067a7123ba979d534531d7d0dfc3ca736e3785aa9c5af7ec63dbedf1d589e5d09705ce5ba792eea" },
                { "pt-PT", "1568744ee2f059b404eb7302f2256065d3843723d4fde04d0cd45e0ab80154e74b3fe40f257cd241c1c07acd166753c20de456a31623fb0e5e6bc7c24d2ae5f2" },
                { "rm", "9801054f8ad3f443c25c997dd6b62a65f5134fa642266d32278b6e4aaf787326476273f15ba42bcb24361818a9550aa059dcdcbd7296ca55db73f639d7b87c80" },
                { "ro", "946393264a70608f623b1676abd2886c2693b8f07e43ae310f1885797f8a40cc736f5e5e2b435e590729defcc51ebfa74903b15edc43867e008f87fff6b9fce8" },
                { "ru", "2427b42301f30e01e5a45302f4f1dffa2253bcee0c6508939c42f4b6c3c2fa5461db1cf2b988fe08a10dc3e8094164108fa9055c23fbd4364a5ddfe9561a784d" },
                { "sk", "29f858bea740e90122da864bae2cb8e8e0f4c0e9d635b850b67a5d656f1aa5abea89893eb54d1e3535f6784c1a9367ec5386a54227be1ba66de5e36db8759757" },
                { "sl", "52ba209a966e39164b8b4c9290b9674214861a50e62283a68c4f2b9f328f0d6095cf65b7791a3ead4ced3d085d5ecb3266a99e2fe2242373f18e15fefc8edf83" },
                { "sq", "c0882607831c01cf961e145f4b8c81a4a060334881a919fd8ee29e3b0200a653646d06f5d13a67d049e38f90bafbec7d78268f82cdfbce3d13724dc76e49e3ff" },
                { "sr", "b285661380a49b76252130761835e5ca846205f3ad4b9d8cb40224885fb009224a564b0f0e6a76524b4c6869747be62a02b2ed74a8169a115852325dbe0a754d" },
                { "sv-SE", "928ba8cec4cbb6e5f9db9c3676f6ca03db676f71bab401eb82d1ed3a11802d489a32dc774d7cf6f4e4efd82af67a8a2770d02a2f5eb7a7e96d4a21868e915045" },
                { "th", "6f8fcbefbc3dadbc4315c5b6d4453829281c0460499da6025e3d785a6619d37de5f464c4c716618c5f78e4cff4089dd7a56baf26bb8796a4066c0367b0c5e651" },
                { "tr", "9d1d93e5411d70fefa8ae273deac0cab58a11c7b5c47734633c6043487d13134d0cf4fca64c61e3795bc37adbb4f7aaaf20c631857ef737fa40263fb66bed2b3" },
                { "uk", "840fadadf7ca43c545b192acc285018968296d7d9592cdaab75518dc2e347238809f48ac3bb331ce4ca57f22332615d84708f279468f1485f24550d8f81f9af4" },
                { "uz", "6e207b6de6808bdbf0f106cfdac2cbf61708e67ad73e454dd87a7fe053454e623d9412a441507171b78bfb8563a9abe0c556cf5eceee6f8b56f69f3674ef24c4" },
                { "vi", "841ca74029b425fc63854b9c25a916ba91b454a426772cc98408f5125be5f24ed3258c3b027a9f90ee3e9289dfe8411ddb17cb59762ba539f92c1c672e594ecd" },
                { "zh-CN", "5d00082979e9a4044347086cfc09b0e495d48bd9d509c4e7a1264390403687256bf90a8ab07d216784ca1ba9f184ff268040149875d706c0ca80b93f039fd8ab" },
                { "zh-TW", "76b97c2cd5be5f7e1772b2a44f1cb2efec75c5b31476f003e93541bd276bcf04805842011cf02c01aba8c8200024124edd71ecb8f301d8d8dcba1be999d3ff43" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.5.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "9334bbcc1ecfb5fd60dce2550505ddbe178f79d15ef57248e5b4509f0f32c2dd2066a928b1243c495f495066a41b35da4e43076cce4e615ab22e4882d0d0c5d3" },
                { "ar", "a63a476948cacbfc316623aefd47e0586be8725cf1e5096567b6ae1bb8bc2b5787549909474e315810430871b55a3318bd9f913ee2f0c1ff1b33ab744575dbe7" },
                { "ast", "397a9a7c1eef5ef693a3be383d67e2d6c87759960fde401921949bbd35a9a2f81caa1e9d7dd30cb5dc81de7ace6a768c913f06dcd107b0d517c254c0e422338f" },
                { "be", "bda10f9957255c81103926af2ccff6812ff3f1f9fb1154de6765d16bf82f1a03f82811e2b8bce2e055c415cd521ab166090e5a429fe35184d24ff146f1c53356" },
                { "bg", "072e04902980841da0a0b6c6a2cbbe10d7c8a5a3e8068ff009d711ddeb617b3fa28f4825d06c50ead5cd809673aa8d12604cbd08aaee3b0e2edee66c23547a59" },
                { "br", "5db2d01eb5e6e86293594d08d7efec260bf8032544330adbd88e62223d24f8c0b0006324f323536d1cee75b21bac74813927d4283d409bb0e8afa88adc6227b9" },
                { "ca", "0159423704f695640248ba89d582de2017edd3d5c301f0d48322dc9e8a1bdf5c689dc66a13f2845ba8b0c2dd0ffd91b144a7e0486c15188ad71a9800c15822ce" },
                { "cak", "c7959d41fcc38996ab6e5c376c86f6acdaa6c12ac71902c4c601cb723bcb588e1444679cd64a58d26b0ffef79e474563fb311146343832fd143d2b7ffbd6e147" },
                { "cs", "d75234b135239ee17fdf67cd392b92c56c6012d25dd08b25b0211f8ec56264c494120a653ed2737811498d895f19ee1496b2ae226ed76761f69b5a58f07fbba2" },
                { "cy", "8b702c3c7b3c639c34b064716e931914a44c2a62b890f9d53587089e6703ffe0b2d245935bb198f82256daa3c621dd4a6685303567de5fbce274353729581321" },
                { "da", "584525cdfb56e33fcfa8c56dd5ef9b46a3d1c812398d3ad0d0843779730f22ec41a5c707c49544c9d7e269284a25d394ae7f95f0defb214c32dac194f3bddaad" },
                { "de", "c0044ff78af9f1c9446874d45141125b968bd5be51251e06be21ad2abb7cc7f1845737dea3b52ce8d303b2f23bcd86f729394c154c38e133d9383001ffb7bda4" },
                { "dsb", "b76da1200eab5587c8c6ce3037375294d1b0e3ec90363222b385ef2b126a8404961c935bfc44103bcc8017019581e981d694b995e201645d0c9f3f0b60f24d9e" },
                { "el", "1548d6fc432ae6536122e48ffc90a137971384f33fcbd74b0e741f22287274276da2439d2844b03d7d4f58c67a537fd659af139ebf3cf2ae27fffc086adb72cf" },
                { "en-CA", "73d212843b0d75d90b719da1c77d1d96cba8373ad3275972a132695f0f9b2005ee5f083de4c868c763f036a830fd77d96c494530440ee6e1a99fa2908829a81c" },
                { "en-GB", "9e72b6d3d61218bdd35724587a0eb19985294d1bc2000752ea074cea96761423aaf27d0ace984042885b1c4a16127028f172836608e13974e84172c7835f8840" },
                { "en-US", "92e81f16fc26c06a116ea68a69467a9e4ff363ed08012a87fbf66d0de2f41e5ccd17466984cbb1b32e13ca1a0da8739c5620e58d3b68aab2f646a28e7d5b34ec" },
                { "es-AR", "5f4fd2f5c6ed0fb7121cb18bd9e4ecfd5f025df25f751465dab31f683fd7e3919da9728b535de7701fbd48da0c933275c179231423126b8cfcb772500143d5e1" },
                { "es-ES", "a898a27c78d6c74342f54bb7889704b9bb671f8f9a22801059f00e05dcf8d41fa6f68134b1c7cbf3b5fe996cf2598c348404afc74d48e0e6c4c86685eed4a78c" },
                { "es-MX", "e24cca04784e5495e1a3b92b7af62c48ff18c3d2585d24f3a4aee859afd4fccb7348d1afa51374efd2fad71d2cf37abb86e834f84e9e6a57e719a53f437219a7" },
                { "et", "85aeee525969ef6ab7c9178e7e6fcae9e60b66fa3e97d71ab48c58a697f6cf39a9e52b91e9d6c13fdb5612bbce6f7972bfe9ed8c00d3861847ae9e06af50b2b2" },
                { "eu", "60ba6177d8a65d2c50ae5ba183189c00af056342ec0425ce3fd96da0a4b28f73a40883854c171dd914651e4940264cbca8541f573a2c9b6a4c410fd2fa67537e" },
                { "fi", "5ae48136b3789eb5db4f7b019ff90fe4da246bb40a1343f456cb61e4491efadab1b80154a501a65c4139ced22a98bd4a590b60eaa8ec0c253760300d711c8fc1" },
                { "fr", "105c558e245866e929a5368e8487e163ee0226f062acf6e9e67af2f1c5e222da3a72df18c86265d247297010558e0268e00700d5f8a6105330fbee9b40132c02" },
                { "fy-NL", "caf7e357f7fb0172410ded29db9c11122cbc94c76b0dbb50c7d880afdf0620d52dad9b0649164111e1c5d320b396b01deefbab90b8a4fc4419643afea42db300" },
                { "ga-IE", "b8797d882dd791fddb94546b054b72c48bab69971e9a10608aef177f96e17a5896a6e045b740fe0eb034354764ad25a09ac78f9cdc1f13fb5f0ccafbbf0a1db2" },
                { "gd", "f2750962ef0eb667c432dfab772e6bebdb4bac28f4e23c8a13bdcc55757e367f9bc1961df5f00f263f456ce1c97f33de48822b97058595b5ac97e11cc841c585" },
                { "gl", "190600758fd157db897d8103690a44a3a6b641d1d0bfb40dd7f8cf7f3a8b102fa2ee8449baafd04e3ba145821add23d0f556c74df1672151e86569b5909f68a7" },
                { "he", "563f84faf78c327050bec0954e1799f73fd78bb77d08b3c59680b1c545227dc3402bcdbf6893f391734cba16f4c0047ee011248123743b8c0b7a93b7f34cffa3" },
                { "hr", "6afbcc477519af525a0642275ca39a68589df8658f921d8d407c938fcab264bad596473fab9194572fa397942f7c1c5a1969bb239990d9cc04c8292dae2a8df9" },
                { "hsb", "3098431f4024fffb88d1b233067fd946eeaa49584be6b5ea13981d8c5ffe47c047ed028b4210e350784bbece389c25c20fb96ced13b0a32e01a65475b85ebf94" },
                { "hu", "4b6b4452ec3f3b4dca16ff928e3544452c5289da977f345ec2f0098c9029dfd2560ec65e64fc1830e98d1d76852f60d70e9f7f492435ad5a3b193b99b5007e49" },
                { "hy-AM", "679b3ee5fcb3d23aa74ebe1f97d332b418d1bcc9f73055ae30e40d6852c6b0c9a8a7869f67e753a66f159b2477d82e0a09a355d40b6c6bec29759765f062421c" },
                { "id", "632e720639723424e7112fc2ce7fbbba22b75734c8cd48dbb0d29ff7041d8c3240fe69ccb5157d5609fafe31d07a85e542d7ca083aa169aa7a79a63b4ea9d271" },
                { "is", "c06ccbc7e53a32ffede5b80f34ca5da1b6c1ec2b91362aa471ecdd0cc556a4bae53421b71671d357f7d304a07282df0a6c9c9bae614ab175adc88a96971e1ab4" },
                { "it", "7711e40799bd143891f3a0ef574d673c9cb570463dda3338383d6a898386ec51c203d6de4a3639820bb2b5a52a387a0d50dd0b90a17c70eb197f7ea92a7d20ce" },
                { "ja", "43ef68dcfdb56e345b3bb4c58cdb4a0551ccf70372a98adeada501705c9bbddafdf6a7215a3c1eb90f3022bd5d33fd8a4cebab1f0cd24142f8029fcfa717edb7" },
                { "ka", "7218c0171cd6ad3f5bea7458b479fa758747916cf61c0eeb8c8d513e662ed58df4bace0562e492a11cc14f29b73b5bc199e20ad1dcdcf6e90d2984f1f444fe21" },
                { "kab", "709991faabf7d3bd08fcc2dc54fab0da8b7881140567bcc6922f8fb71c165cf3df5b75f782c90b331b1fbca803ef261c4c50f5d080487e1b0e8ce87ef2661a2d" },
                { "kk", "90ec9099cad847b031bbff12764df2936428bf46d2644869919ec267a149dfcd5bd8025231ac01e87d58ed494941e601b4cc552c9971b31e338a342ebe6b79b4" },
                { "ko", "d44216a89f9660ad89a79fd2225f745853d6222c6d2f0e78c65fc26e180d4bd12d512357bc6d18a455fba9591f2d5f615bf60fa31969c4f7b221e48f2eb6c23b" },
                { "lt", "e21250fdb105466f8d74f8246c0a54e2f18782eb2a7cf4767748d5fa5b7f18ffe18e63ecdda8e253c3659d6bfd55b3da758eb4238d51af28a8c3b62eef0eb913" },
                { "lv", "23c2e013671b379736b5f093b71eaa0903417182f65f61f34f5719bdef682039d16d5009a2f5a3c01360d8c48918d4bdb18cf958357dc6508813e5fcd91da4eb" },
                { "ms", "12b9722d0bbcaa5de42f903f37b38514b5eead45a6d009c80f3115079bd45bf20256b20312b100e2dbdb69d00d96947a3543da4d4e7c851cfd4d3a1fc2ad15d2" },
                { "nb-NO", "7389aa49a9c2fed42264966e1c684e04a19a6fec3db55c77c144a1e7393963a29ff6fd828037a46dd161b72024ec793ef20c5e722eef76abf97f64d1b7a996b6" },
                { "nl", "38e5b443dd69c77b47b0d3c8de7d762c10531b1a0a6371d7113493ddbff7eab0b7cf3395f974531178c333f8410fa193edcb3f6f74e0c54660be9b53445a351b" },
                { "nn-NO", "896d950cb8ba0736b47654a48da3f8763c3f55084e1c065c95f03396513cb10ada3552afb86e7f1430445fade9f3bbbcbfce525e33d8deba83d4883093be2832" },
                { "pa-IN", "5ef40a7c554db626e438156b944dfad915198c50cf283a64a1beb9a48db9b52dc22df4011d49566c4a4869b3eebc29ff5c48121924220dd2eb7e447b65124990" },
                { "pl", "a0a8cf589c7f6900c49e2d619dd112880572740384609ccd1356c9369f332777b5ca7404ed078ac4a6787f66b92e3a260999992ab82cd6b589927a3dad5c2053" },
                { "pt-BR", "647bbee822e8cae5ec0e21e038736b47ba61ef28afa6342859a96078fbde61dc1f420e7e1b5dd4aab7778f68fae382e97db611522b45478a1ff20d7f651304de" },
                { "pt-PT", "977c491e33bbfbf4edfa22e8f2fa0733f358bf8c90ede6b641305049d45da39ac63d5fa55868e3a07f6f9a3ef2a57e12f7da6373c556cac0b757bf0fade652a0" },
                { "rm", "b32378e70f986aa124845c3fb8eb76fbe7ff75df6ff82c6a2b7eab22fd121d66fdb9bd6ccf7090a70376fc9662db1c95ec5003be661776483e3fb0e38179679e" },
                { "ro", "3a110dc5afcba9fae3943a913ee40501d08ae2f0936fe4417f08e40483a5a272ce2fad8ebfc3be16ec255019c15efe799ae413c9ebfcae7df5f45b363c7d0f83" },
                { "ru", "bd83becae6f860ef6a74bb377a79d1fa5cf652120e745fab94d2cd78bebab586479d5232166df5d6b53324fe54e524e1a26afeb3950393db6874c38a09f8c6a7" },
                { "sk", "804a940972b1a023eb8645dbfccd9dd4b914f1bf5ecd4e82e05b8dcb9b267d5de9102443229fc51f99a7afe69e3f1b497beb226ecf188cd0cdfa5da9260d80ac" },
                { "sl", "dc3be37b477cbfc517c96763361d4aa3b631c5ae8f2bc71eda1101e4666f5132b7420315b284e45f012879ec2035e3160f1424f49e42931acae3f1aab181c73b" },
                { "sq", "940e11422ceaf4b8dfc074ffde57c45f9b5c896291c6ae9bb19442dc02f671d507ec56a42eedd5b6c8bcfff3e004b5b0b064391034847f6a50cffc0106e700a9" },
                { "sr", "be0271690c34c424d696dcdcbbcb1e2525648d4dad77c0e95467f6a94af72b96acc40bd3fda88d16399252ece7d4e5a63d8f508a20728d92de3f3481a46065ba" },
                { "sv-SE", "37d4cae49b6f8714e84f6777dd18688811f1eab06887ee9cbb3e1bbdc6cccc9289c470cbaedd533f274dea10bce3d9e23b6c7ac056acf73cc7b6a4db569dbfe0" },
                { "th", "f47f125d43d14fc52c3d615204900fe06763fa1cffffc416ba361369d1ddd49a56434789760167f6cda2174708f7eb028cca7b83d90407a2372e882d60dea00c" },
                { "tr", "98ded7cf805683e7169448a7379a85f905c6826ce929e94bc9249f5128263f6a25d518d482e83bd04149aca4d8c5f46503948081436e41c3f6a74860f22c2734" },
                { "uk", "0dd8a38d29f057e70594d10d21b701689568c312009569622dea9be2e5dcf0e9c49c730b784f427d6807fe053039076d69f13e7d25daa4a57c2534a9c94ce31e" },
                { "uz", "18e35e6da9b7d89676229da02cad3c95878c890eeee69f7013b3cea6403be79ca40897594834d2edf8da0d322c6d3861da470af70d206624e110c8f2b228f30b" },
                { "vi", "af1d1315b7b4f9c5ed656c0ac0301d6a082a3d015183d4cf016131d11f9c5c4a92ecf53c5e858fe133e3c61ec50cc744724d47161b040afb6b8ca4de0e8cc0f1" },
                { "zh-CN", "fef483f6c17ff3405230d39b278477c311ec83493fa5b75e02b28fe92b283386df22757802d1e093bf732ed5dbabf11f5082b39d30c157e34e5679d550f0def9" },
                { "zh-TW", "33cc1d465cf235c7a1187fc2dae58a8ce7eef8291e06ecbf8b059dce8b318ea95bbaf94ba700ee6ce86e547194540ccda05b2d0f698e95b722d95657f529d8bd" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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
