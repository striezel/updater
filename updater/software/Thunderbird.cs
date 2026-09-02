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
        private const string knownVersion = "140.15.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.15.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "dca7c895267c5a5af456186b7194def09c532f4791847f745903a40eebf7f801a0f8fc3cb5f5662d7a49e18409ce4b32c9dc61c12ee7ad5a1e657b0c01ab463f" },
                { "ar", "7e00a91472fbc819af4c280623bbb624a5ccc82eacc36ed64861bff353cc9fa3c5ca2124286b625b30714b5d3d94f453331b5cb23d0e9105b72e22b9034493a1" },
                { "ast", "26265458c357d3fb3c40524a0e433dbce8f2021dd31f417b56eb362be3a445ca4b2c7daf1de34815184e8ba203a8b7712a4a86b56fe087f37d2e1ea09c2df24e" },
                { "be", "e68b28d057bb1eb3850c45abf0224dc55b431d80ad7da9ef9ebe9d54647e6a3b82a6dac77a1f4c21ead0cc671c71f028a0a31bb5f45da4d5ce92c7641d407e45" },
                { "bg", "8bd4e855e5b08f7500ce9262e3628e885ec51033754eb6632d60e284110a13faa3ff2dcbb02b7a1597b941a468134b0e825da6f35ef63cc21f4d2328835b432c" },
                { "br", "8965a1cce395535a5abb50975b93874301070695dc74118f8b291ae566dc21bac061791a359ebd008e3e6320a9d8a04ac5158d9595e7296b3a937969be932fbc" },
                { "ca", "2049e491e6f99e656c4e6136fe2b4d0e7c1b670f0a786423be53a02c64a02da6da86d6c61ad0f1398e3050043d1d31b2b9e0b0b00d62bec57002d544dd5cc23b" },
                { "cak", "e70d8fdf179f3ee23200e72d77a6b190031354ad008c619118862dbabbc332235aa0cdb467a057ac3de34c1fc9b0c68684bb8c4976fed56ad3b9d1ad49b3382c" },
                { "cs", "147f5fa008d85f1f87b54a36409a8b7f6586d98b3f9c5cdbf2eb59d51b2e49f05d8fc5e11f8781894a3b1e942a66770c0a1e540b132be6aa78cac462fc96b9e1" },
                { "cy", "bf97b51ef8a545a1107c14fb23b8a709fee1f34ef176f2990f7310ea4214aeb6baae935e56ead110752c18e252737751368bbce0658999017ffa30c7f06f010d" },
                { "da", "f1f249e79fd9ded78f3bf94553e427d583d6e5f44cdc19df022a2dae3f7e66c65844fcff9f5709c13c3c7c2cb0bf30c91d27df9040075a410161b3d90f8d9303" },
                { "de", "acb532fd4ee3c88f6423894a9251bc9f174a34f0a1d4ed9d498602358e122fc4c35e132f410bdfcc3c9345775f35c0fe3126bc31a14103a9aaebb1fff4bde038" },
                { "dsb", "e0dd4898cdb6a2186289e38ece2621d860c1e9de3011f165f8c0a764627a25e712ce5ef5e28525ceb0472bc848fe0251518e2ee9899d17b27720f3708abb374e" },
                { "el", "b84b9a050b59cf7dcfc96e590a021172a6ebb4de232714569749047030ab57e6588b98e1acf3ec0c8ea7c8290d3435aedf72ebf2abae868dfcf590b05f9ebdd2" },
                { "en-CA", "f42976ca9f17c91a475ff3ae01c179de161b17c75e11acdc5ca892da18dab76fb5d4ef47d5c88ace8011a843105d321d3a72dea27563567bbf0cf9b861aeaf88" },
                { "en-GB", "b7733fab2cbebb53ea88ca7a1720fff99b28491a7cca3bc503655b32f33f2595f440c42c93ead7ebc64325aff15a7e1d510ae1cfd8ed8da22c9b87818e1443f7" },
                { "en-US", "a83f7b98a93ffeb6a0b5e0ad9762134947cb51fe4326d5150499033d191af3d841dc3dea13fb79a886ba716ce7927f92baa74991ccca4ec53b018e3990218230" },
                { "es-AR", "4f0f04788d4fa6c40dce6fc8efe4f2e2ffb7b85c1a4948aa5c0861f254cc161e6125be53651cabb09a650e0a26789670db22bb68fa22e44bd06bfc65b8642378" },
                { "es-ES", "3bef5355d049341e9388a9b9344c1d8f7d26966ed66ecb59c25a6c4e6c65281d4a137227319c76165a1865b34af190d7ad0b3c55a9f793816713add7e6c5aefd" },
                { "es-MX", "36c6099ea310b36670d2303dc7930b53d022fbd2271bb8272b1d19211cc590d84ecbdb8251b49c8c2f6b8ab6a5ab957acd7d8870ebc752c19dc770e312be775c" },
                { "et", "fad3dc7486060747fb4b8420331357059823aa9232c85e4e9ce508205121cd1888e7bac6fc4e1fdb4820e77cf824dcf9d4f432ecfae222f555e1006e299469bf" },
                { "eu", "07166d263440ca54c2181205e506002cbef97efc1cb45ba220a215e2ebc59f3912027a48fae3200fa971400331b809cfb3a574ff23080ce70dd85fe18701d091" },
                { "fi", "01d011710c8c736f1e6f813acec7a2c7b45d9a060bbc391e3959c7a6489af78d9ef1b5024cb9abee3295bba7ddd918b96b1df58c9652b3b5536d87b902a22d20" },
                { "fr", "bf7a2ef89355855f12b3cf521c2ef088a578570b3444c62dbda7575dbfbe296f34a07064ded585649a224905da8b1eb93df400c2a4906e4dbec57a60064df9bf" },
                { "fy-NL", "c14a50bbb507863e097500fc3e2e24e82fad036f804b222e78c2355e409b71bbb87611a18f5bd572f7a6fdd691679a96d46b127aece73e750be49dace9ff60a6" },
                { "ga-IE", "6cacfff6ebe421934f15a555594783765b0b40eb962a1a8ec3d0fd4d066fea62df7a283998d876cc87eb99e8baef6a743c2acb16851c6340927788e3c5e58bc1" },
                { "gd", "adb44e3f3bef9359d0577e2a1307a8c010afb8425552ea4b989c699846d1c42ae255c4d4bb5ca9b51752465f37333cda1573b01081edf3392f0494dd7c725521" },
                { "gl", "d888e97ce3cf9ada85beb7fba54d7cc1461c1d4452e511114bd610ed7c47391cd8bda825dc8d56c095b4a9dd2c2718d86b3bb8502d15e8a3dea53e605ac3ab12" },
                { "he", "662d961152a26efb5f0902d643377563530b5b746ae9ee259f0c946f87cb66948ce8d3eb92aa7f57bfd9fbf1c5fce27cf3a7f4f630e02ac72fe8c75677aba1a9" },
                { "hr", "e7d46f3e84333e7e85da21d87dcee6a2cbc19394b57b2938b3be13cef95a1963a33207396e5f185ad606b1eca56cfd8a8bf8694ff0a639a5d76a259828b020a8" },
                { "hsb", "fceb8587cf4c4ad151da6395c1e26301b1ad096e4be6c559f2b515e0d8cb19bde3e5f29a6ba4473d0c197ac88b895cc7ca85bb2ec34f1c32005e843463bd27e3" },
                { "hu", "4070d76bddad8e2cd125d3ab6ae71a4fadd5468579941e2689c61e7408a5cfa6eb9e3570108ede376b7c14e49b012542a8646c78f973210bf2c48c4651f16540" },
                { "hy-AM", "efd6e7fee83097993a17002300efa52988725f139eec360926e67cbd09f9934cb6bf7b0faa8085cdb831bd01bc4b598c0faf8bd0ebc44c146f376f5c24e7848f" },
                { "id", "8171d2f3771ecf40ad54361b99dcd95ccb27aa39516171d5accc0e1e926bc730d213c0e0048369c95d274d93451d9c7d6078aa916f3acdf51f3f7687b993a19b" },
                { "is", "69c3ee39ff59cd140a20cd62710303eafe3302153d5f689bb9697d694d97404e1f80592aaa522d45d1f36b43cb039f300881f3042c318995c4b05f364cba6e9f" },
                { "it", "95b93f16836d2a74d51ea3d11545076dcefe3016cf94246421a2b1e65ead7d147df2618d47dca1cc62d693942ceb15a380e2e1098ecbd3f90652bb93c6b3b269" },
                { "ja", "186826e90953a7f91543e7dbac7425f5db5d1792033e125ead427b04a4e316c71fcbdfafca96b9b3eacaaa5267d185a819d65fb9d580e7dd7212f4992133ca42" },
                { "ka", "507402b8ef514487c18793ab998dbe44af39fdd797d0c54318ac1999426ef3099798823cd314ba680200f58349f795bad247da241542842fcaca33f912fdc19a" },
                { "kab", "4c4e1badbd72e86e28a19205f70379ed6d0bf8473af8bc17b86e98946d52b85ea8ef898702328623f98eb1e1d98c39cd0963d57c2ffad482c815f4814e68edca" },
                { "kk", "38cf09bc164e1dc3c730a5bd8443f6c3ad3701a1e4d1f146451b9fcf4d4ff11bb2267ceda514364eb655bcb5efe14a1dca8ae44054dadf90dff6aa301bc613c5" },
                { "ko", "82f099b28eb49e6816f32d6c156c231a596dacd22e8ae1f7e43bad7098e71500a5d3cf54c8f65e59266d1f093ffb6b5bae726d3ad3a9d212379a72af23030064" },
                { "lt", "c850b810135485315940c010c3504a29863e558c9b47ac549b84ca52c077caf991b9b7e3373b4ad65bf6712a0c476d760661a470282fcc4450f368b4a8aa5584" },
                { "lv", "5a6ff024aeff3b01dad6f83d31390e9b92bd2afad6da419700c14c4502ad55e173b87430c2334ca8a4f40d50bce9fc2cbb7839f978d61859cc3f29c91d850b68" },
                { "ms", "0dce52b4c845d2aaf419f857295d6dda73d4315ab1c327110972fbee687a70cbee4b92487e26498d2fd94c5abc4f0ac8eab1af5962ac631c55b8e825af3f1217" },
                { "nb-NO", "e3dc8fd8042bcc81a13fb947143068a17eb4cf46e62f21b78d7b76090b9a5f16cbb3e8d08555f4333ac971629f4f856d76c220819c51b7982ea9535c9fefb092" },
                { "nl", "3d77bee5dec09254595c767de69295b91b599aae7fc3722ae671097a5fd48a0abf9db74a8d501211c7961acb02cc44efa2c19016d0aa83d1198c94285de6a1d7" },
                { "nn-NO", "edd624898d05a2b426f806463ce6fdd429d63df9e496f1c955185cde1332d6b52166f0687767d8a3c8e52712533d82ea617a674247f0f48f30c6b2dfc90f02c0" },
                { "pa-IN", "8f746270a280339d086d0dafbf2b8e3cad6867a792e116be719441e034d93dc6a5cb2110f825921e05fb5e5d667297c66b6e5c6118974a9e00971ad574d331e4" },
                { "pl", "1041e24823a695316b4bf3d7a23e34ec1abb4b8ff120cffaacd63ea64e1826b241ca16668d774be834286156b93191f4cd6d01ba6cacc71fd6cbc03cc0253174" },
                { "pt-BR", "05cbdd6d2157b8b4fb90282c91f0fe9d10c23a62f3cd05a51f8cc4408da8db464e50d3b93ab50601932f7d93ee602e649aea8eaedf859534afb77e4125d992ab" },
                { "pt-PT", "b2ee9d916afd9a68a763f94e73cc638938bf11419b30865eac8b5813c24fab2ff2e3a36b93f18283ffb9b42b79c7b35df79025efff816c4484ade64cfcfd8fc9" },
                { "rm", "390ad9c223c0b124e927878db6e2969675fbdcda6be402b17060fef496d29f8bee0a9b279ba60d3b08cfdd13904c74af0ca262bccffe63497e1279ef445d5390" },
                { "ro", "725288ae677f6dff43eff758e790ff3d2093ad5d23f87200218b12983bb6c053287de0de9d4832d36c2234778c4e768ffb66577253ca1db827f63a6801bfbb47" },
                { "ru", "479a26e8e469354e4c091fa8bd4a71860cbba1dbbdf0967576f65ee25e59fa56c63f75876d83aced3d47d4a40629843ef95e78b819988883463d617914dae981" },
                { "sk", "ebab8d1f0f6afbd96ff1b8a1848b36551f7ad92282cf459b6e98bc4513a0dbc5f64e9910591d2107f6d809a001f00d735eba3e54d1cd6ca32f785254d2957511" },
                { "sl", "96db11b8abe1a83caab4999ec2b235876e57185b0e692b4ed9bc763574d8ec2ee850d0ffceeb07e3d06c57cdabf64d0f5da484cf685263869068a7411025c3e5" },
                { "sq", "ffd87917810da4802aaaf18f3bd59d874fa6535a4feb0ee462b0fb1311229b9dc389771f45d285047fc97b1e691b1e199fde35f4d6fc3252bf87beb753eab8fd" },
                { "sr", "801e216c31ee111d343a427f0567831c1ac048b1358b2a58f1181c27fbc82db57f31da63e3dfaab081908bce40927238d07597318f2d0a99ed629676e8a2c478" },
                { "sv-SE", "6c4848b7d074deb4887d2e607c81e989580a667b29bef4228582f20f33fc0ebffa1484f04c3a6a07674ebb965b5de327e2db85a31c894021c27aa51bddde661e" },
                { "th", "f2bbe97addab8b571763449fedecfc56db998be0b3560131bbebddb1f594bbd4925e2050a4f28b68e7eb0b318304a074f0b643ddeeeb90f98f260467bcf16a85" },
                { "tr", "902a91427449fe6a69670b96a8e98ff2b70a8925b277e2ff7cdeb7b7992f8239b7f5ad8e131bc2b6a58f8a746a94733d85767068c7c31bcdbadba267f4bffe10" },
                { "uk", "f4aaf556b5e0959ff957846b477b77732ab5d56dc4ccfa98bda8679162b31da04b6503dcb69ff8ff0280a7435fab0fe5e53698e8952f19bd4793a1b62fedfc13" },
                { "uz", "7b6451d47e00a313d5e3ba1494aa9714adf3b2a33b1613778f8dd49fa7ec9f382089c0bdea092bf1e1fb02d9675eeea3285ebc80ceab27febe94e88f442302c8" },
                { "vi", "034661a84f9a89262564c8d192cb30143afb5b4b9c27d056f932c58ba62901ff6fdf712080a6a89c3e84c4e99d1518cae666edefb82c99c5beaf028738780c3c" },
                { "zh-CN", "95aa39167f0b2d5704f87fe2e60e23a5375bc321b57220d7ee8f8520064fb82410d9316c65004aaa518151d13899c4db417395fb5c1da73c56b5dce52aceb82c" },
                { "zh-TW", "de7d91125d0fb44b00e38c2696b032c346bc62990ce1ce56b7dfa60a46e5176df9b8d000c631fcc3f8bb7b5a827a9fea98f09df10814797be97a7bf21fd7a409" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.15.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "8e7d6511e7b6f39da1417c4dc88eeb71f7cbdead7e04e62ca83cbfda420af2bface20cb92e2c4c7b3b5e6f105e09010c2f3c456ff568b58fe4af65d7329b1c74" },
                { "ar", "876d566bcc647380daa031821069ba9c1ded7560c76a5092099b7727c5c98feb5bd46449b01b95403eedda8b23a794af1ffbcc582da64e86c2689bbd9404062b" },
                { "ast", "699c2c72d017f2cefe26f00b15739ea32028da33c88fb495c3a93fc38c8bdbacf545f73bde39fae78e2a5f2f77f86b5a00c3c261c37f835135b5c124d24a0a78" },
                { "be", "db636e7088e55a84b2b72e23e6e7fa9cccbf1a4fcb96759f883e8638e8a80e85d44b8daf355fcdb8538da38e40786f68f7020b145e55ebf34db9350cfb9b1133" },
                { "bg", "c209ebdfa38ae8ed1c9a6ba76e142b7e6ec497c7c230a7f36a016f5bd754a7fe4d1d340a1da5fc2292f9a267c0e8bbd969c297b6137475c20ef6b263e39ddbb2" },
                { "br", "f12d3b5a2aeac35c734f2babd7fdf826fbf8b1fe0a0c577da082014ba5ae5658d5692040571a79db4e7602e2bff3708e5688e6465b440a19a1cb3da6f91dea59" },
                { "ca", "2ca67533c29de4ac6bc82e2e9707900ea526371ee96aacb5b0ab22c2bb263767fd101bf2ee38b6541b8071630a7f4102bdf752c09fa6a4f93bd4629c2e34dc21" },
                { "cak", "5b70408e562f18d0e7f7780bac2a4e43d128d1d8f03a6b21b859b92d66a3a911cfbaab3ab792dfc9f3c31a8995c4df06361e196121b8beefae4ae94d60cfe704" },
                { "cs", "8281c452651b03b058bffb9d4a0588e6995e2cad7e88775da8d78b42bd2b904ec718fff62fe8f0cb9c790fc2e775c090cb93ce2021e34a147ecc96ef146570e5" },
                { "cy", "3b8354c1dac39b02d7310576f347e380f6700565d8291f0cbae484bb5e6751d5df1425a03c603cbd1e077834c3d63cf705d4dd5403970ada84b4de066d4770ac" },
                { "da", "dd524f1dd0f2b3e66ec75bcec9838a48243992f8157e0c4487c5f2aa727ce1439e74bb9e4c51431fe04242d8da3229e062e67a35cf55c883911a3a23d298f223" },
                { "de", "f67163787e978f159d32853fd94732a1f2177c2393486bb1a4227587f4132e0907364bed1463a90cabbeaca3d2b1aaba60bd768dc58ae23a339bacc8639fdd9d" },
                { "dsb", "2550e9134591a9325df783bc437204f5741c0eb448325c09773ba56d4cf071de76de5891850371bae4d3404e71e020f662a1a823074848fefe868f0c00379f32" },
                { "el", "0264d25a78b58b0884bdbc7881515c1aa7844f144ceae261bbc75f583f6497f2e252d5163a05bbaaa300711af0d0565ba04bed567671b7289f7b81cf465329d9" },
                { "en-CA", "e087abc323113ca8ac735d167b53472542a474a9670951beeabda4757a2b9b2d030096f3ccc28b858deb27e334c6ba5b52e41996284b3ce474dfd4f704dacc74" },
                { "en-GB", "53622824d55d9d7b6e150440e21f6379db20c2741e99dc55f7c25c09544b92549416c9da0f6e8032ba1c6b768df969784ebe4c273b10ff17c774d1609bc0e4f2" },
                { "en-US", "1f5bfeef945a6a7221dc81d2dc3c02d20608030bc0c4ae1d7b657b63e2b4f4e8ca72982f34643c3389c39431fc35895c5d34e7a729f9d4bb81d8f80603c61ad6" },
                { "es-AR", "f0be7dcd1540eb2ecbc59f47938f54dc029009e53c8ec0f39f77dcd2e9bff03f9ee865445d0eb8b64fbcabc184425e42bb4aafc9dcb98f58f33625e25f234736" },
                { "es-ES", "062afba30734fb381307a218445b7160d2bed7b327df3ae36cb79aaa36933e7fbf3684dad542accc2bc5f6491cc4dc034294c50259dccf21e8d56e151eeb4118" },
                { "es-MX", "057a24fd869eb400b3bdf842977b422e692371fbeba71df52ec0e17cc5032f84f9c6bd58b80d34a0ba3be892a8f295b9f1131975617cab27bc1d04e2051aeaa9" },
                { "et", "d0b7749776790c4e9535e91aa1c1ad9a5ba8988dde0be7687681ee9dfd62f9cb89273f31ea03f5bdb2af260b6a4105f1ff3fdc43c6f6e6284b23cfad4e23aa29" },
                { "eu", "f3b75255b3727673e24c9d18c3ae773678fe1501731b989df207b16cea3f75f6d13a33ff5246ccf1e7ecfef9750b6d852e63f0a250c6b9a272c2887632a86e79" },
                { "fi", "e240685e3e7c7904a7f199bba960b6e33d84c899ace1bd4cca1b9746e3aecb9f7f0c12bed067fee95acc7c796ba90da7788235a52f2598e8d24a669fcb1d08d7" },
                { "fr", "25c99ed104b07ab3309556ca5ea0dbafc5b2ad6447766b7407a4ffc26c080b28dcace22121840106bceffa16965bb6a3ec605beb3d3378182b00a84677ffa54e" },
                { "fy-NL", "e8a2843f5a76cbdd4280afcf073acbd0dc04b29543ab27b35723aafebf892527fd696758d5d145df0b75677e607cca88fa346ccdf5298bd25c54cd5fdd3ae6e7" },
                { "ga-IE", "686e6cbda62fb613609b9829fb86f39c4a57d6d7038836e8256055f2ec309a7475f48f2c21b3acbf89960cb69b01113972e2b263cff1752d01a0e41523ddb10b" },
                { "gd", "4e0bb8fe4067201e0b859d32d57313b45b7ce05a383e0656f2243e059bfedfb7ec8d92aaaf2096cfdd351695d04a50c684f80d3a8dad1b2db8b555d41c670d7d" },
                { "gl", "338dd8e880aaf1d5a942acefba5d5d35e5466dad5e67cfb8f0693df8c99517608ba6c1c43ddd018269a61e9df3d358be9df1be8477eb5446044a945ee9d8cd90" },
                { "he", "7476eb9ab525793662de308b4db6dfc713771bcddad47222cf3536d64052d1c903312d9e191a78446ab1bbaa567fb3d5b32a34bb4e9b8057c13560a7faea2ea0" },
                { "hr", "4c580acbfdeff12af6d874d5481cae2311eae5206e45c56076b1e33961e91a190be01c882c34f3d0ae970089f62bad7d65468305d1698a6f915c82bd35ca7e69" },
                { "hsb", "16628d91789e2bd4fd1dca63e0228c1e87a4288160061f3c859b8f5b84b5b0f3eca3d148abb92f82c4ccf645663373ba4edbe32176f3a40268eea8d1fa222f58" },
                { "hu", "de252582f9a992694809572ebdcbff7e02d1c78e69fb1a453f08b52da045be992c8311b637dc041ea92b38ad2b02f1fd3981b95411e3cf437b923282f5300d1b" },
                { "hy-AM", "dd044e044e556fabe8e81e8b01a14a9931c6492c517974edc4e2b6b1d4521f79f743e14bcb973b509af141f5398f0327813c057009bad4150fb7c50766d30a65" },
                { "id", "ef87e458b8889ba2f305e972611a198cb037b06e99a5c307c8f50f4da20c81f715321392f428cb721ee98f9b2fbd4151125876e15beb0ec626579f779bb27ceb" },
                { "is", "af313819db5aec54ea5901c22bace916f5cc5eb70bc7c763086b23f24096137e3c2bb3993c04e3fa9dd948626e07884340430f703e47df0e96f07ea0a3ea6f77" },
                { "it", "cc74068f5504f74784651c3ea0d25408beab18782a0206a48b107926562254bc4e3ea12e8ae51832488a313bccfe52f11b2cea43441eff15633696e097bcacad" },
                { "ja", "0d5c34f542f75beb4017467610a3cded72b9c85efc5279b80d9dab696efb49b1443a86b4c3bce60e6765db5395ecb0bba98c9e1c2bfec771faf41b97c8385700" },
                { "ka", "29fdc01ea3032b478e3bae890f7355a068be6a18bf97ce0b44b8c1bfdcc3270b4a004b027bc1cb68dc9c1d6fe867c02d3b2c55e34993e3bbb44078ced2f5eaa7" },
                { "kab", "cead3fe7a82bc295bd5603e2d1db94784906365576843efc1caa022701035a08f422d647a60a3e67552d51e33e730c5236e7c3562673902e263ec861389c4f74" },
                { "kk", "b910766b7a43e6ce47a35ac8ed6ae14fbfdce0774b775a8f288d536c01b64cc6ba980967f49e8bf9fbe1caae22d1dfb75db62295ae8f521bfddbbee8011429ef" },
                { "ko", "252c6d8014b4d1debbbdd4f8e5efcf5b2607e3a0b89498c761495156a0b35d8be73fc805853f0071f7b64c0584b7a69c189458e699552bf2744400253882997c" },
                { "lt", "aa254b759665d77debebe3c2e41ce246f749f79bc9750fe15dcc84bd3f69bbeee6b7554b05cfa7d0d0d64c5115a2fde2506fff2a033b1920f8d6d37de983c5e7" },
                { "lv", "4d4f12f97f9b78177936b6ea522ecb6d429247053576e803358436a1a3fc5fffa85b3544582835fcfbe819d04a8fce5026fcda7a000364617495e1ff6ff37b24" },
                { "ms", "8942fbad53809376867c630153d9167c7f4b6e69f8e7f65b7be1189e2683a23b69018f71c56533c2f0fb0982a20361c804a36301f9e3f51b99fafb6580d5a678" },
                { "nb-NO", "98496151bf74049b4789b3eaddf71355c337b7a5f6a725f8d8d5fa223edd834ad55cd57bd4764e7ac46e35180e4702d711a4a50d7cfaeefc89bdc1880aad2e03" },
                { "nl", "88e3706c3e4f31eee65ab5d1a65907d88156ecb0b9dd314f0cd439cb940c2a8978e1556f6d0ef8cb81486e3f4d4348ce3625095a07672bb9224c75433c86ebf1" },
                { "nn-NO", "21da816bcb1713c3987b9310aea5bfba3395a006ed1feeb59dfc85fbbc6d303a34052da8e2cfd6c1da1f691934d9d578aeffb41e4124c305ebc45902c1ff83eb" },
                { "pa-IN", "c43fef471f72d1d8700e2912f04875fbe20be0ef8955779e1ad5f29c54eb405e957d6721d101ec84a113f3d5e8434dbf6c1d8c9f84cb63af6ce4b4f9ea4d80c0" },
                { "pl", "91c8901331fae9c48b8c2009b418533204f39bc3202a7e10358958b49f097bcad41e047a1dc965e5316605729c347d918530bc5fc10948d40339a7b3c9070eef" },
                { "pt-BR", "8f9194f2ce08109258e9b37b33ded089fefed8cf28a15b2604f8ab9e6ace114181d6b8bcf3e328e15e507808f6c2769a220dce700e1e25bbd302e57b911114e0" },
                { "pt-PT", "0c7d4e3bb3ab9889037c22416b357d594281448ce947450b530a14f0dbd013be1a7b2474ad070063f1642f40937dbcfc64113b52d48c202b7db795da874b9ac9" },
                { "rm", "cbe5c62e9c237e417ecb0bc128182f61f654f2b07e1a87e05702988ec0ce636a93a418a901e8e78a8928fa47c9f55b0cb099700aa58a64df4add3d9750c0bf2f" },
                { "ro", "e763fe6f0c9654e447df50672f32eba7abd2cd32994d6920228a9fa015c9604d9922b204475601260c8b5171708ad33ab5c6bc61179df9ea920a13a29caf5821" },
                { "ru", "5a03fc4ac6a865512705d4e89c33c4735033e73450a98ec5210a4e4769f541e79d4f68515c7222dc00e3551558c9e32ff799a174eb046a4682221328b719fa10" },
                { "sk", "7afbf9584d5561886feacd4f9e9018470135c866407c3b1a25d5a5232edb9b95742318449166976d46fedc31baa320673d628de0bd106a5ca5abd2325acd68dc" },
                { "sl", "0e282f7a92ce366975a165afb961b7f801d82f86d0f97ff21f73e13a93c92f492e96381080d16c552aa15e0e0d317b2ffe451bba4ca716f00aa95a2525ed7328" },
                { "sq", "98bab75f7778e485350fb6b854562be5cca730ed62fa03accbbbae39ef5aeadcfabdb5556c71994e164196e4debcfbc27c824f807c5fd002f5e7ec60d86f62f5" },
                { "sr", "b844c4ab722570c7d3921ac117db380986386793236ab8d23f9c6eb761a9aa45d448a381b1f15aefe64f14798b05dae865e5d8e44ea2cb1ff44ef1788f3f93b8" },
                { "sv-SE", "b9078263fabea723bc246f892818a66519259358ef23b828c5f113bd35e9bd5a73e68f30a6516a9ee1a13d86b46c957e242eb6344f4f7dd5a26d67ab05ce3a00" },
                { "th", "29233eaa116fbdb012cd7fff7b192f8c985b60c3790f4c992c892f9160a457a39734f1727950d083833473c062966f0975b21134c895a1af140a3cdc3c5a4223" },
                { "tr", "0669590ffba0350299ab1244a0a66b443da8c5239b28e7ce82c4b6fd7a2d18a8fecca1a9da84af5c1065ca1260fbff6f0e52bf29ad57a2beffaf62d5024bda4e" },
                { "uk", "225f28e4bcbe25d0da6a2378f6444a29c8527edeb9eace68562781cca120001acbce4a757b4f6ff66c9270dcf75d4b4699681ad2eb3a8946e89e3400412805e6" },
                { "uz", "63fd7cb141dd13118e44e00a532e70aa1400eeac617589d35a76188eabad79e176e616f583d31e9eb35bc4e9fe4d92e8dfccd7dd6124afe39276e4c6650183c4" },
                { "vi", "d29d02add2b7c457b4001ab1881d36d316efd1dc9d5b57110066d297569052a525d93accec093a7cbc473d75296665608f9834dbcff8e3717208359700dbda67" },
                { "zh-CN", "5bc337fcaaad90824b062f2f7eb570eecac4241933d06376d9177fd7aa2011289e9ece088c2ee5bcf5d6550fb166149658eaf7ef219e96965e01b44a326969b1" },
                { "zh-TW", "936fb0f5a3535bfb0f104e61476417caf783b1f6860b9b761d54f2b6df1befb9c9fc4d8ea9d038ac7390cc5cfeb70378c77757943ceffb73e402f6b047decf7e" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                string newLocation = (response.Headers.Location?.ToString()) ?? "";
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
