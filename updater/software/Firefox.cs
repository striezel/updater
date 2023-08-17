/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


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
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
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
            // https://ftp.mozilla.org/pub/firefox/releases/116.0.3/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "7de014af22ccc27358898f5db182e4063d226b6353c342cf88b6e80862c3b787f9650dfa2aa422787d28792bdb115148e02a56221d3072039d402b77be73f3d4" },
                { "af", "fddd191815c97828596f168febcd6efc3b16e05fbd3fa9dee5e649751f19e88778169af12353c48846b8b7b8f559c7e0db7140d84a3e34a6dea3885f020c86db" },
                { "an", "08e1c49d22e706a930ba876448b424fc02362671f59858b251f99c9983bf3b7e6a513af1dece8008c2298731c3fffb3c60282b5edaf6a5669c0047f6991b3d2d" },
                { "ar", "3c2c05770e222bbf7248064fbee4824797bfccb3b510757139940524837ee3ac16aed0f7c4642fa39b098c2d0fb83471b265bd8aaae07931bb7150f0aa68e68f" },
                { "ast", "af5ab7233396e25e85c48cd34df1690a568dd07646f5a166477fa19d02f7a4ee0d6b2786d77a102247a46212e968dd1efe02ce19c61ad7292359f980e7b923bf" },
                { "az", "76d17149f06cc5e47713d218ef44de725b9b7489a3b5cddcf4a314245729104adaa2b616e5605a7205b6f85ea84f4cbe5dbeecfad8722f79c7d3de70f4823d1f" },
                { "be", "5a5cb5626beb2c82b29d22128fe1df98b7a160c6fe04361f311b821e0b84cfc83cd39a74b88c4aa856b2c178bef8bb5f3cbfd4868e541b5f4fa89f58a6362be7" },
                { "bg", "cf7f2eeb247838a7f4ac12528462a63b3edd9ef8206d6ae4431043f34c13adc1f357613d7385d124a070486858c0cac9409513a3d328128b42d99682025501c4" },
                { "bn", "b848bb4704bac01ef218a926e6a140be9ff83c87e14a70864f44c4a36bf862385a69df40c63a31cc6379d66afbe422279230d44cf5b60dc28fb3d9de806a3b5f" },
                { "br", "32c3e60ad60864aa51c1590d928501f3fa5898fb05f7643822b5a572195d5a63bb9bb83eb93d7eb3fea037204eda3430b536ae90eb89b306d26032875e8cdca2" },
                { "bs", "3271b34ce2c47acbdae6b772c7cf67613abee6e9cfcca63e39950221c843b93f897645a01b935d64aab86b1506a2408bd97b9045c134101ca509fa4dfeae44b9" },
                { "ca", "086e0e3c8d7d5218ee7a183a8a99fcb025c60661e494936c2edfe954c739c7c7c579b739630f741017fc8c3438fabdaec11407f7f384f28a16ee96b578dac787" },
                { "cak", "86b3ac19875e18c85eb6a15a7d0d604122a43133c5566594ba840d182044add44867ddd031cba4a9729d402857d9966870f2c5f881d54bfc6daee9d0e038818c" },
                { "cs", "db3271ea1f97b54d0cacd3977d478bfa072df5df34e114c452cc94e2c4eb0f658f4096b11f69997ba64454c720de51d8096a441c135ae48d3925349201834d72" },
                { "cy", "45ca5ae0c02e372d044423d39d5e4ea4ecf1776f54d5e8d587a3369f4ce096e9a794d98106f9fb0ccc16810a772859e4509f874cb4920d19a606c29947713f56" },
                { "da", "fc1fb74cecd1827a5bb165e6e27c03e568771ab5b216d36c60ecf289b53ee40807da20da96b68c2c5bc1bff72762f5791f6f22b8b038bdaa9b79b889e70fc499" },
                { "de", "9d4d5142c8327309c501c3cfa45631a06586a97f4073d31c737ca75537a855de573738fb20a0ee0ceead32a42904dc690017602c1aad194e7fdc18972986edc9" },
                { "dsb", "8ebfb6463bde58a6a67253ba96397d2d9cc69dc8959340afa0309dd244112ac38547e7889178a4579213427ba74feae59041a055a341094c169299bb8474d1c0" },
                { "el", "8bea41a122409a8a178ffb3efb7cbe308bb08211f2ee8729873daaa73ff350cbd47a421a9294232fc8579709ccea2282b23ee55cf062d3209ee83ea21f80e143" },
                { "en-CA", "0482adaa198b6b9cb8bda01307973c6411423ad7357053d7c52d6baf0a3756cfb33bdf84aa69930cf5d2f6e5f97ce182d4868608a3491bd2e990cbe4407414f7" },
                { "en-GB", "3b450c99e14b4d0e3228bb88f6488f01caf7f28aec7cc0985c520e7522783da49b16dbf79a3bb83c352ad290c70eeb460f119e50aeffcee1ef8697b1677a7ab6" },
                { "en-US", "75a254a4de990152cf402a1c2e1eee358ccb0d44dbe817fb89aeec1bbce68266e74ea1951651d30a71087082cc29515f5520c50120fa95e7ccbdb5b9a71b2243" },
                { "eo", "42481c3d5fa34e54b59ae4c5d992e8a17ab14960df05233f501725d411f10b3654b7d7c94c0994908a4f6359c414f49d8e378eb0ffe707bf51045a6481112ba1" },
                { "es-AR", "f693a1dadcd4cb811bf6650431f0cbde0f830f22804bcfe63e0188cd919d42cc2e20c2762ee5d3dc377375344de4d17ccabd21fc296d919048d64724c5cc2a19" },
                { "es-CL", "c1483462613da03662dc58c8cc4b64dd1afe163f41c1b9926f97dc16a2547fc3885a2a302f42be4b35a92c922db5afbe017e6f31126108baada663e91f432c31" },
                { "es-ES", "60bd153db758062dbd255885706a6488e346033b8a908e5f462b5292ec1974f846e74f1597394da69bffa03a4327b779ae1786580eae007216b00e43d52e4fd8" },
                { "es-MX", "edbe23445345f698e905ac7bbea2ab6119909f22093b12d4ac3b93b825217e996b9e98602f27e65437b3c1e4fe3a4d749327efb9073416f59919d7947bdce911" },
                { "et", "2bd66f575b4a2f8fcc5f6129d08cd847e28d334588c2e78a7c4fba880bd194595db3c45de0eab8286e75b602e8a46404e81113d6c2c3cc1271a3f53d65815490" },
                { "eu", "d69ddecb529cbe76015b99fa187b5fed02950378500fb831f9a5c6950cd740426d5c26ad915b69b5274a73cb174b33323968270d1b5ebe6e8261fd756859d6c7" },
                { "fa", "e6b3dc5c0cd62c8c757e0dac854bdb6ddd6b3ca9b3494011487d7b287326893cd93156c3b3374e6f5415651ed583bd27306caaa958008df1fbf1d7db4c7f40cb" },
                { "ff", "3c5dabb943f31655af4dd2ee78ad2a75ce1ec7bfcaec4a830944a72897028af35edf4ce169e1eba0e66cfceb3f3f0723a972f73cfc9da8dcdd03c13cef47c828" },
                { "fi", "49bf9cd8bad67691dd7236ab322d4a85b03a25d2e4307c7d60e5a64939a3c84e4bccde12d60b239549d7a374492964096c38c18654257a440f2f7ea74e0ca1d5" },
                { "fr", "0f485ba67a1559e48dcde4640d786070d9894b1714815161a0efd4b9eb35ba5606939679557a81fb4ce95a3c98668b4f1cf9e97a60d604e0ee7bf6cca627af69" },
                { "fur", "abc6fe024c74109546abc2008b71557f2c1dc6de59472c17b80bcb4394652d382847253f37b3a721cd9dd7f57cf690dbf93c4c671371d16b8aba8891ea762bef" },
                { "fy-NL", "2e520468be68306e538dccbd9971133a92f003c530f1138755b5bb2875ce29bcc7be464687ef5dbe389260cfa91f31b7a4ae6eba5c5f74fac0083d9796aef96e" },
                { "ga-IE", "cb53d805ed0b9de8c79b7d3bd2b886060b1bd691cdd2be6f42ad1f7d5a003c3fa0ba94d366d69e75dc0b16066c4759e08dd990059a6166416bb074685ef9d73c" },
                { "gd", "1612d7cc7c1c9ee22c1d0934880a6f6605a00885e28e5f120c8261abebff6cff0b5d7ef14e30ad66800eda872ededd47a0f74778fc00d7c59cbb345a192a01ed" },
                { "gl", "84a750dc1632be3e45b328a8ee0fb1481d53e2e822c2abbffefa043b89ce4b14913f235911527f45e2bec8a20494737235eb50185a45f7022c939368ad89c80b" },
                { "gn", "d0c1ce074a02be29614a3b29c55c7b774a9f6a7e12d1b0d55ec4332465e342346899d0f704fca37febdb265ca755609584685839f30e1f40d6da41864e5394a0" },
                { "gu-IN", "10a404a2fd89b0a87df0791b33ff543585dec926ff5b436773968fcd460274111e866ea2bafadfef62549b607e38130816f728c567d10708609c84cbf20b8c07" },
                { "he", "6c144ce7abe923e898f65c1fa9f71498bcea5e1d32e9df635664450b159d3b7301abf0c24bf14a9c83461e70288e6f3bf4f05428e33c313549f84a7c7d636972" },
                { "hi-IN", "45336d08f00252d098fe9bee807a2a3c204eaef0d0c7b37b5a7ce492b2c260e22cafdc78a47d0332aa31e3fcb772dfc3ee2dd486c6dda221f8fe6a99bb539c1f" },
                { "hr", "214e219e7410007198e707945db19abaf8e4625490899171184c65f450de3dcb755bfa0e24d1d4e7839d7b19c87d639e6c1993f9d5cb9578e89ea29f060a8ba4" },
                { "hsb", "4b1a30953a2ebe054d570b3bfe248cf4055ddf7419b2733b676e2228e1544385269640353e46ae9efafb2145ab0447bfa9e903b58042d821b764b1536504d583" },
                { "hu", "96f4d5492f5880aeecbdf6b3e67aeb59cd00bd3330d7ec1e76a172ba115b53be33abd6f588272b4c494de703004fb0af032b3597153c2375f10b1be2f15a53b1" },
                { "hy-AM", "299ba6de28ea858dac660b97c12619f0f56ae96e255c980985819ec8e2e040b9f1cc250af1b3cf635709fcaeeda62ce60728c5b9f2a2a4cd9e565148bf1badb8" },
                { "ia", "17ca6dbef4d6f2b3a173b1914a42d525d599687ce361eae3fc3c140d9bca34c5527f2b948aa4085d6aca8b96b2bde63ec794e103184c9e92abc59c918f4800d5" },
                { "id", "38b833110e572e38a030c4fe093f80cdefa9fb13c7db29971fb2aaddeeac0f90fc049671d800c308a6bea1d9a95cd507c88bb5b6af99f7639a06324fcaae4208" },
                { "is", "6d4f5185ba8d1e9217a24351cf44bed03b24955f027db20123cd80d5bf3a2aa6f7d4dc0bccafd8604377c258139df2072141b7b5e7ca22e3f18c2f3181828adc" },
                { "it", "0f68f667f7196be28ae3769c92ad131affb6515b4fd2a3fd8aa9f24dd8b84ed47f3f37c64349d81b5a1b646985db0ca44ea848fd74f99ba4285cea3d23627f7d" },
                { "ja", "aa7220a4b872a99edbc0551f981ef96c27a0c1cdee9d7a8d2c6b85193b7fdb79ba73976de4424617ee2183582f0146d4f429b5d2c39949357fb1b267097ddd9c" },
                { "ka", "57e1e3b61db8b9aaed532ce822534914ffb184d67fe249efd11b80c7901d6846498941c77963f454ea1b1fc6976c4efce22004c19505bba64b6baac76a689b76" },
                { "kab", "418a4f0ade490b0707c2c1c45bd159fa9a2713bff8eead6c189e9d6866d5ef2d28d179d4ca640807fc586fa8f0c0239e36d0b6723fafde8fea431310697c8d3d" },
                { "kk", "bf96047e9a240d09300a510fd6bee303d60ea1489ff40c6af6de0e117895e1ff43602ed7c04b2c0dda2c3126b3b0527b65603371cfeba08b85701e5986cae602" },
                { "km", "2d1108cb836e5dfbd709b6e3d994de2702b2924d84954f2f9e6dc378f93a2738d445f0cd013a9b8fbec4d4002b8c63623bcf11ff86df546cbe51216ba16a044a" },
                { "kn", "705aabb057d0817eb12e5af2959ff0915cf3ad0607c1e7ec6536e53ed8553f368c3a821a053433145e447f1a950b7c3e051930b0e9d21bcbfba919806039d720" },
                { "ko", "dda99a30d7eec7476f09ac1e5b8fe8b74a3cb6b381e9243e0b106eb9d303e21ed2fb2ef270d29ddcc5abbe78168a050510f76828349a0cdaa13ad7da674a228d" },
                { "lij", "c09cf2a84bd8bbd32f2ed90f921474bfd6267dda936e2c9fc1f0cb360a00730180b4cd56fab1b441c20b211904c4774292a634542fcc0b9e383ff9e4f55cce59" },
                { "lt", "a2fd6f50d29ee5e77e7bd4b9f80efcb1aea7a4f60237d76542686294168eb2a1183c5b3b5de8264137e9a46ff0858edd1412d8326224332d4d0942a139167e0c" },
                { "lv", "8d324256c02eceffc05fd65caa9d5dd7b928ce9f3d026c9becfafd223c54bac998c0c6b4a9386bd24978804f11566cad9edb5dce698a5ef4d13ffda945fcfac3" },
                { "mk", "e5fe29369978658361eca1e62756ba62edfd09b100abe76c96b9b276f16294112adaf2990539644243464d5cbc823ba4b705a6973829e2ad75e263b135449b1c" },
                { "mr", "ae1a34d19f9fe61492ae7fc53e632efa8acba26201213f55ad02c3513bc493f1178efbddc6ce5cbf1efad527d41ce3fb856205cfb9e5d897fd5cfc5aec32833e" },
                { "ms", "997791cc977bf79ca4d7a2d5784a20aee602048b7421e326433eac73a24701b0772da676dc502af9e602a71a0d9984fbc97f6740b8be8014ad96a4454c7fadae" },
                { "my", "f8640367d4a4a61a4a19e72d394c62bc10d211c2672a5dc3843229104da602e421d0b9dbee0735e3f3048e511b34add4511c2c23fe9e204a9ae33d29e7112a32" },
                { "nb-NO", "d5f656e21ff6686ca22fe6e2f45fa3d040316c8db9f034db79aafd4c049c3f38526aeb0a0d1576cd0a1afbbf04ef7efa69633704daa8fb958d31fca8dc68a5a3" },
                { "ne-NP", "e9dbfe9d3690c2a52b6cc328ce753755290e3772d7936a9c42384d93d73a4e4e5eb1129cd14de787757c1f6a3fe90f245fbc29b33b5824b963e7f225e84ef438" },
                { "nl", "9173498dd55ae8fa065b7cc14ced57f6996356f98f20a91bde7291320bdb307adc318d9e5822551b342083daf18519aaf824d6a3a1d4182a4aae74528c97c426" },
                { "nn-NO", "fba94a0ebcc9b8c57a4e801d6f3d0fc683aa8ad4ed21f347f5676673b78833c1547dcd7dad338d2207ab8c59e123b90d03d126a99837e416da0076ed03224f85" },
                { "oc", "9bcd688e45ecf48f2a02f84bc2b9abe273ade75bc6514eba6449528e0d5dbfb031190620299907693a5765af9c861731df765f3b08253f0545220b4201bbc72c" },
                { "pa-IN", "a7e9d85301846db271eeb49284a1c73135756020d74e07d2b29783bdfe3b8826cf30aa27065594f0527fbaa40031c79831b26e68eacc7569861416c43261e6af" },
                { "pl", "483e50dd85c9c01794d15ec2879b10ce2d67604e77b7e358114e7df59f00c1d44fb398922878cb44a3ee5fab8cf9497d986d2dc48f3c0050fe0b889e2906d3f4" },
                { "pt-BR", "cecfe19179507cf82816eac065bd65abdcb8d3b8ea5867c89338536c6b58294fd0d7632ecf1a32201b81399537d0f896b5c4d9a7e17d45f3821893fe60f90680" },
                { "pt-PT", "b5e2ce5828a55e0b4a39d85500a06c4433e74d1c59d0b151f327542baa28387a4b936177eff8fec963181092b3c6e81ca8cc65319dcab386b21b73c17e032d4d" },
                { "rm", "68c0b3bb7f876ec77b0fac5fef8717ba17feb07c201a99e2589f8da497327246000db6cdc861dd45df959eac51d0f86512cf73a41cacb27a4bff811041cd17fd" },
                { "ro", "07db70317beb44abf9c361f558307562fd4c4b39abb6f2b7ab07f0f473001bbb8ce16000f755076c7f9417b48ac4ec8e372f923419433b965b632fdb74823cfe" },
                { "ru", "20df9f03de8d791c750ada9f35b8cfe0234b69bd84f450fa16e514cc852ab66c6fc2dd9d86eb34298d48ccb47517af641e72c4fc82f9d758b36154fa925cbb95" },
                { "sc", "654848b0e3b2559302f91d99097aba9b002469668c29183010a1b2e5addd5776a83f37d852c79795a42949710cad6db386959f177505e28510007a91774a8b4e" },
                { "sco", "fd5bf17e4d464feb897c8d3e5b13c5be76bbc811c7be97cbd44b7b6d91c49c955ac138d90bf4946d0a07baafa07f1908dcb0f24aeb2c43cc2a76ba4d1a1098ee" },
                { "si", "4347c61b662ad50daeeb57691ca8c27d337a2645887144e850d25c54cf0c88c8d4257e1f684f38e5cf25098c278f8817c47dff4aa27a33c342ea58f4d294786b" },
                { "sk", "e9ada022a8b45aba71de3f939173d2af00dddda28671804fdf790a4e0ffbae9e29331df22dd4f799388ada78d2f4d9bbf88c36b15d98d009b32559601102e852" },
                { "sl", "32ef5236b962b62cbe22e62f12c5f2614d644a2b4113d068ec1724c94f663dff25e8f225a2a310eb675b98264e69129dee64727e264d50828009da0ef2c7e84a" },
                { "son", "c94536fc8dfd734c0f673e587525bff88c266bede923d54ddfb5b829bf168a9c0952daf1b0ac81822449f45e2b40eb63c96522509c30e7c3cb1cba85bd543f24" },
                { "sq", "295a138500f8569d01ea902325387ce0cf9fbc746ad61d7c5456ccbe8fb84d8ebc0972f40fee8bf30657cbd4d93b8fbab295236d32fe48e5d9d8258450ce30d9" },
                { "sr", "056b35da9327358125620f6396712bdf75582929b279a9c2d9cdf9c7c5901735cbb73ecada4116e5e76b641a47a1166bcff08d9b96bcde27fce3303b8392f89b" },
                { "sv-SE", "1df9d0e98556ee6b69f19782745df1254f10cc2bd80fa81d5fc8501dee6c7586ea61cf9299199c6be69890d53e725ba2686573cce5eaa65ac29699f9bf4227b8" },
                { "szl", "e9b0e53ecb9815f52dce64616104a4f04d2f43b0a89affc18934c8133e0269f23d9825f0ba84d0183237e456cdfa5ce197c7d21555a51631f681fbfde816918c" },
                { "ta", "2423cef52979b6fab70cbed9cbf99a0258132ed1b30c342e1a5729541ce9840efaa32f9030128665aeb7f4c126b93a5a889737d4069d8fd8754d7118e6ae2061" },
                { "te", "9dddb34a745358ef999f85a35f99ad82305dede5fbdb9078022cc2fa8d6840fe45c3938fef5923acbe61798914ae36927b56c2edb5f2020f0faba58e8d7596cc" },
                { "tg", "a549a7692431749d7297b4ea9d71394f52282212820b0d4b27305a241f4edc8392768fb52e21a35c4fbaca263d10cbba2411b1528eb974716783d1ea5c3f5b68" },
                { "th", "6d879bed31ba61a6047299389fe302ec1dcc38bf1a16433391d663bcdea2c3989bf09263146eaff8ff086f6d6d4860b25b8f5be53a956dc277f82a38253d04f1" },
                { "tl", "c2b39371cdc07024898db5783a4f0f5ad310e3142892a3d1c7a3a275c978cdc0039be0ced68cdb12eb61bfbd8110758176ce2d3dcd0a46a62eb26acddda967ec" },
                { "tr", "f8ece30334bba9d34923c346ecdf4b5ab23c26fde20b36a291f2cf09e6b1c81999e0546c1e7baf54c3082d23db85af0ea8000c67de6cb43f0496992031a6e9c1" },
                { "trs", "faf7b1a9ff117dda72c5fe527d4975d1dc15655a1b65d27c588beaa130f39f644a5e198cdd565d40aed672592c71a0845bd7af4931cedf029c70930306c83fe8" },
                { "uk", "2be77d27fb10d57a197c594e36f67d80b7aabdac25354b55b0abbd6fa046b8655765a466cbb1fa34b0f0626e2954866a1a9c72970ae98cc9568f03b563933d86" },
                { "ur", "59f1f4eaa9110c0d27e25163c54d6c51867baf58fd5e139ce8d185aaab3585df93960a01e233beeeaa3d0558bab40738c82151abe7323921b8b62f8bb75af627" },
                { "uz", "352eb687c98ffd944681496b533737e71f7e09c801465113a5116dfcc5e1d25c2fb784d1864199ea6cc67462db56b4cb98f199946b7997707b9b9ad1f0c7f476" },
                { "vi", "1265ad047c6b23eb6943ac6164982c9481abeaa38dc9285bcb9a64fbac4d3281a1a7f831c3185f367b4d285439b06ad65108e73824528b7dfa95a01cdc915ca1" },
                { "xh", "41e36eed8a8ddb9f6e20297995430058f7580d9826e3e978eacdc3aa8ef32f46b35243ebc4a182f70f2ccbb2cfde848c830bd12bdcb8737f3ad79acacc5c3f63" },
                { "zh-CN", "cc3941192a498b2a24ca792eec7b5298095c8cd815601ac1374a8b87200c21e0883fd7cbe4a4178a820d8bff6e37bfa99ad538abbe0774b583d162e2d2ae5cda" },
                { "zh-TW", "e4aaded2145c81abb42edb13beffc8514d7f6e68309cb3426075b84886dd70fefd24887bab5223b5af7070efcbab34cea8d573e20fa217a2d1ffcce0a9a8cda2" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/116.0.3/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "39a741182d235b4164391331223db1066449f9db8a4164e9f7380eb290b7793d1583983bf6a02c03e1919e61634dd996f38ff2e17b077fdd7d807ee2dfc853b5" },
                { "af", "13899a7ea4857d733eb625ba314495d44f4150bd3d424e0561daed3d587b7f977df2d40d9aa717dec2f7059e334938033dc5c14168a6f60621a2ddd54c4d7593" },
                { "an", "9548302188c3dc975f60036a3d4ad0d42e7721bc7925501fd47acf47515dc2da56e81eadfe72d6c6b84c18262460b4d2b0d53c358968967c7ca75c3a2c106f6e" },
                { "ar", "10f11a655315af0dc350f2df8778014809db64a658a9a8d0d97c3ec8f394d24169babd760174a557667ff598061cfad8c88c3f7b98b28477b56b89bafd680995" },
                { "ast", "1de6b729ec6d3178b034e87697873acd5425e04ec341baca3d447ca57cda477b1fa3cd49f469716d061093f0beb5a9d4b4e57911b0454a2833816d2a173a8544" },
                { "az", "c9f45ef7f48d5c5e3c27d1bf5647d697bdfa4253f521fcde8343a38c9be9d3fb6c8e4c92d2b0e42e6bfba03c833ac961186c6ca30da7ab6f6a4e5238e640765d" },
                { "be", "5c7eb4634b0823e6336ff6901e666d071b922dc6bf0e1dca0699ae46d94dac8584d224935ee8d5b4b81540d78226779bb0b6cec3e9892a094c2149a65db13fc3" },
                { "bg", "36e48d83770b71964c7a40e421d2bf85edfcabed6146b96c5f67bc0c8924dc4fd7fe6007d75c07b2fc193915a16fa3000b3bb6fed2da3e1455bc3d841978ff2d" },
                { "bn", "3fa5ab4a14364b50f912b17973eda053d0c3b81f66f403557ed996601d97ed39b5b1fb37516fc34681ee3d3ff17b10b7365e54352b05f41cea619cdd48c6fcd2" },
                { "br", "e1f264fc6416953e1155113a797fcd36715ad9cb5b84560e44a3e4ff31d40fee33f54265ec83d047451072dbf1ee7f954d2a1fd75558e539173775ccd0e2846e" },
                { "bs", "ed5faadd46a1d1879a2fb609e4d7c340f2358a2be2152ad6243b25290c5b830c6fa55a7710e4d521a42038c75d6eae24ec100318a859090a76a9838046b96045" },
                { "ca", "38b8a1e45228eae364c0de9816e6bb868bc87ac1e323126ebb08d361671ae7508644ce44ca1f932188a52614398c6137d0f754b211cf80fd879d86c40932fe29" },
                { "cak", "c1ab430cdba851af4516b62019ec0bf19e770c29c6d64e3ca078f40f6dad32ac0c8e2ea6611a3d781d62052a4e205fb12799ab7f6b66fcc1ac3d6ace945bcef4" },
                { "cs", "b792bdc8796b30d264ca0b543f43dfbee60da46b052eba8947e78a3ded18afac76ca8bbd7aaa705ca0d46a0542f2f7b403d5ef731cded67472ba7fc55b1803e0" },
                { "cy", "413b86e100092294504703908e710f083aa282951da2335d825c3cccb437cb0594ec39ecb6b93ea3cdf7979852e12cb41d23e996df12c13de3cd04663e5352f6" },
                { "da", "349dda9828d1e7a7602b98b3b48d682e1afcbdb5da7b6b8fe3b2ea0af61ab6c24bc6ceacfdf121d1975b9f9746d44b92c364fe8397c1f5260b3c80df4f8e1e5f" },
                { "de", "51fe48a86281a74c6c4523ea360b603849a9f2ff92ab15ed38678d11bf4bf9869b4bacde4501491c920ec8be17a64c9a0cc7654c6e2eaf750a1856a4af7c3c54" },
                { "dsb", "6df5a63cdd53cae00ac79cd54b789e51ce0f7ecf9488bdb8f077a6c87502054f0e846169ce33e1faa72d3bf31cc0c80a56762b73565ec9340a709e0db83b30b0" },
                { "el", "c4685347009e4f8548c046823c3dd9b2b7db1f107724085da97447fd5bc2ebc036e5d63eed3fd932d772db892eb1ffd0d43c136c2f0a3576c2d44b2ce5fdd18f" },
                { "en-CA", "47fa0c777f2efb0f8df1ef85065dc3f8c3defaefa2fc5792ea59f5c976940abb764a8eea4e185106f1fa3f38c04179128b0cead7db21507d3917faf432681b56" },
                { "en-GB", "b3afe747a5faac6b1cdcfe642c279f4006f217b6c3d14ac9558b29674f595a5cc1ecce73f33495947c53c39e0a65023b68bd689892fd3816f9984ad69e8241b4" },
                { "en-US", "0b6c915f63324e16760b4d4d97602b537aec44cb872e81e2e6648e20a236c7797eb7554ad5353620d6681b0edb290ffc7d8ce8dca80df674ed5b364d707ee6a6" },
                { "eo", "c64b884f1dea1fd9668034fca8195bf3343a956f317fd9211c55ee8baf3b3c59ca954180f6aeb2c151e2a56aea629317bdae061a47d2dd75e52e08f08902eb43" },
                { "es-AR", "264085913a73f1ab4ccfaa0e961291c849a6ea149b335a57a67790a78f7101724afa8c5a39b075d7e3ad24db511961685b4c76d7ecd1d16cd6f33407b7ffe52d" },
                { "es-CL", "da8153fa1b7fa33165501807d44acce1ec878c21ef80f779819b5314710549057cdf11ce401385b57dab7ddaa7cce811cba1c28a8098426807147e9f670c2c29" },
                { "es-ES", "43cb83d26924360a85cd1674a82da857f16cdd8a237519093b306e6d95d95110bd4f86b85b30fa6482583dced61154f807e9e3f0dabea54cd6e9d35373f9d00b" },
                { "es-MX", "ef81f5564733a9a1f4dfe1e96c90338c49eba60d2878a81927e9c2da43259323ca254f209521cf09b4711379c84e49765d1fef0625b6e8f5bb24adbf5e4ca776" },
                { "et", "a7eb7456037d531219f0445cfc305fb9586b7cf891cfd0f684ff769ffa4d16062258ae4dd27119f27958b4c0704b6f82692462e0e588bd6a086c99aaa6874b19" },
                { "eu", "f93d6663c92df2a19ec3822c3a74cd88fd6c8d66a5ab393c396b809ef085f433c1d8830232ea047014b759390c066e6c4b29be41041a4a9e5fa2e41b51464cae" },
                { "fa", "6f24a52e0266af65a4deb16ffbf1799adcac2f6791155e500a9ee21548fa3048caaeb62a1c21435de340d5c717199757fa45df60bcf0a32ceb26f8d67a881ff1" },
                { "ff", "c01438bad1137f8a7a553c8d3235b6eb6a35b72e68387225794abb0e0bfbf4da9d80dad6636eeb5856bbe19c3b3dd4cbb84506b3cf63e44c22c67a782602c648" },
                { "fi", "d9c14fd63dfc22c70c830f64feeb435028849c51816f1eea8de9c4301c0d470b3a2761c30d84602b7bca46d5f77547072399d9ab8275e6d859374766db25a464" },
                { "fr", "b7ecb29d3e714a108bccef36b9f952bcc9243f8d75d67a678affee234774f472ead84543e2ba0a3572b394caf263cf01fc543f2be085aba2ae83b9b2617478e4" },
                { "fur", "42cac8b5a76203fa9ecd011bbf7f3d992607a70a7b17f033bfd57b5c86b022735f416cf4c6d314403c9cf1a2f013ebf0c2e692adf50f119c699d0875ef7bcabe" },
                { "fy-NL", "fa7a3e291947fd96fea772c3e5019c35dd51146334695236520e3903b4331900ecaf3b3c41f8e745f1fbd03d5df04668c8137373a65c1f78e1c4c2bcae536222" },
                { "ga-IE", "4010831081f54171e3ec48d119c68b1ecc8596e09354c5715151c1c4545576f28c3739da6c104f760b40892cd75d7f2452ba95c877c4393a4adabb395098870b" },
                { "gd", "6e868d3469428e40bd9e9c05fef908c3bac93d4c5c0238dbd05336c44095030e1781eb0c94594b60dba2c2c2cda27009284183804ace72b9f4f8b07d3ee282bf" },
                { "gl", "a8847f6e6888294b063b4e9a4884cd1b12dd9ac57cc106281654826d9f2401e7be622d43ad9a67bb607cc378c84f7028d0901145efbe40dd84fb6840dea613fb" },
                { "gn", "720718875c315f695c044ceec926a0b4ffd82e31e7b299e0606c53b5ab5909cb98b80fcb5ce9d910ffa71a751832c55f945a9e03eeb274c6cac58117106be773" },
                { "gu-IN", "25efb7f6330d9033f9922fa32e86c8423240f9fe4075a236929cf6daee16d079b71d3110c0d93b3d6005cd82429024f33129854332bab659c46b6b58c2b4db7f" },
                { "he", "32876d0f6079fd3bb671e429e7019e435779563866f61a3048d7802cf643d2e9918edf90e0539b2680332ff85188fa06e9123bd7cff2df3c44263c52334152da" },
                { "hi-IN", "28682b044468716b768d4590bda08ca517054515b7a45ab71da2fb977c509caf367f147e11eef64f6fe875c26e918fffec3b2fc76c773e4a01d2968ee6ebd16f" },
                { "hr", "0b6c56641b1f4af5b074906895a54b1adca0c2fb267450fc4b4736fdd4cae41088b1d12f27656b26fc5979b61db4dabfff033a3bb2692b3d192d5b49a1393120" },
                { "hsb", "e9fa8f9eeeed3bc43efef28a6f129151c6569bee19d2c102afc376ab00234c65ee83d08bbeae6140e71cdcca60512d0a0e425e28347e265b2be0f5cf5b2c92d0" },
                { "hu", "2c6ef1cfd810e7f8242e0676046619e4fce1d9e7e51ef2f41eb597d16c557c81010651a42839678c78be5b0d6e4e32f1b8ee31008c9aec63cb29e0b2d87e5a07" },
                { "hy-AM", "327c4c4034d0623ad62b0b58dbf1ff4c1449f0b13da0d272e8ca7ed8e668d5917d400645ff1ded3c51e1f6b31f4dd3a78bb97e8aa2d2d389ac0eb7465233f71a" },
                { "ia", "20a553b49358ceec4e19757f3c00645eb14986268fc7a8d68c767d291f796df6ecc0fb11edcc40c62301dff7d8ea1b4383b8a0c5a0e21e901139c928813b4709" },
                { "id", "90289498bd9ede3bf5c16826bfcbba47cf6a9b8b34e85cb8d2909aaf89f0febe020553e0072811b8573033978dfb11dba53f6cde5fa707e743ec9deb55076555" },
                { "is", "ad228e7d2be75c1d0ba4bce80557b5cc47b6efe985ebec2c951df2b39c54b9b44a0d8a3f3ccedbeace456820acf009bb04626c71f34aff11c6ebd6e04ff55da7" },
                { "it", "dc98430f85a577092095edef40a7b6bc44e370551c9ac3288ca237ed6f86f6169141348ec89ff3b4df15e4cc1a70a5637466d590167bf6ed24e3f7838c3e52bd" },
                { "ja", "2574c6ed1370422d75d259fe45cfd985d3b1f6f9c370862efc226b66d2584f863d18dd410c62cafd5e34ffd7802f4c9b26c6300bb7c9257ec4bab566d7f4cb49" },
                { "ka", "8ee447ca38a1a40718e735932472c9736abf8bc3f744360a62035c0f0357327b1a553a1c7430cf2fed15dc337029cd791022ec8243f1136012e511896aef8173" },
                { "kab", "bbdb7727cfec6f87ed4e3b481d197cd0896c4f5f88cdc172dcf5dc3df6ec1579d8ac722bf4bc1382c745377e353430d8d86f19f0149a9cacfb103a6aaf18190b" },
                { "kk", "51a36289b68b74598b8109f9be7abc64c538f0230b842599f9fb1a2624e2ea673883f946c2ae822ee32a917af12c9000205a787e49157ce7cc3c6d5f66b10022" },
                { "km", "9a1dca4d20e32a88c72b4ab61fa4eb1f35607c0951fe2469966fc66813d1067e2f17a7f72e734427195504c1fcda0fc522c6cfdb0d5cae39a4efe86f203695d3" },
                { "kn", "41bb35c77952ca51ca118d72441aae7efc53b88fcf422a07341a84d088ad8084e24ba8448a98b2c6246e6da46336345f7168dbaaf79cf55709206459d9fbc98a" },
                { "ko", "47f57faead7b129893228ed5ad6ee1cdf2b0fa14bcbd80938503c356382d7aeb3c2ef21a64118ab3b3315a78d26131671980b94b3f169739504e1d9368118248" },
                { "lij", "c2b457442013f60c469e21befbb1f92bf7c19bba1a98777515d29ca5a96a066b49cb31cb5bed473a1122360059cdfef05ffdf0a94e7233b28ae3f6592c0ba08b" },
                { "lt", "c1d8083021d0f9e33ef62dce47f6102cd654b52167c6042693166ebf078bf4d062a6bad26b0ac9207f39952ac909d2d5a87fc0bc0865e472b136db2a9626bb29" },
                { "lv", "1638c7d304d2b177128973bb78c45679ac2e77713b34bd1d19f59925aeba00b850243a9724bbd4cf9e95cbafee3f9fad3296a1ed069a39f36c59c5d729b0a639" },
                { "mk", "2b4f1ca40e4a2e5e5c4ca37e8844b13fd45560b2bbfa87e222a360e0a14a2100914907fca696d6c6c8fbc4c574676e65d12a6cb5fdacf887fb9f9145e258fd7a" },
                { "mr", "7fcfb9ef45a9f890fa8c21ea2b1241aed7c6a5d7a966746107b29b54a101926799613a86f724bc876745f9519d72bedb63c6052fd1ee7b03745c1b9dcb290d64" },
                { "ms", "80277939ad8ded249cfcd1995e7ecdfcce983a6cd0e4ff913d1645903264795f744550a098423b0b7f1daf0e0a4c81ea273f541f26a79f4414ecc1f7e172a78d" },
                { "my", "1ee87a707da34c75a2cbb397581002873f1a1be957220c9e77f70551ad1443dc8fa88b0af886deda9c62174faf22186c7416a4d9d78fc061f386831c7a3b728d" },
                { "nb-NO", "0485504b62f338c19b144507bdc57fb07c304d1381313a02b56798760afc6a7901619f47b2a386563c8e160d1548135c493d58482180a6d55df8f0cf4f85182e" },
                { "ne-NP", "6057a1e72eef5b5a6ad7173c753ba7569970eba013b4b2372289f3d4e502618a49271f11ca86ac6d8b7839b59eeb80f1603661fa23f0e579883ccec6eac2cc2b" },
                { "nl", "2af344ab7694fcb1393619b78631a4d715a457af8903f09463373ad8c8ff22f87c7bf0ec8657d3e4ff5b52c283fb1e1236039e26da3545922e06f7fec0507a51" },
                { "nn-NO", "e210b6dff07c9dcd90681557eb9b0ce917ad9bbdb6e8238e756d8c62b6ae6f5f6f32ea78157eb91372909f20ccb6ab0c64833021f95cc20c203b0e55a1b73d23" },
                { "oc", "e78d8c48440cbff884d0d52a35441881a20568c67375f3ef02f3cf18b95cc3aad706a09bb78442afade7bba6d5f1b56754dd1fc4224a961b6598116afb04535d" },
                { "pa-IN", "02134007c663c971df8d5f6ffe69c0ed38de0f8634bdad4b1d4e885d630c20fe6d9d5fff38e16ca33a24538ad70d7390aa5b127b73e55f39853408d4b93714e0" },
                { "pl", "d5fdb2142830408c15ff01650b550fd6898f357af1d4b7d52c2d917e585fd1d711e205033a2e98af1681b51863cdaec9352217181729355b7bae1ab2a9c5b42d" },
                { "pt-BR", "e8033028a38789207ddd413b0c92788d1ca4adf7fcccc7cd9ad3b894257436d6112faa73efa692b06b49e186441370861e8a13a3a55e3c9551abda328df47bdb" },
                { "pt-PT", "9c033c14b709473f0d6976f3ec3d6780d5eb16dd9229ee7e38a1015a47e71020344f430ab1ce0203c8065d1f92e732686fcb98f7a3990920d61de91e1965abdb" },
                { "rm", "f0d3911d71585b1a8254155f96de98f104260124e68e832ef265fe62bc54e4cbcf96f339ca40d15c1117a4034cfe98e785d915235d749f75bc944b189c413dfc" },
                { "ro", "6cd9243d3a7f8d4cf3379c5419964f7a419c2a36d12d1f1b1f5de214f8c846aa212bb32f699780e61d729346256c05c82edeaff85a4f68c70f741ccc298f269c" },
                { "ru", "b91462a69d8dbade0fdd73403120623ea29c692ef7b7e448455b05667595aa216c8e4db05d5432ac635b4e19c0d26a672b624a23d0eceacf6059c10fcaa3c27d" },
                { "sc", "5eb1fcd19a19969da30b342c23ff99f201d244a0c1452d87b5f1cebdd9eddc1baea90a1e2da88e2f23f27609966358140c05c077ba422a0dc504bc39c687750c" },
                { "sco", "36b03a49cb47acb2de2be8b7d85aec1250f90e2ed74e0a724bbbb99d471d616a804903b517681c8cf3c0228f173e0bb1cd737ff59ad780fc4e6d9c4be9b690fd" },
                { "si", "644a5a9fe5a5a7b5ef451491fb262dad860dea78277e20d581776b5e26f550e66b72729b7ba801314d4a65d048def11743c8ccbe8998652854a66773b14549cf" },
                { "sk", "0cc2a32eb1cf14ff8367d6f8cb0e915e9bc7a0572dd8c5f095b824b1c64151e202d721b2edc2a2458294444e92dc08b673fc75938da048a7d6651f05361ad5a3" },
                { "sl", "a05240c9e29a9996bd3c7dc27e5828bb23edd2439dd34814b5c1730752e6db7f3db8314012be2ecf75f0de2aa5cfb69190365b6a98b4971de75ecc651f3c5c83" },
                { "son", "750fad0cee1485a40eba18fd3286a58d6f480d6662d6c21b9a3ea2b4457422b98575d4bef1381a7974ba0bfea84de6eef13c769e9697e70858a92036cab12dee" },
                { "sq", "20721247881469f43a37b113770ad9b8c86b5800f19b8fe572355e25855ff3356b83c065d30bd2c4b83d0fdd3cc7aaedb2dc1928c7f31eb859f57c411050f1b0" },
                { "sr", "d12fceb9bfe1c901f86b0a0e5f50736c62bde101a9bcb4015f63d3b5c7cad2cf966916b2cf79faf39a1b06aa1fafa3a8b92630ea84b1ce4861acf226cb58a213" },
                { "sv-SE", "2293ae44e87406089693dc0f7f037f9f7ef7156417065c8b9d19cf0ba6311c6959020e2f0067b49cd498ce42d14742aab7ee977bf63868850ff4e55e8c6197bc" },
                { "szl", "8d52374690930e6128d144c9fccb0826140f9b346f7196cf515ede10d2c30c5dc30c1a42eeb1dc1b179c3efbe2a39c6bd8e1439605a9bcce074a77192b710410" },
                { "ta", "70bd6783f0d00aea429e1ebdb1db0f6a91b136a7731492a8d722119d5a85ce589a22290b6d4ab490ff4438488295274675140fc5086c093b1e76c2715c3b0845" },
                { "te", "d9b530017926f1189f48755d242be6ec8a58544c0d08abfb736998fbd31ca7b94d3caa413c32330553269b5480c8ca03e5c74f590a2a82b04e414ade98857658" },
                { "tg", "7b7e72e95014bf3ddaf6ab4bb8a34a33ca2b7ce453a2f59b98ea4da1e28484fef8b949f56e93a7df45a6961ea5d1e64e611356736c530a86286e13c1396716e2" },
                { "th", "03bce57156656c403a43244fffe700ab6d2532db046d9801a68e95b085c3843899d4a7d4082fff2bc997fdeb9363e0e3479b4a3b6cbec9f01f4e6080b915dcb3" },
                { "tl", "b6b7ab6ad0cc3861101117ec5a98a9bf9503028323aa385eb8d81064a719aeb6966569c150da1b115d07c59c4d3f1c781ee99a15ba354803d190daa56b7e897d" },
                { "tr", "d9b5868441504ce4894c84c92340955d125ab428c2477004044599c5a268bb2dce78134b1e54b1e93a04be9cefea192e79af7ec164dd1cade88c2d73fce585f8" },
                { "trs", "d6dae856ce2759d207927010c9a1992e9f514375ea486032234c8a166eaa6caf4394a18eb7b42beaa71f576393ce5172b50a8494d81070b527565d21b933163b" },
                { "uk", "e5ff77c2e2122fe6d35712b7d84c0c6a1409baf9255d4b2e7df8cff04ce58519a1fecfccbccb6928aaba33bf8832ab0c2586487832f2a3f5b58a5ab9c9d41296" },
                { "ur", "0d234f2527d398528a99fbba9623424a4e6ee697ca3104a4dee3b8596628b32bfe45710b4c71b20a5dc0dcaa95d34ab8b70fba81790e4306a3cf8c89e9a3e0a0" },
                { "uz", "bcb2d7ababc46627c5089967c8f1b7adeb95a699bd7fa2cf376d51b5eb24dd541e04f738cbe5b4722f146aa3ce8aad77633e8986174aa5d0ec15da21b7ce1acd" },
                { "vi", "711e18a0bee11c0aa0c9a6a6d5413c88af4d90a27fb40e680f4b0be8f69750a835c23d4919bf6809809b097227794b9bb0462c71cb2534763bc172d8b809aec1" },
                { "xh", "f294ff2720f2dcc98b495f2a0e92172fb3d37916fbfb034165424135e6741d5ee12046f52928c1ef07736de4d3fa0769ce8c54be8b9af55cdef137fabecabdfd" },
                { "zh-CN", "858e6e28797efbb82e6924e4bfb685749aa2d9345accbc6dfb9893b649e483cfbc2c7c053077032575a8093924b0c331d71bbbd61d2d4cd3e8712d295ea8dea7" },
                { "zh-TW", "1645391dfa25abefd7b01830bea093a6d9811b4f0071bab4446ccf758a88d71dccb6e315c6abc004e7aaceffb15eb915fb64148ec097720022df33f14ae7fd7b" }
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
            const string knownVersion = "116.0.3";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
            logger.Info("Searcing for newer version of Firefox...");
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
                // failure occurred
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
