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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.13.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "6b6e58b00f20eeb50a802a4d2a859ea3746a008c1860694670a52a32dea10832faedfde6a21364c092e5a13002c67f9c113b784a030c4ca350f00470ee4322ad" },
                { "ar", "de4afa10b91fd70aab00d7964096782de971e50162235f7cbfa72d9124a3ae934a0b38193f2dc2755a8f1d112c560b72486d9fe60c4e3c6aaedc79f95e31ddc1" },
                { "ast", "e773a4227d24a0527fb79f6b23b25eef96369fb3509fa51949616a269662f057d1a678f75e7524ae817a1df1dadd51dd1296ec88153539a513e91303bc6c1893" },
                { "be", "8805ea38f78581d4beab9f1060c02854231c59b64b306634d308df116258fb2647502c676986c8051e5a67d52892e6bdbdcecd1beeb3541f533cce6cc77ac20b" },
                { "bg", "26bcdd48d1aacdd5759afbdadcb152939ddbbc8dda15301faf0c71d1c6f821e0dc0264b0e21e990b26541073f35ed5c34d07d18cca5d984fa97fbc56b27f90d9" },
                { "br", "4f50b904e44895c379192ab3011ecdca4c85929599581cf1e6c92135c2ba3cb6f262f80814afaeadff3703524fe94b4d7aab6b2c90a367ac440e65faa18b36a8" },
                { "ca", "36da300ba4b2c20371a342c5d9e8271f34c0d2f452bb5e80ab63fe386a972dc341a7a9f6b85d45537c23bae2f24dfb58e7c3a51d5bdc245127204e3ef5babbe3" },
                { "cak", "389f6e2ad5d7e42a4781ce800b806cbc710d2928675a6e7b2a67b03c3eec5a054066900d66d41c55e33a486685cef1dab372ad78e2a2b3d41b76b82a1af798ca" },
                { "cs", "2d726693d06702150bef7e1f2ba517e68474b20708953a857c71424118d14829bfc340c4338a7a003fed90aa4b6c2537b1b436ba80bab3ab3afb893e92275ef3" },
                { "cy", "ff65375b04608d53853f7f195098cc7ddf7e228cb05e07efd1527ceb4c60f517830f215cef93d63302d69047bc9b7e9fa96697cafd52ec693131c5ee6ff7a147" },
                { "da", "83fd1c33e0fbadb7ab9ea2e8d0189fcf6b2747c80ef1f1b60186de79aaa1a1903f8e3fd361ce1f44c91e0af6a365eabab9f3baad16728031b472d05e58902c6c" },
                { "de", "9b54d5e29b30123a23ea718e276fb105d9f92c207da03e83bf14c05a65f501c10bd4bcfa7e531e542bb8bba246b73f2a84eb9717abe3b6045301978977479846" },
                { "dsb", "72e88a7d1d1f4fbabd5a990f9760ef92f7e7b7ad182f97d91fabd7bce3cfb430763e1bb66d45c077f745d1db56fc2af1d62473e04fc5ab0e72159a578ba4ded8" },
                { "el", "fd19a8b09d4339f618d92d6a629ec1482ee0cd8a2831952f741014cb26e131b3e86ba9e1d433a263b2acdfcbb2703262bc5dc3b92c038b8b293d24ad3bfae426" },
                { "en-CA", "4d9870540d5c3a471e1f913c2778ec6e4aedd7ab58ea66760fa7b8a594266182c02a88ac773afe951e25817e010923efbae1b2eb9d069a742af4d8dbc51aa933" },
                { "en-GB", "1a3a31871f99498b3ccbf62b4021b13189bcb9451a9ceec2b52b125a9b0f60baad36418a64c71350a5d9802cf94c774c0473d98c52e532917258a28a91b0c1c9" },
                { "en-US", "5ee73faa5010d3a5b579ac9f45ce213f810132112488aa18dd4119cab4ca17af500c68b5f90b0e6bd407c47bc1044696f328c58bad18476066449754e7afac60" },
                { "es-AR", "013021f6538e03c703b21483475481377cae5133c94cf787628af952a301b1cd0c74327e13369b66933ad96bacbb1daebf15d1a0d302a61bc2c1c8b29f6a47e1" },
                { "es-ES", "3148e3dda4c539277d33da5dd26538d2e9346f713bbba71e17f8db25592052a013779cb91d969b22332e4c4ddc1aa2a86d880fe478f29a9483fc7b3a54646908" },
                { "es-MX", "81660d46b8a55714f62d6a6204f825dc92ec095d0fb20e30fbc106b9efdc384cd5585bb7f8c62bf8adf3b2ae2f1e19c4f320a38bc52c56eec88137b1bd375531" },
                { "et", "2db377a52576ff801bca9ce779a3913b1340a002d0d2f2a705c4d99bb99da73f1880aa0a6c608bba3e1ff5d003a06ceb4130a69b12566322fedc0184295d7fc5" },
                { "eu", "85e4d21c161d78c293e3479b993ba002172f3799b89eb6614ecfc698eb78cc4bd588bd122afb85ac6f5693accafe4f01c6a84f51983fba7034b3296cc70dab8f" },
                { "fi", "c17330cc4ed5e113e4605719b3251927ff2ccc49eb9703288c68ae90d2a2745a00e588732470f33e888ae6c27e1d3004b142d562000d80742d7105140775fe53" },
                { "fr", "5f8b2f4f42f74083af8e9596194ebe4e7b962620289b3cb191c2279c7647cd5403e5f9852e0d1d2198cb10e9b924283477da08378cf861defdb195455e39d615" },
                { "fy-NL", "15d63bbf293dfc9a97c8a353697b9816264591894096da9b66f7bb5453f8a54949417a99f8f427d20bda420edfe8a7c1d6ceafa5dc43f6e0dac599db30940ee9" },
                { "ga-IE", "f5d8d74358e9a6647084e18fd86b83d1d3415cbc9bb487157c3e3e89d8c9d63a3fac35e2d97692be8aa34ad94b59c9091b8d7dee4cf6460a9fe4381d055c8cd0" },
                { "gd", "7f5ec61563e582cc7c5c1e3042217461f0ad5fce7381a9ac1debf782424f8b51d17de6b32a6195e2f89bf46fdc81a917507ce64bd26ff15faa75530df3e238a5" },
                { "gl", "e4f59d574c9d752e7c0274cfdb362897b7f85ca76b4f2eee14d0fc8cd8f23d9c6229c7679771673cfac047040b90d7a1f9aae2a3de4ee3d9f554f1d8a057eebd" },
                { "he", "1429b213a02a014128fff1ff6ea12c1c64f588a42eda3602efe61282e304d37529b6a4ab8abdd15d4fe317537f07ebba671f619d1d6b90a56856f3b739e7343c" },
                { "hr", "f8306ea3350fdca26971865eee940fee135f21a18d380430e500d0f13729d9dd38cf7d5f4142b67339bc7f88d87732d88c74ec758d82148636cc7dc9b8ba4e15" },
                { "hsb", "5f8c0c48ee70bed9c122bc99d59be98e856ec2b1ffbb2f95026f0967434dd31e383a48dac793c239a816e7fcb12d8896e4379d822421d1554e9de4ad56766055" },
                { "hu", "bd07095f4900104fc1ca7c7f0d8c4e4019c105eb4c26ea019dfc4e09d80f464f0144d5d1857a5b31d7c47e39e14e6c9ffe3064e66335b4f0092c523a6e0127c6" },
                { "hy-AM", "f6ae6a59097b94362df79ec1ca4758a90dded1f07457f2f28e305664a252edb6a361f64af902739b80e957a3703a3eea7ba530e31555a6cc62400f49eeba22cf" },
                { "id", "5b36aaec6f3a1b0f5b4e7ff9969b04584aed3a288a38fc8e828a04eaf18157eecaba8187a007805bf997a1b1e979c70444c6bc8e392f8937e0a088c0997f9a6e" },
                { "is", "f638094c2214f1efbac8c06e00d00d64eadbff2c1cc16b0408b7a4b7fa13cdfcc05b8cf1963ac285c04a1dad6e96f6ab1e7a24958c54f1d87db49eb6438a2e38" },
                { "it", "aedcc4044f6d706949fe7b007813ee391d42a12f33b1e5d74e17e1c1bdfbde657da91c781b5547c5a496e6cb3ee430b9eed809a51ea54fe50075599700bbc695" },
                { "ja", "b51fe3c3ce56fbf01aac6947b08a58032e15bbdc0a32836d341281b1a150e6fac5c4395508effa5d4fdfda9c1f38e002678b86fad63d5750a705729926a13236" },
                { "ka", "44669fe162be43bf13ad4fa3a9ec81865024331c05b397aaa6e8925cc9d4846040e1ea32b3563ecdc0a2d691d65e44a11565186fe7395945ccf07c22eb61a05b" },
                { "kab", "926ef9dcd4a602bbce0f4c8eadb96ba9cf8ea8575f60a8c658c8ece27b99dcfd4f60d87bb8a62aa3711993c7a6db5a305299af98c850352fd2170469c151a4b4" },
                { "kk", "a2ec993a7df979355811685db533d8dfcf6d15987748f48aa160f4fb472ab4a8854cf55c2588a36d80c57958b2ba6fe7995c72a5ba035aeaad38f843f6f0a4cd" },
                { "ko", "5afea0e8c57140eddc6a3baa2234af52b95bd840913916fca32bbf68775e1e3eef035ff570ba787bac97b3ae1ca68e388f2c4c82946e561c8de4f14f34cab4c9" },
                { "lt", "9a95a0ca1de2e3d8a9e33a473d70978b4fb2344938ad74a9b668f3cf9c88118e68277c60c215ba7a9dc09550d64e2d9f7f4ca914a369251d5fb3232c9af41858" },
                { "lv", "edb7d4b4e58adb13b6bf30fe5036fbd14ec6e485a8466af2593052c8e22f917073750b09c37e9bc0a389615f875d7b4d16ab824b8dcb5f4390a5836890a37182" },
                { "ms", "583a944209456a909219bea458e42b7205d05200a3df7f36b0ccee92b83ec6349c3f229150bfd8bd9e68e227a978fb59998595cf182c0e0a91f6d54863023ad1" },
                { "nb-NO", "6cf686b75c032c48cf48f3a1dcf78ee828c3833d839279af664846d17db2efd4f4fd3e9ceb4e7915aa3654c1d89d0bb76aaed1ebb882100e96447f7e5ed02e23" },
                { "nl", "560ba5f658486c15bc684c3e7be6bd1c523928f247185d212ec37c307298b15a7521796928b7bda5e42bc7bf3cebfc760cc5971a362a1e39b51781f0423074d4" },
                { "nn-NO", "76c213ab807da0397d943c4bcf364ef9fd5b57a3fd3f319f81ab9e8c52dddf3ccc882e34e721a489ff3c14b9710fde23a731a157bc71868b41f3ebfb733f5011" },
                { "pa-IN", "d27cab3dc715ded68dd8aba101981c9b99216e1bdbeb942f5c63803a6ebfe988618048991854703f05473e19dc194d87771752c2006cfc861312a1b99b4e1a0b" },
                { "pl", "807231ef1f0c05f18d379ccf5cd413a9bbca37ac1e3bf635b2f4b879b5f1e63fe81fe300bf5532aeae6f13b0904215d3979ed851c76244637b416ca4c15ec73c" },
                { "pt-BR", "6d9cb7c4a992095e858a5ceff60b132e46f136f097a70f1b1b6af6f7de890638e3720ca9f3537dd17e95dd11ae6520cc6e7d6119c2f56e8d5e48d20efb658e58" },
                { "pt-PT", "715b3b25bc90db7957a4cf02197032cef425f12d3e70424f1b41ef20c1936deb2c21044404933ffbc339e00db940c5d55c95dbe2d94736a75e77c427f6bb60f8" },
                { "rm", "75f4be7f75e3e7f21696ead14dee66999c2ba1ae54ee070ff5df46a51718a503ece365e108aac841c280b4ab8dda79647a03d4f90659bcb24ca7404495eada93" },
                { "ro", "1a77ad473e3682c8cb5a927ca99568b84204d17c4c38d03da45c6c7492fb95b0aee3b265521aca174980f74be1f2a7739cac1ab779abb39c66a1592b80a6e5a4" },
                { "ru", "92a8c55e192ebc37919dc3929bc8fe1cd3cbc9b06ec31bbbaca80f23bed6e269aae943af798462f85f206891e0d2c56643eeb0e59d75103f544b6551f091bd49" },
                { "sk", "3f7bb624ea6596f1cb547fa2feb12736a4cd6e4f23cd2a3b1c48e8fa5730118b5477941d69823aeb0902452fbab44e30244c560364b44d97b62cf7d68b753274" },
                { "sl", "8c61b8ee64ae6125969cc60e1ab28b3517395c39df6e340e86cc5b51e07d3d57fecd38bf420dac70efbda7a736e5e473ebff5f445ebd00ae89b2c78fa61dafd1" },
                { "sq", "4f91cea512a929e96a5a29156589765412dce65415bc869a67c6346fe4fcd67bf79863fbdad14313a8051c862736696ca231f9adf648744b5d9c5dae8cf9280e" },
                { "sr", "a82fe6fa0e4856a427e2b7ae6c4f7444667249f42eeacfac759eeabca6d8bf4b8f312f332bd44c80fd0c006c3f42407ab2ee2c192f84835ce5d3c9bf121fbb35" },
                { "sv-SE", "074170e355a13440b7ed1d2092303dbfdb00bbdbfc7b140c4cdcba07705ddb9582d3792654582a418fc8db1d9cf2e8e53099a5495680476f9964acd371125531" },
                { "th", "a1802cf3a18a23b1168ea689fc6d0a4ebad85c756226ca8560928d5a69bfd0d6bcb01d4295086dfc45035f410098a8a0d3c9db6cfa5ffce8cdbd4a303f8c2a8d" },
                { "tr", "a6b709b81ad84d42e5d90c9903e1e784df8a232ceb596c93a8bf9685c7366acd1adc8ceb597d8d98a2171490e0a6b31e9f05f94e5de3dc7ee7e31ef81c61e74f" },
                { "uk", "0631c6f485b952b3299ad0a95eb641ace17a724d6d86986d8d20efd3affa3a92da6fcb57eb0a61df6db605ea82145a81785af314648db502776be35bf8bb8afd" },
                { "uz", "4787bd8b53b8a198138fa37178bab9ee9f9eece693bd43b713bd83d4d287977061e90367b18d8ef611ae70aca898676512d5780e995b838b49f0a175a529db1c" },
                { "vi", "39cab181dd9dbd0643b6d19c64c080e8e5baba9f494473feac0ff19d7c1e77e9755ed592d261c83e413fa2f8b9b9d0cdc2fc7980d906ac849fd46ccaaddee091" },
                { "zh-CN", "62a57f80b2397e21a96ff5416a9855745a8b6d0963f0ce286ffcc845a5f1dd1ca8281e083ef1601f1d6e3d9ed3251c14ff7a8a6fa1c691bcd8b0032162065e6f" },
                { "zh-TW", "01cec3a9ebf7050b03b76e48ebf5fabf09f214d8c36fb7a89393347ccea7ea19fa40b036807ef4030e5f1acd8764c56bbfe964d533cbbfea0f8d9bc920afadee" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/115.13.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "47029bda1e84939a0bf5146ae87211b243db7db886b604cdd66985abac9d37a1e67963b0534405181f44bab096709089a2150675b301a18b1b137a51434e80d3" },
                { "ar", "9fceb754d3f3fd0b45da4dc1fbf94e4288dc0e9a5b8cea0ae00294858f08dd926cefd885594c6d066510c8b6ca1da96f29817c552f21ac4aad0cfcb243716de8" },
                { "ast", "172ce0d26809ca3c0b37a625ad74d67a95e2931ac9e4011ad3fe43de16954661ff8ecfe77ec1487e0379c2d526957a0519ad4bce09ea536309a3e60ddbbefee4" },
                { "be", "6c02e59166482d3447a63fc8f2e8152f0ddce4554ab03bb64db55a351cce7693fc31792e7a8aa8b5fa75e14971c30424f5ea33aa79815cdf5c119b9bf4698aa2" },
                { "bg", "e193bb0b270792780d1cb627e9462ea5b398866dc4d4dca4d0639ad605f421d0007402bd48c9052c9c3fff2c7ae18e8ffda35279354e1cbd95de352cfb550eb9" },
                { "br", "a7e3ea81ee1f96c6359c854d4f060cd5da460651dda014b6d5f5598b6e8f9a4cd797469c88da42e70ef0a1153439a0c82fb50e56151e7ce78a68985f64f1c40c" },
                { "ca", "622175ce3ac9896cd0bd90ff75bc3f4df9c09fdee45ee84b71e41ff8932aae7c7f019e8631d73dbec82ee35c048c7da644c9d851dc5ebf96208a33553b667968" },
                { "cak", "c5a953bf0024ff467152c5fb393f5c1038d984b2eabbd95a0cbb01ac0b61f05a6a1b0672c03d924279a28e02f2176465de80c5e3935b207afa2cf5f051169498" },
                { "cs", "325deac773fe8ef6cfe56d2034195b8da8cbcf2c247588ad4ac9e5e133d983c8a5547988391ecef172e5e63bcbd53d93dade994c9428745f9132d95b1ccd5a79" },
                { "cy", "09635f4cb884158a07f6749fbcf6c06e5c1cb6daca57bd62d34024993e9cc09c8cf6ecef28c9ccac6098f727a416263258b11fea37a5e433ef2a02b0eb788f95" },
                { "da", "ef61341820291a13ce1b12398c7378c48fe8a78d89570f56c0204bd1d48676994f38539b3d592450185efab8873177ecf05942ac2c2a4b7b697b5a779cf97ad1" },
                { "de", "ba13072284f9f4d8a7085d475acc2842c214c10c0b927fd662276a0cfe4a385fcfeff35c6a8014803026e10462e161b051be301702f8124f1df593b15aea924c" },
                { "dsb", "507d5f827dc8357a65deb13b0dd16dd748b82514a3878f11ec8d5321cfeb41348af83de3211592cd1e8e5fb171aa8182c4b51a8c37f96d0daeffa018c5dcde7b" },
                { "el", "ea2f93a8674733466e0b4d853c3ee4150a387dabce8e2e6cd2a9681122a93e099a4ac4db40d917d54aa19176bc030f2c92518a3e91c7c22b403244fa85e0f425" },
                { "en-CA", "e83f1cc50c0a17d56d7ac9fab4a8ff806e50daeb582609f072bc6ca0fddad0fa4e9494d7c0a7e9981178473bb6ddf7ea01dbf5e5c36c6003b7fe2bea329defba" },
                { "en-GB", "eee5604025b45fb20b2fa05c062c06880849883ca0e918c45324a60e8c22cfb16f7cb769f4120a34163c2d14ddc449f7b37646abedc0703f931b1fe49f36a36f" },
                { "en-US", "ce1bd50ab811780b8325be655a6e156f061a10cf87a256ce09e20ef4b6d27abb0986df2ea2d95aa99bd22f84bb7a705bdfe65adb78adca00dc187432ca233f6f" },
                { "es-AR", "d200246e3948c25d27b84654042f797b4c6fd69905e7549d55bd65659a93ac22c477f6bf4b7670e466196311f29b55cd568c57bc1f1befa08b79a3cd79a55a57" },
                { "es-ES", "fe80cef1f70f2ec6574008625bb1417e319cb6d65543f444435d8dcbbffffe5872c3a69c7746134e452f237a39af0434e4cf805c6eef04f13c51d95eac4ed870" },
                { "es-MX", "954794285ddf173c40209c08a7ae807ae48925c3a85f31bdc3fcb206b4895ca0c07cdb95634d8c3b49194f53291d38cb39ab675021c13589b394b8f13d6ce2fc" },
                { "et", "8f1d4ce720c6a769931d08ce7eb1225e69c789c52349efc7e7f5911975661da15bc4d2e8a82a44dac5935c82ca5fcdffa006a581e7621a74137c174f510464d9" },
                { "eu", "b24f25eb1a0c1c71361e40b50d6dad5844ecc3ec580a4c914a21cdc98d49905176983f7490171e024d822cf1381741e723258dd7f0cd88c97f2c50818e0d61d6" },
                { "fi", "63d0bc539fef1f3dc108961e013aa970c05e765970232a097e0711000abdf181cd39cf3fd19264bd794199de2b1c42573996d15cc24c12f6d1ea20eb1ef2453e" },
                { "fr", "5e277fe26dcb40a897c451c49b3068ac391e9d8923935f4190f2d7fbaa7205651f95d4c54fb73981814ae0b449b6c8c1b8ea053acc8e62ee887fcffe2949806f" },
                { "fy-NL", "4a801b30404a1ae3f4cf38f1303f017374a803362d64b125bca7009c5e4382ae8ab0bb7c8f08bf4889fe8c2452481de099e8be310e562acc7c682a0b1062e8b8" },
                { "ga-IE", "af15b5beeec0c626e54e978c1d2e812a808ed28b45d70fdaa3df4bc4e9224d01da5b353da5207c188e3a9cdb5cba3395d5a35c46c53adbf3b4f7c368aa9e8437" },
                { "gd", "39db765de095c560bc5d97a021fcc16ea537fd5e45c78915611895c567a44e7e0a91ebe1d3267abebce5b292b04c34c9b891b76da2e775fa07464380a64bc6a8" },
                { "gl", "11fbccb4895baf0b5e006b6418669a003a7777e1cd6ff7c8548d6e73945a6f1397f4d792fbd4a1ea824931bb7d80afa277e572dda643e457bab64e7b2d353e09" },
                { "he", "29e8834e075964368fb5383e7491be7bcb28b5ccc2c796f7a1db69f974412a100d813222f07b81f32af59e84a792064538fbade52db0f80a764d704e3d8a2eb3" },
                { "hr", "5cf639212534cb55b9ff900abdf69687ebf2ef0c9d834c27b922af4bdf1d351991a5bc31d1b632574dea2b8dda679814f99eb78a3b366787a4888723b2ec1001" },
                { "hsb", "ead93c18e66a44060b8224a96c7001c8e53f2e319fc7e4c36976d5af6037dfc02d93ce90585e809bf30d190335f0371131abec707c7883aed0ac8941d20374b6" },
                { "hu", "7d1d83056005fe965c7f11363c6053d2a8191387dafb34f47df9c85668f0864b9d9e19e54737cd64e801c2c9476485332ed409efaf88bc8c886b1d482a0b11f4" },
                { "hy-AM", "dc901b1163e79ed7a9a7eeab5f21668994b1e1e1f83cdd37cbfc74f56a709db8871e93fa0b16269483bd3ea041a61e8f780b83c039dd91b6e0c81f652349dc23" },
                { "id", "8c2dd25118e9d5e551dd5ccf8bef6a1f1139bb980d4dab26303fe4b702e0aa8e8ff367454f3408db3380b139a0f72eb19f66b88597ed67a3e875844032449025" },
                { "is", "324cbc76a8ae5a64443ca2a3d554a030ea1e095f07b3153427de8bb675f87f4394fd607abc6f4ba4b0f90b0a44afe8f821f40299587e1d7b7f047de94f7fba31" },
                { "it", "73f8881f67c358e994060821d356972ace1f6e4e5a53458d7f038f4d6bea8d1f197502c6ad7e7451d682f09147d5ba633526f55c340f179df4bdbb1777f13e3e" },
                { "ja", "ec84b990561402e38ba0b83ea857965bfe72a89b9e3ea2fda90db0498e94ad9f07c4314fce14e2469a330293844cfceacb3f53b703ade619d2340a946e0596bc" },
                { "ka", "563e7ed6494baf979038890dcd2434a3af86f4c8b26884936b6423340872a485072119f9fada71e363f8b814152796bc5b17d547b782c558b9cb9372e31c362d" },
                { "kab", "42cead348594003da068bde113846c23d6d59cb22b3e044e949c7bd8bfd46cbf20991cf2e7c46ba51886bbf7d4767c91e39737e6f42c0b426bb6db9f05a94ef9" },
                { "kk", "135900e029cfcd574175aba95da4c44e050f50e7baead14f9730f4eb269020e3dec494858d2ad3b90eaddcae6b4867759a5f3efdcccf011e8452cd4d6b7e6856" },
                { "ko", "2d6207d307d3ee02b7b44655d4fb180839b74f2bf44a034caa82c0f2321f47ce96ec4551faf6babe9b2a03db4fb19e92adbdbf150ec0ea605486b1d676969477" },
                { "lt", "2bca8315ad433bd751432d0425363f19e28f6765faf7499700ba70b748b701200142c9cea2881c32154af6500fa8b970e2e0fc007e8e5a975e2b6a04c3ab0f18" },
                { "lv", "407e8b211cb96d81f3bd8c100a2dfde762fc29a2f6c35680578d840aad7a8e64b1f0554f249cb332ef4f58243e15464856b23ca039b48071da94d0b39cbb365d" },
                { "ms", "453c8119d6238c653aea23bd48411f99410a9b60edecead28fe960979f23276aee2805364856ee8e2314af00418312690b290ed490a2d9e3505b4b98c171c71c" },
                { "nb-NO", "e715ff1dedb7d50531ad9c676571d706b5e61afaee521bc74cfb392c3ef2b40b44c12ba1b975eedf72772684b40aa0f1a4e68edfc8a52265cb2e0d40c9882771" },
                { "nl", "b1913c29f42bff200b968d844b729a89b948ec7c867241a23c5d1af0311f8dd456508f16f8959910448fa480bae5ec08414d8bed173469c07bfd819751354002" },
                { "nn-NO", "6f4f6f3e7bc6c550869c527eed4b62292930e039ec09314fe0fa84eb77504ef1a4515b0bb10b32d177b1dce63f51d2d4d811ef37258e871a34478a432e46c75e" },
                { "pa-IN", "065517303f17880ca45fec3c3c3e4c9a70ce687cacdaf3501d4cabf0865165828ec93948f4ec431c6b139d2b63f0d73653d482924439c924ac866382577a1c56" },
                { "pl", "5968da44f0403be7cb95d5018e58436e712905dc317bc4dd1665bacb10b6b79681e52cdc036d54ceaa4f12228b7d45c7edbd58170f2c74740882f9bb95467c43" },
                { "pt-BR", "f194ec0d9fc47d15a4126edfead573a83ad38d8e63277bd09523eb9a191710eadbb8395978fbd64a2fcd3fa8ca9bca6c96dc5b395c2b83546053f93041963c76" },
                { "pt-PT", "7d5614ba00e856f593e89253d6d8b5692f396e1f716d156eee2edfb1d1268195a29e864802b391add8faf45e1d5567445aff29d176dfd027d340b219c6f38c98" },
                { "rm", "59dd7104ed833bb1174f9ff2671a9a27f14ff3bcfa1485638bf979d37cd8b4460fc2e442774c25d714923f2dcb07ec0ca4f35843e792aabff5627c916b4d5af3" },
                { "ro", "0a07b883d2fd80ad9602256ff14644eb6098515c5389c1a63224ef7fef81cb221af6af592caab85a4d649b13f90c2f21d474339643feed7b4f3e6c1bcef36a0c" },
                { "ru", "b1d38ac72ff0755f588b0d4fd3f14f1589458c6f6eadf54e4926cc88bcb88abe61e9791768e5fd2c8c8c8be096da8657e54484c935040e52c33e61e2b51916f0" },
                { "sk", "b035f618ce5356d31c87600ceeeaa30df2424bcf2a39c7b3c0c1940e88a496732cf6145ca5714d4a24051aa1aaa1e09a8f9edce92979d627279029a92a6b0d56" },
                { "sl", "6ab2ec1d3a98f1f9f8a582bcf58968667645c6824edd4c7e64b729996aa4d5de09bb07122e8e9c58a751aca9b298f0ec2904529e0ffa24ae615fd9bf395e3cdd" },
                { "sq", "20f4e8326a74a14eb0572140b410cf719e49ededf4760353b8f0eac3b4ea1bd3f7ee5ee395607f5198ec3b92f100205b95deacf8500bb8651f90c961da114b5b" },
                { "sr", "46af4432521e6fededc55cb4fc766c38595524214c2d7f08995736fc44e1a05eb65f34ad2dc0263d70360e6db940d195e1da7c492246f986efcfbabaf3d5432c" },
                { "sv-SE", "c1b39bdb6dfede6ec23d86b0560f1078cedb78fd9aa99df78c9c80cc7066e37d786571ec9b66ab58c49b9b18d8caf96596230a5ad3cf0e40ec2e527e51e9eef5" },
                { "th", "53c53a31ffe27449aa9eda213efc6c593c4c582df073fd6bd73b33942a4f16b5b361826cda4a552b7e31f50ff01a84325779877afe9971b8b0515d7b8fe5a3e5" },
                { "tr", "0c2b3b8629684b68e4cc6f4a3802e799855175890f2516eee0e43e86ef6517f2ef1731a2ebbe77882f6c28b403723ccda2effad10b8734d74572135bb1ad99cb" },
                { "uk", "c90e654d5f9ef057e02824c7d3a505607fa94ba3ad1425d1063188c8012150255e0fb8c9f160c06187db306999233b7281aedeb4cddc472acea26957c626bcb0" },
                { "uz", "d0815fdad5e7bb8f4d8c25e34481f4d363d0517e704ff85b8d1f3b3fa24826643e3f938b9a5db1d94bf1cf0bf591e9876c16bf2413091307252ec33a0739b4c1" },
                { "vi", "495542cb67dcd9f8a246c36e33dead8bb9bf4662c1f287e596ae78dc687f0305ba32ebdb3fc61fbd88f5dec9aa0718c15ef331af2ddef4046704e27b1491703e" },
                { "zh-CN", "5c65cdeaab3218f6eb595b856537122cf09f3ea5ea61fa0aee4488a67984d3725496b09cc59ec61c2c0f5241edc82a76ef9a0fb9d65b4c019cc30d7f49cfa2ba" },
                { "zh-TW", "4a54b78df209669592307bcbcc4d05a2149b64521cf3a10805ea8316f9c3a1b768a0fd34b297466d2c238a2a60e5ee7bf38068ef99cdd268acaf32c2bc7f0ec2" }
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
            const string version = "115.13.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
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
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32-bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
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
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
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
            return new List<string>(1)
            {
                "thunderbird"
            };
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
