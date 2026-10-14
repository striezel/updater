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
        private const string knownVersion = "153.5.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "78cd2c1e4a9daf721bf33c0c20585b8636ad18c541f264673ba33af80d9f9cc255d6bec5fab7d44135b102282ace85e956f8d0a0d22f26c41895e80541d9d281" },
                { "ar", "dcf2b46970b5dcdc4ed4ee09346cab02aab6b880bf8e7634c32d088b89d6f6951c2562ecb27b33d8c2b66063750f4e4db3d6e2c920cb6de712770c81d9fb3845" },
                { "ast", "57a398ee5948354f0b100edcbd5944a650d55df11ec585812635e2ad18681aac52488d9f5df6c37ff60f7aecfe63ebe5dc2a709484a394f4785c03b534ba8d23" },
                { "be", "f84c3c823e586d71b7aeecb4845c88d23cfc1e4daaf42b809a955f1a5ead49ed34aa7acd353bee27879b6ae5ce1f8f6459179fad8bee29b6328037faa334ef66" },
                { "bg", "503dd811df2c3ec6e142b144c6bf1da388898b15e2200b22b668539934d391bcbae39d1756b24b30bb43ddfe998d5dd01b641b64628de6c44bacae496ac0c270" },
                { "br", "c2b80383ccfd8fcf52b6101e0fbcdd124e79c940b03abe7334bff69468d032a1bf01f93733d095c60bff3cdfd7436a7c77a24e14ccecd776afbd963656a3a5b9" },
                { "ca", "8e15559f9337868fd94d3fbf067dddf43309a2b696d1e4ab10f28b36a15171b0e09bd96b479f940341e668f165b8b34f02832eb1cddae716232043d16c888270" },
                { "cak", "4fca4e196aade629980ed7e41d938670f645479f62c6410882594e9a562b874b327e8c60216f99c12c9f73ac92d7742fcd385bfe473f40b853e3a4c97b65aad1" },
                { "cs", "e3f7509e906c55b6ba96df745447f229ac5f44085a9425ee1a895f8f79ca67c833ef8a122ae0acc5e1bede759f077b19557d2eea5b8e661eadfb9d2876d1c130" },
                { "cy", "9cd16a2d6a27b9d2d6bfaa78cbf877a52d2e17baf3bb009099974fb28a64db2ee0a3ec7361b29b917410149ec437176dc16867db3cc7a643be41ba0e81a2bff7" },
                { "da", "9488abb3e50b44b56975bb56c3f14ca9a6e95957fb9fa301c49ae0c6c3888628ae86a52bb82f804ff54a4e15223d34eb16010d3cb36f14fafe21726b98c413e2" },
                { "de", "33a3a5f6bfe45c10a483289a4ba7839c0955709d99d226f213b018a65ea47a526d05f34e58aa959a2a56e8d0b7f73b749a9082c7e275db8d984e327cf63ba772" },
                { "dsb", "6b4ddde8df50dfa4f57ac0a6991d075bd32b9e5127cf6ae2bfd43bbcca4ded0d4f234dcfe45d884d5cbede5af41ffb50c720590461b51665d678e2fb8ab9a465" },
                { "el", "876821e8100c3c0fc9aa589b815e92dca8f353f7372d4418fa64821e9eb6a3e3901785a75b139640811f0583318536d3ac162cf0c9e2f07ed2ae1986618605bf" },
                { "en-CA", "6d251f34df92448f09fd0ce455e3c58eaef3ea61af658352772435208aa0c43eb66168e17f31e6c714da6a1325f8d8db895750a5c53794157f06064249c00a17" },
                { "en-GB", "8b338436eaa86dff56fe97385b497bf208e6bae37175fec59dd30d018b54f15632bcd96ebd50378c19c93cbfd8574c4a082b4b2f46fefab8c2874c29a19490b1" },
                { "en-US", "667d7ad71a7fdb90dc4d91be8159c8dffa277976dd319186707cd4b697df0ea2d72736518910dd0afaa17cba25597589c362a594501eeb46737f5f43f861e7bf" },
                { "es-AR", "6c124a01a61c4bf429d271cc1af46236253260f6695dabd2f0541d0ebacff5ec297cfb6e2d869a1e9a1b55917db47fa50e0eccda9a5ee1c2ae0891fbd88998bc" },
                { "es-ES", "9fe15dbbcc8c265e0f3e71168e319f016b26d22910eb43c341d4935b4ebf7c6bcfd143de1c936f82d76265fc1f4143c483d32356ed815e788ad3fd39d8adf347" },
                { "es-MX", "5727f783b363fa2f4f4734b08cf011cfb546efe5a41f833e71bef72983577e84fb9831ed42d85bc7cf8ff25364ea58f9743b05a7809180103e8c176cf55eb7af" },
                { "et", "4cfbb9524424ac94ea710248af47c4229f3b4eaf04d2bebd0e9f9b451e48c2823e36000e89f0fdefbb78a1acfd6b3c5fab24a1af69195caa04141911c2b04a8c" },
                { "eu", "9141b076c9e33867d75b3744d634872761c4286e2b6ee013d56c8dcf1124dbc089e24dfeeaae8a2f74be78360069387aa65fd8a4d70c70f57b1ed63eecb7a72d" },
                { "fi", "15224b3eeaf4011ef7358ead1905b541c419263c526eeaebfac85c3d7e57de630667b8f70fd6ac4fb86ccb8c276a66f51e81a4935de19c0a38131b1a49d150f3" },
                { "fr", "3c1a2f7f8f5e06061e602c6440ec3b116d912b04333146fce97f715d5997604b3b2ffec195da4e6fadf5cf7a3ec5b3b4b727a769c92e90798fbb542a7788322c" },
                { "fy-NL", "3247cb35d54e60bee9bba75f348346cb1579dc1eed409fc32443ac03a08cfc20364ca4f285ea55312ec2634495531128ed6712606c38b0e02bb2cfd9d4b4a1af" },
                { "ga-IE", "1c4a985e39541e4033ea5ee78309753dfab11bf9f3a27430b3713b3cf6250176cfc7be5f126ca12924a591504165c51f9ce1844b9bce1149947afac75db3bf70" },
                { "gd", "7c8f99ea808a5a591ab0e651e10d8867a08fe63ad8d185a7a89a5742cb77400e50ae8b3229dc54f05ecc82595a2980474a4d67c673e778eb6fc44dadc0097c70" },
                { "gl", "cc9bdfc5ad90d0fb8e71b81e50415a0b146c83d5990471ac61da3d2448d5fbeced3b615b343bbfa18053ac659e469a23c1007a1100378db6c5b0c26abd256353" },
                { "he", "0026ae8226a576cba9a033df60914b1fdff96d82ba463de3aab1e5ae7ebe7a2a09389f8808ca924d733fdd599b2ebc923f2f66dff5b0d598d900fca2d90486d7" },
                { "hr", "6b9290f951e7b58e5f0743f7e2e3828ae08fb26471532740cec7ab79d79c480497ed859c15e70b82071d5034c446aa8451974f5c0dae27d2199c543255853477" },
                { "hsb", "76631e19e16972baa2382cc02cd04b3a111844f907b5500dc67e2edc2ce77100c10a2fbcade2db6a7405523c3ef819a7c1441ba4c9bc70486ae763577ac975b5" },
                { "hu", "c2366183ec3a9f6581a578d3a73dc568039f29100bf8ba5f51b6540b19da6400ae90398e1a193f85fd03e407dc7356d19ce8db8043b129f6338766542236d039" },
                { "hy-AM", "80211cfdc3498a74cd0ebb64da648a2f5e15f603119f2e325984fae566882a36292144d6453d5ce5e03412bb5a427d934a32d5779c5db47df62a0da4f39bfb80" },
                { "id", "0bc92da487d62a1606ca588c6e1cdd2a43d6e3dc481c8de9e27686c21f1dce20b120815556c1dbeef05a212b9478e2ed7f28a62d51e4633902fe8ae04ad7a800" },
                { "is", "9bcd35977a5890cdb583033f46c80cfb23f4dc4a8d718313fa5b31950d1b976c08ed9b4d2c58cace3be908b59b855402cc96ace01e918b20fb334bcf1687205f" },
                { "it", "105513d19cee7b091df1a007278edc4322c3ffd99fc7081b8ab87bc867a099aa575be3b6cbf2d42861ef69e7e1a915d2fbda8d87be01148e9a8ca492cb64f269" },
                { "ja", "6b1f52865b29f63bcbb5de10a344c0fd414c5a9c2d5d44e57443b4a162caaeece3da34c3ceca0a9cae6e22c114b4a247e66be42d4fbc9d7aed7efa835b90ce93" },
                { "ka", "213d096f0ac9bf11e9b68ce9f3e120a1e6b38a17aef26b3b3bfe8bff96791dfd4ec8575d45a2f8321f90db1b65a7dbde09956373b57d28b7079534473d0679e2" },
                { "kab", "58828b7a7d3ab7a6488e2a036bcb93e4719abcf481bd469b65e58b8ff9ebf49f753b4bf416df60cfb9c614d7b9aa995508d0e367deb1c168570033e61c7a165e" },
                { "kk", "7b3cfcac18e62943246e1020a1557a70902c84cd7cfd04055dc861858eda51f318b788cd7acf78d0324448ce9e6a7e3bec80c37b52f7ba5fd474ab7e6e5ecbfa" },
                { "ko", "7b707796fff9e50662964f11b7b86870d6d653c2a6ffeecc34fe97d7778762fcd7e0ded77c080df92ecc46d141f2ce2e3874f60c678685815d4386f2db120dda" },
                { "lt", "0e0794b9fa7c287dd7a9b502275777ddf6a86c4d16e0dbe13e55eedb50515474302afcf68f1cca995298dc60e9835d226db35c97e7ef2b7a988fd374873b67c4" },
                { "lv", "babe7450239531a282873165fe213cc173f70e865d67bf743824d22b1ad4aa8cd4f1d6344cbdb00bfea624148335abde963266d39ad430d20bc48a28e6b8fa1c" },
                { "ms", "cfab4ff76d42315e206455ca73e43047be1cfda3915afd7ded03a86060c69e072f963e35480174bd1bc7599255cc548c39aa7dd2c918d6710865cb5ea7321731" },
                { "nb-NO", "4a5037bb4da74f81f5485393a7b2828f7ede192a753e9e6a1950d0c222dfa3e463d6f81713fb57cd5cee8f4ea493316568a8681824b55ae525b1f77bedf27418" },
                { "nl", "eed3a7b664568bb369b95aae9869cc01b28438a65893a91e1ecb377707e4f2619084a9463d206b6ff868f398e2cbf68412af9e6c612fbab9a6f0f8c1fda5048b" },
                { "nn-NO", "ba947eee0d717250dc9d3a9c463249d4bf6dfc5d2ff4f9d9dabe488dde53a89f3563e207a1023cdd9a0432b35ca1e06c59d669cb707a9ea4870662135cb55ba9" },
                { "pa-IN", "e4e953d6b51b437f59161b0b8ab3296a86d246f53892e46d719b1322e49bf3338584c33e44c607fd67f4f779b07b2fc8a2d959ee5cf299f94bd8b71ed33ef910" },
                { "pl", "df20054c8316311b2d76ce16f01f599f54284edf832094aa6a71cc1fcf6881745d4a2721649f0d531f060d77e0a70b9f90f624035ed55bfd0c8deb9da5ac8045" },
                { "pt-BR", "b756b7778f8ccdf70551b4308116925509110d4862520eb28c27c09c62141b47adc1eedfb4b39092a3c4e9b5e00ad504f3105225ce18a3c155d00f41e69b4add" },
                { "pt-PT", "8dc78e9b56b000379886528b7b362b4a9bdda0846444346b02b9f70ccb51c8f03a20e0b18f4f60ebf4e67d81a26125e42645b0923bd6382d6c48b70c690c997e" },
                { "rm", "ab53ad335a77b84658bd8c629b8ed2aca8398e6f00988d28ce556a91e2d11caa4902d549407c7ebb7b0e050c3b85fe192f8ce5187d0a23157eb7af08530e4e7b" },
                { "ro", "4679189c940cabdab509a5083fc7c237eb5bf9d6e3f9d58a0b79fc8bee072b3aa6c202347b3c7eccda16c1da8e331adf49cbf423952dcccecbdaaeef32b7ae65" },
                { "ru", "546612b715756fa342dfc55d0145de7e1333c5ecdc470e06f0cbab7cb5331b262f10e0a00cc0d05d44a01f11630c5c000ebe808d7f662a8478ec62a839192a54" },
                { "sk", "49dbe0ad2d562771b2dd51f974cb2e5408c82fd55f4707315fe51880be1751d07d6d94e91c2e10a0e68bc1cf2c7be59b8b149d8b6266de3ef7786ebaaa6fed4d" },
                { "sl", "67d945ca77d9ac8054b9b41741efd53af85c03d4255979664b0f28b4683b1a507e863daf4787306ea353526cb42dc71a6983609665efb2175429ae047c1691f2" },
                { "sq", "0d1c48ca41d58ed4bdb2bc10c5618866080a4a5ab21a4732a7457ed08ded1954d40ad69c185c551b24c8efddca20a0bcd55683499093779451c6c0547e3c8962" },
                { "sr", "a1f4b3c190f26d309e81ae6b1d491f8c8cda06fbcdbe575f7f3e857c5df34c54a07b351b27fedbe6d4920d4e6537b7f3ac3fd128ba7263bcd68375b3e7d47e04" },
                { "sv-SE", "6fccd982896c11afcac82e8ce3233362060ab99af53010e395cb87cfc67cce7f2d0fc5c34c39f011b7ff3714b50fd64678099798b3e58033c4d43ec5df9fccae" },
                { "th", "0a0d61c4adebcf352c5296c625627171fd8c2efbcc858200f7ae579569ad3421f364ba63de81e40e1a2c95983229cc88fde8cab83263bd1faefe7dd1d830c961" },
                { "tr", "a5aad216b58aa2c8cc735311b1a02d7921cbbeb2c541e851ad01df4ab7d278ada99732487016318a2958018534cd6c709a2fc7f1ca3d2dac6b1c96c125180b1c" },
                { "uk", "bc01752240b40c3646ecc1446b68bcddf00427992caa30150709ff2453aa6439528382dedea3eb132229073553280684b1bad34c377e8cefc13c1ae8d7d6e7ed" },
                { "uz", "88b8e735d3dccebb12e1bd349333f68b71a3796e26e4762e7c4610c7962f5860a2684f8dace6c9c0a507042ad171fbfa3d2e2d13159dcfb3b175b9afe3192f4b" },
                { "vi", "3ea70b34abab7a4b358183cbd144418c1a6c5107033ae1955118d098eda8092d9cd834aec4d97927e632711855cb842630d43b60e99e02c17d60f2134eaece30" },
                { "zh-CN", "512317087b82d4397510d4ef28bd0cd817a978e1ec09505a72f986d0f172dbf8bebac16b65b7c49e736d0890a01fcd910dae0ec49714280898fdb0718de73a1f" },
                { "zh-TW", "67ccb6222ed1692a98d9ab92f08e8307be42b577f75a67c18b513486a029d71afe72572414c83126cc29a31741f7c6b2ea714d5faa40ac3ac945da7d35a8ca0c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.5.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "87a3aecccf35c858d21f94c0c7ad58c9de76e80256f2801dd87a3c39af4858509ff40e0c35765bd8e9b63a7cb00625267116b80351ba442234d12c17a29f130d" },
                { "ar", "4cb774d269eaee6e42330a0a8d9397fed592f8b841afc09a18712e265cb6f4ebc4a010de85c544845504cedff2f209c5f8a5a91c9ab9eda875d9e79e1e3ce62d" },
                { "ast", "b4195bbb47ccba5747a69997b68671b374b92c42f9a602a37a637c7877f1465cafb81710f93416f88df4a7dd21a3faef983038058396608ab6432a8ce6a1d7d0" },
                { "be", "2e209a7310f1f79eaa1b0c17d67a7d94a778ef02d693da23ed85b6ddff72454652e9000fad4876bdb9413825ca559fe160bd5bb40e45937f452d55b6e411248c" },
                { "bg", "2a190a7cf113a8821791eb730ac1c25be3b9bcaf885bf0e885d2cf4cb30747e40063a4d2cbe2fd5aa0c118d1e34df8b33d9489f6b6fae880b9a03e231af91b9d" },
                { "br", "7dd5b628734f0d44b79894e2eeb567f53e51eccf78afc9f132ed6ca902815478475e1f2bf07f91021546cc917f6d866429fd1775021b815b261a1294a95f413c" },
                { "ca", "0034861530b0f21914d686f5bb804f1da6abf7df6b02648c49916315bddfc796ac48d97772395b497130c6bc5a3d27899c4df12266c23279a10a052b242459d6" },
                { "cak", "44aaac31f852ae746ab54c416c2b494092b7cc91b84d3fe4887d9b44ca89f6f0b3a36636ca7344c367de61c1f0b032d64896d96e280feca69c3bf39e32a09b14" },
                { "cs", "65c5272e9d671ac4e12ade3d747a885b6c027e6594d8ab7e965b79234dc5cc98def1d900500ee55a3a4fc9948b4e1f7973dac7502fd22134bdb54a96a58bec95" },
                { "cy", "7b27dcbfa818a22dbc916ebfb42edfa44078cbcd7e90701779ca4cbf720b2db5d8c1b76b5a163ea2bd76016d6d2b3331e851a6039ed19aee2f861b0db264926c" },
                { "da", "1fa9555cee42be17337f0ee12c8f55bf9f04966920c082cbc3796b783ca2dc0a0ddd26cf9cafdb88ff97fde297074d89b3dd06ac3cec51f1615a7d6148789edd" },
                { "de", "4c3a1993013f175cd4677901609f2b287559dee1cacdae356cdc314602c9f4505686dc73756845fc593deeb47f784f219e038628d00bf18e5418021298edad7b" },
                { "dsb", "88033a81fd64b59fabe7da180db4f8222b650a18f8201e0287420c6aec7e81a403401d9000245392f7b162100f744e2702f61f429e592a9900e2610a66df1416" },
                { "el", "a3f591d04b43107244cfb5e8f848edba766da8bcc4027f64199d3d23fda3757985060d9aeb808db823eceff0dd28038ca05542d648f560eb0644ef41da6122d5" },
                { "en-CA", "f6f42fb90708b655bd1bd17396f2175b8fa52091ac5e22d49d88a5abea5191644d93ef8a9026307c81f2d383d6ab014f44346104e61f03ac5ae05711ee368dd7" },
                { "en-GB", "91e31a3095ad3f6765fcf43ec9157250ebc44e766cdadcca1e96ef16515f8fee9595491a66ccb4d049e8bf29f678997f030490ef3dc51ffb7e0a41b1671212c5" },
                { "en-US", "543c377b5a58f6480755dbd9291dc1496c4959554addedfd924e28779b9e61cf9d2ac4b519512528eb9940bbe6392325d9c06220e0eb974e869545b6cb6187bd" },
                { "es-AR", "7fe26f5eb79fb6fd502b19cb4d3e4ac6f89af7dd858cb32d50730a0decbdf454940a8fa2e42524167e444ffbf4dd90007352d1c591d810fe8bdc7234d5ae5d45" },
                { "es-ES", "ba16accdbf7fe2f0917a39ca287f04b949e28b3712f3ada1ab8837b9fa55ec19ca250489bf4f4febb2b15ecab70ec6a836870ea0aebeea536ab3c2f60fd5af33" },
                { "es-MX", "bd8eecd4d53b7fea087d1b3565cbdf2eaf14dc7041fc51517bfbd20b5c1917f876209366089f8a66aa0e3891e06775eeac75125735242f7838fe576650cb1631" },
                { "et", "64ffc8a9f31dfa6f2160f38431f0b70888c75436132d99f2f49281cd3c569a9d0256be047d73aca19a1c2b52060c2185a3aae4ff418cfd39df3c0cf73ed4bb61" },
                { "eu", "0e4f85dc9a9ee5f5e4547579696d136123553d292c40fa4dd68ffcfe0a90b7220972983753a658b00d66edd3f289828d87681dcdd25344e4c7ddb5210932fd39" },
                { "fi", "280a55e8b4f22ecc2167f7380a4bf8aa9af1654d87925334e94b39b130e4853e38d68dabae28ee6e19d1160df78c668eefa3c1d92e50bc15f48b0828642bc730" },
                { "fr", "31e6a36dde2c29ed55515ba748123b73f3e4a7dbe903dfed15f5c2af7cbf9a80f2cccd893676e95d349835aa4620185d626642803405826f434ca737045c988b" },
                { "fy-NL", "acf56880fcd2a90990857602747fef6520eda1ef0cc7cedca2cd1c7cb39b25671d6028cc734348bb02ea9dc269101e155739aaaa46cefd75ed7d4935d8469768" },
                { "ga-IE", "a2da7da7669ea8f4066400c126cb20f27b8535c155f961e98f042d94d81277f3b998a1092c8b30a85e5691b9fa1e60bf2d689799b6488a1bb18e26559389519b" },
                { "gd", "af6690bda6ceeaf26afe7a48529b30c0015a5e56f8dbdf8c55cc751fb5dad98c2a50e436cae018afc72b43f5215d1cd891389d35cdb495b04853db121c7fb99f" },
                { "gl", "f5b8478fd1ab6ed4a3a727cb8d7c52d45eec943ec3c12078ab4931cebe2a65fdc7c5e2e94e3ac0081c05b150c70644073e58dbdc14746262d809c5746aa7d4f2" },
                { "he", "66f34e3a81d67ee852baa1f16eeaa11b69261314faab9fbc66af1c52a4d0684f6a19ebdc82fed6b8f596bf5e08f6282314f6e80f7b623ed981067b6d1d1e8496" },
                { "hr", "bffa9bf0185496b1f33051f17906d6053da96f74df062fb52a2162ba5178f1a4f0ff3efa48123d38753cfb45b193d0e6802c1ae689c244ff7dc7cbc6f596f493" },
                { "hsb", "1e97585d8d73c8c5d1e299db7d54711e235f9db31c8038e581952613d9be5b52e6dca055eba2697ff9fc5925d558575fd1ab7dcde519fb506c7e0b526d8baa33" },
                { "hu", "cb0c4040641d6a83fe98d983bf653d88ba01ce79a418f9d1d1f2afb31167147fe068763439feca78e2ef921acc4b9cac6c27db728ff7953df6386710fa0075eb" },
                { "hy-AM", "412b65c8439addb41359dbe37b2eebb638b1b0ba4af56d35ca48c87a61de20b2afa3147aa785f212485c0384c6f353cb9d850d51417bca96cf5744329531bac7" },
                { "id", "ab128239401caf89ffe7aea6dfd1c027e96853044ff720fef03777e7ccb542eb0ca072124e5505dd1fcce70d0b825dbc3c576fb1ed8ca088139d54c61e8a716b" },
                { "is", "f5dc1c8c5b52bcc4d17b3c6f80ebdf18285c1f0f6c60506dac35b9b6bd86c8d409c250b5504913a042bc32e34409135608357b69219afd19f01b18762d02ed12" },
                { "it", "23d979eb21d9d59352df87c1f967d2881a4ada5ae59529b6fcd98e71bd4bb5166d8c55c5ecbcb39a8cacd2bffafac9f4c8bba4b7731737389f8054e36f806eba" },
                { "ja", "99d6c3cf86a108f206f2e36723f6f8ef7690a3c59ea7266700d4ec69eedcb91fcc9a52d37cf3f16bd9286aa064f9a93e91c276ee95c33565ff9bf07843610eec" },
                { "ka", "371e3d59b794c1eab5bda8c13d7863a1cfcfc204c3491d0c8ae3705a4a36a644888e1182a0ad33fdbdafa662f96ab7b96261e355da39e6ed1b77fe4f67754d76" },
                { "kab", "d6499f476f101e4365c055fb8cff42a8a3e2e0d9b34b6460964f35bd97ea26b744fcf4294a4903548a312a1787c22a35e5ff9bc43fe6d3d3a6d4f0bc7802cfa3" },
                { "kk", "52a1c0d85557382eeb8a9e8f46843b181d64d89a51392794523269b7937fe6aee0369ffb7f18e86c0f2eb1ecc5e94aa837d33d10bb19b47448a3c477cd0dd9cf" },
                { "ko", "7fcf598dac6c15319bb6f68191a78ed5410213d00cc6a8476fdee65c72c1215ac0b14e3ec52ddb21ce92af7d8d2b90d71d68d1a22c9d33be7050996750258dc7" },
                { "lt", "c99ab150ce735bda7c2051d81768f69a32315c3cbf4fdbfbe5a5788437111fd533481c24577bbc7e62b94be6a004db5ca71fc6947e0fdb6dedef9e152fae192f" },
                { "lv", "c6aea5dbf9ec0169fe721c0373fdf760738751b077f091ff8c27937f3de9c4e3369fcc744a6da5e220ffefbe93c40c4ba8d24d811b3ce98bdf90a23094bb92f1" },
                { "ms", "3174a28ae7c5a3782dca70d35abe8e676bd2809971a0931494c56e81ea2fde0295082aedf09198cdda4aa8eebbf07afb1c50c9bf6f94dea28466a07c2ab1b3e4" },
                { "nb-NO", "c87aeb6db131f95f92c4d194eedde70454bc9c160eabcf012351eedfec019ec7e1770811c5fd9ba70562a1a5d18914881ff367b032e77a6528bc4add11005b28" },
                { "nl", "75e9d94e0159a06e5bcb12a6f4e839631283e1ccfd91a07ae1f9f5c0edef41528c26ba04beb9fd576059a482f52c24e1dcef74c345c27d40bb7113eb1b77b4dc" },
                { "nn-NO", "a288ed7bed146432519d41cee97b92bc329a1c48325029d66382bc2472e535546979e450946d228623e4b626e1912f7ebdc54642a6afa8c572ed9cdd79273c54" },
                { "pa-IN", "5ab9f501367c0a516b27eb64a125e6eb628e3ea7c28e4a9a055906fd52b78aa414a7d7116ae3b69a81bb6615ef6a36a78f4a7760382841f97568a99c5cd133fb" },
                { "pl", "f2885e0700a9bfd31668a3fbda68c03dfeb3fd852b099e156753e906cae65134bb8b886d52eab5b3b4d68d895fefdc0d258e1a61cd3a1f282cc2b8f175775102" },
                { "pt-BR", "86476eb64c942a7d37817ce376004ba25b3df0462c0945affa97056da877cbcac1a4814bbb331c06da761fa9f0c048c7f66520336915990f8395e892248d7f9f" },
                { "pt-PT", "5c242f30369a9ef5fb272b6c5c5c0e5445003b7f1b819b1debfd0c4684ad6a9fb7179042dcca61c197b1fa938036e56e6139d00a6991f242bf1a4fea658c5a3f" },
                { "rm", "18eca093ef4d12f2f23a82caa3e3c6f4f5e302f6f814492acdb3ee7c5f954ab2eb12d785abee61211667b8bf2e8c52dceb3779217cc02780a09f82f07af09713" },
                { "ro", "610c6c099cf2b4fc8c7c3cc7f608b0836984de07e5a11e19d2d388f5ed96a7de9344d1206a412b168a37ee426c8ac14bae757ed6bea5f48a2386f1fa51f7aa8c" },
                { "ru", "5c15046eb728d1e7fcb811948c5cb53b8d4986ac99fc4b6bfbed04b26e142f313f985899a69c198e26b17946fc81379f938a7537aed19621cec40010a89d1ca5" },
                { "sk", "d98e0c8d6d348eded4788367e5f914c6375ae89d00a773bab82e7b35e8386c789fd03782bb7b710ed1a52737820d8e6cf620cb122f338fb971d785a76272a1ad" },
                { "sl", "2341c2bab090e40d7b84e1d7337db77e69210bbda902206f6a042a2786510c68e9cfa9b67b3cc2bf11226dafbe4dc7882485a3169cd507298c2a330121b17ae6" },
                { "sq", "bc38880cee968dc53ad2b1e628a37f747dad332c37e2acca340676667cabf6af8c97e783afcd85e51eb41009b5a7883f519ae5173a5a7f46916d83d51636cadd" },
                { "sr", "ca813e81266e334c79d70aaeb6dc82d74ca948f617ed8c05a7a1c8dad7b422643b0dba42cf216366dd2f1ba52d0e10fb89707cde544d40503d9bbc2366e16d40" },
                { "sv-SE", "cce759807c65177faf7a2ea63dbdcf0265aa75dfc77ab8ea1177134f7d63b9ef113d1293a136af5afaf2a41460f4bcd4fcd62e8c3ef62c5a947b83673726afa5" },
                { "th", "b256139863259820d6c6e6a4ecad98c77c689c98c19035fac9665ba0969829ad58fd8ac768aa56bfe4b9d825c2ab6f94ac464a1d749185e1a28d7f866c1b9be7" },
                { "tr", "a73a50891276a0be8e9faf7ed7d38e7890f218ee081736543540b624088e792099f0db53f721ebef204dedeee492f89d2eb46c88d913d2036819a82c23cb4926" },
                { "uk", "f608b46f5cbc7eaf59980cf205970e0482abb1e22ffcf0fd77b243d49c05c37c1e8f713de925ba8a3b1fa75126eec465468d28cb514bcee8ea70ba2f95827a19" },
                { "uz", "2ec5aad80014e74a4f4afa9a7abe7a302e4fcc159fb11423159734bbbdb75c895555750370aecec99cc170edf2c63e65d3ac9a89aa0a2eaa13eab6c5cb51c4e5" },
                { "vi", "1d9a321853693bdaded532c09a543efa4c98b14ecc24937f908d14e7c3c22929984314fc47d066b1f1f40985c26ae84f7583141ab30b3756855eebb58d646dc4" },
                { "zh-CN", "0243d665f972fb26b625488e4b65e29be76821a8b425558a7ed1a587b60acb4598796505a5eb7b24cf17455a9f984561b9b1165aaef3d283e9c9d94679b5f473" },
                { "zh-TW", "d2a7f92358a188333d0dbf0669d00793a082435d9df5cced42414e318fd1575d9ee05b107c15f311dbe39f6df4a662ca98ea0e773585ce00017f694b5280fb28" }
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
