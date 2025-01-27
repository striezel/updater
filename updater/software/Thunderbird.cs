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
        private const string knownVersion = "128.6.1";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.6.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "ffc42ed5551d6d94893990842f91ee78b9185111510c18862eadad673bad767c99478eb2b147b35ebb1564fe14d78577d4ca2f494cb0b1ef96eba09dbc2ed8a9" },
                { "ar", "14f341ef729232c51c06de1909604e7f5deb6c58fad5bd6c3882870c0ecc5aafe7ef9a9a3e884d4be1d92192251db2006fad5a1bc7676bef32cdd29cb1a8a737" },
                { "ast", "38d9ac1e76cc82cc841ce633f8127e7850ce2f204adbdcf554b2cd48e6ed218277c4a55cdb215143ecfa6bdae6a6cf38b91a729a11a37d125f1878923bc9e228" },
                { "be", "d7aa595ee126fea110144ea33e3f9351bc0700e24d22cdbf77f9e7e4743736df9784e7b42167f47b460d2c36662994d89cff11a8084393fb375ceb2247acda7b" },
                { "bg", "0c3edb8f6f939ac90efe6a12090424ab353b272c1b5edb5ac8ee50d199ab1ec79321528f85afaee015fcf72287aa57bcdb9a9dab40b9addfc597f347b311c53d" },
                { "br", "a1402a21207a37696d7401856aedb88fb459fe996f6328bae133af9bc722f128690580f99f0878d455bed9c09b3ac84b4aa372c60f37237a4c5b4cb65788ef2a" },
                { "ca", "2219ac0c5e11a6c6478ab35acf2ea5f311d1ec74400c66a908159bb7c430bb42a25d51225a82880ef54f01ff1213707ff83e3629ed3bcce595aa20268d61f2d7" },
                { "cak", "f6a9457475db5cec0ea09b8239d068aaf1037d877a54f58a1714b25b8b754cb26ae30fc1c39e7e8a3f25e593682589c92ba796efaa6ec40085f7ca5e8b77ba65" },
                { "cs", "40e26628d25ae6bbc10b0b5de95f5ffcb1c2f3dce89972cf95ff320874697a2870c4dec4cb6ebf98631a31617f79fca5def4a04920525d98325bb800b649bc99" },
                { "cy", "668310aae84a6c598968fb644aa57353a32f2acdef2dfbcc1a87fbbc0ef26fa74aaab546e0f1b4f495327ebb34e670b8d263a5c1f0fb5326e0f83936424d31c8" },
                { "da", "fcb0c014cc6514e4d8d1f7527a6c904256158ad673d77d1d73eb166daa26bb4754b8f98af23f0d02fe52558aed81042f03b47ab72a9ba48adb5df8151bc82e19" },
                { "de", "77af767fc9dd047ffa4f3487fa4203d59967123088b8d9d9b04fa36065786e92d33ad59817bb565641498150ed948d0e9af96096d53b0c64efea62d7c07fd8b7" },
                { "dsb", "59f6755c4c5fddc2d75d4238e17210037a09d87f37a083d8d389c6589fa6c10c42ead2f609697346185187b6823b1b6a152503bf77b49128225ea56eea38a7f9" },
                { "el", "5544ec49134fa3378bebab9a593c88090763135a8fcee67c36e746eff8085f1622d55eb2998fccca126112856e9417c3c314c594cc44f5c98a704e0016a00f3d" },
                { "en-CA", "c6f52e76b17b3c5d2d23a626999f8559c99d516a9bd813fc8f30cda41eb2141049513ab15af58dff3c0e71cd643967df15c23be54735de16d7dcc6fdde08cfce" },
                { "en-GB", "4ffd7df77de5a7343075e89e1aa3543c433272c3ccc5f5900556e9d611511a68d6ed798cbf72e9e3600ea0d2b45bea7e66aca7065c8347f15540128afcc03110" },
                { "en-US", "91e6bea3f7b4e18eca25ab338a8bf90ac5891082964dbfd9c0b8dbcfc23c881fcfff4cbb110dacb382bd51348a68d9095aa439d41e70163cdc9cca33188a64ab" },
                { "es-AR", "47b1713386e3d985f52032d24d7334783905e9b65c8aaed3040e12c2228a58780e8e6a76eec0b694d70d381eb499070140f34fc903b9a57226eaa5a5aaebf9cb" },
                { "es-ES", "61ff91510cc51eaba1b43b2e2a415f15c94dd413e589a9c7e9afd70469c21d7b6f003275ab57d06d1f123a1097e22cdea0452940180ddb3ccdd83a13e0ebd792" },
                { "es-MX", "e6ec223ba1a5e205b4e70392a4d8c4ceb7c16cafe5a658eabcc86275ea3181d53f8e593c4c2a506730197451c1205ea2bb9d564e6be4d4e1fe98c09b5ce61230" },
                { "et", "0513b4b7501f5c8631fc635bf5f72ff60a756476b18cf9fb8d2012d86f3faed7b45f078d06d43e3e36e4d58af241d68f57aaf9b3c39808391b1f33f819153603" },
                { "eu", "eb3e55152708a4ab616cc157949898c63acc6fe0df94af5859926ac3bd790625c638fea9ccc3bb7c1ca6b7cb18a2f4d88fa3bbc3bfeaf9ef017f9a4033cb62b4" },
                { "fi", "72f8badf2465ccec2634a34b8722d511b8e6e01efe8f81d989bb6dfe508c2ecdbd88f0d501fe4ceba5ce3472d6a76b13863a32d35958963d61355ab95862bdad" },
                { "fr", "aa83b91ebe6ef0496563cbc2700a40c51120f40ffc97ed0065895da897c31fe90eea749e95d6db024ca2cf133d481aad20dceb2c95d6307db7e687aabae4fb00" },
                { "fy-NL", "6462a011bcbe9aff80a934dc69fa457b203d57017f77b9a7e2a99749f00926d8530d5c6c554e118e423093093b0149a04e7c5573eea1731bab2cc7852a672d54" },
                { "ga-IE", "981b1ca4f0ea75f4772d5c85f88d06a16ff6ee2975cf4ae43218657f11abf6b76271bca13b7729ee0e6761e462c393128b9461ec3a5063e6e90ba8854c2b5f79" },
                { "gd", "335f5e5294ebfc136335a627ba69b288a613e78d077085a2588d58c3c20ac4b137eabc7970a6422c42325253ba69c92289118a381dee0681e2c5df05aaddc082" },
                { "gl", "42601dfc06a49a78605e9966d15d4e00f3fd40f402f260b074e9d5ac860a5b7d59f0474894c0bb9c14603d9741eb8f6d8d15d4a1b0ff5c3bf58377e4d6ecb14a" },
                { "he", "5eb03b42b6d3f6ba1c2cc288600a77cce7a8d6a2fb2dcdd7af4aa1ef72e7cbb5490f716334261adba6b036f3c5dc34554ff4ed14517fbf59c99af0bbca0123d9" },
                { "hr", "ef0f44d3c57bcfb4d4c2b46709aab35f6aa6ab8c31345121e00a25a1c039683e09a6e987163e773ceb954f4fcc221704945d7cdc5fecc53b5dc9427213304a2f" },
                { "hsb", "e963f435c9a2b41378b5a2b8550ba8b74d4c558890217f3ac39e69345e1d7d313d80eb9445b98f0334362b4486a7ce9cb30ba71eeca56a52981972043ed74ab5" },
                { "hu", "ad6ac71e01044f1c21403050d8df275a26514d309ee41a6170957a6bf9dcc667b28f54d1540b6bcf2cac5531bca03b28fdc51eb215577531e25e5f971727bab3" },
                { "hy-AM", "b16d0212578a36e503e659a292c3f0c1996003d4b8640ca97ec00839bd555359ae4bc9f0f7600e6ff6382bd12de3702eefba806dc6538627cb89d2baeaeb8c1d" },
                { "id", "0f60a59fb022d60ef79d662cc7a631b82487b9d9202a42d3e5e8d14938b9e5a5c108c445d1719e08bf5ee880f102c7ea1f94d0a49807bc8929d92f9c718710ec" },
                { "is", "ef8c23e76bfdcc72616f1b0938eb27fd02e59fff05869691e8fba97f704336f52e448a760d818a6d4300eb45738772d98c65ef0b9c419330482478486cf2b472" },
                { "it", "ed14c148d48a06f60cd1889d6c0fb5b7e36d87a1b62a16a3d88ca4a2031226f41f41a38ce04de11c22f93151a3ae121e686717ec249b5fc0cc98c683bc99f57a" },
                { "ja", "5123ca65de04767ce2f4df13370cc3f2c3222932d9f8713bb1a796e09f63c8755858e62f02b88b27fd6ec1d78d20fd0135082b9e5c88ddb57ca0459f5f42e074" },
                { "ka", "042e2f88bbfb094b9e38ef2bea827142ef2755074385c6067fc37a41dc5076ec87a784177a272e0d0718d2455dbb65b9eb8d3deab91975738b53a4b6afd88775" },
                { "kab", "3bd475939d213eb1b7c1cc9c938dff75c66b19aa6dff319742d0be8ccfbc148a22b0b142892bcc2da15df3bde5d4afca92cacd1b0e56ba08613ab9d5baf0a3d1" },
                { "kk", "c7966684afc649f508a4f249f236ab74bc951c5b6c7401fc47e9211f88e026649da213fe8270ef255b049f05e6be8093e05992f4c1d287fb809a7f0988023402" },
                { "ko", "6d9232ca9379d00bc248738e7d42b6df143497eab49867545f51ce190b358b0f10fc672cf38be2ba736d3895e267fbbc613f97718e7dd3f4d57c53c2db696c85" },
                { "lt", "856c7705b4b171b080e9ac85506ec67cdf83a5ea9c74eb0ec8289432b6c21eb0e1c18d4eb1084fde80502896e46a8cb302cbb06ab54ab465fcd5439d7d8a89e1" },
                { "lv", "7ac9af42c28d43a12767679812572055e3e9c997ddd64a24d1d1a5c3e6cecd36b97dfc1f9294fa62ab0cdf952ad143b32452b74905e8eac8419b3e3475813de8" },
                { "ms", "ec471a73556ec35161db0e8648b733fd84e7c673aade44e78353a3a2298afeecbaddb62942c6d36da5f193f518e345a54f44ecf01c89e6847d440b1b7aa5aa1f" },
                { "nb-NO", "6feecd13b739c707da10340df8b5d7e2e0b2ac298d2d57938373599c875f06879e6c8d5aed9aeb65be8fa4d7ca34421e9ac5a7ad858b12ad7efc58e0b0ee1da4" },
                { "nl", "1cb005aa650f5c6dd2dde4b76c182fdd0ddaaba390742080e5af491f9b3274eeabfd4dd992f376f2c368a802b70abc3162608944ac0ea366410008b2a2947889" },
                { "nn-NO", "a2fe6faea627c12962030655ed7e0fcfabdf9fc45df352d5b50f47ad82ee7d809b7248109be858a6dfac0796dab4abb3de9a2cc3a1bc635540105567320e568b" },
                { "pa-IN", "cb424093b90d81f507dc55fc9aa95b6de5f2d7f9904aa79f5f2d97adb96657909ed166da0cacd44292ccee34a81fd9a9edc25a8328367571471447e05ce74933" },
                { "pl", "a19f5af30cb8871bc12e17e8990a10afeefb7b145c985f12654f33831188d4e33a971ab944520302c49ca231399a9bebef1ed6f2c2ad4c7db96444d66a357079" },
                { "pt-BR", "bf9cc49c84f1c1c7f2f6471969074c9b4559f52079f8403b8cf36a3d0a38359d1aa6eb3c1f1a5a36f0bacc26efa289e68782edef20de93ef58e93d3deae33348" },
                { "pt-PT", "cfd56f773692ba7c4b3fc879b30dfd3e105bc02fd189dd9955eddc8a03fca1054306388f0ef690561ba75a75f65df0230857894090b9fb7adca38b7e589c4d47" },
                { "rm", "d179e04e47b14730bd14328342cf42177794c448a8e0df03c423edc3aaceaf7150183c2f2cf531595fa875be631b3a4f7053829f1ddb965efb624dbff4330750" },
                { "ro", "e7033aa7819668c0d234b619f59956732a93c1529cabca10f1d9a3e71f3fa804de214c438bf5d6fb7bc212787080028f8529f5ddff455a1ab091f302daba783a" },
                { "ru", "9a2a92c461fce646eb1ed3f348c5c56cbc63671473448240a24a13aace126fec5d49ab84489730986be03f1d505188d507d95930fb15f3f9554987fe7c894d9d" },
                { "sk", "765271af90c21d28e55c68dd557288e17fab9ea9ac952497646a1b99b1f5d45259a38c2de2e90501b58c8f45ec4d3040d993e3b30a7277efae16505ba8ab4e6a" },
                { "sl", "5c88c706ef876b993c8d23be788172dc185197a0cd91d09623ad720e77f52622545f004362a72f996ebaaca2aae64559ba3c1bf056153bd7ae8c0febf7d4becd" },
                { "sq", "c9ff0389892e900e8b4897b7474aa186d690596321b828b24f3d5d7c9554407d05e4a9355f023271410e3d0279a3cbf38ffc53ee70c2d1ca3910ad7dd9c08150" },
                { "sr", "1d8f41c54e2a2543c74542c89a39f82740cf716c4a77d140f1bfcd9182dc0d909958a9443466809f7b0e8c3ad329b56f57813fde305174dc205f7175064b222d" },
                { "sv-SE", "a9b27c7ada4e4b90a87a504e332688ee2d6b1d7c07a8ae0c6a7406a7d8fabd9c8b204acce81b8839fc033cdecf36b98d0da08d20354ee014beb6262d0ad7d652" },
                { "th", "4fc5a54622ca585fab4e886743f6b8658549b754f0b55d8b4fdbf041ff6c86ce6123aa3c90d944cb185a0396d42be03b33001c32a0b98e040e7156ffef761b82" },
                { "tr", "7a2da3f52c60ac31ef86cef0312c47045b98e92ce7cc469c8617782bf54ab31e030175fb21bc32ef0a5c00fba42e99958ec3c31f0ef780dd541f0dde7eb67c14" },
                { "uk", "967a4bef116f0688c346bd87b694a37daa97acb6959792938fa5481579f92f4f84793eaa177c50d05daf2f8728020070964a7286b54196f944e9b1fd1f8ed7b8" },
                { "uz", "58eed4324093b3aa35bade58a006b8adcc22f410de385569cb173a65170655064a68ac2b4a2c9546f453a3ba451a0ff7ecb47c385eb2a8e86e696489e42bb3f6" },
                { "vi", "2bee140c72d2289b5dc0bb61c0b3850bacae578ac575ba49e0ea6451cb442d95c93c02cc116d07d1a9da7b0dbe260252e4ff465e7081b850c7cc6eecb3655814" },
                { "zh-CN", "5e634f0944d6cf61db828efff05aaf35f3865e0211cfa6d2ac865ea96efe85080ac261f4987291dc3b8e4900117bc6bf291e2c9594feb6e6a601aa2e71a4a183" },
                { "zh-TW", "6dfee0282dca4fe9388b0b24aa194a15a055fe142752577d54270fe966cbbb846a873c4bf9b1f5e8b711ed80d819ec947711d834de97ba46c5a0a9bc4e93129b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.6.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "682a6fab7963a5631f4893ad5b39c88fdeb936873c8f4d7fe0540a69da00d52c29709eee09382278f2d15a66e7c025b6e6a9b81b9f7c0cc67308d96d10829913" },
                { "ar", "25a174774c59a47bbf1a414e1a6bf04a17a5fa6a1d399f515c075e71ab025801072104f3312f98df29cefea01cb255466340a6f12302119e849a61ee14344067" },
                { "ast", "a9ff4740a978562792bf9cf0f23443b58a2cd3ad69949c6109d9388767ebf9e733708266d8721ef289ee347237e001ee2beb809ae54c24cc08ca267ecf36f251" },
                { "be", "0c45f38b84914a896570224c57cf57d8f8d55da3d48d55b3b10d5fcf8e510bd2fa0af0201ec853058c3b34828f62155084dfee922590b356ab526bce26f112f3" },
                { "bg", "e1d74b8e6d94d9a100e7712cc055a3e5346a041e40b95c5e0253d7f85cddd2d3757776fe354510a61f862ca2937f9923fb803e5874647f5ef7316ba9ed582849" },
                { "br", "4f481ea744c1ef9ff111a84baa24010b0a495a74a2b1fe78800883e685db102b0335aa50c76ba2f5f626a4bd2896cc15c8a5e170a990295007e7a35f334abe8a" },
                { "ca", "7d097748b5dd7d92f8d96d75f8dbe58ebfdac1fa701d60015b7ca053a8e5ed7d2843cd8be313e905103ad589302c261ab3fde9a0c0085d1ce8e98a795a64c74a" },
                { "cak", "538f96b33c107e133ab1053894e4b928b88fa19f00033d9448572b17ac32fe56199e9fe8593445018dfd913915bd258f39575395db798df5539265a12efe3cc8" },
                { "cs", "8a0a2256ddb48cc2ec11d5a50c82f03bb242e5dd9753057f7a37f435f0f48c3ace9b95e1be4a7dae6528a398eb2f0881bea59c2c6b37c77cf9051b161d7a660c" },
                { "cy", "0af14fc4c4a7d3a1df06a8b32f0d62be7b14c54791977700b53f47c96bdaa5f120d9c3f8032c528a7917d51ebd8956726be3ace4e174354ba4ab511923c95f6a" },
                { "da", "bfe9b2d0d41e61310dae792aded473f36f9ef00963106c091f3b8be114fa8b4904e4e9ce2f7db96a942f2188ce7029711597469ea24e6c48f5aa67f98167e7e8" },
                { "de", "8d78d0b7f729f8dc2bc525f34908dec67bc844bec3311ec5eae5defb60301003777c47fe121a124c3ce6dc5a918418ae0b78d298ec49fbb8fe441547e824f008" },
                { "dsb", "e8cc4d2b480d0c45c5748aadc02c4709fb3c210e063cd6d49670bab7565ab294ebb9af2beb012ddc3e8fb510726cf11f992ec5b7676a6f600fc86958969785e0" },
                { "el", "23d8a55d0dd31b00dbe2487afbe83705289ff110a3f53d7a05fc4e3b897686cfc9934f16e2df4c0d8fe65d7ed63eb2b307a2e674de8a307e29019183f4530ff3" },
                { "en-CA", "4532004ed9331af71a46e66749d53310be80e53c8bd15ffbfa3350d3430687d966ec0541c8910a7545c0b2c271ae48ac384f089bbd21e2aab7986fa435c0da78" },
                { "en-GB", "14ffd522a0cc4ca4d44216dcf1408ce515570298f5a53c562eb48d8b728815ae95a670481208f885ccc6cfc7f381ae33b41d7e9ad01d8b2be9e57af8a57146db" },
                { "en-US", "6397488cbf389d793a88e6c06b179d97641594aca87313920967035bb9133811f88ecab845cdae21386ec0ea089e161d795098c2993ec2c4681e7b37249b85e0" },
                { "es-AR", "ae50621cd5c4721393f4f37b833188a4ac3fe0b34c5afb5944fe3c6fc71e31a08bc962c0c4a9c5af1295aebff3b7722d6fd16d54584694d448a27daa6bfba71c" },
                { "es-ES", "335d4c69a90f14cc1c066fd039eca45760bbf8fe8b3790fd328a670a67971f7cb59593c7a41de44147f4a96282af8c5d4184fe80c3b7e0fb9e31ed5dc7753ed1" },
                { "es-MX", "adb7ca78b3e1bba449942b655a6aabdb71c4217d4865dc1d3564d43d22e16119c500927a99fa71bfab2d19ad6f0a963239604be46152d664376a743b2018b819" },
                { "et", "9b3bd8171bcb6d9ac509ca3774b361ab01312f531a150fa8ae1c7665728bb67507977e31d471518011bea1373ed3e6e26025b6a363dfed06eae1099862616b80" },
                { "eu", "00f316e2f4ce523cb15e84fb4031010afac5d2cd58c383265580f10ad50a98e050ec0a62c7cc14ab4d68547bbac73bf01ab9b1051942439951d7f39e281aa092" },
                { "fi", "faffaf5c6af77721f69c0380da82bb82c97f67605945d98809e420b48f4456c7de2de807f37aec11de430965dd2035b8bf4c95ab321b0ce1fbec10bd9b9971a4" },
                { "fr", "ee7f8c40a9e68baa6b673dc2adb8e2452c43b6c5acc272d5da35f62318ef3dc1b144c036362ffb539ff1c26bd713b1238489297433013d460048e1804dccc82f" },
                { "fy-NL", "ddca11cf742aa72e9989935621cfe293e18b3626f8a3cbefd241e2436b84393000847649183fb6fb3f9de086a729680725e34d8b742ef424cfdaecd0aeb37211" },
                { "ga-IE", "55d78fc16fea8cab2a44e066492595cbc88a79b77f54ec25bd3313c2c52a94c9811b9586aa889137e5f58792741a8bd2e7adb95b9887aec4b1a20121c535ede4" },
                { "gd", "aec9817af41a9162c0dbee9f55b5c60294413223d63d26e1f19db310385b8bd35ca8d249e181675b9a13bfd2b2b30fdb5bf4a0114976806f835d1d420fc53205" },
                { "gl", "235f354b70f559c39108495699721d38d864efbfb22833ee6d239e3793aec1699c1908d0827dc87de401835c9404c09cc82c5afb4bfdaaf4bd0d58b5b613a0d9" },
                { "he", "4338f0174be4db6e7ce1742c29e8cc5c5defe8ebc27293fa3889cf37c61160a35f7bf8b0e5608f8d1451a5568084e957ca1a7e38b889662d923ace5b5dae9782" },
                { "hr", "d8bc09b163b6292209365fbf74b5ccf20a80c3c2311759d571b9816c4838a5281e24d9f855f3494c95658d7708adb4adf3b2a6da449b4505a37dba392aca7295" },
                { "hsb", "0dd378ef1d19b1865a6fb0d584a27587d2bcc12b1fa05e0bb3f8f7a1dfe12bcdf032b72ddc576554211a87e408ffaa58045b5fc80d1ec963ec10ffc14f2d0e41" },
                { "hu", "446394ae597a8dcd10b4950c466582dc56a4c3f6473bb3f05a920f401af7f875409d99ff7145b9c9e2bea34ed1ab64de478a360c18fa2aa724bcb3d2723b0a65" },
                { "hy-AM", "53e99025c0481ece19ca5b0de1ed6b2701a04b814f68ad34a4dd6a0dd8a7d8c267e25fab75a5b0097778dde47bdd76428846ddc3d1e9eb33e8fe245c07d38a5b" },
                { "id", "3997dfba18c8ffd96340f08ec0aec27616fa86d52c228371c378bbde5de8d1cda1663c92cee300dff13f255c6c761afe641cd626396861f57a9fdfc400dce657" },
                { "is", "788322daa5e61ab0affa30c21a2d6917dffe0beb76dc17e8bcdc463998838f89056cf1a4417bc24688c20d15d06f9a0bfb81f4a7140cc4f5ea286bc68c8d65fa" },
                { "it", "cb39dfffe21a4fa499470e869c0db626bc9dbbd28f9567f6ee0cc264df8cbde7c44752c4da644f8e7900893c610385f1115256dc1b4e7421f5c3d4e168613195" },
                { "ja", "893c298c2a3006aa497fb2867e008e320b3ff5b3728615cb0529a9982fc8b783b82998d91e4e561c506570e7c02f597d21c4bb5b9ae147083c246f4f50fbbe18" },
                { "ka", "8944e5596e25855492dbc81848f07e8528a0693f1eb1aabb2ec59b3eb8ba8398f425fb50d3726b5e99e69beff483affd3c4d582ad4473cb0b8d2741dc7d01291" },
                { "kab", "49af31fd89df3dd52db519b9bc49f8614131e634cd66dbe194259dd5475a5f1e60abfb2199ba8e65aac56170681254a01b189ffb00dae48d69667fbd961daf44" },
                { "kk", "f2bce9801d0fc4d0e6adae1e0e44cb76c7ac936621b26360d17df41287ed11371f817a06d38573575bd89af9abf9d163f8715ddbbe34283f50dff2e64853b06a" },
                { "ko", "77f147876a504a6af87fc643dd4d9644914537c1731c0fcbbd7c07496a0523c6eefff57dab0b28bd1a592b142c6c18ba25b51a508520a4f0648dfacd31ad174a" },
                { "lt", "21fab523c7227cef04c9fe9cbcee9f7dd4b9671e0cef8817f32256e8b054b82fc49c7de62836eea1b03f882418329c94421440e2e4cbdaef68ff824c02856e64" },
                { "lv", "ebbc7f58e223201fe63496b735ef7df8769d7decd7256ffd1e65fc48249359b1d44afac26e11ddbfb3e1912614967debe6c9819feb71e123439389bf74b27b7c" },
                { "ms", "1c81e0eaa4af55a79f3aaea64e43d08fa58f28f8357abb73518cfc32e6af51e86a0c7fca9d817d855a62da3a6070518e67c85a933bc9d98ae2b49e4d7e34464c" },
                { "nb-NO", "5a9d34f76bb26dbfbf00a827bb58cc3fe45a0d8b1a130b4757b6834f39c2e97dd61c5ef5a78020cdc95245a4cba823f2df9d50555bc1ba15960ef8ece8de9f76" },
                { "nl", "4f1684424247438fa834b66a05ac23186edbee8174a277363b289ddfeeb90acec01880fe47f4a09fe53d40c2462c4c5ffb620f256a548d89ff47ab930cef9c7e" },
                { "nn-NO", "81e137e9de7540d8ca487f77ce2a6ab24630f6285100965666c45a2a6b5bdad0dbb67571eb5e74b9015017c5005b02621c448698a7c3deccfb23cd7f496e0471" },
                { "pa-IN", "b844c775583471caffb0770c892158222953492adb58eccbb60074efb7c2331ed854a5f32da1d38e208c0e768d0eca8298deb510f6dba3c1327f61cca5aa1ee2" },
                { "pl", "0fbc2c897df20ff3035371e1b20cecefcf1d7170d197e365bc8e43c9ca47f6f5ae0e34504e0be8ba1d372cc84f83e1c11d4304976aafe7241faa4f9f1203cc34" },
                { "pt-BR", "5e1fb4939b72bc339739e8fe38b1885918982b167314ad0689fd8bf8b3f2c5c77bae32513ec691131b138d4fd1163f30bc021413a9b12c6f2bc5451a1e9171ba" },
                { "pt-PT", "ee4c2cadef29cdaa31bceb441d18b42138404c656442d4c6b78bee8e40bac7bf01cb03f3b4ee9e84df1203ac7b7555fd3a146748bc2fd4fbf3056ecbf29fb5d3" },
                { "rm", "bd9e49c0a61705fd8fb9a2e2a1002956203825344e493cfb4bec6d62b65e15017f995280efdc7953b4d71137e26922340863366816b2a61b4bb3ff7b15cea8c8" },
                { "ro", "1bc03b01e2c484bc8c41fbd2f55c3e9e80c0a8c6bc38b4004481a20830d1bf6c8c16f9aa370417876f8ef9baeed836aea8fb69649e7364276874ce6d3cb5c102" },
                { "ru", "5612328b8d2042f084fa4f0a3358b8b9ebf27fc51dd2011905f99105f929c4d67ad2b87146f968ba75ca88d381f630841375264542756cfcb590eb4a5c63a518" },
                { "sk", "1f6ea737e9b8ca78ce5bf11d95a3fae51c965f948ee22e51a3e2351ff048e4da57c8b02d94f8082cf1ef23432cb736e1233fb810508757c6e46ec9cd3bf7158c" },
                { "sl", "aeccfd3df328b1a2e3c94ed4b1e0c03db3daf5d9728379a39b8763752ab95987345f2390f03512331f16dff0eefe0bb7c5d19108494b7737d1fb3df2ff628be1" },
                { "sq", "2d24c906676c58565a26aaba1d54f32a93e98b2fb04affd270ac31891b480a83eb7937dbab06960742593fd06abddfbb9d20fe9b4ba2a3699208e27bce819975" },
                { "sr", "1e238bc60786cac8298eb8b4dbfdadcddfc54e9a358e016a4a8eee866d82cb79aa501598dd47052b83ec28a312fad1357bc598534ca1d9a424aa1dc3bf6c379d" },
                { "sv-SE", "e7083d6300702f80c37173c8b2355e5b29863aa7e73cd96403fc520658c1498d8984b353ba4017dfccd9582ccf7297c96bc51a81d91a2ba19f5140962a439860" },
                { "th", "37f4a99fe54611f40280ca7d0a978b5dd8ddb6566e1d306702fbc65a198ddeb497ae61a400ec37e9048fb740d377406349ac42be30de45c102bebced51e6003e" },
                { "tr", "7ed420529e35a40e9b24bb13fe54eab56e91060d8cd5e008c575a23ff22c7d7b213b3b84f4fc019268bb90b98e44204cb42157972201a8971a6f7d298c428531" },
                { "uk", "0bde1b5921d9e79887b96638e167869e71292fe050f8ff252ee00699b25484bbd855c3c8ae6209e2578aa7b9ad7ef9dac869bc9d90f352c31307f373dc589435" },
                { "uz", "da2b29abf027bc05774753f7932edcdd52b67c7535d29ef3191093f24d2d227bfa08c7b2e568a5bf5e823c15848b9bef656bcdd89875065f7182df9c604fe9d8" },
                { "vi", "b18655f4ee110ad281e58fe55ef632885b9398ef6976a1b26bc89999388b1019d15a830a032dc571a09df054f16ed0290da50ee198cf894dc505cae98a4146f6" },
                { "zh-CN", "536dd4eb89f781c938bd3ed784c9288d2b387b30456371c87361764e41372bca844e1cd67505cd748345b9e270e8df564179119b7bdc4454bfffe1bd6d1596b0" },
                { "zh-TW", "d99e7752619ca96f10b7dcf9c1ef1ff69e8ce136c7e14e75dc32359b57ee8dc29fa34c7bb108d9ce1365c4967392a7043574d6f612f3797fc840e3bd31f851bd" }
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
