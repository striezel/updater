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
        private const string currentVersion = "135.0b7";


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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/135.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "af600c895783f3e8e863af924d242cad2617fd60a9ee92996bcb056e10daab5283547fb924ad0088465d6e34664d4f2c844b50f5b2235a95eefed40f6d95d3cd" },
                { "af", "587116d9d19c1fa31f9472b3d34652fde897f86cb51e8db8d439d05f4373c79783b2e548b12ca121c9a5069f4df4df659b1eac5f23288c316f8974941de110bf" },
                { "an", "9f07a1a9fa5bf0622411aba955f642970721d206967c8aeeb23d374e5144e9ff9ab7ad37b212175973da8bafd875e556d663d9594e03c6a043c64fed8e4812df" },
                { "ar", "cbf2156721a59eb3367ffca365bfd2bede7ae0234b0ce6ae6cc897e71ac4fe6a9162795105e9afde4a9414d4f57f0e0b7a2c0c7816c22958ef8e1e43c575a187" },
                { "ast", "2e4eebfe34321784ed660edd2679df6bac7dc1d3c0ac5c5301729ba21de9ef38f127f680e94d4d4853931b95997d4933a7f16d7c84c6917e4a136c7528938c71" },
                { "az", "fdb04beafec39af88289346cf3c82146a4c5c187f5e3e10162ed7d91162e4fa883fc60833ed3a4609aa57d04217c1f7d182f7379f54e995eed5b07651d65bbd7" },
                { "be", "a90367c794d70924645a3ecd564a3e9280709ec4418822bfde15824b3a4499f199ad017b551af8b31026a6af44ecde858d5446c58c1f4c595a872bb47adddcb6" },
                { "bg", "8d5dba423a23035dc7eb1e6533c219acd28a5a8b80fb961e9948faaebd7e34c07c6bc25526e45c8aac0185db57d50e0045dfaf8be8a6b1453dde7309b7dc6bf1" },
                { "bn", "bc14e18968aeceda4be1608e31c2a63057c5de3bc8cfff7468a18973fac151ee50e343ddc26c1040b0f6e4878df466abe478e4c909d1890b4eac6e7e8a51d187" },
                { "br", "2f87a0545375c63c143166e3be310cf5babf9d6438ab3e1ab9858847b0a136b221ad45dbd404dfbe8fdd23885d8c2278c9e62d976dd3fe22f9868b143ed79fc0" },
                { "bs", "c305c2b29ad2daad5280aa1080103fb99d1825cec3cea06e69aab1b60c39db1f3e5a138a91a5913df8e29f69301768f54f90c1c1379447ccf3596a75badf6047" },
                { "ca", "52ba0bd2893da1ac4c82a312af6c21dc456fe0af86bc8b484aa08ac56c15855dfb0cff7cfd92c7e7b5833c0538067e09ed493d19fd03fbc8cfd58c3b347ae397" },
                { "cak", "20359b78d2d19ca37e59b480c76526b17e99966f2d90b6e8d61484b0160224b23788171951ca796be46f688061ed0fb2e9e957bf3661340b238e76089d64b882" },
                { "cs", "d35c04964e58131dcf53ec8aa8e443bcd347638d91278d128aa4ea8ea99517aec2fdb10077c54963443f4b2ce9a6fbed28144014ffc258b8b60b3955b2aeb489" },
                { "cy", "df033abb70712a0c9b1958953d40fb2b40bc9270f41e07f58787cdd65c91f4b186b5d34c451f34c4c7a21a35b42b2a7681754398d396c7530379787318bb608b" },
                { "da", "d5f5fba94eb6c4710b1312b4b5a05679b24981e9ad729ed1bf8366dae8a32664feccafd211d56142b888759a6149b88e73cbfdb24820c5269d788bfb2dfbccf2" },
                { "de", "ef25f95090b544c1d1877e195d82dca39a5008ab112443390a2c917875d61382f52716732c4d5eb20d3643a5a6ad54f8877854d7b2e14d4b9b835856bff5ed49" },
                { "dsb", "119bb97ad412bcf9f346a6dc2742460c799f3d926b61c01fe6f12649559a042538a79daf472aebc168f62fe68612a0492eb41da0dd006173debebb6c8698807c" },
                { "el", "abf580ea4b57d26338ab40fa35106175acb82fb70bb191e1235c1c3923ba3c06bab9e0c6b089e98c64775e587665ba22d9c1dbb9429445903129ccfccb2ea2ea" },
                { "en-CA", "ce2b5acae2d1055c0e9614cf25c15bacb1a87d1ed42b057141ffd5b7bc830a37a0e9c29f2564baa4c28cbd884492c1a3570b1c7523e8a54ec7fa6f8813373b42" },
                { "en-GB", "8552777cc1cdbde912204db65b9c8b6f7043d340596b8cc616385c81f88fa47be3c8b10d8c9641840408ce1aa989860c26f165138f560cb037c5050494b8fe62" },
                { "en-US", "d48c3e5659946a7427298aa6aad5644605244f7113f9a57bbf15f11fd60613c7ddba488e2d642cbe41bc87b6454850746bb29f92885de00fcdb3b8fb48c00c27" },
                { "eo", "8f2aa626cd0fb8164847dc783fdc21e4a4f918ade2bae4f6eed46ca33e91d38b975638382da97fb6b816651c95a862b973e8b8629f30c17e0da2a86ef968d6e4" },
                { "es-AR", "799150a6855a3d7dfd47c045e7a21e940b55ec84a41319b8c41b63bba346da1014a398d13454b78692fdd97451b03caeda4a7690b4c6ea8c79f770cb353bb994" },
                { "es-CL", "c954125c9db9eea6f3ffd1da1c386526e185fffafcdc8413f2ce3556c2992b5a113f188c76476029149f892bfde100699d1c841f0a87086e8c8728c9ec82a9e5" },
                { "es-ES", "118b59e519bffae40961c42d8e0398d1c71c3a050b0228087ab7a203bb8e1efa0ee53416b4a4989d4f24caa9d4cd95f894cffe754fe1773214cf917d38d6c01b" },
                { "es-MX", "848ebd0f9c728b1bd3889e7002818a3b27bb539a43b6d2fb1072fc5c11bf275d0459fdab63081d8ec086499528d41ade9ea641feb04701d55f1a00193da105c1" },
                { "et", "9e865a550379edc1c214e462c2a1b632893b59c608d19ccab533dd9a5b32be4f0e14d55066c54e77c9dc727897ae8a4659f86e5c0b107edd2dce4da132281b3d" },
                { "eu", "de38a46966cf9684b338dd5b6d7130d14f76e9289c27b15fd7a7fe50d173f5ad0b2f320cc24986d5cea534a97b0ea6a5e3fae17d48d1b322414f9e8521664642" },
                { "fa", "ce082283dda3a069623488efc29178b068d54b179d3c9928c859f6db32d44567a6d1dd6dfeadc664a6b336254d9c6f0986080461bf0796852bb956d35f33d250" },
                { "ff", "1cb9e56cec1ac8e95b37f3a73528c50cb277f2cb4a4b2eba95d35eac52a586a76f7ac38dae6c936ea73e2bc12a189b54278a8bfcb0f7ed7b1e0075bb2d4f36f5" },
                { "fi", "bb411ea436c2df33d49fcffba9c9c09d934c856cb35d4722e6da8bfb5cd0316478db95e4731286c0b7370f13eae93114116afcaffd9f6ea208d760ac20d279bd" },
                { "fr", "ed2e78906b06ef7364abf2e4f3467c14214b92464e87d76ceb8ca018910191222c9389f3873b28bd95545c97e19df6aa9bc794f82a7d2b47596772abbe754898" },
                { "fur", "c6a14f53577e7bce37cfeec0df07f42057721ad671d98753064d7ed6479e2b0b94822a37de635c6091ae3a51dc9bd8efd75d0964f94ee9cbb7c67692d4a4f2aa" },
                { "fy-NL", "2cbd311eb5d91bb441cf4e734ea707061737e47e5ba7ba0c9b4d276fdce45866cd3e53375499078950ef311af46023721e0b4b946474a2fbd56c0f5d12b8e49a" },
                { "ga-IE", "6e197f0936842d5e2e5b2696224ee78222c9abaad96ad563a9f8cae10d9dc0c5cefe3887d48bc5199a94e084228e8fdf235b6dec419b44af73ba7f04de2b270e" },
                { "gd", "0eda5f30bc84d1b6d0a956038c469eaa7f47872d546cbf1f5a1458806134f43006633731cf952edfab811319cc164291a8a44ba721648db88776bb19ec22bb07" },
                { "gl", "65bad32055dd2adcd9c1c12df2a211116eabd0e8602b5a1837307cc36c747bbed51a5608ad314102061c6078e8e352affceb4ff2af3b12c61d71570e490d4f93" },
                { "gn", "67e12b195c953eca3f19267ced3d84eae9c4e9c6f37bc95719f56e154fe0184ee6f095084deb5b261bff22b44ad9ce8340517b4e5f1bc26df0b105b695818327" },
                { "gu-IN", "fd4528412eb13ed592eec6d64aa9c80f9dd965f5ccc38904c07f085b0b4b418890c3529d2b3e276485eb4b2d502d6361a9791dbeb22140ff0611766a26cf47b8" },
                { "he", "2409ce3d3fa0fbec4dbda29bda73dc932d65dabedb7aab9cf377fcb13608a4c8ed8e8b40ad02e98a88a26c9506cc1172d2203b6434551f276e7266e4fe66a690" },
                { "hi-IN", "f7fcd03934afb8c997bb36f55c214a5f59935592c50f73ba7b52b60b9bd1384d627d238c6d1767bfb0278d99ab83dec2754609fd148e130ce7722cba692a4db3" },
                { "hr", "a699a8f1888c2b771a1dc3d194d76cfc552cdec6ff4582b966d3fa6f0ad3b1e99bcd04e6a9b972dbf7adb41f8fd66610aa0588bafe4efebb7324185bbae0e2cb" },
                { "hsb", "b2eb376546a6bace6ac5b5c7a58fd0cbde7e1ae01a4f29afc4b4e39a77d954918cbdc567c67253179bf17d1e21f1e2fd9dbe51c7ec8891be7cd256e57dd13d95" },
                { "hu", "9b73ef7cb2310c99893e40437d03e5fb1527adebd13b1addb9b269aa15a3dafad25bac768a31598e111e42116ed56ddc73d0b53f98745b1b43007fb1dab66feb" },
                { "hy-AM", "a1f8761686c8084ec940e56baa61d7917ae1b995ef24cdbceebbaaf60f01e77c50d1d8f3238027ae40cf7dd7e8fa9b8b1f68c7c0d5cb2da363e1491fdce78cf0" },
                { "ia", "545a914809c7f22c91204a15dc969ad29fdf710bf45ef182a151887077b7b5c61cebe729fe54a198627bc0538788f9fceeaea145d6071008b580ae31ab227766" },
                { "id", "d242baa3c70a48ad19816d73ea0278b4981875fbdccf3749163110461151f268a2401212c408eec99e97e29e9bfd657f861ce9baafdb7ad0d9b4c2f8b5f23f26" },
                { "is", "d0f751d074602f159cda61fb5947712b324494f2c6507440be368f5ba0f4d5d7e654ca9897e415fca578f08317172aff6ba694f7b0b860d440199120b4ca1a62" },
                { "it", "9ee731c7635ea4610f73ada49c065c3c0d5fad0e5b0215294e5e2935c94fcb8fcde91feebb3160cdb59bdce4bd1b8482c14d135eef814aa59dc3370b3dca072b" },
                { "ja", "c229724968c3609043a477a1d39bf80fbf3a25fcdf26e83e7523ebbda6ccff969369426c2ff5cfaac0ab8cacec452ec40d291742bbb883ffc7e3c3c9703d116d" },
                { "ka", "5563f21752c4e0dc579318be1d15026810f643aff7fedfd46271234163fc624f516292556bd272d6a974c733ea232a60066f7b7f0e8d00aaf14b37bc58024119" },
                { "kab", "90ba5dc89e85ad9ba6045ec001b521b2f8136c8fb803cdeb49a1265babcac6bf05384769ba478356043f0a8ff455d0e14f10a4ea04090f4da6d6f176721d64de" },
                { "kk", "e4b96baa528ddc1ff364028f45ee78be48b12eb09a5668309d0049e2804aa08f02a1cc8e59911f4f22d43fa46848a4e45ca54e1479d132b32279a0cb8f1947ef" },
                { "km", "5b04f507d2ae7a91ec0807dc895d8d67c5c460f166d9b255ad0d13087b53e7720060a8feecee91a7e3de5bd44a20805810d0e05865309541b14cec8c3c5181c9" },
                { "kn", "c3f4cd6a8a202bf34e410232a4a9a43936847c1106f8c15265a41ab3fb8df3fd51ed307936389151a87854d4d1a376505c7483f687db0677f758e948117049bc" },
                { "ko", "0e275dae99f3dea3cdc839c46498708a6de0ae938180fe5346798f1033bd0d043748bffa958edf706d22360d800b0985ffeb6abc070251790b520950a3289aa6" },
                { "lij", "320d398938a12f667d57fa632c1bf7b7b6ddc392f09648232bc0ea1ce8a76ae1a9c95a956823e2cf53f99a8875dcc4754c530fae7b621642d84053f466949113" },
                { "lt", "301200ba7ac3643736c34145920abc46bfb47962f2f02ccbbdedd99c79647661ed198908494e5db885cc50263c172c100d0acaa4e46ac51c3f1e1abdba318603" },
                { "lv", "a2124cb212407247cb02f0858e3870caae217c2897399e4781c56ab1bd3608609a82e82b0956c0f72db5a1e2e0cd9dc7665e549a9ef8e91dc683b5f4fef944f5" },
                { "mk", "2fd6bf3be578663d3b39fea19df430ff76b0fdda972d5c6f84c8144283722df34f7f31fc395b7ac9f210a6c767fb349e450d9908ac0ee38e8a545594a822e63b" },
                { "mr", "2c57bb3319d818c0fb8f5e043caba036122500141c197bc40e6b0c59166c24e449f8388d2655cd15f58632f13f23ea53ed23b71302d561727cd47c2551b370cc" },
                { "ms", "87e92571518dfe323eb2ace539c4d7a94ec582e56d6282ff3ecbc6e4eed247bcd53f256cf06b4aad553bec71ae89a43e7082ae43e50adad732f3c16e13ffa01c" },
                { "my", "c3cd82abf722c2d82707998c2f38052277e2b10f5727c8700515886112a8e67a80c7dc215a7a426061be7d0066e5754b67232987ec144304476e5461575446f1" },
                { "nb-NO", "eb261f2bf6f13432ae8ba0ee7e7e948ebe84107018a381ab07b991128ee00baaa5cf483e2b2aae933fe9a4ff7b67ec5725b1d04c4c2eed3f643c8393c3438867" },
                { "ne-NP", "70b76cb5fff739bc4e2ef0fd15941e5dda6434a04cf570da5e7e5528f07cf676a9a057dc186490f84f3b33af85ac8e0dd5fc6064111bb5607b2f7298ab7866ac" },
                { "nl", "d412ae807a8b24f5c701d9e379313e57a58833053de8e28cbe713286bafa47aa0582ae2f35a1ba7620588d31272077f9549b2f17c240cfb201873c3f6a7566b3" },
                { "nn-NO", "c5d9f2840d4b74b40835f1dfd0ccecce65380ed54ab3d86f1f9d6be5d3753829b97a9c1c634b0022ab5f50c5d277b05b08db4193c01c894eb938ae37f4a5f308" },
                { "oc", "2ab5c9f02f8f033e670817ef41b133a6deb4d23f7a109fb13acc883e28b3985ff30658af8111ed8e3410bdccccdbae56857b4f6b837b97f8a1a6be8b181a72f6" },
                { "pa-IN", "49ea561d9702aa1b74bd1460c87c250ac9873ae90b1fa3771c18774de36bfa597ba54ce56158b540c2690f47b1d97056764bcd26605e0832df86da2edd56b251" },
                { "pl", "3f4614beab01579c6767869cd3abbb91de539254e99d314393e7fcb91514a8967e40312ffa785890f996066878a56b22209e145f9de36f5b95a40f5495ddbcbf" },
                { "pt-BR", "b1c006ebe9732970f3e9de694738f6805700dbed3795f660b7589c031c0455e1955c456c5345673586eaac58c132a5f8df0e2cccf16a1ff4789e6fc63d51464f" },
                { "pt-PT", "f447ec75edec17e7052793a303c1ced6cb5a3400c2442b0f0dccb5a09ec4c805b72e0b578a201ab70063ec41de6462fad9bc40fe273c1c2ce0f6f15adca80852" },
                { "rm", "2cb7fa630911b3da7517dba93b3ae823886baa593a905a9b526c16dfbd8a52a836998bc90b83e46423b51b49db122d2759624b461accb6def0e83ad9eea4f2b7" },
                { "ro", "e48dda5a20c9bc6f721ac24b910892d61d2eba2fc10acda983659479547e059b3964b51f8c7340fc116ccf3b76c598258fb317f52e3b40fcc992ec6cdbe574b4" },
                { "ru", "ea909d38f8ec7941927409611799e818344ff5776b71c3d46278fcfd98f6d6c1c80f24c1c9a29e7e1e0be4d3131c1749f7f9a2f0d5318cccb552850bd2a16f5e" },
                { "sat", "140ca4b0c1b9d5189b57fb448f9c58065c54cb57a2ce4b38241e4cb79f1e2c731584290da03650afaa0fbf8e9906e8387114477df45db92df5f83551f50bc85f" },
                { "sc", "0b56197d1d6b773da34b5c7a8a2cb53556b315759438d787af778bd36e560b4d0710f91619d0744e932a44a7d6098024af401ad1860881e06d8ee9e790b24e69" },
                { "sco", "84643a9c7a3975b1da9ed5577cf48465dca6e7f93867f7f94703ae61d5a54decce9d4c8bd89f50eecd0a08d57f96e2446298f2200c7e5ff8cab4f937a863fed0" },
                { "si", "a3d333783c54e9cad525155e9087ab9f912fa99f49fa2f01ed9e48949198d71e7195a7c9d2af0f5e4127c650179815defcec36df012205d248c3fc379072fa75" },
                { "sk", "d5ce01b36435a0151ea8c95b7dc6fa431b4746e05ff4a5b149e8c4890857b8b399a731df819c3e1edb5c86391d3494f32d028c577af2353e32739218ac9d011d" },
                { "skr", "d06a10eced6c45f4cd5b6f263946ee04e6966d7d95901c7faab746c88b952e267f15dee1e25b1c9e28e8a08a9620aceb7369d7c174fe880b497099ae7a98b249" },
                { "sl", "84f93319bb8770da3803299c7940effd73fcb1be296686efbf35f0b42a0f0c86435e0c41cd8125f4534be887a340e95786376221591a2548384aa31bc37cd948" },
                { "son", "e8f7045470bc14e0093d79cd190d28ffece3471353247077132919bfbfd1f05eb345683fe9b745362ff460b6ca78cc748ac1993b0ad81bfa654d58dc4bc54c0f" },
                { "sq", "c057fef18772ebb7c8fcdecea57afc8c7aeb2e8204616506150e74ac1db727f68954cb391f47aea6702f64262a2f258e0ae796163d34a52ddfcec768cc2f0ab4" },
                { "sr", "8c44a474c06debd0d370c9746e8da0b796a21f847c3cf1f5420683ffe23b1dc9452162a05387aee049b1cb139b5dd765ae5d5987698938118ea9ae0171bb940c" },
                { "sv-SE", "99a260582486b898fe36810cf44b466b1a6393fc36d797c7fef5aaa028a0d3b1166df6f740b964f6d63cee81b8954acf96c8757d36cf90b2660494b46760f7d4" },
                { "szl", "0e4327b037f94646586cdaebc909c7d434be7de2fdf850182d9600d1f384a936e558d552b46e7cc2d3e4bf1ed4025516878d7e8af23d0ef2d2513d86ca995ac7" },
                { "ta", "c91ee73e803ada0307d65fd9f2798caa7387e2338b13ab94b4ebef46c328aa1f000f9834af28c43f601d62552599f0c9c0ee14c537a0e72e9595453e7ef0a40c" },
                { "te", "25e97996c31feeef2f7a07528eb1f9f21d68fea399617009b20d1ac131915e9011a2acb551594dffe10f8caf32c294a625230bf649a3604327e1ffb125f7a7ae" },
                { "tg", "d96cab8404b1198a4b0a4efa4a34f41c2e9b2ba4ed66b1fafb337ed588259e012e49db223bc68d74983bf60be68d654a287b43f0c4c4ff622f5d094bb24deebc" },
                { "th", "c6c460645fa6be2df9eda60fa5229e99d2e04fb0690496f652ab3506f6f7f659e38f2ca5a8ac5061be6ab6592eca30e7f6c1e7ff5a8b8432aa5cecaa92ecfc3c" },
                { "tl", "6fd21d33bc278c0ca1fb93d72f8518c17d0d2549ffb309af6d8b6a595aedc33159c21730ae48ee1eacf66b6c9066b26ceccac1f740482c0bc62b7a68d033ad2a" },
                { "tr", "44dc0113c247f019e95cf523e7c7dfddee4df37f40353bc857d0d24583e88812f81593fea0cbafaaa4f5cb6faf514f38c47088a63bbffe1d9bca878797f1f565" },
                { "trs", "f2faa590c9716a4bf6a922cc87746583870f015053529097ec3eb439c5ea2c411f42ab7bddfc2fc2a1025c6a3df2e3ea9d3a1dba38c455e138580dff777b971a" },
                { "uk", "272a5ccf9733d0d6ade52c4d93ab117801d0b536b1fecfd67c42cfd9f5622f365ed51f7f27b12c64b4bef3bb74de7d114ae457511fef1d87c5152ab2357c0bb4" },
                { "ur", "97564d0599deb075af98434ff0db2a255cb05a7dc797a2a4dff913b2ec94f28050013a3a8a7f21e7822844d87f7864fc84374db8dd87bcf62db153157bdd69a4" },
                { "uz", "bc259be9d4f3994022dab9c76eb693d2c9cfecd4fa50198a3381229fb39e1ea0b617593c65ff410f1f3c9c793e039c5ceca864baec409d048b45edaa815988af" },
                { "vi", "2848fca384452aa119481eec249e2b0d8e8b81756adbfe7335cf22f0bb80e9776a9d00935804810eec791e3f6b2f32ea9115112a92ed8e29e8c90551347f344a" },
                { "xh", "7c27d66bf9e873107422a78693291dcc6c2cf845cf7c9df30dd1567b6d923690018307eefb006c37e6366a82545b49a7d3ad468e1ca257c07b4efc5d62f48848" },
                { "zh-CN", "1f8d058086bdbf849ecd7b18f9793c1437f4dc3623745531a8b4eebd21bebe1d7147ab67146326df5af7665229646a3740f02aed2ab89af98f82901d1fa793ff" },
                { "zh-TW", "6582adb526dba0f7061e5cfa4b39440ce3f779fba93763e4a88b63335cc4cb194b328d83a51138288ed6248f30ef809b5be509a246723be5e61ef4b3186c9a00" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/135.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d6acb3f6bb2efe4fc30b4b5784ecb631abdb04026426818a076849620745b194f9bb0b1bd048b9b24add147d4b00357cafc0792e126a4ec8793179d537956dda" },
                { "af", "b4e6a78cf7d2edfaab9123b2c2aa8a1093593d07e690b1ae851d6ab852e7a2eef1a61cd60f84e2dfe0bb814021f3b94e82ec582f11d9f0f708bcd49bb23393d7" },
                { "an", "a1d851f5b290b824cf41853b6fd7022a47a1e3ea789720c17eee1bc8e7cb8de9b6e63f2e02d5efc18b74ecc348d33c24b7b332477e534ae4e2988246e3a1cb88" },
                { "ar", "bcac551c6ff83b1d97351dd1a3019f4c10d83847c6491baa53eb8b7dfd21cc74b9393381c2fcdde24b61f03ca22f1f1173da6898538dbc2513d3abab2b1b2d1e" },
                { "ast", "74543fd794707a6c0e8ebef343e7a49162a2b6fa5f73a40a13c58c50e65bc5f07005b05c69281b6fca8899c70bcc8b0e6b951ec2e9ecfac129844a9013eb6dbb" },
                { "az", "b20afb6d172f7326f219f910c0aa53eaa2165ac4d7dc1502a4e247a6be2d75ec14c1709b940f4b311bd614dd3c1740fce04182ad040b368bf9ec2901886060be" },
                { "be", "cb56ddcc3b82810e8c36b3acf6f7b59dbb5e649a7df52283105af08735f56d1eb9b997d2a4c2dee9d81536c74f02e650756c66f46b54fe4e05219f2a0869344a" },
                { "bg", "c1e28648cd7e0011031d97779d0b13eb18afa01a49cef8b283348a0cc173d52d4acea2aaae4adf59343834e65f7ef6ba0987b167945e9de764da5e0e5d96fa31" },
                { "bn", "68025b0aec9904e8f54226d32cfc16421000245da6d9b7548a984bd58ff2c14bd3ab888bc82d094fb2642f0d7141b9d8f776ba2fc77325a6ea886f3aa7a5b462" },
                { "br", "659ba8b30712c8c259e31d3ad586de1dd7e52652a50facca34236001ab81ab44dfe1b55fbf40fa1045a08ffe927ed859853aa40d3fbef75d489738057e0bba18" },
                { "bs", "cc459b7f5f09d32218ebd4874f64cda8001718f77d60967db4c7bdaf6c7f4c8b1555d2e3a448610b3be4a34246a9ab028f7f5ceec16fa8c05a3c60c2148290e2" },
                { "ca", "fa05b2f0d218676cdbe08976c74225f692eaa73295bb7d3571a4c8b5f0713b13e923846338e52980b56ea272052fdd49358ace22dc5687443cb6d7cb6b0fe03d" },
                { "cak", "bcebbbc409775dfebf3986e21666620cb03e653ff0d22f6983171208cbfdb67143c5026a610c71067e86fb254e28bbb7dd5cd4222bff79ba2bb258d79799de46" },
                { "cs", "76f2aa0b33e7d7efcd71cf5282be605a7d6b725f51a5c78e131bc8def47e1346dff0fa14d8100f8960620fb6d0c3ffe4edebd664ded29e9188b38d3192ec4c20" },
                { "cy", "b2c7e4dcf2dccf690a03e215f39f984f8ce4f3a3a772e0fe556f4f75d63bfa808c4419a026d42f4693fe76e6ce6d03cd8e62d73aab1adbda59ddaae311df22dc" },
                { "da", "7ce5b65781e2d7bf1b677d6fadf14a9c3e875f7bdc92c79feab2442c8ef262e0b0d3dd6fdd1791d1dc6956c6df261e226a2a9dcb8a6e3f5c387cd5a1c8dbad79" },
                { "de", "e8667ca3fdf6faec9454ee0dd8135c9715bbbe897f6773a8a6da0ac304c55ae826df7ef3c5b57aa936476df3410ef869feaba2c62ba72509f5559dda6197e6c2" },
                { "dsb", "d9e2fda337ce806484e835c57a15e501a28d1b8b45d270ffe73002dcbed37c1b5d06e1a4c27ec98f1326ed95fa4c4a4cdf282c50291b1e2e986e0c094504adec" },
                { "el", "5034aa425437d25576d9e7da5017791bdc70ea174125c16d6e1be92f299b2f00bb3d2610df1b655060372511d377b086f152612d7f9bf93dec7185fc38ef5859" },
                { "en-CA", "1156277d006a8f6d2ba6410ca77cd321a7c34551e53ef674e77aee986c2ba00511886e49d35fb0649ec73e10452e6e19d91aa8ced7eb6d96cedbed9b17d761d4" },
                { "en-GB", "d98a42789a956f7c8aa51a966fe1a1f36ef4dca63e85a5442ee50ce4132198e6043748a0b310571891151b759586247715d149312965f20f77cabf9df4453b02" },
                { "en-US", "d836d7abee8b7adadabd5972212959573d1501496230ae8aa8d44d6414ce3f9017e9f0695278fedfa9a8d909adddbe543489b2e3c262a69969fd33900af76a81" },
                { "eo", "a73b1a6bd0a2980718cd517b454b07ab868e3db0a90c0f4b17976512e150a98e3a6679f5a3e0d9ccf3d2ea2f497fad97ad25afc128853d14126587b619d2cd87" },
                { "es-AR", "44cd2f92c7be7f80f246c941a74420705b1b3af597d3fb1e6e94b952d3385ae946ff1c6cd21b093b1fbcf9e9dc03a876ab75528d01860a570450800fdfdcf031" },
                { "es-CL", "ea57262e624a8370bc3be243599d909134671128964f15faf9b2f1ea8e34bf21c8142ee48589a769ef8622644bb415d6f74f17d764b35a7eb9f8026765902118" },
                { "es-ES", "89a880c746526176428add9fceee344f4e6e93b4f5ff281fecfe3d594aeffc10e785baeda1cd4466ae69380efdff14b9a2d62ca2bffcfe08003b619be4eae12d" },
                { "es-MX", "c8fd0475b44165059a55e7c0bd3d2b2bc52669dd427982c2743646af12dc369852d269d9342389aee762b7ff91ee359a930c50a95b40cbe7b21ad44b364186fe" },
                { "et", "477c105bae339cb7ca733bbaffd951b9041477032ef90dd13ccc5c2c94843b797f310b75950f61b1703cc62e7c4c7f10048f9f4df888ee0b754d26f5d4f53532" },
                { "eu", "ddcf11ca4d14059b763c39fe7b8a04d3cd12aba90fd0763efa2d74bfd0f11c13fb56d26ef215117cfaeb4db1363728a3bee361d4575a95bd027f0b7e175e8d42" },
                { "fa", "3f08f52ef44825d5c83f037932906a64cd526adab714423130114ed2afa796597025f365f5965b805a0dab0300b34cf9bdabde00392f69513c2363e566698366" },
                { "ff", "e9e6bbb60fad6aa47800f965201a7c7cd13ca5592de1acb340d8b7f0e1dc35e34821f8a15114ead4b01ea12dd52a60ddc77cc4a65a17938979863d58c5134659" },
                { "fi", "3262a47ff21b0030ceca4399ad8981e00c903555e20c40468e5926e0f5601e3125b746d5ae6e513a72656763d00c08871099a1d8c467bb0692b01c3deb155d02" },
                { "fr", "d6a29563c5b64fe54e1195a1ee2ea71fdc9d629ec105e28424050a663715f56a72d3414bab7b9cfc982892faccacbf56cea55de8bebfcf930c7b3aeaa526af8b" },
                { "fur", "00301378b20a291485a606f8d35a4c3b9627b8d5238fcff112ba5568810b01e5f183169ffffd30b5c4f9af4e295f6eeda64f743c5a23c311fdeff85540ac0221" },
                { "fy-NL", "7b9b868b4ac9d109e06c0b24313c1325820011966624fa997646f5e5def08ca7c99d52bba462018884d9f216ea63eab769d578fafec3002d5d41f39d581112ac" },
                { "ga-IE", "1016bb7492cb1dc7af8df1e55500acb27d805e278b43afd6d15e418453822997fef21d355bc82af79f8df1ba9db8c21a5fd2858488f3760d66c0a9076bce128c" },
                { "gd", "9375bb5ffc252243a1f7ff85ec6cebf932584aeec2e550e4c6d336af32d0174bb110a70cb16e2f8d6b18ccaec431e505cfd59fb02da9a8cd5f10865c10d948a8" },
                { "gl", "9a5085a446e2d0cc98c1bec8817fed70157c9a0ae6ed37e5f5e407853c01ccc30c79a8b4215ae2e9f78c6f4de2294a9a0426625c7043c207b3c728429fa4b207" },
                { "gn", "8b51fa7cce6746fafb3d419f7c563e45acca74b8529aba71f03d4d36687c3cfabcb933f16fa100d830d269570120894427e334791e31c18c337f53f84c25ed34" },
                { "gu-IN", "d74c8fa3d64e872e0196292a36fc1797a9e6c3d6c3e8df2caae27d0bb07cb5a08effd2e62f0fcb96f8ca892270d5dafa370abcc8e7740f02cd75b7de03cb728d" },
                { "he", "7d1f60bdbc0a68530ff70f84595e9de5011cc8fbfb36918c337de7bf7d37cb8c19c8e91813dba051bd8af1398aea5f9941f64b12f6a329ae454f559f90e4a574" },
                { "hi-IN", "f64df4d22567af5197a4b8fbf2475e2fe20b8a9fa50af6ea8d0a9d1bf39c48d965e9b181b3fe06914e7eb1283fece98835f2070c6ec0be1abce87b475707fd97" },
                { "hr", "1166545a7e7f5797c520912d6ac2f768d38154f68574d2b07d87d86757e78d616026ce17d53fc0cdcdca7030a4b463114bc4ecf40a582f087ae85e4db5ef26f0" },
                { "hsb", "5dfad1a89a910820c8e40f77520fa0473fcd5518776c20a0dabc27f4ca323c9208224ed189feac21e121358f46e339d102af3b5e6337d83f62b2cc4156919e56" },
                { "hu", "375eed5326c720848cb418c9e8373eeea1d2da7a22daabe06e6ac4e73b33f4ae07a4638b5824ee836d7369af35b32dc32fa0573f10699e645a8ead92502c3889" },
                { "hy-AM", "2f927ee838911171c70793d91e7f73e962a9da322f774a908fed61c2b2fb2b4a2a8d43f48c31b725e0315f14b2107724cde0b34049879366bef4895db4729a75" },
                { "ia", "3323c2a7d373ccb65bb1abb6334636d8ad8155795a0c60f96235d37e61ff424f6d83b1f5e4113d0cd24c656a10a0b419569929a251e148eb0789d5db2d3131d5" },
                { "id", "91ce018b4db591c9a4eac8924df2c95f8f9bc823e71cd56eb2ec40176609425aa7aa596bdfcb93ad2e6f970f2f921aa563306e798f4158b19904f6dceeae461e" },
                { "is", "be4fc1793cea0682222d9632771ff3776982c72717f286c49acb5976593092363a1782ee1d8d5561a40597b51c0b1b73be7f1c0c04165bce0fbf888c7f674028" },
                { "it", "50b7a34d7da3abe6f7c6c5f453275dd77be7200de8a50bf537cca7a02d9b1ed1cd2966d46b08d92b8453125a9c73d3cdda65bc93582fb9092ff3c66fb9db7e59" },
                { "ja", "686173f88dfdcf69879a33023ac0da901efe971c2ddb7de610c5ccde93a63e651a1d2eb5f09bef0bddded15a8dd355ca92816b2f342f2d71de51a67a1e613f03" },
                { "ka", "e8f834a64b751bd50ed0052b01407d9b1f64683c3fdbe7abfe802f31ce3a9f7d1c4df80998874f62d6e5514d1201c40a8e9452306b333b1a2468d64df9664a51" },
                { "kab", "8389fe75fae63889d6a12d2631cc38a298bdff8141d309db9439f1a245a920109bd586730ca2c07f8702e99d8eede54dea6e305fd83ae2973203574c8a471e88" },
                { "kk", "534aec50f61f1e3bfba42f46e253e0d8c51bc54de6f7308646010f42de916a1e970738b734cf291c014f46ca1585933a97dfcf4c2ba00494c36e23daed9257b4" },
                { "km", "8ae30373666e8f177d82ab51c880a07196fc9280d5751a39a86b5ea6c09bde9bcb9262682151d7d1231f077d36d6df4c2a10b819b63e1dd9ab98798aa7d5d302" },
                { "kn", "c5f54eef5e696cad1eb9e40a45aeb520d7238e2726a8caf560cfe376bab7b70233bf44935f7c884a9a1409ce89ae4d7ed3c4aac23c553f077c53505237051778" },
                { "ko", "3f86e65876685f0e6382f95f767645c58ddb6212126ae4b934702b35f10e5dfb4fee850d7cee4d7573e6d50179803f66c60fda06a9210609e99096e0aeb3832d" },
                { "lij", "00eb8ac46fc35f53277ee225f4022f8bbc06b0fdea57fbd6cf2f9f441ec8209b874d3ff6ba1c3f4c453c912ad331ac4720cf457e6427e85f503d330135c7c396" },
                { "lt", "90d567d9193108bf8274a0fe161a67dea82b622ff7c19baae50d6c7d699c0f2db7aa1afb69047fb266d8c895a9ace99faa74b24c92ca067482969af209392e27" },
                { "lv", "eb935f1106e64242485b5de96b66651ad614a020f8094ddd6cc582a08f146f663be5dcf5539877cc50e8bc75507df444905caebd48036d557eeb88e29a8786b7" },
                { "mk", "f86e5391c522a069f350e5256c1445fbeb1ae145c424d0556a86d5f973c0d1de6255736532e5efb90e2d92d9fa8c07e733eb7977495f0cd52401cd144b75122d" },
                { "mr", "707466f1bdd8562cbe68455ee56c0c5fcd3d416c65edc4d699ad4df2e5494a53d598de71ce88787a9ac1e020a774e9ccd1c32ca1667ab7e57e9f1b8e62e38490" },
                { "ms", "63b3be1174ebe9a40c93fd01fc1caff6cff0bc5d25e4e9de69a1f143f3445e24ecef313fbc16d22490a07e6d403cfdd0e079bc3c64ebd42935f9a746ecf3adac" },
                { "my", "96a458a9ba15ca88712cfdef4b1f0985a634942d6de1c2c53c725502ae2752d9eb60fd669b176321babb67b7e5ed5af8e20392c086c7d360cd99776e4f1f3161" },
                { "nb-NO", "9faca2e9fc31aec3dedda1eab8dce2ba4c62535288141d6692ff5c147096d90a681e53f7767acbd1604f13e9c90ac8b5ddb2c4fe2f6bd48833b1b8b3fcffdbe5" },
                { "ne-NP", "aa7ea79b8e69f71a4493feeac53f43f500a19bd1b2059527dde86b4e142bb9b465019e34c26b73b6d64c4002869996c8e7765bce695bcdfa2094a4565b4d0dcc" },
                { "nl", "66d730852f241c723b5fecf510d8dec37760a89cebe57af57d90d4784180d526d229d3cb36ebb57f360bd69e2b5567ba2b4d4ec4d0932031a5f483aa0de9c462" },
                { "nn-NO", "6964851b05bbe3ac871aa3f1403bc73096e3ecde459118335352419097f2973101a0daf80233a123013006272b5315c9caf7c0b003155cc937709da6e55b7e4b" },
                { "oc", "84cb832e86f801c119b46819f4245bac7e43a4b88fe09927171ef07a4962104ff54d97b213380ebc934c4cbb717ab771d012800a5c6e221a2a04f723d533f7c1" },
                { "pa-IN", "4bf7b9e4311750e2dd52cecc5cf03821d9815a6ad645702d1eb978e4bfe882fb7a37f61c2c2b89d6bcc2701c8d080e8eb52cf8f64bd0ec0c88bfd15b63ff93c5" },
                { "pl", "9e86938be863b59508f8051b0ee2f0f8dfc68f94b60e815e47c9cc2de872751203cc5ea40af0cbb38944e4c72a9b5fc7c3109ce66ad0d784d1e18ad887f513da" },
                { "pt-BR", "c2685e29db49402ebfcda933eb416b14c369ae618c1e048fc6d8d58cbe09883bbfd9a8824a58e147b977efb0cce605d6c8846609780a4da5d2533b79ed3c82fd" },
                { "pt-PT", "f24e54ecb39c740466a252cf7504f6cfc142df917e2c1b61861235decf5f77431f239890fe7b96d36013dcdd29a78171001de8e58499a9dacffd84f18e6c9d61" },
                { "rm", "3135e783b5840596f932e9ef0b2021b8941120668b7041b6a6f4b67a4b3baccf1cc580080a34afd7cdba692be5b1bd08779eae29c583b35b98bf1e40eefa44ca" },
                { "ro", "79b8beea860489db328574769c33e2b9664a769236ac74e28cf4f82c79ce4dd7731f60bf2d4b75218f276db77ca7e5f071f7f9c0945662cc576be2f2290dc697" },
                { "ru", "1a031dd35c8dd2ca0a74f7b9aa5f4437f6f7de6aab57d35a049b31f18e96efdc9609134b59c8ca9bc1e5e6758d398cf261b2d1884a100405376f6edadd0f0609" },
                { "sat", "f0728f2647d88099c3ea3afb04a608e385b82b31f5c926fa3643ec478193ff2ef864354930da570d5e9724dddf6c45ab250f380ad60eacc075161d0f55b05bfc" },
                { "sc", "2d5e83f69619d2360ba4d96da651a2d34c7e3796ff22277365a5944e0667e13c93e79f57ccb303969c1a5b881da1f7866b2a11024fab6e9200b4efa46dd924bd" },
                { "sco", "bcbcdb76facdc19132980bdefc7490b82cc403f87fd7bd38446e42cd822e4d040c477057ab4634dec426c1352233616647ee1eb5f5733f0b63a974f7418e258c" },
                { "si", "2c14c8711cc6f3536f6f54439546772a984b3a691b129c81ffc350a9b284b34cacf67d2842a9a4478f50dbc4bce15a816d6944fbc722109ff35faeb500d20362" },
                { "sk", "a4cbea11f81077f403583bc7bc8876c701141d8860d5dd61b27d19195752d785848f907a9094b10a6160bb38b6c6bfefadbbb50d13a7d68992402275e1c82d42" },
                { "skr", "7185233f49f17384eef15ac0df2d4934ede61ab72237f54cc261fbb92cb74d9816cd17ca7a19dd32e5b3a965376b767452d90be5a320ad0d7f56caa9d008f7bf" },
                { "sl", "8f6f35d1e64a8b631a013aad051e515e039707f4174885ad2240a4920685a0225c34b91fe741980bbf7ffca3ac5167dc5ac868963c1c36dcc6a542db501887c2" },
                { "son", "6c5de2111f0d27b4318115b8da341114a99f830d72e6331cfdbadffe2ca76aa33f35b21de0a758729d16cccb42acaf9676d9ee2d4ee591f5ab6a5ee49016cdc8" },
                { "sq", "56398620a2c9e82c1a72436808c943c24e87f67655158486738a4dae861fc6ccf9ac6c08cda7834cdb1a0b5cb97de080f26121a8920d85bba4e82ac54611d8d2" },
                { "sr", "b20909f329b63731af21740b0486ca734e3eeea72b776667c0737921ce6ebb633df2b9e4135edfa79b6f97984d75cfc88e35f7e619e35ad78b2dc33fc20eaac5" },
                { "sv-SE", "eda73848c2f1934930741e1b77beda180b37734e0747848f1c2d0e0e2e4045dc074cbcbb8226fc67d1418eafe4160ff7681c183833ac773d1dd5b3c7e69b35e2" },
                { "szl", "fa5c1f62036830266e0648a631748796d3f4ee0acee647858bb9fe0f5a38ec97340f0ac559228b889d4f0427618ed441ce53b5184b0a6583020b6d54d8a9a3a3" },
                { "ta", "9b08c83a354305c3daf342c0eca5b32fcf76f80127dc6e545f8ecc00f59f2910943648e5978fae79cf20e227d78731e415c9f820e1242e91aeda588867c7e7fe" },
                { "te", "eb1d33df04f9c09fd07c7a9e5652b957543b7a2616f6d1d9f6c7bc10e4efba3bc161001f61f98aeffb4fbf4773fc0ea674685c79d29733756ade0f1d400a1f01" },
                { "tg", "40bc16812b08f29ee67dd88a0762089aa36ac669865dfff9ba7be7cfcc9a1aab1e3da79f11772d736b53838bd8565d9f7d320ffd8cdc60e57d2b776bf4b2d04c" },
                { "th", "8c12e51b83b607084010620eb45df2514166bec8b1c25608c1618a9f2d62d3a0a51ae4c9f9053f6843f68a3115b66d3a11ee1643ed5f0ba361502e60d3bb0049" },
                { "tl", "ac31e3729191fa271b599f1f5325a1aa0feaf629e8111f2fbb42f84f84bd9e7c31d49cdfbcc54a71ff1f0227f2db6253b6a5b90b7b2114613f08777403c1fe0d" },
                { "tr", "6d993efbba7994619ae0c1dbe12d35793c9bc4e13be926dd9b12b73e586d3b11b55ea61d26e574e8e30e3951380f900be75d34a68518fae14b47c20b0e645af6" },
                { "trs", "dd366698546f938245869704413a02d41da5a23b74119d2f8f7958efaa8f23c0f581107c86aecbe2ac71b592ab6639bc5e6f537484dc9a9e1765326241e33b9c" },
                { "uk", "64b0ed4040637d52bd4ed10e5bdab2c690e3c60dbcd8262953191ed0eb74ccfb99568a7dace249d9039b46c967ea23194936b4e2569b43065b692d1610a74fdb" },
                { "ur", "8ca6f6a837a114f791a2766732ed82a785877c4904605b5a89f8386779fbc4799dbabd4a3242e12566cea4c76f8a40ef7445652400005fde30bbb411f3b2031d" },
                { "uz", "628aaebcf8c7875953724781677db9647d059a772e39bac0da1bcaa9b60bde10c61c5c62040674e3704cdc941d770b634873633bd236a83bf3424c54e2bebdda" },
                { "vi", "d66fd0e5a8cb59e565c8fe1819ea587206e984984c3f7136eb3327a51e9d89a4953c168478ef5be9b1b92bfdf87ae6378894f9d1d9309c8d2e94e04023a13bbe" },
                { "xh", "b9bb9694eedea1952d1f0484d236bcd00bb27580675573f5a02263379aa3609e963ad0798e35761ad2fb48577b0d0e681e8d9cff519c9ad8afab1521c137565e" },
                { "zh-CN", "bc0cfeee8175eec43b9d69ba81329d1e900ec8a541a289d0278a2e67022e325e09b5295b1e256e8aa7e2ccd24d529c55a8f4564a452d359c0f30eede060eb320" },
                { "zh-TW", "952f774563c981a8bdf42c258e27b311d97ae0eb69af4d2ea8747fb853f54fa74d8eac477991e3c9c477521a82f04999dca07fbb2675dfaf2bc126c96e9789a6" }
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
