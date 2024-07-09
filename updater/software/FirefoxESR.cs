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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "4a3f63f4556d9cd93a164a8641b0f4e4a0173c5a3b544368a850556cea4e6d6371fe0c4b7ab363043312c43be874f0eb26bdcd837448e7b85e5d86d8948afd8c" },
                { "af", "e492cf580a72618c6920c4d8408005a0cab115818cc18905d00869a11ed5cc1e385c26634dda3b612113f78f2a25c66cd395f4187a63b16373f9becd0af2946c" },
                { "an", "fd72146138b2de36c7ecda8d2c15bbada62e0663e1b6aa83a005a0525fef0722ebe8ceec6784ef9e9a2a7ff24b816e56142cf271b027c5a0690e03e9d4677410" },
                { "ar", "c21564cca9c38a67d5cd839c5a12cc7c84989a2807ac0a195258c7dce4d0e0931f02a71fdb82d59b593fb3b2500e0a76ef60ab48b724b696ec39606b36a932ae" },
                { "ast", "2cc5487132043e9aa411f488153adf356352b93e52eedb117149b062ef515fb5e424b64dcb506fb49e9081ca717564bf51c3680cfabcbed84e0de1fff27513cb" },
                { "az", "3d246a50881abc99a6f9dd7f46a41b9f5d976f9e0d448842a4173f0d80c0c511c523e71ec5121404ddbd22774163627c78c294a14bc9366cebe7f0689be6a332" },
                { "be", "fd9cc5494b57fe088fe6064c39f489024dc91bafd3a401f962e69500b712444cad6adfe6515c8697ee9dc06c8bbc76df53341af85a46c5a8dfd2822e0cb6f0bc" },
                { "bg", "61c315bdcfad9c7e785c20e9f48ba3827e09c225d3b14c36c4c1cad51bc9a057108d4565d26f475d28fe3a326911b8e24520a80ce4af9a88109835dee6a2fc4c" },
                { "bn", "ed4e08aa0d8bd87efb2db34765a009b9c46cb17f39c0bcf34b734e7b7b59cc706a5d40c5b6f0225739598fd17d37730ac4f37d715219d21585ac563ea0d644c8" },
                { "br", "37cf210291b5994d3b112c6ed1035683ad00ca5fbed8bc796b39225393a900dc9b8fdfabe777ef7ddc1af4fe78b5834f93602d77f3de71afa691d3f5f1488bb2" },
                { "bs", "496ec0b733cab4342b7b56778d2453604fe56994c6937898a9dcd0d98b9863ac31ec3a53d8ba6604bee0c7c883eafcdd30702a1c5960c28fe9a381b6f3a5a4ff" },
                { "ca", "d6204fa364c408580e8d8d0f896fb4bd61a467080ce6cefdeed34698889ec5868f59d19090eaff6c82c147ce167f593f97b68a2d78d7438e1f6aa9b16e416d82" },
                { "cak", "ae297e5df4eaaaa726f2bad335dea8841856084ae64aa72eb3e3c5d0fd9b0c63fad6c5bdc7f36bb91a8e4d38d74688d857e0ad7206fb3143e87afa2993219718" },
                { "cs", "05cce10963cb0365c9cc4753133b32261bcee3bbaf2bc47129b652a0381f50ab190b79816aa6e21cf26ba88557aae5bdae9e1cc439b63ed793d55cf119b43e8e" },
                { "cy", "7d1c47ce772949771eab97751fd210cea3ab2d40aae24e5ccbfa27557f2e82c20d8d972323a0d8e5540e5221d7be05c5faa1ce896d2ce937eb539c491fb56b8f" },
                { "da", "9b3b46a6fe173b2c1ae67c4cfede68225f9d7dcfbd1b676a79cfb7d734bc1ab05b8e84f21a5a5eb401e6cee28535fe11ee3c5ac2ce13e8f86b17fa8803823a21" },
                { "de", "17c9001ad64ae563145e2c2d56fdecc0d784423903ed78dc36c84bbf00774eae97e9f3527233d71f2e62ad310171ee7a2e4ab4931423e6993489b4341d6a52e3" },
                { "dsb", "5336a53998cb6bcc04b5897dcffa437e0737fb4f60c75fe58707b0b1d6d473c4b39d78d5c466b3c1a2b0cf118aad82532523aca6f4e3499e078f4e7b13baee4c" },
                { "el", "d9904b365bf7a5086fcd38fc3a79a06af50dd6db311dd1fe7382386f15085cf8fa26f880d97d04d46ad2a07a79d6f1c2e2d2ab81afbb0dacc6b512b201a723c8" },
                { "en-CA", "ff0559cf5af04b66303d23e0a16aed7d022ed6815f0b2737fd3733a47f0f85b7055800f31afa1a1b3bb489a02f6599a09492f76f34369f678b790c5101e1b738" },
                { "en-GB", "182437e1f9c5a7b54c320a6781324926af4ad0f9b35d113ffc6fcb147353253a195dc5baf22690bd623bdf98329097d0661db19d2af5a5b892fcc2cd0bad8ca0" },
                { "en-US", "85c54a8ceda719e1131857800b7ef72f4427b6fc6e0ad6660657d486b0017c307bd05126a6eb72640b6ccfe47ac0246221566ca594431972b64ab5d692716d4b" },
                { "eo", "1bf61473e20f75592404732c01c4156d25219439b150631d7bb267306d781082b0483d1b767ee818c9c661793d648127262de09f7c2de6f94bd7d0fce8a5b076" },
                { "es-AR", "504e9960936a143bab6030804802bcec816e2d0a3eb0b171f68e329e0e952c2a314df71fe5f558fa75994532b2ca07f4c9f3ddae06405d0349a9bae6916f1379" },
                { "es-CL", "54e20054651c8348bda3f4490fa131bd30c64816ce564f9d44b102a77ad54f668dc00dd1b1443795c2d3fc3d43dc3ec25502330b7871afe6f96f30b1404b5b99" },
                { "es-ES", "fae46663d375691e55568fb3b8caa73238102246d2b658f797de0366b31f591ec0b8c228aa399d66d6c13bcb5bdfb37202417e3ab2322e60945b185e5ba18fd8" },
                { "es-MX", "3063b1727928f332aacfd65070c0c44f9a2459368d4219985cd981bb19339082a38bae86f5ef3c1ed510268817647be39825c7cdf15a92b2be6641a54bea897b" },
                { "et", "63625d657b533629756247f59c70693a161cd092971c27945133ddc37715365b02568b5aa6cbfae6e31147fc046aa155e918531203b4b6e0f9a5f8bb6d06cfdf" },
                { "eu", "61b81eb627c4618ccd5b94bb48565fb904f564b28bdc95aa740e3284cbc1f8d1fc9014b977f4cbed9b4b4390592d4763809628528001fb02ff6b62946618d830" },
                { "fa", "91cc62b7c4e8f62286280b196a2d364aea925bbd9718721285ef9eccc9b7f5998eb9e9e550a30c60b243741cd8ba9d69c5aad07648549465e8b29323e78d0dd6" },
                { "ff", "de09e7dc6c8bfccd2ae9df1b335f383776fdbe8bae56c3f396be6e68b1f73e8339d4b26365d0992c522b2568e8bd31daf26bd47f1e6ca326d4857e1fd6692a30" },
                { "fi", "64e3fec1b24ea9b9189c0a5ef5f541bfee44bc0dbac617ce7453d77e8cf0a0e873f03dd0e6f21e6660fa697729a14dfa9fc9380c7270f0eebe9deaf1f21613b8" },
                { "fr", "fbf778c51347cb28823998b0927b70b104e01feb03e5ca6da78418c2e342a7eec58b8c7b548d02e5bda1de761954a099b103e389703480edd31e696c4f86d4ef" },
                { "fur", "f652be180c7e7bf419db1a0e75e0a8bf8631146710a590c70a3b13a6b84f19604a179c3f1ebc6cb1f69d9b6a44d18a18b97661285f72482bc8c0b2ccfb0c9730" },
                { "fy-NL", "7be137b33f8e36274f5076939f05eee0722d7437b1c22722b97394120e72f07d844cbf9f8f68a7961e45468703fb87f166b834a0c696c24f341e7d61fb3a094a" },
                { "ga-IE", "c3d5803b6e42b5cc182409437b1ec8a4a1a5daa91d8f4462fd4983fc460378b7580194de2319c5afd133bb79b8b5cb661a92142526a6adcc7865584d093a7cbe" },
                { "gd", "e6b2b2d5e0f01e97da8b231ae498c8ed6941384d81fd8aedd659ac151da96d0213b175f2d463b23e1aa7cbaf6429eec37f46649b35e5bf03b8ea833fed35f79c" },
                { "gl", "2e5f4f03c4254d58e6f45b1d36b5fe6dfde9064773f375529f4e222dd3f34f01f834f9cb640ce1f1503153f0163d6b231cc8ad7cba1d9cbfdc1b1c6587f88121" },
                { "gn", "656ba8e89d40cb6af55a0012dc3bd033b7747ae665cdd2d21f47161e7676159cbad83ffcecd7bec5a4945adf88f684934448021ba5e31ca9abce2e205e350153" },
                { "gu-IN", "20c8ca64e328445995e5ff48aaf5b1a6ddbf4345eab2efaa09841e2b5494394a00cbfc096303f58895f6cb8f2bf8e72ce37f74eb72bc3eef0d8cc5141c90ee7d" },
                { "he", "63d89b4485804b08aa5e00493f587428c13a8788f719ddd16455eff6133d4c0d37fc83aa4259f67875ea7ff74d7a36ee15d48732446abef9026fa81d1fe64df9" },
                { "hi-IN", "403566a0b1dd1f293077bb7704ef674ec4a7868a81328895ea1fab800796cf3ba6fee1499e8f51feff559dda8432a12cb97a806b84cbfd67ce6ecc6e52a9a87d" },
                { "hr", "a9d4ec6291bbbe36f22368b275c14c3aff2b3b32f4c4eaa5486355cab9f2459c4a5d3de6bdeb00468c99ada9836381d74cf2e283b49c0eb2534e32973d8bc459" },
                { "hsb", "bbb810b24950be957a0e56f6f6c8942ed1f7cfee0c76d02f01245967ff291889a911a2e927f6a85d3533bd4c4a6abaf4b160b1197c68ec71888d10da40e470ab" },
                { "hu", "a86118c02487df6c0d6abf1d3e9b8573d1b7e7f881e9a4396ca67372ec34aeb718d995ddd262d068d15f311674e26fa5161f1f588d909bfe0319b3bfa896bd0f" },
                { "hy-AM", "7d6b7e6683c30569ee9b29eed390fdacb0461f27b25c5ccc767a2d6a63901d1e7918a09c3a4182911242bfe8e3e63dd72d32f642cd2cc3afe9b8eb2c503e3e2a" },
                { "ia", "1107ffcad42deeac500577f0da521485e7d1f47fb8f48e4d3103915f0a1de2996f13e130b83ecd02228e911225744abc4a2629fd2050c3025060b7484bccdb79" },
                { "id", "56c56a9cc628b9511cb64495209b223f3ec807e0e0fb827de61b1d6e951a27f501eb1dcc632ee02452b46efdaa840b9d77e53563b5edc50b819c3f965381ecfa" },
                { "is", "dec2760f2d5dc3fb5f0ea15957e0be406370a6696119c9f9e91972f40198be7b95449fcc340a54839f9680b91850cdb156f2e278d9e3a6e76997a6c1c8c48265" },
                { "it", "f82fabd00225cb76721e838a83a969ae87a3cdf108d165f67aa53f1015f3d589c4f8bf5a39cca4291650846638352e98c1688e059ceb2590510a335f0890d7cc" },
                { "ja", "5298a06e7ca8de42c491290ea2ad831cbeaacfb8bbf2cb41fd59734852844293436e85c90df10b803b71da1938d9c190fbf5a2b4b37b4e54b9eb3227667eb75a" },
                { "ka", "c42b0b0c85d92189e108e13e282610dc4f00019bf7b2a29267e59788e14c068fe372dbe08cab75b5c97876febfd02dc0bc0d1886ad31c28726c3c991855dd15a" },
                { "kab", "63fe817df41bf4d78fda2293661bb6c5268d7ed4b0be257c5a1a592127f42ff763d14373943bf758759e52310c4ac9110f29aecb022b0ccdfce4a86063b4918c" },
                { "kk", "fee65d6df79a27075d05d04e637ae30944128b082734889a3f9c64efd22056369ef9f4e00cdd83ff080ae25059f87302444781fe0ae82f2dd46c3a38919de226" },
                { "km", "0cd26d904db3cf66716bbc30a2962ab3b422b454a540123d1b0a6220637ef3c5df99d1647534273ebbcf83657e662a5af5f5f16358f2abcce53f8d00def74c6e" },
                { "kn", "aa1ea9002698b1320061042feda4367b1cd7308da61c01086c81a6e72ce41e596c001c4de444fbdbd3db595fe86a096644eaebb71623b4bc80417fec8b50eb1f" },
                { "ko", "8f86cfb056808723bb6de38be04bd93f56e545b88b30835d73c62a2f5b9cb610c7fd9f73f265df15404b22138a00f15405c3056cba0fc89c3ba2f80569296f1a" },
                { "lij", "31162a0f3191a0ef13c57bb9078fd3a5e8362713fd665288e8320cbdd7bf2145d868ff9d59bb1f487563ab1abf38133326690dd9af7546d18419e30bdc1009ba" },
                { "lt", "6fdcd2f1f6e6c4f2a60480ba58e033b4a2271c7ca9c136ae29df77645a4ef4f61a272515d09240138cee8cb9c095c13aa656d86a050898c52996589309390ca8" },
                { "lv", "fcd28b0e42d3723eaf3895af974f8d82272462819c779d4f68668920d508eab1e676e3cfb32c4806ef4a96aaee7206002fbb274e538ac4449304f94300829b3f" },
                { "mk", "44a6e905fb6763f041da87ffc9d37162c0bda523e4d8e18297275e46fb85f4e9920daa03e5a352d808b85fb6c74786f0499729195f8b62a169298c815422cd61" },
                { "mr", "9c1a71c43003fc9684be0fc9ecd2936abdf907b541d3593fd8769d10d8ea2b604c06d0e093dacb69e55cd7e3e5773d74ac37c002c1b4a01b409abbd2484f1f8a" },
                { "ms", "8cdf85a0624df1f8dbbe267753509d9662d337127317e6413e8a7bffdb447b28e97119b384353eb9bd6aea89c60a7be56b02f12b3ebe757596cf1490d5c2d701" },
                { "my", "0bcaa73e7570fc9790a05c5f880c8a377b9173c6f0a520dd152dcebbc35e6e138f0134a495668fac29b1beec86c3108c2b27918f927b7a57661fdc366d260bd8" },
                { "nb-NO", "8bc69a14f05a9a55cf6462a3cddac2bb17d999bcf57382c5f890db923e98aed7cb50776c2b6fe3aac7656eb5f12d903385da6c27193aa6231770e2460e619556" },
                { "ne-NP", "477816ddce09b5c17a565eb4a56a946e6f59441f92b409e4ccdfdd5004a9346b03d5cd3d6203e092e0815070f2ee3e9f8b4301afe13e493c5b37bc8079013661" },
                { "nl", "0c2f5ba24efead5bd4a5a2af5fb10a64f24cd7f7d62ffd646fb24a16f02fc431a546180df6c6cb2f1b868728b76d0082c45bf817970f16912be0040b4a8ac954" },
                { "nn-NO", "2b02de6fb081ec8d1cbc4d307d24f4c150f31bf395c890ca4609c1d6b1e7d04868e7ac5868acd4fc88a4d30b1bb9e1b51a2b1d9aa1386042ccff006fb1f2271e" },
                { "oc", "413451622aab51594f3b713dd6425e9ed1f3155c7c49a2d65b27bae00b3fa7681f8c272a7007cc78c07426837cf0d12855e62d969ceb73d93131155d4add5226" },
                { "pa-IN", "d81749e99bcc5587c6a28320eed492ec8b2464872c2bc4df455d5450cb3eabafa4b9832b75c97b9579635b6c4d88bb4b8056221a872572a83fec1f4dadc0e183" },
                { "pl", "fd1e0942c2e354d22ff6d83e90f2851fe3630d86f6ec0743d4d3826bb654fddb188bd71dd60e5a9bf8ac3330ab74c098985c4d1aa6e310f9cb24098902d614f8" },
                { "pt-BR", "e6997e78eeacbe03ece930ecb8a12854d66aadad3f72fae74b2f806e70f3de160553d622f4106c4aa331b7b5d74f5c4ff119f607c84b6db7a29a471a4efe2d76" },
                { "pt-PT", "f2fa598d48deb0da5acd227e157f3ef6a8e0dcac45a76e4da7f9bfecec79a5003c209a9a996f145a6b5a33655f2234dda3ed30ddd03b874781f638096aecb4ea" },
                { "rm", "2839371782b4b5983b539c612a1c68cf46a849faf6eef2b10e78577b153861dd4ba834a8e31df5543547d07319908da128154966a86fea6d9d8b2a507092e8b3" },
                { "ro", "4f90ffafddcda26f8c8305c219e957542e394c2dc472a84e685bba5dd7666a2b6291f419f892ecdec3b2fa37203a82196ea93578c1e06d8303f9684ddf4139d9" },
                { "ru", "ea8b28283f2baadbf2d6df46910e1174bc5304201e456b7e3dc6347149511abf479325be23bd9006f855063e6d3c756feca0ea4d1a970eb56387790939fb1c30" },
                { "sc", "0cd133061b3f212b0ca0346343ac2559938f6bd6f0c002c7c9f795066b5ccab83c9c0a6d0650c032f525a55b5a3e59760f4caa39abbb2b286adb2254e07e6ac1" },
                { "sco", "4c3013b084ce0e4bd7dc0a2740c3e0ec1ed8319ae697872b9fdeb58c4246e263b0d39b5f5f71180c5e3d44363cc47bc45f7b719901f96730be1c4701ec943125" },
                { "si", "f55c94b27f08d287062d9e5add13f607ef3d116f3908fc495f0520842c5bd1022e2d3f38cbb404f0af6b891d15813b8adf1446bb5d8f2ee8de85a9fc504ebb81" },
                { "sk", "8691f605f5b9d77e7f295ba0e465983cfd132a1d854911290e2bfe0db98da43acb1a5bdca9fefb0ef2d7fe73400a43627823c081b95cee1aa2d33e43764ad93f" },
                { "sl", "712bfa2d94ed61099132bd1da9665a7f83898c6fb884973226bfd83462cc469f3eb0d751ed453aa8f1d65cc01c2a629ae723f3843411ca7add77130248fb7ce9" },
                { "son", "783555f28cf32042f3161102d6eb8bd3e15090489542535a4939b7e02665d0128d373d6ebf71562880e17dce013e3383e57a52beec9e070c1bfed237fb1d85f3" },
                { "sq", "543facbb107466af35fe545099aadd20eabeb1c0569e47f85ea8d7be3a7c67a09faa3691aad542fc33b4e41e180b23121f26a437c0d0e49a6ba7203c2ddadea2" },
                { "sr", "5d3b73a762f6a41c58d60af9145df057f497f3e96ca3f382d671beaa5aaae5e3650c39df2ed30278e2fffb91cd5effff6a10af0262729b8fd904b364b47745cf" },
                { "sv-SE", "754f4ebddbe7e1affc0b5c0f296906d026c9f206aae7ed2e0ab058ff852c5dba14e9fa3f0829107ba1fc4d0c7c56d45f0305b0113e0a88d6baeff260bdbff7bf" },
                { "szl", "5266ced95e0fc3ec8a9b9053f467c1df4051949ce8d8a355ed8862b2fcde0db7c70e6c202f72fc100adc067a15beb010134a5e028d00e3d6644c5f278aec0cf1" },
                { "ta", "f77f30817c14a13603963aa5a86e8fd48b2bfe64bac62d5b149746b238d20ef3882a0fb526282c6f86ab02f45f35c225c0b9c70672d3a94506b017a4a5f2fcd3" },
                { "te", "3f6dfe48b35756efbfb07f64a31cab14c07c08ed268e3aef8a2fe1196a5b9fd629027d4ab8059d7cf39405bfb16c28ca9a379f167e6b7bd7726f79da3af79395" },
                { "tg", "499fdca024a30a32637534a0a16fb66de11054d5cf1f876218a2d2f05124a5c7d2629fc1d5102e6940f6cc79df4f9634c7ec355d2974c97b32a4b36415286f75" },
                { "th", "80b0142e808bf3b8badd6d55e1bbf406bde55982e5d5e810ad033efbe298cf75a6e7ddc1720c967aabd643c73e4bf43dea9a1a4f570db1bd9d234698a1f172a7" },
                { "tl", "70cb2245fd6a449d286ce6aa53ac23b5e4672ba2df12376d822edd78341a1945d7113a366aeccab34d4929c0a02a254e9903988a82d5bf7bd57a2ba7b4491fd8" },
                { "tr", "7741cee820a7be5fd45a6c6336189edb102616d8c2760ad5e029198ee0e143a5621ef80528f5e4041f9e821d26f3ab19ac2ca23a70148971b28425f4f28b1681" },
                { "trs", "30a4c0f089144930569538a9bf9500a17a47db0c60d6ca2a4d7d5daf487cef6a419ecda619f0dc5cd173b8e1c05645f735a864d709989f6c261a41a85f1048d2" },
                { "uk", "e54543098c9a4e7056135a10cfbcf33c9a320e71d05c7021233ea2179ee3289f9a8d28cdad7cbe300f78a625c5d936de10e08b27039808920e21afae8d4e080c" },
                { "ur", "0d6acfdd1222fcd8083d1ef8b4cddb33ea879a28b5e7d6493fcfc22c30ed3efee460e919a9b5f2373ad03f05195a3aafca083c9dab1fb3741723f5410f589e1a" },
                { "uz", "6e2af567cd7488e119456e5ccb784b931376e9c320b506cd9832813a07a430c2c10a7d7511225430566b27fdc8cf5bf747c06df6e7336d71d0431f5fe8f281a4" },
                { "vi", "c87dcf0f9e73666794391e64640b7ef80ab94e235386f1e0f67ad7654e00d4a60ce6b5a0a5b969e9ee4a0b9f9967b03ed2b28f05750acdc5fe4c157a11d14674" },
                { "xh", "07c8e3ac8ab8a64a8bcc48a06d7b4ce486e8231e9b8d265995a6c2dfe894cea702730aa55a1f60e47f00c05a0b8077487cf62b2d464e17d6420e22bf30220fbe" },
                { "zh-CN", "1b3ef6c9d0045f16020c171ee0d9a257a889dc23dbbd46b678cbf2608ef4caf174bfcd3ead83ebc3500b4c6b7b62ee6b1666e53fde3c3d91ceab4293f873bdc7" },
                { "zh-TW", "be8210683ab97316b420cc3b6214408f2837a11a3ee02f487c1a8245bf633487866b70e0e8495e39449258f3a0da61bb43df6ce0c0a84d103f5015a5a0dd4325" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "afe262ab27ac806722022da8f5688c6fa9bddd8ce47d884fb4f83875c66b48c1608388328f4d9f1edab66d8676258408e1a403e606b241ba98ca4f2119f524b6" },
                { "af", "5c0e12a005ed4f18800d791e7737530d058c5294b0c47c974d86cca6cb817ad9acb42d460eac53e499913a1b2f6ace091d442e4cce75d266a0c0211f832e434b" },
                { "an", "653a66b613537a031462be86ad6c8599b01ffb478e9b9603a1e683b0678efa858b7862758297b3b081fc550e56ea1ec291ba0c96821004c2ceb52be00779ccf4" },
                { "ar", "89854efb8ae752dc28207cdac9e5931d820c92d2ae8c6e5b97ba76dfabb3d27bd66dd7693ed8cfd6fd4e17cc4eabd6365cdec1bf67ff89660a7b01255a4e99bf" },
                { "ast", "592db6c0113a058741a14f266572550d9bd5fb2b1d02aa12d1b6bb0bbb57b3541624b26f942c055d4151ae47be7adef3ac8359f75a92dc35d2c315845e4f8272" },
                { "az", "65a447d7e6efcfa4f43ccaeb7a15c5c43e32a5a38e3297a25ba4c13414cdefe426f05682545823a3383853610591b9c00266d7de474d63d13653647e5878e752" },
                { "be", "b5d586954c0a268abf6435124723f2f78310f1197570dd911216bda80b1a86fcef98cfad76477386b6eaac5f5d7a4b8dac4b1a3354c98aeaa95b72b370bfcde0" },
                { "bg", "d31b80951eb1a4bf88e53f742a083620daf6077e4b47bfca2271c738c02064ba0a7cd9e6c2aed23c705ba537684a62c19d827a7c91fea3209b4fa17d4992a905" },
                { "bn", "9eca89247f1098a437f710fefe7c334532893ef17dbc4fbcba7dfc64ffd2c03c463f0dac38c60fe1584ee05faeb7759b19083e86e2acf45418caa15c44c0f67a" },
                { "br", "ccb3f4cfa0560ce6fc3f74ff2c955b8668a552374e317aba1026d419ee71ea174152ea19a95dd80cf41cfa3dc32642d41c7d2f40e5b3e95842cbaaefe4e9a211" },
                { "bs", "ce31031aa6dc87c2ce1067aa2f2f8dfe9d1516aa9413141774a1ff8f045eb0cd9f32c294665814c2ab2d65acfd3e6859e1f24f15604f65ec585944ce65b70729" },
                { "ca", "5dc3c8f3b4814550ca9b730a703585e311b0e276228f3cec903322b6d2ebc5c301de814000c488b28fad3d8e00f519c0c1b1d18a1902ac53974de74abd16c465" },
                { "cak", "e64232c1fb8f4199aa7f749304c8a4b2ab09da2c6cfd32ce5ba1986a915632bab4cc32889661416019d48e913acff59c3e44626c1ba0190129aba1413843f1ca" },
                { "cs", "d0410ad13582e820d29b3c653f902e45278f015f7f18647b558eab34dd53e53d7be3c8309f3a5d8712fac2cae17296081c15205d2c077b328960f9fc87693ef4" },
                { "cy", "53cd7ff536b2d6832e0f8c209bb422d154d9707de716b9873f8057d42789950410b89820ced9daee44502b5ad81d2022e8f1987a13b4f0a9ac3aa25365fb47b9" },
                { "da", "b41bab159a6da082d57fb4a03727f5a813d91525ded9a7d53a30f8698009e41937aa9f3b99ea4c7a453e016f222f3ac6436cd38198c2d3c98e4046940c86340b" },
                { "de", "9a4f39a7bf9c6312b4cfe678f488ac4e71c0a5abb769153fd1a224a59fca64325ad42a8915b92281d9233529c10e5e626ece7ac24c1489ed0869a78ac084efe0" },
                { "dsb", "bd3ee51d85c42fbfdd07780c36a386dc4af411bd05253dec13c4a3ac515d3d2dec4027ca7f76fa800dcb955576a9a1f591b2e3a9089050844145611ddb0a487b" },
                { "el", "817918885ebf57d98e9ad22c6e34021265f6df26ef92d86e135381c9d72375786765c8a75db9e7c2e486c9453ff06c3f755f33bd4628f6ad432af79118c865e6" },
                { "en-CA", "6cfc0b8282115eee089efcd925daffe5d3971fdc48191a9a2b357c7243ff7916a9c1056da4bd8ac18fb3fb26ff493aa5ddbe96b27bf03f61558955bd1c60ce62" },
                { "en-GB", "d143d283544c5c72ab359491e5d0315e4e31b27375d0af7e0621736dcfb44c35a80b6686fb436c7377a62ebde92f19f156f5ffb5e2f4f2e685c2d42b131be4a1" },
                { "en-US", "7a8d5910d38417a36ce898c00dbda2c45ced9abb550f8667a1023cdce68ff97476550c57d49a056b8d8e500b0336050de5b16ee3feafce73b4b4848a54d95ccb" },
                { "eo", "22bc9fcf150832bcb55fb530c32139779f8d86a1b4e4ba0205f774b67948bc1aada8216541ad3a8b8c44e25aaa0dc27fa2f57dd6beecf01c045fd9a66183626a" },
                { "es-AR", "ab333a5903805d77db3c9af5982a5fe119804050bd7bd550efd133ceaa249cfd7126128e21a3b34554015cab1d01843f0a2a0bf45467b39b4df0eb9ed8d0e999" },
                { "es-CL", "34ba4339e2bda308611a1bc08479b980948e8b8be77c49dd7d4b686200f9dc25f8ee7dd68562baad6ea98cbf63a2d82b1dd726abec1e404ec90df40182551fcd" },
                { "es-ES", "305626be0e61f963dc850c21c6a4be1678b7b7fd3fb29aa77616893fa3dc22cae5d99fa32677bcd2f60dbce87bf256b67560a952d988fff3cd34aaf8c45040f3" },
                { "es-MX", "db3d51ab2240e4f251cce59873205d5a950c04ffebf957183a3e35000c1319c7660d7d27e56f60e1b847d17ee1e843dbc2503920ff960a3a4160ee30300a6714" },
                { "et", "b38aa816e18801e9e858e4d6d63c51c7186f15cd568a35ca441395d2ce1b5e506b07836d9a89394d169b85c28c21c37113e18e80ea3a39340f93ee18a24e718e" },
                { "eu", "0dd3337057815fef009ec7731dc02d988a04dbb254c66a4d829c76eea6469e0e862aa1f3734b4033b0c01f39932e0b4281abd95284d7e435c05aa40fff595b0f" },
                { "fa", "2197f936332c39ad7fb1bbce2a92e0c20e56c7130f10f99b01adce51bb12ac0377cdb3e2acecdb6271501eff8cf156a4d9defd990898df10f32a58590dee955e" },
                { "ff", "a0fd2a498161f4a330ed5f310c57e217beb5580aff4dd9a271816dd61a4d984db4d8157fced4394f110c4f195e157ad4f8226d3b62da7076b50ebcb84c160579" },
                { "fi", "30ce9df39046510bcec232bd28538422dbc332a48d88b4c7ccb8d024e36d810e8fe307492708f5ed2a353869022b993f4b909e638729139ac1bc0fcc272677e2" },
                { "fr", "5e87911b81417f7dccf380b7226241e22b6709260f294e8a4ccb8809b0d775288e2aa552750f411c65bb912ad287b75987be97b25c6a5a459ec263ce031ffc4c" },
                { "fur", "2f9c7a7f7c393548fc4879ad5eb56b0470a386dad8ffcf08564409b497d40462fa05a79b6a4097ede636bc14abd1eb80d7ac4b6830567a076520653e8e0c1ffd" },
                { "fy-NL", "cec1de37b2a8613275eeb789000c255123a1af8b8df078df55381860aeae9b89e120f9f8f5635da5022634b74eae4bb6206e790546f8d1ec408425e20710ca0b" },
                { "ga-IE", "d575db4240ae6d9abaaee1fd5b510c9335d10480a66e1d529ed0cf2ce0ff512d7a03cceebdb88e606718fe0c8f784ee4c63814d43c1dcea6746a23c9c3548a88" },
                { "gd", "f68261b6c198d64f89d675bd2e28493ec1827bf035163c2557ea004b4fcf49a3c05782e2491f2cb8f94d9b0f07f76547f24c2524c3a60366e79c45d12113f395" },
                { "gl", "d282e4139fe9d56e74d37f0554c63997d9f60c5c3760de45993593f392cea0450f9b57eeee4b6645c7fc6c6ef514d9e0252be689bd8d92045fd1420d9cd84789" },
                { "gn", "fbd2810d1d28e7a4b11c8a807f8691f86513e643c418a91c67443c6a5bca899b7c7b37e33670aa904c5c4c6aaf4010a8cfc554b2a0f38915ad4570b099e52407" },
                { "gu-IN", "246688db7e565fc011e5f773f51a29bc4cd0cddff97c2e98d5d07a767ac31fdf8bdcbb6ac41f3bae2e19e7b1e919dd60f34a58c7da59fe890bb3fe13179ce326" },
                { "he", "9c29236cc614f1bedb820519d45c6e45cbe56bfe26c008cef718dcde752ea7800e87584ed9b3ed00103955cffe71653096dfd73520f114a95c75c14e873881f5" },
                { "hi-IN", "919e05696de7cc2d20563344c6b85c3ddd260ffa806fd3fffd33acd550b776457a233c3a5c7754d26d2d246fbd70f569781ffea49cecabcda6f1a5ce2afae706" },
                { "hr", "0dfe07f8a30c5dbd10e8201216ff2d31713e4a6c418e8ceb0b3098c3b70c4aaa723d9788510ab18443eb6c30748c55382fcf0b838e1dbe65bc32e1a8d51e2c3d" },
                { "hsb", "e7575e611879c35fd85db3065567e9b438db6da73e57a648baa27e60f5935128c11f36fd186b50a4393ed65e7e919709642562a1d8ba5a5348aa710e111d6807" },
                { "hu", "422a52b425635f0b12c6cd7541f81ff1b7c058307e18d31f8197fb697461ac3a8bceb3d6ddb700a87bd46c779c83c13d81ba660ed826ae2e4141482e1ad31553" },
                { "hy-AM", "09bea4577cefe099deef8ad90f11c89c40d221217b04f7521f8f55f0e818ff26eac5fbb9fc0f235c175bf629323c0e8d7634ea5d7fc0765a03676d6652a5f836" },
                { "ia", "2f9bde129475d2241859b13067d184c677f6e65a760e14df65006f7c0760d1c2e97047e4b8b038e8f5e775d98aa575fa05ac1caba09789a2e7f831a9875b1340" },
                { "id", "54f96bf5bef92994d7b805ff1551b072f559a25f03a356120ff08c9a1fd6af624abc1339c2961d87bd157cb077edb64748a0ba438eba22da2a886517660d9168" },
                { "is", "3f693a159fff3aee2780de41987e99d74f5e15b38ba3a0de9aa77e23f2bc7c9f0911ce342004b32fa7b92a7505b17bbd959d29a2ccdfe8fc5c5152a58c698512" },
                { "it", "6969f707ab80dd7fe7b79a0efdc15b1faa34698f4f395bd85b5adaff8a28818850ceec0633c8be0cc3414a5aa6762de5eaa4affdbb6a46c5443308e17351a317" },
                { "ja", "f2874e7e9760760e50a8d9d070fd6ce9398b437f7281b4fd5ad7ec9741ede0a962a55876bbdf2ecf6997d22929ea96b4dd55719d2d42253e7eaeef9411ef70b6" },
                { "ka", "599cd208d5f24fb9456c24b62b0703b849427fbbe825525489bb59adc153504afc16c01266dcfca009f39521bb78f002b52d0d1e0f3ad86472407b91364afa22" },
                { "kab", "f11c9eceea21cf92fe4430228df76d87095da102c8aa3f1557b08a2e39461aa0f7f7d64abda5cf00006460284d1b246f59feb5990450e3b2271d693465f91b47" },
                { "kk", "0265cf0fd5c496ceb233a7f198c4e69fcceab2411f643800e70ef9345f9cbd284cf59bf166ae288e0cf14fffbe91f67ffd739a1923ceb8f808abc3352b87b473" },
                { "km", "a46863e56231e573412b2c8f8283c5003e34d3a815f38cb61a36ac487e0b2b4e79da0fe043fc19345bdd9ab99b144a7c87c8f118f14d97f186583f423cae80ca" },
                { "kn", "36f10913a9255e6e4af46b97ceb1ebd09439905acaeab71660aa842c09871939f5a5c06aecf5c0c8be19c6a6d7c4c88b9ae3bcd53a17481d437d7584f192bd88" },
                { "ko", "01f26d1c2382cbd797fac47327f9bb19bcc983ede9e676a01add1921591e83247e871dcfebb09919800ea10a55b2ab6e1532182cae5213c971a2b1a32d865314" },
                { "lij", "834c7622a43687129c77e9bde915122b42a635b241ec1aec1e657f15487aaedcc685391fd0a05db57fa068d81a94a4c249bfdf4ccdeaedf508d8866308a49c46" },
                { "lt", "ccfb40b78349db4b14492c742875d527717e1f3ff37cebc2946ae0b3f48f90fbf1281ef35663b640e9515d6b2fbb7024244361d21246adbbe36cfdb888ed8b0d" },
                { "lv", "e3cf6d369daeceaa0cec670de4adfb62fd278fdc04c18b1a41f059a33a7f64e7ad5d5a8b391e5894c466d90d1a8dd9ecd5111afaf318ebab76725eb91f506864" },
                { "mk", "8b7620fc67ced6aced244807e7758de4ce508f619b8b8a175ddee928742b0186a5dbf2f4ead0eb8d7619b2e8db0a7db9dc1a68331d4808cb9f462bb2e4164261" },
                { "mr", "0dbb769c2f8c0d479b551b9ba6a3af30baa7ed5b68cc57bd8e8064e72af608edbd211e7dc9c71a551f6d6cdb0d705f03017eff501234826dcc6f2434a56bf994" },
                { "ms", "6c559232dea6f9bbecb6df3effcbf26337caaed50b8fd477d1cb721ea59fe08e32eb1c2ed92980bc4f5a8c35fb7dec85aa4233fdd14e9bff131125f8f2204c07" },
                { "my", "6c5890835ff88db8fc175f5b033cd1c49a9399c96d5822966c5ce5427246e9b900742993de05cf9cc23cdbc8ef444927c51a358589ac32e6c157b660ec28a7fc" },
                { "nb-NO", "d20df7f93f1fdba7b03bb5950afbc6466f010bfcd303e420f51e0f44d4d3ff36b22c69a0f4c08b0b2f5bf735e0810dbcaf2989b506545a16d566aeefe9938da6" },
                { "ne-NP", "557500123c64fec75db2175062b64d48856caa466f57adba90dd046015b7dab99d0c46807c1daf7a48b906a323d07c2bfc1405dc952bd42b175ef5a93c3183dd" },
                { "nl", "5742503ae5f919dafab07c9d43fe5462643d6f0fe1a16295cef511d7787cad911d78fb4304410e52b6564b91146d28d67a1178847e4e4147fc38aa5075fd61de" },
                { "nn-NO", "72530d34dab69bb11af9f3d24f6a4d156a0efdff1d99d9ae6142cabdb7fac66e4ab6bb3d66ea2645f4fb71be44d006b0851b3794d6dc51b37cd4d4f48d6d34d8" },
                { "oc", "5590fec756d2bac05933ac308f6ec7d28b11a872c9a579c368d4cacb5b43c36c9e19630f685490ec45aad4f4403ef4abd7ff046223ca07a12dd11c7d6af63fcd" },
                { "pa-IN", "9497bbaf8e97d341b00f8b2e7ee8fce7ed685b9c7900d2cf9dca7e38b93cd21d43a8fb30d97a74d8e4933a6e6bd9137d6823357e378ca4e2cebbf4e8256925af" },
                { "pl", "5a281b81d0007c27e2403ec31d0d649d163654b6e3cd3c50601f0109c6f26c56589f1898cae07d978af40c25345d047c4d59c36b367c194f19087fba4e7799db" },
                { "pt-BR", "10526f6e58498c98cb3a12ce2787fd37bdaa03d8eef1cc972079bc7e341ae85c90123d38ada7e8fb43c0af7bfeb6626a50b378edd678fd7ff2d5a9e029b25a86" },
                { "pt-PT", "8838d63dbe859cda3ab0cec4b23c0e09ee4ea7d6d63479a58518d4794a3e9a5daf703316b63ca147f07a0220cbc83f7ea1ddf013b8b4a5e65aa45b59133a7ba1" },
                { "rm", "c05b61ded8dbbe75d1083e1fb572c827882794798c3391d9c3c0b894c9096957be174800d2beed84e1d13ca22171cc07f648eda474b636262138c78d50b24d27" },
                { "ro", "86449b1e0591a9125974f4cf4e96722b61f0532ab90af71c94f38e03e7474b539f9fc39e97819c36820dd7f650c694514f02e616a8487f17da1905d7ff9cad92" },
                { "ru", "70b88fb04d58d3ef39388b222819297f40ebbc07588322866f48ed1e47312505193828dc38aadcca0b8afa6e506d2f5f90301c8ea1c3cfde234eb869d037dc13" },
                { "sc", "eb40f0ae21b7e506fb2c2e38f7304e12aad3e96cb4ef33b06fb0057563d22f18e24e1965037eaf7fd1aca7be1fd41d5e2e9d0d7a2e46c549bf9537ca40dce24f" },
                { "sco", "0003035e850e0c518c95b6d4c976cd57ace93ef439aac8fcacc427c6385da8d882c487192abc2b23be19e0e5d247f8536d828c1440e3031f0ef165ebd59e76c0" },
                { "si", "72b979b4543cf0ee189b8c094548469fc4a2df904f6102f7c80d8b5a2296648ed25864423af7c572bdec4ee8eca2ba5324170619352a3d79a0c83fb41bae8f1e" },
                { "sk", "4f03baf841a5bbd8666a7e248cd2e682d168dd71303231d3c3f5eb9be5d63e34acd900b7916556533daefa8e1a6af5b6d888e214a5bab13327ec712a764b0b19" },
                { "sl", "0dfa628f8e4ef09e70435740eb17f5611c99ac0cf430c3b287d8c5aaba805a9092729b36aa69209d54c8cc1bfef33b35a8e3cb9f48bf84007da59bdfd3c2ad36" },
                { "son", "bf9df3094fa08bd3517d973b6ef95f6fe4a31d31d723724b1b918d8bf75ad018fc0b6568a39b8e50bfc88c5ab4d231f78b68c25d4001251664dc33af499b88a4" },
                { "sq", "2b710945d3398b97090c76b86fa0d9b5f269ac6a1adb6d5b32dc2fb7c25b32cfae8eb5e21a6bc6e7260886729123b377ea2cc7e475fa890f7460289e6a8ec52a" },
                { "sr", "79b94ff33d77119e8e28adf406e1596960355de1100f3f0df19c0a24723077b25be1c2c3917b51fdf32e4baff86e01e6d8e5499215121e064434d7d7310126da" },
                { "sv-SE", "5a89221032ed6e379b995d3dc20205aea73d7ab0b39cba4d91d8008608fe182510b238cf56f55370d0a14081c48661d78581300ada3b0d63875b9810a2fd3f2a" },
                { "szl", "0f9ea02a103ae4a564196c64653649282b8321f5794a79397543eb32ff7c580d9c5dfc4bb1da96d6fad98dad4584e5e2f210d8bc6b3024f0d2f4b40e579ddfcc" },
                { "ta", "86be0d8dcc1f5cc87e5d8f62d5bd1dc6f96707810b9c07dd1e3015cb9e821e0c0dff885ec36d9362992d1381b34efb97310658d810b691d527d4cef1e7e9f788" },
                { "te", "1a10266b391b113ffce14c5da138a7752530705282cb31003e6096ff81177aac98b3139a42bfd3c44c745943b8173cd8393930d6b279eb08930e69ac51f69806" },
                { "tg", "72357bd354d528794c526626c71fafa11377f2d56c7feec7a09a3a9943c23c560fa24a424d7023acd258a585654795ee825c18356afb7ce49fcced4d15fdcfe9" },
                { "th", "1e458eb903e45ad27e4e4d4919b0362cbd53bdd0a40b9a661bc44b7003f0f7eea0c1116fdd50760695e82ec92bb2be78390560d0988a4fe2b0b1c34fc91a14ca" },
                { "tl", "8d99c69be6ec2e2f5edfd636291d8f76d7567d85a9b69f8c036d8be8c83a695ee2d826f6b66b00e786b9ac5356025d82378de4b33c602c8217371407f1291472" },
                { "tr", "453cb61fd6d1ce4edd2f7de7019ce1ddf7babb70675b9d70f1a829f5de1cd666be5aba438b510c13a4f24a9128c0740e83b4aa88c0521d95a00d3772664329e7" },
                { "trs", "bb89fa8fe4bfce68306464459d41a34d7c7a79a2c85797fc6c7a2375f531c27ea2716e1af97f672af8c7f986ef3db69f06517b1ecc13079394af251ffdbb60ff" },
                { "uk", "8dc70d934fae74932ceb42d61a3f63580d7f12ead986fccd475182cfc3eb1a1083ab4295e8189d50c1f303551c119e6f4b6aa2d8118348f3fa0379a74e4c89c4" },
                { "ur", "9d434bcc042c88d9332325cef9cebd79c6c4b5cebdfabf825f6b290056289820609354083365713cdce4d36333a2ee474d88fda53efe72c473043010e686f924" },
                { "uz", "2ab674b0c059ffbaef56232b8227284e93d381dc5dc84ecfec1485e8b5a2c8db5dd48c89fa29d0ac877ef8216ac6b90014e53d28ae13c5cdeb520a2e103fb440" },
                { "vi", "75069c26f1ec84928474aa6fe3ffb07a53de9c460edb3b72677c1d78cadc6991c1768d05dab72e63518ab2cf0eb01c7e3589f837fd9323f779a0277e5d972162" },
                { "xh", "9a7575469e08688b4ff605da93c0451573bfb9f1089966395af1f4a38a635cf65abd246f16dd2aa9402b51241fc4aaf6401feea9ce58e118783c3a0c9ea62b39" },
                { "zh-CN", "010d47daea038392c5ec45ea589e1c75c0f06bfd45ecc37daf16686237aee28fe624b73fe6dffc8c9b1c7c80488bb43154be4dda4a1dcbbcf04593eafe5471ca" },
                { "zh-TW", "9a56b0fe60870a0116e7e04f298000558457977df67050544260219346932adaa3bde2ebaa5bf6d7bb3c348657be774bfc5823b0e799c0757d883c74fd645f3e" }
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
            const string knownVersion = "115.13.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
