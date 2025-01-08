/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using updater.versions;

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
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.6.0";


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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "331c020373276470b8951ddd92ca6f0616d317a34e69daa93d86475cccc5b7eeb6326ffae022fecde7e6c5cb421e461185d01d8099c59918eb0b5fd328a5d3f0" },
                { "af", "69c7f6316d921b18fb7b4b45b0647cd930f826e74bfd0f52cf37639fe32befa1b9a9a809cbcdb07297ac8714a0db0360fc692b449fb2163b1b8187df62d2a8c5" },
                { "an", "df7a4d2150d31d88c701bc50826c6e86422ddcbe5120068a8cce5462cd3fb1c8006c77490259b2c9442ae17ca49a7a5a4645af76d477c991ff251a46ac6b434a" },
                { "ar", "c39cdd627b4c4b2db0a5e0897dd7caa73474737bcf3c1beb768a01bbcccb6e9e5d6ade2d5af44634e872a268ea83582a30666bedc5e6445b4a3bd5b872a0e589" },
                { "ast", "611a842de3ca836dfe74742296fcf6ed78bc9f421c9110ee7f240d825a4916e392defbed6284fbce117a6a43e8f1274c46810094a8738b25d1fb0171aa8913bd" },
                { "az", "285dde61eafcfb6fa5ac4763d53fc2947037cf5a963abdaf5c806f45abc24f8b935305875a09036bfcbcbf0e674a5505378ac9a2dfa4793076b7b4f8d26f5f93" },
                { "be", "0452062c126885b687e553f3d7a5ab2a2aaa2d0fc83cf3c3defa76dace175ef1d52b31667922d3c3b5f5c83ea040fe088ada00c6e8d5d57d1f41088fb20a4f0f" },
                { "bg", "27089844dbcaccee40b63a0371b0f73476bf89ec1dfef544e9e5fb151744adc4aaf56b88da73d86e9853bae6ceefb0b14abbf668f0a1ede71e15e0d14461cad6" },
                { "bn", "2dfad7b7ca8800f06c02ae0d08f68d30104eea2c917e93620af433b1fad2bdb5c76d8ffeb399460a1731645d01633fa336d467db685f2de6ebeb26c36c0b3f26" },
                { "br", "25b549774c49be9f5fb5c29ee4de22a7d22a001d06425857e4c64f1f2cbe6d4b18cba5c9d5759e7ac158bf75ef7845de1cc007ebc89bdbc3f1745020a6896412" },
                { "bs", "1fc3a395f01101437b64392ce0acdd66d828e565006d3fb01e7cd5d44003c460b508530bfd1b950b7987b24f55f59b0cdbba8fecf459e3b591018ac125917993" },
                { "ca", "e8ef8bfd81d8455e8cc1e7136ff241d0ff7dd17b2a06c95f204d3c9b64096e59fdd9594d1499cb9e2365141ef04e61c9314d14941f8889200fd7ff54fa8c38db" },
                { "cak", "a6d3fd6183fe5f5b56aa563323de1e524236732531048ff21c54f0b1013b7f4d4eaf59a2b021e291fafc8150fd1d350ae70be4bbebb572966c37354654f177e8" },
                { "cs", "a7ff394bf0ab84e3f1c9b9b8b35003c5968dfe9f91a5bac11ccfc069c7620a1786a7d80792dc203fbab76d770954d008f9f86465ca11aebaa36bd00cb11a2711" },
                { "cy", "7de0821e0881d07f38ff8a91ec71ea7466cfdd2049521c03a0409477739abb442a220705fd9891a038df60a9232967283f3098b8bf7f94f4d71243bb7780863e" },
                { "da", "b93768c2cabffa2a9a40741267943e30a4b68d6c26bc03780c9447cff63d42c9b6cb3ebdd4dc5c25000fc9c5f46f64d8d4ec7a4a4d9b1d1567387e87b9927470" },
                { "de", "509a90af0593eea45c53b7eaedec4bbc3fc7e25a8a5533e8fbfc4da88b4bd7460592002659ec24b282bc2240558cead588359e49efaeee73f39071c527bf9eff" },
                { "dsb", "3dbc53068a884b65fb305d66b12aeabf1fe065c3254cf499592b41af7614ab4f9bf789871ada5aff7ff6cc5c906ae69f616e6da1b8954d20c40ffb0753dc369e" },
                { "el", "19f26d0d009e639d7874330fbbf59fc7074e05abf7c7625f6acab55ad3b4550cfab3d10311bd020547aa0064a6a5d46097d7d395fe820a774b6b2c53fb49bcd4" },
                { "en-CA", "e423d744720a9a96c1577acbe828290c4bca3c188d09f23de59b967f351267ebffcc62d98920bc77101ed0b39bceb157b1469b7184cc27b6c46561db77d5bc11" },
                { "en-GB", "693ae6888bf7215d6b5fead7be71d3728a5db51e90f3eebff4a9c2afe27b193f9a905be062c846ff538e5603f7881bf56c6c7ecb1b1d684498db049bea2875d1" },
                { "en-US", "19f5ebaddd0ba824af578a4344e4b0c632f4d51fa91688b71af2ab2faf574b04affd9087e643d802ec7da1fa119380e7c046d91666bd487dfbce17cea08a503b" },
                { "eo", "93b3d49ae526f58e0dc65e2d5e2de04de6c7c2f33c08868be5cb4bfb13e43d9375ba6fef2590d4cf91ca199f422b25480ef570c782e44f97945a466de220ac89" },
                { "es-AR", "72a14ed1e34c4a0a5d95b6ae6041661b13c0225fc1d600e590bc8f41c70f99428fe7df343fda7000204b2d4432cbf66d886ffba55b2d350a29f27f94012dc6e1" },
                { "es-CL", "0e2d8bf6592336e9ec7ae91d2125800a224c6f5d7e786c9b3ad1b593ecd4cea9cb5695c62f64047ec7cbd698b42bd421b41a15ddf0dedcd2460532094da97985" },
                { "es-ES", "e0748ad35fd37d4bfff8864259fdf02a5d793b44855f32052c331f8ff6c7b7cb1a6042bc2dd98f063be342f3b4304d0bae0249ecdab4855589c68a0489f5cdcd" },
                { "es-MX", "2c3b9c48b9fb0db741a0c3c39dc5d7d4b751035918a4a0b9f488d578de2e45d094a7bcbdb75d99fb93bc0d9d2f2b722131118a9a9c04278ba739c6b3deefa138" },
                { "et", "34d70f050a0cb80810c7734acd4e0f393d43b9b02fe22015f88005e0163640b687e1a4423054f3aefca7933d3a682d6ce1793a89f53cf2ec8241e639fb97f8a2" },
                { "eu", "4e560e839c5d3e0b6aa169871636eaec5aa7e99b5a76623a46415bc623cf55613bbbe0001e545136e4e02fa44da27acb4594a886603033a672c67a5072129950" },
                { "fa", "6baeb24d5542836a96174cd93694ab9304db8ce8d7c67f9c6492285a57ba012fd11b887094db30bda7e416deb4831cf76faae0e55c8ce4aaf0a468926dc17014" },
                { "ff", "14b091fc921c40813eb489597bb1d4bd7e4160e490957dfaa12000da5345a40b1a80267bbce2778e2199a46aacd12253d944f8610ee360fb59d1bcbecd944f22" },
                { "fi", "4e4a9e05c9e5d2847dd11906c35179aaf383e228dac01f9762555e144b292bee1591012e80f16d107251babacb7d15e8b4065757d610370008d7b05052bbadac" },
                { "fr", "8097be53012b2298d50cfdd3003769e7f13362d8a15d6eeb64993eff70cfcdeebde93697c621b75110570ab0762ab1744e5a8e7bc7690d351787570ed4da5f1b" },
                { "fur", "e4bf2ce5d5328f9772dd1e282b35848d8b7ae265f2af2e6d9fb509d2227a771b52f32d63ab697fce664420a6b378f8e458607095de21b14ce28af1dc59bf7f03" },
                { "fy-NL", "2bd80fcc98ba705f2052555aeac5196a853f3c9b39beff1ae3139943144f9de8dadf373e83dad5203f34f387d508727184a254d9d1c50a32b904d73b61bde312" },
                { "ga-IE", "1c69e8268ac629ecee2aababa325544404d99510f1bad094f049e672ec7e70b90914b971ca5b36a9c1d5a3857e8892157e870079d2ad2d9857eb5a3e9dffc4d4" },
                { "gd", "a6dd0e1a8c5a0951a5a01f499de69229d356285e220b51de37e6fbcf54911fb8628e559c9675649bec56a61109e901b44e26c7ac7a8e07f7d919e69dcbd3319a" },
                { "gl", "fe8eacc6e7525823e3a3d16aab4c86579df66208baa865bd1a01b038ac3bf14563d3520349b0ba203996cbc0779c50e7469aa3acd7355e5c1589d72776ba9530" },
                { "gn", "95b402d25a3de9b79600ded1ec9012bb00a5f7c16e996685fe8a43e64c2ecb2fde4431f2944630dfe9ce331b3dd355fe6be3f701cbbbeedee0161e2cc5c62363" },
                { "gu-IN", "e0d5d6a54185988af98e8b113770520619ad86c0ba2874c50d803012cd1254dfce11487869547928ff65666ed73f731a7d431c443e0a61f819ca82c416267de0" },
                { "he", "2aa0359a45728ca068a912e0cd78d0e637dd64626473e32acd6df6ef70e3c829a969d5fdf7c9a89ce043c25ebafd4a354fab40846c8fe6fe719d4b6c970df6a9" },
                { "hi-IN", "2a731c223976d6ef5a72691f4ba848e9a9363e6698700b578700f8f6f186a979e5f972fe40a1f7777a878da8d1d5a9a541169253e64616351582be9a79113ab7" },
                { "hr", "3d95679d3e7df28d0cb79096bf50ad6374cd09cbc82fdf08ad95b309b37567a000d7c937a2ca72e287ad4610dcc73d8f85777332c7a5089b80f84b0640cdcbd7" },
                { "hsb", "8ceee713a0cb09bb519da5e569026dfa2c19fa5a2540713b21f86b5ac035ca7d132145932be92089e7c835fcdb7b2cbea2e5a717e5ba5e0bb7aa97bb7e62de14" },
                { "hu", "eab2afe4be26d77d5f0d7e12c3e9bdefd7853589a3b897384ce89918c695f3cecceef4c4fce1a0a06dda1134b5111e508231af43c4aafb48a44032ec1b7b890d" },
                { "hy-AM", "8ddef02f10889e8d1e9aece2138830b99e690b639cf5ffe1e5f1f6c49cc5209b4f7e7bfebcbdad492d7f684ad67621038c0e5f9853c5985a78bcb3270d4e3c49" },
                { "ia", "067793603d07328662685829292aea567d2a35d3f4f9adcd9c13c49603f64a84354f8378c42e7b82a2bf8bbead40e38094f9f52f2f102320a4c586666e1c0307" },
                { "id", "0a9eb310d374c0cf98d2b5fbf7cdb9875fc8d8d7700c77f5d0e910e8466c94b3c6dda39eef00f86cf6eb7d691da21e21540a9367078b967cdfdc1f341a3083e8" },
                { "is", "2cd9d33e3a5aa3dd8aae175f830b963dc32d56cf458e94c1ff4d6f0359a8dfb63ea0c10423017c8e8520aa31e1904dbd52c11100e929dd9d1525a665b13ccb95" },
                { "it", "812cbaab90bae4e350d752311a26b324c495b216f4120944121759b2947d8b79b3e687d41020512d0b5fea86f785e8ae97a93ab54d7dd0bf4e75f0ad7dafcf1b" },
                { "ja", "8fa42231068777d0aa86f47811682c42dff2416b7fba478f31970f17072c72d0413690bcc7d9bf7170edee930cb24d4db80c28089b831e6f450ccbe364e345db" },
                { "ka", "a7b266268682aacb155a9b2b9cf90b636b33ca845ff17bf76a5f2245069954906d15888c726c2d7bd97cfa65697a117b452ea9aa640785c3f13455a7f51ec91d" },
                { "kab", "a729e7e9fd52655e63536c08f6841f1e3733e18211936f04e3769843e50a796caee9629b24a04ad0b8b61ceb1bd79bfb8372c915ba4ebc8b13146dda49ac4e88" },
                { "kk", "e1866aaf264ec109eba93353526dc1b57c8767a92296936c31fb27f8c87d1ddddbe25eedc18967795d955db090775153f4f5043d43ac6ddfda0c3f79087b573a" },
                { "km", "6750e0cad55f835a2cc8bb4157fbd74feeab3707b4f34f34925809055a92b9068b822cadd6419cc313a8a3a2e9f45cedd50fb5543ca8d7cf7e355e2c7c072ad7" },
                { "kn", "9a520969de1aeac91e4cd4975434d6589686980b85febffd2bf831b758923bb294f9514d0fc8864e410334287476dda620d05fdf6102211307146220a2dbf12c" },
                { "ko", "a6a60abcf1e2664f27799c807dac0734cea0c2a1e6c8ba86f84530b62762f8aee4b35c306a7cae8f4137d1182d74f4ce4cd9842fcbfe9f2a6fcde63c4ff6e5ab" },
                { "lij", "b3eda4bdca2555ab8aa5bb0203b064e962a02cbc2d88d22a09448178e92dac07a8b896468abe5b4ef2fa5a50ce271693d1ca5dec37dffeeabc2b5f4870a19a17" },
                { "lt", "75f1767d98ab863b0259e910f5c9306b27f709a5b61fb2ba103335bb8a73cb397aaf85135a89108417726467fbbfd57965fd6699a0d44a621911b0469d20a607" },
                { "lv", "be83ef28be7c38a96acac8c509b77106a3b11dd0fedc712f383ce6c8c4aa2b106df4b8b05e8315cf4da24a1c3d7b625dc663a47724379deaf93e23e9033f258b" },
                { "mk", "dc181ea2b40c88128fdb8e0753c6837b83eb41730eba13444b58452c88d59cd20d729b548090010a25f1a7578b5bbb6f63b68f2f7329e7dc45ee987d96925570" },
                { "mr", "185f4ae8b3db9773fbbf3b133bb54d7a5e03813bb63d8d55e131ec42bcc0173397be5fe0719eaf791bf82571e1a1f248c40c364e366e36c932ec31fbcea1ad4c" },
                { "ms", "4143033aa3093bf28f55d2e79275ca6d4a0b141c0ab62524ea739ed7474a6511d6d0360ac41d3e34b06b5f833f2089670ec09723e719704834798bfe8bec0a1c" },
                { "my", "79a4fe6e6044c1d79122de76a3b59186009fb0b79b77c08f1cede1429a28f982a48f4ba6cfd062794d3452d4ad38a12eb4852352d8fae47dd56d715a51624281" },
                { "nb-NO", "ca6b8a850bd31783d715e5f91f63b864cf04a92a2b12eeb3a98f680981b1496335cee9877e7dfe6aa8c47c7bcff5df6c31d1247a240c77f2675b91072d66c003" },
                { "ne-NP", "9817a74812d6b1b8df4870f4678b6b9481cc087ce6103104a974ca35955a6f0f9d9ad9831d306cdae51a05e58d26830abf8d90ba04a4a913e0d513f499752b03" },
                { "nl", "e91a2c0f256d0df198a21329cdbad5f9372dacdc1330e6cadc2457f12f6a21fe6cbd02dc53de646313958f68472c223a4c7b9e8d375f048da03dc73e685936a3" },
                { "nn-NO", "397d1b01396ae52011105f892aba01f5de7fa3852354d7c457d1c420240d2cac3c259474d600db86d64998ff146677682194e6af5de1a16af89f8e9ed46bb07d" },
                { "oc", "fc9ff9c5fd92f5ec519a5f338a0b1258820fda55e5d98c235ce138a055d9bba7865630f79e9fd18ff3bd03b26dbd17be49f64f6122f1287da861cb9b07d2fee5" },
                { "pa-IN", "bdce4b1097195bad07c6cc0ca4fab0ad48cb8c2931a11a35296b57d1ca45dda8f9c4acacf852a531a2a44cfdc65589fd76e4db8b3a1126976dc095c75992aec6" },
                { "pl", "af1c9dffd7e4eb8ee6edc0371846fee0a51601e0d8f824c76083fe0fa29e5f7a77c6835e071a0b76e6cf42a3479c68c9d5b28e9cd83c32c01cbf99fda29c43e6" },
                { "pt-BR", "7e8854ac380fb1e2e57f8283bf67bc537d33fd13bdfbfc5d081843e8e52418dcea514c7f3a66f9d83bf8c61f1a8b65a4c51f8b4020764d156be403d7228f2c92" },
                { "pt-PT", "08580e63f3dd570dca056c1a6a4e6c80813a30999db399b4e64152992e98652c8dddde1a39c58cdcca27743379e911bdceb678df0e89833390f12f6efdf05c19" },
                { "rm", "8495b24e12541c6aba83e38b6471ac323fc5cc7b03d8c45173a7440bba196e255fe27d70fc6b01dcd16030b3c4ce5accfc3201e62e74cbf9b8106cc708dc41a7" },
                { "ro", "ed9e09224fa3ff144d73ad7e7f15c2cd32d3e749e6943b9d3495a7971dac5539ae25bf5ba0e3672ea884e28ec87512e5028fc615796ba2ce8cf9ce78ff133d76" },
                { "ru", "8a1120adc0416676e598776c33e14f624822cac845d44fdadc81c10f381cafb5ac20a1f6886e23b8a9f10814452eb2c734a73003fabfe98a44eae7f57f94871f" },
                { "sat", "5ba501533c60028c3001e947a98032e8cd0feddf6003231d368a22a04a902fce1f44dc973c9eecdf815d1fc0d09043692f0d9872ead1f5eb03c96751a455d3c0" },
                { "sc", "8da4349038d1d57fc391d7dc04974739a4bc7a822db613f46fa8a286e353b30007b144018b0f619c03013c0a46aa58c9caa1922a8dbe56c0f806b54e2a103d5e" },
                { "sco", "2af8a6c74dc6872b678469ffb71f86abcd72e561f48edf01ef83fafeb8628f0fa93f02e5f11004b98502d1d28ee1292b35c7dd3a510fe87d79bf3363bbf9575d" },
                { "si", "cde7acfe965ca9d2ff4f8a3ee05f6cfbb68db5ec6ed4e7ce27100f98f08443b4e10581b5150be83110098fd9f01d88e5468bcd0cf744307b1fda305d09634441" },
                { "sk", "302421d220477354613f3323a9e84bae9519852eda752a3b0fec3a5bcb16647a9f3da7508be7a32e0248431e4223e9b76b8ccd04e45c66ee8695c8a62b4c2496" },
                { "skr", "e4405f3231005c7522ec96dd76beb292b44f8d54f5e2da119169e2feb9b8bb77a46193ff64845459b2ae401d460eae5b71bcc4f7c8334658d072a43bf064cb3a" },
                { "sl", "37a0187f88ae4c32f3e7c54446e77f6a63c55cb398466acc60b5299ac66949d7abb8b5d388e4c24909ea65076444d27b6d3576fd8ed732b130f48e70c5c56823" },
                { "son", "795da78fb8b4cf76de83afe5b0746a1718e3e72efca2c5c49790b6d83a089c95adea251b7615c81a48b34bd33f51830d41c663629c8226f647e2af0464e938ad" },
                { "sq", "c4d5a7ea7e9f0039dc8b436e52f45920a62d80a07c00bab3705c55f8327aa7b63abcb66ba4f0112bb8f43d170f5c519e5b25d642a514ea99b87ab421e68dbb76" },
                { "sr", "f83f652746b0ebd849c912fa490a8982ab27fef6ffdcd36f6537911bc2846e43bb75a2b86d3339d4bf7e41fe4b9dece05a94167b032c8ffda03a13ea5cfb8ac1" },
                { "sv-SE", "87fc2877a6a9f7ba2f0f82eb7a189909e4da4b9b873947721fc79e69b2a6e510c46fdca3c4d148d6cdb39616052098a08ff311ada679de7505b845c9e124bd83" },
                { "szl", "23ef522e76c6badf2124a6eade80ae1d7ebc0270240d999bb96789cf0ab5215ae6bec67b170e9b003f6f0856ea4f7b8099ec1eedf6a3fc053dcde1fab12862ba" },
                { "ta", "c53e9d711c674b8e9da62a4794ee2c79db52953db01597e2525a0573f304061fe5ff10e3d8b76f9901bfd85fa585bdfc9a165da94fc732a23fc1dd1c4b1e9bfe" },
                { "te", "cc1fb727371f384a50676d4aa9073f46840285cb6054bfc86e85af6616f86fcfb4d773074e117286296a1f0a3457ba9f16f2c1033d25f4af1ee1a7b29a0c0cb0" },
                { "tg", "3d116e1ff9f51b18de24c14bf46fe0ec29fea2a07da7c1f289eac70982468381793a9c4ca7b23ca3193f0b4a3f2be5ef95c9d58e71c3d7f11c0d98f6e794f9d7" },
                { "th", "8a7dd8c3b9697f34934dabcc7ea5ab5207c80c19663e2f16f5d1ea3c6772f23654c8b2e1fac792adc9ffca95da7d5dbb254a7226b706888de8e2ba57153c79af" },
                { "tl", "79b3e09975d3a5b05f0dff73c04e1323ee29b2c283cb1c33342bb67ac19e6bceb88c2f67bb7ff6b9a0e403c0162480c6f0ca80c68f72b03c7f7133f403952f64" },
                { "tr", "eedaae7e83bc6f33a7d26cb40142a52a7e6ce6590bc12e63eeab0fee76bfc4186e92f57288bda2524a8edf61fe5ba3321fe191ccc7652e8611cf5dcf955de6c6" },
                { "trs", "8cc802513d12489c5fe4a6a92117a9d0f5220770cfbf8119b809aab6905c0f30578ee692f4769356578bb57964973861bc36e64885e322331d31f79ca81366e9" },
                { "uk", "e7871b37b85f3efdb47602579763e51c8137c64dc7f0cdb0e53cfd7555c7c65992ab90a16f1a729fae5d0f293b1b38d4d6baeaa033c172f01e4071ca1f7df3c7" },
                { "ur", "c1538c9d958e15138d9a6112d4daa71e01b2ceeeefbe2903cd0788bed7e9fae6811e6e0ba00bfe1dff1fad7518dc1571d19b01024124f9d716f8590ca8e1f99d" },
                { "uz", "7510b64b294186ae940a82f7b53420ac06da075fc333c07063afba8377c3f0029482eb71fa8f4bece51f5196da3a1aa22517275f8eddc00ff21cc1ae3f76ec1a" },
                { "vi", "bd7933d400c7caea1e5aaccf82a28f38eb387df9b3a3f1527940c5cb0827a103e86074df144ba0d0eb2b113aba3bdb8d8869194a606335cdd2e8f54da78556c1" },
                { "xh", "e477a73cd8eac1f1b5dfaec6479643d74806f881321f73391961a417578413daa4de89070b6f455c1bea97aa057c61b865a3f6d83ca2d61d9f12e319876b3e8f" },
                { "zh-CN", "118ffebb4a3a434a08d084b252433da46dcfce35ba881d3e22ff6f250371a27dc2b542d003287ee9ef351866f97c511569383a59e89093eb31169cf8047884c3" },
                { "zh-TW", "5c7c4f5d4e9829782b7d461cc7ae1e7a4efc473bc846aeb566b695edf8d4a4b846832c6cee4eeea0cbc035ee1f1bc40d0885906b0501bb9d3613791505ffc693" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f09efba7baf42a4ba8144b8cf21a9cff6ad751d3743e73fd12b0295a69f39fa743d3d4890180c0442a0095cb9d5dca93ea00b38ba7a2bdfe5ac0a944e84150ad" },
                { "af", "aeb5223d7b3a926a38b6ead17e3b20df05037fa9a5034daf13d62b5ca3b2b0b45d6ae5180aab1ce63e64d6e2a22162d79d893ba3756e8a6692c4425cc1a56542" },
                { "an", "06c37ab4cdae1225ca42f92d37ac02a60cdbb3990db10a37881938eaf8a25b77606138dd42c768ea458cdb9ae88bf130227367c2fac8cce7827d20c9f58dfab7" },
                { "ar", "fd044a4882394079225ec2345f76d2d492e8311d626900801bd4bf3e38fc453e8dd9f2b9ce5103cf142a4bf8e00d1cbc8b5b7fde6fe93bd41d1d3c7d3e06c652" },
                { "ast", "ba92a2b9fa2f1cb08b0bfaa64fb2da8fa9de609eec78c7b636811261aab04e96c7e3e49e8da3dfabedb672a1617a7967c02818b4f2b5e96d43552219acd25955" },
                { "az", "bcbe4cc83134c48995ec6739d33808752c758712db86570cb05b0e7db5d8349a9f80d80454c4e14793b9080a27fabfc395a821a46902e7d53ffa355619839e5d" },
                { "be", "e4bc0c9970143f8771b158a0a24e3a2afc7f69ec47d73337e6d7dacbc8180d76e696a1fc9626739dfa30acbeb209c2f5221d48558d1e7bc364685135a2f2e216" },
                { "bg", "31fbeebb1f84ab8d541f6856dba62f43fcc6750437ccc76ec13d2307b3094c4f4c7a91de1e603990a53a37c6b94b2fea9b024424d59f21c85bae52902f5f9a51" },
                { "bn", "f5bc8350cbe3908ff693174a957d947645623c61fc44af1f507297a0347ce3223ddf9ee8f1328c8d1affd6e7f767a6348743358c8c067e846db1d36a91a5db90" },
                { "br", "f068c8d712e292ce3729459ab3725727c217b2b7852076bdced0f2a0573c11827669c3cd948b793cdcbb068b9621603782aad21fae192ba390b9234ea5c5b442" },
                { "bs", "08587ef7713646e2fff6c8bf9b0c3040e7e28f58b1fa29827f23844232a04addc41a66af5aa6cb86d86b780f16ea0f46fff5579c65e558092415fe15d6ba5dc9" },
                { "ca", "e19deba79119397f1281023a04b2a3b182c64338b25968bb4b3d34ffe74ec8366f6318d40b6845a84674a9cc5b60c480a0e5a954cf4a1afeb517210ade524536" },
                { "cak", "12a82fa516d581957f5ee6965f49be63a97572a9a7d1717f07420614082bfb95e555f0d134190c740af4079678f8eaeb379a6b268726d8def9c84c711dc78fd2" },
                { "cs", "f88b3c25a8bfe91c1c989383a8ab0872c82697f1b21eae384c554222198e7145a1c9ea76e571a0f9a288ae5738fc8cce8a5113531e1beabde881e71e158b98dd" },
                { "cy", "dd67c64af47f3c5168eae825cb243bcb249db41425134f16df89728760766aaa4366f17dc712aa457b2527126d6c696787907af63d8a5e5323dfd49a9c600d77" },
                { "da", "bd7abf5633437e7a37fb9180348abdda9d89b6a34a9e43c6a01a3cf322175c7123e576db0391ee9482ec22b6cba734bc0c2856b15801bc5cbcfd2db883c325e9" },
                { "de", "3c210048a765897e663afd23de44ce3ee4dc11d35c78fb3f5d40d1428ee27a4e0c33549bad24163f17bf58b6ebd36f92e07bad1c4ce144381bb7baaa36c1daec" },
                { "dsb", "b3078dcec823f14d877ee51bbbe32384cec7a89a2009f423756312bd680056a5c50d7c19eb698930deaf14a6e3f13aa80a5ca326212c51aa42403b9a9fca752e" },
                { "el", "3f31f6c36f57ea5d6f7fe65e47232bc4b88f87600a318b8d58bd6cd5a814794d0b66dbf5c21d90badcb3a38832218cbc7450d93400c0810a6750ff10546585bf" },
                { "en-CA", "bb50fc2d4f7ac84b0e465a318eb6854996a7ba910ad9084e8c8dbdb6916a3979810a924d7274563ea6e9597b49aac2333413ed5565540a048cd467793c537644" },
                { "en-GB", "3a404235701ba4bf8fb3c4c933c5db10ba0b133b6866a8a24ddb2a4988d46b6fbdc15c869b4c4ac4c49923ae90e02b737f59b2820da365e70f0671d2c444b37a" },
                { "en-US", "0783e9f7c5f9d0d823fb29dedaed20d8c9aad9ed4fe79c1e5a9c6ab068b72852da24d745f80032f9644b50e492769d348bf481ce7dd68cd9a281fdd7574783e4" },
                { "eo", "a7164ab8d82ad2a23b7f476e08077eaf1858bf03e31704281c33ada149018fee3248058f40d41f5546a3d6f254228d07cddfd77d867434f42be44aeb87e30441" },
                { "es-AR", "8a8772fc5bf9ec00b7395da161aa42b9bb5dfd2e7b8fd9b88435f363879493e86464fe1c8f2f43309720ac5c87848d253d34b0a2562e109202910c5054a64ac0" },
                { "es-CL", "95dab075cb586587589b068f723181f652ecfc58e46a10d3d455a574ff58c8c77aa2582645cb28a3daf1be4071d1ad4a5ff483ffad4af3768c19b40063048345" },
                { "es-ES", "17020a2b1aee371f3eb748f307646d7e95329856baaa543cdf3b059a3a424939d8087daec3b7f4b0b458b3c60fee89cef9106a4090bd62b663c1360f4c8a5b9e" },
                { "es-MX", "36a2f3cbccb93c161f7e027d7975252d02ccb0b03d2e35832f42f5308987ac8cd2b8f97f19082566292a02c8c9e8db6e8daf6ed953187260c1cb736527069c1a" },
                { "et", "bffab77b8e88d456ed0bad0ebf3869976432eba71df17d9fbaa7db11a82a62af9e341f9159b7f93d252488f07591cc33d0d954a486feed878e2e818558f69a06" },
                { "eu", "4e4b83288379e058dfb255927f0ec8c84044c3c7fd50434e9b46d3ad5d5845f15b024551ca8c72c2f2395a34c55832a107085740e4c5590d3f5e065d3c8aceed" },
                { "fa", "d11e0cdf2115468b75bb26bd66dbbd28ddf6a4c0e37a0238221fda1c8ae0e1635887ea828e508899e9213f427cb08dd1d5d6cf2fae5a3ec55fa88288827063e8" },
                { "ff", "bec9d5a2b9bb8454b00713bdf99c16d3461aeee60313f48d00bed402c2f88d978de02cf592f9a20cce9d15a557c6c2900137f2e8b785534233fa3aa5acd55baa" },
                { "fi", "d058e6375d314bd964457ee50a34bb1952459cdbed99dc55d71fee803fee228d2c70ab59875d7985803bdc2a4a905eac70e64af770409aa2d18febbc0963335f" },
                { "fr", "c37d901d2c19fb9eda9b6d7d0f561e52c2d095f232dd289dbf9b53e9ab6e29dd18f822b512d8f4223c004671b12d4ca141c5e18eab66e4f6cf4e2476718c7e5b" },
                { "fur", "a072f87a4adac3e4e06e6d5e90730bd8cb2cca6e64a43412f9e314376c4538875ec2738c5126f7603014005f4b53398cbecce11f9e5facbd26ceb5033702eed6" },
                { "fy-NL", "ba212d90cb57cf7bce456ee2f2550c949b45ffd3963d0af32c75e6a70c5e72959972b561d3af0de1c3ff7b43523fbed54a01c1be8f2c81570c7a8cac58d933d7" },
                { "ga-IE", "8dbc155bf551e808bb7e1d555ffb867665c6f58fef862e48c8ba1bce06fbf6463974c01d3a3ed544496cb5073d1498b8285561c00090a10b9f87245e127c8018" },
                { "gd", "41904d50899222cb1e87c39abee8d0ea40ba96fbb77929dda69dde78a14c4d5c02c66343e61265b9a1787a055e04f01cd1db4b326176d486aada50d35af75ab0" },
                { "gl", "51d26abd288ca5935de00e0ecb8b8adda8e308d50423981afb83810d8ecbd1cee40ecfb1019cfeab1dee871d6b41a4e08448a2f916dc1068aa889a52a239c08d" },
                { "gn", "b30fa6e4aaed5ebf1a5dadd93ee7d84d66adb04c4a43e1c16a0d16d66d107bfd53e553b32a58d72cb7ee81c98d6c6063bae6b2ea5fd3a6b9ee69ca2c70a53ba0" },
                { "gu-IN", "b486bc357b0782a8d62ed3210536b5c8bf1a7dfc31b53c5efb3e27a01a1a6e5a68fd793ae3aa574857486563c6f899641082e93d4aedd4c807f167fd44efe775" },
                { "he", "abf61c189a7632c0cc4a0b51648196cd7f3b422b425068b1e062e05b82ca0c9aa525d4d694840fb9065f29abb5b325e626cdb2bcfc97832193e4e064156acda6" },
                { "hi-IN", "54a98463a4bb1807a9232e9f48d64781a43286a498abfb9771a3005b8b501da031fcbb45b35ad13129eb1c6b79fb3425480cea4e6a6f64fb0f4b51cb61c9aa8c" },
                { "hr", "8c68220d0edf938a4580dac1c2b5430854e5993e35dc51f0a27115e0e10b2e865a8f5747797d3653030da944017e01de4e2929e714cd1990de042bc2e16ae95d" },
                { "hsb", "3c14d45ebdca0c483a9941803ff6a880993a865a717470e1c9e61417bc993733bcd21aea3bf75115df81db8dea461a2bbfcf68655c401c072ec3d55d434b79e8" },
                { "hu", "6e0a6de716b2e48a390ac8c268e9f1d8d470488566cd2c860b6d6d60ebaa9a0682195aba83c8c4e583032072bb0a0a1fce09c413d158bdc49bebcca7981f7761" },
                { "hy-AM", "99c472d8ba614142f97050d6c7d806dec1737cf5859435eac4a38cc4814a0c1ad1abe213465ad99d96467a797c3ad23bea492d471cf4651b98e09308f857138f" },
                { "ia", "3db7645f478f683e338e7d34416b1e7aa1b27bc7bca8127cd2dae06a06b6d8704734f04e6985b5ba6298ae0ff3cb7fdc5be3139f3c682e64365fcb207001e62e" },
                { "id", "1cefea7737395474b92328352b230b014cdd2ccef59d74bd1e86a62b42f965d90b06a328294e60324f938c8e2a50743599d6e1783586139f6360cce76b7342cc" },
                { "is", "d56cb3f397adb083e1475ecf0d34289adcac4d0ccb52e333c0a3ab53768e40160ffe68099124b5e418aea1fa1f835f172cdcefec5391378ae0aa759003a5bb2e" },
                { "it", "1224f0e3efee2b2561c4b94a00d16160d94b7ca4f00838c7760131e4c050607fe5b363774c5e19dbf35e1d0878e34ea67381c4564f93eeea9ce69e2a88440ee0" },
                { "ja", "e067e8b6485332833448d3d6993fe7da385f4ade4dbca183c6e76e1fa2b50f5f8958bcb7f17d25a9c081dc9583e994ab531f2e0691c4085aee63d44e18f2a046" },
                { "ka", "c4891a6a299fab2f0305f46ab76a05775ead9d3ed69c685b543e40a47b0e52b5f78d7b49b7b47920e2cb00fc964bd8f96bffcadb3d13a00962d13c450a57a383" },
                { "kab", "03abcf21ba1dda98386fcafe1704a48538a60ef87f2948aceb2371192700985702f95cd79fd155c93cd9de663debf193ece0ad7d1d0683c565310b8a5668c986" },
                { "kk", "8e031f9b712499bfe8565e462d783b108ddf8d02ee4e752d06215e6a85ae89345d6e095d08e9f2813af1cae087c2e94f9db57c972b712a11dc2a8bd3f10a9dae" },
                { "km", "621ac605b5036265eb20cf31315227c92efdb97df641566a9f151e5530529484aed305a3623c504dc1d492f50d0c3e129933e843d08e9637429abe247653c27a" },
                { "kn", "58173533e95be46049874e5db51e5ef613743b6d5dd339db1dec8a19be199fa44650654a7a474476b1ae677e66282a7d4116fc033b246ad73c20d7d80ea4bbba" },
                { "ko", "3ec276854865ea6c3c2e410901ceb91970a17c7006d2b63a6b38dc2dc8b14cfce8cb1d04c2b86aef347293c743a3898b29c796a89841da4c66bebdf1c675c300" },
                { "lij", "61fafc0a664dfcc29a55cd3c8e675b19a90c93150363d8c373aa1c614d3847ece4c21872675b80e28039dcf5ad19fc92f6dc226575101ae49e7291cdbcb700bb" },
                { "lt", "2ddb5532b7cd281bd6c9f1e13d3437a7022d4c46f5c951f0cd450334f150ffd907db4a4887ff7b82c1b7d8fee3302b29507201d9b54239ecadad19ab6a4a7d60" },
                { "lv", "9f63c58cca4c4ecc2bbf9096697dab74e2d30f6a5065f9d2a55630f25c6ad0d90a63168b95fb9982bdb2679504209346ffa8bc3617bcc5fc55f8ba1ce0561460" },
                { "mk", "0a87c9fd939591480a785cc3ca7d1b136b7ed07de826ed5953071fb0d0018bb4b9b8105da640a2f0c2a2f6cc4cffed5cd91159f2653195106a47a26cdd353310" },
                { "mr", "3b67654b411437c44cace9166c34727c41cc17ddc53d84eeff78a9ce2455e261f160abde3a170411515ec135f52116cbd3e9552cd5be9fe50ddd54c625d61317" },
                { "ms", "caedf6e79da0ef44328f04c1c076071d1bd551a04fdc9cbebe92f1c701592be94f56a51da9a4843e0b42b4bffe02cc7db224ce892c5d4485721092ab4981e791" },
                { "my", "42a3a1875aaf278ed4edbcb3a603df3d50e3ab0f63fbf5569a12796012775b07d3cc711170afa0dd7ba3b96ab6b331e2868c5f2c6783027fd6972e42a56005fd" },
                { "nb-NO", "68c9ecbc5982c2056a101753a842e7c2de9897aaea9f73820d92e2a8c8a55e181295a414aac8171a0a31bf7a5f91f2ea6b08227267f12e11e455f3f93835ca10" },
                { "ne-NP", "1ff7472f55a66fd3506223c038fef4466a01aa5086f29fb30ff2cd60d9a7147cf8b06c01c1ea5c9abb73e72c16b70e02a59367ccb50dbf20468aa8f8bc05fd70" },
                { "nl", "98fab45a0a7b96af664a67faa94df6c1085284d864f5adb05ae7a58fbcd5fb12284ae54327cacccbc121f065b922da747ba8f8c5ef4584cc1582d25a3ab667d9" },
                { "nn-NO", "0eb93633634ada9e966ff61c073e6a11cd341700975a8d3e3db7dc02a7b153fff2ada0675a00727c3cfe8c0a2e71aa7baec34e001396746a931ff2ae8487b08d" },
                { "oc", "0a0940529ad77e60ba9e5b48dbb63f525456dce0b6e0482dab262f138fbad0b524ec90addfe477b656ca35753d02032807c216c84d4c3065cae4a396a9cb01ae" },
                { "pa-IN", "36f0728e0631fca74b5ef45d807a9de98215c817145f5d0b97c526741684f9fa9adf963fe2e52b60fa247d7d4825326c146d5bad8f8205718b39191b53b2489f" },
                { "pl", "aa68a1c6f1e30c7e31bac910f8d21547d13c6f56ba185e3a09f185fda68fc8465716eb169142007aa830c7158bd126dc70e5442e6ccf6e304a336528f7d0aef8" },
                { "pt-BR", "9e7e1dfc5a61797535a4b0b2ed9ae0fd836cadb8979e468ba4b43394d108dd322ac7e2538a43a235cc20e71d3da752d743423df16a6f810f90c282ea8c9b021d" },
                { "pt-PT", "4af017e81ed07ed0eb813b3d8a6de27482c893847691989a269bbcd547fbb22c31c648c1ecc5053e800a8eb185247d7a83c8bf35b16b64575f1956e75470bf56" },
                { "rm", "d7487a1cb9ffc9aadc8ca6b6580c7045dc5b96e76fcfb669d6bded976a41a7d0a5aa13f4c12fa8e4eb9dbbf1fd8899d7dda4e62e998c7d7ef8ff4b267945f443" },
                { "ro", "204047b14142a74a0ed467ef0135c758f37d4502622a3002e9a718ed5f92efbb729e6b96f9118431ea7751fbcae853bc184eebf4df398289fe34b6149eae7571" },
                { "ru", "57ddc84d833196f1c5176d18f2cd92efb3c12b6e217fd02a2282c6b264ed2cd1b3a75f533a860ad887c28706736037b9d5cae8e69086944d7dace477ea2167f5" },
                { "sat", "07ca1c9737eca4d85bb7a0acb3670250666cff192ca434cd9aeec0c6ae6679940fa58a4d6c4c07964fd703c051ce5271a8a0a7e02e2f71b4fa88f1f26ef6d5f0" },
                { "sc", "e2c1bdccb08cd63a1320073d2ac235b3a830a275e98ea7e519b518892fb13914603514b99c31738715d2379baa419ecae8f315df21180310e6acb4be8d13f38e" },
                { "sco", "49ce7b093fe07e4f1bc6be40a098d9760b5e49340335bffd581e38f89386282d689390c65dd2a7e39067cb7b6052b5f92d5b7b05127a09f56f5c0171717be95a" },
                { "si", "5072d03644df4337ad5c3accef7c814e4bb5a3038c9b929c5f1dec163e3edd8c315e1d0174b41e31fd685489ebd31ccc0b4733e06f7c9e0681691656b136b646" },
                { "sk", "223a49e66934672a75676f9306a74850d9816d9ad72b6bab3546b217a89f01d5a8ce7efd07c78b8a8137a988b8b8a0b233e9921c24d93601e1ca5a67188d1467" },
                { "skr", "67d783e1775f80c65818beaf2c757e47e5577dcf62183da8a8ce9b3ccedafafdf1997ccfaff022fe960b27868636298edb566aa649c566bbab8978f5afc398ef" },
                { "sl", "08ad547730de417fff9422db676a82300227a02269729a69da8e58085d4611c149a9c34414a70b486d98b855317a407943edd751367f022d1d435b0dc9d101e3" },
                { "son", "b2f6cd3798ae8434ab0cbdb80d220035330d799f2a24c7615bff30e57eeb44646d8775c43c48c5cd676e99f866e4228dc97b69ae7ae9431541dc6f90cc23a6cf" },
                { "sq", "b5dbdc63d9ba33dc4b062e93b087605dff39580efd07954ff416e88bbbae5fe684337769cbdb926ddbb699d09eee19ee3eb6d2e4eef03cadf31be386c0680332" },
                { "sr", "e3080e64cf52afc5d6ff8c74d04df55deda40155cd1d5b014f39064a4f22d80a6041398ca15597ec46cf9c403303c1f193da85dfdbaa89a7008a21cc93068acb" },
                { "sv-SE", "efced2c68ce2b649e4e13d8e5924325b056ff2f953c096bc1d597941f3e0b4e1821099e5d8bd96b9e3c34b9d1e700898c3d55e16dc47eb9ab6849edf26154238" },
                { "szl", "c2e0400cc685b39c9b60007b446d154397096b7ff18cf5abae0ec3dfd9b8bb69c8c47ab51e2d073aac7d732402c7f20a9cc437f680a27b1ab1d83660bf987be1" },
                { "ta", "8ebe34d3244a3892c850ea622488f30938402f0b23ff5ff2a22a4c542f8aecb84f25bbadc4a62fd467e2cf059d8c08c17aaefbb343b87077cb0b12aa1e82d031" },
                { "te", "07c6a4aea0ab61ccd1d7d72258db312d0bc267f5d8cd1a249cdb9a36ab09f747313a1cf8b313451d65e3ec8a86b961f8d88e8e99c91e1cdeccca5645e0dc6cfe" },
                { "tg", "2bb2ab38c0ac54fb59c607079b82c140a52904bbbea522a12176837dfacc16e168427075d8bbc71e02a87b349e390a05a3e7a7aae0dd029723d8e508d35dd75e" },
                { "th", "7cef8354b73755e8ced13143570380cbefb73f403bd700ff278fca64c5eb701eaa4fc830863ab5e72a45e01055c1a460b61261bddd2dadc4914aa3867f437022" },
                { "tl", "66b9e7949e8e95c733c221a6aa2da8394748f850cfe6d23583d5c4f014ed960e280e0fb1d698130a937884a6f15b4e02fac6b5e0dcdf2f74ae11d7fe9ba4d269" },
                { "tr", "5f2f11e2861370a67fdaefa7a36eb4a9cb7f6476635e1e0e7bf7aa2bc6e5e7e4c0bb66ba83578697a8a0fd787eda24dd7716d44034c03a44693ae4c5ef34ee92" },
                { "trs", "33443661f722a05ced64aaf774946de1ec7a9a3a5030d5b4629e96f45fbf70985add59010dbcf18adcb8a35c13f8d1fc8511de80a68d5c3dc0abb9169443fb76" },
                { "uk", "8d53a6c0ce777b8b55064a25c83544005b35c725a60af91e9458ed1f0bfc96dbea06ea3ae9bbd55bfcd3f0ea93359b2a19b046a9aa5eef0054f2a7b1f0f928ce" },
                { "ur", "1e1b9ece014648742c4f7f49fe97db67272795d7c884d6c3d72928b3727bd6f5f0213ce81a43496e351195cf5d0ac63a1d650c7b61144e59b128aa67c603d4ce" },
                { "uz", "d70885f09d3050084823fb474542f11f8d6958a1c6f73ae3b9cc03b89da8b5e2b4e561bbd575c0304af7244c6c8089827d2ee9c891b8df21defa722654ec9c11" },
                { "vi", "8c2746639411b592735705cf366c3c2fdf9056f6d0598ca34092d6501200ac319b388e87b4d746b3740032844a728895e88ebce76040efd203c0b0e2b087aca2" },
                { "xh", "5af26b20b01e8e2e1d88abdcf93e847a3d50243d294ed837704a51d6c9033d334b6b9160719c19314ceab9fff6549d094f1ec272c3f1c65f2cee5f5c44daee01" },
                { "zh-CN", "8d3677438e1e4a9fe598d45eed56e249a61c91d2fb405a7003d5057721aa6504830c05d99488a35e70454fca6322147edba01ac08105ae7c7e8034058d859b54" },
                { "zh-TW", "ef25d48b427f56ec986e0d65f4aa92afb98d1c7b6786554a91d73d6c4a8c1736e70de0011b4bf37cfd3e767b4d3fd7dcfa8158a625081912b8c2710504c7d5c8" }
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
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
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
