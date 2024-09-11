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
        private const string knownVersion = "128.2.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.2.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "45d22bd850b4ce865335aabb37554bc6ca01bc8879bcd105d175da3cde5c6067a61451396922602c52096900f2444575a449bd5c1ec76eb75731c9abb3722a55" },
                { "ar", "2ca459c15be95b06ddd4923076b17fdb60932f542f5f04cd41ab8720f3a6fff184d9a68dd693811b5eb77779f653e65673612bf181989b34e8710e20801d7116" },
                { "ast", "85b9082343ae910b32d19db718fab4f5e951845fcdba8e4e14c7cf4dcc1e92005cda29ad37a9dab30d82ed39a0b2de1c74f72b32661c088d851ad3344fd5c039" },
                { "be", "9d6ad25f62e10861871e00514b8a2b046ec10014b55b2abb529a8068e6a1b75f4657d5dcee2faf282c266a5dd08f03fa54b8a52bc13f4fae72badd276254e049" },
                { "bg", "2a1d7cc7d0db8b3f4dfa8efaafb480ce44b05c852fe9996797ba111eaa112497ecde85d16efc9e8b23340dc2c04cd5b2230ed55d33e145146b3b52dc2ab699a7" },
                { "br", "3c4227d64e250e420088b2363d4333ebe05c89227faac4bdafb416f13f0be19382bac58092c1e866b7ee2c9a226d001367d8b1f587796998b019ab404c57bbdf" },
                { "ca", "7ec73cf0edec78a9afa99244b7f3f53dd90d808f4c217cb32707d7d529982f914bdb9f1294c5731f056c0a42c45b2e327b19c6a8640d62cf64e07ca61e3a9731" },
                { "cak", "b9e708a457335133882ca9e43a6e4fafbb5dcb14826527311400caa733dae460537837dc362e28a252705dff0c90c4575a068883de1eaaa3c84b8605a1b686d2" },
                { "cs", "c879637452bebd950a05cb6b5d46361607c809b03085c9ae3d8a4e655ed014b48b41cd15990c8dd5ec24c5a98b59d083ed03b528be49217089c672fe9676c723" },
                { "cy", "17aa4d4e73495a17b5a0e077c8af648130e856fe3538be213029357112bf1af61ee0e70ffa7bedd4f59db9d5eb77b841d73d84acdfdd2be7f865648ecfeec142" },
                { "da", "59e44b90507b02e8fc35f47ce99919d4702231086626c3bb742b81e8ea1589812c8dc2cd1468271267d9a014cec404a927b28e4514f0e64a9c4b79c6b846db91" },
                { "de", "2ca4a0e1ae295e3d45b81c202c361371957b27c2378f1f2a8ddd090fbb68215968721c1850a98d22af4a0071f77935a14c9e8af095b44fc320a291801fdbca46" },
                { "dsb", "3a38729b110ca286f06764b24196fab7b6319c788d89fa02879929f43ca4aa5e214d4e01371d43c5cb079c98db81e4b4f9b762602c2b8f086d26fa85325fdf60" },
                { "el", "5068b61ca840ab2573bf8dd157ae122a0d9200a3ad72166c1a1024cd2a4419ba9e9ec9466dc4be4d06203f4cde40b1a86bbb22de7febc233ecdf5a08b7ff1b0f" },
                { "en-CA", "7a961ec5bff226967ba761b7358a9eb2f41e3f520a7c5b4c385793bde8873760baeefc58c5a44192ba4064cc15945e9215847f2fea822edf099acdb42daa9de5" },
                { "en-GB", "5d54b5780747248c52d0f3bc3161aca3a4725b989361bfbacdd5205fb1570c67570ce20f5e03d22ec8daaecc4adaab4e1357b64a6365c16bbf77c648a8e1a2d6" },
                { "en-US", "39c383ee4b531209a15e0f4f07a7b12df3736a2614d92550f7e07291c4f824c8a2f924b6a2c1ba08443e06358af20ad8d0f7a195b0361d50d8574e138906fd4d" },
                { "es-AR", "87f90c1c1de78d8b3cc707c094dd425579f8e5c28318bcf88d3d2f616e6ed4dad858c60eb87838914a98a74bd556542227a18f3d275a91219848bff660fd966e" },
                { "es-ES", "cbe67e34c232c6bc88c786ac8bddd19aec9b625414065ebb466f9e8f8392f7b176bda0df43d2b749acbaebf8d71845fee5a80314a06f1f00c7ee4faa51085ad4" },
                { "es-MX", "6763ed78d82f717c52affc231e087144cd52844b605eb7bddfca42d2a2664ed84f85fcee2e55cf4286bb8e5dc37f5f6bd986ab2d5fe29520ede3a65bb181a7bc" },
                { "et", "8bd3717491b43e130fa38d34107a0e4e8ff8710df1693c68526211b8d4832038331a5e466938a7b7924b68ff173b6afaa666d97ff46362f73185ac6da7804ccf" },
                { "eu", "dc53a3917818bc7d81d401c7e6e7fcb9588609e47df4ba755ddfdb078d5b9e5993fbce29e79549b1f4795865fb33295ce0e7e4e836e7b748559f7c5ca68ebcea" },
                { "fi", "3606cd1b2f662244fc71f3e9d11f1306422ea37538b0e9c14abd4a21820b8ce87efdab0f6d5933a9277952d706c03af5459f8992b6c3f731a12b7e2c28803238" },
                { "fr", "0c8c63f1845ad5efa8424dc2e29f3c9baba780f3c2d5bd63ae4968cef4c5b17af2ad82a3a10191a13df38e72d2922e9cf794c57f867f42b750065cd072e3141c" },
                { "fy-NL", "5f8637de10ecf9cd5198aaeca68f5b7f767fe491a64dd73fe9f102b50be3a5f27399406ce9de30fc535437de2c5822c1971416e02f4ac2cf3e9dc12a8b5cf742" },
                { "ga-IE", "e8ec722868611abe6cd34cac1feba2844d174c230314abf4b6a86e0f0450b8a1c11bd5419c9725ceee365a99f502eb7a70a7f4159611853049ff40a468a205fc" },
                { "gd", "b2e858b0447e32a6699a9a12c8de99cc5a5cf8c77724c7f23fcbf9d5d78553a845ba4af9f622c6ddc285c1fb98312c6ca4105c4a5ab532130eadf2d18852e571" },
                { "gl", "5f12ac312220547f09e10e6fa7374c8e89fcbaaa7a92041f84821bcd2d871cb573deadf426d94ff415a04a5e706a4c17d57dd102dc0bab8ac159ecfe74faa9c9" },
                { "he", "01369b7e53577b10dd245ea563dd8dff00d18089b0df7a9a1af5403775d622726b895adf79a9ddcf810ef6057df700989861081af48a79a1f3c6700904399699" },
                { "hr", "d175d160da6e8ee960a4f22b7808534bf4d8211da170ef9f7036da3dcf59de801153f362210c2152cdca217eb29663a80f5fe0b977fc133ad6900f99ba13b6c8" },
                { "hsb", "d976f93391414950c5c62d5f237f98020355ca8ccb57120f4421286304200afbb6f0c0a4f19372202e3c57685fb0a78f2abab70f691f8a4534bdf77d1744cbe6" },
                { "hu", "0424027897567de244b0ef0ed531cdfd5568478e5019514c3aca1a3a231ad06b5c50921ea69720f8dabfab8dbb9e6d080b70fa3a781b12e0f831dfacf73acaf4" },
                { "hy-AM", "27f51181d4c7d7933d1a4af63850f6df07fa9f0ffb5639670cdfb880af041203faad4fd6a6b969990d8c5e989408a50a092b2459114a82fb3cf7f610e2b615ce" },
                { "id", "430a348370186a862a67df1ddf26f33b8da519cb2add64eeda987e96aa44d30a8d8cdb36ca586ac42dc95fc42cef6dca9787fe141d91b4ed04eacf9e7c26ce90" },
                { "is", "40e15518b9ad80390dcf6252bc6484db925af9c7c42ada79150542d5b905f375bf26e3e13d7c84ff7602fcb1dc5676e70e814033b353cddac688804102f6cc8a" },
                { "it", "3760673d60d04bb35bdbfd658777aa09bbcf5f698d11748e06ebccec25a76b188b82e68875d11df9baa20c5219d27a3c0d063e3cf9f737e5177dccd266744912" },
                { "ja", "e9894f4ae8fd7e4a7d8da53dd4ec2dee505ade81e2c2e10d3f4ad628ad9ce4a1ec628a6e57b4c4453d2894625461ef8bdd713a048f02552961a78fcf47f54986" },
                { "ka", "5ead40d40e4f8cc6268ed5af19fd2c5ea5637ee480f606d257a727c875c46032f3df033fc656746bc58ef59a4bdc2ce572418cd34d460bd20a30e23049482197" },
                { "kab", "7756b930408242968266427d321ee98cbe30df25c58550817f92aafb66d5463799e8043084a08bce89f1df8c9a167fda91bdda2d78db0d389c201b0e570c11c7" },
                { "kk", "41ceababba76f356e96ee6ea37f456d8355202a243a2317d988f536d612741ebac074ac527c8d8ab43084f4c6c37ef24a917b51b50c22316083ec7676c0004a9" },
                { "ko", "47f92ec7e3aea886ef1f72fe80e4a833494db3fea2f0719782e736e0b985ce090f674c0fde15a37e7d56e540434001e9239b755954d363b4f811dbf4de9cdb66" },
                { "lt", "e60896f1fac6b7f2fb9338cace2c28454ed65573b5bbd8466a8baf30fcbcdbde5ab36ee7ee56863872928cd1472a8be6b17d082c3a45f6c425c177ebebd4cfe3" },
                { "lv", "61dd915c6eecb461cb7224406c880ad2cb43b6fbb7afcedc9ac4f2f64ef37503f8525014d5aaa54f58a1c23ef170b8756fec215b0ac37bb4098388c75d2e4a56" },
                { "ms", "fbbfcacf3eafaac53a7a1f260b2f307090fc819a6adff6d0fc581f045aa93ca31b242f915dc65ca2225c65fe4d81f569df645bed4360847421e0db6b450cd044" },
                { "nb-NO", "73443332283d25ba96b385aa894bcce8e9bb3160aafeed9e9f76c7d9c8b7ea8d6ae821039d221831426d417e37ee71189f3692d613e5782a5536c28af5390635" },
                { "nl", "5d90ec460aad13021f9b33f27724e0bb51cb3115881284013d7df64f73e436452793353fd99b9a830e4b0bfdee1e3fe58a6cf8602ab22036d757e0d2c0a09a96" },
                { "nn-NO", "6d33c2df007cf5d433e25a5c719ce18c4ff92cb0aeae1e91b63144d93b63342ef30afd8e72ae54df304444a5a021f9c1924fd7fc41cb098dfeea48fd8ee11fd1" },
                { "pa-IN", "5251c367cb7ed4173f2b3f9f011b7b6d8ec0e20a947f240b8bc4034bfb3943c904c45309a58ad0f71cab2b7a28ae6ef731ab83be5522ff358fd9fc7a0bd069dc" },
                { "pl", "7869bebad495289c4f1d6f9f9fc191a33823064c2f7fab614cfaf28c825dd87c93ae5b52cdb60fd75e9a49196df67cd09ecd8c0a7269bac6562cfaf2ab51baad" },
                { "pt-BR", "424d60c8832191140e17c48473abd98c602a267b271cb8a34105b37f9e37312101f077e4ddbcc30bc6000ac4d0f8acac9baa3a7863f43cfd69849d4e7f2c9ade" },
                { "pt-PT", "27f9c148f6e0a26af2c6c55ec865f72efda36e7e4b79b821ba202855b2fd1593b0dfa01f9d3d24419fd9ec5c3356dc67456c43ec954b923cda844dd331a2d3a0" },
                { "rm", "0be6bfa56a716e4612db4ba11b4cb2a321470d1b2db59353c68480ca7d902560f5cc8507f02dbc47c83afff1c505ae47d3e58f9a1d7efff9d975d8661fde0d64" },
                { "ro", "fa528581abbf157889912f466604d06cbc235ef90c3d7240686a5152f3954a728b7178bd558c09f2ae14fa65edfb8121085e225b30ea1d36fccf954e775f63ab" },
                { "ru", "4def55abcc48d1961fee031d6c9af0a4a6f94eba45e1b5ce3d15fc42d603511b77df184b59d262536583f8a1f565532cf9e8cbdf50b07460475cd4875edc1c38" },
                { "sk", "76ddf2d3168a57b36686173c76d98a90ada166956be633bbd002126eeabefb1e5d8ecfc5d849f754d6224353bb21f4d0c37f6ef058430e7b572317f982f74e3d" },
                { "sl", "aad46284e88368a963eb0ad872360ac4984f1db65c3960dbf8cdbcedfdc017c005b7b41c0526f3e701afafe6ee4e8ede2d2e71ca087ba9b97134685b563ec6b8" },
                { "sq", "8e958cbd6ed636b80a61a14356be74d76c4aaefc8c7948cd5fc0e7bf3c55034b2a205e52f9d14e8dd706f34476227be4a10136e11f9899216a9db76955235559" },
                { "sr", "dbbc7b61e210b7a7e11e0b0eeaec64c530451fcde6f9425b4e4adcc23314c82229a66311d7fa12b768ca50dea9e506cc473b6734398b54faf874c297ed8ca95e" },
                { "sv-SE", "424f3df26f82b54edab304641cd7582aa506c7375d6cf8e048d6f0f062d49bb2413ddf90d5e0f358359f7a0266326229cc107b6fca838dcb1f93593e56c4fe69" },
                { "th", "2d19ef43ff1e589cb89240d8d91f7f934cb7fa86b76efe4996782ac3a57fd955ded3fca634cb09d681503db42135c5bb9419a61d724c1d758f88220f57c8a0ca" },
                { "tr", "a3b2f8c32c88f24d21a85b43bfa5c7cf6791ba481c761ee9d39085fb966fa273c3959fc0bdeb7b4c083791896fed217df82854e477311ae3224d94be00bd619f" },
                { "uk", "8082abf3be01aa2fb0b5f6dde666e9d53d01d782dff629477ee86ec21b587fe2f20f1d7d3b06c4c07028a5c8b7e4af623a5eddc276fda7198b36181b030557d7" },
                { "uz", "26712add1eea2fa712a934a0a2bd66cc23d7a7c5b25a23281fcd7cb361ca03168e4e8cd8c2ca6ab54df673b26fdb89b8b9911139bb7f3e961d390ad6a544b50b" },
                { "vi", "3e4e776d121a35186ac1d0a86182c4f17f50b2ce1d83a55bba5b27d1c57fd3b0e5fe7e57c16520f623afc177fbe492bdd3fc39e04cba629c6e528b39750033c4" },
                { "zh-CN", "9cb485bdccfefebe0307d9125dfd7d6797deccde7d42e5a85f95df50081e4540a01fa26797867809f2c0170c1e454e8ddacfc95ab4233d58c14ba46ebe662fb1" },
                { "zh-TW", "29a55f57d37855a0787b069e566d01783f679b88f44f1f083caa8ef5014a9f96f722edeb31c41c0c50b243d7ed64efc62d5d0a74e18957bb1994c256eec9f4b8" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.2.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "13c08235720fcc974f334bcaacc625b5cdf7daa44d672d07d827a5e6ec16dbab1fcf9ac0947b8abd000d8713522489b0b8d3dc71517d79b79cfc55f49d5ca55d" },
                { "ar", "a53ba43dd4ec53f94c556b1ac91c853571b4df72d6f899368931269dea7b67b9565478208f86dbea3dd52f9583f263f6fa4534684c1934133278c0db93b5789c" },
                { "ast", "fe7baf0010c5a96eec5831f2b2cba0e0068e5a3374cab3f87714f78925ac62a035e12cb6e6fb2d1793f67945767c1f8de0a6c45c8336f84a389c69e34d7cef66" },
                { "be", "517929c7ce6dd32c5e85a7426dc03288112840e88dc9fda8c18c5de8ddbeb1d3ee451f4dbc96c49dd2d916768e2ca9f39538184f776f9c292b34fb08bfa42886" },
                { "bg", "7441f496edafe8d2d62b4905d3479b1e55c2dde2162f38781d369c2b4e6a1da18e9525e488c62af943843f4fe5c5dbb5d932cbdb2467b455fd82f01c965ae0f6" },
                { "br", "749696565905b057032ffbaab8d4b3da2de251b329659c94d72f03e2b5d1d14daf9fea6e85f0ce930a62aee37704c8c1d633e896a8bed10f925d4558e6c1535e" },
                { "ca", "0bf3484e13fc473857c2a0385f4af245b1a0a71554a4c4417ccd8e1b9d27b360212d2c477062c7d952d7d53aa7699a11c87f2fe3439791a3cb6d92a6c7df70fe" },
                { "cak", "beab48fda7be89d615384a2eafe2a9f1cc18bcbf8f80d2dae98fcd2092ef450f8d619c2bf7d949b2c9ddf6a9cc9098bec41f686dc43df25441576dd67caa235a" },
                { "cs", "449d7344e301e549eb4c6db2054ec98cd19eb881c02f773120d355fcb2669629fb423cb68c57814fb2086a914ec1fd097b3c5620ffe0a33c0c298570efcef7fa" },
                { "cy", "1d3f171b740d6d2f3da8f685b39041aa690e9a2d9634397ebadbb905cbfbca7430cbdd91576e20a2f9b9ab9cdc1ecb5a9eb6727cf426eaa22a90f192c9f2b5ee" },
                { "da", "9458c16ad660cbac99fb9ea2a4a9ebe19d1b5573f6606c6b4914275cc7ef36808211153016b6fd89df7774623692d23030a0d3e7d19edd6bbdf283e0f9fb165e" },
                { "de", "22ab182301fb12db66d34c4d4c1bc2ef273a2a7d054439b4c65309333f775c090c1016c29d2a841adacbb5d1f3f1b028a216a7fc228ec3faa50dfe1157eae04b" },
                { "dsb", "4403959642d449824738f2cd7961d1b322696cdec3937ab2ac4e844ebe2ba9d3b14e4963c05fe443744e4b4892f480ee6995f6c3aeabd345a5d70d2ff308ee58" },
                { "el", "a767d05212c40399b9cf3ceff267fb5a9c18425c61c93ace7a466bd144dd199c9573de6ec10c5e191892eba4890ca7a6356de7eb41334e074c95095b8cc939db" },
                { "en-CA", "2d7b50e11947428a4749046a4cc2ca762151880c474d3cf2cb99625cd7909277f6e0ec1f74bdfb387f81e4c0b5ee47ac0bd758260037b8abdae5e7786728797c" },
                { "en-GB", "c6861dc8b2c7d87ed5b4b69ffa63dab82c582e85f52ef8c14f15add0ffb59bf5d2cf418de01427dbccf016426c2964e1475282555deb574c8d0412253a823338" },
                { "en-US", "ca0b6573552f33058ab71939431baa73fe635ace939255a530dd86f1069a80bf5aefe09394dc9c50fe249a6050dde52c29701ea8c0c57351b47ba573a0e7a02b" },
                { "es-AR", "c372072bed973dbb041b5f73c97a113b3eabd9a43929d9743447c235fd6e161e537f71d8caeb5a831f2053e7abc1ea019bc14d36a4ad4bf55363beea5aa50f89" },
                { "es-ES", "35d2e1ee755a0298ce7e33452edb890d8b97c59c357f95ae7acffc4672e565d77925284118d739c511dfc01efb83e4ef589d5bc51e23bc2ca26c1148b618cdcf" },
                { "es-MX", "b56f0b16eb7c8460a109de147907364b048afe8f9da4dd479213a2d9e8e2587efbdedf8989f1fbad12eec8b1cc66b80f1a843543b0a245f3292258b428b31b0e" },
                { "et", "6922ca77ebebb51cfdacffec55df73bb731f3c1621775787a901a1996871cbf90be393845fe7f02db6ff4a8a59f4f2736beb701a25351ac8e30de9811e5bf03a" },
                { "eu", "e0e746610a3df6e58b06647bf2c01571189a559e374fc0cdbb38e697c03a4ed9f74da33f578671fa0ce5bfcffdae9e2d8612b2f4ff0a383fd1e685042e2e9b6c" },
                { "fi", "dcbcdadfa1cc7a9acb88c61cc1e75e0637ef0d4977b854aa9f8698f98e9c116046c17067b4d4ff8f11e47879388f7546309ac412c055fcb95feefa62913a9a88" },
                { "fr", "1a7cbd2c9fc524305108b81526baa77dccadb9206c62657c4c7fbc238f9efee3e16b874e416ba907ead319b21a6eb667758a2977999164077028b74094ff1c76" },
                { "fy-NL", "74c06c4f5c3bc5b779edbe5d4d3fdc57225826266db8ed1f71e0be7f2a5a2bff66b4563d6423e03b328a6e3107e92dfc6f8d82b8fd5171152f49a72fa22cb74e" },
                { "ga-IE", "20b2283e18926828bd97342fd99bda9e8c60d9692799edfac6b84f078187db34f80c44e6ef6adeeb7ce6353eadf9d212493522c5d76642502bedf23987237b5f" },
                { "gd", "b43e273e1fd0ea68a51ab729db05fbc48b9f26fdfcd9f7df9bc03fd6e771157cf0387cd370b733dc841167cf5424aefeaeb495dcf5b53bad27a254e5844dbc1f" },
                { "gl", "a9b7fcc5c9078afac43066ad3db5ca73f5fdffcbbc65a8e18f463b452c9fd8ee2d4d615474816e8869f5df529b9f44c0737e81202e5357064275e171709bb04a" },
                { "he", "a6eef7529187dfd3a07a3281756d49d0d8fade67d07f345209d3c53f30f03f47ba38ef6049e9763fca7c9a8def527da41c8b18d293b15c4bf6d2fe769f0f1a93" },
                { "hr", "afe176e4234274b82aed403542e6e2d14d2d58536893bd557fc7c31b460a329f3091cc9a761c1c065f882709bcd37e53bd19b1e9ff44ffb5aafe7c4a2460e2a9" },
                { "hsb", "f1b35903d0c696b4bcac30db65f22c969e1aae10944d8945d3ecb308c5af8a645553490d36e527b5410e7b013fd815b1cc2cf33312030d2e83ccaf7d0adbbbcf" },
                { "hu", "9ded5f9ef372c0bca9dd786228d4387b46188556532a5d2f6c50e930defa02f16a550cbb73b2183d7002de0236fc81000ec14f409a6684ce94bc411510a2480e" },
                { "hy-AM", "5cb8ac2c120151a538a85dc1b145c22bc95e58eb3e6f8092c3583a97dded974b25652974e73696709e36bf9cfb39c314c0a8a266adb7b2fd469abba77ce46360" },
                { "id", "c702a69754ece37dcd9cfabd8c138db82cf0af45d59f80cc38477d7ffd368e16b61fcab293354cc24ef5426050f8cb379e65ee72002050f501747f9976170a0d" },
                { "is", "0e605eb88b20c2b84eb54f94042b813d2fa6950a1cf4a316061e35fca1e955046a1c1526847988af28535a8c60549e61f5be52a9faca72cce3e118e52b1174ec" },
                { "it", "01d7427095936aaa6a2b9b63efc1ecdbb42d7ce54bc14fd784e9929c9e2e554f3e1d2119eebf0d5a72aa99529991dcfcdd2b30ebe3e5ff564f12f8011510db36" },
                { "ja", "638effeb7d538b768ca66de7d73282e5f1d8776c4db3feb0f340255d235cdd0aa5e1c788cd3e26b1d9c859f47bf89375b84ed512e1cea1dcfb8ad460ea639173" },
                { "ka", "3378be13e528acf13bf4ffbce0d7728dae86bdfc684494b7a89d96a7b84d35becc636492166616ae3d67eaf634846124a27f571acf428024b9c559de03ee99da" },
                { "kab", "898784580d297f078a34dcc1850a390f0cc6e921a65c9635a012b05cf6f359cc1d42a0666582a5139baecefaa384a09798dd6950b7ac76e749b1b291405cde5c" },
                { "kk", "920484aaa0e00d2e9491a1d3b766c8e6254baa9253a54cb20c0055e2b56fd37552f4ed6e82ff6256bb70eefaf50c56935ae0deab376406dbb39c54413353a71f" },
                { "ko", "6352df10596b04725ecedfdea9f5415daff4f42f49ed1f6451ef21f834bf859ce805f0748c822dbea2782e010285468af26cf2a55eac3d6d255e9b42c71f31d8" },
                { "lt", "5b05691f90c732e8ab862fc10516ba12a7a2b6c29e33cd2d0246e15aee63d1464fa872646f8779aca8206e8ab857fbe752c7c6678658563f80ffbb505a0c3453" },
                { "lv", "0909eb7fbfad46ee967abc937a051566908778c15b721e74427f5718a5e6c20fec34fd83b1b0eb9235dae6801681411ced70d69837ab4428b777cef726958e67" },
                { "ms", "f95ebb678f17c6de0ae2a6ee73606c9324452c4b3201a972fac13b73c6a7387a37b9112f14464c197eee5aaebc1d26d3566ba89233d2a713c3ac322916b89669" },
                { "nb-NO", "f810568122454b439033079af04817713c621da50bcff4e5e5bce24b7a909e2480176ba1dfd5480282c6d30a63042828301c18d0c937006b29749580d88e7092" },
                { "nl", "17406bd78a84fc5a575b19912a534635122ebea2a8a431a38334243b70cff38c4019298a26d21e1be1e44a79bc8c7c1d57a0bfe270cd6f18d902e4d59d26aa47" },
                { "nn-NO", "2102c5192a01d93fecb38b7510fe00c288f4ba9b1017f630bf37adfce0d58867b44cd2b22125495601aea62d8eb0185a4a49f5a376c37ab67bc2dc9840a2d6fb" },
                { "pa-IN", "35696612a9fcaedd29906334fe25fc2bcfe951ed96a0b1fa5511b3cd4299c6a7b5598046fa962461f30a92086106e5b3aa3a87ff742c0e8a1a24b239939f6e60" },
                { "pl", "96391591a5ab5424466bf4cb70d41c225b9fcdbd6f6992d621ff915bf7b6252655315858d3b295473e6fa34342d31e0044497548b952370f0f3cb8bb47b84ce8" },
                { "pt-BR", "134f312e8ebf9461fceb47e10285699276afcec2bdfc4dbe933bc99b50255c1dd35042baa65b5c520b71558b023b4841908f2f80bd0e614d5eda727cbe8dcdbd" },
                { "pt-PT", "ef1c4db9111027e9bc23ea7bd349381446fe13c5866d297afca8f9111bb9fdfaf6b431c9f47a86ec5459e612b3292b0acfb883faff908e633fa6b73212421675" },
                { "rm", "0431243e3f329db6fad4bffc5a8ed66c3f0c5b3a841adf04a743e457440231e9fd80858be989df6f3ac97c32f0b5d53c023278d706ac715e140c36e5f6be91b0" },
                { "ro", "aa9adffc92fc4db8d81d9d24a86617ef3371f6870120155782aa9d9885318eaa4994cb2eac541b8efcfee9040fcc2fd16826ce576665ce02d941e78ed267cf14" },
                { "ru", "f4d02cebe6bea865bb3aa0f754faf0bba1c5df5040b5f0ed1c598d03df53daa52d22cd02c3552c33676843a074d3979d8aa015df67e0de2cbcfb36a3069536b0" },
                { "sk", "14226f919c1fa4ee00dde49fb0c77b600dcd943ae3339d9b678447774846c5a9bfd1a6ce51b965626f199f649646a2983325feb6608051a784b9a323c72955d3" },
                { "sl", "39d1157de692f81a68ff6a8927d5a263adf7a17f5eda44408347d80c313187aa819712c1e6c78243e28aaea6e5fe73d99d6d2235cde9041171fa5e727a1f8f71" },
                { "sq", "492860fc7e40abb5439f63514638917e2d297799bd202a8b6f714bfd95835749eacdc2df2017e12cba317c828f7fd042bd5cdfc1ccfa6cad8bbec3c2d6f92ee9" },
                { "sr", "b16946eb7827bf2f28cc35acd6a094f890d779bee733843e41d18dcd7297d679ead92d0ecf8e3c63ecf4131669520dec0291f48b1afc16a9ba57c9f166090932" },
                { "sv-SE", "a2dc46c1e0d4ecc520722671858b939913d7372fc4a3f4571f1a50f6597f79db89572ba5676d62c2a9207b96f2794031f592c123def921dd6398211ece43209b" },
                { "th", "b7144121d4d686bd9ca696b6bb421a727d658b9517362afaec98bf515927317dbc2340469822581c2f62a9b906b96a4a737f5080607852816ac7ddb5abb61a94" },
                { "tr", "5cf2759f56523476cd6b4fcd7a11cdbdf61d0b38f7fef08cc541d4dfc63416eb66df6614f193c8a0fb741e6ded65d498dce618aab1f6e641c1174a5bfc1eb1c0" },
                { "uk", "a52b1eb34e42887350293e1321bd2b5089b0e5ddc27f5699477f5ae3ab4f3e4c132026b1ac292ba0ef4b0846f70e384f2d6c8e046b5434e22bc6d68cfe75e686" },
                { "uz", "e07b43fb73c1cf9988d7a19e6bc45380bd33453b7c69a70dd1c87fd0d6d196a167d176076ff84523c5db8e9c3b170a6359088739b0eb51b472d28da8191121fa" },
                { "vi", "e902b5b603b6328aa57ca88bd229bcc2c6d98b2bc769b2fdede4744cac1fd0f84ac53f3379fb48f607febf21cf1a9cc684651997d6871957c3901c7636401e4f" },
                { "zh-CN", "75c4d9f3da5feff8d986cbeba505299098118bacad98881cffe3de4b69c6efecef3d03a039e2d37284d84f9b399d02c8f909365a2b0b22bc6e393fb76067f9cf" },
                { "zh-TW", "4e876b69999c90f843f40fb2364909a141f0ad1d7557f0d7708f3af419e158fc921257009bded264ff9d98bb33501f561f5c4c1cd7ae94398c6652e7a9884c6d" }
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
